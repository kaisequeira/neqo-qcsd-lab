"""Create-only launch evidence for independently verified rapid study lanes.

Image validation executes inside the selected immutable collection image. The
image's installed qualification receipt and client are checked against its
full clean source mount. External study modules retain a separate identity.
This adapter deliberately offers fresh generations rather than generic resume.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from . import rapid_capture_plan as plan
from . import rapid_site_admission as admission
from .util import SOURCE_METADATA_KEYS, durable_create

SPEC_TYPE = "qcsd-rapid-v5-capture-spec"
INTENT_TYPE = "qcsd-rapid-v5-lane-launch-intent"
LINEAGE_TYPE = "qcsd-rapid-v5-lane-execution-lineage"
COMPLETE_TYPE = "qcsd-rapid-v5-complete-lane-launch"
PROCESS_TYPE = "qcsd-rapid-v5-lane-host-process"
PROCESS_START_TYPE = "qcsd-rapid-v5-lane-host-start"
RETIREMENT_TYPE = "qcsd-rapid-v5-observed-interrupted-lane-retirement"
IMAGE_PROOF_TYPE = "qcsd-rapid-v5-executed-image-plan-check"
PLAN_TYPE = "qcsd-rapid-v5-lane-plan"
TRAFFIC_FILES = {
    "research_profile_sha256": ("neqo-qcsd/neqo-csdef/profiles/research-1200.toml", plan.RESEARCH_PROFILE_SHA256),
    "buflo_parameters_sha256": ("config/defense-params/buflo-live.json", plan.BUFLO_PARAMETERS_SHA256),
    "cs_buflo_parameters_sha256": ("config/defense-params/cs-buflo-ctsp-live.json", plan.CS_BUFLO_PARAMETERS_SHA256),
}
PATH_KEYS = {"data_root", "runtime_source_root", "module_root", "execution_root", "acquisition_root",
             "cohort", "qualification_spec", "workload_root", "campaign_dir", "plan_receipt",
             "source_manifest", "client_binary", "base_launcher", "host_launcher"}
RUNTIME_KEYS = {"runtime_source_root", "module_root", "execution_root", "source_manifest",
                "client_binary", "base_launcher", "host_launcher", "collection_image_digest"}
CAPTURE_LOCK_PARENT = Path("/var/tmp")
STUDY_PROFILE_FILE = "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
LIFECYCLE_LOCK_PARENT = Path("/var/tmp")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _read(path: Path) -> bytes:
    return admission._read(path)


def _load(raw: bytes) -> Any:
    return admission._load(raw)


def _json(value: Any) -> bytes:
    return admission._json(value)


def _regular_directory(path: Path) -> Path:
    path = Path(path).absolute()
    if not path.is_dir() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("capture paths require existing directories without symlinks")
    return path


def _study_profile(execution_root: Path) -> Path:
    path = execution_root / STUDY_PROFILE_FILE
    if _sha(_read(path)) != plan.FROZEN_V5_PROFILE_SHA256:
        raise ValueError("rapid capture requires the exact frozen v5 profile in the execution root")
    return path


def _qualification_layout(spec: CaptureSpec) -> None:
    value = _load(_read(spec.qualification_spec))
    if (not isinstance(value, dict) or set(value) != {"schema_version", "qualification_sets"}
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or not isinstance(value["qualification_sets"], list) or not value["qualification_sets"]):
        raise ValueError("capture qualification spec schema is invalid")
    seen = set()
    for row in value["qualification_sets"]:
        if (not isinstance(row, dict) or set(row) != {"qualification_set", "manifest", "sidecar_root", "prefix_spec_root"}
            or not isinstance(row["qualification_set"], str)
            or plan.IDENTIFIER_RE.fullmatch(row["qualification_set"]) is None
            or row["qualification_set"] in seen or row["prefix_spec_root"] is not None):
            raise ValueError("capture requires distinct response-only qualification sets")
        seen.add(row["qualification_set"])
        expected = spec.campaign_dir.parent / "chaff-response-qualification-store/sets" / row["qualification_set"]
        for key, target in (("sidecar_root", expected), ("manifest", expected / "_qualification-set.json")):
            reference = row[key]
            if not isinstance(reference, str) or not reference:
                raise ValueError("capture qualification paths are invalid")
            path = Path(reference)
            if not path.is_absolute():
                path = spec.qualification_spec.parent / path
            if path.absolute() != target:
                raise ValueError("capture qualifiers must use the actual installed response-set layout")
        _regular_directory(expected)
        _read(expected / "_qualification-set.json")


@dataclass(frozen=True)
class CaptureSpec:
    data_root: Path
    runtime_source_root: Path
    module_root: Path
    execution_root: Path
    acquisition_root: Path
    cohort: Path
    qualification_spec: Path
    workload_root: Path
    campaign_dir: Path
    plan_receipt: Path
    source_manifest: Path
    client_binary: Path
    base_launcher: Path
    host_launcher: Path
    collection_image_digest: str
    execution_generation: str

    def serializable(self) -> dict[str, str]:
        return {key: str(value) for key, value in asdict(self).items()}


def load_capture_spec(path: Path) -> CaptureSpec:
    """Resolve user-supplied paths relative to one portable operator spec."""
    value = _load(_read(path))
    if (not isinstance(value, dict) or set(value) != {"schema_version", "artifact_type", "inputs"}
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] not in {SPEC_TYPE, "qcsd-rapid-v6-rolling-capture-spec"} or not isinstance(value["inputs"], dict)
        or set(value["inputs"]) != PATH_KEYS | {"collection_image_digest", "execution_generation"}):
        raise ValueError("rapid capture spec schema is invalid")
    inputs = dict(value["inputs"])
    for key in PATH_KEYS:
        reference = inputs[key]
        if not isinstance(reference, str) or not reference:
            raise ValueError("rapid capture spec path is invalid")
        target = Path(reference)
        inputs[key] = target.absolute() if target.is_absolute() else (path.absolute().parent / target).absolute()
    result = CaptureSpec(**inputs)
    _check_spec(result)
    if value["artifact_type"] == "qcsd-rapid-v6-rolling-capture-spec" and _load(_read(result.cohort)).get("receipt_type") != "qcsd-rapid-v6-immutable-enrollment-batch":
        raise ValueError("rolling capture spec requires its prospective enrollment authority")
    return result


def _check_spec(spec: CaptureSpec) -> None:
    if (not isinstance(spec.collection_image_digest, str) or plan.IMAGE_RE.fullmatch(spec.collection_image_digest) is None
        or not isinstance(spec.execution_generation, str) or plan.IDENTIFIER_RE.fullmatch(spec.execution_generation) is None):
        raise ValueError("rapid capture spec runtime identity is invalid")
    for key in ("data_root", "runtime_source_root", "module_root", "execution_root", "acquisition_root",
                "workload_root", "campaign_dir"):
        _regular_directory(getattr(spec, key))
    for key in PATH_KEYS - {"data_root", "runtime_source_root", "module_root", "execution_root", "acquisition_root",
                           "workload_root", "campaign_dir"}:
        _read(getattr(spec, key))
    for key in ("acquisition_root", "cohort", "qualification_spec", "workload_root", "campaign_dir", "plan_receipt"):
        if not getattr(spec, key).is_relative_to(spec.data_root):
            raise ValueError("study input escapes the explicit mounted data root")
    if spec.host_launcher != spec.execution_root / "qcsd-lab":
        raise ValueError("host launcher must own the explicit execution root")
    if (not spec.campaign_dir.is_relative_to(spec.execution_root)
        or spec.workload_root != spec.campaign_dir.parent / "workloads"):
        raise ValueError("capture campaigns and workloads must use the actual host execution config layout")
    if _read(spec.base_launcher) != _read(spec.runtime_source_root / "qcsd-lab"):
        raise ValueError("image base launcher differs from the full clean runtime source")
    _study_profile(spec.execution_root)
    _qualification_layout(spec)
    for _, (relative, digest) in TRAFFIC_FILES.items():
        if _sha(_read(spec.execution_root / relative)) != digest:
            raise ValueError("rapid capture changes a prospectively fixed traffic file")


def _plan_module(module_root: Path):
    path = module_root / "tools/rapid_plan.py"
    spec = importlib.util.spec_from_file_location("qcsd_rapid_bound_plan", path)
    if spec is None or spec.loader is None:
        raise ValueError("frozen rapid plan implementation is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _plan_args(spec: CaptureSpec) -> SimpleNamespace:
    return SimpleNamespace(command="verify", root=spec.acquisition_root, cohort=spec.cohort,
                           qualification_spec=spec.qualification_spec, workload_root=spec.workload_root,
                           campaign_dir=spec.campaign_dir, output=spec.plan_receipt)


def executed_image_runtime_check(value: Mapping[str, str]) -> dict[str, Any]:
    """Small real image/source check usable before any study cohort exists."""
    from .chaff_qualification import _bound_neqo_client, _qualification_execution_context
    from .util import DEFAULT_SOURCE_METADATA, source_metadata
    if not isinstance(value, Mapping) or set(value) != RUNTIME_KEYS:
        raise ValueError("installed runtime preflight inputs are invalid")
    spec = SimpleNamespace(**{key: Path(item) if key != "collection_image_digest" else item for key, item in value.items()})
    for key in ("runtime_source_root", "module_root", "execution_root"):
        _regular_directory(getattr(spec, key))
    if (plan.IMAGE_RE.fullmatch(spec.collection_image_digest) is None
        or spec.host_launcher != spec.execution_root / "qcsd-lab"
        or _read(spec.base_launcher) != _read(spec.runtime_source_root / "qcsd-lab")):
        raise ValueError("installed runtime preflight launcher or image differs")
    _study_profile(spec.execution_root)
    if (os.environ.get("QCSD_LAB_ROOT") != str(spec.runtime_source_root)
        or os.environ.get("QCSD_LAB_IMAGE_DIGEST") != spec.collection_image_digest
        or os.environ.get("QCSD_LAB_SOURCE_METADATA") != str(DEFAULT_SOURCE_METADATA)):
        raise ValueError("rapid plan verification requires the exact installed image source bridge")
    implementation, source, image = _qualification_execution_context()
    _, client_sha = _bound_neqo_client(implementation)
    exported = _load(_read(spec.source_manifest))
    if {**exported, "image_digest": image} != source or set(exported) != SOURCE_METADATA_KEYS:
        raise ValueError("exported image source metadata differs from the installed runtime")
    if _sha(_read(spec.client_binary)) != client_sha:
        raise ValueError("retained client snapshot differs from the installed image client")
    traffic = {key: _sha(_read(spec.execution_root / relative)) for key, (relative, _) in TRAFFIC_FILES.items()}
    if traffic != {key: digest for key, (_, digest) in TRAFFIC_FILES.items()}:
        raise ValueError("installed runtime preflight changes the fixed traffic files")
    return {
        "schema_version": 1, "artifact_type": "qcsd-rapid-v5-installed-runtime-preflight",
        "collection_image_digest": image, "runtime_source": source_metadata(),
        "source_manifest_sha256": _sha(_read(spec.source_manifest)), "client_sha256": client_sha,
        "base_launcher_sha256": _sha(_read(spec.base_launcher)),
        "host_launcher_sha256": _sha(_read(spec.host_launcher)),
        "qualification_implementation": implementation, "traffic_hashes": traffic,
        "formal_accepted_trace_count": 0, "scientific_credit": False,
    }


def executed_image_plan_check(value: Mapping[str, str], *, _context=None) -> dict[str, Any]:
    """Run inside the bound collection image; no caller can supply a pass flag."""
    spec = CaptureSpec(**{key: Path(item) if key in PATH_KEYS else item for key, item in value.items()})
    _check_spec(spec)
    runtime = executed_image_runtime_check({key: value[key] for key in RUNTIME_KEYS})
    stored_plan = admission._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    if stored_plan.get("study_version") == 6:
        from . import rapid_rolling_capture as rolling
        from .rapid_operation_facts import OperationFacts
        context = OperationFacts() if _context is None else _context
        with context.scope():
            result = rolling.image_plan_check(spec, runtime, _context=context)
        context.check()
        return result
    module = _plan_module(spec.module_root)
    result = module.run(_plan_args(spec))
    if (result.get("valid") is not True or type(result.get("formal_accepted_trace_count")) is not int
        or result["formal_accepted_trace_count"] != 0):
        raise ValueError("bound rapid plan did not independently verify")
    context, sites, bindings, generation, _ = module._inputs(_plan_args(spec))
    # The qualification implementation above checked every installed executable
    # and every clean source file. Study overlays retain their own byte inventory.
    module_hashes = {path.relative_to(spec.module_root).as_posix(): _sha(_read(path))
                     for path in sorted((spec.module_root / "src/qcsd_lab").glob("*.py"))}
    module_hashes.update({path.relative_to(spec.module_root).as_posix(): _sha(_read(path))
                         for path in sorted((spec.module_root / "tools").glob("*.py"))})
    return {
        "schema_version": 1, "artifact_type": IMAGE_PROOF_TYPE,
        **{key: runtime[key] for key in ("collection_image_digest", "runtime_source", "source_manifest_sha256",
                                       "client_sha256", "base_launcher_sha256", "host_launcher_sha256",
                                       "qualification_implementation", "traffic_hashes")},
        "overlay_source_hashes": module_hashes,
        "plan_receipt_sha256": _sha(_read(spec.plan_receipt)),
        "plan_payload": admission._unpack(_read(spec.plan_receipt), PLAN_TYPE),
        "bindings": bindings.digests(), "sites": [asdict(site) for site in sites],
        "cohort_generation": generation, "acquisition_provenance_sha256": context.provenance_sha256,
    }


IMAGE_CHECK_SCRIPT = (
    "import json,sys; from qcsd_lab.rapid_lane_evidence import executed_image_plan_check; "
    "print(json.dumps(executed_image_plan_check(json.loads(sys.argv[1])),sort_keys=True,allow_nan=False))"
)


def image_check_command(spec: CaptureSpec, *, capture_control_installation: Path | None = None,
                        inherit_environment: bool = True, campaign_name: str | None = None, _context=None) -> list[str]:
    _check_spec(spec)
    roots = {spec.data_root, spec.runtime_source_root, spec.module_root, spec.execution_root,
             spec.source_manifest.parent, spec.client_binary.parent, spec.base_launcher.parent}
    if admission._unpack(_read(spec.plan_receipt), PLAN_TYPE).get("study_version") == 6:
        from . import rapid_rolling_capture as rolling
        roots.update(rolling.enrollment_roots(spec))
        if campaign_name is not None:
            roots.update(rolling.readiness_roots(spec, campaign_name, _context=_context))
    extra_environment = {}
    plan_payload = admission._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    if "scheduling" in plan_payload:
        from . import rapid_rolling_schedule as schedule
        schedule.require_schedule(plan_payload["scheduling"], spec, declared_at=plan_payload["declared_at"], _context=_context)
        roots.update(schedule.mount_roots(plan_payload["scheduling"], _context=_context))
        extra_environment["QCSD_RAPID_COLLECTION_COMPATIBILITY"] = plan_payload["scheduling"]["path"]
    reference = (str(capture_control_installation) if capture_control_installation is not None
                 else os.environ.get("QCSD_RAPID_COLLECTION_COMPATIBILITY") if inherit_environment else None)
    if reference and _load(_read(Path(reference))).get("receipt_type") == "qcsd-rapid-v5-capture-control-installation-v2":
        if "scheduling" in plan_payload:
            raise ValueError("a rolling schedule cannot also claim a historical installation")
        from . import rapid_capture_control_installation as installation
        capsule_path = Path(reference)
        payload, _ = installation.validate_capsule(capsule_path, actual_image=spec.collection_image_digest)
        installation.check_current_spec(payload, spec)
        roots.add(Path(payload["evidence_root"]))
        for role in (payload["base_spec"], payload["runtime_spec"]):
            roots.update(Path(role[key]) for key in ("data_root", "runtime_source_root", "module_root", "execution_root"))
            roots.update(Path(role[key]).parent for key in ("source_manifest", "client_binary", "base_launcher"))
        extra_environment = {"QCSD_RAPID_COLLECTION_COMPATIBILITY": str(capsule_path),
                             "QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION": str(capsule_path)}
    command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
               "--tmpfs", "/tmp:rw,nosuid,noexec,size=64m"]
    for root in sorted(roots):
        _regular_directory(root)
        command += ["--volume", f"{root}:{root}:ro"]
    for key, value in {
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(spec.module_root / "src"),
        "QCSD_LAB_ROOT": str(spec.runtime_source_root),
        "QCSD_LAB_SOURCE_METADATA": "/usr/share/qcsd-lab/source.json",
        "QCSD_LAB_IMAGE_DIGEST": spec.collection_image_digest,
        **extra_environment,
    }.items():
        command += ["--env", f"{key}={value}"]
    return command + ["--entrypoint", "/opt/qcsd-venv/bin/python3", spec.collection_image_digest,
                      "-c", IMAGE_CHECK_SCRIPT, json.dumps(spec.serializable(), sort_keys=True)]


def _put_object(root: Path, raw: bytes) -> dict[str, str]:
    digest = _sha(raw)
    directory = root / "objects"
    directory.mkdir(exist_ok=True)
    path = directory / digest
    if path.exists():
        if _read(path) != raw:
            raise ValueError("capture evidence object changed")
    else:
        durable_create(path, raw)
    return {"path": f"objects/{digest}", "sha256": digest}


def _object(root: Path, reference: Mapping[str, str]) -> bytes:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise ValueError("capture evidence reference is invalid")
    return _read(admission._child(root, reference))


def _create(root: Path, path: Path, kind: str, payload: Mapping[str, Any]) -> None:
    durable_create(path, _json(admission._bind(kind, payload)))


def _payload(path: Path, kind: str) -> dict[str, Any]:
    return admission._unpack(_read(path), kind)


def _host_intent(raw: bytes) -> dict[str, Any]:
    """Share process evidence without changing historical launch authority."""
    kind = _load(raw).get("receipt_type")
    if kind == INTENT_TYPE:
        return admission._unpack(raw, INTENT_TYPE)
    from .rapid_runtime_epochs import INTENT_TYPE as repaired, CANARY_INTENT_TYPE
    if kind not in {repaired, CANARY_INTENT_TYPE}:
        raise ValueError("unknown rapid host intent")
    return admission._unpack(raw, kind)


def _validate_image_proof(proof: Any, spec: CaptureSpec, *, equivalent_plan: bool = False, _context=None) -> tuple[plan.Site, ...]:
    _check_spec(spec)
    key = ("image-proof", _sha(_json(proof)), _sha(_json(spec.serializable())), equivalent_plan)
    if _context is not None:
        _context.bind_capture(spec)
        if _context.has(key):
            return _context.get(key)
    fields = {"schema_version", "artifact_type", "collection_image_digest", "runtime_source", "source_manifest_sha256",
              "client_sha256", "base_launcher_sha256", "host_launcher_sha256", "qualification_implementation",
              "overlay_source_hashes", "traffic_hashes", "plan_receipt_sha256", "plan_payload", "bindings",
              "sites", "cohort_generation", "acquisition_provenance_sha256"}
    if (not isinstance(proof, dict) or set(proof) != fields or type(proof["schema_version"]) is not int
        or proof["schema_version"] != 1 or proof["artifact_type"] != IMAGE_PROOF_TYPE
        or proof["collection_image_digest"] != spec.collection_image_digest):
        raise ValueError("executed image proof is malformed or has another image")
    from .chaff_qualification import _validate_implementation_receipt, _validate_source
    source = proof["runtime_source"]
    _validate_source(source, spec.collection_image_digest)
    implementation = proof["qualification_implementation"]
    _validate_implementation_receipt(implementation, require_current=False)
    if ({**_load(_read(spec.source_manifest)), "image_digest": spec.collection_image_digest} != source
        or proof["source_manifest_sha256"] != _sha(_read(spec.source_manifest))
        or any(implementation["source"][key] != source[key] for key in SOURCE_METADATA_KEYS - {"image_digest"})
        or proof["client_sha256"] != _sha(_read(spec.client_binary))
        or implementation["neqo_qcsd_client"]["sha256"] != proof["client_sha256"]
        or proof["base_launcher_sha256"] != _sha(_read(spec.base_launcher))
        or implementation["source_files"]["qcsd-lab"] != proof["base_launcher_sha256"]
        or proof["host_launcher_sha256"] != _sha(_read(spec.host_launcher))
        or proof["traffic_hashes"] != {key: digest for key, (_, digest) in TRAFFIC_FILES.items()}):
        raise ValueError("executed image proof source, executable or traffic identities differ")
    for relative, digest in implementation["source_files"].items():
        if _sha(_read(spec.runtime_source_root / relative)) != digest:
            raise ValueError("full clean runtime source differs from the actual installed image proof")
    modules = {path.relative_to(spec.module_root).as_posix(): _sha(_read(path))
               for path in sorted((spec.module_root / "src/qcsd_lab").glob("*.py"))}
    modules.update({path.relative_to(spec.module_root).as_posix(): _sha(_read(path))
                    for path in sorted((spec.module_root / "tools").glob("*.py"))})
    if proof["overlay_source_hashes"] != modules:
        raise ValueError("external study source changed after image plan validation")
    stored_plan = admission._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    if ((not equivalent_plan and (_json(proof["plan_payload"]) != _json(stored_plan)
                                  or proof["plan_receipt_sha256"] != _sha(_read(spec.plan_receipt))))
        or _json(proof["bindings"]) != _json(stored_plan["bindings"])
        or _json(proof["sites"]) != _json(stored_plan["sites"])
        or _json(proof["plan_payload"]["bindings"]) != _json(proof["bindings"])
        or _json(proof["plan_payload"]["sites"]) != _json(proof["sites"])
        or proof["acquisition_provenance_sha256"] != stored_plan["acquisition_provenance_sha256"]
        or proof["cohort_generation"] != stored_plan["cohort_generation"]):
        raise ValueError("executed image proof differs from the retained exact plan")
    sites = tuple(plan.Site(**row) for row in proof["sites"])
    if proof["cohort_generation"] == "rolling-50":
        from . import rapid_rolling_capture as rolling
        actual_sites, _ = rolling.verify_capture_plan(spec, _context=_context)
        if sites != actual_sites:
            raise ValueError("rolling image proof differs from its immutable enrolled batch")
        plan._check_sites(sites, final=True, study_version=6)
    else:
        plan._check_sites(sites, final=proof["cohort_generation"] == "final-50")
    plan._check_workload_files(sites, spec.workload_root)
    return _context.remember(key, sites) if _context is not None else sites


def check_bound_image(spec: CaptureSpec, root: Path, *, campaign_name: str | None = None, _context=None) -> dict[str, Any]:
    """Execute and retain the actual isolated image validator before actuation."""
    command = image_check_command(spec, campaign_name=campaign_name, _context=_context)
    if _context is not None:
        _context.check()
    started = _now()
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=300)
    record = {"command": command, "returncode": result.returncode, "started_at": started, "completed_at": _now(),
              "stdout": _put_object(root, result.stdout.encode()), "stderr": _put_object(root, result.stderr.encode()),
              "validator_script_sha256": _sha(IMAGE_CHECK_SCRIPT.encode())}
    reference = os.environ.get("QCSD_RAPID_COLLECTION_COMPATIBILITY")
    if reference and _load(_read(Path(reference))).get("receipt_type") == "qcsd-rapid-v5-capture-control-installation-v2":
        record["capture_control_installation"] = {"path": str(Path(reference).absolute()), "sha256": _sha(_read(Path(reference)))}
    durable_create(root / f"image-check-{_sha(_json(record))}.json", _json(record))
    if result.returncode != 0:
        raise ValueError("bound collection image plan check failed; raw execution output retained")
    proof = _load(result.stdout.encode())
    _validate_image_proof(proof, spec, _context=_context)
    return {"proof": proof, "execution": record}


def _lane(proof: Mapping[str, Any], campaign_name: str) -> plan.Lane:
    rows = proof["plan_payload"]["lanes"]
    matching = [row for row in rows if row.get("campaign_name") == campaign_name]
    if len(matching) != 1:
        raise ValueError("requested lane is absent or repeated in the independently verified plan")
    row = matching[0]
    return plan.Lane(**{key: tuple(value) if key == "workload_ids" else value
                        for key, value in row.items() if key != "campaign_sha256"})


def verify_dns_receipt(raw: bytes, campaign_name: str, workloads: Mapping[str, bytes]) -> str:
    value = _load(raw)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "campaign", "hosts"}
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["campaign"] != campaign_name or not isinstance(value["hosts"], list)):
        raise ValueError("rapid DNS receipt schema or campaign differs")
    expected = set()
    for workload in workloads.values():
        prepared = _load(workload).get("preparation", {})
        approved = prepared.get("approved_origins")
        if not isinstance(approved, list) or not approved:
            raise ValueError("DNS authority requires every prepared approved origin")
        for origin in approved:
            parsed = urlsplit(origin)
            if parsed.scheme != "https" or parsed.hostname is None:
                raise ValueError("DNS authority contains an invalid approved origin")
            expected.add(parsed.hostname)
    observed = []
    for row in value["hosts"]:
        if not isinstance(row, list) or len(row) != 2 or any(not isinstance(x, str) for x in row):
            raise ValueError("rapid DNS host row is invalid")
        host, address = row
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or not ip.is_global or ip.is_multicast or ip.is_reserved or str(ip) != address:
            raise ValueError("rapid DNS pin is not a canonical public IPv4 address")
        observed.append(host)
    if observed != sorted(expected):
        raise ValueError("rapid DNS pins do not exactly cover all approved workload hostnames")
    return _sha(raw)


@contextmanager
def capture_lock(execution_root: Path, *, lifecycle: bool = False):
    """Serialize this host user's rapid topology across every copied Lab root.

    The adjacent lifecycle guardian retains its own lock while qcsd-lab runs;
    using that same descriptor here would deadlock the child guardian. This
    distinct lock covers adapter preflight through final receipt publication.
    """
    _regular_directory(execution_root)
    parent = _regular_directory(LIFECYCLE_LOCK_PARENT if lifecycle else CAPTURE_LOCK_PARENT)
    metadata = parent.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if not ((metadata.st_uid == 0 and mode & stat.S_ISVTX)
            or (metadata.st_uid == os.getuid() and mode & 0o077 == 0)):
        raise ValueError("shared rapid capture lock parent has unsafe ownership or mode")
    name = "qcsd-docker-lifecycle" if lifecycle else "qcsd-rapid-capture"
    path = parent / f"{name}-{os.getuid()}.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or metadata.st_size != 0):
            raise ValueError("shared rapid capture lock is not a private regular empty file")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # An inherited supervisor descriptor owns the same open file
        # description. Explicit LOCK_UN here would release its live lock.
        yield descriptor
    finally:
        os.close(descriptor)


def _process_identity(pid: int) -> dict[str, Any]:
    root = Path(f"/proc/{pid}")
    raw = (root / "stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    argv = (root / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    return {"pid": pid, "starttime": fields[19], "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "argv": [value.decode() for value in argv], "uid": root.stat().st_uid, "state": fields[0]}


def _retired_identity(identity: Mapping[str, Any]) -> str:
    if (not isinstance(identity, dict) or set(identity) != {"pid", "starttime", "boot_id", "argv", "uid", "state"}
        or type(identity["pid"]) is not int or identity["pid"] <= 0
        or identity["uid"] != os.getuid() or type(identity["uid"]) is not int
        or not isinstance(identity["starttime"], str) or not identity["starttime"].isdigit()
        or not isinstance(identity["argv"], list) or not identity["argv"]
        or any(not isinstance(item, str) for item in identity["argv"])):
        raise ValueError("host-start process identity is malformed")
    if identity["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        return "different-boot"
    try:
        current = _process_identity(identity["pid"])
    except FileNotFoundError:
        return "absent"
    if current["starttime"] != identity["starttime"]:
        return "pid-reused"
    if current["state"] == "Z":
        return "zombie"
    raise ValueError("original host or supervisor process is still alive; wait for it to retire")


HOST_GATE_SCRIPT = (
    "import json,os,sys; command=json.loads(sys.argv[1]); "
    "go=os.read(int(sys.argv[2]),1); "
    "os.close(int(sys.argv[2])); "
    "sys.exit(125) if go!=b'G' else os.execvpe(command[0],command,os.environ)"
)
SUPERVISOR_SCRIPT = (
    "import json,sys; from qcsd_lab.rapid_lane_evidence import _supervise_command; "
    "sys.exit(_supervise_command(json.loads(sys.argv[1]),int(sys.argv[2])))"
)


def _supervise_command(value: Mapping[str, Any], lock_descriptor: int) -> int:
    """Retain the flock and actual host evidence independently of the caller.

    A pipe gate prevents host exec before durable PID/starttime publication.
    If this supervisor dies before publication, EOF retires the blocked gate.
    """
    root = _regular_directory(Path(value["evidence_root"]))
    directory = _regular_directory(Path(value["directory"]))
    if not directory.is_relative_to(root):
        raise ValueError("supervisor evidence directory escapes its root")
    intent_path = directory / "intent.json"
    intent = _host_intent(_read(intent_path))
    command = value["command"]
    execution_root = Path(value["execution_root"])
    if (not isinstance(command, list) or len(command) != 3 or command[:2] != [str(execution_root / "qcsd-lab"), "run"]
        or Path(command[2]).stem != intent["campaign_name"]
        or not stat.S_ISREG(os.fstat(lock_descriptor).st_mode)):
        raise ValueError("supervisor does not own the bound host command and inherited lock")
    metadata = os.fstat(lock_descriptor)
    lock_path = Path(os.readlink(f"/proc/self/fd/{lock_descriptor}"))
    linked = lock_path.stat()
    if (lock_path.name != f"qcsd-rapid-capture-{os.getuid()}.lock"
        or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1 or metadata.st_size != 0
        or (metadata.st_dev, metadata.st_ino) != (linked.st_dev, linked.st_ino)):
        raise ValueError("supervisor inherited lock does not bind the shared private topology lock")
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    started = _now()
    child = None
    returncode = None
    failure = None
    read_fd, write_fd = os.pipe()
    try:
        with (directory / "host.stdout.log").open("xb") as stdout, (directory / "host.stderr.log").open("xb") as stderr:
            gate = [sys.executable, "-c", HOST_GATE_SCRIPT, json.dumps(command), str(read_fd)]
            child = subprocess.Popen(gate, stdout=stdout, stderr=stderr, pass_fds=(read_fd,), start_new_session=True)
            os.close(read_fd)
            read_fd = -1
            start = {"command": command, "execution_root": str(execution_root), "started_at": started,
                     "intent_sha256": _sha(_read(intent_path)), "host": _process_identity(child.pid),
                     "supervisor": _process_identity(os.getpid()), "gate_script_sha256": _sha(HOST_GATE_SCRIPT.encode()),
                     "supervisor_script_sha256": _sha(SUPERVISOR_SCRIPT.encode())}
            _create(root, directory / "host-start.json", PROCESS_START_TYPE, start)
            os.write(write_fd, b"G")
            os.close(write_fd)
            write_fd = -1
            def forward(signum, _frame):
                if child.poll() is None:
                    os.killpg(child.pid, signum)
            for watched in (signal.SIGINT, signal.SIGTERM):
                signal.signal(watched, forward)
            returncode = child.wait()
    except BaseException as error:
        failure = {"type": type(error).__name__, "message": str(error)}
        if child is not None and child.poll() is None:
            if write_fd >= 0:
                os.close(write_fd)
                write_fd = -1
            child.wait()
        raise
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                os.close(descriptor)
        _create(root, directory / "host-process.json", PROCESS_TYPE, {
            "command": command, "execution_root": str(execution_root), "started_at": started, "completed_at": _now(),
            "returncode": returncode, "interruption": failure,
            "start": _put_object(root, _read(directory / "host-start.json")) if (directory / "host-start.json").is_file() else None,
            "stdout": _put_object(root, _read(directory / "host.stdout.log")) if (directory / "host.stdout.log").exists() else None,
            "stderr": _put_object(root, _read(directory / "host.stderr.log")) if (directory / "host.stderr.log").exists() else None,
        })
    return 0


def _actuate_host(spec: CaptureSpec, root: Path, directory: Path, command: list[str], env: Mapping[str, str], lock_descriptor: int) -> None:
    value = {"evidence_root": str(root), "directory": str(directory), "command": command, "execution_root": str(spec.execution_root)}
    worker_env = {**env, "PYTHONPATH": str(spec.module_root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    with (directory / "supervisor.stdout.log").open("xb") as stdout, (directory / "supervisor.stderr.log").open("xb") as stderr:
        child = subprocess.Popen([sys.executable, "-c", SUPERVISOR_SCRIPT, json.dumps(value), str(lock_descriptor)],
                                 env=worker_env, stdout=stdout, stderr=stderr,
                                 pass_fds=(lock_descriptor,), start_new_session=True)
        status = child.wait()
    if status != 0:
        raise RuntimeError("host supervisor failed; preserve this attempt and use retire-lane after actual lifecycle cleanup")


def _validated_host_start(raw: bytes, intent_raw: bytes, *, campaign_name: str) -> dict[str, Any]:
    if _load(raw).get("receipt_type") == "qcsd-rapid-v5-parallel-worker-start":
        from .rapid_formal_parallel import verified_worker_start
        return verified_worker_start(raw, intent_raw, campaign_name)
    value = admission._unpack(raw, PROCESS_START_TYPE)
    if (set(value) != {"command", "execution_root", "started_at", "intent_sha256", "host", "supervisor",
                       "gate_script_sha256", "supervisor_script_sha256"}
        or value["intent_sha256"] != _sha(intent_raw)
        or value["gate_script_sha256"] != _sha(HOST_GATE_SCRIPT.encode())
        or value["supervisor_script_sha256"] != _sha(SUPERVISOR_SCRIPT.encode())
        or not isinstance(value["execution_root"], str) or not Path(value["execution_root"]).is_absolute()
        or not isinstance(value["command"], list) or len(value["command"]) != 3
        or value["command"][:2] != [str(Path(value["execution_root"]) / "qcsd-lab"), "run"]
        or Path(value["command"][2]).stem != campaign_name):
        raise ValueError("host-start receipt does not prove the exact bound command")
    intent = _host_intent(intent_raw)
    if admission._utc(value["started_at"]) < admission._utc(intent["started_at"]):
        raise ValueError("actual host start predates the launch intent")
    for key, script in (("host", HOST_GATE_SCRIPT), ("supervisor", SUPERVISOR_SCRIPT)):
        identity = value[key]
        if (not isinstance(identity, dict) or set(identity) != {"pid", "starttime", "boot_id", "argv", "uid", "state"}
            or type(identity["pid"]) is not int or identity["pid"] <= 0
            or type(identity["uid"]) is not int or identity["uid"] < 0
            or not isinstance(identity["starttime"], str) or not identity["starttime"].isdigit()
            or not isinstance(identity["boot_id"], str) or len(identity["boot_id"]) != 36
            or not isinstance(identity["argv"], list) or len(identity["argv"]) != 5
            or not isinstance(identity["argv"][0], str) or not Path(identity["argv"][0]).is_absolute()
            or identity["argv"][1:3] != ["-c", script]
            or not identity["argv"][4].isdigit()):
            raise ValueError("actual host/supervisor birth identity is invalid")
    if _load(value["host"]["argv"][3].encode()) != value["command"]:
        raise ValueError("retained host gate argv differs from the intended execution")
    worker = _load(value["supervisor"]["argv"][3].encode())
    if worker.get("command") != value["command"] or worker.get("execution_root") != value["execution_root"]:
        raise ValueError("retained actual supervisor argv differs from the host command")
    return value


def _verified_host_process(raw: bytes, root: Path, intent_raw: bytes, campaign_name: str) -> dict[str, Any]:
    if _load(raw).get("receipt_type") == "qcsd-rapid-v5-parallel-worker-process":
        from .rapid_formal_parallel import verified_worker_process
        return verified_worker_process(raw, root, intent_raw, campaign_name)
    value = admission._unpack(raw, PROCESS_TYPE)
    if (set(value) != {"command", "execution_root", "started_at", "completed_at", "returncode", "interruption", "start", "stdout", "stderr"}
        or (type(value["returncode"]) is not int and value["returncode"] is not None)
        or (value["interruption"] is None and value["returncode"] is None)):
        raise ValueError("actual terminal host-process schema is invalid")
    if value["interruption"] is not None and (
        not isinstance(value["interruption"], dict) or set(value["interruption"]) != {"type", "message"}
        or any(not isinstance(item, str) for item in value["interruption"].values())
    ):
        raise ValueError("retained host interruption is not a typed actual exception")
    start = _validated_host_start(_object(root, value["start"]), intent_raw, campaign_name=campaign_name)
    if (any(_json(value[key]) != _json(start[key]) for key in ("command", "execution_root", "started_at"))
        or not admission._utc(start["started_at"]) <= admission._utc(value["completed_at"]) <= datetime.now(UTC)):
        raise ValueError("actual terminal host process differs from its durable birth evidence")
    for key in ("stdout", "stderr"):
        _object(root, value[key])
    return value


def _retirement_quiescence(root: Path, lifecycle_descriptor: int) -> dict[str, Any]:
    uid = os.getuid()
    processes = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != uid:
                continue
            identity = _process_identity(int(directory.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        if identity["uid"] != uid or identity["state"] == "Z":
            continue
        for item in identity["argv"]:
            target = item
            if item.startswith("/proc/self/fd/"):
                try:
                    target = str((directory / "fd" / Path(item).name).resolve(strict=True))
                except FileNotFoundError:
                    continue
            if (Path(target).name in {"qcsd-lab", "docker_lifecycle_lock_guardian.py", "docker_signal_supervisor.sh"}
                or "qcsd-docker-supervisor" in target):
                processes.append(identity)
                break
    if processes:
        raise ValueError("a QCSD host/guardian/supervisor is still live; finish lifecycle cleanup before retire-lane")
    sockets = Path("/proc/net/unix").read_bytes()
    if f"@qcsd-docker-lifecycle-guardian-{uid}".encode() in sockets:
        raise ValueError("the lifecycle guardian socket remains live")
    namespace = LIFECYCLE_LOCK_PARENT / f"qcsd-docker-lifecycle-{uid}"
    entries = []
    if namespace.exists():
        _regular_directory(namespace)
        entries = [path.name for path in namespace.iterdir()
                   if path.name.startswith(("run.", "network.", "build.", "transaction.", "retirement.", ".retired."))]
    if entries:
        raise ValueError("durable Docker lifecycle ownership remains; recover it before retire-lane")
    executions = _retirement_docker_absence(root)
    metadata = os.fstat(lifecycle_descriptor)
    return {"lifecycle_lock": {"path": str(LIFECYCLE_LOCK_PARENT / f"qcsd-docker-lifecycle-{uid}.lock"),
                               "device": metadata.st_dev, "inode": metadata.st_ino, "uid": metadata.st_uid,
                               "mode": stat.S_IMODE(metadata.st_mode), "links": metadata.st_nlink, "size": metadata.st_size},
            "guardian_processes": processes, "guardian_sockets": _put_object(root, sockets),
            "lifecycle_entries": entries, "docker_executions": executions}


def _retirement_docker_absence(root: Path) -> list[dict[str, Any]]:
    executions = []
    env = {key: item for key, item in os.environ.items() if key not in {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"}}
    env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    with tempfile.TemporaryDirectory(prefix="retirement-docker-", dir=root) as config:
        for operation in (("ps", "--all", "--quiet"), ("network", "ls", "--quiet")):
            command = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", config,
                       *operation, "--filter", "label=org.qcsd.owner=qcsd-lab"]
            result = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    check=False, timeout=30)
            record = {"command": command, "returncode": result.returncode, "stdout": _put_object(root, result.stdout.encode()),
                      "stderr": _put_object(root, result.stderr.encode())}
            durable_create(root / f"retirement-check-{_sha(_json(record))}.json", _json(record))
            executions.append(record)
            if result.returncode != 0 or result.stdout.strip():
                raise ValueError("owned Docker containers/networks remain or actual absence query failed; preserve and clean lifecycle")
    return executions


def _prebirth_batch_proof(spec, root, intent_path, authority_path, output, public_started, public_completed):
    """Reopen one failed official batch before its mandatory durable preflight.

    The launcher hashes identify reviewed Source with a durable preflight and
    batch initialization before every measured worker birth. An exit status or
    a missing worker start by itself never supplies this authority.
    """
    from . import rapid_formal_parallel as formal
    from . import rapid_parallel_capture as parallel
    authority_path = authority_path.absolute()
    output = _regular_directory(output)
    value, facts = formal._audit(authority_path)
    matches = [index for index, fact in enumerate(facts)
               if fact[0] == spec and fact[1] == root and fact[2] == intent_path]
    if len(matches) != 1 or not output.is_relative_to(spec.execution_root / "results"):
        raise ValueError("prebirth retirement does not bind one exact official batch lane")
    index = matches[0]
    _, _, _, intent, _, lane, _ = facts[index]
    if (lane.study_version != 6 or lane.role != "formal" or lane.generation != 1
        or intent["actuator"] != "parallel-formal-worker"):
        raise ValueError("prebirth retirement is only an unstarted rolling formal initial generation")
    source = _read(spec.host_launcher)
    # These complete historical launchers retain write-once image-preflight
    # and batch initialization before any worker creation. Do not
    # infer this order from an arbitrary launcher containing matching strings.
    reviewed = {
        "0c1d2ed0364b9159e9acf8d1c45eb4fec2b661ec65d4165e88d5eb03c6466900",
        "42489d4b66b004787c6a827084f311d6916c21f810ffd9373b2627df76a36d39",
        "fe6a857e07b0a1376de788c8d15f933a90a6518a3811de843227e5700add5043",
    }
    if (_sha(source) not in reviewed or _sha(source) != intent["runtime_identity"]["host_launcher_sha256"]
        or _sha(_read(spec.base_launcher)) != intent["runtime_identity"]["base_launcher_sha256"]):
        raise ValueError("prebirth retirement lacks reviewed original Source before worker birth")
    expected = {"operator-intent.json", "host-start.json", "host-process.json",
                "host.stdout", "host.stderr", "blocked.json"}
    if {path.name for path in output.iterdir()} != expected:
        raise ValueError("prebirth batch has progressed beyond the absent durable preflight boundary")
    for fact in facts:
        worker_spec, _, worker_intent, _, _, worker_lane, _ = fact
        names = {path.name for path in worker_intent.parent.iterdir()}
        if "retirement.json" in names:
            previous = _payload(worker_intent.parent / "retirement.json", "qcsd-rapid-v6-observed-prebirth-lane-retirement")
            retained = previous["proof"]
            if (previous["scientific_credit"] is not False or retained["batch_root"] != str(output)
                or retained["campaign_name"] != worker_lane.campaign_name
                or retained["authority"] != {"path": str(authority_path), "sha256": _sha(_read(authority_path))}
                or _object(root, retained["intent"]) != _read(worker_intent)):
                raise ValueError("peer prebirth retirement belongs to another original batch")
            names.remove("retirement.json")
        if (names != {"intent.json", "lineage.json"}
            or (worker_spec.execution_root / "results" / worker_lane.campaign_name).exists()
            or (worker_spec.execution_root / "results" / worker_lane.campaign_name).is_symlink()):
            raise ValueError("prebirth batch retains worker birth, result or completion evidence")
    parallel.verify_operator_closure(authority_path, output, value)
    start = parallel.load(output / "host-start.json")
    process = parallel.load(output / "host-process.json")
    operator = parallel.load(output / "operator-intent.json")
    blocked = parallel.load(output / "blocked.json")
    if (process["returncode"] == 0 or process.get("scientific_credit") is not False
        or any(type(row.get("formal_accepted_trace_count")) is not int
               or row["formal_accepted_trace_count"] != 0 for row in (process, operator, blocked))
        or operator.get("scientific_credit") is not False or blocked.get("scientific_credit") is not False
        or operator["operator_implementation_sha256"] != _sha(_read(spec.module_root / "tools/rapid_parallel_capture.py"))
        or admission._utc(operator["created_at"]) < admission._utc(intent["started_at"])
        or admission._utc(start["started_at"]) < admission._utc(operator["created_at"])
        or admission._utc(blocked["observed_at"]) < admission._utc(process["completed_at"])):
        raise ValueError("prebirth batch lacks exact closed failed zero-credit operator evidence")
    public_started, public_completed = public_started.absolute(), public_completed.absolute()
    if (public_started.parent != public_completed.parent
        or not public_completed.name.endswith("-completed.json")
        or public_started.name != public_completed.name.removesuffix("-completed.json") + "-started.json"):
        raise ValueError("prebirth public closure paths do not identify one recorded invocation")
    prefix = public_completed.name.removesuffix("-completed.json")
    public_paths = {"started": public_started, "completed": public_completed,
                    "stdout": public_completed.parent / (prefix + ".stdout.log"),
                    "stderr": public_completed.parent / (prefix + ".stderr.log")}
    before, after = _load(_read(public_started)), _load(_read(public_completed))
    argv = before.get("command")
    if isinstance(argv, list) and argv[:2] == ["env", "PYTHONDONTWRITEBYTECODE=1"]:
        argv = argv[2:]
    if (not isinstance(argv, list) or len(argv) != 9 or not Path(argv[0]).is_absolute()
        or argv[1:] != ["-I", "-B", str(spec.module_root / "tools/rapid_parallel_capture.py"),
                           "launch", "--authority", str(authority_path), "--output", str(output)]
        or type(after.get("returncode")) is not int or after["returncode"] == 0
        or admission._utc(before["started_at"]) > admission._utc(start["started_at"])
        or admission._utc(after["completed_at"]) < admission._utc(process["completed_at"])
        or admission._utc(after["completed_at"]) > admission._utc(_now())
        or any(after.get(key + "_sha256") != _sha(_read(public_paths[key])) for key in ("stdout", "stderr"))):
        raise ValueError("prebirth retirement lacks the actual closed public batch invocation")
    return {"authority": {"path": str(authority_path), "sha256": _sha(_read(authority_path))},
            "spec": spec.serializable(), "intent": _put_object(root, _read(intent_path)),
            "campaign_name": lane.campaign_name, "execution_root": str(spec.execution_root),
            "batch_root": str(output), "worker_index": index, "source_before_worker_birth": _put_object(root, source),
            "batch_inventory": {name: _put_object(root, _read(output / name)) for name in sorted(expected)},
            "public_execution": {key: {"path": str(path), "object": _put_object(root, _read(path))}
                                 for key, path in public_paths.items()}}


def _verified_retirement_checks(checks, root, uid):
    """Reopen the retained actual lifecycle census without new live queries."""
    if (set(checks) != {"lifecycle_lock", "guardian_processes", "guardian_sockets", "lifecycle_entries", "docker_executions"}
        or checks["guardian_processes"] != [] or checks["lifecycle_entries"] != [] or len(checks["docker_executions"]) != 2):
        raise ValueError("retirement does not retain quiescent actual lifecycle observations")
    lock = checks["lifecycle_lock"]
    if (set(lock) != {"path", "device", "inode", "uid", "mode", "links", "size"}
        or lock["path"] != str(LIFECYCLE_LOCK_PARENT / f"qcsd-docker-lifecycle-{uid}.lock")
        or any(type(lock[key]) is not int for key in ("device", "inode", "uid", "mode", "links", "size"))
        or lock["uid"] != uid or lock["mode"] != 0o600 or lock["links"] != 1 or lock["size"] != 0):
        raise ValueError("retirement lacks the actual private lifecycle lock identity")
    if f"@qcsd-docker-lifecycle-guardian-{uid}".encode() in _object(root, checks["guardian_sockets"]):
        raise ValueError("retirement retained a live guardian socket")
    for execution, operation in zip(checks["docker_executions"], (("ps", "--all", "--quiet"), ("network", "ls", "--quiet")), strict=True):
        command = execution["command"]
        if (type(execution["returncode"]) is not int or execution["returncode"] != 0 or len(command) != 10
            or command[:5] != ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", command[4]]
            or command[5:] != [*operation, "--filter", "label=org.qcsd.owner=qcsd-lab"]
            or _object(root, execution["stdout"]).strip()):
            raise ValueError("retirement does not prove actual empty owned Docker inventories")
        _object(root, execution["stderr"])


def _retire_prebirth_lane(spec, root, intent_path, authority_path, output, public_started, public_completed):
    proof = _prebirth_batch_proof(spec, root, intent_path, authority_path, output, public_started, public_completed)
    start = _load(_object(root, proof["batch_inventory"]["host-start.json"]))
    retired = {key: _retired_identity(start[key]) for key in ("host", "operator")}
    with capture_lock(spec.execution_root, lifecycle=True) as descriptor:
        checks = _retirement_quiescence(root, descriptor)
        if (proof != _prebirth_batch_proof(spec, root, intent_path, authority_path, output, public_started, public_completed)
            or retired != {key: _retired_identity(start[key]) for key in retired}):
            raise ValueError("prebirth batch or process census changed during locked retirement")
        _verified_retirement_checks(checks, root, start["host"]["uid"])
        payload = {"proof": proof, "observed_at": _now(), "retired_batch_processes": retired,
                   "checks": checks, "scientific_credit": False}
        path = intent_path.parent / "retirement.json"
        _create(root, path, "qcsd-rapid-v6-observed-prebirth-lane-retirement", payload)
    return path


def _verified_prebirth_retirement(raw, root, intent_raw, campaign_name):
    value = admission._unpack(raw, "qcsd-rapid-v6-observed-prebirth-lane-retirement")
    if (set(value) != {"proof", "observed_at", "retired_batch_processes", "checks", "scientific_credit"}
        or value["scientific_credit"] is not False or set(value["retired_batch_processes"]) != {"host", "operator"}
        or any(item not in {"absent", "pid-reused", "different-boot", "zombie"}
               for item in value["retired_batch_processes"].values())):
        raise ValueError("prebirth retirement fields or actual process dispositions differ")
    proof = value["proof"]
    spec = CaptureSpec(**{key: Path(item) if key in PATH_KEYS else item for key, item in proof["spec"].items()})
    intent_path = root / "lanes" / campaign_name / "intent.json"
    public = proof["public_execution"]
    expected = _prebirth_batch_proof(spec, root, intent_path, Path(proof["authority"]["path"]),
                                    Path(proof["batch_root"]), Path(public["started"]["path"]), Path(public["completed"]["path"]))
    if (proof != expected or _object(root, proof["intent"]) != intent_raw or proof["campaign_name"] != campaign_name
        or admission._utc(value["observed_at"]) < admission._utc(_load(_object(root, public["completed"]["object"]))["completed_at"])):
        raise ValueError("prebirth retirement changed its exact original failed batch proof")
    start = _load(_object(root, proof["batch_inventory"]["host-start.json"]))
    _verified_retirement_checks(value["checks"], root, start["host"]["uid"])
    return {**value, "execution_root": proof["execution_root"], "campaign_name": campaign_name,
            "actuator": "parallel-formal-worker"}


def retire_lane(spec: CaptureSpec, root: Path, intent_path: Path, *, batch_authority=None,
                batch_output=None, public_started=None, public_completed=None) -> Path:
    """Observe a lost supervisor attempt as retired, granting no completion."""
    root = _regular_directory(root)
    with capture_lock(spec.execution_root):
        intent, _, lane, _ = _intent_and_lineage(spec, root, intent_path)
        directory = intent_path.parent
        if (directory / "complete.json").exists() or (directory / "host-process.json").exists():
            raise ValueError("attempt already has actual terminal process evidence; retain it and use a fresh successor if incomplete")
        start_path = directory / "host-start.json"
        if not start_path.is_file():
            references = (batch_authority, batch_output, public_started, public_completed)
            if any(path is not None for path in references):
                if any(path is None for path in references):
                    raise ValueError("prebirth retirement requires all exact batch and public closure references")
                return _retire_prebirth_lane(spec, root, intent_path, *references)
            raise ValueError("no durable host-start proof; quarantine this physical lane and inspect the pre-exec window; it cannot be retired by declaration")
        if any(path is not None for path in (batch_authority, batch_output, public_started, public_completed)):
            raise ValueError("a born worker cannot use prebirth retirement")
        start_raw = _read(start_path)
        start = _validated_host_start(start_raw, _read(intent_path), campaign_name=lane.campaign_name)
        retired = {key: _retired_identity(start[key]) for key in ("host", "supervisor")}
        with capture_lock(spec.execution_root, lifecycle=True) as descriptor:
            checks = _retirement_quiescence(root, descriptor)
            # Recheck identities after Docker observations while both locks hold.
            if retired != {key: _retired_identity(start[key]) for key in retired}:
                raise ValueError("original process census changed during retirement observation")
            payload = {"command": start["command"], "execution_root": start["execution_root"],
                       "started_at": start["started_at"], "observed_at": _now(), "scientific_credit": False,
                       "host_start": _put_object(root, start_raw), "retired_processes": retired, "checks": checks}
            output = directory / "retirement.json"
            _create(root, output, RETIREMENT_TYPE, payload)
    return output


def _verified_retirement(raw: bytes, root: Path, intent_raw: bytes, campaign_name: str) -> dict[str, Any]:
    if _load(raw).get("receipt_type") == "qcsd-rapid-v6-observed-prebirth-lane-retirement":
        return _verified_prebirth_retirement(raw, root, intent_raw, campaign_name)
    if _load(raw).get("receipt_type") == "qcsd-rapid-v5-parallel-worker-retirement":
        from .rapid_formal_parallel import verified_worker_retirement
        return verified_worker_retirement(raw, root, intent_raw, campaign_name)
    value = admission._unpack(raw, RETIREMENT_TYPE)
    if (set(value) != {"command", "execution_root", "started_at", "observed_at", "scientific_credit", "host_start", "retired_processes", "checks"}
        or value["scientific_credit"] is not False
        or not isinstance(value["retired_processes"], dict) or set(value["retired_processes"]) != {"host", "supervisor"}
        or any(item not in {"absent", "pid-reused", "different-boot", "zombie"} for item in value["retired_processes"].values())):
        raise ValueError("interrupted lane retirement schema is invalid")
    start = _validated_host_start(_object(root, value["host_start"]), intent_raw, campaign_name=campaign_name)
    if any(_json(value[key]) != _json(start[key]) for key in ("command", "execution_root", "started_at")):
        raise ValueError("retirement differs from its actual original process start")
    if admission._utc(value["observed_at"]) < admission._utc(start["started_at"]):
        raise ValueError("retirement observation predates the actual start")
    _verified_retirement_checks(value["checks"], root, start["host"]["uid"])
    return value


def _lineage_payload(spec: CaptureSpec, lane: plan.Lane, checked: Mapping[str, Any], root: Path,
                     predecessor_receipt: Path | None, *, _context=None) -> dict[str, Any]:
    proof = checked["proof"]
    rolling_readiness = {}
    scheduling_capsule = None
    if lane.study_version == 6:
        from . import rapid_rolling_capture as rolling
        rolling_readiness = {"rolling_readiness": rolling.require_mode_readiness(spec, lane, before=checked["execution"]["started_at"], _context=_context)}
        payload = _payload(spec.plan_receipt, PLAN_TYPE)
        if "scheduling" in payload:
            from .rapid_rolling_schedule import require_schedule
            scheduling_capsule = require_schedule(payload["scheduling"], spec, declared_at=payload["declared_at"], started_at=checked["execution"]["started_at"], _context=_context)
            rolling_readiness["rolling_scheduling"] = payload["scheduling"]
    installation_reference = checked["execution"].get("capture_control_installation")
    if installation_reference is not None:
        from . import rapid_capture_control_installation as installation
        if (not isinstance(installation_reference, dict) or set(installation_reference) != {"path", "sha256"}
            or not Path(installation_reference["path"]).is_absolute()
            or _sha(_read(Path(installation_reference["path"]))) != installation_reference["sha256"]):
            raise ValueError("lane image check changed its capture-control installation")
        payload, _ = installation.validate_capsule(Path(installation_reference["path"]), actual_image=spec.collection_image_digest)
        installation.check_current_spec(payload, spec)
        if payload["evidence_root"] != str(root) or admission._utc(checked["execution"]["started_at"]) < admission._utc(payload["published_at"]):
            raise ValueError("lane image check predates its actual capture-control installation")
    source = proof["runtime_source"]
    predecessor_name = predecessor_sha = None
    predecessor = None
    predecessor_attempt = None
    predecessor_spec = spec
    if lane.generation > 1:
        if predecessor_receipt is None:
            raise ValueError("fresh recovery generation requires actual immediate predecessor evidence")
        if (predecessor_receipt.parent / "complete.json").exists():
            raise ValueError("a completed lane cannot be selectively recaptured under this recovery policy")
        predecessor = _payload(predecessor_receipt, INTENT_TYPE)
        predecessor_name = plan._campaign_name(lane.role, lane.block, lane.shard, lane.mode, lane.generation - 1, lane.study_version)
        predecessor_path = spec.campaign_dir / f"{predecessor_name}.yml"
        predecessor_sha = _sha(_read(predecessor_path))
        if (predecessor["campaign_name"] != predecessor_name or predecessor["campaign_sha256"] != predecessor_sha
            or predecessor["bindings"] != proof["bindings"]):
            raise ValueError("source-changing recovery is unsupported without independently verified targeted proof")
        expected_runtime = {"collection_image_digest": spec.collection_image_digest, "runtime_source": source,
            "client_sha256": proof["client_sha256"], "base_launcher_sha256": proof["base_launcher_sha256"],
            "host_launcher_sha256": proof["host_launcher_sha256"], "traffic_hashes": proof["traffic_hashes"]}
        if predecessor["runtime_identity"] != expected_runtime:
            if scheduling_capsule is None:
                raise ValueError("source-changing recovery is unsupported without independently verified targeted proof")
            from .rapid_rolling_schedule import _spec
            predecessor_spec = _spec(scheduling_capsule["base_spec"])
            # The capsule permits only unchanged capture physics. Keep the
            # original attempt on its own runtime and process paths.
            original, _, original_lane, _ = _intent_and_lineage(predecessor_spec, root, predecessor_receipt)
            if (predecessor_receipt != root / "lanes" / predecessor_name / "intent.json"
                or original != predecessor or original_lane.logical_name != lane.logical_name
                or original_lane.generation != lane.generation - 1
                or admission._utc(original["started_at"]) > admission._utc(scheduling_capsule["published_at"])):
                raise ValueError("rolling recovery changed its original source-bound failed predecessor")
        process_path = predecessor_receipt.parent / "host-process.json"
        retirement_path = predecessor_receipt.parent / "retirement.json"
        if not process_path.is_file() and not retirement_path.is_file():
            raise ValueError("predecessor has no actual terminal process or verified retirement evidence; run retire-lane after lifecycle cleanup")
        if retirement_path.is_file():
            _verified_retirement(_read(retirement_path), root, _read(predecessor_receipt), predecessor_name)
        if process_path.is_file():
            _verified_host_process(_read(process_path), root, _read(predecessor_receipt), predecessor_name)
        # Existing partial result bytes stay untouched. Generic resume is never invoked.
        predecessor_attempt = {
            "host_process": _put_object(root, _read(process_path)) if process_path.is_file() else None,
            "retirement": _put_object(root, _read(retirement_path)) if retirement_path.is_file() else None,
            "inventory": {path.relative_to(predecessor_receipt.parent).as_posix(): _put_object(root, _read(path))
                          for path in sorted(predecessor_receipt.parent.rglob("*")) if path.is_file()},
            "result_inventory": {
                path.relative_to(predecessor_spec.execution_root / "results" / predecessor_name).as_posix(): _put_object(root, _read(path))
                for path in sorted((predecessor_spec.execution_root / "results" / predecessor_name).rglob("*")) if path.is_file()
            },
        }
    bindings = proof["bindings"]
    artifacts = {
        key: _put_object(root, _read(path)) for key, path in {
            "source_manifest": spec.source_manifest, "client_binary": spec.client_binary,
            "base_launcher": spec.base_launcher, "host_launcher": spec.host_launcher,
            "plan_receipt": spec.plan_receipt, "cohort": spec.cohort,
            "study_profile": _study_profile(spec.execution_root),
        }.items()
    }
    artifacts.update({key: _put_object(root, _read(spec.execution_root / relative)) for key, (relative, _) in TRAFFIC_FILES.items()})
    return {
        "execution_generation": spec.execution_generation, "profile_receipt_sha256": bindings["profile_sha256"],
        "cohort_receipt_sha256": bindings["cohort_sha256"],
        **({"selection_amendment_sha256": bindings["selection_amendment_sha256"]} if "selection_amendment_sha256" in bindings else {}),
        **proof["traffic_hashes"], "collection_image_digest": spec.collection_image_digest,
        "lab_commit": source["lab_commit"], "base_launcher_sha256": proof["base_launcher_sha256"],
        "host_launcher_sha256": proof["host_launcher_sha256"], "equivalent_to_cohort": True,
        "predecessor_campaign_name": predecessor_name, "predecessor_campaign_sha256": predecessor_sha,
        "predecessor_intent": _put_object(root, _read(predecessor_receipt)) if predecessor_receipt else None,
        "predecessor_attempt": predecessor_attempt, "artifacts": artifacts, "image_check": checked,
        **({"capture_control_installation": installation_reference} if installation_reference is not None else {}),
        **rolling_readiness,
    }


def prepare_lane_intent(spec: CaptureSpec, evidence_root: Path, campaign_name: str,
                        checked: Mapping[str, Any], *, predecessor_intent: Path | None = None,
                        actuator: str = "run", _prepared_lineage: Mapping[str, Any] | None = None, _context=None) -> Path:
    """Claim the ordinary lane identity after the actual immutable-image check.

    Both actuators use the same plan, lineage and failed-only predecessor rules.
    This helper creates no process, result namespace or scientific completion.
    Its caller holds the capture lock while claiming the create-only lane.
    """
    root = _regular_directory(evidence_root)
    if actuator not in {"run", "parallel-formal-worker"}:
        raise ValueError("unknown lane actuator")
    directory = root / "lanes" / campaign_name
    if directory.exists() or directory.is_symlink():
        raise FileExistsError("rapid physical lane destination is already claimed")
    sites = _validate_image_proof(checked["proof"], spec, _context=_context)
    lane = _lane(checked["proof"], campaign_name)
    if lane.study_version == 6:
        if actuator != "run":
            from .rapid_rolling_schedule import require_schedule
            payload = _payload(spec.plan_receipt, PLAN_TYPE)
            require_schedule(payload.get("scheduling"), spec, declared_at=payload["declared_at"], started_at=checked["execution"]["started_at"], _context=_context)
    campaign = spec.campaign_dir / f"{campaign_name}.yml"
    if _read(campaign) != plan.render_lane_campaign(lane, sites):
        raise ValueError("launch campaign differs from the independently verified grid")
    namespace = spec.execution_root / "results" / lane.campaign_name
    if namespace.exists() or namespace.is_symlink():
        raise FileExistsError("physical campaign namespace already contains an unbound or prior attempt")
    lineage = (_lineage_payload(spec, lane, checked, root, predecessor_intent, _context=_context)
               if _prepared_lineage is None else dict(_prepared_lineage))
    if (_prepared_lineage is not None and (actuator != "parallel-formal-worker"
        or lineage.get("image_check") != checked
        or lineage.get("predecessor_intent") != (
            _put_object(root, _read(predecessor_intent)) if predecessor_intent else None))):
        raise ValueError("parallel prepared lineage differs from its checked image or immediate predecessor")
    if _context is not None:
        _context.check()
    directory.mkdir(parents=True)
    lineage_path = directory / "lineage.json"
    _create(root, lineage_path, LINEAGE_TYPE, lineage)
    identity = {"collection_image_digest": spec.collection_image_digest, "runtime_source": checked["proof"]["runtime_source"],
                "client_sha256": checked["proof"]["client_sha256"], "base_launcher_sha256": lineage["base_launcher_sha256"],
                "host_launcher_sha256": lineage["host_launcher_sha256"], "traffic_hashes": checked["proof"]["traffic_hashes"]}
    intent = {
        "campaign_name": campaign_name, "campaign_sha256": _sha(_read(campaign)),
        "logical_lane": lane.logical_name, "generation": lane.generation,
        "bindings": checked["proof"]["bindings"], "runtime_identity": identity,
        "lineage": {"path": lineage_path.relative_to(root).as_posix(), "sha256": _sha(_read(lineage_path))},
        "started_at": _now(), "actuator": actuator, "scientific_credit": False,
    }
    intent_path = directory / "intent.json"
    _create(root, intent_path, INTENT_TYPE, intent)
    return intent_path


def launch_lane(spec: CaptureSpec, evidence_root: Path, campaign_name: str, *, predecessor_intent: Path | None = None) -> Path:
    """Launch exactly one verified lane, retaining every process outcome."""
    root = _regular_directory(evidence_root)
    with capture_lock(spec.execution_root) as lock_descriptor:
        # Retain the early create-only check before the potentially costly image call.
        directory = root / "lanes" / campaign_name
        if directory.exists() or directory.is_symlink():
            raise FileExistsError("rapid physical lane destination is already claimed")
        checked = check_bound_image(spec, root, campaign_name=campaign_name)
        intent_path = prepare_lane_intent(spec, root, campaign_name, checked, predecessor_intent=predecessor_intent)
        campaign = spec.campaign_dir / f"{campaign_name}.yml"
        env = dict(os.environ)
        env.update(QCSD_LAB_COLLECTION_IMAGE=spec.collection_image_digest,
                   QCSD_RAPID_IMAGE_SOURCE_QCSD=str(spec.base_launcher),
                   QCSD_RAPID_V5_PROFILE_PATH=str(_study_profile(spec.execution_root)),
                   QCSD_RAPID_DNS_RECEIPT_PATH=str(directory / "dns.json"))
        lane = _lane(checked["proof"], campaign_name)
        if lane.study_version == 6:
            from . import rapid_rolling_capture as rolling
            payload = _payload(spec.plan_receipt, PLAN_TYPE)
            if "scheduling" in payload:
                env["QCSD_RAPID_COLLECTION_COMPATIBILITY"] = payload["scheduling"]["path"]
            env["QCSD_RAPID_ROLLING_LAUNCH_INPUT"] = _json({"spec": spec.serializable(), "root": str(root),
                "intent": str(intent_path), "intent_sha256": _sha(_read(intent_path)),
                "readiness_mount_roots": [str(path) for path in rolling.readiness_roots(spec, campaign_name)]}).decode()
        command = [str(spec.host_launcher), "run", str(campaign)]
        _actuate_host(spec, root, directory, command, env, lock_descriptor)
        returncode = _payload(directory / "host-process.json", PROCESS_TYPE)["returncode"]
        if lane.study_version == 6:
            from . import rapid_rolling_capture as rolling
            completed = Path(rolling.check_lane_in_image(spec, root, intent_path, complete=True)["receipt"])
        else:
            completed = complete_lane(spec, root, intent_path)
        if returncode != 0:
            raise RuntimeError(f"deep-verified lane receipt retained at {completed}; host exit {returncode} needs lifecycle diagnosis")
        return completed


def _intent_and_lineage(spec: CaptureSpec, root: Path, intent_path: Path, *, _context=None) -> tuple[dict[str, Any], dict[str, Any], plan.Lane, tuple[plan.Site, ...]]:
    intent = _payload(intent_path, INTENT_TYPE)
    lineage = _payload(admission._child(root, intent["lineage"]), LINEAGE_TYPE)
    checked = lineage["image_check"]
    installation_reference = checked["execution"].get("capture_control_installation")
    if lineage.get("capture_control_installation") != installation_reference:
        raise ValueError("lane lineage differs from its actual image-check installation")
    if installation_reference is not None:
        from . import rapid_capture_control_installation as installation
        if (not isinstance(installation_reference, dict) or set(installation_reference) != {"path", "sha256"}
            or not Path(installation_reference["path"]).is_absolute()
            or _sha(_read(Path(installation_reference["path"]))) != installation_reference["sha256"]):
            raise ValueError("retained lane capture-control installation changed")
        payload, _ = installation.validate_capsule(Path(installation_reference["path"]), actual_image=spec.collection_image_digest)
        installation.check_current_spec(payload, spec)
        if (payload["evidence_root"] != str(root)
            or not admission._utc(payload["published_at"]) <= admission._utc(checked["execution"]["started_at"])
                <= admission._utc(intent["started_at"])):
            raise ValueError("retained lane predates its source-bound capture-control installation")
    if (checked["execution"]["returncode"] != 0 or type(checked["execution"]["returncode"]) is not int
        or checked["execution"]["validator_script_sha256"] != _sha(IMAGE_CHECK_SCRIPT.encode())
        or _json(_load(_object(root, checked["execution"]["stdout"]))) != _json(checked["proof"])):
        raise ValueError("retained actual image-check execution does not prove its facts")
    sites = _validate_image_proof(checked["proof"], spec, equivalent_plan=True, _context=_context)
    lane = _lane(checked["proof"], intent["campaign_name"])
    scheduling_capsule = None
    if lane.study_version == 6:
        from . import rapid_rolling_capture as rolling
        payload = _payload(spec.plan_receipt, PLAN_TYPE)
        reference = payload.get("scheduling")
        if lineage.get("rolling_scheduling") != reference:
            raise ValueError("rolling lane changed its sealed scheduling authority")
        if reference is not None:
            from .rapid_rolling_schedule import require_schedule
            scheduling_capsule = require_schedule(reference, spec, declared_at=payload["declared_at"], started_at=checked["execution"]["started_at"], _context=_context)
        if (intent.get("actuator") != "run" and (intent.get("actuator") != "parallel-formal-worker" or reference is None)
            or lineage.get("rolling_readiness") != rolling.require_mode_readiness(spec, lane, before=checked["execution"]["started_at"], _context=_context)):
            raise ValueError("rolling lane changed its sealed setting-specific readiness")
    elif "rolling_readiness" in lineage or "rolling_scheduling" in lineage:
        raise ValueError("historical lane cannot claim rolling readiness authority")
    if _read(spec.campaign_dir / f"{lane.campaign_name}.yml") != plan.render_lane_campaign(lane, sites):
        raise ValueError("actual campaign bytes changed after bound launch")
    proof = checked["proof"]
    expected_identity = {
        "collection_image_digest": proof["collection_image_digest"], "runtime_source": proof["runtime_source"],
        "client_sha256": proof["client_sha256"], "base_launcher_sha256": proof["base_launcher_sha256"],
        "host_launcher_sha256": proof["host_launcher_sha256"], "traffic_hashes": proof["traffic_hashes"],
    }
    if (intent.get("scientific_credit") is not False or intent.get("actuator") not in {"run", "parallel-formal-worker"}
        or intent["logical_lane"] != lane.logical_name or type(intent["generation"]) is not int
        or intent["generation"] != lane.generation or intent["bindings"] != checked["proof"]["bindings"]
        or intent["campaign_sha256"] != _sha(plan.render_lane_campaign(lane, sites))
        or _json(intent["runtime_identity"]) != _json(expected_identity)):
        raise ValueError("launch intent differs from its actual verified plan")
    expected_lineage = {
        "execution_generation": spec.execution_generation,
        "profile_receipt_sha256": proof["bindings"]["profile_sha256"],
        "cohort_receipt_sha256": proof["bindings"]["cohort_sha256"],
        **({"selection_amendment_sha256": proof["bindings"]["selection_amendment_sha256"]}
           if "selection_amendment_sha256" in proof["bindings"] else {}),
        **proof["traffic_hashes"], "collection_image_digest": proof["collection_image_digest"],
        "lab_commit": proof["runtime_source"]["lab_commit"],
        "base_launcher_sha256": proof["base_launcher_sha256"], "host_launcher_sha256": proof["host_launcher_sha256"],
        "equivalent_to_cohort": True,
    }
    if any(_json(lineage.get(key)) != _json(value) for key, value in expected_lineage.items()):
        raise ValueError("lineage fields differ from independently reopened image and study identities")
    if set(lineage["artifacts"]) != set(TRAFFIC_FILES) | {"source_manifest", "client_binary", "base_launcher", "host_launcher", "plan_receipt", "cohort", "study_profile"}:
        raise ValueError("lineage artifact inventory is incomplete or enlarged")
    artifact_hashes = {
        "source_manifest": proof["source_manifest_sha256"], "client_binary": proof["client_sha256"],
        "base_launcher": proof["base_launcher_sha256"], "host_launcher": proof["host_launcher_sha256"],
        "plan_receipt": proof["plan_receipt_sha256"], "cohort": proof["bindings"]["cohort_sha256"],
        "study_profile": plan.FROZEN_V5_PROFILE_SHA256,
        **proof["traffic_hashes"],
    }
    for key, reference in lineage["artifacts"].items():
        raw = _object(root, reference)
        if _sha(raw) != artifact_hashes[key]:
            raise ValueError("retained lineage artifact differs from the actual image/plan proof")
        if key == "plan_receipt" and _json(admission._unpack(raw, PLAN_TYPE)) != _json(proof["plan_payload"]):
            raise ValueError("retained plan receipt differs from the actual executed verifier output")
    if lane.generation == 1:
        if any(lineage.get(key) is not None for key in ("predecessor_campaign_name", "predecessor_campaign_sha256", "predecessor_intent", "predecessor_attempt")):
            raise ValueError("initial generation claims predecessor history")
    else:
        predecessor_name = plan._campaign_name(lane.role, lane.block, lane.shard, lane.mode, lane.generation - 1, lane.study_version)
        predecessor = admission._unpack(_object(root, lineage["predecessor_intent"]), INTENT_TYPE)
        predecessor_raw = _read(spec.campaign_dir / f"{predecessor_name}.yml")
        predecessor_lane = plan.successor_lane(
            plan.Lane(lane.role, lane.block, lane.shard, lane.mode,
                      lane.logical_name, lane.workload_ids, lane.visits_per_workload,
                      lane.qualification_set, 1, lane.study_version), lane.generation - 1,
        ) if lane.generation > 2 else plan.Lane(lane.role, lane.block, lane.shard, lane.mode,
                                              lane.logical_name, lane.workload_ids, lane.visits_per_workload,
                                              lane.qualification_set, 1, lane.study_version)
        predecessor_spec = spec
        predecessor_identity = expected_identity
        if _json(predecessor["runtime_identity"]) != _json(expected_identity):
            if scheduling_capsule is None:
                raise ValueError("recovery generation changes prior identity or skips its immediate predecessor")
            from .rapid_rolling_schedule import _spec
            predecessor_spec = _spec(scheduling_capsule["base_spec"])
            original_path = root / "lanes" / predecessor_name / "intent.json"
            if (original_path.parent / "complete.json").exists():
                raise ValueError("a completed lane cannot be selectively recaptured under this recovery policy")
            if _read(original_path) != _object(root, lineage["predecessor_intent"]):
                raise ValueError("rolling recovery replaced its original source-bound predecessor intent")
            original, _, original_lane, _ = _intent_and_lineage(predecessor_spec, root, original_path)
            if (original != predecessor or original_lane.logical_name != lane.logical_name
                or original_lane.generation != lane.generation - 1
                or admission._utc(original["started_at"]) > admission._utc(scheduling_capsule["published_at"])):
                raise ValueError("rolling recovery changed its original source-bound failed predecessor")
            predecessor_identity = original["runtime_identity"]
        if (predecessor_raw != plan.render_lane_campaign(predecessor_lane, sites)
            or lineage["predecessor_campaign_name"] != predecessor_name
            or lineage["predecessor_campaign_sha256"] != _sha(predecessor_raw)
            or predecessor["campaign_name"] != predecessor_name
            or predecessor["campaign_sha256"] != _sha(predecessor_raw)
            or _json(predecessor["runtime_identity"]) != _json(predecessor_identity)
            or predecessor["bindings"] != intent["bindings"]):
            raise ValueError("recovery generation changes prior identity or skips its immediate predecessor")
        previous = lineage["predecessor_attempt"]
        process = _verified_host_process(_object(root, previous["host_process"]), root,
                                         _object(root, lineage["predecessor_intent"]), predecessor_name) if previous["host_process"] else None
        for reference in previous["inventory"].values():
            _object(root, reference)
        for reference in previous["result_inventory"].values():
            _object(root, reference)
        if process is not None and not _process_matches_lane(process, predecessor_spec, predecessor_name):
            raise ValueError("recovery predecessor lacks an actual bound host attempt")
        if previous["retirement"] is not None:
            retirement = _verified_retirement(_object(root, previous["retirement"]), root,
                                             _object(root, lineage["predecessor_intent"]), predecessor_name)
            if not _process_matches_lane(retirement, predecessor_spec, predecessor_name):
                raise ValueError("retirement observation belongs to another original host command")
        elif process is None:
            raise ValueError("recovery predecessor has neither terminal process nor observed retirement")
    return intent, lineage, lane, sites


def complete_lane(spec: CaptureSpec, root: Path, intent_path: Path) -> Path:
    intent, lineage, lane, sites = _intent_and_lineage(spec, root, intent_path)
    directory = intent_path.parent
    process = _verified_host_process(_read(directory / "host-process.json"), root, _read(intent_path), lane.campaign_name)
    start = _validated_host_start(_read(directory / "host-start.json"), _read(intent_path), campaign_name=lane.campaign_name)
    if (process["start"] != {"path": f"objects/{_sha(_read(directory / 'host-start.json'))}", "sha256": _sha(_read(directory / "host-start.json"))}
        or process["started_at"] != start["started_at"] or process["command"] != start["command"]):
        raise ValueError("host terminal process differs from its durable actual start")
    _object(root, process["start"])
    if process["interruption"] is not None:
        raise ValueError("interrupted physical lane requires a preserved fresh generation")
    namespace = spec.execution_root / "results" / lane.campaign_name
    candidates = [path for path in namespace.iterdir() if path.is_dir()] if namespace.is_dir() else []
    if len(candidates) != 1:
        raise ValueError("physical lane must own exactly one retained result root")
    result = candidates[0]
    experiment = _load(_read(result / "experiment.json"))
    if admission._utc(experiment["started_at"]) < admission._utc(process["started_at"]):
        raise ValueError("result predates the actual bound launch")
    workloads = {site.workload_id: _read(spec.workload_root / f"{site.workload_id}.json")
                 for site in sites if site.workload_id in lane.workload_ids}
    dns_path = directory / "dns.json"
    dns_sha = verify_dns_receipt(_read(dns_path), lane.campaign_name, workloads)
    verified = plan.verify_lane_result(
        result, lane, collection_image_digest=spec.collection_image_digest,
        lab_commit=lineage["lab_commit"], campaign_sha256=intent["campaign_sha256"],
        workload_sha256s={name: _sha(raw) for name, raw in workloads.items()},
        qualification_set_manifest_sha256=(next(site.qualification_set_manifest_sha256 for site in sites
                                              if site.workload_id == lane.workload_ids[0]) if lane.qualification_set else None),
    )
    if intent["actuator"] == "parallel-formal-worker":
        from .rapid_formal_parallel import verify_worker_result
        verify_worker_result(process, result)
    _check_spec(spec)
    payload = {
        "intent": {"path": intent_path.relative_to(root).as_posix(), "sha256": _sha(_read(intent_path))},
        "campaign_name": lane.campaign_name, "campaign_sha256": intent["campaign_sha256"],
        "profile_receipt_sha256": intent["bindings"]["profile_sha256"], "cohort_receipt_sha256": intent["bindings"]["cohort_sha256"],
        "execution_generation": lineage["execution_generation"], "lineage_receipt_sha256": intent["lineage"]["sha256"],
        "base_launcher_sha256": lineage["base_launcher_sha256"], "host_launcher_sha256": lineage["host_launcher_sha256"],
        "collection_image_digest": spec.collection_image_digest, "lab_commit": lineage["lab_commit"],
        "result_relpath": result.relative_to(spec.execution_root / "results").as_posix(),
        "result_seal_sha256": verified["result_seal_sha256"], "dns_pin_receipt_sha256": dns_sha,
        "accepted": verified["accepted"], "scientific_credit": verified["scientific_credit"],
        "completed_at": _now(), "host_returncode": process["returncode"],
    }
    output = directory / "complete.json"
    _create(root, output, COMPLETE_TYPE, payload)
    return output


def _process_matches_lane(process: Mapping[str, Any], spec: CaptureSpec, campaign_name: str) -> bool:
    if process.get("actuator") == "parallel-formal-worker":
        return (process.get("execution_root") == str(spec.execution_root)
                and process.get("campaign_name") == campaign_name)
    original = process.get("execution_root")
    if not isinstance(original, str) or not Path(original).is_absolute() or ".." in Path(original).parts:
        return False
    relative = spec.campaign_dir.relative_to(spec.execution_root) / f"{campaign_name}.yml"
    return process.get("command") == [str(Path(original) / "qcsd-lab"), "run", str(Path(original) / relative)]


def verify_execution_lineage(path: Path, *, spec: CaptureSpec, evidence_root: Path) -> dict[str, Any]:
    """Concrete callback: rederive lineage from installed-image and retained bytes."""
    _, lineage, _, _ = _intent_and_lineage(spec, evidence_root, path.parent / "intent.json")
    if _read(path) != _read(admission._child(evidence_root, _payload(path.parent / "intent.json", INTENT_TYPE)["lineage"])):
        raise ValueError("lineage callback opened another lane's authority")
    return lineage


def verify_launch_receipt(
    path: Path, *, spec: CaptureSpec, evidence_root: Path, _manifest_already_deep_verified: bool = False,
) -> dict[str, Any]:
    """Concrete callback: reopen the DNS, process, plan, source and result seal.

    The private fast path is used only by verify_formal_manifest, which calls
    verify_lane_result immediately before this callback for the same result.
    """
    stored = _payload(path, COMPLETE_TYPE)
    root = _regular_directory(evidence_root)
    intent_path = admission._child(root, stored["intent"])
    intent, lineage, lane, sites = _intent_and_lineage(spec, root, intent_path)
    process = _verified_host_process(_read(path.parent / "host-process.json"), root, _read(intent_path), lane.campaign_name)
    start = _validated_host_start(_object(root, process["start"]), _read(intent_path), campaign_name=lane.campaign_name)
    if (_object(root, process["start"]) != _read(path.parent / "host-start.json")
        or process["started_at"] != start["started_at"] or process["command"] != start["command"]):
        raise ValueError("actual terminal process does not reopen its original host birth evidence")
    if (process["interruption"] is not None or type(process["returncode"]) is not int
        or stored["host_returncode"] != process["returncode"]
        or not _process_matches_lane(process, spec, lane.campaign_name)):
        raise ValueError("completed launch has no matching completed actual host process")
    for key in ("stdout", "stderr"):
        _object(root, process[key])
    workloads = {site.workload_id: _read(spec.workload_root / f"{site.workload_id}.json")
                 for site in sites if site.workload_id in lane.workload_ids}
    dns_sha = verify_dns_receipt(_read(path.parent / "dns.json"), lane.campaign_name, workloads)
    result = plan._safe_child(spec.execution_root / "results", stored["result_relpath"], "result")
    if Path(stored["result_relpath"]).parts[0] != lane.campaign_name:
        raise ValueError("completed result escapes its exact physical lane namespace")
    if _manifest_already_deep_verified:
        seal_sha = _sha(_read(result / "evidence.sha256"))
        accepted = lane.sample_count
        credit = ("none-diagnostic" if lane.role == "diagnostic" else
                  "formal-only-if-bound-to-rolling-enrollment" if lane.study_version == 6 else
                  "formal-only-if-bound-to-final-50-plan")
    else:
        checked = plan.verify_lane_result(
            result, lane, collection_image_digest=spec.collection_image_digest, lab_commit=lineage["lab_commit"],
            campaign_sha256=intent["campaign_sha256"], workload_sha256s={name: _sha(raw) for name, raw in workloads.items()},
            qualification_set_manifest_sha256=(next(site.qualification_set_manifest_sha256 for site in sites
                                                  if site.workload_id == lane.workload_ids[0]) if lane.qualification_set else None),
        )
        seal_sha, accepted, credit = checked["result_seal_sha256"], checked["accepted"], checked["scientific_credit"]
    if intent["actuator"] == "parallel-formal-worker":
        from .rapid_formal_parallel import verify_worker_result, require_batch_closure
        verify_worker_result(process, result)
        require_batch_closure(process)
    expected = {
        "campaign_name": lane.campaign_name, "campaign_sha256": intent["campaign_sha256"],
        "profile_receipt_sha256": intent["bindings"]["profile_sha256"], "cohort_receipt_sha256": intent["bindings"]["cohort_sha256"],
        "execution_generation": lineage["execution_generation"], "lineage_receipt_sha256": intent["lineage"]["sha256"],
        "base_launcher_sha256": lineage["base_launcher_sha256"], "host_launcher_sha256": lineage["host_launcher_sha256"],
        "collection_image_digest": spec.collection_image_digest, "lab_commit": lineage["lab_commit"],
        "result_seal_sha256": seal_sha, "dns_pin_receipt_sha256": dns_sha,
        "accepted": accepted, "scientific_credit": credit,
    }
    if any(_json(stored.get(key)) != _json(value) for key, value in expected.items()):
        raise ValueError("completed launch differs from independently reopened source, DNS or result facts")
    if not admission._utc(intent["started_at"]) <= admission._utc(process["started_at"]) <= admission._utc(process["completed_at"]) <= admission._utc(stored["completed_at"]) <= datetime.now(UTC):
        raise ValueError("completed launch chronology is invalid")
    return {**stored, "result_root": str(result.resolve())}


def formal_manifest_rows(spec: CaptureSpec, evidence_root: Path) -> list[dict[str, Any]]:
    """Derive physical rows; every registered logical slot appears once."""
    stored_plan = admission._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    if stored_plan["cohort_generation"] != "final-50":
        raise ValueError("diagnostic shakedown grants zero formal corpus credit")
    sites = tuple(plan.Site(**row) for row in stored_plan["sites"])
    expected = {lane.logical_name for lane in plan.plan_lanes(sites, final=True, study_version=5)}
    rows = {}
    root = _regular_directory(evidence_root)
    for intent in (root / "lanes").glob("*/intent.json"):
        if not (intent.parent / "host-process.json").is_file() and not (intent.parent / "retirement.json").is_file():
            raise ValueError("formal corpus cannot hide an active or unretired physical launch")
        value = _payload(intent, INTENT_TYPE)
        if (intent.parent / "host-process.json").is_file():
            _verified_host_process(_read(intent.parent / "host-process.json"), root, _read(intent), value["campaign_name"])
        if (intent.parent / "retirement.json").is_file():
            _verified_retirement(_read(intent.parent / "retirement.json"), root, _read(intent), value["campaign_name"])
    for path in sorted((root / "lanes").glob("*/complete.json")):
        launch = verify_launch_receipt(path, spec=spec, evidence_root=root)
        intent = _payload(admission._child(root, launch["intent"]), INTENT_TYPE)
        _, lineage, lane, _ = _intent_and_lineage(spec, root, admission._child(root, launch["intent"]))
        if lane.role != "formal":
            raise ValueError("diagnostic completion cannot enter the formal evidence root")
        row = {
            "logical_lane": lane.logical_name, "generation": lane.generation,
            "campaign_name": lane.campaign_name, "campaign_sha256": launch["campaign_sha256"],
            "execution_generation": lineage["execution_generation"], "collection_image_digest": launch["collection_image_digest"],
            "lab_commit": launch["lab_commit"], "base_launcher_sha256": launch["base_launcher_sha256"],
            "host_launcher_sha256": launch["host_launcher_sha256"], "lineage_receipt_relpath": intent["lineage"]["path"],
            "lineage_receipt_sha256": intent["lineage"]["sha256"], "result_relpath": launch["result_relpath"],
            "result_seal_sha256": launch["result_seal_sha256"], "launch_receipt_relpath": path.relative_to(root).as_posix(),
            "launch_receipt_sha256": _sha(_read(path)), "dns_pin_receipt_sha256": launch["dns_pin_receipt_sha256"],
        }
        if lane.logical_name in rows:
            raise ValueError("formal corpus has multiple completed physical generations for one logical slot")
        rows[lane.logical_name] = row
    if set(rows) != expected:
        raise ValueError("formal corpus has missing or unregistered logical lanes")
    return [rows[lane.logical_name] for lane in plan.plan_lanes(sites, final=True, study_version=5)]


def verify_corpus_manifest(manifest: Mapping[str, Any], *, spec: CaptureSpec, evidence_root: Path) -> dict[str, Any]:
    """Actual final verifier callbacks; no caller-supplied eligibility/pass facts."""
    module = _plan_module(spec.module_root)
    # This closure runs in the exact collection image, with the installed
    # strict qualifier gate and the full clean source bridge still active.
    executed_image_plan_check(spec.serializable())
    context, sites, bindings, _, _ = module._inputs(_plan_args(spec))
    status = admission.acquisition_status(context)
    lookup = {ref["sha256"]: admission._child(context.root, ref) for ref in status["terminal_prefix"]}
    cohort_payload = _load(_read(spec.cohort))["payload"]
    site_by_terminal = {row["terminal_receipt_sha256"]: site for row in cohort_payload["terminal_decisions"]
                        if row["outcome"] == "admitted" for site in sites if site.candidate_id == row["candidate_id"]}
    provenance = admission._unpack(_read(context.root / "provenance.json"), admission.PROVENANCE_TYPE)
    return plan.verify_formal_manifest(
        manifest, sites, bindings=bindings,
        curated_source=admission._child(context.root, provenance["inputs"]["source"]),
        fallback_catalogue=admission._child(context.root, provenance["inputs"]["catalogue"]),
        execution_binding=context.execution_binding,
        deep_verify_terminal=lambda digest: admission.verify_site_terminal(lookup[digest], context),
        verify_site_workload=lambda digest: site_by_terminal[digest],
        campaign_dir=spec.campaign_dir, workload_root=spec.workload_root,
        result_root=spec.execution_root / "results", launch_receipt_root=evidence_root,
        lineage_receipt_root=evidence_root,
        verify_launch_receipt=lambda path: verify_launch_receipt(path, spec=spec, evidence_root=evidence_root,
                                                               _manifest_already_deep_verified=True),
        verify_execution_lineage=lambda path: verify_execution_lineage(path, spec=spec, evidence_root=evidence_root),
    )


def publish_corpus_manifest(spec: CaptureSpec, evidence_root: Path, output: Path) -> dict[str, Any]:
    """Create the final 16,000-trace manifest only after independent closure."""
    stored_plan = admission._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    manifest = {"schema_version": 1, "artifact_type": plan.V5_CORPUS_TYPE,
                "bindings": stored_plan["bindings"], "lanes": formal_manifest_rows(spec, evidence_root)}
    facts = verify_corpus_manifest(manifest, spec=spec, evidence_root=evidence_root)
    durable_create(output, _json(manifest))
    return {**facts, "manifest_sha256": _sha(_read(output)), "manifest": str(output)}
