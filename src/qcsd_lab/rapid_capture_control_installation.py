"""Install reviewed capture control before formal flights, retaining acquisition.

The original image actually reopens the cohort, prepared graphs and response
qualification offline.  A separate actual installed-image check binds the new
collector.  Both raw executions, source inventories and initial qualified input
bytes remain sealed.  This zero-credit capsule is neither a failed-lane repair
nor a replacement admission decision.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import rapid_capture_control_compatibility as compatibility
from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as admission
from . import runtime_provenance as provenance
from .util import SOURCE_METADATA_KEYS, durable_create

CAPSULE_TYPE = "qcsd-rapid-v5-capture-control-installation-v2"
MODULE_FILE = "src/qcsd_lab/rapid_capture_control_installation.py"
INVENTORY_RULE = "initial-qualified-input-bytes-retained-additions-require-separate-lane-authority-v1"
RUNTIME_SCRIPT = (
    "import json,sys; from qcsd_lab.rapid_capture_control_installation import executed_runtime_check; "
    "print(json.dumps(executed_runtime_check(json.loads(sys.argv[1])),sort_keys=True,allow_nan=False))"
)
CAPSULE_KEYS = {"base_spec", "runtime_spec", "evidence_root", "old_image_check", "new_runtime_check",
                "review", "compatibility_bridge", "qualified_inputs", "inventory_rule", "published_at",
                "formal_accepted_trace_count", "scientific_credit"}
EXECUTION_KEYS = {"command", "actor", "started_at", "completed_at", "returncode", "error",
                  "stdout", "stderr", "validator_script_sha256", "started_record"}


def _spec(value: Mapping[str, str]) -> lanes.CaptureSpec:
    if not isinstance(value, Mapping) or set(value) != lanes.PATH_KEYS | {"collection_image_digest", "execution_generation"}:
        raise ValueError("capture-control installation spec fields differ")
    result = lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item for key, item in value.items()})
    lanes._check_spec(result)
    return result


def _sources(spec: lanes.CaptureSpec) -> dict[str, bytes]:
    from .chaff_qualification import IMPLEMENTATION_FILES
    names = set(IMPLEMENTATION_FILES)
    names.update(path.relative_to(spec.runtime_source_root).as_posix()
                 for folder in ("src/qcsd_lab", "tools")
                 for path in (spec.runtime_source_root / folder).glob("*.py"))
    names.update(relative for relative, _ in lanes.TRAFFIC_FILES.values())
    return {name: admission._read(spec.runtime_source_root / name) for name in sorted(names)}


def _inventory(root: Path) -> dict[str, str]:
    root = lanes._regular_directory(root)
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("qualified input inventory contains a symbolic link")
        if path.is_dir():
            continue
        result[path.relative_to(root).as_posix()] = admission._sha(admission._read(path))
    if not result:
        raise ValueError("qualified input inventory is empty")
    return result


def _qualified_inputs(spec: lanes.CaptureSpec) -> dict[str, Any]:
    return {"cohort_sha256": admission._sha(admission._read(spec.cohort)),
            "qualification_spec_sha256": admission._sha(admission._read(spec.qualification_spec)),
            "plan_receipt_sha256": admission._sha(admission._read(spec.plan_receipt)),
            "workloads": _inventory(spec.workload_root),
            "qualification_store": _inventory(spec.campaign_dir.parent / "chaff-response-qualification-store"),
            "campaigns": _inventory(spec.campaign_dir)}


def _matching_inputs(base: lanes.CaptureSpec, runtime: lanes.CaptureSpec) -> dict[str, Any]:
    for spec in (base, runtime):
        lanes._check_spec(spec)
        if spec.module_root != spec.runtime_source_root or admission._read(spec.host_launcher) != admission._read(spec.base_launcher):
            raise ValueError("capture-control installation requires matching clean source and launcher roles")
    if base.data_root != runtime.data_root or base.acquisition_root != runtime.acquisition_root:
        raise ValueError("capture-control installation cannot replace the retained acquisition root or data authority")
    before, after = _qualified_inputs(base), _qualified_inputs(runtime)
    if before != after:
        raise ValueError("capture-control installation changed cohort, prepared graph, plan or qualification bytes")
    return before


def _verify_inputs(spec: lanes.CaptureSpec, expected: Mapping[str, Any], *, additions: bool) -> None:
    actual = _qualified_inputs(spec)
    if not isinstance(expected, Mapping) or set(expected) != set(actual):
        raise ValueError("capture-control qualified input inventory fields differ")
    for name, value in expected.items():
        if isinstance(value, Mapping):
            if (not value or any(not isinstance(path, str) or _invalid_relative_path(path) or not compatibility.historical._digest(digest)
                                 for path, digest in value.items())
                or any(actual[name].get(path) != digest for path, digest in value.items())
                or (not additions and actual[name] != value)):
                raise ValueError("retained initial qualified input bytes changed or disappeared")
        elif actual[name] != value:
            raise ValueError("retained cohort, qualifier spec or initial plan changed")


def _invalid_relative_path(value: str) -> bool:
    path = Path(value)
    return path.is_absolute() or path.as_posix() != value or "\\" in value or any(part in {".", ".."} for part in path.parts)


def _formal_history(root: Path, specs: tuple[lanes.CaptureSpec, ...], *, published_at: str | None = None) -> None:
    """Publication precedes real formal identities; later exact retries remain valid."""
    from .rapid_runtime_epochs import INTENT_TYPE as runtime_intent
    for path in root.rglob("intent.json"):
        raw = admission._load(admission._read(path))
        if not isinstance(raw, Mapping) or raw.get("receipt_type") not in {lanes.INTENT_TYPE, runtime_intent}:
            continue
        value = admission._unpack(admission._read(path), raw["receipt_type"])
        name = value.get("campaign_name")
        if not isinstance(name, str) or "-formal-" not in name:
            continue
        if published_at is None or admission._utc(value["started_at"]) < admission._utc(published_at):
            raise ValueError("capture-control installation must precede every formal lane intent")
    for spec in specs:
        results = spec.execution_root / "results"
        if not results.exists():
            continue
        for namespace in results.iterdir():
            if "-formal-" not in namespace.name:
                continue
            if namespace.is_symlink() or not namespace.is_dir():
                raise ValueError("formal result namespace is not a regular directory")
            if published_at is None:
                raise ValueError("capture-control installation cannot precede an already allocated formal result")
            for experiment in namespace.glob("*/experiment.json"):
                value = admission._load(admission._read(experiment))
                if admission._utc(value["started_at"]) < admission._utc(published_at):
                    raise ValueError("formal result predates prospective capture-control installation")


def image_check_command(spec: lanes.CaptureSpec, *, role: str,
                        actor: Mapping[str, int] | None = None) -> list[str]:
    """No ambient compatibility environment enters the original-image check."""
    lanes._check_spec(spec)
    actor = dict(actor) if actor is not None else {"uid": os.getuid(), "gid": os.getgid()}
    if (set(actor) != {"uid", "gid"} or any(type(value) is not int or not 0 <= value < 2**32 for value in actor.values())
        or role not in {"original-plan", "new-runtime"}):
        raise ValueError("capture-control image-check role or actor is invalid")
    roots = {spec.data_root, spec.runtime_source_root, spec.module_root, spec.execution_root,
             spec.source_manifest.parent, spec.client_binary.parent, spec.base_launcher.parent}
    command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--user", f"{actor['uid']}:{actor['gid']}",
               "--tmpfs", "/tmp:rw,nosuid,noexec,size=64m"]
    for path in sorted(roots):
        lanes._regular_directory(path)
        command += ["--volume", f"{path}:{path}:ro"]
    for key, value in {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(spec.module_root / "src"),
                       "QCSD_LAB_ROOT": str(spec.runtime_source_root),
                       "QCSD_LAB_SOURCE_METADATA": "/usr/share/qcsd-lab/source.json",
                       "QCSD_LAB_IMAGE_DIGEST": spec.collection_image_digest}.items():
        command += ["--env", f"{key}={value}"]
    script = lanes.IMAGE_CHECK_SCRIPT if role == "original-plan" else RUNTIME_SCRIPT
    command += ["--entrypoint", "/opt/qcsd-venv/bin/python3", spec.collection_image_digest]
    return command + (["-c", script, json.dumps(spec.serializable(), sort_keys=True)] if role == "original-plan"
                      else ["-I", "-c", script, json.dumps(spec.serializable(), sort_keys=True)])


def _runtime_projection(proof: Mapping[str, Any]) -> dict[str, Any]:
    return {"schema_version": 1, "artifact_type": "qcsd-rapid-v5-installed-runtime-preflight",
            **{key: proof[key] for key in ("collection_image_digest", "runtime_source", "source_manifest_sha256",
                "client_sha256", "base_launcher_sha256", "host_launcher_sha256", "qualification_implementation", "traffic_hashes")},
            "formal_accepted_trace_count": 0, "scientific_credit": False}


def executed_runtime_check(value: Mapping[str, str]) -> dict[str, Any]:
    spec = _spec(value)
    runtime = lanes.executed_image_runtime_check({key: value[key] for key in lanes.RUNTIME_KEYS})
    installed = provenance.validate_runtime_receipt(required_schema_version=2)
    for path, digest in installed["source_files"].items():
        if admission._sha(admission._read(spec.runtime_source_root / path)) != digest:
            raise ValueError("new installed capture-control image differs from its complete source")
    if admission._read(Path(__file__)) != admission._read(spec.runtime_source_root / MODULE_FILE):
        raise ValueError("capture-control installation validator is not from the declared installed source")
    return {"runtime_proof": runtime, "python_runtime_receipt": installed}


def _run_check(spec: lanes.CaptureSpec, root: Path, directory: Path, *, role: str) -> dict[str, Any]:
    directory.mkdir(parents=True)
    actor = {"uid": os.getuid(), "gid": os.getgid()}
    command = image_check_command(spec, role=role, actor=actor)
    script = lanes.IMAGE_CHECK_SCRIPT if role == "original-plan" else RUNTIME_SCRIPT
    started = {"command": command, "actor": actor, "started_at": admission._now(),
               "validator_script_sha256": admission._sha(script.encode())}
    start_path = directory / "started.json"
    durable_create(start_path, admission._json(started))
    stdout = stderr = b""
    returncode = None
    error = None
    try:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=300)
        stdout, stderr, returncode = process.stdout, process.stderr, process.returncode
    except (OSError, subprocess.SubprocessError) as failure:
        stdout, stderr = getattr(failure, "stdout", None) or b"", getattr(failure, "stderr", None) or b""
        error = {"type": type(failure).__name__, "message": str(failure)}
    execution = {**started, "completed_at": admission._now(), "returncode": returncode, "error": error,
        "stdout": lanes._put_object(root, stdout), "stderr": lanes._put_object(root, stderr),
        "started_record": admission.evidence_reference(root, start_path)}
    complete_path = directory / "completed.json"
    durable_create(complete_path, admission._json(execution))
    if error is not None or type(returncode) is not int or returncode != 0:
        raise ValueError("actual capture-control image check failed; original started/completed/raw logs retained")
    return {"execution": execution, "proof": admission._load(stdout),
            "completed_record": admission.evidence_reference(root, complete_path)}


def _verify_check(check: Mapping[str, Any], spec: lanes.CaptureSpec, root: Path, *, role: str) -> None:
    if not isinstance(check, Mapping) or set(check) != {"execution", "proof", "completed_record"}:
        raise ValueError("capture-control actual image check fields differ")
    execution = check["execution"]
    script = lanes.IMAGE_CHECK_SCRIPT if role == "original-plan" else RUNTIME_SCRIPT
    if (not isinstance(execution, Mapping) or set(execution) != EXECUTION_KEYS
        or type(execution["returncode"]) is not int or execution["returncode"] != 0 or execution["error"] is not None
        or execution["command"] != image_check_command(spec, role=role, actor=execution["actor"])
        or execution["validator_script_sha256"] != admission._sha(script.encode())
        or admission._load(lanes._object(root, execution["stdout"])) != check["proof"]):
        raise ValueError("capture-control capsule lacks a matching actual command and successful raw output")
    lanes._object(root, execution["stderr"])
    completed = admission._load(admission._read(admission._child(root, check["completed_record"])))
    if completed != execution:
        raise ValueError("capture-control actual completed record changed")
    started = admission._load(admission._read(admission._child(root, execution["started_record"])))
    if started != {key: execution[key] for key in ("command", "actor", "started_at", "validator_script_sha256")}:
        raise ValueError("capture-control actual started record changed")
    if not admission._utc(execution["started_at"]) <= admission._utc(execution["completed_at"]) <= admission._utc(admission._now()):
        raise ValueError("capture-control actual check chronology is invalid")
    if role == "original-plan":
        lanes._validate_image_proof(check["proof"], spec)
        return
    proof = check["proof"]
    if not isinstance(proof, Mapping) or set(proof) != {"runtime_proof", "python_runtime_receipt"}:
        raise ValueError("new capture-control runtime proof fields differ")
    runtime, installed = proof["runtime_proof"], proof["python_runtime_receipt"]
    compatibility.historical._runtime(runtime, compatibility.historical._source_inventory(_sources(spec)))
    if (runtime["collection_image_digest"] != spec.collection_image_digest
        or runtime["runtime_source"] != {**admission._load(admission._read(spec.source_manifest)),
                                        "image_digest": spec.collection_image_digest}
        or runtime["source_manifest_sha256"] != admission._sha(admission._read(spec.source_manifest))
        or runtime["client_sha256"] != admission._sha(admission._read(spec.client_binary))
        or runtime["base_launcher_sha256"] != admission._sha(admission._read(spec.base_launcher))
        or runtime["host_launcher_sha256"] != admission._sha(admission._read(spec.host_launcher))
        or runtime["traffic_hashes"] != {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}):
        raise ValueError("new capture-control runtime differs from its actual image, source, client or fixed traffic")
    if (not isinstance(installed, Mapping) or set(installed) != provenance._RECEIPT_KEYS
        or type(installed["schema_version"]) is not int or installed["schema_version"] != 2
        or installed["artifact_type"] != provenance.RUNTIME_RECEIPT_TYPE or installed["domain"] != provenance.RUNTIME_RECEIPT_DOMAIN
        or installed["payload_sha256"] != provenance._payload_sha256(installed, domain=provenance.RUNTIME_RECEIPT_DOMAIN)
        or any(installed["source"][key] != runtime["runtime_source"][key] for key in SOURCE_METADATA_KEYS - {"image_digest"})):
        raise ValueError("new capture-control full installed-source receipt is invalid")
    provenance._validate_source(installed["source"])
    files = provenance._source_files(installed["source_files"])
    retained_modules = {path.relative_to(spec.runtime_source_root).as_posix()
                        for path in (spec.runtime_source_root / "src/qcsd_lab").glob("*.py")}
    if {path for path in files if path.startswith("src/qcsd_lab/")} != retained_modules:
        raise ValueError("new capture-control complete installed module inventory is incomplete")
    for path, digest in files.items():
        if admission._sha(admission._read(spec.runtime_source_root / path)) != digest:
            raise ValueError("new capture-control complete retained source differs from installed proof")
    modules = provenance._installed_records(installed["installed_modules"],
        expected={path for path in files if path.startswith("src/qcsd_lab/")}, label="capture-control installed module")
    tools = provenance._installed_records(installed["installed_tools"],
        expected=set(provenance._REQUIRED_TOOL_SOURCES), label="capture-control installed tool")
    for path, record in {**modules, **tools}.items():
        if record["sha256"] != files[path]:
            raise ValueError("new capture-control installed source role differs from retained proof")
    entrypoint = provenance._installed_record(installed["installed_entrypoint"], "capture-control entrypoint")
    if entrypoint["sha256"] != files["qcsd-lab"]:
        raise ValueError("new capture-control installed launcher differs from retained source")


def _reference_check(spec: lanes.CaptureSpec, output: Path) -> None:
    if admission._read(Path(__file__)) != admission._read(spec.runtime_source_root / MODULE_FILE):
        raise ValueError("capture-control publisher differs from the source being installed")
    if output.exists() or output.is_symlink():
        raise FileExistsError("capture-control installation capsule is create-only")


def publish_installation(base_spec: lanes.CaptureSpec, new_spec: lanes.CaptureSpec,
                         root: Path, output: Path, review: Mapping[str, Any] | None = None,
                         *, reason: str | None = None) -> Path:
    root = lanes._regular_directory(root)
    output = Path(output).absolute()
    if not output.is_relative_to(root) or output.parent != root or not root.is_relative_to(base_spec.data_root):
        raise ValueError("capture-control capsule requires a create-only file inside its explicit evidence root")
    _reference_check(new_spec, output)
    # This lock is host-global across all copied execution roots.  Taking it
    # twice would reject our own second descriptor, rather than protect both.
    with lanes.capture_lock(base_spec.execution_root):
        inputs = _matching_inputs(base_spec, new_spec)
        _formal_history(root, (base_spec, new_spec))
        context = admission.load_admission_context(base_spec.acquisition_root)
        old_sources, new_sources = _sources(base_spec), _sources(new_spec)
        changes, _ = compatibility.source_changes(old_sources, new_sources)
        if review is None:
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("capture-control installation requires an explicit reviewed reason")
            review = {"schema_version": 1, "artifact_type": compatibility.REVIEW_TYPE,
                      "repair_scope": compatibility.REVIEW_SCOPE, "reason": reason,
                      "changes": changes, "acquisition_source_groups": context.mounted_module_hashes}
        directory = root / "control-installation-checks" / output.stem
        if directory.exists() or directory.is_symlink():
            raise FileExistsError("capture-control installation attempt namespace was already used")
        old_check = _run_check(base_spec, root, directory / "original-plan", role="original-plan")
        _verify_check(old_check, base_spec, root, role="original-plan")
        new_check = _run_check(new_spec, root, directory / "new-runtime", role="new-runtime")
        _verify_check(new_check, new_spec, root, role="new-runtime")
        bridge = compatibility.validate_compatibility(_runtime_projection(old_check["proof"]),
            new_check["proof"]["runtime_proof"], old_sources, new_sources, review,
            acquisition_source_groups=context.mounted_module_hashes)
        _formal_history(root, (base_spec, new_spec))
        if inputs != _matching_inputs(base_spec, new_spec):
            raise ValueError("qualified inputs changed during capture-control installation checks")
        payload = {"base_spec": base_spec.serializable(), "runtime_spec": new_spec.serializable(),
            "evidence_root": str(root), "old_image_check": old_check, "new_runtime_check": new_check,
            "review": dict(review), "compatibility_bridge": bridge, "qualified_inputs": inputs,
            "inventory_rule": INVENTORY_RULE, "published_at": admission._now(),
            "formal_accepted_trace_count": 0, "scientific_credit": False}
        durable_create(output, admission._json(admission._bind(CAPSULE_TYPE, payload)))
        validate_capsule(output, actual_image=new_spec.collection_image_digest)
    return output


def validate_capsule(path: Path, *, actual_image: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = admission._unpack(admission._read(path), CAPSULE_TYPE)
    if (set(payload) != CAPSULE_KEYS or payload["scientific_credit"] is not False
        or type(payload["formal_accepted_trace_count"]) is not int or payload["formal_accepted_trace_count"] != 0
        or payload["inventory_rule"] != INVENTORY_RULE):
        raise ValueError("capture-control installation capsule grants unsupported or changed authority")
    base, runtime = _spec(payload["base_spec"]), _spec(payload["runtime_spec"])
    root = lanes._regular_directory(Path(payload["evidence_root"]))
    if (base.data_root != runtime.data_root or base.acquisition_root != runtime.acquisition_root
        or not Path(path).absolute().is_relative_to(root) or not root.is_relative_to(base.data_root)
        or actual_image is not None and actual_image != runtime.collection_image_digest):
        raise ValueError("capture-control capsule changed its acquisition, mounted data or actual image")
    for spec in (base, runtime):
        if spec.module_root != spec.runtime_source_root or admission._read(spec.host_launcher) != admission._read(spec.base_launcher):
            raise ValueError("capture-control capsule changed matching source/launcher roles")
    _verify_inputs(base, payload["qualified_inputs"], additions=False)
    _verify_inputs(runtime, payload["qualified_inputs"], additions=True)
    _verify_check(payload["old_image_check"], base, root, role="original-plan")
    _verify_check(payload["new_runtime_check"], runtime, root, role="new-runtime")
    context = admission.load_admission_context(base.acquisition_root)
    bridge = compatibility.validate_compatibility(_runtime_projection(payload["old_image_check"]["proof"]),
        payload["new_runtime_check"]["proof"]["runtime_proof"], _sources(base), _sources(runtime), payload["review"],
        acquisition_source_groups=context.mounted_module_hashes)
    if bridge != payload["compatibility_bridge"]:
        raise ValueError("capture-control capsule bridge differs from independently reopened source roles")
    first, last = payload["old_image_check"]["execution"], payload["new_runtime_check"]["execution"]
    if not (admission._utc(first["completed_at"]) <= admission._utc(last["started_at"])
            <= admission._utc(last["completed_at"]) <= admission._utc(payload["published_at"]) <= admission._utc(admission._now())):
        raise ValueError("capture-control capsule predates its actual installed checks")
    _formal_history(root, (base, runtime), published_at=payload["published_at"])
    return payload, bridge


def check_current_spec(capsule: Path | Mapping[str, Any], spec: lanes.CaptureSpec) -> None:
    """Bind worker runtime and inputs; official g02 may have its own plan file."""
    payload = validate_capsule(capsule, actual_image=spec.collection_image_digest)[0] if isinstance(capsule, Path) else capsule
    if not isinstance(payload, Mapping) or set(payload) != CAPSULE_KEYS:
        raise ValueError("capture-control current-spec check requires the closed installation payload")
    lanes._check_spec(spec)
    _spec(payload["runtime_spec"])
    if any(value != spec.serializable()[key] for key, value in payload["runtime_spec"].items() if key != "plan_receipt"):
        raise ValueError("worker spec differs from its source-bound capture-control installation")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    publish = commands.add_parser("publish")
    for name in ("base-spec", "new-spec", "evidence-root", "output"):
        publish.add_argument(f"--{name}", type=Path, required=True)
    authority = publish.add_mutually_exclusive_group(required=True)
    authority.add_argument("--review", type=Path)
    authority.add_argument("--reason")
    verify = commands.add_parser("verify")
    verify.add_argument("--capsule", type=Path, required=True)
    verify.add_argument("--actual-image")
    verify.add_argument("--current-spec", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "publish":
            path = publish_installation(lanes.load_capture_spec(args.base_spec), lanes.load_capture_spec(args.new_spec),
                args.evidence_root, args.output, admission._load(admission._read(args.review)) if args.review else None,
                reason=args.reason)
        else:
            path = args.capsule
            payload, _ = validate_capsule(path, actual_image=args.actual_image)
            if args.current_spec:
                check_current_spec(payload, lanes.load_capture_spec(args.current_spec))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"capture-control installation: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"capsule": str(path), "capsule_sha256": admission._sha(admission._read(path)),
                      "formal_accepted_trace_count": 0, "scientific_credit": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
