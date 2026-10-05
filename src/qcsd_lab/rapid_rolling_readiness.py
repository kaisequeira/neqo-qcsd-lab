"""Reopen an actual image-produced canary without executing its deep verifier.

This is a per-setting launch prerequisite, not a new deep-verification result.
The ordinary deep operation must already have succeeded in the exact installed
runtime. Every authoritative result byte and both actual operation records are
reopened here; host inspection never invokes Docker or gives scientific credit.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .application_response_policy import (
    application_response_identity_signature,
    validate_application_responses,
)
from .rapid_lane_evidence import RUNTIME_KEYS, TRAFFIC_FILES, verify_dns_receipt
from .util import SOURCE_METADATA_KEYS, durable_create
from .verification import _read_checksums, authoritative_files

MODES = {"undefended", "front", "tamaraw", "buflo", "cs-buflo"}
REFERENCE_KEYS = {"schema_version", "plan", "deep_receipt", "capture", "deep"}
OPERATION_KEYS = {"started", "completed", "stdout", "stderr"}
ZERO = {"scientific_credit": False, "site_credit": 0,
        "study_pilot_accepted_trace_count": 0, "formal_accepted_trace_count": 0}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
EQUIVALENCE_TYPE = "qcsd-rapid-v6-canary-measurement-source-equivalence"
# These are actual replay/capture/verification dependencies, not a recursive
# import closure through preparation's browser discovery producer. The old
# frozen browser graph remains a separately authenticated input.
DEPENDENCY_FILES = {
    "measurement": frozenset({
        "capture", "capture_session", "kernel_tx", "kernel_tx_runtime",
        "process_scheduler", "orchestrator", "experiment", "defenses",
        "parameters", "profiles", "cli",
    }),
    "acceptance": frozenset({
        "verification", "fidelity", "buflo_handoff", "buflo_evaluation",
        "capture_acceptance_policy", "application_response_policy", "manifest",
        "discovery_evidence", "browser_egress", "class_study", "util",
    }),
    "chaff": frozenset({"chaff_qualification", "__init__", "acquisition_errors"}),
}
STATIC_MEASUREMENT_FILES = frozenset({
    "Dockerfile", "docker/collection-entrypoint", "pyproject.toml", "uv.lock", ".dockerignore",
})
EQUIVALENCE_KEYS = {"schema_version", "artifact_type", "canary_plan_sha256",
    "original_runtime", "current_runtime", "original_inventory", "current_inventory",
    "dependency_groups", "original_source", "current_source", "client_sha256",
    "native_file_count", "shell_control_units", "published_at", *ZERO}


def _shell_projection(raw: bytes) -> tuple[bytes, dict[str, str]]:
    """Protect all launcher bytes outside the five reviewed rolling seams."""
    units = {}
    for name, old, new in (
        ("host-environment", b'    "QCSD_RAPID_EPOCH_LAUNCH_INPUT","QCSD_RAPID_COLLECTION_COMPATIBILITY",\n',
         b'    "QCSD_RAPID_EPOCH_LAUNCH_INPUT","QCSD_RAPID_ROLLING_LAUNCH_INPUT","QCSD_RAPID_COLLECTION_COMPATIBILITY",\n'),
        ("profile-version", b'  elif [[ "${rapid_capture_version}" == "v5" ]]; then\n',
         b'  elif [[ "${rapid_capture_version}" == "v5" || "${rapid_capture_version}" == "v6" ]]; then\n'),
    ):
        matched = [value for value in (old, new) if raw.count(value) == 1]
        if len(matched) != 1:
            raise ValueError("rolling shell projection lacks a unique reviewed exact line")
        value = matched[0]
        units[name] = _sha(value)
        raw = raw.replace(value, f"# rolling-canary-projection:{name}\n".encode())
    for name, starts, end in (
        ("selector", (b"rapid_v2_diagnostic_pattern=",), b'study_build_execution_path=""\n'),
        ("formal-predicate", (b'if role == "formal":\n',), b'elif role == "diagnostic" and study_version == "v5":\n'),
        ("authority-transport", (
            b'  if (( rapid_capture_epoch || rapid_compatibility_runtime_epoch )); then\n',
            b'  if (( rapid_capture_epoch || rapid_compatibility_runtime_epoch )) || [[ "${rapid_capture_version}" == "v6" ]]; then\n',
        ), b"  # Docker's isolated client bridge"),
    ):
        candidates = [value for value in starts if raw.count(value) == 1]
        if len(candidates) != 1 or raw.count(end) != 1:
            raise ValueError("rolling shell projection lacks a unique reviewed region")
        start = raw.index(candidates[0])
        stop = raw.index(end)
        if stop <= start:
            raise ValueError("rolling shell projection regions are out of order")
        units[name] = _sha(raw[start:stop])
        raw = raw[:start] + f"# rolling-canary-projection:{name}\n".encode() + raw[stop:]
    return raw, units


def _prepare_units(raw: bytes) -> dict[str, str]:
    """Bind the real qualification subprocess and provenance units only."""
    tree = ast.parse(raw)
    selected = {}
    imports = []
    globals_used = {"subprocess", "neqo_host_timeout", "capture_scheduler_launch_prefix",
        "datetime", "UTC", "run", "ProcessTimeoutError", "RecoverablePreparationError",
        "Path", "durable_create", "canonical_bytes", "hashlib"}
    seen_bindings = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            aliases = []
            for item in node.names:
                if item.name == "*":
                    raise ValueError("qualification preparation must not use wildcard bindings")
                name = item.asname or (item.name.split(".")[0] if isinstance(node, ast.Import) else item.name)
                if name in globals_used:
                    if name in seen_bindings:
                        raise ValueError("qualification preparation rebinds a protected import")
                    seen_bindings.add(name)
                    aliases.append(item)
            if aliases:
                projected = (ast.Import(names=aliases) if isinstance(node, ast.Import)
                    else ast.ImportFrom(module=node.module, names=aliases, level=node.level))
                imports.append(ast.dump(projected, include_attributes=False))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_run_neqo":
            if node.name in selected:
                raise ValueError("qualification preparation duplicates its subprocess unit")
            selected[node.name] = ast.dump(node, include_attributes=False)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in globals_used:
            raise ValueError("qualification preparation shadows a protected subprocess global")
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {item.id for target in targets for item in ast.walk(target) if isinstance(item, ast.Name)}
            if names & globals_used:
                raise ValueError("qualification preparation rebinds a protected subprocess global")
            if "NEQO_PROVENANCE_KEYS" in names:
                if "NEQO_PROVENANCE_KEYS" in selected:
                    raise ValueError("qualification preparation duplicates provenance keys")
                selected["NEQO_PROVENANCE_KEYS"] = ast.dump(node, include_attributes=False)
    if set(selected) != {"_run_neqo", "NEQO_PROVENANCE_KEYS"} or seen_bindings != globals_used:
        raise ValueError("qualification preparation lacks its exact subprocess/provenance dependencies")
    return {**{name: _sha(value.encode()) for name, value in selected.items()},
            "subprocess-imports": _sha(_encoded(imports))}


def _inventory(root: Path) -> dict[str, dict[str, Any]]:
    root = _path(root, directory=True)
    result = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError("equivalence source inventory contains a linked path")
        if path.is_file():
            result[relative.as_posix()] = {"sha256": _sha(_read(path)),
                                          "executable": bool(path.stat().st_mode & 0o111)}
    return dict(sorted(result.items()))


def _bound_inventory(reference: Any, root: Path) -> dict[str, dict[str, Any]]:
    _, raw = _reference(reference)
    value = _json(raw)
    if value != _inventory(root):
        raise ValueError("equivalence inventory does not cover the exact runtime source bytes")
    return value


def _groups(root: Path, inventory: Mapping[str, Any], *, amended_static: bool = False,
            duration_policy: str | None = None) -> tuple[dict[str, Any], dict[str, str]]:
    groups = {}
    for group, names in DEPENDENCY_FILES.items():
        relatives = {"src/qcsd_lab/" + name + ".py" for name in names}
        if group == "measurement":
            relatives.update(STATIC_MEASUREMENT_FILES)
        groups[group] = {relative: inventory[relative] for relative in sorted(relatives)}
    if amended_static:
        # This prospective role binds the new adapter and FRONT V4 verifier.
        # Historical dependency groups keep their exact interpretation.
        from .supplied_static_capture_amendment import SOURCE_FILES
        groups["static-capture-amendment-v1"] = {
            relative: inventory[relative] for relative in sorted(SOURCE_FILES.values())}
        if duration_policy is not None:
            from .supplied_static_capture_amendment import DURATION_SOURCE_FILES
            groups["static-buflo-duration200-v1"] = {
                relative: inventory[relative] for relative in sorted(DURATION_SOURCE_FILES.values())}
    elif duration_policy is not None:
        raise ValueError("BuFLO200 equivalence requires its static amendment authority")
    protected, shell_units = _shell_projection(_read(root / "qcsd-lab"))
    groups["measurement"]["qcsd-lab:protected-measurement"] = {
        "sha256": _sha(protected), "executable": inventory["qcsd-lab"]["executable"]}
    for name, digest in _prepare_units(_read(root / "src/qcsd_lab/prepare.py")).items():
        groups["chaff"]["src/qcsd_lab/prepare.py:" + name] = {"sha256": digest,
            "executable": inventory["src/qcsd_lab/prepare.py"]["executable"]}
    from .rapid_capture_traffic import files
    groups["traffic"] = {relative: inventory[relative] for relative, _ in files(duration_policy).values()}
    groups["native"] = {relative: value for relative, value in inventory.items() if relative.startswith("neqo-qcsd/")}
    if not groups["native"]:
        raise ValueError("equivalence requires the entire nonempty Native source inventory")
    return groups, shell_units


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _encoded(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("canary JSON contains a duplicate key")
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    if not isinstance(value, dict):
        raise ValueError("canary evidence must contain a JSON object")
    return value


def _path(value: Any, *, directory: bool = False) -> Path:
    if not isinstance(value, (str, Path)):
        raise ValueError("canary path is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path != path.absolute():
        raise ValueError("canary paths must be absolute and canonical")
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("canary evidence must not follow symlinks")
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError("canary evidence path is absent or has another type")
    return path


def _read(path: Path, digest: Any = None) -> bytes:
    raw = _path(path).read_bytes()
    if digest is not None and (not isinstance(digest, str) or _SHA.fullmatch(digest) is None
                               or _sha(raw) != digest):
        raise ValueError("canary evidence SHA-256 differs")
    return raw


def _reference(value: Any) -> tuple[Path, bytes]:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
        raise ValueError("canary file reference has an invalid exact schema")
    path = _path(value["path"])
    return path, _read(path, value["sha256"])


def _child(root: Path, relative: Any) -> Path:
    if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
        or ".." in Path(relative).parts or Path(relative).as_posix() != relative):
        raise ValueError("canary relative input path is invalid")
    return _path(root / relative)


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("canary operation timestamp is invalid")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("canary operation timestamp lacks a timezone")
    return result


def _operation(value: Any, directory: Path, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != OPERATION_KEYS:
        raise ValueError("canary operation has an invalid exact schema")
    contents = {}
    for key, suffix in (("started", "-started.json"), ("completed", "-completed.json"),
                        ("stdout", ".stdout.log"), ("stderr", ".stderr.log")):
        path, contents[key] = _reference(value[key])
        if path != directory / "logs" / (name + suffix):
            raise ValueError("canary operation refers to another record or log")
    start, end = _json(contents["started"]), _json(contents["completed"])
    elapsed = end.get("elapsed_seconds")
    command = start.get("command")
    if (type(end.get("returncode")) is not int or end["returncode"] != 0
        or end.get("invocation_error") is not None
        or end.get("stdout_sha256") != _sha(contents["stdout"])
        or end.get("stderr_sha256") != _sha(contents["stderr"])
        or type(elapsed) not in {int, float} or not math.isfinite(elapsed) or elapsed < 0
        or not isinstance(command, list) or not command
        or any(not isinstance(item, str) or not item for item in command)
        or _timestamp(end.get("completed_at")) < _timestamp(start.get("started_at"))):
        raise ValueError("canary lacks a successful actual operation and unchanged raw logs")
    return {"command": command, "start": _timestamp(start["started_at"]),
            "end": _timestamp(end["completed_at"]), "elapsed_seconds": elapsed}


def _clean_source(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != SOURCE_METADATA_KEYS
        or value.get("lab_dirty") is not False or value.get("neqo_dirty") is not False
        or value.get("image_digest") is not None
        or value.get("neqo_commit") != value.get("neqo_pinned_commit")
        or any(not isinstance(value.get(key), str) or re.fullmatch(r"[0-9a-f]{40}", value[key]) is None
               for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"))
        or any(value.get(key) != _sha(b"") for key in ("lab_patch_sha256", "neqo_patch_sha256"))):
        raise ValueError("canary requires its exact clean Lab and pinned Native source")
    return value


def _deep_command(plan: Mapping[str, Any], directory: Path, plan_sha: str,
                  mode: str, declared_root: str, command: list[str], *, ordinary_transport: str | None = None) -> list[str]:
    # The retained recipe uses the operator's UID, not the verifier's current UID.
    try:
        user = command[command.index("--user") + 1]
        mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--volume"]
        recipe_mount, = [item for item in mounts if item.endswith(":/recipe.py:ro")]
        helper_mount, = [item for item in mounts if item.endswith(":/helpers.py:ro")]
    except (ValueError, IndexError) as error:
        raise ValueError("canary deep operation lacks its installed verifier transport") from error
    if re.fullmatch(r"[0-9]+:[0-9]+", user) is None:
        raise ValueError("canary verifier user is invalid")
    recipe = _path(recipe_mount.removesuffix(":/recipe.py:ro"))
    helper = _path(helper_mount.removesuffix(":/helpers.py:ro"))
    _read(recipe, plan["recipe_sha256"])
    _read(helper, plan["helper_sha256"])
    image = plan["canonical_runtime"]["collection_image_digest"]
    static_mounts = []
    if "static_capture_amendment" in plan:
        from .static_evidence_transport import amended_canary_roots
        roots = amended_canary_roots(plan, directory)
    else:
        original = _json(_read(directory / "lineage/original-manifest.json", plan["original_workload_sha256"]))
        from .static_evidence_transport import manifest_roots
        roots = manifest_roots(original)
    if "qualification_delivery_compatibility" in plan:
        from .application_response_policy import application_body_identity_policy
        from .qualification_control_authority import roots as witness_roots
        roots = sorted(set(roots) | set(witness_roots(plan["qualification_delivery_compatibility"],
                       body_policy=application_body_identity_policy(plan))))
    for root in roots:
        static_mounts.extend(["--volume", f"{root}:{root}:ro"])
    if ordinary_transport is not None:
        from .rapid_ordinary_canary_retry import transport_mounts
        static_mounts = transport_mounts(plan, directory, static_mounts, complete=ordinary_transport == "group")
    return ["docker", "run", "--rm", "--name", f'qcsd-v12-{plan["name"]}-verify-image',
            "--network", "none", "--user", user, "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL", "--env", f"QCSD_LAB_IMAGE_DIGEST={image}",
            "--env", "QCSD_LAB_ROOT=/lab", "--env",
            "QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json", "--env",
            "QCSD_PUBLIC_ORIGIN_ONLY=1", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--volume", f'{plan["clean_runtime_root"]}:/runtime-src:ro',
            "--volume", f'{plan["execution_root"]}:/lab:ro', "--volume",
            f"{directory}:/diagnostic:rw", "--volume", recipe_mount, "--volume", helper_mount,
            *static_mounts,
            "--workdir", "/lab", "--entrypoint", "/opt/qcsd-venv/bin/python3", image,
            "-I", "-B", "/recipe.py", "verify-image", "--plan", "/diagnostic/plan.json",
            "--plan-sha256", plan_sha, "--mode", mode, "--result", declared_root]


def _qualification(plan: Mapping[str, Any], directory: Path, execution: Path,
                   config: Mapping[str, Any], workload: Mapping[str, Any], source: Mapping[str, Any]) -> str:
    from .response_budget_qualification import load_named_qualification_set

    completion = _json(_read(directory / "qualification-complete.json"))
    named_path = execution / "config/chaff-response-qualification-store/sets" / plan["qualification_set"] / "_qualification-set.json"
    _read(named_path, completion.get("named_manifest_sha256"))
    # Historical inspection is followed by explicit equality with THIS bound
    # runtime. It does not assert that the host inspection package was installed.
    named = load_named_qualification_set(named_path, workload_root=execution / "config/workloads",
        expected_qualification_set=plan["qualification_set"], expected_qualification_scope="response-only",
        expected_workload_ids=[plan["workload_id"]], require_current_implementation=False)
    sidecar_path = named_path.parent / (plan["workload_id"] + ".json")
    sidecar = _json(_read(sidecar_path, completion.get("sidecar_sha256")))
    from .qualification_control_authority import FIELD, POLICY_FIELD, validate_sidecar
    compatibility = plan.get(FIELD)
    if compatibility is not None:
        if (config.get(POLICY_FIELD) != plan.get(POLICY_FIELD)
            or not isinstance(config.get(FIELD), Mapping)
            or config[FIELD].get("sha256") != compatibility.get("sha256")):
            raise ValueError("canary qualification compatibility differs from its explicit captured policy")
        validate_sidecar(sidecar, plan["canonical_runtime"], workload_id=plan["workload_id"],
            workload_sha256=plan["workload_sha256"], reference=compatibility,
            body_policy=plan.get(POLICY_FIELD))
    if ((compatibility is None and (sidecar.get("qualification_source") != source
        or sidecar.get("qualification_image_digest") != source["image_digest"]
        or sidecar.get("implementation_receipt", {}).get("sha256")
        != plan["canonical_runtime"]["checks"]["collection"]["qualification_implementation_sha256"]))
        or config.get("chaff_qualification_set") != plan["qualification_set"]
        or config.get("chaff_qualification_set_manifest_sha256") != named.manifest_sha256
        or workload.get("chaff_qualification_sha256") != completion["sidecar_sha256"]):
        raise ValueError("canary qualification differs from its actual bound runtime or inputs")
    return named.manifest_sha256


def _validate_canary(reference: Mapping[str, Any], *, runtime: Mapping[str, str], mode: str,
                     _transport_recovery=None) -> dict[str, Any]:
    """Reopen one recorded complete canary for an exact collection runtime.

    ``reference`` has schema_version=1, plan/deep_receipt file references and
    capture/deep operations. Each operation has started/completed/stdout/stderr
    references; every file reference has exactly absolute path and sha256.
    ``runtime`` is rapid_lane_evidence.RUNTIME_KEYS. Its actual installed image
    preflight must be checked independently by the caller against these facts.
    """
    if (not isinstance(reference, Mapping) or set(reference) != REFERENCE_KEYS
        or type(reference.get("schema_version")) is not int or reference["schema_version"] != 1
        or not isinstance(runtime, Mapping) or set(runtime) != RUNTIME_KEYS
        or mode not in MODES):
        raise ValueError("rolling canary reference, runtime or setting is invalid")
    plan_path, plan_raw = _reference(reference["plan"])
    receipt_path, receipt_raw = _reference(reference["deep_receipt"])
    directory = plan_path.parent
    if plan_path.name != "plan.json" or receipt_path != directory / f"{mode}-deep-verification.json":
        raise ValueError("canary plan or deep receipt belongs to another setting")
    plan, receipt = _json(plan_raw), _json(receipt_raw)
    canonical_raw = _read(directory / "canonical-runtime.json", plan["canonical_runtime_sha256"])
    canonical = _json(canonical_raw)
    if canonical != plan["canonical_runtime"]:
        raise ValueError("canary canonical runtime differs from its frozen plan")
    source = _clean_source(_json(_read(_path(runtime["source_manifest"]))))
    client_sha = _sha(_read(_path(runtime["client_binary"])))
    image = runtime["collection_image_digest"]
    collection = canonical["checks"]["collection"]
    if (_IMAGE.fullmatch(image) is None or canonical["source"] != source
        or canonical["collection_image_digest"] != image or collection["source"] != source
        or collection["image_digest"] != image or collection["client_sha256"] != client_sha
        or canonical["installed_client_sha256"] != client_sha
        or canonical.get("installed_byte_verification_completed") is not True
        or canonical["exported_source_manifest_sha256"] != _sha(_read(_path(runtime["source_manifest"])))
        or plan["expected_lab_commit"] != source["lab_commit"]
        or plan["expected_native_commit"] != source["neqo_commit"]):
        raise ValueError("canary changed the current source, collection image or installed client")
    execution = _path(plan["execution_root"], directory=True)
    current_execution = _path(runtime["execution_root"], directory=True)
    clean = _path(plan["clean_runtime_root"], directory=True)
    from .rapid_capture_traffic import canary_files
    selected_traffic = canary_files(plan, mode)
    traffic = {key: _sha(_read(_child(current_execution, relative)))
               for key, (relative, _) in selected_traffic.items()}
    if traffic != plan["traffic_hashes"] or traffic != {key: digest for key, (_, digest) in selected_traffic.items()}:
        raise ValueError("canary changes the fixed traffic settings")
    for key, (relative, _) in selected_traffic.items():
        _read(_child(execution, relative), traffic[key])
    inventory = _json(_read(directory / "source-inventory.json", canonical["source_inventory_sha256"]))
    if not inventory or "qcsd-lab" not in inventory:
        raise ValueError("canary source inventory omits its actual launcher")
    for relative, record in inventory.items():
        if not isinstance(record, Mapping) or set(record) != {"sha256", "executable"}:
            raise ValueError("canary source inventory record is invalid")
        for root in (clean, execution):
            path = _child(root, relative)
            _read(path, record["sha256"])
            if bool(path.stat().st_mode & 0o111) is not record["executable"]:
                raise ValueError("canary source executable identity differs")
    matching = [item for item in plan["campaigns"] if isinstance(item, dict) and item.get("mode") == mode]
    if len(matching) != 1:
        raise ValueError("canary setting is absent or repeated")
    campaign = matching[0]
    campaign_path = _child(execution, campaign["campaign_relative"])
    _read(campaign_path, campaign["campaign_sha256"])
    if (type(campaign.get("visits")) is not int or campaign["visits"] != 1
        or any(type(receipt.get(key)) is not type(value) or receipt[key] != value for key, value in ZERO.items())
        or receipt.get("valid") is not True or receipt.get("status") != "complete"
        or receipt.get("mode") != mode or receipt.get("purpose") != "smoke"
        or receipt.get("name") != campaign["name"]
        or type(receipt.get("accepted_samples")) is not int or receipt["accepted_samples"] != 1
        or receipt.get("source") != source or receipt.get("plan_sha256") != _sha(plan_raw)
        or receipt.get("canonical_runtime_sha256") != _sha(canonical_raw)
        or receipt.get("selection_sha256") != plan["selection_sha256"]
        or receipt.get("workload_sha256") != plan["workload_sha256"]):
        raise ValueError("canary lacks an exact complete zero-credit deep receipt")
    declared = Path(receipt.get("root", ""))
    if declared.parent != Path("/lab/results") / campaign["name"]:
        raise ValueError("canary result is not a direct child of its bound campaign")
    result = _path(execution / "results" / campaign["name"] / declared.name, directory=True)
    checksums = _read_checksums(result, result / "evidence.sha256")
    files = authoritative_files(result)
    if (set(files) != set(checksums) or type(receipt.get("authoritative_files")) is not int
        or receipt["authoritative_files"] != len(files)):
        raise ValueError("canary evidence seal does not cover its exact authoritative files")
    for relative, path in files.items():
        _read(path, checksums[relative])
    _read(result / "evidence.sha256", receipt["evidence_index_sha256"])
    experiment = _json(_read(result / "experiment.json", receipt["experiment_sha256"]))
    config, summary = experiment["configuration"], experiment["summary"]
    from .application_response_policy import application_body_identity_policy
    body_policy = application_body_identity_policy(plan)
    if (application_body_identity_policy(config) != body_policy
        or application_body_identity_policy(receipt) != body_policy):
        raise ValueError("canary plan, actual configuration and deep receipt changed application body policy")
    if (config.get("qualification_delivery_compatibility") != plan.get("qualification_delivery_compatibility")
        or receipt.get("qualification_delivery_compatibility") != plan.get("qualification_delivery_compatibility")):
        raise ValueError("canary plan, configuration and deep receipt changed qualification delivery witness")
    from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
    if body_policy == COMPLETE_APPLICATION_DELIVERY_POLICY and receipt.get("content_equality_across_visits_claimed") is not False:
        raise ValueError("complete delivery deep receipt falsely claims cross-visit content equality")
    actual_source = {**source, "image_digest": image}
    workloads, defenses, samples = config["workloads"], config["defenses"], experiment["samples"]
    if (experiment.get("status") != "complete" or experiment.get("name") != campaign["name"]
        or experiment.get("purpose") != "smoke" or experiment.get("source") != actual_source
        or any(type(summary.get(key)) is not int or summary[key] != expected
               for key, expected in (("planned", 1), ("accepted", 1), ("failed", 0)))
        or summary.get("passed") is not True
        or config.get("campaign_sha256") != campaign["campaign_sha256"]
        or config.get("limits") != campaign["limits"] or config.get("profile") != "research-1200"
        or config.get("request_policies") != ["as-defined"]
        or len(workloads) != 1 or len(defenses) != 1 or len(samples) != 1
        or defenses[0].get("name") != mode or workloads[0].get("id") != plan["workload_id"]
        or workloads[0].get("sha256") != plan["workload_sha256"]
        or type(workloads[0].get("visits")) is not int or workloads[0]["visits"] != 1
        or samples[0].get("state") != "accepted" or samples[0].get("defense") != mode
        or samples[0].get("workload_id") != plan["workload_id"]
        or samples[0].get("request_policy") != "as-defined"
        or type(samples[0].get("visit")) is not int or samples[0]["visit"] != 0):
        raise ValueError("canary result differs from its full single-visit frozen setting")
    manifest_raw = _read(_child(result, workloads[0]["manifest"]), plan["workload_sha256"])
    manifest = _json(manifest_raw)
    resources = manifest["resources"]
    original = _json(_read(directory / "lineage/original-manifest.json", plan["original_workload_sha256"]))
    if resources != original.get("resources"):
        raise ValueError("canary changed or pruned its original full resource graph")
    origins = sorted({f'{urlsplit(row["url"]).scheme}://{urlsplit(row["url"]).netloc}' for row in resources})
    graph = {"resource_count": len(resources), "resource_records_sha256": _sha(_encoded(resources)), "origins": origins}
    if (not resources or len({row["id"] for row in resources}) != len(resources)
        or graph != plan["full_graph"] or receipt.get("full_graph") != graph):
        raise ValueError("canary did not retain its whole frozen resource and origin graph")
    run = _json(_read(_child(result, samples[0]["path"] + "/neqo/run.json")))
    response = validate_application_responses(manifest, run, body_identity_policy=body_policy)
    identity = application_response_identity_signature(manifest, response["response_signature"], body_identity_policy=body_policy)
    if (receipt.get("response_identity_sha256") != _sha(_encoded(identity))
        or sorted(str(row["origin"]).rstrip("/") for row in run["endpoints"]) != origins):
        raise ValueError("canary changed its actual complete response identity or endpoints")
    dns_sha = verify_dns_receipt(_read(directory / "dns-receipts" / (mode + ".json")),
                                 campaign["name"], {plan["workload_id"]: manifest_raw})
    if receipt.get("dns_receipt_sha256") != dns_sha:
        raise ValueError("canary DNS receipt differs from the completed deep proof")
    qualification_sha = None
    if mode != "undefended":
        qualification_sha = _qualification(plan, directory, execution, config, workloads[0], actual_source)
    if mode in {"buflo", "cs-buflo"}:
        key = "buflo_parameters_sha256" if mode == "buflo" else "cs_buflo_parameters_sha256"
        if defenses[0].get("parameters_sha256") != traffic[key]:
            raise ValueError("canary capture changed the defended parameter receipt")
    capture = _operation(reference["capture"], directory, mode + "-capture")
    deep = (_operation(reference["deep"], directory, mode + "-deep")
            if _transport_recovery is None else _transport_recovery)
    expected_capture = ["env", f"QCSD_LAB_COLLECTION_IMAGE={image}",
        f"QCSD_RAPID_IMAGE_SOURCE_QCSD={clean / 'qcsd-lab'}",
        f"QCSD_RAPID_DNS_RECEIPT_PATH={directory / 'dns-receipts' / (mode + '.json')}",
        str(execution / "qcsd-lab"), "run", str(campaign_path)]
    expected_deep = (_deep_command(plan, directory, _sha(plan_raw), mode, str(declared), deep["command"])
                     if _transport_recovery is None else _transport_recovery["expected_command"])
    if (capture["command"] != campaign["run_argv"] or capture["command"] != expected_capture
        or deep["command"] != expected_deep
        or deep["start"] < capture["end"]
        or not deep["start"] <= _timestamp(receipt.get("completed_at")) <= deep["end"]):
        raise ValueError("canary actual capture/deep commands or causal completion order differ")
    facts = {"schema_version": 1, "mode": mode, "source": actual_source, "client_sha256": client_sha,
            "traffic_hashes": traffic, "canary_plan_sha256": _sha(plan_raw),
            "deep_receipt_sha256": _sha(receipt_raw), "canonical_runtime_sha256": _sha(canonical_raw),
            "result_root": str(result), "result_seal_sha256": receipt["evidence_index_sha256"],
            "full_graph": graph, "workload_sha256": plan["workload_sha256"],
            "qualification_manifest_sha256": qualification_sha, "recorded_image_deep_reopened": True,
            "fresh_deep_verification_performed": False, **ZERO}
    if "application_body_identity_policy" in plan:
        facts["application_body_identity_policy"] = body_policy
    if "qualification_delivery_compatibility" in plan:
        facts["qualification_delivery_compatibility"] = plan["qualification_delivery_compatibility"]
    return facts


def validate_canary(reference: Mapping[str, Any], *, runtime: Mapping[str, str], mode: str) -> dict[str, Any]:
    """Reopen one schema-one per-setting canary using RUNTIME_KEYS inputs.

    File references contain exactly ``path`` and ``sha256``. The reference has
    ``plan``, ``deep_receipt``, and ``capture``/``deep`` operations; operations
    contain ``started``, ``completed``, ``stdout`` and ``stderr`` file references.
    Schema two additionally has one ``source_equivalence`` file reference.
    No subprocess or fresh deep verification is performed. The caller compares
    ``authority_source``/client/traffic to its actual installed image preflight;
    ``source`` always retains the original actual canary source and image.
    """
    try:
        if isinstance(reference, Mapping) and reference.get("schema_version") == 4:
            from .rapid_ordinary_canary_retry import validate
            return validate(reference, runtime=runtime, mode=mode)
        if isinstance(reference, Mapping) and reference.get("schema_version") == 3:
            from .rapid_canary_control_bridge import validate
            return validate(reference, runtime=runtime, mode=mode)
        if isinstance(reference, Mapping) and reference.get("schema_version") == 2:
            return _validate_equivalent(reference, runtime=runtime, mode=mode)
        result = _validate_canary(reference, runtime=runtime, mode=mode)
        return {**result, "authority_source": result["source"], "source_equivalence_sha256": None,
                "source_equivalence_published_at": None}
    except (KeyError, IndexError, TypeError, OSError) as error:
        raise ValueError("canary evidence has a missing field or invalid typed input") from error


def readiness_mount_roots(reference: Mapping[str, Any], *, runtime: Mapping[str, str],
                          mode: str, _context=None) -> list[Path]:
    """Derive the read-only transport for a reopened canary, without executing it.

    These roots let the actual installed validator reopen the same historical
    records and source roles. They grant no writable evidence namespace and
    come only from the closed reference and its authenticated runtime inputs.
    """
    if isinstance(reference, Mapping) and reference.get("schema_version") == 4:
        from .rapid_ordinary_canary_retry import roots
        return roots(reference, runtime=runtime, mode=mode)
    if isinstance(reference, Mapping) and reference.get("schema_version") == 3:
        from .rapid_canary_control_bridge import roots
        return roots(reference, runtime=runtime, mode=mode)
    if _context is None:
        validate_canary(reference, runtime=runtime, mode=mode)
    else:
        _context.validate_canary(reference, runtime, mode, validate_canary)
    plan_path, plan_raw = _reference(reference["plan"])
    plan = _json(plan_raw)
    roots = {plan_path.parent, _path(plan["clean_runtime_root"], directory=True),
             _path(plan["execution_root"], directory=True)}
    if "static_capture_amendment" in plan:
        from .static_evidence_transport import amended_canary_roots
        roots.update(amended_canary_roots(plan, plan_path.parent))
    else:
        from .static_evidence_transport import manifest_roots
        original = _json(_read(plan_path.parent / "lineage/original-manifest.json", plan["original_workload_sha256"]))
        roots.update(manifest_roots(original))
    if "qualification_delivery_compatibility" in plan:
        from .application_response_policy import application_body_identity_policy
        from .qualification_control_authority import roots as witness_roots
        roots.update(witness_roots(plan["qualification_delivery_compatibility"],
                                  body_policy=application_body_identity_policy(plan)))
    runtimes = [runtime]
    if reference["schema_version"] == 2:
        capsule_path, capsule_raw = _reference(reference["source_equivalence"])
        capsule = _json(capsule_raw)
        roots.add(capsule_path.parent)
        inventory_path, _ = _reference(capsule["current_inventory"])
        roots.add(inventory_path.parent)
        runtimes.append(capsule["original_runtime"])
    for role in runtimes:
        roots.update(_path(role[key], directory=True)
                     for key in ("runtime_source_root", "module_root", "execution_root"))
        roots.update(_path(role[key]).parent
                     for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    _, deep_start_raw = _reference(reference["deep"]["started"])
    command = _json(deep_start_raw)["command"]
    for target in ("/recipe.py", "/helpers.py"):
        suffix = ":" + target + ":ro"
        mount, = [command[index + 1] for index, item in enumerate(command)
                  if item == "--volume" and command[index + 1].endswith(suffix)]
        roots.add(_path(mount.removesuffix(suffix)).parent)
    for root in roots:
        _path(root, directory=True)
        if any(character in str(root) for character in ("\n", "\r", "\0", ":")):
            raise ValueError("readiness mounts require regular absolute transport-safe directories")
    return sorted(roots)


def _equivalence(reference: Mapping[str, Any], *, original_runtime: Mapping[str, str],
                 runtime: Mapping[str, str], current_inventory: Mapping[str, str],
                 original_result: Mapping[str, Any]) -> dict[str, Any]:
    if (not isinstance(runtime, Mapping) or set(runtime) != RUNTIME_KEYS
        or any(not isinstance(value, str) for value in runtime.values())
        or _IMAGE.fullmatch(runtime["collection_image_digest"]) is None):
        raise ValueError("equivalence current runtime has an invalid exact schema")
    plan_path, plan_raw = _reference(reference["plan"])
    plan = _json(plan_raw)
    original_inventory = {"path": str(plan_path.parent / "source-inventory.json"),
                          "sha256": plan["canonical_runtime"]["source_inventory_sha256"]}
    original_root = _path(original_runtime["runtime_source_root"], directory=True)
    if original_root != _path(plan["clean_runtime_root"], directory=True):
        raise ValueError("equivalence original runtime source is not the actual canary source")
    current_root = _path(runtime["runtime_source_root"], directory=True)
    old_inventory = _bound_inventory(original_inventory, original_root)
    new_inventory = _bound_inventory(current_inventory, current_root)
    result_root = _path(original_result["result_root"], directory=True)
    experiment = _json(_read(result_root / "experiment.json"))
    manifest = _json(_read(_child(result_root,
        experiment["configuration"]["workloads"][0]["manifest"]), plan["workload_sha256"]))
    from .rapid_selected_capture_input import is_selected
    from .selected_capture_amendment import is_amended as is_selected_amended
    from .rapid_selected_budget_input import is_selected as is_selected_budget
    from .per_class_selected_capture_amendment import is_amended as is_per_class_amended
    if is_selected_budget(manifest.get("preparation")) or is_per_class_amended(manifest.get("preparation")):
        raise ValueError("per-class selected canary requires its actual current qualification/readiness Source")
    if is_selected(manifest.get("preparation")) or is_selected_amended(manifest.get("preparation")):
        raise ValueError("selected-input canary requires fresh qualification and readiness under its own Source")
    from .whole_graph_supplement import is_whole
    from .whole_graph_capture_amendment import is_amended as is_whole_amended
    from .supplied_static_budget_successor import is_budget
    from .static_budget_capture_amendment import is_amended as is_budget_amended
    if is_budget(manifest.get("preparation")) or is_budget_amended(manifest.get("preparation")):
        raise ValueError("response-budget canary Source reuse requires a separately registered prospective projection")
    if is_whole(manifest.get("preparation")) or is_whole_amended(manifest.get("preparation")):
        raise ValueError("whole graph canary Source reuse requires its separately registered prospective projection")
    from .supplied_static_capture_amendment import is_amended
    amended_static = is_amended(manifest.get("preparation"))
    if amended_static != ("static_capture_amendment" in plan):
        raise ValueError("canary equivalence changed its explicit static amendment authority")
    if amended_static:
        from .supplied_static_capture_amendment import _closed
        amendment_path, _ = _reference(plan["static_capture_amendment"])
        amendment = _closed(amendment_path)
        if ({key: amendment["runtime"][key] for key in RUNTIME_KEYS} != original_runtime
            or sum(row["capture_manifest"]["sha256"] == plan["workload_sha256"]
                   for row in amendment["workloads"]) != 1):
            raise ValueError("canary equivalence changed its original amended runtime or workload")
    from .rapid_capture_traffic import FIELD, canary_policy, files
    duration_policy = canary_policy(plan)
    if amended_static and amendment.get(FIELD) != duration_policy:
        raise ValueError("canary equivalence changed its explicit BuFLO duration policy")
    old_groups, old_shell = _groups(original_root, old_inventory, amended_static=amended_static,
                                   duration_policy=duration_policy)
    new_groups, new_shell = _groups(current_root, new_inventory, amended_static=amended_static,
                                   duration_policy=duration_policy)
    if old_groups != new_groups:
        differing = sorted(name for name in old_groups if old_groups[name] != new_groups[name])
        raise ValueError("canary equivalence changes protected dependencies: " + ", ".join(differing))
    source = _clean_source(_json(_read(_path(runtime["source_manifest"]))))
    authority_source = {**source, "image_digest": runtime["collection_image_digest"]}
    client_sha = _sha(_read(_path(runtime["client_binary"])))
    if (client_sha != original_result["client_sha256"]
        or source["neqo_commit"] != original_result["source"]["neqo_commit"]):
        raise ValueError("canary equivalence changes the exact installed client or Native commit")
    current_execution = _path(runtime["execution_root"], directory=True)
    traffic = {key: _sha(_read(_child(current_execution, relative)))
               for key, (relative, _) in files(duration_policy).items()}
    if traffic != original_result["traffic_hashes"]:
        raise ValueError("canary equivalence changes the current traffic settings")
    return {"schema_version": 1, "artifact_type": EQUIVALENCE_TYPE,
        "canary_plan_sha256": _sha(plan_raw), "original_runtime": dict(original_runtime),
        "current_runtime": dict(runtime), "original_inventory": original_inventory,
        "current_inventory": dict(current_inventory),
        "dependency_groups": {name: {"files": len(entries), "sha256": _sha(_encoded(entries))}
                              for name, entries in old_groups.items()},
        "original_source": original_result["source"], "current_source": authority_source,
        "client_sha256": client_sha, "native_file_count": len(old_groups["native"]),
        "shell_control_units": {"original": old_shell, "current": new_shell}, **ZERO}


def build_source_equivalence(reference: Mapping[str, Any], *, original_runtime: Mapping[str, str],
                             runtime: Mapping[str, str], current_inventory: Mapping[str, str],
                             mode: str) -> dict[str, Any]:
    """Derive a prospective capsule; the caller publishes it create-only.

    This performs only host reopening. It authorizes reuse of a canary launch
    prerequisite and carries no authority to reuse enrollment qualifications,
    import admission decisions or give scientific credit to the old result.
    The actual current installed image check remains a separate prerequisite.
    """
    try:
        original = _validate_canary(reference, runtime=original_runtime, mode=mode)
        return _equivalence(reference, original_runtime=original_runtime, runtime=runtime,
                            current_inventory=current_inventory, original_result=original)
    except (KeyError, IndexError, TypeError, OSError) as error:
        raise ValueError("canary equivalence has missing or invalid typed evidence") from error


def publish_source_equivalence(reference: Mapping[str, Any], output: Path, *,
                               original_runtime: Mapping[str, str], runtime: Mapping[str, str],
                               current_inventory: Mapping[str, str], mode: str) -> dict[str, str]:
    """Publish only derived source equivalence, without any image execution.

    The caller must subsequently obtain a real current image runtime preflight
    and bind this timestamp before its lane intent. Existing output is never
    overwritten; no scientific, site or historical qualification credit moves.
    """
    output = Path(output)
    if (not output.is_absolute() or ".." in output.parts
        or any(item.is_symlink() for item in (output, *output.parents))):
        raise ValueError("equivalence output must be an absolute unlinked create-only path")
    if output.exists():
        raise FileExistsError("canary source equivalence output is already claimed")
    if any(output.is_relative_to(_path(role["runtime_source_root"], directory=True))
           for role in (original_runtime, runtime)):
        raise ValueError("canary equivalence output must remain outside both frozen Source roots")
    capsule = build_source_equivalence(reference, original_runtime=original_runtime, runtime=runtime,
                                       current_inventory=current_inventory, mode=mode)
    capsule["published_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    raw = _encoded(capsule)
    durable_create(output, raw)
    return {"path": str(output), "sha256": _sha(raw)}


def _validate_equivalent(reference: Mapping[str, Any], *, runtime: Mapping[str, str], mode: str) -> dict[str, Any]:
    if (set(reference) != REFERENCE_KEYS | {"source_equivalence"}
        or type(reference["schema_version"]) is not int or reference["schema_version"] != 2):
        raise ValueError("equivalent canary reference has an invalid exact schema")
    _, raw = _reference(reference["source_equivalence"])
    capsule = _json(raw)
    if (set(capsule) != EQUIVALENCE_KEYS or type(capsule["schema_version"]) is not int
        or capsule["schema_version"] != 1 or capsule["artifact_type"] != EQUIVALENCE_TYPE
        or capsule["current_runtime"] != runtime
        or any(type(capsule[key]) is not type(value) or capsule[key] != value for key, value in ZERO.items())):
        raise ValueError("canary equivalence capsule has an invalid exact scope or authority")
    if _timestamp(capsule["published_at"]) > datetime.now(UTC):
        raise ValueError("canary equivalence publication is in the future")
    original_reference = {key: value for key, value in reference.items() if key != "source_equivalence"}
    original_reference["schema_version"] = 1
    original = _validate_canary(original_reference, runtime=capsule["original_runtime"], mode=mode)
    expected = _equivalence(original_reference, original_runtime=capsule["original_runtime"], runtime=runtime,
                            current_inventory=capsule["current_inventory"], original_result=original)
    expected["published_at"] = capsule["published_at"]
    if capsule != expected:
        raise ValueError("canary equivalence capsule differs from its reopened source roles and dependencies")
    return {**original, "authority_source": capsule["current_source"],
            "source_equivalence_sha256": _sha(raw), "dependency_groups": capsule["dependency_groups"],
            "native_file_count": capsule["native_file_count"],
            "source_equivalence_published_at": capsule["published_at"]}
