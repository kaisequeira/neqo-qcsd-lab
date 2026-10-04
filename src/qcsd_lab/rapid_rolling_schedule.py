"""Prospective scheduling-only qualification reuse for rolling formal capture.

This authority preserves the original enrollment, prepared graphs and named
120-response qualification. It permits a reviewed serial-to-parallel control
change after older formal lanes exist. It does not validate traffic, replace an
admission decision, promote diagnostics, or authorize retrying a completed lane.
The historical installation and failed-lane contracts remain unchanged.
"""
from __future__ import annotations

import ast
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import chaff_qualification as qualification
from . import rapid_capture_control_compatibility as control
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_rolling_readiness as evidence
from . import rapid_runtime_compatibility as historical
from .util import durable_create

CAPSULE_TYPE = "qcsd-rapid-v6-prospective-parallel-scheduling"
CONTRACT_V1 = "rolling-v6-unchanged-qualification-parallel-scheduling-v1"
CONTRACT_V2 = "rolling-v6-pre-birth-release-parallel-scheduling-v2"
CONTRACT_V3 = "rolling-v6-lifecycle-first-parallel-scheduling-v3"
CONTRACT_V4 = "rolling-v6-observed-prebirth-retirement-parallel-scheduling-v4"
CONTRACT = "rolling-v6-operation-local-verification-facts-parallel-scheduling-v5"
V1_HELPER_SHA256 = "d4efd16eb61a7458d77ee0a4d218323fc2e15c5016a1f4e0888d22b5c63c8605"
V2_HELPER_SHA256 = "1880eb36f622cb2ea17c5363cae9d90243189387d598eca70febb776b75120d8"
V3_HELPER_SHA256 = "2f962c2332731d14e24503c6d68bd08c5c2bda8578671bde2b81354b9dc36f6b"
V4_HELPER_SHA256 = "18afc767c2c08066b4f547b19af414ef00373456bbd97964c50bbcf769e8f6b0"
FACTS_FILE = "src/qcsd_lab/rapid_operation_facts.py"
MODULE_FILE = "src/qcsd_lab/rapid_rolling_schedule.py"
ENVIRONMENT = "QCSD_RAPID_COLLECTION_COMPATIBILITY"
V1_CONTROL_DEFINITIONS = {
    "src/qcsd_lab/rapid_lane_evidence.py": frozenset({
        "prepare_lane_intent", "_lineage_payload", "_intent_and_lineage", "image_check_command", "launch_lane"}),
    "src/qcsd_lab/rapid_rolling_capture.py": frozenset({
        "verify_enrollment", "_verify_enrollment", "_sites", "_sites_from_enrollment",
        "_bindings", "_bindings_from_enrollment", "capture_spec", "_capture_spec_from_enrollment",
        "verify_capture_plan", "publish_plan", "require_mode_readiness", "lane_check_command",
        "validate_host_launch", "_reopen_lane_check", "readiness_roots", "enrollment_roots"}),
    "src/qcsd_lab/rapid_formal_parallel.py": frozenset({
        "_audit", "prepare_batch", "_lane", "worker_inputs", "worker_environment",
        "retire_lane", "verify_results", "image_preflight"}),
    "src/qcsd_lab/rapid_runtime_epochs.py": frozenset({"validate_qualification_reuse"}),
    "tools/rapid_rolling_capture.py": frozenset({"run", "_parser"}),
    "tools/rapid_formal_parallel.py": frozenset({"main"}),
}
V2_CONTROL_DEFINITIONS = {**V1_CONTROL_DEFINITIONS,
    "src/qcsd_lab/rapid_formal_parallel.py": V1_CONTROL_DEFINITIONS["src/qcsd_lab/rapid_formal_parallel.py"] | {
        "_worker_context", "_worker_inputs_actual", "_release_fence", "_check_release_fence",
        "prepare_release", "prepared_worker_inputs", "release"},
    "src/qcsd_lab/rapid_parallel_capture.py": frozenset({"release", "main"}),
    "tools/rapid_parallel_capture.py": frozenset({"_host_authority", "launch", "main"}),
}
V3_CONTROL_DEFINITIONS = {**V2_CONTROL_DEFINITIONS,
    "src/qcsd_lab/rapid_parallel_capture.py": V2_CONTROL_DEFINITIONS["src/qcsd_lab/rapid_parallel_capture.py"] | {
        "lifecycle_inputs", "formal_entry_inputs"},
}
V4_CONTROL_DEFINITIONS = {**V3_CONTROL_DEFINITIONS,
    "src/qcsd_lab/rapid_lane_evidence.py": V3_CONTROL_DEFINITIONS["src/qcsd_lab/rapid_lane_evidence.py"] | {
        "retire_lane", "_verified_retirement", "_prebirth_batch_proof", "_verified_retirement_checks",
        "_retire_prebirth_lane", "_verified_prebirth_retirement"},
}
CONTROL_DEFINITIONS = {**V4_CONTROL_DEFINITIONS,
    "src/qcsd_lab/rapid_rolling_readiness.py": frozenset({"readiness_mount_roots"}),
    "src/qcsd_lab/rapid_lane_evidence.py": V4_CONTROL_DEFINITIONS["src/qcsd_lab/rapid_lane_evidence.py"] | {
        "_validate_image_proof", "check_bound_image", "executed_image_plan_check"},
    "src/qcsd_lab/rapid_rolling_capture.py": V4_CONTROL_DEFINITIONS["src/qcsd_lab/rapid_rolling_capture.py"] | {
        "image_plan_check"},
    "src/qcsd_lab/rapid_formal_parallel.py": V4_CONTROL_DEFINITIONS["src/qcsd_lab/rapid_formal_parallel.py"] | {
        "authority", "_context", "initialize", "_preflight", "_reopen_intent"},
    "src/qcsd_lab/rapid_parallel_capture.py": V4_CONTROL_DEFINITIONS["src/qcsd_lab/rapid_parallel_capture.py"] | {
        "authority", "image_preflight", "initialize", "gate", "_require_result_birth",
        "verify_results", "verify_results_in_image"},
}
NEW_FILES = frozenset({MODULE_FILE, "tests/test_rapid_rolling_schedule.py",
                       "tests/test_rapid_rolling_schedule_source.py",
                       "tests/test_rapid_rolling_parallel.py", "tests/test_rapid_rolling_policy_mounts.py"})
V2_NEW_FILES = NEW_FILES | {"tests/test_rapid_parallel_operator_import.py",
    "tests/test_rapid_parallel_release_preparation.py", "tests/test_rapid_parallel_control_factoring.py"}
V3_NEW_FILES = V2_NEW_FILES | {"tests/test_rapid_parallel_guardian_entry.py",
    "tests/test_rapid_parallel_lifecycle_inputs.py", "tests/test_rapid_parallel_guardian_projection.py"}
V4_NEW_FILES = V3_NEW_FILES | {"tests/test_rapid_prebirth_retirement.py",
    "tests/fixtures/rapid_parallel_scheduling_v2.json.zlib.b85.txt"}
V5_NEW_FILES = V4_NEW_FILES | {FACTS_FILE, "tests/test_rapid_operation_facts.py",
    "tests/fixtures/rapid_rolling_schedule_v4.py.zlib.b85.txt", "tests/test_rapid_parallel_json_transport.py",
    "tests/test_rapid_parallel_fail_first.py"}
DOCUMENTS = frozenset({"PROJECT.md", "docs/RAPID-CAPTURE-PATH.md", "docs/EVIDENCE-INDEX.md",
                       "docs/CAPTURE-READINESS.md", "docs/CLASS-STUDY.md"})
V5_DOCUMENTS = DOCUMENTS | {"docs/RAPID-CAPTURE-REPAIRS.md"}
CONTROL_TESTS = frozenset({"tests/test_rapid_rolling_capture.py"})
LIMITS = {"final_sites": 50, "settings": 5, "visits_per_site_setting": 64,
          "visits_per_lane_workload": 4, "maximum_sites_per_batch": 5,
          "final_accepted_traces": 16000}
CAPSULE_KEYS = {"schema_version", "artifact_type", "contract", "base_spec", "runtime",
    "qualification_spec", "original_canonical", "current_canonical", "qualified_inputs",
    "source_comparison", "reason", "published_at", "limits", "formal_accepted_trace_count",
    "scientific_credit"}
EXPORT_PROGRAM = (
    "from pathlib import Path; import os; "
    "pairs=(('/usr/share/qcsd-lab/source.json','/export/source.json'),"
    "('/usr/local/bin/neqo-qcsd-client','/export/neqo-qcsd-client')); "
    "[(Path(dst).open('xb').write(Path(src).read_bytes())) for src,dst in pairs]; "
    "os.chmod('/export/neqo-qcsd-client',0o555)"
)


def _shell_projection(raw: bytes) -> tuple[bytes, dict[str, str]]:
    units = {}
    for name, start, end in control.SHELL_REGIONS:
        if raw.count(start) != 1 or raw.count(end) != 1:
            raise ValueError("scheduling launcher lacks unique named section boundaries")
        first, last = raw.index(start), raw.index(end)
        if last <= first:
            raise ValueError("scheduling launcher section order differs")
        units[name] = evidence._sha(raw[first:last])
        raw = raw[:first] + f"# rolling-scheduling:{name}\n".encode() + raw[last:]
    starts = (b'  if (( rapid_capture_epoch || rapid_compatibility_runtime_epoch )); then\n',
              b'  if (( rapid_capture_epoch || rapid_compatibility_runtime_epoch )) || [[ "${rapid_capture_version}" == "v6" ]]; then\n')
    end = b"  # Docker's isolated client bridge"
    candidates = [start for start in starts if raw.count(start) == 1]
    if len(candidates) != 1 or raw.count(end) != 1:
        raise ValueError("scheduling launcher authority transport is not uniquely bounded")
    first, last = raw.index(candidates[0]), raw.index(end)
    if last <= first:
        raise ValueError("scheduling launcher authority transport order differs")
    units["authority-transport"] = evidence._sha(raw[first:last])
    return raw[:first] + b"# rolling-scheduling:authority-transport\n" + raw[last:], units


def _python_projection(path: str, raw: bytes, *, contract=CONTRACT) -> tuple[bytes, dict[str, str]]:
    definitions = (V1_CONTROL_DEFINITIONS if contract == CONTRACT_V1
                   else V2_CONTROL_DEFINITIONS if contract == CONTRACT_V2
                   else V3_CONTROL_DEFINITIONS if contract == CONTRACT_V3
                   else V4_CONTROL_DEFINITIONS if contract == CONTRACT_V4 else CONTROL_DEFINITIONS)
    permitted = definitions.get(path)
    if permitted is None:
        raise ValueError(f"scheduling changes protected source: {path}")
    tree = ast.parse(raw, filename=path)
    retained, units = [], {}
    bootstrap = ast.parse('_ROOT = Path(__file__).resolve().parents[1]\nsys.path.insert(0, str(_ROOT / "src"))').body
    bootstrap_nodes = {ast.dump(node, include_attributes=False) for node in bootstrap}
    found_bootstrap = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in permitted:
            if node.name in units:
                raise ValueError("scheduling duplicates a named control definition")
            units[node.name] = evidence._sha(ast.dump(node, include_attributes=False).encode())
        elif (contract in {CONTRACT_V2, CONTRACT_V3, CONTRACT_V4, CONTRACT} and path == "tools/rapid_parallel_capture.py"
              and ast.dump(node, include_attributes=False) in bootstrap_nodes):
            found_bootstrap.append(ast.dump(node, include_attributes=False))
        else:
            retained.append(node)
    if found_bootstrap:
        if found_bootstrap != [ast.dump(node, include_attributes=False) for node in bootstrap]:
            raise ValueError("scheduling repository import bootstrap is duplicated or reordered")
        indices = [index for index, node in enumerate(tree.body)
                   if ast.dump(node, include_attributes=False) in bootstrap_nodes]
        first_lab_import = next(index for index, node in enumerate(tree.body)
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("qcsd_lab"))
        if indices != [first_lab_import - 2, first_lab_import - 1]:
            raise ValueError("scheduling repository import bootstrap must precede lab imports")
        units["declared-repository-import-bootstrap"] = evidence._sha("\n".join(found_bootstrap).encode())
    return ast.dump(ast.Module(body=retained, type_ignores=[]), include_attributes=False).encode(), units


def _guardian_diagnostic_projection(raw: bytes) -> tuple[bytes, dict[str, str]]:
    """Permit only the literal diagnostic in the existing READY timeout branch."""
    tree = ast.parse(raw)
    matches = []
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef) or function.name != "_wait_for_child":
            continue
        for node in ast.walk(function):
            if (isinstance(node, ast.If)
                and ast.dump(node.test, include_attributes=False) == ast.dump(
                    ast.parse("now >= ready_deadline and not ready", mode="eval").body,
                    include_attributes=False)):
                matches.append(node)
    if len(matches) != 1:
        raise ValueError("scheduling guardian lacks its unique original READY timeout boundary")
    branch = matches[0]
    diagnostic = ast.parse('print("qcsd-lab Docker lifecycle guardian: initial READY handshake timed out before admission", file=sys.stderr)').body[0]
    expected = ast.dump(diagnostic, include_attributes=False)
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.Expr)
               and ast.dump(node, include_attributes=False) == expected]
    units = {}
    if matches:
        if len(matches) != 1 or not branch.body or branch.body[0] is not matches[0]:
            raise ValueError("scheduling guardian READY diagnostic is duplicated or moved")
        branch.body.pop(0)
        units["ready-timeout-diagnostic"] = evidence._sha(expected.encode())
    return ast.dump(tree, include_attributes=False).encode(), units


def source_changes(old: Mapping[str, bytes], new: Mapping[str, bytes], *, client_sha256: str,
                   contract=CONTRACT) -> dict[str, Any]:
    """Derive exact named control edits and unchanged scientific dependencies."""
    if contract not in {CONTRACT_V1, CONTRACT_V2, CONTRACT_V3, CONTRACT_V4, CONTRACT}:
        raise ValueError("scheduling source projection has an unknown contract")
    allowed_new = (NEW_FILES if contract == CONTRACT_V1 else V2_NEW_FILES
                   if contract == CONTRACT_V2 else V3_NEW_FILES if contract == CONTRACT_V3
                   else V4_NEW_FILES if contract == CONTRACT_V4 else V5_NEW_FILES)
    before, after = historical._source_inventory(old), historical._source_inventory(new)
    allowed_documents = V5_DOCUMENTS if contract == CONTRACT else DOCUMENTS
    if set(before) - set(after) or not (set(after) - set(before)) <= allowed_new | allowed_documents:
        raise ValueError("scheduling added an unregistered source or removed retained source")
    changes, projections = {}, {}
    for path in sorted(after):
        if before.get(path) == after[path]:
            continue
        if path in allowed_documents or path in CONTROL_TESTS or path in allowed_new - {MODULE_FILE, FACTS_FILE}:
            units, projection = ["nonexecuting-evidence-description"], None
        elif path == MODULE_FILE and path not in before:
            if ((contract == CONTRACT and new[path] != evidence._read(Path(__file__).absolute()))
                or (contract == CONTRACT_V1 and evidence._sha(new[path]) != V1_HELPER_SHA256)
                or (contract == CONTRACT_V2 and evidence._sha(new[path]) != V2_HELPER_SHA256)
                or (contract == CONTRACT_V3 and evidence._sha(new[path]) != V3_HELPER_SHA256)
                or (contract == CONTRACT_V4 and evidence._sha(new[path]) != V4_HELPER_SHA256)):
                raise ValueError("scheduling helper differs from the executing reviewed helper")
            ast.parse(new[path], filename=path)
            units, projection = ["new-scheduling-authority"], None
        elif path == FACTS_FILE and path not in before and contract == CONTRACT:
            if new[path] != evidence._read(Path(__file__).absolute().parent / "rapid_operation_facts.py"):
                raise ValueError("operation facts differ from the executing reviewed implementation")
            ast.parse(new[path], filename=path)
            units, projection = ["operation-local-raw-dependency-facts"], None
        elif (path == MODULE_FILE and contract == CONTRACT_V2
              and before[path] == V1_HELPER_SHA256
              and evidence._sha(new[path]) == V2_HELPER_SHA256):
            # This exact source-bound validator revision declares the new
            # named control units. It grants no scientific dependency edit.
            units, projection = ["scheduling-v2-pre-birth-release-authority"], None
        elif (path == MODULE_FILE and contract == CONTRACT_V3
              and before[path] in {V1_HELPER_SHA256, V2_HELPER_SHA256}
              and evidence._sha(new[path]) == V3_HELPER_SHA256):
            units, projection = ["scheduling-v3-lifecycle-first-authority"], None
        elif (path == MODULE_FILE and contract == CONTRACT_V4
              and before[path] in {V1_HELPER_SHA256, V2_HELPER_SHA256, V3_HELPER_SHA256}
              and evidence._sha(new[path]) == V4_HELPER_SHA256):
            units, projection = ["scheduling-v4-observed-prebirth-retirement-authority"], None
        elif (path == MODULE_FILE and contract == CONTRACT
              and before[path] in {V1_HELPER_SHA256, V2_HELPER_SHA256, V3_HELPER_SHA256, V4_HELPER_SHA256}
              and new[path] == evidence._read(Path(__file__).absolute())):
            units, projection = ["scheduling-v5-operation-local-verification-facts-authority"], None
        else:
            project = (_shell_projection if path == "qcsd-lab"
                       else _guardian_diagnostic_projection if contract in {CONTRACT_V3, CONTRACT_V4, CONTRACT}
                       and path == "tools/docker_lifecycle_lock_guardian.py"
                       else lambda raw: _python_projection(path, raw, contract=contract))
            protected_old, old_units = project(old[path])
            protected_new, new_units = project(new[path])
            if protected_old != protected_new:
                raise ValueError(f"scheduling changed code outside named control units: {path}")
            units = sorted(name for name in old_units.keys() | new_units.keys()
                           if old_units.get(name) != new_units.get(name))
            if not units:
                raise ValueError("scheduling byte change has no reviewed semantic unit")
            projection = {"protected_sha256": evidence._sha(protected_old),
                          "old_units": old_units, "new_units": new_units}
        changes[path] = {"before_sha256": before.get(path), "after_sha256": after[path], "units": units}
        projections[path] = projection
    groups = {}
    for group, names in evidence.DEPENDENCY_FILES.items():
        paths = {"src/qcsd_lab/" + name + ".py" for name in names}
        if group == "measurement":
            paths.update(evidence.STATIC_MEASUREMENT_FILES)
        groups[group] = {path: before[path] for path in sorted(paths)}
        if any(before[path] != after.get(path) for path in paths):
            raise ValueError(f"scheduling changed {group} dependencies")
    protected_old, _ = _shell_projection(old["qcsd-lab"])
    protected_new, _ = _shell_projection(new["qcsd-lab"])
    if protected_old != protected_new:
        raise ValueError("scheduling changed protected launcher measurement bytes")
    groups["measurement"]["qcsd-lab:protected"] = evidence._sha(protected_old)
    groups["chaff"]["prepare:protected-units"] = evidence._prepare_units(old["src/qcsd_lab/prepare.py"])
    if groups["chaff"]["prepare:protected-units"] != evidence._prepare_units(new["src/qcsd_lab/prepare.py"]):
        raise ValueError("scheduling changed the qualification subprocess")
    for group, paths in (("traffic", {path for path, _ in lanes.TRAFFIC_FILES.values()}),
                         ("native", {path for path in before if path.startswith("neqo-qcsd/")})):
        if not paths or any(before[path] != after.get(path) for path in paths):
            raise ValueError(f"scheduling changed the complete {group} inventory")
        groups[group] = {path: before[path] for path in sorted(paths)}
    if {path for path in after if path.startswith("neqo-qcsd/")} != set(groups["native"]):
        raise ValueError("scheduling added Native source")
    acquisition = {}
    for group, names in control._expected_acquisition_modules().items():
        acquisition[group] = {}
        for name in names:
            path = ("src/" if name.startswith("qcsd_lab.") else "") + name.replace(".", "/") + ".py"
            acquisition[group][name] = client_sha256 if name == "neqo-qcsd-client" else before[path]
    acquisition = control._acquisition_groups(acquisition, before, after, client_sha256)
    dependencies = historical.qualification_dependencies(old)
    if dependencies != historical.qualification_dependencies(new):
        raise ValueError("scheduling changed the response-only qualification primitive")
    return {"changed_sources": changes, "control_projection": projections,
            "dependency_groups": groups, "acquisition_source_groups": acquisition,
            "qualification_dependencies": dependencies}


def _producer_command(root: Path, name: str, canonical: Mapping, inputs: Mapping, command: list[str]) -> list[str]:
    """Reconstruct the existing runtime producer argv, without executing it."""
    if name == "client-reuse":
        # Command files are JSON arrays, rather than evidence JSON objects.
        from .util import load_json
        expected = load_json(root / "client-reuse-command.json")
        if (not isinstance(expected, list) or len(expected) != 7
            or any(not isinstance(arg, str) or not arg for arg in expected) or not Path(expected[0]).is_absolute()
            or expected[1:] != ["-I", "-B", canonical["client_reuse_recipe"]["path"], "_copy", "--build-root", str(root)]):
            raise ValueError("scheduling client reuse producer command differs")
        return expected
    if name == "release-build":
        try:
            user = command[command.index("--user") + 1]
        except (ValueError, IndexError) as error:
            raise ValueError("scheduling Native release command lacks its actor") from error
        if re.fullmatch(r"[0-9]+:[0-9]+", user) is None:
            raise ValueError("scheduling Native release actor differs")
        return ["docker", "run", "--rm", "--name", "qcsd-response-release-" + inputs["source"]["lab_commit"][:12],
            "--network", "none", "--user", user,
            "--volume", f"{root / 'image-context/source/neqo-qcsd'}:/source:ro",
            "--volume", f"{inputs['registry']}:/usr/local/cargo/registry",
            "--volume", f"{inputs['git_cache']}:/usr/local/cargo/git",
            "--volume", f"{inputs['target']}:/target", "--workdir", "/source",
            "--env", "CARGO_TARGET_DIR=/target", "--env", "NEQO_QCSD_GIT_COMMIT=" + inputs["source"]["neqo_commit"],
            "--entrypoint", "/bin/sh", inputs["toolchain_image"], "-c",
            "cargo build --locked --offline --release -p neqo-bin --features qcsd --bin neqo-qcsd-client"]
    if name == "actual-runtime-export":
        try:
            user = command[command.index("--user") + 1]
        except (ValueError, IndexError) as error:
            raise ValueError("scheduling runtime export lacks its actor") from error
        if re.fullmatch(r"[0-9]+:[0-9]+", user) is None:
            raise ValueError("scheduling runtime export actor differs")
        return ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", user,
            "--volume", f"{root / 'runtime-export'}:/export:rw", "--entrypoint", "/opt/qcsd-venv/bin/python3",
            canonical["prepare_image_digest"], "-I", "-c", EXPORT_PROGRAM]
    role, step = name.split("-", 1)
    base = inputs[role + "_base_image"]
    if evidence._IMAGE.fullmatch(base) is None:
        raise ValueError("scheduling runtime build base is not immutable")
    alias = f"qcsd-response-base-{role}:{base.removeprefix('sha256:')}"
    if step == "base-alias":
        return ["docker", "image", "tag", base, alias]
    if step in {"base-before", "base-after"}:
        return ["docker", "image", "inspect", "--format", "{{.Id}}", alias]
    if step == "image-build":
        return ["docker", "build", "--pull=false", "--network", "none", "--file", role.title() + ".Dockerfile",
            "--iidfile", str(root / (role + "-image-id.txt")), "--tag",
            f"qcsd-{role}:response-policy-{inputs['source']['lab_commit'][:12]}",
            "--build-arg", "LAB_COMMIT=" + inputs["source"]["lab_commit"],
            "--build-arg", "NEQO_COMMIT=" + inputs["source"]["neqo_commit"], "."]
    if step == "installed-verification":
        image = canonical[role + "_image_digest"]
        try:
            user = command[command.index("--user") + 1]
        except (ValueError, IndexError) as error:
            raise ValueError("scheduling installed verifier lacks its actor") from error
        if re.fullmatch(r"[0-9]+:[0-9]+", user) is None:
            raise ValueError("scheduling installed verifier actor differs")
        return ["docker", "run", "--rm", "--network", "none", "--user", user,
            "--env", "QCSD_LAB_IMAGE_DIGEST=" + image, "--env", "QCSD_LAB_ROOT=/runtime-src",
            "--entrypoint", "/opt/qcsd-venv/bin/python3", image, "-I", "/recipe/verify_installed.py", role]
    raise ValueError("scheduling runtime operation is unknown")


def reopen_runtime(reference: Mapping[str, str], runtime: Mapping[str, str], *, _seen: frozenset[str] = frozenset(), _inspector: bool = False) -> tuple[dict, dict[str, bytes]]:
    """Reopen all twelve actual runtime operations, installed checks and export."""
    if type(_inspector) is not bool:
        raise ValueError("runtime inspector selection must be explicitly typed")
    path, raw = evidence._reference(reference)
    if str(path) in _seen:
        raise ValueError("scheduling runtime provenance contains a cycle")
    _seen = _seen | {str(path)}
    value, root = evidence._json(raw), path.parent
    source = evidence._clean_source(value.get("source"))
    if (value.get("scope") != "actual-installed-runtime-bytes-not-live-study-qualification"
        or value.get("installed_byte_verification_completed") is not True
        or value.get("scientific_credit") is not False
        or type(value.get("formal_accepted_trace_count")) is not int or value["formal_accepted_trace_count"] != 0
        or value.get("collection_image_digest") != runtime["collection_image_digest"]):
        raise ValueError("scheduling lacks its actual installed runtime closure")
    verified = evidence._timestamp(value["verified_at"])
    if verified > datetime.now(UTC):
        raise ValueError("scheduling runtime closure is in the future")
    source_raw = evidence._read(Path(runtime["source_manifest"]), value["exported_source_manifest_sha256"])
    client = evidence._read(Path(runtime["client_binary"]), value["installed_client_sha256"])
    if (evidence._json(source_raw) != source or Path(value["source_manifest"]) != Path(runtime["source_manifest"])
        or Path(value["client_binary"]) != Path(runtime["client_binary"])
        or evidence._read(root / "runtime-export/source.json") != source_raw
        or evidence._read(root / "runtime-export/neqo-qcsd-client") != client):
        raise ValueError("scheduling runtime source or client export changed")
    source_root = Path(runtime["runtime_source_root"])
    inventory_ref = {"path": str(root / "source-inventory.json"), "sha256": value["source_inventory_sha256"]}
    inventory = evidence._bound_inventory(inventory_ref, source_root)
    if inventory != evidence._inventory(root / "image-context/source"):
        raise ValueError("scheduling image context differs from complete frozen source")
    sources = {name: evidence._read(source_root / name) for name in inventory}
    inputs_raw = evidence._read(root / "build-inputs.json")
    inputs = evidence._json(inputs_raw)
    if (evidence._read(root / "image-context/build-inputs.json") != inputs_raw or inputs["source"] != source
        or inputs["source_inventory_sha256"] != value["source_inventory_sha256"]
        or inputs["cargo_lock_sha256"] != evidence._sha(sources["neqo-qcsd/Cargo.lock"])
        or evidence._IMAGE.fullmatch(inputs["toolchain_image"]) is None
        or not historical._digest(inputs["rust_archive_sha256"])
        or set(inputs["recipe_files"]) != {"Collection.Dockerfile", "Prepare.Dockerfile", "generate_receipts.py", "verify_installed.py"}
        or any(evidence._sha(evidence._read(root / "image-context" / name)) != digest for name, digest in inputs["recipe_files"].items())):
        raise ValueError("scheduling runtime producer, Native lock or immutable build inputs changed")
    if (Path(runtime["module_root"]) != source_root
        or evidence._read(Path(runtime["base_launcher"])) != sources["qcsd-lab"]
        or evidence._read(Path(runtime["host_launcher"])) != sources["qcsd-lab"]):
        raise ValueError("scheduling source and launcher roles differ")
    client_record = evidence._json(evidence._read(root / "client-build.json", value["native_build_record_sha256"]))
    if (client_record.get("source") != source or client_record.get("client_sha256") != value["installed_client_sha256"]
        or client_record.get("scientific_credit") is not False
        or evidence._read(root / "image-context/neqo-qcsd-client") != client
        or not Path(runtime["client_binary"]).stat().st_mode & 0o111
        or not (root / "image-context/neqo-qcsd-client").stat().st_mode & 0o111):
        raise ValueError("scheduling client build provenance or executable bytes changed")
    action = value.get("native_artifact_action")
    if action == "verified-exact-existing-client-reuse":
        native_operation = "client-reuse"
        for key in ("client_reuse_proof", "client_reuse_recipe", "original_native_build_record", "original_canonical"):
            evidence._reference(value[key])
        _, reuse_raw = evidence._reference(value["client_reuse_proof"])
        reuse = evidence._json(reuse_raw)
        original_path, original_raw = evidence._reference(value["original_canonical"])
        original = evidence._json(original_raw)
        original_root = original_path.parent / "image-context/source"
        original_runtime = {"runtime_source_root": str(original_root), "module_root": str(original_root),
            "base_launcher": str(original_root / "qcsd-lab"), "host_launcher": str(original_root / "qcsd-lab"),
            "source_manifest": original["source_manifest"], "client_binary": original["client_binary"],
            "collection_image_digest": original["collection_image_digest"]}
        original, _ = reopen_runtime(value["original_canonical"], original_runtime, _seen=_seen, _inspector=_inspector)
        original_inventory = evidence._json(evidence._read(original_path.parent / "source-inventory.json", original["source_inventory_sha256"]))
        original_native = {name: record for name, record in original_inventory.items() if name.startswith("neqo-qcsd/")}
        current_native = {name: record for name, record in inventory.items() if name.startswith("neqo-qcsd/")}
        original_inputs = evidence._json(evidence._read(original_path.parent / "build-inputs.json"))
        if (value["original_native_build_record"] != rolling._ref(original_path.parent / "client-build.json")
            or evidence._read(root / "image-context/client-build.json") != evidence._read(root / "client-build.json")):
            raise ValueError("scheduling original and installed client-build records differ")
        expected_refs = {"original_build_inputs": rolling._ref(original_path.parent / "build-inputs.json"),
            "original_installed_client": rolling._ref(Path(original["client_binary"])),
            "original_installed_source": rolling._ref(Path(original["source_manifest"])),
            "original_source_inventory": rolling._ref(original_path.parent / "source-inventory.json"),
            "target_build_inputs": rolling._ref(root / "build-inputs.json"),
            "target_source_inventory": inventory_ref}
        if _inspector:
            from .rapid_runtime_inspector import schema1_reuse_facts
            schema1_reuse_facts(reuse, value, original, original_path, current_native, original_native)
        if (reuse.get("artifact_type") != "qcsd-exact-existing-native-client-reuse" or reuse.get("source") != source
            or reuse.get("scientific_credit") is not False or reuse.get("runtime_qualification") != "not-executed"
            or reuse.get("client_sha256") != value["installed_client_sha256"]
            or reuse.get("original_canonical") != value["original_canonical"]
            or reuse.get("original_client_build") != value["original_native_build_record"]
            or reuse.get("native_source_inventory_equal") is not True or original_native != current_native
            or original["installed_client_sha256"] != value["installed_client_sha256"]
            or any(reuse.get(key) != reference for key, reference in expected_refs.items())
            or any(reuse.get(key) != inputs[key] or inputs[key] != original_inputs[key]
                   for key in ("toolchain_image", "cargo_lock_sha256", "rust_archive_sha256"))
            or reuse.get("original_actual_operation_completions") != original["actual_operation_completions"]
            or not _inspector and (reuse.get("original_client_executable") is not True
                or type(reuse.get("native_source_file_count")) is not int or reuse["native_source_file_count"] != len(current_native))
            or client_record.get("client_reuse_proof") != value["client_reuse_proof"]
            or client_record.get("client_reuse_completion") != evidence._json(evidence._read(root / "client-reuse-completed.json"))):
            raise ValueError("scheduling exact-client reuse differs from its actual original Native build")
    elif action == "new-cached-native-release-build":
        native_operation = "release-build"
        if (client_record.get("release_completion") != evidence._json(evidence._read(root / "release-build-completed.json"))
            or client_record.get("release_command_sha256") != evidence._sha(evidence._read(root / "release-command.json"))):
            raise ValueError("scheduling original Native build command or completion changed")
    else:
        raise ValueError("scheduling runtime has an unknown Native artifact provenance")
    names = {"actual-runtime-export", native_operation} | {
        f"{role}-{name}" for role in ("collection", "prepare")
        for name in ("base-alias", "base-before", "image-build", "base-after", "installed-verification")}
    operations = value.get("actual_operation_completions")
    if not isinstance(operations, Mapping) or set(operations) != names:
        raise ValueError("scheduling runtime requires all twelve actual operations")
    if ({path.name.removesuffix("-started.json") for path in root.glob("*-started.json")} != names
        or {path.name.removesuffix("-completed.json") for path in root.glob("*-completed.json")} != names):
        raise ValueError("scheduling runtime actual record inventory differs")
    for name in sorted(names):
        completed_raw = evidence._read(root / (name + "-completed.json"))
        started_raw = evidence._read(root / (name + "-started.json"))
        completed, started = evidence._json(completed_raw), evidence._json(started_raw)
        elapsed, command = completed.get("elapsed_seconds"), started.get("command")
        summary = {"record_sha256": evidence._sha(completed_raw),
                   "started_record_sha256": evidence._sha(started_raw), "elapsed_seconds": elapsed}
        if (operations[name] != summary or type(completed.get("returncode")) is not int
            or completed["returncode"] != 0 or completed.get("invocation_error") is not None
            or type(elapsed) not in {float, int} or not math.isfinite(elapsed) or elapsed < 0
            or not isinstance(command, list) or not command or any(not isinstance(arg, str) or not arg for arg in command)
            or command != _producer_command(root, name, value, inputs, command)
            or started.get("cwd") != (str(root / "image-context") if name.endswith("image-build") else None)
            or not evidence._timestamp(started["started_at"]) <= evidence._timestamp(completed["completed_at"]) <= verified
            or evidence._sha(evidence._read(root / (name + ".stdout.log"))) != completed.get("stdout_sha256")
            or evidence._sha(evidence._read(root / (name + ".stderr.log"))) != completed.get("stderr_sha256")):
            raise ValueError("scheduling runtime operation, chronology or raw logs changed")
    if action == "verified-exact-existing-client-reuse":
        started = evidence._json(evidence._read(root / "client-reuse-started.json"))
        completed = evidence._json(evidence._read(root / "client-reuse-completed.json"))
        if (not _inspector or "copied_at" in reuse) and not evidence._timestamp(started["started_at"]) <= evidence._timestamp(reuse["copied_at"]) <= evidence._timestamp(completed["completed_at"]):
            raise ValueError("scheduling copied client predates or follows its actual reuse operation")
    for role in ("collection", "prepare"):
        proof = evidence._json(evidence._read(root / (role + "-installed-verification.stdout.log")))
        image = value[role + "_image_digest"]
        if (proof != value["checks"][role] or proof.get("scope") != "installed-runtime-byte-and-source-verification-only"
            or proof.get("role") != role or proof.get("image_digest") != image or proof.get("source") != source
            or proof.get("client_sha256") != value["installed_client_sha256"]
            or proof.get("source_metadata_raw_sha256") != evidence._sha(source_raw)
            or evidence._read(root / (role + "-image-id.txt")).decode().strip() != image
            or evidence._read(root / (role + "-base-before.stdout.log"))
               != evidence._read(root / (role + "-base-after.stdout.log"))):
            raise ValueError("scheduling installed image proof or immutable build base changed")
    return value, sources


def _qualified_inputs(cohort: Path, qualifier: Path, workload_root: Path, expected_sites: list[dict], *, _context=None) -> dict:
    spec = evidence._json(evidence._read(qualifier))
    if set(spec) != {"schema_version", "qualification_sets"} or type(spec["schema_version"]) is not int or spec["schema_version"] != 1:
        raise ValueError("scheduling qualification spec differs")
    sets = spec["qualification_sets"]
    if not isinstance(sets, list) or len(sets) != 1:
        raise ValueError("scheduling needs the original single named qualification set")
    item = sets[0]
    if set(item) != {"qualification_set", "manifest", "sidecar_root", "prefix_spec_root"} or item["prefix_spec_root"] is not None:
        raise ValueError("scheduling cannot replace fixed response qualification with fitting")
    def resolve(name):
        value = item[name]
        if not isinstance(value, str) or not value:
            raise ValueError("scheduling qualification path is invalid")
        return evidence._path(Path(value) if Path(value).is_absolute() else qualifier.parent / value,
                              directory=name == "sidecar_root")
    manifest, sidecars = resolve("manifest"), resolve("sidecar_root")
    ids = [site["workload_id"] for site in expected_sites]
    if not 1 <= len(ids) <= 5 or len(set(ids)) != len(ids):
        raise ValueError("scheduling batch must retain one to five unique sites")
    key = None
    if _context is not None:
        import json
        key = ("qualified-inputs", json.dumps(expected_sites, sort_keys=True), _context.content_key(
            [cohort, qualifier, manifest, *(workload_root / (name + ".json") for name in ids)],
            [sidecars, *(workload_root / (name + "-application-response-evidence") for name in ids)],
            include_modes=False))
        if _context.has(key):
            return _context.get(key)
    validator = (qualification.validate_named_qualification_set_manifest if _context is None else
        lambda value, **kwargs: _context.validate_named_qualification(value, qualification.validate_named_qualification_set_manifest, **kwargs))
    validator(evidence._json(evidence._read(manifest)),
        workload_root=workload_root, sidecar_root=sidecars, prefix_spec_root=None,
        expected_qualification_set=item["qualification_set"], expected_workload_ids=ids,
        expected_qualification_scope="response-only", require_current_implementation=False)
    workloads, implementations, sources = {}, {}, {}
    for site in expected_sites:
        name = site["workload_id"]
        raw = evidence._read(workload_root / (name + ".json"), site["workload_sha256"])
        workloads[name] = {"workload_sha256": evidence._sha(raw), "application_evidence":
            evidence._inventory(workload_root / (name + "-application-response-evidence"))}
        sidecar = evidence._json(evidence._read(sidecars / (name + ".json")))
        if (type(sidecar.get("schema_version")) is not int
            or sidecar["schema_version"] != qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION):
            raise ValueError("scheduling needs the unchanged full 120-response qualification schema")
        implementations[name] = sidecar["implementation_receipt"]["sha256"]
        sources[name] = {"source": sidecar["qualification_source"], "image": sidecar["qualification_image_digest"]}
    result = {"enrollment_sha256": evidence._sha(evidence._read(cohort)),
            "qualification_spec_sha256": evidence._sha(evidence._read(qualifier)),
            "named_set": item["qualification_set"], "named_manifest_sha256": evidence._sha(evidence._read(manifest)),
            "qualification_files": evidence._inventory(sidecars), "workloads": workloads,
            "implementation_sha256": implementations, "qualification_sources": sources}
    return _context.remember(key, result) if _context is not None else result


def _spec(value: Mapping[str, str]) -> lanes.CaptureSpec:
    return lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item for key, item in value.items()})


def _derive(base: lanes.CaptureSpec, runtime: Mapping[str, str], qualifier: Path,
            original: Mapping[str, str], current: Mapping[str, str], *, contract=CONTRACT, _context=None) -> dict:
    lanes._check_spec(base)
    runtime = rolling._runtime(runtime)
    if runtime["data_root"] != str(base.data_root):
        raise ValueError("scheduling cannot replace original study data or enrollment authority")
    plan = lanes._payload(base.plan_receipt, lanes.PLAN_TYPE)
    if (plan.get("study_version") != 6 or plan.get("cohort_generation") != "rolling-50"
        or any(type(row["visits_per_workload"]) is not int or row["visits_per_workload"] != 4
               or row["workload_ids"] != [site["workload_id"] for site in plan["sites"]] for row in plan["lanes"])):
        raise ValueError("scheduling needs the original four-visit rolling plan")
    if (plan["runtime"] != {key: str(getattr(base, key)) for key in rolling.RUNTIME_FIELDS}
        or plan["qualification_spec_sha256"] != evidence._sha(evidence._read(base.qualification_spec))):
        raise ValueError("scheduling base specification differs from its original plan")
    for row in plan["lanes"]:
        for campaign_root in (base.campaign_dir, Path(runtime["campaign_dir"])):
            evidence._read(campaign_root / (row["campaign_name"] + ".yml"), row["campaign_sha256"])
    old_runtime = {key: str(getattr(base, key)) for key in lanes.RUNTIME_KEYS}
    old, old_sources = reopen_runtime(original, old_runtime)
    new, new_sources = reopen_runtime(current, runtime)
    inventories = []
    for reference, canonical in ((original, old), (current, new)):
        inventories.append(evidence._json(evidence._read(Path(reference["path"]).parent / "source-inventory.json",
                                                       canonical["source_inventory_sha256"])))
    if any(inventories[0][path]["executable"] != inventories[1][path]["executable"]
           for path in inventories[0].keys() & inventories[1].keys()):
        raise ValueError("scheduling changed a retained source executable mode")
    native_keys = {"neqo_commit", "neqo_pinned_commit", "neqo_dirty", "neqo_patch_sha256"}
    if (any(old["source"][key] != new["source"][key] for key in native_keys)
        or old["installed_client_sha256"] != new["installed_client_sha256"]):
        raise ValueError("scheduling changed Native source or the exact installed client")
    helper = new_sources.get(MODULE_FILE)
    if ((contract == CONTRACT and helper != evidence._read(Path(__file__).absolute()))
        or (contract == CONTRACT_V1 and (helper is None or evidence._sha(helper) != V1_HELPER_SHA256))
        or (contract == CONTRACT_V2 and (helper is None or evidence._sha(helper) != V2_HELPER_SHA256))
        or (contract == CONTRACT_V3 and (helper is None or evidence._sha(helper) != V3_HELPER_SHA256))
        or (contract == CONTRACT_V4 and (helper is None or evidence._sha(helper) != V4_HELPER_SHA256))):
        raise ValueError("new installed runtime lacks this exact scheduling validator")
    comparison = source_changes(old_sources, new_sources, client_sha256=old["installed_client_sha256"], contract=contract)
    build_dependencies = []
    for reference in (original, current):
        inputs = evidence._json(evidence._read(Path(reference["path"]).parent / "build-inputs.json"))
        build_dependencies.append({key: inputs[key] for key in (
            "collection_base_image", "prepare_base_image", "toolchain_image", "cargo_lock_sha256",
            "rust_archive_sha256", "recipe_files")})
    if build_dependencies[0] != build_dependencies[1]:
        raise ValueError("scheduling changed installed image bases, producer or Native build dependencies")
    comparison["runtime_build_dependencies"] = build_dependencies[0]
    before = _qualified_inputs(base.cohort, base.qualification_spec, base.workload_root, plan["sites"], _context=_context)
    after = _qualified_inputs(base.cohort, qualifier, Path(runtime["workload_root"]), plan["sites"], _context=_context)
    old_source = {**old["source"], "image_digest": old["collection_image_digest"]}
    if (before != after or set(before["implementation_sha256"].values()) != {
            old["checks"]["collection"]["qualification_implementation_sha256"]}
        or any(value != {"source": old_source, "image": old["collection_image_digest"]}
               for value in before["qualification_sources"].values())):
        raise ValueError("scheduling changed the complete graphs, original source labels or 120-response qualification")
    return {"qualified_inputs": before, "source_comparison": comparison}


def publish_schedule(base_spec: lanes.CaptureSpec, runtime: Mapping[str, str], qualification_spec: Path,
                     original_canonical: Mapping[str, str], current_canonical: Mapping[str, str],
                     output: Path, *, reason: str) -> dict[str, str]:
    """Publish before a new parallel plan; older serial intents remain historical."""
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("prospective scheduling needs its explicit scientific scope")
    output = Path(output)
    if (not output.is_absolute() or ".." in output.parts
        or any(item.is_symlink() for item in (output, *output.parents))):
        raise ValueError("scheduling output must be an absolute unlinked create-only path")
    for source_root in (base_spec.runtime_source_root, Path(runtime["runtime_source_root"]),
                        Path(original_canonical["path"]).parent / "image-context",
                        Path(current_canonical["path"]).parent / "image-context",
                        Path(original_canonical["path"]).parent / "runtime-export",
                        Path(current_canonical["path"]).parent / "runtime-export"):
        if output.is_relative_to(source_root):
            raise ValueError("scheduling output must remain outside frozen source and runtime contexts")
    derived = _derive(base_spec, runtime, qualification_spec, original_canonical, current_canonical)
    now = datetime.now(UTC).isoformat()
    payload = {"schema_version": 1, "artifact_type": CAPSULE_TYPE, "contract": CONTRACT,
        "base_spec": base_spec.serializable(), "runtime": dict(runtime),
        "qualification_spec": rolling._ref(qualification_spec), "original_canonical": dict(original_canonical),
        "current_canonical": dict(current_canonical), **derived, "reason": reason.strip(), "published_at": now,
        "limits": dict(LIMITS), "formal_accepted_trace_count": 0, "scientific_credit": False}
    durable_create(output.absolute(), evidence._encoded(payload))
    return rolling._ref(output.absolute())


def validate_schedule(reference: Mapping[str, str], *, runtime: Mapping[str, str] | None = None,
                      before: str | None = None, _context=None) -> dict:
    _, raw = evidence._reference(reference)
    value = evidence._json(raw)
    from . import rapid_original_static_parallel_schedule as original_static
    if isinstance(value, dict) and value.get("artifact_type") == original_static.CAPSULE_TYPE:
        return original_static.validate_schedule(reference, runtime=runtime, before=before, _context=_context)
    from . import rapid_static_parallel_schedule as static
    if isinstance(value, dict) and value.get("artifact_type") == static.CAPSULE_TYPE:
        return static.validate_schedule(reference, runtime=runtime, before=before, _context=_context)
    if (set(value) != CAPSULE_KEYS or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != CAPSULE_TYPE or value["contract"] not in {CONTRACT_V1, CONTRACT_V2, CONTRACT_V3, CONTRACT_V4, CONTRACT} or value["limits"] != LIMITS
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False or not isinstance(value["reason"], str) or not value["reason"].strip()):
        raise ValueError("prospective scheduling capsule has an invalid exact contract")
    published = evidence._timestamp(value["published_at"])
    if (published > datetime.now(UTC) or before is not None
        and not published < evidence._timestamp(before) <= datetime.now(UTC)):
        raise ValueError("scheduling capsule must precede the new parallel plan and intent")
    qualifier, _ = evidence._reference(value["qualification_spec"])
    if runtime is not None and dict(runtime) != value["runtime"]:
        raise ValueError("scheduling capsule belongs to a different runtime")
    key = ("schedule-derive", evidence._sha(raw))
    if _context is not None:
        _context._reference(reference)
        _context.bind_schedule(value)
    if _context is not None and _context.has(key):
        derived = _context.get(key)
    else:
        derived = _derive(_spec(value["base_spec"]), value["runtime"], qualifier,
                          value["original_canonical"], value["current_canonical"],
                          contract=value["contract"], _context=_context)
        if _context is not None:
            _context.remember(key, derived)
    if any(value[key] != derived[key] for key in derived):
        raise ValueError("scheduling source projections or retained qualified bytes changed")
    for ref in (value["original_canonical"], value["current_canonical"]):
        _, contents = evidence._reference(ref)
        if evidence._timestamp(evidence._json(contents)["verified_at"]) > published:
            raise ValueError("scheduling was declared before its actual runtime closure")
    return value


def validate_qualification_reuse(old_impl: Mapping, current_impl: Mapping, reference: Mapping[str, str],
                                *, actual_image: str, before: str | None = None, _context=None) -> None:
    """Typed installed hook: no ambient or source-only qualification exemption."""
    capsule = validate_schedule(reference, before=before, _context=_context)
    from . import rapid_original_static_parallel_schedule as original_static
    if capsule["artifact_type"] == original_static.CAPSULE_TYPE:
        original_static.validate_current_qualification(old_impl, current_impl, reference,
            actual_image=actual_image, before=before, _context=_context)
        return
    from . import rapid_static_parallel_schedule as static
    if capsule["artifact_type"] == static.CAPSULE_TYPE:
        static.validate_current_qualification(old_impl, current_impl, reference,
            actual_image=actual_image, before=before, _context=_context)
        return
    if actual_image != capsule["runtime"]["collection_image_digest"]:
        raise ValueError("scheduling qualification hook is executing another image")
    for receipt, key in ((old_impl, "original_canonical"), (current_impl, "current_canonical")):
        qualification._validate_implementation_receipt(receipt, require_current=False)
        _, raw = evidence._reference(capsule[key])
        canonical = evidence._json(raw)
        inventory = evidence._json(evidence._read(Path(capsule[key]["path"]).parent / "source-inventory.json",
                                                 canonical["source_inventory_sha256"]))
        if (receipt["schema_version"] != qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION
            or receipt["sha256"] != canonical["checks"]["collection"]["qualification_implementation_sha256"]
            or receipt["source"] != canonical["source"]
            or receipt["neqo_qcsd_client"]["sha256"] != canonical["installed_client_sha256"]
            or any(inventory.get(path, {}).get("sha256") != digest for path, digest in receipt["source_files"].items())):
            raise ValueError("scheduling installed qualification source or executable differs")
    if (old_impl["neqo_qcsd_client"] != current_impl["neqo_qcsd_client"]
        or old_impl["installed_entrypoint"]["path"] != current_impl["installed_entrypoint"]["path"]
        or any(old_impl["installed_modules"][path]["path"] != current_impl["installed_modules"][path]["path"]
               for path in qualification.IMPLEMENTATION_PYTHON_FILES)):
        raise ValueError("scheduling changed installed executable or module paths")


def require_schedule(reference: Mapping[str, str], spec: lanes.CaptureSpec, *, declared_at: str,
                     started_at: str | None = None, _context=None) -> dict:
    """Plan/intent hook; failed-only retry proof stays with the ordinary lane API."""
    runtime = {key: str(getattr(spec, key)) for key in rolling.RUNTIME_FIELDS}
    capsule = validate_schedule(reference, runtime=runtime, before=declared_at, _context=_context)
    base = _spec(capsule["base_spec"])
    if (spec.cohort != base.cohort or spec.acquisition_root != base.acquisition_root
        or rolling._ref(spec.qualification_spec) != capsule["qualification_spec"]):
        raise ValueError("scheduling plan replaced its original enrollment or qualification")
    if started_at is not None and not evidence._timestamp(declared_at) <= evidence._timestamp(started_at) <= datetime.now(UTC):
        raise ValueError("scheduling intent predates its new plan")
    return capsule


def validate_ready_canary(reference: Mapping[str, Any], schedule_reference: Mapping[str, str], *,
                          mode: str, before: str, _context=None) -> dict:
    """Reopen the original passed setting without attributing it to new code."""
    capsule = validate_schedule(schedule_reference, before=before, _context=_context)
    base = _spec(capsule["base_spec"])
    plan = lanes._payload(base.plan_receipt, lanes.PLAN_TYPE)
    if mode not in plan["readiness"] or plan["readiness"][mode] != reference:
        raise ValueError("scheduling canary is not the original setting's bound prerequisite")
    runtime = {key: str(getattr(base, key)) for key in lanes.RUNTIME_KEYS}
    if _context is not None:
        return _context.validate_canary(reference, runtime, mode, evidence.validate_canary)
    return evidence.validate_canary(reference, runtime=runtime, mode=mode)


def mount_roots(reference: Mapping[str, str], *, _context=None) -> list[Path]:
    """Derive read-only transport from the fully reopened capsule and runtimes."""
    capsule = validate_schedule(reference, _context=_context)
    from . import rapid_original_static_parallel_schedule as original_static
    if capsule["artifact_type"] == original_static.CAPSULE_TYPE:
        return original_static.mount_roots(reference, _context=_context)
    from . import rapid_static_parallel_schedule as static
    if capsule["artifact_type"] == static.CAPSULE_TYPE:
        return static.mount_roots(reference, _context=_context)
    roots = {Path(reference["path"]).parent}
    for role in (capsule["base_spec"], capsule["runtime"]):
        roots.update(Path(role[key]) for key in ("data_root", "runtime_source_root", "module_root", "execution_root"))
        roots.update(Path(role[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    for original in (capsule["original_canonical"], capsule["current_canonical"]):
        seen = set()
        while original is not None:
            path, raw = evidence._reference(original)
            if path in seen:
                raise ValueError("scheduling runtime transport contains a reuse cycle")
            seen.add(path)
            roots.add(path.parent)
            canonical = evidence._json(raw)
            for key in ("client_reuse_recipe", "client_reuse_proof", "original_native_build_record"):
                if key in canonical:
                    roots.add(evidence._reference(canonical[key])[0].parent)
            original = canonical.get("original_canonical")
    for root in roots:
        evidence._path(str(root), directory=True)
        if any(c in str(root) for c in ("\n", "\r", "\0", ":")):
            raise ValueError("scheduling transport requires regular absolute roots")
    return sorted(roots)
