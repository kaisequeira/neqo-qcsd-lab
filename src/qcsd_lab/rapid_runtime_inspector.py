"""Prospective control inspectors for unchanged installed static measurements.

The measurement and control images are independently reopened. No old receipt
is edited or attributed to the control image. Only named control definitions
may differ; the complete graphs, qualification primitive and physical capture
dependencies stay bound to their original bytes.
"""
from __future__ import annotations

import ast
import json
import math
import stat
from dataclasses import replace
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping

from . import chaff_qualification as qualification
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_readiness as evidence
from . import rapid_rolling_schedule as legacy
from .util import durable_create

CONTRACT = "rolling-v6-static-measurement-and-installed-control-inspector-v2"
DEPENDENCY_CONTRACT = "rolling-v6-static-measurement-and-installed-control-inspector-v3"
MODULE_FILE = "src/qcsd_lab/rapid_runtime_inspector.py"
REUSE_SCHEMA1_KEYS = frozenset({"schema_version", "artifact_type", "native_artifact_action", "source",
    "original_native_build_source", "client_sha256", "original_canonical", "original_build_inputs",
    "original_client_build", "original_release_command", "original_release_started", "original_release_completion",
    "original_installed_client", "original_installed_source", "original_actual_operation_completions",
    "original_source_inventory", "target_build_inputs", "target_source_inventory", "native_source_inventory_equal",
    "rust_archive_sha256", "cargo_lock_sha256", "toolchain_image", "producer_recipe", "native_compilation_executed",
    "scientific_credit", "formal_accepted_trace_count", "runtime_qualification"})


def schema1_reuse_facts(reuse: Mapping, canonical: Mapping, original: Mapping,
                        original_path: Path, current_native: Mapping, original_native: Mapping) -> dict:
    """Authenticate the real schema1 producer, then derive its absent facts.

    The original producer emitted neither an executable/count convenience field
    nor a copy timestamp. Its exact producer and successful actual copy command
    bind that operation. Present convenience values still require strict types
    and equality; this branch never repairs a changed receipt.
    """
    optional = {"original_client_executable", "native_source_file_count", "copied_at"}
    if (not isinstance(reuse, Mapping) or not REUSE_SCHEMA1_KEYS <= set(reuse)
        or set(reuse) - REUSE_SCHEMA1_KEYS - optional
        or type(reuse["schema_version"]) is not int or reuse["schema_version"] != 1
        or reuse["artifact_type"] != "qcsd-exact-existing-native-client-reuse"
        or reuse["native_artifact_action"] != "verified-exact-existing-client-reuse"
        or reuse["native_compilation_executed"] is not False
        or reuse["scientific_credit"] is not False or reuse["runtime_qualification"] != "not-executed"
        or type(reuse["formal_accepted_trace_count"]) is not int or reuse["formal_accepted_trace_count"] != 0
        or original.get("native_artifact_action") != "new-cached-native-release-build"
        or original.get("native_compilation_executed", True) is not True
        or reuse["producer_recipe"] != canonical["client_reuse_recipe"]
        or reuse["original_native_build_source"] != original["source"]
        or not current_native or current_native != original_native):
        raise ValueError("inspector schema1 reuse producer or original Native authority differs")
    evidence._reference(reuse["producer_recipe"])
    expected = {"original_release_command": original_path.parent / "release-command.json",
                "original_release_started": original_path.parent / "release-build-started.json",
                "original_release_completion": original_path.parent / "release-build-completed.json"}
    for name, path in expected.items():
        if reuse[name] != {"path": str(path), "sha256": evidence._sha(evidence._read(path))}:
            raise ValueError("inspector schema1 original release reference differs")
        evidence._reference(reuse[name])
    started = evidence._json(evidence._read(expected["original_release_started"]))
    completed = evidence._json(evidence._read(expected["original_release_completion"]))
    command = json.loads(evidence._read(expected["original_release_command"]), object_pairs_hook=evidence._pairs)
    if (started.get("command") != command or type(completed.get("returncode")) is not int
        or completed["returncode"] != 0 or completed.get("invocation_error") is not None
        or not evidence._timestamp(started["started_at"]) <= evidence._timestamp(completed["completed_at"])
        or reuse["original_actual_operation_completions"] != original["actual_operation_completions"]):
        raise ValueError("inspector schema1 original release did not actually complete")
    copy_root = Path(canonical["client_reuse_proof"]["path"]).parent
    copy_started = evidence._json(evidence._read(copy_root / "client-reuse-started.json"))
    copy_completed = evidence._json(evidence._read(copy_root / "client-reuse-completed.json"))
    if (not evidence._timestamp(completed["completed_at"]) <= evidence._timestamp(original["verified_at"])
            <= evidence._timestamp(copy_started["started_at"]) <= evidence._timestamp(copy_completed["completed_at"])
        or type(copy_completed.get("returncode")) is not int or copy_completed["returncode"] != 0
        or copy_completed.get("invocation_error") is not None):
        raise ValueError("inspector schema1 original runtime must close before the actual copy starts")
    client_path, client = evidence._reference(reuse["original_installed_client"])
    if (str(client_path) != original["client_binary"] or not client_path.stat().st_mode & 0o111
        or evidence._sha(client) != original["installed_client_sha256"]
        or original["source"]["neqo_commit"].encode() not in client):
        raise ValueError("inspector schema1 original installed executable differs")
    count = len(current_native)
    if ("original_client_executable" in reuse and reuse["original_client_executable"] is not True
        or "native_source_file_count" in reuse and
           (type(reuse["native_source_file_count"]) is not int or reuse["native_source_file_count"] != count)):
        raise ValueError("inspector schema1 present convenience facts are malformed or changed")
    if "copied_at" in reuse:
        evidence._timestamp(reuse["copied_at"])
    return {"original_client_executable": True, "native_source_file_count": count,
            "copy_chronology": "actual-bound-copy-operation"}


def is_inspected(value: Any) -> bool:
    return (isinstance(value, Mapping) and type(value.get("schema_version")) is int
            and ((value["schema_version"] == 2 and value.get("contract") == CONTRACT)
                 or (value["schema_version"] == 3 and value.get("contract") == DEPENDENCY_CONTRACT))
            and value.get("artifact_type") == "qcsd-rapid-v6-current-static-parallel-scheduling")


CONTROL_DEFINITIONS = {
    "src/qcsd_lab/rapid_rolling_schedule.py": frozenset({"reopen_runtime", "validate_schedule",
        "validate_qualification_reuse", "mount_roots"}),
    "src/qcsd_lab/rapid_static_parallel_schedule.py": frozenset({"validate_schedule",
        "validate_current_qualification", "mount_roots"}),
    "src/qcsd_lab/rapid_rolling_capture.py": frozenset({"_static_measurement_runtime", "publish_plan",
        "verify_capture_plan", "require_mode_readiness", "readiness_roots"}),
    "src/qcsd_lab/rapid_runtime_epochs.py": frozenset({"validate_qualification_reuse"}),
    "src/qcsd_lab/rapid_formal_parallel.py": frozenset({"_release_fence"}),
    "src/qcsd_lab/rapid_operation_facts.py": frozenset({"OperationFacts.bind_schedule"}),
    "tools/rapid_rolling_capture.py": frozenset({"run", "_parser"}),
}
DEPENDENCY_CONTROL_DEFINITIONS = {**CONTROL_DEFINITIONS,
    "src/qcsd_lab/rapid_operation_facts.py": frozenset({"OperationFacts.bind_schedule",
        "OperationFacts._workload_evidence_trees", "OperationFacts.bind_canary"})}
NEW_FILES = frozenset({MODULE_FILE, "src/qcsd_lab/rapid_original_static_parallel_schedule.py",
    "tests/test_rapid_runtime_inspector.py", "tests/test_rapid_original_static_parallel_schedule.py",
    "tests/test_rapid_static_shell_dispatch.py", "docs/ORIGINAL-STATIC-THREE-MODES.md"})
DOCUMENTS = frozenset({"PROJECT.md", "docs/EVIDENCE-INDEX.md", "docs/RAPID-CAPTURE-PATH.md",
                      "docs/ORIGINAL-STATIC-THREE-MODES.md"})
ROUTING_OLD = b'    if [[ "${rapid_scheduling_kind}" == "qcsd-rapid-v6-prospective-parallel-scheduling" ]]; then\n'
ROUTING_NEW = (b'    if [[ "${rapid_scheduling_kind}" == "qcsd-rapid-v6-prospective-parallel-scheduling" ||\n'
    b'          "${rapid_scheduling_kind}" == "qcsd-rapid-v6-current-static-parallel-scheduling" ||\n'
    b'          "${rapid_scheduling_kind}" == "qcsd-rapid-v6-current-original-static-parallel-scheduling" ]]; then\n')


def _python_projection(path: str, raw: bytes, *, _dependency_closure=False) -> tuple[str, dict[str, str]]:
    if type(_dependency_closure) is not bool:
        raise ValueError("inspector input closure projection must be explicitly typed")
    tree = ast.parse(raw, filename=path)
    permitted = (DEPENDENCY_CONTROL_DEFINITIONS if _dependency_closure else CONTROL_DEFINITIONS)[path]
    units = {}
    retained = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in permitted:
            if node.name in units:
                raise ValueError("inspector duplicates a named control definition")
            units[node.name] = evidence._sha(ast.dump(node, include_attributes=False).encode())
        elif isinstance(node, ast.ClassDef):
            methods = []
            for method in node.body:
                name = node.name + "." + getattr(method, "name", "")
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and name in permitted:
                    if name in units:
                        raise ValueError("inspector duplicates a named control method")
                    units[name] = evidence._sha(ast.dump(method, include_attributes=False).encode())
                else:
                    methods.append(method)
            node.body = methods
            retained.append(node)
        else:
            retained.append(node)
    return ast.dump(ast.Module(body=retained, type_ignores=[]), include_attributes=False), units


def _routing_projection(raw: bytes) -> bytes:
    values = [item for item in (ROUTING_OLD, ROUTING_NEW) if raw.count(item) == 1]
    if len(values) != 1:
        raise ValueError("inspector launcher lacks the exact named static routing predicate")
    return raw.replace(values[0], b"# static-inspector:exact-artifact-routing\n")


def source_changes(old: Mapping[str, bytes], new: Mapping[str, bytes], *, client_sha256: str,
                   duration_policy: str | None = None, _dependency_closure=False) -> dict:
    """Closed named control projection, with all other Source protected."""
    if type(_dependency_closure) is not bool:
        raise ValueError("inspector input closure projection must be explicitly typed")
    from . import rapid_capture_control_compatibility as acquisition
    from . import supplied_static_capture_amendment as amendment
    from . import rapid_capture_traffic as traffic
    if set(old) - set(new) or set(new) - set(old) - NEW_FILES:
        raise ValueError("inspector added an unregistered Source or removed an original Source")
    changes = {}
    for path in sorted(new):
        if old.get(path) == new[path]:
            continue
        if path in DOCUMENTS or path.startswith("tests/") and path in NEW_FILES:
            units = ["nonexecuting-prospective-description"]
        elif path in NEW_FILES and path.startswith("src/") and path not in old:
            imported = evidence._read(Path(import_module("qcsd_lab." + Path(path).stem).__file__))
            if imported != new[path]:
                raise ValueError("inspector new authority differs from the actual executing control Source")
            ast.parse(new[path])
            units = ["explicit-new-control-authority"]
        elif path == "qcsd-lab":
            if _routing_projection(old[path]) != _routing_projection(new[path]):
                raise ValueError("inspector changed launcher bytes outside the exact static routing predicate")
            units = ["exact-static-artifact-routing"]
        elif path in CONTROL_DEFINITIONS:
            before, old_units = _python_projection(path, old[path], _dependency_closure=_dependency_closure)
            after, new_units = _python_projection(path, new[path], _dependency_closure=_dependency_closure)
            if before != after:
                raise ValueError("inspector changed Source outside named control definitions: " + path)
            units = sorted(name for name in old_units.keys() | new_units.keys()
                           if old_units.get(name) != new_units.get(name))
            if not units:
                raise ValueError("inspector Source differs without a named semantic control change")
        else:
            raise ValueError("inspector changed a protected Source: " + path)
        changes[path] = {"before_sha256": evidence._sha(old[path]) if path in old else None,
                         "after_sha256": evidence._sha(new[path]), "units": units}
    protected = {path: evidence._sha(old[path]) for path in qualification.IMPLEMENTATION_FILES
                 if path != "qcsd-lab"}
    protected.update({path: evidence._sha(old[path]) for path in amendment.authority_files(duration_policy).values()})
    for group, names in evidence.DEPENDENCY_FILES.items():
        for name in names:
            path = "src/qcsd_lab/" + name + ".py"
            protected[path] = evidence._sha(old[path])
    for path in evidence.STATIC_MEASUREMENT_FILES:
        protected[path] = evidence._sha(old[path])
    for path, digest in protected.items():
        if path not in new or evidence._sha(new[path]) != digest:
            raise ValueError("inspector changed a measurement, acceptance, chaff or amendment producer")
    old_native = {path: evidence._sha(raw) for path, raw in old.items() if path.startswith("neqo-qcsd/")}
    new_native = {path: evidence._sha(raw) for path, raw in new.items() if path.startswith("neqo-qcsd/")}
    if not old_native or old_native != new_native:
        raise ValueError("inspector changed the full Native Source inventory")
    traffic_hashes = traffic.expected(duration_policy)
    if any(evidence._sha(old[path]) != digest or evidence._sha(new[path]) != digest
           for path, digest in traffic.files(duration_policy).values()):
        raise ValueError("inspector changed fixed traffic parameters")
    expected = acquisition._expected_acquisition_modules()
    hashes = {path: evidence._sha(raw) for path, raw in old.items()}
    current_hashes = {path: evidence._sha(raw) for path, raw in new.items()}
    groups = {group: {name: client_sha256 if name == "neqo-qcsd-client" else hashes[
        ("src/" if name.startswith("qcsd_lab.") else "") + name.replace(".", "/") + ".py"]
        for name in names} for group, names in expected.items()}
    acquisition_groups = acquisition._acquisition_groups(groups, hashes, current_hashes, client_sha256)
    return {"contract": DEPENDENCY_CONTRACT if _dependency_closure else CONTRACT,
            "changed_sources": changes, "protected_sources": protected,
            "native_source_hashes": old_native, "traffic_hashes": traffic_hashes,
            "acquisition_source_groups": acquisition_groups,
            "launcher_protected_sha256": evidence._sha(_routing_projection(old["qcsd-lab"]))}


KEYS = {"schema_version", "artifact_type", "contract", "base_spec", "runtime", "qualification_spec",
    "original_canonical", "current_canonical", "qualified_inputs", "control_sources", "source_comparison",
    "static_capture_amendment", "mode", "traffic_hashes", "buflo_duration_policy", "reason", "published_at",
    "execution_inputs", "execution_copy", "limits", "formal_accepted_trace_count", "scientific_credit"}


def _copy_operation(reference: Mapping, base: lanes.CaptureSpec, plan: Mapping,
                    canonicals: tuple[Mapping, Mapping], *, _context=None) -> datetime:
    if not isinstance(reference, Mapping) or set(reference) != evidence.OPERATION_KEYS:
        raise ValueError("inspector needs all four actual input-copy recorder references")
    contents, paths = {}, {}
    for key, value in reference.items():
        paths[key], contents[key] = evidence._reference(value)
        if _context is not None:
            _context._reference(value)
    started_path = paths["started"]
    if not started_path.name.endswith("-started.json"):
        raise ValueError("inspector copy operation lacks its original recorder name")
    name = started_path.name.removesuffix("-started.json")
    if any(paths[key] != started_path.parent / (name + suffix) for key, suffix in
           (("completed", "-completed.json"), ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))):
        raise ValueError("inspector copy operation combines unrelated recorder files")
    start, end = evidence._json(contents["started"]), evidence._json(contents["completed"])
    command, elapsed = start.get("command"), end.get("elapsed_seconds")
    if (type(end.get("returncode")) is not int or end["returncode"] != 0
        or end.get("invocation_error") is not None
        or end.get("stdout_sha256") != evidence._sha(contents["stdout"])
        or end.get("stderr_sha256") != evidence._sha(contents["stderr"])
        or not isinstance(command, list) or not command
        or any(not isinstance(item, str) or not item for item in command)
        or type(elapsed) not in {int, float} or not math.isfinite(elapsed) or elapsed < 0):
        raise ValueError("inspector input copying lacks a successful actual command and original raw logs")
    began, ended = evidence._timestamp(start.get("started_at")), evidence._timestamp(end.get("completed_at"))
    if (not began <= ended < datetime.now(UTC)
        or any(evidence._timestamp(value["verified_at"]) > began for value in canonicals)
        or evidence._timestamp(plan["declared_at"]) > began):
        raise ValueError("inspector copying precedes an original plan or closed control runtime")
    for mode, canary in plan["readiness"].items():
        for phase in ("capture", "deep"):
            completed = evidence._json(evidence._reference(canary[phase]["completed"])[1])
            if evidence._timestamp(completed["completed_at"]) > began:
                raise ValueError("inspector copying precedes the original passed setting's closure")
    qualifier = evidence._json(evidence._read(base.qualification_spec))
    sidecars = Path(qualifier["qualification_sets"][0]["sidecar_root"])
    if not sidecars.is_absolute():
        sidecars = base.qualification_spec.parent / sidecars
    epoch = began - datetime(1970, 1, 1, tzinfo=UTC)
    start_ns = (epoch.days * 86400 + epoch.seconds) * 1_000_000_000 + epoch.microseconds * 1000
    for site in plan["sites"]:
        sidecar = evidence._json(evidence._read(sidecars / (site["workload_id"] + ".json")))
        for attempt in sidecar["candidate_attempts"]:
            for item in attempt["connection_epochs"]:
                receipt = item["receipt"]
                if type(receipt.get("ended_unix_ns")) is not int or receipt["ended_unix_ns"] > start_ns:
                    raise ValueError("inspector copying precedes an original 120-response completion")
    return ended


def _execution_inputs(base: lanes.CaptureSpec, runtime: Mapping[str, str], qualifier: Path,
                      plan: Mapping, *, _context=None) -> dict:
    """Bind input copies into a distinct control execution without rewriting proofs."""
    old_root, new_root = base.execution_root, Path(runtime["execution_root"])
    if (old_root == new_root or old_root.is_relative_to(new_root) or new_root.is_relative_to(old_root)
        or any(new_root.is_relative_to(getattr(base, key)) or getattr(base, key).is_relative_to(new_root)
               for key in ("runtime_source_root", "module_root"))
        or Path(runtime["host_launcher"]) != new_root / "qcsd-lab"
        or evidence._read(Path(runtime["host_launcher"])) != evidence._read(Path(runtime["base_launcher"]))):
        raise ValueError("inspector needs a distinct execution root and its actual control launcher")
    for key in ("workload_root", "campaign_dir"):
        if Path(runtime[key]).relative_to(new_root) != getattr(base, key).relative_to(old_root):
            raise ValueError("inspector input copies changed the relative execution layout")
    def copied(original: Path, current: Path) -> dict:
        old = evidence._read(original)
        new = evidence._read(current)
        if old != new or stat.S_IMODE(original.stat().st_mode) != stat.S_IMODE(current.stat().st_mode):
            raise ValueError("inspector execution input copy changed original bytes or executable mode")
        if _context is not None:
            _context.watch_file(original); _context.watch_file(current)
        return {"original": {"path": str(original), "sha256": evidence._sha(old)},
                "current": {"path": str(current), "sha256": evidence._sha(new)},
                "mode": stat.S_IMODE(original.stat().st_mode)}
    def full_inventory(root):
        return {name: {**row, "mode": stat.S_IMODE((root / name).stat().st_mode)}
                for name, row in evidence._inventory(root).items()}
    workload_inventory = full_inventory(base.workload_root)
    if not workload_inventory or workload_inventory != full_inventory(Path(runtime["workload_root"])):
        raise ValueError("inspector workload copy changed complete file bytes, modes or membership")
    if _context is not None:
        _context.watch_tree(base.workload_root); _context.watch_tree(Path(runtime["workload_root"]))
    workloads = {row["workload_id"]: copied(base.workload_root / (row["workload_id"] + ".json"),
        Path(runtime["workload_root"]) / (row["workload_id"] + ".json")) for row in plan["sites"]}
    campaigns = {row["campaign_name"]: copied(base.campaign_dir / (row["campaign_name"] + ".yml"),
        Path(runtime["campaign_dir"]) / (row["campaign_name"] + ".yml")) for row in plan["lanes"]}
    old_q = evidence._json(evidence._read(base.qualification_spec))
    new_q = evidence._json(evidence._read(qualifier))
    if (set(old_q) != {"schema_version", "qualification_sets"} or set(new_q) != set(old_q)
        or type(new_q["schema_version"]) is not int or new_q["schema_version"] != 1
        or old_q["schema_version"] != 1 or len(old_q["qualification_sets"]) != 1
        or not isinstance(new_q["qualification_sets"], list) or len(new_q["qualification_sets"]) != 1):
        raise ValueError("inspector copied qualifier envelope has an invalid exact schema")
    old_row, new_row = old_q["qualification_sets"][0], new_q["qualification_sets"][0]
    if (set(old_row) != {"qualification_set", "manifest", "sidecar_root", "prefix_spec_root"}
        or set(new_row) != set(old_row) or new_row["qualification_set"] != old_row["qualification_set"]
        or new_row["prefix_spec_root"] is not None or old_row["prefix_spec_root"] is not None):
        raise ValueError("inspector changed the original named qualification or scope")
    def resolved(row, source, name):
        value = row[name]
        if not isinstance(value, str) or not value:
            raise ValueError("inspector qualification copy path is invalid")
        path = Path(value) if Path(value).is_absolute() else source.parent / value
        return evidence._path(path, directory=name == "sidecar_root")
    old_set = resolved(old_row, base.qualification_spec, "sidecar_root")
    new_set = resolved(new_row, qualifier, "sidecar_root")
    expected_old = base.campaign_dir.parent / "chaff-response-qualification-store/sets" / old_row["qualification_set"]
    expected_new = Path(runtime["campaign_dir"]).parent / "chaff-response-qualification-store/sets" / old_row["qualification_set"]
    if (old_set != expected_old or new_set != expected_new
        or resolved(old_row, base.qualification_spec, "manifest") != old_set / "_qualification-set.json"
        or resolved(new_row, qualifier, "manifest") != new_set / "_qualification-set.json"):
        raise ValueError("inspector named qualification copy changed its actual installed config layout")
    before, after = full_inventory(old_set), full_inventory(new_set)
    if not before or before != after:
        raise ValueError("inspector changed a full original named120 file, inventory or executable mode")
    if _context is not None:
        _context.watch_file(base.qualification_spec); _context.watch_file(qualifier)
        _context.watch_tree(old_set); _context.watch_tree(new_set)
    return {"workloads": workloads, "workload_inventory": workload_inventory, "campaigns": campaigns,
        "qualification_spec": {"original": {"path": str(base.qualification_spec), "sha256": evidence._sha(evidence._read(base.qualification_spec))},
                               "current": {"path": str(qualifier), "sha256": evidence._sha(evidence._read(qualifier))}},
        "named_set": {"original_root": str(old_set), "current_root": str(new_set), "inventory": before}}


def _derive(base: lanes.CaptureSpec, runtime: Mapping[str, str], qualifier: Path,
            original: Mapping[str, str], current: Mapping[str, str], execution_copy: Mapping,
            *, _context=None, _dependency_closure=False) -> dict:
    from . import rapid_static_parallel_schedule as static
    from . import rapid_rolling_capture as rolling
    from . import rapid_capture_traffic as traffic
    from . import supplied_static_capture_amendment as amendment
    lanes._check_spec(base)
    runtime = rolling._runtime(runtime)
    if runtime["data_root"] != str(base.data_root):
        raise ValueError("inspector cannot replace the study data root")
    sites, plan = rolling.verify_capture_plan(base, require_current=False, _context=_context)
    if ("scheduling" in plan or "front_capture_amendment" in plan
        or "static_capture_amendment" not in plan or plan.get("study_version") != 6
        or plan.get("cohort_generation") != "rolling-50" or len(plan["readiness"]) != 1
        or not 1 <= len(sites) <= 5
        or any(type(row["visits_per_workload"]) is not int or row["visits_per_workload"] != 4
               or row["workload_ids"] != [site.workload_id for site in sites] for row in plan["lanes"])):
        raise ValueError("inspector requires its original serial amended four-visit plan")
    mode = next(iter(plan["readiness"]))
    execution_inputs = _execution_inputs(base, runtime, qualifier, plan, _context=_context)
    reference = plan["static_capture_amendment"]
    measurement_runtime = {key: str(getattr(base, key)) for key in rolling.RUNTIME_FIELDS}
    closed = amendment.validate_amendment(rolling._open_ref(reference), enrollment=base.cohort,
                                        runtime=measurement_runtime)
    if mode not in closed["modes"]:
        raise ValueError("inspector setting differs from its original amendment")
    old, old_sources = legacy.reopen_runtime(original, measurement_runtime, _inspector=True)
    new, new_sources = legacy.reopen_runtime(current, runtime, _inspector=True)
    _copy_operation(execution_copy, base, plan, (old, new), _context=_context)
    if (any(old["source"][key] != new["source"][key] for key in
            ("neqo_commit", "neqo_pinned_commit", "neqo_dirty", "neqo_patch_sha256"))
        or old["installed_client_sha256"] != new["installed_client_sha256"]):
        raise ValueError("inspector changed the original Native or actual installed client")
    selected = traffic.declared(plan)
    comparison = source_changes(old_sources, new_sources, client_sha256=old["installed_client_sha256"],
                                duration_policy=selected, _dependency_closure=_dependency_closure)
    inventories, build_dependencies = [], []
    for ref, canonical in ((original, old), (current, new)):
        root = Path(ref["path"]).parent
        inventories.append(evidence._json(evidence._read(root / "source-inventory.json", canonical["source_inventory_sha256"])))
        inputs = evidence._json(evidence._read(root / "build-inputs.json"))
        build_dependencies.append({key: inputs[key] for key in ("collection_base_image", "prepare_base_image",
            "toolchain_image", "cargo_lock_sha256", "rust_archive_sha256", "recipe_files")})
    if (build_dependencies[0] != build_dependencies[1]
        or any(inventories[0][path]["executable"] != inventories[1][path]["executable"]
               for path in inventories[0].keys() & inventories[1].keys())):
        raise ValueError("inspector changed build dependencies or retained Source executable modes")
    comparison["runtime_build_dependencies"] = build_dependencies[0]
    controls = {}
    for relative in (MODULE_FILE, *static.CONTROL_FILES, *CONTROL_DEFINITIONS):
        own = (evidence._read(Path(import_module("qcsd_lab." + Path(relative).stem).__file__))
               if relative.startswith("src/qcsd_lab/") else evidence._read(Path(runtime["module_root"]) / relative))
        if own != new_sources.get(relative):
            raise ValueError("inspector execution differs from its actual installed control Source")
        controls[relative] = evidence._sha(own)
    qualified = static._qualified_inputs(base, base.qualification_spec, plan["sites"], _context=_context)
    copied_base = replace(base, workload_root=Path(runtime["workload_root"]),
        campaign_dir=Path(runtime["campaign_dir"]), qualification_spec=qualifier)
    copied_qualified = static._qualified_inputs(copied_base, qualifier, plan["sites"], _context=_context)
    measurement_source = {**old["source"], "image_digest": old["collection_image_digest"]}
    if ({key: value for key, value in qualified.items() if key != "qualification_spec_sha256"}
          != {key: value for key, value in copied_qualified.items() if key != "qualification_spec_sha256"}
        or set(qualified["implementation_sha256"].values()) != {
            old["checks"]["collection"]["qualification_implementation_sha256"]}
        or any(row != {"source": measurement_source, "image": old["collection_image_digest"]}
               for row in qualified["qualification_sources"].values())):
        raise ValueError("inspector changed the original actual 120-response producer identity")
    for key in ("runtime_source_root", "module_root", "execution_root"):
        for relative, digest in traffic.files(selected).values():
            evidence._read(Path(runtime[key]) / relative, digest)
    row = next(row for row in plan["lanes"] if row["mode"] == mode)
    rolling.require_mode_readiness(base, lanes._lane({"plan_payload": plan}, row["campaign_name"]), _context=_context)
    static.terminal_inputs(base.cohort, _context=_context)
    return {"qualified_inputs": qualified, "execution_inputs": execution_inputs,
            "execution_copy": dict(execution_copy),
            "control_sources": controls, "source_comparison": comparison,
            "static_capture_amendment": reference, "mode": mode, "traffic_hashes": traffic.expected(selected),
            traffic.FIELD: selected}


def publish_schedule(base_spec: lanes.CaptureSpec, runtime: Mapping[str, str], qualification_spec: Path,
                     original_canonical: Mapping[str, str], current_canonical: Mapping[str, str],
                     output: Path, *, execution_copy: Mapping, reason: str) -> dict[str, str]:
    from . import rapid_static_parallel_schedule as static
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("inspector requires an explicit prospective control scope")
    output = Path(output)
    if (not output.is_absolute() or ".." in output.parts
        or any(item.is_symlink() for item in (output, *output.parents))):
        raise ValueError("inspector output must be an absolute unlinked create-only path")
    for role in (base_spec.serializable(), runtime):
        if any(output.is_relative_to(Path(role[key])) for key in ("runtime_source_root", "module_root")):
            raise ValueError("inspector output overlaps a frozen Source role")
    if any(output.is_relative_to(Path(ref["path"]).parent) for ref in (original_canonical, current_canonical)):
        raise ValueError("inspector output overlaps an immutable runtime closure")
    derived = _derive(base_spec, runtime, qualification_spec, original_canonical, current_canonical,
        execution_copy, _dependency_closure=True)
    now = datetime.now(UTC).isoformat()
    if any(evidence._timestamp(evidence._json(evidence._reference(ref)[1])["verified_at"]) > evidence._timestamp(now)
           for ref in (original_canonical, current_canonical)):
        raise ValueError("inspector publication precedes an actual runtime closure")
    if evidence._timestamp(evidence._json(evidence._reference(execution_copy["completed"])[1])["completed_at"]) >= evidence._timestamp(now):
        raise ValueError("inspector publication must follow actual completed input copying")
    payload = {"schema_version": 3, "artifact_type": static.CAPSULE_TYPE, "contract": DEPENDENCY_CONTRACT,
        "base_spec": base_spec.serializable(), "runtime": dict(runtime),
        "qualification_spec": {"path": str(qualification_spec), "sha256": evidence._sha(evidence._read(qualification_spec))},
        "original_canonical": dict(original_canonical), "current_canonical": dict(current_canonical),
        **derived, "reason": reason.strip(), "published_at": now, "limits": dict(legacy.LIMITS),
        "formal_accepted_trace_count": 0, "scientific_credit": False}
    durable_create(output, evidence._encoded(payload))
    return {"path": str(output), "sha256": evidence._sha(evidence._read(output))}


def validate_schedule(reference: Mapping[str, str], *, runtime: Mapping[str, str] | None = None,
                      before: str | None = None, _context=None) -> dict:
    value = evidence._json(evidence._reference(reference)[1])
    if (not is_inspected(value) or set(value) != KEYS or value["limits"] != legacy.LIMITS
        or value["scientific_credit"] is not False or type(value["formal_accepted_trace_count"]) is not int
        or value["formal_accepted_trace_count"] != 0 or not isinstance(value["reason"], str) or not value["reason"].strip()):
        raise ValueError("inspector has an invalid exact prospective contract")
    published = evidence._timestamp(value["published_at"])
    if (published > datetime.now(UTC) or before is not None and
        not published < evidence._timestamp(before) <= datetime.now(UTC)
        or runtime is not None and dict(runtime) != value["runtime"]):
        raise ValueError("inspector belongs to another control runtime or prospective chronology")
    if _context is not None:
        _context._reference(reference)
        _context.bind_schedule(value)
    key = ("static-inspector-v2", evidence._sha(evidence._reference(reference)[1]))
    if _context is not None and _context.has(key):
        derived = _context.get(key)
    else:
        derived = _derive(legacy._spec(value["base_spec"]), value["runtime"],
            evidence._reference(value["qualification_spec"])[0], value["original_canonical"],
            value["current_canonical"], value["execution_copy"], _context=_context,
            _dependency_closure=value["schema_version"] == 3)
        if _context is not None:
            _context.remember(key, derived)
    if any(value[name] != item for name, item in derived.items()):
        raise ValueError("inspector changed its Source roles, original qualification, complete graph or traffic")
    if any(evidence._timestamp(evidence._json(evidence._reference(ref)[1])["verified_at"]) > published
           for ref in (value["original_canonical"], value["current_canonical"])):
        raise ValueError("inspector predates an actual runtime closure")
    if evidence._timestamp(evidence._json(evidence._reference(value["execution_copy"]["completed"])[1])["completed_at"]) >= published:
        raise ValueError("inspector publication predates actual completed input copying")
    return value


def validate_qualification(old_impl: Mapping, current_impl: Mapping, reference: Mapping[str, str], *,
                           actual_image: str, before: str | None = None, _context=None) -> None:
    """Bind both real image implementations and the exact qualified primitive."""
    value = validate_schedule(reference, before=before, _context=_context)
    if actual_image != value["runtime"]["collection_image_digest"]:
        raise ValueError("inspector qualification hook executes another control image")
    for receipt, key in ((old_impl, "original_canonical"), (current_impl, "current_canonical")):
        qualification._validate_implementation_receipt(receipt, require_current=False)
        canonical = evidence._json(evidence._reference(value[key])[1])
        inventory = evidence._json(evidence._read(Path(value[key]["path"]).parent / "source-inventory.json",
                                                canonical["source_inventory_sha256"]))
        if (receipt["schema_version"] != qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION
            or receipt["sha256"] != canonical["checks"]["collection"]["qualification_implementation_sha256"]
            or receipt["source"] != canonical["source"]
            or receipt["neqo_qcsd_client"]["sha256"] != canonical["installed_client_sha256"]
            or any(inventory.get(path, {}).get("sha256") != digest for path, digest in receipt["source_files"].items())):
            raise ValueError("inspector qualification differs from its actual measurement or control image")
    if (old_impl["neqo_qcsd_client"] != current_impl["neqo_qcsd_client"]
        or old_impl["installed_entrypoint"] != current_impl["installed_entrypoint"]
        or old_impl["installed_modules"] != current_impl["installed_modules"]
        or any(old_impl["source_files"][path] != current_impl["source_files"][path]
               for path in qualification.IMPLEMENTATION_FILES if path != "qcsd-lab")):
        raise ValueError("inspector changed a real qualification executable or installed primitive")
    changed = old_impl["source_files"]["qcsd-lab"] != current_impl["source_files"]["qcsd-lab"]
    projected = value["source_comparison"]["changed_sources"].get("qcsd-lab")
    if changed and (projected is None or projected["units"] != ["exact-static-artifact-routing"]
        or projected["before_sha256"] != old_impl["source_files"]["qcsd-lab"]
        or projected["after_sha256"] != current_impl["source_files"]["qcsd-lab"]):
        raise ValueError("inspector qualification launcher lacks the exact named routing projection")
