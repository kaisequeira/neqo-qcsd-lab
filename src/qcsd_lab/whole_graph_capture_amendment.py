"""Prospective traffic settings for mixed original/static and whole-graph admissions.

The old amendment schema and producer maps retain their meanings. This separate
receipt binds each original data role, the new occurrence-graph verifier, and
the current actual capture Source before derived files or named120 runs exist.
"""
from __future__ import annotations

from copy import deepcopy
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping

from . import supplied_static_capture_amendment as old
from . import supplied_static_graph as graph
from . import supplied_static_preparation as prep
from . import whole_graph_supplement as whole
from . import rapid_capture_traffic as traffic
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling

DECLARATION_TYPE = "qcsd-mixed-whole-graph-capture-policy-declaration-v1"
RECEIPT_TYPE = "qcsd-mixed-whole-graph-capture-policy-amendment-v1"
CONTRACT = "unchanged-mixed-original-and-whole-occurrence-get-graphs-with-explicit-capture-settings-v1"
DURATION_CONTRACT = "unchanged-mixed-complete-get-graphs-with-fixed-buflo200-setting-v1"
ROLE = "mixed-whole-occurrence-get-amended-capture-preparation-v1"
DURATION_ROLE = "mixed-whole-occurrence-get-amended-buflo200-preparation-v1"
ADAPTER_FILES = {name: "src/qcsd_lab/" + name + ".py" for name in
    ("whole_graph_input", "whole_graph_supplement", "whole_graph_capture_amendment", "rapid_rolling_capture")}


CADENCE64_ROLE = "mixed-whole-occurrence-get-amended-buflo-cadence64-budget640-preparation-v1"
CADENCE64_CONTRACT = "unchanged-mixed-complete-get-graphs-with-fixed-buflo-cadence64-budget640-setting-v1"


def capture_role(duration: str | None) -> str:
    selected = traffic.policy(duration)
    return CADENCE64_ROLE if selected == traffic.budget.CADENCE64_POLICY else DURATION_ROLE if selected else ROLE


def capture_contract(duration: str | None) -> str:
    selected = traffic.policy(duration)
    return CADENCE64_CONTRACT if selected == traffic.budget.CADENCE64_POLICY else DURATION_CONTRACT if selected else CONTRACT


def is_amended(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("data_role") in {ROLE, DURATION_ROLE, CADENCE64_ROLE}


def authority_files(duration_policy: str | None = None) -> dict[str, str]:
    return {**old.authority_files(duration_policy), **ADAPTER_FILES}


def _sources(runtime: Mapping[str, str], duration_policy: str | None) -> dict[str, str]:
    files = authority_files(duration_policy)
    current = {name: graph.digest(lanes._read(Path(import_module("qcsd_lab." + name).__file__))) for name in files}
    for key in ("module_root", "runtime_source_root"):
        if any(graph.digest(lanes._read(Path(runtime[key]) / relative)) != current[name] for name, relative in files.items()):
            raise ValueError("whole graph amendment authority differs from the actual current frozen Source")
    return current


def _rows(enrollment: Path, runtime: Mapping[str, str], batch, classes) -> list[dict]:
    policy = rolling.verify_policy(rolling._open_ref(batch["policy"]).parent)
    if policy["contract"] != rolling.STATIC_CONTRACT:
        raise ValueError("mixed whole graph amendment requires the same static fifty-site study")
    rows = []
    for row in classes[-len(batch["selected_candidate_ids"]):]:
        context = rolling._context_for_policy(policy, Path(row["admission_root"]))
        terminal = rolling._open_ref(row["terminal"])
        facts = rolling._verify_terminal(context, terminal)
        path, manifest = rolling._prepared_workload(context, terminal)
        preparation = manifest["preparation"]
        if (not (whole.is_whole(preparation) or prep.is_static(preparation)) or facts["outcome"] != "admitted"
                or {key: preparation.get(key) for key in old.ORIGINAL_POLICIES} != old.ORIGINAL_POLICIES):
            raise ValueError("mixed amendment changed its original complete GET or traffic settings")
        evidence = preparation["whole_graph_get_evidence"] if whole.is_whole(preparation) else preparation["static_get_evidence"]
        target = Path(runtime["workload_root"]) / path.name
        if target == path:
            raise ValueError("whole graph amendment must preserve the original manifest")
        rows.append({"candidate_id": row["candidate_id"], "workload_id": path.stem, "original_data_role": preparation["data_role"],
            "original_terminal": rolling._ref(terminal), "original_manifest": rolling._ref(path), "original_get_proof": evidence["proof"],
            "original_capture_policies": dict(old.ORIGINAL_POLICIES),
            "resource_records_sha256": graph.digest(graph.canonical_bytes(manifest["resources"])), "capture_manifest_path": str(target)})
    if not isinstance(rolling._context_for_policy(policy, Path(batch["admission_root"])), whole.Context):
        raise ValueError("whole graph amendment cannot replace an original-only static context authority")
    return rows


def _derived(original: Mapping[str, Any], declaration: Mapping[str, str], policies: Mapping[str, str], duration: str | None) -> dict:
    if not (whole.is_whole(original.get("preparation")) or prep.is_static(original.get("preparation"))):
        raise ValueError("whole graph amendment requires the exact admitted original preparation")
    value = deepcopy(dict(original))
    value["preparation"].update(data_role=capture_role(duration),
        **{old.FIELD: dict(declaration)}, **dict(policies))
    old.capture.validate_front_preparation_policy(value["preparation"])
    old.capture.validate_buflo_kernel_preparation_policy(value["preparation"])
    return value


def _declaration(path: Path, *, enrollment=None, runtime=None) -> dict:
    value = old.receipts._unpack(lanes._read(path), DECLARATION_TYPE)
    duration = traffic.policy(value.get(traffic.FIELD))
    fields = set(old.DECLARATION_FIELDS) | {"original_data_roles"}
    if duration:
        fields.update({traffic.FIELD, "traffic_artifacts"})
    rolling._keys(value, fields, "whole graph capture declaration")
    selected = old._policies(value["policies"], buflo_duration_policy=duration)
    expected_runtime = rolling._runtime(value["runtime"])
    actual_enrollment = rolling._open_ref(value["enrollment"])
    batch, classes, policy = rolling._verify_enrollment(actual_enrollment)
    rows = _rows(actual_enrollment, expected_runtime, batch, classes)
    if (value["contract"] != (capture_contract(duration))
            or value["original_data_role"] != whole.ROLE or value["original_data_roles"] != sorted({row["original_data_role"] for row in rows})
            or value["capture_data_role"] != (capture_role(duration))
            or value["modes"] != old._modes(selected) or duration and value["modes"] != ["buflo"]
            or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or value["scientific_credit"] is not False
            or enrollment is not None and actual_enrollment != enrollment.absolute()
            or runtime is not None and expected_runtime != rolling._runtime({key: runtime[key] for key in rolling.RUNTIME_FIELDS})
            or expected_runtime["data_root"] != policy["runtime"]["data_root"]
            or value["admission_provenance"] != rolling._ref(Path(batch["admission_root"]) / "provenance.json")
            or value["workloads"] != rows or value["authority_sources"] != _sources(expected_runtime, duration)
            or value["runtime_artifacts"] != {key: rolling._ref(Path(expected_runtime[key])) for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher")}
            or duration and value["traffic_artifacts"] != traffic.artifacts(expected_runtime, duration)
            or not old.receipts._utc(batch["declared_at"]) <= old.receipts._utc(value["published_at"]) <= old.receipts._utc(old.receipts._now())):
        raise ValueError("whole graph amendment changed original data roles, graph, GET, Source, traffic or runtime")
    for row in rows:
        rolling._keys(row, old.ROW_FIELDS | {"original_data_role"}, "whole graph amendment workload")
    return value


def validate_amendment(path: Path, *, enrollment=None, runtime=None) -> dict:
    value = old.receipts._unpack(lanes._read(path), RECEIPT_TYPE)
    rolling._keys(value, old.RECEIPT_FIELDS, "whole graph amendment closure")
    declaration = _declaration(rolling._open_ref(value["declaration"]), enrollment=enrollment, runtime=runtime)
    if (value["contract"] != declaration["contract"] or Path(declaration["receipt_path"]) != path.absolute()
            or value["scientific_credit"] is not False or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or not old.receipts._utc(declaration["published_at"]) <= old.receipts._utc(value["published_at"]) <= old.receipts._utc(old.receipts._now())):
        raise ValueError("whole graph amendment closure changed prospective identity or credit")
    expected = []
    for row in declaration["workloads"]:
        original = lanes._load(lanes._read(rolling._open_ref(row["original_manifest"])))
        path = Path(row["capture_manifest_path"])
        if lanes._read(path) != graph.canonical_bytes(_derived(original, value["declaration"], declaration["policies"], declaration.get(traffic.FIELD))):
            raise ValueError("whole graph capture amendment pruned or changed an original occurrence/DAG/header")
        expected.append({**row, "capture_manifest": rolling._ref(path)})
    if value["workloads"] != expected:
        raise ValueError("whole graph amendment closure changed its complete derived workload inventory")
    return {**value, "modes": declaration["modes"], "runtime": declaration["runtime"], "policies": declaration["policies"],
        **({traffic.FIELD: declaration[traffic.FIELD], "traffic_artifacts": declaration["traffic_artifacts"]} if traffic.FIELD in declaration else {})}


def publish_amendment(enrollment: Path, runtime: Mapping[str, str], output: Path, *, front_policy=None, buflo_policy=None, buflo_duration_policy=None) -> Path:
    selected = old.policies(front_policy=front_policy, buflo_policy=buflo_policy,
                            buflo_duration_policy=buflo_duration_policy)
    duration = traffic.policy(buflo_duration_policy)
    if duration and old._modes(selected) != ["buflo"]:
        raise ValueError("whole graph fixed BuFLO200 amendment authorizes only BuFLO")
    runtime = rolling._runtime(dict(runtime))
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    study = rolling._open_ref(batch["policy"]).parent
    output = output.absolute()
    declaration_path = output.with_name(output.stem + "-declaration.json")
    if (runtime["data_root"] != policy["runtime"]["data_root"] or not output.is_relative_to(study) or ".." in output.parts
            or any(path.exists() or path.is_symlink() for path in (output, declaration_path))):
        raise ValueError("whole graph amendment needs fresh create-only files under the original study")
    rows = _rows(enrollment, runtime, batch, classes)
    if any(Path(row["capture_manifest_path"]).exists() or Path(row["capture_manifest_path"]).is_symlink() for row in rows):
        raise ValueError("whole graph amendment never replaces an original or previous workload")
    payload = {"contract": capture_contract(duration), "original_data_role": whole.ROLE,
        "original_data_roles": sorted({row["original_data_role"] for row in rows}), "capture_data_role": capture_role(duration),
        "policies": selected, "modes": old._modes(selected), "enrollment": rolling._ref(enrollment),
        "admission_provenance": rolling._ref(Path(batch["admission_root"]) / "provenance.json"), "runtime": runtime,
        "runtime_artifacts": {key: rolling._ref(Path(runtime[key])) for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher")},
        "authority_sources": _sources(runtime, duration), "workloads": rows, "receipt_path": str(output),
        "published_at": old.receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0}
    if duration:
        payload.update({traffic.FIELD: duration, "traffic_artifacts": traffic.artifacts(runtime, duration)})
    rolling._write(declaration_path, DECLARATION_TYPE, payload)
    reference = rolling._ref(declaration_path)
    captured = []
    for row in rows:
        original = lanes._load(lanes._read(rolling._open_ref(row["original_manifest"])))
        old.receipts.durable_create(Path(row["capture_manifest_path"]), graph.canonical_bytes(_derived(original, reference, selected, duration)))
        captured.append({**row, "capture_manifest": rolling._ref(Path(row["capture_manifest_path"]))})
    rolling._write(output, RECEIPT_TYPE, {"contract": payload["contract"], "declaration": reference, "workloads": captured,
        "published_at": old.receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0})
    validate_amendment(output, enrollment=enrollment, runtime=runtime)
    return output


def validate_preparation(value: Mapping[str, Any], resources: list[dict]) -> dict:
    if not is_amended(value):
        raise ValueError("mixed whole graph capture role is absent")
    declaration = _declaration(prep.open_reference(value.get(old.FIELD)))
    amendment = validate_amendment(Path(declaration["receipt_path"]))
    actual = graph.canonical_bytes({"preparation": value, "resources": resources})
    matches = [row for row in amendment["workloads"] if graph.canonical_bytes(_derived(
        lanes._load(lanes._read(prep.open_reference(row["original_manifest"]))), amendment["declaration"], declaration["policies"], declaration.get(traffic.FIELD))) == actual]
    if len(matches) != 1:
        raise ValueError("mixed capture preparation changed its admitted whole graph or prospective setting")
    original = lanes._load(lanes._read(prep.open_reference(matches[0]["original_manifest"])))
    validator = whole.validate_preparation if whole.is_whole(original["preparation"]) else prep.validate_static_preparation
    return validator(original["preparation"], original["resources"])


def preparation_inputs(value: Mapping[str, Any]) -> tuple[set[Path], set[Path]]:
    """Bind this mixed declaration and complete raw evidence, never its parent."""
    declaration_path = prep.open_reference(value[old.FIELD])
    declaration = _declaration(declaration_path)
    receipt_path = Path(declaration["receipt_path"])
    closed = validate_amendment(receipt_path)
    enrollment = rolling._open_ref(declaration["enrollment"])
    files, trees = whole.terminal_inputs(enrollment)
    files.update({declaration_path, receipt_path, enrollment,
                  rolling._open_ref(declaration["admission_provenance"])})
    for reference in declaration["runtime_artifacts"].values():
        files.add(rolling._open_ref(reference))
    for reference in declaration.get("traffic_artifacts", {}).values():
        files.add(rolling._open_ref(reference))
    for row in closed["workloads"]:
        path = prep.open_reference(row["original_manifest"])
        files.add(path)
        files.add(prep.open_reference(row["original_terminal"]))
        files.add(prep.open_reference(row["capture_manifest"]))
        original = lanes._load(lanes._read(path))
        if whole.is_whole(original["preparation"]):
            raw_files, raw_trees = whole.preparation_inputs(original["preparation"])
            files.update(raw_files)
            trees.update(raw_trees)
        else:
            # The original GET remains a complete sealed raw tree. Namespace
            # parents provide transport and may contain other operations;
            # bind their four authenticated records individually instead.
            evidence = original["preparation"]["static_get_evidence"]
            trees.add(Path(evidence["root"]))
            files.add(prep.open_reference(evidence["proof"]))
            original_proof = lanes._load(lanes._read(prep.open_reference(evidence["proof"])))
            files.add(prep.open_reference(original_proof["context"]))
            if evidence["namespace"] is not None:
                files.update(prep.open_reference(evidence["namespace"][key]) for key in
                    ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    batch = rolling.admission._unpack(lanes._read(enrollment), rolling.ENROLLMENT_TYPE)
    policy_path = rolling._open_ref(batch["policy"])
    policy = rolling.verify_policy(policy_path.parent)
    files.add(policy_path)
    for key in ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"):
        files.add(rolling._open_ref(policy[key]))
    for runtime in (declaration["runtime"], policy["runtime"]):
        trees.update(Path(runtime[key]) for key in ("runtime_source_root", "module_root"))
        files.update(Path(runtime[key]) for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    from .static_evidence_transport import _path
    for path in files:
        _path(path)
    for path in trees:
        _path(path, directory=True)
    return files, trees


def preparation_roots(value: Mapping[str, Any]) -> list[Path]:
    declaration_path = prep.open_reference(value[old.FIELD])
    declaration = _declaration(declaration_path)
    roots = {declaration_path.parent}
    enrollment = rolling._open_ref(declaration["enrollment"])
    files, trees = whole.terminal_inputs(enrollment)
    roots.update(path.parent for path in files)
    roots.update(trees)
    for row in declaration["workloads"]:
        path = prep.open_reference(row["original_manifest"])
        original = lanes._load(lanes._read(path))
        roots.add(path.parent)
        roots.update(whole.preparation_roots(original["preparation"]) if whole.is_whole(original["preparation"]) else prep.preparation_roots(original["preparation"]))
    for runtime in (declaration["runtime"], rolling.verify_policy(rolling._open_ref(
            rolling.admission._unpack(lanes._read(enrollment), rolling.ENROLLMENT_TYPE)["policy"]).parent)["runtime"]):
        roots.update(Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
        roots.update(Path(runtime[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    return sorted(roots)
