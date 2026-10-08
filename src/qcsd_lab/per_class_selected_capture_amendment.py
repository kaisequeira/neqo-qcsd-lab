"""Prospective fixed FRONT/BuFLO settings for selected complete GET inputs.

The immutable enrollment and original GET labels remain unchanged. A fresh
current selected-input receipt may reprove the same retained raw GET; it grants
no additional admission or trace credit. Derived manifests change only the
explicit capture policy and this new, separately typed preparation role.
"""
from __future__ import annotations

from copy import deepcopy
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping

from . import rapid_per_class_selected_enrollment as additive
from . import rapid_capture_traffic as traffic
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_per_class_selected_input as selected
from . import supplied_static_capture_amendment as old
from . import supplied_static_graph as graph

DECLARATION_TYPE = "qcsd-per-class-selected-graph-capture-policy-declaration-v1"
RECEIPT_TYPE = "qcsd-per-class-selected-graph-capture-policy-amendment-v1"
CONTRACT = "unchanged-per-class-selected-graphs-with-fixed-front-or-buflo-policy-v1"
ROLE = "per-class-selected-graph-amended-capture-preparation-v1"
DURATION_ROLE = "per-class-selected-graph-amended-buflo200-preparation-v1"
ADAPTER_FILES = {name: "src/qcsd_lab/" + name + ".py" for name in (
    "per_class_selected_capture_amendment", "rapid_per_class_selected_input", "rapid_per_class_selected_enrollment",
    "rapid_selected_budget_input", "rapid_selected_capture_input", "rapid_additive_static_enrollment",
    "rapid_rolling_capture", "rapid_rolling_readiness", "rapid_operation_facts")}
DECLARATION_FIELDS = old.DECLARATION_FIELDS | {"renewals", "capture_limits", "traffic_artifacts"}
ROW_FIELDS = old.ROW_FIELDS | {"current_selected_input", "current_selected_manifest", "class_index"}


CADENCE64_ROLE = "per-class-selected-graph-amended-buflo-cadence64-budget640-preparation-v1"
CADENCE64_CONTRACT = "unchanged-per-class-selected-graphs-with-fixed-buflo-cadence64-budget640-setting-v1"


def capture_role(duration: str | None) -> str:
    selected = traffic.policy(duration)
    return CADENCE64_ROLE if selected == traffic.budget.CADENCE64_POLICY else DURATION_ROLE if selected else ROLE


def capture_contract(duration: str | None) -> str:
    selected = traffic.policy(duration)
    return CADENCE64_CONTRACT if selected == traffic.budget.CADENCE64_POLICY else CONTRACT


def is_amended(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("data_role") in {ROLE, DURATION_ROLE, CADENCE64_ROLE}


def is_receipt(path: Path) -> bool:
    return lanes._load(lanes._read(path)).get("receipt_type") == RECEIPT_TYPE


def authority_files(duration_policy: str | None = None) -> dict[str, str]:
    return {**old.authority_files(duration_policy), **ADAPTER_FILES}


def _sources(runtime: Mapping[str, str], duration_policy: str | None) -> dict[str, str]:
    files = authority_files(duration_policy)
    current = {name: graph.digest(lanes._read(Path(import_module("qcsd_lab." + name).__file__))) for name in files}
    for key in ("runtime_source_root", "module_root"):
        if any(graph.digest(lanes._read(Path(runtime[key]) / relative)) != current[name] for name, relative in files.items()):
            raise ValueError("selected amendment authority differs from its current installed/frozen Source")
    return current


def _enrolled(batch, classes, policy) -> list[dict]:
    if policy["contract"] != additive.CONTRACT:
        raise ValueError("selected capture amendment requires its additive selected enrollment")
    rows = classes[-len(batch["selected_candidate_ids"]):]
    if not 1 <= len(rows) <= 5 or [row["candidate_id"] for row in rows] != batch["selected_candidate_ids"]:
        raise ValueError("selected amendment changed its complete enrolled tail or order")
    return rows


def _original(row: Mapping[str, Any]) -> tuple[dict, dict]:
    """Authenticate old metadata; current raw proof is supplied by the renewal."""
    path = selected.reopen(row["prepared_workload"])
    original = lanes._load(lanes._read(path))
    if not selected.is_selected(original.get("preparation")) or path.stem != row["workload_id"]:
        raise ValueError("selected amendment original capture role or workload changed")
    receipt_ref = selected.receipt_ref(original["preparation"])
    value, _ = additive.input_metadata(receipt_ref)
    genuine = lanes._load(lanes._read(selected.reopen(value["original_manifest"])))
    genuine = selected.wrap(genuine, receipt_ref)
    if (original != genuine or value["candidate_id"] != row["candidate_id"]
        or value["workload_id"] != row["workload_id"] or value["canonical_sites"] != row["canonical_sites"]
        or row.get("capture_input") is not None and row["capture_input"] != receipt_ref):
        raise ValueError("selected amendment cannot replace a class, original graph or audited admission")
    return original, value


def metadata_inputs(enrollment: Path, batch, classes, policy) -> tuple[set[Path], set[Path]]:
    """Authenticate enrollment metadata without treating old validators as current."""
    from .rapid_operation_facts import OperationFacts
    context = OperationFacts()
    for path in additive.membership_inputs(enrollment):
        context.watch_file(path)
    for row in _enrolled(batch, classes, policy):
        original, previous = _original(row)
        context.watch_file(selected.reopen(row["prepared_workload"]))
        for path in selected.audit_inputs(selected.reopen(previous["selection_audit"])):
            context.watch_file(path)
    roots = {Path(policy["runtime"][key]) for key in ("runtime_source_root", "module_root")}
    for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
        context.watch_file(Path(policy["runtime"][key]))
    for relative, _ in traffic.files().values():
        context.watch_file(Path(policy["runtime"]["execution_root"]) / relative)
    return set(context._files), roots


def _rows(batch, classes, policy, runtime, renewals) -> list[dict]:
    enrolled = _enrolled(batch, classes, policy)
    rolling._keys(renewals, {row["candidate_id"] for row in enrolled}, "selected amendment renewal map")
    rows = []
    for row in enrolled:
        original, previous = _original(row)
        renewal = renewals[row["candidate_id"]]
        rolling._keys(renewal, {"input", "manifest"}, "selected amendment renewal")
        receipt_path = selected.reopen(renewal["input"])
        current, baseline, _ = selected.validate_input(receipt_path)
        path = selected.reopen(renewal["manifest"])
        manifest = lanes._load(lanes._read(path))
        selected.validate_preparation(manifest["preparation"], manifest["resources"])
        expected = deepcopy(baseline)
        expected = selected.wrap(expected, renewal["input"])
        if (manifest != expected or manifest["resources"] != original["resources"]
            or path.stem != row["workload_id"] or current["candidate_id"] != row["candidate_id"]
            or any(current[key] != previous[key] for key in (
                "original_manifest", "original_role", "workload_id", "canonical_sites", "selection_audit",
                "raw_root", "raw_inventory", "proof", "declaration", "namespace", "neutral", "approved_origins",
                "capture_limits", "measurement_runtime", "recorded_producer_sources"))
            or current["capture_limits"] != additive.select_classes(batch, classes, policy)[1]
            or {key: manifest["preparation"].get(key) for key in old.ORIGINAL_POLICIES} != old.ORIGINAL_POLICIES):
            raise ValueError("selected amendment renewal changes its original raw GET, graph, request, caps or policy")
        target = Path(runtime["workload_root"]) / path.name
        if target in {path, selected.reopen(row["prepared_workload"])}:
            raise ValueError("selected amendment must preserve original/current selected manifests")
        rows.append({"candidate_id": row["candidate_id"], "workload_id": row["workload_id"],
            "class_index": row["class_index"], "original_terminal": row["terminal"],
            "original_manifest": {key: row["prepared_workload"][key] for key in ("path", "sha256")},
            "original_get_proof": {key: current["proof"][key] for key in ("path", "sha256")},
            "current_selected_input": dict(renewal["input"]), "current_selected_manifest": dict(renewal["manifest"]),
            "original_capture_policies": dict(old.ORIGINAL_POLICIES),
            "resource_records_sha256": graph.digest(graph.canonical_bytes(manifest["resources"])),
            "capture_manifest_path": str(target)})
    return rows


def _derived(original, reference, policies, duration):
    if not selected.is_selected(original.get("preparation")):
        raise ValueError("selected amendment needs its current complete selected preparation")
    value = deepcopy(original)
    value["preparation"].update(data_role=capture_role(duration),
        **{old.FIELD: dict(reference)}, **dict(policies))
    old.capture.validate_front_preparation_policy(value["preparation"])
    old.capture.validate_buflo_kernel_preparation_policy(value["preparation"])
    return value


def _declaration(path: Path, *, enrollment=None, runtime=None) -> dict:
    value = old.receipts._unpack(lanes._read(path), DECLARATION_TYPE)
    duration = traffic.policy(value.get(traffic.FIELD))
    fields = set(DECLARATION_FIELDS) | ({traffic.FIELD} if duration else set())
    rolling._keys(value, fields, "selected capture declaration")
    policies = old._policies(value["policies"], buflo_duration_policy=duration)
    modes = old._modes(policies)
    actual_runtime = rolling._runtime(value["runtime"])
    actual_enrollment = rolling._open_ref(value["enrollment"])
    batch, classes, policy = rolling._verify_enrollment(actual_enrollment)
    rows = _rows(batch, classes, policy, actual_runtime, value["renewals"])
    study = rolling._open_ref(batch["policy"]).parent
    if (value["contract"] != capture_contract(duration) or value["original_data_role"] != selected.ROLE
        or value["capture_data_role"] != (capture_role(duration))
        or len(modes) != 1 or value["modes"] != modes
        or modes == ["buflo"] and duration not in {traffic.budget.POLICY, traffic.budget.CADENCE64_POLICY}
        or modes == ["front"] and duration is not None
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False
        or enrollment is not None and actual_enrollment != enrollment.absolute()
        or runtime is not None and actual_runtime != rolling._runtime({key: runtime[key] for key in rolling.RUNTIME_FIELDS})
        or actual_runtime["data_root"] != policy["runtime"]["data_root"]
        or value["admission_provenance"] != batch["admission_provenance"]
        or graph.canonical_bytes(value["workloads"]) != graph.canonical_bytes(rows)
        or graph.canonical_bytes(value["capture_limits"]) != graph.canonical_bytes(additive.select_classes(batch, classes, policy)[1])
        or value["authority_sources"] != _sources(actual_runtime, duration)
        or value["traffic_artifacts"] != _traffic_artifacts(actual_runtime, duration)
        or value["runtime_artifacts"] != {key: rolling._ref(Path(actual_runtime[key])) for key in (
            "source_manifest", "client_binary", "base_launcher", "host_launcher")}
        or not path.is_relative_to(study) or not Path(value["receipt_path"]).is_relative_to(study)
        or not old.receipts._utc(batch["declared_at"]) <= old.receipts._utc(value["published_at"]) <= old.receipts._utc(old.receipts._now())):
        raise ValueError("selected declaration changes its class/order/raw/Source/profile/caps or fixed setting")
    for row in rows:
        rolling._keys(row, ROW_FIELDS, "selected amendment workload")
        input_value = selected.payload(selected.reopen(row["current_selected_input"]))
        if old.receipts._utc(input_value["declared_at"]) > old.receipts._utc(value["published_at"]):
            raise ValueError("selected current input was published after its capture declaration")
    return value


def _traffic_artifacts(runtime, duration):
    result = {}
    for key, (relative, digest) in traffic.files(duration).items():
        path = Path(runtime["runtime_source_root"]) / relative
        if graph.digest(lanes._read(path)) != digest or lanes._read(Path(runtime["module_root"]) / relative) != lanes._read(path):
            raise ValueError("selected capture setting changed its fixed profile or parameters")
        result[key] = rolling._ref(path)
    return result


def validate_amendment(path: Path, *, enrollment=None, runtime=None) -> dict:
    value = old.receipts._unpack(lanes._read(path), RECEIPT_TYPE)
    rolling._keys(value, old.RECEIPT_FIELDS, "selected capture amendment")
    declaration = _declaration(rolling._open_ref(value["declaration"]), enrollment=enrollment, runtime=runtime)
    if (value["contract"] != declaration["contract"] or Path(declaration["receipt_path"]) != path.absolute()
        or value["scientific_credit"] is not False or type(value["formal_accepted_trace_count"]) is not int
        or value["formal_accepted_trace_count"] != 0
        or not old.receipts._utc(declaration["published_at"]) <= old.receipts._utc(value["published_at"]) <= old.receipts._utc(old.receipts._now())):
        raise ValueError("selected amendment closure changed its contract, publication or credit")
    rows = []
    for row in declaration["workloads"]:
        current = lanes._load(lanes._read(selected.reopen(row["current_selected_manifest"])))
        target = Path(row["capture_manifest_path"])
        if lanes._read(target) != graph.canonical_bytes(_derived(current, value["declaration"], declaration["policies"], declaration.get(traffic.FIELD))):
            raise ValueError("selected amended manifest changes a full resource graph or undeclared preparation field")
        rows.append({**row, "capture_manifest": rolling._ref(target)})
    if graph.canonical_bytes(value["workloads"]) != graph.canonical_bytes(rows):
        raise ValueError("selected amendment changed its complete manifest inventory")
    return {**value, "modes": declaration["modes"], "runtime": declaration["runtime"],
        "policies": declaration["policies"], "capture_limits": declaration["capture_limits"],
        "traffic_artifacts": declaration["traffic_artifacts"],
        **({traffic.FIELD: declaration[traffic.FIELD]} if traffic.FIELD in declaration else {})}


def publish_amendment(enrollment: Path, runtime: Mapping[str, str], output: Path, *,
                      front_policy=None, buflo_policy=None, buflo_duration_policy=None) -> Path:
    policies = old.policies(front_policy=front_policy, buflo_policy=buflo_policy,
                            buflo_duration_policy=buflo_duration_policy)
    duration = traffic.policy(buflo_duration_policy)
    modes = old._modes(policies)
    if len(modes) != 1 or modes == ["buflo"] and duration not in {traffic.budget.POLICY, traffic.budget.CADENCE64_POLICY} or modes == ["front"] and duration is not None:
        raise ValueError("selected amendment needs one explicit FRONT V4 or fixed BuFLO200 setting")
    runtime = rolling._runtime(dict(runtime))
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    enrolled = _enrolled(batch, classes, policy)
    study = rolling._open_ref(batch["policy"]).parent
    output = output.absolute()
    declaration = output.with_name(output.stem + "-declaration.json")
    inputs_root = output.with_name(output.stem + "-current-inputs")
    if (runtime["data_root"] != policy["runtime"]["data_root"] or not output.is_relative_to(study)
        or any(path.is_symlink() for path in (output, *output.parents, inputs_root, *inputs_root.parents))
        or any(path.exists() or path.is_symlink() for path in (output, declaration, inputs_root))
        or any(path.exists() or path.is_symlink() for row in enrolled
               for path in [(Path(runtime["workload_root"]) / (row["workload_id"] + ".json"))])):
        raise ValueError("selected amendment requires create-only outputs, preserving all previous attempts")
    source = _sources(runtime, duration)
    artifacts = _traffic_artifacts(runtime, duration)
    inputs_root.mkdir(mode=0o700)
    from .util import fsync_directory
    fsync_directory(inputs_root)
    fsync_directory(inputs_root.parent)
    renewals = {}
    for row in enrolled:
        _, previous = _original(row)
        old_input = selected.receipt_ref(lanes._load(lanes._read(selected.reopen(row["prepared_workload"]))) ["preparation"])
        if previous["direct_validator_sources"] == selected.current_sources(old_input):
            selected.validate_input(selected.reopen(old_input))
            renewals[row["candidate_id"]] = {"input": dict(old_input), "manifest": dict(row["prepared_workload"])}
        else:
            new_input = inputs_root / (row["workload_id"] + "-input.json")
            selected.publish_input(new_input, audit=selected.reopen(previous["selection_audit"]), candidate_id=row["candidate_id"])
            new_manifest = inputs_root / (row["workload_id"] + ".json")
            selected.prepare_input(new_input, new_manifest)
            renewals[row["candidate_id"]] = {"input": selected.reference(new_input), "manifest": selected.reference(new_manifest)}
    rows = _rows(batch, classes, policy, runtime, renewals)
    value = {"contract": capture_contract(duration), "original_data_role": selected.ROLE,
        "capture_data_role": capture_role(duration), "policies": policies, "modes": modes,
        "enrollment": rolling._ref(enrollment), "admission_provenance": batch["admission_provenance"],
        "runtime": dict(runtime), "runtime_artifacts": {key: rolling._ref(Path(runtime[key])) for key in (
            "source_manifest", "client_binary", "base_launcher", "host_launcher")},
        "authority_sources": source, "traffic_artifacts": artifacts, "capture_limits": additive.select_classes(batch, classes, policy)[1],
        "renewals": renewals, "workloads": rows, "receipt_path": str(output),
        "published_at": old.receipts._now(), "formal_accepted_trace_count": 0, "scientific_credit": False}
    if duration:
        value[traffic.FIELD] = duration
    rolling._write(declaration, DECLARATION_TYPE, value)
    ref = rolling._ref(declaration)
    captured = []
    for row in rows:
        current = lanes._load(lanes._read(selected.reopen(row["current_selected_manifest"])))
        target = Path(row["capture_manifest_path"])
        old.receipts.durable_create(target, graph.canonical_bytes(_derived(current, ref, policies, duration)))
        captured.append({**row, "capture_manifest": rolling._ref(target)})
    rolling._write(output, RECEIPT_TYPE, {"contract": value["contract"], "declaration": ref, "workloads": captured,
        "published_at": old.receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0})
    validate_amendment(output, enrollment=enrollment, runtime=runtime)
    return output


def validate_preparation(value: Mapping[str, Any], resources: list[dict]) -> dict:
    if not is_amended(value):
        raise ValueError("selected amended capture role is absent")
    declaration = _declaration(rolling._open_ref(value.get(old.FIELD)))
    amendment = validate_amendment(Path(declaration["receipt_path"]))
    actual = graph.canonical_bytes({"preparation": value, "resources": resources})
    matching = [row for row in amendment["workloads"] if graph.canonical_bytes(_derived(
        lanes._load(lanes._read(selected.reopen(row["current_selected_manifest"]))),
        amendment["declaration"], declaration["policies"], declaration.get(traffic.FIELD))) == actual]
    if len(matching) != 1:
        raise ValueError("selected capture preparation differs from its exact graph/policy declaration")
    return selected.validate_input(selected.reopen(matching[0]["current_selected_input"]))[2]


def preparation_inputs(value: Mapping[str, Any]) -> tuple[set[Path], set[Path]]:
    declaration_path = rolling._open_ref(value[old.FIELD])
    declaration = _declaration(declaration_path)
    receipt_path = Path(declaration["receipt_path"])
    validate_amendment(receipt_path)
    files, trees = {declaration_path, receipt_path, rolling._open_ref(declaration["enrollment"])}, set()
    batch, classes, policy = rolling._verify_enrollment(rolling._open_ref(declaration["enrollment"]))
    files.update(rolling._open_ref(ref) for ref in declaration["runtime_artifacts"].values())
    files.update(rolling._open_ref(ref) for ref in declaration["traffic_artifacts"].values())
    files.add(rolling._open_ref(batch["policy"]))
    # Exact metadata refs are immutable inputs; no shared evidence parent tree.
    metadata_files, metadata_trees = metadata_inputs(rolling._open_ref(declaration["enrollment"]), batch, classes, policy)
    files.update(metadata_files)
    trees.update(metadata_trees)
    for row in declaration["workloads"]:
        files.update({rolling._open_ref(row["original_manifest"]), selected.reopen(row["current_selected_manifest"])})
        current = lanes._load(lanes._read(selected.reopen(row["current_selected_manifest"])))
        own_files, own_trees = selected.preparation_inputs(current["preparation"], current["resources"])
        files.update(own_files)
        trees.update(own_trees)
    for key in ("runtime_source_root", "module_root"):
        trees.add(Path(declaration["runtime"][key]))
    return files, trees


def preparation_roots(value: Mapping[str, Any]) -> list[Path]:
    files, trees = preparation_inputs(value)
    roots = set(trees) | {path.parent for path in files}
    declaration = _declaration(rolling._open_ref(value[old.FIELD]))
    _, _, policy = rolling._verify_enrollment(rolling._open_ref(declaration["enrollment"]))
    roots.add(Path(policy["runtime"]["execution_root"]))
    return sorted(root for root in roots if not any(root != parent and root.is_relative_to(parent) for parent in roots))


def enrollment_roots(spec) -> list[Path]:
    """Transport this typed amendment's renewed raw input and sealed ledger."""
    payload = old.receipts._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
    batch, _, policy = rolling._verify_enrollment(spec.cohort)
    if (payload["bindings"]["cohort_sha256"] != graph.digest(lanes._read(spec.cohort))
        or Path(batch["admission_root"]) != spec.acquisition_root
        or policy["runtime"]["data_root"] != str(spec.data_root)
        or "scheduling" in payload):
        raise ValueError("selected amended transport changes its serial enrollment or runtime")
    amendment = validate_amendment(rolling._open_ref(payload["static_capture_amendment"]),
                                  enrollment=spec.cohort, runtime=spec.serializable())
    roots = set()
    for row in amendment["workloads"]:
        manifest = lanes._load(lanes._read(rolling._open_ref(row["capture_manifest"])))
        roots.update(preparation_roots(manifest["preparation"]))
    runtime = payload["runtime"]
    roots.update(Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
    roots.update(Path(runtime[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    for root in roots:
        lanes._regular_directory(root)
        if any(char in str(root) for char in ("\n", "\r", "\0", ":")):
            raise ValueError("selected amended transport requires canonical regular absolute roots")
    return sorted(roots)
