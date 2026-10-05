"""Append-only selected membership with explicit, immutable per-class limits.

The retained V1 enrollment and scientific slots keep their exact identities.
Only the selected flight tail is checked for homogeneous limits; no policy
rewrites an earlier class budget or makes unfinished membership a global gate.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from . import rapid_additive_static_enrollment as old
from . import rapid_selected_capture_input as plain
from . import rapid_selected_budget_input as selected_budget
from . import rapid_rolling_capture as rolling
from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as receipts
from . import supplied_static_budget_successor as budget
from . import supplied_static_graph as graph

POLICY_TYPE = "qcsd-prospective-per-class-selected-enrollment-policy-v1"
ENROLLMENT_TYPE = "qcsd-prospective-per-class-selected-enrollment-batch-v1"
CONTRACT = "carried-selected-classes-plus-explicit-per-class-budget-admissions-v1"
ROLE = "selected-complete-graph-per-class-budget-ledger-v1"
POLICY_FIELDS = {"contract", "data_role", "seed_enrollment", "seed_policy", "seed_classes", "seed_progress",
    "seed_batch_ordinal", "admission_identity", "runtime", "runtime_source_manifest", "client_binary", "base_launcher", "host_launcher",
    "implementation_sources", "published_at", "canonical_site_rule", "selection_rule", "capture_limits", "class_target", "modes",
    "visits_per_class_mode", "formal_trace_target", "maximum_batch_size", "visits_per_lane_workload",
    "global_shakedown_required", "complete_membership_before_first_lane_required", "scientific_credit", "formal_accepted_trace_count"}
BATCH_FIELDS = old.BATCH_FIELDS


def policy_kind(root: Path) -> bool:
    return lanes._load(lanes._read(root / "policy.json")).get("receipt_type") == POLICY_TYPE


def enrollment_kind(path: Path) -> bool:
    return lanes._load(lanes._read(path)).get("receipt_type") == ENROLLMENT_TYPE


def _sources():
    return {module.__name__: graph.digest(lanes._read(Path(module.__file__))) for module in
        (old, plain, selected_budget, __import__(__name__, fromlist=["_"]))}


def valid_limits(value: Any) -> dict:
    expected = [budget.static.capture_limits(16 * 1024 * 1024, 64),
                budget.static.capture_limits(budget.RESPONSE_BYTES, budget.RECORDING_MEGABYTES)]
    if (not isinstance(value, dict) or set(value) != set(expected[0])
            or any(type(value[key]) is not int for key in value) or value not in expected):
        raise ValueError("per-class limits require exact original16/64 or prospective64/256 settings")
    return dict(value)


def input_metadata(ref: Mapping[str, Any]) -> tuple[dict, dict]:
    kind = lanes._load(lanes._read(plain.reopen(ref))).get("receipt_type")
    if kind == plain.RECEIPT_TYPE:
        return old.input_metadata(ref)
    if kind == selected_budget.RECEIPT_TYPE:
        return selected_budget.input_metadata(ref)
    raise ValueError("per-class ledger refuses an unknown selected input authority")


def input_module(ref: Mapping[str, Any]):
    kind = lanes._load(lanes._read(plain.reopen(ref))).get("receipt_type")
    if kind == plain.RECEIPT_TYPE:
        return plain
    if kind == selected_budget.RECEIPT_TYPE:
        return selected_budget
    raise ValueError("per-class capture refuses an unknown selected input type")


def _seed(path: Path) -> tuple[dict, list[dict], dict]:
    if not old.enrollment_kind(path):
        raise ValueError("per-class successor needs the exact authentic selected V1 seed ledger")
    batch, classes, policy = old.verify_enrollment(path)
    limits = valid_limits(policy["capture_limits"])
    return batch, [{**deepcopy(row), "capture_limits": dict(limits)} for row in classes], policy


def initialize(root: Path, *, seed_enrollment: Path, seed_progress: Mapping[str, Any], runtime: Mapping[str, str]) -> Path:
    root = lanes._regular_directory(root)
    if any(root.iterdir()):
        raise ValueError("per-class successor requires a fresh empty policy namespace")
    batch, classes, policy = _seed(seed_enrollment)
    old._progress(lanes._load(lanes._read(plain.reopen(seed_progress))), classes)
    actual_runtime = rolling._runtime(dict(runtime))
    if not root.is_relative_to(Path(actual_runtime["data_root"])):
        raise ValueError("per-class policy leaves its declared runtime data scope")
    payload = {"contract": CONTRACT, "data_role": ROLE, "seed_enrollment": rolling._ref(seed_enrollment),
        "seed_policy": batch["policy"], "seed_classes": classes, "seed_progress": dict(seed_progress),
        "seed_batch_ordinal": batch["ordinal"], "admission_identity": policy["admission_identity"],
        "runtime": actual_runtime, "implementation_sources": _sources(), "published_at": receipts._now(),
        "canonical_site_rule": old.SITE_RULE, "selection_rule": old.SELECTION_RULE,
        "capture_limits": dict(policy["capture_limits"]), "class_target": 50, "modes": list(rolling.plan.MODES),
        "visits_per_class_mode": 64, "formal_trace_target": 16000, "maximum_batch_size": 5,
        "visits_per_lane_workload": 4, "global_shakedown_required": False,
        "complete_membership_before_first_lane_required": False, "scientific_credit": False, "formal_accepted_trace_count": 0}
    for key in ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"):
        payload[key] = rolling._ref(Path(actual_runtime["source_manifest" if key == "runtime_source_manifest" else key]))
    return rolling._write(root / "policy.json", POLICY_TYPE, payload)


def verify_policy(root: Path) -> dict:
    root = lanes._regular_directory(root)
    value = receipts._unpack(lanes._read(root / "policy.json"), POLICY_TYPE)
    rolling._keys(value, POLICY_FIELDS, "per-class selected policy")
    exact = {"contract": CONTRACT, "data_role": ROLE, "implementation_sources": _sources(),
        "canonical_site_rule": old.SITE_RULE, "selection_rule": old.SELECTION_RULE, "class_target": 50,
        "modes": list(rolling.plan.MODES), "visits_per_class_mode": 64, "formal_trace_target": 16000,
        "maximum_batch_size": 5, "visits_per_lane_workload": 4, "global_shakedown_required": False,
        "complete_membership_before_first_lane_required": False, "scientific_credit": False, "formal_accepted_trace_count": 0}
    if any(type(value[key]) is not type(expected) or value[key] != expected for key, expected in exact.items()):
        raise ValueError("per-class policy changes its prospective contract or executing Source")
    batch, classes, policy = _seed(rolling._open_ref(value["seed_enrollment"]))
    if (value["seed_policy"] != batch["policy"] or value["seed_classes"] != classes
            or type(value["seed_batch_ordinal"]) is not int or value["seed_batch_ordinal"] != batch["ordinal"]
            or value["admission_identity"] != policy["admission_identity"] or value["capture_limits"] != policy["capture_limits"]
            or not receipts._utc(batch["declared_at"]) <= receipts._utc(value["published_at"]) <= receipts._utc(receipts._now())):
        raise ValueError("per-class successor renumbers, replaces or changes a retained seed")
    old._progress(lanes._load(lanes._read(plain.reopen(value["seed_progress"]))), classes)
    runtime = rolling._runtime(value["runtime"])
    if not root.is_relative_to(Path(runtime["data_root"])):
        raise ValueError("per-class policy leaves its actual runtime scope")
    for key in ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"):
        if rolling._open_ref(value[key]) != Path(runtime["source_manifest" if key == "runtime_source_manifest" else key]):
            raise ValueError("per-class policy changes a runtime artifact")
    return value


def _old_policy(policy):
    return old.verify_policy(rolling._open_ref(policy["seed_policy"]).parent)


def _context_metadata(policy: dict, path: Path, *, _files: set[Path] | None = None) -> dict:
    raw = lanes._load(lanes._read(path))
    previous = _old_policy(policy)
    if raw.get("receipt_type") != budget.CONTEXT_TYPE:
        return old._context_metadata(previous, path, _files=_files)
    value = receipts._unpack(lanes._read(path), budget.CONTEXT_TYPE)
    original_path = rolling._open_ref(value["original_context"])
    baseline = old._context_metadata(previous, original_path, _files=_files)
    active_path = rolling._open_ref(value["prospective_context"])
    active = receipts._unpack(lanes._read(active_path), budget.static.PROVENANCE_TYPE)
    if (value["contract"] != budget.CONTRACT or value["data_role"] != budget.ROLE
            or not budget.refs.zero(value) or value["capture_limits"] != valid_limits(budget.static.capture_limits(budget.RESPONSE_BYTES, budget.RECORDING_MEGABYTES))
            or active["candidates"] != baseline["candidates"]
            or value["original_identity"] != previous["admission_identity"]
            or active["source_sha256"] != baseline["source_sha256"]
            or active["runtime_binding"] != baseline["runtime_binding"]
            or active["parent_context"] is not None or active["inherited_terminals"] != []):
        raise ValueError("per-class budget declaration replaces the genuine original reservations")
    if _files is not None:
        _files.update({path.absolute(), original_path, active_path})
    return {**active, "declared_at": value["declared_at"]}


def _chosen(policy: dict, provenance: Any, input_ref: Any, manifest_ref: Any) -> tuple[dict, dict]:
    context = _context_metadata(policy, rolling._open_ref(provenance))
    value, audited = input_metadata(input_ref)
    module = input_module(input_ref)
    limits = valid_limits(value["capture_limits"])
    candidate = next((row for row in context["candidates"] if row["candidate_id"] == value["candidate_id"]), None)
    if candidate is None or candidate != audited["candidate"] or audited["context"] != provenance:
        raise ValueError("per-class selection is not an actually admitted declared reservation")
    manifest_path = plain.reopen(manifest_ref)
    manifest = lanes._load(lanes._read(manifest_path))
    expected = lanes._load(lanes._read(plain.reopen(value["original_manifest"])))
    field = "selected_input_evidence" if module is plain else selected_budget.FIELD
    expected["preparation"].update(data_role=module.ROLE, **{field: {"schema_version": 1, "record_type": module.RECEIPT_TYPE, "receipt": dict(input_ref)}})
    if manifest != expected or manifest_path.stem != value["workload_id"]:
        raise ValueError("per-class manifest replaces its original full graph or policies")
    terminal = audited["terminal"]
    rolling._open_ref(terminal)
    chosen = {"candidate_id": value["candidate_id"], "terminal": terminal, "admission_root": str(Path(provenance["path"]).parent),
        "class_index": 0, "primary_origin": rolling.origin(manifest["preparation"]["final_url"]), "workload_id": value["workload_id"],
        "canonical_sites": value["canonical_sites"], "capture_input": dict(input_ref), "prepared_workload": dict(manifest_ref), "capture_limits": limits}
    decision = {"position": candidate["position"], "candidate_id": value["candidate_id"], "outcome": "admitted",
        "terminal": terminal, "capture_input": dict(input_ref), "prepared_workload": dict(manifest_ref)}
    return decision, chosen


def _batches(root: Path, policy: dict) -> list[Path]:
    return old._batches(root, policy)


def _verify_enrollment_uncached(path: Path) -> tuple[dict, list[dict], dict]:
    value = receipts._unpack(lanes._read(path), ENROLLMENT_TYPE)
    rolling._keys(value, BATCH_FIELDS, "per-class selected enrollment")
    root = rolling._open_ref(value["policy"]).parent
    policy = verify_policy(root)
    ordinal = value["ordinal"]
    if (type(ordinal) is not int or path.absolute() != rolling._batch_path(root, ordinal)
            or value["scientific_credit"] is not False or value["selection_rule"] != old.SELECTION_RULE):
        raise ValueError("per-class enrollment namespace or rule changed")
    if ordinal == policy["seed_batch_ordinal"] + 1:
        if value["parent"] is not None or value["seed"] != policy["seed_enrollment"]:
            raise ValueError("per-class first batch lost its authentic eleven-class predecessor")
        previous, earliest = list(policy["seed_classes"]), policy["published_at"]
    else:
        if value["seed"] is not None or rolling._open_ref(value["parent"]) != rolling._batch_path(root, ordinal - 1):
            raise ValueError("per-class enrollment skips its immediate predecessor")
        parent, previous, _ = verify_enrollment(rolling._open_ref(value["parent"]))
        earliest = parent["declared_at"]
    if (type(value["first_class_index"]) is not int or value["first_class_index"] != len(previous) + 1
            or not receipts._utc(earliest) <= receipts._utc(value["declared_at"]) <= receipts._utc(receipts._now())
            or Path(value["admission_root"]) != rolling._open_ref(value["admission_provenance"]).parent
            or not isinstance(value["decisions"], list) or not 1 <= len(value["decisions"]) <= 5):
        raise ValueError("per-class membership numbering, declaration or selected count changed")
    chosen, positions = [], []
    for row in value["decisions"]:
        rolling._keys(row, {"position", "candidate_id", "outcome", "terminal", "capture_input", "prepared_workload"}, "per-class decision")
        expected, item = _chosen(policy, value["admission_provenance"], row["capture_input"], row["prepared_workload"])
        data, _ = input_metadata(row["capture_input"])
        if row != expected or receipts._utc(data["declared_at"]) > receipts._utc(value["declared_at"]):
            raise ValueError("per-class decision changed its genuine admission or chronology")
        item["class_index"] = len(previous) + len(chosen) + 1
        chosen.append(item)
        positions.append(row["position"])
    classes = previous + chosen
    old._deduplicate(classes)
    select_classes(value, classes, policy)
    context = _context_metadata(policy, rolling._open_ref(value["admission_provenance"]))
    pending = [{"position": row["position"], "candidate_id": row["candidate_id"], "assessment": "unassessed-by-this-ledger"}
        for row in context["candidates"] if row["candidate_id"] not in {item["candidate_id"] for item in classes}]
    if (positions != sorted(set(positions)) or value["selected_candidate_ids"] != [row["candidate_id"] for row in chosen]
            or type(value["last_candidate_position"]) is not int or value["last_candidate_position"] != positions[-1]
            or value["unassessed_reservations"] != pending):
        raise ValueError("per-class batch changes reservation order or fabricates an assessment")
    return value, classes, policy


def verify_enrollment(path: Path) -> tuple[dict, list[dict], dict]:
    """Reuse exact metadata membership only inside the owning action."""
    from .rapid_operation_facts import current_context
    context = current_context()
    if context is None:
        return _verify_enrollment_uncached(path)
    raw = context.watch_file(path)
    key = ("per-class-enrollment", str(path.absolute()), lanes._sha(raw))
    if context.has(key):
        return context.get(key)
    context._enrollment(path)
    result = _verify_enrollment_uncached(path)
    context.check()
    return context.remember(key, result)


def select_classes(batch: Mapping[str, Any], classes: list[dict], policy: Mapping[str, Any]) -> tuple[list[dict], dict]:
    if policy["contract"] != CONTRACT:
        raise ValueError("per-class selector requires its explicit policy")
    ids = batch["selected_candidate_ids"]
    rows = classes[-len(ids):]
    if not isinstance(ids, list) or not 1 <= len(ids) <= 5 or [row["candidate_id"] for row in rows] != ids:
        raise ValueError("per-class flight changed its immutable selected tail")
    caps = [valid_limits(row["capture_limits"]) for row in rows]
    if any(value != caps[0] for value in caps):
        raise ValueError("per-class capture must group only identical per-class budgets")
    return deepcopy(rows), dict(caps[0])


def enroll(root: Path, *, acquisition_root: Path, inputs: Mapping[str, Any], prepared_workloads: Mapping[str, Any]) -> Path:
    policy = verify_policy(root)
    if not 1 <= len(inputs) <= 5 or set(inputs) != set(prepared_workloads):
        raise ValueError("per-class batch needs one to five complete selected inputs/manifests")
    batches = _batches(root, policy)
    ordinal, previous = policy["seed_batch_ordinal"] + 1, list(policy["seed_classes"])
    parent, seed = None, policy["seed_enrollment"]
    if batches:
        prior, previous, _ = verify_enrollment(batches[-1])
        ordinal, parent, seed = prior["ordinal"] + 1, rolling._ref(batches[-1]), None
    provenance = rolling._ref(acquisition_root / "provenance.json")
    context = _context_metadata(policy, rolling._open_ref(provenance))
    decisions, chosen = [], []
    for candidate_id, input_ref in inputs.items():
        input_module(input_ref).validate_input(plain.reopen(input_ref))
        decision, row = _chosen(policy, provenance, input_ref, prepared_workloads[candidate_id])
        if row["candidate_id"] != candidate_id:
            raise ValueError("per-class input map changes its admitted candidate")
        decisions.append(decision)
        chosen.append(row)
    decisions.sort(key=lambda row: row["position"])
    by_id = {row["candidate_id"]: row for row in chosen}
    chosen = [by_id[row["candidate_id"]] for row in decisions]
    for index, row in enumerate(chosen, len(previous) + 1):
        row["class_index"] = index
    classes = previous + chosen
    old._deduplicate(classes)
    draft = {"selected_candidate_ids": [row["candidate_id"] for row in chosen]}
    select_classes(draft, classes, policy)  # refuse mixed limits before a write
    pending = [{"position": row["position"], "candidate_id": row["candidate_id"], "assessment": "unassessed-by-this-ledger"}
        for row in context["candidates"] if row["candidate_id"] not in {item["candidate_id"] for item in classes}]
    payload = {"policy": rolling._ref(root / "policy.json"), "ordinal": ordinal, "parent": parent, "seed": seed,
        "decisions": decisions, "selected_candidate_ids": draft["selected_candidate_ids"], "first_class_index": len(previous) + 1,
        "last_candidate_position": decisions[-1]["position"], "admission_root": str(acquisition_root), "admission_provenance": provenance,
        "unassessed_reservations": pending, "selection_rule": old.SELECTION_RULE, "declared_at": receipts._now(), "scientific_credit": False}
    output = rolling._batch_path(root, ordinal)
    rolling._write(output, ENROLLMENT_TYPE, payload)
    verify_enrollment(output)
    return output


def membership_inputs(path: Path) -> set[Path]:
    # Dependency selection precedes the action memo's first proof. Calling
    # the public wrapper here would recursively request its own binding.
    batch, classes, policy = _verify_enrollment_uncached(path)
    files = old.membership_inputs(rolling._open_ref(policy["seed_enrollment"]))
    files.update({path.absolute(), rolling._open_ref(batch["policy"]), plain.reopen(policy["seed_progress"])})
    files.update(rolling._open_ref(policy[key]) for key in
        ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"))
    cursor = batch
    while cursor["parent"] is not None:
        parent = rolling._open_ref(cursor["parent"])
        files.add(parent)
        cursor = receipts._unpack(lanes._read(parent), ENROLLMENT_TYPE)
    for row in classes[len(policy["seed_classes"]):]:
        value, audited = input_metadata(row["capture_input"])
        files.update({plain.reopen(row["capture_input"]), plain.reopen(row["prepared_workload"]), plain.reopen(value["original_manifest"]),
            rolling._open_ref(audited["terminal"]), rolling._open_ref(audited["context"])})
        _context_metadata(policy, rolling._open_ref(audited["context"]), _files=files)
        audit_path = plain.reopen(value["selection_audit"])
        if input_module(row["capture_input"]) is plain:
            files.update(plain.audit_inputs(audit_path))
        else:
            audit = selected_budget.read_audit(audit_path)
            files.add(audit_path)
            files.update(plain.reopen(audit[key]) for key in ("started", "completed", "stdout", "stderr", "source_inventory"))
    return files


def preparation_inputs(value: Mapping[str, Any], resources: list[dict]) -> tuple[set[Path], set[Path]]:
    if plain.is_selected(value):
        return plain.preparation_inputs(value, resources)
    if selected_budget.is_selected(value):
        return selected_budget.preparation_inputs(value, resources)
    raise ValueError("per-class preparation has no supported selected role")


def preparation_roots(value: Mapping[str, Any], resources: list[dict]) -> list[Path]:
    if plain.is_selected(value):
        return plain.preparation_roots(value, resources)
    if selected_budget.is_selected(value):
        return selected_budget.preparation_roots(value, resources)
    raise ValueError("per-class transport has no supported selected role")


def enrollment_roots(spec) -> list[Path]:
    batch, classes, policy = verify_enrollment(spec.cohort)
    payload = receipts._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
    if (payload["bindings"]["cohort_sha256"] != lanes._sha(lanes._read(spec.cohort))
            or policy["runtime"]["data_root"] != str(spec.data_root) or Path(batch["admission_root"]) != spec.acquisition_root):
        raise ValueError("per-class transport changes its membership/runtime")
    roots = {path.parent for path in membership_inputs(spec.cohort)}
    runtime = payload["runtime"]
    roots.update(Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
    roots.update(Path(runtime[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    rows, _ = select_classes(batch, classes, policy)
    for row in rows:
        manifest = lanes._load(lanes._read(plain.reopen(row["prepared_workload"])))
        roots.update(preparation_roots(manifest["preparation"], manifest["resources"]))
    for root in roots:
        lanes._regular_directory(root)
        if any(char in str(root) for char in ("\n", "\r", "\0", ":")):
            raise ValueError("per-class roots require canonical regular same-absolute paths")
    return sorted(roots)
