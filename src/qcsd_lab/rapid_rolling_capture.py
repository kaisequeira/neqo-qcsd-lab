"""Prospective rolling formal capture, independent of unfinished membership.

Admission keeps its original source role and complete-page rules. Immutable
enrollment batches contain one to five sites; a later batch cannot alter a
previous decision, workload, qualifier, lane or visit. The final corpus still
requires fifty sites, five settings and exactly sixty-four visits per setting.
"""

from __future__ import annotations

import json
import secrets
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from . import rapid_capture_plan as plan
from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as admission
from .chaff_qualification import RESPONSE_ONLY_QUALIFICATION_SCOPE
from .response_budget_qualification import validate_named_qualification_set_manifest
from .discover import origin

POLICY_TYPE = "qcsd-rapid-v6-rolling-formal-policy"
STATIC_POLICY_TYPE = "qcsd-rapid-v6-supplied-static-rolling-formal-policy-v1"
STATIC_CONTRACT = "first-fifty-ordered-complete-fixed-resource-get-admissions-v1"
ENROLLMENT_TYPE = "qcsd-rapid-v6-immutable-enrollment-batch"
RUNTIME_TYPE = "qcsd-rapid-v6-rolling-runtime-inputs"
CORPUS_TYPE = "qcsd-rapid-v6-complete-rolling-corpus"
LANE_CHECK_TYPE = "qcsd-rapid-v6-installed-lane-deep-check"
CONTRACT = "first-fifty-ordered-admissions-in-immutable-one-to-five-site-batches-v1"
RUNTIME_FIELDS = lanes.RUNTIME_KEYS | {"data_root", "workload_root", "campaign_dir", "execution_generation"}


def _keys(value: Any, fields: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields differ")


def _ref(path: Path) -> dict[str, str]:
    path = Path(path).absolute()
    return {"path": str(path), "sha256": lanes._sha(lanes._read(path))}


def _open_ref(value: Any) -> Path:
    _keys(value, {"path", "sha256"}, "rolling reference")
    if not isinstance(value["path"], str) or not Path(value["path"]).is_absolute():
        raise ValueError("rolling references require absolute regular paths")
    path = Path(value["path"])
    if lanes._sha(lanes._read(path)) != value["sha256"]:
        raise ValueError("rolling referenced bytes changed")
    return path


def _write(path: Path, kind: str, payload: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    admission.durable_create(path, admission._json(admission._bind(kind, payload)))
    return path


def _runtime(value: Any) -> dict[str, str]:
    _keys(value, RUNTIME_FIELDS, "rolling runtime")
    if any(not isinstance(item, str) or not item for item in value.values()):
        raise ValueError("rolling runtime values require nonempty strings")
    for key in RUNTIME_FIELDS - {"collection_image_digest", "execution_generation"}:
        path = Path(value[key])
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("rolling runtime paths require explicit absolute locations")
        if key in {"data_root", "runtime_source_root", "module_root", "execution_root", "workload_root", "campaign_dir"}:
            lanes._regular_directory(path)
        else:
            lanes._read(path)
    if plan.IMAGE_RE.fullmatch(value["collection_image_digest"]) is None or plan.IDENTIFIER_RE.fullmatch(value["execution_generation"]) is None:
        raise ValueError("rolling runtime image or generation is invalid")
    execution = Path(value["execution_root"])
    data = Path(value["data_root"])
    if (not execution.is_relative_to(data) or Path(value["host_launcher"]) != execution / "qcsd-lab"
        or not Path(value["campaign_dir"]).is_relative_to(execution)
        or Path(value["workload_root"]) != Path(value["campaign_dir"]).parent / "workloads"
        or lanes._read(Path(value["base_launcher"])) != lanes._read(Path(value["runtime_source_root"]) / "qcsd-lab")):
        raise ValueError("rolling runtime changes the actual capture layout or launcher")
    lanes._study_profile(execution)
    for relative, digest in lanes.TRAFFIC_FILES.values():
        if lanes._sha(lanes._read(execution / relative)) != digest:
            raise ValueError("rolling capture changes fixed traffic settings")
    source = lanes._load(lanes._read(Path(value["source_manifest"])))
    if (set(source) != lanes.SOURCE_METADATA_KEYS or source["lab_dirty"] is not False
        or source["neqo_dirty"] is not False or source["neqo_commit"] != source["neqo_pinned_commit"]):
        raise ValueError("rolling capture requires clean separately bound source")
    return dict(value)


def _write_spec(path: Path, spec: lanes.CaptureSpec) -> None:
    lanes._check_spec(spec)
    admission.durable_create(path, admission._json({"schema_version": 1,
        "artifact_type": "qcsd-rapid-v6-rolling-capture-spec", "inputs": spec.serializable()}))


def load_runtime(path: Path) -> dict[str, str]:
    value = lanes._load(lanes._read(path))
    _keys(value, {"schema_version", "artifact_type", "inputs"}, "rolling runtime spec")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["artifact_type"] != RUNTIME_TYPE:
        raise ValueError("rolling runtime spec identity differs")
    inputs = dict(value["inputs"])
    for key in RUNTIME_FIELDS - {"collection_image_digest", "execution_generation"}:
        if key in inputs and isinstance(inputs[key], str):
            target = Path(inputs[key])
            inputs[key] = str(target.absolute() if target.is_absolute() else (path.absolute().parent / target).absolute())
    return _runtime(inputs)


def _admission_identity(context) -> dict[str, str]:
    from . import static_budget_capture as budget_capture
    from . import supplied_static_budget_successor as budget
    if isinstance(context, (budget.Context, budget_capture.Context)):
        return budget_capture.identity(context)
    from . import supplied_static_admission as static
    from . import whole_graph_supplement as whole
    if isinstance(context, whole.Context):
        return whole.identity(context)
    if isinstance(context, static.Context):
        return static.identity(context)
    if context.selection_amendment_revision != 12:
        raise ValueError("rolling capture requires the explicitly prepared V12 traffic policies")
    return {"profile_sha256": lanes._sha(context.profile_bytes),
            "source_sha256": lanes._sha(context.source_bytes),
            "catalogue_sha256": lanes._sha(context.catalogue_bytes),
            "selection_amendment_sha256": context.selection_amendment_sha256,
            "candidate_order_sha256": lanes._sha(admission._json(list(context.candidates)))}


def _context_for_policy(policy: Mapping[str, Any], root: Path):
    if policy["contract"] == STATIC_CONTRACT:
        from . import static_budget_capture as budget_capture
        from . import supplied_static_budget_successor as budget
        if budget_capture.is_context(root):
            return budget_capture.load_context(root)
        if budget.is_context(root):
            return budget.load_context(root)
        from . import whole_graph_supplement as whole
        if whole.is_context(root):
            return whole.load_context(root)
        from .supplied_static_admission import load_context
        return load_context(root)
    return admission.load_admission_context(root)


def _verify_terminal(context, path: Path):
    from . import static_budget_capture as budget_capture
    from . import supplied_static_budget_successor as budget
    if isinstance(context, (budget.Context, budget_capture.Context)):
        return budget_capture.verify_terminal(path, context)
    from . import supplied_static_admission as static
    from . import whole_graph_supplement as whole
    if isinstance(context, whole.Context):
        return whole.verify_terminal(path, context)
    return static.verify_terminal(path, context) if isinstance(context, static.Context) else admission.verify_site_terminal(path, context)


def _static_context_limits(context):
    from . import static_budget_capture as budget_capture
    from . import supplied_static_budget_successor as budget
    if isinstance(context, (budget.Context, budget_capture.Context)):
        return budget_capture.context_limits(context)
    from . import whole_graph_supplement as whole
    from .supplied_static_admission import context_limits
    return whole.context_limits(context) if isinstance(context, whole.Context) else context_limits(context)


def initialize_study(acquisition_root: Path, root: Path, runtime: Mapping[str, str], *, supplied_static: bool = False) -> Path:
    if type(supplied_static) is not bool:
        raise ValueError("static rolling opt-in must be boolean")
    root = lanes._regular_directory(root)
    runtime = _runtime(dict(runtime))
    if any(root.iterdir()) or not root.is_relative_to(Path(runtime["data_root"])):
        raise ValueError("rolling study needs an empty directory under its explicit data root")
    contract = STATIC_CONTRACT if supplied_static else CONTRACT
    context = _context_for_policy({"contract": contract}, acquisition_root)
    payload = {"contract": contract, "admission_identity": _admission_identity(context),
               "initial_admission_root": str(context.root), "runtime": runtime,
               "runtime_source_manifest": _ref(Path(runtime["source_manifest"])),
               "client_binary": _ref(Path(runtime["client_binary"])),
               "base_launcher": _ref(Path(runtime["base_launcher"])),
               "host_launcher": _ref(Path(runtime["host_launcher"])),
               "published_at": admission._now(), "class_target": 50,
               "modes": list(plan.MODES), "visits_per_class_mode": 64,
               "formal_trace_target": 16000, "maximum_batch_size": 5,
               "visits_per_lane_workload": 4, "global_shakedown_required": False,
               "complete_membership_before_first_lane_required": False,
               "formal_accepted_trace_count": 0, "scientific_credit": False}
    if supplied_static:
        from .supplied_static_preparation import ROLE
        payload["data_role"] = ROLE
        payload["capture_limits"] = _static_context_limits(context)
    return _write(root / "policy.json", STATIC_POLICY_TYPE if supplied_static else POLICY_TYPE, payload)


def verify_policy(root: Path) -> dict[str, Any]:
    root = lanes._regular_directory(root)
    raw = lanes._read(root / "policy.json")
    kind = lanes._load(raw).get("receipt_type")
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    if kind == per_class.POLICY_TYPE:
        return per_class.verify_policy(root)
    if kind == additive.POLICY_TYPE:
        return additive.verify_policy(root)
    if kind not in (POLICY_TYPE, STATIC_POLICY_TYPE):
        raise ValueError("rolling policy has an unknown scientific data role")
    value = admission._unpack(raw, kind)
    fields = {"contract", "admission_identity", "initial_admission_root", "runtime",
                 "runtime_source_manifest", "client_binary", "base_launcher", "host_launcher",
                 "published_at", "class_target", "modes", "visits_per_class_mode",
                 "formal_trace_target", "maximum_batch_size", "visits_per_lane_workload",
                 "global_shakedown_required", "complete_membership_before_first_lane_required",
                 "formal_accepted_trace_count", "scientific_credit"}
    contract = STATIC_CONTRACT if kind == STATIC_POLICY_TYPE else CONTRACT
    if kind == STATIC_POLICY_TYPE:
        from .supplied_static_preparation import ROLE
        fields.add("data_role")
        fields.add("capture_limits")
        if value.get("data_role") != ROLE:
            raise ValueError("static rolling policy changed its fixed-resource claim")
    _keys(value, fields, "rolling policy")
    exact = {"contract": contract, "class_target": 50, "modes": list(plan.MODES),
             "visits_per_class_mode": 64, "formal_trace_target": 16000,
             "maximum_batch_size": 5, "visits_per_lane_workload": 4,
             "global_shakedown_required": False, "complete_membership_before_first_lane_required": False,
             "formal_accepted_trace_count": 0, "scientific_credit": False}
    if any(type(value[key]) is not type(expected) or value[key] != expected for key, expected in exact.items()):
        raise ValueError("rolling policy changes its prospective scientific contract")
    runtime = _runtime(value["runtime"])
    if not root.is_relative_to(Path(runtime["data_root"])) or admission._utc(value["published_at"]) > admission._utc(admission._now()):
        raise ValueError("rolling policy root or publication time differs")
    for key, runtime_key in (("runtime_source_manifest", "source_manifest"), ("client_binary", "client_binary"),
                             ("base_launcher", "base_launcher"), ("host_launcher", "host_launcher")):
        if _open_ref(value[key]) != Path(runtime[runtime_key]):
            raise ValueError("rolling policy runtime reference was relocated or replaced")
    initial = _context_for_policy(value, Path(value["initial_admission_root"]))
    if _admission_identity(initial) != value["admission_identity"]:
        raise ValueError("rolling policy admission inputs changed")
    if kind == STATIC_POLICY_TYPE:
        if value["capture_limits"] != _static_context_limits(initial):
            raise ValueError("static rolling policy changed its prospectively declared capture budgets")
    return value


def _batch_path(root: Path, ordinal: int) -> Path:
    if type(ordinal) is not int or not 1 <= ordinal <= 50:
        raise ValueError("rolling batch ordinal is outside one to fifty")
    return root / "batches" / f"b{ordinal:04d}" / "enrollment.json"


def _batches(root: Path) -> list[Path]:
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    if per_class.policy_kind(root):
        return per_class._batches(root, per_class.verify_policy(root))
    if additive.policy_kind(root):
        return additive._batches(root, additive.verify_policy(root))
    directory = root / "batches"
    if not directory.exists():
        return []
    lanes._regular_directory(directory)
    children = sorted(directory.iterdir())
    paths = [_batch_path(root, ordinal) for ordinal in range(1, len(children) + 1)]
    if [path.parent for path in paths] != children or any(not path.is_file() or path.is_symlink() for path in paths):
        raise ValueError("rolling batch namespace contains a hole or an unfinished claim")
    return paths


def _terminal_row(context, position: int, reference: Mapping[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    if not 1 <= position <= len(context.candidates):
        raise ValueError("rolling decision position is outside the frozen order")
    path = _open_ref(reference)
    from . import static_budget_capture as budget_capture
    from . import supplied_static_budget_successor as budget
    from . import supplied_static_admission as static
    from . import whole_graph_supplement as whole
    if isinstance(context, (budget.Context, budget_capture.Context)):
        if path != budget_capture.terminal_path(context, position):
            raise ValueError("rolling budget terminal differs from its immutable declared context")
    elif isinstance(context, whole.Context):
        if path != whole.terminal_path(context, position):
            raise ValueError("rolling whole graph terminal differs from its original or appended immutable context")
    elif isinstance(context, static.Context):
        if path != static.terminal_path(context, position):
            raise ValueError("rolling static terminal differs from its closed original or successor context")
    elif not path.is_relative_to(context.root / "attempts"):
        raise ValueError("rolling terminal escapes its separately bound admission context")
    facts = _verify_terminal(context, path)
    candidate = context.candidates[position - 1]
    if facts["candidate_id"] != candidate["candidate_id"]:
        raise ValueError("rolling enrollment reordered or skipped a candidate decision")
    return {"position": position, "candidate_id": facts["candidate_id"],
            "outcome": facts["outcome"], "terminal": dict(reference)}, facts


def _prepared_workload(context, terminal_path: Path) -> tuple[Path, dict[str, Any]]:
    from . import static_budget_capture as budget_capture
    from . import supplied_static_budget_successor as budget
    if isinstance(context, (budget.Context, budget_capture.Context)):
        return budget_capture.prepared_workload(context, terminal_path)
    from . import supplied_static_admission as static
    from . import whole_graph_supplement as whole
    if isinstance(context, whole.Context):
        return whole.prepared_workload(context, terminal_path)
    if isinstance(context, static.Context):
        return static.prepared_workload(context, terminal_path)
    terminal = admission._unpack(lanes._read(terminal_path), admission.TERMINAL_TYPE)
    preparation = admission._unpack(lanes._read(admission._child(context.root, terminal["preparation"])), admission.PREPARATION_TYPE)
    original = admission._child(context.root, preparation["prepared_workload"])
    return original, lanes._load(lanes._read(original))


def verify_enrollment(path: Path, *, _verified: dict | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    batch, classes, _ = _verify_enrollment(path, _verified=_verified)
    return batch, classes


def _verify_enrollment(path: Path, *, _verified: dict | None = None) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    from .rapid_operation_facts import current_context
    facts_context = current_context()
    raw = lanes._read(path) if facts_context is None else facts_context.watch_file(path)
    key = ("rolling-enrollment", str(path.absolute()), lanes._sha(raw))
    if facts_context is not None:
        if facts_context.has(key):
            result, ancestry = facts_context.get(key)
            if _verified is not None:
                _verified.update(ancestry)
            return result
        facts_context._enrollment(path)
        facts_context.watch_file(Path(__file__))
    ancestry = {}
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    if lanes._load(raw).get("receipt_type") == per_class.ENROLLMENT_TYPE:
        value, classes, policy = per_class.verify_enrollment(path)
        result = (value, classes, policy)
        ancestry[path.absolute()] = (lanes._sha(raw), value, classes)
        if _verified is not None:
            _verified.update(ancestry)
        if facts_context is not None:
            facts_context.remember(key, (result, ancestry))
        return result
    if lanes._load(raw).get("receipt_type") == additive.ENROLLMENT_TYPE:
        value, classes, policy = additive.verify_enrollment(path)
        if _verified is not None:
            _verified[path.absolute()] = (lanes._sha(raw), value, classes)
        result = (value, classes, policy)
        ancestry[path.absolute()] = (lanes._sha(raw), value, classes)
        if facts_context is not None:
            facts_context.remember(key, (result, ancestry))
        return result
    value = admission._unpack(raw, ENROLLMENT_TYPE)
    _keys(value, {"policy", "ordinal", "parent", "admission_root", "admission_provenance",
                 "decisions", "selected_candidate_ids", "first_class_index", "last_candidate_position",
                 "declared_at", "scientific_credit"}, "rolling enrollment")
    policy_path = _open_ref(value["policy"])
    root = policy_path.parent
    policy = verify_policy(root)
    if path.absolute() != _batch_path(root, value["ordinal"]) or value["scientific_credit"] is not False:
        raise ValueError("rolling enrollment namespace or credit differs")
    previous: list[dict[str, Any]] = []
    first_position, first_class = 1, 1
    earliest = policy["published_at"]
    if value["ordinal"] == 1:
        if value["parent"] is not None:
            raise ValueError("initial rolling enrollment invents a predecessor")
    else:
        if _open_ref(value["parent"]) != _batch_path(root, value["ordinal"] - 1):
            raise ValueError("rolling enrollment skips or replaces its parent")
        parent, previous, _ = _verify_enrollment(_open_ref(value["parent"]),
            _verified=ancestry if facts_context is not None else _verified)
        first_position = parent["last_candidate_position"] + 1
        first_class = parent["first_class_index"] + len(parent["selected_candidate_ids"])
        earliest = parent["declared_at"]
    if (type(value["first_class_index"]) is not int or value["first_class_index"] != first_class
        or not admission._utc(earliest) <= admission._utc(value["declared_at"]) <= admission._utc(admission._now())):
        raise ValueError("rolling enrollment membership ordinal or chronology differs")
    context = _context_for_policy(policy, Path(value["admission_root"]))
    if (_admission_identity(context) != policy["admission_identity"]
        or _open_ref(value["admission_provenance"]) != context.root / "provenance.json"):
        raise ValueError("rolling enrollment changed its admission role, order or policies")
    if not isinstance(value["decisions"], list) or not value["decisions"]:
        raise ValueError("rolling enrollment needs a complete ordered terminal extension")
    selected = []
    for offset, row in enumerate(value["decisions"]):
        _keys(row, {"position", "candidate_id", "outcome", "terminal"}, "rolling decision")
        expected, facts = _terminal_row(context, first_position + offset, row["terminal"])
        if row != expected:
            raise ValueError("rolling decision differs from its reopened original evidence")
        if facts_context is not None:
            terminal_path, seen_terminals = _open_ref(row["terminal"]), set()
            while True:
                if terminal_path in seen_terminals:
                    raise ValueError("rolling terminal raw dependency lineage contains a cycle")
                seen_terminals.add(terminal_path)
                terminal = lanes._load(facts_context.watch_file(terminal_path))["payload"]
                retained_get = terminal.get("get_evidence_root")
                if retained_get is not None:
                    facts_context.watch_tree(Path(retained_get))
                if terminal.get("original_terminal") is None:
                    break
                terminal_path = _open_ref(terminal["original_terminal"])
        if facts["outcome"] == "admitted":
            workload_path, workload = _prepared_workload(context, _open_ref(row["terminal"]))
            if facts_context is not None:
                facts_context.watch_file(workload_path)
                if isinstance(workload.get("preparation"), Mapping) and "data_role" in workload["preparation"]:
                    for evidence_root in facts_context._workload_evidence_trees(workload_path):
                        facts_context.watch_tree(evidence_root)
            selected.append({"candidate_id": facts["candidate_id"], "terminal": row["terminal"],
                             "admission_root": str(context.root), "class_index": first_class + len(selected),
                             "primary_origin": origin(workload["preparation"]["final_url"]),
                             "workload_id": workload_path.stem})
    if (not 1 <= len(selected) <= 5 or first_class + len(selected) - 1 > 50
        or value["selected_candidate_ids"] != [row["candidate_id"] for row in selected]
        or type(value["last_candidate_position"]) is not int
        or value["last_candidate_position"] != first_position + len(value["decisions"]) - 1
        or value["decisions"][-1]["outcome"] != "admitted"):
        raise ValueError("rolling batch must end at its first one to five ordered admissions")
    if set(value["selected_candidate_ids"]) & {row["candidate_id"] for row in previous}:
        raise ValueError("rolling enrollment repeats an earlier class")
    classes = previous + selected
    if len({row["primary_origin"] for row in classes}) != len(classes):
        raise ValueError("rolling enrollment repeats an earlier class's primary origin")
    if len({row["workload_id"] for row in classes}) != len(classes):
        raise ValueError("rolling enrollment repeats an earlier class's workload identity")
    _effective_capture_limits(value, classes, policy)
    ancestry[path.absolute()] = (lanes._sha(raw), value, classes)
    if _verified is not None:
        _verified.update(ancestry)
    result = (value, classes, policy)
    if facts_context is not None:
        facts_context.remember(key, (result, ancestry))
    return result


def enroll(root: Path, *, acquisition_root: Path | None = None, count: int = 1) -> Path:
    policy = verify_policy(root)
    if type(count) is not int or not 1 <= count <= 5:
        raise ValueError("rolling enrollment count must be one to five")
    existing = _batches(root)
    ordinal, first_position, first_class, parent = 1, 1, 1, None
    if existing:
        old, chosen = verify_enrollment(existing[-1])
        ordinal, first_position, first_class = old["ordinal"] + 1, old["last_candidate_position"] + 1, len(chosen) + 1
        parent = _ref(existing[-1])
    if first_class + count - 1 > 50:
        raise ValueError("rolling enrollment cannot exceed fifty classes")
    context = _context_for_policy(policy, acquisition_root or Path(policy["initial_admission_root"]))
    if _admission_identity(context) != policy["admission_identity"]:
        raise ValueError("rolling successor admission changed the frozen catalogue or scientific rules")
    from . import supplied_static_admission as static
    from . import whole_graph_supplement as whole
    from . import static_budget_capture as budget_capture
    from . import supplied_static_budget_successor as budget
    status = (budget_capture.acquisition_status(context) if isinstance(context, (budget.Context, budget_capture.Context))
              else whole.acquisition_status(context) if isinstance(context, whole.Context)
              else static.acquisition_status(context) if isinstance(context, static.Context) else admission.acquisition_status(context))
    decisions, selected = [], []
    for position, reference in enumerate(status["terminal_prefix"], 1):
        if position < first_position:
            continue
        terminal_reference = reference if isinstance(context, (static.Context, whole.Context, budget.Context, budget_capture.Context)) else _ref(admission._child(context.root, reference))
        row, facts = _terminal_row(context, position, terminal_reference)
        decisions.append(row)
        if facts["outcome"] == "admitted":
            selected.append(facts["candidate_id"])
        if len(selected) == count:
            break
    if len(selected) != count:
        raise ValueError("not enough new independently admitted sites for this rolling batch")
    if isinstance(context, (budget.Context, budget_capture.Context)):
        manifests = [_prepared_workload(context, _open_ref(row["terminal"]))[1]
                     for row in decisions if row["outcome"] == "admitted"]
        budget_capture.selected_capture_limits(manifests, policy["capture_limits"])
    output = _batch_path(root, ordinal)
    payload = {"policy": _ref(root / "policy.json"), "ordinal": ordinal, "parent": parent,
               "admission_root": str(context.root), "admission_provenance": _ref(context.root / "provenance.json"),
               "decisions": decisions, "selected_candidate_ids": selected, "first_class_index": first_class,
               "last_candidate_position": decisions[-1]["position"], "declared_at": admission._now(),
               "scientific_credit": False}
    _write(output, ENROLLMENT_TYPE, payload)
    verify_enrollment(output)
    return output


def _sites(enrollment: Path, qualifier_spec: Path, workload_root: Path, *, require_current: bool = False,
           front_capture_amendment: Mapping[str, Any] | None = None,
           static_capture_amendment: Mapping[str, Any] | None = None,
           runtime: Mapping[str, str] | None = None) -> tuple[plan.Site, ...]:
    batch, all_classes = verify_enrollment(enrollment)
    return _sites_from_enrollment(batch, all_classes, qualifier_spec, workload_root, require_current=require_current,
                                 enrollment=enrollment, runtime=runtime, front_capture_amendment=front_capture_amendment,
                                 static_capture_amendment=static_capture_amendment)


def _sites_from_enrollment(batch: Mapping[str, Any], all_classes: list[dict[str, Any]],
                           qualifier_spec: Path, workload_root: Path, *, require_current: bool,
                           enrollment: Path | None = None, runtime: Mapping[str, str] | None = None,
                           front_capture_amendment: Mapping[str, Any] | None = None,
                           static_capture_amendment: Mapping[str, Any] | None = None,
                           delivery_compatibility: Mapping[str, str] | None = None,
                           body_policy: str | None = None, selected_input_renewal=None,
                           enrolled_subgroup=None, _context=None) -> tuple[plan.Site, ...]:
    from . import rapid_undefended_capture as ordinary
    if ordinary.is_inputs(lanes._load(lanes._read(qualifier_spec))):
        if selected_input_renewal is not None or enrolled_subgroup is not None:
            raise ValueError("defended selected renewal or subgroup cannot authorize ordinary-only inputs")
        return ordinary.sites_from_enrollment(batch, all_classes, qualifier_spec, workload_root,
            require_current=require_current, enrollment=enrollment, runtime=runtime,
            front_capture_amendment=front_capture_amendment, static_capture_amendment=static_capture_amendment,
            delivery_compatibility=delivery_compatibility)
    classes = all_classes[-len(batch["selected_candidate_ids"]):]
    if enrolled_subgroup is not None:
        from . import rapid_enrolled_subgroup as subgroup
        if enrollment is None:
            raise ValueError("subgroup requires its original enrollment reference")
        classes = subgroup.validate(enrolled_subgroup, enrollment, batch, all_classes)
    policy = verify_policy(_open_ref(batch["policy"]).parent)
    from . import rapid_additive_static_enrollment as additive
    from .rapid_per_class_selected_enrollment import CONTRACT as PER_CLASS_CONTRACT
    selected_policy = policy["contract"] in {additive.CONTRACT, PER_CLASS_CONTRACT}
    amendment = None
    renewal = None
    if selected_input_renewal is not None:
        from . import rapid_selected_input_renewal as renewed
        if (not selected_policy or enrollment is None or runtime is None
                or front_capture_amendment is not None or static_capture_amendment is not None
                or delivery_compatibility is not None):
            raise ValueError("defended selected renewal requires its separate enrolled current runtime")
        renewal_path = _open_ref(selected_input_renewal)
        declared = lanes._load(lanes._read(renewal_path))
        renewal = renewed.validate(renewal_path, enrollment=enrollment, runtime=runtime,
            mode=declared["mode"], tamaraw_configuration_policy=declared["tamaraw_configuration_policy"])[0]
    if front_capture_amendment is not None and static_capture_amendment is not None:
        raise ValueError("browser and static capture amendments have separate authority")
    if front_capture_amendment is not None:
        if selected_policy:
            raise ValueError("selected inputs require their own prospective FRONT capture policy authority")
        if policy["contract"] == STATIC_CONTRACT:
            raise ValueError("static preparation already binds the current FRONT policy; a browser amendment cannot be imported")
        from .rapid_front_capture_amendment import _validate_for_enrollment
        if enrollment is None or runtime is None:
            raise ValueError("FRONT amendment requires this operation's verified enrollment and runtime")
        amendment = _validate_for_enrollment(_open_ref(front_capture_amendment), enrollment, runtime, batch, all_classes)
    if static_capture_amendment is not None:
        from .supplied_static_capture_amendment import validate_amendment
        if policy["contract"] != STATIC_CONTRACT and not selected_policy or enrollment is None or runtime is None:
            raise ValueError("static capture amendment requires its original static enrollment and current runtime")
        amendment = validate_amendment(_open_ref(static_capture_amendment), enrollment=enrollment, runtime=runtime)
        if selected_policy:
            from . import selected_capture_amendment as selected_amendment
            if policy["contract"] == PER_CLASS_CONTRACT:
                from . import per_class_selected_capture_amendment as selected_amendment
            if amendment["contract"] != selected_amendment.CONTRACT:
                raise ValueError("selected inputs cannot import a historical static capture amendment")
    spec = lanes._load(lanes._read(qualifier_spec))
    _keys(spec, {"schema_version", "qualification_sets"}, "rolling qualifiers")
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1 or not isinstance(spec["qualification_sets"], list) or len(spec["qualification_sets"]) != 1:
        raise ValueError("rolling batch needs one exact named response qualification set")
    q = spec["qualification_sets"][0]
    _keys(q, {"qualification_set", "manifest", "sidecar_root", "prefix_spec_root"}, "rolling qualification set")
    if q["prefix_spec_root"] is not None:
        raise ValueError("rolling capture uses fixed response-only padding, without fitting")
    def resolve(value):
        if not isinstance(value, str) or not value:
            raise ValueError("rolling qualifier path is invalid")
        p = Path(value)
        return p.absolute() if p.is_absolute() else (qualifier_spec.absolute().parent / p).absolute()
    manifest, sidecars = resolve(q["manifest"]), resolve(q["sidecar_root"])
    sites = []
    for row in classes:
        if selected_policy:
            from . import rapid_selected_capture_input as selected
            if policy["contract"] == PER_CLASS_CONTRACT:
                from . import rapid_per_class_selected_input as selected
            original = selected.reopen(renewal["renewals"][row["candidate_id"]]["manifest"] if renewal is not None else
                row["prepared_workload"] if amendment is None else
                next(item["current_selected_manifest"] for item in amendment["workloads"]
                     if item["candidate_id"] == row["candidate_id"]))
            workload = lanes._load(lanes._read(original))
            selected.validate_preparation(workload["preparation"], workload["resources"])
            facts = {"admission": {"prepared_workload_sha256": lanes._sha(lanes._read(original))}}
        else:
            context = _context_for_policy(policy, Path(row["admission_root"]))
            terminal_path = _open_ref(row["terminal"])
            facts = _verify_terminal(context, terminal_path)
            original, workload = _prepared_workload(context, terminal_path)
        if amendment is None and lanes._read(workload_root / original.name) != lanes._read(original):
            raise ValueError("rolling capture pruned or changed an admitted complete workload")
        digest = (facts["admission"]["prepared_workload_sha256"] if amendment is None
                  else next(item["capture_manifest"]["sha256"] for item in amendment["workloads"]
                            if item["candidate_id"] == row["candidate_id"]))
        sites.append(plan.Site(row["candidate_id"], original.stem, digest,
                               origin(workload["preparation"]["final_url"]), q["qualification_set"], lanes._sha(lanes._read(manifest))))
    validator = (validate_named_qualification_set_manifest if _context is None else
        lambda value, **kwargs: _context.validate_named_qualification(value, validate_named_qualification_set_manifest, **kwargs))
    if delivery_compatibility is None:
        validator(lanes._load(lanes._read(manifest)), workload_root=workload_root,
            sidecar_root=sidecars, prefix_spec_root=None, expected_qualification_set=q["qualification_set"],
            expected_workload_ids=[site.workload_id for site in sites], expected_qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
            require_current_implementation=require_current)
    else:
        from .qualification_control_authority import load_named_qualification_set
        load_named_qualification_set(manifest, delivery_compatibility=delivery_compatibility,
            body_policy=body_policy, workload_root=workload_root, sidecar_root=sidecars,
            expected_qualification_set=q["qualification_set"], prefix_spec_root=None,
            expected_workload_ids=[site.workload_id for site in sites],
            expected_qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
            require_current_implementation=require_current)
    if amendment is not None or selected_policy:
        expected_source = {**lanes._load(lanes._read(Path(runtime["source_manifest"]))),
                           "image_digest": runtime["collection_image_digest"]}
        from datetime import UTC, datetime
        published = admission._utc(renewal["published_at"] if renewal is not None else
            amendment["published_at"] if amendment is not None else policy["published_at"]) - datetime(1970, 1, 1, tzinfo=UTC)
        published_ns = (published.days * 86400 + published.seconds) * 1_000_000_000 + published.microseconds * 1000
        for site in sites:
            sidecar = lanes._load(lanes._read(sidecars / (site.workload_id + ".json")))
            if (sidecar.get("qualification_source") != expected_source
                or sidecar.get("qualification_image_digest") != runtime["collection_image_digest"]
                or sidecar.get("implementation_receipt", {}).get("neqo_qcsd_client", {}).get("sha256")
                   != lanes._sha(lanes._read(Path(runtime["client_binary"])))):
                raise ValueError("capture amendment requires fresh qualification from its bound capture runtime")
            attempts = sidecar.get("candidate_attempts")
            if not isinstance(attempts, list) or not attempts:
                raise ValueError("capture amendment requires actual prospective response qualification epochs")
            for attempt in attempts:
                epochs = attempt.get("connection_epochs") if isinstance(attempt, dict) else None
                if not isinstance(epochs, list) or not epochs:
                    raise ValueError("capture amendment requires actual prospective response qualification epochs")
                for epoch in epochs:
                    receipt = epoch.get("receipt") if isinstance(epoch, dict) else None
                    started = receipt.get("started_unix_ns") if isinstance(receipt, dict) else None
                    if type(started) is not int or started < published_ns:
                        raise ValueError("response qualification began before its prospective capture amendment")
    return plan._check_sites(sites, final=True, study_version=6)


def _bindings(enrollment: Path) -> dict[str, str]:
    _, _, policy = _verify_enrollment(enrollment)
    return _bindings_from_enrollment(enrollment, policy)


def _bindings_from_enrollment(enrollment: Path, policy: Mapping[str, Any]) -> dict[str, str]:
    return {"profile_sha256": policy["admission_identity"]["profile_sha256"],
            "cohort_sha256": lanes._sha(lanes._read(enrollment)), "study_version": "v6",
            "selection_amendment_sha256": policy["admission_identity"]["selection_amendment_sha256"]}


def _effective_capture_limits(batch, classes, policy):
    """Reopen per-class budgets without changing the original study policy."""
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    if policy["contract"] == per_class.CONTRACT:
        return per_class.select_classes(batch, classes, policy)[1]
    if policy["contract"] == additive.CONTRACT:
        return dict(policy["capture_limits"])
    if policy["contract"] != STATIC_CONTRACT:
        return None
    from . import static_budget_capture as budget_capture
    from . import supplied_static_budget_successor as budget
    root = Path(batch["admission_root"])
    if lanes._load(lanes._read(root / "provenance.json")).get("receipt_type") not in {budget.CONTEXT_TYPE, budget_capture.CONTEXT_TYPE}:
        return policy["capture_limits"]
    context = _context_for_policy(policy, root)
    selected = classes[batch["first_class_index"] - 1:]
    manifests = [_prepared_workload(context, _open_ref(row["terminal"]))[1] for row in selected]
    return budget_capture.selected_capture_limits(manifests, policy["capture_limits"])


def _render_campaign(lane: plan.Lane, sites, policy: Mapping[str, Any], *, buflo_duration_policy: str | None = None,
                     capture_limits: Mapping[str, int] | None = None,
                     application_body_identity_policy: str | None = None,
                     qualification_delivery_compatibility: Mapping[str, str] | None = None,
                     tamaraw_configuration_policy: str | None = None) -> bytes:
    from .rapid_additive_static_enrollment import CONTRACT as ADDITIVE_CONTRACT
    from .rapid_per_class_selected_enrollment import CONTRACT as PER_CLASS_CONTRACT
    return plan.render_lane_campaign(lane, sites, static_capture_limits=(
        (capture_limits if capture_limits is not None else policy["capture_limits"])
        if policy["contract"] in {STATIC_CONTRACT, ADDITIVE_CONTRACT, PER_CLASS_CONTRACT} else None),
        buflo_duration_policy=buflo_duration_policy,
        application_body_identity_policy=application_body_identity_policy,
        qualification_delivery_compatibility=qualification_delivery_compatibility,
        tamaraw_configuration_policy=tamaraw_configuration_policy if lane.mode == "tamaraw" else None)


def _static_canary_facts(facts: Mapping[str, Any], amendment: Mapping[str, Any]) -> dict[str, Any]:
    """Translate two authenticated graph encodings at the planner boundary.

    Historical canary receipts hash indented JSON; static GET amendments hash
    compact JSON. Reopen both bound manifests and check the complete historical
    canary graph before translating this temporary comparator input. Stored
    readiness, capture and amendment records retain their original bytes.
    """
    from . import supplied_static_graph as graph
    from .rapid_rolling_readiness import _encoded

    matching = [row for row in amendment["workloads"]
                if row["capture_manifest"]["sha256"] == facts.get("workload_sha256")]
    if len(matching) != 1:
        raise ValueError("static canary has no unique amendment-bound workload")
    row = matching[0]
    original = lanes._load(lanes._read(_open_ref(row["original_manifest"])))
    captured = lanes._load(lanes._read(_open_ref(row["capture_manifest"])))
    resources = original.get("resources")
    if not isinstance(resources, list) or not resources or captured.get("resources") != resources:
        raise ValueError("static canary changed its amendment-bound complete resources")
    from urllib.parse import urlsplit
    historical = {"resource_count": len(resources),
                  "resource_records_sha256": lanes._sha(_encoded(resources)),
                  "origins": sorted({f'{urlsplit(item["url"]).scheme}://{urlsplit(item["url"]).netloc}'
                                     for item in resources})}
    compact_sha = graph.digest(graph.canonical_bytes(resources))
    if facts.get("full_graph") != historical or row["resource_records_sha256"] != compact_sha:
        raise ValueError("static canary graph differs from its authenticated readiness or amendment")
    return {**facts, "full_graph": {**historical, "resource_records_sha256": compact_sha}}


def _static_measurement_runtime(scheduling, runtime, *, _context=None):
    """Select a measurement role only through the closed inspector authority."""
    if scheduling is not None:
        from . import rapid_runtime_inspector as inspector
        value = lanes._load(lanes._read(_open_ref(scheduling)))
        if inspector.is_inspected(value):
            value = inspector.validate_schedule(scheduling, runtime={key: str(runtime[key]) for key in RUNTIME_FIELDS},
                                                _context=_context)
            return {key: value["base_spec"][key] for key in RUNTIME_FIELDS}
    return runtime


def publish_plan(root: Path, enrollment: Path, qualification_spec: Path, output: Path,
                 *, readiness: Mapping[str, Any], runtime_inputs: Mapping[str, str] | None = None,
                 scheduling: Mapping[str, str] | None = None,
                 front_capture_amendment: Path | None = None,
                 static_capture_amendment: Path | None = None,
                 application_body_identity_policy: str | None = None,
                 qualification_delivery_compatibility: Mapping[str, str] | None = None,
                 tamaraw_configuration_policy: str | None = None,
                 selected_input_renewal: Path | None = None, class_indices=None, _context=None) -> Path:
    from .application_response_policy import validate_application_body_identity_policy, application_body_identity_policy as declared_body_policy, COMPLETE_APPLICATION_DELIVERY_POLICY
    body_policy = validate_application_body_identity_policy(application_body_identity_policy)
    from .tamaraw_fixed_configuration import validate_policy as validate_fixed_tamaraw_policy
    fixed_tamaraw = validate_fixed_tamaraw_policy(tamaraw_configuration_policy)
    if fixed_tamaraw is not None and (set(readiness) != {"tamaraw"} or scheduling is not None
            or front_capture_amendment is not None or static_capture_amendment is not None
            or qualification_delivery_compatibility is not None or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):
        raise ValueError("fixed Tamaraw plan requires its own current serial complete-graph canary")
    if qualification_delivery_compatibility is not None:
        from .qualification_control_authority import validate
        validate(qualification_delivery_compatibility, body_policy=body_policy)
    from .rapid_operation_facts import current_context
    _context = current_context() if _context is None else _context
    if _context is not None and current_context() is not _context:
        with _context.scope():
            return publish_plan(root, enrollment, qualification_spec, output,
                readiness=readiness, runtime_inputs=runtime_inputs, scheduling=scheduling,
                front_capture_amendment=front_capture_amendment,
                static_capture_amendment=static_capture_amendment,
                application_body_identity_policy=application_body_identity_policy,
                qualification_delivery_compatibility=qualification_delivery_compatibility,
                tamaraw_configuration_policy=tamaraw_configuration_policy,
                selected_input_renewal=selected_input_renewal, class_indices=class_indices, _context=_context)
    if _context is not None:
        _context._enrollment(enrollment)
    policy = verify_policy(root)
    batch, classes = verify_enrollment(enrollment)
    subgroup_value = None
    if class_indices is not None:
        from . import rapid_enrolled_subgroup as subgroup
        if scheduling is not None:
            raise ValueError("subgroup selection requires its prospective serial plan authority")
        subgroup_value = subgroup.declare(enrollment, batch, classes, class_indices)
    from .rapid_additive_static_enrollment import CONTRACT as ADDITIVE_CONTRACT
    from .rapid_per_class_selected_enrollment import CONTRACT as PER_CLASS_CONTRACT
    per_class_policy = policy["contract"] == PER_CLASS_CONTRACT
    selected_policy = policy["contract"] in {ADDITIVE_CONTRACT, PER_CLASS_CONTRACT}
    if per_class_policy and scheduling is not None:
        raise ValueError("per-class selected budget capture has only its prospective serial authority")
    if selected_policy and front_capture_amendment is not None:
        raise ValueError("selected-input enrollment requires its own fixed setting authority")
    if selected_policy and scheduling is not None:
        from . import rapid_selected_parallel_schedule as selected_schedule
        try:
            selected_capsule = selected_schedule.is_selected(scheduling)
        except (KeyError, TypeError, ValueError, OSError):
            selected_capsule = False
        if not selected_capsule:
            raise ValueError("selected-input enrollment has only its prospectively verified serial setting authority without a selected capsule")
    if selected_policy and static_capture_amendment is None and not set(readiness) <= {"undefended", "tamaraw", "cs-buflo"}:
        raise ValueError("selected FRONT and BuFLO require a prospective fixed capture policy declaration")
    effective_limits = _effective_capture_limits(batch, classes, policy)
    runtime = _runtime(dict(runtime_inputs)) if runtime_inputs is not None else policy["runtime"]
    if runtime["data_root"] != policy["runtime"]["data_root"]:
        raise ValueError("a rolling runtime successor must retain its declared study data root")
    if _open_ref(batch["policy"]) != root / "policy.json" or not set(readiness) <= set(plan.MODES):
        raise ValueError("rolling plan changed its policy or supplied unknown readiness")
    from . import rapid_undefended_capture as ordinary
    ordinary_only = ordinary.is_inputs(lanes._load(lanes._read(qualification_spec)))
    if ordinary_only and (subgroup_value is not None or set(readiness) != {"undefended"} or any(item is not None for item in
            (scheduling, front_capture_amendment, static_capture_amendment, qualification_delivery_compatibility))):
        raise ValueError("ordinary-only inputs require their own serial ordinary readiness")
    measurement_runtime = _static_measurement_runtime(scheduling, runtime, _context=_context)
    selected_reference = None
    if selected_input_renewal is not None:
        from . import rapid_selected_input_renewal as renewed
        if (ordinary_only or len(readiness) != 1 or scheduling is not None
                or front_capture_amendment is not None or static_capture_amendment is not None
                or qualification_delivery_compatibility is not None or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):
            raise ValueError("defended selected renewal requires one fresh qualified serial condition")
        selected_reference = _ref(selected_input_renewal)
        renewed.validate(selected_input_renewal, enrollment=enrollment, runtime=measurement_runtime,
            mode=next(iter(readiness)), tamaraw_configuration_policy=fixed_tamaraw)
    amendment_reference, amendment = None, None
    static_reference, static_amendment = None, None
    if front_capture_amendment is not None and static_capture_amendment is not None:
        raise ValueError("browser and static capture amendments cannot share a plan")
    if front_capture_amendment is not None:
        from .rapid_front_capture_amendment import validate_amendment
        if set(readiness) != {"front"}:
            raise ValueError("FRONT amendment authorizes only a freshly ready FRONT setting")
        amendment_reference = _ref(front_capture_amendment)
        amendment = validate_amendment(front_capture_amendment, enrollment=enrollment, runtime=runtime)
    if static_capture_amendment is not None:
        from .supplied_static_capture_amendment import validate_amendment
        if policy["contract"] != STATIC_CONTRACT and not selected_policy:
            raise ValueError("static capture amendment requires its static preparation authority")
        static_reference = _ref(static_capture_amendment)
        static_amendment = validate_amendment(static_capture_amendment, enrollment=enrollment, runtime=measurement_runtime)
        if selected_policy:
            from . import selected_capture_amendment as selected_amendment
            if policy["contract"] == PER_CLASS_CONTRACT:
                from . import per_class_selected_capture_amendment as selected_amendment
            if static_amendment["contract"] != selected_amendment.CONTRACT:
                raise ValueError("selected plan requires its own prospective fixed capture policy declaration")
        if not readiness or not set(readiness) <= set(static_amendment["modes"]):
            raise ValueError("static plan requires only its independently ready amended settings")
    from .rapid_rolling_readiness import validate_canary
    schedule_spec = None
    if scheduling is not None:
        from . import rapid_rolling_schedule as schedule
        capsule = schedule.validate_schedule(scheduling, runtime=runtime, _context=_context)
        from . import rapid_selected_parallel_schedule as selected_schedule
        if selected_policy:
            if (capsule["artifact_type"] != selected_schedule.CAPSULE_TYPE
                or set(readiness) != {capsule["mode"]}
                or capsule["static_capture_amendment"] != static_reference):
                raise ValueError("selected enrollment requires its current same-mode selected capsule")
        elif capsule["artifact_type"] == selected_schedule.CAPSULE_TYPE:
            raise ValueError("selected scheduling cannot replace another enrollment authority")
        from .rapid_static_parallel_schedule import require_delivery_binding
        require_delivery_binding({"application_body_identity_policy": body_policy,
            **({"qualification_delivery_compatibility": qualification_delivery_compatibility}
               if qualification_delivery_compatibility is not None else {})}, capsule)
        from . import rapid_original_static_parallel_schedule as original_static
        if capsule.get("artifact_type") == original_static.CAPSULE_TYPE:
            if (policy["contract"] != STATIC_CONTRACT or static_reference is not None
                or amendment_reference is not None or set(readiness) != {capsule["mode"]}):
                raise ValueError("original static scheduling requires only its unchanged independently ready setting")
        from . import rapid_static_parallel_schedule as static_schedule
        if capsule.get("artifact_type") == static_schedule.CAPSULE_TYPE and static_reference is None:
            raise ValueError("current static scheduling requires its explicit static amendment")
        if static_reference is not None:
            expected_type = selected_schedule.CAPSULE_TYPE if selected_policy else static_schedule.CAPSULE_TYPE
            if (capsule["artifact_type"] != expected_type
                or capsule["static_capture_amendment"] != static_reference
                or set(readiness) != {capsule["mode"]}):
                raise ValueError("static amendment requires its current same-setting scheduling capsule")
        schedule_spec = schedule._spec(capsule["base_spec"])
        if (schedule_spec.cohort != enrollment.absolute() or schedule_spec.acquisition_root != Path(batch["admission_root"])
            or _ref(qualification_spec) != capsule["qualification_spec"]):
            raise ValueError("rolling scheduled plan changes enrollment or qualified inputs")
    for mode, reference in readiness.items():
        if subgroup_value is not None:
            subgroup.require_canary(reference, subgroup_value)
        if scheduling is not None and reference.get("schema_version") == 3:
            raise ValueError("canary control witness bridge authorizes only serial original-static capture")
        if scheduling is None:
            canary_runtime = {key: runtime[key] for key in lanes.RUNTIME_KEYS}
            facts = (validate_canary(reference, runtime=canary_runtime, mode=mode)
                     if _context is None else
                     _context.validate_canary(reference, canary_runtime, mode, validate_canary))
        else:
            facts = schedule.validate_ready_canary(reference, scheduling, mode=mode,
                before=admission._now(), _context=_context)
        if amendment is not None:
            from .rapid_front_capture_amendment import require_canary
            require_canary(reference, facts, amendment_reference, amendment)
        if declared_body_policy(facts) != body_policy:
            raise ValueError("rolling plan differs from its canary's declared application body policy")
        from .tamaraw_fixed_configuration import policy as fixed_tamaraw_policy, configuration_sha256
        if (fixed_tamaraw_policy(facts) != fixed_tamaraw
            or fixed_tamaraw is not None and facts.get("tamaraw_configuration_sha256") != configuration_sha256()):
            raise ValueError("rolling plan differs from its canary's fixed Tamaraw condition")
        if facts.get("control_authority_witness", facts.get("qualification_delivery_compatibility")) != qualification_delivery_compatibility:
            raise ValueError("rolling plan differs from its canary's qualification delivery witness")
        if static_amendment is not None:
            from .supplied_static_capture_amendment import require_canary
            require_canary(reference, _static_canary_facts(facts, static_amendment),
                           static_reference, static_amendment, mode=mode)
        if selected_reference is not None:
            renewed.require_canary(reference, selected_input_renewal, mode=mode)
    workloads, campaigns = Path(runtime["workload_root"]), Path(runtime["campaign_dir"])
    from .rapid_capture_traffic import FIELD
    duration_policy = static_amendment.get(FIELD) if static_amendment is not None else None
    sites = _sites_from_enrollment(batch, classes, qualification_spec, workloads, require_current=False,
                   enrollment=enrollment, runtime=measurement_runtime,
                   front_capture_amendment=amendment_reference,
                   static_capture_amendment=static_reference,
                   delivery_compatibility=qualification_delivery_compatibility, body_policy=body_policy,
                   selected_input_renewal=selected_reference, enrolled_subgroup=subgroup_value, _context=_context)
    if ordinary_only:
        ordinary.require_canary(facts, sites)
    planned = plan.plan_lanes(sites, final=True, study_version=6, rolling_batch=batch["ordinal"])
    hashes = {}
    if _context is not None:
        _context.check()
    for lane in planned:
        path = campaigns / f"{lane.campaign_name}.yml"
        raw = _render_campaign(lane, sites, policy, buflo_duration_policy=duration_policy, capture_limits=effective_limits,
                               application_body_identity_policy=application_body_identity_policy,
                               qualification_delivery_compatibility=qualification_delivery_compatibility,
                               tamaraw_configuration_policy=fixed_tamaraw)
        if path.exists():
            if lanes._read(path) != raw:
                raise ValueError("rolling plan cannot replace an earlier campaign")
        else:
            admission.durable_create(path, raw)
        if _context is not None:
            _context.watch_file(path)
        hashes[lane.campaign_name] = lanes._sha(raw)
    payload = {"study_version": 6, "cohort_generation": "rolling-50", "bindings": _bindings(enrollment),
               "runtime": runtime, "runtime_artifacts": {key: _ref(Path(runtime[key]))
                    for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher")},
               "acquisition_provenance_sha256": _ref(Path(batch["admission_root"]) / "provenance.json")["sha256"],
               "qualification_spec_sha256": lanes._sha(lanes._read(qualification_spec)),
               "sites": [asdict(site) for site in sites], "lanes": [{**asdict(lane), "workload_ids": list(lane.workload_ids),
                  "campaign_sha256": hashes[lane.campaign_name]} for lane in planned],
               "planned_trace_count": sum(lane.sample_count for lane in planned),
               "readiness": dict(readiness), "declared_at": admission._now(),
               "formal_accepted_trace_count": 0, "scientific_credit": False}
    if subgroup_value is not None:
        payload[subgroup.FIELD] = subgroup_value
    if ordinary_only:
        payload[ordinary.FIELD] = ordinary.CONTRACT
        ordinary.require_plan(payload)
    if scheduling is not None:
        payload["scheduling"] = dict(scheduling)
        schedule.require_schedule(scheduling, lanes.CaptureSpec(**{
            key: Path(item) if key in lanes.PATH_KEYS else item for key, item in {
                **runtime, "acquisition_root": batch["admission_root"], "cohort": str(enrollment.absolute()),
                "qualification_spec": str(qualification_spec.absolute()), "plan_receipt": str(output.absolute())}.items()}),
            declared_at=payload["declared_at"], _context=_context)
    if application_body_identity_policy is not None:
        payload["application_body_identity_policy"] = body_policy
    if fixed_tamaraw is not None:
        payload["tamaraw_configuration_policy"] = fixed_tamaraw
    if selected_reference is not None:
        payload["selected_input_renewal"] = selected_reference
    if qualification_delivery_compatibility is not None:
        payload["qualification_delivery_compatibility"] = dict(qualification_delivery_compatibility)
    if amendment_reference is not None:
        payload["front_capture_amendment"] = amendment_reference
    if static_reference is not None:
        payload["static_capture_amendment"] = static_reference
        if duration_policy is not None:
            payload[FIELD] = duration_policy
    if policy["contract"] == STATIC_CONTRACT or selected_policy:
        payload["data_role"] = policy["data_role"]
        payload["capture_limits"] = effective_limits
    if _context is not None:
        _context.check()
    return _write(output, lanes.PLAN_TYPE, payload)


def capture_spec(root: Path, enrollment: Path, qualification_spec: Path, plan_receipt: Path) -> lanes.CaptureSpec:
    policy = verify_policy(root)
    batch, _ = verify_enrollment(enrollment)
    return _capture_spec_from_enrollment(root, enrollment, qualification_spec, plan_receipt, batch, policy)


def _capture_spec_from_enrollment(root: Path, enrollment: Path, qualification_spec: Path, plan_receipt: Path,
                                  batch: Mapping[str, Any], policy: Mapping[str, Any]) -> lanes.CaptureSpec:
    payload = lanes.plan_payload(lanes._read(plan_receipt))
    value = _runtime(payload["runtime"])
    if value["data_root"] != policy["runtime"]["data_root"]:
        raise ValueError("rolling capture runtime changed its declared data root")
    _keys(payload["runtime_artifacts"], {"source_manifest", "client_binary", "base_launcher", "host_launcher"}, "rolling plan runtime artifacts")
    for key, reference in payload["runtime_artifacts"].items():
        if _open_ref(reference) != Path(value[key]):
            raise ValueError("rolling plan runtime artifact changed")
    if _open_ref(batch["policy"]) != root / "policy.json":
        raise ValueError("rolling capture spec belongs to another study")
    inputs = {**value, "acquisition_root": batch["admission_root"], "cohort": str(enrollment.absolute()),
              "qualification_spec": str(qualification_spec.absolute()), "plan_receipt": str(plan_receipt.absolute())}
    return lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item for key, item in inputs.items()})


def verify_capture_plan(spec: lanes.CaptureSpec, *, require_current: bool = False, _context=None) -> tuple[tuple[plan.Site, ...], dict[str, Any]]:
    from . import rapid_quick_profile as quick
    if quick.is_plan(spec.plan_receipt):
        return quick.verify_plan(spec, _context=_context)
    from .rapid_operation_facts import current_context
    _context = current_context() if _context is None else _context
    if _context is not None and current_context() is not _context:
        # Installed qualification hooks retain their public signature. Expose
        # only this caller's live action, then restore any outer scope.
        with _context.scope():
            return verify_capture_plan(spec, require_current=require_current, _context=_context)
    # These facts live only inside this verification call. Public entry points
    # independently reopen enrollment; no prior operation supplies authority.
    key = ("capture-plan", json.dumps(spec.serializable(), sort_keys=True), require_current)
    if _context is not None:
        _context.bind_capture(spec)
        if _context.has(key):
            return _context.get(key)
    from . import rapid_epoch_target_parallel_schedule as epoch_workers
    if epoch_workers.is_plan(spec.plan_receipt):
        return epoch_workers.verify_plan(spec, require_current=require_current, _context=_context)
    from . import rapid_target_parallel_schedule as target_workers
    if target_workers.is_plan(spec.plan_receipt):
        return target_workers.verify_plan(spec, require_current=require_current, _context=_context)
    from . import rapid_target_chunks as target_chunks
    if target_chunks.is_plan(spec.plan_receipt):
        result = target_chunks.verify_plan(spec, require_current=require_current, _context=_context)
        return _context.remember(key, result) if _context is not None else result
    from . import rapid_epoch_target_chunks as epoch_chunks
    if epoch_chunks.is_plan(spec.plan_receipt):
        result = epoch_chunks.verify_plan(spec, require_current=require_current, _context=_context)
        return _context.remember(key, result) if _context is not None else result
    from . import rapid_ordinary_parallel_schedule as ordinary_parallel
    if ordinary_parallel.is_plan(spec.plan_receipt):
        return ordinary_parallel.verify_plan(spec, require_current=require_current, _context=_context)
    from . import rapid_slot_chunks as chunks
    if chunks.is_plan(spec.plan_receipt):
        result = chunks.verify_plan(spec, require_current=require_current, _context=_context)
        return _context.remember(key, result) if _context is not None else result
    batch, classes, policy = _verify_enrollment(spec.cohort)
    from .rapid_additive_static_enrollment import CONTRACT as ADDITIVE_CONTRACT
    from .rapid_per_class_selected_enrollment import CONTRACT as PER_CLASS_CONTRACT
    selected_policy = policy["contract"] in {ADDITIVE_CONTRACT, PER_CLASS_CONTRACT}
    root = _open_ref(batch["policy"]).parent
    expected_spec = _capture_spec_from_enrollment(root, spec.cohort, spec.qualification_spec, spec.plan_receipt, batch, policy)
    if spec != expected_spec:
        raise ValueError("rolling spec changed frozen runtime, admission or input locations")
    value = admission._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
    measurement_runtime = _static_measurement_runtime(value.get("scheduling"), spec.serializable(), _context=_context)
    fields = {"study_version", "cohort_generation", "bindings", "runtime", "runtime_artifacts", "acquisition_provenance_sha256",
                 "qualification_spec_sha256", "sites", "lanes", "planned_trace_count", "readiness",
                 "declared_at", "formal_accepted_trace_count", "scientific_credit"}
    from .application_response_policy import application_body_identity_policy, COMPLETE_APPLICATION_DELIVERY_POLICY
    body_policy = application_body_identity_policy(value)
    from . import rapid_enrolled_subgroup as subgroup
    subgroup_value = value.get(subgroup.FIELD)
    if subgroup.FIELD in value:
        fields.add(subgroup.FIELD)
        subgroup.validate(subgroup_value, spec.cohort, batch, classes)
        if "scheduling" in value:
            raise ValueError("subgroup has only its prospective serial plan authority")
        for reference in value["readiness"].values():
            subgroup.require_canary(reference, subgroup_value)
    from .tamaraw_fixed_configuration import policy as fixed_tamaraw_policy
    fixed_tamaraw = fixed_tamaraw_policy(value)
    selected_reference = value.get("selected_input_renewal")
    if selected_reference is not None:
        from . import rapid_selected_input_renewal as renewed
        fields.add(renewed.FIELD)
        if (len(value["readiness"]) != 1 or "scheduling" in value
                or any(key in value for key in ("static_capture_amendment", "front_capture_amendment", "qualification_delivery_compatibility"))
                or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):
            raise ValueError("defended renewed plan changed its separate serial condition")
        renewal_path = _open_ref(selected_reference)
        renewed.validate(renewal_path, enrollment=spec.cohort, runtime=measurement_runtime,
            mode=next(iter(value["readiness"])), tamaraw_configuration_policy=fixed_tamaraw)
        for mode, reference in value["readiness"].items():
            renewed.require_canary(reference, renewal_path, mode=mode)
    if fixed_tamaraw is not None:
        fields.add("tamaraw_configuration_policy")
        if (set(value["readiness"]) != {"tamaraw"} or "scheduling" in value
            or any(key in value for key in ("static_capture_amendment", "front_capture_amendment", "qualification_delivery_compatibility"))
            or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):
            raise ValueError("fixed Tamaraw plan changed its serial condition authority")
    from . import rapid_undefended_capture as ordinary
    ordinary_inputs = ordinary.is_inputs(lanes._load(lanes._read(spec.qualification_spec)))
    if ordinary_inputs != (ordinary.FIELD in value):
        raise ValueError("ordinary-only plan and input authority must be declared together")
    if ordinary_inputs:
        fields.add(ordinary.FIELD)
        ordinary.require_plan(value)
    if "application_body_identity_policy" in value:
        fields.add("application_body_identity_policy")
    if "qualification_delivery_compatibility" in value:
        fields.add("qualification_delivery_compatibility")
        from .qualification_control_authority import validate
        validate(value["qualification_delivery_compatibility"], body_policy=body_policy)
    if policy["contract"] == STATIC_CONTRACT or selected_policy:
        fields.add("data_role")
        fields.add("capture_limits")
        if value.get("data_role") != policy["data_role"] or value.get("capture_limits") != _effective_capture_limits(batch, classes, policy):
            raise ValueError("static rolling plan changed its scientific data role")
    if "scheduling" in value:
        if policy["contract"] == PER_CLASS_CONTRACT:
            raise ValueError("per-class selected budget capture has only its prospective serial authority")
        fields.add("scheduling")
        from . import rapid_rolling_schedule as schedule
        from .rapid_static_parallel_schedule import require_delivery_binding
        require_delivery_binding(value, schedule.validate_schedule(value["scheduling"],
            runtime=value["runtime"], before=value["declared_at"], _context=_context))
        from . import rapid_original_static_parallel_schedule as original_static
        if original_static.is_static(value["scheduling"]):
            original_static.require_plan(value, _context=_context)
        from . import rapid_selected_parallel_schedule as selected_schedule
        if selected_policy:
            if not selected_schedule.is_selected(value["scheduling"]):
                raise ValueError("selected plan requires its current typed selected scheduling capsule")
            selected_schedule.require_plan(value, _context=_context)
        elif selected_schedule.is_selected(value["scheduling"]):
            raise ValueError("selected scheduling changed its additive enrollment policy")
    amendment_reference, static_reference = None, None
    if "front_capture_amendment" in value:
        fields.add("front_capture_amendment")
        amendment_reference = value["front_capture_amendment"]
        _open_ref(amendment_reference)  # Explicit null is not the absent-policy branch.
        from .rapid_front_capture_amendment import _validate_for_enrollment
        amendment = _validate_for_enrollment(_open_ref(amendment_reference), spec.cohort,
                     spec.serializable(), batch, classes)
        if (not isinstance(value.get("readiness"), dict) or set(value["readiness"]) != {"front"}
            or admission._utc(amendment["published_at"]) > admission._utc(value["declared_at"])):
            raise ValueError("FRONT plan changed its prospective publication or mode authority")
    if "static_capture_amendment" in value:
        from .supplied_static_capture_amendment import validate_amendment
        fields.add("static_capture_amendment")
        static_reference = value["static_capture_amendment"]
        if policy["contract"] != STATIC_CONTRACT and not selected_policy or amendment_reference is not None:
            raise ValueError("static capture amendment has separate static authority")
        if "scheduling" in value:
            if selected_policy:
                from . import rapid_selected_parallel_schedule as selected_schedule
                selected_schedule.require_plan(value, _context=_context)
            else:
                from . import rapid_static_parallel_schedule as static_schedule
                static_schedule.require_plan(value, _context=_context)
        amendment = validate_amendment(_open_ref(static_reference), enrollment=spec.cohort, runtime=measurement_runtime)
        if selected_policy:
            from . import selected_capture_amendment as selected_amendment
            if policy["contract"] == PER_CLASS_CONTRACT:
                from . import per_class_selected_capture_amendment as selected_amendment
            if amendment["contract"] != selected_amendment.CONTRACT:
                raise ValueError("selected plan cannot import historical static capture authority")
        if (not isinstance(value.get("readiness"), dict) or not value["readiness"]
            or not set(value["readiness"]) <= set(amendment["modes"])
            or admission._utc(amendment["published_at"]) > admission._utc(value["declared_at"])):
            raise ValueError("static plan changed its prospective publication or per-setting authority")
        from .rapid_capture_traffic import FIELD, declared
        if FIELD in value:
            fields.add(FIELD)
        if value.get(FIELD) != amendment.get(FIELD) or (FIELD in value and declared(value) is None):
            raise ValueError("static plan changed its prospective BuFLO duration traffic contract")
    _keys(value, fields, "rolling plan")
    if selected_policy and (amendment_reference is not None
        or static_reference is None and not set(value["readiness"]) <= {"undefended", "tamaraw", "cs-buflo"}):
        raise ValueError("selected plan requires its own independently verified serial mode authority")
    sites = _sites_from_enrollment(batch, classes, spec.qualification_spec, spec.workload_root,
               require_current=require_current, enrollment=spec.cohort, runtime=measurement_runtime,
               front_capture_amendment=amendment_reference, static_capture_amendment=static_reference,
               delivery_compatibility=value.get("qualification_delivery_compatibility"), body_policy=body_policy,
               selected_input_renewal=selected_reference, enrolled_subgroup=subgroup_value, _context=_context)
    if (value["study_version"] != 6 or type(value["study_version"]) is not int
        or value["cohort_generation"] != "rolling-50" or value["bindings"] != _bindings_from_enrollment(spec.cohort, policy)
        or value["sites"] != [asdict(site) for site in sites]
        or value["qualification_spec_sha256"] != lanes._sha(lanes._read(spec.qualification_spec))
        or value["acquisition_provenance_sha256"] != lanes._sha(lanes._read(spec.acquisition_root / "provenance.json"))
        or value["formal_accepted_trace_count"] != 0 or type(value["formal_accepted_trace_count"]) is not int
        or value["scientific_credit"] is not False or not isinstance(value["readiness"], dict)
        or not set(value["readiness"]) <= set(plan.MODES)
        or not admission._utc(batch["declared_at"]) <= admission._utc(value["declared_at"]) <= admission._utc(admission._now())):
        raise ValueError("rolling plan changed its immutable scientific bindings")
    if "scheduling" in value:
        from .rapid_rolling_schedule import require_schedule
        require_schedule(value["scheduling"], spec, declared_at=value["declared_at"], _context=_context)
    expected = plan.plan_lanes(sites, final=True, study_version=6, rolling_batch=batch["ordinal"])
    rows = value["lanes"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("rolling plan has no independently registered lanes")
    if len(rows) == 1 and type(rows[0].get("generation")) is int and rows[0]["generation"] > 1:
        row = rows[0]
        base = next((lane for lane in expected if lane.logical_name == plan._campaign_name(
            row["role"], row["block"], row["shard"], row["mode"], 1, 6)), None)
        if base is None:
            raise ValueError("rolling successor is outside its immutable batch")
        expected = (plan.successor_lane(base, row["generation"]),)
    actual = []
    for lane in expected:
        raw = _render_campaign(lane, sites, policy, buflo_duration_policy=value.get("buflo_duration_policy"),
                               capture_limits=value.get("capture_limits"),
                               application_body_identity_policy=value.get("application_body_identity_policy"),
                               qualification_delivery_compatibility=value.get("qualification_delivery_compatibility"),
                               tamaraw_configuration_policy=fixed_tamaraw)
        if lanes._read(spec.campaign_dir / f"{lane.campaign_name}.yml") != raw:
            raise ValueError("rolling campaign changed sites, graph, visits or fixed settings")
        actual.append({**asdict(lane), "workload_ids": list(lane.workload_ids), "campaign_sha256": lanes._sha(raw)})
    if rows != actual or value["planned_trace_count"] != sum(lane.sample_count for lane in expected):
        raise ValueError("rolling plan omitted, repeated or invented visit lanes")
    return _context.remember(key, (sites, value)) if _context is not None else (sites, value)


def require_mode_readiness(spec: lanes.CaptureSpec, lane: plan.Lane, *, before: str | None = None, _context=None) -> dict[str, Any]:
    from .rapid_operation_facts import current_context
    _context = current_context() if _context is None else _context
    if _context is not None and current_context() is not _context:
        with _context.scope():
            return require_mode_readiness(spec, lane, before=before, _context=_context)
    sites, payload = verify_capture_plan(spec, _context=_context)
    from . import rapid_quick_profile as quick
    if quick.is_payload(payload):
        quick.require_worker(payload, lane, sites, spec)
        return payload["scheduling"]
    if lane.study_version != 6 or lane.role != "formal":
        raise ValueError("rolling readiness cannot authorize a historical or diagnostic lane")
    if lane.mode not in payload["readiness"]:
        raise ValueError(f"rolling {lane.mode} lacks its own successful current full canary")
    if "scheduling" in payload and payload["readiness"][lane.mode].get("schema_version") == 3:
        raise ValueError("canary control witness bridge cannot replace parallel setting authority")
    from .rapid_rolling_readiness import validate_canary
    if "scheduling" in payload:
        from . import rapid_rolling_schedule as schedule
        schedule.require_schedule(payload["scheduling"], spec, declared_at=payload["declared_at"], started_at=before, _context=_context)
        facts = schedule.validate_ready_canary(payload["readiness"][lane.mode], payload["scheduling"],
            mode=lane.mode, before=payload["declared_at"], _context=_context)
        from . import rapid_static_parallel_schedule as static_schedule
        from . import rapid_original_static_parallel_schedule as original_static
        from . import rapid_selected_parallel_schedule as selected_schedule
        from .rapid_capture_traffic import plan_files
        current_static = (static_schedule.is_static(payload["scheduling"])
                          or original_static.is_static(payload["scheduling"])
                          or selected_schedule.is_selected(payload["scheduling"]))
        from . import rapid_ordinary_parallel_schedule as ordinary_parallel
        from . import rapid_target_parallel_schedule as target_workers
        from . import rapid_epoch_target_parallel_schedule as epoch_workers
        current_static = (current_static or ordinary_parallel.is_schedule(payload["scheduling"])
                          or target_workers.is_schedule(payload["scheduling"])
                          or epoch_workers.is_schedule(payload["scheduling"]))
        expected_traffic = plan_files(payload) if current_static else lanes.TRAFFIC_FILES
        if (facts.get("client_sha256") != lanes._sha(lanes._read(spec.client_binary))
            or facts.get("traffic_hashes") != {key: digest for key, (_, digest) in expected_traffic.items()}):
            raise ValueError("scheduled setting changed its original client or fixed traffic")
        if current_static:
            measurement_runtime = _static_measurement_runtime(payload["scheduling"], spec.serializable(), _context=_context)
            expected_source = {**lanes._load(lanes._read(Path(measurement_runtime["source_manifest"]))),
                               "image_digest": measurement_runtime["collection_image_digest"]}
            if facts.get("authority_source") != expected_source:
                raise ValueError("static scheduled readiness changed its exact current Source")
    else:
        from .rapid_capture_traffic import plan_files
        runtime = {key: spec.serializable()[key] for key in lanes.RUNTIME_KEYS}
        facts = (validate_canary(payload["readiness"][lane.mode], runtime=runtime, mode=lane.mode)
                 if _context is None else _context.validate_canary(
                     payload["readiness"][lane.mode], runtime, lane.mode, validate_canary))
        expected_source = {**lanes._load(lanes._read(spec.source_manifest)), "image_digest": spec.collection_image_digest}
        if (facts.get("authority_source") != expected_source or facts.get("client_sha256") != lanes._sha(lanes._read(spec.client_binary))
            or facts.get("traffic_hashes") != {key: digest for key, (_, digest) in plan_files(payload).items()}):
            raise ValueError("rolling setting readiness differs from the independently checked installed Source, client or traffic")
    if "front_capture_amendment" in payload:
        from .rapid_front_capture_amendment import require_canary, validate_amendment
        reference = payload["front_capture_amendment"]
        amendment = validate_amendment(_open_ref(reference), enrollment=spec.cohort,
                     runtime={key: spec.serializable()[key] for key in RUNTIME_FIELDS})
        require_canary(payload["readiness"][lane.mode], facts, reference, amendment)
        if before is not None and admission._utc(amendment["published_at"]) > admission._utc(before):
            raise ValueError("FRONT amendment was not published before its actual launch")
    if "static_capture_amendment" in payload:
        from .supplied_static_capture_amendment import require_canary, validate_amendment
        reference = payload["static_capture_amendment"]
        amendment = validate_amendment(_open_ref(reference), enrollment=spec.cohort,
                     runtime=_static_measurement_runtime(payload.get("scheduling"), spec.serializable(), _context=_context))
        require_canary(payload["readiness"][lane.mode], _static_canary_facts(facts, amendment),
                       reference, amendment, mode=lane.mode)
        if before is not None and admission._utc(amendment["published_at"]) > admission._utc(before):
            raise ValueError("static capture amendment was not published before its actual launch")
    from . import rapid_undefended_capture as ordinary
    if ordinary.FIELD in payload:
        ordinary.require_canary(facts, sites)
    if payload["readiness"][lane.mode].get("schema_version") == 6:
        from .rapid_ordinary_canary_carry import require_current_plan
        require_current_plan(facts, spec, payload, sites)
    publication = facts.get("control_bridge_published_at", facts.get("source_equivalence_published_at"))
    from .application_response_policy import application_body_identity_policy
    if application_body_identity_policy(facts) != application_body_identity_policy(payload):
        raise ValueError("formal readiness changed its declared application body policy")
    from .tamaraw_fixed_configuration import policy as fixed_tamaraw_policy, configuration_sha256
    if (fixed_tamaraw_policy(facts) != fixed_tamaraw_policy(payload)
        or fixed_tamaraw_policy(payload) is not None and facts.get("tamaraw_configuration_sha256") != configuration_sha256()):
        raise ValueError("formal readiness changed its fixed Tamaraw condition")
    if facts.get("control_authority_witness", facts.get("qualification_delivery_compatibility")) != payload.get("qualification_delivery_compatibility"):
        raise ValueError("formal readiness changed its declared qualification delivery witness")
    if publication is not None and (admission._utc(publication) > admission._utc(payload["declared_at"])
                                  or before is not None and admission._utc(publication) > admission._utc(before)):
        raise ValueError("rolling canary Source equivalence was not prospectively published before its plan and launch")
    return payload["readiness"][lane.mode]


def image_plan_check(spec: lanes.CaptureSpec, runtime: Mapping[str, Any], *, _context=None) -> dict[str, Any]:
    sites, payload = verify_capture_plan(spec, require_current=True, _context=_context)
    # This new authority must be the actual installed producer, not a host
    # supplied replacement for the collection image's implementation.
    relative = "src/qcsd_lab/rapid_rolling_capture.py"
    own = lanes._read(Path(__file__))
    if own != lanes._read(spec.runtime_source_root / relative) or own != lanes._read(spec.module_root / relative):
        from .rapid_ordinary_transport_control import FIELD as transport_field, validate_image_authority
        if transport_field not in lanes._load(lanes._read(spec.qualification_spec)):
            raise ValueError("rolling authority differs from the installed and frozen source")
        validate_image_authority(spec, payload, runtime, own)
    if "slot_chunk_policy" in payload:
        from . import rapid_slot_chunks
        relative = "src/qcsd_lab/rapid_slot_chunks.py"
        own = lanes._read(Path(rapid_slot_chunks.__file__))
        if own != lanes._read(spec.runtime_source_root / relative) or own != lanes._read(spec.module_root / relative):
            raise ValueError("slot chunk authority differs from the installed and frozen Source")
    if "target_chunk_policy" in payload:
        from . import rapid_target_chunks
        relative = "src/qcsd_lab/rapid_target_chunks.py"
        own = lanes._read(Path(rapid_target_chunks.__file__))
        if own != lanes._read(spec.runtime_source_root / relative) or own != lanes._read(spec.module_root / relative):
            raise ValueError("target chunk authority differs from the installed and frozen Source")
    if "epoch_target_chunk_policy" in payload:
        from . import rapid_epoch_target_chunks, rapid_per_mode_native_target
        for module in (rapid_epoch_target_chunks, rapid_per_mode_native_target):
            relative = "src/qcsd_lab/" + module.__name__.rsplit(".", 1)[-1] + ".py"
            own = lanes._read(Path(module.__file__))
            if own != lanes._read(spec.runtime_source_root / relative) or own != lanes._read(spec.module_root / relative):
                raise ValueError("epoch chunk authority differs from the installed and frozen Source")
    if "front_capture_amendment" in payload:
        from . import rapid_front_capture_amendment
        relative = "src/qcsd_lab/rapid_front_capture_amendment.py"
        own = lanes._read(Path(rapid_front_capture_amendment.__file__))
        if own != lanes._read(spec.runtime_source_root / relative) or own != lanes._read(spec.module_root / relative):
            raise ValueError("FRONT amendment authority differs from the installed and frozen source")
    if "static_capture_amendment" in payload:
        from .supplied_static_capture_amendment import _sources
        _sources(spec.serializable(), duration_policy=payload.get("buflo_duration_policy"))
    modules = {path.relative_to(spec.module_root).as_posix(): lanes._sha(lanes._read(path))
               for base in (spec.module_root / "src/qcsd_lab", spec.module_root / "tools") for path in sorted(base.glob("*.py"))}
    return {"schema_version": 1, "artifact_type": lanes.IMAGE_PROOF_TYPE,
            **{key: runtime[key] for key in ("collection_image_digest", "runtime_source", "source_manifest_sha256",
                 "client_sha256", "base_launcher_sha256", "host_launcher_sha256", "qualification_implementation", "traffic_hashes")},
            "overlay_source_hashes": modules, "plan_receipt_sha256": lanes._sha(lanes._read(spec.plan_receipt)),
            "plan_payload": payload, "bindings": payload["bindings"], "sites": [asdict(site) for site in sites],
            "cohort_generation": "rolling-50", "acquisition_provenance_sha256": payload["acquisition_provenance_sha256"]}


def validate_host_launch(value: Any, *, expected_campaign: str, actual_image: str, _context=None) -> None:
    from .rapid_operation_facts import OperationFacts, current_context
    _context = current_context() if _context is None else _context
    if _context is None:
        context = OperationFacts()
        with context.scope():
            validate_host_launch(value, expected_campaign=expected_campaign, actual_image=actual_image, _context=context)
            context.check()
            return
    if current_context() is not _context:
        with _context.scope():
            return validate_host_launch(value, expected_campaign=expected_campaign, actual_image=actual_image, _context=_context)
    _keys(value, {"spec", "root", "intent", "intent_sha256", "readiness_mount_roots"}, "rolling host launch")
    spec = lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item for key, item in value["spec"].items()})
    root, path = Path(value["root"]), Path(value["intent"])
    if (spec.collection_image_digest != actual_image or not root.is_relative_to(spec.data_root)
        or lanes._sha(_context.watch_file(path)) != value["intent_sha256"]):
        raise ValueError("rolling host launch changed its actual image, root or intent")
    lanes.executed_image_plan_check(spec.serializable(), _context=_context)
    provisional = lanes._payload(path, lanes.INTENT_TYPE)
    _context.watch_file(lanes.admission._child(root, provisional["lineage"]))
    intent, lineage, lane, _ = lanes._intent_and_lineage(spec, root, path, _context=_context)
    # Current admission files are immutable inputs too. Their exact refs can
    # coexist with later host/worker outputs in the same transport parent.
    _context._references(intent, root)
    _context._references(lineage, root)
    if (lane.study_version != 6 or lane.campaign_name != expected_campaign
        or intent["actuator"] not in {"run", "parallel-formal-worker"}):
        raise ValueError("rolling host launch requires its exact formal lane")
    payload = lanes.plan_payload(lanes._read(spec.plan_receipt))
    if "epoch_target_chunk_policy" in payload:
        from .rapid_epoch_target_chunks import require_intent
        require_intent(payload["epoch_target_chunk_policy"], intent["started_at"])
    if intent["actuator"] == "parallel-formal-worker":
        from .rapid_rolling_schedule import require_schedule
        payload = lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE)
        require_schedule(payload.get("scheduling"), spec, declared_at=payload["declared_at"], started_at=intent["started_at"], _context=_context)
    if value["readiness_mount_roots"] != [str(path) for path in readiness_roots(spec, expected_campaign, _context=_context)]:
        raise ValueError("rolling host launch changed its derived read-only canary mounts")
    require_mode_readiness(spec, lane, _context=_context)


def publish_successor(spec: lanes.CaptureSpec, lane_name: str, generation: int, output: Path) -> Path:
    from . import rapid_epoch_target_parallel_schedule as epoch_workers
    if epoch_workers.is_plan(spec.plan_receipt):
        return epoch_workers.publish_successor(spec, lane_name, generation, output)
    from . import rapid_target_parallel_schedule as target_workers
    if target_workers.is_plan(spec.plan_receipt):
        return target_workers.publish_successor(spec, lane_name, generation, output)
    from . import rapid_target_chunks as target_chunks
    if target_chunks.is_plan(spec.plan_receipt):
        return target_chunks.publish_successor(spec, lane_name, generation, output)
    from . import rapid_epoch_target_chunks as epoch_chunks
    if epoch_chunks.is_plan(spec.plan_receipt):
        return epoch_chunks.publish_successor(spec, lane_name, generation, output)
    from . import rapid_ordinary_parallel_schedule as ordinary_parallel
    if ordinary_parallel.is_plan(spec.plan_receipt):
        return ordinary_parallel.publish_successor(spec, lane_name, generation, output)
    from . import rapid_slot_chunks as chunks
    if chunks.is_plan(spec.plan_receipt):
        return chunks.publish_successor(spec, lane_name, generation, output)
    sites, value = verify_capture_plan(spec)
    base = next((plan.Lane(**{key: tuple(item) if key == "workload_ids" else item for key, item in row.items()
                              if key != "campaign_sha256"}) for row in value["lanes"] if row["campaign_name"] == lane_name), None)
    if base is None or generation != base.generation + 1:
        raise ValueError("rolling recovery must name the immediate failed lane successor")
    lane = plan.successor_lane(base, generation)
    raw = plan.render_lane_campaign(lane, sites, static_capture_limits=value.get("capture_limits"),
                                    buflo_duration_policy=value.get("buflo_duration_policy"),
                                    application_body_identity_policy=value.get("application_body_identity_policy"),
                                    qualification_delivery_compatibility=value.get("qualification_delivery_compatibility"),
                                    tamaraw_configuration_policy=value.get("tamaraw_configuration_policy") if lane.mode == "tamaraw" else None)
    admission.durable_create(spec.campaign_dir / f"{lane.campaign_name}.yml", raw)
    value = {**value, "lanes": [{**asdict(lane), "workload_ids": list(lane.workload_ids), "campaign_sha256": lanes._sha(raw)}],
             "planned_trace_count": lane.sample_count, "declared_at": admission._now()}
    return _write(output, lanes.PLAN_TYPE, value)


LANE_CHECK_SCRIPT = """
import json,sys
from pathlib import Path
from qcsd_lab import rapid_lane_evidence as e
value=json.loads(sys.argv[1])
spec=e.CaptureSpec(**{k:Path(v) if k in e.PATH_KEYS else v for k,v in value['spec'].items()})
e.executed_image_plan_check(spec.serializable())
root,target=Path(value['root']),Path(value['target'])
receipt=e.complete_lane(spec,root,target) if value['complete'] else target
# Completion just deep-verified this result; the host reopens its sealed bytes.
print(json.dumps({'receipt':str(receipt),'facts':e.verify_launch_receipt(
    receipt,spec=spec,evidence_root=root,_manifest_already_deep_verified=value['complete'])},
    sort_keys=True,allow_nan=False))
""".strip()


def enrollment_roots(spec: lanes.CaptureSpec) -> list[Path]:
    from . import rapid_quick_profile as quick
    if quick.is_plan(spec.plan_receipt):
        return quick.mount_roots(lanes.plan_payload(lanes._read(spec.plan_receipt))["scheduling"])
    """Derive transport from sealed policy and enrollment metadata only.

    The installed plan check still reopens every terminal and prepared graph.
    Mount derivation does not repeat that scientific verification on the host.
    """
    from . import rapid_epoch_target_parallel_schedule as epoch_workers
    if epoch_workers.is_plan(spec.plan_receipt):
        return sorted(epoch_workers.roots(spec))
    from . import rapid_target_parallel_schedule as target_workers
    if target_workers.is_plan(spec.plan_receipt):
        return sorted(target_workers.roots(spec))
    from . import rapid_target_chunks as target_chunks
    if target_chunks.is_plan(spec.plan_receipt):
        return sorted(target_chunks.roots(spec))
    from . import rapid_epoch_target_chunks as epoch_chunks
    if epoch_chunks.is_plan(spec.plan_receipt):
        return sorted(epoch_chunks.roots(spec))
    from . import rapid_ordinary_parallel_schedule as ordinary_parallel
    if ordinary_parallel.is_plan(spec.plan_receipt):
        return sorted(ordinary_parallel.roots(spec))
    from . import rapid_undefended_capture as ordinary
    stored = lanes.plan_payload(lanes._read(spec.plan_receipt))
    if ordinary.FIELD in stored:
        from . import rapid_ordinary_transport_control as transport
        return transport.enrollment_roots(spec, stored)
    from . import rapid_slot_chunks as chunks
    if chunks.is_plan(spec.plan_receipt):
        return sorted(chunks.roots(spec))
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    payload = admission._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
    if "selected_input_renewal" in payload:
        from .rapid_selected_input_renewal import enrollment_roots as renewed_roots
        return sorted(renewed_roots(spec))
    if per_class.enrollment_kind(spec.cohort):
        payload = admission._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
        if "static_capture_amendment" in payload:
            from . import per_class_selected_capture_amendment
            return per_class_selected_capture_amendment.enrollment_roots(spec)
        return per_class.enrollment_roots(spec)
    if additive.enrollment_kind(spec.cohort):
        payload = admission._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
        if "static_capture_amendment" in payload:
            from . import selected_capture_amendment as selected_amendment
            return selected_amendment.enrollment_roots(spec)
        return additive.enrollment_roots(spec)
    path = spec.cohort.absolute()
    payload = admission._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
    if (type(payload.get("study_version")) is not int or payload["study_version"] != 6
        or payload.get("cohort_generation") != "rolling-50"
        or payload.get("bindings", {}).get("cohort_sha256") != lanes._sha(lanes._read(path))):
        raise ValueError("rolling transport changed its bound enrollment")
    roots, seen = set(), set()
    policy_reference = None
    expected_ordinal = None
    while True:
        if path in seen:
            raise ValueError("rolling transport enrollment contains a cycle")
        seen.add(path)
        batch = admission._unpack(lanes._read(path), ENROLLMENT_TYPE)
        _keys(batch, {"policy", "ordinal", "parent", "admission_root", "admission_provenance",
                     "decisions", "selected_candidate_ids", "first_class_index", "last_candidate_position",
                     "declared_at", "scientific_credit"}, "rolling enrollment transport")
        policy_path = _open_ref(batch["policy"])
        if policy_reference is None:
            root = policy_path.parent
            if policy_path != root / "policy.json":
                raise ValueError("rolling transport requires its official policy namespace")
            policy = verify_policy(root)
            if policy["runtime"]["data_root"] != str(spec.data_root):
                raise ValueError("rolling transport changed its study data root")
            policy_reference = batch["policy"]
            roots.add(root)
            runtime = policy["runtime"]
            roots.update(Path(runtime[key]) for key in ("data_root", "runtime_source_root", "module_root", "execution_root"))
            roots.update(_open_ref(policy[key]).parent for key in
                         ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"))
            roots.add(lanes._regular_directory(Path(policy["initial_admission_root"])))
        elif batch["policy"] != policy_reference:
            raise ValueError("rolling transport parent changes its sealed policy")
        ordinal = batch["ordinal"]
        if (path != _batch_path(root, ordinal) or batch["scientific_credit"] is not False
            or expected_ordinal is not None and ordinal != expected_ordinal):
            raise ValueError("rolling transport enrollment is outside its claimed batch namespace")
        context_root = lanes._regular_directory(Path(batch["admission_root"]))
        if _open_ref(batch["admission_provenance"]) != context_root / "provenance.json":
            raise ValueError("rolling transport changed its sealed admission provenance")
        if expected_ordinal is None and context_root != spec.acquisition_root:
            raise ValueError("rolling transport changed its current admission context")
        context = _context_for_policy(policy, context_root)
        if _admission_identity(context) != policy["admission_identity"]:
            raise ValueError("rolling transport admission context changed its policy inputs")
        # Admission inputs, module Sources, retained root-role records and all
        # attempt artifacts are closed relative references under this root.
        roots.add(context_root)
        from . import supplied_static_admission as static
        from . import whole_graph_supplement as whole
        from . import supplied_static_budget_successor as budget
        from . import static_budget_capture as budget_capture
        if isinstance(context, (budget.Context, budget_capture.Context)):
            roots.update(budget_capture.roots(context))
        if isinstance(context, whole.Context):
            roots.update(whole.roots(context))
        if isinstance(context, static.Context):
            roots.update(static.roots(context))
        if ordinal == 1:
            if batch["parent"] is not None:
                raise ValueError("rolling transport initial enrollment invents a parent")
            break
        parent = _open_ref(batch["parent"])
        if parent != _batch_path(root, ordinal - 1):
            raise ValueError("rolling transport skips its immediate parent enrollment")
        path, expected_ordinal = parent, ordinal - 1
    for root in roots:
        lanes._regular_directory(root)
        if any(char in str(root) for char in ("\n", "\r", "\0", ":")):
            raise ValueError("rolling transport requires regular canonical mount roots")
    return sorted(roots)


def readiness_roots(spec: lanes.CaptureSpec, campaign_name: str, *, _context=None) -> list[Path]:
    from .rapid_operation_facts import current_context
    _context = current_context() if _context is None else _context
    if _context is not None and current_context() is not _context:
        with _context.scope():
            return readiness_roots(spec, campaign_name, _context=_context)
    _, payload = verify_capture_plan(spec, _context=_context)
    from . import rapid_quick_profile as quick
    if quick.is_payload(payload):
        return quick.mount_roots(payload["scheduling"], _context=_context)
    proof = {"plan_payload": payload}
    lane = lanes._lane(proof, campaign_name)
    reference = require_mode_readiness(spec, lane, _context=_context)
    from .rapid_rolling_readiness import readiness_mount_roots
    roots = set(enrollment_roots(spec))
    if "static_capture_amendment" in payload:
        from .supplied_static_capture_amendment import validate_amendment, preparation_roots
        amendment = validate_amendment(_open_ref(payload["static_capture_amendment"]),
                     enrollment=spec.cohort,
                     runtime=_static_measurement_runtime(payload.get("scheduling"), spec.serializable(), _context=_context))
        for row in amendment["workloads"]:
            value = lanes._load(lanes._read(_open_ref(row["capture_manifest"])))
            roots.update(preparation_roots(value["preparation"]))
    if "scheduling" in payload:
        from . import rapid_rolling_schedule as schedule
        capsule = schedule.require_schedule(payload["scheduling"], spec, declared_at=payload["declared_at"], _context=_context)
        roots.update(schedule.mount_roots(payload["scheduling"], _context=_context))
        roots.update(readiness_mount_roots(reference,
            runtime={key: capsule["base_spec"][key] for key in lanes.RUNTIME_KEYS}, mode=lane.mode, _context=_context))
        return sorted(roots)
    return sorted(roots | set(readiness_mount_roots(reference,
        runtime={key: spec.serializable()[key] for key in lanes.RUNTIME_KEYS}, mode=lane.mode, _context=_context)))


def lane_check_command(spec: lanes.CaptureSpec, root: Path, target: Path, *, complete: bool,
                       operation_token: str | None = None, _context=None) -> list[str]:
    command = lanes.image_check_command(spec, inherit_environment=False, campaign_name=target.parent.name,
                                       _context=_context)
    index = command.index("--entrypoint")
    mount = f"{root}:{root}:{'rw' if complete else 'ro'}"
    matches = [position + 1 for position, item in enumerate(command[:index])
               if item == "--volume" and command[position + 1].split(":")[1] == str(root)]
    if matches:
        command[matches[0]] = mount
    else:
        command[index:index] = ["--volume", mount]
    if operation_token is not None:
        if (type(operation_token) is not str or len(operation_token) != 32
            or any(char not in "0123456789abcdef" for char in operation_token)):
            raise ValueError("installed lane check operation token is invalid")
        command[command.index("--entrypoint"):command.index("--entrypoint")] = [
            "--name", "qcsd-rapid-lane-check-" + operation_token,
            "--label", "org.qcsd.owner=qcsd-lab",
            "--label", "org.qcsd.role=rolling-installed-lane-check",
            "--label", "org.qcsd.operation=" + operation_token,
            "--cidfile", str(root / "lane-checks" / operation_token / "container.id"),
        ]
    command[-2:] = [LANE_CHECK_SCRIPT, json.dumps({"spec": spec.serializable(), "root": str(root),
        "target": str(target), "complete": complete}, sort_keys=True)]
    return command


def check_lane_in_image(spec: lanes.CaptureSpec, root: Path, target: Path, *, complete: bool, _context=None) -> dict[str, Any]:
    """Run the unchanged ordinary deep verifier in the actual bound image."""
    _, plan_payload = verify_capture_plan(spec, _context=_context)
    root = lanes._regular_directory(root)
    target = target.absolute()
    if not target.is_relative_to(root / "lanes"):
        raise ValueError("rolling lane deep target escapes its declared evidence root")
    lane = lanes._lane({"plan_payload": plan_payload}, target.parent.name)
    # One installed plan/source allowance plus one frozen capture timeout per trace.
    timeout_seconds = 300 + lane.sample_count * plan.V5_CAPTURE_LIMITS["timeout_seconds"]
    operation_token = secrets.token_hex(16)
    command = lane_check_command(spec, root, target, complete=complete,
                                 operation_token=operation_token, _context=_context)
    if _context is not None:
        _context.check()
    parent = root / "lane-checks"
    parent.mkdir(exist_ok=True)
    lanes._regular_directory(parent)
    directory = parent / operation_token
    directory.mkdir(mode=0o700)
    start = {"command": command, "started_at": admission._now(),
             "operation_token": operation_token, "timeout_seconds": timeout_seconds}
    start_path = directory / "actual-started.json"
    admission.durable_create(start_path, admission._json(start))
    error = None
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=timeout_seconds)
        status, stdout, stderr = result.returncode, result.stdout.encode(), result.stderr.encode()
    except subprocess.TimeoutExpired as failure:
        status = None
        stdout, stderr = getattr(failure, "stdout", None) or b"", getattr(failure, "stderr", None) or b""
        stdout = stdout.encode() if isinstance(stdout, str) else stdout
        stderr = stderr.encode() if isinstance(stderr, str) else stderr
        cidfile = directory / "container.id"
        name = "qcsd-rapid-lane-check-" + operation_token
        cleanup = {"status": "not-inspected", "cidfile": str(cidfile), "container_name": name,
                   "inspect": None, "remove": None}
        try:
            container_id = None
            if cidfile.exists() or cidfile.is_symlink():
                raw_id = lanes._read(cidfile).decode("ascii")
                container_id = raw_id.removesuffix("\n")
                if (raw_id not in {container_id, container_id + "\n"} or len(container_id) != 64
                    or any(char not in "0123456789abcdef" for char in container_id)):
                    raise ValueError("owned lane check cidfile is malformed")
            def recorded_docker(command):
                completed = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, check=False, timeout=30)
                output = completed.stdout.encode() if isinstance(completed.stdout, str) else completed.stdout or b""
                errors = completed.stderr.encode() if isinstance(completed.stderr, str) else completed.stderr or b""
                record = {"command": command, "returncode": completed.returncode,
                          "stdout": lanes._put_object(root, output), "stderr": lanes._put_object(root, errors)}
                return completed, output, record
            inspect_command = ["docker", "container", "inspect", container_id or name]
            inspected, inspect_output, cleanup["inspect"] = recorded_docker(inspect_command)
            if inspected.returncode != 0:
                cleanup["status"] = "inspect-failed"
            else:
                values = json.loads(inspect_output)
                if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
                    raise ValueError("owned lane check inspect returned no unique container")
                observed = values[0]
                actual_id = observed.get("Id")
                config = observed.get("Config")
                labels = config.get("Labels") if isinstance(config, dict) else None
                if (not isinstance(actual_id, str) or len(actual_id) != 64
                    or any(char not in "0123456789abcdef" for char in actual_id)
                    or container_id is not None and actual_id != container_id
                    or observed.get("Name") != "/" + name or not isinstance(labels, dict)
                    or labels.get("org.qcsd.owner") != "qcsd-lab"
                    or labels.get("org.qcsd.role") != "rolling-installed-lane-check"
                    or labels.get("org.qcsd.operation") != operation_token
                    or config.get("Image") != spec.collection_image_digest):
                    cleanup["status"] = "identity-mismatch"
                else:
                    removed, _, cleanup["remove"] = recorded_docker(["docker", "rm", "-f", actual_id])
                    cleanup["status"] = "removed" if removed.returncode == 0 else "remove-failed"
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError) as cleanup_error:
            cleanup["status"] = "cleanup-error"
            cleanup["error"] = {"type": type(cleanup_error).__name__, "message": str(cleanup_error)}
        error = {"type": type(failure).__name__, "message": str(failure), "cleanup": cleanup}
    except (OSError, subprocess.SubprocessError) as failure:
        status = None
        stdout, stderr = getattr(failure, "stdout", None) or b"", getattr(failure, "stderr", None) or b""
        stdout = stdout.encode() if isinstance(stdout, str) else stdout
        stderr = stderr.encode() if isinstance(stderr, str) else stderr
        error = {"type": type(failure).__name__, "message": str(failure)}
    end = {"command": command, "started_at": start["started_at"], "completed_at": admission._now(),
           "returncode": status, "invocation_error": error,
           "operation_token": operation_token, "timeout_seconds": timeout_seconds,
           "stdout": lanes._put_object(root, stdout), "stderr": lanes._put_object(root, stderr)}
    end_path = directory / "actual-completed.json"
    admission.durable_create(end_path, admission._json(end))
    if type(status) is not int or status != 0:
        raise ValueError("actual installed rolling lane deep check failed; raw records retained")
    value = lanes._load(stdout)
    _keys(value, {"receipt", "facts"}, "installed lane result")
    payload = {"spec": spec.serializable(), "root": str(root), "target": str(target), "complete": complete,
               "started": _ref(start_path), "completed": _ref(end_path), "receipt": _ref(Path(value["receipt"])),
               "facts": value["facts"]}
    closure = _write(directory / "closure.json", LANE_CHECK_TYPE, payload)
    _reopen_lane_check(_ref(closure))
    if _context is not None:
        _context.check()
    return {"closure": _ref(closure), "receipt": value["receipt"], **value["facts"]}


def _reopen_lane_check(reference: Any) -> tuple[lanes.CaptureSpec, Path, dict[str, Any], plan.Lane, tuple[plan.Site, ...]]:
    path = _open_ref(reference)
    value = admission._unpack(lanes._read(path), LANE_CHECK_TYPE)
    _keys(value, {"spec", "root", "target", "complete", "started", "completed", "receipt", "facts"}, "lane deep closure")
    if type(value["complete"]) is not bool:
        raise ValueError("rolling deep closure action is invalid")
    spec = lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item for key, item in value["spec"].items()})
    root, target = lanes._regular_directory(Path(value["root"])), Path(value["target"])
    _, plan_payload = verify_capture_plan(spec)
    started_path, completed_path = _open_ref(value["started"]), _open_ref(value["completed"])
    start = lanes._load(lanes._read(started_path))
    end = lanes._load(lanes._read(completed_path))
    legacy_start = {"command", "started_at"}
    legacy_end = {"command", "started_at", "completed_at", "returncode", "invocation_error", "stdout", "stderr"}
    if set(start) == legacy_start and set(end) == legacy_end:
        command = lane_check_command(spec, root, target, complete=value["complete"])
    elif set(start) == legacy_start | {"operation_token", "timeout_seconds"} and set(end) == legacy_end | {"operation_token", "timeout_seconds"}:
        token = start["operation_token"]
        lane = lanes._lane({"plan_payload": plan_payload}, target.parent.name)
        deadline = 300 + lane.sample_count * plan.V5_CAPTURE_LIMITS["timeout_seconds"]
        if (type(token) is not str or len(token) != 32 or any(char not in "0123456789abcdef" for char in token)
            or path.parent != root / "lane-checks" / token
            or started_path != path.parent / "actual-started.json"
            or completed_path != path.parent / "actual-completed.json"
            or type(start["timeout_seconds"]) is not int or start["timeout_seconds"] != deadline
            or end["operation_token"] != token or type(end["timeout_seconds"]) is not int
            or end["timeout_seconds"] != deadline):
            raise ValueError("rolling lane closure changed its owned actor or operational deadline")
        command = lane_check_command(spec, root, target, complete=value["complete"], operation_token=token)
    else:
        raise ValueError("rolling lane closure has an unsupported actual operation record")
    if (start["command"] != command or end["command"] != command or end["started_at"] != start["started_at"]
        or type(end["returncode"]) is not int or end["returncode"] != 0 or end["invocation_error"] is not None
        or not admission._utc(start["started_at"]) <= admission._utc(end["completed_at"]) <= admission._utc(admission._now())):
        raise ValueError("rolling lane closure lacks its actual successful installed deep execution")
    stdout = lanes._load(lanes._object(root, end["stdout"]))
    lanes._object(root, end["stderr"])
    receipt = _open_ref(value["receipt"])
    if stdout != {"receipt": str(receipt), "facts": value["facts"]} or not receipt.is_relative_to(root / "lanes"):
        raise ValueError("rolling lane closure differs from its actual image output")
    if target != (receipt.parent / "intent.json" if value["complete"] else receipt):
        raise ValueError("rolling lane closure verified another target")
    intent, _, lane, sites = lanes._intent_and_lineage(spec, root, receipt.parent / "intent.json")
    if lane.study_version != 6 or lane.role != "formal" or intent["actuator"] not in {"run", "parallel-formal-worker"}:
        raise ValueError("rolling final closure cannot promote diagnostic evidence")
    if intent["actuator"] == "parallel-formal-worker":
        from .rapid_rolling_schedule import require_schedule
        payload = lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE)
        require_schedule(payload.get("scheduling"), spec, declared_at=payload["declared_at"], started_at=intent["started_at"])
    result = Path(value["facts"]["result_root"])
    from .verification import _read_checksums, authoritative_files
    files, checksums = authoritative_files(result), _read_checksums(result, result / "evidence.sha256")
    if set(files) != set(checksums) or any(lanes._sha(lanes._read(files[name])) != digest for name, digest in checksums.items()):
        raise ValueError("rolling result bytes differ from the actual deep-verified seal")
    # The actual installed operation above deep-verified this exact result;
    # the private fast path now reopens its ordinary lifecycle/DNS/Source proof.
    facts = lanes.verify_launch_receipt(receipt, spec=spec, evidence_root=root, _manifest_already_deep_verified=True)
    if facts != value["facts"] or facts["accepted"] != lane.sample_count:
        raise ValueError("rolling closure changed its deep-verified lane facts")
    return spec, receipt, facts, lane, sites


def _corpus_facts(root: Path, closures: list[Any]) -> dict[str, Any]:
    policy = verify_policy(root)
    batches = _batches(root)
    if not batches:
        raise ValueError("rolling corpus has no admitted membership")
    verified_batches = {}
    _, classes = verify_enrollment(batches[-1], _verified=verified_batches)
    if len(classes) != 50 or len({row["candidate_id"] for row in classes}) != 50:
        raise ValueError("rolling final corpus requires exactly fifty independently admitted classes")
    class_index = {row["candidate_id"]: row["class_index"] for row in classes}
    expected = {(index, mode, visit) for index in range(1, 51) for mode in plan.MODES for visit in range(64)}
    observed: set[tuple[int, str, int]] = set()
    logical: set[str] = set()
    rows = []
    for reference in closures:
        spec, receipt, result, lane, sites = _reopen_lane_check(reference)
        bound = verified_batches.get(spec.cohort.absolute())
        if bound is None or lanes._sha(lanes._read(spec.cohort)) != bound[0]:
            raise ValueError("rolling corpus changed or introduced an enrollment after its complete chain reopening")
        batch = bound[1]
        if _open_ref(batch["policy"]) != root / "policy.json":
            raise ValueError("rolling corpus pooled another study's enrollments")
        if lane.study_version != 6 or lane.role != "formal" or lane.logical_name in logical:
            raise ValueError("rolling corpus repeats a lane or promotes diagnostic evidence")
        logical.add(lane.logical_name)
        ids = {site.workload_id: site.candidate_id for site in sites}
        for workload in lane.workload_ids:
            index = class_index[ids[workload]]
            from .rapid_slot_chunks import logical_slot
            for visit in range(lane.visits_per_workload):
                slot = index, lane.mode, logical_slot(lane, visit)
                if slot not in expected or slot in observed:
                    raise ValueError("rolling corpus repeats or invents a formal class/setting/visit slot")
                observed.add(slot)
        rows.append({"closure": dict(reference), "spec": spec.serializable(), "receipt": _ref(receipt), "logical_lane": lane.logical_name,
                     "accepted": result["accepted"], "result_seal_sha256": result["result_seal_sha256"]})
    if observed != expected or sum(row["accepted"] for row in rows) != 16000:
        raise ValueError("rolling corpus does not contain exactly fifty by five by sixty-four accepted traces")
    facts = {"policy": _ref(root / "policy.json"), "final_enrollment": _ref(batches[-1]),
               "classes": classes, "lanes": rows, "accepted": 16000, "lane_count": len(rows),
               "scientific_credit": True}
    if policy["contract"] == STATIC_CONTRACT:
        facts["data_role"] = policy["data_role"]
    return facts


def publish_corpus(root: Path, closures: list[Any], output: Path) -> dict[str, Any]:
    if not output.absolute().is_relative_to(root.absolute()):
        raise ValueError("rolling corpus manifest must remain inside its study root")
    payload = {**_corpus_facts(root, closures), "closed_at": admission._now()}
    _write(output, CORPUS_TYPE, payload)
    return verify_corpus_manifest(root, output)


def verify_corpus_manifest(root: Path, path: Path) -> dict[str, Any]:
    value = admission._unpack(lanes._read(path), CORPUS_TYPE)
    fields = {"policy", "final_enrollment", "classes", "lanes", "accepted", "lane_count", "scientific_credit", "closed_at"}
    policy = verify_policy(root)
    if policy["contract"] == STATIC_CONTRACT:
        fields.add("data_role")
    _keys(value, fields, "rolling corpus")
    expected = _corpus_facts(root, [row["closure"] for row in value["lanes"]])
    if any(value[key] != item or type(value[key]) is not type(item) for key, item in expected.items()) or admission._utc(value["closed_at"]) > admission._utc(admission._now()):
        raise ValueError("rolling final manifest differs from its independently reopened exact corpus")
    return {"valid": True, "accepted": 16000, "lane_count": value["lane_count"], "manifest": str(path), "scientific_credit": True}
