"""Prospective rolling formal capture, independent of unfinished membership.

Admission keeps its original source role and complete-page rules. Immutable
enrollment batches contain one to five sites; a later batch cannot alter a
previous decision, workload, qualifier, lane or visit. The final corpus still
requires fifty sites, five settings and exactly sixty-four visits per setting.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from . import rapid_capture_plan as plan
from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as admission
from .chaff_qualification import RESPONSE_ONLY_QUALIFICATION_SCOPE, validate_named_qualification_set_manifest
from .discover import origin

POLICY_TYPE = "qcsd-rapid-v6-rolling-formal-policy"
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
    if context.selection_amendment_revision != 12:
        raise ValueError("rolling capture requires the explicitly prepared V12 traffic policies")
    return {"profile_sha256": lanes._sha(context.profile_bytes),
            "source_sha256": lanes._sha(context.source_bytes),
            "catalogue_sha256": lanes._sha(context.catalogue_bytes),
            "selection_amendment_sha256": context.selection_amendment_sha256,
            "candidate_order_sha256": lanes._sha(admission._json(list(context.candidates)))}


def initialize_study(acquisition_root: Path, root: Path, runtime: Mapping[str, str]) -> Path:
    root = lanes._regular_directory(root)
    runtime = _runtime(dict(runtime))
    if any(root.iterdir()) or not root.is_relative_to(Path(runtime["data_root"])):
        raise ValueError("rolling study needs an empty directory under its explicit data root")
    context = admission.load_admission_context(acquisition_root)
    payload = {"contract": CONTRACT, "admission_identity": _admission_identity(context),
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
    return _write(root / "policy.json", POLICY_TYPE, payload)


def verify_policy(root: Path) -> dict[str, Any]:
    root = lanes._regular_directory(root)
    value = admission._unpack(lanes._read(root / "policy.json"), POLICY_TYPE)
    _keys(value, {"contract", "admission_identity", "initial_admission_root", "runtime",
                 "runtime_source_manifest", "client_binary", "base_launcher", "host_launcher",
                 "published_at", "class_target", "modes", "visits_per_class_mode",
                 "formal_trace_target", "maximum_batch_size", "visits_per_lane_workload",
                 "global_shakedown_required", "complete_membership_before_first_lane_required",
                 "formal_accepted_trace_count", "scientific_credit"}, "rolling policy")
    exact = {"contract": CONTRACT, "class_target": 50, "modes": list(plan.MODES),
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
    initial = admission.load_admission_context(Path(value["initial_admission_root"]))
    if _admission_identity(initial) != value["admission_identity"]:
        raise ValueError("rolling policy admission inputs changed")
    return value


def _batch_path(root: Path, ordinal: int) -> Path:
    if type(ordinal) is not int or not 1 <= ordinal <= 50:
        raise ValueError("rolling batch ordinal is outside one to fifty")
    return root / "batches" / f"b{ordinal:04d}" / "enrollment.json"


def _batches(root: Path) -> list[Path]:
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
    if not path.is_relative_to(context.root / "attempts"):
        raise ValueError("rolling terminal escapes its separately bound admission context")
    facts = admission.verify_site_terminal(path, context)
    candidate = context.candidates[position - 1]
    if facts["candidate_id"] != candidate["candidate_id"]:
        raise ValueError("rolling enrollment reordered or skipped a candidate decision")
    return {"position": position, "candidate_id": facts["candidate_id"],
            "outcome": facts["outcome"], "terminal": dict(reference)}, facts


def _prepared_workload(context, terminal_path: Path) -> tuple[Path, dict[str, Any]]:
    terminal = admission._unpack(lanes._read(terminal_path), admission.TERMINAL_TYPE)
    preparation = admission._unpack(lanes._read(admission._child(context.root, terminal["preparation"])), admission.PREPARATION_TYPE)
    original = admission._child(context.root, preparation["prepared_workload"])
    return original, lanes._load(lanes._read(original))


def verify_enrollment(path: Path, *, _verified: dict | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    batch, classes, _ = _verify_enrollment(path, _verified=_verified)
    return batch, classes


def _verify_enrollment(path: Path, *, _verified: dict | None = None) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    raw = lanes._read(path)
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
        parent, previous, _ = _verify_enrollment(_open_ref(value["parent"]), _verified=_verified)
        first_position = parent["last_candidate_position"] + 1
        first_class = parent["first_class_index"] + len(parent["selected_candidate_ids"])
        earliest = parent["declared_at"]
    if (type(value["first_class_index"]) is not int or value["first_class_index"] != first_class
        or not admission._utc(earliest) <= admission._utc(value["declared_at"]) <= admission._utc(admission._now())):
        raise ValueError("rolling enrollment membership ordinal or chronology differs")
    context = admission.load_admission_context(Path(value["admission_root"]))
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
        if facts["outcome"] == "admitted":
            workload_path, workload = _prepared_workload(context, _open_ref(row["terminal"]))
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
    if _verified is not None:
        _verified[path.absolute()] = (lanes._sha(raw), value, classes)
    return value, classes, policy


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
    context = admission.load_admission_context(acquisition_root or Path(policy["initial_admission_root"]))
    if _admission_identity(context) != policy["admission_identity"]:
        raise ValueError("rolling successor admission changed the frozen catalogue or scientific rules")
    status = admission.acquisition_status(context)
    decisions, selected = [], []
    for position, reference in enumerate(status["terminal_prefix"], 1):
        if position < first_position:
            continue
        row, facts = _terminal_row(context, position, _ref(admission._child(context.root, reference)))
        decisions.append(row)
        if facts["outcome"] == "admitted":
            selected.append(facts["candidate_id"])
        if len(selected) == count:
            break
    if len(selected) != count:
        raise ValueError("not enough new independently admitted sites for this rolling batch")
    output = _batch_path(root, ordinal)
    payload = {"policy": _ref(root / "policy.json"), "ordinal": ordinal, "parent": parent,
               "admission_root": str(context.root), "admission_provenance": _ref(context.root / "provenance.json"),
               "decisions": decisions, "selected_candidate_ids": selected, "first_class_index": first_class,
               "last_candidate_position": decisions[-1]["position"], "declared_at": admission._now(),
               "scientific_credit": False}
    _write(output, ENROLLMENT_TYPE, payload)
    verify_enrollment(output)
    return output


def _sites(enrollment: Path, qualifier_spec: Path, workload_root: Path, *, require_current: bool = False) -> tuple[plan.Site, ...]:
    batch, all_classes = verify_enrollment(enrollment)
    return _sites_from_enrollment(batch, all_classes, qualifier_spec, workload_root, require_current=require_current)


def _sites_from_enrollment(batch: Mapping[str, Any], all_classes: list[dict[str, Any]],
                           qualifier_spec: Path, workload_root: Path, *, require_current: bool) -> tuple[plan.Site, ...]:
    classes = all_classes[-len(batch["selected_candidate_ids"]):]
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
        context = admission.load_admission_context(Path(row["admission_root"]))
        terminal_path = _open_ref(row["terminal"])
        facts = admission.verify_site_terminal(terminal_path, context)
        original, workload = _prepared_workload(context, terminal_path)
        if lanes._read(workload_root / original.name) != lanes._read(original):
            raise ValueError("rolling capture pruned or changed an admitted complete workload")
        sites.append(plan.Site(row["candidate_id"], original.stem, facts["admission"]["prepared_workload_sha256"],
                               origin(workload["preparation"]["final_url"]), q["qualification_set"], lanes._sha(lanes._read(manifest))))
    validate_named_qualification_set_manifest(lanes._load(lanes._read(manifest)), workload_root=workload_root,
        sidecar_root=sidecars, prefix_spec_root=None, expected_qualification_set=q["qualification_set"],
        expected_workload_ids=[site.workload_id for site in sites], expected_qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
        require_current_implementation=require_current)
    return plan._check_sites(sites, final=True, study_version=6)


def _bindings(enrollment: Path) -> dict[str, str]:
    _, _, policy = _verify_enrollment(enrollment)
    return _bindings_from_enrollment(enrollment, policy)


def _bindings_from_enrollment(enrollment: Path, policy: Mapping[str, Any]) -> dict[str, str]:
    return {"profile_sha256": policy["admission_identity"]["profile_sha256"],
            "cohort_sha256": lanes._sha(lanes._read(enrollment)), "study_version": "v6",
            "selection_amendment_sha256": policy["admission_identity"]["selection_amendment_sha256"]}


def publish_plan(root: Path, enrollment: Path, qualification_spec: Path, output: Path,
                 *, readiness: Mapping[str, Any], runtime_inputs: Mapping[str, str] | None = None) -> Path:
    policy = verify_policy(root)
    batch, _ = verify_enrollment(enrollment)
    runtime = _runtime(dict(runtime_inputs)) if runtime_inputs is not None else policy["runtime"]
    if runtime["data_root"] != policy["runtime"]["data_root"]:
        raise ValueError("a rolling runtime successor must retain its declared study data root")
    if _open_ref(batch["policy"]) != root / "policy.json" or not set(readiness) <= set(plan.MODES):
        raise ValueError("rolling plan changed its policy or supplied unknown readiness")
    from .rapid_rolling_readiness import validate_canary
    for mode, reference in readiness.items():
        validate_canary(reference, runtime={key: runtime[key] for key in lanes.RUNTIME_KEYS}, mode=mode)
    workloads, campaigns = Path(runtime["workload_root"]), Path(runtime["campaign_dir"])
    sites = _sites(enrollment, qualification_spec, workloads)
    planned = plan.plan_lanes(sites, final=True, study_version=6, rolling_batch=batch["ordinal"])
    hashes = {}
    for lane in planned:
        path = campaigns / f"{lane.campaign_name}.yml"
        raw = plan.render_lane_campaign(lane, sites)
        if path.exists():
            if lanes._read(path) != raw:
                raise ValueError("rolling plan cannot replace an earlier campaign")
        else:
            admission.durable_create(path, raw)
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
    return _write(output, lanes.PLAN_TYPE, payload)


def capture_spec(root: Path, enrollment: Path, qualification_spec: Path, plan_receipt: Path) -> lanes.CaptureSpec:
    policy = verify_policy(root)
    batch, _ = verify_enrollment(enrollment)
    return _capture_spec_from_enrollment(root, enrollment, qualification_spec, plan_receipt, batch, policy)


def _capture_spec_from_enrollment(root: Path, enrollment: Path, qualification_spec: Path, plan_receipt: Path,
                                  batch: Mapping[str, Any], policy: Mapping[str, Any]) -> lanes.CaptureSpec:
    payload = admission._unpack(lanes._read(plan_receipt), lanes.PLAN_TYPE)
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


def verify_capture_plan(spec: lanes.CaptureSpec, *, require_current: bool = False) -> tuple[tuple[plan.Site, ...], dict[str, Any]]:
    # These facts live only inside this verification call. Public entry points
    # independently reopen enrollment; no prior operation supplies authority.
    batch, classes, policy = _verify_enrollment(spec.cohort)
    root = _open_ref(batch["policy"]).parent
    expected_spec = _capture_spec_from_enrollment(root, spec.cohort, spec.qualification_spec, spec.plan_receipt, batch, policy)
    if spec != expected_spec:
        raise ValueError("rolling spec changed frozen runtime, admission or input locations")
    sites = _sites_from_enrollment(batch, classes, spec.qualification_spec, spec.workload_root, require_current=require_current)
    value = admission._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
    _keys(value, {"study_version", "cohort_generation", "bindings", "runtime", "runtime_artifacts", "acquisition_provenance_sha256",
                 "qualification_spec_sha256", "sites", "lanes", "planned_trace_count", "readiness",
                 "declared_at", "formal_accepted_trace_count", "scientific_credit"}, "rolling plan")
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
        raw = plan.render_lane_campaign(lane, sites)
        if lanes._read(spec.campaign_dir / f"{lane.campaign_name}.yml") != raw:
            raise ValueError("rolling campaign changed sites, graph, visits or fixed settings")
        actual.append({**asdict(lane), "workload_ids": list(lane.workload_ids), "campaign_sha256": lanes._sha(raw)})
    if rows != actual or value["planned_trace_count"] != sum(lane.sample_count for lane in expected):
        raise ValueError("rolling plan omitted, repeated or invented visit lanes")
    return sites, value


def require_mode_readiness(spec: lanes.CaptureSpec, lane: plan.Lane, *, before: str | None = None) -> dict[str, Any]:
    _, payload = verify_capture_plan(spec)
    if lane.study_version != 6 or lane.role != "formal":
        raise ValueError("rolling readiness cannot authorize a historical or diagnostic lane")
    if lane.mode not in payload["readiness"]:
        raise ValueError(f"rolling {lane.mode} lacks its own successful current full canary")
    from .rapid_rolling_readiness import validate_canary
    facts = validate_canary(payload["readiness"][lane.mode], runtime={key: spec.serializable()[key] for key in lanes.RUNTIME_KEYS}, mode=lane.mode)
    expected_source = {**lanes._load(lanes._read(spec.source_manifest)), "image_digest": spec.collection_image_digest}
    if (facts.get("authority_source") != expected_source or facts.get("client_sha256") != lanes._sha(lanes._read(spec.client_binary))
        or facts.get("traffic_hashes") != {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}):
        raise ValueError("rolling setting readiness differs from the independently checked installed Source, client or traffic")
    publication = facts.get("source_equivalence_published_at")
    if publication is not None and (admission._utc(publication) > admission._utc(payload["declared_at"])
                                  or before is not None and admission._utc(publication) > admission._utc(before)):
        raise ValueError("rolling canary Source equivalence was not prospectively published before its plan and launch")
    return payload["readiness"][lane.mode]


def image_plan_check(spec: lanes.CaptureSpec, runtime: Mapping[str, Any]) -> dict[str, Any]:
    sites, payload = verify_capture_plan(spec, require_current=True)
    # This new authority must be the actual installed producer, not a host
    # supplied replacement for the collection image's implementation.
    relative = "src/qcsd_lab/rapid_rolling_capture.py"
    own = lanes._read(Path(__file__))
    if own != lanes._read(spec.runtime_source_root / relative) or own != lanes._read(spec.module_root / relative):
        raise ValueError("rolling authority differs from the installed and frozen source")
    modules = {path.relative_to(spec.module_root).as_posix(): lanes._sha(lanes._read(path))
               for base in (spec.module_root / "src/qcsd_lab", spec.module_root / "tools") for path in sorted(base.glob("*.py"))}
    return {"schema_version": 1, "artifact_type": lanes.IMAGE_PROOF_TYPE,
            **{key: runtime[key] for key in ("collection_image_digest", "runtime_source", "source_manifest_sha256",
                 "client_sha256", "base_launcher_sha256", "host_launcher_sha256", "qualification_implementation", "traffic_hashes")},
            "overlay_source_hashes": modules, "plan_receipt_sha256": lanes._sha(lanes._read(spec.plan_receipt)),
            "plan_payload": payload, "bindings": payload["bindings"], "sites": [asdict(site) for site in sites],
            "cohort_generation": "rolling-50", "acquisition_provenance_sha256": payload["acquisition_provenance_sha256"]}


def validate_host_launch(value: Any, *, expected_campaign: str, actual_image: str) -> None:
    _keys(value, {"spec", "root", "intent", "intent_sha256", "readiness_mount_roots"}, "rolling host launch")
    spec = lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item for key, item in value["spec"].items()})
    root, path = Path(value["root"]), Path(value["intent"])
    if (spec.collection_image_digest != actual_image or not root.is_relative_to(spec.data_root)
        or lanes._sha(lanes._read(path)) != value["intent_sha256"]):
        raise ValueError("rolling host launch changed its actual image, root or intent")
    lanes.executed_image_plan_check(spec.serializable())
    intent, _, lane, _ = lanes._intent_and_lineage(spec, root, path)
    if lane.study_version != 6 or intent["actuator"] != "run" or lane.campaign_name != expected_campaign:
        raise ValueError("rolling host launch requires its exact serial formal lane")
    if value["readiness_mount_roots"] != [str(path) for path in readiness_roots(spec, expected_campaign)]:
        raise ValueError("rolling host launch changed its derived read-only canary mounts")
    require_mode_readiness(spec, lane)


def publish_successor(spec: lanes.CaptureSpec, lane_name: str, generation: int, output: Path) -> Path:
    sites, value = verify_capture_plan(spec)
    base = next((plan.Lane(**{key: tuple(item) if key == "workload_ids" else item for key, item in row.items()
                              if key != "campaign_sha256"}) for row in value["lanes"] if row["campaign_name"] == lane_name), None)
    if base is None or generation != base.generation + 1:
        raise ValueError("rolling recovery must name the immediate failed lane successor")
    lane = plan.successor_lane(base, generation)
    raw = plan.render_lane_campaign(lane, sites)
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
print(json.dumps({'receipt':str(receipt),'facts':e.verify_launch_receipt(receipt,spec=spec,evidence_root=root)},sort_keys=True,allow_nan=False))
""".strip()


def enrollment_roots(spec: lanes.CaptureSpec) -> list[Path]:
    """Derive transport from sealed policy and enrollment metadata only.

    The installed plan check still reopens every terminal and prepared graph.
    Mount derivation does not repeat that scientific verification on the host.
    """
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
        context = admission.load_admission_context(context_root)
        if _admission_identity(context) != policy["admission_identity"]:
            raise ValueError("rolling transport admission context changed its policy inputs")
        # Admission inputs, module Sources, retained root-role records and all
        # attempt artifacts are closed relative references under this root.
        roots.add(context_root)
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


def readiness_roots(spec: lanes.CaptureSpec, campaign_name: str) -> list[Path]:
    _, payload = verify_capture_plan(spec)
    proof = {"plan_payload": payload}
    lane = lanes._lane(proof, campaign_name)
    reference = require_mode_readiness(spec, lane)
    from .rapid_rolling_readiness import readiness_mount_roots
    return sorted(set(enrollment_roots(spec)) | set(readiness_mount_roots(reference,
        runtime={key: spec.serializable()[key] for key in lanes.RUNTIME_KEYS}, mode=lane.mode)))


def lane_check_command(spec: lanes.CaptureSpec, root: Path, target: Path, *, complete: bool) -> list[str]:
    command = lanes.image_check_command(spec, inherit_environment=False, campaign_name=target.parent.name)
    index = command.index("--entrypoint")
    mount = f"{root}:{root}:{'rw' if complete else 'ro'}"
    matches = [position + 1 for position, item in enumerate(command[:index])
               if item == "--volume" and command[position + 1].split(":")[1] == str(root)]
    if matches:
        command[matches[0]] = mount
    else:
        command[index:index] = ["--volume", mount]
    command[-2:] = [LANE_CHECK_SCRIPT, json.dumps({"spec": spec.serializable(), "root": str(root),
        "target": str(target), "complete": complete}, sort_keys=True)]
    return command


def check_lane_in_image(spec: lanes.CaptureSpec, root: Path, target: Path, *, complete: bool) -> dict[str, Any]:
    """Run the unchanged ordinary deep verifier in the actual bound image."""
    verify_capture_plan(spec)
    root = lanes._regular_directory(root)
    target = target.absolute()
    if not target.is_relative_to(root / "lanes"):
        raise ValueError("rolling lane deep target escapes its declared evidence root")
    command = lane_check_command(spec, root, target, complete=complete)
    start = {"command": command, "started_at": admission._now()}
    directory = root / "lane-checks" / lanes._sha(admission._json(start))
    directory.mkdir(parents=True)
    start_path = directory / "actual-started.json"
    admission.durable_create(start_path, admission._json(start))
    error = None
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=600)
        status, stdout, stderr = result.returncode, result.stdout.encode(), result.stderr.encode()
    except (OSError, subprocess.SubprocessError) as failure:
        status = None
        stdout, stderr = getattr(failure, "stdout", None) or b"", getattr(failure, "stderr", None) or b""
        stdout = stdout.encode() if isinstance(stdout, str) else stdout
        stderr = stderr.encode() if isinstance(stderr, str) else stderr
        error = {"type": type(failure).__name__, "message": str(failure)}
    end = {"command": command, "started_at": start["started_at"], "completed_at": admission._now(),
           "returncode": status, "invocation_error": error,
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
    return {"closure": _ref(closure), "receipt": value["receipt"], **value["facts"]}


def _reopen_lane_check(reference: Any) -> tuple[lanes.CaptureSpec, Path, dict[str, Any], plan.Lane, tuple[plan.Site, ...]]:
    path = _open_ref(reference)
    value = admission._unpack(lanes._read(path), LANE_CHECK_TYPE)
    _keys(value, {"spec", "root", "target", "complete", "started", "completed", "receipt", "facts"}, "lane deep closure")
    if type(value["complete"]) is not bool:
        raise ValueError("rolling deep closure action is invalid")
    spec = lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item for key, item in value["spec"].items()})
    root, target = lanes._regular_directory(Path(value["root"])), Path(value["target"])
    verify_capture_plan(spec)
    start = lanes._load(lanes._read(_open_ref(value["started"])))
    end = lanes._load(lanes._read(_open_ref(value["completed"])))
    command = lane_check_command(spec, root, target, complete=value["complete"])
    if (set(start) != {"command", "started_at"} or set(end) != {"command", "started_at", "completed_at", "returncode", "invocation_error", "stdout", "stderr"}
        or start["command"] != command or end["command"] != command or end["started_at"] != start["started_at"]
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
    if lane.study_version != 6 or lane.role != "formal" or intent["actuator"] != "run":
        raise ValueError("rolling final closure cannot promote diagnostic or parallel evidence")
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
    verify_policy(root)
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
            for visit in range(4):
                slot = index, lane.mode, (lane.block - 1) * 4 + visit
                if slot not in expected or slot in observed:
                    raise ValueError("rolling corpus repeats or invents a formal class/setting/visit slot")
                observed.add(slot)
        rows.append({"closure": dict(reference), "spec": spec.serializable(), "receipt": _ref(receipt), "logical_lane": lane.logical_name,
                     "accepted": result["accepted"], "result_seal_sha256": result["result_seal_sha256"]})
    if observed != expected or sum(row["accepted"] for row in rows) != 16000:
        raise ValueError("rolling corpus does not contain exactly fifty by five by sixty-four accepted traces")
    return {"policy": _ref(root / "policy.json"), "final_enrollment": _ref(batches[-1]),
               "classes": classes, "lanes": rows, "accepted": 16000, "lane_count": len(rows),
               "scientific_credit": True}


def publish_corpus(root: Path, closures: list[Any], output: Path) -> dict[str, Any]:
    if not output.absolute().is_relative_to(root.absolute()):
        raise ValueError("rolling corpus manifest must remain inside its study root")
    payload = {**_corpus_facts(root, closures), "closed_at": admission._now()}
    _write(output, CORPUS_TYPE, payload)
    return verify_corpus_manifest(root, output)


def verify_corpus_manifest(root: Path, path: Path) -> dict[str, Any]:
    value = admission._unpack(lanes._read(path), CORPUS_TYPE)
    _keys(value, {"policy", "final_enrollment", "classes", "lanes", "accepted", "lane_count", "scientific_credit", "closed_at"}, "rolling corpus")
    expected = _corpus_facts(root, [row["closure"] for row in value["lanes"]])
    if any(value[key] != item or type(value[key]) is not type(item) for key, item in expected.items()) or admission._utc(value["closed_at"]) > admission._utc(admission._now()):
        raise ValueError("rolling final manifest differs from its independently reopened exact corpus")
    return {"valid": True, "accepted": 16000, "lane_count": value["lane_count"], "manifest": str(path), "scientific_credit": True}
