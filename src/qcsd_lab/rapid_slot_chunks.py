"""Prospective remaining-slot lanes; historical four-visit plans stay exact.

The prior progress artifact excludes already accepted slots from planning. It
does not grant scientific credit to a new plan. Final aggregation must reopen
the original and new physical closures independently.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, replace
from functools import wraps
from importlib import import_module
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

import yaml

from . import rapid_capture_plan as legacy
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_additive_static_enrollment as enrollment
from . import rapid_site_admission as receipts
from . import supplied_static_graph as graph

POLICY_TYPE = "qcsd-complete-graph-remaining-slot-chunk-policy-v1"
PLAN_TYPE = "qcsd-complete-graph-remaining-slot-chunk-plan-v1"
PROGRESS_TYPE = "root-reopened-remaining-slot-chunk-scientific-progress-v1"
CONTRACT = "unchanged-full-graphs-with-authenticated-remaining-0-through-63-slots-v1"
LAYOUT = "explicit-logical-offset-bounded-sixteen-visit-chunks-v1"
MAX_VISITS = 16
SLOTS_PER_CLASS_MODE = 64
FINAL_TARGET = 16000
CONTROL_MODULES = ("rapid_slot_chunks", "rapid_capture_plan", "rapid_lane_evidence", "rapid_rolling_capture")
LAUNCH_NAME_PATTERN = (
    r"^rapid-selected50-slot-v1-p([0-9a-f]{16})-s(0[1-9]|[1-4][0-9]|50)-"
    r"(undefended|front|tamaraw|buflo|cs-buflo)-v([0-5][0-9]|6[0-3])-"
    r"n(0[1-9]|1[0-6])-c(0[1-9]|[1-5][0-9]|6[0-4])(-g(0[2-9]|[1-9][0-9]))?$"
)


def validate_launcher_campaign(campaign, expected_mode: str) -> None:
    """Check the installed chunk shape before the unchanged v6 intent gate.

    The namespace grants no plan authority. The subsequent rolling image
    preflight still reopens the sealed policy, slot rows, campaign and intent.
    Generic resume is excluded by the host selector.
    """
    match = re.fullmatch(LAUNCH_NAME_PATTERN, campaign.name)
    if match is None:
        raise ValueError("chunk launcher requires its exact registered namespace")
    start, count = int(match[4]), int(match[5])
    if (start + count > SLOTS_PER_CLASS_MODE or expected_mode != match[3]
            or campaign.schema_version != 1 or campaign.purpose != "evaluation"
            or campaign.profile != "research-1200" or campaign.request_policies != ("as-defined",)
            or not 1 <= len(campaign.workloads) <= 5
            or len({workload.id for workload in campaign.workloads}) != len(campaign.workloads)
            or any(type(workload.visits) is not int or workload.visits != count
                   for workload in campaign.workloads)
            or len(campaign.defenses) != 1 or campaign.defenses[0].name != expected_mode
            or (campaign.chaff_qualification_set is None) == (expected_mode != "undefended")):
        raise ValueError("chunk launcher changed its bounded visits, mode or full workload contract")


def _owned_action(function):
    """Close fresh dependencies within this action before returning authority."""
    @wraps(function)
    def run(*args, **kwargs):
        from .rapid_operation_facts import OperationFacts, current_context
        context = kwargs.get("_context") or current_context()
        if context is None:
            context = OperationFacts()
            context.begin_action()
        with context.scope():
            result = function(*args, **kwargs)
            from .rapid_partial_progress import close_operation
            close_operation(context)
            return result
    return run


def _raw(path: Path) -> bytes:
    from .rapid_operation_facts import current_context
    context = current_context()
    return lanes._read(path) if context is None else context.watch_file(path)


def _publication_path(path: Path, study: Path) -> Path:
    path = path.absolute()
    if (".." in path.parts or any(c in str(path) for c in "\n\r\0:")
            or not path.is_relative_to(study) or path == study
            or any(item.is_symlink() for item in (path, *path.parents))
            or path.exists()):
        raise ValueError("chunk publication needs an unclaimed nonlinked path inside its enrollment study")
    return path


def sources() -> dict[str, str]:
    return {name: graph.digest(_raw(Path(import_module("qcsd_lab." + name).__file__)))
            for name in CONTROL_MODULES}


@dataclass(frozen=True)
class ChunkLane:
    role: str
    block: int
    shard: int
    mode: str
    campaign_name: str
    workload_ids: tuple[str, ...]
    visits_per_workload: int
    qualification_set: str | None
    slot_start: int
    slot_policy_sha256: str
    generation: int = 1
    study_version: int = 6
    lane_layout: str = LAYOUT

    @property
    def sample_count(self) -> int:
        return len(self.workload_ids) * self.visits_per_workload

    @property
    def logical_name(self) -> str:
        return name(self, 1)


def name(lane: ChunkLane, generation: int) -> str:
    if type(generation) is not int or not 1 <= generation <= legacy.MAX_LANE_GENERATION:
        raise ValueError("chunk recovery generation is outside 1..99")
    value = (f"rapid-selected50-slot-v1-p{lane.slot_policy_sha256[:16]}-s{lane.shard:02d}-"
             f"{lane.mode}-v{lane.slot_start:02d}-n{lane.visits_per_workload:02d}-c{lane.block:02d}")
    return value if generation == 1 else value + f"-g{generation:02d}"


def checked_lane(value: Mapping[str, Any]) -> ChunkLane:
    fields = set(ChunkLane.__dataclass_fields__)
    rolling._keys(value, fields, "registered slot chunk lane")
    if not isinstance(value["workload_ids"], (list, tuple)):
        raise ValueError("chunk workload identity needs an explicit ordered list")
    lane = ChunkLane(**{key: tuple(item) if key == "workload_ids" else item for key, item in value.items()})
    if (lane.role != "formal" or type(lane.study_version) is not int or lane.study_version != 6
            or lane.lane_layout != LAYOUT or lane.mode not in legacy.MODES
            or type(lane.block) is not int or not 1 <= lane.block <= 64
            or type(lane.shard) is not int or not 1 <= lane.shard <= 50
            or type(lane.slot_start) is not int or not 0 <= lane.slot_start < 64
            or type(lane.visits_per_workload) is not int or not 1 <= lane.visits_per_workload <= MAX_VISITS
            or lane.slot_start + lane.visits_per_workload > 64
            or not isinstance(lane.slot_policy_sha256, str) or legacy.SHA256_RE.fullmatch(lane.slot_policy_sha256) is None
            or not 1 <= len(lane.workload_ids) <= 5 or len(set(lane.workload_ids)) != len(lane.workload_ids)
            or any(not isinstance(item, str) or legacy.IDENTIFIER_RE.fullmatch(item) is None for item in lane.workload_ids)
            or (lane.qualification_set is None) != (lane.mode == "undefended")
            or lane.qualification_set is not None and (not isinstance(lane.qualification_set, str)
                or legacy.IDENTIFIER_RE.fullmatch(lane.qualification_set) is None)
            or lane.campaign_name != name(lane, lane.generation)):
        raise ValueError("chunk lane changes its policy, logical slots, count, mode or identity")
    return lane


def successor(lane: ChunkLane, generation: int) -> ChunkLane:
    checked_lane(asdict(lane))
    if type(generation) is not int or generation != lane.generation + 1:
        raise ValueError("chunk recovery must preserve slots and advance one generation")
    return replace(lane, generation=generation, campaign_name=name(lane, generation))


def _registered_slots(lane, accepted: int, progress_type: str) -> range:
    if type(accepted) is not int or accepted <= 0 or lane.sample_count != accepted:
        raise ValueError("prior progress changed its exact accepted lane count")
    if isinstance(lane, ChunkLane):
        checked_lane(asdict(lane))
        if progress_type != PROGRESS_TYPE:
            raise ValueError("chunk progress needs its explicit new accepted-slot contract")
        return range(lane.slot_start, lane.slot_start + lane.visits_per_workload)
    if (not isinstance(lane, legacy.Lane) or lane.role != "formal" or lane.study_version != 6
            or lane.visits_per_workload != 4 or not 1 <= lane.block <= 16
            or lane.campaign_name != legacy._campaign_name(lane.role, lane.block, lane.shard, lane.mode,
                                                           lane.generation, lane.study_version)):
        raise ValueError("prior progress must retain its original registered four-visit identity")
    return range((lane.block - 1) * 4, lane.block * 4)


def prior_progress(reference: Mapping[str, str], classes: list[dict]) -> tuple[dict, set[tuple[int, str, int]], set[Path]]:
    from . import rapid_partial_progress as partial
    candidate_path = partial._open(reference)
    if lanes._load(_raw(candidate_path)).get("artifact_type") == partial.TYPE:
        value, files = partial.read_inputs(reference, classes=classes)
        slots = {(r["class_index"], r["mode"], r["visit"]) for r in value["accepted_formal_slots"]}
        return value, slots, files
    # The new boundary already authenticates an optional permission mode;
    # the unchanged historical helper receives only its exact two-key schema.
    path = rolling._open_ref({key: reference[key] for key in ("path", "sha256")})
    value = lanes._load(_raw(path))
    enrollment._progress(value, classes)
    if (value.get("artifact_type") not in {"root-reopened-rolling-static-scientific-progress", PROGRESS_TYPE}
            or value.get("final_target") != FINAL_TARGET or type(value.get("final_target")) is not int
            or type(value.get("historical_browser_traces_excluded")) is not int
            or value["historical_browser_traces_excluded"] < 0
            or not isinstance(value.get("lanes"), list) or not value["lanes"]):
        raise ValueError("chunk policy needs the authenticated genuine prior accepted-slot manifest")
    files, total, derived = {path}, 0, set()
    class_index = {row["candidate_id"]: row["class_index"] for row in classes}
    for row in value["lanes"]:
        rolling._keys(row, {"accepted", "complete_reference", "lane_closure_reference"}, "prior physical lane")
        complete_path = rolling._open_ref(row["complete_reference"])
        closure_path = rolling._open_ref(row["lane_closure_reference"])
        complete = receipts._unpack(_raw(complete_path), lanes.COMPLETE_TYPE)
        closure = receipts._unpack(_raw(closure_path), rolling.LANE_CHECK_TYPE)
        if (type(row["accepted"]) is not int or row["accepted"] <= 0
                or type(complete["accepted"]) is not int or complete["accepted"] != row["accepted"]
                or type(complete["host_returncode"]) is not int or complete["host_returncode"] != 0
                or type(closure["complete"]) is not bool or closure["receipt"] != row["complete_reference"]
                or closure["facts"]["accepted"] != row["accepted"]
                or any(closure["facts"].get(key) != item for key, item in complete.items())):
            raise ValueError("prior slot manifest changes a genuine closed physical lane")
        for key in ("started", "completed"):
            files.add(rolling._open_ref(closure[key]))
        completed = lanes._load(_raw(rolling._open_ref(closure["completed"])))
        started = lanes._load(_raw(rolling._open_ref(closure["started"])))
        if (type(completed.get("returncode")) is not int or completed["returncode"] != 0
                or completed.get("invocation_error") is not None or started["command"] != completed["command"]
                or started["started_at"] != completed["started_at"]
                or not receipts._utc(started["started_at"]) <= receipts._utc(completed["completed_at"])
                    <= receipts._utc(value["closed_at"])):
            raise ValueError("prior accepted-slot manifest includes a failed installed check")
        root = lanes._regular_directory(Path(closure["root"]))
        target = (complete_path.parent / "intent.json") if closure["complete"] else complete_path
        if closure["target"] != str(target):
            raise ValueError("prior deep operation changes its actual complete or verify action target")
        for key in ("stdout", "stderr"):
            files.add(receipts._child(root, completed[key]))
        if lanes._load(lanes._object(root, completed["stdout"])) != {"receipt": str(complete_path), "facts": closure["facts"]}:
            raise ValueError("prior accepted slots differ from their actual installed deep output")
        intent_path = receipts._child(root, complete["intent"])
        intent = lanes._payload(intent_path, lanes.INTENT_TYPE)
        lineage_path = receipts._child(root, intent["lineage"])
        lineage = lanes._payload(lineage_path, lanes.LINEAGE_TYPE)
        proof = lineage["image_check"]["proof"]
        proof_plan = lanes.plan_payload(_raw(Path(closure["spec"]["plan_receipt"])))
        if (complete["lineage_receipt_sha256"] != intent["lineage"]["sha256"]
                or proof["plan_payload"] != proof_plan
                or proof["plan_receipt_sha256"] != graph.digest(_raw(Path(closure["spec"]["plan_receipt"])))
                or complete["campaign_name"] != intent["campaign_name"]
                or complete["campaign_sha256"] != intent["campaign_sha256"]
                or complete["collection_image_digest"] != proof["collection_image_digest"]
                or complete["lab_commit"] != proof["runtime_source"]["lab_commit"]):
            raise ValueError("prior lane changes its original sealed plan, runtime or intent")
        lane = lanes._lane(proof, complete["campaign_name"])
        registered = _registered_slots(lane, row["accepted"], value["artifact_type"])
        if isinstance(lane, ChunkLane) and (proof_plan.get("lane_layout") != LAYOUT
                or proof_plan.get("slot_chunk_policy", {}).get("sha256") != lane.slot_policy_sha256):
            raise ValueError("prior chunk lost its sealed plan and slot-policy binding")
        result_root = Path(closure["facts"]["result_root"])
        seal_path, experiment_path = result_root / "evidence.sha256", result_root / "experiment.json"
        from .verification import _read_checksums
        checksums = _read_checksums(result_root, seal_path)
        if (graph.digest(_raw(seal_path)) != complete["result_seal_sha256"]
                or checksums.get("experiment.json") != graph.digest(_raw(experiment_path))):
            raise ValueError("prior slot mapping changes its deep-bound actual experiment")
        experiment = lanes._load(_raw(experiment_path))
        samples = experiment["samples"]
        expected_samples = {(workload, lane.mode, visit) for workload in lane.workload_ids
                            for visit in range(lane.visits_per_workload)}
        if (experiment["status"] != "complete" or experiment["name"] != lane.campaign_name
                or experiment["summary"]["accepted"] != lane.sample_count
                or len(samples) != lane.sample_count
                or {(sample["workload_id"], sample["defense"], sample["visit"]) for sample in samples} != expected_samples
                or any(sample["state"] != "accepted" or type(sample["visit"]) is not int for sample in samples)):
            raise ValueError("prior sample mapping lost its actual accepted local visits")
        sites = {site["workload_id"]: site["candidate_id"] for site in proof_plan["sites"]}
        for workload, mode, visit in expected_samples:
            if sites.get(workload) not in class_index:
                raise ValueError("prior slots renumber or replace an enrolled class")
            slot = (class_index[sites[workload]], mode, registered[visit])
            if slot in derived:
                raise ValueError("prior progress repeats an actual logical sample slot")
            derived.add(slot)
        files.update({intent_path, lineage_path, Path(closure["spec"]["plan_receipt"]), seal_path, experiment_path})
        total += row["accepted"]
        files.update({complete_path, closure_path})
    if total != value["formal_accepted_trace_count"]:
        raise ValueError("prior accepted slots differ from their closed lane count")
    slots = {(row["class_index"], row["mode"], row["visit"]) for row in value["accepted_formal_slots"]}
    if slots != derived:
        raise ValueError("prior counter moves accepted slots away from their sealed original lane identities")
    return value, slots, files


def ranges(accepted: set[int], *, maximum: int = MAX_VISITS) -> tuple[tuple[int, int], ...]:
    if (type(maximum) is not int or not 1 <= maximum <= MAX_VISITS
            or any(type(visit) is not int or not 0 <= visit < 64 for visit in accepted)):
        raise ValueError("remaining-slot range changes its declared 0..63/maximum16 bounds")
    answer, position = [], 0
    while position < 64:
        if position in accepted:
            position += 1
            continue
        start = position
        while position < 64 and position not in accepted and position - start < maximum:
            position += 1
        answer.append((start, position - start))
    return tuple(answer)


def _base_spec(value: Mapping[str, str]) -> lanes.CaptureSpec:
    rolling._keys(value, lanes.PATH_KEYS | {"collection_image_digest", "execution_generation"}, "chunk base spec")
    result = lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item for key, item in value.items()})
    lanes._check_spec(result)
    payload = receipts._unpack(_raw(result.plan_receipt), lanes.PLAN_TYPE)
    if payload.get("study_version") != 6 or "scheduling" in payload or "lane_layout" in payload:
        raise ValueError("chunk base must be its current qualified serial four-visit plan")
    return result


@_owned_action
def publish_policy(base_spec: lanes.CaptureSpec, prior: Mapping[str, str], output: Path, *, modes: Sequence[str],
                   maximum_visits: int = MAX_VISITS) -> Path:
    base_spec = _base_spec(base_spec.serializable())
    _, base = rolling.verify_capture_plan(base_spec)
    from .tamaraw_fixed_configuration import policy as fixed_tamaraw_policy
    if fixed_tamaraw_policy(base) is not None:
        raise ValueError("fixed Tamaraw chunks require a distinct condition target map; historical TAM slots cannot be carried")
    enrollment_path = base_spec.cohort
    batch, classes, policy = rolling._verify_enrollment(enrollment_path)
    value, accepted, prior_files = prior_progress(prior, classes)
    from .rapid_operation_facts import current_context
    for path in prior_files:
        current_context().watch_file(path)
    modes = list(modes)
    if (not modes or modes != [mode for mode in legacy.MODES if mode in modes]
            or len(modes) != len(set(modes)) or type(maximum_visits) is not int or not 1 <= maximum_visits <= MAX_VISITS):
        raise ValueError("chunk policy needs ordered known settings and maximum1..16 visits")
    if not set(modes) <= set(base["readiness"]):
        raise ValueError("chunk modes need their own current complete-site readiness")
    runtime = rolling._runtime(base["runtime"])
    payload = {"contract": CONTRACT, "lane_layout": LAYOUT, "enrollment": rolling._ref(enrollment_path),
        "base_spec": base_spec.serializable(), "base_four_visit_plan": rolling._ref(base_spec.plan_receipt),
        "enrollment_policy": batch["policy"], "prior_progress": dict(prior),
        "prior_slots": [list(row) for row in sorted(accepted)], "prior_count": len(accepted),
        "modes": modes, "maximum_visits": maximum_visits, "visits_per_class_mode": 64,
        "formal_trace_target": FINAL_TARGET, "implementation_sources": sources(), "runtime": runtime,
        "published_at": receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0}
    output = _publication_path(output, rolling._open_ref(batch["policy"]).parent)
    from .rapid_partial_progress import close_operation
    close_operation(current_context())
    path = rolling._write(output, POLICY_TYPE, payload)
    validate_policy(rolling._ref(path))
    return path


@_owned_action
def validate_policy(reference: Mapping[str, str]) -> tuple[dict, dict, list[dict], dict]:
    path = rolling._open_ref(reference)
    value = receipts._unpack(_raw(path), POLICY_TYPE)
    rolling._keys(value, {"contract", "lane_layout", "enrollment", "enrollment_policy", "prior_progress", "prior_slots",
        "prior_count", "modes", "maximum_visits", "visits_per_class_mode", "formal_trace_target", "implementation_sources",
        "runtime", "published_at", "scientific_credit", "formal_accepted_trace_count", "base_spec", "base_four_visit_plan"}, "slot chunk policy")
    base_spec = _base_spec(value["base_spec"])
    _, base = rolling.verify_capture_plan(base_spec)
    from .tamaraw_fixed_configuration import policy as fixed_tamaraw_policy
    if fixed_tamaraw_policy(base) is not None:
        raise ValueError("fixed Tamaraw chunks require a distinct condition target map; historical TAM slots cannot be carried")
    enrollment_path = rolling._open_ref(value["enrollment"])
    batch, classes, policy = rolling._verify_enrollment(enrollment_path)
    prior, accepted, _ = prior_progress(value["prior_progress"], classes)
    if (value["contract"] != CONTRACT or value["lane_layout"] != LAYOUT or value["implementation_sources"] != sources()
            or value["enrollment_policy"] != batch["policy"] or value["runtime"] != rolling._runtime(base["runtime"])
            or value["enrollment"] != rolling._ref(base_spec.cohort)
            or value["base_four_visit_plan"] != rolling._ref(base_spec.plan_receipt)
            or value["prior_slots"] != [list(row) for row in sorted(accepted)] or value["prior_count"] != len(accepted)
            or type(value["prior_count"]) is not int or value["visits_per_class_mode"] != 64
            or type(value["visits_per_class_mode"]) is not int or value["formal_trace_target"] != FINAL_TARGET
            or type(value["formal_trace_target"]) is not int or value["scientific_credit"] is not False
            or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or not isinstance(value["modes"], list)
            or value["modes"] != [mode for mode in legacy.MODES if mode in value["modes"]] or not value["modes"]
            or not set(value["modes"]) <= set(base["readiness"])
            or type(value["maximum_visits"]) is not int or not 1 <= value["maximum_visits"] <= MAX_VISITS
            or not receipts._utc(batch["declared_at"]) <= receipts._utc(value["published_at"]) <= receipts._utc(receipts._now())
            or not receipts._utc(prior["closed_at"]) <= receipts._utc(value["published_at"])
            or not receipts._utc(base["declared_at"]) <= receipts._utc(value["published_at"])
            or not path.is_relative_to(rolling._open_ref(batch["policy"]).parent)):
        raise ValueError("chunk policy changed its actual membership, prior slots, Source, runtime or limits")
    return value, batch, classes, policy


def planned_lanes(sites: Sequence[legacy.Site], classes: Sequence[dict], policy: Mapping[str, Any],
                  policy_reference: Mapping[str, str], *, shard: int) -> tuple[ChunkLane, ...]:
    sites = legacy._check_sites(sites, final=True, study_version=6)
    ids = {row["workload_id"]: row["class_index"] for row in classes}
    if len(ids) != len(classes) or any(site.workload_id not in ids for site in sites):
        raise ValueError("chunk planner changed its immutable class/workload identity")
    accepted = {tuple(row) for row in policy["prior_slots"]}
    answer = []
    for mode in policy["modes"]:
        grouped = defaultdict(list)
        registered_vectors = set()
        for site in sites:
            completed = {visit for index, setting, visit in accepted if index == ids[site.workload_id] and setting == mode}
            vector = ranges(completed, maximum=policy["maximum_visits"])
            registered_vectors.add(vector)
            for start, count in vector:
                grouped[start, count].append(site)
        if len(registered_vectors) != 1:
            raise ValueError("chunk groups need the same remaining slots to preserve their exact named qualification cohort")
        for block, ((start, count), selected) in enumerate(sorted(grouped.items()), 1):
            lane = ChunkLane("formal", block, shard, mode, "", tuple(site.workload_id for site in selected),
                count, None if mode == "undefended" else selected[0].qualification_set, start, policy_reference["sha256"])
            lane = replace(lane, campaign_name=name(lane, 1))
            answer.append(checked_lane(asdict(lane)))
    planned = {(ids[workload], lane.mode, lane.slot_start + local)
               for lane in answer for workload in lane.workload_ids for local in range(lane.visits_per_workload)}
    expected = {(ids[site.workload_id], mode, visit) for site in sites for mode in policy["modes"] for visit in range(64)} - accepted
    if (planned != expected or sum(lane.sample_count for lane in answer) != len(planned)
            or planned & accepted):
        raise ValueError("chunk plan repeats accepted slots, loses gaps or exceeds the fixed64 target")
    return tuple(answer)


def render(lane: ChunkLane, sites: Sequence[legacy.Site], **options) -> bytes:
    checked_lane(asdict(lane))
    if lane.mode != "tamaraw" and "tamaraw_configuration_policy" in options:
        options = {**options, "tamaraw_configuration_policy": None}
    if lane.mode != "front" and "front_configuration_policy" in options:
        options = {**options, "front_configuration_policy": None}
    selected = tuple(site for workload in lane.workload_ids for site in sites if site.workload_id == workload)
    if len(selected) != len(lane.workload_ids):
        raise ValueError("chunk campaign changed its complete selected workload graph")
    base = legacy.Lane("formal", 1, lane.shard, lane.mode,
        legacy._campaign_name("formal", 1, lane.shard, lane.mode, 1, 6), lane.workload_ids, 4,
        lane.qualification_set, 1, 6)
    document = yaml.safe_load(legacy.render_lane_campaign(base, selected, **options))
    document.update(name=lane.campaign_name, seed=int(graph.digest(lane.campaign_name.encode())[:16], 16),
                    workloads={workload: lane.visits_per_workload for workload in lane.workload_ids})
    return yaml.safe_dump(document, sort_keys=False, width=100).encode()


def is_plan(path: Path) -> bool:
    value = lanes._load(_raw(path))
    return isinstance(value, dict) and value.get("receipt_type") == PLAN_TYPE


def _render_options(value: Mapping[str, Any]) -> dict[str, Any]:
    return {"static_capture_limits": value.get("capture_limits"),
            "buflo_duration_policy": value.get("buflo_duration_policy"),
            "application_body_identity_policy": value.get("application_body_identity_policy"),
            "tamaraw_configuration_policy": value.get("tamaraw_configuration_policy"),
            "front_configuration_policy": value.get("front_configuration_policy"),
            "qualification_delivery_compatibility": value.get("qualification_delivery_compatibility")}


def _row(lane: ChunkLane, raw: bytes) -> dict[str, Any]:
    return {**asdict(lane), "workload_ids": list(lane.workload_ids), "campaign_sha256": graph.digest(raw)}


def input_files(value: Mapping[str, Any]) -> set[Path]:
    """Exact metadata for slot authority; workload/raw fences remain the base's."""
    policy_path = rolling._open_ref(value["slot_chunk_policy"])
    policy = receipts._unpack(_raw(policy_path), POLICY_TYPE)
    files = {policy_path, rolling._open_ref(policy["base_four_visit_plan"]),
             rolling._open_ref(policy["enrollment"]), rolling._open_ref(policy["enrollment_policy"])}
    _, _, classes, _ = validate_policy(value["slot_chunk_policy"])
    files.update(prior_progress(policy["prior_progress"], classes)[2])
    previous = value.get("previous_chunk_plan")
    seen = set()
    while previous is not None:
        path = rolling._open_ref(previous)
        if path in seen or len(seen) >= legacy.MAX_LANE_GENERATION:
            raise ValueError("chunk recovery plan ancestry contains a cycle or too many generations")
        seen.add(path)
        files.add(path)
        previous = receipts._unpack(_raw(path), PLAN_TYPE).get("previous_chunk_plan")
    return files


@_owned_action
def publish_plan(base_spec: lanes.CaptureSpec, policy_reference: Mapping[str, str], output: Path,
                 *, _context=None) -> Path:
    from .rapid_operation_facts import current_context
    _context = current_context() if _context is None else _context
    base_spec = _base_spec(base_spec.serializable())
    sites, base = rolling.verify_capture_plan(base_spec, _context=_context)
    policy, batch, classes, _ = validate_policy(policy_reference)
    if policy["base_spec"] != base_spec.serializable():
        raise ValueError("chunk plan changes its current qualified base spec")
    output = _publication_path(output, rolling._open_ref(batch["policy"]).parent)
    planned = planned_lanes(sites, classes, policy, policy_reference, shard=batch["ordinal"])
    if not planned:
        raise ValueError("chunk plan has no remaining sample slots")
    if _context is not None:
        for path in prior_progress(policy["prior_progress"], classes)[2]:
            _context.watch_file(path)
        _context.watch_file(rolling._open_ref(policy_reference))
        _context.check()
    from .rapid_partial_progress import close_operation
    close_operation()
    rows = []
    for lane in planned:
        raw = render(lane, sites, **_render_options(base))
        path = base_spec.campaign_dir / (lane.campaign_name + ".yml")
        receipts.durable_create(path, raw)
        if _context is not None:
            _context.watch_file(path)
        rows.append(_row(lane, raw))
    value = {**base, "lanes": rows, "planned_trace_count": sum(lane.sample_count for lane in planned),
             "readiness": {mode: base["readiness"][mode] for mode in policy["modes"]},
             "declared_at": receipts._now(), "lane_layout": LAYOUT,
             "slot_chunk_policy": dict(policy_reference), "base_four_visit_plan": rolling._ref(base_spec.plan_receipt),
             "previous_chunk_plan": None}
    if _context is not None:
        _context.check()
    from .rapid_partial_progress import close_operation
    close_operation()
    return rolling._write(output, PLAN_TYPE, value)


@_owned_action
def verify_plan(spec: lanes.CaptureSpec, *, require_current: bool = False, _context=None):
    from .rapid_operation_facts import current_context
    _context = current_context() if _context is None else _context
    value = receipts._unpack(_raw(spec.plan_receipt), PLAN_TYPE)
    dependencies = input_files(value)
    if _context is not None:
        for path in dependencies:
            _context.watch_file(path)
    policy, batch, classes, _ = validate_policy(value.get("slot_chunk_policy"))
    base_spec = _base_spec(policy["base_spec"])
    if spec != replace(base_spec, plan_receipt=spec.plan_receipt):
        raise ValueError("chunk spec changed its qualified runtime, graphs or inputs")
    sites, base = rolling.verify_capture_plan(base_spec, require_current=require_current, _context=_context)
    rolling._keys(value, set(base) | {"lane_layout", "slot_chunk_policy", "base_four_visit_plan", "previous_chunk_plan"},
                  "remaining-slot chunk plan")
    changed = {"lanes", "planned_trace_count", "readiness", "declared_at"}
    if (any(value[key] != item or type(value[key]) is not type(item) for key, item in base.items() if key not in changed)
            or value["lane_layout"] != LAYOUT or value["base_four_visit_plan"] != rolling._ref(base_spec.plan_receipt)
            or value["readiness"] != {mode: base["readiness"][mode] for mode in policy["modes"]}
            or not receipts._utc(policy["published_at"]) <= receipts._utc(value["declared_at"]) <= receipts._utc(receipts._now())):
        raise ValueError("chunk plan changes qualified current Source, readiness, profile, caps or graphs")
    expected = planned_lanes(sites, classes, policy, value["slot_chunk_policy"], shard=batch["ordinal"])
    rows = value["lanes"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("chunk plan has no registered remaining slots")
    if value["previous_chunk_plan"] is not None:
        predecessor_path = rolling._open_ref(value["previous_chunk_plan"])
        if predecessor_path == spec.plan_receipt or not predecessor_path.is_relative_to(rolling._open_ref(batch["policy"]).parent):
            raise ValueError("chunk recovery changes its study or cycles to itself")
        # Reopen ancestry before accepting a new generation; all campaign/raw
        # bytes stay on their original immutable Source and sample identities.
        _, previous = rolling.verify_capture_plan(replace(spec, plan_receipt=predecessor_path),
                                                  require_current=require_current, _context=_context)
        if (len(rows) != 1 or rows[0].get("generation", 0) <= 1
                or any(value[key] != previous[key] for key in value if key not in
                       {"lanes", "planned_trace_count", "declared_at", "previous_chunk_plan"})
                or receipts._utc(value["declared_at"]) < receipts._utc(previous["declared_at"])):
            raise ValueError("chunk recovery changes its original slot/policy authority")
        current = checked_lane({key: item for key, item in rows[0].items() if key != "campaign_sha256"})
        candidates = [checked_lane({key: item for key, item in row.items() if key != "campaign_sha256"})
                      for row in previous["lanes"] if row["campaign_name"] == name(current, current.generation - 1)]
        if len(candidates) != 1 or successor(candidates[0], current.generation) != current:
            raise ValueError("chunk recovery skips a generation or changes its logical slot vector")
        expected = (current,)
    actual = []
    for lane in expected:
        raw = render(lane, sites, **_render_options(base))
        if _raw(spec.campaign_dir / (lane.campaign_name + ".yml")) != raw:
            raise ValueError("chunk campaign changed its full graph, requests, slots or traffic settings")
        actual.append(_row(lane, raw))
    if (rows != actual or type(value["planned_trace_count"]) is not int
            or value["planned_trace_count"] != sum(lane.sample_count for lane in expected)):
        raise ValueError("chunk plan lost, repeated or invented remaining visits")
    if _context is not None:
        for path in dependencies:
            _context.watch_file(path)
        _context.check()
    return sites, value


@_owned_action
def publish_successor(spec: lanes.CaptureSpec, lane_name: str, generation: int, output: Path) -> Path:
    from .rapid_operation_facts import current_context
    context = current_context()
    sites, value = rolling.verify_capture_plan(spec)
    _, batch, _, _ = validate_policy(value["slot_chunk_policy"])
    output = _publication_path(output, rolling._open_ref(batch["policy"]).parent)
    matching = [row for row in value["lanes"] if row["campaign_name"] == lane_name]
    if len(matching) != 1:
        raise ValueError("chunk recovery needs exactly one registered immediate predecessor")
    base = checked_lane({key: item for key, item in matching[0].items() if key != "campaign_sha256"})
    lane = successor(base, generation)
    raw = render(lane, sites, **_render_options(value))
    from .rapid_partial_progress import close_operation
    close_operation(context)
    campaign = spec.campaign_dir / (lane.campaign_name + ".yml")
    receipts.durable_create(campaign, raw)
    context.watch_file(campaign)
    value = {**value, "lanes": [_row(lane, raw)], "planned_trace_count": lane.sample_count,
             "declared_at": receipts._now(), "previous_chunk_plan": rolling._ref(spec.plan_receipt)}
    context.check()
    from .rapid_partial_progress import close_operation
    close_operation()
    return rolling._write(output, PLAN_TYPE, value)


def roots(spec: lanes.CaptureSpec) -> set[Path]:
    value = receipts._unpack(_raw(spec.plan_receipt), PLAN_TYPE)
    result = {path.parent for path in input_files(value)}
    policy = receipts._unpack(_raw(rolling._open_ref(value["slot_chunk_policy"])), POLICY_TYPE)
    result.update(rolling.enrollment_roots(_base_spec(policy["base_spec"])))
    return result


def logical_slot(lane, local_visit: int) -> int:
    if type(local_visit) is not int or not 0 <= local_visit < lane.visits_per_workload:
        raise ValueError("logical slot needs an actual bounded local visit")
    if isinstance(lane, ChunkLane):
        checked_lane(asdict(lane))
        return lane.slot_start + local_visit
    return (lane.block - 1) * 4 + local_visit
