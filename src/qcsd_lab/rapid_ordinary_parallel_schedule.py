"""Current ordinary parallel authority; no padding qualification or credit.

The capsule reopens an unchanged serial ordinary plan (four visits or an
authenticated remaining-slot chunk). A distinct plan wrapper adds only the
two-worker actuator authority. Every graph, request, limit and canary remains
bound to its actual current runtime. Old ordinary and defended contracts keep
their own validators.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping

from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_rolling_schedule as schedule
from . import rapid_undefended_capture as ordinary
from . import rapid_slot_chunks as chunks
from . import rapid_site_admission as receipts
from .rapid_operation_facts import OperationFacts, current_context

CAPSULE_TYPE = "qcsd-rapid-v6-current-ordinary-parallel-scheduling-v1"
PLAN_TYPE = "qcsd-rapid-v6-current-ordinary-parallel-plan-v1"
CONTRACT = "current-complete-ordinary-graphs-disjoint-one-through-sixteen-slot-workers-v1"
FIELD = "ordinary_parallel_contract"
CONTROL_FILES = (
    "qcsd-lab", "tools/rapid_rolling_capture.py",
    "src/qcsd_lab/rapid_ordinary_parallel_schedule.py",
    "src/qcsd_lab/rapid_undefended_capture.py", "src/qcsd_lab/rapid_slot_chunks.py",
    "src/qcsd_lab/rapid_capture_plan.py", "src/qcsd_lab/rapid_lane_evidence.py",
    "src/qcsd_lab/rapid_rolling_capture.py", "src/qcsd_lab/rapid_rolling_schedule.py",
    "src/qcsd_lab/rapid_operation_facts.py", "src/qcsd_lab/rapid_formal_parallel.py",
    "src/qcsd_lab/rapid_runtime_epochs.py",
    "src/qcsd_lab/rapid_ordinary_group_canary.py", "src/qcsd_lab/rapid_rolling_readiness.py",
    "src/qcsd_lab/rapid_ordinary_transport_control.py",
    "tools/_rapid_class_mode_flight/flight/operator.py",
)
CAPSULE_KEYS = {"schema_version", "artifact_type", "contract", "base_spec", "runtime",
    "qualification_spec", "original_canonical", "current_canonical", "input_authority",
    "canary", "capture_limits", "body_policy", "traffic_hashes", "control_sources",
    "published_at", "reason", "formal_accepted_trace_count", "scientific_credit"}
EXTRA_PLAN_KEYS = {"scheduling", FIELD, "ordinary_parallel_base_spec"}


def _scope(function):
    def action(*args, **kwargs):
        context = kwargs.get("_context") or current_context()
        owned = context is None
        context = OperationFacts() if owned else context
        if owned:
            context.begin_action()
        with context.scope():
            result = function(*args, **kwargs)
            if owned:
                from .rapid_partial_progress import close_operation
                close_operation(context)
            return result
    return action


def _read(path):
    context = current_context()
    return lanes._read(path) if context is None else context.watch_file(Path(path))


def is_plan(path: Path) -> bool:
    return lanes._load(_read(path)).get("receipt_type") == PLAN_TYPE


def is_payload(value: Mapping[str, Any]) -> bool:
    return value.get(FIELD) == CONTRACT


def is_schedule(reference) -> bool:
    return lanes._load(_read(rolling._open_ref(reference))).get("artifact_type") == CAPSULE_TYPE


def _spec(value):
    return schedule._spec(value)


def _base(base):
    lanes._check_spec(base)
    value = lanes.plan_payload(_read(base.plan_receipt))
    ordinary.require_plan(value)
    if FIELD in value or "scheduling" in value or value.get("runtime") != {
            key: base.serializable()[key] for key in rolling.RUNTIME_FIELDS}:
        raise ValueError("ordinary parallel needs its exact current unscheduled serial base")
    return rolling.verify_capture_plan(base, require_current=True, _context=current_context())


def input_dependencies(base, sites, *, _context=None):
    """Exact input files/raw trees; no live output-parent observations."""
    context = _context or current_context()
    if context is not None:
        context.bind_capture(base)
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    from . import rapid_per_class_selected_input as facade
    from . import rapid_selected_capture_input as selected
    files = {base.cohort, base.qualification_spec, base.plan_receipt}
    trees = set()
    if per_class.enrollment_kind(base.cohort):
        files.update(per_class.membership_inputs(base.cohort))
    elif additive.enrollment_kind(base.cohort):
        files.update(additive.membership_inputs(base.cohort))
    else:
        raise ValueError("ordinary parallel currently requires explicit selected enrollment")
    inputs = lanes._load(_read(base.qualification_spec))
    renewal = inputs.get("renewal")
    if renewal is not None:
        path = rolling._open_ref(renewal)
        files.add(path)
        value = lanes._load(_read(path))
        for row in value["rows"]:
            for name in ("current_input", "current_manifest"):
                if context is not None:
                    context.watch_file(Path(row[name]["path"]))
                files.add(facade.reopen(row[name]))
    for site in sites:
        path = base.workload_root / (site.workload_id + ".json")
        files.add(path)
        manifest = lanes._load(_read(path))
        preparation = manifest["preparation"]
        if selected.is_selected(preparation):
            own_files, own_trees = selected.preparation_inputs(preparation, manifest["resources"])
        else:
            own_files, own_trees = facade.preparation_inputs(preparation, manifest["resources"])
        input_module = facade.module_for_preparation(preparation)
        payload = receipts._unpack(_read(facade.reopen(facade.receipt_ref(preparation))), input_module.RECEIPT_TYPE)
        bound_files = selected._bound_validator_files(payload)
        modules = selected._direct_modules() if input_module is selected else input_module._modules()
        # Runtime imports may live in the execution copy or installed package.
        # Keep original receipt refs; publish declared paths for additional imports.
        for module in modules:
            imported = Path(module.__file__).absolute()
            if imported not in own_files:
                continue
            declared = base.module_root / "src" / Path(*module.__name__.split(".")).with_suffix(".py")
            if _read(imported) != _read(declared):
                raise ValueError("ordinary selected validator differs from its declared runtime Source")
            if context is not None:
                context.watch_file(imported)
            if imported != declared and imported not in bound_files:
                own_files.discard(imported)
            own_files.add(declared)
        files.update(own_files); trees.update(own_trees)
    if "slot_chunk_policy" in lanes.plan_payload(_read(base.plan_receipt)):
        files.update(chunks.input_files(lanes.plan_payload(_read(base.plan_receipt))))
    if context is not None:
        for path in files:
            context.watch_file(path)
        for path in trees:
            context.watch_tree(path)
    return files, trees


def _derive(base, runtime, canonical_ref):
    runtime = rolling._runtime(runtime)
    if runtime != {key: base.serializable()[key] for key in rolling.RUNTIME_FIELDS}:
        raise ValueError("ordinary scheduling changed its current serial runtime")
    context = current_context()
    sites, value = _base(base)
    if (not value["lanes"] or any(row["mode"] != "undefended" or row["qualification_set"] is not None
            or type(row["visits_per_workload"]) is not int or not 1 <= row["visits_per_workload"] <= 16
            for row in value["lanes"])):
        raise ValueError("ordinary scheduling accepts only bounded unqualified ordinary lanes")
    canonical, source_files = schedule.reopen_runtime(canonical_ref, runtime, _inspector=True)
    controls = {}
    for relative in CONTROL_FILES:
        own = (Path(import_module("qcsd_lab." + Path(relative).stem).__file__)
               if relative.startswith("src/qcsd_lab/") else Path(runtime["runtime_source_root"]) / relative)
        raw = _read(own)
        if source_files.get(relative) != raw or _read(Path(runtime["module_root"]) / relative) != raw:
            raise ValueError("ordinary scheduling executing/installed/frozen control Source differs")
        controls[relative] = lanes._sha(raw)
    lane = lanes._lane({"plan_payload": value}, value["lanes"][0]["campaign_name"])
    canary = rolling.require_mode_readiness(base, lane, _context=context)
    from . import rapid_ordinary_group_canary as group_canary
    from . import rapid_ordinary_canary_carry as carry
    if ((canary.get("schema_version"), canary.get("artifact_type")) not in
            ((5, group_canary.TYPE), (6, carry.TYPE))):
        raise ValueError("ordinary scheduling needs its own successful current full-group canary")
    from .rapid_rolling_readiness import validate_canary
    facts = (validate_canary(canary, runtime={key: runtime[key] for key in lanes.RUNTIME_KEYS}, mode="undefended")
             if context is None else context.validate_canary(canary,
                 {key: runtime[key] for key in lanes.RUNTIME_KEYS}, "undefended", validate_canary))
    ordinary.require_canary(facts, sites)
    from .application_response_policy import application_body_identity_policy
    from .rapid_capture_traffic import plan_files
    expected_source = {**canonical["source"], "image_digest": canonical["collection_image_digest"]}
    traffic = {key: digest for key, (_, digest) in plan_files(value).items()}
    if (facts.get("authority_source") != expected_source
            or facts.get("client_sha256") != lanes._sha(_read(base.client_binary))
            or facts.get("traffic_hashes") != traffic
            or application_body_identity_policy(facts) != application_body_identity_policy(value)):
        raise ValueError("ordinary canary differs from current image/client/fixed traffic/body policy")
    files, trees = input_dependencies(base, sites, _context=context)
    return {"input_authority": {"base_plan": rolling._ref(base.plan_receipt),
        "ordinary_input": rolling._ref(base.qualification_spec), "enrollment": rolling._ref(base.cohort),
        "sites": value["sites"], "files": sorted(str(path) for path in files),
        "raw_trees": sorted(str(path) for path in trees)},
        "canary": canary, "capture_limits": value["capture_limits"],
        "body_policy": application_body_identity_policy(value),
        "traffic_hashes": traffic, "control_sources": controls}


def bind_dependencies(value, context):
    """Register the complete proof read closure before any cached reuse."""
    base = _spec(value["base_spec"])
    context.bind_capture(base)
    key = ("ordinary-parallel-dependencies", lanes._sha(lanes._json(value)))
    if context.has(key):
        return
    pending, seen = [value["current_canonical"]], set()
    while pending:
        item = pending.pop(); path = rolling._open_ref(item)
        if path in seen:
            raise ValueError("ordinary runtime dependency contains an ancestor cycle")
        seen.add(path)
        context.watch_tree(path.parent)
        canonical = lanes._load(context.watch_file(path))
        context._references(canonical, path.parent)
        for name in ("client_reuse_recipe", "client_reuse_proof", "original_native_build_record", "closure_recipe"):
            if name in canonical:
                context.watch_file(rolling._open_ref(canonical[name]))
        if canonical.get("original_canonical") is not None:
            pending.append(canonical["original_canonical"])
    input_dependencies(base, tuple(ordinary.OrdinarySite(**row) for row in
        lanes.plan_payload(context.watch_file(base.plan_receipt))["sites"]), _context=context)
    context.remember(key, True)


@_scope
def publish_schedule(base_spec, runtime, qualification_spec, original_canonical, current_canonical,
                     output, *, reason):
    if (original_canonical != current_canonical or rolling._ref(qualification_spec) != rolling._ref(base_spec.qualification_spec)
            or not isinstance(reason, str) or not reason.strip()):
        raise ValueError("ordinary scheduling needs one current canonical/input and a prospective reason")
    seed = {"base_spec": base_spec.serializable(), "current_canonical": dict(current_canonical)}
    bind_dependencies(seed, current_context())
    derived = _derive(base_spec, runtime, current_canonical)
    output = chunks._publication_path(Path(output), rolling._open_ref(
        rolling._verify_enrollment(base_spec.cohort)[0]["policy"]).parent)
    value = {"schema_version": 1, "artifact_type": CAPSULE_TYPE, "contract": CONTRACT,
        "base_spec": base_spec.serializable(), "runtime": dict(runtime),
        "qualification_spec": rolling._ref(qualification_spec),
        "original_canonical": dict(original_canonical), "current_canonical": dict(current_canonical),
        **derived, "published_at": receipts._now(), "reason": reason.strip(),
        "scientific_credit": False, "formal_accepted_trace_count": 0}
    from .rapid_partial_progress import close_operation
    close_operation(current_context())
    receipts.durable_create(output, lanes._json(value))
    return rolling._ref(output)


@_scope
def validate_schedule(reference, *, runtime=None, before=None, _context=None):
    path = rolling._open_ref(reference)
    raw = _read(path); value = lanes._load(raw)
    rolling._keys(value, CAPSULE_KEYS, "ordinary scheduling")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["artifact_type"] != CAPSULE_TYPE or value["contract"] != CONTRACT
            or value["original_canonical"] != value["current_canonical"]
            or value["scientific_credit"] is not False
            or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or not isinstance(value["reason"], str) or not value["reason"].strip()
            or runtime is not None and dict(runtime) != value["runtime"]
            or not receipts._utc(value["published_at"]) <= receipts._utc(before or receipts._now())):
        raise ValueError("ordinary scheduling exact header/runtime/chronology differs")
    context = current_context()
    context.watch_file(path)
    bind_dependencies(value, context)
    key = (CAPSULE_TYPE, lanes._sha(raw))
    if context.has(key):
        derived = context.get(key)
    else:
        derived = _derive(_spec(value["base_spec"]), value["runtime"], value["current_canonical"])
        context.remember(key, derived)
    if any(value[name] != item for name, item in derived.items()):
        raise ValueError("ordinary scheduling changed full input/graph/caps/canary/Source")
    canonical = lanes._load(_read(rolling._open_ref(value["current_canonical"])))
    if (not receipts._utc(canonical["verified_at"]) <= receipts._utc(value["published_at"])
            or rolling._ref(_spec(value["base_spec"]).qualification_spec) != value["qualification_spec"]):
        raise ValueError("ordinary scheduling predates actual runtime or changed its input")
    return value


@_scope
def publish_plan(base_spec, scheduling, output, *, _context=None):
    capsule = validate_schedule(scheduling)
    if capsule["base_spec"] != base_spec.serializable():
        raise ValueError("ordinary parallel plan changed its exact serial base")
    _, base = _base(base_spec)
    output = chunks._publication_path(Path(output), rolling._open_ref(
        rolling._verify_enrollment(base_spec.cohort)[0]["policy"]).parent)
    value = {**base, "scheduling": dict(scheduling), FIELD: CONTRACT,
        "ordinary_parallel_base_spec": base_spec.serializable(), "declared_at": receipts._now()}
    from .rapid_partial_progress import close_operation
    close_operation(current_context())
    return rolling._write(output, PLAN_TYPE, value)


def prepared_lane(value):
    """Reopen the exact ChunkLane or legacy Lane, without a four-visit coercion."""
    if "lane_layout" in value:
        return chunks.checked_lane(value)
    return lanes.plan.Lane(**{**value, "workload_ids": tuple(value["workload_ids"])})


def prepared_sites(payload, rows):
    return tuple(ordinary.OrdinarySite(**row) for row in rows) if is_payload(payload) else tuple(
        lanes.plan.Site(**row) for row in rows)


@_scope
def verify_plan(spec, *, require_current=False, _context=None):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    base = _spec(value["ordinary_parallel_base_spec"])
    if spec != replace(base, plan_receipt=spec.plan_receipt):
        raise ValueError("ordinary parallel wrapper changed its full serial specification")
    sites, old = _base(base)
    rolling._keys(value, set(old) | EXTRA_PLAN_KEYS, "ordinary parallel plan")
    if (not is_payload(value) or any(value[key] != item for key, item in old.items() if key != "declared_at")
            or not receipts._utc(old["declared_at"]) <= receipts._utc(value["declared_at"]) <= receipts._utc(receipts._now())):
        raise ValueError("ordinary parallel wrapper changed serial slots/graphs/caps/traffic/canary")
    capsule = validate_schedule(value["scheduling"], runtime=value["runtime"], before=value["declared_at"])
    if capsule["base_spec"] != base.serializable():
        raise ValueError("ordinary plan uses another serial base capsule")
    return sites, value


def require_plan(payload, *, _context=None):
    if not is_payload(payload):
        raise ValueError("ordinary parallel typed policy missing")
    capsule = validate_schedule(payload["scheduling"], runtime=payload["runtime"], before=payload["declared_at"])
    base = _spec(payload["ordinary_parallel_base_spec"])
    _, old = _base(base)
    rolling._keys(payload, set(old) | EXTRA_PLAN_KEYS, "ordinary parallel payload")
    if capsule["base_spec"] != base.serializable() or any(
            payload[key] != item for key, item in old.items() if key != "declared_at"):
        raise ValueError("ordinary parallel payload changed its complete serial authority")
    return capsule


def check_layout(spec, inputs):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    base = _spec(value["ordinary_parallel_base_spec"])
    if spec != replace(base, plan_receipt=spec.plan_receipt):
        raise ValueError("ordinary parallel layout changed its serial runtime/input")
    ordinary.check_layout(base, inputs)
    require_plan(value)


def require_worker(payload, lane, sites, spec):
    require_plan(payload)
    if (lane.role != "formal" or lane.mode != "undefended" or lane.qualification_set is not None
            or not 1 <= lane.visits_per_workload <= 16
            or lane.sample_count != lane.visits_per_workload * len(lane.workload_ids)
            or not set(lane.workload_ids) <= {site.workload_id for site in sites}
            or asdict(lanes._lane({"plan_payload": payload}, lane.campaign_name)) != asdict(lane)):
        raise ValueError("ordinary worker changed its exact registered bounded slot lane")
    return {(workload, "undefended", chunks.logical_slot(lane, local))
        for workload in lane.workload_ids for local in range(lane.visits_per_workload)}


def require_disjoint(facts):
    if not any(is_payload(payload) for _, payload, _, _ in facts):
        return
    if not all(is_payload(payload) for _, payload, _, _ in facts):
        raise ValueError("ordinary parallel pair cannot mix another scheduling contract")
    occupied = set()
    for spec, payload, lane, sites in facts:
        own = require_worker(payload, lane, sites, spec)
        if occupied & own:
            raise ValueError("ordinary parallel workers repeat a logical class/mode/visit slot")
        occupied.update(own)


@_scope
def mount_roots(reference, *, _context=None):
    capsule = validate_schedule(reference)
    base = _spec(capsule["base_spec"])
    sites, old = _base(base)
    files, trees = input_dependencies(base, sites)
    roots = trees | {path.parent for path in files} | {Path(reference["path"]).parent}
    roots.update(Path(value) for key, value in capsule["runtime"].items() if key in
        {"runtime_source_root", "module_root", "execution_root"})
    roots.update(Path(capsule["runtime"][key]).parent for key in
        ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    roots.update(Path(path) for path in rolling.enrollment_roots(base))
    for row in old["lanes"][:1]:
        roots.update(Path(path) for path in rolling.readiness_roots(base, row["campaign_name"]))
    pending, seen = [capsule["current_canonical"]], set()
    while pending:
        item = pending.pop(); path = rolling._open_ref(item)
        if path in seen:
            raise ValueError("ordinary runtime transport has an ancestor cycle")
        seen.add(path); roots.add(path.parent)
        canonical = lanes._load(_read(path))
        for key in ("client_reuse_recipe", "client_reuse_proof", "original_native_build_record", "closure_recipe"):
            if key in canonical:
                roots.add(rolling._open_ref(canonical[key]).parent)
        if canonical.get("original_canonical") is not None:
            pending.append(canonical["original_canonical"])
    return sorted(root for root in roots if not any(root != other and root.is_relative_to(other) for other in roots))


def roots(spec):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    return set(mount_roots(value["scheduling"])) | {spec.plan_receipt.parent}


def validate_current_implementation(old, current, reference, *, actual_image, before=None, _context=None):
    value = validate_schedule(reference, before=before, _context=_context)
    if (old != current or actual_image != value["runtime"]["collection_image_digest"]):
        raise ValueError("ordinary scheduling cannot exempt changed implementation or image")


@_scope
def publish_successor(spec, lane_name, generation, output):
    _, value = verify_plan(spec)
    base = _spec(value["ordinary_parallel_base_spec"])
    output = Path(output)
    serial = output.with_name(output.stem + "-serial.json")
    capsule_path = output.with_name(output.stem + "-scheduling.json")
    if any(path.exists() or path.is_symlink() for path in (output, serial, capsule_path)):
        raise FileExistsError("ordinary recovery is create-only including its serial/capsule authority")
    path = rolling.publish_successor(base, lane_name, generation, serial)
    successor = replace(base, plan_receipt=path)
    capsule = validate_schedule(value["scheduling"])
    reference = publish_schedule(successor, value["runtime"], base.qualification_spec,
        capsule["current_canonical"], capsule["current_canonical"], capsule_path,
        reason="immediate original failed worker successor; completed peer remains immutable")
    return publish_plan(successor, reference, output)
