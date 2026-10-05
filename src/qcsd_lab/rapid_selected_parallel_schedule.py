"""Current same-mode parallel lanes for additive selected complete graphs.

This is a new capsule authority. It never changes an original/static capsule
or lends an earlier qualification to a derived selected manifest. Membership,
each selected raw GET, current Source/client, full named120 and the setting's
current complete canary are independently reopened before lane actuation.
"""
from __future__ import annotations

from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import chaff_qualification as qualification
from . import response_budget_qualification as budget
from . import rapid_additive_static_enrollment as additive
from . import rapid_capture_traffic as traffic
from . import rapid_lane_evidence as lanes
from . import rapid_original_static_parallel_schedule as original
from . import rapid_rolling_capture as rolling
from . import rapid_rolling_readiness as evidence
from . import rapid_rolling_schedule as legacy
from . import rapid_selected_capture_input as selected
from . import rapid_static_parallel_schedule as static
from . import selected_capture_amendment as amendment
from . import supplied_static_graph as graph
from .util import durable_create

CAPSULE_TYPE = "qcsd-rapid-v6-current-selected-parallel-scheduling"
CONTRACT = "rolling-v6-current-selected-full-graph-same-setting-parallel-v1"
DELIVERY_CONTRACT = "rolling-v6-current-selected-complete-delivery-parallel-v2"
MODES = frozenset(rolling.plan.MODES)
KEYS = {"schema_version", "artifact_type", "contract", "base_spec", "runtime",
    "qualification_spec", "original_canonical", "current_canonical", "qualified_inputs",
    "control_sources", "membership", "data_role", "mode", "traffic_hashes",
    "static_capture_amendment", traffic.FIELD, "reason", "published_at", "limits",
    "formal_accepted_trace_count", "scientific_credit"}
CONTROL_FILES = tuple(dict.fromkeys((*original.CONTROL_FILES, *amendment.authority_files().values(),
    "src/qcsd_lab/rapid_selected_parallel_schedule.py", "src/qcsd_lab/selected_capture_amendment.py",
    "src/qcsd_lab/rapid_selected_capture_input.py", "src/qcsd_lab/rapid_additive_static_enrollment.py",
    "src/qcsd_lab/rapid_capture_traffic.py",
    "src/qcsd_lab/application_response_policy.py", "src/qcsd_lab/response_budget_qualification.py")))


def _delivery(value: Mapping[str, Any]) -> dict:
    fields = static.delivery_fields(value)
    if "qualification_delivery_compatibility" in fields:
        raise ValueError("selected parallel settings require their own current named120 evidence")
    return fields


def _header(value: Any, *, before: str | None = None) -> None:
    delivery = _delivery(value) if isinstance(value, dict) else {}
    if (not isinstance(value, dict) or set(value) != KEYS | set(delivery)
        or type(value["schema_version"]) is not int or value["schema_version"] != (2 if delivery else 1)
        or value["artifact_type"] != CAPSULE_TYPE
        or value["contract"] != (DELIVERY_CONTRACT if delivery else CONTRACT)
        or value["data_role"] != selected.ROLE or value["limits"] != legacy.LIMITS
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False
        or type(value["mode"]) is not str or value["mode"] not in MODES
        or not isinstance(value["reason"], str) or not value["reason"].strip()):
        raise ValueError("selected parallel capsule has another exact policy or mode contract")
    published = evidence._timestamp(value["published_at"])
    if (published > datetime.now(UTC) or before is not None
        and not published < evidence._timestamp(before) <= datetime.now(UTC)):
        raise ValueError("selected scheduling must precede its plan and lane intents")


def is_selected(reference: Mapping[str, str]) -> bool:
    return evidence._json(evidence._reference(reference)[1]).get("artifact_type") == CAPSULE_TYPE


def input_dependencies(enrollment: Path, workloads: Path, sites: list[dict], *, _context=None) -> tuple[set[Path], set[Path]]:
    """Immutable selected metadata and own raw trees, never output parents."""
    files = additive.membership_inputs(enrollment)
    trees = set()
    for site in sites:
        path = workloads / (site["workload_id"] + ".json")
        raw = evidence._read(path, site["workload_sha256"])
        manifest = evidence._json(raw)
        preparation = manifest["preparation"]
        if selected.is_selected(preparation):
            own_files, own_trees = selected.preparation_inputs(preparation, manifest["resources"])
        elif amendment.is_amended(preparation):
            own_files, own_trees = amendment.preparation_inputs(preparation)
        else:
            raise ValueError("selected parallel input has another preparation authority")
        files.add(path)
        files.update(own_files)
        trees.update(own_trees)
    for path in files:
        evidence._path(path)
        if _context is not None:
            _context.watch_file(path)
    for root in trees:
        evidence._path(root, directory=True)
        if _context is not None:
            _context.watch_tree(root, ignore_git=True)
    return files, trees


def _membership(base: lanes.CaptureSpec, plan: Mapping[str, Any]) -> dict:
    batch, classes, policy = rolling._verify_enrollment(base.cohort)
    if policy["contract"] != additive.CONTRACT or len(batch["selected_candidate_ids"]) != len(plan["sites"]):
        raise ValueError("selected parallel requires its exact additive selected batch")
    rows = classes[-len(batch["selected_candidate_ids"]):]
    if ([row["candidate_id"] for row in rows] != batch["selected_candidate_ids"]
        or [(row["candidate_id"], row["workload_id"]) for row in rows]
        != [(row["candidate_id"], row["workload_id"]) for row in plan["sites"]]):
        raise ValueError("selected parallel changed class numbering, reservation order or workload membership")
    return {"policy": rolling._ref(rolling._open_ref(batch["policy"])),
        "enrollment": rolling._ref(base.cohort), "ordinal": batch["ordinal"],
        "first_class_index": batch["first_class_index"], "classes": [
            {"candidate_id": row["candidate_id"], "class_index": row["class_index"],
             "workload_id": row["workload_id"], "capture_input": row["capture_input"],
             "prepared_workload": row["prepared_workload"], "terminal": row["terminal"]} for row in rows],
        "seed_enrollment": policy["seed_enrollment"], "seed_progress": policy["seed_progress"]}


def _qualified_inputs(base: lanes.CaptureSpec, qualifier: Path, sites: list[dict], *, _context=None) -> dict:
    spec = evidence._json(evidence._read(qualifier))
    if (not isinstance(spec, dict) or set(spec) != {"schema_version", "qualification_sets"}
        or type(spec["schema_version"]) is not int or spec["schema_version"] != 1
        or not isinstance(spec["qualification_sets"], list) or len(spec["qualification_sets"]) != 1):
        raise ValueError("selected parallel requires one full current response qualification set")
    row = spec["qualification_sets"][0]
    if (not isinstance(row, dict) or set(row) != {"qualification_set", "manifest", "sidecar_root", "prefix_spec_root"}
        or row["prefix_spec_root"] is not None):
        raise ValueError("selected parallel qualification has no fitting or shortened prefix")
    def resolve(name):
        value = row[name]
        if not isinstance(value, str) or not value:
            raise ValueError("selected qualification path is invalid")
        return evidence._path(Path(value) if Path(value).is_absolute() else qualifier.parent / value,
                              directory=name == "sidecar_root")
    manifest, sidecars = resolve("manifest"), resolve("sidecar_root")
    ids = [site["workload_id"] for site in sites]
    if not 1 <= len(ids) <= legacy.LIMITS["maximum_sites_per_batch"] or len(set(ids)) != len(ids):
        raise ValueError("selected parallel needs one to five complete distinct graphs")
    validator = (budget.validate_named_qualification_set_manifest if _context is None else
        lambda value, **kwargs: _context.validate_named_qualification(value,
            budget.validate_named_qualification_set_manifest, **kwargs))
    named = evidence._json(evidence._read(manifest))
    validator(named, workload_root=base.workload_root, sidecar_root=sidecars,
        prefix_spec_root=None, expected_qualification_set=row["qualification_set"],
        expected_workload_ids=ids, expected_qualification_scope="response-only", require_current_implementation=False)
    if named.get("artifact_type") != budget.NAMED_ARTIFACT_TYPE or named.get("qualification_sidecar_schema_version") != budget.SIDECAR_SCHEMA_VERSION:
        raise ValueError("selected parallel requires the declared response-budget schema and full120")
    workloads, implementations, sources = {}, {}, {}
    for site in sites:
        name = site["workload_id"]
        raw = evidence._read(base.workload_root / (name + ".json"), site["workload_sha256"])
        workload = evidence._json(raw)
        preparation = workload["preparation"]
        if selected.is_selected(preparation):
            proof = selected.validate_preparation(preparation, workload["resources"])
        elif amendment.is_amended(preparation):
            proof = amendment.validate_preparation(preparation, workload["resources"])
        else:
            raise ValueError("qualified selected graph has another preparation role")
        sidecar_path = sidecars / (name + ".json")
        sidecar = evidence._json(evidence._read(sidecar_path))
        if type(sidecar.get("schema_version")) is not int or sidecar["schema_version"] != budget.SIDECAR_SCHEMA_VERSION:
            raise ValueError("selected parallel requires each current full120 schema3 sidecar")
        workloads[name] = {"workload_sha256": evidence._sha(raw), "preparation_role": preparation["data_role"],
            "resource_records_sha256": graph.digest(graph.canonical_bytes(workload["resources"])),
            "resource_count": len(workload["resources"]), "original_get_proof_sha256": graph.digest(graph.canonical_bytes(proof)),
            "qualification_sidecar": rolling._ref(sidecar_path)}
        implementations[name] = sidecar["implementation_receipt"]["sha256"]
        sources[name] = {"source": sidecar["qualification_source"], "image": sidecar["qualification_image_digest"]}
    return {"enrollment_sha256": evidence._sha(evidence._read(base.cohort)),
        "qualification_spec_sha256": evidence._sha(evidence._read(qualifier)), "named_set": row["qualification_set"],
        "named_manifest_sha256": evidence._sha(evidence._read(manifest)),
        "qualification_files": evidence._inventory(sidecars), "workloads": workloads,
        "implementation_sha256": implementations, "qualification_sources": sources}


def _derive(base: lanes.CaptureSpec, runtime: Mapping[str, str], qualifier: Path,
            original_canonical: Mapping[str, str], current_canonical: Mapping[str, str], *, _context=None) -> dict:
    lanes._check_spec(base)
    runtime = rolling._runtime(runtime)
    if (dict(original_canonical) != dict(current_canonical)
        or runtime != {key: base.serializable()[key] for key in rolling.RUNTIME_FIELDS}
        or rolling._ref(qualifier) != rolling._ref(base.qualification_spec)):
        raise ValueError("selected parallel uses one current canonical, runtime and qualifier")
    sites, plan = rolling.verify_capture_plan(base, require_current=False, _context=_context)
    delivery = _delivery(plan)
    if ("scheduling" in plan or "front_capture_amendment" in plan
        or plan.get("data_role") != selected.ROLE or plan.get("study_version") != 6
        or plan.get("cohort_generation") != "rolling-50" or len(plan["readiness"]) != 1
        or not 1 <= len(sites) <= legacy.LIMITS["maximum_sites_per_batch"]
        or any(type(row["visits_per_workload"]) is not int or row["visits_per_workload"] != 4
               or row["workload_ids"] != [site.workload_id for site in sites] for row in plan["lanes"])):
        raise ValueError("selected parallel requires a serial current same-mode four-visit base plan")
    mode = next(iter(plan["readiness"]))
    if mode not in MODES:
        raise ValueError("selected parallel has an unknown setting")
    amendment_ref = plan.get("static_capture_amendment")
    if mode in {"front", "buflo"}:
        if amendment_ref is None:
            raise ValueError("selected FRONT/BuFLO parallel requires its typed fixed-policy amendment")
        closed = amendment.validate_amendment(rolling._open_ref(amendment_ref), enrollment=base.cohort, runtime=runtime)
        if mode not in closed["modes"]:
            raise ValueError("selected parallel mode is outside its prospective amendment")
    elif amendment_ref is not None:
        raise ValueError("selected unchanged modes cannot import an amended setting")
    membership = _membership(base, plan)
    canonical, source_files = legacy.reopen_runtime(current_canonical, runtime, _inspector=True)
    if (canonical["source"]["neqo_dirty"] is not False
        or canonical["source"]["neqo_commit"] != canonical["source"]["neqo_pinned_commit"]):
        raise ValueError("selected parallel changed clean pinned Native Source")
    controls = {}
    for relative in CONTROL_FILES:
        raw = (lanes._read(Path(import_module("qcsd_lab." + Path(relative).stem).__file__))
               if relative.startswith("src/qcsd_lab/") else lanes._read(Path(runtime["runtime_source_root"]) / relative))
        if source_files.get(relative) != raw or lanes._read(Path(runtime["module_root"]) / relative) != raw:
            raise ValueError("selected parallel installed/frozen control or input authority differs")
        controls[relative] = lanes._sha(raw)
    selected_traffic = traffic.declared(plan)
    for name in ("runtime_source_root", "module_root", "execution_root"):
        for relative, digest in traffic.files(selected_traffic).values():
            evidence._read(Path(runtime[name]) / relative, digest)
    qualified = _qualified_inputs(base, qualifier, plan["sites"], _context=_context)
    source = {**canonical["source"], "image_digest": canonical["collection_image_digest"]}
    if (set(qualified["implementation_sha256"].values()) != {
            canonical["checks"]["collection"]["qualification_implementation_sha256"]}
        or any(row != {"source": source, "image": canonical["collection_image_digest"]}
               for row in qualified["qualification_sources"].values())):
        raise ValueError("selected parallel requires current full120 Source/image/client evidence")
    lane_row = next(row for row in plan["lanes"] if row["mode"] == mode)
    lane = lanes._lane({"plan_payload": plan}, lane_row["campaign_name"])
    canary = rolling.require_mode_readiness(base, lane, _context=_context)
    canary_runtime = {key: base.serializable()[key] for key in lanes.RUNTIME_KEYS}
    facts = (evidence.validate_canary(canary, runtime=canary_runtime, mode=mode) if _context is None else
        _context.validate_canary(canary, canary_runtime, mode, evidence.validate_canary))
    matching = [site for site in sites if site.workload_sha256 == facts.get("workload_sha256")]
    if len(matching) != 1:
        raise ValueError("selected parallel canary is not one unique complete selected workload")
    workload = evidence._json(evidence._read(base.workload_root / (matching[0].workload_id + ".json"), matching[0].workload_sha256))
    resources = workload["resources"]
    expected_graph = {"resource_count": len(resources), "resource_records_sha256": evidence._sha(evidence._encoded(resources)),
        "origins": sorted({f'{urlsplit(row["url"]).scheme}://{urlsplit(row["url"]).netloc}' for row in resources})}
    if facts.get("full_graph") != expected_graph:
        raise ValueError("selected parallel canary changed its complete graph/headers/DAG")
    input_dependencies(base.cohort, base.workload_root, plan["sites"], _context=_context)
    return {"qualified_inputs": qualified, "control_sources": controls, "membership": membership,
        "data_role": selected.ROLE, "mode": mode, "traffic_hashes": traffic.expected(selected_traffic),
        "static_capture_amendment": amendment_ref, traffic.FIELD: selected_traffic, **delivery}


def publish_schedule(base_spec: lanes.CaptureSpec, runtime: Mapping[str, str], qualification_spec: Path,
                     original_canonical: Mapping[str, str], current_canonical: Mapping[str, str],
                     output: Path, *, reason: str) -> dict[str, str]:
    from .rapid_operation_facts import OperationFacts, current_context
    context = current_context()
    if context is None:
        context = OperationFacts()
        with context.scope():
            result = publish_schedule(base_spec, runtime, qualification_spec, original_canonical,
                current_canonical, output, reason=reason)
            context.check()
            return result
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("selected parallel needs its prospective reason")
    output = Path(output)
    if (not output.is_absolute() or ".." in output.parts or any(p.is_symlink() for p in (output,*output.parents))
        or any(output.is_relative_to(root) for root in (base_spec.runtime_source_root, base_spec.module_root,
            Path(current_canonical["path"]).parent))):
        raise ValueError("selected capsule needs a fresh unlinked output outside immutable authority")
    derived = _derive(base_spec, runtime, qualification_spec, original_canonical, current_canonical, _context=context)
    delivery = _delivery(derived)
    now = datetime.now(UTC).isoformat()
    value = {"schema_version": 2 if delivery else 1, "artifact_type": CAPSULE_TYPE,
        "contract": DELIVERY_CONTRACT if delivery else CONTRACT, "base_spec": base_spec.serializable(),
        "runtime": dict(runtime), "qualification_spec": rolling._ref(qualification_spec),
        "original_canonical": dict(original_canonical), "current_canonical": dict(current_canonical),
        **derived, "reason": reason.strip(), "published_at": now, "limits": dict(legacy.LIMITS),
        "formal_accepted_trace_count": 0, "scientific_credit": False}
    _header(value)
    context.check()
    durable_create(output, evidence._encoded(value))
    return rolling._ref(output)


def validate_schedule(reference: Mapping[str, str], *, runtime=None, before=None, _context=None) -> dict:
    from .rapid_operation_facts import OperationFacts, current_context
    _context = current_context() if _context is None else _context
    if _context is None:
        context = OperationFacts()
        with context.scope():
            result = validate_schedule(reference, runtime=runtime, before=before, _context=context)
            context.check()
            return result
    if current_context() is not _context:
        with _context.scope():
            return validate_schedule(reference, runtime=runtime, before=before, _context=_context)
    _, raw = evidence._reference(reference)
    value = evidence._json(raw)
    _header(value, before=before)
    if runtime is not None and dict(runtime) != value["runtime"]:
        raise ValueError("selected capsule names another runtime")
    qualifier, _ = evidence._reference(value["qualification_spec"])
    if _context is not None:
        _context._reference(reference)
        _context.bind_schedule(value)
    key = ("current-selected-parallel", evidence._sha(raw))
    if _context is not None and _context.has(key):
        derived = _context.get(key)
    else:
        derived = _derive(legacy._spec(value["base_spec"]), value["runtime"], qualifier,
            value["original_canonical"], value["current_canonical"], _context=_context)
        if _context is not None:
            _context.remember(key, derived)
    if any(value.get(name) != item for name,item in derived.items()):
        raise ValueError("selected scheduling changed membership, full graph, current evidence or Source")
    canonical = evidence._json(evidence._reference(value["current_canonical"])[1])
    if evidence._timestamp(canonical["verified_at"]) > evidence._timestamp(value["published_at"]):
        raise ValueError("selected capsule predates its actual runtime")
    return value


def require_plan(payload: Mapping[str, Any], *, _context=None) -> dict:
    value = validate_schedule(payload["scheduling"], runtime=payload["runtime"], before=payload["declared_at"], _context=_context)
    static.require_delivery_binding(payload,value)
    base_plan = lanes._payload(legacy._spec(value["base_spec"]).plan_receipt, lanes.PLAN_TYPE)
    if (payload.get("data_role") != selected.ROLE or "front_capture_amendment" in payload
        or payload.get("static_capture_amendment") != value["static_capture_amendment"]
        or payload.get(traffic.FIELD) != value[traffic.FIELD]
        or set(payload.get("readiness",{})) != {value["mode"]}
        or payload["readiness"][value["mode"]] != base_plan["readiness"][value["mode"]]):
        raise ValueError("selected scheduled plan changed mode, typed policy or current canary")
    return value


def validate_current_qualification(old_impl: Mapping, current_impl: Mapping, reference: Mapping[str,str],
                                 *, actual_image: str, before=None, _context=None) -> None:
    value = validate_schedule(reference,before=before,_context=_context)
    if actual_image != value["runtime"]["collection_image_digest"] or dict(old_impl) != dict(current_impl):
        raise ValueError("selected parallel permits only exact equal current qualification receipts")
    qualification._validate_implementation_receipt(current_impl,require_current=False)
    canonical = evidence._json(evidence._reference(value["current_canonical"])[1])
    if (current_impl["sha256"] != canonical["checks"]["collection"]["qualification_implementation_sha256"]
        or current_impl["source"] != canonical["source"]
        or current_impl["neqo_qcsd_client"]["sha256"] != canonical["installed_client_sha256"]):
        raise ValueError("selected qualification hook changed its current Source/client/implementation")


def mount_roots(reference: Mapping[str,str], *, _context=None) -> list[Path]:
    from .rapid_operation_facts import OperationFacts, current_context
    _context = current_context() if _context is None else _context
    if _context is None:
        context = OperationFacts()
        with context.scope():
            roots = mount_roots(reference, _context=context)
            context.check()
            return roots
    if current_context() is not _context:
        with _context.scope():
            return mount_roots(reference, _context=_context)
    value = validate_schedule(reference,_context=_context)
    base = legacy._spec(value["base_spec"])
    plan = lanes._payload(base.plan_receipt,lanes.PLAN_TYPE)
    files,trees = input_dependencies(base.cohort,base.workload_root,plan["sites"],_context=_context)
    roots = trees | {path.parent for path in files} | {Path(reference["path"]).parent}
    for key in ("runtime_source_root","module_root","execution_root"):
        roots.add(Path(value["runtime"][key]))
    for key in ("source_manifest","client_binary","base_launcher","host_launcher"):
        roots.add(Path(value["runtime"][key]).parent)
    roots.add(base.qualification_spec.parent)
    qualifier = evidence._json(evidence._read(base.qualification_spec))
    for row in qualifier["qualification_sets"]:
        for key in ("manifest", "sidecar_root"):
            target = Path(row[key])
            target = target if target.is_absolute() else base.qualification_spec.parent / target
            target = evidence._path(target, directory=key == "sidecar_root")
            roots.add(target if key == "sidecar_root" else target.parent)
    roots.add(base.plan_receipt.parent)
    pending,seen = [value["current_canonical"]],set()
    while pending:
        item = pending.pop()
        path,raw = evidence._reference(item)
        if path in seen:
            raise ValueError("selected runtime dependency contains a cycle")
        seen.add(path);roots.add(path.parent)
        canonical = evidence._json(raw)
        for key in ("client_reuse_recipe","client_reuse_proof","original_native_build_record"):
            if key in canonical:
                roots.add(evidence._reference(canonical[key])[0].parent)
        if canonical.get("original_canonical") is not None:
            pending.append(canonical["original_canonical"])
    for root in roots:
        evidence._path(root,directory=True)
        if any(c in str(root) for c in ("\n","\r","\0",":")):
            raise ValueError("selected parallel mounts require canonical absolute readonly roots")
    return sorted(root for root in roots if not any(root != parent and root.is_relative_to(parent) for parent in roots))
