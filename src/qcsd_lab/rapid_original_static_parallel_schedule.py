"""Current same-setting parallel capture of unchanged original static graphs.

Undefended, Tamaraw and CS-BuFLO retain the complete admitted manifest and
its original capture policies. Each setting has its own current-runtime canary
and current named120 qualification; no amendment or historical reuse is granted.
Existing FRONT/BuFLO amendment and scheduling authorities remain separate.
"""
from __future__ import annotations

from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import chaff_qualification as qualification
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_rolling_readiness as evidence
from . import rapid_rolling_schedule as legacy
from . import rapid_static_parallel_schedule as amended
from . import supplied_static_graph as graph
from . import supplied_static_preparation as preparation
from .util import durable_create

CAPSULE_TYPE = "qcsd-rapid-v6-current-original-static-parallel-scheduling"
CONTRACT = "rolling-v6-current-original-static-same-setting-parallel-scheduling-v1"
MODES = frozenset({"undefended", "tamaraw", "cs-buflo"})
CONTROL_FILES = (*amended.CONTROL_FILES,
    "src/qcsd_lab/rapid_runtime_inspector.py",
    "src/qcsd_lab/rapid_original_static_parallel_schedule.py",
    "src/qcsd_lab/rapid_rolling_capture.py",
    "src/qcsd_lab/rapid_operation_facts.py",
    "src/qcsd_lab/rapid_rolling_readiness.py")
KEYS = {"schema_version", "artifact_type", "contract", "base_spec", "runtime",
    "qualification_spec", "original_canonical", "current_canonical", "qualified_inputs",
    "control_sources", "data_role", "mode", "traffic_hashes", "reason", "published_at",
    "limits", "formal_accepted_trace_count", "scientific_credit"}


def _header(value: Any, *, before: str | None = None) -> None:
    if (not isinstance(value, dict) or set(value) != KEYS
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != CAPSULE_TYPE or value["contract"] != CONTRACT
        or value["limits"] != legacy.LIMITS or value["data_role"] != preparation.ROLE
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False
        or not isinstance(value["reason"], str) or not value["reason"].strip()
        or type(value["mode"]) is not str or value["mode"] not in MODES):
        raise ValueError("original static scheduling capsule has an invalid exact contract")
    published = evidence._timestamp(value["published_at"])
    if (published > datetime.now(UTC) or before is not None
        and not published < evidence._timestamp(before) <= datetime.now(UTC)):
        raise ValueError("original static scheduling must precede its new plan and intent")


def is_static(reference: Mapping[str, str]) -> bool:
    return evidence._json(evidence._reference(reference)[1]).get("artifact_type") == CAPSULE_TYPE


def _qualified_inputs(base: lanes.CaptureSpec, qualifier: Path, sites: list[dict], *, _context=None) -> dict:
    spec = evidence._json(evidence._read(qualifier))
    if (set(spec) != {"schema_version", "qualification_sets"}
        or type(spec["schema_version"]) is not int or spec["schema_version"] != 1
        or not isinstance(spec["qualification_sets"], list) or len(spec["qualification_sets"]) != 1):
        raise ValueError("original static scheduling requires one exact current named qualification spec")
    row = spec["qualification_sets"][0]
    if (not isinstance(row, dict) or set(row) != {"qualification_set", "manifest", "sidecar_root", "prefix_spec_root"}
        or row["prefix_spec_root"] is not None):
        raise ValueError("original static scheduling requires full response qualification without fitting")
    def resolve(name):
        value = row[name]
        if not isinstance(value, str) or not value:
            raise ValueError("original static qualification path is invalid")
        return evidence._path(Path(value) if Path(value).is_absolute() else qualifier.parent / value,
                              directory=name == "sidecar_root")
    manifest, sidecars = resolve("manifest"), resolve("sidecar_root")
    ids = [site["workload_id"] for site in sites]
    if not 1 <= len(ids) <= legacy.LIMITS["maximum_sites_per_batch"] or len(set(ids)) != len(ids):
        raise ValueError("original static scheduling needs one to five complete unique site graphs")
    validator = (qualification.validate_named_qualification_set_manifest if _context is None else
        lambda value, **kwargs: _context.validate_named_qualification(value,
            qualification.validate_named_qualification_set_manifest, **kwargs))
    validator(evidence._json(evidence._read(manifest)), workload_root=base.workload_root,
        sidecar_root=sidecars, prefix_spec_root=None, expected_qualification_set=row["qualification_set"],
        expected_workload_ids=ids, expected_qualification_scope="response-only", require_current_implementation=False)
    workloads, implementations, sources = {}, {}, {}
    for site in sites:
        name = site["workload_id"]
        raw = evidence._read(base.workload_root / (name + ".json"), site["workload_sha256"])
        workload = evidence._json(raw)
        if not preparation.is_static(workload["preparation"]):
            raise ValueError("original static scheduling requires unchanged original preparation")
        preparation.validate_static_preparation(workload["preparation"], workload["resources"])
        workloads[name] = {"workload_sha256": evidence._sha(raw), "application_evidence": None,
            "resource_records_sha256": graph.digest(graph.canonical_bytes(workload["resources"])),
            "original_get_proof": workload["preparation"]["static_get_evidence"]["proof"]}
        sidecar = evidence._json(evidence._read(sidecars / (name + ".json")))
        if (type(sidecar.get("schema_version")) is not int
            or sidecar["schema_version"] != qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION):
            raise ValueError("original static scheduling requires the complete current 120-response schema")
        implementations[name] = sidecar["implementation_receipt"]["sha256"]
        sources[name] = {"source": sidecar["qualification_source"], "image": sidecar["qualification_image_digest"]}
    return {"enrollment_sha256": evidence._sha(evidence._read(base.cohort)),
        "qualification_spec_sha256": evidence._sha(evidence._read(qualifier)), "named_set": row["qualification_set"],
        "named_manifest_sha256": evidence._sha(evidence._read(manifest)),
        "qualification_files": evidence._inventory(sidecars), "workloads": workloads,
        "implementation_sha256": implementations, "qualification_sources": sources}


def _derive(base: lanes.CaptureSpec, runtime: Mapping[str, str], qualifier: Path,
            original: Mapping[str, str], current: Mapping[str, str], *, _context=None) -> dict:
    lanes._check_spec(base)
    runtime = rolling._runtime(runtime)
    if (dict(original) != dict(current)
        or runtime != {key: base.serializable()[key] for key in rolling.RUNTIME_FIELDS}
        or rolling._ref(qualifier) != rolling._ref(base.qualification_spec)):
        raise ValueError("original static scheduling requires one exact current canonical, runtime and qualifier")
    sites, plan = rolling.verify_capture_plan(base, require_current=False, _context=_context)
    if (any(name in plan for name in ("scheduling", "front_capture_amendment", "static_capture_amendment", "buflo_duration_policy"))
        or plan.get("data_role") != preparation.ROLE or plan.get("study_version") != 6
        or plan.get("cohort_generation") != "rolling-50" or len(plan["readiness"]) != 1
        or not 1 <= len(sites) <= legacy.LIMITS["maximum_sites_per_batch"]
        or any(type(row["visits_per_workload"]) is not int or row["visits_per_workload"] != 4
               or row["workload_ids"] != [site.workload_id for site in sites] for row in plan["lanes"])):
        raise ValueError("original static scheduling requires a serial unchanged single-setting four-visit base plan")
    mode = next(iter(plan["readiness"]))
    if mode not in MODES:
        raise ValueError("original static scheduling cannot replace FRONT or BuFLO amendments")
    canonical, sources = legacy.reopen_runtime(current, runtime, _inspector=True)
    if (canonical["source"]["neqo_dirty"] is not False
        or canonical["source"]["neqo_commit"] != canonical["source"]["neqo_pinned_commit"]):
        raise ValueError("original static scheduling changed its clean pinned Native Source")
    controls = {}
    for relative in CONTROL_FILES:
        raw = (lanes._read(Path(import_module("qcsd_lab." + Path(relative).stem).__file__))
               if relative.startswith("src/qcsd_lab/") else
               lanes._read(Path(runtime["runtime_source_root"]) / relative))
        if sources.get(relative) != raw or lanes._read(Path(runtime["module_root"]) / relative) != raw:
            raise ValueError("original static scheduling installed control Source differs")
        controls[relative] = lanes._sha(raw)
    for name in ("runtime_source_root", "module_root", "execution_root"):
        for relative, digest in lanes.TRAFFIC_FILES.values():
            evidence._read(Path(runtime[name]) / relative, digest)
    qualified = _qualified_inputs(base, qualifier, plan["sites"], _context=_context)
    source = {**canonical["source"], "image_digest": canonical["collection_image_digest"]}
    if (set(qualified["implementation_sha256"].values()) != {
            canonical["checks"]["collection"]["qualification_implementation_sha256"]}
        or any(row != {"source": source, "image": canonical["collection_image_digest"]}
               for row in qualified["qualification_sources"].values())):
        raise ValueError("original static scheduling requires fresh current named 120-response qualification")
    row = next(row for row in plan["lanes"] if row["mode"] == mode)
    lane = lanes._lane({"plan_payload": plan}, row["campaign_name"])
    canary = rolling.require_mode_readiness(base, lane, _context=_context)
    canary_runtime = {key: base.serializable()[key] for key in lanes.RUNTIME_KEYS}
    facts = (evidence.validate_canary(canary, runtime=canary_runtime, mode=mode) if _context is None else
             _context.validate_canary(canary, canary_runtime, mode, evidence.validate_canary))
    matching = [site for site in sites if site.workload_sha256 == facts.get("workload_sha256")]
    if len(matching) != 1:
        raise ValueError("original static canary is not a unique complete enrolled workload")
    workload = evidence._json(evidence._read(base.workload_root / (matching[0].workload_id + ".json"),
                                           matching[0].workload_sha256))
    resources = workload["resources"]
    expected_graph = {"resource_count": len(resources),
        "resource_records_sha256": evidence._sha(evidence._encoded(resources)),
        "origins": sorted({f'{urlsplit(item["url"]).scheme}://{urlsplit(item["url"]).netloc}'
                           for item in resources})}
    if facts.get("full_graph") != expected_graph:
        raise ValueError("original static canary changed its complete enrolled graph")
    amended.terminal_inputs(base.cohort, _context=_context)
    return {"qualified_inputs": qualified, "control_sources": controls,
            "data_role": preparation.ROLE, "mode": mode,
            "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}}


def publish_schedule(base_spec: lanes.CaptureSpec, runtime: Mapping[str, str], qualification_spec: Path,
                     original_canonical: Mapping[str, str], current_canonical: Mapping[str, str],
                     output: Path, *, reason: str) -> dict[str, str]:
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("original static scheduling needs its explicit scientific scope")
    output = Path(output)
    if (not output.is_absolute() or ".." in output.parts
        or any(item.is_symlink() for item in (output, *output.parents))):
        raise ValueError("original static scheduling output must be an absolute unlinked create-only path")
    for root in (base_spec.runtime_source_root, base_spec.module_root, Path(current_canonical["path"]).parent):
        if output.is_relative_to(root):
            raise ValueError("original static scheduling output must remain outside frozen Source and runtime closure")
    derived = _derive(base_spec, runtime, qualification_spec, original_canonical, current_canonical)
    now = datetime.now(UTC).isoformat()
    canonical = evidence._json(evidence._reference(current_canonical)[1])
    if evidence._timestamp(canonical["verified_at"]) > evidence._timestamp(now):
        raise ValueError("original static scheduling predates actual current runtime closure")
    payload = {"schema_version": 1, "artifact_type": CAPSULE_TYPE, "contract": CONTRACT,
        "base_spec": base_spec.serializable(), "runtime": dict(runtime),
        "qualification_spec": rolling._ref(qualification_spec), "original_canonical": dict(original_canonical),
        "current_canonical": dict(current_canonical), **derived, "reason": reason.strip(), "published_at": now,
        "limits": dict(legacy.LIMITS), "formal_accepted_trace_count": 0, "scientific_credit": False}
    durable_create(output, evidence._encoded(payload))
    return rolling._ref(output)


def validate_schedule(reference: Mapping[str, str], *, runtime: Mapping[str, str] | None = None,
                      before: str | None = None, _context=None) -> dict:
    _, raw = evidence._reference(reference)
    value = evidence._json(raw)
    _header(value, before=before)
    qualifier, _ = evidence._reference(value["qualification_spec"])
    if runtime is not None and dict(runtime) != value["runtime"]:
        raise ValueError("original static scheduling capsule belongs to another runtime")
    if _context is not None:
        _context._reference(reference)
        _context.bind_schedule(value)
    key = ("current-original-static-schedule", evidence._sha(raw))
    if _context is not None and _context.has(key):
        derived = _context.get(key)
    else:
        derived = _derive(legacy._spec(value["base_spec"]), value["runtime"], qualifier,
                          value["original_canonical"], value["current_canonical"], _context=_context)
        if _context is not None:
            _context.remember(key, derived)
    if any(value[name] != item for name, item in derived.items()):
        raise ValueError("original static scheduling changed its current Source, traffic, graph or qualification")
    canonical = evidence._json(evidence._reference(value["current_canonical"])[1])
    if evidence._timestamp(canonical["verified_at"]) > evidence._timestamp(value["published_at"]):
        raise ValueError("original static scheduling predates actual runtime closure")
    return value


def require_plan(payload: Mapping[str, Any], *, _context=None) -> dict:
    value = validate_schedule(payload["scheduling"], runtime=payload["runtime"],
                              before=payload["declared_at"], _context=_context)
    base_plan = lanes._payload(legacy._spec(value["base_spec"]).plan_receipt, lanes.PLAN_TYPE)
    if (payload.get("data_role") != preparation.ROLE
        or any(name in payload for name in ("front_capture_amendment", "static_capture_amendment", "buflo_duration_policy"))
        or set(payload.get("readiness", {})) != {value["mode"]}
        or payload["readiness"][value["mode"]] != base_plan["readiness"][value["mode"]]):
        raise ValueError("original static scheduled plan changed its unchanged role, setting, canary or traffic")
    return value


def validate_current_qualification(old_impl: Mapping, current_impl: Mapping, reference: Mapping[str, str],
                                   *, actual_image: str, before: str | None = None, _context=None) -> None:
    value = validate_schedule(reference, before=before, _context=_context)
    if actual_image != value["runtime"]["collection_image_digest"] or dict(old_impl) != dict(current_impl):
        raise ValueError("original static scheduling permits only exact equal current qualification receipts")
    qualification._validate_implementation_receipt(current_impl, require_current=False)
    canonical = evidence._json(evidence._reference(value["current_canonical"])[1])
    inventory = evidence._json(evidence._read(Path(value["current_canonical"]["path"]).parent / "source-inventory.json",
                                             canonical["source_inventory_sha256"]))
    if (current_impl["schema_version"] != qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION
        or current_impl["sha256"] != canonical["checks"]["collection"]["qualification_implementation_sha256"]
        or current_impl["source"] != canonical["source"]
        or current_impl["neqo_qcsd_client"]["sha256"] != canonical["installed_client_sha256"]
        or any(inventory.get(path, {}).get("sha256") != digest for path, digest in current_impl["source_files"].items())):
        raise ValueError("original static scheduling changed the exact current qualification implementation")


def mount_roots(reference: Mapping[str, str], *, _context=None) -> list[Path]:
    value = validate_schedule(reference, _context=_context)
    base = legacy._spec(value["base_spec"])
    files, trees = amended.terminal_inputs(base.cohort, _context=_context)
    roots = {Path(reference["path"]).parent, *trees, *(path.parent for path in files)}
    roots.update(rolling.enrollment_roots(base))
    for role in (base.serializable(), value["runtime"]):
        roots.update(Path(role[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
        roots.update(Path(role[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    pending, seen = [value["current_canonical"]], set()
    while pending:
        path, raw = evidence._reference(pending.pop())
        if path in seen:
            raise ValueError("original static runtime transport contains a reuse cycle")
        seen.add(path)
        roots.add(path.parent)
        canonical = evidence._json(raw)
        for key in ("client_reuse_recipe", "client_reuse_proof", "original_native_build_record"):
            if key in canonical:
                roots.add(evidence._reference(canonical[key])[0].parent)
        if canonical.get("original_canonical") is not None:
            pending.append(canonical["original_canonical"])
    for root in roots:
        evidence._path(root, directory=True)
        if any(c in str(root) for c in ("\n", "\r", "\0", ":")):
            raise ValueError("original static scheduling transport requires regular absolute roots")
    return sorted(roots)
