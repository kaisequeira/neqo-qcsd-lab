"""Prospective same-setting parallel scheduling for current static preparation.

Both workers retain the same current runtime, complete original GET graphs,
derived amendment, named 120-response qualification and passed canary. This
contract grants no historical Source projection or qualification exemption.
Ordinary failed-only lane generations and independent deep checks are unchanged.
"""
from __future__ import annotations

from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping

from . import rapid_lane_evidence as lanes
from . import chaff_qualification as qualification
from . import rapid_rolling_capture as rolling
from . import rapid_rolling_readiness as evidence
from . import rapid_rolling_schedule as legacy
from . import buflo_duration_budget as budget
from . import supplied_static_capture_amendment as amendment
from .util import durable_create

CAPSULE_TYPE = "qcsd-rapid-v6-current-static-parallel-scheduling"
CONTRACT = "rolling-v6-current-static-same-setting-parallel-scheduling-v1"
CONTROL_FILES = (
    "src/qcsd_lab/rapid_static_parallel_schedule.py",
    "src/qcsd_lab/rapid_rolling_schedule.py",
    "src/qcsd_lab/rapid_formal_parallel.py",
    "src/qcsd_lab/rapid_runtime_epochs.py",
    "tools/rapid_rolling_capture.py",
)
KEYS = {"schema_version", "artifact_type", "contract", "base_spec", "runtime",
    "qualification_spec", "original_canonical", "current_canonical", "qualified_inputs",
    "control_sources", "static_capture_amendment", "mode", "traffic_hashes",
    "buflo_duration_policy", "reason", "published_at", "limits",
    "formal_accepted_trace_count", "scientific_credit"}


def _header(value: Any, *, before: str | None = None) -> None:
    if (not isinstance(value, dict) or set(value) != KEYS
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != CAPSULE_TYPE or value["contract"] != CONTRACT
        or value["limits"] != legacy.LIMITS
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False
        or not isinstance(value["reason"], str) or not value["reason"].strip()
        or type(value["mode"]) is not str or value["mode"] not in {"front", "buflo"}):
        raise ValueError("static scheduling capsule has an invalid exact contract")
    published = evidence._timestamp(value["published_at"])
    if (published > datetime.now(UTC) or before is not None
        and not published < evidence._timestamp(before) <= datetime.now(UTC)):
        raise ValueError("static scheduling must precede its new plan and intent")


def is_static(reference: Mapping[str, str]) -> bool:
    _, raw = evidence._reference(reference)
    value = evidence._json(raw)
    return isinstance(value, dict) and value.get("artifact_type") == CAPSULE_TYPE


def terminal_inputs(enrollment: Path, *, _context=None) -> tuple[set[Path], set[Path]]:
    """Authenticated selected prefix only, including inherited deferred GETs.

    Context declaration files are immutable; unrelated later terminal attempts
    stay outside the release fence. Complete declared GET trees and external
    namespace records remain dependencies for admitted and deferred decisions.
    """
    from . import supplied_static_admission as static
    from . import supplied_static_preparation as prep
    rolling._verify_enrollment(enrollment)
    files, trees, seen, terminals = set(), set(), set(), {}
    path = enrollment
    while True:
        batch = rolling.admission._unpack(lanes._read(path), rolling.ENROLLMENT_TYPE)
        context = static.load_context(Path(batch["admission_root"]))
        ancestor = context
        while ancestor.root not in seen:
            seen.add(ancestor.root)
            files.add(ancestor.root / "provenance.json")
            for key in ("source_list", "profile", "candidate_order"):
                files.add(prep.open_reference(ancestor.provenance[key]))
            # load_context authenticates the whole sealed inherited prefix,
            # including entries beyond this enrollment's selected decisions.
            # Later mutable terminal attempts are not part of that prefix.
            for reference in ancestor.provenance["inherited_terminals"]:
                terminals[rolling._open_ref(reference)] = (reference, ancestor)
            if ancestor.provenance["parent_context"] is None:
                break
            ancestor = static.load_context(prep.open_reference(ancestor.provenance["parent_context"]).parent)
        for decision in batch["decisions"]:
            reference = decision["terminal"]
            terminals[rolling._open_ref(reference)] = (reference, context)
        if batch["parent"] is None:
            break
        path = rolling._open_ref(batch["parent"])
    for terminal, (reference, context) in terminals.items():
        static.verify_terminal(terminal, context)
        value = rolling.admission._unpack(lanes._read(terminal), static.TERMINAL_TYPE)
        trees.add(terminal.parent)
        if value["get_evidence_root"] is not None:
            trees.add(evidence._path(value["get_evidence_root"], directory=True))
        if value["namespace"] is not None:
            files.update(prep.open_reference(value["namespace"][key]) for key in
                         ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    for item in files:
        evidence._path(item)
        if _context is not None:
            _context.watch_file(item)
    for item in trees:
        evidence._path(item, directory=True)
        if _context is not None:
            _context.watch_tree(item)
    return files, trees


def _qualified_inputs(base: lanes.CaptureSpec, qualifier: Path, sites: list[dict], *, _context=None) -> dict:
    """Full current named120 with static inline GET identity, no browser tree."""
    spec = evidence._json(evidence._read(qualifier))
    if (not isinstance(spec, dict) or set(spec) != {"schema_version", "qualification_sets"}
        or type(spec["schema_version"]) is not int or spec["schema_version"] != 1
        or not isinstance(spec["qualification_sets"], list) or len(spec["qualification_sets"]) != 1):
        raise ValueError("static scheduling requires its exact single current named qualification spec")
    row = spec["qualification_sets"][0]
    if (not isinstance(row, dict) or set(row) != {"qualification_set", "manifest", "sidecar_root", "prefix_spec_root"}
        or row["prefix_spec_root"] is not None):
        raise ValueError("static scheduling cannot replace full response qualification with fitting")
    def resolve(name):
        value = row[name]
        if not isinstance(value, str) or not value:
            raise ValueError("static scheduling qualification path is invalid")
        return evidence._path(Path(value) if Path(value).is_absolute() else qualifier.parent / value,
                              directory=name == "sidecar_root")
    manifest, sidecars = resolve("manifest"), resolve("sidecar_root")
    ids = [site["workload_id"] for site in sites]
    if not 1 <= len(ids) <= 5 or len(set(ids)) != len(ids):
        raise ValueError("static scheduling needs one to five complete unique site graphs")
    validator = (qualification.validate_named_qualification_set_manifest if _context is None else
        lambda value, **kwargs: _context.validate_named_qualification(value,
            qualification.validate_named_qualification_set_manifest, **kwargs))
    validator(evidence._json(evidence._read(manifest)), workload_root=base.workload_root,
        sidecar_root=sidecars, prefix_spec_root=None, expected_qualification_set=row["qualification_set"],
        # HOST reopening has no executed-image namespace. The exact current
        # canonical implementation SHA, Source and image are required below;
        # the worker's installed image check retains its ordinary current gate.
        expected_workload_ids=ids, expected_qualification_scope="response-only", require_current_implementation=False)
    workloads, implementations, sources = {}, {}, {}
    for site in sites:
        name = site["workload_id"]
        raw = evidence._read(base.workload_root / (name + ".json"), site["workload_sha256"])
        workload = evidence._json(raw)
        if not amendment.is_amended(workload["preparation"]):
            raise ValueError("static scheduling qualification lacks the exact amended preparation role")
        amendment.validate_preparation(workload["preparation"], workload["resources"])
        from .supplied_static_graph import canonical_bytes, digest
        workloads[name] = {"workload_sha256": evidence._sha(raw), "application_evidence": None,
            "resource_records_sha256": digest(canonical_bytes(workload["resources"])),
            "original_get_proof": workload["preparation"]["static_get_evidence"]["proof"]}
        sidecar = evidence._json(evidence._read(sidecars / (name + ".json")))
        if (type(sidecar.get("schema_version")) is not int
            or sidecar["schema_version"] != qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION):
            raise ValueError("static scheduling requires the complete current 120-response schema")
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
        raise ValueError("static scheduling requires one exact current canonical, runtime and qualifier")
    sites, plan = rolling.verify_capture_plan(base, require_current=False, _context=_context)
    if ("scheduling" in plan or "front_capture_amendment" in plan
        or "static_capture_amendment" not in plan or plan.get("study_version") != 6
        or plan.get("cohort_generation") != "rolling-50" or len(plan["readiness"]) != 1
        or not 1 <= len(sites) <= legacy.LIMITS["maximum_sites_per_batch"]
        or any(type(row["visits_per_workload"]) is not int or row["visits_per_workload"] != 4
               or row["workload_ids"] != [site.workload_id for site in sites] for row in plan["lanes"])):
        raise ValueError("static scheduling requires a current serial single-setting four-visit base plan")
    mode = next(iter(plan["readiness"]))
    reference = plan["static_capture_amendment"]
    closed = amendment.validate_amendment(rolling._open_ref(reference), enrollment=base.cohort, runtime=runtime)
    if mode not in closed["modes"]:
        raise ValueError("static scheduling setting is outside its exact amendment")
    canonical, sources = legacy.reopen_runtime(current, runtime)
    if (canonical["source"]["neqo_dirty"] is not False
        or canonical["source"]["neqo_commit"] != canonical["source"]["neqo_pinned_commit"]):
        raise ValueError("static scheduling changed its clean pinned Native Source")
    from . import rapid_capture_traffic as traffic
    selected = traffic.declared(plan)
    # Every current control authority is fixed even when this setting selects
    # the historical three traffic files. This does not relabel the original
    # amendment's eleven/ nineteen producer declarations.
    authority = [*amendment.authority_files(budget.POLICY).values(), *CONTROL_FILES]
    controls = {}
    for relative in authority:
        raw = (lanes._read(Path(import_module("qcsd_lab." + Path(relative).stem).__file__))
               if relative.startswith("src/qcsd_lab/") else
               lanes._read(Path(runtime["runtime_source_root"]) / relative))
        if sources.get(relative) != raw:
            raise ValueError("static scheduling installed amendment or control Source differs")
        controls[relative] = lanes._sha(raw)
    traffic_hashes = traffic.expected(selected)
    for name in ("runtime_source_root", "module_root", "execution_root"):
        for relative, digest in traffic.files(selected).values():
            evidence._read(Path(runtime[name]) / relative, digest)
    qualified = _qualified_inputs(base, qualifier, plan["sites"], _context=_context)
    source = {**canonical["source"], "image_digest": canonical["collection_image_digest"]}
    if (set(qualified["implementation_sha256"].values()) != {
            canonical["checks"]["collection"]["qualification_implementation_sha256"]}
        or any(row != {"source": source, "image": canonical["collection_image_digest"]}
               for row in qualified["qualification_sources"].values())):
        raise ValueError("static scheduling requires fresh current named 120-response qualification")
    row = next(row for row in plan["lanes"] if row["mode"] == mode)
    lane = lanes._lane({"plan_payload": plan}, row["campaign_name"])
    rolling.require_mode_readiness(base, lane, _context=_context)
    terminal_inputs(base.cohort, _context=_context)
    return {"qualified_inputs": qualified, "control_sources": controls,
            "static_capture_amendment": reference, "mode": mode,
            "traffic_hashes": traffic_hashes, traffic.FIELD: selected}


def publish_schedule(base_spec: lanes.CaptureSpec, runtime: Mapping[str, str], qualification_spec: Path,
                     original_canonical: Mapping[str, str], current_canonical: Mapping[str, str],
                     output: Path, *, reason: str) -> dict[str, str]:
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("static scheduling needs its explicit scientific scope")
    output = Path(output)
    if (not output.is_absolute() or ".." in output.parts
        or any(item.is_symlink() for item in (output, *output.parents))):
        raise ValueError("static scheduling output must be an absolute unlinked create-only path")
    for root in (base_spec.runtime_source_root, base_spec.module_root,
                 Path(current_canonical["path"]).parent):
        if output.is_relative_to(root):
            raise ValueError("static scheduling output must remain outside frozen runtime Source and closure")
    derived = _derive(base_spec, runtime, qualification_spec, original_canonical, current_canonical)
    now = datetime.now(UTC).isoformat()
    canonical = evidence._json(evidence._reference(current_canonical)[1])
    if evidence._timestamp(canonical["verified_at"]) > evidence._timestamp(now):
        raise ValueError("static scheduling predates actual current runtime closure")
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
        raise ValueError("static scheduling capsule belongs to another runtime")
    if _context is not None:
        _context._reference(reference)
        _context.bind_schedule(value)
    key = ("current-static-schedule", evidence._sha(raw))
    if _context is not None and _context.has(key):
        derived = _context.get(key)
    else:
        derived = _derive(legacy._spec(value["base_spec"]), value["runtime"], qualifier,
                          value["original_canonical"], value["current_canonical"], _context=_context)
        if _context is not None:
            _context.remember(key, derived)
    if any(value[name] != item for name, item in derived.items()):
        raise ValueError("static scheduling changed its current Source, traffic, graph or qualification")
    canonical = evidence._json(evidence._reference(value["current_canonical"])[1])
    if evidence._timestamp(canonical["verified_at"]) > evidence._timestamp(value["published_at"]):
        raise ValueError("static scheduling predates actual runtime closure")
    return value


def require_plan(payload: Mapping[str, Any], *, _context=None) -> dict:
    value = validate_schedule(payload["scheduling"], runtime=payload["runtime"],
                              before=payload["declared_at"], _context=_context)
    if (payload.get("static_capture_amendment") != value["static_capture_amendment"]
        or set(payload.get("readiness", {})) != {value["mode"]}
        or payload["readiness"][value["mode"]] != lanes._payload(
            legacy._spec(value["base_spec"]).plan_receipt, lanes.PLAN_TYPE)["readiness"][value["mode"]]
        or payload.get("buflo_duration_policy") != value["buflo_duration_policy"]):
        raise ValueError("static scheduled plan changed its exact amendment, setting, canary or traffic")
    return value


def validate_current_qualification(old_impl: Mapping, current_impl: Mapping, reference: Mapping[str, str],
                                   *, actual_image: str, before: str | None = None, _context=None) -> None:
    """Existing image environment hook; equal current receipts only.

    It grants no historical implementation substitution or capture authority.
    The ordinary actual-plan/spec hooks independently bind the study and lanes.
    """
    value = validate_schedule(reference, before=before, _context=_context)
    if actual_image != value["runtime"]["collection_image_digest"] or dict(old_impl) != dict(current_impl):
        raise ValueError("static scheduling permits only exact equal current qualification receipts")
    qualification._validate_implementation_receipt(current_impl, require_current=False)
    canonical = evidence._json(evidence._reference(value["current_canonical"])[1])
    inventory = evidence._json(evidence._read(Path(value["current_canonical"]["path"]).parent / "source-inventory.json",
                                             canonical["source_inventory_sha256"]))
    if (current_impl["schema_version"] != qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION
        or current_impl["sha256"] != canonical["checks"]["collection"]["qualification_implementation_sha256"]
        or current_impl["source"] != canonical["source"]
        or current_impl["neqo_qcsd_client"]["sha256"] != canonical["installed_client_sha256"]
        or any(inventory.get(path, {}).get("sha256") != digest for path, digest in current_impl["source_files"].items())):
        raise ValueError("static scheduling changed the exact current qualification implementation")


def mount_roots(reference: Mapping[str, str], *, _context=None) -> list[Path]:
    value = validate_schedule(reference, _context=_context)
    base = legacy._spec(value["base_spec"])
    files, trees = terminal_inputs(base.cohort, _context=_context)
    roots = {Path(reference["path"]).parent, *trees, *(path.parent for path in files)}
    roots.update(rolling.enrollment_roots(base))
    for role in (base.serializable(), value["runtime"]):
        roots.update(Path(role[key]) for key in
                     ("runtime_source_root", "module_root", "execution_root"))
        roots.update(Path(role[key]).parent for key in
                     ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    pending, seen = [value["current_canonical"]], set()
    while pending:
        path, raw = evidence._reference(pending.pop())
        if path in seen:
            raise ValueError("static scheduling runtime transport contains a reuse cycle")
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
            raise ValueError("static scheduling transport requires regular absolute roots")
    return sorted(roots)
