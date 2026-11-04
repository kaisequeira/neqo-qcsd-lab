"""Explicit serial ordinary capture from complete admitted resource graphs.

This input declares no padding responses. It authorizes only the undefended
setting after its own current full-site canary and independent deep checks.
The historical qualified five-setting contract remains a separate path.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from . import rapid_capture_plan as plan
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_site_admission as admission

INPUT_TYPE = "qcsd-rapid-admitted-ordinary-only-input-v1"
CONTRACT = "complete-admitted-graphs-current-ordinary-canary-no-padding-qualification-v1"
FIELD = "ordinary_capture_contract"
RENEWAL_TYPE = "qcsd-rapid-ordinary-unchanged-selected-input-renewal-v1"


@dataclass(frozen=True)
class OrdinarySite(plan.Site):
    """A site whose explicit ordinary input declares no padding qualification."""


def _read(path: Path) -> bytes:
    from .rapid_operation_facts import current_context
    context = current_context()
    return lanes._read(path) if context is None else context.watch_file(path)


def _reference(path: Path) -> dict:
    path = Path(path).absolute()
    raw = _read(path)
    return {"path": str(path), "sha256": lanes._sha(raw)}


def _sources() -> dict[str, str]:
    from . import rapid_undefended_capture as own
    return {module.__name__: lanes._sha(_read(Path(module.__file__)))
            for module in (own, plan, lanes, rolling)}


def is_inputs(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("artifact_type") == INPUT_TYPE


def check_sites(sites: Sequence[plan.Site], *, final: bool, study_version: int) -> tuple[OrdinarySite, ...]:
    selected = tuple(sites)
    if (not final or type(study_version) is not int or study_version != 6
            or not 1 <= len(selected) <= 5
            or any(type(site) is not OrdinarySite for site in selected)):
        raise ValueError("ordinary-only capture requires one to five explicitly typed enrolled sites")
    for site in selected:
        try:
            parsed = urlsplit(site.primary_origin)
            canonical = (parsed.scheme == "https" and parsed.hostname is not None
                and parsed.netloc == parsed.hostname and not parsed.path
                and not parsed.query and not parsed.fragment
                and parsed.username is None and parsed.password is None)
        except (TypeError, ValueError):
            canonical = False
        if (not isinstance(site.candidate_id, str) or plan.IDENTIFIER_RE.fullmatch(site.candidate_id) is None
                or not isinstance(site.workload_id, str) or plan.IDENTIFIER_RE.fullmatch(site.workload_id) is None
                or not isinstance(site.workload_sha256, str) or plan.SHA256_RE.fullmatch(site.workload_sha256) is None
                or not canonical or site.qualification_set is not None
                or site.qualification_set_manifest_sha256 is not None):
            raise ValueError("ordinary-only site changed its full workload or no-padding identity")
    for field in ("candidate_id", "workload_id", "primary_origin"):
        values = [getattr(site, field) for site in selected]
        if len(values) != len(set(values)):
            raise ValueError("ordinary-only capture repeats an enrolled site identity")
    return selected


def plan_lanes(sites, *, final, study_version, rolling_batch):
    selected = check_sites(sites, final=final, study_version=study_version)
    if type(rolling_batch) is not int or not 1 <= rolling_batch <= 50:
        raise ValueError("ordinary-only capture requires its immutable enrollment ordinal")
    return tuple(plan.Lane("formal", block, rolling_batch, "undefended",
        plan._campaign_name("formal", block, rolling_batch, "undefended", 1, 6),
        tuple(site.workload_id for site in selected), 4, None, 1, 6)
        for block in range(1, 17))


def _renew_rows(enrollment, batch, classes, policy, renewals):
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    from . import rapid_selected_capture_input as plain
    from . import rapid_per_class_selected_input as facade
    from . import selected_capture_amendment as amendment
    if policy["contract"] == per_class.CONTRACT:
        from . import per_class_selected_capture_amendment as amendment
        facade_module = facade
    elif policy["contract"] == additive.CONTRACT:
        facade_module = plain
    else:
        raise ValueError("ordinary renewal supports only explicit selected enrollment")
    chosen = classes[-len(batch["selected_candidate_ids"]):]
    rolling._keys(renewals, set(batch["selected_candidate_ids"]), "ordinary renewal map")
    rows = []
    for row in chosen:
        original, previous = amendment._original(row)
        renewal = renewals[row["candidate_id"]]
        rolling._keys(renewal, {"input", "manifest"}, "ordinary input renewal")
        input_path = facade_module.reopen(renewal["input"])
        validator = (facade_module.module_for_preparation(original["preparation"])
                     if policy["contract"] == per_class.CONTRACT else plain)
        current, baseline, _ = validator.validate_input(input_path)
        path = facade_module.reopen(renewal["manifest"])
        manifest = lanes._load(_read(path))
        validator.validate_preparation(manifest["preparation"], manifest["resources"])
        expected = deepcopy(baseline)
        field = "selected_input_evidence" if validator is plain else validator.FIELD
        expected["preparation"].update(data_role=validator.ROLE, **{field: {
            "schema_version": 1, "record_type": validator.RECEIPT_TYPE, "receipt": dict(renewal["input"])}})
        retained = ("original_manifest", "original_role", "workload_id", "canonical_sites", "selection_audit",
            "raw_root", "raw_inventory", "proof", "declaration", "namespace", "neutral", "approved_origins",
            "capture_limits", "measurement_runtime", "recorded_producer_sources")
        if (manifest != expected or manifest["resources"] != original["resources"]
                or path.stem != row["workload_id"] or current["candidate_id"] != row["candidate_id"]
                or any(current[key] != previous[key] for key in retained)):
            raise ValueError("ordinary renewal changed original GET, full graph, requests, policies, caps or producer labels")
        rows.append({"candidate_id": row["candidate_id"], "class_index": row["class_index"],
            "workload_id": row["workload_id"], "original_manifest": dict(row["prepared_workload"]),
            "current_manifest": dict(renewal["manifest"]), "current_input": dict(renewal["input"])})
    return rows


def publish_renewal(enrollment: Path, output: Path) -> Path:
    """Reissue only current selected validation; preserve immutable raw GET."""
    from . import rapid_selected_capture_input as plain
    from . import rapid_per_class_selected_enrollment as per_class
    from . import rapid_per_class_selected_input as facade
    from . import selected_capture_amendment as amendment
    from .rapid_operation_facts import OperationFacts, current_context
    from .util import fsync_directory
    context = current_context()
    if context is None:
        with OperationFacts().scope() as context:
            result = publish_renewal(enrollment, output)
            context.check()
            return result
    context._enrollment(enrollment)
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    if policy["contract"] == per_class.CONTRACT:
        from . import per_class_selected_capture_amendment as amendment
        facade_module = facade
    else:
        from .rapid_additive_static_enrollment import CONTRACT as selected_contract
        if policy["contract"] != selected_contract:
            raise ValueError("ordinary renewal requires selected enrollment")
        facade_module = plain
    output = output.absolute()
    inputs = output.with_name(output.stem + "-inputs")
    if any(path.exists() or path.is_symlink() for path in (output, inputs)):
        raise ValueError("ordinary renewal requires create-only outputs")
    lanes._regular_directory(output.parent)
    chosen = classes[-len(batch["selected_candidate_ids"]):]
    prior = [(row, amendment._original(row)) for row in chosen]
    context.check()
    inputs.mkdir(mode=0o700)
    fsync_directory(inputs)
    fsync_directory(inputs.parent)
    renewals = {}
    for row, (original, previous) in prior:
        validator = (facade_module.module_for_preparation(original["preparation"])
                     if policy["contract"] == per_class.CONTRACT else plain)
        if previous["direct_validator_sources"] == validator.direct_sources():
            ref = facade_module.receipt_ref(original["preparation"]) if facade_module is facade else original["preparation"]["selected_input_evidence"]["receipt"]
            renewals[row["candidate_id"]] = {"input": ref, "manifest": dict(row["prepared_workload"])}
        else:
            new_input = inputs / (row["workload_id"] + "-input.json")
            validator.publish_input(new_input, audit=facade_module.reopen(previous["selection_audit"]), candidate_id=row["candidate_id"])
            new_manifest = inputs / (row["workload_id"] + ".json")
            validator.prepare_input(new_input, new_manifest)
            renewals[row["candidate_id"]] = {"input": facade_module.reference(new_input),
                "manifest": facade_module.reference(new_manifest)}
    rows = _renew_rows(enrollment, batch, classes, policy, renewals)
    value = {"schema_version": 1, "artifact_type": RENEWAL_TYPE, "contract": CONTRACT,
        "mode": "undefended", "enrollment": _reference(enrollment), "renewals": renewals,
        "rows": rows, "control_sources": _sources(), "scientific_credit": False,
        "formal_accepted_trace_count": 0}
    context.check()
    admission.durable_create(output, lanes._json(value))
    context.watch_file(output)
    return output


def validate_renewal(path: Path, enrollment: Path):
    value = lanes._load(_read(path))
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    fields = {"schema_version", "artifact_type", "contract", "mode", "enrollment", "renewals",
        "rows", "control_sources", "scientific_credit", "formal_accepted_trace_count"}
    rolling._keys(value, fields, "ordinary renewal")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["artifact_type"] != RENEWAL_TYPE or value["contract"] != CONTRACT
            or value["mode"] != "undefended" or value["enrollment"] != _reference(enrollment)
            or value["control_sources"] != _sources() or value["scientific_credit"] is not False
            or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or value["rows"] != _renew_rows(enrollment, batch, classes, policy, value["renewals"])):
        raise ValueError("ordinary renewal changed its exact selected class, graph, Source or zero-credit authority")
    return value, batch, classes, policy


def flight_inputs(path: Path, enrollment: Path, study: Path):
    """Portable stage intake for this explicit ordinary renewal only."""
    from . import rapid_selected_capture_input as plain
    from . import rapid_per_class_selected_input as facade
    value, batch, classes, policy = validate_renewal(path, enrollment)
    if rolling._open_ref(batch["policy"]).parent != Path(study).absolute():
        raise ValueError("ordinary renewed flight changed its selected study")
    from .static_evidence_transport import manifest_roots
    from .rapid_additive_static_enrollment import membership_inputs
    from .rapid_per_class_selected_enrollment import CONTRACT as per_class_contract, membership_inputs as per_class_inputs
    metadata = (per_class_inputs if policy["contract"] == per_class_contract else membership_inputs)(enrollment)
    roots = {Path(path).absolute().parent, *(item.parent for item in metadata)}
    bindings, manifests = [], []
    selected_rows = classes[-len(batch["selected_candidate_ids"]):]
    for row, renewed in zip(selected_rows, value["rows"]):
        original = facade.reopen(renewed["current_manifest"])
        manifest = lanes._load(_read(original))
        roots.update(manifest_roots(manifest))
        # The portable producer owns its exact full graph description.
        bindings.append({"candidate_id": row["candidate_id"], "class_index": row["class_index"],
            "admission_root": row["admission_root"], "terminal": {key: row["terminal"][key] for key in ("path", "sha256")},
            "original_workload": {key: renewed["current_manifest"][key] for key in ("path", "sha256")},
            "workload_id": row["workload_id"], "selection_sha256": policy["admission_identity"]["profile_sha256"]})
        manifests.append(manifest)
    return batch, policy, bindings, manifests, sorted(str(root) for root in roots), {
        **rolling._effective_capture_limits(batch, classes, policy), "max_attempts": 1}


def _admitted_sites(batch, classes, policy, workload_root, renewal=None):
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    from . import rapid_selected_capture_input as selected
    from . import rapid_per_class_selected_input as facade
    from .discover import origin
    if policy["contract"] not in {rolling.STATIC_CONTRACT, additive.CONTRACT, per_class.CONTRACT}:
        raise ValueError("ordinary-only inputs require complete static or selected GET admission")
    chosen = classes[-len(batch["selected_candidate_ids"]):]
    if [row["candidate_id"] for row in chosen] != batch["selected_candidate_ids"] or not 1 <= len(chosen) <= 5:
        raise ValueError("ordinary-only inputs changed the exact enrolled tail order")
    sites = []
    renewals = None if renewal is None else renewal["renewals"]
    for row in chosen:
        if policy["contract"] in {additive.CONTRACT, per_class.CONTRACT}:
            validator = facade if policy["contract"] == per_class.CONTRACT else selected
            original = validator.reopen(row["prepared_workload"] if renewals is None else renewals[row["candidate_id"]]["manifest"])
            workload = lanes._load(_read(original))
            validator.validate_preparation(workload["preparation"], workload["resources"])
        else:
            context = rolling._context_for_policy(policy, Path(row["admission_root"]))
            terminal = rolling._open_ref(row["terminal"])
            rolling._verify_terminal(context, terminal)
            original, workload = rolling._prepared_workload(context, terminal)
        if row["workload_id"] != original.stem or _read(Path(workload_root) / original.name) != _read(original):
            raise ValueError("ordinary-only capture changed or pruned an admitted complete graph")
        sites.append(OrdinarySite(row["candidate_id"], original.stem, lanes._sha(_read(original)),
            origin(workload["preparation"]["final_url"]), None, None))
    return check_sites(sites, final=True, study_version=6)


def _derive(enrollment: Path, runtime: Mapping[str, str], renewal=None):
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    value = rolling._runtime(dict(runtime))
    if value["data_root"] != policy["runtime"]["data_root"]:
        raise ValueError("ordinary-only runtime changed the enrolled study data root")
    renewal_value = None
    if renewal is not None:
        rolling._keys(renewal, {"path", "sha256"}, "ordinary renewal reference")
        if not Path(renewal["path"]).resolve().is_relative_to(Path(value["data_root"]).resolve()):
            raise ValueError("ordinary renewal must remain inside the authenticated runtime data root")
        if _reference(Path(renewal["path"])) != renewal:
            raise ValueError("ordinary renewal reference changed")
        renewal_value = validate_renewal(Path(renewal["path"]), enrollment)[0]
        if any(not Path(row[key]["path"]).resolve().is_relative_to(Path(value["data_root"]).resolve())
               for row in renewal_value["rows"] for key in ("current_input", "current_manifest")):
            raise ValueError("ordinary renewed inputs and manifests must remain inside the authenticated runtime data root")
    sites = _admitted_sites(batch, classes, policy, Path(value["workload_root"]), renewal=renewal_value)
    limits = rolling._effective_capture_limits(batch, classes, policy)
    if limits is None:
        raise ValueError("ordinary-only inputs require explicit per-flight admitted capture limits")
    return {"schema_version": 1, "artifact_type": INPUT_TYPE, "contract": CONTRACT,
        "mode": "undefended", "padding_qualification_required": False,
        "enrollment": _reference(enrollment), "runtime": value,
        "runtime_artifacts": {key: _reference(Path(value[key])) for key in
            ("source_manifest", "client_binary", "base_launcher", "host_launcher")},
        "renewal": renewal,
        "sites": [asdict(site) for site in sites], "capture_limits": limits,
        "control_sources": _sources(), "formal_accepted_trace_count": 0,
        "scientific_credit": False}, sites


def publish_inputs(enrollment: Path, runtime: Mapping[str, str], output: Path, *, renewal=None) -> Path:
    from .rapid_operation_facts import OperationFacts, current_context
    context = current_context()
    if context is None:
        with OperationFacts().scope() as context:
            result = publish_inputs(enrollment, runtime, output, renewal=renewal)
            context.check()
            return result
    context._enrollment(enrollment)
    value, _ = _derive(enrollment, runtime, renewal=renewal)
    context.check()
    admission.durable_create(output, lanes._json(value))
    context.watch_file(output)
    context.check()
    return output


def validate_inputs(path: Path, *, enrollment: Path, runtime: Mapping[str, str], require_current=False):
    value = lanes._load(_read(path))
    if "ordinary_transport_control" in value:
        from .rapid_ordinary_transport_control import validate_inputs as validate_transport_inputs
        return validate_transport_inputs(path, enrollment=enrollment, runtime=runtime,
                                         require_current=require_current)
    expected, sites = _derive(enrollment, runtime, renewal=value.get("renewal"))
    if value != expected or type(value.get("schema_version")) is not int or type(value.get("formal_accepted_trace_count")) is not int:
        raise ValueError("ordinary-only input changed its exact enrollment, full graphs, caps, runtime or Source")
    if require_current:
        for relative in ("rapid_undefended_capture.py", "rapid_capture_plan.py", "rapid_lane_evidence.py", "rapid_rolling_capture.py"):
            own = _read(Path(__file__).parent / relative)
            for key in ("runtime_source_root", "module_root"):
                if _read(Path(runtime[key]) / "src/qcsd_lab" / relative) != own:
                    raise ValueError("ordinary-only control differs from actual installed and frozen Source")
    return sites


def sites_from_enrollment(batch, classes, path, workload_root, *, enrollment, runtime, require_current,
                          front_capture_amendment=None, static_capture_amendment=None,
                          delivery_compatibility=None, **kwargs):
    if enrollment is None or runtime is None or any(item is not None for item in
            (front_capture_amendment, static_capture_amendment, delivery_compatibility)):
        raise ValueError("ordinary-only capture has separate serial unamended authority")
    if str(Path(workload_root)) != runtime["workload_root"]:
        raise ValueError("ordinary-only inputs changed the current complete workload root")
    return validate_inputs(path, enrollment=enrollment,
        runtime={key: runtime[key] for key in rolling.RUNTIME_FIELDS}, require_current=require_current)


def require_plan(value: Mapping[str, Any]) -> None:
    if (value.get(FIELD) != CONTRACT or value.get("study_version") != 6
            or type(value.get("study_version")) is not int or value.get("cohort_generation") != "rolling-50"
            or not isinstance(value.get("readiness"), dict) or set(value["readiness"]) != {"undefended"}
            or any(key in value for key in ("scheduling", "static_capture_amendment", "front_capture_amendment",
                "qualification_delivery_compatibility", "buflo_duration_policy"))
            or any(row.get("mode") != "undefended" or row.get("qualification_set") is not None for row in value.get("lanes", []))):
        raise ValueError("ordinary-only plan cannot authorize padding or another capture setting")


def require_canary(facts, sites) -> None:
    if facts.get("ordinary_canary_carry") is not None:
        from .rapid_ordinary_canary_carry import TYPE
        if (facts["ordinary_canary_carry"] != TYPE or not sites or facts.get("mode") != "undefended"
                or facts.get("authority_workload_sha256") != sites[0].workload_sha256
                or facts.get("ordinary_carry_sites") != [{"candidate_id": site.candidate_id,
                    "workload_id": site.workload_id, "workload_sha256": site.workload_sha256} for site in sites]
                or facts.get("recorded_image_deep_reopened") is not True):
            raise ValueError("ordinary carry differs from its authenticated current full-site authority")
        return
    if (not sites or facts.get("mode") != "undefended"
            or facts.get("workload_sha256") != sites[0].workload_sha256
            or facts.get("recorded_image_deep_reopened") is not True):
        raise ValueError("ordinary-only readiness must deep-verify this enrolled full-site manifest")


def check_layout(spec, value) -> None:
    if not is_inputs(value):
        raise ValueError("ordinary-only qualification input type changed")
    stored = lanes.plan_payload(lanes._read(spec.plan_receipt))
    require_plan(stored)
    if (value.get("contract") != CONTRACT or value.get("mode") != "undefended"
            or value.get("padding_qualification_required") is not False
            or value.get("enrollment") != _reference(spec.cohort)
            or value.get("runtime") != {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
            or value.get("runtime_artifacts") != stored.get("runtime_artifacts")
            or value.get("control_sources") != _sources()
            or value.get("sites") != stored.get("sites")
            or value.get("capture_limits") != stored.get("capture_limits")
            or stored.get("qualification_spec_sha256") != lanes._sha(_read(spec.qualification_spec))):
        raise ValueError("ordinary-only input layout differs from its exact current plan")
