"""Current complete selected GET inputs for one prospectively fixed defense.

This receipt renews validation of retained GET bytes. It does not qualify a
defense, waive its canary, alter admission, or carry historical trace credit.
"""
from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Mapping

from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_site_admission as receipts
from . import rapid_undefended_capture as ordinary
from . import rapid_selected_capture_input as selected
from . import rapid_per_class_selected_input as facade
from . import rapid_selected_budget_input as selected_budget
from . import rapid_per_class_selected_enrollment as per_class
from . import selected_capture_amendment as amendment
from . import tamaraw_fixed_configuration as tamaraw

FIELD = "selected_input_renewal"
TYPE = "qcsd-current-selected-complete-get-defended-input-renewal-v1"
CONTRACT = "same-complete-selected-get-current-fixed-defense-runtime-v1"
SOURCE_FILES = {name: "src/qcsd_lab/" + name + ".py" for name in (
    "rapid_selected_input_renewal", "rapid_selected_capture_input",
    "rapid_undefended_capture", "selected_capture_amendment",
    "rapid_rolling_capture", "tamaraw_fixed_configuration", "rapid_per_class_selected_input",
    "rapid_selected_budget_input", "per_class_selected_capture_amendment")}
SOURCE_FILES.update({module.__name__.rsplit(".", 1)[-1]:
    "src/qcsd_lab/" + module.__name__.rsplit(".", 1)[-1] + ".py"
    for module in selected_budget._modules()})


def _condition(mode, fixed):
    if type(mode) is not str or mode not in {"tamaraw", "cs-buflo"}:
        raise ValueError("selected renewal supports only TAM8192 or CS-BuFLO")
    fixed = tamaraw.validate_policy(fixed)
    if (mode == "tamaraw" and fixed != tamaraw.POLICY
            or mode == "cs-buflo" and fixed is not None):
        raise ValueError("selected renewal changed its prospective fixed defense")
    return fixed


def _sources(runtime):
    result = {name: lanes._sha(ordinary._read(Path(import_module("qcsd_lab." + name).__file__)))
              for name in SOURCE_FILES}
    for key in ("runtime_source_root", "module_root", "execution_root"):
        for name, relative in SOURCE_FILES.items():
            if lanes._sha(ordinary._read(Path(runtime[key]) / relative)) != result[name]:
                raise ValueError("selected renewal differs from actual current Source")
    return result


def _base(enrollment, runtime, mode, fixed):
    fixed = _condition(mode, fixed)
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    from .rapid_additive_static_enrollment import CONTRACT as plain_contract
    if policy["contract"] not in {plain_contract, per_class.CONTRACT}:
        raise ValueError("defended renewal requires immutable selected enrollment")
    runtime = rolling._runtime({key: runtime[key] for key in rolling.RUNTIME_FIELDS})
    if runtime["data_root"] != policy["runtime"]["data_root"]:
        raise ValueError("selected renewal changed the enrolled data root")
    return batch, classes, policy, runtime, fixed


def _artifacts(runtime):
    return {key: ordinary._reference(Path(runtime[key])) for key in (
        "source_manifest", "client_binary", "base_launcher", "host_launcher")}


def publish(enrollment: Path, runtime: Mapping[str, str], output: Path, *, mode: str,
            tamaraw_configuration_policy=None) -> Path:
    from .rapid_operation_facts import OperationFacts, current_context
    from .util import fsync_directory
    if current_context() is None:
        with OperationFacts().scope() as context:
            result = publish(enrollment, runtime, output, mode=mode,
                             tamaraw_configuration_policy=tamaraw_configuration_policy)
            context.check()
            return result
    batch, classes, policy, runtime, fixed = _base(enrollment, runtime, mode, tamaraw_configuration_policy)
    adapter = amendment
    if policy["contract"] == per_class.CONTRACT:
        from . import per_class_selected_capture_amendment as adapter
    output = output.absolute()
    inputs = output.with_name(output.stem + "-inputs")
    lanes._regular_directory(output.parent)
    if (not output.is_relative_to(Path(runtime["data_root"]))
            or any(path.exists() or path.is_symlink() for path in (output, inputs))):
        raise ValueError("selected renewal requires fresh outputs inside its runtime data root")
    rows = classes[-len(batch["selected_candidate_ids"]):]
    originals = [(row, adapter._original(row)) for row in rows]
    sources = _sources(runtime)
    if any((Path(runtime["workload_root"]) / (row["workload_id"] + ".json")).exists()
           for row in rows):
        raise ValueError("selected renewal must preserve every attempted capture manifest")
    inputs.mkdir(mode=0o700)
    fsync_directory(inputs)
    fsync_directory(inputs.parent)
    renewals = {}
    for row, (original, previous) in originals:
        validator = facade.module_for_preparation(original["preparation"]) if policy["contract"] == per_class.CONTRACT else selected
        receipt = inputs / (row["workload_id"] + "-input.json")
        validator.publish_input(receipt, audit=facade.reopen(previous["selection_audit"]), candidate_id=row["candidate_id"])
        manifest = inputs / (row["workload_id"] + ".json")
        validator.prepare_input(receipt, manifest)
        renewals[row["candidate_id"]] = {"input": facade.reference(receipt), "manifest": facade.reference(manifest)}
    renewed = ordinary._renew_rows(enrollment, batch, classes, policy, renewals)
    for row in renewed:
        target = Path(runtime["workload_root"]) / (row["workload_id"] + ".json")
        receipts.durable_create(target, ordinary._read(facade.reopen(row["current_manifest"])))
    value = {"schema_version": 1, "artifact_type": TYPE, "contract": CONTRACT,
        "mode": mode, "tamaraw_configuration_policy": fixed,
        "enrollment": ordinary._reference(enrollment), "runtime": runtime,
        "runtime_artifacts": _artifacts(runtime), "control_sources": sources,
        "capture_limits": rolling._effective_capture_limits(batch, classes, policy),
        "renewals": renewals, "rows": renewed, "published_at": receipts._now(),
        "scientific_credit": False, "formal_accepted_trace_count": 0}
    current_context().check()
    receipts.durable_create(output, lanes._json(value))
    validate(output, enrollment=enrollment, runtime=runtime, mode=mode,
             tamaraw_configuration_policy=fixed)
    return output


def validate(path: Path, *, enrollment: Path, runtime, mode,
             tamaraw_configuration_policy=None):
    batch, classes, policy, runtime, fixed = _base(enrollment, runtime, mode, tamaraw_configuration_policy)
    value = lanes._load(ordinary._read(path))
    fields = {"schema_version", "artifact_type", "contract", "mode", "tamaraw_configuration_policy",
        "enrollment", "runtime", "runtime_artifacts", "control_sources", "capture_limits",
        "renewals", "rows", "published_at", "scientific_credit", "formal_accepted_trace_count"}
    rolling._keys(value, fields, "current defended selected renewal")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["artifact_type"] != TYPE or value["contract"] != CONTRACT
            or value["mode"] != mode or value["tamaraw_configuration_policy"] != fixed
            or value["enrollment"] != ordinary._reference(enrollment) or value["runtime"] != runtime
            or value["runtime_artifacts"] != _artifacts(runtime) or value["control_sources"] != _sources(runtime)
            or value["capture_limits"] != rolling._effective_capture_limits(batch, classes, policy)
            or value["rows"] != ordinary._renew_rows(enrollment, batch, classes, policy, value["renewals"])
            or value["scientific_credit"] is not False or type(value["formal_accepted_trace_count"]) is not int
            or value["formal_accepted_trace_count"] != 0
            or not path.absolute().is_relative_to(Path(runtime["data_root"]))
            or not receipts._utc(batch["declared_at"]) <= receipts._utc(value["published_at"]) <= receipts._utc(receipts._now())):
        raise ValueError("selected renewal changed its exact graph, mode, runtime, Source or zero-credit role")
    for row in value["rows"]:
        if any(not Path(row[key]["path"]).is_relative_to(Path(runtime["data_root"]))
               for key in ("current_input", "current_manifest")):
            raise ValueError("selected renewed inputs escaped their capture data root")
        target = Path(runtime["workload_root"]) / (row["workload_id"] + ".json")
        if ordinary._read(target) != ordinary._read(facade.reopen(row["current_manifest"])):
            raise ValueError("selected renewal changed its complete execution graph")
    return value, batch, classes, policy


def flight_inputs(path: Path, enrollment: Path, study: Path, *, runtime, mode,
                  tamaraw_configuration_policy=None):
    value, batch, classes, policy = validate(path, enrollment=enrollment, runtime=runtime,
        mode=mode, tamaraw_configuration_policy=tamaraw_configuration_policy)
    if rolling._open_ref(batch["policy"]).parent != study.absolute():
        raise ValueError("defended renewed flight changed its immutable study")
    adapter = amendment
    if policy["contract"] == per_class.CONTRACT:
        from . import per_class_selected_capture_amendment as adapter
    files, trees = adapter.metadata_inputs(enrollment, batch, classes, policy)
    from .static_evidence_transport import manifest_roots
    roots = set(trees) | {item.parent for item in files} | {path.absolute().parent}
    roots.update(Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
    roots.update(Path(runtime[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    bindings, manifests = [], []
    for row, renewed in zip(classes[-len(batch["selected_candidate_ids"]):], value["rows"]):
        manifest = lanes._load(ordinary._read(facade.reopen(renewed["current_manifest"])))
        roots.update(manifest_roots(manifest))
        bindings.append({"candidate_id": row["candidate_id"], "class_index": row["class_index"],
            "admission_root": row["admission_root"], "terminal": {key: row["terminal"][key] for key in ("path", "sha256")},
            "original_workload": {key: renewed["current_manifest"][key] for key in ("path", "sha256")},
            "workload_id": row["workload_id"], "selection_sha256": policy["admission_identity"]["profile_sha256"]})
        manifests.append(manifest)
    return batch, policy, bindings, manifests, sorted(str(root) for root in roots), {
        **value["capture_limits"], "max_attempts": 1}


def require_canary(reference, path, *, mode):
    plan = lanes._load(ordinary._read(rolling._open_ref(reference["plan"])))
    started = lanes._load(ordinary._read(rolling._open_ref(reference["capture"]["started"])))
    value = lanes._load(ordinary._read(path))
    if (plan.get(FIELD) != ordinary._reference(path) or [row["mode"] for row in plan["campaigns"]] != [mode]
            or receipts._utc(started["started_at"]) < receipts._utc(value["published_at"])):
        raise ValueError("defended renewal requires its own fresh mode canary")


def plan_roots(plan, directory):
    path = rolling._open_ref(plan[FIELD])
    mode, = [row["mode"] for row in plan["campaigns"]]
    runtime = rolling.load_runtime(Path(directory) / "runtime-spec.json")
    return [Path(root) for root in flight_inputs(path, rolling._open_ref(plan["enrollment"]),
        Path(plan["study_root"]), runtime=runtime, mode=mode,
        tamaraw_configuration_policy=plan.get("tamaraw_configuration_policy"))[4]]


def enrollment_roots(spec):
    payload = receipts._unpack(ordinary._read(spec.plan_receipt), lanes.PLAN_TYPE)
    path = rolling._open_ref(payload[FIELD])
    mode, = payload["readiness"]
    return [Path(root) for root in flight_inputs(path, spec.cohort,
        rolling._open_ref(rolling._verify_enrollment(spec.cohort)[0]["policy"]).parent,
        runtime={key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}, mode=mode,
        tamaraw_configuration_policy=payload.get("tamaraw_configuration_policy"))[4]]
