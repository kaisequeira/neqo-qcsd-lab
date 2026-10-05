"""Explicit control authority for an unchanged complete original-static TAM canary.

The original image, Source, witness and successful measurement stay original.
This artifact authenticates a new installed consumer of the same qualification.
It executes no qualification, capture or independent deep verification.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from . import rapid_rolling_readiness as ready
from . import qualification_delivery_compatibility as delivery
from . import qualification_control_authority as control
from .rapid_operation_facts import OperationFacts, current_context
from .util import durable_create

TYPE = "qcsd-original-static-tamaraw-canary-control-witness-bridge-v1"
CONTRACT = "unchanged-complete-delivery-measurement-new-installed-control-v1"
FIELD = "control_witness_bridge"
MODULE = "src/qcsd_lab/rapid_canary_control_bridge.py"
SELECTED_ENUM_LINE = b'          "${rapid_scheduling_kind}" == "qcsd-rapid-v6-current-selected-parallel-scheduling" ||\n'
SELECTED_ENUM_CONTEXT = (b'          "${rapid_scheduling_kind}" == "qcsd-rapid-v6-current-static-parallel-scheduling" ||\n'
    + SELECTED_ENUM_LINE + b'          "${rapid_scheduling_kind}" == "qcsd-rapid-v6-current-original-static-parallel-scheduling" ]]; then\n')
KEYS = {"schema_version", "artifact_type", "contract", "mode", "original_canary",
    "original_runtime", "current_runtime", "current_inventory", "current_witness",
    "published_at", "measurement_facts", "current_source", "qualification_binding",
    "dependency_groups", "shell_projection", "measurement_deep_completed_at", *ready.ZERO}


def _groups(root, inventory):
    groups, units = ready._groups(root, inventory)
    shell, _ = ready._shell_projection(ready._read(root / "qcsd-lab"))
    count = shell.count(SELECTED_ENUM_LINE)
    if count not in (0, 1):
        raise ValueError("control bridge has an ambiguous registered shell predicate")
    if count and shell.count(SELECTED_ENUM_CONTEXT) != 1:
        raise ValueError("control bridge selected predicate moved outside its exact registered dispatch")
    protected = shell.replace(SELECTED_ENUM_LINE, b"")
    groups["measurement"]["qcsd-lab:protected-measurement"]["sha256"] = ready._sha(protected)
    if "src/qcsd_lab/orchestrator.py" in groups["measurement"]:
        orchestrator = control.normalize_orchestrator_imports(ready._read(root / "src/qcsd_lab/orchestrator.py"))
        groups["measurement"]["src/qcsd_lab/orchestrator.py"]["sha256"] = ready._sha(orchestrator)
    return groups, {"historical_control_units": units, "selected_predicate_count": count,
                   "selected_predicate_sha256": ready._sha(SELECTED_ENUM_LINE)}


def _derive(*, original_canary, original_runtime, current_runtime, current_inventory, current_witness, mode):
    if mode != "tamaraw":
        raise ValueError("control witness bridge authorizes only original-static Tamaraw")
    if (set(original_canary) != ready.REFERENCE_KEYS or original_canary.get("schema_version") != 1
        or type(original_canary["schema_version"]) is not int):
        raise ValueError("control bridge needs the exact original measured canary reference")
    for runtime in (original_runtime, current_runtime):
        if (set(runtime) != ready.RUNTIME_KEYS or any(not isinstance(x, str) for x in runtime.values())
            or ready._IMAGE.fullmatch(runtime["collection_image_digest"]) is None):
            raise ValueError("control bridge has another exact runtime role")
    context = current_context()
    context.bind_canary(original_canary, original_runtime)
    original = context.validate_canary(original_canary, original_runtime, mode, ready.validate_canary)
    plan_path, plan_raw = ready._reference(original_canary["plan"])
    plan = ready._json(plan_raw)
    if "static_capture_amendment" in plan or "front_capture_amendment" in plan:
        raise ValueError("control bridge cannot reinterpret amended measurement authority")
    from .supplied_static_preparation import ROLE
    from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY, application_body_identity_policy
    if (application_body_identity_policy(original) != COMPLETE_APPLICATION_DELIVERY_POLICY
        or application_body_identity_policy(plan) != COMPLETE_APPLICATION_DELIVERY_POLICY):
        raise ValueError("control bridge needs an already measured complete-delivery policy")
    result = Path(original["result_root"])
    experiment = ready._json(ready._read(result / "experiment.json"))
    manifest = ready._json(ready._read(ready._child(result,
        experiment["configuration"]["workloads"][0]["manifest"]), plan["workload_sha256"]))
    if manifest.get("preparation", {}).get("data_role") != ROLE:
        raise ValueError("control bridge needs an unchanged original-static prepared graph")
    old_witness_ref = original.get(delivery.FIELD)
    if old_witness_ref is None:
        raise ValueError("control bridge needs the original measured qualification witness")
    old, _, _ = delivery.validate(old_witness_ref, body_policy=COMPLETE_APPLICATION_DELIVERY_POLICY)
    new, _, _ = control.validate(current_witness, body_policy=COMPLETE_APPLICATION_DELIVERY_POLICY)
    if new.get("artifact_type") != control.TYPE or new.get("original_witness") != old_witness_ref:
        raise ValueError("control bridge needs its explicitly typed current qualification authority")
    shared = {key: old[key] for key in ("producer", "qualification_group", "qualified_inputs", "workloads",
        "client_sha256", "producer_source", "producer_image", "producer_implementation_sha256", delivery.POLICY_FIELD)}
    if any(new[key] != value for key, value in shared.items()):
        raise ValueError("control bridge changed the original complete qualification group, inputs or semantics")
    launcher_copies = {}
    for label, witness, runtime in (("original", old, original_runtime), ("current", new, current_runtime)):
        witness_runtime = witness["consumer"]["runtime"]
        if any(witness_runtime[key] != runtime[key] for key in delivery.RUNTIME_KEYS - {"host_launcher"}):
            raise ValueError("control bridge changed either witness's real installed consumer")
        source_launcher, capture_launcher = Path(witness_runtime["host_launcher"]), Path(runtime["host_launcher"])
        source_raw, capture_raw = context.watch_file(source_launcher), context.watch_file(capture_launcher)
        source_mode, capture_mode = source_launcher.stat().st_mode & 0o777, capture_launcher.stat().st_mode & 0o777
        if source_raw != capture_raw or source_mode != capture_mode:
            raise ValueError("control bridge changed the explicit qualification/capture launcher copy bytes or mode")
        launcher_copies[label] = {"witness_launcher": {"path": str(source_launcher), "sha256": ready._sha(source_raw), "mode": source_mode},
            "capture_launcher": {"path": str(capture_launcher), "sha256": ready._sha(capture_raw), "mode": capture_mode}}
    old_root = ready._path(original_runtime["runtime_source_root"], directory=True)
    new_root = ready._path(current_runtime["runtime_source_root"], directory=True)
    if old_root != ready._path(plan["clean_runtime_root"], directory=True):
        raise ValueError("control bridge original Source differs from its measured canary")
    old_inventory_ref = {"path": str(plan_path.parent / "source-inventory.json"),
                         "sha256": plan["canonical_runtime"]["source_inventory_sha256"]}
    old_inventory = ready._bound_inventory(old_inventory_ref, old_root)
    context.watch_file(ready._reference(current_inventory)[0])
    new_inventory = ready._bound_inventory(current_inventory, new_root)
    for name in (MODULE, "src/qcsd_lab/rapid_rolling_readiness.py", "src/qcsd_lab/rapid_rolling_capture.py"):
        own = Path(__file__).parents[2] / name
        if ready._read(own) != ready._read(new_root / name):
            raise ValueError("control bridge executing inspector differs from current bound Source")
        context.watch_file(own)
    context.watch_tree(new_root, ignore_git=True)
    context.watch_tree(Path(current_runtime["module_root"]), ignore_git=True)
    for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
        context.watch_file(Path(current_runtime[name]))
    old_groups, old_shell = _groups(old_root, old_inventory)
    new_groups, new_shell = _groups(new_root, new_inventory)
    if old_groups != new_groups:
        raise ValueError("control bridge changed measurement, acceptance, qualification, Native or traffic dependencies")
    source = ready._clean_source(ready._json(ready._read(Path(current_runtime["source_manifest"]))))
    authority = {**source, "image_digest": current_runtime["collection_image_digest"]}
    if (new["consumer_source"] != source or new["consumer_image"] != current_runtime["collection_image_digest"]
        or ready._sha(ready._read(Path(current_runtime["client_binary"]))) != original["client_sha256"]
        or new["client_sha256"] != original["client_sha256"]
        or source["neqo_commit"] != original["source"]["neqo_commit"]):
        raise ValueError("control bridge changed actual installed client, Source or image")
    from .rapid_capture_traffic import files
    if {key: ready._sha(context.watch_file(Path(current_runtime["execution_root"]) / relative))
        for key, (relative, _) in files().items()} != original["traffic_hashes"]:
        raise ValueError("control bridge changed execution traffic assets")
    return {"measurement_facts": original, "current_source": authority,
        "qualification_binding": {"original_witness": old_witness_ref, "current_witness": current_witness,
            "same_producer_group_inputs_semantics": shared, "explicit_launcher_copies": launcher_copies},
        "dependency_groups": {name: {"files": len(entries), "sha256": ready._sha(ready._encoded(entries))}
            for name, entries in old_groups.items()},
        "shell_projection": {"original": old_shell, "current": new_shell},
        "measurement_deep_completed_at": ready._operation(original_canary["deep"], plan_path.parent,
            mode + "-deep")["end"].isoformat()}


def declare(output, **inputs):
    context = OperationFacts()
    with context.scope():
        facts = _derive(**inputs)
        old = delivery.validate(facts["qualification_binding"]["original_witness"], body_policy=delivery.POLICY)[0]
        new = control.validate(inputs["current_witness"], body_policy=delivery.POLICY)[0]
        published = datetime.now(UTC).isoformat()
        if (any(ready._timestamp(x["published_at"]) >= ready._timestamp(published) for x in (old, new))
            or ready._timestamp(facts["measurement_deep_completed_at"]) >= ready._timestamp(published)):
            raise ValueError("control bridge publication must follow both actual witnesses")
        value = {"schema_version": 1, "artifact_type": TYPE, "contract": CONTRACT,
                 **inputs, **facts, "published_at": published, **ready.ZERO}
        destination = Path(output).absolute()
        if any(destination.is_relative_to(Path(inputs[name][key])) for name in ("original_runtime", "current_runtime")
               for key in ("runtime_source_root", "module_root", "execution_root")):
            raise ValueError("control bridge needs a fresh external publication namespace")
        context.check()
        durable_create(destination, ready._encoded(value))
        return {**inputs["original_canary"], "schema_version": 3,
                FIELD: {"path": str(destination), "sha256": ready._sha(ready._read(destination))}}


def validate(reference, *, runtime, mode):
    if (set(reference) != ready.REFERENCE_KEYS | {FIELD}
        or type(reference.get("schema_version")) is not int or reference["schema_version"] != 3):
        raise ValueError("control bridge canary reference has another exact schema")
    path, raw = ready._reference(reference[FIELD])
    value = ready._json(raw)
    if (set(value) != KEYS or type(value.get("schema_version")) is not int or value["schema_version"] != 1
        or value["artifact_type"] != TYPE or value["contract"] != CONTRACT
        or value["current_runtime"] != runtime or value["mode"] != mode
        or any(type(value[key]) is not type(expected) or value[key] != expected for key, expected in ready.ZERO.items())):
        raise ValueError("control bridge has another exact contract or runtime authority")
    original_reference = {key: item for key, item in reference.items() if key != FIELD}
    original_reference["schema_version"] = 1
    if value["original_canary"] != original_reference or ready._timestamp(value["published_at"]) > datetime.now(UTC):
        raise ValueError("control bridge changed original measurement or publication chronology")
    context = current_context()
    if context is None:
        context = OperationFacts()
        with context.scope():
            result = validate(reference, runtime=runtime, mode=mode)
            context.check()
            return result
    context.watch_file(path)
    facts = _derive(**{key: value[key] for key in ("original_canary", "original_runtime", "current_runtime",
        "current_inventory", "current_witness", "mode")})
    if any(value[key] != fact for key, fact in facts.items()):
        raise ValueError("control bridge differs from freshly reopened measurement and consumer facts")
    if ready._timestamp(facts["measurement_deep_completed_at"]) >= ready._timestamp(value["published_at"]):
        raise ValueError("control bridge predates its actual measured deep completion")
    for witness in (facts["qualification_binding"]["original_witness"], value["current_witness"]):
        witness_value = control.validate(witness, body_policy=delivery.POLICY)[0]
        if ready._timestamp(witness_value["published_at"]) >= ready._timestamp(value["published_at"]):
            raise ValueError("control bridge predates its actual qualification witness")
    original = facts["measurement_facts"]
    return {**original, "authority_source": facts["current_source"],
            "control_authority_witness": value["current_witness"], FIELD: reference[FIELD],
            "control_bridge_published_at": value["published_at"]}


def roots(reference, *, runtime, mode):
    validate(reference, runtime=runtime, mode=mode)
    path, raw = ready._reference(reference[FIELD]); value = ready._json(raw)
    roots = set(ready.readiness_mount_roots(value["original_canary"], runtime=value["original_runtime"], mode=mode))
    roots.update(control.roots(value["current_witness"], body_policy=delivery.POLICY))
    roots.add(path.parent)
    roots.add(ready._reference(value["current_inventory"])[0].parent)
    for key in ("runtime_source_root", "module_root", "execution_root"):
        roots.add(ready._path(runtime[key], directory=True))
    for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
        roots.add(ready._path(runtime[key]).parent)
    return sorted(roots)
