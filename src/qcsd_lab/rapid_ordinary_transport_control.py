"""Explicit ordinary transport controls over an unchanged measured runtime.

Only mount selection and the input reader's named transport dispatch change.
Original graphs, raw GET validators, canary/deep programs and runtime labels
retain their original authority. Unmarked ordinary inputs keep their reader.
"""
from __future__ import annotations

import ast
import stat
from dataclasses import asdict
from pathlib import Path

from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_undefended_capture as ordinary
from . import rapid_ordinary_canary_retry as retry
from . import rapid_rolling_readiness as old
from .rapid_operation_facts import OperationFacts, current_context
from .util import durable_create

TYPE = "qcsd-current-ordinary-original-runtime-transport-control-v1"
FIELD = "ordinary_transport_control"
KEYS = {"schema_version", "artifact_type", "original_plan", "runtime", "source_inventory",
        "control_sources", "scientific_credit", "formal_accepted_trace_count"}
CONTROLS = ("rapid_undefended_capture.py", "rapid_capture_plan.py",
            "rapid_lane_evidence.py", "rapid_rolling_capture.py")


def _inventory(root):
    inventory = old._inventory(Path(root))
    return {name: {**item, "mode": stat.S_IMODE((Path(root) / name).stat().st_mode)}
            for name, item in inventory.items()}


def _open(reference):
    return retry._open(reference)


def _read(path):
    context = current_context()
    return old._read(path) if context is None else context.watch_file(Path(path))


def _reference(path):
    path = Path(path).absolute()
    return {"path": str(path), "sha256": old._sha(_read(path))}


def _owned(function):
    def call(*args, **kwargs):
        if current_context() is not None:
            return function(*args, **kwargs)
        with OperationFacts().scope() as context:
            result = function(*args, **kwargs)
            context.check()
            return result
    return call


def _boundary_projection(original, current, name, inserted):
    left, right = ast.parse(original), ast.parse(current)
    units = [node for node in right.body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(units) != 1:
        raise ValueError("ordinary transport named control is missing or duplicated")
    unit = units[0]
    expected = ast.parse(inserted).body
    start = 1
    if ast.dump(ast.Module(body=unit.body[start:start + len(expected)], type_ignores=[]), include_attributes=False) != ast.dump(
            ast.Module(body=expected, type_ignores=[]), include_attributes=False):
        raise ValueError("ordinary transport control dispatch differs from its closed implementation")
    del unit.body[start:start + len(expected)]
    if ast.dump(left, include_attributes=False) != ast.dump(right, include_attributes=False):
        raise ValueError("ordinary transport changes residual controls or acceptance")


def check_projection(runtime_root, module_root):
    original, current = Path(runtime_root) / "src/qcsd_lab", Path(module_root) / "src/qcsd_lab"
    _boundary_projection(_read(original / "rapid_rolling_capture.py"), _image_projection(_read(current / "rapid_rolling_capture.py")),
        "enrollment_roots", '''from . import rapid_undefended_capture as ordinary
stored = lanes.plan_payload(lanes._read(spec.plan_receipt))
if ordinary.FIELD in stored:
    from . import rapid_ordinary_transport_control as transport
    return transport.enrollment_roots(spec, stored)
''')
    _boundary_projection(_read(original / "rapid_undefended_capture.py"), _read(current / "rapid_undefended_capture.py"),
        "validate_inputs", '''if "ordinary_transport_control" in value:
    from .rapid_ordinary_transport_control import validate_inputs as validate_transport_inputs
    return validate_transport_inputs(path, enrollment=enrollment, runtime=runtime,
                                     require_current=require_current)
''')
    for name in ("rapid_capture_plan.py", "rapid_lane_evidence.py"):
        if _read(original / name) != _read(current / name):
            raise ValueError("ordinary transport changes protected planning or actuation Source")


def _image_projection(raw):
    """Normalize only the exact typed installed-authority conditional."""
    tree = ast.parse(raw)
    units = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "image_plan_check"]
    if len(units) != 1:
        raise ValueError("ordinary image authority named unit is missing or duplicated")
    expected = ast.parse('''from .rapid_ordinary_transport_control import FIELD as transport_field, validate_image_authority
if transport_field not in lanes._load(lanes._read(spec.qualification_spec)):
    raise ValueError("rolling authority differs from the installed and frozen source")
validate_image_authority(spec, payload, runtime, own)
''').body
    predicate = ast.parse('if own != lanes._read(spec.runtime_source_root / relative) or own != lanes._read(spec.module_root / relative):\n    pass').body[0].test
    found = [node for node in units[0].body if isinstance(node, ast.If)
             and ast.dump(node.test, include_attributes=False) == ast.dump(predicate, include_attributes=False)]
    if (len(found) != 1 or found[0].orelse or ast.dump(ast.Module(body=found[0].body, type_ignores=[]), include_attributes=False)
        != ast.dump(ast.Module(body=expected, type_ignores=[]), include_attributes=False)):
        raise ValueError("ordinary image authority differs from its exact closed dispatch")
    found[0].body = ast.parse('raise ValueError("rolling authority differs from the installed and frozen source")').body
    return ast.unparse(tree).encode()


@_owned
def validate_image_authority(spec, payload, runtime, own):
    """Allow the closed transport reader while retaining the measured image."""
    inputs = lanes._load(_read(spec.qualification_spec))
    control = inputs.get(FIELD)
    declared_runtime = {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    validate_control(control, declared_runtime)
    sites = validate_inputs(spec.qualification_spec, enrollment=spec.cohort,
        runtime=declared_runtime, require_current=True)
    ordinary.require_plan(payload)
    ordinary.check_layout(spec, inputs)
    if (payload.get("runtime") != declared_runtime or payload.get("sites") != [asdict(site) for site in sites]
        or own != _read(Path(__file__).parent / "rapid_rolling_capture.py")
        or own != _read(spec.module_root / "src/qcsd_lab/rapid_rolling_capture.py")
        or runtime.get("collection_image_digest") != spec.collection_image_digest
        or runtime.get("runtime_source") != {**lanes._load(_read(spec.source_manifest)), "image_digest": spec.collection_image_digest}
        or any(runtime.get(label) != lanes._sha(_read(getattr(spec, key))) for key, label in (
            ("source_manifest", "source_manifest_sha256"), ("client_binary", "client_sha256"),
            ("base_launcher", "base_launcher_sha256"), ("host_launcher", "host_launcher_sha256")))):
        raise ValueError("ordinary installed authority changed its actual image, Source, client or full plan")
    current_context().check()


@_owned
def publish_control(plan_path, runtime, output):
    plan_path, runtime = Path(plan_path).absolute(), rolling._runtime(dict(runtime))
    plan = old._json(_read(plan_path))
    retry.validate_overlay(runtime, plan, plan_path.parent)
    check_projection(runtime["runtime_source_root"], runtime["module_root"])
    value = {"schema_version": 1, "artifact_type": TYPE, "original_plan": _reference(plan_path),
        "runtime": runtime, "source_inventory": _inventory(Path(runtime["module_root"])),
        "control_sources": ordinary._sources(), "scientific_credit": False,
        "formal_accepted_trace_count": 0}
    current_context().check()
    durable_create(output, old._encoded(value))
    current_context().watch_file(Path(output))
    return output


@_owned
def validate_control(reference, runtime):
    path, raw = _open(reference)
    value = old._json(raw)
    rolling._keys(value, KEYS, "ordinary transport control")
    runtime = rolling._runtime(dict(runtime))
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != TYPE or value["runtime"] != runtime
        or value["control_sources"] != ordinary._sources()
        or value["scientific_credit"] is not False
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or Path(runtime["module_root"]) != Path(__file__).resolve().parents[2]):
        raise ValueError("ordinary transport declaration changed current Source, runtime or zero-credit authority")
    context = current_context()
    context.watch_tree(Path(runtime["module_root"]), ignore_git=True)
    if _inventory(Path(runtime["module_root"])) != value["source_inventory"]:
        raise ValueError("ordinary transport Source membership, bytes or modes changed")
    plan_path, plan_raw = _open(value["original_plan"])
    plan = old._json(plan_raw)
    if (runtime["runtime_source_root"] != plan["clean_runtime_root"]
        or runtime["collection_image_digest"] != plan["canonical_runtime"]["collection_image_digest"]
        or old._json(_read(Path(runtime["source_manifest"])))["lab_commit"] != plan["expected_lab_commit"]):
        raise ValueError("ordinary transport relabels the original measured runtime")
    retry.validate_overlay(runtime, plan, plan_path.parent)
    check_projection(runtime["runtime_source_root"], runtime["module_root"])
    return value


@_owned
def publish_renewal(control, runtime, output):
    """Renew the four controls; retain the already current selected receipts."""
    declaration = validate_control(control, runtime)
    plan_path, raw = _open(declaration["original_plan"])
    plan = old._json(raw)
    original_group(plan, plan_path.parent)
    original_path, contents = _open(plan["ordinary_renewal"])
    value = old._json(contents)
    current = {**value, "control_sources": ordinary._sources()}
    context = current_context()
    context.check()
    durable_create(output, old._encoded(current))
    context.watch_file(Path(output))
    enrollment, _ = _open(plan["enrollment"])
    ordinary.validate_renewal(Path(output), enrollment)
    context.check()
    return output


@_owned
def publish_inputs(enrollment, runtime, renewal, control, output):
    validate_control(control, runtime)
    value, sites = ordinary._derive(enrollment, runtime, renewal=renewal)
    value[FIELD] = dict(control)
    current_context().check()
    durable_create(output, lanes._json(value))
    current_context().watch_file(Path(output))
    return output


@_owned
def validate_inputs(path, *, enrollment, runtime, require_current=False):
    value = lanes._load(_read(path))
    control = value.get(FIELD)
    validate_control(control, runtime)
    expected, sites = ordinary._derive(enrollment, runtime, renewal=value.get("renewal"))
    if (value != {**expected, FIELD: control} or type(value.get("schema_version")) is not int
        or type(value.get("formal_accepted_trace_count")) is not int):
        raise ValueError("ordinary transport input changes its exact full graphs, caps or enrollment")
    if require_current:
        check_projection(runtime["runtime_source_root"], runtime["module_root"])
        for name in CONTROLS:
            if _read(Path(__file__).parent / name) != _read(Path(runtime["module_root"]) / "src/qcsd_lab" / name):
                raise ValueError("ordinary transport executing and declared current controls differ")
    return sites


@_owned
def enrollment_roots(spec, payload):
    ordinary.require_plan(payload)
    ordinary.check_layout(spec, lanes._load(_read(spec.qualification_spec)))
    sites = ordinary.validate_inputs(spec.qualification_spec, enrollment=spec.cohort,
        runtime={key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}, require_current=True)
    if [asdict(site) for site in sites] != payload["sites"]:
        raise ValueError("ordinary transport changes current complete graph order")
    inputs = lanes._load(_read(spec.qualification_spec))
    if FIELD in inputs:
        validate_control(inputs[FIELD], inputs["runtime"])
    renewal = rolling._open_ref(inputs["renewal"])
    batch, policy, bindings, manifests, roots, _ = ordinary.flight_inputs(renewal, spec.cohort,
        rolling._open_ref(rolling._verify_enrollment(spec.cohort)[0]["policy"]).parent)
    if ([row["workload_id"] for row in bindings] != [site.workload_id for site in sites]
        or Path(batch["admission_root"]) != spec.acquisition_root):
        raise ValueError("ordinary transport changes immutable admission membership")
    result = set(map(Path, roots)) | {renewal.parent}
    if FIELD in inputs:
        result.add(_open(inputs[FIELD])[0].parent)
    result.update(Path(getattr(spec, key)) for key in ("runtime_source_root", "module_root", "execution_root"))
    result.update(Path(getattr(spec, key)).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    for site in sites:
        if lanes._sha(_read(spec.workload_root / (site.workload_id + ".json"))) != site.workload_sha256:
            raise ValueError("ordinary transport prunes or mutates a renewed workload")
    for root in result:
        lanes._regular_directory(root)
        if any(char in str(root) for char in ("\n", "\r", "\0", ":")):
            raise ValueError("ordinary transport requires regular same-absolute RO roots")
    return sorted(result)


@_owned
def original_group(plan, directory):
    """Validate the retained renewal under its exact original four controls."""
    root = Path(plan["clean_runtime_root"])
    retry.validate_overlay({"module_root": str(Path(__file__).resolve().parents[2])}, plan, directory)
    check_projection(root, Path(__file__).resolve().parents[2])
    inventory = old._json(_read(Path(directory) / "source-inventory.json"))
    sources = {"qcsd_lab." + Path(name).stem: old._sha(old._read(root / "src/qcsd_lab" / name,
        inventory["src/qcsd_lab/" + name]["sha256"])) for name in CONTROLS}
    path, raw = _open(plan["ordinary_renewal"])
    enrollment, _ = _open(plan["enrollment"])
    value = lanes._load(raw)
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    fields = {"schema_version", "artifact_type", "contract", "mode", "enrollment", "renewals",
        "rows", "control_sources", "scientific_credit", "formal_accepted_trace_count"}
    rolling._keys(value, fields, "original ordinary renewal")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != ordinary.RENEWAL_TYPE or value["contract"] != ordinary.CONTRACT
        or value["mode"] != "undefended" or value["enrollment"] != _reference(enrollment)
        or value["control_sources"] != sources or value["scientific_credit"] is not False
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["rows"] != ordinary._renew_rows(enrollment, batch, classes, policy, value["renewals"])
        or rolling._open_ref(batch["policy"]).parent != Path(plan["study_root"])):
        raise ValueError("original ordinary renewal lost its exact producer Source or graph proof")
    bindings, manifests = [], []
    chosen = classes[-len(batch["selected_candidate_ids"]):]
    for row, renewed in zip(chosen, value["rows"], strict=True):
        current, contents = _open({key: renewed["current_manifest"][key] for key in ("path", "sha256")})
        if "mode" in renewed["current_manifest"]:
            from .rapid_selected_capture_input import reopen
            reopen(renewed["current_manifest"])
        manifests.append(lanes._load(contents))
        bindings.append({"candidate_id": row["candidate_id"], "class_index": row["class_index"], "workload_id": row["workload_id"]})
    return bindings, manifests
