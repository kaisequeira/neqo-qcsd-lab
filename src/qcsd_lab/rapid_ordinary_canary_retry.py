"""Reopen an original-image ordinary deep retry with explicit transport authority.

The measured runtime remains the original runtime. This reader is a separately
inventoried study overlay; it changes neither the capture nor the deep verifier.
"""
from __future__ import annotations

import math
import re
import ast
from collections.abc import Mapping
from pathlib import Path

from . import rapid_rolling_readiness as old
from .util import durable_create

TYPE = "qcsd-ordinary-original-image-canary-deep-transport-retry-v1"
KEYS = old.REFERENCE_KEYS | {"artifact_type", "failed_deep", "transport_declaration", "reader_sources"}
FILES = ("rapid_ordinary_canary_retry.py", "rapid_rolling_readiness.py", "rapid_ordinary_transport_control.py")
ADDED_FILES = {"src/qcsd_lab/rapid_ordinary_canary_retry.py", "tools/rapid_ordinary_canary_retry.py",
    "tests/test_rapid_ordinary_canary_retry.py", "docs/ORDINARY-CANARY-TRANSPORT-RETRY.md",
    "src/qcsd_lab/rapid_ordinary_transport_control.py", "tools/rapid_ordinary_transport_control.py",
    "tests/test_rapid_ordinary_transport_control.py", "docs/ORDINARY-FORMAL-TRANSPORT.md"}
CHANGED_UNITS = {"src/qcsd_lab/rapid_rolling_readiness.py": {
    "_deep_command", "_validate_canary", "validate_canary", "readiness_mount_roots"},
    "tools/_rapid_class_mode_flight/flight/operator.py": {"image_argv"},
    "src/qcsd_lab/rapid_rolling_capture.py": {"enrollment_roots"},
    "src/qcsd_lab/rapid_undefended_capture.py": {"validate_inputs"}}


def _open(ref):
    from .rapid_operation_facts import current_context
    if not isinstance(ref, Mapping) or set(ref) != {"path", "sha256"}:
        raise ValueError("ordinary retry requires exact two-field file references")
    context = current_context()
    if context is not None:
        context.watch_file(Path(ref["path"]))
    return old._reference(ref)


def _sources():
    return {name: old._sha(old._read(Path(__file__).parent / name)) for name in FILES}


def _residual(raw, units):
    tree = ast.parse(raw)
    found = [node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in units]
    if set(found) != units or len(found) != len(units):
        raise ValueError("ordinary overlay lacks its exact named transport controls")
    tree.body = [node for node in tree.body if not isinstance(node, ast.FunctionDef) or node.name not in units]
    return ast.dump(tree, include_attributes=False)


def validate_overlay(runtime, plan, directory):
    """Authenticate every old Source byte except the named reader controls."""
    from .rapid_operation_facts import current_context
    context = current_context()
    key = (TYPE, "overlay", runtime["module_root"], plan["canonical_runtime_sha256"])
    if context is not None and context.has(key):
        return
    root = old._path(runtime["module_root"], directory=True)
    if root != Path(__file__).resolve().parents[2]:
        raise ValueError("ordinary overlay runtime must name the actual executing reader Source")
    if context is not None:
        context.watch_tree(root, ignore_git=True)
    baseline = old._json(old._read(directory / "source-inventory.json", plan["canonical_runtime"]["source_inventory_sha256"]))
    inventory = old._inventory(root)
    if set(inventory) != set(baseline) | ADDED_FILES or ADDED_FILES & set(baseline):
        raise ValueError("ordinary overlay changed the exact original Source membership")
    for relative, record in baseline.items():
        if relative not in CHANGED_UNITS:
            if inventory[relative] != record:
                raise ValueError("ordinary overlay changed protected capture, acceptance, Native or default Source")
        else:
            if inventory[relative]["executable"] is not record["executable"]:
                raise ValueError("ordinary overlay changed original control file mode")
            if _residual(old._read(root / relative), CHANGED_UNITS[relative]) != _residual(
                    old._read(Path(plan["clean_runtime_root"]) / relative, record["sha256"]), CHANGED_UNITS[relative]):
                raise ValueError("ordinary overlay changed residual original control units")
    from .rapid_ordinary_transport_control import check_projection
    check_projection(plan["clean_runtime_root"], root)
    if context is not None:
        context.remember(key, True)


def _operation(ref, parent, *, returncode):
    if not isinstance(ref, Mapping) or set(ref) != old.OPERATION_KEYS:
        raise ValueError("ordinary retry operation schema differs")
    contents = {}
    for key, suffix in (("started", "-started.json"), ("completed", "-completed.json"),
                        ("stdout", ".stdout.log"), ("stderr", ".stderr.log")):
        path, contents[key] = _open(ref[key])
        if path != parent / ("undefended-deep" + suffix):
            raise ValueError("ordinary retry operation has another namespace or record")
    start, end = old._json(contents["started"]), old._json(contents["completed"])
    elapsed, command = end.get("elapsed_seconds"), start.get("command")
    if (type(end.get("returncode")) is not int or end["returncode"] != returncode
        or end.get("invocation_error") is not None
        or end.get("stdout_sha256") != old._sha(contents["stdout"])
        or end.get("stderr_sha256") != old._sha(contents["stderr"])
        or type(elapsed) not in {int, float} or not math.isfinite(elapsed) or elapsed < 0
        or not isinstance(command, list) or not command
        or any(not isinstance(item, str) or not item for item in command)
        or old._timestamp(end.get("completed_at")) < old._timestamp(start.get("started_at"))):
        raise ValueError("ordinary retry changed its actual status, raw logs or chronology")
    return {"command": command, "start": old._timestamp(start["started_at"]),
            "end": old._timestamp(end["completed_at"]), "elapsed_seconds": elapsed}


def group_roots(plan, directory):
    """Authenticate the declared full group through the unchanged renewal API."""
    from . import rapid_undefended_capture as ordinary
    from .static_evidence_transport import manifest_roots
    from .rapid_operation_facts import current_context
    context = current_context()
    if ("ordinary_renewal" not in plan or plan.get("reuse") is not None
        or len(plan.get("campaigns", [])) != 1 or plan["campaigns"][0].get("mode") != "undefended"
        or "qualification_delivery_compatibility" in plan or "static_capture_amendment" in plan):
        raise ValueError("deep transport recovery authorizes only this unamended ordinary group")
    # Observe the exact declared immutable transports before the unchanged
    # renewal proof consumes their bytes or membership. The following proof
    # independently recomputes and compares every root; no caller mount waiver.
    if context is not None:
        for root in plan.get("group_preparation_roots", []):
            context.watch_tree(old._path(root, directory=True))
    renewal, _ = _open(plan["ordinary_renewal"])
    enrollment, _ = _open(plan["enrollment"])
    if old._json(old._read(renewal)).get("control_sources") != ordinary._sources():
        from .rapid_ordinary_transport_control import original_group
        bindings, manifests = original_group(plan, directory)
    else:
        _, _, bindings, manifests, _, _ = ordinary.flight_inputs(renewal, enrollment, Path(plan["study_root"]))
    expected = sorted({str(root) for manifest in manifests for root in manifest_roots(manifest)})
    declared = plan.get("group_preparation_roots")
    if (declared != expected or not bindings or len(bindings) != len(plan.get("selected_classes", []))
        or [(r["candidate_id"], r["class_index"], r["workload_id"]) for r in bindings]
        != [(r["candidate_id"], r["class_index"], r["workload_id"]) for r in plan["selected_classes"]]):
        raise ValueError("ordinary retry changed its authenticated full group or class order")
    for root in declared:
        old._path(root, directory=True)
        if any(char in root for char in ("\n", "\r", "\0", ":")):
            raise ValueError("ordinary retry group mount is not canonical")
    return declared


def transport_mounts(plan, directory, original_mounts, *, complete):
    roots = group_roots(plan, directory)
    renewal, _ = _open(plan["ordinary_renewal"])
    text = str(renewal)
    if any(char in text for char in ("\n", "\r", "\0", ":")):
        raise ValueError("ordinary retry renewal mount is not canonical")
    mounts = ["--volume", f"{text}:{text}:ro", *original_mounts]
    if complete:
        present = {value.split(":", 1)[0] for value in mounts[1::2]}
        for root in roots:
            if root not in present:
                mounts += ["--volume", f"{root}:{root}:ro"]
    return mounts


def _transport(reference, plan, directory, plan_sha, mode, declared_root):
    failed = _operation(reference["failed_deep"], directory / "logs", returncode=1)
    retry_start, _ = _open(reference["deep"]["started"])
    operation_root = retry_start.parent
    if operation_root.name != "operations" or operation_root.parent == directory:
        raise ValueError("ordinary retry requires a fresh separate operation namespace")
    deep = _operation(reference["deep"], operation_root, returncode=0)
    expected_failed = old._deep_command(plan, directory, plan_sha, mode, declared_root,
                                        failed["command"], ordinary_transport="first")
    expected_deep = old._deep_command(plan, directory, plan_sha, mode, declared_root,
                                      deep["command"], ordinary_transport="group")
    actor_index = expected_deep.index("--name") + 1
    actor = deep["command"][deep["command"].index("--name") + 1]
    if re.fullmatch(re.escape(expected_deep[actor_index]) + r"-transport-recovery[0-9]{3}", actor) is None:
        raise ValueError("ordinary retry actor is not a fresh typed verifier actor")
    expected_deep[actor_index] = actor
    if failed["command"] != expected_failed or deep["command"] != expected_deep or deep["start"] < failed["end"]:
        raise ValueError("ordinary retry altered original verifier, result, image, mounts or order")
    declaration_path, raw = _open(reference["transport_declaration"])
    declaration = old._json(raw)
    original_mounts = {failed["command"][i + 1] for i, arg in enumerate(failed["command"]) if arg == "--volume"}
    additions = [f"{root}:{root}:ro" for root in plan["group_preparation_roots"] if f"{root}:{root}:ro" not in original_mounts]
    expected = {"original_plan": reference["plan"], "original_failed_deep": reference["failed_deep"]["completed"],
        "added_declared_readonly_group_roots": additions,
        "original_verifier_program_and_image_unchanged": True, "capture_reexecuted": False,
        "readiness_authority_claimed": False, "formal_credit": 0}
    if declaration_path != operation_root.parent / "transport-declaration.json" or old._encoded(declaration) != old._encoded(expected):
        raise ValueError("ordinary retry transport declaration differs from its exact raw operation")
    return {**deep, "expected_command": expected_deep}


def validate(reference, *, runtime, mode):
    from .rapid_operation_facts import OperationFacts, current_context
    context = current_context()
    if context is None:
        with OperationFacts().scope() as context:
            result = validate(reference, runtime=runtime, mode=mode)
            context.check()
            return result
    for name in FILES:
        context.watch_file(Path(__file__).parent / name)
    if (not isinstance(reference, Mapping) or set(reference) != KEYS
        or type(reference.get("schema_version")) is not int or reference["schema_version"] != 4
        or reference.get("artifact_type") != TYPE or mode != "undefended"
        or reference.get("reader_sources") != _sources()
        or not isinstance(runtime, Mapping) or set(runtime) != old.RUNTIME_KEYS):
        raise ValueError("ordinary retry changed its explicit type, mode, reader Source or runtime")
    for name, digest in reference["reader_sources"].items():
        path = Path(__file__).parent / name
        context.watch_file(path)
        if old._read(Path(runtime["module_root"]) / "src/qcsd_lab" / name, digest) != old._read(path, digest):
            raise ValueError("ordinary retry must use its explicitly bound study reader overlay")
    context.bind_canary(reference, runtime)
    plan_path, plan_raw = _open(reference["plan"])
    receipt_path, receipt_raw = _open(reference["deep_receipt"])
    directory = plan_path.parent
    if plan_path.name != "plan.json" or receipt_path != directory / "undefended-deep-verification.json":
        raise ValueError("ordinary retry changed the original plan or result receipt namespace")
    plan, receipt = old._json(plan_raw), old._json(receipt_raw)
    validate_overlay(runtime, plan, directory)
    key = (TYPE, old._sha(old._encoded(reference)), old._sha(old._encoded(runtime)))
    if context.has(key):
        return context.get(key)
    deep = _transport(reference, plan, directory, old._sha(plan_raw), mode, receipt.get("root"))
    original = {key: reference[key] for key in old.REFERENCE_KEYS}
    original["schema_version"] = 1
    facts = old._validate_canary(original, runtime=runtime, mode=mode, _transport_recovery=deep)
    facts = {**facts, "authority_source": facts["source"], "source_equivalence_sha256": None,
        "source_equivalence_published_at": None, "ordinary_deep_transport_retry": TYPE,
        "ordinary_retry_reader_sources": reference["reader_sources"], "capture_reexecuted": False}
    context.check()
    return context.remember(key, facts)


def roots(reference, *, runtime, mode):
    validate(reference, runtime=runtime, mode=mode)
    plan_path, raw = _open(reference["plan"])
    plan = old._json(raw)
    result = {plan_path.parent, Path(plan["clean_runtime_root"]), Path(plan["execution_root"]),
        *map(Path, group_roots(plan, plan_path.parent))}
    result.add(_open(plan["ordinary_renewal"])[0].parent)
    for operation in ("deep", "failed_deep", "capture"):
        result.update(_open(ref)[0].parent for ref in reference[operation].values())
    result.add(_open(reference["transport_declaration"])[0].parent)
    result.update(Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
    result.update(Path(runtime[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    for key in ("recipe_sha256", "helper_sha256"):
        _, raw = _open(reference["deep"]["started"])
        command = old._json(raw)["command"]
        suffix = ":/recipe.py:ro" if key == "recipe_sha256" else ":/helpers.py:ro"
        mount, = [command[i + 1] for i, arg in enumerate(command) if arg == "--volume" and command[i + 1].endswith(suffix)]
        result.add(old._path(mount.removesuffix(suffix)).parent)
    return sorted(result)


def publish(reference, runtime, output):
    from .rapid_operation_facts import OperationFacts, current_context
    context = current_context()
    if context is None:
        with OperationFacts().scope() as context:
            result = publish(reference, runtime, output)
            context.check()
            return result
    value = {**reference, "schema_version": 4, "artifact_type": TYPE, "reader_sources": _sources()}
    validate(value, runtime=runtime, mode="undefended")
    context.check()
    durable_create(output, old._encoded({"undefended": value}))
    context.watch_file(output)
    context.check()
    return value
