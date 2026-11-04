"""A successful current-image ordinary canary with full-group RO transport.

This type records the normal first deep operation, without historical retry
authority. It grants no Source equivalence, padding qualification or credit.
The original full canary acceptance body still verifies the captured evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from . import rapid_rolling_readiness as old
from . import rapid_ordinary_canary_retry as retry
from . import rapid_undefended_capture as ordinary
from .rapid_operation_facts import OperationFacts, current_context

TYPE = "qcsd-current-ordinary-successful-group-canary-v1"
KEYS = old.REFERENCE_KEYS | {"artifact_type", "reader_sources"}
FILES = ("rapid_ordinary_group_canary.py", "rapid_rolling_readiness.py",
         "rapid_undefended_capture.py", "rapid_ordinary_transport_control.py")


def _sources():
    context = current_context()
    result = {}
    for name in FILES:
        path = Path(__file__).parent / name
        result[name] = old._sha(old._read(path) if context is None else context.watch_file(path))
    return result


def reference(value):
    """Tag only the original public successful capture/deep reference."""
    if (not isinstance(value, Mapping) or set(value) != old.REFERENCE_KEYS
        or type(value.get("schema_version")) is not int or value["schema_version"] != 1):
        raise ValueError("ordinary group reference needs the exact original public operation fields")
    return {**value, "schema_version": 5, "artifact_type": TYPE, "reader_sources": _sources()}


def group_roots(plan, directory):
    renewal, contents = retry._open(plan["ordinary_renewal"])
    if old._json(contents).get("control_sources") != ordinary._sources():
        raise ValueError("current group canary cannot project a historical renewal Source")
    return retry.group_roots(plan, directory)


def transport_mounts(plan, directory):
    roots = group_roots(plan, directory)
    renewal, _ = retry._open(plan["ordinary_renewal"])
    mounts = ["--volume", f"{renewal}:{renewal}:ro"]
    for root in roots:
        mounts += ["--volume", f"{root}:{root}:ro"]
    return mounts


def _current_source(plan, directory, runtime):
    """Every current Source member is identical to the actual canary runtime."""
    context = current_context()
    inventory = old._json(old._read(directory / "source-inventory.json",
        plan["canonical_runtime"]["source_inventory_sha256"]))
    roots = [old._path(runtime[key], directory=True) for key in ("runtime_source_root", "module_root")]
    if str(roots[0]) != plan["clean_runtime_root"]:
        raise ValueError("ordinary group canary needs the same current runtime Source")
    for root in roots:
        context.watch_tree(root, ignore_git=True)
        if old._inventory(root) != inventory:
            raise ValueError("ordinary group canary cannot exempt changed Source membership or bytes")
    for name, digest in _sources().items():
        if old._read(roots[0] / "src/qcsd_lab" / name, digest) != old._read(Path(__file__).parent / name, digest):
            raise ValueError("ordinary group executing reader differs from the actual current runtime")


def validate(value, *, runtime, mode):
    context = current_context()
    if context is None:
        with OperationFacts().scope() as context:
            result = validate(value, runtime=runtime, mode=mode)
            context.check()
            return result
    if (not isinstance(value, Mapping) or set(value) != KEYS
        or type(value.get("schema_version")) is not int or value["schema_version"] != 5
        or value.get("artifact_type") != TYPE or mode != "undefended"
        or value.get("reader_sources") != _sources()
        or not isinstance(runtime, Mapping) or set(runtime) != old.RUNTIME_KEYS):
        raise ValueError("ordinary group canary changed its current typed Source, mode or runtime")
    context.bind_canary(value, runtime)
    plan_path, raw = retry._open(value["plan"])
    receipt_path, receipt_raw = retry._open(value["deep_receipt"])
    directory = plan_path.parent
    if plan_path.name != "plan.json" or receipt_path != directory / "undefended-deep-verification.json":
        raise ValueError("ordinary group canary changed its exact public namespace")
    plan, receipt = old._json(raw), old._json(receipt_raw)
    _current_source(plan, directory, runtime)
    group_roots(plan, directory)
    key = (TYPE, old._sha(old._encoded(value)), old._sha(old._encoded(runtime)))
    if context.has(key):
        return context.get(key)
    deep = old._operation(value["deep"], directory, "undefended-deep")
    expected = old._deep_command(plan, directory, old._sha(raw), mode, receipt.get("root"),
                                 deep["command"], ordinary_transport="current-group")
    if deep["command"] != expected:
        raise ValueError("ordinary group deep command changed its exact current program, image or RO transports")
    original = {name: value[name] for name in old.REFERENCE_KEYS}
    original["schema_version"] = 1
    facts = old._validate_canary(original, runtime=runtime, mode=mode,
                                _transport_recovery={**deep, "expected_command": expected})
    facts = {**facts, "authority_source": facts["source"], "source_equivalence_sha256": None,
        "source_equivalence_published_at": None, "ordinary_successful_group_canary": TYPE}
    context.check()
    return context.remember(key, facts)


def roots(value, *, runtime, mode):
    validate(value, runtime=runtime, mode=mode)
    plan_path, raw = retry._open(value["plan"])
    plan = old._json(raw)
    result = {plan_path.parent, Path(plan["clean_runtime_root"]), Path(plan["execution_root"]),
              *map(Path, group_roots(plan, plan_path.parent))}
    result.add(retry._open(plan["ordinary_renewal"])[0].parent)
    for operation in ("capture", "deep"):
        result.update(retry._open(ref)[0].parent for ref in value[operation].values())
    result.update(Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
    result.update(Path(runtime[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    command = old._json(retry._open(value["deep"]["started"])[1])["command"]
    for suffix in (":/recipe.py:ro", ":/helpers.py:ro"):
        mount, = [command[i + 1] for i, arg in enumerate(command)
                  if arg == "--volume" and command[i + 1].endswith(suffix)]
        result.add(old._path(mount.removesuffix(suffix)).parent)
    return sorted(result)
