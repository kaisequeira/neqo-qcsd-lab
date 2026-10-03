"""Explicit qualification reuse for reviewed collection lifecycle repairs.

This prospective contract never changes the historical qualification validator.
It compares two actual installed-runtime proofs and their complete retained
source inventories.  A registered runtime epoch must reopen this bridge before
passing it to ``validate_current_implementation``; a bridge alone is neither a
launch authority nor a claim that its required capture canary passed.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from collections.abc import Mapping
from functools import lru_cache
from pathlib import PurePosixPath
from typing import Any

from . import chaff_qualification as qualification
from .util import SOURCE_METADATA_KEYS

CONTRACT = "response-only-v2-collector-lifecycle-v1"
BRIDGE_TYPE = "qcsd-rapid-collection-qualification-compatibility"
REVIEW_TYPE = "qcsd-rapid-collection-repair-review"
DOMAIN = "qcsd-rapid-collection-qualification-compatibility-v1"
ROOT_FUNCTIONS = (
    "qualify_response_chaff_v2",
    "_validate_response_only_sidecar_v2",
    "derive_response_only_chaff_manifest_v2",
)
# This immutable gate compares implementation/epoch authority rather than
# performing qualification requests.  Its opt-in compatibility hook can
# reopen collector proofs without making those collector functions part of
# the 120-response network primitive.  The entire containing source file and
# every compatibility/epoch validator remain protected byte-for-byte.
AUTHORITY_BOUNDARIES = frozenset({("chaff_qualification", "_validate_implementation_receipt")})
# These functions own copying, observer startup or host process lifecycle.
# Command construction, method settings, sample promotion and validation outside
# the two explicitly reviewed packet observer helpers remain protected.
# Expanding this list requires a new contract version.
COLLECTOR_FUNCTIONS = {
    "src/qcsd_lab/capture_session.py": frozenset({
        "_copy_create_once", "_wait_for_capture_start",
    }),
    "src/qcsd_lab/rapid_lane_evidence.py": frozenset({
        "capture_lock", "_supervise_command", "_actuate_host",
    }),
    "src/qcsd_lab/orchestrator.py": frozenset({"_checkpoint"}),
    # Packet observation/reconciliation helpers do not execute in sustained
    # response-only qualification.  Their entire surrounding validation module
    # remains protected; a repaired collector still needs ordinary deep proof.
    "src/qcsd_lab/fidelity.py": frozenset({"_read_direct_packets", "_reconcile_runner_packets"}),
}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME_KEYS = {
    "schema_version", "artifact_type", "collection_image_digest", "runtime_source",
    "source_manifest_sha256", "client_sha256", "base_launcher_sha256",
    "host_launcher_sha256", "qualification_implementation", "traffic_hashes",
    "formal_accepted_trace_count", "scientific_credit",
}
_BRIDGE_KEYS = {
    "schema_version", "artifact_type", "domain", "contract", "old_runtime_sha256",
    "new_runtime_sha256", "old_implementation_sha256", "new_implementation_sha256",
    "old_source_hashes", "new_source_hashes", "qualification_dependencies",
    "changed_sources", "native_source", "client_sha256", "traffic_hashes",
    "review_sha256", "formal_accepted_trace_count", "scientific_credit", "sha256",
}


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


@lru_cache(maxsize=256)
def _parse(raw: bytes, path: str) -> ast.Module:
    return ast.parse(raw, filename=path)


def _source_inventory(value: Mapping[str, bytes]) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("runtime compatibility requires complete retained source bytes")
    for path, raw in value.items():
        if (not isinstance(path, str) or not path or "\\" in path
            or PurePosixPath(path).is_absolute() or PurePosixPath(path).as_posix() != path
            or any(part in {".", ".."} for part in PurePosixPath(path).parts)
            or not isinstance(raw, bytes)):
            raise ValueError("runtime source inventory contains an invalid path or non-byte content")
    return {path: _sha(raw) for path, raw in sorted(value.items())}


def _runtime(value: Mapping[str, Any], sources: Mapping[str, str]) -> Mapping[str, Any]:
    if (not isinstance(value, Mapping) or set(value) != _RUNTIME_KEYS
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != "qcsd-rapid-v5-installed-runtime-preflight"
        or type(value["formal_accepted_trace_count"]) is not int
        or value["formal_accepted_trace_count"] != 0 or value["scientific_credit"] is not False):
        raise ValueError("runtime compatibility requires the actual installed-runtime proof contract")
    qualification._validate_source(value["runtime_source"], value["collection_image_digest"])
    implementation = value["qualification_implementation"]
    # Structural validation is followed by source, installed role and native
    # comparisons below.  No sidecar is accepted by disabling its current gate.
    qualification._validate_implementation_receipt(implementation, require_current=False)
    if implementation["schema_version"] != qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION:
        raise ValueError("runtime compatibility requires current response-policy implementation receipts")
    if (any(implementation["source"][key] != value["runtime_source"][key]
            for key in SOURCE_METADATA_KEYS - {"image_digest"})
        or any(not _digest(value[key]) for key in (
            "source_manifest_sha256", "client_sha256", "base_launcher_sha256", "host_launcher_sha256"))
        or implementation["neqo_qcsd_client"]["sha256"] != value["client_sha256"]
        or implementation["source_files"]["qcsd-lab"] != value["base_launcher_sha256"]
        or implementation["installed_entrypoint"]["sha256"] != value["base_launcher_sha256"]
        or any(sources.get(path) != digest for path, digest in implementation["source_files"].items())
        or not isinstance(value["traffic_hashes"], Mapping) or not value["traffic_hashes"]
        or any(not isinstance(path, str) or not _digest(digest)
               for path, digest in value["traffic_hashes"].items())):
        raise ValueError("installed runtime proof does not bind its retained source, client or traffic")
    return implementation


def _imports(nodes: Any) -> dict[str, tuple[str, str | None]]:
    """Resolve package imports conservatively; external dependencies are pinned."""
    result: dict[str, tuple[str, str | None]] = {}
    for node in nodes:
        if isinstance(node, ast.ImportFrom):
            if any(item.name == "*" for item in node.names):
                raise ValueError("qualification dependency surface contains a wildcard import")
            if node.level > 1:
                raise ValueError("qualification dependency surface escapes the package")
            if node.level == 1:
                if node.module and "." in node.module:
                    raise ValueError("qualification dependency surface has an unresolved nested package")
                for item in node.names:
                    result[item.asname or item.name] = (
                        (node.module or item.name).split(".")[0],
                        None if node.module is None else item.name,
                    )
            elif node.module == "qcsd_lab":
                for item in node.names:
                    result[item.asname or item.name] = (item.name, None)
            elif node.module and node.module.startswith("qcsd_lab."):
                for item in node.names:
                    result[item.asname or item.name] = (node.module.split(".")[1], item.name)
        elif isinstance(node, ast.Import):
            for item in node.names:
                if item.name == "qcsd_lab":
                    raise ValueError("qualification dependency surface has an ambiguous package import")
                if item.name.startswith("qcsd_lab."):
                    if item.asname is None:
                        raise ValueError("qualification dependency surface has an ambiguous package import")
                    result[item.asname] = (item.name.split(".")[1], None)
    return result


def _eager(tree: ast.Module) -> list[ast.AST]:
    # Function defaults and decorators execute eagerly; function bodies are
    # lazy.  Class bodies execute while importing, with the same method rule.
    nodes: list[ast.AST] = []

    def visit(node: ast.AST) -> None:
        nodes.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for part in [*node.decorator_list, *node.args.defaults,
                         *(item for item in node.args.kw_defaults if item is not None)]:
                visit(part)
            return
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return nodes


def qualification_dependencies(source_bytes: Mapping[str, bytes]) -> dict[str, Any]:
    """Bind eager imports and response-v2 reachable package functions.

    A whole imported module is protected, even if only one of its functions is
    used.  Local imports are followed only inside reachable functions; this
    keeps historical full/Walkie fitting branches outside this v2 contract.
    All other sources still require an explicitly permitted collector edit.
    """
    source_hashes = _source_inventory(source_bytes)
    trees: dict[str, ast.Module] = {}
    for path, raw in source_bytes.items():
        if path.startswith("src/qcsd_lab/") and path.count("/") == 2 and path.endswith(".py"):
            try:
                trees[PurePosixPath(path).stem] = _parse(raw, path)
            except (SyntaxError, ValueError) as error:
                raise ValueError("qualification dependency source is not valid Python") from error
    loaded: set[str] = set()
    reached: set[tuple[str, str]] = set()
    pending = [("chaff_qualification", name) for name in ROOT_FUNCTIONS]

    def load(name: str) -> None:
        if name in loaded:
            return
        if name not in trees:
            raise ValueError(f"qualification dependency source is missing: {name}")
        loaded.add(name)
        nodes = _eager(trees[name])
        for node in nodes:
            if (isinstance(node, ast.Call)
                and ((isinstance(node.func, ast.Name) and node.func.id in {"__import__", "exec", "eval"})
                     or (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"))):
                raise ValueError("qualification import has an unresolved dynamic dependency")
        aliases = _imports(nodes)
        for dependency, _symbol in aliases.values():
            load(dependency)
        # Module-level calls can reach functions during import.
        definitions = {node.name for node in trees[name].body
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        for node in nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in definitions:
                pending.append((name, node.id))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id in aliases and aliases[node.id][1] is not None:
                    pending.append(aliases[node.id])  # type: ignore[arg-type]
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                dependency = aliases.get(node.value.id)
                if dependency is not None and dependency[1] is None:
                    pending.append((dependency[0], node.attr))

    load("__init__")
    while pending:
        name, symbol = pending.pop()
        if (name, symbol) in reached:
            continue
        reached.add((name, symbol))
        load(name)
        definitions = {node.name: node for node in trees[name].body
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        target = definitions.get(symbol)
        if target is None:
            # Imported constants do not create a callable dependency, but their
            # containing module remains fully protected.
            continue
        if (name, symbol) in AUTHORITY_BOUNDARIES:
            continue
        nodes = list(ast.walk(target))
        aliases = _imports(_eager(trees[name]))
        aliases.update(_imports(nodes))
        for dependency, _symbol in _imports(nodes).values():
            load(dependency)
        for node in nodes:
            if (isinstance(node, ast.Call)
                and ((isinstance(node.func, ast.Name) and node.func.id in {"__import__", "exec", "eval"})
                     or (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"))):
                raise ValueError("qualification execution has an unresolved dynamic dependency")
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id in definitions:
                    pending.append((name, node.id))
                elif node.id in aliases and aliases[node.id][1] is not None:
                    pending.append(aliases[node.id])  # type: ignore[arg-type]
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                dependency = aliases.get(node.value.id)
                if dependency is not None and dependency[1] is None:
                    pending.append((dependency[0], node.attr))
    hashes = {}
    projections = {}
    for name in sorted(loaded):
        path = f"src/qcsd_lab/{name}.py"
        exclusions = sorted(symbol for symbol in COLLECTOR_FUNCTIONS.get(path, ())
                            if (name, symbol) not in reached)
        if exclusions:
            projected, _bodies, _signatures = _protected_body_projection(
                path, source_bytes[path], frozenset(exclusions))
            projections[path] = {"sha256": _sha(projected), "excluded_collector_functions": exclusions}
        else:
            hashes[path] = source_hashes[path]
    return {
        "contract": CONTRACT,
        "root_functions": list(ROOT_FUNCTIONS),
        "source_hashes": hashes,
        "source_projections": projections,
        "reachable_symbols": sorted(f"{module}.{symbol}" for module, symbol in reached),
        "authority_boundaries": sorted(f"{module}.{symbol}" for module, symbol in AUTHORITY_BOUNDARIES),
    }


def _protected_body_projection(
    path: str, raw: bytes, permitted: frozenset[str],
) -> tuple[bytes, dict[str, bytes], dict[str, str]]:
    tree = _parse(raw, path)
    lines = raw.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    bodies: dict[str, bytes] = {}
    signatures: dict[str, str] = {}
    spans = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in permitted:
            continue
        if node.name in bodies:
            raise ValueError("collector repair has duplicate function definitions")
        first, last = node.body[0], node.body[-1]
        start = offsets[first.lineno - 1] + first.col_offset
        end = offsets[last.end_lineno - 1] + last.end_col_offset
        bodies[node.name] = raw[start:end]
        signature = copy.deepcopy(node)
        signature.body = [ast.Pass()]
        signatures[node.name] = ast.dump(signature, include_attributes=False)
        spans.append((start, end, node.name))
    if set(bodies) != permitted:
        raise ValueError("collector source lacks a prospectively permitted function")
    projected = raw
    for start, end, name in sorted(spans, reverse=True):
        projected = projected[:start] + f"<collector-body:{name}>".encode() + projected[end:]
    return projected, bodies, signatures


def _collector_change(path: str, before: bytes, after: bytes) -> list[str]:
    permitted = COLLECTOR_FUNCTIONS.get(path)
    if permitted is None:
        raise ValueError(f"repair changes a protected source: {path}")

    try:
        old_projection, old_bodies, old_signatures = _protected_body_projection(path, before, permitted)
        new_projection, new_bodies, new_signatures = _protected_body_projection(path, after, permitted)
    except (SyntaxError, TypeError, ValueError) as error:
        raise ValueError("collector repair cannot derive its protected source projection") from error
    if old_projection != new_projection or old_signatures != new_signatures:
        raise ValueError("collector repair changes protected imports, signatures, constants or validation code")
    changed = sorted(name for name in old_bodies if old_bodies[name] != new_bodies[name])
    if not changed:
        raise ValueError("collector source change is outside a permitted function body")
    if path == "src/qcsd_lab/orchestrator.py":
        def protected_calls(raw: bytes) -> list[str]:
            tree = ast.parse(raw, filename=path)
            function = next(node for node in tree.body
                            if isinstance(node, ast.FunctionDef) and node.name == "_checkpoint")
            return [ast.dump(node, include_attributes=False) for node in ast.walk(function)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in {"_summary", "checkpoint_experiment"}]

        if protected_calls(before) != protected_calls(after):
            raise ValueError("collector checkpoint repair changes summary or checkpoint authority calls")
    return changed


def validate_compatibility(
    old_runtime_proof: Mapping[str, Any],
    new_runtime_proof: Mapping[str, Any],
    old_source_bytes: Mapping[str, bytes],
    new_source_bytes: Mapping[str, bytes],
    review: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive a bridge; its independent epoch/canary authority is external."""
    old_hashes = _source_inventory(old_source_bytes)
    new_hashes = _source_inventory(new_source_bytes)
    if set(old_hashes) != set(new_hashes):
        raise ValueError("collector runtime repair may not add or remove source files")
    old_impl = _runtime(old_runtime_proof, old_hashes)
    new_impl = _runtime(new_runtime_proof, new_hashes)
    native_keys = ("neqo_commit", "neqo_pinned_commit", "neqo_dirty", "neqo_patch_sha256")
    if (any(old_runtime_proof["runtime_source"][key] != new_runtime_proof["runtime_source"][key]
            for key in native_keys)
        or old_runtime_proof["client_sha256"] != new_runtime_proof["client_sha256"]
        or old_runtime_proof["base_launcher_sha256"] != new_runtime_proof["base_launcher_sha256"]
        or old_runtime_proof["host_launcher_sha256"] != new_runtime_proof["host_launcher_sha256"]
        or old_runtime_proof["traffic_hashes"] != new_runtime_proof["traffic_hashes"]):
        raise ValueError("collector repair changes Native, client, launcher or fixed traffic identity")
    old_dependencies = qualification_dependencies(old_source_bytes)
    new_dependencies = qualification_dependencies(new_source_bytes)
    if old_dependencies != new_dependencies:
        raise ValueError("collector repair changes the response-only qualification dependency surface")
    changes = {}
    for path in sorted(old_hashes):
        if old_hashes[path] != new_hashes[path]:
            changes[path] = {
                "before_sha256": old_hashes[path], "after_sha256": new_hashes[path],
                "functions": _collector_change(path, old_source_bytes[path], new_source_bytes[path]),
            }
    if (not isinstance(review, Mapping) or set(review) != {
        "schema_version", "artifact_type", "repair_scope", "reason", "changes"}
        or type(review["schema_version"]) is not int or review["schema_version"] != 1
        or review["artifact_type"] != REVIEW_TYPE or review["repair_scope"] != "collector-lifecycle-only"
        or not isinstance(review["reason"], str) or not review["reason"].strip()
        or _json(review["changes"]) != _json(changes)):
        raise ValueError("collector repair review does not name its exact source hashes and changed functions")
    value = {
        "schema_version": 1, "artifact_type": BRIDGE_TYPE, "domain": DOMAIN, "contract": CONTRACT,
        "old_runtime_sha256": _sha(_json(old_runtime_proof)),
        "new_runtime_sha256": _sha(_json(new_runtime_proof)),
        "old_implementation_sha256": old_impl["sha256"],
        "new_implementation_sha256": new_impl["sha256"],
        "old_source_hashes": old_hashes, "new_source_hashes": new_hashes,
        "qualification_dependencies": old_dependencies, "changed_sources": changes,
        "native_source": {key: old_runtime_proof["runtime_source"][key] for key in native_keys},
        "client_sha256": old_runtime_proof["client_sha256"],
        "traffic_hashes": dict(old_runtime_proof["traffic_hashes"]),
        "review_sha256": _sha(_json(review)), "formal_accepted_trace_count": 0,
        "scientific_credit": False,
    }
    value["sha256"] = _sha(DOMAIN.encode() + b"\0" + _json(value))
    validate_current_implementation(old_impl, new_impl, value)
    return value


def validate_current_implementation(
    old_impl_receipt: Mapping[str, Any],
    current_impl_receipt: Mapping[str, Any],
    bridge: Mapping[str, Any],
) -> None:
    """Compare actual installed roles against an already reopened epoch bridge.

    The caller must derive/reopen the bridge from retained source bytes and the
    registered runtime epoch before using it.  Both original and new receipts
    remain intact; broad historical ``require_current=True`` behavior is not
    changed.  Installed paths and every protected role are compared explicitly.
    """
    if (not isinstance(bridge, Mapping) or set(bridge) != _BRIDGE_KEYS
        or type(bridge["schema_version"]) is not int or bridge["schema_version"] != 1
        or bridge["artifact_type"] != BRIDGE_TYPE or bridge["domain"] != DOMAIN
        or bridge["contract"] != CONTRACT or bridge["formal_accepted_trace_count"] != 0
        or type(bridge["formal_accepted_trace_count"]) is not int or bridge["scientific_credit"] is not False
        or bridge["sha256"] != _sha(DOMAIN.encode() + b"\0" + _json({
            key: value for key, value in bridge.items() if key != "sha256"}))):
        raise ValueError("qualification compatibility bridge is malformed or changed")
    for receipt in (old_impl_receipt, current_impl_receipt):
        qualification._validate_implementation_receipt(receipt, require_current=False)
        if receipt["schema_version"] != qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION:
            raise ValueError("qualification compatibility bridge cannot reinterpret a historical implementation")
    if (old_impl_receipt["sha256"] != bridge["old_implementation_sha256"]
        or current_impl_receipt["sha256"] != bridge["new_implementation_sha256"]
        or old_impl_receipt["installed_entrypoint"] != current_impl_receipt["installed_entrypoint"]
        or old_impl_receipt["neqo_qcsd_client"] != current_impl_receipt["neqo_qcsd_client"]
        or current_impl_receipt["neqo_qcsd_client"]["sha256"] != bridge["client_sha256"]):
        raise ValueError("qualification compatibility bridge has another installed receipt or executable")
    for receipt, inventory_key in (
        (old_impl_receipt, "old_source_hashes"), (current_impl_receipt, "new_source_hashes")):
        if ({key: receipt["source"][key] for key in bridge["native_source"]} != bridge["native_source"]
            or any(bridge[inventory_key].get(path) != digest
                   for path, digest in receipt["source_files"].items())):
            raise ValueError("qualification compatibility bridge source roles differ from installed evidence")
    changed = bridge["changed_sources"]
    for path in qualification.IMPLEMENTATION_FILES:
        before = old_impl_receipt["source_files"][path]
        after = current_impl_receipt["source_files"][path]
        if before != after and (
            path not in COLLECTOR_FUNCTIONS or path not in changed
            or changed[path]["before_sha256"] != before or changed[path]["after_sha256"] != after
            or not set(changed[path]["functions"]).issubset(COLLECTOR_FUNCTIONS[path])):
            raise ValueError("qualification compatibility changes an unreviewed installed source role")
    for path in qualification.IMPLEMENTATION_PYTHON_FILES:
        before = old_impl_receipt["installed_modules"][path]
        after = current_impl_receipt["installed_modules"][path]
        if before["path"] != after["path"]:
            raise ValueError("qualification compatibility changes an installed module path")
    for path, digest in bridge["qualification_dependencies"]["source_hashes"].items():
        if bridge["old_source_hashes"].get(path) != digest or bridge["new_source_hashes"].get(path) != digest:
            raise ValueError("qualification compatibility changes a protected execution dependency")
    for path, projection in bridge["qualification_dependencies"]["source_projections"].items():
        if (path not in COLLECTOR_FUNCTIONS or not _digest(projection["sha256"])
            or not set(projection["excluded_collector_functions"]).issubset(COLLECTOR_FUNCTIONS[path])
            or any(f"{PurePosixPath(path).stem}.{name}" in bridge["qualification_dependencies"]["reachable_symbols"]
                   for name in projection["excluded_collector_functions"])):
            raise ValueError("qualification compatibility excludes an executing qualification dependency")
