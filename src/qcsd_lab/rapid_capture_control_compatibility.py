"""Prospective source comparison for the two-worker capture control path.

This contract preserves the acquisition producer/verifier groups and response
qualification primitive.  It permits only explicitly reviewed capture control
definitions and the existing launcher's parallel sections.  A derived bridge
is not an activation, a passed capture, or permission to promote older images.
The runtime authority must independently reopen these exact retained inputs.
The historical collector-lifecycle-v1 contract remains unchanged.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from . import chaff_qualification as qualification
from . import rapid_runtime_compatibility as historical

CONTRACT = "response-only-v2-parallel-capture-control-v2"
DOMAIN = "qcsd-rapid-parallel-capture-control-compatibility-v2"
BRIDGE_TYPE = historical.BRIDGE_TYPE
REVIEW_TYPE = "qcsd-rapid-parallel-capture-control-review-v2"
REVIEW_SCOPE = "parallel-capture-control-only"
ACQUISITION_GROUPS = frozenset({"curated", "fallback", "navigation", "page",
                              "preparation", "browser_policy", "collector", "attempt"})
NEW_FILES = frozenset({
    "src/qcsd_lab/rapid_formal_parallel.py", "tools/rapid_formal_parallel.py",
    "src/qcsd_lab/rapid_capture_control_compatibility.py",
    "src/qcsd_lab/rapid_capture_control_installation.py",
    "tools/rapid_capture_control_installation.py",
})
# Whole definitions are reviewed, including their signatures.  Everything else
# (imports, eager code, traffic constants, validators outside this list) stays
# protected.  An added helper is not a blanket exemption for its containing file.
CONTROL_DEFINITIONS = {
    "src/qcsd_lab/rapid_lane_evidence.py": frozenset({
        "prepare_lane_intent", "launch_lane", "_validated_host_start",
        "_verified_host_process", "_verified_retirement", "_intent_and_lineage",
        "_process_matches_lane", "complete_lane", "verify_launch_receipt",
        "image_check_command", "check_bound_image", "_lineage_payload",
    }),
    "src/qcsd_lab/rapid_parallel_capture.py": frozenset({
        "authority", "_runtime_authority", "image_preflight", "initialize",
        "release", "retire_lane", "verify_results", "reopen_launch", "gate",
        "retire_session", "verify_operator_closure", "launch_action", "main",
        "_execution_parameter_context",
    }),
    "src/qcsd_lab/rapid_formal_parallel.py": frozenset({"image_preflight", "resolve_dns"}),
    "tools/rapid_parallel_capture.py": frozenset({"launch", "main", "module-docstring"}),
    "src/qcsd_lab/rapid_class_epochs.py": frozenset({
        "prepare_block_lane_intent", "launch_block_lane", "_intent",
        "_terminal_process", "_deep_lane", "verify_lane", "_block_sites",
        "verify_policy", "image_check_command",
        "initialize_study", "_parser", "main",
        "check_corpus_in_image",
    }),
    "src/qcsd_lab/rapid_runtime_epochs.py": frozenset({
        "prepare_repaired_lane_intent", "launch_repaired_lane", "validate_intent",
        "executed_candidate_check", "verify_proposal", "validate_qualification_reuse",
        "_launch_env",
    }),
}
SHELL_REGIONS = (
    ("usage", b"usage() {\n", b"_qcsd_trusted_git() {\n"),
    ("parallel-dispatch", b"parallel_diagnostic=0\n", b'study_cohort_version=""\nstudy_cohort_version_seen=0\n'),
    ("parallel-workers", b"# Two measured workers share one authenticated guardian. All Docker mutations\n",
     b"# Every remaining ETF launch is a public campaign.  Give the measured client\n"),
    ("capture-control-installation-transport", b"\n  rapid_compatibility_args=()\n",
     b"\n  qcsd_run_attached_docker docker run --network none --read-only \\\n"),
)
SHELL_GUARDS = {
    "rapid-epoch-authority-guard": (
        b'  if (( rapid_capture_epoch )) || [[ -n "${QCSD_RAPID_COLLECTION_COMPATIBILITY:-}" ]]; then\n',
        b"  if (( rapid_capture_epoch || rapid_compatibility_runtime_epoch )); then\n",
    ),
}
BRIDGE_KEYS = historical._BRIDGE_KEYS | {"acquisition_source_groups", "control_projection"}
REVIEW_KEYS = {"schema_version", "artifact_type", "repair_scope", "reason", "changes",
               "acquisition_source_groups"}


def _python_projection(path: str, raw: bytes) -> tuple[bytes, dict[str, str]]:
    permitted = CONTROL_DEFINITIONS.get(path)
    if permitted is None:
        raise ValueError(f"capture control changes a protected source: {path}")
    tree = ast.parse(raw, filename=path)
    protected = []
    units = {}
    for index, node in enumerate(tree.body):
        name = (node.name if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                else "module-docstring" if index == 0 and isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                else None)
        if name in permitted:
            if name in units:
                raise ValueError("capture control has duplicate reviewed definitions")
            units[name] = historical._sha(ast.dump(node, include_attributes=False).encode())
        else:
            protected.append(node)
    projected = ast.dump(ast.Module(body=protected, type_ignores=[]), include_attributes=False).encode()
    return projected, units


def _shell_projection(raw: bytes) -> tuple[bytes, dict[str, str]]:
    projected = raw
    units = {}
    # Unique immutable delimiters also prevent moving a permitted section across
    # protected qualification, admission, scheduling or normal launch code.
    for name, start, end in SHELL_REGIONS:
        if projected.count(start) != 1 or projected.count(end) != 1:
            raise ValueError("launcher lacks unique reviewed parallel section boundaries")
        first = projected.index(start)
        last = projected.index(end)
        if last <= first:
            raise ValueError("launcher parallel section order changed")
        units[name] = historical._sha(projected[first:last])
        projected = projected[:first] + f"<capture-control:{name}>\n".encode() + projected[last:]
    for name, variants in SHELL_GUARDS.items():
        if sum(projected.count(value) for value in variants) != 1:
            raise ValueError("launcher epoch authority guard is not an exact approved variant")
        actual = next(value for value in variants if value in projected)
        units[name] = historical._sha(actual)
        projected = projected.replace(actual, f"<capture-control:{name}>\n".encode(), 1)
    return projected, units


def source_changes(old_sources: Mapping[str, bytes], new_sources: Mapping[str, bytes]
                   ) -> tuple[dict[str, Any], dict[str, Any]]:
    """Derive the exact review inventory, rejecting edits outside named units."""
    old_hashes = historical._source_inventory(old_sources)
    new_hashes = historical._source_inventory(new_sources)
    if set(old_hashes) - set(new_hashes) or not (set(new_hashes) - set(old_hashes)).issubset(NEW_FILES):
        raise ValueError("capture control added an unregistered source or removed retained source")
    changes = {}
    projections = {}
    for path in sorted(new_hashes):
        if old_hashes.get(path) == new_hashes[path]:
            continue
        if path not in old_hashes:
            ast.parse(new_sources[path], filename=path)
            units = ["new-file"]
            projection = {"protected_sha256": None, "old_units": {},
                          "new_units": {"new-file": new_hashes[path]}}
        else:
            project = _shell_projection if path == "qcsd-lab" else lambda raw: _python_projection(path, raw)
            before, old_units = project(old_sources[path])
            after, new_units = project(new_sources[path])
            if before != after:
                raise ValueError(f"capture control changes protected code outside reviewed units: {path}")
            units = sorted(name for name in old_units.keys() | new_units.keys()
                           if old_units.get(name) != new_units.get(name))
            if not units:
                raise ValueError("capture control byte change is outside its reviewed semantic units")
            projection = {"protected_sha256": historical._sha(before),
                          "old_units": old_units, "new_units": new_units}
        changes[path] = {"before_sha256": old_hashes.get(path), "after_sha256": new_hashes[path], "units": units}
        projections[path] = projection
    return changes, projections


def _expected_acquisition_modules() -> dict[str, set[str]]:
    # These source inventories are themselves protected in both retained trees.
    from . import rapid_site_admission as admission
    from . import rapid_browser_policy_evidence as browser
    from . import rapid_collector_failure_evidence as collector
    from . import rapid_attempt_failure_evidence as attempt
    navigation = {"qcsd_lab.rapid_page_evidence", "qcsd_lab.class_acquisition",
                  "qcsd_lab.class_catalogue", "qcsd_lab.rapid_study_profile", "qcsd_lab.util"}
    return {**{name: set(modules) for name, modules in admission.ROOT_SCREEN_MODULES.items()},
            "navigation": navigation, "page": navigation | {"qcsd_lab.h3_prebaseline", "neqo-qcsd-client"},
            "preparation": set(admission.preparation_implementation_sources(
                application_response_policy=True, qualified_chaff_origin_policy=True,
                buflo_incoming_credit_release_policy=True)),
            "browser_policy": set(browser.implementation_sources()),
            "collector": set(collector.implementation_sources()),
            "attempt": set(attempt.implementation_sources(application_response_policy=True,
                qualified_chaff_origin_policy=True, buflo_incoming_credit_release_policy=True))}


def _acquisition_groups(groups: Any, old_hashes: Mapping[str, str], new_hashes: Mapping[str, str],
                        client_sha: str) -> dict[str, dict[str, str]]:
    expected = _expected_acquisition_modules()
    if not isinstance(groups, Mapping) or set(groups) != ACQUISITION_GROUPS or set(expected) != ACQUISITION_GROUPS:
        raise ValueError("capture control requires all eight retained acquisition source groups")
    result = {}
    for group, modules in sorted(groups.items()):
        if not isinstance(modules, Mapping) or set(modules) != expected[group]:
            raise ValueError(f"capture control acquisition module inventory differs: {group}")
        result[group] = {}
        for name, digest in sorted(modules.items()):
            if name == "neqo-qcsd-client":
                valid = digest == client_sha
            else:
                if name.startswith("qcsd_lab."):
                    path = "src/" + name.replace(".", "/") + ".py"
                elif name.startswith("tools."):
                    path = name.replace(".", "/") + ".py"
                else:
                    raise ValueError("capture control has an unknown acquisition source role")
                valid = old_hashes.get(path) == digest == new_hashes.get(path)
            if not historical._digest(digest) or not valid:
                raise ValueError("capture control changed a retained acquisition producer, verifier or client")
            result[group][name] = digest
    return result


def _validate_projection_inventory(bridge: Mapping[str, Any]) -> None:
    old, new = bridge["old_source_hashes"], bridge["new_source_hashes"]
    if (not isinstance(old, Mapping) or not old or not isinstance(new, Mapping) or not new
        or any(not isinstance(path, str) or PurePosixPath(path).is_absolute()
               or PurePosixPath(path).as_posix() != path or "\\" in path
               or any(part in {".", ".."} for part in PurePosixPath(path).parts)
               or not historical._digest(digest)
               for mapping in (old, new) for path, digest in mapping.items())
        or set(old) - set(new) or not (set(new) - set(old)).issubset(NEW_FILES)):
        raise ValueError("capture control source hash inventory is malformed")
    changed = {path for path, digest in new.items() if old.get(path) != digest}
    changes, projections = bridge["changed_sources"], bridge["control_projection"]
    if (not isinstance(changes, Mapping) or not isinstance(projections, Mapping)
        or set(changes) != changed or set(projections) != changed):
        raise ValueError("capture control projection inventory is incomplete")
    for path in sorted(changed):
        change, projection = changes[path], projections[path]
        if (not isinstance(change, Mapping) or set(change) != {"before_sha256", "after_sha256", "units"}
            or change["before_sha256"] != old.get(path) or change["after_sha256"] != new[path]
            or not isinstance(projection, Mapping)
            or set(projection) != {"protected_sha256", "old_units", "new_units"}
            or not isinstance(projection["old_units"], Mapping) or not isinstance(projection["new_units"], Mapping)):
            raise ValueError("capture control changed-source projection fields differ")
        if path not in old:
            if (path not in NEW_FILES or change["units"] != ["new-file"]
                or projection != {"protected_sha256": None, "old_units": {}, "new_units": {"new-file": new[path]}}):
                raise ValueError("capture control has an unregistered new source projection")
            continue
        permitted = ({name for name, _, _ in SHELL_REGIONS} | set(SHELL_GUARDS) if path == "qcsd-lab"
                     else CONTROL_DEFINITIONS.get(path))
        before, after = projection["old_units"], projection["new_units"]
        if (permitted is None or not historical._digest(projection["protected_sha256"])
            or not set(before).issubset(permitted) or not set(after).issubset(permitted)
            or any(not historical._digest(digest) for mapping in (before, after) for digest in mapping.values())
            or not change["units"] or change["units"] != sorted(name for name in before.keys() | after.keys()
                if before.get(name) != after.get(name))):
            raise ValueError("capture control has an unsupported definition or launcher projection")


def validate_compatibility(old_runtime_proof: Mapping[str, Any], new_runtime_proof: Mapping[str, Any],
                           old_source_bytes: Mapping[str, bytes], new_source_bytes: Mapping[str, bytes],
                           review: Mapping[str, Any], *, acquisition_source_groups: Mapping[str, Any]
                           ) -> dict[str, Any]:
    """Derive a new bridge; prospective runtime activation remains external."""
    old_hashes = historical._source_inventory(old_source_bytes)
    new_hashes = historical._source_inventory(new_source_bytes)
    old_impl = historical._runtime(old_runtime_proof, old_hashes)
    new_impl = historical._runtime(new_runtime_proof, new_hashes)
    native_keys = ("neqo_commit", "neqo_pinned_commit", "neqo_dirty", "neqo_patch_sha256")
    if (any(old_runtime_proof["runtime_source"][key] != new_runtime_proof["runtime_source"][key] for key in native_keys)
        or old_runtime_proof["client_sha256"] != new_runtime_proof["client_sha256"]
        or old_runtime_proof["traffic_hashes"] != new_runtime_proof["traffic_hashes"]):
        raise ValueError("capture control changes Native, client or fixed traffic identity")
    for proof, hashes in ((old_runtime_proof, old_hashes), (new_runtime_proof, new_hashes)):
        if proof["base_launcher_sha256"] != hashes.get("qcsd-lab") or proof["host_launcher_sha256"] != hashes.get("qcsd-lab"):
            raise ValueError("capture control launchers must bind the actual matching retained source")
    groups = _acquisition_groups(acquisition_source_groups, old_hashes, new_hashes, old_runtime_proof["client_sha256"])
    dependencies = historical.qualification_dependencies(old_source_bytes)
    if dependencies != historical.qualification_dependencies(new_source_bytes):
        raise ValueError("capture control changes the actual response-only qualification dependency surface")
    changes, projections = source_changes(old_source_bytes, new_source_bytes)
    if (not isinstance(review, Mapping) or set(review) != REVIEW_KEYS
        or type(review["schema_version"]) is not int or review["schema_version"] != 1
        or review["artifact_type"] != REVIEW_TYPE or review["repair_scope"] != REVIEW_SCOPE
        or not isinstance(review["reason"], str) or not review["reason"].strip()
        or review["changes"] != changes or review["acquisition_source_groups"] != groups):
        raise ValueError("capture control review does not bind its exact source units and acquisition groups")
    bridge = {"schema_version": 1, "artifact_type": BRIDGE_TYPE, "domain": DOMAIN, "contract": CONTRACT,
        "old_runtime_sha256": historical._sha(historical._json(old_runtime_proof)),
        "new_runtime_sha256": historical._sha(historical._json(new_runtime_proof)),
        "old_implementation_sha256": old_impl["sha256"], "new_implementation_sha256": new_impl["sha256"],
        "old_source_hashes": old_hashes, "new_source_hashes": new_hashes,
        "qualification_dependencies": dependencies, "changed_sources": changes,
        "control_projection": projections, "acquisition_source_groups": groups,
        "native_source": {key: old_runtime_proof["runtime_source"][key] for key in native_keys},
        "client_sha256": old_runtime_proof["client_sha256"], "traffic_hashes": dict(old_runtime_proof["traffic_hashes"]),
        "review_sha256": historical._sha(historical._json(review)), "formal_accepted_trace_count": 0, "scientific_credit": False}
    bridge["sha256"] = historical._sha(DOMAIN.encode() + b"\0" + historical._json(bridge))
    validate_current_implementation(old_impl, new_impl, bridge)
    return bridge


def validate_current_implementation(old_impl: Mapping[str, Any], current_impl: Mapping[str, Any],
                                    bridge: Mapping[str, Any]) -> None:
    """Check installed roles after the runtime authority reopens the bridge."""
    if (not isinstance(bridge, Mapping) or set(bridge) != BRIDGE_KEYS
        or type(bridge["schema_version"]) is not int or bridge["schema_version"] != 1
        or bridge["artifact_type"] != BRIDGE_TYPE or bridge["domain"] != DOMAIN or bridge["contract"] != CONTRACT
        or type(bridge["formal_accepted_trace_count"]) is not int or bridge["formal_accepted_trace_count"] != 0
        or bridge["scientific_credit"] is not False
        or bridge["sha256"] != historical._sha(DOMAIN.encode() + b"\0" + historical._json({key: value for key, value in bridge.items() if key != "sha256"}))):
        raise ValueError("parallel capture control compatibility bridge is malformed or changed")
    if (not isinstance(bridge["native_source"], Mapping)
        or set(bridge["native_source"]) != {"neqo_commit", "neqo_pinned_commit", "neqo_dirty", "neqo_patch_sha256"}):
        raise ValueError("capture control Native source role inventory differs")
    _validate_projection_inventory(bridge)
    for receipt, key, inventory in ((old_impl, "old_implementation_sha256", "old_source_hashes"),
                                     (current_impl, "new_implementation_sha256", "new_source_hashes")):
        qualification._validate_implementation_receipt(receipt, require_current=False)
        if (receipt["schema_version"] != qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION
            or receipt["sha256"] != bridge[key]
            or {name: receipt["source"][name] for name in bridge["native_source"]} != bridge["native_source"]
            or any(bridge[inventory].get(path) != digest for path, digest in receipt["source_files"].items())):
            raise ValueError("capture control installed source roles differ from the reopened bridge")
    if (old_impl["installed_entrypoint"]["path"] != current_impl["installed_entrypoint"]["path"]
        or old_impl["neqo_qcsd_client"] != current_impl["neqo_qcsd_client"]
        or current_impl["neqo_qcsd_client"]["sha256"] != bridge["client_sha256"]):
        raise ValueError("capture control changed an installed executable path or Native client")
    for path in qualification.IMPLEMENTATION_PYTHON_FILES:
        if old_impl["installed_modules"][path]["path"] != current_impl["installed_modules"][path]["path"]:
            raise ValueError("capture control changed an installed module path")
    _acquisition_groups(bridge["acquisition_source_groups"], bridge["old_source_hashes"],
                        bridge["new_source_hashes"], bridge["client_sha256"])
    changes = bridge["changed_sources"]
    for path in qualification.IMPLEMENTATION_FILES:
        before, after = old_impl["source_files"][path], current_impl["source_files"][path]
        if before != after and (path != "qcsd-lab" or path not in changes
            or changes[path]["before_sha256"] != before or changes[path]["after_sha256"] != after):
            raise ValueError("capture control changed a protected installed qualification role")
    for path, digest in bridge["qualification_dependencies"]["source_hashes"].items():
        if bridge["old_source_hashes"].get(path) != digest or bridge["new_source_hashes"].get(path) != digest:
            raise ValueError("capture control changed a protected qualification dependency")
    # Projected dependencies retain the historical strictly enumerated packet
    # observer boundaries; this new contract does not expand that primitive.
    for path, projection in bridge["qualification_dependencies"]["source_projections"].items():
        if (path not in historical.COLLECTOR_FUNCTIONS or not historical._digest(projection["sha256"])
            or not set(projection["excluded_collector_functions"]).issubset(historical.COLLECTOR_FUNCTIONS[path])):
            raise ValueError("capture control excluded an unknown qualification dependency")
