"""Prospective capture policies derived from immutable complete static GETs.

The original preparation, admission and producer interpretation remain exact.
A declaration precedes the derived files; a closed amendment binds their bytes
before fresh response qualification and setting-specific capture readiness.
"""
from __future__ import annotations

from copy import deepcopy
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping

from . import capture_acceptance_policy as capture
from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as receipts
from . import supplied_static_admission as admission
from . import supplied_static_graph as graph
from . import supplied_static_preparation as preparation
from . import rapid_capture_traffic as traffic

ROLE = "supplied-static-complete-get-amended-capture-preparation-v1"
DURATION_ROLE = "supplied-static-complete-get-amended-buflo-duration200-preparation-v2"
FIELD = "static_capture_policy_amendment"
DECLARATION_TYPE = "qcsd-supplied-static-capture-policy-declaration-v1"
RECEIPT_TYPE = "qcsd-supplied-static-capture-policy-amendment-v1"
CONTRACT = "unchanged-admitted-static-get-and-graph-with-explicit-capture-policy-v1"
DURATION_CONTRACT = "unchanged-admitted-static-get-and-graph-with-explicit-fixed-buflo200-capture-policy-v2"
ORIGINAL_POLICIES = {capture.FIELD: capture.ACK_START_POLICY,
    capture.TAMARAW_FIELD: capture.TAMARAW_POLICY,
    capture.FRONT_FIELD: capture.FRONT_WINDOW_POLICY,
    capture.TERMINAL_PRIMARY_FIELD: capture.TERMINAL_PRIMARY_POLICY}
SOURCE_FILES = {name: "src/qcsd_lab/" + name + ".py" for name in (
    "supplied_static_capture_amendment", "manifest", "application_response_policy",
    "capture_acceptance_policy", "fidelity", "kernel_tx", "capture_session",
    "experiment", "buflo_handoff", "front_preparation_evidence", "static_evidence_transport")}
DURATION_SOURCE_FILES = {name: "src/qcsd_lab/" + name + ".py" for name in (
    "buflo_duration_budget", "rapid_capture_traffic", "parameters", "rapid_capture_plan",
    "rapid_lane_evidence", "rapid_rolling_capture", "rapid_rolling_readiness", "rapid_operation_facts")}
DECLARATION_FIELDS = {"contract", "original_data_role", "capture_data_role", "policies", "modes",
    "enrollment", "admission_provenance", "runtime", "runtime_artifacts", "authority_sources",
    "workloads", "receipt_path", "published_at", "formal_accepted_trace_count", "scientific_credit"}
RECEIPT_FIELDS = {"contract", "declaration", "workloads", "published_at",
                  "formal_accepted_trace_count", "scientific_credit"}
ROW_FIELDS = {"candidate_id", "workload_id", "original_terminal", "original_manifest",
    "original_get_proof", "original_capture_policies", "resource_records_sha256", "capture_manifest_path"}


def is_amended(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("data_role") in {ROLE, DURATION_ROLE}


def policies(*, front_policy: str | None = None, buflo_policy: str | None = None) -> dict[str, str]:
    selected = {}
    if front_policy is not None:
        if type(front_policy) is not str or front_policy != capture.FRONT_RESERVE_POLICY:
            raise ValueError("static FRONT amendment requires the explicit V4 reserve policy")
        selected[capture.FRONT_FIELD] = front_policy
    if buflo_policy is not None:
        if type(buflo_policy) is not str or buflo_policy != capture.BUFLO_KERNEL_PREPARATION_POLICY:
            raise ValueError("static BuFLO amendment requires the explicit V12 preparation policy")
        selected[capture.BUFLO_KERNEL_PREPARATION_FIELD] = buflo_policy
    if not selected:
        raise ValueError("static capture amendment requires at least one explicit capture policy")
    return selected


def _policies(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or not set(value) <= {capture.FRONT_FIELD, capture.BUFLO_KERNEL_PREPARATION_FIELD}:
        raise ValueError("static capture amendment changes unapproved policy fields")
    expected = policies(front_policy=value.get(capture.FRONT_FIELD),
                        buflo_policy=value.get(capture.BUFLO_KERNEL_PREPARATION_FIELD))
    if graph.canonical_bytes(value) != graph.canonical_bytes(expected):
        raise ValueError("static capture amendment policies are malformed or null")
    return expected


def _modes(selected: Mapping[str, str]) -> list[str]:
    return [mode for field, mode in ((capture.FRONT_FIELD, "front"),
        (capture.BUFLO_KERNEL_PREPARATION_FIELD, "buflo")) if field in selected]


def authority_files(duration_policy: str | None = None) -> dict[str, str]:
    return {**SOURCE_FILES, **(DURATION_SOURCE_FILES if traffic.policy(duration_policy) is not None else {})}


def _sources(runtime: Mapping[str, str], *, duration_policy: str | None = None) -> dict[str, str]:
    # Installed imports live in site-packages, independently of the frozen
    # source mounts. Compare actual imported bytes, not an assumed repo layout.
    hashes = {name: graph.digest(lanes._read(Path(import_module("qcsd_lab." + name).__file__)))
              for name in authority_files(duration_policy)}
    for root in (Path(runtime["runtime_source_root"]), Path(runtime["module_root"])):
        if any(graph.digest(lanes._read(root / relative)) != hashes[name] for name, relative in authority_files(duration_policy).items()):
            raise ValueError("static capture amendment authority differs from its actual frozen capture source")
    return hashes


def _rows(enrollment: Path, runtime: Mapping[str, str], batch, classes) -> list[dict[str, Any]]:
    from . import rapid_rolling_capture as rolling
    policy = rolling.verify_policy(rolling._open_ref(batch["policy"]).parent)
    if policy["contract"] != rolling.STATIC_CONTRACT:
        raise ValueError("static capture amendment cannot import a browser study")
    rows = []
    for row in classes[-len(batch["selected_candidate_ids"]):]:
        context = admission.load_context(Path(row["admission_root"]))
        terminal = rolling._open_ref(row["terminal"])
        facts = admission.verify_terminal(terminal, context)
        original, manifest = admission.prepared_workload(context, terminal)
        prep = manifest["preparation"]
        if (not preparation.is_static(prep) or facts["outcome"] != "admitted"
            or {key: prep.get(key) for key in ORIGINAL_POLICIES} != ORIGINAL_POLICIES):
            raise ValueError("static capture amendment changed its original admitted preparation")
        target = Path(runtime["workload_root"]) / original.name
        if target == original:
            raise ValueError("static capture amendment must preserve the original manifest")
        rows.append({"candidate_id": row["candidate_id"], "workload_id": original.stem,
            "original_terminal": rolling._ref(terminal), "original_manifest": rolling._ref(original),
            "original_get_proof": prep["static_get_evidence"]["proof"],
            "original_capture_policies": dict(ORIGINAL_POLICIES),
            "resource_records_sha256": graph.digest(graph.canonical_bytes(manifest["resources"])),
            "capture_manifest_path": str(target)})
    return rows


def _derived(original: Mapping[str, Any], declaration_ref: Mapping[str, str], selected: Mapping[str, str],
             *, duration_policy: str | None = None) -> dict[str, Any]:
    if not preparation.is_static(original.get("preparation")):
        raise ValueError("static capture amendment needs its original complete GET preparation")
    value = deepcopy(dict(original))
    value["preparation"].update(data_role=DURATION_ROLE if traffic.policy(duration_policy) is not None else ROLE,
                                **{FIELD: dict(declaration_ref)}, **dict(selected))
    capture.validate_front_preparation_policy(value["preparation"])
    capture.validate_buflo_kernel_preparation_policy(value["preparation"])
    return value


def _declaration(path: Path, *, enrollment: Path | None = None, runtime: Mapping[str, str] | None = None):
    from . import rapid_rolling_capture as rolling
    value = receipts._unpack(lanes._read(path), DECLARATION_TYPE)
    fields = set(DECLARATION_FIELDS)
    duration_policy = None
    if traffic.FIELD in value:
        fields.update({traffic.FIELD, "traffic_artifacts"})
        duration_policy = traffic.policy(value[traffic.FIELD])
        if duration_policy is None:
            raise ValueError("static duration amendment requires its explicit fixed policy")
    rolling._keys(value, fields, "static capture declaration")
    selected = _policies(value["policies"])
    if (value["contract"] != (DURATION_CONTRACT if duration_policy else CONTRACT)
        or value["original_data_role"] != preparation.ROLE
        or value["capture_data_role"] != (DURATION_ROLE if duration_policy else ROLE)
        or value["modes"] != _modes(selected) or duration_policy and value["modes"] != ["buflo"]
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False):
        raise ValueError("static capture declaration changed its role or scientific credit")
    actual_runtime = rolling._runtime(value["runtime"])
    actual_enrollment = rolling._open_ref(value["enrollment"])
    if (enrollment is not None and actual_enrollment != enrollment.absolute()
        or runtime is not None and actual_runtime != rolling._runtime({key: runtime[key] for key in rolling.RUNTIME_FIELDS})):
        raise ValueError("static capture declaration changed its enrollment or capture runtime")
    batch, classes, policy = rolling._verify_enrollment(actual_enrollment)
    if actual_runtime["data_root"] != policy["runtime"]["data_root"]:
        raise ValueError("static capture declaration changed its original study root")
    root = rolling._open_ref(batch["policy"]).parent
    receipt_path = Path(value["receipt_path"])
    if (not path.is_absolute() or not path.is_relative_to(root) or ".." in path.parts
        or not receipt_path.is_absolute() or not receipt_path.is_relative_to(root)
        or ".." in receipt_path.parts or receipt_path == path):
        raise ValueError("static capture declaration is outside its original study")
    artifacts = {key: rolling._ref(Path(actual_runtime[key])) for key in
                 ("source_manifest", "client_binary", "base_launcher", "host_launcher")}
    if (duration_policy and value["traffic_artifacts"] != traffic.artifacts(actual_runtime, duration_policy)
        or value["runtime_artifacts"] != artifacts
        or value["authority_sources"] != _sources(actual_runtime, duration_policy=duration_policy)
        or value["admission_provenance"] != rolling._ref(Path(batch["admission_root"]) / "provenance.json")
        or value["workloads"] != _rows(actual_enrollment, actual_runtime, batch, classes)
        or not receipts._utc(batch["declared_at"]) <= receipts._utc(value["published_at"]) <= receipts._utc(receipts._now())):
        raise ValueError("static capture declaration changed original GET, graph, source or publication bindings")
    for row in value["workloads"]:
        rolling._keys(row, ROW_FIELDS, "static capture declaration workload")
    return value


def _closed(path: Path, *, enrollment: Path | None = None, runtime: Mapping[str, str] | None = None):
    from . import rapid_rolling_capture as rolling
    value = receipts._unpack(lanes._read(path), RECEIPT_TYPE)
    rolling._keys(value, RECEIPT_FIELDS, "static capture amendment")
    declaration_path = rolling._open_ref(value["declaration"])
    declaration = _declaration(declaration_path, enrollment=enrollment, runtime=runtime)
    if (value["contract"] != declaration["contract"] or Path(declaration["receipt_path"]) != path.absolute()
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False
        or not receipts._utc(declaration["published_at"]) <= receipts._utc(value["published_at"]) <= receipts._utc(receipts._now())):
        raise ValueError("static capture amendment changes its prospective closure or credit")
    expected = []
    for row in declaration["workloads"]:
        original = rolling._open_ref(row["original_manifest"])
        derived = _derived(lanes._load(lanes._read(original)), value["declaration"], declaration["policies"],
                           duration_policy=declaration.get(traffic.FIELD))
        target = Path(row["capture_manifest_path"])
        if lanes._read(target) != graph.canonical_bytes(derived):
            raise ValueError("static capture amendment changed resources, headers, original proof or unrelated fields")
        expected.append({**row, "capture_manifest": rolling._ref(target)})
    if value["workloads"] != expected:
        raise ValueError("static capture amendment changed its exact derived workload inventory")
    return {**value, "modes": declaration["modes"], "runtime": declaration["runtime"],
            "policies": declaration["policies"],
            **({traffic.FIELD: declaration[traffic.FIELD], "traffic_artifacts": declaration["traffic_artifacts"]}
               if traffic.FIELD in declaration else {})}


def publish_amendment(enrollment: Path, runtime: Mapping[str, str], output: Path, *,
                      front_policy: str | None = None, buflo_policy: str | None = None,
                      buflo_duration_policy: str | None = None) -> Path:
    from . import rapid_rolling_capture as rolling
    selected = policies(front_policy=front_policy, buflo_policy=buflo_policy)
    duration_policy = traffic.policy(buflo_duration_policy)
    if duration_policy and _modes(selected) != ["buflo"]:
        raise ValueError("fixed BuFLO200 amendment authorizes only its separately ready BuFLO setting")
    runtime = rolling._runtime(dict(runtime))
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    root = rolling._open_ref(batch["policy"]).parent
    output = output.absolute()
    declaration = output.with_name(output.stem + "-declaration.json")
    if (runtime["data_root"] != policy["runtime"]["data_root"] or not output.is_relative_to(root)
        or ".." in output.parts or any(p.exists() or p.is_symlink() for p in (output, declaration))):
        raise ValueError("static capture amendment requires a fresh declaration in its original study")
    rows = _rows(enrollment, runtime, batch, classes)
    if any(Path(row["capture_manifest_path"]).exists() or Path(row["capture_manifest_path"]).is_symlink() for row in rows):
        raise ValueError("static capture amendment never overwrites an original or previous capture workload")
    payload = {"contract": DURATION_CONTRACT if duration_policy else CONTRACT,
        "original_data_role": preparation.ROLE, "capture_data_role": DURATION_ROLE if duration_policy else ROLE,
        "policies": selected, "modes": _modes(selected), "enrollment": rolling._ref(enrollment),
        "admission_provenance": rolling._ref(Path(batch["admission_root"]) / "provenance.json"),
        "runtime": dict(runtime), "runtime_artifacts": {key: rolling._ref(Path(runtime[key])) for key in
            ("source_manifest", "client_binary", "base_launcher", "host_launcher")},
        "authority_sources": _sources(runtime, duration_policy=duration_policy), "workloads": rows, "receipt_path": str(output),
        "published_at": receipts._now(), "formal_accepted_trace_count": 0, "scientific_credit": False}
    if duration_policy:
        payload.update({traffic.FIELD: duration_policy, "traffic_artifacts": traffic.artifacts(runtime, duration_policy)})
    rolling._write(declaration, DECLARATION_TYPE, payload)
    declaration_ref = rolling._ref(declaration)
    captured = []
    for row in rows:
        original = lanes._load(lanes._read(rolling._open_ref(row["original_manifest"])))
        target = Path(row["capture_manifest_path"])
        receipts.durable_create(target, graph.canonical_bytes(_derived(original, declaration_ref, selected,
            duration_policy=duration_policy)))
        captured.append({**row, "capture_manifest": rolling._ref(target)})
    rolling._write(output, RECEIPT_TYPE, {"contract": payload["contract"], "declaration": declaration_ref,
        "workloads": captured, "published_at": receipts._now(),
        "formal_accepted_trace_count": 0, "scientific_credit": False})
    _closed(output, enrollment=enrollment, runtime=runtime)
    return output


def validate_amendment(path: Path, *, enrollment: Path, runtime: Mapping[str, str]):
    return _closed(path.absolute(), enrollment=enrollment, runtime=runtime)


def validate_preparation(value: Mapping[str, Any], resources: list[dict[str, Any]]):
    if not is_amended(value):
        raise ValueError("static capture amendment data role is absent")
    declaration_path = preparation.open_reference(value.get(FIELD))
    declaration = _declaration(declaration_path)
    amendment = _closed(Path(declaration["receipt_path"]))
    actual = graph.canonical_bytes({"preparation": value, "resources": resources})
    matching = [row for row in amendment["workloads"] if graph.canonical_bytes(_derived(
        lanes._load(lanes._read(preparation.open_reference(row["original_manifest"]))),
        amendment["declaration"], declaration["policies"], duration_policy=declaration.get(traffic.FIELD))) == actual]
    if len(matching) != 1:
        raise ValueError("static capture preparation differs from its exact admitted full graph and policy declaration")
    original = lanes._load(lanes._read(preparation.open_reference(matching[0]["original_manifest"])))
    return preparation.validate_static_preparation(original["preparation"], original["resources"])


def preparation_roots(value: Mapping[str, Any]) -> list[Path]:
    from . import rapid_rolling_capture as rolling
    from .static_evidence_transport import _path
    declaration_path = preparation.open_reference(value[FIELD])
    declaration = _declaration(declaration_path)
    roots = {declaration_path.parent, preparation.open_reference(declaration["enrollment"]).parent,
        preparation.open_reference(declaration["admission_provenance"]).parent}
    for row in declaration["workloads"]:
        original_path = preparation.open_reference(row["original_manifest"])
        original = lanes._load(lanes._read(original_path))
        roots.add(original_path.parent)
        roots.update(preparation.preparation_roots(original["preparation"]))
    # The installed verifier also reopens the declaration's Source and client
    # authority at their original absolute names. Alias mounts at /lab and
    # /runtime-src cannot supply those names. Derive only authenticated roots.
    runtime = declaration["runtime"]
    roots.update(_path(Path(runtime[key]), directory=True) for key in
                 ("runtime_source_root", "module_root", "execution_root"))
    roots.update(_path(preparation.open_reference(reference)).parent
                 for reference in declaration["runtime_artifacts"].values())
    roots.update(_path(preparation.open_reference(reference)).parent
                 for reference in declaration.get("traffic_artifacts", {}).values())
    # The declaration authenticates the original enrollment, whose policy
    # verifier also reopens its own, separately frozen runtime. Transport those
    # original authorities at their actual names without mounting data_root.
    enrollment = rolling._open_ref(declaration["enrollment"])
    batch = receipts._unpack(lanes._read(enrollment), rolling.ENROLLMENT_TYPE)
    policy_path = rolling._open_ref(batch["policy"])
    policy = rolling.verify_policy(policy_path.parent)
    roots.add(policy_path.parent)
    original_runtime = policy["runtime"]
    roots.update(_path(Path(original_runtime[key]), directory=True) for key in
                 ("runtime_source_root", "module_root", "execution_root"))
    roots.update(_path(rolling._open_ref(policy[key])).parent for key in
                 ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"))
    # Only the declaration's verified enrollment and inherited context prefixes
    # are dependencies. Later mutable acquisition decisions are not mounts.
    contexts = {_path(Path(policy["initial_admission_root"]), directory=True)}
    terminals = {}
    while True:
        contexts.add(rolling._open_ref(batch["admission_provenance"]).parent)
        for decision in batch["decisions"]:
            terminal = rolling._open_ref(decision["terminal"])
            terminals[terminal] = decision["terminal"]
        if batch["parent"] is None:
            break
        batch = receipts._unpack(lanes._read(rolling._open_ref(batch["parent"])), rolling.ENROLLMENT_TYPE)
    pending, seen = list(contexts), set()
    while pending:
        context_root = pending.pop()
        if context_root in seen:
            continue
        seen.add(context_root)
        roots.add(_path(context_root, directory=True))
        context = receipts._unpack(lanes._read(context_root / "provenance.json"), admission.PROVENANCE_TYPE)
        for reference in context["inherited_terminals"]:
            terminals[rolling._open_ref(reference)] = reference
        if context["parent_context"] is not None:
            pending.append(rolling._open_ref(context["parent_context"]).parent)
    for reference in terminals.values():
        terminal_path = rolling._open_ref(reference)
        terminal = receipts._unpack(lanes._read(terminal_path), admission.TERMINAL_TYPE)
        roots.add(terminal_path.parent)
        if terminal["outcome"] == "admitted":
            original_path = rolling._open_ref(terminal["prepared_workload"])
            original = lanes._load(lanes._read(original_path))
            roots.add(original_path.parent)
            roots.update(preparation.preparation_roots(original["preparation"]))
        elif terminal["outcome"] == "operational-deferred":
            roots.add(_path(Path(terminal["get_evidence_root"]), directory=True))
            if terminal["namespace"] is not None:
                roots.update(_path(rolling._open_ref(terminal["namespace"][key])).parent for key in
                             ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    return sorted(_path(Path(root), directory=True) for root in roots)


def require_canary(reference, facts, amendment_reference, amendment, *, mode: str):
    from . import rapid_rolling_capture as rolling
    if mode not in amendment["modes"]:
        raise ValueError("static capture amendment does not authorize this setting")
    canary = lanes._load(lanes._read(rolling._open_ref(reference["plan"])))
    matching = [row for row in amendment["workloads"] if row["capture_manifest"]["sha256"] == facts.get("workload_sha256")]
    if (canary.get("static_capture_amendment") != amendment_reference or len(matching) != 1
        or facts.get("full_graph", {}).get("resource_records_sha256") != matching[0]["resource_records_sha256"]):
        raise ValueError("static canary changed its amendment, derived workload or complete graph")
    if canary.get(traffic.FIELD) != amendment.get(traffic.FIELD):
        raise ValueError("static canary changed its explicitly declared BuFLO duration policy")
    if traffic.FIELD in amendment:
        traffic.canary_policy(canary, mode)
    start = lanes._load(lanes._read(rolling._open_ref(reference["capture"]["started"])))
    if receipts._utc(start["started_at"]) < receipts._utc(amendment["published_at"]):
        raise ValueError("static canary was captured before its prospective policy amendment")
