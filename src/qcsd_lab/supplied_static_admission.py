"""Ordered, independently reopened admission for a new fixed-resource study.

No browser terminal is accepted. Actual GET failures are retryable operational
deferrals, never evidence that a site is scientifically ineligible.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import rapid_site_admission as receipts
from . import supplied_static_get as get
from . import supplied_static_graph as graph
from . import supplied_static_preparation as preparation

PROVENANCE_TYPE = "qcsd-static-fixed-resource-acquisition-v1"
TERMINAL_TYPE = "qcsd-static-fixed-resource-terminal-v1"
CONTRACT = "ordered-complete-supplied-get-first-fifty-fixed-resource-replays-v1"
PROFILE = {"schema_version": 1, "contract": CONTRACT, "data_role": preparation.ROLE,
           "class_target": 50, "settings": 5, "visits_per_setting": 64,
           "formal_trace_target": 16000, "complete_get_runs": 1, "minimum_origins": 2,
           "minimum_nonempty_successful_secondary_resources": 1,
           "all_supplied_resources_required": True, "browser_completion_required": False,
           "challenge_absence_claim": False, "response_stability_claim": False}


def capture_limits(max_response_bytes: int, capture_megabytes: int) -> dict[str, int]:
    from .rapid_capture_plan import V5_CAPTURE_LIMITS
    if (type(max_response_bytes) is not int or not 0 < max_response_bytes < 2**64
        or type(capture_megabytes) is not int or not 0 < capture_megabytes < 2**32):
        raise ValueError("static response and recording caps must be explicit positive integers")
    return {**V5_CAPTURE_LIMITS, "max_response_bytes": max_response_bytes, "capture_megabytes": capture_megabytes}


@dataclass(frozen=True)
class Context:
    root: Path
    provenance: dict[str, Any]
    source_bytes: bytes
    candidates: tuple[dict[str, Any], ...]


def _read_json(path: Path) -> Any:
    return get._load(get._read(path))


def _write(path: Path, kind: str, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    receipts.durable_create(path, receipts._json(receipts._bind(kind, payload)))
    return path


def _candidate_rows(source: bytes, digest: str, order: Any = None) -> tuple[dict[str, Any], ...]:
    rows = list(graph._source(source, digest))
    order = list(range(1, len(rows) + 1)) if order is None else order
    if (not isinstance(order, list) or any(type(value) is not int for value in order)
        or len(order) != len(rows) or set(order) != set(range(1, len(rows) + 1))):
        raise ValueError("static candidate order must be a complete unique permutation of source positions")
    return tuple({"candidate_id": "static-" + graph.digest(graph.canonical_bytes(rows[source_position - 1])),
                  "domain": rows[source_position - 1]["crUX_domain"], "position": index,
                  "source_position": source_position,
                  "supplied_candidate_sha256": graph.digest(graph.canonical_bytes(rows[source_position - 1]))}
                 for index, source_position in enumerate(order, 1))


def initialize_context(root: Path, source: Path, *, source_sha256: str,
                       expected_runtime: dict[str, str], max_response_bytes: int = 16_777_216,
                       capture_megabytes: int = 64, parent_context: Path | None = None,
                       candidate_order: list[int] | None = None, ordering_rationale: str | None = None) -> Path:
    root = root.absolute()
    if (not root.is_dir() or root.is_symlink() or any(parent.is_symlink() for parent in root.parents)
        or any(root.iterdir())):
        raise ValueError("static acquisition requires a fresh regular empty directory")
    raw = get._read(source)
    if ((candidate_order is None) != (ordering_rationale is None)
        or ordering_rationale is not None and (not isinstance(ordering_rationale, str)
            or not ordering_rationale.strip() or len(ordering_rationale) > 1000)):
        raise ValueError("explicit static candidate ordering requires both a permutation and its rationale")
    candidates = _candidate_rows(raw, source_sha256, candidate_order)
    runtime = get.runtime_binding(expected_runtime)
    profile = {**PROFILE, "capture_limits": capture_limits(max_response_bytes, capture_megabytes)}
    inherited = []
    parent_reference = None
    if parent_context is not None:
        parent = load_context(parent_context)
        if candidate_order is None:
            candidate_order = [row["source_position"] for row in parent.candidates] + list(range(len(parent.candidates) + 1, len(candidates) + 1))
            candidates = _candidate_rows(raw, source_sha256, candidate_order)
            ordering_rationale = parent.provenance["ordering_rationale"]
        if (runtime != parent.provenance["runtime_binding"]
            or profile != _read_json(parent.root / "profile.json")
            or len(candidates) <= len(parent.candidates)
            or list(graph._source(raw, source_sha256))[:len(parent.candidates)]
                != list(graph._source(parent.source_bytes, parent.provenance["source_sha256"]))
            or candidates[:len(parent.candidates)] != parent.candidates):
            raise ValueError("static successor must append real graphs after the exact original list and rules")
        inherited = acquisition_status(parent)["terminal_prefix"]
        parent_reference = preparation.reference(parent.root / "provenance.json")
    get._write(root / "source-list.json", raw)
    get._json(root / "candidate-order.json", [row["source_position"] for row in candidates])
    get._json(root / "profile.json", profile)
    value = {"contract": CONTRACT, "data_role": preparation.ROLE, "source_sha256": source_sha256,
             "source_list": preparation.reference(root / "source-list.json"),
             "profile": preparation.reference(root / "profile.json"), "runtime_binding": runtime,
             "candidate_order": preparation.reference(root / "candidate-order.json"),
             "ordering_policy": "operator-declared-permutation-v1" if ordering_rationale is not None else "original-source-order-v1",
             "ordering_rationale": ordering_rationale,
             "candidates": list(candidates), "parent_context": parent_reference,
             "inherited_terminals": inherited, "declared_at": receipts._now(),
             "scientific_credit": False, "formal_accepted_trace_count": 0}
    path = _write(root / "provenance.json", PROVENANCE_TYPE, value)
    load_context(root)
    return path


def load_context(root: Path, *, _seen: frozenset[Path] = frozenset()) -> Context:
    root = root.absolute()
    if root in _seen:
        raise ValueError("static context successor contains a cycle")
    value = receipts._unpack(get._read(root / "provenance.json"), PROVENANCE_TYPE)
    get._exact(value, {"contract", "data_role", "source_sha256", "source_list", "profile", "runtime_binding",
                       "candidate_order", "ordering_policy", "ordering_rationale",
                       "candidates", "parent_context", "inherited_terminals", "declared_at", "scientific_credit",
                       "formal_accepted_trace_count"}, "static context")
    if (value["contract"] != CONTRACT or value["data_role"] != preparation.ROLE
        or value["scientific_credit"] is not False or type(value["formal_accepted_trace_count"]) is not int
        or value["formal_accepted_trace_count"] != 0
        or preparation.open_reference(value["source_list"]) != root / "source-list.json"
        or preparation.open_reference(value["profile"]) != root / "profile.json"
        or preparation.open_reference(value["candidate_order"]) != root / "candidate-order.json"
        or not receipts._utc(value["declared_at"]) <= receipts._utc(receipts._now())):
        raise ValueError("static context changes its prospective scientific contract")
    profile = _read_json(root / "profile.json")
    get._exact(profile, set(PROFILE) | {"capture_limits"}, "static acquisition profile")
    limits = profile["capture_limits"]
    if (not isinstance(limits, dict)
        or profile != {**PROFILE, "capture_limits": capture_limits(limits.get("max_response_bytes"), limits.get("capture_megabytes"))}):
        raise ValueError("static profile changed fixed settings or explicit capture budgets")
    get.runtime_binding(value["runtime_binding"])
    raw = get._read(root / "source-list.json")
    order = _read_json(root / "candidate-order.json")
    candidates = _candidate_rows(raw, value["source_sha256"], order)
    if (value["ordering_policy"] not in {"operator-declared-permutation-v1", "original-source-order-v1"}
        or value["ordering_policy"] == "original-source-order-v1" and (
            value["ordering_rationale"] is not None or order != list(range(1, len(candidates) + 1)))
        or value["ordering_policy"] == "operator-declared-permutation-v1" and (
            not isinstance(value["ordering_rationale"], str) or not value["ordering_rationale"].strip()
            or len(value["ordering_rationale"]) > 1000)):
        raise ValueError("static candidate ordering changed its declared rationale or default behavior")
    if list(candidates) != value["candidates"]:
        raise ValueError("static acquisition changes fixed supplied candidate order")
    context = Context(root, value, raw, candidates)
    inherited = value["inherited_terminals"]
    if not isinstance(inherited, list):
        raise ValueError("static inherited terminal prefix must be a closed list")
    if value["parent_context"] is None:
        if inherited:
            raise ValueError("initial static context invents inherited decisions")
    else:
        parent = load_context(preparation.open_reference(value["parent_context"]).parent, _seen=_seen | {root})
        if (preparation.open_reference(value["parent_context"]) != parent.root / "provenance.json"
            or profile != _read_json(parent.root / "profile.json")
            or value["runtime_binding"] != parent.provenance["runtime_binding"]
            or len(candidates) <= len(parent.candidates)
            or list(graph._source(raw, value["source_sha256"]))[:len(parent.candidates)]
                != list(graph._source(parent.source_bytes, parent.provenance["source_sha256"]))
            or candidates[:len(parent.candidates)] != parent.candidates
            or not receipts._utc(parent.provenance["declared_at"]) <= receipts._utc(value["declared_at"])
            or len(inherited) > len(parent.candidates)):
            raise ValueError("static successor changes its parent list, Source, rules or chronology")
        for position, reference in enumerate(inherited, 1):
            path = preparation.open_reference(reference)
            if path != terminal_path(parent, position):
                raise ValueError("static successor skips or rewrites an inherited terminal")
            facts = verify_terminal(path, parent)
            terminal = receipts._unpack(get._read(path), TERMINAL_TYPE)
            if (facts["candidate_id"] != candidates[position - 1]["candidate_id"]
                or receipts._utc(terminal["declared_at"]) > receipts._utc(value["declared_at"])):
                raise ValueError("static inherited decision predates neither its parent nor successor")
    return context


def identity(context: Context) -> dict[str, str]:
    # Successors retain the original ordered prefix and rules. Every appended
    # complete list and its declaration is independently bound by its context.
    while context.provenance["parent_context"] is not None:
        context = load_context(preparation.open_reference(context.provenance["parent_context"]).parent)
    return {"profile_sha256": context.provenance["profile"]["sha256"],
            "source_sha256": context.provenance["source_sha256"],
            "catalogue_sha256": context.provenance["source_sha256"],
            "selection_amendment_sha256": context.provenance["profile"]["sha256"],
            "candidate_order_sha256": graph.digest(receipts._json(list(context.candidates)))}


def terminal_path(context: Context, position: int) -> Path:
    if type(position) is not int or not 1 <= position <= len(context.candidates):
        raise ValueError("static candidate position is out of range")
    if position <= len(context.provenance["inherited_terminals"]):
        return preparation.open_reference(context.provenance["inherited_terminals"][position - 1])
    return context.root / "attempts" / f"candidate-{position:06d}" / "terminal.json"


def _get_arguments(context: Context, position: int) -> dict[str, Any]:
    if type(position) is not int or not 1 <= position <= len(context.candidates):
        raise ValueError("static candidate position is out of range")
    return {"expected_runtime": context.provenance["runtime_binding"],
            "source_sha256": context.provenance["source_sha256"],
            "domain": context.candidates[position - 1]["domain"]}


def context_limits(context: Context) -> dict[str, int]:
    return _read_json(preparation.open_reference(context.provenance["profile"]))["capture_limits"]


def _input_rejection(context: Context, position: int) -> str | None:
    domain = context.candidates[position - 1]["domain"]
    if get.class_acquisition.unsafe_catalogue_domain_reason(domain) is not None:
        return "excluded-primary-domain"
    try:
        graph.import_graph(context.source_bytes, context.provenance["source_sha256"], domain)
    except ValueError:
        return "supplied-input-has-no-complete-multi-origin-graph"
    return None


def record_input_rejection(context: Context, position: int) -> Path:
    terminal_path(context, position)
    if position <= len(context.provenance["inherited_terminals"]):
        raise ValueError("static successor cannot replace an inherited original decision")
    reason = _input_rejection(context, position)
    if reason is None:
        raise ValueError("an executable supplied graph cannot gain an invented input rejection")
    row = context.candidates[position - 1]
    payload = {"data_role": preparation.ROLE, "context": preparation.reference(context.root / "provenance.json"),
               "position": position, "candidate_id": row["candidate_id"], "domain": row["domain"],
               "source_position": row["source_position"],
               "outcome": "input-ineligible", "reason": reason, "prepared_workload": None,
               "get_evidence_root": None, "namespace": None, "declared_at": receipts._now(),
               "scientific_credit": False, "formal_accepted_trace_count": 0}
    path = _write(terminal_path(context, position), TERMINAL_TYPE, payload)
    verify_terminal(path, context)
    return path


def admit(context: Context, position: int, get_root: Path, *, policies: dict[str, str], namespace: Any = None) -> Path:
    if position <= len(context.provenance["inherited_terminals"]):
        raise ValueError("static successor cannot replace an inherited original decision")
    if _input_rejection(context, position) is not None:
        raise ValueError("static input is not executable under the declared public multi-origin policy")
    arguments = _get_arguments(context, position)
    manifest = preparation.build_preparation(get_root, **arguments, policies=policies, namespace=namespace)
    proof = preparation.reopen_get(get_root, **arguments, namespace=namespace)
    if (proof["context"] != preparation.reference(context.root / "provenance.json")
        or receipts._utc(proof["declared_at"]) < receipts._utc(context.provenance["declared_at"])):
        raise ValueError("static GET began before this prospective static acquisition declaration")
    row = context.candidates[position - 1]
    directory = terminal_path(context, position).parent
    directory.mkdir(parents=True, exist_ok=True)
    workload = directory / (row["candidate_id"] + ".json")
    get._json(workload, manifest)
    payload = {"data_role": preparation.ROLE, "context": preparation.reference(context.root / "provenance.json"),
               "position": position, "candidate_id": row["candidate_id"], "domain": row["domain"],
               "source_position": row["source_position"],
               "outcome": "admitted", "reason": None, "prepared_workload": preparation.reference(workload),
               "get_evidence_root": str(get_root.absolute()), "namespace": namespace,
               "declared_at": receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0}
    path = _write(terminal_path(context, position), TERMINAL_TYPE, payload)
    verify_terminal(path, context)
    return path


def record_get_deferral(context: Context, position: int, get_root: Path, *, namespace: Any = None) -> Path:
    from .supplied_static_bootstrap_get import failure_proof
    terminal_path(context, position)
    if position <= len(context.provenance["inherited_terminals"]):
        raise ValueError("static successor cannot replace an inherited original decision")
    failure_proof(get_root, **_get_arguments(context, position), namespace=namespace)
    if _read_json(get_root / "declaration.json")["context"] != preparation.reference(context.root / "provenance.json"):
        raise ValueError("static failed GET belongs to another declared context")
    row = context.candidates[position - 1]
    payload = {"data_role": preparation.ROLE, "context": preparation.reference(context.root / "provenance.json"),
               "position": position, "candidate_id": row["candidate_id"], "domain": row["domain"],
               "source_position": row["source_position"],
               "outcome": "operational-deferred", "reason": "actual-ordinary-native-get-failure",
               "prepared_workload": None, "get_evidence_root": str(get_root.absolute()), "namespace": namespace,
               "declared_at": receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0}
    path = _write(terminal_path(context, position), TERMINAL_TYPE, payload)
    verify_terminal(path, context)
    return path


def verify_terminal(path: Path, context: Context) -> dict[str, Any]:
    value = receipts._unpack(get._read(path), TERMINAL_TYPE)
    get._exact(value, {"data_role", "context", "position", "candidate_id", "domain", "outcome", "reason",
                       "source_position",
                       "prepared_workload", "get_evidence_root", "namespace", "declared_at", "scientific_credit",
                       "formal_accepted_trace_count"}, "static terminal")
    position = value["position"]
    expected = terminal_path(context, position)
    if position <= len(context.provenance["inherited_terminals"]):
        if path.absolute() != expected:
            raise ValueError("static inherited decision changes its immutable original path")
        parent = load_context(preparation.open_reference(context.provenance["parent_context"]).parent)
        return verify_terminal(path, parent)
    row = context.candidates[position - 1]
    if (path.absolute() != expected or value["data_role"] != preparation.ROLE
        or preparation.open_reference(value["context"]) != context.root / "provenance.json"
        or value["candidate_id"] != row["candidate_id"] or value["domain"] != row["domain"]
        or type(value["source_position"]) is not int or value["source_position"] != row["source_position"]
        or value["scientific_credit"] is not False or type(value["formal_accepted_trace_count"]) is not int
        or value["formal_accepted_trace_count"] != 0
        or not receipts._utc(context.provenance["declared_at"]) <= receipts._utc(value["declared_at"]) <= receipts._utc(receipts._now())):
        raise ValueError("static terminal changes its original context, order, role or chronology")
    facts = {"candidate_id": row["candidate_id"], "domain": row["domain"], "outcome": value["outcome"],
             "data_role": preparation.ROLE, "source_position": row["source_position"], "admission": None}
    if value["outcome"] == "input-ineligible":
        if (value["reason"] != _input_rejection(context, position) or value["reason"] is None
            or any(value[key] is not None for key in ("prepared_workload", "get_evidence_root", "namespace"))):
            raise ValueError("static input rejection has no exact source-list reason")
    elif value["outcome"] == "admitted":
        workload = preparation.open_reference(value["prepared_workload"])
        if workload != expected.with_name(row["candidate_id"] + ".json") or value["reason"] is not None:
            raise ValueError("static admission changes its prepared workload namespace")
        manifest = _read_json(workload)
        proof = preparation.validate_static_preparation(manifest["preparation"], manifest["resources"])
        evidence = manifest["preparation"]["static_get_evidence"]
        if (proof["context"] != value["context"]
            or evidence["root"] != value["get_evidence_root"] or evidence["namespace"] != value["namespace"]
            or {"expected_runtime": evidence["runtime_binding"], "source_sha256": evidence["source_sha256"],
                "domain": evidence["domain"]} != _get_arguments(context, position)
            or not receipts._utc(context.provenance["declared_at"]) <= receipts._utc(proof["declared_at"])
                <= receipts._utc(proof["completed_at"]) <= receipts._utc(value["declared_at"])):
            raise ValueError("static admission changed complete GET source/runtime/graph or dates")
        facts["admission"] = {"prepared_workload_sha256": value["prepared_workload"]["sha256"],
                              "full_resource_graph_sha256": graph.digest(graph.canonical_bytes(manifest["resources"])),
                              "complete_get_proof_sha256": evidence["proof"]["sha256"]}
    elif value["outcome"] == "operational-deferred":
        from .supplied_static_bootstrap_get import failure_proof
        if value["prepared_workload"] is not None or value["reason"] != "actual-ordinary-native-get-failure":
            raise ValueError("static operational deferral cannot gain preparation or scientific rejection")
        failure = failure_proof(Path(value["get_evidence_root"]), **_get_arguments(context, position), namespace=value["namespace"])
        if (_read_json(Path(value["get_evidence_root"]) / "declaration.json")["context"] != value["context"]
            or receipts._utc(failure["completed_at"]) > receipts._utc(value["declared_at"])):
            raise ValueError("static deferral was recorded before its actual failure")
    else:
        raise ValueError("static terminal outcome is not a declared input or complete-GET decision")
    return facts


def prepared_workload(context: Context, terminal: Path) -> tuple[Path, dict[str, Any]]:
    verify_terminal(terminal, context)
    value = receipts._unpack(get._read(terminal), TERMINAL_TYPE)
    if value["outcome"] != "admitted":
        raise ValueError("static terminal is not admitted")
    path = preparation.open_reference(value["prepared_workload"])
    return path, _read_json(path)


def acquisition_status(context: Context) -> dict[str, Any]:
    terminals = []
    for position in range(1, len(context.candidates) + 1):
        path = terminal_path(context, position)
        if not path.exists():
            break
        verify_terminal(path, context)
        terminals.append(preparation.reference(path))
    return {"terminal_prefix": terminals, "scientific_credit": False, "formal_accepted_trace_count": 0}


def roots(context: Context) -> list[Path]:
    result = {context.root}
    ancestor = context
    while ancestor.provenance["parent_context"] is not None:
        ancestor = load_context(preparation.open_reference(ancestor.provenance["parent_context"]).parent)
        result.add(ancestor.root)
    for reference in acquisition_status(context)["terminal_prefix"]:
        terminal = preparation.open_reference(reference)
        value = receipts._unpack(get._read(terminal), TERMINAL_TYPE)
        if value["outcome"] == "admitted":
            manifest = _read_json(preparation.open_reference(value["prepared_workload"]))
            result.update(preparation.preparation_roots(manifest["preparation"]))
    return sorted(result)
