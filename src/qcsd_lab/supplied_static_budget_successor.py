"""Prospective response-budget epochs over an unchanged supplied catalogue.

The original producer still performs, proves and accounts each new GET in an
ordinary fresh static context. This adapter preserves the prior ordered prefix
and failed attempt, and explicitly wraps new capture inputs with their budget.
No old context, validator, Native binary, proof or class gains new authority.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import supplied_static_admission as static
from . import supplied_static_bootstrap_get as bootstrap
from . import supplied_static_get as get
from . import supplied_static_graph as graph
from . import supplied_static_preparation as prep
from . import whole_graph_input as refs
from . import whole_graph_supplement as whole

CONTEXT_TYPE = "qcsd-same-catalogue-static-response-budget-context-v1"
CONTRACT = "retained-static-prefix-and-attempt-with-prospective-per-class-response-budget-v1"
TERMINAL_TYPE = "qcsd-static-response-budget-terminal-v1"
ROLE = "supplied-static-prospective-response-budget-preparation-v1"
FIELD = "static_response_budget_successor"
EVIDENCE_TYPE = "qcsd-static-response-budget-capture-evidence-v1"
RESPONSE_BYTES = 64 * 1024 * 1024
RECORDING_MEGABYTES = 256
TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class Context:
    root: Path
    provenance: dict[str, Any]
    original: static.Context
    active: static.Context
    candidates: tuple[dict[str, Any], ...]


def is_context(root: Path) -> bool:
    return get._load(get._read(root / "provenance.json")).get("receipt_type") == CONTEXT_TYPE


def is_budget(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("data_role") == ROLE


def _old_limit_attempt(root: Path, context: static.Context, position: int) -> dict:
    """Authenticate the incomplete attempt; this grants no rejection/GET credit."""
    declaration = get._load(get._read(root / "declaration.json"))
    row = context.candidates[position - 1]
    expected = context.provenance["runtime_binding"]
    neutral, binding, primary, full = bootstrap._inputs(context.source_bytes,
        context.provenance["source_sha256"], row["domain"])
    if (declaration.get("context") != prep.reference(context.root / "provenance.json")
            or declaration.get("record_type") != bootstrap.PROOF_TYPE
            or declaration.get("runtime_binding") != expected
            or declaration.get("domain") != row["domain"]
            or type(declaration.get("candidate_queue_position")) is not int
            or declaration["candidate_queue_position"] != position
            or declaration.get("candidate_source_position") != row["source_position"]
            or declaration.get("source_sha256") != context.provenance["source_sha256"]
            or declaration.get("max_response_bytes") != static.context_limits(context)["max_response_bytes"]
            or declaration.get("timeout_seconds") != TIMEOUT_SECONDS
            or declaration.get("scientific_credit") is not False
            or declaration.get("site_credit") != 0 or declaration.get("formal_accepted_trace_count") != 0
            or get._load(get._read(root / "neutral-input.json")) != neutral
            or get._load(get._read(root / "input-binding.json")) != binding
            or get._load(get._read(root / "bootstrap/native-input.json")) != primary
            or get._load(get._read(root / "native-input.json")) != full
            or (root / "full-get-proof.json").exists()):
        raise ValueError("budget successor does not retain the exact unaccounted static attempt")
    get._runtime(get._load(get._read(root / "runtime.json")), expected)
    bound_declaration = {**declaration, "_raw_sha256": graph.digest(get._read(root / "declaration.json"))}
    # The primary phase is genuinely complete and uses the unchanged verifier.
    # A response-limited full phase retains its partial outcome; authenticate
    # the same process contract without inventing a complete full GET proof.
    bootstrap._step(root / "bootstrap", bound_declaration, primary,
        policy=bootstrap.STRICT_POLICY, execution=root / "bootstrap")
    for child in (root / "bootstrap", root):
        completed = get._exact(get._load(get._read(child / "native-completed.json")), {
            "schema_version", "returncode", "timed_out", "completed_at", "elapsed_ns", "stdout_sha256", "stderr_sha256",
            "outputs", "client_sha256", "source_manifest_sha256"}, "retained completed process")
        started = get._exact(get._load(get._read(child / "native-started.json")), {
            "schema_version", "command", "environment", "started_at", "declaration_sha256", "client_sha256"}, "retained started process")
        phase_policy = bootstrap.STRICT_POLICY if child == root / "bootstrap" else get.RESPONSE_POLICY
        if (type(started["schema_version"]) is not int or started["schema_version"] != 1
                or started["command"] != bootstrap._command(child, declaration["max_response_bytes"], TIMEOUT_SECONDS, phase_policy)
                or started["environment"] != {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": expected["image_digest"],
                    "QCSD_LAB_SOURCE_METADATA": str(get.util.DEFAULT_SOURCE_METADATA)}
                or type(completed["schema_version"]) is not int or completed["schema_version"] != 1
                or get._number(completed["elapsed_ns"], "retained elapsed") < 1
                or type(completed.get("returncode")) is not int or completed["returncode"] != 0
                or completed.get("timed_out") is not False
                or completed.get("client_sha256") != expected["client_sha256"]
                or completed.get("source_manifest_sha256") != expected["source_manifest_sha256"]
                or completed.get("stdout_sha256") != graph.digest(get._read(child / "native.stdout.log"))
                or completed.get("stderr_sha256") != graph.digest(get._read(child / "native.stderr.log"))
                or completed.get("outputs") != {name: graph.digest(get._read(child / "native" / name)) for name in get.FILES}
                or started.get("declaration_sha256") != graph.digest(get._read(root / "declaration.json"))
                or started.get("client_sha256") != expected["client_sha256"]
                or not get._time(declaration["declared_at"]) <= get._time(started["started_at"]) < get._time(completed["completed_at"])):
            raise ValueError("retained response-limit attempt lacks its original closed Native outputs")
    if get._time(get._load(get._read(root / "bootstrap/native-completed.json"))["completed_at"]) > get._time(
            get._load(get._read(root / "native-started.json"))["started_at"]):
        raise ValueError("retained full GET began before its completed primary bootstrap")
    run = get._load(get._read(root / "native/run.json"))
    limited = [row for row in run.get("responses", []) if row.get("outcome") == "response_limit"]
    if (run.get("completion_status") != "partial" or run.get("error") is not None
            or run.get("max_response_bytes") != declaration["max_response_bytes"]
            or run.get("method") != "GET" or run.get("request_policy") != "as-defined"
            or run.get("migration_commit") != expected["native_commit"]
            or run.get("workload_hash_sha256") != graph.digest(get._read(root / "native-input.json"))
            or run.get("application_response_policy") != get.RESPONSE_POLICY
            or len(run.get("responses", [])) != len(full["resources"]) or not limited
            or any(type(row.get("bytes")) is not int or row["bytes"] <= declaration["max_response_bytes"] for row in limited)):
        raise ValueError("retained attempt is not an authenticated response-budget partial run")
    return {"root": str(root), "files": whole._tree_files(root), "position": position,
        "completed_at": get._load(get._read(root / "native-completed.json"))["completed_at"],
        "response_limit_resource_ids": [row["resource_id"] for row in limited],
        "outcome": "retained-incomplete-budget-attempt-no-site-decision", **refs.ZERO}


def initialize_context(root: Path, *, original_context: Path, retained_attempt: Path,
                       retained_operations: list[Path] = ()) -> Path:
    original = static.load_context(original_context)
    status = static.acquisition_status(original)
    inherited = status["terminal_prefix"]
    position = len(inherited) + 1
    if position > len(original.candidates):
        raise ValueError("a completed static queue needs no response-budget retry")
    old_limits = static.context_limits(original)
    if old_limits["max_response_bytes"] >= RESPONSE_BYTES or old_limits["timeout_seconds"] != TIMEOUT_SECONDS:
        raise ValueError("budget successor requires a genuine smaller-budget unchanged-deadline epoch")
    retained = _old_limit_attempt(retained_attempt.absolute(), original, position)
    root = root.absolute()
    for protected in [original.root, retained_attempt, *retained_operations]:
        get.util.require_disjoint_path(root, [protected], label="static budget successor")
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    active_root = root / "prospective-get-context"
    active_root.mkdir(mode=0o700)
    # The existing public constructor, unchanged. No old decisions are copied
    # into this context or reinterpreted at a different capture budget.
    static.initialize_context(active_root, original.root / "source-list.json",
        source_sha256=original.provenance["source_sha256"], expected_runtime=original.provenance["runtime_binding"],
        max_response_bytes=RESPONSE_BYTES, capture_megabytes=RECORDING_MEGABYTES,
        candidate_order=[row["source_position"] for row in original.candidates],
        ordering_rationale=original.provenance["ordering_rationale"] or "Same complete catalogue/order; prospective response-budget retry.")
    payload = {"contract": CONTRACT, "data_role": ROLE,
        "original_context": prep.reference(original.root / "provenance.json"),
        "prospective_context": prep.reference(active_root / "provenance.json"),
        "inherited_terminals": inherited, "first_prospective_position": position,
        "retained_attempt": retained, "retained_operations": [refs.reference(path) for path in retained_operations],
        "original_identity": static.identity(original), "adapter_source": refs.reference(Path(__file__)),
        "capture_limits": static.capture_limits(RESPONSE_BYTES, RECORDING_MEGABYTES),
        "declared_at": static.receipts._now(), **refs.ZERO}
    path = static._write(root / "provenance.json", CONTEXT_TYPE, payload)
    load_context(root)
    return path


def load_context(root: Path) -> Context:
    root = root.absolute()
    value = static.receipts._unpack(get._read(root / "provenance.json"), CONTEXT_TYPE)
    get._exact(value, {"contract", "data_role", "original_context", "prospective_context", "inherited_terminals",
        "first_prospective_position", "retained_attempt", "retained_operations", "original_identity", "adapter_source",
        "capture_limits", "declared_at", *refs.ZERO}, "static budget successor")
    if (value["contract"] != CONTRACT or value["data_role"] != ROLE or not refs.zero(value)
            or not get._time(value["declared_at"]) <= get._time(static.receipts._now())
            or graph.digest(get._read(refs.reopen(value["adapter_source"]))) != graph.digest(get._read(Path(__file__)))):
        raise ValueError("budget successor changed its prospective adapter authority")
    original = static.load_context(prep.open_reference(value["original_context"]).parent)
    active = static.load_context(prep.open_reference(value["prospective_context"]).parent)
    first = value["first_prospective_position"]
    if (type(first) is not int or not 1 <= first <= len(original.candidates)
            or active.root != root / "prospective-get-context"
            or active.source_bytes != original.source_bytes or active.candidates != original.candidates
            or active.provenance["runtime_binding"] != original.provenance["runtime_binding"]
            or active.provenance["parent_context"] is not None or active.provenance["inherited_terminals"] != []
            or value["original_identity"] != static.identity(original)
            or value["capture_limits"] != static.capture_limits(RESPONSE_BYTES, RECORDING_MEGABYTES)
            or static.context_limits(active) != value["capture_limits"]
            or not isinstance(value["inherited_terminals"], list) or len(value["inherited_terminals"]) != first - 1
            or not get._time(original.provenance["declared_at"]) <= get._time(active.provenance["declared_at"]) <= get._time(value["declared_at"])):
        raise ValueError("budget successor changed catalogue, prefix, runtime or explicit capture limits")
    for position, ref in enumerate(value["inherited_terminals"], 1):
        path = prep.open_reference(ref)
        if path != static.terminal_path(original, position):
            raise ValueError("budget successor skips or replaces an earlier terminal")
        static.verify_terminal(path, original)
        terminal = static.receipts._unpack(get._read(path), static.TERMINAL_TYPE)
        if get._time(terminal["declared_at"]) > get._time(value["declared_at"]):
            raise ValueError("budget successor inherited a later unmeasured decision")
    retained = value["retained_attempt"]
    if (_old_limit_attempt(Path(retained["root"]), original, first) != retained
            or get._time(retained["completed_at"]) > get._time(active.provenance["declared_at"])):
        raise ValueError("budget successor rewrites its old failed attempt or chronology")
    for ref in value["retained_operations"]:
        refs.reopen(ref)
    return Context(root, value, original, active, original.candidates)


def identity(context: Context) -> dict[str, str]:
    return dict(context.provenance["original_identity"])


def context_limits(context: Context) -> dict[str, int]:
    # The old study policy retains its old epoch. Each new class/plan instead
    # binds its authenticated 64 MiB preparation via selected_capture_limits.
    return static.context_limits(context.original)


def terminal_path(context: Context, position: int) -> Path:
    if type(position) is not int or not 1 <= position <= len(context.candidates):
        raise ValueError("budget successor position is out of range")
    if position < context.provenance["first_prospective_position"]:
        return prep.open_reference(context.provenance["inherited_terminals"][position - 1])
    return context.root / "attempts" / f"candidate-{position:06d}" / "terminal.json"


def _wrap(manifest: dict, evidence: dict) -> dict:
    result = deepcopy(manifest)
    result["preparation"].update(data_role=ROLE, **{FIELD: deepcopy(evidence)})
    return result


def account_terminal(context: Context, position: int) -> Path:
    if position != acquisition_status(context)["next_candidate_position"]:
        raise ValueError("budget successor cannot skip/repeat an ordered position")
    original_terminal = static.terminal_path(context.active, position)
    facts = static.verify_terminal(original_terminal, context.active)
    record = static.receipts._unpack(get._read(original_terminal), static.TERMINAL_TYPE)
    output = terminal_path(context, position)
    workload_ref = None
    if facts["outcome"] == "admitted":
        original_path, manifest = static.prepared_workload(context.active, original_terminal)
        evidence = {"schema_version": 1, "record_type": EVIDENCE_TYPE,
            "context": prep.reference(context.root / "provenance.json"), "position": position,
            "original_terminal": prep.reference(original_terminal), "original_manifest": prep.reference(original_path),
            "proof": manifest["preparation"]["static_get_evidence"]["proof"],
            "capture_limits": dict(context.provenance["capture_limits"])}
        path = output.parent / original_path.name
        get._json(path, _wrap(manifest, evidence))
        workload_ref = prep.reference(path)
    payload = {"context": prep.reference(context.root / "provenance.json"), "position": position,
        "candidate_id": facts["candidate_id"], "domain": facts["domain"], "outcome": facts["outcome"],
        "original_terminal": prep.reference(original_terminal), "prepared_workload": workload_ref,
        "capture_limits": dict(context.provenance["capture_limits"]),
        "declared_at": static.receipts._now(), **refs.ZERO}
    path = static._write(output, TERMINAL_TYPE, payload)
    verify_terminal(path, context)
    return path


def validate_preparation(value: Mapping[str, Any], resources: list[dict]) -> dict:
    if not is_budget(value):
        raise ValueError("static budget preparation role is absent")
    evidence = get._exact(value.get(FIELD), {"schema_version", "record_type", "context", "position", "original_terminal",
        "original_manifest", "proof", "capture_limits"}, "static budget capture evidence")
    if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1 or evidence["record_type"] != EVIDENCE_TYPE:
        raise ValueError("static budget preparation changed its typed authority")
    context = load_context(prep.open_reference(evidence["context"]).parent)
    position = evidence["position"]
    if (type(position) is not int or not context.provenance["first_prospective_position"] <= position <= len(context.candidates)
            or prep.open_reference(evidence["original_terminal"]) != static.terminal_path(context.active, position)):
        raise ValueError("budget preparation changed original candidate/terminal identity")
    path, original = static.prepared_workload(context.active, prep.open_reference(evidence["original_terminal"]))
    proof = prep.validate_static_preparation(original["preparation"], original["resources"])
    if (prep.open_reference(evidence["original_manifest"]) != path
            or evidence["capture_limits"] != context.provenance["capture_limits"]
            or evidence["proof"] != original["preparation"]["static_get_evidence"]["proof"]
            or original["preparation"]["max_response_bytes"] != RESPONSE_BYTES
            or original["preparation"]["timeout_seconds"] != TIMEOUT_SECONDS
            or _wrap(original, evidence) != {"preparation": value, "resources": resources}):
        raise ValueError("budget capture input changed complete graph, raw GET or five-mode response limits")
    return proof


def verify_terminal(path: Path, context: Context) -> dict:
    first = context.provenance["first_prospective_position"]
    for position, ref in enumerate(context.provenance["inherited_terminals"], 1):
        if path.absolute() == prep.open_reference(ref):
            return static.verify_terminal(path, context.original)
    value = static.receipts._unpack(get._read(path), TERMINAL_TYPE)
    get._exact(value, {"context", "position", "candidate_id", "domain", "outcome", "original_terminal", "prepared_workload",
        "capture_limits", "declared_at", *refs.ZERO}, "static budget terminal")
    position = value["position"]
    if (type(position) is not int or not first <= position <= len(context.candidates)
            or path.absolute() != terminal_path(context, position)
            or value["context"] != prep.reference(context.root / "provenance.json")
            or value["capture_limits"] != context.provenance["capture_limits"] or not refs.zero(value)
            or not get._time(context.provenance["declared_at"]) <= get._time(value["declared_at"]) <= get._time(static.receipts._now())
            or prep.open_reference(value["original_terminal"]) != static.terminal_path(context.active, position)):
        raise ValueError("budget terminal changed its ordered prospective epoch")
    facts = static.verify_terminal(prep.open_reference(value["original_terminal"]), context.active)
    if any(value[key] != facts[key] for key in ("candidate_id", "domain", "outcome")):
        raise ValueError("budget terminal relabels an original producer outcome")
    if facts["outcome"] == "admitted":
        manifest = get._load(get._read(prep.open_reference(value["prepared_workload"])))
        validate_preparation(manifest["preparation"], manifest["resources"])
    elif value["prepared_workload"] is not None:
        raise ValueError("a nonadmitted budget position invents a capture input")
    return facts


def prepared_workload(context: Context, terminal: Path) -> tuple[Path, dict]:
    verify_terminal(terminal, context)
    if terminal in [prep.open_reference(ref) for ref in context.provenance["inherited_terminals"]]:
        return static.prepared_workload(context.original, terminal)
    value = static.receipts._unpack(get._read(terminal), TERMINAL_TYPE)
    if value["outcome"] != "admitted":
        raise ValueError("budget position is not admitted")
    path = prep.open_reference(value["prepared_workload"])
    return path, get._load(get._read(path))


def acquisition_status(context: Context) -> dict:
    terminals = []
    counts = {"admitted": 0, "operational-deferred": 0, "input-ineligible": 0}
    for position in range(1, len(context.candidates) + 1):
        path = terminal_path(context, position)
        if not path.exists():
            break
        facts = verify_terminal(path, context)
        counts[facts["outcome"]] += 1
        terminals.append(prep.reference(path))
    return {"terminal_prefix": terminals, "terminal_count": len(terminals),
        "next_candidate_position": len(terminals) + 1 if len(terminals) < len(context.candidates) else None,
        "candidate_count": len(context.candidates), **counts, **refs.ZERO}


def preparation_inputs(value: Mapping[str, Any]) -> tuple[set[Path], set[Path]]:
    evidence = value[FIELD]
    context = load_context(prep.open_reference(evidence["context"]).parent)
    files = {prep.open_reference(evidence[key]) for key in ("context", "original_terminal", "original_manifest", "proof")}
    files.add(refs.reopen(context.provenance["adapter_source"]))
    files.update(refs.reopen(ref) for ref in context.provenance["retained_operations"])
    ancestors = [context.active]
    current = context.original
    while True:
        ancestors.append(current)
        if current.provenance["parent_context"] is None:
            break
        current = static.load_context(prep.open_reference(current.provenance["parent_context"]).parent)
    for current in ancestors:
        files.update(current.root / name for name in ("provenance.json", "profile.json", "source-list.json", "candidate-order.json"))
    files.update(Path(ref["path"]) for ref in context.provenance["retained_attempt"]["files"].values())
    trees = set()
    for current, terminals in ((context.original, context.provenance["inherited_terminals"]),
                              (context.active, [evidence["original_terminal"]])):
        for ref in terminals:
            terminal = prep.open_reference(ref)
            files.add(terminal)
            record = static.receipts._unpack(get._read(terminal), static.TERMINAL_TYPE)
            if record["prepared_workload"] is not None:
                files.add(prep.open_reference(record["prepared_workload"]))
            if record["get_evidence_root"] is not None:
                trees.add(Path(record["get_evidence_root"]))
            if record["namespace"] is not None:
                files.update(prep.open_reference(record["namespace"][key]) for key in
                    ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    return files, trees


def preparation_roots(value: Mapping[str, Any]) -> list[Path]:
    files, trees = preparation_inputs(value)
    return sorted(trees | {path.parent for path in files})


def roots(context: Context) -> list[Path]:
    # Transport includes complete inherited/deferral evidence and exact Source,
    # while immutable selectors above never watch shared transport parents.
    roots = {context.root, context.active.root}
    current = context.original
    while True:
        roots.add(current.root)
        if current.provenance["parent_context"] is None:
            break
        current = static.load_context(prep.open_reference(current.provenance["parent_context"]).parent)
    roots.update(Path(ref["path"]).parent for ref in context.provenance["retained_attempt"]["files"].values())
    roots.update(refs.reopen(ref).parent for ref in context.provenance["retained_operations"])
    roots.add(refs.reopen(context.provenance["adapter_source"]).parent.parent)
    for ref in context.provenance["inherited_terminals"]:
        terminal = prep.open_reference(ref)
        roots.add(terminal.parent)
        record = static.receipts._unpack(get._read(terminal), static.TERMINAL_TYPE)
        if record["get_evidence_root"] is not None:
            roots.add(Path(record["get_evidence_root"]))
        if record["namespace"] is not None:
            roots.update(prep.open_reference(record["namespace"][key]).parent for key in
                ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    return sorted(roots)


def selected_capture_limits(manifests: list[dict], original_limits: Mapping[str, int]) -> dict[str, int]:
    budgets = []
    for manifest in manifests:
        declared = manifest["preparation"]
        if is_budget(declared):
            validate_preparation(declared, manifest["resources"])
            limits = declared[FIELD]["capture_limits"]
        else:
            # Other typed epochs retain their own existing study contract.
            limits = dict(original_limits)
            if declared.get("max_response_bytes") != limits["max_response_bytes"]:
                raise ValueError("an unrecognized class cannot select a different response budget")
        budgets.append(dict(limits))
    if not budgets or any(limits != budgets[0] for limits in budgets):
        raise ValueError("enroll response-budget classes in homogeneous one-to-five-site capture groups")
    return budgets[0]
