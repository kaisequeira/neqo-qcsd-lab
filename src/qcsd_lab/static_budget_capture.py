"""Explicit capture/enrollment selectors for prospective response-budget classes.

The original GET, budget retry and supplementary whole-graph authorities remain
separate. A mixed context only selects their already authenticated terminal
paths in the unchanged original-then-appended order; it produces no GET proof.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import supplied_static_budget_successor as budget
from . import supplied_static_admission as static
from . import supplied_static_preparation as prep
from . import supplied_static_graph as graph
from . import supplied_static_get as get
from . import whole_graph_input as refs
from . import whole_graph_supplement as whole

CONTEXT_TYPE = "qcsd-static-budget-and-whole-graph-enrollment-context-v1"
CONTRACT = "unchanged-original-budget-prefix-then-declared-whole-graph-tail-v1"


@dataclass(frozen=True)
class Context:
    root: Path
    provenance: dict[str, Any]
    budget: budget.Context
    supplement: whole.Context
    candidates: tuple[dict[str, Any], ...]


def is_context(root: Path) -> bool:
    return get._load(get._read(root / "provenance.json")).get("receipt_type") == CONTEXT_TYPE


def initialize_context(root: Path, *, budget_context: Path, supplement_context: Path,
                       parent_context: Path | None = None) -> Path:
    head = budget.load_context(budget_context)
    tail = whole.load_context(supplement_context)
    if tail.original.root != head.original.root or tail.original.candidates != head.candidates:
        raise ValueError("mixed budget enrollment changed the original full catalogue/order")
    inherited, parent_ref = [], None
    if parent_context is not None:
        parent = load_context(parent_context)
        if (parent.budget.root != head.root or len(tail.candidates) <= len(parent.candidates)
                or tail.candidates[:len(parent.candidates)] != parent.candidates
                or not _supplement_descends(tail, parent.supplement.root)):
            raise ValueError("mixed budget successor must append an authenticated supplement descendant")
        inherited = acquisition_status(parent)["terminal_prefix"]
        parent_ref = prep.reference(parent.root / "provenance.json")
    root = root.absolute()
    for protected in (head.root, tail.root, *([parent_context] if parent_context else [])):
        get.util.require_disjoint_path(root, [protected], label="mixed budget enrollment context")
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    payload = {"contract": CONTRACT, "budget_context": prep.reference(head.root / "provenance.json"),
        "supplement_context": prep.reference(tail.root / "provenance.json"),
        "original_identity": budget.identity(head), "candidates": list(tail.candidates),
        "parent_context": parent_ref, "inherited_terminals": inherited,
        "selector_source": refs.reference(Path(__file__)), "declared_at": static.receipts._now(), **refs.ZERO}
    path = static._write(root / "provenance.json", CONTEXT_TYPE, payload)
    load_context(root)
    return path


def _supplement_descends(context: whole.Context, ancestor: Path) -> bool:
    while context.root != ancestor:
        ref = context.provenance["parent_context"]
        if ref is None:
            return False
        context = whole.load_context(prep.open_reference(ref).parent)
    return True


def load_context(root: Path, *, _seen: frozenset[Path] = frozenset()) -> Context:
    root = root.absolute()
    if root in _seen:
        raise ValueError("mixed budget enrollment context contains a cycle")
    value = static.receipts._unpack(get._read(root / "provenance.json"), CONTEXT_TYPE)
    get._exact(value, {"contract", "budget_context", "supplement_context", "original_identity", "candidates",
        "parent_context", "inherited_terminals", "selector_source", "declared_at", *refs.ZERO}, "mixed budget context")
    if (value["contract"] != CONTRACT or not refs.zero(value)
            or graph.digest(get._read(refs.reopen(value["selector_source"]))) != graph.digest(get._read(Path(__file__)))
            or get._time(value["declared_at"]) > get._time(static.receipts._now())):
        raise ValueError("mixed budget selector changed its Source, time or zero-credit authority")
    head = budget.load_context(prep.open_reference(value["budget_context"]).parent)
    tail = whole.load_context(prep.open_reference(value["supplement_context"]).parent)
    if (tail.original.root != head.original.root or tail.original.candidates != head.candidates
            or list(tail.candidates) != value["candidates"] or value["original_identity"] != budget.identity(head)
            or whole.identity(tail) != budget.identity(head)
            or not get._time(head.provenance["declared_at"]) <= get._time(value["declared_at"])
            or not get._time(tail.provenance["declared_at"]) <= get._time(value["declared_at"])):
        raise ValueError("mixed budget selector changed catalogue, original identity, order or declared inputs")
    context = Context(root, value, head, tail, tail.candidates)
    inherited = value["inherited_terminals"]
    if not isinstance(inherited, list) or len(inherited) > len(context.candidates):
        raise ValueError("mixed budget inherited terminals are not a finite prefix")
    if value["parent_context"] is None:
        if inherited:
            raise ValueError("initial mixed budget context invents inherited decisions")
    else:
        parent = load_context(prep.open_reference(value["parent_context"]).parent, _seen=_seen | {root})
        if (parent.budget.root != head.root or len(tail.candidates) <= len(parent.candidates)
                or tail.candidates[:len(parent.candidates)] != parent.candidates
                or not _supplement_descends(tail, parent.supplement.root)
                or get._time(parent.provenance["declared_at"]) > get._time(value["declared_at"])):
            raise ValueError("mixed budget successor replaces original prefix or supplement authority")
        for position, ref in enumerate(inherited, 1):
            path = prep.open_reference(ref)
            if path != terminal_path(parent, position):
                raise ValueError("mixed budget successor skips an immutable prior terminal")
            verify_terminal(path, parent)
            terminal = get._load(get._read(path))
            payload = static.receipts._unpack(get._read(path), terminal["receipt_type"])
            if get._time(payload["declared_at"]) > get._time(value["declared_at"]):
                raise ValueError("mixed budget successor inherited a later terminal")
    return context


def _head(context: Context | budget.Context) -> budget.Context:
    return context.budget if isinstance(context, Context) else context


def identity(context: Context | budget.Context) -> dict[str, str]:
    return budget.identity(_head(context))


def context_limits(context: Context | budget.Context) -> dict[str, int]:
    return budget.context_limits(_head(context))


def terminal_path(context: Context | budget.Context, position: int) -> Path:
    if type(position) is not int or not 1 <= position <= len(context.candidates):
        raise ValueError("budget capture position is outside the exact original/appended queue")
    head = _head(context)
    if position <= len(head.candidates):
        return budget.terminal_path(head, position)
    return whole.terminal_path(context.supplement, position)


def _position(context: Context | budget.Context, path: Path) -> int:
    kind = get._load(get._read(path))["receipt_type"]
    if kind not in {static.TERMINAL_TYPE, budget.TERMINAL_TYPE, whole.TERMINAL_TYPE}:
        raise ValueError("budget capture terminal has an unknown data authority")
    value = static.receipts._unpack(get._read(path), kind)
    position = value["position"]
    if path.absolute() != terminal_path(context, position):
        raise ValueError("budget capture terminal changed original immutable namespace")
    return position


def verify_terminal(path: Path, context: Context | budget.Context) -> dict:
    position = _position(context, path)
    head = _head(context)
    if position > len(head.candidates):
        return whole.verify_terminal(path, context.supplement)
    facts = budget.verify_terminal(path, head)
    if facts["outcome"] == "admitted" and position >= head.provenance["first_prospective_position"]:
        # The new class uses the authenticated wrapper bytes. The underlying
        # original GET proof keeps its old Source/client/runtime fields intact.
        payload = static.receipts._unpack(get._read(path), budget.TERMINAL_TYPE)
        workload = prep.open_reference(payload["prepared_workload"])
        facts = deepcopy(facts)
        facts["admission"]["prepared_workload_sha256"] = graph.digest(get._read(workload))
    return facts


def prepared_workload(context: Context | budget.Context, path: Path) -> tuple[Path, dict]:
    position = _position(context, path)
    head = _head(context)
    return (budget.prepared_workload(head, path) if position <= len(head.candidates)
            else whole.prepared_workload(context.supplement, path))


def account_terminal(context: budget.Context, position: int) -> Path:
    """Claim the wrapper directory before the unchanged Core writes its file.

    Core002 remains bound to existing budget declarations. Its manifest writer
    is create-only and expects this parent to exist. Reopen the public child
    terminal first; a failed or absent GET cannot create an admitted wrapper.
    """
    from .static_evidence_transport import _path
    context = budget.load_context(context.root)
    if position != budget.acquisition_status(context)["next_candidate_position"]:
        raise ValueError("budget capture account cannot skip/repeat an ordered position")
    static.verify_terminal(static.terminal_path(context.active, position), context.active)
    output = budget.terminal_path(context, position)
    attempts = context.root / "attempts"
    _path(context.root, directory=True)
    if attempts.exists() or attempts.is_symlink():
        _path(attempts, directory=True)
    else:
        attempts.mkdir(mode=0o700, parents=False, exist_ok=False)
        get.util.fsync_directory(context.root)
    output.parent.mkdir(mode=0o700, parents=False, exist_ok=False)
    _path(output.parent, directory=True)
    get.util.fsync_directory(output.parent)
    get.util.fsync_directory(attempts)
    return budget.account_terminal(context, position)


def acquisition_status(context: Context | budget.Context) -> dict:
    terminals, counts = [], {"admitted": 0, "operational-deferred": 0, "input-ineligible": 0}
    for position in range(1, len(context.candidates) + 1):
        path = terminal_path(context, position)
        if not path.exists():
            break
        facts = verify_terminal(path, context)
        counts[facts["outcome"]] += 1
        terminals.append(prep.reference(path))
    return {"terminal_prefix": terminals, "terminal_count": len(terminals), "candidate_count": len(context.candidates),
        "next_candidate_position": len(terminals) + 1 if len(terminals) < len(context.candidates) else None,
        **counts, **refs.ZERO}


def preparation_inputs(value: Mapping[str, Any]) -> tuple[set[Path], set[Path]]:
    files, trees = budget.preparation_inputs(value)
    context = budget.load_context(prep.open_reference(value[budget.FIELD]["context"]).parent)
    # The original failed attempt is a complete immutable tree, including its
    # absent full-proof state. Transport parents remain only transport roots.
    trees.add(Path(context.provenance["retained_attempt"]["root"]))
    return files, trees


def preparation_roots(value: Mapping[str, Any]) -> list[Path]:
    files, trees = preparation_inputs(value)
    return sorted(trees | {path.parent for path in files})


def terminal_inputs(enrollment: Path) -> tuple[set[Path], set[Path]]:
    """Only sealed enrollment/context refs; never scan later active terminals."""
    from . import rapid_rolling_capture as rolling
    from .static_evidence_transport import _path
    rolling._verify_enrollment(enrollment)
    files, trees, seen, terminals = set(), set(), set(), {}

    def context_inputs(context):
        if context.root in seen:
            return
        seen.add(context.root)
        files.add(context.root / "provenance.json")
        if isinstance(context, Context):
            files.add(refs.reopen(context.provenance["selector_source"]))
            context_inputs(context.budget)
            context_inputs(context.supplement)
        elif isinstance(context, budget.Context):
            files.add(refs.reopen(context.provenance["adapter_source"]))
            files.update(refs.reopen(ref) for ref in context.provenance["retained_operations"])
            trees.add(Path(context.provenance["retained_attempt"]["root"]))
            context_inputs(context.original)
            context_inputs(context.active)
        elif isinstance(context, whole.Context):
            context_inputs(context.original)
            for ref in context.provenance["plans"]:
                more_files, more_trees = refs.plan_files(refs.reopen(ref))
                files.update(more_files)
                trees.update(more_trees)
            for ref in context.provenance["graph_inputs"].values():
                more_files, more_trees = refs.input_files(refs.reopen(ref))
                files.update(more_files)
                trees.update(more_trees)
            for item in context.provenance["failed_discoveries"].values():
                files.update(refs.reopen(ref) for ref in item["files"].values())
                trees.add(refs.reopen(item["record"]).parent)
        elif isinstance(context, static.Context):
            files.update(prep.open_reference(context.provenance[key]) for key in
                ("source_list", "profile", "candidate_order"))
        else:
            raise ValueError("budget raw selector has an unknown admission context")
        for ref in context.provenance.get("inherited_terminals", []):
            terminals[prep.open_reference(ref)] = context
        parent_ref = context.provenance.get("parent_context")
        if parent_ref is not None:
            parent_root = prep.open_reference(parent_ref).parent
            if isinstance(context, Context):
                parent = load_context(parent_root)
            elif isinstance(context, whole.Context):
                parent = whole.load_context(parent_root)
            else:
                parent = static.load_context(parent_root)
            context_inputs(parent)

    path = enrollment.absolute()
    batches = set()
    while True:
        if path in batches:
            raise ValueError("budget raw selector enrollment lineage cycles")
        batches.add(path)
        batch = static.receipts._unpack(get._read(path), rolling.ENROLLMENT_TYPE)
        policy_path = rolling._open_ref(batch["policy"])
        policy = rolling.verify_policy(policy_path.parent)
        if policy["contract"] != rolling.STATIC_CONTRACT:
            raise ValueError("budget raw selector cannot import a browser study")
        context = rolling._context_for_policy(policy, Path(batch["admission_root"]))
        files.update({path, policy_path, rolling._open_ref(batch["admission_provenance"])})
        context_inputs(context)
        for row in batch["decisions"]:
            terminals[prep.open_reference(row["terminal"])] = context
        if batch["parent"] is None:
            break
        path = rolling._open_ref(batch["parent"])
    for terminal, context in terminals.items():
        rolling._verify_terminal(context, terminal)
        files.add(terminal)
        kind = get._load(get._read(terminal))["receipt_type"]
        payload = static.receipts._unpack(get._read(terminal), kind)
        if payload["prepared_workload"] is not None:
            path = prep.open_reference(payload["prepared_workload"])
            files.add(path)
            manifest = get._load(get._read(path))
            declared = manifest["preparation"]
            if budget.is_budget(declared):
                more_files, more_trees = preparation_inputs(declared)
                files.update(more_files)
                trees.update(more_trees)
            elif whole.is_whole(declared):
                more_files, more_trees = whole.preparation_inputs(declared)
                files.update(more_files)
                trees.update(more_trees)
        if kind == budget.TERMINAL_TYPE:
            terminal = prep.open_reference(payload["original_terminal"])
            files.add(terminal)
            payload = static.receipts._unpack(get._read(terminal), static.TERMINAL_TYPE)
        if payload["get_evidence_root"] is not None:
            trees.add(Path(payload["get_evidence_root"]))
        if payload["namespace"] is not None:
            files.update(prep.open_reference(payload["namespace"][key]) for key in
                ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    for path in files:
        _path(path)
    for path in trees:
        _path(path, directory=True)
    return files, trees

def roots(context: Context | budget.Context) -> list[Path]:
    roots = set(budget.roots(_head(context)))
    if isinstance(context, Context):
        roots.add(context.root)
        roots.add(refs.reopen(context.provenance["selector_source"]).parent.parent)
        roots.update(whole.roots(context.supplement))
    return sorted(roots)


def selected_capture_limits(manifests: list[dict], original_limits: Mapping[str, int]) -> dict[str, int]:
    # Amended inputs are first authenticated and mapped back to their bound
    # original preparation, so every mode uses its class's same response cap.
    from . import static_budget_capture_amendment as amendment
    original = []
    for manifest in manifests:
        declared = manifest["preparation"]
        if amendment.is_amended(declared):
            amendment.validate_preparation(declared, manifest["resources"])
            original.append(amendment.original_manifest(declared, manifest["resources"]))
        else:
            original.append(manifest)
    return budget.selected_capture_limits(original, original_limits)
