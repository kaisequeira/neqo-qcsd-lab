"""Additive whole-occurrence graphs with independent ordinary GET admission.

This authority preserves the original supplied-static queue and decisions. New
graphs occupy its appended tail in prospectively declared catalogue order. A
browser graph is input only; admission requires a new strict primary bootstrap
and one complete ordinary GET of every original occurrence and dependency.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
import os
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import supplied_static_admission as static
from . import supplied_static_bootstrap_get as bootstrap
from . import supplied_static_get as get
from . import supplied_static_graph as graph
from . import supplied_static_preparation as original
from . import whole_graph_input as inputs

ROLE = "whole-occurrence-independent-complete-get-preparation-v1"
COVERAGE = "all-discovered-occurrences-and-approved-origin-union-v1"
CONTEXT_TYPE = "qcsd-additive-whole-graph-static-context-v1"
CONTRACT = "original-static-prefix-then-declared-whole-occurrence-get-admissions-v1"
TERMINAL_TYPE = "qcsd-additive-whole-graph-static-terminal-v1"
PROOF_TYPE = "qcsd-whole-occurrence-primary-and-complete-native-get-v1"
RECEIPT_TYPE = "qcsd-whole-occurrence-independent-get-preparation-v1"
NAMESPACE_TYPE = "qcsd-whole-occurrence-recorded-get-execution-v1"


class PreparationIneligible(ValueError):
    """A closed complete GET fails a specified whole-graph admission property."""


def policies() -> dict[str, str]:
    from . import capture_acceptance_policy as capture
    return {capture.FIELD: capture.ACK_START_POLICY, capture.TAMARAW_FIELD: capture.TAMARAW_POLICY,
            capture.FRONT_FIELD: capture.FRONT_WINDOW_POLICY, capture.TERMINAL_PRIMARY_FIELD: capture.TERMINAL_PRIMARY_POLICY}


def is_whole(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("data_role") == ROLE


def _tree_files(root: Path) -> dict[str, dict[str, str]]:
    root = root.absolute()
    if not root.is_dir() or any(path.is_symlink() for path in (root, *root.parents)):
        raise ValueError("whole graph raw attempt needs a regular original directory")
    result = {}
    for directory, children, names in os.walk(root, followlinks=False):
        if any((Path(directory) / name).is_symlink() for name in children):
            raise ValueError("whole graph raw attempt contains a linked directory")
        for name in names:
            path = Path(directory) / name
            result[str(path.relative_to(root))] = inputs.reference(path)
    return dict(sorted(result.items()))


def producer_sources() -> dict[str, str]:
    from . import manifest, application_response_policy
    return {**bootstrap.producer_sources(), **{name: graph.digest(get._read(Path(module.__file__))) for name, module in {
        "qcsd_lab.whole_graph_input": inputs, "qcsd_lab.whole_graph_supplement": __import__(__name__, fromlist=["_"]),
        "qcsd_lab.manifest": manifest, "qcsd_lab.application_response_policy": application_response_policy}.items()}}


def _recognized_producer_sources(value: Any) -> bool:
    """Keep whole-GET declarations bound to their finite original reader pair."""
    expected = producer_sources()
    if value == expected:
        return True
    from . import rapid_fixed_condition_target as fixed
    fixed._acquisition_reader_sources()
    return value in [{**expected,
        'qcsd_lab.whole_graph_input': input_sha,
        'qcsd_lab.whole_graph_supplement': supplement_sha}
        for input_sha, supplement_sha in (
            ('5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5',
             '164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7'),
            ('8de0879f1ec1708ec43c061c41ada4d8315dd74865edbd7134045c9fa0b9b940',
             '726c0d6215830730f3938b69545f3b4acc8c727dda3b4528a34732701f8d9f07'),
            ('4b999d64aa59c7ebc91a2d65f29e091752920891d41539f9f079c99bc7dde583',
             'a12ba1de531fd37a4e6ab8abbc8497911ea51d4d45e54d452e3afc927058db66'),
            ('a95019161d069fda019de74768a13283a4a37d89fc6cddab0b2ddd0b52540245',
             '72a3e7030356955033fefab3703abe895c4fdb264910ea9c4d40ca398f175052'))
        if (supplement_sha != '726c0d6215830730f3938b69545f3b4acc8c727dda3b4528a34732701f8d9f07'
            or expected['qcsd_lab.application_response_policy'] ==
                '8d85075852b94e7c8969fc17f141fed45b65c23bf6493fe607ca43b6a902d27e')]


@dataclass(frozen=True)
class Context:
    root: Path
    provenance: dict[str, Any]
    original: static.Context
    candidates: tuple[dict[str, Any], ...]


def _cohort(context: Context):
    from . import rapid_supplemental_cohort as cohort
    return cohort if isinstance(context.original, cohort.CohortAnchor) else None


def _plan_rows(plans: list[dict[str, Any]], prefix: static.Context) -> tuple[dict[str, Any], ...]:
    rows, seen = [], {row["candidate_id"] for row in prefix.candidates}
    domains = {row["domain"] for row in prefix.candidates}
    for plan in plans:
        if (Path(plan["original_prefix"]["context"]["path"]).parent != prefix.root
                or inputs.reopen(plan["original_prefix"]["context"]) != prefix.root / "provenance.json"):
            raise ValueError("supplement discovery has another original static prefix")
        if plan["artifact_type"] == inputs.SEEDED_PLAN_TYPE:
            retry = plan["retry"]
            original_plan = inputs.reopen(retry["original_plan"])
            original_value = inputs.load_plan(original_plan)
            if (original_value not in plans[:plans.index(plan)]
                    or plan["reserved_candidates"] != [row["catalogue_candidate"] for row in rows]
                    or retry["new_catalogue_reservations"] is not False or retry["prior_outcomes_reclassified"] is not False
                    or plan["candidates"] != [original_value["candidates"][index - 1] for index in retry["retry_original_indices"]]):
                raise ValueError("supplement retry changes original reservations, prior failures or queue positions")
            # This is a prospective input attempt at an existing reserved slot,
            # not another catalogue selection or a replacement of old evidence.
            continue
        if plan["artifact_type"] == inputs.CONTINUATION_PLAN_TYPE:
            binding = plan["reservation_continuation"]
            original = inputs.load_plan(inputs.reopen(binding["refs"]["original_plan"]))
            if (original not in plans[:plans.index(plan)] or original["schema_version"] != 4
                    or plan["previous_plans"] != [binding["refs"]["original_plan"]]
                    or plan["reserved_candidates"] != [row["catalogue_candidate"] for row in rows]
                    or binding["original_candidate_indices"] != [2, 3, 4, 5]
                    or binding["original_failed_candidate"] != original["candidates"][0]
                    or plan["candidates"] != original["candidates"][1:]):
                raise ValueError("supplement continuation changes its original pending reservations or queue slots")
            # A new control attempt occupies its old reservation. No original
            # failure becomes a fabricated terminal and no candidate is added.
            continue
        if plan["artifact_type"] == inputs.V9_CONTINUATION_PLAN_TYPE:
            original = inputs.load_plan(inputs.reopen(plan["original_plan"]))
            if (original not in plans[:plans.index(plan)] or original["schema_version"] != 8
                    or plan["previous_plan"] is not None or plan["previous_batch"] is not None
                    or plan["reserved_candidates"] != [row["catalogue_candidate"] for row in rows]
                    or plan["original_candidate_indices"] != [2, 3, 4, 5]
                    or plan["local_candidate_indices"] != [1, 2, 3, 4]
                    or plan["candidates"] != original["candidates"][1:]):
                raise ValueError("V9 continuation changes original V8 pending reservations or queue slots")
            # The original31 failure remains accounted; original32 is retained
            # as an interruption. New actual attempts reuse only slots32--35.
            continue
        # Previous declaration reservations are outcomes-independent. Every
        # reserved identity must appear in this exact preceding queue tail.
        if plan["reserved_candidates"] != [row["catalogue_candidate"] for row in rows]:
            raise ValueError("supplement omitted or reordered an earlier declared discovery candidate")
        for candidate in plan["candidates"]:
            if candidate["candidate_id"] in seen or candidate["domain"] in domains:
                raise ValueError("supplement repeats an original or earlier class identity")
            seen.add(candidate["candidate_id"])
            domains.add(candidate["domain"])
            position = len(prefix.candidates) + len(rows) + 1
            rows.append({"position": position, "source_position": candidate["catalogue_position"],
                "candidate_id": candidate["candidate_id"], "domain": candidate["domain"],
                "catalogue_candidate": deepcopy(candidate)})
    if not rows:
        raise ValueError("supplement requires a prospectively declared appended candidate queue")
    return tuple(rows)


def initialize_context(root: Path, *, original_context: Path, plans: list[Path],
                       graph_inputs: list[Path], expected_runtime: dict[str, str],
                       parent_context: Path | None = None, failed_discoveries: list[Path] = ()) -> Path:
    prefix = static.load_context(original_context)
    runtime = get.runtime_binding(expected_runtime)
    declarations = [inputs.load_plan(path) for path in plans]
    tail = _plan_rows(declarations, prefix)
    by_id = {}
    for path in graph_inputs:
        value, _ = inputs.load_input(path)
        candidate = value["candidate"]["candidate_id"]
        if candidate in by_id:
            raise ValueError("supplement input list repeats a candidate")
        if not any(row["catalogue_candidate"] == value["candidate"] for row in tail):
            raise ValueError("supplement input was not declared before discovery")
        by_id[candidate] = inputs.reference(path)
    failures = {}
    for path in failed_discoveries:
        failure = inputs.load_failure(path)
        candidate = failure["candidate"]["candidate_id"]
        if candidate in failures or candidate in by_id or not any(row["catalogue_candidate"] == failure["candidate"] for row in tail):
            raise ValueError("supplement failed discovery conflicts with a selected whole graph or declared identity")
        failures[candidate] = {"record": inputs.reference(path), "files": _tree_files(path.parent)}
    parent_ref, inherited = None, []
    if parent_context is not None:
        parent = load_context(parent_context)
        if parent.original.root != prefix.root or parent.provenance["runtime_binding"] != runtime:
            raise ValueError("supplement successor changed its original queue or GET runtime")
        old_tail = parent.candidates[len(prefix.candidates):]
        if tail[:len(old_tail)] != old_tail:
            raise ValueError("supplement successor rewrites the appended order")
        for key, ref in parent.provenance["graph_inputs"].items():
            if key in by_id and by_id[key] != ref:
                raise ValueError("supplement successor replaces a discovered whole graph")
            by_id[key] = ref
        for key, ref in parent.provenance["failed_discoveries"].items():
            if key in failures and failures[key] != ref or key in by_id:
                raise ValueError("supplement successor replaces an accounted failed discovery")
            failures[key] = ref
        inherited = acquisition_status(parent)["terminal_prefix"]
        parent_ref = original.reference(parent.root / "provenance.json")
    root = root.absolute()
    for protected in [prefix.root, *plans, *graph_inputs, *failed_discoveries, *([parent_context] if parent_context else [])]:
        get.util.require_disjoint_path(root, [protected], label="whole graph context")
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    payload = {"contract": CONTRACT, "data_role": ROLE, "original_context": original.reference(prefix.root / "provenance.json"),
        "plans": [inputs.reference(path) for path in plans], "graph_inputs": by_id, "failed_discoveries": failures,
        "candidates": list(prefix.candidates + tail), "runtime_binding": runtime,
        "capture_limits": static.context_limits(prefix), "parent_context": parent_ref,
        "inherited_terminals": inherited, "declared_at": static.receipts._now(),
        "scientific_credit": False, "formal_accepted_trace_count": 0}
    path = static._write(root / "provenance.json", CONTEXT_TYPE, payload)
    load_context(root)
    return path


def load_context(root: Path, *, _seen: frozenset[Path] = frozenset()) -> Context:
    from . import rapid_supplemental_cohort as cohort
    if cohort.is_context(root):
        return cohort.load_context(root)
    root = root.absolute()
    if root in _seen:
        raise ValueError("supplement context lineage contains a cycle")
    value = static.receipts._unpack(get._read(root / "provenance.json"), CONTEXT_TYPE)
    get._exact(value, {"contract", "data_role", "original_context", "plans", "graph_inputs", "failed_discoveries", "candidates", "runtime_binding",
        "capture_limits", "parent_context", "inherited_terminals", "declared_at", "scientific_credit", "formal_accepted_trace_count"},
        "whole graph context")
    if (value["contract"] != CONTRACT or value["data_role"] != ROLE or value["scientific_credit"] is not False
            or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or not static.receipts._utc(value["declared_at"]) <= static.receipts._utc(static.receipts._now())):
        raise ValueError("whole graph context changes its zero-credit prospective role")
    prefix = static.load_context(original.open_reference(value["original_context"]).parent)
    declarations = [inputs.load_plan(inputs.reopen(ref)) for ref in value["plans"]]
    candidates = prefix.candidates + _plan_rows(declarations, prefix)
    if list(candidates) != value["candidates"] or value["capture_limits"] != static.context_limits(prefix):
        raise ValueError("supplement changed original candidates, appended order or capture bounds")
    get.runtime_binding(value["runtime_binding"])
    if not isinstance(value["graph_inputs"], dict):
        raise ValueError("supplement inputs must be separately bound by declared candidate identity")
    tail = {row["candidate_id"]: row for row in candidates[len(prefix.candidates):]}
    for key, ref in value["graph_inputs"].items():
        input_value, _ = inputs.load_input(inputs.reopen(ref))
        if (key not in tail or input_value["candidate"] != tail[key]["catalogue_candidate"]
                or input_value["plan"] not in value["plans"]
                or static.receipts._utc(input_value["completed_at"]) > static.receipts._utc(value["declared_at"])):
            raise ValueError("supplement input changes its declared identity or closed chronology")
    if not isinstance(value["failed_discoveries"], dict):
        raise ValueError("supplement failed discovery bindings must be explicit")
    for key, item in value["failed_discoveries"].items():
        get._exact(item, {"record", "files"}, "failed discovery binding")
        failure = inputs.load_failure(inputs.reopen(item["record"]))
        if (key not in tail or key in value["graph_inputs"] or failure["candidate"] != tail[key]["catalogue_candidate"]
                or failure["plan"] not in value["plans"] or _tree_files(Path(item["record"]["path"]).parent) != item["files"]
                or get._time(failure["completed_at"]) > get._time(value["declared_at"])):
            raise ValueError("supplement failure changed original raw attempt, identity or chronology")
    context = Context(root, value, prefix, candidates)
    inherited = value["inherited_terminals"]
    if not isinstance(inherited, list) or len(inherited) > len(candidates):
        raise ValueError("supplement inherited decisions are not a finite prefix")
    if value["parent_context"] is None:
        if inherited:
            raise ValueError("initial supplemental context invents inherited terminals")
    else:
        parent = load_context(original.open_reference(value["parent_context"]).parent, _seen=_seen | {root})
        if (parent.original.root != prefix.root or candidates[:len(parent.candidates)] != parent.candidates
                or value["runtime_binding"] != parent.provenance["runtime_binding"]
                or any(value["graph_inputs"].get(k) != v for k, v in parent.provenance["graph_inputs"].items())
                or any(value["failed_discoveries"].get(k) != v for k, v in parent.provenance["failed_discoveries"].items())
                or not static.receipts._utc(parent.provenance["declared_at"]) <= static.receipts._utc(value["declared_at"])):
            raise ValueError("supplement successor replaces original order, input or GET runtime")
        for position, ref in enumerate(inherited, 1):
            terminal = original.open_reference(ref)
            if terminal != terminal_path(parent, position):
                raise ValueError("supplement successor omits a preceding immutable decision")
            verify_terminal(terminal, parent)
            if static.receipts._utc(_terminal_payload(parent, terminal)["declared_at"]) > static.receipts._utc(value["declared_at"]):
                raise ValueError("supplement inherited terminal closed after successor declaration")
    return context


def is_context(root: Path) -> bool:
    from . import rapid_supplemental_cohort as cohort
    if cohort.is_context(root):
        return True
    return get._load(get._read(root / "provenance.json")).get("receipt_type") == CONTEXT_TYPE


def identity(context: Context) -> dict[str, str]:
    if _cohort(context):
        return dict(context.original.provenance["admission_identity"])
    return static.identity(context.original)


def context_limits(context: Context) -> dict[str, int]:
    return dict(context.provenance["capture_limits"])


def terminal_path(context: Context, position: int) -> Path:
    if type(position) is not int or not 1 <= position <= len(context.candidates):
        raise ValueError("supplement position is outside its exact declared queue")
    if position <= len(context.original.candidates):
        return static.terminal_path(context.original, position)
    if position <= len(context.provenance["inherited_terminals"]):
        return original.open_reference(context.provenance["inherited_terminals"][position - 1])
    return context.root / "attempts" / f"candidate-{position:06d}" / "terminal.json"


def _candidate_input(context: Context, position: int):
    terminal_path(context, position)
    if position <= len(context.original.candidates):
        raise ValueError("whole graph GET cannot reinterpret an original static candidate")
    row = context.candidates[position - 1]
    ref = context.provenance["graph_inputs"].get(row["candidate_id"])
    if ref is None:
        raise ValueError("declared candidate has no closed whole graph input; it cannot be skipped")
    path = inputs.reopen(ref)
    value, neutral = inputs.load_input(path)
    return row, ref, value, neutral


def _manifests(neutral: dict) -> tuple[dict, dict]:
    primary = {"resources": [deepcopy(neutral["resources"][0])]}
    full = deepcopy(neutral)
    full["resources"][0]["known_valid"] = True
    return primary, full


def _execution_root(root: Path, namespace: Any, expected: dict, *, failed_phase=None):
    if namespace is None:
        return root
    if namespace.get("record_type") != NAMESPACE_TYPE:
        raise ValueError("whole graph GET namespace has another authority role")
    return original._execution_root(root, {**namespace, "record_type": original.NAMESPACE}, expected, failed_phase=failed_phase)


def namespace_mapping(root: Path, execution_root: Path, *, started: Path, completed: Path,
                      stdout: Path, stderr: Path, expected_runtime: dict, failed_phase: str | None = None) -> dict:
    value = {"schema_version": 1, "record_type": NAMESPACE_TYPE, "retained_root": str(root.absolute()),
        "execution_root": str(execution_root), "outer_started": original.reference(started),
        "outer_completed": original.reference(completed), "outer_stdout": original.reference(stdout),
        "outer_stderr": original.reference(stderr)}
    _execution_root(root.absolute(), value, get.runtime_binding(expected_runtime), failed_phase=failed_phase)
    return value


def _declaration(root: Path, context: Context, position: int) -> tuple[dict, dict, dict, dict, dict]:
    row, ref, input_value, neutral = _candidate_input(context, position)
    primary, full = _manifests(neutral)
    raw = get._read(root / "declaration.json")
    declaration = get._load(raw)
    get._exact(declaration, {"schema_version", "record_type", "declared_at", "context", "position", "candidate_id", "domain",
        "graph_input", "discovery_runtime", "runtime_binding", "producer_sources", "neutral_input_sha256",
        "bootstrap_input_sha256", "full_input_sha256", "max_response_bytes", "timeout_seconds", "primary_claim",
        "public_origin_policy", *inputs.ZERO}, "whole graph GET declaration")
    expected = context.provenance["runtime_binding"]
    if (type(declaration["schema_version"]) is not int or declaration["schema_version"] != 1
            or declaration["record_type"] != PROOF_TYPE or not inputs.zero(declaration)
            or declaration["context"] != original.reference(context.root / "provenance.json")
            or type(declaration["position"]) is not int or declaration["position"] != position
            or declaration["candidate_id"] != row["candidate_id"] or declaration["domain"] != row["domain"]
            or declaration["graph_input"] != ref or declaration["discovery_runtime"] != input_value["runtime"]
            or declaration["runtime_binding"] != expected or not _recognized_producer_sources(declaration["producer_sources"])
            or declaration["neutral_input_sha256"] != graph.digest(graph.canonical_bytes(neutral))
            or get._load(get._read(root / "neutral-input.json")) != neutral
            or declaration["bootstrap_input_sha256"] != graph.digest(graph.canonical_bytes(primary))
            or declaration["full_input_sha256"] != graph.digest(graph.canonical_bytes(full))
            or type(declaration["max_response_bytes"]) is not int or declaration["max_response_bytes"] != context_limits(context)["max_response_bytes"]
            or type(declaration["timeout_seconds"]) is not int or declaration["timeout_seconds"] != context_limits(context)["timeout_seconds"]
            or declaration["primary_claim"] != get.PRIMARY_CLAIM or declaration["public_origin_policy"] != get.PUBLIC_POLICY
            or not get._time(context.provenance["declared_at"]) <= get._time(declaration["declared_at"])):
        raise ValueError("whole graph GET declaration changed input, separate runtimes, Source, order or bounds")
    source = get._runtime(get._load(get._read(root / "runtime.json")), expected)
    return {**declaration, "_raw_sha256": graph.digest(raw)}, neutral, primary, full, source


def build_proof(root: Path, *, context: Context, position: int, namespace: Any = None) -> dict:
    root = root.absolute()
    declaration, neutral, primary, full, _ = _declaration(root, context, position)
    execution = _execution_root(root, namespace, declaration["runtime_binding"])
    first = bootstrap._step(root / "bootstrap", declaration, primary, policy=bootstrap.STRICT_POLICY, execution=execution / "bootstrap")
    first_end = get._load(get._read(root / "bootstrap/native-completed.json"))["completed_at"]
    full_start = get._load(get._read(root / "native-started.json"))["started_at"]
    if get._time(first_end) > get._time(full_start):
        raise ValueError("whole graph GET began before actual strict primary bootstrap completed")
    native = bootstrap._step(root, declaration, full, policy=get.RESPONSE_POLICY, execution=execution)
    if namespace is not None:
        outer_start = get._load(get._read(original.open_reference(namespace["outer_started"])))["started_at"]
        if get._time(outer_start) > get._time(get._load(get._read(root / "bootstrap/native-started.json"))["started_at"]):
            raise ValueError("whole graph bootstrap predates its actual outer process")
    names = ["declaration.json", "neutral-input.json", "runtime.json"]
    for prefix in ("", "bootstrap/"):
        names.extend(prefix + name for name in ["native-input.json", "dns.json", "native-started.json", "native-completed.json",
            "native.stdout.log", "native.stderr.log", *["native/" + name for name in get.FILES]])
    return {"schema_version": 1, "record_type": PROOF_TYPE, "data_role": ROLE,
        "context": declaration["context"], "position": position, "candidate_id": declaration["candidate_id"],
        "domain": declaration["domain"], "graph_input": declaration["graph_input"],
        "discovery_runtime": declaration["discovery_runtime"], "runtime_binding": declaration["runtime_binding"],
        "producer_sources": declaration["producer_sources"], "declared_at": declaration["declared_at"],
        "completed_at": get._load(get._read(root / "native-completed.json"))["completed_at"],
        "all_occurrences_and_edges_retained": True, "full_list_coverage": True,
        "resource_count": len(neutral["resources"]), "bootstrap_native": first, "native": native,
        "files": {name: graph.digest(get._read(root / name)) for name in names}, **inputs.ZERO}


def reopen_get(root: Path, *, context: Context, position: int, namespace: Any = None) -> dict:
    proof = build_proof(root, context=context, position=position, namespace=namespace)
    if get._load(get._read(root / "full-get-proof.json")) != proof:
        raise ValueError("whole graph proof differs from independently reopened actual raw GET")
    return proof


def failure_proof(root: Path, *, context: Context, position: int, namespace: Any = None) -> dict:
    """Account actual failed process/strict primary, without positive GET credit."""
    root = root.absolute()
    declaration, _, primary, full, _ = _declaration(root, context, position)
    phase = "full" if (root / "native-started.json").exists() else "bootstrap"
    execution = _execution_root(root, namespace, declaration["runtime_binding"], failed_phase=phase)
    child, manifest = (root, full) if phase == "full" else (root / "bootstrap", primary)
    policy = get.RESPONSE_POLICY if phase == "full" else bootstrap.STRICT_POLICY
    started = get._exact(get._load(get._read(child / "native-started.json")),
        {"schema_version", "command", "environment", "started_at", "declaration_sha256", "client_sha256"}, "failed whole GET start")
    completed = get._exact(get._load(get._read(child / "native-completed.json")),
        {"schema_version", "returncode", "timed_out", "completed_at", "elapsed_ns", "stdout_sha256", "stderr_sha256",
         "outputs", "client_sha256", "source_manifest_sha256"}, "failed whole GET completion")
    expected = declaration["runtime_binding"]
    if (type(started["schema_version"]) is not int or started["schema_version"] != 1
            or started["command"] != bootstrap._command(execution if phase == "full" else execution / "bootstrap",
                declaration["max_response_bytes"], declaration["timeout_seconds"], policy)
            or started["environment"] != {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": expected["image_digest"],
                "QCSD_LAB_SOURCE_METADATA": str(get.util.DEFAULT_SOURCE_METADATA)}
            or started["declaration_sha256"] != declaration["_raw_sha256"] or started["client_sha256"] != expected["client_sha256"]
            or get._load(get._read(child / "native-input.json")) != manifest
            or type(completed["schema_version"]) is not int or completed["schema_version"] != 1
            or get._number(completed["elapsed_ns"], "failed GET elapsed") < 1
            or completed["client_sha256"] != expected["client_sha256"] or completed["source_manifest_sha256"] != expected["source_manifest_sha256"]
            or completed["stdout_sha256"] != graph.digest(get._read(child / "native.stdout.log"))
            or completed["stderr_sha256"] != graph.digest(get._read(child / "native.stderr.log"))
            or not get._time(declaration["declared_at"]) <= get._time(started["started_at"]) < get._time(completed["completed_at"])):
        raise ValueError("whole graph failure lacks exact actual command, raw closure or runtime")
    outputs = completed["outputs"]
    if not isinstance(outputs, dict) or not set(outputs) <= set(get.FILES) or any(graph.digest(get._read(child / "native" / name)) != digest for name, digest in outputs.items()):
        raise ValueError("whole graph failed raw Native outputs changed")
    process_failure = ((type(completed["returncode"]) is int and completed["returncode"] != 0 and completed["timed_out"] is False)
        or completed["returncode"] is None and completed["timed_out"] is True)
    if not process_failure:
        if not (phase == "bootstrap" and type(completed["returncode"]) is int and completed["returncode"] == 0 and completed["timed_out"] is False):
            raise ValueError("successful whole graph GET cannot be relabeled as a process failure")
        get._run_proof(get._load(get._read(child / "native/run.json")), child, declaration, started, completed,
            manifest, get._load(get._read(child / "dns.json")), response_policy=policy, rejected_primary=True)
    origins = sorted({get._origin(row["url"]) for row in manifest["resources"]}, key=lambda value: (urlsplit(value).hostname, urlsplit(value).port or 443))
    get._dns(get._load(get._read(child / "dns.json")), origins, declaration["declared_at"], started["started_at"])
    if phase == "full":
        bootstrap._step(root / "bootstrap", declaration, primary, policy=bootstrap.STRICT_POLICY, execution=execution / "bootstrap")
        if get._time(get._load(get._read(root / "bootstrap/native-completed.json"))["completed_at"]) > get._time(started["started_at"]):
            raise ValueError("failed whole GET began before primary approval")
    return {"record_type": PROOF_TYPE, "phase": phase, "completed_at": completed["completed_at"],
        "outcome": "operational-deferred", "files": _tree_files(root), **inputs.ZERO}


def execute_get(context_root: Path, position: int, root: Path) -> dict:
    context = load_context(context_root)
    if _cohort(context):
        _cohort(context).require_get(context, position)
    terminal = terminal_path(context, position)
    if terminal.exists() or terminal.is_symlink():
        raise ValueError("whole graph GET cannot repeat an already accounted decision")
    row, ref, value, neutral = _candidate_input(context, position)
    expected = context.provenance["runtime_binding"]
    if (os.environ.get("QCSD_LAB_IMAGE_DIGEST") != expected["image_digest"]
            or os.environ.get("QCSD_LAB_SOURCE_METADATA") != str(get.util.DEFAULT_SOURCE_METADATA)):
        raise ValueError("whole graph GET must run inside its separately declared installed image")
    implementation, _, _ = get.chaff_qualification._qualification_execution_context()
    client, client_sha = get.chaff_qualification._bound_neqo_client(implementation)
    runtime = {"source_manifest_text": get._read(get.util.DEFAULT_SOURCE_METADATA).decode(), "qualification_implementation": implementation}
    get._runtime(runtime, expected)
    if client != get.CLIENT or client_sha != expected["client_sha256"]:
        raise ValueError("whole graph GET actual installed client differs")
    if get.class_acquisition.unsafe_catalogue_domain_reason(row["domain"]) is not None:
        raise ValueError("whole graph GET primary domain is excluded")
    root = root.absolute()
    for protected in [context.root, context.original.root, inputs.reopen(ref), client, get.util.DEFAULT_SOURCE_METADATA]:
        get.util.require_disjoint_path(root, [protected], label="whole graph GET output")
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    (root / "bootstrap").mkdir(mode=0o700)
    primary, full = _manifests(neutral)
    get._json(root / "neutral-input.json", neutral)
    get._json(root / "runtime.json", runtime)
    declaration = {"schema_version": 1, "record_type": PROOF_TYPE, "declared_at": datetime.now(UTC).isoformat(),
        "context": original.reference(context.root / "provenance.json"), "position": position, "candidate_id": row["candidate_id"],
        "domain": row["domain"], "graph_input": ref, "discovery_runtime": value["runtime"], "runtime_binding": expected,
        "producer_sources": producer_sources(), "neutral_input_sha256": graph.digest(graph.canonical_bytes(neutral)),
        "bootstrap_input_sha256": graph.digest(graph.canonical_bytes(primary)), "full_input_sha256": graph.digest(graph.canonical_bytes(full)),
        **{key: context_limits(context)[key] for key in ("max_response_bytes", "timeout_seconds")},
        "primary_claim": get.PRIMARY_CLAIM, "public_origin_policy": get.PUBLIC_POLICY, **inputs.ZERO}
    get._json(root / "declaration.json", declaration)
    declared = {**declaration, "_raw_sha256": graph.digest(get._read(root / "declaration.json"))}
    bootstrap._execute_step(root / "bootstrap", declared, primary, client, policy=bootstrap.STRICT_POLICY)
    bootstrap._execute_step(root, declared, full, client, policy=get.RESPONSE_POLICY)
    proof = build_proof(root, context=context, position=position)
    get._json(root / "full-get-proof.json", proof)
    return proof


def _prepared(root: Path, proof: dict, evidence: dict) -> dict:
    from . import application_response_policy as app
    input_value, neutral = inputs.load_input(inputs.reopen(proof["graph_input"]))
    run = get._load(get._read(root / "native/run.json"))
    responses = {row["resource_id"]: row for row in run["responses"]}
    resources = deepcopy(neutral["resources"])
    for row in resources:
        response = responses[row["id"]]
        row.update(content_length=response["bytes"], data_length=response["bytes"], known_valid=200 <= response["status"] < 300)
    try:
        app._primary_content_type(responses[0])
    except ValueError as error:
        raise PreparationIneligible("actual-primary-is-not-html-labelled") from error
    primary_origin = get._origin(resources[0]["url"])
    if not any(get._origin(row["url"]) != primary_origin and row["known_valid"] and row["data_length"] > 0 for row in resources):
        raise PreparationIneligible("actual-graph-has-no-nonempty-successful-secondary-origin")
    declaration = get._load(get._read(root / "declaration.json"))
    source = get._runtime(get._load(get._read(root / "runtime.json")), proof["runtime_binding"])
    prep = {"data_role": ROLE, "whole_graph_get_evidence": evidence,
        "source_url": resources[0]["url"], "final_url": resources[0]["url"],
        "approved_origins": input_value["approved_origin_union"], "observed_origins": input_value["observed_origins"],
        "max_response_bytes": declaration["max_response_bytes"], "timeout_seconds": declaration["timeout_seconds"],
        "complete_get_runs": 1, "browser_qualification_claim": False, "challenge_absence_claim": False, "response_stability_claim": False,
        "lab_source": {**source, "image_digest": proof["runtime_binding"]["image_digest"]},
        "prepare_image_digest": proof["runtime_binding"]["image_digest"], **proof["native"]["native_provenance"],
        "expected_responses": [{key: response[key] for key in ("resource_id", "status", "bytes", "body_sha256")}
            for response in sorted(run["responses"], key=lambda row: row["resource_id"])],
        "qualified_chaff_origin_policy": app.APPROVED_ORIGINS_CHAFF_POLICY,
        "application_response_policy": app.COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        "application_response_policy_evidence": {"schema_version": 1, "data_role": ROLE,
            "policy": original.RESPONSE_EVIDENCE, "complete_get_proof_sha256": evidence["proof"]["sha256"]},
        "primary_document_identity_policy": app.VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
        "primary_document_identity_evidence": {"schema_version": 1, "data_role": ROLE,
            "policy": original.PRIMARY_EVIDENCE, "complete_get_proof_sha256": evidence["proof"]["sha256"],
            "complete_get_primary_responses": [{key: deepcopy(responses[0][key]) for key in
                ("resource_id", "url", "status", "bytes", "body_sha256", "content_length", "request_headers", "response_headers", "complete", "outcome")}]},
        "coverage_admission": {"schema_version": 1, "policy": COVERAGE,
            "required_origins": input_value["approved_origin_union"],
            "required_resources": [{"id": row["id"], "url": row["url"]} for row in resources]},
        "udp_payload_qualification": {"schema_version": 2, "outgoing_udp_payload_ceiling": 1200,
            "incoming_udp_payload_limit": 65527, "runs": [proof["native"]["udp_payloads"]]}, **policies()}
    result = {"preparation": prep, "resources": resources}
    try:
        app.validate_prepared_response_graph(result)
    except ValueError as error:
        raise PreparationIneligible("actual-full-response-graph-is-not-capture-eligible") from error
    return result


def build_preparation(root: Path, *, context: Context, position: int, namespace: Any = None) -> dict:
    root = root.absolute()
    proof = reopen_get(root, context=context, position=position, namespace=namespace)
    evidence = {"schema_version": 1, "record_type": RECEIPT_TYPE, "root": str(root),
        "proof": original.reference(root / "full-get-proof.json"), "context": proof["context"],
        "position": position, "runtime_binding": proof["runtime_binding"], "graph_input": proof["graph_input"], "namespace": namespace}
    return _prepared(root, proof, evidence)


def validate_preparation(value: Any, resources: list[dict]) -> dict:
    if not is_whole(value):
        raise ValueError("whole graph preparation role is absent")
    evidence = get._exact(value.get("whole_graph_get_evidence"), {"schema_version", "record_type", "root", "proof", "context",
        "position", "runtime_binding", "graph_input", "namespace"}, "whole graph preparation evidence")
    if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1 or evidence["record_type"] != RECEIPT_TYPE:
        raise ValueError("whole graph preparation evidence has another authority")
    root = Path(evidence["root"])
    if not root.is_absolute() or ".." in root.parts or original.open_reference(evidence["proof"]) != root / "full-get-proof.json":
        raise ValueError("whole graph preparation proof root changed")
    context = load_context(original.open_reference(evidence["context"]).parent)
    proof = reopen_get(root, context=context, position=evidence["position"], namespace=evidence["namespace"])
    if (evidence["runtime_binding"] != proof["runtime_binding"] or evidence["graph_input"] != proof["graph_input"]
            or _prepared(root, proof, evidence) != {"preparation": value, "resources": resources}):
        raise ValueError("whole graph preparation differs from original occurrences, headers, DAG or raw GET")
    return proof


def _terminal_payload(context: Context, path: Path) -> dict:
    kind = get._load(get._read(path))["receipt_type"]
    if kind not in {static.TERMINAL_TYPE, TERMINAL_TYPE}:
        raise ValueError("supplement terminal has another typed authority")
    return static.receipts._unpack(get._read(path), kind)


def admit(context: Context, position: int, get_root: Path, *, namespace: Any = None) -> Path:
    if _cohort(context):
        _cohort(context).require_order(context, position)
    if position <= max(len(context.original.candidates), len(context.provenance["inherited_terminals"])):
        raise ValueError("supplement cannot replace an original or inherited decision")
    workload = build_preparation(get_root, context=context, position=position, namespace=namespace)
    row = context.candidates[position - 1]
    directory = terminal_path(context, position).parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    workload_path = directory / (row["candidate_id"] + ".json")
    get._json(workload_path, workload)
    payload = {"data_role": ROLE, "context": original.reference(context.root / "provenance.json"),
        "position": position, "candidate_id": row["candidate_id"], "domain": row["domain"], "outcome": "admitted",
        "prepared_workload": original.reference(workload_path), "get_evidence_root": str(get_root.absolute()),
        "namespace": namespace, "failure": None, "declared_at": static.receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0}
    path = static._write(terminal_path(context, position), TERMINAL_TYPE, payload)
    verify_terminal(path, context)
    return path


def record_deferral(context: Context, position: int, *, get_root: Path | None = None, namespace: Any = None) -> Path:
    if _cohort(context):
        _cohort(context).require_order(context, position)
    if position <= max(len(context.original.candidates), len(context.provenance["inherited_terminals"])):
        raise ValueError("supplement cannot replace an original or inherited decision")
    row = context.candidates[position - 1]
    if get_root is None:
        failure = context.provenance["failed_discoveries"].get(row["candidate_id"])
        if failure is None or namespace is not None:
            raise ValueError("unmeasured/missing whole graph cannot gain an invented deferral")
        failure = {"kind": "actual-discovery-failure", "evidence": failure}
    else:
        try:
            proof = reopen_get(get_root, context=context, position=position, namespace=namespace)
        except ValueError:
            failure = {"kind": "actual-get-failure", "evidence": failure_proof(get_root, context=context, position=position, namespace=namespace)}
        else:
            try:
                build_preparation(get_root, context=context, position=position, namespace=namespace)
            except PreparationIneligible as error:
                failure = {"kind": "actual-whole-graph-preparation-failure", "evidence": {
                    "proof": original.reference(get_root / "full-get-proof.json"), "reason": str(error)}}
            else:
                raise ValueError("eligible complete whole graph cannot gain an operational deferral")
    payload = {"data_role": ROLE, "context": original.reference(context.root / "provenance.json"),
        "position": position, "candidate_id": row["candidate_id"], "domain": row["domain"], "outcome": "operational-deferred",
        "prepared_workload": None, "get_evidence_root": str(get_root.absolute()) if get_root is not None else None,
        "namespace": namespace, "failure": failure, "declared_at": static.receipts._now(),
        "scientific_credit": False, "formal_accepted_trace_count": 0}
    path = static._write(terminal_path(context, position), TERMINAL_TYPE, payload)
    verify_terminal(path, context)
    return path


def _input_rejection(context: Context, position: int) -> dict:
    """A complete graph can fail only this study's declared two-origin entry rule."""
    row, ref, value, neutral = _candidate_input(context, position)
    if value.get("all_occurrences_and_edges_retained") is not True:
        raise ValueError("study input rejection requires an authenticated complete occurrence graph")
    profile_path = original.open_reference(context.original.provenance["profile"])
    profile = get._load(get._read(profile_path))
    if (type(profile.get("class_target")) is not int or profile["class_target"] != 50
            or type(profile.get("formal_trace_target")) is not int or profile["formal_trace_target"] != 16000
            or type(profile.get("minimum_origins")) is not int or profile["minimum_origins"] != 2):
        raise ValueError("complete-input rejection requires the declared rapid50 two-origin profile")
    origins = sorted({get._origin(resource["url"]) for resource in neutral["resources"]})
    if not origins or len(origins) >= profile["minimum_origins"]:
        raise ValueError("complete graph does not fail the declared origin-count entry rule")
    plan = inputs.load_plan(inputs.reopen(value["plan"]))
    return {"policy": "rapid50-complete-input-minimum-two-resource-origins-v1",
        "profile": inputs.reference(profile_path), "graph_input": ref,
        "candidate_id": row["candidate_id"], "position": position,
        "producer_sources": plan["producer_sources"], "discovery_control": plan.get("discovery_control"),
        "discovery_runtime": value["runtime"], "resource_graph_sha256": value["resource_graph_sha256"],
        "resource_count": len(neutral["resources"]), "actual_resource_origins": origins,
        "actual_resource_origin_count": len(origins), "minimum_origins": 2,
        "all_occurrences_and_edges_retained": True, "http3_assessment": "unassessed",
        "site_universally_invalid_claimed": False, **inputs.ZERO}


def record_input_rejection(context: Context, position: int) -> Path:
    if _cohort(context):
        _cohort(context).require_order(context, position)
    if position <= max(len(context.original.candidates), len(context.provenance["inherited_terminals"])):
        raise ValueError("input rejection cannot replace an original or inherited decision")
    target = terminal_path(context, position)
    if target.exists() or target.is_symlink():
        raise ValueError("input rejection cannot replace an already accounted decision")
    evidence = _input_rejection(context, position)
    row = context.candidates[position - 1]
    payload = {"data_role": ROLE, "context": original.reference(context.root / "provenance.json"),
        "position": position, "candidate_id": row["candidate_id"], "domain": row["domain"],
        "outcome": "input-ineligible", "prepared_workload": None, "get_evidence_root": None,
        "namespace": None, "failure": {"kind": "complete-graph-study-origin-entry-rule", "evidence": evidence},
        "declared_at": static.receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0}
    path = static._write(target, TERMINAL_TYPE, payload)
    verify_terminal(path, context)
    return path


def verify_terminal(path: Path, context: Context) -> dict:
    value = _terminal_payload(context, path)
    position = value["position"]
    expected = terminal_path(context, position)
    if _cohort(context):
        _cohort(context).require_order(context, position)
    if path.absolute() != expected:
        raise ValueError("supplement terminal differs from its immutable queue namespace")
    if position <= len(context.original.candidates):
        return static.verify_terminal(path, context.original)
    if position <= len(context.provenance["inherited_terminals"]):
        parent = load_context(original.open_reference(context.provenance["parent_context"]).parent)
        return verify_terminal(path, parent)
    get._exact(value, {"data_role", "context", "position", "candidate_id", "domain", "outcome", "prepared_workload",
        "get_evidence_root", "namespace", "failure", "declared_at", "scientific_credit", "formal_accepted_trace_count"}, "whole graph terminal")
    row = context.candidates[position - 1]
    if (value["data_role"] != ROLE or value["context"] != original.reference(context.root / "provenance.json")
            or value["candidate_id"] != row["candidate_id"] or value["domain"] != row["domain"]
            or value["scientific_credit"] is not False or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or not static.receipts._utc(context.provenance["declared_at"]) <= static.receipts._utc(value["declared_at"]) <= static.receipts._utc(static.receipts._now())
            or value["outcome"] not in {"admitted", "operational-deferred", "input-ineligible"}):
        raise ValueError("whole graph terminal changed its prospective role, order, outcome or chronology")
    facts = {"candidate_id": row["candidate_id"], "domain": row["domain"], "outcome": value["outcome"], "data_role": ROLE,
        "source_position": row["source_position"], "admission": None}
    if value["outcome"] == "input-ineligible":
        if (value["prepared_workload"] is not None or value["get_evidence_root"] is not None
                or value["namespace"] is not None
                or value["failure"] != {"kind": "complete-graph-study-origin-entry-rule", "evidence": _input_rejection(context, position)}):
            raise ValueError("study input rejection changed complete graph, profile, exact count or no-GET role")
        graph_input = inputs.load_input(inputs.reopen(value["failure"]["evidence"]["graph_input"]))[0]
        if get._time(graph_input["completed_at"]) > get._time(value["declared_at"]):
            raise ValueError("input rejection predates complete discovery")
        return facts
    if value["outcome"] == "operational-deferred":
        failure = get._exact(value["failure"], {"kind", "evidence"}, "whole graph terminal failure")
        if value["prepared_workload"] is not None:
            raise ValueError("operational whole graph deferral cannot carry a prepared workload")
        if failure["kind"] == "actual-discovery-failure":
            if (value["get_evidence_root"] is not None or value["namespace"] is not None
                    or context.provenance["failed_discoveries"].get(row["candidate_id"]) != failure["evidence"]):
                raise ValueError("discovery deferral changed its actual failed attempt")
            completed_at = inputs.load_failure(inputs.reopen(failure["evidence"]["record"]))["completed_at"]
        elif failure["kind"] == "actual-get-failure":
            actual = failure_proof(Path(value["get_evidence_root"]), context=context, position=position, namespace=value["namespace"])
            if actual != failure["evidence"]:
                raise ValueError("whole graph deferral changed its actual failed GET raw evidence")
            completed_at = actual["completed_at"]
        elif failure["kind"] == "actual-whole-graph-preparation-failure":
            root = Path(value["get_evidence_root"])
            proof = reopen_get(root, context=context, position=position, namespace=value["namespace"])
            get._exact(failure["evidence"], {"proof", "reason"}, "whole graph eligibility failure")
            if original.open_reference(failure["evidence"]["proof"]) != root / "full-get-proof.json":
                raise ValueError("whole graph preparation deferral proof differs")
            try:
                build_preparation(root, context=context, position=position, namespace=value["namespace"])
            except PreparationIneligible as error:
                if str(error) != failure["evidence"]["reason"]:
                    raise ValueError("whole graph preparation deferral changed its actual eligibility failure")
            else:
                raise ValueError("eligible whole graph cannot be substituted by preparation deferral")
            completed_at = proof["completed_at"]
        else:
            raise ValueError("unknown whole graph operational deferral kind")
        if get._time(completed_at) > get._time(value["declared_at"]):
            raise ValueError("whole graph deferral predates actual attempt closure")
        return facts
    if value["failure"] is not None:
        raise ValueError("admitted whole graph cannot retain a substituted failure outcome")
    path_workload = original.open_reference(value["prepared_workload"])
    if path_workload != expected.with_name(row["candidate_id"] + ".json"):
        raise ValueError("whole graph admission workload namespace changed")
    workload = get._load(get._read(path_workload))
    proof = validate_preparation(workload["preparation"], workload["resources"])
    evidence = workload["preparation"]["whole_graph_get_evidence"]
    if (proof["context"] != value["context"] or proof["position"] != position
            or evidence["root"] != value["get_evidence_root"] or evidence["namespace"] != value["namespace"]
            or static.receipts._utc(proof["completed_at"]) > static.receipts._utc(value["declared_at"])):
        raise ValueError("whole graph admission changed complete GET evidence or closed time")
    facts["admission"] = {"prepared_workload_sha256": value["prepared_workload"]["sha256"],
        "full_resource_graph_sha256": graph.digest(graph.canonical_bytes(workload["resources"])),
        "complete_get_proof_sha256": evidence["proof"]["sha256"]}
    return facts


def prepared_workload(context: Context, terminal: Path) -> tuple[Path, dict]:
    facts = verify_terminal(terminal, context)
    if facts["outcome"] != "admitted":
        raise ValueError("mixed context terminal is not admitted")
    value = _terminal_payload(context, terminal)
    path = original.open_reference(value["prepared_workload"])
    return path, get._load(get._read(path))


def acquisition_status(context: Context) -> dict:
    records = []
    for position in range(1, len(context.candidates) + 1):
        path = terminal_path(context, position)
        if not path.exists():
            break
        verify_terminal(path, context)
        records.append(original.reference(path))
    return {"terminal_prefix": records, "scientific_credit": False, "formal_accepted_trace_count": 0}


def sealed_context_roots(context: Context) -> set[Path]:
    """Transport only immutable declared/inherited inputs, including failures."""
    if _cohort(context):
        return _cohort(context).roots(context)
    values, seen = set(), set()

    def visit(current):
        if current.root in seen:
            return
        seen.add(current.root)
        values.add(current.root)
        if isinstance(current, static.Context):
            values.update(original.open_reference(current.provenance[key]).parent for key in
                ("source_list", "profile", "candidate_order"))
        else:
            visit(current.original)
            for ref in current.provenance["plans"]:
                values.update(inputs.plan_roots(inputs.reopen(ref)))
            for ref in current.provenance["graph_inputs"].values():
                values.update(inputs.roots(inputs.reopen(ref)))
            for item in current.provenance["failed_discoveries"].values():
                values.add(inputs.reopen(item["record"]).parent)
        for ref in current.provenance["inherited_terminals"]:
            terminal = original.open_reference(ref)
            if isinstance(current, Context):
                verify_terminal(terminal, current)
            else:
                static.verify_terminal(terminal, current)
            payload = _terminal_payload(current, terminal)
            values.add(terminal.parent)
            if payload["get_evidence_root"] is not None:
                values.add(Path(payload["get_evidence_root"]))
            if payload["prepared_workload"] is not None:
                values.add(original.open_reference(payload["prepared_workload"]).parent)
            if payload["namespace"] is not None:
                values.update(original.open_reference(payload["namespace"][key]).parent for key in
                    ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
        parent_ref = current.provenance["parent_context"]
        if parent_ref is not None:
            parent_root = original.open_reference(parent_ref).parent
            visit(load_context(parent_root) if isinstance(current, Context) else static.load_context(parent_root))

    visit(context)
    return values


def preparation_inputs(value: Mapping[str, Any]) -> tuple[set[Path], set[Path]]:
    """Immutable evidence refs and raw trees, distinct from transport parents.

    A context directory may acquire later candidate attempts. Observe its
    declaration and inherited prefix by authenticated file references instead
    of treating that transport directory as a closed evidence tree.
    """
    evidence = value["whole_graph_get_evidence"]
    context = load_context(original.open_reference(evidence["context"]).parent)
    files, trees, terminals, seen = set(), {Path(evidence["root"])}, {}, set()

    def visit(current):
        if current.root in seen:
            return
        seen.add(current.root)
        files.add(current.root / "provenance.json")
        if isinstance(current, static.Context):
            files.update(original.open_reference(current.provenance[key]) for key in
                ("source_list", "profile", "candidate_order"))
        else:
            visit(current.original)
            for ref in current.provenance["plans"]:
                declared_files, declared_trees = inputs.plan_files(inputs.reopen(ref))
                files.update(declared_files)
                trees.update(declared_trees)
            for ref in current.provenance["graph_inputs"].values():
                raw_files, raw_trees = inputs.input_files(inputs.reopen(ref))
                files.update(raw_files)
                trees.update(raw_trees)
            for item in current.provenance["failed_discoveries"].values():
                files.update(inputs.reopen(ref) for ref in item["files"].values())
                trees.add(inputs.reopen(item["record"]).parent)
        for ref in current.provenance["inherited_terminals"]:
            terminals[original.open_reference(ref)] = current
        parent_ref = current.provenance["parent_context"]
        if parent_ref is not None:
            root = original.open_reference(parent_ref).parent
            visit(load_context(root) if isinstance(current, Context) else static.load_context(root))

    visit(context)
    for terminal, owner in terminals.items():
        verifier = verify_terminal if isinstance(owner, Context) else static.verify_terminal
        verifier(terminal, owner)
        payload = _terminal_payload(owner, terminal)
        trees.add(terminal.parent)
        if payload["get_evidence_root"] is not None:
            trees.add(Path(payload["get_evidence_root"]))
        if payload["namespace"] is not None:
            files.update(original.open_reference(payload["namespace"][key]) for key in
                ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    if evidence["namespace"] is not None:
        files.update(original.open_reference(evidence["namespace"][key]) for key in
            ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    from .static_evidence_transport import _path
    for path in files:
        _path(path)
    for path in trees:
        _path(path, directory=True)
    return files, trees


def preparation_roots(value: Mapping[str, Any]) -> list[Path]:
    evidence = value["whole_graph_get_evidence"]
    context = load_context(original.open_reference(evidence["context"]).parent)
    roots_value = {Path(evidence["root"]), *sealed_context_roots(context)}
    if evidence["namespace"] is not None:
        roots_value.update(original.open_reference(evidence["namespace"][key]).parent for key in
            ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    return sorted(roots_value)


def roots(context: Context) -> list[Path]:
    values = sealed_context_roots(context)
    for ref in acquisition_status(context)["terminal_prefix"]:
        terminal = original.open_reference(ref)
        payload = _terminal_payload(context, terminal)
        if payload["get_evidence_root"] is not None:
            values.add(Path(payload["get_evidence_root"]))
        if payload["namespace"] is not None:
            values.update(original.open_reference(payload["namespace"][key]).parent for key in
                ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
        if payload["outcome"] == "admitted":
            workload = get._load(get._read(original.open_reference(payload["prepared_workload"])))
            if is_whole(workload["preparation"]):
                values.update(preparation_roots(workload["preparation"]))
    return sorted(values)


def terminal_inputs(enrollment: Path, *, _context=None) -> tuple[set[Path], set[Path]]:
    """Fence every sealed context dependency and selected/inherited raw attempt.

    Later mutable decisions remain outside the inventory. Discovery pass files,
    original discovery Source and all completed GET raw trees are included.
    """
    from . import rapid_rolling_capture as rolling
    from .static_evidence_transport import _path
    rolling._verify_enrollment(enrollment)
    files, trees, seen, terminals = set(), set(), set(), {}

    def context_inputs(context):
        if context.root in seen:
            return
        seen.add(context.root)
        files.add(context.root / "provenance.json")
        if isinstance(context, static.Context):
            for key in ("source_list", "profile", "candidate_order"):
                files.add(original.open_reference(context.provenance[key]))
        else:
            context_inputs(context.original)
            for ref in context.provenance["plans"]:
                plan_files, plan_trees = inputs.plan_files(inputs.reopen(ref))
                files.update(plan_files)
                trees.update(plan_trees)
            for ref in context.provenance["graph_inputs"].values():
                raw_files, raw_trees = inputs.input_files(inputs.reopen(ref))
                files.update(raw_files)
                trees.update(raw_trees)
            for item in context.provenance["failed_discoveries"].values():
                files.update(inputs.reopen(ref) for ref in item["files"].values())
                failure = inputs.load_failure(inputs.reopen(item["record"]))
                plan_path = inputs.reopen(failure["plan"])
                files.add(plan_path)
                trees.add(Path(item["record"]["path"]).parent)
        for ref in context.provenance["inherited_terminals"]:
            terminals[original.open_reference(ref)] = context
        parent_ref = context.provenance["parent_context"]
        if parent_ref is not None:
            parent_root = original.open_reference(parent_ref).parent
            parent = load_context(parent_root) if isinstance(context, Context) else static.load_context(parent_root)
            context_inputs(parent)

    path = enrollment
    while True:
        batch = rolling.admission._unpack(get._read(path), rolling.ENROLLMENT_TYPE)
        policy = rolling.verify_policy(rolling._open_ref(batch["policy"]).parent)
        if policy["contract"] != rolling.STATIC_CONTRACT:
            raise ValueError("whole graph raw fence cannot import a browser study")
        context = rolling._context_for_policy(policy, Path(batch["admission_root"]))
        context_inputs(context)
        for decision in batch["decisions"]:
            terminals[rolling._open_ref(decision["terminal"])] = context
        if batch["parent"] is None:
            break
        path = rolling._open_ref(batch["parent"])
    for terminal, context in terminals.items():
        rolling._verify_terminal(context, terminal)
        value = _terminal_payload(context, terminal) if isinstance(context, Context) else static.receipts._unpack(get._read(terminal), static.TERMINAL_TYPE)
        trees.add(terminal.parent)
        if value["get_evidence_root"] is not None:
            trees.add(Path(value["get_evidence_root"]))
        if value["namespace"] is not None:
            files.update(original.open_reference(value["namespace"][key]) for key in
                ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    for path in files:
        _path(path)
        if _context is not None:
            _context.watch_file(path)
    for path in trees:
        _path(path, directory=True)
        if _context is not None:
            _context.watch_tree(path)
    return files, trees
