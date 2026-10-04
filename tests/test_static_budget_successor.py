"""HOST emitter-contract fixtures, never real GETs or scientific credit."""
from copy import deepcopy
from pathlib import Path

import pytest

from qcsd_lab import supplied_static_budget_successor as budget
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_bootstrap_get as bootstrap
from qcsd_lab import supplied_static_get as get
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as prep
from tests.test_supplied_static_get import actual_contract_fixture, load, write, reseal_outputs
from tests.test_supplied_static_preparation import fixed_graph, POLICIES


@pytest.fixture
def budget_fixture(fixed_graph, tmp_path, monkeypatch):
    old_root, arguments, _ = fixed_graph
    supplied = load(old_root / "source-list.json")
    # Fifty-two prior immutable decisions, then the existing complete graph.
    source = [{"crUX_domain": f"earlier-{i}.example", "resources": []} for i in range(1, 53)] + supplied
    path = tmp_path / "complete-same-catalogue.json"
    write(path, source)
    prefix = tmp_path / "old-static-prefix"
    prefix.mkdir()
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-03T23:59:59Z")
    static.initialize_context(prefix, path, source_sha256=graph.digest(path.read_bytes()),
        expected_runtime=arguments["expected_runtime"])
    context = static.load_context(prefix)
    for position in range(1, 53):
        static.record_input_rejection(context, position)
    (old_root / "source-list.json").write_bytes(path.read_bytes())
    neutral, binding, primary, full = bootstrap._inputs(path.read_bytes(), graph.digest(path.read_bytes()), arguments["domain"])
    write(old_root / "input-binding.json", binding)
    declaration = load(old_root / "declaration.json")
    declaration.update(context=prep.reference(prefix / "provenance.json"),
        source_sha256=graph.digest(path.read_bytes()), candidate_queue_position=53, candidate_source_position=53,
        input_binding_sha256=graph.digest((old_root / "input-binding.json").read_bytes()))
    write(old_root / "declaration.json", declaration)
    for child in (old_root / "bootstrap", old_root):
        started = load(child / "native-started.json")
        started["declaration_sha256"] = graph.digest((old_root / "declaration.json").read_bytes())
        write(child / "native-started.json", started)
    run = load(old_root / "native/run.json")
    run["completion_status"] = "partial"
    run["responses"][1].update(bytes=16_778_994, content_length=46_150_619, complete=False, outcome="response_limit")
    write(old_root / "native/run.json", run)
    reseal_outputs(old_root)
    (old_root / "full-get-proof.json").unlink()
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-04T00:00:20Z")
    successor = tmp_path / "budget-successor"
    before = {str(path): path.read_bytes() for path in prefix.rglob("*") if path.is_file()}
    before.update({str(path): path.read_bytes() for path in old_root.rglob("*") if path.is_file()})
    budget.initialize_context(successor, original_context=prefix, retained_attempt=old_root)
    return budget.load_context(successor), old_root, before


def test_budget_epoch_preserves_52_ordered_decisions_old_partial_and_full_original_graph(budget_fixture):
    context, old_root, before = budget_fixture
    assert all(Path(path).read_bytes() == raw for path, raw in before.items())
    assert context.active.source_bytes == context.original.source_bytes
    assert context.active.candidates == context.original.candidates
    assert budget.identity(context) == static.identity(context.original)
    assert budget.context_limits(context)["max_response_bytes"] == 16_777_216
    assert static.context_limits(context.active)["max_response_bytes"] == 67_108_864
    assert static.context_limits(context.active)["capture_megabytes"] == 256
    assert static.context_limits(context.original)["capture_megabytes"] == 64
    assert static.context_limits(context.active)["timeout_seconds"] == 120
    status = budget.acquisition_status(context)
    assert status["terminal_count"] == 52 and status["next_candidate_position"] == 53
    assert status["input-ineligible"] == 52 and status["admitted"] == 0
    assert not status["scientific_credit"] and status["formal_accepted_trace_count"] == 0
    assert not (old_root / "full-get-proof.json").exists()
    assert not budget.terminal_path(context, 53).exists()
    assert context.provenance["retained_attempt"]["outcome"] == "retained-incomplete-budget-attempt-no-site-decision"


@pytest.mark.parametrize("change", ["budget", "recording", "deadline", "old-terminal", "old-raw", "old-primary", "successor-source", "order", "position"])
def test_resealed_budget_prefix_or_raw_mutations_reject(budget_fixture, change):
    context, old_root, _ = budget_fixture
    path = context.root / "provenance.json"
    value = static.receipts._unpack(path.read_bytes(), budget.CONTEXT_TYPE)
    if change in {"budget", "recording", "deadline"}:
        field = {"budget": "max_response_bytes", "recording": "capture_megabytes", "deadline": "timeout_seconds"}[change]
        value["capture_limits"][field] = 1
    elif change == "old-terminal":
        value["inherited_terminals"][0] = value["inherited_terminals"][1]
    elif change == "old-raw":
        (old_root / "native.stdout.log").write_bytes(b"changed original attempt")
    elif change == "old-primary":
        run = load(old_root / "native/run.json")
        run["responses"][1]["outcome"] = "succeeded"
        write(old_root / "native/run.json", run)
        reseal_outputs(old_root)
    elif change == "successor-source":
        source = load(context.active.root / "source-list.json")
        source[-1]["resources"].pop()
        write(context.active.root / "source-list.json", source)
    elif change == "order":
        value["inherited_terminals"].reverse()
    else:
        value["first_prospective_position"] = 54
    path.write_bytes(static.receipts._json(static.receipts._bind(budget.CONTEXT_TYPE, value)))
    with pytest.raises(ValueError):
        budget.load_context(context.root)


def test_q53_cannot_be_accounted_from_the_old_partial_or_skipped(budget_fixture):
    context, _, _ = budget_fixture
    with pytest.raises(ValueError, match="skip/repeat"):
        budget.account_terminal(context, 54)
    with pytest.raises((ValueError, OSError)):
        budget.account_terminal(context, 53)
    assert budget.acquisition_status(context)["next_candidate_position"] == 53


def test_existing_get_cap_contract_needs_no_native_or_original_producer_change(budget_fixture):
    context, _, _ = budget_fixture
    command = bootstrap._command(context.active.root / "fresh-get-53", budget.RESPONSE_BYTES, 120, get.RESPONSE_POLICY)
    assert command[command.index("--max-response-bytes") + 1] == "67108864"
    assert command[command.index("--timeout-seconds") + 1] == "120"
    assert command[command.index("--defense") + 1] == "none"
    assert context.active.provenance["runtime_binding"] == context.original.provenance["runtime_binding"]


def test_capture_groups_cannot_silently_mix_original_and_new_response_budgets(monkeypatch):
    limits = static.capture_limits(16_777_216, 64)
    raised = static.capture_limits(budget.RESPONSE_BYTES, budget.RECORDING_MEGABYTES)
    old = {"preparation": {"max_response_bytes": 16_777_216}, "resources": []}
    new = {"preparation": {"data_role": budget.ROLE, budget.FIELD: {"capture_limits": raised}}, "resources": []}
    # This unit concerns group selection only. Full real reopening is exercised
    # separately by new-class account/preparation integration below.
    monkeypatch.setattr(budget, "validate_preparation", lambda value, resources: None)
    assert budget.selected_capture_limits([old], limits) == limits
    assert budget.selected_capture_limits([new], limits) == raised
    with pytest.raises(ValueError, match="homogeneous"):
        budget.selected_capture_limits([old, new], limits)
    with pytest.raises(ValueError, match="unrecognized"):
        budget.selected_capture_limits([{"preparation": {"max_response_bytes": 67_108_864}}], limits)
