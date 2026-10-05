"""Real first validators over synthetic closed Native emitter-contract inputs.

No GET/Native/Docker process runs. The exact Core account body, prior ordered
decisions, complete graphs and byte/mode/membership fences execute unchanged.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_admission_operation_facts as observed
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_budget_successor as budget
from qcsd_lab import static_budget_capture as capture
from tests.test_static_budget_capture import admitted_budget
from tests.test_static_budget_successor import budget_fixture
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_get import actual_contract_fixture
from tools import rapid_static_accounting as tool


@pytest.fixture
def ready_child(budget_fixture, tmp_path, monkeypatch):
    # Postpone only the wrapper publication in the established emitter fixture.
    # Its Native raw validators and ordinary admission all execute genuinely.
    with monkeypatch.context() as setup:
        setup.setattr(capture, "account_terminal", lambda context, position: static.terminal_path(context.active, position))
        context, child, raw, before = admitted_budget.__wrapped__(budget_fixture, tmp_path, setup)
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-04T00:00:31Z")
    assert child == static.terminal_path(context.active, 53)
    assert not budget.terminal_path(context, 53).exists()
    return context, child, raw, before


def test_public_budget_account_one_first_proof_per_prior_terminal_and_fresh_action(ready_child, monkeypatch):
    context, child, raw, before = ready_child
    counts = Counter()
    original = static._verify_terminal_uncached
    def count(path, current):
        counts[(str(path), str(current.root))] += 1
        return original(path, current)
    monkeypatch.setattr(static, "_verify_terminal_uncached", count)
    with observed.action():
        for _ in range(6):
            current = budget.load_context(context.root)
            assert budget.acquisition_status(current)["next_candidate_position"] == 53
            static.verify_terminal(child, current.active)
        result = tool.account_budget(context.root, 53)
        assert result["outcome"] == "admitted" and result["scientific_credit"] is False
        assert budget.acquisition_status(budget.load_context(context.root))["terminal_count"] == 53
    assert len(counts) == 53 and set(counts.values()) == {1}
    assert all(Path(name).read_bytes() == value for name, value in before.items())
    first = sum(counts.values())
    with observed.action():
        assert budget.acquisition_status(budget.load_context(context.root))["terminal_count"] == 53
    assert sum(counts.values()) == first + 53
    with pytest.raises(ValueError, match="skip or repeat"):
        tool.account_budget(context.root, 53)


@pytest.mark.parametrize("change", ["bytes", "mode", "membership"])
def test_mutated_complete_raw_tree_refuses_before_account_parent_claim(ready_child, monkeypatch, change):
    context, _, raw, _ = ready_child
    original = observed.before_publication
    def mutate_then_close():
        path = raw / "native.stdout.log"
        if change == "bytes":
            path.write_bytes(path.read_bytes() + b"changed")
        elif change == "mode":
            path.chmod(0o600 if path.stat().st_mode & 0o777 != 0o600 else 0o644)
        else:
            (raw / "unregistered-raw-file.json").write_text("{}")
        original()
    monkeypatch.setattr(observed, "before_publication", mutate_then_close)
    with pytest.raises(ValueError, match="changed"):
        tool.account_budget(context.root, 53)
    assert not budget.terminal_path(context, 53).parent.exists()


def test_bound_source_inventory_mutation_refuses_before_account_write(ready_child, monkeypatch, tmp_path):
    context, _, _, _ = ready_child
    files = {}
    for relative in sorted(tool._names()):
        path = tool.ROOT / relative
        files[relative] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "mode": path.stat().st_mode & 0o7777}
    inventory = tmp_path / "current-source-inventory.json"
    inventory.write_text(json.dumps({"files": files}))
    digest = hashlib.sha256(inventory.read_bytes()).hexdigest()
    args = tool.parser().parse_args(["--source-inventory", str(inventory), "--source-inventory-sha256", digest,
                                    "account-budget", "--context", str(context.root), "--position", "53"])
    original = observed.before_publication
    def mutate_then_close():
        inventory.write_bytes(inventory.read_bytes() + b" ")
        original()
    monkeypatch.setattr(observed, "before_publication", mutate_then_close)
    with pytest.raises(ValueError, match="changed"):
        tool.run(args)
    assert not budget.terminal_path(context, 53).parent.exists()


def test_cycle_and_missing_or_skipped_child_cannot_gain_memo_authority(budget_fixture):
    context, _, _ = budget_fixture
    with observed.action():
        original = static.load_context(context.original.root)
        with pytest.raises(ValueError, match="cycle"):
            static.load_context(original.root, _seen=frozenset({original.root}))
    with pytest.raises(ValueError, match="skip or repeat"):
        tool.account_budget(context.root, 54)
    with pytest.raises((ValueError, OSError)):
        tool.account_budget(context.root, 53)
    assert not budget.terminal_path(context, 53).parent.exists()


def test_unscoped_original_api_calls_first_validator_each_time(ready_child, monkeypatch):
    context, child, _, _ = ready_child
    original = static._verify_terminal_uncached
    calls = []
    def count(path, current):
        calls.append(path)
        return original(path, current)
    monkeypatch.setattr(static, "_verify_terminal_uncached", count)
    static.verify_terminal(child, context.active)
    static.verify_terminal(child, context.active)
    assert calls.count(child) == 2


@pytest.mark.parametrize("mutated", [False, True])
def test_public_admit_closes_before_fresh_directory_claim(budget_fixture, tmp_path, monkeypatch, mutated):
    # Build the complete synthetic Native raw proof, postponing only its two
    # publications. The new public action performs ordinary admission itself.
    with monkeypatch.context() as setup:
        setup.setattr(static, "admit", lambda context, position, *a, **k: static.terminal_path(context, position))
        setup.setattr(capture, "account_terminal", lambda context, position: static.terminal_path(context.active, position))
        context, child, raw, _ = admitted_budget.__wrapped__(budget_fixture, tmp_path, setup)
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-04T00:00:31Z")
    assert not child.parent.exists()
    from tests.test_supplied_static_preparation import POLICIES
    policy = tmp_path / "fixed-policies.json"
    policy.write_text(json.dumps(POLICIES))
    files = {relative: {"sha256": hashlib.sha256((tool.ROOT / relative).read_bytes()).hexdigest(),
                        "mode": (tool.ROOT / relative).stat().st_mode & 0o7777}
             for relative in sorted(tool._names())}
    inventory = tmp_path / "current-source-inventory.json"
    inventory.write_text(json.dumps({"files": files}))
    args = tool.parser().parse_args(["--source-inventory", str(inventory), "--source-inventory-sha256",
        hashlib.sha256(inventory.read_bytes()).hexdigest(), "admit", "--context", str(context.active.root),
        "--position", "53", "--get-root", str(raw), "--traffic-policies", str(policy)])
    if mutated:
        original = observed.before_publication
        def mutate_then_close():
            (raw / "native.stdout.log").write_bytes(b"changed after full proof")
            original()
        monkeypatch.setattr(observed, "before_publication", mutate_then_close)
        with pytest.raises(ValueError, match="changed"):
            tool.run(args)
        assert not child.parent.exists()
    else:
        result = tool.run(args)
        assert result["outcome"] == "admitted" and result["scientific_credit"] is False
        assert Path(result["terminal"]) == child and static.verify_terminal(child, context.active)["outcome"] == "admitted"
