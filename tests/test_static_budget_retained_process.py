"""Retained incomplete attempts still require genuine closed Native processes."""
from pathlib import Path
import pytest

from qcsd_lab import supplied_static_budget_successor as budget
from tests.test_static_budget_successor import budget_fixture, fixed_graph, actual_contract_fixture, load, write


def test_rehashed_retained_process_contract_mutations_reject(budget_fixture):
    context, retained, _ = budget_fixture
    for phase, change in [("bootstrap", "argv"), ("bootstrap", "environment"),
            ("full", "argv"), ("full", "environment"), ("full", "schema"), ("full", "elapsed"), ("full", "chronology")]:
        child = retained / "bootstrap" if phase == "bootstrap" else retained
        path = child / ("native-completed.json" if change == "elapsed" else "native-started.json")
        original = path.read_bytes()
        value = load(path)
        if change == "elapsed":
            value["elapsed_ns"] = True
        else:
            if change == "argv":
                value["command"][value["command"].index("--max-response-bytes") + 1] = "1"
            elif change == "environment":
                value["environment"]["QCSD_PUBLIC_ORIGIN_ONLY"] = "0"
            elif change == "schema":
                value["schema_version"] = True
            else:
                # Still later than declaration; earlier than bootstrap closure.
                value["started_at"] = load(retained / "bootstrap/native-started.json")["started_at"]
        try:
            write(path, value)
            with pytest.raises(ValueError):
                budget._old_limit_attempt(retained, context.original, 53)
        finally:
            path.write_bytes(original)
        # Restored exact bytes must independently remain valid between cases.
        assert budget._old_limit_attempt(retained, context.original, 53)["site_credit"] == 0


def test_exact_completed_primary_and_partial_full_process_still_authenticate(budget_fixture):
    context, retained, _ = budget_fixture
    value = budget._old_limit_attempt(retained, context.original, 53)
    assert value["outcome"] == "retained-incomplete-budget-attempt-no-site-decision"
    assert value["site_credit"] == 0 and value["formal_accepted_trace_count"] == 0
    assert not (retained / "full-get-proof.json").exists()
