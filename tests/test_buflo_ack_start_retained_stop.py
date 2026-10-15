"""Typed ACK64 stop metadata; original raw/common predicates are prerequisites.

These controls exercise the actual pure ledger and nested-state validators.
ROOT's retained four-file Native098 control supplies the full integration case.
"""
from copy import deepcopy

import pytest

from qcsd_lab import buflo_handoff as handoff
from qcsd_lab import buflo_evaluation as evaluation
from qcsd_lab import fidelity
from tests.test_capture_buflo_ack_start import startup


@pytest.fixture
def stopped():
    ready = startup()
    ready.update(period_us=64_000, armed_at_us=128_000, ready_at_us=100_000,
        ack_observed_at_us=90_000, startup_suppressed_opportunities=2)
    rows = []
    times = {"outgoing": [], "incoming": []}
    for target in range(0, 10_496_001, 64_000):
        for direction in ("outgoing", "incoming"):
            if direction == "incoming" and target < ready["armed_at_us"]:
                continue
            rows.append({"direction": direction, "size": "1200", "target_time_us": str(target)})
            times[direction].append(target + 1_000)
    times["incoming"][-1] = 10_510_000
    diagnostics = {"buflo_incoming_startup": ready,
        "buflo_schedule_stop_latched_at_us": 10_500_000,
        "buflo_terminal_subcell_latched_at_us": 10_520_000,
        "buflo_schedule_stop_scheduled_outgoing_cells": 165,
        "buflo_schedule_stop_terminal_outgoing_cells": 165,
        "buflo_schedule_stop_scheduled_incoming_cells": 163,
        "buflo_schedule_stop_terminal_incoming_cells": 162}
    return ready, diagnostics, rows, times


def nested(stopped):
    ready, diagnostics, rows, times = stopped
    ledger = handoff._buflo_ack_start_stop_drain_ledger(diagnostics, rows, times,
        incoming_startup=ready)
    return {"schema_version": 2, "incoming_startup": deepcopy(ready),
        "policy": fidelity.BUFLO_SCHEDULE_STOP_POLICY,
        "terminal_time_semantics": fidelity.BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS,
        "latched": True, "latched_at_us": 10_500_000, "available_bytes": 496,
        "required_bytes": 1200, "directions": ledger}


def test_exact_165_163_grid_joins_two_suppressed_startup_ticks(stopped):
    value = nested(stopped); original = deepcopy(stopped)
    assert fidelity._buflo_ack_start_schedule_stop_state_valid(value,
        terminal_latched_at_us=10_520_000)
    assert fidelity._buflo_local_abandon_schedule_stop_valid(value,
        terminal_latched_at_us=10_520_000)
    assert value["directions"]["incoming"]["drained_cells_after_stop"] == 1
    assert stopped == original
    ready, diagnostics, rows, times = stopped
    with pytest.raises(ValueError, match="paired stop schedule"):
        handoff._buflo_stop_drain_ledger(diagnostics, rows, times)
    assert not fidelity._buflo_schedule_stop_state_valid(value, terminal_latched_at_us=10_520_000)
    legacy = {key: val for key, val in value.items() if key not in {"schema_version", "incoming_startup"}}
    assert not fidelity._buflo_schedule_stop_state_valid(legacy, terminal_latched_at_us=10_520_000)


@pytest.mark.parametrize("change", ["missing-startup", "extra-startup", "float-version",
    "wrong-period", "wrong-suppression", "wrong-arm", "boolean-count", "count-mismatch",
    "different-last-target", "off-grid-last-target", "outgoing-drain", "terminal-after-latch"])
def test_typed_stop_requires_the_entire_startup_count_and_chronology_binding(stopped, change):
    value = nested(stopped)
    if change == "missing-startup": value.pop("incoming_startup")
    elif change == "extra-startup": value["incoming_startup"]["operator_waiver"] = True
    elif change == "float-version": value["schema_version"] = 2.0
    elif change == "wrong-period": value["incoming_startup"]["period_us"] = 20_000
    elif change == "wrong-suppression": value["incoming_startup"]["startup_suppressed_opportunities"] = 3
    elif change == "wrong-arm": value["incoming_startup"]["armed_at_us"] = 192_000
    elif change == "boolean-count": value["directions"]["incoming"]["scheduled_cells_at_stop"] = True
    elif change == "count-mismatch": value["directions"]["outgoing"]["scheduled_cells_at_stop"] = 166
    elif change == "different-last-target": value["directions"]["incoming"]["last_scheduled_target_us"] -= 64_000
    elif change == "off-grid-last-target":
        for state in value["directions"].values(): state["last_scheduled_target_us"] += 1
    elif change == "outgoing-drain": value["directions"]["outgoing"]["drained_cells_after_stop"] = 1
    else: value["directions"]["incoming"]["last_terminal_at_us"] = 10_520_001
    assert not fidelity._buflo_local_abandon_schedule_stop_valid(value,
        terminal_latched_at_us=10_520_000)


@pytest.mark.parametrize("change", ["gap", "duplicate", "shift", "different-final",
    "changed-diagnostic-startup", "bad-terminal-snapshot", "terminal-after-latch"])
def test_actual_schedule_grid_and_drain_rows_cannot_be_relabelled(stopped, change):
    ready, diagnostics, rows, times = deepcopy(stopped)
    incoming = next(index for index, row in enumerate(rows) if row["direction"] == "incoming")
    if change == "gap": rows.pop(incoming)
    elif change == "duplicate": rows.append(dict(rows[incoming]))
    elif change == "shift": rows[incoming]["target_time_us"] = "128001"
    elif change == "different-final": rows[-1]["target_time_us"] = "10560000"
    elif change == "changed-diagnostic-startup":
        diagnostics["buflo_incoming_startup"] = {**ready, "ready_at_us": 100_001}
    elif change == "bad-terminal-snapshot": diagnostics["buflo_schedule_stop_terminal_incoming_cells"] = 164
    else: times["incoming"][-1] = 10_520_001
    with pytest.raises(ValueError):
        handoff._buflo_ack_start_stop_drain_ledger(diagnostics, rows, times, incoming_startup=ready)


def test_evaluation_joins_both_actual_direction_totals_only_for_the_new_algorithm(stopped):
    value = {"schema_version": 4, "terminal_latched_at_us": 10_520_000,
        "schedule_stop": nested(stopped)}
    metrics = {"outgoing": {"scheduled_cells": 165, "satisfaction_counts": {"satisfied": 165}},
        "incoming": {"scheduled_cells": 163, "satisfaction_counts": {"satisfied": 163}}}
    assert evaluation._algorithm_buflo_schedule_stop_state_valid(value, metrics, algorithm_schema=5)
    assert not evaluation._current_buflo_schedule_stop_state_valid(value, metrics)
    for schema in (4, 5.0, True):
        assert not evaluation._algorithm_buflo_schedule_stop_state_valid(value, metrics, algorithm_schema=schema)


@pytest.mark.parametrize("change", ["scheduled", "boolean-scheduled", "satisfaction-total",
    "boolean-satisfaction", "negative-satisfaction", "missing-direction", "wrong-state-schema"])
def test_evaluation_cannot_hide_a_changed_final_direction_metric(stopped, change):
    value = {"schema_version": 4, "terminal_latched_at_us": 10_520_000,
        "schedule_stop": nested(stopped)}
    metrics = {"outgoing": {"scheduled_cells": 165, "satisfaction_counts": {"satisfied": 165}},
        "incoming": {"scheduled_cells": 163, "satisfaction_counts": {"satisfied": 163}}}
    if change == "scheduled": metrics["incoming"]["scheduled_cells"] = 165
    elif change == "boolean-scheduled": metrics["incoming"]["scheduled_cells"] = True
    elif change == "satisfaction-total": metrics["incoming"]["satisfaction_counts"]["satisfied"] = 162
    elif change == "boolean-satisfaction": metrics["incoming"]["satisfaction_counts"]["satisfied"] = True
    elif change == "negative-satisfaction": metrics["incoming"]["satisfaction_counts"]["satisfied"] = -1
    elif change == "missing-direction": metrics.pop("incoming")
    else: value["schema_version"] = 3
    assert not evaluation._algorithm_buflo_schedule_stop_state_valid(value, metrics, algorithm_schema=5)
