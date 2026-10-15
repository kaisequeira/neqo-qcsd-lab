"""Exact outgoing clock-frame joins; synthetic receipts grant no capture credit.

The original fixture builders and full kernel validators remain in use. No
validator, raw gate, parser, clock reader or wire receipt is mocked here. The
modern packet timestamp uses its own post-TX MONOTONIC lower offset, while the
controller terminal timestamp uses the same provisional TX upper TAI bound.
"""
from copy import deepcopy

import pytest

from qcsd_lab import buflo_handoff as handoff, fidelity, kernel_tx
from tests import test_buflo_cadence64_budget640 as cadence
from tests import test_kernel_tx as wire
from tests import test_kernel_tx_layered_feedback as layered


DEFENSE_START_NS = 110_144_615


def clock_case(drift_ns=8_000):
    """Retain a fully valid layered receipt with an exact local offset drift."""
    raw = layered.layered_receipt()
    item = raw["jobs"][0]["items"][0]
    # Change a genuinely retained clock observation, and its exact diagnostic
    # envelope. The TAI/realtime transmission proof and all windows are whole.
    item["post_tx_clock_phase"]["monotonic"]["clock_ns"] += drift_ns
    mapping = raw["clock_mapping"]
    mapping["effective_monotonic_offset_lower_ns"] -= drift_ns
    mapping["max_observed_offset_drift_ns"] = drift_ns
    run = cadence.native_run(raw)
    run["migration_commit"] = "01e226fb43000691acbda57feb338855b26e66ca"
    run["runner_wakeup_metrics"]["semantics"] = fidelity.RUNNER_WAKEUP_V22_LAYERED_SEMANTICS
    run["defense_start_monotonic_ns"] = DEFENSE_START_NS

    assert raw["schema_version"] == 14 and mapping["schema_version"] == 6
    assert run["runner_wakeup_metrics"]["schema_version"] == 22
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    assert fidelity._runner_wakeup_metrics_valid(run["runner_wakeup_metrics"])
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    evidence, capture, packets = wire._evidence(raw, capture_times=[
        wire._RELEASE_TAI_NS + 3_400_000, wire._RELEASE_TAI_NS + 6_200_000])
    assert kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))

    upper = item["provisional_tx_software_tai_upper_ns"]
    phase = item["post_tx_clock_phase"]["monotonic"]
    lower_offset = phase["tai_before_ns"] - phase["clock_ns"]
    terminal_us = (upper - raw["defense_start_tai_ns"]) // 1_000
    packet_us = (DEFENSE_START_NS + upper - lower_offset
                 - raw["defense_start_monotonic_ns"]) // 1_000
    schedule = [{"direction": "outgoing", "slot_id": "0", "connection": str(item["endpoint"]),
        "size": "1200", "target_time_us": "0", "satisfaction": "satisfied",
        "qcsd_outcome_schema_version": "3", "terminal_defense_elapsed_us": str(terminal_us)}]
    packet = {field: "0" for field in handoff._COMPOSITION_FIELDS}
    packet.update(direction="outgoing", slot_id="0", connection=str(item["endpoint"]), scheduled_target="1200",
        satisfaction="satisfied", qcsd_outcome_schema_version="2", send_policy="exact",
        desired_udp_bytes="1200", observed_udp_length="1200", observed_udp_bytes="1200",
        monotonic_us=str(packet_us), lateness_us="3000")
    return run, raw, schedule, [packet]


def terminal_times(run, schedule, packets):
    return handoff._buflo_terminal_times(schedule, packets,
        defense_start_monotonic_ns=DEFENSE_START_NS, run=run)


@pytest.mark.parametrize("drift_ns", [0, 1_000, 8_000])
def test_valid_modern_dual_clock_pair_uses_exact_provisional_physical_bound(drift_ns):
    run, raw, schedule, packets = clock_case(drift_ns)
    before = deepcopy((run, schedule, packets))
    assert terminal_times(run, schedule, packets) == {"outgoing": [3100], "incoming": []}
    assert (run, schedule, packets) == before
    assert int(packets[0]["monotonic_us"]) == (DEFENSE_START_NS + 3_100_000 + drift_ns) // 1000
    assert raw["jobs"][0]["items"][0]["provisional_tx_software_tai_upper_ns"] == wire._RELEASE_TAI_NS + 3_100_000


@pytest.mark.parametrize("drift_ns", [2_000, 8_000])
def test_same_physical_pair_without_modern_proof_keeps_legacy_exact_refusal(drift_ns):
    _, _, schedule, packets = clock_case(drift_ns)
    with pytest.raises(ValueError, match="controller terminal time differs from its packet"):
        handoff._buflo_terminal_times(schedule, packets, defense_start_monotonic_ns=DEFENSE_START_NS)


def test_legacy_aligned_clock_pair_still_uses_original_exact_join():
    _, _, schedule, packets = clock_case(0)
    assert handoff._buflo_terminal_times(schedule, packets,
        defense_start_monotonic_ns=DEFENSE_START_NS) == {"outgoing": [3100], "incoming": []}


@pytest.mark.parametrize("mutation", [
    "provisional-upper", "epoch-tai", "epoch-monotonic", "phase-clock", "phase-bound",
    "mapping-schema", "wakeup-schema", "wakeup-semantics", "incoming-policy", "incoming-window",
    "process-origin", "future-raw", "boolean-raw", "missing-phase", "missing-main", "duplicate-main",
])
def test_claimed_modern_proof_mutations_refuse_without_legacy_fallback(mutation):
    run, raw, schedule, packets = clock_case()
    item = raw["jobs"][0]["items"][0]
    if mutation == "provisional-upper": item["provisional_tx_software_tai_upper_ns"] += 1
    elif mutation == "epoch-tai": raw["defense_start_tai_ns"] += 1
    elif mutation == "epoch-monotonic": raw["defense_start_monotonic_ns"] += 1
    elif mutation == "phase-clock": item["post_tx_clock_phase"]["monotonic"]["clock_ns"] += 1
    elif mutation == "phase-bound": item["post_tx_clock_phase"]["monotonic"]["tai_before_ns"] += 1
    elif mutation == "mapping-schema": raw["clock_mapping"]["schema_version"] = 5
    elif mutation == "wakeup-schema": run["runner_wakeup_metrics"]["schema_version"] = 21
    elif mutation == "wakeup-semantics": run["runner_wakeup_metrics"]["semantics"] = fidelity.RUNNER_WAKEUP_V22_SEMANTICS
    elif mutation == "incoming-policy": run.pop(cadence.policy.FIELD)
    elif mutation == "incoming-window": raw["incoming_credit_release_window_ns"] += 1
    elif mutation == "process-origin": run["defense_start_monotonic_ns"] += 1
    elif mutation == "future-raw": raw["schema_version"] = 15
    elif mutation == "boolean-raw": raw["schema_version"] = True
    elif mutation == "missing-phase": item.pop("post_tx_clock_phase")
    elif mutation == "missing-main": raw["jobs"][0]["items"].pop(0)
    else: raw["jobs"][0]["items"].append(deepcopy(item))
    with pytest.raises(ValueError):
        terminal_times(run, schedule, packets)


def test_epoch_midpoint_is_required_even_when_original_raw_envelope_accepts_shift():
    run, raw, schedule, packets = clock_case()
    # The original raw reader permits an epoch anywhere in the diagnostic
    # envelope. The new exact frame join must also prove the producer midpoint.
    raw["defense_start_monotonic_ns"] += 1
    for job in raw["jobs"]:
        for field in ("release_monotonic_ns", "deadline_monotonic_ns", "incoming_deadline_monotonic_ns"):
            job[field] += 1
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    with pytest.raises(ValueError):
        terminal_times(run, schedule, packets)


@pytest.mark.parametrize("mutation", [
    "packet-time", "terminal-time", "slot", "endpoint", "target", "size",
    "missing-packet", "duplicate-packet", "duplicate-schedule",
])
def test_exact_clock_proof_cannot_borrow_another_slot_owner_packet_or_target(mutation):
    run, raw, schedule, packets = clock_case()
    if mutation == "packet-time": packets[0]["monotonic_us"] = str(int(packets[0]["monotonic_us"]) + 1)
    elif mutation == "terminal-time": schedule[0]["terminal_defense_elapsed_us"] = "3101"
    elif mutation == "slot": schedule[0]["slot_id"] = packets[0]["slot_id"] = "2"
    elif mutation == "endpoint": schedule[0]["connection"] = packets[0]["connection"] = str(1 - int(schedule[0]["connection"]))
    elif mutation == "target": schedule[0]["target_time_us"] = "1"
    elif mutation == "size": schedule[0]["size"] = "1199"
    elif mutation == "missing-packet": packets.clear()
    elif mutation == "duplicate-packet": packets.append(deepcopy(packets[0]))
    else: schedule.append(deepcopy(schedule[0]))
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    with pytest.raises(ValueError):
        terminal_times(run, schedule, packets)


@pytest.mark.parametrize("field,value", [("terminal_defense_elapsed_us", "5000"), ("lateness_us", "5000")])
def test_original_half_open_five_ms_outgoing_window_is_unchanged(field, value):
    run, _, schedule, packets = clock_case()
    (packets if field == "lateness_us" else schedule)[0][field] = value
    with pytest.raises(ValueError, match="half-open realization window"):
        terminal_times(run, schedule, packets)


def test_original_packet_build_time_cannot_follow_terminalization():
    run, _, schedule, packets = clock_case()
    packets[0]["lateness_us"] = "3101"
    with pytest.raises(ValueError, match="packet-build time follows controller terminalization"):
        terminal_times(run, schedule, packets)


def test_kernel_receipt_does_not_replace_independent_post_veth_deadline_gate():
    _, raw, _, _ = clock_case()
    evidence, capture, packets = wire._evidence(raw, capture_times=[
        wire._RELEASE_TAI_NS + 5_000_000, wire._RELEASE_TAI_NS + 6_200_000])
    assert kernel_tx.kernel_tx_evidence_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))
    assert not kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))
