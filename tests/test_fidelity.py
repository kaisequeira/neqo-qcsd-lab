from __future__ import annotations

import json
from copy import deepcopy

import pytest

from qcsd_lab.fidelity import (
    _schedule_realization_metrics,
    fidelity_eligible,
    reconcile_direct_runner_artifacts,
)


def test_direct_runner_reconciliation_preserves_packet_and_tail_evidence(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="incoming")

    result = reconcile_direct_runner_artifacts(run, packets, trace)

    assert result.evidence_eligible is True
    assert result.metrics["direct_runner_reconciled"] is True
    assert result.metrics["direct_runner_packets"] == 2
    assert result.metrics["direct_matched_packets"] == 2
    assert result.metrics["direct_unmatched_tail_packets"] == 1
    assert result.metrics["direct_unmatched_tail_bytes"] == 100
    assert result.metrics["direct_timestamp_error_max_ns"] == 0
    assert result.metrics["direct_clock_model"] == "constant-offset"
    assert result.metrics["direct_clock_segment_count"] == 1
    assert result.metrics["direct_clock_step_count"] == 0
    assert result.metrics["direct_trace_sha256"]
    assert result.metrics["direct_runner_packets_sha256"]


def test_direct_runner_reconciliation_rejects_unrecorded_outgoing_tail(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="outgoing")

    with pytest.raises(ValueError, match="unrecorded outgoing tail"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_direct_runner_reconciliation_accepts_supported_positive_clock_step(tmp_path):
    offsets = [0] * 32 + [75_000_000] * 32
    times = _clock_epoch_times(2)
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    result = reconcile_direct_runner_artifacts(run, packets, trace)

    assert result.evidence_eligible is True
    assert result.metrics["direct_timestamp_tolerance_ns"] == 10_000_000
    assert result.metrics["direct_clock_model"] == "positive-abrupt-steps"
    assert result.metrics["direct_clock_segment_count"] == 2
    assert result.metrics["direct_clock_step_count"] == 1
    assert result.metrics["direct_timestamp_error_max_ns"] == 0
    assert [segment["packets"] for segment in result.metrics["direct_clock_segments"]] == [
        32,
        32,
    ]
    assert result.metrics["direct_clock_steps"][0]["observed_boundary_delta_ns"] == 75_000_000
    assert result.metrics["direct_clock_steps"][0]["epoch_offset_delta_ns"] == 75_000_000


def test_direct_runner_reconciliation_accepts_repeated_cadenced_clock_steps(tmp_path):
    offsets = [0] * 32 + [75_000_000] * 32 + [150_000_000] * 32
    times = _clock_epoch_times(3)
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    result = reconcile_direct_runner_artifacts(run, packets, trace)

    assert result.evidence_eligible is True
    assert result.metrics["direct_clock_segment_count"] == 3
    assert result.metrics["direct_clock_step_count"] == 2
    assert [step["runner_time_ns"] for step in result.metrics["direct_clock_steps"]] == [
        30_000_000_000,
        60_000_000_000,
    ]


@pytest.mark.parametrize(("tail_packets", "adjustment_ns"), [(3, 791_000_000), (1, 835_000_000)])
def test_direct_runner_reconciliation_accepts_end_anchored_sparse_positive_tail_step(
    tmp_path,
    tail_packets,
    adjustment_ns,
):
    packet_count = 32 + tail_packets
    times = [packet * 20_000_000 for packet in range(packet_count)]
    offsets = [0] * 32 + [adjustment_ns] * tail_packets
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    result = reconcile_direct_runner_artifacts(
        run,
        packets,
        trace,
        clock_anchors=_clock_anchors(adjustment_ns),
    )

    assert result.evidence_eligible is True
    assert result.metrics["direct_clock_model"] == "positive-abrupt-steps"
    assert result.metrics["direct_clock_step_count"] == 1
    assert result.metrics["direct_clock_end_anchor_adjustment_ns"] == adjustment_ns
    assert result.metrics["direct_clock_end_anchor_used"] is True
    assert result.metrics["direct_clock_steps"][0]["end_anchor_corroborated"] is True


def test_direct_runner_reconciliation_rejects_sparse_positive_tail_without_end_anchors(tmp_path):
    times = [packet * 20_000_000 for packet in range(33)]
    offsets = [0] * 32 + [835_000_000]
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="requires realtime/monotonic end-anchor"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_direct_runner_reconciliation_rejects_sparse_positive_tail_with_mismatched_end_anchor(
    tmp_path,
):
    times = [packet * 20_000_000 for packet in range(33)]
    offsets = [0] * 32 + [835_000_000]
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="does not match.*end-anchor adjustment"):
        reconcile_direct_runner_artifacts(
            run,
            packets,
            trace,
            clock_anchors=_clock_anchors(800_000_000),
        )


def test_direct_runner_reconciliation_rejects_well_supported_out_of_range_step_with_anchor(
    tmp_path,
):
    times = [packet * 20_000_000 for packet in range(96)]
    offsets = [0] * 32 + [791_000_000] * 64
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="well-supported.*outside the 50--100 ms bound"):
        reconcile_direct_runner_artifacts(
            run,
            packets,
            trace,
            clock_anchors=_clock_anchors(791_000_000),
        )


def test_direct_runner_reconciliation_keeps_end_anchor_tolerance_fixed_at_ten_ms(tmp_path):
    times = [packet * 20_000_000 for packet in range(33)]
    offsets = [0] * 32 + [835_000_000]
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="does not match.*end-anchor adjustment"):
        reconcile_direct_runner_artifacts(
            run,
            packets,
            trace,
            timestamp_tolerance_ns=100_000_000,
            clock_anchors=_clock_anchors(824_000_000),
        )


@pytest.mark.parametrize("kind", ["negative", "gradual"])
def test_direct_runner_reconciliation_rejects_negative_step_and_drift_with_end_anchors(
    tmp_path,
    kind,
):
    if kind == "negative":
        times = _clock_epoch_times(2)
        offsets = [75_000_000] * 32 + [0] * 32
        anchors = _clock_anchors(-75_000_000)
        expected = "negative clock step"
    else:
        times = [index * 20_000_000 for index in range(64)]
        offsets = [index * 500_000 for index in range(64)]
        anchors = _clock_anchors(offsets[-1])
        expected = "timestamp mismatch"
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match=expected):
        reconcile_direct_runner_artifacts(
            run,
            packets,
            trace,
            clock_anchors=anchors,
        )


def test_direct_runner_reconciliation_rejects_clock_step_without_supported_epochs(tmp_path):
    times = [packet * 10_000_000 for packet in range(32)] + [
        30_000_000_000 + packet * 10_000_000 for packet in range(32)
    ]
    offsets = [0] * 32 + [75_000_000] * 32
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="clock epoch lacks minimum support"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_direct_runner_reconciliation_rejects_clock_step_without_packet_context(tmp_path):
    times = [packet * 20_000_000 for packet in range(4)] + [
        30_000_000_000 + packet * 20_000_000 for packet in range(32)
    ]
    offsets = [0] * 4 + [75_000_000] * 32
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="insufficient consecutive support"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_direct_runner_reconciliation_rejects_uncadenced_repeated_steps(tmp_path):
    times = [
        epoch * 20_000_000_000 + packet * 20_000_000 for epoch in range(3) for packet in range(32)
    ]
    offsets = [0] * 32 + [75_000_000] * 32 + [150_000_000] * 32
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="required 25--35 s cadence"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_direct_runner_reconciliation_rejects_negative_clock_step(tmp_path):
    offsets = [75_000_000] * 32 + [0] * 32
    run, packets, trace = _clock_reconciliation_artifacts(
        tmp_path,
        _clock_epoch_times(2),
        offsets,
    )

    with pytest.raises(ValueError, match="negative clock step"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_direct_runner_reconciliation_rejects_gradual_clock_drift(tmp_path):
    times = [index * 20_000_000 for index in range(64)]
    offsets = [index * 500_000 for index in range(64)]
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="timestamp mismatch"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_direct_runner_reconciliation_rejects_single_clock_outlier(tmp_path):
    times = [index * 100_000_000 for index in range(64)]
    offsets = [0] * 64
    offsets[32] = 75_000_000
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="negative clock step"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_direct_runner_reconciliation_rejects_within_epoch_error_over_tolerance(tmp_path):
    times = [index * 20_000_000 for index in range(64)]
    offsets = [0] * 32 + [11_000_000] * 32
    run, packets, trace = _clock_reconciliation_artifacts(tmp_path, times, offsets)

    with pytest.raises(ValueError, match="11000000ns exceeds 10000000ns"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_schedule_metrics_report_exact_realization_errors(tmp_path):
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    (neqo / "schedule.csv").write_text(
        "action_time_us,direction,size,observed_size,satisfaction,miss_reason\n"
        "10,outgoing,1200,1200,satisfied,\n"
        "20,outgoing,1200,1199,satisfied,\n"
        "30,incoming,1200,,satisfied,\n"
        "40,incoming,1200,,missed,deadline\n",
        encoding="utf-8",
    )

    assert _schedule_realization_metrics(tmp_path) == {
        "scheduled_events": 4,
        "scheduled_outgoing_events": 2,
        "scheduled_incoming_events": 2,
        "satisfied_events": 3,
        "missed_events": 1,
        "missed_event_reasons": {"deadline": 1},
        "outgoing_size_mismatch_events": 1,
        "outgoing_size_absolute_error_bytes": 1,
    }


def test_missing_schedule_has_no_realization_claim(tmp_path):
    assert _schedule_realization_metrics(tmp_path) == {}


def test_defended_sample_requires_exact_zero_miss_schedule_contract():
    diagnostics = _traffic_morphing_diagnostics()

    assert _eligible("traffic-morphing", diagnostics)
    assert not _eligible("traffic-morphing", diagnostics, missed_events=1)
    assert not _eligible("traffic-morphing", diagnostics, missed_events=None)
    assert not _eligible("traffic-morphing", diagnostics, outgoing_size_mismatches=1)
    assert not _eligible("traffic-morphing", diagnostics, outgoing_size_mismatches=None)


@pytest.mark.parametrize(
    "defense",
    ["static", "front", "tamaraw", "traffic-morphing", "wtf-pad", "walkie-talkie"],
)
def test_every_nonbaseline_defense_requires_exact_consumed_incoming_credit(defense):
    if defense == "traffic-morphing":
        diagnostics = _traffic_morphing_diagnostics()
    elif defense == "wtf-pad":
        diagnostics = _wtf_pad_diagnostics()
    elif defense == "walkie-talkie":
        diagnostics = _walkie_talkie_diagnostics()
    else:
        diagnostics = _scheduled_incoming_diagnostics()
    assert _eligible(defense, diagnostics)

    for key in tuple(diagnostics):
        missing = deepcopy(diagnostics)
        del missing[key]
        assert not _eligible(defense, missing)

    extra = deepcopy(diagnostics)
    extra["scheduled_incoming_stale_bytes"] = 0
    assert not _eligible(defense, extra)

    wrong_type = deepcopy(diagnostics)
    wrong_type["scheduled_incoming_requested_bytes"] = False
    assert not _eligible(defense, wrong_type)

    retired = deepcopy(diagnostics)
    retired["scheduled_incoming_consumed_bytes"] = 80
    retired["scheduled_incoming_retired_bytes"] = 20
    assert not _eligible(defense, retired)

    unresolved = deepcopy(diagnostics)
    unresolved["scheduled_incoming_consumed_bytes"] = 80
    unresolved["scheduled_incoming_unresolved_bytes"] = 20
    assert not _eligible(defense, unresolved)

    inconsistent = deepcopy(diagnostics)
    inconsistent["scheduled_incoming_consumed_bytes"] = 99
    assert not _eligible(defense, inconsistent)


def test_wtf_pad_size_error_is_distinct_from_byte_shortfall():
    diagnostics = _wtf_pad_diagnostics()
    diagnostics["wtf_pad_incoming_size_error_bytes"] = 600

    assert diagnostics["wtf_pad_incoming_shortfall_bytes"] == 0
    assert _eligible("wtf-pad", diagnostics)


@pytest.mark.parametrize(
    ("defense", "required_key"),
    [
        ("traffic-morphing", "morphing_egress_packets"),
        ("wtf-pad", "wtf_pad_gap_to_burst"),
        (
            "walkie-talkie",
            "walkie_talkie_application_stream_crossing_bytes",
        ),
    ],
)
def test_defense_diagnostics_are_exact_typed_contracts(
    defense,
    required_key,
):
    diagnostics = {
        "traffic-morphing": _traffic_morphing_diagnostics,
        "wtf-pad": _wtf_pad_diagnostics,
        "walkie-talkie": _walkie_talkie_diagnostics,
    }[defense]()
    assert _eligible(defense, diagnostics)

    missing = deepcopy(diagnostics)
    del missing[required_key]
    assert not _eligible(defense, missing)

    extra = deepcopy(diagnostics)
    extra[f"{required_key}_stale"] = 0
    assert not _eligible(defense, extra)

    wrong_type = deepcopy(diagnostics)
    wrong_type[required_key] = False
    assert not _eligible(defense, wrong_type)


def test_walkie_talkie_rejects_crossing_lifecycle_and_burst_realization_errors():
    diagnostics = _walkie_talkie_diagnostics()

    crossing = deepcopy(diagnostics)
    crossing["walkie_talkie_application_stream_crossing_bytes"] = 1
    assert not _eligible("walkie-talkie", crossing)

    active = deepcopy(diagnostics)
    active["walkie_talkie_application_batch_active"] = True
    assert not _eligible("walkie-talkie", active)

    incomplete = deepcopy(diagnostics)
    incomplete["walkie_talkie_application_batches_completed"] = 0
    assert not _eligible("walkie-talkie", incomplete)

    missing_batch = deepcopy(diagnostics)
    missing_batch["walkie_talkie_observed_application_batches"] = 0
    assert not _eligible("walkie-talkie", missing_batch)

    overflow = deepcopy(diagnostics)
    overflow["walkie_talkie_observed_application_batches"] = 2
    overflow["walkie_talkie_application_batches_completed"] = 2
    overflow["walkie_talkie_application_batch_overflow"] = 1
    assert not _eligible("walkie-talkie", overflow)

    unrealized = deepcopy(diagnostics)
    unrealized["walkie_talkie_burst_realization"][0]["observed_incoming_cells"] = 1
    assert not _eligible("walkie-talkie", unrealized)


def test_walkie_talkie_rejects_source_envelope_overflow_even_when_mould_is_exact():
    diagnostics = _walkie_talkie_diagnostics()
    diagnostics["walkie_talkie_source_envelope_overflow_cells"] = 2

    assert (
        diagnostics["walkie_talkie_target_outgoing_cells"]
        == diagnostics["walkie_talkie_observed_outgoing_cells"]
    )
    assert (
        diagnostics["walkie_talkie_target_incoming_cells"]
        == diagnostics["walkie_talkie_observed_incoming_cells"]
    )
    assert diagnostics["walkie_talkie_target_observed_burst_l1"] == 0
    assert not _eligible("walkie-talkie", diagnostics)


def _eligible(
    defense: str,
    diagnostics: dict,
    *,
    missed_events: object = 0,
    outgoing_size_mismatches: object = 0,
) -> bool:
    return fidelity_eligible(
        defense,
        diagnostics,
        sample_eligible=True,
        missed_events=missed_events,
        outgoing_size_mismatches=outgoing_size_mismatches,
    )


def _traffic_morphing_diagnostics() -> dict:
    return {
        **_scheduled_incoming_diagnostics(),
        "morphing_egress_packets": 2,
        "morphing_egress_source_bytes": 230,
        "morphing_egress_target_bytes": 400,
        "morphing_egress_bypasses": 0,
        "morphing_egress_pacing_bypasses": 0,
        "morphing_egress_congestion_bypasses": 0,
        "morphing_egress_coalesced_bypasses": 0,
        "morphing_egress_invalid_size_bypasses": 0,
        "morphing_egress_target_selection_bypasses": 0,
        "morphing_egress_target_l1_ppm": 0,
        "morphing_ingress_requested_bytes": 100,
        "morphing_ingress_received_bytes": 100,
        "morphing_ingress_shortfall_bytes": 0,
        "morphing_ingress_wire_mixture_l1_ppm": 0,
        "suppressed_cover_feedback": 1,
    }


def _wtf_pad_diagnostics() -> dict:
    return {
        **_scheduled_incoming_diagnostics(),
        "padding_events": 2,
        "padding_event_guard_triggered": False,
        "wtf_pad_incoming_desired_bytes": 100,
        "wtf_pad_incoming_requested_bytes": 100,
        "wtf_pad_incoming_received_bytes": 100,
        "wtf_pad_incoming_shortfall_bytes": 0,
        "wtf_pad_incoming_size_error_bytes": 0,
        "wtf_pad_incoming_observed_events": 1,
        "wtf_pad_incoming_lag_us_total": 10,
        "wtf_pad_incoming_lag_us_max": 10,
        "wtf_pad_silent_to_burst": 1,
        "wtf_pad_burst_to_gap": 1,
        "wtf_pad_gap_to_burst": 1,
        "wtf_pad_burst_to_silent": 1,
        "suppressed_cover_feedback": 1,
    }


def _walkie_talkie_diagnostics() -> dict:
    return {
        **_scheduled_incoming_diagnostics(),
        "retried_outgoing_events": 0,
        "walkie_talkie_target_outgoing_cells": 2,
        "walkie_talkie_target_incoming_cells": 2,
        "walkie_talkie_observed_outgoing_cells": 2,
        "walkie_talkie_observed_incoming_cells": 2,
        "walkie_talkie_outgoing_shortfall_cells": 0,
        "walkie_talkie_incoming_shortfall_cells": 0,
        "walkie_talkie_outgoing_overflow_cells": 0,
        "walkie_talkie_incoming_overflow_cells": 0,
        "walkie_talkie_incoming_shortfall_bytes": 0,
        "walkie_talkie_incoming_chaff_bytes": 0,
        "walkie_talkie_target_observed_cell_l1": 0,
        "walkie_talkie_target_observed_burst_l1": 0,
        "walkie_talkie_control_only_crossings": 0,
        "walkie_talkie_application_stream_crossing_bytes": 0,
        "walkie_talkie_natural_outgoing_bytes": 150,
        "walkie_talkie_natural_incoming_bytes": 175,
        "walkie_talkie_source_envelope_overflow_cells": 0,
        "walkie_talkie_expected_application_batches": 1,
        "walkie_talkie_observed_application_batches": 1,
        "walkie_talkie_application_batch_overflow": 0,
        "walkie_talkie_application_batches_completed": 1,
        "walkie_talkie_batch_lifecycle_errors": 0,
        "walkie_talkie_application_batch_active": False,
        "walkie_talkie_burst_realization": [
            {
                "index": 0,
                "target_outgoing_cells": 2,
                "target_incoming_cells": 2,
                "observed_outgoing_cells": 2,
                "observed_incoming_cells": 2,
            }
        ],
    }


def _scheduled_incoming_diagnostics() -> dict:
    return {
        "scheduled_incoming_requested_bytes": 100,
        "scheduled_incoming_consumed_bytes": 100,
        "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0,
    }


def _reconciliation_artifacts(
    root,
    *,
    tail_direction: str,
):
    run = root / "run.json"
    packets = root / "packets.csv"
    trace = root / "direct.csv"
    run.write_text(
        json.dumps(
            {
                "completion_status": "complete",
                "endpoints": [
                    {
                        "id": 0,
                        "local_address": "10.0.0.2:50000",
                        "remote_address": "203.0.113.1:443",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    packets.write_text(
        "direction,monotonic_us,connection,observed_udp_length,"
        "scheduled_target,satisfaction,slot_id\n"
        "outgoing,1000,0,1200,,unshaped,\n"
        "incoming,2000,0,1200,,observed,\n",
        encoding="utf-8",
    )
    signed_tail = 100 if tail_direction == "outgoing" else -100
    trace.write_text(
        "relative_time_ns,direction,length_bytes,signed_length_bytes\n"
        "0,outgoing,1242,1242\n"
        "1000000,incoming,1242,-1242\n"
        f"2000000,{tail_direction},100,{signed_tail}\n",
        encoding="utf-8",
    )
    return run, packets, trace


def _clock_epoch_times(epoch_count: int) -> list[int]:
    return [
        epoch * 30_000_000_000 + packet * 20_000_000
        for epoch in range(epoch_count)
        for packet in range(32)
    ]


def _clock_reconciliation_artifacts(root, times_ns: list[int], offsets_ns: list[int]):
    assert len(times_ns) == len(offsets_ns)
    run = root / "run.json"
    packets = root / "packets.csv"
    trace = root / "direct.csv"
    run.write_text(
        json.dumps(
            {
                "completion_status": "complete",
                "endpoints": [
                    {
                        "id": 0,
                        "local_address": "10.0.0.2:50000",
                        "remote_address": "203.0.113.1:443",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    packet_rows = [
        "direction,monotonic_us,connection,observed_udp_length,"
        "scheduled_target,satisfaction,slot_id"
    ]
    trace_rows = ["relative_time_ns,direction,length_bytes,signed_length_bytes"]
    first_direct_time = times_ns[0] + offsets_ns[0]
    for index, (time_ns, offset_ns) in enumerate(zip(times_ns, offsets_ns, strict=True)):
        udp_length = 1_000 + index
        frame_length = udp_length + 42
        packet_rows.append(f"outgoing,{time_ns // 1_000},0,{udp_length},,unshaped,")
        relative_time = time_ns + offset_ns - first_direct_time
        trace_rows.append(f"{relative_time},outgoing,{frame_length},{frame_length}")
    packets.write_text("\n".join(packet_rows) + "\n", encoding="utf-8")
    trace.write_text("\n".join(trace_rows) + "\n", encoding="utf-8")
    return run, packets, trace


def _clock_anchors(adjustment_ns: int) -> dict[str, int]:
    start_realtime = 1_800_000_000_000_000_000
    start_monotonic = 9_000_000_000_000
    monotonic_elapsed = 12_000_000_000
    return {
        "start_realtime_unix_ns": start_realtime,
        "start_monotonic_ns": start_monotonic,
        "end_realtime_unix_ns": start_realtime + monotonic_elapsed + adjustment_ns,
        "end_monotonic_ns": start_monotonic + monotonic_elapsed,
    }
