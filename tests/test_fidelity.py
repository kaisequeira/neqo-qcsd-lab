from __future__ import annotations

import json
from copy import deepcopy

import pytest

from qcsd_lab.fidelity import (
    CONSUMPTION_SCHEDULE_QCSD_FIELDS,
    RUNNER_CSV_U64_MAX,
    SCHEDULE_QCSD_FIELDS,
    _csv_uint,
    _runner_csv_u64,
    _schedule_realization_metrics,
    _scheduled_incoming_diagnostics_match,
    _validate_qcsd_trace_extension,
    fidelity_eligible,
    reconcile_direct_runner_artifacts,
    validate_primary_capture_clock_integrity,
)


def test_runner_csv_u64_parser_accepts_exact_rust_maximum() -> None:
    maximum = str(RUNNER_CSV_U64_MAX)

    assert _runner_csv_u64("0", label="runner value") == 0
    assert _runner_csv_u64(maximum, label="runner value") == RUNNER_CSV_U64_MAX
    assert _csv_uint({"value": maximum}, "value") == RUNNER_CSV_U64_MAX


@pytest.mark.parametrize(
    "value",
    (
        str(2**64),
        "9" * 10_000,
        "-1",
        "+1",
        " 1",
        "1 ",
        "1.0",
        "01",
        "١",
        "true",
        "",
    ),
)
def test_runner_csv_u64_parser_rejects_noncanonical_or_out_of_domain(value: str) -> None:
    with pytest.raises(ValueError):
        _runner_csv_u64(value, label="runner value")


def test_trace_extension_rejects_coherent_u64_overflow_chronology() -> None:
    row = {field: "" for field in SCHEDULE_QCSD_FIELDS}
    row.update(
        {
            "direction": "incoming",
            "target_time_us": "0",
            "action_time_us": "1",
            "qcsd_outcome_schema_version": "3",
            "send_policy": "exact",
            "desired_udp_bytes": "1200",
            "credit_advertised_at_us": "2",
            "credit_advertisement_delay_us": "1",
            "credit_consumed_at_us": str(2**64),
            "credit_consumption_delay_us": str(2**64 - 1),
            "terminal_defense_elapsed_us": "2",
        }
    )

    with pytest.raises(ValueError, match="consumption"):
        _validate_qcsd_trace_extension(row, label="incoming schedule row")


def test_current_qcsd_trace_suffix_is_source_stable_v3() -> None:
    assert SCHEDULE_QCSD_FIELDS[-5:] == (
        "credit_advertised_at_us",
        "credit_advertisement_delay_us",
        "credit_consumed_at_us",
        "credit_consumption_delay_us",
        "terminal_defense_elapsed_us",
    )


def test_incoming_exact_terminal_is_receive_credit_not_udp_realization() -> None:
    row = {field: "" for field in SCHEDULE_QCSD_FIELDS}
    row.update(
        {
            "direction": "incoming",
            "target_time_us": "0",
            "action_time_us": "0",
            "qcsd_outcome_schema_version": "3",
            "send_policy": "exact",
            "desired_udp_bytes": "1200",
            "credit_advertised_at_us": "100",
            "credit_advertisement_delay_us": "100",
            "credit_consumed_at_us": "500",
            "credit_consumption_delay_us": "500",
            "terminal_defense_elapsed_us": "500",
        }
    )
    _validate_qcsd_trace_extension(row, label="incoming schedule row")

    credit = {
        field: row[field]
        for field in (
            "credit_advertised_at_us",
            "credit_advertisement_delay_us",
            "credit_consumed_at_us",
            "credit_consumption_delay_us",
        )
    }
    row.update({field: "" for field in credit})
    row["qcsd_outcome_schema_version"] = "1"
    row["terminal_defense_elapsed_us"] = ""
    row["observed_udp_bytes"] = "1200"
    _validate_qcsd_trace_extension(row, label="incoming observed packet row")

    row["observed_udp_bytes"] = ""
    row["qcsd_outcome_schema_version"] = "3"
    row["terminal_defense_elapsed_us"] = "500"
    row.update(credit)
    row["application_stream_bytes"] = "1"
    with pytest.raises(ValueError, match="receive-credit event UDP realization"):
        _validate_qcsd_trace_extension(row, label="incoming schedule row")

    row["application_stream_bytes"] = ""
    row["credit_consumed_at_us"] = "99"
    with pytest.raises(ValueError, match="consumption"):
        _validate_qcsd_trace_extension(row, label="incoming schedule row")


def test_incoming_diagnostics_version_advertisement_without_breaking_legacy() -> None:
    current = _scheduled_incoming_diagnostics()
    legacy = {
        key: value
        for key, value in current.items()
        if key != "scheduled_incoming_advertised_bytes"
    }
    assert _scheduled_incoming_diagnostics_match(legacy)

    assert _scheduled_incoming_diagnostics_match(current)
    current["scheduled_incoming_advertised_bytes"] = 99
    assert not _scheduled_incoming_diagnostics_match(current)


def test_current_exact_packet_composition_is_distinct_from_terminal_schedule() -> None:
    row = {field: "" for field in SCHEDULE_QCSD_FIELDS}
    row.update(
        {
            "direction": "outgoing",
            "qcsd_outcome_schema_version": "2",
            "send_policy": "exact",
            "desired_udp_bytes": "1200",
            "observed_udp_bytes": "1200",
            "application_stream_bytes": "800",
            "retransmission_stream_bytes": "100",
            "chaff_stream_bytes": "200",
            "defense_control_bytes": "0",
            "quic_padding_bytes": "50",
            "other_quic_bytes": "50",
            "lateness_us": "7",
        }
    )
    _validate_qcsd_trace_extension(row, label="outgoing packet row")
    row["other_quic_bytes"] = "49"
    with pytest.raises(ValueError, match="composition"):
        _validate_qcsd_trace_extension(row, label="outgoing packet row")


def test_primary_capture_clock_integrity_accepts_bounded_linux_clock_evidence() -> None:
    capture = _primary_capture_clock()

    result = validate_primary_capture_clock_integrity(
        capture,
        require_pairing_uncertainty=True,
    )

    assert result == {
        "clock_domain": "linux-kernel",
        "capture_timestamp_type": "host",
        "clock_model": "constant-offset",
        "direct_timestamp_error_max_ns": 1_000,
        "direct_timestamp_tolerance_ns": 10_000_000,
        "realtime_monotonic_elapsed_delta_ns": 9_000_000,
        "realtime_monotonic_elapsed_error_bound_ns": 9_000_200,
        "maximum_elapsed_error_ns": 10_000_000,
        "pairing_uncertainty_recorded": True,
    }


def test_primary_capture_clock_integrity_requires_host_timestamp_for_fresh_capture() -> None:
    capture = _primary_capture_clock()
    del capture["timestamp_type"]

    with pytest.raises(ValueError, match="capture timestamp type is missing"):
        validate_primary_capture_clock_integrity(
            capture,
            require_timestamp_type=True,
        )

    capture["timestamp_type"] = "adapter_unsynced"
    with pytest.raises(ValueError, match="capture timestamp type is not host"):
        validate_primary_capture_clock_integrity(capture)


def test_primary_capture_clock_integrity_rejects_step_repaired_capture() -> None:
    capture = _primary_capture_clock()
    reconciliation = capture["direct_runner_reconciliation"]
    reconciliation.update(
        direct_clock_model="positive-abrupt-steps",
        direct_clock_segment_count=2,
        direct_clock_segments=[{"index": 0}, {"index": 1}],
        direct_clock_step_count=1,
        direct_clock_steps=[{"index": 0}],
    )

    with pytest.raises(ValueError, match="clock model is not constant-offset"):
        validate_primary_capture_clock_integrity(capture)


def test_primary_capture_clock_integrity_counts_pairing_uncertainty_against_budget() -> None:
    capture = _primary_capture_clock()
    anchors = capture["capture_clock_anchors"]
    anchors["end_realtime_unix_ns"] += 999_900

    with pytest.raises(ValueError, match="elapsed difference exceeds 10 ms"):
        validate_primary_capture_clock_integrity(
            capture,
            require_pairing_uncertainty=True,
        )


def test_primary_capture_clock_integrity_rejects_relaxed_packet_tolerance() -> None:
    capture = _primary_capture_clock()
    capture["direct_runner_reconciliation"]["direct_timestamp_tolerance_ns"] = 10_000_001

    with pytest.raises(ValueError, match="timestamp error exceeds the 10 ms limit"):
        validate_primary_capture_clock_integrity(capture)


def test_primary_capture_clock_integrity_requires_new_pairing_evidence_before_promotion() -> None:
    capture = _primary_capture_clock()
    anchors = capture["capture_clock_anchors"]
    del anchors["start_pairing_uncertainty_ns"]
    del anchors["end_pairing_uncertainty_ns"]

    with pytest.raises(ValueError, match="pairing uncertainty is missing"):
        validate_primary_capture_clock_integrity(
            capture,
            require_pairing_uncertainty=True,
        )

    assert (
        validate_primary_capture_clock_integrity(capture)["pairing_uncertainty_recorded"] is False
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


def test_direct_runner_reconciliation_rejects_contradictory_error_class(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="incoming")
    receipt = json.loads(run.read_text(encoding="utf-8"))
    receipt["error_class"] = "client-defense-fidelity-v1"
    run.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(ValueError, match="did not complete"):
        reconcile_direct_runner_artifacts(run, packets, trace)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    (
        ("outgoing,1000,0,1200,,unshaped,", "outgoing,01,0,1200,,unshaped,", "packet time"),
        (
            "outgoing,1000,0,1200,,unshaped,",
            f"outgoing,1000,{2**64},1200,,unshaped,",
            "connection",
        ),
        (
            "outgoing,1000,0,1200,,unshaped,",
            f"outgoing,1000,0,{'9' * 10_000},,unshaped,",
            "UDP length",
        ),
        (
            "outgoing,1000,0,1200,,unshaped,",
            f"outgoing,1000,0,1200,{2**64},satisfied,1",
            "scheduled target",
        ),
        (
            "outgoing,1000,0,1200,,unshaped,",
            "outgoing,1000,0,1200,1200,satisfied,١",
            "slot id",
        ),
    ),
)
def test_direct_runner_reconciliation_bounds_every_packet_unsigned_field(
    tmp_path, old, new, message
):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="incoming")
    packets.write_text(
        packets.read_text(encoding="utf-8").replace(old, new),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        reconcile_direct_runner_artifacts(run, packets, trace)


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
        "terminal_satisfactions": {"missed": 1, "satisfied": 3},
        "terminal_slots_unique": True,
        "duplicate_terminal_slots": 0,
        "invalid_terminal_rows": 4,
        "typed_congestion_reason_column": False,
        "typed_credit_advertisement_columns": False,
        "typed_credit_consumption_columns": False,
        "typed_controller_terminal_time_column": False,
        "invalid_congestion_reason_events": 0,
        "congestion_reasons": {},
        "terminal_desired_outgoing_bytes": 0,
        "terminal_observed_outgoing_bytes": 0,
        "catch_up_events": 0,
        "invalid_typed_outcome_rows": 0,
        "typed_composition_bytes": {
            "application_stream_bytes": 0,
            "retransmission_stream_bytes": 0,
            "chaff_stream_bytes": 0,
            "defense_control_bytes": 0,
            "quic_padding_bytes": 0,
            "other_quic_bytes": 0,
        },
        "typed_lateness_us_total": 0,
        "typed_lateness_us_max": 0,
        "typed_real_bearing_outgoing_bytes": 0,
        "incoming_credit_advertised_events": 0,
        "incoming_credit_consumed_events": 0,
        "incoming_credit_missing_events": 0,
        "incoming_credit_consumption_missing_events": 0,
        "invalid_credit_advertisement_events": 0,
        "invalid_credit_consumption_events": 0,
        "incoming_credit_advertisement_delay_us_total": 0,
        "incoming_credit_advertisement_delay_us_max": 0,
        "incoming_credit_advertisement_delay_us_values": [],
        "incoming_credit_consumption_delay_us_total": 0,
        "incoming_credit_consumption_delay_us_max": 0,
        "incoming_credit_consumption_delay_us_values": [],
        "terminal_defense_elapsed_us_values": [],
        "target_times_us_by_direction": {"outgoing": [], "incoming": []},
        "scheduled_sizes_by_direction": {
            "outgoing": [1_200, 1_200],
            "incoming": [1_200, 1_200],
        },
    }


def test_missing_schedule_has_no_realization_claim(tmp_path):
    assert _schedule_realization_metrics(tmp_path) == {}


def test_runner_packet_reader_accepts_exact_nullable_qcsd_extension(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="incoming")
    rows = packets.read_text(encoding="utf-8").splitlines()
    extension = (
        ",qcsd_outcome_schema_version,send_policy,desired_udp_bytes,observed_udp_bytes,"
        "application_stream_bytes,retransmission_stream_bytes,chaff_stream_bytes,"
        "defense_control_bytes,quic_padding_bytes,other_quic_bytes,lateness_us,"
        "congestion_reason"
    )
    packets.write_text(
        "\n".join([rows[0] + extension, *(row + "," * 12 for row in rows[1:])]) + "\n"
    )

    result = reconcile_direct_runner_artifacts(run, packets, trace)

    assert result.evidence_eligible is True
    assert result.metrics["direct_runner_packets"] == 2


def test_runner_packet_reader_accepts_current_nullable_qcsd_extension(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="incoming")
    rows = packets.read_text(encoding="utf-8").splitlines()
    header = rows[0] + "," + ",".join(SCHEDULE_QCSD_FIELDS)
    empty_suffix = "," * len(SCHEDULE_QCSD_FIELDS)
    packets.write_text(
        "\n".join([header, *(row + empty_suffix for row in rows[1:])]) + "\n",
        encoding="utf-8",
    )

    result = reconcile_direct_runner_artifacts(run, packets, trace)

    assert result.evidence_eligible is True
    assert result.metrics["direct_runner_packets"] == 2


def test_runner_packet_reader_accepts_historical_consumption_suffix(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="incoming")
    rows = packets.read_text(encoding="utf-8").splitlines()
    header = rows[0] + "," + ",".join(CONSUMPTION_SCHEDULE_QCSD_FIELDS)
    empty_suffix = "," * len(CONSUMPTION_SCHEDULE_QCSD_FIELDS)
    packets.write_text(
        "\n".join([header, *(row + empty_suffix for row in rows[1:])]) + "\n",
        encoding="utf-8",
    )

    result = reconcile_direct_runner_artifacts(run, packets, trace)

    assert result.evidence_eligible is True
    assert result.metrics["direct_runner_packets"] == 2


def test_runner_packet_reader_rejects_nonexact_qcsd_extension(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="outgoing")
    rows = packets.read_text(encoding="utf-8").splitlines()
    packets.write_text("\n".join([rows[0] + ",unexpected", *(row + "," for row in rows[1:])]))

    with pytest.raises(ValueError, match="invalid direct/runner evidence columns"):
        reconcile_direct_runner_artifacts(run, packets, trace)


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


@pytest.mark.parametrize(
    "defense",
    ["static", "front", "tamaraw", "traffic-morphing", "wtf-pad", "walkie-talkie"],
)
def test_established_defense_zero_activity_never_certifies(defense):
    diagnostics = _zero_activity_diagnostics(defense)

    assert not _eligible(
        defense,
        diagnostics,
        schedule_metrics=_empty_activation_schedule(),
    )


def test_wtf_pad_zero_padding_can_certify_after_real_traffic_activates_automaton():
    diagnostics = _zero_activity_diagnostics("wtf-pad")
    diagnostics["wtf_pad_silent_to_burst"] = 1

    assert _eligible(
        "wtf-pad",
        diagnostics,
        schedule_metrics=_empty_activation_schedule(),
    )


def _eligible(
    defense: str,
    diagnostics: dict,
    *,
    missed_events: object = 0,
    outgoing_size_mismatches: object = 0,
    schedule_metrics: dict | None = None,
    resolved_configuration: dict | None = None,
) -> bool:
    if schedule_metrics is None:
        schedule_metrics = _activation_schedule(defense)
    if resolved_configuration is None:
        resolved_configuration = _activation_configuration(defense)
    return fidelity_eligible(
        defense,
        diagnostics,
        sample_eligible=True,
        missed_events=missed_events,
        outgoing_size_mismatches=outgoing_size_mismatches,
        schedule_metrics=schedule_metrics,
        resolved_configuration=resolved_configuration,
        require_defense_activation=True,
    )


def _activation_schedule(defense: str) -> dict:
    directional = {
        "static": ([25_000], [30_000], [100], [100]),
        "front": ([25_000], [30_000], [100], [100]),
        "tamaraw": ([0], [0], [100], [100]),
        "traffic-morphing": ([], [0], [], [100]),
        "wtf-pad": ([25_000], [30_000], [100], [100]),
        "walkie-talkie": ([0, 1], [0, 1], [50, 50], [50, 50]),
    }[defense]
    outgoing_targets, incoming_targets, outgoing_sizes, incoming_sizes = directional
    outgoing = len(outgoing_sizes)
    incoming = len(incoming_sizes)
    count = outgoing + incoming
    return {
        "scheduled_events": count,
        "scheduled_outgoing_events": outgoing,
        "scheduled_incoming_events": incoming,
        "satisfied_events": count,
        "missed_events": 0,
        "missed_event_reasons": {},
        "outgoing_size_mismatch_events": 0,
        "outgoing_size_absolute_error_bytes": 0,
        "terminal_satisfactions": {"satisfied": count} if count else {},
        "terminal_slots_unique": True,
        "duplicate_terminal_slots": 0,
        "invalid_terminal_rows": 0,
        "typed_congestion_reason_column": True,
        "typed_credit_advertisement_columns": True,
        "typed_credit_consumption_columns": True,
        "typed_controller_terminal_time_column": True,
        "invalid_congestion_reason_events": 0,
        "congestion_reasons": {},
        "terminal_desired_outgoing_bytes": sum(outgoing_sizes),
        "terminal_observed_outgoing_bytes": sum(outgoing_sizes),
        "catch_up_events": 0,
        "invalid_typed_outcome_rows": 0,
        "typed_composition_bytes": {},
        "typed_lateness_us_total": 0,
        "typed_lateness_us_max": 0,
        "typed_real_bearing_outgoing_bytes": 0,
        "incoming_credit_advertised_events": incoming,
        "incoming_credit_consumed_events": incoming,
        "incoming_credit_missing_events": 0,
        "incoming_credit_consumption_missing_events": 0,
        "invalid_credit_advertisement_events": 0,
        "invalid_credit_consumption_events": 0,
        "incoming_credit_advertisement_delay_us_total": 0,
        "incoming_credit_advertisement_delay_us_max": 0,
        "incoming_credit_advertisement_delay_us_values": [0] * incoming,
        "incoming_credit_consumption_delay_us_total": 0,
        "incoming_credit_consumption_delay_us_max": 0,
        "incoming_credit_consumption_delay_us_values": [0] * incoming,
        "terminal_defense_elapsed_us_values": [0] * count,
        "target_times_us_by_direction": {
            "outgoing": outgoing_targets,
            "incoming": incoming_targets,
        },
        "scheduled_sizes_by_direction": {
            "outgoing": outgoing_sizes,
            "incoming": incoming_sizes,
        },
    }


def _empty_activation_schedule() -> dict:
    schedule = _activation_schedule("traffic-morphing")
    schedule.update(
        scheduled_events=0,
        scheduled_outgoing_events=0,
        scheduled_incoming_events=0,
        satisfied_events=0,
        terminal_satisfactions={},
        terminal_desired_outgoing_bytes=0,
        terminal_observed_outgoing_bytes=0,
        incoming_credit_advertised_events=0,
        incoming_credit_consumed_events=0,
        incoming_credit_advertisement_delay_us_values=[],
        incoming_credit_consumption_delay_us_values=[],
        terminal_defense_elapsed_us_values=[],
        target_times_us_by_direction={"outgoing": [], "incoming": []},
        scheduled_sizes_by_direction={"outgoing": [], "incoming": []},
    )
    return schedule


def _activation_configuration(defense: str) -> dict:
    parameters = {
        "static": {"kind": "static", "padding_only": True, "schedule": "schedule.csv"},
        "front": {
            "kind": "front",
            "n_client_packets": 2,
            "n_server_packets": 2,
            "packet_size": 100,
        },
        "tamaraw": {
            "kind": "tamaraw",
            "incoming_interval_us": 10,
            "outgoing_interval_us": 20,
            "packet_size": 100,
            "modulo": 1,
        },
        "traffic-morphing": {
            "kind": "traffic_morphing",
            "matrix": "matrix.json",
            "workload_id": "test",
        },
        "wtf-pad": {
            "kind": "wtf_pad",
            "histograms": "histograms.json",
            "max_padding_events": 10,
            "packet_size": 100,
        },
        "walkie-talkie": {
            "kind": "walkie_talkie",
            "molded": "mould.json",
            "workload_id": "test",
            "packet_size": 50,
        },
    }[defense]
    return {
        "schema_version": 2,
        "max_udp_payload_size": 1_200,
        "defense": parameters,
    }


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
        "scheduled_incoming_advertised_bytes": 100,
        "scheduled_incoming_consumed_bytes": 100,
        "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0,
    }


def _zero_activity_diagnostics(defense: str) -> dict:
    factories = {
        "static": _scheduled_incoming_diagnostics,
        "front": _scheduled_incoming_diagnostics,
        "tamaraw": _scheduled_incoming_diagnostics,
        "traffic-morphing": _traffic_morphing_diagnostics,
        "wtf-pad": _wtf_pad_diagnostics,
        "walkie-talkie": _walkie_talkie_diagnostics,
    }
    diagnostics = factories[defense]()
    for key, value in tuple(diagnostics.items()):
        if type(value) is int:
            diagnostics[key] = 0
        elif isinstance(value, list):
            diagnostics[key] = (
                [
                    {
                        "index": 0,
                        "target_outgoing_cells": 0,
                        "target_incoming_cells": 0,
                        "observed_outgoing_cells": 0,
                        "observed_incoming_cells": 0,
                    }
                ]
                if key == "walkie_talkie_burst_realization"
                else []
            )
    return diagnostics


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


def _primary_capture_clock() -> dict[str, object]:
    return {
        "primary": True,
        "timestamp_type": "host",
        "capture_clock_anchors": {
            "start_realtime_unix_ns": 10_000_000_000,
            "start_monotonic_ns": 1_000_000_000,
            "end_realtime_unix_ns": 11_009_000_000,
            "end_monotonic_ns": 2_000_000_000,
            "start_pairing_uncertainty_ns": 100,
            "end_pairing_uncertainty_ns": 100,
        },
        "direct_runner_reconciliation": {
            "direct_clock_model": "constant-offset",
            "direct_clock_segment_count": 1,
            "direct_clock_segments": [{"index": 0}],
            "direct_clock_step_count": 0,
            "direct_clock_steps": [],
            "direct_runner_reconciled": True,
            "evidence_eligible": True,
            "direct_timestamp_error_max_ns": 1_000,
            "direct_timestamp_tolerance_ns": 10_000_000,
        },
    }
