from __future__ import annotations

import csv
import ipaddress
import math
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from statistics import median_low
from typing import Any

from .capture import read_normalized_trace
from .defenses import DEFENSE_ADAPTATIONS
from .util import load_json, sha256_file

RUNNER_PACKET_FIELDS = (
    "direction",
    "monotonic_us",
    "connection",
    "observed_udp_length",
    "scheduled_target",
    "satisfaction",
    "slot_id",
)
DEFAULT_TIMESTAMP_TOLERANCE_NS = 10_000_000
CLOCK_STEP_MIN_NS = 50_000_000
CLOCK_STEP_MAX_NS = 100_000_000
CLOCK_STEP_CONTEXT_PACKETS = 5
CLOCK_EPOCH_MIN_PACKETS = 32
CLOCK_EPOCH_MIN_SPAN_NS = 500_000_000
CLOCK_STEP_MIN_INTERVAL_NS = 25_000_000_000
CLOCK_STEP_MAX_INTERVAL_NS = 35_000_000_000
CLOCK_ANCHOR_FIELDS = {
    "start_realtime_unix_ns",
    "start_monotonic_ns",
    "end_realtime_unix_ns",
    "end_monotonic_ns",
}
RECONCILIATION_LIMITATIONS = (
    (
        "Encrypted direct PCAP proves datagram timing, direction, and wire length, but cannot "
        "identify QUIC PADDING frames or independently recover the pre-padding source size."
    ),
    (
        "The normalized tuple-union trace omits endpoint identifiers, so concurrent "
        "equal-sized datagrams can only be correlated by their clock-aligned aggregate "
        "sequence."
    ),
    (
        "The runner drains endpoint sockets serially, so aggregate ordering across "
        "connections is reconstructed from packet timestamps; near-simultaneous packets "
        "are validated only through exact size multiplicity and the residual bound."
    ),
    (
        "Normalization removes the capture's absolute timestamp; a uniform offset between "
        "the runner monotonic clock and capture clock is therefore unobservable."
    ),
    (
        "Abrupt capture wall-clock corrections are accepted only as positive 50--100 ms "
        "steps with consecutive packet support, well-supported constant-offset epochs, and "
        "a 25--35 s cadence when steps repeat. A final positive step whose terminal epoch "
        "lacks the ordinary packet/span support additionally requires independently sealed "
        "realtime/monotonic wrapper anchors; "
        "negative steps and drift remain ineligible."
    ),
    (
        "Ethernet frame-to-UDP conversion assumes the declared untagged Ethernet, "
        "non-fragmented IPv4/IPv6 direct-capture contract."
    ),
)


@dataclass(frozen=True)
class DirectRunnerReconciliation:
    metrics: dict[str, Any]
    limitations: tuple[str, ...]
    evidence_eligible: bool


@dataclass(frozen=True)
class _DirectPacket:
    index: int
    relative_time_ns: int
    direction: str
    frame_length: int


@dataclass(frozen=True)
class _RunnerPacket:
    index: int
    monotonic_us: int
    connection: int
    direction: str
    udp_length: int
    expected_frame_length: int


def reconcile_direct_runner_artifacts(
    run_path: Path,
    runner_packets_path: Path,
    direct_trace_path: Path,
    *,
    timestamp_tolerance_ns: int = DEFAULT_TIMESTAMP_TOLERANCE_NS,
    clock_anchors: Mapping[str, Any] | None = None,
) -> DirectRunnerReconciliation:
    """Reconcile collection artifacts before an attempt is promoted."""

    if timestamp_tolerance_ns < 0:
        raise ValueError("direct/runner timestamp tolerance must be non-negative")
    run = _object(load_json(run_path), "runner metadata")
    if run.get("completion_status") != "complete":
        raise ValueError("runner did not complete before direct reconciliation")
    overheads = _endpoint_frame_overheads(run)
    runner_packets = _read_runner_packets(runner_packets_path, overheads)
    direct_packets = _read_direct_packets(direct_trace_path)
    clock_adjustment_ns = _clock_adjustment_ns(clock_anchors)
    matches, unmatched_tail, residuals, clock_offset, clock_metrics = _reconcile_runner_packets(
        runner_packets,
        direct_packets,
        timestamp_tolerance_ns=timestamp_tolerance_ns,
        end_anchor_adjustment_ns=clock_adjustment_ns,
    )
    absolute_residuals = sorted(abs(value) for value in residuals)
    return DirectRunnerReconciliation(
        metrics={
            "direct_trace_sha256": sha256_file(direct_trace_path),
            "direct_runner_packets_sha256": sha256_file(runner_packets_path),
            "direct_runner_reconciled": True,
            "direct_runner_packets": len(runner_packets),
            "direct_matched_packets": len(matches),
            "direct_unmatched_tail_packets": len(unmatched_tail),
            "direct_unmatched_tail_bytes": sum(
                direct_packets[index].frame_length for index in unmatched_tail
            ),
            "direct_clock_offset_ns": clock_offset,
            **clock_metrics,
            "direct_timestamp_tolerance_ns": timestamp_tolerance_ns,
            "direct_timestamp_error_max_ns": max(absolute_residuals, default=0),
            "direct_timestamp_error_p95_ns": _percentile_95(absolute_residuals),
        },
        limitations=RECONCILIATION_LIMITATIONS,
        evidence_eligible=len(matches) == len(runner_packets),
    )


def _endpoint_frame_overheads(run: Mapping[str, Any]) -> dict[int, int]:
    endpoints = run.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError("runner metadata has no endpoint tuples")
    result: dict[int, int] = {}
    for value in endpoints:
        endpoint = _object(value, "runner endpoint")
        identifier = _unsigned(endpoint.get("id"), "endpoint id")
        if identifier in result:
            raise ValueError(f"runner metadata has duplicate endpoint id {identifier}")
        local = endpoint.get("local_address")
        remote = endpoint.get("remote_address")
        if not isinstance(local, str) or not isinstance(remote, str):
            endpoint_tuple = endpoint.get("tuple")
            if isinstance(endpoint_tuple, Mapping):
                local = endpoint_tuple.get("local")
                remote = endpoint_tuple.get("remote")
        local_ip = _socket_ip(local, "local")
        remote_ip = _socket_ip(remote, "remote")
        if local_ip.version != remote_ip.version:
            raise ValueError("runner endpoint tuple mixes IP address families")
        result[identifier] = 14 + (20 if local_ip.version == 4 else 40) + 8
    return result


def _socket_ip(value: Any, label: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or not value:
        raise ValueError(f"runner endpoint has no {label} socket address")
    if value.startswith("["):
        end = value.find("]")
        if end <= 1 or value[end + 1 : end + 2] != ":":
            raise ValueError(f"runner endpoint has invalid {label} socket address")
        host = value[1:end]
    else:
        try:
            host, port = value.rsplit(":", 1)
            int(port)
        except (ValueError, TypeError) as error:
            raise ValueError(f"runner endpoint has invalid {label} socket address") from error
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError as error:
        raise ValueError(f"runner endpoint has invalid {label} IP address") from error


def _read_direct_packets(path: Path) -> list[_DirectPacket]:
    rows = read_normalized_trace(path)
    if not rows:
        raise ValueError("direct trace is empty")
    packets = []
    previous_time = -1
    for index, row in enumerate(rows):
        relative_time = _unsigned(row.get("relative_time_ns"), "direct relative time")
        if index == 0 and relative_time != 0:
            raise ValueError("direct trace must start at zero")
        if relative_time < previous_time:
            raise ValueError("direct timestamps are not monotonic")
        previous_time = relative_time
        direction = _direction(row.get("direction"), "direct trace")
        frame_length = _positive(row.get("length_bytes"), "direct frame length")
        signed_length = _integer(row.get("signed_length_bytes"), "direct signed length")
        if signed_length != (frame_length if direction == "outgoing" else -frame_length):
            raise ValueError("direct signed length is inconsistent")
        packets.append(_DirectPacket(index, relative_time, direction, frame_length))
    return packets


def _read_runner_packets(
    path: Path,
    endpoint_overheads: Mapping[int, int],
) -> list[_RunnerPacket]:
    rows = _read_exact_csv(path, RUNNER_PACKET_FIELDS)
    if not rows:
        raise ValueError("runner packet trace is empty")
    packets = []
    previous_time: dict[tuple[int, str], int] = {}
    for index, row in enumerate(rows):
        monotonic_us = _unsigned(row.get("monotonic_us"), "runner packet time")
        connection = _unsigned(row.get("connection"), "runner connection")
        if connection not in endpoint_overheads:
            raise ValueError(f"runner packet references unknown connection {connection}")
        direction = _direction(row.get("direction"), "runner packet trace")
        stream = (connection, direction)
        if monotonic_us < previous_time.get(stream, -1):
            raise ValueError(
                "runner packet timestamps are not monotonic within one connection and direction"
            )
        previous_time[stream] = monotonic_us
        udp_length = _positive(row.get("observed_udp_length"), "runner UDP length")
        if udp_length > 65_535:
            raise ValueError("runner UDP length exceeds the UDP domain")
        packets.append(
            _RunnerPacket(
                index,
                monotonic_us,
                connection,
                direction,
                udp_length,
                udp_length + endpoint_overheads[connection],
            )
        )
    return packets


def _reconcile_runner_packets(
    runner: list[_RunnerPacket],
    direct: list[_DirectPacket],
    *,
    timestamp_tolerance_ns: int,
    end_anchor_adjustment_ns: int | None,
) -> tuple[dict[int, int], list[int], list[int], int, dict[str, Any]]:
    direct_by_signature: dict[tuple[str, int], deque[int]] = defaultdict(deque)
    runner_by_signature: dict[tuple[str, int], list[_RunnerPacket]] = defaultdict(list)
    for packet in direct:
        direct_by_signature[(packet.direction, packet.frame_length)].append(packet.index)
    for packet in runner:
        runner_by_signature[(packet.direction, packet.expected_frame_length)].append(packet)

    matches: dict[int, int] = {}
    for signature, packets in runner_by_signature.items():
        candidates = direct_by_signature[signature]
        if len(candidates) < len(packets):
            packet = min(packets, key=lambda item: item.index)
            raise ValueError(
                "direct trace has no frame for runner packet "
                f"{packet.index} ({packet.direction}, UDP {packet.udp_length})"
            )
        for packet in sorted(
            packets,
            key=lambda item: (item.monotonic_us, item.connection, item.index),
        ):
            matches[packet.index] = candidates.popleft()

    unmatched = sorted(index for values in direct_by_signature.values() for index in values)
    last_matched = max(matches.values(), default=-1)
    if any(index <= last_matched for index in unmatched):
        raise ValueError(
            "direct trace contains an unmatched packet before the runner-correlated capture tail"
        )
    if any(direct[index].direction != "incoming" for index in unmatched):
        raise ValueError("direct trace contains an unrecorded outgoing tail packet")

    ordered_matches = sorted(
        [
            (
                runner[runner_index],
                direct_index,
                direct[direct_index].relative_time_ns - runner[runner_index].monotonic_us * 1_000,
            )
            for runner_index, direct_index in matches.items()
        ],
        key=lambda item: (item[0].monotonic_us, item[0].connection, item[0].index),
    )
    residuals, clock_offset, clock_metrics = _reconcile_clock_epochs(
        ordered_matches,
        timestamp_tolerance_ns=timestamp_tolerance_ns,
        end_anchor_adjustment_ns=end_anchor_adjustment_ns,
    )
    return matches, unmatched, residuals, clock_offset, clock_metrics


def _reconcile_clock_epochs(
    ordered_matches: list[tuple[_RunnerPacket, int, int]],
    *,
    timestamp_tolerance_ns: int,
    end_anchor_adjustment_ns: int | None,
) -> tuple[list[int], int, dict[str, Any]]:
    """Fit only strongly evidenced positive wall-clock steps between constant epochs."""

    negative_steps = [
        current[2] - previous[2]
        for previous, current in zip(ordered_matches, ordered_matches[1:], strict=False)
        if current[2] - previous[2] <= -CLOCK_STEP_MIN_NS
    ]
    if negative_steps:
        raise ValueError(
            "direct/runner timestamp mismatch includes a negative clock step: "
            f"{min(negative_steps)}ns"
        )

    positive_steps = [
        (index, ordered_matches[index][2] - ordered_matches[index - 1][2])
        for index in range(1, len(ordered_matches))
        if ordered_matches[index][2] - ordered_matches[index - 1][2] >= CLOCK_STEP_MIN_NS
    ]
    boundaries: list[int] = []
    boundary_deltas: list[int] = []
    end_anchored_boundary: int | None = None
    for index, delta in positive_steps:
        context_start = index - CLOCK_STEP_CONTEXT_PACKETS
        context_end = index + CLOCK_STEP_CONTEXT_PACKETS
        standard_step = CLOCK_STEP_MIN_NS <= delta <= CLOCK_STEP_MAX_NS
        if context_start < 0:
            raise ValueError("direct/runner clock step has insufficient consecutive support")
        tail_epoch = ordered_matches[index:]
        tail_span_ns = (
            (tail_epoch[-1][0].monotonic_us - tail_epoch[0][0].monotonic_us) * 1_000
            if tail_epoch
            else 0
        )
        sparse_tail = (
            len(tail_epoch) < CLOCK_EPOCH_MIN_PACKETS or tail_span_ns < CLOCK_EPOCH_MIN_SPAN_NS
        )
        has_standard_context = context_end <= len(ordered_matches)
        if sparse_tail and end_anchor_adjustment_ns is not None:
            if end_anchored_boundary is not None or index != positive_steps[-1][0]:
                raise ValueError("only one final positive clock step may use end-anchor evidence")
            context_end = len(ordered_matches)
            end_anchored_boundary = index
        elif standard_step and has_standard_context:
            pass
        elif sparse_tail:
            raise ValueError(
                "sparse final positive clock step requires "
                "realtime/monotonic end-anchor corroboration"
            )
        elif not standard_step:
            raise ValueError(
                "well-supported direct/runner clock-step epoch offsets are outside the "
                "50--100 ms bound"
            )
        direct_indices = [
            direct_index
            for _packet, direct_index, _offset in ordered_matches[context_start:context_end]
        ]
        if any(
            current != previous + 1
            for previous, current in zip(direct_indices, direct_indices[1:], strict=False)
        ):
            raise ValueError("direct/runner clock step lacks consecutive packet support")
        boundaries.append(index)
        boundary_deltas.append(delta)

    if len(boundaries) > 1:
        boundary_times = [ordered_matches[index][0].monotonic_us * 1_000 for index in boundaries]
        for previous, current in zip(boundary_times, boundary_times[1:], strict=False):
            interval = current - previous
            if not CLOCK_STEP_MIN_INTERVAL_NS <= interval <= CLOCK_STEP_MAX_INTERVAL_NS:
                raise ValueError(
                    "repeated direct/runner clock steps lack the required 25--35 s cadence"
                )

    epoch_bounds = [0, *boundaries, len(ordered_matches)]
    residuals: list[int] = []
    segments: list[dict[str, Any]] = []
    offsets: list[int] = []
    for epoch_index, (start, end) in enumerate(zip(epoch_bounds, epoch_bounds[1:], strict=False)):
        epoch = ordered_matches[start:end]
        packet_count = len(epoch)
        span_ns = (epoch[-1][0].monotonic_us - epoch[0][0].monotonic_us) * 1_000 if epoch else 0
        weak_epoch = packet_count < CLOCK_EPOCH_MIN_PACKETS or span_ns < CLOCK_EPOCH_MIN_SPAN_NS
        is_end_anchored_tail = end_anchored_boundary is not None and start == end_anchored_boundary
        if boundaries and weak_epoch and not is_end_anchored_tail:
            raise ValueError(
                "direct/runner clock epoch lacks minimum support: "
                f"{packet_count} packets over {span_ns}ns"
            )
        offset = median_low([item[2] for item in epoch])
        epoch_residuals = [item[2] - offset for item in epoch]
        maximum_error = max((abs(value) for value in epoch_residuals), default=0)
        if maximum_error > timestamp_tolerance_ns:
            raise ValueError(
                f"direct/runner timestamp mismatch in clock epoch {epoch_index}: "
                f"{maximum_error}ns exceeds {timestamp_tolerance_ns}ns"
            )
        residuals.extend(epoch_residuals)
        offsets.append(offset)
        absolute_epoch_residuals = sorted(abs(value) for value in epoch_residuals)
        segments.append(
            {
                "index": epoch_index,
                "runner_packet_start": epoch[0][0].index,
                "runner_packet_end": epoch[-1][0].index,
                "direct_packet_start": epoch[0][1],
                "direct_packet_end": epoch[-1][1],
                "packets": packet_count,
                "runner_span_ns": span_ns,
                "clock_offset_ns": offset,
                "timestamp_error_max_ns": maximum_error,
                "timestamp_error_p95_ns": _percentile_95(absolute_epoch_residuals),
            }
        )

    steps: list[dict[str, Any]] = []
    for step_index, (boundary, observed_delta) in enumerate(
        zip(boundaries, boundary_deltas, strict=True)
    ):
        offset_delta = offsets[step_index + 1] - offsets[step_index]
        end_anchor_corroborated = boundary == end_anchored_boundary
        if end_anchor_corroborated:
            assert end_anchor_adjustment_ns is not None
            cumulative_offset_delta = offsets[-1] - offsets[0]
            if (
                end_anchor_adjustment_ns <= 0
                or abs(cumulative_offset_delta - end_anchor_adjustment_ns)
                > DEFAULT_TIMESTAMP_TOLERANCE_NS
            ):
                raise ValueError(
                    "direct/runner final clock step does not match the "
                    "realtime/monotonic end-anchor adjustment"
                )
        elif not CLOCK_STEP_MIN_NS <= offset_delta <= CLOCK_STEP_MAX_NS:
            raise ValueError(
                "direct/runner clock-step epoch offsets are outside the 50--100 ms bound"
            )
        packet, direct_index, _offset = ordered_matches[boundary]
        steps.append(
            {
                "index": step_index,
                "runner_packet": packet.index,
                "direct_packet": direct_index,
                "runner_time_ns": packet.monotonic_us * 1_000,
                "observed_boundary_delta_ns": observed_delta,
                "epoch_offset_delta_ns": offset_delta,
                "end_anchor_corroborated": end_anchor_corroborated,
            }
        )

    clock_offset = offsets[0]
    return (
        residuals,
        clock_offset,
        {
            "direct_clock_model": ("positive-abrupt-steps" if steps else "constant-offset"),
            "direct_clock_segment_count": len(segments),
            "direct_clock_step_count": len(steps),
            "direct_clock_segments": segments,
            "direct_clock_steps": steps,
            "direct_clock_end_anchor_adjustment_ns": end_anchor_adjustment_ns,
            "direct_clock_end_anchor_used": end_anchored_boundary is not None,
        },
    )


def _clock_adjustment_ns(clock_anchors: Mapping[str, Any] | None) -> int | None:
    if clock_anchors is None:
        return None
    if set(clock_anchors) != CLOCK_ANCHOR_FIELDS:
        raise ValueError("capture clock anchors have invalid fields")
    values: dict[str, int] = {}
    for field in CLOCK_ANCHOR_FIELDS:
        value = clock_anchors.get(field)
        if type(value) is not int or value < 0:
            raise ValueError(f"capture clock anchor {field} must be a non-negative integer")
        values[field] = value
    monotonic_elapsed = values["end_monotonic_ns"] - values["start_monotonic_ns"]
    if monotonic_elapsed <= 0:
        raise ValueError("capture monotonic end anchor must follow its start anchor")
    realtime_elapsed = values["end_realtime_unix_ns"] - values["start_realtime_unix_ns"]
    return realtime_elapsed - monotonic_elapsed


def _read_exact_csv(path: Path, fields: tuple[str, ...]) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source)
            rows = list(reader)
    except OSError as error:
        raise ValueError(f"cannot read direct/runner evidence {path}") from error
    if reader.fieldnames != list(fields):
        raise ValueError(f"invalid direct/runner evidence columns in {path}")
    return rows


def _percentile_95(sorted_values: list[int]) -> int:
    if not sorted_values:
        return 0
    return sorted_values[max(0, math.ceil(len(sorted_values) * 0.95) - 1)]


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _direction(value: Any, label: str) -> str:
    if value not in {"outgoing", "incoming"}:
        raise ValueError(f"{label} has an invalid direction")
    return str(value)


def _integer(value: Any, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} is not an integer") from error
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{label} is not an integer")
    return parsed


def _unsigned(value: Any, label: str) -> int:
    parsed = _integer(value, label)
    if parsed < 0:
        raise ValueError(f"{label} must be non-negative")
    return parsed


def _positive(value: Any, label: str) -> int:
    parsed = _integer(value, label)
    if parsed <= 0:
        raise ValueError(f"{label} must be positive")
    return parsed


def _schedule_realization_metrics(sample: Path) -> dict[str, Any]:
    path = sample / "neqo/schedule.csv"
    if not path.is_file():
        return {}
    with path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    satisfactions: dict[str, int] = {}
    miss_reasons: dict[str, int] = {}
    directions: dict[str, int] = {}
    outgoing_size_mismatches = 0
    outgoing_size_error_bytes = 0
    for row in rows:
        satisfaction = str(row.get("satisfaction", ""))
        direction = str(row.get("direction", ""))
        satisfactions[satisfaction] = satisfactions.get(satisfaction, 0) + 1
        directions[direction] = directions.get(direction, 0) + 1
        reason = str(row.get("miss_reason", ""))
        if reason:
            miss_reasons[reason] = miss_reasons.get(reason, 0) + 1
        if direction == "outgoing" and satisfaction == "satisfied":
            try:
                requested = int(row["size"])
                observed = int(row["observed_size"])
            except (KeyError, TypeError, ValueError):
                outgoing_size_mismatches += 1
                continue
            if requested != observed:
                outgoing_size_mismatches += 1
                outgoing_size_error_bytes += abs(requested - observed)
    return {
        "scheduled_events": len(rows),
        "scheduled_outgoing_events": directions.get("outgoing", 0),
        "scheduled_incoming_events": directions.get("incoming", 0),
        "satisfied_events": satisfactions.get("satisfied", 0),
        "missed_events": satisfactions.get("missed", 0),
        "missed_event_reasons": dict(sorted(miss_reasons.items())),
        "outgoing_size_mismatch_events": outgoing_size_mismatches,
        "outgoing_size_absolute_error_bytes": outgoing_size_error_bytes,
    }


_INTEGER = "integer"
_BOOLEAN = "boolean"
_BURST_VECTOR = "burst-vector"
_SCHEDULED_INCOMING_CONTRACT = {
    "scheduled_incoming_requested_bytes": _INTEGER,
    "scheduled_incoming_consumed_bytes": _INTEGER,
    "scheduled_incoming_retired_bytes": _INTEGER,
    "scheduled_incoming_unresolved_bytes": _INTEGER,
}
_DIAGNOSTIC_CONTRACTS: dict[str, dict[str, str]] = {
    "traffic-morphing": {
        **{
            key: _INTEGER
            for key in (
                "morphing_egress_packets",
                "morphing_egress_source_bytes",
                "morphing_egress_target_bytes",
                "morphing_egress_bypasses",
                "morphing_egress_pacing_bypasses",
                "morphing_egress_congestion_bypasses",
                "morphing_egress_coalesced_bypasses",
                "morphing_egress_invalid_size_bypasses",
                "morphing_egress_target_selection_bypasses",
                "morphing_egress_target_l1_ppm",
                "morphing_ingress_requested_bytes",
                "morphing_ingress_received_bytes",
                "morphing_ingress_shortfall_bytes",
                "morphing_ingress_wire_mixture_l1_ppm",
                "suppressed_cover_feedback",
            )
        },
    },
    "wtf-pad": {
        "padding_events": _INTEGER,
        "padding_event_guard_triggered": _BOOLEAN,
        **{
            key: _INTEGER
            for key in (
                "wtf_pad_incoming_desired_bytes",
                "wtf_pad_incoming_requested_bytes",
                "wtf_pad_incoming_received_bytes",
                "wtf_pad_incoming_shortfall_bytes",
                "wtf_pad_incoming_size_error_bytes",
                "wtf_pad_incoming_observed_events",
                "wtf_pad_incoming_lag_us_total",
                "wtf_pad_incoming_lag_us_max",
                "wtf_pad_silent_to_burst",
                "wtf_pad_burst_to_gap",
                "wtf_pad_gap_to_burst",
                "wtf_pad_burst_to_silent",
                "suppressed_cover_feedback",
            )
        },
    },
    "walkie-talkie": {
        **{
            key: _INTEGER
            for key in (
                "retried_outgoing_events",
                "walkie_talkie_target_outgoing_cells",
                "walkie_talkie_target_incoming_cells",
                "walkie_talkie_observed_outgoing_cells",
                "walkie_talkie_observed_incoming_cells",
                "walkie_talkie_outgoing_shortfall_cells",
                "walkie_talkie_incoming_shortfall_cells",
                "walkie_talkie_outgoing_overflow_cells",
                "walkie_talkie_incoming_overflow_cells",
                "walkie_talkie_incoming_shortfall_bytes",
                "walkie_talkie_incoming_chaff_bytes",
                "walkie_talkie_target_observed_cell_l1",
                "walkie_talkie_target_observed_burst_l1",
                "walkie_talkie_control_only_crossings",
                "walkie_talkie_application_stream_crossing_bytes",
                "walkie_talkie_natural_outgoing_bytes",
                "walkie_talkie_natural_incoming_bytes",
                "walkie_talkie_source_envelope_overflow_cells",
                "walkie_talkie_expected_application_batches",
                "walkie_talkie_observed_application_batches",
                "walkie_talkie_application_batch_overflow",
                "walkie_talkie_application_batches_completed",
                "walkie_talkie_batch_lifecycle_errors",
            )
        },
        "walkie_talkie_application_batch_active": _BOOLEAN,
        "walkie_talkie_burst_realization": _BURST_VECTOR,
    },
}


def _diagnostics_match_contract(defense: str, diagnostics: dict[str, Any]) -> bool:
    contract = _DIAGNOSTIC_CONTRACTS.get(defense)
    if contract is None:
        return True
    if defense == "traffic-morphing":
        selected = {
            key: value
            for key, value in diagnostics.items()
            if key.startswith("morphing_") or key == "suppressed_cover_feedback"
        }
    elif defense == "wtf-pad":
        selected = {
            key: value
            for key, value in diagnostics.items()
            if key.startswith("wtf_pad_")
            or key
            in {
                "padding_events",
                "padding_event_guard_triggered",
                "suppressed_cover_feedback",
            }
        }
    else:
        selected = {
            key: value
            for key, value in diagnostics.items()
            if key.startswith("walkie_talkie_") or key == "retried_outgoing_events"
        }
    if set(selected) != set(contract):
        return False
    return all(_diagnostic_value_matches(kind, selected[key]) for key, kind in contract.items())


def _scheduled_incoming_diagnostics_match(diagnostics: dict[str, Any]) -> bool:
    selected = {
        key: value for key, value in diagnostics.items() if key.startswith("scheduled_incoming_")
    }
    if set(selected) != set(_SCHEDULED_INCOMING_CONTRACT):
        return False
    if not all(
        _diagnostic_value_matches(kind, selected[key])
        for key, kind in _SCHEDULED_INCOMING_CONTRACT.items()
    ):
        return False
    requested = selected["scheduled_incoming_requested_bytes"]
    consumed = selected["scheduled_incoming_consumed_bytes"]
    retired = selected["scheduled_incoming_retired_bytes"]
    unresolved = selected["scheduled_incoming_unresolved_bytes"]
    return (
        requested == consumed + retired + unresolved
        and requested == consumed
        and retired == 0
        and unresolved == 0
    )


def _diagnostic_value_matches(kind: str, value: Any) -> bool:
    if kind == _INTEGER:
        return type(value) is int and value >= 0
    if kind == _BOOLEAN:
        return type(value) is bool
    if kind != _BURST_VECTOR or not isinstance(value, list) or not value:
        return False
    expected_fields = {
        "index",
        "target_outgoing_cells",
        "target_incoming_cells",
        "observed_outgoing_cells",
        "observed_incoming_cells",
    }
    return all(
        isinstance(item, dict)
        and set(item) == expected_fields
        and item["index"] == index
        and all(type(item[field]) is int and item[field] >= 0 for field in expected_fields)
        for index, item in enumerate(value)
    )


def fidelity_eligible(
    defense: str,
    diagnostics: dict[str, Any],
    *,
    sample_eligible: bool,
    missed_events: Any = None,
    outgoing_size_mismatches: Any = None,
) -> bool:
    if not sample_eligible:
        return False
    if (
        defense in DEFENSE_ADAPTATIONS
        and defense != "undefended"
        and (
            type(missed_events) is not int
            or missed_events != 0
            or type(outgoing_size_mismatches) is not int
            or outgoing_size_mismatches != 0
        )
    ):
        return False
    if (
        defense in DEFENSE_ADAPTATIONS
        and defense != "undefended"
        and not _scheduled_incoming_diagnostics_match(diagnostics)
    ):
        return False
    if not _diagnostics_match_contract(defense, diagnostics):
        return False
    if defense == "traffic-morphing":
        return (
            int(diagnostics.get("morphing_egress_bypasses", 0)) == 0
            and int(diagnostics.get("morphing_ingress_shortfall_bytes", 0)) == 0
        )
    if defense == "wtf-pad":
        return (
            diagnostics["padding_event_guard_triggered"] is False
            and diagnostics["wtf_pad_incoming_shortfall_bytes"] == 0
        )
    if defense == "walkie-talkie":
        zero_error_keys = (
            "walkie_talkie_outgoing_shortfall_cells",
            "walkie_talkie_incoming_shortfall_cells",
            "walkie_talkie_outgoing_overflow_cells",
            "walkie_talkie_incoming_overflow_cells",
            "walkie_talkie_incoming_shortfall_bytes",
            "walkie_talkie_target_observed_burst_l1",
            "walkie_talkie_application_stream_crossing_bytes",
            "walkie_talkie_source_envelope_overflow_cells",
            "walkie_talkie_application_batch_overflow",
            "walkie_talkie_batch_lifecycle_errors",
        )
        return (
            all(diagnostics[key] == 0 for key in zero_error_keys)
            and diagnostics["walkie_talkie_application_batch_active"] is False
            and diagnostics["walkie_talkie_expected_application_batches"]
            == diagnostics["walkie_talkie_observed_application_batches"]
            == diagnostics["walkie_talkie_application_batches_completed"]
            and all(
                burst["target_outgoing_cells"] == burst["observed_outgoing_cells"]
                and burst["target_incoming_cells"] == burst["observed_incoming_cells"]
                for burst in diagnostics["walkie_talkie_burst_realization"]
            )
        )
    return True
