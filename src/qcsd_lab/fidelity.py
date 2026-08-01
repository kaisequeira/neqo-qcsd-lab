from __future__ import annotations

import csv
import ipaddress
import json
import math
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from statistics import median_low
from typing import Any

from .capture import read_normalized_trace
from .defenses import DEFENSE_ADAPTATIONS, defense_from_runtime_identity
from .util import atomic_text, load_json, sha256_file

REQUIRED_LIST_FIELDS = (
    "preserved_invariants",
    "exact_client_mechanisms",
    "qcsd_approximations",
    "unavailable_peer_properties",
    "paper_references",
)

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


def reconcile_direct_runner(
    sample: Path,
    *,
    timestamp_tolerance_ns: int = DEFAULT_TIMESTAMP_TOLERANCE_NS,
) -> DirectRunnerReconciliation:
    """Bind runner-observed UDP datagrams to the normalized direct trace."""

    sample = sample.resolve()
    metadata = _object(load_json(sample / "sample.json"), "sample metadata")
    view = _validate_direct_view(sample, metadata)
    result = reconcile_direct_runner_artifacts(
        sample / "neqo/run.json",
        sample / "neqo/packets.csv",
        sample / "traces/direct-quic.csv",
        timestamp_tolerance_ns=timestamp_tolerance_ns,
    )
    return DirectRunnerReconciliation(
        metrics={"direct_capture_sha256": view["capture_sha256"], **result.metrics},
        limitations=result.limitations,
        evidence_eligible=result.evidence_eligible,
    )


def reconcile_direct_runner_artifacts(
    run_path: Path,
    runner_packets_path: Path,
    direct_trace_path: Path,
    *,
    timestamp_tolerance_ns: int = DEFAULT_TIMESTAMP_TOLERANCE_NS,
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
    matches, unmatched_tail, residuals, clock_offset = _reconcile_runner_packets(
        runner_packets,
        direct_packets,
        timestamp_tolerance_ns=timestamp_tolerance_ns,
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
            "direct_timestamp_tolerance_ns": timestamp_tolerance_ns,
            "direct_timestamp_error_max_ns": max(absolute_residuals, default=0),
            "direct_timestamp_error_p95_ns": _percentile_95(absolute_residuals),
        },
        limitations=RECONCILIATION_LIMITATIONS,
        evidence_eligible=len(matches) == len(runner_packets),
    )


def _validate_direct_view(sample: Path, metadata: Mapping[str, Any]) -> Mapping[str, Any]:
    views = metadata.get("views")
    matches = (
        [view for view in views if isinstance(view, Mapping) and view.get("id") == "direct-quic"]
        if isinstance(views, list)
        else []
    )
    if len(matches) != 1:
        raise ValueError("sample must declare one direct-quic view")
    view = matches[0]
    if (
        view.get("valid") is not True
        or view.get("kind") != "direct-quic"
        or view.get("interface") != "eth0"
        or view.get("primary") is not True
        or view.get("capture_active_through_settle") is not True
        or view.get("capture_path") != "captures/direct-quic.pcapng"
        or view.get("trace_path") != "traces/direct-quic.csv"
        or view.get("length_basis") != "frame.len"
        or view.get("link_type") != "Ethernet"
    ):
        raise ValueError("direct observer declaration is incompatible")
    capture = sample / "captures/direct-quic.pcapng"
    trace = sample / "traces/direct-quic.csv"
    if (
        not capture.is_file()
        or not trace.is_file()
        or view.get("capture_sha256") != sha256_file(capture)
        or view.get("trace_sha256") != sha256_file(trace)
    ):
        raise ValueError("direct observer hashes do not match its artifacts")
    return view


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
) -> tuple[dict[int, int], list[int], list[int], int]:
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

    offsets = [
        direct[direct_index].relative_time_ns - runner[runner_index].monotonic_us * 1_000
        for runner_index, direct_index in matches.items()
    ]
    clock_offset = median_low(offsets)
    residuals = [offset - clock_offset for offset in offsets]
    maximum_error = max((abs(value) for value in residuals), default=0)
    if maximum_error > timestamp_tolerance_ns:
        raise ValueError(
            f"direct/runner timestamp mismatch: {maximum_error}ns exceeds "
            f"{timestamp_tolerance_ns}ns"
        )
    return matches, unmatched, residuals, clock_offset


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


def write_fidelity_record(
    sample: Path,
    *,
    baseline_wire_bytes: int | None,
) -> tuple[Path, bool]:
    """Write one machine-readable client-only adaptation record."""

    metadata = load_json(sample / "sample.json")
    run_path = sample / "neqo" / "run.json"
    run = load_json(run_path) if run_path.is_file() else {}
    record = _fidelity_record(
        sample,
        metadata,
        run,
        baseline_wire_bytes=baseline_wire_bytes,
    )
    destination = sample / "fidelity.yml"
    # JSON is valid YAML 1.2 while providing deterministic, dependency-free
    # parsing for validators and downstream analysis.
    atomic_text(destination, json.dumps(record, indent=2, sort_keys=True) + "\n")
    return destination, bool(record["fidelity_eligible"])


def validate_fidelity_record(
    sample: Path,
    indexed: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Validate one fidelity artifact against its sample and direct trace."""

    if indexed.get("fidelity_path") != "fidelity.yml":
        raise ValueError("sample fidelity path is invalid")
    if metadata.get("fidelity_path") != "fidelity.yml":
        raise ValueError("sample metadata fidelity path is invalid")
    path = sample / "fidelity.yml"
    if not path.is_file():
        raise ValueError("sample fidelity record is missing")
    record = load_json(path)
    if indexed.get("defense") != metadata.get("defense") or indexed.get(
        "runtime_kind"
    ) != metadata.get("runtime_kind"):
        raise ValueError("sample fidelity identity binding is invalid")
    defense = defense_from_runtime_identity(
        indexed.get("defense"),
        indexed.get("runtime_kind"),
    )
    if (
        record.get("schema_version") != 1
        or record.get("defense") != defense
        or record.get("adaptation") != ("none" if defense == "undefended" else "qcsd-client-only")
        or not isinstance(record.get("realization_metrics"), dict)
        or any(not isinstance(record.get(key), list) for key in REQUIRED_LIST_FIELDS)
    ):
        raise ValueError("sample fidelity record has an invalid contract")
    run_path = sample / "neqo/run.json"
    run = load_json(run_path) if run_path.is_file() else {}
    expected_record = _fidelity_record(
        sample,
        metadata,
        run,
        baseline_wire_bytes=_paired_baseline_wire_bytes(sample, indexed),
    )
    sample_eligible = indexed.get("eligible") is True
    expected = expected_record["fidelity_eligible"]
    if (
        record.get("sample_eligible") is not sample_eligible
        or record.get("fidelity_eligible") is not expected
        or metadata.get("fidelity_eligible") is not expected
        or indexed.get("fidelity_eligible") is not expected
    ):
        raise ValueError("sample fidelity eligibility is incorrect")
    if record["realization_metrics"].get("direct_wire_bytes") != expected_record[
        "realization_metrics"
    ].get("direct_wire_bytes"):
        raise ValueError("sample fidelity direct-byte metric is incorrect")
    comparable_record = record
    # Results sealed before the lab/fitter boundary was simplified contain a
    # redundant morphing-only reconstruction block.  The generic direct
    # reconciliation and runtime diagnostics are still reproduced exactly;
    # tolerate only additional legacy ``morphing_*`` metrics so historical
    # captures remain independently valid without retaining that code path.
    if defense == "traffic-morphing" and isinstance(record.get("realization_metrics"), dict):
        expected_metrics = expected_record["realization_metrics"]
        observed_metrics = record["realization_metrics"]
        extras = set(observed_metrics) - set(expected_metrics)
        if extras and all(key.startswith("morphing_") for key in extras):
            comparable_record = {
                **record,
                "realization_metrics": {key: observed_metrics.get(key) for key in expected_metrics},
            }
    if comparable_record != expected_record:
        raise ValueError("sample fidelity record does not reproduce from sealed evidence")
    return record


def _fidelity_record(
    sample: Path,
    metadata: dict[str, Any],
    run: dict[str, Any],
    *,
    baseline_wire_bytes: int | None,
) -> dict[str, Any]:
    defense = defense_from_runtime_identity(
        metadata.get("defense"),
        metadata.get("runtime_kind"),
    )
    trace_path = sample / "traces/direct-quic.csv"
    trace = read_normalized_trace(trace_path) if trace_path.is_file() else []
    wire_bytes = sum(int(row["length_bytes"]) for row in trace)
    diagnostics = run.get("defense_diagnostics", metadata.get("defense_diagnostics"))
    if not isinstance(diagnostics, dict):
        diagnostics = {}
    schedule_metrics = _schedule_realization_metrics(sample)
    realization_metrics = {
        "direct_wire_bytes": wire_bytes if trace else None,
        "direct_wire_byte_ratio_vs_undefended": (
            wire_bytes / baseline_wire_bytes if baseline_wire_bytes else None
        ),
        "direct_wire_byte_overhead_ratio": (
            wire_bytes / baseline_wire_bytes - 1.0 if baseline_wire_bytes else None
        ),
        "direct_added_wire_bytes_vs_undefended": (
            wire_bytes - baseline_wire_bytes if baseline_wire_bytes is not None else None
        ),
        **schedule_metrics,
        **{
            key: value
            for key, value in sorted(diagnostics.items())
            if _is_realization_metric(defense, key)
        },
    }
    direct_reconciliation = None
    if (
        trace
        and (sample / "neqo/packets.csv").is_file()
        and run.get("completion_status") == "complete"
    ):
        direct_reconciliation = reconcile_direct_runner(sample)
        realization_metrics.update(direct_reconciliation.metrics)
    eligible = fidelity_eligible(
        defense,
        diagnostics,
        sample_eligible=metadata.get("eligible") is True,
        missed_events=schedule_metrics.get("missed_events"),
        outgoing_size_mismatches=schedule_metrics.get("outgoing_size_mismatch_events"),
    )
    if metadata.get("eligible") is True:
        eligible = bool(
            eligible
            and direct_reconciliation is not None
            and direct_reconciliation.evidence_eligible
        )
    adaptation = DEFENSE_ADAPTATIONS[defense]
    record = {
        "schema_version": 1,
        "defense": defense,
        "adaptation": "qcsd-client-only" if defense != "undefended" else "none",
        "paper_equivalent": False if defense != "undefended" else None,
        "preserved_invariants": list(adaptation.preserved_invariants),
        "exact_client_mechanisms": list(adaptation.exact_client_mechanisms),
        "qcsd_approximations": list(adaptation.qcsd_approximations),
        "unavailable_peer_properties": list(adaptation.unavailable_peer_properties),
        "realization_metrics": realization_metrics,
        "paper_references": list(adaptation.paper_references),
        "sample_eligible": metadata.get("eligible") is True,
        "fidelity_eligible": eligible,
    }
    if direct_reconciliation is not None:
        limitations = list(direct_reconciliation.limitations)
        record["evidence_limitations"] = limitations
    return record


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
        "credit_advertised_events": satisfactions.get("credit_advertised", 0),
        "missed_events": satisfactions.get("missed", 0),
        "missed_event_reasons": dict(sorted(miss_reasons.items())),
        "outgoing_size_mismatch_events": outgoing_size_mismatches,
        "outgoing_size_absolute_error_bytes": outgoing_size_error_bytes,
    }


def _paired_baseline_wire_bytes(
    sample: Path,
    indexed: dict[str, Any],
) -> int | None:
    root = sample.parents[2]
    index_path = root / "samples.jsonl"
    if not index_path.is_file():
        return None
    visit_id = indexed.get("visit_id")
    with index_path.open(encoding="utf-8") as source:
        members = [json.loads(line) for line in source if line.strip()]
    for member in members:
        if member.get("visit_id") != visit_id:
            continue
        member_path = root / str(member.get("path", ""))
        metadata_path = member_path / "sample.json"
        if not metadata_path.is_file() or load_json(metadata_path).get("baseline") is not True:
            continue
        trace_path = member_path / "traces/direct-quic.csv"
        if not trace_path.is_file():
            return None
        rows = read_normalized_trace(trace_path)
        return sum(int(row["length_bytes"]) for row in rows)
    return None


def _is_realization_metric(defense: str, key: str) -> bool:
    prefix = {
        "traffic-morphing": "morphing_",
        "wtf-pad": "wtf_pad_",
        "walkie-talkie": "walkie_talkie_",
    }.get(defense)
    return bool(
        defense == "traffic-morphing"
        and key == "suppressed_cover_feedback"
        or defense == "wtf-pad"
        and key
        in {
            "padding_events",
            "padding_event_guard_triggered",
            "suppressed_cover_feedback",
        }
        or defense == "walkie-talkie"
        and key == "retried_outgoing_events"
        or (prefix is not None and key.startswith(prefix))
    )


_INTEGER = "integer"
_BOOLEAN = "boolean"
_BURST_VECTOR = "burst-vector"
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
                "morphing_ingress_target_l1_ppm",
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
