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
SCHEDULE_PREFIX_FIELDS = (
    "target_time_us",
    "direction",
    "size",
    "connection",
    "action_time_us",
    "satisfaction",
    "observed_size",
    "miss_reason",
    "slot_id",
)
LEGACY_SCHEDULE_QCSD_FIELDS = (
    "qcsd_outcome_schema_version",
    "send_policy",
    "desired_udp_bytes",
    "observed_udp_bytes",
    "application_stream_bytes",
    "retransmission_stream_bytes",
    "chaff_stream_bytes",
    "defense_control_bytes",
    "quic_padding_bytes",
    "other_quic_bytes",
    "lateness_us",
    "congestion_reason",
)
ADVERTISEMENT_SCHEDULE_QCSD_FIELDS = LEGACY_SCHEDULE_QCSD_FIELDS + (
    "credit_advertised_at_us",
    "credit_advertisement_delay_us",
)
CONSUMPTION_SCHEDULE_QCSD_FIELDS = ADVERTISEMENT_SCHEDULE_QCSD_FIELDS + (
    "credit_consumed_at_us",
    "credit_consumption_delay_us",
)
SCHEDULE_QCSD_FIELDS = CONSUMPTION_SCHEDULE_QCSD_FIELDS + ("terminal_defense_elapsed_us",)
DEFAULT_TIMESTAMP_TOLERANCE_NS = 10_000_000
CLOCK_STEP_MIN_NS = 50_000_000
BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US = 5_000
BUFLO_TERMINAL_SUBCELL_POLICY = (
    "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
)
BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT = (
    "typed_stop_sending_and_reset_stream_defense_control_may_follow_the_last_exact_cell"
)
BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS = (
    "post-cancellation unscheduled packet composition proves defense-control "
    "bytes but does not expose individual QUIC frame identity"
)
BUFLO_SCHEDULE_STOP_POLICY = (
    "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
    "then_drain_already_advertised_incoming_credit"
)
BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS = (
    "exact_controller_terminal_resolution_duration_at_relative_to_defense_start_"
    "floored_to_microseconds"
)
BUFLO_SCHEDULE_STOP_V4_INTEGER_KEYS = frozenset(
    {
        "buflo_schedule_stop_latched_at_us",
        "buflo_schedule_stop_available_bytes",
        "buflo_schedule_stop_required_bytes",
        "buflo_schedule_stop_scheduled_incoming_cells",
        "buflo_schedule_stop_scheduled_outgoing_cells",
        "buflo_schedule_stop_terminal_incoming_cells",
        "buflo_schedule_stop_terminal_outgoing_cells",
    }
)
BUFLO_SCHEDULE_STOP_V4_BOOLEAN_KEYS = frozenset({"buflo_schedule_stop_latched"})
BUFLO_SCHEDULE_STOP_V4_KEYS = (
    BUFLO_SCHEDULE_STOP_V4_INTEGER_KEYS | BUFLO_SCHEDULE_STOP_V4_BOOLEAN_KEYS
)
CS_BUFLO_LOCAL_ET_V3_INTEGER_KEYS = frozenset(
    {
        "cs_buflo_local_et_latched_at_us",
        "cs_buflo_local_et_application_receive_streams_handed_off",
        "cs_buflo_local_et_application_parser_boundaries_handed_off",
        "cs_buflo_local_et_application_parser_lease_bytes_handed_off",
        "cs_buflo_local_et_application_send_endpoints_released",
        "cs_buflo_post_local_et_natural_outgoing_bytes",
        "cs_buflo_post_local_et_natural_incoming_bytes",
    }
)
CS_BUFLO_LOCAL_ET_V3_BOOLEAN_KEYS = frozenset({"cs_buflo_local_et_before_application_complete"})
CS_BUFLO_LOCAL_ET_V3_KEYS = CS_BUFLO_LOCAL_ET_V3_INTEGER_KEYS | CS_BUFLO_LOCAL_ET_V3_BOOLEAN_KEYS
CS_BUFLO_STOP_DRAIN_V4_INTEGER_KEYS = frozenset(
    {
        "cs_buflo_early_termination_translation_version",
        "cs_buflo_outgoing_termination_stop_crossing_total_bytes",
        "cs_buflo_incoming_termination_stop_crossing_total_bytes",
        "cs_buflo_outgoing_termination_stop_crossing_increment_bytes",
        "cs_buflo_incoming_termination_stop_crossing_increment_bytes",
        "cs_buflo_outgoing_termination_stop_latched_at_us",
        "cs_buflo_incoming_termination_stop_latched_at_us",
        "cs_buflo_outgoing_termination_stop_scheduled_cells_at_stop",
        "cs_buflo_incoming_termination_stop_scheduled_cells_at_stop",
        "cs_buflo_outgoing_termination_stop_terminal_cells_at_stop",
        "cs_buflo_incoming_termination_stop_terminal_cells_at_stop",
        "cs_buflo_outgoing_termination_stop_progress_bytes_at_stop",
        "cs_buflo_incoming_termination_stop_progress_bytes_at_stop",
        "cs_buflo_outgoing_termination_stop_padding_target_bytes_at_stop",
        "cs_buflo_incoming_termination_stop_padding_target_bytes_at_stop",
        "cs_buflo_outgoing_termination_stop_provisional_invalidation_count",
        "cs_buflo_incoming_termination_stop_provisional_invalidation_count",
    }
)
CS_BUFLO_STOP_DRAIN_V4_BOOLEAN_KEYS = frozenset(
    {
        "cs_buflo_outgoing_termination_stop_latched",
        "cs_buflo_incoming_termination_stop_latched",
    }
)
CS_BUFLO_STOP_DRAIN_V4_STRING_KEYS = frozenset(
    {
        "cs_buflo_termination_stop_policy",
        "cs_buflo_outgoing_termination_stop_reason",
        "cs_buflo_incoming_termination_stop_reason",
        "cs_buflo_outgoing_termination_stop_phase",
        "cs_buflo_incoming_termination_stop_phase",
    }
)
CS_BUFLO_STOP_DRAIN_V4_KEYS = (
    CS_BUFLO_STOP_DRAIN_V4_INTEGER_KEYS
    | CS_BUFLO_STOP_DRAIN_V4_BOOLEAN_KEYS
    | CS_BUFLO_STOP_DRAIN_V4_STRING_KEYS
)
BUFLO_TERMINAL_STATE_V1_KEYS = frozenset(
    {
        "terminal_subcell_policy",
        "terminal_subcell_observer_effect",
        "pending_request_cancellations",
        "stream_cancellations",
        "receipt_cancellations",
        "exact_capacity_bytes_cancelled",
        "whole_cell_floor_bytes",
        "terminal_latched",
        "terminal_latched_at_us",
        "open_streams_at_latch",
        "parser_lease_bytes_at_latch",
        "pending_parser_boundaries_at_latch",
        "typed_cancellation_action_events",
        "first_cancellation_monotonic_us",
        "last_exact_outgoing_cell_monotonic_us",
        "last_scheduled_terminal_monotonic_us",
        "control_evidence_semantics",
        "post_cancellation_unscheduled_defense_control_packets",
        "post_cancellation_unscheduled_defense_control_bytes",
        "first_post_cancellation_defense_control_monotonic_us",
        "last_post_cancellation_defense_control_monotonic_us",
        "paper_equivalent",
        "implementation_scope",
    }
)
BUFLO_TERMINAL_STATE_V2_KEYS = BUFLO_TERMINAL_STATE_V1_KEYS | {
    "schema_version",
    "pending_application_parser_boundaries_at_latch",
}
BUFLO_TERMINAL_STATE_KEYS = BUFLO_TERMINAL_STATE_V2_KEYS | {"schedule_stop"}
BUFLO_SCHEDULE_STOP_STATE_KEYS = frozenset(
    {
        "policy",
        "terminal_time_semantics",
        "latched",
        "latched_at_us",
        "available_bytes",
        "required_bytes",
        "directions",
    }
)
BUFLO_SCHEDULE_STOP_DIRECTION_KEYS = frozenset(
    {
        "scheduled_cells_at_stop",
        "terminal_cells_at_stop",
        "drained_cells_after_stop",
        "last_scheduled_target_us",
        "last_terminal_at_us",
        "terminal_cells_strictly_before_stop",
        "terminal_cells_at_or_before_stop",
        "terminal_cells_at_stop_timestamp",
    }
)


def _buflo_schedule_stop_state_valid(value: Any, *, terminal_latched_at_us: int) -> bool:
    """Validate derived schema-3 BuFLO stop-then-drain chronology."""

    if not isinstance(value, Mapping) or set(value) != BUFLO_SCHEDULE_STOP_STATE_KEYS:
        return False
    stop_us = value.get("latched_at_us")
    available = value.get("available_bytes")
    required = value.get("required_bytes")
    directions = value.get("directions")
    if (
        value.get("policy") != BUFLO_SCHEDULE_STOP_POLICY
        or value.get("terminal_time_semantics") != BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS
        or value.get("latched") is not True
        or type(stop_us) is not int
        or stop_us < 10_000_000
        or stop_us > terminal_latched_at_us
        or type(available) is not int
        or type(required) is not int
        or required != 1_200
        or not 0 <= available < required
        or not isinstance(directions, Mapping)
        or set(directions) != {"outgoing", "incoming"}
    ):
        return False
    for direction in ("outgoing", "incoming"):
        state = directions[direction]
        if (
            not isinstance(state, Mapping)
            or set(state) != BUFLO_SCHEDULE_STOP_DIRECTION_KEYS
            or any(type(state[key]) is not int or state[key] < 0 for key in state)
        ):
            return False
        scheduled = state["scheduled_cells_at_stop"]
        terminal = state["terminal_cells_at_stop"]
        drained = state["drained_cells_after_stop"]
        strictly_before = state["terminal_cells_strictly_before_stop"]
        at_or_before = state["terminal_cells_at_or_before_stop"]
        at_timestamp = state["terminal_cells_at_stop_timestamp"]
        if (
            scheduled == 0
            or not 0 <= terminal <= scheduled
            or drained != scheduled - terminal
            or not 0 <= strictly_before <= terminal <= at_or_before <= scheduled
            or at_timestamp != at_or_before - strictly_before
            or state["last_scheduled_target_us"] > stop_us
            or state["last_terminal_at_us"] > terminal_latched_at_us
            or (direction == "outgoing" and drained != 0)
        ):
            return False
    outgoing = directions["outgoing"]
    incoming = directions["incoming"]
    return bool(
        outgoing["scheduled_cells_at_stop"] == incoming["scheduled_cells_at_stop"]
        and outgoing["last_scheduled_target_us"] == incoming["last_scheduled_target_us"]
    )


def buflo_terminal_state_valid(value: Any) -> bool:
    """Validate implicit-v1 or explicit schema-2/3 BuFLO tail evidence."""

    if not isinstance(value, Mapping):
        return False
    schema_version = value.get("schema_version", 1)
    if type(schema_version) is not int:
        return False
    expected_keys = (
        BUFLO_TERMINAL_STATE_V1_KEYS
        if schema_version == 1
        else BUFLO_TERMINAL_STATE_V2_KEYS
        if schema_version == 2
        else BUFLO_TERMINAL_STATE_KEYS
        if schema_version == 3
        else None
    )
    if expected_keys is None or set(value) != expected_keys:
        return False
    integer_fields = {
        "pending_request_cancellations",
        "stream_cancellations",
        "receipt_cancellations",
        "exact_capacity_bytes_cancelled",
        "whole_cell_floor_bytes",
        "terminal_latched_at_us",
        "open_streams_at_latch",
        "parser_lease_bytes_at_latch",
        "pending_parser_boundaries_at_latch",
        "typed_cancellation_action_events",
        "post_cancellation_unscheduled_defense_control_packets",
        "post_cancellation_unscheduled_defense_control_bytes",
    }
    if schema_version in {2, 3}:
        integer_fields.add("pending_application_parser_boundaries_at_latch")
    if any(type(value[field]) is not int or value[field] < 0 for field in integer_fields):
        return False
    streams = value["stream_cancellations"]
    capacity = value["exact_capacity_bytes_cancelled"]
    last_exact = value["last_exact_outgoing_cell_monotonic_us"]
    last_scheduled = value["last_scheduled_terminal_monotonic_us"]
    cancellation = value["first_cancellation_monotonic_us"]
    first_control = value["first_post_cancellation_defense_control_monotonic_us"]
    last_control = value["last_post_cancellation_defense_control_monotonic_us"]
    common = (
        value["terminal_subcell_policy"] == BUFLO_TERMINAL_SUBCELL_POLICY
        and value["terminal_subcell_observer_effect"] == BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT
        and value["pending_request_cancellations"] == 0
        and streams == value["receipt_cancellations"] == value["typed_cancellation_action_events"]
        and value["whole_cell_floor_bytes"] == 1_200
        and value["terminal_latched"] is True
        and value["terminal_latched_at_us"] >= 10_000_000
        and value["open_streams_at_latch"] == streams
        and value["parser_lease_bytes_at_latch"] == 0
        and (
            value["pending_parser_boundaries_at_latch"] == 0
            if schema_version == 1
            else value["pending_application_parser_boundaries_at_latch"] == 0
            and value["pending_parser_boundaries_at_latch"] <= streams
        )
        and value["paper_equivalent"] is False
        and value["implementation_scope"] == "client_only_quic"
        and value["control_evidence_semantics"] == BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS
        and type(last_exact) is int
        and last_exact >= 0
        and type(last_scheduled) is int
        and last_scheduled >= last_exact
        and value["terminal_latched_at_us"] >= last_scheduled
    )
    if not common:
        return False
    if schema_version == 3 and not _buflo_schedule_stop_state_valid(
        value["schedule_stop"], terminal_latched_at_us=value["terminal_latched_at_us"]
    ):
        return False
    if streams == 0:
        return bool(
            capacity == 0
            and value["pending_parser_boundaries_at_latch"] == 0
            and value["post_cancellation_unscheduled_defense_control_packets"] == 0
            and value["post_cancellation_unscheduled_defense_control_bytes"] == 0
            and cancellation is None
            and first_control is None
            and last_control is None
        )
    # Schema 3 translates process-clock CSV microseconds into the defense
    # clock.  Because the CSV value was floored before a potentially
    # sub-microsecond-aligned defense-start offset was applied, its stored
    # lower bound may be one microsecond below the diagnostic latch even when
    # the underlying cancellation causally followed that latch.
    cancellation_clock_slack_us = 1 if schema_version == 3 else 0
    return bool(
        0 <= capacity < 1_200
        and value["post_cancellation_unscheduled_defense_control_packets"] > 0
        and value["post_cancellation_unscheduled_defense_control_bytes"] > 0
        and type(cancellation) is int
        and type(first_control) is int
        and type(last_control) is int
        and max(last_scheduled, value["terminal_latched_at_us"])
        <= cancellation + cancellation_clock_slack_us
        <= first_control
        <= last_control
    )


def buflo_terminal_diagnostics_valid(
    diagnostics: Mapping[str, Any], *, require_current: bool = False
) -> bool:
    """Validate the version-inferred flat BuFLO terminal diagnostic contract."""

    application_key = "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    parser_current = application_key in diagnostics
    schedule_stop_present = BUFLO_SCHEDULE_STOP_V4_KEYS & set(diagnostics)
    if schedule_stop_present and schedule_stop_present != BUFLO_SCHEDULE_STOP_V4_KEYS:
        return False
    stop_drain_current = schedule_stop_present == BUFLO_SCHEDULE_STOP_V4_KEYS
    if require_current and (not parser_current or not stop_drain_current):
        return False
    streams = diagnostics.get("buflo_terminal_subcell_stream_cancellations")
    open_streams = diagnostics.get("buflo_terminal_subcell_open_streams_at_latch")
    capacity = diagnostics.get("buflo_terminal_subcell_exact_capacity_bytes_cancelled")
    total_boundaries = diagnostics.get("buflo_terminal_subcell_pending_parser_boundaries_at_latch")
    integer_values = (streams, open_streams, capacity, total_boundaries)
    if any(type(value) is not int or value < 0 for value in integer_values):
        return False
    if (
        diagnostics.get("buflo_terminal_subcell_latched") is not True
        or type(diagnostics.get("buflo_terminal_subcell_latched_at_us")) is not int
        or diagnostics["buflo_terminal_subcell_latched_at_us"] < 10_000_000
        or open_streams != streams
        or diagnostics.get("buflo_terminal_subcell_parser_lease_bytes_at_latch") != 0
        or diagnostics.get("buflo_terminal_subcell_pending_request_cancellations") != 0
    ):
        return False
    if parser_current:
        application_boundaries = diagnostics.get(application_key)
        if (
            type(application_boundaries) is not int
            or application_boundaries != 0
            or total_boundaries > streams
        ):
            return False
    elif total_boundaries != 0:
        return False
    terminal_tail_valid = bool(
        (streams == 0 and capacity == 0 and total_boundaries == 0)
        or (streams > 0 and 0 <= capacity < 1_200)
    )
    if not terminal_tail_valid or not stop_drain_current:
        return terminal_tail_valid
    if any(
        type(diagnostics.get(key)) is not int or diagnostics[key] < 0
        for key in BUFLO_SCHEDULE_STOP_V4_INTEGER_KEYS
    ):
        return False
    stop_us = diagnostics["buflo_schedule_stop_latched_at_us"]
    available = diagnostics["buflo_schedule_stop_available_bytes"]
    required = diagnostics["buflo_schedule_stop_required_bytes"]
    scheduled_incoming = diagnostics["buflo_schedule_stop_scheduled_incoming_cells"]
    scheduled_outgoing = diagnostics["buflo_schedule_stop_scheduled_outgoing_cells"]
    terminal_incoming = diagnostics["buflo_schedule_stop_terminal_incoming_cells"]
    terminal_outgoing = diagnostics["buflo_schedule_stop_terminal_outgoing_cells"]
    return bool(
        diagnostics.get("buflo_schedule_stop_latched") is True
        and stop_us >= 10_000_000
        and stop_us <= diagnostics["buflo_terminal_subcell_latched_at_us"]
        and required == 1_200
        and 0 <= available < required
        and scheduled_incoming == diagnostics.get("buflo_scheduled_incoming_cells")
        and scheduled_outgoing == diagnostics.get("buflo_scheduled_outgoing_cells")
        and scheduled_incoming == scheduled_outgoing
        and scheduled_outgoing > 0
        and terminal_outgoing == scheduled_outgoing
        and 0 <= terminal_incoming <= scheduled_incoming
        and diagnostics.get("buflo_outgoing_unresolved_cells") == 0
        and diagnostics.get("buflo_incoming_unresolved_cells") == 0
    )


def cs_buflo_local_et_handoff_valid(
    diagnostics: Mapping[str, Any], *, require_current: bool = False
) -> bool:
    """Validate the current CS-BuFLO application-passthrough transition."""

    present = CS_BUFLO_LOCAL_ET_V3_KEYS & set(diagnostics)
    if not present:
        return not require_current
    if present != CS_BUFLO_LOCAL_ET_V3_KEYS:
        return False
    if any(
        type(diagnostics[key]) is not int or diagnostics[key] < 0
        for key in CS_BUFLO_LOCAL_ET_V3_INTEGER_KEYS
    ) or any(type(diagnostics[key]) is not bool for key in CS_BUFLO_LOCAL_ET_V3_BOOLEAN_KEYS):
        return False
    before_application_complete = diagnostics["cs_buflo_local_et_before_application_complete"]
    handoff_keys = (
        "cs_buflo_local_et_application_receive_streams_handed_off",
        "cs_buflo_local_et_application_parser_boundaries_handed_off",
        "cs_buflo_local_et_application_parser_lease_bytes_handed_off",
        "cs_buflo_local_et_application_send_endpoints_released",
    )
    post_keys = (
        "cs_buflo_post_local_et_natural_outgoing_bytes",
        "cs_buflo_post_local_et_natural_incoming_bytes",
    )
    if before_application_complete:
        if not any(diagnostics[key] > 0 for key in handoff_keys):
            return False
    elif any(diagnostics[key] != 0 for key in (*handoff_keys, *post_keys)):
        return False
    for direction in ("outgoing", "incoming"):
        final_natural = diagnostics.get(f"cs_buflo_natural_{direction}_bytes")
        frozen_natural = diagnostics.get(f"cs_buflo_{direction}_padding_basis_natural_bytes")
        post_natural = diagnostics[f"cs_buflo_post_local_et_natural_{direction}_bytes"]
        real_bearing = diagnostics.get(f"cs_buflo_real_bearing_{direction}_bytes")
        if (
            type(final_natural) is not int
            or type(frozen_natural) is not int
            or type(real_bearing) is not int
            or final_natural != frozen_natural + post_natural
            or real_bearing > frozen_natural
        ):
            return False
    return True


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
CLOCK_ANCHOR_UNCERTAINTY_FIELDS = {
    "start_pairing_uncertainty_ns",
    "end_pairing_uncertainty_ns",
}
MAX_CAPTURE_CLOCK_ERROR_NS = 10_000_000
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
        "Abrupt capture wall-clock corrections can be modeled for failed-attempt diagnostics "
        "only as positive 50--100 ms steps with consecutive packet support, well-supported "
        "constant-offset epochs, and a 25--35 s cadence when steps repeat. A final positive "
        "step whose terminal epoch lacks the ordinary packet/span support additionally "
        "requires independently sealed realtime/monotonic wrapper anchors. Promotion still "
        "requires one constant-offset segment with zero steps; negative steps and drift are "
        "ineligible even for the diagnostic model."
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


def validate_primary_capture_clock_integrity(
    capture: Mapping[str, Any],
    *,
    label: str = "primary capture",
    require_pairing_uncertainty: bool = False,
    require_timestamp_type: bool = False,
) -> dict[str, Any]:
    """Validate the Linux clocks that produced one primary capture.

    Packet timestamps come from the Linux capture clock while runner packet
    timestamps come from Linux ``CLOCK_MONOTONIC``. This is the authoritative
    admission check for their relationship; no external host clock is part of
    the evidence contract.
    """

    prefix = f"{label}:"
    if not isinstance(capture, Mapping) or capture.get("primary") is not True:
        raise ValueError(f"{prefix} primary capture diagnostics are missing")
    timestamp_type = capture.get("timestamp_type")
    if timestamp_type is not None and timestamp_type != "host":
        raise ValueError(f"{prefix} capture timestamp type is not host")
    if require_timestamp_type and timestamp_type != "host":
        raise ValueError(f"{prefix} capture timestamp type is missing")
    reconciliation = capture.get("direct_runner_reconciliation")
    if not isinstance(reconciliation, Mapping):
        raise ValueError(f"{prefix} direct/runner reconciliation is missing")
    if reconciliation.get("direct_clock_model") != "constant-offset":
        raise ValueError(f"{prefix} direct clock model is not constant-offset")

    segments = reconciliation.get("direct_clock_segments")
    if (
        reconciliation.get("direct_clock_segment_count") != 1
        or not isinstance(segments, list)
        or len(segments) != 1
    ):
        raise ValueError(f"{prefix} direct clock must contain exactly one segment")
    steps = reconciliation.get("direct_clock_steps")
    if reconciliation.get("direct_clock_step_count") != 0 or not isinstance(steps, list) or steps:
        raise ValueError(f"{prefix} direct clock must contain zero steps")
    if (
        reconciliation.get("direct_runner_reconciled") is not True
        or reconciliation.get("evidence_eligible") is not True
    ):
        raise ValueError(f"{prefix} direct/runner reconciliation is not evidence-eligible")

    maximum_error = reconciliation.get("direct_timestamp_error_max_ns")
    tolerance = reconciliation.get("direct_timestamp_tolerance_ns")
    if (
        type(maximum_error) is not int
        or maximum_error < 0
        or type(tolerance) is not int
        or not 0 <= tolerance <= MAX_CAPTURE_CLOCK_ERROR_NS
        or maximum_error > tolerance
    ):
        raise ValueError(f"{prefix} direct timestamp error exceeds the 10 ms limit")

    anchors = capture.get("capture_clock_anchors")
    if not isinstance(anchors, Mapping):
        raise ValueError(f"{prefix} wrapper clock anchors are missing")
    anchor_fields = set(anchors)
    supported_fields = (
        CLOCK_ANCHOR_FIELDS,
        CLOCK_ANCHOR_FIELDS | CLOCK_ANCHOR_UNCERTAINTY_FIELDS,
    )
    if anchor_fields not in supported_fields:
        raise ValueError(f"{prefix} wrapper clock anchors have invalid fields")
    if require_pairing_uncertainty and not CLOCK_ANCHOR_UNCERTAINTY_FIELDS <= anchor_fields:
        raise ValueError(f"{prefix} wrapper clock pairing uncertainty is missing")

    values: dict[str, int] = {}
    for field in CLOCK_ANCHOR_FIELDS:
        value = anchors.get(field)
        if type(value) is not int or value < 0:
            raise ValueError(f"{prefix} wrapper clock anchor {field} is invalid")
        values[field] = value
    uncertainties: dict[str, int] = {}
    for field in CLOCK_ANCHOR_UNCERTAINTY_FIELDS:
        value = anchors.get(field, 0)
        if type(value) is not int or value < 0:
            raise ValueError(f"{prefix} wrapper clock anchor {field} is invalid")
        uncertainties[field] = value

    monotonic_elapsed = values["end_monotonic_ns"] - values["start_monotonic_ns"]
    realtime_elapsed = values["end_realtime_unix_ns"] - values["start_realtime_unix_ns"]
    if monotonic_elapsed <= 0 or realtime_elapsed < 0:
        raise ValueError(f"{prefix} wrapper clock elapsed duration is invalid")
    elapsed_delta = realtime_elapsed - monotonic_elapsed
    elapsed_error_bound = (
        abs(elapsed_delta)
        + uncertainties["start_pairing_uncertainty_ns"]
        + uncertainties["end_pairing_uncertainty_ns"]
    )
    if elapsed_error_bound > MAX_CAPTURE_CLOCK_ERROR_NS:
        raise ValueError(f"{prefix} wrapper realtime/monotonic elapsed difference exceeds 10 ms")
    return {
        "clock_domain": "linux-kernel",
        "capture_timestamp_type": timestamp_type,
        "clock_model": "constant-offset",
        "direct_timestamp_error_max_ns": maximum_error,
        "direct_timestamp_tolerance_ns": tolerance,
        "realtime_monotonic_elapsed_delta_ns": elapsed_delta,
        "realtime_monotonic_elapsed_error_bound_ns": elapsed_error_bound,
        "maximum_elapsed_error_ns": MAX_CAPTURE_CLOCK_ERROR_NS,
        "pairing_uncertainty_recorded": bool(CLOCK_ANCHOR_UNCERTAINTY_FIELDS <= anchor_fields),
    }


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
    if (
        run.get("completion_status") != "complete"
        or run.get("error") is not None
        or run.get("error_class") is not None
    ):
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
    rows = _read_compatible_csv(
        path,
        RUNNER_PACKET_FIELDS,
        RUNNER_PACKET_FIELDS + LEGACY_SCHEDULE_QCSD_FIELDS,
        RUNNER_PACKET_FIELDS + ADVERTISEMENT_SCHEDULE_QCSD_FIELDS,
        RUNNER_PACKET_FIELDS + CONSUMPTION_SCHEDULE_QCSD_FIELDS,
        RUNNER_PACKET_FIELDS + SCHEDULE_QCSD_FIELDS,
    )
    if not rows:
        raise ValueError("runner packet trace is empty")
    packets = []
    previous_time: dict[tuple[int, str], int] = {}
    for index, row in enumerate(rows):
        _validate_qcsd_trace_extension(row, label=f"runner packet {index}")
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
    if set(clock_anchors) not in (
        CLOCK_ANCHOR_FIELDS,
        CLOCK_ANCHOR_FIELDS | CLOCK_ANCHOR_UNCERTAINTY_FIELDS,
    ):
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


def _read_compatible_csv(path: Path, *field_schemas: tuple[str, ...]) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source)
            rows = list(reader)
    except OSError as error:
        raise ValueError(f"cannot read direct/runner evidence {path}") from error
    if tuple(reader.fieldnames or ()) not in set(field_schemas):
        raise ValueError(f"invalid direct/runner evidence columns in {path}")
    return rows


def _validate_qcsd_trace_extension(row: Mapping[str, str], *, label: str) -> None:
    if "qcsd_outcome_schema_version" not in row:
        return
    values = {field: row.get(field, "") for field in SCHEDULE_QCSD_FIELDS}
    if not values["qcsd_outcome_schema_version"]:
        if any(values.values()):
            raise ValueError(f"{label} has typed QCSD values without a schema version")
        return
    schema = values["qcsd_outcome_schema_version"]
    if schema not in {"1", "2", "3"}:
        raise ValueError(f"{label} has an unsupported QCSD outcome schema")
    advertisement_fields = (
        "credit_advertised_at_us",
        "credit_advertisement_delay_us",
    )
    consumption_fields = ("credit_consumed_at_us", "credit_consumption_delay_us")
    terminal_field = "terminal_defense_elapsed_us"
    advertisement_present = any(values[field] for field in advertisement_fields)
    consumption_present = any(values[field] for field in consumption_fields)
    advertisement_complete = all(values[field].isdecimal() for field in advertisement_fields)
    consumption_complete = all(values[field].isdecimal() for field in consumption_fields)
    if advertisement_present and not advertisement_complete:
        raise ValueError(f"{label} has incomplete receive-credit advertisement evidence")
    if consumption_present and not consumption_complete:
        raise ValueError(f"{label} has incomplete receive-credit consumption evidence")
    terminal_present = bool(values[terminal_field])
    terminal_complete = values[terminal_field].isdecimal()
    if terminal_present != (schema == "3") or (terminal_present and not terminal_complete):
        raise ValueError(f"{label} has invalid controller terminal-time evidence")
    if terminal_present and row.get("target_time_us") not in {None, ""}:
        target = row["target_time_us"]
        if (
            not isinstance(target, str)
            or not target.isdecimal()
            or int(values[terminal_field]) < int(target)
        ):
            raise ValueError(f"{label} has a controller terminal time before its target")
    if consumption_present and (schema not in {"2", "3"} or not advertisement_complete):
        raise ValueError(f"{label} has unbound receive-credit consumption evidence")
    if not values["send_policy"]:
        if any(values[field] for field in LEGACY_SCHEDULE_QCSD_FIELDS[1:]):
            raise ValueError(f"{label} has credit-only metadata mixed with an outcome")
        if (
            schema == "3"
            and not consumption_present
            and (not advertisement_present or advertisement_complete)
        ):
            return
        if schema != "2" or not advertisement_complete or consumption_present:
            raise ValueError(f"{label} has a schema-only row without typed evidence")
        return
    if values["send_policy"] not in {"exact", "congestion_sensitive", "unscheduled"}:
        raise ValueError(f"{label} has an invalid QCSD send policy")
    if not values["desired_udp_bytes"].isdecimal():
        raise ValueError(f"{label} has invalid QCSD size evidence")
    if int(values["desired_udp_bytes"]) <= 0:
        raise ValueError(f"{label} has a non-positive QCSD desired size")
    incoming_credit_terminal = (
        row.get("direction") == "incoming"
        and values["send_policy"] == "exact"
        and not values["observed_udp_bytes"]
        and advertisement_complete
    )
    observed_present = bool(values["observed_udp_bytes"])
    outcome_suffix = (*LEGACY_SCHEDULE_QCSD_FIELDS[4:11], "congestion_reason")
    if not observed_present and not incoming_credit_terminal:
        if any(
            values[field] for field in (*outcome_suffix, *advertisement_fields, *consumption_fields)
        ):
            raise ValueError(f"{label} has terminal evidence before an observed size")
        # Serialized action rows carry their typed policy and desired size
        # before transport produces the terminal observation.
        return
    if observed_present and not values["observed_udp_bytes"].isdecimal():
        raise ValueError(f"{label} has invalid QCSD size evidence")
    optional_numbers = (
        *LEGACY_SCHEDULE_QCSD_FIELDS[4:11],
        *advertisement_fields,
        *consumption_fields,
    )
    if any(value and not value.isdecimal() for value in (values[key] for key in optional_numbers)):
        raise ValueError(f"{label} has invalid QCSD composition evidence")
    components = LEGACY_SCHEDULE_QCSD_FIELDS[4:10]
    populated_components = [bool(values[key]) for key in components]
    if incoming_credit_terminal and any(
        values[key] for key in (*components, "lateness_us", "congestion_reason")
    ):
        raise ValueError(f"{label} gives an incoming receive-credit event UDP realization")
    if consumption_present and not incoming_credit_terminal:
        raise ValueError(f"{label} attaches peer-consumption timing to a non-incoming slot")
    if incoming_credit_terminal and row.get("action_time_us") not in {None, ""}:
        action_time = row["action_time_us"]
        if not isinstance(action_time, str) or not action_time.isdecimal():
            raise ValueError(f"{label} has invalid receive-credit action timing")
        action = int(action_time)
        advertised = int(values["credit_advertised_at_us"])
        advertised_delay = int(values["credit_advertisement_delay_us"])
        if advertised < action or advertised_delay != advertised - action:
            raise ValueError(f"{label} has invalid receive-credit advertisement timing")
        if consumption_present:
            consumed = int(values["credit_consumed_at_us"])
            consumed_delay = int(values["credit_consumption_delay_us"])
            if consumed < advertised or consumed_delay != consumed - action:
                raise ValueError(f"{label} has invalid receive-credit consumption timing")
    if any(populated_components) and (
        not all(populated_components)
        or sum(int(values[key]) for key in components) != int(values["observed_udp_bytes"])
    ):
        raise ValueError(f"{label} has inconsistent QCSD byte composition")
    if values["congestion_reason"] not in {"", "congestion_limited", "pacing_limited"}:
        raise ValueError(f"{label} has an invalid QCSD congestion reason")
    if values["send_policy"] == "exact" and any(populated_components):
        if schema not in {"2", "3"} or not values["lateness_us"].isdecimal():
            raise ValueError(f"{label} has incomplete exact packet composition evidence")
    elif values["send_policy"] == "exact" and values["lateness_us"]:
        raise ValueError(f"{label} gives an exact outcome unexplained lateness")
    if values["send_policy"] in {"exact", "unscheduled"} and values["congestion_reason"]:
        raise ValueError(f"{label} gives an exact send a congestion reason")


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
    return _schedule_realization_metrics_from_path(sample / "neqo/schedule.csv")


def _schedule_realization_metrics_from_path(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
        fieldnames = tuple(reader.fieldnames or ())
    satisfactions: dict[str, int] = {}
    miss_reasons: dict[str, int] = {}
    directions: dict[str, int] = {}
    outgoing_size_mismatches = 0
    outgoing_size_error_bytes = 0
    invalid_rows = 0
    invalid_congestion_reasons = 0
    terminal_slots: set[int] = set()
    duplicate_terminal_slots = 0
    action_times: set[tuple[str, int]] = set()
    catch_up_events = 0
    terminal_desired_bytes = 0
    terminal_observed_bytes = 0
    typed_real_bearing_outgoing_bytes = 0
    congestion_reasons: dict[str, int] = {}
    target_times: dict[str, list[int]] = {"outgoing": [], "incoming": []}
    scheduled_sizes: dict[str, list[int]] = {"outgoing": [], "incoming": []}
    typed_schema = fieldnames in {
        SCHEDULE_PREFIX_FIELDS + LEGACY_SCHEDULE_QCSD_FIELDS,
        SCHEDULE_PREFIX_FIELDS + ADVERTISEMENT_SCHEDULE_QCSD_FIELDS,
        SCHEDULE_PREFIX_FIELDS + CONSUMPTION_SCHEDULE_QCSD_FIELDS,
        SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS,
    }
    advertisement_schema = fieldnames in {
        SCHEDULE_PREFIX_FIELDS + ADVERTISEMENT_SCHEDULE_QCSD_FIELDS,
        SCHEDULE_PREFIX_FIELDS + CONSUMPTION_SCHEDULE_QCSD_FIELDS,
        SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS,
    }
    consumption_schema = fieldnames in {
        SCHEDULE_PREFIX_FIELDS + CONSUMPTION_SCHEDULE_QCSD_FIELDS,
        SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS,
    }
    current_schema = fieldnames == SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS
    typed_composition_bytes = {
        key: 0
        for key in (
            "application_stream_bytes",
            "retransmission_stream_bytes",
            "chaff_stream_bytes",
            "defense_control_bytes",
            "quic_padding_bytes",
            "other_quic_bytes",
        )
    }
    typed_lateness_total = 0
    typed_lateness_max = 0
    invalid_typed_rows = 0
    advertised_incoming = 0
    consumed_incoming = 0
    missing_incoming_advertisements = 0
    missing_incoming_consumptions = 0
    invalid_credit_advertisements = 0
    invalid_credit_consumptions = 0
    credit_advertisement_delays: list[int] = []
    credit_consumption_delays: list[int] = []
    terminal_defense_elapsed_values: list[int] = []
    for row in rows:
        satisfaction = str(row.get("satisfaction", ""))
        direction = str(row.get("direction", ""))
        satisfactions[satisfaction] = satisfactions.get(satisfaction, 0) + 1
        directions[direction] = directions.get(direction, 0) + 1
        reason = str(row.get("miss_reason", ""))
        if reason:
            miss_reasons[reason] = miss_reasons.get(reason, 0) + 1
        try:
            slot = int(row["slot_id"])
            action_time = int(row["action_time_us"])
            target_time = int(row["target_time_us"])
            if min(slot, action_time, target_time) < 0:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            invalid_rows += 1
        else:
            target_times.setdefault(direction, []).append(target_time)
            if slot in terminal_slots:
                duplicate_terminal_slots += 1
            terminal_slots.add(slot)
            action_key = (direction, action_time)
            if action_key in action_times:
                catch_up_events += 1
            action_times.add(action_key)
        if direction not in {"outgoing", "incoming"} or satisfaction not in {
            "satisfied",
            "missed",
            "full",
            "partial",
            "suppressed",
        }:
            invalid_rows += 1
        else:
            try:
                scheduled_sizes[direction].append(_csv_uint(row, "size"))
            except (KeyError, TypeError, ValueError):
                invalid_rows += 1
        if current_schema:
            try:
                if row["qcsd_outcome_schema_version"] != "3":
                    raise ValueError
                terminal_at = _csv_uint(row, "terminal_defense_elapsed_us")
                if terminal_at < _csv_uint(row, "target_time_us"):
                    raise ValueError
                terminal_defense_elapsed_values.append(terminal_at)
            except (KeyError, TypeError, ValueError):
                invalid_typed_rows += 1
        typed_reason = str(row.get("congestion_reason", ""))
        if satisfaction in {"partial", "suppressed"}:
            congestion_reasons[typed_reason] = congestion_reasons.get(typed_reason, 0) + 1
            if typed_reason not in {"congestion_limited", "pacing_limited"}:
                invalid_congestion_reasons += 1
            expected_debug_reason = {
                "congestion_limited": "CongestionLimited",
                "pacing_limited": "PacingLimited",
            }.get(typed_reason)
            if reason != expected_debug_reason:
                invalid_congestion_reasons += 1
        elif typed_reason:
            invalid_congestion_reasons += 1
        if advertisement_schema:
            advertised = row.get("credit_advertised_at_us", "")
            advertisement_delay = row.get("credit_advertisement_delay_us", "")
            consumed = row.get("credit_consumed_at_us", "")
            consumption_delay = row.get("credit_consumption_delay_us", "")
            if direction == "outgoing":
                if advertised or advertisement_delay or consumed or consumption_delay:
                    invalid_credit_advertisements += 1
            elif direction == "incoming":
                if satisfaction == "missed":
                    if consumed or consumption_delay:
                        invalid_credit_consumptions += 1
                    if bool(advertised) != bool(advertisement_delay):
                        invalid_credit_advertisements += 1
                    continue
                if not advertised or not advertisement_delay:
                    missing_incoming_advertisements += 1
                else:
                    try:
                        advertised_at_us = _csv_uint(row, "credit_advertised_at_us")
                        delay_us = _csv_uint(row, "credit_advertisement_delay_us")
                        action_time_us = _csv_uint(row, "action_time_us")
                        if (
                            advertised_at_us < action_time_us
                            or delay_us != advertised_at_us - action_time_us
                        ):
                            raise ValueError
                    except (KeyError, TypeError, ValueError):
                        invalid_credit_advertisements += 1
                    else:
                        advertised_incoming += 1
                        credit_advertisement_delays.append(delay_us)
                if consumption_schema:
                    if not consumed or not consumption_delay:
                        missing_incoming_consumptions += 1
                    else:
                        try:
                            consumed_at_us = _csv_uint(row, "credit_consumed_at_us")
                            consumed_delay_us = _csv_uint(row, "credit_consumption_delay_us")
                            action_time_us = _csv_uint(row, "action_time_us")
                            advertised_at_us = _csv_uint(row, "credit_advertised_at_us")
                            if (
                                consumed_at_us < advertised_at_us
                                or consumed_delay_us != consumed_at_us - action_time_us
                            ):
                                raise ValueError
                        except (KeyError, TypeError, ValueError):
                            invalid_credit_consumptions += 1
                        else:
                            consumed_incoming += 1
                            credit_consumption_delays.append(consumed_delay_us)
        if typed_schema and satisfaction != "missed":
            try:
                desired = _csv_uint(row, "desired_udp_bytes")
                size = _csv_uint(row, "size")
                expected_schema = (
                    "3"
                    if current_schema
                    else (
                        "2"
                        if consumption_schema
                        and direction == "incoming"
                        and satisfaction == "satisfied"
                        else "1"
                    )
                )
                if row["qcsd_outcome_schema_version"] != expected_schema or desired != size:
                    raise ValueError
                if satisfaction == "satisfied":
                    if row["send_policy"] != "exact":
                        raise ValueError
                    if direction == "outgoing":
                        observed = _csv_uint(row, "observed_udp_bytes")
                        observed_size = _csv_uint(row, "observed_size")
                        if observed != observed_size or observed != desired:
                            raise ValueError
                    elif row["observed_udp_bytes"] or row["observed_size"]:
                        # An incoming fixed opportunity is locally realized at
                        # MAX_STREAM_DATA advertisement and terminalized only
                        # after peer stream-offset consumption. It never claims
                        # a corresponding server datagram's UDP size.
                        raise ValueError
                    if any(row[field] for field in SCHEDULE_QCSD_FIELDS[4:11]):
                        raise ValueError
                elif satisfaction in {"full", "partial", "suppressed"}:
                    if row["send_policy"] != "congestion_sensitive":
                        raise ValueError
                    observed = _csv_uint(row, "observed_udp_bytes")
                    components = {key: _csv_uint(row, key) for key in typed_composition_bytes}
                    if sum(components.values()) != observed:
                        raise ValueError
                    if satisfaction == "suppressed":
                        if observed != 0 or row["observed_size"]:
                            raise ValueError
                    else:
                        if observed != _csv_uint(row, "observed_size"):
                            raise ValueError
                    lateness = _csv_uint(row, "lateness_us")
                    typed_lateness_total += lateness
                    typed_lateness_max = max(typed_lateness_max, lateness)
                    if direction == "outgoing" and components["application_stream_bytes"] > 0:
                        typed_real_bearing_outgoing_bytes += components["application_stream_bytes"]
                    for key, value in components.items():
                        typed_composition_bytes[key] += value
                else:
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                invalid_typed_rows += 1
        if direction == "outgoing" and satisfaction in {"satisfied", "full"}:
            try:
                requested = int(row["size"])
                observed = int(row["observed_size"])
            except (KeyError, TypeError, ValueError):
                outgoing_size_mismatches += 1
                continue
            if requested != observed:
                outgoing_size_mismatches += 1
                outgoing_size_error_bytes += abs(requested - observed)
        if direction == "outgoing" and satisfaction in {"full", "partial", "suppressed"}:
            try:
                terminal_desired_bytes += int(row["size"])
                terminal_observed_bytes += (
                    _csv_uint(row, "observed_udp_bytes")
                    if satisfaction == "suppressed"
                    else int(row["observed_size"])
                )
            except (KeyError, TypeError, ValueError):
                invalid_rows += 1
    return {
        "scheduled_events": len(rows),
        "scheduled_outgoing_events": directions.get("outgoing", 0),
        "scheduled_incoming_events": directions.get("incoming", 0),
        "satisfied_events": satisfactions.get("satisfied", 0),
        "missed_events": satisfactions.get("missed", 0),
        "missed_event_reasons": dict(sorted(miss_reasons.items())),
        "outgoing_size_mismatch_events": outgoing_size_mismatches,
        "outgoing_size_absolute_error_bytes": outgoing_size_error_bytes,
        "terminal_satisfactions": dict(sorted(satisfactions.items())),
        "terminal_slots_unique": duplicate_terminal_slots == 0,
        "duplicate_terminal_slots": duplicate_terminal_slots,
        "invalid_terminal_rows": invalid_rows,
        "typed_congestion_reason_column": current_schema,
        "typed_credit_advertisement_columns": advertisement_schema,
        "typed_credit_consumption_columns": consumption_schema,
        "typed_controller_terminal_time_column": current_schema,
        "invalid_congestion_reason_events": invalid_congestion_reasons,
        "congestion_reasons": dict(sorted(congestion_reasons.items())),
        "terminal_desired_outgoing_bytes": terminal_desired_bytes,
        "terminal_observed_outgoing_bytes": terminal_observed_bytes,
        "catch_up_events": catch_up_events,
        "invalid_typed_outcome_rows": invalid_typed_rows,
        "typed_composition_bytes": typed_composition_bytes,
        "typed_lateness_us_total": typed_lateness_total,
        "typed_lateness_us_max": typed_lateness_max,
        "typed_real_bearing_outgoing_bytes": typed_real_bearing_outgoing_bytes,
        "incoming_credit_advertised_events": advertised_incoming,
        "incoming_credit_consumed_events": consumed_incoming,
        "incoming_credit_missing_events": missing_incoming_advertisements,
        "incoming_credit_consumption_missing_events": missing_incoming_consumptions,
        "invalid_credit_advertisement_events": invalid_credit_advertisements,
        "invalid_credit_consumption_events": invalid_credit_consumptions,
        "incoming_credit_advertisement_delay_us_total": sum(credit_advertisement_delays),
        "incoming_credit_advertisement_delay_us_max": max(credit_advertisement_delays, default=0),
        "incoming_credit_advertisement_delay_us_values": credit_advertisement_delays,
        "incoming_credit_consumption_delay_us_total": sum(credit_consumption_delays),
        "incoming_credit_consumption_delay_us_max": max(credit_consumption_delays, default=0),
        "incoming_credit_consumption_delay_us_values": credit_consumption_delays,
        "terminal_defense_elapsed_us_values": terminal_defense_elapsed_values,
        "target_times_us_by_direction": target_times,
        "scheduled_sizes_by_direction": scheduled_sizes,
    }


def _csv_uint(row: Mapping[str, Any], field: str) -> int:
    value = row[field]
    if not isinstance(value, str) or not value or not value.isdecimal():
        raise ValueError(f"schedule field {field} is not an unsigned integer")
    return int(value)


_INTEGER = "integer"
_BOOLEAN = "boolean"
_STRING = "string"
_BURST_VECTOR = "burst-vector"
_CS_RATE_TRANSITION_VECTOR = "cs-rate-transition-vector"
CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS = "udp_client_only_observed_udp_power_of_two_crossing"
CS_BUFLO_EARLY_TERMINATION_SEMANTICS = (
    "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing"
)
CS_BUFLO_INCOMING_CADENCE_BOUNDARY = "complete_local_on_wire_max_stream_data_advertisement"
CS_BUFLO_INCOMING_TERMINAL_BOUNDARY = "eventual_peer_stream_offset_consumption"
CS_BUFLO_INCOMING_BOUNDARY_SEPARATION = (
    "advertisement_rearms_cadence_but_does_not_claim_peer_datagram_or_consumption"
)
CS_BUFLO_RATE_BOUNDARY_TRANSLATION_VERSION = 2
CS_BUFLO_RATE_BOUNDARY_COUNTER_SEMANTICS = (
    "client_only_quic_fresh_application_stream_bytes_outgoing_retransmission_"
    "excluded_and_consumed_application_offsets_incoming"
)
CS_BUFLO_AUTHOR_RATE_BOUNDARY_COUNTER_SEMANTICS = (
    "per_direction_actually_transmitted_real_plus_junk_bytes"
)
CS_BUFLO_EARLY_TERMINATION_TRANSLATION_VERSION = 2
CS_BUFLO_TERMINATION_STOP_POLICY = (
    "stop_new_opportunities_at_first_eligible_padding_target_or_power_of_two_"
    "crossing_then_drain_advertised_credit_exactly_once"
)
CS_BUFLO_TERMINATION_STOP_REASONS = frozenset({"padding_target_reached", "power_of_two_crossing"})
CS_BUFLO_TERMINATION_STOP_PHASES = frozenset({"application_complete", "strict_quiet"})
RUNNER_WAKEUP_SEMANTICS = (
    "actual_select_return_source; socket_wins_simultaneous_readiness; "
    "controller_subset_is_effective_earliest_deadline; "
    "scheduled_cells_are_not_wakeups"
)
RUNNER_WAKEUP_V2_SEMANTICS = (
    f"{RUNNER_WAKEUP_SEMANTICS}; "
    "buflo_exact_release_guard_reserves_candidate_window; "
    "buflo_exact_release_active_wait_tail_us=250; "
    "buflo_exact_release_guards_are_separately_receipted_active_waits; "
    "buflo_active_defense_socket_drains_are_single_batch; "
    "buflo_active_defense_http_drains_are_single_event; "
    "buflo_output_is_interrupted_at_guard"
)
RUNNER_WAKEUP_V3_SEMANTICS = (
    f"{RUNNER_WAKEUP_SEMANTICS}; "
    "buflo_exact_release_guard_reserves_candidate_window; "
    "buflo_exact_release_active_wait_tail_us=5000; "
    "buflo_exact_release_guards_are_separately_receipted_active_waits; "
    "buflo_active_defense_socket_drains_are_single_batch; "
    "buflo_active_defense_http_drains_are_single_event; "
    "buflo_output_is_interrupted_at_guard"
)
RUNNER_WAKEUP_V4_SEMANTICS = (
    f"{RUNNER_WAKEUP_SEMANTICS}; "
    "buflo_ordinary_output_admission_is_one_realization_window_before_guard; "
    "buflo_exact_release_guard_reserves_candidate_window; "
    "buflo_exact_release_active_wait_tail_us=5000; "
    "buflo_exact_release_guards_are_separately_receipted_active_waits; "
    "buflo_active_defense_socket_drains_are_single_batch; "
    "buflo_active_defense_http_drains_are_single_event; "
    "buflo_ordinary_output_stops_at_admission; "
    "buflo_exact_release_guard_begins_at_guard; "
    "cs_exact_incoming_retry_phases=1/4,1/2,3/4"
)
RUNNER_WAKEUP_V5_SEMANTICS = (
    f"{RUNNER_WAKEUP_V4_SEMANTICS}; "
    "buflo_exact_incoming_retry_wakeups=transport_callback_or_1/4,1/2,3/4,deadline; "
    "buflo_exact_incoming_retry_drives="
    "count_owner_endpoint_output_drive_invocations_including_immediate_and_error; "
    "buflo_exact_incoming_retry_resolutions="
    "count_drive_invocations_clearing_at_least_one_captured_identity; "
    "buflo_exact_incoming_retry_max_wake_lateness_includes_terminal_deadline=true; "
    "buflo_exact_incoming_inventory="
    "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
    "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
)
RUNNER_WAKEUP_V6_SEMANTICS = (
    f"{RUNNER_WAKEUP_SEMANTICS}; "
    "buflo_ordinary_output_admission_lead_us=10000; "
    "buflo_exact_release_guard_reserves_candidate_window; "
    "buflo_exact_release_guard_lead_us=10000; "
    "buflo_exact_release_active_wait_tail_us=10000; "
    "buflo_exact_release_guard_coincides_with_output_admission=true; "
    "buflo_exact_release_guards_are_separately_receipted_active_waits; "
    "buflo_active_defense_socket_drains_are_single_batch; "
    "buflo_active_defense_http_drains_are_single_event; "
    "buflo_ordinary_output_stops_at_admission; "
    "buflo_exact_release_guard_begins_at_guard; "
    "cs_exact_incoming_retry_phases=1/4,1/2,3/4; "
    "buflo_exact_incoming_retry_wakeups=transport_callback_or_1/4,1/2,3/4,deadline; "
    "buflo_exact_incoming_retry_drives="
    "count_owner_endpoint_output_drive_invocations_including_immediate_and_error; "
    "buflo_exact_incoming_retry_resolutions="
    "count_drive_invocations_clearing_at_least_one_captured_identity; "
    "buflo_exact_incoming_retry_max_wake_lateness_includes_terminal_deadline=true; "
    "buflo_exact_incoming_inventory="
    "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
    "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
)
RUNNER_WAKEUP_V7_SEMANTICS = (
    f"{RUNNER_WAKEUP_V6_SEMANTICS}; "
    "buflo_exact_release_timing_histogram_upper_bounds_ns="
    "50000,100000,250000,500000,1000000,2000000,5000000,overflow; "
    "buflo_exact_release_active_spin_interruption_threshold_ns=50000; "
    "buflo_exact_release_active_spin_gap_histogram_counts_one_max_gap_per_guard; "
    "buflo_exact_release_dispatch_lateness_histogram_counts_one_guard_exit_per_guard; "
    "buflo_exact_release_dispatch_at_or_after_deadline_uses_half_open_window=true; "
    "buflo_exact_release_aux_clocks="
    "linux_clock_monotonic_raw_and_thread_cputime_id_or_unavailable; "
    "buflo_exact_release_aux_clock_unavailable_includes_missing_or_nonmonotonic_sample=true; "
    "buflo_exact_release_estimated_off_cpu_is_monotonic_elapsed_minus_"
    "thread_cpu_elapsed_saturating; "
    "buflo_exact_release_aux_clock_cannot_attribute_guest_scheduler_vs_hypervisor_steal; "
    "buflo_exact_release_worst_guard_is_max_dispatch_lateness_first_on_tie; "
    "buflo_exact_release_worst_guard_times_are_relative_to_defense_start_or_null; "
    "buflo_rolling_prearm_not_before_relative_us_rounding=ceil; "
    "buflo_rolling_prearm_deadline_relative_us_rounding=floor; "
    "buflo_exact_release_packet_timestamp_us_semantics=nominal_defense_release; "
    "buflo_exact_release_worst_guard_release_and_deadline_semantics="
    "actual_adapter_instants; "
    "buflo_exact_release_actual_adapter_window_ns="
    "nominal_control_interval_ns_or_nominal_minus_1000; "
    "buflo_exact_release_actual_guard_and_active_wait_lead_ns="
    "twice_actual_adapter_window_ns; "
    "buflo_exact_release_10000us_lead_fields_are_configured_maxima=true"
)
RUNNER_WAKEUP_V8_SEMANTICS = (
    f"{RUNNER_WAKEUP_V7_SEMANTICS}; "
    "buflo_exact_release_active_wait_poll=poll_instant_without_arch_spin_hint"
)
RUNNER_WAKEUP_V9_SEMANTICS = (
    f"{RUNNER_WAKEUP_SEMANTICS}; "
    "buflo_ordinary_output_admission_lead_us=10000; "
    "buflo_exact_release_guard_reserves_candidate_window; "
    "buflo_exact_release_guard_lead_us=5000; "
    "buflo_exact_release_active_wait_tail_us=5000; "
    "buflo_exact_release_guard_coincides_with_output_admission=false; "
    "buflo_exact_release_guards_are_separately_receipted_active_waits; "
    "buflo_exact_release_schema9_passive_wait_unreachable=true; "
    "buflo_exact_release_guard_wait_equals_active_wait=true; "
    "buflo_exact_release_max_passive_wake_lateness_equals_"
    "max_guard_entry_lateness=true; "
    "buflo_active_defense_socket_drains_are_single_batch; "
    "buflo_active_defense_http_drains_are_single_event; "
    "buflo_ordinary_output_stops_at_admission; "
    "buflo_exact_release_guard_begins_one_actual_adapter_window_before_release=true; "
    "cs_exact_incoming_retry_phases=1/4,1/2,3/4; "
    "buflo_exact_incoming_retry_wakeups=transport_callback_or_1/4,1/2,3/4,deadline; "
    "buflo_exact_incoming_retry_drives="
    "count_owner_endpoint_output_drive_invocations_including_immediate_and_error; "
    "buflo_exact_incoming_retry_resolutions="
    "count_drive_invocations_clearing_at_least_one_captured_identity; "
    "buflo_exact_incoming_retry_max_wake_lateness_includes_terminal_deadline=true; "
    "buflo_exact_incoming_inventory="
    "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
    "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss; "
    "buflo_exact_release_timing_histogram_upper_bounds_ns="
    "50000,100000,250000,500000,1000000,2000000,5000000,overflow; "
    "buflo_exact_release_active_spin_interruption_threshold_ns=50000; "
    "buflo_exact_release_active_wait_iterations="
    "counter_read_attempts_including_ordered_and_unavailable_or_fallback_"
    "authoritative_polls; "
    "buflo_exact_release_active_spin_gap_histogram_counts_one_max_gap_per_guard_entry; "
    "buflo_exact_release_dispatch_lateness_histogram_counts_one_dispatch_ready_guard; "
    "buflo_exact_release_guard_entries=dispatch_ready_guards+failed_guards; "
    "buflo_exact_release_failed_guards=sum_typed_failure_guards; "
    "buflo_exact_release_failed_guards_max=1; "
    "buflo_exact_release_last_failure_present_iff_failed_guards=1; "
    "buflo_exact_release_failure_dispatch_at_is_null=true; "
    "buflo_exact_release_dispatch_at_or_after_deadline_uses_half_open_window=true; "
    "buflo_exact_release_worst_guard_is_max_dispatch_lateness_first_on_tie; "
    "buflo_exact_release_worst_guard_times_are_relative_to_defense_start_or_null; "
    "buflo_rolling_prearm_not_before_relative_us_rounding=ceil; "
    "buflo_rolling_prearm_deadline_relative_us_rounding=floor; "
    "buflo_exact_release_packet_timestamp_us_semantics=nominal_defense_release; "
    "buflo_exact_release_worst_guard_release_and_deadline_semantics="
    "actual_adapter_instants; "
    "buflo_exact_release_actual_adapter_window_ns="
    "nominal_control_interval_ns_or_nominal_minus_1000; "
    "buflo_exact_release_actual_guard_and_active_wait_lead_ns=actual_adapter_window_ns; "
    "buflo_exact_release_configured_output_admission_lead_us=10000; "
    "buflo_exact_release_configured_guard_and_active_wait_lead_us=5000; "
    "buflo_exact_release_active_wait_poll="
    "linux_aarch64_cntvct_el0_predictive_else_instant_authoritative_fallback; "
    "buflo_exact_release_counter_target_rounding=ceil; "
    "buflo_exact_release_counter_calibration=counter_instant_counter; "
    "buflo_exact_release_counter_is_predictive_only=true; "
    "buflo_exact_release_counter_frequency_hz_range_inclusive=1000000..4294967295; "
    "buflo_exact_release_counter_target_error="
    "defensive_unreachable_for_valid_live_guard_and_frequency; "
    "buflo_exact_release_counter_unavailable="
    "scripted_trait_failure_not_architectural_trap_receipt; "
    "buflo_exact_release_production_counter_access=target_gated_live_smoke_test; "
    "buflo_exact_release_counter_frequency_change="
    "hard_failure_before_transport_dispatch_and_before_success_metrics_mutation; "
    "buflo_exact_release_cross_guard_frequency_precedence="
    "typed_wait_failure_preserved_dispatch_ready_retyped; "
    "buflo_exact_release_dispatch_confirmation=authoritative_instant; "
    "buflo_exact_release_transport_and_socket_clock=authoritative_instant; "
    "buflo_exact_release_counter_regression=hard_failure; "
    "buflo_exact_release_guard_metrics_recorded_before_result_propagation=true; "
    "buflo_exact_release_transport_dispatch_result_precedes_guard_metrics=true"
)
RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS = [
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
]
RUNNER_WAKEUP_V7_NEW_INTEGER_KEYS = frozenset(
    {
        "buflo_exact_release_max_guard_entry_lateness_nanoseconds",
        "buflo_exact_release_passive_sleep_calls",
        "buflo_exact_release_passive_sleep_requested_nanoseconds",
        "buflo_exact_release_passive_sleep_elapsed_nanoseconds",
        "buflo_exact_release_max_passive_sleep_overrun_nanoseconds",
        "buflo_exact_release_active_wait_iterations",
        "buflo_exact_release_active_spin_interruptions",
        "buflo_exact_release_active_spin_interruption_nanoseconds",
        "buflo_exact_release_max_active_spin_gap_nanoseconds",
        "buflo_exact_release_active_wait_aux_clock_guards",
        "buflo_exact_release_active_wait_aux_clock_unavailable_guards",
        "buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards",
        "buflo_exact_release_active_wait_monotonic_raw_nanoseconds",
        "buflo_exact_release_active_wait_thread_cpu_nanoseconds",
        "buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds",
        "buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds",
        "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds",
        "buflo_exact_release_dispatch_at_or_after_deadline_guards",
    }
)
RUNNER_WAKEUP_V7_OBJECT_KEYS = frozenset(
    {
        "buflo_exact_release_aux_clock_source",
        "buflo_exact_release_dispatch_lateness_histogram",
        "buflo_exact_release_active_spin_gap_histogram",
        "buflo_exact_release_worst_guard",
    }
)
RUNNER_WAKEUP_V7_WORST_TIME_KEYS = frozenset(
    {
        "guard_at_defense_nanoseconds",
        "entered_at_defense_nanoseconds",
        "active_wait_at_defense_nanoseconds",
        "active_wait_started_at_defense_nanoseconds",
        "release_at_defense_nanoseconds",
        "deadline_at_defense_nanoseconds",
        "dispatch_at_defense_nanoseconds",
    }
)
RUNNER_WAKEUP_V7_WORST_AUX_KEYS = frozenset(
    {
        "active_wait_monotonic_raw_nanoseconds",
        "active_wait_thread_cpu_nanoseconds",
        "active_wait_estimated_off_cpu_nanoseconds",
        "active_wait_monotonic_raw_divergence_nanoseconds",
    }
)
RUNNER_WAKEUP_V7_WORST_INTEGER_KEYS = frozenset(
    {
        "endpoint",
        "slot",
        "packet_timestamp_us",
        "guard_entry_lateness_nanoseconds",
        "passive_sleep_calls",
        "passive_sleep_requested_nanoseconds",
        "passive_sleep_elapsed_nanoseconds",
        "max_passive_sleep_overrun_nanoseconds",
        "active_wait_iterations",
        "active_wait_monotonic_nanoseconds",
        "active_spin_interruptions",
        "active_spin_interruption_nanoseconds",
        "max_active_spin_gap_nanoseconds",
        "dispatch_lateness_nanoseconds",
        "dispatch_after_deadline_nanoseconds",
    }
)
RUNNER_WAKEUP_V7_WORST_KEYS = (
    RUNNER_WAKEUP_V7_WORST_TIME_KEYS
    | RUNNER_WAKEUP_V7_WORST_AUX_KEYS
    | RUNNER_WAKEUP_V7_WORST_INTEGER_KEYS
    | {"phase", "dispatch_at_or_after_deadline"}
)
RUNNER_WAKEUP_V9_POLL_SOURCES = frozenset(
    {
        "linux-aarch64-cntvct-el0-predictive-v1",
        "instant-authoritative-fallback-v1",
    }
)
RUNNER_WAKEUP_V9_NEW_INTEGER_KEYS = frozenset(
    {
        "buflo_exact_release_dispatch_ready_guards",
        "buflo_exact_release_failed_guards",
        "buflo_exact_release_invalid_counter_frequency_guards",
        "buflo_exact_release_counter_unavailable_failure_guards",
        "buflo_exact_release_counter_nonmonotonic_failure_guards",
        "buflo_exact_release_counter_frequency_changed_guards",
        "buflo_exact_release_counter_target_error_guards",
        "buflo_exact_release_max_guard_entry_lateness_nanoseconds",
        "buflo_exact_release_passive_sleep_calls",
        "buflo_exact_release_passive_sleep_requested_nanoseconds",
        "buflo_exact_release_passive_sleep_elapsed_nanoseconds",
        "buflo_exact_release_max_passive_sleep_overrun_nanoseconds",
        "buflo_exact_release_active_wait_iterations",
        "buflo_exact_release_active_spin_interruptions",
        "buflo_exact_release_active_spin_interruption_nanoseconds",
        "buflo_exact_release_max_active_spin_gap_nanoseconds",
        "buflo_exact_release_active_wait_counter_guards",
        "buflo_exact_release_active_wait_counter_unavailable_guards",
        "buflo_exact_release_active_wait_counter_nonmonotonic_guards",
        "buflo_exact_release_active_wait_counter_calibrations",
        "buflo_exact_release_active_wait_instant_confirmations",
        "buflo_exact_release_active_wait_early_confirmation_retries",
        "buflo_exact_release_active_wait_counter_nanoseconds",
        "buflo_exact_release_max_active_wait_counter_gap_nanoseconds",
        "buflo_exact_release_max_counter_calibration_span_nanoseconds",
        "buflo_exact_release_dispatch_at_or_after_deadline_guards",
    }
)
RUNNER_WAKEUP_V9_OBJECT_KEYS = frozenset(
    {
        "buflo_exact_release_active_wait_poll_source",
        "buflo_exact_release_active_wait_counter_frequency_hz",
        "buflo_exact_release_dispatch_lateness_histogram",
        "buflo_exact_release_active_spin_gap_histogram",
        "buflo_exact_release_worst_guard",
        "buflo_exact_release_last_failure",
    }
)
RUNNER_WAKEUP_V9_WORST_COUNTER_NULLABLE_KEYS = frozenset(
    {
        "active_wait_counter_frequency_hz",
        "active_wait_counter_nanoseconds",
        "max_active_wait_counter_gap_nanoseconds",
        "max_counter_calibration_span_nanoseconds",
    }
)
RUNNER_WAKEUP_V9_WORST_COUNTER_INTEGER_KEYS = frozenset(
    {
        "active_wait_counter_calibrations",
        "active_wait_instant_confirmations",
        "active_wait_early_confirmation_retries",
    }
)
RUNNER_WAKEUP_V9_WORST_KEYS = (
    RUNNER_WAKEUP_V7_WORST_TIME_KEYS
    | RUNNER_WAKEUP_V7_WORST_INTEGER_KEYS
    | RUNNER_WAKEUP_V9_WORST_COUNTER_NULLABLE_KEYS
    | RUNNER_WAKEUP_V9_WORST_COUNTER_INTEGER_KEYS
    | {
        "phase",
        "dispatch_at_or_after_deadline",
        "active_wait_poll_source",
    }
)
RUNNER_WAKEUP_V9_FAILURE_TIME_KEYS = frozenset(
    {
        "guard_at_defense_nanoseconds",
        "entered_at_defense_nanoseconds",
        "active_wait_at_defense_nanoseconds",
        "active_wait_started_at_defense_nanoseconds",
        "release_at_defense_nanoseconds",
        "deadline_at_defense_nanoseconds",
        "exited_at_defense_nanoseconds",
    }
)
RUNNER_WAKEUP_V9_FAILURE_COUNTER_NULLABLE_KEYS = frozenset(
    {
        "counter_frequency_hz",
        "counter_nanoseconds",
        "max_counter_gap_nanoseconds",
        "max_counter_calibration_span_nanoseconds",
    }
)
RUNNER_WAKEUP_V9_FAILURE_INTEGER_KEYS = frozenset(
    {
        "endpoint",
        "slot",
        "packet_timestamp_us",
        "guard_entry_lateness_nanoseconds",
        "exit_before_release_nanoseconds",
        "counter_calibrations",
        "instant_confirmations",
        "early_confirmation_retries",
    }
)
RUNNER_WAKEUP_V9_FAILURE_KEYS = (
    RUNNER_WAKEUP_V9_FAILURE_TIME_KEYS
    | RUNNER_WAKEUP_V9_FAILURE_COUNTER_NULLABLE_KEYS
    | RUNNER_WAKEUP_V9_FAILURE_INTEGER_KEYS
    | {
        "outcome",
        "phase",
        "dispatch_at_defense_nanoseconds",
        "exit_at_or_after_deadline",
        "active_wait_poll_source",
        "counter_backed",
        "counter_unavailable",
        "counter_nonmonotonic",
    }
)
RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME = {
    "invalid-counter-frequency": "buflo_exact_release_invalid_counter_frequency_guards",
    "counter-unavailable": "buflo_exact_release_counter_unavailable_failure_guards",
    "counter-nonmonotonic": "buflo_exact_release_counter_nonmonotonic_failure_guards",
    "counter-frequency-changed": "buflo_exact_release_counter_frequency_changed_guards",
    "counter-target-error": "buflo_exact_release_counter_target_error_guards",
}
_LEGACY_SCHEDULED_INCOMING_CONTRACT = {
    "scheduled_incoming_requested_bytes": _INTEGER,
    "scheduled_incoming_consumed_bytes": _INTEGER,
    "scheduled_incoming_retired_bytes": _INTEGER,
    "scheduled_incoming_unresolved_bytes": _INTEGER,
}
_SCHEDULED_INCOMING_CONTRACT = {
    **_LEGACY_SCHEDULED_INCOMING_CONTRACT,
    "scheduled_incoming_advertised_bytes": _INTEGER,
}
_DIAGNOSTIC_CONTRACTS: dict[str, dict[str, str]] = {
    "buflo": {
        **{
            key: _INTEGER
            for key in (
                "buflo_scheduled_outgoing_cells",
                "buflo_scheduled_incoming_cells",
                "buflo_full_outgoing_cells",
                "buflo_partial_outgoing_cells",
                "buflo_suppressed_outgoing_cells",
                "buflo_missed_outgoing_cells",
                "buflo_missed_incoming_cells",
                "buflo_outgoing_unresolved_cells",
                "buflo_incoming_unresolved_cells",
                "buflo_catch_up_outgoing_cells",
                "buflo_catch_up_incoming_cells",
                "buflo_terminal_subcell_pending_request_cancellations",
                "buflo_terminal_subcell_stream_cancellations",
                "buflo_terminal_subcell_exact_capacity_bytes_cancelled",
                "buflo_terminal_subcell_latched_at_us",
                "buflo_terminal_subcell_open_streams_at_latch",
                "buflo_terminal_subcell_parser_lease_bytes_at_latch",
                "buflo_terminal_subcell_pending_parser_boundaries_at_latch",
                "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch",
                *BUFLO_SCHEDULE_STOP_V4_INTEGER_KEYS,
            )
        },
        "buflo_paper_equivalent": _BOOLEAN,
        "buflo_client_only": _BOOLEAN,
        "buflo_egress_backlog_pending": _BOOLEAN,
        "buflo_application_complete": _BOOLEAN,
        "buflo_minimum_duration_reached": _BOOLEAN,
        "buflo_event_guard_triggered": _BOOLEAN,
        "buflo_terminal_subcell_latched": _BOOLEAN,
        "buflo_schedule_stop_latched": _BOOLEAN,
    },
    "cs-buflo": {
        **{
            key: _INTEGER
            for key in (
                "cs_buflo_scheduled_outgoing_cells",
                "cs_buflo_scheduled_incoming_cells",
                "cs_buflo_full_outgoing_cells",
                "cs_buflo_partial_outgoing_cells",
                "cs_buflo_suppressed_outgoing_cells",
                "cs_buflo_missed_outgoing_cells",
                "cs_buflo_missed_incoming_cells",
                "cs_buflo_desired_udp_bytes",
                "cs_buflo_realized_udp_bytes",
                "cs_buflo_application_stream_bytes",
                "cs_buflo_retransmission_stream_bytes",
                "cs_buflo_chaff_stream_bytes",
                "cs_buflo_defense_control_bytes",
                "cs_buflo_quic_padding_bytes",
                "cs_buflo_other_quic_bytes",
                "cs_buflo_lateness_us_total",
                "cs_buflo_lateness_us_max",
                "cs_buflo_natural_outgoing_bytes",
                "cs_buflo_natural_incoming_bytes",
                "cs_buflo_cover_outgoing_bytes",
                "cs_buflo_cover_incoming_bytes",
                "cs_buflo_real_bearing_outgoing_bytes",
                "cs_buflo_real_bearing_incoming_bytes",
                "cs_buflo_realized_incoming_credit_bytes",
                "cs_buflo_outgoing_padding_basis_natural_bytes",
                "cs_buflo_incoming_padding_basis_natural_bytes",
                "cs_buflo_outgoing_padding_basis_cover_bytes",
                "cs_buflo_incoming_padding_basis_cover_bytes",
                "cs_buflo_outgoing_padding_basis_total_bytes",
                "cs_buflo_incoming_padding_basis_total_bytes",
                "cs_buflo_reference_tcp_write_size_bytes",
                "cs_buflo_reference_nominal_tcp_packet_size_bytes",
                "cs_buflo_runtime_udp_packet_size_bytes",
                "cs_buflo_outgoing_termination_accounted_bytes",
                "cs_buflo_incoming_termination_accounted_bytes",
                "cs_buflo_outgoing_last_termination_increment_bytes",
                "cs_buflo_incoming_last_termination_increment_bytes",
                "cs_buflo_outgoing_padding_target_bytes",
                "cs_buflo_incoming_padding_target_bytes",
                "cs_buflo_outgoing_interval_us",
                "cs_buflo_incoming_interval_us",
                "cs_buflo_outgoing_rate_adaptations",
                "cs_buflo_incoming_rate_adaptations",
                "cs_buflo_rate_boundary_translation_version",
                "cs_buflo_local_et_pending_request_cancellations",
                "cs_buflo_local_et_stream_cancellations",
                "cs_buflo_next_outgoing_adaptation_boundary_bytes",
                "cs_buflo_next_incoming_adaptation_boundary_bytes",
                "cs_buflo_outgoing_estimator_samples",
                "cs_buflo_incoming_estimator_samples",
                "cs_buflo_outgoing_minimum_interval_opportunities",
                "cs_buflo_incoming_minimum_interval_opportunities",
                "cs_buflo_incoming_minimum_interval_local_realized",
                "cs_buflo_outgoing_minimum_interval_terminal",
                "cs_buflo_incoming_minimum_interval_terminal",
                "cs_buflo_outgoing_minimum_interval_full",
                "cs_buflo_incoming_minimum_interval_full",
                "cs_buflo_incoming_local_realized_cells",
                "cs_buflo_outgoing_unresolved_cells",
                "cs_buflo_incoming_unresolved_cells",
                *CS_BUFLO_LOCAL_ET_V3_INTEGER_KEYS,
                *CS_BUFLO_STOP_DRAIN_V4_INTEGER_KEYS,
            )
        },
        **{
            key: _BOOLEAN
            for key in (
                "cs_buflo_paper_equivalent",
                "cs_buflo_client_only",
                "cs_buflo_payload_padding",
                "cs_buflo_total_padding",
                "cs_buflo_outgoing_power_of_two_crossed",
                "cs_buflo_incoming_power_of_two_crossed",
                "cs_buflo_egress_backlog_pending",
                "cs_buflo_application_complete",
                "cs_buflo_quiet_time_reached",
                "cs_buflo_local_termination_latched",
                "cs_buflo_event_guard_triggered",
                *CS_BUFLO_LOCAL_ET_V3_BOOLEAN_KEYS,
                *CS_BUFLO_STOP_DRAIN_V4_BOOLEAN_KEYS,
            )
        },
        "cs_buflo_early_termination_semantics": _STRING,
        **{key: _STRING for key in CS_BUFLO_STOP_DRAIN_V4_STRING_KEYS},
        "cs_buflo_rate_boundary_counter_semantics": _STRING,
        "cs_buflo_author_rate_boundary_counter_semantics": _STRING,
        "cs_buflo_rate_transitions": _CS_RATE_TRANSITION_VECTOR,
    },
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
    defense = _canonical_fidelity_defense(defense)
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
    elif defense == "walkie-talkie":
        selected = {
            key: value
            for key, value in diagnostics.items()
            if key.startswith("walkie_talkie_") or key == "retried_outgoing_events"
        }
    elif defense == "buflo":
        selected = {key: value for key, value in diagnostics.items() if key.startswith("buflo_")}
    else:
        selected = {key: value for key, value in diagnostics.items() if key.startswith("cs_buflo_")}
    expected = set(contract)
    if defense == "buflo" and (
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch" not in selected
    ):
        # Historical summary schema 2 predates the application/chaff parser-boundary
        # split.  Its single aggregate was required to be zero.
        expected.remove("buflo_terminal_subcell_pending_application_parser_boundaries_at_latch")
    if defense == "buflo" and not (BUFLO_SCHEDULE_STOP_V4_KEYS & set(selected)):
        # Historical summary schemas 2 and 3 predate the explicit
        # stop-new-opportunities/then-drain receipt. Partial schema-4 evidence
        # remains invalid because the exact-key comparison still requires all
        # fields when any one of them is present.
        expected -= BUFLO_SCHEDULE_STOP_V4_KEYS
    if defense == "cs-buflo" and not (CS_BUFLO_LOCAL_ET_V3_KEYS & set(selected)):
        # Historical summary schema 2 predates the explicit application-state
        # passthrough and post-local-ET natural-byte accounting contract.
        expected -= CS_BUFLO_LOCAL_ET_V3_KEYS
    if defense == "cs-buflo" and not (CS_BUFLO_STOP_DRAIN_V4_KEYS & set(selected)):
        # Historical summary schemas 2 and 3 predate the asynchronous
        # stop-new-opportunities/then-drain translation.  Partial version-4
        # evidence remains invalid because the exact-key comparison below
        # still requires the complete receipt.
        expected -= CS_BUFLO_STOP_DRAIN_V4_KEYS
    if set(selected) != expected:
        return False
    return all(_diagnostic_value_matches(contract[key], selected[key]) for key in expected)


def _scheduled_incoming_diagnostics_match(diagnostics: dict[str, Any]) -> bool:
    selected = {
        key: value for key, value in diagnostics.items() if key.startswith("scheduled_incoming_")
    }
    selected_keys = frozenset(selected)
    if selected_keys not in {
        frozenset(_LEGACY_SCHEDULED_INCOMING_CONTRACT),
        frozenset(_SCHEDULED_INCOMING_CONTRACT),
    }:
        return False
    if not all(
        _diagnostic_value_matches(kind, selected[key])
        for key, kind in (
            _SCHEDULED_INCOMING_CONTRACT.items()
            if "scheduled_incoming_advertised_bytes" in selected
            else _LEGACY_SCHEDULED_INCOMING_CONTRACT.items()
        )
    ):
        return False
    requested = selected["scheduled_incoming_requested_bytes"]
    advertised = selected.get("scheduled_incoming_advertised_bytes")
    consumed = selected["scheduled_incoming_consumed_bytes"]
    retired = selected["scheduled_incoming_retired_bytes"]
    unresolved = selected["scheduled_incoming_unresolved_bytes"]
    return (
        requested == consumed + retired + unresolved
        and requested == consumed
        and (advertised is None or requested == advertised)
        and retired == 0
        and unresolved == 0
    )


def _diagnostic_value_matches(kind: str, value: Any) -> bool:
    if kind == _INTEGER:
        return type(value) is int and value >= 0
    if kind == _BOOLEAN:
        return type(value) is bool
    if kind == _STRING:
        return isinstance(value, str) and bool(value)
    if kind == _CS_RATE_TRANSITION_VECTOR:
        return _cs_buflo_rate_transition_vector_valid(value)
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


def _cs_buflo_rate_transition_vector_valid(value: Any) -> bool:
    required = {
        "schema_version",
        "direction",
        "at_us",
        "boundary_bytes",
        "real_bearing_bytes",
        "eligible_samples",
        "median_interval_us",
        "previous_interval_us",
        "resulting_interval_us",
        "retained_current_interval",
    }
    if not isinstance(value, list):
        return False
    prior_time = -1
    direction_counts = {"outgoing": 0, "incoming": 0}
    for transition in value:
        if not isinstance(transition, Mapping) or set(transition) != required:
            return False
        direction = transition.get("direction")
        median = transition.get("median_interval_us")
        integer_fields = (
            "at_us",
            "boundary_bytes",
            "real_bearing_bytes",
            "eligible_samples",
            "previous_interval_us",
            "resulting_interval_us",
        )
        if (
            transition.get("schema_version") != 1
            or direction not in direction_counts
            or any(
                type(transition.get(field)) is not int or transition[field] < 0
                for field in integer_fields
            )
            or type(transition.get("retained_current_interval")) is not bool
            or (median is not None and (type(median) is not int or median <= 0))
            or transition["at_us"] < prior_time
            or transition["eligible_samples"] > 1_000
            or transition["boundary_bytes"] != 16_384 << direction_counts[str(direction)]
            or transition["real_bearing_bytes"] < transition["boundary_bytes"]
            or transition["previous_interval_us"] not in {4_096, 8_192, 16_384, 32_768}
            or transition["resulting_interval_us"] not in {4_096, 8_192, 16_384, 32_768}
        ):
            return False
        retained = transition["retained_current_interval"]
        if retained != (median is None):
            return False
        if median is None:
            if transition["resulting_interval_us"] != transition["previous_interval_us"]:
                return False
        else:
            selected = max(4_096, min(32_768, 1 << (median.bit_length() - 1)))
            if transition["resulting_interval_us"] != selected:
                return False
        prior_time = transition["at_us"]
        direction_counts[str(direction)] += 1
    return True


def new_defense_terminal_receipts_valid(
    run: Mapping[str, Any],
    defense_kind: str,
    *,
    require_application_complete: bool = False,
    require_current_schema: bool = False,
) -> bool:
    """Validate the versioned terminal summary bound to flat Rust diagnostics.

    The schema validator permits CS-BuFLO's strict quiet-time fallback when
    requested.  Successful study capture passes
    ``require_application_complete=True`` so a missing local onLoad analogue
    remains ineligible for the study cohort.
    """

    canonical = {"buflo": "buflo", "cs_buflo": "cs-buflo"}.get(defense_kind)
    if canonical is None:
        return False
    resolved = run.get("resolved_configuration")
    resolved_defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    diagnostics = run.get("defense_diagnostics")
    if (
        run.get("completion_status") != "complete"
        or run.get("error") is not None
        or run.get("error_class") is not None
        or not isinstance(resolved, Mapping)
        or resolved.get("schema_version") != 2
        or not isinstance(resolved_defense, Mapping)
        or resolved_defense.get("kind") != defense_kind
        or not isinstance(diagnostics, dict)
        or not _diagnostics_match_contract(canonical, diagnostics)
        or not _runner_wakeup_metrics_valid(run.get("runner_wakeup_metrics"))
    ):
        return False
    wakeup_metrics = run["runner_wakeup_metrics"]
    if require_current_schema and wakeup_metrics["schema_version"] != 9:
        return False
    if wakeup_metrics["schema_version"] in {2, 3, 4, 5, 6, 7, 8, 9} and defense_kind != "buflo":
        if any(
            wakeup_metrics[key]
            for key in (
                "buflo_exact_release_guard_entries",
                "buflo_exact_release_guard_wait_nanoseconds",
                "buflo_exact_release_active_wait_nanoseconds",
                "buflo_exact_release_max_passive_wake_lateness_nanoseconds",
                "buflo_exact_release_max_guard_exit_lateness_nanoseconds",
            )
        ):
            return False
    if wakeup_metrics["schema_version"] in {5, 6, 7, 8, 9} and defense_kind != "buflo":
        if any(
            wakeup_metrics[key]
            for key in (
                "buflo_exact_incoming_retry_drives",
                "buflo_exact_incoming_retry_resolutions",
                "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
            )
        ):
            return False
    if wakeup_metrics["schema_version"] in {4, 5, 6, 7, 8, 9} and defense_kind != "cs_buflo":
        if any(
            wakeup_metrics[key]
            for key in (
                "cs_exact_incoming_retry_drives",
                "cs_exact_incoming_retry_resolutions",
                "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
            )
        ):
            return False
    if wakeup_metrics["schema_version"] in {7, 8, 9} and defense_kind == "buflo":
        scheduled_outgoing = diagnostics.get("buflo_scheduled_outgoing_cells")
        if (
            type(scheduled_outgoing) is not int
            or scheduled_outgoing <= 0
            or wakeup_metrics["buflo_exact_release_guard_entries"] != scheduled_outgoing - 1
            or wakeup_metrics["buflo_exact_release_dispatch_at_or_after_deadline_guards"] != 0
            or wakeup_metrics["buflo_exact_release_max_guard_exit_lateness_nanoseconds"]
            >= 5_000_000
        ):
            return False
    if wakeup_metrics["schema_version"] == 9 and defense_kind == "buflo":
        guard_entries = wakeup_metrics["buflo_exact_release_guard_entries"]
        dispatch_ready = wakeup_metrics["buflo_exact_release_dispatch_ready_guards"]
        confirmations = wakeup_metrics["buflo_exact_release_active_wait_instant_confirmations"]
        early_retries = wakeup_metrics["buflo_exact_release_active_wait_early_confirmation_retries"]
        if (
            dispatch_ready != guard_entries
            or wakeup_metrics["buflo_exact_release_failed_guards"] != 0
            or any(
                wakeup_metrics[key] for key in RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME.values()
            )
            or wakeup_metrics["buflo_exact_release_last_failure"] is not None
        ):
            return False
        worst = wakeup_metrics["buflo_exact_release_worst_guard"]
        if guard_entries > 0 and (
            not isinstance(worst, Mapping)
            or any(type(worst.get(key)) is not int for key in RUNNER_WAKEUP_V7_WORST_TIME_KEYS)
        ):
            return False
        if wakeup_metrics[
            "buflo_exact_release_active_wait_poll_source"
        ] == "linux-aarch64-cntvct-el0-predictive-v1" and (
            wakeup_metrics["buflo_exact_release_active_wait_counter_guards"] != guard_entries
            or wakeup_metrics["buflo_exact_release_active_wait_counter_unavailable_guards"] != 0
            or wakeup_metrics["buflo_exact_release_active_wait_counter_nonmonotonic_guards"] != 0
            or confirmations != guard_entries + early_retries
            or wakeup_metrics["buflo_exact_release_active_wait_counter_calibrations"]
            != confirmations
        ):
            return False
    prefix = "buflo_" if defense_kind == "buflo" else "cs_buflo_"
    selected = {key: value for key, value in diagnostics.items() if key.startswith(prefix)}
    selected_key = "buflo_summary" if defense_kind == "buflo" else "cs_buflo_summary"
    other_key = "cs_buflo_summary" if defense_kind == "buflo" else "buflo_summary"
    summary = run.get(selected_key)
    if other_key not in run or run[other_key] is not None or not isinstance(summary, Mapping):
        return False
    expected_fields = {
        "schema_version",
        "kind",
        "implementation_scope",
        "paper_equivalent",
        "incoming_opportunity_semantics",
        "unavailable_peer_properties",
        "diagnostics",
    }
    if defense_kind == "buflo":
        expected_fields.update(
            {
                "terminal_subcell_policy",
                "terminal_subcell_observer_effect",
            }
        )
    else:
        expected_fields.update(
            {
                "early_termination_semantics",
                "incoming_cadence_boundary",
                "incoming_terminal_boundary",
                "incoming_boundary_separation",
            }
        )
    summary_schema = summary.get("schema_version")
    if defense_kind == "cs_buflo" and summary_schema == 4:
        expected_fields.update(
            {
                "early_termination_translation_version",
                "termination_stop_policy",
            }
        )
    if defense_kind == "buflo" and summary_schema == 4:
        expected_fields.add("terminal_schedule_stop_policy")
    supported_summary_schemas = {2, 3, 4}
    if (
        set(summary) != expected_fields
        or type(summary_schema) is not int
        or summary_schema not in supported_summary_schemas
        or (require_current_schema and summary_schema != 4)
        or summary.get("kind") != defense_kind
        or summary.get("implementation_scope") != "client_only_quic"
        or summary.get("paper_equivalent") is not False
        or summary.get("incoming_opportunity_semantics")
        != "client_receive_credit_and_response_qualified_chaff_attempt"
        or summary.get("unavailable_peer_properties")
        != ["scheduled_server_datagram_timing", "scheduled_server_datagram_size"]
        or summary.get("diagnostics") != diagnostics
    ):
        return False
    if defense_kind == "buflo":
        parser_current = summary_schema in {3, 4}
        stop_drain_current = summary_schema == 4
        stop_drain_present = bool(BUFLO_SCHEDULE_STOP_V4_KEYS & set(selected))
        responses = run.get("chaff_responses")
        receipt_cancellations = (
            sum(
                isinstance(response, Mapping)
                and response.get("outcome") == "buflo_terminal_subcell_tail_cancelled"
                for response in responses
            )
            if isinstance(responses, list)
            else None
        )
        return (
            summary.get("terminal_subcell_policy") == BUFLO_TERMINAL_SUBCELL_POLICY
            and summary.get("terminal_subcell_observer_effect")
            == BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT
            and (
                not stop_drain_current
                or summary.get("terminal_schedule_stop_policy") == BUFLO_SCHEDULE_STOP_POLICY
            )
            and selected["buflo_client_only"] is True
            and parser_current
            == ("buflo_terminal_subcell_pending_application_parser_boundaries_at_latch" in selected)
            and stop_drain_current == stop_drain_present
            and buflo_terminal_diagnostics_valid(selected, require_current=stop_drain_current)
            and (
                not parser_current
                or receipt_cancellations == selected["buflo_terminal_subcell_stream_cancellations"]
            )
            and (not require_application_complete or selected["buflo_application_complete"] is True)
        )
    current = summary_schema in {3, 4}
    stop_drain_current = summary_schema == 4
    early_termination_semantics = (
        CS_BUFLO_EARLY_TERMINATION_SEMANTICS
        if stop_drain_current
        else CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS
    )
    return (
        summary.get("early_termination_semantics") == early_termination_semantics
        and (
            not stop_drain_current
            or (
                type(summary.get("early_termination_translation_version")) is int
                and summary.get("early_termination_translation_version")
                == CS_BUFLO_EARLY_TERMINATION_TRANSLATION_VERSION
            )
        )
        and (
            not stop_drain_current
            or summary.get("termination_stop_policy") == CS_BUFLO_TERMINATION_STOP_POLICY
        )
        and summary.get("incoming_cadence_boundary") == CS_BUFLO_INCOMING_CADENCE_BOUNDARY
        and summary.get("incoming_terminal_boundary") == CS_BUFLO_INCOMING_TERMINAL_BOUNDARY
        and summary.get("incoming_boundary_separation") == CS_BUFLO_INCOMING_BOUNDARY_SEPARATION
        and selected["cs_buflo_early_termination_semantics"] == early_termination_semantics
        and selected["cs_buflo_client_only"] is True
        and selected["cs_buflo_quiet_time_reached"] is True
        and selected["cs_buflo_local_termination_latched"] is True
        and current == CS_BUFLO_LOCAL_ET_V3_KEYS.issubset(selected)
        and stop_drain_current == CS_BUFLO_STOP_DRAIN_V4_KEYS.issubset(selected)
        and (
            not stop_drain_current
            or (
                selected["cs_buflo_outgoing_termination_stop_latched"] is True
                and selected["cs_buflo_incoming_termination_stop_latched"] is True
                and _cs_buflo_stop_drain_matches(selected)
            )
        )
        and cs_buflo_local_et_handoff_valid(selected, require_current=current)
        and (
            not current
            or selected["cs_buflo_application_complete"] is True
            or selected["cs_buflo_local_et_before_application_complete"] is True
        )
        and (not require_application_complete or selected["cs_buflo_application_complete"] is True)
    )


def _runner_wakeup_v7_histogram_valid(value: Any, *, entries: int) -> bool:
    return bool(
        isinstance(value, Mapping)
        and set(value) == {"upper_bounds_nanoseconds", "counts"}
        and value.get("upper_bounds_nanoseconds") == RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS
        and isinstance(value.get("counts"), list)
        and len(value["counts"]) == 8
        and all(type(count) is int and count >= 0 for count in value["counts"])
        and sum(value["counts"]) == entries
    )


def _runner_wakeup_v7_bucket(value: int) -> int:
    return sum(value > upper for upper in RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS)


def _runner_wakeup_v7_worst_guard_valid(value: Any, *, metrics: Mapping[str, Any]) -> bool:
    entries = metrics["buflo_exact_release_guard_entries"]
    if entries == 0:
        return value is None
    if not isinstance(value, Mapping) or set(value) != RUNNER_WAKEUP_V7_WORST_KEYS:
        return False
    if (
        any(
            type(value.get(key)) is not int or value[key] < 0
            for key in RUNNER_WAKEUP_V7_WORST_INTEGER_KEYS
        )
        or value.get("phase") not in {"prearmed", "committed"}
        or type(value.get("dispatch_at_or_after_deadline")) is not bool
    ):
        return False
    times = [value[key] for key in RUNNER_WAKEUP_V7_WORST_TIME_KEYS]
    if not (
        all(item is None for item in times)
        or all(type(item) is int and item >= 0 for item in times)
    ):
        return False
    for key in RUNNER_WAKEUP_V7_WORST_AUX_KEYS:
        if value[key] is not None and (type(value[key]) is not int or value[key] < 0):
            return False

    dispatch_lateness = value["dispatch_lateness_nanoseconds"]
    at_or_after_deadline = value["dispatch_at_or_after_deadline"]
    dispatch_after_deadline = value["dispatch_after_deadline_nanoseconds"]
    outside_count = metrics["buflo_exact_release_dispatch_at_or_after_deadline_guards"]
    active_wait = value["active_wait_monotonic_nanoseconds"]
    raw_elapsed = value["active_wait_monotonic_raw_nanoseconds"]
    thread_cpu_elapsed = value["active_wait_thread_cpu_nanoseconds"]
    estimated_off_cpu = value["active_wait_estimated_off_cpu_nanoseconds"]
    raw_divergence = value["active_wait_monotonic_raw_divergence_nanoseconds"]
    spin_interruptions = value["active_spin_interruptions"]
    spin_interruption_nanoseconds = value["active_spin_interruption_nanoseconds"]
    max_spin_gap = value["max_active_spin_gap_nanoseconds"]

    if (
        dispatch_lateness != metrics["buflo_exact_release_max_guard_exit_lateness_nanoseconds"]
        or (outside_count == 0 and at_or_after_deadline)
        or (outside_count == entries and not at_or_after_deadline)
        or (not at_or_after_deadline and dispatch_after_deadline != 0)
        or metrics["buflo_exact_release_dispatch_lateness_histogram"]["counts"][
            _runner_wakeup_v7_bucket(dispatch_lateness)
        ]
        == 0
        or value["guard_entry_lateness_nanoseconds"]
        > metrics["buflo_exact_release_max_guard_entry_lateness_nanoseconds"]
        or value["passive_sleep_calls"] > metrics["buflo_exact_release_passive_sleep_calls"]
        or value["passive_sleep_requested_nanoseconds"]
        > metrics["buflo_exact_release_passive_sleep_requested_nanoseconds"]
        or value["passive_sleep_elapsed_nanoseconds"]
        > metrics["buflo_exact_release_passive_sleep_elapsed_nanoseconds"]
        or value["max_passive_sleep_overrun_nanoseconds"]
        > metrics["buflo_exact_release_max_passive_sleep_overrun_nanoseconds"]
        or value["active_wait_iterations"] > metrics["buflo_exact_release_active_wait_iterations"]
        or active_wait > metrics["buflo_exact_release_active_wait_nanoseconds"]
        or value["active_spin_interruptions"]
        > metrics["buflo_exact_release_active_spin_interruptions"]
        or value["active_spin_interruption_nanoseconds"]
        > metrics["buflo_exact_release_active_spin_interruption_nanoseconds"]
        or value["max_active_spin_gap_nanoseconds"]
        > metrics["buflo_exact_release_max_active_spin_gap_nanoseconds"]
        or value["max_passive_sleep_overrun_nanoseconds"]
        > value["passive_sleep_elapsed_nanoseconds"]
        or spin_interruptions > value["active_wait_iterations"]
        or ((spin_interruptions > 0) != (max_spin_gap > 50_000))
        or ((spin_interruptions == 0) != (spin_interruption_nanoseconds == 0))
        or (spin_interruptions > 0 and spin_interruption_nanoseconds < max_spin_gap)
        or spin_interruption_nanoseconds > active_wait
        or max_spin_gap > active_wait
        or metrics["buflo_exact_release_active_spin_gap_histogram"]["counts"][
            _runner_wakeup_v7_bucket(max_spin_gap)
        ]
        == 0
        or ((raw_elapsed is None) != (raw_divergence is None))
        or ((thread_cpu_elapsed is None) != (estimated_off_cpu is None))
        or (raw_elapsed is not None and raw_divergence != abs(active_wait - raw_elapsed))
        or (
            thread_cpu_elapsed is not None
            and estimated_off_cpu != max(active_wait - thread_cpu_elapsed, 0)
        )
        or (
            raw_elapsed is not None
            and thread_cpu_elapsed is not None
            and metrics["buflo_exact_release_active_wait_aux_clock_guards"] == 0
        )
        or (
            (raw_elapsed is None or thread_cpu_elapsed is None)
            and metrics["buflo_exact_release_active_wait_aux_clock_unavailable_guards"] == 0
        )
        or (
            metrics["buflo_exact_release_aux_clock_source"] == "unavailable-on-platform"
            and any(value[key] is not None for key in RUNNER_WAKEUP_V7_WORST_AUX_KEYS)
        )
    ):
        return False
    bounded_aux = {
        "active_wait_monotonic_raw_nanoseconds": (
            "buflo_exact_release_active_wait_monotonic_raw_nanoseconds"
        ),
        "active_wait_thread_cpu_nanoseconds": (
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds"
        ),
        "active_wait_estimated_off_cpu_nanoseconds": (
            "buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds"
        ),
        "active_wait_monotonic_raw_divergence_nanoseconds": (
            "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds"
        ),
    }
    if any(
        value[key] is not None and value[key] > metrics[metric]
        for key, metric in bounded_aux.items()
    ):
        return False
    if all(item is not None for item in times):
        guard = value["guard_at_defense_nanoseconds"]
        entered = value["entered_at_defense_nanoseconds"]
        active_at = value["active_wait_at_defense_nanoseconds"]
        active_started = value["active_wait_started_at_defense_nanoseconds"]
        release = value["release_at_defense_nanoseconds"]
        deadline = value["deadline_at_defense_nanoseconds"]
        dispatch = value["dispatch_at_defense_nanoseconds"]
        nominal_release = value["packet_timestamp_us"] * 1_000
        release_skew = release - nominal_release
        deadline_skew = nominal_release + 5_000_000 - deadline
        normalization_skew = release_skew + deadline_skew
        actual_window = deadline - release
        if (
            not 0 <= release_skew <= 999
            or not 0 <= deadline_skew <= 999
            or normalization_skew not in {0, 1_000}
            or actual_window != 5_000_000 - normalization_skew
            or actual_window not in {4_999_000, 5_000_000}
            or active_at != guard
            or release - guard != 2 * actual_window
            or not guard <= entered <= active_started <= dispatch
            or release > dispatch
            or value["guard_entry_lateness_nanoseconds"] != entered - guard
            or active_wait != dispatch - active_started
            or active_started - active_at
            > metrics["buflo_exact_release_max_passive_wake_lateness_nanoseconds"]
            or dispatch_lateness != dispatch - release
            or at_or_after_deadline is not (dispatch >= deadline)
            or dispatch_after_deadline != max(dispatch - deadline, 0)
        ):
            return False
    else:
        possible_windows = (4_999_000, 5_000_000)
        if not any(
            at_or_after_deadline is (dispatch_lateness >= window)
            and dispatch_after_deadline == max(dispatch_lateness - window, 0)
            for window in possible_windows
        ):
            return False
    return True


def _runner_wakeup_fine_timing_valid(
    value: Any,
    *,
    schema_version: int,
    semantics: str,
) -> bool:
    """Validate one version of fine-grained exact-release timing evidence."""

    base_integer_keys = {
        "wait_returns",
        "socket_readiness_wakeups",
        "timer_wakeups",
        "controller_deadline_timer_wakeups",
        "other_timer_wakeups",
        "buflo_exact_release_guard_entries",
        "buflo_exact_release_guard_wait_nanoseconds",
        "buflo_exact_release_active_wait_nanoseconds",
        "buflo_exact_release_max_passive_wake_lateness_nanoseconds",
        "buflo_exact_release_max_guard_exit_lateness_nanoseconds",
        "buflo_exact_incoming_retry_drives",
        "buflo_exact_incoming_retry_resolutions",
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
        "cs_exact_incoming_retry_drives",
        "cs_exact_incoming_retry_resolutions",
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
    }
    integer_keys = base_integer_keys | set(RUNNER_WAKEUP_V7_NEW_INTEGER_KEYS)
    required = (
        integer_keys
        | set(RUNNER_WAKEUP_V7_OBJECT_KEYS)
        | {
            "schema_version",
            "semantics",
        }
    )
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("schema_version") != schema_version
        or value.get("semantics") != semantics
        or any(type(value.get(key)) is not int or value[key] < 0 for key in integer_keys)
        or value.get("buflo_exact_release_aux_clock_source")
        not in {
            "linux-clock-gettime-monotonic-raw-and-thread-cputime-id-v1",
            "unavailable-on-platform",
        }
    ):
        return False
    entries = value["buflo_exact_release_guard_entries"]
    if (
        not _runner_wakeup_v7_histogram_valid(
            value["buflo_exact_release_dispatch_lateness_histogram"], entries=entries
        )
        or not _runner_wakeup_v7_histogram_valid(
            value["buflo_exact_release_active_spin_gap_histogram"], entries=entries
        )
        or not _runner_wakeup_v7_worst_guard_valid(
            value["buflo_exact_release_worst_guard"], metrics=value
        )
        or value["buflo_exact_release_active_wait_nanoseconds"]
        > value["buflo_exact_release_guard_wait_nanoseconds"]
        or value["buflo_exact_release_active_wait_aux_clock_guards"]
        + value["buflo_exact_release_active_wait_aux_clock_unavailable_guards"]
        != entries
        or value["buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards"]
        > value["buflo_exact_release_active_wait_aux_clock_unavailable_guards"]
        or value["buflo_exact_release_dispatch_at_or_after_deadline_guards"] > entries
        or value["buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds"]
        > value["buflo_exact_release_active_wait_nanoseconds"]
        or value["buflo_exact_release_max_passive_sleep_overrun_nanoseconds"]
        > value["buflo_exact_release_passive_sleep_elapsed_nanoseconds"]
        or value["buflo_exact_release_max_active_spin_gap_nanoseconds"]
        > value["buflo_exact_release_active_wait_nanoseconds"]
        or value["buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds"]
        > value["buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds"]
        or value["buflo_exact_release_active_spin_interruptions"]
        > value["buflo_exact_release_active_wait_iterations"]
        or (
            (value["buflo_exact_release_active_spin_interruptions"] == 0)
            != (value["buflo_exact_release_active_spin_interruption_nanoseconds"] == 0)
        )
        or (
            (value["buflo_exact_release_active_spin_interruptions"] > 0)
            != (value["buflo_exact_release_max_active_spin_gap_nanoseconds"] > 50_000)
        )
        or (
            value["buflo_exact_release_active_spin_interruptions"] > 0
            and value["buflo_exact_release_active_spin_interruption_nanoseconds"]
            < value["buflo_exact_release_max_active_spin_gap_nanoseconds"]
        )
        or value["buflo_exact_release_active_spin_interruption_nanoseconds"]
        > value["buflo_exact_release_active_wait_nanoseconds"]
        or (
            entries > 0
            and value["buflo_exact_release_active_spin_gap_histogram"]["counts"][
                _runner_wakeup_v7_bucket(
                    value["buflo_exact_release_max_active_spin_gap_nanoseconds"]
                )
            ]
            == 0
        )
    ):
        return False
    timing_scalars = {
        "buflo_exact_release_guard_wait_nanoseconds",
        "buflo_exact_release_active_wait_nanoseconds",
        "buflo_exact_release_max_passive_wake_lateness_nanoseconds",
        "buflo_exact_release_max_guard_exit_lateness_nanoseconds",
        *RUNNER_WAKEUP_V7_NEW_INTEGER_KEYS,
    }
    if entries == 0 and any(value[key] for key in timing_scalars):
        return False
    if value["buflo_exact_release_aux_clock_source"] == "unavailable-on-platform" and (
        value["buflo_exact_release_active_wait_aux_clock_guards"] != 0
        or value["buflo_exact_release_active_wait_aux_clock_unavailable_guards"] != entries
        or any(
            value[key]
            for key in (
                "buflo_exact_release_active_wait_monotonic_raw_nanoseconds",
                "buflo_exact_release_active_wait_thread_cpu_nanoseconds",
                "buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds",
                "buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds",
                "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds",
            )
        )
    ):
        return False
    return (
        value["wait_returns"] == value["socket_readiness_wakeups"] + value["timer_wakeups"]
        and value["timer_wakeups"]
        == value["controller_deadline_timer_wakeups"] + value["other_timer_wakeups"]
        and value["cs_exact_incoming_retry_resolutions"] <= value["cs_exact_incoming_retry_drives"]
        and (
            value["cs_exact_incoming_retry_drives"] != 0
            or value["cs_exact_incoming_retry_max_phase_lateness_nanoseconds"] == 0
        )
        and value["buflo_exact_incoming_retry_resolutions"]
        <= value["buflo_exact_incoming_retry_drives"]
    )


def _runner_wakeup_v9_last_failure_valid(
    value: Any,
    *,
    metrics: Mapping[str, Any],
) -> bool:
    """Validate the authoritative exit receipt for one typed wait failure."""

    failed = metrics["buflo_exact_release_failed_guards"]
    if failed == 0:
        return value is None
    if failed != 1 or not isinstance(value, Mapping) or set(value) != RUNNER_WAKEUP_V9_FAILURE_KEYS:
        return False
    if (
        any(
            type(value.get(key)) is not int or value[key] < 0
            for key in RUNNER_WAKEUP_V9_FAILURE_INTEGER_KEYS
        )
        or value.get("outcome") not in RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME
        or value.get("phase") not in {"prearmed", "committed"}
        or value.get("dispatch_at_defense_nanoseconds") is not None
        or type(value.get("exit_at_or_after_deadline")) is not bool
        or value.get("active_wait_poll_source") not in RUNNER_WAKEUP_V9_POLL_SOURCES
        or any(
            type(value.get(key)) is not bool
            for key in ("counter_backed", "counter_unavailable", "counter_nonmonotonic")
        )
    ):
        return False

    times = [value[key] for key in RUNNER_WAKEUP_V9_FAILURE_TIME_KEYS]
    if not (
        all(item is None for item in times)
        or all(type(item) is int and item >= 0 for item in times)
    ):
        return False
    counter_tuple = (
        value["counter_frequency_hz"],
        value["counter_nanoseconds"],
        value["max_counter_gap_nanoseconds"],
        value["max_counter_calibration_span_nanoseconds"],
    )
    if not (
        all(item is None for item in counter_tuple)
        or all(type(item) is int and item >= 0 for item in counter_tuple)
    ):
        return False
    frequency, counter_nanoseconds, max_counter_gap, max_calibration_span = counter_tuple
    if frequency is not None and not 1_000_000 <= frequency <= 2**32 - 1:
        return False

    outcome = value["outcome"]
    outcome_counter = RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME[outcome]
    counter_backed = value["counter_backed"]
    counter_unavailable = value["counter_unavailable"]
    counter_nonmonotonic = value["counter_nonmonotonic"]
    calibrations = value["counter_calibrations"]
    confirmations = value["instant_confirmations"]
    early_retries = value["early_confirmation_retries"]
    outcome_flags_valid = {
        "invalid-counter-frequency": (
            frequency is None
            and not counter_backed
            and counter_unavailable
            and not counter_nonmonotonic
        ),
        "counter-unavailable": (
            frequency is not None
            and not counter_backed
            and counter_unavailable
            and not counter_nonmonotonic
        ),
        "counter-nonmonotonic": (
            frequency is not None
            and counter_backed
            and not counter_unavailable
            and counter_nonmonotonic
        ),
        "counter-frequency-changed": (
            frequency is not None
            and counter_backed
            and not counter_unavailable
            and not counter_nonmonotonic
        ),
        "counter-target-error": (
            frequency is not None
            and counter_backed
            and not counter_unavailable
            and not counter_nonmonotonic
        ),
    }[outcome]
    if (
        not outcome_flags_valid
        or value["active_wait_poll_source"]
        != metrics["buflo_exact_release_active_wait_poll_source"]
        or value["active_wait_poll_source"] != "linux-aarch64-cntvct-el0-predictive-v1"
        or metrics[outcome_counter] != 1
        or counter_backed == counter_unavailable
        or counter_backed
        and metrics["buflo_exact_release_active_wait_counter_guards"] == 0
        or counter_unavailable
        and metrics["buflo_exact_release_active_wait_counter_unavailable_guards"] == 0
        or counter_nonmonotonic
        is not (metrics["buflo_exact_release_active_wait_counter_nonmonotonic_guards"] > 0)
        or early_retries > confirmations
        or confirmations > calibrations
        or (counter_nanoseconds or 0)
        > metrics["buflo_exact_release_active_wait_counter_nanoseconds"]
        or (max_counter_gap or 0)
        > metrics["buflo_exact_release_max_active_wait_counter_gap_nanoseconds"]
        or (max_calibration_span or 0)
        > metrics["buflo_exact_release_max_counter_calibration_span_nanoseconds"]
        or (max_counter_gap or 0) > (counter_nanoseconds or 0)
        or (max_calibration_span or 0) > (counter_nanoseconds or 0)
        or (max_calibration_span or 0) > (max_counter_gap or 0)
        or (
            calibrations == 0
            and any((counter_nanoseconds or 0, max_counter_gap or 0, max_calibration_span or 0))
        )
        or outcome == "counter-target-error"
        and calibrations == 0
        or calibrations > metrics["buflo_exact_release_active_wait_counter_calibrations"]
        or confirmations > metrics["buflo_exact_release_active_wait_instant_confirmations"]
        or early_retries > metrics["buflo_exact_release_active_wait_early_confirmation_retries"]
    ):
        return False
    if outcome == "counter-frequency-changed" and not (
        calibrations == confirmations == early_retries + 1
    ):
        return False
    if outcome == "counter-frequency-changed" and value["exit_before_release_nanoseconds"] != 0:
        return False
    if outcome == "counter-target-error" and not (
        calibrations == confirmations + 1 == early_retries + 1
    ):
        return False
    if outcome in {"counter-unavailable", "counter-nonmonotonic"} and not (
        confirmations == early_retries and calibrations in {confirmations, confirmations + 1}
    ):
        return False
    if outcome == "invalid-counter-frequency" and any((calibrations, confirmations, early_retries)):
        return False
    if (
        outcome == "invalid-counter-frequency"
        and metrics["buflo_exact_release_dispatch_ready_guards"] == 0
        and metrics["buflo_exact_release_active_wait_iterations"] != 0
    ):
        return False
    established_frequency = metrics["buflo_exact_release_active_wait_counter_frequency_hz"]
    if outcome == "counter-frequency-changed":
        if (
            established_frequency is None
            or established_frequency == frequency
            or metrics["buflo_exact_release_dispatch_ready_guards"] == 0
            or metrics["buflo_exact_release_worst_guard"] is None
        ):
            return False
    elif (
        frequency is not None
        and established_frequency != frequency
        and outcome not in {"counter-unavailable", "counter-nonmonotonic", "counter-target-error"}
    ):
        return False

    if all(item is not None for item in times):
        guard = value["guard_at_defense_nanoseconds"]
        entered = value["entered_at_defense_nanoseconds"]
        active_at = value["active_wait_at_defense_nanoseconds"]
        active_started = value["active_wait_started_at_defense_nanoseconds"]
        release = value["release_at_defense_nanoseconds"]
        deadline = value["deadline_at_defense_nanoseconds"]
        exited = value["exited_at_defense_nanoseconds"]
        nominal_release = value["packet_timestamp_us"] * 1_000
        release_skew = release - nominal_release
        deadline_skew = nominal_release + 5_000_000 - deadline
        normalization_skew = release_skew + deadline_skew
        actual_window = deadline - release
        if (
            not 0 <= release_skew <= 999
            or not 0 <= deadline_skew <= 999
            or normalization_skew not in {0, 1_000}
            or actual_window != 5_000_000 - normalization_skew
            or actual_window not in {4_999_000, 5_000_000}
            or active_at != guard
            or release - guard != actual_window
            or not guard <= entered == active_started <= exited
            or value["guard_entry_lateness_nanoseconds"] != entered - guard
            or entered - guard > metrics["buflo_exact_release_max_guard_entry_lateness_nanoseconds"]
            or active_started - active_at
            > metrics["buflo_exact_release_max_passive_wake_lateness_nanoseconds"]
            or exited - active_started > metrics["buflo_exact_release_active_wait_nanoseconds"]
            or exited - entered > metrics["buflo_exact_release_guard_wait_nanoseconds"]
            or value["exit_before_release_nanoseconds"] != max(release - exited, 0)
            or value["exit_at_or_after_deadline"] is not (exited >= deadline)
            or (outcome == "counter-frequency-changed" and exited < release)
        ):
            return False
    return True


def _runner_wakeup_v9_worst_guard_valid(
    value: Any,
    *,
    metrics: Mapping[str, Any],
) -> bool:
    """Validate schema-nine predictive-clock evidence for the worst guard."""

    dispatch_ready = metrics["buflo_exact_release_dispatch_ready_guards"]
    if dispatch_ready == 0:
        return value is None
    if not isinstance(value, Mapping) or set(value) != RUNNER_WAKEUP_V9_WORST_KEYS:
        return False
    if (
        any(
            type(value.get(key)) is not int or value[key] < 0
            for key in (
                RUNNER_WAKEUP_V7_WORST_INTEGER_KEYS | RUNNER_WAKEUP_V9_WORST_COUNTER_INTEGER_KEYS
            )
        )
        or value.get("phase") not in {"prearmed", "committed"}
        or type(value.get("dispatch_at_or_after_deadline")) is not bool
        or value.get("active_wait_poll_source") not in RUNNER_WAKEUP_V9_POLL_SOURCES
    ):
        return False
    times = [value[key] for key in RUNNER_WAKEUP_V7_WORST_TIME_KEYS]
    if not (
        all(item is None for item in times)
        or all(type(item) is int and item >= 0 for item in times)
    ):
        return False
    for key in RUNNER_WAKEUP_V9_WORST_COUNTER_NULLABLE_KEYS:
        if value[key] is not None and (type(value[key]) is not int or value[key] < 0):
            return False
    counter_frequency_value = value["active_wait_counter_frequency_hz"]
    if counter_frequency_value is not None and not (
        1_000_000 <= counter_frequency_value <= 2**32 - 1
    ):
        return False

    dispatch_lateness = value["dispatch_lateness_nanoseconds"]
    at_or_after_deadline = value["dispatch_at_or_after_deadline"]
    dispatch_after_deadline = value["dispatch_after_deadline_nanoseconds"]
    outside_count = metrics["buflo_exact_release_dispatch_at_or_after_deadline_guards"]
    active_wait = value["active_wait_monotonic_nanoseconds"]
    spin_interruptions = value["active_spin_interruptions"]
    spin_interruption_nanoseconds = value["active_spin_interruption_nanoseconds"]
    max_spin_gap = value["max_active_spin_gap_nanoseconds"]
    source = value["active_wait_poll_source"]
    counter_frequency = value["active_wait_counter_frequency_hz"]
    counter_calibrations = value["active_wait_counter_calibrations"]
    instant_confirmations = value["active_wait_instant_confirmations"]
    early_retries = value["active_wait_early_confirmation_retries"]
    counter_nanoseconds = value["active_wait_counter_nanoseconds"]
    max_counter_gap = value["max_active_wait_counter_gap_nanoseconds"]
    max_calibration_span = value["max_counter_calibration_span_nanoseconds"]

    if (
        source != metrics["buflo_exact_release_active_wait_poll_source"]
        or counter_frequency != metrics["buflo_exact_release_active_wait_counter_frequency_hz"]
        or dispatch_lateness != metrics["buflo_exact_release_max_guard_exit_lateness_nanoseconds"]
        or (outside_count == 0 and at_or_after_deadline)
        or (outside_count == dispatch_ready and not at_or_after_deadline)
        or (not at_or_after_deadline and dispatch_after_deadline != 0)
        or metrics["buflo_exact_release_dispatch_lateness_histogram"]["counts"][
            _runner_wakeup_v7_bucket(dispatch_lateness)
        ]
        == 0
        or value["guard_entry_lateness_nanoseconds"]
        > metrics["buflo_exact_release_max_guard_entry_lateness_nanoseconds"]
        or value["passive_sleep_calls"] > metrics["buflo_exact_release_passive_sleep_calls"]
        or value["passive_sleep_requested_nanoseconds"]
        > metrics["buflo_exact_release_passive_sleep_requested_nanoseconds"]
        or value["passive_sleep_elapsed_nanoseconds"]
        > metrics["buflo_exact_release_passive_sleep_elapsed_nanoseconds"]
        or value["max_passive_sleep_overrun_nanoseconds"]
        > metrics["buflo_exact_release_max_passive_sleep_overrun_nanoseconds"]
        or value["active_wait_iterations"] > metrics["buflo_exact_release_active_wait_iterations"]
        or active_wait > metrics["buflo_exact_release_active_wait_nanoseconds"]
        or spin_interruptions > metrics["buflo_exact_release_active_spin_interruptions"]
        or spin_interruption_nanoseconds
        > metrics["buflo_exact_release_active_spin_interruption_nanoseconds"]
        or max_spin_gap > metrics["buflo_exact_release_max_active_spin_gap_nanoseconds"]
        or counter_calibrations > metrics["buflo_exact_release_active_wait_counter_calibrations"]
        or instant_confirmations > metrics["buflo_exact_release_active_wait_instant_confirmations"]
        or early_retries > metrics["buflo_exact_release_active_wait_early_confirmation_retries"]
        or (counter_nanoseconds or 0)
        > metrics["buflo_exact_release_active_wait_counter_nanoseconds"]
        or (max_counter_gap or 0)
        > metrics["buflo_exact_release_max_active_wait_counter_gap_nanoseconds"]
        or (max_calibration_span or 0)
        > metrics["buflo_exact_release_max_counter_calibration_span_nanoseconds"]
        or value["max_passive_sleep_overrun_nanoseconds"]
        > value["passive_sleep_elapsed_nanoseconds"]
        or spin_interruptions > value["active_wait_iterations"]
        or ((spin_interruptions > 0) != (max_spin_gap > 50_000))
        or ((spin_interruptions == 0) != (spin_interruption_nanoseconds == 0))
        or (spin_interruptions > 0 and spin_interruption_nanoseconds < max_spin_gap)
        or spin_interruption_nanoseconds > active_wait
        or max_spin_gap > active_wait
        or metrics["buflo_exact_release_active_spin_gap_histogram"]["counts"][
            _runner_wakeup_v7_bucket(max_spin_gap)
        ]
        == 0
        or early_retries > instant_confirmations
        or instant_confirmations > counter_calibrations
    ):
        return False
    if source == "linux-aarch64-cntvct-el0-predictive-v1":
        counter_tuple = (
            counter_frequency,
            counter_nanoseconds,
            max_counter_gap,
            max_calibration_span,
        )
        if (
            not all(item is not None for item in counter_tuple)
            or instant_confirmations != early_retries + 1
            or counter_calibrations != instant_confirmations
            or value["active_wait_iterations"] < 2 * counter_calibrations
            or max_spin_gap != max_counter_gap
            or max_calibration_span > max_counter_gap
        ):
            return False
    elif (
        counter_frequency is not None
        or counter_calibrations != 0
        or instant_confirmations != 0
        or early_retries != 0
        or counter_nanoseconds is not None
        or max_counter_gap is not None
        or max_calibration_span is not None
    ):
        return False

    if all(item is not None for item in times):
        guard = value["guard_at_defense_nanoseconds"]
        entered = value["entered_at_defense_nanoseconds"]
        active_at = value["active_wait_at_defense_nanoseconds"]
        active_started = value["active_wait_started_at_defense_nanoseconds"]
        release = value["release_at_defense_nanoseconds"]
        deadline = value["deadline_at_defense_nanoseconds"]
        dispatch = value["dispatch_at_defense_nanoseconds"]
        nominal_release = value["packet_timestamp_us"] * 1_000
        release_skew = release - nominal_release
        deadline_skew = nominal_release + 5_000_000 - deadline
        normalization_skew = release_skew + deadline_skew
        actual_window = deadline - release
        if (
            not 0 <= release_skew <= 999
            or not 0 <= deadline_skew <= 999
            or normalization_skew not in {0, 1_000}
            or actual_window != 5_000_000 - normalization_skew
            or actual_window not in {4_999_000, 5_000_000}
            or active_at != guard
            or release - guard != actual_window
            or not guard <= entered == active_started <= dispatch
            or release > dispatch
            or value["guard_entry_lateness_nanoseconds"] != entered - guard
            or active_wait != dispatch - active_started
            or active_started - active_at
            > metrics["buflo_exact_release_max_passive_wake_lateness_nanoseconds"]
            or dispatch_lateness != dispatch - release
            or at_or_after_deadline is not (dispatch >= deadline)
            or dispatch_after_deadline != max(dispatch - deadline, 0)
        ):
            return False
    else:
        possible_windows = (4_999_000, 5_000_000)
        if not any(
            at_or_after_deadline is (dispatch_lateness >= window)
            and dispatch_after_deadline == max(dispatch_lateness - window, 0)
            for window in possible_windows
        ):
            return False
    return True


def _runner_wakeup_v9_relative_chronology_available(value: Any) -> bool:
    """Require relative guard times when the enclosing run has a defence start."""

    if not isinstance(value, Mapping) or value.get("schema_version") != 9:
        return False
    for object_key, time_keys in (
        ("buflo_exact_release_worst_guard", RUNNER_WAKEUP_V7_WORST_TIME_KEYS),
        ("buflo_exact_release_last_failure", RUNNER_WAKEUP_V9_FAILURE_TIME_KEYS),
    ):
        item = value.get(object_key)
        if item is not None and (
            not isinstance(item, Mapping)
            or any(type(item.get(key)) is not int for key in time_keys)
        ):
            return False
    return True


def _runner_wakeup_v9_valid(value: Any) -> bool:
    """Validate the current predictive-clock, authoritative-Instant receipt."""

    base_integer_keys = {
        "wait_returns",
        "socket_readiness_wakeups",
        "timer_wakeups",
        "controller_deadline_timer_wakeups",
        "other_timer_wakeups",
        "buflo_exact_release_guard_entries",
        "buflo_exact_release_guard_wait_nanoseconds",
        "buflo_exact_release_active_wait_nanoseconds",
        "buflo_exact_release_max_passive_wake_lateness_nanoseconds",
        "buflo_exact_release_max_guard_exit_lateness_nanoseconds",
        "buflo_exact_incoming_retry_drives",
        "buflo_exact_incoming_retry_resolutions",
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
        "cs_exact_incoming_retry_drives",
        "cs_exact_incoming_retry_resolutions",
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
    }
    integer_keys = base_integer_keys | set(RUNNER_WAKEUP_V9_NEW_INTEGER_KEYS)
    required = integer_keys | set(RUNNER_WAKEUP_V9_OBJECT_KEYS) | {"schema_version", "semantics"}
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or value.get("schema_version") != 9
        or value.get("semantics") != RUNNER_WAKEUP_V9_SEMANTICS
        or any(type(value.get(key)) is not int or value[key] < 0 for key in integer_keys)
        or value.get("buflo_exact_release_active_wait_poll_source")
        not in RUNNER_WAKEUP_V9_POLL_SOURCES
    ):
        return False
    frequency = value["buflo_exact_release_active_wait_counter_frequency_hz"]
    if frequency is not None and (
        type(frequency) is not int or not 1_000_000 <= frequency <= 2**32 - 1
    ):
        return False
    entries = value["buflo_exact_release_guard_entries"]
    dispatch_ready = value["buflo_exact_release_dispatch_ready_guards"]
    failed = value["buflo_exact_release_failed_guards"]
    typed_failures = sum(value[key] for key in RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME.values())
    source = value["buflo_exact_release_active_wait_poll_source"]
    counter_guards = value["buflo_exact_release_active_wait_counter_guards"]
    unavailable_guards = value["buflo_exact_release_active_wait_counter_unavailable_guards"]
    nonmonotonic_guards = value["buflo_exact_release_active_wait_counter_nonmonotonic_guards"]
    calibrations = value["buflo_exact_release_active_wait_counter_calibrations"]
    confirmations = value["buflo_exact_release_active_wait_instant_confirmations"]
    early_retries = value["buflo_exact_release_active_wait_early_confirmation_retries"]
    counter_nanoseconds = value["buflo_exact_release_active_wait_counter_nanoseconds"]
    max_counter_gap = value["buflo_exact_release_max_active_wait_counter_gap_nanoseconds"]
    max_calibration_span = value["buflo_exact_release_max_counter_calibration_span_nanoseconds"]
    calibration_surplus = calibrations - confirmations
    minimum_calibration_surplus = value["buflo_exact_release_counter_target_error_guards"]
    maximum_calibration_surplus = (
        minimum_calibration_surplus
        + value["buflo_exact_release_counter_unavailable_failure_guards"]
        + value["buflo_exact_release_counter_nonmonotonic_failure_guards"]
    )
    if (
        not _runner_wakeup_v7_histogram_valid(
            value["buflo_exact_release_dispatch_lateness_histogram"], entries=dispatch_ready
        )
        or not _runner_wakeup_v7_histogram_valid(
            value["buflo_exact_release_active_spin_gap_histogram"], entries=entries
        )
        or not _runner_wakeup_v9_worst_guard_valid(
            value["buflo_exact_release_worst_guard"], metrics=value
        )
        or not _runner_wakeup_v9_last_failure_valid(
            value["buflo_exact_release_last_failure"], metrics=value
        )
        or value["buflo_exact_release_active_wait_nanoseconds"]
        > value["buflo_exact_release_guard_wait_nanoseconds"]
        or value["buflo_exact_release_active_wait_nanoseconds"]
        != value["buflo_exact_release_guard_wait_nanoseconds"]
        or value["buflo_exact_release_max_passive_wake_lateness_nanoseconds"]
        != value["buflo_exact_release_max_guard_entry_lateness_nanoseconds"]
        or any(
            value[key]
            for key in (
                "buflo_exact_release_passive_sleep_calls",
                "buflo_exact_release_passive_sleep_requested_nanoseconds",
                "buflo_exact_release_passive_sleep_elapsed_nanoseconds",
                "buflo_exact_release_max_passive_sleep_overrun_nanoseconds",
            )
        )
        or entries != dispatch_ready + failed
        or failed != typed_failures
        or failed > 1
        or counter_guards + unavailable_guards != entries
        or nonmonotonic_guards > counter_guards
        or early_retries > confirmations
        or confirmations > calibrations
        or not minimum_calibration_surplus <= calibration_surplus <= maximum_calibration_surplus
        or confirmations
        != counter_guards
        - value["buflo_exact_release_counter_nonmonotonic_failure_guards"]
        - value["buflo_exact_release_counter_target_error_guards"]
        + early_retries
        or max_counter_gap > counter_nanoseconds
        or max_calibration_span > counter_nanoseconds
        or (calibrations == 0 and any((counter_nanoseconds, max_counter_gap, max_calibration_span)))
        or value["buflo_exact_release_dispatch_at_or_after_deadline_guards"] > dispatch_ready
        or value["buflo_exact_release_max_passive_sleep_overrun_nanoseconds"]
        > value["buflo_exact_release_passive_sleep_elapsed_nanoseconds"]
        or value["buflo_exact_release_max_active_spin_gap_nanoseconds"]
        > value["buflo_exact_release_active_wait_nanoseconds"]
        or value["buflo_exact_release_active_spin_interruptions"]
        > value["buflo_exact_release_active_wait_iterations"]
        or (
            (value["buflo_exact_release_active_spin_interruptions"] == 0)
            != (value["buflo_exact_release_active_spin_interruption_nanoseconds"] == 0)
        )
        or (
            (value["buflo_exact_release_active_spin_interruptions"] > 0)
            != (value["buflo_exact_release_max_active_spin_gap_nanoseconds"] > 50_000)
        )
        or (
            value["buflo_exact_release_active_spin_interruptions"] > 0
            and value["buflo_exact_release_active_spin_interruption_nanoseconds"]
            < value["buflo_exact_release_max_active_spin_gap_nanoseconds"]
        )
        or value["buflo_exact_release_active_spin_interruption_nanoseconds"]
        > value["buflo_exact_release_active_wait_nanoseconds"]
        or (
            entries > 0
            and value["buflo_exact_release_active_spin_gap_histogram"]["counts"][
                _runner_wakeup_v7_bucket(
                    value["buflo_exact_release_max_active_spin_gap_nanoseconds"]
                )
            ]
            == 0
        )
    ):
        return False
    timing_scalars = {
        "buflo_exact_release_guard_wait_nanoseconds",
        "buflo_exact_release_active_wait_nanoseconds",
        "buflo_exact_release_max_passive_wake_lateness_nanoseconds",
        "buflo_exact_release_max_guard_exit_lateness_nanoseconds",
        *RUNNER_WAKEUP_V9_NEW_INTEGER_KEYS,
    }
    if entries == 0 and (any(value[key] for key in timing_scalars) or frequency is not None):
        return False
    if dispatch_ready == 0 and (
        value["buflo_exact_release_max_guard_exit_lateness_nanoseconds"] != 0
        or value["buflo_exact_release_dispatch_at_or_after_deadline_guards"] != 0
    ):
        return False
    if source == "linux-aarch64-cntvct-el0-predictive-v1":
        last_failure = value["buflo_exact_release_last_failure"]
        failure_calibrations = (
            last_failure["counter_calibrations"] if isinstance(last_failure, Mapping) else 0
        )
        required_counter_reads = (
            2 * calibrations
            + value["buflo_exact_release_counter_unavailable_failure_guards"]
            + (2 if failure_calibrations == 0 else 1)
            * value["buflo_exact_release_counter_nonmonotonic_failure_guards"]
        )
        if (
            counter_guards
            != dispatch_ready
            + value["buflo_exact_release_counter_nonmonotonic_failure_guards"]
            + value["buflo_exact_release_counter_frequency_changed_guards"]
            + value["buflo_exact_release_counter_target_error_guards"]
            or unavailable_guards
            != value["buflo_exact_release_invalid_counter_frequency_guards"]
            + value["buflo_exact_release_counter_unavailable_failure_guards"]
            or nonmonotonic_guards
            != value["buflo_exact_release_counter_nonmonotonic_failure_guards"]
            or value["buflo_exact_release_active_wait_iterations"] < required_counter_reads
            or value["buflo_exact_release_max_active_spin_gap_nanoseconds"] != max_counter_gap
            or max_calibration_span > max_counter_gap
        ):
            return False
        if counter_guards > 0 and (type(frequency) is not int or frequency <= 0):
            return False
        if frequency is None and any(
            (
                counter_guards,
                calibrations,
                confirmations,
                early_retries,
                counter_nanoseconds,
                max_counter_gap,
                max_calibration_span,
            )
        ):
            return False
    elif (
        frequency is not None
        or counter_guards != 0
        or unavailable_guards != entries
        or nonmonotonic_guards != 0
        or calibrations != 0
        or confirmations != 0
        or early_retries != 0
        or counter_nanoseconds != 0
        or max_counter_gap != 0
        or max_calibration_span != 0
    ):
        return False
    return (
        value["wait_returns"] == value["socket_readiness_wakeups"] + value["timer_wakeups"]
        and value["timer_wakeups"]
        == value["controller_deadline_timer_wakeups"] + value["other_timer_wakeups"]
        and value["cs_exact_incoming_retry_resolutions"] <= value["cs_exact_incoming_retry_drives"]
        and (
            value["cs_exact_incoming_retry_drives"] != 0
            or value["cs_exact_incoming_retry_max_phase_lateness_nanoseconds"] == 0
        )
        and value["buflo_exact_incoming_retry_resolutions"]
        <= value["buflo_exact_incoming_retry_drives"]
    )


def _runner_wakeup_v7_valid(value: Any) -> bool:
    """Validate historical schema-seven exact-release timing evidence."""

    return _runner_wakeup_fine_timing_valid(
        value,
        schema_version=7,
        semantics=RUNNER_WAKEUP_V7_SEMANTICS,
    )


def _runner_wakeup_v8_valid(value: Any) -> bool:
    """Validate historical barrier-free exact-release timing evidence."""

    return _runner_wakeup_fine_timing_valid(
        value,
        schema_version=8,
        semantics=RUNNER_WAKEUP_V8_SEMANTICS,
    )


def _runner_wakeup_metrics_valid(value: Any) -> bool:
    base_required = {
        "schema_version",
        "semantics",
        "wait_returns",
        "socket_readiness_wakeups",
        "timer_wakeups",
        "controller_deadline_timer_wakeups",
        "other_timer_wakeups",
    }
    if not isinstance(value, Mapping):
        return False
    schema_version = value.get("schema_version")
    if type(schema_version) is not int:
        return False
    if schema_version == 9:
        return _runner_wakeup_v9_valid(value)
    if schema_version == 8:
        return _runner_wakeup_v8_valid(value)
    if schema_version == 7:
        return _runner_wakeup_v7_valid(value)
    if schema_version == 1:
        required = base_required
        semantics = RUNNER_WAKEUP_SEMANTICS
    elif schema_version in {2, 3, 4, 5, 6}:
        required = base_required | {
            "buflo_exact_release_guard_entries",
            "buflo_exact_release_guard_wait_nanoseconds",
            "buflo_exact_release_active_wait_nanoseconds",
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds",
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds",
        }
        if schema_version in {4, 5, 6}:
            required |= {
                "cs_exact_incoming_retry_drives",
                "cs_exact_incoming_retry_resolutions",
                "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
            }
        if schema_version in {5, 6}:
            required |= {
                "buflo_exact_incoming_retry_drives",
                "buflo_exact_incoming_retry_resolutions",
                "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
            }
        semantics = {
            2: RUNNER_WAKEUP_V2_SEMANTICS,
            3: RUNNER_WAKEUP_V3_SEMANTICS,
            4: RUNNER_WAKEUP_V4_SEMANTICS,
            5: RUNNER_WAKEUP_V5_SEMANTICS,
            6: RUNNER_WAKEUP_V6_SEMANTICS,
        }[schema_version]
    else:
        return False
    if set(value) != required or value.get("semantics") != semantics:
        return False
    counters = tuple(required - {"schema_version", "semantics"})
    if any(type(value.get(key)) is not int or value[key] < 0 for key in counters):
        return False
    if schema_version in {2, 3, 4, 5, 6}:
        guard_measurements = (
            value["buflo_exact_release_guard_wait_nanoseconds"],
            value["buflo_exact_release_active_wait_nanoseconds"],
            value["buflo_exact_release_max_passive_wake_lateness_nanoseconds"],
            value["buflo_exact_release_max_guard_exit_lateness_nanoseconds"],
        )
        if value["buflo_exact_release_active_wait_nanoseconds"] > value[
            "buflo_exact_release_guard_wait_nanoseconds"
        ] or (value["buflo_exact_release_guard_entries"] == 0 and any(guard_measurements)):
            return False
    if schema_version in {4, 5, 6} and (
        value["cs_exact_incoming_retry_resolutions"] > value["cs_exact_incoming_retry_drives"]
        or (
            value["cs_exact_incoming_retry_drives"] == 0
            and value["cs_exact_incoming_retry_max_phase_lateness_nanoseconds"] != 0
        )
    ):
        return False
    if (
        schema_version in {5, 6}
        and value["buflo_exact_incoming_retry_resolutions"]
        > value["buflo_exact_incoming_retry_drives"]
    ):
        return False
    return (
        value["wait_returns"] == value["socket_readiness_wakeups"] + value["timer_wakeups"]
        and value["timer_wakeups"]
        == value["controller_deadline_timer_wakeups"] + value["other_timer_wakeups"]
    )


def fidelity_eligible(
    defense: str,
    diagnostics: dict[str, Any],
    *,
    sample_eligible: bool,
    missed_events: Any = None,
    outgoing_size_mismatches: Any = None,
    schedule_metrics: Mapping[str, Any] | None = None,
) -> bool:
    defense = _canonical_fidelity_defense(defense)
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
    if defense == "buflo":
        zero_keys = (
            "buflo_partial_outgoing_cells",
            "buflo_suppressed_outgoing_cells",
            "buflo_missed_outgoing_cells",
            "buflo_missed_incoming_cells",
            "buflo_outgoing_unresolved_cells",
            "buflo_incoming_unresolved_cells",
            "buflo_catch_up_outgoing_cells",
            "buflo_catch_up_incoming_cells",
        )
        return (
            all(diagnostics[key] == 0 for key in zero_keys)
            and diagnostics["buflo_paper_equivalent"] is False
            and diagnostics["buflo_client_only"] is True
            and diagnostics["buflo_egress_backlog_pending"] is False
            and diagnostics["buflo_application_complete"] is True
            and diagnostics["buflo_minimum_duration_reached"] is True
            and diagnostics["buflo_event_guard_triggered"] is False
            and buflo_terminal_diagnostics_valid(diagnostics)
            and diagnostics["buflo_scheduled_outgoing_cells"]
            == diagnostics["buflo_full_outgoing_cells"]
            and isinstance(schedule_metrics, Mapping)
            and diagnostics["buflo_scheduled_outgoing_cells"]
            == schedule_metrics.get("scheduled_outgoing_events")
            and diagnostics["buflo_scheduled_incoming_cells"]
            == schedule_metrics.get("scheduled_incoming_events")
            and diagnostics["buflo_scheduled_incoming_cells"]
            == schedule_metrics.get("incoming_credit_advertised_events")
            and diagnostics["buflo_scheduled_incoming_cells"]
            == schedule_metrics.get("incoming_credit_consumed_events")
            and schedule_metrics.get(
                "incoming_credit_advertisement_delay_us_max",
                BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US,
            )
            < BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US
            and diagnostics["scheduled_incoming_requested_bytes"]
            == diagnostics["buflo_scheduled_incoming_cells"] * 1_200
            and diagnostics.get("scheduled_incoming_advertised_bytes")
            == diagnostics["scheduled_incoming_requested_bytes"]
            and _new_schedule_terminal_contract(schedule_metrics, congestion_sensitive=False)
            and _buflo_schedule_matches_canonical_parameters(schedule_metrics)
        )
    if defense == "cs-buflo":
        return _cs_buflo_fidelity_eligible(diagnostics, schedule_metrics)
    return True


def _canonical_fidelity_defense(defense: str) -> str:
    if defense in {"cs-buflo-ctsp", "cs-buflo-cpsp"}:
        return "cs-buflo"
    return defense


def _new_schedule_terminal_contract(
    schedule: Mapping[str, Any] | None, *, congestion_sensitive: bool
) -> bool:
    if not isinstance(schedule, Mapping):
        return False
    common = (
        schedule.get("terminal_slots_unique") is True
        and schedule.get("duplicate_terminal_slots") == 0
        and schedule.get("invalid_terminal_rows") == 0
        and schedule.get("typed_congestion_reason_column") is True
        and schedule.get("typed_credit_advertisement_columns") is True
        and schedule.get("typed_credit_consumption_columns") is True
        and schedule.get("typed_controller_terminal_time_column") is True
        and len(schedule.get("terminal_defense_elapsed_us_values", ()))
        == schedule.get("scheduled_events")
        and schedule.get("invalid_typed_outcome_rows") == 0
        and schedule.get("incoming_credit_missing_events") == 0
        and schedule.get("incoming_credit_consumption_missing_events") == 0
        and schedule.get("invalid_credit_advertisement_events") == 0
        and schedule.get("invalid_credit_consumption_events") == 0
    )
    if not common:
        return False
    if not congestion_sensitive:
        return True
    return schedule.get("invalid_congestion_reason_events") == 0


def _buflo_schedule_matches_canonical_parameters(schedule: Mapping[str, Any]) -> bool:
    targets = schedule.get("target_times_us_by_direction")
    sizes = schedule.get("scheduled_sizes_by_direction")
    terminal = schedule.get("terminal_satisfactions")
    if not isinstance(targets, Mapping) or not isinstance(sizes, Mapping):
        return False
    total = 0
    for direction in ("outgoing", "incoming"):
        directional_targets = targets.get(direction)
        directional_sizes = sizes.get(direction)
        ordered_targets = (
            sorted(directional_targets) if isinstance(directional_targets, list) else []
        )
        if (
            not isinstance(directional_targets, list)
            or not isinstance(directional_sizes, list)
            or not directional_targets
            or len(directional_targets) != len(directional_sizes)
            or len(directional_targets) > 6_000
            # Incoming opportunities are serialized when their advertised
            # credit is consumed, not when the target was scheduled.  Under a
            # bottleneck, independently outstanding credits can therefore
            # reach terminal state out of target order.  Canonical cadence is
            # a property of the complete target set, not terminal CSV order.
            or ordered_targets[0] != 0
            or 10_000_000 not in ordered_targets
            or any(size != 1_200 for size in directional_sizes)
            or any(
                current - previous != 20_000
                for previous, current in zip(ordered_targets[:-1], ordered_targets[1:], strict=True)
            )
        ):
            return False
        total += len(directional_targets)
    return total <= 12_000 and terminal == {"satisfied": total}


def _cs_buflo_fidelity_eligible(
    diagnostics: Mapping[str, Any], schedule: Mapping[str, Any] | None
) -> bool:
    if not _new_schedule_terminal_contract(schedule, congestion_sensitive=True):
        return False
    assert schedule is not None
    stop_drain_current = CS_BUFLO_STOP_DRAIN_V4_KEYS.issubset(diagnostics)
    expected_early_termination_semantics = (
        CS_BUFLO_EARLY_TERMINATION_SEMANTICS
        if stop_drain_current
        else CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS
    )
    if (
        diagnostics["cs_buflo_paper_equivalent"] is not False
        or diagnostics["cs_buflo_client_only"] is not True
        or diagnostics["cs_buflo_payload_padding"] == diagnostics["cs_buflo_total_padding"]
        or diagnostics["cs_buflo_early_termination_semantics"]
        != expected_early_termination_semantics
        or diagnostics["cs_buflo_rate_boundary_translation_version"]
        != CS_BUFLO_RATE_BOUNDARY_TRANSLATION_VERSION
        or diagnostics["cs_buflo_rate_boundary_counter_semantics"]
        != CS_BUFLO_RATE_BOUNDARY_COUNTER_SEMANTICS
        or diagnostics["cs_buflo_author_rate_boundary_counter_semantics"]
        != CS_BUFLO_AUTHOR_RATE_BOUNDARY_COUNTER_SEMANTICS
        or diagnostics["cs_buflo_reference_tcp_write_size_bytes"] != 548
        or diagnostics["cs_buflo_reference_nominal_tcp_packet_size_bytes"] != 600
        or diagnostics["cs_buflo_runtime_udp_packet_size_bytes"] != 600
        or diagnostics["cs_buflo_egress_backlog_pending"] is not False
        or diagnostics["cs_buflo_application_complete"] is not True
        or diagnostics["cs_buflo_quiet_time_reached"] is not True
        or diagnostics["cs_buflo_local_termination_latched"] is not True
        or diagnostics["cs_buflo_event_guard_triggered"] is not False
        or not cs_buflo_local_et_handoff_valid(diagnostics)
    ):
        return False
    zero_keys = (
        "cs_buflo_missed_outgoing_cells",
        "cs_buflo_missed_incoming_cells",
        "cs_buflo_outgoing_unresolved_cells",
        "cs_buflo_incoming_unresolved_cells",
    )
    if any(diagnostics[key] != 0 for key in zero_keys):
        return False
    for direction in ("outgoing", "incoming"):
        opportunities = diagnostics[f"cs_buflo_{direction}_minimum_interval_opportunities"]
        terminal_at_minimum = diagnostics[f"cs_buflo_{direction}_minimum_interval_terminal"]
        full_at_minimum = diagnostics[f"cs_buflo_{direction}_minimum_interval_full"]
        if opportunities != terminal_at_minimum or full_at_minimum > terminal_at_minimum:
            return False
        if direction == "incoming" and not (
            opportunities
            == diagnostics["cs_buflo_incoming_minimum_interval_local_realized"]
            == terminal_at_minimum
            == full_at_minimum
        ):
            return False
    terminal = schedule.get("terminal_satisfactions")
    if not isinstance(terminal, Mapping):
        return False
    if (
        diagnostics["cs_buflo_scheduled_outgoing_cells"]
        != diagnostics["cs_buflo_full_outgoing_cells"]
        + diagnostics["cs_buflo_partial_outgoing_cells"]
        + diagnostics["cs_buflo_suppressed_outgoing_cells"]
        or diagnostics["cs_buflo_full_outgoing_cells"] != terminal.get("full", 0)
        or diagnostics["cs_buflo_partial_outgoing_cells"] != terminal.get("partial", 0)
        or diagnostics["cs_buflo_suppressed_outgoing_cells"] != terminal.get("suppressed", 0)
        or diagnostics["cs_buflo_scheduled_outgoing_cells"]
        != schedule.get("scheduled_outgoing_events")
        or diagnostics["cs_buflo_scheduled_incoming_cells"]
        != schedule.get("scheduled_incoming_events")
        or diagnostics["cs_buflo_scheduled_incoming_cells"] != terminal.get("satisfied", 0)
        or diagnostics["cs_buflo_incoming_local_realized_cells"]
        != diagnostics["cs_buflo_scheduled_incoming_cells"]
        or diagnostics["cs_buflo_desired_udp_bytes"]
        != schedule.get("terminal_desired_outgoing_bytes")
        or diagnostics["cs_buflo_realized_udp_bytes"]
        != schedule.get("terminal_observed_outgoing_bytes")
        or diagnostics["cs_buflo_real_bearing_outgoing_bytes"]
        != schedule.get("typed_real_bearing_outgoing_bytes")
        or diagnostics["cs_buflo_real_bearing_incoming_bytes"]
        != diagnostics["cs_buflo_incoming_padding_basis_natural_bytes"]
        or diagnostics["scheduled_incoming_requested_bytes"]
        != diagnostics["cs_buflo_scheduled_incoming_cells"] * 600
        or diagnostics.get("scheduled_incoming_advertised_bytes")
        != diagnostics["scheduled_incoming_requested_bytes"]
        or diagnostics["cs_buflo_realized_incoming_credit_bytes"]
        != diagnostics["scheduled_incoming_consumed_bytes"]
        or diagnostics["cs_buflo_scheduled_incoming_cells"]
        != schedule.get("incoming_credit_advertised_events")
        or diagnostics["cs_buflo_scheduled_incoming_cells"]
        != schedule.get("incoming_credit_consumed_events")
    ):
        return False
    composition = sum(
        diagnostics[key]
        for key in (
            "cs_buflo_application_stream_bytes",
            "cs_buflo_retransmission_stream_bytes",
            "cs_buflo_chaff_stream_bytes",
            "cs_buflo_defense_control_bytes",
            "cs_buflo_quic_padding_bytes",
            "cs_buflo_other_quic_bytes",
        )
    )
    if (
        composition != diagnostics["cs_buflo_realized_udp_bytes"]
        or diagnostics["cs_buflo_desired_udp_bytes"] < diagnostics["cs_buflo_realized_udp_bytes"]
        or diagnostics["cs_buflo_lateness_us_max"] > diagnostics["cs_buflo_lateness_us_total"]
    ):
        return False
    typed_composition = schedule.get("typed_composition_bytes")
    if not isinstance(typed_composition, Mapping) or any(
        typed_composition.get(key) != diagnostics[f"cs_buflo_{key}"]
        for key in (
            "application_stream_bytes",
            "retransmission_stream_bytes",
            "chaff_stream_bytes",
            "defense_control_bytes",
            "quic_padding_bytes",
            "other_quic_bytes",
        )
    ):
        return False
    if (
        schedule.get("typed_lateness_us_total") != diagnostics["cs_buflo_lateness_us_total"]
        or schedule.get("typed_lateness_us_max") != diagnostics["cs_buflo_lateness_us_max"]
    ):
        return False
    if not _cs_buflo_padding_targets_match(diagnostics):
        return False
    transitions = diagnostics["cs_buflo_rate_transitions"]
    if not _cs_buflo_rate_transition_vector_valid(transitions):
        return False
    for direction in ("outgoing", "incoming"):
        interval = diagnostics[f"cs_buflo_{direction}_interval_us"]
        adaptations = diagnostics[f"cs_buflo_{direction}_rate_adaptations"]
        next_boundary = diagnostics[f"cs_buflo_next_{direction}_adaptation_boundary_bytes"]
        samples = diagnostics[f"cs_buflo_{direction}_estimator_samples"]
        real_bearing = diagnostics[f"cs_buflo_real_bearing_{direction}_bytes"]
        directional_transitions = [
            transition for transition in transitions if transition["direction"] == direction
        ]
        if (
            interval not in {4_096, 8_192, 16_384, 32_768}
            or samples > 1_000
            or next_boundary != 16_384 << adaptations
            or real_bearing >= next_boundary
            or (adaptations > 0 and real_bearing < (16_384 << (adaptations - 1)))
            or len(directional_transitions) != adaptations
            or (
                directional_transitions
                and directional_transitions[-1]["resulting_interval_us"] != interval
            )
            or (not directional_transitions and interval != 8_192)
            or any(
                transition["real_bearing_bytes"] > real_bearing
                for transition in directional_transitions
            )
        ):
            return False
    return True


def _ceiling_power_of_two(value: Any) -> int:
    if type(value) is not int or value <= 0:
        return 0
    maximum = (1 << 64) - 1
    if value > maximum:
        return 0
    candidate = 1 << ((value - 1).bit_length())
    return candidate if candidate <= maximum else maximum


def _cs_buflo_power_of_two_crossed(total: Any, increment: Any) -> bool:
    """Recompute the Algorithm-4 crossing from one realized UDP increment."""

    return (
        type(total) is int
        and type(increment) is int
        and 0 < increment <= total
        and (total - increment).bit_length() < total.bit_length()
    )


def _cs_buflo_payload_padding_target(natural: Any, cover: Any) -> int:
    """Recompute the pinned CPSP target from its frozen directional basis."""

    maximum = (1 << 64) - 1
    if (
        type(natural) is not int
        or type(cover) is not int
        or natural < 0
        or cover < 0
        or natural > maximum
        or cover > maximum
    ):
        return -1
    current = min(natural + cover, maximum)
    if current == 0:
        return 0
    quantum = _ceiling_power_of_two(max(natural, 1))
    if quantum <= 0:
        return -1
    return min(((current + quantum - 1) // quantum) * quantum, maximum)


def _cs_buflo_stop_drain_matches(diagnostics: Mapping[str, Any]) -> bool:
    """Validate version-4 asynchronous stop/drain evidence when present."""

    present = CS_BUFLO_STOP_DRAIN_V4_KEYS & set(diagnostics)
    if not present:
        return True
    if (
        present != CS_BUFLO_STOP_DRAIN_V4_KEYS
        or diagnostics["cs_buflo_early_termination_translation_version"]
        != CS_BUFLO_EARLY_TERMINATION_TRANSLATION_VERSION
        or diagnostics["cs_buflo_termination_stop_policy"] != CS_BUFLO_TERMINATION_STOP_POLICY
    ):
        return False

    for direction in ("outgoing", "incoming"):
        latched = diagnostics[f"cs_buflo_{direction}_termination_stop_latched"]
        crossing_total = diagnostics[f"cs_buflo_{direction}_termination_stop_crossing_total_bytes"]
        crossing_increment = diagnostics[
            f"cs_buflo_{direction}_termination_stop_crossing_increment_bytes"
        ]
        reason = diagnostics[f"cs_buflo_{direction}_termination_stop_reason"]
        phase = diagnostics[f"cs_buflo_{direction}_termination_stop_phase"]
        latched_at_us = diagnostics[f"cs_buflo_{direction}_termination_stop_latched_at_us"]
        scheduled_at_stop = diagnostics[
            f"cs_buflo_{direction}_termination_stop_scheduled_cells_at_stop"
        ]
        terminal_at_stop = diagnostics[
            f"cs_buflo_{direction}_termination_stop_terminal_cells_at_stop"
        ]
        progress_at_stop = diagnostics[
            f"cs_buflo_{direction}_termination_stop_progress_bytes_at_stop"
        ]
        target_at_stop = diagnostics[
            f"cs_buflo_{direction}_termination_stop_padding_target_bytes_at_stop"
        ]
        provisional_invalidations = diagnostics[
            f"cs_buflo_{direction}_termination_stop_provisional_invalidation_count"
        ]
        final_total = diagnostics[f"cs_buflo_{direction}_termination_accounted_bytes"]
        target = diagnostics[f"cs_buflo_{direction}_padding_target_bytes"]
        final_scheduled = diagnostics[f"cs_buflo_scheduled_{direction}_cells"]
        unresolved = diagnostics[f"cs_buflo_{direction}_unresolved_cells"]
        final_terminal = final_scheduled - unresolved
        no_crossing_evidence = crossing_total == 0 and crossing_increment == 0
        crossing_evidence = (
            type(crossing_total) is int
            and type(crossing_increment) is int
            and 0 < crossing_total <= final_total
            and crossing_total > crossing_increment
            and _cs_buflo_power_of_two_crossed(crossing_total, crossing_increment)
        )
        if (
            latched is not True
            or not isinstance(reason, str)
            or reason not in CS_BUFLO_TERMINATION_STOP_REASONS
            or not isinstance(phase, str)
            or phase not in CS_BUFLO_TERMINATION_STOP_PHASES
            or any(
                type(value) is not int or value < 0
                for value in (
                    latched_at_us,
                    scheduled_at_stop,
                    terminal_at_stop,
                    progress_at_stop,
                    target_at_stop,
                    provisional_invalidations,
                    final_scheduled,
                    unresolved,
                )
            )
            or latched_at_us > diagnostics["cs_buflo_local_et_latched_at_us"]
            or target_at_stop != target
            or scheduled_at_stop != final_scheduled
            or terminal_at_stop > scheduled_at_stop
            or final_terminal != final_scheduled
            or terminal_at_stop > final_terminal
            or not (no_crossing_evidence or crossing_evidence)
            or (
                direction == "incoming"
                and crossing_evidence
                and crossing_increment != diagnostics["cs_buflo_runtime_udp_packet_size_bytes"]
            )
            or (
                reason == "padding_target_reached"
                and (not no_crossing_evidence or progress_at_stop < target_at_stop)
            )
            or (reason == "power_of_two_crossing" and not crossing_evidence)
        ):
            return False
    return True


def _cs_buflo_padding_targets_match(diagnostics: Mapping[str, Any]) -> bool:
    """Validate frozen CTSP/CPSP bases without substituting terminal counters.

    Live cover, realized-byte, and (for pre-onLoad local termination) natural
    counters may continue increasing after the padding decision freezes.  The
    explicit basis counters remain the only sound target inputs; version-3
    post-local-ET natural counters reconcile later application passthrough
    without mutating that frozen basis or the rate estimator.
    """

    for direction in ("outgoing", "incoming"):
        frozen_natural = diagnostics[f"cs_buflo_{direction}_padding_basis_natural_bytes"]
        frozen_cover = diagnostics[f"cs_buflo_{direction}_padding_basis_cover_bytes"]
        post_natural = diagnostics.get(f"cs_buflo_post_local_et_natural_{direction}_bytes", 0)
        if (
            diagnostics[f"cs_buflo_natural_{direction}_bytes"] != frozen_natural + post_natural
            or diagnostics[f"cs_buflo_cover_{direction}_bytes"] < frozen_cover
        ):
            return False
    if (
        diagnostics["cs_buflo_outgoing_termination_accounted_bytes"]
        != diagnostics["cs_buflo_realized_udp_bytes"]
        or diagnostics["cs_buflo_incoming_termination_accounted_bytes"]
        != diagnostics["cs_buflo_realized_incoming_credit_bytes"]
        or diagnostics["cs_buflo_outgoing_power_of_two_crossed"]
        != _cs_buflo_power_of_two_crossed(
            diagnostics["cs_buflo_outgoing_termination_accounted_bytes"],
            diagnostics["cs_buflo_outgoing_last_termination_increment_bytes"],
        )
        or diagnostics["cs_buflo_incoming_power_of_two_crossed"]
        != _cs_buflo_power_of_two_crossed(
            diagnostics["cs_buflo_incoming_termination_accounted_bytes"],
            diagnostics["cs_buflo_incoming_last_termination_increment_bytes"],
        )
        or diagnostics["cs_buflo_realized_udp_bytes"]
        < diagnostics["cs_buflo_outgoing_padding_basis_total_bytes"]
        or diagnostics["cs_buflo_realized_incoming_credit_bytes"]
        < diagnostics["cs_buflo_incoming_padding_basis_total_bytes"]
    ):
        return False

    incoming_expected = _cs_buflo_payload_padding_target(
        diagnostics["cs_buflo_incoming_padding_basis_natural_bytes"],
        diagnostics["cs_buflo_incoming_padding_basis_cover_bytes"],
    )
    if diagnostics["cs_buflo_payload_padding"]:
        outgoing_expected = _cs_buflo_payload_padding_target(
            diagnostics["cs_buflo_outgoing_padding_basis_natural_bytes"],
            diagnostics["cs_buflo_outgoing_padding_basis_cover_bytes"],
        )
    else:
        outgoing_expected = _ceiling_power_of_two(
            diagnostics["cs_buflo_outgoing_padding_basis_total_bytes"]
        )
    targets_match = (
        outgoing_expected >= 0
        and incoming_expected >= 0
        and diagnostics["cs_buflo_outgoing_padding_target_bytes"] == outgoing_expected
        and diagnostics["cs_buflo_incoming_padding_target_bytes"] == incoming_expected
    )
    outgoing_progress = (
        diagnostics["cs_buflo_natural_outgoing_bytes"]
        + diagnostics["cs_buflo_cover_outgoing_bytes"]
        if diagnostics["cs_buflo_payload_padding"]
        else diagnostics["cs_buflo_realized_udp_bytes"]
    )
    incoming_progress = (
        diagnostics["cs_buflo_natural_incoming_bytes"]
        + diagnostics["cs_buflo_cover_incoming_bytes"]
    )
    return (
        targets_match
        and _cs_buflo_stop_drain_matches(diagnostics)
        and (
            outgoing_progress >= outgoing_expected
            or diagnostics["cs_buflo_outgoing_power_of_two_crossed"] is True
            or diagnostics.get("cs_buflo_outgoing_termination_stop_reason")
            == "power_of_two_crossing"
        )
        and (
            incoming_progress >= incoming_expected
            or diagnostics["cs_buflo_incoming_power_of_two_crossed"] is True
            or diagnostics.get("cs_buflo_incoming_termination_stop_reason")
            == "power_of_two_crossing"
        )
    )
