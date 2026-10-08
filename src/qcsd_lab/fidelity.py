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
from typing import Any, Iterable

from .capture import read_normalized_trace
from .defenses import DEFENSE_ADAPTATIONS
from .kernel_tx import (
    KERNEL_TX_HISTORICAL_RUNNER_SEMANTICS,
    KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS,
    KERNEL_TX_PROTECTED_SELECTION_WAIT_V2_SEMANTICS,
    KERNEL_TX_RESERVE_SELECTION_WAIT_SEMANTICS,
    KERNEL_TX_RESERVE_RUNNER_SCHEMA_VERSION,
    KERNEL_TX_CADENCE64_RUNNER_SCHEMA_VERSION,
    KERNEL_TX_CADENCE64_TX_SEMANTICS,
    KERNEL_TX_CADENCE64_SELECTION_WAIT_SEMANTICS,
    KERNEL_TX_RESERVE_TX_SEMANTICS,
    KERNEL_TX_RUNNER_V10_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_V10_SEMANTICS,
    KERNEL_TX_RUNNER_V8_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_V8_SEMANTICS,
    KERNEL_TX_RUNNER_V9_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_V9_SEMANTICS,
    KERNEL_TX_RUNNER_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_SEMANTICS,
    KERNEL_TX_RUNNER_V7_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_V7_SEMANTICS,
    KERNEL_TX_RUNNER_V6_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_V6_SEMANTICS,
    KERNEL_TX_RUNNER_V5_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_V5_SEMANTICS,
    KERNEL_TX_RUNNER_V3_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_V3_SEMANTICS,
    KERNEL_TX_RUNNER_V4_SCHEMA_VERSION,
    KERNEL_TX_RUNNER_V4_SEMANTICS,
    KERNEL_TX_RUNNER_V2_SEMANTICS,
    kernel_tx_runner_receipt_success_valid,
    kernel_tx_runner_receipt_valid,
    kernel_tx_incoming_window_bound_to_run_valid,
)
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
BUFLO_INCOMING_CREDIT_RELEASE_WINDOW_US = 5_000
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

TERMINAL_EVIDENCE_RENDER_ERROR_CLASS = "run-artifact-evidence-finalization-v1"


def terminal_evidence_render_receipt_valid(
    run: Mapping[str, Any],
    *,
    require_present: bool = False,
    require_empty: bool = False,
) -> bool:
    """Validate total run-artifact rendering without rejecting historical receipts."""

    if "terminal_evidence_render_errors" not in run:
        return not require_present
    errors = run.get("terminal_evidence_render_errors")
    if not isinstance(errors, list) or not all(
        isinstance(error, str) and bool(error) for error in errors
    ):
        return False
    if require_empty and errors:
        return False
    if not errors:
        return True
    return bool(
        run.get("completion_status") == "error"
        and run.get("error_class") == TERMINAL_EVIDENCE_RENDER_ERROR_CLASS
        and isinstance(run.get("error"), str)
        and bool(run["error"])
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


def _buflo_run_period_us(run: Mapping[str, Any]) -> int:
    """Select64 only after the exact Native/raw/policy tuple has authenticated."""
    from .capture_acceptance_policy import CADENCE64_ACK_START_POLICY, FIELD
    from .buflo_duration_budget import CADENCE64_POLICY, RUN_FIELD
    wakeups = run.get("runner_wakeup_metrics")
    raw = wakeups.get("buflo_kernel_tx") if isinstance(wakeups, Mapping) else None
    marker = run.get(FIELD)
    parameters = run.get("defense_parameters")
    receipt = parameters.get(RUN_FIELD) if isinstance(parameters, Mapping) else None
    prospective = (isinstance(wakeups, Mapping) and wakeups.get("schema_version") == 22
        or isinstance(raw, Mapping) and raw.get("schema_version") == 13
        or isinstance(marker, Mapping) and marker.get("policy") == CADENCE64_ACK_START_POLICY
        or isinstance(receipt, Mapping) and receipt.get("policy") == CADENCE64_POLICY)
    if not prospective:
        return 20_000
    if (not isinstance(wakeups, Mapping) or type(wakeups.get("schema_version")) is not int
        or wakeups["schema_version"] != 22
        or not kernel_tx_incoming_window_bound_to_run_valid(run)):
        raise ValueError("64ms terminal diagnostics lack their exact Native/raw/policy binding")
    return 64_000


def buflo_terminal_diagnostics_valid(
    diagnostics: Mapping[str, Any], *, require_current: bool = False,
    incoming_startup: Mapping[str, Any] | None = None,
    buflo_period_us: int = 20_000,
) -> bool:
    """Validate the version-inferred flat BuFLO terminal diagnostic contract."""

    if (type(buflo_period_us) is not int or buflo_period_us not in {20_000, 64_000}
        or buflo_period_us == 64_000 and incoming_startup is None):
        return False
    if incoming_startup is not None:
        from .capture_acceptance_policy import validate_buflo_startup_receipt
        try:
            validate_buflo_startup_receipt(incoming_startup, period_us=buflo_period_us)
            validate_buflo_startup_receipt(diagnostics.get("buflo_incoming_startup"), period_us=buflo_period_us)
        except ValueError:
            return False
        if diagnostics.get("buflo_incoming_startup") != incoming_startup:
            return False
    elif "buflo_incoming_startup" in diagnostics:
        return False

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
        and scheduled_incoming + (incoming_startup["startup_suppressed_opportunities"]
                                  if incoming_startup is not None else 0) == scheduled_outgoing
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
        "equal-sized datagrams can only be correlated by their aggregate size/direction "
        "sequence and incoming receive causality."
    ),
    (
        "The runner drains endpoint sockets serially, so aggregate ordering across "
        "connections is reconstructed from packet timestamps; near-simultaneous packets "
        "are validated only through exact size multiplicity. Incoming runner timestamps "
        "mark user-space socket drain, not wire ingress; the direct PCAP supplies wire timing."
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
    connection: int | None = None
    timestamp_unix_ns: int | None = None


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
        or not terminal_evidence_render_receipt_valid(run, require_empty=True)
    ):
        raise ValueError("runner did not complete before direct reconciliation")
    overheads = _endpoint_frame_overheads(run)
    runner_packets = _read_runner_packets(runner_packets_path, overheads)
    direct_packets = _read_direct_packets(direct_trace_path)
    boundaries = _endpoint_receive_boundaries(run, runner_packets, direct_packets)
    clock_adjustment_ns = _clock_adjustment_ns(clock_anchors)
    matches, unmatched_tail, residuals, clock_offset, clock_metrics = _reconcile_runner_packets(
        runner_packets,
        direct_packets,
        timestamp_tolerance_ns=timestamp_tolerance_ns,
        end_anchor_adjustment_ns=clock_adjustment_ns,
        endpoint_receive_boundaries=boundaries,
    )
    if boundaries is not None:
        if clock_anchors is None:
            raise ValueError("endpoint receive-tail reconciliation requires wrapper clock anchors")
        # This checks the same sealed host-clock contract as ordinary capture
        # acceptance. The tail predicate itself uses direct UNIX timestamps,
        # never the fitted outgoing clock offset or its 10 ms tolerance.
        validate_primary_capture_clock_integrity({
            "primary": True, "timestamp_type": "host",
            "capture_clock_anchors": clock_anchors,
            "direct_runner_reconciliation": {
                **clock_metrics, "direct_runner_reconciled": True,
                "evidence_eligible": True,
                "direct_timestamp_error_max_ns": max(map(abs, residuals), default=0),
                "direct_timestamp_tolerance_ns": timestamp_tolerance_ns,
            },
        }, require_pairing_uncertainty=True, require_timestamp_type=True)
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


def _endpoint_receive_boundaries(
    run: Mapping[str, Any], runner: list[_RunnerPacket], direct: list[_DirectPacket],
) -> dict[int, int] | None:
    """Open only prospective, complete native final-receive-drain receipts."""
    endpoints = run["endpoints"]
    identifiers = {_unsigned(endpoint["id"], "endpoint id") for endpoint in endpoints}
    if any(packet.connection is not None and packet.connection not in identifiers for packet in direct):
        raise ValueError("direct trace references unknown endpoint")
    if not any("receive_lifecycle" in endpoint for endpoint in endpoints):
        return None
    if any(packet.connection is None or packet.timestamp_unix_ns is None for packet in direct):
        raise ValueError("endpoint receive lifecycle requires endpoint-resolved UNIX capture rows")
    anchor, ended = run.get("time_anchor_unix_ns"), run.get("ended_unix_ns")
    if type(anchor) is not int or type(ended) is not int or not 0 < anchor <= ended:
        raise ValueError("endpoint receive lifecycle has invalid runner time bounds")
    latest: dict[int, int] = {}
    for packet in runner:
        latest[packet.connection] = max(latest.get(packet.connection, 0), packet.monotonic_us * 1000)
    boundaries = {}
    for endpoint in endpoints:
        identifier = _unsigned(endpoint["id"], "endpoint id")
        receipt = endpoint.get("receive_lifecycle")
        expected = {"schema_version", "source", "time_basis", "disposition", "scientific_credit",
                    "polling_stopped_at_elapsed_ns", "polling_stopped_at_unix_ns"}
        if not isinstance(receipt, Mapping) or set(receipt) != expected:
            raise ValueError("endpoint receive lifecycle fields differ")
        if (type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or receipt["source"] != "native-final-udp-receive-drain-v1"
            or receipt["time_basis"] != "runner-process-start-elapsed-monotonic-v1"
            or receipt["scientific_credit"] is not False):
            raise ValueError("endpoint receive lifecycle schema or source differs")
        elapsed, unix = receipt["polling_stopped_at_elapsed_ns"], receipt["polling_stopped_at_unix_ns"]
        if receipt["disposition"] in {"bounded_one_batch", "error", "not_polled"}:
            if elapsed is not None or unix is not None:
                raise ValueError("endpoint receive lifecycle exposes an unproven drain boundary")
            continue
        if receipt["disposition"] != "drained_to_would_block":
            raise ValueError("endpoint receive lifecycle has an unknown disposition")
        if (type(elapsed) is not int or elapsed < latest.get(identifier, 0)
            or type(unix) is not int or not anchor <= unix <= ended):
            raise ValueError("endpoint receive lifecycle boundary is stale or outside the run")
        boundaries[identifier] = unix
    # Exact modes may bound ordinary input to one batch. Such runs retain
    # strict global-tail reconciliation, never an invented local drain.
    return boundaries if len(boundaries) == len(endpoints) else None


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
    first_unix = None
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
        connection = timestamp_unix = None
        if "connection" in row:
            connection = _unsigned(row["connection"], "direct connection")
            timestamp_unix = _positive(row.get("timestamp_unix_ns"), "direct UNIX timestamp")
            if first_unix is None:
                first_unix = timestamp_unix
            if timestamp_unix - first_unix != relative_time:
                raise ValueError("direct UNIX and relative timestamps differ")
        packets.append(_DirectPacket(index, relative_time, direction, frame_length,
                                     connection, timestamp_unix))
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
        monotonic_us = _runner_csv_u64(
            row.get("monotonic_us"), label="runner packet time"
        )
        connection = _runner_csv_u64(
            row.get("connection"), label="runner connection"
        )
        if connection not in endpoint_overheads:
            raise ValueError(f"runner packet references unknown connection {connection}")
        direction = _direction(row.get("direction"), "runner packet trace")
        stream = (connection, direction)
        if monotonic_us < previous_time.get(stream, -1):
            raise ValueError(
                "runner packet timestamps are not monotonic within one connection and direction"
            )
        previous_time[stream] = monotonic_us
        udp_length = _runner_csv_u64(
            row.get("observed_udp_length"), label="runner UDP length"
        )
        if not 0 < udp_length <= 65_535:
            raise ValueError("runner UDP length exceeds the UDP domain")
        scheduled_target = row.get("scheduled_target")
        slot_id = row.get("slot_id")
        if scheduled_target:
            scheduled_size = _runner_csv_u64(
                scheduled_target, label="runner scheduled target"
            )
            if not 0 < scheduled_size <= 65_535:
                raise ValueError("runner scheduled target exceeds the UDP domain")
        if slot_id:
            _runner_csv_u64(slot_id, label="runner slot id")
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
    endpoint_receive_boundaries: Mapping[int, int] | None = None,
) -> tuple[dict[int, int], list[int], list[int], int, dict[str, Any]]:
    direct_by_signature: dict[tuple, deque[int]] = defaultdict(deque)
    runner_by_signature: dict[tuple, list[_RunnerPacket]] = defaultdict(list)
    with_connections = all(packet.connection is not None for packet in direct)
    for packet in direct:
        signature = (packet.direction, packet.frame_length)
        if with_connections:
            signature = (packet.connection, *signature)
        direct_by_signature[signature].append(packet.index)
    for packet in runner:
        signature = (packet.direction, packet.expected_frame_length)
        if with_connections:
            signature = (packet.connection, *signature)
        runner_by_signature[signature].append(packet)

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
    if endpoint_receive_boundaries is None and any(index <= last_matched for index in unmatched):
        raise ValueError(
            "direct trace contains an unmatched packet before the runner-correlated capture tail"
        )
    if any(direct[index].direction != "incoming" for index in unmatched):
        raise ValueError("direct trace contains an unrecorded outgoing tail packet")
    if endpoint_receive_boundaries is not None:
        final_match: dict[int, int] = {}
        for runner_index, direct_index in matches.items():
            connection = runner[runner_index].connection
            final_match[connection] = max(final_match.get(connection, -1), direct_index)
            if (runner[runner_index].direction == "incoming"
                and direct[direct_index].timestamp_unix_ns > endpoint_receive_boundaries[connection]):
                raise ValueError("matched incoming packet is after its endpoint final drain")
        for index in unmatched:
            packet = direct[index]
            if (packet.connection not in final_match or index <= final_match[packet.connection]
                or packet.timestamp_unix_ns < endpoint_receive_boundaries[packet.connection]):
                raise ValueError("direct trace contains an unlogged packet before its endpoint final drain")

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
    # Outgoing runner rows are recorded after socket handoff. Incoming rows
    # instead share the caller's time at a user-space socket drain, which can
    # follow PCAP ingress by many milliseconds under burst load. Fit the
    # capture/runner clock using outgoing packets, then check that every
    # matched incoming packet was on the wire before its user-space drain.
    clock_matches = [
        match for match in ordered_matches if match[0].direction == "outgoing"
    ]
    if not clock_matches:
        raise ValueError("direct/runner clock reconciliation has no outgoing packet")
    residuals, clock_offset, clock_metrics = _reconcile_clock_epochs(
        clock_matches,
        timestamp_tolerance_ns=timestamp_tolerance_ns,
        end_anchor_adjustment_ns=end_anchor_adjustment_ns,
    )
    incoming_lags: list[int] = []
    clock_steps = clock_metrics["direct_clock_steps"]
    current_offset = clock_offset
    step_index = 0
    for packet, _direct_index, observed_offset in ordered_matches:
        runner_time_ns = packet.monotonic_us * 1_000
        while (
            step_index < len(clock_steps)
            and runner_time_ns >= clock_steps[step_index]["runner_time_ns"]
        ):
            current_offset += clock_steps[step_index]["epoch_offset_delta_ns"]
            step_index += 1
        if packet.direction != "incoming":
            continue
        ingress_to_drain_ns = current_offset - observed_offset
        if ingress_to_drain_ns < -timestamp_tolerance_ns:
            raise ValueError(
                "direct/runner incoming packet appears after its user-space drain: "
                f"packet {packet.index}, {-ingress_to_drain_ns}ns exceeds "
                f"{timestamp_tolerance_ns}ns clock uncertainty"
            )
        incoming_lags.append(ingress_to_drain_ns)
    positive_lags = sorted(max(0, lag) for lag in incoming_lags)
    clock_metrics.update(
        {
            "direct_timestamp_basis": "outgoing-socket-handoff-vs-wire-v1",
            "direct_outgoing_clock_packets": len(clock_matches),
            "direct_incoming_causality_packets": len(incoming_lags),
            "direct_incoming_ingress_to_drain_lag_max_ns": max(
                positive_lags, default=0
            ),
            "direct_incoming_ingress_to_drain_lag_p95_ns": _percentile_95(positive_lags),
            "direct_incoming_causality_slack_max_ns": max(
                (max(0, -lag) for lag in incoming_lags), default=0
            ),
            "direct_tail_policy": ("native-final-udp-receive-drain-v1"
                                   if endpoint_receive_boundaries is not None else "global-last-match-v1"),
            "direct_endpoint_receive_tail_packets": (len(unmatched)
                                                     if endpoint_receive_boundaries is not None else 0),
        }
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

    def complete_unsigned(fields: tuple[str, ...]) -> bool:
        if not all(values[field] for field in fields):
            return False
        try:
            for field in fields:
                _runner_csv_u64(values[field], label=f"{label} {field}")
        except ValueError:
            return False
        return True

    advertisement_present = any(values[field] for field in advertisement_fields)
    consumption_present = any(values[field] for field in consumption_fields)
    advertisement_complete = complete_unsigned(advertisement_fields)
    consumption_complete = complete_unsigned(consumption_fields)
    if advertisement_present and not advertisement_complete:
        raise ValueError(f"{label} has incomplete receive-credit advertisement evidence")
    if consumption_present and not consumption_complete:
        raise ValueError(f"{label} has incomplete receive-credit consumption evidence")
    terminal_present = bool(values[terminal_field])
    terminal_complete = complete_unsigned((terminal_field,))
    if terminal_present != (schema == "3") or (terminal_present and not terminal_complete):
        raise ValueError(f"{label} has invalid controller terminal-time evidence")
    if terminal_present and row.get("target_time_us") not in {None, ""}:
        target = row["target_time_us"]
        try:
            terminal_at = _runner_csv_u64(
                values[terminal_field], label=f"{label} {terminal_field}"
            )
            target_at = _runner_csv_u64(target, label=f"{label} target_time_us")
        except ValueError as error:
            raise ValueError(f"{label} has invalid controller/target timing") from error
        if terminal_at < target_at:
            raise ValueError(f"{label} terminal time predates its defense target")
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
    try:
        desired_udp_bytes = _runner_csv_u64(
            values["desired_udp_bytes"], label=f"{label} desired_udp_bytes"
        )
    except ValueError as error:
        raise ValueError(f"{label} has invalid QCSD size evidence") from error
    if desired_udp_bytes <= 0:
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
    if observed_present:
        try:
            _runner_csv_u64(
                values["observed_udp_bytes"], label=f"{label} observed_udp_bytes"
            )
        except ValueError as error:
            raise ValueError(f"{label} has invalid QCSD size evidence") from error
    optional_numbers = (
        *LEGACY_SCHEDULE_QCSD_FIELDS[4:11],
        *advertisement_fields,
        *consumption_fields,
    )
    try:
        for field in optional_numbers:
            if values[field]:
                _runner_csv_u64(values[field], label=f"{label} {field}")
    except ValueError as error:
        raise ValueError(f"{label} has invalid QCSD composition evidence") from error
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
        try:
            action = _runner_csv_u64(action_time, label=f"{label} action_time_us")
        except ValueError as error:
            raise ValueError(f"{label} has invalid receive-credit action timing") from error
        advertised = _runner_csv_u64(
            values["credit_advertised_at_us"],
            label=f"{label} credit_advertised_at_us",
        )
        advertised_delay = _runner_csv_u64(
            values["credit_advertisement_delay_us"],
            label=f"{label} credit_advertisement_delay_us",
        )
        if advertised < action or advertised_delay != advertised - action:
            raise ValueError(f"{label} has invalid receive-credit advertisement timing")
        if consumption_present:
            consumed = _runner_csv_u64(
                values["credit_consumed_at_us"],
                label=f"{label} credit_consumed_at_us",
            )
            consumed_delay = _runner_csv_u64(
                values["credit_consumption_delay_us"],
                label=f"{label} credit_consumption_delay_us",
            )
            if consumed < advertised or consumed_delay != consumed - action:
                raise ValueError(f"{label} has invalid receive-credit consumption timing")
    if any(populated_components) and (
        not all(populated_components)
        or sum(
            _runner_csv_u64(values[key], label=f"{label} {key}") for key in components
        )
        != _runner_csv_u64(
            values["observed_udp_bytes"], label=f"{label} observed_udp_bytes"
        )
    ):
        raise ValueError(f"{label} has inconsistent QCSD byte composition")
    if values["congestion_reason"] not in {"", "congestion_limited", "pacing_limited"}:
        raise ValueError(f"{label} has an invalid QCSD congestion reason")
    if values["send_policy"] == "exact" and any(populated_components):
        try:
            _runner_csv_u64(values["lateness_us"], label=f"{label} lateness_us")
        except ValueError as error:
            raise ValueError(f"{label} has incomplete exact packet composition evidence") from error
        if schema not in {"2", "3"}:
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


def _schedule_realization_metrics(sample: Path, *, tamaraw_configuration_policy: str | None = None) -> dict[str, Any]:
    return _schedule_realization_metrics_from_path(sample / "neqo/schedule.csv", tamaraw_configuration_policy=tamaraw_configuration_policy)


def _schedule_realization_metrics_from_path(path: Path, *, tamaraw_configuration_policy: str | None = None) -> dict[str, Any]:
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
            slot = _csv_uint(row, "slot_id")
            action_time = _csv_uint(row, "action_time_us")
            target_time = _csv_uint(row, "target_time_us")
            if row.get("connection"):
                _csv_uint(row, "connection")
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
                requested = _csv_uint(row, "size")
                observed = _csv_uint(row, "observed_size")
            except (KeyError, TypeError, ValueError):
                outgoing_size_mismatches += 1
                continue
            if requested != observed:
                outgoing_size_mismatches += 1
                outgoing_size_error_bytes += abs(requested - observed)
        if direction == "outgoing" and satisfaction in {"full", "partial", "suppressed"}:
            try:
                terminal_desired_bytes += _csv_uint(row, "size")
                terminal_observed_bytes += (
                    _csv_uint(row, "observed_udp_bytes")
                    if satisfaction == "suppressed"
                    else _csv_uint(row, "observed_size")
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
        **_incoming_credit_release_metrics(path, rows),
        **_buflo_duration_budget_metrics(path),
        **_tamaraw_capture_metrics(path, rows),
        **_front_capture_metrics(path, rows),
        **_terminal_primary_partial_metrics(path, rows, tamaraw_configuration_policy=tamaraw_configuration_policy),
    }


def _buflo_duration_budget_metrics(schedule_path: Path) -> dict[str, Any]:
    """Join the optional budget to frozen parameter bytes, never infer it from counts."""
    artifact = schedule_path.with_name("defense-parameters.json")
    parsed = load_json(artifact) if artifact.is_file() else None
    opted_in = isinstance(parsed, Mapping) and parsed.get("duration_budget_policy") is not None
    run_path = schedule_path.with_name("run.json")
    if not run_path.is_file():
        if opted_in:
            raise ValueError("fixed BuFLO duration parameters have no actual Native run receipt")
        return {}
    run = load_json(run_path)
    parameter = run.get("defense_parameters") if isinstance(run, Mapping) else None
    if not isinstance(parameter, Mapping):
        if opted_in:
            raise ValueError("fixed BuFLO duration parameters have no actual Native parameter receipt")
        return {}
    from .buflo_duration_budget import RUN_FIELD, validate_native_receipt
    if RUN_FIELD not in parameter:
        if opted_in:
            raise ValueError("fixed BuFLO duration parameters have no actual Native budget receipt")
        return {}
    if not artifact.is_file() or artifact.is_symlink():
        raise ValueError("Native BuFLO duration receipt has no frozen regular parameter artifact")
    return validate_native_receipt(run, artifact.read_bytes())


def _terminal_primary_partial_metrics(schedule_path: Path, rows: list[dict[str, str]], *,
                                      tamaraw_configuration_policy: str | None = None) -> dict[str, Any]:
    from .capture_acceptance_policy import validate_terminal_primary_partial_evidence
    try:
        run = load_json(schedule_path.with_name("run.json"))
    except (OSError, ValueError):
        return {}
    return validate_terminal_primary_partial_evidence(run, runner_directory=schedule_path.parent, schedule_rows=rows,
        tamaraw_configuration_policy=tamaraw_configuration_policy)


def _terminal_primary_partial_allowance(defense: str, schedule: Mapping[str, Any] | None) -> tuple[int, int] | None:
    from .capture_acceptance_policy import TERMINAL_PRIMARY_FIELD, validate_terminal_primary_capture_marker
    if not isinstance(schedule, Mapping) or TERMINAL_PRIMARY_FIELD not in schedule:
        return (0, 0)
    cell = {"tamaraw": 1200, "buflo": 1200, "cs-buflo": 600}.get(defense)
    if cell is None:
        return None
    try:
        validate_terminal_primary_capture_marker(schedule[TERMINAL_PRIMARY_FIELD], cell_size=cell)
    except ValueError:
        return None
    count = schedule.get("terminal_primary_partial_cells")
    retired = schedule.get("terminal_primary_partial_retired_bytes")
    consumed = schedule.get("terminal_primary_partial_consumed_bytes")
    if (type(count) is not int or count not in {0, 1} or type(retired) is not int or type(consumed) is not int
        or schedule.get("terminal_primary_partial_cell_size") != cell
        or any(not (isinstance(schedule.get(key), str) and len(schedule[key]) == 64
            and all(char in "0123456789abcdef" for char in schedule[key])) for key in (
            "terminal_primary_partial_events_sha256", "terminal_primary_partial_schedule_sha256"))):
        return None
    if count == 0:
        return (0, 0) if retired == consumed == 0 and "terminal_primary_partial_proof" not in schedule else None
    proof = schedule.get("terminal_primary_partial_proof")
    if (not isinstance(proof, Mapping) or not 0 < retired < cell or not 0 < consumed < cell
        or retired + consumed != cell or proof.get("retired_bytes") != retired
        or proof.get("consumed_bytes") != consumed or proof.get("cell_bytes") != cell
        or schedule.get("missed_event_reasons") != {"ReceiveCreditRetired": 1}):
        return None
    return count, retired


def _front_capture_metrics(schedule_path: Path, rows: list[dict[str, str]]) -> dict[str, Any]:
    """Keep raw misses; prove the exact prospective outgoing omission policy."""
    from .capture_acceptance_policy import FRONT_FIELD, FRONT_PADDING_POLICY, FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY, validate_front_capture_run
    try:
        run = load_json(schedule_path.with_name("run.json"))
    except (OSError, ValueError):
        return {}
    if not isinstance(run, Mapping) or FRONT_FIELD not in run:
        return {}
    marker = validate_front_capture_run(run)
    padding_policy = marker["policy"] in {FRONT_PADDING_POLICY, FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY}
    reserve_policy = marker["policy"] in {FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY}
    outgoing_window_us = marker.get("outgoing_release_window_us", 5000)
    allowed_reasons = {"CongestionLimited", "DeadlineExpired"} if padding_policy else {"CongestionLimited"}
    start_ns = run.get("defense_start_monotonic_ns")
    if type(start_ns) is not int or start_ns < 0:
        raise ValueError("FRONT omission proof lacks its defense clock")
    outgoing = {}
    omissions = {}
    for row in rows:
        if row.get("direction") not in {"incoming", "outgoing"}:
            raise ValueError("FRONT omission proof contains an invalid direction")
        if row.get("direction") != "outgoing":
            if row.get("satisfaction") != "satisfied":
                raise ValueError("FRONT omission policy cannot waive an incoming miss")
            continue
        slot = _csv_uint(row, "slot_id")
        if slot in outgoing or row.get("qcsd_outcome_schema_version") != "3" or _csv_uint(row, "size") != 1200:
            raise ValueError("FRONT omission proof repeats or changes an outgoing cell")
        outgoing[slot] = row
        if row.get("satisfaction") == "missed":
            if (row.get("miss_reason") not in allowed_reasons or row.get("observed_size")
                or any(row.get(key) for key in SCHEDULE_QCSD_FIELDS[1:-1])):
                raise ValueError("FRONT omission policy rejects this outgoing miss")
            omissions[slot] = row
        elif row.get("satisfaction") != "satisfied":
            raise ValueError("FRONT omission proof contains a non-exact outgoing outcome")
    events_path = schedule_path.with_name("events.csv")
    with events_path.open(newline="", encoding="utf-8") as source:
        events = list(csv.DictReader(source))
    padding_actions = {}
    reserve_windows, preexpired = {}, set()
    if reserve_policy:
        from .front_preparation_evidence import validate_windows
        reserve_windows, preexpired = validate_windows(run, outgoing, omissions, events)
        padding_actions = {slot: (window["action_us"], window["action"]["deadline_after_us"])
                           for slot, window in reserve_windows.items() if slot in omissions}
    if padding_policy and not reserve_policy:
        for event in events:
            if event.get("event") != "action" or event.get("outcome") != "applied":
                continue
            details = json.loads(event["details"])
            if not isinstance(details, Mapping) or details.get("type") != "send_packet":
                continue
            slot = details.get("slot")
            if type(slot) is not int or slot not in omissions:
                continue
            row = omissions[slot]
            packet = details.get("packet")
            release, deadline = details.get("not_before_after_us"), details.get("deadline_after_us")
            if (slot in padding_actions or details.get("allow_stream_data") is not False
                or details.get("send_policy", "exact") != "exact"
                or type(details.get("endpoint")) is not int
                or details["endpoint"] != _csv_uint(row, "connection")
                or _csv_uint(event, "connection") != details["endpoint"]
                or not isinstance(packet, Mapping) or set(packet) != {"timestamp_us", "direction", "length"}
                or type(packet.get("timestamp_us")) is not int
                or packet["timestamp_us"] != _csv_uint(row, "target_time_us")
                or packet.get("direction") != "outgoing"
                or type(packet.get("length")) is not int or packet["length"] != 1200
                or type(release) is not int or type(deadline) is not int
                or not 0 <= release < deadline <= 2**64 - 1
                # Native rounds the release upward and deadline downward.
                # V1/V2 retain 5000 us; the V3 prepared source declares 10000.
                or deadline - release not in {outgoing_window_us - 1, outgoing_window_us}):
                raise ValueError("FRONT omission lacks a unique applied pure-padding opportunity")
            action_us = _csv_uint(event, "monotonic_us")
            if action_us < start_ns // 1000:
                raise ValueError("FRONT padding opportunity precedes its defense clock")
            padding_actions[slot] = (action_us, deadline)
        if set(padding_actions) != set(omissions):
            raise ValueError("FRONT omission lacks its actual applied padding action")
    matched_misses = set()
    sequences = set()
    for event in events:
        if event.get("event") != "observation" or event.get("outcome") != "recorded":
            continue
        details = json.loads(event["details"])
        if not isinstance(details, Mapping) or details.get("type") != "slot_missed":
            continue
        slot = details.get("slot")
        row = omissions.get(slot) if type(slot) is int else None
        if row is None or slot in matched_misses or slot in preexpired:
            raise ValueError("FRONT omission proof lacks unique matching native miss observations")
        production_ns, sequence = details.get("production_monotonic_ns"), details.get("production_sequence")
        packet = details.get("packet")
        if (type(production_ns) is not int or production_ns < start_ns
            or type(sequence) is not int or sequence < 0 or sequence in sequences
            or type(details.get("endpoint")) is not int
            or details["endpoint"] != _csv_uint(row, "connection")
            or _csv_uint(event, "connection") != details["endpoint"]
            or details.get("reason") != {"CongestionLimited": "congestion_limited",
                                          "DeadlineExpired": "deadline_expired"}[row["miss_reason"]]
            or not isinstance(packet, Mapping) or set(packet) != {"timestamp_us", "direction", "length"}
            or type(packet.get("timestamp_us")) is not int or packet["timestamp_us"] != _csv_uint(row, "target_time_us")
            or packet.get("direction") != "outgoing" or type(packet.get("length")) is not int or packet["length"] != 1200
            or _csv_uint(event, "monotonic_us") != production_ns // 1000
            # Native preserves the observation's production clock, then records
            # terminal_defense_elapsed_us when the controller reduces it. These
            # are distinct instants; the reduction may follow production.
            or (production_ns - start_ns) // 1000 > _csv_uint(row, "terminal_defense_elapsed_us")):
            raise ValueError("FRONT omission proof differs from its actual native packet and clock identity")
        if padding_policy:
            action_us, deadline_after_us = padding_actions[slot]
            if (production_ns // 1000 < action_us
                or (not reserve_policy and row["miss_reason"] == "DeadlineExpired"
                    # The CSV action time is floored: prove expiry beyond the
                    # entire possible action/deadline interval in nanoseconds.
                    and production_ns < (action_us + deadline_after_us + 1) * 1000)):
                raise ValueError("FRONT padding miss precedes its applied action or expiry deadline")
            if (reserve_policy and row["miss_reason"] == "DeadlineExpired"
                and production_ns < reserve_windows[slot]["construction_deadline_ns"]):
                raise ValueError("FRONT V4 padding miss precedes its recorded construction deadline")
        matched_misses.add(slot)
        sequences.add(sequence)
    if matched_misses | preexpired != set(omissions):
        raise ValueError("FRONT omission proof lacks its actual native miss evidence")
    packets_path = schedule_path.with_name("packets.csv")
    packets = _read_exact_csv(packets_path, RUNNER_PACKET_FIELDS + SCHEDULE_QCSD_FIELDS)
    matched = set()
    for packet in packets:
        if packet.get("direction") != "outgoing" or not packet.get("slot_id"):
            continue
        slot = _csv_uint(packet, "slot_id")
        row = outgoing.get(slot)
        if (row is None or slot in omissions or slot in matched
            or row.get("satisfaction") != "satisfied" or packet.get("satisfaction") != "satisfied"
            or packet.get("connection") != row.get("connection")
            or row.get("send_policy") != "exact" or packet.get("send_policy") != "exact"
            or any(_csv_uint(packet, key) != 1200 for key in (
                "observed_udp_length", "scheduled_target", "desired_udp_bytes", "observed_udp_bytes"))
            or _csv_uint(row, "observed_size") != 1200 or _csv_uint(row, "observed_udp_bytes") != 1200):
            raise ValueError("FRONT omission proof lacks unique actual full outgoing shaped cells")
        matched.add(slot)
    if not outgoing or matched != set(outgoing) - set(omissions):
        raise ValueError("FRONT omission proof lacks actual outgoing packet handoffs")
    if reserve_policy:
        from .front_preparation_evidence import validate_physical_handoffs
        validate_physical_handoffs(run, reserve_windows, omissions, events, packets)
    metrics = {"front_capture_policy": marker,
            "front_outgoing_scheduled_events": len(outgoing),
            "front_outgoing_congestion_omissions": sum(row["miss_reason"] == "CongestionLimited" for row in omissions.values()),
            "front_outgoing_shaped_handoff_events": len(matched),
            "front_outgoing_omissions_within_bound": len(omissions) * marker["outgoing_omission_ratio_denominator"]
                <= len(outgoing) * marker["outgoing_omission_ratio_numerator"],
            "front_outgoing_congestion_omission_events_sha256": sha256_file(events_path),
            "front_outgoing_release_packets_sha256": sha256_file(packets_path)}
    if padding_policy:
        metrics.update(front_outgoing_padding_omissions=len(omissions),
            front_outgoing_deadline_omissions=sum(row["miss_reason"] == "DeadlineExpired" for row in omissions.values()),
            front_outgoing_padding_action_events_sha256=sha256_file(events_path))
    if reserve_policy:
        metrics.update(front_outgoing_pre_registration_omissions=len(preexpired),
            front_outgoing_preparation_window_events=len(reserve_windows),
            front_outgoing_preparation_failure_events=0,
            front_outgoing_physical_window_violations=0,
            front_preparation_window_events_sha256=sha256_file(events_path))
    return metrics


def _front_capture_activation_valid(diagnostics: Mapping[str, Any], schedule: Mapping[str, Any],
                                    resolved: Mapping[str, Any] | None) -> bool:
    from .capture_acceptance_policy import FRONT_PADDING_POLICY, FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY, validate_front_capture_marker
    try:
        marker = validate_front_capture_marker(schedule.get("front_capture_policy"))
    except ValueError:
        return False
    count = schedule.get("scheduled_events")
    outgoing, incoming = schedule.get("scheduled_outgoing_events"), schedule.get("scheduled_incoming_events")
    padding_policy = marker["policy"] in {FRONT_PADDING_POLICY, FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY}
    missed = schedule.get("front_outgoing_padding_omissions" if padding_policy else "front_outgoing_congestion_omissions")
    integer_fields = ("scheduled_events", "scheduled_outgoing_events", "scheduled_incoming_events",
        "satisfied_events", "missed_events", "outgoing_size_mismatch_events", "outgoing_size_absolute_error_bytes",
        "duplicate_terminal_slots", "invalid_terminal_rows", "invalid_typed_outcome_rows",
        "incoming_credit_missing_events", "incoming_credit_consumption_missing_events",
        "invalid_credit_advertisement_events", "invalid_credit_consumption_events",
        "front_outgoing_scheduled_events", "front_outgoing_congestion_omissions", "front_outgoing_shaped_handoff_events")
    if any(type(schedule.get(key)) is not int or schedule[key] < 0 for key in integer_fields):
        return False
    reasons = {"CongestionLimited": missed} if missed else {}
    if padding_policy:
        congestion, expired = schedule.get("front_outgoing_congestion_omissions"), schedule.get("front_outgoing_deadline_omissions")
        if (any(type(value) is not int or value < 0 for value in (missed, congestion, expired))
            or congestion + expired != missed):
            return False
        reasons = {key: value for key, value in (("CongestionLimited", congestion), ("DeadlineExpired", expired)) if value}
    if (any(type(value) is not int or value < 0 for value in (count, outgoing, incoming, missed))
        or not 1 <= outgoing <= marker["n_client_packets"] or not 1 <= incoming <= marker["n_server_packets"] or count != incoming + outgoing
        or missed * marker["outgoing_omission_ratio_denominator"] > outgoing * marker["outgoing_omission_ratio_numerator"]
        or schedule.get("missed_events") != missed
        or schedule.get("satisfied_events") != count - missed
        or schedule.get("terminal_satisfactions") != ({"satisfied": count - missed, "missed": missed} if missed else {"satisfied": count})
        or schedule.get("front_outgoing_scheduled_events") != outgoing
        or schedule.get("front_outgoing_shaped_handoff_events") != outgoing - missed
        or schedule.get("front_outgoing_omissions_within_bound") is not True
        or schedule.get("outgoing_size_mismatch_events") != 0
        or schedule.get("outgoing_size_absolute_error_bytes") != 0
        or schedule.get("invalid_terminal_rows") != 0
        or schedule.get("missed_event_reasons") != reasons
        or not _new_schedule_terminal_contract(schedule, congestion_sensitive=False)):
        return False
    hashes = ("front_outgoing_congestion_omission_events_sha256", "front_outgoing_release_packets_sha256")
    if padding_policy:
        hashes += ("front_outgoing_padding_action_events_sha256",)
    if marker["policy"] in {FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY}:
        before_registration = schedule.get("front_outgoing_pre_registration_omissions")
        if (type(before_registration) is not int or not 0 <= before_registration <= schedule["front_outgoing_deadline_omissions"]
            or type(schedule.get("front_outgoing_preparation_window_events")) is not int
            or schedule["front_outgoing_preparation_window_events"] != outgoing
            or type(schedule.get("front_outgoing_preparation_failure_events")) is not int
            or schedule["front_outgoing_preparation_failure_events"] != 0
            or type(schedule.get("front_outgoing_physical_window_violations")) is not int
            or schedule["front_outgoing_physical_window_violations"] != 0):
            return False
        hashes += ("front_preparation_window_events_sha256",)
    for key in hashes:
        value = schedule.get(key)
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            return False
    sizes, targets = schedule.get("scheduled_sizes_by_direction"), schedule.get("target_times_us_by_direction")
    if not isinstance(sizes, Mapping) or not isinstance(targets, Mapping):
        return False
    for direction, expected in (("outgoing", outgoing), ("incoming", incoming)):
        if (not isinstance(sizes.get(direction), list) or len(sizes[direction]) != expected
            or any(type(size) is not int or size != 1200 for size in sizes[direction])
            or not isinstance(targets.get(direction), list) or len(targets[direction]) != expected
            or any(type(target) is not int or target < 0 for target in targets[direction])):
            return False
    if marker["policy"] == FRONT_LIGHT_POLICY:
        from .front_fixed_configuration import POLICY as CONFIGURATION_POLICY, validate_run
        try:
            validate_run({"resolved_configuration": resolved, "front_capture_policy": marker}, selected_policy=CONFIGURATION_POLICY)
        except (ValueError, TypeError, KeyError):
            return False
        if (schedule.get("front_incoming_credit_release_policy") != marker
            or type(schedule.get("incoming_credit_release_window_us")) is not int
            or schedule["incoming_credit_release_window_us"] != 10000
            or type(schedule.get("incoming_credit_release_timing_events")) is not int
            or schedule["incoming_credit_release_timing_events"] != incoming
            or type(schedule.get("incoming_credit_release_window_violations")) is not int
            or schedule["incoming_credit_release_window_violations"] != 0
            or type(schedule.get("incoming_credit_release_original_5000us_violations")) is not int
            or not 0 <= schedule["incoming_credit_release_original_5000us_violations"] <= incoming):
            return False
        return all(diagnostics.get(key) == incoming * 1200 for key in (
            "scheduled_incoming_requested_bytes", "scheduled_incoming_advertised_bytes", "scheduled_incoming_consumed_bytes"))
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    expected_defense = {"kind": "front", "n_client_packets": 900, "n_server_packets": 1200,
                        "packet_size": 1200, "peak_minimum_seconds": 0.1, "peak_maximum_seconds": 2.5}
    return (isinstance(defense, Mapping) and all(type(defense.get(k)) is type(v) and defense[k] == v for k, v in expected_defense.items())
        and type(resolved.get("schema_version")) is int and resolved["schema_version"] == 2
        and type(resolved.get("control_interval_us")) is int and resolved["control_interval_us"] == 5000
        and resolved.get("drop_unsatisfied_events") is False
        and type(resolved.get("max_udp_payload_size")) is int and resolved["max_udp_payload_size"] == 1200
        and all(diagnostics.get(key) == incoming * 1200 for key in (
            "scheduled_incoming_requested_bytes", "scheduled_incoming_advertised_bytes", "scheduled_incoming_consumed_bytes")))


def _tamaraw_capture_metrics(schedule_path: Path, rows: list[dict[str, str]]) -> dict[str, Any]:
    """Measure actual UDP handoff; registration and parser reads supply no send proof."""
    from .capture_acceptance_policy import TAMARAW_FIELD, tamaraw_outgoing_release_window
    try:
        run = load_json(schedule_path.with_name("run.json"))
    except (OSError, ValueError):
        return {}
    if not isinstance(run, Mapping) or TAMARAW_FIELD not in run:
        return {}
    window = tamaraw_outgoing_release_window(run)
    start_ns = run.get("defense_start_monotonic_ns")
    if type(start_ns) is not int or start_ns < 0:
        raise ValueError("Tamaraw physical release proof lacks its defense clock")
    packets_path = schedule_path.with_name("packets.csv")
    packets = _read_exact_csv(packets_path, RUNNER_PACKET_FIELDS + SCHEDULE_QCSD_FIELDS)
    scheduled = {}
    for row in rows:
        if row.get("direction") != "outgoing":
            continue
        slot = _csv_uint(row, "slot_id")
        if slot in scheduled:
            raise ValueError("Tamaraw physical release proof repeats an outgoing slot")
        scheduled[slot] = row
    matched = set()
    violations = historical_violations = 0
    lateness = []
    for packet in packets:
        if packet.get("direction") != "outgoing" or not packet.get("slot_id"):
            continue
        slot = _csv_uint(packet, "slot_id")
        row = scheduled.get(slot)
        if (row is None or slot in matched
            or packet.get("connection") != row.get("connection")
            or packet.get("satisfaction") != "satisfied" or row.get("satisfaction") != "satisfied"
            or packet.get("send_policy") != "exact" or row.get("send_policy") != "exact"
            or any(_csv_uint(packet, key) != 1_200 for key in (
                "observed_udp_length", "scheduled_target", "desired_udp_bytes", "observed_udp_bytes"))
            or _csv_uint(row, "size") != 1_200
            or _csv_uint(row, "observed_size") != 1_200):
            raise ValueError("Tamaraw physical release proof lacks unique complete shaped cells")
        matched.add(slot)
        release_ns = start_ns + _csv_uint(row, "target_time_us") * 1_000
        lower_ns = _csv_uint(packet, "monotonic_us") * 1_000
        upper_ns = lower_ns + 1_000
        if lower_ns < release_ns or upper_ns > release_ns + window * 1_000:
            violations += 1
        if lower_ns < release_ns or upper_ns > release_ns + 5_000_000:
            historical_violations += 1
        lateness.append(max(0, (upper_ns - release_ns - 1) // 1_000))
    if not scheduled or matched != set(scheduled):
        raise ValueError("Tamaraw physical release proof lacks scheduled outgoing handoffs")
    return {"tamaraw_capture_policy": run[TAMARAW_FIELD],
            "tamaraw_outgoing_release_window_us": window,
            "tamaraw_outgoing_release_timing_events": len(matched),
            "tamaraw_outgoing_release_window_violations": violations,
            "tamaraw_outgoing_release_original_5000us_violations": historical_violations,
            "tamaraw_outgoing_release_lateness_upper_bound_us_max": max(lateness),
            "tamaraw_outgoing_release_packets_sha256": sha256_file(packets_path)}


def _tamaraw_capture_metrics_valid(schedule: Mapping[str, Any] | None) -> bool:
    from .capture_acceptance_policy import tamaraw_outgoing_window_from_policy
    if not isinstance(schedule, Mapping):
        return False
    try:
        window = tamaraw_outgoing_window_from_policy(schedule.get("tamaraw_capture_policy"))
    except ValueError:
        return False
    count = schedule.get("scheduled_outgoing_events")
    measured = schedule.get("tamaraw_outgoing_release_timing_events")
    historical = schedule.get("tamaraw_outgoing_release_original_5000us_violations")
    maximum = schedule.get("tamaraw_outgoing_release_lateness_upper_bound_us_max")
    digest = schedule.get("tamaraw_outgoing_release_packets_sha256")
    return (type(count) is int and count > 0 and type(measured) is int and measured == count
        and type(schedule.get("tamaraw_outgoing_release_window_us")) is int
        and schedule["tamaraw_outgoing_release_window_us"] == window
        and type(schedule.get("tamaraw_outgoing_release_window_violations")) is int
        and schedule["tamaraw_outgoing_release_window_violations"] == 0
        and type(historical) is int and 0 <= historical <= count
        and type(maximum) is int and 0 <= maximum < window
        and isinstance(digest, str) and len(digest) == 64
        and all(value in "0123456789abcdef" for value in digest))


def _buflo_schedule_release_window(metrics: Mapping[str, Any]) -> int:
    from .capture_acceptance_policy import incoming_release_window_from_policy
    if "incoming_credit_release_policy" not in metrics:
        if "incoming_credit_release_window_us" in metrics:
            raise ValueError("incoming credit release window lacks its explicit policy")
        return BUFLO_INCOMING_CREDIT_RELEASE_WINDOW_US
    window = incoming_release_window_from_policy(metrics["incoming_credit_release_policy"])
    original = metrics.get("incoming_credit_release_original_5000us_violations")
    if (type(metrics.get("incoming_credit_release_window_us")) is not int
        or metrics["incoming_credit_release_window_us"] != window
        or type(original) is not int or original < 0):
        raise ValueError("incoming credit release metrics differ from their policy")
    return window


def _buflo_metric_startup(metrics: Mapping[str, Any]) -> Mapping[str, Any] | None:
    from .capture_acceptance_policy import ACK_START_POLICY, CADENCE64_ACK_START_POLICY, validate_buflo_startup_receipt
    marker = metrics.get("incoming_credit_release_policy")
    if not isinstance(marker, Mapping) or marker.get("policy") not in {ACK_START_POLICY, CADENCE64_ACK_START_POLICY}:
        if "buflo_incoming_startup" in metrics or "buflo_incoming_startup_events_sha256" in metrics:
            raise ValueError("BuFLO startup metrics lack their V2 policy")
        return None
    _buflo_schedule_release_window(metrics)
    period_us = 64_000 if marker["policy"] == CADENCE64_ACK_START_POLICY else 20_000
    if period_us == 64_000:
        from .buflo_duration_budget import RUN_FIELD, CADENCE64_RECEIPT, CADENCE64_PARAMETER_SHA256, validate_receipt
        validate_receipt(metrics.get(RUN_FIELD))
        if (metrics[RUN_FIELD] != CADENCE64_RECEIPT
            or metrics.get("buflo_duration_budget_parameter_sha256") != CADENCE64_PARAMETER_SHA256):
            raise ValueError("64ms startup metrics differ from exact Native duration provenance")
    startup = validate_buflo_startup_receipt(metrics.get("buflo_incoming_startup"), period_us=period_us)
    digest = metrics.get("buflo_incoming_startup_events_sha256")
    if (not isinstance(digest, str) or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)):
        raise ValueError("BuFLO startup metrics lack reopened event evidence")
    return startup


def _buflo_kernel_credit_release_intervals(
    run: Mapping[str, Any], rows: list[dict[str, str]]
) -> dict[int, tuple[int, int, int]] | None:
    """Join each modern incoming slot to all its validated physical carriers.

    CSV advertisement stamps retain their process MONOTONIC diagnostics.
    Modern kernel receipts bound each physical TX directly in TAI; a single
    initial MONOTONIC offset cannot replace those retained per-item brackets.
    This does not replace the independent post-veth evidence promotion gate.
    """
    from .kernel_tx import (
        KERNEL_TX_RUNNER_V10_SCHEMA_VERSION, KERNEL_TX_RUNNER_SCHEMA_VERSION,
        KERNEL_TX_RESERVE_RUNNER_SCHEMA_VERSION, KERNEL_TX_CADENCE64_RUNNER_SCHEMA_VERSION,
        kernel_tx_incoming_window_bound_to_run_valid,
        kernel_tx_runner_receipt_success_valid,
    )

    wakeups = run.get("runner_wakeup_metrics")
    raw = wakeups.get("buflo_kernel_tx") if isinstance(wakeups, Mapping) else None
    if raw is None or (isinstance(raw, Mapping) and type(raw.get("schema_version")) is int
                       and 1 <= raw["schema_version"] <= 9):
        return None
    if (not isinstance(raw, Mapping)
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] not in {
            KERNEL_TX_RUNNER_V10_SCHEMA_VERSION, KERNEL_TX_RUNNER_SCHEMA_VERSION,
            KERNEL_TX_RESERVE_RUNNER_SCHEMA_VERSION, KERNEL_TX_CADENCE64_RUNNER_SCHEMA_VERSION,
        }
        or not kernel_tx_runner_receipt_success_valid(raw)
        or not kernel_tx_incoming_window_bound_to_run_valid(run)):
        raise ValueError("BuFLO incoming release lacks valid bound modern kernel evidence")

    carriers: dict[int, tuple[Mapping[str, Any], list[Mapping[str, Any]], set[int]]] = {}
    for job in raw["jobs"]:
        items = {item["item_id"]: item for item in job["items"]}
        for identity in job["credit_identities"]:
            item = (job["items"][0] if identity["resolution"] == "coalesced-in-main-finalized"
                    else items[identity["carrier_item_id"]])
            slot = identity["slot"]
            if slot not in carriers:
                carriers[slot] = (job, [], set())
            carriers[slot][1].append(item)
            carriers[slot][2].add(identity["endpoint_index"])

    intervals: dict[int, tuple[int, int, int]] = {}
    for row in rows:
        if row.get("direction") != "incoming":
            continue
        slot = _csv_uint(row, "slot_id")
        if slot in intervals or slot not in carriers:
            raise ValueError("BuFLO incoming slot lacks unique kernel carrier coverage")
        job, items, owners = carriers[slot]
        target_ns = _csv_uint(row, "target_time_us") * 1_000
        if target_ns != job["release_tai_ns"] - raw["defense_start_tai_ns"]:
            raise ValueError("BuFLO incoming target differs from its kernel release")
        connection = row.get("connection")
        if ((connection and owners != {_csv_uint(row, "connection")})
            or (not connection and len(owners) <= 1)):
            raise ValueError("BuFLO incoming owner differs from its kernel carriers")
        advertised = _csv_uint(row, "credit_advertised_at_us")
        action = _csv_uint(row, "action_time_us")
        if (advertised < action
            or _csv_uint(row, "credit_advertisement_delay_us") != advertised - action):
            raise ValueError("BuFLO incoming advertisement has inconsistent CSV stamps")
        intervals[slot] = (job["release_tai_ns"],
            min(item["tx_software_tai_lower_ns"] for item in items),
            max(item["tx_software_tai_upper_ns"] for item in items))
    if set(intervals) != set(carriers):
        raise ValueError("BuFLO kernel credit identity lacks its incoming schedule slot")
    return intervals


def _incoming_credit_release_metrics(
    schedule_path: Path, rows: list[dict[str, str]]
) -> dict[str, Any]:
    """Bound receive-credit handoff against the scheduled defense tick.

    The raw CSV delay starts at action registration, which may intentionally
    prearm an incoming opportunity. Both CSV stamps are floored process-clock
    microseconds; run.json gives the defense start on that same clock in exact
    nanoseconds. Legacy receipts compare the full possible advertisement interval with the
    nominal tick's half-open source-bound window, never rounding a boundary
    inward. Historical receipts retain 5 ms; the explicit rapid policy permits
    10 ms incoming credit jitter at the unchanged 20 ms interval. Validated
    modern kernel receipts use the joined physical TAI intervals instead.
    """

    run_path = schedule_path.with_name("run.json")
    try:
        run = load_json(run_path)
    except (OSError, ValueError):
        return {}
    start_ns = run.get("defense_start_monotonic_ns") if isinstance(run, Mapping) else None
    if type(start_ns) is not int or start_ns < 0:
        return {}

    from .capture_acceptance_policy import ACK_START_POLICY, CADENCE64_ACK_START_POLICY, FIELD, buflo_incoming_release_window, validate_buflo_startup_evidence
    window_us = buflo_incoming_release_window(run)
    from .capture_acceptance_policy import FRONT_FIELD, FRONT_LIGHT_POLICY, validate_front_capture_run
    front_marker = run.get(FRONT_FIELD)
    front_v5 = isinstance(front_marker, Mapping) and front_marker.get("policy") == FRONT_LIGHT_POLICY
    if front_v5:
        front_marker = validate_front_capture_run(run)
        if FIELD in run:
            raise ValueError("FRONT V5 cannot borrow a BuFLO incoming window")
        window_us = front_marker["incoming_release_window_us"]
    startup = None
    if FIELD in run and run[FIELD]["policy"] in {ACK_START_POLICY, CADENCE64_ACK_START_POLICY}:
        startup = validate_buflo_startup_evidence(run, runner_directory=schedule_path.parent, schedule_rows=rows)
    kernel_intervals = _buflo_kernel_credit_release_intervals(run, rows)

    timing_events = 0
    window_violations = 0
    historical_window_violations = 0
    lateness_upper_bounds_us: list[int] = []
    for row in rows:
        if row.get("direction") != "incoming" or row.get("satisfaction") == "missed":
            continue
        try:
            target_us = _csv_uint(row, "target_time_us")
            advertised_us = _csv_uint(row, "credit_advertised_at_us")
        except (KeyError, TypeError, ValueError):
            window_violations += 1
            historical_window_violations += 1
            continue
        timing_events += 1
        if kernel_intervals is not None:
            release_ns, lower_ns, upper_ns = kernel_intervals[_csv_uint(row, "slot_id")]
            # Kernel TAI bounds are inclusive; the deadline remains exclusive.
            window_violations += int(lower_ns < release_ns or upper_ns >= release_ns + window_us * 1_000)
            historical_window_violations += int(lower_ns < release_ns or upper_ns >= release_ns
                + BUFLO_INCOMING_CREDIT_RELEASE_WINDOW_US * 1_000)
            lateness_upper_bounds_us.append(max(0, (upper_ns - release_ns) // 1_000))
        else:
            release_ns = start_ns + target_us * 1_000
            advertised_lower_ns = advertised_us * 1_000
            advertised_upper_ns = advertised_lower_ns + 1_000
            # The CSV upper edge and the selected release window are exclusive.
            if (advertised_lower_ns < release_ns or advertised_upper_ns > release_ns + window_us * 1_000):
                window_violations += 1
            if (advertised_lower_ns < release_ns or advertised_upper_ns > release_ns
                + BUFLO_INCOMING_CREDIT_RELEASE_WINDOW_US * 1_000):
                historical_window_violations += 1
            lateness_upper_bounds_us.append(max(0, (advertised_upper_ns - release_ns - 1) // 1_000))
    return {
        **({"incoming_credit_release_time_basis": "validated-kernel-physical-CLOCK_TAI-v1"}
           if kernel_intervals is not None else {}),
        **({"buflo_incoming_startup": startup,
            "buflo_incoming_startup_events_sha256": sha256_file(schedule_path.with_name("events.csv"))}
           if startup is not None else {}),
        **({"incoming_credit_release_policy": run[FIELD],
            "incoming_credit_release_window_us": window_us,
            "incoming_credit_release_original_5000us_violations": historical_window_violations}
           if FIELD in run else {}),
        **({"front_incoming_credit_release_policy": front_marker,
            "incoming_credit_release_window_us": window_us,
            "incoming_credit_release_original_5000us_violations": historical_window_violations}
           if front_v5 else {}),
        "incoming_credit_release_timing_events": timing_events,
        "incoming_credit_release_window_violations": window_violations,
        "incoming_credit_release_lateness_upper_bound_us_max": max(
            lateness_upper_bounds_us, default=0
        ),
    }


RUNNER_CSV_U64_MAX = 2**64 - 1
_RUNNER_CSV_U64_MAX_TEXT = str(RUNNER_CSV_U64_MAX)


def _runner_csv_u64(value: Any, *, label: str) -> int:
    """Parse the canonical unsigned integer domain emitted by Rust trace rows."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is not an unsigned integer")
    if len(value) > len(_RUNNER_CSV_U64_MAX_TEXT):
        raise ValueError(f"{label} is outside the Rust u64 domain")
    if value != "0" and (
        value[0] not in "123456789"
        or any(character not in "0123456789" for character in value[1:])
    ):
        raise ValueError(f"{label} is not a canonical ASCII unsigned integer")
    if len(value) == len(_RUNNER_CSV_U64_MAX_TEXT) and value > _RUNNER_CSV_U64_MAX_TEXT:
        raise ValueError(f"{label} is outside the Rust u64 domain")
    return int(value)


def _csv_uint(row: Mapping[str, Any], field: str) -> int:
    return _runner_csv_u64(row[field], label=f"schedule field {field}")


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
RUNNER_WAKEUP_V10_SEMANTICS = (
    f"{RUNNER_WAKEUP_SEMANTICS}; "
    "buflo_ordinary_output_admission_lead_us=10000; "
    "buflo_exact_release_guard_reserves_candidate_window; "
    "buflo_exact_release_guard_lead_us=5000; "
    "buflo_exact_release_active_wait_tail_us=5000; "
    "buflo_exact_release_guard_coincides_with_output_admission=false; "
    "buflo_exact_release_guards_are_separately_receipted_active_waits; "
    "buflo_exact_release_schema10_passive_wait_unreachable=true; "
    "buflo_exact_release_guard_wait_equals_active_wait=true; "
    "buflo_exact_release_max_passive_wake_lateness_equals_"
    "max_guard_entry_lateness=true; "
    "buflo_exact_release_aggregate_entry_lateness_reachable="
    "max_retained_failure_entry_or_5000000_plus_max_dispatch_lateness; "
    "buflo_exact_release_aggregate_active_wait_reachable="
    "retained_success_plus_retained_failure_plus_bounded_unretained_successes_"
    "with_hidden_entry_max_subtraction_saturating; "
    "buflo_exact_release_active_derived_maxima_reachable="
    "retained_per_metric_or_unretained_success_5000000_plus_dispatch; "
    "buflo_exact_release_deadline_count_reachable="
    "outside_zero_or_max_dispatch_lateness_at_least_4999000; "
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
    "linux_aarch64_cntvct_el0_predictive_authoritative_watchdog_else_"
    "instant_authoritative_fallback; "
    "buflo_exact_release_counter_target_rounding=ceil; "
    "buflo_exact_release_counter_calibration=counter_instant_counter; "
    "buflo_exact_release_counter_is_predictive_with_periodic_authoritative_watchdog=true; "
    "buflo_exact_release_authoritative_watchdog_interval_successful_relaxed_reads=64; "
    "buflo_exact_release_authoritative_watchdog_dispatch_preserves_strict_half_open_"
    "transport_check=true; "
    "buflo_exact_release_authoritative_watchdog_cadence_validated_guards="
    "count_dispatch_ready_production_guards_passing_exact_per_guard_cadence; "
    "buflo_exact_release_zero_failure_authoritative_watchdog_remainder_reads="
    "active_wait_iterations-2*counter_calibrations; "
    "buflo_exact_release_zero_failure_authoritative_watchdog_remainder_bound="
    "counter_calibrations=guards+early_confirmation_retries_and_"
    "64*checks<=remainder<64*(checks+guards)_and_remainder>=early_confirmation_retries; "
    "buflo_exact_release_zero_failure_empty_partition="
    "zero_iterations_calibrations_checks_retries_dispatches; "
    "buflo_exact_release_remaining_success_guard_projection="
    "subtract_worst_and_exact_retained_failure_then_same_remainder_bounds; "
    "buflo_exact_release_zero_failure_watchdog_dispatch_residue="
    "dispatches<=checks_and_remainder-64*checks<=63*(guards-dispatches); "
    "buflo_exact_release_max_authoritative_sample_gap="
    "consecutive_calibration_watchdog_or_final_authoritative_samples; "
    "buflo_exact_release_authoritative_counter_lag="
    "max_authoritative_elapsed_minus_counter_elapsed_from_current_calibration_anchor; "
    "buflo_exact_release_counter_authoritative_lead="
    "max_counter_elapsed_minus_authoritative_elapsed_from_current_calibration_anchor; "
    "buflo_exact_release_counter_frequency_hz_range_inclusive=1000000..4294967295; "
    "buflo_exact_release_counter_target_error="
    "defensive_unreachable_for_valid_live_guard_and_frequency; "
    "buflo_exact_release_first_calibration_target_error="
    "exactly_two_ordered_reads_and_zero_relaxed_reads; "
    "buflo_exact_release_zero_calibration_counter_unavailable="
    "one_or_two_ordered_reads_and_zero_relaxed_reads; "
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
    "buflo_exact_release_transport_dispatch_result_precedes_guard_metrics=true; "
    "buflo_exact_release_failure_authoritative_watchdog_cadence="
    "successful_relaxed_reads_R_checks_floor_R_div_64; "
    "buflo_exact_release_failure_terminal_counter_reads="
    "target_or_frequency_change_0_unavailable_or_nonmonotonic_1_or_2_"
    "C_eq_confirmations_plus_1_requires_1; "
    "buflo_exact_release_failure_retry_requires_successful_relaxed_read=true; "
    "buflo_exact_release_early_confirmation_retry_requires_positive_counter_nanoseconds=true; "
    "buflo_exact_release_failure_counter_comparison_absence="
    "zero_watchdog_and_zero_confirmation_implies_zero_lag_and_lead; "
    "buflo_exact_release_sole_success_failure_projection="
    "exact_saturating_sums_chronology_and_maxima; "
    "buflo_exact_release_retained_failure_exact_fields="
    "iterations_active_duration_interruptions_interruption_nanoseconds_and_max_gap; "
    "buflo_exact_release_nullable_chronology_duration="
    "adapter_window_exists_in_4999000_or_5000000_nanoseconds; "
    "buflo_exact_release_structural_count_partitions=checked_u64_exact_no_saturation; "
    "buflo_exact_release_histogram_integrity=max_bucket_and_coupled_G_plus_A_minus_H_times_50001; "
    "buflo_exact_release_remaining_histograms=subtract_exact_worst_and_failure; "
    "buflo_exact_release_remaining_success_duration=dispatch_bucket_floor_with_4999000ns_window; "
    "buflo_exact_incoming_retry_zero_drives_implies_zero_max_lateness=true; "
    "buflo_exact_release_predictive_interruptions="
    "count_le_iterations_minus_anchor_and_nonmonotonic_or_calibrated_unavailable_"
    "failed_read_and_nanoseconds_le_counter"
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
RUNNER_WAKEUP_V10_NEW_INTEGER_KEYS = frozenset(
    {
        "buflo_exact_release_active_wait_authoritative_watchdog_checks",
        "buflo_exact_release_active_wait_authoritative_watchdog_dispatches",
        "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards",
        "buflo_exact_release_max_authoritative_sample_gap_nanoseconds",
        "buflo_exact_release_max_authoritative_counter_lag_nanoseconds",
        "buflo_exact_release_max_counter_authoritative_lead_nanoseconds",
    }
)
RUNNER_WAKEUP_V10_INTEGER_KEYS = (
    frozenset(
        {
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
    )
    | RUNNER_WAKEUP_V9_NEW_INTEGER_KEYS
    | RUNNER_WAKEUP_V10_NEW_INTEGER_KEYS
)
RUNNER_WAKEUP_V10_REQUIRED_KEYS = (
    RUNNER_WAKEUP_V10_INTEGER_KEYS
    | RUNNER_WAKEUP_V9_OBJECT_KEYS
    | {"schema_version", "semantics"}
)
RUNNER_WAKEUP_V10_WORST_NEW_INTEGER_KEYS = frozenset(
    {
        "active_wait_authoritative_watchdog_checks",
        "active_wait_authoritative_watchdog_dispatches",
        "max_authoritative_sample_gap_nanoseconds",
        "max_authoritative_counter_lag_nanoseconds",
        "max_counter_authoritative_lead_nanoseconds",
    }
)
RUNNER_WAKEUP_V10_WORST_KEYS = (
    RUNNER_WAKEUP_V9_WORST_KEYS | RUNNER_WAKEUP_V10_WORST_NEW_INTEGER_KEYS
)
RUNNER_WAKEUP_V10_FAILURE_NEW_INTEGER_KEYS = frozenset(
    {
        "active_wait_iterations",
        "active_wait_monotonic_nanoseconds",
        "active_spin_interruptions",
        "active_spin_interruption_nanoseconds",
        "max_active_spin_gap_nanoseconds",
        "authoritative_watchdog_checks",
        "authoritative_watchdog_dispatches",
        "max_authoritative_sample_gap_nanoseconds",
        "max_authoritative_counter_lag_nanoseconds",
        "max_counter_authoritative_lead_nanoseconds",
    }
)
RUNNER_WAKEUP_V10_FAILURE_KEYS = (
    RUNNER_WAKEUP_V9_FAILURE_KEYS | RUNNER_WAKEUP_V10_FAILURE_NEW_INTEGER_KEYS
)
RUNNER_WAKEUP_V10_POLL_SOURCES = frozenset(
    {
        "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2",
        "instant-authoritative-fallback-v1",
    }
)
RUNNER_WAKEUP_V10_U64_MAX = RUNNER_CSV_U64_MAX
RUNNER_WAKEUP_V11_V1_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema10_layout_is_retained_for_non_kernel_metrics; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_HISTORICAL_RUNNER_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V11_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema10_layout_is_retained_for_non_kernel_metrics; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V2_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V12_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema12_retains_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V3_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V13_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema13_retains_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V4_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V14_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema14_retains_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V5_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V15_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema15_retains_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V6_SEMANTICS}; "
    "buflo_kernel_protected_selection_wait_semantics="
    f"{KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V16_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema16_retains_schema15_and_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V7_SEMANTICS}; "
    "buflo_kernel_protected_selection_wait_semantics="
    f"{KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V17_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema17_retains_schema16_schema15_and_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V8_SEMANTICS}; "
    "buflo_kernel_protected_selection_wait_semantics="
    f"{KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V18_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema18_retains_schema17_schema16_schema15_and_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V9_SEMANTICS}; "
    "buflo_kernel_protected_selection_wait_semantics="
    f"{KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V19_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema19_retains_schema18_schema17_schema16_schema15_and_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_V10_SEMANTICS}; "
    "buflo_kernel_protected_selection_wait_semantics="
    f"{KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V20_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema20_retains_schema19_schema18_schema17_schema16_schema15_and_schema10_layout_for_non_kernel_metrics=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    "buflo_kernel_tx_raw_semantics="
    f"{KERNEL_TX_RUNNER_SEMANTICS}; "
    "buflo_kernel_protected_selection_wait_semantics="
    f"{KERNEL_TX_PROTECTED_SELECTION_WAIT_V2_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V11_REQUIRED_KEYS = RUNNER_WAKEUP_V10_REQUIRED_KEYS | {"buflo_kernel_tx"}
RUNNER_WAKEUP_V21_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema21_retains_schema20_layout_for_non_kernel_metrics_and_requires_opted_in_kernel_schema12=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    f"buflo_kernel_tx_raw_semantics={KERNEL_TX_RESERVE_TX_SEMANTICS}; "
    f"buflo_kernel_protected_selection_wait_semantics={KERNEL_TX_RESERVE_SELECTION_WAIT_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V22_SEMANTICS = (
    f"{RUNNER_WAKEUP_V10_SEMANTICS}; "
    "runner_schema22_retains_schema21_layout_for_non_kernel_metrics_and_requires_opted_in_kernel_schema13=true; "
    "buflo_legacy_exact_release_guard_metrics_are_zero_with_kernel_tx=true; "
    f"buflo_kernel_tx_raw_semantics={KERNEL_TX_CADENCE64_TX_SEMANTICS}; "
    f"buflo_kernel_protected_selection_wait_semantics={KERNEL_TX_CADENCE64_SELECTION_WAIT_SEMANTICS}; "
    "post_veth_and_qdisc_end_state_are_separate_lab_evidence=true"
)
RUNNER_WAKEUP_V12_REQUIRED_KEYS = RUNNER_WAKEUP_V11_REQUIRED_KEYS
RUNNER_WAKEUP_V13_REQUIRED_KEYS = RUNNER_WAKEUP_V12_REQUIRED_KEYS
RUNNER_WAKEUP_V14_REQUIRED_KEYS = RUNNER_WAKEUP_V13_REQUIRED_KEYS
RUNNER_WAKEUP_V15_REQUIRED_KEYS = RUNNER_WAKEUP_V14_REQUIRED_KEYS
RUNNER_WAKEUP_V16_REQUIRED_KEYS = RUNNER_WAKEUP_V15_REQUIRED_KEYS
RUNNER_WAKEUP_V17_REQUIRED_KEYS = RUNNER_WAKEUP_V16_REQUIRED_KEYS
RUNNER_WAKEUP_V18_REQUIRED_KEYS = RUNNER_WAKEUP_V17_REQUIRED_KEYS
RUNNER_WAKEUP_V19_REQUIRED_KEYS = RUNNER_WAKEUP_V18_REQUIRED_KEYS
RUNNER_WAKEUP_V20_REQUIRED_KEYS = RUNNER_WAKEUP_V19_REQUIRED_KEYS
RUNNER_WAKEUP_V21_REQUIRED_KEYS = RUNNER_WAKEUP_V20_REQUIRED_KEYS
RUNNER_WAKEUP_V22_REQUIRED_KEYS = RUNNER_WAKEUP_V21_REQUIRED_KEYS


def _runner_wakeup_v10_checked_u64_sum(*values: int) -> int | None:
    total = 0
    for value in values:
        if value > RUNNER_WAKEUP_V10_U64_MAX - total:
            return None
        total += value
    return total


def _runner_wakeup_v10_checked_u64_product(left: int, right: int) -> int | None:
    if left and right > RUNNER_WAKEUP_V10_U64_MAX // left:
        return None
    return left * right


def _runner_wakeup_v10_saturating_u64_sum(values: Iterable[int]) -> int:
    total = 0
    for value in values:
        total = min(total + value, RUNNER_WAKEUP_V10_U64_MAX)
    return total


def _runner_wakeup_v10_active_wait_reachability_valid(
    value: Mapping[str, Any],
    *,
    worst: Any,
    failure: Any,
) -> bool:
    """Bound aggregate active-time evidence by the retained live guard geometry."""

    dispatch_ready = value["buflo_exact_release_dispatch_ready_guards"]
    maximum_dispatch_lateness = value[
        "buflo_exact_release_max_guard_exit_lateness_nanoseconds"
    ]
    maximum_success_active_wait_unclamped = 5_000_000 + maximum_dispatch_lateness
    maximum_success_active_wait = min(
        maximum_success_active_wait_unclamped,
        RUNNER_WAKEUP_V10_U64_MAX,
    )
    retained_worst_active_wait = (
        worst["active_wait_monotonic_nanoseconds"] if isinstance(worst, Mapping) else 0
    )
    retained_failure_active_wait = (
        failure["active_wait_monotonic_nanoseconds"]
        if isinstance(failure, Mapping)
        else 0
    )
    retained_entry_lateness = max(
        worst["guard_entry_lateness_nanoseconds"] if isinstance(worst, Mapping) else 0,
        failure["guard_entry_lateness_nanoseconds"] if isinstance(failure, Mapping) else 0,
    )
    maximum_entry_lateness = value[
        "buflo_exact_release_max_guard_entry_lateness_nanoseconds"
    ]
    required_hidden_success_entry_lateness = (
        maximum_entry_lateness if maximum_entry_lateness > retained_entry_lateness else 0
    )
    unretained_successes = max(dispatch_ready - int(isinstance(worst, Mapping)), 0)
    unretained_capacity_product = maximum_success_active_wait * unretained_successes
    if (
        unretained_successes > 0
        and maximum_success_active_wait_unclamped > RUNNER_WAKEUP_V10_U64_MAX
    ):
        aggregate_active_wait_ceiling = RUNNER_WAKEUP_V10_U64_MAX
    elif required_hidden_success_entry_lateness > unretained_capacity_product:
        return False
    else:
        aggregate_active_wait_ceiling = min(
            unretained_capacity_product
            - required_hidden_success_entry_lateness
            + retained_worst_active_wait
            + retained_failure_active_wait,
            RUNNER_WAKEUP_V10_U64_MAX,
        )
    unretained_success_active_maximum = (
        maximum_success_active_wait if unretained_successes else 0
    )
    active_derived_maxima = (
        (
            value["buflo_exact_release_max_active_spin_gap_nanoseconds"],
            worst["max_active_spin_gap_nanoseconds"] if isinstance(worst, Mapping) else 0,
            failure["max_active_spin_gap_nanoseconds"]
            if isinstance(failure, Mapping)
            else 0,
        ),
        (
            value["buflo_exact_release_max_active_wait_counter_gap_nanoseconds"],
            (worst["max_active_wait_counter_gap_nanoseconds"] or 0)
            if isinstance(worst, Mapping)
            else 0,
            (failure["max_counter_gap_nanoseconds"] or 0)
            if isinstance(failure, Mapping)
            else 0,
        ),
        (
            value["buflo_exact_release_max_counter_calibration_span_nanoseconds"],
            (worst["max_counter_calibration_span_nanoseconds"] or 0)
            if isinstance(worst, Mapping)
            else 0,
            (failure["max_counter_calibration_span_nanoseconds"] or 0)
            if isinstance(failure, Mapping)
            else 0,
        ),
        (
            value["buflo_exact_release_max_authoritative_sample_gap_nanoseconds"],
            worst["max_authoritative_sample_gap_nanoseconds"]
            if isinstance(worst, Mapping)
            else 0,
            failure["max_authoritative_sample_gap_nanoseconds"]
            if isinstance(failure, Mapping)
            else 0,
        ),
        (
            value["buflo_exact_release_max_authoritative_counter_lag_nanoseconds"],
            worst["max_authoritative_counter_lag_nanoseconds"]
            if isinstance(worst, Mapping)
            else 0,
            failure["max_authoritative_counter_lag_nanoseconds"]
            if isinstance(failure, Mapping)
            else 0,
        ),
    )
    return (
        value["buflo_exact_release_active_wait_nanoseconds"]
        <= aggregate_active_wait_ceiling
        and all(
            aggregate
            <= max(retained_worst, retained_failure, unretained_success_active_maximum)
            for aggregate, retained_worst, retained_failure in active_derived_maxima
        )
        and (
            value["buflo_exact_release_dispatch_at_or_after_deadline_guards"] == 0
            or maximum_dispatch_lateness >= 4_999_000
        )
    )


def _runner_wakeup_v10_minimum_interruption_nanoseconds(count: int) -> int:
    return min(count * 50_001, RUNNER_WAKEUP_V10_U64_MAX)


def _runner_wakeup_v10_histogram_minimum_interruption_nanoseconds(
    counts: Iterable[int], max_gap: int
) -> int:
    counts = tuple(counts)
    lower_bounds = (0, 50_001, 100_001, 250_001, 500_001, 1_000_001, 2_000_001, 5_000_001)
    minimum = min(
        sum(count * lower for count, lower in zip(counts, lower_bounds, strict=True)),
        RUNNER_WAKEUP_V10_U64_MAX,
    )
    if max_gap > 50_000:
        bucket = next(
            (
                index
                for index, upper in enumerate(RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS)
                if max_gap <= upper
            ),
            7,
        )
        minimum = min(
            minimum + max_gap - lower_bounds[bucket],
            RUNNER_WAKEUP_V10_U64_MAX,
        )
    return minimum


def _runner_wakeup_v10_histogram_max_valid(counts: Iterable[int], maximum: int) -> bool:
    counts = tuple(counts)
    bucket = next(
        (
            index
            for index, upper in enumerate(RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS)
            if maximum <= upper
        ),
        7,
    )
    return counts[bucket] > 0 and not any(counts[bucket + 1 :])


def _runner_wakeup_v10_histogram_interruption_minimum(
    counts: Iterable[int], maximum: int, interruptions: int
) -> int | None:
    counts = tuple(counts)
    high_guards = _runner_wakeup_v10_saturating_u64_sum(counts[1:])
    if interruptions < high_guards:
        return None
    histogram_minimum = _runner_wakeup_v10_histogram_minimum_interruption_nanoseconds(
        counts, maximum
    )
    return min(
        histogram_minimum + (interruptions - high_guards) * 50_001,
        RUNNER_WAKEUP_V10_U64_MAX,
    )


def _runner_wakeup_v10_subtract_histogram_maxima(
    counts: Iterable[int], maxima: Iterable[int]
) -> list[int] | None:
    """Remove the one per-guard histogram observation exposed by nested receipts."""

    residual = list(counts)
    for maximum in maxima:
        bucket = _runner_wakeup_v7_bucket(maximum)
        if residual[bucket] == 0:
            return None
        residual[bucket] -= 1
    return residual


def _runner_wakeup_v10_residual_histogram_minimum(
    counts: Iterable[int], *, aggregate_maximum: int, nested_maxima: Iterable[int], interruptions: int
) -> int | None:
    """Return the coupled duration floor after subtracting exact nested guard maxima."""

    nested = tuple(nested_maxima)
    residual = _runner_wakeup_v10_subtract_histogram_maxima(counts, nested)
    if residual is None:
        return None
    high_guards = _runner_wakeup_v10_saturating_u64_sum(residual[1:])
    if interruptions < high_guards:
        return None
    minimum = _runner_wakeup_v10_histogram_minimum_interruption_nanoseconds(residual, 0)
    if aggregate_maximum > 50_000 and aggregate_maximum > max(nested, default=0):
        bucket = _runner_wakeup_v7_bucket(aggregate_maximum)
        lower_bounds = (0, 50_001, 100_001, 250_001, 500_001, 1_000_001, 2_000_001, 5_000_001)
        if residual[bucket] == 0:
            return None
        minimum = min(
            minimum + aggregate_maximum - lower_bounds[bucket],
            RUNNER_WAKEUP_V10_U64_MAX,
        )
    return min(
        minimum + (interruptions - high_guards) * 50_001,
        RUNNER_WAKEUP_V10_U64_MAX,
    )


def _runner_wakeup_v10_residual_active_duration_minimum(
    dispatch_counts: Iterable[int], *, worst_dispatch_lateness: int, max_entry_lateness: int
) -> int | None:
    """Lower-bound active duration for successful guards omitted from the worst receipt."""

    residual = _runner_wakeup_v10_subtract_histogram_maxima(
        dispatch_counts, (worst_dispatch_lateness,)
    )
    if residual is None:
        return None
    lower_bounds = (0, 50_001, 100_001, 250_001, 500_001, 1_000_001, 2_000_001, 5_000_001)
    return _runner_wakeup_v10_saturating_u64_sum(
        count * max(4_999_000 + lower - max_entry_lateness, 0)
        for count, lower in zip(residual, lower_bounds, strict=True)
    )


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


def _diagnostics_match_contract(defense: str, diagnostics: dict[str, Any], *, buflo_period_us: int = 20_000) -> bool:
    if type(buflo_period_us) is not int or buflo_period_us not in {20_000, 64_000}:
        return False
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
    if defense == "buflo" and "buflo_incoming_startup" in selected:
        from .capture_acceptance_policy import validate_buflo_startup_receipt
        try:
            validate_buflo_startup_receipt(selected.pop("buflo_incoming_startup"), period_us=buflo_period_us)
        except ValueError:
            return False
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


def _scheduled_incoming_diagnostics_match(diagnostics: dict[str, Any], *, allowed_retired_bytes: int = 0) -> bool:
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
        and requested == consumed + allowed_retired_bytes
        and (advertised is None or requested == advertised)
        and retired == allowed_retired_bytes
        and unresolved == 0
    )


_ESTABLISHED_RUNTIME_KIND = {
    "static": "static",
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
}


def _current_exact_schedule_activation(
    schedule: Mapping[str, Any] | None,
    *,
    allow_empty: bool,
    allowed_partial_cells: int = 0,
) -> bool:
    """Require a complete current exact-event ledger, including a valid empty one.

    A zero-row schedule is meaningful only for adaptations such as WTF-PAD,
    where real traffic can activate the automaton without the sampled timer
    producing padding.  Fixed schedules must pass ``allow_empty=False``.
    """

    if not isinstance(schedule, Mapping):
        return False
    integer_fields = (
        "scheduled_events",
        "scheduled_outgoing_events",
        "scheduled_incoming_events",
        "satisfied_events",
        "missed_events",
        "outgoing_size_mismatch_events",
        "outgoing_size_absolute_error_bytes",
        "duplicate_terminal_slots",
        "invalid_terminal_rows",
        "invalid_typed_outcome_rows",
        "incoming_credit_missing_events",
        "incoming_credit_consumption_missing_events",
        "invalid_credit_advertisement_events",
        "invalid_credit_consumption_events",
    )
    if any(type(schedule.get(field)) is not int or schedule[field] < 0 for field in integer_fields):
        return False
    count = schedule["scheduled_events"]
    outgoing = schedule["scheduled_outgoing_events"]
    incoming = schedule["scheduled_incoming_events"]
    satisfactions = schedule.get("terminal_satisfactions")
    targets = schedule.get("target_times_us_by_direction")
    sizes = schedule.get("scheduled_sizes_by_direction")
    if (
        (count == 0 and not allow_empty)
        or outgoing + incoming != count
        or schedule["satisfied_events"] != count - allowed_partial_cells
        or schedule["missed_events"] != allowed_partial_cells
        or schedule["outgoing_size_mismatch_events"] != 0
        or schedule["outgoing_size_absolute_error_bytes"] != 0
        or schedule.get("terminal_slots_unique") is not True
        or schedule["duplicate_terminal_slots"] != 0
        or schedule["invalid_terminal_rows"] != 0
        or schedule["invalid_typed_outcome_rows"] != 0
        or schedule["incoming_credit_missing_events"] != 0
        or schedule["incoming_credit_consumption_missing_events"] != 0
        or schedule["invalid_credit_advertisement_events"] != 0
        or schedule["invalid_credit_consumption_events"] != 0
        or satisfactions != ({"satisfied": count - 1, "missed": 1} if allowed_partial_cells else ({"satisfied": count} if count else {}))
        or not isinstance(targets, Mapping)
        or set(targets) != {"outgoing", "incoming"}
        or not isinstance(sizes, Mapping)
        or set(sizes) != {"outgoing", "incoming"}
        or not _new_schedule_terminal_contract(schedule, congestion_sensitive=False)
    ):
        return False
    for direction, expected_count in (("outgoing", outgoing), ("incoming", incoming)):
        directional_targets = targets[direction]
        directional_sizes = sizes[direction]
        if (
            not isinstance(directional_targets, list)
            or len(directional_targets) != expected_count
            or any(type(value) is not int or value < 0 for value in directional_targets)
            or not isinstance(directional_sizes, list)
            or len(directional_sizes) != expected_count
            or any(type(value) is not int or value <= 0 for value in directional_sizes)
        ):
            return False
    return True


def _established_defense_activation_valid(
    defense: str,
    diagnostics: Mapping[str, Any],
    schedule: Mapping[str, Any] | None,
    resolved_configuration: Mapping[str, Any] | None,
) -> bool:
    """Prove that an established mode processed traffic and realised its policy.

    Zero errors alone are not activation evidence.  This predicate binds the
    terminal counters to a current exact schedule and to the runner's resolved
    defence kind.  WTF-PAD deliberately permits zero sampled padding events,
    but only after a real packet has driven its silent-to-burst automaton.
    """

    runtime_kind = _ESTABLISHED_RUNTIME_KIND.get(defense)
    if runtime_kind is None or not isinstance(resolved_configuration, Mapping):
        return False
    resolved_defense = resolved_configuration.get("defense")
    maximum_udp = resolved_configuration.get("max_udp_payload_size")
    if (
        resolved_configuration.get("schema_version") != 2
        or type(maximum_udp) is not int
        or maximum_udp <= 0
        or not isinstance(resolved_defense, Mapping)
        or resolved_defense.get("kind") != runtime_kind
    ):
        return False

    allow_empty = defense in {"traffic-morphing", "wtf-pad"}
    allowance = _terminal_primary_partial_allowance(defense, schedule)
    if allowance is None:
        return False
    partial, retired = allowance
    if not _current_exact_schedule_activation(schedule, allow_empty=allow_empty, allowed_partial_cells=partial):
        return False
    assert isinstance(schedule, Mapping)
    sizes = schedule["scheduled_sizes_by_direction"]
    targets = schedule["target_times_us_by_direction"]
    incoming_sizes = sizes["incoming"]
    outgoing_sizes = sizes["outgoing"]
    if (
        any(value > maximum_udp for value in (*incoming_sizes, *outgoing_sizes))
        or diagnostics.get("scheduled_incoming_requested_bytes") != sum(incoming_sizes)
        or diagnostics.get("scheduled_incoming_advertised_bytes") != sum(incoming_sizes)
        or diagnostics.get("scheduled_incoming_consumed_bytes") != sum(incoming_sizes) - retired
    ):
        return False

    if defense == "static":
        return (
            resolved_defense.get("padding_only") is True
            and isinstance(resolved_defense.get("schedule"), str)
            and bool(resolved_defense["schedule"])
            and schedule["scheduled_events"] > 0
        )

    if defense == "front":
        client_maximum = resolved_defense.get("n_client_packets")
        server_maximum = resolved_defense.get("n_server_packets")
        packet_size = resolved_defense.get("packet_size")
        return (
            type(client_maximum) is int
            and type(server_maximum) is int
            and type(packet_size) is int
            and 1 <= schedule["scheduled_outgoing_events"] <= client_maximum
            and 1 <= schedule["scheduled_incoming_events"] <= server_maximum
            and packet_size <= maximum_udp
            and all(value == packet_size for value in (*incoming_sizes, *outgoing_sizes))
        )

    if defense == "tamaraw":
        incoming_interval = resolved_defense.get("incoming_interval_us")
        outgoing_interval = resolved_defense.get("outgoing_interval_us")
        packet_size = resolved_defense.get("packet_size")
        modulo = resolved_defense.get("modulo")
        if (
            type(incoming_interval) is not int
            or type(outgoing_interval) is not int
            or type(packet_size) is not int
            or type(modulo) is not int
            or min(incoming_interval, outgoing_interval, packet_size, modulo) <= 0
            or packet_size > maximum_udp
            or any(value != packet_size for value in (*incoming_sizes, *outgoing_sizes))
        ):
            return False
        for direction, interval in (
            ("incoming", incoming_interval),
            ("outgoing", outgoing_interval),
        ):
            count = schedule[f"scheduled_{direction}_events"]
            if count < modulo or count % modulo or sorted(targets[direction]) != [
                index * interval for index in range(count)
            ]:
                return False
        return True

    if defense == "traffic-morphing":
        packets = diagnostics.get("morphing_egress_packets")
        source_bytes = diagnostics.get("morphing_egress_source_bytes")
        target_bytes = diagnostics.get("morphing_egress_target_bytes")
        requested = diagnostics.get("morphing_ingress_requested_bytes")
        received = diagnostics.get("morphing_ingress_received_bytes")
        return (
            isinstance(resolved_defense.get("matrix"), str)
            and bool(resolved_defense["matrix"])
            and isinstance(resolved_defense.get("workload_id"), str)
            and bool(resolved_defense["workload_id"])
            and type(packets) is int
            and packets > 0
            and type(source_bytes) is int
            and packets <= source_bytes <= packets * maximum_udp
            and type(target_bytes) is int
            and source_bytes <= target_bytes <= packets * maximum_udp
            and schedule["scheduled_outgoing_events"] == 0
            and requested == sum(incoming_sizes)
            and received == sum(incoming_sizes)
        )

    if defense == "wtf-pad":
        packet_size = resolved_defense.get("packet_size")
        maximum_events = resolved_defense.get("max_padding_events")
        padding_events = diagnostics.get("padding_events")
        incoming_desired = diagnostics.get("wtf_pad_incoming_desired_bytes")
        incoming_requested = diagnostics.get("wtf_pad_incoming_requested_bytes")
        incoming_received = diagnostics.get("wtf_pad_incoming_received_bytes")
        return (
            isinstance(resolved_defense.get("histograms"), str)
            and bool(resolved_defense["histograms"])
            and type(packet_size) is int
            and 0 < packet_size <= maximum_udp
            and type(maximum_events) is int
            and maximum_events > 0
            and type(padding_events) is int
            and 0 <= padding_events <= maximum_events
            and schedule["scheduled_events"] == padding_events
            and all(value == packet_size for value in (*incoming_sizes, *outgoing_sizes))
            and incoming_desired == sum(incoming_sizes)
            and incoming_requested == sum(incoming_sizes)
            and incoming_received == sum(incoming_sizes)
            and type(diagnostics.get("wtf_pad_silent_to_burst")) is int
            and diagnostics["wtf_pad_silent_to_burst"] > 0
        )

    if defense != "walkie-talkie":
        return False
    packet_size = resolved_defense.get("packet_size")
    expected_batches = diagnostics.get("walkie_talkie_expected_application_batches")
    realization = diagnostics.get("walkie_talkie_burst_realization")
    target_outgoing = diagnostics.get("walkie_talkie_target_outgoing_cells")
    target_incoming = diagnostics.get("walkie_talkie_target_incoming_cells")
    observed_outgoing = diagnostics.get("walkie_talkie_observed_outgoing_cells")
    observed_incoming = diagnostics.get("walkie_talkie_observed_incoming_cells")
    return (
        isinstance(resolved_defense.get("molded"), str)
        and bool(resolved_defense["molded"])
        and isinstance(resolved_defense.get("workload_id"), str)
        and bool(resolved_defense["workload_id"])
        and type(packet_size) is int
        and 0 < packet_size <= maximum_udp
        and all(value == packet_size for value in (*incoming_sizes, *outgoing_sizes))
        and type(expected_batches) is int
        and expected_batches > 0
        and isinstance(realization, list)
        and len(realization) == expected_batches
        and type(target_outgoing) is int
        and type(target_incoming) is int
        and target_outgoing > 0
        and target_incoming > 0
        and schedule["scheduled_outgoing_events"] == target_outgoing
        and schedule["scheduled_incoming_events"] == target_incoming
        and target_outgoing == observed_outgoing
        and target_incoming == observed_incoming
        and sum(item["target_outgoing_cells"] for item in realization) == target_outgoing
        and sum(item["target_incoming_cells"] for item in realization) == target_incoming
        and sum(item["observed_outgoing_cells"] for item in realization) == observed_outgoing
        and sum(item["observed_incoming_cells"] for item in realization) == observed_incoming
        and diagnostics.get("walkie_talkie_natural_outgoing_bytes", 0) > 0
        and diagnostics.get("walkie_talkie_natural_incoming_bytes", 0) > 0
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
    runner_directory: Path | None = None,
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
    try:
        buflo_period_us = _buflo_run_period_us(run) if defense_kind == "buflo" else 20_000
    except (ValueError, TypeError, KeyError):
        return False
    resolved = run.get("resolved_configuration")
    resolved_defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    diagnostics = run.get("defense_diagnostics")
    if (
        run.get("completion_status") != "complete"
        or run.get("error") is not None
        or run.get("error_class") is not None
        or not terminal_evidence_render_receipt_valid(
            run,
            require_present=require_current_schema,
            require_empty=True,
        )
        or not isinstance(resolved, Mapping)
        or resolved.get("schema_version") != 2
        or not isinstance(resolved_defense, Mapping)
        or resolved_defense.get("kind") != defense_kind
        or not isinstance(diagnostics, dict)
        or not _diagnostics_match_contract(canonical, diagnostics, buflo_period_us=buflo_period_us)
        or not _runner_wakeup_metrics_valid(run.get("runner_wakeup_metrics"))
    ):
        return False
    wakeup_metrics = run["runner_wakeup_metrics"]
    current_runner_schemas = {17, 18, 19, 20, 21, 22} if defense_kind == "buflo" else {10}
    if require_current_schema and wakeup_metrics["schema_version"] not in current_runner_schemas:
        return False
    if (
        wakeup_metrics["schema_version"] in {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
        and defense_kind != "buflo"
        and wakeup_metrics["buflo_kernel_tx"] is not None
    ):
        return False
    if (
        wakeup_metrics["schema_version"]
        in {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
        and defense_kind != "buflo"
        and any(
            wakeup_metrics[key]
            for key in (
                "buflo_exact_release_guard_entries",
                "buflo_exact_release_guard_wait_nanoseconds",
                "buflo_exact_release_active_wait_nanoseconds",
                "buflo_exact_release_max_passive_wake_lateness_nanoseconds",
                "buflo_exact_release_max_guard_exit_lateness_nanoseconds",
            )
        )
    ):
        return False
    if (
        wakeup_metrics["schema_version"]
        in {5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
        and defense_kind != "buflo"
        and any(
            wakeup_metrics[key]
            for key in (
                "buflo_exact_incoming_retry_drives",
                "buflo_exact_incoming_retry_resolutions",
                "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
            )
        )
    ):
        return False
    if (
        wakeup_metrics["schema_version"]
        in {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
        and defense_kind != "cs_buflo"
        and any(
            wakeup_metrics[key]
            for key in (
                "cs_exact_incoming_retry_drives",
                "cs_exact_incoming_retry_resolutions",
                "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
            )
        )
    ):
        return False
    if wakeup_metrics["schema_version"] in {7, 8, 9, 10} and defense_kind == "buflo":
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
    if wakeup_metrics["schema_version"] in {9, 10} and defense_kind == "buflo":
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
    if (
        wakeup_metrics["schema_version"] in {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
        and defense_kind == "buflo"
    ):
        scheduled_outgoing = diagnostics.get("buflo_scheduled_outgoing_cells")
        kernel_tx = wakeup_metrics.get("buflo_kernel_tx")
        if (
            type(scheduled_outgoing) is not int
            or scheduled_outgoing <= 0
            or not kernel_tx_runner_receipt_success_valid(kernel_tx)
            or not kernel_tx_incoming_window_bound_to_run_valid(run)
            or kernel_tx["aggregate"]["job_count"] != scheduled_outgoing
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
    incoming_startup = None
    from .capture_acceptance_policy import ACK_START_POLICY, CADENCE64_ACK_START_POLICY, FIELD, validate_buflo_startup_evidence
    marker = run.get(FIELD)
    if isinstance(marker, Mapping) and marker.get("policy") in {ACK_START_POLICY, CADENCE64_ACK_START_POLICY}:
        if defense_kind != "buflo" or summary_schema != 4:
            return False
        try:
            incoming_startup = validate_buflo_startup_evidence(run, runner_directory=runner_directory)
        except (OSError, ValueError, TypeError, KeyError):
            return False
        expected_fields.add("incoming_startup")
        if diagnostics.get("buflo_incoming_startup") != incoming_startup:
            return False
    elif "buflo_incoming_startup" in diagnostics:
        return False
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
            and buflo_terminal_diagnostics_valid(selected, require_current=stop_drain_current,
                                                  incoming_startup=incoming_startup, buflo_period_us=buflo_period_us)
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
        or type(value.get("phase")) is not str
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
        or type(value.get("outcome")) is not str
        or value.get("outcome") not in RUNNER_WAKEUP_V9_FAILURE_COUNTER_BY_OUTCOME
        or type(value.get("phase")) is not str
        or value.get("phase") not in {"prearmed", "committed"}
        or value.get("dispatch_at_defense_nanoseconds") is not None
        or type(value.get("exit_at_or_after_deadline")) is not bool
        or type(value.get("active_wait_poll_source")) is not str
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
        or type(value.get("phase")) is not str
        or value.get("phase") not in {"prearmed", "committed"}
        or type(value.get("dispatch_at_or_after_deadline")) is not bool
        or type(value.get("active_wait_poll_source")) is not str
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
        or type(value.get("buflo_exact_release_active_wait_poll_source")) is not str
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


def _runner_wakeup_v10_project_schema_nine(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project additive schema-ten telemetry onto the frozen schema-nine contract."""

    projected = dict(value)
    for key in RUNNER_WAKEUP_V10_NEW_INTEGER_KEYS:
        projected.pop(key, None)
    projected.update(
        {
            "schema_version": 9,
            "semantics": RUNNER_WAKEUP_V9_SEMANTICS,
        }
    )
    projected["timer_wakeups"] = (
        value["controller_deadline_timer_wakeups"] + value["other_timer_wakeups"]
    )
    projected["wait_returns"] = value["socket_readiness_wakeups"] + projected["timer_wakeups"]
    for histogram_key, expected_total in (
        (
            "buflo_exact_release_dispatch_lateness_histogram",
            value["buflo_exact_release_dispatch_ready_guards"],
        ),
        (
            "buflo_exact_release_active_spin_gap_histogram",
            value["buflo_exact_release_guard_entries"],
        ),
    ):
        histogram = dict(value[histogram_key])
        counts = list(histogram["counts"])
        excess = sum(counts) - expected_total
        for index, count in enumerate(counts):
            reduction = min(max(count - 1, 0), max(excess, 0))
            counts[index] -= reduction
            excess -= reduction
        histogram["counts"] = counts
        projected[histogram_key] = histogram
    if projected.get("buflo_exact_release_active_wait_poll_source") == (
        "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
    ):
        projected["buflo_exact_release_active_wait_poll_source"] = (
            "linux-aarch64-cntvct-el0-predictive-v1"
        )
    worst = projected.get("buflo_exact_release_worst_guard")
    if isinstance(worst, Mapping):
        projected_worst = dict(worst)
        for key in RUNNER_WAKEUP_V10_WORST_NEW_INTEGER_KEYS:
            projected_worst.pop(key, None)
        if projected_worst.get("active_wait_poll_source") == (
            "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
        ):
            projected_worst["active_wait_poll_source"] = "linux-aarch64-cntvct-el0-predictive-v1"
        projected["buflo_exact_release_worst_guard"] = projected_worst
    failure = projected.get("buflo_exact_release_last_failure")
    if isinstance(failure, Mapping):
        projected_failure = dict(failure)
        for key in RUNNER_WAKEUP_V10_FAILURE_NEW_INTEGER_KEYS:
            projected_failure.pop(key, None)
        if projected_failure.get("active_wait_poll_source") == (
            "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
        ):
            projected_failure["active_wait_poll_source"] = "linux-aarch64-cntvct-el0-predictive-v1"
        projected["buflo_exact_release_last_failure"] = projected_failure
    return projected


def _runner_wakeup_v10_u64_domain_valid(value: Mapping[str, Any]) -> bool:
    """Bind every schema-ten Rust integer field to its serialised u64 domain."""

    aggregate_u64_keys = set(value) - RUNNER_WAKEUP_V9_OBJECT_KEYS - {"schema_version", "semantics"}
    if any(
        type(value.get(key)) is not int or not 0 <= value[key] <= RUNNER_WAKEUP_V10_U64_MAX
        for key in aggregate_u64_keys
    ):
        return False
    for histogram_key in (
        "buflo_exact_release_dispatch_lateness_histogram",
        "buflo_exact_release_active_spin_gap_histogram",
    ):
        histogram = value.get(histogram_key)
        counts = histogram.get("counts") if isinstance(histogram, Mapping) else None
        if not isinstance(counts, list) or any(
            type(count) is not int or not 0 <= count <= RUNNER_WAKEUP_V10_U64_MAX
            for count in counts
        ):
            return False

    worst = value.get("buflo_exact_release_worst_guard")
    if isinstance(worst, Mapping):
        worst_integer_keys = (
            RUNNER_WAKEUP_V7_WORST_INTEGER_KEYS
            | RUNNER_WAKEUP_V9_WORST_COUNTER_INTEGER_KEYS
            | RUNNER_WAKEUP_V10_WORST_NEW_INTEGER_KEYS
        )
        if any(
            type(worst.get(key)) is not int or not 0 <= worst[key] <= RUNNER_WAKEUP_V10_U64_MAX
            for key in worst_integer_keys
        ):
            return False
        if any(
            worst.get(key) is not None
            and (type(worst[key]) is not int or not 0 <= worst[key] <= RUNNER_WAKEUP_V10_U64_MAX)
            for key in RUNNER_WAKEUP_V7_WORST_TIME_KEYS
            | RUNNER_WAKEUP_V9_WORST_COUNTER_NULLABLE_KEYS
        ):
            return False

    failure = value.get("buflo_exact_release_last_failure")
    if isinstance(failure, Mapping):
        failure_integer_keys = (
            RUNNER_WAKEUP_V9_FAILURE_INTEGER_KEYS | RUNNER_WAKEUP_V10_FAILURE_NEW_INTEGER_KEYS
        )
        if any(
            type(failure.get(key)) is not int or not 0 <= failure[key] <= RUNNER_WAKEUP_V10_U64_MAX
            for key in failure_integer_keys
        ):
            return False
        if any(
            failure.get(key) is not None
            and (
                type(failure[key]) is not int or not 0 <= failure[key] <= RUNNER_WAKEUP_V10_U64_MAX
            )
            for key in RUNNER_WAKEUP_V9_FAILURE_TIME_KEYS
            | RUNNER_WAKEUP_V9_FAILURE_COUNTER_NULLABLE_KEYS
            | {"dispatch_at_defense_nanoseconds"}
        ):
            return False
    return True


def _runner_wakeup_v10_failure_minimum_iterations(value: Mapping[str, Any]) -> int:
    """Return the counter-read lower bound exposed by one typed failure."""

    calibrations = value["counter_calibrations"]
    checks = value["authoritative_watchdog_checks"]
    outcome = value["outcome"]
    terminal_failure_reads = {
        "invalid-counter-frequency": 0,
        "counter-unavailable": 1,
        "counter-nonmonotonic": 2 if calibrations == 0 else 1,
        "counter-frequency-changed": 0,
        "counter-target-error": 0,
    }[outcome]
    return calibrations * 2 + checks * 64 + terminal_failure_reads


def _runner_wakeup_v10_failure_iterations_valid(
    value: Mapping[str, Any],
    *,
    iterations: int,
) -> bool:
    """Validate one isolated failure's exact watchdog cadence and terminal reads."""

    calibrations = value["counter_calibrations"]
    confirmations = value["instant_confirmations"]
    checks = value["authoritative_watchdog_checks"]
    outcome = value["outcome"]
    if outcome == "invalid-counter-frequency":
        return iterations == 0
    if outcome == "counter-unavailable" and calibrations == 0:
        return iterations in {1, 2}
    if outcome == "counter-nonmonotonic" and calibrations == 0:
        return iterations == 2
    if outcome == "counter-target-error" and value["early_confirmation_retries"] == 0:
        return iterations == 2
    terminal_read_options = {
        "invalid-counter-frequency": (0,),
        "counter-unavailable": ((1,) if calibrations == confirmations + 1 else (1, 2)),
        "counter-nonmonotonic": (
            (2,) if calibrations == 0 else (1,) if calibrations == confirmations + 1 else (1, 2)
        ),
        "counter-frequency-changed": (0,),
        "counter-target-error": (0,),
    }[outcome]
    calibration_reads = _runner_wakeup_v10_checked_u64_product(calibrations, 2)
    watchdog_reads = _runner_wakeup_v10_checked_u64_product(checks, 64)
    if calibration_reads is None or watchdog_reads is None:
        return False
    for terminal_reads in terminal_read_options:
        relaxed_reads = iterations - calibration_reads - terminal_reads
        if (
            relaxed_reads >= 0
            and relaxed_reads >= value["early_confirmation_retries"]
            and checks == relaxed_reads // 64
            and (value["authoritative_watchdog_dispatches"] == 0 or relaxed_reads % 64 == 0)
        ):
            return True
    return False


def _runner_wakeup_v10_failure_elapsed_nanoseconds(value: Mapping[str, Any]) -> int | None:
    """Recover a failure's active duration when relative chronology is present."""

    times = [value[key] for key in RUNNER_WAKEUP_V9_FAILURE_TIME_KEYS]
    if not all(type(item) is int for item in times):
        return None
    return (
        value["exited_at_defense_nanoseconds"] - value["active_wait_started_at_defense_nanoseconds"]
    )


def _runner_wakeup_v10_success_duration_valid(value: Mapping[str, Any]) -> bool:
    """Bind exact active duration even when relative chronology is unavailable."""

    duration = value["active_wait_monotonic_nanoseconds"]
    entry_lateness = value["guard_entry_lateness_nanoseconds"]
    dispatch_lateness = value["dispatch_lateness_nanoseconds"]
    for window in (4_999_000, 5_000_000):
        elapsed_from_guard = _runner_wakeup_v10_checked_u64_sum(window, dispatch_lateness)
        if (
            elapsed_from_guard is not None
            and elapsed_from_guard >= entry_lateness
            and duration == elapsed_from_guard - entry_lateness
        ):
            return True
    return False


def _runner_wakeup_v10_failure_duration_valid(value: Mapping[str, Any]) -> bool:
    """Bind failure duration to its release/deadline classification without timestamps."""

    elapsed_from_guard = _runner_wakeup_v10_checked_u64_sum(
        value["guard_entry_lateness_nanoseconds"],
        value["active_wait_monotonic_nanoseconds"],
    )
    if elapsed_from_guard is None:
        return False
    return any(
        value["exit_before_release_nanoseconds"] == max(window - elapsed_from_guard, 0)
        and value["exit_at_or_after_deadline"] is (elapsed_from_guard >= 2 * window)
        for window in (4_999_000, 5_000_000)
    )


def _runner_wakeup_v10_worst_guard_valid(
    value: Any,
    *,
    metrics: Mapping[str, Any],
) -> bool:
    """Validate additive watchdog evidence for the worst successful guard."""

    dispatch_ready = metrics["buflo_exact_release_dispatch_ready_guards"]
    if dispatch_ready == 0:
        return value is None
    if not isinstance(value, Mapping) or set(value) != RUNNER_WAKEUP_V10_WORST_KEYS:
        return False
    if any(
        type(value.get(key)) is not int or value[key] < 0
        for key in RUNNER_WAKEUP_V10_WORST_NEW_INTEGER_KEYS
    ):
        return False
    checks = value["active_wait_authoritative_watchdog_checks"]
    dispatches = value["active_wait_authoritative_watchdog_dispatches"]
    calibrations = value["active_wait_counter_calibrations"]
    iterations = value["active_wait_iterations"]
    relaxed_reads = iterations - 2 * calibrations
    sample_gap = value["max_authoritative_sample_gap_nanoseconds"]
    counter_lag = value["max_authoritative_counter_lag_nanoseconds"]
    counter_lead = value["max_counter_authoritative_lead_nanoseconds"]
    counter_nanoseconds = value["active_wait_counter_nanoseconds"]
    active_wait = value["active_wait_monotonic_nanoseconds"]
    aggregate_bounds = {
        "active_wait_iterations": "buflo_exact_release_active_wait_iterations",
        "active_wait_monotonic_nanoseconds": "buflo_exact_release_active_wait_nanoseconds",
        "active_spin_interruptions": "buflo_exact_release_active_spin_interruptions",
        "active_spin_interruption_nanoseconds": (
            "buflo_exact_release_active_spin_interruption_nanoseconds"
        ),
        "max_active_spin_gap_nanoseconds": (
            "buflo_exact_release_max_active_spin_gap_nanoseconds"
        ),
        "active_wait_authoritative_watchdog_checks": (
            "buflo_exact_release_active_wait_authoritative_watchdog_checks"
        ),
        "active_wait_authoritative_watchdog_dispatches": (
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches"
        ),
        "max_authoritative_sample_gap_nanoseconds": (
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds"
        ),
        "max_authoritative_counter_lag_nanoseconds": (
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds"
        ),
        "max_counter_authoritative_lead_nanoseconds": (
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds"
        ),
    }
    if (
        dispatches > checks
        or dispatches > 1
        or dispatches > value["active_wait_instant_confirmations"]
        or sample_gap > value["active_wait_monotonic_nanoseconds"]
        or counter_lag > value["active_wait_monotonic_nanoseconds"]
        or counter_lead > (counter_nanoseconds or 0)
        or any(value[nested] > metrics[aggregate] for nested, aggregate in aggregate_bounds.items())
        or not _runner_wakeup_v10_success_duration_valid(value)
        or value["active_spin_interruptions"] > 0
        and value["active_spin_interruption_nanoseconds"]
        < min(
            value["max_active_spin_gap_nanoseconds"]
            + (value["active_spin_interruptions"] - 1) * 50_001,
            RUNNER_WAKEUP_V10_U64_MAX,
        )
    ):
        return False
    if value["active_wait_poll_source"] == (
        "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
    ):
        if (
            relaxed_reads < 0
            or checks != relaxed_reads // 64
            or relaxed_reads < value["active_wait_early_confirmation_retries"]
            or value["active_wait_early_confirmation_retries"] > 0
            and (counter_nanoseconds or 0) == 0
            or value["active_spin_interruptions"] > max(iterations - 1, 0)
            or value["active_spin_interruption_nanoseconds"]
            < _runner_wakeup_v10_minimum_interruption_nanoseconds(
                value["active_spin_interruptions"]
            )
            or (value["active_spin_interruptions"] > 0)
            != (value["max_active_spin_gap_nanoseconds"] > 50_000)
            or value["max_active_spin_gap_nanoseconds"] > active_wait
            or value["active_spin_interruptions"] > 0
            and value["active_spin_interruption_nanoseconds"]
            < min(
                value["max_active_spin_gap_nanoseconds"]
                + (value["active_spin_interruptions"] - 1) * 50_001,
                RUNNER_WAKEUP_V10_U64_MAX,
            )
            or value["active_spin_interruption_nanoseconds"] > (counter_nanoseconds or 0)
            or (dispatches > 0 and relaxed_reads % 64 != 0)
        ):
            return False
    elif any(value[key] for key in RUNNER_WAKEUP_V10_WORST_NEW_INTEGER_KEYS):
        return False
    if dispatch_ready == 1 and metrics["buflo_exact_release_failed_guards"] == 0:
        counter_nanoseconds = value["active_wait_counter_nanoseconds"] or 0
        max_counter_gap = value["max_active_wait_counter_gap_nanoseconds"] or 0
        max_calibration_span = value["max_counter_calibration_span_nanoseconds"] or 0
        exact_aggregate_values = {
            "buflo_exact_release_guard_wait_nanoseconds": active_wait,
            "buflo_exact_release_active_wait_nanoseconds": active_wait,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": value[
                "guard_entry_lateness_nanoseconds"
            ],
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": value[
                "guard_entry_lateness_nanoseconds"
            ],
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": value[
                "dispatch_lateness_nanoseconds"
            ],
            "buflo_exact_release_passive_sleep_calls": value["passive_sleep_calls"],
            "buflo_exact_release_passive_sleep_requested_nanoseconds": value[
                "passive_sleep_requested_nanoseconds"
            ],
            "buflo_exact_release_passive_sleep_elapsed_nanoseconds": value[
                "passive_sleep_elapsed_nanoseconds"
            ],
            "buflo_exact_release_max_passive_sleep_overrun_nanoseconds": value[
                "max_passive_sleep_overrun_nanoseconds"
            ],
            "buflo_exact_release_active_wait_iterations": iterations,
            "buflo_exact_release_active_spin_interruptions": value["active_spin_interruptions"],
            "buflo_exact_release_active_spin_interruption_nanoseconds": value[
                "active_spin_interruption_nanoseconds"
            ],
            "buflo_exact_release_max_active_spin_gap_nanoseconds": value[
                "max_active_spin_gap_nanoseconds"
            ],
            "buflo_exact_release_active_wait_counter_calibrations": calibrations,
            "buflo_exact_release_active_wait_instant_confirmations": value[
                "active_wait_instant_confirmations"
            ],
            "buflo_exact_release_active_wait_early_confirmation_retries": value[
                "active_wait_early_confirmation_retries"
            ],
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": checks,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": dispatches,
            "buflo_exact_release_active_wait_counter_nanoseconds": counter_nanoseconds,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": max_counter_gap,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": (max_calibration_span),
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": sample_gap,
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": counter_lag,
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": counter_lead,
            "buflo_exact_release_dispatch_at_or_after_deadline_guards": int(
                value["dispatch_at_or_after_deadline"]
            ),
        }
        if (
            metrics["buflo_exact_release_active_wait_poll_source"]
            != value["active_wait_poll_source"]
            or metrics["buflo_exact_release_active_wait_counter_frequency_hz"]
            != value["active_wait_counter_frequency_hz"]
            or any(metrics[key] != expected for key, expected in exact_aggregate_values.items())
        ):
            return False
    return True


def _runner_wakeup_v10_last_failure_valid(
    value: Any,
    *,
    metrics: Mapping[str, Any],
) -> bool:
    """Validate additive watchdog evidence retained by one typed wait failure."""

    failed = metrics["buflo_exact_release_failed_guards"]
    if failed == 0:
        return value is None
    if (
        failed != 1
        or not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V10_FAILURE_KEYS
    ):
        return False
    if any(
        type(value.get(key)) is not int or value[key] < 0
        for key in RUNNER_WAKEUP_V10_FAILURE_NEW_INTEGER_KEYS
    ):
        return False
    checks = value["authoritative_watchdog_checks"]
    dispatches = value["authoritative_watchdog_dispatches"]
    sample_gap = value["max_authoritative_sample_gap_nanoseconds"]
    counter_lag = value["max_authoritative_counter_lag_nanoseconds"]
    counter_lead = value["max_counter_authoritative_lead_nanoseconds"]
    counter_nanoseconds = value["counter_nanoseconds"]
    aggregate_bounds = {
        "authoritative_watchdog_checks": (
            "buflo_exact_release_active_wait_authoritative_watchdog_checks"
        ),
        "authoritative_watchdog_dispatches": (
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches"
        ),
        "max_authoritative_sample_gap_nanoseconds": (
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds"
        ),
        "max_authoritative_counter_lag_nanoseconds": (
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds"
        ),
        "max_counter_authoritative_lead_nanoseconds": (
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds"
        ),
    }
    if (
        dispatches > checks
        or dispatches > 1
        or dispatches > value["instant_confirmations"]
        or (dispatches > 0 and value.get("outcome") != "counter-frequency-changed")
        or counter_lead > (counter_nanoseconds or 0)
        or any(value[nested] > metrics[aggregate] for nested, aggregate in aggregate_bounds.items())
        or checks * 64 + value["counter_calibrations"] * 2 > value["active_wait_iterations"]
        or value["active_spin_interruption_nanoseconds"]
        < _runner_wakeup_v10_minimum_interruption_nanoseconds(
            value["active_spin_interruptions"]
        )
        or value["active_spin_interruption_nanoseconds"]
        > value["active_wait_monotonic_nanoseconds"]
        or (value["active_spin_interruptions"] == 0)
        != (value["active_spin_interruption_nanoseconds"] == 0)
        or (value["active_spin_interruptions"] > 0)
        != (value["max_active_spin_gap_nanoseconds"] > 50_000)
        or value["max_active_spin_gap_nanoseconds"]
        > value["active_wait_monotonic_nanoseconds"]
        or value["active_spin_interruptions"] > 0
        and value["max_active_spin_gap_nanoseconds"]
        > value["active_spin_interruption_nanoseconds"]
        or value["active_spin_interruptions"] > 0
        and value["active_spin_interruption_nanoseconds"]
        < min(
            value["max_active_spin_gap_nanoseconds"]
            + (value["active_spin_interruptions"] - 1) * 50_001,
            RUNNER_WAKEUP_V10_U64_MAX,
        )
        or value["active_spin_interruption_nanoseconds"] > (counter_nanoseconds or 0)
        or value["active_wait_poll_source"]
        == "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
        and value["max_active_spin_gap_nanoseconds"]
        != (value["max_counter_gap_nanoseconds"] or 0)
        or not _runner_wakeup_v10_failure_duration_valid(value)
    ):
        return False
    times = [value[key] for key in RUNNER_WAKEUP_V9_FAILURE_TIME_KEYS]
    if all(type(item) is int for item in times):
        active_elapsed = (
            value["exited_at_defense_nanoseconds"]
            - value["active_wait_started_at_defense_nanoseconds"]
        )
        if (
            value["active_wait_monotonic_nanoseconds"] != active_elapsed
            or sample_gap > active_elapsed
            or counter_lag > active_elapsed
        ):
            return False
    elif (
        sample_gap > metrics["buflo_exact_release_active_wait_nanoseconds"]
        or counter_lag > metrics["buflo_exact_release_active_wait_nanoseconds"]
    ):
        return False
    if value.get("outcome") == "invalid-counter-frequency" and any(
        value[key]
        for key in RUNNER_WAKEUP_V10_FAILURE_NEW_INTEGER_KEYS
        if key
        not in {
            "active_wait_monotonic_nanoseconds",
            "max_authoritative_sample_gap_nanoseconds",
        }
    ):
        return False
    if (
        value.get("outcome") == "invalid-counter-frequency"
        and sample_gap != value["active_wait_monotonic_nanoseconds"]
    ):
        return False
    first_calibration_target_error = (
        value.get("outcome") == "counter-target-error" and value["early_confirmation_retries"] == 0
    )
    if checks == 0 and value["instant_confirmations"] == 0 and any((counter_lag, counter_lead)):
        return False
    if first_calibration_target_error and any((checks, dispatches, counter_lag, counter_lead)):
        return False
    if checks > 0 and (
        value["counter_calibrations"] == 0 or type(value.get("counter_frequency_hz")) is not int
    ):
        return False
    if value["early_confirmation_retries"] > 0 and (counter_nanoseconds or 0) == 0:
        return False
    minimum_iterations = _runner_wakeup_v10_failure_minimum_iterations(value)
    if value["active_wait_iterations"] < minimum_iterations:
        return False
    if not _runner_wakeup_v10_failure_iterations_valid(
        value, iterations=value["active_wait_iterations"]
    ):
        return False
    terminal_no_gap_reads = int(
        value["outcome"] in {"counter-unavailable", "counter-nonmonotonic"}
    )
    if value["active_spin_interruptions"] > max(
        value["active_wait_iterations"] - 1 - terminal_no_gap_reads, 0
    ):
        return False
    singleton_failure = (
        metrics["buflo_exact_release_guard_entries"] == 1
        and metrics["buflo_exact_release_dispatch_ready_guards"] == 0
        and failed == 1
    )
    if singleton_failure:
        exact_aggregate_values = {
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": value[
                "guard_entry_lateness_nanoseconds"
            ],
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": value[
                "guard_entry_lateness_nanoseconds"
            ],
            "buflo_exact_release_active_wait_counter_calibrations": value["counter_calibrations"],
            "buflo_exact_release_active_wait_iterations": value["active_wait_iterations"],
            "buflo_exact_release_active_wait_nanoseconds": value[
                "active_wait_monotonic_nanoseconds"
            ],
            "buflo_exact_release_active_spin_interruptions": value[
                "active_spin_interruptions"
            ],
            "buflo_exact_release_active_spin_interruption_nanoseconds": value[
                "active_spin_interruption_nanoseconds"
            ],
            "buflo_exact_release_max_active_spin_gap_nanoseconds": value[
                "max_active_spin_gap_nanoseconds"
            ],
            "buflo_exact_release_active_wait_instant_confirmations": value["instant_confirmations"],
            "buflo_exact_release_active_wait_early_confirmation_retries": value[
                "early_confirmation_retries"
            ],
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": checks,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": dispatches,
            "buflo_exact_release_active_wait_counter_nanoseconds": counter_nanoseconds or 0,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": value[
                "max_counter_gap_nanoseconds"
            ]
            or 0,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": value[
                "max_counter_calibration_span_nanoseconds"
            ]
            or 0,
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": sample_gap,
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": counter_lag,
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": counter_lead,
        }
        failure_elapsed = _runner_wakeup_v10_failure_elapsed_nanoseconds(value)
        if failure_elapsed is not None:
            exact_aggregate_values.update(
                {
                    "buflo_exact_release_guard_wait_nanoseconds": failure_elapsed,
                    "buflo_exact_release_active_wait_nanoseconds": failure_elapsed,
                }
            )
        if (
            metrics["buflo_exact_release_active_wait_counter_frequency_hz"]
            != value["counter_frequency_hz"]
            or any(metrics[key] != expected for key, expected in exact_aggregate_values.items())
            or first_calibration_target_error
            and metrics["buflo_exact_release_active_wait_iterations"] != 2
        ):
            return False
        if not _runner_wakeup_v10_failure_iterations_valid(
            value,
            iterations=value["active_wait_iterations"],
        ):
            return False
        failure_iterations = value["active_wait_iterations"]
        terminal_no_gap_reads = int(
            value["outcome"] in {"counter-unavailable", "counter-nonmonotonic"}
        )
        if metrics["buflo_exact_release_active_spin_interruptions"] > max(
            failure_iterations - 1 - terminal_no_gap_reads, 0
        ) or metrics[
            "buflo_exact_release_active_spin_interruption_nanoseconds"
        ] < _runner_wakeup_v10_minimum_interruption_nanoseconds(
            metrics["buflo_exact_release_active_spin_interruptions"]
        ) or metrics["buflo_exact_release_active_spin_interruption_nanoseconds"] > (
            value["counter_nanoseconds"] or 0
        ):
            return False
    return True


def _runner_wakeup_v10_relative_chronology_available(value: Any) -> bool:
    """Require schema-ten relative guard times when a defence start is present."""

    if not isinstance(value, Mapping) or value.get("schema_version") != 10:
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


def _runner_wakeup_v10_valid(value: Any) -> bool:
    """Validate the watchdog-bounded predictive-counter receipt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V10_REQUIRED_KEYS
        or value.get("schema_version") != 10
        or value.get("semantics") != RUNNER_WAKEUP_V10_SEMANTICS
        or not _runner_wakeup_v10_u64_domain_valid(value)
        or any(
            type(value.get(key)) is not int or value[key] < 0
            for key in RUNNER_WAKEUP_V10_NEW_INTEGER_KEYS
        )
        or type(value.get("buflo_exact_release_active_wait_poll_source")) is not str
        or value.get("buflo_exact_release_active_wait_poll_source")
        not in RUNNER_WAKEUP_V10_POLL_SOURCES
        or value["timer_wakeups"]
        != _runner_wakeup_v10_saturating_u64_sum(
            (
                value["controller_deadline_timer_wakeups"],
                value["other_timer_wakeups"],
            )
        )
        or value["wait_returns"]
        != _runner_wakeup_v10_saturating_u64_sum(
            (value["socket_readiness_wakeups"], value["timer_wakeups"])
        )
        or value["buflo_exact_incoming_retry_drives"] == 0
        and value["buflo_exact_incoming_retry_max_wake_lateness_nanoseconds"] != 0
        or _runner_wakeup_v10_saturating_u64_sum(
            value["buflo_exact_release_dispatch_lateness_histogram"]["counts"]
        )
        != value["buflo_exact_release_dispatch_ready_guards"]
        or _runner_wakeup_v10_saturating_u64_sum(
            value["buflo_exact_release_active_spin_gap_histogram"]["counts"]
        )
        != value["buflo_exact_release_guard_entries"]
        or not _runner_wakeup_v9_valid(_runner_wakeup_v10_project_schema_nine(value))
        or not _runner_wakeup_v10_worst_guard_valid(
            value.get("buflo_exact_release_worst_guard"), metrics=value
        )
        or not _runner_wakeup_v10_last_failure_valid(
            value.get("buflo_exact_release_last_failure"), metrics=value
        )
    ):
        return False
    entries = value["buflo_exact_release_guard_entries"]
    dispatch_ready = value["buflo_exact_release_dispatch_ready_guards"]
    frequency_changed = value["buflo_exact_release_counter_frequency_changed_guards"]
    counter_guards = value["buflo_exact_release_active_wait_counter_guards"]
    iterations = value["buflo_exact_release_active_wait_iterations"]
    calibrations = value["buflo_exact_release_active_wait_counter_calibrations"]
    checks = value["buflo_exact_release_active_wait_authoritative_watchdog_checks"]
    dispatches = value["buflo_exact_release_active_wait_authoritative_watchdog_dispatches"]
    cadence_validated = value[
        "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards"
    ]
    aggregate_retries = value[
        "buflo_exact_release_active_wait_early_confirmation_retries"
    ]
    aggregate_counter_nanoseconds = value[
        "buflo_exact_release_active_wait_counter_nanoseconds"
    ]
    production_counter = value["buflo_exact_release_active_wait_poll_source"] == (
        "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
    )
    if (
        entries > 0
        and not _runner_wakeup_v10_histogram_max_valid(
            value["buflo_exact_release_active_spin_gap_histogram"]["counts"],
            value["buflo_exact_release_max_active_spin_gap_nanoseconds"],
        )
        or dispatch_ready > 0
        and not _runner_wakeup_v10_histogram_max_valid(
            value["buflo_exact_release_dispatch_lateness_histogram"]["counts"],
            value["buflo_exact_release_max_guard_exit_lateness_nanoseconds"],
        )
    ):
        return False
    calibration_reads = _runner_wakeup_v10_checked_u64_product(calibrations, 2)
    watchdog_reads = _runner_wakeup_v10_checked_u64_product(checks, 64)
    total_minimum_reads = (
        None
        if calibration_reads is None or watchdog_reads is None
        else _runner_wakeup_v10_checked_u64_sum(calibration_reads, watchdog_reads)
    )
    new_values = tuple(value[key] for key in RUNNER_WAKEUP_V10_NEW_INTEGER_KEYS)
    interruption_minimum = _runner_wakeup_v10_histogram_interruption_minimum(
        value["buflo_exact_release_active_spin_gap_histogram"]["counts"],
        value["buflo_exact_release_max_active_spin_gap_nanoseconds"],
        value["buflo_exact_release_active_spin_interruptions"],
    )
    if (
        dispatches > checks
        or dispatches > counter_guards
        or dispatches > dispatch_ready + frequency_changed
        or dispatches > value["buflo_exact_release_active_wait_instant_confirmations"]
        or (production_counter and cadence_validated != dispatch_ready)
        or (not production_counter and cadence_validated != 0)
        or total_minimum_reads is None
        or total_minimum_reads > iterations
        or aggregate_retries > 0 and aggregate_counter_nanoseconds == 0
        or interruption_minimum is None
        or interruption_minimum
        > value["buflo_exact_release_active_spin_interruption_nanoseconds"]
        or value["buflo_exact_release_max_authoritative_sample_gap_nanoseconds"]
        > value["buflo_exact_release_active_wait_nanoseconds"]
        or value["buflo_exact_release_max_authoritative_counter_lag_nanoseconds"]
        > value["buflo_exact_release_active_wait_nanoseconds"]
        or value["buflo_exact_release_max_counter_authoritative_lead_nanoseconds"]
        > value["buflo_exact_release_active_wait_counter_nanoseconds"]
        or (entries == 0 and any(new_values))
    ):
        return False
    if production_counter and value["buflo_exact_release_failed_guards"] == 0:
        if calibration_reads is None or watchdog_reads is None:
            return False
        remainder_reads = iterations - calibration_reads
        retries = value["buflo_exact_release_active_wait_early_confirmation_retries"]
        if calibrations != entries + retries or remainder_reads < retries:
            return False
        if entries == 0:
            if (
                iterations != 0
                or calibrations != 0
                or value["buflo_exact_release_active_wait_early_confirmation_retries"] != 0
                or checks != 0
                or dispatches != 0
            ):
                return False
        watchdog_upper = _runner_wakeup_v10_checked_u64_product(checks + entries, 64)
        residue_capacity = _runner_wakeup_v10_checked_u64_product(entries - dispatches, 63)
        if (
            watchdog_upper is None
            or residue_capacity is None
            or entries > 0
            and not watchdog_reads <= remainder_reads < watchdog_upper
            or checks < dispatches
            or remainder_reads - watchdog_reads > residue_capacity
        ):
            return False
        worst = value["buflo_exact_release_worst_guard"]
        if dispatch_ready > 1 and isinstance(worst, Mapping):
            remaining_successes = dispatch_ready - 1
            residual_calibrations = calibrations - worst["active_wait_counter_calibrations"]
            residual_retries = (
                value["buflo_exact_release_active_wait_early_confirmation_retries"]
                - worst["active_wait_early_confirmation_retries"]
            )
            residual_checks = checks - worst["active_wait_authoritative_watchdog_checks"]
            residual_dispatches = (
                dispatches - worst["active_wait_authoritative_watchdog_dispatches"]
            )
            residual_iterations = iterations - worst["active_wait_iterations"]
            residual_calibration_reads = _runner_wakeup_v10_checked_u64_product(
                residual_calibrations, 2
            )
            residual_watchdog_reads = _runner_wakeup_v10_checked_u64_product(residual_checks, 64)
            residual_watchdog_upper = _runner_wakeup_v10_checked_u64_product(
                residual_checks + remaining_successes, 64
            )
            residual_residue_capacity = _runner_wakeup_v10_checked_u64_product(
                remaining_successes - residual_dispatches, 63
            )
            residual_relaxed_reads = (
                -1
                if residual_calibration_reads is None
                else residual_iterations - residual_calibration_reads
            )
            residual_interruptions = (
                value["buflo_exact_release_active_spin_interruptions"]
                - worst["active_spin_interruptions"]
            )
            residual_interruption_ns = (
                value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                - worst["active_spin_interruption_nanoseconds"]
            )
            residual_allocation_valid = (
                iterations == RUNNER_WAKEUP_V10_U64_MAX
                or value["buflo_exact_release_active_spin_interruptions"]
                == RUNNER_WAKEUP_V10_U64_MAX
                or worst["active_spin_interruptions"] == RUNNER_WAKEUP_V10_U64_MAX
                or residual_interruptions
                <= max(residual_iterations - remaining_successes, 0)
                and residual_interruption_ns
                >= _runner_wakeup_v10_minimum_interruption_nanoseconds(
                    residual_interruptions
                )
                and (
                    value["buflo_exact_release_active_wait_counter_nanoseconds"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or residual_interruption_ns
                    <= value["buflo_exact_release_active_wait_counter_nanoseconds"]
                    - (worst["active_wait_counter_nanoseconds"] or 0)
                )
                and (
                    value["buflo_exact_release_active_wait_nanoseconds"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or residual_interruption_ns
                    <= value["buflo_exact_release_active_wait_nanoseconds"]
                    - worst["active_wait_monotonic_nanoseconds"]
                )
                and _runner_wakeup_v10_saturating_u64_sum(
                    value["buflo_exact_release_active_spin_gap_histogram"]["counts"][1:]
                )
                - int(worst["max_active_spin_gap_nanoseconds"] > 50_000)
                <= residual_interruptions
            )
            if (
                min(
                    residual_calibrations,
                    residual_retries,
                    residual_checks,
                    residual_dispatches,
                    residual_iterations,
                    residual_relaxed_reads,
                )
                < 0
                or residual_watchdog_reads is None
                or residual_watchdog_upper is None
                or residual_residue_capacity is None
                or residual_calibrations != remaining_successes + residual_retries
                or residual_relaxed_reads < residual_retries
                or residual_retries > 0
                and value["buflo_exact_release_active_wait_counter_nanoseconds"]
                - (worst["active_wait_counter_nanoseconds"] or 0)
                == 0
                or residual_checks < residual_dispatches
                or not residual_watchdog_reads <= residual_relaxed_reads < residual_watchdog_upper
                or residual_relaxed_reads - residual_watchdog_reads > residual_residue_capacity
                or not residual_allocation_valid
            ):
                return False
    if production_counter:
        read_bearing_guards = (
            entries - value["buflo_exact_release_invalid_counter_frequency_guards"]
        )
        terminal_no_gap_guards = value[
            "buflo_exact_release_counter_nonmonotonic_failure_guards"
        ] + int(
            isinstance(value["buflo_exact_release_last_failure"], Mapping)
            and value["buflo_exact_release_last_failure"]["outcome"] == "counter-unavailable"
            and value["buflo_exact_release_last_failure"]["counter_calibrations"] > 0
        )
        if (
            iterations != RUNNER_WAKEUP_V10_U64_MAX
            and value["buflo_exact_release_active_spin_interruptions"]
            > max(iterations - read_bearing_guards - terminal_no_gap_guards, 0)
            or value["buflo_exact_release_active_spin_interruption_nanoseconds"]
            > value["buflo_exact_release_active_wait_counter_nanoseconds"]
        ):
            return False
    failure = value["buflo_exact_release_last_failure"]
    worst = value["buflo_exact_release_worst_guard"]
    retained_failure_entry_lateness = (
        failure["guard_entry_lateness_nanoseconds"] if isinstance(failure, Mapping) else 0
    )
    success_entry_lateness_ceiling = min(
        5_000_000 + value["buflo_exact_release_max_guard_exit_lateness_nanoseconds"],
        RUNNER_WAKEUP_V10_U64_MAX,
    )
    if value["buflo_exact_release_max_guard_entry_lateness_nanoseconds"] > max(
        retained_failure_entry_lateness,
        success_entry_lateness_ceiling,
    ):
        return False
    if isinstance(failure, Mapping) and dispatch_ready > 0:
        if not isinstance(worst, Mapping):
            return False
        if production_counter and dispatch_ready > 1:
            remaining_successes = dispatch_ready - 1
            residual_calibrations = calibrations - worst["active_wait_counter_calibrations"]
            residual_retries = (
                value["buflo_exact_release_active_wait_early_confirmation_retries"]
                - worst["active_wait_early_confirmation_retries"]
            )
            residual_checks = checks - worst["active_wait_authoritative_watchdog_checks"]
            residual_dispatches = (
                dispatches - worst["active_wait_authoritative_watchdog_dispatches"]
            )
            residual_iterations = iterations - worst["active_wait_iterations"]
            failure_calibrations = failure["counter_calibrations"]
            failure_retries = failure["early_confirmation_retries"]
            failure_checks = failure["authoritative_watchdog_checks"]
            failure_dispatches = failure["authoritative_watchdog_dispatches"]
            residual_calibrations -= failure_calibrations
            residual_retries -= failure_retries
            residual_checks -= failure_checks
            residual_dispatches -= failure_dispatches

            def remaining_success_partition_valid(failure_iterations: int) -> bool:
                success_iterations = residual_iterations - failure_iterations
                calibration_reads = _runner_wakeup_v10_checked_u64_product(residual_calibrations, 2)
                watchdog_reads = _runner_wakeup_v10_checked_u64_product(residual_checks, 64)
                watchdog_upper = _runner_wakeup_v10_checked_u64_product(
                    residual_checks + remaining_successes, 64
                )
                residue_capacity = _runner_wakeup_v10_checked_u64_product(
                    remaining_successes - residual_dispatches, 63
                )
                if None in {
                    calibration_reads,
                    watchdog_reads,
                    watchdog_upper,
                    residue_capacity,
                }:
                    return False
                success_relaxed_reads = success_iterations - calibration_reads
                failure_elapsed = _runner_wakeup_v10_failure_elapsed_nanoseconds(failure)
                success_counter_budget = max(
                    value["buflo_exact_release_active_wait_counter_nanoseconds"]
                    - (worst["active_wait_counter_nanoseconds"] or 0)
                    - (failure["counter_nanoseconds"] or 0),
                    0,
                )
                success_active_budget = max(
                    value["buflo_exact_release_active_wait_nanoseconds"]
                    - worst["active_wait_monotonic_nanoseconds"]
                    - (failure_elapsed or 0),
                    0,
                )
                success_effective_capacity = min(
                    max(success_iterations - remaining_successes, 0),
                    success_counter_budget // 50_001,
                    success_active_budget // 50_001,
                )
                interruption_capacity_valid = (
                    iterations == RUNNER_WAKEUP_V10_U64_MAX
                    or value["buflo_exact_release_active_spin_interruptions"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or worst["active_spin_interruptions"] == RUNNER_WAKEUP_V10_U64_MAX
                    or value["buflo_exact_release_active_spin_interruptions"]
                    - worst["active_spin_interruptions"]
                    - failure["active_spin_interruptions"]
                    <= success_effective_capacity
                )
                residual_histogram_valid = (
                    value["buflo_exact_release_active_spin_interruptions"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or worst["active_spin_interruptions"] == RUNNER_WAKEUP_V10_U64_MAX
                    or _runner_wakeup_v10_saturating_u64_sum(
                        value["buflo_exact_release_active_spin_gap_histogram"]["counts"][1:]
                    )
                    - int(worst["max_active_spin_gap_nanoseconds"] > 50_000)
                    <= value["buflo_exact_release_active_spin_interruptions"]
                    - worst["active_spin_interruptions"]
                )
                interruption_nanoseconds_valid = (
                    value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or value["buflo_exact_release_active_wait_counter_nanoseconds"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or value["buflo_exact_release_active_spin_interruptions"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or worst["active_spin_interruptions"] == RUNNER_WAKEUP_V10_U64_MAX
                    or value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                    - worst["active_spin_interruption_nanoseconds"]
                    - failure["active_spin_interruption_nanoseconds"]
                    >= _runner_wakeup_v10_minimum_interruption_nanoseconds(
                        value["buflo_exact_release_active_spin_interruptions"]
                        - worst["active_spin_interruptions"]
                        - failure["active_spin_interruptions"]
                    )
                    and value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                    - worst["active_spin_interruption_nanoseconds"]
                    - failure["active_spin_interruption_nanoseconds"]
                    <= value["buflo_exact_release_active_wait_counter_nanoseconds"]
                    - (worst["active_wait_counter_nanoseconds"] or 0)
                )
                interruption_duration_valid = (
                    value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or value["buflo_exact_release_active_wait_nanoseconds"]
                    == RUNNER_WAKEUP_V10_U64_MAX
                    or value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                    - worst["active_spin_interruption_nanoseconds"]
                    - failure["active_spin_interruption_nanoseconds"]
                    <= value["buflo_exact_release_active_wait_nanoseconds"]
                    - worst["active_wait_monotonic_nanoseconds"]
                )
                return (
                    min(
                        residual_calibrations,
                        residual_retries,
                        residual_checks,
                        residual_dispatches,
                        success_iterations,
                        success_relaxed_reads,
                    )
                    >= 0
                    and residual_calibrations == remaining_successes + residual_retries
                    and success_relaxed_reads >= residual_retries
                    and (
                        residual_retries == 0
                        or success_counter_budget > 0
                    )
                    and residual_checks >= residual_dispatches
                    and watchdog_reads <= success_relaxed_reads < watchdog_upper
                    and success_relaxed_reads - watchdog_reads <= residue_capacity
                    and interruption_capacity_valid
                    and residual_histogram_valid
                    and interruption_nanoseconds_valid
                    and interruption_duration_valid
                )

            possible_failure_iterations = {failure["active_wait_iterations"]}
            if not any(
                _runner_wakeup_v10_failure_iterations_valid(
                    failure,
                    iterations=failure_iterations,
                )
                and remaining_success_partition_valid(failure_iterations)
                for failure_iterations in possible_failure_iterations
            ):
                return False
        additive_bounds = {
            "buflo_exact_release_active_wait_iterations": (
                worst["active_wait_iterations"] + failure["active_wait_iterations"]
            ),
            "buflo_exact_release_active_wait_nanoseconds": (
                worst["active_wait_monotonic_nanoseconds"]
                + failure["active_wait_monotonic_nanoseconds"]
            ),
            "buflo_exact_release_active_spin_interruptions": (
                worst["active_spin_interruptions"] + failure["active_spin_interruptions"]
            ),
            "buflo_exact_release_active_spin_interruption_nanoseconds": (
                worst["active_spin_interruption_nanoseconds"]
                + failure["active_spin_interruption_nanoseconds"]
            ),
            "buflo_exact_release_active_wait_counter_calibrations": (
                worst["active_wait_counter_calibrations"] + failure["counter_calibrations"]
            ),
            "buflo_exact_release_active_wait_instant_confirmations": (
                worst["active_wait_instant_confirmations"] + failure["instant_confirmations"]
            ),
            "buflo_exact_release_active_wait_early_confirmation_retries": (
                worst["active_wait_early_confirmation_retries"]
                + failure["early_confirmation_retries"]
            ),
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": (
                worst["active_wait_authoritative_watchdog_checks"]
                + failure["authoritative_watchdog_checks"]
            ),
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": (
                worst["active_wait_authoritative_watchdog_dispatches"]
                + failure["authoritative_watchdog_dispatches"]
            ),
            "buflo_exact_release_active_wait_counter_nanoseconds": (
                (worst["active_wait_counter_nanoseconds"] or 0)
                + (failure["counter_nanoseconds"] or 0)
            ),
        }
        failure_elapsed = _runner_wakeup_v10_failure_elapsed_nanoseconds(failure)
        if failure_elapsed is not None:
            additive_bounds.update(
                {
                    "buflo_exact_release_guard_wait_nanoseconds": (
                        worst["active_wait_monotonic_nanoseconds"] + failure_elapsed
                    ),
                    "buflo_exact_release_active_wait_nanoseconds": (
                        worst["active_wait_monotonic_nanoseconds"] + failure_elapsed
                    ),
                }
            )
        additive_bounds = {
            key: min(minimum, RUNNER_WAKEUP_V10_U64_MAX) for key, minimum in additive_bounds.items()
        }
        if any(value[key] < minimum for key, minimum in additive_bounds.items()):
            return False
        if dispatch_ready == 1:
            expected_spin_counts = [0] * 8
            for maximum in (
                worst["max_active_spin_gap_nanoseconds"],
                failure["max_active_spin_gap_nanoseconds"],
            ):
                expected_spin_counts[_runner_wakeup_v7_bucket(maximum)] += 1
            exact_paired_values = {
                key: minimum
                for key, minimum in additive_bounds.items()
            }
            exact_paired_values.update(
                {
                    "buflo_exact_release_max_passive_wake_lateness_nanoseconds": max(
                        worst["guard_entry_lateness_nanoseconds"],
                        failure["guard_entry_lateness_nanoseconds"],
                    ),
                    "buflo_exact_release_max_guard_entry_lateness_nanoseconds": max(
                        worst["guard_entry_lateness_nanoseconds"],
                        failure["guard_entry_lateness_nanoseconds"],
                    ),
                    "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": max(
                        worst["max_active_wait_counter_gap_nanoseconds"] or 0,
                        failure["max_counter_gap_nanoseconds"] or 0,
                    ),
                    "buflo_exact_release_max_counter_calibration_span_nanoseconds": max(
                        worst["max_counter_calibration_span_nanoseconds"] or 0,
                        failure["max_counter_calibration_span_nanoseconds"] or 0,
                    ),
                    "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": max(
                        worst["max_authoritative_sample_gap_nanoseconds"],
                        failure["max_authoritative_sample_gap_nanoseconds"],
                    ),
                    "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": max(
                        worst["max_authoritative_counter_lag_nanoseconds"],
                        failure["max_authoritative_counter_lag_nanoseconds"],
                    ),
                    "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": max(
                        worst["max_counter_authoritative_lead_nanoseconds"],
                        failure["max_counter_authoritative_lead_nanoseconds"],
                    ),
                    "buflo_exact_release_max_active_spin_gap_nanoseconds": max(
                        worst["max_active_spin_gap_nanoseconds"],
                        failure["max_active_spin_gap_nanoseconds"],
                    ),
                }
            )
            if any(value[key] != expected for key, expected in exact_paired_values.items()):
                return False
            if value["buflo_exact_release_active_spin_gap_histogram"][
                "counts"
            ] != expected_spin_counts:
                return False
            if not _runner_wakeup_v10_failure_iterations_valid(
                failure,
                iterations=iterations - worst["active_wait_iterations"],
            ):
                return False
            if (
                iterations != RUNNER_WAKEUP_V10_U64_MAX
                and value["buflo_exact_release_active_spin_interruptions"]
                != RUNNER_WAKEUP_V10_U64_MAX
                and worst["active_spin_interruptions"] != RUNNER_WAKEUP_V10_U64_MAX
            ):
                failure_iterations = iterations - worst["active_wait_iterations"]
                failure_interruptions = (
                    value["buflo_exact_release_active_spin_interruptions"]
                    - worst["active_spin_interruptions"]
                )
                terminal_no_gap_reads = int(
                    failure["outcome"] in {"counter-unavailable", "counter-nonmonotonic"}
                )
                if failure_interruptions > max(
                    failure_iterations - 1 - terminal_no_gap_reads,
                    0,
                ):
                    return False
            if (
                value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                != RUNNER_WAKEUP_V10_U64_MAX
                and worst["active_spin_interruption_nanoseconds"] != RUNNER_WAKEUP_V10_U64_MAX
                and value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                - worst["active_spin_interruption_nanoseconds"]
                < _runner_wakeup_v10_minimum_interruption_nanoseconds(
                    value["buflo_exact_release_active_spin_interruptions"]
                    - worst["active_spin_interruptions"]
                )
                or value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                != RUNNER_WAKEUP_V10_U64_MAX
                and worst["active_spin_interruption_nanoseconds"]
                != RUNNER_WAKEUP_V10_U64_MAX
                and value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                - worst["active_spin_interruption_nanoseconds"]
                > (failure["counter_nanoseconds"] or 0)
                or value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                != RUNNER_WAKEUP_V10_U64_MAX
                and value["buflo_exact_release_active_wait_nanoseconds"]
                != RUNNER_WAKEUP_V10_U64_MAX
                and value["buflo_exact_release_active_spin_interruption_nanoseconds"]
                - worst["active_spin_interruption_nanoseconds"]
                > value["buflo_exact_release_active_wait_nanoseconds"]
                - worst["active_wait_monotonic_nanoseconds"]
            ):
                return False
        if dispatch_ready == 1 and failure["outcome"] == "counter-frequency-changed":
            failure_relaxed_reads = (
                iterations - worst["active_wait_iterations"] - failure["counter_calibrations"] * 2
            )
            failure_checks = failure["authoritative_watchdog_checks"]
            failure_dispatches = failure["authoritative_watchdog_dispatches"]
            if (
                failure_relaxed_reads < 0
                or failure_checks != failure_relaxed_reads // 64
                or (failure_dispatches > 0 and failure_relaxed_reads % 64 != 0)
            ):
                return False
        if (
            dispatch_ready == 1
            and failure["outcome"] == "counter-target-error"
            and failure["early_confirmation_retries"] == 0
            and iterations != min(worst["active_wait_iterations"] + 2, RUNNER_WAKEUP_V10_U64_MAX)
        ):
            return False
        if (
            dispatch_ready == 1
            and failure["outcome"] == "invalid-counter-frequency"
            and iterations != worst["active_wait_iterations"]
        ):
            return False
        if (
            dispatch_ready == 1
            and failure["outcome"] == "counter-nonmonotonic"
            and failure["counter_calibrations"] == 0
            and iterations != min(worst["active_wait_iterations"] + 2, RUNNER_WAKEUP_V10_U64_MAX)
        ):
            return False
    if (
        dispatch_ready > 1
        and isinstance(worst, Mapping)
        and RUNNER_WAKEUP_V10_U64_MAX
        not in {
            dispatch_ready,
            iterations,
            value["buflo_exact_release_active_spin_interruptions"],
            value["buflo_exact_release_active_spin_interruption_nanoseconds"],
            value["buflo_exact_release_active_wait_nanoseconds"],
            value["buflo_exact_release_active_wait_counter_nanoseconds"],
        }
    ):
        nested_failures = (failure,) if isinstance(failure, Mapping) else ()
        remaining_successes = dispatch_ready - 1
        nested_interruptions = worst["active_spin_interruptions"] + sum(
            item["active_spin_interruptions"] for item in nested_failures
        )
        nested_interruption_ns = worst["active_spin_interruption_nanoseconds"] + sum(
            item["active_spin_interruption_nanoseconds"] for item in nested_failures
        )
        nested_iterations = worst["active_wait_iterations"] + sum(
            item["active_wait_iterations"] for item in nested_failures
        )
        nested_active_ns = worst["active_wait_monotonic_nanoseconds"] + sum(
            item["active_wait_monotonic_nanoseconds"] for item in nested_failures
        )
        nested_counter_ns = (worst["active_wait_counter_nanoseconds"] or 0) + sum(
            item["counter_nanoseconds"] or 0 for item in nested_failures
        )
        residual_values = (
            value["buflo_exact_release_active_spin_interruptions"] - nested_interruptions,
            value["buflo_exact_release_active_spin_interruption_nanoseconds"]
            - nested_interruption_ns,
            iterations - nested_iterations,
            value["buflo_exact_release_active_wait_nanoseconds"] - nested_active_ns,
            value["buflo_exact_release_active_wait_counter_nanoseconds"] - nested_counter_ns,
        )
        if min(residual_values) < 0:
            return False
        (
            residual_interruptions,
            residual_interruption_ns,
            residual_iterations,
            residual_active_ns,
            residual_counter_ns,
        ) = residual_values
        nested_maxima = (worst["max_active_spin_gap_nanoseconds"],) + tuple(
            item["max_active_spin_gap_nanoseconds"] for item in nested_failures
        )
        residual_minimum_ns = _runner_wakeup_v10_residual_histogram_minimum(
            value["buflo_exact_release_active_spin_gap_histogram"]["counts"],
            aggregate_maximum=value["buflo_exact_release_max_active_spin_gap_nanoseconds"],
            nested_maxima=nested_maxima,
            interruptions=residual_interruptions,
        )
        residual_active_minimum = _runner_wakeup_v10_residual_active_duration_minimum(
            value["buflo_exact_release_dispatch_lateness_histogram"]["counts"],
            worst_dispatch_lateness=worst["dispatch_lateness_nanoseconds"],
            max_entry_lateness=value[
                "buflo_exact_release_max_guard_entry_lateness_nanoseconds"
            ],
        )
        count_capacity = residual_iterations
        if production_counter:
            count_capacity = max(count_capacity - remaining_successes, 0)
        if (
            residual_minimum_ns is None
            or residual_active_minimum is None
            or residual_interruptions > count_capacity
            or residual_interruption_ns < residual_minimum_ns
            or residual_interruption_ns > residual_active_ns
            or production_counter and residual_interruption_ns > residual_counter_ns
            or residual_active_ns < residual_active_minimum
        ):
            return False
    if not _runner_wakeup_v10_active_wait_reachability_valid(
        value,
        worst=worst,
        failure=failure,
    ):
        return False
    if value["buflo_exact_release_active_wait_poll_source"] == (
        "instant-authoritative-fallback-v1"
    ) and any(new_values):
        return False
    return True


def _runner_wakeup_v11_project_schema_ten(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project a kernel-TX wrapper onto the frozen schema-10 envelope."""

    projected = dict(value)
    projected.pop("buflo_kernel_tx", None)
    projected["schema_version"] = 10
    projected["semantics"] = RUNNER_WAKEUP_V10_SEMANTICS
    return projected


def _runner_wakeup_v11_legacy_buflo_metrics_neutral(value: Mapping[str, Any]) -> bool:
    """Prove the superseded user-space BuFLO path emitted no observations."""

    integer_values = (
        field_value
        for key, field_value in value.items()
        if key.startswith("buflo_exact_") and type(field_value) is int
    )
    return bool(
        not any(integer_values)
        and value["buflo_exact_release_active_wait_poll_source"]
        == "instant-authoritative-fallback-v1"
        and value["buflo_exact_release_active_wait_counter_frequency_hz"] is None
        and value["buflo_exact_release_worst_guard"] is None
        and value["buflo_exact_release_last_failure"] is None
        and not any(value["buflo_exact_release_dispatch_lateness_histogram"]["counts"])
        and not any(value["buflo_exact_release_active_spin_gap_histogram"]["counts"])
    )


def _runner_wakeup_v11_valid(value: Any) -> bool:
    """Validate frozen schema 11 without reinterpreting schema-10 fields.

    A non-null ``buflo_kernel_tx`` is raw Rust evidence only.  Router-ingress
    capture and final qdisc counters live in the separately hashed Lab
    ``kernel_tx_evidence`` receipt; callers must require that receipt before a
    sample becomes eligible.
    """

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V11_REQUIRED_KEYS
        or value.get("schema_version") != 11
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    if kernel_tx is None:
        return value.get("semantics") in {
            RUNNER_WAKEUP_V11_V1_SEMANTICS,
            RUNNER_WAKEUP_V11_SEMANTICS,
        }
    if not isinstance(kernel_tx, Mapping):
        return False
    expected_semantics = {
        1: RUNNER_WAKEUP_V11_V1_SEMANTICS,
        2: RUNNER_WAKEUP_V11_SEMANTICS,
    }.get(kernel_tx.get("schema_version"))
    return bool(
        expected_semantics is not None
        and value.get("semantics") == expected_semantics
        and kernel_tx_runner_receipt_valid(kernel_tx)
        # Kernel scheduling supersedes the schema-10 user-space exact-release
        # guard/retry mechanism.  Keeping those counters non-zero would claim
        # two mutually exclusive physical realization paths for one sample.
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v12_valid(value: Any) -> bool:
    """Validate frozen schema 12 with an exact nested runner-v3 receipt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V12_REQUIRED_KEYS
        or value.get("schema_version") != 12
        or value.get("semantics") != RUNNER_WAKEUP_V12_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version")
        == KERNEL_TX_RUNNER_V3_SCHEMA_VERSION
        == 3
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v13_valid(value: Any) -> bool:
    """Validate frozen schema 13 with an exact nested runner-v4 receipt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V13_REQUIRED_KEYS
        or value.get("schema_version") != 13
        or value.get("semantics") != RUNNER_WAKEUP_V13_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version")
        == KERNEL_TX_RUNNER_V4_SCHEMA_VERSION
        == 4
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v14_valid(value: Any) -> bool:
    """Validate frozen schema 14 with an exact nested runner-v5 receipt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V14_REQUIRED_KEYS
        or value.get("schema_version") != 14
        or value.get("semantics") != RUNNER_WAKEUP_V14_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_RUNNER_V5_SCHEMA_VERSION == 5
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v15_valid(value: Any) -> bool:
    """Validate frozen schema 15 with an exact nested runner-v6 receipt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V15_REQUIRED_KEYS
        or value.get("schema_version") != 15
        or value.get("semantics") != RUNNER_WAKEUP_V15_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_RUNNER_V6_SCHEMA_VERSION == 6
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v16_valid(value: Any) -> bool:
    """Validate frozen schema 16 with an exact nested runner-v7 receipt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V16_REQUIRED_KEYS
        or value.get("schema_version") != 16
        or value.get("semantics") != RUNNER_WAKEUP_V16_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_RUNNER_V7_SCHEMA_VERSION == 7
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v17_valid(value: Any) -> bool:
    """Validate frozen schema 17 with an exact nested runner-v8 receipt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V17_REQUIRED_KEYS
        or value.get("schema_version") != 17
        or value.get("semantics") != RUNNER_WAKEUP_V17_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_RUNNER_V8_SCHEMA_VERSION == 8
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v18_valid(value: Any) -> bool:
    """Validate frozen schema 18 with an exact nested runner-v9 receipt."""

    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V18_REQUIRED_KEYS
        or value.get("schema_version") != 18
        or value.get("semantics") != RUNNER_WAKEUP_V18_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_RUNNER_V9_SCHEMA_VERSION == 9
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v19_valid(value: Any) -> bool:
    """Validate schema19 with exact runner10 role-specific physical deadlines."""
    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V19_REQUIRED_KEYS
        or type(value.get("schema_version")) is not int or value["schema_version"] != 19
        or value.get("semantics") != RUNNER_WAKEUP_V19_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_RUNNER_V10_SCHEMA_VERSION == 10
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v20_valid(value: Any) -> bool:
    """Validate runner 20 with a raw 11 measured selection-entry receipt."""
    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V20_REQUIRED_KEYS
        or type(value.get("schema_version")) is not int or value["schema_version"] != 20
        or value.get("semantics") != RUNNER_WAKEUP_V20_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_RUNNER_SCHEMA_VERSION == 11
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v21_valid(value: Any) -> bool:
    """Validate opted-in preparation reserve with unchanged physical evidence."""
    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V21_REQUIRED_KEYS
        or type(value.get("schema_version")) is not int or value["schema_version"] != 21
        or value.get("semantics") != RUNNER_WAKEUP_V21_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_RESERVE_RUNNER_SCHEMA_VERSION == 12
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
    )


def _runner_wakeup_v22_valid(value: Any) -> bool:
    """Validate prospective64ms preparation reserve with unchanged physical evidence."""
    if (
        not isinstance(value, Mapping)
        or set(value) != RUNNER_WAKEUP_V22_REQUIRED_KEYS
        or type(value.get("schema_version")) is not int or value["schema_version"] != 22
        or value.get("semantics") != RUNNER_WAKEUP_V22_SEMANTICS
        or not _runner_wakeup_v10_valid(_runner_wakeup_v11_project_schema_ten(value))
    ):
        return False
    kernel_tx = value.get("buflo_kernel_tx")
    return bool(
        isinstance(kernel_tx, Mapping)
        and kernel_tx.get("schema_version") == KERNEL_TX_CADENCE64_RUNNER_SCHEMA_VERSION == 13
        and kernel_tx_runner_receipt_valid(kernel_tx)
        and _runner_wakeup_v11_legacy_buflo_metrics_neutral(value)
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
    if schema_version == 22:
        return _runner_wakeup_v22_valid(value)
    if schema_version == 21:
        return _runner_wakeup_v21_valid(value)
    if schema_version == 20:
        return _runner_wakeup_v20_valid(value)
    if schema_version == 19:
        return _runner_wakeup_v19_valid(value)
    if schema_version == 18:
        return _runner_wakeup_v18_valid(value)
    if schema_version == 17:
        return _runner_wakeup_v17_valid(value)
    if schema_version == 16:
        return _runner_wakeup_v16_valid(value)
    if schema_version == 15:
        return _runner_wakeup_v15_valid(value)
    if schema_version == 14:
        return _runner_wakeup_v14_valid(value)
    if schema_version == 13:
        return _runner_wakeup_v13_valid(value)
    if schema_version == 12:
        return _runner_wakeup_v12_valid(value)
    if schema_version == 11:
        return _runner_wakeup_v11_valid(value)
    if schema_version == 10:
        return _runner_wakeup_v10_valid(value)
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
    resolved_configuration: Mapping[str, Any] | None = None,
    require_defense_activation: bool = False,
) -> bool:
    defense = _canonical_fidelity_defense(defense)
    if not sample_eligible:
        return False
    buflo_period_us = 20_000
    if defense == "buflo" and isinstance(schedule_metrics, Mapping):
        try:
            bound_startup = _buflo_metric_startup(schedule_metrics)
        except (ValueError, TypeError, KeyError):
            return False
        if bound_startup is not None:
            buflo_period_us = bound_startup["period_us"]
    allowance = _terminal_primary_partial_allowance(defense, schedule_metrics)
    if allowance is None:
        return False
    partial, retired = allowance
    if defense == "front" and isinstance(schedule_metrics, Mapping) and "front_capture_policy" in schedule_metrics:
        return (_scheduled_incoming_diagnostics_match(diagnostics)
            and _diagnostics_match_contract(defense, diagnostics, buflo_period_us=buflo_period_us)
            and type(missed_events) is int and missed_events == schedule_metrics.get("missed_events")
            and type(outgoing_size_mismatches) is int and outgoing_size_mismatches == 0
            and _front_capture_activation_valid(diagnostics, schedule_metrics, resolved_configuration))
    if (
        defense in DEFENSE_ADAPTATIONS
        and defense != "undefended"
        and (
            type(missed_events) is not int
            or missed_events != partial
            or type(outgoing_size_mismatches) is not int
            or outgoing_size_mismatches != 0
        )
    ):
        return False
    if (
        defense in DEFENSE_ADAPTATIONS
        and defense != "undefended"
        and not _scheduled_incoming_diagnostics_match(diagnostics, allowed_retired_bytes=retired)
    ):
        return False
    if not _diagnostics_match_contract(defense, diagnostics, buflo_period_us=buflo_period_us):
        return False
    if (
        require_defense_activation
        and defense in _ESTABLISHED_RUNTIME_KIND
        and not _established_defense_activation_valid(
            defense,
            diagnostics,
            schedule_metrics,
            resolved_configuration,
        )
    ):
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
        try:
            incoming_startup = _buflo_metric_startup(schedule_metrics) if isinstance(schedule_metrics, Mapping) else None
        except ValueError:
            return False
        if diagnostics.get("buflo_incoming_startup") != incoming_startup:
            return False
        zero_keys = (
            "buflo_partial_outgoing_cells",
            "buflo_suppressed_outgoing_cells",
            "buflo_missed_outgoing_cells",
            "buflo_outgoing_unresolved_cells",
            "buflo_incoming_unresolved_cells",
            "buflo_catch_up_outgoing_cells",
            "buflo_catch_up_incoming_cells",
        )
        return (
            all(diagnostics[key] == 0 for key in zero_keys)
            and diagnostics["buflo_missed_incoming_cells"] == partial
            and diagnostics["buflo_paper_equivalent"] is False
            and diagnostics["buflo_client_only"] is True
            and diagnostics["buflo_egress_backlog_pending"] is False
            and diagnostics["buflo_application_complete"] is True
            and diagnostics["buflo_minimum_duration_reached"] is True
            and diagnostics["buflo_event_guard_triggered"] is False
            and buflo_terminal_diagnostics_valid(diagnostics, incoming_startup=incoming_startup, buflo_period_us=buflo_period_us)
            and diagnostics["buflo_scheduled_outgoing_cells"]
            == diagnostics["buflo_full_outgoing_cells"]
            and isinstance(schedule_metrics, Mapping)
            and diagnostics["buflo_scheduled_outgoing_cells"]
            == schedule_metrics.get("scheduled_outgoing_events")
            and diagnostics["buflo_scheduled_incoming_cells"]
            == schedule_metrics.get("scheduled_incoming_events")
            and diagnostics["buflo_scheduled_incoming_cells"] - partial
            == schedule_metrics.get("incoming_credit_advertised_events")
            and diagnostics["buflo_scheduled_incoming_cells"] - partial
            == schedule_metrics.get("incoming_credit_consumed_events")
            and schedule_metrics.get("incoming_credit_release_timing_events")
            == diagnostics["buflo_scheduled_incoming_cells"] - partial
            and schedule_metrics.get("incoming_credit_release_window_violations") == 0
            and type(
                schedule_metrics.get("incoming_credit_release_lateness_upper_bound_us_max")
            ) is int
            and 0
            <= schedule_metrics["incoming_credit_release_lateness_upper_bound_us_max"]
            < _buflo_schedule_release_window(schedule_metrics)
            and diagnostics["scheduled_incoming_requested_bytes"]
            == diagnostics["buflo_scheduled_incoming_cells"] * 1_200
            and diagnostics.get("scheduled_incoming_advertised_bytes")
            == diagnostics["scheduled_incoming_requested_bytes"]
            and _new_schedule_terminal_contract(schedule_metrics, congestion_sensitive=False)
            and _buflo_schedule_matches_canonical_parameters(schedule_metrics, allowed_partial_cells=partial)
        )
    if defense == "cs-buflo":
        return _cs_buflo_fidelity_eligible(diagnostics, schedule_metrics, allowed_partial_cells=partial)
    if defense == "tamaraw" and isinstance(schedule_metrics, Mapping) and "tamaraw_capture_policy" in schedule_metrics:
        return (_tamaraw_capture_metrics_valid(schedule_metrics)
            and _new_schedule_terminal_contract(schedule_metrics, congestion_sensitive=False)
            and _established_defense_activation_valid(defense, diagnostics, schedule_metrics, resolved_configuration))
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


def _buflo_schedule_matches_canonical_parameters(schedule: Mapping[str, Any], *, allowed_partial_cells: int = 0) -> bool:
    targets = schedule.get("target_times_us_by_direction")
    sizes = schedule.get("scheduled_sizes_by_direction")
    terminal = schedule.get("terminal_satisfactions")
    if not isinstance(targets, Mapping) or not isinstance(sizes, Mapping):
        return False
    try:
        startup = _buflo_metric_startup(schedule)
        from .buflo_duration_budget import schedule_bounds
        maximum_events, duration_budget_us = schedule_bounds(schedule)
        period_us = schedule.get("buflo_duration_budget", {}).get("interval_us", 20_000)
        if period_us == 64_000 and (startup is None or startup["period_us"] != period_us):
            return False
        minimum_tick_us = ((10_000_000 + period_us - 1) // period_us) * period_us
    except ValueError:
        return False
    total = 0
    for direction in ("outgoing", "incoming"):
        directional_targets = targets.get(direction)
        directional_sizes = sizes.get(direction)
        if "buflo_duration_budget" in schedule and isinstance(directional_targets, list) and any(
            type(target) is not int or target < 0 or target >= duration_budget_us
            for target in directional_targets
        ):
            return False
        ordered_targets = (
            sorted(directional_targets) if isinstance(directional_targets, list) else []
        )
        if (
            not isinstance(directional_targets, list)
            or not isinstance(directional_sizes, list)
            or not directional_targets
            or len(directional_targets) != len(directional_sizes)
            or len(directional_targets) > maximum_events
            # Incoming opportunities are serialized when their advertised
            # credit is consumed, not when the target was scheduled.  Under a
            # bottleneck, independently outstanding credits can therefore
            # reach terminal state out of target order.  Canonical cadence is
            # a property of the complete target set, not terminal CSV order.
            or ordered_targets[0] != (startup["armed_at_us"] if startup is not None and direction == "incoming" else 0)
            or (minimum_tick_us not in ordered_targets
                and (startup is None or direction == "outgoing" or startup["armed_at_us"] <= minimum_tick_us))
            or any(size != 1_200 for size in directional_sizes)
            or any(
                current - previous != period_us
                for previous, current in zip(ordered_targets[:-1], ordered_targets[1:], strict=True)
            )
        ):
            return False
        total += len(directional_targets)
    if startup is not None and (
        len(targets["outgoing"]) - len(targets["incoming"]) != startup["startup_suppressed_opportunities"]
        or max(targets["outgoing"]) != max(targets["incoming"])
    ):
        return False
    return total <= maximum_events * 2 and terminal == ({"satisfied": total - 1, "missed": 1} if allowed_partial_cells else {"satisfied": total})


def _cs_buflo_fidelity_eligible(
    diagnostics: Mapping[str, Any], schedule: Mapping[str, Any] | None, *, allowed_partial_cells: int = 0
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
        "cs_buflo_outgoing_unresolved_cells",
        "cs_buflo_incoming_unresolved_cells",
    )
    if any(diagnostics[key] != 0 for key in zero_keys) or diagnostics["cs_buflo_missed_incoming_cells"] != allowed_partial_cells:
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
            and 0 <= terminal_at_minimum - full_at_minimum <= allowed_partial_cells
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
        or diagnostics["cs_buflo_scheduled_incoming_cells"] - allowed_partial_cells != terminal.get("satisfied", 0)
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
        or diagnostics["cs_buflo_scheduled_incoming_cells"] - allowed_partial_cells
        != schedule.get("incoming_credit_advertised_events")
        or diagnostics["cs_buflo_scheduled_incoming_cells"] - allowed_partial_cells
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
