from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import qcsd_lab.buflo_evaluation as evaluation_module
import qcsd_lab.buflo_handoff as handoff
import qcsd_lab.buflo_handoff as handoff_module
import qcsd_lab.buflo_study as study_module
import qcsd_lab.fidelity as fidelity_module
from qcsd_lab.buflo_handoff import (
    FORMAL_RESULT_NAMES,
    _algorithm_diagnostics,
    _performance_metadata,
    _read_shape_only_pcap,
    _validate_formal_sample_redirect_attestation,
    _validate_handoff_sample_correctness,
    _validate_run_sample_binding,
    _validate_runner_extension,
    _write_checksums,
    _write_shape_only_pcap,
    validate_study_handoff,
)
from qcsd_lab.capture import ObserverPacket
from qcsd_lab.fidelity import (
    CONSUMPTION_SCHEDULE_QCSD_FIELDS,
    RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
    RUNNER_WAKEUP_V7_SEMANTICS,
    RUNNER_WAKEUP_V8_SEMANTICS,
    RUNNER_WAKEUP_V9_SEMANTICS,
    RUNNER_WAKEUP_V10_SEMANTICS,
    SCHEDULE_QCSD_FIELDS,
)
from qcsd_lab.orchestrator import Workload, _redirect_attestation
from qcsd_lab.verification import VerifiedResult


def _packet(relative_time_ns: int, direction: str, frame_len: int) -> ObserverPacket:
    signed = frame_len if direction == "outgoing" else -frame_len
    return ObserverPacket(
        timestamp_unix_ns=1_000_000_000 + relative_time_ns,
        relative_time_ns=relative_time_ns,
        direction=direction,
        frame_len=frame_len,
        signed_frame_len=signed,
    )


def test_direction_metrics_use_target_order_not_incoming_terminal_order() -> None:
    fields = (*handoff.SCHEDULE_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)

    def incoming(target_us: int, action_us: int, slot: int) -> dict[str, str]:
        row = {field: "" for field in fields}
        row.update(
            target_time_us=str(target_us),
            direction="incoming",
            size="1200",
            action_time_us=str(action_us),
            satisfaction="satisfied",
            slot_id=str(slot),
            qcsd_outcome_schema_version="3",
            send_policy="exact",
            desired_udp_bytes="1200",
            credit_advertised_at_us=str(action_us),
            credit_advertisement_delay_us="0",
            credit_consumed_at_us=str(action_us + 100),
            credit_consumption_delay_us="100",
            terminal_defense_elapsed_us=str(target_us + 100),
        )
        return row

    metrics = handoff_module._direction_algorithm_metrics(
        [incoming(0, 0, 1), incoming(40_000, 40_000, 3), incoming(20_000, 80_000, 2)],
        direction="incoming",
        runtime_kind="buflo",
    )

    assert metrics["inter_target_delta_us"] == {
        "count": 2,
        "minimum": 20_000,
        "maximum": 20_000,
        "mean": 20_000,
        "p50": 20_000,
        "p95": 20_000,
    }


def test_handoff_csv_unsigned_uses_exact_rust_u64_domain() -> None:
    maximum = str(fidelity_module.RUNNER_CSV_U64_MAX)

    assert handoff._csv_unsigned(maximum, label="handoff value") == 2**64 - 1
    with pytest.raises(ValueError, match="u64 domain"):
        handoff._csv_unsigned(str(2**64), label="handoff value")
    with pytest.raises(ValueError, match="canonical ASCII"):
        handoff._csv_unsigned("01", label="handoff value")
    with pytest.raises(ValueError, match="not positive"):
        handoff._csv_unsigned("0", label="handoff value", positive=True)


def _runner_wakeup_receipt(schema_version: int, *, guard_entries: int = 0) -> dict[str, object]:
    if guard_entries < 0 or (schema_version not in {9, 10} and guard_entries != 0):
        raise ValueError("guarded-release fixtures require runner-wakeup schema 9 or 10")
    if schema_version == 10:
        receipt = _runner_wakeup_receipt(9, guard_entries=guard_entries)
        worst = receipt["buflo_exact_release_worst_guard"]
        active_wait = worst["active_wait_monotonic_nanoseconds"] if isinstance(worst, dict) else 0
        receipt.update(
            {
                "schema_version": 10,
                "semantics": RUNNER_WAKEUP_V10_SEMANTICS,
                "buflo_exact_release_active_wait_poll_source": (
                    "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
                ),
                "buflo_exact_release_active_wait_authoritative_watchdog_checks": 0,
                "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": 0,
                "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards": (
                    guard_entries
                ),
                "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": active_wait,
                "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": 0,
                "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": 0,
            }
        )
        if isinstance(worst, dict):
            worst.update(
                {
                    "active_wait_poll_source": (
                        "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
                    ),
                    "active_wait_authoritative_watchdog_checks": 0,
                    "active_wait_authoritative_watchdog_dispatches": 0,
                    "max_authoritative_sample_gap_nanoseconds": active_wait,
                    "max_authoritative_counter_lag_nanoseconds": 0,
                    "max_counter_authoritative_lead_nanoseconds": 0,
                }
            )
        return receipt
    semantics = (
        "actual_select_return_source; socket_wins_simultaneous_readiness; "
        "controller_subset_is_effective_earliest_deadline; "
        "scheduled_cells_are_not_wakeups"
    )
    receipt: dict[str, object] = {
        "schema_version": schema_version,
        "semantics": semantics,
        "wait_returns": 0,
        "socket_readiness_wakeups": 0,
        "timer_wakeups": 0,
        "controller_deadline_timer_wakeups": 0,
        "other_timer_wakeups": 0,
    }
    if schema_version in {2, 3, 4, 5, 6, 7, 8, 9}:
        active_wait_tail_us = 250 if schema_version == 2 else 5000
        if schema_version in {6, 7, 8, 9}:
            semantics = (
                f"{semantics}; "
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
                "buflo_exact_incoming_retry_wakeups="
                "transport_callback_or_1/4,1/2,3/4,deadline; "
                "buflo_exact_incoming_retry_drives="
                "count_owner_endpoint_output_drive_invocations_"
                "including_immediate_and_error; "
                "buflo_exact_incoming_retry_resolutions="
                "count_drive_invocations_clearing_at_least_one_captured_identity; "
                "buflo_exact_incoming_retry_max_wake_lateness_"
                "includes_terminal_deadline=true; "
                "buflo_exact_incoming_inventory="
                "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
                "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
            )
        elif schema_version in {4, 5}:
            semantics = (
                f"{semantics}; "
                "buflo_ordinary_output_admission_is_one_realization_window_before_guard; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                f"buflo_exact_release_active_wait_tail_us={active_wait_tail_us}; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_ordinary_output_stops_at_admission; "
                "buflo_exact_release_guard_begins_at_guard; "
                "cs_exact_incoming_retry_phases=1/4,1/2,3/4"
            )
            if schema_version == 5:
                semantics = (
                    f"{semantics}; "
                    "buflo_exact_incoming_retry_wakeups="
                    "transport_callback_or_1/4,1/2,3/4,deadline; "
                    "buflo_exact_incoming_retry_drives="
                    "count_owner_endpoint_output_drive_invocations_"
                    "including_immediate_and_error; "
                    "buflo_exact_incoming_retry_resolutions="
                    "count_drive_invocations_clearing_at_least_one_captured_identity; "
                    "buflo_exact_incoming_retry_max_wake_lateness_"
                    "includes_terminal_deadline=true; "
                    "buflo_exact_incoming_inventory="
                    "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
                    "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
                )
        else:
            semantics = (
                f"{semantics}; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                f"buflo_exact_release_active_wait_tail_us={active_wait_tail_us}; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_output_is_interrupted_at_guard"
            )
        receipt.update(
            {
                "semantics": semantics,
                "buflo_exact_release_guard_entries": 0,
                "buflo_exact_release_guard_wait_nanoseconds": 0,
                "buflo_exact_release_active_wait_nanoseconds": 0,
                "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 0,
                "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 0,
            }
        )
    if schema_version in {4, 5, 6, 7, 8, 9}:
        receipt.update(
            {
                "cs_exact_incoming_retry_drives": 0,
                "cs_exact_incoming_retry_resolutions": 0,
                "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 0,
            }
        )
    if schema_version in {5, 6, 7, 8, 9}:
        receipt.update(
            {
                "buflo_exact_incoming_retry_drives": 0,
                "buflo_exact_incoming_retry_resolutions": 0,
                "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 0,
            }
        )
    if schema_version in {7, 8}:
        receipt.update(
            {
                "semantics": (
                    RUNNER_WAKEUP_V8_SEMANTICS
                    if schema_version == 8
                    else RUNNER_WAKEUP_V7_SEMANTICS
                ),
                "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 0,
                "buflo_exact_release_passive_sleep_calls": 0,
                "buflo_exact_release_passive_sleep_requested_nanoseconds": 0,
                "buflo_exact_release_passive_sleep_elapsed_nanoseconds": 0,
                "buflo_exact_release_max_passive_sleep_overrun_nanoseconds": 0,
                "buflo_exact_release_active_wait_iterations": 0,
                "buflo_exact_release_active_spin_interruptions": 0,
                "buflo_exact_release_active_spin_interruption_nanoseconds": 0,
                "buflo_exact_release_max_active_spin_gap_nanoseconds": 0,
                "buflo_exact_release_aux_clock_source": (
                    "linux-clock-gettime-monotonic-raw-and-thread-cputime-id-v1"
                ),
                "buflo_exact_release_active_wait_aux_clock_guards": 0,
                "buflo_exact_release_active_wait_aux_clock_unavailable_guards": 0,
                "buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards": 0,
                "buflo_exact_release_active_wait_monotonic_raw_nanoseconds": 0,
                "buflo_exact_release_active_wait_thread_cpu_nanoseconds": 0,
                "buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds": 0,
                "buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds": 0,
                "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds": 0,
                "buflo_exact_release_dispatch_at_or_after_deadline_guards": 0,
                "buflo_exact_release_dispatch_lateness_histogram": {
                    "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                    "counts": [0] * 8,
                },
                "buflo_exact_release_active_spin_gap_histogram": {
                    "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                    "counts": [0] * 8,
                },
                "buflo_exact_release_worst_guard": None,
            }
        )
    if schema_version == 9:
        receipt.update(
            {
                "semantics": RUNNER_WAKEUP_V9_SEMANTICS,
                "buflo_exact_release_dispatch_ready_guards": 0,
                "buflo_exact_release_failed_guards": 0,
                "buflo_exact_release_invalid_counter_frequency_guards": 0,
                "buflo_exact_release_counter_unavailable_failure_guards": 0,
                "buflo_exact_release_counter_nonmonotonic_failure_guards": 0,
                "buflo_exact_release_counter_frequency_changed_guards": 0,
                "buflo_exact_release_counter_target_error_guards": 0,
                "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 0,
                "buflo_exact_release_passive_sleep_calls": 0,
                "buflo_exact_release_passive_sleep_requested_nanoseconds": 0,
                "buflo_exact_release_passive_sleep_elapsed_nanoseconds": 0,
                "buflo_exact_release_max_passive_sleep_overrun_nanoseconds": 0,
                "buflo_exact_release_active_wait_iterations": 0,
                "buflo_exact_release_active_spin_interruptions": 0,
                "buflo_exact_release_active_spin_interruption_nanoseconds": 0,
                "buflo_exact_release_max_active_spin_gap_nanoseconds": 0,
                "buflo_exact_release_active_wait_poll_source": (
                    "linux-aarch64-cntvct-el0-predictive-v1"
                ),
                "buflo_exact_release_active_wait_counter_frequency_hz": None,
                "buflo_exact_release_active_wait_counter_guards": 0,
                "buflo_exact_release_active_wait_counter_unavailable_guards": 0,
                "buflo_exact_release_active_wait_counter_nonmonotonic_guards": 0,
                "buflo_exact_release_active_wait_counter_calibrations": 0,
                "buflo_exact_release_active_wait_instant_confirmations": 0,
                "buflo_exact_release_active_wait_early_confirmation_retries": 0,
                "buflo_exact_release_active_wait_counter_nanoseconds": 0,
                "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 0,
                "buflo_exact_release_max_counter_calibration_span_nanoseconds": 0,
                "buflo_exact_release_dispatch_at_or_after_deadline_guards": 0,
                "buflo_exact_release_dispatch_lateness_histogram": {
                    "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                    "counts": [0] * 8,
                },
                "buflo_exact_release_active_spin_gap_histogram": {
                    "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                    "counts": [0] * 8,
                },
                "buflo_exact_release_worst_guard": None,
                "buflo_exact_release_last_failure": None,
            }
        )
        if guard_entries:
            active_wait_per_guard = 5_001_000
            receipt.update(
                {
                    "buflo_exact_release_guard_entries": guard_entries,
                    "buflo_exact_release_dispatch_ready_guards": guard_entries,
                    "buflo_exact_release_guard_wait_nanoseconds": (
                        guard_entries * active_wait_per_guard
                    ),
                    "buflo_exact_release_active_wait_nanoseconds": (
                        guard_entries * active_wait_per_guard
                    ),
                    "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 1_000,
                    "buflo_exact_release_active_wait_iterations": 2 * guard_entries,
                    "buflo_exact_release_max_active_spin_gap_nanoseconds": 1,
                    "buflo_exact_release_active_wait_counter_frequency_hz": 1_000_000_000,
                    "buflo_exact_release_active_wait_counter_guards": guard_entries,
                    "buflo_exact_release_active_wait_counter_calibrations": guard_entries,
                    "buflo_exact_release_active_wait_instant_confirmations": guard_entries,
                    "buflo_exact_release_active_wait_counter_nanoseconds": (
                        guard_entries * active_wait_per_guard
                    ),
                    "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 1,
                    "buflo_exact_release_max_counter_calibration_span_nanoseconds": 1,
                    "buflo_exact_release_dispatch_lateness_histogram": {
                        "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                        "counts": [guard_entries, 0, 0, 0, 0, 0, 0, 0],
                    },
                    "buflo_exact_release_active_spin_gap_histogram": {
                        "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                        "counts": [guard_entries, 0, 0, 0, 0, 0, 0, 0],
                    },
                    "buflo_exact_release_worst_guard": {
                        "endpoint": 0,
                        "slot": 3,
                        "phase": "committed",
                        "packet_timestamp_us": 20_000,
                        "guard_at_defense_nanoseconds": 15_000_000,
                        "entered_at_defense_nanoseconds": 15_000_000,
                        "active_wait_at_defense_nanoseconds": 15_000_000,
                        "active_wait_started_at_defense_nanoseconds": 15_000_000,
                        "release_at_defense_nanoseconds": 20_000_000,
                        "deadline_at_defense_nanoseconds": 25_000_000,
                        "dispatch_at_defense_nanoseconds": 20_001_000,
                        "guard_entry_lateness_nanoseconds": 0,
                        "passive_sleep_calls": 0,
                        "passive_sleep_requested_nanoseconds": 0,
                        "passive_sleep_elapsed_nanoseconds": 0,
                        "max_passive_sleep_overrun_nanoseconds": 0,
                        "active_wait_iterations": 2,
                        "active_wait_monotonic_nanoseconds": active_wait_per_guard,
                        "active_wait_poll_source": ("linux-aarch64-cntvct-el0-predictive-v1"),
                        "active_wait_counter_frequency_hz": 1_000_000_000,
                        "active_wait_counter_calibrations": 1,
                        "active_wait_instant_confirmations": 1,
                        "active_wait_early_confirmation_retries": 0,
                        "active_wait_counter_nanoseconds": active_wait_per_guard,
                        "max_active_wait_counter_gap_nanoseconds": 1,
                        "max_counter_calibration_span_nanoseconds": 1,
                        "active_spin_interruptions": 0,
                        "active_spin_interruption_nanoseconds": 0,
                        "max_active_spin_gap_nanoseconds": 1,
                        "dispatch_lateness_nanoseconds": 1_000,
                        "dispatch_at_or_after_deadline": False,
                        "dispatch_after_deadline_nanoseconds": 0,
                    },
                }
            )
    return receipt


def _complete_buflo_run(
    *,
    scheduled_outgoing: int,
    scheduled_incoming: int,
    stream_cancellations: int = 0,
    cancelled_capacity: int = 0,
    pending_parser_boundaries: int = 0,
    terminal_incoming_at_stop: int | None = None,
    current_runner: bool = True,
) -> dict[str, object]:
    if terminal_incoming_at_stop is None:
        terminal_incoming_at_stop = scheduled_incoming
    diagnostics = {
        "buflo_scheduled_outgoing_cells": scheduled_outgoing,
        "buflo_scheduled_incoming_cells": scheduled_incoming,
        "buflo_full_outgoing_cells": scheduled_outgoing,
        "buflo_partial_outgoing_cells": 0,
        "buflo_suppressed_outgoing_cells": 0,
        "buflo_missed_outgoing_cells": 0,
        "buflo_missed_incoming_cells": 0,
        "buflo_outgoing_unresolved_cells": 0,
        "buflo_incoming_unresolved_cells": 0,
        "buflo_catch_up_outgoing_cells": 0,
        "buflo_catch_up_incoming_cells": 0,
        "buflo_terminal_subcell_pending_request_cancellations": 0,
        "buflo_terminal_subcell_stream_cancellations": stream_cancellations,
        "buflo_terminal_subcell_exact_capacity_bytes_cancelled": cancelled_capacity,
        "buflo_terminal_subcell_latched": True,
        "buflo_terminal_subcell_latched_at_us": 10_000_001,
        "buflo_terminal_subcell_open_streams_at_latch": stream_cancellations,
        "buflo_terminal_subcell_parser_lease_bytes_at_latch": 0,
        "buflo_terminal_subcell_pending_parser_boundaries_at_latch": (pending_parser_boundaries),
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch": 0,
        "buflo_schedule_stop_latched": True,
        "buflo_schedule_stop_latched_at_us": 10_000_000,
        "buflo_schedule_stop_available_bytes": cancelled_capacity,
        "buflo_schedule_stop_required_bytes": 1_200,
        "buflo_schedule_stop_scheduled_incoming_cells": scheduled_incoming,
        "buflo_schedule_stop_scheduled_outgoing_cells": scheduled_outgoing,
        "buflo_schedule_stop_terminal_incoming_cells": terminal_incoming_at_stop,
        "buflo_schedule_stop_terminal_outgoing_cells": scheduled_outgoing,
        "buflo_paper_equivalent": False,
        "buflo_client_only": True,
        "buflo_egress_backlog_pending": False,
        "buflo_application_complete": True,
        "buflo_minimum_duration_reached": True,
        "buflo_event_guard_triggered": False,
    }
    runner_wakeup_metrics = _runner_wakeup_receipt(
        10, guard_entries=max(scheduled_outgoing - 1, 0)
    )
    if current_runner:
        if scheduled_outgoing != 1:
            raise ValueError("current kernel-TX fixture supports one outgoing opportunity")
        from tests.test_kernel_tx import _runner_wakeup_v16

        runner_wakeup_metrics = _runner_wakeup_v16()
    return {
        "completion_status": "complete",
        "error": None,
        "terminal_evidence_render_errors": [],
        "defense_start_monotonic_ns": 0,
        "resolved_configuration": {
            "schema_version": 2,
            "defense": {"kind": "buflo"},
        },
        "runner_wakeup_metrics": runner_wakeup_metrics,
        "defense_diagnostics": diagnostics,
        "chaff_responses": [
            {"outcome": "buflo_terminal_subcell_tail_cancelled"}
            for _ in range(stream_cancellations)
        ],
        "buflo_summary": {
            "schema_version": 4,
            "kind": "buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "incoming_opportunity_semantics": (
                "client_receive_credit_and_response_qualified_chaff_attempt"
            ),
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "terminal_subcell_policy": (
                "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
            ),
            "terminal_subcell_observer_effect": (
                "typed_stop_sending_and_reset_stream_defense_control_may_follow_the_last_exact_cell"
            ),
            "terminal_schedule_stop_policy": (
                "stop_new_opportunities_at_first_terminal_whole_cell_capacity_"
                "exhaustion_then_drain_already_advertised_incoming_credit"
            ),
            "diagnostics": diagnostics,
        },
        "cs_buflo_summary": None,
    }


def _complete_cs_buflo_run() -> dict[str, object]:
    """Build one exact schema-4 runner receipt for handoff-only tests."""

    diagnostics: dict[str, object] = {}
    for key, kind in fidelity_module._DIAGNOSTIC_CONTRACTS["cs-buflo"].items():
        diagnostics[key] = (
            0
            if kind == fidelity_module._INTEGER
            else False
            if kind == fidelity_module._BOOLEAN
            else []
            if kind == fidelity_module._CS_RATE_TRANSITION_VECTOR
            else "unused"
        )
    diagnostics.update(
        {
            "cs_buflo_paper_equivalent": False,
            "cs_buflo_client_only": True,
            "cs_buflo_payload_padding": True,
            "cs_buflo_total_padding": False,
            "cs_buflo_early_termination_semantics": (
                fidelity_module.CS_BUFLO_EARLY_TERMINATION_SEMANTICS
            ),
            "cs_buflo_scheduled_outgoing_cells": 1,
            "cs_buflo_scheduled_incoming_cells": 1,
            "cs_buflo_full_outgoing_cells": 1,
            "cs_buflo_desired_udp_bytes": 600,
            "cs_buflo_realized_udp_bytes": 600,
            "cs_buflo_chaff_stream_bytes": 600,
            "cs_buflo_lateness_us_total": 100,
            "cs_buflo_lateness_us_max": 100,
            "cs_buflo_natural_outgoing_bytes": 500,
            "cs_buflo_natural_incoming_bytes": 300,
            "cs_buflo_cover_outgoing_bytes": 100,
            "cs_buflo_cover_incoming_bytes": 300,
            "cs_buflo_real_bearing_outgoing_bytes": 400,
            "cs_buflo_real_bearing_incoming_bytes": 300,
            "cs_buflo_realized_incoming_credit_bytes": 600,
            "cs_buflo_outgoing_padding_basis_natural_bytes": 500,
            "cs_buflo_incoming_padding_basis_natural_bytes": 300,
            "cs_buflo_outgoing_padding_basis_cover_bytes": 100,
            "cs_buflo_incoming_padding_basis_cover_bytes": 300,
            "cs_buflo_outgoing_padding_basis_total_bytes": 600,
            "cs_buflo_incoming_padding_basis_total_bytes": 600,
            "cs_buflo_reference_tcp_write_size_bytes": 548,
            "cs_buflo_reference_nominal_tcp_packet_size_bytes": 600,
            "cs_buflo_runtime_udp_packet_size_bytes": 600,
            "cs_buflo_outgoing_termination_accounted_bytes": 1_200,
            "cs_buflo_incoming_termination_accounted_bytes": 600,
            "cs_buflo_outgoing_last_termination_increment_bytes": 600,
            "cs_buflo_incoming_last_termination_increment_bytes": 600,
            "cs_buflo_outgoing_padding_target_bytes": 1_024,
            "cs_buflo_incoming_padding_target_bytes": 600,
            "cs_buflo_outgoing_power_of_two_crossed": True,
            "cs_buflo_incoming_power_of_two_crossed": True,
            "cs_buflo_outgoing_interval_us": 8_192,
            "cs_buflo_incoming_interval_us": 8_192,
            "cs_buflo_rate_boundary_translation_version": 2,
            "cs_buflo_rate_boundary_counter_semantics": (
                fidelity_module.CS_BUFLO_RATE_BOUNDARY_COUNTER_SEMANTICS
            ),
            "cs_buflo_author_rate_boundary_counter_semantics": (
                fidelity_module.CS_BUFLO_AUTHOR_RATE_BOUNDARY_COUNTER_SEMANTICS
            ),
            "cs_buflo_rate_transitions": [],
            "cs_buflo_next_outgoing_adaptation_boundary_bytes": 16_384,
            "cs_buflo_next_incoming_adaptation_boundary_bytes": 16_384,
            "cs_buflo_incoming_local_realized_cells": 1,
            "cs_buflo_application_complete": True,
            "cs_buflo_quiet_time_reached": True,
            "cs_buflo_local_termination_latched": True,
            "cs_buflo_local_et_latched_at_us": 300,
            "cs_buflo_local_et_before_application_complete": False,
            "cs_buflo_early_termination_translation_version": 2,
            "cs_buflo_termination_stop_policy": (fidelity_module.CS_BUFLO_TERMINATION_STOP_POLICY),
            "cs_buflo_outgoing_termination_stop_latched": True,
            "cs_buflo_incoming_termination_stop_latched": True,
            "cs_buflo_outgoing_termination_stop_crossing_total_bytes": 1_200,
            "cs_buflo_incoming_termination_stop_crossing_total_bytes": 0,
            "cs_buflo_outgoing_termination_stop_crossing_increment_bytes": 600,
            "cs_buflo_incoming_termination_stop_crossing_increment_bytes": 0,
            "cs_buflo_outgoing_termination_stop_reason": "power_of_two_crossing",
            "cs_buflo_incoming_termination_stop_reason": "padding_target_reached",
            "cs_buflo_outgoing_termination_stop_phase": "application_complete",
            "cs_buflo_incoming_termination_stop_phase": "application_complete",
            "cs_buflo_outgoing_termination_stop_latched_at_us": 100,
            "cs_buflo_incoming_termination_stop_latched_at_us": 100,
            "cs_buflo_outgoing_termination_stop_scheduled_cells_at_stop": 1,
            "cs_buflo_incoming_termination_stop_scheduled_cells_at_stop": 1,
            "cs_buflo_outgoing_termination_stop_terminal_cells_at_stop": 0,
            "cs_buflo_incoming_termination_stop_terminal_cells_at_stop": 0,
            "cs_buflo_outgoing_termination_stop_progress_bytes_at_stop": 600,
            "cs_buflo_incoming_termination_stop_progress_bytes_at_stop": 600,
            "cs_buflo_outgoing_termination_stop_padding_target_bytes_at_stop": 1_024,
            "cs_buflo_incoming_termination_stop_padding_target_bytes_at_stop": 600,
            "cs_buflo_outgoing_termination_stop_provisional_invalidation_count": 0,
            "cs_buflo_incoming_termination_stop_provisional_invalidation_count": 1,
            "cs_buflo_egress_backlog_pending": False,
            "cs_buflo_event_guard_triggered": False,
        }
    )
    summary = {
        "schema_version": 4,
        "kind": "cs_buflo",
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "incoming_opportunity_semantics": (
            "client_receive_credit_and_response_qualified_chaff_attempt"
        ),
        "unavailable_peer_properties": [
            "scheduled_server_datagram_timing",
            "scheduled_server_datagram_size",
        ],
        "early_termination_semantics": (fidelity_module.CS_BUFLO_EARLY_TERMINATION_SEMANTICS),
        "early_termination_translation_version": 2,
        "termination_stop_policy": fidelity_module.CS_BUFLO_TERMINATION_STOP_POLICY,
        "incoming_cadence_boundary": fidelity_module.CS_BUFLO_INCOMING_CADENCE_BOUNDARY,
        "incoming_terminal_boundary": (fidelity_module.CS_BUFLO_INCOMING_TERMINAL_BOUNDARY),
        "incoming_boundary_separation": (fidelity_module.CS_BUFLO_INCOMING_BOUNDARY_SEPARATION),
        "diagnostics": diagnostics,
    }
    return {
        "completion_status": "complete",
        "error": None,
        "terminal_evidence_render_errors": [],
        "defense_start_monotonic_ns": 0,
        "resolved_configuration": {
            "schema_version": 2,
            "defense": {"kind": "cs_buflo"},
        },
        "runner_wakeup_metrics": _runner_wakeup_receipt(10),
        "defense_diagnostics": diagnostics,
        "buflo_summary": None,
        "cs_buflo_summary": summary,
    }


def test_schema_ten_buflo_guarded_release_remains_historical() -> None:
    run = _complete_buflo_run(
        scheduled_outgoing=2,
        scheduled_incoming=2,
        current_runner=False,
    )
    metrics = run["runner_wakeup_metrics"]

    assert fidelity_module.new_defense_terminal_receipts_valid(
        run,
        "buflo",
        require_application_complete=True,
    )
    assert not fidelity_module.new_defense_terminal_receipts_valid(
        run,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    assert metrics["buflo_exact_release_guard_entries"] == 1
    assert metrics["buflo_exact_release_dispatch_ready_guards"] == 1
    assert metrics["buflo_exact_release_failed_guards"] == 0
    assert metrics["buflo_exact_release_last_failure"] is None
    assert all(
        type(metrics["buflo_exact_release_worst_guard"][key]) is int
        for key in fidelity_module.RUNNER_WAKEUP_V7_WORST_TIME_KEYS
    )


def _formal_source_binding_fixture(
    tmp_path: Path,
) -> tuple[
    Path,
    dict[str, object],
    list[dict[str, object]],
    dict[str, str],
    VerifiedResult,
]:
    source_root = (tmp_path / "formal-result").resolve()
    source_sample_relative = "samples/example-r1/as-defined/visit-001/buflo"
    source_sample_root = source_root / source_sample_relative
    (source_sample_root / "neqo").mkdir(parents=True)
    source_files = {
        "capture.pcapng": b"sealed-pcapng\n",
        "neqo/run.json": b'{"completion_status":"complete"}\n',
        "neqo/schedule.csv": b"target_time_us\n0\n",
        "neqo/events.csv": b"monotonic_us\n0\n",
        "neqo/packets.csv": b"monotonic_us\n0\n",
    }
    for relative, content in source_files.items():
        path = source_sample_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    workload_relative = "inputs/workloads/example-r1.json"
    workload = source_root / workload_relative
    workload.parent.mkdir(parents=True)
    workload.write_bytes(b'{"id":"example-r1"}\n')

    checksums = {
        f"{source_sample_relative}/{relative}": hashlib.sha256(content).hexdigest()
        for relative, content in source_files.items()
    }
    checksums[workload_relative] = hashlib.sha256(workload.read_bytes()).hexdigest()
    evidence = source_root / "evidence.sha256"
    evidence.write_text(
        "".join(f"{checksums[path]}  {path}\n" for path in sorted(checksums)),
        encoding="utf-8",
    )

    sample = {
        "sample_id": "sample-001",
        "workload_id": "example-r1",
        "request_policy": "as-defined",
        "visit": 1,
        "defense": "buflo",
        "runtime_kind": "buflo",
        "baseline": False,
        "seed": 7,
        "attempts": 1,
        "path": source_sample_relative,
    }
    source = {"immutable": True}
    experiment = {
        "name": "formal-test",
        "configuration": {"campaign_sha256": "1" * 64},
        "source": source,
        "samples": [sample],
        "started_at": "2027-01-01T00:00:00+00:00",
        "completed_at": "2027-01-01T00:00:01+00:00",
    }
    receipt = VerifiedResult(
        root=source_root,
        experiment=experiment,
        checksums=checksums,
        accepted_samples={
            "sample-001": {
                relative: digest
                for relative, digest in checksums.items()
                if relative.startswith(f"{source_sample_relative}/")
            }
        },
    )

    handoff_root = (tmp_path / "handoff").resolve()
    local_bindings = {
        "raw_pcapng_path": ("raw/sample-001.pcapng", "capture.pcapng"),
        "raw_run_path": ("raw/sample-001.run.json", "neqo/run.json"),
        "runner_schedule_path": (
            "diagnostics/sample-001.schedule.csv",
            "neqo/schedule.csv",
        ),
        "runner_events_path": (
            "diagnostics/sample-001.events.csv",
            "neqo/events.csv",
        ),
        "runner_packets_path": (
            "diagnostics/sample-001.packets.csv",
            "neqo/packets.csv",
        ),
    }
    row: dict[str, object] = dict(sample)
    row["source_sample_path"] = row.pop("path")
    handoff_checksums: dict[str, str] = {}
    for path_key, (local_relative, source_suffix) in local_bindings.items():
        destination = handoff_root / local_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((source_sample_root / source_suffix).read_bytes())
        digest_key = path_key.replace("_path", "_sha256")
        row[path_key] = local_relative
        row[digest_key] = checksums[f"{source_sample_relative}/{source_suffix}"]
        handoff_checksums[local_relative] = str(row[digest_key])
    application_relative = "inputs/acquisition-block-001/example-r1.json"
    application = handoff_root / application_relative
    application.parent.mkdir(parents=True)
    application.write_bytes(workload.read_bytes())
    row["application_workload_path"] = application_relative
    row["application_workload_sha256"] = checksums[workload_relative]
    row["acquisition_block_index"] = 0
    handoff_checksums[application_relative] = checksums[workload_relative]

    dataset: dict[str, object] = {
        "execution_source": source,
        "blocks": [
            {
                "acquisition_block_index": 0,
                "result_name": "formal-test",
                "result_root": str(source_root),
                "result_evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                "authoritative_files": len(checksums),
                "configuration": experiment["configuration"],
                "started_at": experiment["started_at"],
                "completed_at": experiment["completed_at"],
                "elapsed_seconds": 1.0,
            }
        ],
    }
    return handoff_root, dataset, [row], handoff_checksums, receipt


def _install_formal_source_verifier(
    monkeypatch: pytest.MonkeyPatch,
    receipt: VerifiedResult,
) -> list[Path]:
    verified_roots: list[Path] = []

    def verify(root: Path) -> VerifiedResult:
        verified_roots.append(Path(root))
        return receipt

    monkeypatch.setattr(handoff, "FORMAL_BLOCKS", (0,))
    monkeypatch.setattr(handoff, "verify_result", verify)
    monkeypatch.setattr(handoff, "_validate_source_results", lambda *_args, **_kwargs: None)
    return verified_roots


def _kernel_tx_handoff_fixture(
    tmp_path: Path,
) -> tuple[
    Path,
    dict[str, object],
    dict[str, object],
    list[dict[str, object]],
]:
    from tests.test_kernel_tx import _evidence, _runner_wakeup_v16

    source_root = (tmp_path / "source").resolve()
    sample_id = "sample-001"
    source_run = source_root / "samples/example/as-defined/visit-001/buflo/neqo/run.json"
    source_run.parent.mkdir(parents=True)
    wakeups = _runner_wakeup_v16()
    run: dict[str, object] = {"runner_wakeup_metrics": wakeups}
    run_bytes = json.dumps(run, sort_keys=True, separators=(",", ":")).encode()
    source_run.write_bytes(run_bytes)
    run_digest = hashlib.sha256(run_bytes).hexdigest()

    capture_bytes = b"sealed post-veth pcapng"
    capture_digest = hashlib.sha256(capture_bytes).hexdigest()
    evidence, router_receipt, router_packets = _evidence(wakeups["buflo_kernel_tx"])

    def replace_fixture_digest(value: object) -> object:
        if isinstance(value, dict):
            return {key: replace_fixture_digest(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace_fixture_digest(item) for item in value]
        if value == "a" * 64:
            return run_digest
        if value == "b" * 64:
            return capture_digest
        return value

    evidence = replace_fixture_digest(evidence)
    router_receipt = replace_fixture_digest(router_receipt)
    assert isinstance(evidence, dict)
    assert isinstance(router_receipt, dict)
    sidecar = source_root / handoff.KERNEL_TX_EVIDENCE_DIRECTORY / sample_id
    sidecar.mkdir(parents=True)
    sidecar_files = {
        "router-capture.pcapng": capture_bytes,
        "router-receipt.json": json.dumps(
            router_receipt, sort_keys=True, separators=(",", ":")
        ).encode(),
        "kernel-tx-evidence.json": json.dumps(
            evidence, sort_keys=True, separators=(",", ":")
        ).encode(),
    }
    artifacts: dict[str, str] = {}
    checksums = {
        source_run.relative_to(source_root).as_posix(): run_digest,
    }
    for name, content in sidecar_files.items():
        path = sidecar / name
        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        artifacts[name] = digest
        checksums[path.relative_to(source_root).as_posix()] = digest
    sample = {
        "sample_id": sample_id,
        "runtime_kind": "buflo",
        "diagnostics": {
            handoff.KERNEL_TX_EVIDENCE_RECEIPT_KEY: {
                "schema_version": handoff.KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION,
                "source": handoff.KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
                "directory": f"{handoff.KERNEL_TX_EVIDENCE_DIRECTORY}/{sample_id}",
                "artifacts": artifacts,
            }
        },
    }
    receipt = VerifiedResult(
        root=source_root,
        experiment={"samples": [sample]},
        checksums=checksums,
        accepted_samples={},
    )
    root = (tmp_path / "handoff-kernel").resolve()
    (root / "raw").mkdir(parents=True)
    (root / handoff.KERNEL_TX_EVIDENCE_DIRECTORY).mkdir()
    local_run = root / "raw/sample-001.run.json"
    local_run.write_bytes(run_bytes)
    binding = handoff._export_kernel_tx_sidecar(
        root,
        receipt,
        sample,
        run=run,
    )
    assert isinstance(binding, dict)
    row: dict[str, object] = {
        "sample_id": sample_id,
        "runtime_kind": "buflo",
        "raw_run_path": "raw/sample-001.run.json",
        "kernel_tx_evidence": binding,
    }
    return root, row, run, router_packets


def test_focused_handoff_copies_and_deep_verifies_kernel_tx_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, row, run, router_packets = _kernel_tx_handoff_fixture(tmp_path)

    expected = {
        f"kernel-tx-evidence/sample-001/{name}"
        for name in handoff.KERNEL_TX_EVIDENCE_FILES
    }
    assert handoff._validate_kernel_tx_binding(root, row, run=run) == expected
    monkeypatch.setattr(
        "qcsd_lab.kernel_tx_runtime.extract_router_udp_packets",
        lambda _path: router_packets,
    )
    handoff._deep_validate_kernel_tx_binding(root, row, run=run)
    assert not any(
        path.is_relative_to(root / "raw/sample-001")
        for path in (root / handoff.KERNEL_TX_EVIDENCE_DIRECTORY).rglob("*")
    )


def test_handoff_kernel_tx_runner_pairs_preserve_history_and_reject_cross_versions() -> None:
    from tests.test_kernel_tx import (
        _runner_receipt_v2,
        _runner_receipt_v3,
        _runner_receipt_v4,
        _runner_receipt_v5,
        _runner_receipt_v6,
        _runner_receipt_v7,
        _runner_wakeup_v11,
        _runner_wakeup_v12,
        _runner_wakeup_v13,
        _runner_wakeup_v14,
        _runner_wakeup_v15,
        _runner_wakeup_v16,
    )

    schema_eleven_v2 = _runner_wakeup_v11()
    schema_eleven_v2["buflo_kernel_tx"] = _runner_receipt_v2()
    schema_eleven_v2["semantics"] = fidelity_module.RUNNER_WAKEUP_V11_SEMANTICS
    for wakeups in (
        _runner_wakeup_v11(),
        schema_eleven_v2,
        _runner_wakeup_v12(),
        _runner_wakeup_v13(),
        _runner_wakeup_v14(),
        _runner_wakeup_v15(),
        _runner_wakeup_v16(),
    ):
        required, raw = handoff._runner_kernel_tx_requirement(
            {"runner_wakeup_metrics": wakeups},
            runtime_kind="buflo",
        )
        assert required is True
        assert raw is wakeups["buflo_kernel_tx"]

    invalid_pairs = (
        (_runner_wakeup_v11(), _runner_receipt_v3()),
        (_runner_wakeup_v12(), _runner_receipt_v4()),
        (_runner_wakeup_v13(), _runner_receipt_v3()),
        (_runner_wakeup_v14(), _runner_receipt_v4()),
        (_runner_wakeup_v14(), _runner_receipt_v6()),
        (_runner_wakeup_v15(), _runner_receipt_v5()),
        (_runner_wakeup_v16(), _runner_receipt_v6()),
        (_runner_wakeup_v15(), _runner_receipt_v7()),
    )
    for wakeups, raw in invalid_pairs:
        wakeups["buflo_kernel_tx"] = raw
        with pytest.raises(ValueError, match="runner-wakeup/raw schema pairing"):
            handoff._runner_kernel_tx_requirement(
                {"runner_wakeup_metrics": wakeups},
                runtime_kind="buflo",
            )


def test_focused_handoff_kernel_tx_deep_verification_rejects_coherent_reseal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, row, run, router_packets = _kernel_tx_handoff_fixture(tmp_path)
    binding = row["kernel_tx_evidence"]
    assert isinstance(binding, dict)
    artifacts = binding["artifacts"]
    assert isinstance(artifacts, dict)
    artifact = artifacts["kernel-tx-evidence.json"]
    assert isinstance(artifact, dict)
    path = root / str(artifact["path"])
    evidence = json.loads(path.read_text(encoding="utf-8"))
    evidence["aggregate"]["matched_item_count"] = 1
    path.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    artifact["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    assert handoff._validate_kernel_tx_binding(root, row, run=run)
    monkeypatch.setattr(
        "qcsd_lab.kernel_tx_runtime.extract_router_udp_packets",
        lambda _path: router_packets,
    )
    with pytest.raises(ValueError, match="failed deep validation"):
        handoff._deep_validate_kernel_tx_binding(root, row, run=run)


@pytest.mark.parametrize("mutation", ["missing", "extra-directory", "symlink"])
def test_focused_handoff_kernel_tx_inventory_is_exact(
    tmp_path: Path,
    mutation: str,
) -> None:
    root, row, run, _router_packets = _kernel_tx_handoff_fixture(tmp_path)
    sidecar = root / handoff.KERNEL_TX_EVIDENCE_DIRECTORY / "sample-001"
    if mutation == "missing":
        (sidecar / "router-receipt.json").unlink()
    elif mutation == "extra-directory":
        (sidecar / "extra").mkdir()
    else:
        (sidecar / "router-receipt.json").unlink()
        (sidecar / "router-receipt.json").symlink_to("kernel-tx-evidence.json")

    with pytest.raises(ValueError, match="kernel-TX directory"):
        handoff._validate_kernel_tx_binding(root, row, run=run)


def test_formal_handoff_reverifies_and_binds_authoritative_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, dataset, rows, checksums, receipt = _formal_source_binding_fixture(tmp_path)
    verified_roots = _install_formal_source_verifier(monkeypatch, receipt)

    handoff._validate_formal_source_bindings(
        root,
        dataset,
        rows,
        handoff_checksums=checksums,
    )

    assert verified_roots == [receipt.root]


def test_public_formal_handoff_validation_rechecks_sources_when_not_deep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, dataset, rows, _checksums, receipt = _formal_source_binding_fixture(tmp_path)
    verified_roots = _install_formal_source_verifier(monkeypatch, receipt)
    for directory in ("stripped", "traces", handoff.KERNEL_TX_EVIDENCE_DIRECTORY):
        (root / directory).mkdir(parents=True)
    (root / "README.md").write_text("formal test handoff\n", encoding="utf-8")
    dataset.update(
        {
            "formal": True,
            "result_names": ["formal-test"],
            "counts_by_defense": {"buflo": 1},
        }
    )
    dataset["schema_version"] = handoff.HANDOFF_SCHEMA_VERSION
    rows[0].update(
        schema_version=handoff.HANDOFF_SCHEMA_VERSION,
        packet_count=0,
        kernel_tx_evidence=None,
    )
    (root / "dataset.json").write_text(json.dumps(dataset, sort_keys=True) + "\n", encoding="utf-8")
    (root / "samples.jsonl").write_text(
        json.dumps(rows[0], sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _write_checksums(root)

    sample = SimpleNamespace(sample_id="sample-001", defense="buflo", trace=())
    monkeypatch.setattr(handoff, "_validate_handoff_rows", lambda *_args, **_kwargs: (True, False))
    monkeypatch.setattr(handoff, "_validate_dataset", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handoff, "load_study_handoff", lambda _root: (sample,))
    monkeypatch.setattr(handoff, "validate_formal_cohort", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handoff, "FORMAL_RESULT_NAMES", ("formal-test",))

    assert validate_study_handoff(root, formal=True, deep=False) == root
    assert verified_roots == [receipt.root]


@pytest.mark.parametrize(
    ("path_key", "digest_key"),
    [
        ("raw_pcapng_path", "raw_pcapng_sha256"),
        ("raw_run_path", "raw_run_sha256"),
        ("runner_schedule_path", "runner_schedule_sha256"),
        ("runner_events_path", "runner_events_sha256"),
        ("runner_packets_path", "runner_packets_sha256"),
        ("application_workload_path", "application_workload_sha256"),
    ],
)
def test_formal_handoff_rejects_rechecksummed_source_copy_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path_key: str,
    digest_key: str,
) -> None:
    root, dataset, rows, checksums, receipt = _formal_source_binding_fixture(tmp_path)
    _install_formal_source_verifier(monkeypatch, receipt)
    row = rows[0]
    local_relative = str(row[path_key])
    (root / local_relative).write_bytes(b"locally substituted and rechecksummed\n")
    substituted_digest = hashlib.sha256((root / local_relative).read_bytes()).hexdigest()
    row[digest_key] = substituted_digest
    checksums[local_relative] = substituted_digest

    with pytest.raises(ValueError, match="differs from its sealed source artifact"):
        handoff._validate_formal_source_bindings(
            root,
            dataset,
            rows,
            handoff_checksums=checksums,
        )


@pytest.mark.parametrize("binding", ["result_evidence_sha256", "authoritative_files"])
def test_formal_handoff_rejects_result_seal_binding_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    binding: str,
) -> None:
    root, dataset, rows, checksums, receipt = _formal_source_binding_fixture(tmp_path)
    _install_formal_source_verifier(monkeypatch, receipt)
    block = dataset["blocks"][0]
    assert isinstance(block, dict)
    block[binding] = "0" * 64 if binding.endswith("sha256") else 999

    with pytest.raises(ValueError, match="source result seal or lineage differs"):
        handoff._validate_formal_source_bindings(
            root,
            dataset,
            rows,
            handoff_checksums=checksums,
        )


def test_formal_handoff_rejects_noncanonical_source_result_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, dataset, rows, checksums, receipt = _formal_source_binding_fixture(tmp_path)
    verified_roots = _install_formal_source_verifier(monkeypatch, receipt)
    alias = tmp_path / "result-alias"
    alias.symlink_to(receipt.root, target_is_directory=True)
    block = dataset["blocks"][0]
    assert isinstance(block, dict)
    block["result_root"] = str(alias)

    with pytest.raises(ValueError, match="source result root is not canonical"):
        handoff._validate_formal_source_bindings(
            root,
            dataset,
            rows,
            handoff_checksums=checksums,
        )
    assert verified_roots == []


def test_shape_only_pcap_round_trip(tmp_path: Path) -> None:
    trace = (
        _packet(0, "outgoing", 1_242),
        _packet(8_192_123, "incoming", 642),
        _packet(2_000_000_000, "outgoing", 100),
    )
    path = tmp_path / "shape.pcap"

    _write_shape_only_pcap(trace, path)

    assert _read_shape_only_pcap(path) == tuple(
        (packet.relative_time_ns, packet.direction, packet.frame_len) for packet in trace
    )
    assert b"192.0.2.1" not in path.read_bytes()


def test_shape_only_pcap_rejects_non_monotonic_input(tmp_path: Path) -> None:
    trace = (
        _packet(10, "outgoing", 100),
        _packet(9, "incoming", 100),
    )
    with pytest.raises(ValueError, match="not monotonic"):
        _write_shape_only_pcap(trace, tmp_path / "shape.pcap")


def test_runner_extension_accepts_current_exact_packet_composition() -> None:
    row = {field: "" for field in SCHEDULE_QCSD_FIELDS}
    row.update(
        qcsd_outcome_schema_version="2",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        application_stream_bytes="900",
        retransmission_stream_bytes="100",
        chaff_stream_bytes="100",
        defense_control_bytes="0",
        quic_padding_bytes="50",
        other_quic_bytes="50",
        lateness_us="4",
    )
    _validate_runner_extension(row, label="packets.csv row")
    row["chaff_stream_bytes"] = "99"
    with pytest.raises(ValueError, match="composition"):
        _validate_runner_extension(row, label="packets.csv row")


@pytest.mark.parametrize(
    "suffix",
    [
        fidelity_module.LEGACY_SCHEDULE_QCSD_FIELDS,
        fidelity_module.ADVERTISEMENT_SCHEDULE_QCSD_FIELDS,
        fidelity_module.CONSUMPTION_SCHEDULE_QCSD_FIELDS,
    ],
)
def test_extended_runner_reader_preserves_historical_headers(
    tmp_path: Path,
    suffix: tuple[str, ...],
) -> None:
    path = tmp_path / "schedule.csv"
    fields = (*handoff.SCHEDULE_PREFIX_FIELDS, *suffix)
    row = {field: "" for field in fields}
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerow(row)

    rows = handoff._read_extended_runner_csv(
        path,
        handoff.SCHEDULE_PREFIX_FIELDS,
        label="historical schedule.csv",
        require_current_schema=False,
    )
    assert rows[0]["terminal_defense_elapsed_us"] == ""
    with pytest.raises(ValueError, match="exact extended schema"):
        handoff._read_extended_runner_csv(
            path,
            handoff.SCHEDULE_PREFIX_FIELDS,
            label="current schedule.csv",
        )


@pytest.mark.parametrize("detailed", [False, True])
def test_nonformal_handoff_closed_inventory(tmp_path: Path, detailed: bool) -> None:
    root = tmp_path / "handoff"
    directories = [root / "raw", root / "stripped", root / "traces"]
    if detailed:
        directories.append(root / "diagnostics")
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    trace = root / "traces/sample.csv"
    trace.write_text(
        "relative_time_ns,direction,length_bytes,signed_length_bytes\n"
        "0,outgoing,1242,1242\n"
        "100,incoming,642,-642\n",
        encoding="utf-8",
    )
    import hashlib

    artifacts = {
        "raw_pcapng_path": "raw/sample.pcapng",
        "raw_pcap_path": "raw/sample.pcap",
        "raw_run_path": "raw/sample.run.json",
        "shape_pcap_path": "stripped/sample.pcap",
        "trace_path": "traces/sample.csv",
    }
    buflo_run = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=1,
    )
    for key, relative in artifacts.items():
        if key != "trace_path":
            (root / relative).write_bytes(
                (
                    (json.dumps(buflo_run, sort_keys=True) + "\n").encode()
                    if detailed and key == "raw_run_path"
                    else key.encode()
                )
            )
    digests = {
        key.replace("_path", "_sha256"): hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for key, relative in artifacts.items()
    }
    row = {
        "schema_version": 1,
        "sample_id": "sample",
        "class_label": "example-r1",
        "workload_id": "example-r1",
        "defense": "buflo",
        "runtime_kind": "buflo",
        "baseline": False,
        "request_policy": "as-defined",
        "visit": 1,
        "seed": 2,
        "attempts": 1,
        "acquisition_block_index": 0,
        "acquisition_block_id": "acquisition-block-001",
        "split": "train",
        "paired_visit_id": "block-001/example-r1/as-defined/visit-001",
        "source_result": "test-result",
        "source_sample_path": "samples/example-r1/as-defined/visit-001/buflo",
        **artifacts,
        **digests,
        "packet_count": 2,
        "performance": None,
        "input_bindings": {
            "campaign_sha256": "1" * 64,
            "application_workload_sha256": "2" * 64,
            "runtime_workload_sha256": "3" * 64,
            "chaff_qualification_sha256": "4" * 64,
            "chaff_manifest_sha256": "5" * 64,
            "defense_parameters_sha256": "6" * 64,
            "defense_parameters_provenance_sha256": "7" * 64,
            "max_response_bytes": 1_048_576,
            "max_udp_payload_size": 1_200,
        },
    }
    if detailed:
        schedule = root / "diagnostics/sample.schedule.csv"
        events = root / "diagnostics/sample.events.csv"
        packets = root / "diagnostics/sample.packets.csv"
        schedule_fields = (*handoff.SCHEDULE_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
        outgoing_schedule = {field: "" for field in schedule_fields}
        outgoing_schedule.update(
            target_time_us="0",
            direction="outgoing",
            size="1200",
            connection="0",
            action_time_us="0",
            satisfaction="satisfied",
            observed_size="1200",
            slot_id="0",
            qcsd_outcome_schema_version="3",
            send_policy="exact",
            desired_udp_bytes="1200",
            observed_udp_bytes="1200",
            terminal_defense_elapsed_us="0",
        )
        incoming_schedule = {field: "" for field in schedule_fields}
        incoming_schedule.update(
            target_time_us="0",
            direction="incoming",
            size="1200",
            connection="0",
            action_time_us="0",
            satisfaction="satisfied",
            slot_id="1",
            qcsd_outcome_schema_version="3",
            send_policy="exact",
            desired_udp_bytes="1200",
            credit_advertised_at_us="100",
            credit_advertisement_delay_us="100",
            credit_consumed_at_us="500",
            credit_consumption_delay_us="500",
            terminal_defense_elapsed_us="500",
        )
        with schedule.open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=schedule_fields)
            writer.writeheader()
            writer.writerows([outgoing_schedule, incoming_schedule])
        event_fields = (*handoff._EVENT_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
        with events.open("w", newline="", encoding="utf-8") as destination:
            csv.DictWriter(destination, fieldnames=event_fields).writeheader()
        packet_fields = (*handoff._PACKET_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
        packet = {field: "" for field in packet_fields}
        packet.update(
            direction="outgoing",
            monotonic_us="0",
            connection="0",
            observed_udp_length="1200",
            scheduled_target="1200",
            satisfaction="satisfied",
            slot_id="0",
            qcsd_outcome_schema_version="2",
            send_policy="exact",
            desired_udp_bytes="1200",
            observed_udp_bytes="1200",
            application_stream_bytes="0",
            retransmission_stream_bytes="0",
            chaff_stream_bytes="1200",
            defense_control_bytes="0",
            quic_padding_bytes="0",
            other_quic_bytes="0",
            lateness_us="0",
        )
        with packets.open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=packet_fields)
            writer.writeheader()
            writer.writerow(packet)
        diagnostics_artifacts = {
            "runner_schedule_path": "diagnostics/sample.schedule.csv",
            "runner_events_path": "diagnostics/sample.events.csv",
            "runner_packets_path": "diagnostics/sample.packets.csv",
        }
        row.update(diagnostics_artifacts)
        row.update(
            {
                key.replace("_path", "_sha256"): hashlib.sha256(
                    (root / relative).read_bytes()
                ).hexdigest()
                for key, relative in diagnostics_artifacts.items()
            }
        )
        row["algorithm_diagnostics"] = _algorithm_diagnostics(
            buflo_run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    (root / "samples.jsonl").write_text(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    (root / "dataset.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_type": "qcsd-buflo-csbuflo-study-handoff",
                "purpose": "buflo-csbuflo-focused-evaluation",
                "formal": False,
                "paper_equivalent": False,
                "implementation_scope": "client_only_quic",
                "result_names": ["test-result"],
                "blocks": [
                    {
                        "acquisition_block_index": 0,
                        "acquisition_block_id": "acquisition-block-001",
                        "split": "train",
                        "result_name": "test-result",
                        "result_root": "/test/result",
                        "result_evidence_sha256": "0" * 64,
                        "authoritative_files": 1,
                        "campaign_path": None,
                        "campaign_sha256": "1" * 64,
                        "configuration": {"campaign_sha256": "1" * 64},
                        "configuration_sha256": (
                            "813674db0efcfd612766349adc393983af6f4963e4100e22934d15b7aae2e83e"
                        ),
                    }
                ],
                "sample_count": 1,
                "classes": ["example-r1"],
                "defenses": ["buflo"],
                "counts_by_defense": {"buflo": 1},
                "counts_by_split": {"train": 1},
                "observation": {
                    "length_basis": "Ethernet frame.len",
                    "direction_rule": "client egress positive; server ingress negative",
                    "model_input": "traces/*.csv or stripped/*.pcap",
                    "raw_restricted": True,
                },
                "execution_source": {},
                "exporter_source": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text("test\n", encoding="utf-8")
    _write_checksums(root)

    assert validate_study_handoff(root, formal=False, deep=False) == root.resolve()

    trace.write_text(trace.read_text(encoding="utf-8") + "1,outgoing,42,42\n", encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_study_handoff(root, formal=False, deep=False)


def test_buflo_algorithm_diagnostics_bind_typed_tail_action_and_control_packet(
    tmp_path: Path,
) -> None:
    schedule = tmp_path / "schedule.csv"
    events = tmp_path / "events.csv"
    packets = tmp_path / "packets.csv"

    def write_rows(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    schedule_fields = (*handoff.SCHEDULE_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    schedule_row = {field: "" for field in schedule_fields}
    schedule_row.update(
        target_time_us="0",
        direction="outgoing",
        size="1200",
        connection="0",
        action_time_us="0",
        satisfaction="satisfied",
        observed_size="1200",
        slot_id="1",
        qcsd_outcome_schema_version="3",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        terminal_defense_elapsed_us="4999",
    )
    incoming_schedule_row = {field: "" for field in schedule_fields}
    incoming_schedule_row.update(
        target_time_us="0",
        direction="incoming",
        size="1200",
        # A logical receive-credit opportunity can be advertised and consumed
        # across multiple streams or endpoints, so its terminal action has no
        # singular connection identity.  The slot and typed credit chronology
        # remain the authoritative binding.
        connection="",
        action_time_us="0",
        satisfaction="satisfied",
        slot_id="2",
        qcsd_outcome_schema_version="3",
        send_policy="exact",
        desired_udp_bytes="1200",
        credit_advertised_at_us="0",
        credit_advertisement_delay_us="0",
        credit_consumed_at_us="10000001",
        credit_consumption_delay_us="10000001",
        terminal_defense_elapsed_us="10000001",
    )
    write_rows(schedule, schedule_fields, [schedule_row, incoming_schedule_row])

    event_fields = (*handoff._EVENT_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    event_row = {field: "" for field in event_fields}
    event_row.update(
        monotonic_us="10000010",
        connection="0",
        event="action",
        outcome="applied",
        details=json.dumps(
            {
                "type": "cancel_chaff",
                "endpoint": 0,
                "stream": 4,
                "reason": "buflo_terminal_subcell_tail",
            },
            sort_keys=True,
        ),
    )
    write_rows(events, event_fields, [event_row])

    packet_fields = (*handoff._PACKET_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    exact_packet = {field: "" for field in packet_fields}
    exact_packet.update(
        direction="outgoing",
        monotonic_us="4999",
        connection="0",
        observed_udp_length="1200",
        scheduled_target="1200",
        satisfaction="satisfied",
        slot_id="1",
        qcsd_outcome_schema_version="2",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="1200",
        defense_control_bytes="0",
        quic_padding_bytes="0",
        other_quic_bytes="0",
        lateness_us="0",
    )
    control_packet = {field: "" for field in packet_fields}
    control_packet.update(
        direction="outgoing",
        monotonic_us="10000020",
        connection="0",
        observed_udp_length="50",
        satisfaction="unshaped",
        qcsd_outcome_schema_version="2",
        send_policy="unscheduled",
        desired_udp_bytes="50",
        observed_udp_bytes="50",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="0",
        defense_control_bytes="4",
        quic_padding_bytes="0",
        other_quic_bytes="46",
        lateness_us="0",
    )
    write_rows(packets, packet_fields, [exact_packet, control_packet])

    run = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=1,
        stream_cancellations=1,
        cancelled_capacity=1_199,
        terminal_incoming_at_stop=0,
    )
    algorithm = _algorithm_diagnostics(
        run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert run["runner_wakeup_metrics"]["schema_version"] == 16
    assert algorithm["schema_version"] == 4
    assert evaluation_module._load_algorithm_diagnostics(algorithm, defense="buflo") == algorithm
    assert algorithm["buflo_state"]["schema_version"] == 3
    assert (
        algorithm["buflo_state"]["schedule_stop"]["directions"]["outgoing"][
            "drained_cells_after_stop"
        ]
        == 0
    )
    assert (
        algorithm["buflo_state"]["schedule_stop"]["terminal_time_semantics"]
        == fidelity_module.BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS
    )
    assert (
        algorithm["buflo_state"]["schedule_stop"]["directions"]["incoming"][
            "drained_cells_after_stop"
        ]
        == 1
    )
    assert algorithm["buflo_state"]["typed_cancellation_action_events"] == 1
    assert algorithm["buflo_state"]["post_cancellation_unscheduled_defense_control_packets"] == 1
    assert algorithm["buflo_state"]["post_cancellation_unscheduled_defense_control_bytes"] == 4

    for _label, packet_rows in (
        ("missing", [control_packet]),
        ("duplicate", [exact_packet, dict(exact_packet), control_packet]),
        (
            "wrong slot",
            [{**exact_packet, "slot_id": "99"}, control_packet],
        ),
        (
            "wrong direction",
            [{**exact_packet, "direction": "incoming"}, control_packet],
        ),
        (
            "wrong target",
            [{**exact_packet, "scheduled_target": "1199"}, control_packet],
        ),
        (
            "wrong observed UDP length",
            [{**exact_packet, "observed_udp_length": "1199"}, control_packet],
        ),
        (
            "missing packet composition",
            [
                {
                    **exact_packet,
                    **{field: "" for field in (*handoff._COMPOSITION_FIELDS, "lateness_us")},
                },
                control_packet,
            ],
        ),
        (
            "extra wrong-policy scheduled packet",
            [
                exact_packet,
                {
                    **exact_packet,
                    "monotonic_us": "9999991",
                    "slot_id": "99",
                    "send_policy": "congestion_sensitive",
                },
                control_packet,
            ],
        ),
        (
            "extra slot-only packet",
            [{**control_packet, "slot_id": "99"}, exact_packet, control_packet],
        ),
        (
            "unscheduled packet with exact policy",
            [{**control_packet, "send_policy": "exact"}, exact_packet],
        ),
        (
            "packet lateness at exclusive boundary",
            [{**exact_packet, "lateness_us": "5000"}, control_packet],
        ),
        (
            "post-stop",
            [{**exact_packet, "monotonic_us": "10000001"}, control_packet],
        ),
    ):
        write_rows(packets, packet_fields, packet_rows)
        with pytest.raises(
            ValueError,
            match=(
                "outgoing terminal packet|outgoing controller terminal time|"
                "half-open realization window|"
                "packet-build time follows controller terminalization|"
                "stop/drain schedule chronology|incomplete scheduled packet identity|"
                "scheduled incoming datagram|unscheduled packet a scheduled send policy"
            ),
        ):
            _algorithm_diagnostics(
                run,
                defense="buflo",
                runtime_kind="buflo",
                schedule_path=schedule,
                events_path=events,
                packets_path=packets,
            )
    write_rows(packets, packet_fields, [exact_packet, control_packet])

    late_schedule_row = dict(schedule_row)
    late_schedule_row["terminal_defense_elapsed_us"] = "5000"
    late_packet = {**exact_packet, "monotonic_us": "5000"}
    write_rows(schedule, schedule_fields, [late_schedule_row, incoming_schedule_row])
    write_rows(packets, packet_fields, [late_packet, control_packet])
    with pytest.raises(ValueError, match="half-open realization window"):
        _algorithm_diagnostics(
            run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(schedule, schedule_fields, [schedule_row, incoming_schedule_row])
    write_rows(packets, packet_fields, [exact_packet, control_packet])

    offset_run = json.loads(json.dumps(run))
    offset_run["defense_start_monotonic_ns"] = 21_827_440
    offset_us = 21_828
    offset_schedule_row = dict(schedule_row)
    offset_schedule_row["action_time_us"] = str(offset_us)
    offset_incoming = dict(incoming_schedule_row)
    offset_incoming.update(
        action_time_us=str(offset_us),
        credit_advertised_at_us=str(offset_us),
        credit_advertisement_delay_us="0",
        credit_consumed_at_us=str(10_000_001 + offset_us),
        credit_consumption_delay_us="10000001",
    )
    offset_event = dict(event_row)
    offset_event["monotonic_us"] = str(10_000_010 + offset_us)
    offset_exact_packet = dict(exact_packet)
    offset_exact_packet["monotonic_us"] = str(4_999 + offset_us)
    offset_control_packet = dict(control_packet)
    offset_control_packet["monotonic_us"] = str(10_000_020 + offset_us)
    write_rows(schedule, schedule_fields, [offset_schedule_row, offset_incoming])
    write_rows(events, event_fields, [offset_event])
    write_rows(
        packets,
        packet_fields,
        [offset_exact_packet, offset_control_packet],
    )
    offset_algorithm = _algorithm_diagnostics(
        offset_run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    offset_state = offset_algorithm["buflo_state"]
    assert offset_state["last_exact_outgoing_cell_monotonic_us"] == 4_999
    assert offset_state["last_scheduled_terminal_monotonic_us"] == 10_000_001
    assert offset_state["schedule_stop"]["directions"]["incoming"]["drained_cells_after_stop"] == 1
    write_rows(schedule, schedule_fields, [schedule_row, incoming_schedule_row])
    write_rows(events, event_fields, [event_row])
    write_rows(packets, packet_fields, [exact_packet, control_packet])

    missing_clock = json.loads(json.dumps(run))
    missing_clock.pop("defense_start_monotonic_ns")
    with pytest.raises(ValueError, match="defense clock binding"):
        _algorithm_diagnostics(
            missing_clock,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )

    current_summary_with_v2_wakeups = json.loads(json.dumps(run))
    current_summary_with_v2_wakeups["runner_wakeup_metrics"] = _runner_wakeup_receipt(2)
    with pytest.raises(ValueError, match="terminal-tail evidence is unavailable"):
        _algorithm_diagnostics(
            current_summary_with_v2_wakeups,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )

    historical_v3 = json.loads(json.dumps(run))
    historical_v3["buflo_summary"]["schema_version"] = 3
    historical_v3["buflo_summary"].pop("terminal_schedule_stop_policy")
    for key in fidelity_module.BUFLO_SCHEDULE_STOP_V4_KEYS:
        historical_v3["defense_diagnostics"].pop(key)
        historical_v3["buflo_summary"]["diagnostics"].pop(key)
    with pytest.raises(ValueError, match="terminal-tail evidence is unavailable"):
        _algorithm_diagnostics(
            historical_v3,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    historical_v3_algorithm = _algorithm_diagnostics(
        historical_v3,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
        require_current=False,
    )
    assert historical_v3_algorithm["schema_version"] == 3
    assert historical_v3_algorithm["buflo_state"]["schema_version"] == 2

    legacy_run = json.loads(json.dumps(historical_v3))
    legacy_run["runner_wakeup_metrics"] = _runner_wakeup_receipt(2)
    legacy_run["buflo_summary"]["schema_version"] = 2
    legacy_run["defense_diagnostics"].pop(
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    )
    legacy_run["buflo_summary"]["diagnostics"].pop(
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    )
    with pytest.raises(ValueError, match="terminal-tail evidence is unavailable"):
        _algorithm_diagnostics(
            legacy_run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    legacy_algorithm = _algorithm_diagnostics(
        legacy_run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
        require_current=False,
    )
    assert legacy_algorithm["schema_version"] == 2
    assert "schema_version" not in legacy_algorithm["buflo_state"]

    event_row["details"] = event_row["details"].replace(
        "buflo_terminal_subcell_tail", "cs_buflo_local_early_termination"
    )
    write_rows(events, event_fields, [event_row])
    with pytest.raises(ValueError, match="terminal-tail evidence is inconsistent"):
        _algorithm_diagnostics(
            run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )

    event_row["details"] = event_row["details"].replace(
        "cs_buflo_local_early_termination", "buflo_terminal_subcell_tail"
    )
    write_rows(events, event_fields, [event_row])
    for diagnostic, changed in (
        ("buflo_terminal_subcell_parser_lease_bytes_at_latch", 1),
        ("buflo_terminal_subcell_exact_capacity_bytes_cancelled", 1_200),
        ("buflo_schedule_stop_latched", False),
        ("buflo_schedule_stop_latched_at_us", 10_000_002),
        ("buflo_schedule_stop_available_bytes", 1_200),
        ("buflo_schedule_stop_required_bytes", 1_199),
        ("buflo_schedule_stop_scheduled_incoming_cells", 2),
        ("buflo_schedule_stop_terminal_incoming_cells", 2),
        ("buflo_schedule_stop_terminal_outgoing_cells", 0),
    ):
        invalid_run = json.loads(json.dumps(run))
        invalid_run["defense_diagnostics"][diagnostic] = changed
        invalid_run["buflo_summary"]["diagnostics"][diagnostic] = changed
        with pytest.raises(ValueError, match="terminal-tail evidence"):
            _algorithm_diagnostics(
                invalid_run,
                defense="buflo",
                runtime_kind="buflo",
                schedule_path=schedule,
                events_path=events,
                packets_path=packets,
            )

    partial_run = json.loads(json.dumps(run))
    partial_run["defense_diagnostics"].pop("buflo_schedule_stop_available_bytes")
    partial_run["buflo_summary"]["diagnostics"].pop("buflo_schedule_stop_available_bytes")
    with pytest.raises(ValueError, match="terminal-tail evidence"):
        _algorithm_diagnostics(
            partial_run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )

    drifted_policy = json.loads(json.dumps(run))
    drifted_policy["buflo_summary"]["terminal_schedule_stop_policy"] = "drifted"
    with pytest.raises(ValueError, match="terminal-tail evidence"):
        _algorithm_diagnostics(
            drifted_policy,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )

    incoming_schedule_row["credit_consumed_at_us"] = "10000002"
    incoming_schedule_row["credit_consumption_delay_us"] = "10000002"
    incoming_schedule_row["terminal_defense_elapsed_us"] = "10000002"
    write_rows(schedule, schedule_fields, [schedule_row, incoming_schedule_row])
    with pytest.raises(ValueError, match="terminal-tail evidence|stop/drain"):
        _algorithm_diagnostics(
            run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    incoming_schedule_row["credit_consumed_at_us"] = "10000001"
    incoming_schedule_row["credit_consumption_delay_us"] = "10000001"
    incoming_schedule_row["terminal_defense_elapsed_us"] = "10000001"
    write_rows(schedule, schedule_fields, [schedule_row, incoming_schedule_row])

    second_event = dict(event_row)
    second_event.update(
        monotonic_us="10000030",
        details=json.dumps(
            {
                "type": "cancel_chaff",
                "endpoint": 0,
                "stream": 8,
                "reason": "buflo_terminal_subcell_tail",
            },
            sort_keys=True,
        ),
    )
    write_rows(events, event_fields, [event_row, second_event])
    two_stream_run = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=1,
        stream_cancellations=2,
        cancelled_capacity=1_199,
        terminal_incoming_at_stop=0,
    )
    with pytest.raises(ValueError, match="terminal-tail evidence is inconsistent"):
        _algorithm_diagnostics(
            two_stream_run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    control_packet["monotonic_us"] = "10000040"
    write_rows(packets, packet_fields, [exact_packet, control_packet])
    two_stream = _algorithm_diagnostics(
        two_stream_run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert two_stream["buflo_state"]["stream_cancellations"] == 2
    assert (
        two_stream["buflo_state"]["first_post_cancellation_defense_control_monotonic_us"]
        == 10_000_040
    )

    retained_boundary_run = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=1,
        stream_cancellations=2,
        cancelled_capacity=624,
        pending_parser_boundaries=1,
        terminal_incoming_at_stop=0,
    )
    retained_boundary = _algorithm_diagnostics(
        retained_boundary_run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert retained_boundary["buflo_state"]["pending_parser_boundaries_at_latch"] == 1
    assert retained_boundary["buflo_state"]["pending_application_parser_boundaries_at_latch"] == 0

    for diagnostic, changed in (
        (
            "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch",
            1,
        ),
        ("buflo_terminal_subcell_pending_parser_boundaries_at_latch", 3),
    ):
        invalid_run = json.loads(json.dumps(retained_boundary_run))
        invalid_run["defense_diagnostics"][diagnostic] = changed
        invalid_run["buflo_summary"]["diagnostics"][diagnostic] = changed
        with pytest.raises(ValueError, match="terminal-tail evidence"):
            _algorithm_diagnostics(
                invalid_run,
                defense="buflo",
                runtime_kind="buflo",
                schedule_path=schedule,
                events_path=events,
                packets_path=packets,
            )


def test_cs_buflo_schema_four_handoff_reconstructs_stop_drain_and_preserves_legacy_shapes(
    tmp_path: Path,
) -> None:
    schedule = tmp_path / "schedule.csv"
    events = tmp_path / "events.csv"
    packets = tmp_path / "packets.csv"

    def write_rows(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    schedule_fields = (*handoff.SCHEDULE_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    outgoing = {field: "" for field in schedule_fields}
    outgoing.update(
        target_time_us="50",
        direction="outgoing",
        size="600",
        connection="0",
        action_time_us="150",
        satisfaction="full",
        observed_size="600",
        slot_id="1",
        qcsd_outcome_schema_version="3",
        send_policy="congestion_sensitive",
        desired_udp_bytes="600",
        observed_udp_bytes="600",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="600",
        defense_control_bytes="0",
        quic_padding_bytes="0",
        other_quic_bytes="0",
        lateness_us="100",
        terminal_defense_elapsed_us="150",
    )
    incoming = {field: "" for field in schedule_fields}
    incoming.update(
        target_time_us="50",
        direction="incoming",
        size="600",
        connection="0",
        action_time_us="50",
        satisfaction="satisfied",
        slot_id="2",
        qcsd_outcome_schema_version="3",
        send_policy="exact",
        desired_udp_bytes="600",
        credit_advertised_at_us="150",
        credit_advertisement_delay_us="100",
        credit_consumed_at_us="250",
        credit_consumption_delay_us="200",
        terminal_defense_elapsed_us="250",
    )
    write_rows(schedule, schedule_fields, [outgoing, incoming])
    write_rows(
        events,
        (*handoff._EVENT_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS),
        [],
    )
    packet_fields = (*handoff._PACKET_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    packet = {field: "" for field in packet_fields}
    packet.update(
        direction="outgoing",
        monotonic_us="150",
        connection="0",
        observed_udp_length="600",
        scheduled_target="600",
        satisfaction="full",
        slot_id="1",
        qcsd_outcome_schema_version="2",
        send_policy="congestion_sensitive",
        desired_udp_bytes="600",
        observed_udp_bytes="600",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="600",
        defense_control_bytes="0",
        quic_padding_bytes="0",
        other_quic_bytes="0",
        lateness_us="100",
    )
    write_rows(packets, packet_fields, [packet])

    run = _complete_cs_buflo_run()
    current = _algorithm_diagnostics(
        run,
        defense="cs-buflo",
        runtime_kind="cs_buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert run["runner_wakeup_metrics"]["schema_version"] == 10
    assert evaluation_module._load_algorithm_diagnostics(current, defense="cs-buflo") == current
    reconstructed = _algorithm_diagnostics(
        run,
        defense="cs-buflo",
        runtime_kind="cs_buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert reconstructed == current
    assert current["schema_version"] == 4
    for direction, last_terminal in (("outgoing", 150), ("incoming", 250)):
        state = current["cs_buflo_state"]["directions"][direction]
        assert state["termination_stop_latched_at_us"] == 100
        assert state["termination_stop_scheduled_cells_at_stop"] == 1
        assert state["termination_stop_terminal_cells_at_stop"] == 0
        assert state["stop_drain_ledger"] == {
            "drained_cells_after_stop": 1,
            "last_scheduled_target_us": 50,
            "last_terminal_at_us": last_terminal,
            "terminal_cells_strictly_before_stop": 0,
            "terminal_cells_at_or_before_stop": 0,
            "terminal_cells_at_stop_timestamp": 0,
        }

    tied_outgoing = dict(outgoing)
    tied_outgoing["terminal_defense_elapsed_us"] = "100"
    tied_outgoing["lateness_us"] = "50"
    tied_packet = dict(packet)
    tied_packet["monotonic_us"] = "100"
    tied_packet["lateness_us"] = "50"
    write_rows(schedule, schedule_fields, [tied_outgoing, incoming])
    write_rows(packets, packet_fields, [tied_packet])
    tied_run = json.loads(json.dumps(run))
    for receipt in (
        tied_run["defense_diagnostics"],
        tied_run["cs_buflo_summary"]["diagnostics"],
    ):
        receipt["cs_buflo_lateness_us_total"] = 50
        receipt["cs_buflo_lateness_us_max"] = 50
    tied = _algorithm_diagnostics(
        tied_run,
        defense="cs-buflo",
        runtime_kind="cs_buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert tied["cs_buflo_state"]["directions"]["outgoing"]["stop_drain_ledger"] == {
        "drained_cells_after_stop": 1,
        "last_scheduled_target_us": 50,
        "last_terminal_at_us": 100,
        "terminal_cells_strictly_before_stop": 0,
        "terminal_cells_at_or_before_stop": 1,
        "terminal_cells_at_stop_timestamp": 1,
    }
    write_rows(schedule, schedule_fields, [outgoing, incoming])
    write_rows(packets, packet_fields, [packet])

    before_target = dict(outgoing)
    before_target["terminal_defense_elapsed_us"] = "49"
    write_rows(schedule, schedule_fields, [before_target, incoming])
    with pytest.raises(ValueError, match="terminal time predates its defense target"):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )

    after_stop = dict(outgoing)
    after_stop["target_time_us"] = "101"
    after_stop["terminal_defense_elapsed_us"] = "201"
    after_stop_packet = dict(packet)
    after_stop_packet["monotonic_us"] = "201"
    write_rows(schedule, schedule_fields, [after_stop, incoming])
    write_rows(packets, packet_fields, [after_stop_packet])
    with pytest.raises(ValueError, match="stop/drain schedule chronology"):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(schedule, schedule_fields, [outgoing, incoming])
    write_rows(packets, packet_fields, [packet])

    handoff_delayed_outgoing = dict(outgoing)
    handoff_delayed_outgoing["terminal_defense_elapsed_us"] = "151"
    handoff_delayed_packet = dict(packet)
    handoff_delayed_packet["monotonic_us"] = "151"
    write_rows(schedule, schedule_fields, [handoff_delayed_outgoing, incoming])
    write_rows(packets, packet_fields, [handoff_delayed_packet])
    assert (
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )["directions"]["outgoing"]["scheduling_lateness_us"]["maximum"]
        == 100
    )
    write_rows(schedule, schedule_fields, [outgoing, incoming])
    write_rows(packets, packet_fields, [packet])

    timestamp_mismatch = dict(packet)
    timestamp_mismatch["monotonic_us"] = "151"
    write_rows(packets, packet_fields, [timestamp_mismatch])
    with pytest.raises(ValueError, match="packet/controller timing is inconsistent"):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(packets, packet_fields, [packet])

    write_rows(packets, packet_fields, [])
    with pytest.raises(ValueError, match="packet inventory is not one-to-one"):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(packets, packet_fields, [packet])

    extra_wrong_policy = {
        **packet,
        "monotonic_us": "151",
        "slot_id": "99",
        "send_policy": "exact",
    }
    write_rows(packets, packet_fields, [packet, extra_wrong_policy])
    with pytest.raises(ValueError, match="packet inventory is not one-to-one"):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(packets, packet_fields, [packet])

    extra_incoming_scheduled = {
        **packet,
        "direction": "incoming",
        "monotonic_us": "151",
        "slot_id": "99",
        "send_policy": "exact",
    }
    write_rows(packets, packet_fields, [packet, extra_incoming_scheduled])
    with pytest.raises(ValueError, match="scheduled incoming datagram"):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(packets, packet_fields, [packet])

    mismatched_packet = dict(packet)
    mismatched_packet["application_stream_bytes"] = "1"
    mismatched_packet["chaff_stream_bytes"] = "599"
    write_rows(packets, packet_fields, [mismatched_packet])
    with pytest.raises(ValueError, match="outgoing packet binding is invalid"):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(packets, packet_fields, [packet])

    partial_outgoing = dict(outgoing)
    partial_outgoing.update(
        satisfaction="partial",
        observed_size="300",
        miss_reason="CongestionLimited",
        observed_udp_bytes="300",
        chaff_stream_bytes="300",
        congestion_reason="congestion_limited",
    )
    partial_packet = dict(packet)
    partial_packet.update(
        observed_udp_length="300",
        satisfaction="partial",
        observed_udp_bytes="300",
        chaff_stream_bytes="300",
        congestion_reason="congestion_limited",
    )
    partial_run = json.loads(json.dumps(run))
    for receipt in (
        partial_run["defense_diagnostics"],
        partial_run["cs_buflo_summary"]["diagnostics"],
    ):
        receipt["cs_buflo_full_outgoing_cells"] = 0
        receipt["cs_buflo_partial_outgoing_cells"] = 1
        receipt["cs_buflo_realized_udp_bytes"] = 300
        receipt["cs_buflo_chaff_stream_bytes"] = 300
    write_rows(schedule, schedule_fields, [partial_outgoing, incoming])
    write_rows(packets, packet_fields, [partial_packet])
    assert (
        _algorithm_diagnostics(
            partial_run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )["directions"]["outgoing"]["satisfaction_counts"]["partial"]
        == 1
    )
    write_rows(schedule, schedule_fields, [outgoing, incoming])
    write_rows(packets, packet_fields, [packet])

    buffered_consumption = dict(incoming)
    buffered_consumption["credit_consumed_at_us"] = "5250"
    buffered_consumption["credit_consumption_delay_us"] = "5200"
    write_rows(schedule, schedule_fields, [outgoing, buffered_consumption])
    assert (
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )["directions"]["incoming"]["receive_credit_consumption"]["delay_us"]["maximum"]
        == 5200
    )

    mismatched_consumption = dict(incoming)
    mismatched_consumption["credit_consumed_at_us"] = "10251"
    mismatched_consumption["credit_consumption_delay_us"] = "10201"
    write_rows(schedule, schedule_fields, [outgoing, mismatched_consumption])
    with pytest.raises(
        ValueError, match="terminal time differs from translated credit consumption"
    ):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(schedule, schedule_fields, [outgoing, incoming])

    missed_incoming = {field: "" for field in schedule_fields}
    missed_incoming.update(
        target_time_us="50",
        direction="incoming",
        size="600",
        connection="0",
        action_time_us="50",
        satisfaction="missed",
        miss_reason="DeadlineExpired",
        slot_id="2",
        qcsd_outcome_schema_version="3",
        terminal_defense_elapsed_us="250",
    )
    write_rows(schedule, schedule_fields, [outgoing, missed_incoming])
    with pytest.raises(ValueError, match="terminal schedule differs from runner counters"):
        _algorithm_diagnostics(
            run,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    write_rows(schedule, schedule_fields, [outgoing, incoming])

    connection_start_crossing = json.loads(json.dumps(run))
    for receipt in (
        connection_start_crossing["defense_diagnostics"],
        connection_start_crossing["cs_buflo_summary"]["diagnostics"],
    ):
        receipt["cs_buflo_outgoing_termination_stop_crossing_total_bytes"] = 600
        receipt["cs_buflo_outgoing_termination_stop_crossing_increment_bytes"] = 600
    with pytest.raises(ValueError, match="runner diagnostics are incomplete"):
        _algorithm_diagnostics(
            connection_start_crossing,
            defense="cs-buflo",
            runtime_kind="cs_buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )

    legacy_v3 = json.loads(json.dumps(run))
    legacy_v3["cs_buflo_summary"]["schema_version"] = 3
    legacy_v3["cs_buflo_summary"].pop("early_termination_translation_version")
    legacy_v3["cs_buflo_summary"].pop("termination_stop_policy")
    for receipt in (
        legacy_v3["defense_diagnostics"],
        legacy_v3["cs_buflo_summary"]["diagnostics"],
    ):
        receipt["cs_buflo_early_termination_semantics"] = (
            fidelity_module.CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS
        )
        for key in fidelity_module.CS_BUFLO_STOP_DRAIN_V4_KEYS:
            receipt.pop(key)
    legacy_v3["cs_buflo_summary"]["early_termination_semantics"] = (
        fidelity_module.CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS
    )
    legacy_schedule_fields = (
        *handoff.SCHEDULE_PREFIX_FIELDS,
        *CONSUMPTION_SCHEDULE_QCSD_FIELDS,
    )
    legacy_outgoing = {field: outgoing[field] for field in legacy_schedule_fields}
    legacy_outgoing["qcsd_outcome_schema_version"] = "1"
    legacy_incoming = {field: incoming[field] for field in legacy_schedule_fields}
    legacy_incoming["qcsd_outcome_schema_version"] = "2"
    legacy_packet_fields = (
        *handoff._PACKET_PREFIX_FIELDS,
        *CONSUMPTION_SCHEDULE_QCSD_FIELDS,
    )
    legacy_packet = {field: packet[field] for field in legacy_packet_fields}
    write_rows(
        schedule,
        legacy_schedule_fields,
        [legacy_outgoing, legacy_incoming],
    )
    write_rows(
        events,
        (*handoff._EVENT_PREFIX_FIELDS, *CONSUMPTION_SCHEDULE_QCSD_FIELDS),
        [],
    )
    write_rows(packets, legacy_packet_fields, [legacy_packet])
    v3 = _algorithm_diagnostics(
        legacy_v3,
        defense="cs-buflo",
        runtime_kind="cs_buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
        require_latest_cs=False,
    )
    expected_state_keys = {
        "padding_variant",
        "early_termination_semantics",
        "incoming_boundaries",
        "rate_boundary_translation",
        "rate_transitions",
        "local_termination",
        "incoming_local_realized_cells",
        "directions",
    }
    expected_v3_direction_keys = {
        "natural_bytes",
        "real_bearing_bytes",
        "post_local_et_natural_bytes",
        "terminal_interval_us",
        "rate_adaptations",
        "next_adaptation_boundary_bytes",
        "estimator_samples",
        "padding_basis_natural_bytes",
        "padding_basis_cover_bytes",
        "padding_basis_total_bytes",
        "padding_target_bytes",
        "power_of_two_crossed",
        "minimum_interval_opportunities",
        "minimum_interval_terminal",
        "minimum_interval_full",
        "minimum_interval_local_realized",
        "incoming_local_realized_cells",
        "rate_transitions",
    }
    assert v3["schema_version"] == 3
    assert set(v3["cs_buflo_state"]) == expected_state_keys
    assert set(v3["cs_buflo_state"]["local_termination"]) == {
        "latched",
        "pending_request_cancellations",
        "stream_cancellations",
        "latched_at_us",
        "before_application_complete",
        "application_receive_streams_handed_off",
        "application_parser_boundaries_handed_off",
        "application_parser_lease_bytes_handed_off",
        "application_send_endpoints_released",
        "post_local_et_natural_outgoing_bytes",
        "post_local_et_natural_incoming_bytes",
    }
    assert all(
        set(state) == expected_v3_direction_keys
        and not any(key.startswith("termination_stop_") for key in state)
        and "termination_accounted_bytes" not in state
        and "last_termination_increment_bytes" not in state
        for state in v3["cs_buflo_state"]["directions"].values()
    )

    legacy_v2 = json.loads(json.dumps(legacy_v3))
    legacy_v2["runner_wakeup_metrics"] = _runner_wakeup_receipt(2)
    legacy_v2["cs_buflo_summary"]["schema_version"] = 2
    for receipt in (
        legacy_v2["defense_diagnostics"],
        legacy_v2["cs_buflo_summary"]["diagnostics"],
    ):
        for key in fidelity_module.CS_BUFLO_LOCAL_ET_V3_KEYS:
            receipt.pop(key)
    v2 = _algorithm_diagnostics(
        legacy_v2,
        defense="cs-buflo",
        runtime_kind="cs_buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
        require_current=False,
        require_latest_cs=False,
    )
    expected_v2_direction_keys = expected_v3_direction_keys - {
        "natural_bytes",
        "real_bearing_bytes",
        "post_local_et_natural_bytes",
    }
    assert v2["schema_version"] == 2
    assert set(v2["cs_buflo_state"]) == expected_state_keys
    assert set(v2["cs_buflo_state"]["local_termination"]) == {
        "latched",
        "pending_request_cancellations",
        "stream_cancellations",
    }
    assert all(
        set(state) == expected_v2_direction_keys
        and not any(key.startswith("termination_stop_") for key in state)
        and "termination_accounted_bytes" not in state
        and "last_termination_increment_bytes" not in state
        for state in v2["cs_buflo_state"]["directions"].values()
    )


def test_cs_buflo_stop_drain_ledger_accepts_zero_time_empty_vector() -> None:
    diagnostics = {
        "cs_buflo_local_et_latched_at_us": 0,
        "cs_buflo_outgoing_termination_stop_latched_at_us": 0,
        "cs_buflo_incoming_termination_stop_latched_at_us": 0,
        "cs_buflo_outgoing_termination_stop_scheduled_cells_at_stop": 0,
        "cs_buflo_incoming_termination_stop_scheduled_cells_at_stop": 0,
        "cs_buflo_outgoing_termination_stop_terminal_cells_at_stop": 0,
        "cs_buflo_incoming_termination_stop_terminal_cells_at_stop": 0,
    }
    assert handoff._cs_buflo_stop_drain_ledger(diagnostics, []) == {
        "outgoing": {
            "drained_cells_after_stop": 0,
            "last_scheduled_target_us": 0,
            "last_terminal_at_us": 0,
            "terminal_cells_strictly_before_stop": 0,
            "terminal_cells_at_or_before_stop": 0,
            "terminal_cells_at_stop_timestamp": 0,
        },
        "incoming": {
            "drained_cells_after_stop": 0,
            "last_scheduled_target_us": 0,
            "last_terminal_at_us": 0,
            "terminal_cells_strictly_before_stop": 0,
            "terminal_cells_at_or_before_stop": 0,
            "terminal_cells_at_stop_timestamp": 0,
        },
    }


def test_formal_result_names_are_ten_ordered_blocks() -> None:
    assert len(FORMAL_RESULT_NAMES) == 10
    assert FORMAL_RESULT_NAMES[0].endswith("formal-01-1200")
    assert FORMAL_RESULT_NAMES[-1].endswith("formal-10-1200")


@pytest.mark.parametrize("mutation", ["missing", "altered"])
def test_formal_redirect_attestation_tampering_blocks_source_validation(
    tmp_path: Path,
    mutation: str,
) -> None:
    data = {
        "preparation": {
            "source_url": "https://example.com/",
            "final_url": "https://example.com/",
            "expected_responses": [{"resource_id": 0, "status": 200}],
        },
        "resources": [{"id": 0, "url": "https://example.com/"}],
    }
    sample_path = tmp_path / "samples/example/as-defined/visit-001/undefended"
    neqo = sample_path / "neqo"
    neqo.mkdir(parents=True)
    (neqo / "run.json").write_text(
        json.dumps(
            {
                "responses": [
                    {
                        "resource_id": 0,
                        "url": "https://example.com/",
                        "status": 200,
                        "complete": True,
                        "outcome": "succeeded",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    workload = SimpleNamespace(id="example-r1", data=data)
    receipt = _redirect_attestation(workload, sample_path)
    _validate_formal_sample_redirect_attestation(
        {"redirect_attestation": receipt}, workload, sample_path
    )

    diagnostics = (
        {}
        if mutation == "missing"
        else {
            "redirect_attestation": {
                **receipt,
                "all_redirect_sequences_empty": False,
            }
        }
    )
    with pytest.raises(ValueError, match="explicitly attest empty"):
        _validate_formal_sample_redirect_attestation(diagnostics, workload, sample_path)


@pytest.mark.parametrize("mutation", ["missing", "altered"])
def test_formal_source_result_rejects_redirect_attestation_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    data = {
        "preparation": {
            "source_url": "https://example.com/",
            "final_url": "https://example.com/",
            "expected_responses": [{"resource_id": 0, "status": 200}],
        },
        "resources": [{"id": 0, "url": "https://example.com/"}],
    }
    workload_bytes = (json.dumps(data, sort_keys=True) + "\n").encode()
    workload_digest = hashlib.sha256(workload_bytes).hexdigest()
    checked_workload = tmp_path / "checked-workload.json"
    checked_workload.write_bytes(workload_bytes)
    workload = Workload(
        id="example-r1",
        visits=1,
        path=checked_workload,
        source_bytes=workload_bytes,
        sha256=workload_digest,
        data=data,
        resource_count=1,
        origin_count=1,
    )
    campaign = SimpleNamespace(name="formal-test", workloads=(workload,))
    root = tmp_path / "result"
    sealed_workload = root / "inputs/workloads/example-r1.json"
    sealed_workload.parent.mkdir(parents=True)
    sealed_workload.write_bytes(workload_bytes)
    sample_path = root / "samples/example-r1/as-defined/visit-001/undefended"
    neqo = sample_path / "neqo"
    neqo.mkdir(parents=True)
    (neqo / "run.json").write_text(
        json.dumps(
            {
                "responses": [
                    {
                        "resource_id": 0,
                        "url": "https://example.com/",
                        "status": 200,
                        "complete": True,
                        "outcome": "succeeded",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    redirect_receipt = _redirect_attestation(workload, sample_path)
    sample = {
        "sample_id": "sample-001",
        "workload_id": "example-r1",
        "request_policy": "as-defined",
        "visit": 1,
        "defense": "undefended",
        "runtime_kind": "none",
        "baseline": True,
        "seed": 7,
        "path": "samples/example-r1/as-defined/visit-001/undefended",
        "state": "accepted",
        "eligible": True,
        "attempts": 1,
        "diagnostics": {"redirect_attestation": redirect_receipt},
    }
    experiment = {
        "name": "formal-test",
        "purpose": "evaluation",
        "status": "complete",
        "configuration": {},
        "source": {},
        "samples": [sample],
        "summary": {
            "planned": 1,
            "accepted": 1,
            "eligible": 1,
            "failed": 0,
            "passed": True,
        },
        "started_at": "2027-01-01T00:00:00+00:00",
        "completed_at": "2027-01-01T00:00:01+00:00",
    }
    verified = VerifiedResult(root=root, experiment=experiment, checksums={}, accepted_samples={})

    monkeypatch.setattr(handoff_module, "FORMAL_BLOCKS", (0,))
    monkeypatch.setattr(handoff_module, "FORMAL_RESULT_NAMES", ("formal-test",))
    monkeypatch.setattr(handoff_module, "FORMAL_DEFENSES", ("undefended",))
    monkeypatch.setattr(handoff_module, "CLASS_LABELS", {"example-r1": "example"})
    monkeypatch.setattr(handoff_module, "_FORMAL_DYNAMIC_CONFIGURATION_KEYS", set())
    monkeypatch.setattr(
        handoff_module,
        "_formal_campaign_path_for_result",
        lambda _receipt, _index: tmp_path / "campaign.yml",
    )
    monkeypatch.setattr(
        handoff_module,
        "_expected_formal_configuration",
        lambda _path: (campaign, {}),
    )
    monkeypatch.setattr(
        handoff_module,
        "_validate_formal_result_admission",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(handoff_module, "plan_campaign", lambda _campaign: [sample])
    monkeypatch.setattr(handoff_module, "_immutable_source", lambda _source: True)
    monkeypatch.setattr(handoff_module, "_formal_temporal_proof", lambda _blocks: {})
    monkeypatch.setattr(study_module, "_validate_public_network_condition", lambda _value: None)

    handoff_module._validate_source_results((verified,), formal=True)
    if mutation == "missing":
        sample["diagnostics"] = {}
    else:
        sample["diagnostics"] = {
            "redirect_attestation": {
                **redirect_receipt,
                "all_redirect_sequences_empty": False,
            }
        }
    with pytest.raises(ValueError, match="explicitly attest empty"):
        handoff_module._validate_source_results((verified,), formal=True)


def test_performance_metadata_binds_trace_run_and_resource_usage() -> None:
    trace = (
        ObserverPacket(1, 0, "outgoing", 1_242, 1_242, 1_200),
        ObserverPacket(2, 100, "incoming", 642, -642, 600),
    )
    usage = {
        "schema_version": 1,
        "source": "gnu-time-v",
        "user_cpu_seconds": 0.1,
        "system_cpu_seconds": 0.2,
        "wall_time_seconds": 1.0,
        "maximum_rss_bytes": 123_000,
        "voluntary_context_switches": 2,
        "involuntary_context_switches": 3,
        "timer_wakeups": None,
        "timer_wakeups_unavailable_reason": "unavailable in container",
        "rapl_energy_joules": None,
        "rapl_unavailable_reason": "unavailable in container",
    }
    run = {
        "defense_start_monotonic_ns": 1_000,
        "application_completion_monotonic_ns": 2_001_000,
        "responses": [{"bytes": 400}, {"bytes": 600}],
        "client_resource_usage": usage,
        "endpoints": [{"transport_stats": "  tx: 20 lost 4 lateack 0\n"}],
    }

    performance = _performance_metadata(run, trace)

    assert performance["application_duration_ns"] == 2_000_000
    assert performance["application_response_bytes"] == 1_000
    assert performance["udp_payload_bytes"] == {"outgoing": 1_200, "incoming": 600}
    assert performance["transport_retransmissions"] == 4


def test_raw_run_binding_covers_workload_chaff_parameters_and_limits() -> None:
    bindings = {
        "campaign_sha256": "1" * 64,
        "application_workload_sha256": "2" * 64,
        "runtime_workload_sha256": "3" * 64,
        "chaff_qualification_sha256": "4" * 64,
        "chaff_manifest_sha256": "5" * 64,
        "defense_parameters_sha256": "6" * 64,
        "defense_parameters_provenance_sha256": "7" * 64,
        "max_response_bytes": 1_048_576,
        "max_udp_payload_size": 1_200,
    }
    sample = {
        "seed": 9,
        "request_policy": "as-defined",
        "runtime_kind": "buflo",
        "baseline": False,
    }
    run = {
        "completion_status": "complete",
        "error": None,
        "seed": 9,
        "request_policy": "as-defined",
        "workload_hash_sha256": "3" * 64,
        "application_workload_source_hash_sha256": "2" * 64,
        "chaff_manifest_hash_sha256": "5" * 64,
        "max_response_bytes": 1_048_576,
        "resolved_configuration": {
            "max_udp_payload_size": 1_200,
            "defense": {"kind": "buflo"},
        },
        "defense_parameters": {
            "kind": "buflo",
            "path": "/sealed/parameters.json",
            "sha256": "6" * 64,
        },
    }

    _validate_run_sample_binding(run, sample, bindings)

    run["error_class"] = "client-defense-fidelity-v1"
    with pytest.raises(ValueError, match="accepted sample"):
        _validate_run_sample_binding(run, sample, bindings)
    run["error_class"] = None

    run["workload_hash_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="accepted sample"):
        _validate_run_sample_binding(run, sample, bindings)
    run["workload_hash_sha256"] = "3" * 64
    run["chaff_manifest_hash_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="defended run"):
        _validate_run_sample_binding(run, sample, bindings)


def test_handoff_recomputes_prepared_response_identity(tmp_path: Path) -> None:
    workload = tmp_path / "workload.json"
    workload.write_text(
        json.dumps(
            {
                "preparation": {
                    "expected_responses": [
                        {
                            "resource_id": 0,
                            "status": 200,
                            "bytes": 4,
                            "body_sha256": "a" * 64,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    row = {
        "workload_id": "example-r1",
        "defense": "undefended",
        "runtime_kind": "none",
    }
    run = {
        "responses": [
            {
                "resource_id": 0,
                "status": 200,
                "bytes": 4,
                "body_sha256": "a" * 64,
                "complete": True,
                "outcome": "succeeded",
            }
        ],
        "defense_diagnostics": {},
    }

    _validate_handoff_sample_correctness(
        row,
        run=run,
        workload_path=workload,
        schedule_path=tmp_path / "absent-schedule.csv",
        formal=False,
    )
    run["responses"][0]["body_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="response/fidelity"):
        _validate_handoff_sample_correctness(
            row,
            run=run,
            workload_path=workload,
            schedule_path=tmp_path / "absent-schedule.csv",
            formal=False,
        )


def test_export_destination_cannot_overlap_result_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result_root = tmp_path / "result"
    result_root.mkdir()
    monkeypatch.setattr(handoff, "verify_result", lambda root: SimpleNamespace(root=Path(root)))
    monkeypatch.setattr(handoff, "_validate_source_results", lambda *args, **kwargs: None)

    with pytest.raises(ValueError, match="overlaps protected input"):
        handoff.export_study_handoff(
            (result_root,),
            result_root / "handoff",
            formal=False,
        )
