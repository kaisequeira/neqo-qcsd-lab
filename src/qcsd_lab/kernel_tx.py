"""Fail-closed evidence contracts for BuFLO kernel-timed egress.

The raw runner receipt and the Lab reconciliation receipt deliberately remain
separate.  Rust can attest socket configuration, clock brackets, enqueue
ordering and Linux transmit timestamps, but it cannot observe the router-side
capture or the final ``tc`` counters.  The Lab receipt binds those independent
observations to the immutable raw receipt by hash and by every job/item
identity.  Callers must require :func:`kernel_tx_evidence_success_valid` for an
accepted BuFLO sample; validating the raw runner receipt alone is insufficient.

All mappings use exact-key schemas.  Nanosecond timestamps are unsigned integer
values.  ``CLOCK_TAI`` is the scheduling clock, ``CLOCK_MONOTONIC`` represents
Rust's authoritative monotonic clock, and Linux TX_SCHED/TX_SOFTWARE plus
PCAPNG timestamps are retained in their raw ``CLOCK_REALTIME`` frame as well as
their bracket-derived TAI translation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

KERNEL_TX_RUNNER_SCHEMA_VERSION = 4
KERNEL_TX_RUNNER_V3_SCHEMA_VERSION = 3
KERNEL_TX_HISTORICAL_RUNNER_SCHEMA_VERSION = 1
KERNEL_TX_EVIDENCE_SCHEMA_VERSION = 1
KERNEL_TX_REALIZATION_WINDOW_NS = 5_000_000
KERNEL_TX_ADAPTER_WINDOW_NS = frozenset({4_999_000, 5_000_000})
KERNEL_TX_CADENCE_NS = 20_000_000
KERNEL_TX_HISTORICAL_ETF_DELTA_NS = 4_000_000
KERNEL_TX_ETF_DELTA_NS = 4_500_000
KERNEL_TX_PRIO_MAP = [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1]
KERNEL_TX_MAX_CLOCK_BRACKET_NS = 250_000
KERNEL_TX_MAX_CLOCK_OFFSET_DRIFT_NS = 250_000
KERNEL_TX_MAX_UDP_PAYLOAD_BYTES = 1_200
_SOF_TXTIME_REPORT_ERRORS = 1 << 1
OBSERVER_TOPOLOGY_RECEIPT_SCHEMA_VERSION = 1
OBSERVER_TOPOLOGY_RECEIPT_SOURCE = "accepted-attempt-observer-topology-v1"

_KERNEL_TX_ETF_DELTA_BY_RUNNER_SCHEMA = {
    KERNEL_TX_HISTORICAL_RUNNER_SCHEMA_VERSION: KERNEL_TX_HISTORICAL_ETF_DELTA_NS,
    2: KERNEL_TX_HISTORICAL_ETF_DELTA_NS,
    KERNEL_TX_RUNNER_V3_SCHEMA_VERSION: KERNEL_TX_HISTORICAL_ETF_DELTA_NS,
    KERNEL_TX_RUNNER_SCHEMA_VERSION: KERNEL_TX_ETF_DELTA_NS,
}

KERNEL_TX_HISTORICAL_RUNNER_SEMANTICS = (
    "client_only_buflo_kernel_timed_egress_v2; "
    "clock=CLOCK_TAI_bracketed_against_CLOCK_MONOTONIC_and_CLOCK_REALTIME; "
    "exact_outgoing=SO_TXTIME_SCM_TXTIME_ETF; "
    "tick_zero_is_kernel_timed_after_future_defense_start_arm=true; "
    "residual_incoming_credit=ordered_after_exact_transmit; "
    "same_endpoint_credit_may_be_coalesced_in_exact_outgoing=true; "
    "packet_priority=per_datagram_SCM_PRIORITY_after_IP_controls_or_single_threaded_serialized_SO_PRIORITY; "
    "serialized_ipv4_traffic_class=socket_IP_TOS_before_SO_PRIORITY_and_restore_IP_TOS_before_SO_PRIORITY; "
    "serialized_ipv6_traffic_class=per_message_IPV6_TCLASS; "
    "serialized_socket_state_requires_verified_traffic_class_and_priority_readback_and_restoration; "
    "sender_exclusivity_is_current_thread_control_flow_not_OS_socket_ownership; "
    "selection_cutoff=release_minus_5ms; "
    "tx_sched_and_tx_software_are_linux_error_queue_timestamps; "
    "strict_realization_window_is_half_open; no_catch_up=true; "
    "client_only_preselection_adaptation=true; paper_equivalent=false; "
    "raw_runner_receipt_does_not_claim_post_veth_observation=true"
)
KERNEL_TX_RUNNER_V2_SEMANTICS = (
    "client_only_buflo_kernel_timed_egress_v2; "
    "clock=CLOCK_TAI_bracketed_against_CLOCK_MONOTONIC_and_CLOCK_REALTIME; "
    "exact_outgoing=SO_TXTIME_SCM_TXTIME_ETF; "
    "tick_zero_is_kernel_timed_after_future_defense_start_arm=true; "
    "residual_incoming_credit=ordered_after_exact_transmit; "
    "same_endpoint_credit_may_be_coalesced_in_exact_outgoing=true; "
    "packet_priority=per_datagram_SCM_PRIORITY_after_IP_controls_or_single_threaded_serialized_SO_PRIORITY; "
    "serialized_ipv4_traffic_class=socket_IP_TOS_before_SO_PRIORITY_and_restore_IP_TOS_before_SO_PRIORITY; "
    "serialized_ipv6_traffic_class=per_message_IPV6_TCLASS; "
    "serialized_socket_state_requires_verified_traffic_class_and_priority_readback_and_restoration; "
    "sender_exclusivity_is_current_thread_control_flow_not_OS_socket_ownership; "
    "selection_cutoff=release_minus_5ms; "
    "tx_sched_and_tx_software_are_linux_error_queue_timestamps; "
    "enqueue_monotonic_corroboration=item_local_post_tx_phase; "
    "global_monotonic_drift_is_diagnostic=true; "
    "strict_realization_window_is_half_open; no_catch_up=true; "
    "client_only_preselection_adaptation=true; paper_equivalent=false; "
    "raw_runner_receipt_does_not_claim_post_veth_observation=true"
)
KERNEL_TX_RUNNER_V3_SEMANTICS = (
    "client_only_buflo_kernel_timed_egress_v3; "
    "clock=CLOCK_TAI_bracketed_against_CLOCK_MONOTONIC_and_CLOCK_REALTIME; "
    "exact_outgoing=SO_TXTIME_SCM_TXTIME_ETF; "
    "tick_zero_is_kernel_timed_after_future_defense_start_arm=true; "
    "residual_incoming_credit=ordered_after_exact_transmit; "
    "same_endpoint_credit_may_be_coalesced_in_exact_outgoing=true; "
    "packet_priority=per_datagram_SCM_PRIORITY_after_IP_controls_or_single_threaded_serialized_SO_PRIORITY; "
    "serialized_ipv4_traffic_class=socket_IP_TOS_before_SO_PRIORITY_and_restore_IP_TOS_before_SO_PRIORITY; "
    "serialized_ipv6_traffic_class=per_message_IPV6_TCLASS; "
    "serialized_socket_state_requires_verified_traffic_class_and_priority_readback_and_restoration; "
    "sender_exclusivity_is_current_thread_control_flow_not_OS_socket_ownership; "
    "selection_cutoff=release_minus_5ms; "
    "tx_sched_and_tx_software_are_linux_error_queue_timestamps; "
    "enqueue_clock_evidence=TAI_before_sendmsg_then_MONOTONIC_after_sendmsg_then_TAI_after; "
    "post_tx_phase_same_clock_order_is_hard=true; "
    "post_tx_monotonic_offset_overlap_is_diagnostic=true; "
    "global_monotonic_drift_is_diagnostic=true; "
    "strict_realization_window_is_half_open; no_catch_up=true; "
    "client_only_preselection_adaptation=true; paper_equivalent=false; "
    "raw_runner_receipt_does_not_claim_post_veth_observation=true"
)
KERNEL_TX_RUNNER_SEMANTICS = (
    "client_only_buflo_kernel_timed_egress_v4; "
    "clock=CLOCK_TAI_bracketed_against_CLOCK_MONOTONIC_and_CLOCK_REALTIME; "
    "exact_outgoing=SO_TXTIME_SCM_TXTIME_ETF; "
    "tick_zero_is_kernel_timed_after_future_defense_start_arm=true; "
    "residual_incoming_credit=ordered_after_exact_transmit; "
    "same_endpoint_credit_may_be_coalesced_in_exact_outgoing=true; "
    "packet_priority=per_datagram_SCM_PRIORITY_after_IP_controls_or_single_threaded_serialized_SO_PRIORITY; "
    "serialized_ipv4_traffic_class=socket_IP_TOS_before_SO_PRIORITY_and_restore_IP_TOS_before_SO_PRIORITY; "
    "serialized_ipv6_traffic_class=per_message_IPV6_TCLASS; "
    "serialized_socket_state_requires_verified_traffic_class_and_priority_readback_and_restoration; "
    "sender_exclusivity_is_current_thread_control_flow_not_OS_socket_ownership; "
    "selection_cutoff=release_minus_5ms; "
    "etf_delta=4.5ms; "
    "etf_expiry_precedes_minimum_half_open_deadline_by_499us_or_more=true; "
    "tx_sched_and_tx_software_are_linux_error_queue_timestamps; "
    "txtime_drop_scm_timestamping_is_requested_tai_context_not_transmit_evidence=true; "
    "enqueue_clock_evidence=TAI_before_sendmsg_then_MONOTONIC_after_sendmsg_then_TAI_after; "
    "post_tx_phase_same_clock_order_is_hard=true; "
    "post_tx_monotonic_offset_overlap_is_diagnostic=true; "
    "global_monotonic_drift_is_diagnostic=true; "
    "strict_realization_window_is_half_open; no_catch_up=true; "
    "client_only_preselection_adaptation=true; paper_equivalent=false; "
    "raw_runner_receipt_does_not_claim_post_veth_observation=true"
)
KERNEL_TX_EVIDENCE_SEMANTICS = (
    "buflo_kernel_timed_egress_lab_reconciliation_v1; "
    "runner_receipt_binding=canonical_json_sha256; "
    "qdisc_observation=tc_json_before_and_after; "
    "capture_observer=router_ingress_post_client_veth_pre_netem; "
    "router_namespace_state=interfaces_routes_qdiscs_offloads_nat_before_and_after; "
    "capture_service_end_state=idle_no_dumpcap_child; "
    "accepted_packet_window=[release,deadline); "
    "one_reconciliation_per_runner_item_in_runner_order; "
    "zero_unresolved_qdisc_drops_capture_drops_required_for_success"
)

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTROLLER_ISOLATION_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "source",
        "controller_pid",
        "pr_get_dumpable_option",
        "pr_set_dumpable_option",
        "dumpable_before_set",
        "set_dumpable_value",
        "dumpable_after_set",
        "dumpable_before_client_spawn",
        "verified_before_observer_credentials",
        "protected_scope",
    }
)
_OBSERVER_TOPOLOGY_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "source",
        "network_receipt_sha256",
        "network_receipt",
        "observer_binding",
        "controller_isolation",
    }
)
_CLOCK_SAMPLE_KEYS = frozenset(
    {
        "schema_version",
        "tai_before_ns",
        "clock_ns",
        "tai_after_ns",
        "bracket_width_ns",
    }
)
_CLOCK_PHASE_KEYS = frozenset({"monotonic", "realtime"})
_CLOCK_MAPPING_KEYS = frozenset(
    {
        "schema_version",
        "tai_clock_id",
        "monotonic_clock_id",
        "realtime_clock_id",
        "start",
        "end",
        "instant_alignment",
        "max_observed_bracket_width_ns",
        "max_observed_offset_drift_ns",
        "effective_monotonic_offset_lower_ns",
        "effective_monotonic_offset_upper_ns",
        "effective_realtime_offset_lower_ns",
        "effective_realtime_offset_upper_ns",
        "per_item_monotonic_evidence_count",
        "per_item_realtime_evidence_count",
        "effective_envelope_semantics",
    }
)
_INSTANT_ALIGNMENT_KEYS = frozenset(
    {
        "schema_version",
        "monotonic_clock_ns",
        "instant_bracket_width_ns",
        "selected_upper_offset_ns",
        "semantics",
    }
)
_INSTANT_ALIGNMENT_SEMANTICS = (
    "std_Instant_bracketed_around_CLOCK_MONOTONIC; upper_bracket_edge_selected; "
    "translated_Instant_is_a_conservative_latest_bound; "
    "full_bracket_width_is_alignment_uncertainty"
)
_EFFECTIVE_ENVELOPE_SEMANTICS_V1 = (
    "start_and_end_clock_phases_plus_every_retained_per_item_post_tx_realtime_bracket_"
    "and_enqueue_monotonic_direct_tai_bracket; final_interval_is_conservative_union; "
    "widened_interval_must_still_fit_half_open_realization_window"
)
_EFFECTIVE_ENVELOPE_SEMANTICS_V2 = (
    "start_and_end_clock_phases_plus_every_explicit_per_item_post_tx_clock_phase; "
    "every_clock_phase_subsample_and_instant_alignment_bracket_is_at_most_250us; "
    "effective_monotonic_offset_is_a_nonfatal_diagnostic_union_and_max_observed_"
    "offset_drift_is_the_exact_maximum_start_relative_midpoint_drift_across_both_"
    "clocks_and_all_retained_phases; each_enqueue_MONOTONIC_timestamp_is_"
    "translated_only_with_its_item_local_post_TX_monotonic_phase_and_must_overlap_"
    "its_direct_enqueue_TAI_bracket; "
    "realtime_offset_is_the_nonempty_running_intersection_used_online_and_recomputed_"
    "exactly_at_finalization; final_realtime_interval_must_be_contained_by_every_"
    "provisional_interval; direct_enqueue_TAI_before_release_and_causal_order_"
    "predicates_remain_hard_gates; incoming_TX_lower_must_not_precede_its_enqueue_"
    "TAI_lower"
)
_EFFECTIVE_ENVELOPE_SEMANTICS_V3 = (
    "start_and_end_clock_phases_plus_every_explicit_per_item_post_tx_clock_phase; "
    "every_clock_phase_subsample_and_instant_alignment_bracket_is_at_most_250us; "
    "effective_monotonic_offset_is_a_nonfatal_diagnostic_union_and_max_observed_"
    "offset_drift_is_the_exact_maximum_start_relative_midpoint_drift_across_both_"
    "clocks_and_all_retained_phases; each_enqueue_TAI_interval_is_direct_send_"
    "sequence_evidence_and_must_be_ordered; each_enqueue_MONOTONIC_and_TAI_upper_"
    "must_precede_its_post_TX_phase_in_their_respective_clock_frames; enqueue_to_"
    "post_TX_MONOTONIC_offset_overlap_is_diagnostic_not_a_hard_gate; realtime_"
    "offset_is_the_nonempty_running_intersection_used_online_and_recomputed_"
    "exactly_at_finalization; final_realtime_interval_must_be_contained_by_every_"
    "provisional_interval; direct_enqueue_TAI_before_release_and_causal_order_"
    "predicates_remain_hard_gates; incoming_TX_lower_must_not_precede_its_enqueue_"
    "TAI_lower"
)
_PROCESS_SCHEDULER_KEYS = frozenset(
    {
        "schema_version",
        "source",
        "policy",
        "priority",
        "affinity_cpus",
        "rlimit_rtprio",
        "no_new_privileges",
        "effective_capabilities_hex",
        "cgroup_effective_cpuset",
        "affinity_scope",
        "contract",
        "contract_valid",
    }
)
_SOCKET_SETUP_KEYS = frozenset(
    {
        "schema_version",
        "family",
        "local_address",
        "duplicated_fd_cloexec",
        "nonblocking",
        "socket_type",
        "txtime_clock_id",
        "txtime_flags",
        "timestamping_report_flags",
        "timed_priority",
        "priority_before_probe",
        "priority_after_probe",
        "corresponding_error_queue_enabled",
        "etf_deadline_mode",
        "etf_skip_socket_check",
        "priority_method",
        "scm_priority_supported",
        "scm_priority_probe_family",
        "scm_priority_probe_errno",
        "exclusive_socket_sender_required",
        "per_datagram_timestamp_requests",
    }
)
_PRIVILEGE_KEYS = frozenset(
    {
        "schema_version",
        "uid",
        "gid",
        "supplementary_groups",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bounding",
        "cap_ambient",
        "no_new_privileges",
    }
)
_HELPER_THREAD_KEYS = frozenset(
    {
        "schema_version",
        "contract_name",
        "target_cpu",
        "observed_affinity",
        "scheduler_policy",
        "scheduler_policy_name",
        "scheduler_priority",
        "thread_id",
        "privilege",
        "endpoint_socket_count",
        "credit_owner_capacity",
        "max_datagrams_per_owner",
        "max_post_main_datagrams",
    }
)
_HELPER_LIFECYCLE_KEYS = frozenset(
    {
        "schema_version",
        "globally_poisoned",
        "poison_reason",
        "completed_main_jobs",
        "completed_immediate_datagrams",
        "aborted_jobs",
        "failed_commands",
        "causal_main_proven",
        "active_job_id",
        "last_main_job_id",
        "remaining_post_main_datagrams",
    }
)
_HELPER_SOCKET_SHUTDOWN_KEYS = frozenset(
    {
        "schema_version",
        "socket_count",
        "active_job_id",
        "pending_socket_count",
        "stale_error_queue_socket_count",
        "nonzero_priority_socket_count",
        "inspection_errors",
        "clean",
    }
)
_HELPER_SHUTDOWN_KEYS = frozenset(
    {
        "schema_version",
        "shutdown_command_sent",
        "shutdown_received",
        "worker_joined",
        "shutdown_complete",
        "clean_socket_state",
        "global_poisoned",
        "failed_commands",
        "remaining_post_main_datagrams",
        "socket_state",
        "lifecycle",
        "errors",
    }
)
_RUNTIME_CONTRACT_KEYS = frozenset(
    {
        "schema_version",
        "scheduler_contract",
        "scheduler_initial",
        "socket_setup",
        "privilege_drop",
        "helper_thread",
        "helper_lifecycle",
        "helper_shutdown",
        "socket_count",
        "single_threaded_sender_control_flow_enforced",
        "prebuild_selection_cutoff_lead_ns",
        "prebuild_selection_semantics",
        "post_main_inventory_semantics",
        "max_post_main_datagrams",
    }
)
_QDISC_CONTRACT_KEYS = frozenset(
    {
        "schema_version",
        "interface",
        "root_kind",
        "root_handle",
        "bands",
        "priomap",
        "timed_kind",
        "timed_parent",
        "timed_handle",
        "ordinary_kind",
        "ordinary_parent",
        "ordinary_handle",
        "clock_id",
        "delta_ns",
        "deadline_mode",
        "offload",
        "skip_socket_check",
        "timed_socket_priority",
        "ordinary_socket_priority",
        "priority_method",
        "scm_priority_supported",
        "single_threaded_sender_control_flow_enforced",
        "so_priority_before",
        "so_priority_during",
        "so_priority_after",
        "so_priority_reset_valid",
        "so_txtime_enabled",
        "tx_sched_timestamping_enabled",
        "tx_software_timestamping_enabled",
        "tx_timestamp_opt_id_enabled",
        "txtime_errors_enabled",
    }
)
_TXTIME_ERROR_KEYS = frozenset(
    {"family", "errno", "kind", "requested_txtime_tai_ns"}
)
_SEND_ATTEMPT_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "requested_txtime_tai_ns",
        "latest_enqueue_tai_ns",
        "enqueue_before_tai_ns",
        "enqueue_monotonic_ns",
        "enqueue_after_tai_ns",
        "sendmsg_result",
        "send_errno",
        "payload_bytes",
        "source",
        "destination",
        "tos",
        "priority_method",
    }
)
_ITEM_V1_KEYS = frozenset(
    {
        "schema_version",
        "item_id",
        "job_id",
        "order_index",
        "event_id",
        "role",
        "endpoint_index",
        "endpoint",
        "send_path",
        "datagram_sha256",
        "source_address",
        "destination_address",
        "socket_timestamp_id",
        "udp_payload_bytes",
        "target_tai_ns",
        "scm_txtime_tai_ns",
        "enqueue_monotonic_ns",
        "enqueue_tai_ns",
        "enqueue_tai_lower_ns",
        "enqueue_tai_upper_ns",
        "tx_sched_realtime_ns",
        "tx_sched_tai_ns",
        "tx_sched_tai_lower_ns",
        "tx_sched_tai_upper_ns",
        "tx_software_realtime_ns",
        "provisional_tx_software_tai_lower_ns",
        "provisional_tx_software_tai_upper_ns",
        "tx_software_tai_ns",
        "tx_software_tai_lower_ns",
        "tx_software_tai_upper_ns",
        "send_attempt",
        "txtime_error",
        "terminal_error",
        "terminal_error_detail",
        "finalization_state",
        "terminal_outcome",
    }
)
_ITEM_V2_KEYS = _ITEM_V1_KEYS | {"post_tx_clock_phase"}
_ITEM_V3_KEYS = _ITEM_V2_KEYS
_ITEM_V4_KEYS = _ITEM_V3_KEYS
_JOB_KEYS = frozenset(
    {
        "schema_version",
        "job_id",
        "tick",
        "release_monotonic_ns",
        "release_tai_ns",
        "deadline_monotonic_ns",
        "deadline_tai_ns",
        "items",
        "credit_identities",
        "prepared_output_failure",
        "helper_job_close",
        "helper_job_abort",
        "terminal_error",
        "terminal_outcome",
    }
)
_PREPARED_OUTPUT_FAILURE_KEYS = frozenset(
    {
        "schema_version",
        "stage",
        "transport_output_mutated",
        "observations_drained",
        "batch_source_address",
        "batch_destination_address",
        "batch_datagram_count",
        "batch_datagram_lengths",
        "batch_sha256",
        "batch_hash_error",
        "observation_count",
        "built_composition_count",
        "satisfied_datagram_count",
        "attributed_datagram_count",
        "error",
    }
)
_PREPARED_OUTPUT_FAILURE_WRAPPER_KEYS = frozenset(
    {"schema_version", "job_id", "endpoint_index", "endpoint", "failure"}
)
_CREDIT_IDENTITY_KEYS = frozenset(
    {
        "schema_version",
        "slot",
        "endpoint_index",
        "endpoint",
        "stream_id",
        "absolute_limit",
        "identity_kind",
        "identity_detail",
        "resolution",
        "carrier_item_id",
    }
)
_HELPER_JOB_CLOSE_KEYS = frozenset(
    {"schema_version", "job_id", "unused_post_main_datagrams", "complete"}
)
_HELPER_JOB_ABORT_KEYS = frozenset(
    {
        "schema_version",
        "job_id",
        "reason",
        "unused_post_main_datagrams",
        "complete",
        "aborted",
        "global_poisoned",
        "failed_commands",
    }
)
_RUNNER_AGGREGATE_KEYS = frozenset(
    {
        "schema_version",
        "job_count",
        "item_count",
        "etf_item_count",
        "ordered_item_count",
        "captured_credit_identity_count",
        "prepared_output_failure_count",
        "main_coalesced_credit_identity_count",
        "carrier_credit_identity_count",
        "unresolved_credit_identity_count",
        "transmitted_item_count",
        "failed_item_count",
        "tx_sched_timestamp_count",
        "tx_software_timestamp_count",
        "txtime_error_count",
        "timestamp_evidence_missing_count",
        "window_violation_count",
        "unresolved_item_count",
        "max_tx_software_lateness_ns",
        "terminal_outcome",
    }
)
_RUNNER_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "semantics",
        "terminal_outcome",
        "primary_error",
        "cleanup_errors",
        "defense_start_monotonic_ns",
        "defense_start_tai_ns",
        "clock_start",
        "clock_end",
        "clock_mapping_valid",
        "clock_mapping_error",
        "clock_mapping",
        "runtime_contract",
        "qdisc_contract",
        "jobs",
        "aggregate",
        "terminal_errors",
    }
)

_QDISC_SNAPSHOT_KEYS = frozenset(
    {
        "packets",
        "bytes",
        "drops",
        "overlimits",
        "requeues",
        "backlog_bytes",
        "backlog_packets",
        "qlen",
    }
)
_QDISC_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "source",
        "observed_contract",
        "installed_before_runner",
        "verified_after_runner",
        "restored_after_capture",
        "before",
        "after",
    }
)
_CAPTURE_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "capture_id",
        "observer_role",
        "interface",
        "pcapng_sha256",
        "timestamp_clock_id",
        "timestamp_type",
        "capture_start_realtime_ns",
        "capture_end_realtime_ns",
        "packets_received",
        "packets_dropped",
        "interface_packets_dropped",
        "dumpcap_received_packets",
        "dumpcap_returncode",
        "capture_active_at_stop",
        "router_state_start",
        "router_state_end",
        "capture_service_end_state",
    }
)
_ROUTER_STATE_KEYS = frozenset(
    {
        "schema_version",
        "topology_kind",
        "capture_process_state",
        "capture_process_active",
        "client_interface",
        "uplink_interface",
        "client_subnet",
        "ipv4_forwarding",
        "interfaces",
        "routes",
        "qdiscs",
        "offloads",
        "nat_rules",
        "invariants",
    }
)
_ROUTER_INVARIANT_KEYS = frozenset(
    {
        "client_interface_present",
        "uplink_interface_present",
        "ipv4_forwarding_enabled",
        "uplink_default_route_present",
        "source_masquerade_required",
        "source_masquerade_present",
    }
)
_RECONCILIATION_KEYS = frozenset(
    {
        "schema_version",
        "item_id",
        "job_id",
        "order_index",
        "endpoint",
        "datagram_sha256",
        "source_address",
        "destination_address",
        "candidate_packet_count",
        "capture_packet_index",
        "capture_endpoint",
        "capture_source_address",
        "capture_destination_address",
        "capture_direction",
        "capture_realtime_ns",
        "capture_tai_lower_ns",
        "capture_tai_upper_ns",
        "capture_udp_payload_bytes",
        "capture_datagram_sha256",
        "tx_to_capture_delta_lower_ns",
        "tx_to_capture_delta_upper_ns",
        "terminal_outcome",
    }
)
_EVIDENCE_AGGREGATE_KEYS = frozenset(
    {
        "schema_version",
        "job_count",
        "item_count",
        "matched_item_count",
        "runner_failed_item_count",
        "missing_item_count",
        "duplicate_item_count",
        "length_mismatch_item_count",
        "window_violation_item_count",
        "order_violation_item_count",
        "unresolved_item_count",
        "qdisc_drop_count",
        "qdisc_overlimit_count",
        "qdisc_requeue_count",
        "capture_drop_count",
        "max_tx_to_capture_delta_ns",
        "terminal_outcome",
    }
)
_EVIDENCE_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "semantics",
        "runner_run_json_sha256",
        "runner_kernel_tx_sha256",
        "controlled_network_receipt_sha256",
        "controlled_network_receipt",
        "controlled_observer_binding",
        "qdisc",
        "post_veth_capture",
        "reconciliations",
        "aggregate",
    }
)

_ITEM_OUTCOMES = frozenset(
    {
        "transmitted",
        "txtime-error",
        "timestamp-evidence-missing",
        "window-violation",
        "controller-trace-finalization-failed",
    }
)
_RECONCILIATION_OUTCOMES = frozenset(
    {
        "matched",
        "runner-failed",
        "missing",
        "duplicate",
        "length-mismatch",
        "window-violation",
        "order-violation",
    }
)


def _u64(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**64 - 1


def _positive_u64(value: Any) -> bool:
    return _u64(value) and value > 0


def _exact_mapping(value: Any, keys: frozenset[str]) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) and set(value) == keys else None


def _nullable_u64(value: Any) -> bool:
    return value is None or _u64(value)


def _schema(value: Mapping[str, Any], expected: int = 1) -> bool:
    return type(value.get("schema_version")) is int and value["schema_version"] == expected


def _sha256(value: Any) -> bool:
    return type(value) is str and _HEX_SHA256.fullmatch(value) is not None


def _string(value: Any) -> bool:
    return type(value) is str and bool(value)


def _nullable_string(value: Any) -> bool:
    return value is None or _string(value)


def _i64(value: Any) -> bool:
    return type(value) is int and -(2**63) <= value <= 2**63 - 1


def _i128(value: Any) -> bool:
    return type(value) is int and -(2**127) <= value <= 2**127 - 1


def _nullable_i64(value: Any) -> bool:
    return value is None or _i64(value)


def _socket_address(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    host: str
    port: str
    if value.startswith("["):
        closing = value.rfind("]:")
        if closing < 0:
            return False
        host, port = value[1:closing], value[closing + 2 :]
    else:
        host, separator, port = value.rpartition(":")
        if not separator:
            return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return port.isdecimal() and 0 < int(port) <= 65_535


def _prepared_output_failure_valid(
    value: Any,
    *,
    job_id: int,
    socket_setup: Sequence[Mapping[str, Any]],
) -> bool:
    wrapper = _exact_mapping(value, _PREPARED_OUTPUT_FAILURE_WRAPPER_KEYS)
    if (
        wrapper is None
        or not _schema(wrapper)
        or wrapper.get("job_id") != job_id
        or not _u64(wrapper.get("endpoint_index"))
        or wrapper.get("endpoint") != wrapper.get("endpoint_index")
        or wrapper["endpoint_index"] >= len(socket_setup)
    ):
        return False
    failure = _exact_mapping(wrapper.get("failure"), _PREPARED_OUTPUT_FAILURE_KEYS)
    if (
        failure is None
        or not _schema(failure)
        or not _string(failure.get("stage"))
        or type(failure.get("transport_output_mutated")) is not bool
        or type(failure.get("observations_drained")) is not bool
        or not _nullable_string(failure.get("batch_source_address"))
        or not _nullable_string(failure.get("batch_destination_address"))
        or not _u64(failure.get("batch_datagram_count"))
        or not isinstance(failure.get("batch_datagram_lengths"), list)
        or not all(_positive_u64(length) for length in failure["batch_datagram_lengths"])
        or failure["batch_datagram_count"] != len(failure["batch_datagram_lengths"])
        or not (failure.get("batch_sha256") is None or _sha256(failure["batch_sha256"]))
        or not _nullable_string(failure.get("batch_hash_error"))
        or not all(
            _u64(failure.get(key))
            for key in (
                "observation_count",
                "built_composition_count",
                "satisfied_datagram_count",
                "attributed_datagram_count",
            )
        )
        or failure["attributed_datagram_count"] > failure["batch_datagram_count"]
        or failure["satisfied_datagram_count"] > failure["observation_count"]
        or not _string(failure.get("error"))
    ):
        return False
    source = failure["batch_source_address"]
    destination = failure["batch_destination_address"]
    batch_present = failure["batch_datagram_count"] > 0
    return bool(
        (source is None) == (destination is None)
        and (source is not None) == batch_present
        and (failure["batch_sha256"] is not None or failure["batch_hash_error"] is not None)
        == batch_present
        and not (
            failure["batch_sha256"] is not None
            and failure["batch_hash_error"] is not None
        )
        and (source is None or _socket_address(source))
        and (destination is None or _socket_address(destination))
        and (
            source is None
            or source == socket_setup[wrapper["endpoint_index"]]["local_address"]
        )
    )


def _midpoint(lower: int, upper: int) -> int:
    return lower + (upper - lower) // 2


def _translated_interval(
    mapping: Mapping[str, Any], *, clock: str, raw_ns: int
) -> tuple[int, int]:
    low, high = _offset_envelope(mapping, clock)
    return raw_ns + low, raw_ns + high


def kernel_tx_receipt_sha256(value: Mapping[str, Any]) -> str:
    """Hash a receipt using the Lab's canonical JSON v1 encoding."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _clock_sample_valid(value: Any) -> bool:
    sample = _exact_mapping(value, _CLOCK_SAMPLE_KEYS)
    return bool(
        sample is not None
        and _schema(sample)
        and all(
            _u64(sample.get(key))
            for key in ("tai_before_ns", "clock_ns", "tai_after_ns", "bracket_width_ns")
        )
        and sample["tai_before_ns"] <= sample["tai_after_ns"]
        and sample["bracket_width_ns"] == sample["tai_after_ns"] - sample["tai_before_ns"]
        and sample["bracket_width_ns"] <= KERNEL_TX_MAX_CLOCK_BRACKET_NS
    )


def _offset_midpoint_drift_ns(start: Mapping[str, Any], end: Mapping[str, Any]) -> int:
    start_twice = start["tai_before_ns"] + start["tai_after_ns"] - 2 * start["clock_ns"]
    end_twice = end["tai_before_ns"] + end["tai_after_ns"] - 2 * end["clock_ns"]
    return (abs(end_twice - start_twice) + 1) // 2


def _clock_phase_valid(value: Any) -> bool:
    phase = _exact_mapping(value, _CLOCK_PHASE_KEYS)
    return bool(
        phase is not None
        and all(_clock_sample_valid(phase.get(clock)) for clock in ("monotonic", "realtime"))
        and phase["monotonic"]["tai_after_ns"]
        <= phase["realtime"]["tai_before_ns"]
    )


def _clock_phases_chronological(
    start: Mapping[str, Any], end: Mapping[str, Any]
) -> bool:
    return bool(
        start["realtime"]["tai_after_ns"] <= end["monotonic"]["tai_before_ns"]
        and all(
            start[clock]["clock_ns"] <= end[clock]["clock_ns"]
            for clock in ("monotonic", "realtime")
        )
    )


def _sample_offset_bounds(sample: Mapping[str, Any]) -> tuple[int, int]:
    return (
        sample["tai_before_ns"] - sample["clock_ns"],
        sample["tai_after_ns"] - sample["clock_ns"],
    )


def _phase_offset_envelope(
    mapping: Mapping[str, Any], clock: str
) -> tuple[int, int]:
    bounds = [
        _sample_offset_bounds(mapping[phase][clock]) for phase in ("start", "end")
    ]
    return min(bound[0] for bound in bounds), max(bound[1] for bound in bounds)


def _offset_intersection(
    bounds: Sequence[tuple[int, int]],
) -> tuple[int, int] | None:
    lower = max(bound[0] for bound in bounds)
    upper = min(bound[1] for bound in bounds)
    return (lower, upper) if lower <= upper else None


def _clock_phases_strictly_ordered(
    earlier: Mapping[str, Any], later: Mapping[str, Any]
) -> bool:
    """Mirror the schema-two Rust phase ordering predicate exactly."""

    return bool(
        earlier["realtime"]["tai_after_ns"]
        <= later["monotonic"]["tai_before_ns"]
        and earlier["monotonic"]["clock_ns"]
        <= later["monotonic"]["clock_ns"]
        and earlier["realtime"]["clock_ns"] <= later["realtime"]["clock_ns"]
    )


def _clock_mapping_valid(value: Any) -> bool:
    mapping = _exact_mapping(value, _CLOCK_MAPPING_KEYS)
    schema_version = mapping.get("schema_version") if mapping is not None else None
    expected_semantics = {
        1: _EFFECTIVE_ENVELOPE_SEMANTICS_V1,
        2: _EFFECTIVE_ENVELOPE_SEMANTICS_V2,
        3: _EFFECTIVE_ENVELOPE_SEMANTICS_V3,
        4: _EFFECTIVE_ENVELOPE_SEMANTICS_V3,
    }.get(schema_version)
    if (
        mapping is None
        or expected_semantics is None
        or mapping.get("tai_clock_id") != "CLOCK_TAI"
        or mapping.get("monotonic_clock_id") != "CLOCK_MONOTONIC"
        or mapping.get("realtime_clock_id") != "CLOCK_REALTIME"
        or not _u64(mapping.get("max_observed_bracket_width_ns"))
        or not _u64(mapping.get("max_observed_offset_drift_ns"))
        or not all(
            _i128(mapping.get(key))
            for key in (
                "effective_monotonic_offset_lower_ns",
                "effective_monotonic_offset_upper_ns",
                "effective_realtime_offset_lower_ns",
                "effective_realtime_offset_upper_ns",
            )
        )
        or not _u64(mapping.get("per_item_monotonic_evidence_count"))
        or not _u64(mapping.get("per_item_realtime_evidence_count"))
        or mapping.get("effective_envelope_semantics") != expected_semantics
    ):
        return False
    instant = _exact_mapping(mapping.get("instant_alignment"), _INSTANT_ALIGNMENT_KEYS)
    if (
        instant is None
        or not _schema(instant)
        or not _u64(instant.get("monotonic_clock_ns"))
        or not _u64(instant.get("instant_bracket_width_ns"))
        or instant["instant_bracket_width_ns"] > KERNEL_TX_MAX_CLOCK_BRACKET_NS
        or instant.get("selected_upper_offset_ns")
        != instant["instant_bracket_width_ns"]
        or instant.get("semantics") != _INSTANT_ALIGNMENT_SEMANTICS
    ):
        return False
    phases: dict[str, Mapping[str, Any]] = {}
    for phase_name in ("start", "end"):
        phase = mapping.get(phase_name)
        if not _clock_phase_valid(phase):
            return False
        assert isinstance(phase, Mapping)
        phases[phase_name] = phase
    phase_width = max(
        instant["instant_bracket_width_ns"],
        *(
            phases[phase][clock]["bracket_width_ns"]
            for phase in ("start", "end")
            for clock in ("monotonic", "realtime")
        ),
    )
    phase_drift = max(
        _offset_midpoint_drift_ns(
            phases["start"][clock],
            phases["end"][clock],
        )
        for clock in ("monotonic", "realtime")
    )
    monotonic_phase = _phase_offset_envelope(mapping, "monotonic")
    realtime_bounds = [
        _sample_offset_bounds(phases[phase]["realtime"])
        for phase in ("start", "end")
    ]
    realtime_phase = _phase_offset_envelope(mapping, "realtime")
    realtime_intersection = _offset_intersection(realtime_bounds)
    if schema_version == 1:
        realtime_valid = bool(
            mapping["effective_realtime_offset_lower_ns"] <= realtime_phase[0]
            and mapping["effective_realtime_offset_upper_ns"] >= realtime_phase[1]
            and _clock_phases_chronological(phases["start"], phases["end"])
        )
    else:
        realtime_valid = bool(
            realtime_intersection is not None
            and mapping["effective_realtime_offset_lower_ns"]
            >= realtime_intersection[0]
            and mapping["effective_realtime_offset_upper_ns"]
            <= realtime_intersection[1]
            and _clock_phases_strictly_ordered(phases["start"], phases["end"])
        )
    return bool(
        phase_width <= mapping["max_observed_bracket_width_ns"]
        <= KERNEL_TX_MAX_CLOCK_BRACKET_NS
        and phase_drift <= mapping["max_observed_offset_drift_ns"]
        and (
            schema_version in {2, 3, 4}
            or mapping["max_observed_offset_drift_ns"]
            <= KERNEL_TX_MAX_CLOCK_OFFSET_DRIFT_NS
        )
        and mapping["effective_monotonic_offset_lower_ns"] <= monotonic_phase[0]
        and mapping["effective_monotonic_offset_upper_ns"] >= monotonic_phase[1]
        and mapping["effective_monotonic_offset_lower_ns"]
        <= mapping["effective_monotonic_offset_upper_ns"]
        and mapping["effective_realtime_offset_lower_ns"]
        <= mapping["effective_realtime_offset_upper_ns"]
        and realtime_valid
        and phases["start"]["monotonic"]["clock_ns"]
        <= instant["monotonic_clock_ns"]
        <= phases["end"]["monotonic"]["clock_ns"]
    )


def _clock_mapping_matches_items(
    mapping: Mapping[str, Any], jobs: Sequence[Mapping[str, Any]]
) -> bool:
    if mapping["schema_version"] in {2, 3, 4}:
        return _clock_mapping_v2_matches_items(mapping, jobs)
    envelopes = {
        clock: list(_phase_offset_envelope(mapping, clock))
        for clock in ("monotonic", "realtime")
    }
    widths = [
        mapping["instant_alignment"]["instant_bracket_width_ns"],
        *(
        mapping[phase][clock]["bracket_width_ns"]
        for phase in ("start", "end")
        for clock in ("monotonic", "realtime")
        ),
    ]
    drifts = [
        _offset_midpoint_drift_ns(mapping["start"][clock], mapping["end"][clock])
        for clock in ("monotonic", "realtime")
    ]
    references = {
        clock: _midpoint(*_sample_offset_bounds(mapping["start"][clock]))
        for clock in ("monotonic", "realtime")
    }
    counts = {"monotonic": 0, "realtime": 0}
    for item in (item for job in jobs for item in job["items"]):
        evidence = (
            (
                "monotonic",
                item["enqueue_monotonic_ns"],
                item["enqueue_tai_lower_ns"],
                item["enqueue_tai_upper_ns"],
            ),
            (
                "realtime",
                item["tx_software_realtime_ns"],
                item["provisional_tx_software_tai_lower_ns"],
                item["provisional_tx_software_tai_upper_ns"],
            ),
        )
        for clock, raw, lower, upper in evidence:
            if raw is None or lower is None or upper is None:
                continue
            if lower > upper:
                return False
            bounds = (lower - raw, upper - raw)
            envelopes[clock][0] = min(envelopes[clock][0], bounds[0])
            envelopes[clock][1] = max(envelopes[clock][1], bounds[1])
            counts[clock] += 1
            drifts.append(abs(references[clock] - _midpoint(*bounds)))
            widths.append(bounds[1] - bounds[0])
    return bool(
        mapping["effective_monotonic_offset_lower_ns"] == envelopes["monotonic"][0]
        and mapping["effective_monotonic_offset_upper_ns"] == envelopes["monotonic"][1]
        and mapping["effective_realtime_offset_lower_ns"] == envelopes["realtime"][0]
        and mapping["effective_realtime_offset_upper_ns"] == envelopes["realtime"][1]
        and mapping["per_item_monotonic_evidence_count"] == counts["monotonic"]
        and mapping["per_item_realtime_evidence_count"] == counts["realtime"]
        and mapping["max_observed_bracket_width_ns"] == max(widths)
        and mapping["max_observed_offset_drift_ns"] == max(drifts)
    )


def _clock_mapping_v2_matches_items(
    mapping: Mapping[str, Any], jobs: Sequence[Mapping[str, Any]]
) -> bool:
    monotonic_envelope = list(_phase_offset_envelope(mapping, "monotonic"))
    start_realtime_bounds = _sample_offset_bounds(mapping["start"]["realtime"])
    end_realtime_bounds = _sample_offset_bounds(mapping["end"]["realtime"])
    # The Rust sender cannot know the final phase while transmitting.  Rebuild
    # its online running intersection from the start phase and each retained
    # post-TX phase in item order; only add the end phase when checking the
    # final mapping.  This distinction is observable whenever the final phase
    # narrows an earlier provisional interval.
    online_realtime_intersection = start_realtime_bounds
    final_realtime_bounds = [start_realtime_bounds, end_realtime_bounds]
    widths = [
        mapping["instant_alignment"]["instant_bracket_width_ns"],
        *(
        mapping[phase][clock]["bracket_width_ns"]
        for phase in ("start", "end")
        for clock in ("monotonic", "realtime")
        ),
    ]
    drifts = [
        _offset_midpoint_drift_ns(mapping["start"][clock], mapping["end"][clock])
        for clock in ("monotonic", "realtime")
    ]
    evidence_count = 0
    previous_phase = mapping["start"]
    for item in (item for job in jobs for item in job["items"]):
        phase = item.get("post_tx_clock_phase")
        if phase is None:
            continue
        if (
            not _clock_phase_valid(phase)
            or not _clock_phases_strictly_ordered(previous_phase, phase)
            or not _clock_phases_strictly_ordered(phase, mapping["end"])
            or (
                item.get("tx_software_realtime_ns") is not None
                and item["tx_software_realtime_ns"] > phase["realtime"]["clock_ns"]
            )
            or (
                item.get("enqueue_monotonic_ns") is not None
                and item["enqueue_monotonic_ns"] > phase["monotonic"]["clock_ns"]
            )
            or (
                item.get("enqueue_tai_upper_ns") is not None
                and item["enqueue_tai_upper_ns"]
                > phase["monotonic"]["tai_before_ns"]
            )
        ):
            return False
        monotonic_bounds = _sample_offset_bounds(phase["monotonic"])
        phase_realtime_bounds = _sample_offset_bounds(phase["realtime"])
        refined_online_intersection = _offset_intersection(
            [online_realtime_intersection, phase_realtime_bounds]
        )
        if refined_online_intersection is None:
            return False
        online_realtime_intersection = refined_online_intersection
        final_realtime_bounds.append(phase_realtime_bounds)
        tx_software_realtime_ns = item.get("tx_software_realtime_ns")
        provisional_lower = item.get("provisional_tx_software_tai_lower_ns")
        provisional_upper = item.get("provisional_tx_software_tai_upper_ns")
        if provisional_lower is not None and tx_software_realtime_ns is not None:
            expected_provisional = (
                tx_software_realtime_ns + online_realtime_intersection[0],
                tx_software_realtime_ns + online_realtime_intersection[1],
            )
            if (
                not all(_u64(bound) for bound in expected_provisional)
                or (provisional_lower, provisional_upper) != expected_provisional
            ):
                return False
        monotonic_envelope[0] = min(monotonic_envelope[0], monotonic_bounds[0])
        monotonic_envelope[1] = max(monotonic_envelope[1], monotonic_bounds[1])
        for clock, bounds in (
            ("monotonic", monotonic_bounds),
            ("realtime", phase_realtime_bounds),
        ):
            widths.append(bounds[1] - bounds[0])
            drifts.append(
                _offset_midpoint_drift_ns(
                    mapping["start"][clock], phase[clock]
                )
            )
        evidence_count += 1
        previous_phase = phase
    final_realtime_intersection = _offset_intersection(final_realtime_bounds)
    if final_realtime_intersection is None:
        return False
    return bool(
        mapping["effective_monotonic_offset_lower_ns"] == monotonic_envelope[0]
        and mapping["effective_monotonic_offset_upper_ns"] == monotonic_envelope[1]
        and mapping["effective_realtime_offset_lower_ns"]
        == final_realtime_intersection[0]
        and mapping["effective_realtime_offset_upper_ns"]
        == final_realtime_intersection[1]
        and mapping["per_item_monotonic_evidence_count"] == evidence_count
        and mapping["per_item_realtime_evidence_count"] == evidence_count
        and mapping["max_observed_bracket_width_ns"] == max(widths)
        and mapping["max_observed_offset_drift_ns"] == max(drifts)
    )


def _offset_envelope(mapping: Mapping[str, Any], clock: str) -> tuple[int, int]:
    return (
        mapping[f"effective_{clock}_offset_lower_ns"],
        mapping[f"effective_{clock}_offset_upper_ns"],
    )


def _translated_timestamp_valid(
    mapping: Mapping[str, Any], *, clock: str, raw_ns: Any, tai_ns: Any
) -> bool:
    if not _u64(raw_ns) or not _u64(tai_ns):
        return False
    low, high = _offset_envelope(mapping, clock)
    return low <= tai_ns - raw_ns <= high


def _clock_frame_contains(mapping: Mapping[str, Any], *, clock: str, raw_ns: int) -> bool:
    return mapping["start"][clock]["clock_ns"] <= raw_ns <= mapping["end"][clock]["clock_ns"]


def _item_local_enqueue_clock_consistent(
    phase: Any,
    *,
    enqueue_monotonic_ns: int,
    enqueue_tai_lower_ns: int,
    enqueue_tai_upper_ns: int,
) -> bool:
    """Mirror schema two's item-local MONOTONIC corroboration exactly."""

    if (
        not _clock_phase_valid(phase)
        or enqueue_monotonic_ns > phase["monotonic"]["clock_ns"]
        or enqueue_tai_lower_ns > enqueue_tai_upper_ns
        or enqueue_tai_upper_ns > phase["monotonic"]["tai_before_ns"]
    ):
        return False
    lower_offset, upper_offset = _sample_offset_bounds(phase["monotonic"])
    mapped_lower = enqueue_monotonic_ns + lower_offset
    mapped_upper = enqueue_monotonic_ns + upper_offset
    return bool(
        _u64(mapped_lower)
        and _u64(mapped_upper)
        and mapped_lower <= mapped_upper
        and mapped_lower <= enqueue_tai_upper_ns
        and enqueue_tai_lower_ns <= mapped_upper
    )


def _item_local_enqueue_operation_ordered(
    phase: Any,
    *,
    enqueue_monotonic_ns: int,
    enqueue_tai_lower_ns: int,
    enqueue_tai_upper_ns: int,
) -> bool:
    """Validate schema three's directly observed send-sequence ordering."""

    return bool(
        _clock_phase_valid(phase)
        and enqueue_tai_lower_ns <= enqueue_tai_upper_ns
        and enqueue_monotonic_ns <= phase["monotonic"]["clock_ns"]
        and enqueue_tai_upper_ns <= phase["monotonic"]["tai_before_ns"]
    )


def _privilege_valid(value: Any) -> bool:
    receipt = _exact_mapping(value, _PRIVILEGE_KEYS)
    if receipt is None or not _schema(receipt):
        return False
    uid = receipt.get("uid")
    gid = receipt.get("gid")
    caps = (
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bounding",
        "cap_ambient",
    )
    return bool(
        isinstance(uid, list)
        and len(uid) == 4
        and all(type(item) is int and item == uid[0] for item in uid)
        and uid[0] > 0
        and isinstance(gid, list)
        and len(gid) == 4
        and all(type(item) is int and item == gid[0] for item in gid)
        and gid[0] > 0
        and receipt.get("supplementary_groups") == []
        and all(
            isinstance(receipt.get(key), str)
            and len(receipt[key]) == 16
            and set(receipt[key]) <= {"0"}
            for key in caps
        )
        and receipt.get("no_new_privileges") is True
    )


def _process_scheduler_valid(value: Any) -> bool:
    receipt = _exact_mapping(value, _PROCESS_SCHEDULER_KEYS)
    limit = receipt.get("rlimit_rtprio") if receipt is not None else None
    return bool(
        receipt is not None
        and _schema(receipt)
        and receipt.get("source") == "linux-sched-and-procfs-v1"
        and receipt.get("policy") == "SCHED_RR"
        and receipt.get("priority") == 1
        and receipt.get("affinity_cpus") == [10]
        and isinstance(limit, Mapping)
        and set(limit) == {"soft", "hard"}
        and limit.get("soft") == limit.get("hard") == 1
        and receipt.get("no_new_privileges") is True
        and receipt.get("effective_capabilities_hex")
        in {"0000000000001100", "0000000000000000"}
        and receipt.get("cgroup_effective_cpuset") == "10-11"
        and receipt.get("affinity_scope")
        == "qcsd_container_affinity_partition_not_physical_cpu_isolation"
        and receipt.get("contract")
        == "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"
        and receipt.get("contract_valid") is True
    )


def _socket_setup_valid(value: Any) -> bool:
    receipt = _exact_mapping(value, _SOCKET_SETUP_KEYS)
    if receipt is None or not _schema(receipt):
        return False
    local_address = receipt.get("local_address")
    if not _socket_address(local_address):
        return False
    assert isinstance(local_address, str)
    host = (
        local_address[1 : local_address.rfind("]:")]
        if local_address.startswith("[")
        else local_address.rpartition(":")[0]
    )
    family = receipt.get("family")
    try:
        address_family = "ipv4" if ipaddress.ip_address(host).version == 4 else "ipv6"
    except ValueError:
        return False
    priority_method = receipt.get("priority_method")
    scm_supported = receipt.get("scm_priority_supported")
    probe_errno = receipt.get("scm_priority_probe_errno")
    return bool(
        family == address_family
        and receipt.get("duplicated_fd_cloexec") is True
        and receipt.get("nonblocking") is True
        and receipt.get("socket_type") == 2
        and receipt.get("txtime_clock_id") == 11
        and type(receipt.get("txtime_flags")) is int
        and receipt.get("txtime_flags") == _SOF_TXTIME_REPORT_ERRORS
        and receipt.get("timestamping_report_flags") == 2_192
        and receipt.get("timed_priority") == 6
        and receipt.get("priority_before_probe") == 0
        and receipt.get("priority_after_probe") == 0
        and receipt.get("corresponding_error_queue_enabled") is True
        and receipt.get("etf_deadline_mode") is False
        and receipt.get("etf_skip_socket_check") is False
        and priority_method in {"per_datagram_scm_priority", "serialized_socket_so_priority"}
        and type(scm_supported) is bool
        and receipt.get("scm_priority_probe_family") == family
        and (
            (
                priority_method == "per_datagram_scm_priority"
                and scm_supported is True
                and probe_errno is None
            )
            or (
                priority_method == "serialized_socket_so_priority"
                and scm_supported is False
                and probe_errno == 22
            )
        )
        and receipt.get("exclusive_socket_sender_required") is True
        and receipt.get("per_datagram_timestamp_requests") is True
    )


def _helper_lifecycle_valid(value: Any) -> bool:
    receipt = _exact_mapping(value, _HELPER_LIFECYCLE_KEYS)
    return bool(
        receipt is not None
        and _schema(receipt)
        and type(receipt.get("globally_poisoned")) is bool
        and _nullable_string(receipt.get("poison_reason"))
        and all(
            _u64(receipt.get(key))
            for key in (
                "completed_main_jobs",
                "completed_immediate_datagrams",
                "aborted_jobs",
                "failed_commands",
                "remaining_post_main_datagrams",
            )
        )
        and type(receipt.get("causal_main_proven")) is bool
        and _nullable_u64(receipt.get("active_job_id"))
        and _nullable_u64(receipt.get("last_main_job_id"))
        and (receipt["globally_poisoned"] or receipt["poison_reason"] is None)
    )


def _helper_shutdown_valid(value: Any) -> bool:
    receipt = _exact_mapping(value, _HELPER_SHUTDOWN_KEYS)
    if receipt is None or not _schema(receipt):
        return False
    socket_state = receipt.get("socket_state")
    lifecycle = receipt.get("lifecycle")
    socket_valid = socket_state is None or bool(
        (socket_state := _exact_mapping(socket_state, _HELPER_SOCKET_SHUTDOWN_KEYS)) is not None
        and _schema(socket_state)
        and _u64(socket_state.get("socket_count"))
        and _nullable_u64(socket_state.get("active_job_id"))
        and all(
            _u64(socket_state.get(key))
            for key in (
                "pending_socket_count",
                "stale_error_queue_socket_count",
                "nonzero_priority_socket_count",
            )
        )
        and isinstance(socket_state.get("inspection_errors"), list)
        and all(_string(item) for item in socket_state["inspection_errors"])
        and type(socket_state.get("clean")) is bool
    )
    return bool(
        all(
            type(receipt.get(key)) is bool
            for key in (
                "shutdown_command_sent",
                "shutdown_received",
                "worker_joined",
                "shutdown_complete",
                "clean_socket_state",
                "global_poisoned",
            )
        )
        and _nullable_u64(receipt.get("failed_commands"))
        and _nullable_u64(receipt.get("remaining_post_main_datagrams"))
        and socket_valid
        and (lifecycle is None or _helper_lifecycle_valid(lifecycle))
        and isinstance(receipt.get("errors"), list)
        and all(_string(item) for item in receipt["errors"])
    )


def _runtime_contract_valid(value: Any, *, success: bool, jobs: Sequence[Mapping[str, Any]]) -> bool:
    contract = _exact_mapping(value, _RUNTIME_CONTRACT_KEYS)
    if (
        contract is None
        or not _schema(contract)
        or any(not isinstance(job, Mapping) for job in jobs)
        or any(
            not isinstance(job.get("items"), list)
            or any(not isinstance(item, Mapping) for item in job["items"])
            for job in jobs
        )
    ):
        return False
    setups = contract.get("socket_setup")
    socket_count = contract.get("socket_count")
    helper = _exact_mapping(contract.get("helper_thread"), _HELPER_THREAD_KEYS)
    lifecycle = contract.get("helper_lifecycle")
    shutdown = contract.get("helper_shutdown")
    if (
        contract.get("scheduler_contract")
        != "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"
        or not _process_scheduler_valid(contract.get("scheduler_initial"))
        or not isinstance(setups, list)
        or not setups
        or not all(_socket_setup_valid(item) for item in setups)
        or not _positive_u64(socket_count)
        or len(setups) != socket_count
        or len({item["local_address"] for item in setups}) != socket_count
        or not _privilege_valid(contract.get("privilege_drop"))
        or helper is None
        or not _schema(helper)
        or helper.get("contract_name")
        != "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"
        or helper.get("target_cpu") != 11
        or helper.get("observed_affinity") != [11]
        or helper.get("scheduler_policy") != 2
        or helper.get("scheduler_policy_name") != "SCHED_RR"
        or helper.get("scheduler_priority") != 1
        or not _positive_u64(helper.get("thread_id"))
        or not _privilege_valid(helper.get("privilege"))
        or helper["privilege"] != contract["privilege_drop"]
        or helper.get("endpoint_socket_count") != socket_count
        or helper.get("credit_owner_capacity") != socket_count
        or helper.get("max_datagrams_per_owner") != 1
        or helper.get("max_post_main_datagrams") != socket_count
        or contract.get("single_threaded_sender_control_flow_enforced") is not True
        or contract.get("prebuild_selection_cutoff_lead_ns") != 5_000_000
        or contract.get("prebuild_selection_semantics")
        != "application_and_transport_state_selected_at_nominal_release_while_wall_clock_is_one_strict_window_early; runner_freezes_until_kernel_tx_software_receipt; client_only_adaptation; paper_equivalent=false"
        or contract.get("post_main_inventory_semantics")
        != "residual_scheduled_incoming_credit_is_deduplicated_by_endpoint_owner; at_most_one_immediate_datagram_per_owner_per_job; a_second_datagram_for_the_same_owner_is_a_hard_failure; same_endpoint_credit_may_be_coalesced_in_the_exact_main_datagram"
        or contract.get("max_post_main_datagrams") != socket_count
        or (lifecycle is not None and not _helper_lifecycle_valid(lifecycle))
        or (shutdown is not None and not _helper_shutdown_valid(shutdown))
    ):
        return False
    if not success:
        return True
    ordered = sum(
        item.get("send_path") == "ordered-after-exact"
        for job in jobs
        for item in job.get("items", [])
    )
    socket_state = shutdown.get("socket_state") if isinstance(shutdown, Mapping) else None
    return bool(
        isinstance(lifecycle, Mapping)
        and isinstance(shutdown, Mapping)
        and lifecycle.get("globally_poisoned") is False
        and lifecycle.get("poison_reason") is None
        and lifecycle.get("completed_main_jobs") == len(jobs)
        and lifecycle.get("completed_immediate_datagrams") == ordered
        and lifecycle.get("aborted_jobs") == 0
        and lifecycle.get("failed_commands") == 0
        and lifecycle.get("causal_main_proven") is False
        and lifecycle.get("active_job_id") is None
        and lifecycle.get("last_main_job_id") == (len(jobs) - 1 if jobs else None)
        and lifecycle.get("remaining_post_main_datagrams") == 0
        and shutdown.get("shutdown_command_sent") is True
        and shutdown.get("shutdown_received") is True
        and shutdown.get("worker_joined") is True
        and shutdown.get("shutdown_complete") is True
        and shutdown.get("clean_socket_state") is True
        and shutdown.get("global_poisoned") is False
        and shutdown.get("failed_commands") == 0
        and shutdown.get("remaining_post_main_datagrams") == 0
        and shutdown.get("errors") == []
        and shutdown.get("lifecycle") == lifecycle
        and isinstance(socket_state, Mapping)
        and socket_state.get("socket_count") == socket_count
        and socket_state.get("active_job_id") is None
        and socket_state.get("pending_socket_count") == 0
        and socket_state.get("stale_error_queue_socket_count") == 0
        and socket_state.get("nonzero_priority_socket_count") == 0
        and socket_state.get("inspection_errors") == []
        and socket_state.get("clean") is True
    )


def _kernel_tx_etf_delta_ns(runner_schema_version: int) -> int | None:
    return _KERNEL_TX_ETF_DELTA_BY_RUNNER_SCHEMA.get(runner_schema_version)


def _qdisc_contract_valid(value: Any, *, runner_schema_version: int) -> bool:
    contract = _exact_mapping(value, _QDISC_CONTRACT_KEYS)
    expected_delta_ns = _kernel_tx_etf_delta_ns(runner_schema_version)
    if not (
        contract is not None
        and expected_delta_ns is not None
        and _schema(contract)
        and type(contract.get("interface")) is str
        and bool(contract["interface"])
        and contract.get("root_kind") == "prio"
        and contract.get("root_handle") == "1:"
        and type(contract.get("bands")) is int
        and contract["bands"] == 2
        and isinstance(contract.get("priomap"), list)
        and all(type(priority) is int for priority in contract["priomap"])
        and contract["priomap"] == KERNEL_TX_PRIO_MAP
        and contract.get("timed_kind") == "etf"
        and contract.get("timed_parent") == "1:1"
        and contract.get("timed_handle") == "20:"
        and contract.get("ordinary_kind") == "pfifo"
        and contract.get("ordinary_parent") == "1:2"
        and contract.get("ordinary_handle") == "10:"
        and contract.get("clock_id") == "CLOCK_TAI"
        and type(contract.get("delta_ns")) is int
        and contract["delta_ns"] > 0
        and contract["delta_ns"] == expected_delta_ns
        and contract["delta_ns"] < min(KERNEL_TX_ADAPTER_WINDOW_NS)
        and contract.get("deadline_mode") is False
        and contract.get("offload") is False
        and contract.get("skip_socket_check") is False
        and type(contract.get("timed_socket_priority")) is int
        and contract["timed_socket_priority"] == 6
        and type(contract.get("ordinary_socket_priority")) is int
        and contract["ordinary_socket_priority"] == 0
        and type(contract.get("scm_priority_supported")) is bool
        and contract.get("single_threaded_sender_control_flow_enforced") is True
        and type(contract.get("so_priority_before")) is int
        and contract["so_priority_before"] == 0
        and type(contract.get("so_priority_during")) is int
        and type(contract.get("so_priority_after")) is int
        and contract["so_priority_after"] == 0
        and contract.get("so_priority_reset_valid") is True
        and all(
            contract.get(key) is True
            for key in (
                "so_txtime_enabled",
                "tx_sched_timestamping_enabled",
                "tx_software_timestamping_enabled",
                "tx_timestamp_opt_id_enabled",
                "txtime_errors_enabled",
            )
        )
    ):
        return False
    if contract.get("priority_method") == "per_datagram_scm_priority":
        return bool(
            contract["scm_priority_supported"] is True and contract["so_priority_during"] == 0
        )
    if contract.get("priority_method") == "serialized_socket_so_priority":
        return bool(
            contract["scm_priority_supported"] is False
            and contract["so_priority_during"] == contract["timed_socket_priority"]
        )
    return False


def _txtime_error_valid(value: Any, *, requested_txtime_tai_ns: int | None) -> bool:
    error = _exact_mapping(value, _TXTIME_ERROR_KEYS)
    return bool(
        error is not None
        and error.get("family") in {"ipv4", "ipv6"}
        and _positive_u64(error.get("errno"))
        and error.get("kind") in {"invalid_parameter", "missed"}
        and _u64(error.get("requested_txtime_tai_ns"))
        and (
            requested_txtime_tai_ns is None
            or error["requested_txtime_tai_ns"] == requested_txtime_tai_ns
        )
    )


def _txtime_failure_matches_item(item: Mapping[str, Any]) -> bool:
    """Bind a retained TXTIME diagnostic to the helper's pending request.

    Timed main sends retain their explicit ``SCM_TXTIME`` value.  Immediate
    post-main sends have no SCM control message, but the helper deliberately
    uses zero as its internal pending-request sentinel.  A different value is
    retained only by the producer's typed mismatch path.
    """

    error = item.get("txtime_error")
    if not isinstance(error, Mapping):
        return False
    expected = item.get("scm_txtime_tai_ns")
    if item.get("send_path") == "ordered-after-exact":
        expected = 0
    observed = error.get("requested_txtime_tai_ns")
    if observed != expected:
        return item.get("terminal_error") == "txtime_drop_mismatch"
    expected_terminal_error = {
        "invalid_parameter": "txtime_invalid_parameter",
        "missed": "txtime_missed",
    }.get(error.get("kind"))
    return item.get("terminal_error") == expected_terminal_error


def _send_attempt_valid(value: Any, *, item: Mapping[str, Any]) -> bool:
    attempt = _exact_mapping(value, _SEND_ATTEMPT_KEYS)
    if attempt is None or not _schema(attempt):
        return False
    expected_kind = "timed_main" if item.get("send_path") == "etf" else "immediate_post_main"
    return bool(
        attempt.get("kind") == expected_kind
        and attempt.get("requested_txtime_tai_ns") == item.get("scm_txtime_tai_ns")
        and _u64(attempt.get("latest_enqueue_tai_ns"))
        and _u64(attempt.get("enqueue_before_tai_ns"))
        and _nullable_u64(attempt.get("enqueue_monotonic_ns"))
        and _nullable_u64(attempt.get("enqueue_after_tai_ns"))
        and _i64(attempt.get("sendmsg_result"))
        and _nullable_i64(attempt.get("send_errno"))
        and attempt.get("payload_bytes") == item.get("udp_payload_bytes")
        and attempt.get("source") == item.get("source_address")
        and attempt.get("destination") == item.get("destination_address")
        and type(attempt.get("tos")) is int
        and 0 <= attempt["tos"] <= 255
        and attempt.get("priority_method")
        in {None, "per_datagram_scm_priority", "serialized_socket_so_priority"}
    )


def _item_enqueue_evidence_valid(item: Mapping[str, Any]) -> bool:
    """Validate the producer's incremental enqueue-field projection.

    A completed timed/immediate enqueue projects all four item fields.  A
    ``SendAttemptReceipt`` is deliberately incremental: the TAI-before sample
    always exists, while the following monotonic and TAI-after samples may each
    be absent when the corresponding clock read failed.  Rust retains that
    partial evidence instead of erasing it.
    """

    monotonic = item.get("enqueue_monotonic_ns")
    middle = item.get("enqueue_tai_ns")
    lower = item.get("enqueue_tai_lower_ns")
    upper = item.get("enqueue_tai_upper_ns")
    attempt = item.get("send_attempt")
    if lower is None:
        return bool(
            monotonic is None
            and middle is None
            and upper is None
            and attempt is None
        )
    if upper is None:
        if middle is not None:
            return False
    elif lower > upper or middle != _midpoint(lower, upper):
        return False
    if attempt is None:
        return monotonic is not None and upper is not None
    return bool(
        lower == attempt.get("enqueue_before_tai_ns")
        and monotonic == attempt.get("enqueue_monotonic_ns")
        and upper == attempt.get("enqueue_after_tai_ns")
        and item.get("socket_timestamp_id") is None
        and item.get("tx_sched_realtime_ns") is None
        and item.get("tx_software_realtime_ns") is None
        and item.get("post_tx_clock_phase") is None
        and item.get("provisional_tx_software_tai_lower_ns") is None
        and item.get("provisional_tx_software_tai_upper_ns") is None
        and item.get("txtime_error") is None
    )


def _timestamp_pair_valid(item: Mapping[str, Any], prefix: str, mapping: Mapping[str, Any]) -> bool:
    raw = item[f"{prefix}_realtime_ns"]
    translated = item[f"{prefix}_tai_ns"]
    if (raw is None) != (translated is None):
        return False
    return raw is None or (
        _clock_frame_contains(mapping, clock="realtime", raw_ns=raw)
        and _translated_timestamp_valid(
            mapping,
            clock="realtime",
            raw_ns=raw,
            tai_ns=translated,
        )
    )


def _rust_bool(value: bool) -> str:
    return "true" if value else "false"


def _final_mapping_error_detail(
    item: Mapping[str, Any],
    *,
    enqueue_interval_complete: bool,
    enqueue_clock_consistent: bool,
    timestamp_evidence_complete: bool,
    tx_order_valid: bool,
    physical_window_valid: bool,
    provisional_interval_valid: bool,
    controller_and_trace_finalized: bool,
    structural_and_order_valid: bool,
) -> str:
    """Reproduce the Rust finaliser's generated item diagnostic exactly."""

    values = (
        ("enqueue_complete", enqueue_interval_complete),
        ("enqueue_clock_consistent", enqueue_clock_consistent),
        ("timestamp_complete", timestamp_evidence_complete),
        ("tx_order", tx_order_valid),
        ("physical_window", physical_window_valid),
        ("provisional_interval", provisional_interval_valid),
        ("endpoint_tuple", True),
        ("item_sequence", True),
        ("job_identity", True),
        ("controller_trace_finalized", controller_and_trace_finalized),
        ("structural_order", structural_and_order_valid),
    )
    rendered = ", ".join(f"{name}={_rust_bool(state)}" for name, state in values)
    return f"item {item['item_id']} failed final mapping: {rendered}"


def _runner_item_valid(
    value: Any,
    *,
    mapping: Mapping[str, Any],
    contract: Mapping[str, Any],
    job: Mapping[str, Any],
    expected_item_id: int,
    expected_order_index: int,
    outgoing_tx_tai_upper_ns: int | None,
    socket_setup: Sequence[Mapping[str, Any]],
    strict_success: bool,
) -> bool:
    item_schema_version = mapping["schema_version"]
    item_keys = {
        1: _ITEM_V1_KEYS,
        2: _ITEM_V2_KEYS,
        3: _ITEM_V3_KEYS,
        4: _ITEM_V4_KEYS,
    }.get(item_schema_version)
    if item_keys is None:
        return False
    item = _exact_mapping(value, item_keys)
    if (
        item is None
        or not _schema(item, item_schema_version)
        or (
            item_schema_version in {2, 3, 4}
            and item.get("post_tx_clock_phase") is not None
            and not _clock_phase_valid(item["post_tx_clock_phase"])
        )
        or not all(_u64(item.get(key)) for key in ("item_id", "job_id", "order_index", "event_id"))
        or item.get("item_id") != expected_item_id
        or item.get("job_id") != job["job_id"]
        or item.get("order_index") != expected_order_index
        or not _u64(item.get("endpoint_index"))
        or item.get("endpoint") != item.get("endpoint_index")
        or item["endpoint_index"] >= len(socket_setup)
        or not _sha256(item.get("datagram_sha256"))
        or not _socket_address(item.get("source_address"))
        or not _socket_address(item.get("destination_address"))
        or item["source_address"]
        != socket_setup[item["endpoint_index"]]["local_address"]
        or not _nullable_u64(item.get("socket_timestamp_id"))
        or not _positive_u64(item.get("udp_payload_bytes"))
        or item["udp_payload_bytes"] > KERNEL_TX_MAX_UDP_PAYLOAD_BYTES
        or item.get("target_tai_ns") != job["release_tai_ns"]
        or not all(
            _nullable_u64(item.get(key))
            for key in (
                "scm_txtime_tai_ns",
                "enqueue_monotonic_ns",
                "enqueue_tai_ns",
                "enqueue_tai_lower_ns",
                "enqueue_tai_upper_ns",
                "tx_sched_realtime_ns",
                "tx_sched_tai_ns",
                "tx_sched_tai_lower_ns",
                "tx_sched_tai_upper_ns",
                "tx_software_realtime_ns",
                "provisional_tx_software_tai_lower_ns",
                "provisional_tx_software_tai_upper_ns",
                "tx_software_tai_ns",
                "tx_software_tai_lower_ns",
                "tx_software_tai_upper_ns",
            )
        )
        or not _nullable_string(item.get("terminal_error"))
        or not _nullable_string(item.get("terminal_error_detail"))
        or (item.get("send_attempt") is not None and not _send_attempt_valid(item["send_attempt"], item=item))
        or not _item_enqueue_evidence_valid(item)
        or (
            item.get("txtime_error") is not None
            and not _txtime_error_valid(
                item["txtime_error"], requested_txtime_tai_ns=item.get("scm_txtime_tai_ns")
            )
        )
        or item.get("terminal_outcome") not in _ITEM_OUTCOMES
        or item.get("finalization_state")
        not in {
            "helper-terminal-failure",
            "physical-transmit-proven",
            "controller-and-trace-finalized",
        }
    ):
        return False
    post_tx_phase = item.get("post_tx_clock_phase")
    if item_schema_version in {2, 3, 4} and post_tx_phase is not None and any(
        item.get(key) is None
        for key in (
            "enqueue_monotonic_ns",
            "enqueue_tai_upper_ns",
            "socket_timestamp_id",
            "tx_sched_realtime_ns",
            "tx_software_realtime_ns",
        )
    ):
        return False
    enqueue_fields = (
        item["enqueue_monotonic_ns"],
        item["enqueue_tai_ns"],
        item["enqueue_tai_lower_ns"],
        item["enqueue_tai_upper_ns"],
    )
    enqueue_complete = all(value is not None for value in enqueue_fields)
    enqueue_interval_complete = all(
        value is not None for value in enqueue_fields[2:]
    ) and item["enqueue_tai_lower_ns"] <= item["enqueue_tai_upper_ns"]
    enqueue_clock_consistent = False
    if enqueue_complete:
        enqueue_monotonic, enqueue_mid, enqueue_lower, enqueue_upper = enqueue_fields
        assert all(isinstance(value, int) for value in enqueue_fields)
        if item_schema_version == 2:
            enqueue_clock_consistent = _item_local_enqueue_clock_consistent(
                post_tx_phase,
                enqueue_monotonic_ns=enqueue_monotonic,
                enqueue_tai_lower_ns=enqueue_lower,
                enqueue_tai_upper_ns=enqueue_upper,
            )
        elif item_schema_version in {3, 4}:
            enqueue_clock_consistent = _item_local_enqueue_operation_ordered(
                post_tx_phase,
                enqueue_monotonic_ns=enqueue_monotonic,
                enqueue_tai_lower_ns=enqueue_lower,
                enqueue_tai_upper_ns=enqueue_upper,
            )
        else:
            mapped_lower, mapped_upper = _translated_interval(
                mapping, clock="monotonic", raw_ns=enqueue_monotonic
            )
            enqueue_clock_consistent = bool(
                mapped_lower <= enqueue_upper
                and enqueue_lower <= mapped_upper
                and _clock_frame_contains(
                    mapping, clock="monotonic", raw_ns=enqueue_monotonic
                )
            )
    for prefix in ("tx_sched", "tx_software"):
        raw = item[f"{prefix}_realtime_ns"]
        middle = item[f"{prefix}_tai_ns"]
        lower = item[f"{prefix}_tai_lower_ns"]
        upper = item[f"{prefix}_tai_upper_ns"]
        complete = all(value is not None for value in (raw, middle, lower, upper))
        all_null = all(value is None for value in (raw, middle, lower, upper))
        if not (complete or all_null):
            return False
        if complete:
            assert all(isinstance(value, int) for value in (raw, middle, lower, upper))
            if (
                (lower, upper)
                != _translated_interval(mapping, clock="realtime", raw_ns=raw)
                or middle != _midpoint(lower, upper)
                or not _clock_frame_contains(mapping, clock="realtime", raw_ns=raw)
            ):
                return False
    provisional = (
        item["provisional_tx_software_tai_lower_ns"],
        item["provisional_tx_software_tai_upper_ns"],
    )
    if (provisional[0] is None) != (provisional[1] is None):
        return False
    if item_schema_version in {2, 3, 4} and provisional[0] is not None and post_tx_phase is None:
        return False
    if provisional[0] is not None:
        if (
            provisional[0] > provisional[1]
            or item["tx_software_tai_lower_ns"] is None
        ):
            return False
        if item_schema_version == 1 and (
            item["tx_software_tai_lower_ns"] > provisional[0]
            or item["tx_software_tai_upper_ns"] < provisional[1]
        ):
            return False
        if item_schema_version in {2, 3, 4} and (
            provisional[0] > item["tx_software_tai_lower_ns"]
            or provisional[1] < item["tx_software_tai_upper_ns"]
        ):
            return False
    if expected_order_index == 0:
        if (
            item.get("role") != "exact-outgoing"
            or item.get("send_path") != "etf"
            or item.get("event_id") != 2 * job["tick"]
            or item["udp_payload_bytes"] != KERNEL_TX_MAX_UDP_PAYLOAD_BYTES
            or item.get("scm_txtime_tai_ns") != job["release_tai_ns"] + contract["delta_ns"]
        ):
            return False
    elif (
        item.get("role") != "incoming-credit"
        or item.get("send_path") != "ordered-after-exact"
        or item.get("event_id") != 2 * job["tick"] + 1
        or item.get("scm_txtime_tai_ns") is not None
        or outgoing_tx_tai_upper_ns is None
    ):
        return False
    tx_sched = item["tx_sched_realtime_ns"]
    tx_software = item["tx_software_realtime_ns"]
    tx_order_valid = bool(
        tx_sched is not None
        and tx_software is not None
        and tx_sched <= tx_software
    )
    outcome = item["terminal_outcome"]
    error = item["txtime_error"]
    timestamp_evidence_complete = (
        item["socket_timestamp_id"] is not None
        and tx_sched is not None
        and tx_software is not None
    )
    post_tx_phase_complete = bool(
        item_schema_version == 1 or item.get("post_tx_clock_phase") is not None
    )
    timestamp_evidence_complete = bool(
        timestamp_evidence_complete and post_tx_phase_complete
    )
    within_window = bool(
        item["tx_software_tai_lower_ns"] is not None
        and item["tx_software_tai_lower_ns"] >= job["release_tai_ns"]
        and item["tx_software_tai_upper_ns"] < job["deadline_tai_ns"]
    )
    provisional_interval_complete = bool(
        provisional[0] is not None and item["tx_software_tai_lower_ns"] is not None
    )
    if expected_order_index == 0:
        transport_order_valid = bool(
            enqueue_interval_complete
            and item["enqueue_tai_upper_ns"] < job["release_tai_ns"]
        )
    else:
        transport_order_valid = bool(
            enqueue_interval_complete
            and item["enqueue_tai_lower_ns"] >= outgoing_tx_tai_upper_ns
            and item["enqueue_tai_upper_ns"] < job["deadline_tai_ns"]
            and item["tx_software_tai_lower_ns"] is not None
            and item["tx_software_tai_lower_ns"] >= outgoing_tx_tai_upper_ns
            and item["tx_software_tai_lower_ns"]
            >= item["enqueue_tai_lower_ns"]
        )
    transmission_validation_complete = bool(
        enqueue_interval_complete
        and enqueue_clock_consistent
        and timestamp_evidence_complete
        and tx_order_valid
        and within_window
        and provisional_interval_complete
        and transport_order_valid
    )
    controller_and_trace_finalized = (
        item["finalization_state"] == "controller-and-trace-finalized"
    )
    generated_error_detail = _final_mapping_error_detail(
        item,
        enqueue_interval_complete=enqueue_interval_complete,
        enqueue_clock_consistent=enqueue_clock_consistent,
        timestamp_evidence_complete=timestamp_evidence_complete,
        tx_order_valid=tx_order_valid,
        physical_window_valid=within_window,
        provisional_interval_valid=provisional_interval_complete,
        controller_and_trace_finalized=controller_and_trace_finalized,
        structural_and_order_valid=transport_order_valid,
    )
    if strict_success:
        return bool(
            outcome == "transmitted"
            and item["finalization_state"] == "controller-and-trace-finalized"
            and transmission_validation_complete
            and error is None
            and item["send_attempt"] is None
            and item["terminal_error"] is None
            and item["terminal_error_detail"] is None
        )
    if outcome == "transmitted":
        return bool(
            item["finalization_state"] == "controller-and-trace-finalized"
            and transmission_validation_complete
            and error is None
            and item["send_attempt"] is None
            and item["terminal_error"] is None
            and item["terminal_error_detail"] is None
        )
    if outcome == "txtime-error":
        return bool(
            item["finalization_state"] == "helper-terminal-failure"
            and enqueue_interval_complete
            and item.get("post_tx_clock_phase") is None
            and provisional[0] is None
            and error is not None
            and item["send_attempt"] is None
            and _txtime_failure_matches_item(item)
            and item["terminal_error"] is not None
            and item["terminal_error_detail"] is not None
        )
    if outcome == "timestamp-evidence-missing":
        return bool(
            item["finalization_state"]
            in {"helper-terminal-failure", "physical-transmit-proven"}
            and (not timestamp_evidence_complete or not enqueue_interval_complete)
            and error is None
            and item["terminal_error"] is not None
            and item["terminal_error_detail"] is not None
            and (
                item["terminal_error"]
                != "final_conservative_envelope_validation_failed"
                or item["terminal_error_detail"] == generated_error_detail
            )
        )
    if outcome == "controller-trace-finalization-failed":
        return bool(
            item["finalization_state"] == "physical-transmit-proven"
            and transmission_validation_complete
            and error is None
            and item["terminal_error"] is not None
            and item["terminal_error_detail"] is not None
        )
    return bool(
        item["finalization_state"] == "physical-transmit-proven"
        and timestamp_evidence_complete
        and enqueue_interval_complete
        and item["terminal_error"]
        == "final_conservative_envelope_validation_failed"
        and error is None
        and item["send_attempt"] is None
        and item["terminal_error_detail"] == generated_error_detail
    )


def _runner_job_valid(
    value: Any,
    *,
    mapping: Mapping[str, Any],
    contract: Mapping[str, Any],
    expected_job_id: int,
    expected_first_item_id: int,
    previous_job: Mapping[str, Any] | None,
    socket_setup: Sequence[Mapping[str, Any]],
    max_post_main_datagrams: int,
    strict_success: bool,
) -> tuple[bool, int]:
    job = _exact_mapping(value, _JOB_KEYS)
    if (
        job is None
        or not _schema(job)
        or not _u64(job.get("job_id"))
        or not _u64(job.get("tick"))
        or job.get("job_id") != expected_job_id
        or job.get("tick") != expected_job_id
        or not all(
            _u64(job.get(key))
            for key in (
                "release_monotonic_ns",
                "release_tai_ns",
                "deadline_monotonic_ns",
                "deadline_tai_ns",
            )
        )
        or not _translated_timestamp_valid(
            mapping,
            clock="monotonic",
            raw_ns=job["release_monotonic_ns"],
            tai_ns=job["release_tai_ns"],
        )
        or not _translated_timestamp_valid(
            mapping,
            clock="monotonic",
            raw_ns=job["deadline_monotonic_ns"],
            tai_ns=job["deadline_tai_ns"],
        )
        or not _clock_frame_contains(
            mapping,
            clock="monotonic",
            raw_ns=job["release_monotonic_ns"],
        )
        or (
            not _clock_frame_contains(
                mapping,
                clock="monotonic",
                raw_ns=job["deadline_monotonic_ns"],
            )
            and not (
                not strict_success
                and job.get("terminal_outcome") == "failed"
                and job["deadline_monotonic_ns"]
                > mapping["end"]["monotonic"]["clock_ns"]
            )
        )
        or job["deadline_monotonic_ns"] - job["release_monotonic_ns"]
        != KERNEL_TX_REALIZATION_WINDOW_NS
        or job["deadline_tai_ns"] - job["release_tai_ns"]
        != KERNEL_TX_REALIZATION_WINDOW_NS
        or not isinstance(job.get("items"), Sequence)
        or isinstance(job["items"], (str, bytes))
        or not job["items"]
        or not isinstance(job.get("credit_identities"), list)
        or (
            job.get("prepared_output_failure") is not None
            and not _prepared_output_failure_valid(
                job["prepared_output_failure"],
                job_id=job["job_id"],
                socket_setup=socket_setup,
            )
        )
        or not _nullable_string(job.get("terminal_error"))
        or job.get("terminal_outcome") not in {"complete", "failed"}
    ):
        return False, expected_first_item_id
    if previous_job is not None and (
        job["release_monotonic_ns"] - previous_job["release_monotonic_ns"] != KERNEL_TX_CADENCE_NS
        or job["release_tai_ns"] - previous_job["release_tai_ns"] != KERNEL_TX_CADENCE_NS
    ):
        return False, expected_first_item_id
    outgoing_tx_tai_upper_ns: int | None = None
    item_id = expected_first_item_id
    failed = False
    for order_index, item in enumerate(job["items"]):
        if not _runner_item_valid(
            item,
            mapping=mapping,
            contract=contract,
            job=job,
            expected_item_id=item_id,
            expected_order_index=order_index,
            outgoing_tx_tai_upper_ns=outgoing_tx_tai_upper_ns,
            socket_setup=socket_setup,
            strict_success=strict_success,
        ):
            return False, item_id
        if order_index == 0:
            outgoing_tx_tai_upper_ns = item["tx_software_tai_upper_ns"]
        failed |= item["terminal_outcome"] != "transmitted"
        item_id += 1
    identities: list[Mapping[str, Any]] = []
    seen_identity_keys: set[tuple[Any, ...]] = set()
    for identity_value in job["credit_identities"]:
        identity = _exact_mapping(identity_value, _CREDIT_IDENTITY_KEYS)
        if (
            identity is None
            or not _schema(identity)
            or identity.get("slot") != 2 * job["tick"] + 1
            or not _u64(identity.get("endpoint_index"))
            or identity.get("endpoint") != identity.get("endpoint_index")
            or identity["endpoint"] >= len(socket_setup)
            or not _u64(identity.get("stream_id"))
            or not _u64(identity.get("absolute_limit"))
            or identity.get("identity_kind") not in {"scheduled", "parser-lease"}
            or not _u64(identity.get("identity_detail"))
            or (
                identity["identity_kind"] == "scheduled"
                and identity["identity_detail"] != 0
            )
            or identity.get("resolution")
            not in {
                "pending",
                "coalesced-in-main-finalized",
                "post-main-carrier-physical",
                "post-main-carrier-finalized",
            }
            or not _nullable_u64(identity.get("carrier_item_id"))
        ):
            return False, item_id
        key = (
            identity["slot"],
            identity["endpoint_index"],
            identity["endpoint"],
            identity["stream_id"],
            identity["absolute_limit"],
            identity["identity_kind"],
            identity["identity_detail"],
        )
        if key in seen_identity_keys:
            return False, item_id
        seen_identity_keys.add(key)
        identities.append(identity)
    if identities != sorted(
        identities,
        key=lambda identity: (
            identity["slot"],
            identity["endpoint_index"],
            identity["endpoint"],
            identity["stream_id"],
            identity["absolute_limit"],
            identity["identity_kind"],
            identity["identity_detail"],
        ),
    ):
        return False, item_id
    incoming_items = [item for item in job["items"] if item["role"] == "incoming-credit"]
    close = _exact_mapping(job.get("helper_job_close"), _HELPER_JOB_CLOSE_KEYS)
    abort = job.get("helper_job_abort")
    if abort is not None:
        abort = _exact_mapping(abort, _HELPER_JOB_ABORT_KEYS)
        if (
            abort is None
            or not _schema(abort)
            or abort.get("job_id") != job["job_id"]
            or not _string(abort.get("reason"))
            or not _u64(abort.get("unused_post_main_datagrams"))
            or any(type(abort.get(key)) is not bool for key in ("complete", "aborted", "global_poisoned"))
            or not _u64(abort.get("failed_commands"))
        ):
            return False, item_id
    if strict_success:
        main_endpoint = (
            job["items"][0]["endpoint_index"],
            job["items"][0]["endpoint"],
        )
        for identity in identities:
            if identity["resolution"] == "coalesced-in-main-finalized":
                if (
                    identity["carrier_item_id"] is not None
                    or (identity["endpoint_index"], identity["endpoint"])
                    != main_endpoint
                ):
                    return False, item_id
            elif identity["resolution"] == "post-main-carrier-finalized":
                if not any(
                    item["item_id"] == identity["carrier_item_id"]
                    and item["endpoint_index"] == identity["endpoint_index"]
                    and item["endpoint"] == identity["endpoint"]
                    for item in incoming_items
                ):
                    return False, item_id
            else:
                return False, item_id
        if any(
            not any(identity["carrier_item_id"] == item["item_id"] for identity in identities)
            for item in incoming_items
        ):
            return False, item_id
        if (
            close is None
            or not _schema(close)
            or close.get("job_id") != job["job_id"]
            or close.get("unused_post_main_datagrams")
            != max_post_main_datagrams - len(incoming_items)
            or close.get("complete") is not True
            or abort is not None
            or job["prepared_output_failure"] is not None
            or job["terminal_error"] is not None
            or job["terminal_outcome"] != "complete"
            or failed
        ):
            return False, item_id
    else:
        if close is not None and (
            not _schema(close)
            or close.get("job_id") != job["job_id"]
            or not _u64(close.get("unused_post_main_datagrams"))
            or type(close.get("complete")) is not bool
        ):
            return False, item_id
        if job["terminal_outcome"] == "complete" and (
            failed
            or job["terminal_error"] is not None
            or job["prepared_output_failure"] is not None
        ):
            return False, item_id
    return True, item_id


def _unmapped_runner_item_valid(
    value: Any,
    *,
    job: Mapping[str, Any],
    expected_item_id: int,
    expected_order_index: int,
    socket_setup: Sequence[Mapping[str, Any]],
    runner_schema_version: int,
) -> bool:
    item_keys = {
        1: _ITEM_V1_KEYS,
        2: _ITEM_V2_KEYS,
        3: _ITEM_V3_KEYS,
        4: _ITEM_V4_KEYS,
    }.get(runner_schema_version)
    if item_keys is None:
        return False
    item = _exact_mapping(value, item_keys)
    if (
        item is None
        or not _schema(item, runner_schema_version)
        or (
            runner_schema_version in {2, 3, 4}
            and item.get("post_tx_clock_phase") is not None
            and not _clock_phase_valid(item["post_tx_clock_phase"])
        )
        or not all(_u64(item.get(key)) for key in ("item_id", "job_id", "order_index", "event_id"))
        or item.get("item_id") != expected_item_id
        or item.get("job_id") != job["job_id"]
        or item.get("order_index") != expected_order_index
        or not _u64(item.get("endpoint_index"))
        or item.get("endpoint") != item.get("endpoint_index")
        or item["endpoint_index"] >= len(socket_setup)
        or not _sha256(item.get("datagram_sha256"))
        or not _socket_address(item.get("source_address"))
        or not _socket_address(item.get("destination_address"))
        or item["source_address"]
        != socket_setup[item["endpoint_index"]]["local_address"]
        or not _nullable_u64(item.get("socket_timestamp_id"))
        or not _positive_u64(item.get("udp_payload_bytes"))
        or item["udp_payload_bytes"] > KERNEL_TX_MAX_UDP_PAYLOAD_BYTES
        or item.get("target_tai_ns") != job["release_tai_ns"]
        or not all(
            _nullable_u64(item.get(key))
            for key in (
                "scm_txtime_tai_ns",
                "enqueue_monotonic_ns",
                "enqueue_tai_ns",
                "enqueue_tai_lower_ns",
                "enqueue_tai_upper_ns",
                "tx_sched_realtime_ns",
                "tx_sched_tai_ns",
                "tx_sched_tai_lower_ns",
                "tx_sched_tai_upper_ns",
                "tx_software_realtime_ns",
                "provisional_tx_software_tai_lower_ns",
                "provisional_tx_software_tai_upper_ns",
                "tx_software_tai_ns",
                "tx_software_tai_lower_ns",
                "tx_software_tai_upper_ns",
            )
        )
        or any(
            item[key] is not None
            for key in (
                "tx_sched_tai_ns",
                "tx_sched_tai_lower_ns",
                "tx_sched_tai_upper_ns",
                "tx_software_tai_ns",
                "tx_software_tai_lower_ns",
                "tx_software_tai_upper_ns",
            )
        )
        or not _nullable_string(item.get("terminal_error"))
        or not _nullable_string(item.get("terminal_error_detail"))
        or item.get("terminal_error") is None
        or item.get("terminal_error_detail") is None
        or (
            item.get("send_attempt") is not None
            and not _send_attempt_valid(item["send_attempt"], item=item)
        )
        or not _item_enqueue_evidence_valid(item)
        or (
            item.get("txtime_error") is not None
            and not _txtime_error_valid(
                item["txtime_error"],
                requested_txtime_tai_ns=item.get("scm_txtime_tai_ns"),
            )
        )
        or item.get("finalization_state")
        not in {
            "helper-terminal-failure",
            "physical-transmit-proven",
            "controller-and-trace-finalized",
        }
        or item.get("terminal_outcome")
        not in {
            "txtime-error",
            "timestamp-evidence-missing",
            "controller-trace-finalization-failed",
        }
    ):
        return False
    post_tx_phase = item.get("post_tx_clock_phase")
    enqueue_clock_consistent = False
    if post_tx_phase is not None:
        enqueue_monotonic_ns = item.get("enqueue_monotonic_ns")
        enqueue_tai_lower_ns = item.get("enqueue_tai_lower_ns")
        enqueue_tai_upper_ns = item.get("enqueue_tai_upper_ns")
        socket_timestamp_id = item.get("socket_timestamp_id")
        tx_sched_realtime_ns = item.get("tx_sched_realtime_ns")
        tx_software_realtime_ns = item.get("tx_software_realtime_ns")
        if (
            enqueue_monotonic_ns is None
            or enqueue_tai_lower_ns is None
            or enqueue_tai_upper_ns is None
            or socket_timestamp_id is None
            or tx_sched_realtime_ns is None
            or tx_software_realtime_ns is None
        ):
            return False
        if runner_schema_version == 2:
            enqueue_clock_consistent = _item_local_enqueue_clock_consistent(
                post_tx_phase,
                enqueue_monotonic_ns=enqueue_monotonic_ns,
                enqueue_tai_lower_ns=enqueue_tai_lower_ns,
                enqueue_tai_upper_ns=enqueue_tai_upper_ns,
            )
        elif runner_schema_version in {3, 4}:
            enqueue_clock_consistent = _item_local_enqueue_operation_ordered(
                post_tx_phase,
                enqueue_monotonic_ns=enqueue_monotonic_ns,
                enqueue_tai_lower_ns=enqueue_tai_lower_ns,
                enqueue_tai_upper_ns=enqueue_tai_upper_ns,
            )
    provisional_lower = item["provisional_tx_software_tai_lower_ns"]
    provisional_upper = item["provisional_tx_software_tai_upper_ns"]
    if (provisional_lower is None) != (provisional_upper is None) or (
        provisional_lower is not None and provisional_lower > provisional_upper
    ):
        return False
    if expected_order_index == 0:
        if (
            item.get("role") != "exact-outgoing"
            or item.get("send_path") != "etf"
            or item.get("event_id") != 2 * job["tick"]
            or item["udp_payload_bytes"] != KERNEL_TX_MAX_UDP_PAYLOAD_BYTES
            or item.get("scm_txtime_tai_ns")
            != job["release_tai_ns"]
            + _KERNEL_TX_ETF_DELTA_BY_RUNNER_SCHEMA[runner_schema_version]
        ):
            return False
    elif (
        item.get("role") != "incoming-credit"
        or item.get("send_path") != "ordered-after-exact"
        or item.get("event_id") != 2 * job["tick"] + 1
        or item.get("scm_txtime_tai_ns") is not None
    ):
        return False
    enqueue_interval_complete = bool(
        item["enqueue_tai_lower_ns"] is not None
        and item["enqueue_tai_upper_ns"] is not None
        and item["enqueue_tai_lower_ns"] <= item["enqueue_tai_upper_ns"]
    )
    tx_order_valid = bool(
        item["tx_sched_realtime_ns"] is not None
        and item["tx_software_realtime_ns"] is not None
        and item["tx_sched_realtime_ns"] <= item["tx_software_realtime_ns"]
    )
    structural_and_order_valid = bool(
        expected_order_index == 0
        and item["enqueue_tai_upper_ns"] is not None
        and item["enqueue_tai_upper_ns"] < job["release_tai_ns"]
    )
    if (
        runner_schema_version in {2, 3, 4}
        and item["terminal_error"]
        == "final_conservative_envelope_validation_failed"
        and item["terminal_error_detail"]
        != _final_mapping_error_detail(
            item,
            enqueue_interval_complete=enqueue_interval_complete,
            enqueue_clock_consistent=enqueue_clock_consistent,
            timestamp_evidence_complete=False,
            tx_order_valid=tx_order_valid,
            physical_window_valid=False,
            provisional_interval_valid=False,
            controller_and_trace_finalized=(
                item["finalization_state"] == "controller-and-trace-finalized"
            ),
            structural_and_order_valid=structural_and_order_valid,
        )
    ):
        return False
    outcome = item["terminal_outcome"]
    if outcome == "txtime-error":
        return bool(
            item["finalization_state"] == "helper-terminal-failure"
            and item["enqueue_monotonic_ns"] is not None
            and item["enqueue_tai_lower_ns"] is not None
            and item["enqueue_tai_upper_ns"] is not None
            and item["txtime_error"] is not None
            and item["send_attempt"] is None
            and item.get("post_tx_clock_phase") is None
            and provisional_lower is None
            and _txtime_failure_matches_item(item)
        )
    if outcome == "controller-trace-finalization-failed":
        return bool(
            item["finalization_state"] == "physical-transmit-proven"
            and item["txtime_error"] is None
            and item["send_attempt"] is None
            and (
                runner_schema_version == 1
                or item.get("post_tx_clock_phase") is not None
            )
            and provisional_lower is not None
        )
    return item["txtime_error"] is None


def _schema_two_mapping_failure_matches_evidence(
    *,
    clock_start: Mapping[str, Any],
    clock_end: Mapping[str, Any] | None,
    defense_start_monotonic_ns: int | None,
    jobs: Sequence[Mapping[str, Any]],
    error: str,
) -> bool:
    """Replay the producer's fail-fast mapping builder without translating.

    The Instant anchor exists only inside a successful mapping receipt.  Its
    one otherwise-unobservable failure is therefore accepted solely under the
    producer's exact chronology error string.  Every failure derivable from
    retained clock and item evidence is bound to its exact first failing
    predicate and, where present, item identity or measured value.
    """

    phase_items = [
        item
        for job in jobs
        for item in job["items"]
        if item.get("post_tx_clock_phase") is not None
    ]
    previous_online_phase = clock_start
    for index, item in enumerate(phase_items):
        phase = item["post_tx_clock_phase"]
        item_id = item["item_id"]
        if not _clock_phases_strictly_ordered(previous_online_phase, phase):
            return bool(
                index == len(phase_items) - 1
                and error
                == f"BuFLO kernel item {item_id} retained an out-of-order post-TX clock phase"
            )
        if (
            item["tx_software_realtime_ns"] > phase["realtime"]["clock_ns"]
            or item["enqueue_monotonic_ns"] > phase["monotonic"]["clock_ns"]
            or item["enqueue_tai_upper_ns"] > phase["monotonic"]["tai_before_ns"]
        ):
            return bool(
                index == len(phase_items) - 1
                and error
                == f"BuFLO kernel item {item_id} clock phase preceded its retained transmission evidence"
            )
        previous_online_phase = phase

    if clock_end is None:
        prefix = "BuFLO final clock sample failed: "
        return error.startswith(prefix) and bool(error.removeprefix(prefix).strip())
    if defense_start_monotonic_ns is None:
        return not jobs and error == "BuFLO kernel epoch was never armed"
    if not _clock_phases_strictly_ordered(clock_start, clock_end):
        return (
            error
            == "BuFLO kernel clock phases and Instant anchor were not temporally ordered"
        )
    # The anchor bracket itself is not repeated outside a successful mapping.
    # With otherwise ordered phases this exact error is the only observable
    # representation of an out-of-range anchor.
    if error == "BuFLO kernel clock phases and Instant anchor were not temporally ordered":
        return True

    realtime_intersection = _offset_intersection(
        [
            _sample_offset_bounds(clock_start["realtime"]),
            _sample_offset_bounds(clock_end["realtime"]),
        ]
    )
    if realtime_intersection is None:
        return error == "BuFLO kernel start/end realtime offset intersection was empty"

    max_width = max(
        phase[clock]["bracket_width_ns"]
        for phase in (clock_start, clock_end)
        for clock in ("monotonic", "realtime")
    )
    previous_phase = clock_start
    for item in (item for job in jobs for item in job["items"]):
        phase = item.get("post_tx_clock_phase")
        if phase is None:
            continue
        item_id = item["item_id"]
        if not _clock_phases_strictly_ordered(
            previous_phase, phase
        ) or not _clock_phases_strictly_ordered(phase, clock_end):
            return error == (
                f"BuFLO kernel item {item_id} retained an out-of-order post-TX clock phase"
            )
        if (
            item["tx_software_realtime_ns"] > phase["realtime"]["clock_ns"]
            or item["enqueue_monotonic_ns"] > phase["monotonic"]["clock_ns"]
            or item["enqueue_tai_upper_ns"] > phase["monotonic"]["tai_before_ns"]
        ):
            return error == (
                f"BuFLO kernel item {item_id} clock phase preceded its retained transmission evidence"
            )
        phase_realtime_bounds = _sample_offset_bounds(phase["realtime"])
        realtime_intersection = _offset_intersection(
            [realtime_intersection, phase_realtime_bounds]
        )
        if realtime_intersection is None:
            return error == (
                f"BuFLO kernel realtime offset intersection became empty at item {item_id}"
            )
        max_width = max(
            max_width,
            phase["monotonic"]["bracket_width_ns"],
            phase["realtime"]["bracket_width_ns"],
        )
        previous_phase = phase
    if max_width > KERNEL_TX_MAX_CLOCK_BRACKET_NS:
        return error == (
            f"BuFLO kernel clock bracket {max_width} ns exceeded 250000 ns"
        )
    return False


def _unmapped_runner_jobs_valid(
    jobs: Sequence[Mapping[str, Any]],
    *,
    defense_start_monotonic_ns: int | None,
    defense_start_tai_ns: int | None,
    clock_start: Mapping[str, Any],
    clock_end: Mapping[str, Any] | None,
    clock_mapping_error: str,
    socket_setup: Sequence[Mapping[str, Any]],
    runner_schema_version: int,
) -> bool:
    if jobs and (defense_start_monotonic_ns is None or defense_start_tai_ns is None):
        return False
    expected_item_id = 0
    for expected_job_id, value in enumerate(jobs):
        job = _exact_mapping(value, _JOB_KEYS)
        if (
            job is None
            or not _schema(job)
            or job.get("job_id") != expected_job_id
            or job.get("tick") != expected_job_id
            or not all(
                _u64(job.get(key))
                for key in (
                    "release_monotonic_ns",
                    "release_tai_ns",
                    "deadline_monotonic_ns",
                    "deadline_tai_ns",
                )
            )
            or job["deadline_monotonic_ns"] - job["release_monotonic_ns"]
            != KERNEL_TX_REALIZATION_WINDOW_NS
            or job["deadline_tai_ns"] - job["release_tai_ns"]
            != KERNEL_TX_REALIZATION_WINDOW_NS
            or job["release_monotonic_ns"]
            != defense_start_monotonic_ns + expected_job_id * KERNEL_TX_CADENCE_NS
            or job["release_tai_ns"]
            != defense_start_tai_ns + expected_job_id * KERNEL_TX_CADENCE_NS
            or not isinstance(job.get("items"), list)
            or any(not isinstance(item, Mapping) for item in job["items"])
            or not isinstance(job.get("credit_identities"), list)
            or (
                job.get("prepared_output_failure") is not None
                and not _prepared_output_failure_valid(
                    job["prepared_output_failure"],
                    job_id=job["job_id"],
                    socket_setup=socket_setup,
                )
            )
            or not _string(job.get("terminal_error"))
            or job.get("terminal_outcome") != "failed"
        ):
            return False
        for order_index, item in enumerate(job["items"]):
            if not _unmapped_runner_item_valid(
                item,
                job=job,
                expected_item_id=expected_item_id,
                expected_order_index=order_index,
                socket_setup=socket_setup,
                runner_schema_version=runner_schema_version,
            ):
                return False
            expected_item_id += 1
        seen_identities: set[tuple[Any, ...]] = set()
        for value in job["credit_identities"]:
            identity = _exact_mapping(value, _CREDIT_IDENTITY_KEYS)
            if (
                identity is None
                or not _schema(identity)
                or identity.get("slot") != 2 * job["tick"] + 1
                or not _u64(identity.get("endpoint_index"))
                or identity.get("endpoint") != identity.get("endpoint_index")
                or identity["endpoint"] >= len(socket_setup)
                or not _u64(identity.get("stream_id"))
                or not _u64(identity.get("absolute_limit"))
                or identity.get("identity_kind") not in {"scheduled", "parser-lease"}
                or not _u64(identity.get("identity_detail"))
                or (
                    identity["identity_kind"] == "scheduled"
                    and identity["identity_detail"] != 0
                )
                or identity.get("resolution")
                not in {
                    "pending",
                    "coalesced-in-main-finalized",
                    "post-main-carrier-physical",
                    "post-main-carrier-finalized",
                }
                or not _nullable_u64(identity.get("carrier_item_id"))
            ):
                return False
            key = tuple(identity[name] for name in _CREDIT_IDENTITY_KEYS - {"schema_version"})
            if key in seen_identities:
                return False
            seen_identities.add(key)
        close = job.get("helper_job_close")
        if close is not None:
            close = _exact_mapping(close, _HELPER_JOB_CLOSE_KEYS)
            if (
                close is None
                or not _schema(close)
                or close.get("job_id") != job["job_id"]
                or not _u64(close.get("unused_post_main_datagrams"))
                or type(close.get("complete")) is not bool
            ):
                return False
        abort = job.get("helper_job_abort")
        if abort is not None:
            abort = _exact_mapping(abort, _HELPER_JOB_ABORT_KEYS)
            if (
                abort is None
                or not _schema(abort)
                or abort.get("job_id") != job["job_id"]
                or not _string(abort.get("reason"))
                or not _u64(abort.get("unused_post_main_datagrams"))
                or any(
                    type(abort.get(key)) is not bool
                    for key in ("complete", "aborted", "global_poisoned")
                )
                or not _u64(abort.get("failed_commands"))
            ):
                return False
    return bool(
        runner_schema_version == 1
        or _schema_two_mapping_failure_matches_evidence(
            clock_start=clock_start,
            clock_end=clock_end,
            defense_start_monotonic_ns=defense_start_monotonic_ns,
            jobs=jobs,
            error=clock_mapping_error,
        )
    )


def _runner_aggregate(value: Any, jobs: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    aggregate = _exact_mapping(value, _RUNNER_AGGREGATE_KEYS)
    if (
        aggregate is None
        or not _schema(aggregate)
        or any(
            not _u64(aggregate.get(key))
            for key in _RUNNER_AGGREGATE_KEYS - {"schema_version", "terminal_outcome"}
        )
    ):
        return None
    items = [item for job in jobs for item in job["items"]]
    outcomes = [item["terminal_outcome"] for item in items]
    tx_lateness = [
        max(0, item["tx_software_tai_upper_ns"] - item["target_tai_ns"])
        for item in items
        if item["tx_software_tai_upper_ns"] is not None
    ]
    identities = [identity for job in jobs for identity in job["credit_identities"]]
    expected = {
        "schema_version": 1,
        "job_count": len(jobs),
        "item_count": len(items),
        "etf_item_count": sum(item["send_path"] == "etf" for item in items),
        "ordered_item_count": sum(item["send_path"] == "ordered-after-exact" for item in items),
        "captured_credit_identity_count": len(identities),
        "prepared_output_failure_count": sum(
            job["prepared_output_failure"] is not None for job in jobs
        ),
        "main_coalesced_credit_identity_count": sum(
            identity["resolution"] == "coalesced-in-main-finalized"
            for identity in identities
        ),
        "carrier_credit_identity_count": sum(
            identity["resolution"] == "post-main-carrier-finalized"
            for identity in identities
        ),
        "unresolved_credit_identity_count": sum(
            identity["resolution"]
            not in {"coalesced-in-main-finalized", "post-main-carrier-finalized"}
            for identity in identities
        ),
        "transmitted_item_count": outcomes.count("transmitted"),
        "failed_item_count": sum(outcome != "transmitted" for outcome in outcomes),
        "tx_sched_timestamp_count": sum(item["tx_sched_tai_ns"] is not None for item in items),
        "tx_software_timestamp_count": sum(
            item["tx_software_tai_ns"] is not None for item in items
        ),
        "txtime_error_count": outcomes.count("txtime-error"),
        "timestamp_evidence_missing_count": outcomes.count("timestamp-evidence-missing"),
        "window_violation_count": outcomes.count("window-violation"),
        "unresolved_item_count": 0,
        "max_tx_software_lateness_ns": max(tx_lateness, default=0),
        "terminal_outcome": (
            "complete"
            if jobs
            and all(outcome == "transmitted" for outcome in outcomes)
            and all(job["terminal_outcome"] == "complete" for job in jobs)
            else "failed"
        ),
    }
    return dict(aggregate) if dict(aggregate) == expected else None


def kernel_tx_runner_receipt_valid(value: Any) -> bool:
    """Validate Rust-observable kernel timing evidence without capture claims."""

    receipt = _exact_mapping(value, _RUNNER_RECEIPT_KEYS)
    receipt_schema_version = (
        receipt.get("schema_version") if receipt is not None else None
    )
    expected_semantics = {
        KERNEL_TX_HISTORICAL_RUNNER_SCHEMA_VERSION: (
            KERNEL_TX_HISTORICAL_RUNNER_SEMANTICS
        ),
        2: KERNEL_TX_RUNNER_V2_SEMANTICS,
        KERNEL_TX_RUNNER_V3_SCHEMA_VERSION: KERNEL_TX_RUNNER_V3_SEMANTICS,
        KERNEL_TX_RUNNER_SCHEMA_VERSION: KERNEL_TX_RUNNER_SEMANTICS,
    }.get(receipt_schema_version)
    if (
        receipt is None
        or expected_semantics is None
        or receipt.get("semantics") != expected_semantics
        or not _qdisc_contract_valid(
            receipt.get("qdisc_contract"),
            runner_schema_version=receipt_schema_version,
        )
        or receipt.get("terminal_outcome") not in {"complete", "failed"}
        or not _nullable_string(receipt.get("primary_error"))
        or not isinstance(receipt.get("cleanup_errors"), list)
        or not all(_string(item) for item in receipt["cleanup_errors"])
        or not isinstance(receipt.get("terminal_errors"), list)
        or not all(_string(item) for item in receipt["terminal_errors"])
        or not _nullable_u64(receipt.get("defense_start_monotonic_ns"))
        or not _nullable_u64(receipt.get("defense_start_tai_ns"))
        or (receipt["defense_start_monotonic_ns"] is None)
        != (receipt["defense_start_tai_ns"] is None)
        or not _clock_phase_valid(receipt.get("clock_start"))
        or (
            receipt.get("clock_end") is not None
            and not _clock_phase_valid(receipt["clock_end"])
        )
        or type(receipt.get("clock_mapping_valid")) is not bool
        or not _nullable_string(receipt.get("clock_mapping_error"))
        or (
            receipt.get("clock_mapping") is not None
            and not _clock_mapping_valid(receipt["clock_mapping"])
        )
        or not isinstance(receipt.get("jobs"), list)
    ):
        return False
    success = receipt["terminal_outcome"] == "complete"
    mapping = receipt["clock_mapping"]
    clock_start = receipt["clock_start"]
    clock_end = receipt["clock_end"]
    assert isinstance(clock_start, Mapping)
    if clock_end is not None:
        assert isinstance(clock_end, Mapping)
        if receipt_schema_version == 1:
            chronological = _clock_phases_chronological(clock_start, clock_end)
        else:
            chronological = _clock_phases_strictly_ordered(clock_start, clock_end)
        start_end_mapping_failure = bool(
            receipt.get("clock_mapping") is None
            and receipt.get("clock_mapping_error")
            == "BuFLO kernel clock phases and Instant anchor were not temporally ordered"
        )
        if not chronological and not start_end_mapping_failure:
            return False
    if mapping is None:
        if receipt["clock_mapping_valid"] or receipt["clock_mapping_error"] is None:
            return False
    elif (
        receipt["clock_mapping_valid"] is not True
        or receipt["clock_mapping_error"] is not None
        or clock_end is None
        or mapping["schema_version"] != receipt_schema_version
        or mapping["start"] != clock_start
        or mapping["end"] != clock_end
    ):
        return False
    if success and (
        mapping is None
        or clock_end is None
        or receipt["defense_start_monotonic_ns"] is None
        or receipt["defense_start_tai_ns"] is None
        or receipt["primary_error"] is not None
        or receipt["cleanup_errors"]
        or receipt["terminal_errors"]
    ):
        return False
    if mapping is None:
        jobs = receipt["jobs"]
        runtime = receipt.get("runtime_contract")
        if not _runtime_contract_valid(runtime, success=False, jobs=jobs):
            return False
        assert isinstance(runtime, Mapping)
        return bool(
            not success
            and receipt["clock_mapping_error"] in receipt["cleanup_errors"]
            and _unmapped_runner_jobs_valid(
                jobs,
                defense_start_monotonic_ns=receipt["defense_start_monotonic_ns"],
                defense_start_tai_ns=receipt["defense_start_tai_ns"],
                clock_start=clock_start,
                clock_end=clock_end,
                clock_mapping_error=receipt["clock_mapping_error"],
                socket_setup=runtime["socket_setup"],
                runner_schema_version=receipt_schema_version,
            )
            and _runner_aggregate(receipt.get("aggregate"), jobs) is not None
        )
    if receipt["defense_start_monotonic_ns"] is None or receipt["defense_start_tai_ns"] is None:
        return False
    if (
        not _translated_timestamp_valid(
            mapping,
            clock="monotonic",
            raw_ns=receipt["defense_start_monotonic_ns"],
            tai_ns=receipt["defense_start_tai_ns"],
        )
        or not _clock_frame_contains(
            mapping,
            clock="monotonic",
            raw_ns=receipt["defense_start_monotonic_ns"],
        )
    ):
        return False
    contract = receipt["qdisc_contract"]
    jobs = receipt["jobs"]
    runtime = receipt.get("runtime_contract")
    if not _runtime_contract_valid(runtime, success=success, jobs=jobs):
        return False
    socket_setup = runtime["socket_setup"]
    priority_methods = {setup["priority_method"] for setup in socket_setup}
    scm_supported = {setup["scm_priority_supported"] for setup in socket_setup}
    if (
        priority_methods != {contract["priority_method"]}
        or scm_supported != {contract["scm_priority_supported"]}
        or contract["single_threaded_sender_control_flow_enforced"]
        != runtime["single_threaded_sender_control_flow_enforced"]
    ):
        return False
    next_item_id = 0
    previous: Mapping[str, Any] | None = None
    for job_id, job in enumerate(jobs):
        valid, next_item_id = _runner_job_valid(
            job,
            mapping=mapping,
            contract=contract,
            expected_job_id=job_id,
            expected_first_item_id=next_item_id,
            previous_job=previous,
            socket_setup=socket_setup,
            max_post_main_datagrams=runtime["max_post_main_datagrams"],
            strict_success=success,
        )
        if not valid:
            return False
        previous = job
    if not _clock_mapping_matches_items(mapping, jobs):
        return False
    if jobs and (
        jobs[0]["release_monotonic_ns"] != receipt["defense_start_monotonic_ns"]
        or jobs[0]["release_tai_ns"] != receipt["defense_start_tai_ns"]
    ):
        return False
    aggregate = _runner_aggregate(receipt.get("aggregate"), jobs)
    return bool(
        aggregate is not None
        and aggregate["terminal_outcome"] == receipt["terminal_outcome"]
        and (
            not success
            or aggregate["job_count"] > 0
            and aggregate["failed_item_count"] == 0
            and aggregate["prepared_output_failure_count"] == 0
            and aggregate["unresolved_credit_identity_count"] == 0
        )
    )


def kernel_tx_runner_receipt_success_valid(value: Any) -> bool:
    """Require a valid, non-empty raw receipt with no typed terminal failure."""

    return bool(
        kernel_tx_runner_receipt_valid(value)
        and value["aggregate"]["job_count"] > 0
        and value["aggregate"]["unresolved_item_count"] == 0
        and value["aggregate"]["unresolved_credit_identity_count"] == 0
        and value["aggregate"]["prepared_output_failure_count"] == 0
        and value["aggregate"]["failed_item_count"] == 0
        and value["aggregate"]["terminal_outcome"] == "complete"
    )


def _qdisc_snapshot_valid(value: Any) -> bool:
    snapshot = _exact_mapping(value, _QDISC_SNAPSHOT_KEYS)
    return bool(snapshot is not None and all(_u64(snapshot.get(key)) for key in snapshot))


def _qdisc_evidence_valid(value: Any, *, runner: Mapping[str, Any]) -> bool:
    evidence = _exact_mapping(value, _QDISC_EVIDENCE_KEYS)
    if (
        evidence is None
        or not _schema(evidence)
        or evidence.get("source") != "tc-json-v1"
        or evidence.get("observed_contract") != runner["qdisc_contract"]
        or evidence.get("installed_before_runner") is not True
        or evidence.get("verified_after_runner") is not True
        or evidence.get("restored_after_capture") is not True
        or not _qdisc_snapshot_valid(evidence.get("before"))
        or not _qdisc_snapshot_valid(evidence.get("after"))
    ):
        return False
    before = evidence["before"]
    after = evidence["after"]
    counters = ("packets", "bytes", "drops", "overlimits", "requeues")
    return bool(
        all(after[key] >= before[key] for key in counters)
        and before["backlog_bytes"] == before["backlog_packets"] == before["qlen"] == 0
        and after["backlog_bytes"] == after["backlog_packets"] == after["qlen"] == 0
    )


def _router_offloads_disabled(value: Any, interface: str) -> bool:
    if (
        not isinstance(value, list)
        or len(value) != 1
        or not isinstance(value[0], Mapping)
        or value[0].get("ifname") != interface
    ):
        return False
    for feature in (
        "generic-receive-offload",
        "generic-segmentation-offload",
        "tcp-segmentation-offload",
        "tx-udp-segmentation",
    ):
        state = value[0].get(feature)
        if not isinstance(state, Mapping) or state.get("active") is not False:
            return False
    return True


def _router_interface_ipv4(value: Any, interface: str) -> str | None:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping):
        return None
    row = value[0]
    flags = row.get("flags")
    addresses = row.get("addr_info")
    if (
        row.get("ifname") != interface
        or row.get("mtu") != 1_500
        or not isinstance(flags, list)
        or not all(isinstance(flag, str) for flag in flags)
        or not {"UP", "LOWER_UP"} <= set(flags)
        or not isinstance(addresses, list)
    ):
        return None
    ipv4 = [
        address
        for address in addresses
        if isinstance(address, Mapping) and address.get("family") == "inet"
    ]
    if len(ipv4) != 1:
        return None
    try:
        parsed = ipaddress.ip_interface(f"{ipv4[0].get('local')}/{ipv4[0].get('prefixlen')}")
    except ValueError:
        return None
    return str(parsed.ip) if parsed.version == 4 else None


def _router_state_valid(value: Any, *, phase: str) -> bool:
    state = _exact_mapping(value, _ROUTER_STATE_KEYS)
    if state is None or not _schema(state):
        return False
    topology_kind = state.get("topology_kind")
    client_interface = state.get("client_interface")
    uplink_interface = state.get("uplink_interface")
    interfaces = state.get("interfaces")
    qdiscs = state.get("qdiscs")
    offloads = state.get("offloads")
    invariants = _exact_mapping(state.get("invariants"), _ROUTER_INVARIANT_KEYS)
    expected_active = phase == "capturing"
    if (
        phase not in {"capturing", "idle"}
        or topology_kind not in {"shared-two-network-router", "routed-public-egress"}
        or state.get("capture_process_state") != phase
        or state.get("capture_process_active") is not expected_active
        or not _string(client_interface)
        or not _string(uplink_interface)
        or client_interface == uplink_interface
        or state.get("ipv4_forwarding") != 1
        or not isinstance(interfaces, Mapping)
        or set(interfaces) != {client_interface, uplink_interface}
        or any(
            _router_interface_ipv4(rows, interface) is None
            for interface, rows in interfaces.items()
        )
        or not isinstance(state.get("routes"), list)
        or not isinstance(qdiscs, Mapping)
        or set(qdiscs) != {client_interface, uplink_interface}
        or not all(isinstance(rows, list) and rows for rows in qdiscs.values())
        or not isinstance(offloads, Mapping)
        or set(offloads) != {client_interface, uplink_interface}
        or not all(
            _router_offloads_disabled(rows, interface)
            for interface, rows in offloads.items()
        )
        or not isinstance(state.get("nat_rules"), list)
        or not all(_string(rule) and not rule.startswith("#") for rule in state["nat_rules"])
        or invariants is None
        or any(type(invariants.get(key)) is not bool for key in _ROUTER_INVARIANT_KEYS)
        or invariants["client_interface_present"] is not True
        or invariants["uplink_interface_present"] is not True
        or invariants["ipv4_forwarding_enabled"] is not True
    ):
        return False
    client_subnet = state.get("client_subnet")
    if client_subnet is not None:
        try:
            parsed_subnet = ipaddress.ip_network(client_subnet, strict=True)
        except (TypeError, ValueError):
            return False
        if parsed_subnet.version != 4 or str(parsed_subnet) != client_subnet:
            return False
    if topology_kind == "routed-public-egress":
        expected_nat_rule = (
            f"-A POSTROUTING -s {client_subnet} -o {uplink_interface} -j MASQUERADE"
        )
        default_routes = [
            route
            for route in state["routes"]
            if isinstance(route, Mapping) and route.get("dst") == "default"
        ]
        return bool(
            client_subnet is not None
            and ipaddress.ip_address(
                _router_interface_ipv4(interfaces[client_interface], client_interface)
            )
            in parsed_subnet
            and len(default_routes) == 1
            and default_routes[0].get("dev") == uplink_interface
            and expected_nat_rule in state["nat_rules"]
            and not any(
                isinstance(qdisc, Mapping) and qdisc.get("kind") == "netem"
                for rows in qdiscs.values()
                for qdisc in rows
            )
            and invariants["uplink_default_route_present"] is True
            and invariants["source_masquerade_required"] is True
            and invariants["source_masquerade_present"] is True
        )
    return bool(invariants["source_masquerade_required"] is False)


def _router_state_pair_valid(start_value: Any, end_value: Any) -> bool:
    if not _router_state_valid(start_value, phase="capturing") or not _router_state_valid(
        end_value, phase="idle"
    ):
        return False
    start = start_value
    end = end_value
    stable_keys = {
        "topology_kind",
        "client_interface",
        "uplink_interface",
        "client_subnet",
        "ipv4_forwarding",
        "interfaces",
        "routes",
        "nat_rules",
        "offloads",
        "invariants",
    }
    if any(start[key] != end[key] for key in stable_keys):
        return False
    for interface in (start["client_interface"], start["uplink_interface"]):
        start_identity = [
            (row.get("kind"), row.get("handle"), row.get("parent"))
            for row in start["qdiscs"][interface]
            if isinstance(row, Mapping)
        ]
        end_identity = [
            (row.get("kind"), row.get("handle"), row.get("parent"))
            for row in end["qdiscs"][interface]
            if isinstance(row, Mapping)
        ]
        if not start_identity or start_identity != end_identity:
            return False
    return True


def _capture_evidence_valid(value: Any) -> bool:
    capture = _exact_mapping(value, _CAPTURE_EVIDENCE_KEYS)
    return bool(
        capture is not None
        and _schema(capture, 2)
        and capture.get("artifact_type") == "qcsd-kernel-tx-router-capture"
        and _sha256(capture.get("capture_id"))
        and capture.get("observer_role") == "router-ingress-post-client-veth-pre-netem"
        and capture.get("interface") == "eth0"
        and _sha256(capture.get("pcapng_sha256"))
        and capture.get("timestamp_clock_id") == "CLOCK_REALTIME"
        and capture.get("timestamp_type") == "host"
        and all(
            _u64(capture.get(key))
            for key in (
                "capture_start_realtime_ns",
                "capture_end_realtime_ns",
                "packets_received",
                "packets_dropped",
                "interface_packets_dropped",
                "dumpcap_received_packets",
            )
        )
        and capture.get("dumpcap_returncode") in {0, 2}
        and capture.get("capture_active_at_stop") is True
        and _router_state_pair_valid(
            capture.get("router_state_start"), capture.get("router_state_end")
        )
        and capture.get("capture_service_end_state") == "idle-no-dumpcap-child"
        and capture["capture_start_realtime_ns"] <= capture["capture_end_realtime_ns"]
        and capture["packets_received"] <= capture["dumpcap_received_packets"]
    )


def _controlled_topology_valid(
    network_value: Any,
    binding_value: Any,
    expected_network_sha256: Any,
) -> bool:
    if (
        not isinstance(network_value, Mapping)
        or not isinstance(binding_value, Mapping)
        or not isinstance(network_value.get("image_digest"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", network_value["image_digest"])
        is None
        or not _sha256(expected_network_sha256)
        or kernel_tx_receipt_sha256(network_value) != expected_network_sha256
    ):
        return False
    if network_value.get("artifact_type") == "qcsd-kernel-tx-public-network-v1":
        return _public_topology_valid(network_value, binding_value)
    network_keys = {
        "schema_version",
        "artifact_type",
        "image_digest",
        "topology",
        "capture_point",
        "client",
        "router",
        "servers",
        "directional_coverage",
        "rate_aggregation",
        "observation_contract",
    }
    binding_keys = {
        "schema_version",
        "artifact_type",
        "topology_kind",
        "image_digest",
        "observer",
        "client_network",
        "server_network",
        "observed_direction",
        "capture_position",
    }
    topology = network_value.get("topology")
    capture = network_value.get("capture_point")
    router = network_value.get("router")
    directional = network_value.get("directional_coverage")
    observer = binding_value.get("observer")
    client_network = binding_value.get("client_network")
    server_network = binding_value.get("server_network")
    topology_client_network = (
        topology.get("client_network") if isinstance(topology, Mapping) else None
    )
    topology_server_network = (
        topology.get("server_network") if isinstance(topology, Mapping) else None
    )
    return bool(
        set(network_value) == network_keys
        and network_value.get("schema_version") == 2
        and network_value.get("artifact_type") == "qcsd-buflo-controlled-network-v2"
        and set(binding_value) == binding_keys
        and binding_value.get("schema_version") == 1
        and binding_value.get("artifact_type")
        == "qcsd-kernel-tx-controlled-observer-binding"
        and binding_value.get("image_digest") == network_value.get("image_digest")
        and binding_value.get("topology_kind") == "shared-two-network-router"
        and binding_value.get("observed_direction") == "client-to-server"
        and binding_value.get("capture_position")
        == "router-eth0-ingress-after-client-veth-before-ifb0-ingress-netem"
        and isinstance(topology, Mapping)
        and topology.get("kind") == "shared-two-network-router"
        and isinstance(topology_client_network, Mapping)
        and isinstance(topology_server_network, Mapping)
        and isinstance(capture, Mapping)
        and capture.get("client_to_server_position")
        == "before-router-eth0-ingress-ifb0-netem"
        and isinstance(router, Mapping)
        and isinstance(directional, Mapping)
        and isinstance(directional.get("client_to_server"), Mapping)
        and directional["client_to_server"].get("shaping_site")
        == "router:eth0-ingress-redirect-ifb0-root"
        and directional["client_to_server"].get("capture_position") == "before-impairment"
        and isinstance(observer, Mapping)
        and observer.get("role") == "router-ingress-post-client-veth-pre-netem"
        and observer.get("container_name") == router.get("container")
        and observer.get("interface") == "eth0"
        and observer.get("interface_direction") == "ingress"
        and observer.get("ipv4") == router.get("client_ipv4")
        and isinstance(client_network, Mapping)
        and client_network.get("name") == topology_client_network.get("name")
        and isinstance(server_network, Mapping)
        and server_network.get("name") == topology_server_network.get("name")
    )


def _public_topology_valid(
    network_value: Mapping[str, Any], binding_value: Mapping[str, Any]
) -> bool:
    network_keys = {
        "schema_version",
        "artifact_type",
        "image_digest",
        "topology",
        "capture_point",
        "client",
        "router",
        "directional_coverage",
        "observation_contract",
    }
    binding_keys = {
        "schema_version",
        "artifact_type",
        "topology_kind",
        "image_digest",
        "observer",
        "client_network",
        "uplink_network",
        "observed_direction",
        "capture_position",
    }
    topology = network_value.get("topology")
    capture = network_value.get("capture_point")
    client = network_value.get("client")
    router = network_value.get("router")
    directional = network_value.get("directional_coverage")
    observer = binding_value.get("observer")
    client_network = binding_value.get("client_network")
    uplink_network = binding_value.get("uplink_network")
    topology_client = topology.get("client_network") if isinstance(topology, Mapping) else None
    topology_uplink = topology.get("uplink_network") if isinstance(topology, Mapping) else None
    docker_ids = (
        observer.get("container_id") if isinstance(observer, Mapping) else None,
        client_network.get("id") if isinstance(client_network, Mapping) else None,
        client_network.get("router_endpoint_id")
        if isinstance(client_network, Mapping)
        else None,
        uplink_network.get("id") if isinstance(uplink_network, Mapping) else None,
        uplink_network.get("router_endpoint_id")
        if isinstance(uplink_network, Mapping)
        else None,
    )
    try:
        client_subnet = ipaddress.ip_network(
            topology_client.get("subnet") if isinstance(topology_client, Mapping) else None,
            strict=True,
        )
        observer_ip = ipaddress.ip_address(
            observer.get("ipv4") if isinstance(observer, Mapping) else None
        )
    except (TypeError, ValueError):
        return False
    return bool(
        set(network_value) == network_keys
        and network_value.get("schema_version") == 1
        and set(binding_value) == binding_keys
        and binding_value.get("schema_version") == 1
        and binding_value.get("artifact_type") == "qcsd-kernel-tx-public-observer-binding"
        and binding_value.get("image_digest") == network_value.get("image_digest")
        and binding_value.get("topology_kind") == "routed-public-egress"
        and binding_value.get("observed_direction") == "client-to-public-origin"
        and binding_value.get("capture_position")
        == "router-eth0-ingress-after-client-veth-before-forwarding-and-masquerade"
        and isinstance(topology, Mapping)
        and set(topology)
        == {"kind", "client_network", "uplink_network", "router_interfaces"}
        and topology.get("kind") == "routed-public-egress"
        and isinstance(topology_client, Mapping)
        and set(topology_client) == {"name", "subnet"}
        and client_subnet.version == 4
        and str(client_subnet) == topology_client.get("subnet")
        and isinstance(topology_uplink, Mapping)
        and set(topology_uplink) == {"name"}
        and topology.get("router_interfaces") == {"client": "eth0", "uplink": "eth1"}
        and isinstance(capture, Mapping)
        and capture == {
            "client_to_server_position": "before-router-eth0-forwarding-and-masquerade"
        }
        and isinstance(client, Mapping)
        and set(client) == {"network", "default_route_via"}
        and client.get("network") == topology_client.get("name")
        and isinstance(router, Mapping)
        and set(router)
        == {
            "container",
            "client_ipv4",
            "client_interface",
            "uplink_interface",
            "ipv4_forwarding",
            "source_masquerade",
        }
        and router.get("client_interface") == "eth0"
        and router.get("uplink_interface") == "eth1"
        and router.get("ipv4_forwarding") is True
        and router.get("source_masquerade") is True
        and str(observer_ip) == router.get("client_ipv4") == client.get("default_route_via")
        and observer_ip in client_subnet
        and isinstance(directional, Mapping)
        and directional
        == {
            "client_to_server": {
                "capture_position": "before-forwarding",
                "nat_position": "after-capture",
            }
        }
        and network_value.get("observation_contract")
        == {"client_only": True, "ordinary_public_origins": True}
        and isinstance(observer, Mapping)
        and set(observer)
        == {
            "role",
            "container_name",
            "container_id",
            "interface",
            "interface_direction",
            "ipv4",
        }
        and observer.get("role") == "router-ingress-post-client-veth-pre-netem"
        and observer.get("container_name") == router.get("container")
        and observer.get("interface") == "eth0"
        and observer.get("interface_direction") == "ingress"
        and isinstance(client_network, Mapping)
        and set(client_network) == {"name", "id", "router_endpoint_id"}
        and client_network.get("name") == topology_client.get("name")
        and isinstance(uplink_network, Mapping)
        and set(uplink_network) == {"name", "id", "router_endpoint_id"}
        and uplink_network.get("name") == topology_uplink.get("name")
        and all(_sha256(value) for value in docker_ids)
    )


def observer_topology_receipt_valid(
    value: Any,
    *,
    expected_image_digest: str | None = None,
) -> bool:
    """Validate one immutable routed/controlled observer topology envelope."""

    receipt = _exact_mapping(value, _OBSERVER_TOPOLOGY_RECEIPT_KEYS)
    if receipt is None:
        return False
    network = receipt.get("network_receipt")
    binding = receipt.get("observer_binding")
    digest = receipt.get("network_receipt_sha256")
    if (
        not _schema(receipt, OBSERVER_TOPOLOGY_RECEIPT_SCHEMA_VERSION)
        or receipt.get("source") != OBSERVER_TOPOLOGY_RECEIPT_SOURCE
        or not controller_isolation_receipt_valid(receipt.get("controller_isolation"))
        or not _controlled_topology_valid(network, binding, digest)
        or not isinstance(network, Mapping)
    ):
        return False
    image_digest = network.get("image_digest")
    if not isinstance(image_digest, str) or _IMAGE_DIGEST.fullmatch(image_digest) is None:
        return False
    return expected_image_digest is None or image_digest == expected_image_digest


def controller_isolation_receipt_valid(value: Any) -> bool:
    """Validate proof that the credential-holding controller was non-dumpable."""

    receipt = _exact_mapping(value, _CONTROLLER_ISOLATION_RECEIPT_KEYS)
    return bool(
        receipt is not None
        and _schema(receipt)
        and receipt.get("source") == "linux-prctl-controller-nondumpable-v1"
        and _positive_u64(receipt.get("controller_pid"))
        and receipt.get("pr_get_dumpable_option") == 3
        and receipt.get("pr_set_dumpable_option") == 4
        and receipt.get("dumpable_before_set") in {0, 1}
        and receipt.get("set_dumpable_value") == 0
        and receipt.get("dumpable_after_set") == 0
        and receipt.get("dumpable_before_client_spawn") == 0
        and receipt.get("verified_before_observer_credentials") is True
        and receipt.get("protected_scope")
        == "controller-process-environment-and-router-capture-credentials"
    )


def build_observer_topology_receipt(
    *,
    network_receipt: Mapping[str, Any],
    observer_binding: Mapping[str, Any],
    network_receipt_sha256: str,
    controller_isolation: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the validated live topology for retention in ``experiment.json``."""

    receipt = {
        "schema_version": OBSERVER_TOPOLOGY_RECEIPT_SCHEMA_VERSION,
        "source": OBSERVER_TOPOLOGY_RECEIPT_SOURCE,
        "network_receipt_sha256": network_receipt_sha256,
        "network_receipt": dict(network_receipt),
        "observer_binding": dict(observer_binding),
        "controller_isolation": dict(controller_isolation),
    }
    if not observer_topology_receipt_valid(receipt):
        raise ValueError("observer topology receipt inputs are invalid")
    return receipt


def _reconciliation_valid(
    value: Any,
    *,
    runner_item: Mapping[str, Any],
    runner_job: Mapping[str, Any],
    mapping: Mapping[str, Any],
    capture: Mapping[str, Any],
    router_packets: Sequence[Mapping[str, Any]],
    previous_capture_packet_index: int | None,
) -> tuple[bool, int | None]:
    row = _exact_mapping(value, _RECONCILIATION_KEYS)
    if (
        row is None
        or not _schema(row)
        or not all(_u64(row.get(key)) for key in ("item_id", "job_id", "order_index", "endpoint"))
        or row.get("item_id") != runner_item["item_id"]
        or row.get("job_id") != runner_item["job_id"]
        or row.get("order_index") != runner_item["order_index"]
        or row.get("endpoint") != runner_item["endpoint"]
        or row.get("datagram_sha256") != runner_item["datagram_sha256"]
        or row.get("source_address") != runner_item["source_address"]
        or row.get("destination_address") != runner_item["destination_address"]
        or not _u64(row.get("candidate_packet_count"))
        or row.get("terminal_outcome") not in _RECONCILIATION_OUTCOMES
        or not all(
            _nullable_u64(row.get(key))
            for key in (
                "capture_packet_index",
                "capture_endpoint",
                "capture_realtime_ns",
                "capture_tai_lower_ns",
                "capture_tai_upper_ns",
                "capture_udp_payload_bytes",
            )
        )
        or not _nullable_i64(row.get("tx_to_capture_delta_lower_ns"))
        or not _nullable_i64(row.get("tx_to_capture_delta_upper_ns"))
    ):
        return False, previous_capture_packet_index
    captured_fields = (
        "capture_packet_index",
        "capture_endpoint",
        "capture_source_address",
        "capture_destination_address",
        "capture_realtime_ns",
        "capture_tai_lower_ns",
        "capture_tai_upper_ns",
        "capture_udp_payload_bytes",
        "capture_datagram_sha256",
        "tx_to_capture_delta_lower_ns",
        "tx_to_capture_delta_upper_ns",
    )
    captured = all(row[key] is not None for key in captured_fields)
    all_null = all(row[key] is None for key in (*captured_fields, "capture_direction"))
    outcome = row["terminal_outcome"]
    runner_failed = runner_item["terminal_outcome"] != "transmitted"
    if runner_failed:
        return bool(
            outcome == "runner-failed" and row["candidate_packet_count"] == 0 and all_null
        ), (previous_capture_packet_index)
    if outcome in {"missing", "duplicate"}:
        expected_candidates = 0 if outcome == "missing" else row["candidate_packet_count"]
        return bool(
            all_null
            and expected_candidates == row["candidate_packet_count"]
            and (outcome != "duplicate" or row["candidate_packet_count"] > 1)
        ), previous_capture_packet_index
    if not captured or row["candidate_packet_count"] != 1:
        return False, previous_capture_packet_index
    if (
        row.get("capture_direction") != "outgoing"
        or row["capture_endpoint"] != runner_item["endpoint"]
        or row["capture_packet_index"] >= capture["packets_received"]
        or row["capture_packet_index"] >= len(router_packets)
        or row["capture_source_address"] != runner_item["source_address"]
        or row["capture_destination_address"] != runner_item["destination_address"]
        or row["capture_datagram_sha256"] != runner_item["datagram_sha256"]
        or row["capture_udp_payload_bytes"] > KERNEL_TX_MAX_UDP_PAYLOAD_BYTES
        or (
            row["capture_tai_lower_ns"],
            row["capture_tai_upper_ns"],
        )
        != _translated_interval(
            mapping, clock="realtime", raw_ns=row["capture_realtime_ns"]
        )
        or not _clock_frame_contains(
            mapping,
            clock="realtime",
            raw_ns=row["capture_realtime_ns"],
        )
        or not (
            capture["capture_start_realtime_ns"]
            <= row["capture_realtime_ns"]
            <= capture["capture_end_realtime_ns"]
        )
        or runner_item["tx_software_tai_lower_ns"] is None
        or row["tx_to_capture_delta_lower_ns"]
        != row["capture_tai_lower_ns"] - runner_item["tx_software_tai_upper_ns"]
        or row["tx_to_capture_delta_upper_ns"]
        != row["capture_tai_upper_ns"] - runner_item["tx_software_tai_lower_ns"]
        or row["tx_to_capture_delta_lower_ns"] > row["tx_to_capture_delta_upper_ns"]
        or runner_item["tx_software_realtime_ns"] > row["capture_realtime_ns"]
        or dict(router_packets[row["capture_packet_index"]])
        != {
            "schema_version": 1,
            "packet_index": row["capture_packet_index"],
            "frame_number": row["capture_packet_index"] + 1,
            "capture_realtime_ns": row["capture_realtime_ns"],
            "source_address": row["capture_source_address"],
            "destination_address": row["capture_destination_address"],
            "udp_payload_bytes": row["capture_udp_payload_bytes"],
            "datagram_sha256": row["capture_datagram_sha256"],
        }
    ):
        return False, previous_capture_packet_index
    length_matches = row["capture_udp_payload_bytes"] == runner_item["udp_payload_bytes"]
    in_window = (
        runner_job["release_tai_ns"] <= row["capture_tai_lower_ns"]
        and row["capture_tai_upper_ns"] < runner_job["deadline_tai_ns"]
    )
    ordered = (
        previous_capture_packet_index is None
        or row["capture_packet_index"] > previous_capture_packet_index
    )
    expected_outcome = (
        "length-mismatch"
        if not length_matches
        else "window-violation"
        if not in_window
        else "order-violation"
        if not ordered
        else "matched"
    )
    return outcome == expected_outcome, row["capture_packet_index"]


def _evidence_aggregate(
    value: Any,
    *,
    runner: Mapping[str, Any],
    qdisc: Mapping[str, Any],
    capture: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    aggregate = _exact_mapping(value, _EVIDENCE_AGGREGATE_KEYS)
    if (
        aggregate is None
        or not _schema(aggregate)
        or any(
            not _u64(aggregate.get(key))
            for key in _EVIDENCE_AGGREGATE_KEYS - {"schema_version", "terminal_outcome"}
        )
    ):
        return None
    outcomes = [row["terminal_outcome"] for row in rows]
    deltas = [
        row["tx_to_capture_delta_upper_ns"]
        for row in rows
        if row["tx_to_capture_delta_upper_ns"] is not None
    ]
    before = qdisc["before"]
    after = qdisc["after"]
    qdisc_drops = after["drops"] - before["drops"]
    qdisc_overlimits = after["overlimits"] - before["overlimits"]
    qdisc_requeues = after["requeues"] - before["requeues"]
    capture_drops = capture["packets_dropped"] + capture["interface_packets_dropped"]
    failure_count = sum(outcome != "matched" for outcome in outcomes)
    expected = {
        "schema_version": 1,
        "job_count": runner["aggregate"]["job_count"],
        "item_count": len(rows),
        "matched_item_count": outcomes.count("matched"),
        "runner_failed_item_count": outcomes.count("runner-failed"),
        "missing_item_count": outcomes.count("missing"),
        "duplicate_item_count": outcomes.count("duplicate"),
        "length_mismatch_item_count": outcomes.count("length-mismatch"),
        "window_violation_item_count": outcomes.count("window-violation"),
        "order_violation_item_count": outcomes.count("order-violation"),
        "unresolved_item_count": 0,
        "qdisc_drop_count": qdisc_drops,
        "qdisc_overlimit_count": qdisc_overlimits,
        "qdisc_requeue_count": qdisc_requeues,
        "capture_drop_count": capture_drops,
        "max_tx_to_capture_delta_ns": max((max(0, value) for value in deltas), default=0),
        "terminal_outcome": (
            "complete"
            if failure_count == 0 and runner["aggregate"]["terminal_outcome"] == "complete"
            else "failed"
        ),
    }
    return dict(aggregate) if dict(aggregate) == expected else None


def kernel_tx_evidence_valid(
    value: Any,
    *,
    runner_receipt: Any,
    expected_run_json_sha256: str,
    expected_router_capture_sha256: str,
    router_capture_receipt: Any,
    router_packets: Sequence[Mapping[str, Any]],
) -> bool:
    """Validate Lab qdisc/capture evidence against one raw runner receipt."""

    receipt = _exact_mapping(value, _EVIDENCE_RECEIPT_KEYS)
    capture = receipt.get("post_veth_capture") if receipt is not None else None
    if (
        receipt is None
        or not _schema(receipt, KERNEL_TX_EVIDENCE_SCHEMA_VERSION)
        or receipt.get("semantics") != KERNEL_TX_EVIDENCE_SEMANTICS
        or not kernel_tx_runner_receipt_valid(runner_receipt)
        or not _sha256(expected_run_json_sha256)
        or not _sha256(receipt.get("runner_run_json_sha256"))
        or receipt.get("runner_kernel_tx_sha256") != kernel_tx_receipt_sha256(runner_receipt)
        or receipt.get("runner_run_json_sha256") != expected_run_json_sha256
        or not _sha256(expected_router_capture_sha256)
        or not _capture_evidence_valid(capture)
        or capture != router_capture_receipt
        or capture.get("pcapng_sha256")
        != expected_router_capture_sha256
        or not _controlled_topology_valid(
            receipt.get("controlled_network_receipt"),
            receipt.get("controlled_observer_binding"),
            receipt.get("controlled_network_receipt_sha256"),
        )
        or not _qdisc_evidence_valid(receipt.get("qdisc"), runner=runner_receipt)
        or not isinstance(receipt.get("reconciliations"), list)
        or not isinstance(router_packets, Sequence)
        or isinstance(router_packets, (str, bytes))
        or len(router_packets) != capture["packets_received"]
    ):
        return False
    network_receipt = receipt["controlled_network_receipt"]
    network_topology = network_receipt["topology"]
    capture_state = capture["router_state_start"]
    expected_topology_kind = network_topology["kind"]
    observed_router_ip = _router_interface_ipv4(
        capture_state["interfaces"][capture_state["client_interface"]],
        capture_state["client_interface"],
    )
    if (
        capture_state["topology_kind"] != expected_topology_kind
        or capture_state["client_interface"] != "eth0"
        or observed_router_ip != network_receipt["router"]["client_ipv4"]
        or (
            expected_topology_kind == "routed-public-egress"
            and capture_state["client_subnet"]
            != network_topology["client_network"]["subnet"]
        )
    ):
        return False
    runner_items: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = [
        (job, item) for job in runner_receipt["jobs"] for item in job["items"]
    ]
    rows = receipt["reconciliations"]
    if len(rows) != len(runner_items):
        return False
    previous_capture_packet_index: int | None = None
    for row, (job, item) in zip(rows, runner_items, strict=True):
        valid, previous_capture_packet_index = _reconciliation_valid(
            row,
            runner_item=item,
            runner_job=job,
            mapping=runner_receipt["clock_mapping"],
            capture=capture,
            router_packets=router_packets,
            previous_capture_packet_index=previous_capture_packet_index,
        )
        if not valid:
            return False
    return (
        _evidence_aggregate(
            receipt.get("aggregate"),
            runner=runner_receipt,
            qdisc=receipt["qdisc"],
            capture=capture,
            rows=rows,
        )
        is not None
    )


def kernel_tx_evidence_success_valid(
    value: Any,
    *,
    runner_receipt: Any,
    expected_run_json_sha256: str,
    expected_router_capture_sha256: str,
    router_capture_receipt: Any,
    router_packets: Sequence[Mapping[str, Any]],
) -> bool:
    """Require complete raw and independent evidence with no drop or ambiguity."""

    if not kernel_tx_evidence_valid(
        value,
        runner_receipt=runner_receipt,
        expected_run_json_sha256=expected_run_json_sha256,
        expected_router_capture_sha256=expected_router_capture_sha256,
        router_capture_receipt=router_capture_receipt,
        router_packets=router_packets,
    ):
        return False
    aggregate = value["aggregate"]
    qdisc = value["qdisc"]
    sent = qdisc["after"]["packets"] - qdisc["before"]["packets"]
    return bool(
        kernel_tx_runner_receipt_success_valid(runner_receipt)
        and aggregate["terminal_outcome"] == "complete"
        and aggregate["matched_item_count"] == aggregate["item_count"]
        and aggregate["unresolved_item_count"] == 0
        and aggregate["qdisc_drop_count"] == 0
        and aggregate["qdisc_overlimit_count"] == 0
        and aggregate["qdisc_requeue_count"] == 0
        and aggregate["capture_drop_count"] == 0
        and sent == runner_receipt["aggregate"]["etf_item_count"]
    )


def build_kernel_tx_evidence(
    *,
    runner_receipt: Mapping[str, Any],
    runner_run_json_sha256: str,
    qdisc_evidence: Mapping[str, Any],
    router_capture_receipt: Mapping[str, Any],
    router_packets: Sequence[Mapping[str, Any]],
    controlled_network_receipt: Mapping[str, Any],
    controlled_network_receipt_sha256: str,
    controlled_observer_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Construct one deterministic independent capture reconciliation.

    The builder accepts only an already-successful raw Rust receipt.  It uses
    encrypted datagram hashes plus exact socket tuples to find the same packet
    at router ingress; no CID, TLS, plaintext or application metadata enters
    the evidence boundary.
    """

    if not kernel_tx_runner_receipt_success_valid(runner_receipt):
        raise ValueError("kernel-TX evidence requires a successful raw runner receipt")
    if not _sha256(runner_run_json_sha256):
        raise ValueError("kernel-TX run.json digest is malformed")
    if not _capture_evidence_valid(router_capture_receipt):
        raise ValueError("kernel-TX router capture receipt is invalid")
    if len(router_packets) != router_capture_receipt["packets_received"]:
        raise ValueError("kernel-TX extracted packet count differs from the capture receipt")
    if not _controlled_topology_valid(
        controlled_network_receipt,
        controlled_observer_binding,
        controlled_network_receipt_sha256,
    ):
        raise ValueError("kernel-TX controlled observer topology is invalid")
    if not _qdisc_evidence_valid(qdisc_evidence, runner=runner_receipt):
        raise ValueError("kernel-TX qdisc evidence differs from the runner contract")

    mapping = runner_receipt["clock_mapping"]
    rows: list[dict[str, Any]] = []
    previous_index: int | None = None
    for job in runner_receipt["jobs"]:
        for item in job["items"]:
            candidates = [
                packet
                for packet in router_packets
                if packet.get("source_address") == item["source_address"]
                and packet.get("destination_address") == item["destination_address"]
                and packet.get("datagram_sha256") == item["datagram_sha256"]
            ]
            common = {
                "schema_version": 1,
                "item_id": item["item_id"],
                "job_id": item["job_id"],
                "order_index": item["order_index"],
                "endpoint": item["endpoint"],
                "datagram_sha256": item["datagram_sha256"],
                "source_address": item["source_address"],
                "destination_address": item["destination_address"],
                "candidate_packet_count": len(candidates),
            }
            if item["terminal_outcome"] != "transmitted":
                rows.append(
                    {
                        **common,
                        "capture_packet_index": None,
                        "capture_endpoint": None,
                        "capture_source_address": None,
                        "capture_destination_address": None,
                        "capture_direction": None,
                        "capture_realtime_ns": None,
                        "capture_tai_lower_ns": None,
                        "capture_tai_upper_ns": None,
                        "capture_udp_payload_bytes": None,
                        "capture_datagram_sha256": None,
                        "tx_to_capture_delta_lower_ns": None,
                        "tx_to_capture_delta_upper_ns": None,
                        "terminal_outcome": "runner-failed",
                    }
                )
                continue
            if len(candidates) != 1:
                rows.append(
                    {
                        **common,
                        "capture_packet_index": None,
                        "capture_endpoint": None,
                        "capture_source_address": None,
                        "capture_destination_address": None,
                        "capture_direction": None,
                        "capture_realtime_ns": None,
                        "capture_tai_lower_ns": None,
                        "capture_tai_upper_ns": None,
                        "capture_udp_payload_bytes": None,
                        "capture_datagram_sha256": None,
                        "tx_to_capture_delta_lower_ns": None,
                        "tx_to_capture_delta_upper_ns": None,
                        "terminal_outcome": "missing" if not candidates else "duplicate",
                    }
                )
                continue
            packet = candidates[0]
            capture_lower, capture_upper = _translated_interval(
                mapping,
                clock="realtime",
                raw_ns=packet["capture_realtime_ns"],
            )
            tx_lower = item["tx_software_tai_lower_ns"]
            tx_upper = item["tx_software_tai_upper_ns"]
            assert isinstance(tx_lower, int) and isinstance(tx_upper, int)
            length_matches = packet["udp_payload_bytes"] == item["udp_payload_bytes"]
            in_window = (
                job["release_tai_ns"] <= capture_lower
                and capture_upper < job["deadline_tai_ns"]
            )
            ordered = previous_index is None or packet["packet_index"] > previous_index
            outcome = (
                "length-mismatch"
                if not length_matches
                else "window-violation"
                if not in_window
                else "order-violation"
                if not ordered
                else "matched"
            )
            rows.append(
                {
                    **common,
                    "capture_packet_index": packet["packet_index"],
                    "capture_endpoint": item["endpoint"],
                    "capture_source_address": packet["source_address"],
                    "capture_destination_address": packet["destination_address"],
                    "capture_direction": "outgoing",
                    "capture_realtime_ns": packet["capture_realtime_ns"],
                    "capture_tai_lower_ns": capture_lower,
                    "capture_tai_upper_ns": capture_upper,
                    "capture_udp_payload_bytes": packet["udp_payload_bytes"],
                    "capture_datagram_sha256": packet["datagram_sha256"],
                    "tx_to_capture_delta_lower_ns": capture_lower - tx_upper,
                    "tx_to_capture_delta_upper_ns": capture_upper - tx_lower,
                    "terminal_outcome": outcome,
                }
            )
            previous_index = packet["packet_index"]

    outcomes = [row["terminal_outcome"] for row in rows]
    before = qdisc_evidence["before"]
    after = qdisc_evidence["after"]
    deltas = [
        row["tx_to_capture_delta_upper_ns"]
        for row in rows
        if row["tx_to_capture_delta_upper_ns"] is not None
    ]
    capture_drops = (
        router_capture_receipt["packets_dropped"]
        + router_capture_receipt["interface_packets_dropped"]
    )
    aggregate = {
        "schema_version": 1,
        "job_count": runner_receipt["aggregate"]["job_count"],
        "item_count": len(rows),
        "matched_item_count": outcomes.count("matched"),
        "runner_failed_item_count": outcomes.count("runner-failed"),
        "missing_item_count": outcomes.count("missing"),
        "duplicate_item_count": outcomes.count("duplicate"),
        "length_mismatch_item_count": outcomes.count("length-mismatch"),
        "window_violation_item_count": outcomes.count("window-violation"),
        "order_violation_item_count": outcomes.count("order-violation"),
        "unresolved_item_count": 0,
        "qdisc_drop_count": after["drops"] - before["drops"],
        "qdisc_overlimit_count": after["overlimits"] - before["overlimits"],
        "qdisc_requeue_count": after["requeues"] - before["requeues"],
        "capture_drop_count": capture_drops,
        "max_tx_to_capture_delta_ns": max(
            (max(0, value) for value in deltas), default=0
        ),
        "terminal_outcome": (
            "complete" if all(outcome == "matched" for outcome in outcomes) else "failed"
        ),
    }
    receipt = {
        "schema_version": KERNEL_TX_EVIDENCE_SCHEMA_VERSION,
        "semantics": KERNEL_TX_EVIDENCE_SEMANTICS,
        "runner_run_json_sha256": runner_run_json_sha256,
        "runner_kernel_tx_sha256": kernel_tx_receipt_sha256(runner_receipt),
        "controlled_network_receipt_sha256": controlled_network_receipt_sha256,
        "controlled_network_receipt": dict(controlled_network_receipt),
        "controlled_observer_binding": dict(controlled_observer_binding),
        "qdisc": dict(qdisc_evidence),
        "post_veth_capture": dict(router_capture_receipt),
        "reconciliations": rows,
        "aggregate": aggregate,
    }
    if not kernel_tx_evidence_valid(
        receipt,
        runner_receipt=runner_receipt,
        expected_run_json_sha256=runner_run_json_sha256,
        expected_router_capture_sha256=router_capture_receipt["pcapng_sha256"],
        router_capture_receipt=router_capture_receipt,
        router_packets=router_packets,
    ):
        raise ValueError("constructed kernel-TX evidence failed self-validation")
    return receipt
