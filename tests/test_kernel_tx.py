from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from qcsd_lab import capture_session, fidelity, kernel_tx
from qcsd_lab.kernel_tx import (
    KERNEL_TX_EVIDENCE_SEMANTICS,
    KERNEL_TX_RUNNER_SEMANTICS,
    build_kernel_tx_evidence,
    build_observer_topology_receipt,
    kernel_tx_evidence_success_valid,
    kernel_tx_evidence_valid,
    kernel_tx_receipt_sha256,
    kernel_tx_runner_receipt_success_valid,
    kernel_tx_runner_receipt_valid,
    observer_topology_receipt_valid,
)
from tests.test_buflo_handoff import _runner_wakeup_receipt

_MONOTONIC_TO_TAI_NS = 1_000_000_000_000
_REALTIME_TO_TAI_NS = 37_000_000_000
_RELEASE_MONOTONIC_NS = 100_100_000_000
_RELEASE_TAI_NS = _RELEASE_MONOTONIC_NS + _MONOTONIC_TO_TAI_NS


def _controller_isolation() -> dict[str, object]:
    return {
        "schema_version": 1,
        "source": "linux-prctl-controller-nondumpable-v1",
        "controller_pid": 1234,
        "pr_get_dumpable_option": 3,
        "pr_set_dumpable_option": 4,
        "dumpable_before_set": 1,
        "set_dumpable_value": 0,
        "dumpable_after_set": 0,
        "dumpable_before_client_spawn": 0,
        "verified_before_observer_credentials": True,
        "protected_scope": (
            "controller-process-environment-and-router-capture-credentials"
        ),
    }


def _clock_sample(clock_ns: int, offset_ns: int) -> dict[str, int]:
    return {
        "schema_version": 1,
        "tai_before_ns": clock_ns + offset_ns,
        "clock_ns": clock_ns,
        "tai_after_ns": clock_ns + offset_ns,
        "bracket_width_ns": 0,
    }


def _clock_mapping() -> dict[str, object]:
    return {
        "schema_version": 1,
        "tai_clock_id": "CLOCK_TAI",
        "monotonic_clock_id": "CLOCK_MONOTONIC",
        "realtime_clock_id": "CLOCK_REALTIME",
        "start": {
            "monotonic": _clock_sample(100_000_000_000, _MONOTONIC_TO_TAI_NS),
            "realtime": _clock_sample(1_063_000_000_000, _REALTIME_TO_TAI_NS),
        },
        "end": {
            "monotonic": _clock_sample(101_000_000_000, _MONOTONIC_TO_TAI_NS),
            "realtime": _clock_sample(1_064_000_000_000, _REALTIME_TO_TAI_NS),
        },
        "instant_alignment": {
            "schema_version": 1,
            "monotonic_clock_ns": _RELEASE_MONOTONIC_NS,
            "instant_bracket_width_ns": 0,
            "selected_upper_offset_ns": 0,
            "semantics": (
                "std_Instant_bracketed_around_CLOCK_MONOTONIC; "
                "upper_bracket_edge_selected; "
                "translated_Instant_is_a_conservative_latest_bound; "
                "full_bracket_width_is_alignment_uncertainty"
            ),
        },
        "max_observed_bracket_width_ns": 0,
        "max_observed_offset_drift_ns": 0,
        "effective_monotonic_offset_lower_ns": _MONOTONIC_TO_TAI_NS,
        "effective_monotonic_offset_upper_ns": _MONOTONIC_TO_TAI_NS,
        "effective_realtime_offset_lower_ns": _REALTIME_TO_TAI_NS,
        "effective_realtime_offset_upper_ns": _REALTIME_TO_TAI_NS,
        "per_item_monotonic_evidence_count": 2,
        "per_item_realtime_evidence_count": 2,
        "effective_envelope_semantics": (
            "start_and_end_clock_phases_plus_every_retained_per_item_post_tx_"
            "realtime_bracket_and_enqueue_monotonic_direct_tai_bracket; "
            "final_interval_is_conservative_union; "
            "widened_interval_must_still_fit_half_open_realization_window"
        ),
    }


def _qdisc_contract() -> dict[str, object]:
    return {
        "schema_version": 1,
        "interface": "eth0",
        "root_kind": "prio",
        "root_handle": "1:",
        "bands": 2,
        "priomap": [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        "timed_kind": "etf",
        "timed_parent": "1:1",
        "timed_handle": "20:",
        "ordinary_kind": "pfifo",
        "ordinary_parent": "1:2",
        "ordinary_handle": "10:",
        "clock_id": "CLOCK_TAI",
        "delta_ns": 4_000_000,
        "deadline_mode": False,
        "offload": False,
        "skip_socket_check": False,
        "timed_socket_priority": 6,
        "ordinary_socket_priority": 0,
        "priority_method": "serialized_socket_so_priority",
        "scm_priority_supported": False,
        "single_threaded_sender_control_flow_enforced": True,
        "so_priority_before": 0,
        "so_priority_during": 6,
        "so_priority_after": 0,
        "so_priority_reset_valid": True,
        "so_txtime_enabled": True,
        "tx_sched_timestamping_enabled": True,
        "tx_software_timestamping_enabled": True,
        "tx_timestamp_opt_id_enabled": True,
        "txtime_errors_enabled": True,
    }


def _item(
    *,
    item_id: int,
    order_index: int,
    role: str,
    endpoint: int,
    event_id: int,
    enqueue_tai_ns: int,
    tx_sched_tai_ns: int,
    tx_software_tai_ns: int,
) -> dict[str, object]:
    source = f"10.0.0.2:{40_000 + endpoint}"
    destination = f"10.0.1.{10 + endpoint}:4433"
    digest = f"{item_id + 1:064x}"
    return {
        "schema_version": 1,
        "item_id": item_id,
        "job_id": 0,
        "order_index": order_index,
        "event_id": event_id,
        "role": role,
        "endpoint_index": endpoint,
        "endpoint": endpoint,
        "send_path": "etf" if order_index == 0 else "ordered-after-exact",
        "datagram_sha256": digest,
        "source_address": source,
        "destination_address": destination,
        "socket_timestamp_id": item_id + 10,
        "udp_payload_bytes": 1_200 if order_index == 0 else 64,
        "target_tai_ns": _RELEASE_TAI_NS,
        "scm_txtime_tai_ns": _RELEASE_TAI_NS + 4_000_000 if order_index == 0 else None,
        "enqueue_monotonic_ns": enqueue_tai_ns - _MONOTONIC_TO_TAI_NS,
        "enqueue_tai_ns": enqueue_tai_ns,
        "enqueue_tai_lower_ns": enqueue_tai_ns,
        "enqueue_tai_upper_ns": enqueue_tai_ns,
        "tx_sched_realtime_ns": tx_sched_tai_ns - _REALTIME_TO_TAI_NS,
        "tx_sched_tai_ns": tx_sched_tai_ns,
        "tx_sched_tai_lower_ns": tx_sched_tai_ns,
        "tx_sched_tai_upper_ns": tx_sched_tai_ns,
        "tx_software_realtime_ns": tx_software_tai_ns - _REALTIME_TO_TAI_NS,
        "tx_software_tai_ns": tx_software_tai_ns,
        "provisional_tx_software_tai_lower_ns": tx_software_tai_ns,
        "provisional_tx_software_tai_upper_ns": tx_software_tai_ns,
        "tx_software_tai_lower_ns": tx_software_tai_ns,
        "tx_software_tai_upper_ns": tx_software_tai_ns,
        "send_attempt": None,
        "txtime_error": None,
        "terminal_error": None,
        "terminal_error_detail": None,
        "finalization_state": "controller-and-trace-finalized",
        "terminal_outcome": "transmitted",
    }


def _privilege() -> dict[str, object]:
    return {
        "schema_version": 1,
        "uid": [1000, 1000, 1000, 1000],
        "gid": [1000, 1000, 1000, 1000],
        "supplementary_groups": [],
        "cap_inheritable": "0000000000000000",
        "cap_permitted": "0000000000000000",
        "cap_effective": "0000000000000000",
        "cap_bounding": "0000000000000000",
        "cap_ambient": "0000000000000000",
        "no_new_privileges": True,
    }


def _socket_setup(endpoint: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "family": "ipv4",
        "local_address": f"10.0.0.2:{40_000 + endpoint}",
        "duplicated_fd_cloexec": True,
        "nonblocking": True,
        "socket_type": 2,
        "txtime_clock_id": 11,
        "txtime_flags": 2,
        "timestamping_report_flags": 2192,
        "timed_priority": 6,
        "priority_before_probe": 0,
        "priority_after_probe": 0,
        "corresponding_error_queue_enabled": True,
        "etf_deadline_mode": False,
        "etf_skip_socket_check": False,
        "priority_method": "serialized_socket_so_priority",
        "scm_priority_supported": False,
        "scm_priority_probe_family": "ipv4",
        "scm_priority_probe_errno": 22,
        "exclusive_socket_sender_required": True,
        "per_datagram_timestamp_requests": True,
    }


def _lifecycle() -> dict[str, object]:
    return {
        "schema_version": 1,
        "globally_poisoned": False,
        "poison_reason": None,
        "completed_main_jobs": 1,
        "completed_immediate_datagrams": 1,
        "aborted_jobs": 0,
        "failed_commands": 0,
        "causal_main_proven": False,
        "active_job_id": None,
        "last_main_job_id": 0,
        "remaining_post_main_datagrams": 0,
    }


def _runtime_contract() -> dict[str, object]:
    privilege = _privilege()
    lifecycle = _lifecycle()
    socket_state = {
        "schema_version": 1,
        "socket_count": 2,
        "active_job_id": None,
        "pending_socket_count": 0,
        "stale_error_queue_socket_count": 0,
        "nonzero_priority_socket_count": 0,
        "inspection_errors": [],
        "clean": True,
    }
    return {
        "schema_version": 1,
        "scheduler_contract": "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
        "scheduler_initial": {
            "schema_version": 1,
            "source": "linux-sched-and-procfs-v1",
            "policy": "SCHED_RR",
            "priority": 1,
            "affinity_cpus": [10],
            "rlimit_rtprio": {"soft": 1, "hard": 1},
            "no_new_privileges": True,
            "effective_capabilities_hex": "0000000000001100",
            "cgroup_effective_cpuset": "10-11",
            "affinity_scope": "qcsd_container_affinity_partition_not_physical_cpu_isolation",
            "contract": "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
            "contract_valid": True,
        },
        "socket_setup": [_socket_setup(0), _socket_setup(1)],
        "privilege_drop": privilege,
        "helper_thread": {
            "schema_version": 1,
            "contract_name": "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
            "target_cpu": 11,
            "observed_affinity": [11],
            "scheduler_policy": 2,
            "scheduler_policy_name": "SCHED_RR",
            "scheduler_priority": 1,
            "thread_id": 1234,
            "privilege": copy.deepcopy(privilege),
            "endpoint_socket_count": 2,
            "credit_owner_capacity": 2,
            "max_datagrams_per_owner": 1,
            "max_post_main_datagrams": 2,
        },
        "helper_lifecycle": lifecycle,
        "helper_shutdown": {
            "schema_version": 1,
            "shutdown_command_sent": True,
            "shutdown_received": True,
            "worker_joined": True,
            "shutdown_complete": True,
            "clean_socket_state": True,
            "global_poisoned": False,
            "failed_commands": 0,
            "remaining_post_main_datagrams": 0,
            "socket_state": socket_state,
            "lifecycle": copy.deepcopy(lifecycle),
            "errors": [],
        },
        "socket_count": 2,
        "single_threaded_sender_control_flow_enforced": True,
        "prebuild_selection_cutoff_lead_ns": 5_000_000,
        "prebuild_selection_semantics": (
            "application_and_transport_state_selected_at_nominal_release_while_wall_clock_is_one_strict_window_early; "
            "runner_freezes_until_kernel_tx_software_receipt; client_only_adaptation; paper_equivalent=false"
        ),
        "post_main_inventory_semantics": (
            "residual_scheduled_incoming_credit_is_deduplicated_by_endpoint_owner; "
            "at_most_one_immediate_datagram_per_owner_per_job; a_second_datagram_for_the_same_owner_is_a_hard_failure; "
            "same_endpoint_credit_may_be_coalesced_in_the_exact_main_datagram"
        ),
        "max_post_main_datagrams": 2,
    }


def _runner_receipt() -> dict[str, object]:
    outgoing = _item(
        item_id=0,
        order_index=0,
        role="exact-outgoing",
        endpoint=1,
        event_id=0,
        enqueue_tai_ns=_RELEASE_TAI_NS - 1_000_000,
        tx_sched_tai_ns=_RELEASE_TAI_NS - 500_000,
        tx_software_tai_ns=_RELEASE_TAI_NS + 100_000,
    )
    incoming = _item(
        item_id=1,
        order_index=1,
        role="incoming-credit",
        endpoint=0,
        event_id=1,
        enqueue_tai_ns=_RELEASE_TAI_NS + 110_000,
        tx_sched_tai_ns=_RELEASE_TAI_NS + 120_000,
        tx_software_tai_ns=_RELEASE_TAI_NS + 150_000,
    )
    clock_mapping = _clock_mapping()
    return {
        "schema_version": 1,
        "semantics": kernel_tx.KERNEL_TX_HISTORICAL_RUNNER_SEMANTICS,
        "terminal_outcome": "complete",
        "primary_error": None,
        "cleanup_errors": [],
        "defense_start_monotonic_ns": _RELEASE_MONOTONIC_NS,
        "defense_start_tai_ns": _RELEASE_TAI_NS,
        "clock_start": copy.deepcopy(clock_mapping["start"]),
        "clock_end": copy.deepcopy(clock_mapping["end"]),
        "clock_mapping_valid": True,
        "clock_mapping_error": None,
        "clock_mapping": clock_mapping,
        "runtime_contract": _runtime_contract(),
        "qdisc_contract": _qdisc_contract(),
        "jobs": [
            {
                "schema_version": 1,
                "job_id": 0,
                "tick": 0,
                "release_monotonic_ns": _RELEASE_MONOTONIC_NS,
                "release_tai_ns": _RELEASE_TAI_NS,
                "deadline_monotonic_ns": _RELEASE_MONOTONIC_NS + 5_000_000,
                "deadline_tai_ns": _RELEASE_TAI_NS + 5_000_000,
                "items": [outgoing, incoming],
                "credit_identities": [
                    {
                        "schema_version": 1,
                        "slot": 1,
                        "endpoint_index": 0,
                        "endpoint": 0,
                        "stream_id": 4,
                        "absolute_limit": 64,
                        "identity_kind": "scheduled",
                        "identity_detail": 0,
                        "resolution": "post-main-carrier-finalized",
                        "carrier_item_id": 1,
                    }
                ],
                "prepared_output_failure": None,
                "helper_job_close": {
                    "schema_version": 1,
                    "job_id": 0,
                    "unused_post_main_datagrams": 1,
                    "complete": True,
                },
                "helper_job_abort": None,
                "terminal_error": None,
                "terminal_outcome": "complete",
            }
        ],
        "aggregate": {
            "schema_version": 1,
            "job_count": 1,
            "item_count": 2,
            "etf_item_count": 1,
            "ordered_item_count": 1,
            "captured_credit_identity_count": 1,
            "prepared_output_failure_count": 0,
            "main_coalesced_credit_identity_count": 0,
            "carrier_credit_identity_count": 1,
            "unresolved_credit_identity_count": 0,
            "transmitted_item_count": 2,
            "failed_item_count": 0,
            "tx_sched_timestamp_count": 2,
            "tx_software_timestamp_count": 2,
            "txtime_error_count": 0,
            "timestamp_evidence_missing_count": 0,
            "window_violation_count": 0,
            "unresolved_item_count": 0,
            "max_tx_software_lateness_ns": 150_000,
            "terminal_outcome": "complete",
        },
        "terminal_errors": [],
    }


def _runner_receipt_v2() -> dict[str, object]:
    """Upgrade the historical fixture to the refined clock-mapping contract."""

    raw = _runner_receipt()
    raw["schema_version"] = 2
    raw["semantics"] = KERNEL_TX_RUNNER_SEMANTICS
    mapping = raw["clock_mapping"]
    assert isinstance(mapping, dict)
    mapping["schema_version"] = 2
    mapping["effective_envelope_semantics"] = (
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
    for job in raw["jobs"]:
        for item in job["items"]:
            item["schema_version"] = 2
            post_tai_ns = item["tx_software_tai_ns"] + 1
            item["post_tx_clock_phase"] = {
                "monotonic": _clock_sample(
                    post_tai_ns - _MONOTONIC_TO_TAI_NS,
                    _MONOTONIC_TO_TAI_NS,
                ),
                "realtime": _clock_sample(
                    post_tai_ns - _REALTIME_TO_TAI_NS,
                    _REALTIME_TO_TAI_NS,
                ),
            }
    return raw


def _refresh_failed_runner_receipt(
    raw: dict[str, object], *, primary_error: str
) -> None:
    """Recompute the producer's top-level failure projection for test fixtures."""

    jobs = raw["jobs"]
    items = [item for job in jobs for item in job["items"]]
    raw["terminal_outcome"] = "failed"
    raw["primary_error"] = primary_error
    raw["terminal_errors"] = [primary_error]
    for job in jobs:
        if any(item["terminal_outcome"] != "transmitted" for item in job["items"]):
            job["terminal_error"] = primary_error
            job["terminal_outcome"] = "failed"
    outcomes = [item["terminal_outcome"] for item in items]
    aggregate = raw["aggregate"]
    aggregate.update(
        {
            "transmitted_item_count": outcomes.count("transmitted"),
            "failed_item_count": sum(outcome != "transmitted" for outcome in outcomes),
            "tx_sched_timestamp_count": sum(
                item["tx_sched_tai_ns"] is not None for item in items
            ),
            "tx_software_timestamp_count": sum(
                item["tx_software_tai_ns"] is not None for item in items
            ),
            "txtime_error_count": outcomes.count("txtime-error"),
            "timestamp_evidence_missing_count": outcomes.count(
                "timestamp-evidence-missing"
            ),
            "window_violation_count": outcomes.count("window-violation"),
            "max_tx_software_lateness_ns": max(
                (
                    max(0, item["tx_software_tai_upper_ns"] - item["target_tai_ns"])
                    for item in items
                    if item["tx_software_tai_upper_ns"] is not None
                ),
                default=0,
            ),
            "terminal_outcome": "failed",
        }
    )


def _clear_final_clock_translations(item: dict[str, object]) -> None:
    for prefix in ("tx_sched", "tx_software"):
        for suffix in ("tai_ns", "tai_lower_ns", "tai_upper_ns"):
            item[f"{prefix}_{suffix}"] = None


def _schema_two_unmapped_error_detail(item: dict[str, object]) -> str:
    enqueue_complete = (
        item["enqueue_tai_lower_ns"] is not None
        and item["enqueue_tai_upper_ns"] is not None
        and item["enqueue_tai_lower_ns"] <= item["enqueue_tai_upper_ns"]
    )
    tx_order = (
        item["tx_sched_realtime_ns"] is not None
        and item["tx_software_realtime_ns"] is not None
        and item["tx_sched_realtime_ns"] <= item["tx_software_realtime_ns"]
    )
    structural_order = (
        item["order_index"] == 0
        and item["enqueue_tai_upper_ns"] is not None
        and item["enqueue_tai_upper_ns"] < item["target_tai_ns"]
    )
    controller_finalized = (
        item["finalization_state"] == "controller-and-trace-finalized"
    )

    def rust_bool(value: bool) -> str:
        return "true" if value else "false"

    return (
        f"item {item['item_id']} failed final mapping: "
        f"enqueue_complete={rust_bool(enqueue_complete)}, "
        "enqueue_clock_consistent=false, timestamp_complete=false, "
        f"tx_order={rust_bool(tx_order)}, physical_window=false, "
        "provisional_interval=false, endpoint_tuple=true, item_sequence=true, "
        "job_identity=true, "
        f"controller_trace_finalized={rust_bool(controller_finalized)}, "
        f"structural_order={rust_bool(structural_order)}"
    )


def _make_schema_two_mapping_failure(
    raw: dict[str, object], *, mapping_error: str
) -> None:
    raw.update(
        {
            "cleanup_errors": [mapping_error],
            "clock_mapping_valid": False,
            "clock_mapping_error": mapping_error,
            "clock_mapping": None,
        }
    )
    for item in (item for job in raw["jobs"] for item in job["items"]):
        _clear_final_clock_translations(item)
        item["terminal_outcome"] = "timestamp-evidence-missing"
        item["terminal_error"] = "final_conservative_envelope_validation_failed"
        item["terminal_error_detail"] = _schema_two_unmapped_error_detail(item)
    _refresh_failed_runner_receipt(raw, primary_error=mapping_error)


def _runner_wakeup_v11() -> dict[str, object]:
    value = _runner_wakeup_receipt(10)
    value.update(
        {
            "schema_version": 11,
            "semantics": fidelity.RUNNER_WAKEUP_V11_SEMANTICS,
            "buflo_exact_release_active_wait_poll_source": ("instant-authoritative-fallback-v1"),
            "buflo_kernel_tx": _runner_receipt(),
        }
    )
    return value


def _failed_before_arm_runner_receipt() -> dict[str, object]:
    raw = _runner_receipt()
    mapping_error = "BuFLO kernel epoch was never armed"
    raw.update(
        {
            "terminal_outcome": "failed",
            "primary_error": "kernel timing failed before arm",
            "cleanup_errors": [mapping_error],
            "defense_start_monotonic_ns": None,
            "defense_start_tai_ns": None,
            "clock_mapping_valid": False,
            "clock_mapping_error": mapping_error,
            "clock_mapping": None,
            "jobs": [],
        }
    )
    raw["aggregate"] = {
        "schema_version": 1,
        "job_count": 0,
        "item_count": 0,
        "etf_item_count": 0,
        "ordered_item_count": 0,
        "captured_credit_identity_count": 0,
        "prepared_output_failure_count": 0,
        "main_coalesced_credit_identity_count": 0,
        "carrier_credit_identity_count": 0,
        "unresolved_credit_identity_count": 0,
        "transmitted_item_count": 0,
        "failed_item_count": 0,
        "tx_sched_timestamp_count": 0,
        "tx_software_timestamp_count": 0,
        "txtime_error_count": 0,
        "timestamp_evidence_missing_count": 0,
        "window_violation_count": 0,
        "unresolved_item_count": 0,
        "max_tx_software_lateness_ns": 0,
        "terminal_outcome": "failed",
    }
    return raw


def _snapshot(*, packets: int = 0, drops: int = 0) -> dict[str, int]:
    return {
        "packets": packets,
        "bytes": packets * 1_242,
        "drops": drops,
        "overlimits": 0,
        "requeues": 0,
        "backlog_bytes": 0,
        "backlog_packets": 0,
        "qlen": 0,
    }


def _topology() -> tuple[dict[str, object], dict[str, object], str]:
    network = {
        "schema_version": 2,
        "artifact_type": "qcsd-buflo-controlled-network-v2",
        "image_digest": f"sha256:{'c' * 64}",
        "topology": {
            "kind": "shared-two-network-router",
            "client_network": {"name": "client"},
            "server_network": {"name": "server"},
            "router_interfaces": [],
        },
        "capture_point": {
            "client_to_server_position": "before-router-eth0-ingress-ifb0-netem"
        },
        "client": {},
        "router": {"container": "router", "client_ipv4": "10.0.0.1"},
        "servers": [],
        "directional_coverage": {
            "client_to_server": {
                "shaping_site": "router:eth0-ingress-redirect-ifb0-root",
                "capture_position": "before-impairment",
            }
        },
        "rate_aggregation": {},
        "observation_contract": {},
    }
    binding = {
        "schema_version": 1,
        "artifact_type": "qcsd-kernel-tx-controlled-observer-binding",
        "topology_kind": "shared-two-network-router",
        "image_digest": network["image_digest"],
        "observer": {
            "role": "router-ingress-post-client-veth-pre-netem",
            "container_name": "router",
            "container_id": "d" * 64,
            "interface": "eth0",
            "interface_direction": "ingress",
            "ipv4": "10.0.0.1",
        },
        "client_network": {"name": "client", "id": "e" * 64, "router_endpoint_id": "f" * 64},
        "server_network": {"name": "server", "id": "1" * 64, "router_endpoint_id": "2" * 64},
        "observed_direction": "client-to-server",
        "capture_position": "router-eth0-ingress-after-client-veth-before-ifb0-ingress-netem",
    }
    return network, binding, kernel_tx_receipt_sha256(network)


def _router_state(*, active: bool) -> dict[str, object]:
    def offloads(interface: str) -> list[dict[str, object]]:
        return [
            {
                "ifname": interface,
                "generic-receive-offload": {"active": False},
                "generic-segmentation-offload": {"active": False},
                "tcp-segmentation-offload": {"active": False},
                "tx-udp-segmentation": {"active": False},
            }
        ]

    def interface(name: str, address: str) -> list[dict[str, object]]:
        local, prefix = address.split("/", 1)
        return [
            {
                "ifname": name,
                "mtu": 1_500,
                "flags": ["UP", "LOWER_UP"],
                "addr_info": [
                    {"family": "inet", "local": local, "prefixlen": int(prefix)}
                ],
            }
        ]

    return {
        "schema_version": 1,
        "topology_kind": "shared-two-network-router",
        "capture_process_state": "capturing" if active else "idle",
        "capture_process_active": active,
        "client_interface": "eth0",
        "uplink_interface": "eth1",
        "client_subnet": None,
        "ipv4_forwarding": 1,
        "interfaces": {
            "eth0": interface("eth0", "10.0.0.1/24"),
            "eth1": interface("eth1", "10.0.1.1/24"),
        },
        "routes": [{"dst": "10.0.0.0/24", "dev": "eth0"}],
        "qdiscs": {
            "eth0": [{"kind": "noqueue", "handle": "0:", "parent": "root"}],
            "eth1": [{"kind": "noqueue", "handle": "0:", "parent": "root"}],
        },
        "offloads": {"eth0": offloads("eth0"), "eth1": offloads("eth1")},
        "nat_rules": ["*nat", "COMMIT"],
        "invariants": {
            "client_interface_present": True,
            "uplink_interface_present": True,
            "ipv4_forwarding_enabled": True,
            "uplink_default_route_present": False,
            "source_masquerade_required": False,
            "source_masquerade_present": False,
        },
    }


def _public_topology() -> tuple[dict[str, object], dict[str, object], str]:
    network = {
        "schema_version": 1,
        "artifact_type": "qcsd-kernel-tx-public-network-v1",
        "image_digest": f"sha256:{'c' * 64}",
        "topology": {
            "kind": "routed-public-egress",
            "client_network": {"name": "public-client", "subnet": "10.222.1.0/24"},
            "uplink_network": {"name": "bridge"},
            "router_interfaces": {"client": "eth0", "uplink": "eth1"},
        },
        "capture_point": {
            "client_to_server_position": "before-router-eth0-forwarding-and-masquerade"
        },
        "client": {"network": "public-client", "default_route_via": "10.222.1.2"},
        "router": {
            "container": "public-router",
            "client_ipv4": "10.222.1.2",
            "client_interface": "eth0",
            "uplink_interface": "eth1",
            "ipv4_forwarding": True,
            "source_masquerade": True,
        },
        "directional_coverage": {
            "client_to_server": {
                "capture_position": "before-forwarding",
                "nat_position": "after-capture",
            }
        },
        "observation_contract": {
            "client_only": True,
            "ordinary_public_origins": True,
        },
    }
    binding = {
        "schema_version": 1,
        "artifact_type": "qcsd-kernel-tx-public-observer-binding",
        "topology_kind": "routed-public-egress",
        "image_digest": network["image_digest"],
        "observer": {
            "role": "router-ingress-post-client-veth-pre-netem",
            "container_name": "public-router",
            "container_id": "d" * 64,
            "interface": "eth0",
            "interface_direction": "ingress",
            "ipv4": "10.222.1.2",
        },
        "client_network": {
            "name": "public-client",
            "id": "e" * 64,
            "router_endpoint_id": "f" * 64,
        },
        "uplink_network": {
            "name": "bridge",
            "id": "1" * 64,
            "router_endpoint_id": "2" * 64,
        },
        "observed_direction": "client-to-public-origin",
        "capture_position": (
            "router-eth0-ingress-after-client-veth-before-forwarding-and-masquerade"
        ),
    }
    return network, binding, kernel_tx_receipt_sha256(network)


def _public_router_state(*, active: bool) -> dict[str, object]:
    state = _router_state(active=active)
    state.update(
        {
            "topology_kind": "routed-public-egress",
            "client_subnet": "10.222.1.0/24",
            "routes": [{"dst": "default", "dev": "eth1", "gateway": "172.17.0.1"}],
            "nat_rules": [
                "*nat",
                "-A POSTROUTING -s 10.222.1.0/24 -o eth1 -j MASQUERADE",
                "COMMIT",
            ],
            "invariants": {
                "client_interface_present": True,
                "uplink_interface_present": True,
                "ipv4_forwarding_enabled": True,
                "uplink_default_route_present": True,
                "source_masquerade_required": True,
                "source_masquerade_present": True,
            },
        }
    )
    state["interfaces"]["eth0"][0]["addr_info"][0].update(  # type: ignore[index]
        {"local": "10.222.1.2", "prefixlen": 24}
    )
    state["interfaces"]["eth1"][0]["addr_info"][0].update(  # type: ignore[index]
        {"local": "172.17.0.2", "prefixlen": 16}
    )
    return state


def test_public_observer_topology_receipt_is_immutable_and_image_bound() -> None:
    network, binding, digest = _public_topology()
    receipt = build_observer_topology_receipt(
        network_receipt=network,
        observer_binding=binding,
        network_receipt_sha256=digest,
        controller_isolation=_controller_isolation(),
    )

    assert observer_topology_receipt_valid(
        receipt,
        expected_image_digest=f"sha256:{'c' * 64}",
    )
    mutated = copy.deepcopy(receipt)
    mutated["network_receipt"]["router"]["source_masquerade"] = False
    assert not observer_topology_receipt_valid(mutated)
    dumpable = copy.deepcopy(receipt)
    dumpable["controller_isolation"]["dumpable_before_client_spawn"] = 1
    assert not observer_topology_receipt_valid(dumpable)
    assert not observer_topology_receipt_valid(
        receipt,
        expected_image_digest=f"sha256:{'d' * 64}",
    )


def _evidence(
    runner: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    items = runner["jobs"][0]["items"]
    capture_times = [_RELEASE_TAI_NS + 200_000, _RELEASE_TAI_NS + 250_000]
    packets = [
        {
            "schema_version": 1,
            "packet_index": index,
            "frame_number": index + 1,
            "capture_realtime_ns": capture_tai - _REALTIME_TO_TAI_NS,
            "source_address": item["source_address"],
            "destination_address": item["destination_address"],
            "udp_payload_bytes": item["udp_payload_bytes"],
            "datagram_sha256": item["datagram_sha256"],
        }
        for index, (item, capture_tai) in enumerate(zip(items, capture_times, strict=True))
    ]
    capture = {
        "schema_version": 2,
        "artifact_type": "qcsd-kernel-tx-router-capture",
        "capture_id": "3" * 64,
        "observer_role": "router-ingress-post-client-veth-pre-netem",
        "interface": "eth0",
        "timestamp_clock_id": "CLOCK_REALTIME",
        "timestamp_type": "host",
        "capture_start_realtime_ns": 1_063_000_000_000,
        "capture_end_realtime_ns": 1_064_000_000_000,
        "packets_received": 2,
        "packets_dropped": 0,
        "interface_packets_dropped": 0,
        "dumpcap_received_packets": 2,
        "dumpcap_returncode": 0,
        "pcapng_sha256": "b" * 64,
        "capture_active_at_stop": True,
        "router_state_start": _router_state(active=True),
        "router_state_end": _router_state(active=False),
        "capture_service_end_state": "idle-no-dumpcap-child",
    }
    network, binding, network_digest = _topology()
    evidence = build_kernel_tx_evidence(
        runner_receipt=runner,
        runner_run_json_sha256="a" * 64,
        qdisc_evidence={
            "schema_version": 1,
            "source": "tc-json-v1",
            "observed_contract": copy.deepcopy(runner["qdisc_contract"]),
            "installed_before_runner": True,
            "verified_after_runner": True,
            "restored_after_capture": True,
            "before": _snapshot(),
            "after": _snapshot(packets=1),
        },
        router_capture_receipt=capture,
        router_packets=packets,
        controlled_network_receipt=network,
        controlled_network_receipt_sha256=network_digest,
        controlled_observer_binding=binding,
    )
    return evidence, capture, packets


def _evidence_arguments(
    capture: dict[str, object], packets: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "expected_run_json_sha256": "a" * 64,
        "expected_router_capture_sha256": "b" * 64,
        "router_capture_receipt": capture,
        "router_packets": packets,
    }


def test_runner_schema_eleven_binds_raw_kernel_tx_without_rewriting_schema_ten() -> None:
    wakeups = _runner_wakeup_v11()

    assert kernel_tx_runner_receipt_valid(wakeups["buflo_kernel_tx"])
    assert kernel_tx_runner_receipt_success_valid(wakeups["buflo_kernel_tx"])
    assert fidelity._runner_wakeup_v11_valid(wakeups)
    assert fidelity._runner_wakeup_metrics_valid(wakeups)
    assert capture_session._runner_wakeup_metrics_valid(wakeups)
    assert fidelity._runner_wakeup_v10_valid(_runner_wakeup_receipt(10))

    wakeups["buflo_exact_incoming_retry_drives"] = 1
    assert not fidelity._runner_wakeup_v11_valid(wakeups)


def test_runner_schema_eleven_preserves_failed_before_arm_without_eligibility() -> None:
    wakeups = _runner_wakeup_v11()
    raw = _failed_before_arm_runner_receipt()
    wakeups["buflo_kernel_tx"] = raw

    assert kernel_tx_runner_receipt_valid(raw)
    assert not kernel_tx_runner_receipt_success_valid(raw)
    assert fidelity._runner_wakeup_v11_valid(wakeups)
    assert fidelity._runner_wakeup_metrics_valid(wakeups)
    assert capture_session._runner_wakeup_metrics_valid(wakeups)

    scheduler = copy.deepcopy(raw["runtime_contract"]["scheduler_initial"])
    run = {
        "process_scheduler": scheduler,
        "resolved_configuration": {"defense": {"kind": "buflo"}},
        "runner_wakeup_metrics": wakeups,
    }
    assert not capture_session._process_scheduler_bound_to_run_valid(
        run,
        expected_contract="qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
    )


def test_runner_schema_eleven_retains_null_kernel_receipt_for_other_modes() -> None:
    wakeups = _runner_wakeup_receipt(10)
    wakeups.update(
        {
            "schema_version": 11,
            "semantics": fidelity.RUNNER_WAKEUP_V11_SEMANTICS,
            "buflo_kernel_tx": None,
        }
    )

    assert fidelity._runner_wakeup_v11_valid(wakeups)
    assert capture_session._runner_wakeup_metrics_valid(wakeups)


def test_runner_schema_eleven_is_exact_key_and_clock_fail_closed() -> None:
    wakeups = _runner_wakeup_v11()
    wakeups["unexpected"] = None
    assert not fidelity._runner_wakeup_v11_valid(wakeups)

    raw = _runner_receipt()
    raw["clock_mapping"]["start"]["monotonic"]["tai_after_ns"] += 250_001
    raw["clock_mapping"]["start"]["monotonic"]["bracket_width_ns"] = 250_001
    raw["clock_mapping"]["max_observed_bracket_width_ns"] = 250_001
    assert not kernel_tx_runner_receipt_valid(raw)


def test_kernel_tx_schema_two_refines_realtime_and_preserves_schema_one() -> None:
    historical = _runner_receipt()
    current = _runner_receipt_v2()

    assert kernel_tx_runner_receipt_valid(historical)
    assert kernel_tx_runner_receipt_valid(current)
    assert kernel_tx_runner_receipt_success_valid(current)
    historical["semantics"] = KERNEL_TX_RUNNER_SEMANTICS
    assert not kernel_tx_runner_receipt_valid(historical)
    historical["semantics"] = kernel_tx.KERNEL_TX_HISTORICAL_RUNNER_SEMANTICS
    current["semantics"] = kernel_tx.KERNEL_TX_HISTORICAL_RUNNER_SEMANTICS
    assert not kernel_tx_runner_receipt_valid(current)
    current["semantics"] = KERNEL_TX_RUNNER_SEMANTICS
    wakeups = _runner_wakeup_v11()
    wakeups["buflo_kernel_tx"] = copy.deepcopy(current)
    assert fidelity._runner_wakeup_v11_valid(wakeups)
    assert capture_session._runner_wakeup_metrics_valid(wakeups)

    first = current["jobs"][0]["items"][0]
    first["provisional_tx_software_tai_lower_ns"] -= 1
    assert not kernel_tx_runner_receipt_valid(current)

    current = _runner_receipt_v2()
    del current["jobs"][0]["items"][0]["post_tx_clock_phase"]
    assert not kernel_tx_runner_receipt_valid(current)

    current = _runner_receipt_v2()
    current["jobs"][0]["items"][0]["schema_version"] = 1
    assert not kernel_tx_runner_receipt_valid(current)

    failed_before_arm = _failed_before_arm_runner_receipt()
    failed_before_arm["schema_version"] = 2
    failed_before_arm["semantics"] = KERNEL_TX_RUNNER_SEMANTICS
    assert kernel_tx_runner_receipt_valid(failed_before_arm)


def test_kernel_tx_schema_two_reconstructs_online_before_final_intersection() -> None:
    current = _runner_receipt_v2()
    mapping = current["clock_mapping"]
    assert isinstance(mapping, dict)

    def bounded_sample(
        clock_ns: int, lower_offset_ns: int, upper_offset_ns: int
    ) -> dict[str, int]:
        return {
            "schema_version": 1,
            "tai_before_ns": clock_ns + lower_offset_ns,
            "clock_ns": clock_ns,
            "tai_after_ns": clock_ns + upper_offset_ns,
            "bracket_width_ns": upper_offset_ns - lower_offset_ns,
        }

    mapping["start"]["realtime"] = bounded_sample(
        mapping["start"]["realtime"]["clock_ns"],
        _REALTIME_TO_TAI_NS,
        _REALTIME_TO_TAI_NS + 200,
    )
    mapping["end"]["realtime"] = bounded_sample(
        mapping["end"]["realtime"]["clock_ns"],
        _REALTIME_TO_TAI_NS + 60,
        _REALTIME_TO_TAI_NS + 140,
    )
    current["clock_start"] = copy.deepcopy(mapping["start"])
    current["clock_end"] = copy.deepcopy(mapping["end"])

    online_offsets = ((20, 180), (40, 160))
    for item, (lower_delta, upper_delta) in zip(
        current["jobs"][0]["items"], online_offsets, strict=True
    ):
        phase = item["post_tx_clock_phase"]
        phase["realtime"] = bounded_sample(
            phase["realtime"]["clock_ns"],
            _REALTIME_TO_TAI_NS + lower_delta,
            _REALTIME_TO_TAI_NS + upper_delta,
        )
        raw_tx = item["tx_software_realtime_ns"]
        item["provisional_tx_software_tai_lower_ns"] = (
            raw_tx + _REALTIME_TO_TAI_NS + lower_delta
        )
        item["provisional_tx_software_tai_upper_ns"] = (
            raw_tx + _REALTIME_TO_TAI_NS + upper_delta
        )
        for prefix in ("tx_sched", "tx_software"):
            raw_timestamp = item[f"{prefix}_realtime_ns"]
            final_lower = raw_timestamp + _REALTIME_TO_TAI_NS + 60
            final_upper = raw_timestamp + _REALTIME_TO_TAI_NS + 140
            item[f"{prefix}_tai_lower_ns"] = final_lower
            item[f"{prefix}_tai_upper_ns"] = final_upper
            item[f"{prefix}_tai_ns"] = (final_lower + final_upper) // 2

    mapping["effective_realtime_offset_lower_ns"] = _REALTIME_TO_TAI_NS + 60
    mapping["effective_realtime_offset_upper_ns"] = _REALTIME_TO_TAI_NS + 140
    mapping["max_observed_bracket_width_ns"] = 200
    mapping["max_observed_offset_drift_ns"] = 0
    current["aggregate"]["max_tx_software_lateness_ns"] = max(
        item["tx_software_tai_upper_ns"] - _RELEASE_TAI_NS
        for item in current["jobs"][0]["items"]
    )

    assert kernel_tx_runner_receipt_success_valid(current)

    # The final phase was unavailable online.  Substituting the narrower final
    # interval for the first item's wider provisional interval must fail.
    first = current["jobs"][0]["items"][0]
    first_raw_tx = first["tx_software_realtime_ns"]
    first["provisional_tx_software_tai_lower_ns"] = (
        first_raw_tx + _REALTIME_TO_TAI_NS + 60
    )
    first["provisional_tx_software_tai_upper_ns"] = (
        first_raw_tx + _REALTIME_TO_TAI_NS + 140
    )
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_matches_rust_ceil_midpoint_drift() -> None:
    current = _runner_receipt_v2()
    mapping = current["clock_mapping"]
    first = current["jobs"][0]["items"][0]
    phase = first["post_tx_clock_phase"]
    monotonic = phase["monotonic"]
    monotonic["tai_before_ns"] -= 1
    monotonic["bracket_width_ns"] = 1

    mapping["effective_monotonic_offset_lower_ns"] = _MONOTONIC_TO_TAI_NS - 1
    mapping["max_observed_bracket_width_ns"] = 1
    # Rust computes midpoint drift from doubled integer offsets and rounds the
    # half-nanosecond uncertainty upwards.
    mapping["max_observed_offset_drift_ns"] = 1

    assert kernel_tx_runner_receipt_success_valid(current)

    mapping["max_observed_offset_drift_ns"] = 0
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_uses_item_local_monotonic_corroboration() -> None:
    current = _runner_receipt_v2()
    mapping = current["clock_mapping"]
    first = current["jobs"][0]["items"][0]
    local_offset_delta_ns = 100
    monotonic = first["post_tx_clock_phase"]["monotonic"]
    monotonic["tai_before_ns"] -= local_offset_delta_ns
    monotonic["tai_after_ns"] -= local_offset_delta_ns
    mapping["effective_monotonic_offset_lower_ns"] -= local_offset_delta_ns
    mapping["max_observed_offset_drift_ns"] = local_offset_delta_ns

    # The mapping-wide union still overlaps the exact enqueue bracket, but the
    # item's own phase does not.  Schema two must reject that substitution.
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_typed_physical_window_failure() -> None:
    current = _runner_receipt_v2()
    job = current["jobs"][0]
    item = job["items"][1]
    deadline = job["deadline_tai_ns"]
    delta = deadline - item["tx_software_tai_ns"]
    item["tx_software_realtime_ns"] += delta
    for key in (
        "tx_software_tai_ns",
        "tx_software_tai_lower_ns",
        "tx_software_tai_upper_ns",
    ):
        item[key] = deadline
    for sample in item["post_tx_clock_phase"].values():
        sample["clock_ns"] += delta
        sample["tai_before_ns"] += delta
        sample["tai_after_ns"] += delta
    item["provisional_tx_software_tai_lower_ns"] = None
    item["provisional_tx_software_tai_upper_ns"] = None
    item["finalization_state"] = "physical-transmit-proven"
    item["terminal_outcome"] = "window-violation"
    item["terminal_error"] = "final_conservative_envelope_validation_failed"
    item["terminal_error_detail"] = (
        "item 1 failed final mapping: enqueue_complete=true, "
        "enqueue_clock_consistent=true, timestamp_complete=true, tx_order=true, "
        "physical_window=false, provisional_interval=false, endpoint_tuple=true, "
        "item_sequence=true, job_identity=true, controller_trace_finalized=false, "
        "structural_order=true"
    )
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic physical window failure"
    )

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    item["terminal_error_detail"] = None
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_window_failure_can_be_credit_causality() -> None:
    current = _runner_receipt_v2()
    job = current["jobs"][0]
    outgoing, incoming = job["items"]
    causal_violation = outgoing["tx_software_tai_upper_ns"] - 1
    incoming["enqueue_tai_ns"] = causal_violation
    incoming["enqueue_tai_lower_ns"] = causal_violation
    incoming["enqueue_tai_upper_ns"] = causal_violation
    incoming["enqueue_monotonic_ns"] = causal_violation - _MONOTONIC_TO_TAI_NS
    incoming["finalization_state"] = "physical-transmit-proven"
    incoming["terminal_outcome"] = "window-violation"
    incoming["terminal_error"] = "final_conservative_envelope_validation_failed"
    incoming["terminal_error_detail"] = (
        "item 1 failed final mapping: enqueue_complete=true, "
        "enqueue_clock_consistent=true, timestamp_complete=true, tx_order=true, "
        "physical_window=true, provisional_interval=true, endpoint_tuple=true, "
        "item_sequence=true, job_identity=true, controller_trace_finalized=false, "
        "structural_order=false"
    )
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic incoming-credit causality failure"
    )

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    incoming["enqueue_tai_lower_ns"] = outgoing["tx_software_tai_upper_ns"]
    incoming["enqueue_tai_upper_ns"] = outgoing["tx_software_tai_upper_ns"]
    incoming["enqueue_tai_ns"] = outgoing["tx_software_tai_upper_ns"]
    incoming["enqueue_monotonic_ns"] = (
        outgoing["tx_software_tai_upper_ns"] - _MONOTONIC_TO_TAI_NS
    )
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_rejects_incoming_tx_before_its_enqueue_lower() -> None:
    current = _runner_receipt_v2()
    incoming = current["jobs"][0]["items"][1]
    enqueue_tai_ns = incoming["tx_software_tai_lower_ns"] + 1
    incoming["enqueue_tai_ns"] = enqueue_tai_ns
    incoming["enqueue_tai_lower_ns"] = enqueue_tai_ns
    incoming["enqueue_tai_upper_ns"] = enqueue_tai_ns
    incoming["enqueue_monotonic_ns"] = enqueue_tai_ns - _MONOTONIC_TO_TAI_NS

    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_unfinalised_physical_item() -> None:
    current = _runner_receipt_v2()
    item = current["jobs"][0]["items"][1]
    item.update(
        {
            "finalization_state": "physical-transmit-proven",
            "terminal_outcome": "window-violation",
            "terminal_error": "final_conservative_envelope_validation_failed",
            "terminal_error_detail": (
                "item 1 failed final mapping: enqueue_complete=true, "
                "enqueue_clock_consistent=true, timestamp_complete=true, "
                "tx_order=true, physical_window=true, "
                "provisional_interval=true, endpoint_tuple=true, "
                "item_sequence=true, job_identity=true, "
                "controller_trace_finalized=false, structural_order=true"
            ),
        }
    )
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic post-physical controller interruption"
    )

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    item["terminal_error"] = "different_failure"
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_incremental_send_attempt_failure() -> None:
    current = _runner_receipt_v2()
    item = current["jobs"][0]["items"][1]
    attempt_before = _RELEASE_TAI_NS + 110_000
    item.update(
        {
            "socket_timestamp_id": None,
            "enqueue_monotonic_ns": None,
            "enqueue_tai_ns": None,
            "enqueue_tai_lower_ns": attempt_before,
            "enqueue_tai_upper_ns": None,
            "tx_sched_realtime_ns": None,
            "tx_sched_tai_ns": None,
            "tx_sched_tai_lower_ns": None,
            "tx_sched_tai_upper_ns": None,
            "tx_software_realtime_ns": None,
            "provisional_tx_software_tai_lower_ns": None,
            "provisional_tx_software_tai_upper_ns": None,
            "tx_software_tai_ns": None,
            "tx_software_tai_lower_ns": None,
            "tx_software_tai_upper_ns": None,
            "post_tx_clock_phase": None,
            "send_attempt": {
                "schema_version": 1,
                "kind": "immediate_post_main",
                "requested_txtime_tai_ns": None,
                "latest_enqueue_tai_ns": current["jobs"][0]["deadline_tai_ns"],
                "enqueue_before_tai_ns": attempt_before,
                "enqueue_monotonic_ns": None,
                "enqueue_after_tai_ns": None,
                "sendmsg_result": item["udp_payload_bytes"],
                "send_errno": None,
                "payload_bytes": item["udp_payload_bytes"],
                "source": item["source_address"],
                "destination": item["destination_address"],
                "tos": 0,
                "priority_method": "serialized_socket_so_priority",
            },
            "finalization_state": "helper-terminal-failure",
            "terminal_outcome": "timestamp-evidence-missing",
            "terminal_error": "io_error",
            "terminal_error_detail": "synthetic post-send clock failure",
        }
    )
    mapping = current["clock_mapping"]
    mapping["per_item_monotonic_evidence_count"] = 1
    mapping["per_item_realtime_evidence_count"] = 1
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic incremental send-attempt failure"
    )

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    item["send_attempt"]["enqueue_before_tai_ns"] += 1
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_pre_send_failure_without_enqueue() -> None:
    current = _runner_receipt_v2()
    job = current["jobs"][0]
    item = job["items"][0]
    job["items"] = [item]
    job["credit_identities"] = []
    job["helper_job_close"] = None
    for key in (
        "enqueue_monotonic_ns",
        "enqueue_tai_ns",
        "enqueue_tai_lower_ns",
        "enqueue_tai_upper_ns",
        "socket_timestamp_id",
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
        "post_tx_clock_phase",
    ):
        item[key] = None
    item.update(
        {
            "finalization_state": "helper-terminal-failure",
            "terminal_outcome": "timestamp-evidence-missing",
            "terminal_error": "enqueue_deadline",
            "terminal_error_detail": "synthetic cutoff reached before sendmsg",
        }
    )
    current["clock_mapping"]["per_item_monotonic_evidence_count"] = 0
    current["clock_mapping"]["per_item_realtime_evidence_count"] = 0
    current["aggregate"].update(
        {
            "item_count": 1,
            "ordered_item_count": 0,
            "captured_credit_identity_count": 0,
            "carrier_credit_identity_count": 0,
        }
    )
    _refresh_failed_runner_receipt(current, primary_error="synthetic pre-send failure")

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    item["enqueue_tai_upper_ns"] = item["target_tai_ns"]
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_partial_kernel_timestamp_failure() -> None:
    current = _runner_receipt_v2()
    item = current["jobs"][0]["items"][1]
    item.update(
        {
            "tx_software_realtime_ns": None,
            "tx_software_tai_ns": None,
            "tx_software_tai_lower_ns": None,
            "tx_software_tai_upper_ns": None,
            "post_tx_clock_phase": None,
            "provisional_tx_software_tai_lower_ns": None,
            "provisional_tx_software_tai_upper_ns": None,
            "finalization_state": "helper-terminal-failure",
            "terminal_outcome": "timestamp-evidence-missing",
            "terminal_error": "report_timeout",
            "terminal_error_detail": "synthetic TX_SCHED-only timeout",
        }
    )
    current["clock_mapping"]["per_item_monotonic_evidence_count"] = 1
    current["clock_mapping"]["per_item_realtime_evidence_count"] = 1
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic partial timestamp failure"
    )

    assert kernel_tx_runner_receipt_valid(current)

    unmapped = copy.deepcopy(current)
    mapping_error = "BuFLO final clock sample failed: synthetic"
    unmapped.update(
        {
            "cleanup_errors": [mapping_error],
            "clock_end": None,
            "clock_mapping_valid": False,
            "clock_mapping_error": mapping_error,
            "clock_mapping": None,
        }
    )
    outgoing, failed = unmapped["jobs"][0]["items"]
    for candidate in (outgoing, failed):
        _clear_final_clock_translations(candidate)
    outgoing["terminal_outcome"] = "timestamp-evidence-missing"
    outgoing["terminal_error"] = "final_conservative_envelope_validation_failed"
    outgoing["terminal_error_detail"] = _schema_two_unmapped_error_detail(outgoing)
    _refresh_failed_runner_receipt(unmapped, primary_error=mapping_error)
    assert kernel_tx_runner_receipt_valid(unmapped)


def test_kernel_tx_schema_two_accepts_post_tx_clock_sample_failure() -> None:
    current = _runner_receipt_v2()
    item = current["jobs"][0]["items"][1]
    item["post_tx_clock_phase"] = None
    item["provisional_tx_software_tai_lower_ns"] = None
    item["provisional_tx_software_tai_upper_ns"] = None
    item["finalization_state"] = "physical-transmit-proven"
    item["terminal_outcome"] = "timestamp-evidence-missing"
    item["terminal_error"] = "clock_sample_failed"
    item["terminal_error_detail"] = "synthetic post-transmit clock sample failure"
    mapping = current["clock_mapping"]
    mapping["per_item_monotonic_evidence_count"] = 1
    mapping["per_item_realtime_evidence_count"] = 1
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic post-transmit clock sample failure"
    )

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    item["terminal_outcome"] = "window-violation"
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic post-transmit clock sample failure"
    )
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_controller_finalization_failure() -> None:
    current = _runner_receipt_v2()
    item = current["jobs"][0]["items"][1]
    item["finalization_state"] = "physical-transmit-proven"
    item["terminal_outcome"] = "controller-trace-finalization-failed"
    item["terminal_error"] = "controller_or_trace_finalization_failed"
    item["terminal_error_detail"] = "synthetic controller finalization failure"
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic controller finalization failure"
    )

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    item["provisional_tx_software_tai_lower_ns"] = None
    item["provisional_tx_software_tai_upper_ns"] = None
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_terminal_txtime_failure() -> None:
    current = _runner_receipt_v2()
    job = current["jobs"][0]
    item = job["items"][0]
    job["items"] = [item]
    job["credit_identities"] = []
    job["helper_job_close"] = None
    item.update(
        {
            "socket_timestamp_id": None,
            "tx_sched_realtime_ns": None,
            "tx_sched_tai_ns": None,
            "tx_sched_tai_lower_ns": None,
            "tx_sched_tai_upper_ns": None,
            "tx_software_realtime_ns": None,
            "provisional_tx_software_tai_lower_ns": None,
            "provisional_tx_software_tai_upper_ns": None,
            "tx_software_tai_ns": None,
            "tx_software_tai_lower_ns": None,
            "tx_software_tai_upper_ns": None,
            "post_tx_clock_phase": None,
            "txtime_error": {
                "family": "ipv4",
                "errno": 125,
                "kind": "missed",
                "requested_txtime_tai_ns": item["scm_txtime_tai_ns"],
            },
            "finalization_state": "helper-terminal-failure",
            "terminal_outcome": "txtime-error",
            "terminal_error": "txtime_missed",
            "terminal_error_detail": "synthetic ETF deadline miss",
        }
    )
    mapping = current["clock_mapping"]
    mapping["per_item_monotonic_evidence_count"] = 0
    mapping["per_item_realtime_evidence_count"] = 0
    current["aggregate"].update(
        {
            "item_count": 1,
            "ordered_item_count": 0,
            "captured_credit_identity_count": 0,
            "carrier_credit_identity_count": 0,
        }
    )
    _refresh_failed_runner_receipt(current, primary_error="synthetic txtime failure")

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    item["txtime_error"]["requested_txtime_tai_ns"] += 1
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_immediate_txtime_mismatch_failure() -> None:
    current = _runner_receipt_v2()
    item = current["jobs"][0]["items"][1]
    item.update(
        {
            "socket_timestamp_id": item["socket_timestamp_id"],
            "tx_software_realtime_ns": None,
            "tx_software_tai_ns": None,
            "tx_software_tai_lower_ns": None,
            "tx_software_tai_upper_ns": None,
            "post_tx_clock_phase": None,
            "provisional_tx_software_tai_lower_ns": None,
            "provisional_tx_software_tai_upper_ns": None,
            "txtime_error": {
                "family": "ipv4",
                "errno": 125,
                "kind": "missed",
                "requested_txtime_tai_ns": 123,
            },
            "finalization_state": "helper-terminal-failure",
            "terminal_outcome": "txtime-error",
            "terminal_error": "txtime_drop_mismatch",
            "terminal_error_detail": "synthetic stray TXTIME diagnostic",
        }
    )
    mapping = current["clock_mapping"]
    mapping["per_item_monotonic_evidence_count"] = 1
    mapping["per_item_realtime_evidence_count"] = 1
    _refresh_failed_runner_receipt(
        current, primary_error="synthetic immediate TXTIME mismatch"
    )

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    item["terminal_error"] = "txtime_missed"
    assert not kernel_tx_runner_receipt_valid(current)

    item["terminal_error"] = "txtime_drop_mismatch"
    item["txtime_error"]["requested_txtime_tai_ns"] = 0
    assert not kernel_tx_runner_receipt_valid(current)

    item["terminal_error"] = "txtime_missed"
    assert kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_binds_mapping_failure_to_first_bad_phase() -> None:
    current = _runner_receipt_v2()
    mapping_error = (
        "BuFLO kernel item 0 retained an out-of-order post-TX clock phase"
    )
    current.update(
        {
            "cleanup_errors": [mapping_error],
            "clock_mapping_valid": False,
            "clock_mapping_error": mapping_error,
            "clock_mapping": None,
        }
    )
    for item in current["jobs"][0]["items"]:
        for sample in item["post_tx_clock_phase"].values():
            sample["clock_ns"] += 2_000_000_000
            sample["tai_before_ns"] += 2_000_000_000
            sample["tai_after_ns"] += 2_000_000_000
        _clear_final_clock_translations(item)
        item["terminal_outcome"] = "timestamp-evidence-missing"
        item["terminal_error"] = "final_conservative_envelope_validation_failed"
        item["terminal_error_detail"] = _schema_two_unmapped_error_detail(item)
    _refresh_failed_runner_receipt(current, primary_error=mapping_error)

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    wrong_error = "BuFLO kernel item 1 retained an out-of-order post-TX clock phase"
    current["clock_mapping_error"] = wrong_error
    current["cleanup_errors"] = [wrong_error]
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_binds_mapping_failure_to_local_tx_evidence() -> None:
    current = _runner_receipt_v2()
    mapping_error = (
        "BuFLO kernel item 1 clock phase preceded its retained transmission evidence"
    )
    current.update(
        {
            "cleanup_errors": [mapping_error],
            "clock_mapping_valid": False,
            "clock_mapping_error": mapping_error,
            "clock_mapping": None,
        }
    )
    for item in current["jobs"][0]["items"]:
        _clear_final_clock_translations(item)
        item["terminal_outcome"] = "timestamp-evidence-missing"
        item["terminal_error"] = "final_conservative_envelope_validation_failed"
        item["terminal_error_detail"] = _schema_two_unmapped_error_detail(item)
    failed_item = current["jobs"][0]["items"][1]
    failed_item["tx_software_realtime_ns"] = (
        failed_item["post_tx_clock_phase"]["realtime"]["clock_ns"] + 1
    )
    failed_item["tx_sched_realtime_ns"] = failed_item["tx_software_realtime_ns"]
    _refresh_failed_runner_receipt(current, primary_error=mapping_error)

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    wrong_error = (
        "BuFLO kernel item 0 clock phase preceded its retained transmission evidence"
    )
    current["clock_mapping_error"] = wrong_error
    current["cleanup_errors"] = [wrong_error]
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_accepts_typed_start_end_chronology_failure() -> None:
    current = _runner_receipt_v2()
    mapping_error = (
        "BuFLO kernel clock phases and Instant anchor were not temporally ordered"
    )
    current.update(
        {
            "cleanup_errors": [mapping_error],
            "clock_mapping_valid": False,
            "clock_mapping_error": mapping_error,
            "clock_mapping": None,
        }
    )
    for clock in ("monotonic", "realtime"):
        start_sample = current["clock_start"][clock]
        end_sample = current["clock_end"][clock]
        shift = end_sample["clock_ns"] - start_sample["clock_ns"] + 1
        end_sample["clock_ns"] -= shift
        end_sample["tai_before_ns"] -= shift
        end_sample["tai_after_ns"] -= shift
    for item in current["jobs"][0]["items"]:
        _clear_final_clock_translations(item)
        item["terminal_outcome"] = "timestamp-evidence-missing"
        item["terminal_error"] = "final_conservative_envelope_validation_failed"
        item["terminal_error_detail"] = _schema_two_unmapped_error_detail(item)
    _refresh_failed_runner_receipt(current, primary_error=mapping_error)

    assert kernel_tx_runner_receipt_valid(current)
    assert not kernel_tx_runner_receipt_success_valid(current)

    wrong_error = "BuFLO final clock sample failed: synthetic"
    current["clock_mapping_error"] = wrong_error
    current["cleanup_errors"] = [wrong_error]
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_binds_all_derived_mapping_failures() -> None:
    start_end_empty = _runner_receipt_v2()
    empty_error = "BuFLO kernel start/end realtime offset intersection was empty"
    end_realtime = start_end_empty["clock_end"]["realtime"]
    end_realtime["tai_before_ns"] += 1
    end_realtime["tai_after_ns"] += 1
    _make_schema_two_mapping_failure(start_end_empty, mapping_error=empty_error)
    assert kernel_tx_runner_receipt_valid(start_end_empty)

    item_empty = _runner_receipt_v2()
    item_error = (
        "BuFLO kernel realtime offset intersection became empty at item 1"
    )
    item_realtime = item_empty["jobs"][0]["items"][1]["post_tx_clock_phase"][
        "realtime"
    ]
    item_realtime["tai_before_ns"] += 1
    item_realtime["tai_after_ns"] += 1
    _make_schema_two_mapping_failure(item_empty, mapping_error=item_error)
    assert kernel_tx_runner_receipt_valid(item_empty)
    item_empty["clock_mapping_error"] = (
        "BuFLO kernel realtime offset intersection became empty at item 0"
    )
    item_empty["cleanup_errors"] = [item_empty["clock_mapping_error"]]
    assert not kernel_tx_runner_receipt_valid(item_empty)

    unsupported = _runner_receipt_v2()
    _make_schema_two_mapping_failure(
        unsupported, mapping_error="synthetic unsupported mapping failure"
    )
    assert not kernel_tx_runner_receipt_valid(unsupported)


def test_kernel_tx_schema_two_retains_large_monotonic_drift_as_exact_diagnostic() -> None:
    current = _runner_receipt_v2()
    mapping = current["clock_mapping"]
    drift_ns = 5_000_000
    mapping["end"]["monotonic"]["clock_ns"] -= drift_ns
    current["clock_end"]["monotonic"]["clock_ns"] -= drift_ns
    mapping["effective_monotonic_offset_upper_ns"] += drift_ns
    mapping["max_observed_offset_drift_ns"] = drift_ns

    assert kernel_tx_runner_receipt_success_valid(current)

    mapping["max_observed_offset_drift_ns"] -= 1
    assert not kernel_tx_runner_receipt_valid(current)


def test_kernel_tx_schema_two_constants_match_the_rust_producer() -> None:
    source = (Path(__file__).parents[1] / "neqo-qcsd/neqo-bin/src/qcsd/mod.rs").read_text(
        encoding="utf-8"
    )
    runner_prefix = 'const BUFLO_KERNEL_TX_SEMANTICS: &str = "'
    runner_line = next(
        line for line in source.splitlines() if line.startswith(runner_prefix)
    )
    assert runner_line.endswith('";')
    assert KERNEL_TX_RUNNER_SEMANTICS == runner_line[len(runner_prefix) : -2]
    mapping_prefix = 'const BUFLO_KERNEL_CLOCK_MAPPING_SEMANTICS: &str = "'
    mapping_line = next(
        line for line in source.splitlines() if line.startswith(mapping_prefix)
    )
    assert mapping_line.endswith('";')
    assert (
        kernel_tx._EFFECTIVE_ENVELOPE_SEMANTICS_V2
        == mapping_line[len(mapping_prefix) : -2]
    )
    assert "const BUFLO_KERNEL_TX_RECEIPT_SCHEMA_VERSION: u32 = 2;" in source
    assert "const BUFLO_KERNEL_ITEM_RECEIPT_SCHEMA_VERSION: u32 = 2;" in source
    assert "const BUFLO_KERNEL_CLOCK_MAPPING_SCHEMA_VERSION: u32 = 2;" in source

    raw = _runner_receipt()
    raw["clock_start"] = None
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["clock_mapping_valid"] = False
    assert not kernel_tx_runner_receipt_valid(raw)


def test_runner_kernel_tx_validates_the_exact_per_item_clock_envelope() -> None:
    raw = _runner_receipt()
    mapping = raw["clock_mapping"]
    first = raw["jobs"][0]["items"][0]
    first_enqueue = first["enqueue_tai_ns"]
    first_tx = first["tx_software_tai_ns"]
    first["enqueue_tai_lower_ns"] = first_enqueue - 7
    first["enqueue_tai_upper_ns"] = first_enqueue + 9
    first["enqueue_tai_ns"] = first_enqueue + 1
    first["provisional_tx_software_tai_lower_ns"] = first_tx - 10
    first["provisional_tx_software_tai_upper_ns"] = first_tx + 20
    mapping.update(
        {
            "effective_monotonic_offset_lower_ns": _MONOTONIC_TO_TAI_NS - 7,
            "effective_monotonic_offset_upper_ns": _MONOTONIC_TO_TAI_NS + 9,
            "effective_realtime_offset_lower_ns": _REALTIME_TO_TAI_NS - 10,
            "effective_realtime_offset_upper_ns": _REALTIME_TO_TAI_NS + 20,
            "max_observed_bracket_width_ns": 30,
            "max_observed_offset_drift_ns": 5,
        }
    )
    for item in raw["jobs"][0]["items"]:
        for prefix in ("tx_sched", "tx_software"):
            observed = item[f"{prefix}_realtime_ns"]
            lower = observed + _REALTIME_TO_TAI_NS - 10
            upper = observed + _REALTIME_TO_TAI_NS + 20
            item[f"{prefix}_tai_lower_ns"] = lower
            item[f"{prefix}_tai_upper_ns"] = upper
            item[f"{prefix}_tai_ns"] = lower + (upper - lower) // 2
    raw["aggregate"]["max_tx_software_lateness_ns"] = max(
        item["tx_software_tai_upper_ns"] - item["target_tai_ns"]
        for item in raw["jobs"][0]["items"]
    )

    assert kernel_tx_runner_receipt_valid(raw)

    raw["clock_mapping"]["per_item_realtime_evidence_count"] = 1
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    first = raw["jobs"][0]["items"][0]
    first["enqueue_tai_lower_ns"] -= 125_000
    first["enqueue_tai_upper_ns"] += 125_001
    first["enqueue_tai_ns"] = (
        first["enqueue_tai_lower_ns"] + first["enqueue_tai_upper_ns"]
    ) // 2
    raw["clock_mapping"]["effective_monotonic_offset_lower_ns"] -= 125_000
    raw["clock_mapping"]["effective_monotonic_offset_upper_ns"] += 125_001
    raw["clock_mapping"]["max_observed_bracket_width_ns"] = 250_001
    assert not kernel_tx_runner_receipt_valid(raw)


def test_runner_kernel_tx_rejects_wrong_qdisc_or_nonterminal_txtime_error() -> None:
    raw = _runner_receipt()
    raw["qdisc_contract"]["deadline_mode"] = True
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["qdisc_contract"]["ordinary_socket_priority"] = False
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["aggregate"]["job_count"] = True
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    item = raw["jobs"][0]["items"][0]
    item["terminal_outcome"] = "txtime-error"
    item["tx_software_realtime_ns"] = None
    item["tx_software_tai_ns"] = None
    assert not kernel_tx_runner_receipt_valid(raw)


def test_runner_kernel_tx_accepts_preferred_scm_priority_and_requires_serialized_reset() -> None:
    raw = _runner_receipt()
    contract = raw["qdisc_contract"]
    contract.update(
        {
            "priority_method": "per_datagram_scm_priority",
            "scm_priority_supported": True,
            "so_priority_during": 0,
        }
    )
    for setup in raw["runtime_contract"]["socket_setup"]:
        setup.update(
            {
                "priority_method": "per_datagram_scm_priority",
                "scm_priority_supported": True,
                "scm_priority_probe_errno": None,
            }
        )
    assert kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["qdisc_contract"]["so_priority_reset_valid"] = False
    assert not kernel_tx_runner_receipt_valid(raw)


def test_runner_kernel_tx_requires_exact_scheduler_socket_and_privilege_receipts() -> None:
    raw = _runner_receipt()
    raw["runtime_contract"]["scheduler_initial"]["source"] = (
        "linux-proc-sched-affinity-v1"
    )
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["runtime_contract"]["scheduler_initial"]["contract_valid"] = False
    assert not kernel_tx_runner_receipt_valid(raw)

    for invalid_flags in (0, 1, 2.0, 3):
        raw = _runner_receipt()
        raw["runtime_contract"]["socket_setup"][0]["txtime_flags"] = invalid_flags
        assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["runtime_contract"]["socket_setup"][0]["timestamping_report_flags"] = 16
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["runtime_contract"]["socket_setup"][0]["scm_priority_probe_errno"] = 1
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["runtime_contract"]["socket_setup"][0]["family"] = "ipv6"
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["runtime_contract"]["privilege_drop"]["cap_effective"] = "0"
    assert not kernel_tx_runner_receipt_valid(raw)


def test_top_scheduler_allows_bounded_setup_caps_only_with_nested_buflo_proof() -> None:
    wakeups = _runner_wakeup_v11()
    raw = wakeups["buflo_kernel_tx"]
    scheduler = copy.deepcopy(raw["runtime_contract"]["scheduler_initial"])
    run = {
        "process_scheduler": scheduler,
        "resolved_configuration": {"defense": {"kind": "buflo"}},
        "runner_wakeup_metrics": wakeups,
    }
    contract = "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"

    assert capture_session._process_scheduler_bound_to_run_valid(
        run,
        expected_contract=contract,
    )

    non_buflo = copy.deepcopy(run)
    non_buflo["resolved_configuration"]["defense"]["kind"] = "none"
    assert not capture_session._process_scheduler_bound_to_run_valid(
        non_buflo,
        expected_contract=contract,
    )
    non_buflo["process_scheduler"]["effective_capabilities_hex"] = "0000000000000000"
    assert capture_session._process_scheduler_bound_to_run_valid(
        non_buflo,
        expected_contract=contract,
    )

    missing_drop_proof = copy.deepcopy(run)
    missing_drop_proof["runner_wakeup_metrics"]["buflo_kernel_tx"]["runtime_contract"][
        "privilege_drop"
    ]["cap_effective"] = "0000000000001100"
    assert not capture_session._process_scheduler_bound_to_run_valid(
        missing_drop_proof,
        expected_contract=contract,
    )

    mismatched_initial = copy.deepcopy(run)
    mismatched_initial["process_scheduler"]["effective_capabilities_hex"] = (
        "0000000000000000"
    )
    assert not capture_session._process_scheduler_bound_to_run_valid(
        mismatched_initial,
        expected_contract=contract,
    )
    mismatched_initial["process_scheduler"]["effective_capabilities_hex"] = (
        "0000000000001100"
    )
    mismatched_initial["runner_wakeup_metrics"]["buflo_kernel_tx"]["runtime_contract"][
        "scheduler_initial"
    ]["effective_capabilities_hex"] = "0000000000000000"
    assert not capture_session._process_scheduler_bound_to_run_valid(
        mismatched_initial,
        expected_contract=contract,
    )


def test_runner_kernel_tx_accepts_terminal_txtime_error_but_not_as_success() -> None:
    raw = _failed_before_arm_runner_receipt()

    assert kernel_tx_runner_receipt_valid(raw)
    assert not kernel_tx_runner_receipt_success_valid(raw)


def test_failed_runner_retains_create_only_raw_qdisc_observation(
    tmp_path: Path,
) -> None:
    observation = {
        "schema_version": 1,
        "source": "tc-json-v1",
        "installed_before_runner": True,
        "verified_after_runner": True,
        "restored_after_capture": True,
        "before": _snapshot(),
        "after": _snapshot(packets=1),
    }
    diagnostics = tmp_path / "diagnostics"
    path = capture_session._persist_kernel_qdisc_observation(
        diagnostics,
        observation,
    )
    original = path.read_bytes()
    assert path.name == "kernel-tx-qdisc-observation.json"
    assert path.read_text(encoding="utf-8").endswith("\n")
    assert json.loads(original) == observation

    failed_runner = _failed_before_arm_runner_receipt()
    assert kernel_tx_runner_receipt_valid(failed_runner)
    assert not kernel_tx_runner_receipt_success_valid(failed_runner)
    with pytest.raises(ValueError, match="successful raw runner receipt"):
        build_kernel_tx_evidence(
            runner_receipt=failed_runner,
            runner_run_json_sha256="a" * 64,
            qdisc_evidence=observation,
            router_capture_receipt={},
            router_packets=[],
            controlled_network_receipt={},
            controlled_network_receipt_sha256="b" * 64,
            controlled_observer_binding={},
        )
    assert not (diagnostics / "kernel-tx-evidence.json").exists()

    changed = copy.deepcopy(observation)
    changed["after"]["drops"] = 1
    with pytest.raises(FileExistsError):
        capture_session._persist_kernel_qdisc_observation(diagnostics, changed)
    assert path.read_bytes() == original


@pytest.mark.parametrize("runner_schema_version", [1, 2])
def test_runner_kernel_tx_serialises_end_clock_mapping_failure_after_jobs(
    runner_schema_version: int,
) -> None:
    raw = _runner_receipt_v2() if runner_schema_version == 2 else _runner_receipt()
    mapping_error = "BuFLO final clock sample failed: synthetic"
    raw.update(
        {
            "terminal_outcome": "failed",
            "cleanup_errors": [mapping_error],
            "clock_end": None,
            "clock_mapping_valid": False,
            "clock_mapping_error": mapping_error,
            "clock_mapping": None,
            "terminal_errors": ["final conservative mapping unavailable"],
        }
    )
    job = raw["jobs"][0]
    job["terminal_error"] = (
        "job did not retain complete conservative kernel timing evidence"
    )
    job["terminal_outcome"] = "failed"
    for item in job["items"]:
        for key in (
            "tx_sched_tai_ns",
            "tx_sched_tai_lower_ns",
            "tx_sched_tai_upper_ns",
            "tx_software_tai_ns",
            "tx_software_tai_lower_ns",
            "tx_software_tai_upper_ns",
        ):
            item[key] = None
        item["terminal_error"] = "final_conservative_envelope_validation_failed"
        item["terminal_error_detail"] = (
            _schema_two_unmapped_error_detail(item)
            if runner_schema_version == 2
            else "synthetic final mapping failure"
        )
        item["terminal_outcome"] = "timestamp-evidence-missing"
    raw["aggregate"].update(
        {
            "transmitted_item_count": 0,
            "failed_item_count": 2,
            "tx_sched_timestamp_count": 0,
            "tx_software_timestamp_count": 0,
            "timestamp_evidence_missing_count": 2,
            "max_tx_software_lateness_ns": 0,
            "terminal_outcome": "failed",
        }
    )

    assert kernel_tx_runner_receipt_valid(raw)
    assert not kernel_tx_runner_receipt_success_valid(raw)

    if runner_schema_version == 2:
        # A mapping failure does not erase the retained item phases.  Their
        # producer order remains independently verifiable even without a final
        # mapping or end phase.
        first_phase = raw["jobs"][0]["items"][0]["post_tx_clock_phase"]
        for clock in ("monotonic", "realtime"):
            first_phase[clock]["clock_ns"] += 1_000_000
            first_phase[clock]["tai_before_ns"] += 1_000_000
            first_phase[clock]["tai_after_ns"] += 1_000_000
        assert not kernel_tx_runner_receipt_valid(raw)

    raw["jobs"][0]["items"][0]["tx_software_tai_ns"] = _RELEASE_TAI_NS
    assert not kernel_tx_runner_receipt_valid(raw)


def test_runner_kernel_tx_requires_controller_finalization_and_receipts_preparation_failure(
) -> None:
    raw = _runner_receipt()
    raw["jobs"][0]["items"][0]["finalization_state"] = "physical-transmit-proven"
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["jobs"][0]["items"][0]["endpoint_index"] = 0
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    failure = {
        "schema_version": 1,
        "job_id": 0,
        "endpoint_index": 0,
        "endpoint": 0,
        "failure": {
            "schema_version": 1,
            "stage": "test-output",
            "transport_output_mutated": False,
            "observations_drained": False,
            "batch_source_address": None,
            "batch_destination_address": None,
            "batch_datagram_count": 0,
            "batch_datagram_lengths": [],
            "batch_sha256": None,
            "batch_hash_error": None,
            "observation_count": 0,
            "built_composition_count": 0,
            "satisfied_datagram_count": 0,
            "attributed_datagram_count": 0,
            "error": "synthetic preparation failure",
        },
    }
    raw["terminal_outcome"] = "failed"
    raw["primary_error"] = "prepared output failed"
    raw["terminal_errors"] = ["prepared output failed"]
    raw["jobs"][0]["prepared_output_failure"] = failure
    raw["jobs"][0]["terminal_error"] = "prepared output failed"
    raw["jobs"][0]["terminal_outcome"] = "failed"
    raw["aggregate"]["prepared_output_failure_count"] = 1
    raw["aggregate"]["terminal_outcome"] = "failed"

    assert kernel_tx_runner_receipt_valid(raw)
    assert not kernel_tx_runner_receipt_success_valid(raw)

    raw["aggregate"]["prepared_output_failure_count"] = 0
    assert not kernel_tx_runner_receipt_valid(raw)


def test_runner_kernel_tx_rejects_malformed_job_items_without_raising() -> None:
    raw = _runner_receipt()
    raw["jobs"][0]["items"] = None
    assert not kernel_tx_runner_receipt_valid(raw)

    raw = _runner_receipt()
    raw["jobs"][0]["items"][0] = None
    assert not kernel_tx_runner_receipt_valid(raw)


def test_lab_evidence_binds_qdisc_capture_and_every_ordered_item() -> None:
    runner = _runner_receipt()
    evidence, capture, packets = _evidence(runner)
    arguments = _evidence_arguments(capture, packets)

    assert kernel_tx_evidence_valid(
        evidence,
        runner_receipt=runner,
        **arguments,
    )
    assert kernel_tx_evidence_success_valid(
        evidence,
        runner_receipt=runner,
        **arguments,
    )


def test_lab_evidence_accepts_only_receipted_public_routed_nat_observer() -> None:
    runner = _runner_receipt()
    _controlled_evidence, capture, packets = _evidence(runner)
    capture["router_state_start"] = _public_router_state(active=True)
    capture["router_state_end"] = _public_router_state(active=False)
    network, binding, network_digest = _public_topology()
    evidence = build_kernel_tx_evidence(
        runner_receipt=runner,
        runner_run_json_sha256="a" * 64,
        qdisc_evidence={
            "schema_version": 1,
            "source": "tc-json-v1",
            "observed_contract": copy.deepcopy(runner["qdisc_contract"]),
            "installed_before_runner": True,
            "verified_after_runner": True,
            "restored_after_capture": True,
            "before": _snapshot(),
            "after": _snapshot(packets=1),
        },
        router_capture_receipt=capture,
        router_packets=packets,
        controlled_network_receipt=network,
        controlled_network_receipt_sha256=network_digest,
        controlled_observer_binding=binding,
    )
    arguments = _evidence_arguments(capture, packets)

    assert kernel_tx_evidence_success_valid(
        evidence, runner_receipt=runner, **arguments
    )

    evidence["post_veth_capture"]["router_state_end"]["invariants"][
        "source_masquerade_present"
    ] = False
    capture["router_state_end"]["invariants"]["source_masquerade_present"] = False
    assert not kernel_tx_evidence_valid(
        evidence, runner_receipt=runner, **arguments
    )


def test_lab_evidence_rejects_hash_identity_and_capture_order_mutations() -> None:
    runner = _runner_receipt()
    evidence, capture, packets = _evidence(runner)
    arguments = _evidence_arguments(capture, packets)
    evidence["runner_kernel_tx_sha256"] = "0" * 64
    assert not kernel_tx_evidence_valid(
        evidence, runner_receipt=runner, **arguments
    )

    evidence, capture, packets = _evidence(runner)
    arguments = _evidence_arguments(capture, packets)
    evidence["reconciliations"][1]["item_id"] = 0
    assert not kernel_tx_evidence_valid(
        evidence, runner_receipt=runner, **arguments
    )

    evidence, capture, packets = _evidence(runner)
    arguments = _evidence_arguments(capture, packets)
    evidence["reconciliations"][1]["capture_packet_index"] = 6
    assert not kernel_tx_evidence_valid(
        evidence, runner_receipt=runner, **arguments
    )


def test_lab_evidence_enforces_post_veth_half_open_window() -> None:
    runner = _runner_receipt()
    _evidence_value, capture, packets = _evidence(runner)
    packets[0]["capture_realtime_ns"] = (
        _RELEASE_TAI_NS + 5_000_000 - _REALTIME_TO_TAI_NS
    )
    network, binding, network_digest = _topology()
    evidence = build_kernel_tx_evidence(
        runner_receipt=runner,
        runner_run_json_sha256="a" * 64,
        qdisc_evidence={
            "schema_version": 1,
            "source": "tc-json-v1",
            "observed_contract": copy.deepcopy(runner["qdisc_contract"]),
            "installed_before_runner": True,
            "verified_after_runner": True,
            "restored_after_capture": True,
            "before": _snapshot(),
            "after": _snapshot(packets=1),
        },
        router_capture_receipt=capture,
        router_packets=packets,
        controlled_network_receipt=network,
        controlled_network_receipt_sha256=network_digest,
        controlled_observer_binding=binding,
    )
    arguments = _evidence_arguments(capture, packets)
    assert kernel_tx_evidence_valid(evidence, runner_receipt=runner, **arguments)
    assert not kernel_tx_evidence_success_valid(evidence, runner_receipt=runner, **arguments)


def test_lab_evidence_preserves_drop_receipt_but_blocks_success() -> None:
    runner = _runner_receipt()
    evidence, capture, packets = _evidence(runner)
    arguments = _evidence_arguments(capture, packets)
    evidence["qdisc"]["after"]["drops"] = 1
    evidence["aggregate"]["qdisc_drop_count"] = 1

    assert kernel_tx_evidence_valid(
        evidence, runner_receipt=runner, **arguments
    )
    assert not kernel_tx_evidence_success_valid(
        evidence, runner_receipt=runner, **arguments
    )


def test_lab_evidence_requires_exact_nested_keys_and_zero_capture_drops_for_success() -> None:
    runner = _runner_receipt()
    evidence, capture, packets = _evidence(runner)
    arguments = _evidence_arguments(capture, packets)
    evidence["post_veth_capture"]["unexpected"] = None
    assert not kernel_tx_evidence_valid(
        evidence, runner_receipt=runner, **arguments
    )

    evidence, capture, packets = _evidence(runner)
    arguments = _evidence_arguments(capture, packets)
    evidence["aggregate"]["job_count"] = True
    assert not kernel_tx_evidence_valid(
        evidence, runner_receipt=runner, **arguments
    )

    evidence, capture, packets = _evidence(runner)
    arguments = _evidence_arguments(capture, packets)
    evidence["post_veth_capture"]["packets_dropped"] = 1
    capture["packets_dropped"] = 1
    evidence["aggregate"]["capture_drop_count"] = 1
    assert kernel_tx_evidence_valid(
        evidence, runner_receipt=runner, **arguments
    )
    assert not kernel_tx_evidence_success_valid(
        evidence, runner_receipt=runner, **arguments
    )
