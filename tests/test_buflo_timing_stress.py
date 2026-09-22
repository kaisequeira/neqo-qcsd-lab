from __future__ import annotations

import csv
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from qcsd_lab import buflo_study
from qcsd_lab.fidelity import SCHEDULE_PREFIX_FIELDS, SCHEDULE_QCSD_FIELDS
from qcsd_lab.kernel_tx import build_observer_topology_receipt
from qcsd_lab.parameters import (
    PREVIOUS_TIMING_STRESS_INPUT_POLICY,
    PREVIOUS_TIMING_STRESS_V2_INPUT_POLICY,
    PREVIOUS_TIMING_STRESS_V3_INPUT_POLICY,
    PREVIOUS_TIMING_STRESS_V4_INPUT_POLICY,
    TIMING_STRESS_INPUT_POLICY,
    validate_parameter_artifact,
)
from qcsd_lab.util import sha256_file
from tests.test_buflo_handoff import _runner_wakeup_receipt
from tests.test_kernel_tx import (
    _controller_isolation,
    _evidence,
    _runner_receipt_v2,
    _runner_wakeup_v11,
    _runner_wakeup_v12,
    _topology,
)


def test_timing_stress_contract_preserves_frozen_campaign_counts_and_dynamic_drain() -> None:
    plan = buflo_study.load_study_plan()
    stress = plan["timing_stress"]

    assert len(buflo_study.generated_stage_cells("regression")) == 18
    assert len(buflo_study.generated_stage_cells("controlled")) == 160
    assert stress == {
        "execution_stage": "mandatory-regression-prelude",
        "evidence_class": "timing-stress-nonformal-excluded",
        "workload": "complex-two-origin",
        "treatment": "buflo",
        "network_profile": "clean",
        "visits": 12,
        "max_attempts": 1,
        "authoritative_checkpoint": "experiment.json",
        "interval_us": 20_000,
        "minimum_duration_us": 100_000_000,
        "packet_size": 1_200,
        "max_events_per_direction": 6_000,
        "strict_half_open_window_us": 5_000,
        "contract_schema_version": 5,
        "cadence_semantics": ("inclusive-minimum-prefix-plus-bounded-terminal-whole-cell-drain"),
        "mandatory_prefix_opportunities_per_direction": 5_001,
        "minimum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": 5_000,
        "maximum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": 5_999,
        "minimum_incoming_bytes_per_visit": 6_001_200,
        "maximum_incoming_bytes_per_visit": 7_200_000,
        "minimum_kernel_timed_outgoing_releases_after_tick_zero": 60_000,
        "maximum_kernel_timed_outgoing_releases_after_tick_zero": 71_988,
        "minimum_opportunities_per_direction": 60_012,
        "maximum_opportunities_per_direction": 72_000,
        "logical_order_evidence": "direction-target-slot-identity",
        "physical_row_order": "terminal-resolution-order-not-dispatch-order",
        "terminal_schedule_stop_policy": (
            "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
            "then_drain_already_advertised_incoming_credit"
        ),
        "realization_backend": "linux-etf-so-txtime-post-veth-v1",
        "runner_wakeup_schema_version": 12,
        "legacy_userspace_exact_release_projection": (
            "schema-10-compatibility-fields-retained-and-neutral"
        ),
        "kernel_tx_runner_receipt_schema_version": 3,
        "kernel_tx_evidence_schema_version": 1,
        "observer_topology_receipt_schema_version": 1,
        "physical_outgoing_observer": "router-ingress-post-client-veth-pre-netem",
        "tick_zero_physical_observation_required": True,
        "formal_evidence": False,
    }
    sensitivity = buflo_study._timing_stress_sensitivity()
    assert sensitivity["guard_population"] == 60_000
    assert sensitivity["iid_detection_probability_at_target"] > 0.95
    assert sensitivity["zero_failure_one_sided_95_percent_upper_rate"] < 1 / 20_000
    maximum_sensitivity = buflo_study._timing_stress_sensitivity(71_988)
    assert maximum_sensitivity["guard_population"] == 71_988
    assert (
        maximum_sensitivity["iid_detection_probability_at_target"]
        > sensitivity["iid_detection_probability_at_target"]
    )


def test_timing_stress_parameters_require_narrow_explicit_admission() -> None:
    parameter = buflo_study.TIMING_STRESS_PARAMETERS
    provenance = buflo_study.TIMING_STRESS_PARAMETERS_PROVENANCE

    with pytest.raises(ValueError, match="explicit timing-stress admission"):
        validate_parameter_artifact(
            parameter,
            provenance_path=provenance,
            expected_kind="buflo",
            expected_qcsd_profile="research-1200",
            expected_udp_payload_ceiling=1_200,
        )

    artifact = validate_parameter_artifact(
        parameter,
        provenance_path=provenance,
        expected_kind="buflo",
        allow_timing_stress=True,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1_200,
    )
    assert artifact.input_policy == TIMING_STRESS_INPUT_POLICY
    assert buflo_study._timing_stress_parameter_inputs()["input_policy"] == (
        TIMING_STRESS_INPUT_POLICY
    )

    provenance_value = json.loads(provenance.read_text(encoding="utf-8"))
    assert provenance_value["schema_version"] == 5
    assert provenance_value["capture_contract"] == {
        "schema_version": 5,
        "visits": 12,
        "max_attempts": 1,
        "authoritative_checkpoint": "experiment.json",
        "mandatory_prefix_opportunities_per_direction": 5_001,
        "maximum_opportunities_per_direction": 6_000,
        "minimum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": 5_000,
        "maximum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": 5_999,
        "minimum_incoming_bytes_per_visit": 6_001_200,
        "maximum_incoming_bytes_per_visit": 7_200_000,
        "cadence_semantics": ("inclusive-minimum-prefix-plus-bounded-terminal-whole-cell-drain"),
        "terminal_drain_suffix": "contiguous-exact-paired-whole-cell-opportunities",
        "logical_order_evidence": "direction-target-slot-identity",
        "physical_row_order": "terminal-resolution-order-not-dispatch-order",
        "terminal_schedule_stop_policy": (
            "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
            "then_drain_already_advertised_incoming_credit"
        ),
        "strict_half_open_window_us": 5_000,
        "catch_up": False,
        "realization_backend": "linux-etf-so-txtime-post-veth-v1",
        "runner_wakeup_schema_version": 12,
        "legacy_userspace_exact_release_projection": (
            "schema-10-compatibility-fields-retained-and-neutral"
        ),
        "kernel_tx_runner_receipt_schema_version": 3,
        "kernel_tx_evidence_schema_version": 1,
        "observer_topology_receipt_schema_version": 1,
        "physical_outgoing_observer": "router-ingress-post-client-veth-pre-netem",
        "tick_zero_physical_observation_required": True,
    }


def test_previous_timing_stress_parameters_remain_valid_as_historical_input() -> None:
    parameter = buflo_study.STUDY_ROOT / "buflo-timing-stress-v1.json"
    provenance = parameter.with_suffix(parameter.suffix + ".provenance.json")

    artifact = validate_parameter_artifact(
        parameter,
        provenance_path=provenance,
        expected_kind="buflo",
        allow_timing_stress=True,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1_200,
    )

    assert artifact.input_policy == PREVIOUS_TIMING_STRESS_INPUT_POLICY
    assert json.loads(provenance.read_text(encoding="utf-8"))["schema_version"] == 1


def test_schema_two_timing_stress_parameters_remain_historical_not_current() -> None:
    parameter = buflo_study.STUDY_ROOT / "buflo-timing-stress-v2.json"
    provenance = parameter.with_suffix(parameter.suffix + ".provenance.json")

    artifact = validate_parameter_artifact(
        parameter,
        provenance_path=provenance,
        expected_kind="buflo",
        allow_timing_stress=True,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1_200,
    )

    assert artifact.input_policy == PREVIOUS_TIMING_STRESS_V2_INPUT_POLICY
    assert artifact.input_policy != TIMING_STRESS_INPUT_POLICY
    assert buflo_study.TIMING_STRESS_PARAMETERS.name == "buflo-timing-stress-v5.json"
    assert json.loads(provenance.read_text(encoding="utf-8"))["schema_version"] == 2


def test_schema_three_timing_stress_parameters_remain_historical_not_current() -> None:
    parameter = buflo_study.STUDY_ROOT / "buflo-timing-stress-v3.json"
    provenance = parameter.with_suffix(parameter.suffix + ".provenance.json")

    artifact = validate_parameter_artifact(
        parameter,
        provenance_path=provenance,
        expected_kind="buflo",
        allow_timing_stress=True,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1_200,
    )

    assert artifact.input_policy == PREVIOUS_TIMING_STRESS_V3_INPUT_POLICY
    assert artifact.input_policy != TIMING_STRESS_INPUT_POLICY
    assert buflo_study.TIMING_STRESS_PARAMETERS.name == "buflo-timing-stress-v5.json"
    assert json.loads(provenance.read_text(encoding="utf-8"))["schema_version"] == 3


def test_schema_four_timing_stress_parameters_remain_historical_not_current() -> None:
    parameter = buflo_study.STUDY_ROOT / "buflo-timing-stress-v4.json"
    provenance = parameter.with_suffix(parameter.suffix + ".provenance.json")

    artifact = validate_parameter_artifact(
        parameter,
        provenance_path=provenance,
        expected_kind="buflo",
        allow_timing_stress=True,
        expected_qcsd_profile="research-1200",
        expected_udp_payload_ceiling=1_200,
    )

    assert artifact.input_policy == PREVIOUS_TIMING_STRESS_V4_INPUT_POLICY
    assert artifact.input_policy != TIMING_STRESS_INPUT_POLICY
    assert buflo_study.TIMING_STRESS_PARAMETERS.name == "buflo-timing-stress-v5.json"
    assert json.loads(provenance.read_text(encoding="utf-8"))["schema_version"] == 4


def test_historical_timing_stress_inputs_remain_byte_identical() -> None:
    expected = {
        "buflo-timing-stress-v1.json": (
            "9249fd4324c1d24dd6e4d03221b6f92fe4eb6a331b2c756206e91aa318e21285"
        ),
        "buflo-timing-stress-v1.json.provenance.json": (
            "6b11ac948e7d34bce2da3d3df7a6202e19bdfaae1b9d401f4248fb24397722aa"
        ),
        "buflo-timing-stress-v2.json": (
            "9249fd4324c1d24dd6e4d03221b6f92fe4eb6a331b2c756206e91aa318e21285"
        ),
        "buflo-timing-stress-v2.json.provenance.json": (
            "f6e24f01b32b08e2cbc57f8791cc2877846f1fae6800fe61d4f563ddf16738f4"
        ),
        "buflo-timing-stress-v3.json": (
            "9249fd4324c1d24dd6e4d03221b6f92fe4eb6a331b2c756206e91aa318e21285"
        ),
        "buflo-timing-stress-v3.json.provenance.json": (
            "d6e67c15dadfcad0689353487d8dd6eaa4a14a2c3e0b5e0f709bcbee35241d61"
        ),
        "buflo-timing-stress-v4.json": (
            "9249fd4324c1d24dd6e4d03221b6f92fe4eb6a331b2c756206e91aa318e21285"
        ),
        "buflo-timing-stress-v4.json.provenance.json": (
            "f901c77ec6cc2b4f106a040af8c9d90ad134f2a51bb36c3c32c20193cc4c97ad"
        ),
    }

    assert {
        name: sha256_file(buflo_study.STUDY_ROOT / name) for name in expected
    } == expected


def _checkpoint_binding(*, cohort_version: int = 46) -> dict[str, Any]:
    return {
        "cohort_version": cohort_version,
        "lab_commit": "1" * 40,
        "neqo_commit": "2" * 40,
        "neqo_pinned_commit": "2" * 40,
        "image_digest": "sha256:" + "3" * 64,
        "study_plan_sha256": "4" * 64,
        "opportunity_contract_sha256": "5" * 64,
        "canonical_parameter_sha256": "6" * 64,
        "canonical_parameter_provenance_sha256": "7" * 64,
        "parameter_sha256": "8" * 64,
        "parameter_provenance_sha256": "9" * 64,
        "network_receipt_sha256": "a" * 64,
        "environment_receipt_sha256": "b" * 64,
        "application_workload_sha256": "c" * 64,
        "runtime_workload_sha256": "d" * 64,
        "response_qualification_sha256": "e" * 64,
        "response_qualification_manifest_sha256": "f" * 64,
        "qualified_chaff_manifest_sha256": "0" * 64,
    }


def test_timing_stress_completed_first_launch_resumes_without_relaunch(
    tmp_path: Path,
) -> None:
    attempt = tmp_path / "attempt-01"
    attempt.mkdir()
    (attempt / "attempt.json").write_text(json.dumps({"success": True}), encoding="utf-8")
    launches = 0

    def collect() -> None:
        nonlocal launches
        launches += 1

    assert (
        buflo_study._timing_stress_collect_or_resume(
            attempt,
            collect,
            recorded_attempt="attempts/visit-000/attempt-01",
        )
        is False
    )
    assert launches == 0


@pytest.mark.parametrize("terminal_kind", ("incomplete", "rejected"))
def test_timing_stress_existing_nonaccepted_first_launch_is_terminal(
    tmp_path: Path, terminal_kind: str
) -> None:
    attempt = tmp_path / "attempt-01"
    attempt.mkdir()
    if terminal_kind == "rejected":
        (attempt / "timing-stress-error.json").write_text("{}\n", encoding="utf-8")
    launches = 0

    def collect() -> None:
        nonlocal launches
        launches += 1

    with pytest.raises(ValueError, match="terminal"):
        buflo_study._timing_stress_collect_or_resume(
            attempt,
            collect,
            recorded_attempt="attempts/visit-000/attempt-01",
        )
    assert launches == 0


def test_timing_stress_failed_attempt_receives_durable_rejection_receipt(
    tmp_path: Path,
) -> None:
    attempt = tmp_path / "attempt-01"
    attempt.mkdir()
    (attempt / "attempt.json").write_text(
        json.dumps({"success": False, "runner_error_class": "client-defense-execution-v1"}),
        encoding="utf-8",
    )

    error = ValueError("strict BuFLO release failed")
    buflo_study._timing_stress_persist_rejection(attempt, error, stage="collect")

    receipt = json.loads((attempt / "timing-stress-error.json").read_text(encoding="utf-8"))
    assert receipt == {
        "schema_version": buflo_study.TIMING_STRESS_ATTEMPT_ERROR_SCHEMA_VERSION,
        "artifact_type": buflo_study.TIMING_STRESS_ATTEMPT_ERROR_TYPE,
        "failure": {
            "stage": "collect",
            "type": "ValueError",
            "message": "strict BuFLO release failed",
        },
    }
    assert buflo_study._timing_stress_attempt_rejected(attempt)

    with pytest.raises(ValueError, match="rejected and terminal"):
        buflo_study._timing_stress_collect_or_resume(
            attempt,
            lambda: pytest.fail("terminal launch must never be repeated"),
            recorded_attempt="attempts/visit-000/attempt-01",
        )


def test_timing_stress_newly_reserved_first_launch_is_launched_once(tmp_path: Path) -> None:
    attempt = tmp_path / "attempt-01"
    launches = 0

    def collect() -> None:
        nonlocal launches
        launches += 1

    assert (
        buflo_study._timing_stress_collect_or_resume(
            attempt,
            collect,
            recorded_attempt="attempts/visit-000/attempt-01",
            newly_reserved=True,
        )
        is True
    )
    assert launches == 1


def test_timing_stress_checkpoint_never_relaunches_missing_accepted_evidence(
    tmp_path: Path,
) -> None:
    attempt = tmp_path / "attempt-01"
    launches = 0

    def collect() -> None:
        nonlocal launches
        launches += 1

    with pytest.raises(ValueError, match="recorded first-launch evidence is missing"):
        buflo_study._timing_stress_collect_or_resume(
            attempt,
            collect,
            recorded_attempt="attempts/visit-000/attempt-01",
        )
    assert launches == 0


def test_timing_stress_launch_reservation_is_durable_before_collection(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "experiment.json"
    state = {
        "schema_version": buflo_study.TIMING_STRESS_SCHEMA_VERSION,
        "artifact_type": buflo_study.TIMING_STRESS_CHECKPOINT_TYPE,
        "campaign_binding": _checkpoint_binding(),
        "launched_visits": {},
        "accepted_visits": {},
    }
    relative = "attempts/visit-000/attempt-01"

    assert buflo_study._timing_stress_reserve_launch(
        state_path,
        state,
        visit_name="visit-000",
        relative_attempt=relative,
    )
    assert json.loads(state_path.read_text(encoding="utf-8"))["launched_visits"] == {
        "visit-000": relative
    }

    observed_reservation = False

    def collect() -> None:
        nonlocal observed_reservation
        observed_reservation = json.loads(state_path.read_text(encoding="utf-8"))[
            "launched_visits"
        ] == {"visit-000": relative}

    assert buflo_study._timing_stress_collect_or_resume(
        tmp_path / relative,
        collect,
        recorded_attempt=relative,
        newly_reserved=True,
    )
    assert observed_reservation


@pytest.mark.parametrize("lost_kind", ("absent", "deleted-rejection"))
def test_timing_stress_recorded_launch_loss_is_terminal(tmp_path: Path, lost_kind: str) -> None:
    attempt = tmp_path / "attempts/visit-000/attempt-01"
    if lost_kind == "deleted-rejection":
        attempt.mkdir(parents=True)
        error = attempt / "timing-stress-error.json"
        error.write_text("{}\n", encoding="utf-8")
        error.unlink()
        attempt.rmdir()
    launches = 0

    def collect() -> None:
        nonlocal launches
        launches += 1

    with pytest.raises(ValueError, match="missing and terminal"):
        buflo_study._timing_stress_collect_or_resume(
            attempt,
            collect,
            recorded_attempt="attempts/visit-000/attempt-01",
        )
    assert launches == 0


def test_timing_stress_checkpoint_rejects_acceptance_without_launch() -> None:
    state = {
        "schema_version": buflo_study.TIMING_STRESS_SCHEMA_VERSION,
        "artifact_type": buflo_study.TIMING_STRESS_CHECKPOINT_TYPE,
        "campaign_binding": _checkpoint_binding(),
        "launched_visits": {},
        "accepted_visits": {
            "visit-000": "attempts/visit-000/attempt-01",
        },
    }

    with pytest.raises(ValueError, match="without a launch"):
        buflo_study._validate_timing_stress_checkpoint(state, require_complete=False)


def test_timing_stress_checkpoint_rejects_campaign_binding_tamper() -> None:
    binding = _checkpoint_binding()
    state = {
        "schema_version": buflo_study.TIMING_STRESS_SCHEMA_VERSION,
        "artifact_type": buflo_study.TIMING_STRESS_CHECKPOINT_TYPE,
        "campaign_binding": dict(binding),
        "launched_visits": {},
        "accepted_visits": {},
    }
    buflo_study._validate_timing_stress_checkpoint(
        state,
        require_complete=False,
        expected_binding=binding,
    )

    state["campaign_binding"]["parameter_sha256"] = "1" * 64
    with pytest.raises(ValueError, match="campaign binding"):
        buflo_study._validate_timing_stress_checkpoint(
            state,
            require_complete=False,
            expected_binding=binding,
        )


def test_timing_stress_root_and_input_inventories_reject_stray_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "buflo-timing-stress"
    for directory in (
        root / "attempts",
        root / "inputs/application",
        root / "inputs/application-response-qualification",
        root / "inputs/chaff",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    for relative in (
        "receipt.json",
        "experiment.json",
        "inputs/study-environment.json",
        "inputs/application/complex.json",
        "inputs/application/runtime-complex.json",
        "inputs/application-response-qualification/complex.json",
        "inputs/chaff/qualified-manifest.json",
    ):
        (root / relative).write_text("{}\n", encoding="utf-8")

    buflo_study._validate_timing_stress_root_inventory(root)
    stray = root / "unbound.txt"
    stray.write_text("unbound\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory is not closed"):
        buflo_study._validate_timing_stress_root_inventory(root)
    stray.unlink()

    input_stray = root / "inputs/application/unbound.json"
    input_stray.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory is not closed"):
        buflo_study._validate_timing_stress_root_inventory(root)


SCHEDULE_FIELDS = SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS


def _small_schedule_rows(
    opportunities: int,
    *,
    targets: tuple[int, ...] | None = None,
) -> list[dict[str, Any]]:
    if targets is None:
        targets = tuple(range(0, opportunities * 20, 20))
    assert len(targets) == opportunities
    rows: list[dict[str, Any]] = []
    for target in targets:
        tick = target // 20
        rows.extend(
            (
                {
                    "target_time_us": target,
                    "direction": "outgoing",
                    "size": 1_200,
                    "connection": 0,
                    "action_time_us": target,
                    "satisfaction": "satisfied",
                    "observed_size": 1_200,
                    "miss_reason": "",
                    "slot_id": 2 * tick,
                    "qcsd_outcome_schema_version": 3,
                    "send_policy": "exact",
                    "desired_udp_bytes": 1_200,
                    "observed_udp_bytes": 1_200,
                    "congestion_reason": "",
                    "credit_advertised_at_us": "",
                    "credit_advertisement_delay_us": "",
                    "credit_consumed_at_us": "",
                    "credit_consumption_delay_us": "",
                    "terminal_defense_elapsed_us": target + 1,
                },
                {
                    "target_time_us": target,
                    "direction": "incoming",
                    "size": 1_200,
                    "connection": 0,
                    "action_time_us": target,
                    "satisfaction": "satisfied",
                    "observed_size": "",
                    "miss_reason": "",
                    "slot_id": 2 * tick + 1,
                    "qcsd_outcome_schema_version": 3,
                    "send_policy": "exact",
                    "desired_udp_bytes": 1_200,
                    "observed_udp_bytes": "",
                    "congestion_reason": "",
                    "credit_advertised_at_us": target + 1,
                    "credit_advertisement_delay_us": 1,
                    "credit_consumed_at_us": target + 2,
                    "credit_consumption_delay_us": 2,
                    "terminal_defense_elapsed_us": target + 2,
                },
            )
        )
    return rows


def _write_small_schedule(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=SCHEDULE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _small_run(opportunities: int) -> dict[str, Any]:
    guards = opportunities - 1
    last_target = (opportunities - 1) * 20
    incoming_bytes = opportunities * 1_200
    histogram = {"upper_bounds_nanoseconds": [5_000_000], "counts": [guards]}
    diagnostics = {
        "buflo_scheduled_outgoing_cells": opportunities,
        "buflo_scheduled_incoming_cells": opportunities,
        "buflo_full_outgoing_cells": opportunities,
        "buflo_partial_outgoing_cells": 0,
        "buflo_suppressed_outgoing_cells": 0,
        "buflo_missed_outgoing_cells": 0,
        "buflo_missed_incoming_cells": 0,
        "buflo_outgoing_unresolved_cells": 0,
        "buflo_incoming_unresolved_cells": 0,
        "buflo_catch_up_outgoing_cells": 0,
        "buflo_catch_up_incoming_cells": 0,
        "buflo_event_guard_triggered": False,
        "buflo_application_complete": True,
        "buflo_minimum_duration_reached": True,
        "buflo_egress_backlog_pending": False,
        "scheduled_incoming_requested_bytes": incoming_bytes,
        "scheduled_incoming_advertised_bytes": incoming_bytes,
        "scheduled_incoming_consumed_bytes": incoming_bytes,
        "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0,
        "buflo_schedule_stop_latched": True,
        "buflo_schedule_stop_latched_at_us": last_target + 1,
        "buflo_schedule_stop_available_bytes": 270,
        "buflo_schedule_stop_required_bytes": 1_200,
        "buflo_schedule_stop_scheduled_incoming_cells": opportunities,
        "buflo_schedule_stop_scheduled_outgoing_cells": opportunities,
        "buflo_schedule_stop_terminal_incoming_cells": opportunities - 1,
        "buflo_schedule_stop_terminal_outgoing_cells": opportunities,
        "buflo_terminal_subcell_latched": True,
        "buflo_terminal_subcell_latched_at_us": last_target + 2,
        "buflo_terminal_subcell_open_streams_at_latch": 1,
        "buflo_terminal_subcell_parser_lease_bytes_at_latch": 0,
        "buflo_terminal_subcell_pending_parser_boundaries_at_latch": 0,
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch": 0,
        "buflo_terminal_subcell_pending_request_cancellations": 0,
        "buflo_terminal_subcell_stream_cancellations": 1,
        "buflo_terminal_subcell_exact_capacity_bytes_cancelled": 273,
    }
    run = {
        "runner_wakeup_metrics": {
            "schema_version": 10,
            "buflo_exact_release_guard_entries": guards,
            "buflo_exact_release_dispatch_ready_guards": guards,
            "buflo_exact_release_failed_guards": 0,
            "buflo_exact_release_invalid_counter_frequency_guards": 0,
            "buflo_exact_release_counter_unavailable_failure_guards": 0,
            "buflo_exact_release_counter_nonmonotonic_failure_guards": 0,
            "buflo_exact_release_counter_frequency_changed_guards": 0,
            "buflo_exact_release_counter_target_error_guards": 0,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 1_000,
            "buflo_exact_release_dispatch_at_or_after_deadline_guards": 0,
            "buflo_exact_release_active_wait_poll_source": (
                "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
            ),
            "buflo_exact_release_active_wait_counter_frequency_hz": 1_000_000_000,
            "buflo_exact_release_active_wait_counter_guards": guards,
            "buflo_exact_release_active_wait_counter_unavailable_guards": 0,
            "buflo_exact_release_active_wait_counter_nonmonotonic_guards": 0,
            "buflo_exact_release_active_wait_counter_calibrations": guards,
            "buflo_exact_release_active_wait_instant_confirmations": guards,
            "buflo_exact_release_active_wait_early_confirmation_retries": 0,
            "buflo_exact_release_active_wait_authoritative_watchdog_checks": guards,
            "buflo_exact_release_active_wait_authoritative_watchdog_dispatches": 0,
            "buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards": (
                guards
            ),
            "buflo_exact_release_active_wait_counter_nanoseconds": 20,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 4,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 4,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 3,
            "buflo_exact_release_max_authoritative_sample_gap_nanoseconds": 5,
            "buflo_exact_release_max_authoritative_counter_lag_nanoseconds": 0,
            "buflo_exact_release_max_counter_authoritative_lead_nanoseconds": 0,
            "buflo_exact_release_dispatch_lateness_histogram": dict(histogram),
            "buflo_exact_release_active_spin_gap_histogram": dict(histogram),
            "buflo_exact_release_worst_guard": {
                "guard_at_defense_nanoseconds": 1,
                "entered_at_defense_nanoseconds": 1,
                "active_wait_at_defense_nanoseconds": 1,
                "active_wait_started_at_defense_nanoseconds": 1,
                "release_at_defense_nanoseconds": 2,
                "deadline_at_defense_nanoseconds": 3,
                "dispatch_at_defense_nanoseconds": 2,
                "active_wait_poll_source": (
                    "linux-aarch64-cntvct-el0-predictive-authoritative-watchdog-v2"
                ),
                "active_wait_counter_frequency_hz": 1_000_000_000,
                "active_wait_instant_confirmations": 1,
                "active_wait_early_confirmation_retries": 0,
                "active_wait_authoritative_watchdog_checks": 0,
                "active_wait_authoritative_watchdog_dispatches": 0,
                "max_authoritative_sample_gap_nanoseconds": 5,
                "max_authoritative_counter_lag_nanoseconds": 0,
                "max_counter_authoritative_lead_nanoseconds": 0,
            },
            "buflo_exact_release_last_failure": None,
        },
        "defense_diagnostics": diagnostics,
        "buflo_summary": {
            "schema_version": 4,
            "kind": "buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "terminal_schedule_stop_policy": (
                "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
                "then_drain_already_advertised_incoming_credit"
            ),
            "terminal_subcell_policy": (
                "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
            ),
            "diagnostics": diagnostics,
        },
    }
    return run


def _patch_small_schedule_contract(
    monkeypatch: pytest.MonkeyPatch,
    *,
    opportunities: int,
) -> None:
    from qcsd_lab import fidelity

    monkeypatch.setattr(buflo_study, "TIMING_STRESS_INTERVAL_US", 20)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_MINIMUM_DURATION_US", 40)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_WINDOW_US", 5)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_MANDATORY_OPPORTUNITIES_PER_DIRECTION", 3)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_MAX_EVENTS_PER_DIRECTION", 5)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_MINIMUM_GUARDS_PER_VISIT", 2)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_MAXIMUM_GUARDS_PER_VISIT", 4)
    # The production terminal validator retains the live ten-second floor.  This
    # scaled cadence fixture exercises the surrounding schema-5 evidence contract.
    monkeypatch.setattr(fidelity, "buflo_terminal_diagnostics_valid", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        fidelity,
        "_schedule_realization_metrics",
        lambda path: {
            "scheduled_events": opportunities * 2,
            "scheduled_outgoing_events": opportunities,
            "scheduled_incoming_events": opportunities,
            "satisfied_events": opportunities * 2,
            "terminal_satisfactions": {"satisfied": opportunities * 2},
            "missed_events": 0,
            "outgoing_size_mismatch_events": 0,
            "catch_up_events": 0,
            "duplicate_terminal_slots": 0,
            "invalid_terminal_rows": 0,
            "invalid_typed_outcome_rows": 0,
            "incoming_credit_advertised_events": opportunities,
            "incoming_credit_consumed_events": opportunities,
            "incoming_credit_missing_events": 0,
            "incoming_credit_consumption_missing_events": 0,
            "invalid_credit_advertisement_events": 0,
            "invalid_credit_consumption_events": 0,
        },
    )
    guards = opportunities - 1
    histogram = {
        "upper_bounds_nanoseconds": [
            50_000,
            100_000,
            250_000,
            500_000,
            1_000_000,
            2_000_000,
            5_000_000,
        ],
        "counts": [guards, 0, 0, 0, 0, 0, 0, 0],
    }
    monkeypatch.setattr(
        buflo_study,
        "_timing_stress_kernel_tx_evidence",
        lambda *args, **kwargs: {
            "realization_backend": "linux-etf-so-txtime-post-veth-v1",
            "runner_wakeup_schema_version": 12,
            "legacy_userspace_exact_release_projection": {
                "schema_version": 10,
                "neutral": True,
            },
            "runner_receipt_schema_version": 3,
            "evidence_schema_version": 1,
            "observer_topology_schema_version": 1,
            "job_count": opportunities,
            "item_count": opportunities,
            "etf_item_count": opportunities,
            "ordered_item_count": 0,
            "captured_credit_identity_count": opportunities,
            "matched_item_count": opportunities,
            "runner_failed_item_count": 0,
            "runner_unresolved_item_count": 0,
            "evidence_unresolved_item_count": 0,
            "qdisc_drop_count": 0,
            "qdisc_overlimit_count": 0,
            "qdisc_requeue_count": 0,
            "capture_drop_count": 0,
            "max_tx_software_lateness_ns": 1_000,
            "max_tx_to_capture_delta_ns": 1_000,
            "max_post_veth_outgoing_release_lateness_ns": 1_000,
            "kernel_timed_release_lateness_histogram_after_tick_zero": histogram,
            "runner_receipt_sha256": "1" * 64,
            "evidence_sha256": "2" * 64,
            "router_capture_sha256": "3" * 64,
            "router_receipt_sha256": "4" * 64,
            "network_receipt_sha256": "5" * 64,
        },
    )


def test_timing_stress_schedule_requires_exact_cells_and_credit_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_small_schedule_contract(monkeypatch, opportunities=3)
    _write_small_schedule(tmp_path / "neqo/schedule.csv", _small_schedule_rows(3))
    run = _small_run(3)

    evidence = buflo_study._timing_stress_schedule_evidence(
        tmp_path, run, network_receipt={}
    )
    assert evidence["contract_schema_version"] == 5
    assert evidence["cadence"] == {
        "interval_us": 20,
        "minimum_duration_us": 40,
        "mandatory_prefix_opportunities_per_direction": 3,
        "terminal_drain_opportunities_per_direction": 0,
        "last_target_time_us": 40,
        "logical_slot_inventory": 6,
        "terminal_resolution_row_reorderings": 0,
    }
    assert evidence["full_outgoing_cells"] == 3
    assert evidence["incoming_credit_bytes"] == {
        "requested": 3_600,
        "advertised": 3_600,
        "consumed": 3_600,
        "retired": 0,
        "unresolved": 0,
    }
    assert evidence["realization_backend"] == "linux-etf-so-txtime-post-veth-v1"
    assert evidence["runner_wakeup_schema_version"] == 12
    assert evidence["legacy_userspace_exact_release_projection"] == {
        "schema_version": 10,
        "neutral": True,
    }
    assert evidence["kernel_timed_outgoing_releases_after_tick_zero"] == 2
    assert evidence["release_outcomes"] == {
        "tick_zero_observed": 1,
        "kernel_timed_after_tick_zero": 2,
        "post_veth_matched": 3,
        "failed": 0,
    }
    assert evidence["terminal_schedule_stop"]["available_bytes"] == 270
    assert evidence["terminal_schedule_stop"]["drained_incoming_cells_after_stop"] == 1
    assert evidence["terminal_subcell_drain"]["exact_capacity_bytes_cancelled"] == 273

    run["defense_diagnostics"]["scheduled_incoming_consumed_bytes"] = 2_400
    with pytest.raises(ValueError, match="terminal diagnostics"):
        buflo_study._timing_stress_schedule_evidence(
            tmp_path, run, network_receipt={}
        )


def test_timing_stress_rejects_coherently_resealed_incoming_u64_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_small_schedule_contract(monkeypatch, opportunities=3)
    rows = _small_schedule_rows(3)
    incoming = rows[-1]
    action = int(incoming["action_time_us"])
    incoming["credit_consumed_at_us"] = 2**64
    incoming["credit_consumption_delay_us"] = 2**64 - action
    _write_small_schedule(tmp_path / "neqo/schedule.csv", rows)

    with pytest.raises(ValueError, match="incoming opportunity lacks exact credit evidence"):
        buflo_study._timing_stress_schedule_evidence(
            tmp_path,
            _small_run(3),
            network_receipt={},
        )


def test_timing_stress_rejects_overflowed_connection_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_small_schedule_contract(monkeypatch, opportunities=3)
    rows = _small_schedule_rows(3)
    rows[0]["connection"] = 2**64
    _write_small_schedule(tmp_path / "neqo/schedule.csv", rows)

    with pytest.raises(ValueError, match="malformed row"):
        buflo_study._timing_stress_schedule_evidence(
            tmp_path,
            _small_run(3),
            network_receipt={},
        )


def test_timing_stress_rejects_nonexact_runner_schedule_header(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_small_schedule_contract(monkeypatch, opportunities=3)
    path = tmp_path / "neqo/schedule.csv"
    path.parent.mkdir(parents=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=(*SCHEDULE_FIELDS, "unbound"))
        writer.writeheader()
        writer.writerows(_small_schedule_rows(3))

    with pytest.raises(ValueError, match="current typed outcome columns"):
        buflo_study._timing_stress_schedule_evidence(
            tmp_path,
            _small_run(3),
            network_receipt={},
        )


@pytest.mark.parametrize("reorder_terminal_rows", (False, True))
def test_timing_stress_accepts_exact_terminal_drain_suffix_and_resolution_reordering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reorder_terminal_rows: bool,
) -> None:
    _patch_small_schedule_contract(monkeypatch, opportunities=4)
    rows = _small_schedule_rows(4)
    if reorder_terminal_rows:
        rows[-2:] = reversed(rows[-2:])
    _write_small_schedule(tmp_path / "neqo/schedule.csv", rows)

    evidence = buflo_study._timing_stress_schedule_evidence(
        tmp_path, _small_run(4), network_receipt={}
    )

    assert evidence["scheduled_outgoing_opportunities"] == 4
    assert evidence["scheduled_incoming_opportunities"] == 4
    assert (
        evidence["mandatory_prefix_kernel_timed_outgoing_releases_after_tick_zero"]
        == 2
    )
    assert (
        evidence["terminal_drain_kernel_timed_outgoing_releases_after_tick_zero"]
        == 1
    )
    assert evidence["cadence"]["terminal_drain_opportunities_per_direction"] == 1
    assert evidence["cadence"]["last_target_time_us"] == 60
    assert evidence["cadence"]["terminal_resolution_row_reorderings"] == (
        2 if reorder_terminal_rows else 0
    )


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("below-prefix", "equal bounded directional inventories"),
        ("above-maximum", "equal bounded directional inventories"),
        ("gap", "inclusive minimum cadence"),
        ("unequal-directions", "equal bounded directional inventories"),
        ("invalid-slot", "exact no-catch-up ordering"),
        ("late-suffix", "half-open window"),
        ("terminal-stop-tamper", "terminal drain"),
    ),
)
def test_timing_stress_rejects_invalid_prefix_suffix_and_terminal_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    message: str,
) -> None:
    opportunities = {"below-prefix": 2, "above-maximum": 6}.get(case, 4)
    _patch_small_schedule_contract(monkeypatch, opportunities=opportunities)
    targets = (0, 20, 60, 80) if case == "gap" else None
    rows = _small_schedule_rows(opportunities, targets=targets)
    if case == "unequal-directions":
        rows.pop()
    elif case == "invalid-slot":
        rows[-2]["slot_id"] = 0
    elif case == "late-suffix":
        rows[-2]["terminal_defense_elapsed_us"] = rows[-2]["target_time_us"] + 5
    run = _small_run(opportunities)
    if case == "terminal-stop-tamper":
        run["defense_diagnostics"]["buflo_schedule_stop_available_bytes"] = 1_200
    _write_small_schedule(tmp_path / "neqo/schedule.csv", rows)

    with pytest.raises(ValueError, match=message):
        buflo_study._timing_stress_schedule_evidence(
            tmp_path, run, network_receipt={}
        )


def _write_kernel_tx_attempt(
    attempt: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    runner_schema_version: int = 3,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    neqo = attempt / "neqo"
    diagnostics = attempt / "diagnostics"
    neqo.mkdir(parents=True)
    diagnostics.mkdir()
    wakeups = _runner_wakeup_v12() if runner_schema_version == 3 else _runner_wakeup_v11()
    if runner_schema_version == 2:
        wakeups["buflo_kernel_tx"] = _runner_receipt_v2()
    elif runner_schema_version not in {1, 3}:
        raise ValueError("test runner schema must be 1, 2, or 3")
    run = {"runner_wakeup_metrics": wakeups}
    run_path = neqo / "run.json"
    run_path.write_text(json.dumps(run), encoding="utf-8")
    router_capture = diagnostics / "kernel-tx-post-veth-raw.pcapng"
    router_capture.write_bytes(b"test post-veth capture")

    raw = run["runner_wakeup_metrics"]["buflo_kernel_tx"]
    evidence, router_receipt, packets = _evidence(raw)
    router_receipt["pcapng_sha256"] = sha256_file(router_capture)
    evidence["runner_run_json_sha256"] = sha256_file(run_path)
    evidence["post_veth_capture"] = copy.deepcopy(router_receipt)
    evidence_path = diagnostics / "kernel-tx-evidence.json"
    router_receipt_path = diagnostics / "kernel-tx-post-veth-receipt.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    router_receipt_path.write_text(json.dumps(router_receipt), encoding="utf-8")

    network, binding, network_digest = _topology()
    topology = build_observer_topology_receipt(
        network_receipt=network,
        observer_binding=binding,
        network_receipt_sha256=network_digest,
        controller_isolation=_controller_isolation(),
    )
    result = {
        "observer_topology_required": True,
        "observer_topology_receipt": topology,
        "observer_topology_valid": True,
        "kernel_tx_evidence_required": True,
        "kernel_tx_evidence_path": "diagnostics/kernel-tx-evidence.json",
        "kernel_tx_evidence_sha256": sha256_file(evidence_path),
        "kernel_tx_evidence_valid": True,
        "kernel_tx_evidence_error": None,
    }
    (attempt / "attempt.json").write_text(json.dumps(result), encoding="utf-8")
    monkeypatch.setattr(
        "qcsd_lab.kernel_tx_runtime.extract_router_udp_packets",
        lambda path: copy.deepcopy(packets),
    )
    return run, network, packets


def _rewrite_kernel_tx_result_hash(attempt: Path) -> None:
    result_path = attempt / "attempt.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["kernel_tx_evidence_sha256"] = sha256_file(
        attempt / "diagnostics/kernel-tx-evidence.json"
    )
    result_path.write_text(json.dumps(result), encoding="utf-8")


def test_timing_stress_kernel_tx_evidence_accepts_complete_current_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, network, _packets = _write_kernel_tx_attempt(tmp_path, monkeypatch)

    evidence = buflo_study._timing_stress_kernel_tx_evidence(
        tmp_path,
        run,
        opportunities=1,
        network_receipt=network,
    )

    assert evidence["realization_backend"] == "linux-etf-so-txtime-post-veth-v1"
    assert evidence["runner_wakeup_schema_version"] == 12
    assert evidence["legacy_userspace_exact_release_projection"] == {
        "schema_version": 10,
        "neutral": True,
    }
    assert evidence["job_count"] == 1
    assert evidence["etf_item_count"] == 1
    assert evidence["matched_item_count"] == evidence["item_count"] == 2
    assert evidence["max_post_veth_outgoing_release_lateness_ns"] == 200_000
    assert sum(
        evidence["kernel_timed_release_lateness_histogram_after_tick_zero"]["counts"]
    ) == 0


def test_timing_stress_kernel_tx_evidence_rejects_historical_nested_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, network, _packets = _write_kernel_tx_attempt(
        tmp_path,
        monkeypatch,
        runner_schema_version=1,
    )

    with pytest.raises(ValueError, match="current schema-12 kernel-TX evidence"):
        buflo_study._timing_stress_kernel_tx_evidence(
            tmp_path,
            run,
            opportunities=1,
            network_receipt=network,
        )


@pytest.mark.parametrize(
    "tamper",
    (
        "schema-ten",
        "nonneutral-legacy-projection",
        "missing-sidecar",
        "sidecar-substitution",
        "observer-substitution",
        "qdisc-drop",
        "job-count",
    ),
)
def test_timing_stress_kernel_tx_evidence_rejects_adversarial_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    run, network, _packets = _write_kernel_tx_attempt(tmp_path, monkeypatch)
    evidence_path = tmp_path / "diagnostics/kernel-tx-evidence.json"
    run_path = tmp_path / "neqo/run.json"
    opportunities = 1
    if tamper == "schema-ten":
        run["runner_wakeup_metrics"] = _runner_wakeup_receipt(10)
        run_path.write_text(json.dumps(run), encoding="utf-8")
    elif tamper == "nonneutral-legacy-projection":
        run["runner_wakeup_metrics"]["buflo_exact_release_guard_entries"] = 1
        run_path.write_text(json.dumps(run), encoding="utf-8")
    elif tamper == "missing-sidecar":
        evidence_path.unlink()
    elif tamper == "sidecar-substitution":
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["controlled_observer_binding"]["observer"]["container_id"] = "9" * 64
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        _rewrite_kernel_tx_result_hash(tmp_path)
    elif tamper == "observer-substitution":
        result_path = tmp_path / "attempt.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["observer_topology_receipt"]["network_receipt"]["router"][
            "client_ipv4"
        ] = "10.0.0.9"
        result_path.write_text(json.dumps(result), encoding="utf-8")
    elif tamper == "qdisc-drop":
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["qdisc"]["after"]["drops"] = 1
        evidence["aggregate"]["qdisc_drop_count"] = 1
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        _rewrite_kernel_tx_result_hash(tmp_path)
    else:
        opportunities = 2

    with pytest.raises(ValueError, match="kernel-TX|observer"):
        buflo_study._timing_stress_kernel_tx_evidence(
            tmp_path,
            run,
            opportunities=opportunities,
            network_receipt=network,
        )


def _aggregate_timing(opportunities: int) -> dict[str, Any]:
    releases = opportunities - 1
    incoming_bytes = opportunities * 1_200
    terminal_drain = opportunities - 5_001
    histogram = {
        "upper_bounds_nanoseconds": [
            50_000,
            100_000,
            250_000,
            500_000,
            1_000_000,
            2_000_000,
            5_000_000,
        ],
        "counts": [0, 0, 0, 0, 0, 0, releases, 0],
    }
    kernel = {
        "realization_backend": "linux-etf-so-txtime-post-veth-v1",
        "runner_wakeup_schema_version": 12,
        "legacy_userspace_exact_release_projection": {
            "schema_version": 10,
            "neutral": True,
        },
        "runner_receipt_schema_version": 3,
        "evidence_schema_version": 1,
        "observer_topology_schema_version": 1,
        "job_count": opportunities,
        "item_count": opportunities * 2,
        "etf_item_count": opportunities,
        "ordered_item_count": opportunities,
        "captured_credit_identity_count": opportunities,
        "matched_item_count": opportunities * 2,
        "runner_failed_item_count": 0,
        "runner_unresolved_item_count": 0,
        "evidence_unresolved_item_count": 0,
        "qdisc_drop_count": 0,
        "qdisc_overlimit_count": 0,
        "qdisc_requeue_count": 0,
        "capture_drop_count": 0,
        "max_tx_software_lateness_ns": 4_000_000,
        "max_tx_to_capture_delta_ns": 500_000,
        "max_post_veth_outgoing_release_lateness_ns": 4_999_999,
        "kernel_timed_release_lateness_histogram_after_tick_zero": histogram,
        "runner_receipt_sha256": "1" * 64,
        "evidence_sha256": "2" * 64,
        "router_capture_sha256": "3" * 64,
        "router_receipt_sha256": "4" * 64,
        "network_receipt_sha256": "5" * 64,
    }
    return {
        "contract_schema_version": 5,
        "cadence": {
            "interval_us": 20_000,
            "minimum_duration_us": 100_000_000,
            "mandatory_prefix_opportunities_per_direction": 5_001,
            "terminal_drain_opportunities_per_direction": terminal_drain,
            "last_target_time_us": releases * 20_000,
            "logical_slot_inventory": opportunities * 2,
            "terminal_resolution_row_reorderings": 2 if terminal_drain else 0,
        },
        "mandatory_prefix_kernel_timed_outgoing_releases_after_tick_zero": 5_000,
        "terminal_drain_kernel_timed_outgoing_releases_after_tick_zero": terminal_drain,
        "kernel_timed_outgoing_releases_after_tick_zero": releases,
        "release_outcomes": {
            "tick_zero_observed": 1,
            "kernel_timed_after_tick_zero": releases,
            "post_veth_matched": opportunities,
            "failed": 0,
        },
        "scheduled_outgoing_opportunities": opportunities,
        "scheduled_incoming_opportunities": opportunities,
        "directional_events": opportunities * 2,
        "full_outgoing_cells": opportunities,
        "incoming_credit_bytes": {
            "requested": incoming_bytes,
            "advertised": incoming_bytes,
            "consumed": incoming_bytes,
            "retired": 0,
            "unresolved": 0,
        },
        "max_schedule_outgoing_terminal_lateness_us": 4_999,
        "max_incoming_credit_advertisement_delay_us": 4_999,
        "realization_backend": "linux-etf-so-txtime-post-veth-v1",
        "runner_wakeup_schema_version": 12,
        "legacy_userspace_exact_release_projection": {
            "schema_version": 10,
            "neutral": True,
        },
        "kernel_tx": kernel,
        "kernel_timed_release_lateness_histogram_after_tick_zero": histogram,
    }


def test_timing_stress_aggregate_binds_dynamic_mixed_visit_counts() -> None:
    opportunities = [5_001, 5_481] * 6
    aggregate = buflo_study._timing_stress_aggregate(
        [{"timing": _aggregate_timing(value)} for value in opportunities]
    )
    buflo_study._validate_timing_stress_aggregate(aggregate)

    assert aggregate["opportunities_per_direction_by_visit"] == opportunities
    assert (
        aggregate["terminal_drain_opportunities_per_direction_by_visit"]
        == [
            0,
            480,
        ]
        * 6
    )
    assert aggregate["kernel_timed_outgoing_releases_after_tick_zero"] == 62_880
    assert (
        aggregate["mandatory_prefix_kernel_timed_outgoing_releases_after_tick_zero"]
        == 60_000
    )
    assert (
        aggregate["terminal_drain_kernel_timed_outgoing_releases_after_tick_zero"]
        == 2_880
    )
    assert aggregate["full_outgoing_cells"] == 62_892
    assert aggregate["terminal_drain_opportunities_per_direction"] == 2_880
    assert aggregate["minimum_last_target_time_us"] == 100_000_000
    assert aggregate["maximum_last_target_time_us"] == 109_600_000
    assert aggregate["terminal_resolution_row_reorderings"] == 12
    assert aggregate["incoming_credit_bytes"] == {
        "requested": 75_470_400,
        "advertised": 75_470_400,
        "consumed": 75_470_400,
        "retired": 0,
        "unresolved": 0,
    }
    assert aggregate["release_outcomes"] == {
        "tick_zero_observed": 12,
        "kernel_timed_after_tick_zero": 62_880,
        "post_veth_matched": 62_892,
        "failed": 0,
    }
    assert aggregate["legacy_userspace_exact_release_projection"] == {
        "schema_version": 10,
        "neutral_visits": 12,
        "nonneutral_visits": 0,
    }
    assert aggregate["kernel_tx"]["job_count"] == 62_892
    assert aggregate["kernel_tx"]["etf_item_count"] == 62_892
    assert aggregate["kernel_tx"]["item_count"] == 125_784
    assert aggregate["kernel_tx"]["matched_item_count"] == 125_784
    assert aggregate["kernel_tx"]["runner_failed_item_count"] == 0
    assert aggregate["kernel_tx"]["capture_drop_count"] == 0
    assert aggregate["kernel_timed_release_lateness_histogram_after_tick_zero"][
        "counts"
    ] == [0, 0, 0, 0, 0, 0, 62_880, 0]
    assert (
        aggregate["observed_sensitivity"][
            "kernel_timed_outgoing_release_population_after_tick_zero"
        ]
        == 62_880
    )
    assert "guard_population" not in aggregate["observed_sensitivity"]
    assert set(aggregate["zero_failure_counts"].values()) == {0}


def test_current_timing_stress_aggregate_rejects_schema_two_sample() -> None:
    historical = _aggregate_timing(5_001)
    historical["contract_schema_version"] = 2

    with pytest.raises(ValueError, match="current kernel-TX contract"):
        buflo_study._timing_stress_aggregate(
            [{"timing": copy.deepcopy(historical)} for _ in range(12)]
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("runner_receipt_schema_version", 1),
        ("runner_receipt_schema_version", 2),
        ("evidence_schema_version", 2),
        ("observer_topology_schema_version", 2),
    ),
)
def test_current_timing_stress_aggregate_rejects_nested_schema_substitution(
    field: str, value: int
) -> None:
    timing = _aggregate_timing(5_001)
    timing["kernel_tx"][field] = value

    with pytest.raises(ValueError, match="current kernel-TX contract"):
        buflo_study._timing_stress_aggregate(
            [{"timing": copy.deepcopy(timing)} for _ in range(12)]
        )


@pytest.mark.parametrize(
    "tamper",
    (
        "above-maximum",
        "sensitivity",
        "failure-count",
        "kernel-job-count",
        "legacy-projection",
    ),
)
def test_timing_stress_dynamic_aggregate_rejects_contract_tamper(tamper: str) -> None:
    aggregate = buflo_study._timing_stress_aggregate(
        [{"timing": _aggregate_timing(value)} for value in [5_001, 5_481] * 6]
    )
    if tamper == "above-maximum":
        aggregate["opportunities_per_direction_by_visit"][0] = 6_001
    elif tamper == "sensitivity":
        aggregate["observed_sensitivity"] = (
            buflo_study._timing_stress_kernel_sensitivity()
        )
    elif tamper == "failure-count":
        aggregate["zero_failure_counts"]["late_post_veth_outgoing_releases"] = 1
    elif tamper == "kernel-job-count":
        aggregate["kernel_tx"]["job_count"] -= 1
    else:
        aggregate["legacy_userspace_exact_release_projection"]["nonneutral_visits"] = 1

    with pytest.raises(ValueError, match="aggregate zero-failure gate"):
        buflo_study._validate_timing_stress_aggregate(aggregate)


def test_schema_six_regression_receipt_binds_stress_rejects_aborted_five_and_preserves_four(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[object] = []
    monkeypatch.setattr(buflo_study, "_validate_network_receipt", lambda *args, **kwargs: None)
    network = {"image_digest": "sha256:" + "1" * 64}
    monkeypatch.setattr(
        buflo_study,
        "_validate_timing_stress_binding",
        lambda value, **_kwargs: (
            called.append(value)
            or {
                "passed": True,
                "cohort_version": 37,
                "network": network,
                "source": {"image_digest": network["image_digest"]},
            }
        ),
    )
    common = {
        "stage": "regression",
        "netem_profile": "clean",
        "netem_rank": 0,
        "client_qdisc": "none",
        "server_qdisc": "none",
        "workload_aliases": {"complex": "local-large", "simple": "local-small"},
        "fixture_scope": (
            "single-origin-prefix-regression-plus-bound-two-origin-nine-mode-compatibility"
        ),
        "cohort_version": 37,
        "treatment_order": list(buflo_study.load_study_plan()["regression"]["treatments"]),
        "evidence_class": "controlled-test-only-nonformal",
        "network": network,
    }
    stress_binding = {"path": "/evidence/buflo-timing-stress/receipt.json", "sha256": "0" * 64}
    current = {
        "schema_version": 6,
        **common,
        "timing_stress": stress_binding,
    }
    assert buflo_study.validate_controlled_campaign_receipt(current) == current

    previous = {"schema_version": 5, **common, "timing_stress": stress_binding}
    with pytest.raises(ValueError, match="schema 5 was reserved by failed cohorts"):
        buflo_study.validate_controlled_campaign_receipt(previous)
    assert called == [stress_binding]

    historical = {"schema_version": 4, **common}
    assert buflo_study.validate_controlled_campaign_receipt(historical) == historical


@pytest.mark.parametrize("tamper", ("sibling", "source", "image", "network", "cohort"))
def test_current_and_standalone_regression_stress_binding_rejects_every_identity_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    destination = tmp_path / "regression"
    receipt_path = destination / "buflo-timing-stress/receipt.json"
    receipt_path.parent.mkdir(parents=True)
    image = "sha256:" + "1" * 64
    network: dict[str, Any] = {"image_digest": image, "topology": "exact"}
    receipt_path.write_text(json.dumps({"network": network}), encoding="utf-8")
    lineage: dict[str, Any] = {"image_digest": image, "lab_commit": "lab"}
    stress = {
        "source": dict(lineage),
        "network": dict(network),
        "cohort_version": 37,
    }
    binding_path = receipt_path
    if tamper == "sibling":
        binding_path = destination / "other/receipt.json"
    elif tamper == "source":
        stress["source"] = {**lineage, "lab_commit": "other"}
    elif tamper == "image":
        stress["source"] = {**lineage, "image_digest": "sha256:" + "2" * 64}
    elif tamper == "network":
        stress["network"] = {**network, "topology": "other"}
    elif tamper == "cohort":
        stress["cohort_version"] = 38
    binding = {"path": str(binding_path), "sha256": "0" * 64}
    controlled = {
        "schema_version": 6,
        "network": network,
        "cohort_version": 37,
        "timing_stress": binding,
    }
    receipts = [dict(controlled) for _ in range(3)]
    monkeypatch.setattr(
        buflo_study,
        "_validate_timing_stress_binding",
        lambda value, **_kwargs: stress,
    )

    with pytest.raises(ValueError, match="timing-stress"):
        buflo_study._validate_current_regression_timing_stress(
            receipts,
            destination=destination,
            lineage=lineage,
        )


def test_current_regression_stress_binding_accepts_exact_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "regression"
    receipt_path = destination / "buflo-timing-stress/receipt.json"
    receipt_path.parent.mkdir(parents=True)
    image = "sha256:" + "1" * 64
    network = {"image_digest": image, "topology": "exact"}
    receipt_path.write_text(json.dumps({"network": network}), encoding="utf-8")
    lineage = {"image_digest": image, "lab_commit": "lab"}
    stress = {
        "source": lineage,
        "network": network,
        "cohort_version": 37,
        "passed": True,
    }
    binding = {"path": str(receipt_path), "sha256": "0" * 64}
    controlled = {
        "schema_version": 6,
        "network": network,
        "cohort_version": 37,
        "timing_stress": binding,
    }
    monkeypatch.setattr(
        buflo_study,
        "_validate_timing_stress_binding",
        lambda value, **_kwargs: stress,
    )

    assert (
        buflo_study._validate_current_regression_timing_stress(
            [dict(controlled) for _ in range(3)],
            destination=destination,
            lineage=lineage,
        )
        == stress
    )
