from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from qcsd_lab import buflo_study
from qcsd_lab.parameters import (
    TIMING_STRESS_INPUT_POLICY,
    validate_parameter_artifact,
)


def test_timing_stress_contract_preserves_frozen_campaign_counts() -> None:
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
        "outgoing_opportunities_per_visit": 5_001,
        "incoming_opportunities_per_visit": 5_001,
        "guarded_outgoing_releases_per_visit": 5_000,
        "full_outgoing_cells_per_visit": 5_001,
        "incoming_bytes_per_visit": 6_001_200,
        "expected_guarded_outgoing_releases": 60_000,
        "expected_outgoing_opportunities": 60_012,
        "expected_incoming_opportunities": 60_012,
        "expected_directional_events": 120_024,
        "formal_evidence": False,
    }
    sensitivity = buflo_study._timing_stress_sensitivity()
    assert sensitivity["guard_population"] == 60_000
    assert sensitivity["iid_detection_probability_at_target"] > 0.95
    assert sensitivity["zero_failure_one_sided_95_percent_upper_rate"] < 1 / 20_000


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
        "schema_version": buflo_study.TIMING_STRESS_SCHEMA_VERSION,
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
        "launched_visits": {},
        "accepted_visits": {
            "visit-000": "attempts/visit-000/attempt-01",
        },
    }

    with pytest.raises(ValueError, match="without a launch"):
        buflo_study._validate_timing_stress_checkpoint(state, require_complete=False)


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


def _write_small_exact_schedule(path: Path) -> None:
    fields = [
        "target_time_us",
        "direction",
        "size",
        "action_time_us",
        "satisfaction",
        "observed_size",
        "miss_reason",
        "slot_id",
        "qcsd_outcome_schema_version",
        "send_policy",
        "desired_udp_bytes",
        "observed_udp_bytes",
        "congestion_reason",
        "credit_advertised_at_us",
        "credit_advertisement_delay_us",
        "credit_consumed_at_us",
        "credit_consumption_delay_us",
        "terminal_defense_elapsed_us",
    ]
    rows: list[dict[str, Any]] = []
    for tick, target in enumerate((0, 20, 40)):
        rows.extend(
            (
                {
                    "target_time_us": target,
                    "direction": "outgoing",
                    "size": 1_200,
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
    path.parent.mkdir(parents=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _small_run() -> dict[str, Any]:
    histogram = {"upper_bounds_nanoseconds": [5_000_000], "counts": [2]}
    return {
        "runner_wakeup_metrics": {
            "schema_version": 9,
            "buflo_exact_release_guard_entries": 2,
            "buflo_exact_release_dispatch_ready_guards": 2,
            "buflo_exact_release_failed_guards": 0,
            "buflo_exact_release_invalid_counter_frequency_guards": 0,
            "buflo_exact_release_counter_unavailable_failure_guards": 0,
            "buflo_exact_release_counter_nonmonotonic_failure_guards": 0,
            "buflo_exact_release_counter_frequency_changed_guards": 0,
            "buflo_exact_release_counter_target_error_guards": 0,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 1_000,
            "buflo_exact_release_dispatch_at_or_after_deadline_guards": 0,
            "buflo_exact_release_active_wait_poll_source": (
                "linux-aarch64-cntvct-el0-predictive-v1"
            ),
            "buflo_exact_release_active_wait_counter_frequency_hz": 1_000_000_000,
            "buflo_exact_release_active_wait_counter_guards": 2,
            "buflo_exact_release_active_wait_counter_unavailable_guards": 0,
            "buflo_exact_release_active_wait_counter_nonmonotonic_guards": 0,
            "buflo_exact_release_active_wait_counter_calibrations": 2,
            "buflo_exact_release_active_wait_instant_confirmations": 2,
            "buflo_exact_release_active_wait_early_confirmation_retries": 0,
            "buflo_exact_release_active_wait_counter_nanoseconds": 20,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 4,
            "buflo_exact_release_max_active_wait_counter_gap_nanoseconds": 4,
            "buflo_exact_release_max_counter_calibration_span_nanoseconds": 3,
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
                "active_wait_poll_source": "linux-aarch64-cntvct-el0-predictive-v1",
                "active_wait_counter_frequency_hz": 1_000_000_000,
                "active_wait_instant_confirmations": 1,
                "active_wait_early_confirmation_retries": 0,
            },
            "buflo_exact_release_last_failure": None,
        },
        "defense_diagnostics": {
            "buflo_scheduled_outgoing_cells": 3,
            "buflo_scheduled_incoming_cells": 3,
            "buflo_full_outgoing_cells": 3,
            "buflo_partial_outgoing_cells": 0,
            "buflo_suppressed_outgoing_cells": 0,
            "buflo_missed_outgoing_cells": 0,
            "buflo_missed_incoming_cells": 0,
            "buflo_outgoing_unresolved_cells": 0,
            "buflo_incoming_unresolved_cells": 0,
            "buflo_catch_up_outgoing_cells": 0,
            "buflo_catch_up_incoming_cells": 0,
            "buflo_event_guard_triggered": False,
            "scheduled_incoming_requested_bytes": 3_600,
            "scheduled_incoming_advertised_bytes": 3_600,
            "scheduled_incoming_consumed_bytes": 3_600,
            "scheduled_incoming_retired_bytes": 0,
            "scheduled_incoming_unresolved_bytes": 0,
        },
    }


def _patch_small_schedule_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    from qcsd_lab import fidelity

    monkeypatch.setattr(buflo_study, "TIMING_STRESS_INTERVAL_US", 20)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_MINIMUM_DURATION_US", 40)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_WINDOW_US", 5)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_OUTGOING_PER_VISIT", 3)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_INCOMING_PER_VISIT", 3)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_GUARDS_PER_VISIT", 2)
    monkeypatch.setattr(buflo_study, "TIMING_STRESS_INCOMING_BYTES_PER_VISIT", 3_600)
    monkeypatch.setattr(fidelity, "_runner_wakeup_metrics_valid", lambda value: True)
    monkeypatch.setattr(
        fidelity,
        "_schedule_realization_metrics",
        lambda path: {
            "scheduled_events": 6,
            "scheduled_outgoing_events": 3,
            "scheduled_incoming_events": 3,
            "satisfied_events": 6,
            "terminal_satisfactions": {"satisfied": 6},
            "missed_events": 0,
            "outgoing_size_mismatch_events": 0,
            "catch_up_events": 0,
            "duplicate_terminal_slots": 0,
            "invalid_terminal_rows": 0,
            "invalid_typed_outcome_rows": 0,
            "incoming_credit_advertised_events": 3,
            "incoming_credit_consumed_events": 3,
            "incoming_credit_missing_events": 0,
            "incoming_credit_consumption_missing_events": 0,
            "invalid_credit_advertisement_events": 0,
            "invalid_credit_consumption_events": 0,
        },
    )


def test_timing_stress_schedule_requires_exact_cells_and_credit_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_small_schedule_contract(monkeypatch)
    _write_small_exact_schedule(tmp_path / "neqo/schedule.csv")
    run = _small_run()

    evidence = buflo_study._timing_stress_schedule_evidence(tmp_path, run)
    assert evidence["full_outgoing_cells"] == 3
    assert evidence["incoming_credit_bytes"] == {
        "requested": 3_600,
        "advertised": 3_600,
        "consumed": 3_600,
        "retired": 0,
        "unresolved": 0,
    }
    assert evidence["runner_wakeup_schema_version"] == 9
    assert evidence["active_wait_counter"]["counter_guards"] == 2
    assert evidence["active_wait_counter"]["instant_confirmations"] == 2

    missing_worst_times = json.loads(json.dumps(run))
    missing_worst_times["runner_wakeup_metrics"]["buflo_exact_release_worst_guard"][
        "release_at_defense_nanoseconds"
    ] = None
    with pytest.raises(ValueError, match="current Linux guard timing evidence"):
        buflo_study._timing_stress_schedule_evidence(tmp_path, missing_worst_times)

    run["defense_diagnostics"]["scheduled_incoming_consumed_bytes"] = 2_400
    with pytest.raises(ValueError, match="terminal diagnostics"):
        buflo_study._timing_stress_schedule_evidence(tmp_path, run)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("buflo_exact_release_active_wait_counter_unavailable_guards", 1),
        ("buflo_exact_release_active_wait_counter_nonmonotonic_guards", 1),
        ("buflo_exact_release_active_wait_counter_calibrations", 3),
        ("buflo_exact_release_active_wait_instant_confirmations", 1),
        ("buflo_exact_release_max_guard_exit_lateness_nanoseconds", 5_000),
    ),
)
def test_schema_nine_timing_stress_rejects_counter_or_authoritative_lateness_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
) -> None:
    _patch_small_schedule_contract(monkeypatch)
    _write_small_exact_schedule(tmp_path / "neqo/schedule.csv")
    run = _small_run()
    run["runner_wakeup_metrics"][field] = value

    with pytest.raises(ValueError, match="current Linux guard timing evidence"):
        buflo_study._timing_stress_schedule_evidence(tmp_path, run)


@pytest.mark.parametrize("schema_version", (6, 7, 8))
def test_timing_stress_rejects_noncurrent_wakeup_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, schema_version: int
) -> None:
    _patch_small_schedule_contract(monkeypatch)
    _write_small_exact_schedule(tmp_path / "neqo/schedule.csv")
    run = _small_run()
    run["runner_wakeup_metrics"]["schema_version"] = schema_version

    with pytest.raises(ValueError, match="current Linux guard timing evidence"):
        buflo_study._timing_stress_schedule_evidence(tmp_path, run)


def test_timing_stress_aggregate_binds_aux_diagnostics_and_byte_totals() -> None:
    timing = {
        "guarded_outgoing_releases": 5_000,
        "guard_outcomes": {
            "entries": 5_000,
            "dispatch_ready": 5_000,
            "failed": 0,
            "typed_failures": {
                "invalid_counter_frequency": 0,
                "counter_unavailable": 0,
                "counter_nonmonotonic": 0,
                "counter_frequency_changed": 0,
                "counter_target_error": 0,
            },
            "last_failure": None,
        },
        "scheduled_outgoing_opportunities": 5_001,
        "scheduled_incoming_opportunities": 5_001,
        "directional_events": 10_002,
        "full_outgoing_cells": 5_001,
        "incoming_credit_bytes": {
            "requested": 6_001_200,
            "advertised": 6_001_200,
            "consumed": 6_001_200,
            "retired": 0,
            "unresolved": 0,
        },
        "max_outgoing_release_lateness_us": 4_999,
        "max_incoming_credit_advertisement_delay_us": 4_999,
        "max_guard_exit_lateness_nanoseconds": 4_999_999,
        "max_active_spin_gap_nanoseconds": 2_264_322,
        "active_wait_counter": {
            "source": "linux-aarch64-cntvct-el0-predictive-v1",
            "frequency_hz": 1_000_000_000,
            "counter_guards": 5_000,
            "unavailable_guards": 0,
            "nonmonotonic_guards": 0,
            "calibrations": 5_000,
            "instant_confirmations": 5_000,
            "early_confirmation_retries": 0,
            "counter_nanoseconds": 25_000_000_000,
            "max_counter_gap_nanoseconds": 2_264_322,
            "max_calibration_span_nanoseconds": 1_000,
        },
        "dispatch_lateness_histogram": {
            "upper_bounds_nanoseconds": [5_000_000],
            "counts": [5_000],
        },
        "active_spin_gap_histogram": {
            "upper_bounds_nanoseconds": [5_000_000],
            "counts": [5_000],
        },
    }
    aggregate = buflo_study._timing_stress_aggregate([{"timing": timing} for _ in range(12)])

    assert aggregate["guarded_outgoing_releases"] == 60_000
    assert aggregate["full_outgoing_cells"] == 60_012
    assert aggregate["incoming_credit_bytes"] == {
        "requested": 72_014_400,
        "advertised": 72_014_400,
        "consumed": 72_014_400,
        "retired": 0,
        "unresolved": 0,
    }
    assert aggregate["active_wait_counter_guards"] == 60_000
    assert aggregate["guard_outcomes"]["dispatch_ready"] == 60_000
    assert aggregate["guard_outcomes"]["failed"] == 0
    assert aggregate["active_wait_instant_confirmations"] == 60_000
    assert aggregate["active_wait_counter_nanoseconds"] == 300_000_000_000
    assert aggregate["max_active_wait_counter_gap_nanoseconds"] == 2_264_322
    assert aggregate["dispatch_lateness_histogram"]["counts"] == [60_000]
    assert aggregate["active_spin_gap_histogram"]["counts"] == [60_000]
    assert set(aggregate["zero_failure_counts"].values()) == {0}


def test_schema_five_regression_receipt_binds_stress_and_preserves_schema_four(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[object] = []
    monkeypatch.setattr(buflo_study, "_validate_network_receipt", lambda *args, **kwargs: None)
    network = {"image_digest": "sha256:" + "1" * 64}
    monkeypatch.setattr(
        buflo_study,
        "_validate_timing_stress_binding",
        lambda value: (
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
        "schema_version": 5,
        **common,
        "timing_stress": stress_binding,
    }
    assert buflo_study.validate_controlled_campaign_receipt(current) == current
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
        "schema_version": 5,
        "network": network,
        "cohort_version": 37,
        "timing_stress": binding,
    }
    receipts = [dict(controlled) for _ in range(3)]
    monkeypatch.setattr(
        buflo_study,
        "_validate_timing_stress_binding",
        lambda value: stress,
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
        "schema_version": 5,
        "network": network,
        "cohort_version": 37,
        "timing_stress": binding,
    }
    monkeypatch.setattr(
        buflo_study,
        "_validate_timing_stress_binding",
        lambda value: stress,
    )

    assert (
        buflo_study._validate_current_regression_timing_stress(
            [dict(controlled) for _ in range(3)],
            destination=destination,
            lineage=lineage,
        )
        == stress
    )
