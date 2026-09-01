from __future__ import annotations

import base64
import shutil
from pathlib import Path
from typing import Any

import pytest

import qcsd_lab.orchestrator as orchestrator
import qcsd_lab.buflo_study as buflo_study
from qcsd_lab.experiment import input_digest, load_experiment
from qcsd_lab.orchestrator import resume_campaign, run_campaign
from qcsd_lab.util import atomic_json, load_json
from qcsd_lab.verification import verify_result

from .test_campaign import (
    _configuration,
    _install_attempt_scheduler_evidence,
    _resource,
    _write_pacing_miss,
    _write_successful_attempt,
)


class _InterruptAfterOneAccepted:
    def __init__(self, *, install_scheduler_evidence: bool = False) -> None:
        self.calls: list[tuple[str, str, int]] = []
        self.install_scheduler_evidence = install_scheduler_evidence

    def __call__(
        self,
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        self.calls.append((workload_id, defense.name, seed))
        if len(self.calls) == 1:
            result = _write_successful_attempt(attempt, workload_id, defense.name)
            if self.install_scheduler_evidence:
                _install_attempt_scheduler_evidence(attempt, result)
            return result
        attempt.mkdir(parents=True)
        (attempt / "unpromoted.tmp").write_text("interrupted", encoding="utf-8")
        raise KeyboardInterrupt("controlled interruption")


class _ResumeCollector:
    def __init__(self, *, install_scheduler_evidence: bool = False) -> None:
        self.calls: list[tuple[str, str, int]] = []
        self.install_scheduler_evidence = install_scheduler_evidence

    def __call__(
        self,
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        self.calls.append((workload_id, defense.name, seed))
        assert not (attempt / "unpromoted.tmp").exists()
        result = _write_successful_attempt(attempt, workload_id, defense.name)
        if self.install_scheduler_evidence:
            _install_attempt_scheduler_evidence(attempt, result)
        return result


class _FailFrontCollector:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(
        self,
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        _seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        self.calls += 1
        if self.calls == 2:
            attempt.mkdir(parents=True)
            return {
                "success": False,
                "failure": {"stage": "collection", "message": "controlled failure"},
            }
        return _write_successful_attempt(attempt, workload_id, defense.name)


def _resume_configuration(tmp_path: Path, *, max_attempts: int = 2) -> Path:
    """Create two undefended visits for resume mechanics without chaff authority."""

    return _configuration(
        tmp_path,
        workloads={
            "alpha": (
                2,
                [_resource(0, "https://alpha.test/", headers=[["accept", "text/html"]])],
            )
        },
        max_attempts=max_attempts,
    )


def _buflo_resume_configuration(tmp_path: Path, *, max_attempts: int = 3) -> Path:
    path = _resume_configuration(tmp_path, max_attempts=max_attempts)
    # Campaigns are YAML; retain the common fixture's exact fields while giving
    # this prospective result the study identity that activates physical-launch
    # accounting.
    import yaml

    campaign = yaml.safe_load(path.read_text(encoding="utf-8"))
    campaign["name"] = "buflo-study-v1-regression-attempt-accounting-1200"
    path.write_text(yaml.safe_dump(campaign, sort_keys=False), encoding="utf-8")
    return path


def _allow_synthetic_study_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "QCSD_STUDY_ENVIRONMENT_B64",
        base64.b64encode(b"{}").decode("ascii"),
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_study_environment_receipt",
        lambda _value, *, expected_image_digest=None: {"passed": True},
    )
    monkeypatch.setattr(
        orchestrator,
        "_redirect_attestation",
        lambda _workload, _sample_path: {
            "prepared_redirect_sequence": [],
            "final_redirect_sequence": [],
            "passed": True,
        },
    )


def _interrupted_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Any]]:
    campaign = _resume_configuration(tmp_path, max_attempts=2)
    monkeypatch.setattr(
        orchestrator.capture_engine,
        "_collect_attempt",
        _InterruptAfterOneAccepted(),
    )
    with pytest.raises(KeyboardInterrupt, match="controlled interruption"):
        run_campaign(campaign, tmp_path / "results")
    [root] = (tmp_path / "results" / "contract-test").iterdir()
    value = load_json(root / "experiment.json")
    return root, value


def _rebind_input_digest(root: Path, experiment: dict[str, Any]) -> None:
    experiment["input_digest"] = input_digest(
        root,
        source=experiment["source"],
        configuration=experiment["configuration"],
        samples=experiment["samples"],
    )
    atomic_json(root / "experiment.json", experiment)


def test_resume_keeps_accepted_samples_and_discards_only_interrupted_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _resume_configuration(tmp_path, max_attempts=2)
    interrupted = _InterruptAfterOneAccepted()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", interrupted)

    with pytest.raises(KeyboardInterrupt, match="controlled interruption"):
        run_campaign(campaign, tmp_path / "results")

    [root] = (tmp_path / "results" / "contract-test").iterdir()
    before = load_experiment(root)
    accepted_before = next(sample for sample in before["samples"] if sample["state"] == "accepted")
    running_before = next(sample for sample in before["samples"] if sample["state"] == "running")
    accepted_bytes = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in (root / accepted_before["path"]).rglob("*")
        if path.is_file()
    }
    stale_attempt = (
        root
        / "failures"
        / running_before["sample_id"]
        / f"attempt-{running_before['attempts']:03d}"
    )
    assert (stale_attempt / "unpromoted.tmp").is_file()
    assert not (root / "evidence.sha256").exists()

    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)
    assert resume_campaign(root) == root

    verified = verify_result(root)
    after = verified.experiment
    accepted_after = next(
        sample for sample in after["samples"] if sample["sample_id"] == accepted_before["sample_id"]
    )
    assert accepted_after["attempts"] == accepted_before["attempts"] == 1
    assert resumed.calls == [
        (
            running_before["workload_id"],
            running_before["defense"],
            running_before["seed"],
        )
    ]
    assert {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in (root / accepted_after["path"]).rglob("*")
        if path.is_file()
    } == accepted_bytes
    assert not stale_attempt.exists()
    assert after["status"] == "complete"
    assert after["summary"]["passed"] is True


def test_buflo_resume_counts_and_receipts_a_hard_interruption_as_a_physical_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _buflo_resume_configuration(tmp_path, max_attempts=3)
    _allow_synthetic_study_environment(monkeypatch)
    results_root = tmp_path / "results"
    results_root.mkdir()
    interrupted = _InterruptAfterOneAccepted(install_scheduler_evidence=True)
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", interrupted)

    with pytest.raises(KeyboardInterrupt, match="controlled interruption"):
        run_campaign(campaign, results_root)

    [root] = (results_root / "buflo-study-v1-regression-attempt-accounting-1200").iterdir()
    before = load_experiment(root)
    running = next(sample for sample in before["samples"] if sample["state"] == "running")
    assert running["attempts"] == 1

    resumed = _ResumeCollector(install_scheduler_evidence=True)
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)
    assert resume_campaign(root) == root

    after = verify_result(root).experiment
    retried = next(
        sample for sample in after["samples"] if sample["sample_id"] == running["sample_id"]
    )
    assert retried["attempts"] == 2
    tombstone = root / "failures" / running["sample_id"] / "attempt-001/failure.json"
    assert load_json(tombstone) == {
        "stage": "interruption",
        "type": "HardInterruption",
        "message": "collector process stopped after the physical launch checkpoint",
        "physical_attempt": 1,
    }


def test_buflo_resume_cannot_exceed_total_launch_cap_after_hard_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _buflo_resume_configuration(tmp_path, max_attempts=1)
    _allow_synthetic_study_environment(monkeypatch)
    results_root = tmp_path / "results"
    results_root.mkdir()
    interrupted = _InterruptAfterOneAccepted(install_scheduler_evidence=True)
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", interrupted)

    with pytest.raises(KeyboardInterrupt, match="controlled interruption"):
        run_campaign(campaign, results_root)

    [root] = (results_root / "buflo-study-v1-regression-attempt-accounting-1200").iterdir()
    resumed = _ResumeCollector(install_scheduler_evidence=True)
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)
    with pytest.raises(orchestrator.CampaignIncomplete):
        resume_campaign(root)

    assert resumed.calls == []
    after = verify_result(root).experiment
    exhausted = next(sample for sample in after["samples"] if sample["state"] != "accepted")
    assert exhausted["attempts"] == 1
    assert exhausted["failure"]["type"] == "HardInterruption"


def test_resume_discards_only_recognizable_uncommitted_atomic_write_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _experiment = _interrupted_result(tmp_path, monkeypatch)
    top_level = root / ".experiment.json.qcsd-tmp-dead"
    nested = root / "failures/.failure.json.qcsd-tmp-dead"
    top_level.write_text("partial", encoding="utf-8")
    nested.write_text("partial", encoding="utf-8")
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    assert resume_campaign(root) == root

    assert not top_level.exists()
    assert not nested.exists()
    assert verify_result(root).experiment["status"] == "complete"


def test_resume_retains_completed_failure_left_before_state_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    running = next(sample for sample in experiment["samples"] if sample["state"] == "running")
    attempt = root / "failures" / running["sample_id"] / f"attempt-{running['attempts']:03d}"
    (attempt / "unpromoted.tmp").unlink()
    failure = {
        "stage": "runner",
        "type": "ControlledFailure",
        "message": "durable failure before checkpoint",
    }
    atomic_json(attempt / "failure.json", failure)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    assert resume_campaign(root) == root

    verified = verify_result(root)
    retained = root / "failures" / running["sample_id"] / "attempt-001/failure.json"
    assert load_json(retained) == failure
    recovered = next(
        sample
        for sample in verified.experiment["samples"]
        if sample["sample_id"] == running["sample_id"]
    )
    assert recovered["attempts"] == 2
    assert len(resumed.calls) == 1


def test_resume_promotes_completed_success_left_before_promotion_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    running = next(sample for sample in experiment["samples"] if sample["state"] == "running")
    attempt = root / "failures" / running["sample_id"] / f"attempt-{running['attempts']:03d}"
    (attempt / "unpromoted.tmp").unlink()
    receipt = _write_successful_attempt(
        attempt,
        running["workload_id"],
        running["defense"],
    )
    atomic_json(attempt / "attempt.json", receipt)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    assert resume_campaign(root) == root

    verified = verify_result(root)
    recovered = next(
        sample
        for sample in verified.experiment["samples"]
        if sample["sample_id"] == running["sample_id"]
    )
    assert recovered["state"] == "accepted"
    assert recovered["attempts"] == 1
    assert resumed.calls == []
    assert not attempt.exists()


def test_resume_rejects_completed_clock_stepped_attempt_before_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    running = next(sample for sample in experiment["samples"] if sample["state"] == "running")
    attempt = root / "failures" / running["sample_id"] / f"attempt-{running['attempts']:03d}"
    (attempt / "unpromoted.tmp").unlink()
    receipt = _write_successful_attempt(attempt, running["workload_id"], running["defense"])
    receipt["views"][0]["direct_runner_reconciliation"].update(
        direct_clock_model="positive-abrupt-steps",
        direct_clock_segment_count=2,
        direct_clock_segments=[{"index": 0}, {"index": 1}],
        direct_clock_step_count=1,
        direct_clock_steps=[{"index": 0}],
    )
    atomic_json(attempt / "attempt.json", receipt)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    assert resume_campaign(root) == root

    verified = verify_result(root)
    recovered = next(
        sample
        for sample in verified.experiment["samples"]
        if sample["sample_id"] == running["sample_id"]
    )
    assert recovered["state"] == "accepted"
    assert recovered["attempts"] == 2
    assert len(resumed.calls) == 1
    retained = load_json(attempt / "attempt.json")
    assert retained["success"] is False
    assert retained["failure"]["type"] == "StrictCaptureClockIntegrityFailure"


def test_resume_rejects_completed_response_drift_before_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    running = next(sample for sample in experiment["samples"] if sample["state"] == "running")
    attempt = root / "failures" / running["sample_id"] / f"attempt-{running['attempts']:03d}"
    (attempt / "unpromoted.tmp").unlink()
    receipt = _write_successful_attempt(
        attempt,
        running["workload_id"],
        running["defense"],
        body_sha256="b" * 64,
    )
    atomic_json(attempt / "attempt.json", receipt)
    monkeypatch.setattr(
        orchestrator,
        "_prepared_response_signature",
        lambda _manifest: [(0, 200, 64, "a" * 64, "succeeded")],
    )
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    assert resume_campaign(root) == root

    verified = verify_result(root)
    recovered = next(
        sample
        for sample in verified.experiment["samples"]
        if sample["sample_id"] == running["sample_id"]
    )
    assert recovered["state"] == "accepted"
    assert recovered["eligible"] is True
    assert recovered["attempts"] == 2
    assert len(resumed.calls) == 1
    retained = load_json(attempt / "attempt.json")
    assert retained["success"] is False
    assert retained["failure"]["type"] == "StrictPreparedResponseIdentityFailure"
    assert attempt.relative_to(root).as_posix() + "/attempt.json" in verified.checksums


def test_defended_pacing_miss_is_recorded_as_a_fidelity_failure(tmp_path: Path) -> None:
    attempt = tmp_path / "attempt"
    receipt = _write_successful_attempt(attempt, "alpha", "front")
    _write_pacing_miss(attempt)
    failure = orchestrator._intrinsic_fidelity_failure(
        {"defense": "front", "runtime_kind": "front"},
        receipt,
        attempt,
    )
    assert failure is not None
    failed_receipt = orchestrator._record_fidelity_failure(attempt, receipt, failure)
    assert failed_receipt["success"] is False
    assert failed_receipt["failure"]["stage"] == "fidelity"
    assert load_json(attempt / "attempt.json") == failed_receipt


def test_resume_rejects_mutated_accepted_evidence_before_collecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _resume_configuration(tmp_path, max_attempts=2)
    interrupted = _InterruptAfterOneAccepted()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", interrupted)
    with pytest.raises(KeyboardInterrupt):
        run_campaign(campaign, tmp_path / "results")

    [root] = (tmp_path / "results" / "contract-test").iterdir()
    experiment = load_experiment(root)
    accepted = next(sample for sample in experiment["samples"] if sample["state"] == "accepted")
    (root / accepted["path"] / "capture.pcapng").write_bytes(b"tampered")
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(ValueError, match="accepted sample hash mismatch"):
        resume_campaign(root)
    assert resumed.calls == []


def test_resume_recovers_sample_promoted_before_accepted_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _resume_configuration(tmp_path, max_attempts=2)
    collector = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)
    promote = orchestrator._promote_attempt
    promoted: list[str] = []

    def crash_after_second_promotion(root: Path, sample: dict[str, Any], attempt: Path) -> None:
        promote(root, sample, attempt)
        promoted.append(sample["sample_id"])
        if len(promoted) == 2:
            raise KeyboardInterrupt("controlled crash after promotion")

    monkeypatch.setattr(orchestrator, "_promote_attempt", crash_after_second_promotion)
    with pytest.raises(KeyboardInterrupt, match="controlled crash after promotion"):
        run_campaign(campaign, tmp_path / "results")

    [root] = (tmp_path / "results" / "contract-test").iterdir()
    before = load_experiment(root)
    accepted = next(sample for sample in before["samples"] if sample["state"] == "accepted")
    running = next(sample for sample in before["samples"] if sample["state"] == "running")
    accepted_bytes = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in (root / accepted["path"]).rglob("*")
        if path.is_file()
    }
    assert (root / running["path"] / "capture.pcapng").is_file()

    monkeypatch.setattr(orchestrator, "_promote_attempt", promote)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)
    assert resume_campaign(root) == root

    after = verify_result(root).experiment
    assert resumed.calls == []
    assert {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in (root / accepted["path"]).rglob("*")
        if path.is_file()
    } == accepted_bytes
    assert after["summary"]["passed"] is True


def test_resume_finishes_validated_attempt_interrupted_before_atomic_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _resume_configuration(tmp_path, max_attempts=2)
    collector = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)
    promote = orchestrator._promote_attempt
    promotions = 0

    def crash_before_second_promotion(root: Path, sample: dict[str, Any], attempt: Path) -> None:
        nonlocal promotions
        promotions += 1
        if promotions == 2:
            raise KeyboardInterrupt("controlled crash before promotion")
        promote(root, sample, attempt)

    monkeypatch.setattr(orchestrator, "_promote_attempt", crash_before_second_promotion)
    with pytest.raises(KeyboardInterrupt, match="controlled crash before promotion"):
        run_campaign(campaign, tmp_path / "results")

    [root] = (tmp_path / "results" / "contract-test").iterdir()
    before = load_experiment(root)
    running = next(sample for sample in before["samples"] if sample["state"] == "running")
    attempt = root / running["diagnostics"]["promotion"]["attempt"]
    assert attempt.is_dir()
    assert not (root / running["path"]).exists()

    monkeypatch.setattr(orchestrator, "_promote_attempt", promote)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)
    assert resume_campaign(root) == root

    verified = verify_result(root)
    assert resumed.calls == []
    assert not attempt.exists()
    assert verified.experiment["summary"]["passed"] is True


def test_resume_revalidates_clock_before_finishing_pending_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _resume_configuration(tmp_path, max_attempts=2)
    collector = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)
    promote = orchestrator._promote_attempt
    promotions = 0

    def crash_before_second_promotion(root: Path, sample: dict[str, Any], attempt: Path) -> None:
        nonlocal promotions
        promotions += 1
        if promotions == 2:
            raise KeyboardInterrupt("controlled crash before promotion")
        promote(root, sample, attempt)

    monkeypatch.setattr(orchestrator, "_promote_attempt", crash_before_second_promotion)
    with pytest.raises(KeyboardInterrupt, match="controlled crash before promotion"):
        run_campaign(campaign, tmp_path / "results")

    [root] = (tmp_path / "results" / "contract-test").iterdir()
    experiment = load_experiment(root)
    running = next(sample for sample in experiment["samples"] if sample["state"] == "running")
    running["diagnostics"]["capture"]["timestamp_type"] = "adapter_unsynced"
    atomic_json(root / "experiment.json", experiment)

    monkeypatch.setattr(orchestrator, "_promote_attempt", promote)
    with pytest.raises(ValueError, match="pending promotion capture clock integrity is invalid"):
        resume_campaign(root)


def test_resume_seals_terminal_complete_checkpoint_without_recollection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _resume_configuration(tmp_path, max_attempts=1)
    collector = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)

    def crash_before_seal(_root: Path) -> None:
        raise KeyboardInterrupt("controlled crash before seal")

    monkeypatch.setattr(orchestrator, "_seal", crash_before_seal)
    with pytest.raises(KeyboardInterrupt, match="controlled crash before seal"):
        run_campaign(campaign, tmp_path / "results")

    [root] = (tmp_path / "results" / "contract-test").iterdir()
    before = load_experiment(root)
    calls_before = list(collector.calls)
    assert before["status"] == "complete"
    assert before["summary"]["passed"] is True
    assert not (root / "evidence.sha256").exists()

    assert resume_campaign(root) == root

    verified = verify_result(root)
    assert verified.experiment == before
    assert collector.calls == calls_before


def test_resume_recovers_terminal_incomplete_checkpoint_before_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _resume_configuration(tmp_path, max_attempts=1)
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", _FailFrontCollector())
    seal = orchestrator._seal

    def crash_before_seal(_root: Path) -> None:
        raise KeyboardInterrupt("controlled crash before incomplete seal")

    monkeypatch.setattr(orchestrator, "_seal", crash_before_seal)
    with pytest.raises(KeyboardInterrupt, match="controlled crash before incomplete seal"):
        run_campaign(campaign, tmp_path / "results")

    [root] = (tmp_path / "results" / "contract-test").iterdir()
    before = load_experiment(root)
    assert before["status"] == "incomplete"
    assert not (root / "evidence.sha256").exists()

    monkeypatch.setattr(orchestrator, "_seal", seal)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)
    assert resume_campaign(root) == root

    verified = verify_result(root)
    assert verified.experiment["status"] == "complete"
    assert len(resumed.calls) == 1
    assert resumed.calls[0][1] == "undefended"


def test_resume_rejects_unsafe_sample_id_before_attempt_path_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    running = next(sample for sample in experiment["samples"] if sample["state"] == "running")
    old_id = running["sample_id"]
    running["sample_id"] = "../../outside"
    experiment["execution_order"] = [
        running["sample_id"] if sample_id == old_id else sample_id
        for sample_id in experiment["execution_order"]
    ]
    atomic_json(root / "experiment.json", experiment)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("must remain", encoding="utf-8")
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(ValueError, match="invalid sample ID"):
        resume_campaign(root)
    assert sentinel.read_text(encoding="utf-8") == "must remain"
    assert resumed.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        "sample_id",
        "workload_and_path",
        "policy_and_path",
        "visit_and_path",
        "defense_and_path",
        "runtime_kind",
        "baseline",
        "seed",
    ],
)
def test_resume_rejects_rebound_sample_identity_not_derived_from_frozen_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    sample = next(sample for sample in experiment["samples"] if sample["state"] == "running")
    old_id = sample["sample_id"]
    if mutation == "sample_id":
        sample["sample_id"] = "safe-but-tampered"
        experiment["execution_order"] = [
            sample["sample_id"] if sample_id == old_id else sample_id
            for sample_id in experiment["execution_order"]
        ]
    elif mutation == "workload_and_path":
        sample["workload_id"] = "other-workload"
    elif mutation == "policy_and_path":
        sample["request_policy"] = "half-duplex"
    elif mutation == "visit_and_path":
        sample["visit"] = 9
    elif mutation == "defense_and_path":
        sample["defense"] = "tamaraw"
    elif mutation == "runtime_kind":
        sample["runtime_kind"] = "tamaraw"
    elif mutation == "baseline":
        sample["baseline"] = not sample["baseline"]
    elif mutation == "seed":
        sample["seed"] += 1
    if mutation.endswith("and_path"):
        sample["path"] = (
            f"samples/{sample['workload_id']}/{sample['request_policy']}/"
            f"visit-{sample['visit']:03d}/{sample['defense']}"
        )
    # Even rewriting the self-contained digest cannot make an altered plan
    # agree with the plan re-derived from the frozen campaign inputs.
    _rebind_input_digest(root, experiment)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(ValueError, match="planned sample identity/order mismatch"):
        resume_campaign(root)
    assert resumed.calls == []


def test_resume_rejects_reordered_execution_even_with_rebound_input_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    experiment["samples"].reverse()
    experiment["execution_order"] = [sample["sample_id"] for sample in experiment["samples"]]
    _rebind_input_digest(root, experiment)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(ValueError, match="planned sample identity/order mismatch"):
        resume_campaign(root)
    assert resumed.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        "campaign_sha256",
        "profile",
        "request_policies",
        "max_attempts",
        "workload_id",
        "workload_visits",
        "workload_manifest",
        "workload_sha256",
        "workload_resource_count",
        "workload_origin_count",
        "defense_name",
        "defense_kind",
        "defense_baseline",
        "defense_configuration",
    ],
)
def test_resume_rejects_rebound_configuration_not_derived_from_frozen_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    configuration = experiment["configuration"]
    workload = configuration["workloads"][0]
    defense = configuration["defenses"][0]
    if mutation == "campaign_sha256":
        configuration["campaign_sha256"] = "0" * 64
    elif mutation == "profile":
        configuration["profile"] = "published"
    elif mutation == "request_policies":
        configuration["request_policies"] = ["half-duplex"]
    elif mutation == "max_attempts":
        configuration["limits"]["max_attempts"] = 3
    elif mutation == "workload_id":
        workload["id"] = "renamed"
    elif mutation == "workload_visits":
        workload["visits"] += 1
    elif mutation == "workload_manifest":
        workload["manifest"] = "inputs/workloads/renamed.json"
    elif mutation == "workload_sha256":
        workload["sha256"] = "0" * 64
    elif mutation == "workload_resource_count":
        workload["resource_count"] += 1
    elif mutation == "workload_origin_count":
        workload["origin_count"] += 1
    elif mutation == "defense_name":
        defense["name"] = "baseline"
    elif mutation == "defense_kind":
        defense["kind"] = "front"
    elif mutation == "defense_baseline":
        defense["baseline"] = False
    else:
        defense["mode"] = "chaff-only"
    _rebind_input_digest(root, experiment)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(
        ValueError,
        match="experiment configuration does not match frozen campaign inputs",
    ):
        resume_campaign(root)
    assert resumed.calls == []


@pytest.mark.parametrize(("field", "replacement"), [("name", "renamed"), ("purpose", "evaluation")])
def test_resume_rejects_rebound_experiment_identity_from_frozen_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    experiment[field] = replacement
    _rebind_input_digest(root, experiment)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(ValueError, match=rf"experiment {field} does not match frozen campaign"):
        resume_campaign(root)
    assert resumed.calls == []


def test_resume_refuses_rebound_terminal_purpose_before_sealing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    experiment["status"] = "incomplete"
    experiment["completed_at"] = "2026-08-06T00:01:00+00:00"
    experiment["purpose"] = "evaluation"
    _rebind_input_digest(root, experiment)

    with pytest.raises(ValueError, match="purpose does not match frozen campaign"):
        resume_campaign(root)
    assert not (root / "evidence.sha256").exists()


@pytest.mark.parametrize(
    "field",
    [
        "parameters",
        "parameters_sha256",
        "provenance",
        "provenance_sha256",
        "input_policy",
    ],
)
def test_resume_rejects_injected_external_parameter_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    baseline = experiment["configuration"]["defenses"][0]
    baseline[field] = "0" * 64 if field.endswith("sha256") else "tampered"
    _rebind_input_digest(root, experiment)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(
        ValueError,
        match="experiment configuration does not match frozen campaign inputs",
    ):
        resume_campaign(root)
    assert resumed.calls == []


def test_reviewed_defended_smoke_cannot_enter_resume_workflow_without_qualification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Path(__file__).parents[1] / "config/defense-params/traffic-morphing-live.json"
    campaign = _configuration(
        tmp_path,
        workloads={"simple": (1, [_resource(0, "https://simple.test/")])},
        defenses=[
            "undefended",
            {
                "name": "traffic-morphing",
                "kind": "traffic_morphing",
                "parameters": str(fixture),
            },
        ],
    )
    called = False

    def collect(*_args: object, **_kwargs: object) -> dict[str, Any]:
        nonlocal called
        called = True
        raise AssertionError

    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collect)
    with pytest.raises(ValueError, match="research-prepared workloads and qualified chaff"):
        run_campaign(campaign, tmp_path / "results")
    assert called is False


def test_resume_rejects_symlinked_attempt_ancestor_without_removing_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _interrupted_result(tmp_path, monkeypatch)
    running = next(sample for sample in experiment["samples"] if sample["state"] == "running")
    failure_root = root / "failures" / running["sample_id"]
    shutil.rmtree(failure_root)
    outside = tmp_path / "outside-attempts"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("must remain", encoding="utf-8")
    failure_root.symlink_to(outside, target_is_directory=True)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(ValueError, match="unsafe attempt path"):
        resume_campaign(root)
    assert sentinel.read_text(encoding="utf-8") == "must remain"
    assert resumed.calls == []
