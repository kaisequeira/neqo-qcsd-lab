from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.experiment import input_digest, load_experiment
from qcsd_lab.orchestrator import resume_campaign, run_campaign
from qcsd_lab.util import atomic_json, load_json
from qcsd_lab.verification import verify_result

from .test_campaign import _configuration, _write_successful_attempt


class _InterruptAfterOneAccepted:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []

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
            return _write_successful_attempt(attempt, workload_id, defense.name)
        attempt.mkdir(parents=True)
        (attempt / "unpromoted.tmp").write_text("interrupted", encoding="utf-8")
        raise KeyboardInterrupt("controlled interruption")


class _ResumeCollector:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []

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
        return _write_successful_attempt(attempt, workload_id, defense.name)


class _FailFrontCollector:
    def __call__(
        self,
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        _seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        if defense.name == "front":
            attempt.mkdir(parents=True)
            return {
                "success": False,
                "failure": {"stage": "collection", "message": "controlled failure"},
            }
        return _write_successful_attempt(attempt, workload_id, defense.name)


def _interrupted_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Any]]:
    campaign = _configuration(tmp_path, max_attempts=2)
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


def _interrupted_smoke_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Any]]:
    campaign = Path(__file__).parents[1] / "config/campaigns/smoke.yml"
    monkeypatch.setattr(
        orchestrator.capture_engine,
        "_respect_origin_cooldown",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        orchestrator.capture_engine,
        "_collect_attempt",
        _InterruptAfterOneAccepted(),
    )
    with pytest.raises(KeyboardInterrupt, match="controlled interruption"):
        run_campaign(campaign, tmp_path / "results")
    [root] = (tmp_path / "results" / "consolidated-smoke").iterdir()
    return root, load_experiment(root)


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
    campaign = _configuration(tmp_path, max_attempts=2)
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


def test_resume_rejects_mutated_accepted_evidence_before_collecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _configuration(tmp_path, max_attempts=2)
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
    campaign = _configuration(tmp_path, max_attempts=2)
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
    campaign = _configuration(tmp_path, max_attempts=2)
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


def test_resume_seals_terminal_complete_checkpoint_without_recollection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = _configuration(tmp_path, max_attempts=1)
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
    campaign = _configuration(tmp_path, max_attempts=1)
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
    assert resumed.calls[0][1] == "front"


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
        workload["visits"] = 2
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
def test_resume_rejects_rebound_external_parameter_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    root, experiment = _interrupted_smoke_result(tmp_path, monkeypatch)
    parameterized = next(
        defense
        for defense in experiment["configuration"]["defenses"]
        if defense["kind"] == "traffic_morphing"
    )
    parameterized[field] = "0" * 64 if field.endswith("sha256") else "tampered"
    _rebind_input_digest(root, experiment)
    resumed = _ResumeCollector()
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", resumed)

    with pytest.raises(
        ValueError,
        match="experiment configuration does not match frozen campaign inputs",
    ):
        resume_campaign(root)
    assert resumed.calls == []


def test_frozen_smoke_inputs_cannot_be_reclassified_for_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _interrupted_smoke_result(tmp_path, monkeypatch)
    frozen_campaign = root / "inputs/campaign.yml"
    value = orchestrator.yaml.safe_load(frozen_campaign.read_text(encoding="utf-8"))
    value["purpose"] = "evaluation"
    frozen_campaign.write_text(
        orchestrator.yaml.safe_dump(value, sort_keys=False), encoding="utf-8"
    )
    experiment["purpose"] = "evaluation"
    experiment["configuration"]["campaign_sha256"] = orchestrator.sha256_file(frozen_campaign)
    _rebind_input_digest(root, experiment)

    with pytest.raises(ValueError, match="research-grade provenance"):
        resume_campaign(root)
    assert not (root / "evidence.sha256").exists()


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
