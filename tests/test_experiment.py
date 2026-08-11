from __future__ import annotations

from pathlib import Path

import pytest

from qcsd_lab.experiment import (
    accepted_sample_hashes,
    accept_sample,
    checkpoint_experiment,
    finalize_experiment,
    initialize_experiment,
    interrupt_running_samples,
    load_experiment,
    result_path,
    set_sample_eligibility,
    transition_sample,
    validate_accepted_samples,
    validate_resume_fingerprints,
)
from qcsd_lab.util import atomic_text, sha256_file


def _configuration(campaign: Path) -> dict:
    return {
        "campaign_sha256": sha256_file(campaign),
        "profile": "live",
        "request_policies": ["as-defined"],
        "workloads": [{"id": "site", "sha256": "b" * 64}],
        "defenses": [{"name": "undefended", "kind": "none"}],
        "limits": {"max_attempts": 3},
    }


def _sample() -> dict:
    return {
        "sample_id": "site-as-defined-000-undefended",
        "workload_id": "site",
        "request_policy": "as-defined",
        "visit": 0,
        "defense": "undefended",
        "runtime_kind": "none",
        "baseline": True,
        "seed": 41,
        "path": "samples/site/as-defined/visit-000/undefended",
    }


def _initialize(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "results" / "campaign" / "run-001"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    atomic_text(campaign, "schema: 1\n")
    experiment = initialize_experiment(
        root,
        name="campaign",
        purpose="smoke",
        run_id="run-001",
        source={"lab_commit": "a" * 40, "image": "sha256:image"},
        configuration=_configuration(campaign),
        samples=[_sample()],
        started_at="2026-08-06T00:00:00+00:00",
    )
    return root, experiment


def _write_artifacts(root: Path) -> Path:
    sample = root / _sample()["path"]
    atomic_text(sample / "capture.pcapng", "capture")
    atomic_text(sample / "neqo/run.json", "{}\n")
    atomic_text(sample / "neqo/packets.csv", "time,size\n")
    atomic_text(sample / "neqo/events.csv", "time,event\n")
    atomic_text(sample / "neqo/schedule.csv", "time,size\n")
    return sample


def test_result_path_is_canonical_and_path_safe(tmp_path):
    assert (
        result_path(tmp_path, "smoke", "20260806T000000Z")
        == (tmp_path / "smoke" / "20260806T000000Z").resolve()
    )
    with pytest.raises(ValueError, match="campaign name"):
        result_path(tmp_path, "../escape", "run")


def test_experiment_checkpoint_owns_sample_lifecycle_and_summary(tmp_path):
    root, experiment = _initialize(tmp_path)
    assert load_experiment(root) == experiment
    assert load_experiment(root)["source"] == {
        "lab_commit": "a" * 40,
        "image": "sha256:image",
    }
    assert (root / "inputs/source.json").is_file()
    assert experiment["summary"] == {
        "planned": 1,
        "accepted": 0,
        "failed": 0,
        "eligible": 0,
        "passed": False,
    }

    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    _write_artifacts(root)
    accepted = accept_sample(
        root,
        experiment,
        _sample()["sample_id"],
        diagnostics={"capture_valid": True},
    )
    assert accepted["artifacts"] == accepted_sample_hashes(root, accepted)
    assert accepted["attempts"] == 1
    set_sample_eligibility(experiment, _sample()["sample_id"], True)
    checkpoint_experiment(root, experiment)
    summary = finalize_experiment(
        root,
        experiment,
        status="complete",
        completed_at="2026-08-06T00:01:00+00:00",
    )
    assert summary == {
        "planned": 1,
        "accepted": 1,
        "failed": 0,
        "eligible": 1,
        "passed": True,
    }
    assert validate_accepted_samples(root) == {_sample()["sample_id"]: accepted["artifacts"]}


def test_accepted_sample_hashes_are_exact_and_require_canonical_artifacts(tmp_path):
    root, experiment = _initialize(tmp_path)
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    sample = _write_artifacts(root)
    (sample / "neqo/schedule.csv").unlink()
    with pytest.raises(ValueError, match="missing.*schedule.csv"):
        accept_sample(root, experiment, _sample()["sample_id"])

    atomic_text(sample / "neqo/schedule.csv", "time,size\n")
    atomic_text(sample / "unexpected.log", "not canonical")
    with pytest.raises(ValueError, match="extra.*unexpected.log"):
        accept_sample(root, experiment, _sample()["sample_id"])
    (sample / "unexpected.log").unlink()
    accept_sample(root, experiment, _sample()["sample_id"])
    atomic_text(sample / "neqo/run.json", '{"tampered":true}\n')
    with pytest.raises(ValueError, match="modified.*run.json"):
        validate_accepted_samples(root, experiment)

    atomic_text(sample / "neqo/run.json", "{}\n")
    atomic_text(sample / "unexpected.log", "not canonical")
    with pytest.raises(ValueError, match="extra.*unexpected.log"):
        validate_accepted_samples(root, experiment)


def test_nonaccepted_sample_files_cannot_enter_authoritative_samples(tmp_path):
    root, experiment = _initialize(tmp_path)
    atomic_text(root / _sample()["path"] / "partial.tmp", "interrupted")
    with pytest.raises(ValueError, match="unbound files.*partial.tmp"):
        validate_accepted_samples(root, experiment)


def test_resume_fingerprint_binds_source_configuration_and_input_bytes(tmp_path):
    root, experiment = _initialize(tmp_path)
    assert (
        validate_resume_fingerprints(
            root,
            experiment=experiment,
            expected_source=experiment["source"],
            expected_configuration=experiment["configuration"],
        )
        == experiment["input_digest"]
    )

    atomic_text(root / "inputs/campaign.yml", "schema: 2\n")
    with pytest.raises(ValueError, match="input fingerprint mismatch"):
        validate_resume_fingerprints(root, experiment=experiment)


def test_resume_fingerprint_binds_the_immutable_ordered_sample_plan(tmp_path):
    root, experiment = _initialize(tmp_path)
    experiment["samples"][0]["seed"] += 1

    with pytest.raises(ValueError, match="input fingerprint mismatch"):
        validate_resume_fingerprints(root, experiment=experiment)


def test_stale_running_sample_becomes_interrupted_without_losing_attempt_count(tmp_path):
    _, experiment = _initialize(tmp_path)
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    assert interrupt_running_samples(experiment) == [_sample()["sample_id"]]
    sample = experiment["samples"][0]
    assert sample["state"] == "interrupted"
    assert sample["attempts"] == 1
    assert sample["failure"]["stage"] == "interruption"


def test_sealed_experiment_cannot_be_checkpointed(tmp_path):
    root, experiment = _initialize(tmp_path)
    atomic_text(root / "evidence.sha256", "placeholder")
    with pytest.raises(ValueError, match="sealed result is immutable"):
        checkpoint_experiment(root, experiment)
