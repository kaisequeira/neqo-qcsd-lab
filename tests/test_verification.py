from __future__ import annotations

from pathlib import Path

import pytest

import qcsd_lab.orchestrator as orchestrator
import qcsd_lab.verification as verification
from qcsd_lab.experiment import (
    accept_sample,
    checkpoint_experiment,
    finalize_experiment,
    input_digest,
    initialize_experiment,
    transition_sample,
    validate_durable_attempt_evidence,
)
from qcsd_lab.util import atomic_json, atomic_text, sha256_file
from qcsd_lab.verification import (
    authoritative_files,
    prepare_resume,
    reseal_result,
    retire_seal_for_resume,
    seal_result,
    verify_result,
)
from tests.scheduler_fixtures import install_scheduler_runtime_receipt


def _make_result(tmp_path: Path, *, complete: bool = False) -> tuple[Path, dict]:
    root = tmp_path / "results/smoke/run-001"
    config = tmp_path / "config"
    (config / "campaigns").mkdir(parents=True)
    (config / "workloads").mkdir()
    atomic_text(
        config / "workloads/site.json",
        '{"resources":[{"id":0,"url":"https://site.test/","type":"Document",'
        '"content_length":64,"data_length":64,"chaff_priority":true,'
        '"known_valid":true,"depends_on":[],"headers":[]}]}\n',
    )
    campaign_path = config / "campaigns/campaign.yml"
    atomic_text(
        campaign_path,
        "schema: 1\n"
        "name: smoke\n"
        "purpose: smoke\n"
        "seed: 41\n"
        "profile: live\n"
        "workloads:\n  site: 1\n"
        "request_policies:\n  - as-defined\n"
        "defenses:\n  - undefended\n",
    )
    source = {"lab_commit": "a" * 40}
    campaign = orchestrator.load_campaign(campaign_path)
    runtime, configuration = orchestrator._materialize_inputs(root, campaign, source)
    [planned] = orchestrator.plan_campaign(runtime)
    experiment = initialize_experiment(
        root,
        name="smoke",
        purpose="smoke",
        run_id="run-001",
        source=source,
        configuration=configuration,
        samples=[planned],
        started_at="2026-08-06T00:00:00+00:00",
    )
    transition_sample(experiment, planned["sample_id"], "running", increment_attempt=True)
    sample = root / planned["path"]
    atomic_text(sample / "capture.pcapng", "capture")
    atomic_text(sample / "neqo/run.json", "{}\n")
    atomic_text(sample / "neqo/packets.csv", "time,size\n")
    atomic_text(sample / "neqo/events.csv", "time,event\n")
    atomic_text(sample / "neqo/schedule.csv", "time,size\n")
    accept_sample(root, experiment, planned["sample_id"], eligible=complete)
    checkpoint_experiment(root, experiment)
    finalize_experiment(
        root,
        experiment,
        status="complete" if complete else "incomplete",
        completed_at="2026-08-06T00:01:00+00:00",
    )
    return root, experiment


def _make_durable_result(tmp_path: Path) -> tuple[Path, dict]:
    root, experiment = _make_result(tmp_path, complete=True)
    experiment["name"] = "buflo-study-v1-attempt-evidence-test"
    [sample] = experiment["samples"]
    run_path = root / sample["path"] / "neqo/run.json"
    run: dict = {}
    diagnostics: dict = {}
    install_scheduler_runtime_receipt(run, diagnostics)
    atomic_json(run_path, run)
    sample["diagnostics"] = diagnostics
    relative = run_path.relative_to(root).as_posix()
    sample["artifacts"][relative] = sha256_file(run_path)
    atomic_json(root / "experiment.json", experiment)
    return root, experiment


def _write_failure_receipt(path: Path, failure: dict) -> None:
    path.mkdir(parents=True)
    atomic_json(path / "failure.json", failure)


def test_generated_successor_create_checkpoint_seal_and_verify_is_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        verification,
        "_validate_frozen_contract",
        lambda *_args, **_kwargs: None,
    )
    study_id = "classifier-multiorigin100-v2-g01-0123456789ab"
    name = f"{study_id}-formal-01-1200"
    root = tmp_path / "results" / name / "run-001"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    atomic_text(campaign, "schema: 2\n")
    configuration = {
        "campaign_sha256": sha256_file(campaign),
        "profile": "research-1200",
        "request_policies": ["as-defined"],
        "workloads": [{"id": "site", "sha256": "b" * 64}],
        "defenses": [{"name": "undefended", "kind": "none"}],
        "limits": {"max_attempts": 3},
        "evidence_role": "formal",
        "class_study_cohort_sha256": "c" * 64,
        "class_study_cohort_assembly_sha256": "d" * 64,
        "class_study_id": study_id,
        "class_study_launch_sha256": "e" * 64,
        "class_study_foundation_sha256": "f" * 64,
        "class_study_successor_sha256": "1" * 64,
        "class_study_readiness_sha256": "2" * 64,
        "class_study_historical_pre_snapshot_sha256": "3" * 64,
        "public_origin_policy": {
            "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
            "required_value": "1",
            "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
        },
    }
    planned = {
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
    experiment = initialize_experiment(
        root,
        name=name,
        purpose="evaluation",
        run_id="run-001",
        source={"lab_commit": "a" * 40},
        configuration=configuration,
        samples=[planned],
        started_at="2026-09-06T00:00:00+00:00",
    )
    transition_sample(experiment, planned["sample_id"], "running", increment_attempt=True)
    failure = {"stage": "collection", "type": "UnexpectedFailure"}
    _write_failure_receipt(
        root / "failures" / planned["sample_id"] / "attempt-001",
        failure,
    )
    transition_sample(
        experiment,
        planned["sample_id"],
        "failed",
        failure=failure,
        eligible=False,
    )
    checkpoint_experiment(root, experiment)
    finalize_experiment(
        root,
        experiment,
        status="incomplete",
        completed_at="2026-09-06T00:01:00+00:00",
    )

    seal_result(root)
    verified = verify_result(root)

    assert verified.experiment["configuration"]["class_study_id"] == study_id
    assert (
        f"failures/{planned['sample_id']}/attempt-001/failure.json"
        in verified.checksums
    )


def test_seal_is_deterministic_and_excludes_rebuildable_derived_files(tmp_path):
    root, _ = _make_result(tmp_path, complete=True)
    atomic_text(root / "derived/report.html", "first report")
    checksums = seal_result(root)
    first = (root / "evidence.sha256").read_bytes()
    assert list(checksums) == sorted(checksums)
    assert all(not path.startswith("derived/") for path in checksums)
    verified = verify_result(root)
    assert verified.checksums == checksums
    assert verified.as_dict() == {
        "valid": True,
        "root": str(root.resolve()),
        "name": "smoke",
        "purpose": "smoke",
        "status": "complete",
        "authoritative_files": len(checksums),
        "accepted_samples": 1,
    }

    atomic_text(root / "derived/report.html", "regenerated report")
    atomic_text(root / "derived/plots/trace.svg", "<svg/>")
    assert verify_result(root).checksums == checksums
    assert seal_result(root) == checksums
    assert (root / "evidence.sha256").read_bytes() == first


def test_verify_rejects_coherently_resealed_scheduler_runtime_tampering(
    tmp_path: Path,
) -> None:
    root, experiment = _make_result(tmp_path, complete=True)
    [sample] = experiment["samples"]
    run_path = root / sample["path"] / "neqo/run.json"
    run = {}
    diagnostics: dict = {}
    install_scheduler_runtime_receipt(run, diagnostics)
    atomic_json(run_path, run)
    sample["diagnostics"] = diagnostics
    relative = run_path.relative_to(root).as_posix()
    sample["artifacts"][relative] = sha256_file(run_path)
    atomic_json(root / "experiment.json", experiment)
    seal_result(root)
    verify_result(root)

    receipt = sample["diagnostics"]["scheduler_runtime_receipt"]
    receipt["scheduler_runtime_evidence"]["proc_stat_steal"]["steal_ticks_delta"] = 1
    atomic_json(root / "experiment.json", experiment)
    checksums = {
        relative: sha256_file(path) for relative, path in authoritative_files(root).items()
    }
    atomic_text(
        root / "evidence.sha256",
        "".join(f"{checksums[path]}  {path}\n" for path in sorted(checksums)),
    )

    with pytest.raises(ValueError, match="scheduler runtime receipt is invalid"):
        verify_result(root)


def test_seal_and_verify_enforce_durable_physical_attempt_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(verification, "_validate_frozen_contract", lambda *_args, **_kwargs: None)

    seal_root, seal_experiment = _make_durable_result(tmp_path / "seal")
    [seal_sample] = seal_experiment["samples"]
    _write_failure_receipt(
        seal_root / "failures" / seal_sample["sample_id"] / "attempt-001",
        {"stage": "collection", "type": "UnexpectedFailure"},
    )
    with pytest.raises(ValueError, match="unexpected durable failed-attempt evidence"):
        seal_result(seal_root)
    assert not (seal_root / "evidence.sha256").exists()

    verify_root, verify_experiment = _make_durable_result(tmp_path / "verify")
    seal_result(verify_root)
    verify_experiment["samples"][0]["attempts"] = 2
    atomic_json(verify_root / "experiment.json", verify_experiment)
    checksums = {
        relative: sha256_file(path) for relative, path in authoritative_files(verify_root).items()
    }
    atomic_text(
        verify_root / "evidence.sha256",
        "".join(f"{checksums[path]}  {path}\n" for path in sorted(checksums)),
    )
    with pytest.raises(ValueError, match="lacks its durable failed-attempt directory"):
        verify_result(verify_root)


@pytest.mark.parametrize(
    "terminal_type",
    ["StrictDefenseFidelityFailure", "StrictClientDefenseExecutionFailure"],
)
@pytest.mark.parametrize(
    "study_id",
    (
        "classifier-multiorigin100-v1",
        "classifier-multiorigin100-v2-g01-0123456789ab",
    ),
)
def test_durable_attempt_evidence_requires_exact_contiguous_terminal_receipts(
    tmp_path: Path,
    terminal_type: str,
    study_id: str,
) -> None:
    root = tmp_path / "durable"
    (root / "failures").mkdir(parents=True)
    previous_failure = {"stage": "collection", "type": "TransientFailure"}
    terminal_failure = {"stage": "fidelity", "type": terminal_type}
    sample_id = "sample-001"
    first = root / "failures" / sample_id / "attempt-001"
    second = root / "failures" / sample_id / "attempt-002"
    _write_failure_receipt(first, previous_failure)
    atomic_json(
        second / "attempt.json",
        {"success": False, "failure": terminal_failure},
    )
    experiment = {
        "name": f"{study_id}-formal-01-1200",
        "configuration": {
            "class_study_id": study_id,
            "limits": {"max_attempts": 3},
        },
        "samples": [
            {
                "sample_id": sample_id,
                "state": "failed",
                "attempts": 2,
                "failure": terminal_failure,
            }
        ],
    }
    validate_durable_attempt_evidence(root, experiment)

    experiment["samples"][0].update(
        state="accepted",
        attempts=3,
        failure=None,
    )
    with pytest.raises(ValueError, match="retried after a terminal client defence/QCSD"):
        validate_durable_attempt_evidence(root, experiment)
    experiment["samples"][0].update(
        state="failed",
        attempts=2,
        failure=terminal_failure,
    )

    atomic_json(
        second / "attempt.json",
        {"success": True, "failure": terminal_failure},
    )
    with pytest.raises(ValueError, match="not a terminal failure"):
        validate_durable_attempt_evidence(root, experiment)
    atomic_json(
        second / "attempt.json",
        {"success": False, "failure": terminal_failure},
    )

    extra = root / "failures" / sample_id / "attempt-003"
    _write_failure_receipt(extra, previous_failure)
    with pytest.raises(ValueError, match="not exact and contiguous"):
        validate_durable_attempt_evidence(root, experiment)
    unknown = root / "failures" / "unknown-sample"
    extra.rename(unknown)
    with pytest.raises(ValueError, match="failed-sample inventory"):
        validate_durable_attempt_evidence(root, experiment)
    unknown.rename(extra)
    experiment["samples"][0]["attempts"] = 3
    experiment["samples"][0]["failure"] = {"stage": "fidelity", "type": "OtherFailure"}
    with pytest.raises(ValueError, match="terminal client defence/QCSD failure"):
        validate_durable_attempt_evidence(root, experiment)


def test_incomplete_durable_result_can_seal_unlaunched_tail_after_defect(
    tmp_path: Path,
) -> None:
    root = tmp_path / "partial"
    (root / "failures").mkdir(parents=True)
    experiment = {
        "name": "classifier-multiorigin100-v1-formal-01-1200",
        "status": "incomplete",
        "configuration": {
            "class_study_id": "classifier-multiorigin100-v1",
            "limits": {"max_attempts": 3},
        },
        "samples": [
            {
                "sample_id": "unlaunched-001",
                "state": "planned",
                "attempts": 0,
                "failure": None,
            }
        ],
    }

    validate_durable_attempt_evidence(root, experiment)

    (root / "failures/unlaunched-001").mkdir()
    with pytest.raises(ValueError, match="unlaunched sample.*unexpected"):
        validate_durable_attempt_evidence(root, experiment)


def test_legacy_generic_result_keeps_per_invocation_attempt_compatibility(tmp_path: Path) -> None:
    root, experiment = _make_result(tmp_path, complete=True)
    experiment["samples"][0]["attempts"] = 2
    atomic_json(root / "experiment.json", experiment)

    seal_result(root)

    assert verify_result(root).experiment["samples"][0]["attempts"] == 2


@pytest.mark.parametrize("mutation", ["missing", "modified", "extra"])
def test_verification_rejects_missing_modified_and_extra_authoritative_files(tmp_path, mutation):
    root, _ = _make_result(tmp_path, complete=True)
    seal_result(root)
    run = root / "samples/site/as-defined/visit-000/undefended/neqo/run.json"
    if mutation == "missing":
        run.unlink()
    elif mutation == "modified":
        atomic_text(run, '{"changed":true}\n')
    else:
        atomic_text(root / "samples/site/as-defined/visit-000/undefended/extra.txt", "extra")
    with pytest.raises(ValueError, match=mutation):
        verify_result(root)


def test_verification_rejects_unknown_top_level_files_but_not_derived(tmp_path):
    root, _ = _make_result(tmp_path, complete=True)
    atomic_text(root / "legacy.jsonl", "{}\n")
    with pytest.raises(ValueError, match="unknown top-level.*legacy.jsonl"):
        seal_result(root)


@pytest.mark.parametrize(
    "relative",
    [
        "inputs/campaign.yml",
        "samples/site/as-defined/visit-000/undefended/capture.pcapng",
        "samples/site/as-defined/visit-000/undefended/neqo/run.json",
    ],
)
def test_campaign_capture_and_neqo_tampering_each_fail_verification(tmp_path, relative):
    root, _ = _make_result(tmp_path, complete=True)
    seal_result(root)
    path = root / relative
    path.write_bytes(path.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="modified authoritative evidence"):
        verify_result(root)


def test_checksum_tampering_fails_verification(tmp_path):
    root, _ = _make_result(tmp_path, complete=True)
    seal_result(root)
    index = root / "evidence.sha256"
    content = index.read_text(encoding="utf-8")
    index.write_text(("0" if content[0] != "0" else "1") + content[1:], encoding="utf-8")
    with pytest.raises(ValueError, match="modified authoritative evidence"):
        verify_result(root)


def test_bad_resume_fingerprint_preserves_verified_seal(tmp_path):
    root, experiment = _make_result(tmp_path)
    seal_result(root)
    before = (root / "evidence.sha256").read_bytes()
    with pytest.raises(ValueError, match="source fingerprint mismatch"):
        retire_seal_for_resume(root, expected_source={"lab_commit": "f" * 40})
    assert (root / "evidence.sha256").read_bytes() == before
    assert verify_result(root).experiment == experiment


def test_historical_read_only_contract_rejection_preserves_verified_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _make_result(tmp_path)
    seal_result(root)
    before_seal = (root / "evidence.sha256").read_bytes()
    before_experiment = (root / "experiment.json").read_bytes()
    original = verification._validate_frozen_contract

    def historical_only(
        candidate_root: Path,
        candidate_experiment: dict,
        *,
        allow_historical_research_bundle: bool,
    ) -> None:
        if not allow_historical_research_bundle:
            raise ValueError("legacy bundle is frozen historical evidence only")
        original(
            candidate_root,
            candidate_experiment,
            allow_historical_research_bundle=True,
        )

    monkeypatch.setattr(verification, "_validate_frozen_contract", historical_only)
    assert verify_result(root).experiment == experiment
    with pytest.raises(ValueError, match="frozen historical evidence"):
        prepare_resume(root)
    assert (root / "evidence.sha256").read_bytes() == before_seal
    assert (root / "experiment.json").read_bytes() == before_experiment


def test_incomplete_seal_can_be_retired_resumed_and_resealed(tmp_path):
    root, experiment = _make_result(tmp_path)
    original_artifacts = dict(experiment["samples"][0]["artifacts"])
    seal_result(root)
    resumed = retire_seal_for_resume(
        root,
        expected_source=experiment["source"],
        expected_configuration=experiment["configuration"],
        expected_input_digest=experiment["input_digest"],
    )
    assert not (root / "evidence.sha256").exists()
    assert resumed["status"] == "running"
    assert resumed["samples"][0]["artifacts"] == original_artifacts

    finalize_experiment(
        root,
        resumed,
        status="incomplete",
        completed_at="2026-08-06T00:02:00+00:00",
    )
    reseal_result(root)
    assert verify_result(root).accepted_samples[resumed["samples"][0]["sample_id"]] == (
        original_artifacts
    )


def test_complete_result_refuses_resume_without_retiring_seal(tmp_path):
    root, _ = _make_result(tmp_path, complete=True)
    seal_result(root)
    before = (root / "evidence.sha256").read_bytes()
    with pytest.raises(ValueError, match="completed result cannot be resumed"):
        prepare_resume(root)
    assert (root / "evidence.sha256").read_bytes() == before


def test_seal_rejects_self_rebound_experiment_purpose(tmp_path: Path) -> None:
    root, experiment = _make_result(tmp_path, complete=True)
    experiment["purpose"] = "evaluation"
    experiment["input_digest"] = input_digest(
        root,
        source=experiment["source"],
        configuration=experiment["configuration"],
        samples=experiment["samples"],
    )
    atomic_json(root / "experiment.json", experiment)

    with pytest.raises(ValueError, match="purpose does not match frozen campaign"):
        seal_result(root)
    assert not (root / "evidence.sha256").exists()


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("timeout_seconds", 121),
        ("max_response_bytes", 1_048_575),
        ("capture_seconds", 181),
        ("capture_megabytes", 63),
        ("max_attempts", 2),
        ("per_origin_cooldown_seconds", 29),
        ("settle_seconds", 2),
    ),
)
def test_verify_rejects_every_consistently_resealed_limit_mutation(
    tmp_path: Path,
    field: str,
    replacement: int,
) -> None:
    root, experiment = _make_result(tmp_path, complete=True)
    experiment["configuration"]["limits"][field] = replacement
    experiment["input_digest"] = input_digest(
        root,
        source=experiment["source"],
        configuration=experiment["configuration"],
        samples=experiment["samples"],
    )
    atomic_json(root / "experiment.json", experiment)
    checksums = {
        relative: sha256_file(path) for relative, path in authoritative_files(root).items()
    }
    atomic_text(
        root / "evidence.sha256",
        "".join(f"{checksums[path]}  {path}\n" for path in sorted(checksums)),
    )

    with pytest.raises(ValueError, match="configuration does not match frozen campaign"):
        verify_result(root)


def test_unsealed_resume_marks_stale_attempt_interrupted(tmp_path):
    root = tmp_path / "results/smoke/run-001"
    inputs = root / "inputs"
    (inputs / "workloads").mkdir(parents=True)
    atomic_text(
        inputs / "workloads/site.json",
        '{"resources":[{"id":0,"url":"https://site.test/","type":"Document",'
        '"content_length":64,"data_length":64,"chaff_priority":true,'
        '"known_valid":true,"depends_on":[],"headers":[]}]}\n',
    )
    campaign = inputs / "campaign.yml"
    atomic_text(
        campaign,
        "schema: 1\n"
        "name: smoke\n"
        "purpose: smoke\n"
        "seed: 41\n"
        "profile: live\n"
        "workloads:\n  site: 1\n"
        "request_policies:\n  - as-defined\n"
        "defenses:\n  - undefended\n",
    )
    frozen_campaign = orchestrator._campaign_from_frozen_inputs(root)
    configuration = orchestrator._frozen_configuration(root, frozen_campaign)
    [sample] = orchestrator.plan_campaign(frozen_campaign)
    experiment = initialize_experiment(
        root,
        name="smoke",
        purpose="smoke",
        run_id="run-001",
        source={"lab_commit": "a" * 40},
        configuration=configuration,
        samples=[sample],
    )
    transition_sample(experiment, sample["sample_id"], "running", increment_attempt=True)
    checkpoint_experiment(root, experiment)
    resumed = prepare_resume(root)
    assert resumed["samples"][0]["state"] == "interrupted"
    assert resumed["samples"][0]["attempts"] == 1
