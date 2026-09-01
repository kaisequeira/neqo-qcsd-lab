from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import experiment as experiment_module
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
from qcsd_lab.util import atomic_json, atomic_text, load_json, sha256_file
from tests.scheduler_fixtures import install_scheduler_runtime_receipt


def _configuration(campaign: Path) -> dict:
    return {
        "campaign_sha256": sha256_file(campaign),
        "profile": "live",
        "request_policies": ["as-defined"],
        "workloads": [{"id": "site", "sha256": "b" * 64}],
        "defenses": [{"name": "undefended", "kind": "none"}],
        "limits": {"max_attempts": 3},
    }


def _class_configuration(
    campaign: Path,
    role: str,
    *,
    successor: bool = False,
) -> dict:
    configuration = _configuration(campaign)
    configuration.update(
        profile="research-1200",
        evidence_role=role,
        class_study_cohort_sha256="c" * 64,
        class_study_cohort_assembly_sha256="d" * 64,
        class_study_id=(
            "classifier-multiorigin100-v2-012345abcdef"
            if successor
            else "classifier-multiorigin100-v1"
        ),
        class_study_launch_sha256="e" * 64,
        class_study_foundation_sha256="f" * 64,
        public_origin_policy={
            "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
            "required_value": "1",
            "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
        },
    )
    if successor:
        configuration["class_study_successor_sha256"] = "1" * 64
    if role in {"canary", "formal"}:
        configuration.update(
            class_study_readiness_sha256="2" * 64,
            class_study_historical_pre_snapshot_sha256="3" * 64,
        )
    return configuration


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


def _initialize_class_experiment(
    tmp_path: Path,
    *,
    role: str,
    configuration: dict | None = None,
    successor: bool = False,
) -> tuple[Path, dict]:
    run_id = f"run-{role}"
    root = tmp_path / "results" / "class-campaign" / run_id
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    atomic_text(campaign, "schema: 2\n")
    resolved = (
        _class_configuration(campaign, role, successor=successor)
        if configuration is None
        else configuration
    )
    experiment = initialize_experiment(
        root,
        name="class-campaign",
        purpose="evaluation" if role == "formal" else "smoke",
        run_id=run_id,
        source={"lab_commit": "a" * 40, "image": "sha256:image"},
        configuration=resolved,
        samples=[_sample()],
        started_at="2026-08-29T00:00:00+00:00",
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


def test_generic_schema_seven_without_scheduler_contract_remains_compatible(
    tmp_path: Path,
) -> None:
    root, experiment = _initialize(tmp_path)
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    sample_root = _write_artifacts(root)
    atomic_json(
        sample_root / "neqo/run.json",
        {"runner_wakeup_metrics": {"schema_version": 7}},
    )
    accepted = accept_sample(root, experiment, _sample()["sample_id"])

    assert validate_accepted_samples(root, experiment) == {
        _sample()["sample_id"]: accepted["artifacts"]
    }


def test_generic_nonstudy_schema_six_remains_compatible(tmp_path: Path) -> None:
    root, experiment = _initialize(tmp_path)
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    sample_root = _write_artifacts(root)
    atomic_json(
        sample_root / "neqo/run.json",
        {"runner_wakeup_metrics": {"schema_version": 6}},
    )
    accepted = accept_sample(root, experiment, _sample()["sample_id"])

    assert validate_accepted_samples(root, experiment) == {
        _sample()["sample_id"]: accepted["artifacts"]
    }


@pytest.mark.parametrize("schema_version", (6, 7, 8, 9))
def test_current_class_sample_rejects_historical_runner_wakeup_schema(
    tmp_path: Path,
    schema_version: int,
) -> None:
    root, experiment = _initialize_class_experiment(tmp_path, role="formal")
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    sample_root = _write_artifacts(root)
    atomic_json(
        sample_root / "neqo/run.json",
        {"runner_wakeup_metrics": {"schema_version": schema_version}},
    )
    accept_sample(root, experiment, _sample()["sample_id"])

    with pytest.raises(ValueError, match="class-study.*schema 10"):
        validate_accepted_samples(root, experiment)


def test_buflo_study_schema_ten_rejects_missing_scheduler_runtime_receipt(
    tmp_path: Path,
) -> None:
    root, experiment = _initialize(tmp_path)
    experiment["name"] = "buflo-study-v1-scheduler-receipt-test"
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    sample_root = _write_artifacts(root)
    atomic_json(
        sample_root / "neqo/run.json",
        {"runner_wakeup_metrics": {"schema_version": 10}},
    )
    accept_sample(root, experiment, _sample()["sample_id"])

    with pytest.raises(ValueError, match="lacks its scheduler runtime receipt"):
        validate_accepted_samples(root, experiment)


@pytest.mark.parametrize("schema_version", (6, 7, 8, 9))
def test_current_buflo_historical_schema_cannot_claim_current_compatibility(
    tmp_path: Path,
    schema_version: int,
) -> None:
    root, experiment = _initialize(tmp_path)
    experiment["name"] = "buflo-study-v1-historical-scheduler-test"
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    sample_root = _write_artifacts(root)
    atomic_json(
        sample_root / "neqo/run.json",
        {"runner_wakeup_metrics": {"schema_version": schema_version}},
    )
    accept_sample(root, experiment, _sample()["sample_id"])

    with pytest.raises(ValueError, match="exact pinned v36"):
        validate_accepted_samples(root, experiment)


def test_exact_pinned_v36_buflo_schema_six_remains_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, experiment = _initialize(tmp_path)
    experiment["name"] = "buflo-study-v1-regression-buflo-1200"
    experiment["source"] = dict(experiment_module._HISTORICAL_BUFLO_V36_SOURCE)
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    sample_root = _write_artifacts(root)
    atomic_json(
        sample_root / "neqo/run.json",
        {"runner_wakeup_metrics": {"schema_version": 6}},
    )
    accepted = accept_sample(root, experiment, _sample()["sample_id"])
    canonical = json.dumps(experiment, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    monkeypatch.setitem(
        experiment_module._HISTORICAL_BUFLO_V36_EXPERIMENT_SHA256,
        experiment["name"],
        hashlib.sha256(canonical).hexdigest(),
    )

    assert validate_accepted_samples(root, experiment) == {
        _sample()["sample_id"]: accepted["artifacts"]
    }

    experiment["source"] = {"lab_commit": "a" * 40, "image": "sha256:image"}
    with pytest.raises(ValueError, match="exact pinned v36"):
        validate_accepted_samples(root, experiment)


def test_current_scheduler_receipt_is_deeply_revalidated_after_promotion(
    tmp_path: Path,
) -> None:
    root, experiment = _initialize(tmp_path)
    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    sample_root = _write_artifacts(root)
    run = load_json(sample_root / "neqo/run.json")
    diagnostics: dict = {}
    install_scheduler_runtime_receipt(run, diagnostics)
    atomic_json(sample_root / "neqo/run.json", run)
    accepted = accept_sample(
        root,
        experiment,
        _sample()["sample_id"],
        diagnostics=diagnostics,
    )
    validate_accepted_samples(root, experiment)

    receipt = accepted["diagnostics"]["scheduler_runtime_receipt"]
    receipt["scheduler_runtime_evidence"]["cgroup_cpu_stat"]["nr_throttled_delta"] = 1
    with pytest.raises(ValueError, match="scheduler runtime receipt is invalid"):
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


def test_named_qualification_set_survives_initialization_checkpoint_and_resume_validation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "results/campaign/run-named-set"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    atomic_text(campaign, "schema: 1\nchaff_qualification_set: cohort-v1\n")
    configuration = _configuration(campaign)
    configuration["chaff_qualification_set"] = "cohort-v1"

    experiment = initialize_experiment(
        root,
        name="campaign",
        purpose="smoke",
        run_id="run-named-set",
        source={"lab_commit": "a" * 40, "image": "sha256:image"},
        configuration=configuration,
        samples=[_sample()],
        started_at="2026-08-19T00:00:00+00:00",
    )
    assert load_experiment(root)["configuration"]["chaff_qualification_set"] == "cohort-v1"

    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    checkpoint_experiment(root, experiment)
    resumed = load_experiment(root)
    assert interrupt_running_samples(resumed) == [_sample()["sample_id"]]
    checkpoint_experiment(root, resumed)
    assert load_experiment(root)["samples"][0]["state"] == "interrupted"
    assert (
        validate_resume_fingerprints(
            root,
            experiment=resumed,
            expected_configuration=configuration,
        )
        == resumed["input_digest"]
    )


@pytest.mark.parametrize(
    ("role", "successor"),
    (
        ("certification", False),
        ("canary", False),
        ("formal", False),
        ("formal", True),
    ),
)
def test_class_study_configuration_survives_initialize_checkpoint_load_and_resume(
    tmp_path: Path,
    role: str,
    successor: bool,
) -> None:
    root, experiment = _initialize_class_experiment(
        tmp_path,
        role=role,
        successor=successor,
    )
    configuration = experiment["configuration"]
    assert load_experiment(root)["configuration"] == configuration

    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    checkpoint_experiment(root, experiment)
    resumed = load_experiment(root)
    assert interrupt_running_samples(resumed) == [_sample()["sample_id"]]
    checkpoint_experiment(root, resumed)
    loaded = load_experiment(root)
    assert loaded["samples"][0]["state"] == "interrupted"
    assert (
        validate_resume_fingerprints(
            root,
            experiment=loaded,
            expected_configuration=configuration,
        )
        == loaded["input_digest"]
    )


@pytest.mark.parametrize(
    ("role", "field", "invalid", "successor"),
    (
        (
            "certification",
            "class_study_id",
            "classifier-multiorigin100-v2",
            False,
        ),
        ("certification", "class_study_cohort_sha256", "A" * 64, False),
        (
            "certification",
            "class_study_cohort_assembly_sha256",
            "0" * 63,
            False,
        ),
        ("certification", "class_study_launch_sha256", "not-a-digest", False),
        ("certification", "class_study_foundation_sha256", None, False),
        ("canary", "class_study_readiness_sha256", True, False),
        ("formal", "class_study_historical_pre_snapshot_sha256", "0" * 63, False),
        ("formal", "class_study_successor_sha256", "z" * 64, True),
        ("formal", "public_origin_policy", None, False),
        (
            "formal",
            "public_origin_policy",
            {
                "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
                "required_value": "0",
                "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
            },
            False,
        ),
        (
            "formal",
            "public_origin_policy",
            {
                "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
                "required_value": "1",
            },
            False,
        ),
        (
            "formal",
            "public_origin_policy",
            {
                "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
                "required_value": "1",
                "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
                "fallback": "allow",
            },
            False,
        ),
    ),
)
def test_class_study_configuration_rejects_malformed_typed_fields(
    tmp_path: Path,
    role: str,
    field: str,
    invalid: object,
    successor: bool,
) -> None:
    campaign = tmp_path / "campaign.yml"
    atomic_text(campaign, "schema: 2\n")
    configuration = _class_configuration(campaign, role, successor=successor)
    configuration[field] = invalid

    with pytest.raises(ValueError, match=field):
        _initialize_class_experiment(
            tmp_path,
            role=role,
            configuration=configuration,
        )


@pytest.mark.parametrize(
    "missing",
    (
        "evidence_role",
        "class_study_cohort_sha256",
        "class_study_cohort_assembly_sha256",
        "class_study_id",
        "class_study_launch_sha256",
        "class_study_foundation_sha256",
        "public_origin_policy",
    ),
)
def test_class_study_configuration_requires_complete_common_binding(
    tmp_path: Path,
    missing: str,
) -> None:
    campaign = tmp_path / "campaign.yml"
    atomic_text(campaign, "schema: 2\n")
    configuration = _class_configuration(campaign, "certification")
    configuration.pop(missing)

    with pytest.raises(ValueError, match="class-study binding is incomplete"):
        _initialize_class_experiment(
            tmp_path,
            role="certification",
            configuration=configuration,
        )


def test_class_study_configuration_enforces_role_authority_and_successor_cooccurrence(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "campaign.yml"
    atomic_text(campaign, "schema: 2\n")

    certification = _class_configuration(campaign, "certification")
    certification["class_study_readiness_sha256"] = "2" * 64
    certification["class_study_historical_pre_snapshot_sha256"] = "3" * 64
    with pytest.raises(ValueError, match="role authority is inconsistent"):
        _initialize_class_experiment(
            tmp_path / "certification",
            role="certification",
            configuration=certification,
        )

    canary = _class_configuration(campaign, "canary")
    canary.pop("class_study_readiness_sha256")
    with pytest.raises(ValueError, match="role authority is inconsistent"):
        _initialize_class_experiment(
            tmp_path / "canary",
            role="canary",
            configuration=canary,
        )

    base = _class_configuration(campaign, "formal")
    base["class_study_successor_sha256"] = "1" * 64
    with pytest.raises(ValueError, match="successor binding is inconsistent"):
        _initialize_class_experiment(
            tmp_path / "base",
            role="formal",
            configuration=base,
        )

    successor = _class_configuration(campaign, "formal", successor=True)
    successor.pop("class_study_successor_sha256")
    with pytest.raises(ValueError, match="successor binding is inconsistent"):
        _initialize_class_experiment(
            tmp_path / "successor",
            role="formal",
            configuration=successor,
        )


@pytest.mark.parametrize("qualification_set", [None, "", "../escape", ".hidden", "Mixed-Case"])
def test_experiment_rejects_invalid_present_qualification_set(
    tmp_path: Path, qualification_set: object
) -> None:
    root = tmp_path / "results/campaign/run-invalid-set"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    atomic_text(campaign, "schema: 1\n")
    configuration = _configuration(campaign)
    configuration["chaff_qualification_set"] = qualification_set

    with pytest.raises(ValueError, match="configuration chaff_qualification_set is invalid"):
        initialize_experiment(
            root,
            name="campaign",
            purpose="smoke",
            run_id="run-invalid-set",
            source={"lab_commit": "a" * 40, "image": "sha256:image"},
            configuration=configuration,
            samples=[_sample()],
            started_at="2026-08-19T00:00:00+00:00",
        )


def test_latin_square_defense_order_survives_initialization_checkpoint_and_resume_validation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "results/campaign/run-latin-square"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    atomic_text(campaign, "schema: 2\ndefense_order: cyclic-latin-square\n")
    configuration = _configuration(campaign)
    configuration["defense_order"] = {
        "scheme": "cyclic-latin-square",
        "block": 0,
    }

    experiment = initialize_experiment(
        root,
        name="campaign",
        purpose="smoke",
        run_id="run-latin-square",
        source={"lab_commit": "a" * 40, "image": "sha256:image"},
        configuration=configuration,
        samples=[_sample()],
        started_at="2026-08-27T00:00:00+00:00",
    )
    assert load_experiment(root)["configuration"]["defense_order"] == {
        "scheme": "cyclic-latin-square",
        "block": 0,
    }

    transition_sample(experiment, _sample()["sample_id"], "running", increment_attempt=True)
    checkpoint_experiment(root, experiment)
    resumed = load_experiment(root)
    assert interrupt_running_samples(resumed) == [_sample()["sample_id"]]
    checkpoint_experiment(root, resumed)
    assert (
        validate_resume_fingerprints(
            root,
            experiment=resumed,
            expected_configuration=configuration,
        )
        == resumed["input_digest"]
    )


@pytest.mark.parametrize(
    "defense_order",
    [
        None,
        {},
        {"scheme": "cyclic-latin-square"},
        {"scheme": "cyclic-latin-square", "block": 0, "extra": True},
        {"scheme": "seeded-shuffle", "block": 0},
        {"scheme": "cyclic-latin-square", "block": True},
        {"scheme": "cyclic-latin-square", "block": -1},
        {"scheme": "cyclic-latin-square", "block": "0"},
    ],
)
def test_experiment_rejects_invalid_present_defense_order(
    tmp_path: Path, defense_order: object
) -> None:
    root = tmp_path / "results/campaign/run-invalid-order"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    atomic_text(campaign, "schema: 2\n")
    configuration = _configuration(campaign)
    configuration["defense_order"] = defense_order

    with pytest.raises(ValueError, match="configuration defense_order is invalid"):
        initialize_experiment(
            root,
            name="campaign",
            purpose="smoke",
            run_id="run-invalid-order",
            source={"lab_commit": "a" * 40, "image": "sha256:image"},
            configuration=configuration,
            samples=[_sample()],
            started_at="2026-08-27T00:00:00+00:00",
        )


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
