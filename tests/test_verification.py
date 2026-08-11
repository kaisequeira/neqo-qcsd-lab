from __future__ import annotations

from pathlib import Path

import pytest

import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.experiment import (
    accept_sample,
    checkpoint_experiment,
    finalize_experiment,
    input_digest,
    initialize_experiment,
    transition_sample,
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


def test_verify_rejects_consistently_resealed_mutable_configuration(tmp_path: Path) -> None:
    root, experiment = _make_result(tmp_path, complete=True)
    experiment["configuration"]["limits"]["max_attempts"] = 2
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
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    atomic_text(campaign, "schema: 1\n")
    configuration = {
        "campaign_sha256": sha256_file(campaign),
        "profile": "live",
        "request_policies": ["as-defined"],
        "workloads": [{"id": "site"}],
        "defenses": [{"name": "undefended"}],
        "limits": {"max_attempts": 3},
    }
    sample = {
        "sample_id": "site-as-defined-000-undefended",
        "workload_id": "site",
        "request_policy": "as-defined",
        "visit": 0,
        "defense": "undefended",
        "runtime_kind": "none",
        "baseline": True,
        "seed": 1,
        "path": "samples/site/as-defined/visit-000/undefended",
    }
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
