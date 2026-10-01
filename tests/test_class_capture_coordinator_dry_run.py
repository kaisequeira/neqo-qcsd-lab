"""Zero-credit coordinator rehearsal with a sealed synthetic canary result.

The cohort and two-origin workloads are generated fixtures.  External build,
foundation, certification and live packet collection are represented by test
doubles; the generated campaign parser, coordinator delegation, one-root claim,
durable experiment, interruption recovery, seal, and result verifier are real.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from qcsd_lab import buflo_study, class_pipeline, orchestrator
from qcsd_lab.class_layout import (
    AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
    AUTHORITATIVE_COHORT_FILENAME,
)
from qcsd_lab.class_study import STUDY_ID, load_study_receipt
from qcsd_lab.util import atomic_json, load_json, sha256_file
from qcsd_lab.verification import verify_result
from tests.test_campaign import (
    _install_attempt_scheduler_evidence,
    _write_successful_attempt,
)
from tests.test_class_campaign_execution import (
    _BUILD_IDENTITY,
    _SOURCE,
    _install_preclaim_authority,
)
from tests.test_class_late_campaign_dry_run import _rehearsal_inputs


def _admitted_canary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, class_pipeline.CohortAdmission, Path, Path, Path]:
    campaigns, _set_path, final_ids, _authority = _rehearsal_inputs(
        tmp_path, monkeypatch
    )
    campaign = campaigns / f"{STUDY_ID}-canary-01-1200.yml"
    loaded = orchestrator.load_campaign(campaign)
    foundation, readiness, snapshot = _install_preclaim_authority(
        tmp_path, monkeypatch, loaded
    )
    assert readiness is not None and snapshot is not None

    study_root = tmp_path / "config/class-study/v1"
    cohort_path = study_root / AUTHORITATIVE_COHORT_FILENAME
    assembly_path = study_root / AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME
    _cohort, selection = load_study_receipt(cohort_path)
    assert tuple(candidate.candidate_id for candidate in selection.final) == final_ids
    assembly = load_json(assembly_path)["payload"]
    prepared_hashes = {
        record["candidate_id"]: record["prepared_workload"]["sha256"]
        for record in assembly["candidates"]
        if record["candidate_id"] in final_ids
    }
    admission = class_pipeline.CohortAdmission(
        cohort_path=cohort_path,
        assembly_path=assembly_path,
        selection=selection,
        cohort_sha256=sha256_file(cohort_path),
        assembly_sha256=sha256_file(assembly_path),
        prepared_workload_sha256=prepared_hashes,
    )

    monkeypatch.setenv(orchestrator.CLASS_STUDY_PUBLIC_ORIGIN_ENV, "1")
    monkeypatch.setattr(orchestrator, "source_metadata", lambda: dict(_SOURCE))
    monkeypatch.setattr(
        buflo_study,
        "validate_study_environment_receipt",
        lambda _value, *, expected_image_digest=None, allow_historical=False: {
            "image_id": expected_image_digest,
            "build_execution": _BUILD_IDENTITY,
        },
    )
    monkeypatch.setattr(
        class_pipeline,
        "_result_index",
        lambda *_args, **_kwargs: [
            {
                "name": f"{STUDY_ID}-certification-900-1200",
                "evidence_role": "certification",
                "block": None,
                "root": str(tmp_path / "synthetic-certification"),
                "evidence_sha256": "e" * 64,
            }
        ],
    )
    monkeypatch.setattr(
        class_pipeline,
        "_validate_capture_foundation",
        lambda *_args, **_kwargs: {
            "required_environment": {
                orchestrator.CLASS_STUDY_FOUNDATION_ENV: str(foundation)
            }
        },
    )
    monkeypatch.setattr(
        class_pipeline,
        "_validate_formal_capture_authority",
        lambda *_args, **_kwargs: {
            "required_environment": {
                orchestrator.CLASS_STUDY_READINESS_ENV: str(readiness),
                orchestrator.CLASS_STUDY_HISTORICAL_PRE_ENV: str(snapshot),
            }
        },
    )
    # Real certification-derived capacity requires 900 actual captures.  This
    # fixture has no such evidence, so only that external estimate is omitted.
    monkeypatch.setattr(
        class_pipeline, "_formal_capacity_preflight", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        orchestrator.capture_engine,
        "_respect_origin_cooldown",
        lambda *_args, **_kwargs: None,
    )
    return campaign, admission, foundation, readiness, snapshot


def _coordinate(
    action: str,
    *,
    campaign: Path,
    admission: class_pipeline.CohortAdmission,
    foundation: Path,
    readiness: Path,
    snapshot: Path,
    results_root: Path,
    capture_result: Path | None = None,
    execute: bool,
) -> class_pipeline.ClassStudyActionResult:
    return class_pipeline._coordinate_capture(
        action,
        pilot_admission=None,
        final_admission=admission,
        campaign=campaign if action == "capture" else None,
        results_root=results_root if action == "capture" else None,
        capture_result=capture_result,
        prerequisite_roots=(),
        foundation_attestation=foundation,
        readiness_attestation=readiness,
        historical_pre_snapshot=snapshot,
        execute=execute,
    )


def test_canary_coordinator_resumes_one_claim_and_seals_exact_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, admission, foundation, readiness, snapshot = _admitted_canary(
        tmp_path, monkeypatch
    )
    results = tmp_path / "results"
    results.mkdir()
    args = {
        "campaign": campaign,
        "admission": admission,
        "foundation": foundation,
        "readiness": readiness,
        "snapshot": snapshot,
        "results_root": results,
    }
    guidance = _coordinate("capture", **args, execute=False)
    assert guidance.status == "ready"
    assert guidance.details["preflight"]["sample_count"] == 100
    assert not (results / campaign.stem).exists()

    calls: list[tuple[str, Path]] = []
    interrupted = False

    def collect(
        attempt: Path,
        runtime_manifest: Path,
        workload_id: str,
        defense: Any,
        seed: int,
        context: Any,
    ) -> dict[str, Any]:
        nonlocal interrupted
        assert defense.name == "undefended" and defense.baseline is True
        calls.append((workload_id, attempt))
        if len(calls) == 2 and not interrupted:
            interrupted = True
            attempt.mkdir(parents=True)
            (attempt / "unpromoted.tmp").write_text("stopped\n", encoding="utf-8")
            raise KeyboardInterrupt("controlled canary interruption")
        result = _write_successful_attempt(attempt, workload_id, defense.name)
        prepared = load_json(tmp_path / "config/workloads" / f"{workload_id}.json")
        run_path = attempt / "neqo/run.json"
        run = load_json(run_path)
        run.update(
            error=None,
            error_class=None,
            seed=seed,
            request_policy=context.request_policy,
            workload_hash_sha256=sha256_file(runtime_manifest),
            max_response_bytes=context.limits.max_response_bytes,
            resolved_configuration={
                "max_udp_payload_size": 1_200,
                "defense": {"kind": "none"},
            },
            application_workload_source_hash_sha256=None,
            chaff_manifest_hash_sha256=None,
            chaff_responses=[],
            defense_parameters=None,
            responses=[
                {
                    **response,
                    "url": prepared["resources"][response["resource_id"]]["url"],
                    "complete": True,
                    "outcome": "succeeded",
                }
                for response in prepared["preparation"]["expected_responses"]
            ],
            endpoints=[
                {"origin": origin}
                for origin in prepared["preparation"]["approved_origins"]
            ],
        )
        atomic_json(run_path, run)
        _install_attempt_scheduler_evidence(attempt, result)
        return result

    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collect)
    with pytest.raises(KeyboardInterrupt, match="controlled canary interruption"):
        _coordinate("capture", **args, execute=True)
    [root] = (results / campaign.stem).iterdir()
    interrupted_experiment = load_json(root / "experiment.json")
    assert interrupted_experiment["status"] == "running"
    assert sum(sample["state"] == "accepted" for sample in interrupted_experiment["samples"]) == 1
    assert sum(sample["state"] == "running" for sample in interrupted_experiment["samples"]) == 1
    assert not (root / "evidence.sha256").exists()

    resumed = _coordinate("resume", **args, capture_result=root, execute=True)
    assert resumed.status == "complete"
    assert resumed.details["valid"] is True
    assert resumed.details["samples"] == resumed.details["accepted"] == 100
    verified = verify_result(root)
    assert verified.experiment["status"] == "complete"
    assert verified.experiment["summary"]["passed"] is True
    assert len(verified.accepted_samples) == 100
    assert len(calls) == 101  # one interrupted physical attempt is never reused
    assert (root / "evidence.sha256").is_file()
    assert sum(sample["attempts"] == 2 for sample in verified.experiment["samples"]) == 1

    seal_sha256 = sha256_file(root / "evidence.sha256")
    with pytest.raises(FileExistsError, match="resume"):
        _coordinate("capture", **args, execute=True)
    assert sha256_file(root / "evidence.sha256") == seal_sha256
