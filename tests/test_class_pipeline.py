from __future__ import annotations

import csv
import json
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import qcsd_lab.class_pipeline as pipeline
from qcsd_lab import buflo_handoff, orchestrator, util
from qcsd_lab.capture_session import Defense, Limits
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    STUDY_ID,
)
from qcsd_lab.fidelity import BUFLO_SCHEDULE_STOP_V4_KEYS, SCHEDULE_QCSD_FIELDS
from qcsd_lab.verification import VerifiedResult


@dataclass(frozen=True)
class _Candidate:
    candidate_id: str


def _admission(tmp_path: Path, *, pilot: int = 120, final: int = 100):
    tmp_path.mkdir(parents=True, exist_ok=True)
    cohort = tmp_path / "cohort.json"
    assembly = tmp_path / "assembly.json"
    cohort.write_text("{}", encoding="utf-8")
    assembly.write_text("{}", encoding="utf-8")
    pilot_candidates = tuple(_Candidate(f"pilot-{index:03d}") for index in range(pilot))
    final_candidates = tuple(_Candidate(f"final-{index:03d}") for index in range(final))
    bindings = {
        candidate.candidate_id: f"{index:064x}"
        for index, candidate in enumerate((*pilot_candidates, *final_candidates), start=1)
    }
    return pipeline.CohortAdmission(
        cohort_path=cohort,
        assembly_path=assembly,
        selection=SimpleNamespace(
            pilot=pilot_candidates,
            final=final_candidates,
            reserves=(),
        ),
        cohort_sha256="a" * 64,
        assembly_sha256="b" * 64,
        prepared_workload_sha256=bindings,
    )


def _record(role: str, *, block: int | None = None) -> dict[str, object]:
    suffix = f"-{block:02d}" if block is not None else ""
    return {
        "valid": True,
        "root": f"/evidence/{role}{suffix}",
        "name": f"{STUDY_ID}-{role}{suffix}-1200",
        "evidence_role": role,
        "block": block,
        "samples": 1,
        "accepted": 1,
        "evidence_sha256": "e" * 64,
        "first_launch_unique_class_mode_pairs": (
            pipeline.CERTIFICATION_PAIR_COUNT if role == "certification" else None
        ),
    }


def _qualification_authority() -> dict[str, object]:
    source = {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    prepare = "sha256:" + "4" * 64
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": {
            "path": "/evidence/foundation.json",
            "sha256": "5" * 64,
            "payload_sha256": "6" * 64,
        },
        "build_execution": {"path": "/evidence/build.json", "sha256": "7" * 64},
        "build_execution_identity": {
            "cohort_version": 23,
            "sha256": "7" * 64,
            "collection_image": source["image_digest"],
            "started_at": "2026-08-28T00:00:00+00:00",
            "finished_at": "2026-08-28T01:00:00+00:00",
        },
        "collection_source": source,
        "prepare_source": {**source, "image_digest": prepare},
        "prepare_image_digest": prepare,
    }


def test_status_exposes_stability_and_certification_contracts():
    status = pipeline.class_study_status()

    assert status["stages"]["stability"]["gate"]["labels"] == [
        "t+30s",
        "t+24h",
        "t+72h",
    ]
    assert status["certification_contract"] == {
        "classes": 100,
        "modes": list(COMPATIBILITY_MODES),
        "expected_unique_class_mode_pairs": 900,
        "first_launch_only": True,
        "accepted_and_eligible_required": True,
    }
    assert status["next_required_stage"] == "prospective-catalogue"
    assert status["attestation_generated"] is False


def test_status_verifies_supplied_promotion_receipts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import qcsd_lab.class_attestation as attestation

    paths = {
        name: tmp_path / f"{name}.json"
        for name in ("foundation", "readiness", "pre", "post", "comparison", "validation")
    }
    for path in paths.values():
        path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        attestation,
        "validate_class_foundation_attestation",
        lambda path, **kwargs: {"path": str(path), "runtime_role": kwargs["runtime_role"]},
    )
    monkeypatch.setattr(
        attestation,
        "validate_class_readiness_attestation",
        lambda path, **kwargs: {"path": str(path), "deep": kwargs["deep_code_gate"]},
    )
    monkeypatch.setattr(
        attestation,
        "validate_class_historical_snapshot",
        lambda path, **kwargs: {"path": str(path), "phase": kwargs["expected_phase"]},
    )
    monkeypatch.setattr(
        attestation,
        "validate_class_comparison_review",
        lambda path: {"path": str(path), "passed": True},
    )
    monkeypatch.setattr(
        attestation,
        "validate_class_validation_attestation",
        lambda path, **kwargs: {"path": str(path), "promotion_authority": True},
    )

    status = pipeline.class_study_status(
        foundation_attestation=paths["foundation"],
        readiness_attestation=paths["readiness"],
        historical_pre_snapshot=paths["pre"],
        historical_post_snapshot=paths["post"],
        comparison_review=paths["comparison"],
        validation_attestation=paths["validation"],
        deep=True,
    )

    assert status["stages"]["foundation"]["runtime_role"] == "collection"
    assert status["stages"]["readiness"]["deep"] is True
    assert status["stages"]["historical_pre_snapshot"]["phase"] == "pre-formal"
    assert status["stages"]["historical_post_snapshot"]["phase"] == "post-formal"
    assert status["stages"]["comparison_review"]["passed"] is True
    assert status["attestation_generated"] is True


def test_status_refits_numeric_and_final_bundles_against_unique_stage_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "pilot-fitting-result"
    source.mkdir()
    numeric_root = tmp_path / "classifier-multiorigin100-v1-pilot-fitting-numeric"
    numeric_root.mkdir()
    final_root = tmp_path / "classifier-multiorigin100-v1-pilot-fitting"
    final_root.mkdir()
    prefix_root = tmp_path / "classifier-multiorigin100-v1-pilot-fitting-prefix-specs"
    prefix_root.mkdir()
    workload_root = tmp_path / "workloads"
    workload_root.mkdir()
    qualification_root = tmp_path / pipeline.PILOT_QUALIFICATION_SET
    qualification_root.mkdir()
    qualification_manifest = qualification_root / pipeline.NAMED_QUALIFICATION_SET_MANIFEST
    qualification_manifest.write_text("{}\n", encoding="utf-8")
    foundation = tmp_path / "foundation.json"
    foundation.write_text("{}\n", encoding="utf-8")
    record = {
        **_record("pilot-fitting"),
        "root": str(source),
    }
    monkeypatch.setattr(pipeline, "_result_index", lambda *_args, **_kwargs: [record])
    import qcsd_lab.class_attestation as attestation

    monkeypatch.setattr(
        attestation,
        "validate_class_foundation_attestation",
        lambda *_args, **_kwargs: {"valid": True},
    )
    monkeypatch.setattr(
        attestation,
        "class_qualification_authority",
        lambda *_args, **_kwargs: _qualification_authority(),
    )
    monkeypatch.setattr(pipeline, "_validate_qualification_sidecars", lambda *_args: None)

    numeric_calls: list[Path | None] = []
    numeric = SimpleNamespace(
        stage="pilot",
        as_dict=lambda: {"valid": True, "stage": "pilot", "root": str(numeric_root)},
    )

    def verify_numeric(_path: Path, *, source_result_root: Path | None = None):
        numeric_calls.append(source_result_root)
        return numeric

    final_calls: list[Path | None] = []

    def verify_final(
        _path: Path,
        *,
        qualification_context,
        source_result_root: Path | None = None,
    ):
        final_calls.append(source_result_root)
        return SimpleNamespace(
            as_dict=lambda: {"valid": True, "stage": "pilot", "root": str(final_root)}
        )

    monkeypatch.setattr(pipeline, "verify_numeric_fitting_bundle", verify_numeric)
    monkeypatch.setattr(pipeline, "verify_class_fitting_bundle", verify_final)
    monkeypatch.setattr(
        pipeline,
        "_verify_prefix_spec_root",
        lambda *_args, **_kwargs: {"valid": True, "stage": "pilot"},
    )
    monkeypatch.setattr(pipeline, "_admission_for_stage", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(pipeline, "_stage_workloads", lambda *_args, **_kwargs: ("alpha",))
    monkeypatch.setattr(
        pipeline,
        "load_named_qualification_set",
        lambda path, **_kwargs: SimpleNamespace(
            path=path.parent,
            manifest_sha256="a" * 64,
            workload_ids=("alpha",),
        ),
    )

    status = pipeline.class_study_status(
        workload_root=workload_root,
        result_roots=(source,),
        numeric_bundle_roots=(numeric_root,),
        prefix_spec_roots=(prefix_root,),
        qualification_manifests=(qualification_manifest,),
        final_bundle_roots=(final_root,),
        foundation_attestation=foundation,
    )

    assert numeric_calls == [None, source]
    assert final_calls == [source]
    assert status["stages"]["numeric_fitting"]["state"] == "verified"
    assert status["stages"]["final_fitting"]["state"] == "verified"


def test_status_rejects_numeric_bundle_from_another_fitting_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "pilot-fitting-result"
    source.mkdir()
    numeric_root = tmp_path / "classifier-multiorigin100-v1-pilot-fitting-numeric"
    numeric_root.mkdir()
    record = {**_record("pilot-fitting"), "root": str(source)}
    monkeypatch.setattr(pipeline, "_result_index", lambda *_args, **_kwargs: [record])

    staged = SimpleNamespace(stage="pilot")

    def verify_numeric(_path: Path, *, source_result_root: Path | None = None):
        if source_result_root is not None:
            raise ValueError(
                "numeric bundle source result differs from independently refitted evidence"
            )
        return staged

    monkeypatch.setattr(pipeline, "verify_numeric_fitting_bundle", verify_numeric)
    with pytest.raises(ValueError, match="source result differs"):
        pipeline.class_study_status(
            result_roots=(source,),
            numeric_bundle_roots=(numeric_root,),
        )


def test_finalize_fitting_deep_verifies_the_unique_stage_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "pilot-fitting-result"
    source.mkdir()
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    layout = pipeline.class_study_layout()
    numeric_root = layout.pilot_numeric_root
    numeric_root.mkdir(parents=True)
    output = tmp_path / "final"
    output.mkdir()
    artifacts = layout.artifacts_root
    workloads = layout.workload_root
    prefixes = layout.pilot_prefix_root
    qualification_root = layout.pilot_qualification_set_root
    for path in (artifacts, workloads, prefixes, qualification_root):
        path.mkdir(parents=True, exist_ok=True)
    qualification = qualification_root / "_qualification-set.json"
    qualification.write_text("{}\n", encoding="utf-8")
    foundation = tmp_path / "foundation.json"
    foundation.write_text("{}\n", encoding="utf-8")
    admission = object()
    record = {**_record("pilot-fitting"), "root": str(source)}
    monkeypatch.setattr(pipeline, "_optional_admission", lambda *_args, **_kwargs: admission)
    monkeypatch.setattr(pipeline, "_admission_for_stage", lambda *_args, **_kwargs: admission)
    monkeypatch.setattr(pipeline, "_result_index", lambda *_args, **_kwargs: [record])
    monkeypatch.setattr(pipeline, "_require_numeric_admission", lambda *_args: None)

    numeric_calls: list[Path | None] = []

    def verify_numeric(_path: Path, *, source_result_root: Path | None = None):
        numeric_calls.append(source_result_root)
        return SimpleNamespace(stage="pilot")

    final_calls: list[Path | None] = []

    def verify_final(
        _path: Path,
        *,
        qualification_context,
        source_result_root: Path | None = None,
    ):
        final_calls.append(source_result_root)
        return SimpleNamespace(as_dict=lambda: {"valid": True, "stage": "pilot"})

    monkeypatch.setattr(pipeline, "verify_numeric_fitting_bundle", verify_numeric)
    monkeypatch.setattr(pipeline, "finalize_fitting_bundle", lambda *_args, **_kwargs: output)
    monkeypatch.setattr(pipeline, "verify_class_fitting_bundle", verify_final)
    import qcsd_lab.class_attestation as attestation

    monkeypatch.setattr(
        attestation,
        "class_qualification_authority",
        lambda *_args, **_kwargs: _qualification_authority(),
    )

    result = pipeline.run_class_study_action(
        "finalize-fitting",
        stage="pilot",
        result_roots=(source,),
        numeric_bundle_root=numeric_root,
        qualification_manifest=qualification,
        prefix_spec_root=prefixes,
        workload_root=workloads,
        artifacts_root=artifacts,
        foundation_attestation=foundation,
    )
    assert result.status == "complete"
    assert numeric_calls == [source]
    assert final_calls == [source]


def test_finalize_fitting_rejects_stale_numeric_before_publication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "pilot-fitting-result"
    source.mkdir()
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    numeric_root = pipeline.class_study_layout().pilot_numeric_root
    numeric_root.mkdir(parents=True)
    admission = object()
    record = {**_record("pilot-fitting"), "root": str(source)}
    monkeypatch.setattr(pipeline, "_optional_admission", lambda *_args, **_kwargs: admission)
    monkeypatch.setattr(pipeline, "_admission_for_stage", lambda *_args, **_kwargs: admission)
    monkeypatch.setattr(pipeline, "_result_index", lambda *_args, **_kwargs: [record])

    def stale(_path: Path, *, source_result_root: Path | None = None):
        assert source_result_root == source
        raise ValueError("numeric bundle differs from independently refitted evidence")

    monkeypatch.setattr(pipeline, "verify_numeric_fitting_bundle", stale)
    monkeypatch.setattr(
        pipeline,
        "finalize_fitting_bundle",
        lambda *_args, **_kwargs: pytest.fail("stale numeric bundle was published"),
    )
    with pytest.raises(ValueError, match="independently refitted"):
        pipeline.run_class_study_action(
            "finalize-fitting",
            stage="pilot",
            result_roots=(source,),
            numeric_bundle_root=numeric_root,
        )


def test_campaign_bridge_passes_exact_assembly_api(monkeypatch, tmp_path):
    seen = {}

    def fake_campaign_documents(cohort, **kwargs):
        seen["cohort"] = cohort
        seen.update(kwargs)
        return {"one.yml": {"class_study_cohort_assembly": kwargs["cohort_assembly_reference"]}}

    monkeypatch.setattr(pipeline, "campaign_documents", fake_campaign_documents)
    cohort = tmp_path / "cohort.json"
    assembly = tmp_path / "assembly.json"

    documents = pipeline._campaign_documents_with_assembly(
        cohort,
        assembly,
        cohort_reference="cohort.json",
        cohort_assembly_reference="assembly.json",
        pilot_bundle_reference="pilot",
        authoritative_bundle_reference="authoritative",
    )

    assert documents["one.yml"]["class_study_cohort_assembly"] == "assembly.json"
    assert seen["cohort"] == cohort
    assert seen["cohort_assembly_receipt"] == assembly


def test_certification_requires_exact_900_first_launch_pairs(monkeypatch, tmp_path):
    class_ids = tuple(f"class-{index:03d}" for index in range(100))
    samples = [
        {
            "sample_id": f"{workload_id}-{mode}",
            "workload_id": workload_id,
            "defense": mode,
            "runtime_kind": {
                "buflo": "buflo",
                "cs-buflo": "cs_buflo",
            }.get(mode),
            "visit": 0,
            "request_policy": "as-defined",
            "state": "accepted",
            "eligible": True,
            "attempts": 1,
        }
        for workload_id in class_ids
        for mode in COMPATIBILITY_MODES
    ]
    verified = VerifiedResult(
        root=tmp_path,
        experiment={
            "configuration": {"defenses": [{"name": mode} for mode in COMPATIBILITY_MODES]},
            "samples": samples,
        },
        checksums={},
        accepted_samples={sample["sample_id"]: {} for sample in samples},
    )
    reopened: list[tuple[str, str]] = []
    bound: list[tuple[str, str]] = []
    monkeypatch.setattr(
        pipeline,
        "_validate_current_candidate_sample_receipt",
        lambda _verified, sample, *, role: reopened.append((role, str(sample["defense"]))),
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_class_sample_run_receipt",
        lambda _verified, sample, *, role: bound.append((role, str(sample["defense"]))),
    )

    count, pairs = pipeline._validate_non_fitting_result(
        verified,
        role="certification",
        selected_ids=class_ids,
    )

    assert count == 900
    assert pairs == 900
    assert len(bound) == 900
    assert {mode: bound.count(("certification", mode)) for mode in COMPATIBILITY_MODES} == {
        mode: 100 for mode in COMPATIBILITY_MODES
    }
    assert reopened.count(("certification", "buflo")) == 100
    assert reopened.count(("certification", "cs-buflo")) == 100
    samples[0]["attempts"] = 2
    with pytest.raises(ValueError, match="first launch|invalid attempt"):
        pipeline._validate_non_fitting_result(
            verified,
            role="certification",
            selected_ids=class_ids,
        )


def test_formal_result_accepts_preserved_retry_success_within_budget(monkeypatch, tmp_path):
    class_ids = tuple(f"class-{index:03d}" for index in range(100))
    samples = [
        {
            "sample_id": f"{workload_id}-{mode}-{visit}",
            "workload_id": workload_id,
            "defense": mode,
            "runtime_kind": {
                "buflo": "buflo",
                "cs-buflo": "cs_buflo",
            }.get(mode),
            "visit": visit,
            "request_policy": "as-defined",
            "state": "accepted",
            "eligible": True,
            "attempts": 2,
        }
        for workload_id in class_ids
        for mode in FORMAL_MODES
        for visit in range(2)
    ]
    verified = VerifiedResult(
        root=tmp_path,
        experiment={
            "configuration": {"defenses": [{"name": mode} for mode in FORMAL_MODES]},
            "samples": samples,
        },
        checksums={},
        accepted_samples={sample["sample_id"]: {} for sample in samples},
    )
    reopened: list[tuple[str, str]] = []
    bound: list[tuple[str, str]] = []
    monkeypatch.setattr(
        pipeline,
        "_validate_current_candidate_sample_receipt",
        lambda _verified, sample, *, role: reopened.append((role, str(sample["defense"]))),
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_class_sample_run_receipt",
        lambda _verified, sample, *, role: bound.append((role, str(sample["defense"]))),
    )

    assert pipeline._validate_non_fitting_result(
        verified,
        role="formal",
        selected_ids=class_ids,
    ) == (1_600, None)
    assert len(bound) == 1_600
    assert {mode: bound.count(("formal", mode)) for mode in FORMAL_MODES} == {
        mode: 200 for mode in FORMAL_MODES
    }
    assert reopened.count(("formal", "buflo")) == 200
    assert reopened.count(("formal", "cs-buflo")) == 200

    samples[0]["attempts"] = 4
    with pytest.raises(ValueError, match="invalid attempt"):
        pipeline._validate_non_fitting_result(
            verified,
            role="formal",
            selected_ids=class_ids,
        )


def _candidate_verified_result(
    tmp_path: Path, run: dict[str, object]
) -> tuple[VerifiedResult, dict[str, object]]:
    root = (tmp_path / "candidate-result").resolve()
    sample_relative = "samples/class-000/as-defined/visit-001/buflo"
    sample_root = root / sample_relative
    (sample_root / "neqo").mkdir(parents=True)
    (sample_root / "capture.pcapng").write_bytes(b"sealed-pcapng\n")
    (sample_root / "neqo/run.json").write_text(
        json.dumps(run, sort_keys=True) + "\n", encoding="utf-8"
    )

    def write_rows(name: str, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
        with (sample_root / f"neqo/{name}").open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    schedule_fields = (*buflo_handoff.SCHEDULE_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    outgoing = {field: "" for field in schedule_fields}
    outgoing.update(
        target_time_us="0",
        direction="outgoing",
        size="1200",
        connection="0",
        action_time_us="4999",
        satisfaction="satisfied",
        observed_size="1200",
        slot_id="1",
        qcsd_outcome_schema_version="3",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        terminal_defense_elapsed_us="4999",
    )
    incoming = {field: "" for field in schedule_fields}
    incoming.update(
        target_time_us="0",
        direction="incoming",
        size="1200",
        connection="0",
        action_time_us="0",
        satisfaction="satisfied",
        slot_id="2",
        qcsd_outcome_schema_version="3",
        send_policy="exact",
        desired_udp_bytes="1200",
        credit_advertised_at_us="0",
        credit_advertisement_delay_us="0",
        credit_consumed_at_us="10000000",
        credit_consumption_delay_us="10000000",
        terminal_defense_elapsed_us="10000000",
    )
    schedule_rows = [outgoing, incoming]
    scheduled_outgoing = int(run["defense_diagnostics"]["buflo_scheduled_outgoing_cells"])
    if scheduled_outgoing not in {1, 2}:
        raise ValueError("candidate fixture supports one or two outgoing cells")
    if scheduled_outgoing == 2:
        guarded_outgoing = dict(outgoing)
        guarded_outgoing.update(
            target_time_us="20000",
            action_time_us="20001",
            slot_id="3",
            terminal_defense_elapsed_us="20001",
        )
        guarded_incoming = dict(incoming)
        guarded_incoming.update(
            target_time_us="20000",
            action_time_us="20000",
            slot_id="4",
            credit_advertised_at_us="20000",
            credit_advertisement_delay_us="0",
            credit_consumed_at_us="10000000",
            credit_consumption_delay_us="9980000",
            terminal_defense_elapsed_us="10000000",
        )
        schedule_rows.extend((guarded_outgoing, guarded_incoming))
    write_rows("schedule.csv", schedule_fields, schedule_rows)

    event_fields = (*buflo_handoff._EVENT_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    write_rows("events.csv", event_fields, [])

    packet_fields = (*buflo_handoff._PACKET_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    packet = {field: "" for field in packet_fields}
    packet.update(
        direction="outgoing",
        monotonic_us="4999",
        connection="0",
        observed_udp_length="1200",
        scheduled_target="1200",
        satisfaction="satisfied",
        slot_id="1",
        qcsd_outcome_schema_version="2",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="1200",
        defense_control_bytes="0",
        quic_padding_bytes="0",
        other_quic_bytes="0",
        lateness_us="0",
    )
    packets = [packet]
    if scheduled_outgoing == 2:
        guarded_packet = dict(packet)
        guarded_packet.update(monotonic_us="20001", slot_id="3", lateness_us="1")
        packets.append(guarded_packet)
    write_rows("packets.csv", packet_fields, packets)
    artifacts = {
        path.relative_to(root).as_posix(): util.sha256_file(path)
        for path in sorted(sample_root.rglob("*"))
        if path.is_file()
    }
    sample: dict[str, object] = {
        "sample_id": "class-000-buflo",
        "path": sample_relative,
        "defense": "buflo",
        "runtime_kind": "buflo",
        "artifacts": artifacts,
    }
    return (
        VerifiedResult(
            root=root,
            experiment={"samples": [sample]},
            checksums=dict(artifacts),
            accepted_samples={str(sample["sample_id"]): dict(artifacts)},
        ),
        sample,
    )


def _reseal_candidate_artifact(
    verified: VerifiedResult,
    sample: dict[str, object],
    path: Path,
) -> None:
    relative = path.relative_to(verified.root).as_posix()
    digest = util.sha256_file(path)
    artifacts = sample["artifacts"]
    assert isinstance(artifacts, dict)
    artifacts[relative] = digest
    verified.accepted_samples[str(sample["sample_id"])][relative] = digest
    verified.checksums[relative] = digest


def test_class_result_reopens_current_candidate_terminal_receipt(tmp_path: Path) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run

    verified, sample = _candidate_verified_result(
        tmp_path,
        _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1),
    )

    pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


def test_class_result_reopens_current_guarded_buflo_receipt(tmp_path: Path) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run

    verified, sample = _candidate_verified_result(
        tmp_path,
        _complete_buflo_run(scheduled_outgoing=2, scheduled_incoming=2),
    )

    pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


def test_class_result_rejects_historical_schema_eight_runner_receipt(tmp_path: Path) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run, _runner_wakeup_receipt

    run = _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1)
    run["runner_wakeup_metrics"] = _runner_wakeup_receipt(8)
    verified, sample = _candidate_verified_result(tmp_path, run)

    with pytest.raises(ValueError, match="runner-wakeup schema-9"):
        pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


def test_class_result_rejects_historical_candidate_summary_even_when_sealed_and_eligible(
    tmp_path: Path,
) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run

    run = json.loads(json.dumps(_complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1)))
    run["buflo_summary"]["schema_version"] = 3
    run["buflo_summary"].pop("terminal_schedule_stop_policy")
    for key in BUFLO_SCHEDULE_STOP_V4_KEYS:
        run["defense_diagnostics"].pop(key)
        run["buflo_summary"]["diagnostics"].pop(key)
    verified, sample = _candidate_verified_result(tmp_path, run)

    with pytest.raises(ValueError, match="current schema-4 terminal receipt"):
        pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


@pytest.mark.parametrize("missing", sorted(BUFLO_SCHEDULE_STOP_V4_KEYS))
def test_class_result_rejects_each_missing_schedule_stop_diagnostic(
    tmp_path: Path, missing: str
) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run

    run = json.loads(json.dumps(_complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1)))
    run["defense_diagnostics"].pop(missing)
    run["buflo_summary"]["diagnostics"].pop(missing)
    verified, sample = _candidate_verified_result(tmp_path, run)

    with pytest.raises(ValueError, match="current schema-4 terminal receipt"):
        pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


def test_class_result_rejects_missing_buflo_defense_clock_binding(
    tmp_path: Path,
) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run

    run = json.loads(json.dumps(_complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1)))
    run.pop("defense_start_monotonic_ns")
    verified, sample = _candidate_verified_result(tmp_path, run)

    with pytest.raises(ValueError, match="terminal/schedule chronology"):
        pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


def test_class_result_rejects_sealed_schedule_stop_chronology_mutation(
    tmp_path: Path,
) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run

    verified, sample = _candidate_verified_result(
        tmp_path,
        _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1),
    )
    schedule_path = verified.root / str(sample["path"]) / "neqo/schedule.csv"
    with schedule_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
        fields = tuple(reader.fieldnames or ())
    rows[1]["credit_consumed_at_us"] = "10010002"
    rows[1]["credit_consumption_delay_us"] = "10010002"
    with schedule_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    _reseal_candidate_artifact(verified, sample, schedule_path)

    with pytest.raises(ValueError, match="terminal/schedule chronology"):
        pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


def test_class_result_rejects_sealed_outgoing_packet_binding_mutation(
    tmp_path: Path,
) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run

    verified, sample = _candidate_verified_result(
        tmp_path,
        _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1),
    )
    packets_path = verified.root / str(sample["path"]) / "neqo/packets.csv"
    with packets_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
        fields = tuple(reader.fieldnames or ())
    rows[0]["slot_id"] = "7"
    with packets_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    _reseal_candidate_artifact(verified, sample, packets_path)

    with pytest.raises(ValueError, match="terminal/schedule chronology"):
        pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


def test_class_result_rejects_sealed_terminal_event_inventory_mutation(
    tmp_path: Path,
) -> None:
    from tests.test_buflo_handoff import _complete_buflo_run

    verified, sample = _candidate_verified_result(
        tmp_path,
        _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1),
    )
    events_path = verified.root / str(sample["path"]) / "neqo/events.csv"
    event_fields = (*buflo_handoff._EVENT_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    row = {field: "" for field in event_fields}
    row.update(
        monotonic_us="10000001",
        connection="0",
        event="action",
        outcome="applied",
        details=json.dumps(
            {
                "type": "cancel_chaff",
                "endpoint": 0,
                "stream": 7,
                "reason": "buflo_terminal_subcell_tail",
            },
            sort_keys=True,
        ),
    )
    with events_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=event_fields)
        writer.writeheader()
        writer.writerow(row)
    _reseal_candidate_artifact(verified, sample, events_path)

    with pytest.raises(ValueError, match="terminal/schedule chronology"):
        pipeline._validate_current_candidate_sample_receipt(verified, sample, role="certification")


def test_runtime_input_identities_follow_the_real_frozen_configuration_contract(
    tmp_path: Path,
) -> None:
    root = tmp_path / "result"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    campaign_path = inputs / "campaign.yml"
    campaign_path.write_text("schema: 1\n", encoding="utf-8")
    parameter_modes = {
        "traffic-morphing": "traffic_morphing",
        "wtf-pad": "wtf_pad",
        "walkie-talkie": "walkie_talkie",
        "buflo": "buflo",
        "cs-buflo": "cs_buflo",
    }
    defenses = [Defense("undefended", "none", True)]
    defenses.append(
        Defense(
            "static",
            "static",
            False,
            schedule="schedule.csv",
            schedule_path=inputs / "defense-parameters/static/schedule.csv",
            schedule_sha256="1" * 64,
            mode="chaff-and-shape",
        )
    )
    defenses.extend((Defense("front", "front", False), Defense("tamaraw", "tamaraw", False)))
    for index, (name, kind) in enumerate(parameter_modes.items(), start=2):
        defenses.append(
            Defense(
                name,
                kind,
                False,
                parameters="parameters.json",
                parameters_path=inputs / f"defense-parameters/{name}/parameters.json",
                parameters_sha256=f"{index:x}" * 64,
                parameters_provenance="provenance.json",
                parameters_provenance_path=(inputs / f"defense-parameters/{name}/provenance.json"),
                parameters_provenance_sha256="a" * 64,
                parameters_input_policy="sealed-class-study-fitting-v1",
            )
        )
    campaign = orchestrator.Campaign(
        path=campaign_path,
        source_bytes=campaign_path.read_bytes(),
        name="runtime-input-contract",
        purpose="evaluation",
        seed=1,
        profile="1200",
        workloads=(),
        request_policies=("as-defined",),
        defenses=tuple(defenses),
        limits=Limits(),
    )

    configuration = orchestrator._frozen_configuration(root, campaign)
    identities = pipeline._defense_runtime_input_identities(configuration)

    assert tuple(identities) == COMPATIBILITY_MODES
    assert identities["undefended"] == {
        "identity_type": "source-bound-no-defense",
        "runtime_kind": "none",
    }
    assert identities["front"]["identity_type"] == "source-bound-built-in"
    assert identities["static"] == {
        "identity_type": "hash-bound-static-schedule",
        "runtime_kind": "static",
        "schedule_sha256": "1" * 64,
        "mode": "chaff-and-shape",
    }
    assert {
        name: identity["parameters_sha256"]
        for name, identity in identities.items()
        if identity["identity_type"] == "hash-bound-parameter-artifact"
    } == {name: f"{index:x}" * 64 for index, name in enumerate(parameter_modes, start=2)}


def test_formal_capture_requires_matching_canary_and_prior_blocks():
    records = [
        _record("certification"),
        _record("canary", block=1),
        _record("formal", block=1),
    ]
    with pytest.raises(ValueError, match="canary block 02"):
        pipeline._validate_capture_prerequisites("formal", 2, records)

    records.append(_record("canary", block=2))
    pipeline._validate_capture_prerequisites("formal", 2, records)


def test_prior_capture_records_must_match_certified_runtime_and_manifest() -> None:
    certification_runtime_inputs = {mode: {"identity": mode} for mode in COMPATIBILITY_MODES}
    foundation_sha256 = "1" * 64
    readiness_sha256 = "2" * 64
    historical_pre_sha256 = "3" * 64
    manifest_sha256 = "4" * 64
    certification = {
        "evidence_role": "certification",
        "class_study_foundation_sha256": foundation_sha256,
    }
    canary = {
        "evidence_role": "canary",
        "class_study_foundation_sha256": foundation_sha256,
        "class_study_readiness_sha256": readiness_sha256,
        "class_study_historical_pre_snapshot_sha256": historical_pre_sha256,
        "defense_runtime_inputs": {"undefended": certification_runtime_inputs["undefended"]},
        "chaff_qualification_set_manifest_sha256": None,
    }
    formal = {
        "evidence_role": "formal",
        "class_study_foundation_sha256": foundation_sha256,
        "class_study_readiness_sha256": readiness_sha256,
        "class_study_historical_pre_snapshot_sha256": historical_pre_sha256,
        "defense_runtime_inputs": {
            mode: certification_runtime_inputs[mode] for mode in pipeline.FORMAL_MODES
        },
        "chaff_qualification_set_manifest_sha256": manifest_sha256,
    }
    records = (certification, canary, formal)
    kwargs = {
        "foundation_sha256": foundation_sha256,
        "readiness_sha256": readiness_sha256,
        "historical_pre_sha256": historical_pre_sha256,
        "certification_runtime_inputs": certification_runtime_inputs,
        "final_qualification_manifest_sha256": manifest_sha256,
    }
    pipeline._require_prior_capture_runtime_bindings(records, **kwargs)

    drifted = {**formal, "chaff_qualification_set_manifest_sha256": "f" * 64}
    with pytest.raises(ValueError, match="qualification manifest differs"):
        pipeline._require_prior_capture_runtime_bindings((certification, canary, drifted), **kwargs)
    drifted = {
        **formal,
        "defense_runtime_inputs": {
            **formal["defense_runtime_inputs"],
            "traffic-morphing": {"identity": "drifted"},
        },
    }
    with pytest.raises(ValueError, match="runtime inputs differ"):
        pipeline._require_prior_capture_runtime_bindings((certification, canary, drifted), **kwargs)


def test_canary_and_formal_capture_require_readiness_and_pre_snapshot(tmp_path):
    admission = _admission(tmp_path)
    with pytest.raises(ValueError, match="--readiness-attestation"):
        pipeline._validate_formal_capture_authority(
            "canary",
            readiness_attestation=None,
            historical_pre_snapshot=None,
            admission=admission,
            prerequisite_records=(),
            capture_started_at=None,
        )

    unexpected = tmp_path / "unexpected.json"
    unexpected.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="forbids readiness"):
        pipeline._validate_formal_capture_authority(
            "certification",
            readiness_attestation=unexpected,
            historical_pre_snapshot=None,
            admission=admission,
            prerequisite_records=(),
            capture_started_at=None,
        )


@pytest.mark.parametrize(
    "role",
    (
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    ),
)
def test_every_capture_role_requires_and_binds_one_foundation_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, role: str
) -> None:
    import qcsd_lab.class_attestation as attestation

    foundation = tmp_path / f"{role}-foundation.json"
    foundation.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        attestation,
        "validate_class_foundation_attestation",
        lambda *_args, **_kwargs: {
            "recorded_at": "2026-08-28T00:00:00+00:00",
            "source": {"identity": "fixture"},
        },
    )
    with pytest.raises(ValueError, match="--foundation-attestation"):
        pipeline._validate_capture_foundation(
            role,
            foundation_attestation=None,
            capture_started_at=None,
            expected_sha256=None,
            prerequisite_records=(),
        )

    authority = pipeline._validate_capture_foundation(
        role,
        foundation_attestation=foundation,
        capture_started_at=None,
        expected_sha256=None,
        prerequisite_records=(),
    )
    assert authority is not None
    assert authority["foundation_attestation"]["sha256"] == pipeline.sha256_file(foundation)


def test_capture_foundation_rejects_resume_or_prerequisite_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import qcsd_lab.class_attestation as attestation

    foundation = tmp_path / "foundation.json"
    foundation.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        attestation,
        "validate_class_foundation_attestation",
        lambda *_args, **_kwargs: {
            "recorded_at": "2026-08-28T00:00:00+00:00",
            "source": {"identity": "fixture"},
        },
    )
    with pytest.raises(ValueError, match="different foundation attestation"):
        pipeline._validate_capture_foundation(
            "certification",
            foundation_attestation=foundation,
            capture_started_at="2026-08-28T01:00:00+00:00",
            expected_sha256="f" * 64,
            prerequisite_records=(),
        )
    with pytest.raises(ValueError, match="prerequisites use a different foundation"):
        pipeline._validate_capture_foundation(
            "certification",
            foundation_attestation=foundation,
            capture_started_at=None,
            expected_sha256=None,
            prerequisite_records=({"class_study_foundation_sha256": "f" * 64},),
        )


def test_formal_capacity_preflight_projects_certification_and_requires_triple_space(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    certification = tmp_path / "certification"
    certification.mkdir()
    (certification / "payload.bin").write_bytes(b"x" * 9_000)
    (certification / "evidence.sha256").write_text("seal\n", encoding="utf-8")
    verified = SimpleNamespace(
        root=certification,
        accepted_samples={f"s-{index}": {} for index in range(900)},
        checksums={"payload.bin": "a" * 64},
        experiment={
            "started_at": "2026-08-28T00:00:00+00:00",
            "completed_at": "2026-08-28T00:15:00+00:00",
        },
    )
    monkeypatch.setattr(pipeline, "verify_result", lambda _root: verified)
    monkeypatch.setattr(
        pipeline.shutil,
        "disk_usage",
        lambda _root: SimpleNamespace(total=10**12, used=0, free=10**12),
    )
    capacity = pipeline._formal_capacity_preflight(
        "canary",
        authority={"certification_result_root": str(certification)},
        prerequisite_records=(),
        storage_root=tmp_path,
        current_experiment=None,
    )
    assert capacity is not None
    assert capacity["progress"]["remaining_samples"] == 17_000
    assert capacity["storage"]["required_free_bytes_three_times_projection"] == (
        3 * capacity["storage"]["projected_remaining_bytes"]
    )
    assert capacity["wall_time"]["expected_remaining_hours"] > 0

    required = capacity["storage"]["required_free_bytes_three_times_projection"]
    monkeypatch.setattr(
        pipeline.shutil,
        "disk_usage",
        lambda _root: SimpleNamespace(total=required, used=1, free=required - 1),
    )
    with pytest.raises(ValueError, match="three times projected"):
        pipeline._formal_capacity_preflight(
            "formal",
            authority={"certification_result_root": str(certification)},
            prerequisite_records=(),
            storage_root=tmp_path,
            current_experiment=None,
        )


def test_capture_guidance_does_not_launch(monkeypatch, tmp_path):
    admission = _admission(tmp_path)
    campaign = tmp_path / "formal.yml"
    campaign.write_text("schema: 2\n", encoding="utf-8")
    records = [
        _record("certification"),
        _record("canary", block=1),
    ]
    monkeypatch.setattr(pipeline, "_result_index", lambda roots, **kwargs: records)
    monkeypatch.setattr(
        pipeline,
        "preflight_campaign",
        lambda path: {
            "name": f"{STUDY_ID}-formal-01-1200",
            "evidence_role": "formal",
            "sample_count": 1600,
        },
    )
    monkeypatch.setattr(
        pipeline, "_require_capture_admission_binding", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_capture_foundation",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_formal_capture_authority",
        lambda *args, **kwargs: {"valid": True},
    )
    monkeypatch.setattr(
        pipeline,
        "_formal_capacity_preflight",
        lambda *args, **kwargs: {"passed": True},
    )

    def forbidden_run(*args, **kwargs):
        raise AssertionError("capture was launched without explicit execution")

    monkeypatch.setattr(pipeline, "run_campaign", forbidden_run)
    result = pipeline._coordinate_capture(
        "capture",
        pilot_admission=None,
        final_admission=admission,
        campaign=campaign,
        results_root=tmp_path,
        capture_result=None,
        prerequisite_roots=(),
        foundation_attestation=None,
        readiness_attestation=None,
        historical_pre_snapshot=None,
        execute=False,
    )

    assert result.status == "ready"
    assert result.details["will_create_result"] is False


def test_capture_delegates_only_after_prerequisites(monkeypatch, tmp_path):
    admission = _admission(tmp_path)
    campaign = tmp_path / "formal.yml"
    campaign.write_text("schema: 2\n", encoding="utf-8")
    output = tmp_path / "result"
    output.mkdir()
    records = [_record("certification"), _record("canary", block=1)]
    monkeypatch.setattr(pipeline, "_result_index", lambda roots, **kwargs: records)
    monkeypatch.setattr(
        pipeline,
        "preflight_campaign",
        lambda path: {
            "name": f"{STUDY_ID}-formal-01-1200",
            "evidence_role": "formal",
            "class_study_id": STUDY_ID,
            "class_study_cohort_sha256": admission.cohort_sha256,
            "class_study_cohort_assembly_sha256": admission.assembly_sha256,
        },
    )
    monkeypatch.setattr(
        pipeline, "_require_capture_admission_binding", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_capture_foundation",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_formal_capture_authority",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        pipeline,
        "_formal_capacity_preflight",
        lambda *args, **kwargs: {"passed": True},
    )
    launched = []

    def authorised_run(path, root):
        orchestrator._require_class_study_coordinator_capture_authority(
            {
                "name": f"{STUDY_ID}-formal-01-1200",
                "evidence_role": "formal",
                "class_study_id": STUDY_ID,
                "campaign_sha256": util.sha256_file(campaign),
                "class_study_cohort_sha256": admission.cohort_sha256,
                "class_study_cohort_assembly_sha256": admission.assembly_sha256,
            }
        )
        launched.append((path, root))
        return output

    monkeypatch.setattr(
        pipeline,
        "run_campaign",
        authorised_run,
    )
    monkeypatch.setattr(
        pipeline,
        "verify_class_study_result",
        lambda root, **kwargs: {"valid": True, "root": str(root)},
    )

    result = pipeline._coordinate_capture(
        "capture",
        pilot_admission=None,
        final_admission=admission,
        campaign=campaign,
        results_root=tmp_path,
        capture_result=None,
        prerequisite_roots=(),
        foundation_attestation=None,
        readiness_attestation=None,
        historical_pre_snapshot=None,
        execute=True,
    )

    assert result.status == "complete"
    assert launched == [(campaign, tmp_path)]
    with pytest.raises(ValueError, match="validated prerequisite ledger"):
        orchestrator._require_class_study_coordinator_capture_authority(
            {
                "name": f"{STUDY_ID}-formal-01-1200",
                "evidence_role": "formal",
                "class_study_id": STUDY_ID,
                "campaign_sha256": util.sha256_file(campaign),
                "class_study_cohort_sha256": admission.cohort_sha256,
                "class_study_cohort_assembly_sha256": admission.assembly_sha256,
            }
        )


@pytest.mark.parametrize(
    ("role", "name"),
    (
        ("pilot-fitting", f"{STUDY_ID}-pilot-fitting-600-1200"),
        ("pilot-compatibility", f"{STUDY_ID}-pilot-compatibility-1080-1200"),
        ("authoritative-fitting", f"{STUDY_ID}-authoritative-fitting-1200"),
        ("formal", f"{STUDY_ID}-formal-01-1200"),
    ),
)
def test_generic_run_rejects_coordinator_only_class_capture_before_mutation(
    monkeypatch,
    tmp_path,
    role,
    name,
):
    campaign = orchestrator.Campaign(
        path=tmp_path / "formal.yml",
        source_bytes=b"schema: 2\n",
        name=name,
        purpose="evaluation",
        seed=1,
        profile="live",
        workloads=(),
        request_policies=(),
        defenses=(),
        limits=Limits(120, 1024, 180, 64, 3, 30.0, 1.0),
        schema_version=2,
        evidence_role=role,
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
        class_study_id=STUDY_ID,
    )
    monkeypatch.setattr(orchestrator, "load_campaign", lambda _path: campaign)
    monkeypatch.setattr(
        orchestrator,
        "_run_loaded_campaign",
        lambda *_args, **_kwargs: pytest.fail("generic launch reached result mutation"),
    )

    with pytest.raises(ValueError, match="validated prerequisite ledger"):
        orchestrator.run_campaign(campaign.path, tmp_path / "missing-results")
    assert not (tmp_path / "missing-results").exists()


@pytest.mark.parametrize(
    ("role", "name"),
    (
        ("pilot-fitting", f"{STUDY_ID}-pilot-fitting-600-1200"),
        ("pilot-compatibility", f"{STUDY_ID}-pilot-compatibility-1080-1200"),
        ("authoritative-fitting", f"{STUDY_ID}-authoritative-fitting-1200"),
        ("certification", f"{STUDY_ID}-certification-900-1200"),
    ),
)
def test_generic_resume_rejects_coordinator_only_class_capture_before_mutation(
    monkeypatch,
    tmp_path,
    role,
    name,
):
    root = tmp_path / "result"
    root.mkdir()
    (root / "experiment.json").write_text(
        json.dumps(
            {
                "name": name,
                "configuration": {
                    "evidence_role": role,
                    "class_study_id": STUDY_ID,
                    "campaign_sha256": "c" * 64,
                    "class_study_cohort_sha256": "a" * 64,
                    "class_study_cohort_assembly_sha256": "b" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        orchestrator,
        "_resume_campaign_locked",
        lambda *_args, **_kwargs: pytest.fail("generic resume reached result mutation"),
    )

    with pytest.raises(ValueError, match="validated prerequisite ledger"):
        orchestrator.resume_campaign(root)


@pytest.mark.parametrize(
    ("role", "name", "predecessor"),
    (
        (
            "pilot-compatibility",
            f"{STUDY_ID}-pilot-compatibility-1080-1200",
            "pilot-fitting",
        ),
        (
            "authoritative-fitting",
            f"{STUDY_ID}-authoritative-fitting-1200",
            "pilot-compatibility",
        ),
    ),
)
def test_coordinator_authorises_ordered_predecessor_roles_only_inside_scope(
    role,
    name,
    predecessor,
):
    configuration = {
        "name": name,
        "evidence_role": role,
        "class_study_id": STUDY_ID,
        "campaign_sha256": "c" * 64,
        "class_study_cohort_sha256": "a" * 64,
        "class_study_cohort_assembly_sha256": "b" * 64,
    }
    predecessor_record = _record(predecessor)

    with orchestrator._class_study_coordinator_capture_authority(
        configuration,
        (predecessor_record,),
    ):
        orchestrator._require_class_study_coordinator_capture_authority(configuration)

    with pytest.raises(ValueError, match="validated prerequisite ledger"):
        orchestrator._require_class_study_coordinator_capture_authority(configuration)


def test_successor_authoritative_fitting_uses_exact_restart_authority() -> None:
    study_id = "classifier-multiorigin100-v2-" + "c" * 16
    configuration = {
        "name": f"{study_id}-authoritative-fitting-2000-1200",
        "evidence_role": "authoritative-fitting",
        "class_study_id": study_id,
        "campaign_sha256": "f" * 64,
        "class_study_cohort_sha256": "a" * 64,
        "class_study_cohort_assembly_sha256": "b" * 64,
        orchestrator.CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY: "d" * 64,
    }

    with orchestrator._class_study_coordinator_capture_authority(configuration, ()):
        orchestrator._require_class_study_coordinator_capture_authority(configuration)
        with pytest.raises(ValueError, match="validated prerequisite ledger"):
            orchestrator._require_class_study_coordinator_capture_authority(
                {
                    **configuration,
                    orchestrator.CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY: "e" * 64,
                }
            )


def test_initial_pilot_fitting_uses_coordinator_authority_without_predecessor() -> None:
    configuration = {
        "name": f"{STUDY_ID}-pilot-fitting-600-1200",
        "evidence_role": "pilot-fitting",
        "class_study_id": STUDY_ID,
        "campaign_sha256": "f" * 64,
        "class_study_cohort_sha256": "a" * 64,
        "class_study_cohort_assembly_sha256": "b" * 64,
    }

    with orchestrator._class_study_coordinator_capture_authority(configuration, ()):
        orchestrator._require_class_study_coordinator_capture_authority(configuration)
    with pytest.raises(ValueError, match="validated prerequisite ledger"):
        orchestrator._require_class_study_coordinator_capture_authority(configuration)


def test_coordinator_resume_carries_validated_prerequisite_authority(
    monkeypatch,
    tmp_path,
):
    admission = _admission(tmp_path / "admission")
    source = tmp_path / "result"
    source.mkdir()
    configuration = {
        "evidence_role": "formal",
        "class_study_id": STUDY_ID,
        "campaign_sha256": "c" * 64,
        "class_study_cohort_sha256": admission.cohort_sha256,
        "class_study_cohort_assembly_sha256": admission.assembly_sha256,
    }
    (source / "experiment.json").write_text(
        json.dumps(
            {
                "name": f"{STUDY_ID}-formal-01-1200",
                "started_at": "2026-08-31T00:00:00+00:00",
                "status": "incomplete",
                "configuration": configuration,
            }
        ),
        encoding="utf-8",
    )
    records = [_record("certification"), _record("canary", block=1)]
    monkeypatch.setattr(pipeline, "_result_index", lambda roots, **kwargs: records)
    monkeypatch.setattr(
        pipeline, "_require_capture_admission_binding", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_capture_foundation",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_formal_capture_authority",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        pipeline,
        "_formal_capacity_preflight",
        lambda *args, **kwargs: {"passed": True},
    )
    resumed = []

    def authorised_resume(root):
        orchestrator._require_class_study_coordinator_capture_authority(
            {**configuration, "name": f"{STUDY_ID}-formal-01-1200"}
        )
        resumed.append(root)
        return root

    monkeypatch.setattr(pipeline, "resume_campaign", authorised_resume)
    monkeypatch.setattr(
        pipeline,
        "verify_class_study_result",
        lambda root, **kwargs: {"valid": True, "root": str(root)},
    )

    result = pipeline._coordinate_capture(
        "resume",
        pilot_admission=None,
        final_admission=admission,
        campaign=None,
        results_root=None,
        capture_result=source,
        prerequisite_roots=(),
        foundation_attestation=None,
        readiness_attestation=None,
        historical_pre_snapshot=None,
        execute=True,
    )

    assert result.status == "complete"
    assert resumed == [source]


def test_qualification_defaults_to_resumable_guidance(monkeypatch, tmp_path):
    admission = _admission(tmp_path)
    numeric = tmp_path / "numeric"
    prefix = tmp_path / "prefix"
    workloads = tmp_path / "workloads"
    sidecars = tmp_path / "sidecars"
    publications = tmp_path / "sets"
    for path in (numeric, prefix, workloads, sidecars, publications):
        path.mkdir()
    checkpoint = tmp_path / "checkpoint.json"
    monkeypatch.setattr(
        pipeline,
        "verify_numeric_fitting_bundle",
        lambda path: SimpleNamespace(stage="pilot"),
    )
    monkeypatch.setattr(
        pipeline,
        "_verify_prefix_spec_root",
        lambda *args, **kwargs: {"valid": True},
    )
    monkeypatch.setattr(pipeline, "_require_numeric_admission", lambda *args: None)
    monkeypatch.setattr(
        pipeline,
        "initialize_named_qualification_checkpoint",
        lambda *args, **kwargs: checkpoint.write_text("{}", encoding="utf-8"),
    )
    monkeypatch.setattr(
        pipeline,
        "reconcile_named_qualification_checkpoint",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        pipeline,
        "pending_named_qualification_workloads",
        lambda *args, **kwargs: ("pilot-000", "pilot-001"),
    )
    monkeypatch.setattr(
        pipeline,
        "qualify_chaff",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("live qualification should not run by default")
        ),
    )
    authority = _qualification_authority()
    monkeypatch.setattr(
        pipeline,
        "_qualification_execution_context",
        lambda: ({}, authority["prepare_source"], authority["prepare_image_digest"]),
    )

    result = pipeline._coordinate_qualification(
        "pilot",
        admission=admission,
        numeric_bundle_root=numeric,
        prefix_spec_root=prefix,
        workload_root=workloads,
        checkpoint_path=checkpoint,
        sidecar_root=sidecars,
        publication_root=publications,
        workload_id=None,
        qualify_all_pending=False,
        qualification_authority=authority,
    )

    assert result.status == "pending"
    assert result.details["qualified"] == 118
    assert result.details["next_workload"] == "pilot-000"


def _qualification_coordinator_inputs(monkeypatch, tmp_path):
    admission = _admission(tmp_path)
    roots = {
        name: tmp_path / name for name in ("numeric", "prefix", "workloads", "sidecars", "sets")
    }
    for path in roots.values():
        path.mkdir(exist_ok=True)
    checkpoint = tmp_path / "checkpoint.json"
    monkeypatch.setattr(
        pipeline,
        "verify_numeric_fitting_bundle",
        lambda _path: SimpleNamespace(stage="pilot"),
    )
    monkeypatch.setattr(pipeline, "_require_numeric_admission", lambda *_args: None)
    monkeypatch.setattr(
        pipeline, "_verify_prefix_spec_root", lambda *_args, **_kwargs: {"valid": True}
    )
    return admission, roots, checkpoint


@pytest.mark.parametrize(
    "source_result",
    (
        {"study_id": STUDY_ID},
        {
            "study_id": "classifier-multiorigin100-v2-other",
            "class_study_successor_sha256": "a" * 64,
        },
        {
            "study_id": "classifier-multiorigin100-v2-active",
            "class_study_successor_sha256": "b" * 64,
        },
    ),
    ids=("predecessor-v1", "other-v2", "same-id-different-restart"),
)
def test_successor_qualification_rejects_wrong_numeric_lineage_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source_result: dict[str, object],
) -> None:
    admission, roots, checkpoint = _qualification_coordinator_inputs(monkeypatch, tmp_path)
    monkeypatch.setattr(
        pipeline,
        "verify_numeric_fitting_bundle",
        lambda _path: SimpleNamespace(
            stage="authoritative",
            provenance={"source_result": source_result},
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "_verify_prefix_spec_root",
        lambda *_args, **_kwargs: pytest.fail(
            "prefix evidence read after wrong successor fitting lineage"
        ),
    )

    with pytest.raises(
        ValueError,
        match="predecessor or another successor restart",
    ):
        pipeline._coordinate_qualification(
            "authoritative",
            admission=admission,
            numeric_bundle_root=roots["numeric"],
            prefix_spec_root=roots["prefix"],
            workload_root=roots["workloads"],
            checkpoint_path=checkpoint,
            sidecar_root=roots["sidecars"],
            publication_root=roots["sets"],
            workload_id=None,
            qualify_all_pending=False,
            qualification_authority=_qualification_authority(),
            expected_successor_study_id="classifier-multiorigin100-v2-active",
            expected_successor_restart_sha256="a" * 64,
        )
    assert not checkpoint.exists()
    assert list(roots["sets"].iterdir()) == []


@pytest.mark.parametrize("action", ("prefix-specs", "finalize-fitting"))
def test_successor_numeric_publishers_reject_wrong_restart_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    action: str,
) -> None:
    study_id = "classifier-multiorigin100-v2-active"
    restart = tmp_path / "restart.json"
    restart.write_text("restart\n", encoding="utf-8")
    context = {
        "study_id": study_id,
        "restart_path": restart,
        "restart": {"predecessor_foundation_sha256": "f" * 64},
        "artifacts_root": tmp_path / "artifacts",
        "numeric_bundle_root": tmp_path / "numeric",
        "prefix_spec_root": tmp_path / "prefix-specs",
        "qualification_checkpoint": tmp_path / "qualification/checkpoint.json",
        "qualification_sidecar_root": tmp_path / "qualification/final-full",
        "qualification_publication_root": tmp_path / "qualification",
        "qualification_manifest": tmp_path / "qualification/final-full/_qualification-set.json",
        "final_bundle_root": tmp_path / "final-bundle",
    }
    admission = _admission(tmp_path / "admission")
    wrong_numeric = SimpleNamespace(
        stage="authoritative",
        provenance={
            "source_result": {
                "study_id": study_id,
                "class_study_successor_sha256": "0" * 64,
            }
        },
    )
    monkeypatch.setattr(
        pipeline,
        "_successor_action_context",
        lambda *_args, **_kwargs: context,
    )
    monkeypatch.setattr(
        pipeline,
        "verify_successor_cohort_admission",
        lambda _path: admission,
    )
    monkeypatch.setattr(
        pipeline,
        "verify_numeric_fitting_bundle",
        lambda *_args, **_kwargs: wrong_numeric,
    )
    monkeypatch.setattr(pipeline, "_require_numeric_admission", lambda *_args: None)
    monkeypatch.setattr(
        pipeline,
        "_result_index",
        lambda *_args, **_kwargs: [
            {"evidence_role": "authoritative-fitting", "root": str(tmp_path / "result")}
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "_require_successor_result_records",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        pipeline,
        "derive_schema_six_prefix_specs",
        lambda *_args, **_kwargs: pytest.fail(
            "prefix specifications were published for another successor restart"
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "finalize_fitting_bundle",
        lambda *_args, **_kwargs: pytest.fail(
            "fitting bundle was finalised for another successor restart"
        ),
    )

    with pytest.raises(
        ValueError,
        match="predecessor or another successor restart",
    ):
        pipeline.run_class_study_action(
            action,
            stage="authoritative",
            successor_restart=restart,
            result_roots=(tmp_path / "result",),
            workload_root=tmp_path / "workloads",
        )
    assert not context["artifacts_root"].exists()
    assert not context["final_bundle_root"].exists()


@pytest.mark.parametrize("mismatch", ("source", "image"))
def test_qualification_runtime_mismatch_fails_before_checkpoint_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mismatch: str
) -> None:
    admission, roots, checkpoint = _qualification_coordinator_inputs(monkeypatch, tmp_path)
    authority = _qualification_authority()
    source = dict(authority["prepare_source"])
    image = str(authority["prepare_image_digest"])
    if mismatch == "source":
        source["lab_commit"] = "8" * 40
    else:
        image = "sha256:" + "8" * 64
    monkeypatch.setattr(pipeline, "_qualification_execution_context", lambda: ({}, source, image))
    monkeypatch.setattr(
        pipeline,
        "initialize_named_qualification_checkpoint",
        lambda *_args, **_kwargs: pytest.fail("checkpoint mutated before runtime lineage gate"),
    )

    with pytest.raises(ValueError, match="runtime differs"):
        pipeline._coordinate_qualification(
            "pilot",
            admission=admission,
            numeric_bundle_root=roots["numeric"],
            prefix_spec_root=roots["prefix"],
            workload_root=roots["workloads"],
            checkpoint_path=checkpoint,
            sidecar_root=roots["sidecars"],
            publication_root=roots["sets"],
            workload_id=None,
            qualify_all_pending=False,
            qualification_authority=authority,
        )
    assert not checkpoint.exists()
    assert list(roots["sets"].iterdir()) == []


@pytest.mark.parametrize("mismatch", ("source", "image"))
def test_stale_qualification_sidecar_fails_before_checkpoint_or_publication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mismatch: str
) -> None:
    admission, roots, checkpoint = _qualification_coordinator_inputs(monkeypatch, tmp_path)
    authority = _qualification_authority()
    source = dict(authority["prepare_source"])
    image = str(authority["prepare_image_digest"])
    if mismatch == "source":
        source["neqo_commit"] = "8" * 40
    else:
        image = "sha256:" + "8" * 64
    (roots["sidecars"] / "pilot-000.json").write_text(
        json.dumps(
            {
                "qualification_source": source,
                "qualification_image_digest": image,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        pipeline,
        "_qualification_execution_context",
        lambda: (
            {},
            authority["prepare_source"],
            authority["prepare_image_digest"],
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "initialize_named_qualification_checkpoint",
        lambda *_args, **_kwargs: pytest.fail("checkpoint mutated before stale-sidecar gate"),
    )

    with pytest.raises(ValueError, match="foundation prepare build"):
        pipeline._coordinate_qualification(
            "pilot",
            admission=admission,
            numeric_bundle_root=roots["numeric"],
            prefix_spec_root=roots["prefix"],
            workload_root=roots["workloads"],
            checkpoint_path=checkpoint,
            sidecar_root=roots["sidecars"],
            publication_root=roots["sets"],
            workload_id=None,
            qualify_all_pending=False,
            qualification_authority=authority,
        )
    assert not checkpoint.exists()
    assert list(roots["sets"].iterdir()) == []


def test_new_wrong_image_sidecar_fails_before_checkpoint_record_or_publication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    admission, roots, checkpoint = _qualification_coordinator_inputs(monkeypatch, tmp_path)
    authority = _qualification_authority()
    monkeypatch.setattr(
        pipeline,
        "_qualification_execution_context",
        lambda: (
            {},
            authority["prepare_source"],
            authority["prepare_image_digest"],
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "initialize_named_qualification_checkpoint",
        lambda *_args, **_kwargs: checkpoint.write_text("{}\n", encoding="utf-8"),
    )
    monkeypatch.setattr(
        pipeline, "reconcile_named_qualification_checkpoint", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        pipeline,
        "pending_named_qualification_workloads",
        lambda *_args, **_kwargs: ("pilot-000",),
    )

    def qualify(workload_id: str, **_kwargs) -> None:
        (roots["sidecars"] / f"{workload_id}.json").write_text(
            json.dumps(
                {
                    "qualification_source": authority["prepare_source"],
                    "qualification_image_digest": "sha256:" + "9" * 64,
                }
            )
            + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(pipeline, "qualify_chaff", qualify)
    monkeypatch.setattr(
        pipeline,
        "record_named_qualification_checkpoint",
        lambda *_args, **_kwargs: pytest.fail("wrong-image sidecar entered checkpoint"),
    )
    monkeypatch.setattr(
        pipeline,
        "publish_named_qualification_set_from_checkpoint",
        lambda *_args, **_kwargs: pytest.fail("wrong-image sidecar was published"),
    )

    with pytest.raises(ValueError, match="foundation prepare build"):
        pipeline._coordinate_qualification(
            "pilot",
            admission=admission,
            numeric_bundle_root=roots["numeric"],
            prefix_spec_root=roots["prefix"],
            workload_root=roots["workloads"],
            checkpoint_path=checkpoint,
            sidecar_root=roots["sidecars"],
            publication_root=roots["sets"],
            workload_id="pilot-000",
            qualify_all_pending=False,
            qualification_authority=authority,
        )
    assert list(roots["sets"].iterdir()) == []


def test_qualify_prefix_rejects_wrong_foundation_before_coordinator_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import qcsd_lab.class_attestation as attestation

    foundation = tmp_path / "foundation.json"
    foundation.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    layout = pipeline.class_study_layout()
    admission = object()
    monkeypatch.setattr(pipeline, "_optional_admission", lambda *_args, **_kwargs: admission)
    observed: dict[str, object] = {}

    def reject(_path: Path, **kwargs):
        observed.update(kwargs)
        raise ValueError("foundation prepare runtime differs")

    monkeypatch.setattr(attestation, "class_qualification_authority", reject)
    monkeypatch.setattr(
        pipeline,
        "_coordinate_qualification",
        lambda *_args, **_kwargs: pytest.fail("coordinator ran with a wrong foundation"),
    )

    with pytest.raises(ValueError, match="foundation prepare runtime differs"):
        pipeline.run_class_study_action(
            "qualify-prefix",
            stage="pilot",
            numeric_bundle_root=layout.pilot_numeric_root,
            prefix_spec_root=layout.pilot_prefix_root,
            workload_root=layout.workload_root,
            qualification_checkpoint=tmp_path / "checkpoint.json",
            qualification_sidecar_root=tmp_path / "sidecars",
            qualification_publication_root=layout.qualification_sets_root,
            foundation_attestation=foundation,
        )
    assert observed["runtime_role"] == "prepare"
    assert not (tmp_path / "checkpoint.json").exists()


def test_cli_exposes_class_study_without_implicit_execution():
    from qcsd_lab.cli import parser

    parsed = parser().parse_args(
        [
            "class-study",
            "capture",
            "--stage",
            "authoritative",
            "--campaign",
            "formal.yml",
            "--pilot-cohort",
            "pilot.json",
            "--pilot-cohort-assembly",
            "pilot-assembly.json",
            "--final-cohort",
            "final.json",
            "--final-cohort-assembly",
            "final-assembly.json",
            "--acquisition-completion",
            "completion.json",
            "--final-selection",
            "selection.json",
            "--foundation-attestation",
            "foundation.json",
            "--readiness-attestation",
            "readiness.json",
            "--historical-pre-snapshot",
            "pre.json",
        ]
    )

    assert parsed.command == "class-study"
    assert parsed.action == "capture"
    assert parsed.execute is False
    assert parsed.stage == "authoritative"
    assert parsed.pilot_cohort == Path("pilot.json")
    assert parsed.final_cohort == Path("final.json")
    assert parsed.acquisition_completion == Path("completion.json")
    assert parsed.final_selection == Path("selection.json")
    assert parsed.foundation_attestation == Path("foundation.json")
    assert parsed.readiness_attestation == Path("readiness.json")
    assert parsed.historical_pre_snapshot == Path("pre.json")


def test_final_selection_is_recomputed_from_pilot_fit_and_compatibility(monkeypatch, tmp_path):
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    layout = pipeline.class_study_layout()
    admission = _admission(layout.study_config_root, pilot=120, final=100)
    numeric_root = layout.pilot_numeric_root
    numeric_root.mkdir(parents=True)
    (numeric_root / "numeric-provenance.json").write_text("{}\n", encoding="utf-8")
    pilot_ids = tuple(item.candidate_id for item in admission.selection.pilot)
    selected_pairs = [
        {
            "real": pilot_ids[index],
            "decoy": pilot_ids[index + 1],
            "base_matching_cost_packets": 0,
            "matching_cost_packets": 2,
        }
        for index in range(0, len(pilot_ids), 2)
    ]
    numeric = SimpleNamespace(
        root=numeric_root,
        stage="pilot",
        artifact_hashes={
            "traffic_morphing": "a" * 64,
            "wtf_pad": "b" * 64,
            "walkie_talkie": "c" * 64,
        },
        provenance={
            "fitting_contract": {"workload_order": list(pilot_ids)},
            "cohort": {
                "receipt_sha256": admission.cohort_sha256,
                "assembly_receipt_sha256": admission.assembly_sha256,
            },
            "source_result": {"evidence_sha256": "d" * 64},
            "algorithms": {"walkie_talkie": {"selected_pairs": selected_pairs}},
        },
    )
    monkeypatch.setattr(pipeline, "verify_numeric_fitting_bundle", lambda path: numeric)
    finalized_root = tmp_path / "compatibility/inputs/defense-parameters/class-study"
    finalized_root.mkdir(parents=True)
    (finalized_root / "provenance.json").write_text("{}\n", encoding="utf-8")
    (finalized_root / "walkie-talkie.json").write_text(
        json.dumps(
            {
                "profiles": [
                    {
                        "real": pair["real"],
                        "decoy": pair["decoy"],
                        "bursts": [{"outgoing": 3, "incoming": 2}],
                    }
                    for pair in selected_pairs
                ],
                "qualification_bindings": [
                    {
                        "workload_id": workload_id,
                        "chaff_qualification_sidecar_sha256": "1" * 64,
                        "prefix_pack_spec_sha256": "2" * 64,
                        "qualified_chaff_manifest_sha256": "3" * 64,
                        "qualified_parallel_chaff_streams": 5,
                        "walkie_talkie_required_chaff_streams": 1,
                    }
                    for workload_id in pilot_ids
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    finalized = SimpleNamespace(
        root=finalized_root,
        stage="pilot",
        artifact_hashes={
            "traffic_morphing": "a" * 64,
            "wtf_pad": "b" * 64,
            # Finalization binds qualification evidence into Walkie-Talkie, so
            # this runtime hash must not be the numeric staging hash.
            "walkie_talkie": "9" * 64,
        },
    )
    monkeypatch.setattr(
        pipeline,
        "_verify_pilot_compatibility_fitting_bundle",
        lambda *_args, **_kwargs: finalized,
    )
    monkeypatch.setattr(
        pipeline,
        "_qualified_final_pair_selection",
        lambda *_args, **_kwargs: SimpleNamespace(
            matching=tuple((pilot_ids[index], pilot_ids[index + 1]) for index in range(0, 100, 2))
        ),
    )
    compatibility = {
        "name": f"{STUDY_ID}-pilot-compatibility-1080-1200",
        "root": str(tmp_path / "compatibility"),
        "evidence_sha256": "e" * 64,
        "experiment_sha256": "f" * 64,
        "accepted": 1080,
        "unique_class_mode_pairs": 1080,
        "defense_parameter_sha256": {
            "traffic-morphing": finalized.artifact_hashes["traffic_morphing"],
            "wtf-pad": finalized.artifact_hashes["wtf_pad"],
            "walkie-talkie": finalized.artifact_hashes["walkie_talkie"],
        },
    }
    monkeypatch.setattr(
        pipeline,
        "verify_class_study_result",
        lambda *args, **kwargs: compatibility,
    )

    pilot_cohort = layout.study_config_root / pipeline.PILOT_COHORT_FILENAME
    pilot_assembly = layout.study_config_root / pipeline.PILOT_COHORT_ASSEMBLY_FILENAME
    pilot_cohort.write_bytes(admission.cohort_path.read_bytes())
    pilot_assembly.write_bytes(admission.assembly_path.read_bytes())
    admission = replace(
        admission,
        cohort_path=pilot_cohort,
        assembly_path=pilot_assembly,
    )
    destination = layout.study_config_root / pipeline.FINAL_SELECTION_FILENAME
    pipeline.write_final_selection_input(
        destination,
        pilot_admission=admission,
        pilot_numeric_bundle_root=numeric_root,
        pilot_compatibility_result_root=tmp_path / "compatibility",
    )
    value = json.loads(destination.read_text(encoding="utf-8"))
    pairs = pipeline.validate_final_selection_input(
        value,
        pilot_admission=admission,
        pilot_numeric_bundle_root=numeric_root,
        pilot_compatibility_result_root=tmp_path / "compatibility",
    )
    assert len(pairs) == 60
    assert {item for pair in pairs for item in pair} == set(pilot_ids)
    assert pairs[0] == (pilot_ids[0], pilot_ids[1])
    assert pairs[-1] == (pilot_ids[-2], pilot_ids[-1])
    assert (
        value["payload"]["pilot_compatibility"]["fitted_parameter_sha256"]
        == compatibility["defense_parameter_sha256"]
    )
    assert value["payload"]["pilot_compatibility"]["finalized_bundle"][
        "provenance_sha256"
    ] == pipeline.sha256_file(finalized_root / "provenance.json")

    graph = {frozenset(pair) for pair in pairs}
    assert frozenset((pilot_ids[0], pilot_ids[2])) not in graph
    rule = value["payload"]["feasible_pair_rule"]
    assert rule["qualified_pair_edges"] == 60
    assert rule["unqualified_alternate_pairs_excluded"] == (120 * 119 // 2) - 60
    assert rule["unselected_pairs_inferred_from_endpoint_compatibility"] is False
    assert len(value["payload"]["selected_final_perfect_matching"]) == 50

    compatibility["defense_parameter_sha256"]["walkie-talkie"] = "0" * 64
    with pytest.raises(ValueError, match="exact pilot fitted parameters"):
        pipeline.validate_final_selection_input(
            json.loads(destination.read_text(encoding="utf-8")),
            pilot_admission=admission,
            pilot_numeric_bundle_root=numeric_root,
            pilot_compatibility_result_root=tmp_path / "compatibility",
        )
    compatibility["defense_parameter_sha256"]["walkie-talkie"] = "9" * 64

    value["payload"]["feasible_pair_graph"][0].reverse()
    with pytest.raises(ValueError, match="SHA-256|verified pilot evidence"):
        pipeline.validate_final_selection_input(
            value,
            pilot_admission=admission,
            pilot_numeric_bundle_root=numeric_root,
            pilot_compatibility_result_root=tmp_path / "compatibility",
        )


def test_campaign_publication_is_two_stage_and_never_reuses_pilot_for_final(monkeypatch, tmp_path):
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    layout = pipeline.class_study_layout()
    study_root = layout.study_config_root
    study_root.mkdir(parents=True)

    def canonical_admission(stage: str):
        source = _admission(tmp_path / stage)
        if stage == "pilot":
            cohort_name = pipeline.PILOT_COHORT_FILENAME
            assembly_name = pipeline.PILOT_COHORT_ASSEMBLY_FILENAME
        else:
            cohort_name = pipeline.AUTHORITATIVE_COHORT_FILENAME
            assembly_name = pipeline.AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME
        cohort = study_root / cohort_name
        assembly = study_root / assembly_name
        cohort.write_bytes(source.cohort_path.read_bytes())
        assembly.write_bytes(source.assembly_path.read_bytes())
        return replace(source, cohort_path=cohort, assembly_path=assembly)

    pilot = canonical_admission("pilot")
    final = canonical_admission("final")
    destination = layout.campaign_root
    destination.mkdir(parents=True)
    roles = ["pilot-fitting", "pilot-compatibility", "authoritative-fitting", "certification"]
    roles.extend(role for _block in range(10) for role in ("canary", "formal"))

    def documents(cohort, assembly, **kwargs):
        return {
            f"campaign-{index:02d}.yml": {
                "evidence_role": role,
                "class_study_cohort_assembly": kwargs["cohort_assembly_reference"],
            }
            for index, role in enumerate(roles)
        }

    monkeypatch.setattr(pipeline, "_campaign_documents_with_assembly", documents)
    monkeypatch.setattr(
        pipeline,
        "verify_campaign_set",
        lambda *args, **kwargs: {"valid": True},
    )
    pilot_paths = pipeline.publish_campaign_set("pilot", pilot, destination)
    assert len(pilot_paths) == 2
    final_paths = pipeline.publish_campaign_set(
        "authoritative", pilot, destination, final_admission=final
    )
    assert len(final_paths) == 24


def test_receipt_and_campaign_publishers_reject_alternate_lineage_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path / "lab")
    layout = pipeline.class_study_layout()
    layout.campaign_root.mkdir(parents=True)
    alternate_admission = _admission(tmp_path / "alternate")

    with pytest.raises(ValueError, match="pilot cohort receipt"):
        pipeline.publish_campaign_set(
            "pilot",
            alternate_admission,
            layout.campaign_root,
        )
    assert list(layout.campaign_root.iterdir()) == []

    final_selection = layout.study_config_root / pipeline.FINAL_SELECTION_FILENAME
    with pytest.raises(ValueError, match="pilot cohort receipt"):
        pipeline.write_final_selection_input(
            final_selection,
            pilot_admission=alternate_admission,
            pilot_numeric_bundle_root=layout.pilot_numeric_root,
            pilot_compatibility_result_root=tmp_path / "compatibility",
        )
    assert not final_selection.exists()


def test_launcher_rewrites_class_paths_and_never_mounts_workspace_rw():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert '"${image_id}" "${class_container_args[@]}"' in launcher
    assert (
        "--pilot-cohort|--pilot-cohort-assembly|--final-cohort|--final-cohort-assembly"
    ) in launcher
    assert "--acquisition-completion" in launcher
    assert "--final-selection" in launcher
    assert "--foundation-attestation" in launcher
    assert "--readiness-attestation" in launcher
    assert "--historical-pre-snapshot" in launcher
    assert "QCSD_CLASS_FOUNDATION_ATTESTATION" in launcher
    assert "QCSD_CLASS_READINESS_ATTESTATION" in launcher
    assert "QCSD_CLASS_HISTORICAL_PRE_SNAPSHOT" in launcher
    assert "QCSD_STUDY_ENVIRONMENT_B64" in launcher
    assert '"${class_study_execute}" == "1"' in launcher
    assert 'study_capture_scheduler_contract="qcsd-client-rr1-cpu10-v1"' in launcher
    assert "research capture requires the create-only no-cache build receipt" in launcher
    assert '--volume "${ROOT}:/lab:rw"' not in launcher
    assert "rejects a blanket workspace read-write mount" in launcher
    assert ".class-study-acquisition.lock" in launcher
    assert "another class-study acquisition process holds the runner lock" in launcher
    assert (
        "class-study qualify-prefix requires --foundation-attestation as a regular file" in launcher
    )
    assert "class-study foundation build receipt digest changed" in launcher
    assert 'PREPARE_IMAGE="${class_qualification_fields[0]}"' in launcher
    assert (
        "class-study qualify-prefix rejects QCSD_LAB_PREPARE_IMAGE that differs from foundation"
        in launcher
    )


def test_acquisition_run_is_bounded_and_never_sleeps(monkeypatch, tmp_path):
    import qcsd_lab.class_acquisition as acquisition

    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    layout = pipeline.class_study_layout()
    catalogue = layout.study_config_root / f"{STUDY_ID}-candidates.json"
    catalogue.parent.mkdir(parents=True)
    catalogue.write_text("{}\n", encoding="utf-8")
    runner = layout.acquisition_root
    stability = layout.stability_root
    workloads = layout.workload_root
    for path in (runner, stability, workloads):
        path.mkdir(parents=True)
    seen = {}

    class Backend:
        def __init__(self, *, timeout_ms):
            seen["timeout_ms"] = timeout_ms

    def run(root, **kwargs):
        seen.update(kwargs)
        return {
            "candidate_count": CANDIDATE_COUNT,
            "terminal_count": 17,
            "complete": False,
            "work_due_now": True,
            "next_due": "2026-09-01T00:00:00Z",
        }

    monkeypatch.setattr(acquisition, "ExistingAcquisitionBackend", Backend)
    monkeypatch.setattr(acquisition, "run_due_acquisition", run)
    result = pipeline.run_class_study_action(
        "acquisition-run",
        candidate_catalogue_path=catalogue,
        acquisition_root=runner,
        stability_root=stability,
        workload_root=workloads,
        acquisition_max_candidates=7,
        acquisition_timeout_ms=45_000,
    )

    assert result.status == "pending"
    assert result.details["bounded_candidates"] == 7
    assert result.details["runner_slept"] is False
    assert "rerun now" in result.blockers[0]
    assert seen["max_candidates"] == 7
    assert seen["timeout_ms"] == 45_000

    with pytest.raises(ValueError, match="between 1 and 60000"):
        pipeline.run_class_study_action(
            "acquisition-run",
            candidate_catalogue_path=catalogue,
            acquisition_root=runner,
            stability_root=stability,
            workload_root=workloads,
            acquisition_timeout_ms=60_001,
        )


@pytest.mark.parametrize(
    ("action", "stage", "argument", "message"),
    (
        ("acquisition-run", None, "candidate_catalogue_path", "candidate catalogue"),
        ("stability", None, "workload_root", "workload root"),
        ("cohort", "pilot", "cohort_receipt_path", "direct child"),
        ("campaigns", "pilot", "campaign_root", "campaign root"),
        ("fit-numeric", "pilot", "artifacts_root", "artifact root"),
        ("prefix-specs", "pilot", "numeric_bundle_root", "numeric bundle"),
        (
            "qualify-prefix",
            "pilot",
            "qualification_publication_root",
            "qualification publication root",
        ),
        ("finalize-fitting", "pilot", "final_bundle_root", "final bundle"),
        ("capture", "authoritative", "campaign", "campaign"),
        ("foundation", None, "destination", "foundation destination"),
    ),
)
def test_mutating_actions_reject_alternate_fresh_paths_before_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    stage: str | None,
    argument: str,
    message: str,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path / "lab")
    alternate = tmp_path / "alternate/nested/value.json"
    kwargs = {argument: alternate}

    with pytest.raises(ValueError, match=message):
        pipeline.run_class_study_action(action, stage=stage, **kwargs)
    assert not alternate.exists()


@pytest.mark.parametrize(
    ("action", "stage", "argument"),
    (
        ("acquisition-run", None, "candidate_catalogue_path"),
        ("campaigns", "pilot", "pilot_cohort_receipt_path"),
        ("campaigns", "pilot", "pilot_cohort_assembly_path"),
        ("campaigns", "authoritative", "final_cohort_receipt_path"),
        ("campaigns", "authoritative", "final_cohort_assembly_path"),
        ("cohort", "authoritative", "final_selection_path"),
    ),
)
def test_mutating_actions_reject_colliding_direct_child_receipt_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    stage: str | None,
    argument: str,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path / "lab")
    wrong = pipeline.class_study_layout().study_config_root / "collision.json"

    with pytest.raises(ValueError, match="wrong canonical filename"):
        pipeline.run_class_study_action(action, stage=stage, **{argument: wrong})
    assert not wrong.exists()


def test_qualify_prefix_rejects_symlinked_named_publication_root_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path / "lab")
    layout = pipeline.class_study_layout()
    layout.qualification_sets_root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    layout.pilot_qualification_set_root.symlink_to(outside, target_is_directory=True)
    checkpoint = tmp_path / "checkpoint.json"

    with pytest.raises(ValueError, match="symbolic-link component"):
        pipeline.run_class_study_action(
            "qualify-prefix",
            stage="pilot",
            qualification_checkpoint=checkpoint,
            qualification_publication_root=layout.qualification_sets_root,
        )
    assert not checkpoint.exists()


@pytest.mark.parametrize("action", ("status", "resume", "verify"))
def test_read_only_and_frozen_actions_bypass_prospective_layout_gate(
    tmp_path: Path,
    action: str,
) -> None:
    alternate = tmp_path / "sealed-result/inputs/campaign.yml"
    pipeline._validate_fresh_layout_arguments(
        action=action,
        stage="pilot",
        candidate_catalogue_path=alternate,
        acquisition_root=alternate,
        stability_root=alternate,
        workload_root=alternate,
        pilot_cohort_receipt_path=alternate,
        pilot_cohort_assembly_path=alternate,
        final_cohort_receipt_path=alternate,
        final_cohort_assembly_path=alternate,
        cohort_receipt_path=alternate,
        cohort_assembly_path=alternate,
        final_selection_path=alternate,
        campaign_root=alternate,
        campaign=alternate,
        artifacts_root=alternate,
        numeric_bundle_root=alternate,
        prefix_spec_root=alternate,
        qualification_sidecar_root=alternate,
        qualification_publication_root=alternate,
        qualification_manifest=alternate,
        final_bundle_root=alternate,
        destination=alternate,
    )


def test_acquisition_and_stability_use_exact_canonical_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    layout = pipeline.class_study_layout()

    with pytest.raises(ValueError, match="acquisition root.*canonical"):
        pipeline.run_class_study_action(
            "acquisition-status",
            acquisition_root=tmp_path / "artifacts/alternate-acquisition",
        )
    with pytest.raises(ValueError, match="stability root.*canonical"):
        pipeline.run_class_study_action(
            "stability",
            stability_root=tmp_path / "artifacts/alternate-stability",
        )

    # The layout boundary itself accepts the two exact, stable study paths.
    pipeline._validate_fresh_layout_arguments(
        action="acquisition-status",
        stage=None,
        candidate_catalogue_path=None,
        acquisition_root=layout.acquisition_root,
        stability_root=layout.stability_root,
        workload_root=None,
        pilot_cohort_receipt_path=None,
        pilot_cohort_assembly_path=None,
        final_cohort_receipt_path=None,
        final_cohort_assembly_path=None,
        cohort_receipt_path=None,
        cohort_assembly_path=None,
        final_selection_path=None,
        campaign_root=None,
        campaign=None,
        artifacts_root=None,
        numeric_bundle_root=None,
        prefix_spec_root=None,
        qualification_sidecar_root=None,
        qualification_publication_root=None,
        qualification_manifest=None,
        final_bundle_root=None,
        destination=None,
    )


def test_authoritative_selection_uses_pilot_numeric_canonical_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    layout = pipeline.class_study_layout()

    with pytest.raises(ValueError, match="requires --candidate-catalogue"):
        pipeline.run_class_study_action(
            "cohort",
            stage="authoritative",
            numeric_bundle_root=layout.pilot_numeric_root,
        )
    with pytest.raises(ValueError, match="numeric bundle.*canonical"):
        pipeline.run_class_study_action(
            "cohort",
            stage="authoritative",
            numeric_bundle_root=layout.authoritative_numeric_root,
        )


def test_readiness_requires_mixed_pilot_and_authoritative_canonical_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    layout = pipeline.class_study_layout()

    with pytest.raises(ValueError, match="requires --cohort-version"):
        pipeline.run_class_study_action(
            "readiness",
            numeric_bundle_root=layout.pilot_numeric_root,
            prefix_spec_root=layout.authoritative_prefix_root,
            final_bundle_root=layout.authoritative_final_root,
            qualification_sidecar_root=layout.final_qualification_set_root,
        )
    with pytest.raises(ValueError, match="numeric bundle.*canonical"):
        pipeline.run_class_study_action(
            "readiness",
            numeric_bundle_root=layout.authoritative_numeric_root,
            prefix_spec_root=layout.authoritative_prefix_root,
            final_bundle_root=layout.authoritative_final_root,
            qualification_sidecar_root=layout.final_qualification_set_root,
        )


def test_capture_preflight_rejects_same_id_workload_or_assembly_substitution(tmp_path):
    admission = _admission(tmp_path)
    workloads = [
        {
            "id": item.candidate_id,
            "sha256": admission.prepared_workload_sha256[item.candidate_id],
        }
        for item in admission.selection.final
    ]
    value = {
        "class_study_cohort_sha256": admission.cohort_sha256,
        "class_study_cohort_assembly_sha256": admission.assembly_sha256,
        "workloads": workloads,
    }
    pipeline._require_capture_admission_binding(
        value,
        admission=admission,
        role="formal",
    )

    substituted = {**value, "class_study_cohort_assembly_sha256": "0" * 64}
    with pytest.raises(ValueError, match="different cohort admission"):
        pipeline._require_capture_admission_binding(
            substituted,
            admission=admission,
            role="formal",
        )
    workloads[0] = {**workloads[0], "sha256": "0" * 64}
    with pytest.raises(ValueError, match="prepared workload"):
        pipeline._require_capture_admission_binding(
            value,
            admission=admission,
            role="formal",
        )
