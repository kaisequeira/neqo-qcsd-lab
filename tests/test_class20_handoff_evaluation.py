"""Prospective 20-site handoff dimensions and fail-closed promotion boundary."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import class_attestation, class_evaluation, class_handoff
from qcsd_lab.class_study import (
    CLASS20_PROFILE,
    CLASS20_STUDY_ID,
    bind_receipt,
    canonical_json_bytes,
)
from qcsd_lab.util import sha256_file


def test_profile20_handoff_and_evaluation_agree_on_full_matrix() -> None:
    handoff = class_handoff._dimensions_for_study(CLASS20_STUDY_ID)
    evaluation = class_evaluation._formal_dimensions_for_study(CLASS20_STUDY_ID)
    assert handoff.study_id == evaluation.study_id == CLASS20_STUDY_ID
    assert handoff.class_count == evaluation.classes == CLASS20_PROFILE.final_count == 20
    assert handoff.block_count == evaluation.blocks == 10
    assert handoff.visits_per_block == evaluation.visits_per_block == 10
    assert handoff.modes == evaluation.modes == CLASS20_PROFILE.formal_modes
    assert len(handoff.modes) == 8
    assert handoff.samples_per_block == 1_600
    assert handoff.sample_count == evaluation.sample_count == 16_000
    assert evaluation.train_blocks == tuple(range(1, 9))
    assert evaluation.validation_blocks == (9,)
    assert evaluation.test_blocks == (10,)
    assert class_evaluation._is_formal_dimensions(evaluation)
    assert class_evaluation._formal_random_chance(CLASS20_STUDY_ID) == 0.05
    assert class_evaluation._formal_random_chance(class_handoff.STUDY_ID) == 0.01
    assert "pilot-compatibility" not in class_handoff._excluded_evidence_roles(handoff)
    assert "pilot-compatibility" in class_handoff._excluded_evidence_roles(
        class_handoff._DIMENSIONS
    )
    assert class_handoff.PROFILE_ARTIFACT_TYPE != class_handoff.ARTIFACT_TYPE
    assert (
        class_evaluation._evaluation_artifact_type(CLASS20_STUDY_ID)
        != class_evaluation.EVALUATION_ARTIFACT_TYPE
    )


def test_profile20_export_rejects_v1_snapshot_before_source_replay(
    tmp_path: Path,
) -> None:
    result = tmp_path / "result"
    result.mkdir()
    (result / "experiment.json").write_text(
        json.dumps({"configuration": {"class_study_id": CLASS20_STUDY_ID}}),
        encoding="utf-8",
    )
    calls: list[Path] = []

    def source_verifier(path: Path):
        calls.append(path)
        raise AssertionError("20-site source replay should not start before snapshot authority")

    old_snapshot = tmp_path / "v1-post.json"
    old_snapshot.write_bytes(canonical_json_bytes(bind_receipt({
        "study_id": class_handoff.STUDY_ID,
        "snapshot_schema_version": 1,
        "phase": "post-formal",
    }, receipt_type=class_attestation.HISTORICAL_SNAPSHOT_RECEIPT_TYPE)))
    with pytest.raises(ValueError, match="historical-post snapshot identity is invalid"):
        class_handoff.export_class_handoff(
            [result], tmp_path / "handoff",
            historical_post_snapshot=old_snapshot,
            source_verifier=source_verifier,
        )
    assert calls == []


def test_v1_public_export_preserves_existing_snapshot_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = tmp_path / "result"
    result.mkdir()
    (result / "experiment.json").write_text(
        json.dumps({"configuration": {"class_study_id": class_handoff.STUDY_ID}}),
        encoding="utf-8",
    )
    destination = tmp_path / "handoff"
    snapshot = tmp_path / "post.json"
    seen: list[dict] = []

    def routed_export(_roots, _destination, **kwargs):
        seen.append(kwargs)
        return destination

    monkeypatch.setattr(class_handoff, "_export_class_handoff", routed_export)
    assert class_handoff.export_class_handoff(
        [result], destination, historical_post_snapshot=snapshot,
        source_verifier=lambda _path: SimpleNamespace(experiment={
            "configuration": {"class_study_id": class_handoff.STUDY_ID}
        }),
    ) == destination
    assert seen[0]["dimensions"].study_id == class_handoff.STUDY_ID
    assert seen[0]["dimensions"].sample_count == 16_000
    assert seen[0]["historical_post_snapshot"] == snapshot


def test_profile20_public_export_routes_to_registered_snapshot_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = tmp_path / "result"
    result.mkdir()
    (result / "experiment.json").write_text(
        json.dumps({"configuration": {"class_study_id": CLASS20_STUDY_ID}}),
        encoding="utf-8",
    )
    post = tmp_path / "post.json"
    post.write_bytes(canonical_json_bytes(bind_receipt({
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": class_handoff._CLASS20_OVERLAY_SHA256,
        "snapshot_schema_version": 2,
        "phase": "post-formal",
    }, receipt_type=class_attestation.HISTORICAL_SNAPSHOT_RECEIPT_TYPE)))
    destination = tmp_path / "handoff"
    calls: list[dict] = []

    def source_verifier(path: Path):
        assert path == result
        return SimpleNamespace(experiment={"configuration": {"class_study_id": CLASS20_STUDY_ID}})

    def routed_export(_roots, _destination, **kwargs):
        calls.append(kwargs)
        assert _roots == [result]
        assert _destination == destination
        return destination

    monkeypatch.setattr(class_handoff, "_export_class_handoff", routed_export)
    assert class_handoff.export_class_handoff(
        [result], destination, historical_post_snapshot=post,
        source_verifier=source_verifier,
    ) == destination
    assert calls[0]["historical_post_snapshot"] == post
    assert calls[0]["dimensions"].study_id == CLASS20_STUDY_ID
    assert calls[0]["dimensions"].sample_count == 16_000
    assert "historical_post_validator" not in calls[0]


def test_profile20_public_verify_and_evaluation_reach_deep_handoff_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "handoff"
    root.mkdir()
    (root / "dataset.json").write_text(
        json.dumps({"study_id": CLASS20_STUDY_ID}), encoding="utf-8"
    )
    calls: list[tuple[str, bool]] = []

    def routed_verify(path: Path, **kwargs):
        calls.append(("handoff", kwargs["deep"]))
        assert kwargs["dimensions"].study_id == CLASS20_STUDY_ID
        assert kwargs["dimensions"].sample_count == 16_000
        return path

    def routed_load(path: Path, **kwargs):
        calls.append(("evaluation", kwargs["deep_verify"]))
        assert kwargs["dimensions"].study_id == CLASS20_STUDY_ID
        assert kwargs["dimensions"].sample_count == 16_000
        assert kwargs["handoff_verifier"] == class_evaluation._verify_handoff
        return "loaded"

    monkeypatch.setattr(class_handoff, "_verify_class_handoff", routed_verify)
    monkeypatch.setattr(class_evaluation, "_load_class_handoff", routed_load)
    assert class_handoff.verify_class_handoff(root) == root
    assert class_evaluation.load_class_handoff(root) == "loaded"
    assert calls == [("handoff", True), ("evaluation", True)]


def test_profile20_handoff_binds_exact_deep_validated_post_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots = []
    receipts = []
    for block in range(1, 11):
        root = tmp_path / f"block-{block:02d}"
        root.mkdir()
        (root / "evidence.sha256").write_text(f"block {block}\n", encoding="utf-8")
        roots.append(root)
        receipts.append(SimpleNamespace(root=root, experiment={
            "completed_at": "2020-01-01T00:00:00+00:00"
        }))
    foundation_sha, readiness_sha, pre_sha = "a" * 64, "b" * 64, "c" * 64
    launches = tuple(f"{block:064x}" for block in range(1, 11))
    context = class_handoff._SourceContext(
        receipts=tuple(receipts), class_ids=(), workload_records=(),
        class_manifest_sha256="d" * 64, cohort_sha256="e" * 64,
        cohort_payload_sha256="f" * 64, cohort_assembly_sha256="0" * 64,
        cohort_assembly_payload_sha256="1" * 64,
        class_study_launch_sha256s=launches, class_study_successor_sha256=None,
        class_study_foundation_sha256=foundation_sha,
        class_study_readiness_sha256=readiness_sha,
        class_study_historical_pre_snapshot_sha256=pre_sha,
        defense_runtime_inputs={}, chaff_qualification_set="set",
        chaff_qualification_set_manifest_sha256="2" * 64,
        execution_source={"image_digest": "pinned"},
    )
    snapshot = tmp_path / "post.json"
    snapshot.write_text("post\n", encoding="utf-8")
    post = {
        "phase": "post-formal", "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": class_handoff._CLASS20_OVERLAY_SHA256,
        "source": context.execution_source,
        "readiness": {"sha256": readiness_sha},
        "pre_formal_snapshot": {"sha256": pre_sha},
        "formal_results": [
            {
                "root": str(root.resolve()),
                "evidence_sha256": sha256_file(root / "evidence.sha256"),
                "class_study_launch_sha256": launch,
                "class_study_foundation_sha256": foundation_sha,
                "class_study_readiness_sha256": readiness_sha,
                "class_study_historical_pre_snapshot_sha256": pre_sha,
            }
            for root, launch in zip(roots, launches, strict=True)
        ],
        "sha256": sha256_file(snapshot), "payload_sha256": "3" * 64,
        "recorded_at": "2020-01-02T00:00:00+00:00",
    }
    calls: list[tuple[Path, str]] = []

    def deep_validator(path: Path, *, expected_phase: str):
        calls.append((path, expected_phase))
        return post

    monkeypatch.setattr(class_attestation, "validate_class_historical_snapshot", deep_validator)
    dimensions = class_handoff._dimensions_for_study(CLASS20_STUDY_ID)
    bound = class_handoff._bind_historical_post_snapshot(
        context, snapshot, dimensions=dimensions, validator=None
    )
    assert calls == [(snapshot.resolve(), "post-formal")]
    assert bound.class_study_historical_post_snapshot_sha256 == sha256_file(snapshot)
    post["formal_results"][0]["class_study_launch_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="differs from the exact source blocks"):
        class_handoff._bind_historical_post_snapshot(
            context, snapshot, dimensions=dimensions, validator=None
        )
