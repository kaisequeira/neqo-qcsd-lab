"""Synthetic public-stage routing for the separately registered 20-site profile."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import class_public20 as public
from qcsd_lab.class_study import (
    CLASS20_PROFILE, CLASS20_STUDY_ID, FORMAL_MODES,
    _CLASS20_OVERLAY_SHA256, bind_receipt, canonical_json_bytes,
)
from qcsd_lab.util import sha256_file


def _file(path: Path, content: bytes = b"evidence\n") -> Path:
    path.write_bytes(content)
    return path


def _handoff_dataset(path: Path, *, profile_sha256: str = _CLASS20_OVERLAY_SHA256) -> Path:
    path.mkdir()
    (path / "dataset.json").write_bytes(canonical_json_bytes({
        "schema_version": public.PROFILE_SCHEMA_VERSION,
        "artifact_type": public.PROFILE_ARTIFACT_TYPE,
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": profile_sha256,
        "sample_count": CLASS20_PROFILE.formal_sample_count,
        "class_count": CLASS20_PROFILE.final_count,
        "modes": list(FORMAL_MODES),
    }))
    return path


def _evaluation_receipt(path: Path) -> Path:
    return _file(path, canonical_json_bytes(bind_receipt({
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
    }, receipt_type=public.class_evaluation.EVALUATION_RECEIPT_TYPE)))


def _export_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    readiness_path = _file(tmp_path / "readiness.json")
    pre_path = _file(tmp_path / "pre.json")
    post_path = _file(tmp_path / "post.json")
    cohort_path = _file(tmp_path / "cohort.json")
    assembly_path = _file(tmp_path / "assembly.json")
    canaries = tuple((tmp_path / f"canary-{block:02d}") for block in range(1, 11))
    formals = tuple((tmp_path / f"formal-{block:02d}") for block in range(1, 11))
    for root in (*canaries, *formals):
        root.mkdir()
    source = {"immutable": "synthetic"}
    runtime = {mode: {"mode": mode} for mode in public.COMPATIBILITY_MODES}
    parameters = {mode: "a" * 64 for mode in public.att._PARAMETER_MODES}
    readiness = {
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "attestation_schema_version": public.att.CLASS20_READINESS_SCHEMA_VERSION,
        "source": source,
        "build_execution_identity": "synthetic-build",
        "evidence": {
            "final_cohort": public.att._file_binding(cohort_path),
            "final_cohort_assembly": public.att._file_binding(assembly_path),
            "foundation": {"sha256": "b" * 64},
        },
        "summary": {
            "canary_expected_samples": 200,
            "formal_expected_samples": 16_000,
            "certification_defense_runtime_inputs": runtime,
            "certification_defense_parameter_sha256": parameters,
            "final_qualification_set_manifest_sha256": "c" * 64,
        },
    }
    pre = {
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "snapshot_schema_version": public.att.CLASS20_HISTORICAL_SNAPSHOT_SCHEMA_VERSION,
        "source": source,
        "readiness": public.att._file_binding(readiness_path),
        "historical_corpus_guard_sha256": "d" * 64,
        "recorded_at": "2026-10-02T00:00:00+00:00",
    }
    post = {
        **pre,
        "pre_formal_snapshot": public.att._file_binding(pre_path),
        "recorded_at": "2026-10-02T01:00:00+00:00",
        "formal_results": [],
    }
    lineage = {
        "class_study_id": CLASS20_STUDY_ID,
        "class_study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "class_study_foundation_sha256": "b" * 64,
        "class_study_readiness_sha256": sha256_file(readiness_path),
        "class_study_historical_pre_snapshot_sha256": sha256_file(pre_path),
        "cohort_sha256": sha256_file(cohort_path),
        "cohort_assembly_sha256": sha256_file(assembly_path),
    }
    records = {}
    experiments = {}
    first = datetime(2026, 10, 2, tzinfo=UTC)
    for block, (canary, formal) in enumerate(zip(canaries, formals, strict=True), start=1):
        for role, root in (("canary", canary), ("formal", formal)):
            ordinal = (block - 1) * 2 + (role == "formal")
            modes = ("undefended",) if role == "canary" else FORMAL_MODES
            planned = 20 if role == "canary" else 1_600
            record = {
                "valid": True, "root": str(root), "evidence_role": role,
                "block": block, "samples": planned, "accepted": planned,
                **lineage,
                "evidence_sha256": f"{ordinal + 1:064x}",
                "class_study_launch_sha256": f"{ordinal + 101:064x}",
                "defense_runtime_inputs": {mode: runtime[mode] for mode in modes},
                "defense_parameter_sha256": (
                    {} if role == "canary" else {mode: parameters[mode] for mode in FORMAL_MODES if mode in parameters}
                ),
                "chaff_qualification_set_manifest_sha256": (
                    None if role == "canary" else "c" * 64
                ),
            }
            records[root] = record
            started = first + timedelta(minutes=ordinal + 1)
            experiments[root] = {
                "source": source,
                "started_at": started.isoformat(),
                "completed_at": (started + timedelta(seconds=30)).isoformat(),
            }
            if role == "formal":
                post["formal_results"].append({key: record[key] for key in public._FORMAL_SNAPSHOT_KEYS})
    monkeypatch.setattr(public, "source_metadata", lambda: source)
    monkeypatch.setattr(public.att, "_validate_immutable_source", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(public.att, "validate_class_readiness_attestation", lambda _path: readiness)
    monkeypatch.setattr(
        public.att, "validate_class_historical_snapshot",
        lambda _path, *, expected_phase: pre if expected_phase == "pre-formal" else post,
    )
    monkeypatch.setattr(public, "load_validated_profile_cohort", lambda *_args, **_kwargs: ((), tuple(range(20))))
    monkeypatch.setattr(public.att, "_validated_runtime_inputs", lambda value, **_kwargs: value)
    monkeypatch.setattr(public, "verify_profile_class_result", lambda root, **_kwargs: records[root])
    monkeypatch.setattr(public, "verify_result", lambda root: SimpleNamespace(experiment=experiments[root]))
    monkeypatch.setattr(public.att, "_validate_result_environment", lambda *_args: {"build": "synthetic-build"})
    monkeypatch.setattr(
        public.att, "_one_class_build_execution_identity",
        lambda _values, **_kwargs: "synthetic-build",
    )
    return {
        "final_cohort_receipt": cohort_path,
        "final_cohort_assembly": assembly_path,
        "readiness_attestation": readiness_path,
        "historical_pre_snapshot": pre_path,
        "historical_post_snapshot": post_path,
        "canary_result_roots": canaries,
        "formal_result_roots": formals,
        "records": records,
        "post": post,
    }


def test_v2_export_indexes_all_canaries_and_formals_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _export_fixture(tmp_path, monkeypatch)
    destination = tmp_path / "handoff"
    calls = []

    def export(roots, path, *, historical_post_snapshot):
        calls.append((tuple(roots), historical_post_snapshot))
        return _handoff_dataset(path)

    monkeypatch.setattr(public, "export_class_handoff", export)
    monkeypatch.setattr(public, "verify_class_handoff", lambda path, *, deep: Path(path))
    result = public.run_profile_public_stage(
        "export", destination=destination,
        **{key: value for key, value in inputs.items() if key not in {"records", "post"}},
    )
    assert result["state"] == "complete"
    assert result["details"]["canary_samples"] == 200
    assert result["details"]["samples"] == 16_000
    assert calls == [(inputs["formal_result_roots"], inputs["historical_post_snapshot"])]


def test_v2_export_rejects_bad_canary_and_post_binding_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _export_fixture(tmp_path, monkeypatch)
    destination = tmp_path / "handoff"
    monkeypatch.setattr(public, "export_class_handoff", lambda *_args, **_kwargs: pytest.fail("published invalid evidence"))
    canary = inputs["canary_result_roots"][0]
    inputs["records"][canary]["accepted"] = 19
    with pytest.raises(ValueError, match="canary block 01"):
        public.run_profile_public_stage(
            "export", destination=destination,
            **{key: value for key, value in inputs.items() if key not in {"records", "post"}},
        )
    assert not destination.exists()
    inputs["records"][canary]["accepted"] = 20
    inputs["post"]["formal_results"][0]["class_study_launch_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="ordered same-build"):
        public.run_profile_public_stage(
            "export", destination=destination,
            **{key: value for key, value in inputs.items() if key not in {"records", "post"}},
        )
    assert not destination.exists()


def test_v2_evaluate_rejects_other_profile_before_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _handoff_dataset(tmp_path / "handoff", profile_sha256="0" * 64)
    monkeypatch.setattr(public, "verify_class_handoff", lambda path, *, deep: Path(path))
    monkeypatch.setattr(
        public.class_evaluation, "write_class_evaluation_receipt",
        lambda *_args, **_kwargs: pytest.fail("wrote cross-profile evaluation"),
    )
    with pytest.raises(ValueError, match="another study profile"):
        public.run_profile_public_stage(
            "evaluate", destination=tmp_path / "evaluation.json",
            handoff=handoff, dlsvm_cache_directory=tmp_path / "cache",
        )


def test_v2_evaluate_verifies_published_receipt_with_full_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _handoff_dataset(tmp_path / "handoff")
    destination = tmp_path / "evaluation.json"
    seen = {}
    monkeypatch.setattr(public, "verify_class_handoff", lambda path, *, deep: Path(path))

    def write(path, *, handoff_root, dlsvm_cache_directory, deep_verify_handoff):
        seen["writer"] = (handoff_root, dlsvm_cache_directory, deep_verify_handoff)
        return _evaluation_receipt(path)

    def verify(path, *, handoff_root, deep_verify_handoff, replay_attacks):
        seen["verifier"] = (path, handoff_root, deep_verify_handoff, replay_attacks)
        return {
            "study_id": CLASS20_STUDY_ID,
            "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        }

    monkeypatch.setattr(public.class_evaluation, "write_class_evaluation_receipt", write)
    monkeypatch.setattr(public.class_evaluation, "verify_class_evaluation_receipt", verify)
    monkeypatch.setattr(public.att, "_require_evaluation_completion", lambda *_args, **_kwargs: None)
    result = public.run_profile_public_stage(
        "evaluate", destination=destination, handoff=handoff,
        dlsvm_cache_directory=tmp_path / "cache", deep=False,
    )
    assert result["state"] == "complete"
    assert seen["writer"] == (handoff, tmp_path / "cache", True)
    assert seen["verifier"] == (destination, handoff, True, True)


def test_v2_verify_rejects_cross_profile_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _file(tmp_path / "readiness.json", canonical_json_bytes(bind_receipt({
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": "0" * 64,
    }, receipt_type=public.att.READINESS_RECEIPT_TYPE)))
    monkeypatch.setattr(
        public.att, "validate_class_readiness_attestation",
        lambda *_args, **_kwargs: pytest.fail("replayed another profile"),
    )
    with pytest.raises(ValueError, match="another study profile"):
        public.run_profile_public_stage("verify", target=target)


@pytest.mark.parametrize(("receipt_type", "validator_name"), (
    (public.att.ACQUISITION_AUTHORITY_RECEIPT_TYPE, "validate_class_acquisition_authority"),
    (public.att.FOUNDATION_RECEIPT_TYPE, "validate_class_foundation_attestation"),
))
@pytest.mark.parametrize("deep", (True, False))
def test_v2_verify_reconstructs_profile_promotion_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    receipt_type: str, validator_name: str, deep: bool,
) -> None:
    target = _file(tmp_path / "promotion.json", canonical_json_bytes(bind_receipt({
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
    }, receipt_type=receipt_type)))
    expected = {
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "path": str(target),
    }
    calls = []

    def validate(path: Path, **kwargs):
        calls.append((path, kwargs))
        return expected

    monkeypatch.setattr(public.att, validator_name, validate)
    result = public.run_profile_public_stage("verify", target=target, deep=deep)
    assert result["state"] == "complete"
    assert result["details"] == expected
    assert calls == [(target, (
        {"runtime_role": "collection", "allow_historical": False}
        if receipt_type == public.att.ACQUISITION_AUTHORITY_RECEIPT_TYPE
        else {"deep_code_gate": deep, "runtime_role": "collection"}
    ))]


@pytest.mark.parametrize(("receipt_type", "validator_name"), (
    (public.att.ACQUISITION_AUTHORITY_RECEIPT_TYPE, "validate_class_acquisition_authority"),
    (public.att.FOUNDATION_RECEIPT_TYPE, "validate_class_foundation_attestation"),
))
def test_v2_verify_rejects_other_profile_promotion_before_reconstruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    receipt_type: str, validator_name: str,
) -> None:
    target = _file(tmp_path / "promotion.json", canonical_json_bytes(bind_receipt({
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": "0" * 64,
    }, receipt_type=receipt_type)))
    monkeypatch.setattr(
        public.att, validator_name,
        lambda *_args, **_kwargs: pytest.fail("replayed another profile"),
    )
    with pytest.raises(ValueError, match="another study profile"):
        public.run_profile_public_stage("verify", target=target)


@pytest.mark.parametrize(("receipt_type", "validator_name"), (
    (public.att.ACQUISITION_AUTHORITY_RECEIPT_TYPE, "validate_class_acquisition_authority"),
    (public.att.FOUNDATION_RECEIPT_TYPE, "validate_class_foundation_attestation"),
))
def test_v2_verify_rejects_tampered_promotion_before_reconstruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    receipt_type: str, validator_name: str,
) -> None:
    receipt = bind_receipt({
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
    }, receipt_type=receipt_type)
    receipt["payload"]["cohort_version"] = 999
    target = _file(tmp_path / "promotion.json", canonical_json_bytes(receipt))
    monkeypatch.setattr(
        public.att, validator_name,
        lambda *_args, **_kwargs: pytest.fail("replayed tampered receipt"),
    )
    with pytest.raises(ValueError, match="payload SHA-256"):
        public.run_profile_public_stage("verify", target=target)


def test_v2_comparison_template_and_final_attestation_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _handoff_dataset(tmp_path / "handoff")
    evaluation_path = _evaluation_receipt(tmp_path / "evaluation.json")
    monkeypatch.setattr(public, "verify_class_handoff", lambda path, *, deep: Path(path))
    monkeypatch.setattr(
        public.class_evaluation, "verify_class_evaluation_receipt",
        lambda *_args, **_kwargs: {
            "study_id": CLASS20_STUDY_ID,
            "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        },
    )
    monkeypatch.setattr(public.att, "_require_evaluation_completion", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        public.att, "build_class_comparison_review_template",
        lambda **_kwargs: {
            "study_id": CLASS20_STUDY_ID,
            "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
            "reviews": [],
        },
    )
    template = public.run_profile_public_stage(
        "comparison-review", handoff=handoff, evaluation_receipt=evaluation_path,
    )
    assert template["state"] == "ready"
    assert template["details"]["study_id"] == CLASS20_STUDY_ID

    inputs = [_file(tmp_path / f"evidence-{index}.json") for index in range(4)]
    destination = tmp_path / "attestation.json"
    seen = {}

    def create(path, **kwargs):
        seen.update(kwargs)
        return _file(path)

    monkeypatch.setattr(public.att, "create_class_validation_attestation", create)
    monkeypatch.setattr(
        public.att, "validate_class_validation_attestation",
        lambda _path, **_kwargs: {
            "study_id": CLASS20_STUDY_ID,
            "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        },
    )
    result = public.run_profile_public_stage(
        "attest", destination=destination,
        readiness_attestation=inputs[0], historical_pre_snapshot=inputs[1],
        historical_post_snapshot=inputs[2], handoff=handoff,
        evaluation_receipt=evaluation_path, comparison_review=inputs[3],
        canary_result_roots=(), formal_result_roots=(),
    )
    assert result["state"] == "complete"
    assert seen["_post_write_validate"] is False
