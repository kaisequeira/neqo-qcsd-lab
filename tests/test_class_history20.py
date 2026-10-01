"""Zero-credit tests for the prospective 20-site snapshot boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import class_attestation as att, class_history20 as history
from qcsd_lab.class_layout import class_study_layout
from qcsd_lab.class_study import (
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    bind_receipt,
    canonical_json_bytes,
    load_class20_profile_contract,
)
from qcsd_lab.util import sha256_file


def _digest(character: str = "a") -> str:
    return character * 64


def _file(path: Path, content: bytes = b"evidence") -> Path:
    path.write_bytes(content)
    return path


def _runtime(modes: tuple[str, ...]) -> dict[str, dict]:
    kinds = {
        "undefended": "none", "static": "static", "front": "front",
        "tamaraw": "tamaraw", "traffic-morphing": "traffic_morphing",
        "wtf-pad": "wtf_pad", "walkie-talkie": "walkie_talkie",
        "buflo": "buflo", "cs-buflo": "cs_buflo",
    }
    result = {}
    for mode in modes:
        if mode in att._PARAMETER_MODES:
            result[mode] = {
                "identity_type": "hash-bound-parameter-artifact",
                "runtime_kind": kinds[mode],
                "parameters_sha256": _digest("b"),
                "provenance_sha256": _digest("c"),
                "input_policy": "sealed-class-study-fitting-v1",
            }
        elif mode == "static":
            result[mode] = {
                "identity_type": "hash-bound-static-schedule",
                "runtime_kind": "static",
                "schedule_sha256": _digest("d"),
                "mode": "chaff-and-shape",
            }
        else:
            result[mode] = {
                "identity_type": (
                    "source-bound-no-defense" if mode == "undefended"
                    else "source-bound-built-in"
                ),
                "runtime_kind": kinds[mode],
            }
    return result


def _readiness(tmp_path: Path) -> tuple[Path, dict]:
    profile = load_class20_profile_contract()
    profile_path = class_study_layout(profile=profile).study_config_root / "study.json"
    readiness_path = tmp_path / "readiness.json"
    readiness_path.write_bytes(canonical_json_bytes(bind_receipt(
        {
            "artifact_type": att.READINESS_RECEIPT_TYPE,
            "study_id": profile.study_id,
            "attestation_schema_version": att.CLASS20_READINESS_SCHEMA_VERSION,
        },
        receipt_type=att.READINESS_RECEIPT_TYPE,
    )))
    certification_root = tmp_path / "certification"
    certification_root.mkdir()
    _file(certification_root / "evidence.sha256")
    final_cohort = _file(tmp_path / "cohort.json")
    final_assembly = _file(tmp_path / "assembly.json")
    source = {"test_source": "pinned"}
    runtime = _runtime(COMPATIBILITY_MODES)
    return readiness_path, {
        "study_id": profile.study_id,
        "attestation_schema_version": att.CLASS20_READINESS_SCHEMA_VERSION,
        "study_profile_sha256": sha256_file(profile_path),
        "source": source,
        "build_execution_identity": {"test_build": "same"},
        "evidence": {
            "certification_result": att._result_binding(certification_root),
            "foundation": {"sha256": _digest("e")},
            "final_cohort": att._file_binding(final_cohort),
            "final_cohort_assembly": att._file_binding(final_assembly),
        },
        "summary": {
            "certification_defense_runtime_inputs": runtime,
            "certification_defense_parameter_sha256": {
                mode: _digest("b") for mode in att._PARAMETER_MODES
            },
            "final_qualification_set_manifest_sha256": _digest("f"),
            "formal_expected_samples": profile.formal_sample_count,
        },
    }


def _mock_common(monkeypatch: pytest.MonkeyPatch, readiness: dict) -> None:
    monkeypatch.setattr(att, "validate_class_readiness_attestation", lambda _path: readiness)
    monkeypatch.setattr(att, "_validate_immutable_source", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(history, "source_metadata", lambda: readiness["source"])
    monkeypatch.setattr(history, "validate_historical_corpus_guard", lambda **_kwargs: {"guard": "fixed"})
    monkeypatch.setattr(
        history, "verify_result",
        lambda _root: SimpleNamespace(experiment={"completed_at": "2020-01-01T00:00:00+00:00"}),
    )


def test_v2_pre_snapshot_create_validate_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness_path, readiness = _readiness(tmp_path)
    _mock_common(monkeypatch, readiness)
    output = att.create_class_historical_snapshot(
        tmp_path / "pre.json", phase="pre-formal", readiness_attestation=readiness_path
    )
    record = att.validate_class_historical_snapshot(output, expected_phase="pre-formal")
    assert record["snapshot_schema_version"] == 2
    assert record["study_id"] == readiness["study_id"]
    assert record["study_profile_sha256"] == readiness["study_profile_sha256"]
    assert record["formal_results"] == []
    assert record["pre_formal_snapshot"] is None


def test_v2_pre_snapshot_rejects_other_profile_and_early_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness_path, readiness = _readiness(tmp_path)
    _mock_common(monkeypatch, readiness)
    readiness["study_profile_sha256"] = _digest("0")
    with pytest.raises(ValueError, match="another readiness, source, or profile"):
        history._snapshot_value(
            phase="pre-formal", readiness_attestation=readiness_path,
            formal_result_roots=(), pre_snapshot=None,
            recorded_at="2020-01-02T00:00:00+00:00",
        )
    readiness["study_profile_sha256"] = sha256_file(
        class_study_layout(profile=load_class20_profile_contract()).study_config_root / "study.json"
    )
    with pytest.raises(ValueError, match="predates certification"):
        history._snapshot_value(
            phase="pre-formal", readiness_attestation=readiness_path,
            formal_result_roots=(), pre_snapshot=None,
            recorded_at="2019-12-31T00:00:00+00:00",
        )


@pytest.mark.parametrize(
    ("study_id", "schema"),
    [("classifier-multiorigin20-v1", 1), ("classifier-multiorigin100-v1", 2)],
)
def test_snapshot_dispatch_rejects_cross_profile_schema(
    tmp_path: Path, study_id: str, schema: int
) -> None:
    payload = {
        "snapshot_schema_version": schema,
        "artifact_type": history.RECEIPT_TYPE,
        "study_id": study_id,
    }
    receipt = tmp_path / "snapshot.json"
    receipt.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=history.RECEIPT_TYPE)))
    with pytest.raises(ValueError, match="study identity and schema must match exactly"):
        att.validate_class_historical_snapshot(receipt)


def test_v2_post_requires_ten_exact_formal_bindings() -> None:
    payload = {key: None for key in history._SNAPSHOT_KEYS}
    payload.update({
        "snapshot_schema_version": 2,
        "artifact_type": history.RECEIPT_TYPE,
        "study_id": "classifier-multiorigin20-v1",
        "phase": "post-formal",
        "formal_results": [],
    })
    with pytest.raises(ValueError, match="ten formal blocks"):
        history._validate_envelope(payload)
    payload["formal_results"] = [{"root": "/tmp/unsealed"}] * 10
    with pytest.raises(ValueError, match="binding shape"):
        history._validate_envelope(payload)


def test_v2_formal_results_bind_exact_lineage_and_chronology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = load_class20_profile_contract()
    readiness_path, readiness = _readiness(tmp_path)
    pre_path = _file(tmp_path / "pre.json")
    roots = []
    for block in range(1, profile.formal_block_count + 1):
        root = tmp_path / f"formal-{block:02d}"
        root.mkdir()
        _file(root / "evidence.sha256", bytes([block]))
        roots.append(root)
    formal_runtime = _runtime(FORMAL_MODES)
    state = {"wrong_block": None, "overlap": False}

    def profile_result(root: Path, *, expected_block: int, **_kwargs: object) -> dict:
        record = {
            "valid": True,
            "class_study_id": profile.study_id,
            "class_study_profile_sha256": readiness["study_profile_sha256"],
            "class_study_foundation_sha256": readiness["evidence"]["foundation"]["sha256"],
            "class_study_readiness_sha256": sha256_file(readiness_path),
            "class_study_historical_pre_snapshot_sha256": sha256_file(pre_path),
            "cohort_sha256": readiness["evidence"]["final_cohort"]["sha256"],
            "cohort_assembly_sha256": readiness["evidence"]["final_cohort_assembly"]["sha256"],
            "samples": 1600, "accepted": 1600,
            "defense_runtime_inputs": formal_runtime,
            "defense_parameter_sha256": {mode: _digest("b") for mode in att._PARAMETER_MODES},
            "chaff_qualification_set_manifest_sha256": _digest("f"),
            "chaff_qualification_set": class_study_layout(profile=profile).final_qualification_set_root.name,
            "class_study_launch_sha256": f"{expected_block:064x}",
            "evidence_sha256": sha256_file(root / "evidence.sha256"),
        }
        if expected_block == state["wrong_block"]:
            record["class_study_readiness_sha256"] = _digest("0")
        return record

    def sealed(root: Path) -> SimpleNamespace:
        block = int(root.name[-2:])
        started = datetime(2020, 1, 2, tzinfo=UTC) + timedelta(hours=block * 2)
        if state["overlap"] and block == 2:
            started -= timedelta(hours=2)
        return SimpleNamespace(experiment={
            "source": readiness["source"],
            "started_at": started.isoformat(),
            "completed_at": (started + timedelta(hours=1)).isoformat(),
        })

    monkeypatch.setattr(history, "verify_profile_class_result", profile_result)
    monkeypatch.setattr(history, "verify_result", sealed)
    monkeypatch.setattr(history, "_validate_result_environment", lambda *_args: {"test": "environment"})
    monkeypatch.setattr(att, "_one_class_build_execution_identity", lambda *_args, **_kwargs: readiness["build_execution_identity"])
    kwargs = {
        "roots": roots, "profile": profile, "readiness": readiness,
        "readiness_path": readiness_path,
        "pre": {"recorded_at": "2020-01-02T00:00:00+00:00"},
        "pre_path": pre_path,
        "recorded_at": datetime(2020, 1, 4, tzinfo=UTC),
    }
    bindings = history._validate_formal_results(**kwargs)
    assert len(bindings) == 10
    assert set(bindings[0]) == history._FORMAL_BINDING_KEYS
    state["wrong_block"] = 3
    with pytest.raises(ValueError, match="differs from readiness"):
        history._validate_formal_results(**kwargs)
    state["wrong_block"] = None
    state["overlap"] = True
    with pytest.raises(ValueError, match="chronological and non-overlapping"):
        history._validate_formal_results(**kwargs)
