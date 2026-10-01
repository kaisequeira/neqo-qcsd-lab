"""Cheap, zero-credit checks for the prospective readiness receipt boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from qcsd_lab import class_attestation, class_readiness20
from qcsd_lab.class_layout import class_study_layout
from qcsd_lab.class_study import (
    bind_receipt,
    canonical_json_bytes,
    load_class20_profile_contract,
)
from qcsd_lab.util import sha256_file


def _payload() -> dict:
    profile = load_class20_profile_contract()
    profile_path = class_study_layout(profile=profile).study_config_root / "study.json"
    return {
        "attestation_schema_version": class_readiness20.SCHEMA_VERSION,
        "artifact_type": class_readiness20.RECEIPT_TYPE,
        "study_id": profile.study_id,
        "study_profile_sha256": sha256_file(profile_path),
        "cohort_version": 1,
        "implementation_status": class_readiness20.IMPLEMENTATION_STATUS,
        "promotion_authority": False,
        "implementation_scope": class_attestation.IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "source": {},
        "build_execution_identity": {},
        "evidence": {key: {} for key in class_readiness20._EVIDENCE_KEYS},
        "summary": {},
        "hard_gates": class_attestation._hard_gate_records(
            class_readiness20._GATES,
            {gate: ["a" * 64] for gate in class_readiness20._GATES},
        ),
        "all_readiness_gates_passed": True,
    }


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("attestation_schema_version", 3),
        ("study_id", "classifier-multiorigin100-v1"),
        ("promotion_authority", True),
        ("no_waivers", False),
        ("all_readiness_gates_passed", False),
    ],
)
def test_v2_readiness_envelope_rejects_v1_or_unearned_authority(
    field: str, replacement: object
) -> None:
    payload = _payload()
    class_readiness20._validate_envelope(payload)
    payload[field] = replacement
    with pytest.raises(ValueError, match="readiness envelope"):
        class_readiness20._validate_envelope(payload)


def test_v2_readiness_envelope_requires_exact_profile_and_gates() -> None:
    payload = _payload()
    payload["study_profile_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="readiness envelope"):
        class_readiness20._validate_envelope(payload)
    payload = _payload()
    payload["hard_gates"] = payload["hard_gates"][:-1]
    with pytest.raises(ValueError, match="hard-gate"):
        class_readiness20._validate_envelope(payload)


def test_rehashed_outer_receipt_cannot_replace_bound_foundation(
    tmp_path: Path,
) -> None:
    foundation = tmp_path / "foundation.json"
    foundation.write_text("original", encoding="utf-8")
    payload = _payload()
    payload["evidence"]["foundation"] = class_readiness20._file_binding(foundation)
    receipt = tmp_path / "readiness.json"
    receipt.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=class_readiness20.RECEIPT_TYPE))
    )
    foundation.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="foundation hash changed"):
        class_readiness20.validate_profile_readiness_attestation(receipt)


def test_final_assembly_must_bind_exact_acquisition_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = load_class20_profile_contract()
    monkeypatch.setattr(class_readiness20, "LAB_ROOT", tmp_path)
    catalogue = tmp_path / "config" / "catalogue.json"
    completion = tmp_path / "artifacts" / "runner" / "completion.json"
    stability = tmp_path / "artifacts" / "stability"
    workloads = tmp_path / "config" / "workloads"
    for file_path in (catalogue, completion):
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("{}", encoding="utf-8")
    stability.mkdir(parents=True)
    workloads.mkdir(parents=True)
    payload = {
        "study_id": profile.study_id,
        "candidate_catalogue": {
            "path": "config/catalogue.json", "sha256": sha256_file(catalogue),
        },
        "acquisition_completion": {
            "path": "artifacts/runner/completion.json", "sha256": sha256_file(completion),
        },
        "stability_root": "artifacts/stability",
        "workload_root": "config/workloads",
    }
    assembly = tmp_path / "assembly.json"

    def check() -> None:
        assembly.write_bytes(
            canonical_json_bytes(
                bind_receipt(payload, receipt_type="qcsd-class-study-profile-cohort-assembly")
            )
        )
        class_readiness20._require_acquisition_cohort_bindings(
            assembly,
            candidate_catalogue=catalogue,
            stability_root=stability,
            workload_root=workloads,
            acquisition_completion=completion,
            profile=profile,
        )

    check()
    payload["workload_root"] = "config/other-workloads"
    with pytest.raises(ValueError, match="workload_root"):
        check()
    payload["workload_root"] = "config/workloads"
    payload["acquisition_completion"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="acquisition_completion hash"):
        check()


def test_result_lineage_rejects_mixed_source_bound_studies() -> None:
    profile = load_class20_profile_contract()
    profile_path = class_study_layout(profile=profile).study_config_root / "study.json"
    record = {
        "class_study_id": profile.study_id,
        "class_study_profile_sha256": sha256_file(profile_path),
        "class_study_foundation_sha256": "a" * 64,
        "cohort_sha256": "b" * 64,
        "cohort_assembly_sha256": "c" * 64,
    }
    kwargs = {
        "profile": profile,
        "foundation_sha256": "a" * 64,
        "cohort_sha256": "b" * 64,
        "assembly_sha256": "c" * 64,
    }
    class_readiness20._require_result_lineage(record, **kwargs)
    record["cohort_assembly_sha256"] = "d" * 64
    with pytest.raises(ValueError, match="another profile, foundation, or cohort"):
        class_readiness20._require_result_lineage(record, **kwargs)


def test_readiness_create_dispatches_only_the_registered_20_site_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "readiness.json"
    seen: list[tuple[Path, dict]] = []

    def create_profile(path: Path, **inputs: object) -> Path:
        seen.append((path, inputs))
        return path

    monkeypatch.setattr(class_readiness20, "create_profile_readiness_attestation", create_profile)
    result = class_attestation.create_class_readiness_attestation(
        destination, study_id="classifier-multiorigin20-v1", cohort_version=17
    )
    assert result == destination
    assert seen == [(destination, {"cohort_version": 17})]
    with pytest.raises(ValueError, match="unsupported study identity"):
        class_attestation.create_class_readiness_attestation(
            destination, study_id="classifier-multiorigin19-v1"
        )


@pytest.mark.parametrize(
    ("study_id", "schema_version"),
    [
        ("classifier-multiorigin20-v1", 3),
        ("classifier-multiorigin20-v1", 2),
        ("classifier-multiorigin100-v1", 4),
    ],
)
def test_readiness_validation_rejects_cross_profile_schema_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    study_id: str, schema_version: int,
) -> None:
    path = tmp_path / "readiness.json"
    monkeypatch.setattr(
        class_attestation,
        "_load_bound_receipt",
        lambda *_args, **_kwargs: (
            path, {}, {"study_id": study_id, "attestation_schema_version": schema_version}
        ),
    )
    with pytest.raises(ValueError, match="study identity and schema must match exactly"):
        class_attestation.validate_class_readiness_attestation(path)


def test_readiness_validation_routes_schema_four_to_deep_v2_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "readiness.json"
    monkeypatch.setattr(
        class_attestation,
        "_load_bound_receipt",
        lambda *_args, **_kwargs: (
            path, {},
            {
                "study_id": "classifier-multiorigin20-v1",
                "attestation_schema_version": 4,
            },
        ),
    )
    seen: list[tuple[Path, bool]] = []

    def validate_profile(receipt: Path, *, deep_code_gate: bool) -> dict:
        seen.append((receipt, deep_code_gate))
        return {"study_id": "classifier-multiorigin20-v1", "valid": True}

    monkeypatch.setattr(class_readiness20, "validate_profile_readiness_attestation", validate_profile)
    value = class_attestation.validate_class_readiness_attestation(
        path, deep_code_gate=False, allow_historical=True
    )
    assert value["study_id"] == "classifier-multiorigin20-v1"
    assert seen == [(path, False)]
