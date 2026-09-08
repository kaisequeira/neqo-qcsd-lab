from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from qcsd_lab.class_build_admission import BuildAdmission, resolve_action_admission
from qcsd_lab.class_study import canonical_json_bytes, canonical_json_sha256
from qcsd_lab.util import sha256_file
from tests.test_cli import (
    _class_build_admission_fixture,
    _second_class_build_admission_fixture,
)

PILOT_QUALIFICATION_SET = "classifier-multiorigin100-v1-pilot120-full-v1"
AUTHORITATIVE_QUALIFICATION_SET = "classifier-multiorigin100-v1-final100-full-v1"


def _qualification_authority(fixture: object) -> dict[str, object]:
    admitted: BuildAdmission = fixture.admitted
    return {
        "schema_version": 2,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": {
            "path": str(fixture.foundation),
            "sha256": sha256_file(fixture.foundation),
            "payload_sha256": json.loads(fixture.foundation.read_bytes())["payload_sha256"],
        },
        "build_execution": {
            "path": str(fixture.build),
            "sha256": sha256_file(fixture.build),
        },
        "build_execution_identity": admitted.identity,
        "collection_source": admitted.source,
        "prepare_source": {
            **dict(admitted.source),
            "image_digest": admitted.prepare_image,
        },
        "prepare_image_digest": admitted.prepare_image,
    }


def _source_result(source: Mapping[str, object], stage: str) -> dict[str, object]:
    campaign = (
        "classifier-multiorigin100-v1-pilot-fitting-1200"
        if stage == "pilot"
        else "classifier-multiorigin100-v1-authoritative-fitting-1200"
    )
    return {
        "campaign": campaign,
        "evidence_sha256": "1" * 64,
        "experiment_sha256": "2" * 64,
        "input_digest": "3" * 64,
        "campaign_sha256": "4" * 64,
        "source_fingerprints": dict(source),
    }


def _numeric_bundle(
    root: Path,
    name: str,
    *,
    source: Mapping[str, object],
    stage: str,
) -> Path:
    """Write the production numeric-provenance shape without invented authority."""

    bundle = root / "artifacts/classifier-multiorigin100-v1" / name
    bundle.mkdir(parents=True)
    bundle_name = (
        "classifier-multiorigin100-v1-pilot-fitting-numeric"
        if stage == "pilot"
        else "classifier-multiorigin100-v1-authoritative-fitting-numeric"
    )
    provenance = {
        "schema_version": 1,
        "artifact_type": "qcsd-class-study-numeric-fitting-bundle",
        "status": "numeric-staging-only",
        "runtime_authorized": False,
        "stage": stage,
        "bundle_name": bundle_name,
        "qcsd_profile": "research-1200",
        "udp_payload_ceiling": 1_200,
        "parameter_input_policy": None,
        "source_result": _source_result(source, stage),
        "cohort": {
            "role": stage,
            "receipt_sha256": "5" * 64,
            "receipt": {},
            "assembly_receipt_sha256": "6" * 64,
            "assembly_receipt": {},
        },
        "fitting_contract": {},
        "sample_contributions": {},
        "nontraining_inputs": {
            "qualification_bytes_excluded": True,
            "prefix_specification_bytes_excluded": True,
            "status": "pending",
        },
        "algorithms": {},
        "artifacts": {},
    }
    assert "qualification_authority" not in repr(provenance)
    (bundle / "numeric-provenance.json").write_bytes(canonical_json_bytes(provenance))
    return bundle


def _final_bundle(
    root: Path,
    name: str,
    *,
    source: Mapping[str, object],
    authority: Mapping[str, object],
) -> Path:
    """Write the source and qualification carriers used by final provenance."""

    bundle = root / "artifacts/classifier-multiorigin100-v1" / name
    bundle.mkdir(parents=True)
    provenance = {
        "schema_version": 2,
        "artifact_type": "qcsd-class-study-research-defense-bundle",
        "status": "authoritative-fitted-artifact",
        "runtime_authorized": True,
        "stage": "authoritative",
        "bundle_name": "classifier-multiorigin100-v1-authoritative-fitting",
        "qcsd_profile": "research-1200",
        "udp_payload_ceiling": 1_200,
        "parameter_input_policy": "sealed-class-study-fitting-v1",
        "source_result": _source_result(source, "authoritative"),
        "cohort": {},
        "fitting_contract": {},
        "sample_contributions": {},
        "qualification_inputs": {
            "qualification_authority": dict(authority),
        },
        "algorithms": {},
        "artifacts": {},
    }
    (bundle / "provenance.json").write_bytes(canonical_json_bytes(provenance))
    return bundle


def _action_options(action: str, fixture: object) -> dict[str, object]:
    if action in {"cohort", "campaigns"}:
        return {
            "foundation": str(fixture.foundation),
            "acquisition_completion": str(fixture.acquisition_completion),
        }
    if action == "prefix-specs":
        return {"capture_result": str(fixture.resume)}
    if action == "qualify-prefix":
        return {
            "foundation": str(fixture.foundation),
            "capture_result": str(fixture.resume),
        }
    if action == "finalize-fitting":
        return {
            "foundation": str(fixture.foundation),
            "results": [str(fixture.resume)],
        }
    if action == "readiness":
        return {
            "build": str(fixture.build),
            "foundation": str(fixture.foundation),
        }
    raise AssertionError(f"unhandled test action: {action}")


@pytest.mark.parametrize(
    ("action", "numeric_stage"),
    (
        ("cohort", "pilot"),
        ("campaigns", "pilot"),
        ("prefix-specs", "authoritative"),
        ("qualify-prefix", "authoritative"),
        ("finalize-fitting", "authoritative"),
        ("readiness", "pilot"),
    ),
)
def test_actions_accept_numeric_source_projection_from_the_same_build(
    tmp_path: Path,
    action: str,
    numeric_stage: str,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    numeric = _numeric_bundle(
        fixture.root,
        f"matching-source-{action}",
        source=fixture.admitted.source,
        stage=numeric_stage,
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action=action,
            stage="authoritative",
            cohort_version=62 if action == "readiness" else None,
            options={
                **_action_options(action, fixture),
                "numeric_bundle": [str(numeric)],
            },
            build_loader=fixture.load,
        )
        == fixture.admitted
    )


@pytest.mark.parametrize(
    ("action", "numeric_stage"),
    (
        ("cohort", "pilot"),
        ("campaigns", "pilot"),
        ("prefix-specs", "authoritative"),
        ("qualify-prefix", "authoritative"),
        ("finalize-fitting", "authoritative"),
        ("readiness", "pilot"),
    ),
)
def test_actions_reject_numeric_source_projection_from_another_build(
    tmp_path: Path,
    action: str,
    numeric_stage: str,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    numeric = _numeric_bundle(
        first.root,
        f"cross-build-source-{action}",
        source=second.admitted.source,
        stage=numeric_stage,
    )

    with pytest.raises(ValueError, match=r"source fingerprints|source.*differ"):
        resolve_action_admission(
            first.root,
            action=action,
            stage="authoritative",
            cohort_version=62 if action == "readiness" else None,
            options={
                **_action_options(action, first),
                "numeric_bundle": [str(numeric)],
            },
            build_loader=second.load,
        )


def test_verify_numeric_target_requires_capture_result_build_authority(
    tmp_path: Path,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    numeric = _numeric_bundle(
        fixture.root,
        "verify-source-without-result",
        source=fixture.admitted.source,
        stage="authoritative",
    )

    with pytest.raises(ValueError, match="capture-result"):
        resolve_action_admission(
            fixture.root,
            action="verify",
            stage="authoritative",
            options={"target": str(numeric)},
            build_loader=fixture.load,
        )


def test_verify_numeric_target_accepts_matching_capture_result_source(
    tmp_path: Path,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    numeric = _numeric_bundle(
        fixture.root,
        "verify-matching-source",
        source=fixture.admitted.source,
        stage="authoritative",
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action="verify",
            stage="authoritative",
            options={
                "target": str(numeric),
                "capture_result": str(fixture.resume),
            },
            build_loader=fixture.load,
        )
        == fixture.admitted
    )


def test_verify_numeric_target_rejects_mismatched_capture_result_source(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    numeric = _numeric_bundle(
        first.root,
        "verify-cross-build-source",
        source=second.admitted.source,
        stage="authoritative",
    )

    with pytest.raises(ValueError, match=r"source fingerprints|source.*differ"):
        resolve_action_admission(
            first.root,
            action="verify",
            stage="authoritative",
            options={
                "target": str(numeric),
                "capture_result": str(first.resume),
            },
            build_loader=second.load,
        )


def test_final_provenance_rejects_qualification_and_source_from_different_builds(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    final = _final_bundle(
        first.root,
        "cross-build-final",
        source=second.admitted.source,
        authority=_qualification_authority(first),
    )

    with pytest.raises(ValueError, match=r"source fingerprints|source.*differ"):
        resolve_action_admission(
            first.root,
            action="verify",
            options={
                "target": str(final),
                "capture_result": str(first.resume),
            },
            build_loader=second.load,
        )


def test_final_provenance_accepts_matching_qualification_source_and_capture_result(
    tmp_path: Path,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    final = _final_bundle(
        fixture.root,
        "matching-final",
        source=fixture.admitted.source,
        authority=_qualification_authority(fixture),
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action="verify",
            options={
                "target": str(final),
                "capture_result": str(fixture.resume),
            },
            build_loader=fixture.load,
        )
        == fixture.admitted
    )


def _write_qualification_set(
    publication_root: Path,
    name: str,
    authority: Mapping[str, object],
) -> Path:
    target = publication_root / name
    target.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 3,
        "artifact_type": "qcsd-named-chaff-qualification-set",
        "qualification_set": name,
        "qualification_scope": "full",
        "qualification_sidecar_schema_version": 3,
        "workload_count": 0,
        "workload_ids": [],
        "workloads": [],
        "bindings_sha256": "7" * 64,
        "qualification_authority": dict(authority),
        "qualification_authority_sha256": canonical_json_sha256(authority),
    }
    (target / "_qualification-set.json").write_bytes(canonical_json_bytes(manifest))
    return target


def _qualify_prefix_admission(
    fixture: object,
    *,
    stage: str,
    publication_root: Path,
    build_loader: object,
) -> BuildAdmission | None:
    return resolve_action_admission(
        fixture.root,
        action="qualify-prefix",
        stage=stage,
        options={
            "foundation": str(fixture.foundation),
            "capture_result": str(fixture.resume),
            "qualification_publication_root": str(publication_root),
        },
        build_loader=build_loader,
    )


def test_pilot_qualification_admits_only_pilot_target_not_authoritative_sibling(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    publication = first.root / "config/chaff-qualification-store/sets"
    publication.mkdir(parents=True)
    _write_qualification_set(
        publication,
        PILOT_QUALIFICATION_SET,
        _qualification_authority(first),
    )
    _write_qualification_set(
        publication,
        AUTHORITATIVE_QUALIFICATION_SET,
        second.qualification_authority,
    )

    assert (
        _qualify_prefix_admission(
            first,
            stage="pilot",
            publication_root=publication,
            build_loader=second.load,
        )
        == first.admitted
    )


def test_authoritative_qualification_admits_only_final_target_not_pilot_sibling(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    publication = first.root / "config/chaff-qualification-store/sets"
    publication.mkdir(parents=True)
    _write_qualification_set(
        publication,
        PILOT_QUALIFICATION_SET,
        second.qualification_authority,
    )
    _write_qualification_set(
        publication,
        AUTHORITATIVE_QUALIFICATION_SET,
        _qualification_authority(first),
    )

    assert (
        _qualify_prefix_admission(
            first,
            stage="authoritative",
            publication_root=publication,
            build_loader=second.load,
        )
        == first.admitted
    )


@pytest.mark.parametrize("stage", ("pilot", "authoritative"))
def test_qualification_target_may_be_absent_before_create_only_publication(
    tmp_path: Path,
    stage: str,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    publication = fixture.root / "config/chaff-qualification-store/sets"
    publication.mkdir(parents=True)

    assert (
        _qualify_prefix_admission(
            fixture,
            stage=stage,
            publication_root=publication,
            build_loader=fixture.load,
        )
        == fixture.admitted
    )


def test_unrelated_published_qualification_sibling_is_ignored(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    publication = first.root / "config/chaff-qualification-store/sets"
    publication.mkdir(parents=True)
    _write_qualification_set(
        publication,
        "unrelated-study-final-full-v9",
        second.qualification_authority,
    )

    assert (
        _qualify_prefix_admission(
            first,
            stage="pilot",
            publication_root=publication,
            build_loader=second.load,
        )
        == first.admitted
    )
