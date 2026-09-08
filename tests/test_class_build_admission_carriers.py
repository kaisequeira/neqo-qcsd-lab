from __future__ import annotations

import json
from pathlib import Path

import pytest

from qcsd_lab.class_build_admission import BuildAdmission, resolve_action_admission
from qcsd_lab.class_study import canonical_json_bytes
from qcsd_lab.util import sha256_file
from tests.test_cli import (
    _class_build_admission_fixture,
    _second_class_build_admission_fixture,
)


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


def _fitted_bundle(
    root: Path,
    name: str,
    authority: dict[str, object],
) -> Path:
    bundle = root / "artifacts/classifier-multiorigin100-v1" / name
    bundle.mkdir(parents=True)
    (bundle / "provenance.json").write_bytes(
        canonical_json_bytes(
            {
                "schema_version": 2,
                "artifact_type": "qcsd-class-study-research-defense-bundle",
                "status": "authoritative-fitted-artifact",
                "runtime_authorized": True,
                "stage": "authoritative",
                "qualification_context": {
                    "qualification_authority": authority,
                },
            }
        )
    )
    (bundle / "traffic-morphing.json").write_text("{}\n", encoding="utf-8")
    return bundle


def _published_qualification_set(
    root: Path,
    name: str,
    authority: dict[str, object],
) -> Path:
    publication = root / "config/chaff-qualification-store/sets"
    selected = publication / name
    selected.mkdir(parents=True)
    (selected / "_qualification-set.json").write_bytes(
        canonical_json_bytes(
            {
                "schema_version": 3,
                "artifact_type": "qcsd-named-chaff-qualification-set",
                "qualification_set": name,
                "qualification_scope": "full",
                "qualification_authority": authority,
            }
        )
    )
    return publication


def test_status_campaign_root_accepts_matching_fitted_bundle_authority(
    tmp_path: Path,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    bundle = _fitted_bundle(
        fixture.root,
        "matching-status-fitted",
        _qualification_authority(fixture),
    )
    campaign_root = fixture.root / "config/classifier-multiorigin100-v1/status-campaigns"
    campaign_root.mkdir(parents=True)
    parameter = "/lab/" + str((bundle / "traffic-morphing.json").relative_to(fixture.root))
    (campaign_root / "authoritative.yaml").write_text(
        "schema: 2\n"
        "evidence_role: authoritative-fitting\n"
        "defenses:\n"
        f"  - {{name: traffic-morphing, parameters: {parameter}}}\n",
        encoding="utf-8",
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action="status",
            options={
                "foundation": str(fixture.foundation),
                "campaign_root": str(campaign_root),
            },
            build_loader=fixture.load,
        )
        == fixture.admitted
    )


def test_status_campaign_root_does_not_open_runtime_fitted_bundle(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    bundle = _fitted_bundle(
        first.root,
        "conflicting-status-fitted",
        second.qualification_authority,
    )
    campaign_root = first.root / "config/classifier-multiorigin100-v1/status-campaigns"
    campaign_root.mkdir(parents=True)
    parameter = "/lab/" + str((bundle / "traffic-morphing.json").relative_to(first.root))
    (campaign_root / "authoritative.yaml").write_text(
        "schema: 2\n"
        "evidence_role: authoritative-fitting\n"
        "defenses:\n"
        f"  - {{name: traffic-morphing, parameters: {parameter}}}\n",
        encoding="utf-8",
    )

    assert (
        resolve_action_admission(
            first.root,
            action="status",
            options={
                "foundation": str(first.foundation),
                "campaign_root": str(campaign_root),
            },
            build_loader=second.load,
        )
        == first.admitted
    )


def test_qualify_prefix_accepts_matching_published_qualification_authority(
    tmp_path: Path,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    publication = _published_qualification_set(
        fixture.root,
        "classifier-multiorigin100-v1-final100-full-v1",
        _qualification_authority(fixture),
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action="qualify-prefix",
            stage="authoritative",
            options={
                "foundation": str(fixture.foundation),
                "qualification_publication_root": str(publication),
            },
            build_loader=fixture.load,
        )
        == fixture.admitted
    )


def test_qualify_prefix_rejects_cross_build_published_qualification_authority(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    publication = _published_qualification_set(
        first.root,
        "classifier-multiorigin100-v1-final100-full-v1",
        second.qualification_authority,
    )

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            first.root,
            action="qualify-prefix",
            stage="authoritative",
            options={
                "foundation": str(first.foundation),
                "qualification_publication_root": str(publication),
            },
            build_loader=second.load,
        )
