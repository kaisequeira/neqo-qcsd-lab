from __future__ import annotations

import copy
import shutil
from pathlib import Path

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab.util import load_json, sha256_file

ROOT = Path(__file__).resolve().parents[1]
WORKLOAD_ROOT = ROOT / "config/workloads"
RESPONSE_SIDECAR_ROOT = (
    ROOT / "config/chaff-response-qualification-store/sets/classifier-multiorigin5-v2"
)
FULL_SIDECAR_ROOT = ROOT / "config/chaff-qualification-store/v2"
PREFIX_SPEC_ROOT = ROOT / "config/chaff-prefix-specs/v2"
RESPONSE_IDS = (
    "rfc9114-text-r2",
    "hyper-basic-client-r3",
    "getbootstrap-home-r4",
)
FULL_IDS = ("getbootstrap-home-r3", "bootstrap-introduction-r3")


def test_named_response_manifest_accepts_arbitrary_ordered_cohort_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def network() -> object:
        raise AssertionError("metadata construction must not acquire traffic")

    monkeypatch.setattr(qualification, "_qualification_execution_context", network)
    requested = tuple(reversed(RESPONSE_IDS))
    manifest = qualification.build_named_qualification_set_manifest(
        requested,
        qualification_set="classifier-multiorigin100-v1",
        qualification_scope="response-only",
        workload_root=WORKLOAD_ROOT,
        sidecar_root=RESPONSE_SIDECAR_ROOT,
        require_current_implementation=False,
    )

    assert manifest["schema_version"] == 1
    assert manifest["workload_count"] == 3
    assert manifest["workload_ids"] == list(requested)
    assert [entry["index"] for entry in manifest["workloads"]] == [0, 1, 2]
    assert [entry["workload_id"] for entry in manifest["workloads"]] == list(requested)
    assert all(entry["prefix_pack_spec"] is None for entry in manifest["workloads"])
    assert (
        qualification.validate_named_qualification_set_manifest(
            manifest,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=RESPONSE_SIDECAR_ROOT,
            expected_qualification_set="classifier-multiorigin100-v1",
            expected_qualification_scope="response-only",
            expected_workload_ids=requested,
            require_current_implementation=False,
        )
        == manifest
    )

    tampered = copy.deepcopy(manifest)
    tampered["workloads"][0]["qualification_sidecar"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="workload binding"):
        qualification.validate_named_qualification_set_manifest(
            tampered,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=RESPONSE_SIDECAR_ROOT,
            require_current_implementation=False,
        )


def test_named_full_manifest_binds_prefix_specs_and_full_sidecars() -> None:
    manifest = qualification.build_named_qualification_set_manifest(
        FULL_IDS,
        qualification_set="classifier-multiorigin100-full-v1",
        qualification_scope="full",
        workload_root=WORKLOAD_ROOT,
        sidecar_root=FULL_SIDECAR_ROOT,
        prefix_spec_root=PREFIX_SPEC_ROOT,
        require_current_implementation=False,
    )

    assert manifest["workload_ids"] == list(FULL_IDS)
    assert all(entry["prefix_pack_spec"] is not None for entry in manifest["workloads"])
    assert (
        qualification.validate_named_qualification_set_manifest(
            manifest,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=FULL_SIDECAR_ROOT,
            prefix_spec_root=PREFIX_SPEC_ROOT,
            expected_workload_ids=FULL_IDS,
            require_current_implementation=False,
        )
        == manifest
    )

    with pytest.raises(ValueError, match="prefix-spec root"):
        qualification.validate_named_qualification_set_manifest(
            manifest,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=FULL_SIDECAR_ROOT,
            require_current_implementation=False,
        )


def test_named_manifest_schema_two_binds_expected_qualification_authority() -> None:
    sidecar = load_json(FULL_SIDECAR_ROOT / f"{FULL_IDS[0]}.json")
    authority = {
        "schema_version": 1,
        "artifact_type": "fixture-authority",
        "prepare_source": sidecar["qualification_source"],
        "prepare_image_digest": sidecar["qualification_image_digest"],
    }
    manifest = qualification.build_named_qualification_set_manifest(
        FULL_IDS,
        qualification_set="classifier-multiorigin100-authority-v1",
        qualification_scope="full",
        workload_root=WORKLOAD_ROOT,
        sidecar_root=FULL_SIDECAR_ROOT,
        prefix_spec_root=PREFIX_SPEC_ROOT,
        require_current_implementation=False,
        qualification_authority=authority,
    )
    assert manifest["schema_version"] == 2
    assert manifest["qualification_authority"] == authority
    assert qualification.validate_named_qualification_set_manifest(
        manifest,
        workload_root=WORKLOAD_ROOT,
        sidecar_root=FULL_SIDECAR_ROOT,
        prefix_spec_root=PREFIX_SPEC_ROOT,
        require_current_implementation=False,
        expected_qualification_authority=authority,
    ) == manifest
    with pytest.raises(ValueError, match="expected build"):
        qualification.validate_named_qualification_set_manifest(
            manifest,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=FULL_SIDECAR_ROOT,
            prefix_spec_root=PREFIX_SPEC_ROOT,
            require_current_implementation=False,
            expected_qualification_authority={**authority, "prepare_image_digest": "other"},
        )


def test_named_full_publication_atomically_carries_its_prefix_specs(tmp_path: Path) -> None:
    publications = tmp_path / "sets"
    publications.mkdir()

    output = qualification.publish_named_qualification_set(
        FULL_IDS,
        qualification_set="classifier-multiorigin100-full-v1",
        qualification_scope="full",
        workload_root=WORKLOAD_ROOT,
        sidecar_root=FULL_SIDECAR_ROOT,
        publication_root=publications,
        prefix_spec_root=PREFIX_SPEC_ROOT,
        require_current_implementation=False,
    )

    published_specs = output.path / qualification.NAMED_QUALIFICATION_PREFIX_DIRECTORY
    assert sorted(path.name for path in published_specs.iterdir()) == [
        f"{workload_id}.json" for workload_id in sorted(FULL_IDS)
    ]
    for workload_id in FULL_IDS:
        assert (published_specs / f"{workload_id}.json").read_bytes() == (
            PREFIX_SPEC_ROOT / f"{workload_id}.json"
        ).read_bytes()
    assert (
        qualification.load_named_qualification_set(
            output.manifest_path,
            workload_root=WORKLOAD_ROOT,
            prefix_spec_root=published_specs,
            expected_workload_ids=FULL_IDS,
            require_current_implementation=False,
        )
        == output
    )


@pytest.mark.parametrize("workload_ids", [(), ("one", "one"), ("Mixed",)])
def test_named_contract_rejects_empty_duplicate_or_invalid_cohorts(
    tmp_path: Path, workload_ids: tuple[str, ...]
) -> None:
    with pytest.raises(ValueError, match="workload"):
        qualification.initialize_named_qualification_checkpoint(
            tmp_path / "checkpoint.json",
            workload_ids,
            qualification_set="cohort-v1",
            qualification_scope="response-only",
            workload_root=WORKLOAD_ROOT,
        )
    assert not (tmp_path / "checkpoint.json").exists()


def test_checkpoint_recovers_per_class_outputs_and_publishes_create_only(
    tmp_path: Path,
) -> None:
    checkpoint_path = tmp_path / "checkpoint.json"
    sidecars = tmp_path / "sidecars"
    publications = tmp_path / "sets"
    sidecars.mkdir()
    publications.mkdir()
    qualification.initialize_named_qualification_checkpoint(
        checkpoint_path,
        RESPONSE_IDS,
        qualification_set="classifier-multiorigin100-v1",
        qualification_scope="response-only",
        workload_root=WORKLOAD_ROOT,
    )
    with pytest.raises(FileExistsError, match="create-only"):
        qualification.initialize_named_qualification_checkpoint(
            checkpoint_path,
            RESPONSE_IDS,
            qualification_set="classifier-multiorigin100-v1",
            qualification_scope="response-only",
            workload_root=WORKLOAD_ROOT,
        )
    assert (
        qualification.pending_named_qualification_workloads(
            checkpoint_path,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=sidecars,
            require_current_implementation=False,
        )
        == RESPONSE_IDS
    )

    recovered_id = RESPONSE_IDS[1]
    shutil.copyfile(
        RESPONSE_SIDECAR_ROOT / f"{recovered_id}.json",
        sidecars / f"{recovered_id}.json",
    )
    checkpoint = qualification.reconcile_named_qualification_checkpoint(
        checkpoint_path,
        workload_root=WORKLOAD_ROOT,
        sidecar_root=sidecars,
        require_current_implementation=False,
    )
    assert [entry["status"] for entry in checkpoint["workloads"]] == [
        "pending",
        "qualified",
        "pending",
    ]

    for workload_id in (RESPONSE_IDS[0], RESPONSE_IDS[2]):
        shutil.copyfile(
            RESPONSE_SIDECAR_ROOT / f"{workload_id}.json",
            sidecars / f"{workload_id}.json",
        )
        qualification.record_named_qualification_checkpoint(
            checkpoint_path,
            workload_id,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=sidecars,
            require_current_implementation=False,
        )
    checkpoint_sha256 = sha256_file(checkpoint_path)
    qualification.record_named_qualification_checkpoint(
        checkpoint_path,
        recovered_id,
        workload_root=WORKLOAD_ROOT,
        sidecar_root=sidecars,
        require_current_implementation=False,
    )
    assert sha256_file(checkpoint_path) == checkpoint_sha256
    assert (
        qualification.pending_named_qualification_workloads(
            checkpoint_path,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=sidecars,
            require_current_implementation=False,
        )
        == ()
    )
    response_sidecar = load_json(RESPONSE_SIDECAR_ROOT / f"{RESPONSE_IDS[0]}.json")
    authority = {
        "schema_version": 1,
        "artifact_type": "fixture-authority",
        "prepare_source": response_sidecar["qualification_source"],
        "prepare_image_digest": response_sidecar["qualification_image_digest"],
    }

    output = qualification.publish_named_qualification_set_from_checkpoint(
        checkpoint_path,
        workload_root=WORKLOAD_ROOT,
        sidecar_root=sidecars,
        publication_root=publications,
        require_current_implementation=False,
        qualification_authority=authority,
    )
    assert output.workload_ids == RESPONSE_IDS
    assert sorted(path.name for path in output.path.iterdir()) == sorted(
        [qualification.NAMED_QUALIFICATION_SET_MANIFEST]
        + [f"{workload_id}.json" for workload_id in RESPONSE_IDS]
    )
    assert (
        qualification.load_named_qualification_set(
            output.manifest_path,
            workload_root=WORKLOAD_ROOT,
            expected_workload_ids=RESPONSE_IDS,
            require_current_implementation=False,
            expected_qualification_authority=authority,
        )
        == output
    )
    with pytest.raises(FileExistsError, match="create-only"):
        qualification.publish_named_qualification_set_from_checkpoint(
            checkpoint_path,
            workload_root=WORKLOAD_ROOT,
            sidecar_root=sidecars,
            publication_root=publications,
            require_current_implementation=False,
            qualification_authority=authority,
        )


def test_incomplete_checkpoint_cannot_publish_and_input_drift_is_detected(
    tmp_path: Path,
) -> None:
    workloads = tmp_path / "workloads"
    sidecars = tmp_path / "sidecars"
    publications = tmp_path / "sets"
    workloads.mkdir()
    sidecars.mkdir()
    publications.mkdir()
    workload_id = RESPONSE_IDS[0]
    shutil.copyfile(WORKLOAD_ROOT / f"{workload_id}.json", workloads / f"{workload_id}.json")
    checkpoint_path = tmp_path / "checkpoint.json"
    qualification.initialize_named_qualification_checkpoint(
        checkpoint_path,
        (workload_id,),
        qualification_set="single-class-v1",
        qualification_scope="response-only",
        workload_root=workloads,
    )
    with pytest.raises(ValueError, match="incomplete"):
        qualification.publish_named_qualification_set_from_checkpoint(
            checkpoint_path,
            workload_root=workloads,
            sidecar_root=sidecars,
            publication_root=publications,
            require_current_implementation=False,
        )

    with (workloads / f"{workload_id}.json").open("ab") as output:
        output.write(b"\n")
    with pytest.raises(ValueError, match="input binding"):
        qualification.load_named_qualification_checkpoint(
            checkpoint_path,
            workload_root=workloads,
            sidecar_root=sidecars,
            require_current_implementation=False,
        )


def test_class_study_prefix_specs_dispatch_without_legacy_reframing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def class_validator(value: object, **kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        assert isinstance(value, dict)
        return value

    from qcsd_lab import class_fitting

    monkeypatch.setattr(
        class_fitting,
        "validate_schema_six_prefix_spec_shape",
        class_validator,
    )
    value = {
        "artifact_type": "qcsd-class-study-walkie-talkie-prefix-pack-spec",
        "numeric_profile_derivation": (
            "schema-six-runtime-bursts-verbatim-no-additional-sender-framing"
        ),
    }
    manifest = {"resources": []}
    assert qualification.validate_prefix_spec_for_qualification(
        value,
        workload_id="class-one",
        application_manifest=manifest,
    ) == value
    assert observed == {
        "workload_id": "class-one",
        "application_manifest": manifest,
    }
