"""Zero-credit v2 fitting-to-qualification rehearsal without live Neqo traffic.

The numeric fitter, schema-six prefix projector, named checkpoint, atomic set
publisher, and finalized bundle verifier are real.  Only the network-produced
qualification sidecar verifier is replaced with a synthetic boundary.  A pass
here cannot stand in for the twenty live chaff qualifications.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import class_fitting
from qcsd_lab.class_fitting import (
    AUTHORITATIVE_STAGE,
    QualificationContext,
    create_numeric_fitting_bundle,
    derive_schema_six_prefix_specs,
    finalize_fitting_bundle,
    validate_schema_six_prefix_spec,
    verify_class_fitting_bundle,
    verify_numeric_fitting_bundle,
)
from qcsd_lab.class_study import CLASS20_PROFILE, canonical_json_bytes
from qcsd_lab.class_acquisition import validate_class_study_preparation
from qcsd_lab.util import load_json, sha256_bytes, sha256_file
from tests.test_class_fitting import (
    _bind_numeric_publication_source,
    _fitters,
    _profile_final_inputs,
    _qualification_authority,
)
from tests.test_manifest import class_study_prepared_manifest


def test_v2_twenty_site_numeric_prefix_qualification_and_final_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _profile_final_inputs(tmp_path, monkeypatch)
    ids = inputs.workload_ids
    assert len(ids) == CLASS20_PROFILE.final_count == 20

    numeric_parent = tmp_path / "numeric-artifacts"
    numeric_parent.mkdir()
    numeric = create_numeric_fitting_bundle(
        tmp_path,
        artifacts_root=numeric_parent,
        stage=AUTHORITATIVE_STAGE,
        study_profile=CLASS20_PROFILE,
        fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
        fitters=_fitters(),
    )
    source_result_root, source_checks = _bind_numeric_publication_source(
        monkeypatch, tmp_path, inputs,
    )
    fitted = verify_numeric_fitting_bundle(
        numeric,
        source_result_root=source_result_root,
        fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
        fitters=_fitters(),
    )
    assert fitted.provenance["fitting_contract"]["samples_consumed"] == 400

    workload_root = tmp_path / "workloads"
    workload_root.mkdir()
    for workload_id in ids:
        manifest = class_study_prepared_manifest()
        headers = [
            ["accept", "text/html,application/xhtml+xml"],
            ["accept-encoding", "identity"],
            ["accept-language", "en-US,en;q=0.9"],
        ]
        for resource in manifest["resources"]:
            resource["known_valid"] = True
            resource["headers"] = headers
        manifest["preparation"]["expected_responses"][1]["bytes"] = 8_192
        validate_class_study_preparation(manifest, workload_id=workload_id)
        (workload_root / f"{workload_id}.json").write_bytes(canonical_json_bytes(manifest))

    prefix_parent = tmp_path / "prefix-artifacts"
    prefix_parent.mkdir()
    prefix_root = derive_schema_six_prefix_specs(
        numeric,
        source_result_root=source_result_root,
        workload_root=workload_root,
        artifacts_root=prefix_parent,
    )
    assert {path.stem for path in prefix_root.iterdir()} == set(ids)
    walkie_path = numeric / class_fitting.BUNDLE_FILES["walkie_talkie"]
    walkie = load_json(walkie_path)
    for workload_id in ids:
        spec = load_json(prefix_root / f"{workload_id}.json")
        assert spec["schema_version"] == 4
        validate_schema_six_prefix_spec(
            spec,
            workload_id=workload_id,
            walkie_talkie=walkie,
            source_walkie_talkie_artifact_sha256=sha256_file(walkie_path),
            application_manifest=load_json(workload_root / f"{workload_id}.json"),
        )

    authority = _qualification_authority()
    sidecar_root = tmp_path / "sidecars"
    sidecar_root.mkdir()
    publication_root = tmp_path / "sets"
    publication_root.mkdir()
    checkpoint = tmp_path / "qualification-checkpoint.json"
    set_name = f"{CLASS20_PROFILE.study_id}-final20-full-v1"
    qualification.initialize_named_qualification_checkpoint(
        checkpoint,
        ids,
        qualification_set=set_name,
        qualification_scope="full",
        workload_root=workload_root,
        prefix_spec_root=prefix_root,
        qualification_authority=authority,
    )
    assert qualification.pending_named_qualification_workloads(
        checkpoint,
        workload_root=workload_root,
        sidecar_root=sidecar_root,
        prefix_spec_root=prefix_root,
        expected_qualification_authority=authority,
    ) == ids
    with pytest.raises(ValueError, match="incomplete"):
        qualification.publish_named_qualification_set_from_checkpoint(
            checkpoint,
            workload_root=workload_root,
            sidecar_root=sidecar_root,
            publication_root=publication_root,
            prefix_spec_root=prefix_root,
            qualification_authority=authority,
        )

    def synthetic_sidecar_loader(sidecar_path: Path, **kwargs: object) -> SimpleNamespace:
        workload_id = kwargs["workload_id"]
        assert isinstance(workload_id, str)
        assert kwargs["expected_sidecar_schema_version"] == 3
        assert kwargs["expected_qualification_authority"] == authority
        assert kwargs["base_manifest_path"] == workload_root / f"{workload_id}.json"
        prefix_path = Path(kwargs["prefix_spec_path"])
        assert prefix_path.name == f"{workload_id}.json"
        sidecar = load_json(sidecar_path)
        assert sidecar["synthetic_only"] is True
        assert sidecar["workload_id"] == workload_id
        assert sidecar["qualification_authority"] == authority
        assert sidecar["qualification_authority_sha256"] == sha256_bytes(
            canonical_json_bytes(authority)
        )
        spec = load_json(prefix_path)
        assert spec["workload_id"] == workload_id
        required = spec["required_chaff_streams"]
        return SimpleNamespace(
            sidecar_sha256=sha256_file(sidecar_path),
            manifest_sha256=sha256_bytes(f"synthetic-runtime:{workload_id}".encode()),
            application_resource_id=spec["application_resource_id"],
            selected_chaff_resource_id=spec["selected_chaff_resource_id"],
            qualified_parallel_chaff_streams=max(5, required),
            walkie_talkie_required_chaff_streams=required,
        )

    monkeypatch.setattr(qualification, "load_qualified_chaff", synthetic_sidecar_loader)
    for workload_id in ids:
        sidecar = {
            "schema_version": 3,
            "workload_id": workload_id,
            "synthetic_only": True,
            "qualification_source": authority["prepare_source"],
            "qualification_image_digest": authority["prepare_image_digest"],
            "qualification_authority": authority,
            "qualification_authority_sha256": sha256_bytes(canonical_json_bytes(authority)),
        }
        (sidecar_root / f"{workload_id}.json").write_bytes(canonical_json_bytes(sidecar))

    qualification.record_named_qualification_checkpoint(
        checkpoint,
        ids[0],
        workload_root=workload_root,
        sidecar_root=sidecar_root,
        prefix_spec_root=prefix_root,
        expected_qualification_authority=authority,
    )
    reconciled = qualification.reconcile_named_qualification_checkpoint(
        checkpoint,
        workload_root=workload_root,
        sidecar_root=sidecar_root,
        prefix_spec_root=prefix_root,
        expected_qualification_authority=authority,
    )
    assert all(entry["status"] == "qualified" for entry in reconciled["workloads"])
    published = qualification.publish_named_qualification_set_from_checkpoint(
        checkpoint,
        workload_root=workload_root,
        sidecar_root=sidecar_root,
        publication_root=publication_root,
        prefix_spec_root=prefix_root,
        qualification_authority=authority,
    )
    published_prefixes = published.path / "_prefix-specs"
    assert published.workload_ids == ids
    assert {path.stem for path in published_prefixes.iterdir()} == set(ids)
    for workload_id in ids:
        assert (published_prefixes / f"{workload_id}.json").read_bytes() == (
            prefix_root / f"{workload_id}.json"
        ).read_bytes()
    qualification.load_named_qualification_set(
        published.manifest_path,
        workload_root=workload_root,
        prefix_spec_root=published_prefixes,
        expected_workload_ids=ids,
        expected_qualification_authority=authority,
    )

    context = QualificationContext(
        workload_root=workload_root,
        sidecar_root=published.path,
        prefix_spec_root=published_prefixes,
        loader=synthetic_sidecar_loader,
        prefix_validator=validate_schema_six_prefix_spec,
        preparation_validator=validate_class_study_preparation,
        qualification_authority=authority,
    )
    final_parent = tmp_path / "final-artifacts"
    final_parent.mkdir()
    final = finalize_fitting_bundle(
        numeric,
        source_result_root=source_result_root,
        qualification_manifest_path=published.manifest_path,
        qualification_context=context,
        artifacts_root=final_parent,
    )
    verified = verify_class_fitting_bundle(final, qualification_context=context)
    assert verified.stage == AUTHORITATIVE_STAGE
    assert verified.provenance["qualification_inputs"]["qualification_set"] == set_name
    assert len(verified.provenance["qualification_inputs"]["qualification_bindings"]) == 20
    assert source_checks

    first_published_spec = published_prefixes / f"{ids[0]}.json"
    first_published_spec.write_bytes(first_published_spec.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="prefix specification"):
        verify_class_fitting_bundle(final, qualification_context=context)
