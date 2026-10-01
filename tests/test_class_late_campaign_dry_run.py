"""Zero-credit rehearsal of generated defended class-study campaign loading.

The prepared workloads, traces, qualification sidecars, and foundation are
synthetic.  Only the live qualification decoder and foundation attestation are
replaced by test doubles; campaign YAML, cohort binding, named-set manifest,
fitting-bundle verification, defense loading, and planning use production code.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from qcsd_lab import (
    chaff_qualification,
    class_attestation,
    class_fitting,
    orchestrator,
    parameters,
    util,
)
from qcsd_lab.class_campaigns import campaign_documents
from qcsd_lab.class_fitting import (
    AUTHORITATIVE_STAGE,
    create_numeric_fitting_bundle,
    finalize_fitting_bundle,
    verify_class_fitting_bundle,
)
from qcsd_lab.class_layout import (
    AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
    AUTHORITATIVE_COHORT_FILENAME,
    FINAL_QUALIFICATION_SET,
)
from qcsd_lab.class_study import canonical_json_bytes, validate_study_receipt
from qcsd_lab.util import sha256_file
from tests.test_class_campaign_execution import _complete_two_origin_workload
from tests.test_class_fitting import (
    _bind_numeric_publication_source,
    _cohort_assembly,
    _cohort_receipt,
    _fitters,
    _inputs,
    _named_set_bindings_digest,
    _qualification_authority,
    _qualification_context,
)


def _rehearsal_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, tuple[str, ...], dict[str, Any]]:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    monkeypatch.setattr(parameters, "LAB_ROOT", tmp_path)
    config = tmp_path / "config"
    study_root = config / "class-study/v1"
    workload_root = config / "workloads"
    campaigns = config / "classifier-multiorigin100-v1-campaigns"
    for root in (study_root, workload_root, campaigns):
        root.mkdir(parents=True)

    cohort = _cohort_receipt()
    final_ids = tuple(item.candidate_id for item in validate_study_receipt(cohort).final)
    workload_hashes: dict[str, str] = {}
    generated = tmp_path / "generated-workloads"
    generated.mkdir()
    for workload_id in final_ids:
        workload = _complete_two_origin_workload(
            generated, visits=2, workload_id=workload_id
        )
        path = workload_root / f"{workload_id}.json"
        path.write_bytes(workload.source_bytes)
        workload_hashes[workload_id] = sha256_file(path)
    cohort_path = study_root / AUTHORITATIVE_COHORT_FILENAME
    assembly_path = study_root / AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME
    cohort_path.write_bytes(canonical_json_bytes(cohort))
    assembly = _cohort_assembly(cohort, workload_hashes)
    assembly_path.write_bytes(canonical_json_bytes(assembly))
    documents = campaign_documents(
        cohort_path, cohort_assembly_receipt=assembly_path
    )
    for name, document in documents.items():
        (campaigns / name).write_text(
            yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
        )

    inputs = replace(
        _inputs(AUTHORITATIVE_STAGE, cohort),
        cohort_assembly_receipt=assembly,
        cohort_assembly_receipt_sha256=sha256_file(assembly_path),
    )
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    numeric = create_numeric_fitting_bundle(
        tmp_path / "synthetic-fitting-source",
        artifacts_root=artifacts,
        stage=AUTHORITATIVE_STAGE,
        fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
        fitters=_fitters(),
    )
    source_root, _calls = _bind_numeric_publication_source(monkeypatch, tmp_path, inputs)
    context = _qualification_context(
        tmp_path, stage=AUTHORITATIVE_STAGE, workload_ids=final_ids
    )
    set_root = config / "chaff-qualification-store/sets" / FINAL_QUALIFICATION_SET
    spec_root = config / "chaff-prefix-specs/sets" / FINAL_QUALIFICATION_SET
    shutil.copytree(context.sidecar_root, set_root)
    shutil.copytree(context.prefix_spec_root, spec_root)
    set_path = set_root / "_qualification-set.json"
    set_value = json.loads(set_path.read_text(encoding="utf-8"))
    for entry in set_value["workloads"]:
        entry["workload_manifest"]["sha256"] = workload_hashes[entry["workload_id"]]
    set_value["bindings_sha256"] = _named_set_bindings_digest(set_value)
    set_path.write_bytes(canonical_json_bytes(set_value))
    context = replace(
        context,
        workload_root=workload_root,
        sidecar_root=set_root,
        prefix_spec_root=spec_root,
    )
    finalized = finalize_fitting_bundle(
        numeric,
        source_result_root=source_root,
        qualification_manifest_path=set_path,
        qualification_context=context,
        artifacts_root=artifacts,
    )
    assert verify_class_fitting_bundle(
        finalized, qualification_context=context
    ).provenance["runtime_authorized"] is True

    fixed = config / "defense-params"
    fixed.mkdir()
    checked_in = Path(__file__).parents[1] / "config/defense-params"
    for name in (
        "static-control-1200.csv",
        "buflo-live.json",
        "buflo-live.json.provenance.json",
        "cs-buflo-ctsp-live.json",
        "cs-buflo-ctsp-live.json.provenance.json",
    ):
        shutil.copy2(checked_in / name, fixed / name)

    authority = _qualification_authority()
    foundation_path = tmp_path / "synthetic-foundation.json"
    foundation_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv(orchestrator.CLASS_STUDY_FOUNDATION_ENV, str(foundation_path))

    def synthetic_foundation(
        path: Path, *, deep_code_gate: bool, runtime_role: str
    ) -> dict[str, Any]:
        assert path in {
            foundation_path,
            Path(authority["foundation_attestation"]["path"]),
        }
        assert deep_code_gate is True and runtime_role == "collection"
        return authority

    monkeypatch.setattr(
        class_attestation, "class_qualification_authority", synthetic_foundation
    )

    # The sidecars are synthetic.  Keep the real named-set, bundle, parameter,
    # campaign and planning validators; substitute only the unavailable live
    # qualification decoder and its matched prefix validator.
    monkeypatch.setattr(
        chaff_qualification,
        "validate_prefix_spec_for_qualification",
        lambda value, *, workload_id, application_manifest: value,
    )

    def synthetic_qualified(sidecar_path: Path, **kwargs: Any) -> SimpleNamespace:
        workload_id = kwargs["workload_id"]
        assert kwargs["require_current_implementation"] is True
        assert kwargs.get("expected_sidecar_schema_version", 3) == 3
        if kwargs.get("expected_qualification_authority") is not None:
            assert kwargs["expected_qualification_authority"] == authority
        prepared = json.loads(kwargs["base_manifest_path"].read_text(encoding="utf-8"))
        runtime = orchestrator.runtime_manifest(prepared)
        runtime["resources"][0]["content_length"] = 1_200
        runtime["resources"][0]["data_length"] = 1_200
        runtime.update(
            application_resource_id=0,
            selected_chaff_resource_id=1,
            qualified_parallel_chaff_streams=5,
            walkie_talkie_required_chaff_streams=1,
        )
        return SimpleNamespace(
            sidecar_sha256=sha256_file(sidecar_path),
            manifest_sha256=next(
                entry["runtime_manifest_sha256"]
                for entry in set_value["workloads"]
                if entry["workload_id"] == workload_id
            ),
            manifest=runtime,
        )

    monkeypatch.setattr(chaff_qualification, "load_qualified_chaff", synthetic_qualified)
    real_verify = verify_class_fitting_bundle

    def verify_synthetic_bundle(root: Path, *, qualification_context, **kwargs):
        return real_verify(
            root,
            qualification_context=replace(
                qualification_context,
                loader=context.loader,
                prefix_validator=context.prefix_validator,
                preparation_validator=context.preparation_validator,
                require_current_implementation=False,
            ),
            **kwargs,
        )

    monkeypatch.setattr(
        class_fitting, "verify_class_fitting_bundle", verify_synthetic_bundle
    )
    return campaigns, set_path, final_ids, authority


def test_generated_late_defended_campaigns_load_and_reject_wrong_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaigns, set_path, final_ids, authority = _rehearsal_inputs(
        tmp_path, monkeypatch
    )
    certification = campaigns / "classifier-multiorigin100-v1-certification-900-1200.yml"
    formal = campaigns / "classifier-multiorigin100-v1-formal-01-1200.yml"
    expected_modes = {
        "undefended",
        "front",
        "tamaraw",
        "traffic-morphing",
        "wtf-pad",
        "walkie-talkie",
        "buflo",
        "cs-buflo",
    }
    for path, count, modes in (
        (certification, 900, expected_modes | {"static"}),
        (formal, 1_600, expected_modes),
    ):
        loaded = orchestrator.load_campaign(
            path, expected_qualification_authority=authority
        )
        assert tuple(workload.id for workload in loaded.workloads) == final_ids
        assert {workload.origin_count for workload in loaded.workloads} == {2}
        assert {defense.name for defense in loaded.defenses} == modes
        assert {
            workload.qualification_set_manifest_sha256 for workload in loaded.workloads
        } == {sha256_file(set_path)}
        plan = orchestrator.plan_campaign(loaded)
        assert len(plan) == count
        assert len({sample["sample_id"] for sample in plan}) == count
        assert Counter(sample["defense"] for sample in plan) == Counter(
            {mode: count // len(modes) for mode in modes}
        )
        preflight = orchestrator.preflight_campaign(path)
        assert preflight["valid"] is True
        assert preflight["sample_count"] == count
        assert preflight["chaff_qualification_set_manifest_sha256"] == sha256_file(set_path)

    wrong_authority = {
        **authority,
        "prepare_image_digest": "sha256:" + "f" * 64,
    }
    with pytest.raises(ValueError, match="expected class qualification authority differs"):
        orchestrator.load_campaign(
            formal, expected_qualification_authority=wrong_authority
        )

    mutated = yaml.safe_load(formal.read_text(encoding="utf-8"))
    mutated["chaff_qualification_set"] = "classifier-multiorigin100-v1-wrong-full-v1"
    formal.write_text(yaml.safe_dump(mutated, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="named qualification-set manifest"):
        orchestrator.load_campaign(formal)
