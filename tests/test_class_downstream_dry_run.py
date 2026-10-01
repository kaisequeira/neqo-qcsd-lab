"""Zero-credit rehearsal of the class-study consumers after acquisition.

The synthetic acquisition and fitting traces are deliberately local fixtures.
The compact handoff source is a separate fixture because constructing 16,000
raw packet captures would turn this contract test into a second acquisition.
Neither fixture is a launch, qualification, certification, or capture receipt.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

import qcsd_lab.class_pipeline as pipeline
from qcsd_lab import orchestrator
from qcsd_lab.class_campaigns import campaign_documents
from qcsd_lab.class_cohort import build_evidenced_cohort
from qcsd_lab.class_fitting import (
    PILOT_STAGE,
    QualificationContext,
    create_numeric_fitting_bundle,
    finalize_fitting_bundle,
    verify_class_fitting_bundle,
    verify_numeric_fitting_bundle,
)
from qcsd_lab.class_handoff import _DIMENSIONS
from qcsd_lab.class_study import STUDY_ID, canonical_json_bytes, validate_study_receipt
from tests.test_class_cohort import _synthetic_acquisition_prefix_loaded_pilot_campaign
from tests.test_class_fitting import (
    _bind_numeric_publication_source,
    _fitters,
    _inputs,
    _qualification_context,
)


def test_synthetic_acquisition_reaches_final_campaign_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Carry one admitted cohort identity through fitting and capture planning."""

    pilot, admission, cohort_path, assembly_path, workload_root = (
        _synthetic_acquisition_prefix_loaded_pilot_campaign(tmp_path, monkeypatch)
    )
    pilot_plan = orchestrator.plan_campaign(pilot)
    assert len(pilot_plan) == 480
    assert {workload.origin_count for workload in pilot.workloads} == {2}

    cohort_receipt = json.loads(cohort_path.read_text(encoding="utf-8"))
    assembly_receipt = json.loads(assembly_path.read_text(encoding="utf-8"))
    inputs = replace(
        _inputs(PILOT_STAGE, cohort_receipt),
        cohort_assembly_receipt=assembly_receipt,
        cohort_assembly_receipt_sha256=admission.assembly_sha256,
    )
    artifacts_root = tmp_path / "diagnostic-numeric"
    artifacts_root.mkdir()
    numeric_root = create_numeric_fitting_bundle(
        tmp_path / "diagnostic-pilot-fitting-result",
        artifacts_root=artifacts_root,
        stage=PILOT_STAGE,
        fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
        fitters=_fitters(),
    )
    numeric = verify_numeric_fitting_bundle(
        numeric_root,
        fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
        fitters=_fitters(),
    )
    assert numeric.provenance["cohort"]["receipt_sha256"] == admission.cohort_sha256
    assert numeric.provenance["cohort"]["assembly_receipt_sha256"] == admission.assembly_sha256
    assert numeric.provenance["fitting_contract"]["samples_consumed"] == len(pilot_plan)

    source_result_root, _calls = _bind_numeric_publication_source(
        monkeypatch, tmp_path, inputs
    )
    context = _qualification_context(
        tmp_path,
        stage=PILOT_STAGE,
        workload_ids=inputs.workload_ids,
    )
    final_artifacts = tmp_path / "diagnostic-finalized-pilot"
    final_artifacts.mkdir()
    finalized_root = finalize_fitting_bundle(
        numeric_root,
        source_result_root=source_result_root,
        qualification_manifest_path=context.sidecar_root / "_qualification-set.json",
        qualification_context=context,
        artifacts_root=final_artifacts,
    )
    finalized = verify_class_fitting_bundle(
        finalized_root, qualification_context=context
    )

    compatibility_root = tmp_path / "diagnostic-compatibility"
    frozen = compatibility_root / "inputs"
    shutil.copytree(finalized_root, frozen / "defense-parameters/class-study")
    shutil.copytree(context.workload_root, frozen / "workloads")
    shutil.copytree(context.sidecar_root, frozen / "chaff-qualifications")
    shutil.copytree(context.prefix_spec_root, frozen / "chaff-prefix-specs")

    def verify_frozen(root: Path, *, qualification_context: QualificationContext):
        assert root == frozen / "defense-parameters/class-study"
        return verify_class_fitting_bundle(
            root,
            qualification_context=QualificationContext(
                workload_root=qualification_context.workload_root,
                sidecar_root=qualification_context.sidecar_root,
                prefix_spec_root=qualification_context.prefix_spec_root,
                loader=context.loader,
                prefix_validator=context.prefix_validator,
                preparation_validator=context.preparation_validator,
                require_current_implementation=False,
                qualification_authority=context.qualification_authority,
            ),
        )

    monkeypatch.setattr(pipeline, "verify_class_fitting_bundle", verify_frozen)
    monkeypatch.setattr(
        pipeline,
        "verify_numeric_fitting_bundle",
        lambda root, *, source_result_root: verify_numeric_fitting_bundle(
            root,
            source_result_root=source_result_root,
            fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
            fitters=_fitters(),
        ),
    )
    compatibility = {
        "name": "classifier-multiorigin100-v1-pilot-compatibility-1080-1200",
        "root": str(compatibility_root),
        "evidence_sha256": "8" * 64,
        "experiment_sha256": "9" * 64,
        "accepted": 1_080,
        "unique_class_mode_pairs": 1_080,
        "class_study_foundation_sha256": context.qualification_authority[
            "foundation_attestation"
        ]["sha256"],
        "defense_parameter_sha256": {
            "traffic-morphing": finalized.artifact_hashes["traffic_morphing"],
            "wtf-pad": finalized.artifact_hashes["wtf_pad"],
            "walkie-talkie": finalized.artifact_hashes["walkie_talkie"],
        },
    }
    monkeypatch.setattr(
        pipeline, "verify_class_study_result", lambda *_args, **_kwargs: compatibility
    )
    selection_input = pipeline.build_final_selection_input(
        admission,
        pilot_fitting_result_root=source_result_root,
        pilot_numeric_bundle_root=numeric_root,
        pilot_compatibility_result_root=compatibility_root,
        qualification_authority=context.qualification_authority,
    )
    pairs = pipeline.validate_final_selection_input(
        selection_input,
        pilot_admission=admission,
        pilot_fitting_result_root=source_result_root,
        pilot_numeric_bundle_root=numeric_root,
        pilot_compatibility_result_root=compatibility_root,
        qualification_authority=context.qualification_authority,
    )
    assert len(pairs) == 60
    assert len(selection_input["payload"]["selected_final_perfect_matching"]) == 50
    selection_path = tmp_path / "diagnostic-final-selection.json"
    selection_path.write_bytes(canonical_json_bytes(selection_input))

    final_cohort, final_assembly = build_evidenced_cohort(
        tmp_path / "candidates.json",
        stability_root=tmp_path / "artifacts" / f"{STUDY_ID}-stability-v130",
        workload_root=workload_root,
        acquisition_completion_path=(
            tmp_path / "artifacts" / f"{STUDY_ID}-acquisition-v130" / "completion.json"
        ),
        feasible_pairs=pairs,
        final_selection_receipt_path=selection_path,
    )
    final_ids = tuple(
        candidate.candidate_id for candidate in validate_study_receipt(final_cohort).final
    )
    assert len(final_ids) == 100
    study_root = cohort_path.parent
    final_cohort_path = study_root / "classifier-multiorigin100-v1-cohort.json"
    final_assembly_path = study_root / "classifier-multiorigin100-v1-cohort-assembly.json"
    final_cohort_path.write_bytes(canonical_json_bytes(final_cohort))
    final_assembly_path.write_bytes(canonical_json_bytes(final_assembly))

    pilot_documents = campaign_documents(
        cohort_path,
        cohort_assembly_receipt=assembly_path,
        cohort_reference="../class-study/v1/" + cohort_path.name,
        cohort_assembly_reference="../class-study/v1/" + assembly_path.name,
    )
    final_documents = campaign_documents(
        final_cohort_path,
        cohort_assembly_receipt=final_assembly_path,
        cohort_reference="../class-study/v1/" + final_cohort_path.name,
        cohort_assembly_reference="../class-study/v1/" + final_assembly_path.name,
    )
    documents = {
        **{
            name: document
            for name, document in pilot_documents.items()
            if document["evidence_role"] in {"pilot-fitting", "pilot-compatibility"}
        },
        **{
            name: document
            for name, document in final_documents.items()
            if document["evidence_role"] not in {"pilot-fitting", "pilot-compatibility"}
        },
    }
    campaign_root = tmp_path / "config/classifier-multiorigin100-v1-campaigns"
    totals: Counter[str] = Counter()
    for filename, document in documents.items():
        path = campaign_root / filename
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        role = document["evidence_role"]
        planned = (
            sum(document["workloads"].values())
            * len(document["request_policies"])
            * len(document["defenses"])
        )
        if role in {"pilot-fitting", "authoritative-fitting", "canary"}:
            loaded = orchestrator.load_campaign(path)
            plan = orchestrator.plan_campaign(loaded)
            assert len(plan) == planned
            if role != "pilot-fitting":
                assert tuple(workload.id for workload in loaded.workloads) == final_ids
                assert {workload.origin_count for workload in loaded.workloads} == {2}
        else:
            # Defended roles intentionally remain unlaunchable without genuine
            # named qualification and fitted runtime artifacts.  Their canonical
            # documents and cardinality are validated by campaign_documents.
            with pytest.raises(ValueError, match="named qualification-set manifest"):
                orchestrator.load_campaign(path)
        totals[role] += planned
    assert totals == {
        "pilot-fitting": 480,
        "pilot-compatibility": 1_080,
        "authoritative-fitting": 2_000,
        "certification": 900,
        "canary": 1_000,
        "formal": 16_000,
    }
    assert _DIMENSIONS.sample_count == totals["formal"]
    assert _DIMENSIONS.class_count == len(final_ids)
    assert _DIMENSIONS.block_count == 10
