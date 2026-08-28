from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import qcsd_lab.class_pipeline as class_pipeline
from qcsd_lab.class_cohort import ASSEMBLY_RECEIPT_TYPE
from qcsd_lab.class_fitting import (
    AUTHORITATIVE_PARAMETER_INPUT_POLICY,
    AUTHORITATIVE_QUALIFICATION_SET,
    AUTHORITATIVE_STAGE,
    BUNDLE_FILES,
    FINAL_ARTIFACT_TYPE,
    FINAL_FILES,
    NUMERIC_ARTIFACT_TYPE,
    NUMERIC_FILES,
    PILOT_PARAMETER_INPUT_POLICY,
    PILOT_QUALIFICATION_SET,
    PILOT_STAGE,
    ClassFitters,
    ClassFittingInputs,
    QualificationContext,
    _named_set_bindings_digest,
    build_schema_six_prefix_spec,
    class_fitting_artifact_type,
    class_research_parameter_record,
    create_numeric_fitting_bundle,
    finalize_fitting_bundle,
    require_successor_fitting_identity,
    validate_class_fitting_result,
    validate_schema_six_prefix_spec_shape,
    verify_class_fitting_bundle,
    verify_numeric_fitting_bundle,
)
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    build_study_receipt,
    canonical_json_bytes,
    validate_study_receipt,
)
from qcsd_lab.fitting_morphing import minimum_cost_derangement
from qcsd_lab.fitting_trace import FittingTrace
from qcsd_lab.fitting_walkie_talkie import minimum_weight_perfect_matching_from_costs
from qcsd_lab.util import sha256_bytes, sha256_file
from qcsd_lab.verification import VerifiedResult

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize(
    "source_result",
    (
        {"study_id": "classifier-multiorigin100-v1"},
        {
            "study_id": "classifier-multiorigin100-v2-other",
            "class_study_successor_sha256": "a" * 64,
        },
        {
            "study_id": "classifier-multiorigin100-v2-active",
            "class_study_successor_sha256": "b" * 64,
        },
    ),
    ids=("predecessor-v1", "other-v2", "same-id-different-restart"),
)
def test_successor_fitting_identity_requires_exact_study_and_restart(
    source_result: Mapping[str, Any],
) -> None:
    expected_study_id = "classifier-multiorigin100-v2-active"
    expected_restart_sha256 = "a" * 64

    with pytest.raises(
        ValueError,
        match="predecessor or another successor restart",
    ):
        require_successor_fitting_identity(
            {"source_result": source_result},
            expected_study_id=expected_study_id,
            expected_restart_sha256=expected_restart_sha256,
        )

    require_successor_fitting_identity(
        {
            "source_result": {
                "study_id": expected_study_id,
                "class_study_successor_sha256": expected_restart_sha256,
            }
        },
        expected_study_id=expected_study_id,
        expected_restart_sha256=expected_restart_sha256,
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _cohort_receipt() -> dict[str, Any]:
    candidates = []
    for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA):
        for offset in range(CANDIDATES_PER_STRATUM):
            candidates.append(
                ClassCandidate(
                    candidate_id=f"class-{stratum_index}-{offset:02d}",
                    domain=f"site-{stratum_index}-{offset:02d}.example.com",
                    rank=stratum.minimum_rank + offset,
                    eligible=True,
                )
            )
    return build_study_receipt(
        candidates,
        tranco_list_id="unit-test-list",
        tranco_list_sha256="a" * 64,
    )


def _cohort_assembly(
    receipt: Mapping[str, Any],
    workload_hashes: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    selection = validate_study_receipt(receipt)
    records = [
        {
            "candidate_id": candidate.candidate_id,
            "eligible": True,
            "selected_page": {
                "candidate_domain": candidate.domain,
                "registrable_domain": candidate.domain,
                "url": f"https://{candidate.domain}/",
                "source": "canonical-homepage",
                "ordinal": 0,
                "discovery_content_type": None,
            },
            "stability_receipt": {
                "path": f"{candidate.candidate_id}/page-00.json",
                "sha256": "c" * 64,
                "payload_sha256": "d" * 64,
            },
            "prepared_workload": {
                "path": f"{candidate.candidate_id}.json",
                "sha256": (workload_hashes or {}).get(candidate.candidate_id, "e" * 64),
            },
            "reasons": [],
        }
        for candidate in selection.candidates
    ]
    return bind_receipt(
        {
            "study_id": "classifier-multiorigin100-v1",
            "assembly_schema_version": 1,
            "eligibility_policy": {
                "source": "three-window-page-stability-receipt-only",
                "probe_windows": ["t+30s", "t+24h", "t+72h"],
                "page_order": (
                    "canonical-homepage-then-hash-ordered-safe-same-domain-links"
                ),
                "outcome_optimisation": False,
                "classifier_or_defence_measurements_used": False,
                "prepared_workload_sha256_required": True,
            },
            "candidate_catalogue": {
                "path": "candidates.json",
                "sha256": "a" * 64,
                "payload_sha256": "b" * 64,
            },
            "stability_root": "stability",
            "workload_root": "workloads",
            "candidates": records,
            "eligible_count": CANDIDATE_COUNT,
            "selected_evidence_count": 120,
            "cohort": {
                "receipt_type": receipt["receipt_type"],
                "payload_sha256": receipt["payload_sha256"],
                "canonical_file_sha256": sha256_bytes(canonical_json_bytes(receipt)),
            },
        },
        receipt_type=ASSEMBLY_RECEIPT_TYPE,
    )


def _source() -> dict[str, Any]:
    return {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": EMPTY_SHA256,
        "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": EMPTY_SHA256,
    }


def _qualification_authority() -> dict[str, Any]:
    collection = _source()
    prepare_image = "sha256:" + "4" * 64
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": {
            "path": "/evidence/foundation.json",
            "sha256": "5" * 64,
            "payload_sha256": "6" * 64,
        },
        "build_execution": {
            "path": "/evidence/build.json",
            "sha256": "7" * 64,
        },
        "build_execution_identity": {
            "cohort_version": 23,
            "sha256": "7" * 64,
            "collection_image": collection["image_digest"],
            "started_at": "2026-08-28T00:00:00+00:00",
            "finished_at": "2026-08-28T01:00:00+00:00",
        },
        "collection_source": collection,
        "prepare_source": {**collection, "image_digest": prepare_image},
        "prepare_image_digest": prepare_image,
    }


def _trace(workload_id: str, policy: str, visit: int) -> FittingTrace:
    sample_id = f"sample-{workload_id}-{policy}-{visit:03d}"
    return FittingTrace(
        sample_id=sample_id,
        workload_id=workload_id,
        request_policy=policy,
        visit=visit,
        root=Path("."),
        packets=(),
        observations=(),
        training_input_sha256=_digest(f"training:{sample_id}"),
        consumed_evidence=(("events.csv", _digest(f"events:{sample_id}")),),
    )


def _inputs(stage: str, receipt: Mapping[str, Any]) -> ClassFittingInputs:
    selection = validate_study_receipt(receipt)
    candidates = selection.pilot if stage == PILOT_STAGE else selection.final
    workload_ids = tuple(candidate.candidate_id for candidate in candidates)
    visits = 2 if stage == PILOT_STAGE else 10
    mappings = {
        policy: {
            workload_id: tuple(_trace(workload_id, policy, visit) for visit in range(visits))
            for workload_id in workload_ids
        }
        for policy in ("as-defined", "half-duplex")
    }
    campaign = (
        "classifier-multiorigin100-v1-pilot-fitting-1200"
        if stage == PILOT_STAGE
        else "classifier-multiorigin100-v1-authoritative-fitting-1200"
    )
    source_result = {
        "campaign": campaign,
        "evidence_sha256": _digest(f"evidence:{stage}"),
        "experiment_sha256": _digest(f"experiment:{stage}"),
        "input_digest": _digest(f"input:{stage}"),
        "campaign_sha256": _digest(f"campaign:{stage}"),
        "source_fingerprints": _source(),
    }
    verified = VerifiedResult(Path("."), {}, {}, {})
    assembly = _cohort_assembly(receipt)
    return ClassFittingInputs(
        verified=verified,
        stage=stage,
        workload_ids=workload_ids,
        visits_per_policy=visits,
        as_defined=mappings["as-defined"],
        half_duplex=mappings["half-duplex"],
        cohort_receipt=dict(receipt),
        cohort_receipt_sha256=sha256_bytes(canonical_json_bytes(receipt)),
        cohort_assembly_receipt=assembly,
        cohort_assembly_receipt_sha256=sha256_bytes(canonical_json_bytes(assembly)),
        source_result=source_result,
    )


def _fitters() -> ClassFitters:
    def traffic(
        traces: Mapping[str, Sequence[FittingTrace]],
    ) -> tuple[dict[str, object], dict[str, object]]:
        names = tuple(traces)
        next_target = {name: names[(index + 1) % len(names)] for index, name in enumerate(names)}
        candidates = [
            {
                "source": source,
                "target": target,
                "l1_cost": 0.0 if target == next_target[source] else 1.0,
                "estimated_added_bytes": 0.0,
            }
            for source in names
            for target in names
            if source != target
        ]
        selected = [
            {
                "source": source,
                "target": next_target[source],
                "l1_cost": 0.0,
                "estimated_added_bytes": 0.0,
            }
            for source in names
        ]
        return (
            {
                "schema_version": 2,
                "adaptation": "qcsd-client-only",
                "paper_equivalent": False,
                "profiles": [{"source": source, "target": next_target[source]} for source in names],
            },
            {"candidate_costs": candidates, "selected_mapping": selected},
        )

    def wtf(
        traces: Sequence[FittingTrace], *, fitted_from: str
    ) -> tuple[dict[str, object], dict[str, object]]:
        assert len(traces) in {240, 1000}
        return (
            {
                "schema_version": 2,
                "adaptation": "qcsd-client-only",
                "paper_equivalent": False,
                "fitted_from": fitted_from,
            },
            {"training_sample_count": len(traces)},
        )

    def walkie(
        traces: Mapping[str, Sequence[FittingTrace]],
    ) -> tuple[dict[str, object], dict[str, object]]:
        names = tuple(sorted(traces))
        zero_pairs = {(names[index], names[index + 1]) for index in range(0, len(names), 2)}
        candidates = [
            {
                "left": left,
                "right": right,
                "base_matching_cost_packets": 0 if (left, right) in zero_pairs else 1,
                "matching_cost_packets": 2 if (left, right) in zero_pairs else 3,
            }
            for index, left in enumerate(names)
            for right in names[index + 1 :]
        ]
        selected = [
            {
                "real": left,
                "decoy": right,
                "base_matching_cost_packets": 0,
                "matching_cost_packets": 2,
            }
            for left, right in sorted(zero_pairs)
        ]
        return (
            {
                "schema_version": 6,
                "adaptation": "qcsd-client-only",
                "paper_equivalent": False,
                "packet_size": 1200,
                "profiles": [
                    {
                        "real": left,
                        "decoy": right,
                        "bursts": [{"outgoing": 3, "incoming": 2}],
                    }
                    for left, right in sorted(zero_pairs)
                ],
            },
            {"candidate_pair_costs": candidates, "selected_pairs": selected},
        )

    return ClassFitters(traffic_morphing=traffic, wtf_pad=wtf, walkie_talkie=walkie)


def _numeric_bundle(
    tmp_path: Path, stage: str, receipt: Mapping[str, Any]
) -> tuple[Path, ClassFittingInputs]:
    inputs = _inputs(stage, receipt)
    artifacts = tmp_path / f"artifacts-{stage}"
    artifacts.mkdir()

    def load(_root: Path, **_kwargs: Any) -> ClassFittingInputs:
        return inputs

    bundle = create_numeric_fitting_bundle(
        tmp_path,
        artifacts_root=artifacts,
        stage=stage,
        fitting_inputs_loader=load,
        fitters=_fitters(),
    )
    return bundle, inputs


@pytest.mark.parametrize(
    ("stage", "expected_samples"),
    [(PILOT_STAGE, 480), (AUTHORITATIVE_STAGE, 2000)],
)
def test_numeric_bundles_bind_exact_120_and_100_class_arithmetic(
    tmp_path: Path, stage: str, expected_samples: int
) -> None:
    bundle, _inputs_value = _numeric_bundle(tmp_path, stage, _cohort_receipt())
    verified = verify_numeric_fitting_bundle(bundle)

    assert {path.name for path in bundle.iterdir()} == NUMERIC_FILES
    assert verified.provenance["artifact_type"] == NUMERIC_ARTIFACT_TYPE
    assert verified.provenance["fitting_contract"]["samples_consumed"] == expected_samples
    assert (
        sum(
            len(rows)
            for workload in verified.provenance["sample_contributions"]
            for rows in workload["policies"].values()
        )
        == expected_samples
    )
    assert verified.provenance["nontraining_inputs"]["qualification_bytes_excluded"] is True


def test_verified_result_loader_rejects_cross_product_and_source_tampering(tmp_path: Path) -> None:
    receipt = _cohort_receipt()
    selection = validate_study_receipt(receipt)
    workload_ids = tuple(candidate.candidate_id for candidate in selection.pilot)
    root = tmp_path / "result"
    (root / "inputs/workloads").mkdir(parents=True)
    (root / "samples").mkdir()
    (root / "inputs/class-study-cohort.json").write_bytes(canonical_json_bytes(receipt))
    (root / "evidence.sha256").write_text("seal\n", encoding="utf-8")
    workloads = []
    samples = []
    for workload_id in workload_ids:
        manifest = root / "inputs/workloads" / f"{workload_id}.json"
        manifest.write_text("{}\n", encoding="utf-8")
        workloads.append(
            {
                "id": workload_id,
                "visits": 2,
                "manifest": manifest.relative_to(root).as_posix(),
                "sha256": sha256_file(manifest),
            }
        )
        for policy in ("as-defined", "half-duplex"):
            for visit in range(2):
                sample_root = (
                    root / "samples" / workload_id / policy / f"visit-{visit:03d}" / "undefended"
                )
                sample_root.mkdir(parents=True)
                samples.append(
                    {
                        "sample_id": f"sample-{workload_id}-{policy}-{visit:03d}",
                        "workload_id": workload_id,
                        "request_policy": policy,
                        "visit": visit,
                        "defense": "undefended",
                        "runtime_kind": "none",
                        "baseline": True,
                        "state": "accepted",
                        "eligible": True,
                        "attempts": 1,
                        "artifacts": {},
                        "path": sample_root.relative_to(root).as_posix(),
                    }
                )
    assembly_path = root / "inputs/class-study-cohort-assembly.json"
    assembly_path.write_bytes(
        canonical_json_bytes(
            _cohort_assembly(
                receipt,
                {record["id"]: record["sha256"] for record in workloads},
            )
        )
    )
    experiment = {
        "name": "classifier-multiorigin100-v1-pilot-fitting-1200",
        "purpose": "fitting",
        "status": "complete",
        "summary": {"passed": True},
        "input_digest": "4" * 64,
        "source": _source(),
        "configuration": {
            "campaign_sha256": "5" * 64,
            "profile": "research-1200",
            "request_policies": ["as-defined", "half-duplex"],
            "defenses": [{"name": "undefended", "kind": "none", "baseline": True}],
            "limits": {
                "timeout_seconds": 120,
                "max_response_bytes": 1024 * 1024,
                "capture_seconds": 180,
                "capture_megabytes": 64,
                "max_attempts": 3,
                "per_origin_cooldown_seconds": 30.0,
                "settle_seconds": 1.0,
            },
            "evidence_role": "pilot-fitting",
            "class_study_cohort_sha256": sha256_file(root / "inputs/class-study-cohort.json"),
            "class_study_cohort_assembly_sha256": sha256_file(assembly_path),
            "workloads": workloads,
        },
        "samples": samples,
    }
    verified = VerifiedResult(
        root=root,
        experiment=experiment,
        checksums={"experiment.json": "6" * 64},
        accepted_samples={},
    )

    def verifier(_root: Path) -> VerifiedResult:
        return verified

    def trace_loader(_root: Path, **kwargs: Any) -> FittingTrace:
        return _trace(kwargs["workload_id"], kwargs["request_policy"], kwargs["visit"])

    result = validate_class_fitting_result(
        root,
        result_verifier=verifier,
        trace_loader=trace_loader,
        preparation_validator=lambda *_args, **_kwargs: None,
    )
    assert len(result.workload_ids) == 120
    assert sum(map(len, result.as_defined.values())) == 240

    experiment["samples"] = samples[:-1]
    with pytest.raises(ValueError, match="exactly 480"):
        validate_class_fitting_result(
            root,
            result_verifier=verifier,
            trace_loader=trace_loader,
            preparation_validator=lambda *_args, **_kwargs: None,
        )

    experiment["samples"] = samples
    experiment["source"]["lab_dirty"] = True
    with pytest.raises(ValueError, match="clean immutable"):
        validate_class_fitting_result(
            root,
            result_verifier=verifier,
            trace_loader=trace_loader,
            preparation_validator=lambda *_args, **_kwargs: None,
        )


def _qualification_context(
    tmp_path: Path,
    *,
    stage: str,
    workload_ids: Sequence[str],
) -> QualificationContext:
    workload_root = tmp_path / "qualification-workloads"
    sidecar_root = tmp_path / "qualification-sidecars"
    prefix_root = tmp_path / "qualification-prefixes"
    workload_root.mkdir()
    sidecar_root.mkdir()
    prefix_root.mkdir()
    entries = []
    runtime_hashes: dict[str, str] = {}
    authority = _qualification_authority()
    for index, workload_id in enumerate(workload_ids):
        workload_path = workload_root / f"{workload_id}.json"
        sidecar_path = sidecar_root / f"{workload_id}.json"
        prefix_path = prefix_root / f"{workload_id}.json"
        workload_path.write_text("{}\n", encoding="utf-8")
        sidecar_path.write_text(
            json.dumps(
                {
                    "workload_id": workload_id,
                    "qualification_source": authority["prepare_source"],
                    "qualification_image_digest": authority["prepare_image_digest"],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        prefix_path.write_text(json.dumps({"workload_id": workload_id}) + "\n", encoding="utf-8")
        runtime_hash = _digest(f"runtime:{workload_id}")
        runtime_hashes[workload_id] = runtime_hash
        entries.append(
            {
                "index": index,
                "workload_id": workload_id,
                "workload_manifest": {
                    "path": workload_path.name,
                    "sha256": sha256_file(workload_path),
                },
                "qualification_sidecar": {
                    "path": sidecar_path.name,
                    "sha256": sha256_file(sidecar_path),
                },
                "runtime_manifest_sha256": runtime_hash,
                "prefix_pack_spec": {
                    "path": prefix_path.name,
                    "sha256": sha256_file(prefix_path),
                },
            }
        )
    qualification_set = (
        PILOT_QUALIFICATION_SET if stage == PILOT_STAGE else AUTHORITATIVE_QUALIFICATION_SET
    )
    named: dict[str, Any] = {
        "schema_version": 2,
        "artifact_type": "qcsd-named-chaff-qualification-set",
        "qualification_set": qualification_set,
        "qualification_scope": "full",
        "qualification_sidecar_schema_version": 2,
        "workload_count": len(workload_ids),
        "workload_ids": list(workload_ids),
        "workloads": entries,
        "qualification_authority": authority,
    }
    named["bindings_sha256"] = _named_set_bindings_digest(named)
    (sidecar_root / "_qualification-set.json").write_bytes(canonical_json_bytes(named))

    def loader(sidecar_path: Path, **kwargs: Any) -> Any:
        workload_id = kwargs["workload_id"]
        return SimpleNamespace(
            sidecar_sha256=sha256_file(sidecar_path),
            manifest_sha256=runtime_hashes[workload_id],
            application_resource_id=0,
            selected_chaff_resource_id=1,
            qualified_parallel_chaff_streams=5,
            walkie_talkie_required_chaff_streams=1,
        )

    def prefix_validator(value: object, **_kwargs: Any) -> dict[str, Any]:
        assert isinstance(value, dict)
        return value

    return QualificationContext(
        workload_root=workload_root,
        sidecar_root=sidecar_root,
        prefix_spec_root=prefix_root,
        loader=loader,
        prefix_validator=prefix_validator,
        preparation_validator=lambda *_args, **_kwargs: None,
        require_current_implementation=False,
        qualification_authority=authority,
    )


def test_final_bundle_policy_qualification_binding_and_tamper_rejection(tmp_path: Path) -> None:
    receipt = _cohort_receipt()
    numeric, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, receipt)
    context = _qualification_context(
        tmp_path,
        stage=PILOT_STAGE,
        workload_ids=inputs.workload_ids,
    )
    final_root = tmp_path / "final-artifacts"
    final_root.mkdir()
    bundle = finalize_fitting_bundle(
        numeric,
        qualification_manifest_path=context.sidecar_root / "_qualification-set.json",
        qualification_context=context,
        artifacts_root=final_root,
    )
    verified = verify_class_fitting_bundle(bundle, qualification_context=context)
    assert {path.name for path in bundle.iterdir()} == FINAL_FILES
    assert verified.provenance["artifact_type"] == FINAL_ARTIFACT_TYPE
    assert verified.parameter_input_policy == PILOT_PARAMETER_INPUT_POLICY
    assert verified.provenance["runtime_authorized"] is False
    assert (
        len(
            json.loads((bundle / BUNDLE_FILES["walkie_talkie"]).read_text())[
                "qualification_bindings"
            ]
        )
        == 120
    )
    assert class_fitting_artifact_type(verified.provenance) == FINAL_ARTIFACT_TYPE

    parameter = bundle / BUNDLE_FILES["traffic_morphing"]
    provenance = bundle / "provenance.json"
    record = class_research_parameter_record(
        parameter,
        provenance,
        expected_kind="traffic_morphing",
        expected_workloads=inputs.workload_ids,
        campaign_evidence_role="pilot-compatibility",
        qualification_context=context,
    )
    assert record[2] == PILOT_PARAMETER_INPUT_POLICY
    with pytest.raises(ValueError, match="pilot fitting artifacts are test-only"):
        class_research_parameter_record(
            parameter,
            provenance,
            expected_kind="traffic_morphing",
            expected_workloads=inputs.workload_ids,
            campaign_evidence_role="formal",
            qualification_context=context,
        )

    first = context.sidecar_root / f"{inputs.workload_ids[0]}.json"
    first.write_text('{"tampered":true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_class_fitting_bundle(bundle, qualification_context=context)


def test_finalization_rejects_named_set_from_another_prepare_build_before_publication(
    tmp_path: Path,
) -> None:
    receipt = _cohort_receipt()
    numeric, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, receipt)
    context = _qualification_context(
        tmp_path,
        stage=PILOT_STAGE,
        workload_ids=inputs.workload_ids,
    )
    wrong = json.loads(json.dumps(context.qualification_authority))
    wrong_image = "sha256:" + "9" * 64
    wrong["prepare_image_digest"] = wrong_image
    wrong["prepare_source"]["image_digest"] = wrong_image
    wrong_context = QualificationContext(
        workload_root=context.workload_root,
        sidecar_root=context.sidecar_root,
        prefix_spec_root=context.prefix_spec_root,
        loader=context.loader,
        prefix_validator=context.prefix_validator,
        preparation_validator=context.preparation_validator,
        require_current_implementation=False,
        qualification_authority=wrong,
    )
    final_root = tmp_path / "wrong-foundation-final-artifacts"
    final_root.mkdir()

    with pytest.raises(ValueError, match="expected foundation"):
        finalize_fitting_bundle(
            numeric,
            qualification_manifest_path=context.sidecar_root / "_qualification-set.json",
            qualification_context=wrong_context,
            artifacts_root=final_root,
        )
    assert list(final_root.iterdir()) == []


def test_final_selection_binds_the_qualification_finalized_pilot_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise numeric fit -> qualification -> finalization -> selection binding."""

    receipt = _cohort_receipt()
    numeric_root, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, receipt)
    numeric = verify_numeric_fitting_bundle(numeric_root)
    context = _qualification_context(
        tmp_path,
        stage=PILOT_STAGE,
        workload_ids=inputs.workload_ids,
    )
    final_parent = tmp_path / "final-artifacts"
    final_parent.mkdir()
    final_root = finalize_fitting_bundle(
        numeric_root,
        qualification_manifest_path=context.sidecar_root / "_qualification-set.json",
        qualification_context=context,
        artifacts_root=final_parent,
    )
    finalized = verify_class_fitting_bundle(final_root, qualification_context=context)
    assert (
        finalized.artifact_hashes["walkie_talkie"]
        != numeric.artifact_hashes["walkie_talkie"]
    )

    compatibility_root = tmp_path / "compatibility"
    frozen_inputs = compatibility_root / "inputs"
    shutil.copytree(
        final_root,
        frozen_inputs / "defense-parameters/class-study",
    )
    shutil.copytree(context.workload_root, frozen_inputs / "workloads")
    shutil.copytree(context.sidecar_root, frozen_inputs / "chaff-qualifications")
    shutil.copytree(context.prefix_spec_root, frozen_inputs / "chaff-prefix-specs")

    # The compact fitting fixtures use injected qualification validators.  Keep
    # those validators while requiring the production selection code to open
    # and verify the exact frozen result-side paths.
    def verify_frozen(root: Path, *, qualification_context: QualificationContext):
        assert root == frozen_inputs / "defense-parameters/class-study"
        assert qualification_context.workload_root == frozen_inputs / "workloads"
        assert qualification_context.sidecar_root == frozen_inputs / "chaff-qualifications"
        assert qualification_context.prefix_spec_root == frozen_inputs / "chaff-prefix-specs"
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
            ),
        )

    monkeypatch.setattr(class_pipeline, "verify_class_fitting_bundle", verify_frozen)
    compatibility = {
        "name": "classifier-multiorigin100-v1-pilot-compatibility-1080-1200",
        "root": str(compatibility_root),
        "evidence_sha256": "8" * 64,
        "experiment_sha256": "9" * 64,
        "accepted": 1_080,
        "unique_class_mode_pairs": 1_080,
        "defense_parameter_sha256": {
            "traffic-morphing": finalized.artifact_hashes["traffic_morphing"],
            "wtf-pad": finalized.artifact_hashes["wtf_pad"],
            "walkie-talkie": finalized.artifact_hashes["walkie_talkie"],
        },
    }
    monkeypatch.setattr(
        class_pipeline,
        "verify_class_study_result",
        lambda *_args, **_kwargs: compatibility,
    )

    cohort_path = tmp_path / "pilot-cohort.json"
    assembly_path = tmp_path / "pilot-cohort-assembly.json"
    cohort_path.write_bytes(canonical_json_bytes(receipt))
    assembly_path.write_bytes(canonical_json_bytes(inputs.cohort_assembly_receipt))
    admission = class_pipeline.CohortAdmission(
        cohort_path=cohort_path,
        assembly_path=assembly_path,
        selection=validate_study_receipt(receipt),
        cohort_sha256=sha256_file(cohort_path),
        assembly_sha256=sha256_file(assembly_path),
        prepared_workload_sha256={workload_id: "a" * 64 for workload_id in inputs.workload_ids},
    )
    selection = class_pipeline.build_final_selection_input(
        admission,
        pilot_numeric_bundle_root=numeric_root,
        pilot_compatibility_result_root=compatibility_root,
    )
    bound = selection["payload"]["pilot_compatibility"]
    assert bound["fitted_parameter_sha256"] == compatibility["defense_parameter_sha256"]
    assert bound["finalized_bundle"] == {
        "source": "frozen-pilot-compatibility-inputs",
        "provenance_sha256": sha256_file(final_root / "provenance.json"),
        "artifact_sha256": compatibility["defense_parameter_sha256"],
    }
    graph = tuple(
        tuple(pair) for pair in selection["payload"]["feasible_pair_graph"]
    )
    assert len(graph) == len(inputs.workload_ids) // 2
    assert {workload_id for pair in graph for workload_id in pair} == set(
        inputs.workload_ids
    )
    # Only the pair-specific runtime profiles exercised by the frozen bundle
    # are admitted.  Endpoint qualification under two different profiles does
    # not manufacture an alternate cross-profile edge.
    assert frozenset((graph[0][0], graph[1][0])) not in {
        frozenset(pair) for pair in graph
    }
    rule = selection["payload"]["feasible_pair_rule"]
    assert rule["qualified_pair_edges"] == 60
    assert rule["unqualified_alternate_pairs_excluded"] == (120 * 119 // 2) - 60
    assert rule["unselected_pairs_inferred_from_endpoint_compatibility"] is False
    assert len(selection["payload"]["feasible_pair_evidence"]) == 60
    assert len(selection["payload"]["selected_final_perfect_matching"]) == 50

    with pytest.raises(ValueError, match="perfect 20-per-stratum"):
        class_pipeline._qualified_final_pair_selection(
            admission,
            pilot_cohort=receipt,
            feasible_pairs=(),
        )

    compatibility["defense_parameter_sha256"] = {
        **compatibility["defense_parameter_sha256"],
        "walkie-talkie": numeric.artifact_hashes["walkie_talkie"],
    }
    with pytest.raises(ValueError, match="exact pilot fitted parameters"):
        class_pipeline.build_final_selection_input(
            admission,
            pilot_numeric_bundle_root=numeric_root,
            pilot_compatibility_result_root=compatibility_root,
        )


def test_authoritative_policy_is_separate_from_pilot_policy() -> None:
    assert PILOT_PARAMETER_INPUT_POLICY == "sealed-class-study-pilot-fitting-v1"
    assert AUTHORITATIVE_PARAMETER_INPUT_POLICY == "sealed-class-study-fitting-v1"
    assert PILOT_QUALIFICATION_SET == "classifier-multiorigin100-v1-pilot120-full-v1"
    assert AUTHORITATIVE_QUALIFICATION_SET == "classifier-multiorigin100-v1-final100-full-v1"


def test_schema_six_prefix_projection_does_not_double_sender_framing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import qcsd_lab.chaff_qualification as qualification

    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        qualification, "selected_navigation_root", lambda _manifest, _workload: {"id": 0}
    )
    monkeypatch.setattr(
        qualification,
        "selected_chaff_resource",
        lambda _manifest, _workload: ({"id": 9}, {"bytes": 48_000}),
    )

    def capacity_plan(*, bursts: Sequence[Mapping[str, int]], **_kwargs: Any):
        captured["bursts"] = list(bursts)
        return 5, []

    monkeypatch.setattr(qualification, "_capacity_plan", capacity_plan)
    walkie = {
        "schema_version": 6,
        "packet_size": 1200,
        "profiles": [
            {"real": "class-a", "decoy": "class-b", "bursts": [{"outgoing": 7, "incoming": 4}]}
        ],
    }
    spec = build_schema_six_prefix_spec(
        "class-a",
        walkie,
        source_walkie_talkie_artifact_sha256="a" * 64,
        application_manifest={},
    )

    assert captured["bursts"] == [{"outgoing": 7, "incoming": 4}]
    assert spec["numeric_profile"]["bursts"][0]["outgoing"] == 7
    assert spec["numeric_profile_derivation"].endswith("no-additional-sender-framing")
    assert (
        validate_schema_six_prefix_spec_shape(
            spec,
            workload_id="class-a",
            application_manifest={},
        )
        == spec
    )
    tampered = json.loads(json.dumps(spec))
    tampered["numeric_profile"]["bursts"][0]["outgoing"] = 8
    with pytest.raises(ValueError, match="numeric derivation"):
        validate_schema_six_prefix_spec_shape(
            tampered,
            workload_id="class-a",
            application_manifest={},
        )


def test_scalable_solver_boundaries_cover_120_assignment_and_100_matching() -> None:
    assignment_names = tuple(f"w{index:03d}" for index in range(120))
    next_target = {
        name: assignment_names[(index + 1) % len(assignment_names)]
        for index, name in enumerate(assignment_names)
    }
    costs = {
        (source, target): SimpleNamespace(
            fidelity_cost=0.0 if target == next_target[source] else 1.0,
            byte_cost=0.0,
        )
        for source in assignment_names
        for target in assignment_names
        if source != target
    }
    assignment = minimum_cost_derangement(assignment_names, costs)
    assert assignment == tuple((name, next_target[name]) for name in assignment_names)

    matching_names = tuple(f"m{index:03d}" for index in range(100))
    intended = {
        (matching_names[index], matching_names[index + 1])
        for index in range(0, len(matching_names), 2)
    }
    pair_costs = {
        (left, right): 0 if (left, right) in intended else 1
        for index, left in enumerate(matching_names)
        for right in matching_names[index + 1 :]
    }
    matching = minimum_weight_perfect_matching_from_costs(matching_names, pair_costs)
    assert tuple((left, right) for left, right, _cost in matching) == tuple(sorted(intended))
