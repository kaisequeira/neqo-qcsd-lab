from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import qcsd_lab.class_fitting as class_fitting
from qcsd_lab.acquisition_selection import derive_global_operational_censor_selection
from qcsd_lab.class_catalogue import load_candidate_catalogue_receipt
import qcsd_lab.class_pipeline as class_pipeline
import qcsd_lab.experiment as experiment_module
import qcsd_lab.verification as verification_module
from qcsd_lab import orchestrator
from qcsd_lab.class_cohort import ASSEMBLY_RECEIPT_TYPE
from qcsd_lab.class_fitting import (
    AUTHORITATIVE_PARAMETER_INPUT_POLICY,
    AUTHORITATIVE_QUALIFICATION_SET,
    AUTHORITATIVE_STAGE,
    BUNDLE_FILES,
    FINAL_ARTIFACT_TYPE,
    FINAL_FILES,
    FINAL_PROVENANCE_SCHEMA_VERSION,
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
    derive_schema_six_prefix_specs,
    finalize_fitting_bundle,
    require_successor_fitting_identity,
    validate_class_fitting_result,
    validate_schema_six_prefix_spec_shape,
    verify_class_fitting_bundle,
    verify_numeric_fitting_bundle,
)
from qcsd_lab.class_study import (
    CLASS20_PROFILE,
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    build_study_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    deterministic_profile_candidate_order,
    validate_study_receipt,
)
from qcsd_lab.class_cohort20 import (
    ASSEMBLY_RECEIPT_TYPE as PROFILE_ASSEMBLY_RECEIPT_TYPE,
    COHORT_RECEIPT_TYPE as PROFILE_COHORT_RECEIPT_TYPE,
)
from qcsd_lab.class_run_binding import resolve_class_sample_run_binding
from qcsd_lab.fitting_morphing import minimum_cost_derangement
from qcsd_lab.fitting_trace import FittingTrace
from qcsd_lab.fitting_walkie_talkie import minimum_weight_perfect_matching_from_costs
from qcsd_lab.util import sha256_bytes, sha256_file
from qcsd_lab.verification import VerifiedResult
from tests.test_class_cohort import _synthetic_acquisition_prefix_loaded_pilot_campaign
from tests.test_fitting_bundle import _event_csv

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize(
    "source_result",
    (
        {"study_id": "classifier-multiorigin100-v1"},
        {
            "study_id": "classifier-multiorigin100-v2-g01-abcdef123456",
            "class_study_successor_sha256": "a" * 64,
        },
        {
            "study_id": "classifier-multiorigin100-v2-g01-0123456789ab",
            "class_study_successor_sha256": "b" * 64,
        },
    ),
    ids=("predecessor-v1", "other-v2", "same-id-different-restart"),
)
def test_successor_fitting_identity_requires_exact_study_and_restart(
    source_result: Mapping[str, Any],
) -> None:
    expected_study_id = "classifier-multiorigin100-v2-g01-0123456789ab"
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
                "page_order": ("canonical-homepage-then-hash-ordered-safe-same-domain-links"),
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
        "schema_version": 2,
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
            "completion_path": "/lab/artifacts/buflo-study/build-completion-v23.json",
            "completion_sha256": "8" * 64,
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


def _profile_pilot_inputs() -> ClassFittingInputs:
    catalogue_path = (
        Path(__file__).resolve().parents[1]
        / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
    )
    profile_path = Path(__file__).resolve().parents[1] / "config/class-study/v2/study.json"
    catalogue, candidates = load_candidate_catalogue_receipt(catalogue_path)
    tranco = catalogue["payload"]["tranco"]
    ordered = deterministic_profile_candidate_order(
        candidates, tranco_list_sha256=tranco["list_sha256"], profile=CLASS20_PROFILE
    )
    resolved = tuple(
        replace(candidate, eligible=index < CLASS20_PROFILE.pilot_count)
        for index, candidate in enumerate(ordered)
    )
    pilot_ids = tuple(item.candidate_id for item in resolved[:CLASS20_PROFILE.pilot_count])
    cohort = bind_receipt(
        {
            "study_id": CLASS20_PROFILE.study_id,
            "cohort_schema_version": 1,
            "profile_sha256": sha256_file(profile_path),
            "stage": "pilot",
            "tranco": {
                "list_id": tranco["list_id"],
                "list_sha256": tranco["list_sha256"],
            },
            "candidates": [item.as_dict() for item in resolved],
            "pilot_ids": list(pilot_ids),
            "final_ids": [],
            "reserve_ids": [],
            "matching": [],
            "final_selection": None,
        },
        receipt_type=PROFILE_COHORT_RECEIPT_TYPE,
    )
    records = []
    for item in resolved:
        selected = item.eligible
        records.append({
            "candidate_id": item.candidate_id,
            "eligible": selected,
            "selected_page": (
                {
                    "candidate_domain": item.domain,
                    "registrable_domain": item.domain,
                    "url": f"https://{item.domain}/",
                    "source": "canonical-homepage",
                    "ordinal": 0,
                    "discovery_content_type": None,
                } if selected else None
            ),
            "stability_receipt": (
                {"path": f"{item.candidate_id}/page-00.json", "sha256": "a" * 64,
                 "payload_sha256": "b" * 64} if selected else None
            ),
            "prepared_workload": (
                {"path": f"{item.candidate_id}.json", "sha256": "c" * 64}
                if selected else None
            ),
            "reasons": [] if selected else ["unassessed-deterministic-prefix-tail"],
            "disposition": "eligible" if selected else "unassessed",
        })
    selection = derive_global_operational_censor_selection(
        candidates,
        tranco_list_sha256=tranco["list_sha256"],
        ordered_candidate_ids=[item.candidate_id for item in resolved],
        order_policy="round-robin-five-frozen-within-stratum-orders",
        eligible_quota=CLASS20_PROFILE.pilot_count,
        terminal_disposition={workload_id: "eligible" for workload_id in pilot_ids},
    )
    assembly = bind_receipt(
        {
            "study_id": CLASS20_PROFILE.study_id,
            "assembly_schema_version": 1,
            "profile": {"path": "config/class-study/v2/study.json", "sha256": sha256_file(profile_path)},
            "candidate_catalogue": {
                "path": "config/class-study/v1/classifier-multiorigin100-v1-candidates.json",
                "sha256": sha256_file(catalogue_path),
                "payload_sha256": catalogue["payload_sha256"],
            },
            "acquisition_completion": {
                "path": f"artifacts/{CLASS20_PROFILE.study_id}-acquisition-v999/completion.json",
                "sha256": "d" * 64,
                "payload_sha256": "e" * 64,
                "provenance_sha256": "f" * 64,
                "selection_payload_sha256": sha256_bytes(canonical_json_bytes(selection)),
            },
            "acquisition_selection": selection,
            "stability_root": f"artifacts/{CLASS20_PROFILE.study_id}-stability-v999",
            "workload_root": f"config/{CLASS20_PROFILE.study_id}-workloads-v999",
            "candidates": records,
            "eligible_count": CLASS20_PROFILE.pilot_count,
            "selected_evidence_count": CLASS20_PROFILE.pilot_count,
            "cohort": {
                "receipt_type": cohort["receipt_type"],
                "payload_sha256": cohort["payload_sha256"],
                "canonical_file_sha256": sha256_bytes(canonical_json_bytes(cohort)),
            },
        },
        receipt_type=PROFILE_ASSEMBLY_RECEIPT_TYPE,
    )
    visits = 2
    by_policy = {
        policy: {
            workload_id: tuple(_trace(workload_id, policy, visit) for visit in range(visits))
            for workload_id in pilot_ids
        }
        for policy in ("as-defined", "half-duplex")
    }
    source_result = {
        "campaign": f"{CLASS20_PROFILE.study_id}-pilot-fitting-120-1200",
        "evidence_sha256": _digest("profile20 evidence"),
        "experiment_sha256": _digest("profile20 experiment"),
        "input_digest": _digest("profile20 input"),
        "campaign_sha256": _digest("profile20 campaign"),
        "source_fingerprints": _source(),
        "study_id": CLASS20_PROFILE.study_id,
        "class_study_profile_sha256": sha256_file(profile_path),
    }
    return ClassFittingInputs(
        verified=VerifiedResult(Path("."), {}, {}, {}),
        stage=PILOT_STAGE,
        workload_ids=pilot_ids,
        visits_per_policy=visits,
        as_defined=by_policy["as-defined"],
        half_duplex=by_policy["half-duplex"],
        cohort_receipt=cohort,
        cohort_receipt_sha256=sha256_bytes(canonical_json_bytes(cohort)),
        cohort_assembly_receipt=assembly,
        cohort_assembly_receipt_sha256=sha256_bytes(canonical_json_bytes(assembly)),
        source_result=source_result,
        study_profile=CLASS20_PROFILE,
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
        assert len(traces) in {60, 200, 240, 1000}
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
        *,
        feasible_pairs: Sequence[tuple[str, str]] | None = None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        names = tuple(sorted(traces))
        zero_pairs = {(names[index], names[index + 1]) for index in range(0, len(names), 2)}
        chosen_pairs = sorted(
            zero_pairs if feasible_pairs is None else {
                tuple(sorted(pair)) for pair in feasible_pairs
            }
        )
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
                "base_matching_cost_packets": 0 if (left, right) in zero_pairs else 1,
                "matching_cost_packets": 2 if (left, right) in zero_pairs else 3,
            }
            for left, right in chosen_pairs
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
                    for left, right in chosen_pairs
                ],
            },
            {
                "algorithm": (
                    "full-cohort-minimum-weight-perfect-matching"
                    if feasible_pairs is None else class_fitting.PROFILE_FIXED_PAIR_ALGORITHM
                ),
                "pairing_objective": (
                    "minimum-base-symmetric-mold-padding-cost"
                    if feasible_pairs is None else class_fitting.PROFILE_FIXED_PAIR_OBJECTIVE
                ),
                "candidate_pair_costs": candidates,
                "selected_pairs": selected,
            },
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


def _bind_numeric_publication_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    inputs: ClassFittingInputs,
) -> tuple[Path, list[tuple[Path, Path | None]]]:
    """Make compact numeric fixtures exercise the production source-bound verifier."""

    source_result_root = tmp_path / f"source-{inputs.stage}"
    source_result_root.mkdir()
    calls: list[tuple[Path, Path | None]] = []
    real_verifier = verify_numeric_fitting_bundle

    def verify_bound_numeric(
        root: Path,
        *,
        source_result_root: Path | None = None,
    ):
        calls.append((root, source_result_root))
        return real_verifier(
            root,
            source_result_root=source_result_root,
            fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
            fitters=_fitters(),
        )

    monkeypatch.setattr(
        class_fitting,
        "verify_numeric_fitting_bundle",
        verify_bound_numeric,
    )
    return source_result_root, calls


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


def test_profile20_numeric_fitting_binds_30_pilot_sites_and_source_profile(
    tmp_path: Path,
) -> None:
    inputs = _profile_pilot_inputs()
    artifacts = tmp_path / "profile20-artifacts"
    artifacts.mkdir()
    bundle = create_numeric_fitting_bundle(
        tmp_path,
        artifacts_root=artifacts,
        stage=PILOT_STAGE,
        study_profile=CLASS20_PROFILE,
        fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
        fitters=_fitters(),
    )
    verified = verify_numeric_fitting_bundle(bundle)
    provenance = verified.provenance
    assert bundle.name == f"{CLASS20_PROFILE.study_id}-pilot-fitting-numeric"
    assert provenance["schema_version"] == 2
    assert provenance["study_id"] == CLASS20_PROFILE.study_id
    assert provenance["study_profile_sha256"] == inputs.source_result[
        "class_study_profile_sha256"
    ]
    assert provenance["fitting_contract"]["samples_consumed"] == 120
    assert provenance["fitting_contract"]["study_id"] == CLASS20_PROFILE.study_id
    assert len(provenance["fitting_contract"]["workload_order"]) == 30
    assert class_fitting._prefix_directory(PILOT_STAGE, CLASS20_PROFILE) == (
        f"{CLASS20_PROFILE.study_id}-pilot-fitting-prefix-specs"
    )

    altered = dict(provenance)
    altered["study_profile_sha256"] = "0" * 64
    (bundle / class_fitting.NUMERIC_PROVENANCE_FILE).write_bytes(canonical_json_bytes(altered))
    with pytest.raises(ValueError, match="another study profile"):
        verify_numeric_fitting_bundle(bundle)


def test_profile20_fitting_rejects_mixed_cohort_and_qualification_set(
    tmp_path: Path,
) -> None:
    inputs = _profile_pilot_inputs()
    with pytest.raises(ValueError, match="cohort|profile"):
        class_fitting._validate_injected_inputs(
            replace(inputs, cohort_receipt=_cohort_receipt()), PILOT_STAGE
        )
    with pytest.raises(ValueError, match="profile identity"):
        class_fitting._validate_source_result(
            {**inputs.source_result, "class_study_profile_sha256": "0" * 64},
            PILOT_STAGE,
            CLASS20_PROFILE,
        )
    sidecars = tmp_path / "sidecars"
    sidecars.mkdir()
    manifest = sidecars / "_qualification-set.json"
    manifest.write_bytes(canonical_json_bytes({key: None for key in class_fitting._NAMED_SET_KEYS}))
    context = QualificationContext(
        workload_root=tmp_path,
        sidecar_root=sidecars,
        prefix_spec_root=tmp_path,
        expected_qualification_set=AUTHORITATIVE_QUALIFICATION_SET,
    )
    with pytest.raises(ValueError, match="another study profile"):
        class_fitting._verify_qualification(
            manifest,
            stage=PILOT_STAGE,
            profile=CLASS20_PROFILE,
            workload_ids=inputs.workload_ids,
            walkie_talkie_path=tmp_path / "unused.json",
            context=context,
        )


def _profile_final_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> ClassFittingInputs:
    """Build a frozen 20-site fit whose pairs agree with its numeric optimum."""

    import qcsd_lab.class_cohort20 as class_cohort20

    pilot = _profile_pilot_inputs()
    study_id = CLASS20_PROFILE.study_id
    cohort_payload = json.loads(json.dumps(pilot.cohort_receipt["payload"]))
    pilot_ids = cohort_payload["pilot_ids"]
    ids = tuple(pilot_ids[:20])
    visits = 10
    half_duplex = {
        workload_id: tuple(_trace(workload_id, "half-duplex", visit) for visit in range(visits))
        for workload_id in ids
    }
    fitted_walkie, _receipt = _fitters().walkie_talkie(half_duplex)
    pilot_order = {workload_id: index for index, workload_id in enumerate(pilot_ids)}
    matching = [
        sorted((row["real"], row["decoy"]), key=pilot_order.__getitem__)
        for row in fitted_walkie["profiles"]
    ]
    matching.sort(key=lambda pair: pilot_order[pair[0]])
    cohort_payload.update({
        "stage": "final",
        "final_ids": list(ids),
        "reserve_ids": pilot_ids[20:],
        "matching": matching,
        "final_selection": {
            "path": f"config/class-study/v2/{study_id}-final-selection.json",
            "sha256": "a" * 64,
            "pilot_cohort": {
                "path": f"config/class-study/v2/{study_id}-pilot-cohort.json",
                "sha256": "b" * 64,
            },
            "pilot_assembly": {
                "path": f"config/class-study/v2/{study_id}-pilot-cohort-assembly.json",
                "sha256": "c" * 64,
            },
        },
    })
    cohort = bind_receipt(cohort_payload, receipt_type=PROFILE_COHORT_RECEIPT_TYPE)
    assembly_payload = json.loads(json.dumps(pilot.cohort_assembly_receipt["payload"]))
    assembly_payload["cohort"] = {
        "receipt_type": cohort["receipt_type"],
        "payload_sha256": cohort["payload_sha256"],
        "canonical_file_sha256": sha256_bytes(canonical_json_bytes(cohort)),
    }
    assembly = bind_receipt(assembly_payload, receipt_type=PROFILE_ASSEMBLY_RECEIPT_TYPE)
    inputs = replace(
        pilot,
        stage=AUTHORITATIVE_STAGE,
        workload_ids=ids,
        visits_per_policy=visits,
        as_defined={
            workload_id: tuple(_trace(workload_id, "as-defined", visit) for visit in range(visits))
            for workload_id in ids
        },
        half_duplex=half_duplex,
        cohort_receipt=cohort,
        cohort_receipt_sha256=sha256_bytes(canonical_json_bytes(cohort)),
        cohort_assembly_receipt=assembly,
        cohort_assembly_receipt_sha256=sha256_bytes(canonical_json_bytes(assembly)),
        source_result={
            **pilot.source_result,
            "campaign": f"{study_id}-authoritative-fitting-400-1200",
        },
    )

    # Intrinsic replay still checks the registered source profile/catalogue.
    # No fresh final-selection, pilot receipt, sidecars, or acquisition roots
    # exist under this temporary Lab root.
    source_root = Path(__file__).resolve().parents[1]
    for relative in (
        Path("config/class-study/v2/study.json"),
        Path("config/class-study/v1/classifier-multiorigin100-v1-candidates.json"),
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, destination)
    monkeypatch.setattr(class_cohort20.util, "LAB_ROOT", tmp_path)
    assert not (tmp_path / cohort_payload["final_selection"]["path"]).exists()
    return inputs


def test_frozen_profile_final_numeric_bundle_survives_missing_selection_and_rejects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sealed fit replays its own cohort after fresh pair evidence is gone."""

    inputs = _profile_final_inputs(tmp_path, monkeypatch)
    cohort_payload = inputs.cohort_receipt["payload"]
    pilot_ids = cohort_payload["pilot_ids"]

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    bundle = create_numeric_fitting_bundle(
        tmp_path,
        artifacts_root=artifacts,
        stage=AUTHORITATIVE_STAGE,
        study_profile=CLASS20_PROFILE,
        fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
        fitters=_fitters(),
    )
    assert verify_numeric_fitting_bundle(bundle).stage == AUTHORITATIVE_STAGE

    provenance_path = bundle / class_fitting.NUMERIC_PROVENANCE_FILE
    provenance = json.loads(provenance_path.read_text())
    malformed = json.loads(json.dumps(cohort_payload))
    malformed["matching"][0] = [pilot_ids[0], pilot_ids[20]]
    changed = bind_receipt(malformed, receipt_type=PROFILE_COHORT_RECEIPT_TYPE)
    provenance["cohort"]["receipt"] = changed
    provenance["cohort"]["receipt_sha256"] = sha256_bytes(canonical_json_bytes(changed))
    provenance_path.write_bytes(canonical_json_bytes(provenance))
    with pytest.raises(ValueError, match="matching differs from final sites"):
        verify_numeric_fitting_bundle(bundle)


def test_profile20_final_numeric_fits_selected_pairs_despite_cheaper_global_matching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _profile_final_inputs(tmp_path, monkeypatch)
    changed_payload = json.loads(json.dumps(inputs.cohort_receipt["payload"]))
    first, second = changed_payload["matching"][:2]
    pilot_order = {
        workload_id: index
        for index, workload_id in enumerate(changed_payload["pilot_ids"])
    }
    competing = [
        sorted((first[0], second[0]), key=pilot_order.__getitem__),
        sorted((first[1], second[1]), key=pilot_order.__getitem__),
    ]
    changed_payload["matching"][:2] = competing
    changed_payload["matching"].sort(key=lambda pair: pilot_order[pair[0]])
    changed_cohort = bind_receipt(
        changed_payload, receipt_type=PROFILE_COHORT_RECEIPT_TYPE,
    )
    assembly_payload = json.loads(json.dumps(inputs.cohort_assembly_receipt["payload"]))
    assembly_payload["cohort"] = {
        "receipt_type": changed_cohort["receipt_type"],
        "payload_sha256": changed_cohort["payload_sha256"],
        "canonical_file_sha256": sha256_bytes(canonical_json_bytes(changed_cohort)),
    }
    changed_assembly = bind_receipt(
        assembly_payload, receipt_type=PROFILE_ASSEMBLY_RECEIPT_TYPE,
    )
    competing_inputs = replace(
        inputs,
        cohort_receipt=changed_cohort,
        cohort_receipt_sha256=sha256_bytes(canonical_json_bytes(changed_cohort)),
        cohort_assembly_receipt=changed_assembly,
        cohort_assembly_receipt_sha256=sha256_bytes(canonical_json_bytes(changed_assembly)),
    )
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    bundle = create_numeric_fitting_bundle(
        tmp_path,
        artifacts_root=artifacts,
        stage=AUTHORITATIVE_STAGE,
        study_profile=CLASS20_PROFILE,
        fitting_inputs_loader=lambda *_args, **_kwargs: competing_inputs,
        fitters=_fitters(),
    )
    verified = verify_numeric_fitting_bundle(
        bundle,
        source_result_root=tmp_path,
        fitting_inputs_loader=lambda *_args, **_kwargs: competing_inputs,
        fitters=_fitters(),
    )
    walkie = verified.provenance["algorithms"]["walkie_talkie"]
    assert walkie["algorithm"] == class_fitting.PROFILE_FIXED_PAIR_ALGORITHM
    assert walkie["pairing_objective"] == class_fitting.PROFILE_FIXED_PAIR_OBJECTIVE
    candidate_costs = {
        (row["left"], row["right"]): row["base_matching_cost_packets"]
        for row in walkie["candidate_pair_costs"]
    }
    unconstrained = minimum_weight_perfect_matching_from_costs(
        competing_inputs.workload_ids, candidate_costs,
    )
    observed = tuple(
        (row["real"], row["decoy"], row["base_matching_cost_packets"])
        for row in walkie["selected_pairs"]
    )
    assert observed != unconstrained
    assert {(left, right) for left, right, _cost in observed} == {
        tuple(sorted(pair)) for pair in changed_payload["matching"]
    }
    fitted = json.loads((bundle / BUNDLE_FILES["walkie_talkie"]).read_text())
    assert {(row["real"], row["decoy"]) for row in fitted["profiles"]} == {
        tuple(sorted(pair)) for pair in changed_payload["matching"]
    }

    forged = json.loads(json.dumps(verified.provenance))
    by_pair = {
        (row["left"], row["right"]): row
        for row in walkie["candidate_pair_costs"]
    }
    forged["algorithms"]["walkie_talkie"]["selected_pairs"] = [
        {
            "real": left,
            "decoy": right,
            "base_matching_cost_packets": by_pair[left, right]["base_matching_cost_packets"],
            "matching_cost_packets": by_pair[left, right]["matching_cost_packets"],
        }
        for left, right, _cost in unconstrained
    ]
    (bundle / class_fitting.NUMERIC_PROVENANCE_FILE).write_bytes(canonical_json_bytes(forged))
    with pytest.raises(ValueError, match="exact constrained optimum"):
        verify_numeric_fitting_bundle(bundle)


def test_profile20_final_bundle_requires_20_qualified_sites_and_selected_pairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _profile_final_inputs(tmp_path, monkeypatch)
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
    source_result_root, _calls = _bind_numeric_publication_source(
        monkeypatch, tmp_path, inputs,
    )
    context = _qualification_context(
        tmp_path,
        stage=AUTHORITATIVE_STAGE,
        workload_ids=inputs.workload_ids,
        profile20=True,
    )
    final_parent = tmp_path / "final-artifacts"
    final_parent.mkdir()
    final = finalize_fitting_bundle(
        numeric,
        source_result_root=source_result_root,
        qualification_manifest_path=context.sidecar_root / "_qualification-set.json",
        qualification_context=context,
        artifacts_root=final_parent,
    )
    verified = verify_class_fitting_bundle(final, qualification_context=context)
    assert verified.root.name == f"{CLASS20_PROFILE.study_id}-authoritative-fitting"
    assert verified.stage == AUTHORITATIVE_STAGE
    assert verified.provenance["schema_version"] == 3
    assert verified.provenance["runtime_authorized"] is True
    assert verified.provenance["qualification_inputs"]["qualification_set"] == (
        f"{CLASS20_PROFILE.study_id}-final20-full-v1"
    )
    assert len(verified.provenance["qualification_inputs"]["qualification_bindings"]) == 20


def test_verified_result_loader_rejects_cross_product_and_source_tampering(tmp_path: Path) -> None:
    from tests.test_manifest import class_study_prepared_manifest

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
                        "seed": visit + (0 if policy == "as-defined" else 10),
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

    bindings: dict[str, object] = {}
    resolver_calls: list[str] = []

    def trace_loader(_root: Path, **kwargs: Any) -> FittingTrace:
        workload_id = kwargs["workload_id"]
        assert kwargs["run_binding"] is bindings[workload_id]
        assert type(kwargs["seed"]) is int
        return _trace(kwargs["workload_id"], kwargs["request_policy"], kwargs["visit"])

    def run_binding_resolver(
        _root: Path,
        _configuration: Mapping[str, Any],
        sample: Mapping[str, Any],
        **kwargs: Any,
    ) -> Any:
        workload_id = str(sample["workload_id"])
        resolver_calls.append(workload_id)
        assert kwargs == {"allow_derived_runtime_without_frozen_copy": True}
        assert sample == {
            "workload_id": workload_id,
            "defense": "undefended",
            "runtime_kind": "none",
            "baseline": True,
        }
        binding = object()
        bindings[workload_id] = binding
        return binding

    result = validate_class_fitting_result(
        root,
        result_verifier=verifier,
        trace_loader=trace_loader,
        preparation_validator=lambda *_args, **_kwargs: None,
        run_binding_resolver=run_binding_resolver,
    )
    assert len(result.workload_ids) == 120
    assert sum(map(len, result.as_defined.values())) == 240
    assert resolver_calls == list(workload_ids)
    assert set(bindings) == set(workload_ids)

    experiment["samples"] = samples[:-1]
    with pytest.raises(ValueError, match="exactly 480"):
        validate_class_fitting_result(
            root,
            result_verifier=verifier,
            trace_loader=trace_loader,
            preparation_validator=lambda *_args, **_kwargs: None,
            run_binding_resolver=run_binding_resolver,
        )

    experiment["samples"] = samples
    experiment["source"]["lab_dirty"] = True
    with pytest.raises(ValueError, match="clean immutable"):
        validate_class_fitting_result(
            root,
            result_verifier=verifier,
            trace_loader=trace_loader,
            preparation_validator=lambda *_args, **_kwargs: None,
            run_binding_resolver=run_binding_resolver,
        )

    experiment["source"]["lab_dirty"] = False
    first_manifest_path = root / workloads[0]["manifest"]
    incomplete = class_study_prepared_manifest()
    incomplete["preparation"].pop("coverage_admission")
    first_manifest_path.write_bytes(canonical_json_bytes(incomplete))
    workloads[0]["sha256"] = sha256_file(first_manifest_path)
    assembly_path.write_bytes(
        canonical_json_bytes(
            _cohort_assembly(
                receipt,
                {record["id"]: record["sha256"] for record in workloads},
            )
        )
    )
    experiment["configuration"]["class_study_cohort_assembly_sha256"] = sha256_file(assembly_path)

    with pytest.raises(ValueError, match="requires a complete-coverage admission"):
        validate_class_fitting_result(
            root,
            result_verifier=verifier,
            trace_loader=trace_loader,
            run_binding_resolver=run_binding_resolver,
        )


def test_sealed_synthetic_pilot_result_reaches_default_numeric_refit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bridge admitted 120-class inputs into the default fitter with zero credit.

    The fixture substitutes only the external foundation/frozen-campaign and
    kernel scheduler receipts. It still creates and verifies a real local seal
    and loads all 480 typed traces. Compact deterministic fitters keep the
    120-class matching calculation bounded; algorithm tests cover their solver.
    """
    campaign, admission, cohort_path, assembly_path, _workload_root = (
        _synthetic_acquisition_prefix_loaded_pilot_campaign(tmp_path, monkeypatch)
    )
    root = tmp_path / "diagnostic-fitting-result"
    inputs = root / "inputs"
    workload_inputs = inputs / "workloads"
    workload_inputs.mkdir(parents=True)
    (inputs / "campaign.yml").write_bytes(campaign.source_bytes)
    (inputs / "class-study-cohort.json").write_bytes(cohort_path.read_bytes())
    (inputs / "class-study-cohort-assembly.json").write_bytes(assembly_path.read_bytes())
    workload_records = []
    for workload in campaign.workloads:
        relative = f"inputs/workloads/{workload.id}.json"
        (root / relative).write_bytes(workload.source_bytes)
        workload_records.append(
            {
                "id": workload.id,
                "visits": workload.visits,
                "manifest": relative,
                "sha256": workload.sha256,
                "resource_count": workload.resource_count,
                "origin_count": workload.origin_count,
            }
        )
    configuration = {
        "campaign_sha256": sha256_file(inputs / "campaign.yml"),
        "profile": campaign.profile,
        "request_policies": list(campaign.request_policies),
        "workloads": workload_records,
        "defenses": [
            {"name": defense.name, "kind": defense.kind, "baseline": defense.baseline}
            for defense in campaign.defenses
        ],
        "limits": campaign.limits.as_dict(),
        "evidence_role": campaign.evidence_role,
        "class_study_cohort_sha256": admission.cohort_sha256,
        "class_study_cohort_assembly_sha256": admission.assembly_sha256,
        "class_study_id": "classifier-multiorigin100-v1",
        "class_study_launch_sha256": "e" * 64,
        "class_study_foundation_sha256": "f" * 64,
        "public_origin_policy": {
            "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
            "required_value": "1",
            "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
        },
    }
    plan = orchestrator.plan_campaign(campaign)
    assert len(plan) == 480
    experiment = experiment_module.initialize_experiment(
        root,
        name=campaign.name,
        purpose=campaign.purpose,
        run_id="diagnostic-001",
        source=_source(),
        configuration=configuration,
        samples=plan,
        started_at="2026-10-01T00:00:00+00:00",
    )
    # These are independent live authority contracts; synthetic test receipts
    # are deliberately not presented as a foundation or scheduler attestation.
    monkeypatch.setattr(verification_module, "_validate_frozen_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(
        experiment_module, "validate_accepted_scheduler_runtime_receipt", lambda *_a: None
    )
    workload_index = {workload.id: index for index, workload in enumerate(campaign.workloads)}
    for sample in plan:
        experiment_module.transition_sample(
            experiment, sample["sample_id"], "running", increment_attempt=True
        )
        binding = resolve_class_sample_run_binding(
            root,
            configuration,
            sample,
            allow_derived_runtime_without_frozen_copy=True,
        )
        sample_root = root / sample["path"]
        neqo = sample_root / "neqo"
        neqo.mkdir(parents=True)
        run = {
            "completion_status": "complete",
            "terminal_evidence_render_errors": [],
            "seed": sample["seed"],
            "request_policy": sample["request_policy"],
            "workload_hash_sha256": binding.input_bindings["runtime_workload_sha256"],
            "max_response_bytes": configuration["limits"]["max_response_bytes"],
            "resolved_configuration": {
                "max_udp_payload_size": 1_200,
                "defense": {"kind": "none"},
            },
            "responses": [
                {
                    "resource_id": resource_id,
                    "status": status,
                    "bytes": size,
                    "body_sha256": body_sha256,
                    "outcome": outcome,
                    "complete": True,
                }
                for resource_id, status, size, body_sha256, outcome in binding.expected_responses
            ],
            "endpoints": [{"origin": origin} for origin in binding.expected_origins],
            "defense_start_monotonic_ns": 0,
            "application_completion_monotonic_ns": 75_000_000,
        }
        (neqo / "run.json").write_bytes(canonical_json_bytes(run))
        (neqo / "events.csv").write_text(
            _event_csv(
                workload_index[sample["workload_id"]] % 12,
                sample["visit"],
                half_duplex=sample["request_policy"] == "half-duplex",
            ),
            encoding="utf-8",
        )
        (neqo / "packets.csv").write_text("direction,monotonic_us\n", encoding="utf-8")
        (neqo / "schedule.csv").write_text("target_time_us,direction,size\n", encoding="utf-8")
        (sample_root / "capture.pcapng").write_bytes(b"synthetic-zero-credit\n")
        experiment_module.accept_sample(root, experiment, sample["sample_id"], eligible=True)
    experiment_module.finalize_experiment(
        root,
        experiment,
        status="complete",
        completed_at="2026-10-01T00:10:00+00:00",
    )
    verification_module.seal_result(root)
    assert verification_module.verify_result(root).experiment["summary"]["accepted"] == 480

    artifacts_root = tmp_path / "diagnostic-numeric-artifacts"
    artifacts_root.mkdir()
    numeric_root = create_numeric_fitting_bundle(
        root,
        artifacts_root=artifacts_root,
        stage=PILOT_STAGE,
        expected_cohort_receipt_path=cohort_path,
        expected_cohort_assembly_receipt_path=assembly_path,
        fitters=_fitters(),
    )
    refitted = verify_numeric_fitting_bundle(
        numeric_root, source_result_root=root, fitters=_fitters()
    )
    assert refitted.stage == PILOT_STAGE
    assert refitted.provenance["fitting_contract"]["samples_consumed"] == 480
    assert refitted.provenance["cohort"]["receipt_sha256"] == admission.cohort_sha256

    first_events = root / plan[0]["path"] / "neqo/events.csv"
    first_events.write_text(first_events.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="modified authoritative evidence"):
        verify_numeric_fitting_bundle(numeric_root, source_result_root=root, fitters=_fitters())


def _qualification_context(
    tmp_path: Path,
    *,
    stage: str,
    workload_ids: Sequence[str],
    profile20: bool = False,
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
                    "schema_version": 3,
                    "workload_id": workload_id,
                    "qualification_source": authority["prepare_source"],
                    "qualification_image_digest": authority["prepare_image_digest"],
                    "qualification_authority": authority,
                    "qualification_authority_sha256": canonical_json_sha256(authority),
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
    if profile20:
        count = CLASS20_PROFILE.pilot_count if stage == PILOT_STAGE else CLASS20_PROFILE.final_count
        cohort = "pilot" if stage == PILOT_STAGE else "final"
        qualification_set = f"{CLASS20_PROFILE.study_id}-{cohort}{count}-full-v1"
    else:
        qualification_set = (
            PILOT_QUALIFICATION_SET if stage == PILOT_STAGE else AUTHORITATIVE_QUALIFICATION_SET
        )
    named: dict[str, Any] = {
        "schema_version": 3,
        "artifact_type": "qcsd-named-chaff-qualification-set",
        "qualification_set": qualification_set,
        "qualification_scope": "full",
        "qualification_sidecar_schema_version": 3,
        "workload_count": len(workload_ids),
        "workload_ids": list(workload_ids),
        "workloads": entries,
        "qualification_authority": authority,
        "qualification_authority_sha256": canonical_json_sha256(authority),
    }
    named["bindings_sha256"] = _named_set_bindings_digest(named)
    (sidecar_root / "_qualification-set.json").write_bytes(canonical_json_bytes(named))

    def loader(sidecar_path: Path, **kwargs: Any) -> Any:
        workload_id = kwargs["workload_id"]
        assert kwargs["expected_sidecar_schema_version"] == 3
        assert kwargs["expected_qualification_authority"] == authority
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


def test_create_only_publishers_recheck_the_exact_source_before_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A post-precheck source substitution must not poison either final path."""

    numeric, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, _cohort_receipt())
    source_result_root, calls = _bind_numeric_publication_source(
        monkeypatch,
        tmp_path,
        inputs,
    )
    verify_numeric_fitting_bundle(
        numeric,
        source_result_root=source_result_root,
        fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
        fitters=_fitters(),
    )

    provenance_path = numeric / "numeric-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["source_result"]["evidence_sha256"] = "f" * 64
    provenance_path.write_bytes(canonical_json_bytes(provenance))
    assert (
        verify_numeric_fitting_bundle(numeric).provenance["source_result"]["evidence_sha256"]
        == "f" * 64
    )

    prefix_artifacts = tmp_path / "prefix-publication"
    final_artifacts = tmp_path / "final-publication"
    prefix_artifacts.mkdir()
    final_artifacts.mkdir()
    context = _qualification_context(
        tmp_path,
        stage=PILOT_STAGE,
        workload_ids=inputs.workload_ids,
    )

    with pytest.raises(ValueError, match="sealed source result"):
        derive_schema_six_prefix_specs(
            numeric,
            source_result_root=source_result_root,
            workload_root=context.workload_root,
            artifacts_root=prefix_artifacts,
        )
    with pytest.raises(ValueError, match="sealed source result"):
        finalize_fitting_bundle(
            numeric,
            source_result_root=source_result_root,
            qualification_manifest_path=context.sidecar_root / "_qualification-set.json",
            qualification_context=context,
            artifacts_root=final_artifacts,
        )

    assert calls == [
        (numeric, source_result_root),
        (numeric, source_result_root),
    ]
    assert list(prefix_artifacts.iterdir()) == []
    assert list(final_artifacts.iterdir()) == []


def test_prefix_derivation_rejects_incomplete_class_coverage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tests.test_manifest import class_study_prepared_manifest

    numeric, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, _cohort_receipt())
    source_result_root, _calls = _bind_numeric_publication_source(
        monkeypatch,
        tmp_path,
        inputs,
    )
    workload_root = tmp_path / "prefix-workloads"
    artifact_root = tmp_path / "prefix-artifacts"
    workload_root.mkdir()
    artifact_root.mkdir()
    incomplete = class_study_prepared_manifest()
    incomplete["preparation"].pop("coverage_admission")
    (workload_root / f"{inputs.workload_ids[0]}.json").write_bytes(canonical_json_bytes(incomplete))

    with pytest.raises(ValueError, match="requires a complete-coverage admission"):
        derive_schema_six_prefix_specs(
            numeric,
            source_result_root=source_result_root,
            workload_root=workload_root,
            artifacts_root=artifact_root,
        )
    assert list(artifact_root.iterdir()) == []


def test_finalization_default_context_rejects_incomplete_class_coverage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tests.test_manifest import class_study_prepared_manifest

    numeric, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, _cohort_receipt())
    source_result_root, _calls = _bind_numeric_publication_source(
        monkeypatch,
        tmp_path,
        inputs,
    )
    context = _qualification_context(
        tmp_path,
        stage=PILOT_STAGE,
        workload_ids=inputs.workload_ids,
    )
    first_id = inputs.workload_ids[0]
    first_path = context.workload_root / f"{first_id}.json"
    incomplete = class_study_prepared_manifest()
    incomplete["preparation"].pop("coverage_admission")
    first_path.write_bytes(canonical_json_bytes(incomplete))
    qualification_path = context.sidecar_root / "_qualification-set.json"
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    qualification["workloads"][0]["workload_manifest"]["sha256"] = sha256_file(first_path)
    qualification["bindings_sha256"] = _named_set_bindings_digest(qualification)
    qualification_path.write_bytes(canonical_json_bytes(qualification))
    strict_context = QualificationContext(
        workload_root=context.workload_root,
        sidecar_root=context.sidecar_root,
        prefix_spec_root=context.prefix_spec_root,
        loader=context.loader,
        prefix_validator=context.prefix_validator,
        require_current_implementation=False,
        qualification_authority=context.qualification_authority,
    )
    final_root = tmp_path / "strict-final-artifacts"
    final_root.mkdir()

    with pytest.raises(ValueError, match="requires a complete-coverage admission"):
        finalize_fitting_bundle(
            numeric,
            source_result_root=source_result_root,
            qualification_manifest_path=qualification_path,
            qualification_context=strict_context,
            artifacts_root=final_root,
        )
    assert list(final_root.iterdir()) == []


def test_final_bundle_policy_qualification_binding_and_tamper_rejection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt = _cohort_receipt()
    numeric, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, receipt)
    source_result_root, calls = _bind_numeric_publication_source(
        monkeypatch,
        tmp_path,
        inputs,
    )
    context = _qualification_context(
        tmp_path,
        stage=PILOT_STAGE,
        workload_ids=inputs.workload_ids,
    )
    final_root = tmp_path / "final-artifacts"
    final_root.mkdir()
    bundle = finalize_fitting_bundle(
        numeric,
        source_result_root=source_result_root,
        qualification_manifest_path=context.sidecar_root / "_qualification-set.json",
        qualification_context=context,
        artifacts_root=final_root,
    )
    assert calls == [(numeric, source_result_root)]
    verified = verify_class_fitting_bundle(bundle, qualification_context=context)
    assert {path.name for path in bundle.iterdir()} == FINAL_FILES
    assert verified.provenance["artifact_type"] == FINAL_ARTIFACT_TYPE
    assert verified.provenance["schema_version"] == FINAL_PROVENANCE_SCHEMA_VERSION
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

    legacy_provenance = json.loads(json.dumps(verified.provenance))
    legacy_provenance["schema_version"] = 1
    with pytest.raises(ValueError, match="pre-publication and non-evidentiary"):
        class_fitting._validate_final_provenance(legacy_provenance)

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
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt = _cohort_receipt()
    numeric, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, receipt)
    source_result_root, _calls = _bind_numeric_publication_source(
        monkeypatch,
        tmp_path,
        inputs,
    )
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
            source_result_root=source_result_root,
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
    source_result_root, _calls = _bind_numeric_publication_source(
        monkeypatch,
        tmp_path,
        inputs,
    )
    context = _qualification_context(
        tmp_path,
        stage=PILOT_STAGE,
        workload_ids=inputs.workload_ids,
    )
    final_parent = tmp_path / "final-artifacts"
    final_parent.mkdir()
    final_root = finalize_fitting_bundle(
        numeric_root,
        source_result_root=source_result_root,
        qualification_manifest_path=context.sidecar_root / "_qualification-set.json",
        qualification_context=context,
        artifacts_root=final_parent,
    )
    finalized = verify_class_fitting_bundle(final_root, qualification_context=context)
    assert finalized.artifact_hashes["walkie_talkie"] != numeric.artifact_hashes["walkie_talkie"]

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
                qualification_authority=qualification_context.qualification_authority,
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
    pilot_fitting_result = tmp_path / "pilot-fitting-result"
    pilot_fitting_result.mkdir()

    def verify_bound_numeric(
        root: Path,
        *,
        source_result_root: Path | None = None,
    ):
        assert root == numeric_root
        assert source_result_root == pilot_fitting_result
        return numeric

    monkeypatch.setattr(
        class_pipeline,
        "verify_numeric_fitting_bundle",
        verify_bound_numeric,
    )
    selection = class_pipeline.build_final_selection_input(
        admission,
        pilot_fitting_result_root=pilot_fitting_result,
        pilot_numeric_bundle_root=numeric_root,
        pilot_compatibility_result_root=compatibility_root,
        qualification_authority=context.qualification_authority,
    )
    bound = selection["payload"]["pilot_compatibility"]
    assert bound["fitted_parameter_sha256"] == compatibility["defense_parameter_sha256"]
    assert bound["finalized_bundle"] == {
        "source": "frozen-pilot-compatibility-inputs",
        "provenance_sha256": sha256_file(final_root / "provenance.json"),
        "artifact_sha256": compatibility["defense_parameter_sha256"],
        "qualification_authority": context.qualification_authority,
        "qualification_authority_sha256": canonical_json_sha256(
            context.qualification_authority
        ),
    }
    graph = tuple(tuple(pair) for pair in selection["payload"]["feasible_pair_graph"])
    assert len(graph) == len(inputs.workload_ids) // 2
    assert {workload_id for pair in graph for workload_id in pair} == set(inputs.workload_ids)
    # Only the pair-specific runtime profiles exercised by the frozen bundle
    # are admitted.  Endpoint qualification under two different profiles does
    # not manufacture an alternate cross-profile edge.
    assert frozenset((graph[0][0], graph[1][0])) not in {frozenset(pair) for pair in graph}
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

    wrong_authority = json.loads(json.dumps(context.qualification_authority))
    wrong_authority["foundation_attestation"] = {
        "path": "/evidence/other-foundation.json",
        "sha256": "8" * 64,
        "payload_sha256": "9" * 64,
    }
    wrong_authority["build_execution"] = {
        "path": "/evidence/other-build.json",
        "sha256": "a" * 64,
    }
    wrong_authority["build_execution_identity"]["sha256"] = "a" * 64
    wrong_authority["prepare_image_digest"] = "sha256:" + "b" * 64
    wrong_authority["prepare_source"]["image_digest"] = wrong_authority[
        "prepare_image_digest"
    ]
    compatibility["class_study_foundation_sha256"] = wrong_authority[
        "foundation_attestation"
    ]["sha256"]
    with pytest.raises(ValueError, match="expected foundation"):
        class_pipeline.build_final_selection_input(
            admission,
            pilot_fitting_result_root=pilot_fitting_result,
            pilot_numeric_bundle_root=numeric_root,
            pilot_compatibility_result_root=compatibility_root,
            qualification_authority=wrong_authority,
        )
    compatibility["class_study_foundation_sha256"] = context.qualification_authority[
        "foundation_attestation"
    ]["sha256"]

    compatibility["defense_parameter_sha256"] = {
        **compatibility["defense_parameter_sha256"],
        "walkie-talkie": numeric.artifact_hashes["walkie_talkie"],
    }
    with pytest.raises(ValueError, match="exact pilot fitted parameters"):
        class_pipeline.build_final_selection_input(
            admission,
            pilot_fitting_result_root=pilot_fitting_result,
            pilot_numeric_bundle_root=numeric_root,
            pilot_compatibility_result_root=compatibility_root,
            qualification_authority=context.qualification_authority,
        )


def test_final_selection_rejects_self_consistent_numeric_source_substitution_before_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An internally valid bundle cannot replace the selected fitting result."""

    receipt = _cohort_receipt()
    numeric_root, inputs = _numeric_bundle(tmp_path, PILOT_STAGE, receipt)
    provenance_path = numeric_root / "numeric-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["source_result"]["evidence_sha256"] = "f" * 64
    provenance_path.write_bytes(canonical_json_bytes(provenance))

    # The substitution is deliberately self-consistent within the numeric
    # directory.  Only reopening the selected source result exposes it.
    unbound = verify_numeric_fitting_bundle(numeric_root)
    assert unbound.provenance["source_result"]["evidence_sha256"] == "f" * 64

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
    selected_result = tmp_path / "selected-pilot-fitting-result"
    selected_result.mkdir()
    destination = tmp_path / "final-selection.json"
    numeric_calls: list[tuple[Path, Path | None]] = []

    def verify_bound_numeric(
        root: Path,
        *,
        source_result_root: Path | None = None,
    ):
        numeric_calls.append((root, source_result_root))
        return verify_numeric_fitting_bundle(
            root,
            source_result_root=source_result_root,
            fitting_inputs_loader=lambda *_args, **_kwargs: inputs,
            fitters=_fitters(),
        )

    monkeypatch.setattr(
        class_pipeline,
        "require_canonical_fresh_child",
        lambda *_args, **_kwargs: destination,
    )
    monkeypatch.setattr(class_pipeline, "_require_fresh_admission_paths", lambda *_a, **_k: None)
    monkeypatch.setattr(class_pipeline, "require_canonical_fresh_path", lambda *_a, **_k: None)
    monkeypatch.setattr(
        class_pipeline,
        "verify_numeric_fitting_bundle",
        verify_bound_numeric,
    )
    monkeypatch.setattr(
        class_pipeline,
        "verify_class_study_result",
        lambda *_args, **_kwargs: pytest.fail(
            "pilot compatibility was read after numeric source substitution"
        ),
    )
    monkeypatch.setattr(
        class_pipeline,
        "_write_or_verify_bytes",
        lambda *_args, **_kwargs: pytest.fail(
            "final-selection destination was written after numeric source substitution"
        ),
    )

    with pytest.raises(ValueError, match="sealed source result"):
        class_pipeline.write_final_selection_input(
            destination,
            pilot_admission=admission,
            pilot_fitting_result_root=selected_result,
            pilot_numeric_bundle_root=numeric_root,
            pilot_compatibility_result_root=tmp_path / "pilot-compatibility-result",
            qualification_authority=_qualification_authority(),
        )

    assert numeric_calls == [(numeric_root, selected_result)]
    assert not destination.exists()


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
    monkeypatch.setattr(
        qualification,
        "_primary_origin_prefix_projection",
        lambda _manifest, *, workload_id, component_count: ("https://class-a.test", [[0]], []),
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
    assert spec["schema_version"] == 4
    assert spec["qualification_scope"] == "primary-origin-capacity-v1"
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


def _multiorigin_schema_six_prefix_inputs(
    bursts: list[dict[str, int]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    from tests.test_capture_acceptance import _controlled_complex_manifest

    manifest = _controlled_complex_manifest("127.0.0.1", 4433, "127.0.0.2", 4434)
    walkie = {
        "schema_version": 6,
        "packet_size": 1200,
        "profiles": [{"real": "complex", "decoy": "other", "bursts": bursts}],
    }
    return manifest, walkie


def test_schema_four_prefix_preserves_graph_depth_and_primary_origin_capacity() -> None:
    manifest, walkie = _multiorigin_schema_six_prefix_inputs(
        [
            {"outgoing": 4, "incoming": 129},
            {"outgoing": 1, "incoming": 0},
            {"outgoing": 1, "incoming": 0},
        ]
    )
    spec = build_schema_six_prefix_spec(
        "complex",
        walkie,
        source_walkie_talkie_artifact_sha256="a" * 64,
        application_manifest=manifest,
    )

    assert spec["schema_version"] == 4
    assert spec["qualification_scope"] == "primary-origin-capacity-v1"
    assert spec["primary_origin"] == "https://127.0.0.1:4433"
    assert [stage["application_resource_ids"] for stage in spec["stream_activation_stages"]] == [
        [0], [1], [],
    ]
    assert [stage["application_body_floor_bytes"] for stage in spec["stream_activation_stages"]] == [
        131_072, 1_024, 0,
    ]
    expected = {row["resource_id"]: row for row in manifest["preparation"]["expected_responses"]}
    assert spec["unproven_application_resources"] == [
        {
            "resource_id": resource["id"],
            "url": resource["url"],
            "status": expected[resource["id"]]["status"],
            "bytes": expected[resource["id"]]["bytes"],
            "body_sha256": expected[resource["id"]]["body_sha256"],
            "reason": "secondary-origin",
        }
        for resource in manifest["resources"][2:]
    ]
    assert class_fitting.validate_schema_six_prefix_spec(
        spec,
        workload_id="complex",
        walkie_talkie=walkie,
        source_walkie_talkie_artifact_sha256="a" * 64,
        application_manifest=manifest,
    ) == spec


def test_schema_four_prefix_ledger_covers_all_unrequested_resources() -> None:
    manifest, walkie = _multiorigin_schema_six_prefix_inputs(
        [{"outgoing": 4, "incoming": 1}]
    )
    spec = build_schema_six_prefix_spec(
        "complex",
        walkie,
        source_walkie_talkie_artifact_sha256="a" * 64,
        application_manifest=manifest,
    )
    assert [row["resource_id"] for row in spec["unproven_application_resources"]] == [1, 2, 3]
    assert [row["reason"] for row in spec["unproven_application_resources"]] == [
        "outside-prefix-components", "secondary-origin", "secondary-origin",
    ]
    assert [row["application_resource_ids"] for row in spec["stream_activation_stages"]] == [[0]]


@pytest.mark.parametrize(
    "mutation",
    (
        lambda spec: spec.update(qualification_scope="full-graph"),
        lambda spec: spec.update(primary_origin="https://127.0.0.2:4434"),
        lambda spec: spec["unproven_application_resources"].pop(),
        lambda spec: spec["unproven_application_resources"].reverse(),
        lambda spec: spec["unproven_application_resources"][0].update(bytes=1),
        lambda spec: spec["unproven_application_resources"][1].update(reason="outside-prefix-components"),
    ),
)
def test_schema_four_prefix_rejects_projection_tampering(mutation: Any) -> None:
    manifest, walkie = _multiorigin_schema_six_prefix_inputs(
        [{"outgoing": 4, "incoming": 1}]
    )
    spec = build_schema_six_prefix_spec(
        "complex",
        walkie,
        source_walkie_talkie_artifact_sha256="a" * 64,
        application_manifest=manifest,
    )
    tampered = json.loads(json.dumps(spec))
    mutation(tampered)
    with pytest.raises(ValueError, match="primary-origin projection"):
        validate_schema_six_prefix_spec_shape(
            tampered, workload_id="complex", application_manifest=manifest
        )


def test_historical_schema_three_prefix_is_verifiable_but_new_spec_is_scoped() -> None:
    manifest, walkie = _multiorigin_schema_six_prefix_inputs(
        [
            {"outgoing": 4, "incoming": 129},
            {"outgoing": 1, "incoming": 0},
            {"outgoing": 1, "incoming": 0},
        ]
    )
    historical = build_schema_six_prefix_spec(
        "complex",
        walkie,
        source_walkie_talkie_artifact_sha256="a" * 64,
        application_manifest=manifest,
        _historical_schema_three=True,
    )
    assert historical["schema_version"] == 3
    assert "qualification_scope" not in historical
    assert [stage["application_resource_ids"] for stage in historical["stream_activation_stages"]] == [
        [0], [1, 2], [3],
    ]
    assert class_fitting.validate_schema_six_prefix_spec(
        historical,
        workload_id="complex",
        walkie_talkie=walkie,
        source_walkie_talkie_artifact_sha256="a" * 64,
        application_manifest=manifest,
    ) == historical
    polluted = {**historical, "qualification_scope": "primary-origin-capacity-v1"}
    with pytest.raises(ValueError, match="exact schema"):
        validate_schema_six_prefix_spec_shape(
            polluted, workload_id="complex", application_manifest=manifest
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
