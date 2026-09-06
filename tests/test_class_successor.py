from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from qcsd_lab import (
    buflo_study,
    chaff_qualification,
    class_attestation,
    class_layout,
    orchestrator,
)
from qcsd_lab import class_pipeline as pipeline
from qcsd_lab import class_successor as successor
from qcsd_lab.class_study import (
    COMPATIBILITY_MODES,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    CohortSelection,
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    validate_hash_bound_receipt,
)
from qcsd_lab.parameters import ParameterArtifact
from qcsd_lab.util import sha256_file
from qcsd_lab.verification import VerifiedResult


def _candidate(stratum_index: int, member: int) -> ClassCandidate:
    stratum = TRANCO_RANK_STRATA[stratum_index]
    return ClassCandidate(
        candidate_id=f"s{stratum_index}-{member:02d}",
        domain=f"s{stratum_index}-{member:02d}.example",
        rank=stratum.minimum_rank + member,
        eligible=True,
    )


def _within_stratum_predecessor(*, reverse_graph: bool = False) -> CohortSelection:
    members = tuple(
        tuple(_candidate(stratum_index, member) for member in range(24))
        for stratum_index in range(5)
    )
    pilot = tuple(candidate for stratum in members for candidate in stratum)
    final = tuple(candidate for stratum in members for candidate in stratum[:20])
    reserves = tuple(candidate for stratum in members for candidate in stratum[20:])
    graph = tuple(
        (stratum[index].candidate_id, stratum[index + 1].candidate_id)
        for stratum in members
        for index in range(0, 24, 2)
    )
    matching = tuple(
        (stratum[index].candidate_id, stratum[index + 1].candidate_id)
        for stratum in members
        for index in range(0, 20, 2)
    )
    return CohortSelection(
        candidates=pilot,
        pilot=pilot,
        final=final,
        reserves=reserves,
        feasible_pairs=tuple(reversed(graph)) if reverse_graph else graph,
        matching=tuple(reversed(matching)) if reverse_graph else matching,
    )


def _cross_stratum_predecessor() -> CohortSelection:
    members = tuple(
        tuple(_candidate(stratum_index, member) for member in range(24))
        for stratum_index in range(5)
    )
    pilot = tuple(candidate for stratum in members for candidate in stratum)
    final = tuple(candidate for stratum in members for candidate in stratum[:20])
    reserves = tuple(candidate for stratum in members for candidate in stratum[20:])
    graph: list[tuple[str, str]] = [
        (members[0][0].candidate_id, members[1][0].candidate_id),
        (members[0][1].candidate_id, members[1][1].candidate_id),
    ]
    matching = list(graph)
    for stratum_index in (0, 1):
        for index in range(2, 20, 2):
            pair = (
                members[stratum_index][index].candidate_id,
                members[stratum_index][index + 1].candidate_id,
            )
            graph.append(pair)
            matching.append(pair)
        graph.extend(
            (
                (
                    members[stratum_index][20].candidate_id,
                    members[stratum_index][21].candidate_id,
                ),
                (
                    members[stratum_index][22].candidate_id,
                    members[stratum_index][23].candidate_id,
                ),
            )
        )
    for stratum_index in (2, 3, 4):
        for index in range(0, 24, 2):
            pair = (
                members[stratum_index][index].candidate_id,
                members[stratum_index][index + 1].candidate_id,
            )
            graph.append(pair)
            if index < 20:
                matching.append(pair)
    return CohortSelection(
        candidates=pilot,
        pilot=pilot,
        final=final,
        reserves=reserves,
        feasible_pairs=tuple(graph),
        matching=tuple(matching),
    )


def test_single_failure_replaces_its_whole_qualified_pair() -> None:
    predecessor = _within_stratum_predecessor()

    selected = successor.select_successor_cohort(predecessor, ["s0-00"])

    assert selected.failed_class_ids == ("s0-00",)
    assert selected.replaced_predecessor_ids == ("s0-00", "s0-01")
    assert selected.activated_reserve_ids == ("s0-20", "s0-21")
    assert len(selected.final) == 100
    assert len(selected.reserves) == 20
    assert len(selected.matching) == 50
    assert selected.as_dict()["final_per_stratum"] == {
        stratum.id: 20 for stratum in TRANCO_RANK_STRATA
    }


def test_quota_repair_can_require_cascading_pair_replacement() -> None:
    predecessor = _cross_stratum_predecessor()

    selected = successor.select_successor_cohort(predecessor, ["s0-00"])

    assert set(selected.replaced_predecessor_ids) == {
        "s0-00",
        "s1-00",
        "s0-01",
        "s1-01",
    }
    assert set(selected.activated_reserve_ids) == {
        "s0-20",
        "s0-21",
        "s1-20",
        "s1-21",
    }
    assert selected.as_dict()["final_per_stratum"] == {
        stratum.id: 20 for stratum in TRANCO_RANK_STRATA
    }


def test_multiple_failures_are_all_excluded_with_maximum_retention() -> None:
    predecessor = _within_stratum_predecessor()

    selected = successor.select_successor_cohort(
        predecessor,
        ["s2-00", "s0-00", "s2-00"],
    )

    assert selected.failed_class_ids == ("s0-00", "s2-00")
    assert set(selected.replaced_predecessor_ids) == {
        "s0-00",
        "s0-01",
        "s2-00",
        "s2-01",
    }
    assert len(selected.retained_predecessor_ids) == 96


def test_iterative_selection_uses_root_graph_and_cumulative_failures() -> None:
    authority = _within_stratum_predecessor()
    first = successor.select_successor_cohort(authority, ["s0-00"])
    incumbent = CohortSelection(
        candidates=authority.candidates,
        pilot=authority.pilot,
        final=first.final,
        reserves=first.reserves,
        feasible_pairs=first.matching,
        matching=first.matching,
    )

    second = successor.select_successor_cohort(
        authority,
        ["s0-00", "s1-00"],
        incumbent=incumbent,
    )

    assert second.failed_class_ids == ("s0-00", "s1-00")
    assert {"s0-00", "s1-00"}.isdisjoint(candidate.candidate_id for candidate in second.final)
    assert set(second.replaced_predecessor_ids) == {"s1-00", "s1-01"}
    assert set(second.activated_reserve_ids) == {"s1-20", "s1-21"}
    root_edges = {frozenset(pair) for pair in authority.feasible_pairs or ()}
    assert len(root_edges) == 60
    assert len(incumbent.feasible_pairs or ()) == 50
    assert all(frozenset(pair) in root_edges for pair in second.matching)


def test_generated_g02_cohort_rebinds_root_evidence_for_reactivated_edge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _within_stratum_predecessor()
    first = successor.select_successor_cohort(authority, ["s0-00"])
    incumbent = CohortSelection(
        candidates=authority.candidates,
        pilot=authority.pilot,
        final=first.final,
        reserves=first.reserves,
        feasible_pairs=first.matching,
        matching=first.matching,
    )
    second = successor.select_successor_cohort(
        authority,
        ["s0-00", "s1-00"],
        incumbent=incumbent,
    )
    generated_selection = CohortSelection(
        candidates=authority.candidates,
        pilot=authority.pilot,
        final=second.final,
        reserves=second.reserves,
        feasible_pairs=second.matching,
        matching=second.matching,
    )

    predecessor_cohort = tmp_path / "g01-cohort.json"
    predecessor_assembly = tmp_path / "g01-assembly.json"
    root_final_selection = tmp_path / "root-final-selection.json"
    predecessor_cohort.write_text('{"fixture":"cohort"}\n', encoding="utf-8")
    predecessor_assembly.write_text('{"fixture":"assembly"}\n', encoding="utf-8")
    root_final_value = _final_selection_receipt(authority)
    root_final_selection.write_bytes(canonical_json_bytes(root_final_value))

    decision = {
        "evidence": {
            "predecessor_cohort": successor._file_binding(predecessor_cohort),
            "predecessor_cohort_assembly": successor._file_binding(predecessor_assembly),
        },
        "successor_selection": second.as_dict(),
        "selection_authority": {
            "final_selection": successor._file_binding(root_final_selection),
        },
        "replacement_lineage": {
            "generation": 2,
            "cumulative_failed_class_ids": ["s0-00", "s1-00"],
        },
    }
    compatible = bind_receipt(
        {"fixture": "generated-g02-cohort"},
        receipt_type="qcsd-class-study-cohort",
    )
    predecessor_value = {"payload": {"tranco": {"list_id": "TEST", "list_sha256": "a" * 64}}}
    predecessor_selection_binding = {
        "path": "successor-final-selection.json",
        "sha256": "1" * 64,
        "payload_sha256": "2" * 64,
        "payload": root_final_value["payload"],
    }

    monkeypatch.setattr(
        successor,
        "load_study_receipt",
        lambda _path: (predecessor_value, incumbent),
    )
    monkeypatch.setattr(successor, "build_study_receipt", lambda *_args, **_kwargs: compatible)
    monkeypatch.setattr(
        successor,
        "validate_study_receipt",
        lambda _value: generated_selection,
    )

    def validate_assembly(
        value: dict[str, Any],
        *,
        cohort: dict[str, Any],
    ) -> dict[str, Any]:
        if value == {"fixture": "assembly"}:
            return {"final_selection": predecessor_selection_binding}
        payload = validate_hash_bound_receipt(
            value,
            expected_type="qcsd-class-study-cohort-assembly",
        )
        final_binding = payload["final_selection"]
        final_value = bind_receipt(
            final_binding["payload"],
            receipt_type=successor.FINAL_SELECTION_RECEIPT_TYPE,
        )
        successor._validate_final_selection_receipt(
            final_value,
            generated_selection,
        )
        assert cohort == compatible
        return payload

    monkeypatch.setattr(
        successor,
        "validate_cohort_assembly_receipt",
        validate_assembly,
    )

    generated_cohort, generated_assembly, final_value = (
        successor._successor_compatible_cohort_files(decision)
    )
    final_payload = successor._validate_final_selection_receipt(
        final_value,
        generated_selection,
    )
    graph = final_payload["feasible_pair_graph"]
    matching = final_payload["selected_final_perfect_matching"]
    evidence = final_payload["feasible_pair_evidence"]
    evidence_pairs = {frozenset((record["left"], record["right"])) for record in evidence}
    reactivated = frozenset(("s1-20", "s1-21"))

    assert generated_cohort == compatible
    assert (
        validate_hash_bound_receipt(
            generated_assembly,
            expected_type="qcsd-class-study-cohort-assembly",
        )["final_selection"]["payload"]
        == final_payload
    )
    assert len(graph) == len(matching) == len(evidence) == 50
    assert graph == matching == [list(pair) for pair in second.matching]
    assert evidence_pairs == {frozenset(pair) for pair in second.matching}
    assert reactivated in evidence_pairs
    assert reactivated not in {frozenset(pair) for pair in first.matching}
    assert reactivated in {frozenset(pair) for pair in authority.feasible_pairs or ()}


def test_successor_fails_when_failed_edges_exceed_a_stratum_quota() -> None:
    predecessor = _within_stratum_predecessor()

    failures = ["s0-00", "s0-02", "s0-04"]
    messages = []
    for ordered in (failures, list(reversed(failures))):
        with pytest.raises(ValueError, match="quota-feasible") as caught:
            successor.select_successor_cohort(predecessor, ordered)
        messages.append(str(caught.value))
    assert messages[0] == messages[1]


def test_successor_uses_no_unqualified_edge_and_is_order_deterministic() -> None:
    first_predecessor = _within_stratum_predecessor()
    reversed_predecessor = _within_stratum_predecessor(reverse_graph=True)

    first = successor.select_successor_cohort(
        first_predecessor,
        ["s3-00", "s0-00"],
    )
    second = successor.select_successor_cohort(
        reversed_predecessor,
        ["s0-00", "s3-00"],
    )

    assert first.as_dict() == second.as_dict()
    qualified = {frozenset(pair) for pair in first_predecessor.feasible_pairs or ()}
    assert all(frozenset(pair) in qualified for pair in first.matching)


def test_successor_rejects_a_nonmatching_or_unqualified_graph() -> None:
    predecessor = _within_stratum_predecessor()
    graph = list(predecessor.feasible_pairs or ())
    graph[0] = (graph[0][0], graph[1][0])
    substituted = CohortSelection(
        candidates=predecessor.candidates,
        pilot=predecessor.pilot,
        final=predecessor.final,
        reserves=predecessor.reserves,
        feasible_pairs=tuple(graph),
        matching=predecessor.matching,
    )

    with pytest.raises(ValueError, match="one-to-one"):
        successor.select_successor_cohort(substituted, ["s0-00"])


def test_successor_policy_is_create_only_hash_bound_and_explicit(tmp_path: Path) -> None:
    path = successor.create_successor_policy(tmp_path / "policy.json")
    payload = successor.validate_successor_policy(path)

    assert payload["predecessor_mutation_permitted"] is False
    assert payload["root_study_id"] == STUDY_ID
    assert payload["successor_identity"]["study_id"].startswith(
        f"{successor.SUCCESSOR_STUDY_PREFIX}-g<generation>-"
    )
    assert payload["failure_policy"] == {
        "source": "sealed-incomplete-900-cell-first-launch-certification-only",
        "class_incompatibility_types": [
            {
                "stage": "fidelity",
                "type": "StrictPreparedResponseIdentityFailure",
            }
        ],
        "class_incompatibility_proof": (
            "undefended-prepared-response-identity-failure-for-the-same-workload"
        ),
        "defense_fidelity_or_defended_correctness_authorises_replacement": False,
        "capture_infrastructure_or_unclassified_failure_authorises_replacement": False,
        "all_failed_classes_excluded": True,
        "manual_failure_classification_permitted": False,
    }
    assert payload["generation_policy"] == {
        "iterative_successors_permitted": True,
        "original_selection_authority_retained": True,
        "cumulative_failed_classes_may_reenter": False,
        "distinct_hash_namespace_per_generation": True,
        "quota_or_reserve_exhaustion": "fail-closed-new-acquisition-cohort-required",
        "authorised_formal_capture_may_precede_replacement": False,
    }
    assert payload["downstream_restart"] == {
        "authoritative_fitting_samples": 2_000,
        "final_qualification_executions": 600,
        "first_launch_certification_cells": 900,
        "certification_scope": "complete-100-class-by-9-mode-cross-product",
        "reuse_predecessor_authoritative_artifacts": False,
        "all_downstream_gates_restart": True,
    }
    with pytest.raises(FileExistsError, match="create-only"):
        successor.create_successor_policy(path)

    value = json.loads(path.read_text(encoding="utf-8"))
    value["payload"]["predecessor_mutation_permitted"] = True
    path.write_bytes(canonical_json_bytes(value))
    with pytest.raises(ValueError, match="SHA-256"):
        successor.validate_successor_policy(path)


def test_successor_readiness_public_create_and_validate_reconstruct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    study_id = "classifier-multiorigin100-v2-g01-123456789abc"
    restart = tmp_path / "successor-restart.json"
    foundation = tmp_path / "foundation.json"
    restart.write_text("restart\n", encoding="utf-8")
    foundation.write_text("foundation\n", encoding="utf-8")

    fitting_result = tmp_path / "authoritative-fitting-result"
    certification_result = tmp_path / "certification-result"
    for root in (fitting_result, certification_result):
        root.mkdir()
        (root / "evidence.sha256").write_text("seal\n", encoding="utf-8")
        (root / "experiment.json").write_text("{}\n", encoding="utf-8")
    fitting_bundle = tmp_path / "authoritative-fitting-bundle"
    fitting_bundle.mkdir()
    (fitting_bundle / "provenance.json").write_text("{}\n", encoding="utf-8")
    workload_root = tmp_path / "workloads"
    sidecar_root = tmp_path / "qualification"
    prefix_root = tmp_path / "prefix"
    for root in (workload_root, sidecar_root, prefix_root):
        root.mkdir()

    def result_binding(root: Path) -> dict[str, str]:
        return {
            "root": str(root.resolve()),
            "evidence_sha256": sha256_file(root / "evidence.sha256"),
            "experiment_sha256": sha256_file(root / "experiment.json"),
        }

    payload = {
        "attestation_schema_version": 1,
        "artifact_type": successor.READINESS_RECEIPT_TYPE,
        "study_id": study_id,
        "evidence": {
            "successor_restart": successor._file_binding(restart),
            "foundation": successor._file_binding(foundation),
            "authoritative_fitting_result": result_binding(fitting_result),
            "authoritative_fitting_bundle": {
                "root": str(fitting_bundle.resolve()),
                "provenance": "provenance.json",
                "provenance_sha256": sha256_file(fitting_bundle / "provenance.json"),
                "artifacts": {},
            },
            "qualification_context": {
                "workload_root": {"root": str(workload_root.resolve())},
                "sidecar_root": {"root": str(sidecar_root.resolve())},
                "prefix_spec_root": {"root": str(prefix_root.resolve())},
            },
            "certification_result": result_binding(certification_result),
        },
        "summary": {
            "authoritative_fitting_samples": 2_000,
            "final_qualification_executions": 600,
            "certification_samples": 900,
            "predecessor_downstream_evidence_reused": False,
        },
    }
    calls: list[bool] = []

    def reconstruct(**inputs: object) -> dict[str, Any]:
        calls.append(bool(inputs["deep_code_gate"]))
        assert Path(inputs["restart_receipt"]).resolve() == restart.resolve()
        assert Path(inputs["foundation_attestation"]).resolve() == foundation.resolve()
        assert (
            Path(inputs["authoritative_fitting_result_root"]).resolve() == fitting_result.resolve()
        )
        assert Path(inputs["certification_result_root"]).resolve() == certification_result.resolve()
        return payload

    monkeypatch.setattr(successor, "_successor_readiness_value", reconstruct)
    destination = tmp_path / "successor-readiness.json"
    created = successor.create_successor_readiness(
        destination,
        restart_receipt=restart,
        foundation_attestation=foundation,
        authoritative_fitting_result_root=fitting_result,
        authoritative_fitting_bundle_root=fitting_bundle,
        qualification_workload_root=workload_root,
        qualification_sidecar_root=sidecar_root,
        qualification_prefix_root=prefix_root,
        certification_result_root=certification_result,
    )
    verified = successor.validate_successor_readiness(created)

    assert verified["study_id"] == study_id
    assert verified["summary"]["authoritative_fitting_samples"] == 2_000
    assert calls == [True, False, True]
    with pytest.raises(FileExistsError):
        successor.create_successor_readiness(
            destination,
            restart_receipt=restart,
            foundation_attestation=foundation,
            authoritative_fitting_result_root=fitting_result,
            authoritative_fitting_bundle_root=fitting_bundle,
            qualification_workload_root=workload_root,
            qualification_sidecar_root=sidecar_root,
            qualification_prefix_root=prefix_root,
            certification_result_root=certification_result,
        )


def _pair_evidence(left: str, right: str) -> dict[str, Any]:
    digest = hashlib.sha256(f"{left}\0{right}".encode()).hexdigest()
    return {
        "left": left,
        "right": right,
        "runtime_profile_real": right,
        "runtime_profile_decoy": left,
        "runtime_profile_sha256": digest,
        "endpoint_qualification": [
            {
                "workload_id": workload_id,
                "chaff_qualification_sidecar_sha256": digest,
                "prefix_pack_spec_sha256": digest,
                "qualified_chaff_manifest_sha256": digest,
                "qualified_parallel_chaff_streams": 8,
                "walkie_talkie_required_chaff_streams": 6,
            }
            for workload_id in (left, right)
        ],
    }


def _pilot_lineage_evidence() -> tuple[dict[str, Any], dict[str, Any]]:
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    source_result = {
        "campaign": f"{STUDY_ID}-pilot-fitting-1200",
        "evidence_sha256": "7" * 64,
        "experiment_sha256": "8" * 64,
        "input_digest": "9" * 64,
        "campaign_sha256": "a" * 64,
        "source_fingerprints": {
            "image_digest": "sha256:" + "b" * 64,
            "lab_commit": "c" * 40,
            "lab_dirty": False,
            "lab_patch_sha256": empty,
            "neqo_commit": "d" * 40,
            "neqo_pinned_commit": "d" * 40,
            "neqo_dirty": False,
            "neqo_patch_sha256": empty,
        },
    }
    parameters = {
        "traffic-morphing": "e" * 64,
        "wtf-pad": "f" * 64,
        "walkie-talkie": "0" * 64,
    }
    collection_source = source_result["source_fingerprints"]
    prepare_image = "sha256:" + "1" * 64
    qualification_authority = {
        "schema_version": 1,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": {
            "path": "/evidence/foundation.json",
            "sha256": "2" * 64,
            "payload_sha256": "3" * 64,
        },
        "build_execution": {"path": "/evidence/build.json", "sha256": "4" * 64},
        "build_execution_identity": {
            "cohort_version": 23,
            "sha256": "4" * 64,
            "collection_image": collection_source["image_digest"],
            "started_at": "2026-08-28T00:00:00+00:00",
            "finished_at": "2026-08-28T01:00:00+00:00",
        },
        "collection_source": collection_source,
        "prepare_source": {**collection_source, "image_digest": prepare_image},
        "prepare_image_digest": prepare_image,
    }
    return (
        {
            "numeric_provenance_sha256": "1" * 64,
            "walkie_talkie_artifact_sha256": "2" * 64,
            "source_result": source_result,
        },
        {
            "campaign": f"{STUDY_ID}-pilot-compatibility-1080-1200",
            "evidence_sha256": "3" * 64,
            "experiment_sha256": "4" * 64,
            "accepted_samples": 1_080,
            "unique_class_mode_pairs": 1_080,
            "fitted_parameter_sha256": parameters,
            "finalized_bundle": {
                "source": "frozen-pilot-compatibility-inputs",
                "provenance_sha256": "5" * 64,
                "artifact_sha256": parameters,
                "qualification_authority": qualification_authority,
                "qualification_authority_sha256": canonical_json_sha256(
                    qualification_authority
                ),
            },
        },
    )


def _final_selection_receipt(predecessor: CohortSelection) -> dict[str, Any]:
    numeric, compatibility = _pilot_lineage_evidence()
    qualified_edges = len(predecessor.feasible_pairs or ())
    possible_edges = 120 * 119 // 2
    payload = {
        "study_id": STUDY_ID,
        "selection_schema_version": pipeline.FINAL_SELECTION_SCHEMA_VERSION,
        "selection_policy": "tranco-bound-order-with-qualified-selected-wt6-pairs",
        "pilot_cohort": {"sha256": "1" * 64, "payload_sha256": "2" * 64},
        "pilot_cohort_assembly": {
            "sha256": "3" * 64,
            "payload_sha256": "4" * 64,
        },
        "pilot_numeric_fitting": numeric,
        "pilot_compatibility": compatibility,
        "feasible_pair_rule": {
            "source": ("finalized-selected-wt6-profile-and-both-endpoint-qualification"),
            "candidate_unordered_pairs": possible_edges,
            "qualified_pair_edges": qualified_edges,
            "unqualified_alternate_pairs_excluded": possible_edges - qualified_edges,
            "pair_specific_finalized_runtime_profile_required": True,
            "both_endpoint_frozen_prefix_qualification_required": True,
            "unselected_pairs_inferred_from_endpoint_compatibility": False,
            "numeric_fit_selected_runtime_profiles_used": True,
            "final_20_per_stratum_perfect_matching_required": True,
            "classifier_outcomes_used": False,
            "measured_bandwidth_latency_or_privacy_outcomes_used": False,
        },
        "feasible_pair_evidence": [
            _pair_evidence(left, right) for left, right in predecessor.feasible_pairs or ()
        ],
        "feasible_pair_graph": [list(pair) for pair in predecessor.feasible_pairs or ()],
        "selected_final_perfect_matching": [list(pair) for pair in predecessor.matching or ()],
    }
    return bind_receipt(
        payload,
        receipt_type=successor.FINAL_SELECTION_RECEIPT_TYPE,
    )


def _decision_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    failures: dict[tuple[str, str], dict[str, Any]],
    predecessor: CohortSelection | None = None,
    study_id: str = STUDY_ID,
    predecessor_restart: Path | None = None,
) -> tuple[dict[str, Path], VerifiedResult]:
    predecessor = predecessor or _within_stratum_predecessor()
    monkeypatch.setattr(class_layout.util, "LAB_ROOT", tmp_path)
    policy = successor.create_successor_policy(tmp_path / "policy.json")
    study_config_root = tmp_path / "config/class-study/v1"
    study_config_root.mkdir(parents=True)
    cohort = study_config_root / class_layout.AUTHORITATIVE_COHORT_FILENAME
    cohort.write_text("{}\n", encoding="utf-8")
    final_selection = study_config_root / class_layout.FINAL_SELECTION_FILENAME
    final_selection_value = _final_selection_receipt(predecessor)
    final_selection.write_bytes(canonical_json_bytes(final_selection_value))
    assembly = study_config_root / class_layout.AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME
    assembly.write_text("{}\n", encoding="utf-8")
    foundation = tmp_path / "foundation.json"
    foundation.write_text("{}\n", encoding="utf-8")

    source = {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": "3" * 64,
        "neqo_commit": "4" * 40,
        "neqo_pinned_commit": "4" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": "5" * 64,
    }
    build = {
        "cohort_version": 23,
        "sha256": "6" * 64,
        "collection_image": source["image_digest"],
        "started_at": "2026-08-28T00:00:00+00:00",
        "finished_at": "2026-08-28T00:01:00+00:00",
    }
    result = tmp_path / "certification"
    inputs = result / "inputs"
    inputs.mkdir(parents=True)
    certification_name = f"{study_id}-certification-900-1200"
    if predecessor_restart is None:
        campaign_root = tmp_path / "config" / class_layout.CAMPAIGN_DIRECTORY
        campaign_root.mkdir(parents=True)
        authoritative_campaign = campaign_root / f"{certification_name}.yml"
        authoritative_campaign.write_text(
            f"name: {certification_name}\nfixture: true\n",
            encoding="utf-8",
        )
    else:
        authoritative_campaign = (
            predecessor_restart.parent / "campaigns" / f"{certification_name}.yml"
        )
        if not authoritative_campaign.exists():
            authoritative_campaign.parent.mkdir(parents=True, exist_ok=True)
            authoritative_campaign.write_text(
                f"name: {certification_name}\nfixture: true\n",
                encoding="utf-8",
            )
    frozen = {
        "inputs/campaign.yml": authoritative_campaign,
        "inputs/class-study-cohort.json": cohort,
        "inputs/class-study-cohort-assembly.json": assembly,
        "inputs/class-study-foundation.json": foundation,
    }
    if predecessor_restart is not None:
        frozen["inputs/class-study-successor.json"] = predecessor_restart
    for relative, source_path in frozen.items():
        (result / relative).write_bytes(source_path.read_bytes())
    launch = inputs / "class-study-launch.json"
    launch.write_text('{"launch":"first"}\n', encoding="utf-8")
    environment = inputs / "study-environment.json"
    environment.write_text("{}\n", encoding="utf-8")
    experiment_file = result / "experiment.json"
    experiment_file.write_text('{"sealed":"fixture"}\n', encoding="utf-8")
    evidence = result / "evidence.sha256"
    evidence.write_text("sealed fixture\n", encoding="utf-8")

    samples: list[dict[str, Any]] = []
    accepted: dict[str, dict[str, str]] = {}
    producer_failures: dict[str, dict[str, Any]] = {}
    for candidate in predecessor.final:
        for defense in COMPATIBILITY_MODES:
            sample_id = f"{candidate.candidate_id}-{defense}"
            failure = failures.get((candidate.candidate_id, defense))
            sample = {
                "sample_id": sample_id,
                "workload_id": candidate.candidate_id,
                "defense": defense,
                "visit": 0,
                "request_policy": "as-defined",
                "attempts": 1,
                "state": "failed" if failure is not None else "accepted",
                "eligible": failure is None,
                "failure": failure,
            }
            samples.append(sample)
            if failure is None:
                accepted[sample_id] = {}
            else:
                producer_failures[sample_id] = json.loads(canonical_json_bytes(failure))
                (result / "failures" / sample_id / "attempt-001").mkdir(parents=True)
    checksums = {relative: sha256_file(result / relative) for relative in frozen}
    checksums.update(
        {
            "inputs/class-study-launch.json": sha256_file(launch),
            "inputs/study-environment.json": sha256_file(environment),
            "experiment.json": sha256_file(experiment_file),
        }
    )
    verified = VerifiedResult(
        root=result,
        experiment={
            "name": f"{study_id}-certification-900-1200",
            "status": "incomplete",
            "summary": {"passed": False},
            "source": source,
            "configuration": {
                "evidence_role": "certification",
                "class_study_id": study_id,
                "class_study_cohort_sha256": sha256_file(cohort),
                "class_study_cohort_assembly_sha256": sha256_file(assembly),
                "class_study_foundation_sha256": sha256_file(foundation),
                "class_study_launch_sha256": sha256_file(launch),
                "campaign_sha256": sha256_file(authoritative_campaign),
                "defenses": [{"name": mode} for mode in COMPATIBILITY_MODES],
                "workloads": [{"id": candidate.candidate_id} for candidate in predecessor.final],
                **(
                    {"class_study_successor_sha256": sha256_file(predecessor_restart)}
                    if predecessor_restart is not None
                    else {}
                ),
            },
            "samples": samples,
        },
        checksums=checksums,
        accepted_samples=accepted,
    )

    monkeypatch.setattr(successor, "verify_result", lambda path: verified)
    frozen_workloads = tuple(
        SimpleNamespace(id=candidate.candidate_id) for candidate in predecessor.final
    )
    monkeypatch.setattr(
        orchestrator,
        "_campaign_from_frozen_inputs",
        lambda _root: SimpleNamespace(workloads=frozen_workloads),
    )
    monkeypatch.setattr(
        orchestrator,
        "_prepared_response_identity_failure",
        lambda _workload, attempt: producer_failures.get(attempt.parent.name),
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_current_candidate_sample_receipt",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        pipeline,
        "_validate_class_sample_run_receipt",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        successor,
        "load_study_receipt",
        lambda path: ({"receipt_type": "fixture"}, predecessor),
    )
    final_payload = final_selection_value["payload"]
    monkeypatch.setattr(
        successor,
        "validate_cohort_assembly_receipt",
        lambda value, *, cohort: {
            "final_selection": {
                "sha256": sha256_file(final_selection),
                "payload_sha256": final_selection_value["payload_sha256"],
                "payload": final_payload,
            }
        },
    )
    monkeypatch.setattr(
        class_attestation,
        "validate_class_foundation_attestation",
        lambda path, *, deep_code_gate=True, runtime_role="collection": {
            "source": source,
            "build_execution_identity": build,
        },
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_study_environment_receipt",
        lambda value, *, expected_image_digest=None: {"build_execution": build},
    )

    def compatible_files(
        decision: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        authority_path = successor._path_from_file_binding(
            decision["selection_authority"]["final_selection"],
            "fixture root final selection",
        )
        authority_value = json.loads(authority_path.read_text(encoding="utf-8"))
        authority_payload = validate_hash_bound_receipt(
            authority_value,
            expected_type=successor.FINAL_SELECTION_RECEIPT_TYPE,
        )
        matching = decision["successor_selection"]["matching"]
        evidence_by_pair = {
            frozenset((record["left"], record["right"])): record
            for record in authority_payload["feasible_pair_evidence"]
        }
        final_payload = {
            **authority_payload,
            "selection_policy": "sealed-class-incompatibility-successor-v2",
            "feasible_pair_rule": {
                "source": "qualified-root-120-class-60-edge-graph",
                "selection": "decision-bound-successor-50-edge-matching",
                "cumulative_failed_classes_excluded": decision["replacement_lineage"][
                    "cumulative_failed_class_ids"
                ],
                "replacement_generation": decision["replacement_lineage"]["generation"],
                "decision_payload_sha256": successor.canonical_json_sha256(decision),
            },
            "feasible_pair_evidence": [evidence_by_pair[frozenset(pair)] for pair in matching],
            "feasible_pair_graph": matching,
            "selected_final_perfect_matching": matching,
        }
        final_value = bind_receipt(
            final_payload,
            receipt_type=successor.FINAL_SELECTION_RECEIPT_TYPE,
        )
        compatible = bind_receipt(
            {"fixture": "cohort", "matching": matching},
            receipt_type="fixture-cohort",
        )
        assembly = bind_receipt(
            {
                "fixture": "assembly",
                "final_selection": {
                    "path": "successor-final-selection.json",
                    "sha256": hashlib.sha256(canonical_json_bytes(final_value)).hexdigest(),
                    "payload_sha256": final_value["payload_sha256"],
                    "payload": final_payload,
                },
            },
            receipt_type="fixture-assembly",
        )
        return compatible, assembly, final_value

    monkeypatch.setattr(
        successor,
        "_successor_compatible_cohort_files",
        compatible_files,
    )
    return (
        {
            "policy_receipt": policy,
            "certification_result_root": result,
            "predecessor_cohort_receipt": cohort,
            "predecessor_cohort_assembly": assembly,
            "predecessor_final_selection": final_selection,
            "predecessor_foundation_attestation": foundation,
        },
        verified,
    )


def test_decision_binds_exact_failure_and_preserves_v1_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "prepared identity drift",
        "details": [{"workload_id": "s0-00"}],
    }
    inputs, verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "undefended"): failure},
    )
    protected = {name: path.read_bytes() for name, path in inputs.items() if path.is_file()}

    destination = tmp_path / "decision.json"
    successor.create_successor_decision(destination, **inputs)
    payload = successor.validate_successor_decision(destination)

    assert payload["predecessor_study_id"] == STUDY_ID
    assert payload["successor"]["study_id"].startswith(f"{successor.SUCCESSOR_STUDY_PREFIX}-g01-")
    assert payload["successor"]["study_id"] != STUDY_ID
    assert payload["successor"]["launch_namespace"] != f".{STUDY_ID}-launches"
    certification = payload["certification_failure"]
    assert certification["failed_class_ids"] == ["s0-00"]
    assert certification["accepted_full_graph_run_receipts"] == 899
    assert certification["failed_cells"] == [
        {
            "sample_id": "s0-00-undefended",
            "workload_id": "s0-00",
            "defense": "undefended",
            "visit": 0,
            "attempts": 1,
            "classification": "class-incompatibility",
            "replacement_role": "authorising-undefended",
            "failure": failure,
            "failure_sha256": successor.canonical_json_sha256(failure),
            "producer_recomputed_failure_sha256": (successor.canonical_json_sha256(failure)),
        }
    ]
    assert payload["successor_selection"]["replaced_predecessor_ids"] == [
        "s0-00",
        "s0-01",
    ]
    assert payload["downstream_restart"] == successor.DOWNSTREAM_RESTART
    assert all(
        path.read_bytes() == protected[name] for name, path in inputs.items() if path.is_file()
    )

    with pytest.raises(FileExistsError, match="create-only"):
        successor.create_successor_decision(destination, **inputs)
    with pytest.raises(ValueError, match="overlaps protected input"):
        successor.create_successor_decision(
            inputs["certification_result_root"] / "decision.json",
            **inputs,
        )

    failed_sample = next(
        sample for sample in verified.experiment["samples"] if sample["state"] == "failed"
    )
    failed_sample["failure"] = {**failure, "message": "coherently changed"}
    with pytest.raises(ValueError, match="does not reproduce"):
        successor.validate_successor_decision(destination)


def test_second_generation_binds_restart_and_accumulates_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _within_stratum_predecessor()
    first = successor.select_successor_cohort(authority, ["s0-00"])
    incumbent = CohortSelection(
        candidates=authority.candidates,
        pilot=authority.pilot,
        final=first.final,
        reserves=first.reserves,
        feasible_pairs=first.matching,
        matching=first.matching,
    )
    first_study_id = f"{successor.SUCCESSOR_STUDY_PREFIX}-g01-{'a' * 12}"
    predecessor_restart = tmp_path / "g01-successor-restart.json"
    predecessor_restart.write_text('{"generation":1}\n', encoding="utf-8")
    failure = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "second class identity is unavailable",
        "details": [{"workload_id": "s1-00"}],
    }
    inputs, verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s1-00", "undefended"): failure},
        predecessor=incumbent,
        study_id=first_study_id,
        predecessor_restart=predecessor_restart,
    )
    source = verified.experiment["source"]
    build = {
        "cohort_version": 23,
        "sha256": "6" * 64,
        "collection_image": source["image_digest"],
        "started_at": "2026-08-28T00:00:00+00:00",
        "finished_at": "2026-08-28T00:01:00+00:00",
    }
    certification_relative = f"campaigns/{first_study_id}-certification-900-1200.yml"
    certification_campaign = predecessor_restart.parent / certification_relative
    lineage = successor._PredecessorLineage(
        study_id=first_study_id,
        generation=1,
        current=incumbent,
        authority=authority,
        authority_cohort_path=inputs["predecessor_cohort_receipt"],
        authority_assembly_path=inputs["predecessor_cohort_assembly"],
        authority_final_selection_path=inputs["predecessor_final_selection"],
        cumulative_failed_class_ids=("s0-00",),
        restart_path=predecessor_restart,
        restart={
            "predecessor_foundation_sha256": sha256_file(
                inputs["predecessor_foundation_attestation"]
            ),
            "source_sha256": successor.canonical_json_sha256(source),
            "build_execution_identity_sha256": successor.canonical_json_sha256(build),
            "immutable_plan_artifacts": {
                certification_relative: {
                    "path": certification_relative,
                    "sha256": sha256_file(certification_campaign),
                }
            },
        },
    )
    monkeypatch.setattr(successor, "_predecessor_lineage", lambda **_kwargs: lineage)

    destination = successor.create_successor_decision(
        tmp_path / "g02-decision.json",
        **inputs,
    )
    payload = successor.validate_successor_decision(destination)

    assert payload["predecessor_study_id"] == first_study_id
    assert payload["successor"]["study_id"].startswith(f"{successor.SUCCESSOR_STUDY_PREFIX}-g02-")
    replacement = payload["replacement_lineage"]
    assert replacement["generation"] == 2
    assert replacement["previous_cumulative_failed_class_ids"] == ["s0-00"]
    assert replacement["new_failed_class_ids"] == ["s1-00"]
    assert replacement["cumulative_failed_class_ids"] == ["s0-00", "s1-00"]
    assert replacement["predecessor_restart_sha256"] == sha256_file(predecessor_restart)
    assert payload["evidence"]["predecessor_successor_restart"] == (
        successor._file_binding(predecessor_restart)
    )
    assert {"s0-00", "s1-00"}.isdisjoint(payload["successor_selection"]["final"])


def test_predecessor_lineage_reconstructs_immediate_restart_and_root_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _within_stratum_predecessor()
    first = successor.select_successor_cohort(authority, ["s0-00"])
    incumbent = CohortSelection(
        candidates=authority.candidates,
        pilot=authority.pilot,
        final=first.final,
        reserves=first.reserves,
        feasible_pairs=first.matching,
        matching=first.matching,
    )
    policy = successor.create_successor_policy(tmp_path / "policy.json")
    plan = tmp_path / "generation-one/plan"
    plan.mkdir(parents=True)
    cohort = plan / "successor-compatible-cohort.json"
    assembly = plan / "successor-compatible-cohort-assembly.json"
    final_selection = plan / "successor-final-selection.json"
    restart = plan / "successor-restart.json"
    for path in (cohort, assembly, final_selection, restart):
        path.write_text(f'{{"fixture":"{path.name}"}}\n', encoding="utf-8")

    root_cohort = tmp_path / "root-cohort.json"
    root_assembly = tmp_path / "root-assembly.json"
    root_final_selection = tmp_path / "root-final-selection.json"
    root_cohort.write_text('{"root":"cohort"}\n', encoding="utf-8")
    root_assembly.write_text('{"root":"assembly"}\n', encoding="utf-8")
    root_final_value = _final_selection_receipt(authority)
    root_final_selection.write_bytes(canonical_json_bytes(root_final_value))
    selection_authority = {
        "study_id": STUDY_ID,
        "cohort": successor._file_binding(root_cohort),
        "cohort_assembly": successor._file_binding(root_assembly),
        "final_selection": successor._file_binding(root_final_selection),
        "pilot_classes": 120,
        "qualified_pair_edges": 60,
    }
    prior_decision_path = tmp_path / "generation-one-decision.json"
    study_id = f"{successor.SUCCESSOR_STUDY_PREFIX}-g01-{'b' * 12}"
    prior_decision = {
        "successor": {"study_id": study_id, "identity_sha256": "b" * 64},
        "successor_selection": first.as_dict(),
        "selection_authority": selection_authority,
        "replacement_lineage": {
            "generation": 1,
            "cumulative_failed_class_ids": ["s0-00"],
            "root_selection_authority_sha256": successor.canonical_json_sha256(selection_authority),
        },
        "evidence": {"policy": successor._file_binding(policy)},
    }
    prior_decision_path.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                prior_decision,
                receipt_type=successor.DECISION_RECEIPT_TYPE,
            )
        )
    )
    restart_payload = {
        "study_id": study_id,
        "replacement_generation": 1,
        "successor_decision": successor._file_binding(prior_decision_path),
        "immutable_plan_artifacts": {
            path.name: {"path": path.name, "sha256": sha256_file(path)}
            for path in (cohort, assembly, final_selection)
        },
    }
    monkeypatch.setattr(
        successor,
        "validate_successor_restart",
        lambda _path: restart_payload,
    )
    monkeypatch.setattr(
        successor,
        "validate_successor_decision",
        lambda _path: pytest.fail(
            "lineage repeated a decision reconstruction already performed by restart validation"
        ),
    )
    monkeypatch.setattr(
        successor,
        "load_study_receipt",
        lambda path: ({"receipt_type": "fixture"}, authority)
        if Path(path) == root_cohort
        else pytest.fail("lineage loaded a non-root selection authority"),
    )
    monkeypatch.setattr(
        successor,
        "validate_cohort_assembly_receipt",
        lambda value, *, cohort: {
            "final_selection": {
                "sha256": sha256_file(root_final_selection),
                "payload_sha256": root_final_value["payload_sha256"],
                "payload": root_final_value["payload"],
            }
        },
    )

    lineage = successor._predecessor_lineage(
        policy_path=policy,
        cohort_path=cohort,
        cohort=incumbent,
        assembly_path=assembly,
        final_selection_path=final_selection,
    )

    assert lineage.study_id == study_id
    assert lineage.generation == 1
    assert lineage.restart_path == restart.resolve()
    assert lineage.cumulative_failed_class_ids == ("s0-00",)
    assert len(lineage.authority.feasible_pairs or ()) == 60
    assert len(lineage.current.feasible_pairs or ()) == 50

    restart_payload["replacement_generation"] = 2
    with pytest.raises(ValueError, match="successor identity is inconsistent"):
        successor._predecessor_lineage(
            policy_path=policy,
            cohort_path=cohort,
            cohort=incumbent,
            assembly_path=assembly,
            final_selection_path=final_selection,
        )
    restart_payload["replacement_generation"] = 1

    restart_payload["immutable_plan_artifacts"][cohort.name]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="plan binding differs"):
        successor._predecessor_lineage(
            policy_path=policy,
            cohort_path=cohort,
            cohort=incumbent,
            assembly_path=assembly,
            final_selection_path=final_selection,
        )


def test_actual_g01_restart_drives_bound_g02_restart_with_cumulative_exclusion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    first_root.mkdir()
    first_failure = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "first prepared identity is unavailable",
        "details": [{"workload_id": "s0-00"}],
    }
    first_inputs, first_verified = _decision_fixture(
        first_root,
        monkeypatch,
        failures={("s0-00", "undefended"): first_failure},
    )
    authority = _within_stratum_predecessor()
    first_decision_path = successor.create_successor_decision(
        first_root / "decision.json",
        **first_inputs,
    )
    first_decision = successor.validate_successor_decision(first_decision_path)
    assert first_decision["successor"]["study_id"].startswith(
        f"{successor.SUCCESSOR_STUDY_PREFIX}-g01-"
    )
    restarts = tmp_path / "restarts"
    restarts.mkdir()
    first_restart_path = successor.create_successor_restart(
        restarts / first_decision["successor"]["study_id"],
        decision_receipt=first_decision_path,
    )
    first_plan = first_restart_path.parent
    first_cohort = first_plan / "successor-compatible-cohort.json"
    first_assembly = first_plan / "successor-compatible-cohort-assembly.json"
    first_final_selection = first_plan / "successor-final-selection.json"
    first_selected = first_decision["successor_selection"]
    candidate_by_id = {candidate.candidate_id: candidate for candidate in authority.pilot}
    incumbent = CohortSelection(
        candidates=authority.candidates,
        pilot=authority.pilot,
        final=tuple(candidate_by_id[item] for item in first_selected["final"]),
        reserves=tuple(candidate_by_id[item] for item in first_selected["reserves"]),
        feasible_pairs=tuple(tuple(pair) for pair in first_selected["matching"]),
        matching=tuple(tuple(pair) for pair in first_selected["matching"]),
    )

    second_root = tmp_path / "second"
    second_root.mkdir()
    second_failure = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "second prepared identity is unavailable",
        "details": [{"workload_id": "s1-00"}],
    }
    second_inputs, second_verified = _decision_fixture(
        second_root,
        monkeypatch,
        failures={("s1-00", "undefended"): second_failure},
        predecessor=incumbent,
        study_id=first_decision["successor"]["study_id"],
        predecessor_restart=first_restart_path,
    )
    second_inputs.update(
        predecessor_cohort_receipt=first_cohort,
        predecessor_cohort_assembly=first_assembly,
        predecessor_final_selection=first_final_selection,
    )
    for relative, source in (
        ("inputs/class-study-cohort.json", first_cohort),
        ("inputs/class-study-cohort-assembly.json", first_assembly),
    ):
        frozen = second_verified.root / relative
        frozen.write_bytes(source.read_bytes())
        second_verified.checksums[relative] = sha256_file(frozen)
    second_configuration = second_verified.experiment["configuration"]
    second_configuration["class_study_cohort_sha256"] = sha256_file(first_cohort)
    second_configuration["class_study_cohort_assembly_sha256"] = sha256_file(first_assembly)

    root_cohort = first_inputs["predecessor_cohort_receipt"]
    root_final_selection = first_inputs["predecessor_final_selection"]
    root_final_value = json.loads(root_final_selection.read_text(encoding="utf-8"))
    first_final_value = json.loads(first_final_selection.read_text(encoding="utf-8"))
    first_final_payload = validate_hash_bound_receipt(
        first_final_value,
        expected_type=successor.FINAL_SELECTION_RECEIPT_TYPE,
    )

    def load_cohort(path: Path) -> tuple[dict[str, str], CohortSelection]:
        resolved = Path(path).resolve()
        if resolved == root_cohort.resolve():
            return {"fixture_kind": "root"}, authority
        if resolved == first_cohort.resolve():
            return {"fixture_kind": "generation-one"}, incumbent
        raise AssertionError(f"unexpected cohort lineage path: {resolved}")

    def validate_assembly(
        value: dict[str, Any],
        *,
        cohort: dict[str, str],
    ) -> dict[str, Any]:
        if cohort.get("fixture_kind") == "generation-one":
            return {
                "final_selection": {
                    "sha256": sha256_file(first_final_selection),
                    "payload_sha256": first_final_value["payload_sha256"],
                    "payload": first_final_payload,
                }
            }
        assert cohort.get("fixture_kind") == "root"
        return {
            "final_selection": {
                "sha256": sha256_file(root_final_selection),
                "payload_sha256": root_final_value["payload_sha256"],
                "payload": root_final_value["payload"],
            }
        }

    verified_by_root = {
        first_verified.root.resolve(): first_verified,
        second_verified.root.resolve(): second_verified,
    }
    monkeypatch.setattr(successor, "load_study_receipt", load_cohort)
    monkeypatch.setattr(successor, "validate_cohort_assembly_receipt", validate_assembly)
    monkeypatch.setattr(
        successor,
        "verify_result",
        lambda path: verified_by_root[Path(path).resolve()],
    )
    workloads_by_result = {
        first_verified.root.resolve(): tuple(
            SimpleNamespace(id=candidate.candidate_id) for candidate in authority.final
        ),
        second_verified.root.resolve(): tuple(
            SimpleNamespace(id=candidate.candidate_id) for candidate in incumbent.final
        ),
    }
    failures_by_result = {
        first_verified.root.resolve(): first_failure,
        second_verified.root.resolve(): second_failure,
    }
    monkeypatch.setattr(
        orchestrator,
        "_campaign_from_frozen_inputs",
        lambda root: SimpleNamespace(workloads=workloads_by_result[Path(root).resolve()]),
    )
    monkeypatch.setattr(
        orchestrator,
        "_prepared_response_identity_failure",
        lambda _workload, attempt: failures_by_result[attempt.parents[2].resolve()],
    )
    # Both generations retain the same canonical root authority; the two
    # result directories above are only fixture namespaces.
    monkeypatch.setattr(class_layout.util, "LAB_ROOT", first_root)

    second_decision_path = successor.create_successor_decision(
        second_root / "decision.json",
        **second_inputs,
    )
    second_decision = successor.validate_successor_decision(second_decision_path)
    second_id = second_decision["successor"]["study_id"]
    assert second_id.startswith(f"{successor.SUCCESSOR_STUDY_PREFIX}-g02-")
    assert second_decision["replacement_lineage"]["cumulative_failed_class_ids"] == [
        "s0-00",
        "s1-00",
    ]
    assert second_decision["selection_authority"] == first_decision["selection_authority"]
    assert second_decision["selection_authority"]["qualified_pair_edges"] == 60
    assert second_decision["evidence"]["predecessor_successor_restart"] == (
        successor._file_binding(first_restart_path)
    )
    assert {"s0-00", "s1-00"}.isdisjoint(second_decision["successor_selection"]["final"])

    second_restart_path = successor.create_successor_restart(
        restarts / second_id,
        decision_receipt=second_decision_path,
    )
    second_restart = successor.validate_successor_restart(second_restart_path)
    assert second_restart["replacement_generation"] == 2
    assert second_restart["predecessor_study_id"] == first_decision["successor"]["study_id"]
    assert [
        gate.get("samples", gate.get("executions", gate.get("cells")))
        for gate in second_restart["required_restart_gates"]
    ] == [2_000, 600, 900]


def test_decision_and_policy_tampering_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "prepared identity mismatch",
        "details": [{"workload_id": "s1-00"}],
    }
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s1-00", "undefended"): failure},
    )
    destination = tmp_path / "decision.json"
    successor.create_successor_decision(destination, **inputs)
    value = json.loads(destination.read_text(encoding="utf-8"))
    value["payload"]["predecessor_mutation_permitted"] = True
    destination.write_bytes(canonical_json_bytes(value))

    with pytest.raises(ValueError, match="SHA-256"):
        successor.validate_successor_decision(destination)


def test_infrastructure_failure_cannot_authorise_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s0-00", "undefended"): {
                "stage": "interruption",
                "type": "HardInterruption",
                "message": "host stopped after launch checkpoint",
            }
        },
    )

    with pytest.raises(ValueError, match="infrastructure"):
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)
    assert not (tmp_path / "decision.json").exists()


def test_completed_certification_cannot_authorise_post_readiness_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "prepared identity changed after certification",
        "details": [{"workload_id": "s0-00"}],
    }
    inputs, verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "undefended"): failure},
    )
    verified.experiment["status"] = "complete"
    verified.experiment["summary"] = {"passed": True}

    with pytest.raises(ValueError, match="sealed incomplete certification"):
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)
    assert not (tmp_path / "decision.json").exists()


def test_undefended_identity_failure_authorises_same_class_defended_corroboration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "prepared identity is unavailable",
        "details": [{"workload_id": "s0-00"}],
    }
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", mode): failure for mode in COMPATIBILITY_MODES},
    )

    destination = successor.create_successor_decision(
        tmp_path / "decision.json",
        **inputs,
    )
    certification = successor.validate_successor_decision(destination)["certification_failure"]

    assert certification["failed_class_ids"] == ["s0-00"]
    assert certification["authorising_undefended_cell_ids"] == ["s0-00-undefended"]
    assert certification["corroborating_defended_cell_ids"] == [
        f"s0-00-{mode}" for mode in COMPATIBILITY_MODES if mode != "undefended"
    ]
    assert [cell["replacement_role"] for cell in certification["failed_cells"]] == [
        "authorising-undefended",
        *("corroborating-defended" for _mode in COMPATIBILITY_MODES[1:]),
    ]


def _complete_identity_failure(workload_id: str) -> dict[str, Any]:
    return {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "application responses differ from the frozen prepared identity",
        "details": [
            {
                "workload_id": workload_id,
                "expected_response_count": 3,
                "observed_response_count": 2,
                "expected_response_signature_sha256": "a" * 64,
                "observed_response_signature_sha256": "b" * 64,
                "differing_resource_ids": ["document", "stylesheet"],
            }
        ],
    }


def test_prepared_identity_failure_must_exactly_reproduce_from_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = _complete_identity_failure("s0-00")
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "undefended"): failure},
    )

    decision = successor.validate_successor_decision(
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)
    )
    [cell] = decision["certification_failure"]["failed_cells"]
    assert cell["producer_recomputed_failure_sha256"] == (successor.canonical_json_sha256(failure))


@pytest.mark.parametrize(
    "mutation",
    ("workload-only", "digest", "count", "resource-ids"),
)
def test_prepared_identity_failure_rejects_checkpoint_only_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    failure = _complete_identity_failure("s0-00")
    inputs, verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "undefended"): failure},
    )
    failed_sample = next(
        sample for sample in verified.experiment["samples"] if sample["state"] == "failed"
    )
    changed = json.loads(canonical_json_bytes(failure))
    details = changed["details"][0]
    if mutation == "workload-only":
        changed["details"] = [{"workload_id": "s0-00"}]
    elif mutation == "digest":
        details["expected_response_signature_sha256"] = "c" * 64
    elif mutation == "count":
        details["observed_response_count"] = 1
    else:
        details["differing_resource_ids"] = ["document"]
    failed_sample["failure"] = changed

    with pytest.raises(ValueError, match="does not reproduce"):
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)


@pytest.mark.parametrize(
    "message",
    (
        "lacks a valid current schema-4 terminal receipt",
        "has invalid current terminal/schedule chronology",
    ),
    ids=("stale-schema", "stale-chronology"),
)
def test_accepted_candidate_receipt_is_reopened_before_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    message: str,
) -> None:
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "undefended"): _complete_identity_failure("s0-00")},
    )

    def reject_candidate(
        _verified_result: VerifiedResult,
        sample: dict[str, Any],
        *,
        role: str,
    ) -> None:
        assert sample["defense"] in {"buflo", "cs-buflo"}
        assert role == "successor certification"
        raise ValueError(f"{role} {sample['defense']} sample {message}")

    monkeypatch.setattr(
        pipeline,
        "_validate_current_candidate_sample_receipt",
        reject_candidate,
    )
    with pytest.raises(ValueError, match=message):
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)


def test_every_accepted_certification_cell_reopens_its_full_run_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "undefended"): _complete_identity_failure("s0-00")},
    )
    reopened: list[tuple[str, str]] = []

    def bind_run(
        _verified_result: VerifiedResult,
        sample: dict[str, Any],
        *,
        role: str,
    ) -> None:
        assert role == "successor certification"
        reopened.append((str(sample["sample_id"]), str(sample["defense"])))

    monkeypatch.setattr(
        pipeline,
        "_validate_class_sample_run_receipt",
        bind_run,
    )
    decision_path = successor.create_successor_decision(
        tmp_path / "decision.json",
        **inputs,
    )

    accepted = [
        sample for sample in verified.experiment["samples"] if sample["state"] == "accepted"
    ]
    assert len(reopened) >= len(accepted) == 899
    assert {sample_id for sample_id, _mode in reopened} == {
        sample["sample_id"] for sample in accepted
    }
    assert {
        mode: len({sample_id for sample_id, observed_mode in reopened if observed_mode == mode})
        for mode in COMPATIBILITY_MODES
    } == {
        "undefended": 99,
        **{mode: 100 for mode in COMPATIBILITY_MODES if mode != "undefended"},
    }
    assert (
        successor.validate_successor_decision(decision_path)["certification_failure"][
            "accepted_full_graph_run_receipts"
        ]
        == 899
    )


def test_certification_campaign_must_match_generated_base_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "undefended"): _complete_identity_failure("s0-00")},
    )
    frozen = verified.root / "inputs/campaign.yml"
    frozen.write_text("name: coherently-rehashed-tamper\n", encoding="utf-8")
    changed_sha256 = sha256_file(frozen)
    verified.checksums["inputs/campaign.yml"] = changed_sha256
    verified.experiment["configuration"]["campaign_sha256"] = changed_sha256

    with pytest.raises(ValueError, match="differs from its generated authority"):
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)


def test_generation_zero_rejects_rehashed_alternate_root_authority_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "undefended"): _complete_identity_failure("s0-00")},
    )
    alternate_root = tmp_path / "alternate-authority"
    alternate_root.mkdir()
    canonical = inputs["predecessor_cohort_receipt"]
    alternate = alternate_root / canonical.name
    alternate.write_bytes(canonical.read_bytes())
    rebound = {**inputs, "predecessor_cohort_receipt": alternate}

    with pytest.raises(ValueError, match="canonical class-study layout"):
        successor.create_successor_decision(tmp_path / "decision.json", **rebound)


def test_defended_only_identity_failure_cannot_authorise_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "defended response differs",
        "details": [{"workload_id": "s0-00"}],
    }
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s0-00", "buflo"): failure},
    )

    with pytest.raises(ValueError, match="undefended prepared-identity"):
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)


@pytest.mark.parametrize(
    "other_failure",
    [
        {
            "stage": "fidelity",
            "type": "StrictDefenseFidelityFailure",
            "message": "scheduler realization failed",
        },
        {
            "stage": "interruption",
            "type": "HardInterruption",
            "message": "capture host stopped",
        },
    ],
    ids=("defense-fidelity", "infrastructure"),
)
def test_undefended_identity_authority_does_not_mask_other_failure_types(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    other_failure: dict[str, Any],
) -> None:
    authority = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "prepared identity is unavailable",
        "details": [{"workload_id": "s0-00"}],
    }
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s0-00", "undefended"): authority,
            ("s0-00", "buflo"): other_failure,
        },
    )

    with pytest.raises(ValueError, match="cannot authorise class replacement"):
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)


def test_defended_identity_corroboration_requires_same_workload_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "prepared identity is unavailable",
        "details": [{"workload_id": "s0-00"}],
    }
    unproven = {
        **authority,
        "details": [{"workload_id": "s1-00"}],
    }
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s0-00", "undefended"): authority,
            ("s0-00", "cs-buflo"): unproven,
        },
    )

    with pytest.raises(ValueError, match="cannot authorise class replacement"):
        successor.create_successor_decision(tmp_path / "decision.json", **inputs)


def test_successor_restart_is_distinct_complete_and_not_readiness_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s0-00", "undefended"): {
                "stage": "fidelity",
                "type": "StrictPreparedResponseIdentityFailure",
                "message": "class-specific prepared identity mismatch",
                "details": [{"workload_id": "s0-00"}],
            }
        },
    )
    decision_path = successor.create_successor_decision(
        tmp_path / "decision.json",
        **inputs,
    )
    decision = successor.validate_successor_decision(decision_path)
    study_id = decision["successor"]["study_id"]
    parent = tmp_path / "successors"
    parent.mkdir()
    restart_path = successor.create_successor_restart(
        parent / study_id,
        decision_receipt=decision_path,
    )
    payload = successor.validate_successor_restart(restart_path)

    assert payload["study_id"] == study_id
    assert payload["predecessor_study_id"] == STUDY_ID
    assert payload["namespace"]["launch_namespace"] == f".{study_id}-launches"
    assert payload["readiness"] == {
        "authorised": False,
        "promotion_authority": False,
        "required_before_readiness": [
            "successor-authoritative-fitting-2000-of-2000",
            "successor-final-qualification-600-of-600",
            "successor-first-launch-certification-900-of-900",
        ],
        "status": "restart-plan-only-no-readiness-authority",
    }
    gate_counts = [
        gate.get("samples", gate.get("executions", gate.get("cells")))
        for gate in payload["required_restart_gates"]
    ]
    assert gate_counts == [2_000, 600, 900]
    assert all(
        gate["predecessor_result_reuse_permitted"] is False
        for gate in payload["required_restart_gates"]
    )

    plan_root = restart_path.parent
    qualification_value = json.loads(
        (plan_root / "final-qualification-plan.json").read_text(encoding="utf-8")
    )
    qualification = validate_hash_bound_receipt(
        qualification_value,
        expected_type=successor.QUALIFICATION_PLAN_RECEIPT_TYPE,
    )
    assert qualification["total_executions"] == 600
    assert qualification["per_workload"] == {
        "response_identity_runs": 3,
        "prefix_pack_runs": 3,
        "total_executions": 6,
    }
    campaigns = [
        yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in sorted((plan_root / "campaigns").glob("*.yml"))
    ]
    by_role = {campaign["evidence_role"]: campaign for campaign in campaigns}
    fitting = by_role["authoritative-fitting"]
    certification = by_role["certification"]
    canary = by_role["canary"]
    formal = by_role["formal"]
    assert sum(fitting["workloads"].values()) * 2 == 2_000
    assert sum(certification["workloads"].values()) * 9 == 900
    assert fitting["class_study_successor"] == "../successor-restart.json"
    assert certification["class_study_successor"] == "../successor-restart.json"
    assert fitting["name"].startswith(f"{study_id}-")
    assert certification["name"].startswith(f"{study_id}-")
    assert fitting["limits"]["max_attempts"] == 3
    assert certification["limits"]["max_attempts"] == 1
    assert canary["limits"]["max_attempts"] == 3
    assert formal["limits"]["max_attempts"] == 3

    with pytest.raises(FileExistsError, match="create-only"):
        successor.create_successor_restart(
            parent / study_id,
            decision_receipt=decision_path,
        )


def test_generated_successor_certification_and_formal_load_freeze_and_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the live three-root trust split and result-local reload boundary."""

    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s0-00", "undefended"): {
                "stage": "fidelity",
                "type": "StrictPreparedResponseIdentityFailure",
                "message": "class-specific prepared identity mismatch",
                "details": [{"workload_id": "s0-00"}],
            }
        },
    )
    decision_path = successor.create_successor_decision(tmp_path / "decision.json", **inputs)
    decision = successor.validate_successor_decision(decision_path)
    successor_parent = tmp_path / "successors"
    successor_parent.mkdir()
    study_id = decision["successor"]["study_id"]
    restart_path = successor.create_successor_restart(
        successor_parent / study_id,
        decision_receipt=decision_path,
    )
    restart_root = restart_path.parent.parent
    campaign_root = restart_root / "plan/campaigns"

    lab_root = tmp_path / "lab"
    workload_root = lab_root / "config/workloads"
    workload_root.mkdir(parents=True)
    from tests.test_class_campaign_execution import _complete_origin_workload

    fixture_root = tmp_path / "current-workload-fixtures"
    fixture_root.mkdir()
    selected_ids = tuple(decision["successor_selection"]["final"])
    manifest_hashes = {}
    for workload_id in selected_ids:
        complete = _complete_origin_workload(
            fixture_root,
            visits=1,
            workload_id=workload_id,
            origin_count=2,
        )
        destination = workload_root / f"{workload_id}.json"
        destination.write_bytes(complete.source_bytes)
        manifest_hashes[workload_id] = sha256_file(destination)
    monkeypatch.setattr(orchestrator, "LAB_ROOT", lab_root)

    # The successor plan intentionally carries compatible cohort envelopes;
    # this test isolates orchestration/path semantics from cohort cryptography,
    # which has dedicated deep successor-admission tests above.
    import qcsd_lab.class_cohort as class_cohort
    import qcsd_lab.class_study as class_study

    selection = SimpleNamespace(
        pilot=tuple(SimpleNamespace(candidate_id=value) for value in selected_ids),
        final=tuple(SimpleNamespace(candidate_id=value) for value in selected_ids),
    )
    monkeypatch.setattr(
        class_study,
        "load_study_receipt",
        lambda _path: ({"payload_sha256": "a" * 64}, selection),
    )
    monkeypatch.setattr(
        class_cohort,
        "validate_cohort_assembly_receipt",
        lambda value, *, cohort: value,
    )
    monkeypatch.setattr(
        class_cohort,
        "cohort_workload_hashes",
        lambda _value, *, cohort, workload_ids: {
            workload_id: manifest_hashes[workload_id] for workload_id in workload_ids
        },
    )

    bundle_root = restart_root / "artifacts" / f"{STUDY_ID}-authoritative-fitting"
    bundle_root.mkdir(parents=True)
    for filename in (
        "traffic-morphing.json",
        "wtf-pad.json",
        "walkie-talkie.json",
    ):
        (bundle_root / filename).write_text('{"schema_version":1}\n', encoding="utf-8")
    (bundle_root / "provenance.json").write_text(
        '{"artifact_type":"qcsd-class-study-research-defense-bundle"}\n',
        encoding="utf-8",
    )

    qualification_set = f"{study_id}-final-full"
    qualification_authority = _pilot_lineage_evidence()[1]["finalized_bundle"][
        "qualification_authority"
    ]
    sidecar_root = restart_root / "qualification" / qualification_set
    prefix_root = sidecar_root / chaff_qualification.NAMED_QUALIFICATION_PREFIX_DIRECTORY
    prefix_root.mkdir(parents=True)
    set_manifest = sidecar_root / chaff_qualification.NAMED_QUALIFICATION_SET_MANIFEST
    set_manifest.write_bytes(
        canonical_json_bytes(
            {
                "qualification_authority": qualification_authority,
                "qualification_authority_sha256": canonical_json_sha256(
                    qualification_authority
                ),
            }
        )
    )
    for workload_id in selected_ids:
        (sidecar_root / f"{workload_id}.json").write_text("{}\n", encoding="utf-8")
        (prefix_root / f"{workload_id}.json").write_text("{}\n", encoding="utf-8")

    def load_named(path: Path, **kwargs: object) -> SimpleNamespace:
        assert kwargs["expected_qualification_set"] == qualification_set
        assert kwargs["expected_workload_ids"] == selected_ids
        return SimpleNamespace(
            manifest_path=path.resolve(),
            manifest_sha256=sha256_file(path),
        )

    def load_full(path: Path, **kwargs: object) -> SimpleNamespace:
        base = Path(kwargs["base_manifest_path"])
        manifest = orchestrator.runtime_manifest(json.loads(base.read_text(encoding="utf-8")))
        encoded = orchestrator.canonical_bytes(manifest)
        return SimpleNamespace(
            sidecar_sha256=sha256_file(path),
            manifest_sha256=orchestrator.sha256_bytes(encoded),
            manifest=manifest,
        )

    monkeypatch.setattr(chaff_qualification, "load_named_qualification_set", load_named)
    monkeypatch.setattr(chaff_qualification, "load_qualified_chaff", load_full)
    monkeypatch.setattr(
        orchestrator,
        "_validate_loaded_qualification_bindings",
        lambda _defenses, _workloads: None,
    )

    live_contexts: list[object] = []

    def parameter_artifact(path: Path, **kwargs: object) -> ParameterArtifact:
        provenance = Path(kwargs.get("provenance_path") or path.parent / "provenance.json")
        is_class_bundle = provenance.parent == bundle_root
        if is_class_bundle:
            context = kwargs.get("qualification_context")
            assert context is not None
            assert context.workload_root == workload_root.resolve()
            assert context.sidecar_root == sidecar_root.resolve()
            assert (
                context.prefix_spec_root
                == (
                    restart_root / "artifacts" / f"{STUDY_ID}-authoritative-fitting-prefix-specs"
                ).resolve()
            )
            assert context.expected_qualification_set == qualification_set
            assert context.qualification_authority == qualification_authority
            assert kwargs["qualification_authority"] == qualification_authority
            live_contexts.append(context)
        return ParameterArtifact(
            path=path.resolve(),
            sha256=sha256_file(path),
            provenance_path=provenance.resolve(),
            provenance_sha256=sha256_file(provenance),
            input_policy=(
                "sealed-class-study-fitting-v1" if is_class_bundle else "reviewed-config-v1"
            ),
        )

    def frozen_parameter_artifact(path: Path, **kwargs: object) -> ParameterArtifact:
        provenance = Path(kwargs["provenance_path"])
        if path.parent.name == "class-study":
            assert kwargs["expected_qualification_set"] == qualification_set
            assert kwargs["qualification_authority"] == qualification_authority
            policy = "sealed-class-study-fitting-v1"
        else:
            policy = "reviewed-config-v1"
        return ParameterArtifact(
            path=path.resolve(),
            sha256=sha256_file(path),
            provenance_path=provenance.resolve(),
            provenance_sha256=sha256_file(provenance),
            input_policy=policy,
        )

    monkeypatch.setattr(orchestrator, "validate_parameter_artifact", parameter_artifact)
    monkeypatch.setattr(
        orchestrator,
        "validate_frozen_parameter_artifact",
        frozen_parameter_artifact,
    )
    monkeypatch.setattr(orchestrator, "_materialize_study_environment", lambda *_args: None)

    def materialize_foundation(inputs_root: Path, _campaign: object) -> None:
        (inputs_root / "class-study-foundation.json").write_text(
            "{}\n", encoding="utf-8"
        )

    monkeypatch.setattr(
        orchestrator,
        "_materialize_class_study_authority",
        materialize_foundation,
    )

    def relocated_authority(path: Path, **_kwargs: object) -> dict[str, object]:
        value = json.loads(json.dumps(qualification_authority))
        value["foundation_attestation"]["path"] = str(path.resolve())
        return value

    monkeypatch.setattr(
        class_attestation,
        "class_qualification_authority",
        relocated_authority,
    )
    monkeypatch.setattr(orchestrator, "_frozen_configuration", lambda *_args: {})

    names = (
        f"{study_id}-certification-900-1200.yml",
        f"{study_id}-formal-01-1200.yml",
    )
    loaded = []
    for index, name in enumerate(names):
        campaign = orchestrator._load_campaign(
            campaign_root / name,
            frozen_inputs=None,
            expected_qualification_authority=qualification_authority,
        )
        expected_samples = 900 if campaign.evidence_role == "certification" else 1_600
        assert len(orchestrator.plan_campaign(campaign)) == expected_samples
        result_root = tmp_path / f"materialized-{index}"
        runtime, _configuration = orchestrator._materialize_inputs(
            result_root,
            campaign,
            {},
        )
        assert runtime.class_study_id == study_id
        frozen = orchestrator._load_campaign(
            result_root / "inputs/campaign.yml",
            frozen_inputs=result_root / "inputs",
        )
        assert frozen.class_study_id == study_id
        assert frozen.class_study_successor_sha256 == sha256_file(restart_path)
        assert len(orchestrator.plan_campaign(frozen)) == expected_samples
        loaded.append(frozen.evidence_role)

    assert loaded == ["certification", "formal"]
    downstream_counts = {"canary": 0, "formal": 1_600}
    for path in sorted(campaign_root.glob("*.yml")):
        if path.name in names or "-authoritative-fitting-" in path.name:
            continue
        campaign = orchestrator._load_campaign(
            path,
            frozen_inputs=None,
            expected_qualification_authority=qualification_authority,
        )
        if campaign.evidence_role not in downstream_counts:
            continue
        downstream_counts[campaign.evidence_role] += len(orchestrator.plan_campaign(campaign))
    assert downstream_counts == {"canary": 1_000, "formal": 16_000}
    # Three fitted defenses are independently validated for certification and
    # for each of the ten formal blocks.
    assert len(live_contexts) == 33


def test_successor_restart_rejects_wrong_namespace_and_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s1-00", "undefended"): {
                "stage": "fidelity",
                "type": "StrictPreparedResponseIdentityFailure",
                "message": "class-specific response mismatch",
                "details": [{"workload_id": "s1-00"}],
            }
        },
    )
    decision_path = successor.create_successor_decision(
        tmp_path / "decision.json",
        **inputs,
    )
    decision = successor.validate_successor_decision(decision_path)
    parent = tmp_path / "successors"
    parent.mkdir()
    wrong = parent / "not-the-hash-derived-study"
    with pytest.raises(ValueError, match="hash-derived study ID"):
        successor.create_successor_restart(wrong, decision_receipt=decision_path)
    assert not wrong.exists()

    root = parent / decision["successor"]["study_id"]
    receipt = successor.create_successor_restart(root, decision_receipt=decision_path)
    campaign = next((receipt.parent / "campaigns").glob("*.yml"))
    original = campaign.read_bytes()
    campaign.write_bytes(original + b"# tamper\n")
    with pytest.raises(ValueError, match="artifact changed"):
        successor.validate_successor_restart(receipt)

    campaign.write_bytes(original)
    (receipt.parent / "unreceipted.txt").write_text("forbidden\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected or missing entries"):
        successor.validate_successor_restart(receipt)


def test_pipeline_and_cli_expose_successor_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from qcsd_lab.cli import parser

    parsed = parser().parse_args(
        [
            "class-study",
            "successor-decision",
            "--successor-policy",
            "policy.json",
            "--certification-result",
            "certification",
            "--final-cohort",
            "cohort.json",
            "--final-cohort-assembly",
            "assembly.json",
            "--final-selection",
            "selection.json",
            "--foundation-attestation",
            "foundation.json",
            "--destination",
            "decision.json",
        ]
    )
    assert parsed.action == "successor-decision"
    assert parsed.successor_policy == Path("policy.json")

    policy = tmp_path / "policy.json"
    created = pipeline.run_class_study_action(
        "successor-policy",
        destination=policy,
    )
    assert created.status == "complete"
    verified = pipeline.run_class_study_action(
        "successor-verify",
        target=policy,
    )
    assert verified.details["root_study_id"] == STUDY_ID

    decision = tmp_path / "decision.json"
    observed: dict[str, object] = {}

    def create(path: Path, **kwargs: object) -> Path:
        observed.update(kwargs)
        path.write_text("{}\n", encoding="utf-8")
        return path

    monkeypatch.setattr(successor, "create_successor_decision", create)
    monkeypatch.setattr(
        successor,
        "validate_successor_decision",
        lambda path, **_kwargs: {"path": str(path)},
    )
    result = pipeline.run_class_study_action(
        "successor-decision",
        successor_policy=policy,
        certification_result=tmp_path / "certification",
        final_cohort_receipt_path=tmp_path / "cohort.json",
        final_cohort_assembly_path=tmp_path / "assembly.json",
        final_selection_path=tmp_path / "selection.json",
        foundation_attestation=tmp_path / "foundation.json",
        destination=decision,
    )
    assert result.status == "complete"
    assert observed["policy_receipt"] == policy
    assert observed["certification_result_root"] == tmp_path / "certification"


def test_successor_context_rejects_copied_workloads_and_mixed_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s0-00", "undefended"): {
                "stage": "fidelity",
                "type": "StrictPreparedResponseIdentityFailure",
                "message": "class-specific prepared identity mismatch",
                "details": [{"workload_id": "s0-00"}],
            }
        },
    )
    decision = successor.create_successor_decision(tmp_path / "decision.json", **inputs)
    payload = successor.validate_successor_decision(decision)
    parent = tmp_path / "successors"
    parent.mkdir()
    restart = successor.create_successor_restart(
        parent / payload["successor"]["study_id"],
        decision_receipt=decision,
    )
    canonical = tmp_path / "config/workloads"
    canonical.mkdir(parents=True)
    copied = tmp_path / "copied-workloads"
    copied.mkdir()

    arguments = {
        "successor_restart": restart,
        "campaign": None,
        "artifacts_root": None,
        "numeric_bundle_root": None,
        "prefix_spec_root": None,
        "qualification_checkpoint": None,
        "qualification_sidecar_root": None,
        "qualification_publication_root": None,
        "qualification_manifest": None,
        "final_bundle_root": None,
        "snapshot_phase": None,
        "destination": None,
    }
    with pytest.raises(ValueError, match="canonical prepared workload"):
        pipeline._successor_action_context("status", workload_root=copied, **arguments)
    context = pipeline._successor_action_context("status", workload_root=canonical, **arguments)
    assert context is not None
    assert context["study_id"] == payload["successor"]["study_id"]

    wrong_foundation = tmp_path / "wrong-foundation.json"
    wrong_foundation.write_text('{"wrong":true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="another foundation authority"):
        pipeline._successor_action_context(
            "qualify-prefix",
            workload_root=canonical,
            foundation_attestation=wrong_foundation,
            **arguments,
        )
    assert not (restart.parent.parent / "qualification/checkpoint.json").exists()

    with pytest.raises(ValueError, match="another study identity"):
        pipeline._require_successor_receipt_lineage(
            {"study_id": STUDY_ID},
            context,
            label="readiness attestation",
            require_restart=True,
        )
    with pytest.raises(ValueError, match="another restart authority"):
        pipeline._require_successor_receipt_lineage(
            {
                "study_id": context["study_id"],
                "evidence": {"successor_restart": {"sha256": "0" * 64}},
            },
            context,
            label="readiness attestation",
            require_restart=True,
        )
    pipeline._require_successor_receipt_lineage(
        {
            "study_id": context["study_id"],
            "evidence": {"successor_restart": {"sha256": sha256_file(restart)}},
        },
        context,
        label="readiness attestation",
        require_restart=True,
    )
    comparison_context = class_attestation._qcsd_comparison_context(
        "buflo", study_id=context["study_id"]
    )
    assert context["study_id"] in comparison_context["dataset_size"]
    assert STUDY_ID not in comparison_context["dataset_size"]


def test_host_wrapper_routes_successor_paths_without_v1_layout_reuse() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")

    assert "successor-policy|successor-decision|successor-restart|successor-verify" in launcher
    path_case = launcher.split("--candidate-catalogue|--acquisition-root", 1)[1].split(")", 1)[0]
    for flag in (
        "--successor-policy",
        "--successor-decision",
        "--successor-restart",
        "--destination",
        "--target",
    ):
        assert flag in path_case
    assert (
        "foundation|readiness|historical-snapshot|comparison-review|attest|"
        "successor-policy|successor-decision|successor-restart"
    ) in launcher
    fresh_case = launcher.split("class_fresh_layout=0", 1)[1].split("fi\n\n  case", 1)[0]
    assert "successor-policy" not in fresh_case
