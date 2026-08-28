from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path
from typing import Any

import pytest
import yaml

from qcsd_lab import buflo_study, chaff_qualification, class_attestation, orchestrator
from qcsd_lab import class_pipeline as pipeline
from qcsd_lab import class_successor as successor
from qcsd_lab.parameters import ParameterArtifact
from qcsd_lab.class_study import (
    COMPATIBILITY_MODES,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    CohortSelection,
    bind_receipt,
    canonical_json_bytes,
    validate_hash_bound_receipt,
)
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


def test_successor_fails_when_failed_edges_exceed_a_stratum_quota() -> None:
    predecessor = _within_stratum_predecessor()

    with pytest.raises(ValueError, match="quota-feasible"):
        successor.select_successor_cohort(
            predecessor,
            ["s0-00", "s0-02", "s0-04"],
        )


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
    study_id = "classifier-multiorigin100-v2-123456789abc"
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
                "provenance_sha256": sha256_file(
                    fitting_bundle / "provenance.json"
                ),
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
            Path(inputs["authoritative_fitting_result_root"]).resolve()
            == fitting_result.resolve()
        )
        assert (
            Path(inputs["certification_result_root"]).resolve()
            == certification_result.resolve()
        )
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


def _final_selection_receipt(predecessor: CohortSelection) -> dict[str, Any]:
    payload = {
        "study_id": STUDY_ID,
        "selection_schema_version": 1,
        "selection_policy": "test-qualified-pairs",
        "pilot_cohort": {"sha256": "1" * 64, "payload_sha256": "2" * 64},
        "pilot_cohort_assembly": {
            "sha256": "3" * 64,
            "payload_sha256": "4" * 64,
        },
        "pilot_numeric_fitting": {"numeric_provenance_sha256": "5" * 64},
        "pilot_compatibility": {"evidence_sha256": "6" * 64},
        "feasible_pair_rule": {"qualified_pair_edges": 60},
        "feasible_pair_evidence": [
            {"left": left, "right": right} for left, right in predecessor.feasible_pairs or ()
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
) -> tuple[dict[str, Path], VerifiedResult]:
    predecessor = _within_stratum_predecessor()
    policy = successor.create_successor_policy(tmp_path / "policy.json")
    cohort = tmp_path / "cohort.json"
    cohort.write_text("{}\n", encoding="utf-8")
    final_selection = tmp_path / "final-selection.json"
    final_selection_value = _final_selection_receipt(predecessor)
    final_selection.write_bytes(canonical_json_bytes(final_selection_value))
    assembly = tmp_path / "assembly.json"
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
    frozen = {
        "inputs/class-study-cohort.json": cohort,
        "inputs/class-study-cohort-assembly.json": assembly,
        "inputs/class-study-foundation.json": foundation,
    }
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
            "name": successor.CERTIFICATION_NAME,
            "status": "incomplete",
            "summary": {"passed": False},
            "source": source,
            "configuration": {
                "evidence_role": "certification",
                "class_study_cohort_sha256": sha256_file(cohort),
                "class_study_cohort_assembly_sha256": sha256_file(assembly),
                "class_study_foundation_sha256": sha256_file(foundation),
                "class_study_launch_sha256": sha256_file(launch),
                "defenses": [{"name": mode} for mode in COMPATIBILITY_MODES],
                "workloads": [{"id": candidate.candidate_id} for candidate in predecessor.final],
            },
            "samples": samples,
        },
        checksums=checksums,
        accepted_samples=accepted,
    )

    monkeypatch.setattr(successor, "verify_result", lambda path: verified)
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
    monkeypatch.setattr(
        successor,
        "_successor_compatible_cohort_files",
        lambda _decision: (
            bind_receipt({"fixture": "cohort"}, receipt_type="fixture-cohort"),
            bind_receipt({"fixture": "assembly"}, receipt_type="fixture-assembly"),
            bind_receipt(
                {"fixture": "selection"},
                receipt_type=successor.FINAL_SELECTION_RECEIPT_TYPE,
            ),
        ),
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
        failures={("s0-00", "buflo"): failure},
    )
    protected = {name: path.read_bytes() for name, path in inputs.items() if path.is_file()}

    destination = tmp_path / "decision.json"
    successor.create_successor_decision(destination, **inputs)
    payload = successor.validate_successor_decision(destination)

    assert payload["predecessor_study_id"] == STUDY_ID
    assert payload["successor"]["study_id"].startswith(f"{successor.SUCCESSOR_STUDY_PREFIX}-")
    assert payload["successor"]["study_id"] != STUDY_ID
    assert payload["successor"]["launch_namespace"] != f".{STUDY_ID}-launches"
    certification = payload["certification_failure"]
    assert certification["failed_class_ids"] == ["s0-00"]
    assert certification["failed_cells"] == [
        {
            "sample_id": "s0-00-buflo",
            "workload_id": "s0-00",
            "defense": "buflo",
            "visit": 0,
            "attempts": 1,
            "classification": "class-incompatibility",
            "failure": failure,
            "failure_sha256": successor.canonical_json_sha256(failure),
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
    with pytest.raises(ValueError, match="reconstructed evidence"):
        successor.validate_successor_decision(destination)


def test_decision_and_policy_tampering_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = {
        "stage": "fidelity",
        "type": "StrictDefenseFidelityFailure",
        "message": "defense mismatch",
    }
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={("s1-00", "cs-buflo"): failure},
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


def test_successor_restart_is_distinct_complete_and_not_readiness_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s0-00", "buflo"): {
                "stage": "fidelity",
                "type": "StrictDefenseFidelityFailure",
                "message": "class-specific defense mismatch",
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
            ("s0-00", "buflo"): {
                "stage": "fidelity",
                "type": "StrictDefenseFidelityFailure",
                "message": "class-specific defense mismatch",
            }
        },
    )
    decision_path = successor.create_successor_decision(
        tmp_path / "decision.json", **inputs
    )
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
    source_manifest = (
        Path(__file__).parents[1] / "config/workloads/rfc9114-text-r2.json"
    ).read_bytes()
    selected_ids = tuple(decision["successor_selection"]["final"])
    for workload_id in selected_ids:
        (workload_root / f"{workload_id}.json").write_bytes(source_manifest)
    manifest_sha256 = sha256_file(workload_root / f"{selected_ids[0]}.json")
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
            workload_id: manifest_sha256 for workload_id in workload_ids
        },
    )

    bundle_root = restart_root / "artifacts" / f"{STUDY_ID}-authoritative-fitting"
    bundle_root.mkdir(parents=True)
    for filename in (
        "traffic-morphing.json",
        "wtf-pad.json",
        "walkie-talkie.json",
    ):
        (bundle_root / filename).write_text(
            '{"schema_version":1}\n', encoding="utf-8"
        )
    (bundle_root / "provenance.json").write_text(
        '{"artifact_type":"qcsd-class-study-research-defense-bundle"}\n',
        encoding="utf-8",
    )

    qualification_set = f"{study_id}-final-full"
    sidecar_root = restart_root / "qualification" / qualification_set
    prefix_root = sidecar_root / chaff_qualification.NAMED_QUALIFICATION_PREFIX_DIRECTORY
    prefix_root.mkdir(parents=True)
    set_manifest = sidecar_root / chaff_qualification.NAMED_QUALIFICATION_SET_MANIFEST
    set_manifest.write_text("{}\n", encoding="utf-8")
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
            assert context.prefix_spec_root == (
                restart_root
                / "artifacts"
                / f"{STUDY_ID}-authoritative-fitting-prefix-specs"
            ).resolve()
            assert context.expected_qualification_set == qualification_set
            live_contexts.append(context)
        return ParameterArtifact(
            path=path.resolve(),
            sha256=sha256_file(path),
            provenance_path=provenance.resolve(),
            provenance_sha256=sha256_file(provenance),
            input_policy=(
                "sealed-class-study-fitting-v1"
                if is_class_bundle
                else "reviewed-config-v1"
            ),
        )

    def frozen_parameter_artifact(path: Path, **kwargs: object) -> ParameterArtifact:
        provenance = Path(kwargs["provenance_path"])
        if path.parent.name == "class-study":
            assert kwargs["expected_qualification_set"] == qualification_set
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
    monkeypatch.setattr(
        orchestrator, "_materialize_study_environment", lambda *_args: None
    )
    monkeypatch.setattr(
        orchestrator, "_materialize_class_study_authority", lambda *_args: None
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
        campaign = orchestrator._load_campaign(path, frozen_inputs=None)
        if campaign.evidence_role not in downstream_counts:
            continue
        downstream_counts[campaign.evidence_role] += len(
            orchestrator.plan_campaign(campaign)
        )
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
            ("s1-00", "cs-buflo"): {
                "stage": "fidelity",
                "type": "StrictPreparedResponseIdentityFailure",
                "message": "class-specific response mismatch",
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
    assert verified.details["predecessor_study_id"] == STUDY_ID

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
    import qcsd_lab.util as util

    inputs, _verified = _decision_fixture(
        tmp_path,
        monkeypatch,
        failures={
            ("s0-00", "buflo"): {
                "stage": "fidelity",
                "type": "StrictDefenseFidelityFailure",
                "message": "class-specific defense mismatch",
            }
        },
    )
    decision = successor.create_successor_decision(
        tmp_path / "decision.json", **inputs
    )
    payload = successor.validate_successor_decision(decision)
    parent = tmp_path / "successors"
    parent.mkdir()
    restart = successor.create_successor_restart(
        parent / payload["successor"]["study_id"],
        decision_receipt=decision,
    )
    lab_root = tmp_path / "lab"
    canonical = lab_root / "config/workloads"
    canonical.mkdir(parents=True)
    copied = lab_root / "copied-workloads"
    copied.mkdir()
    monkeypatch.setattr(util, "LAB_ROOT", lab_root)

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
        pipeline._successor_action_context(
            "status", workload_root=copied, **arguments
        )
    context = pipeline._successor_action_context(
        "status", workload_root=canonical, **arguments
    )
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
            "evidence": {
                "successor_restart": {"sha256": sha256_file(restart)}
            },
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
    path_case = launcher.split(
        "--candidate-catalogue|--acquisition-root", 1
    )[1].split(")", 1)[0]
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
