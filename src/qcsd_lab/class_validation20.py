"""Final promotion authority for the prospective 20-site class study.

This schema is separate from the historical 100-site final attestation.  It
replays the complete 200-canary and 16,000-formal result sequence, then binds
the deep handoff, classifier evaluation, comparison review, and both historical
snapshots to the same registered profile and immutable source.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import class_attestation as att
from . import class_evaluation
from .class_cohort20 import load_validated_profile_cohort
from .class_handoff import (
    CLASS_STUDY_HISTORICAL_POST_INPUT,
    CLASS_STUDY_LAUNCH_INPUT,
    CLASS_STUDY_LAUNCHES_PATH,
    PROFILE_ARTIFACT_TYPE,
    PROFILE_SCHEMA_VERSION,
    verify_class_handoff,
)
from .class_profile_result import verify_profile_class_result
from .class_study import (
    CLASS20_PROFILE,
    CLASS20_STUDY_ID,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    _CLASS20_OVERLAY_SHA256,
    canonical_json_sha256,
    load_class20_profile_contract,
)
from .util import load_json, sha256_file, source_metadata
from .verification import verify_result


def profile_validation_value(
    *,
    readiness_attestation: Path,
    canary_result_roots: Sequence[Path],
    formal_result_roots: Sequence[Path],
    historical_pre_snapshot: Path,
    historical_post_snapshot: Path,
    handoff: Path,
    evaluation_receipt: Path,
    comparison_review: Path,
    deep_code_gate: bool,
) -> dict[str, Any]:
    """Reconstruct the exact prospective final attestation from live evidence."""

    if type(deep_code_gate) is not bool:
        raise ValueError("20-site validation deep-code flag must be boolean")
    profile = load_class20_profile_contract()
    if profile != CLASS20_PROFILE:
        raise ValueError("20-site final validation has another registered profile")
    readiness_path = att._regular_file(readiness_attestation, "20-site readiness")
    readiness = att.validate_class_readiness_attestation(
        readiness_path, deep_code_gate=deep_code_gate,
    )
    current_source = source_metadata()
    att._validate_immutable_source(current_source, label="20-site final source")
    if (
        readiness.get("study_id") != CLASS20_STUDY_ID
        or readiness.get("attestation_schema_version") != att.CLASS20_READINESS_SCHEMA_VERSION
        or readiness.get("study_profile_sha256") != _CLASS20_OVERLAY_SHA256
        or readiness.get("source") != current_source
    ):
        raise ValueError("20-site final validation uses another readiness or source")
    evidence = readiness.get("evidence")
    summary = readiness.get("summary")
    if not isinstance(evidence, Mapping) or not isinstance(summary, Mapping):
        raise ValueError("20-site readiness has no final evidence inventory")
    foundation = evidence.get("foundation")
    if (
        not isinstance(foundation, Mapping)
        or not isinstance(foundation.get("sha256"), str)
        or att._DIGEST.fullmatch(foundation["sha256"]) is None
    ):
        raise ValueError("20-site readiness has no foundation identity")
    foundation_sha = str(foundation["sha256"])
    readiness_sha = sha256_file(readiness_path)
    cohort_path = att._path_from_binding(evidence.get("final_cohort"), label="20-site final cohort")
    assembly_path = att._path_from_binding(
        evidence.get("final_cohort_assembly"), label="20-site final cohort assembly"
    )
    _pilot, final_ids = load_validated_profile_cohort(
        cohort_path, assembly_path, profile=profile, require_deep=True,
    )
    if len(final_ids) != profile.final_count:
        raise ValueError("20-site final validation lacks its selected 20 sites")
    cohort_sha, assembly_sha = sha256_file(cohort_path), sha256_file(assembly_path)
    blocks = profile.formal_block_count
    canary_roots = _exact_roots(canary_result_roots, blocks, "canary")
    formal_roots = _exact_roots(formal_result_roots, blocks, "formal")
    if set(canary_roots) & set(formal_roots):
        raise ValueError("20-site canary and formal results overlap")
    if (
        summary.get("formal_expected_samples") != profile.formal_sample_count
        or summary.get("canary_expected_samples") != profile.final_count * blocks
    ):
        raise ValueError("20-site readiness has another formal capture plan")

    pre_path = att._regular_file(historical_pre_snapshot, "20-site pre snapshot")
    post_path = att._regular_file(historical_post_snapshot, "20-site post snapshot")
    pre = att.validate_class_historical_snapshot(pre_path, expected_phase="pre-formal")
    post = att.validate_class_historical_snapshot(post_path, expected_phase="post-formal")
    if (
        pre.get("snapshot_schema_version") != att.CLASS20_HISTORICAL_SNAPSHOT_SCHEMA_VERSION
        or post.get("snapshot_schema_version") != att.CLASS20_HISTORICAL_SNAPSHOT_SCHEMA_VERSION
        or pre.get("study_id") != CLASS20_STUDY_ID
        or post.get("study_id") != CLASS20_STUDY_ID
        or pre.get("study_profile_sha256") != _CLASS20_OVERLAY_SHA256
        or post.get("study_profile_sha256") != _CLASS20_OVERLAY_SHA256
        or pre.get("source") != current_source
        or post.get("source") != current_source
        or pre.get("readiness") != att._file_binding(readiness_path)
        or post.get("readiness") != att._file_binding(readiness_path)
        or post.get("pre_formal_snapshot") != att._file_binding(pre_path)
        or pre.get("historical_corpus_guard_sha256")
        != post.get("historical_corpus_guard_sha256")
    ):
        raise ValueError("20-site historical snapshots differ from the same profile and readiness")
    pre_time = att._aware_timestamp(pre.get("recorded_at"), label="20-site pre snapshot")
    post_time = att._aware_timestamp(post.get("recorded_at"), label="20-site post snapshot")
    certification_root = att._root_from_result_binding(
        evidence.get("certification_result"), label="20-site certification"
    )
    certification = verify_result(certification_root)
    certification_finish = att._aware_timestamp(
        certification.experiment.get("completed_at"), label="20-site certification completion"
    )
    if pre_time < certification_finish:
        raise ValueError("20-site pre snapshot predates certification")

    runtime = att._validated_runtime_inputs(
        summary.get("certification_defense_runtime_inputs"),
        expected_modes=COMPATIBILITY_MODES,
        label="20-site certified runtime",
    )
    parameters = summary.get("certification_defense_parameter_sha256")
    if not isinstance(parameters, Mapping) or set(parameters) != att._PARAMETER_MODES:
        raise ValueError("20-site certification parameter map is incomplete")
    formal_parameters = {mode: parameters[mode] for mode in FORMAL_MODES if mode in parameters}
    qualification_sha = summary.get("final_qualification_set_manifest_sha256")
    if not isinstance(qualification_sha, str) or att._DIGEST.fullmatch(qualification_sha) is None:
        raise ValueError("20-site final qualification identity is missing")

    canary_records: list[dict[str, Any]] = []
    formal_records: list[dict[str, Any]] = []
    canary_bindings: list[dict[str, str]] = []
    formal_bindings: list[dict[str, str]] = []
    historical_formal: list[dict[str, str]] = []
    environments: list[Mapping[str, Any]] = []
    previous_finish = pre_time
    for block, (canary_root, formal_root) in enumerate(
        zip(canary_roots, formal_roots, strict=True), start=1
    ):
        for role, root in (("canary", canary_root), ("formal", formal_root)):
            record = verify_profile_class_result(
                root, profile=profile, cohort_receipt=cohort_path,
                cohort_assembly=assembly_path, expected_role=role, expected_block=block,
            )
            planned = profile.final_count if role == "canary" else (
                profile.final_count * len(FORMAL_MODES) * profile.formal_visits_per_block
            )
            expected_modes = ("undefended",) if role == "canary" else FORMAL_MODES
            if (
                record.get("valid") is not True
                or record.get("root") != str(root)
                or record.get("class_study_id") != CLASS20_STUDY_ID
                or record.get("class_study_profile_sha256") != _CLASS20_OVERLAY_SHA256
                or record.get("class_study_foundation_sha256") != foundation_sha
                or record.get("class_study_readiness_sha256") != readiness_sha
                or record.get("class_study_historical_pre_snapshot_sha256") != sha256_file(pre_path)
                or record.get("cohort_sha256") != cohort_sha
                or record.get("cohort_assembly_sha256") != assembly_sha
                or record.get("samples") != planned
                or record.get("accepted") != planned
                or record.get("defense_runtime_inputs")
                != {mode: runtime[mode] for mode in expected_modes}
                or record.get("defense_parameter_sha256")
                != ({} if role == "canary" else formal_parameters)
                or record.get("chaff_qualification_set_manifest_sha256")
                != (None if role == "canary" else qualification_sha)
            ):
                raise ValueError(f"20-site {role} block {block:02d} differs from readiness")
            verified = verify_result(root)
            if verified.experiment.get("source") != current_source:
                raise ValueError("20-site final block uses another immutable source")
            start = att._aware_timestamp(
                verified.experiment.get("started_at"), label=f"20-site {role} start"
            )
            finish = att._aware_timestamp(
                verified.experiment.get("completed_at"), label=f"20-site {role} completion"
            )
            if start < previous_finish or finish <= start:
                raise ValueError("20-site canary and formal blocks are not chronological")
            previous_finish = finish
            environments.append(att._validate_result_environment(verified, current_source))
            binding = att._class_result_binding(root)
            if role == "canary":
                canary_records.append(record)
                canary_bindings.append(binding)
            else:
                formal_records.append(record)
                formal_bindings.append(binding)
                historical_formal.append({
                    key: binding[key] for key in (
                        "root", "evidence_sha256", "class_study_launch_sha256",
                        "class_study_foundation_sha256", "class_study_readiness_sha256",
                        "class_study_historical_pre_snapshot_sha256",
                    )
                })
    if (
        previous_finish > post_time
        or sum(record["accepted"] for record in canary_records) != profile.final_count * blocks
        or sum(record["accepted"] for record in formal_records) != profile.formal_sample_count
        or post.get("formal_results") != historical_formal
        or att._one_class_build_execution_identity(environments, include_completion=True)
        != readiness.get("build_execution_identity")
    ):
        raise ValueError("20-site final capture lacks complete same-build before/after evidence")

    handoff_root = verify_class_handoff(handoff, deep=True)
    dataset = load_json(att._regular_file(handoff_root / "dataset.json", "20-site handoff dataset"))
    expected_post = {
        "path": CLASS_STUDY_HISTORICAL_POST_INPUT,
        "sha256": sha256_file(post_path),
        "payload_sha256": post.get("payload_sha256"),
    }
    handoff_blocks = dataset.get("blocks") if isinstance(dataset, Mapping) else None
    if (
        not isinstance(dataset, Mapping)
        or dataset.get("schema_version") != PROFILE_SCHEMA_VERSION
        or dataset.get("artifact_type") != PROFILE_ARTIFACT_TYPE
        or dataset.get("study_id") != CLASS20_STUDY_ID
        or dataset.get("study_profile_sha256") != _CLASS20_OVERLAY_SHA256
        or dataset.get("sample_count") != profile.formal_sample_count
        or dataset.get("class_count") != profile.final_count
        or dataset.get("classes") != list(final_ids)
        or dataset.get("modes") != list(FORMAL_MODES)
        or not isinstance(handoff_blocks, list)
        or len(handoff_blocks) != blocks
        or [block.get("result_root") for block in handoff_blocks]
        != [str(root) for root in formal_roots]
        or [block.get("result_evidence_sha256") for block in handoff_blocks]
        != [record["evidence_sha256"] for record in formal_records]
        or dataset.get("execution_source", {}).get("value") != current_source
        or dataset.get("exporter_source") != current_source
        or dataset.get("historical_post_snapshot") != expected_post
        or sha256_file(att._regular_file(
            handoff_root / CLASS_STUDY_HISTORICAL_POST_INPUT,
            "embedded 20-site post snapshot",
        )) != expected_post["sha256"]
    ):
        raise ValueError("20-site handoff differs from formal source evidence")

    evaluation = class_evaluation.verify_class_evaluation_receipt(
        evaluation_receipt, handoff_root=handoff_root,
        deep_verify_handoff=True, replay_attacks=True,
    )
    completed = att._require_evaluation_completion(evaluation, require_full_replay=True)
    launch_blocks = [
        {
            "block": block,
            "path": f"{CLASS_STUDY_LAUNCHES_PATH}/block-{block:02d}.json",
            "sha256": record["class_study_launch_sha256"],
        }
        for block, record in enumerate(formal_records, start=1)
    ]
    launches = {
        "source_path": CLASS_STUDY_LAUNCH_INPUT,
        "blocks": launch_blocks,
        "bindings_sha256": canonical_json_sha256(launch_blocks),
    }
    evaluation_handoff = evaluation.get("handoff")
    if (
        evaluation.get("study_id") != CLASS20_STUDY_ID
        or evaluation.get("study_profile_sha256") != _CLASS20_OVERLAY_SHA256
        or evaluation.get("class_study_launches") != launches
        or not isinstance(evaluation_handoff, Mapping)
        or evaluation_handoff.get("class_study_launches_sha256")
        != canonical_json_sha256(launches)
    ):
        raise ValueError("20-site evaluation differs from formal launch evidence")
    comparison = att.validate_class_comparison_review(
        comparison_review, handoff=handoff_root,
        evaluation_receipt=evaluation_receipt,
    )
    if (
        comparison.get("study_id") != CLASS20_STUDY_ID
        or comparison.get("review_schema_version")
        != att.CLASS20_COMPARISON_REVIEW_SCHEMA_VERSION
        or comparison.get("study_profile_sha256") != _CLASS20_OVERLAY_SHA256
        or comparison.get("handoff") != att._handoff_binding(handoff_root)
        or comparison.get("evaluation") != att._file_binding(evaluation_receipt)
    ):
        raise ValueError("20-site comparison review differs from handoff or evaluation")

    final_evidence = {
        "readiness": att._file_binding(readiness_path),
        "canary_results": canary_bindings,
        "formal_results": formal_bindings,
        "historical_pre_snapshot": att._file_binding(pre_path),
        "historical_post_snapshot": att._file_binding(post_path),
        "handoff": att._handoff_binding(handoff_root),
        "evaluation": att._file_binding(evaluation_receipt),
        "comparison_review": att._file_binding(comparison_review),
    }
    gate_evidence = {
        "class-readiness-attestation": [final_evidence["readiness"]["sha256"]],
        "pre-block-canaries-200-of-200": [
            binding["evidence_sha256"] for binding in canary_bindings
        ],
        "formal-capture-16000-of-16000": [
            binding["evidence_sha256"] for binding in formal_bindings
        ],
        "closed-deep-verified-handoff": [final_evidence["handoff"]["sha256sums_sha256"]],
        "client-correctness": [completed["correctness_sha256"]],
        "performance-and-overhead-reporting": [completed["performance_sha256"]],
        "candidate-algorithm-and-transport-reporting": [completed["candidate_algorithm_sha256"]],
        "dlsvm-capacity-preflight": [
            completed["dlsvm_preflight_sha256"], completed["dlsvm_execution_model_sha256"],
        ],
        "classifier-security-evaluation": [final_evidence["evaluation"]["sha256"]],
        "original-study-comparison-review": [final_evidence["comparison_review"]["sha256"]],
        "historical-corpus-before-after-identity": [
            final_evidence["historical_pre_snapshot"]["sha256"],
            final_evidence["historical_post_snapshot"]["sha256"],
            post["historical_corpus_guard_sha256"],
        ],
        "current-source-and-no-waiver-promotion": [
            canonical_json_sha256(current_source), final_evidence["readiness"]["sha256"],
        ],
        "source-pinned-20-site-study-profile": [_CLASS20_OVERLAY_SHA256],
    }
    return {
        "attestation_schema_version": att.CLASS20_VALIDATION_SCHEMA_VERSION,
        "artifact_type": att.VALIDATION_RECEIPT_TYPE,
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "cohort_version": readiness["cohort_version"],
        "implementation_status": att.VALIDATED_STATUS,
        "implementation_status_description": att.VALIDATED_DESCRIPTION,
        "promotion_authority": True,
        "implementation_scope": att.IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "source": dict(current_source),
        "evidence": final_evidence,
        "summary": {
            "classes": profile.final_count,
            "modes": len(FORMAL_MODES),
            "canary_samples": profile.final_count * blocks,
            "formal_samples": profile.formal_sample_count,
            "formal_blocks": blocks,
            "client_correctness": completed["correctness"],
            "performance": completed["performance"],
            "candidate_algorithm": {
                "sample_count": completed["candidate_algorithm"]["sample_count"],
                "sha256": completed["candidate_algorithm_sha256"],
            },
            "dlsvm_capacity_preflight": completed["dlsvm_preflight"],
            "classifier_result_count": evaluation["result_count"],
            "comparison_reviewed_metrics": comparison["reviewed_metric_count"],
            "historical_corpus_guard_sha256": post["historical_corpus_guard_sha256"],
            "certification_defense_runtime_inputs": runtime,
            "final_qualification_set_manifest_sha256": qualification_sha,
        },
        "hard_gates": att._hard_gate_records(att._CLASS20_FINAL_GATES, gate_evidence),
        "all_validation_gates_passed": True,
    }


def _exact_roots(roots: Sequence[Path], count: int, label: str) -> tuple[Path, ...]:
    if not isinstance(roots, Sequence) or isinstance(roots, (str, bytes)):
        raise ValueError(f"20-site {label} result inventory is malformed")
    values = tuple(att._regular_directory(Path(root), f"20-site {label} result") for root in roots)
    if len(values) != count or len(set(values)) != count:
        raise ValueError(f"20-site validation requires {count} unique {label} results")
    return values
