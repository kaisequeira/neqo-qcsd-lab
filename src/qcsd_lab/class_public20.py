"""Public post-capture stages for the registered 20-site class study.

The coordinator accepts paths explicitly so that the CLI can route the v2
profile without borrowing the 100-site result index.  Publication first
reconstructs its inputs; the publisher's create-only output is then verified
through the same public authority boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import class_attestation as att
from . import class_evaluation
from .class_cohort20 import load_validated_profile_cohort
from .class_handoff import (
    PROFILE_ARTIFACT_TYPE,
    PROFILE_SCHEMA_VERSION,
    export_class_handoff,
    verify_class_handoff,
)
from .class_profile_result import verify_profile_class_result
from .class_study import (
    CLASS20_PROFILE,
    CLASS20_STUDY_ID,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    _CLASS20_OVERLAY_SHA256,
    load_class20_profile_contract,
)
from .util import require_disjoint_path, sha256_file, source_metadata
from .verification import verify_result


_FORMAL_SNAPSHOT_KEYS = (
    "root",
    "evidence_sha256",
    "class_study_launch_sha256",
    "class_study_foundation_sha256",
    "class_study_readiness_sha256",
    "class_study_historical_pre_snapshot_sha256",
)


def run_profile_public_stage(
    action: str,
    *,
    destination: Path | None = None,
    final_cohort_receipt: Path | None = None,
    final_cohort_assembly: Path | None = None,
    readiness_attestation: Path | None = None,
    historical_pre_snapshot: Path | None = None,
    historical_post_snapshot: Path | None = None,
    canary_result_roots: Sequence[Path] = (),
    formal_result_roots: Sequence[Path] = (),
    handoff: Path | None = None,
    evaluation_receipt: Path | None = None,
    comparison_review_input: Path | None = None,
    reviewer: str | None = None,
    reviewed_at: str | None = None,
    comparison_review: Path | None = None,
    dlsvm_cache_directory: Path | None = None,
    target: Path | None = None,
    deep: bool = True,
) -> dict[str, Any]:
    """Run one v2 public stage; return action, state, details, and messages.

    ``deep`` controls only read-only verification.  Publishing always deeply
    reconstructs the input and published evidence.
    """

    if action not in {"export", "evaluate", "comparison-review", "attest", "verify"}:
        raise ValueError("20-site public action is not registered")
    if type(deep) is not bool:
        raise ValueError("20-site public deep flag must be a boolean")
    if load_class20_profile_contract() != CLASS20_PROFILE:
        raise ValueError("20-site public stage requires the registered profile")

    if action == "export":
        cohort_input = _required(final_cohort_receipt, "--final-cohort")
        assembly_input = _required(final_cohort_assembly, "--final-cohort-assembly")
        readiness_input = _required(readiness_attestation, "--readiness-attestation")
        pre_input = _required(historical_pre_snapshot, "--historical-pre-snapshot")
        post_input = _required(historical_post_snapshot, "--historical-post-snapshot")
        output = _fresh_destination(
            _required(destination, "--destination"),
            (cohort_input, assembly_input, readiness_input, pre_input, post_input,
             *canary_result_roots, *formal_result_roots),
            label="20-site handoff",
        )
        roots, index = _validated_export_index(
            final_cohort_receipt=cohort_input,
            final_cohort_assembly=assembly_input,
            readiness_attestation=readiness_input,
            historical_pre_snapshot=pre_input,
            historical_post_snapshot=post_input,
            canary_result_roots=canary_result_roots,
            formal_result_roots=formal_result_roots,
        )
        published = export_class_handoff(
            roots, output, historical_post_snapshot=index["post_path"]
        )
        verified = _require_profile_handoff(published)
        details = {
            "valid": True,
            "root": str(verified),
            "study_id": CLASS20_STUDY_ID,
            "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
            "canary_blocks": CLASS20_PROFILE.formal_block_count,
            "canary_samples": CLASS20_PROFILE.final_count * CLASS20_PROFILE.formal_block_count,
            "formal_blocks": CLASS20_PROFILE.formal_block_count,
            "samples": CLASS20_PROFILE.formal_sample_count,
        }
        return _result(action, "complete", details)

    if action == "evaluate":
        handoff_input = _required(handoff, "--handoff")
        output = _fresh_destination(
            _required(destination, "--destination"), (handoff_input,),
            label="20-site evaluation receipt",
        )
        cache = _required(dlsvm_cache_directory, "--dlsvm-cache-directory")
        require_disjoint_path(cache, (handoff_input, output), label="20-site DLSVM cache")
        handoff_root = _require_profile_handoff(handoff_input)
        published = class_evaluation.write_class_evaluation_receipt(
            output, handoff_root=handoff_root, dlsvm_cache_directory=cache,
            deep_verify_handoff=True,
        )
        details = _require_profile_evaluation(published, handoff_root, replay_attacks=True)
        return _result(action, "complete", details)

    if action == "comparison-review":
        handoff_input = _required(handoff, "--handoff")
        evaluation_path = _required(evaluation_receipt, "--evaluation-receipt")
        output = None
        review_input = None
        if comparison_review_input is not None:
            output = _fresh_destination(
                _required(destination, "--destination"),
                (handoff_input, evaluation_path, comparison_review_input),
                label="20-site comparison review",
            )
            review_input = att._load_regular_json(
                comparison_review_input, "20-site comparison review input"
            )
            if set(review_input) != {"reviews"} or not isinstance(review_input["reviews"], list):
                raise ValueError("20-site comparison input must contain only a reviews array")
        handoff_root = _require_profile_handoff(handoff_input)
        _require_profile_evaluation(evaluation_path, handoff_root, replay_attacks=False)
        template = att.build_class_comparison_review_template(
            handoff=handoff_root, evaluation_receipt=evaluation_path,
        )
        _require_profile(template, label="20-site comparison template")
        if comparison_review_input is None:
            return _result(
                action, "ready", template,
                ("complete every review entry, save only the reviews array under a "
                 "top-level reviews key, then rerun with --comparison-review-input, "
                 "--reviewer, --reviewed-at, and --destination",),
            )
        assert output is not None and review_input is not None
        published = att.create_class_comparison_review(
            output, handoff=handoff_root, evaluation_receipt=evaluation_path,
            reviewer=reviewer, reviewed_at=reviewed_at,
            reviews=review_input["reviews"], _post_write_validate=False,
        )
        details = att.validate_class_comparison_review(
            published, handoff=handoff_root, evaluation_receipt=evaluation_path,
        )
        _require_profile(details, label="20-site comparison review")
        return _result(action, "complete", details)

    if action == "attest":
        inputs = {
            "readiness_attestation": _required(readiness_attestation, "--readiness-attestation"),
            "canary_result_roots": canary_result_roots,
            "formal_result_roots": formal_result_roots,
            "historical_pre_snapshot": _required(
                historical_pre_snapshot, "--historical-pre-snapshot"
            ),
            "historical_post_snapshot": _required(
                historical_post_snapshot, "--historical-post-snapshot"
            ),
            "handoff": _required(handoff, "--handoff"),
            "evaluation_receipt": _required(evaluation_receipt, "--evaluation-receipt"),
            "comparison_review": _required(comparison_review, "--comparison-review"),
        }
        output = _fresh_destination(
            _required(destination, "--destination"),
            (inputs["readiness_attestation"], *canary_result_roots,
             *formal_result_roots, inputs["historical_pre_snapshot"],
             inputs["historical_post_snapshot"], inputs["handoff"],
             inputs["evaluation_receipt"], inputs["comparison_review"]),
            label="20-site final validation",
        )
        published = att.create_class_validation_attestation(
            output, _post_write_validate=False, **inputs,
        )
        details = att.validate_class_validation_attestation(
            published, deep_code_gate=False,
        )
        _require_profile(details, label="20-site final validation")
        return _result(action, "complete", details)

    details = _verify_public_target(
        _required(target, "--target"), handoff=handoff, deep=deep,
    )
    return _result(action, "complete", details)


def _validated_export_index(
    *,
    final_cohort_receipt: Path,
    final_cohort_assembly: Path,
    readiness_attestation: Path,
    historical_pre_snapshot: Path,
    historical_post_snapshot: Path,
    canary_result_roots: Sequence[Path],
    formal_result_roots: Sequence[Path],
) -> tuple[tuple[Path, ...], dict[str, Any]]:
    """Deeply index the exact ordered 200-canary/16,000-formal sequence."""

    profile = CLASS20_PROFILE
    blocks = profile.formal_block_count
    canaries = _exact_roots(canary_result_roots, blocks, "canary")
    formals = _exact_roots(formal_result_roots, blocks, "formal")
    if set(canaries) & set(formals):
        raise ValueError("20-site canary and formal inventories overlap")
    readiness_path = att._regular_file(readiness_attestation, "20-site readiness")
    pre_path = att._regular_file(historical_pre_snapshot, "20-site pre snapshot")
    post_path = att._regular_file(historical_post_snapshot, "20-site post snapshot")
    cohort_path = att._regular_file(final_cohort_receipt, "20-site final cohort")
    assembly_path = att._regular_file(final_cohort_assembly, "20-site final assembly")
    readiness = att.validate_class_readiness_attestation(readiness_path)
    pre = att.validate_class_historical_snapshot(pre_path, expected_phase="pre-formal")
    post = att.validate_class_historical_snapshot(post_path, expected_phase="post-formal")
    for label, value, schema in (
        ("readiness", readiness, att.CLASS20_READINESS_SCHEMA_VERSION),
        ("pre snapshot", pre, att.CLASS20_HISTORICAL_SNAPSHOT_SCHEMA_VERSION),
        ("post snapshot", post, att.CLASS20_HISTORICAL_SNAPSHOT_SCHEMA_VERSION),
    ):
        _require_profile(value, label=f"20-site {label}")
        version_key = "attestation_schema_version" if label == "readiness" else "snapshot_schema_version"
        if value.get(version_key) != schema:
            raise ValueError(f"20-site {label} has another schema")
    source = source_metadata()
    att._validate_immutable_source(source, label="20-site export source")
    if (
        readiness.get("source") != source
        or pre.get("source") != source
        or post.get("source") != source
        or pre.get("readiness") != att._file_binding(readiness_path)
        or post.get("readiness") != att._file_binding(readiness_path)
        or post.get("pre_formal_snapshot") != att._file_binding(pre_path)
        or pre.get("historical_corpus_guard_sha256")
        != post.get("historical_corpus_guard_sha256")
    ):
        raise ValueError("20-site export snapshots differ from readiness or source")
    evidence = readiness.get("evidence")
    summary = readiness.get("summary")
    if not isinstance(evidence, Mapping) or not isinstance(summary, Mapping):
        raise ValueError("20-site readiness lacks its evidence inventory")
    if (
        evidence.get("final_cohort") != att._file_binding(cohort_path)
        or evidence.get("final_cohort_assembly") != att._file_binding(assembly_path)
        or summary.get("canary_expected_samples") != profile.final_count * blocks
        or summary.get("formal_expected_samples") != profile.formal_sample_count
    ):
        raise ValueError("20-site export uses another cohort or capture plan")
    _, final_ids = load_validated_profile_cohort(
        cohort_path, assembly_path, profile=profile, require_deep=True,
    )
    if len(final_ids) != profile.final_count:
        raise ValueError("20-site export lacks the selected final cohort")
    foundation = evidence.get("foundation")
    if not isinstance(foundation, Mapping) or not isinstance(foundation.get("sha256"), str):
        raise ValueError("20-site readiness lacks foundation identity")
    runtime = att._validated_runtime_inputs(
        summary.get("certification_defense_runtime_inputs"),
        expected_modes=COMPATIBILITY_MODES,
        label="20-site certified runtime",
    )
    parameters = summary.get("certification_defense_parameter_sha256")
    if not isinstance(parameters, Mapping) or set(parameters) != att._PARAMETER_MODES:
        raise ValueError("20-site certified parameter map is incomplete")
    formal_parameters = {mode: parameters[mode] for mode in FORMAL_MODES if mode in parameters}
    qualification_sha = summary.get("final_qualification_set_manifest_sha256")
    if not isinstance(qualification_sha, str) or att._DIGEST.fullmatch(qualification_sha) is None:
        raise ValueError("20-site final qualification identity is missing")
    lineage = {
        "class_study_id": CLASS20_STUDY_ID,
        "class_study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "class_study_foundation_sha256": foundation["sha256"],
        "class_study_readiness_sha256": sha256_file(readiness_path),
        "class_study_historical_pre_snapshot_sha256": sha256_file(pre_path),
        "cohort_sha256": sha256_file(cohort_path),
        "cohort_assembly_sha256": sha256_file(assembly_path),
    }
    previous_finish = att._aware_timestamp(pre.get("recorded_at"), label="20-site pre snapshot")
    post_time = att._aware_timestamp(post.get("recorded_at"), label="20-site post snapshot")
    formal_bindings: list[dict[str, str]] = []
    environments: list[Mapping[str, Any]] = []
    launch_hashes: set[str] = set()
    for block, (canary_root, formal_root) in enumerate(zip(canaries, formals, strict=True), start=1):
        for role, root in (("canary", canary_root), ("formal", formal_root)):
            record = verify_profile_class_result(
                root, profile=profile, cohort_receipt=cohort_path,
                cohort_assembly=assembly_path, expected_role=role, expected_block=block,
            )
            planned = profile.final_count if role == "canary" else (
                profile.final_count * len(FORMAL_MODES) * profile.formal_visits_per_block
            )
            modes = ("undefended",) if role == "canary" else FORMAL_MODES
            if (
                record.get("valid") is not True
                or record.get("root") != str(root)
                or record.get("evidence_role") != role
                or record.get("block") != block
                or any(record.get(key) != value for key, value in lineage.items())
                or record.get("samples") != planned
                or record.get("accepted") != planned
                or record.get("defense_runtime_inputs") != {mode: runtime[mode] for mode in modes}
                or record.get("defense_parameter_sha256")
                != ({} if role == "canary" else formal_parameters)
                or record.get("chaff_qualification_set_manifest_sha256")
                != (None if role == "canary" else qualification_sha)
            ):
                raise ValueError(f"20-site {role} block {block:02d} differs from readiness")
            launch = record.get("class_study_launch_sha256")
            if not isinstance(launch, str) or launch in launch_hashes:
                raise ValueError("20-site public results lack unique launch identities")
            launch_hashes.add(launch)
            verified = verify_result(root)
            if verified.experiment.get("source") != source:
                raise ValueError("20-site public result uses another immutable source")
            started = att._aware_timestamp(
                verified.experiment.get("started_at"), label=f"20-site {role} start"
            )
            completed = att._aware_timestamp(
                verified.experiment.get("completed_at"), label=f"20-site {role} completion"
            )
            if started < previous_finish or completed <= started:
                raise ValueError("20-site public results are not chronological")
            previous_finish = completed
            environments.append(att._validate_result_environment(verified, source))
            if role == "formal":
                formal_bindings.append({
                    "root": str(root),
                    "evidence_sha256": record["evidence_sha256"],
                    "class_study_launch_sha256": launch,
                    "class_study_foundation_sha256": lineage["class_study_foundation_sha256"],
                    "class_study_readiness_sha256": lineage["class_study_readiness_sha256"],
                    "class_study_historical_pre_snapshot_sha256": lineage[
                        "class_study_historical_pre_snapshot_sha256"
                    ],
                })
    if (
        previous_finish > post_time
        or post.get("formal_results") != formal_bindings
        or att._one_class_build_execution_identity(environments, include_completion=True)
        != readiness.get("build_execution_identity")
    ):
        raise ValueError("20-site public export lacks complete ordered same-build evidence")
    return formals, {
        "readiness_path": readiness_path,
        "pre_path": pre_path,
        "post_path": post_path,
        "cohort_path": cohort_path,
        "assembly_path": assembly_path,
    }


def _exact_roots(roots: Sequence[Path], count: int, label: str) -> tuple[Path, ...]:
    if not isinstance(roots, Sequence) or isinstance(roots, (str, bytes)):
        raise ValueError(f"20-site {label} inventory is malformed")
    values = tuple(att._regular_directory(Path(root), f"20-site {label} result") for root in roots)
    if len(values) != count or len(set(values)) != count:
        raise ValueError(f"20-site public stage requires {count} unique {label} results")
    return values


def _require_profile(value: Mapping[str, Any], *, label: str) -> None:
    if (
        not isinstance(value, Mapping)
        or value.get("study_id") != CLASS20_STUDY_ID
        or value.get("study_profile_sha256") != _CLASS20_OVERLAY_SHA256
    ):
        raise ValueError(f"{label} uses another study profile")


def _require_profile_handoff(path: Path, *, deep: bool = True) -> Path:
    candidate = att._regular_directory(path, "20-site handoff")
    dataset = att._load_regular_json(candidate / "dataset.json", "20-site handoff dataset")
    _require_profile(dataset, label="20-site handoff")
    if (
        dataset.get("schema_version") != PROFILE_SCHEMA_VERSION
        or dataset.get("artifact_type") != PROFILE_ARTIFACT_TYPE
        or dataset.get("sample_count") != CLASS20_PROFILE.formal_sample_count
        or dataset.get("class_count") != CLASS20_PROFILE.final_count
        or dataset.get("modes") != list(FORMAL_MODES)
    ):
        raise ValueError("20-site handoff has another formal matrix")
    return verify_class_handoff(candidate, deep=deep)


def _require_profile_evaluation(
    path: Path, handoff_root: Path, *, replay_attacks: bool,
    deep_verify_handoff: bool = True,
) -> dict[str, Any]:
    _receipt_path, _envelope, payload = att._load_bound_receipt(
        path, expected_type=class_evaluation.EVALUATION_RECEIPT_TYPE,
    )
    _require_profile(payload, label="20-site evaluation")
    value = class_evaluation.verify_class_evaluation_receipt(
        path, handoff_root=handoff_root,
        deep_verify_handoff=deep_verify_handoff, replay_attacks=replay_attacks,
    )
    _require_profile(value, label="20-site evaluation")
    att._require_evaluation_completion(value, require_full_replay=replay_attacks)
    return value


def _verify_public_target(target: Path, *, handoff: Path | None, deep: bool) -> dict[str, Any]:
    path = Path(target).absolute()
    if path.is_symlink():
        raise ValueError("20-site public verification target cannot be a symlink")
    if path.is_dir():
        root = _require_profile_handoff(path, deep=deep)
        return {
            "valid": True, "root": str(root), "study_id": CLASS20_STUDY_ID,
            "study_profile_sha256": _CLASS20_OVERLAY_SHA256, "deep": deep,
        }
    value = att._load_regular_json(path, "20-site public verification target")
    receipt_type = value.get("receipt_type")
    accepted_receipt_types = {
        att.ACQUISITION_AUTHORITY_RECEIPT_TYPE,
        att.FOUNDATION_RECEIPT_TYPE,
        class_evaluation.EVALUATION_RECEIPT_TYPE,
        att.READINESS_RECEIPT_TYPE,
        att.HISTORICAL_SNAPSHOT_RECEIPT_TYPE,
        att.COMPARISON_REVIEW_RECEIPT_TYPE,
        att.VALIDATION_RECEIPT_TYPE,
    }
    if not isinstance(receipt_type, str) or receipt_type not in accepted_receipt_types:
        raise ValueError("20-site public verification target type is not registered")
    _receipt_path, _envelope, payload = att._load_bound_receipt(
        path, expected_type=receipt_type,
    )
    _require_profile(payload, label="20-site verification target")
    if receipt_type == class_evaluation.EVALUATION_RECEIPT_TYPE:
        binding = payload.get("handoff")
        if handoff is None and (not isinstance(binding, Mapping) or not isinstance(binding.get("root"), str)):
            raise ValueError("20-site evaluation verification needs --handoff")
        root = _require_profile_handoff(
            Path(binding["root"]) if handoff is None else Path(handoff), deep=deep,
        )
        return _require_profile_evaluation(
            path, root, replay_attacks=deep, deep_verify_handoff=deep,
        )
    if receipt_type == att.ACQUISITION_AUTHORITY_RECEIPT_TYPE:
        details = att.validate_class_acquisition_authority(
            path, runtime_role="collection", allow_historical=False,
        )
    elif receipt_type == att.FOUNDATION_RECEIPT_TYPE:
        details = att.validate_class_foundation_attestation(
            path, deep_code_gate=deep, runtime_role="collection",
        )
    elif receipt_type == att.READINESS_RECEIPT_TYPE:
        details = att.validate_class_readiness_attestation(path, deep_code_gate=deep)
    elif receipt_type == att.HISTORICAL_SNAPSHOT_RECEIPT_TYPE:
        details = att.validate_class_historical_snapshot(path)
    elif receipt_type == att.COMPARISON_REVIEW_RECEIPT_TYPE:
        details = att.validate_class_comparison_review(path, handoff=handoff)
    elif receipt_type == att.VALIDATION_RECEIPT_TYPE:
        details = att.validate_class_validation_attestation(path, deep_code_gate=deep)
    _require_profile(details, label="20-site verification target")
    return details


def _fresh_destination(path: Path, protected: Sequence[Path], *, label: str) -> Path:
    candidate = Path(path).absolute()
    if candidate.exists() or candidate.is_symlink():
        raise FileExistsError(f"{label} already exists: {candidate}")
    return require_disjoint_path(candidate, tuple(Path(item) for item in protected), label=label)


def _required(value: Path | None, option: str) -> Path:
    if value is None:
        raise ValueError(f"20-site public stage requires {option}")
    return Path(value)


def _result(
    action: str, state: str, details: dict[str, Any], messages: tuple[str, ...] = ()
) -> dict[str, Any]:
    return {"action": action, "state": state, "details": details, "messages": messages}
