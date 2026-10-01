"""Prospective 20-site pre/post-formal historical snapshot authority.

The schema-1 100-site snapshots remain in ``class_attestation``.  A schema-2
post snapshot is published only after all ten sealed 20-site formal blocks
are independently rechecked against the same readiness, cohort, profile,
runtime inputs, build, and pre snapshot.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import class_attestation
from .buflo_study import _validate_result_environment, validate_historical_corpus_guard
from .class_layout import class_study_layout
from .class_profile_result import verify_profile_class_result
from .class_study import (
    CLASS20_STUDY_ID,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    bind_receipt,
    canonical_json_sha256,
    load_class20_profile_contract,
    write_create_only_json,
)
from .util import LAB_ROOT, require_disjoint_path, sha256_file, source_metadata
from .verification import verify_result


SCHEMA_VERSION = class_attestation.CLASS20_HISTORICAL_SNAPSHOT_SCHEMA_VERSION
RECEIPT_TYPE = class_attestation.HISTORICAL_SNAPSHOT_RECEIPT_TYPE
_FORMAL_BINDING_KEYS = frozenset(
    {
        "root",
        "evidence_sha256",
        "class_study_launch_sha256",
        "class_study_foundation_sha256",
        "class_study_readiness_sha256",
        "class_study_historical_pre_snapshot_sha256",
    }
)
_SNAPSHOT_KEYS = frozenset(
    {
        "snapshot_schema_version",
        "artifact_type",
        "study_id",
        "study_profile_sha256",
        "phase",
        "recorded_at",
        "source",
        "readiness",
        "historical_corpus_guard",
        "historical_corpus_guard_sha256",
        "pre_formal_snapshot",
        "formal_results",
    }
)


def create_profile_historical_snapshot(
    destination: Path,
    *,
    phase: str,
    readiness_attestation: Path,
    formal_result_roots: Sequence[Path] = (),
    pre_snapshot: Path | None = None,
) -> Path:
    """Create one source-bound v2 snapshot after deep reconstruction."""

    protected = [
        LAB_ROOT / "handoffs/classifier-multiorigin5-v2",
        Path(readiness_attestation),
        *(Path(root) for root in formal_result_roots),
    ]
    if pre_snapshot is not None:
        protected.append(Path(pre_snapshot))
    destination = require_disjoint_path(
        destination,
        tuple(protected),
        label=f"20-site historical {phase} snapshot destination",
    )
    payload = _snapshot_value(
        phase=phase,
        readiness_attestation=readiness_attestation,
        formal_result_roots=formal_result_roots,
        pre_snapshot=pre_snapshot,
        recorded_at=None,
    )
    output = write_create_only_json(
        destination, bind_receipt(payload, receipt_type=RECEIPT_TYPE)
    )
    validate_profile_historical_snapshot(output)
    return output


def validate_profile_historical_snapshot(
    path: Path, *, expected_phase: str | None = None
) -> dict[str, Any]:
    """Rebuild a v2 snapshot from the bound source and sealed evidence."""

    receipt_path, value, payload = class_attestation._load_bound_receipt(
        path, expected_type=RECEIPT_TYPE
    )
    _validate_envelope(payload)
    phase = payload["phase"]
    if expected_phase is not None and phase != expected_phase:
        raise ValueError("20-site historical snapshot has the wrong phase")
    readiness = class_attestation._path_from_binding(
        payload["readiness"], label="20-site readiness"
    )
    roots = class_attestation._roots_from_bindings(
        payload["formal_results"], allow_empty=True
    )
    pre_binding = payload["pre_formal_snapshot"]
    pre_path = (
        None if pre_binding is None else class_attestation._path_from_binding(
            pre_binding, label="20-site pre snapshot"
        )
    )
    expected = _snapshot_value(
        phase=phase,
        readiness_attestation=readiness,
        formal_result_roots=roots,
        pre_snapshot=pre_path,
        recorded_at=payload["recorded_at"],
    )
    if payload != expected:
        raise ValueError("20-site historical snapshot differs from reconstructed evidence")
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": value["payload_sha256"],
        **expected,
    }


def _validate_envelope(payload: Mapping[str, Any]) -> None:
    if (
        set(payload) != _SNAPSHOT_KEYS
        or payload.get("snapshot_schema_version") != SCHEMA_VERSION
        or payload.get("artifact_type") != RECEIPT_TYPE
        or payload.get("study_id") != CLASS20_STUDY_ID
        or payload.get("phase") not in {"pre-formal", "post-formal"}
        or not isinstance(payload.get("formal_results"), list)
    ):
        raise ValueError("20-site historical snapshot envelope is invalid")
    formal = payload["formal_results"]
    if any(not isinstance(binding, Mapping) or set(binding) != _FORMAL_BINDING_KEYS for binding in formal):
        raise ValueError("20-site historical snapshot formal binding shape is invalid")
    if payload["phase"] == "pre-formal":
        if formal or payload.get("pre_formal_snapshot") is not None:
            raise ValueError("20-site pre snapshot cannot bind formal evidence")
    elif len(formal) != load_class20_profile_contract().formal_block_count:
        raise ValueError("20-site post snapshot requires ten formal blocks")


def _snapshot_value(
    *,
    phase: str,
    readiness_attestation: Path,
    formal_result_roots: Sequence[Path],
    pre_snapshot: Path | None,
    recorded_at: object,
) -> dict[str, Any]:
    if phase not in {"pre-formal", "post-formal"}:
        raise ValueError("20-site historical snapshot phase is invalid")
    profile = load_class20_profile_contract()
    layout = class_study_layout(profile=profile)
    profile_sha256 = sha256_file(
        class_attestation._regular_file(
            layout.study_config_root / "study.json", "20-site study profile"
        )
    )
    readiness_path = class_attestation._regular_file(
        readiness_attestation, "20-site readiness"
    )
    readiness = class_attestation.validate_class_readiness_attestation(readiness_path)
    source = source_metadata()
    class_attestation._validate_immutable_source(source, label="20-site historical source")
    if (
        readiness.get("study_id") != profile.study_id
        or readiness.get("attestation_schema_version")
        != class_attestation.CLASS20_READINESS_SCHEMA_VERSION
        or readiness.get("study_profile_sha256") != profile_sha256
        or readiness.get("source") != source
    ):
        raise ValueError("20-site historical snapshot uses another readiness, source, or profile")
    if recorded_at is None:
        recorded_at = datetime.now(UTC).isoformat()
    timestamp = class_attestation._aware_timestamp(
        recorded_at, label=f"20-site historical {phase} snapshot"
    )
    evidence = readiness.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("20-site readiness has no evidence inventory")
    certification_root = class_attestation._root_from_result_binding(
        evidence.get("certification_result"), label="20-site certification"
    )
    certification_finish = class_attestation._aware_timestamp(
        verify_result(certification_root).experiment.get("completed_at"),
        label="20-site certification completion",
    )
    if timestamp < certification_finish:
        raise ValueError("20-site historical snapshot predates certification")

    if phase == "pre-formal":
        if formal_result_roots or pre_snapshot is not None:
            raise ValueError("20-site pre snapshot cannot bind formal evidence")
        results: list[dict[str, str]] = []
        pre_binding = None
    else:
        if len(formal_result_roots) != profile.formal_block_count or pre_snapshot is None:
            raise ValueError("20-site post snapshot requires pre snapshot and ten formal blocks")
        roots = tuple(
            class_attestation._regular_directory(Path(root), "20-site formal result")
            for root in formal_result_roots
        )
        if len(set(roots)) != profile.formal_block_count:
            raise ValueError("20-site post snapshot requires unique formal roots")
        pre_path = class_attestation._regular_file(pre_snapshot, "20-site pre snapshot")
        pre = validate_profile_historical_snapshot(pre_path, expected_phase="pre-formal")
        if (
            pre.get("source") != source
            or pre.get("study_profile_sha256") != profile_sha256
            or pre.get("readiness") != class_attestation._file_binding(readiness_path)
        ):
            raise ValueError("20-site historical snapshots use different authorities")
        results = _validate_formal_results(
            roots=roots,
            profile=profile,
            readiness=readiness,
            readiness_path=readiness_path,
            pre=pre,
            pre_path=pre_path,
            recorded_at=timestamp,
        )
        pre_binding = class_attestation._file_binding(pre_path)
    guard = validate_historical_corpus_guard(deep=True)
    return {
        "snapshot_schema_version": SCHEMA_VERSION,
        "artifact_type": RECEIPT_TYPE,
        "study_id": profile.study_id,
        "study_profile_sha256": profile_sha256,
        "phase": phase,
        "recorded_at": timestamp.isoformat(),
        "source": dict(source),
        "readiness": class_attestation._file_binding(readiness_path),
        "historical_corpus_guard": guard,
        "historical_corpus_guard_sha256": canonical_json_sha256(guard),
        "pre_formal_snapshot": pre_binding,
        "formal_results": results,
    }


def _validate_formal_results(
    *,
    roots: Sequence[Path],
    profile: Any,
    readiness: Mapping[str, Any],
    readiness_path: Path,
    pre: Mapping[str, Any],
    pre_path: Path,
    recorded_at: datetime,
) -> list[dict[str, str]]:
    evidence = readiness["evidence"]
    summary = readiness["summary"]
    final_cohort = class_attestation._path_from_binding(
        evidence["final_cohort"], label="20-site final cohort"
    )
    final_assembly = class_attestation._path_from_binding(
        evidence["final_cohort_assembly"], label="20-site final cohort assembly"
    )
    foundation_sha256 = evidence["foundation"]["sha256"]
    readiness_sha256 = sha256_file(readiness_path)
    pre_sha256 = sha256_file(pre_path)
    profile_sha256 = readiness["study_profile_sha256"]
    qualification_sha256 = summary["final_qualification_set_manifest_sha256"]
    certification_runtime = class_attestation._validated_runtime_inputs(
        summary["certification_defense_runtime_inputs"],
        expected_modes=COMPATIBILITY_MODES,
        label="20-site certification runtime",
    )
    expected_runtime = {mode: certification_runtime[mode] for mode in FORMAL_MODES}
    certification_parameters = summary["certification_defense_parameter_sha256"]
    expected_parameters = {
        mode: certification_parameters[mode]
        for mode in FORMAL_MODES
        if mode in class_attestation._PARAMETER_MODES
    }
    expected_lineage = {
        "class_study_id": profile.study_id,
        "class_study_profile_sha256": profile_sha256,
        "class_study_foundation_sha256": foundation_sha256,
        "class_study_readiness_sha256": readiness_sha256,
        "class_study_historical_pre_snapshot_sha256": pre_sha256,
        "cohort_sha256": sha256_file(final_cohort),
        "cohort_assembly_sha256": sha256_file(final_assembly),
    }
    first_start_after = class_attestation._aware_timestamp(
        pre["recorded_at"], label="20-site pre snapshot"
    )
    environments: list[Mapping[str, Any]] = []
    bindings: list[dict[str, str]] = []
    launches: set[str] = set()
    accepted_total = 0
    for block, root in enumerate(roots, start=1):
        record = verify_profile_class_result(
            root,
            profile=profile,
            cohort_receipt=final_cohort,
            cohort_assembly=final_assembly,
            expected_role="formal",
            expected_block=block,
        )
        if (
            record.get("valid") is not True
            or any(record.get(key) != value for key, value in expected_lineage.items())
            or record.get("samples")
            != profile.final_count * len(FORMAL_MODES) * profile.formal_visits_per_block
            or record.get("accepted")
            != profile.final_count * len(FORMAL_MODES) * profile.formal_visits_per_block
            or class_attestation._validated_runtime_inputs(
                record.get("defense_runtime_inputs"),
                expected_modes=FORMAL_MODES,
                label=f"20-site formal block {block:02d}",
            ) != expected_runtime
            or record.get("defense_parameter_sha256") != expected_parameters
            or record.get("chaff_qualification_set_manifest_sha256") != qualification_sha256
            or record.get("chaff_qualification_set")
            != class_study_layout(profile=profile).final_qualification_set_root.name
        ):
            raise ValueError(f"20-site formal block {block:02d} differs from readiness")
        launch_sha256 = record.get("class_study_launch_sha256")
        if not isinstance(launch_sha256, str) or launch_sha256 in launches:
            raise ValueError("20-site formal blocks lack unique first-launch identities")
        launches.add(launch_sha256)
        verified = verify_result(root)
        if verified.experiment.get("source") != readiness["source"]:
            raise ValueError("20-site formal block uses another immutable source")
        started = class_attestation._aware_timestamp(
            verified.experiment.get("started_at"),
            label=f"20-site formal block {block:02d} start",
        )
        completed = class_attestation._aware_timestamp(
            verified.experiment.get("completed_at"),
            label=f"20-site formal block {block:02d} completion",
        )
        if started < first_start_after or completed <= started:
            raise ValueError("20-site formal blocks are not chronological and non-overlapping")
        first_start_after = completed
        environments.append(_validate_result_environment(verified, readiness["source"]))
        accepted_total += record["accepted"]
        bindings.append(
            {
                "root": str(root),
                "evidence_sha256": record["evidence_sha256"],
                "class_study_launch_sha256": launch_sha256,
                "class_study_foundation_sha256": foundation_sha256,
                "class_study_readiness_sha256": readiness_sha256,
                "class_study_historical_pre_snapshot_sha256": pre_sha256,
            }
        )
    if (
        accepted_total != profile.formal_sample_count
        or summary.get("formal_expected_samples") != profile.formal_sample_count
        or recorded_at < first_start_after
        or class_attestation._one_class_build_execution_identity(
            environments, include_completion=True
        ) != readiness["build_execution_identity"]
    ):
        raise ValueError("20-site post snapshot lacks complete same-build formal evidence")
    return bindings
