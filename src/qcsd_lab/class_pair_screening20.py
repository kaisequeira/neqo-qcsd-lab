"""Replayable qualification screen for the prospective 20-site pilot pairs.

Only a fully validated sidecar for *both* endpoints proves a passing pair.
The sole negative outcome currently supported is a deterministic WT6 prefix
capacity failure, recomputed from a verified numeric fit and frozen prepared
workload.  A missing sidecar, failed command, timeout, or invalid evidence
remains pending and cannot be published as a screened pair.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from .chaff_qualification import (
    CLASS_STUDY_QUALIFICATION_SCHEMA_VERSION,
    load_qualified_chaff,
)
from .class_acquisition import validate_class_study_preparation
from .class_attestation import FOUNDATION_RECEIPT_TYPE, class_qualification_authority
from .class_cohort20 import load_validated_profile_cohort
from .class_fitting import (
    BUNDLE_FILES,
    NUMERIC_PROVENANCE_FILE,
    build_schema_six_prefix_spec,
    validate_schema_six_prefix_spec,
    verify_numeric_fitting_bundle,
)
from .class_layout import class_study_layout, require_canonical_fresh_child, require_canonical_fresh_path
from .class_study import (
    CLASS20_PROFILE,
    ClassStudyProfile,
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    load_class20_profile_contract,
    validate_hash_bound_receipt,
    write_create_only_json,
)
from .util import LAB_ROOT, load_json, sha256_file

RECEIPT_TYPE = "qcsd-class-study-pilot-pair-screening"
SCHEMA_VERSION = 1
_CAPACITY_FAILURES = frozenset({
    "receiver continuation horizon exceeds qualification stream ceiling",
    "Walkie-Talkie mould is infeasible within the qualified one-shot stream ceiling",
})


@dataclass(frozen=True)
class PrefixCapacityFailure:
    """A replayable numeric/prepared-capacity failure, not a failed live visit."""

    workload_id: str
    reason: str
    workload_sha256: str
    walkie_talkie_sha256: str


@dataclass(frozen=True)
class PrefixSpecPublication:
    """Operational publication result; the pair receipt remains authoritative."""

    published_paths: tuple[Path, ...]
    capacity_failures: tuple[PrefixCapacityFailure, ...]
    profile_sha256: str
    pilot_cohort_sha256: str
    numeric_provenance_sha256: str


def build_pair_screening_receipt(
    *,
    pilot_cohort_path: Path,
    pilot_assembly_path: Path,
    numeric_bundle_root: Path,
    fitting_result_root: Path,
    workload_root: Path,
    prefix_spec_root: Path,
    sidecar_root: Path,
    foundation_attestation_path: Path,
    profile: ClassStudyProfile = CLASS20_PROFILE,
) -> dict[str, Any]:
    """Rebuild all 15 outcomes from exact file-backed evidence or fail closed."""

    if profile != CLASS20_PROFILE or load_class20_profile_contract() != profile:
        raise ValueError("pair screening requires the source-pinned 20-site profile")
    layout = class_study_layout(profile=profile)
    overlay_path = _file(layout.study_config_root / "study.json", layout.lab_root)
    source_overlay = LAB_ROOT / "config/class-study/v2/study.json"
    if sha256_file(overlay_path) != sha256_file(source_overlay):
        raise ValueError("pair-screening profile differs from source-pinned overlay")
    cohort_path = require_canonical_fresh_child(
        pilot_cohort_path, field="study_config_root",
        filename=f"{profile.study_id}-pilot-cohort.json", profile=profile,
    )
    assembly_path = require_canonical_fresh_child(
        pilot_assembly_path, field="study_config_root",
        filename=f"{profile.study_id}-pilot-cohort-assembly.json", profile=profile,
    )
    numeric_root = require_canonical_fresh_path(
        numeric_bundle_root, field="pilot_numeric_root", profile=profile,
    )
    specs = require_canonical_fresh_path(
        prefix_spec_root, field="pilot_prefix_root", profile=profile,
    )
    sidecars = require_canonical_fresh_path(
        sidecar_root, field="pilot_qualification_set_root", profile=profile,
    )
    cohort_path = _file(cohort_path, layout.lab_root)
    assembly_path = _file(assembly_path, layout.lab_root)
    numeric_root = _directory(numeric_root, layout.lab_root)
    specs = _directory(specs, layout.lab_root)
    sidecars = _directory(sidecars, layout.lab_root)
    fitting_root = _directory(fitting_result_root, layout.lab_root)
    foundation_path = _file(foundation_attestation_path, layout.lab_root)

    cohort = load_json(cohort_path)
    assembly = load_json(assembly_path)
    pilot_ids, final_ids = load_validated_profile_cohort(
        cohort_path, assembly_path, profile=profile, require_deep=True,
    )
    if len(pilot_ids) != profile.pilot_count or final_ids:
        raise ValueError("pair screening requires the completed pilot cohort")
    assembly_payload = validate_hash_bound_receipt(
        assembly, expected_type="qcsd-class-study-profile-cohort-assembly"
    )
    if _relative(workload_root, layout.lab_root) != assembly_payload["workload_root"]:
        raise ValueError("pair screening workload root differs from the admitted pilot")
    workloads = _directory(workload_root, layout.lab_root)

    numeric = verify_numeric_fitting_bundle(
        numeric_root, source_result_root=fitting_root,
    )
    provenance = numeric.provenance
    if (
        numeric.stage != "pilot"
        or provenance.get("study_id") != profile.study_id
        or provenance.get("study_profile_sha256")
        != sha256_file(layout.study_config_root / "study.json")
        or provenance["fitting_contract"]["workload_order"] != list(pilot_ids)
        or provenance["cohort"]["receipt"] != cohort
        or provenance["cohort"]["assembly_receipt"] != assembly
        or provenance["cohort"]["receipt_sha256"]
        != canonical_json_sha256(cohort)
        or provenance["cohort"]["assembly_receipt_sha256"]
        != canonical_json_sha256(assembly)
    ):
        raise ValueError("numeric WT6 fit differs from the admitted pilot or profile")
    authority = class_qualification_authority(
        # Offline replay verifies the recorded build and every foundation gate
        # without depending on the reviewer's currently running container.
        foundation_path, deep_code_gate=True, runtime_role=None,
    )
    foundation = validate_hash_bound_receipt(
        load_json(foundation_path), expected_type=FOUNDATION_RECEIPT_TYPE,
    )
    if (
        foundation.get("study_id") != profile.study_id
        or foundation.get("study_profile_sha256") != sha256_file(overlay_path)
    ):
        raise ValueError("pair screening requires this profile's full foundation")
    if provenance["source_result"]["source_fingerprints"] != authority["collection_source"]:
        raise ValueError("pilot numeric fit and full foundation use different source or image")

    walkie_path = _file(numeric_root / BUNDLE_FILES["walkie_talkie"], layout.lab_root)
    walkie = load_json(walkie_path)
    walkie_sha = sha256_file(walkie_path)
    planned = _planned_pairs(walkie, pilot_ids)
    rows: list[dict[str, Any]] = []
    for left, right in planned:
        endpoint_inputs: list[tuple[str, Path, Mapping[str, Any], dict[str, Any] | None, str | None]] = []
        for workload_id in (left, right):
            manifest_path = _file(workloads / f"{workload_id}.json", layout.lab_root)
            manifest = load_json(manifest_path)
            validate_class_study_preparation(manifest, workload_id=workload_id)
            try:
                derived_spec = build_schema_six_prefix_spec(
                    workload_id, walkie,
                    source_walkie_talkie_artifact_sha256=walkie_sha,
                    application_manifest=manifest,
                )
            except ValueError as error:
                if str(error) not in _CAPACITY_FAILURES:
                    raise
                endpoint_inputs.append((workload_id, manifest_path, manifest, None, str(error)))
            else:
                endpoint_inputs.append((workload_id, manifest_path, manifest, derived_spec, None))
        capacity_failures = [item for item in endpoint_inputs if item[4] is not None]
        endpoints: list[dict[str, Any]] = []
        if capacity_failures:
            # A capacity failure is a reproducible numeric/preparation fact.
            # Contradictory publication under the same identity blocks this
            # result; it is never interpreted as a failed live command.
            for workload_id, manifest_path, _manifest, _spec, reason in endpoint_inputs:
                if reason is not None and (
                    (specs / f"{workload_id}.json").exists()
                    or (sidecars / f"{workload_id}.json").exists()
                ):
                    raise ValueError("capacity-failed endpoint has contradictory qualification files")
                endpoints.append({
                    "workload_id": workload_id,
                    "workload": _binding(manifest_path, layout.lab_root),
                    "capacity_derivation": reason or "feasible",
                })
            qualified = False
            failure_reason = "deterministic-wt6-prefix-capacity"
        else:
            for workload_id, manifest_path, manifest, derived_spec, _reason in endpoint_inputs:
                assert derived_spec is not None
                spec_path = _file(specs / f"{workload_id}.json", layout.lab_root)
                sidecar_path = _file(sidecars / f"{workload_id}.json", layout.lab_root)
                spec = validate_schema_six_prefix_spec(
                    load_json(spec_path), workload_id=workload_id,
                    walkie_talkie=walkie,
                    source_walkie_talkie_artifact_sha256=walkie_sha,
                    application_manifest=manifest,
                )
                if spec["schema_version"] != 4 or canonical_json_bytes(spec) != canonical_json_bytes(derived_spec):
                    raise ValueError("pair endpoint lacks the exact scoped WT6 prefix spec")
                qualified_input = load_qualified_chaff(
                    sidecar_path, workload_id=workload_id,
                    base_manifest_path=manifest_path, prefix_spec_path=spec_path,
                    require_current_implementation=False,
                    expected_sidecar_schema_version=CLASS_STUDY_QUALIFICATION_SCHEMA_VERSION,
                    expected_qualification_authority=authority,
                )
                endpoints.append({
                    "workload_id": workload_id,
                    "workload": _binding(manifest_path, layout.lab_root),
                    "prefix_spec": _binding(spec_path, layout.lab_root),
                    "sidecar": _binding(sidecar_path, layout.lab_root),
                    "qualified_manifest_sha256": qualified_input.manifest_sha256,
                })
            qualified = True
            failure_reason = None
        evidence = {"pair": [left, right], "endpoints": endpoints}
        rows.append({
            **evidence,
            "qualified": qualified,
            "failure_reason": failure_reason,
            "evidence_sha256": canonical_json_sha256(evidence),
        })

    payload = {
        "schema_version": SCHEMA_VERSION,
        "study_id": profile.study_id,
        "profile": _binding(overlay_path, layout.lab_root),
        "pilot_cohort": _binding(cohort_path, layout.lab_root),
        "pilot_assembly": _binding(assembly_path, layout.lab_root),
        "numeric_bundle": {
            "root": _relative(numeric_root, layout.lab_root),
            "provenance_sha256": sha256_file(numeric_root / NUMERIC_PROVENANCE_FILE),
            "walkie_talkie_sha256": walkie_sha,
            "fitting_result_root": _relative(fitting_root, layout.lab_root),
            "source_result": provenance["source_result"],
        },
        "foundation_attestation": _binding(foundation_path, layout.lab_root),
        "qualification_authority_sha256": canonical_json_sha256(authority),
        "workload_root": _relative(workloads, layout.lab_root),
        "prefix_spec_root": _relative(specs, layout.lab_root),
        "sidecar_root": _relative(sidecars, layout.lab_root),
        "pilot_ids": list(pilot_ids),
        "planned_pairs": [list(pair) for pair in planned],
        "pair_outcomes": rows,
        "qualified_pair_count": sum(row["qualified"] for row in rows),
    }
    return bind_receipt(payload, receipt_type=RECEIPT_TYPE)


def validate_pair_screening_receipt(value: Mapping[str, Any], **inputs: Any) -> dict[str, Any]:
    """Recompute every outcome; a hash-valid caller assertion is insufficient."""

    validate_hash_bound_receipt(value, expected_type=RECEIPT_TYPE)
    expected = build_pair_screening_receipt(**inputs)
    if canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise ValueError("pair-screening receipt differs from replayed evidence")
    return expected


def publish_pair_screening_receipt(destination: Path, **inputs: Any) -> Path:
    """Create one immutable receipt only after all 15 pair proofs replay."""

    profile = inputs.get("profile", CLASS20_PROFILE)
    if profile != CLASS20_PROFILE or load_class20_profile_contract() != profile:
        raise ValueError("pair screening requires the source-pinned 20-site profile")
    target = require_canonical_fresh_child(
        destination, field="study_config_root",
        filename=f"{profile.study_id}-pair-screening.json", profile=profile,
    )
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"pair-screening receipt is create-only: {target}")
    receipt = build_pair_screening_receipt(**inputs)
    path = write_create_only_json(target, receipt)
    validate_pair_screening_receipt(load_json(path), **inputs)
    return path


def publish_feasible_pilot_prefix_specs(
    *,
    pilot_cohort_path: Path,
    pilot_assembly_path: Path,
    numeric_bundle_root: Path,
    fitting_result_root: Path,
    workload_root: Path,
    prefix_spec_root: Path,
    profile: ClassStudyProfile = CLASS20_PROFILE,
) -> PrefixSpecPublication:
    """Publish each feasible WT6 spec independently after a full pilot refit.

    Derive and validate every pilot endpoint before any write.  The two exact
    capacity-ceiling outcomes are returned as replayable negative evidence;
    all other failures abort without making new files.  Existing spec bytes
    are accepted only after full revalidation against the same numeric fit.
    A later call can resume a partially published directory without replacing
    any entry.  Pair screening independently replays these derivations.
    """

    return _replay_feasible_pilot_prefix_specs(
        pilot_cohort_path=pilot_cohort_path,
        pilot_assembly_path=pilot_assembly_path,
        numeric_bundle_root=numeric_bundle_root,
        fitting_result_root=fitting_result_root,
        workload_root=workload_root,
        prefix_spec_root=prefix_spec_root,
        profile=profile,
        create_missing=True,
    )


def verify_feasible_pilot_prefix_specs(
    *,
    pilot_cohort_path: Path,
    pilot_assembly_path: Path,
    numeric_bundle_root: Path,
    fitting_result_root: Path,
    workload_root: Path,
    prefix_spec_root: Path,
    profile: ClassStudyProfile = CLASS20_PROFILE,
) -> PrefixSpecPublication:
    """Deep-replay all 30 prefix outcomes without changing the filesystem.

    Every feasible endpoint must already have its exact scoped schema-four
    spec.  Deterministic capacity failures must have no spec.  The returned
    paths are verified existing files, never files this call created.
    """

    return _replay_feasible_pilot_prefix_specs(
        pilot_cohort_path=pilot_cohort_path,
        pilot_assembly_path=pilot_assembly_path,
        numeric_bundle_root=numeric_bundle_root,
        fitting_result_root=fitting_result_root,
        workload_root=workload_root,
        prefix_spec_root=prefix_spec_root,
        profile=profile,
        create_missing=False,
    )


def _replay_feasible_pilot_prefix_specs(
    *,
    pilot_cohort_path: Path,
    pilot_assembly_path: Path,
    numeric_bundle_root: Path,
    fitting_result_root: Path,
    workload_root: Path,
    prefix_spec_root: Path,
    profile: ClassStudyProfile,
    create_missing: bool,
) -> PrefixSpecPublication:

    if profile != CLASS20_PROFILE or load_class20_profile_contract() != profile:
        raise ValueError("pilot prefix publication requires the source-pinned 20-site profile")
    layout = class_study_layout(profile=profile)
    overlay_path = _file(layout.study_config_root / "study.json", layout.lab_root)
    source_overlay = LAB_ROOT / "config/class-study/v2/study.json"
    if sha256_file(overlay_path) != sha256_file(source_overlay):
        raise ValueError("pilot prefix profile differs from source-pinned overlay")
    cohort_path = _file(require_canonical_fresh_child(
        pilot_cohort_path, field="study_config_root",
        filename=f"{profile.study_id}-pilot-cohort.json", profile=profile,
    ), layout.lab_root)
    assembly_path = _file(require_canonical_fresh_child(
        pilot_assembly_path, field="study_config_root",
        filename=f"{profile.study_id}-pilot-cohort-assembly.json", profile=profile,
    ), layout.lab_root)
    numeric_root = _directory(require_canonical_fresh_path(
        numeric_bundle_root, field="pilot_numeric_root", profile=profile,
    ), layout.lab_root)
    specs = require_canonical_fresh_path(
        prefix_spec_root, field="pilot_prefix_root", profile=profile,
    )
    fitting_root = _directory(fitting_result_root, layout.lab_root)
    cohort = load_json(cohort_path)
    assembly = load_json(assembly_path)
    pilot_ids, final_ids = load_validated_profile_cohort(
        cohort_path, assembly_path, profile=profile, require_deep=True,
    )
    if len(pilot_ids) != profile.pilot_count or final_ids:
        raise ValueError("pilot prefix publication requires the completed pilot cohort")
    assembly_payload = validate_hash_bound_receipt(
        assembly, expected_type="qcsd-class-study-profile-cohort-assembly"
    )
    if _relative(workload_root, layout.lab_root) != assembly_payload["workload_root"]:
        raise ValueError("pilot prefix workload root differs from the admitted pilot")
    workloads = _directory(workload_root, layout.lab_root)
    numeric = verify_numeric_fitting_bundle(
        numeric_root, source_result_root=fitting_root,
    )
    provenance = numeric.provenance
    if (
        numeric.stage != "pilot"
        or provenance.get("study_id") != profile.study_id
        or provenance.get("study_profile_sha256") != sha256_file(overlay_path)
        or provenance["fitting_contract"]["workload_order"] != list(pilot_ids)
        or provenance["cohort"]["receipt"] != cohort
        or provenance["cohort"]["assembly_receipt"] != assembly
        or provenance["cohort"]["receipt_sha256"] != canonical_json_sha256(cohort)
        or provenance["cohort"]["assembly_receipt_sha256"]
        != canonical_json_sha256(assembly)
    ):
        raise ValueError("pilot prefix numeric WT6 fit differs from the admitted pilot")
    walkie_path = _file(numeric_root / BUNDLE_FILES["walkie_talkie"], layout.lab_root)
    walkie = load_json(walkie_path)
    walkie_sha = sha256_file(walkie_path)
    _planned_pairs(walkie, pilot_ids)

    # No filesystem mutation occurs until all 30 prepared manifests and their
    # WT6 derivations have been examined.  An unrelated exception is pending.
    feasible: list[tuple[str, Path, Mapping[str, Any], dict[str, Any]]] = []
    failures: list[PrefixCapacityFailure] = []
    for workload_id in pilot_ids:
        manifest_path = _file(workloads / f"{workload_id}.json", layout.lab_root)
        manifest = load_json(manifest_path)
        validate_class_study_preparation(manifest, workload_id=workload_id)
        try:
            spec = build_schema_six_prefix_spec(
                workload_id, walkie,
                source_walkie_talkie_artifact_sha256=walkie_sha,
                application_manifest=manifest,
            )
        except ValueError as error:
            if str(error) not in _CAPACITY_FAILURES:
                raise
            failures.append(PrefixCapacityFailure(
                workload_id=workload_id, reason=str(error),
                workload_sha256=sha256_file(manifest_path),
                walkie_talkie_sha256=walkie_sha,
            ))
        else:
            if spec.get("schema_version") != 4:
                raise ValueError("pilot prefix derivation did not produce scoped schema four")
            feasible.append((workload_id, manifest_path, manifest, spec))

    # Existing evidence is checked before adding any new specs.  This also
    # catches stale output for a now-failed capacity derivation.
    parent = layout.artifacts_root
    if parent.exists() or parent.is_symlink():
        _directory(parent, layout.lab_root)
    elif create_missing:
        parent.mkdir()
        _directory(parent, layout.lab_root)
    else:
        raise ValueError("pilot prefix artifacts root is absent")
    if specs.exists() or specs.is_symlink():
        _directory(specs, layout.lab_root)
        allowed = {f"{workload_id}.json" for workload_id in pilot_ids}
        if any(item.name not in allowed for item in specs.iterdir()):
            raise ValueError("pilot prefix directory contains an unknown entry")
    elif create_missing:
        try:
            specs.mkdir()
        except FileExistsError:
            pass
        _directory(specs, layout.lab_root)
    else:
        raise ValueError("pilot prefix spec directory is absent")
    for failure in failures:
        target = specs / f"{failure.workload_id}.json"
        if target.exists() or target.is_symlink():
            raise ValueError("capacity-failed endpoint has a contradictory prefix spec")
    for workload_id, manifest_path, manifest, derived in feasible:
        target = specs / f"{workload_id}.json"
        if target.exists() or target.is_symlink():
            _verify_published_spec(
                target, workload_id=workload_id, manifest=manifest,
                walkie=walkie, walkie_sha=walkie_sha, expected=derived,
                lab_root=layout.lab_root,
            )

    published: list[Path] = []
    for workload_id, _manifest_path, manifest, derived in feasible:
        target = specs / f"{workload_id}.json"
        if create_missing and not target.exists() and not target.is_symlink():
            try:
                write_create_only_json(target, derived)
            except FileExistsError:
                # Another create-only writer can win the race; exact replay is
                # still required before this run accepts those bytes.
                pass
        _verify_published_spec(
            target, workload_id=workload_id, manifest=manifest,
            walkie=walkie, walkie_sha=walkie_sha, expected=derived,
            lab_root=layout.lab_root,
        )
        published.append(target)
    return PrefixSpecPublication(
        published_paths=tuple(published),
        capacity_failures=tuple(failures),
        profile_sha256=sha256_file(overlay_path),
        pilot_cohort_sha256=sha256_file(cohort_path),
        numeric_provenance_sha256=sha256_file(numeric_root / NUMERIC_PROVENANCE_FILE),
    )


def _verify_published_spec(
    path: Path, *, workload_id: str, manifest: Mapping[str, Any],
    walkie: Mapping[str, Any], walkie_sha: str, expected: Mapping[str, Any],
    lab_root: Path,
) -> None:
    published = validate_schema_six_prefix_spec(
        load_json(_file(path, lab_root)), workload_id=workload_id,
        walkie_talkie=walkie,
        source_walkie_talkie_artifact_sha256=walkie_sha,
        application_manifest=manifest,
    )
    if (
        published.get("schema_version") != 4
        or canonical_json_bytes(published) != canonical_json_bytes(expected)
    ):
        raise ValueError("published pilot prefix spec differs from verified numeric derivation")


def _planned_pairs(walkie: Mapping[str, Any], pilot_ids: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    profiles = walkie.get("profiles")
    if not isinstance(profiles, list) or len(profiles) != len(pilot_ids) // 2:
        raise ValueError("numeric WT6 does not plan 15 pilot pairs")
    order = {workload_id: index for index, workload_id in enumerate(pilot_ids)}
    pairs: list[tuple[str, str]] = []
    covered: list[str] = []
    for row in profiles:
        if not isinstance(row, Mapping):
            raise ValueError("numeric WT6 planned pair is malformed")
        left, right = row.get("real"), row.get("decoy")
        if not isinstance(left, str) or not isinstance(right, str) or left not in order or right not in order or left == right:
            raise ValueError("numeric WT6 planned pair references another pilot")
        pairs.append(tuple(sorted((left, right), key=order.__getitem__)))
        covered.extend((left, right))
    if len(set(covered)) != len(pilot_ids) or set(covered) != set(pilot_ids):
        raise ValueError("numeric WT6 planned pairs do not cover the pilot exactly once")
    return tuple(sorted(pairs, key=lambda pair: (order[pair[0]], order[pair[1]])))


def _binding(path: Path, lab_root: Path) -> dict[str, str]:
    return {"path": _relative(path, lab_root), "sha256": sha256_file(path)}


def _relative(path: Path, lab_root: Path) -> str:
    candidate = Path(os.path.abspath(path))
    if not candidate.is_relative_to(lab_root):
        raise ValueError("pair-screening evidence is outside the Lab root")
    for part in (candidate, *candidate.parents):
        if part == lab_root.parent:
            break
        if part.is_symlink():
            raise ValueError("pair-screening evidence path contains a symbolic link")
    return candidate.relative_to(lab_root).as_posix()


def _file(path: Path, lab_root: Path) -> Path:
    candidate = Path(os.path.abspath(path))
    _relative(candidate, lab_root)
    if not candidate.is_file():
        raise ValueError(f"pair-screening evidence file is missing: {candidate}")
    return candidate


def _directory(path: Path, lab_root: Path) -> Path:
    candidate = Path(os.path.abspath(path))
    _relative(candidate, lab_root)
    if not candidate.is_dir():
        raise ValueError(f"pair-screening evidence directory is missing: {candidate}")
    return candidate
