"""Evidence-replayed final 20-site choice from the planned pilot pairs."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
from typing import Any

from .class_cohort20 import (
    COHORT_RECEIPT_TYPE,
    load_validated_profile_cohort,
)
from .class_layout import class_study_layout, require_canonical_fresh_child
from .class_pair_screening20 import RECEIPT_TYPE as PAIR_SCREENING_RECEIPT_TYPE
from .class_pair_screening20 import validate_pair_screening_receipt
from .class_pipeline import PairQualificationOutcome, ProfileFinalSelection, select_profile_final
from .class_study import (
    CLASS20_PROFILE,
    ClassCandidate,
    ClassStudyProfile,
    bind_receipt,
    canonical_json_bytes,
    load_class20_profile_contract,
    validate_hash_bound_receipt,
    write_create_only_json,
)
from .util import load_json, sha256_file

RECEIPT_TYPE = "qcsd-class-study-profile-final-selection"
SCHEMA_VERSION = 1
SELECTION_POLICY = "first-cap-feasible-ten-qualified-pairs-in-registered-pilot-order"


def build_profile_final_selection_receipt(
    *,
    pair_screening_path: Path,
    pilot_cohort_path: Path,
    pilot_assembly_path: Path,
    profile: ClassStudyProfile = CLASS20_PROFILE,
) -> dict[str, Any]:
    """Reconstruct the 20-site choice from the entire deep-verified pair screen."""

    receipt, _selection = _build(
        pair_screening_path=pair_screening_path,
        pilot_cohort_path=pilot_cohort_path,
        pilot_assembly_path=pilot_assembly_path,
        profile=profile,
    )
    return receipt


def publish_profile_final_selection_receipt(
    destination: Path,
    *,
    pair_screening_path: Path,
    pilot_cohort_path: Path,
    pilot_assembly_path: Path,
    profile: ClassStudyProfile = CLASS20_PROFILE,
) -> Path:
    """Create a final-selection receipt once; never replace a prior outcome."""

    _require_profile(profile)
    target = require_canonical_fresh_child(
        destination, field="study_config_root",
        filename=f"{profile.study_id}-final-selection.json", profile=profile,
    )
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"final-selection receipt is create-only: {target}")
    receipt = build_profile_final_selection_receipt(
        pair_screening_path=pair_screening_path,
        pilot_cohort_path=pilot_cohort_path,
        pilot_assembly_path=pilot_assembly_path,
        profile=profile,
    )
    path = write_create_only_json(target, receipt)
    validate_profile_final_selection_receipt(
        path, pilot_cohort_path=pilot_cohort_path,
        pilot_assembly_path=pilot_assembly_path, profile=profile,
    )
    return path


def validate_profile_final_selection_receipt(
    receipt_path: Path,
    *,
    pilot_cohort_path: Path,
    pilot_assembly_path: Path,
    profile: ClassStudyProfile = CLASS20_PROFILE,
) -> ProfileFinalSelection:
    """Deeply replay the pair screen and deterministic cap-feasible choice."""

    _require_profile(profile)
    layout = class_study_layout(profile=profile)
    path = _file(require_canonical_fresh_child(
        receipt_path, field="study_config_root",
        filename=f"{profile.study_id}-final-selection.json", profile=profile,
    ), layout.lab_root)
    observed = load_json(path)
    payload = validate_hash_bound_receipt(observed, expected_type=RECEIPT_TYPE)
    if not isinstance(payload, Mapping) or not isinstance(payload.get("pair_screening"), Mapping):
        raise ValueError("final-selection receipt has no pair-screening binding")
    screening_path = _bound_path(payload["pair_screening"], layout.lab_root)
    expected, selection = _build(
        pair_screening_path=screening_path,
        pilot_cohort_path=pilot_cohort_path,
        pilot_assembly_path=pilot_assembly_path,
        profile=profile,
    )
    if canonical_json_bytes(observed) != canonical_json_bytes(expected):
        raise ValueError("final-selection receipt differs from replayed pair evidence")
    return selection


def _build(
    *, pair_screening_path: Path, pilot_cohort_path: Path,
    pilot_assembly_path: Path, profile: ClassStudyProfile,
) -> tuple[dict[str, Any], ProfileFinalSelection]:
    _require_profile(profile)
    layout = class_study_layout(profile=profile)
    cohort_path = _file(require_canonical_fresh_child(
        pilot_cohort_path, field="study_config_root",
        filename=f"{profile.study_id}-pilot-cohort.json", profile=profile,
    ), layout.lab_root)
    assembly_path = _file(require_canonical_fresh_child(
        pilot_assembly_path, field="study_config_root",
        filename=f"{profile.study_id}-pilot-cohort-assembly.json", profile=profile,
    ), layout.lab_root)
    screening_path = _file(require_canonical_fresh_child(
        pair_screening_path, field="study_config_root",
        filename=f"{profile.study_id}-pair-screening.json", profile=profile,
    ), layout.lab_root)
    pilot_ids, final_ids = load_validated_profile_cohort(
        cohort_path, assembly_path, profile=profile, require_deep=True,
    )
    if len(pilot_ids) != profile.pilot_count or final_ids:
        raise ValueError("final selection requires the completed 30-site pilot")
    cohort = load_json(cohort_path)
    cohort_payload = validate_hash_bound_receipt(cohort, expected_type=COHORT_RECEIPT_TYPE)
    screening = load_json(screening_path)
    screen_payload = validate_hash_bound_receipt(
        screening, expected_type=PAIR_SCREENING_RECEIPT_TYPE,
    )
    if not isinstance(screen_payload, Mapping):
        raise ValueError("pair-screening payload is malformed")
    numeric = screen_payload.get("numeric_bundle")
    if not isinstance(numeric, Mapping):
        raise ValueError("pair-screening numeric binding is malformed")
    inputs = {
        "pilot_cohort_path": cohort_path,
        "pilot_assembly_path": assembly_path,
        "numeric_bundle_root": _payload_path(numeric.get("root"), layout.lab_root),
        "fitting_result_root": _payload_path(numeric.get("fitting_result_root"), layout.lab_root),
        "workload_root": _payload_path(screen_payload.get("workload_root"), layout.lab_root),
        "prefix_spec_root": _payload_path(screen_payload.get("prefix_spec_root"), layout.lab_root),
        "sidecar_root": _payload_path(screen_payload.get("sidecar_root"), layout.lab_root),
        "foundation_attestation_path": _bound_path(
            screen_payload.get("foundation_attestation"), layout.lab_root,
        ),
        "profile": profile,
    }
    validate_pair_screening_receipt(screening, **inputs)
    if screen_payload.get("pilot_ids") != list(pilot_ids):
        raise ValueError("pair screening uses another pilot order")
    candidates = tuple(
        ClassCandidate(
            candidate_id=row["candidate_id"], domain=row["domain"],
            rank=row["rank"], eligible=row["eligible"],
        ) for row in cohort_payload["candidates"]
    )
    outcomes = tuple(
        PairQualificationOutcome(
            pair=tuple(row["pair"]), qualified=row["qualified"],
            evidence_sha256=row["evidence_sha256"],
            failure_reason=row["failure_reason"],
        ) for row in screen_payload["pair_outcomes"]
    )
    selection = select_profile_final(
        candidates,
        tranco_list_sha256=cohort_payload["tranco"]["list_sha256"],
        planned_pairs=screen_payload["planned_pairs"],
        pair_outcomes=outcomes,
        profile=profile,
    )
    if tuple(item.candidate_id for item in selection.pilot) != pilot_ids:
        raise ValueError("selected final cohort uses another pilot order")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "study_id": profile.study_id,
        "profile": _binding(layout.study_config_root / "study.json", layout.lab_root),
        "pilot_cohort": _binding(cohort_path, layout.lab_root),
        "pilot_assembly": _binding(assembly_path, layout.lab_root),
        "pair_screening": {
            **_binding(screening_path, layout.lab_root),
            "payload_sha256": screening["payload_sha256"],
        },
        "selection_policy": SELECTION_POLICY,
        "planned_pairs": [list(pair) for pair in selection.planned_pairs],
        "pair_outcomes": [
            {
                "pair": list(row.pair), "qualified": row.qualified,
                "failure_reason": row.failure_reason,
                "evidence_sha256": row.evidence_sha256,
            } for row in selection.pair_outcomes
        ],
        "qualified_pair_count": sum(row.qualified for row in selection.pair_outcomes),
        "final_ids": [item.candidate_id for item in selection.final],
        "reserve_ids": [item.candidate_id for item in selection.reserves],
        "matching": [list(pair) for pair in selection.matching],
    }
    return bind_receipt(payload, receipt_type=RECEIPT_TYPE), selection


def _require_profile(profile: ClassStudyProfile) -> None:
    if profile != CLASS20_PROFILE or load_class20_profile_contract() != profile:
        raise ValueError("final selection requires the source-pinned 20-site profile")


def _binding(path: Path, lab_root: Path) -> dict[str, str]:
    return {"path": _relative(path, lab_root), "sha256": sha256_file(path)}


def _bound_path(value: object, lab_root: Path) -> Path:
    if not isinstance(value, Mapping) or not isinstance(value.get("path"), str):
        raise ValueError("evidence binding has no path")
    return _payload_path(value["path"], lab_root)


def _payload_path(value: object, lab_root: Path) -> Path:
    if (
        not isinstance(value, str) or not value or Path(value).is_absolute()
        or any(part in {"", ".", ".."} for part in Path(value).parts)
    ):
        raise ValueError("pair-screening evidence path is not canonical")
    path = lab_root / value
    if _relative(path, lab_root) != value:
        raise ValueError("pair-screening evidence path is not canonical")
    return path


def _relative(path: Path, lab_root: Path) -> str:
    candidate = Path(os.path.abspath(path))
    if not candidate.is_relative_to(lab_root):
        raise ValueError("final-selection evidence is outside the Lab root")
    for part in (candidate, *candidate.parents):
        if part == lab_root.parent:
            break
        if part.is_symlink():
            raise ValueError("final-selection evidence contains a symbolic link")
    return candidate.relative_to(lab_root).as_posix()


def _file(path: Path, lab_root: Path) -> Path:
    candidate = Path(os.path.abspath(path))
    _relative(candidate, lab_root)
    if not candidate.is_file():
        raise ValueError(f"final-selection evidence file is missing: {candidate}")
    return candidate
