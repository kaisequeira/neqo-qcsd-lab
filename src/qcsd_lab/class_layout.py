"""Canonical fresh-input layout for ``classifier-multiorigin100-v1``.

The class study has one publication graph beneath the active Lab checkout.
This module deliberately covers only fresh, workspace-owned inputs.  Callers
that are reading a sealed result must branch to its frozen ``inputs/`` tree
before invoking these helpers.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass, fields
from pathlib import Path, PurePosixPath

from . import util
from .class_study import (
    CLASS20_PROFILE,
    FINAL_CLASS_COUNT,
    PILOT_COUNT,
    STUDY_ID,
    ClassStudyProfile,
)

CAMPAIGN_DIRECTORY = f"{STUDY_ID}-campaigns"
ACQUISITION_DIRECTORY = f"{STUDY_ID}-acquisition"
STABILITY_DIRECTORY = f"{STUDY_ID}-stability"
PILOT_FINAL_DIRECTORY = f"{STUDY_ID}-pilot-fitting"
AUTHORITATIVE_FINAL_DIRECTORY = f"{STUDY_ID}-authoritative-fitting"
PILOT_NUMERIC_DIRECTORY = f"{PILOT_FINAL_DIRECTORY}-numeric"
AUTHORITATIVE_NUMERIC_DIRECTORY = f"{AUTHORITATIVE_FINAL_DIRECTORY}-numeric"
PILOT_PREFIX_DIRECTORY = f"{PILOT_FINAL_DIRECTORY}-prefix-specs"
AUTHORITATIVE_PREFIX_DIRECTORY = f"{AUTHORITATIVE_FINAL_DIRECTORY}-prefix-specs"
PILOT_QUALIFICATION_SET = f"{STUDY_ID}-pilot120-full-v1"
FINAL_QUALIFICATION_SET = f"{STUDY_ID}-final100-full-v1"
PILOT_COHORT_FILENAME = f"{STUDY_ID}-pilot-cohort.json"
PILOT_COHORT_ASSEMBLY_FILENAME = f"{STUDY_ID}-pilot-cohort-assembly.json"
AUTHORITATIVE_COHORT_FILENAME = f"{STUDY_ID}-cohort.json"
AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME = f"{STUDY_ID}-cohort-assembly.json"
FINAL_SELECTION_FILENAME = f"{STUDY_ID}-final-selection.json"

DEFAULT_COHORT_REFERENCE = f"../class-study/v1/{AUTHORITATIVE_COHORT_FILENAME}"
DEFAULT_COHORT_ASSEMBLY_REFERENCE = (
    f"../class-study/v1/{AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME}"
)
DEFAULT_PILOT_FINAL_REFERENCE = f"../../artifacts/{PILOT_FINAL_DIRECTORY}"
DEFAULT_AUTHORITATIVE_FINAL_REFERENCE = (
    f"../../artifacts/{AUTHORITATIVE_FINAL_DIRECTORY}"
)


@dataclass(frozen=True)
class ClassStudyLayout:
    """Exact workspace paths for fresh class-study inputs and publications."""

    lab_root: Path
    results_root: Path
    config_root: Path
    campaign_root: Path
    workload_root: Path
    study_config_root: Path
    defense_params_root: Path
    artifacts_root: Path
    acquisition_root: Path
    stability_root: Path
    pilot_numeric_root: Path
    pilot_final_root: Path
    pilot_prefix_root: Path
    authoritative_numeric_root: Path
    authoritative_final_root: Path
    authoritative_prefix_root: Path
    qualification_sets_root: Path
    pilot_qualification_set_root: Path
    final_qualification_set_root: Path


def class_study_layout(*, profile: ClassStudyProfile | None = None) -> ClassStudyLayout:
    """Return the canonical graph beneath the currently active dynamic Lab root."""

    if profile is not None and profile != CLASS20_PROFILE:
        raise ValueError("unsupported class-study layout profile")
    study_id = STUDY_ID if profile is None else profile.study_id
    pilot_count = PILOT_COUNT if profile is None else profile.pilot_count
    final_count = FINAL_CLASS_COUNT if profile is None else profile.final_count
    study_config_version = "v1" if profile is None else "v2"
    lab_root = _absolute(util.LAB_ROOT)
    config_root = lab_root / "config"
    artifacts_root = lab_root / "artifacts"
    qualification_sets_root = config_root / "chaff-qualification-store/sets"
    return ClassStudyLayout(
        lab_root=lab_root,
        results_root=lab_root / "results",
        config_root=config_root,
        campaign_root=config_root / f"{study_id}-campaigns",
        workload_root=(
            config_root / "workloads"
            if profile is None
            else config_root / f"{study_id}-workloads"
        ),
        study_config_root=config_root / "class-study" / study_config_version,
        defense_params_root=config_root / "defense-params",
        artifacts_root=artifacts_root,
        acquisition_root=artifacts_root / f"{study_id}-acquisition",
        stability_root=artifacts_root / f"{study_id}-stability",
        pilot_numeric_root=artifacts_root / f"{study_id}-pilot-fitting-numeric",
        pilot_final_root=artifacts_root / f"{study_id}-pilot-fitting",
        pilot_prefix_root=artifacts_root / f"{study_id}-pilot-fitting-prefix-specs",
        authoritative_numeric_root=artifacts_root / f"{study_id}-authoritative-fitting-numeric",
        authoritative_final_root=artifacts_root / f"{study_id}-authoritative-fitting",
        authoritative_prefix_root=artifacts_root / f"{study_id}-authoritative-fitting-prefix-specs",
        qualification_sets_root=qualification_sets_root,
        pilot_qualification_set_root=(
            qualification_sets_root / f"{study_id}-pilot{pilot_count}-full-v1"
        ),
        final_qualification_set_root=(
            qualification_sets_root / f"{study_id}-final{final_count}-full-v1"
        ),
    )


def require_canonical_fresh_path(
    path: Path,
    *,
    field: str,
    label: str | None = None,
    profile: ClassStudyProfile | None = None,
) -> Path:
    """Require one exact fresh-layout path without requiring it to exist.

    This function intentionally has no frozen-input exception.  Resume and
    verification callers must resolve sealed result inputs on their own path.
    """

    layout = class_study_layout(profile=profile)
    expected = _layout_field(layout, field)
    candidate = _absolute(path)
    description = label or field.replace("_", " ")
    if candidate != expected:
        raise ValueError(
            f"{description} is outside the canonical class-study layout: "
            f"expected {expected}, got {candidate}"
        )
    _reject_existing_symlinks(candidate, root=layout.lab_root, label=description)
    return candidate


def require_canonical_acquisition_root(
    path: Path,
    *,
    label: str = "acquisition root",
    profile: ClassStudyProfile | None = None,
) -> Path:
    """Require the canonical root or an exact versioned sibling beneath artifacts."""

    layout = class_study_layout(profile=profile)
    canonical = layout.acquisition_root
    candidate = _absolute(path)
    prefix = f"{canonical.name}-v"
    version = candidate.name[len(prefix) :] if candidate.name.startswith(prefix) else ""
    versioned_sibling = (
        candidate.parent == canonical.parent
        and bool(version)
        and version.isascii()
        and version.isdecimal()
        and version[0] != "0"
    )
    if candidate != canonical and not versioned_sibling:
        raise ValueError(
            f"{label} is outside the canonical class-study layout: "
            f"expected {canonical} or a versioned -vN sibling, got {candidate}"
        )
    _reject_existing_symlinks(candidate, root=layout.lab_root, label=label)
    return candidate


def publication_roots_for_acquisition_root(
    acquisition_root: Path, *, profile: ClassStudyProfile | None = None
) -> tuple[Path, Path]:
    """Return the one stability/workload pair owned by an acquisition root.

    The unsuffixed pair remains available for historical verification. New
    allocations use the same ``-vN`` suffix on all three publication roots.
    """

    layout = class_study_layout(profile=profile)
    runner = require_canonical_acquisition_root(acquisition_root, profile=profile)
    if runner == layout.acquisition_root:
        return layout.stability_root, layout.workload_root
    suffix = runner.name.removeprefix(layout.acquisition_root.name)
    return (
        layout.stability_root.with_name(layout.stability_root.name + suffix),
        layout.workload_root.with_name(layout.workload_root.name + suffix),
    )


def require_canonical_publication_root(
    path: Path,
    *,
    field: str,
    label: str | None = None,
    profile: ClassStudyProfile | None = None,
) -> Path:
    """Require the historical root or one exact versioned sibling."""

    if field not in {"stability_root", "workload_root"}:
        raise ValueError(f"unknown class-study publication root field: {field}")
    layout = class_study_layout(profile=profile)
    canonical = _layout_field(layout, field)
    candidate = _absolute(path)
    description = label or field.replace("_", " ")
    suffix = candidate.name.removeprefix(canonical.name + "-v")
    versioned_sibling = (
        candidate.parent == canonical.parent
        and candidate.name.startswith(canonical.name + "-v")
        and bool(suffix)
        and suffix.isascii()
        and suffix.isdecimal()
        and suffix[0] != "0"
    )
    if candidate != canonical and not versioned_sibling:
        raise ValueError(
            f"{description} is outside the canonical class-study layout: "
            f"expected {canonical} or a versioned -vN sibling, got {candidate}"
        )
    _reject_existing_symlinks(candidate, root=layout.lab_root, label=description)
    return candidate


def require_cohort_publication_roots(
    acquisition_root: Path,
    stability_root: Path,
    workload_root: Path,
    *,
    require_versioned: bool = False,
    profile: ClassStudyProfile | None = None,
) -> tuple[Path, Path]:
    """Require publication roots to share the acquisition allocation number."""

    layout = class_study_layout(profile=profile)
    runner = require_canonical_acquisition_root(acquisition_root, profile=profile)
    if require_versioned and runner == layout.acquisition_root:
        raise ValueError("new class-study acquisition requires a versioned -vN root")
    expected_stability, expected_workloads = publication_roots_for_acquisition_root(
        runner, profile=profile
    )
    stability = require_canonical_publication_root(
        stability_root, field="stability_root", label="stability root", profile=profile
    )
    workloads = require_canonical_publication_root(
        workload_root, field="workload_root", label="workload root", profile=profile
    )
    if (stability, workloads) != (expected_stability, expected_workloads):
        raise ValueError(
            "class-study stability and workload roots do not match the acquisition cohort"
        )
    return stability, workloads


def require_canonical_fresh_child(
    path: Path,
    *,
    field: str,
    filename: str | None = None,
    label: str | None = None,
    profile: ClassStudyProfile | None = None,
) -> Path:
    """Require one direct child of a canonical fresh-layout directory.

    ``filename`` makes the child identity exact.  Without it, callers may
    choose a receipt name, but cannot introduce an extra directory level or a
    symbolic-link component.
    """

    layout = class_study_layout(profile=profile)
    parent = _layout_field(layout, field)
    candidate = _absolute(path)
    description = label or f"child of {field.replace('_', ' ')}"
    if candidate.parent != parent:
        raise ValueError(
            f"{description} is outside the canonical class-study layout: "
            f"expected a direct child of {parent}, got {candidate}"
        )
    observed_name = _filename(candidate.name)
    if filename is not None and observed_name != _filename(filename):
        raise ValueError(
            f"{description} has the wrong canonical filename: "
            f"expected {filename}, got {observed_name}"
        )
    _reject_existing_symlinks(candidate, root=layout.lab_root, label=description)
    return candidate


def canonical_campaign_reference(
    *, field: str, filename: str | None = None, profile: ClassStudyProfile | None = None
) -> str:
    """Build a canonical POSIX reference from the dedicated campaign root."""

    layout = class_study_layout(profile=profile)
    target = _layout_field(layout, field)
    if filename is not None:
        target /= _filename(filename)
    relative = Path(os.path.relpath(target, layout.campaign_root)).as_posix()
    return require_canonical_campaign_reference(
        relative,
        field=field,
        filename=filename,
        profile=profile,
    )


def require_canonical_campaign_reference(
    reference: str,
    *,
    field: str,
    filename: str | None = None,
    label: str | None = None,
    profile: ClassStudyProfile | None = None,
) -> str:
    """Require a relative reference to resolve to one exact canonical target."""

    description = label or f"campaign reference to {field.replace('_', ' ')}"
    relative = _relative_reference(reference, label=description)
    layout = class_study_layout(profile=profile)
    target = _layout_field(layout, field)
    if filename is not None:
        target /= _filename(filename)
    candidate = _absolute(layout.campaign_root / Path(*relative.parts))
    if candidate != target:
        raise ValueError(
            f"{description} resolves to an alternate class-study path: "
            f"expected {target}, got {candidate}"
        )
    _reject_existing_symlinks(target, root=layout.lab_root, label=description)
    return reference


def require_canonical_campaign_child_reference(
    reference: str,
    *,
    field: str,
    label: str | None = None,
    profile: ClassStudyProfile | None = None,
) -> str:
    """Require a campaign reference to one direct canonical-directory child."""

    description = label or f"campaign reference below {field.replace('_', ' ')}"
    relative = _relative_reference(reference, label=description)
    layout = class_study_layout(profile=profile)
    parent = _layout_field(layout, field)
    candidate = _absolute(layout.campaign_root / Path(*relative.parts))
    if candidate.parent != parent:
        raise ValueError(
            f"{description} resolves to an alternate class-study path: "
            f"expected a direct child of {parent}, got {candidate}"
        )
    _filename(candidate.name)
    _reject_existing_symlinks(candidate, root=layout.lab_root, label=description)
    return reference


def require_safe_campaign_reference(
    reference: str, *, label: str, profile: ClassStudyProfile | None = None
) -> str:
    """Reject malformed references and lexical escapes from the active Lab root."""

    relative = _relative_reference(reference, label=label)
    layout = class_study_layout(profile=profile)
    candidate = _absolute(layout.campaign_root / Path(*relative.parts))
    if candidate != layout.lab_root and not candidate.is_relative_to(layout.lab_root):
        raise ValueError(f"{label} escapes the canonical Lab root: {reference}")
    _reject_existing_symlinks(candidate, root=layout.lab_root, label=label)
    return reference


def _layout_field(layout: ClassStudyLayout, name: str) -> Path:
    available = {item.name for item in fields(layout) if item.name != "lab_root"}
    if name not in available:
        raise ValueError(f"unknown canonical class-study layout field: {name}")
    value = getattr(layout, name)
    if not isinstance(value, Path):  # pragma: no cover - dataclass contract.
        raise TypeError(f"canonical class-study layout field is not a path: {name}")
    return value


def _relative_reference(value: str, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{label} must be a nonempty normalised POSIX path")
    reference = PurePosixPath(value)
    if (
        reference.is_absolute()
        or reference.as_posix() != value
        or posixpath.normpath(value) != value
    ):
        raise ValueError(f"{label} must be a normalised relative POSIX path")
    return reference


def _filename(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "\\" in value
        or PurePosixPath(value).name != value
    ):
        raise ValueError("canonical class-study filename must contain one safe component")
    return value


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _reject_existing_symlinks(path: Path, *, root: Path, label: str) -> None:
    """Reject symlink components beneath the Lab root, including the root itself."""

    candidate = _absolute(path)
    boundary = _absolute(root)
    if candidate != boundary and not candidate.is_relative_to(boundary):
        raise ValueError(f"{label} escapes the canonical Lab root: {candidate}")
    current = boundary
    if current.is_symlink():
        raise ValueError(f"{label} contains a symbolic-link component: {current}")
    for part in candidate.relative_to(boundary).parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symbolic-link component: {current}")
