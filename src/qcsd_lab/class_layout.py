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
from .class_study import STUDY_ID

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


def class_study_layout() -> ClassStudyLayout:
    """Return the canonical graph beneath the currently active dynamic Lab root."""

    lab_root = _absolute(util.LAB_ROOT)
    config_root = lab_root / "config"
    artifacts_root = lab_root / "artifacts"
    qualification_sets_root = config_root / "chaff-qualification-store/sets"
    return ClassStudyLayout(
        lab_root=lab_root,
        results_root=lab_root / "results",
        config_root=config_root,
        campaign_root=config_root / CAMPAIGN_DIRECTORY,
        workload_root=config_root / "workloads",
        study_config_root=config_root / "class-study/v1",
        defense_params_root=config_root / "defense-params",
        artifacts_root=artifacts_root,
        acquisition_root=artifacts_root / ACQUISITION_DIRECTORY,
        stability_root=artifacts_root / STABILITY_DIRECTORY,
        pilot_numeric_root=artifacts_root / PILOT_NUMERIC_DIRECTORY,
        pilot_final_root=artifacts_root / PILOT_FINAL_DIRECTORY,
        pilot_prefix_root=artifacts_root / PILOT_PREFIX_DIRECTORY,
        authoritative_numeric_root=artifacts_root / AUTHORITATIVE_NUMERIC_DIRECTORY,
        authoritative_final_root=artifacts_root / AUTHORITATIVE_FINAL_DIRECTORY,
        authoritative_prefix_root=artifacts_root / AUTHORITATIVE_PREFIX_DIRECTORY,
        qualification_sets_root=qualification_sets_root,
        pilot_qualification_set_root=qualification_sets_root / PILOT_QUALIFICATION_SET,
        final_qualification_set_root=qualification_sets_root / FINAL_QUALIFICATION_SET,
    )


def require_canonical_fresh_path(
    path: Path,
    *,
    field: str,
    label: str | None = None,
) -> Path:
    """Require one exact fresh-layout path without requiring it to exist.

    This function intentionally has no frozen-input exception.  Resume and
    verification callers must resolve sealed result inputs on their own path.
    """

    layout = class_study_layout()
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


def require_canonical_fresh_child(
    path: Path,
    *,
    field: str,
    filename: str | None = None,
    label: str | None = None,
) -> Path:
    """Require one direct child of a canonical fresh-layout directory.

    ``filename`` makes the child identity exact.  Without it, callers may
    choose a receipt name, but cannot introduce an extra directory level or a
    symbolic-link component.
    """

    layout = class_study_layout()
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


def canonical_campaign_reference(*, field: str, filename: str | None = None) -> str:
    """Build a canonical POSIX reference from the dedicated campaign root."""

    layout = class_study_layout()
    target = _layout_field(layout, field)
    if filename is not None:
        target /= _filename(filename)
    relative = Path(os.path.relpath(target, layout.campaign_root)).as_posix()
    return require_canonical_campaign_reference(
        relative,
        field=field,
        filename=filename,
    )


def require_canonical_campaign_reference(
    reference: str,
    *,
    field: str,
    filename: str | None = None,
    label: str | None = None,
) -> str:
    """Require a relative reference to resolve to one exact canonical target."""

    description = label or f"campaign reference to {field.replace('_', ' ')}"
    relative = _relative_reference(reference, label=description)
    layout = class_study_layout()
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
) -> str:
    """Require a campaign reference to one direct canonical-directory child."""

    description = label or f"campaign reference below {field.replace('_', ' ')}"
    relative = _relative_reference(reference, label=description)
    layout = class_study_layout()
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


def require_safe_campaign_reference(reference: str, *, label: str) -> str:
    """Reject malformed references and lexical escapes from the active Lab root."""

    relative = _relative_reference(reference, label=label)
    layout = class_study_layout()
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
