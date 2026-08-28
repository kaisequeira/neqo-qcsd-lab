from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from qcsd_lab import class_fitting, class_layout, util
from qcsd_lab.class_campaigns import campaign_documents


def _use_lab_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", root)


def test_layout_uses_dynamic_lab_root_and_exact_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    _use_lab_root(monkeypatch, root)

    layout = class_layout.class_study_layout()

    assert layout.lab_root == root
    assert layout.config_root == root / "config"
    assert layout.campaign_root == root / "config/classifier-multiorigin100-v1-campaigns"
    assert layout.campaign_root.parent == layout.config_root
    assert layout.workload_root == root / "config/workloads"
    assert layout.study_config_root == root / "config/class-study/v1"
    assert layout.defense_params_root == root / "config/defense-params"
    assert layout.artifacts_root == root / "artifacts"
    assert layout.acquisition_root == (
        root / "artifacts/classifier-multiorigin100-v1-acquisition"
    )
    assert layout.stability_root == (
        root / "artifacts/classifier-multiorigin100-v1-stability"
    )
    assert layout.pilot_numeric_root == (
        root / "artifacts/classifier-multiorigin100-v1-pilot-fitting-numeric"
    )
    assert layout.pilot_final_root == (
        root / "artifacts/classifier-multiorigin100-v1-pilot-fitting"
    )
    assert layout.pilot_prefix_root == (
        root / "artifacts/classifier-multiorigin100-v1-pilot-fitting-prefix-specs"
    )
    assert layout.authoritative_numeric_root == (
        root / "artifacts/classifier-multiorigin100-v1-authoritative-fitting-numeric"
    )
    assert layout.authoritative_final_root == (
        root / "artifacts/classifier-multiorigin100-v1-authoritative-fitting"
    )
    assert layout.authoritative_prefix_root == (
        root / "artifacts/classifier-multiorigin100-v1-authoritative-fitting-prefix-specs"
    )
    assert layout.pilot_qualification_set_root == (
        root
        / "config/chaff-qualification-store/sets/"
        "classifier-multiorigin100-v1-pilot120-full-v1"
    )
    assert layout.final_qualification_set_root == (
        root
        / "config/chaff-qualification-store/sets/"
        "classifier-multiorigin100-v1-final100-full-v1"
    )
    assert class_layout.PILOT_NUMERIC_DIRECTORY == class_fitting.PILOT_NUMERIC_DIRECTORY
    assert (
        class_layout.AUTHORITATIVE_NUMERIC_DIRECTORY
        == class_fitting.AUTHORITATIVE_NUMERIC_DIRECTORY
    )
    assert class_layout.PILOT_FINAL_DIRECTORY == class_fitting.PILOT_BUNDLE_DIRECTORY
    assert (
        class_layout.AUTHORITATIVE_FINAL_DIRECTORY
        == class_fitting.AUTHORITATIVE_BUNDLE_DIRECTORY
    )
    assert class_layout.PILOT_PREFIX_DIRECTORY == class_fitting.PILOT_PREFIX_DIRECTORY
    assert (
        class_layout.AUTHORITATIVE_PREFIX_DIRECTORY
        == class_fitting.AUTHORITATIVE_PREFIX_DIRECTORY
    )
    assert class_layout.PILOT_QUALIFICATION_SET == class_fitting.PILOT_QUALIFICATION_SET
    assert (
        class_layout.FINAL_QUALIFICATION_SET
        == class_fitting.AUTHORITATIVE_QUALIFICATION_SET
    )


def test_fresh_path_helper_rejects_alternate_and_frozen_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    _use_lab_root(monkeypatch, root)
    expected = root / "config/workloads"

    assert (
        class_layout.require_canonical_fresh_path(expected, field="workload_root")
        == expected
    )
    with pytest.raises(ValueError, match="outside the canonical class-study layout"):
        class_layout.require_canonical_fresh_path(
            root / "alternate/workloads",
            field="workload_root",
        )
    with pytest.raises(ValueError, match="outside the canonical class-study layout"):
        class_layout.require_canonical_fresh_path(
            root / "results/run/inputs/workloads",
            field="workload_root",
        )
    with pytest.raises(ValueError, match="unknown canonical"):
        class_layout.require_canonical_fresh_path(expected, field="not_a_layout_field")


def test_fresh_helpers_reject_existing_symlink_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "config").symlink_to(outside, target_is_directory=True)
    _use_lab_root(monkeypatch, root)

    with pytest.raises(ValueError, match="symbolic-link component"):
        class_layout.require_canonical_fresh_path(
            root / "config/workloads",
            field="workload_root",
        )
    with pytest.raises(ValueError, match="symbolic-link component"):
        class_layout.require_canonical_campaign_reference(
            class_layout.DEFAULT_COHORT_REFERENCE,
            field="study_config_root",
            filename="classifier-multiorigin100-v1-cohort.json",
        )


def test_fresh_child_helper_requires_direct_exact_unsymlinked_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    study_root = root / "config/class-study/v1"
    study_root.mkdir(parents=True)
    _use_lab_root(monkeypatch, root)
    exact = study_root / "classifier-multiorigin100-v1-candidates.json"

    assert class_layout.require_canonical_fresh_child(
        exact,
        field="study_config_root",
        filename=exact.name,
    ) == exact
    with pytest.raises(ValueError, match="direct child"):
        class_layout.require_canonical_fresh_child(
            study_root / "nested/cohort.json",
            field="study_config_root",
        )
    with pytest.raises(ValueError, match="wrong canonical filename"):
        class_layout.require_canonical_fresh_child(
            study_root / "substitute.json",
            field="study_config_root",
            filename=exact.name,
        )
    target = tmp_path / "outside.json"
    target.write_text("{}\n", encoding="utf-8")
    exact.symlink_to(target)
    with pytest.raises(ValueError, match="symbolic-link component"):
        class_layout.require_canonical_fresh_child(
            exact,
            field="study_config_root",
            filename=exact.name,
        )


def test_campaign_references_are_canonical_without_existing_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "absent-lab"
    _use_lab_root(monkeypatch, root)

    assert class_layout.canonical_campaign_reference(
        field="study_config_root",
        filename="classifier-multiorigin100-v1-cohort.json",
    ) == class_layout.DEFAULT_COHORT_REFERENCE
    assert class_layout.canonical_campaign_reference(
        field="study_config_root",
        filename="classifier-multiorigin100-v1-cohort-assembly.json",
    ) == class_layout.DEFAULT_COHORT_ASSEMBLY_REFERENCE
    assert (
        class_layout.canonical_campaign_reference(field="pilot_final_root")
        == class_layout.DEFAULT_PILOT_FINAL_REFERENCE
    )
    assert (
        class_layout.canonical_campaign_reference(field="authoritative_final_root")
        == class_layout.DEFAULT_AUTHORITATIVE_FINAL_REFERENCE
    )
    with pytest.raises(ValueError, match="alternate class-study path"):
        class_layout.require_canonical_campaign_reference(
            "../class-study/classifier-multiorigin100-v1-cohort.json",
            field="study_config_root",
            filename="classifier-multiorigin100-v1-cohort.json",
        )
    with pytest.raises(ValueError, match="normalised relative POSIX path"):
        class_layout.require_canonical_campaign_reference(
            "/tmp/cohort.json",
            field="study_config_root",
            filename="classifier-multiorigin100-v1-cohort.json",
        )
    with pytest.raises(ValueError, match="normalised relative POSIX path"):
        class_layout.require_canonical_campaign_reference(
            "../class-study/../class-study/v1/classifier-multiorigin100-v1-cohort.json",
            field="study_config_root",
            filename="classifier-multiorigin100-v1-cohort.json",
        )
    with pytest.raises(ValueError, match="escapes the canonical Lab root"):
        class_layout.require_safe_campaign_reference(
            "../../../outside.json",
            label="test reference",
        )


def test_campaign_generator_defaults_bind_the_versioned_layout() -> None:
    parameters = inspect.signature(campaign_documents).parameters

    assert parameters["cohort_reference"].default == class_layout.DEFAULT_COHORT_REFERENCE
    assert (
        parameters["cohort_assembly_reference"].default
        == class_layout.DEFAULT_COHORT_ASSEMBLY_REFERENCE
    )
    assert (
        parameters["pilot_bundle_reference"].default
        == class_layout.DEFAULT_PILOT_FINAL_REFERENCE
    )
    assert (
        parameters["authoritative_bundle_reference"].default
        == class_layout.DEFAULT_AUTHORITATIVE_FINAL_REFERENCE
    )


def test_generated_receipt_filenames_are_exact_and_study_scoped() -> None:
    assert class_layout.PILOT_COHORT_FILENAME == (
        "classifier-multiorigin100-v1-pilot-cohort.json"
    )
    assert class_layout.PILOT_COHORT_ASSEMBLY_FILENAME == (
        "classifier-multiorigin100-v1-pilot-cohort-assembly.json"
    )
    assert class_layout.AUTHORITATIVE_COHORT_FILENAME == (
        "classifier-multiorigin100-v1-cohort.json"
    )
    assert class_layout.AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME == (
        "classifier-multiorigin100-v1-cohort-assembly.json"
    )
    assert class_layout.FINAL_SELECTION_FILENAME == (
        "classifier-multiorigin100-v1-final-selection.json"
    )
