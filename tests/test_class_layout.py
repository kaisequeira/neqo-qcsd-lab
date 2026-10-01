from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from qcsd_lab import class_fitting, class_layout, util
from qcsd_lab.class_campaigns import campaign_documents
from qcsd_lab.class_study import CLASS20_PROFILE


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


def test_20_site_profile_has_separate_canonical_publication_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    _use_lab_root(monkeypatch, root)
    layout = class_layout.class_study_layout(profile=CLASS20_PROFILE)

    assert layout.study_config_root == root / "config/class-study/v2"
    assert layout.campaign_root == root / "config/classifier-multiorigin20-v1-campaigns"
    assert layout.workload_root == root / "config/classifier-multiorigin20-v1-workloads"
    assert layout.acquisition_root == root / "artifacts/classifier-multiorigin20-v1-acquisition"
    assert layout.pilot_qualification_set_root.name == (
        "classifier-multiorigin20-v1-pilot30-full-v1"
    )
    assert layout.final_qualification_set_root.name == (
        "classifier-multiorigin20-v1-final20-full-v1"
    )
    runner = layout.acquisition_root.with_name(f"{layout.acquisition_root.name}-v140")
    stability, workloads = class_layout.publication_roots_for_acquisition_root(
        runner, profile=CLASS20_PROFILE
    )
    assert (stability.name, workloads.name) == (
        "classifier-multiorigin20-v1-stability-v140",
        "classifier-multiorigin20-v1-workloads-v140",
    )
    assert class_layout.require_cohort_publication_roots(
        runner, stability, workloads, require_versioned=True, profile=CLASS20_PROFILE
    ) == (stability, workloads)
    with pytest.raises(ValueError, match="outside the canonical class-study layout"):
        class_layout.require_canonical_acquisition_root(runner)
    assert class_layout.canonical_campaign_reference(
        field="study_config_root",
        filename="classifier-multiorigin20-v1-cohort.json",
        profile=CLASS20_PROFILE,
    ) == "../class-study/v2/classifier-multiorigin20-v1-cohort.json"
    with pytest.raises(ValueError, match="alternate class-study path"):
        class_layout.require_canonical_campaign_reference(
            class_layout.DEFAULT_COHORT_REFERENCE,
            field="study_config_root",
            filename="classifier-multiorigin20-v1-cohort.json",
            profile=CLASS20_PROFILE,
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


def test_acquisition_root_accepts_only_canonical_or_versioned_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    _use_lab_root(monkeypatch, root)
    canonical = class_layout.class_study_layout().acquisition_root
    versioned = canonical.with_name(f"{canonical.name}-v127")

    assert class_layout.require_canonical_acquisition_root(canonical) == canonical
    assert class_layout.require_canonical_acquisition_root(versioned) == versioned
    for rejected in (
        canonical.with_name(f"{canonical.name}-v0"),
        canonical.with_name(f"{canonical.name}-v01"),
        canonical.with_name(f"{canonical.name}-v1-extra"),
        versioned / "child",
        root / "alternate" / versioned.name,
    ):
        with pytest.raises(ValueError, match="outside the canonical class-study layout"):
            class_layout.require_canonical_acquisition_root(rejected)

    root.mkdir()
    canonical.parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    versioned.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic-link component"):
        class_layout.require_canonical_acquisition_root(versioned)


def test_versioned_acquisition_owns_one_paired_publication_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "lab"
    _use_lab_root(monkeypatch, root)
    layout = class_layout.class_study_layout()
    runner = layout.acquisition_root.with_name(f"{layout.acquisition_root.name}-v127")
    stability = layout.stability_root.with_name(f"{layout.stability_root.name}-v127")
    workloads = layout.workload_root.with_name(f"{layout.workload_root.name}-v127")

    assert class_layout.publication_roots_for_acquisition_root(runner) == (
        stability, workloads
    )
    assert class_layout.require_cohort_publication_roots(
        runner, stability, workloads, require_versioned=True
    ) == (stability, workloads)
    assert class_layout.publication_roots_for_acquisition_root(layout.acquisition_root) == (
        layout.stability_root, layout.workload_root
    )
    with pytest.raises(ValueError, match="requires a versioned"):
        class_layout.require_cohort_publication_roots(
            layout.acquisition_root,
            layout.stability_root,
            layout.workload_root,
            require_versioned=True,
        )
    for wrong in (
        layout.workload_root,
        workloads.with_name(f"{layout.workload_root.name}-v128"),
    ):
        with pytest.raises(ValueError, match="do not match the acquisition cohort"):
            class_layout.require_cohort_publication_roots(
                runner, stability, wrong, require_versioned=True
            )
    for wrong in (
        workloads.with_name(f"{layout.workload_root.name}-v0"),
        workloads.with_name(f"{layout.workload_root.name}-v0127"),
        workloads / "child",
    ):
        with pytest.raises(ValueError, match="outside the canonical class-study layout"):
            class_layout.require_canonical_publication_root(
                wrong, field="workload_root"
            )

    root.mkdir()
    layout.config_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    workloads.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic-link component"):
        class_layout.require_canonical_publication_root(
            workloads, field="workload_root"
        )


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
