"""The 20-site final fitting stages share one sealed 20-workload lineage."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import class_attestation, class_cohort20, class_pipeline, class_profile_result, util
from qcsd_lab.class_study import bind_receipt, canonical_json_bytes


@pytest.fixture
def profile_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    profile = class_pipeline.CLASS20_PROFILE
    monkeypatch.setattr(class_pipeline, "load_class20_profile_contract", lambda: profile)
    layout = class_pipeline.class_study_layout(profile=profile)
    layout.study_config_root.mkdir(parents=True)
    (layout.study_config_root / "study.json").write_text("{}\n", encoding="utf-8")
    layout.artifacts_root.mkdir()
    return profile, layout


def _stub_final_inputs(
    monkeypatch: pytest.MonkeyPatch, profile: object, layout: object,
) -> tuple[Path, Path, Path, Path, Path, tuple[str, ...]]:
    cohort = layout.study_config_root / f"{profile.study_id}-cohort.json"
    assembly = layout.study_config_root / f"{profile.study_id}-cohort-assembly.json"
    fit = layout.results_root / "final-fit"
    numeric = layout.authoritative_numeric_root
    workloads = layout.workload_root
    ids = tuple(f"site-{number:02d}" for number in range(20))
    monkeypatch.setattr(
        class_pipeline, "_profile_authoritative_fitting_inputs",
        lambda **kwargs: (ids, fit, numeric, workloads),
    )
    return cohort, assembly, fit, numeric, workloads, ids


def test_final_prefix_route_uses_exact_numeric_source_and_root(
    profile_layout, monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, layout = profile_layout
    cohort, assembly, fit, numeric, workloads, ids = _stub_final_inputs(
        monkeypatch, profile, layout,
    )
    called = []

    def derive(root, **kwargs):
        called.append((root, kwargs))
        return layout.authoritative_prefix_root

    monkeypatch.setattr(class_pipeline, "derive_schema_six_prefix_specs", derive)
    monkeypatch.setattr(
        class_pipeline, "_verify_prefix_spec_root",
        lambda *args, **kwargs: {
            "valid": True, "root": str(layout.authoritative_prefix_root),
            "workloads": len(ids),
        },
    )
    result = class_pipeline.run_class_study_action(
        "prefix-specs", study_id=profile.study_id, stage="authoritative",
        final_cohort_receipt_path=cohort, final_cohort_assembly_path=assembly,
        capture_result=fit, numeric_bundle_root=numeric, workload_root=workloads,
        artifacts_root=layout.artifacts_root,
        prefix_spec_root=layout.authoritative_prefix_root,
    )
    assert result.status == "complete"
    assert called == [(numeric, {
        "source_result_root": fit, "workload_root": workloads,
        "artifacts_root": layout.artifacts_root,
    })]


def test_final_qualification_uses_named_set_and_checked_work_root(
    profile_layout, monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, layout = profile_layout
    cohort, assembly, fit, numeric, workloads, ids = _stub_final_inputs(
        monkeypatch, profile, layout,
    )
    work = class_pipeline._profile_final_qualification_work_root(layout)
    checkpoint = class_pipeline._profile_final_qualification_checkpoint(layout)
    foundation = layout.artifacts_root / "foundation.json"
    monkeypatch.setattr(
        class_attestation, "class_qualification_authority",
        lambda *args, **kwargs: {"approved": True},
    )
    seen = []

    def coordinate(stage, **kwargs):
        seen.append((stage, kwargs))
        return class_pipeline.ClassStudyActionResult(
            "qualify-prefix", "pending", {"pending": len(ids)},
        )

    monkeypatch.setattr(class_pipeline, "_coordinate_qualification", coordinate)
    common = dict(
        study_id=profile.study_id, stage="authoritative",
        final_cohort_receipt_path=cohort, final_cohort_assembly_path=assembly,
        capture_result=fit, numeric_bundle_root=numeric, workload_root=workloads,
        prefix_spec_root=layout.authoritative_prefix_root,
        qualification_checkpoint=checkpoint, qualification_sidecar_root=work,
        qualification_publication_root=layout.qualification_sets_root,
        foundation_attestation=foundation,
    )
    result = class_pipeline.run_class_study_action("qualify-prefix", **common)
    assert result.status == "pending"
    assert len(seen) == 1
    assert seen[0][1]["workload_ids"] == ids
    assert seen[0][1]["qualification_set_name"] == layout.final_qualification_set_root.name
    assert seen[0][1]["sidecar_root"] == work
    assert seen[0][1]["checkpoint_path"] == checkpoint
    with pytest.raises(ValueError, match="work root is not canonical"):
        class_pipeline.run_class_study_action(
            "qualify-prefix", **{**common, "qualification_sidecar_root": layout.artifacts_root / "other"},
        )
    assert len(seen) == 1


def test_final_bundle_uses_published_specs_and_same_sealed_result(
    profile_layout, monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, layout = profile_layout
    cohort, assembly, fit, numeric, workloads, ids = _stub_final_inputs(
        monkeypatch, profile, layout,
    )
    published = layout.final_qualification_set_root
    manifest = published / "_qualification-set.json"
    prefixes = published / "_prefix-specs"
    foundation = layout.artifacts_root / "foundation.json"
    monkeypatch.setattr(
        class_attestation, "class_qualification_authority",
        lambda *args, **kwargs: {"approved": True},
    )
    seen = []

    def finalize(root, **kwargs):
        seen.append((root, kwargs))
        return layout.authoritative_final_root

    monkeypatch.setattr(class_pipeline, "finalize_fitting_bundle", finalize)
    monkeypatch.setattr(
        class_pipeline, "verify_class_fitting_bundle",
        lambda *args, **kwargs: SimpleNamespace(
            stage="authoritative", as_dict=lambda: {"valid": True},
        ),
    )
    result = class_pipeline.run_class_study_action(
        "finalize-fitting", study_id=profile.study_id, stage="authoritative",
        final_cohort_receipt_path=cohort, final_cohort_assembly_path=assembly,
        authoritative_fitting_result=fit, numeric_bundle_root=numeric,
        workload_root=workloads, qualification_sidecar_root=published,
        qualification_manifest=manifest, prefix_spec_root=prefixes,
        artifacts_root=layout.artifacts_root,
        final_bundle_root=layout.authoritative_final_root,
        foundation_attestation=foundation,
    )
    assert result.status == "complete"
    assert len(ids) == 20 and len(seen) == 1
    assert seen[0][0] == numeric
    assert seen[0][1]["source_result_root"] == fit
    assert seen[0][1]["qualification_context"].sidecar_root == published
    assert seen[0][1]["qualification_context"].prefix_spec_root == prefixes


def test_authoritative_fitting_inputs_reject_other_workload_publication(
    profile_layout, monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, layout = profile_layout
    cohort = layout.study_config_root / f"{profile.study_id}-cohort.json"
    assembly = layout.study_config_root / f"{profile.study_id}-cohort-assembly.json"
    cohort.write_bytes(b"{}\n")
    payload = {"workload_root": f"config/{profile.study_id}-workloads-v140"}
    assembly.write_bytes(canonical_json_bytes(bind_receipt(
        payload, receipt_type=class_cohort20.ASSEMBLY_RECEIPT_TYPE,
    )))
    ids = tuple(f"site-{number:02d}" for number in range(20))
    monkeypatch.setattr(
        class_cohort20, "load_validated_profile_cohort",
        lambda *args, **kwargs: (tuple(f"pilot-{number:02d}" for number in range(30)), ids),
    )
    wrong = layout.lab_root / "config/wrong-workloads"
    wrong.mkdir(parents=True)
    with pytest.raises(ValueError, match="differ from the sealed cohort"):
        class_pipeline._profile_authoritative_fitting_inputs(
            profile=profile, final_cohort_receipt=cohort,
            final_cohort_assembly=assembly,
            fitting_result=layout.results_root / "fit",
            numeric_bundle_root=layout.authoritative_numeric_root,
            workload_root=wrong,
        )
