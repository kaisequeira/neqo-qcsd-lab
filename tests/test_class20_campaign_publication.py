"""Pilot and final profile campaigns share one create-only directory."""

from pathlib import Path

import pytest

from qcsd_lab import class_cohort20, class_pipeline, util


def test_final_campaigns_replay_existing_pilot_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    profile = class_pipeline.CLASS20_PROFILE
    layout = class_pipeline.class_study_layout(profile=profile)
    layout.study_config_root.mkdir(parents=True)
    layout.campaign_root.mkdir(parents=True)
    pilot = layout.study_config_root / f"{profile.study_id}-pilot-cohort.json"
    pilot_assembly = layout.study_config_root / f"{profile.study_id}-pilot-cohort-assembly.json"
    final = layout.study_config_root / f"{profile.study_id}-cohort.json"
    final_assembly = layout.study_config_root / f"{profile.study_id}-cohort-assembly.json"
    for path in (pilot, pilot_assembly, final, final_assembly):
        path.write_text("{}\n", encoding="utf-8")

    pilot_ids = tuple(f"site-{index:02d}" for index in range(30))
    final_ids = pilot_ids[:20]

    def validated_cohort(
        cohort_path: Path, assembly_path: Path, *, profile: object, require_deep: bool,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        assert require_deep
        assert assembly_path in {pilot_assembly, final_assembly}
        return pilot_ids, (() if cohort_path == pilot else final_ids)

    monkeypatch.setattr(class_cohort20, "load_validated_profile_cohort", validated_cohort)
    pilot_args = dict(
        study_id=profile.study_id, stage="pilot", pilot_cohort_receipt_path=pilot,
        pilot_cohort_assembly_path=pilot_assembly, campaign_root=layout.campaign_root,
    )
    final_args = dict(
        study_id=profile.study_id, stage="authoritative", final_cohort_receipt_path=final,
        final_cohort_assembly_path=final_assembly, campaign_root=layout.campaign_root,
    )
    assert class_pipeline.run_class_study_action("campaigns", **pilot_args).status == "complete"
    pilot_files = tuple(layout.campaign_root.iterdir())
    assert len(pilot_files) == 1
    saved_pilot = pilot_files[0].read_bytes()

    pilot_files[0].write_bytes(saved_pilot + b"# changed\n")
    with pytest.raises(ValueError, match="existing campaign differs"):
        class_pipeline.run_class_study_action("campaigns", **final_args)
    assert tuple(layout.campaign_root.iterdir()) == pilot_files

    pilot_files[0].write_bytes(saved_pilot)
    assert class_pipeline.run_class_study_action("campaigns", **final_args).status == "complete"
    assert len(tuple(layout.campaign_root.iterdir())) == 23
    assert class_pipeline.run_class_study_action("campaigns", **pilot_args).status == "complete"
