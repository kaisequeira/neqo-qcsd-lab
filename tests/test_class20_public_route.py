"""The v2 coordinator reaches public stages without the v1 result index."""

from pathlib import Path

import pytest

from qcsd_lab import class_pipeline, class_public20


@pytest.mark.parametrize("action", (
    "export", "evaluate", "comparison-review", "attest", "verify",
))
def test_profile_public_action_uses_v2_coordinator(
    action: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        class_pipeline, "load_class20_profile_contract",
        lambda: class_pipeline.CLASS20_PROFILE,
    )
    received = []

    def public_stage(selected: str, **kwargs):
        received.append((selected, kwargs))
        return {
            "action": selected, "state": "complete",
            "details": {"valid": True, "profile": "20-site"}, "messages": (),
        }

    monkeypatch.setattr(class_public20, "run_profile_public_stage", public_stage)
    monkeypatch.setattr(
        class_pipeline, "_result_index",
        lambda *args, **kwargs: pytest.fail("v1 result index reached"),
    )
    result = class_pipeline.run_class_study_action(
        action, study_id=class_pipeline.CLASS20_STUDY_ID,
        destination=tmp_path / "output", final_cohort_receipt_path=tmp_path / "cohort.json",
        final_cohort_assembly_path=tmp_path / "assembly.json",
        canary_result_roots=(tmp_path / "canary",),
        formal_result_roots=(tmp_path / "formal",),
        handoff=tmp_path / "handoff", target=tmp_path / "target.json",
    )
    assert result.status == "complete"
    assert result.details == {"valid": True, "profile": "20-site"}
    assert received[0][0] == action
    assert received[0][1]["formal_result_roots"] == (tmp_path / "formal",)
    assert received[0][1]["final_cohort_receipt"] == tmp_path / "cohort.json"
