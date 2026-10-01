"""Deep 20-site final-selection receipt and cohort-hook adversarial checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from qcsd_lab import class_final_selection20 as final20
from qcsd_lab import class_pair_screening20 as screen20
from qcsd_lab.class_cohort20 import _deep_final_selection
from qcsd_lab.class_study import CLASS20_PROFILE, bind_receipt, canonical_json_bytes
from qcsd_lab.util import load_json
from tests.test_class_cohort20 import _pilot_receipt
from tests.test_class_pair_screening20 import _fixture as _pair_fixture


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cohort = _pilot_receipt()
    pilot_ids = tuple(cohort["payload"]["pilot_ids"])
    inputs, observed_ids, _pairs, _calls = _pair_fixture(
        tmp_path, monkeypatch, pilot_ids=pilot_ids, cohort=cohort,
    )
    assert observed_ids == pilot_ids
    def deep_pilot(*args, **kwargs):
        assert kwargs["require_deep"] is True
        return pilot_ids, ()
    monkeypatch.setattr(final20, "load_validated_profile_cohort", deep_pilot)
    screening_path = inputs["pilot_cohort_path"].with_name(
        f"{CLASS20_PROFILE.study_id}-pair-screening.json"
    )
    screening_path.write_bytes(canonical_json_bytes(
        screen20.build_pair_screening_receipt(**inputs)
    ))
    destination = screening_path.with_name(
        f"{CLASS20_PROFILE.study_id}-final-selection.json"
    )
    selection_inputs = {
        "pair_screening_path": screening_path,
        "pilot_cohort_path": inputs["pilot_cohort_path"],
        "pilot_assembly_path": inputs["pilot_assembly_path"],
    }
    return inputs, selection_inputs, destination


def test_final_receipt_replays_pairs_and_cohort_hook(tmp_path, monkeypatch):
    _screen_inputs, inputs, destination = _fixture(tmp_path, monkeypatch)
    path = final20.publish_profile_final_selection_receipt(destination, **inputs)
    receipt = load_json(path)
    payload = receipt["payload"]
    assert payload["selection_policy"] == final20.SELECTION_POLICY
    assert payload["qualified_pair_count"] == 15
    assert len(payload["planned_pairs"]) == 15
    assert len(payload["matching"]) == 10
    assert len(payload["final_ids"]) == 20
    assert len(payload["reserve_ids"]) == 10
    selected = final20.validate_profile_final_selection_receipt(
        path, pilot_cohort_path=inputs["pilot_cohort_path"],
        pilot_assembly_path=inputs["pilot_assembly_path"],
    )
    assert [item.candidate_id for item in selected.final] == payload["final_ids"]
    assert _deep_final_selection(
        path, pilot_cohort_path=inputs["pilot_cohort_path"],
        pilot_assembly_path=inputs["pilot_assembly_path"], profile=CLASS20_PROFILE,
    ) == selected
    with pytest.raises(FileExistsError, match="create-only"):
        final20.publish_profile_final_selection_receipt(destination, **inputs)


def test_final_receipt_rejects_hash_valid_rewritten_choice(tmp_path, monkeypatch):
    _screen_inputs, inputs, destination = _fixture(tmp_path, monkeypatch)
    final20.publish_profile_final_selection_receipt(destination, **inputs)
    receipt = load_json(destination)
    payload = dict(receipt["payload"])
    payload["final_ids"] = list(reversed(payload["final_ids"]))
    destination.write_bytes(canonical_json_bytes(
        bind_receipt(payload, receipt_type=final20.RECEIPT_TYPE)
    ))
    with pytest.raises(ValueError, match="differs from replayed pair evidence"):
        final20.validate_profile_final_selection_receipt(
            destination, pilot_cohort_path=inputs["pilot_cohort_path"],
            pilot_assembly_path=inputs["pilot_assembly_path"],
        )


def test_final_receipt_rejects_missing_sidecar_after_publication(tmp_path, monkeypatch):
    screen_inputs, inputs, destination = _fixture(tmp_path, monkeypatch)
    final20.publish_profile_final_selection_receipt(destination, **inputs)
    first = load_json(inputs["pair_screening_path"])["payload"]["pilot_ids"][0]
    (screen_inputs["sidecar_root"] / f"{first}.json").unlink()
    with pytest.raises(ValueError, match="evidence file is missing"):
        final20.validate_profile_final_selection_receipt(
            destination, pilot_cohort_path=inputs["pilot_cohort_path"],
            pilot_assembly_path=inputs["pilot_assembly_path"],
        )


def test_final_receipt_rejects_forged_screening_outcome(tmp_path, monkeypatch):
    _screen_inputs, inputs, destination = _fixture(tmp_path, monkeypatch)
    receipt = load_json(inputs["pair_screening_path"])
    payload = dict(receipt["payload"])
    rows = [dict(row) for row in payload["pair_outcomes"]]
    rows[0]["qualified"] = False
    rows[0]["failure_reason"] = "invented"
    payload["pair_outcomes"] = rows
    inputs["pair_screening_path"].write_bytes(canonical_json_bytes(
        bind_receipt(payload, receipt_type=screen20.RECEIPT_TYPE)
    ))
    with pytest.raises(ValueError, match="differs from replayed evidence"):
        final20.publish_profile_final_selection_receipt(destination, **inputs)
    assert not destination.exists()


def test_final_receipt_rejects_noncanonical_screening_path(tmp_path, monkeypatch):
    _screen_inputs, inputs, destination = _fixture(tmp_path, monkeypatch)
    other = destination.with_name("other-screen.json")
    other.write_bytes(inputs["pair_screening_path"].read_bytes())
    with pytest.raises(ValueError, match="wrong canonical filename"):
        final20.publish_profile_final_selection_receipt(
            destination, **{**inputs, "pair_screening_path": other}
        )
    assert not destination.exists()


def test_final_choice_stops_when_only_nine_pairs_qualify(tmp_path, monkeypatch):
    screen_inputs, inputs, destination = _fixture(tmp_path, monkeypatch)
    pilot_ids = load_json(inputs["pair_screening_path"])["payload"]["pilot_ids"]
    failed = set(pilot_ids[::2][:6])
    for workload_id in failed:
        (screen_inputs["prefix_spec_root"] / f"{workload_id}.json").unlink()
        (screen_inputs["sidecar_root"] / f"{workload_id}.json").unlink()
    original = screen20.build_schema_six_prefix_spec
    def capacity(workload_id, *args, **kwargs):
        if workload_id in failed:
            raise ValueError("receiver continuation horizon exceeds qualification stream ceiling")
        return original(workload_id, *args, **kwargs)
    monkeypatch.setattr(screen20, "build_schema_six_prefix_spec", capacity)
    inputs["pair_screening_path"].write_bytes(canonical_json_bytes(
        screen20.build_pair_screening_receipt(**screen_inputs)
    ))
    with pytest.raises(ValueError, match="only 9 qualified pilot pairs"):
        final20.publish_profile_final_selection_receipt(destination, **inputs)
    assert not destination.exists()
