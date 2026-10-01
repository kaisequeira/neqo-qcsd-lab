"""Fail-closed pair-screening behavior at the deep-evidence boundary."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import class_pair_screening20 as screen
from qcsd_lab.class_layout import class_study_layout
from qcsd_lab.class_study import (
    CLASS20_PROFILE,
    bind_receipt,
    canonical_json_sha256,
    canonical_json_bytes,
)
from qcsd_lab import util
from qcsd_lab.util import sha256_file


def _fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    *, pilot_ids: tuple[str, ...] | None = None,
    cohort: dict | None = None,
):
    lab = tmp_path / "lab"
    lab.mkdir()
    monkeypatch.setattr(util, "LAB_ROOT", lab)
    layout = class_study_layout(profile=CLASS20_PROFILE)
    layout.study_config_root.mkdir(parents=True)
    overlay = Path(screen.__file__).resolve().parents[2] / "config/class-study/v2/study.json"
    (layout.study_config_root / "study.json").write_bytes(overlay.read_bytes())
    pilot_ids = pilot_ids or tuple(f"site-{index:02d}" for index in range(30))
    pairs = tuple((pilot_ids[index], pilot_ids[index + 1]) for index in range(0, 30, 2))
    cohort = cohort or {"pilot": list(pilot_ids)}
    assembly = bind_receipt(
        {"workload_root": "config/classifier-multiorigin20-v1-workloads-v1"},
        receipt_type="qcsd-class-study-profile-cohort-assembly",
    )
    cohort_path = layout.study_config_root / f"{CLASS20_PROFILE.study_id}-pilot-cohort.json"
    assembly_path = layout.study_config_root / f"{CLASS20_PROFILE.study_id}-pilot-cohort-assembly.json"
    cohort_path.write_bytes(canonical_json_bytes(cohort))
    assembly_path.write_bytes(canonical_json_bytes(assembly))
    workloads = lab / assembly["payload"]["workload_root"]
    workloads.mkdir(parents=True)
    layout.pilot_numeric_root.mkdir(parents=True)
    layout.pilot_prefix_root.mkdir(parents=True)
    layout.pilot_qualification_set_root.mkdir(parents=True)
    fitting = lab / "results/fitting"
    fitting.mkdir(parents=True)
    foundation = lab / "artifacts/foundation.json"
    foundation.write_bytes(canonical_json_bytes(bind_receipt(
        {
            "study_id": CLASS20_PROFILE.study_id,
            "study_profile_sha256": sha256_file(layout.study_config_root / "study.json"),
        },
        receipt_type=screen.FOUNDATION_RECEIPT_TYPE,
    )))
    walkie = {"profiles": [{"real": a, "decoy": b} for a, b in pairs]}
    walkie_path = layout.pilot_numeric_root / "walkie-talkie.json"
    walkie_path.write_bytes(canonical_json_bytes(walkie))
    (layout.pilot_numeric_root / "numeric-provenance.json").write_text("{}")
    for workload_id in pilot_ids:
        (workloads / f"{workload_id}.json").write_bytes(
            canonical_json_bytes({"workload_id": workload_id})
        )
        (layout.pilot_prefix_root / f"{workload_id}.json").write_bytes(
            canonical_json_bytes({"schema_version": 4, "workload_id": workload_id})
        )
        (layout.pilot_qualification_set_root / f"{workload_id}.json").write_text("{}")
    provenance = {
        "study_id": CLASS20_PROFILE.study_id,
        "study_profile_sha256": sha256_file(layout.study_config_root / "study.json"),
        "fitting_contract": {"workload_order": list(pilot_ids)},
        "cohort": {
            "receipt": cohort,
            "assembly_receipt": assembly,
            "receipt_sha256": canonical_json_sha256(cohort),
            "assembly_receipt_sha256": canonical_json_sha256(assembly),
        },
        "source_result": {"source_fingerprints": {"lab_commit": "a", "image_digest": "sha256:fit"}},
    }
    def deep_cohort(*args, **kwargs):
        assert kwargs["require_deep"] is True
        return pilot_ids, ()
    def deep_numeric(*args, **kwargs):
        assert kwargs["source_result_root"] == fitting
        return SimpleNamespace(stage="pilot", provenance=provenance)
    def full_foundation(*args, **kwargs):
        assert kwargs["deep_code_gate"] is True
        assert kwargs["runtime_role"] is None
        return {"collection_source": {"lab_commit": "a", "image_digest": "sha256:fit"}}
    monkeypatch.setattr(screen, "load_validated_profile_cohort", deep_cohort)
    monkeypatch.setattr(screen, "verify_numeric_fitting_bundle", deep_numeric)
    monkeypatch.setattr(screen, "class_qualification_authority", full_foundation)
    monkeypatch.setattr(screen, "validate_class_study_preparation", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        screen, "build_schema_six_prefix_spec",
        lambda workload_id, *args, **kwargs: {"schema_version": 4, "workload_id": workload_id},
    )
    monkeypatch.setattr(
        screen, "validate_schema_six_prefix_spec",
        lambda value, **kwargs: value,
    )
    sidecar_calls = []

    def qualified(sidecar_path, **kwargs):
        sidecar_calls.append((sidecar_path, kwargs))
        return SimpleNamespace(manifest_sha256="f" * 64)

    monkeypatch.setattr(screen, "load_qualified_chaff", qualified)
    arguments = {
        "pilot_cohort_path": cohort_path,
        "pilot_assembly_path": assembly_path,
        "numeric_bundle_root": layout.pilot_numeric_root,
        "fitting_result_root": fitting,
        "workload_root": workloads,
        "prefix_spec_root": layout.pilot_prefix_root,
        "sidecar_root": layout.pilot_qualification_set_root,
        "foundation_attestation_path": foundation,
    }
    return arguments, pilot_ids, pairs, sidecar_calls


def test_exact_pilot_pairs_require_two_endpoint_qualifications(tmp_path, monkeypatch):
    arguments, pilot_ids, pairs, calls = _fixture(tmp_path, monkeypatch)
    receipt = screen.build_pair_screening_receipt(**arguments)
    payload = receipt["payload"]
    assert payload["pilot_ids"] == list(pilot_ids)
    assert payload["planned_pairs"] == [list(pair) for pair in pairs]
    assert payload["qualified_pair_count"] == 15
    assert len(calls) == 30
    assert all(row["qualified"] is True for row in payload["pair_outcomes"])
    assert all(
        kwargs["expected_qualification_authority"]["collection_source"]["lab_commit"] == "a"
        and kwargs["expected_sidecar_schema_version"] == 3
        for _, kwargs in calls
    )
    assert screen.validate_pair_screening_receipt(receipt, **arguments) == receipt


def test_absent_sidecar_is_pending_and_cannot_be_published(tmp_path, monkeypatch):
    arguments, pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    (arguments["sidecar_root"] / f"{pilot_ids[0]}.json").unlink()
    with pytest.raises(ValueError, match="evidence file is missing"):
        screen.build_pair_screening_receipt(**arguments)
    destination = arguments["pilot_cohort_path"].with_name(
        f"{CLASS20_PROFILE.study_id}-pair-screening.json"
    )
    with pytest.raises(ValueError, match="evidence file is missing"):
        screen.publish_pair_screening_receipt(destination, **arguments)
    assert not destination.exists()


def test_only_replayed_capacity_failure_can_make_negative_pair(tmp_path, monkeypatch):
    arguments, pilot_ids, _pairs, calls = _fixture(tmp_path, monkeypatch)
    failed = pilot_ids[0]
    (arguments["sidecar_root"] / f"{failed}.json").unlink()
    (arguments["prefix_spec_root"] / f"{failed}.json").unlink()
    original = screen.build_schema_six_prefix_spec

    def capacity(workload_id, *args, **kwargs):
        if workload_id == failed:
            raise ValueError("receiver continuation horizon exceeds qualification stream ceiling")
        return original(workload_id, *args, **kwargs)

    monkeypatch.setattr(screen, "build_schema_six_prefix_spec", capacity)
    receipt = screen.build_pair_screening_receipt(**arguments)
    first = receipt["payload"]["pair_outcomes"][0]
    assert first["qualified"] is False
    assert first["failure_reason"] == "deterministic-wt6-prefix-capacity"
    assert first["endpoints"][0]["capacity_derivation"] == (
        "receiver continuation horizon exceeds qualification stream ceiling"
    )
    assert receipt["payload"]["qualified_pair_count"] == 14
    assert len(calls) == 28


def test_ordinary_error_cannot_be_relabeled_as_capacity_failure(tmp_path, monkeypatch):
    arguments, _pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    def failed_command(*args, **kwargs):
        raise ValueError("qualification command failed")
    monkeypatch.setattr(screen, "build_schema_six_prefix_spec", failed_command)
    with pytest.raises(ValueError, match="qualification command failed"):
        screen.build_pair_screening_receipt(**arguments)


def test_hash_valid_forged_outcome_does_not_survive_replay(tmp_path, monkeypatch):
    arguments, _pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    receipt = screen.build_pair_screening_receipt(**arguments)
    payload = dict(receipt["payload"])
    rows = [dict(row) for row in payload["pair_outcomes"]]
    rows[0]["qualified"] = False
    rows[0]["failure_reason"] = "fabricated"
    payload["pair_outcomes"] = rows
    forged = bind_receipt(payload, receipt_type=screen.RECEIPT_TYPE)
    with pytest.raises(ValueError, match="differs from replayed evidence"):
        screen.validate_pair_screening_receipt(forged, **arguments)


def test_different_foundation_source_cannot_screen_numeric_fit(tmp_path, monkeypatch):
    arguments, _pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        screen, "class_qualification_authority",
        lambda *args, **kwargs: {
            "collection_source": {"lab_commit": "different", "image_digest": "sha256:fit"}
        },
    )
    with pytest.raises(ValueError, match="different source or image"):
        screen.build_pair_screening_receipt(**arguments)


def test_source_pinned_profile_cannot_be_replaced(tmp_path, monkeypatch):
    arguments, _pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    overlay = arguments["pilot_cohort_path"].parent / "study.json"
    overlay.write_text("{}")
    with pytest.raises(ValueError, match="source-pinned overlay"):
        screen.build_pair_screening_receipt(**arguments)


def test_capacity_claim_conflicting_with_published_endpoint_is_rejected(tmp_path, monkeypatch):
    arguments, pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    failed = pilot_ids[0]
    def capacity(workload_id, *args, **kwargs):
        if workload_id == failed:
            raise ValueError("receiver continuation horizon exceeds qualification stream ceiling")
        return {"schema_version": 4, "workload_id": workload_id}
    monkeypatch.setattr(screen, "build_schema_six_prefix_spec", capacity)
    with pytest.raises(ValueError, match="contradictory qualification files"):
        screen.build_pair_screening_receipt(**arguments)


def test_prefix_publisher_continues_after_replayed_capacity_failure(tmp_path, monkeypatch):
    arguments, pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    for path in arguments["prefix_spec_root"].iterdir():
        path.unlink()
    failed = pilot_ids[0]
    original = screen.build_schema_six_prefix_spec
    def capacity(workload_id, *args, **kwargs):
        if workload_id == failed:
            raise ValueError("receiver continuation horizon exceeds qualification stream ceiling")
        return original(workload_id, *args, **kwargs)
    monkeypatch.setattr(screen, "build_schema_six_prefix_spec", capacity)
    inputs = {key: value for key, value in arguments.items() if key not in {
        "sidecar_root", "foundation_attestation_path",
    }}
    first = screen.publish_feasible_pilot_prefix_specs(**inputs)
    assert len(first.published_paths) == 29
    assert first.capacity_failures[0].workload_id == failed
    assert first.capacity_failures[0].workload_sha256 == sha256_file(
        arguments["workload_root"] / f"{failed}.json"
    )
    assert not (arguments["prefix_spec_root"] / f"{failed}.json").exists()
    before = {path.name: path.stat().st_ino for path in first.published_paths}
    second = screen.publish_feasible_pilot_prefix_specs(**inputs)
    assert second == first
    assert {path.name: path.stat().st_ino for path in second.published_paths} == before
    (arguments["sidecar_root"] / f"{failed}.json").unlink()
    receipt = screen.build_pair_screening_receipt(**arguments)
    assert receipt["payload"]["qualified_pair_count"] == 14


def test_prefix_publisher_rejects_tampered_existing_spec_before_new_files(tmp_path, monkeypatch):
    arguments, pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    for path in arguments["prefix_spec_root"].iterdir():
        path.unlink()
    corrupted = arguments["prefix_spec_root"] / f"{pilot_ids[0]}.json"
    corrupted.write_bytes(canonical_json_bytes({"schema_version": 4, "workload_id": "wrong"}))
    inputs = {key: value for key, value in arguments.items() if key not in {
        "sidecar_root", "foundation_attestation_path",
    }}
    with pytest.raises(ValueError, match="differs from verified numeric derivation"):
        screen.publish_feasible_pilot_prefix_specs(**inputs)
    assert [item.name for item in arguments["prefix_spec_root"].iterdir()] == [corrupted.name]


def test_prefix_publisher_keeps_noncapacity_error_pending(tmp_path, monkeypatch):
    arguments, _pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    for path in arguments["prefix_spec_root"].iterdir():
        path.unlink()
    def unexpected(*args, **kwargs):
        raise ValueError("transport or command failure")
    monkeypatch.setattr(screen, "build_schema_six_prefix_spec", unexpected)
    inputs = {key: value for key, value in arguments.items() if key not in {
        "sidecar_root", "foundation_attestation_path",
    }}
    with pytest.raises(ValueError, match="transport or command failure"):
        screen.publish_feasible_pilot_prefix_specs(**inputs)
    assert list(arguments["prefix_spec_root"].iterdir()) == []


def test_prefix_verifier_replays_existing_specs_without_writes(tmp_path, monkeypatch):
    arguments, pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    inputs = {key: value for key, value in arguments.items() if key not in {
        "sidecar_root", "foundation_attestation_path",
    }}
    original = {
        path.name: (path.stat().st_ino, path.read_bytes())
        for path in arguments["prefix_spec_root"].iterdir()
    }
    result = screen.verify_feasible_pilot_prefix_specs(**inputs)
    assert len(result.published_paths) == len(pilot_ids)
    assert result.capacity_failures == ()
    assert {
        path.name: (path.stat().st_ino, path.read_bytes())
        for path in arguments["prefix_spec_root"].iterdir()
    } == original

    missing = arguments["prefix_spec_root"] / f"{pilot_ids[0]}.json"
    missing.unlink()
    with pytest.raises(ValueError, match="evidence file is missing"):
        screen.verify_feasible_pilot_prefix_specs(**inputs)
    assert not missing.exists()

    missing.write_bytes(canonical_json_bytes({"schema_version": 4, "workload_id": "wrong"}))
    with pytest.raises(ValueError, match="differs from verified numeric derivation"):
        screen.verify_feasible_pilot_prefix_specs(**inputs)


def test_prefix_verifier_preserves_capacity_negative_and_rejects_contradiction(
    tmp_path, monkeypatch,
):
    arguments, pilot_ids, _pairs, _calls = _fixture(tmp_path, monkeypatch)
    failed = pilot_ids[0]
    failed_spec = arguments["prefix_spec_root"] / f"{failed}.json"
    failed_spec.unlink()
    original = screen.build_schema_six_prefix_spec

    def capacity(workload_id, *args, **kwargs):
        if workload_id == failed:
            raise ValueError("receiver continuation horizon exceeds qualification stream ceiling")
        return original(workload_id, *args, **kwargs)

    monkeypatch.setattr(screen, "build_schema_six_prefix_spec", capacity)
    inputs = {key: value for key, value in arguments.items() if key not in {
        "sidecar_root", "foundation_attestation_path",
    }}
    before = {path.name: path.read_bytes() for path in arguments["prefix_spec_root"].iterdir()}
    result = screen.verify_feasible_pilot_prefix_specs(**inputs)
    assert len(result.published_paths) == 29
    assert len(result.capacity_failures) == 1
    assert result.capacity_failures[0].workload_id == failed
    assert result.capacity_failures[0].workload_sha256 == sha256_file(
        arguments["workload_root"] / f"{failed}.json"
    )
    assert {path.name: path.read_bytes() for path in arguments["prefix_spec_root"].iterdir()} == before

    failed_spec.write_bytes(canonical_json_bytes({"schema_version": 4, "workload_id": failed}))
    with pytest.raises(ValueError, match="contradictory prefix spec"):
        screen.verify_feasible_pilot_prefix_specs(**inputs)
