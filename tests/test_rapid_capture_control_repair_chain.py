"""Qualification reuse composes two real, independently derived source bridges.

The installation fixture retains actual closed image-check envelopes and source
projections. The runtime capsule here provides the hook's already-validated
caller context; actual activation and lane lifecycle are exercised separately
by test_rapid_runtime_parallel. These tests grant no capture authority or credit.
"""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_capture_control_installation as installation
from qcsd_lab import rapid_runtime_compatibility as historical
from qcsd_lab import rapid_runtime_epochs as epochs
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_capture_control_compatibility import sources
from tests.test_rapid_capture_control_installation import installed, publish
from tests.test_rapid_lane_evidence import setup
from tests.test_rapid_runtime_compatibility import review


@pytest.fixture
def chain(installed, monkeypatch):
    publish(installed)
    payload, _ = installation.validate_capsule(installed.capsule)
    old_control = payload["new_runtime_check"]["proof"]["runtime_proof"]
    repaired_sources = dict(installed.new)
    path = "src/qcsd_lab/capture_session.py"
    needle = b'raise RuntimeError("dumpcap exited before capture start")'
    assert needle in repaired_sources[path]
    repaired_sources[path] = repaired_sources[path].replace(
        needle, b'raise RuntimeError("dumpcap exited while awaiting observer readiness")', 1)
    repaired = copy.deepcopy(old_control)
    repaired["collection_image_digest"] = "sha256:" + "8" * 64
    repaired["runtime_source"]["image_digest"] = repaired["collection_image_digest"]
    repaired["runtime_source"]["lab_commit"] = "7" * 40
    implementation = repaired["qualification_implementation"]
    implementation["source"]["lab_commit"] = "7" * 40
    implementation["source_files"][path] = admission._sha(repaired_sources[path])
    implementation["installed_modules"][path]["sha256"] = admission._sha(repaired_sources[path])
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    repaired["source_manifest_sha256"] = admission._sha(admission._json(implementation["source"]))
    bridge = historical.validate_compatibility(old_control, repaired, installed.new, repaired_sources,
        review(installed.new, repaired_sources, {path: ["_wait_for_capture_start"]}))
    capsule = installed.current.execution_root / "config/rapid-runtime-epochs/repair-hook.json"
    capsule.parent.mkdir(parents=True, exist_ok=True)
    runtime_spec = replace(installed.current, collection_image_digest=repaired["collection_image_digest"],
                           execution_generation="repair-hook-001")
    context = {"base_spec": installed.current.serializable(), "runtime_spec": runtime_spec.serializable(),
               "evidence_root": str(installed.root), "intent": str(installed.root / "fixture-intent.json"),
               "intent_sha256": "0" * 64, "scientific_credit": False}
    capsule.write_bytes(admission._json(admission._bind(epochs.CAPSULE_TYPE, context)))
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, str(capsule))
    monkeypatch.setenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", str(installed.capsule))
    token = epochs._CURRENT_BRIDGE.set(bridge)
    try:
        yield installed, payload, old_control, repaired, bridge, capsule, context
    finally:
        epochs._CURRENT_BRIDGE.reset(token)


def test_original_qualifier_reuses_control_then_repair_without_relabeling(chain, monkeypatch):
    _, payload, control, repaired, _, _, _ = chain
    original = payload["old_image_check"]["proof"]["qualification_implementation"]
    unchanged = copy.deepcopy(original)
    epochs.validate_qualification_reuse(original, repaired["qualification_implementation"])
    assert original == unchanged
    assert original["source"] != control["qualification_implementation"]["source"]
    assert control["qualification_implementation"]["sha256"] != repaired["qualification_implementation"]["sha256"]
    # Direct historical v1 reuse keeps its previous behavior and does not read
    # an unrelated secondary reference when its own old receipt already matches.
    monkeypatch.setenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", "/unused/invalid.json")
    epochs.validate_qualification_reuse(control["qualification_implementation"], repaired["qualification_implementation"])


def test_repair_chain_rejects_missing_or_changed_intermediate_authority(chain, monkeypatch):
    state, payload, _, repaired, bridge, capsule, context = chain
    original = payload["old_image_check"]["proof"]["qualification_implementation"]
    current = repaired["qualification_implementation"]
    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION")
    with pytest.raises(ValueError, match="original capture-control installation"):
        epochs.validate_qualification_reuse(original, current)
    monkeypatch.setenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", str(state.capsule))
    wrong = copy.deepcopy(context)
    wrong["evidence_root"] = str(state.root / "other-root")
    capsule.write_bytes(admission._json(admission._bind(epochs.CAPSULE_TYPE, wrong)))
    with pytest.raises(ValueError, match="intermediate installation"):
        epochs.validate_qualification_reuse(original, current)
    capsule.write_bytes(admission._json(admission._bind(epochs.CAPSULE_TYPE, context)))
    forged = copy.deepcopy(bridge)
    forged["old_implementation_sha256"] = "0" * 64
    forged["sha256"] = historical._sha(historical.DOMAIN.encode() + b"\0" + historical._json(
        {key: value for key, value in forged.items() if key != "sha256"}))
    token = epochs._CURRENT_BRIDGE.set(forged)
    try:
        with pytest.raises(ValueError, match="intermediate installation"):
            epochs.validate_qualification_reuse(original, current)
    finally:
        epochs._CURRENT_BRIDGE.reset(token)
    changed_current = copy.deepcopy(current)
    changed_current["neqo_qcsd_client"]["sha256"] = "0" * 64
    changed_current["sha256"] = qualification._implementation_aggregate(changed_current)
    with pytest.raises(ValueError, match="receipt or executable"):
        epochs.validate_qualification_reuse(original, changed_current)
