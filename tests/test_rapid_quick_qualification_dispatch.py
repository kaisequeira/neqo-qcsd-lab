"""Quick profiles must reach the existing qualification validator before launch."""
import hashlib
import json

import pytest

from qcsd_lab import rapid_quick_profile as quick
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import rapid_runtime_epochs as epochs


@pytest.mark.parametrize("kind", [quick.CAPSULE_TYPE, quick.MODE_CAPSULE_TYPE, schedule.CAPSULE_TYPE])
def test_qualified_profile_dispatches_to_full_schedule_validator(tmp_path, monkeypatch, kind):
    path = tmp_path / "profile.json"
    raw = json.dumps({"artifact_type": kind}).encode()
    path.write_bytes(raw)
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, str(path))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)
    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", raising=False)
    old, current, calls = {"old": True}, {"current": True}, []
    monkeypatch.setattr(schedule, "validate_qualification_reuse",
                        lambda *args, **kwargs: calls.append((args, kwargs)))
    token = epochs._CURRENT_BRIDGE.set(None)
    try:
        epochs.validate_qualification_reuse(old, current)
    finally:
        epochs._CURRENT_BRIDGE.reset(token)
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == (old, current, {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()})
    assert kwargs["actual_image"] == "sha256:" + "a" * 64


@pytest.mark.parametrize("kind", [quick.CAPSULE_TYPE, quick.MODE_CAPSULE_TYPE])
@pytest.mark.parametrize("authority", ["installation", "ambient_bridge"])
def test_quick_profile_cannot_claim_historical_repair_authority(tmp_path, monkeypatch, kind, authority):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"artifact_type": kind}))
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, str(path))
    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", raising=False)
    if authority == "installation":
        monkeypatch.setenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", "unrelated-installation")
    def unexpected(*args, **kwargs):
        pytest.fail("a quick profile borrowed historical repair authority")
    monkeypatch.setattr(schedule, "validate_qualification_reuse", unexpected)
    token = epochs._CURRENT_BRIDGE.set({"unrelated": True} if authority == "ambient_bridge" else None)
    try:
        with pytest.raises(ValueError, match="historical installation or runtime repair"):
            epochs.validate_qualification_reuse({}, {})
    finally:
        epochs._CURRENT_BRIDGE.reset(token)


def test_unregistered_profile_cannot_borrow_quick_qualification_dispatch(tmp_path, monkeypatch):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"artifact_type": quick.MODE_CAPSULE_TYPE + "-unregistered"}))
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, str(path))
    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", raising=False)
    def unexpected(*args, **kwargs):
        pytest.fail("unregistered profile entered the quick validator")
    monkeypatch.setattr(schedule, "validate_qualification_reuse", unexpected)
    token = epochs._CURRENT_BRIDGE.set(None)
    try:
        with pytest.raises(ValueError, match="invalid qcsd-rapid-v5-collection-runtime-launch-capsule"):
            epochs.validate_qualification_reuse({}, {})
    finally:
        epochs._CURRENT_BRIDGE.reset(token)
