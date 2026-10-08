"""Exact Source70 complete-audit compatibility; no progress or raw-proof promotion."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_rapid_quick_front_reader_compatibility import _original_fixed
from tests.test_v13_closed_host_reader_compatibility import restore_front_target


SOURCE70 = "f661fbfb19641d6aa19586d2a587475878d080734f33602a0a02df461615ac53"
SOURCE71 = "529e4b7506b8889c01b3399e932502892cdfc634f39eb1c514b01259e0b7cf7c"
PROGRESS328 = "d1f5256a5db3ba4f364c8941942731efee27505b7ad6393c497e16ce82d5c18a"


@pytest.fixture
def complete_audit_target(tmp_path):
    # Two independent literal test inverses reconstruct the entire authentic
    # Source71 and Source70 files. Neither invokes a production projection.
    current = Path(fixed.__file__).read_bytes()
    source71 = _original_fixed(current)
    assert hashlib.sha256(source71).hexdigest() == SOURCE71
    source70 = restore_front_target(source71)
    assert hashlib.sha256(source70).hexdigest() == SOURCE70
    path = tmp_path / "source70" / "rapid_fixed_condition_target.py"
    path.parent.mkdir()
    path.write_bytes(source70)
    path.chmod(0o644)
    return path


def test_exact_complete_audit_target_reaches_enhanced_reader_and_same_science(complete_audit_target):
    before, current = fixed.reference(complete_audit_target), fixed.reference(Path(fixed.__file__))
    assert fixed._compatible_code_ref("target", before, current)
    source = fixed._sources()
    source["target"] = before
    assert fixed._compatible_sources(source)


@pytest.mark.parametrize("mutation", ["bytes", "mode600", "mode4644", "claimed-mode"])
def test_registered_complete_audit_predecessor_refuses_unknown_bytes_or_full_mode(
        complete_audit_target, mutation):
    before, current = fixed.reference(complete_audit_target), fixed.reference(Path(fixed.__file__))
    assert fixed._compatible_code_ref("target", before, current)
    if mutation == "bytes":
        complete_audit_target.write_bytes(complete_audit_target.read_bytes() + b"\ndef added_admission(): return True\n")
    elif mutation == "mode600":
        complete_audit_target.chmod(0o600)
    elif mutation == "mode4644":
        complete_audit_target.chmod(0o4644)
    before = fixed.reference(complete_audit_target)
    if mutation == "claimed-mode":
        before["mode"] = True
    with pytest.raises(ValueError):
        fixed._compatible_code_ref("target", before, current)


@pytest.mark.parametrize("mutation", ["additional-science", "condition", "class-count"])
def test_registered_complete_audit_never_masks_changed_current_science(
        complete_audit_target, tmp_path, mutation):
    before, current = fixed.reference(complete_audit_target), fixed.reference(Path(fixed.__file__))
    assert fixed._compatible_code_ref("target", before, current)
    raw = Path(fixed.__file__).read_bytes()
    if mutation == "additional-science":
        raw += b"\ndef unregistered_admission_science(): return True\n"
    elif mutation == "condition":
        needle = b"'request_policy':'as-defined'"
        assert needle in raw
        # Alter the real scientific function as well as literal snapshots:
        # no production inverse may discard this condition change.
        raw = raw.replace(needle, b"'request_policy':'changed-science'")
    else:
        needle = b"CLASSES, SLOTS, TOTAL = 50, 64, 16000"
        assert needle in raw
        raw = raw.replace(needle, b"CLASSES, SLOTS, TOTAL = 49, 64, 16000", 1)
    path = tmp_path / "current-changed.py"
    path.write_bytes(raw)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        fixed._compatible_code_ref("target", before, fixed.reference(path))


@pytest.mark.parametrize("mutation", ["bytes", "full-mode"])
def test_complete_audit_source_read_keeps_final_operation_fence(complete_audit_target, mutation):
    context = OperationFacts()
    context.begin_action()
    with context.scope():
        source = fixed._sources()
        source["target"] = fixed.reference(complete_audit_target)
        assert fixed._compatible_sources(source)
        if mutation == "bytes":
            complete_audit_target.write_bytes(complete_audit_target.read_bytes() + b"\nchanged after source read\n")
        else:
            complete_audit_target.chmod(0o4644)
        with pytest.raises(ValueError):
            context.check()


def test_optional_genuine_progress328_and_last64_audit_source_dictionaries():
    selected = os.environ.get("QCSD_RAPID_CURRENT328_PROGRESS")
    if not selected:
        pytest.skip("set QCSD_RAPID_CURRENT328_PROGRESS for authentic source-only closure; no full audit implied")
    path = Path(selected)
    progress_ref = fixed.reference(path)
    assert progress_ref["sha256"] == PROGRESS328 and progress_ref["mode"] == 0o600
    progress = json.loads(fixed._open(progress_ref).read_bytes())["payload"]
    assert progress["target_accepted_count"] == 328
    assert fixed._compatible_sources(progress["sources"])
    audit_ref = progress["proofs"][-1]
    audit = json.loads(fixed._open(audit_ref).read_bytes())["payload"]
    assert audit["sources"]["target"]["sha256"] == SOURCE70
    assert len(audit["rows"]) == 64 and audit["scientific_credit"] is False
    original = deepcopy(audit["sources"])
    assert fixed._compatible_sources(audit["sources"])
    assert audit["sources"] == original
