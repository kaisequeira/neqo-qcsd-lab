"""Retained ACK-start directory wiring; ROOT executes the real four-file case.

The small inherited fixtures exercise actual validators and CSV IO. They do
not replace the full Native098 retained receipt or add scientific credit.
"""
import pytest

from qcsd_lab import buflo_handoff as handoff
from qcsd_lab import capture_acceptance_policy as policy
from tests.test_buflo_local_abandon_reader import algorithm, local
from tests.test_capture_buflo_ack_start import fixture as ack_fixture


def test_actual_ack_start_reader_requires_its_events_and_schedule_directory(tmp_path):
    run, _, _ = ack_fixture(tmp_path)
    with pytest.raises(ValueError, match="reopened native event and schedule evidence"):
        policy.validate_buflo_startup_evidence(run, runner_directory=None)
    assert policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path) == run["buflo_summary"]["incoming_startup"]


def test_retained_algorithm_passes_the_bound_directory_to_the_actual_validator(local, monkeypatch):
    run, paths, _, _ = local
    original = handoff.new_defense_terminal_receipts_valid
    calls = []

    def observe(*args, **kwargs):
        calls.append(kwargs.copy())
        return original(*args, **kwargs)

    monkeypatch.setattr(handoff, "new_defense_terminal_receipts_valid", observe)
    assert algorithm(run, paths)["schema_version"] == 5
    assert len(calls) == 1
    assert calls[0]["runner_directory"] == paths["events"].parent
    assert calls[0]["terminal_trace_paths"] == {"events": paths["events"], "packets": paths["packets"]}


@pytest.mark.parametrize("which,change", [("events", "name"), ("schedule", "name"),
    ("packets", "name"), ("schedule", "directory"), ("packets", "directory")])
def test_new_protocol_cannot_reopen_a_different_implicit_native_trace(local, monkeypatch, which, change):
    run, paths, _, _ = local
    paths = dict(paths)
    target = (paths[which].with_name("other-" + paths[which].name) if change == "name"
        else paths[which].parent / "other" / paths[which].name)
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(paths[which].read_bytes())
    paths[which] = target

    def no_common_validation(*args, **kwargs):
        raise AssertionError("different traces must be refused before common validation")

    monkeypatch.setattr(handoff, "new_defense_terminal_receipts_valid", no_common_validation)
    with pytest.raises(ValueError, match="one exact Native evidence directory"):
        algorithm(run, paths)
