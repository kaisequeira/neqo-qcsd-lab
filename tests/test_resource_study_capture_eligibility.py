"""Startup eligibility controls; no live capture or scientific qualification.

The existing disposable cohort fixtures retain real ancestry, SQLite and write
fences, with their declared synthetic preparation/raw leaves. The legacy
coordinator case uses only its synthetic capture backend and validator. No
production lock, reservation, pilot or credit gate is replaced here.
"""
from copy import deepcopy

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from tests.test_resource_study import (
    CaptureBackend, _runtime, controlled_validator, held,
)
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_runtime_cohorts import HOST, MODE, cohort_campaign


def test_one_authenticated_head_preserves_original_current_and_foreign_root_decisions(
        cohort_campaign, monkeypatch):
    c = cohort_campaign
    new = c.fresh(); c.append(new)
    cells = [(HOST, MODE), (HOST, "undefended"), ("unknown.example", MODE)]
    expected = frozenset(key for key in cells if epochs.active_cell(new, *key))
    assert expected == {(HOST, MODE)}
    calls, checked = [], []
    original_records, original_active = epochs._records, epochs._active

    def records(parent):
        calls.append(str(parent.root))
        return original_records(parent)

    def active(store, host, mode, authority):
        checked.append((str(store.root), host, mode))
        return original_active(store, host, mode, authority)

    monkeypatch.setattr(epochs, "_records", records)
    monkeypatch.setattr(epochs, "_active", active)
    observed = cohorts.eligible_cells(new, cells)
    assert type(observed) is frozenset and observed == expected
    assert calls == [str(c.parent.root)]
    assert checked == [(str(new.root), HOST, MODE)]
    # An unaffected mode still belongs to the historical root.
    assert cohorts.eligible_cells(c.old, cells) == {(HOST, "undefended")}


def test_startup_hint_cannot_authorize_a_writer_superseded_after_its_call(cohort_campaign):
    c = cohort_campaign
    first = c.fresh(); c.append(first)
    hint = cohorts.eligible_cells(first, [(HOST, MODE)])
    second = c.fresh(native="c"); c.append(second)
    assert hint == {(HOST, MODE)}  # The old immutable hint carries no write authority.
    assert cohorts.eligible_cells(first, [(HOST, MODE)]) == frozenset()
    assert cohorts.eligible_cells(second, [(HOST, MODE)]) == {(HOST, MODE)}
    with pytest.raises(ValueError, match="stale|superseded|excluded|differs"):
        first.allocate_attempt(HOST, MODE, purpose="pilot")
    assert first.status()["accepted_count"] == second.status()["accepted_count"] == 0


@pytest.mark.parametrize("kind", ["enrollment", "fence"])
@pytest.mark.parametrize("change", ["bytes", "mode"])
def test_eligibility_still_authenticates_current_cell_and_write_fence(
        cohort_campaign, kind, change):
    c = cohort_campaign
    new = c.fresh(); c.append(new)
    assert cohorts.eligible_cells(new, [(HOST, MODE)]) == {(HOST, MODE)}
    path = (new.root / "classes" / HOST / "enrollment.json" if kind == "enrollment"
            else new.root / lineage.FENCE)
    original = path.read_bytes()
    try:
        path.chmod(0o644)
        if change == "bytes":
            path.write_bytes(original + b"\n")
            path.chmod(0o444)
        with pytest.raises(ValueError):
            cohorts.eligible_cells(new, [(HOST, MODE)])
    finally:
        path.chmod(0o644); path.write_bytes(original); path.chmod(0o444)
    assert new.status()["accepted_count"] == 0


def test_closed_source_operation_cannot_be_rebound_to_make_an_eligibility_decision(cohort_campaign):
    c = cohort_campaign
    new = c.fresh(); c.append(new)
    with cohorts.source_operation(new) as auth:
        assert cohorts.eligible_cells(new, [(HOST, MODE)]) == {(HOST, MODE)}
    with pytest.raises(ValueError, match="closed"):
        with cohorts.bind_source(auth):
            cohorts.eligible_cells(new, [(HOST, MODE)])
    assert new.status()["accepted_count"] == 0


def test_missing_current_membership_cannot_be_treated_as_legacy_eligibility(cohort_campaign):
    c = cohort_campaign
    new = c.fresh(); c.append(new)
    marker = new.root / cohorts.MARKER
    raw = marker.read_bytes()
    try:
        marker.unlink()
        with pytest.raises((ValueError, FileNotFoundError)):
            cohorts.eligible_cells(new, [(HOST, MODE)])
    finally:
        marker.write_bytes(raw); marker.chmod(0o444)


@pytest.mark.parametrize("cells", [None, [(HOST,)], [(HOST, MODE), (HOST, MODE)],
    [(HOST, "unknown-mode")], [(HOST, MODE)] * 251])
def test_malformed_or_repeated_eligibility_scope_refuses_before_membership(monkeypatch, cells):
    def forbidden(*args):
        raise AssertionError("malformed eligibility must not read ledger membership")
    monkeypatch.setattr(epochs, "_membership", forbidden)
    with pytest.raises(ValueError):
        cohorts.eligible_cells(None, cells)


def test_public_legacy_capture_uses_one_startup_decision_without_replacing_store_gates(
        held, monkeypatch):
    root, store = held
    backend = CaptureBackend(root)
    calls = []
    original = cohorts.eligible_cells

    def eligible(actual_store, cells):
        calls.append((str(actual_store.root), deepcopy(cells)))
        return original(actual_store, cells)

    monkeypatch.setattr(cohorts, "eligible_cells", eligible)
    result = study.capture(root, _runtime(), workers=2, budget=2, modes=["front"],
        backend=backend)
    assert len(calls) == 1 and calls[0][0] == str(root)
    assert set(map(tuple, calls[0][1])) == {("alpha.example", "front"), ("bravo.example", "front")}
    assert result["progress"]["accepted_count"] == store.status()["accepted_count"] == 2
    assert backend.entered is backend.closed is True
