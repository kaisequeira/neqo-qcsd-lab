"""Fresh BF attempt retry controls; SOURCE only, ROOT alone executes.

The existing disposable BF-writer fixture supplies real public admissions,
source authority, reservation/ledger/seal/commit and tuple boundaries. Native,
PCAP and scientific verification remain explicitly synthetic fixture leaves.
This is not a capture, own-pilot qualification or live success assertion.
"""
from collections import deque
from copy import deepcopy
import threading

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab.resource_study_store import StudyStore
from tests.test_resource_study_bf122_pool import (
    HOSTS, MODE, RoutedBackend, bf_writers, native, pilots,
)


class ScriptedBackend(RoutedBackend):
    """One controlled collector outcome per actual, freshly allocated UUID."""
    def __init__(self, roots, script):
        super().__init__(roots)
        self.script = deque(script)
        self.decisions = []
        self.script_lock = threading.Lock()

    def capture(self, index, attempt, enrolled):
        target = attempt["hostname"] == HOSTS[0]
        with self.script_lock:
            outcome = self.script.popleft() if target and self.script else "S"
            if target:
                self.decisions.append((outcome, deepcopy(attempt)))
        # Existing fixture verifies the real reserved row, excludes concurrent
        # same-host work and writes one disclosed synthetic capture instance.
        if outcome == "D":
            self.ports[HOSTS[0]] = 31000  # existing retained historical tuple
        try:
            result = super().capture(index, attempt, enrolled)
        finally:
            if outcome == "D":
                self.ports.pop(HOSTS[0], None)
        if outcome == "F":
            return {**result, "success": False, "failure": {
                "stage": "runner-binding", "details": [{
                    "reason": "controlled terminal collector rejection; no live packet claim",
                    "runner_error": "controlled strict failure"}]}}
        if outcome == "backend":
            raise RuntimeError("controlled backend identity/authority failure")
        if outcome == "identity-result":
            return {**result, "success": False, "failure": None,
                    "resource_error": "controlled post-Native identity rejection"}
        if outcome == "malformed":
            return {**result, "success": 0, "failure": {
                "stage": "runner-binding", "details": [{"reason": "wrong boolean type"}]}}
        if outcome in {"stage-bool", "details-scalar", "details-empty-record"}:
            failure = {"stage": "runner-binding", "details": [{"reason": "controlled failure"}]}
            if outcome == "stage-bool":
                failure["stage"] = True
            elif outcome == "details-scalar":
                failure["details"] = ["not a typed failure record"]
            else:
                failure["details"] = [{}]
            return {**result, "success": False, "failure": failure}
        return result


def run_route(fixture, route, backend, *, budget=20, chunk=1, pilot=False):
    parent, roots, cells = fixture
    if route == "single":
        return study.capture(roots[0].root, native(), workers=2, budget=budget,
            modes=(MODE,), hostnames=[HOSTS[0]], chunk_sessions=chunk,
            pilot=pilot, backend=backend)
    assert route == "pool" and not pilot
    return study.capture_roots(parent.root, native(), cells, workers=2,
        budget=budget, chunk_sessions=chunk, backend=backend)


def target_paused(result, route):
    return ((HOSTS[0], MODE) in result["paused_cells"] if route == "single"
            else any(row["hostname"] == HOSTS[0] and row["mode"] == MODE
                     for row in result["paused_cells"]))


def target_rows(store, backend):
    ids = {attempt["attempt_id"] for _, attempt in backend.decisions}
    with store._transaction() as connection:
        rows = connection.execute(
            "SELECT attempt_id,path,state,kind FROM attempts WHERE hostname=? AND mode=?",
            (HOSTS[0], MODE)).fetchall()
        accepted = {row[0] for row in connection.execute("SELECT attempt_id FROM accepted")}
    return {row["attempt_id"]: dict(row) for row in rows if row["attempt_id"] in ids}, accepted


def assert_fresh_negative_files(store, backend, rows):
    calls = [attempt for _, attempt in backend.decisions]
    ids = [attempt["attempt_id"] for attempt in calls]
    assert len(ids) == len(set(ids))
    assert len({attempt["path"] for attempt in calls}) == len(calls)
    assert len({int(identifier[:16], 16) for identifier in ids}) == len(ids)
    for outcome, attempt in backend.decisions:
        if outcome == "F":
            row = rows[attempt["attempt_id"]]
            assert row["state"] == row["kind"] == "failed"
            failure = study.load(store.root / attempt["path"] / "failure.json")
            assert failure["attempt_id"] == attempt["attempt_id"]
            assert failure["scientific_credit"] is False
            assert (store.root / attempt["path"] / "capture/neqo/run.json").is_file()


@pytest.mark.parametrize("route", ["single", "pool"])
@pytest.mark.parametrize("chunk", [1, 2])
def test_bf_failure_streak_survives_chunks_and_only_verified_success_resets(
        bf_writers, route, chunk):
    _, roots, _ = bf_writers
    pilots(roots)
    backend = ScriptedBackend(roots, ["F", "S", "F", "F", "S", "F", "F", "F"])
    result = run_route(bf_writers, route, backend, chunk=chunk)
    assert [step for step, _ in backend.decisions] == ["F", "S", "F", "F", "S", "F", "F", "F"]
    assert target_paused(result, route)
    assert len(backend.calls) <= 20 and backend.closed
    rows, accepted = target_rows(roots[0], backend)
    assert len(rows) == 8 and len(accepted) == 2
    assert sum(row["kind"] == "failed" for row in rows.values()) == 6
    assert {a["attempt_id"] for outcome, a in backend.decisions if outcome == "F"}.isdisjoint(accepted)
    assert_fresh_negative_files(roots[0], backend, rows)


@pytest.mark.parametrize("route", ["single", "pool"])
def test_bf_third_collector_failure_pauses_without_stacked_clock_budget(
        bf_writers, route, monkeypatch):
    _, roots, _ = bf_writers
    pilots(roots)
    # If the BF branch fell through, this would authorize a separate clock
    # streak. It must never be consulted for BF after the new branch.
    clock_calls = []
    monkeypatch.setattr(study, "temporary_clock_failure", lambda result: clock_calls.append(result) or True)
    backend = ScriptedBackend(roots, ["F"] * 10)
    result = run_route(bf_writers, route, backend)
    assert len(backend.decisions) == 3 and target_paused(result, route)
    assert clock_calls == []
    rows, accepted = target_rows(roots[0], backend)
    assert len(rows) == 3 and not accepted
    assert_fresh_negative_files(roots[0], backend, rows)
    assert backend.closed and len(backend.calls) <= 20


@pytest.mark.parametrize("route", ["single", "pool"])
def test_bf_duplicate_is_negative_and_does_not_reset_collector_streak(bf_writers, route):
    _, roots, _ = bf_writers
    pilots(roots)
    backend = ScriptedBackend(roots, ["F", "D", "F", "D", "F"])
    result = run_route(bf_writers, route, backend)
    assert [step for step, _ in backend.decisions] == ["F", "D", "F", "D", "F"]
    assert target_paused(result, route)
    rows, accepted = target_rows(roots[0], backend)
    assert len(rows) == 5 and not accepted
    assert sum(row["kind"] == "duplicate" for row in rows.values()) == 2
    assert sum(row["kind"] == "failed" for row in rows.values()) == 3
    assert_fresh_negative_files(roots[0], backend, rows)


@pytest.mark.parametrize("route", ["single", "pool"])
@pytest.mark.parametrize("boundary", ["backend", "seal", "commit"])
def test_bf_backend_seal_or_commit_error_does_not_gain_retry(
        bf_writers, route, boundary, monkeypatch):
    _, roots, _ = bf_writers
    pilots(roots)
    if boundary == "seal":
        original = study.seal
        def seal(root, attempt, *args, **kwargs):
            if attempt["hostname"] == HOSTS[0]:
                raise ValueError("controlled immutable receipt identity failure")
            return original(root, attempt, *args, **kwargs)
        monkeypatch.setattr(study, "seal", seal)
    elif boundary == "commit":
        original = StudyStore.commit_verified
        def commit(store, path, **kwargs):
            if store.root == roots[0].root:
                raise ValueError("controlled commit authority failure")
            return original(store, path, **kwargs)
        monkeypatch.setattr(StudyStore, "commit_verified", commit)
    script = ["backend"] if boundary == "backend" else ["F", "S", "S"]
    backend = ScriptedBackend(roots, script)
    result = run_route(bf_writers, route, backend)
    assert len(backend.decisions) == (1 if boundary == "backend" else 2)
    assert target_paused(result, route)
    rows, accepted = target_rows(roots[0], backend)
    assert not accepted and all(row["kind"] == "failed" for row in rows.values())
    assert backend.closed and len(backend.calls) <= 20


@pytest.mark.parametrize("route", ["single", "pool"])
@pytest.mark.parametrize("boundary", ["allocation", "mark-captured"])
def test_bf_reservation_or_identity_transition_error_does_not_gain_retry(
        bf_writers, route, boundary, monkeypatch):
    _, roots, _ = bf_writers
    pilots(roots)
    if boundary == "allocation":
        original = StudyStore.allocate_attempt
        def allocate(store, host, mode, **kwargs):
            if store.root == roots[0].root:
                raise ValueError("controlled changed writer/attempt identity")
            return original(store, host, mode, **kwargs)
        monkeypatch.setattr(StudyStore, "allocate_attempt", allocate)
    else:
        original = StudyStore.mark_captured
        def captured(store, identifier):
            if store.root == roots[0].root:
                raise ValueError("controlled captured-attempt identity mismatch")
            return original(store, identifier)
        monkeypatch.setattr(StudyStore, "mark_captured", captured)
    backend = ScriptedBackend(roots, ["S"] * 5)
    result = run_route(bf_writers, route, backend)
    assert target_paused(result, route)
    assert len(backend.decisions) == (0 if boundary == "allocation" else 1)
    rows, accepted = target_rows(roots[0], backend)
    assert not accepted
    if boundary == "allocation":
        assert not rows and result["allocation_errors"]
    else:
        assert len(rows) == 1 and next(iter(rows.values()))["kind"] == "failed"
    assert backend.closed


@pytest.mark.parametrize("route", ["single", "pool"])
@pytest.mark.parametrize("outcome", ["identity-result", "malformed", "stage-bool", "details-scalar", "details-empty-record"])
def test_bf_noncollector_or_malformed_false_result_does_not_gain_retry(
        bf_writers, route, outcome):
    _, roots, _ = bf_writers
    pilots(roots)
    backend = ScriptedBackend(roots, [outcome] * 5)
    result = run_route(bf_writers, route, backend)
    assert len(backend.decisions) == 1 and target_paused(result, route)
    rows, accepted = target_rows(roots[0], backend)
    assert len(rows) == 1 and not accepted


def test_bf_pilot_failure_never_uses_new_or_clock_retry(bf_writers, monkeypatch):
    _, roots, _ = bf_writers
    pilots(roots)
    clock_calls = []
    monkeypatch.setattr(study, "temporary_clock_failure", lambda result: clock_calls.append(result) or True)
    backend = ScriptedBackend(roots, ["F"] * 5)
    result = run_route(bf_writers, "single", backend, pilot=True)
    assert len(backend.decisions) == 1 and target_paused(result, "single")
    rows, accepted = target_rows(roots[0], backend)
    assert len(rows) == 1 and not accepted
    assert next(iter(rows.values()))["kind"] == "pilot-failed"
    assert clock_calls == []
