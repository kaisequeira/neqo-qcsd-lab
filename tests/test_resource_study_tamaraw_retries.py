"""Real dispatch/reservations over disposable SQLite, synthetic raw sessions.

The existing fixture validator checks exactly 20 synthetic responses. It is
not Native, timing, runtime, QUIC or scientific qualification evidence.
"""
from copy import deepcopy
import sqlite3

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab.resource_study_store import StudyStore
import test_resource_study as fixtures
from test_resource_study import controlled_validator


POLICY = {"synthetic_tamaraw_policy": "not-physical-proof"}
MISSING = "Tamaraw physical release proof lacks scheduled outgoing handoffs"
EXTRA = "terminal primary partial does not authorize another missed cell"


def accepted_count(store, hostname, mode):
    """Read unmodified map-aware Store status; no indexed Store port."""
    return next(row["accepted"] for row in store.status()["cells"]
                if (row["hostname"], row["mode"]) == (hostname, mode))


def seed_counts(store, hostname, mode, count):
    """Index-only quota fixture; not verified receipts or scientific credit."""
    with store._transaction() as connection:
        for slot in range(1, count + 1):
            identifier = f"index-fixture-{hostname}-{mode}-{slot}"
            path = f"index-fixture/{identifier}"
            connection.execute("""INSERT INTO attempts
                (attempt_id,hostname,mode,slot,attempt,path,state,created_at,updated_at)
                VALUES(?,?,?,?,?,?,'accepted','fixture','fixture')""",
                (identifier, hostname, mode, slot, slot, path))
            connection.execute("INSERT INTO accepted VALUES(?,?,?,?,?,?,?,?,?)",
                (hostname, mode, slot, f"fixture-tuple-{slot}", identifier,
                 path + "/receipt.json", "a" * 64, "{}", "fixture"))


def context(*, rejected=False, reason=EXTRA):
    value = {"success": not rejected, "resource_error": None, "mode_policies": POLICY,
        "runner_returncode": 0, "runner_timed_out": False,
        "runner_completion_status": "complete", "runner_complete": True,
        "runner_binding_valid": not rejected, "endpoint_count_valid": True,
        "process_scheduler_valid": True, "scheduler_runtime_evidence_valid": True,
        "operationally_valid": True, "runner_output_error": None, "runner_error": None,
        "runner_error_class": None, "runner_process_failure": None,
        "observer_topology_required": True, "observer_topology_valid": True,
        "kernel_tx_evidence_required": False, "kernel_tx_evidence_valid": None,
        "views": [{"primary": True, "valid": True,
            "capture_clock_integrity": {"valid": True},
            "direct_runner_reconciliation": {"evidence_eligible": True}}], "failure": None}
    if rejected:
        value["failure"] = {"stage": "runner-binding", "details": [{
            "runner_returncode": 0, "runner_timed_out": False,
            "completion_status": "complete", "scheduler_runtime_evidence_valid": True,
            "incomplete_resources": [], "operational_failure": None,
            "runner_output_error": None, "runner_error": None, "runner_error_class": None,
            "runner_process_failure": None, "runner_binding_error": reason}]}
    return value


@pytest.fixture
def retry_study(tmp_path, controlled_validator, monkeypatch):
    # Reuse the real frozen coordinator fixture, adding a nonempty explicitly
    # synthetic policy before the actual immutable enrollment is published.
    original = fixtures._enrollment

    def enrollment(*args, **kwargs):
        value = original(*args, **kwargs)
        value["mode_policies"] = {"tamaraw": deepcopy(POLICY)}
        return value

    monkeypatch.setattr(fixtures, "_enrollment", enrollment)
    return fixtures.held.__wrapped__(tmp_path, controlled_validator)


class ScriptedBackend(fixtures.CaptureBackend):
    def __init__(self, root, scripts, *, repeat_tuple=False):
        super().__init__(root, repeat_tuple=repeat_tuple)
        self.scripts = deepcopy(scripts)
        self.seal_errors = {}

    def capture(self, worker, attempt, enrollment):
        super().capture(worker, attempt, enrollment)
        action = self.scripts.get(attempt["hostname"], [])
        action = action.pop(0) if action else "pass"
        result = context()
        if action == "collector":
            result = context(rejected=True)
        elif action in {"seal", "integrity"}:
            self.seal_errors[attempt["attempt_id"]] = MISSING if action == "seal" else "runtime provenance changed"
        elif action == "critical":
            result = context(rejected=True, reason="Native executable changed during capture")
            result["resource_error"] = "Native executable changed during capture"
        return result


def run(root, backend, monkeypatch, *, budget, chunk=1, hosts=("alpha.example",), pilot=False):
    original = study.verify_receipt

    def validator(actual_root, receipt):
        if receipt["attempt_id"] in backend.seal_errors:
            raise ValueError(backend.seal_errors[receipt["attempt_id"]])
        return original(actual_root, receipt)

    monkeypatch.setattr(study, "verify_receipt", validator)
    return study.capture(root, fixtures._runtime(), backend=backend, modes=("tamaraw",),
        hostnames=list(hosts), budget=budget, chunk_sessions=chunk, pilot=pilot)


def retry_cell(result):
    return result["tamaraw_strict_rejection_retries"]["cells"][0]


def attempts(root):
    with sqlite3.connect(root / "ledger.sqlite3") as database:
        return database.execute("SELECT attempt_id,state,kind,slot FROM attempts ORDER BY attempt").fetchall()


@pytest.mark.parametrize("rejection", ["collector", "seal"])
def test_strict_rejection_then_fresh_pass_keeps_failed_raw_zero_credit(retry_study, monkeypatch, rejection):
    root, store = retry_study
    backend = ScriptedBackend(root, {"alpha.example": [rejection, "pass"]})
    result = run(root, backend, monkeypatch, budget=2)
    ids = [attempt["attempt_id"] for _, attempt in backend.calls]
    assert len(ids) == len(set(ids)) == 2
    assert [attempt["slot"] for _, attempt in backend.calls] == [1, 1]
    assert [(row[1], row[2]) for row in attempts(root)] == [("failed", "failed"), ("accepted", None)]
    assert accepted_count(store, "alpha.example", "tamaraw") == 1
    assert not result["paused_cells"]
    history = retry_cell(result)
    assert history["actual_retry_count"] == 1 and not history["retry_pending_without_allocation"]
    assert history["rejections"][0]["rejected_attempt_id"] == ids[0]
    assert history["rejections"][0]["fresh_attempt_id"] == ids[1]
    failed = root / backend.calls[0][1]["path"] / "failure.json"
    assert study.load(failed)["scientific_credit"] is False
    retained = (root / "failures/alpha.example/tamaraw" / ids[0] if rejection == "seal"
                else root / backend.calls[0][1]["path"] / "capture")
    assert (retained / "diagnostics/direct-quic-raw.pcapng").is_file()
    assert not (retained / "session.json").exists()


@pytest.mark.parametrize("chunk", [1, 20])
def test_two_retries_total_across_successes_third_rejection_pauses(retry_study, monkeypatch, chunk):
    root, store = retry_study
    backend = ScriptedBackend(root, {"alpha.example": ["collector", "pass", "seal", "pass", "collector", "pass"]})
    result = run(root, backend, monkeypatch, budget=10, chunk=chunk)
    assert len(backend.calls) == 5
    assert accepted_count(store, "alpha.example", "tamaraw") == 2
    assert result["paused_cells"] == [("alpha.example", "tamaraw")]
    history = retry_cell(result)
    assert history["actual_retry_count"] == 2
    assert [r["retry_permitted"] for r in history["rejections"]] == [True, True, False]
    assert [r["fresh_attempt_id"] is not None for r in history["rejections"]] == [True, True, False]
    assert not history["retry_pending_without_allocation"]


def test_paused_cell_does_not_block_healthy_cell(retry_study, monkeypatch):
    root, store = retry_study
    backend = ScriptedBackend(root, {"alpha.example": ["collector"] * 4})
    result = run(root, backend, monkeypatch, budget=8, hosts=("alpha.example", "bravo.example"))
    assert result["paused_cells"] == [("alpha.example", "tamaraw")]
    assert sum(a["hostname"] == "alpha.example" for _, a in backend.calls) == 3
    assert accepted_count(store, "bravo.example", "tamaraw") == 5
    assert len(backend.calls) == 8 and not backend.active and backend.closed


@pytest.mark.parametrize("budget,expected", [(1, 0), (2, 1)])
def test_attempt_exhaustion_cannot_expand_retry_budget(retry_study, monkeypatch, budget, expected):
    root, store = retry_study
    backend = ScriptedBackend(root, {"alpha.example": ["collector"] * 3})
    result = run(root, backend, monkeypatch, budget=budget)
    assert len(backend.calls) == budget and accepted_count(store, "alpha.example", "tamaraw") == 0
    assert retry_cell(result)["actual_retry_count"] == expected
    assert retry_cell(result)["retry_pending_without_allocation"]
    assert result["tamaraw_strict_rejection_retries"]["attempt_budget"] == budget


def test_retry_at_399_cannot_exceed_400_or_spend_rest_of_chunk(retry_study, monkeypatch):
    root, store = retry_study
    seed_counts(store, "alpha.example", "tamaraw", 399)
    backend = ScriptedBackend(root, {"alpha.example": ["collector", "pass"]})
    result = run(root, backend, monkeypatch, budget=20, chunk=20)
    assert len(backend.calls) == 2 and accepted_count(store, "alpha.example", "tamaraw") == 400
    assert [a["slot"] for _, a in backend.calls] == [400, 400]
    assert retry_cell(result)["actual_retry_count"] == 1
    with pytest.raises(ValueError, match="four hundred"):
        store.allocate_attempt("alpha.example", "tamaraw")


def test_duplicate_stays_uncredited_and_does_not_reset_retry_total(retry_study, monkeypatch):
    root, store = retry_study
    backend = ScriptedBackend(root, {"alpha.example": ["pass", "collector", "pass", "collector", "pass", "collector"]},
        repeat_tuple=True)
    result = run(root, backend, monkeypatch, budget=8)
    assert len(backend.calls) == 6 and accepted_count(store, "alpha.example", "tamaraw") == 1
    assert sum(row[2] == "duplicate" for row in attempts(root)) == 2
    assert retry_cell(result)["actual_retry_count"] == 2
    assert result["paused_cells"] == [("alpha.example", "tamaraw")]


@pytest.mark.parametrize("passes", [True, False])
def test_pilot_retries_are_finite_and_success_never_credits(retry_study, monkeypatch, passes):
    root, store = retry_study
    backend = ScriptedBackend(root, {"alpha.example": ["collector", "seal", "pass" if passes else "collector", "pass"]})
    result = run(root, backend, monkeypatch, budget=10, pilot=True)
    assert len(backend.calls) == 3 and accepted_count(store, "alpha.example", "tamaraw") == 0
    assert result["pilot_cells_passed"] == ([("alpha.example", "tamaraw")] if passes else [])
    assert result["paused_cells"] == ([] if passes else [("alpha.example", "tamaraw")])
    assert retry_cell(result)["actual_retry_count"] == 2
    assert [row[2] for row in attempts(root)] == ["pilot-failed", "pilot-failed", "pilot" if passes else "pilot-failed"]


@pytest.mark.parametrize("action", ["critical", "integrity"])
def test_critical_failure_does_not_gain_retry(retry_study, monkeypatch, action):
    root, store = retry_study
    backend = ScriptedBackend(root, {"alpha.example": [action, "pass"]})
    result = run(root, backend, monkeypatch, budget=4)
    assert len(backend.calls) == 1 and accepted_count(store, "alpha.example", "tamaraw") == 0
    assert result["paused_cells"] == [("alpha.example", "tamaraw")]
    assert result["tamaraw_strict_rejection_retries"]["cells"] == []


@pytest.mark.parametrize("field,value", [
    ("resource_error", "changed client"), ("runner_returncode", False),
    ("runner_timed_out", True), ("runner_complete", False), ("endpoint_count_valid", False),
    ("process_scheduler_valid", False), ("scheduler_runtime_evidence_valid", False),
    ("operationally_valid", False), ("runner_output_error", "bad output"),
    ("runner_error", "bad run"), ("runner_error_class", "bad class"),
    ("runner_process_failure", "lost child"), ("observer_topology_valid", False),
    ("kernel_tx_evidence_required", True), ("views", []), ("mode_policies", {}),
])
def test_exact_reason_cannot_override_bad_functional_scheduler_or_runtime_context(field, value):
    result = context(rejected=True)
    result[field] = value
    assert study.tamaraw_retry_reason("tamaraw", result, ValueError("collector rejected session"),
        origin="collector", policy=POLICY) is None


def test_malformed_additional_critical_failure_and_wrong_origin_are_not_retryable():
    result = context(rejected=True)
    result["failure"]["details"].append({"primary": True, "reason": "provenance changed"})
    assert study.tamaraw_retry_reason("tamaraw", result, ValueError(EXTRA), origin="collector", policy=POLICY) is None
    result = context()
    for origin in ("backend", "commit", "allocation", "storage"):
        assert study.tamaraw_retry_reason("tamaraw", result, ValueError(MISSING), origin=origin, policy=POLICY) is None
    for mode in ("undefended", "front", "buflo", "cs-buflo"):
        assert study.tamaraw_retry_reason(mode, result, ValueError(MISSING), origin="seal", policy=POLICY) is None
    result["views"][0]["capture_clock_integrity"] = None
    assert study.tamaraw_retry_reason("tamaraw", result, ValueError(MISSING), origin="seal", policy=POLICY) is None


def test_allocation_failure_is_not_retryable_or_a_native_attempt(retry_study, monkeypatch):
    root, _ = retry_study
    backend = ScriptedBackend(root, {})

    def refused(*args, **kwargs):
        raise ValueError(MISSING)

    monkeypatch.setattr(StudyStore, "allocate_attempt", refused)
    result = run(root, backend, monkeypatch, budget=5)
    assert backend.calls == [] and len(result["allocation_errors"]) == 1
    assert result["tamaraw_strict_rejection_retries"]["cells"] == []


def test_old_clock_exception_remains_a_separate_policy():
    result = context(rejected=True)
    result["runner_binding_valid"] = True
    result["failure"] = {"stage": "capture", "details": [{
        "reason": "direct/runner reconciliation failed: direct/runner timestamp mismatch: fixture"}]}
    assert study.temporary_clock_failure(result)
    assert study.tamaraw_retry_reason("tamaraw", result, ValueError(MISSING), origin="collector", policy=POLICY) is None
