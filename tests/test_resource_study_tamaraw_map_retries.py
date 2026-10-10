"""Map-aware retry dispatch over actual disposable V3 admission/fence roots.

Native/raw validation is the existing explicitly synthetic twenty-response
fixture. Membership, frozen enrollments, reservations, write fences, actual
dispatcher and per-cell pilot selection execute; no traffic authority follows.
"""
from copy import deepcopy
import sqlite3

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab.resource_study_store import StudyStore
import test_resource_study as fixtures
import test_resource_study_lineage as maps
from test_resource_study import controlled_validator
from test_resource_study_tamaraw_retries import (
    POLICY, ScriptedBackend as OriginalScriptedBackend, accepted_count, retry_cell, run,
)


class ScriptedBackend(OriginalScriptedBackend):
    def write_capture(self, attempt, enrollment, port):
        super().write_capture(attempt, enrollment, port)
        directory = self.root / attempt["path"] / "capture"
        run_path = directory / "neqo/run.json"
        run_value = study.load(run_path)
        address = StudyStore(self.root).plan()["class_network"]["assignments"][attempt["hostname"]]["client_ipv4"]
        run_value["endpoints"][0]["local_address"] = f"{address}:{port}"
        maps.rewrite(run_path, run_value)
        # Required topology/scheduler artifact paths exist and are immutable;
        # their contents remain explicitly synthetic under controlled_validator.
        fixtures._write(directory / "class-network.json", {"synthetic_map_fixture": True})
        fixtures._write(directory / "diagnostics/scheduler-runtime-evidence.json",
                        {"synthetic_scheduler_fixture": True})


@pytest.fixture
def mapped(tmp_path, monkeypatch, controlled_validator):
    original = maps.enrollment

    def enrollment(*args, **kwargs):
        value = original(*args, **kwargs)
        value["runtime"] = fixtures._runtime()
        value["mode_policies"]["tamaraw"] = deepcopy(POLICY)
        return value

    monkeypatch.setattr(maps, "enrollment", enrollment)
    parent, child, _ = maps.campaign.__wrapped__(tmp_path, monkeypatch)
    mal = child()
    maps.admit(parent, mal, ["tamaraw", "front"])
    # The exact public pilot reader still runs; only independent raw science is
    # controlled, as in the original coordinator fixture.
    monkeypatch.setattr(epochs, "verify_receipt", study.verify_receipt)
    return parent, mal, child


def qualify(root, hosts, monkeypatch):
    result = run(root, ScriptedBackend(root, {}), monkeypatch,
                 budget=len(hosts), hosts=hosts, pilot=True)
    assert result["pilot_cells_passed"] == [(host, "tamaraw") for host in sorted(hosts)], (
        result, [study.load(path) for path in root.rglob("failure.json")])
    assert result["progress"]["accepted_count"] == 0


def test_mal_retry_uses_admitted_stable_map_and_keeps_failed_pilot_zero_credit(mapped, monkeypatch):
    parent, mal, _ = mapped
    before = deepcopy(epochs._records(parent)[-1])
    backend = ScriptedBackend(mal.root, {lineage.INCLUDED: ["collector", "seal", "pass"]})
    result = run(mal.root, backend, monkeypatch, budget=3, hosts=(lineage.INCLUDED,), pilot=True)
    assert result["pilot_cells_passed"] == [(lineage.INCLUDED, "tamaraw")], (
        result, [study.load(path) for path in mal.root.rglob("failure.json")])
    assert len(backend.calls) == 3 and len({a["attempt_id"] for _, a in backend.calls}) == 3
    assert retry_cell(result)["actual_retry_count"] == 2
    receipt = study.load(next((mal.root / "pilots").rglob("session.json")))
    assert receipt["class_network"]["record_type"] == lineage.MAP
    assert "resource_study_lineage.py" in receipt["coordinator_provenance"]["files"]
    assert receipt["hostname"] == lineage.INCLUDED and not receipt["scientific_credit"]
    assert result["progress"]["accepted_count"] == parent.status()["accepted_count"] == 0
    assert epochs._records(parent)[-1] == before
    assert lineage.EXCLUDED not in mal.plan()["class_network"]["assignments"]


def test_third_retained_rejection_pauses_only_that_cell_under_real_fences(mapped, monkeypatch):
    parent, _, _ = mapped
    qualify(parent.root, ("alpha.example", "beta.example"), monkeypatch)
    backend = ScriptedBackend(parent.root, {"alpha.example": ["collector"] * 4})
    result = run(parent.root, backend, monkeypatch, budget=8,
                 hosts=("alpha.example", "beta.example"))
    assert result["paused_cells"] == [("alpha.example", "tamaraw")]
    assert sum(a["hostname"] == "alpha.example" for _, a in backend.calls) == 3
    assert accepted_count(parent, "alpha.example", "tamaraw") == 0
    assert accepted_count(parent, "beta.example", "tamaraw") == 5
    with parent._transaction() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="write fence"):
            connection.execute("DELETE FROM measurements")


def test_unadmitted_same_map_child_never_dispatches_or_spends_retry_budget(mapped, monkeypatch):
    _, _, child = mapped
    pending = child("unadmitted")
    backend = ScriptedBackend(pending.root, {lineage.INCLUDED: ["collector"]})
    with pytest.raises(ValueError, match="committed parent"):
        run(pending.root, backend, monkeypatch, budget=3, hosts=(lineage.INCLUDED,), pilot=True)
    assert backend.calls == [] and pending.status()["attempts"] == {}


def test_superseded_root_is_filtered_and_direct_allocation_still_refuses(mapped, monkeypatch):
    parent, _, _ = mapped
    fresh = StudyStore(parent.root.parent / "replacement")
    # A genuine new scientific epoch is used only inside this disposable HOST
    # fixture; its raw/preparation boundary is synthetic and gives no authority.
    study.initialize(parent.root / "inputs/supplied-resources.json", fresh.root)
    value = maps.enrollment(fresh, "alpha.example")
    value["runtime"] = fixtures._runtime(client="f")
    fresh.enroll(value)
    monkeypatch.setattr(epochs, "_verify_preparation", lambda *a: None)
    epochs.create_epoch(parent.root, fresh.root, change="native",
        affected_hostnames=["alpha.example"], affected_modes=["tamaraw"])
    backend = ScriptedBackend(parent.root, {"alpha.example": ["collector"]})
    result = run(parent.root, backend, monkeypatch, budget=3, hosts=("alpha.example",), pilot=True)
    assert not backend.calls and not result["tamaraw_strict_rejection_retries"]["cells"]
    with pytest.raises(ValueError, match="excluded|superseded"):
        parent.allocate_attempt("alpha.example", "tamaraw", purpose="pilot")


def test_write_fence_corruption_cannot_be_retried_or_healed(mapped, monkeypatch):
    parent, _, _ = mapped
    before = (parent.root / lineage.FENCE).read_bytes()
    (parent.root / lineage.FENCE).chmod(0o644)
    backend = ScriptedBackend(parent.root, {"alpha.example": ["collector"]})
    with pytest.raises(ValueError):
        run(parent.root, backend, monkeypatch, budget=3, hosts=("alpha.example",), pilot=True)
    assert backend.calls == [] and (parent.root / lineage.FENCE).read_bytes() == before
    assert (parent.root / lineage.FENCE).stat().st_mode & 0o777 == 0o644


def test_retry_does_not_replace_full_runtime_pilot_or_cross_mode_proof(mapped, monkeypatch):
    parent, mal, _ = mapped
    qualify(mal.root, (lineage.INCLUDED,), monkeypatch)
    backend = ScriptedBackend(mal.root, {})
    with pytest.raises(ValueError, match="focused pilot"):
        study.capture(mal.root, fixtures._runtime(lab="b"), backend=backend,
            modes=("tamaraw",), hostnames=[lineage.INCLUDED], budget=3, chunk_sessions=1)
    assert not backend.calls
    backend = ScriptedBackend(mal.root, {})
    with pytest.raises(ValueError, match="focused pilot"):
        study.capture(mal.root, fixtures._runtime(), backend=backend,
            modes=("front",), hostnames=[lineage.INCLUDED], budget=3, chunk_sessions=1)
    assert not backend.calls
    assert epochs.status(parent.root)["accepted_count"] == 0
