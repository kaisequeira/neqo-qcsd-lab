"""Finite Source080 BF pool controls; ROOT alone runs them.

Real disposable selected50 admissions, reservation/slot/tuple/negative/seal/credit
paths execute. Raw scientific verification and packet generation are explicit
synthetic leaves copied from the existing shared-flight fixture. No Docker,
Native qualification or measured success is claimed. Only the allowed ROOT
namespace is mapped to temporary directories for these local fixtures.
"""
from copy import deepcopy
from contextlib import nullcontext
import json
from pathlib import Path
import threading

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_network as network
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import MODES, canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore, _create
from tests.test_resource_study import CaptureBackend
from tests.test_resource_study_epochs import controlled_pilot
from tests.test_resource_study_lineage import (
    HOSTS as ORIGINAL_HOSTS, admit, controlled_credit, enrollment, rewrite,
)

MODE = "buflo"
HOSTS = (lineage.INCLUDED, "alpha.example")
POLICY640 = "rapid-v7-fixed-64ms-640s-duration-budget-v1"


def native():
    return deepcopy(runtime.BF122_SHARED_RUNTIME)


def raw_leaf(root, receipt):
    return {"verified": True, "five_tuple": receipt.get("five_tuple")}


@pytest.fixture
def bf_writers(tmp_path, monkeypatch):
    # Same campaign protocol as the original CS fixture; no scientific/raw
    # acceptance is obtained from these synthetic fixtures.
    from qcsd_lab import resource_study_store as storage
    monkeypatch.setattr(storage.os, "fsync", lambda _: None)
    monkeypatch.setattr(storage, "_fsync", lambda _: None)
    monkeypatch.setattr(epochs, "docker_lock", nullcontext)
    monkeypatch.setattr(epochs, "_verify_preparation", lambda *a, **kw: None)
    monkeypatch.setattr(epochs, "verify_receipt", raw_leaf)
    monkeypatch.setattr(cohorts, "verify_receipt", raw_leaf)
    monkeypatch.setattr(study, "verify_receipt", raw_leaf)
    source = tmp_path / "source.json"
    source.write_bytes(canonical_json([{"crUX_domain": "official.example", "resources": [
        {"resource_domain": host, "resource_urls": [f"https://{host}/r?i={i}" for i in range(20)]}
        for host in ORIGINAL_HOSTS]}]))
    parent = StudyStore(tmp_path / "parent")
    study.initialize(source, parent.root, storage_reserve_bytes=2 * 1024 ** 3)

    def prepared(store, host):
        value = enrollment(store, host)
        value["mode_policies"][MODE] = {"buflo_duration_policy": POLICY640}
        return value

    for host in ORIGINAL_HOSTS[:2]:
        parent.enroll(prepared(parent, host))
    cells = {(host, mode): epochs._cell(parent, host, mode)
             for host in ORIGINAL_HOSTS[:2] for mode in MODES}
    epochs._bind(parent, parent)
    epochs._publish(parent, [], cells, "initial", cells)
    inventory = tmp_path / "MAL.json"
    inventory.write_bytes(canonical_json({"urls": [
        {"url": f"https://{lineage.INCLUDED}/r?i={i}"} for i in range(25)]}))
    inventory.chmod(0o444)
    old = StudyStore(tmp_path / "prior-native")
    lineage.initialize(parent.root, old.root, inventory, storage_reserve_bytes=2 * 1024 ** 3)
    old.enroll(lineage.bind_enrollment(old, prepared(old, HOSTS[0])))
    admit(parent, old)
    controlled_pilot(old, HOSTS[0], MODE)
    attempt = old.allocate_attempt(HOSTS[0], MODE)
    receipt_path = controlled_credit(old, attempt, commit=False)
    receipt = study.load(receipt_path)
    receipt["coordinator_provenance"] = study.coordinator_provenance(class_selection=True)
    rewrite(receipt_path, receipt)
    old.commit_verified(receipt_path, validator=raw_leaf)
    roots = []
    for index, host in enumerate(HOSTS, 1):
        store = StudyStore(tmp_path / f"native122-cohort-{index:03d}")
        cohorts.initialize_cohort(parent.root, store.root)
        donor = old if host == HOSTS[0] else parent
        value = deepcopy(epochs._enrollments(donor)[host][0])
        _create(store.root / value["workload_path"], donor._file(value["workload_path"])[0])
        value["runtime"] = native()
        value["source_occurrences"] = study.candidate_pool(store.root)[host]["source_occurrences"]
        store.enroll(lineage.bind_enrollment(store, value))
        declaration = cohorts.compatibility_template(parent.root, store.root,
            affected_hostnames=[host], affected_modes=[MODE])
        declaration.update(compatible_treatment=True,
            rationale="Disposable Source080 pool fixture; no live/raw qualification claim.")
        declaration_path = tmp_path / f"declaration-{index}.json"
        _create(declaration_path, canonical_json(declaration))
        cohorts.create_cohort(parent.root, store.root, declaration_path, sha256_file(declaration_path))
        roots.append(store)
    # Only the production namespace boundary is mapped for temporary ledgers.
    # The production literal allowlist is independently asserted below.
    monkeypatch.setattr(runtime, "BF122_SHARED_ROOTS", tuple(str(store.root) for store in roots))
    selected = [{"root": str(store.root), "hostname": host, "mode": MODE}
                for store, host in zip(roots, HOSTS)]
    return parent, roots, selected


def pilots(roots):
    for store, host in zip(roots, HOSTS):
        controlled_pilot(store, host, MODE)


class RoutedBackend:
    """Synthetic packet leaf; every capture sees its actual reserved row."""
    def __init__(self, roots, *, fail=None, overlap=False, stop=None, ports=None):
        self.by_host = dict(zip(HOSTS, roots))
        self.fail, self.stop, self.ports = fail, stop, ports or {}
        self.calls, self.released, self.source_handles = [], [], []
        self.active = set()
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(2) if overlap else None
        self.entered = self.closed = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *_):
        assert not self.active
        self.closed = True

    def release(self, index):
        self.released.append(index)

    def capture(self, index, attempt, enrolled):
        host = attempt["hostname"]
        store = self.by_host[host]
        with store._transaction() as connection:
            row = connection.execute("SELECT hostname,mode,slot,state FROM attempts WHERE attempt_id=?",
                                     (attempt["attempt_id"],)).fetchone()
        assert tuple(row) == (host, MODE, attempt["slot"], "reserved")
        assert epochs._enrollments(store)[host][0] == enrolled
        with self.lock:
            assert host not in self.active
            self.active.add(host)
            self.calls.append((store.root, index, deepcopy(attempt)))
            number = len(self.calls)
            self.source_handles.append(cohorts._SOURCE_OPERATION.get())
        try:
            if self.barrier is not None and number <= 2:
                self.barrier.wait(timeout=10)
            if host == self.fail:
                return {"success": False, "failure": "controlled one-root rejection"}
            port = self.ports.get(host, 42000 + number)
            CaptureBackend(store.root).write_capture(attempt, enrolled, port)
            directory = store.root / attempt["path"] / "capture"
            run = json.loads((directory / "neqo/run.json").read_bytes())
            ip = store.plan()["class_network"]["assignments"][host]["client_ipv4"]
            run["endpoints"] = [{"id": 0, "local_address": f"{ip}:{port}",
                                 "remote_address": "8.8.8.8:443"}]
            rewrite(directory / "neqo/run.json", run)
            (directory / "class-network.json").write_bytes(canonical_json(
                network.receipt_binding(store.plan(), sha256_file(store.root / "study.json"), host)))
            (directory / "diagnostics/scheduler-runtime-evidence.json").write_bytes(canonical_json(
                {"fixture": "controlled raw proof leaf; no physical scheduler claim"}))
            if self.stop is not None:
                self.stop.set()
            return {"success": True, "mode_policies": enrolled["mode_policies"][MODE]}
        finally:
            with self.lock:
                self.active.remove(host)


def test_bf_pool_real_two_root_credit_global_slots_and_duplicate_tuple(bf_writers):
    parent, roots, cells = bf_writers
    pilots(roots)
    assert roots[0].status()["accepted_count"] == 0
    assert cohorts.accepted_count(roots[0], HOSTS[0], MODE) == 1
    backend = RoutedBackend(roots, overlap=True)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
                                 chunk_sessions=1, backend=backend)
    assert result["record_type"] == "qcsd-resource-domain-native122-buflo-pool-capture-result-v1"
    assert backend.closed and len(backend.calls) == len(backend.released) == 2
    assert len({worker for _, worker, _ in backend.calls}) == 2
    assert {root for root, _, _ in backend.calls} == {store.root for store in roots}
    assert next(a["slot"] for _, _, a in backend.calls if a["hostname"] == HOSTS[0]) == 2
    assert all(store.status()["accepted_count"] == 1 for store in roots)
    assert cohorts.accepted_count(roots[0], HOSTS[0], MODE) == 2
    assert all(handle is not None and not handle.active for handle in backend.source_handles)
    assert cohorts._SOURCE_OPERATION.get() is None
    duplicate = RoutedBackend(roots, ports={HOSTS[0]: 31000, HOSTS[1]: 43000})
    study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
                        chunk_sessions=1, backend=duplicate)
    assert roots[0].status()["accepted_count"] == 1
    assert cohorts.accepted_count(roots[0], HOSTS[0], MODE) == 2
    with roots[0]._transaction() as connection:
        assert connection.execute("SELECT count(*) FROM attempts WHERE state='duplicate'").fetchone()[0] == 1


def test_bf_pool_failed_root_pauses_while_other_root_replenishes_lane(bf_writers):
    parent, roots, cells = bf_writers
    pilots(roots)
    backend = RoutedBackend(roots, fail=HOSTS[0], overlap=True)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=4,
                                 chunk_sessions=1, backend=backend)
    assert result["paused_cells"] == [cells[0]]
    assert backend.closed and len(backend.calls) == len(backend.released) == 4
    assert sum(a["hostname"] == HOSTS[0] for _, _, a in backend.calls) == 1
    assert roots[0].status()["accepted_count"] == 0
    assert roots[1].status()["accepted_count"] == 3
    with roots[0]._transaction() as connection:
        assert connection.execute("SELECT state FROM attempts").fetchone()[0] == "failed"


def test_bf_pool_stop_drains_started_attempts_and_closes_source(bf_writers):
    parent, roots, cells = bf_writers
    pilots(roots)
    stop = threading.Event()
    backend = RoutedBackend(roots, overlap=True, stop=stop)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=20,
                                 chunk_sessions=1, stop=stop, backend=backend)
    assert result["stop_requested"] is True
    assert backend.closed and len(backend.calls) == len(backend.released) == 2
    assert all(store.status()["accepted_count"] == 1 for store in roots)
    assert all(handle is not None and not handle.active for handle in backend.source_handles)


def test_bf_pool_matching_own_pilot_is_required_per_root(bf_writers):
    parent, roots, cells = bf_writers
    with pytest.raises(ValueError, match="matching focused pilots"):
        study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
                            backend=RoutedBackend(roots))
    controlled_pilot(roots[0], HOSTS[0], MODE)
    backend = RoutedBackend(roots)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=1,
                                 backend=backend)
    assert result["missing_mode_pilots"] == [cells[1]]
    assert result["paused_cells"] == [cells[1]]
    assert len(backend.calls) == 1 and backend.calls[0][0] == roots[0].root


def test_bf_pool_stale_writer_and_live_reservation_do_not_capture(bf_writers):
    parent, roots, cells = bf_writers
    pilots(roots)
    wrong = deepcopy(cells)
    wrong[0]["root"], wrong[1]["root"] = wrong[1]["root"], wrong[0]["root"]
    with pytest.raises(ValueError, match="excluded|superseded|active epoch"):
        study.capture_roots(parent.root, native(), wrong, workers=2, budget=2,
                            backend=RoutedBackend(roots))
    held = roots[0].allocate_attempt(HOSTS[0], MODE)
    backend = RoutedBackend(roots)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
                                 chunk_sessions=1, backend=backend)
    assert any(row["hostname"] == HOSTS[0] for row in result["allocation_errors"])
    assert all(a["hostname"] != HOSTS[0] for _, _, a in backend.calls)
    roots[0].fail_attempt(held["attempt_id"], "controlled pending cleanup")


def test_bf_pool_exact_plan_type_full_runtime_and_no_pilot(bf_writers, tmp_path):
    parent, roots, cells = bf_writers
    plan = tmp_path / "pool.json"
    value = {"record_type": study.BF122_SHARED_CAPTURE_PLAN, "schema_version": 1,
             "parent": str(parent.root), "cells": cells}
    _create(plan, canonical_json(value))
    assert study.load_shared_capture_plan(plan, sha256_file(plan), parent.root) == cells
    with pytest.raises(ValueError):
        study.load_shared_capture_plan(plan, "0" * 64, parent.root)
    wrong = native(); wrong["source"]["lab_commit"] = "0" * 40
    with pytest.raises(ValueError, match="unchanged full runtime"):
        study.capture_roots(parent.root, wrong, cells, workers=2, budget=2)
    with pytest.raises(ValueError, match="continuation-only"):
        study.capture_roots(parent.root, native(), cells, workers=2, budget=2, pilot=True)
    repeated = deepcopy(cells); repeated[1]["hostname"] = repeated[0]["hostname"]
    with pytest.raises(ValueError, match="repeats"):
        study._shared_cells(repeated, buflo122=True)
    mixed = deepcopy(cells); mixed[0]["mode"] = "front"
    with pytest.raises(ValueError, match="BuFLO122 bindings"):
        study._shared_cells(mixed, buflo122=True)


def test_bf_pool_finite_namespace_and_original_cs_profile(tmp_path, monkeypatch):
    expected = tuple("/mnt/lima-neqo-data/neqo-obfuscation/study/"
                     "native122-source079-BuFLO-original50-runtime-cohort-" + f"{index:03d}"
                     for index in range(1, 6))
    assert runtime.BF122_SHARED_ROOTS == expected
    dirs = [tmp_path / str(i) for i in range(6)]
    for root in dirs:
        root.mkdir()
    with pytest.raises(ValueError, match="cohort001 through005"):
        runtime.shared_roots(dirs[:2], buflo122=True)
    monkeypatch.setattr(runtime, "BF122_SHARED_ROOTS", tuple(str(root) for root in dirs[:5]))
    for count in range(2, 6):
        assert runtime.shared_roots(dirs[:count], buflo122=True) == dirs[:count]
    for bad in (dirs[:1], dirs, [dirs[0], dirs[0]], [dirs[0], dirs[5]]):
        with pytest.raises(ValueError):
            runtime.shared_roots(bad, buflo122=True)
    old = deepcopy(runtime.SHARED_NATIVE)
    old["source"] = {"neqo_commit": old["native_commit"]}
    assert runtime.require_shared_runtime(old) is None
    assert runtime.shared_roots(dirs[:2]) == dirs[:2]
    legacy_cells = [{"root": str(root), "hostname": host, "mode": "cs-buflo"}
                    for root, host in zip(dirs, HOSTS)]
    assert study._shared_cells(legacy_cells)[0] == dirs[:2]
