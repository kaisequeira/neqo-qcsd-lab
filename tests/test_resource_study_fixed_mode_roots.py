"""Connected F/T coordinator regression Source; ROOT alone executes.

Real disposable admission, writer/head, matching ownpilot, global shared400,
reservation, seal/inventory/commit and Source-handle paths remain connected.
Preparation and Raw/Docker are the same explicit synthetic leaves used by the
existing multi-root tests. No physical HTTP, pcap, timing or credit claim.
"""
from copy import deepcopy
import json
import threading

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_network as network
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore, _create
from tests.test_resource_study import CaptureBackend
from tests.test_resource_study_epochs import controlled_pilot
from tests.test_resource_study_lineage import campaign, admit, rewrite
from tests.test_resource_study_multiroot_capture import raw_leaf, shared_docker


def fixed_runtime():
    return deepcopy(runtime.FIXED142_SHARED_RUNTIME)


@pytest.fixture
def fixed_writers(campaign, tmp_path, monkeypatch, request):
    parent, child, _ = campaign
    old = child("prior-fixed-FT")
    admit(parent, old)
    for module in (epochs, cohorts, study):
        monkeypatch.setattr(module, "verify_receipt", raw_leaf)
    cellspec = [(lineage.INCLUDED, "front"), ("alpha.example", "tamaraw")]
    if getattr(request, "param", False):
        cellspec = [(lineage.INCLUDED, "front"), (lineage.INCLUDED, "tamaraw"),
                    ("alpha.example", "front")]
    roots, cells = [], []
    for index, (host, mode) in enumerate(cellspec):
        store = StudyStore(tmp_path / ("fixed142-%d" % index))
        cohorts.initialize_cohort(parent.root, store.root)
        donor = old if host == lineage.INCLUDED else parent
        value = deepcopy(epochs._enrollments(donor)[host][0])
        _create(store.root / value["workload_path"], donor._file(value["workload_path"])[0])
        value["runtime"] = fixed_runtime()
        value["source_occurrences"] = study.candidate_pool(store.root)[host]["source_occurrences"]
        store.enroll(lineage.bind_enrollment(store, value))
        declaration = cohorts.compatibility_template(parent.root, store.root,
            affected_hostnames=[host], affected_modes=[mode])
        declaration.update(compatible_treatment=True,
            rationale="Synthetic F/T multi-root routing fixture; no live qualification.")
        path = tmp_path / ("fixed-declaration-%d.json" % index)
        _create(path, canonical_json(declaration))
        cohorts.create_cohort(parent.root, store.root, path, sha256_file(path))
        roots.append(store)
        cells.append({"root": str(store.root), "hostname": host, "mode": mode})
    return parent, roots, cells


def fixed_pilots(roots, cells):
    for store, cell in zip(roots, cells):
        controlled_pilot(store, cell["hostname"], cell["mode"])


class FixedRoutedBackend:
    """Synthetic packets, real per-mode owning-root durable reservations."""
    def __init__(self, roots, cells, *, fail=None, overlap=False, stop=None, repeat_tuple=False):
        self.stores = {(cell["hostname"], cell["mode"]): store
                       for store, cell in zip(roots, cells)}
        self.fail, self.stop = fail, stop
        self.repeat_tuple = repeat_tuple
        self.cell_ports = {key: 44000 + 1000 * index for index, key in enumerate(self.stores)}
        self.calls, self.source_handles, self.released = [], [], []
        self.active = set()
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(2) if overlap else None
        self.entered = self.closed = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *_):
        self.closed = True

    def release(self, index):
        self.released.append(index)

    def capture(self, index, attempt, enrollment):
        key = attempt["hostname"], attempt["mode"]
        store = self.stores[key]
        with store._transaction() as connection:
            row = connection.execute("SELECT hostname,mode,slot,state FROM attempts WHERE attempt_id=?",
                (attempt["attempt_id"],)).fetchone()
        assert tuple(row) == (*key, attempt["slot"], "reserved")
        assert epochs._enrollments(store)[key[0]][0] == enrollment
        with self.lock:
            assert key[0] not in self.active
            self.active.add(key[0])
            self.calls.append((store.root, index, deepcopy(attempt)))
            number = len(self.calls)
            self.source_handles.append(cohorts._SOURCE_OPERATION.get())
        try:
            if self.barrier is not None and number <= 2:
                self.barrier.wait(timeout=10)
            if key == self.fail:
                return {"success": False, "failure": "controlled selected-cell negative"}
            # Tuple identity belongs to the logical cell, not thread order.
            port = self.cell_ports[key] + (1 if self.repeat_tuple else attempt["slot"])
            CaptureBackend(store.root).write_capture(attempt, enrollment, port)
            directory = store.root / attempt["path"] / "capture"
            run = json.loads((directory / "neqo/run.json").read_bytes())
            ip = store.plan()["class_network"]["assignments"][key[0]]["client_ipv4"]
            run["endpoints"] = [{"id": 0, "local_address": f"{ip}:{port}",
                                 "remote_address": "8.8.8.8:443"}]
            rewrite(directory / "neqo/run.json", run)
            (directory / "class-network.json").write_bytes(canonical_json(
                network.receipt_binding(store.plan(), sha256_file(store.root / "study.json"), key[0])))
            (directory / "diagnostics/scheduler-runtime-evidence.json").write_bytes(canonical_json(
                {"fixture": "Raw leaf controlled; no physical scheduler claim"}))
            if self.stop is not None:
                self.stop.set()
            return {"success": True, "mode_policies": enrollment["mode_policies"][key[1]]}
        finally:
            with self.lock:
                self.active.remove(key[0])


def test_mixed_fixed_FT_connected_own_roots_source_and_formal_credit(fixed_writers):
    parent, roots, cells = fixed_writers
    fixed_pilots(roots, cells)
    backend = FixedRoutedBackend(roots, cells, overlap=True)
    result = study.capture_fixed_mode_roots(parent.root, fixed_runtime(), cells,
        workers=2, budget=2, chunk_sessions=1, backend=backend)
    assert result["record_type"] == "qcsd-resource-domain-fixed142-F-T-pool-capture-result-v1"
    assert backend.entered and backend.closed and len(backend.calls) == 2
    assert len({index for _, index, _ in backend.calls}) == 2
    assert not result["paused_cells"]
    for store, cell in zip(roots, cells):
        assert cohorts.accepted_count(store, cell["hostname"], cell["mode"]) == 1
        with store._transaction() as connection:
            row = connection.execute("SELECT receipt_path FROM accepted").fetchone()
        receipt = study.load(store.root / row[0])
        assert (receipt["hostname"], receipt["mode"]) == (cell["hostname"], cell["mode"])
        assert receipt["runtime"] == fixed_runtime()
        assert receipt["study_sha256"] == sha256_file(store.root / "study.json")
        assert receipt["coordinator_provenance"] == study.coordinator_provenance(class_selection=True)
    assert all(handle is not None and handle.active is False for handle in backend.source_handles)
    assert cohorts._SOURCE_OPERATION.get() is None and not backend.active


@pytest.mark.parametrize("fixed_writers", [True], indirect=True)
@pytest.mark.parametrize("chunk_sessions", [1, 20])
def test_same_hostname_modes_use_distinct_roots_without_parallel_hostname(fixed_writers, chunk_sessions):
    parent, roots, cells = fixed_writers
    fixed_pilots(roots, cells)
    backend = FixedRoutedBackend(roots, cells, overlap=True)
    result = study.capture_fixed_mode_roots(parent.root, fixed_runtime(), cells,
        workers=3, budget=3, chunk_sessions=chunk_sessions, backend=backend)
    assert len(backend.calls) == 3 and not result["paused_cells"]
    assert {(str(root), attempt["hostname"], attempt["mode"])for root, _, attempt in backend.calls} == {
        (cell["root"], cell["hostname"], cell["mode"])for cell in cells}
    assert all(store.status()["accepted_count"] == 1 for store in roots)


def test_fixed_FT_failure_and_missing_pilot_are_independent(fixed_writers):
    parent, roots, cells = fixed_writers
    controlled_pilot(roots[1], cells[1]["hostname"], cells[1]["mode"])
    backend = FixedRoutedBackend(roots, cells)
    result = study.capture_fixed_mode_roots(parent.root, fixed_runtime(), cells,
        workers=2, budget=1, backend=backend)
    assert result["paused_cells"] == [cells[0]]
    assert len(backend.calls) == 1 and backend.calls[0][0] == roots[1].root
    controlled_pilot(roots[0], cells[0]["hostname"], cells[0]["mode"])
    negative = FixedRoutedBackend(roots, cells,
        fail=(cells[0]["hostname"], cells[0]["mode"]), overlap=True)
    result = study.capture_fixed_mode_roots(parent.root, fixed_runtime(), cells,
        workers=2, budget=2, chunk_sessions=1, backend=negative)
    assert result["paused_cells"] == [cells[0]] and roots[0].status()["accepted_count"] == 0
    assert roots[1].status()["accepted_count"] == 2
    with roots[0]._transaction() as connection:
        assert connection.execute("SELECT state FROM attempts").fetchone()[0] == "failed"


def test_fixed_FT_original_shared400_includes_existing_credit(fixed_writers, monkeypatch):
    parent, roots, cells = fixed_writers
    fixed_pilots(roots, cells)
    # The fixture is already one admitted writer with zero old credit. One
    # genuine controlled commit must be visible to the original shared counts.
    first = FixedRoutedBackend(roots, cells)
    study.capture_fixed_mode_roots(parent.root, fixed_runtime(), cells,
        workers=2, budget=2, chunk_sessions=1, backend=first)
    counts = cohorts.counts_snapshot(roots[0], [(cells[0]["hostname"], cells[0]["mode"])], latest_only=True)
    assert counts == {(cells[0]["hostname"], cells[0]["mode"]): 1}
    assert {attempt["slot"]for _, _, attempt in first.calls} == {1}
    second = FixedRoutedBackend(roots, cells, repeat_tuple=True)
    study.capture_fixed_mode_roots(parent.root, fixed_runtime(), cells,
        workers=2, budget=2, chunk_sessions=1, backend=second)
    assert {attempt["slot"]for _, _, attempt in second.calls} == {2}
    # Repeated five tuples cannot earn a second distinct connection credit.
    assert all(store.status()["accepted_count"] == 1 for store in roots)
    assert any((store.root / "failures" / cell["hostname"] / cell["mode"]).is_dir()
               for store, cell in zip(roots, cells))


@pytest.mark.parametrize("field", ["canonical_sha256", "client_sha256", "platform", "native_commit",
                                   "collection_image_digest", "prepare_image_digest", "source"])
def test_fixed_full7_mutations_refuse_before_source(field, monkeypatch):
    value = fixed_runtime()
    value[field] = {} if field == "source" else "changed"
    monkeypatch.setattr(cohorts, "source_operation", lambda *_: pytest.fail("runtime mutation reached Source"))
    with pytest.raises(ValueError, match="exact existing Native142"):
        study.capture_fixed_mode_roots(study.Path("/absent"), value, [], workers=2, budget=1)


def test_fixed_plan_modes_duplicate_cells_and_old_runtime_refuse(fixed_writers, tmp_path):
    parent, roots, cells = fixed_writers
    for mode in ("buflo", "cs-buflo", "undefended"):
        wrong = deepcopy(cells)
        wrong[0]["mode"] = mode
        with pytest.raises(ValueError):
            study._shared_cells(wrong, fixed_modes=True)
    with pytest.raises(ValueError, match="repeats"):
        study._shared_cells([cells[0], cells[0], cells[1]], fixed_modes=True)
    value = {"record_type": study.FIXED142_SHARED_CAPTURE_PLAN, "schema_version": 1,
             "parent": str(parent.root), "cells": cells}
    path = tmp_path / "fixed-plan.json"
    _create(path, canonical_json(value))
    assert study.load_fixed_mode_capture_plan(path, sha256_file(path), parent.root) == cells
    with pytest.raises(ValueError):
        study.load_fixed_mode_capture_plan(path, "0" * 64, parent.root)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="immutable"):
        study.load_fixed_mode_capture_plan(path, sha256_file(path), parent.root)
    with pytest.raises(ValueError):
        runtime.require_shared_runtime(fixed_runtime())


def test_fixed_runtime_mode_router_and_jobs_preserve_same_host_owning_root(shared_docker, monkeypatch):
    contexts, _, docker, events = shared_docker
    roots = list(contexts)
    host = "alpha.example"
    cells = {(host, "front"): roots[0], (host, "tamaraw"): roots[1]}
    urls = [f"https://{host}/r?i={i}"for i in range(20)]
    values = {root:{"hostname": host, "runtime": fixed_runtime(), "urls": urls,
        "workload_sha256": "a" * 64, "mode_readiness": {mode: True},
        "mode_policies": {mode: {}}, "preparation_dir": "prepared/" + mode}
        for (_, mode), root in cells.items()}
    monkeypatch.setattr(StudyStore, "enrolled", lambda store: [deepcopy(values[store.root])])
    from tests import test_resource_study_runtime as docker_fixture
    monkeypatch.setattr(docker_fixture, "IMAGE", fixed_runtime()["collection_image_digest"])
    with runtime.MultiRootCaptureRuntime(contexts, fixed_runtime(), 2,
            cell_roots=cells, fixed_modes=True) as engine:
        assert len(engine.class_routes) == 1
        assert engine.flight_binding()["record_type"] == "qcsd-resource-domain-fixed142-F-T-shared-flight-v1"
        for number, ((name, mode), root) in enumerate(cells.items()):
            attempt = {"hostname": name, "mode": mode, "path": "attempts/" + mode,
                       "attempt_id": "%032x" % (number + 1)}
            (root / attempt["path"] / "capture").mkdir(parents=True)
            engine.capture(0, attempt, values[root])
            job = study.load(root / attempt["path"] / "job.json")
            assert job["enrollment_dir"] == str(root / values[root]["preparation_dir"])
            assert job["attempt_dir"] == str(root / attempt["path"] / "capture")
            attachment = study.load(root / attempt["path"] / "capture/class-network.json")
            assert attachment["binding"] == network.receipt_binding(contexts[root]["plan"],
                contexts[root]["study_sha256"], name)
            engine.release(0)
    assert events == ["enter", "exit"] and not docker.containers and not docker.networks


@pytest.mark.parametrize("field", ["lab_dirty", "neqo_dirty"])
def test_fixed_runtime_rejects_integer_alias_of_clean_false(field):
    value = fixed_runtime()
    value["source"][field] = 0
    assert value == fixed_runtime()  # Demonstrates why ordinary dict equality is insufficient.
    with pytest.raises(ValueError, match="exact existing Native142"):
        runtime.require_fixed_mode_runtime(value)
