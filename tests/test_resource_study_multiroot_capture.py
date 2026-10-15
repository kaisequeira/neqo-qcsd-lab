"""Focused two-root launcher controls; no physical Native/capture qualification.

Disposable ledgers use the real admission, reservation, state, seal, inventory,
commit, global quota and write-fence paths. Preparation/raw proof leaves and
Docker are explicit synthetic boundaries. Fixture fsync is omitted and the
fixture Docker lifecycle lock is replaced: these tests claim no durability,
live fidelity, old-data requalification or production rollout readiness.
ROOT alone executes these tests after Source019 pins and peer review stop.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import threading

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_network as network
from qcsd_lab import resource_study_reader_compatibility as compatibility
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore, _create
from tests import test_resource_study_runtime as docker_fixture
from tests.test_resource_study import CaptureBackend
from tests.test_resource_study_epochs import controlled_pilot
from tests.test_resource_study_lineage import campaign, admit, rewrite, controlled_credit


MODE = "cs-buflo"
HOSTS = (lineage.INCLUDED, "alpha.example")


def native():
    value = deepcopy(runtime.SHARED_NATIVE)
    value["source"] = {"neqo_commit": value["native_commit"]}
    return value


def raw_leaf(root, receipt):
    return {"verified": True, "five_tuple": receipt.get("five_tuple")}


@pytest.fixture
def writers(campaign, tmp_path, monkeypatch, request):
    parent, child, _ = campaign
    old = child("prior-native")
    admit(parent, old)
    monkeypatch.setattr(epochs, "verify_receipt", raw_leaf)
    monkeypatch.setattr(cohorts, "verify_receipt", raw_leaf)
    monkeypatch.setattr(study, "verify_receipt", raw_leaf)
    if getattr(request, "param", False):
        controlled_pilot(old, HOSTS[0], MODE)
        attempt = old.allocate_attempt(HOSTS[0], MODE)
        path = controlled_credit(old, attempt, commit=False)
        receipt = study.load(path)
        receipt["coordinator_provenance"] = study.coordinator_provenance(class_selection=True)
        rewrite(path, receipt)
        old.commit_verified(path, validator=raw_leaf)
    roots = []
    for index, host in enumerate(HOSTS):
        store = StudyStore(tmp_path / ("native93-%d" % index))
        cohorts.initialize_cohort(parent.root, store.root)
        donor = old if host == lineage.INCLUDED else parent
        value = deepcopy(epochs._enrollments(donor)[host][0])
        _create(store.root / value["workload_path"], donor._file(value["workload_path"])[0])
        value["runtime"] = native()
        value["source_occurrences"] = study.candidate_pool(store.root)[host]["source_occurrences"]
        store.enroll(lineage.bind_enrollment(store, value))
        declaration = cohorts.compatibility_template(parent.root, store.root,
            affected_hostnames=[host], affected_modes=[MODE])
        declaration.update(compatible_treatment=True,
            rationale="Synthetic launcher routing fixture; not live runtime qualification.")
        path = tmp_path / ("declaration-%d.json" % index)
        _create(path, canonical_json(declaration))
        cohorts.create_cohort(parent.root, store.root, path, sha256_file(path))
        roots.append(store)
    cells = [{"root": str(store.root), "hostname": host, "mode": MODE}
             for store, host in zip(roots, HOSTS)]
    return parent, roots, cells


def pilots(roots):
    for store, host in zip(roots, HOSTS):
        controlled_pilot(store, host, MODE)


class RoutedBackend:
    """Synthetic packet leaf, with real durable owning-root reservations."""
    def __init__(self, roots, *, fail=None, overlap=False, stop=None, ports=None):
        self.by_host = dict(zip(HOSTS, roots))
        self.fail, self.stop = fail, stop
        self.calls, self.released = [], []
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(2) if overlap else None
        self.entered = self.closed = False
        self.source_handles = []
        self.ports = ports or {}

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *_):
        self.closed = True

    def release(self, index):
        self.released.append(index)

    def capture(self, index, attempt, enrollment):
        store = self.by_host[attempt["hostname"]]
        with store._transaction() as connection:
            row = connection.execute("SELECT hostname,mode,slot,state FROM attempts WHERE attempt_id=?",
                (attempt["attempt_id"],)).fetchone()
        assert tuple(row) == (attempt["hostname"], MODE, attempt["slot"], "reserved")
        assert epochs._enrollments(store)[attempt["hostname"]][0] == enrollment
        with self.lock:
            self.calls.append((store.root, index, deepcopy(attempt)))
            number = len(self.calls)
            self.source_handles.append(cohorts._SOURCE_OPERATION.get())
        if self.barrier is not None and number <= 2:
            self.barrier.wait(timeout=10)
        if attempt["hostname"] == self.fail:
            return {"success": False, "failure": "controlled one-root rejection"}
        # Original seal still moves/freezes/inventories these synthetic files,
        # validates enrollment, and calls the explicitly controlled raw leaf.
        port = self.ports.get(attempt["hostname"], 42000 + number)
        CaptureBackend(store.root).write_capture(attempt, enrollment, port)
        directory = store.root / attempt["path"] / "capture"
        run = json.loads((directory / "neqo/run.json").read_bytes())
        ip = store.plan()["class_network"]["assignments"][attempt["hostname"]]["client_ipv4"]
        run["endpoints"] = [{"id": 0, "local_address": f"{ip}:{port}",
                             "remote_address": "8.8.8.8:443"}]
        rewrite(directory / "neqo/run.json", run)
        (directory / "class-network.json").write_bytes(canonical_json(
            network.receipt_binding(store.plan(), sha256_file(store.root / "study.json"), attempt["hostname"])))
        (directory / "diagnostics/scheduler-runtime-evidence.json").write_bytes(canonical_json(
            {"fixture": "raw proof leaf controlled; no physical scheduler claim"}))
        if self.stop is not None:
            self.stop.set()
        return {"success": True, "mode_policies": enrollment["mode_policies"][MODE]}


def test_two_root_formal_routes_real_reserve_seal_credit_and_source_scope(writers):
    parent, roots, cells = writers
    pilots(roots)
    backend = RoutedBackend(roots, overlap=True)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
        chunk_sessions=1, backend=backend)
    assert backend.entered and backend.closed and len(backend.calls) == 2
    assert len(set(index for _, index, _ in backend.calls)) == 2
    assert {root for root, _, _ in backend.calls} == {store.root for store in roots}
    assert len(backend.released) == 2 and not result["paused_cells"]
    assert all(store.status()["accepted_count"] == 1 for store in roots)
    assert all(handle is not None and handle.active is False for handle in backend.source_handles)
    assert cohorts._SOURCE_OPERATION.get() is None
    for store, host in zip(roots, HOSTS):
        assert cohorts.accepted_count(store, host, MODE) == 1
        with store._transaction() as connection:
            row = connection.execute("SELECT receipt_path FROM accepted").fetchone()
        receipt = study.load(store.root / row[0])
        assert receipt["runtime"] == native() and receipt["hostname"] == host
        assert receipt["study_sha256"] == sha256_file(store.root / "study.json")
        assert receipt["coordinator_provenance"] == study.coordinator_provenance(class_selection=True)


def test_pilots_are_own_root_and_zero_credit(writers):
    parent, roots, cells = writers
    backend = RoutedBackend(roots)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
        pilot=True, backend=backend)
    assert len(result["pilot_cells_passed"]) == 2
    assert all(store.status()["accepted_count"] == 0 for store in roots)
    assert all((store.root / "pilots" / host / MODE).is_dir() for store, host in zip(roots, HOSTS))
    assert all(study._shared_pilot(store.root, epochs._enrollments(store)[host][0], native(), MODE)
               for store, host in zip(roots, HOSTS))


def test_missing_pilot_pauses_only_owning_cell(writers):
    parent, roots, cells = writers
    controlled_pilot(roots[0], HOSTS[0], MODE)
    backend = RoutedBackend(roots)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=1, backend=backend)
    assert [row["hostname"] for row in result["paused_cells"]] == [HOSTS[1]]
    assert len(backend.calls) == 1 and backend.calls[0][0] == roots[0].root
    assert roots[0].status()["accepted_count"] == 1 and roots[1].status()["accepted_count"] == 0


def test_one_root_failure_preserves_attempt_and_other_root_credit(writers):
    parent, roots, cells = writers
    pilots(roots)
    backend = RoutedBackend(roots, fail=HOSTS[0], overlap=True)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
        chunk_sessions=1, backend=backend)
    assert backend.closed and len(backend.released) == 2
    assert result["paused_cells"] == [cells[0]]
    assert roots[0].status()["accepted_count"] == 0 and roots[1].status()["accepted_count"] == 1
    with roots[0]._transaction() as connection:
        row = connection.execute("SELECT state FROM attempts").fetchone()
    assert row[0] == "failed"


def test_live_pending_and_stale_writer_still_refuse(writers):
    parent, roots, cells = writers
    pilots(roots)
    held = roots[0].allocate_attempt(HOSTS[0], MODE)
    backend = RoutedBackend(roots)
    result = study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
        chunk_sessions=1, backend=backend)
    assert any(row["hostname"] == HOSTS[0] for row in result["allocation_errors"])
    assert all(call[2]["hostname"] != HOSTS[0] for call in backend.calls)
    roots[0].fail_attempt(held["attempt_id"], "controlled pending cleanup")
    wrong = deepcopy(cells)
    wrong[0]["root"], wrong[1]["root"] = wrong[1]["root"], wrong[0]["root"]
    with pytest.raises(ValueError, match="excluded|superseded|active epoch"):
        study.capture_roots(parent.root, native(), wrong, workers=2, budget=2, pilot=True,
            backend=RoutedBackend(roots))


@pytest.mark.parametrize("writers", [True], indirect=True)
def test_retained_global_credit_sets_next_slot_and_duplicate_tuple_cannot_recredit(writers):
    parent, roots, cells = writers
    pilots(roots)
    assert roots[0].status()["accepted_count"] == 0  # Old credit stays in its original root.
    assert cohorts.accepted_count(roots[0], HOSTS[0], MODE) == 1
    first = RoutedBackend(roots)
    study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
        chunk_sessions=1, backend=first)
    assert next(attempt["slot"] for _, _, attempt in first.calls if attempt["hostname"] == HOSTS[0]) == 2
    assert roots[0].status()["accepted_count"] == 1  # One actual new controlled commit.
    assert cohorts.accepted_count(roots[0], HOSTS[0], MODE) == 2  # Old + new, without relabelling.
    second = RoutedBackend(roots, ports={HOSTS[0]: 31000, HOSTS[1]: 43000})
    study.capture_roots(parent.root, native(), cells, workers=2, budget=2,
        chunk_sessions=1, backend=second)
    assert roots[0].status()["accepted_count"] == 1
    assert cohorts.accepted_count(roots[0], HOSTS[0], MODE) == 2
    with roots[0]._transaction() as connection:
        states = [row[0] for row in connection.execute("SELECT state FROM attempts ORDER BY created_at")]
    assert states.count("duplicate") == 1
    assert any((roots[0].root / "failures" / HOSTS[0] / MODE).iterdir())


@pytest.mark.parametrize("workers,budget,chunk,pilot", [
    (1, 2, 1, True), (12, 2, 1, True), (True, 2, 1, True),
    (2, None, 1, True), (2, 0, 1, True), (2, 1901, 1, True),
    (2, True, 1, True), (2, 2, 0, True), (2, 2, 21, True), (2, 2, 1, 1)])
def test_bounded_arguments_refuse_before_source_or_backend(monkeypatch, workers, budget, chunk, pilot):
    def no_source(*args):
        raise AssertionError("invalid bounds reached Source construction")
    monkeypatch.setattr(cohorts, "source_operation", no_source)
    with pytest.raises(ValueError):
        study.capture_roots(Path("/absent"), native(), [], workers=workers, budget=budget,
            chunk_sessions=chunk, pilot=pilot)


def test_foreign_native_and_mode_and_repeated_logical_cell_refuse(writers):
    parent, roots, cells = writers
    wrong_native = native(); wrong_native["client_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="Native93"):
        study.capture_roots(parent.root, wrong_native, cells, workers=2, budget=2, pilot=True)
    changed = deepcopy(cells)
    changed[0]["mode"] = "front"
    with pytest.raises(ValueError, match="CS bindings"):
        study._shared_cells(changed)
    repeated = deepcopy(cells); repeated[1]["hostname"] = repeated[0]["hostname"]
    with pytest.raises(ValueError, match="repeats"):
        study._shared_cells(repeated)


def test_shared_plan_is_immutable_exact_parent_and_cells(writers, tmp_path):
    parent, roots, cells = writers
    path = tmp_path / "shared-plan.json"
    value = {"record_type": study.SHARED_CAPTURE_PLAN, "schema_version": 1,
             "parent": str(parent.root), "cells": cells}
    _create(path, canonical_json(value))
    assert study.load_shared_capture_plan(path, sha256_file(path), parent.root) == cells
    with pytest.raises(ValueError):
        study.load_shared_capture_plan(path, "0" * 64, parent.root)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="immutable"):
        study.load_shared_capture_plan(path, sha256_file(path), parent.root)


def test_public_capture_roots_cli_routes_explicit_plan_and_restores_signals(writers, tmp_path, monkeypatch):
    parent, roots, cells = writers
    path = tmp_path / "public-shared-plan.json"
    _create(path, canonical_json({"record_type": study.SHARED_CAPTURE_PLAN, "schema_version": 1,
        "parent": str(parent.root), "cells": cells}))
    import signal
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    seen = []
    def capture(actual_parent, actual_runtime, actual_cells, **kwargs):
        seen.append((actual_parent, actual_runtime, actual_cells, kwargs))
        return {"paused_cells": []}
    monkeypatch.setattr(study, "runtime_identity", lambda path: native())
    monkeypatch.setattr(study, "capture_roots", capture)
    assert study.main(["capture-roots", "--root", str(parent.root), "--runtime", str(tmp_path / "canonical.json"),
        "--cells", str(path), "--cells-sha256", sha256_file(path), "--workers", "11", "--attempts", "22", "--pilot"]) == 0
    assert seen[0][:3] == (parent.root, native(), cells)
    assert seen[0][3]["workers"] == 11 and seen[0][3]["budget"] == 22 and seen[0][3]["pilot"] is True
    assert all(signal.getsignal(sig) == previous[sig] for sig in previous)


@pytest.fixture
def shared_docker(tmp_path, monkeypatch):
    first, second = tmp_path / "first", tmp_path / "second"
    names = ["alpha.example", "beta.example", *(f"other-{i}.example" for i in range(48))]
    plan = {"acceptance": network.ACCEPTANCE, "tuple_uniqueness_scope": network.TUPLE_SCOPE,
            "class_network": network.build_network_plan(names)}
    for index, root in enumerate((first, second)):
        root.mkdir(); _create(root / "study.json", canonical_json({**plan, "created_at": str(index)}))
    contexts = {root: {"plan": study.load(root / "study.json"), "study_sha256": sha256_file(root / "study.json")}
                for root in (first, second)}
    events = []
    @contextmanager
    def lock():
        events.append("enter")
        try:
            yield
        finally:
            events.append("exit")
    monkeypatch.setattr(runtime, "docker_lock", lock)
    monkeypatch.setattr(runtime.os, "fsync", lambda _: None)
    monkeypatch.setattr(runtime, "_host_routes", lambda: [])
    monkeypatch.setattr(runtime, "public_ipv4", lambda host: {
        "hostname": host, "addresses": ["8.8.8.8"], "selected_ipv4": "8.8.8.8"})
    monkeypatch.setattr(docker_fixture, "IMAGE", native()["collection_image_digest"])
    docker = docker_fixture.Docker(ncpu=24, image_arch="arm64", architecture="aarch64")
    monkeypatch.setattr(runtime, "_docker", docker)
    return contexts, {"alpha.example": first, "beta.example": second}, docker, events


def test_shared_topology_has_one_lock_union_mounts_and_both_closures(shared_docker):
    contexts, cell_roots, docker, events = shared_docker
    with runtime.MultiRootCaptureRuntime(contexts, native(), 11, cell_roots=cell_roots) as engine:
        assert len(engine.workers) == 11 and len(engine.class_routes) == 2
        launched = [study.load(path / "launched.json") for path in engine.flights.values()]
        assert launched[0]["shared_flight"] == launched[1]["shared_flight"]
        for args in docker.calls:
            if args[0] == "create" and "org.qcsd.role=resource-study-worker" in args:
                mounts = docker_fixture.options(args, "--mount")
                assert all(f"type=bind,src={root},dst={root}" in mounts for root in contexts)
        attachment = engine._activate(0, "beta.example")
        owner = cell_roots["beta.example"]
        assert attachment["binding"] == network.receipt_binding(contexts[owner]["plan"],
            contexts[owner]["study_sha256"], "beta.example")
        engine.release(0)
    assert events == ["enter", "exit"] and not docker.containers and not docker.networks
    for root, flight in engine.flights.items():
        closed = study.load(flight / "closed.json")
        assert closed["cleanup_errors"] == [] and closed["study_sha256"] == contexts[root]["study_sha256"]
    removed = [args[-1] for args in docker.calls if args[0] == "rm"]
    assert len(removed) == len(set(removed)) == 13


def test_shared_native_job_and_attachment_use_own_root(shared_docker):
    contexts, cell_roots, docker, events = shared_docker
    root = cell_roots["beta.example"]
    with runtime.MultiRootCaptureRuntime(contexts, native(), 2, cell_roots=cell_roots) as engine:
        attempt = {"hostname": "beta.example", "mode": MODE, "path": "attempts/unit",
                   "attempt_id": "0123456789abcdef" * 2}
        (root / attempt["path"] / "capture").mkdir(parents=True)
        engine.capture(0, attempt, {"preparation_dir": "prepared/beta"})
        job = study.load(root / attempt["path"] / "job.json")
        assert job["enrollment_dir"] == str(root / "prepared/beta")
        assert job["attempt_dir"] == str(root / attempt["path"] / "capture")
        assert job["seed"] == int(attempt["attempt_id"][:16], 16)
        capture_call = next(args for args in docker.calls if "_capture" in args)
        assert str(root / attempt["path"] / "job.json") in capture_call
        assert engine.root == next(iter(contexts))


def test_partial_launch_failure_cleans_once_and_closes_each_created_root(shared_docker):
    contexts, cell_roots, docker, events = shared_docker
    docker.fail = lambda args: args[0] == "create" and "org.qcsd.role=resource-study-worker" in args
    engine = runtime.MultiRootCaptureRuntime(contexts, native(), 2, cell_roots=cell_roots)
    with pytest.raises(RuntimeError, match="injected"):
        engine.__enter__()
    assert events == ["enter", "exit"] and not docker.containers and not docker.networks
    assert len(engine.flights) == 2
    assert all(study.load(path / "closed.json")["cleanup_errors"] == [] for path in engine.flights.values())
    engine.__exit__(None, None, None)
    assert events == ["enter", "exit"]


def test_closure_publication_failure_is_not_success_and_unlocks(shared_docker, monkeypatch):
    contexts, cell_roots, docker, events = shared_docker
    engine = runtime.MultiRootCaptureRuntime(contexts, native(), 2, cell_roots=cell_roots)
    original = runtime._put
    def put(path, value):
        if path.name == "closed.json" and path.parent.parent.parent == cell_roots["beta.example"]:
            raise OSError("controlled second-root closure failure")
        return original(path, value)
    monkeypatch.setattr(runtime, "_put", put)
    with pytest.raises(RuntimeError, match="closure metadata"):
        with engine:
            pass
    assert events == ["enter", "exit"] and not docker.containers and not docker.networks
    assert not (engine.flights[cell_roots["beta.example"]] / "closed.json").exists()


def test_changed_owner_study_refuses_before_native_job_and_restores_anchor(shared_docker):
    contexts, cell_roots, docker, events = shared_docker
    owner = cell_roots["beta.example"]
    with runtime.MultiRootCaptureRuntime(contexts, native(), 2, cell_roots=cell_roots) as engine:
        before = owner / "study.json"
        rewrite(before, {**study.load(before), "unexpected": True})
        with pytest.raises(ValueError, match="plan changed"):
            engine._activate(0, "beta.example")
        assert engine.root == next(iter(contexts))
        assert not any("_capture" in args for args in docker.calls)


def test_017_018_019_reader_profiles_remain_distinct_and_exact():
    old = compatibility.legacy_contract()
    prior = compatibility.prior_execution_contract()
    assert prior["transitive_source_sha256"] == "c709e8fd516a2d54778aeb053230987c742bd7cb13e086629ff42a2bf4b9d0cc"
    assert hashlib.sha256(canonical_json(prior)).hexdigest() == "1fb5169a34545c61cad3bfd493a1ea3365c8e8f1678b0678619cf0901607bbde"
    actual = cohorts.verifier_contract()
    qualified = compatibility.qualify_execution(actual)
    assert len({canonical_json(value) for value in (old, prior, actual)}) == 3
    for admission in (old, prior, actual):
        binding = compatibility.execution_binding(admission, qualified)
        assert binding["admission_reader"] == admission and binding["execution_reader"] == actual
        assert binding["historical_receipts_requalified_by_compatibility"] is False
        assert binding["authority_issued"] is False and binding["scientific_credit_added"] == 0
    for profile in (old, prior):
        with pytest.raises(ValueError, match="Source020 execution"):
            compatibility.qualify_execution(profile)
    changed = deepcopy(prior); changed["files"]["fidelity.py"] = "0" * 64
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(changed, qualified)
    assert all(actual["files"][name] == old["files"][name] for name in compatibility.PRIMARY_FILES)
