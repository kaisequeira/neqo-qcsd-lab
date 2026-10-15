"""Source027 executor ownership and isolation, without Docker or capture claims.

HOST cases control only process-affinity/procfs observations and pool lifecycle;
they never allocate an attempt, query SQL, launch Native or issue credit. The
Linux-only subprocess case changes only its own affinity and observes actual
new-thread inheritance, then restores the original mask.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_runtime as runtime


@pytest.fixture
def affinity(tmp_path, monkeypatch):
    class Observed:
        def __init__(self):
            self.pid = os.getpid()
            self.mask = set(range(24))
            self.tasks = [self.pid]
            self.task_masks = {}
            self.task_births = {}
            self.task_names = {}
            self.events = []
            self.records = {}
            self.backend = runtime.CaptureRuntime.__new__(runtime.CaptureRuntime)
            self.backend.count = 11
            self.backend.flight = tmp_path
            self.backend.coordinator_partition = (
                tuple(range(24)), tuple((i, i + 1) for i in range(1, 23, 2)), (0, 23))

        def set_mask(self, who, mask):
            assert who == 0
            self.events.append(("affinity", sorted(mask)))
            self.mask = set(mask)

        def put(self, path, value):
            self.events.append(("metadata", path.name))
            self.records[path] = value

        def thread(self, tid):
            if type(tid) is not int or tid <= 0:
                raise ValueError("coordinator task identity must be a positive native TID")
            if tid not in self.tasks:
                raise ProcessLookupError("controlled task has exited")
            return {"tid": tid, "name": self.task_names.get(tid, "controlled-task"),
                "start_ticks": self.task_births.get(tid, 100),
                "affinity": sorted(self.mask if tid == self.pid else self.task_masks.get(tid, {1}))}

    observed = Observed()
    monkeypatch.setattr(runtime.os, "sched_getaffinity", lambda who: set(observed.mask), raising=False)
    monkeypatch.setattr(runtime.os, "sched_setaffinity", observed.set_mask, raising=False)
    monkeypatch.setattr(runtime, "_coordinator_tasks", lambda: list(observed.tasks))
    monkeypatch.setattr(runtime, "_coordinator_thread", observed.thread)
    monkeypatch.setattr(runtime, "_put", observed.put)
    return observed


def test_actual_residual_partition_and_scope_metadata_restore_full_mask(affinity):
    a = affinity
    with a.backend.coordinator_affinity_scope():
        assert a.mask == {0, 23}
        started = a.records[a.backend.flight / "coordinator-affinity-started.json"]
        assert started["affinity_during"] == [0, 23]
        assert started["worker_cpu_pairs"] == [[i, i + 1] for i in range(1, 23, 2)]
        assert started["container_and_Native_affinity_changed"] is False
        assert started["scientific_credit"] is False
    assert a.mask == set(range(24))
    closed = a.records[a.backend.flight / "coordinator-affinity-closed.json"]
    assert closed["restored"] is True and closed["body_failed"] is False
    assert closed["remaining_thread_ids_before_restoration"] == [a.pid]
    assert closed["remaining_thread_ids_after_restoration"] == [a.pid]
    assert closed["pool_joined_before_restoration"] is True


def test_error_and_normal_stop_leave_the_original_mask(affinity):
    a = affinity
    failure = RuntimeError("controlled worker failure")
    with pytest.raises(RuntimeError) as raised:
        with a.backend.coordinator_affinity_scope():
            raise failure
    assert raised.value is failure and a.mask == set(range(24))
    assert a.records[a.backend.flight / "coordinator-affinity-closed.json"]["body_failed"] is True
    stop = threading.Event()
    with a.backend.coordinator_affinity_scope():
        stop.set()
        assert stop.is_set() and a.mask == {0, 23}
    assert a.mask == set(range(24))


def test_scope_start_metadata_failure_still_restores(affinity, monkeypatch):
    a = affinity
    original = a.put

    def refused(path, value):
        if path.name == "coordinator-affinity-started.json":
            raise OSError("controlled metadata write failure")
        original(path, value)

    monkeypatch.setattr(runtime, "_put", refused)
    with pytest.raises(OSError, match="metadata write"):
        with a.backend.coordinator_affinity_scope():
            pytest.fail("scope body must not start")
    assert a.mask == set(range(24))
    assert a.records[a.backend.flight / "coordinator-affinity-closed.json"]["body_failed"] is True


def test_shared_topology_records_the_same_actual_scope_in_each_owned_flight(affinity):
    a = affinity
    other = a.backend.flight / "second-owner"
    a.backend.flights = {"first": a.backend.flight, "second": other}
    with a.backend.coordinator_affinity_scope():
        assert a.records[a.backend.flight / "coordinator-affinity-started.json"] == (
            a.records[other / "coordinator-affinity-started.json"])
    assert a.records[a.backend.flight / "coordinator-affinity-closed.json"] == (
        a.records[other / "coordinator-affinity-closed.json"])


def test_scope_cannot_start_before_backend_partition_exists(affinity):
    a = affinity
    del a.backend.coordinator_partition
    with pytest.raises(AttributeError, match="coordinator_partition"):
        with a.backend.coordinator_affinity_scope():
            pytest.fail("scope cannot precede backend partition")
    assert a.events == []


@pytest.mark.parametrize("change", ["sibling", "missing_cpu", "overlap", "duplicate_pair", "boolean_cpu"])
def test_unmeasured_or_overlapping_scope_refuses_before_any_affinity_change(affinity, change):
    a = affinity
    available, pairs, auxiliary = a.backend.coordinator_partition
    if change == "sibling": a.tasks.append(a.pid + 1)
    elif change == "missing_cpu": a.mask.remove(23)
    elif change == "overlap": auxiliary = (0, 1, 23)
    elif change == "duplicate_pair": pairs = (pairs[0], pairs[0], *pairs[2:])
    else: pairs = ((True, 2), *pairs[1:])
    a.backend.coordinator_partition = available, pairs, auxiliary
    with pytest.raises(ValueError, match="coordinator"):
        with a.backend.coordinator_affinity_scope():
            pytest.fail("invalid scope body must not start")
    assert a.events == []


def test_existing_non_main_thread_cannot_own_scope(affinity):
    a = affinity
    errors = []

    def invoke():
        try:
            with a.backend.coordinator_affinity_scope():
                errors.append(AssertionError("worker owned the coordinator scope"))
        except ValueError as error:
            errors.append(error)

    thread = threading.Thread(target=invoke)
    thread.start(); thread.join()
    assert len(errors) == 1 and isinstance(errors[0], ValueError)
    assert a.events == []


def test_foreign_thread_on_protected_cpu_refuses_and_records_main_restoration(affinity):
    a = affinity
    with pytest.raises(ValueError, match="pool-thread closure"):
        with a.backend.coordinator_affinity_scope():
            a.tasks.append(a.pid + 1)
    assert a.mask == set(range(24))
    closed = a.records[a.backend.flight / "coordinator-affinity-closed.json"]
    assert closed["restored"] is True and closed["pool_joined_before_restoration"] is True
    assert closed["foreign_threads_confined_to_auxiliary"] is False
    assert closed["remaining_thread_ids_before_restoration"] == [a.pid, a.pid + 1]


def test_failed_exit_task_census_cannot_prevent_main_restoration(affinity, monkeypatch):
    a = affinity
    with pytest.raises(OSError, match="procfs unavailable"):
        with a.backend.coordinator_affinity_scope():
            def missing_tasks():
                raise OSError("procfs unavailable")
            monkeypatch.setattr(runtime, "_coordinator_tasks", missing_tasks)
    assert a.mask == set(range(24))
    assert a.backend.flight / "coordinator-affinity-closed.json" not in a.records


@pytest.mark.parametrize("body_error", [False, True])
def test_restore_failure_is_visible_and_preserves_the_original_error(affinity, monkeypatch, body_error):
    a = affinity
    original = a.set_mask
    failure = RuntimeError("controlled body failure")

    def cannot_restore(who, mask):
        if set(mask) == set(range(24)):
            raise OSError("controlled affinity restore failure")
        original(who, mask)

    monkeypatch.setattr(runtime.os, "sched_setaffinity", cannot_restore)
    with pytest.raises(RuntimeError if body_error else OSError) as raised:
        with a.backend.coordinator_affinity_scope():
            if body_error: raise failure
    if body_error:
        assert raised.value is failure
        assert any("restore failure" in note for note in failure.__notes__)
    else:
        assert "restore failure" in str(raised.value)


@pytest.mark.parametrize("failure_point", [None, "pool_init", "pool_enter", "body", "pool_join", "stop"])
def test_real_executor_wrapper_orders_backend_partition_scope_pool_join_and_restore(affinity, monkeypatch, failure_point):
    a = affinity

    class Backend:
        def __enter__(self):
            assert a.mask == set(range(24))
            a.events.append(("backend", "partition-and-start"))
            return self

        def __exit__(self, *error):
            assert a.mask == set(range(24))
            a.events.append(("backend", "close"))

        @contextmanager
        def coordinator_affinity_scope(self):
            with a.backend.coordinator_affinity_scope() as observe_executor:
                yield observe_executor

    class Pool:
        def __init__(self, *, max_workers):
            self._threads = set()
            assert max_workers == 11 and a.mask == {0, 23}
            assert a.events[0] == ("backend", "partition-and-start")
            a.events.append(("pool", "construct"))
            if failure_point == "pool_init": raise RuntimeError("pool_init")

        def __enter__(self):
            if failure_point == "pool_enter": raise RuntimeError("pool_enter")
            return self

        def __exit__(self, *error):
            assert a.mask == {0, 23}
            a.events.append(("pool", "joined"))
            if failure_point == "pool_join": raise RuntimeError("pool_join")

    monkeypatch.setattr(study, "ThreadPoolExecutor", Pool)

    def invoke():
        with study._capture_executor(Backend(), 11):
            assert a.mask == {0, 23}
            if failure_point == "body": raise RuntimeError("body")
            if failure_point == "stop": threading.Event().set()

    if failure_point not in (None, "stop"):
        with pytest.raises(RuntimeError, match=failure_point): invoke()
    else:
        invoke()
    assert a.mask == set(range(24)) and a.events[-1] == ("backend", "close")
    restore = a.events.index(("affinity", list(range(24))))
    if failure_point not in ("pool_init", "pool_enter"):
        assert a.events.index(("pool", "joined")) < restore


def test_injected_nonphysical_test_backend_keeps_existing_executor_api(monkeypatch):
    events = []

    class Backend:
        def __enter__(self): events.append("backend")
        def __exit__(self, *error): events.append("closed")

    class Pool:
        def __init__(self, *, max_workers): assert max_workers == 2
        def __enter__(self): events.append("pool"); return self
        def __exit__(self, *error): events.append("joined")

    monkeypatch.setattr(study, "ThreadPoolExecutor", Pool)
    with study._capture_executor(Backend(), 2): events.append("body")
    assert events == ["backend", "pool", "body", "joined", "closed"]


@pytest.mark.skipif(sys.platform != "linux", reason="genuine Linux self-affinity only; no Docker")
def test_linux_disposable_process_observes_real_pool_inheritance_and_restoration(tmp_path):
    source = Path(runtime.__file__).resolve().parents[1]
    program = '''import json,os,sys,threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, sys.argv[1])
from qcsd_lab.resource_study_runtime import CaptureRuntime
available = sorted(os.sched_getaffinity(0))
if len(available) < 5:
    print("insufficient-cpus")
    raise SystemExit(77)
backend = CaptureRuntime.__new__(CaptureRuntime)
backend.count = 2
backend.flight = Path(sys.argv[2])
pairs = (tuple(available[1:3]), tuple(available[3:5]))
auxiliary = tuple(cpu for cpu in available if all(cpu not in pair for pair in pairs))
backend.coordinator_partition = (tuple(available), pairs, auxiliary)
with backend.coordinator_affinity_scope() as observe_executor:
    assert sorted(os.sched_getaffinity(0)) == list(auxiliary)
    with ThreadPoolExecutor(max_workers=2) as pool:
        with observe_executor(pool):
            barrier = threading.Barrier(2)
            def observe(_):
                barrier.wait(timeout=5)
                return threading.get_native_id(), sorted(os.sched_getaffinity(0))
            values = list(pool.map(observe, range(2)))
            assert len({tid for tid, _ in values}) == 2
            assert all(mask == list(auxiliary) for _, mask in values)
assert sorted(os.sched_getaffinity(0)) == available
closed = json.loads((backend.flight / "coordinator-affinity-closed.json").read_text())
assert closed["executor_registered"] is True
assert closed["pool_joined_before_restoration"] is True
assert len(closed["owned_pool_threads"]) == 2
assert all(not value["alive_after_join"] for value in closed["owned_pool_threads"])
assert closed["remaining_thread_ids_after_restoration"] == [os.getpid()]
print("self-affinity-restored")
'''
    completed = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(source), str(tmp_path)],
        text=True, capture_output=True, timeout=30)
    if completed.returncode == 77:
        pytest.skip("Linux disposable process has fewer than five available CPUs")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "self-affinity-restored\n"


def controlled_pool(a, monkeypatch):
    """Thread objects are real; only their unstarted lifecycle/procfs is controlled."""
    thread = threading.Thread(name="owned-executor-worker")
    thread._native_id = a.pid + 100
    alive = [True]
    monkeypatch.setattr(thread, "is_alive", lambda: alive[0])
    a.tasks.append(thread.native_id)
    a.task_masks[thread.native_id] = {0, 23}
    a.task_names[thread.native_id] = "kernel-worker"
    pool = type("ControlledPool", (), {"_threads": {thread}})()
    return pool, thread, alive


def test_actual_owned_thread_objects_join_while_foreign_auxiliary_thread_remains(affinity, monkeypatch):
    a = affinity
    with a.backend.coordinator_affinity_scope() as observe_executor:
        pool, thread, alive = controlled_pool(a, monkeypatch)
        with observe_executor(pool):
            foreign = a.pid + 200
            a.tasks.append(foreign)
            a.task_masks[foreign] = {0, 23}
            # A matching name does not make the foreign task an executor owner.
            a.task_names[foreign] = thread.name
        alive[0] = False
        a.tasks.remove(thread.native_id)
    closed = a.records[a.backend.flight / "coordinator-affinity-closed.json"]
    assert closed["pool_joined_before_restoration"] is True
    assert closed["foreign_threads_confined_to_auxiliary"] is True
    assert closed["owned_pool_threads"] == [{"tid": thread.native_id, "name": "kernel-worker",
        "start_ticks": 100, "affinity": [0, 23], "python_name": thread.name, "alive_after_join": False}]
    assert closed["remaining_threads_after_restoration"][1]["name"] == thread.name
    assert a.mask == set(range(24))


@pytest.mark.parametrize("fault", ["python_alive", "native_same_birth", "changed_owner_set"])
def test_any_actual_owned_pool_survival_or_changed_ownership_refuses(affinity, monkeypatch, fault):
    a = affinity
    with pytest.raises(ValueError, match="pool-thread closure"):
        with a.backend.coordinator_affinity_scope() as observe_executor:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            with observe_executor(pool):
                pass
            alive[0] = fault == "python_alive"
            if fault != "native_same_birth":
                a.tasks.remove(thread.native_id)
            if fault == "changed_owner_set":
                pool._threads = set()
    closed = a.records[a.backend.flight / "coordinator-affinity-closed.json"]
    assert closed["pool_joined_before_restoration"] is False
    assert closed["restored"] is True


def test_reused_native_tid_is_foreign_only_after_a_different_start_time(affinity, monkeypatch):
    a = affinity
    with a.backend.coordinator_affinity_scope() as observe_executor:
        pool, thread, alive = controlled_pool(a, monkeypatch)
        with observe_executor(pool):
            pass
        alive[0] = False
        a.task_births[thread.native_id] = 101
        a.task_names[thread.native_id] = "new-foreign-task"
    closed = a.records[a.backend.flight / "coordinator-affinity-closed.json"]
    assert closed["owned_pool_threads"][0]["start_ticks"] == 100
    assert closed["remaining_threads_after_restoration"][1]["start_ticks"] == 101
    assert closed["pool_joined_before_restoration"] is True
    assert closed["foreign_threads_confined_to_auxiliary"] is True


@pytest.mark.parametrize("fault", ["protected_mask", "missing_native_id", "unknown_owner"])
def test_unbound_or_unconfined_executor_identity_refuses_before_join(affinity, monkeypatch, fault):
    a = affinity
    with pytest.raises(ValueError, match="coordinator (owned pool|task identity|executor)"):
        with a.backend.coordinator_affinity_scope() as observe_executor:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            if fault == "protected_mask": a.task_masks[thread.native_id] = {1}
            elif fault == "missing_native_id": thread._native_id = None
            else: pool._threads = {object()}
            try:
                with observe_executor(pool):
                    pass
            finally:
                alive[0] = False
                a.tasks = [a.pid]
    assert a.mask == set(range(24))


def test_foreign_affinity_escape_after_main_restoration_is_also_refused(affinity, monkeypatch):
    a = affinity
    original = a.set_mask
    foreign = a.pid + 200

    def escape(who, mask):
        original(who, mask)
        if set(mask) == set(range(24)):
            a.task_masks[foreign] = {23, 1}

    monkeypatch.setattr(runtime.os, "sched_setaffinity", escape)
    with pytest.raises(ValueError, match="pool-thread closure"):
        with a.backend.coordinator_affinity_scope():
            a.tasks.append(foreign)
            a.task_masks[foreign] = {0, 23}
    closed = a.records[a.backend.flight / "coordinator-affinity-closed.json"]
    assert closed["remaining_threads_before_restoration"][1]["affinity"] == [0, 23]
    assert closed["remaining_threads_after_restoration"][1]["affinity"] == [1, 23]
    assert closed["foreign_threads_confined_to_auxiliary"] is False
    assert closed["restored"] is True


def test_owned_observation_failure_does_not_replace_original_body_error(affinity, monkeypatch):
    a = affinity
    original = a.thread
    failure = RuntimeError("controlled body failure")

    def missing(tid):
        if tid != a.pid: raise OSError("controlled owned task observation failure")
        return original(tid)

    with pytest.raises(RuntimeError) as raised:
        with a.backend.coordinator_affinity_scope() as observe_executor:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            monkeypatch.setattr(runtime, "_coordinator_thread", missing)
            try:
                with observe_executor(pool):
                    raise failure
            finally:
                alive[0] = False
                a.tasks.remove(thread.native_id)
    assert raised.value is failure
    assert any("owned task observation failure" in note for note in failure.__notes__)
    assert a.mask == set(range(24))


def test_task_census_change_fails_closed_and_still_restores(affinity, monkeypatch):
    a = affinity
    original = a.thread

    def changes(tid):
        value = original(tid)
        if a.tasks == [a.pid]: a.tasks.append(a.pid + 200)
        return value

    with pytest.raises(ValueError, match="census changed"):
        with a.backend.coordinator_affinity_scope():
            monkeypatch.setattr(runtime, "_coordinator_thread", changes)
    assert a.mask == set(range(24))


def test_actual_proc_stat_parser_binds_name_start_time_and_affinity(tmp_path, monkeypatch):
    tid = 123
    directory = tmp_path / str(tid)
    directory.mkdir()
    (directory / "stat").write_text(f"{tid} (native (worker)) S " + "0 " * 18 + "456\n")
    monkeypatch.setattr(runtime, "Path", lambda value: tmp_path if value == "/proc/self/task" else Path(value))
    monkeypatch.setattr(runtime.os, "sched_getaffinity", lambda who: {0, 23}, raising=False)
    assert runtime._coordinator_thread(tid) == {"tid": tid, "name": "native (worker)",
        "start_ticks": 456, "affinity": [0, 23]}
    for invalid in (None, True, 0):
        with pytest.raises(ValueError, match="positive native TID"):
            runtime._coordinator_thread(invalid)


def test_actual_proc_stat_identity_change_during_mask_read_refuses(tmp_path, monkeypatch):
    tid = 123
    directory = tmp_path / str(tid)
    directory.mkdir()
    path = directory / "stat"
    path.write_text(f"{tid} (worker) S " + "0 " * 18 + "456\n")
    monkeypatch.setattr(runtime, "Path", lambda value: tmp_path if value == "/proc/self/task" else Path(value))

    def changed(who):
        path.write_text(f"{tid} (worker) S " + "0 " * 18 + "457\n")
        return {0, 23}

    monkeypatch.setattr(runtime.os, "sched_getaffinity", changed, raising=False)
    with pytest.raises(ValueError, match="identity changed"):
        runtime._coordinator_thread(tid)
