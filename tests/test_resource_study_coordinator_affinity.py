"""Source024 outer-coordinator isolation, without Docker or capture claims.

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

    observed = Observed()
    monkeypatch.setattr(runtime.os, "sched_getaffinity", lambda who: set(observed.mask), raising=False)
    monkeypatch.setattr(runtime.os, "sched_setaffinity", observed.set_mask, raising=False)
    monkeypatch.setattr(runtime, "_coordinator_tasks", lambda: list(observed.tasks))
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


def test_unjoined_thread_refuses_and_records_main_restoration(affinity):
    a = affinity
    with pytest.raises(ValueError, match="pool-thread closure"):
        with a.backend.coordinator_affinity_scope():
            a.tasks.append(a.pid + 1)
    assert a.mask == set(range(24))
    closed = a.records[a.backend.flight / "coordinator-affinity-closed.json"]
    assert closed["restored"] is True and closed["pool_joined_before_restoration"] is False
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
            with a.backend.coordinator_affinity_scope():
                yield

    class Pool:
        def __init__(self, *, max_workers):
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
    program = '''import os,sys
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
with backend.coordinator_affinity_scope():
    assert sorted(os.sched_getaffinity(0)) == list(auxiliary)
    with ThreadPoolExecutor(max_workers=2) as pool:
        values = list(pool.map(lambda _: sorted(os.sched_getaffinity(0)), range(4)))
        assert values == [list(auxiliary)] * 4
assert sorted(os.sched_getaffinity(0)) == available
print("self-affinity-restored")
'''
    completed = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(source), str(tmp_path)],
        text=True, capture_output=True, timeout=30)
    if completed.returncode == 77:
        pytest.skip("Linux disposable process has fewer than five available CPUs")
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "self-affinity-restored\n"
