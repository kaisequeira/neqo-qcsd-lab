"""Source029 owned Linux teardown decisions, without Docker or capture claims.

These unit controls use the existing synthetic procfs/thread ownership fixture
and a measured fake monotonic clock. The separate real pthread TLS control
reproduces kernel teardown with actual eleven-worker Linux thread ownership.
ROOT alone executes these tests.
"""
import pytest

from qcsd_lab import resource_study_runtime as runtime
from tests.test_resource_study_coordinator_affinity import affinity, controlled_pool


@pytest.fixture
def clock(affinity, monkeypatch):
    class Clock:
        now = 0.0
        callback = None

        def __init__(self):
            self.sleeps = []

        def sleep(self, seconds):
            assert affinity.mask == {0, 23}
            assert 0 < seconds <= 0.01
            self.sleeps.append(seconds)
            self.now = round(self.now + seconds, 9)
            if self.callback is not None:
                self.callback()

    value = Clock()
    monkeypatch.setattr(runtime.time, "monotonic", lambda: value.now)
    monkeypatch.setattr(runtime.time, "sleep", value.sleep)
    return value


def closed(a):
    return a.records[a.backend.flight / "coordinator-affinity-closed.json"]


def test_joined_python_threads_wait_for_their_exact_kernel_birth_to_exit(affinity, clock, monkeypatch):
    a = affinity
    with a.backend.coordinator_affinity_scope() as observe:
        pool, thread, alive = controlled_pool(a, monkeypatch)
        with observe(pool):
            pass
        alive[0] = False

        def finish():
            if clock.now >= 0.5 and thread.native_id in a.tasks:
                a.tasks.remove(thread.native_id)

        clock.callback = finish
    value = closed(a)
    wait = value["owned_kernel_thread_teardown"]
    assert wait["complete"] is True and wait["elapsed_seconds"] == 0.5
    assert wait["maximum_wait_seconds"] == 5.0 and wait["polls"] > 1
    assert wait["owned_thread_identities"] == [{"tid": thread.native_id, "start_ticks": 100}]
    assert wait["remaining_owned_threads"] == []
    assert value["python_pool_joined_before_kernel_wait"] is True
    assert value["pool_joined_before_restoration"] is True
    assert value["restored"] is True and a.mask == set(range(24))
    assert value["record_type"] == "qcsd-Source029-outer-coordinator-affinity-v2"
    assert value["schema_version"] == 2


def test_persistent_owned_kernel_birth_refuses_at_five_seconds_and_restores(affinity, clock, monkeypatch):
    a = affinity
    with pytest.raises(ValueError, match="pool-thread closure"):
        with a.backend.coordinator_affinity_scope() as observe:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            with observe(pool):
                pass
            alive[0] = False
    value = closed(a)
    wait = value["owned_kernel_thread_teardown"]
    assert wait["complete"] is False and wait["elapsed_seconds"] == 5.0
    assert wait["remaining_owned_threads"][0]["tid"] == thread.native_id
    assert value["python_pool_joined_before_kernel_wait"] is True
    assert value["pool_joined_before_restoration"] is False
    assert value["restored"] is True and a.mask == set(range(24))


@pytest.mark.parametrize("missing", [FileNotFoundError, ProcessLookupError])
def test_owned_disappearance_during_stat_or_affinity_requires_a_fresh_census(affinity, clock, monkeypatch, missing):
    a = affinity
    with a.backend.coordinator_affinity_scope() as observe:
        pool, thread, alive = controlled_pool(a, monkeypatch)
        with observe(pool):
            pass
        alive[0] = False
        original = a.thread

        def exits(tid):
            if tid == thread.native_id:
                a.tasks.remove(tid)
                raise missing("controlled owned teardown")
            return original(tid)

        monkeypatch.setattr(runtime, "_coordinator_thread", exits)
    wait = closed(a)["owned_kernel_thread_teardown"]
    assert wait["complete"] is True and wait["polls"] == 2
    assert wait["owned_task_disappearance_retries"] == 1
    assert closed(a)["remaining_thread_ids_before_restoration"] == [a.pid]


def test_owned_removal_between_two_enumerations_retries_the_complete_snapshot(affinity, clock, monkeypatch):
    a = affinity
    with a.backend.coordinator_affinity_scope() as observe:
        pool, thread, alive = controlled_pool(a, monkeypatch)
        with observe(pool):
            pass
        alive[0] = False
        original = a.thread

        def exits(tid):
            value = original(tid)
            if tid == thread.native_id:
                a.tasks.remove(tid)
            return value

        monkeypatch.setattr(runtime, "_coordinator_thread", exits)
    wait = closed(a)["owned_kernel_thread_teardown"]
    assert wait["complete"] is True and wait["owned_task_disappearance_retries"] == 1
    assert wait["polls"] == 2


@pytest.mark.parametrize("protected", [False, True])
def test_reused_tid_has_a_different_foreign_birth_and_keeps_affinity_guards(affinity, clock, monkeypatch, protected):
    a = affinity

    def exercise():
        with a.backend.coordinator_affinity_scope() as observe:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            with observe(pool):
                pass
            alive[0] = False
            a.task_births[thread.native_id] = 101
            a.task_masks[thread.native_id] = {1} if protected else {0, 23}

    if protected:
        with pytest.raises(ValueError, match="escaped auxiliary"):
            exercise()
    else:
        exercise()
        assert closed(a)["owned_kernel_thread_teardown"]["complete"] is True
        assert closed(a)["remaining_threads_after_restoration"][1]["start_ticks"] == 101
    assert a.mask == set(range(24)) and clock.sleeps == []


def test_foreign_disappearance_is_never_an_owned_teardown_retry(affinity, clock, monkeypatch):
    a = affinity
    with pytest.raises(ProcessLookupError, match="foreign"):
        with a.backend.coordinator_affinity_scope() as observe:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            with observe(pool):
                pass
            alive[0] = False
            a.tasks.remove(thread.native_id)
            foreign = a.pid + 200
            a.tasks.append(foreign)
            original = a.thread

            def missing(tid):
                if tid == foreign:
                    raise ProcessLookupError("controlled foreign disappearance")
                return original(tid)

            monkeypatch.setattr(runtime, "_coordinator_thread", missing)
    assert a.mask == set(range(24)) and clock.sleeps == []


@pytest.mark.parametrize("failure", [PermissionError("controlled permission"), ValueError("controlled malformed stat")])
def test_other_owned_observation_errors_remain_refusals(affinity, clock, monkeypatch, failure):
    a = affinity
    with pytest.raises(type(failure), match="controlled"):
        with a.backend.coordinator_affinity_scope() as observe:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            with observe(pool):
                pass
            alive[0] = False
            original = a.thread

            def refused(tid):
                if tid == thread.native_id:
                    raise failure
                return original(tid)

            monkeypatch.setattr(runtime, "_coordinator_thread", refused)
    assert a.mask == set(range(24)) and clock.sleeps == []


def test_live_python_owner_is_not_waited_into_a_success(affinity, clock, monkeypatch):
    a = affinity
    with pytest.raises(ValueError, match="pool-thread closure"):
        with a.backend.coordinator_affinity_scope() as observe:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            with observe(pool):
                pass
    assert closed(a)["python_pool_joined_before_kernel_wait"] is False
    assert closed(a)["owned_kernel_thread_teardown"] is None
    assert closed(a)["pool_joined_before_restoration"] is False
    assert clock.sleeps == [] and a.mask == set(range(24))


def test_repeated_owned_missing_observations_cannot_manufacture_a_stable_pass(affinity, clock, monkeypatch):
    a = affinity
    with pytest.raises(ValueError, match="unstable for five seconds"):
        with a.backend.coordinator_affinity_scope() as observe:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            with observe(pool):
                pass
            alive[0] = False
            original = a.thread

            def missing(tid):
                if tid == thread.native_id:
                    raise ProcessLookupError("owned task still lacks a stable observation")
                return original(tid)

            monkeypatch.setattr(runtime, "_coordinator_thread", missing)
    assert clock.now == 5.0 and a.mask == set(range(24))


def test_known_foreign_tid_reuse_cannot_later_take_the_owned_missing_retry(affinity, clock, monkeypatch):
    a = affinity
    with pytest.raises(ProcessLookupError, match="known foreign"):
        with a.backend.coordinator_affinity_scope() as observe:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            other = a.pid + 101
            second = type(thread)(name="second-owned-executor-worker")
            second._native_id = other
            monkeypatch.setattr(second, "is_alive", lambda: False)
            a.tasks.append(other)
            a.task_masks[other] = {0, 23}
            pool._threads.add(second)
            with observe(pool):
                pass
            alive[0] = False
            a.task_births[thread.native_id] = 101
            original = a.thread

            def observed(tid):
                if tid == thread.native_id and clock.now > 0:
                    raise ProcessLookupError("known foreign reused task disappeared")
                return original(tid)

            monkeypatch.setattr(runtime, "_coordinator_thread", observed)
    assert clock.now == 0.01 and a.mask == set(range(24))


def test_empty_kernel_census_observed_after_deadline_does_not_pass(affinity, clock, monkeypatch):
    a = affinity
    with pytest.raises(ValueError, match="pool-thread closure"):
        with a.backend.coordinator_affinity_scope() as observe:
            pool, thread, alive = controlled_pool(a, monkeypatch)
            with observe(pool):
                pass
            alive[0] = False
            a.tasks.remove(thread.native_id)
            original = a.thread

            def late_observation(tid):
                value = original(tid)
                clock.now = 5.001
                return value

            monkeypatch.setattr(runtime, "_coordinator_thread", late_observation)
    wait = closed(a)["owned_kernel_thread_teardown"]
    assert wait["remaining_owned_threads"] == [] and wait["timed_out"] is True
    assert wait["elapsed_seconds"] == 5.001 and wait["complete"] is False
    assert closed(a)["pool_joined_before_restoration"] is False
    assert a.mask == set(range(24)) and clock.sleeps == []
