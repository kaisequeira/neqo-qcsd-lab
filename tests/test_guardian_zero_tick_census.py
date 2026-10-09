from __future__ import annotations

import importlib.util
from pathlib import Path
import signal
import sys

import pytest


GUARDIAN = Path(__file__).resolve().parents[1] / "tools/docker_lifecycle_lock_guardian.py"


@pytest.fixture
def guardian():
    name = "guardian_zero_tick_census_test"
    spec = importlib.util.spec_from_file_location(name, GUARDIAN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    try:
        yield module
    finally:
        del sys.modules[name]


def proc_stat(pid, *, start=0, parent=0, group=0, session=0, state="I"):
    fields = [state, str(parent), str(group), str(session)] + ["0"] * 15
    fields.append(str(start))
    return f"{pid} (kthreadd) " + " ".join(fields + ["0"] * 30) + "\n"


def patch_records(monkeypatch, records):
    reads = []

    def read(path, *, encoding):
        assert encoding == "ascii"
        pid = int(path.parent.name)
        reads.append(pid)
        value = records[pid]
        return value() if callable(value) else value

    monkeypatch.setattr(Path, "read_text", read)
    return reads


def census(guardian, *, threshold=100, reader=None):
    return guardian._process_references_buildx_candidate(
        2, Path("/proc/2"), threshold=threshold,
        paths=(Path("/var/tmp/.qcsd-buildx-config-503.test"),),
        path_bytes=(b"/var/tmp/.qcsd-buildx-config-503.test",),
        reference_reader=reader,
    )


def census_binding(guardian, monkeypatch, *, owner=0):
    closes = []
    monkeypatch.setattr(guardian, "_open_process_pidfd", lambda pid: 91)
    monkeypatch.setattr(guardian, "_pidfd_is_terminal", lambda *args: False)
    monkeypatch.setattr(guardian, "_process_uid", lambda pid: owner)
    monkeypatch.setattr(guardian.os, "getuid", lambda: 503)
    monkeypatch.setattr(guardian.os, "close", closes.append)
    return closes


def test_actual_shaped_kthreadd_zero_tick_is_readable(guardian, monkeypatch):
    reads = patch_records(monkeypatch, {2: proc_stat(2)})
    assert guardian._process_record(2) == ("I", 0, 0, 0, 0)
    assert reads == [2]


def test_kernel_zero_tick_is_excluded_after_stable_identity(guardian, monkeypatch):
    reads = patch_records(monkeypatch, {2: proc_stat(2)})
    closes = census_binding(guardian, monkeypatch)

    def forbidden(*args):
        pytest.fail("a root-owned kernel task cannot own the user config")

    assert census(guardian, reader=forbidden) is False
    assert reads == [2, 2]
    assert closes == [91]


@pytest.mark.parametrize("change", ["start", "owner"])
def test_zero_tick_exclusion_does_not_bypass_identity_change(guardian, monkeypatch, change):
    values = iter((proc_stat(2), proc_stat(2, start=int(change == "start"))))
    patch_records(monkeypatch, {2: lambda: next(values)})
    closes = census_binding(guardian, monkeypatch)
    owners = iter((0, 503 if change == "owner" else 0))
    monkeypatch.setattr(guardian, "_process_uid", lambda pid: next(owners))
    with pytest.raises(guardian.GuardianError, match="census identity changed"):
        census(guardian)
    assert closes == [91]


def test_zero_tick_eligible_user_still_requires_reference_reader(guardian, monkeypatch):
    patch_records(monkeypatch, {2: proc_stat(2)})
    closes = census_binding(guardian, monkeypatch, owner=503)
    calls = []
    assert census(guardian, threshold=0, reader=lambda *args: calls.append(args) or True) is True
    assert len(calls) == 1
    assert closes == [91]


@pytest.mark.parametrize("start", [-1, "invalid", "0.0"])
def test_zero_tick_support_does_not_accept_invalid_start(guardian, monkeypatch, start):
    patch_records(monkeypatch, {2: proc_stat(2, start=start)})
    with pytest.raises(guardian.GuardianError):
        guardian._process_record(2)


def test_terminal_pidfd_still_requires_replacement_or_absence(guardian, monkeypatch):
    patch_records(monkeypatch, {2: proc_stat(2)})
    closes = census_binding(guardian, monkeypatch)
    terminal = iter((False, True))
    monkeypatch.setattr(guardian, "_pidfd_is_terminal", lambda *args: next(terminal))
    replacements = []
    monkeypatch.setattr(guardian, "_replacement_pidfd_after_terminal", lambda pid: replacements.append(pid))
    assert census(guardian) is False
    assert replacements == [2]
    assert closes == [91]


def drain_fixture(guardian, monkeypatch, *, descendant=False):
    child = guardian.ChildIdentity(900, 250, 900, 900, ("exact-qcsd",))
    records = {
        1: proc_stat(1, state="S", group=1, session=1),
        2: proc_stat(2),
        900: proc_stat(900, start=250, parent=800, group=900, session=900, state="Z"),
    }
    if descendant:
        records[901] = proc_stat(901, start=0, parent=900, group=900, session=900, state="S")
    reads = patch_records(monkeypatch, records)
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(Path(f"/proc/{pid}") for pid in records))
    monkeypatch.setattr(Path, "exists", lambda path: path.parent == Path("/proc") and path.name.isdecimal() and int(path.name) in records)
    monkeypatch.setattr(guardian, "_process_uid", lambda pid: 0 if pid in (1, 2) else 503)
    monkeypatch.setattr(guardian.os, "getuid", lambda: 503)
    monkeypatch.setattr(guardian.time, "monotonic", lambda: 1.0)
    sleeps = []

    def sleep(value):
        sleeps.append(value)
        if len(sleeps) > 3:
            pytest.fail("drain did not terminate after stable empty confirmations")

    monkeypatch.setattr(guardian.time, "sleep", sleep)
    return child, records, reads, sleeps


def test_actual_drain_completes_with_live_kernel_zero_tick(guardian, monkeypatch):
    child, records, reads, sleeps = drain_fixture(guardian, monkeypatch)
    monkeypatch.setattr(guardian, "_kill_child_group", lambda *args: pytest.fail("empty session must not be signaled"))
    guardian._drain_child_group(child)
    assert reads.count(2) == 2
    assert len(sleeps) == 1


def test_actual_drain_keeps_owned_zero_tick_session_member(guardian, monkeypatch):
    child, records, reads, sleeps = drain_fixture(guardian, monkeypatch, descendant=True)
    signals = []

    def kill(pid, sig):
        signals.append((pid, sig))
        records[901] = proc_stat(901, start=0, parent=900, group=900, session=900, state="Z")

    monkeypatch.setattr(guardian, "_kill_child_group", kill)
    guardian._drain_child_group(child)
    assert signals == [(900, signal.SIGKILL)]
    assert reads.count(2) == 3
    assert len(sleeps) == 2


@pytest.mark.parametrize("change", ["start", "owner", "malformed-kernel"])
def test_actual_drain_retains_authority_on_uncertain_identity(guardian, monkeypatch, change):
    child, records, reads, sleeps = drain_fixture(guardian, monkeypatch)
    if change == "start":
        records[900] = proc_stat(900, start=251, group=900, session=900, state="Z")
    elif change == "owner":
        monkeypatch.setattr(guardian, "_process_uid", lambda pid: 0)
    else:
        records[2] = "2 (kthreadd) I 0 0\n"
        with pytest.raises(guardian.GuardianError, match="identity is malformed"):
            guardian._session_processes(child)
        reads.clear()
    monkeypatch.setattr(guardian, "_kill_child_group", lambda *args: pytest.fail("uncertain anchor must not be signaled"))

    class HeldAuthority(Exception):
        pass

    monkeypatch.setattr(guardian.time, "sleep", lambda value: (_ for _ in ()).throw(HeldAuthority()))
    with pytest.raises(HeldAuthority):
        guardian._drain_child_group(child)
    # Normal empty-session drain checks the anchor again before its first
    # sleep. Each uncertainty above instead reaches the hold path immediately.
    assert reads.count(child.pid) == 1
