"""Private gate reads and effective-credential restoration without Docker."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_parallel_capture as parallel
from qcsd_lab import rapid_operation_facts as operations
from tests.test_rapid_parallel_capture import _released, context


def _credentials(monkeypatch, *, uids=(0, 0, 0), gids=(0, 0, 0), threads=1):
    """Model only privileged syscalls; actual input files and validators remain real."""
    state = {"uids": list(uids), "gids": list(gids), "calls": [], "fail": None}
    monkeypatch.setattr(parallel.os, "getresuid", lambda: tuple(state["uids"]))
    monkeypatch.setattr(parallel.os, "getresgid", lambda: tuple(state["gids"]))
    monkeypatch.setattr(parallel.os, "geteuid", lambda: state["uids"][1])
    monkeypatch.setattr(parallel.os, "getegid", lambda: state["gids"][1])

    def change(kind, value):
        state["calls"].append((kind, value))
        if state["fail"] == (kind, value):
            raise PermissionError("test syscall refusal")
        state[kind][1] = value

    monkeypatch.setattr(parallel.os, "seteuid", lambda value: change("uids", value))
    monkeypatch.setattr(parallel.os, "setegid", lambda value: change("gids", value))
    original_iterdir = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(range(threads))
                        if str(path) == "/proc/self/task" else original_iterdir(path))
    return state


def _declared(monkeypatch, uid=1000, gid=1000):
    monkeypatch.setenv("QCSD_LAB_UID", str(uid))
    monkeypatch.setenv("QCSD_LAB_GID", str(gid))


@pytest.mark.parametrize("name", ["QCSD_LAB_UID", "QCSD_LAB_GID"])
@pytest.mark.parametrize("value", [None, "", "-1", "+1", "01", "1 ", "0x10", "4294967295", "12345678901234567890"])
def test_missing_or_malformed_identity_fails_before_any_private_read(monkeypatch, name, value):
    _declared(monkeypatch)
    if value is None:
        monkeypatch.delenv(name)
    else:
        monkeypatch.setenv(name, value)
    state = _credentials(monkeypatch)
    monkeypatch.setattr(parallel, "regular_dir", lambda path: pytest.fail("private input read"))
    monkeypatch.setattr(parallel.os, "execv", lambda *args: pytest.fail("entrypoint executed"))
    with pytest.raises(ValueError, match="explicit canonical numeric"):
        parallel.gate(Path("/unused"), "a" * 64, 0, Path("/unused.json"))
    assert state["calls"] == []


@pytest.mark.parametrize("uid,gid", [(0, 0), (1917, 2405), (4294967294, 4294967294)])
def test_declared_identity_is_portable_and_real_saved_root_remain(monkeypatch, uid, gid):
    _declared(monkeypatch, uid, gid)
    state = _credentials(monkeypatch)
    with parallel._gate_read_credentials():
        assert state["uids"] == [0, uid, 0]
        assert state["gids"] == [0, gid, 0]
    assert state["uids"] == [0, 0, 0]
    assert state["gids"] == [0, 0, 0]


@pytest.mark.parametrize("uids", [(1000, 1000, 1000), (1000, 0, 1000), (0, 0, 1000)])
def test_transition_without_real_and_saved_root_is_rejected(monkeypatch, uids):
    _declared(monkeypatch, 1917, 2405)
    state = _credentials(monkeypatch, uids=uids)
    with pytest.raises(ValueError, match="real and saved root"):
        with parallel._gate_read_credentials():
            pytest.fail("credential scope entered")
    assert state["calls"] == []


def test_process_with_another_thread_cannot_change_credentials(monkeypatch):
    _declared(monkeypatch)
    state = _credentials(monkeypatch, threads=2)
    with pytest.raises(ValueError, match="single-threaded"):
        with parallel._gate_read_credentials():
            pytest.fail("credential scope entered")
    assert state["calls"] == []


def test_failed_uid_drop_restores_gid(monkeypatch):
    _declared(monkeypatch)
    state = _credentials(monkeypatch)
    state["fail"] = ("uids", 1000)
    with pytest.raises(PermissionError, match="syscall refusal"):
        with parallel._gate_read_credentials():
            pytest.fail("credential scope entered")
    assert state["uids"] == state["gids"] == [0, 0, 0]
    assert state["calls"] == [("gids", 1000), ("uids", 1000), ("gids", 0)]


@pytest.mark.parametrize("failure", [None, "authority", "partition", "cpu", "restore"])
def test_actual_private_gate_checks_run_as_declared_user_then_restore(context, monkeypatch, failure):
    _released(context)
    directory = context.output / "lane-1/gate"
    directory.chmod(0o700)
    context.path.chmod(0o600)
    for name in ("release.json", "host-partition.json"):
        (directory / name).chmod(0o600)
    inputs = [context.path, directory / "release.json", directory / "host-partition.json"]
    before = {path: (path.read_bytes(), path.stat().st_mode) for path in inputs}
    _declared(monkeypatch)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    state = _credentials(monkeypatch)
    original_read, original_dir = parallel.read, parallel.regular_dir
    reads, execs = [], []

    def read(path):
        assert state["uids"] == [0, 1000, 0]
        assert state["gids"] == [0, 1000, 0]
        reads.append(Path(path))
        return original_read(path)

    def regular_dir(path):
        assert state["uids"][1] == state["gids"][1] == 1000
        return original_dir(path)

    def execute(command, argv):
        assert state["uids"] == state["gids"] == [0, 0, 0]
        execs.append((command, argv))

    monkeypatch.setattr(parallel, "read", read)
    monkeypatch.setattr(parallel, "regular_dir", regular_dir)
    monkeypatch.setattr(parallel.os, "execv", execute)
    digest = context.digest
    if failure == "authority":
        digest = "0" * 64
    elif failure == "partition":
        (directory / "host-partition.json").write_bytes(b"{}\n")
    elif failure == "cpu":
        monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "9")
    elif failure == "restore":
        state["fail"] = ("uids", 0)
    if failure:
        with pytest.raises((ValueError, TimeoutError, PermissionError)):
            parallel.gate(directory, digest, 0, context.path)
        assert not execs
        assert "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_FILE" not in os.environ
    else:
        parallel.gate(directory, digest, 0, context.path)
        assert execs == [("/usr/local/bin/collection-entrypoint",
                          ["collection-entrypoint", "run", "/lab/config/campaigns/buflo.yml"])]
        assert all(path in reads for path in inputs)
        assert before == {path: (path.read_bytes(), path.stat().st_mode) for path in inputs}
        assert directory.stat().st_mode & 0o777 == 0o700
    assert state["gids"] == [0, 0, 0]
    assert state["uids"] == ([0, 1000, 0] if failure == "restore" else [0, 0, 0])
    assert state["calls"] == [("gids", 1000), ("uids", 1000), ("uids", 0), ("gids", 0)]


def test_private_gate_can_wait_past_120_seconds_without_starting_traffic(context, monkeypatch):
    _released(context)
    directory = context.output / "lane-1/gate"
    release = directory / "release.json"
    raw = release.read_bytes()
    release.unlink()
    _declared(monkeypatch)
    _credentials(monkeypatch)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    elapsed, calls = [0.0], []

    def wait(seconds):
        assert seconds == .1 and not calls
        elapsed[0] += 61
        if elapsed[0] >= 183:
            release.write_bytes(raw)

    def execute(command, argv):
        assert elapsed[0] > 120 and release.read_bytes() == raw
        calls.append((command, argv))

    monkeypatch.setattr(parallel.time, "sleep", wait)
    monkeypatch.setattr(parallel.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(parallel.os, "execv", execute)
    parallel.gate(directory, context.digest, 0, context.path)
    assert calls == [("/usr/local/bin/collection-entrypoint",
                      ["collection-entrypoint", "run", "/lab/config/campaigns/buflo.yml"])]


def test_same_identity_reads_real_private_files_without_any_privilege_syscall(context, monkeypatch):
    _released(context)
    directory = context.output / "lane-1/gate"
    directory.chmod(0o700)
    context.path.chmod(0o600)
    _declared(monkeypatch, os.geteuid(), os.getegid())
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    monkeypatch.setattr(parallel.os, "seteuid", lambda value: pytest.fail("UID changed"))
    monkeypatch.setattr(parallel.os, "setegid", lambda value: pytest.fail("GID changed"))
    execs = []
    monkeypatch.setattr(parallel.os, "execv", lambda command, argv: execs.append((command, argv)))
    parallel.gate(directory, context.digest, 0, context.path)
    assert len(execs) == 1
    assert directory.stat().st_mode & 0o777 == 0o700
    assert context.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("failure", [False, True])
def test_formal_worker_environment_is_read_before_root_restoration(context, monkeypatch, failure):
    from qcsd_lab import rapid_formal_parallel as formal

    _released(context)
    _declared(monkeypatch)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    state = _credentials(monkeypatch)
    original_load = parallel.load
    fact, audit_context = object(), []

    def load(path):
        value = original_load(path)
        if path == context.path:
            return {**value, "artifact_type": "qcsd-two-worker-formal-lane-authority"}
        return value

    def audit(path, *, _context):
        assert path == context.path and state["uids"] == state["gids"] == [0, 1000, 0]
        assert operations.current_context() is _context
        audit_context.append(_context)
        return load(path), [fact, object()]

    def environment(inputs, index, *, fact: object, _context):
        assert state["uids"] == state["gids"] == [0, 1000, 0]
        assert operations.current_context() is _context
        assert fact is facts[0] and _context is audit_context[0] and index == 0
        if failure:
            raise ValueError("test formal proof read failed")
        return {"QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION": "/private/verified-capsule.json"}

    execs = []

    def execute(command, argv):
        assert state["uids"] == state["gids"] == [0, 0, 0]
        assert os.environ["QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"] == "/private/verified-capsule.json"
        execs.append((command, argv))

    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", raising=False)
    facts = [fact]
    monkeypatch.setattr(parallel, "load", load)
    monkeypatch.setattr(formal, "_audit", audit)
    monkeypatch.setattr(formal, "worker_environment", environment)
    monkeypatch.setattr(parallel.os, "execv", execute)
    if failure:
        with pytest.raises(ValueError, match="formal proof read failed"):
            parallel.gate(context.output / "lane-1/gate", context.digest, 0, context.path)
        assert "QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION" not in os.environ
    else:
        parallel.gate(context.output / "lane-1/gate", context.digest, 0, context.path)
    assert state["uids"] == state["gids"] == [0, 0, 0]
    assert len(execs) == int(not failure)
    assert operations.current_context() is None


def test_gate_rechecks_scoped_dependency_before_exec(context, tmp_path, monkeypatch):
    _released(context)
    _declared(monkeypatch)
    state = _credentials(monkeypatch)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    watched = tmp_path / "watched-input.json"
    watched.write_bytes(b'{"source":"original"}\n')
    original_authority = parallel.authority

    def authority(path):
        active = operations.current_context()
        assert active is not None
        active.watch_file(watched)
        value = original_authority(path)
        watched.write_bytes(b'{"source":"changed"}\n')
        return value

    monkeypatch.setattr(parallel, "authority", authority)
    monkeypatch.setattr(parallel.os, "execv", lambda *args: pytest.fail("traffic entrypoint executed"))
    with pytest.raises(ValueError, match="operation dependency bytes or mode changed"):
        parallel.gate(context.output / "lane-1/gate", context.digest, 0, context.path)
    assert state["uids"] == state["gids"] == [0, 0, 0]
    assert operations.current_context() is None
