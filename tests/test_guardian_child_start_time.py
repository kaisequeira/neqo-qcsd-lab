from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


GUARDIAN = Path(__file__).resolve().parents[1] / "tools/docker_lifecycle_lock_guardian.py"


@pytest.fixture
def guardian():
    name = "guardian_child_start_time_test"
    spec = importlib.util.spec_from_file_location(name, GUARDIAN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    try:
        yield module
    finally:
        del sys.modules[name]


def proc_stat(pid, *, start=250, group=None, session=None, state="S"):
    fields = [state, "800", str(pid if group is None else group),
              str(pid if session is None else session)] + ["0"] * 15
    fields.append(str(start))
    return f"{pid} (bash) " + " ".join(fields + ["0"] * 30) + "\n"


def binding_fixture(guardian, monkeypatch, *, pid=900, records=None):
    if records is None:
        records = [proc_stat(pid)]
    records = iter(records)
    reads = []

    def read(path, *, encoding):
        assert path == Path(f"/proc/{pid}/stat") and encoding == "ascii"
        reads.append(path)
        return next(records)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(guardian.os, "getuid", lambda: 503)
    monkeypatch.setattr(guardian, "_process_uid", lambda seen: 503)
    monkeypatch.setattr(guardian.time, "sleep", lambda value: None)
    monotonic = iter([1.0, 1.1, 1.2, 3.1])
    monkeypatch.setattr(guardian.time, "monotonic", lambda: next(monotonic))
    command = ("/source/qcsd-lab", "resource-study", "prepare")
    monkeypatch.setattr(guardian, "_read_cmdline", lambda seen: (
        "/bin/bash", "--noprofile", "--norc", "-p", *command,
    ))
    exits = []
    monkeypatch.setattr(guardian, "_observe_child_exit", lambda child: exits.append(child) or False)
    return command, reads, exits


@pytest.mark.parametrize("pid", [2, 900])
def test_actual_child_binder_never_issues_zero_tick_anchor(guardian, monkeypatch, pid):
    command, reads, exits = binding_fixture(
        guardian, monkeypatch, pid=pid,
        records=[proc_stat(pid, start=0), proc_stat(pid, start=0)],
    )
    monkeypatch.setattr(guardian, "ChildIdentity", lambda *args: pytest.fail("zero child anchor issued"))
    monkeypatch.setattr(guardian, "_process_uid", lambda seen: pytest.fail("invalid operation identity reached owner binding"))
    monkeypatch.setattr(guardian, "_read_cmdline", lambda seen: pytest.fail("invalid operation reached command binding"))
    monkeypatch.setattr(guardian, "_kill_child_group", lambda *args: pytest.fail("unbound process signaled"))
    with pytest.raises(guardian.GuardianError, match="operation start time is invalid"):
        guardian._bind_child_identity(pid, command)
    assert len(reads) == 2 and exits == []


def test_actual_child_binder_preserves_exact_positive_anchor(guardian, monkeypatch):
    command, reads, exits = binding_fixture(guardian, monkeypatch)
    child = guardian._bind_child_identity(900, command)
    assert child == guardian.ChildIdentity(900, 250, 900, 900, command)
    assert reads == [Path("/proc/900/stat")] and exits == [child]


@pytest.mark.parametrize("change", ["start", "owner", "zombie", "exited"])
def test_actual_child_binder_keeps_existing_identity_fences(guardian, monkeypatch, change):
    records = [proc_stat(900)]
    if change == "start":
        records = [proc_stat(900, group=800, session=800), proc_stat(900, start=251)]
    elif change == "zombie":
        records = [proc_stat(900, state="Z")]
    command, reads, exits = binding_fixture(guardian, monkeypatch, records=records)
    if change == "owner":
        monkeypatch.setattr(guardian, "_process_uid", lambda seen: 0)
    elif change == "exited":
        monkeypatch.setattr(guardian, "_observe_child_exit", lambda child: True)
    expected = {
        "start": "identity changed", "owner": "owner changed",
        "zombie": "exited before exact command binding",
        "exited": "exited before exact command binding",
    }[change]
    with pytest.raises(guardian.GuardianError, match=expected):
        guardian._bind_child_identity(900, command)


def test_actual_child_binder_requires_exact_bash_command(guardian, monkeypatch):
    command, reads, exits = binding_fixture(
        guardian, monkeypatch, records=[proc_stat(900), proc_stat(900)],
    )
    monkeypatch.setattr(guardian, "_read_cmdline", lambda seen: ("/different-command",))
    monotonic = iter([1.0, 1.1, 3.1])
    monkeypatch.setattr(guardian.time, "monotonic", lambda: next(monotonic))
    with pytest.raises(guardian.GuardianError, match="did not establish its exact command"):
        guardian._bind_child_identity(900, command)
    assert len(reads) == 2


@pytest.mark.parametrize("start", [-1, "invalid", "0.0"])
def test_actual_child_binder_retains_parser_refusals(guardian, monkeypatch, start):
    command, reads, exits = binding_fixture(
        guardian, monkeypatch,
        records=[proc_stat(900, start=start), proc_stat(900, start=start)],
    )
    with pytest.raises(guardian.GuardianError):
        guardian._bind_child_identity(900, command)
    assert len(reads) == 2 and exits == []
