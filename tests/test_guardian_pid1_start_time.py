from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


GUARDIAN = Path(__file__).resolve().parents[1] / "tools/docker_lifecycle_lock_guardian.py"


@pytest.fixture
def guardian():
    name = "guardian_pid1_start_time_test"
    spec = importlib.util.spec_from_file_location(name, GUARDIAN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    try:
        yield module
    finally:
        del sys.modules[name]


def proc_stat(pid=1, *, start=0, parent=0, group=1, session=1, state="S"):
    # Fields after comm begin at stat field 3; starttime is field 22.
    fields = [state, str(parent), str(group), str(session)] + ["0"] * 15
    fields.append(str(start))
    return f"{pid} (systemd) " + " ".join(fields + ["0"] * 30) + "\n"


def mock_stat(monkeypatch, value):
    reads = []

    def read(path, *, encoding):
        assert encoding == "ascii"
        reads.append(str(path))
        return value() if callable(value) else value

    monkeypatch.setattr(Path, "read_text", read)
    return reads


def census_setup(guardian, monkeypatch, *, owner=0):
    closes = []
    monkeypatch.setattr(guardian, "_open_process_pidfd", lambda pid: 91)
    monkeypatch.setattr(guardian, "_pidfd_is_terminal", lambda *args: False)
    monkeypatch.setattr(guardian, "_process_uid", lambda pid: owner)
    monkeypatch.setattr(guardian.os, "getuid", lambda: 503)
    monkeypatch.setattr(guardian.os, "close", closes.append)
    return closes


def census(guardian, pid=1, *, threshold=100, reader=None):
    return guardian._process_references_buildx_candidate(
        pid,
        Path(f"/proc/{pid}"),
        threshold=threshold,
        paths=(Path("/var/tmp/.qcsd-buildx-config-503.test"),),
        path_bytes=(b"/var/tmp/.qcsd-buildx-config-503.test",),
        reference_reader=reader,
    )


def test_real_shaped_init_zero_tick_is_valid(guardian, monkeypatch):
    reads = mock_stat(monkeypatch, proc_stat())
    assert guardian._process_record(1) == ("S", 0, 1, 1, 0)
    assert reads == ["/proc/1/stat"]


@pytest.mark.parametrize("pid", [2, 503, 12345])
def test_zero_tick_is_a_valid_process_record_for_other_pids(guardian, monkeypatch, pid):
    mock_stat(monkeypatch, proc_stat(pid))
    assert guardian._process_record(pid) == ("S", 0, 1, 1, 0)


def test_zero_tick_cannot_issue_an_operation_anchor(guardian, monkeypatch):
    mock_stat(monkeypatch, proc_stat(12345))
    with pytest.raises(guardian.GuardianError, match="operation start time is invalid"):
        guardian._process_start_time(12345)


def test_positive_operation_anchor_stays_exact(guardian, monkeypatch):
    mock_stat(monkeypatch, proc_stat(12345, start=200))
    assert guardian._process_start_time(12345) == 200


@pytest.mark.parametrize("field", ["start", "parent", "group", "session"])
def test_negative_init_identity_remains_invalid(guardian, monkeypatch, field):
    mock_stat(monkeypatch, proc_stat(**{field: -1}))
    with pytest.raises(guardian.GuardianError, match="start time is invalid"):
        guardian._process_record(1)


@pytest.mark.parametrize("value", ["1 (systemd) S 0 1 1", "1 (systemd) " + "x " * 20])
def test_malformed_init_stat_remains_invalid(guardian, monkeypatch, value):
    mock_stat(monkeypatch, value)
    with pytest.raises(guardian.GuardianError, match="identity is malformed"):
        guardian._process_record(1)


def test_init_is_excluded_only_after_stable_census_identity(guardian, monkeypatch):
    reads = mock_stat(monkeypatch, proc_stat())
    closes = census_setup(guardian, monkeypatch)

    def forbidden_reader(*args):
        pytest.fail("root-owned prebirth init cannot be a user Buildx config owner")

    assert census(guardian, reader=forbidden_reader) is False
    assert reads == ["/proc/1/stat", "/proc/1/stat"]
    assert closes == [91]


@pytest.mark.parametrize("change", ["start", "owner"])
def test_init_exclusion_keeps_before_after_identity_fence(guardian, monkeypatch, change):
    records = iter((proc_stat(), proc_stat(start=int(change == "start"))))
    mock_stat(monkeypatch, lambda: next(records))
    closes = census_setup(guardian, monkeypatch)
    owners = iter((0, 503 if change == "owner" else 0))
    monkeypatch.setattr(guardian, "_process_uid", lambda pid: next(owners))
    with pytest.raises(guardian.GuardianError, match="census identity changed"):
        census(guardian)
    assert closes == [91]


def test_positive_user_owner_is_still_fully_inspected(guardian, monkeypatch):
    reads = mock_stat(monkeypatch, proc_stat(12345, start=200, parent=100))
    closes = census_setup(guardian, monkeypatch, owner=503)
    references = []

    def reader(*args):
        references.append(args)
        return True

    assert census(guardian, 12345, reader=reader) is True
    assert len(references) == 1
    assert reads == ["/proc/12345/stat", "/proc/12345/stat"]
    assert closes == [91]


def test_zero_tick_user_owner_predates_positive_config_threshold(guardian, monkeypatch):
    mock_stat(monkeypatch, proc_stat(12345))
    closes = census_setup(guardian, monkeypatch, owner=503)

    def forbidden_reader(*args):
        pytest.fail("a process born before the config cannot own its later paths")

    assert census(guardian, 12345, reader=forbidden_reader) is False
    assert closes == [91]


def ledger_fixture(guardian, monkeypatch):
    boot = "73b57862-cba9-4d26-9019-e37f68fa895b"
    monkeypatch.setattr(guardian, "_boot_id", lambda: boot)
    monkeypatch.setattr(guardian.os, "getuid", lambda: 503)
    parent = SimpleNamespace(st_dev=1, st_ino=2)
    lock = guardian.LockIdentity(Path("/var/tmp/lock"), 1, 2, 1, 3, 503, 0o600, 1)
    source = guardian.FileIdentity(Path("/source/guardian.py"), 1, 4, 503, 0o644, 1, "a" * 64)
    value = dict(
        boot_id=boot, guardian_pid=100, guardian_start_time=200,
        guardian_source_device=1, guardian_source_inode=4,
        guardian_source_path=str(source.path), guardian_source_sha256=source.sha256,
        lock_device=1, lock_inode=3, lock_path=str(lock.path),
        parent_device=1, parent_inode=2, phase="intent", root_name="root",
        schema=1, token="token", uid=503,
    )
    kwargs = dict(phase="intent", token="token", root_name="root", parent=parent, lock=lock, source=source)
    return value, kwargs


@pytest.mark.parametrize("field,value", [("guardian_pid", 1), ("guardian_start_time", 0)])
def test_buildx_operation_identity_stays_strictly_positive(guardian, monkeypatch, field, value):
    record, kwargs = ledger_fixture(guardian, monkeypatch)
    record[field] = value
    with pytest.raises(guardian.GuardianError, match="differs from schema 1"):
        guardian._validate_buildx_record_common(record, **kwargs)


@pytest.mark.parametrize("field,value", [
    ("guardian_source_path", "/different/guardian.py"),
    ("guardian_source_inode", 5),
    ("guardian_source_sha256", "b" * 64),
])
def test_prior_boot_exact_source_fence_remains_unchanged(guardian, monkeypatch, field, value):
    record, kwargs = ledger_fixture(guardian, monkeypatch)
    record["boot_id"] = "00000000-0000-0000-0000-000000000001"
    guardian._validate_buildx_record_common(record, **kwargs)
    record[field] = value
    with pytest.raises(guardian.GuardianError, match="prior-boot Buildx config ledger identity changed"):
        guardian._validate_buildx_record_common(record, **kwargs)
