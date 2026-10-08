"""Physical sparse-volume headroom, independent of Docker or real disk use."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study_storage as storage


@pytest.fixture
def disk_case(tmp_path, monkeypatch):
    root = tmp_path / "study"
    root.mkdir()
    backing = tmp_path / "volume.img"
    backing.write_bytes(b"sparse fixture")
    state = {"loop": True, "backing": str(backing), "volume_free": 200,
             "backing_free": 80, "queries": []}
    real_path = Path
    loop = SimpleNamespace(is_file=lambda: state["loop"], read_text=lambda: state["backing"] + "\n")
    monkeypatch.setattr(storage, "Path", lambda value: loop if str(value).startswith("/sys/dev/block/") else real_path(value))
    monkeypatch.setattr(storage.os, "major", lambda _: 8)
    monkeypatch.setattr(storage.os, "minor", lambda _: 1)
    def statvfs(path):
        state["queries"].append(path)
        if path == root:
            return SimpleNamespace(f_bavail=state["volume_free"], f_frsize=4096, f_blocks=512)
        assert path == backing
        return SimpleNamespace(f_bavail=state["backing_free"], f_frsize=1024, f_blocks=1024)
    monkeypatch.setattr(storage.os, "statvfs", statvfs)
    return root, backing, state


def test_sparse_volume_free_does_not_replace_smaller_physical_backing_free(disk_case):
    root, backing, state = disk_case
    value = storage.storage_snapshot(root)
    assert value["capture_available_bytes"] == 200 * 4096
    assert value["physical_available_bytes"] == 80 * 1024
    assert value["available_bytes"] == 80 * 1024
    assert value["capture_capacity_bytes"] == 512 * 4096
    assert value["physical_capacity_bytes"] == 1024 * 1024
    assert value["backing_file"] == str(backing)
    assert state["queries"] == [root, backing]


def test_capture_filesystem_can_be_the_smaller_bound(disk_case):
    root, _, state = disk_case
    state["volume_free"] = 1
    assert storage.storage_snapshot(root)["available_bytes"] == 4096


def test_nonloop_filesystem_uses_its_own_available_blocks(disk_case):
    root, _, state = disk_case
    state["loop"] = False
    value = storage.storage_snapshot(root)
    assert value["available_bytes"] == 200 * 4096
    assert "physical_available_bytes" not in value
    assert state["queries"] == [root]


def test_known_loop_device_refuses_absent_backing_metadata(disk_case, monkeypatch):
    root, _, state = disk_case
    state["loop"] = False
    monkeypatch.setattr(storage.os, "major", lambda _: 7)
    with pytest.raises(ValueError, match="loop capture volume backing disk cannot be measured"):
        storage.storage_snapshot(root)
    assert state["queries"] == [root]


@pytest.mark.parametrize("kind", ["missing", "relative", "directory"])
def test_declared_backing_cannot_be_missing_relative_or_a_directory(disk_case, kind):
    root, backing, state = disk_case
    state["backing"] = {"missing": str(backing.parent / "missing.img"),
                        "relative": "relative.img", "directory": str(backing.parent)}[kind]
    with pytest.raises(ValueError, match="backing disk cannot be measured"):
        storage.storage_snapshot(root)
    assert state["queries"] == [root]


@pytest.mark.parametrize("reserve", [80 * 1024, 80 * 1024 + 1])
def test_equal_or_insufficient_physical_reserve_pauses(disk_case, reserve):
    root, _, _ = disk_case
    with pytest.raises(RuntimeError, match="capture paused"):
        storage.require_storage(root, reserve_bytes=reserve)


def test_strictly_positive_headroom_above_reserve_passes(disk_case):
    root, _, _ = disk_case
    value = storage.require_storage(root, reserve_bytes=80 * 1024 - 1)
    assert value["available_bytes"] == 80 * 1024


@pytest.mark.parametrize("reserve", [-1, True, 1.5, "100", None])
def test_reserve_requires_nonnegative_integer_bytes(disk_case, reserve):
    root, _, state = disk_case
    with pytest.raises(ValueError, match="nonnegative byte count"):
        storage.require_storage(root, reserve_bytes=reserve)
    assert state["queries"] == []
