"""Bounded archive staging and durability controls; no Git or Docker execution."""
import errno
import io
import os
from pathlib import Path
import stat
import tarfile
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_portable_runtime as runtime


def archive(rows):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as handle:
        for name, content, mode, kind in rows:
            member = tarfile.TarInfo(name)
            member.mode, member.type = mode, kind
            member.size = len(content) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = "outside"
            handle.addfile(member, io.BytesIO(content) if member.size else None)
    return output.getvalue()


def regular(name="nested/file", content=b"source", mode=0o644):
    return name, content, mode, tarfile.REGTYPE


def test_extract_exact_bytes_modes_and_no_per_file_durability(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("extraction must use the later batch fence")
    monkeypatch.setattr(runtime, "_create", forbidden)
    monkeypatch.setattr(runtime.os, "fsync", forbidden)
    root = tmp_path / "snapshot"
    runtime._extract(archive([regular(), regular("tools/run", b"executable", 0o777)]), root)
    assert (root / "nested/file").read_bytes() == b"source"
    assert stat.S_IMODE((root / "nested/file").stat().st_mode) == 0o644
    assert (root / "tools/run").read_bytes() == b"executable"
    assert stat.S_IMODE((root / "tools/run").stat().st_mode) == 0o755


def test_extract_is_create_only(tmp_path):
    root = tmp_path / "snapshot"
    root.mkdir()
    (root / "file").write_bytes(b"previous")
    with pytest.raises(FileExistsError):
        runtime._extract(archive([regular("file", b"replacement")]), root)
    assert (root / "file").read_bytes() == b"previous"


@pytest.mark.parametrize("bad", [
    regular("../escape"), regular("/escape"), regular(".git/config"),
    ("link", b"", 0o777, tarfile.SYMTYPE),
    ("link", b"", 0o777, tarfile.LNKTYPE),
    ("fifo", b"", 0o644, tarfile.FIFOTYPE),
])
def test_entire_archive_is_validated_before_first_write(tmp_path, bad):
    root = tmp_path / "snapshot"
    with pytest.raises(ValueError):
        runtime._extract(archive([regular("safe"), bad]), root)
    assert not root.exists()


def test_linked_ancestor_refused_before_escaped_directory_creation(tmp_path):
    outside, root = tmp_path / "outside", tmp_path / "snapshot"
    outside.mkdir(); root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="link"):
        runtime._extract(archive([regular("linked/new/file")]), root)
    assert list(outside.iterdir()) == []


def test_syncfs_once_on_snapshot_directory_then_close(tmp_path, monkeypatch):
    root = tmp_path / "snapshot"
    root.mkdir()
    calls, descriptors = [], []
    def flush(descriptor):
        descriptors.append(descriptor)
        calls.append(("syncfs", os.fstat(descriptor).st_ino))
        return 0
    monkeypatch.setattr(runtime.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(syncfs=flush))
    monkeypatch.setattr(runtime.os, "fsync", lambda fd: pytest.fail("unexpected per-file fsync"))
    runtime._flush_snapshot(root)
    assert calls == [("syncfs", root.stat().st_ino)]
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_syncfs_error_propagates_and_closes_descriptor(tmp_path, monkeypatch):
    root = tmp_path / "snapshot"
    root.mkdir()
    descriptors = []
    def flush(descriptor):
        descriptors.append(descriptor)
        return -1
    monkeypatch.setattr(runtime.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(syncfs=flush))
    monkeypatch.setattr(runtime.ctypes, "get_errno", lambda: errno.ENOSPC)
    with pytest.raises(OSError) as failure:
        runtime._flush_snapshot(root)
    assert failure.value.errno == errno.ENOSPC
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_fallback_flushes_regular_files_and_every_nested_directory(tmp_path, monkeypatch):
    root = tmp_path / "snapshot"
    (root / "a/b").mkdir(parents=True)
    (root / "a/b/file").write_bytes(b"source")
    paths = [root / "a/b/file", root / "a/b", root / "a", root]
    observations = []
    monkeypatch.setattr(runtime.ctypes, "CDLL", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(runtime.os, "fsync", lambda fd: observations.append(os.fstat(fd).st_ino))
    runtime._flush_snapshot(root)
    assert set(observations) == {path.stat().st_ino for path in paths}
    assert observations.index((root / "a/b").stat().st_ino) < observations.index(root.stat().st_ino)


@pytest.fixture
def staged_source(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    (checkout / "neqo-qcsd").mkdir(parents=True)
    docker = tmp_path / "docker"
    docker.write_bytes(b"mock executable")
    docker.chmod(0o755)
    native_commit, lab_commit = "d" * 40, "a" * 40
    archives = {"lab": archive([regular("source", b"lab")]),
                "native": archive([regular("Cargo.lock", b"lock")])}
    monkeypatch.setattr(runtime, "_clean", lambda *args: None)
    producer_paths = (runtime.SOURCE_PATH, runtime.CLI_PATH, runtime.VERIFIER_PATH)
    monkeypatch.setattr(runtime, "_read", lambda path: b"producer source"
        if any(str(path).endswith(name) for name in producer_paths) else Path(path).read_bytes())
    def git(path, *args):
        if "ls-files" in args:
            return f"160000 {native_commit} 0\tneqo-qcsd\n".encode()
        assert "archive" in args
        return archives["native" if Path(path).name == "neqo-qcsd" else "lab"]
    monkeypatch.setattr(runtime, "_git", git)
    return checkout, docker, lab_commit, native_commit, archives


def stage_fixture(source, root):
    checkout, docker, lab, native, _ = source
    return runtime.stage(checkout, lab, native, root, selected_platform="linux/amd64", docker=docker)


def test_failed_native_extraction_retains_partial_namespace_without_build_authority(staged_source, tmp_path):
    staged_source[-1]["native"] = archive([regular("../escape")])
    root = tmp_path / "runtime"
    with pytest.raises(ValueError):
        stage_fixture(staged_source, root)
    assert (root / "image-context/source/source").read_bytes() == b"lab"
    assert not (root / "build-inputs.json").exists()
    with pytest.raises(FileNotFoundError):
        runtime._inputs(root)
    with pytest.raises(ValueError, match="create-only"):
        stage_fixture(staged_source, root)


def test_failed_batch_flush_prevents_inventory_or_input_publication(staged_source, tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    def fail_flush(snapshot):
        assert (snapshot / "source").is_file()
        assert (snapshot / "neqo-qcsd/Cargo.lock").is_file()
        raise OSError(errno.ENOSPC, "flush failed")
    monkeypatch.setattr(runtime, "_flush_snapshot", fail_flush)
    monkeypatch.setattr(runtime, "_inventory", lambda path: pytest.fail("inventory preceded durability fence"))
    with pytest.raises(OSError, match="flush failed"):
        stage_fixture(staged_source, root)
    assert not (root / "source-inventory.json").exists()
    assert not (root / "build-inputs.json").exists()


def test_inventory_is_read_only_after_successful_batch_fence(staged_source, tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    order = []
    monkeypatch.setattr(runtime, "_flush_snapshot", lambda path: order.append("flush"))
    def inventory(path):
        order.append("inventory")
        raise RuntimeError("stop before metadata publication")
    monkeypatch.setattr(runtime, "_inventory", inventory)
    with pytest.raises(RuntimeError, match="stop before metadata"):
        stage_fixture(staged_source, root)
    assert order == ["flush", "inventory"]
    assert not (root / "build-inputs.json").exists()
