from __future__ import annotations

import base64
import copy
import ctypes
import fcntl
import hashlib
import json
import os
import select
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from qcsd_lab import cohort_allocation

BASE_VERSION = 3
MODULE = Path(cohort_allocation.__file__).resolve()
IDENTITY_KEYS = {
    "dev",
    "inode",
    "uid",
    "gid",
    "mode",
    "nlink",
    "size",
    "mtime_ns",
    "ctime_ns",
}


def _canonical(value: Any, *, newline: bool = False) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return raw + (b"\n" if newline else b"")


def _identity(seed: int) -> dict[str, int]:
    return {
        "dev": seed,
        "inode": seed + 1,
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "mode": 0o600,
        "nlink": 1,
        "size": seed + 2,
        "mtime_ns": seed + 3,
        "ctime_ns": seed + 4,
    }


def _ledger_raw(*, base: int = BASE_VERSION, marker: str | None = None) -> bytes:
    ledger: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-consumed-cohorts",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "consumed_versions": list(range(1, base + 1)),
    }
    if marker is not None:
        # A semantically equivalent spelling with a distinct byte-level Git binding.
        return json.dumps(ledger, sort_keys=marker == "sorted").encode("ascii") + b"\n"
    return _canonical(ledger, newline=True)


def _blob_oid(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def _git_oid(object_type: bytes, raw: bytes) -> str:
    return hashlib.sha1(
        object_type + b" " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()


def _tree_payload(entries: list[tuple[bytes, bytes, str]]) -> bytes:
    ordered = sorted(
        entries,
        key=lambda entry: entry[1] + (b"/" if entry[0] == b"40000" else b""),
    )
    return b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid) for mode, name, oid in ordered)


def _git_proof(
    *,
    ledger_blob_oid: str,
    neqo_gitlink: str,
    marker: str,
    ledger_mode: bytes = b"100644",
    ledger_name: bytes = b"consumed-cohorts.json",
) -> tuple[str, dict[str, Any]]:
    version_tree = _tree_payload([(ledger_mode, ledger_name, ledger_blob_oid)])
    study_tree = _tree_payload([(b"40000", b"v1", _git_oid(b"tree", version_tree))])
    config_tree = _tree_payload([(b"40000", b"buflo-study", _git_oid(b"tree", study_tree))])
    root_tree = _tree_payload(
        [
            (b"40000", b"config", _git_oid(b"tree", config_tree)),
            (b"160000", b"neqo-qcsd", neqo_gitlink),
        ]
    )
    commit = (
        f"tree {_git_oid(b'tree', root_tree)}\n"
        "author Test <test@example.invalid> 0 +0000\n"
        "committer Test <test@example.invalid> 0 +0000\n"
        f"\nfixture-{marker}\n"
    ).encode("ascii")
    return _git_oid(b"commit", commit), {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-ledger-git-proof",
        "commit_payload_base64": base64.b64encode(commit).decode("ascii"),
        "tree_payloads_base64": [
            base64.b64encode(tree).decode("ascii")
            for tree in (root_tree, config_tree, study_tree, version_tree)
        ],
    }


def _authority(
    allocated: int,
    *,
    ledger_raw: bytes | None = None,
    lab_character: str = "a",
    neqo_character: str = "b",
) -> dict[str, Any]:
    raw = ledger_raw if ledger_raw is not None else _ledger_raw()
    blob = _blob_oid(raw)
    neqo = neqo_character * 40
    lab, proof = _git_proof(
        ledger_blob_oid=blob,
        neqo_gitlink=neqo,
        marker=lab_character,
    )
    receipt = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-allocation",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "ledger_path": "config/buflo-study/v1/consumed-cohorts.json",
        "ledger_sha256": hashlib.sha256(raw).hexdigest(),
        "ledger_payload_base64": base64.b64encode(raw).decode("ascii"),
        "git_object_format": "sha1",
        "ledger_git_blob_oid": blob,
        "lab_commit": lab,
        "neqo_commit": neqo,
        "neqo_gitlink": neqo,
        "lab_commit_ledger_proof": proof,
        "last_consumed_version": BASE_VERSION,
        "allocated_version": allocated,
    }
    directories = {
        name: _identity(10 * (index + 1))
        for index, name in enumerate(("repository-root", "config", "buflo-study", "v1", "git"))
    }
    ledger_identity = _identity(100)
    ledger_identity["size"] = len(raw)
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-allocation-authority",
        "git": {
            "object_format": "sha1",
            "lab_head": lab,
            "head_blob_oid": blob,
            "index_blob_oid": blob,
            "worktree_blob_oid": blob,
            "neqo_head": neqo,
            "head_gitlink": neqo,
            "index_gitlink": neqo,
        },
        "filesystem": {
            "directories": directories,
            "ledger": ledger_identity,
            "git_index": _identity(200),
        },
        "receipt": receipt,
    }


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "lab"
    (root / "artifacts" / "buflo-study").mkdir(parents=True)
    return root


def _registry(root: Path) -> Path:
    return root / "artifacts" / "buflo-study" / "cohort-claims-v1"


def _claim(root: Path, version: int) -> Path:
    return _registry(root) / f"claim-v{version}.json"


def _anchor(root: Path, version: int) -> Path:
    return _registry(root) / f".consumed-v{version}.json"


def _reseal_snapshot(value: dict[str, Any]) -> None:
    payload = dict(value)
    payload.pop("payload_sha256", None)
    value["payload_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()


def _rewrite_claim(root: Path, version: int, value: dict[str, Any]) -> None:
    path = _claim(root, version)
    path.write_bytes(_canonical(value, newline=True))
    path.chmod(0o600)


def _run_cli(
    action: str,
    root: Path,
    value: Any,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-I", str(MODULE), action, "--root", str(root)]
    return subprocess.run(
        command,
        input=_canonical(value).decode("ascii"),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def _held_registry_lock(root: Path) -> int:
    registry_fd, _metadata = cohort_allocation._open_registry(root, create=True)
    try:
        allocation_fd = cohort_allocation._open_registry_lock(registry_fd, create=True)
        try:
            operation_fd = cohort_allocation._open_operation_lock(registry_fd, create=True)
            os.close(operation_fd)
            return allocation_fd
        except BaseException:
            os.close(allocation_fd)
            raise
    finally:
        os.close(registry_fd)


_GUARDED_OWNER = r"""
import os
import subprocess
import sys

def identity(pid):
    raw = open(f"/proc/{pid}/stat", "rb").read()
    fields = raw[raw.rfind(b") ") + 2:].split()
    return int(fields[1]), int(fields[19])

(
    module, action, root, guardian_pid, guardian_start, guardian_fd,
    lock_path, device, inode, parent_device, parent_inode, cohort,
) = sys.argv[1:]
owner_start = identity(os.getpid())[1]
for candidate in os.listdir("/proc/self/fd"):
    try:
        observed = os.fstat(int(candidate))
    except OSError:
        continue
    if (observed.st_dev, observed.st_ino) == (int(device), int(inode)):
        raise SystemExit("guardian lock FD leaked into its qcsd child")
command = [
    sys.executable, "-I", module, action, "--root", root,
    "--held-lock-owner-pid", str(os.getpid()),
    "--held-lock-owner-start", str(owner_start),
    "--held-lock-guardian-pid", guardian_pid,
    "--held-lock-guardian-start", guardian_start,
    "--held-lock-guardian-fd", guardian_fd,
    "--held-lock-path", lock_path,
    "--held-lock-device", device,
    "--held-lock-inode", inode,
    "--held-lock-parent-device", parent_device,
    "--held-lock-parent-inode", parent_inode,
    "--held-lock-cohort-version", cohort,
]
result = subprocess.run(command, input=sys.stdin.buffer.read(), capture_output=True)
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
"""


def _run_guarded_cli(
    action: str,
    root: Path,
    value: Any,
    held_lock_fd: int,
    *,
    cohort_version: int,
    overrides: dict[str, int | str] | None = None,
) -> subprocess.CompletedProcess[str]:
    lock_path = _registry(root) / ".allocation.lock"
    lock_stat = lock_path.stat()
    parent_stat = _registry(root).stat()
    guardian_pid = os.getpid()
    guardian_start = cohort_allocation._process_identity(guardian_pid)[1]
    binding: dict[str, int | str] = {
        "guardian_pid": guardian_pid,
        "guardian_start": guardian_start,
        "guardian_fd": held_lock_fd,
        "lock_path": str(lock_path),
        "device": lock_stat.st_dev,
        "inode": lock_stat.st_ino,
        "parent_device": parent_stat.st_dev,
        "parent_inode": parent_stat.st_ino,
        "cohort": cohort_version,
    }
    if overrides:
        binding.update(overrides)
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _GUARDED_OWNER,
            str(MODULE),
            action,
            str(root),
            str(binding["guardian_pid"]),
            str(binding["guardian_start"]),
            str(binding["guardian_fd"]),
            str(binding["lock_path"]),
            str(binding["device"]),
            str(binding["inode"]),
            str(binding["parent_device"]),
            str(binding["parent_inode"]),
            str(binding["cohort"]),
        ],
        input=_canonical(value).decode("ascii"),
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        close_fds=True,
    )


def test_publish_is_canonical_permanent_and_exactly_verifiable(tmp_path: Path) -> None:
    root = _root(tmp_path)
    authority = _authority(4)

    snapshot = cohort_allocation.publish_cohort_claim(root, authority)

    registry = _registry(root)
    claim = _claim(root, 4)
    assert registry.is_dir()
    assert stat.S_IMODE(registry.stat().st_mode) == 0o700
    assert claim.is_file()
    assert stat.S_IMODE(claim.stat().st_mode) == 0o600
    assert claim.stat().st_nlink == 1
    assert claim.read_bytes() == base64.b64decode(snapshot["claim"]["payload_base64"])
    assert _anchor(root, 4).read_bytes() == claim.read_bytes()
    assert stat.S_IMODE(_anchor(root, 4).stat().st_mode) == 0o600
    assert _anchor(root, 4).stat().st_nlink == 1
    assert snapshot["claim"]["sha256"] == hashlib.sha256(claim.read_bytes()).hexdigest()
    stored = json.loads(claim.read_text(encoding="ascii"))
    assert stored["payload"]["authority"] == authority
    assert stored["payload"]["cohort_version"] == 4
    assert stored["payload"]["predecessor"] == {
        "kind": "genesis-ledger",
        "cohort_version": 3,
        "sha256": authority["receipt"]["ledger_sha256"],
    }
    assert claim.read_bytes() == _canonical(stored, newline=True)
    assert cohort_allocation.verify_cohort_claim(root, snapshot) == snapshot


def test_successors_form_a_dense_hash_chain_and_old_snapshots_remain_valid(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    first = cohort_allocation.publish_cohort_claim(root, _authority(4))
    second_authority = _authority(5, lab_character="c", neqo_character="d")
    second = cohort_allocation.publish_cohort_claim(root, second_authority)

    second_claim = json.loads(_claim(root, 5).read_text(encoding="ascii"))
    assert second_claim["payload"]["predecessor"] == {
        "kind": "cohort-claim",
        "cohort_version": 4,
        "sha256": first["claim"]["sha256"],
    }
    assert second_claim["payload"]["source"] == {
        "lab_commit": second_authority["receipt"]["lab_commit"],
        "neqo_commit": "d" * 40,
        "neqo_gitlink": "d" * 40,
    }
    assert cohort_allocation.verify_cohort_claim(root, first) == first
    assert cohort_allocation.verify_cohort_claim(root, second) == second


def test_chain_is_closed_at_snapshot_and_cli_emits_the_same_exact_proof(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    first = cohort_allocation.publish_cohort_claim(root, _authority(4))
    cohort_allocation.publish_cohort_claim(
        root, _authority(5, lab_character="c", neqo_character="d")
    )

    chain = cohort_allocation.cohort_claim_chain(root, first)

    assert set(chain) == {
        "schema_version",
        "artifact_type",
        "policy",
        "genesis",
        "claims",
        "head",
        "payload_sha256",
    }
    assert chain["artifact_type"] == "qcsd-buflo-study-cohort-claim-chain"
    assert chain["policy"] == "dense-prefix-durable-publications-consume-v1"
    assert chain["genesis"] == {
        "ledger_path": "config/buflo-study/v1/consumed-cohorts.json",
        "ledger_sha256": _authority(4)["receipt"]["ledger_sha256"],
        "last_consumed_version": 3,
    }
    assert [item["cohort_version"] for item in chain["claims"]] == [4]
    assert chain["claims"][0]["payload_base64"] == first["claim"]["payload_base64"]
    assert chain["head"] == {
        "cohort_version": 4,
        "sha256": first["claim"]["sha256"],
    }
    payload = dict(chain)
    digest = payload.pop("payload_sha256")
    assert digest == hashlib.sha256(_canonical(payload)).hexdigest()

    cli = _run_cli("chain", root, first)
    assert cli.returncode == 0, cli.stderr
    assert cli.stdout.encode("ascii") == _canonical(chain, newline=True)


def test_guardian_remote_lock_proof_spans_publish_verify_and_chain(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    held_lock_fd = _held_registry_lock(root)
    try:
        published = _run_guarded_cli(
            "publish",
            root,
            _authority(4),
            held_lock_fd,
            cohort_version=4,
        )
        assert published.returncode == 0, published.stderr
        snapshot = json.loads(published.stdout)

        verified = _run_guarded_cli(
            "verify",
            root,
            snapshot,
            held_lock_fd,
            cohort_version=4,
        )
        assert verified.returncode == 0, verified.stderr
        assert verified.stdout == published.stdout

        chained = _run_guarded_cli(
            "chain",
            root,
            snapshot,
            held_lock_fd,
            cohort_version=4,
        )
        assert chained.returncode == 0, chained.stderr
        assert json.loads(chained.stdout)["head"]["cohort_version"] == 4

        contender = os.open(_registry(root) / ".allocation.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)
    finally:
        os.close(held_lock_fd)


def test_guardian_death_cannot_leave_an_allocator_mutating_past_b_drain(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    authority = _authority(4)
    ready_read, ready_write = os.pipe()
    guardian_pid = os.fork()
    if guardian_pid == 0:
        os.close(ready_read)
        registry_fd = allocation_fd = operation_fd = -1
        try:
            registry_fd, _metadata = cohort_allocation._open_registry(root, create=True)
            allocation_fd = cohort_allocation._open_registry_lock(registry_fd, create=True)
            operation_fd = cohort_allocation._open_operation_lock(registry_fd, create=True)
            os.close(operation_fd)
            operation_fd = -1
            allocation = os.fstat(allocation_fd)
            registry = os.fstat(registry_fd)
            guardian_identity_pid = os.getpid()
            guardian_start = cohort_allocation._process_identity(guardian_identity_pid)[1]
            owner_pid = os.fork()
            if owner_pid == 0:
                # Model the lifecycle guardian's death-bound qcsd child without
                # passing either authority lock into its allocator descendant.
                os.close(allocation_fd)
                os.close(registry_fd)
                libc = ctypes.CDLL(None, use_errno=True)
                if (
                    libc.prctl(
                        cohort_allocation.PR_SET_PDEATHSIG,
                        signal.SIGKILL,
                        0,
                        0,
                        0,
                    )
                    != 0
                    or os.getppid() != guardian_identity_pid
                ):
                    os.write(ready_write, b"error:qcsd-owner-death-binding\n")
                    os._exit(70)
                owner_start = cohort_allocation._process_identity(os.getpid())[1]
                allocator_pid = os.fork()
                if allocator_pid == 0:
                    lock = cohort_allocation.GuardianLockAuthority(
                        owner_pid=os.getppid(),
                        owner_start=owner_start,
                        guardian_pid=guardian_identity_pid,
                        guardian_start=guardian_start,
                        guardian_fd=allocation_fd,
                        path=str(_registry(root) / ".allocation.lock"),
                        device=allocation.st_dev,
                        inode=allocation.st_ino,
                        parent_device=registry.st_dev,
                        parent_inode=registry.st_ino,
                        cohort_version=4,
                    )

                    def pause_before_first_rename(
                        _directory_fd: int, _source: str, _destination: str
                    ) -> None:
                        os.write(ready_write, f"ready:{os.getpid()}\n".encode("ascii"))
                        while True:
                            signal.pause()

                    cohort_allocation._rename_noreplace = pause_before_first_rename
                    try:
                        cohort_allocation.publish_cohort_claim(root, authority, guardian_lock=lock)
                    except BaseException as error:  # noqa: BLE001 - child reports all exits
                        os.write(
                            ready_write,
                            f"error:{type(error).__name__}:{error}\n".encode(
                                "utf-8", errors="replace"
                            ),
                        )
                    os._exit(71)
                _pid, allocator_status = os.waitpid(allocator_pid, 0)
                os.write(
                    ready_write,
                    f"error:allocator-exited:{allocator_status}\n".encode("ascii"),
                )
                os._exit(0)
            os.close(ready_write)
            while True:
                signal.pause()
        except BaseException as error:  # noqa: BLE001 - child reports all exits
            try:
                os.write(
                    ready_write,
                    f"error:{type(error).__name__}:{error}\n".encode("utf-8", errors="replace"),
                )
            finally:
                os._exit(72)

    os.close(ready_write)
    allocator_pid = -1
    allocator_pidfd = -1
    allocation_fd = operation_fd = registry_fd = -1
    try:
        readable, _writable, _exceptional = select.select([ready_read], [], [], 10)
        assert readable, "allocator did not reach its held-B publication boundary"
        message = os.read(ready_read, 4096).decode("utf-8", errors="replace").strip()
        assert message.startswith("ready:"), message
        allocator_pid = int(message.removeprefix("ready:"))
        allocator_pidfd = os.pidfd_open(allocator_pid, 0)

        os.kill(guardian_pid, signal.SIGKILL)
        _pid, status = os.waitpid(guardian_pid, 0)
        assert os.WIFSIGNALED(status)
        assert os.WTERMSIG(status) == signal.SIGKILL

        # A successor first owns A, then drains B.  It cannot inspect or mutate
        # the registry concurrently with the old allocator even in the narrow
        # guardian-death/qcsd-death scheduling interval.
        registry_fd, _metadata = cohort_allocation._open_registry(root, create=False)
        allocation_fd = cohort_allocation._open_registry_lock(registry_fd, create=False)
        operation_fd = os.open(
            cohort_allocation.COHORT_OPERATION_LOCK_NAME,
            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=registry_fd,
        )
        deadline = time.monotonic() + 10
        while True:
            try:
                fcntl.flock(operation_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                assert time.monotonic() < deadline, "orphan allocator retained B"
                time.sleep(0.01)
        death_events = select.poll()
        death_events.register(
            allocator_pidfd,
            select.POLLIN | select.POLLHUP | select.POLLERR,
        )
        assert death_events.poll(1_000), "orphan allocator remained alive after B drained"
        assert not _claim(root, 4).exists()
        assert not _anchor(root, 4).exists()
    finally:
        os.close(ready_read)
        if allocator_pidfd >= 0:
            os.close(allocator_pidfd)
        if operation_fd >= 0:
            os.close(operation_fd)
        if allocation_fd >= 0:
            os.close(allocation_fd)
        if registry_fd >= 0:
            os.close(registry_fd)
        try:
            os.kill(guardian_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if allocator_pid > 0:
            try:
                os.kill(allocator_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    snapshot = cohort_allocation.publish_cohort_claim(root, authority)
    assert snapshot["cohort_version"] == 4
    assert _claim(root, 4).is_file()
    assert not tuple(_registry(root).glob(".claim-v4.*.next"))


@pytest.mark.parametrize(
    ("mutation", "overrides"),
    [
        ("unlocked", {}),
        ("guardian-start", {"guardian_start": 1}),
        ("guardian-pid", {"guardian_pid": 1}),
        ("guardian-fd", {"guardian_fd": 999_999}),
        ("path", {"lock_path": "/not/the/canonical/lock"}),
        ("device", {"device": 1}),
        ("inode", {"inode": 1}),
        ("parent-device", {"parent_device": 1}),
        ("parent-inode", {"parent_inode": 1}),
        ("cohort", {"cohort": 5}),
    ],
)
def test_guardian_remote_lock_proof_rejects_spoofed_or_unlocked_authority(
    tmp_path: Path,
    mutation: str,
    overrides: dict[str, int | str],
) -> None:
    root = _root(tmp_path)
    held_lock_fd = _held_registry_lock(root)
    if mutation == "unlocked":
        fcntl.flock(held_lock_fd, fcntl.LOCK_UN)
    try:
        result = _run_guarded_cli(
            "publish",
            root,
            _authority(4),
            held_lock_fd,
            cohort_version=4,
            overrides=overrides,
        )
        assert result.returncode == 1
        assert "cohort allocation is invalid" in result.stderr
        assert not _claim(root, 4).exists()
    finally:
        os.close(held_lock_fd)


def test_guardian_remote_lock_proof_rejects_replaced_canonical_lock(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    held_lock_fd = _held_registry_lock(root)
    lock = _registry(root) / ".allocation.lock"
    moved = _registry(root) / ".allocation.lock.moved"
    lock.rename(moved)
    lock.write_bytes(b"")
    lock.chmod(0o600)
    try:
        result = _run_guarded_cli(
            "publish",
            root,
            _authority(4),
            held_lock_fd,
            cohort_version=4,
        )
        assert result.returncode == 1
        assert not _claim(root, 4).exists()
    finally:
        os.close(held_lock_fd)


def test_fresh_parent_directories_are_private_and_durably_linked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cold-lab"
    root.mkdir(mode=0o700)
    synced_directories: set[int] = set()
    real_fsync = os.fsync

    def observe_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            synced_directories.add(metadata.st_ino)
        real_fsync(descriptor)

    monkeypatch.setattr(cohort_allocation.os, "fsync", observe_fsync)
    cohort_allocation.publish_cohort_claim(root, _authority(4))

    for directory in (
        root,
        root / "artifacts",
        root / "artifacts" / "buflo-study",
        _registry(root),
    ):
        assert directory.stat().st_ino in synced_directories
    assert stat.S_IMODE((root / "artifacts").stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "artifacts" / "buflo-study").stat().st_mode) == 0o700


def test_open_root_tolerates_benign_ancestor_content_metadata_churn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repository"
    root.mkdir(mode=0o700)
    ancestor = tmp_path.stat()
    unrelated = tmp_path / "unrelated-directory"
    real_fstat = os.fstat
    snapshot: os.stat_result | None = None

    def create_unrelated_child_after_snapshot(descriptor: int) -> os.stat_result:
        nonlocal snapshot
        observed = real_fstat(descriptor)
        if (
            snapshot is None
            and observed.st_dev == ancestor.st_dev
            and observed.st_ino == ancestor.st_ino
        ):
            snapshot = observed
            unrelated.mkdir(mode=0o700)
        return observed

    monkeypatch.setattr(cohort_allocation.os, "fstat", create_unrelated_child_after_snapshot)
    descriptor = cohort_allocation._open_root(root)
    try:
        opened = real_fstat(descriptor)
        expected = root.stat()
        assert (opened.st_dev, opened.st_ino) == (expected.st_dev, expected.st_ino)
    finally:
        os.close(descriptor)

    assert snapshot is not None
    current = tmp_path.stat()
    assert snapshot.st_nlink != current.st_nlink


def test_open_root_rejects_unsafe_ancestor_mode_drift_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ancestor = tmp_path / "ancestor"
    ancestor.mkdir(mode=0o700)
    root = ancestor / "repository"
    root.mkdir(mode=0o700)
    ancestor_identity = ancestor.stat()
    real_fstat = os.fstat
    changed = False

    def weaken_ancestor_after_snapshot(descriptor: int) -> os.stat_result:
        nonlocal changed
        observed = real_fstat(descriptor)
        if (
            not changed
            and observed.st_dev == ancestor_identity.st_dev
            and observed.st_ino == ancestor_identity.st_ino
        ):
            changed = True
            ancestor.chmod(0o777)
        return observed

    monkeypatch.setattr(cohort_allocation.os, "fstat", weaken_ancestor_after_snapshot)
    try:
        with pytest.raises(
            cohort_allocation.CohortAllocationError,
            match="allocation root component directory identity is unsafe",
        ):
            cohort_allocation._open_root(root)
    finally:
        ancestor.chmod(0o700)

    assert changed


def test_open_root_rejects_same_metadata_ancestor_replacement_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ancestor = tmp_path / "ancestor"
    ancestor.mkdir(mode=0o700)
    root = ancestor / "repository"
    root.mkdir(mode=0o700)
    ancestor_identity = ancestor.stat()
    moved = tmp_path / "opened-ancestor"
    real_fstat = os.fstat
    replacement_identity: os.stat_result | None = None

    def replace_ancestor_after_snapshot(descriptor: int) -> os.stat_result:
        nonlocal replacement_identity
        observed = real_fstat(descriptor)
        if (
            replacement_identity is None
            and observed.st_dev == ancestor_identity.st_dev
            and observed.st_ino == ancestor_identity.st_ino
        ):
            ancestor.rename(moved)
            ancestor.mkdir(mode=stat.S_IMODE(observed.st_mode))
            replacement_identity = ancestor.stat()
        return observed

    monkeypatch.setattr(cohort_allocation.os, "fstat", replace_ancestor_after_snapshot)
    with pytest.raises(
        cohort_allocation.CohortAllocationError,
        match="allocation root component directory identity is unsafe",
    ):
        cohort_allocation._open_root(root)

    assert replacement_identity is not None
    assert replacement_identity.st_dev == ancestor_identity.st_dev
    assert replacement_identity.st_ino != ancestor_identity.st_ino
    assert replacement_identity.st_uid == ancestor_identity.st_uid
    assert replacement_identity.st_gid == ancestor_identity.st_gid
    assert stat.S_IMODE(replacement_identity.st_mode) == stat.S_IMODE(ancestor_identity.st_mode)


def test_cold_parent_fsync_failure_admits_no_claim_and_retry_is_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cold-lab"
    root.mkdir(mode=0o700)
    root_inode = root.stat().st_ino
    real_fsync = os.fsync
    failed = False

    def fail_first_root_fsync(descriptor: int) -> None:
        nonlocal failed
        if not failed and os.fstat(descriptor).st_ino == root_inode:
            failed = True
            raise OSError("injected cold-parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(cohort_allocation.os, "fsync", fail_first_root_fsync)
    with pytest.raises(OSError, match="cold-parent fsync failure"):
        cohort_allocation.publish_cohort_claim(root, _authority(4))
    assert not _registry(root).exists()

    monkeypatch.setattr(cohort_allocation.os, "fsync", real_fsync)
    snapshot = cohort_allocation.publish_cohort_claim(root, _authority(4))
    assert snapshot["cohort_version"] == 4


def test_authority_may_name_a_future_version_but_publication_requires_exact_head_plus_one(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    future_authority = _authority(5)

    with pytest.raises(cohort_allocation.CohortAllocationError, match="exact next cohort is v4"):
        cohort_allocation.publish_cohort_claim(root, future_authority)

    assert list(_registry(root).glob("claim-v*.json")) == []
    cohort_allocation.publish_cohort_claim(root, _authority(4))
    retried = cohort_allocation.publish_cohort_claim(root, future_authority)
    assert retried["cohort_version"] == 5


def test_duplicate_claim_is_rejected_without_changing_the_permanent_file(tmp_path: Path) -> None:
    root = _root(tmp_path)
    authority = _authority(4)
    first = cohort_allocation.publish_cohort_claim(root, authority)
    before = _claim(root, 4).read_bytes()
    before_stat = _claim(root, 4).stat()

    with pytest.raises(cohort_allocation.CohortAllocationError, match="exact next cohort is v5"):
        cohort_allocation.publish_cohort_claim(root, authority)

    after_stat = _claim(root, 4).stat()
    assert _claim(root, 4).read_bytes() == before
    assert (after_stat.st_dev, after_stat.st_ino, after_stat.st_ctime_ns) == (
        before_stat.st_dev,
        before_stat.st_ino,
        before_stat.st_ctime_ns,
    )
    assert cohort_allocation.verify_cohort_claim(root, first) == first


def test_concurrent_duplicate_launchers_are_serialised_to_one_claim(tmp_path: Path) -> None:
    root = _root(tmp_path)
    authority = _authority(4)
    command = [sys.executable, "-I", str(MODULE), "publish", "--root", str(root)]
    payload = _canonical(authority)
    processes = [
        subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(2)
    ]
    results = [process.communicate(payload, timeout=15) for process in processes]

    assert sorted(process.returncode for process in processes) == [0, 1]
    successful = [
        stdout for process, (stdout, _stderr) in zip(processes, results) if process.returncode == 0
    ]
    failed = [
        stderr for process, (_stdout, stderr) in zip(processes, results) if process.returncode == 1
    ]
    assert len(successful) == 1
    assert len(successful[0].splitlines()) == 1
    assert b"exact next cohort is v5" in failed[0]
    assert [path.name for path in _registry(root).glob("claim-v*.json")] == ["claim-v4.json"]
    assert not list(_registry(root).glob(".*.next"))


def test_registry_gap_is_rejected(tmp_path: Path) -> None:
    root = _root(tmp_path)
    cohort_allocation.publish_cohort_claim(root, _authority(4))
    gap = _claim(root, 6)
    gap.write_bytes(_claim(root, 4).read_bytes())
    gap.chmod(0o600)

    with pytest.raises(cohort_allocation.CohortAllocationError, match="not one dense suffix"):
        cohort_allocation.publish_cohort_claim(root, _authority(5))


@pytest.mark.parametrize("mutation", ["bytes", "mode", "hardlink", "deleted"])
def test_verify_rejects_claim_byte_or_metadata_tampering(tmp_path: Path, mutation: str) -> None:
    root = _root(tmp_path)
    snapshot = cohort_allocation.publish_cohort_claim(root, _authority(4))
    claim = _claim(root, 4)
    if mutation == "bytes":
        raw = claim.read_bytes()
        claim.write_bytes(raw[:-2] + b" \n")
    elif mutation == "mode":
        claim.chmod(0o620)
    elif mutation == "hardlink":
        os.link(claim, tmp_path / "second-link")
    else:
        claim.unlink()

    with pytest.raises(cohort_allocation.CohortAllocationError):
        cohort_allocation.verify_cohort_claim(root, snapshot)
    if mutation == "deleted":
        assert not claim.exists()
        assert _anchor(root, 4).exists()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink", "writable"])
def test_unsafe_create_only_claim_destination_is_never_replaced(tmp_path: Path, kind: str) -> None:
    root = _root(tmp_path)
    registry = _registry(root)
    registry.mkdir(mode=0o700)
    destination = _claim(root, 4)
    outside = tmp_path / "outside"
    outside.write_bytes(b"sentinel")
    outside.chmod(0o600)
    if kind == "symlink":
        destination.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(destination, 0o600)
    elif kind == "hardlink":
        os.link(outside, destination)
    else:
        destination.write_bytes(b"sentinel")
        destination.chmod(0o620)

    with pytest.raises(cohort_allocation.CohortAllocationError):
        cohort_allocation.publish_cohort_claim(root, _authority(4))

    assert outside.read_bytes() == b"sentinel"
    assert os.path.lexists(destination)
    if kind == "hardlink":
        assert os.lstat(destination).st_ino == outside.stat().st_ino


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink", "writable"])
def test_unsafe_registry_lock_is_rejected(tmp_path: Path, kind: str) -> None:
    root = _root(tmp_path)
    registry = _registry(root)
    registry.mkdir(mode=0o700)
    lock = registry / ".allocation.lock"
    outside = tmp_path / "outside-lock"
    outside.write_bytes(b"")
    outside.chmod(0o600)
    if kind == "symlink":
        lock.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(lock, 0o600)
    elif kind == "hardlink":
        os.link(outside, lock)
    else:
        lock.write_bytes(b"")
        lock.chmod(0o620)

    with pytest.raises(cohort_allocation.CohortAllocationError):
        cohort_allocation.publish_cohort_claim(root, _authority(4))


@pytest.mark.parametrize("kind", ["symlink", "writable"])
def test_unsafe_registry_directory_is_rejected(tmp_path: Path, kind: str) -> None:
    root = _root(tmp_path)
    registry = _registry(root)
    if kind == "symlink":
        outside = tmp_path / "outside-registry"
        outside.mkdir(mode=0o700)
        registry.symlink_to(outside, target_is_directory=True)
    else:
        registry.mkdir(mode=0o700)
        registry.chmod(0o770)

    with pytest.raises(cohort_allocation.CohortAllocationError):
        cohort_allocation.publish_cohort_claim(root, _authority(4))


def test_exact_private_temp_residue_is_reclaimed_before_publication(tmp_path: Path) -> None:
    root = _root(tmp_path)
    cohort_allocation.publish_cohort_claim(root, _authority(4))
    residue = _registry(root) / f".claim-v5.{'1' * 64}.next"
    residue.write_bytes(b"pre-publication residue")
    residue.chmod(0o600)

    snapshot = cohort_allocation.publish_cohort_claim(root, _authority(5))

    assert not residue.exists()
    assert cohort_allocation.verify_cohort_claim(root, snapshot) == snapshot


@pytest.mark.parametrize("kind", ["bad-name", "mode", "symlink", "fifo", "hardlink"])
def test_nonprivate_or_malformed_temp_residue_blocks_publication(tmp_path: Path, kind: str) -> None:
    root = _root(tmp_path)
    cohort_allocation.publish_cohort_claim(root, _authority(4))
    registry = _registry(root)
    exact_name = f".claim-v5.{'2' * 64}.next"
    residue = registry / (".claim-v5.short.next" if kind == "bad-name" else exact_name)
    outside = tmp_path / "outside-residue"
    outside.write_bytes(b"sentinel")
    outside.chmod(0o600)
    if kind == "mode":
        residue.write_bytes(b"residue")
        residue.chmod(0o640)
    elif kind == "symlink":
        residue.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(residue, 0o600)
    elif kind == "hardlink":
        os.link(outside, residue)
    else:
        residue.write_bytes(b"residue")
        residue.chmod(0o600)

    with pytest.raises(cohort_allocation.CohortAllocationError):
        cohort_allocation.publish_cohort_claim(root, _authority(5))


def test_failed_rename_leaves_no_claim_or_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)

    def fail_rename(_fd: int, _source: str, _destination: str) -> None:
        raise OSError("injected rename failure")

    monkeypatch.setattr(cohort_allocation, "_rename_noreplace", fail_rename)
    with pytest.raises(OSError, match="injected rename failure"):
        cohort_allocation.publish_cohort_claim(root, _authority(4))

    assert not list(_registry(root).glob("claim-v*.json"))
    assert not list(_registry(root).glob(".*.next"))


def test_sigkill_before_first_rename_leaves_only_nonconsuming_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    real_rename = cohort_allocation._rename_noreplace

    def die_before_rename(_fd: int, _source: str, _destination: str) -> None:
        os.kill(os.getpid(), signal.SIGKILL)

    monkeypatch.setattr(cohort_allocation, "_rename_noreplace", die_before_rename)
    child = os.fork()
    if child == 0:
        cohort_allocation.publish_cohort_claim(root, _authority(4))
        os._exit(99)
    _pid, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == signal.SIGKILL
    assert not _claim(root, 4).exists()
    assert not _anchor(root, 4).exists()
    residues = list(_registry(root).glob(".claim-v4.*.next"))
    assert len(residues) == 1

    monkeypatch.setattr(cohort_allocation, "_rename_noreplace", real_rename)
    snapshot = cohort_allocation.publish_cohort_claim(root, _authority(4))
    assert snapshot["cohort_version"] == 4
    assert not residues[0].exists()


def test_publish_reclaims_safe_stale_temporaries_before_entry_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    cohort_allocation.publish_cohort_claim(root, _authority(4))
    registry = _registry(root)
    residues = []
    for index in range(4):
        residue = registry / f".claim-v5.{index:064x}.next"
        residue.write_bytes(b"pre-publication residue")
        residue.chmod(0o600)
        residues.append(residue)
    # A, B, the v4 pair, and four residues exceed this bound.  Cleanup under
    # A+B must run before the bounded authoritative registry scan.
    monkeypatch.setattr(cohort_allocation, "MAX_REGISTRY_ENTRIES", 6)

    snapshot = cohort_allocation.publish_cohort_claim(
        root, _authority(5, lab_character="c", neqo_character="d")
    )

    assert snapshot["cohort_version"] == 5
    assert all(not residue.exists() for residue in residues)
    assert len(tuple(registry.iterdir())) == 6


def test_claim_only_post_rename_crash_is_consumed_repaired_then_extended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    real_rename = cohort_allocation._rename_noreplace

    def die_after_claim_rename(directory_fd: int, source: str, destination: str) -> None:
        real_rename(directory_fd, source, destination)
        if destination == "claim-v4.json":
            os.kill(os.getpid(), signal.SIGKILL)

    monkeypatch.setattr(cohort_allocation, "_rename_noreplace", die_after_claim_rename)
    child = os.fork()
    if child == 0:
        cohort_allocation.publish_cohort_claim(root, _authority(4))
        os._exit(99)
    _pid, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status)
    assert _claim(root, 4).is_file()
    assert not _anchor(root, 4).exists()

    monkeypatch.setattr(cohort_allocation, "_rename_noreplace", real_rename)
    successor = cohort_allocation.publish_cohort_claim(
        root, _authority(5, lab_character="c", neqo_character="d")
    )
    assert successor["cohort_version"] == 5
    assert _anchor(root, 4).read_bytes() == _claim(root, 4).read_bytes()


def test_anchor_only_residue_is_repaired_before_successor_publication(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    cohort_allocation.publish_cohort_claim(root, _authority(4))
    raw = _anchor(root, 4).read_bytes()
    _claim(root, 4).unlink()

    successor = cohort_allocation.publish_cohort_claim(
        root, _authority(5, lab_character="c", neqo_character="d")
    )

    assert successor["cohort_version"] == 5
    assert _claim(root, 4).read_bytes() == raw
    assert _anchor(root, 4).read_bytes() == raw


def test_read_only_verify_rejects_missing_anchor_and_successor_repairs_it(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    snapshot = cohort_allocation.publish_cohort_claim(root, _authority(4))
    raw = _claim(root, 4).read_bytes()
    _anchor(root, 4).unlink()

    with pytest.raises(cohort_allocation.CohortAllocationError):
        cohort_allocation.verify_cohort_claim(root, snapshot)
    assert not _anchor(root, 4).exists()

    cohort_allocation.publish_cohort_claim(
        root, _authority(5, lab_character="c", neqo_character="d")
    )
    assert _anchor(root, 4).read_bytes() == raw


def test_mismatched_claim_and_anchor_fail_closed_without_repair_or_successor(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    cohort_allocation.publish_cohort_claim(root, _authority(4))
    original_anchor = _anchor(root, 4).read_bytes()
    changed = json.loads(original_anchor)
    changed["payload"]["source"]["lab_commit"] = "f" * 40
    changed["payload_sha256"] = hashlib.sha256(_canonical(changed["payload"])).hexdigest()
    _claim(root, 4).write_bytes(_canonical(changed, newline=True))
    _claim(root, 4).chmod(0o600)

    with pytest.raises(cohort_allocation.CohortAllocationError, match="differs from its anchor"):
        cohort_allocation.publish_cohort_claim(root, _authority(5))

    assert _anchor(root, 4).read_bytes() == original_anchor
    assert not _claim(root, 5).exists()


def test_publication_fsyncs_complete_temp_before_rename_and_directory_afterward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    events: list[str] = []
    real_write = cohort_allocation._write_all
    real_fsync = os.fsync
    real_rename = cohort_allocation._rename_noreplace

    def observed_write(descriptor: int, raw: bytes) -> None:
        real_write(descriptor, raw)
        events.append("write-complete")

    def observed_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0:
            events.append("temp-fsync")
        elif stat.S_ISDIR(metadata.st_mode):
            events.append("directory-fsync")
        real_fsync(descriptor)

    def observed_rename(directory_fd: int, source: str, destination: str) -> None:
        events.append("rename")
        real_rename(directory_fd, source, destination)

    monkeypatch.setattr(cohort_allocation, "_write_all", observed_write)
    monkeypatch.setattr(cohort_allocation.os, "fsync", observed_fsync)
    monkeypatch.setattr(cohort_allocation, "_rename_noreplace", observed_rename)

    cohort_allocation.publish_cohort_claim(root, _authority(4))

    write_index = events.index("write-complete")
    temp_fsync_index = events.index("temp-fsync", write_index)
    rename_index = events.index("rename", temp_fsync_index)
    assert "directory-fsync" in events[rename_index + 1 :]


def test_directory_fsync_failure_after_rename_conservatively_consumes_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    real_fsync = os.fsync
    real_rename = cohort_allocation._rename_noreplace
    renamed = False

    def observed_rename(directory_fd: int, source: str, destination: str) -> None:
        nonlocal renamed
        real_rename(directory_fd, source, destination)
        renamed = True

    def fail_post_rename_directory_fsync(descriptor: int) -> None:
        if renamed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected post-rename directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(cohort_allocation, "_rename_noreplace", observed_rename)
    monkeypatch.setattr(
        cohort_allocation.os,
        "fsync",
        fail_post_rename_directory_fsync,
    )
    with pytest.raises(OSError, match="post-rename directory fsync failure"):
        cohort_allocation.publish_cohort_claim(root, _authority(4))

    assert _claim(root, 4).is_file()
    assert not list(_registry(root).glob(".*.next"))
    monkeypatch.setattr(cohort_allocation.os, "fsync", real_fsync)
    successor = cohort_allocation.publish_cohort_claim(root, _authority(5))
    assert successor["cohort_version"] == 5


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.__setitem__("unexpected", True),
        lambda value: value["git"].__setitem__("unexpected", True),
        lambda value: value["filesystem"].__setitem__("unexpected", True),
        lambda value: value["receipt"].pop("lab_commit_ledger_proof"),
        lambda value: value["receipt"].__setitem__("unexpected", True),
        lambda value: value["receipt"].__setitem__("git_object_format", "sha256"),
        lambda value: value["receipt"]["lab_commit_ledger_proof"].pop("commit_payload_base64"),
        lambda value: value["receipt"]["lab_commit_ledger_proof"].__setitem__(
            "tree_payloads_base64", []
        ),
        lambda value: value["receipt"].__setitem__("allocated_version", 3),
        lambda value: value.__setitem__("schema_version", True),
        lambda value: value["filesystem"]["ledger"].__setitem__("nlink", True),
    ],
    ids=(
        "authority-extra",
        "git-extra",
        "filesystem-extra",
        "missing-proof",
        "receipt-extra",
        "sha256-object-format",
        "malformed-proof",
        "proof-tree-count",
        "already-consumed",
        "boolean-schema-version",
        "boolean-filesystem-stat",
    ),
)
def test_malformed_authority_is_rejected_without_a_claim(tmp_path: Path, mutate: Any) -> None:
    root = _root(tmp_path)
    authority = _authority(4)
    mutate(authority)

    with pytest.raises(cohort_allocation.CohortAllocationError):
        cohort_allocation.publish_cohort_claim(root, authority)

    assert not _registry(root).exists() or not list(_registry(root).glob("claim-v*.json"))


def test_duplicate_key_and_nonfinite_cli_inputs_are_rejected(tmp_path: Path) -> None:
    root = _root(tmp_path)
    command = [sys.executable, "-I", str(MODULE), "publish", "--root", str(root)]
    for payload in (
        '{"schema_version":1,"schema_version":1}\n',
        '{"schema_version":NaN}\n',
        "not-json\n",
    ):
        result = subprocess.run(
            command,
            input=payload,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 1
        assert result.stdout == ""
        assert "cohort allocation is invalid" in result.stderr


def test_duplicate_keys_inside_embedded_ledger_are_rejected(tmp_path: Path) -> None:
    root = _root(tmp_path)
    raw = (
        b'{"artifact_type":"qcsd-buflo-study-consumed-cohorts",'
        b'"consumed_versions":[1,2,3],"policy":"dense-prefix-durable-publications-consume-v1",'
        b'"schema_version":1,"schema_version":1}\n'
    )
    authority = _authority(4, ledger_raw=raw)

    with pytest.raises(cohort_allocation.CohortAllocationError, match="unique-key"):
        cohort_allocation.publish_cohort_claim(root, authority)


@pytest.mark.parametrize(
    "forgery",
    ["commit-bytes", "tree-bytes", "path-mode", "path-name", "gitlink", "ledger-blob"],
)
def test_forged_git_proof_cannot_become_a_permanent_claim(tmp_path: Path, forgery: str) -> None:
    root = _root(tmp_path)
    authority = _authority(4)
    receipt = authority["receipt"]
    proof = receipt["lab_commit_ledger_proof"]
    if forgery == "commit-bytes":
        raw = base64.b64decode(proof["commit_payload_base64"]) + b"forged"
        proof["commit_payload_base64"] = base64.b64encode(raw).decode("ascii")
    elif forgery == "tree-bytes":
        raw = base64.b64decode(proof["tree_payloads_base64"][2]) + b"forged"
        proof["tree_payloads_base64"][2] = base64.b64encode(raw).decode("ascii")
    else:
        proof_blob = receipt["ledger_git_blob_oid"]
        proof_gitlink = receipt["neqo_gitlink"]
        ledger_mode = b"100644"
        ledger_name = b"consumed-cohorts.json"
        if forgery == "path-mode":
            ledger_mode = b"100755"
        elif forgery == "path-name":
            ledger_name = b"other.json"
        elif forgery == "gitlink":
            proof_gitlink = "e" * 40
        else:
            proof_blob = "0" * 40
        lab, proof = _git_proof(
            ledger_blob_oid=proof_blob,
            neqo_gitlink=proof_gitlink,
            marker=f"forged-{forgery}",
            ledger_mode=ledger_mode,
            ledger_name=ledger_name,
        )
        receipt["lab_commit_ledger_proof"] = proof
        receipt["lab_commit"] = lab
        authority["git"]["lab_head"] = lab

    with pytest.raises(cohort_allocation.CohortAllocationError, match="Git proof"):
        cohort_allocation.publish_cohort_claim(root, authority)

    assert not _registry(root).exists()


def test_ledger_drift_cannot_extend_an_existing_chain(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = cohort_allocation.publish_cohort_claim(root, _authority(4))
    drifted = _authority(5, ledger_raw=_ledger_raw(marker="unsorted"))

    with pytest.raises(cohort_allocation.CohortAllocationError, match="authority is invalid"):
        cohort_allocation.publish_cohort_claim(root, drifted)

    assert not _claim(root, 5).exists()
    assert cohort_allocation.verify_cohort_claim(root, first) == first


def test_recomputed_source_drift_inside_a_claim_is_detected(tmp_path: Path) -> None:
    root = _root(tmp_path)
    cohort_allocation.publish_cohort_claim(root, _authority(4))
    stored = json.loads(_claim(root, 4).read_text(encoding="ascii"))
    stored["payload"]["source"]["lab_commit"] = "f" * 40
    stored["payload_sha256"] = hashlib.sha256(_canonical(stored["payload"])).hexdigest()
    _rewrite_claim(root, 4, stored)
    _anchor(root, 4).write_bytes(_canonical(stored, newline=True))
    _anchor(root, 4).chmod(0o600)

    with pytest.raises(cohort_allocation.CohortAllocationError, match="source is invalid"):
        cohort_allocation.publish_cohort_claim(root, _authority(5))


@pytest.mark.parametrize("field", ["bytes", "sha256", "stat", "boolean-stat", "registry"])
def test_snapshot_binding_tampering_is_rejected(tmp_path: Path, field: str) -> None:
    root = _root(tmp_path)
    snapshot = cohort_allocation.publish_cohort_claim(root, _authority(4))
    altered = copy.deepcopy(snapshot)
    if field == "bytes":
        altered["claim"]["payload_base64"] = base64.b64encode(b"different").decode("ascii")
        altered["claim"]["sha256"] = hashlib.sha256(b"different").hexdigest()
        altered["registry_head_at_publication"]["sha256"] = altered["claim"]["sha256"]
    elif field == "sha256":
        altered["claim"]["sha256"] = "0" * 64
        altered["registry_head_at_publication"]["sha256"] = "0" * 64
    elif field == "stat":
        altered["claim"]["stat"]["size"] += 1
    elif field == "boolean-stat":
        altered["claim"]["stat"]["nlink"] = True
    else:
        altered["registry"]["stat"]["inode"] += 1
    _reseal_snapshot(altered)

    with pytest.raises(cohort_allocation.CohortAllocationError):
        cohort_allocation.verify_cohort_claim(root, altered)


def test_cli_publish_and_verify_emit_one_identical_canonical_json_line(tmp_path: Path) -> None:
    root = _root(tmp_path)
    published = _run_cli("publish", root, _authority(4))
    assert published.returncode == 0, published.stderr
    assert len(published.stdout.splitlines()) == 1
    snapshot = json.loads(published.stdout)
    assert published.stdout.encode("ascii") == _canonical(snapshot, newline=True)

    verified = _run_cli("verify", root, snapshot)
    assert verified.returncode == 0, verified.stderr
    assert verified.stdout == published.stdout


def test_authority_and_claim_key_sets_are_exact(tmp_path: Path) -> None:
    root = _root(tmp_path)
    authority = _authority(4)
    assert set(authority["filesystem"]["ledger"]) == IDENTITY_KEYS
    snapshot = cohort_allocation.publish_cohort_claim(root, authority)
    stored = json.loads(_claim(root, 4).read_text(encoding="ascii"))

    assert set(stored["payload"]["authority"]) == {
        "schema_version",
        "artifact_type",
        "git",
        "filesystem",
        "receipt",
    }
    assert set(stored["payload"]["authority"]["receipt"]) == {
        "schema_version",
        "artifact_type",
        "policy",
        "ledger_path",
        "ledger_sha256",
        "ledger_payload_base64",
        "git_object_format",
        "ledger_git_blob_oid",
        "lab_commit",
        "neqo_commit",
        "neqo_gitlink",
        "lab_commit_ledger_proof",
        "last_consumed_version",
        "allocated_version",
    }
    assert snapshot["registry_head_at_publication"]["cohort_version"] == 4
