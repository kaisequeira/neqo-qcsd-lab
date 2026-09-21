"""Crash-durable, append-only allocation claims for BuFLO-study cohorts.

The checked-in consumed-cohort ledger is a genesis authority.  Runtime cohort
claims form a dense hash chain after that genesis and are deliberately kept
outside the Git checkout's tracked inputs.  A caller is admitted to mutate
Docker only after its complete claim and redundant consumption anchor have been
published create-only, fsynced, and ``publish_cohort_claim`` has returned.
Temporary ``.next`` work is non-admitted and non-consuming preparation.  Any
canonical final record observed after an ambiguous post-rename crash is
conservatively consumed, even though that crashed caller was never admitted.
For guarded builds, the lifecycle guardian alone retains the registry flock;
allocator subprocesses authenticate it through stable procfs bindings and
never inherit, unlock, or duplicate its open file description.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import select
import signal
import stat
import sys
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REGISTRY_RELATIVE_PATH = "artifacts/buflo-study/cohort-claims-v1"
REGISTRY_DIRECTORY_NAME = "cohort-claims-v1"
REGISTRY_LOCK_NAME = ".allocation.lock"
COHORT_OPERATION_LOCK_NAME = ".allocation-operation.lock"
LEDGER_RELATIVE_PATH = "config/buflo-study/v1/consumed-cohorts.json"
ALLOCATION_POLICY = "dense-prefix-durable-publications-consume-v1"
AUTHORITY_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-allocation-authority"
ALLOCATION_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-allocation"
LEDGER_ARTIFACT_TYPE = "qcsd-buflo-study-consumed-cohorts"
CLAIM_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-claim"
SNAPSHOT_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-claim-publication"
CHAIN_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-claim-chain"

MAX_STDIN_BYTES = 8 * 1024 * 1024
MAX_LEDGER_BYTES = 16 * 1024
MAX_CLAIM_BYTES = 4 * 1024 * 1024
MAX_GIT_PROOF_COMMIT_BYTES = 256 * 1024
MAX_GIT_PROOF_TREE_BYTES = 1024 * 1024
MAX_REGISTRY_ENTRIES = 100_000
RENAME_NOREPLACE = 1
PR_SET_PDEATHSIG = 1

# Remote CLI operations deliberately retain B until os._exit(2) closes the
# process file table after the single canonical reply has been flushed.
_PROCESS_EXIT_LOCK_FDS: list[int] = []

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CLAIM_NAME_RE = re.compile(r"claim-v([1-9][0-9]*)[.]json")
_ANCHOR_NAME_RE = re.compile(r"[.]consumed-v([1-9][0-9]*)[.]json")
_TEMP_NAME_RE = re.compile(r"[.]claim-v([1-9][0-9]*)[.]([0-9a-f]{64})[.]next")
_FDINFO_LOCK_RE = re.compile(
    r"lock:\s+[0-9]+:\s+FLOCK\s+ADVISORY\s+WRITE\s+"
    r"([1-9][0-9]*)\s+\S+\s+0\s+EOF"
)
_AUTHORITY_KEYS = {"schema_version", "artifact_type", "git", "filesystem", "receipt"}
_AUTHORITY_GIT_KEYS = {
    "object_format",
    "lab_head",
    "head_blob_oid",
    "index_blob_oid",
    "worktree_blob_oid",
    "neqo_head",
    "head_gitlink",
    "index_gitlink",
}
_AUTHORITY_FILESYSTEM_KEYS = {"directories", "ledger", "git_index"}
_AUTHORITY_DIRECTORY_NAMES = {
    "repository-root",
    "config",
    "buflo-study",
    "v1",
    "git",
}
_AUTHORITY_RECEIPT_KEYS = {
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
_GIT_PROOF_KEYS = {
    "schema_version",
    "artifact_type",
    "commit_payload_base64",
    "tree_payloads_base64",
}
_GIT_PROOF_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-ledger-git-proof"
_GIT_PROOF_PATH = (b"config", b"buflo-study", b"v1", b"consumed-cohorts.json")
_GIT_TREE_ALLOWED_MODES = {b"40000", b"100644", b"100755", b"120000", b"160000"}
_CLAIM_KEYS = {"schema_version", "artifact_type", "payload", "payload_sha256"}
_CLAIM_PAYLOAD_KEYS = {
    "policy",
    "registry_path",
    "cohort_version",
    "authority",
    "authority_sha256",
    "source",
    "ledger",
    "predecessor",
}
_SOURCE_KEYS = {"lab_commit", "neqo_commit", "neqo_gitlink"}
_LEDGER_BINDING_KEYS = {
    "path",
    "sha256",
    "git_object_format",
    "git_blob_oid",
    "payload_base64",
    "last_consumed_version",
}
_PREDECESSOR_KEYS = {"kind", "cohort_version", "sha256"}
_SNAPSHOT_KEYS = {
    "schema_version",
    "artifact_type",
    "policy",
    "cohort_version",
    "registry",
    "claim",
    "registry_head_at_publication",
    "payload_sha256",
}
_REGISTRY_SNAPSHOT_KEYS = {"path", "stat"}
_CLAIM_SNAPSHOT_KEYS = {"path", "sha256", "payload_base64", "stat"}
_FILE_STAT_KEYS = {
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
_DIRECTORY_BINDING_KEYS = {"dev", "inode", "uid", "gid", "mode", "nlink"}
_AUTHORITY_FILE_IDENTITY_KEYS = _FILE_STAT_KEYS
_AUTHORITY_DIRECTORY_IDENTITY_KEYS = {"type", "dev", "inode", "uid", "gid", "mode"}
_AUTHORITY_SCHEMA_VERSIONS = {1, 2}


class CohortAllocationError(ValueError):
    """The allocation authority, registry, claim, or snapshot is invalid."""


@dataclass(frozen=True)
class _BaseAuthority:
    authority: dict[str, Any]
    authority_sha256: str
    requested_version: int
    policy: str
    ledger_path: str
    ledger_sha256: str
    ledger_payload_base64: str
    object_format: str
    ledger_blob_oid: str
    last_consumed_version: int
    lab_commit: str
    neqo_commit: str
    neqo_gitlink: str


@dataclass(frozen=True)
class _ClaimRecord:
    version: int
    name: str
    raw: bytes
    sha256: str
    metadata: os.stat_result
    value: dict[str, Any]


@dataclass(frozen=True)
class GuardianLockAuthority:
    """Out-of-process lifecycle-guardian lock binding supplied to the CLI."""

    owner_pid: int
    owner_start: int
    guardian_pid: int
    guardian_start: int
    guardian_fd: int
    path: str
    device: int
    inode: int
    parent_device: int
    parent_inode: int
    cohort_version: int


@dataclass
class _GuardianLockProof:
    authority: GuardianLockAuthority
    owner_pidfd: int
    guardian_pidfd: int
    canonical_path: str


def _invalid_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json_bytes(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise CohortAllocationError(f"{label} is not unique-key finite UTF-8 JSON") from error


def _canonical_bytes(value: Any, *, newline: bool = False) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise CohortAllocationError("allocation value is not canonical finite JSON") from error
    return encoded + (b"\n" if newline else b"")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_base64(value: Any, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise CohortAllocationError(f"{label} base64 encoding is invalid")
    try:
        encoded = value.encode("ascii")
        raw = base64.b64decode(encoded, validate=True)
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise CohortAllocationError(f"{label} base64 encoding is invalid") from error
    if not raw or len(raw) > maximum or base64.b64encode(raw) != encoded:
        raise CohortAllocationError(f"{label} base64 encoding is invalid")
    return raw


def _positive_integer(value: Any, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise CohortAllocationError(f"{label} must be a positive integer")
    return value


def _integer_record(value: Any, *, keys: set[str]) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == keys
        and all(type(item) is int and item >= 0 for item in value.values())
        and 0 <= value["mode"] <= 0o7777
        and value["nlink"] >= 1
    )


def _authority_directory_record(
    value: Any, *, schema_version: int, name: str
) -> bool:
    if schema_version == 1 or name != "git":
        return _integer_record(value, keys=_AUTHORITY_FILE_IDENTITY_KEYS)
    return (
        isinstance(value, Mapping)
        and set(value) == _AUTHORITY_DIRECTORY_IDENTITY_KEYS
        and all(type(item) is int and item >= 0 for item in value.values())
        and value["type"] == stat.S_IFDIR
        and value["dev"] > 0
        and value["inode"] > 0
        and 0 <= value["mode"] <= 0o7777
    )


def _git_oid(value: Any, *, object_format: str, label: str) -> str:
    length = 40 if object_format == "sha1" else 64
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise CohortAllocationError(f"{label} Git object ID is invalid")
    return value


def _git_sha1_object_oid(object_type: bytes, payload: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(object_type + b" " + str(len(payload)).encode("ascii") + b"\0")
    digest.update(payload)
    return digest.hexdigest()


def _parse_git_tree(payload: bytes) -> dict[bytes, tuple[bytes, str]]:
    entries: dict[bytes, tuple[bytes, str]] = {}
    previous_sort_key: bytes | None = None
    offset = 0
    while offset < len(payload):
        space = payload.find(b" ", offset)
        nul = payload.find(b"\0", space + 1) if space >= 0 else -1
        oid_start = nul + 1
        oid_end = oid_start + 20
        if space <= offset or nul <= space + 1 or oid_end > len(payload):
            raise CohortAllocationError("cohort-allocation Git proof tree is malformed")
        mode = payload[offset:space]
        name = payload[space + 1 : nul]
        if (
            mode not in _GIT_TREE_ALLOWED_MODES
            or name in {b"", b".", b".."}
            or b"/" in name
            or name in entries
        ):
            raise CohortAllocationError("cohort-allocation Git proof tree is malformed")
        sort_key = name + (b"/" if mode == b"40000" else b"")
        if previous_sort_key is not None and sort_key <= previous_sort_key:
            raise CohortAllocationError("cohort-allocation Git proof tree is malformed")
        previous_sort_key = sort_key
        entries[name] = (mode, payload[oid_start:oid_end].hex())
        offset = oid_end
    if not entries:
        raise CohortAllocationError("cohort-allocation Git proof tree is malformed")
    return entries


def _validate_git_proof(
    value: Any,
    *,
    lab_commit: str,
    ledger_blob_oid: str,
    neqo_gitlink: str,
) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != _GIT_PROOF_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _GIT_PROOF_ARTIFACT_TYPE
    ):
        raise CohortAllocationError("cohort-allocation Git proof schema is invalid")
    commit_payload = _strict_base64(
        value.get("commit_payload_base64"),
        label="cohort-allocation Git proof commit",
        maximum=MAX_GIT_PROOF_COMMIT_BYTES,
    )
    encoded_trees = value.get("tree_payloads_base64")
    if not isinstance(encoded_trees, list) or len(encoded_trees) != len(_GIT_PROOF_PATH):
        raise CohortAllocationError("cohort-allocation Git proof tree inventory is invalid")
    tree_payloads = [
        _strict_base64(
            encoded,
            label="cohort-allocation Git proof tree",
            maximum=MAX_GIT_PROOF_TREE_BYTES,
        )
        for encoded in encoded_trees
    ]

    if _git_sha1_object_oid(b"commit", commit_payload) != lab_commit:
        raise CohortAllocationError("cohort-allocation Git proof commit binding is invalid")
    first_line, separator, _remainder = commit_payload.partition(b"\n")
    root_match = re.fullmatch(rb"tree ([0-9a-f]{40})", first_line)
    if not separator or root_match is None:
        raise CohortAllocationError("cohort-allocation Git proof commit is malformed")
    expected_tree_oid = root_match.group(1).decode("ascii")

    for index, (component, tree_payload) in enumerate(
        zip(_GIT_PROOF_PATH, tree_payloads, strict=True)
    ):
        if _git_sha1_object_oid(b"tree", tree_payload) != expected_tree_oid:
            raise CohortAllocationError("cohort-allocation Git proof tree binding is invalid")
        entries = _parse_git_tree(tree_payload)
        if index == 0 and entries.get(b"neqo-qcsd") != (b"160000", neqo_gitlink):
            raise CohortAllocationError("cohort-allocation Git proof gitlink binding is invalid")
        entry = entries.get(component)
        expected_mode = b"100644" if index == len(_GIT_PROOF_PATH) - 1 else b"40000"
        if entry is None or entry[0] != expected_mode:
            raise CohortAllocationError("cohort-allocation Git proof path binding is invalid")
        expected_tree_oid = entry[1]
    if expected_tree_oid != ledger_blob_oid:
        raise CohortAllocationError("cohort-allocation Git proof ledger binding is invalid")


def _file_identity(value: os.stat_result) -> dict[str, int]:
    return {
        "dev": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
        "nlink": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _directory_binding(value: os.stat_result) -> dict[str, int]:
    return {
        "dev": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
        "nlink": value.st_nlink,
    }


def _same_entry(left: os.stat_result, right: os.stat_result) -> bool:
    return _file_identity(left) == _file_identity(right)


def _same_directory_entry(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare stable pathname identity and security metadata for directories."""

    return (
        stat.S_ISDIR(left.st_mode)
        and stat.S_ISDIR(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_uid == right.st_uid
        and left.st_gid == right.st_gid
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
    )


def _safe_ancestor(value: os.stat_result, *, final: bool = False) -> bool:
    mode = stat.S_IMODE(value.st_mode)
    owner_ok = value.st_uid in {0, os.geteuid()}
    write_ok = mode & 0o022 == 0 or (not final and value.st_uid == 0 and mode & stat.S_ISVTX != 0)
    return stat.S_ISDIR(value.st_mode) and owner_ok and write_ok


def _open_directory_at(parent_fd: int, name: str, *, label: str, final: bool = False) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise CohortAllocationError(f"{label} directory is unavailable or unsafe") from error
    try:
        opened = os.fstat(descriptor)
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _safe_ancestor(opened, final=final)
            or not _safe_ancestor(entry, final=final)
            or not _same_directory_entry(opened, entry)
        ):
            raise CohortAllocationError(f"{label} directory identity is unsafe")
        if final and opened.st_uid != os.geteuid():
            raise CohortAllocationError(f"{label} directory is not owned by the current user")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_root(root: Path) -> int:
    raw = os.fspath(root)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw or raw == os.sep:
        raise CohortAllocationError("allocation root must be a canonical absolute directory")
    components = [part for part in raw.split(os.sep) if part]
    descriptor = os.open(
        os.sep,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for index, component in enumerate(components):
            next_fd = _open_directory_at(
                descriptor,
                component,
                label="allocation root component",
                final=index == len(components) - 1,
            )
            os.close(descriptor)
            descriptor = next_fd
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_registry(root: Path, *, create: bool) -> tuple[int, os.stat_result]:
    root_fd = _open_root(root)
    artifacts_fd = study_fd = registry_fd = -1
    try:
        if create:
            artifacts_fd = _open_or_create_private_directory_at(
                root_fd, "artifacts", label="artifacts"
            )
            study_fd = _open_or_create_private_directory_at(
                artifacts_fd, "buflo-study", label="BuFLO artifacts"
            )
        else:
            artifacts_fd = _open_directory_at(root_fd, "artifacts", label="artifacts")
            study_fd = _open_directory_at(artifacts_fd, "buflo-study", label="BuFLO artifacts")
        if create:
            try:
                os.mkdir(REGISTRY_DIRECTORY_NAME, 0o700, dir_fd=study_fd)
            except FileExistsError:
                pass
            else:
                os.fsync(study_fd)
        registry_fd = _open_directory_at(
            study_fd,
            REGISTRY_DIRECTORY_NAME,
            label="cohort-claim registry",
            final=True,
        )
        opened = os.fstat(registry_fd)
        if stat.S_IMODE(opened.st_mode) != 0o700:
            raise CohortAllocationError("cohort-claim registry mode must be exactly 0700")
        return registry_fd, opened
    except BaseException:
        if registry_fd >= 0:
            os.close(registry_fd)
        raise
    finally:
        if study_fd >= 0:
            os.close(study_fd)
        if artifacts_fd >= 0:
            os.close(artifacts_fd)
        os.close(root_fd)


def _open_or_create_private_directory_at(parent_fd: int, name: str, *, label: str) -> int:
    """Open an existing safe directory or durably create a private one."""

    try:
        return _open_directory_at(parent_fd, name, label=label)
    except CohortAllocationError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            # A racing creator is acceptable only if the resulting entry passes
            # the same descriptor/path identity checks as any existing parent.
            pass
        except OSError as error:
            raise CohortAllocationError(f"{label} directory cannot be created safely") from error
        else:
            os.fsync(parent_fd)
    descriptor = _open_directory_at(parent_fd, name, label=label)
    opened = os.fstat(descriptor)
    if stat.S_IMODE(opened.st_mode) != 0o700:
        os.close(descriptor)
        raise CohortAllocationError(f"new {label} directory mode is not private")
    return descriptor


def _open_registry_lock(registry_fd: int, *, create: bool) -> int:
    flags = (
        os.O_RDWR
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    created = False
    if create:
        try:
            descriptor = os.open(
                REGISTRY_LOCK_NAME,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=registry_fd,
            )
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(REGISTRY_LOCK_NAME, flags, dir_fd=registry_fd)
            except OSError as error:
                raise CohortAllocationError(
                    "cohort-claim registry lock is unavailable or unsafe"
                ) from error
        except OSError as error:
            raise CohortAllocationError(
                "cohort-claim registry lock cannot be created safely"
            ) from error
    else:
        try:
            descriptor = os.open(REGISTRY_LOCK_NAME, flags, dir_fd=registry_fd)
        except OSError as error:
            raise CohortAllocationError("cohort-claim registry lock is unavailable") from error
    try:
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(registry_fd)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        opened = os.fstat(descriptor)
        entry = os.stat(REGISTRY_LOCK_NAME, dir_fd=registry_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != 0
            or not _same_entry(opened, entry)
        ):
            raise CohortAllocationError("cohort-claim registry lock identity is unsafe")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_operation_lock(registry_fd: int, *, create: bool) -> int:
    """Open and exclusively hold the canonical allocator-operation lock B."""

    flags = (
        os.O_RDWR
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    created = False
    if create:
        try:
            descriptor = os.open(
                COHORT_OPERATION_LOCK_NAME,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=registry_fd,
            )
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(COHORT_OPERATION_LOCK_NAME, flags, dir_fd=registry_fd)
            except OSError as error:
                raise CohortAllocationError(
                    "cohort-claim operation lock is unavailable or unsafe"
                ) from error
        except OSError as error:
            raise CohortAllocationError(
                "cohort-claim operation lock cannot be created safely"
            ) from error
    else:
        try:
            descriptor = os.open(COHORT_OPERATION_LOCK_NAME, flags, dir_fd=registry_fd)
        except OSError as error:
            raise CohortAllocationError("cohort-claim operation lock is unavailable") from error
    try:
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(registry_fd)
        opened = os.fstat(descriptor)
        entry = os.stat(
            COHORT_OPERATION_LOCK_NAME,
            dir_fd=registry_fd,
            follow_symlinks=False,
        )
        allocation_entry = os.stat(REGISTRY_LOCK_NAME, dir_fd=registry_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != 0
            or not _same_entry(opened, entry)
            or (opened.st_dev, opened.st_ino) == (allocation_entry.st_dev, allocation_entry.st_ino)
        ):
            raise CohortAllocationError("cohort-claim operation lock identity is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.fstat(descriptor)
        final_entry = os.stat(
            COHORT_OPERATION_LOCK_NAME,
            dir_fd=registry_fd,
            follow_symlinks=False,
        )
        final_allocation = os.stat(REGISTRY_LOCK_NAME, dir_fd=registry_fd, follow_symlinks=False)
        if (
            not _same_entry(opened, locked)
            or not _same_entry(locked, final_entry)
            or (locked.st_dev, locked.st_ino) == (final_allocation.st_dev, final_allocation.st_ino)
        ):
            raise CohortAllocationError(
                "cohort-claim operation lock identity changed while acquired"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _close_or_retain_operation_lock(descriptor: int, *, retain: bool) -> None:
    if descriptor < 0:
        return
    if retain:
        _PROCESS_EXIT_LOCK_FDS.append(descriptor)
    else:
        os.close(descriptor)


def _process_identity(pid: int) -> tuple[int, int]:
    if type(pid) is not int or pid <= 0:
        raise CohortAllocationError("guardian-lock process identity is invalid")
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except OSError as error:
        raise CohortAllocationError("guardian-lock process is unavailable") from error
    close = raw.rfind(b") ")
    fields = raw[close + 2 :].split() if close >= 0 else []
    try:
        parent_pid = int(fields[1])
        start_time = int(fields[19])
    except (IndexError, ValueError) as error:
        raise CohortAllocationError("guardian-lock process identity is malformed") from error
    if parent_pid < 0 or start_time <= 0:
        raise CohortAllocationError("guardian-lock process identity is invalid")
    return parent_pid, start_time


def _pidfd_is_alive(descriptor: int) -> bool:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poller.poll(0)


def _arm_guardian_owner_death(authority: GuardianLockAuthority) -> None:
    """Kill a remote allocator when its exact qcsd parent exits.

    The guardian lock is deliberately absent from qcsd and its descendants.
    Bind the allocator to qcsd before opening the claim registry so it cannot
    survive as an orphan and continue a remote-authorised operation after that
    owner has exited.
    """

    if not isinstance(authority, GuardianLockAuthority):
        raise CohortAllocationError("guardian-lock authority is invalid")
    if os.getppid() != authority.owner_pid:
        raise CohortAllocationError("allocator is not a direct child of the lock owner")
    owner_pidfd = -1
    try:
        owner_pidfd = os.pidfd_open(authority.owner_pid, 0)
        _owner_parent, owner_start = _process_identity(authority.owner_pid)
        if owner_start != authority.owner_start or not _pidfd_is_alive(owner_pidfd):
            raise CohortAllocationError("guardian-lock owner identity changed")
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        prctl.restype = ctypes.c_int
        if prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))

        # The parent may have exited between the initial lineage check and
        # prctl(2).  Recheck both the direct-parent relation and its immutable
        # start time immediately after arming, before any registry pathname is
        # opened or mutated.
        if os.getppid() != authority.owner_pid:
            raise CohortAllocationError("guardian-lock owner exited while death-binding")
        _owner_parent, owner_start = _process_identity(authority.owner_pid)
        if owner_start != authority.owner_start or not _pidfd_is_alive(owner_pidfd):
            raise CohortAllocationError("guardian-lock owner exited while death-binding")
    except OSError as error:
        raise CohortAllocationError("cannot bind allocator lifetime to lock owner") from error
    finally:
        if owner_pidfd >= 0:
            os.close(owner_pidfd)


def _read_guardian_fdinfo(authority: GuardianLockAuthority) -> str:
    path = Path(f"/proc/{authority.guardian_pid}/fdinfo/{authority.guardian_fd}")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CohortAllocationError("guardian lock fdinfo is unavailable") from error
    if not raw or len(raw) > 16 * 1024:
        raise CohortAllocationError("guardian lock fdinfo has an invalid size")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise CohortAllocationError("guardian lock fdinfo is malformed") from error
    flag_lines = [line for line in text.splitlines() if line.startswith("flags:")]
    lock_matches = _FDINFO_LOCK_RE.findall(text)
    try:
        flags = int(flag_lines[0].split()[1], 8)
    except (IndexError, ValueError) as error:
        raise CohortAllocationError("guardian lock fdinfo flags are malformed") from error
    if (
        len(flag_lines) != 1
        or (flags & os.O_ACCMODE) != os.O_RDWR
        or lock_matches != [str(authority.guardian_pid)]
    ):
        raise CohortAllocationError("guardian FD does not hold one exclusive WRITE FLOCK")
    return text


def _verify_guardian_lock_proof(
    root: Path,
    registry_fd: int,
    proof: _GuardianLockProof,
    *,
    expected_cohort_version: int,
) -> None:
    authority = proof.authority
    if not _pidfd_is_alive(proof.owner_pidfd) or not _pidfd_is_alive(proof.guardian_pidfd):
        raise CohortAllocationError("guardian-lock process exited")
    owner_parent, owner_start = _process_identity(authority.owner_pid)
    _guardian_parent, guardian_start = _process_identity(authority.guardian_pid)
    if (
        os.getppid() != authority.owner_pid
        or owner_start != authority.owner_start
        or owner_parent != authority.guardian_pid
        or guardian_start != authority.guardian_start
        or authority.cohort_version != expected_cohort_version
    ):
        raise CohortAllocationError("guardian-lock process lineage or cohort changed")

    registry_metadata = os.fstat(registry_fd)
    try:
        canonical = os.stat(
            REGISTRY_LOCK_NAME,
            dir_fd=registry_fd,
            follow_symlinks=False,
        )
        remote = os.stat(f"/proc/{authority.guardian_pid}/fd/{authority.guardian_fd}")
        remote_path = os.readlink(f"/proc/{authority.guardian_pid}/fd/{authority.guardian_fd}")
    except OSError as error:
        raise CohortAllocationError("guardian lock path binding is unavailable") from error
    if (
        proof.canonical_path != authority.path
        or remote_path != authority.path
        or registry_metadata.st_dev != authority.parent_device
        or registry_metadata.st_ino != authority.parent_inode
        or canonical.st_dev != authority.device
        or canonical.st_ino != authority.inode
        or remote.st_dev != authority.device
        or remote.st_ino != authority.inode
        or not stat.S_ISREG(canonical.st_mode)
        or canonical.st_uid != os.geteuid()
        or stat.S_IMODE(canonical.st_mode) != 0o600
        or canonical.st_nlink != 1
        or canonical.st_size != 0
    ):
        raise CohortAllocationError("guardian lock path or inode binding changed")
    _read_guardian_fdinfo(authority)


def _open_guardian_lock_proof(
    root: Path,
    registry_fd: int,
    authority: GuardianLockAuthority,
    *,
    expected_cohort_version: int,
) -> _GuardianLockProof:
    if not isinstance(authority, GuardianLockAuthority):
        raise CohortAllocationError("guardian-lock authority is invalid")
    integer_values = (
        authority.owner_pid,
        authority.owner_start,
        authority.guardian_pid,
        authority.guardian_start,
        authority.guardian_fd,
        authority.device,
        authority.inode,
        authority.parent_device,
        authority.parent_inode,
        authority.cohort_version,
    )
    canonical_path = os.fspath(root / REGISTRY_RELATIVE_PATH / REGISTRY_LOCK_NAME)
    if (
        any(type(value) is not int or value <= 0 for value in integer_values)
        or authority.guardian_fd < 3
        or not isinstance(authority.path, str)
        or authority.path != canonical_path
        or not os.path.isabs(canonical_path)
        or os.path.normpath(canonical_path) != canonical_path
    ):
        raise CohortAllocationError("guardian-lock authority is invalid")
    if os.getppid() != authority.owner_pid:
        raise CohortAllocationError("allocator is not a direct child of the lock owner")
    owner_pidfd = guardian_pidfd = -1
    try:
        owner_pidfd = os.pidfd_open(authority.owner_pid, 0)
        guardian_pidfd = os.pidfd_open(authority.guardian_pid, 0)
    except OSError as error:
        if owner_pidfd >= 0:
            os.close(owner_pidfd)
        if guardian_pidfd >= 0:
            os.close(guardian_pidfd)
        raise CohortAllocationError("cannot bind guardian-lock process identity") from error
    proof = _GuardianLockProof(
        authority=authority,
        owner_pidfd=owner_pidfd,
        guardian_pidfd=guardian_pidfd,
        canonical_path=canonical_path,
    )
    try:
        _verify_guardian_lock_proof(
            root,
            registry_fd,
            proof,
            expected_cohort_version=expected_cohort_version,
        )
        return proof
    except BaseException:
        os.close(owner_pidfd)
        os.close(guardian_pidfd)
        raise


def _close_guardian_lock_proof(proof: _GuardianLockProof) -> None:
    os.close(proof.owner_pidfd)
    os.close(proof.guardian_pidfd)


def _validate_authority(value: Any) -> _BaseAuthority:
    schema_version = value.get("schema_version") if isinstance(value, Mapping) else None
    if (
        not isinstance(value, Mapping)
        or set(value) != _AUTHORITY_KEYS
        or type(schema_version) is not int
        or schema_version not in _AUTHORITY_SCHEMA_VERSIONS
        or value.get("artifact_type") != AUTHORITY_ARTIFACT_TYPE
        or not isinstance(value.get("git"), Mapping)
        or not isinstance(value.get("filesystem"), Mapping)
        or not isinstance(value.get("receipt"), Mapping)
    ):
        raise CohortAllocationError("cohort-allocation authority schema is invalid")
    authority = dict(value)
    receipt = value["receipt"]
    if (
        set(receipt) != _AUTHORITY_RECEIPT_KEYS
        or type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version") != 1
        or receipt.get("artifact_type") != ALLOCATION_ARTIFACT_TYPE
        or receipt.get("policy") != ALLOCATION_POLICY
        or receipt.get("ledger_path") != LEDGER_RELATIVE_PATH
    ):
        raise CohortAllocationError("cohort-allocation authority receipt is invalid")
    object_format = receipt["git_object_format"]
    if object_format != "sha1":
        raise CohortAllocationError("cohort-allocation Git object format is invalid")
    proof = receipt["lab_commit_ledger_proof"]
    ledger_raw = _strict_base64(
        receipt["ledger_payload_base64"],
        label="consumed-cohort ledger",
        maximum=MAX_LEDGER_BYTES,
    )
    ledger_sha256 = receipt["ledger_sha256"]
    if (
        not isinstance(ledger_sha256, str)
        or _SHA256_RE.fullmatch(ledger_sha256) is None
        or _sha256(ledger_raw) != ledger_sha256
    ):
        raise CohortAllocationError("consumed-cohort ledger SHA-256 is invalid")
    ledger_blob_oid = _git_oid(
        receipt["ledger_git_blob_oid"],
        object_format=object_format,
        label="consumed-cohort ledger",
    )
    git_blob = hashlib.new(object_format)
    git_blob.update(b"blob " + str(len(ledger_raw)).encode("ascii") + b"\0" + ledger_raw)
    if git_blob.hexdigest() != ledger_blob_oid:
        raise CohortAllocationError("consumed-cohort ledger Git blob binding is invalid")
    ledger = _load_json_bytes(ledger_raw, label="consumed-cohort ledger")
    if (
        not isinstance(ledger, Mapping)
        or set(ledger) != {"schema_version", "artifact_type", "policy", "consumed_versions"}
        or type(ledger.get("schema_version")) is not int
        or ledger.get("schema_version") != 1
        or ledger.get("artifact_type") != LEDGER_ARTIFACT_TYPE
        or ledger.get("policy") != ALLOCATION_POLICY
    ):
        raise CohortAllocationError("consumed-cohort ledger schema is invalid")
    versions = ledger["consumed_versions"]
    if (
        not isinstance(versions, list)
        or not versions
        or any(type(item) is not int for item in versions)
        or versions != list(range(1, len(versions) + 1))
    ):
        raise CohortAllocationError("consumed-cohort ledger is not a dense prefix")
    last_consumed = _positive_integer(
        receipt["last_consumed_version"], label="last consumed cohort version"
    )
    requested = _positive_integer(receipt["allocated_version"], label="allocated cohort version")
    if last_consumed != versions[-1] or requested <= last_consumed:
        raise CohortAllocationError("cohort-allocation version authority is invalid")
    lab_commit = _git_oid(receipt["lab_commit"], object_format=object_format, label="Lab commit")
    neqo_commit = _git_oid(receipt["neqo_commit"], object_format=object_format, label="Neqo commit")
    neqo_gitlink = _git_oid(
        receipt["neqo_gitlink"], object_format=object_format, label="Neqo gitlink"
    )
    if neqo_commit != neqo_gitlink:
        raise CohortAllocationError("cohort-allocation Neqo source binding is invalid")
    _validate_git_proof(
        proof,
        lab_commit=lab_commit,
        ledger_blob_oid=ledger_blob_oid,
        neqo_gitlink=neqo_gitlink,
    )
    git = value["git"]
    expected_git = {
        "object_format": object_format,
        "lab_head": lab_commit,
        "head_blob_oid": ledger_blob_oid,
        "index_blob_oid": ledger_blob_oid,
        "worktree_blob_oid": ledger_blob_oid,
        "neqo_head": neqo_commit,
        "head_gitlink": neqo_gitlink,
        "index_gitlink": neqo_gitlink,
    }
    if set(git) != _AUTHORITY_GIT_KEYS or dict(git) != expected_git:
        raise CohortAllocationError("cohort-allocation Git authority is inconsistent")
    filesystem = value["filesystem"]
    if set(filesystem) != _AUTHORITY_FILESYSTEM_KEYS:
        raise CohortAllocationError("cohort-allocation filesystem authority is invalid")
    directories = filesystem["directories"]
    if (
        not isinstance(directories, Mapping)
        or set(directories) != _AUTHORITY_DIRECTORY_NAMES
        or any(
            not _authority_directory_record(
                identity,
                schema_version=schema_version,
                name=name,
            )
            or identity["uid"] != os.geteuid()
            or identity["mode"] & 0o022 != 0
            for name, identity in directories.items()
        )
        or not _integer_record(filesystem["ledger"], keys=_AUTHORITY_FILE_IDENTITY_KEYS)
        or not _integer_record(filesystem["git_index"], keys=_AUTHORITY_FILE_IDENTITY_KEYS)
        or filesystem["ledger"]["uid"] != os.geteuid()
        or filesystem["ledger"]["mode"] & 0o133 != 0
        or filesystem["ledger"]["nlink"] != 1
        or filesystem["ledger"]["size"] != len(ledger_raw)
        or filesystem["git_index"]["uid"] != os.geteuid()
        or filesystem["git_index"]["mode"] & 0o022 != 0
        or filesystem["git_index"]["nlink"] != 1
        or filesystem["git_index"]["size"] < 1
    ):
        raise CohortAllocationError("cohort-allocation filesystem authority is invalid")
    canonical = _canonical_bytes(authority)
    return _BaseAuthority(
        authority=authority,
        authority_sha256=_sha256(canonical),
        requested_version=requested,
        policy=ALLOCATION_POLICY,
        ledger_path=LEDGER_RELATIVE_PATH,
        ledger_sha256=ledger_sha256,
        ledger_payload_base64=receipt["ledger_payload_base64"],
        object_format=object_format,
        ledger_blob_oid=ledger_blob_oid,
        last_consumed_version=last_consumed,
        lab_commit=lab_commit,
        neqo_commit=neqo_commit,
        neqo_gitlink=neqo_gitlink,
    )


def _base_matches(left: _BaseAuthority, right: _BaseAuthority) -> bool:
    return (
        left.policy,
        left.ledger_path,
        left.ledger_sha256,
        left.ledger_payload_base64,
        left.object_format,
        left.ledger_blob_oid,
        left.last_consumed_version,
    ) == (
        right.policy,
        right.ledger_path,
        right.ledger_sha256,
        right.ledger_payload_base64,
        right.object_format,
        right.ledger_blob_oid,
        right.last_consumed_version,
    )


def _claim_value(authority: _BaseAuthority, predecessor: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "policy": authority.policy,
        "registry_path": REGISTRY_RELATIVE_PATH,
        "cohort_version": authority.requested_version,
        "authority": authority.authority,
        "authority_sha256": authority.authority_sha256,
        "source": {
            "lab_commit": authority.lab_commit,
            "neqo_commit": authority.neqo_commit,
            "neqo_gitlink": authority.neqo_gitlink,
        },
        "ledger": {
            "path": authority.ledger_path,
            "sha256": authority.ledger_sha256,
            "git_object_format": authority.object_format,
            "git_blob_oid": authority.ledger_blob_oid,
            "payload_base64": authority.ledger_payload_base64,
            "last_consumed_version": authority.last_consumed_version,
        },
        "predecessor": predecessor,
    }
    return {
        "schema_version": 1,
        "artifact_type": CLAIM_ARTIFACT_TYPE,
        "payload": payload,
        "payload_sha256": _sha256(_canonical_bytes(payload)),
    }


def _validate_claim(
    value: Any,
    *,
    expected_version: int,
    base: _BaseAuthority,
    expected_predecessor: dict[str, Any],
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _CLAIM_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != CLAIM_ARTIFACT_TYPE
        or not isinstance(value.get("payload"), Mapping)
    ):
        raise CohortAllocationError(f"cohort claim v{expected_version} schema is invalid")
    payload = value["payload"]
    digest = value["payload_sha256"]
    if (
        set(payload) != _CLAIM_PAYLOAD_KEYS
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        or digest != _sha256(_canonical_bytes(payload))
        or payload.get("policy") != ALLOCATION_POLICY
        or payload.get("registry_path") != REGISTRY_RELATIVE_PATH
        or payload.get("cohort_version") != expected_version
    ):
        raise CohortAllocationError(f"cohort claim v{expected_version} payload is invalid")
    claim_authority = _validate_authority(payload["authority"])
    if (
        claim_authority.requested_version != expected_version
        or not _base_matches(claim_authority, base)
        or payload.get("authority_sha256") != claim_authority.authority_sha256
    ):
        raise CohortAllocationError(f"cohort claim v{expected_version} authority is invalid")
    source = payload["source"]
    if (
        not isinstance(source, Mapping)
        or set(source) != _SOURCE_KEYS
        or source
        != {
            "lab_commit": claim_authority.lab_commit,
            "neqo_commit": claim_authority.neqo_commit,
            "neqo_gitlink": claim_authority.neqo_gitlink,
        }
    ):
        raise CohortAllocationError(f"cohort claim v{expected_version} source is invalid")
    ledger = payload["ledger"]
    if (
        not isinstance(ledger, Mapping)
        or set(ledger) != _LEDGER_BINDING_KEYS
        or ledger
        != {
            "path": base.ledger_path,
            "sha256": base.ledger_sha256,
            "git_object_format": base.object_format,
            "git_blob_oid": base.ledger_blob_oid,
            "payload_base64": base.ledger_payload_base64,
            "last_consumed_version": base.last_consumed_version,
        }
    ):
        raise CohortAllocationError(f"cohort claim v{expected_version} ledger binding is invalid")
    predecessor = payload["predecessor"]
    if (
        not isinstance(predecessor, Mapping)
        or set(predecessor) != _PREDECESSOR_KEYS
        or predecessor != expected_predecessor
    ):
        raise CohortAllocationError(f"cohort claim v{expected_version} predecessor is invalid")
    return dict(value)


def _read_claim(registry_fd: int, name: str, *, version: int) -> _ClaimRecord:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=registry_fd)
    except OSError as error:
        raise CohortAllocationError(f"cohort claim v{version} is unavailable or unsafe") from error
    try:
        before = os.fstat(descriptor)
        entry = os.stat(name, dir_fd=registry_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_CLAIM_BYTES
            or not _same_entry(before, entry)
        ):
            raise CohortAllocationError(f"cohort claim v{version} metadata is unsafe")
        chunks: list[bytes] = []
        observed = 0
        while True:
            block = os.read(descriptor, min(64 * 1024, MAX_CLAIM_BYTES + 1 - observed))
            if not block:
                break
            chunks.append(block)
            observed += len(block)
            if observed > MAX_CLAIM_BYTES:
                raise CohortAllocationError(f"cohort claim v{version} is too large")
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        final_entry = os.stat(name, dir_fd=registry_fd, follow_symlinks=False)
        if (
            len(raw) != before.st_size
            or not _same_entry(before, after)
            or not _same_entry(after, final_entry)
        ):
            raise CohortAllocationError(f"cohort claim v{version} changed while read")
    finally:
        os.close(descriptor)
    value = _load_json_bytes(raw, label=f"cohort claim v{version}")
    if raw != _canonical_bytes(value, newline=True):
        raise CohortAllocationError(f"cohort claim v{version} bytes are not canonical")
    return _ClaimRecord(
        version=version,
        name=name,
        raw=raw,
        sha256=_sha256(raw),
        metadata=before,
        value=value,
    )


def _validate_temp(registry_fd: int, name: str) -> os.stat_result:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=registry_fd)
    except OSError as error:
        raise CohortAllocationError("cohort-claim temporary is unavailable") from error
    try:
        value = os.fstat(descriptor)
        entry = os.stat(name, dir_fd=registry_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_nlink != 1
            or value.st_size > MAX_CLAIM_BYTES
            or not _same_entry(value, entry)
        ):
            raise CohortAllocationError("cohort-claim temporary metadata is unsafe")
        final = os.fstat(descriptor)
        final_entry = os.stat(name, dir_fd=registry_fd, follow_symlinks=False)
        if not _same_entry(value, final) or not _same_entry(final, final_entry):
            raise CohortAllocationError("cohort-claim temporary changed while validated")
        return final
    finally:
        os.close(descriptor)


def _remove_safe_stale_temporaries(registry_fd: int) -> None:
    """Remove only exact private ``.next`` residues while A and B are held."""

    try:
        names = sorted(os.listdir(registry_fd))
    except OSError as error:
        raise CohortAllocationError("cannot enumerate cohort-claim registry") from error
    removed = False
    for name in names:
        if _TEMP_NAME_RE.fullmatch(name) is None:
            continue
        before = _validate_temp(registry_fd, name)
        current = os.stat(name, dir_fd=registry_fd, follow_symlinks=False)
        if not _same_entry(before, current):
            raise CohortAllocationError("cohort-claim temporary changed before cleanup")
        try:
            os.unlink(name, dir_fd=registry_fd)
        except OSError as error:
            raise CohortAllocationError("cohort-claim temporary cannot be removed") from error
        removed = True
    if removed:
        os.fsync(registry_fd)


def _scan_registry(registry_fd: int, base: _BaseAuthority) -> list[_ClaimRecord]:
    try:
        names_before = sorted(os.listdir(registry_fd))
    except OSError as error:
        raise CohortAllocationError("cannot enumerate cohort-claim registry") from error
    if len(names_before) > MAX_REGISTRY_ENTRIES:
        raise CohortAllocationError("cohort-claim registry exceeds its entry limit")
    versions: dict[int, dict[str, str]] = {}
    for name in names_before:
        if name in {REGISTRY_LOCK_NAME, COHORT_OPERATION_LOCK_NAME}:
            continue
        claim_match = _CLAIM_NAME_RE.fullmatch(name)
        if claim_match is not None:
            version = int(claim_match.group(1))
            records = versions.setdefault(version, {})
            if "claim" in records:
                raise CohortAllocationError("cohort-claim registry contains a duplicate version")
            records["claim"] = name
            continue
        anchor_match = _ANCHOR_NAME_RE.fullmatch(name)
        if anchor_match is not None:
            version = int(anchor_match.group(1))
            records = versions.setdefault(version, {})
            if "anchor" in records:
                raise CohortAllocationError("cohort-claim registry contains a duplicate anchor")
            records["anchor"] = name
            continue
        if _TEMP_NAME_RE.fullmatch(name) is not None:
            _validate_temp(registry_fd, name)
            continue
        raise CohortAllocationError(f"cohort-claim registry contains an unexpected entry: {name}")
    ordered = sorted(versions)
    if ordered and ordered != list(range(base.last_consumed_version + 1, ordered[-1] + 1)):
        raise CohortAllocationError("cohort-claim registry is not one dense suffix")
    records: list[_ClaimRecord] = []
    predecessor = {
        "kind": "genesis-ledger",
        "cohort_version": base.last_consumed_version,
        "sha256": base.ledger_sha256,
    }
    for version in ordered:
        names = versions[version]
        claim_record = (
            _read_claim(registry_fd, names["claim"], version=version) if "claim" in names else None
        )
        anchor_record = (
            _read_claim(registry_fd, names["anchor"], version=version)
            if "anchor" in names
            else None
        )
        if claim_record is None and anchor_record is None:
            raise CohortAllocationError(f"cohort claim v{version} has no durable record")
        if (
            claim_record is not None
            and anchor_record is not None
            and claim_record.raw != anchor_record.raw
        ):
            raise CohortAllocationError(f"cohort claim v{version} differs from its anchor")
        # Either independently fsynced pathname is sufficient to prove that the
        # version was consumed.  New publications create both; accepting one
        # preserves conservative consumption after a single-path deletion.
        record = claim_record if claim_record is not None else anchor_record
        assert record is not None
        _validate_claim(
            record.value,
            expected_version=version,
            base=base,
            expected_predecessor=predecessor,
        )
        records.append(record)
        predecessor = {
            "kind": "cohort-claim",
            "cohort_version": version,
            "sha256": record.sha256,
        }
    try:
        names_after = sorted(os.listdir(registry_fd))
    except OSError as error:
        raise CohortAllocationError("cannot re-enumerate cohort-claim registry") from error
    if names_after != names_before:
        raise CohortAllocationError("cohort-claim registry changed while validated")
    return records


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for cohort-claim publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), destination)
    raise OSError(error, os.strerror(error), destination)


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short cohort-claim write")
        offset += written


def _publish_raw_record(registry_fd: int, *, version: int, raw: bytes, destination: str) -> str:
    temporary = f".claim-v{version}.{secrets.token_hex(32)}.next"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    renamed = False
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=registry_fd)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != 0
        ):
            raise CohortAllocationError("new cohort-claim temporary identity is unsafe")
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        entry = os.stat(temporary, dir_fd=registry_fd, follow_symlinks=False)
        if (
            after.st_size != len(raw)
            or not _same_entry(after, entry)
            or stat.S_IMODE(after.st_mode) != 0o600
        ):
            raise CohortAllocationError("new cohort-claim temporary changed before publication")
        os.close(descriptor)
        descriptor = -1
        _rename_noreplace(registry_fd, temporary, destination)
        renamed = True
        os.fsync(registry_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not renamed:
            try:
                os.unlink(temporary, dir_fd=registry_fd)
                os.fsync(registry_fd)
            except FileNotFoundError:
                pass
    return destination


def _publish_raw_claim(registry_fd: int, *, version: int, raw: bytes) -> str:
    return _publish_raw_record(
        registry_fd,
        version=version,
        raw=raw,
        destination=f"claim-v{version}.json",
    )


def _publish_raw_anchor(registry_fd: int, *, version: int, raw: bytes) -> str:
    return _publish_raw_record(
        registry_fd,
        version=version,
        raw=raw,
        destination=f".consumed-v{version}.json",
    )


def _repair_missing_record_counterparts(registry_fd: int, records: list[_ClaimRecord]) -> None:
    """Restore one missing redundant pathname before extending the chain."""

    for record in records:
        claim_name = f"claim-v{record.version}.json"
        anchor_name = f".consumed-v{record.version}.json"
        try:
            os.stat(claim_name, dir_fd=registry_fd, follow_symlinks=False)
        except FileNotFoundError:
            _publish_raw_claim(registry_fd, version=record.version, raw=record.raw)
        try:
            os.stat(anchor_name, dir_fd=registry_fd, follow_symlinks=False)
        except FileNotFoundError:
            _publish_raw_anchor(registry_fd, version=record.version, raw=record.raw)


def _require_redundant_records(
    registry_fd: int,
    records: list[_ClaimRecord],
    *,
    through_version: int,
) -> dict[int, _ClaimRecord]:
    """Require two safe, byte-identical final records through one version."""

    claims: dict[int, _ClaimRecord] = {}
    for record in records:
        if record.version > through_version:
            break
        claim = _read_claim(
            registry_fd,
            f"claim-v{record.version}.json",
            version=record.version,
        )
        anchor = _read_claim(
            registry_fd,
            f".consumed-v{record.version}.json",
            version=record.version,
        )
        if claim.raw != record.raw or anchor.raw != record.raw:
            raise CohortAllocationError(
                f"cohort claim v{record.version} redundancy is inconsistent"
            )
        claims[record.version] = claim
    if through_version not in claims:
        raise CohortAllocationError(f"cohort claim v{through_version} lacks complete redundancy")
    return claims


def _snapshot(
    *,
    registry_metadata: os.stat_result,
    record: _ClaimRecord,
) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "artifact_type": SNAPSHOT_ARTIFACT_TYPE,
        "policy": ALLOCATION_POLICY,
        "cohort_version": record.version,
        "registry": {
            "path": REGISTRY_RELATIVE_PATH,
            "stat": _directory_binding(registry_metadata),
        },
        "claim": {
            "path": f"{REGISTRY_RELATIVE_PATH}/{record.name}",
            "sha256": record.sha256,
            "payload_base64": base64.b64encode(record.raw).decode("ascii"),
            "stat": _file_identity(record.metadata),
        },
        "registry_head_at_publication": {
            "cohort_version": record.version,
            "sha256": record.sha256,
        },
    }
    value["payload_sha256"] = _sha256(_canonical_bytes(value))
    return value


def publish_cohort_claim(
    root: Path,
    authority_value: Any,
    *,
    guardian_lock: GuardianLockAuthority | None = None,
    _retain_operation_lock: bool = False,
) -> dict[str, Any]:
    """Publish one claim under a local or authenticated guardian lock."""

    base = _validate_authority(authority_value)
    if guardian_lock is not None:
        _arm_guardian_owner_death(guardian_lock)
    registry_fd, registry_initial = _open_registry(Path(root), create=guardian_lock is None)
    lock_fd = -1
    operation_lock_fd = -1
    guardian_proof: _GuardianLockProof | None = None
    try:
        if guardian_lock is None:
            lock_fd = _open_registry_lock(registry_fd, create=True)
            operation_lock_fd = _open_operation_lock(registry_fd, create=True)
        else:
            operation_lock_fd = _open_operation_lock(registry_fd, create=False)
            guardian_proof = _open_guardian_lock_proof(
                Path(root),
                registry_fd,
                guardian_lock,
                expected_cohort_version=base.requested_version,
            )
        _remove_safe_stale_temporaries(registry_fd)
        records = _scan_registry(registry_fd, base)
        _repair_missing_record_counterparts(registry_fd, records)
        records = _scan_registry(registry_fd, base)
        head_version = records[-1].version if records else base.last_consumed_version
        if base.requested_version != head_version + 1:
            raise CohortAllocationError(
                f"cohort v{base.requested_version} is not allocatable; "
                f"exact next cohort is v{head_version + 1}"
            )
        predecessor = (
            {
                "kind": "cohort-claim",
                "cohort_version": records[-1].version,
                "sha256": records[-1].sha256,
            }
            if records
            else {
                "kind": "genesis-ledger",
                "cohort_version": base.last_consumed_version,
                "sha256": base.ledger_sha256,
            }
        )
        raw = _canonical_bytes(_claim_value(base, predecessor), newline=True)
        if len(raw) > MAX_CLAIM_BYTES:
            raise CohortAllocationError("cohort claim exceeds its size limit")
        name = _publish_raw_claim(
            registry_fd,
            version=base.requested_version,
            raw=raw,
        )
        _publish_raw_anchor(
            registry_fd,
            version=base.requested_version,
            raw=raw,
        )
        final_records = _scan_registry(registry_fd, base)
        final_claims = _require_redundant_records(
            registry_fd,
            final_records,
            through_version=base.requested_version,
        )
        if (
            len(final_records) != len(records) + 1
            or final_records[-1].version != base.requested_version
            or final_records[-1].name != name
            or final_records[-1].raw != raw
        ):
            raise CohortAllocationError("published cohort claim is not the exact new registry head")
        registry_final = os.fstat(registry_fd)
        if _directory_binding(registry_final) != _directory_binding(registry_initial):
            raise CohortAllocationError("cohort-claim registry identity changed during publication")
        return _snapshot(
            registry_metadata=registry_final,
            record=final_claims[base.requested_version],
        )
    finally:
        try:
            if guardian_proof is not None:
                try:
                    _verify_guardian_lock_proof(
                        Path(root),
                        registry_fd,
                        guardian_proof,
                        expected_cohort_version=base.requested_version,
                    )
                finally:
                    _close_guardian_lock_proof(guardian_proof)
        finally:
            try:
                _close_or_retain_operation_lock(
                    operation_lock_fd,
                    retain=guardian_lock is not None and _retain_operation_lock,
                )
            finally:
                try:
                    if lock_fd >= 0:
                        os.close(lock_fd)
                finally:
                    os.close(registry_fd)


def _validate_snapshot(value: Any) -> tuple[dict[str, Any], bytes, int]:
    if not isinstance(value, Mapping) or set(value) != _SNAPSHOT_KEYS:
        raise CohortAllocationError("cohort-claim publication snapshot schema is invalid")
    payload = dict(value)
    claimed_digest = payload.pop("payload_sha256")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != SNAPSHOT_ARTIFACT_TYPE
        or value.get("policy") != ALLOCATION_POLICY
        or not isinstance(claimed_digest, str)
        or _SHA256_RE.fullmatch(claimed_digest) is None
        or claimed_digest != _sha256(_canonical_bytes(payload))
    ):
        raise CohortAllocationError("cohort-claim publication snapshot digest is invalid")
    version = _positive_integer(value["cohort_version"], label="snapshot cohort version")
    registry = value["registry"]
    claim = value["claim"]
    head = value["registry_head_at_publication"]
    if (
        not isinstance(registry, Mapping)
        or set(registry) != _REGISTRY_SNAPSHOT_KEYS
        or registry.get("path") != REGISTRY_RELATIVE_PATH
        or not _integer_record(registry.get("stat"), keys=_DIRECTORY_BINDING_KEYS)
        or not isinstance(claim, Mapping)
        or set(claim) != _CLAIM_SNAPSHOT_KEYS
        or claim.get("path") != f"{REGISTRY_RELATIVE_PATH}/claim-v{version}.json"
        or not _integer_record(claim.get("stat"), keys=_FILE_STAT_KEYS)
        or not isinstance(head, Mapping)
        or set(head) != {"cohort_version", "sha256"}
        or head.get("cohort_version") != version
        or head.get("sha256") != claim.get("sha256")
    ):
        raise CohortAllocationError("cohort-claim publication snapshot binding is invalid")
    raw = _strict_base64(claim["payload_base64"], label="snapshot claim", maximum=MAX_CLAIM_BYTES)
    if (
        not isinstance(claim.get("sha256"), str)
        or _SHA256_RE.fullmatch(claim["sha256"]) is None
        or _sha256(raw) != claim["sha256"]
    ):
        raise CohortAllocationError("snapshot claim SHA-256 is invalid")
    return dict(value), raw, version


def verify_cohort_claim(
    root: Path,
    snapshot_value: Any,
    *,
    guardian_lock: GuardianLockAuthority | None = None,
    _retain_operation_lock: bool = False,
) -> dict[str, Any]:
    """Verify one claimed version exactly while permitting valid later claims."""

    snapshot, expected_raw, version = _validate_snapshot(snapshot_value)
    claim_value = _load_json_bytes(expected_raw, label="snapshot claim")
    if expected_raw != _canonical_bytes(claim_value, newline=True):
        raise CohortAllocationError("snapshot claim bytes are not canonical")
    if not isinstance(claim_value, Mapping) or not isinstance(claim_value.get("payload"), Mapping):
        raise CohortAllocationError("snapshot claim schema is invalid")
    base = _validate_authority(claim_value["payload"].get("authority"))
    if base.requested_version != version:
        raise CohortAllocationError("snapshot claim version differs from its authority")
    if guardian_lock is not None:
        _arm_guardian_owner_death(guardian_lock)
    registry_fd, registry_metadata = _open_registry(Path(root), create=False)
    lock_fd = -1
    operation_lock_fd = -1
    guardian_proof: _GuardianLockProof | None = None
    try:
        if guardian_lock is None:
            lock_fd = _open_registry_lock(registry_fd, create=False)
            operation_lock_fd = _open_operation_lock(registry_fd, create=False)
        else:
            operation_lock_fd = _open_operation_lock(registry_fd, create=False)
            guardian_proof = _open_guardian_lock_proof(
                Path(root),
                registry_fd,
                guardian_lock,
                expected_cohort_version=version,
            )
        if _directory_binding(registry_metadata) != snapshot["registry"]["stat"]:
            raise CohortAllocationError("cohort-claim registry differs from the snapshot binding")
        records = _scan_registry(registry_fd, base)
        claims = _require_redundant_records(
            registry_fd,
            records,
            through_version=version,
        )
        matching = next((record for record in records if record.version == version), None)
        if matching is None:
            raise CohortAllocationError(f"cohort claim v{version} is absent")
        if (
            matching.name != f"claim-v{version}.json"
            or matching.raw != expected_raw
            or matching.sha256 != snapshot["claim"]["sha256"]
            or _file_identity(matching.metadata) != snapshot["claim"]["stat"]
        ):
            raise CohortAllocationError(f"cohort claim v{version} differs from its snapshot")
        if claims[version].raw != matching.raw:
            raise CohortAllocationError(f"cohort claim v{version} redundancy changed")
        # Deliberately do not require this claim to remain the registry head.
        # Dense, valid successor claims are compatible with historical reproof.
        return snapshot
    finally:
        try:
            if guardian_proof is not None:
                try:
                    _verify_guardian_lock_proof(
                        Path(root),
                        registry_fd,
                        guardian_proof,
                        expected_cohort_version=version,
                    )
                finally:
                    _close_guardian_lock_proof(guardian_proof)
        finally:
            try:
                _close_or_retain_operation_lock(
                    operation_lock_fd,
                    retain=guardian_lock is not None and _retain_operation_lock,
                )
            finally:
                try:
                    if lock_fd >= 0:
                        os.close(lock_fd)
                finally:
                    os.close(registry_fd)


def _chain_value(base: _BaseAuthority, records: list[_ClaimRecord], version: int) -> dict[str, Any]:
    selected = [record for record in records if record.version <= version]
    if (
        not selected
        or selected[0].version != base.last_consumed_version + 1
        or selected[-1].version != version
        or [record.version for record in selected]
        != list(range(base.last_consumed_version + 1, version + 1))
    ):
        raise CohortAllocationError("cohort-claim chain does not close to the genesis ledger")
    claims = [
        {
            "cohort_version": record.version,
            "sha256": record.sha256,
            "payload_base64": base64.b64encode(record.raw).decode("ascii"),
        }
        for record in selected
    ]
    value = {
        "schema_version": 1,
        "artifact_type": CHAIN_ARTIFACT_TYPE,
        "policy": ALLOCATION_POLICY,
        "genesis": {
            "ledger_path": base.ledger_path,
            "ledger_sha256": base.ledger_sha256,
            "last_consumed_version": base.last_consumed_version,
        },
        "claims": claims,
        "head": {
            "cohort_version": version,
            "sha256": selected[-1].sha256,
        },
    }
    value["payload_sha256"] = _sha256(_canonical_bytes(value))
    return value


def cohort_claim_chain(
    root: Path,
    snapshot_value: Any,
    *,
    guardian_lock: GuardianLockAuthority | None = None,
    _retain_operation_lock: bool = False,
) -> dict[str, Any]:
    """Return a self-contained dense claim chain through ``snapshot_value``."""

    snapshot, expected_raw, version = _validate_snapshot(snapshot_value)
    claim_value = _load_json_bytes(expected_raw, label="snapshot claim")
    if expected_raw != _canonical_bytes(claim_value, newline=True):
        raise CohortAllocationError("snapshot claim bytes are not canonical")
    if not isinstance(claim_value, Mapping) or not isinstance(claim_value.get("payload"), Mapping):
        raise CohortAllocationError("snapshot claim schema is invalid")
    base = _validate_authority(claim_value["payload"].get("authority"))
    if base.requested_version != version:
        raise CohortAllocationError("snapshot claim version differs from its authority")
    if guardian_lock is not None:
        _arm_guardian_owner_death(guardian_lock)
    registry_fd, registry_metadata = _open_registry(Path(root), create=False)
    lock_fd = -1
    operation_lock_fd = -1
    guardian_proof: _GuardianLockProof | None = None
    try:
        if guardian_lock is None:
            lock_fd = _open_registry_lock(registry_fd, create=False)
            operation_lock_fd = _open_operation_lock(registry_fd, create=False)
        else:
            operation_lock_fd = _open_operation_lock(registry_fd, create=False)
            guardian_proof = _open_guardian_lock_proof(
                Path(root),
                registry_fd,
                guardian_lock,
                expected_cohort_version=version,
            )
        if _directory_binding(registry_metadata) != snapshot["registry"]["stat"]:
            raise CohortAllocationError("cohort-claim registry differs from the snapshot binding")
        records = _scan_registry(registry_fd, base)
        _require_redundant_records(
            registry_fd,
            records,
            through_version=version,
        )
        matching = next((record for record in records if record.version == version), None)
        if (
            matching is None
            or matching.name != f"claim-v{version}.json"
            or matching.raw != expected_raw
            or matching.sha256 != snapshot["claim"]["sha256"]
            or _file_identity(matching.metadata) != snapshot["claim"]["stat"]
        ):
            raise CohortAllocationError(f"cohort claim v{version} differs from its snapshot")
        chain = _chain_value(base, records, version)
        return chain
    finally:
        try:
            if guardian_proof is not None:
                try:
                    _verify_guardian_lock_proof(
                        Path(root),
                        registry_fd,
                        guardian_proof,
                        expected_cohort_version=version,
                    )
                finally:
                    _close_guardian_lock_proof(guardian_proof)
        finally:
            try:
                _close_or_retain_operation_lock(
                    operation_lock_fd,
                    retain=guardian_lock is not None and _retain_operation_lock,
                )
            finally:
                try:
                    if lock_fd >= 0:
                        os.close(lock_fd)
                finally:
                    os.close(registry_fd)


@contextmanager
def guarded_cohort_evidence_operation(
    root: Path,
    snapshot_value: Any,
    chain_value: Any,
    *,
    guardian_lock: GuardianLockAuthority,
    retain_operation_lock: bool = False,
):
    """Hold authenticated guardian A/B authority over one exact live chain.

    This narrow context is used by the build-completion publisher.  It does
    not expose either lock descriptor: the caller may publish only while the
    remote guardian proof, the operation/drain flock, and the exact redundant
    claim chain are all live.  Remote callers are death-bound to the qcsd
    owner before any registry path is opened.
    """

    snapshot, expected_raw, version = _validate_snapshot(snapshot_value)
    claim_value = _load_json_bytes(expected_raw, label="snapshot claim")
    if expected_raw != _canonical_bytes(claim_value, newline=True):
        raise CohortAllocationError("snapshot claim bytes are not canonical")
    if not isinstance(claim_value, Mapping) or not isinstance(claim_value.get("payload"), Mapping):
        raise CohortAllocationError("snapshot claim schema is invalid")
    base = _validate_authority(claim_value["payload"].get("authority"))
    if base.requested_version != version:
        raise CohortAllocationError("snapshot claim version differs from its authority")
    if not isinstance(chain_value, Mapping):
        raise CohortAllocationError("cohort-claim chain is invalid")
    _arm_guardian_owner_death(guardian_lock)
    registry_fd, registry_metadata = _open_registry(Path(root), create=False)
    operation_lock_fd = -1
    guardian_proof: _GuardianLockProof | None = None
    try:
        operation_lock_fd = _open_operation_lock(registry_fd, create=False)
        guardian_proof = _open_guardian_lock_proof(
            Path(root),
            registry_fd,
            guardian_lock,
            expected_cohort_version=version,
        )

        def reprove() -> dict[str, Any]:
            """Re-prove A, B, and the complete immutable chain while B is held."""

            assert guardian_proof is not None
            _verify_guardian_lock_proof(
                Path(root),
                registry_fd,
                guardian_proof,
                expected_cohort_version=version,
            )
            if _directory_binding(os.fstat(registry_fd)) != snapshot["registry"]["stat"]:
                raise CohortAllocationError(
                    "cohort-claim registry differs from the snapshot binding"
                )
            records = _scan_registry(registry_fd, base)
            claims = _require_redundant_records(
                registry_fd,
                records,
                through_version=version,
            )
            matching = next((record for record in records if record.version == version), None)
            if (
                matching is None
                or matching.name != f"claim-v{version}.json"
                or matching.raw != expected_raw
                or matching.sha256 != snapshot["claim"]["sha256"]
                or _file_identity(matching.metadata) != snapshot["claim"]["stat"]
                or claims[version].raw != matching.raw
            ):
                raise CohortAllocationError(f"cohort claim v{version} differs from its snapshot")
            expected_chain = _chain_value(base, records, version)
            if dict(chain_value) != expected_chain:
                raise CohortAllocationError("cohort-claim chain differs from live registry")
            operation_status = os.fstat(operation_lock_fd)
            operation_entry = os.stat(
                COHORT_OPERATION_LOCK_NAME,
                dir_fd=registry_fd,
                follow_symlinks=False,
            )
            if (
                not _same_entry(operation_status, operation_entry)
                or not stat.S_ISREG(operation_status.st_mode)
                or operation_status.st_uid != os.geteuid()
                or stat.S_IMODE(operation_status.st_mode) != 0o600
                or operation_status.st_nlink != 1
                or operation_status.st_size != 0
            ):
                raise CohortAllocationError("cohort-claim operation lock changed while held")
            # A must still be the guardian's exact live lock after every
            # filesystem read above.  The caller can use this closure at its
            # own irreversible publication boundary rather than relying on a
            # point-in-time proof made when the context was entered.
            _verify_guardian_lock_proof(
                Path(root),
                registry_fd,
                guardian_proof,
                expected_cohort_version=version,
            )
            return {
                "cohort_version": version,
                "authority_sha256": base.authority_sha256,
                "claim_snapshot_sha256": _sha256(_canonical_bytes(snapshot)),
                "claim_file_sha256": matching.sha256,
                "claim_chain_sha256": _sha256(_canonical_bytes(expected_chain)),
                "operation_lock": {
                    "path": str(Path(root) / REGISTRY_RELATIVE_PATH / COHORT_OPERATION_LOCK_NAME),
                    "device": operation_status.st_dev,
                    "inode": operation_status.st_ino,
                    "parent_device": registry_metadata.st_dev,
                    "parent_inode": registry_metadata.st_ino,
                },
            }

        live_authority = reprove()
        live_authority["reprove"] = reprove
        yield live_authority
    finally:
        try:
            if guardian_proof is not None:
                try:
                    _verify_guardian_lock_proof(
                        Path(root),
                        registry_fd,
                        guardian_proof,
                        expected_cohort_version=version,
                    )
                finally:
                    _close_guardian_lock_proof(guardian_proof)
        finally:
            try:
                _close_or_retain_operation_lock(
                    operation_lock_fd,
                    retain=retain_operation_lock,
                )
            finally:
                os.close(registry_fd)


def _stdin_json(*, label: str) -> Any:
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if not raw or len(raw) > MAX_STDIN_BYTES:
        raise CohortAllocationError(f"{label} input is empty or too large")
    return _load_json_bytes(raw, label=label)


def _guardian_lock_from_arguments(arguments: argparse.Namespace) -> GuardianLockAuthority | None:
    names = (
        "held_lock_owner_pid",
        "held_lock_owner_start",
        "held_lock_guardian_pid",
        "held_lock_guardian_start",
        "held_lock_guardian_fd",
        "held_lock_path",
        "held_lock_device",
        "held_lock_inode",
        "held_lock_parent_device",
        "held_lock_parent_inode",
        "held_lock_cohort_version",
    )
    values = [getattr(arguments, name) for name in names]
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise CohortAllocationError("guardian-lock CLI authority is incomplete")
    return GuardianLockAuthority(
        owner_pid=arguments.held_lock_owner_pid,
        owner_start=arguments.held_lock_owner_start,
        guardian_pid=arguments.held_lock_guardian_pid,
        guardian_start=arguments.held_lock_guardian_start,
        guardian_fd=arguments.held_lock_guardian_fd,
        path=arguments.held_lock_path,
        device=arguments.held_lock_device,
        inode=arguments.held_lock_inode,
        parent_device=arguments.held_lock_parent_device,
        parent_inode=arguments.held_lock_parent_inode,
        cohort_version=arguments.held_lock_cohort_version,
    )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qcsd-cohort-allocation")
    actions = parser.add_subparsers(dest="action", required=True)
    for action in ("publish", "verify", "chain"):
        command = actions.add_parser(action)
        command.add_argument("--root", type=Path, required=True)
        command.add_argument("--held-lock-owner-pid", type=int)
        command.add_argument("--held-lock-owner-start", type=int)
        command.add_argument("--held-lock-guardian-pid", type=int)
        command.add_argument("--held-lock-guardian-start", type=int)
        command.add_argument("--held-lock-guardian-fd", type=int)
        command.add_argument("--held-lock-path")
        command.add_argument("--held-lock-device", type=int)
        command.add_argument("--held-lock-inode", type=int)
        command.add_argument("--held-lock-parent-device", type=int)
        command.add_argument("--held-lock-parent-inode", type=int)
        command.add_argument("--held-lock-cohort-version", type=int)
    arguments = parser.parse_args(argv)
    try:
        guardian_lock = _guardian_lock_from_arguments(arguments)
        input_value = _stdin_json(label=f"cohort-allocation {arguments.action}")
        if arguments.action == "publish":
            output = publish_cohort_claim(
                arguments.root,
                input_value,
                guardian_lock=guardian_lock,
                _retain_operation_lock=guardian_lock is not None,
            )
        elif arguments.action == "chain":
            output = cohort_claim_chain(
                arguments.root,
                input_value,
                guardian_lock=guardian_lock,
                _retain_operation_lock=guardian_lock is not None,
            )
        else:
            output = verify_cohort_claim(
                arguments.root,
                input_value,
                guardian_lock=guardian_lock,
                _retain_operation_lock=guardian_lock is not None,
            )
        sys.stdout.buffer.write(_canonical_bytes(output, newline=True))
        sys.stdout.buffer.flush()
        if guardian_lock is not None:
            # B remains held in _PROCESS_EXIT_LOCK_FDS until the kernel closes
            # this process file table.  Do no Python teardown or other work
            # after publishing the one authenticated reply.
            os._exit(0)
        return 0
    except (CohortAllocationError, OSError) as error:
        parser.exit(1, f"qcsd-lab cohort allocation is invalid: {error}\n")


if __name__ == "__main__":
    raise SystemExit(_main())
