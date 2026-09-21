"""Fail-closed host-storage evidence for no-cache study builds."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import hashlib
import importlib.util
import json
import math
import os
import posixpath
import re
import stat
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

BUILD_EXECUTION_ARTIFACT_TYPE = "qcsd-buflo-study-no-cache-build-execution"
BUILD_EXECUTION_MAX_BYTES = 16 * 1024 * 1024
BUILD_COMPLETION_ARTIFACT_TYPE = "qcsd-buflo-study-build-completion"
BUILD_COMPLETION_SCHEMA_VERSION = 1
BUILD_COMPLETION_MAX_BYTES = 64 * 1024
BUILD_COMPLETION_FINAL_REPROOF_BOUNDARY = (
    "after-build-transaction-completion-before-completion-publication"
)
BUILD_COMPLETION_FINAL_REPROOF_MAX_AGE_SECONDS = 2.0
BUILD_WSL_HOST_MIN_AVAILABLE_BYTES = 64 * 1024**3
BUILD_HOST_STORAGE_POLICY = "docker-data-vhdx-backing-volume-minimum-v1"
BUILD_HOST_STORAGE_PROBE = "powershell-get-volume-docker-data-vhdx-v1"
BUILD_HOST_STORAGE_BOUNDARIES = (
    "before-collection",
    "before-prepare",
    "before-reference",
    "after-reference",
)
BUILD_HOST_STORAGE_LOCATION_SOURCES = {
    "wsl-lxss-docker-desktop-data",
    "docker-settings-store",
    "docker-legacy-settings",
}
BUILD_RUST_BASE_IMAGE = (
    "docker.io/library/rust:1.90-bookworm@"
    "sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f"
)
BUILD_DEBIAN_BASE_IMAGE = (
    "docker.io/library/debian:bookworm-slim@"
    "sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
)
BUILD_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
BUILD_IMAGE_TAGS = {
    "collection": "neqo-qcsd-lab-collection:local",
    "prepare": "neqo-qcsd-lab-prepare:local",
    "reference": "neqo-qcsd-lab-reference:local",
}

_OBSERVATION_KEYS = {
    "schema_version",
    "probe",
    "probe_sha256",
    "boundary",
    "observed_at",
    "location_source",
    "data_vhd_path",
    "data_vhd_file_length_bytes",
    "backing_volume_unique_id",
    "drive_letter",
    "file_system",
    "health_status",
    "operational_status",
    "total_bytes",
    "available_bytes",
}
_PREFLIGHT_KEYS = {
    "schema_version",
    "applicable",
    "platform",
    "platform_detection",
    "policy",
    "required_available_bytes",
    "observations",
    "minimum_available_bytes",
    "passed",
}
_BUILD_V1_KEYS = {
    "schema_version",
    "artifact_type",
    "cohort_version",
    "started_at",
    "finished_at",
    "duration_seconds",
    "docker",
    "commands",
    "images",
    "source",
    "build_inputs",
    "dockerfile_sha256",
    "cache_policy",
    "payload_sha256",
}
_BUILD_COMPLETION_KEYS = {
    "schema_version",
    "artifact_type",
    "cohort_version",
    "completed_at",
    "receipt",
    "source",
    "cohort_authority",
    "transaction",
    "final_reproof",
    "payload_sha256",
}
_BUILD_COMPLETION_RECEIPT_KEYS = {
    "path",
    "schema_version",
    "cohort_version",
    "payload_sha256",
    "sha256",
    "stat",
}
_BUILD_COMPLETION_SOURCE_KEYS = {"lab_commit", "neqo_commit", "neqo_gitlink"}
_BUILD_COMPLETION_AUTHORITY_KEYS = {
    "allocation_sha256",
    "claim_snapshot_sha256",
    "claim_file_sha256",
    "claim_chain_sha256",
    "claim_chain_payload_sha256",
}
_BUILD_COMPLETION_REPROOF_KEYS = {
    "boundary",
    "observed_at",
    "authority_sha256",
    "claim_snapshot_sha256",
    "claim_file_sha256",
    "claim_chain_sha256",
}
_BUILD_COMPLETION_LIFECYCLE_KEYS = {
    "path",
    "device",
    "inode",
    "parent_device",
    "parent_inode",
    "lease_nonce",
}
_BUILD_TRANSACTION_RETIREMENT_ARTIFACT_TYPE = (
    "qcsd-buflo-study-build-transaction-retirement"
)
_BUILD_TRANSACTION_BINDING_KEYS = {
    "schema_version",
    "artifact_type",
    "root",
    "record",
}
_BUILD_TRANSACTION_ROOT_KEYS = {"path", "stat"}

# ``python -I path/to/build_storage.py`` cannot import the sibling through the
# package namespace.  Keep the exact fallback module object process-local once
# loaded: GuardianLockAuthority instances must be checked by the same class
# object used by guarded_cohort_evidence_operation.
_COHORT_ALLOCATION_MODULE: Any | None = None
_BUILD_TRANSACTION_RECORD_KEYS = {
    "path",
    "sha256",
    "payload_base64",
    "stat",
}
_BUILD_COMPLETION_TRANSACTION_KEYS = {
    "schema_version",
    "artifact_type",
    "root",
    "record",
    "guardian",
    "lifecycle_lock",
    "cohort_lock",
    "operation_lock",
}
_BUILD_COMPLETION_GUARDIAN_KEYS = {
    "pid",
    "start_time",
    "qcsd_pid",
    "qcsd_start_time",
}
_BUILD_COMPLETION_COHORT_LOCK_KEYS = {
    "path",
    "device",
    "inode",
    "parent_device",
    "parent_inode",
    "guardian_fd",
}
_BUILD_COMPLETION_OPERATION_LOCK_KEYS = {
    "path",
    "device",
    "inode",
    "parent_device",
    "parent_inode",
}
_COHORT_ALLOCATION_KEYS = {
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
_COHORT_ALLOCATION_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-allocation"
_COHORT_ALLOCATION_POLICY = "dense-prefix-durable-publications-consume-v1"
_COHORT_LEDGER_PATH = "config/buflo-study/v1/consumed-cohorts.json"
_COHORT_LEDGER_ARTIFACT_TYPE = "qcsd-buflo-study-consumed-cohorts"
_COHORT_LEDGER_MAX_BYTES = 16 * 1024
_COHORT_GIT_PROOF_KEYS = {
    "schema_version",
    "artifact_type",
    "commit_payload_base64",
    "tree_payloads_base64",
}
_COHORT_GIT_PROOF_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-ledger-git-proof"
_COHORT_GIT_PROOF_COMMIT_MAX_BYTES = 256 * 1024
_COHORT_GIT_PROOF_TREE_MAX_BYTES = 1024 * 1024
_COHORT_GIT_PROOF_TREE_COUNT = 4
_COHORT_CLAIM_MAX_BYTES = 4 * 1024 * 1024
_COHORT_CLAIM_REGISTRY_PATH = "artifacts/buflo-study/cohort-claims-v1"
_COHORT_CLAIM_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-claim"
_COHORT_CLAIM_SNAPSHOT_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-claim-publication"
_COHORT_AUTHORITY_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-allocation-authority"
_COHORT_CLAIM_SNAPSHOT_KEYS = {
    "schema_version",
    "artifact_type",
    "policy",
    "cohort_version",
    "registry",
    "claim",
    "registry_head_at_publication",
    "payload_sha256",
}
_COHORT_CLAIM_KEYS = {"schema_version", "artifact_type", "payload", "payload_sha256"}
_COHORT_CLAIM_PAYLOAD_KEYS = {
    "policy",
    "registry_path",
    "cohort_version",
    "authority",
    "authority_sha256",
    "source",
    "ledger",
    "predecessor",
}
_COHORT_AUTHORITY_KEYS = {"schema_version", "artifact_type", "git", "filesystem", "receipt"}
_COHORT_AUTHORITY_GIT_KEYS = {
    "object_format",
    "lab_head",
    "head_blob_oid",
    "index_blob_oid",
    "worktree_blob_oid",
    "neqo_head",
    "head_gitlink",
    "index_gitlink",
}
_COHORT_AUTHORITY_FILESYSTEM_KEYS = {"directories", "ledger", "git_index"}
_COHORT_AUTHORITY_DIRECTORY_NAMES = {
    "repository-root",
    "config",
    "buflo-study",
    "v1",
    "git",
}
_COHORT_CLAIM_SOURCE_KEYS = {"lab_commit", "neqo_commit", "neqo_gitlink"}
_COHORT_CLAIM_LEDGER_KEYS = {
    "path",
    "sha256",
    "git_object_format",
    "git_blob_oid",
    "payload_base64",
    "last_consumed_version",
}
_COHORT_CLAIM_PREDECESSOR_KEYS = {"kind", "cohort_version", "sha256"}
_COHORT_CLAIM_CHAIN_ARTIFACT_TYPE = "qcsd-buflo-study-cohort-claim-chain"
_COHORT_CLAIM_CHAIN_KEYS = {
    "schema_version",
    "artifact_type",
    "policy",
    "genesis",
    "claims",
    "head",
    "payload_sha256",
}
_COHORT_CLAIM_CHAIN_GENESIS_KEYS = {
    "ledger_path",
    "ledger_sha256",
    "last_consumed_version",
}
_COHORT_CLAIM_CHAIN_ENTRY_KEYS = {
    "cohort_version",
    "sha256",
    "payload_base64",
}
_COHORT_CLAIM_CHAIN_HEAD_KEYS = {"cohort_version", "sha256"}
_COHORT_CLAIM_CHAIN_MAX_ENTRIES = 4096
_COHORT_CLAIM_CHAIN_MAX_DECODED_BYTES = 8 * 1024 * 1024
_COHORT_SNAPSHOT_REGISTRY_KEYS = {"path", "stat"}
_COHORT_SNAPSHOT_CLAIM_KEYS = {"path", "sha256", "payload_base64", "stat"}
_COHORT_FILE_STAT_KEYS = {
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
_COHORT_DIRECTORY_STAT_KEYS = {"dev", "inode", "uid", "gid", "mode", "nlink"}
_COHORT_AUTHORITY_GIT_DIRECTORY_KEYS = {"type", "dev", "inode", "uid", "gid", "mode"}
_COHORT_AUTHORITY_SCHEMA_VERSIONS = {1, 2}
_COHORT_REPROOF_KEYS = {
    "boundary",
    "observed_at",
    "authority_sha256",
    "claim_snapshot_sha256",
    "claim_file_sha256",
}
_COHORT_REPROOF_BOUNDARIES = (
    "after-cohort-claim-before-docker-recovery",
    "immediately-before-docker-recovery",
    "after-evidence-build-lock",
    "immediately-before-build-transaction",
    "immediately-after-build-transaction",
    "immediately-before-collection-build",
    "immediately-before-prepare-build",
    "immediately-before-reference-build",
    "after-reference-build-before-receipt",
)
_COHORT_FINAL_REPROOF_MAX_AGE_SECONDS = 2.0
_BUILDX_IDENTITY_KEYS = {
    "selection_source",
    "plugin_name",
    "plugin_vendor",
    "metadata_schema_version",
    "short_description",
    "reported_plugin_version",
    "reported_plugin_path",
    "plugin",
    "resolved",
    "version_output",
    "version",
    "commit",
}
_BUILDX_KEYS = {"schema_version", "policy", "identity", "observations", "passed"}
_BUILDX_OBSERVATION_KEYS = {"boundary", "observed_at", "identity_sha256"}
_BUILDX_BOUNDARIES = (
    "before-collection",
    "after-collection",
    "after-prepare",
    "after-reference",
)
_BUILDX_STAT_KEYS = {
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
_BUILDX_PLUGIN_KEYS = {"path", "symlink_target"} | _BUILDX_STAT_KEYS
_BUILDX_RESOLVED_KEYS = {"path", "sha256"} | _BUILDX_STAT_KEYS
_BUILDX_DOCKER_METADATA_KEYS = {
    "Name",
    "Path",
    "SchemaVersion",
    "ShortDescription",
    "Vendor",
    "Version",
}
_BUILDX_PLUGIN_DIRECTORIES = frozenset(
    PurePosixPath(path)
    for path in (
        "/usr/local/lib/docker/cli-plugins",
        "/usr/local/libexec/docker/cli-plugins",
        "/usr/lib/docker/cli-plugins",
        "/usr/libexec/docker/cli-plugins",
    )
)
_BUILDX_SELECTION_SOURCE = "docker-info-client-plugin-metadata-v1"
_BUILDX_POLICY = "docker-selected-buildx-binary-stability-v1"
_BUILDX_REQUIRED_UID = 0
_BUILDX_REQUIRED_GID = 0
_ROLE_PROVENANCE_KEYS = {"schema_version", "sources", "build_inputs"}
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_REPO_DIGEST_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_LIFECYCLE_TRANSACTION_NAME_RE = re.compile(r"transaction[.]([0-9a-f]{32})")
_GUARDIAN_FDINFO_LOCK_RE = re.compile(
    r"lock:\s+[0-9]+:\s+FLOCK\s+ADVISORY\s+WRITE\s+"
    r"([1-9][0-9]*)\s+\S+\s+0\s+EOF"
)
_BUILDX_VERSION_OUTPUT_RE = re.compile(
    r"github[.]com/docker/buildx "
    r"(?P<version>v(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.]"
    r"(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?) "
    r"(?P<commit>[0-9a-f]{40})"
)
_VOLUME_ID_RE = re.compile(
    r"\\\\\?\\Volume\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\"
)
_WINDOWS_VHD_RE = re.compile(r"[A-Za-z]:\\[^\r\n]+\.vhdx", re.IGNORECASE)
_SOURCE_KEYS = {
    "image_digest",
    "lab_commit",
    "lab_dirty",
    "lab_patch_sha256",
    "neqo_commit",
    "neqo_pinned_commit",
    "neqo_dirty",
    "neqo_patch_sha256",
}
_BUILD_INPUT_KEYS = {
    "schema_version",
    "artifact_type",
    "rust_base_image",
    "debian_base_image",
    "uv_lock_sha256",
    "cargo_lock_sha256",
}


def _canonical_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


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


def _stat_record(value: os.stat_result) -> dict[str, int]:
    return {
        "dev": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": value.st_mode,
        "nlink": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _completion_file_stat_record(value: os.stat_result) -> dict[str, int]:
    """Project one receipt inode into its exact local completion binding."""

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


def _read_stable_regular_file_with_stat(
    path: Path,
    *,
    label: str,
    maximum_bytes: int | None = None,
) -> tuple[bytes, os.stat_result]:
    """Read one regular file through a no-symlink component walk."""

    if maximum_bytes is not None and (type(maximum_bytes) is not int or maximum_bytes < 0):
        raise ValueError(f"{label} maximum byte count is invalid")
    candidate = Path(os.path.abspath(path))
    if candidate == Path(candidate.anchor):
        raise ValueError(f"{label} is not a stable single regular file")
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    directory_descriptors: list[int] = []
    directory_links: list[tuple[int, str, int]] = []
    descriptor: int | None = None
    try:
        root_descriptor = os.open(candidate.anchor, directory_flags)
        directory_descriptors.append(root_descriptor)
        for component in candidate.parts[1:-1]:
            parent_descriptor = directory_descriptors[-1]
            child_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            child_stat = os.fstat(child_descriptor)
            if not stat.S_ISDIR(child_stat.st_mode):
                os.close(child_descriptor)
                raise ValueError(f"{label} path contains a non-directory component")
            directory_descriptors.append(child_descriptor)
            directory_links.append((parent_descriptor, component, child_descriptor))
        directory_descriptor = directory_descriptors[-1]
        filename = candidate.parts[-1]
        pathname_before = os.stat(
            filename,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(pathname_before.st_mode)
            or pathname_before.st_nlink != 1
            or (maximum_bytes is not None and pathname_before.st_size > maximum_bytes)
        ):
            raise ValueError(f"{label} is not a stable single regular file")
        descriptor = os.open(filename, file_flags, dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _stat_identity(pathname_before) != _stat_identity(before)
            or (maximum_bytes is not None and before.st_size > maximum_bytes)
        ):
            raise ValueError(f"{label} is not a stable single regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        grew_while_reading = bool(os.read(descriptor, 1))
        after = os.fstat(descriptor)
        pathname_after = os.stat(
            filename,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        root_after = os.fstat(root_descriptor)
        root_path_after = os.stat(candidate.anchor, follow_symlinks=False)
        directory_path_stable = _same_directory_entry(root_after, root_path_after) and all(
            _same_directory_entry(
                os.fstat(child_descriptor),
                os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                ),
            )
            for parent_descriptor, component, child_descriptor in directory_links
        )
    except OSError as error:
        raise ValueError(f"{label} cannot be read safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)
    raw = b"".join(chunks)
    if (
        not directory_path_stable
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(pathname_after)
        or len(raw) != before.st_size
        or grew_while_reading
    ):
        raise ValueError(f"{label} changed while it was read")
    return raw, before


def _read_stable_regular_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int | None = None,
) -> bytes:
    raw, _status = _read_stable_regular_file_with_stat(
        path,
        label=label,
        maximum_bytes=maximum_bytes,
    )
    return raw


def _nonempty_buildx_string(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in value)
    )


def _canonical_buildx_path(value: Any, *, label: str) -> PurePosixPath:
    if not _nonempty_buildx_string(value) or "\0" in value or value.startswith("//"):
        raise ValueError(f"{label} is not an absolute canonical path")
    path = PurePosixPath(value)
    if not path.is_absolute() or path.parent == path or str(path) != value or ".." in path.parts:
        raise ValueError(f"{label} is not an absolute canonical path")
    return path


def _validate_buildx_stat(value: Mapping[str, Any], *, label: str) -> dict[str, int]:
    if set(value) != _BUILDX_STAT_KEYS or any(type(value.get(key)) is not int for key in value):
        raise ValueError(f"{label} stat identity is invalid")
    record = {key: value[key] for key in _BUILDX_STAT_KEYS}
    if (
        record["dev"] < 0
        or record["inode"] <= 0
        or record["uid"] < 0
        or record["gid"] < 0
        or record["mode"] <= 0
        or record["mode"] > 0o177777
        or record["nlink"] <= 0
        or record["size"] < 0
        or record["mtime_ns"] < 0
        or record["ctime_ns"] < 0
    ):
        raise ValueError(f"{label} stat identity is invalid")
    return record


def _validate_buildx_identity(
    value: Any,
    *,
    allowed_plugin_directories: frozenset[PurePosixPath] = _BUILDX_PLUGIN_DIRECTORIES,
    required_uid: int = _BUILDX_REQUIRED_UID,
    required_gid: int = _BUILDX_REQUIRED_GID,
) -> dict[str, Any]:
    """Validate one Docker-selected buildx binary identity."""

    if not isinstance(value, Mapping) or set(value) != _BUILDX_IDENTITY_KEYS:
        raise ValueError("no-cache build buildx identity schema is invalid")
    if (
        value.get("selection_source") != _BUILDX_SELECTION_SOURCE
        or value.get("plugin_name") != "buildx"
        or not _nonempty_buildx_string(value.get("plugin_vendor"))
        or not _nonempty_buildx_string(value.get("metadata_schema_version"))
        or not _nonempty_buildx_string(value.get("short_description"))
        or not _nonempty_buildx_string(value.get("reported_plugin_version"))
    ):
        raise ValueError("no-cache build Docker buildx metadata is invalid")
    reported_path = _canonical_buildx_path(
        value.get("reported_plugin_path"),
        label="Docker-reported buildx plugin path",
    )
    if (
        reported_path.name != "docker-buildx"
        or reported_path.parent not in allowed_plugin_directories
    ):
        raise ValueError("Docker-reported buildx plugin path is outside fixed system directories")

    plugin = value.get("plugin")
    resolved = value.get("resolved")
    if not isinstance(plugin, Mapping) or set(plugin) != _BUILDX_PLUGIN_KEYS:
        raise ValueError("no-cache build buildx plugin identity is invalid")
    if not isinstance(resolved, Mapping) or set(resolved) != _BUILDX_RESOLVED_KEYS:
        raise ValueError("no-cache build resolved buildx identity is invalid")
    plugin_path = _canonical_buildx_path(plugin.get("path"), label="buildx plugin lexical path")
    resolved_path = _canonical_buildx_path(
        resolved.get("path"), label="resolved buildx target path"
    )
    if plugin_path != reported_path:
        raise ValueError("no-cache build buildx path binding is invalid")

    plugin_stat = _validate_buildx_stat(
        {key: plugin[key] for key in _BUILDX_STAT_KEYS}, label="buildx plugin"
    )
    resolved_stat = _validate_buildx_stat(
        {key: resolved[key] for key in _BUILDX_STAT_KEYS}, label="resolved buildx target"
    )
    symlink_target = plugin.get("symlink_target")
    if symlink_target is None:
        if (
            not stat.S_ISREG(plugin_stat["mode"])
            or plugin_path != resolved_path
            or plugin_stat != resolved_stat
        ):
            raise ValueError("direct buildx plugin identity does not bind its resolved target")
    else:
        if (
            not _nonempty_buildx_string(symlink_target)
            or "\0" in symlink_target
            or symlink_target.startswith("//")
            or not stat.S_ISLNK(plugin_stat["mode"])
        ):
            raise ValueError("buildx plugin symlink identity is invalid")
        target_path = PurePosixPath(symlink_target)
        if str(target_path) != symlink_target:
            raise ValueError("buildx plugin symlink target is not canonical")
        target_from_parent = (
            target_path if target_path.is_absolute() else plugin_path.parent / target_path
        )
        normalized_target = PurePosixPath(posixpath.normpath(str(target_from_parent)))
        if normalized_target != resolved_path or plugin_stat["size"] != len(
            os.fsencode(symlink_target)
        ):
            raise ValueError("buildx plugin symlink target differs from the resolved target")
    if (
        plugin_stat["uid"] != required_uid
        or plugin_stat["gid"] != required_gid
        or plugin_stat["nlink"] != 1
        or not stat.S_ISREG(resolved_stat["mode"])
        or resolved_stat["uid"] != required_uid
        or resolved_stat["gid"] != required_gid
        or resolved_stat["nlink"] != 1
        or resolved_stat["size"] <= 0
        or not resolved_stat["mode"] & 0o111
        or resolved_stat["mode"] & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH)
        or not isinstance(resolved.get("sha256"), str)
        or _SHA256_RE.fullmatch(resolved["sha256"]) is None
    ):
        raise ValueError("resolved buildx target is not a safe root-owned executable")

    version_output = value.get("version_output")
    match = (
        _BUILDX_VERSION_OUTPUT_RE.fullmatch(version_output)
        if isinstance(version_output, str)
        else None
    )
    if (
        match is None
        or value.get("version") != match.group("version")
        or value.get("commit") != match.group("commit")
        or value.get("reported_plugin_version") != match.group("version")
    ):
        raise ValueError("no-cache build buildx version binding is invalid")
    return {
        "selection_source": value["selection_source"],
        "plugin_name": value["plugin_name"],
        "plugin_vendor": value["plugin_vendor"],
        "metadata_schema_version": value["metadata_schema_version"],
        "short_description": value["short_description"],
        "reported_plugin_version": value["reported_plugin_version"],
        "reported_plugin_path": value["reported_plugin_path"],
        "plugin": dict(plugin),
        "resolved": dict(resolved),
        "version_output": version_output,
        "version": value["version"],
        "commit": value["commit"],
    }


def validate_buildx_provenance(
    value: Any,
    *,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> dict[str, Any]:
    """Validate the schema-1 four-boundary buildx stability proof."""

    if (started_at is None) != (finished_at is None):
        raise ValueError("buildx timing validation requires both build endpoints")
    if (
        not isinstance(value, Mapping)
        or set(value) != _BUILDX_KEYS
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("policy") != _BUILDX_POLICY
        or value.get("passed") is not True
    ):
        raise ValueError("no-cache build buildx provenance schema is invalid")
    identity = _validate_buildx_identity(value.get("identity"))
    identity_sha256 = _canonical_digest(identity)
    observations = value.get("observations")
    if not isinstance(observations, list) or len(observations) != len(_BUILDX_BOUNDARIES):
        raise ValueError("no-cache build buildx observation inventory is invalid")
    projected_observations: list[dict[str, Any]] = []
    observed_times: list[datetime] = []
    for observation, boundary in zip(observations, _BUILDX_BOUNDARIES, strict=True):
        if (
            not isinstance(observation, Mapping)
            or set(observation) != _BUILDX_OBSERVATION_KEYS
            or observation.get("boundary") != boundary
            or not isinstance(observation.get("observed_at"), str)
            or not isinstance(observation.get("identity_sha256"), str)
            or _SHA256_RE.fullmatch(observation["identity_sha256"]) is None
            or observation["identity_sha256"] != identity_sha256
        ):
            raise ValueError("no-cache build buildx observation is invalid")
        observed_times.append(
            _aware_timestamp(observation.get("observed_at"), label="buildx observation")
        )
        projected_observations.append(dict(observation))
    if any(left >= right for left, right in zip(observed_times, observed_times[1:])):
        raise ValueError("no-cache build buildx observations are not strictly increasing")
    if started_at is not None and finished_at is not None:
        if (
            not isinstance(started_at, datetime)
            or not isinstance(finished_at, datetime)
            or started_at.tzinfo is None
            or finished_at.tzinfo is None
        ):
            raise ValueError("buildx timing endpoints are not timezone-aware")
        first, second, third, fourth = observed_times
        if not started_at <= first < second < third < fourth <= finished_at:
            raise ValueError("no-cache build buildx observations fall outside the build")
    return {
        "schema_version": 1,
        "policy": _BUILDX_POLICY,
        "identity": identity,
        "observations": projected_observations,
        "passed": True,
    }


def capture_buildx_observation(
    plugin_metadata: Any,
    *,
    version_output: str,
    allowed_plugin_directories: frozenset[PurePosixPath] | None = None,
    required_uid: int = _BUILDX_REQUIRED_UID,
    required_gid: int = _BUILDX_REQUIRED_GID,
) -> dict[str, Any]:
    """Capture the one healthy Docker-reported buildx plugin and its stable target."""

    if not isinstance(plugin_metadata, list):
        raise ValueError("Docker client plugin metadata is not a list")
    matches = [
        item
        for item in plugin_metadata
        if isinstance(item, Mapping) and item.get("Name") == "buildx"
    ]
    if len(matches) != 1:
        raise ValueError("Docker did not report exactly one buildx client plugin")
    metadata = matches[0]
    if set(metadata) != _BUILDX_DOCKER_METADATA_KEYS or any(
        not _nonempty_buildx_string(metadata.get(key)) for key in metadata
    ):
        raise ValueError("Docker buildx client plugin metadata is not the exact healthy schema")
    reported = _canonical_buildx_path(metadata["Path"], label="Docker-reported buildx plugin path")
    configured_directories = (
        _BUILDX_PLUGIN_DIRECTORIES
        if allowed_plugin_directories is None
        else allowed_plugin_directories
    )
    allowed_directories = frozenset(
        _canonical_buildx_path(str(path), label="allowed buildx plugin directory")
        for path in configured_directories
    )
    if (
        not allowed_directories
        or type(required_uid) is not int
        or required_uid < 0
        or type(required_gid) is not int
        or required_gid < 0
    ):
        raise ValueError("buildx capture ownership policy is invalid")
    if reported.name != "docker-buildx" or reported.parent not in allowed_directories:
        raise ValueError("Docker-reported buildx plugin path is outside fixed system directories")
    match = (
        _BUILDX_VERSION_OUTPUT_RE.fullmatch(version_output)
        if isinstance(version_output, str)
        else None
    )
    if match is None:
        raise ValueError("Docker buildx version output is invalid")
    lexical_path = Path(str(reported))
    try:
        lexical_before = lexical_path.lstat()
        if stat.S_ISLNK(lexical_before.st_mode):
            symlink_target: str | None = os.readlink(lexical_path)
        elif stat.S_ISREG(lexical_before.st_mode):
            symlink_target = None
        else:
            raise ValueError("Docker-reported buildx plugin is neither a symlink nor regular file")
        resolved_path = lexical_path.resolve(strict=True)
        resolved_canonical = _canonical_buildx_path(
            str(resolved_path), label="resolved buildx target path"
        )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(resolved_path, flags)
    except OSError as error:
        raise ValueError("Docker-reported buildx plugin cannot be resolved safely") from error
    digest = hashlib.sha256()
    total = 0
    try:
        resolved_before = os.fstat(descriptor)
        if (
            lexical_before.st_uid != required_uid
            or lexical_before.st_gid != required_gid
            or lexical_before.st_nlink != 1
            or not stat.S_ISREG(resolved_before.st_mode)
            or resolved_before.st_uid != required_uid
            or resolved_before.st_gid != required_gid
            or resolved_before.st_nlink != 1
            or resolved_before.st_size <= 0
            or not resolved_before.st_mode & 0o111
            or resolved_before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("Docker-reported buildx plugin is not a safe executable")
        remaining = resolved_before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            remaining -= len(chunk)
        grew_while_reading = bool(os.read(descriptor, 1))
        resolved_after = os.fstat(descriptor)
        resolved_path_after = resolved_path.stat(follow_symlinks=False)
        lexical_after = lexical_path.lstat()
        symlink_target_after = (
            os.readlink(lexical_path) if stat.S_ISLNK(lexical_after.st_mode) else None
        )
        resolved_from_lexical_after = lexical_path.resolve(strict=True)
    except OSError as error:
        raise ValueError("Docker-reported buildx plugin changed while it was read") from error
    finally:
        os.close(descriptor)
    if (
        _stat_identity(lexical_before) != _stat_identity(lexical_after)
        or symlink_target_after != symlink_target
        or resolved_from_lexical_after != resolved_path
        or _stat_identity(resolved_before) != _stat_identity(resolved_after)
        or _stat_identity(resolved_after) != _stat_identity(resolved_path_after)
        or total != resolved_before.st_size
        or grew_while_reading
    ):
        raise ValueError("Docker-reported buildx plugin changed while it was read")
    record = {
        "selection_source": _BUILDX_SELECTION_SOURCE,
        "plugin_name": metadata["Name"],
        "plugin_vendor": metadata["Vendor"],
        "metadata_schema_version": metadata["SchemaVersion"],
        "short_description": metadata["ShortDescription"],
        "reported_plugin_version": metadata["Version"],
        "reported_plugin_path": metadata["Path"],
        "plugin": {
            "path": metadata["Path"],
            "symlink_target": symlink_target,
            **_stat_record(lexical_before),
        },
        "resolved": {
            "path": str(resolved_canonical),
            "sha256": digest.hexdigest(),
            **_stat_record(resolved_before),
        },
        "version_output": version_output,
        "version": match.group("version"),
        "commit": match.group("commit"),
    }
    identity = _validate_buildx_identity(
        record,
        allowed_plugin_directories=allowed_directories,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    observed_at = datetime.now(UTC).isoformat()
    return {
        "observed_at": observed_at,
        "identity": identity,
        "identity_sha256": _canonical_digest(identity),
    }


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"JSON object contains duplicate key: {key}")
        value[key] = item
    return value


def _load_stable_unique_json(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    required_private_file: bool = False,
) -> tuple[Path, bytes, Any, os.stat_result]:
    candidate = Path(os.path.abspath(path))
    if candidate.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    try:
        resolved_before = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label} path cannot be resolved") from error
    if resolved_before != candidate:
        raise ValueError(f"{label} path contains a symlink")
    raw, status = _read_stable_regular_file_with_stat(
        candidate,
        label=label,
        maximum_bytes=maximum_bytes,
    )
    if required_private_file and (
        status.st_uid != os.geteuid()
        or status.st_gid != os.getegid()
        or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_nlink != 1
    ):
        raise ValueError(f"{label} is not one private create-only regular file")
    try:
        resolved_after = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label} path cannot be resolved") from error
    if resolved_after != resolved_before:
        raise ValueError(f"{label} path changed while it was read")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not unique-key UTF-8 JSON") from error
    return resolved_after, raw, value, status


def load_stable_build_execution_with_stat(
    path: Path,
) -> tuple[Path, bytes, Any, os.stat_result]:
    """Read one build receipt and return the stat bound to those exact bytes."""

    return _load_stable_unique_json(
        path,
        label="build execution receipt",
        maximum_bytes=BUILD_EXECUTION_MAX_BYTES,
    )


def load_stable_build_execution(path: Path) -> tuple[Path, bytes, Any]:
    """Read one build receipt once, rejecting symlinks and duplicate JSON keys."""

    resolved, raw, value, _status = load_stable_build_execution_with_stat(path)
    return resolved, raw, value


def load_stable_build_completion(path: Path) -> tuple[Path, bytes, Any]:
    """Read one authoritative build-completion record through a stable inode."""

    resolved, raw, value, _status = _load_stable_unique_json(
        path,
        label="build completion",
        maximum_bytes=BUILD_COMPLETION_MAX_BYTES,
        required_private_file=True,
    )
    if raw != _canonical_finite_json_bytes(value, label="build completion", newline=True):
        raise ValueError("build-completion bytes are not canonical")
    return resolved, raw, value


def _invalid_json_constant(value: str) -> Any:
    raise ValueError(f"JSON contains invalid constant: {value}")


def _one_version_output_line(raw: bytes) -> str:
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or b"\n" in raw or b"\r" in raw:
        raise ValueError("Docker buildx version observation is not exactly one line")
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise ValueError("Docker buildx version observation is not UTF-8") from error


def _aware_timestamp(value: Any, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{label} timestamp is not timezone-aware")
    return parsed


def _positive_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} is not a positive integer")
    return value


def _validate_clean_source(value: Any, *, collection_image: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SOURCE_KEYS:
        raise ValueError("no-cache build source metadata is malformed")
    commits = (value["lab_commit"], value["neqo_commit"], value["neqo_pinned_commit"])
    if (
        value["image_digest"] != collection_image
        or any(
            not isinstance(commit, str) or _COMMIT_RE.fullmatch(commit) is None
            for commit in commits
        )
        or value["neqo_commit"] != value["neqo_pinned_commit"]
        or value["lab_dirty"] is not False
        or value["neqo_dirty"] is not False
        or value["lab_patch_sha256"] != BUILD_EMPTY_SHA256
        or value["neqo_patch_sha256"] != BUILD_EMPTY_SHA256
    ):
        raise ValueError("no-cache build was not produced by one concrete clean collection image")
    return dict(value)


def _validate_build_inputs(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _BUILD_INPUT_KEYS
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["artifact_type"] != "qcsd-study-build-inputs"
        or value["rust_base_image"] != BUILD_RUST_BASE_IMAGE
        or value["debian_base_image"] != BUILD_DEBIAN_BASE_IMAGE
        or not isinstance(value["uv_lock_sha256"], str)
        or _SHA256_RE.fullmatch(value["uv_lock_sha256"]) is None
        or not isinstance(value["cargo_lock_sha256"], str)
        or _SHA256_RE.fullmatch(value["cargo_lock_sha256"]) is None
    ):
        raise ValueError("no-cache build inputs are invalid")
    return dict(value)


def _decode_canonical_base64(
    value: Any,
    *,
    label: str,
    maximum_bytes: int,
) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} encoding is invalid")
    try:
        encoded = value.encode("ascii")
        payload = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise ValueError(f"{label} encoding is invalid") from error
    if (
        not payload
        or len(payload) > maximum_bytes
        or base64.b64encode(payload) != encoded
    ):
        raise ValueError(f"{label} encoding is invalid")
    return payload


def _git_sha1_object_oid(object_type: bytes, payload: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(object_type + b" " + str(len(payload)).encode("ascii") + b"\0")
    digest.update(payload)
    return digest.hexdigest()


def _parse_git_tree(payload: bytes) -> dict[bytes, tuple[bytes, str]]:
    """Parse one complete canonical SHA-1 Git tree payload."""

    entries: dict[bytes, tuple[bytes, str]] = {}
    previous_sort_key: bytes | None = None
    offset = 0
    allowed_modes = {b"40000", b"100644", b"100755", b"120000", b"160000"}
    while offset < len(payload):
        space = payload.find(b" ", offset)
        nul = payload.find(b"\0", space + 1) if space >= 0 else -1
        oid_start = nul + 1
        oid_end = oid_start + 20
        if space <= offset or nul <= space + 1 or oid_end > len(payload):
            raise ValueError("no-cache build cohort Git proof tree payload is malformed")
        mode = payload[offset:space]
        name = payload[space + 1 : nul]
        if (
            mode not in allowed_modes
            or name in {b"", b".", b".."}
            or b"/" in name
            or name in entries
        ):
            raise ValueError("no-cache build cohort Git proof tree payload is malformed")
        sort_key = name + (b"/" if mode == b"40000" else b"")
        if previous_sort_key is not None and sort_key <= previous_sort_key:
            raise ValueError("no-cache build cohort Git proof tree payload is malformed")
        previous_sort_key = sort_key
        entries[name] = (mode, payload[oid_start:oid_end].hex())
        offset = oid_end
    if not entries:
        raise ValueError("no-cache build cohort Git proof tree payload is malformed")
    return entries


def _validate_lab_commit_ledger_proof(
    value: Any,
    *,
    lab_commit: str,
    ledger_blob_oid: str,
    neqo_gitlink: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _COHORT_GIT_PROOF_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_GIT_PROOF_ARTIFACT_TYPE
    ):
        raise ValueError("no-cache build cohort Git proof schema is invalid")

    commit_payload = _decode_canonical_base64(
        value["commit_payload_base64"],
        label="no-cache build cohort Git proof commit",
        maximum_bytes=_COHORT_GIT_PROOF_COMMIT_MAX_BYTES,
    )
    encoded_trees = value["tree_payloads_base64"]
    if (
        not isinstance(encoded_trees, list)
        or len(encoded_trees) != _COHORT_GIT_PROOF_TREE_COUNT
    ):
        raise ValueError("no-cache build cohort Git proof tree inventory is invalid")
    tree_payloads = [
        _decode_canonical_base64(
            encoded,
            label="no-cache build cohort Git proof tree",
            maximum_bytes=_COHORT_GIT_PROOF_TREE_MAX_BYTES,
        )
        for encoded in encoded_trees
    ]

    if _git_sha1_object_oid(b"commit", commit_payload) != lab_commit:
        raise ValueError("no-cache build cohort Git proof commit binding is invalid")
    first_line, separator, _remainder = commit_payload.partition(b"\n")
    root_match = re.fullmatch(rb"tree ([0-9a-f]{40})", first_line)
    if not separator or root_match is None:
        raise ValueError("no-cache build cohort Git proof commit payload is malformed")
    expected_tree_oid = root_match.group(1).decode("ascii")

    path_components = tuple(
        component.encode("ascii") for component in _COHORT_LEDGER_PATH.split("/")
    )
    for index, (component, tree_payload) in enumerate(
        zip(path_components, tree_payloads, strict=True)
    ):
        if _git_sha1_object_oid(b"tree", tree_payload) != expected_tree_oid:
            raise ValueError("no-cache build cohort Git proof tree binding is invalid")
        entries = _parse_git_tree(tree_payload)
        if index == 0:
            gitlink = entries.get(b"neqo-qcsd")
            if gitlink != (b"160000", neqo_gitlink):
                raise ValueError("no-cache build cohort Git proof gitlink binding is invalid")
        entry = entries.get(component)
        expected_mode = b"100644" if index == len(path_components) - 1 else b"40000"
        if entry is None or entry[0] != expected_mode:
            raise ValueError("no-cache build cohort Git proof path binding is invalid")
        expected_tree_oid = entry[1]
    if expected_tree_oid != ledger_blob_oid:
        raise ValueError("no-cache build cohort Git proof ledger binding is invalid")

    return {
        "schema_version": 1,
        "artifact_type": _COHORT_GIT_PROOF_ARTIFACT_TYPE,
        "commit_payload_base64": value["commit_payload_base64"],
        "tree_payloads_base64": list(encoded_trees),
    }


def _canonical_finite_json_bytes(
    value: Any,
    *,
    label: str,
    newline: bool = False,
) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError(f"{label} is not canonical finite JSON") from error
    return payload + (b"\n" if newline else b"")


def _validate_cohort_stat(
    value: Any,
    *,
    keys: set[str],
    label: str,
    required_mode: int | None = None,
    required_nlink: int | None = None,
    required_size: int | None = None,
) -> dict[str, int]:
    if (
        not isinstance(value, Mapping)
        or set(value) != keys
        or any(type(value[key]) is not int for key in keys)
        or value["dev"] <= 0
        or value["inode"] <= 0
        or value["uid"] < 0
        or value["gid"] < 0
        or not 0 <= value["mode"] <= 0o7777
        or value["nlink"] < 1
        or ("size" in keys and value["size"] < 0)
        or ("mtime_ns" in keys and value["mtime_ns"] < 0)
        or ("ctime_ns" in keys and value["ctime_ns"] < 0)
        or (required_mode is not None and value["mode"] != required_mode)
        or (required_nlink is not None and value["nlink"] != required_nlink)
        or (required_size is not None and value.get("size") != required_size)
    ):
        raise ValueError(f"{label} stat binding is invalid")
    return {key: value[key] for key in keys}


def _validate_cohort_git_directory_authority(value: Any) -> dict[str, int]:
    keys = _COHORT_AUTHORITY_GIT_DIRECTORY_KEYS
    if (
        not isinstance(value, Mapping)
        or set(value) != keys
        or any(type(value[key]) is not int for key in keys)
        or value["type"] != stat.S_IFDIR
        or value["dev"] <= 0
        or value["inode"] <= 0
        or value["uid"] < 0
        or value["gid"] < 0
        or not 0 <= value["mode"] <= 0o7777
    ):
        raise ValueError("no-cache build cohort authority Git directory binding is invalid")
    return {key: value[key] for key in keys}


def _validate_embedded_cohort_authority(
    value: Any,
    *,
    allocation: Mapping[str, Any],
    ledger_size: int,
) -> dict[str, Any]:
    schema_version = value.get("schema_version") if isinstance(value, Mapping) else None
    if (
        not isinstance(value, Mapping)
        or set(value) != _COHORT_AUTHORITY_KEYS
        or type(schema_version) is not int
        or schema_version not in _COHORT_AUTHORITY_SCHEMA_VERSIONS
        or value.get("artifact_type") != _COHORT_AUTHORITY_ARTIFACT_TYPE
        or not isinstance(value.get("receipt"), Mapping)
        or dict(value["receipt"]) != dict(allocation)
    ):
        raise ValueError("no-cache build cohort claim authority is invalid")

    expected_git = {
        "object_format": allocation["git_object_format"],
        "lab_head": allocation["lab_commit"],
        "head_blob_oid": allocation["ledger_git_blob_oid"],
        "index_blob_oid": allocation["ledger_git_blob_oid"],
        "worktree_blob_oid": allocation["ledger_git_blob_oid"],
        "neqo_head": allocation["neqo_commit"],
        "head_gitlink": allocation["neqo_gitlink"],
        "index_gitlink": allocation["neqo_gitlink"],
    }
    git = value.get("git")
    if (
        not isinstance(git, Mapping)
        or set(git) != _COHORT_AUTHORITY_GIT_KEYS
        or dict(git) != expected_git
    ):
        raise ValueError("no-cache build cohort claim Git authority is invalid")

    filesystem = value.get("filesystem")
    if (
        not isinstance(filesystem, Mapping)
        or set(filesystem) != _COHORT_AUTHORITY_FILESYSTEM_KEYS
        or not isinstance(filesystem.get("directories"), Mapping)
        or set(filesystem["directories"]) != _COHORT_AUTHORITY_DIRECTORY_NAMES
    ):
        raise ValueError("no-cache build cohort claim filesystem authority is invalid")
    for name, identity in filesystem["directories"].items():
        validated = (
            _validate_cohort_git_directory_authority(identity)
            if schema_version == 2 and name == "git"
            else _validate_cohort_stat(
                identity,
                keys=_COHORT_FILE_STAT_KEYS,
                label="no-cache build cohort authority directory",
            )
        )
        if validated["mode"] & 0o022:
            raise ValueError("no-cache build cohort claim filesystem authority is invalid")
    ledger_stat = _validate_cohort_stat(
        filesystem.get("ledger"),
        keys=_COHORT_FILE_STAT_KEYS,
        label="no-cache build cohort authority ledger",
        required_nlink=1,
        required_size=ledger_size,
    )
    git_index_stat = _validate_cohort_stat(
        filesystem.get("git_index"),
        keys=_COHORT_FILE_STAT_KEYS,
        label="no-cache build cohort authority Git index",
        required_nlink=1,
    )
    if (
        ledger_stat["mode"] & 0o133
        or git_index_stat["mode"] & 0o022
        or git_index_stat["size"] < 1
    ):
        raise ValueError("no-cache build cohort claim filesystem authority is invalid")
    return json.loads(
        _canonical_finite_json_bytes(value, label="no-cache build cohort claim authority")
    )


def _validate_embedded_cohort_claim(
    raw: bytes,
    *,
    expected_version: int,
    genesis_allocation: Mapping[str, Any],
    expected_predecessor: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate one canonical claim and its independently authenticated authority."""

    try:
        claim_value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeError, ValueError) as error:
        raise ValueError("no-cache build cohort claim is not finite unique-key JSON") from error
    if raw != _canonical_finite_json_bytes(
        claim_value,
        label="no-cache build cohort claim",
        newline=True,
    ):
        raise ValueError("no-cache build cohort claim bytes are not canonical")
    if (
        not isinstance(claim_value, Mapping)
        or set(claim_value) != _COHORT_CLAIM_KEYS
        or type(claim_value.get("schema_version")) is not int
        or claim_value.get("schema_version") != 1
        or claim_value.get("artifact_type") != _COHORT_CLAIM_ARTIFACT_TYPE
        or not isinstance(claim_value.get("payload"), Mapping)
    ):
        raise ValueError("no-cache build cohort claim schema is invalid")
    claim_payload = claim_value["payload"]
    claim_payload_digest = claim_value["payload_sha256"]
    if (
        set(claim_payload) != _COHORT_CLAIM_PAYLOAD_KEYS
        or not isinstance(claim_payload_digest, str)
        or _SHA256_RE.fullmatch(claim_payload_digest) is None
        or claim_payload_digest
        != hashlib.sha256(
            _canonical_finite_json_bytes(
                claim_payload,
                label="no-cache build cohort claim payload",
            )
        ).hexdigest()
        or claim_payload.get("policy") != _COHORT_ALLOCATION_POLICY
        or claim_payload.get("registry_path") != _COHORT_CLAIM_REGISTRY_PATH
        or type(claim_payload.get("cohort_version")) is not int
        or claim_payload.get("cohort_version") != expected_version
    ):
        raise ValueError("no-cache build cohort claim payload is invalid")

    source = claim_payload.get("source")
    authority_value = claim_payload.get("authority")
    allocation_value = (
        authority_value.get("receipt") if isinstance(authority_value, Mapping) else None
    )
    if not isinstance(source, Mapping) or set(source) != _COHORT_CLAIM_SOURCE_KEYS:
        raise ValueError("no-cache build cohort claim source binding is invalid")
    embedded_allocation = _validate_cohort_allocation(
        allocation_value,
        cohort_version=expected_version,
        source=source,
    )
    genesis_fields = (
        "policy",
        "ledger_path",
        "ledger_sha256",
        "ledger_payload_base64",
        "git_object_format",
        "ledger_git_blob_oid",
        "last_consumed_version",
    )
    if any(
        embedded_allocation[field] != genesis_allocation[field]
        for field in genesis_fields
    ):
        raise ValueError("no-cache build cohort claim genesis binding is invalid")
    ledger_raw = base64.b64decode(
        embedded_allocation["ledger_payload_base64"], validate=True
    )
    authority = _validate_embedded_cohort_authority(
        authority_value,
        allocation=embedded_allocation,
        ledger_size=len(ledger_raw),
    )
    authority_sha256 = hashlib.sha256(
        _canonical_finite_json_bytes(
            authority,
            label="no-cache build cohort claim authority",
        )
    ).hexdigest()
    if claim_payload.get("authority_sha256") != authority_sha256:
        raise ValueError("no-cache build cohort claim authority digest is invalid")
    if dict(source) != {
        "lab_commit": embedded_allocation["lab_commit"],
        "neqo_commit": embedded_allocation["neqo_commit"],
        "neqo_gitlink": embedded_allocation["neqo_gitlink"],
    }:
        raise ValueError("no-cache build cohort claim source binding is invalid")
    expected_ledger = {
        "path": embedded_allocation["ledger_path"],
        "sha256": embedded_allocation["ledger_sha256"],
        "git_object_format": embedded_allocation["git_object_format"],
        "git_blob_oid": embedded_allocation["ledger_git_blob_oid"],
        "payload_base64": embedded_allocation["ledger_payload_base64"],
        "last_consumed_version": embedded_allocation["last_consumed_version"],
    }
    if (
        not isinstance(claim_payload.get("ledger"), Mapping)
        or set(claim_payload["ledger"]) != _COHORT_CLAIM_LEDGER_KEYS
        or dict(claim_payload["ledger"]) != expected_ledger
    ):
        raise ValueError("no-cache build cohort claim ledger binding is invalid")
    predecessor = claim_payload.get("predecessor")
    if (
        not isinstance(predecessor, Mapping)
        or set(predecessor) != _COHORT_CLAIM_PREDECESSOR_KEYS
        or dict(predecessor) != dict(expected_predecessor)
    ):
        raise ValueError("no-cache build cohort claim predecessor is invalid")
    return (
        json.loads(
            _canonical_finite_json_bytes(
                claim_value,
                label="no-cache build cohort claim",
            )
        ),
        embedded_allocation,
    )


def _validate_cohort_claim_chain(
    value: Any,
    *,
    allocation: Mapping[str, Any],
    cohort_version: int,
    current_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a self-contained dense claim chain rooted at the checked genesis."""

    if not isinstance(value, Mapping) or set(value) != _COHORT_CLAIM_CHAIN_KEYS:
        raise ValueError("no-cache build cohort claim-chain schema is invalid")
    digest_payload = dict(value)
    claimed_digest = digest_payload.pop("payload_sha256")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_CLAIM_CHAIN_ARTIFACT_TYPE
        or value.get("policy") != _COHORT_ALLOCATION_POLICY
        or not isinstance(claimed_digest, str)
        or _SHA256_RE.fullmatch(claimed_digest) is None
        or claimed_digest
        != hashlib.sha256(
            _canonical_finite_json_bytes(
                digest_payload,
                label="no-cache build cohort claim chain",
            )
        ).hexdigest()
    ):
        raise ValueError("no-cache build cohort claim-chain digest is invalid")
    expected_genesis = {
        "ledger_path": allocation["ledger_path"],
        "ledger_sha256": allocation["ledger_sha256"],
        "last_consumed_version": allocation["last_consumed_version"],
    }
    genesis = value.get("genesis")
    if (
        not isinstance(genesis, Mapping)
        or set(genesis) != _COHORT_CLAIM_CHAIN_GENESIS_KEYS
        or dict(genesis) != expected_genesis
    ):
        raise ValueError("no-cache build cohort claim-chain genesis is invalid")
    claims = value.get("claims")
    expected_count = cohort_version - allocation["last_consumed_version"]
    if (
        not isinstance(claims, list)
        or not claims
        or expected_count > _COHORT_CLAIM_CHAIN_MAX_ENTRIES
        or len(claims) != expected_count
    ):
        raise ValueError("no-cache build cohort claim-chain inventory is invalid")

    previous = {
        "kind": "genesis-ledger",
        "cohort_version": allocation["last_consumed_version"],
        "sha256": allocation["ledger_sha256"],
    }
    total_decoded_bytes = 0
    projected_claims: list[dict[str, Any]] = []
    expected_versions = range(allocation["last_consumed_version"] + 1, cohort_version + 1)
    for entry, expected_version in zip(claims, expected_versions, strict=True):
        if (
            not isinstance(entry, Mapping)
            or set(entry) != _COHORT_CLAIM_CHAIN_ENTRY_KEYS
            or type(entry.get("cohort_version")) is not int
            or entry.get("cohort_version") != expected_version
            or not isinstance(entry.get("sha256"), str)
            or _SHA256_RE.fullmatch(entry["sha256"]) is None
        ):
            raise ValueError("no-cache build cohort claim-chain entry is invalid")
        raw = _decode_canonical_base64(
            entry["payload_base64"],
            label="no-cache build cohort claim-chain entry",
            maximum_bytes=_COHORT_CLAIM_MAX_BYTES,
        )
        total_decoded_bytes += len(raw)
        if (
            total_decoded_bytes > _COHORT_CLAIM_CHAIN_MAX_DECODED_BYTES
            or hashlib.sha256(raw).hexdigest() != entry["sha256"]
        ):
            raise ValueError("no-cache build cohort claim-chain entry digest is invalid")
        _claim, embedded_allocation = _validate_embedded_cohort_claim(
            raw,
            expected_version=expected_version,
            genesis_allocation=allocation,
            expected_predecessor=previous,
        )
        if expected_version == cohort_version and dict(embedded_allocation) != dict(allocation):
            raise ValueError("no-cache build cohort claim-chain tail allocation is invalid")
        projected_claims.append(dict(entry))
        previous = {
            "kind": "cohort-claim",
            "cohort_version": expected_version,
            "sha256": entry["sha256"],
        }

    expected_head = {
        "cohort_version": cohort_version,
        "sha256": projected_claims[-1]["sha256"],
    }
    head = value.get("head")
    snapshot_claim = current_snapshot.get("claim")
    if (
        not isinstance(head, Mapping)
        or set(head) != _COHORT_CLAIM_CHAIN_HEAD_KEYS
        or dict(head) != expected_head
        or not isinstance(snapshot_claim, Mapping)
        or snapshot_claim.get("sha256") != expected_head["sha256"]
        or snapshot_claim.get("payload_base64")
        != projected_claims[-1]["payload_base64"]
    ):
        raise ValueError("no-cache build cohort claim-chain head binding is invalid")
    return {
        "schema_version": 1,
        "artifact_type": _COHORT_CLAIM_CHAIN_ARTIFACT_TYPE,
        "policy": _COHORT_ALLOCATION_POLICY,
        "genesis": dict(genesis),
        "claims": projected_claims,
        "head": dict(head),
        "payload_sha256": claimed_digest,
    }


def _validate_cohort_claim_snapshot(
    value: Any,
    *,
    allocation: Mapping[str, Any],
    cohort_version: int,
) -> tuple[dict[str, Any], str, str, str]:
    if not isinstance(value, Mapping) or set(value) != _COHORT_CLAIM_SNAPSHOT_KEYS:
        raise ValueError("no-cache build cohort claim snapshot schema is invalid")
    snapshot_payload = dict(value)
    snapshot_digest = snapshot_payload.pop("payload_sha256")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_CLAIM_SNAPSHOT_ARTIFACT_TYPE
        or value.get("policy") != _COHORT_ALLOCATION_POLICY
        or type(value.get("cohort_version")) is not int
        or value.get("cohort_version") != cohort_version
        or not isinstance(snapshot_digest, str)
        or _SHA256_RE.fullmatch(snapshot_digest) is None
        or snapshot_digest
        != hashlib.sha256(
            _canonical_finite_json_bytes(
                snapshot_payload,
                label="no-cache build cohort claim snapshot",
            )
        ).hexdigest()
    ):
        raise ValueError("no-cache build cohort claim snapshot digest is invalid")

    registry = value["registry"]
    claim_binding = value["claim"]
    head = value["registry_head_at_publication"]
    expected_claim_path = f"{_COHORT_CLAIM_REGISTRY_PATH}/claim-v{cohort_version}.json"
    if (
        not isinstance(registry, Mapping)
        or set(registry) != _COHORT_SNAPSHOT_REGISTRY_KEYS
        or registry.get("path") != _COHORT_CLAIM_REGISTRY_PATH
        or not isinstance(claim_binding, Mapping)
        or set(claim_binding) != _COHORT_SNAPSHOT_CLAIM_KEYS
        or claim_binding.get("path") != expected_claim_path
        or not isinstance(head, Mapping)
        or set(head) != {"cohort_version", "sha256"}
        or type(head.get("cohort_version")) is not int
        or head.get("cohort_version") != cohort_version
        or head.get("sha256") != claim_binding.get("sha256")
    ):
        raise ValueError("no-cache build cohort claim snapshot binding is invalid")
    _validate_cohort_stat(
        registry.get("stat"),
        keys=_COHORT_DIRECTORY_STAT_KEYS,
        label="no-cache build cohort claim registry",
        required_mode=0o700,
    )
    claim_raw = _decode_canonical_base64(
        claim_binding["payload_base64"],
        label="no-cache build cohort snapshot claim",
        maximum_bytes=_COHORT_CLAIM_MAX_BYTES,
    )
    claim_file_sha256 = claim_binding["sha256"]
    if (
        not isinstance(claim_file_sha256, str)
        or _SHA256_RE.fullmatch(claim_file_sha256) is None
        or hashlib.sha256(claim_raw).hexdigest() != claim_file_sha256
    ):
        raise ValueError("no-cache build cohort claim file SHA-256 is invalid")
    _validate_cohort_stat(
        claim_binding.get("stat"),
        keys=_COHORT_FILE_STAT_KEYS,
        label="no-cache build cohort claim file",
        required_mode=0o600,
        required_nlink=1,
        required_size=len(claim_raw),
    )

    try:
        claim_value = json.loads(
            claim_raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeError, ValueError) as error:
        raise ValueError("no-cache build cohort claim is not finite unique-key JSON") from error
    if claim_raw != _canonical_finite_json_bytes(
        claim_value,
        label="no-cache build cohort claim",
        newline=True,
    ):
        raise ValueError("no-cache build cohort claim bytes are not canonical")
    if (
        not isinstance(claim_value, Mapping)
        or set(claim_value) != _COHORT_CLAIM_KEYS
        or type(claim_value.get("schema_version")) is not int
        or claim_value.get("schema_version") != 1
        or claim_value.get("artifact_type") != _COHORT_CLAIM_ARTIFACT_TYPE
        or not isinstance(claim_value.get("payload"), Mapping)
    ):
        raise ValueError("no-cache build cohort claim schema is invalid")
    claim_payload = claim_value["payload"]
    claim_payload_digest = claim_value["payload_sha256"]
    if (
        set(claim_payload) != _COHORT_CLAIM_PAYLOAD_KEYS
        or not isinstance(claim_payload_digest, str)
        or _SHA256_RE.fullmatch(claim_payload_digest) is None
        or claim_payload_digest
        != hashlib.sha256(
            _canonical_finite_json_bytes(
                claim_payload,
                label="no-cache build cohort claim payload",
            )
        ).hexdigest()
        or claim_payload.get("policy") != _COHORT_ALLOCATION_POLICY
        or claim_payload.get("registry_path") != _COHORT_CLAIM_REGISTRY_PATH
        or type(claim_payload.get("cohort_version")) is not int
        or claim_payload.get("cohort_version") != cohort_version
    ):
        raise ValueError("no-cache build cohort claim payload is invalid")

    ledger_raw = base64.b64decode(allocation["ledger_payload_base64"], validate=True)
    authority = _validate_embedded_cohort_authority(
        claim_payload["authority"],
        allocation=allocation,
        ledger_size=len(ledger_raw),
    )
    authority_sha256 = hashlib.sha256(
        _canonical_finite_json_bytes(
            authority,
            label="no-cache build cohort claim authority",
        )
    ).hexdigest()
    if claim_payload.get("authority_sha256") != authority_sha256:
        raise ValueError("no-cache build cohort claim authority digest is invalid")
    if claim_payload.get("source") != {
        "lab_commit": allocation["lab_commit"],
        "neqo_commit": allocation["neqo_commit"],
        "neqo_gitlink": allocation["neqo_gitlink"],
    } or not isinstance(claim_payload.get("source"), Mapping):
        raise ValueError("no-cache build cohort claim source binding is invalid")
    if set(claim_payload["source"]) != _COHORT_CLAIM_SOURCE_KEYS:
        raise ValueError("no-cache build cohort claim source binding is invalid")
    expected_ledger = {
        "path": allocation["ledger_path"],
        "sha256": allocation["ledger_sha256"],
        "git_object_format": allocation["git_object_format"],
        "git_blob_oid": allocation["ledger_git_blob_oid"],
        "payload_base64": allocation["ledger_payload_base64"],
        "last_consumed_version": allocation["last_consumed_version"],
    }
    if (
        not isinstance(claim_payload.get("ledger"), Mapping)
        or set(claim_payload["ledger"]) != _COHORT_CLAIM_LEDGER_KEYS
        or dict(claim_payload["ledger"]) != expected_ledger
    ):
        raise ValueError("no-cache build cohort claim ledger binding is invalid")

    predecessor = claim_payload.get("predecessor")
    if (
        not isinstance(predecessor, Mapping)
        or set(predecessor) != _COHORT_CLAIM_PREDECESSOR_KEYS
        or type(predecessor.get("cohort_version")) is not int
    ):
        raise ValueError("no-cache build cohort claim predecessor is invalid")
    last_consumed = allocation["last_consumed_version"]
    if cohort_version == last_consumed + 1:
        expected_predecessor = {
            "kind": "genesis-ledger",
            "cohort_version": last_consumed,
            "sha256": allocation["ledger_sha256"],
        }
        if dict(predecessor) != expected_predecessor:
            raise ValueError("no-cache build cohort claim predecessor is invalid")
    elif (
        predecessor.get("kind") != "cohort-claim"
        or predecessor.get("cohort_version") != cohort_version - 1
        or not isinstance(predecessor.get("sha256"), str)
        or _SHA256_RE.fullmatch(predecessor["sha256"]) is None
    ):
        raise ValueError("no-cache build cohort claim predecessor is invalid")

    projected = json.loads(
        _canonical_finite_json_bytes(value, label="no-cache build cohort claim snapshot")
    )
    claim_snapshot_sha256 = hashlib.sha256(
        _canonical_finite_json_bytes(
            projected,
            label="no-cache build cohort claim snapshot",
        )
    ).hexdigest()
    return projected, authority_sha256, claim_snapshot_sha256, claim_file_sha256


def _validate_cohort_authority_reproofs(
    value: Any,
    *,
    started_at: datetime,
    finished_at: datetime,
    authority_sha256: str,
    claim_snapshot_sha256: str,
    claim_file_sha256: str,
    buildx: Mapping[str, Any],
    host_storage_preflight: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(_COHORT_REPROOF_BOUNDARIES):
        raise ValueError("no-cache build cohort-authority reproof inventory is invalid")
    projected: list[dict[str, Any]] = []
    observed_times: list[datetime] = []
    for row, boundary in zip(value, _COHORT_REPROOF_BOUNDARIES, strict=True):
        if (
            not isinstance(row, Mapping)
            or set(row) != _COHORT_REPROOF_KEYS
            or row.get("boundary") != boundary
            or not isinstance(row.get("observed_at"), str)
            or row.get("authority_sha256") != authority_sha256
            or row.get("claim_snapshot_sha256") != claim_snapshot_sha256
            or row.get("claim_file_sha256") != claim_file_sha256
        ):
            raise ValueError("no-cache build cohort-authority reproof is invalid")
        observed = _aware_timestamp(
            row["observed_at"],
            label="cohort-authority reproof",
        )
        if not started_at <= observed <= finished_at:
            raise ValueError("no-cache build cohort-authority reproof timing is invalid")
        observed_times.append(observed)
        projected.append(dict(row))
    if any(left >= right for left, right in zip(observed_times, observed_times[1:])):
        raise ValueError("no-cache build cohort-authority reproof timing is invalid")
    buildx_times = [
        _aware_timestamp(row["observed_at"], label="buildx observation")
        for row in buildx["observations"]
    ]
    if not (
        observed_times[4]
        < buildx_times[0]
        < observed_times[5]
        < buildx_times[1]
        < observed_times[6]
        < buildx_times[2]
        < observed_times[7]
        < buildx_times[3]
        < observed_times[8]
    ):
        raise ValueError("no-cache build cohort-authority stage timeline is invalid")
    if host_storage_preflight["applicable"]:
        storage_times = [
            _aware_timestamp(row["observed_at"], label="host-storage observation")
            for row in host_storage_preflight["observations"]
        ]
        if not (
            observed_times[1]
            < storage_times[0]
            < observed_times[2]
            and buildx_times[1]
            < storage_times[1]
            < observed_times[6]
            and buildx_times[2]
            < storage_times[2]
            < observed_times[7]
            and buildx_times[3]
            < storage_times[3]
            < observed_times[8]
        ):
            raise ValueError("no-cache build cohort-authority storage timeline is invalid")
    if (finished_at - observed_times[-1]).total_seconds() > (
        _COHORT_FINAL_REPROOF_MAX_AGE_SECONDS
    ):
        raise ValueError("no-cache build final cohort-authority reproof is not immediate")
    return projected


def _validate_cohort_allocation(
    value: Any,
    *,
    cohort_version: int,
    source: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _COHORT_ALLOCATION_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _COHORT_ALLOCATION_ARTIFACT_TYPE
        or value.get("policy") != _COHORT_ALLOCATION_POLICY
        or value.get("ledger_path") != _COHORT_LEDGER_PATH
    ):
        raise ValueError("no-cache build cohort allocation schema is invalid")

    encoded = value["ledger_payload_base64"]
    if not isinstance(encoded, str):
        raise ValueError("no-cache build cohort allocation ledger encoding is invalid")
    try:
        encoded_bytes = encoded.encode("ascii")
        ledger_payload = base64.b64decode(encoded_bytes, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise ValueError("no-cache build cohort allocation ledger encoding is invalid") from error
    if (
        not ledger_payload
        or len(ledger_payload) > _COHORT_LEDGER_MAX_BYTES
        or base64.b64encode(ledger_payload) != encoded_bytes
    ):
        raise ValueError("no-cache build cohort allocation ledger encoding is invalid")

    ledger_sha256 = value["ledger_sha256"]
    if (
        not isinstance(ledger_sha256, str)
        or _SHA256_RE.fullmatch(ledger_sha256) is None
        or hashlib.sha256(ledger_payload).hexdigest() != ledger_sha256
    ):
        raise ValueError("no-cache build cohort allocation ledger SHA-256 is invalid")

    object_format = value["git_object_format"]
    if object_format != "sha1":
        raise ValueError("no-cache build cohort allocation Git object format is invalid")
    oid_pattern = _COMMIT_RE
    claimed_blob_oid = value["ledger_git_blob_oid"]
    git_blob = hashlib.new(object_format)
    git_blob.update(b"blob " + str(len(ledger_payload)).encode("ascii") + b"\0")
    git_blob.update(ledger_payload)
    if (
        not isinstance(claimed_blob_oid, str)
        or oid_pattern.fullmatch(claimed_blob_oid) is None
        or git_blob.hexdigest() != claimed_blob_oid
    ):
        raise ValueError("no-cache build cohort allocation Git blob binding is invalid")

    try:
        ledger = json.loads(
            ledger_payload.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeError, ValueError) as error:
        raise ValueError(
            "no-cache build cohort allocation ledger is not unique-key UTF-8 JSON"
        ) from error
    ledger_keys = {"schema_version", "artifact_type", "policy", "consumed_versions"}
    if (
        not isinstance(ledger, Mapping)
        or set(ledger) != ledger_keys
        or type(ledger.get("schema_version")) is not int
        or ledger.get("schema_version") != 1
        or ledger.get("artifact_type") != _COHORT_LEDGER_ARTIFACT_TYPE
        or ledger.get("policy") != _COHORT_ALLOCATION_POLICY
    ):
        raise ValueError("no-cache build cohort allocation ledger schema is invalid")
    versions = ledger["consumed_versions"]
    if (
        not isinstance(versions, list)
        or not versions
        or any(type(version) is not int for version in versions)
        or versions != list(range(1, len(versions) + 1))
    ):
        raise ValueError("no-cache build cohort allocation ledger is not a dense prefix")

    last_consumed = value["last_consumed_version"]
    allocated = value["allocated_version"]
    if (
        type(last_consumed) is not int
        or last_consumed != versions[-1]
        or type(allocated) is not int
        or allocated <= last_consumed
        or allocated != cohort_version
    ):
        raise ValueError("no-cache build cohort allocation version binding is invalid")

    commits = (value["lab_commit"], value["neqo_commit"], value["neqo_gitlink"])
    if (
        any(
            not isinstance(commit, str) or oid_pattern.fullmatch(commit) is None
            for commit in commits
        )
        or value["lab_commit"] != source["lab_commit"]
        or value["neqo_commit"] != source["neqo_commit"]
        or value["neqo_gitlink"] != source["neqo_commit"]
    ):
        raise ValueError("no-cache build cohort allocation source binding is invalid")
    proof = _validate_lab_commit_ledger_proof(
        value["lab_commit_ledger_proof"],
        lab_commit=value["lab_commit"],
        ledger_blob_oid=claimed_blob_oid,
        neqo_gitlink=value["neqo_gitlink"],
    )
    projected = dict(value)
    projected["lab_commit_ledger_proof"] = proof
    return projected


def _validate_checkout_bindings(value: Mapping[str, Any], *, checkout_root: Path | None) -> None:
    if checkout_root is None:
        return
    root = Path(checkout_root).resolve()
    paths = {
        "Dockerfile": root / "Dockerfile",
        "uv.lock": root / "uv.lock",
        "Cargo.lock": root / "neqo-qcsd/Cargo.lock",
    }
    if any(path.is_symlink() or not path.is_file() for path in paths.values()):
        raise ValueError("no-cache build checkout inputs are absent or unsafe")
    build_inputs = value["build_inputs"]
    if (
        value["dockerfile_sha256"] != _sha256_file(paths["Dockerfile"])
        or build_inputs["uv_lock_sha256"] != _sha256_file(paths["uv.lock"])
        or build_inputs["cargo_lock_sha256"] != _sha256_file(paths["Cargo.lock"])
    ):
        raise ValueError("no-cache build checkout binding is stale")


def _validate_role_provenance(
    value: Any,
    *,
    image_ids: Mapping[str, str],
    source: Mapping[str, Any],
    build_inputs: Mapping[str, Any],
) -> dict[str, Any]:
    targets = ("collection", "prepare", "reference")
    if (
        not isinstance(value, Mapping)
        or set(value) != _ROLE_PROVENANCE_KEYS
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["sources"], Mapping)
        or set(value["sources"]) != set(targets)
        or not isinstance(value["build_inputs"], Mapping)
        or set(value["build_inputs"]) != set(targets)
    ):
        raise ValueError("no-cache build role provenance is invalid")

    sources = {
        target: _validate_clean_source(value["sources"][target], collection_image=image_ids[target])
        for target in targets
    }
    source_identities = []
    for target in targets:
        identity = dict(sources[target])
        identity.pop("image_digest")
        source_identities.append(identity)
    if any(identity != source_identities[0] for identity in source_identities[1:]) or sources[
        "collection"
    ] != dict(source):
        raise ValueError("no-cache build image roles were built from different source snapshots")

    collection_inputs = _validate_build_inputs(value["build_inputs"]["collection"])
    prepare_inputs = _validate_build_inputs(value["build_inputs"]["prepare"])
    if (
        value["build_inputs"]["reference"] is not None
        or collection_inputs != prepare_inputs
        or collection_inputs != dict(build_inputs)
    ):
        raise ValueError("no-cache build image roles used different build inputs")
    return {
        "schema_version": 1,
        "sources": sources,
        "build_inputs": {
            "collection": collection_inputs,
            "prepare": prepare_inputs,
            "reference": None,
        },
    }


def validate_build_host_storage_observation(
    value: Any,
    *,
    expected_boundary: str,
    expected_probe_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate one exact backing-volume observation."""

    if not isinstance(value, Mapping) or set(value) != _OBSERVATION_KEYS:
        raise ValueError("host-storage observation schema is invalid")
    data_vhd_path = value["data_vhd_path"]
    path_parts = data_vhd_path.split("\\") if isinstance(data_vhd_path, str) else []
    total_bytes = value["total_bytes"]
    available_bytes = value["available_bytes"]
    file_length = value["data_vhd_file_length_bytes"]
    integers = (total_bytes, available_bytes, file_length)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["probe"] != BUILD_HOST_STORAGE_PROBE
        or not isinstance(value["probe_sha256"], str)
        or _SHA256_RE.fullmatch(value["probe_sha256"]) is None
        or (expected_probe_sha256 is not None and value["probe_sha256"] != expected_probe_sha256)
        or value["boundary"] != expected_boundary
        or value["location_source"] not in BUILD_HOST_STORAGE_LOCATION_SOURCES
        or not isinstance(data_vhd_path, str)
        or _WINDOWS_VHD_RE.fullmatch(data_vhd_path) is None
        or any(part in {"", ".", ".."} for part in path_parts[1:])
        or not isinstance(value["backing_volume_unique_id"], str)
        or _VOLUME_ID_RE.fullmatch(value["backing_volume_unique_id"]) is None
        or (
            value["drive_letter"] is not None
            and (
                not isinstance(value["drive_letter"], str)
                or re.fullmatch(r"[A-Z]", value["drive_letter"]) is None
                or value["drive_letter"] != data_vhd_path[0].upper()
            )
        )
        or not isinstance(value["file_system"], str)
        or not value["file_system"]
        or value["health_status"] != "Healthy"
        or value["operational_status"] != ["OK"]
        or any(not isinstance(item, int) or isinstance(item, bool) for item in integers)
        or file_length <= 0
        or total_bytes <= 0
        or not 0 <= available_bytes <= total_bytes
    ):
        raise ValueError("host-storage observation is invalid")
    _aware_timestamp(value["observed_at"], label="host-storage observation")
    if available_bytes < BUILD_WSL_HOST_MIN_AVAILABLE_BYTES:
        raise ValueError(
            f"requires at least {BUILD_WSL_HOST_MIN_AVAILABLE_BYTES} available bytes "
            f"(64 GiB) on the Docker data VHDX backing volume at "
            f"{expected_boundary}; observed {available_bytes}; no evidentiary receipt "
            "will be created"
        )
    return dict(value)


def validate_build_host_storage_preflight(
    value: Any, *, expected_probe_sha256: str | None = None
) -> dict[str, Any]:
    """Validate all WSL boundary observations or exact non-WSL evidence."""

    if (
        not isinstance(value, Mapping)
        or set(value) != _PREFLIGHT_KEYS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or not isinstance(value.get("applicable"), bool)
        or value.get("policy") != BUILD_HOST_STORAGE_POLICY
        or value.get("required_available_bytes") != BUILD_WSL_HOST_MIN_AVAILABLE_BYTES
        or value.get("passed") is not True
    ):
        raise ValueError("host-storage preflight schema is invalid")
    detection = value["platform_detection"]
    detection_keys = {
        "schema_version",
        "probe",
        "kernel_release",
        "proc_version",
        "wsl_interop_env_present",
        "wsl_distro_name_env_present",
        "run_wsl_directory_present",
    }
    if (
        not isinstance(detection, Mapping)
        or set(detection) != detection_keys
        or type(detection.get("schema_version")) is not int
        or detection.get("schema_version") != 1
        or detection.get("probe") != "wsl-multi-signal-v1"
        or not isinstance(detection.get("kernel_release"), str)
        or not detection["kernel_release"].strip()
        or not isinstance(detection.get("proc_version"), str)
        or not detection["proc_version"].strip()
        or any(
            not isinstance(detection.get(key), bool)
            for key in (
                "wsl_interop_env_present",
                "wsl_distro_name_env_present",
                "run_wsl_directory_present",
            )
        )
    ):
        raise ValueError("host-storage platform detection is invalid")
    detected_wsl = any(
        (
            "microsoft" in detection["kernel_release"].lower(),
            "microsoft" in detection["proc_version"].lower(),
            detection["wsl_interop_env_present"],
            detection["wsl_distro_name_env_present"],
            detection["run_wsl_directory_present"],
        )
    )
    if not value["applicable"]:
        if (
            detected_wsl
            or value["platform"] != "other-host"
            or value["observations"] != []
            or value["minimum_available_bytes"] is not None
        ):
            raise ValueError("non-WSL host-storage preflight is invalid")
        return dict(value)
    if (
        not detected_wsl
        or value["platform"] != "windows-wsl2"
        or not isinstance(value["observations"], list)
        or len(value["observations"]) != len(BUILD_HOST_STORAGE_BOUNDARIES)
    ):
        raise ValueError("WSL host-storage preflight is invalid")
    observations = [
        validate_build_host_storage_observation(
            observation,
            expected_boundary=boundary,
            expected_probe_sha256=expected_probe_sha256,
        )
        for observation, boundary in zip(
            value["observations"], BUILD_HOST_STORAGE_BOUNDARIES, strict=True
        )
    ]
    stable_identities = {
        (
            observation["probe_sha256"],
            observation["location_source"],
            observation["data_vhd_path"],
            observation["backing_volume_unique_id"],
            observation["drive_letter"],
            observation["file_system"],
        )
        for observation in observations
    }
    observed_times = [
        _aware_timestamp(observation["observed_at"], label="host-storage observation")
        for observation in observations
    ]
    minimum_available_bytes = min(observation["available_bytes"] for observation in observations)
    if (
        len(stable_identities) != 1
        or observed_times != sorted(observed_times)
        or any(left >= right for left, right in zip(observed_times, observed_times[1:]))
        or not isinstance(value["minimum_available_bytes"], int)
        or isinstance(value["minimum_available_bytes"], bool)
        or value["minimum_available_bytes"] != minimum_available_bytes
    ):
        raise ValueError("WSL host-storage preflight is inconsistent")
    return dict(value)


def validate_build_execution_envelope(
    value: Any,
    *,
    expected_cohort_version: int | None = None,
    expected_probe_sha256: str | None = None,
    checkout_root: Path | None = None,
    expected_build_root: Path | None = None,
) -> dict[str, Any]:
    """Validate the build receipt envelope used by every launcher reader."""

    schema_version = value.get("schema_version") if isinstance(value, Mapping) else None
    required = set(_BUILD_V1_KEYS)
    if type(schema_version) is int and schema_version in {2, 3, 4, 5}:
        required |= {"host_storage_preflight", "role_provenance"}
    if type(schema_version) is int and schema_version in {4, 5}:
        required |= {"buildx"}
    if schema_version == 5:
        required |= {
            "cohort_allocation",
            "cohort_claim",
            "cohort_claim_chain",
            "cohort_authority_reproofs",
        }
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or type(schema_version) is not int
        or schema_version not in {1, 2, 3, 4, 5}
        or value.get("artifact_type") != BUILD_EXECUTION_ARTIFACT_TYPE
    ):
        raise ValueError("no-cache build execution receipt schema is invalid")
    cohort_version = _positive_integer(value["cohort_version"], label="cohort version")
    if expected_cohort_version is not None and cohort_version != _positive_integer(
        expected_cohort_version, label="expected cohort version"
    ):
        raise ValueError("no-cache build cohort version differs from the request")
    payload = dict(value)
    claimed_payload = payload.pop("payload_sha256")
    if (
        not isinstance(claimed_payload, str)
        or _SHA256_RE.fullmatch(claimed_payload) is None
        or claimed_payload != _canonical_digest(payload)
    ):
        raise ValueError("no-cache build execution payload hash is invalid")
    started = _aware_timestamp(value["started_at"], label="no-cache build start")
    finished = _aware_timestamp(value["finished_at"], label="no-cache build finish")
    duration = value["duration_seconds"]
    if (
        finished < started
        or not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or not math.isfinite(duration)
        or duration <= 0
        or abs(float(duration) - (finished - started).total_seconds()) > 2.0
    ):
        raise ValueError("no-cache build duration is invalid")

    docker = value["docker"]
    docker_keys = {"client_version", "server_version"}
    if schema_version in {2, 3, 4, 5}:
        docker_keys |= {
            "context",
            "endpoint",
            "server_name",
            "server_operating_system",
            "server_os_type",
            "server_architecture",
            "server_id",
        }
    if (
        not isinstance(docker, Mapping)
        or set(docker) != docker_keys
        or any(not isinstance(docker[key], str) or not docker[key] for key in docker)
    ):
        raise ValueError("no-cache build Docker identity is invalid")
    if schema_version in {2, 3, 4, 5} and (
        docker["context"] not in {"default", "desktop-linux"}
        or docker["endpoint"]
        not in {
            "unix:///var/run/docker.sock",
            "npipe:////./pipe/dockerDesktopLinuxEngine",
        }
        or docker["server_os_type"] != "linux"
    ):
        raise ValueError("no-cache build Docker endpoint is not local and supported")

    images = value["images"]
    if not isinstance(images, Mapping) or set(images) != {
        "collection",
        "prepare",
        "reference",
    }:
        raise ValueError("no-cache build image inventory is invalid")
    image_ids: dict[str, str] = {}
    for target in ("collection", "prepare", "reference"):
        record = images[target]
        if (
            not isinstance(record, Mapping)
            or set(record) != {"tag", "id", "repo_digests"}
            or not isinstance(record["tag"], str)
            or not record["tag"]
            or not isinstance(record["id"], str)
            or _IMAGE_ID_RE.fullmatch(record["id"]) is None
            or not isinstance(record["repo_digests"], list)
            or any(
                not isinstance(digest, str) or _REPO_DIGEST_RE.fullmatch(digest) is None
                for digest in record["repo_digests"]
            )
        ):
            raise ValueError(f"no-cache build {target} image binding is invalid")
        if schema_version in {2, 3, 4, 5} and record["tag"] != BUILD_IMAGE_TAGS[target]:
            raise ValueError(f"no-cache build {target} image role tag is invalid")
        image_ids[target] = record["id"]
    if schema_version in {2, 3, 4, 5} and len(set(image_ids.values())) != len(image_ids):
        raise ValueError("no-cache build image roles do not have distinct immutable IDs")

    commands = value["commands"]
    if not isinstance(commands, list) or len(commands) != 3:
        raise ValueError("no-cache build command inventory is incomplete")
    recorded_build_root: PurePosixPath | None = None
    for target, command in zip(("collection", "prepare", "reference"), commands, strict=True):
        prefix = ["docker"]
        if schema_version == 2:
            prefix.extend(["--context", docker["context"]])
        elif schema_version in {3, 4, 5}:
            prefix.extend(["--host", docker["endpoint"]])
        prefix.extend(["build", "--pull", "--no-cache"])
        argv = command.get("argv") if isinstance(command, Mapping) else None
        iidfile_value: str | None = None
        iidfile: PurePosixPath | None = None
        if (
            schema_version in {2, 3, 4, 5}
            and isinstance(argv, list)
            and len(argv) >= len(prefix) + 2
        ):
            iidfile_value = argv[len(prefix) + 1] if argv[len(prefix)] == "--iidfile" else None
            if isinstance(iidfile_value, str):
                iidfile = PurePosixPath(iidfile_value)
                prefix.extend(["--iidfile", iidfile_value])
        prefix.extend(["--target", target, "--tag", images[target]["tag"], "--file"])
        paths_valid = (
            isinstance(argv, list)
            and len(argv) == len(prefix) + 2
            and all(isinstance(argument, str) for argument in argv)
        )
        dockerfile = PurePosixPath(argv[-2]) if paths_valid else None
        build_root = PurePosixPath(argv[-1]) if paths_valid else None
        if (
            not isinstance(command, Mapping)
            or set(command) != {"target", "argv", "exit_code", "image_id"}
            or command.get("target") != target
            or not isinstance(argv, list)
            or argv[:-2] != prefix
            or dockerfile is None
            or build_root is None
            or not dockerfile.is_absolute()
            or not build_root.is_absolute()
            or argv[-2].startswith("//")
            or argv[-1].startswith("//")
            or str(dockerfile) != argv[-2]
            or str(build_root) != argv[-1]
            or ".." in dockerfile.parts
            or ".." in build_root.parts
            or dockerfile.name != "Dockerfile"
            or dockerfile.parent != build_root
            or build_root.parent == build_root
            or (
                schema_version in {2, 3, 4, 5}
                and (
                    iidfile is None
                    or not iidfile.is_absolute()
                    or str(iidfile) != iidfile_value
                    or str(iidfile).startswith("//")
                    or ".." in iidfile.parts
                    or iidfile.name != f"{target}.iid"
                    or iidfile.parent.parent != build_root / "artifacts" / "buflo-study"
                    or re.fullmatch(
                        rf"\.build-iids-v{cohort_version}\.[A-Za-z0-9]{{6}}",
                        iidfile.parent.name,
                    )
                    is None
                )
            )
            or (recorded_build_root is not None and build_root != recorded_build_root)
            or type(command.get("exit_code")) is not int
            or command["exit_code"] != 0
            or command.get("image_id") != image_ids[target]
        ):
            raise ValueError("no-cache build commands do not prove --pull --no-cache execution")
        recorded_build_root = build_root

    if (
        schema_version in {2, 3, 4, 5}
        and expected_build_root is not None
        and recorded_build_root != PurePosixPath(str(Path(expected_build_root).resolve()))
    ):
        raise ValueError("no-cache build command root differs from the checkout")

    if value["cache_policy"] != {
        "pull": True,
        "no_cache": True,
        "scope": ("Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only"),
    }:
        raise ValueError("no-cache build cache policy is invalid")
    source = _validate_clean_source(value["source"], collection_image=image_ids["collection"])
    build_inputs = _validate_build_inputs(value["build_inputs"])
    if (
        not isinstance(value["dockerfile_sha256"], str)
        or _SHA256_RE.fullmatch(value["dockerfile_sha256"]) is None
    ):
        raise ValueError("no-cache build Dockerfile binding is invalid")
    _validate_checkout_bindings(value, checkout_root=checkout_root)

    host_storage_preflight = None
    role_provenance = None
    if schema_version in {2, 3, 4, 5}:
        role_provenance = _validate_role_provenance(
            value["role_provenance"],
            image_ids=image_ids,
            source=source,
            build_inputs=build_inputs,
        )
        host_storage_preflight = validate_build_host_storage_preflight(
            value["host_storage_preflight"],
            expected_probe_sha256=expected_probe_sha256,
        )
        if host_storage_preflight["applicable"]:
            observation_times = [
                _aware_timestamp(observation["observed_at"], label="host-storage observation")
                for observation in host_storage_preflight["observations"]
            ]
            if schema_version == 5:
                timing_is_valid = (
                    started
                    <= observation_times[0]
                    < observation_times[1]
                    < observation_times[2]
                    < observation_times[3]
                    <= finished
                )
            else:
                timing_is_valid = (
                    observation_times[0]
                    <= started
                    < observation_times[1]
                    < observation_times[2]
                    < observation_times[3]
                    <= finished
                )
            if not timing_is_valid:
                raise ValueError("no-cache build host-storage timing is invalid")
            if "docker desktop" not in docker["server_operating_system"].lower():
                raise ValueError("WSL build did not use the local Docker Desktop engine")
    validated = {
        "schema_version": schema_version,
        "cohort_version": cohort_version,
        "image_ids": image_ids,
        "source": dict(source),
        "role_provenance": role_provenance,
        "host_storage_preflight": host_storage_preflight,
    }
    if schema_version in {4, 5}:
        validated["buildx"] = validate_buildx_provenance(
            value["buildx"], started_at=started, finished_at=finished
        )
    if schema_version == 5:
        allocation = _validate_cohort_allocation(
            value["cohort_allocation"], cohort_version=cohort_version, source=source
        )
        claim, authority_digest, snapshot_digest, claim_file_digest = (
            _validate_cohort_claim_snapshot(
                value["cohort_claim"],
                allocation=allocation,
                cohort_version=cohort_version,
            )
        )
        claim_chain = _validate_cohort_claim_chain(
            value["cohort_claim_chain"],
            allocation=allocation,
            cohort_version=cohort_version,
            current_snapshot=claim,
        )
        reproofs = _validate_cohort_authority_reproofs(
            value["cohort_authority_reproofs"],
            started_at=started,
            finished_at=finished,
            authority_sha256=authority_digest,
            claim_snapshot_sha256=snapshot_digest,
            claim_file_sha256=claim_file_digest,
            buildx=validated["buildx"],
            host_storage_preflight=host_storage_preflight,
        )
        validated["cohort_allocation"] = allocation
        validated["cohort_claim"] = claim
        validated["cohort_claim_chain"] = claim_chain
        validated["cohort_authority_reproofs"] = reproofs
    return validated


def build_completion_path(receipt_path: Path, cohort_version: int | None = None) -> Path:
    """Return the exact completion sibling for one versioned build receipt."""

    candidate = Path(os.path.abspath(receipt_path))
    match = re.fullmatch(r"build-execution-v([1-9][0-9]*)[.]json", candidate.name)
    if match is None:
        raise ValueError("build execution receipt filename is not versioned canonically")
    filename_version = int(match.group(1))
    if cohort_version is not None and filename_version != _positive_integer(
        cohort_version, label="expected cohort version"
    ):
        raise ValueError("build execution receipt filename differs from its cohort version")
    return candidate.with_name(f"build-completion-v{filename_version}.json")


def _build_receipt_relative_path(cohort_version: int) -> str:
    return f"artifacts/buflo-study/build-execution-v{cohort_version}.json"


def _normalise_completion_receipt_stat(value: Any) -> dict[str, int]:
    if isinstance(value, os.stat_result):
        projected = _completion_file_stat_record(value)
    elif isinstance(value, Mapping):
        projected = dict(value)
    else:
        raise ValueError("build-completion receipt stat binding is invalid")
    return _validate_cohort_stat(
        projected,
        keys=_COHORT_FILE_STAT_KEYS,
        label="build-completion receipt",
        required_mode=0o600,
        required_nlink=1,
    )


def build_execution_receipt_binding(
    *,
    receipt_path: Path,
    receipt_raw: bytes,
    receipt_value: Mapping[str, Any],
    receipt_stat: os.stat_result | Mapping[str, Any],
    cohort_version: int,
    checkout_root: Path | None = None,
) -> dict[str, Any]:
    """Bind the exact stable schema-5 receipt inode and bytes being committed."""

    version = _positive_integer(cohort_version, label="cohort version")
    if (
        not isinstance(receipt_raw, bytes)
        or not isinstance(receipt_value, Mapping)
        or receipt_value.get("schema_version") != 5
        or receipt_value.get("cohort_version") != version
        or not isinstance(receipt_value.get("payload_sha256"), str)
        or _SHA256_RE.fullmatch(receipt_value["payload_sha256"]) is None
    ):
        raise ValueError("build-completion receipt binding requires one schema-5 receipt")
    candidate = Path(os.path.abspath(receipt_path))
    expected_completion = build_completion_path(candidate, version)
    del expected_completion
    relative_path = _build_receipt_relative_path(version)
    if checkout_root is not None:
        root = Path(os.path.abspath(checkout_root))
        if candidate != root / relative_path:
            raise ValueError("build-completion receipt path differs from the checkout")
    status = _normalise_completion_receipt_stat(receipt_stat)
    if status["size"] != len(receipt_raw):
        raise ValueError("build-completion receipt size binding is invalid")
    return {
        "path": relative_path,
        "schema_version": 5,
        "cohort_version": version,
        "payload_sha256": receipt_value["payload_sha256"],
        "sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "stat": status,
    }


_BUILD_TRANSACTION_RECORD_FIELDS = (
    "object",
    "lifecycle_schema",
    "lifecycle_state",
    "lifecycle_root",
    "lifecycle_token",
    "supervisor_source_path",
    "supervisor_source_sha256",
    "supervisor_source_device",
    "supervisor_source_inode",
    "docker_context",
    "docker_host",
    "docker_server_id",
    "docker_request_revalidation",
    "docker_daemon_id",
    "host_boot_id",
    "working_directory",
    "cohort_version",
    "receipt_path",
    "transaction_state",
)


def _parse_build_transaction_record(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise ValueError("build-transaction record is not ASCII") from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        raise ValueError("build-transaction record framing is invalid")
    lines = text[:-1].split("\n")
    fields: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        if not line or "=" not in line:
            raise ValueError("build-transaction record framing is invalid")
        key, item = line.split("=", 1)
        if key in fields:
            raise ValueError("build-transaction record contains a duplicate field")
        fields[key] = item
        order.append(key)
    if tuple(order) != _BUILD_TRANSACTION_RECORD_FIELDS:
        raise ValueError("build-transaction record field inventory is invalid")
    return fields


def _validate_build_transaction_binding(
    value: Any,
    *,
    expected_root: Path,
    expected_receipt: Path,
    expected_checkout_root: Path,
    expected_cohort_version: int,
    expected_lease_nonce: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _BUILD_TRANSACTION_BINDING_KEYS
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _BUILD_TRANSACTION_RETIREMENT_ARTIFACT_TYPE
    ):
        raise ValueError("build-transaction retirement binding is invalid")
    root = value.get("root")
    record = value.get("record")
    if (
        not isinstance(root, Mapping)
        or set(root) != _BUILD_TRANSACTION_ROOT_KEYS
        or not isinstance(record, Mapping)
        or set(record) != _BUILD_TRANSACTION_RECORD_KEYS
    ):
        raise ValueError("build-transaction retirement binding is invalid")
    expected_root = Path(os.path.abspath(expected_root))
    expected_record = expected_root / "SUPERVISION"
    expected_receipt = Path(os.path.abspath(expected_receipt))
    expected_checkout_root = Path(os.path.abspath(expected_checkout_root))
    if (
        not isinstance(expected_lease_nonce, str)
        or _SHA256_RE.fullmatch(expected_lease_nonce) is None
        or expected_root.name != f"transaction.{expected_lease_nonce[:32]}"
        or root.get("path") != str(expected_root)
        or record.get("path") != str(expected_record)
    ):
        raise ValueError("build-transaction retirement path binding is invalid")
    root_stat = _validate_cohort_stat(
        root.get("stat"),
        keys=_COHORT_DIRECTORY_STAT_KEYS,
        label="build-transaction root",
        required_mode=0o700,
    )
    record_stat = _validate_cohort_stat(
        record.get("stat"),
        keys=_COHORT_FILE_STAT_KEYS,
        label="build-transaction record",
        required_mode=0o600,
        required_nlink=1,
    )
    try:
        raw = base64.b64decode(str(record.get("payload_base64")).encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise ValueError("build-transaction record payload is invalid") from error
    if (
        not isinstance(record.get("sha256"), str)
        or _SHA256_RE.fullmatch(record["sha256"]) is None
        or hashlib.sha256(raw).hexdigest() != record["sha256"]
        or record_stat["size"] != len(raw)
    ):
        raise ValueError("build-transaction record payload binding is invalid")
    fields = _parse_build_transaction_record(raw)
    version = _positive_integer(expected_cohort_version, label="expected cohort version")
    if (
        fields["object"] != "docker-build-transaction"
        or fields["lifecycle_schema"] != "1"
        or fields["lifecycle_state"] != "request-authorised"
        or fields["lifecycle_root"] != str(expected_root)
        or fields["lifecycle_token"] != expected_lease_nonce[:32]
        or not Path(fields["supervisor_source_path"]).is_absolute()
        or _SHA256_RE.fullmatch(fields["supervisor_source_sha256"]) is None
        or not fields["supervisor_source_device"].isdigit()
        or int(fields["supervisor_source_device"]) <= 0
        or not fields["supervisor_source_inode"].isdigit()
        or int(fields["supervisor_source_inode"]) <= 0
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", fields["docker_context"])
        or fields["docker_host"]
        not in {
            "unix:///var/run/docker.sock",
            "npipe:////./pipe/dockerDesktopLinuxEngine",
        }
        or not re.fullmatch(r"[A-Za-z0-9_.:-]+", fields["docker_server_id"])
        or fields["docker_server_id"] != fields["docker_daemon_id"]
        or fields["docker_request_revalidation"]
        != "in-scope-immediately-before-mutation"
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            fields["host_boot_id"],
        )
        is None
        or fields["working_directory"] != str(expected_checkout_root)
        or fields["cohort_version"] != str(version)
        or fields["receipt_path"] != str(expected_receipt)
        or fields["transaction_state"] != "uncommitted-static-tag-mutation"
    ):
        raise ValueError("build-transaction record authority is invalid")
    return {
        "schema_version": 1,
        "artifact_type": _BUILD_TRANSACTION_RETIREMENT_ARTIFACT_TYPE,
        "root": {"path": str(expected_root), "stat": root_stat},
        "record": {
            "path": str(expected_record),
            "sha256": record["sha256"],
            "payload_base64": record["payload_base64"],
            "stat": record_stat,
        },
    }


def capture_build_transaction_binding(
    record_path: Path,
    *,
    expected_receipt: Path,
    expected_checkout_root: Path,
    expected_cohort_version: int,
    expected_lease_nonce: str,
) -> dict[str, Any]:
    """Capture the exact provisional transaction immediately before retirement."""

    record_path = Path(os.path.abspath(record_path))
    root_path = record_path.parent
    if record_path.name != "SUPERVISION" or root_path.is_symlink():
        raise ValueError("build-transaction record path is invalid")
    try:
        root_stat_os = os.stat(root_path, follow_symlinks=False)
    except OSError as error:
        raise ValueError("build-transaction root is unavailable") from error
    if (
        not stat.S_ISDIR(root_stat_os.st_mode)
        or root_stat_os.st_uid != os.geteuid()
        or root_stat_os.st_gid != os.getegid()
        or stat.S_IMODE(root_stat_os.st_mode) != 0o700
        or root_path.resolve(strict=True) != root_path
    ):
        raise ValueError("build-transaction root is not a private canonical directory")
    # SUPERVISION is an exact key=value record, not JSON; use the same stable
    # inode reader while retaining its stat binding.
    raw, record_stat_os = _read_stable_regular_file_with_stat(
        record_path, label="build-transaction record", maximum_bytes=64 * 1024
    )
    if (
        record_path.resolve(strict=True) != record_path
        or record_stat_os.st_uid != os.geteuid()
        or record_stat_os.st_gid != os.getegid()
        or stat.S_IMODE(record_stat_os.st_mode) != 0o600
        or record_stat_os.st_nlink != 1
    ):
        raise ValueError("build-transaction record is not private create-only evidence")
    try:
        root_after = os.stat(root_path, follow_symlinks=False)
        record_after = os.stat(record_path, follow_symlinks=False)
    except OSError as error:
        raise ValueError("build-transaction binding changed while captured") from error
    if (
        _stat_identity(root_after) != _stat_identity(root_stat_os)
        or _stat_identity(record_after) != _stat_identity(record_stat_os)
        or root_after.st_uid != os.geteuid()
        or root_after.st_gid != os.getegid()
        or stat.S_IMODE(root_after.st_mode) != 0o700
    ):
        raise ValueError("build-transaction binding changed while captured")
    root_stat = {
        "dev": root_stat_os.st_dev,
        "inode": root_stat_os.st_ino,
        "uid": root_stat_os.st_uid,
        "gid": root_stat_os.st_gid,
        "mode": stat.S_IMODE(root_stat_os.st_mode),
        "nlink": root_stat_os.st_nlink,
    }
    value = {
        "schema_version": 1,
        "artifact_type": _BUILD_TRANSACTION_RETIREMENT_ARTIFACT_TYPE,
        "root": {"path": str(root_path), "stat": root_stat},
        "record": {
            "path": str(record_path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "payload_base64": base64.b64encode(raw).decode("ascii"),
            "stat": _completion_file_stat_record(record_stat_os),
        },
    }
    return _validate_build_transaction_binding(
        value,
        expected_root=root_path,
        expected_receipt=expected_receipt,
        expected_checkout_root=expected_checkout_root,
        expected_cohort_version=expected_cohort_version,
        expected_lease_nonce=expected_lease_nonce,
    )


def _completion_authority_bindings(
    receipt_value: Mapping[str, Any],
) -> dict[str, str]:
    allocation = receipt_value["cohort_allocation"]
    claim = receipt_value["cohort_claim"]
    chain = receipt_value["cohort_claim_chain"]
    if not isinstance(allocation, Mapping) or not isinstance(claim, Mapping) or not isinstance(
        chain, Mapping
    ):
        raise ValueError("build-completion cohort authority is malformed")
    claim_binding = claim.get("claim")
    if not isinstance(claim_binding, Mapping):
        raise ValueError("build-completion cohort claim binding is malformed")
    return {
        "allocation_sha256": hashlib.sha256(
            _canonical_finite_json_bytes(
                allocation,
                label="build-completion cohort allocation",
            )
        ).hexdigest(),
        "claim_snapshot_sha256": hashlib.sha256(
            _canonical_finite_json_bytes(
                claim,
                label="build-completion cohort claim snapshot",
            )
        ).hexdigest(),
        "claim_file_sha256": str(claim_binding.get("sha256", "")),
        "claim_chain_sha256": hashlib.sha256(
            _canonical_finite_json_bytes(
                chain,
                label="build-completion cohort claim chain",
            )
        ).hexdigest(),
        "claim_chain_payload_sha256": str(chain.get("payload_sha256", "")),
    }


def _validate_build_completion_transaction(
    value: Any,
    *,
    receipt_value: Mapping[str, Any],
    cohort_version: int,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _BUILD_COMPLETION_TRANSACTION_KEYS
        or value.get("schema_version") != 1
        or value.get("artifact_type") != _BUILD_TRANSACTION_RETIREMENT_ARTIFACT_TYPE
    ):
        raise ValueError("build-completion transaction binding is invalid")
    guardian = value.get("guardian")
    lifecycle = value.get("lifecycle_lock")
    cohort_lock = value.get("cohort_lock")
    operation_lock = value.get("operation_lock")
    if (
        not isinstance(guardian, Mapping)
        or set(guardian) != _BUILD_COMPLETION_GUARDIAN_KEYS
        or any(type(guardian[key]) is not int or guardian[key] <= 0 for key in guardian)
        or guardian["pid"] == guardian["qcsd_pid"]
        or not isinstance(lifecycle, Mapping)
        or set(lifecycle) != _BUILD_COMPLETION_LIFECYCLE_KEYS
        or not isinstance(cohort_lock, Mapping)
        or set(cohort_lock) != _BUILD_COMPLETION_COHORT_LOCK_KEYS
        or not isinstance(operation_lock, Mapping)
        or set(operation_lock) != _BUILD_COMPLETION_OPERATION_LOCK_KEYS
    ):
        raise ValueError("build-completion transaction authority is invalid")
    if (
        any(
            type(lifecycle.get(key)) is not int or lifecycle[key] <= 0
            for key in ("device", "inode", "parent_device", "parent_inode")
        )
        or not isinstance(lifecycle.get("lease_nonce"), str)
        or _SHA256_RE.fullmatch(lifecycle["lease_nonce"]) is None
        or any(
            type(cohort_lock.get(key)) is not int or cohort_lock[key] <= 0
            for key in (
                "device",
                "inode",
                "parent_device",
                "parent_inode",
                "guardian_fd",
            )
        )
        or any(
            type(operation_lock.get(key)) is not int or operation_lock[key] <= 0
            for key in ("device", "inode", "parent_device", "parent_inode")
        )
    ):
        raise ValueError("build-completion transaction lock identity is invalid")
    paths: list[Path] = []
    for binding, key in (
        (lifecycle, "path"),
        (cohort_lock, "path"),
        (operation_lock, "path"),
    ):
        raw_path = binding.get(key)
        if not isinstance(raw_path, str):
            raise ValueError("build-completion transaction lock path is invalid")
        path = Path(raw_path)
        if not path.is_absolute() or Path(os.path.normpath(path)) != path:
            raise ValueError("build-completion transaction lock path is invalid")
        paths.append(path)
    lifecycle_path, cohort_path, operation_path = paths
    if (
        not lifecycle_path.name.endswith(".lock")
        or cohort_path.name != ".allocation.lock"
        or operation_path.name != ".allocation-operation.lock"
        or cohort_path.parent != operation_path.parent
        or cohort_lock["parent_device"] != operation_lock["parent_device"]
        or cohort_lock["parent_inode"] != operation_lock["parent_inode"]
        or len(
            {
                (lifecycle["device"], lifecycle["inode"]),
                (cohort_lock["device"], cohort_lock["inode"]),
                (operation_lock["device"], operation_lock["inode"]),
            }
        )
        != 3
    ):
        raise ValueError("build-completion transaction lock relationship is invalid")
    commands = receipt_value.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("build-completion transaction receipt commands are invalid")
    build_root_raw = commands[0].get("argv", [])[-1]
    build_root = Path(str(build_root_raw))
    if not build_root.is_absolute() or Path(os.path.normpath(build_root)) != build_root:
        raise ValueError("build-completion transaction checkout path is invalid")
    transaction_base = Path(str(lifecycle_path)[: -len(".lock")])
    transaction_root = Path(str(value.get("root", {}).get("path", "")))
    expected_receipt = build_root / _build_receipt_relative_path(cohort_version)
    base_binding = {
        "schema_version": value["schema_version"],
        "artifact_type": value["artifact_type"],
        "root": value["root"],
        "record": value["record"],
    }
    validated_base = _validate_build_transaction_binding(
        base_binding,
        expected_root=transaction_root,
        expected_receipt=expected_receipt,
        expected_checkout_root=build_root,
        expected_cohort_version=cohort_version,
        expected_lease_nonce=lifecycle["lease_nonce"],
    )
    if transaction_root.parent != transaction_base:
        raise ValueError("build-completion transaction root is outside lifecycle authority")
    return {
        **validated_base,
        "guardian": dict(guardian),
        "lifecycle_lock": dict(lifecycle),
        "cohort_lock": dict(cohort_lock),
        "operation_lock": dict(operation_lock),
    }


def validate_build_completion_authority(
    value: Any,
    *,
    completion_path: Path,
    receipt_path: Path,
    receipt_raw: bytes,
    receipt_value: Mapping[str, Any],
    receipt_stat: os.stat_result | Mapping[str, Any],
    expected_cohort_version: int | None = None,
    checkout_root: Path | None = None,
    require_receipt_stat_identity: bool = False,
) -> dict[str, Any]:
    """Validate the durable success linearisation for one schema-5 build.

    A completion records the receipt's exact publication-time inode metadata,
    but later readers may observe the pair through a bind mount whose volatile
    stat identity differs.  Ordinary admission therefore compares the receipt
    bytes and portable safety fields.  The publisher opts into exact stat
    identity while proving the irreversible completion boundary.
    """

    if type(require_receipt_stat_identity) is not bool:
        raise ValueError("build-completion receipt stat policy is invalid")

    if not isinstance(value, Mapping) or set(value) != _BUILD_COMPLETION_KEYS:
        raise ValueError("build-completion schema is invalid")
    version = _positive_integer(value.get("cohort_version"), label="cohort version")
    if expected_cohort_version is not None and version != _positive_integer(
        expected_cohort_version, label="expected cohort version"
    ):
        raise ValueError("build-completion cohort version differs from the request")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != BUILD_COMPLETION_SCHEMA_VERSION
        or value.get("artifact_type") != BUILD_COMPLETION_ARTIFACT_TYPE
    ):
        raise ValueError("build-completion schema is invalid")
    payload = dict(value)
    claimed_payload = payload.pop("payload_sha256")
    if (
        not isinstance(claimed_payload, str)
        or _SHA256_RE.fullmatch(claimed_payload) is None
        or claimed_payload
        != hashlib.sha256(
            _canonical_finite_json_bytes(payload, label="build completion")
        ).hexdigest()
    ):
        raise ValueError("build-completion payload hash is invalid")

    receipt_candidate = Path(os.path.abspath(receipt_path))
    completion_candidate = Path(os.path.abspath(completion_path))
    if completion_candidate != build_completion_path(receipt_candidate, version):
        raise ValueError("build-completion path does not match its receipt")
    observed_receipt_binding = build_execution_receipt_binding(
        receipt_path=receipt_candidate,
        receipt_raw=receipt_raw,
        receipt_value=receipt_value,
        receipt_stat=receipt_stat,
        cohort_version=version,
        checkout_root=checkout_root,
    )
    claimed_receipt = value.get("receipt")
    if not isinstance(claimed_receipt, Mapping) or set(claimed_receipt) != (
        _BUILD_COMPLETION_RECEIPT_KEYS
    ):
        raise ValueError("build-completion receipt binding is invalid")
    claimed_receipt_binding = dict(claimed_receipt)
    claimed_receipt_binding["stat"] = _normalise_completion_receipt_stat(
        claimed_receipt.get("stat")
    )
    observed_stat = observed_receipt_binding["stat"]
    claimed_stat = claimed_receipt_binding["stat"]
    portable_stat_keys = ("mode", "nlink", "size")
    if (
        any(
            claimed_receipt_binding[key] != observed_receipt_binding[key]
            for key in _BUILD_COMPLETION_RECEIPT_KEYS - {"stat"}
        )
        or any(claimed_stat[key] != observed_stat[key] for key in portable_stat_keys)
        or (
            require_receipt_stat_identity
            and claimed_receipt_binding != observed_receipt_binding
        )
    ):
        raise ValueError("build-completion receipt binding is invalid")
    # Preserve the completion's immutable publication-time provenance in the
    # projected value; do not replace it with mount-local volatile metadata.
    receipt_binding = claimed_receipt_binding

    validated_receipt = validate_build_execution_envelope(
        receipt_value,
        expected_cohort_version=version,
    )
    if validated_receipt["schema_version"] != 5:
        raise ValueError("build completion can authorise only a schema-5 receipt")
    source = value.get("source")
    allocation = validated_receipt["cohort_allocation"]
    expected_source = {
        "lab_commit": validated_receipt["source"]["lab_commit"],
        "neqo_commit": validated_receipt["source"]["neqo_commit"],
        "neqo_gitlink": allocation["neqo_gitlink"],
    }
    if (
        not isinstance(source, Mapping)
        or set(source) != _BUILD_COMPLETION_SOURCE_KEYS
        or dict(source) != expected_source
    ):
        raise ValueError("build-completion source binding is invalid")

    expected_authority = _completion_authority_bindings(receipt_value)
    if (
        any(_SHA256_RE.fullmatch(digest) is None for digest in expected_authority.values())
        or not isinstance(value.get("cohort_authority"), Mapping)
        or set(value["cohort_authority"]) != _BUILD_COMPLETION_AUTHORITY_KEYS
        or dict(value["cohort_authority"]) != expected_authority
    ):
        raise ValueError("build-completion cohort-authority binding is invalid")

    transaction = _validate_build_completion_transaction(
        value.get("transaction"),
        receipt_value=receipt_value,
        cohort_version=version,
    )

    final_reproof = value.get("final_reproof")
    receipt_reproofs = validated_receipt["cohort_authority_reproofs"]
    expected_reproof_hashes = {
        "authority_sha256": receipt_reproofs[-1]["authority_sha256"],
        "claim_snapshot_sha256": expected_authority["claim_snapshot_sha256"],
        "claim_file_sha256": expected_authority["claim_file_sha256"],
        "claim_chain_sha256": expected_authority["claim_chain_sha256"],
    }
    if (
        not isinstance(final_reproof, Mapping)
        or set(final_reproof) != _BUILD_COMPLETION_REPROOF_KEYS
        or final_reproof.get("boundary") != BUILD_COMPLETION_FINAL_REPROOF_BOUNDARY
        or any(final_reproof.get(key) != digest for key, digest in expected_reproof_hashes.items())
    ):
        raise ValueError("build-completion final reproof is invalid")
    observed_at = _aware_timestamp(
        final_reproof.get("observed_at"), label="build-completion final reproof"
    )
    completed_at = _aware_timestamp(value.get("completed_at"), label="build completion")
    receipt_finished = _aware_timestamp(receipt_value.get("finished_at"), label="build finish")
    age = (completed_at - observed_at).total_seconds()
    if (
        observed_at < receipt_finished
        or completed_at < observed_at
        or age > BUILD_COMPLETION_FINAL_REPROOF_MAX_AGE_SECONDS
    ):
        raise ValueError("build-completion final reproof timing is invalid")

    return {
        "schema_version": BUILD_COMPLETION_SCHEMA_VERSION,
        "artifact_type": BUILD_COMPLETION_ARTIFACT_TYPE,
        "cohort_version": version,
        "completed_at": value["completed_at"],
        "receipt": receipt_binding,
        "source": expected_source,
        "cohort_authority": expected_authority,
        "transaction": transaction,
        "final_reproof": dict(final_reproof),
        "payload_sha256": claimed_payload,
    }


def load_validated_build_execution(
    receipt_path: Path,
    *,
    expected_cohort_version: int | None = None,
    expected_probe_sha256: str | None = None,
    checkout_root: Path | None = None,
    expected_build_root: Path | None = None,
    require_current: bool = True,
) -> tuple[Path, bytes, Any, dict[str, Any], dict[str, Any] | None]:
    """Load a receipt and require completion for current schema-5 evidence."""

    resolved, raw, value, receipt_status = load_stable_build_execution_with_stat(receipt_path)
    validated = validate_build_execution_envelope(
        value,
        expected_cohort_version=expected_cohort_version,
        expected_probe_sha256=expected_probe_sha256,
        checkout_root=checkout_root,
        expected_build_root=expected_build_root,
    )
    if validated["schema_version"] != 5:
        if require_current:
            raise ValueError(
                "current build admission requires schema 5 and its completion"
            )
        return resolved, raw, value, validated, None
    completion_candidate = build_completion_path(resolved, validated["cohort_version"])
    completion_resolved, completion_raw, completion_value = load_stable_build_completion(
        completion_candidate
    )
    completion = validate_build_completion_authority(
        completion_value,
        completion_path=completion_resolved,
        receipt_path=resolved,
        receipt_raw=raw,
        receipt_value=value,
        receipt_stat=receipt_status,
        expected_cohort_version=validated["cohort_version"],
        checkout_root=checkout_root,
    )
    # A second complete pass makes replacement or mutation between the paired
    # reads observable.  This does not claim a durable shell-exit observation;
    # the completion publication itself is the authoritative success point.
    receipt_after, raw_after, value_after, status_after = load_stable_build_execution_with_stat(
        resolved
    )
    completion_after, completion_raw_after, completion_value_after = (
        load_stable_build_completion(completion_resolved)
    )
    if (
        receipt_after != resolved
        or raw_after != raw
        or value_after != value
        or _stat_identity(status_after) != _stat_identity(receipt_status)
        or completion_after != completion_resolved
        or completion_raw_after != completion_raw
        or completion_value_after != completion_value
    ):
        raise ValueError("build receipt or completion changed during paired validation")
    return resolved, raw, value, validated, completion


def _publish_private_create_only_json(path: Path, value: Mapping[str, Any]) -> bytes:
    encoded = _canonical_finite_json_bytes(value, label="build completion", newline=True)
    if len(encoded) > BUILD_COMPLETION_MAX_BYTES:
        raise ValueError("build completion exceeds the stable-reader size limit")
    destination = Path(os.path.abspath(path))
    parent_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    file_read_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    token = os.urandom(32).hex()
    stage_name = f".{destination.name}.{token}.next"
    directory = os.open(destination.parent, parent_flags)
    stage = -1
    published = -1
    linked = False
    try:
        try:
            os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("build-completion destination already exists")
        stage = os.open(
            stage_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        os.fchmod(stage, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(stage, view)
            if written <= 0:
                raise OSError("short build-completion staging write")
            view = view[written:]
        os.fsync(stage)
        os.fsync(directory)
        stage_status = os.fstat(stage)
        if (
            not stat.S_ISREG(stage_status.st_mode)
            or stage_status.st_uid != os.geteuid()
            or stage_status.st_gid != os.getegid()
            or stat.S_IMODE(stage_status.st_mode) != 0o600
            or stage_status.st_nlink != 1
            or stage_status.st_size != len(encoded)
        ):
            raise ValueError("build-completion staging inode is unsafe")
        libc = ctypes.CDLL(None, use_errno=True)
        linkat = libc.linkat
        linkat.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        )
        linkat.restype = ctypes.c_int
        if linkat(
            -100,
            f"/proc/self/fd/{stage}".encode("ascii"),
            directory,
            os.fsencode(destination.name),
            0x400,
        ) != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise ValueError("build-completion destination raced during publication")
            raise OSError(error_number, os.strerror(error_number), destination)
        linked = True
        published = os.open(destination.name, file_read_flags, dir_fd=directory)
        published_status = os.fstat(published)
        linked_stage_status = os.fstat(stage)
        if (
            (published_status.st_dev, published_status.st_ino)
            != (stage_status.st_dev, stage_status.st_ino)
            or _stat_identity(linked_stage_status) != _stat_identity(published_status)
            or published_status.st_nlink != 2
        ):
            raise ValueError("published build completion differs from its staging inode")
        os.lseek(published, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = len(encoded)
        while remaining:
            chunk = os.read(published, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if b"".join(chunks) != encoded or os.read(published, 1):
            raise ValueError("published build-completion bytes changed during publication")
        os.fsync(published)
        os.fsync(directory)
        current_stage = os.stat(stage_name, dir_fd=directory, follow_symlinks=False)
        if (current_stage.st_dev, current_stage.st_ino) != (
            stage_status.st_dev,
            stage_status.st_ino,
        ):
            raise ValueError("build-completion staging pathname changed during publication")
        os.unlink(stage_name, dir_fd=directory)
        os.fsync(directory)
        final_status = os.fstat(published)
        destination_status = os.stat(
            destination.name, dir_fd=directory, follow_symlinks=False
        )
        if (
            (final_status.st_dev, final_status.st_ino)
            != (stage_status.st_dev, stage_status.st_ino)
            or _stat_identity(final_status) != _stat_identity(destination_status)
            or final_status.st_nlink != 1
        ):
            raise ValueError("published build-completion link identity is invalid")
    finally:
        if published >= 0:
            os.close(published)
        if stage >= 0:
            if not linked:
                try:
                    current = os.stat(stage_name, dir_fd=directory, follow_symlinks=False)
                    opened = os.fstat(stage)
                    if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                        os.unlink(stage_name, dir_fd=directory)
                        os.fsync(directory)
                except FileNotFoundError:
                    pass
            os.close(stage)
        os.close(directory)
    return encoded


def _cohort_allocation_module() -> Any:
    global _COHORT_ALLOCATION_MODULE
    if _COHORT_ALLOCATION_MODULE is not None:
        return _COHORT_ALLOCATION_MODULE
    try:
        from qcsd_lab import cohort_allocation as module
    except ModuleNotFoundError:
        # ``python -I path/to/build_storage.py`` intentionally has no caller or
        # script directory on sys.path.  Load the exact sibling by descriptor,
        # never a caller-controlled top-level module of the same name.
        sibling = Path(__file__).resolve().with_name("cohort_allocation.py")
        name = "_qcsd_exact_cohort_allocation"
        spec = importlib.util.spec_from_file_location(name, sibling)
        if spec is None or spec.loader is None:
            raise ValueError("exact cohort-allocation module cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise

    _COHORT_ALLOCATION_MODULE = module
    return _COHORT_ALLOCATION_MODULE


def _verify_guardian_lifecycle_lock(
    lifecycle_authority: Mapping[str, Any],
    *,
    guardian_lock: Any,
) -> Path:
    if (
        not isinstance(lifecycle_authority, Mapping)
        or set(lifecycle_authority) != _BUILD_COMPLETION_LIFECYCLE_KEYS
        or any(
            type(lifecycle_authority.get(key)) is not int
            or lifecycle_authority[key] <= 0
            for key in ("device", "inode", "parent_device", "parent_inode")
        )
        or not isinstance(lifecycle_authority.get("path"), str)
        or not isinstance(lifecycle_authority.get("lease_nonce"), str)
        or _SHA256_RE.fullmatch(lifecycle_authority["lease_nonce"]) is None
    ):
        raise ValueError("build-completion lifecycle-lock authority is invalid")
    lock_path = Path(lifecycle_authority["path"])
    if (
        not lock_path.is_absolute()
        or Path(os.path.normpath(lock_path)) != lock_path
        or not lock_path.name.endswith(".lock")
    ):
        raise ValueError("build-completion lifecycle-lock path is invalid")
    try:
        parent = os.stat(lock_path.parent, follow_symlinks=False)
        entry = os.stat(lock_path, follow_symlinks=False)
    except OSError as error:
        raise ValueError("build-completion lifecycle lock is unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_dev != lifecycle_authority["parent_device"]
        or parent.st_ino != lifecycle_authority["parent_inode"]
        or not stat.S_ISREG(entry.st_mode)
        or entry.st_dev != lifecycle_authority["device"]
        or entry.st_ino != lifecycle_authority["inode"]
        or entry.st_uid != os.geteuid()
        or stat.S_IMODE(entry.st_mode) != 0o600
        or entry.st_nlink != 1
        or entry.st_size != 0
        or (entry.st_dev, entry.st_ino) == (guardian_lock.device, guardian_lock.inode)
    ):
        raise ValueError("build-completion lifecycle-lock identity is invalid")
    matches = 0
    try:
        fd_names = os.listdir(f"/proc/{guardian_lock.guardian_pid}/fd")
    except OSError as error:
        raise ValueError("build-completion guardian descriptor table is unavailable") from error
    for name in fd_names:
        if not name.isdigit() or int(name) < 3:
            continue
        descriptor_path = f"/proc/{guardian_lock.guardian_pid}/fd/{name}"
        try:
            descriptor_status = os.stat(descriptor_path)
            descriptor_target = os.readlink(descriptor_path)
        except OSError:
            continue
        if (descriptor_status.st_dev, descriptor_status.st_ino) != (
            entry.st_dev,
            entry.st_ino,
        ):
            continue
        try:
            fdinfo = Path(
                f"/proc/{guardian_lock.guardian_pid}/fdinfo/{name}"
            ).read_text(encoding="ascii")
        except (OSError, UnicodeError) as error:
            raise ValueError("build-completion lifecycle-lock proof is unavailable") from error
        lock_pids = _GUARDIAN_FDINFO_LOCK_RE.findall(fdinfo)
        if descriptor_target != str(lock_path) or lock_pids != [
            str(guardian_lock.guardian_pid)
        ]:
            raise ValueError("build-completion guardian does not hold the lifecycle lock")
        matches += 1
    if matches != 1:
        raise ValueError("build-completion lifecycle-lock descriptor is not unique")
    return Path(str(lock_path)[: -len(".lock")])


def _verify_retired_build_transaction(
    *,
    lifecycle_root: Path,
    retired_transaction_root: Path,
    receipt_path: Path,
    cohort_version: int,
    guardian_lock: Any,
    lifecycle_authority: Mapping[str, Any],
) -> None:
    transaction = Path(os.path.abspath(retired_transaction_root))
    lease_nonce = lifecycle_authority.get("lease_nonce")
    if (
        transaction.parent != lifecycle_root
        or _LIFECYCLE_TRANSACTION_NAME_RE.fullmatch(transaction.name) is None
        or not isinstance(lease_nonce, str)
        or _SHA256_RE.fullmatch(lease_nonce) is None
        or transaction.name != f"transaction.{lease_nonce[:32]}"
        or guardian_lock.cohort_version != cohort_version
        or guardian_lock.owner_pid != os.getppid()
        or receipt_path.name != f"build-execution-v{cohort_version}.json"
    ):
        raise ValueError("build-completion retired transaction binding is invalid")
    try:
        root_status = os.stat(lifecycle_root, follow_symlinks=False)
    except OSError as error:
        raise ValueError("build-completion lifecycle namespace is unavailable") from error
    if (
        not stat.S_ISDIR(root_status.st_mode)
        or root_status.st_uid != os.geteuid()
        or stat.S_IMODE(root_status.st_mode) != 0o700
    ):
        raise ValueError("build-completion lifecycle namespace is unsafe")
    try:
        os.stat(transaction, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ValueError("build-completion retired transaction cannot be checked") from error
    else:
        raise ValueError("build-completion build transaction is not retired")
    try:
        entries = os.listdir(lifecycle_root)
    except OSError as error:
        raise ValueError("build-completion lifecycle namespace cannot be scanned") from error
    if any(
        re.fullmatch(
            r"(?:transaction|retirement[.]transaction|[.]retired[.]transaction)"
            r"[.][0-9a-f]{32}",
            name,
        )
        for name in entries
    ):
        raise ValueError("build-completion lifecycle namespace retains a transaction")


def _run_git(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(root),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("build-completion source authority cannot be read") from error
    if completed.returncode != 0:
        raise ValueError("build-completion source authority cannot be read")
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise ValueError("build-completion source authority is not ASCII") from error


def _verify_live_completion_source(
    checkout_root: Path,
    receipt_value: Mapping[str, Any],
) -> None:
    root = Path(os.path.abspath(checkout_root))
    source = receipt_value["source"]
    allocation = receipt_value["cohort_allocation"]
    neqo_root = root / "neqo-qcsd"
    if (
        _run_git(root, "status", "--porcelain", "--untracked-files=all")
        or _run_git(neqo_root, "status", "--porcelain", "--untracked-files=all")
        or _run_git(root, "rev-parse", "--verify", "HEAD^{commit}")
        != source["lab_commit"]
        or _run_git(neqo_root, "rev-parse", "--verify", "HEAD^{commit}")
        != source["neqo_commit"]
        or _run_git(root, "rev-parse", "HEAD:neqo-qcsd")
        != allocation["neqo_gitlink"]
    ):
        raise ValueError("build-completion clean source authority changed")
    ledger_path = root / allocation["ledger_path"]
    ledger_raw = _read_stable_regular_file(
        ledger_path,
        label="build-completion consumed-cohort ledger",
        maximum_bytes=_COHORT_LEDGER_MAX_BYTES,
    )
    try:
        expected_ledger = base64.b64decode(
            allocation["ledger_payload_base64"].encode("ascii"), validate=True
        )
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise ValueError("build-completion ledger binding is invalid") from error
    if ledger_raw != expected_ledger or hashlib.sha256(ledger_raw).hexdigest() != allocation[
        "ledger_sha256"
    ]:
        raise ValueError("build-completion consumed-cohort ledger changed")


def publish_build_completion(
    receipt_path: Path,
    *,
    expected_receipt_binding: Mapping[str, Any],
    expected_transaction_binding: Mapping[str, Any],
    expected_cohort_version: int,
    expected_probe_sha256: str,
    checkout_root: Path,
    expected_build_root: Path,
    guardian_lock: Any,
    lifecycle_authority: Mapping[str, Any],
    retired_transaction_root: Path,
    completion_path: Path | None = None,
) -> dict[str, Any]:
    """Publish the irreversible success marker after all earlier work passes."""

    resolved, raw, receipt_value, receipt_status = load_stable_build_execution_with_stat(
        receipt_path
    )
    validated = validate_build_execution_envelope(
        receipt_value,
        expected_cohort_version=expected_cohort_version,
        expected_probe_sha256=expected_probe_sha256,
        checkout_root=checkout_root,
        expected_build_root=expected_build_root,
    )
    if validated["schema_version"] != 5:
        raise ValueError("build completion can authorise only a schema-5 receipt")
    binding = build_execution_receipt_binding(
        receipt_path=resolved,
        receipt_raw=raw,
        receipt_value=receipt_value,
        receipt_stat=receipt_status,
        cohort_version=validated["cohort_version"],
        checkout_root=checkout_root,
    )
    if not isinstance(expected_receipt_binding, Mapping) or dict(
        expected_receipt_binding
    ) != binding:
        raise ValueError("build receipt changed after transaction binding")
    expected_completion = build_completion_path(resolved, validated["cohort_version"])
    destination = expected_completion if completion_path is None else Path(
        os.path.abspath(completion_path)
    )
    if destination != expected_completion:
        raise ValueError("build-completion destination is not the canonical sibling")
    cohort_module = _cohort_allocation_module()
    with cohort_module.guarded_cohort_evidence_operation(
        Path(checkout_root),
        receipt_value["cohort_claim"],
        receipt_value["cohort_claim_chain"],
        guardian_lock=guardian_lock,
        retain_operation_lock=True,
    ) as live_authority:
        reprove_cohort_authority = live_authority.get("reprove")
        if not callable(reprove_cohort_authority):
            raise ValueError("build-completion live cohort authority cannot be reproved")
        expected_authority = _completion_authority_bindings(receipt_value)
        if any(
            live_authority[key] != expected_authority[target]
            for key, target in (
                ("claim_snapshot_sha256", "claim_snapshot_sha256"),
                ("claim_file_sha256", "claim_file_sha256"),
                ("claim_chain_sha256", "claim_chain_sha256"),
            )
        ) or live_authority["authority_sha256"] != validated[
            "cohort_authority_reproofs"
        ][-1]["authority_sha256"]:
            raise ValueError("build-completion live cohort authority changed")
        lifecycle_root = _verify_guardian_lifecycle_lock(
            lifecycle_authority,
            guardian_lock=guardian_lock,
        )
        _verify_retired_build_transaction(
            lifecycle_root=lifecycle_root,
            retired_transaction_root=retired_transaction_root,
            receipt_path=resolved,
            cohort_version=validated["cohort_version"],
            guardian_lock=guardian_lock,
            lifecycle_authority=lifecycle_authority,
        )
        _verify_live_completion_source(Path(checkout_root), receipt_value)
        rebound, rebound_raw, rebound_value, rebound_status = (
            load_stable_build_execution_with_stat(resolved)
        )
        rebound_binding = build_execution_receipt_binding(
            receipt_path=rebound,
            receipt_raw=rebound_raw,
            receipt_value=rebound_value,
            receipt_stat=rebound_status,
            cohort_version=validated["cohort_version"],
            checkout_root=checkout_root,
        )
        if (
            rebound != resolved
            or rebound_raw != raw
            or rebound_value != receipt_value
            or rebound_binding != binding
        ):
            raise ValueError("build receipt changed immediately before completion")
        transaction_base = _validate_build_transaction_binding(
            expected_transaction_binding,
            expected_root=retired_transaction_root,
            expected_receipt=resolved,
            expected_checkout_root=checkout_root,
            expected_cohort_version=validated["cohort_version"],
            expected_lease_nonce=lifecycle_authority["lease_nonce"],
        )
        transaction = {
            **transaction_base,
            "guardian": {
                "pid": guardian_lock.guardian_pid,
                "start_time": guardian_lock.guardian_start,
                "qcsd_pid": guardian_lock.owner_pid,
                "qcsd_start_time": guardian_lock.owner_start,
            },
            "lifecycle_lock": dict(lifecycle_authority),
            "cohort_lock": {
                "path": guardian_lock.path,
                "device": guardian_lock.device,
                "inode": guardian_lock.inode,
                "parent_device": guardian_lock.parent_device,
                "parent_inode": guardian_lock.parent_inode,
                "guardian_fd": guardian_lock.guardian_fd,
            },
            "operation_lock": dict(live_authority["operation_lock"]),
        }
        transaction = _validate_build_completion_transaction(
            transaction,
            receipt_value=receipt_value,
            cohort_version=validated["cohort_version"],
        )

        # Everything below is the final saved-source/transaction/claim-chain
        # boundary.  Recompute it inside the capability child while B remains
        # held: the values captured on context entry are not accepted as a
        # substitute for a proof immediately before the irreversible link.
        _verify_live_completion_source(Path(checkout_root), receipt_value)
        lifecycle_root = _verify_guardian_lifecycle_lock(
            lifecycle_authority,
            guardian_lock=guardian_lock,
        )
        _verify_retired_build_transaction(
            lifecycle_root=lifecycle_root,
            retired_transaction_root=retired_transaction_root,
            receipt_path=resolved,
            cohort_version=validated["cohort_version"],
            guardian_lock=guardian_lock,
            lifecycle_authority=lifecycle_authority,
        )
        final_resolved, final_raw, final_value, final_status = (
            load_stable_build_execution_with_stat(resolved)
        )
        final_binding = build_execution_receipt_binding(
            receipt_path=final_resolved,
            receipt_raw=final_raw,
            receipt_value=final_value,
            receipt_stat=final_status,
            cohort_version=validated["cohort_version"],
            checkout_root=checkout_root,
        )
        if (
            final_resolved != resolved
            or final_raw != raw
            or final_value != receipt_value
            or final_binding != binding
        ):
            raise ValueError("build receipt changed at the completion boundary")
        final_live_authority = reprove_cohort_authority()
        if (
            not isinstance(final_live_authority, Mapping)
            or any(
                final_live_authority.get(key) != live_authority.get(key)
                for key in (
                    "cohort_version",
                    "authority_sha256",
                    "claim_snapshot_sha256",
                    "claim_file_sha256",
                    "claim_chain_sha256",
                    "operation_lock",
                )
            )
        ):
            raise ValueError("build-completion final cohort authority changed")
        observed_at = datetime.now(UTC).isoformat()
        final_reproof = {
            "boundary": BUILD_COMPLETION_FINAL_REPROOF_BOUNDARY,
            "observed_at": observed_at,
            "authority_sha256": final_live_authority["authority_sha256"],
            "claim_snapshot_sha256": final_live_authority[
                "claim_snapshot_sha256"
            ],
            "claim_file_sha256": final_live_authority["claim_file_sha256"],
            "claim_chain_sha256": final_live_authority["claim_chain_sha256"],
        }
        completed_at = datetime.now(UTC).isoformat()
        source = {
            "lab_commit": validated["source"]["lab_commit"],
            "neqo_commit": validated["source"]["neqo_commit"],
            "neqo_gitlink": validated["cohort_allocation"]["neqo_gitlink"],
        }
        completion: dict[str, Any] = {
            "schema_version": BUILD_COMPLETION_SCHEMA_VERSION,
            "artifact_type": BUILD_COMPLETION_ARTIFACT_TYPE,
            "cohort_version": validated["cohort_version"],
            "completed_at": completed_at,
            "receipt": binding,
            "source": source,
            "cohort_authority": expected_authority,
            "transaction": transaction,
            "final_reproof": final_reproof,
        }
        completion["payload_sha256"] = hashlib.sha256(
            _canonical_finite_json_bytes(completion, label="build completion")
        ).hexdigest()
        validate_build_completion_authority(
            completion,
            completion_path=destination,
            receipt_path=resolved,
            receipt_raw=raw,
            receipt_value=receipt_value,
            receipt_stat=receipt_status,
            expected_cohort_version=expected_cohort_version,
            checkout_root=checkout_root,
            require_receipt_stat_identity=True,
        )
        # B is the continuous build-commit capability.  The successful A/L
        # proofs above authorise this already-prepared transaction while B
        # excludes successor cohort allocation/build admission and claim-chain
        # mutation (guardian build paths acquire L -> A -> B; standalone
        # allocators acquire A -> B).  A generic non-build guardian may acquire
        # L without A/B, but the build transaction is already retired and such
        # recovery cannot revoke this create-only receipt/completion identity.
        # Guardian death in the proof-to-link interval therefore has only two
        # completion outcomes: PDEATHSIG prevents the link, or this child
        # completes the authorised link before exiting with B still held.
        encoded = _publish_private_create_only_json(destination, completion)
        completion_resolved, completion_raw, completion_value = (
            load_stable_build_completion(destination)
        )
        if (
            completion_resolved != destination
            or completion_raw != encoded
            or completion_value != completion
        ):
            raise ValueError("published build completion changed after publication")
        _verify_guardian_lifecycle_lock(
            lifecycle_authority,
            guardian_lock=guardian_lock,
        )
        _verify_retired_build_transaction(
            lifecycle_root=lifecycle_root,
            retired_transaction_root=retired_transaction_root,
            receipt_path=resolved,
            cohort_version=validated["cohort_version"],
            guardian_lock=guardian_lock,
            lifecycle_authority=lifecycle_authority,
        )
        projected = validate_build_completion_authority(
            completion_value,
            completion_path=completion_resolved,
            receipt_path=resolved,
            receipt_raw=raw,
            receipt_value=receipt_value,
            receipt_stat=receipt_status,
            expected_cohort_version=expected_cohort_version,
            checkout_root=checkout_root,
            require_receipt_stat_identity=True,
        )
    return projected


def _regular_file(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is not a regular file")
    return path.resolve()


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qcsd-build-storage")
    actions = parser.add_subparsers(dest="action", required=True)
    buildx_observation = actions.add_parser("buildx-observation")
    buildx_observation.add_argument("--plugins-json", type=Path, required=True)
    buildx_observation.add_argument("--version-output", type=Path, required=True)
    observation = actions.add_parser("observation")
    observation.add_argument("--boundary", choices=BUILD_HOST_STORAGE_BOUNDARIES, required=True)
    observation.add_argument("--probe-path", type=Path, required=True)
    receipt = actions.add_parser("receipt")
    receipt.add_argument("path", type=Path)
    receipt.add_argument("--expected-cohort", type=int)
    receipt.add_argument("--probe-path", type=Path, required=True)
    receipt.add_argument("--allow-historical", action="store_true")
    receipt_binding = actions.add_parser("receipt-binding")
    receipt_binding.add_argument("path", type=Path)
    receipt_binding.add_argument("--expected-cohort", type=int, required=True)
    receipt_binding.add_argument("--probe-path", type=Path, required=True)
    transaction_binding = actions.add_parser("transaction-binding")
    transaction_binding.add_argument("path", type=Path)
    transaction_binding.add_argument("--expected-receipt", type=Path, required=True)
    transaction_binding.add_argument("--expected-cohort", type=int, required=True)
    transaction_binding.add_argument("--expected-lease-nonce", required=True)
    transaction_binding.add_argument("--probe-path", type=Path, required=True)
    publish_completion = actions.add_parser("publish-completion")
    publish_completion.add_argument("path", type=Path)
    publish_completion.add_argument("--completion-path", type=Path, required=True)
    publish_completion.add_argument("--expected-cohort", type=int, required=True)
    publish_completion.add_argument("--probe-path", type=Path, required=True)
    publish_completion.add_argument("--receipt-binding-json", required=True)
    publish_completion.add_argument("--transaction-binding-json", required=True)
    publish_completion.add_argument("--held-lock-owner-pid", type=int, required=True)
    publish_completion.add_argument("--held-lock-owner-start", type=int, required=True)
    publish_completion.add_argument("--held-lock-guardian-pid", type=int, required=True)
    publish_completion.add_argument("--held-lock-guardian-start", type=int, required=True)
    publish_completion.add_argument("--held-lock-guardian-fd", type=int, required=True)
    publish_completion.add_argument("--held-lock-path", required=True)
    publish_completion.add_argument("--held-lock-device", type=int, required=True)
    publish_completion.add_argument("--held-lock-inode", type=int, required=True)
    publish_completion.add_argument("--held-lock-parent-device", type=int, required=True)
    publish_completion.add_argument("--held-lock-parent-inode", type=int, required=True)
    publish_completion.add_argument("--held-lock-cohort-version", type=int, required=True)
    publish_completion.add_argument("--lifecycle-lock-path", required=True)
    publish_completion.add_argument("--lifecycle-lock-device", type=int, required=True)
    publish_completion.add_argument("--lifecycle-lock-inode", type=int, required=True)
    publish_completion.add_argument(
        "--lifecycle-lock-parent-device", type=int, required=True
    )
    publish_completion.add_argument(
        "--lifecycle-lock-parent-inode", type=int, required=True
    )
    publish_completion.add_argument("--lifecycle-lease-nonce", required=True)
    publish_completion.add_argument("--retired-transaction-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.action == "buildx-observation":
            metadata_raw = _read_stable_regular_file(
                arguments.plugins_json,
                label="Docker client plugin metadata",
                maximum_bytes=1024 * 1024,
            )
            version_raw = _read_stable_regular_file(
                arguments.version_output,
                label="Docker buildx version output",
                maximum_bytes=4096,
            )
            try:
                plugin_metadata = json.loads(
                    metadata_raw.decode("utf-8"),
                    object_pairs_hook=_unique_json_object,
                    parse_constant=_invalid_json_constant,
                )
            except (UnicodeError, json.JSONDecodeError) as error:
                raise ValueError("Docker client plugin metadata is not valid JSON") from error
            captured = capture_buildx_observation(
                plugin_metadata,
                version_output=_one_version_output_line(version_raw),
            )
            print(json.dumps(captured, sort_keys=True, separators=(",", ":")))
            return 0
        probe_path = _regular_file(arguments.probe_path, label="storage probe")
        probe_sha256 = _sha256_file(probe_path)
        if arguments.action == "observation":
            value = json.load(sys.stdin)
            validated = validate_build_host_storage_observation(
                value,
                expected_boundary=arguments.boundary,
                expected_probe_sha256=probe_sha256,
            )
            print(json.dumps(validated, sort_keys=True, separators=(",", ":")))
            print(validated["data_vhd_path"])
            print(validated["backing_volume_unique_id"])
            print(validated["available_bytes"])
            print(
                _canonical_digest(
                    {
                        key: validated[key]
                        for key in (
                            "probe_sha256",
                            "location_source",
                            "data_vhd_path",
                            "backing_volume_unique_id",
                            "drive_letter",
                            "file_system",
                        )
                    }
                )
            )
            return 0
        checkout_root = probe_path.parents[1]
        if arguments.action == "transaction-binding":
            binding = capture_build_transaction_binding(
                arguments.path,
                expected_receipt=arguments.expected_receipt,
                expected_checkout_root=checkout_root,
                expected_cohort_version=arguments.expected_cohort,
                expected_lease_nonce=arguments.expected_lease_nonce,
            )
            print(json.dumps(binding, sort_keys=True, separators=(",", ":")))
            return 0
        if arguments.action == "publish-completion":
            try:
                expected_binding = json.loads(
                    arguments.receipt_binding_json,
                    object_pairs_hook=_unique_json_object,
                    parse_constant=_invalid_json_constant,
                )
                expected_transaction_binding = json.loads(
                    arguments.transaction_binding_json,
                    object_pairs_hook=_unique_json_object,
                    parse_constant=_invalid_json_constant,
                )
            except json.JSONDecodeError as error:
                raise ValueError("build-completion publication input is invalid JSON") from error
            cohort_module = _cohort_allocation_module()
            guardian_lock = cohort_module.GuardianLockAuthority(
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
            lifecycle_authority = {
                "path": arguments.lifecycle_lock_path,
                "device": arguments.lifecycle_lock_device,
                "inode": arguments.lifecycle_lock_inode,
                "parent_device": arguments.lifecycle_lock_parent_device,
                "parent_inode": arguments.lifecycle_lock_parent_inode,
                "lease_nonce": arguments.lifecycle_lease_nonce,
            }
            publish_build_completion(
                arguments.path,
                expected_receipt_binding=expected_binding,
                expected_transaction_binding=expected_transaction_binding,
                expected_cohort_version=arguments.expected_cohort,
                expected_probe_sha256=probe_sha256,
                checkout_root=checkout_root,
                expected_build_root=checkout_root,
                guardian_lock=guardian_lock,
                lifecycle_authority=lifecycle_authority,
                retired_transaction_root=arguments.retired_transaction_root,
                completion_path=arguments.completion_path,
            )
            # No output follows the authoritative create-only publication.  A
            # caller may be killed after it and still correctly discover
            # success by validating the completion file.
            os._exit(0)
        receipt_path, raw, receipt_value, receipt_status = (
            load_stable_build_execution_with_stat(arguments.path)
        )
        validated = validate_build_execution_envelope(
            receipt_value,
            expected_cohort_version=arguments.expected_cohort,
            expected_probe_sha256=probe_sha256,
            checkout_root=checkout_root,
            expected_build_root=checkout_root,
        )
        if arguments.action == "receipt-binding":
            if validated["schema_version"] != 5:
                raise ValueError("transaction binding requires a schema-5 build receipt")
            binding = build_execution_receipt_binding(
                receipt_path=receipt_path,
                receipt_raw=raw,
                receipt_value=receipt_value,
                receipt_stat=receipt_status,
                cohort_version=validated["cohort_version"],
                checkout_root=checkout_root,
            )
            print(json.dumps(binding, sort_keys=True, separators=(",", ":")))
            return 0
        completion_output: tuple[str, str, str] | None = None
        if validated["schema_version"] == 5:
            receipt_path, raw, receipt_value, validated, completion = (
                load_validated_build_execution(
                    receipt_path,
                    expected_cohort_version=arguments.expected_cohort,
                    expected_probe_sha256=probe_sha256,
                    checkout_root=checkout_root,
                    expected_build_root=checkout_root,
                    require_current=True,
                )
            )
            if completion is None:
                raise ValueError("current build completion is absent")
            completion_path = build_completion_path(
                receipt_path, validated["cohort_version"]
            )
            _completion_resolved, completion_raw, _completion_value = (
                load_stable_build_completion(completion_path)
            )
            completion_output = (
                f"artifacts/buflo-study/{completion_path.name}",
                hashlib.sha256(completion_raw).hexdigest(),
                completion["payload_sha256"],
            )
        elif not arguments.allow_historical:
            raise ValueError(
                "current build admission requires schema 5 and its completion"
            )
        print(hashlib.sha256(raw).hexdigest())
        for target in ("collection", "prepare", "reference"):
            print(validated["image_ids"][target])
        if completion_output is not None:
            for field in completion_output:
                print(field)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, f"qcsd-lab build evidence is invalid: {error}\n")


if __name__ == "__main__":
    raise SystemExit(_main())
