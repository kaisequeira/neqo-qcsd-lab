"""Fail-closed host-storage evidence for no-cache study builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import posixpath
import re
import stat
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

BUILD_EXECUTION_ARTIFACT_TYPE = "qcsd-buflo-study-no-cache-build-execution"
BUILD_EXECUTION_MAX_BYTES = 16 * 1024 * 1024
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


def _read_stable_regular_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int | None = None,
) -> bytes:
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
        directory_path_stable = _stat_identity(root_after) == _stat_identity(
            root_path_after
        ) and all(
            _stat_identity(os.fstat(child_descriptor))
            == _stat_identity(
                os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
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


def load_stable_build_execution(path: Path) -> tuple[Path, bytes, Any]:
    """Read one build receipt once, rejecting symlinks and duplicate JSON keys."""

    candidate = Path(os.path.abspath(path))
    if candidate.is_symlink():
        raise ValueError("build execution receipt cannot be a symlink")
    try:
        resolved_before = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError("build execution receipt path cannot be resolved") from error
    if resolved_before != candidate:
        raise ValueError("build execution receipt path contains a symlink")
    raw = _read_stable_regular_file(
        candidate,
        label="build execution receipt",
        maximum_bytes=BUILD_EXECUTION_MAX_BYTES,
    )
    try:
        resolved_after = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError("build execution receipt path cannot be resolved") from error
    if resolved_after != resolved_before:
        raise ValueError("build execution receipt path changed while it was read")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("build execution receipt is not unique-key UTF-8 JSON") from error
    return resolved_after, raw, value


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
    if type(schema_version) is int and schema_version in {2, 3, 4}:
        required |= {"host_storage_preflight", "role_provenance"}
    if schema_version == 4:
        required |= {"buildx"}
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or type(schema_version) is not int
        or schema_version not in {1, 2, 3, 4}
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
    if schema_version in {2, 3, 4}:
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
    if schema_version in {2, 3, 4} and (
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
        if schema_version in {2, 3, 4} and record["tag"] != BUILD_IMAGE_TAGS[target]:
            raise ValueError(f"no-cache build {target} image role tag is invalid")
        image_ids[target] = record["id"]
    if schema_version in {2, 3, 4} and len(set(image_ids.values())) != len(image_ids):
        raise ValueError("no-cache build image roles do not have distinct immutable IDs")

    commands = value["commands"]
    if not isinstance(commands, list) or len(commands) != 3:
        raise ValueError("no-cache build command inventory is incomplete")
    recorded_build_root: PurePosixPath | None = None
    for target, command in zip(("collection", "prepare", "reference"), commands, strict=True):
        prefix = ["docker"]
        if schema_version == 2:
            prefix.extend(["--context", docker["context"]])
        elif schema_version in {3, 4}:
            prefix.extend(["--host", docker["endpoint"]])
        prefix.extend(["build", "--pull", "--no-cache"])
        argv = command.get("argv") if isinstance(command, Mapping) else None
        iidfile_value: str | None = None
        iidfile: PurePosixPath | None = None
        if schema_version in {2, 3, 4} and isinstance(argv, list) and len(argv) >= len(prefix) + 2:
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
                schema_version in {2, 3, 4}
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
        schema_version in {2, 3, 4}
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
    if schema_version in {2, 3, 4}:
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
            if not (
                observation_times[0]
                <= started
                < observation_times[1]
                < observation_times[2]
                < observation_times[3]
                <= finished
            ):
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
    if schema_version == 4:
        validated["buildx"] = validate_buildx_provenance(
            value["buildx"], started_at=started, finished_at=finished
        )
    return validated


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
        receipt_path, raw, receipt_value = load_stable_build_execution(arguments.path)
        validated = validate_build_execution_envelope(
            receipt_value,
            expected_cohort_version=arguments.expected_cohort,
            expected_probe_sha256=probe_sha256,
            checkout_root=probe_path.parents[1],
            expected_build_root=probe_path.parents[1],
        )
        print(hashlib.sha256(raw).hexdigest())
        for target in ("collection", "prepare", "reference"):
            print(validated["image_ids"][target])
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, f"qcsd-lab build evidence is invalid: {error}\n")


if __name__ == "__main__":
    raise SystemExit(_main())
