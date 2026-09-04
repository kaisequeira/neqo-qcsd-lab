"""Fail-closed host-storage evidence for no-cache study builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

BUILD_EXECUTION_ARTIFACT_TYPE = "qcsd-buflo-study-no-cache-build-execution"
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
_ROLE_PROVENANCE_KEYS = {"schema_version", "sources", "build_inputs"}
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_REPO_DIGEST_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
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
    required = _BUILD_V1_KEYS | (
        {"host_storage_preflight", "role_provenance"}
        if schema_version in {2, 3}
        else set()
    )
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or type(schema_version) is not int
        or schema_version not in {1, 2, 3}
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
    if schema_version in {2, 3}:
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
    if schema_version in {2, 3} and (
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
        if schema_version in {2, 3} and record["tag"] != BUILD_IMAGE_TAGS[target]:
            raise ValueError(f"no-cache build {target} image role tag is invalid")
        image_ids[target] = record["id"]
    if schema_version in {2, 3} and len(set(image_ids.values())) != len(image_ids):
        raise ValueError("no-cache build image roles do not have distinct immutable IDs")

    commands = value["commands"]
    if not isinstance(commands, list) or len(commands) != 3:
        raise ValueError("no-cache build command inventory is incomplete")
    recorded_build_root: PurePosixPath | None = None
    for target, command in zip(("collection", "prepare", "reference"), commands, strict=True):
        prefix = ["docker"]
        if schema_version == 2:
            prefix.extend(["--context", docker["context"]])
        elif schema_version == 3:
            prefix.extend(["--host", docker["endpoint"]])
        prefix.extend(["build", "--pull", "--no-cache"])
        argv = command.get("argv") if isinstance(command, Mapping) else None
        iidfile_value: str | None = None
        iidfile: PurePosixPath | None = None
        if schema_version in {2, 3} and isinstance(argv, list) and len(argv) >= len(prefix) + 2:
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
                schema_version in {2, 3}
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
        schema_version in {2, 3}
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
    if schema_version in {2, 3}:
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
    return {
        "schema_version": schema_version,
        "cohort_version": cohort_version,
        "image_ids": image_ids,
        "source": dict(source),
        "role_provenance": role_provenance,
        "host_storage_preflight": host_storage_preflight,
    }


def _regular_file(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is not a regular file")
    return path.resolve()


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qcsd-build-storage")
    actions = parser.add_subparsers(dest="action", required=True)
    observation = actions.add_parser("observation")
    observation.add_argument("--boundary", choices=BUILD_HOST_STORAGE_BOUNDARIES, required=True)
    observation.add_argument("--probe-path", type=Path, required=True)
    receipt = actions.add_parser("receipt")
    receipt.add_argument("path", type=Path)
    receipt.add_argument("--expected-cohort", type=int)
    receipt.add_argument("--probe-path", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
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
        receipt_path = _regular_file(arguments.path, label="build execution receipt")
        raw = receipt_path.read_bytes()
        validated = validate_build_execution_envelope(
            json.loads(raw),
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
