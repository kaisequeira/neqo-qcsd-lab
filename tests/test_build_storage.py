from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from qcsd_lab import build_storage


GIB = 1024**3
PROBE_SHA256 = "1" * 64
VOLUME_ID = "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\"
DATA_VHD_PATH = "C:\\Users\\kai\\AppData\\Local\\Docker\\wsl\\data\\ext4.vhdx"
BOUNDARY_TIMES = (
    ("before-collection", "2026-09-01T00:00:00+00:00"),
    ("before-prepare", "2026-09-01T00:00:02+00:00"),
    ("before-reference", "2026-09-01T00:00:03+00:00"),
    ("after-reference", "2026-09-01T00:00:04+00:00"),
)


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _rehash(value: dict[str, Any]) -> dict[str, Any]:
    value.pop("payload_sha256", None)
    value["payload_sha256"] = _canonical_digest(value)
    return value


def _rehash_buildx_receipt(value: dict[str, Any]) -> dict[str, Any]:
    identity_sha256 = _canonical_digest(value["buildx"]["identity"])
    for observation in value["buildx"]["observations"]:
        observation["identity_sha256"] = identity_sha256
    return _rehash(value)


def _observation(
    boundary: str,
    observed_at: str,
    *,
    available_bytes: int = 128 * GIB,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "probe": build_storage.BUILD_HOST_STORAGE_PROBE,
        "probe_sha256": PROBE_SHA256,
        "boundary": boundary,
        "observed_at": observed_at,
        "location_source": "wsl-lxss-docker-desktop-data",
        "data_vhd_path": DATA_VHD_PATH,
        "data_vhd_file_length_bytes": 512 * GIB,
        "backing_volume_unique_id": VOLUME_ID,
        "drive_letter": "C",
        "file_system": "NTFS",
        "health_status": "Healthy",
        "operational_status": ["OK"],
        "total_bytes": 1024 * GIB,
        "available_bytes": available_bytes,
    }


def _wsl_preflight(*, available_bytes: int = 128 * GIB) -> dict[str, Any]:
    observations = [
        _observation(boundary, observed_at, available_bytes=available_bytes)
        for boundary, observed_at in BOUNDARY_TIMES
    ]
    return {
        "schema_version": 1,
        "applicable": True,
        "platform": "windows-wsl2",
        "platform_detection": {
            "schema_version": 1,
            "probe": "wsl-multi-signal-v1",
            "kernel_release": "6.6.87.2-microsoft-standard-WSL2",
            "proc_version": "Linux version 6.6.87.2-microsoft-standard-WSL2",
            "wsl_interop_env_present": True,
            "wsl_distro_name_env_present": True,
            "run_wsl_directory_present": True,
        },
        "policy": build_storage.BUILD_HOST_STORAGE_POLICY,
        "required_available_bytes": build_storage.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES,
        "observations": observations,
        "minimum_available_bytes": available_bytes,
        "passed": True,
    }


def _non_wsl_preflight() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "applicable": False,
        "platform": "other-host",
        "platform_detection": {
            "schema_version": 1,
            "probe": "wsl-multi-signal-v1",
            "kernel_release": "6.8.0-79-generic",
            "proc_version": "Linux version 6.8.0-79-generic",
            "wsl_interop_env_present": False,
            "wsl_distro_name_env_present": False,
            "run_wsl_directory_present": False,
        },
        "policy": build_storage.BUILD_HOST_STORAGE_POLICY,
        "required_available_bytes": build_storage.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES,
        "observations": [],
        "minimum_available_bytes": None,
        "passed": True,
    }


def _buildx_provenance() -> dict[str, Any]:
    reported_path = "/usr/local/lib/docker/cli-plugins/docker-buildx"
    symlink_target = (
        "/mnt/wsl/docker-desktop/cli-tools/usr/local/lib/docker/cli-plugins/docker-buildx"
    )
    version = "v0.29.1-desktop.1"
    commit = "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
    identity = {
        "selection_source": "docker-info-client-plugin-metadata-v1",
        "plugin_name": "buildx",
        "plugin_vendor": "Docker Inc.",
        "metadata_schema_version": "0.1.0",
        "short_description": "Docker Buildx",
        "reported_plugin_version": version,
        "reported_plugin_path": reported_path,
        "plugin": {
            "path": reported_path,
            "symlink_target": symlink_target,
            "dev": 2096,
            "inode": 280747,
            "uid": 0,
            "gid": 0,
            "mode": stat.S_IFLNK | 0o777,
            "nlink": 1,
            "size": len(symlink_target.encode()),
            "mtime_ns": 1_788_582_497_670_041_680,
            "ctime_ns": 1_788_582_497_670_041_680,
        },
        "resolved": {
            "path": symlink_target,
            "dev": 1792,
            "inode": 2122,
            "uid": 0,
            "gid": 0,
            "mode": stat.S_IFREG | 0o755,
            "nlink": 1,
            "size": 65_994_936,
            "mtime_ns": 1_763_156_518_000_000_000,
            "ctime_ns": 1_763_166_552_000_000_000,
            "sha256": "9" * 64,
        },
        "version_output": f"github.com/docker/buildx {version} {commit}",
        "version": version,
        "commit": commit,
    }
    identity_sha256 = _canonical_digest(identity)
    return {
        "schema_version": 1,
        "policy": "docker-selected-buildx-binary-stability-v1",
        "identity": identity,
        "observations": [
            {
                "boundary": boundary,
                "observed_at": observed_at,
                "identity_sha256": identity_sha256,
            }
            for boundary, observed_at in (
                ("before-collection", "2026-09-01T00:00:01.100000+00:00"),
                ("after-collection", "2026-09-01T00:00:02+00:00"),
                ("after-prepare", "2026-09-01T00:00:03+00:00"),
                ("after-reference", "2026-09-01T00:00:04.900000+00:00"),
            )
        ],
        "passed": True,
    }


def _docker_buildx_metadata(path: str) -> dict[str, str]:
    return {
        "Name": "buildx",
        "Path": path,
        "SchemaVersion": "0.1.0",
        "ShortDescription": "Docker Buildx",
        "Vendor": "Docker Inc.",
        "Version": "v0.29.1-desktop.1",
    }


def _build_receipt(
    *,
    schema_version: int,
    host_storage_preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    image_ids = {
        "collection": "sha256:" + "a" * 64,
        "prepare": "sha256:" + "b" * 64,
        "reference": "sha256:" + "c" * 64,
    }
    docker: dict[str, Any] = {
        "client_version": "29.0.1",
        "server_version": "29.0.1",
    }
    if schema_version in {2, 3, 4}:
        docker.update(
            {
                "context": "default",
                "endpoint": "unix:///var/run/docker.sock",
                "server_id": "0123456789AB",
                "server_name": "docker-desktop",
                "server_operating_system": (
                    "Docker Desktop 4.51.0"
                    if host_storage_preflight and host_storage_preflight["applicable"]
                    else "Ubuntu 24.04"
                ),
                "server_os_type": "linux",
                "server_architecture": "x86_64",
            }
        )
    build_root = "/workspace/neqo-qcsd-lab"
    commands = []
    for target in ("collection", "prepare", "reference"):
        tag = (
            build_storage.BUILD_IMAGE_TAGS[target]
            if schema_version in {2, 3, 4}
            else f"neqo-qcsd-lab-{target}:test"
        )
        argv = ["docker"]
        if schema_version == 2:
            argv.extend(["--context", docker["context"]])
        elif schema_version in {3, 4}:
            argv.extend(["--host", docker["endpoint"]])
        argv.extend(["build", "--pull", "--no-cache"])
        if schema_version in {2, 3, 4}:
            argv.extend(
                [
                    "--iidfile",
                    (f"{build_root}/artifacts/buflo-study/.build-iids-v34.ABC123/{target}.iid"),
                ]
            )
        argv.extend(
            [
                "--target",
                target,
                "--tag",
                tag,
                "--file",
                f"{build_root}/Dockerfile",
                build_root,
            ]
        )
        commands.append(
            {
                "target": target,
                "argv": argv,
                "exit_code": 0,
                "image_id": image_ids[target],
            }
        )
    value: dict[str, Any] = {
        "schema_version": schema_version,
        "artifact_type": build_storage.BUILD_EXECUTION_ARTIFACT_TYPE,
        "cohort_version": 34,
        "started_at": "2026-09-01T00:00:01+00:00",
        "finished_at": "2026-09-01T00:00:05+00:00",
        "duration_seconds": 4.0,
        "docker": docker,
        "commands": commands,
        "images": {
            target: {
                "tag": (
                    build_storage.BUILD_IMAGE_TAGS[target]
                    if schema_version in {2, 3, 4}
                    else f"neqo-qcsd-lab-{target}:test"
                ),
                "id": image_ids[target],
                "repo_digests": [],
            }
            for target in ("collection", "prepare", "reference")
        },
        "source": {
            "image_digest": image_ids["collection"],
            "lab_commit": "d" * 40,
            "lab_dirty": False,
            "lab_patch_sha256": build_storage.BUILD_EMPTY_SHA256,
            "neqo_commit": "e" * 40,
            "neqo_pinned_commit": "e" * 40,
            "neqo_dirty": False,
            "neqo_patch_sha256": build_storage.BUILD_EMPTY_SHA256,
        },
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": build_storage.BUILD_RUST_BASE_IMAGE,
            "debian_base_image": build_storage.BUILD_DEBIAN_BASE_IMAGE,
            "uv_lock_sha256": "f" * 64,
            "cargo_lock_sha256": "0" * 64,
        },
        "dockerfile_sha256": "d" * 64,
        "cache_policy": {
            "pull": True,
            "no_cache": True,
            "scope": ("Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only"),
        },
    }
    if schema_version in {2, 3, 4}:
        assert host_storage_preflight is not None
        value["host_storage_preflight"] = host_storage_preflight
        value["role_provenance"] = {
            "schema_version": 1,
            "sources": {
                target: {**value["source"], "image_digest": image_ids[target]}
                for target in ("collection", "prepare", "reference")
            },
            "build_inputs": {
                "collection": dict(value["build_inputs"]),
                "prepare": dict(value["build_inputs"]),
                "reference": None,
            },
        }
    if schema_version == 4:
        value["buildx"] = _buildx_provenance()
    return _rehash(value)


def _validate_observation(value: dict[str, Any]) -> dict[str, Any]:
    return build_storage.validate_build_host_storage_observation(
        value,
        expected_boundary="before-collection",
        expected_probe_sha256=PROBE_SHA256,
    )


def test_exact_schema_1_build_receipt_remains_compatible() -> None:
    value = _build_receipt(schema_version=1)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256="f" * 64,
    )

    assert validated == {
        "schema_version": 1,
        "cohort_version": 34,
        "image_ids": {
            "collection": "sha256:" + "a" * 64,
            "prepare": "sha256:" + "b" * 64,
            "reference": "sha256:" + "c" * 64,
        },
        "source": value["source"],
        "role_provenance": None,
        "host_storage_preflight": None,
    }


def test_schema_one_build_command_root_remains_relocatable() -> None:
    value = _build_receipt(schema_version=1)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_build_root=Path("/a/different/current/checkout"),
    )

    assert validated["schema_version"] == 1


@pytest.mark.parametrize(
    "replacement",
    (
        "neqo-qcsd-lab-collection:local",
        "docker.io/library/neqo-qcsd-lab-prepare:local",
        "neqo-qcsd-lab-prepare:other",
    ),
)
def test_schema_two_rejects_rehashed_noncanonical_image_role_tags(
    replacement: str,
) -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["images"]["prepare"]["tag"] = replacement
    tag_index = value["commands"][1]["argv"].index("--tag") + 1
    value["commands"][1]["argv"][tag_index] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="prepare image role tag"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_two_rejects_rehashed_duplicate_immutable_role_ids() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    duplicate = value["images"]["collection"]["id"]
    value["images"]["prepare"]["id"] = duplicate
    value["commands"][1]["image_id"] = duplicate
    _rehash(value)

    with pytest.raises(ValueError, match="distinct immutable IDs"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_two_rejects_rehashed_cross_role_source_snapshot() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["role_provenance"]["sources"]["reference"]["lab_commit"] = "1" * 40
    _rehash(value)

    with pytest.raises(ValueError, match="different source snapshots"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_two_rejects_rehashed_cross_role_build_inputs() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["role_provenance"]["build_inputs"]["prepare"]["uv_lock_sha256"] = "1" * 64
    _rehash(value)

    with pytest.raises(ValueError, match="different build inputs"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    "replacement",
    (
        "/tmp/prepare.iid",
        "/workspace/neqo-qcsd-lab/artifacts/buflo-study/../prepare.iid",
        ("/workspace/neqo-qcsd-lab/artifacts/buflo-study/.build-iids-v35.ABC123/prepare.iid"),
        ("/workspace/neqo-qcsd-lab/artifacts/buflo-study/.build-iids-v34.A/prepare.iid"),
    ),
)
def test_schema_two_rejects_rehashed_unbound_iid_paths(replacement: str) -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    iidfile_index = value["commands"][1]["argv"].index("--iidfile") + 1
    value["commands"][1]["argv"][iidfile_index] = replacement
    _rehash(value)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        build_storage.validate_build_execution_envelope(value)


def test_valid_wsl_schema_2_binds_all_storage_and_docker_evidence() -> None:
    preflight = _wsl_preflight()
    value = _build_receipt(schema_version=2, host_storage_preflight=preflight)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["schema_version"] == 2
    assert validated["host_storage_preflight"] == preflight
    assert validated["host_storage_preflight"] is not preflight


def test_valid_non_wsl_schema_2_records_exact_non_applicable_evidence() -> None:
    preflight = _non_wsl_preflight()
    value = _build_receipt(schema_version=2, host_storage_preflight=preflight)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["host_storage_preflight"] == preflight


def test_valid_schema_3_binds_the_executed_pinned_host_build_argv() -> None:
    preflight = _non_wsl_preflight()
    value = _build_receipt(schema_version=3, host_storage_preflight=preflight)

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["schema_version"] == 3
    assert all(
        command["argv"][:3] == ["docker", "--host", "unix:///var/run/docker.sock"]
        for command in value["commands"]
    )


def test_valid_schema_4_projects_exact_four_boundary_buildx_provenance() -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())

    validated = build_storage.validate_build_execution_envelope(
        value,
        expected_cohort_version=34,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["schema_version"] == 4
    assert validated["buildx"] == value["buildx"]
    assert validated["buildx"] is not value["buildx"]
    assert [row["boundary"] for row in validated["buildx"]["observations"]] == [
        "before-collection",
        "after-collection",
        "after-prepare",
        "after-reference",
    ]


@pytest.mark.parametrize(
    ("field_path", "replacement", "message"),
    (
        (("buildx", "identity", "plugin", "mode"), True, "stat identity"),
        (("buildx", "identity", "resolved", "sha256"), "A" * 64, "safe root-owned"),
        (("buildx", "identity", "reported_plugin_path"), "docker-buildx", "canonical path"),
        (("buildx", "identity", "reported_plugin_version"), "v0.29.0", "version binding"),
        (("buildx", "observations", 2, "boundary"), "after-reference", "observation"),
        (("buildx", "observations", 1, "observed_at"), True, "observation"),
    ),
)
def test_schema_4_rejects_rehashed_malformed_buildx_data(
    field_path: tuple[str | int, ...], replacement: Any, message: str
) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    target: Any = value
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = replacement
    _rehash_buildx_receipt(value)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(value)


def test_schema_4_rejects_extra_buildx_field_and_boundary_reordering() -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["unexpected"] = None
    _rehash(value)
    with pytest.raises(ValueError, match="provenance schema"):
        build_storage.validate_build_execution_envelope(value)

    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["identity"]["unexpected"] = None
    _rehash_buildx_receipt(value)
    with pytest.raises(ValueError, match="identity schema"):
        build_storage.validate_build_execution_envelope(value)

    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["observations"][1]["observed_at"] = value["buildx"]["observations"][0][
        "observed_at"
    ]
    _rehash(value)
    with pytest.raises(ValueError, match="strictly increasing"):
        build_storage.validate_build_execution_envelope(value)

    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["observations"][2]["identity_sha256"] = "1" * 64
    _rehash(value)
    with pytest.raises(ValueError, match="observation"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_4_accepts_a_direct_regular_system_plugin() -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    identity = value["buildx"]["identity"]
    identity["resolved"]["path"] = identity["reported_plugin_path"]
    identity["plugin"] = {
        "path": identity["reported_plugin_path"],
        "symlink_target": None,
        **{key: identity["resolved"][key] for key in build_storage._BUILDX_STAT_KEYS},
    }
    _rehash_buildx_receipt(value)

    validated = build_storage.validate_build_execution_envelope(value)

    assert validated["buildx"]["identity"]["plugin"]["symlink_target"] is None


def test_build_receipt_schema_selection_is_validation_order_independent() -> None:
    values = (
        _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight()),
        _build_receipt(schema_version=1),
        _build_receipt(schema_version=3, host_storage_preflight=_non_wsl_preflight()),
        _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight()),
    )

    assert [
        build_storage.validate_build_execution_envelope(value)["schema_version"] for value in values
    ] == [4, 1, 3, 4]


def test_build_receipt_schema4_requires_buildx_and_schema3_forbids_it() -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value.pop("buildx")
    _rehash(value)
    with pytest.raises(ValueError, match="receipt schema"):
        build_storage.validate_build_execution_envelope(value)

    value = _build_receipt(schema_version=3, host_storage_preflight=_non_wsl_preflight())
    value["buildx"] = _buildx_provenance()
    _rehash(value)
    with pytest.raises(ValueError, match="receipt schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("schema_version", ([], {}))
def test_build_receipt_rejects_unhashable_schema_values_as_invalid(
    schema_version: object,
) -> None:
    value = _build_receipt(schema_version=1)
    value["schema_version"] = schema_version
    _rehash(value)

    with pytest.raises(ValueError, match="receipt schema"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    (
        ("plugin", "uid", 1),
        ("plugin", "gid", 1),
        ("plugin", "nlink", 2),
        ("resolved", "uid", 1),
        ("resolved", "gid", 1),
        ("resolved", "nlink", 2),
        ("resolved", "mode", stat.S_IFREG | 0o644),
        ("resolved", "mode", stat.S_IFREG | stat.S_ISUID | 0o755),
        ("resolved", "mode", stat.S_IFREG | stat.S_ISGID | 0o755),
        ("resolved", "mode", stat.S_IFREG | 0o775),
        ("resolved", "mode", stat.S_IFREG | 0o757),
    ),
)
def test_schema4_rejects_unsafe_buildx_stat_and_mode_data(
    section: str, field: str, replacement: int
) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["identity"][section][field] = replacement
    _rehash_buildx_receipt(value)

    with pytest.raises(ValueError, match="safe root-owned executable"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ("plugin-path", "symlink-target", "resolved-path"))
def test_schema4_rejects_buildx_lexical_and_resolved_path_mismatch(mutation: str) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    identity = value["buildx"]["identity"]
    if mutation == "plugin-path":
        identity["plugin"]["path"] = "/usr/lib/docker/cli-plugins/docker-buildx"
        message = "path binding"
    elif mutation == "symlink-target":
        replacement = "/opt/docker/buildx-v0.29.1"
        identity["plugin"]["symlink_target"] = replacement
        identity["plugin"]["size"] = len(replacement.encode())
        message = "symlink target differs"
    else:
        identity["resolved"]["path"] = "/opt/docker/buildx-v0.29.1"
        message = "symlink target differs"
    _rehash_buildx_receipt(value)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        (
            "version_output",
            "github.com/docker/buildx v0.29.1-desktop.1 28f6246ff24e2c05095e8741e48c48dcb2d3b4bc\r",
        ),
        (
            "version_output",
            "github.com/docker/buildx v0.29.1-desktop.1 "
            "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc\nsecond line",
        ),
        ("version", "v0.29.0"),
        ("commit", "F" * 40),
    ),
)
def test_schema4_rejects_nonexact_or_mismatched_buildx_version(
    field: str, replacement: str
) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["identity"][field] = replacement
    _rehash_buildx_receipt(value)

    with pytest.raises(ValueError, match="version binding"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("index", "observed_at"),
    (
        (0, "2026-09-01T00:00:00.900000+00:00"),
        (3, "2026-09-01T00:00:05.100000+00:00"),
    ),
)
def test_schema4_rejects_buildx_observation_outside_build(index: int, observed_at: str) -> None:
    value = _build_receipt(schema_version=4, host_storage_preflight=_non_wsl_preflight())
    value["buildx"]["observations"][index]["observed_at"] = observed_at
    _rehash(value)

    with pytest.raises(ValueError, match="outside the build"):
        build_storage.validate_build_execution_envelope(value)


def test_buildx_provenance_timing_endpoints_are_both_or_neither() -> None:
    provenance = _buildx_provenance()
    started = datetime.fromisoformat("2026-09-01T00:00:01+00:00")
    finished = datetime.fromisoformat("2026-09-01T00:00:05+00:00")

    assert build_storage.validate_buildx_provenance(provenance) == provenance
    assert (
        build_storage.validate_buildx_provenance(
            provenance,
            started_at=started,
            finished_at=finished,
        )
        == provenance
    )
    with pytest.raises(ValueError, match="both build endpoints"):
        build_storage.validate_buildx_provenance(provenance, started_at=started)
    with pytest.raises(ValueError, match="both build endpoints"):
        build_storage.validate_buildx_provenance(provenance, finished_at=finished)


@pytest.mark.parametrize("mutation", ("missing", "extra", "duplicate", "absent"))
def test_capture_rejects_nonexact_or_nonunique_docker_buildx_metadata(
    mutation: str,
) -> None:
    metadata = _docker_buildx_metadata("/usr/local/lib/docker/cli-plugins/docker-buildx")
    plugins = [metadata]
    if mutation == "missing":
        metadata.pop("Vendor")
        message = "exact healthy schema"
    elif mutation == "extra":
        metadata["Err"] = "plugin failed"
        message = "exact healthy schema"
    elif mutation == "duplicate":
        plugins.append(dict(metadata))
        message = "exactly one buildx"
    else:
        metadata["Name"] = "compose"
        message = "exactly one buildx"

    with pytest.raises(ValueError, match=message):
        build_storage.capture_buildx_observation(
            plugins,
            version_output=(
                "github.com/docker/buildx v0.29.1-desktop.1 "
                "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
            ),
        )


@pytest.mark.parametrize(
    "raw",
    (
        b"github.com/docker/buildx v0.29.1 deadbeef\r\n",
        b"github.com/docker/buildx v0.29.1 deadbeef\nsecond line\n",
    ),
)
def test_buildx_version_file_requires_one_lf_terminated_or_unterminated_line(
    raw: bytes,
) -> None:
    with pytest.raises(ValueError, match="exactly one line"):
        build_storage._one_version_output_line(raw)


def test_capture_buildx_observation_records_one_stable_symlink_identity(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "cli-plugins"
    target_root = tmp_path / "docker-desktop"
    plugin_root.mkdir()
    target_root.mkdir()
    target = target_root / "buildx-v0.29.1"
    target.write_bytes(b"fixture buildx\n")
    target.chmod(0o755)
    plugin = plugin_root / "docker-buildx"
    plugin.symlink_to(target)
    version = "v0.29.1-desktop.1"
    commit = "28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
    metadata = [_docker_buildx_metadata(str(plugin))]

    observation = build_storage.capture_buildx_observation(
        metadata,
        version_output=f"github.com/docker/buildx {version} {commit}",
        allowed_plugin_directories=frozenset({PurePosixPath(str(plugin_root))}),
        required_uid=os.getuid(),
        required_gid=os.getgid(),
    )

    assert observation["identity"]["reported_plugin_path"] == str(plugin)
    assert observation["identity"]["plugin"]["symlink_target"] == str(target)
    assert (
        observation["identity"]["resolved"]["sha256"]
        == hashlib.sha256(target.read_bytes()).hexdigest()
    )
    assert observation["identity_sha256"] == _canonical_digest(observation["identity"])
    assert observation["observed_at"].endswith("+00:00")


def test_buildx_observation_cli_reads_exact_regular_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plugins = tmp_path / "plugins.json"
    version = tmp_path / "version.txt"
    metadata = [_docker_buildx_metadata("/usr/local/lib/docker/cli-plugins/docker-buildx")]
    plugins.write_text(json.dumps(metadata), encoding="utf-8")
    version_output = (
        "github.com/docker/buildx v0.29.1-desktop.1 28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
    )
    version.write_text(version_output + "\n", encoding="utf-8")
    observed = {
        "observed_at": "2026-09-01T00:00:00+00:00",
        "identity": {},
        "identity_sha256": "1" * 64,
    }

    def capture(value: Any, *, version_output: str) -> dict[str, Any]:
        assert value == metadata
        assert version_output == (
            "github.com/docker/buildx v0.29.1-desktop.1 28f6246ff24e2c05095e8741e48c48dcb2d3b4bc"
        )
        return observed

    monkeypatch.setattr(build_storage, "capture_buildx_observation", capture)

    assert (
        build_storage._main(
            [
                "buildx-observation",
                "--plugins-json",
                str(plugins),
                "--version-output",
                str(version),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == observed


def test_buildx_observation_cli_rejects_duplicate_json_keys(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plugins = tmp_path / "plugins.json"
    version = tmp_path / "version.txt"
    plugins.write_text(
        "["
        '{"Name":"buildx","Name":"buildx",'
        '"Path":"/usr/local/lib/docker/cli-plugins/docker-buildx",'
        '"SchemaVersion":"0.1.0","ShortDescription":"Docker Buildx",'
        '"Vendor":"Docker Inc.","Version":"v0.29.1-desktop.1"}'
        "]",
        encoding="utf-8",
    )
    version.write_text(
        "github.com/docker/buildx v0.29.1-desktop.1 28f6246ff24e2c05095e8741e48c48dcb2d3b4bc\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as error:
        build_storage._main(
            [
                "buildx-observation",
                "--plugins-json",
                str(plugins),
                "--version-output",
                str(version),
            ]
        )

    assert error.value.code == 1
    assert "duplicate key: Name" in capsys.readouterr().err


def test_load_stable_build_execution_returns_the_exact_bytes_it_parsed(
    tmp_path: Path,
) -> None:
    receipt = tmp_path / "build-execution.json"
    raw = b'{\n  "schema_version": 1,\n  "label": "\\u0061"\n}\n'
    receipt.write_bytes(raw)

    resolved, observed_raw, value = build_storage.load_stable_build_execution(receipt)

    assert resolved == receipt.resolve()
    assert observed_raw == raw
    assert hashlib.sha256(observed_raw).hexdigest() == hashlib.sha256(raw).hexdigest()
    assert value == {"schema_version": 1, "label": "a"}


def test_load_stable_build_execution_rejects_a_final_path_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    receipt = tmp_path / "build-execution.json"
    receipt.symlink_to(target)

    with pytest.raises(ValueError, match="cannot be a symlink"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_rejects_a_parent_path_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "build-execution.json").write_text("{}", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="path contains a symlink"):
        build_storage.load_stable_build_execution(alias / "build-execution.json")


def test_load_stable_build_execution_rejects_duplicate_keys_at_any_depth(
    tmp_path: Path,
) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_text(
        '{"schema_version":1,"nested":{"digest":"a","digest":"b"}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate key: digest"):
        build_storage.load_stable_build_execution(receipt)


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_load_stable_build_execution_rejects_non_json_numeric_constants(
    tmp_path: Path,
    constant: str,
) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_text(f'{{"value":{constant}}}', encoding="utf-8")

    with pytest.raises(ValueError, match="invalid constant"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_rejects_non_utf8_input(tmp_path: Path) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_bytes(b'{"value":"\xff"}')

    with pytest.raises(ValueError, match="not unique-key UTF-8 JSON"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_enforces_the_size_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(build_storage, "BUILD_EXECUTION_MAX_BYTES", 1)

    with pytest.raises(ValueError, match="not a stable single regular file"):
        build_storage.load_stable_build_execution(receipt)


@pytest.mark.parametrize("kind", ("directory", "hard-link"))
def test_load_stable_build_execution_requires_one_regular_link(
    tmp_path: Path,
    kind: str,
) -> None:
    receipt = tmp_path / "build-execution.json"
    if kind == "directory":
        receipt.mkdir()
    else:
        source = tmp_path / "source.json"
        source.write_text("{}", encoding="utf-8")
        os.link(source, receipt)

    with pytest.raises(ValueError, match="not a stable single regular file"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_rejects_a_change_during_its_single_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "build-execution.json"
    receipt.write_text('{"schema_version":1}', encoding="utf-8")
    real_read = os.read
    changed = False

    def read_then_change(descriptor: int, count: int) -> bytes:
        nonlocal changed
        chunk = real_read(descriptor, count)
        if not changed:
            changed = True
            with receipt.open("ab") as stream:
                stream.write(b" ")
        return chunk

    monkeypatch.setattr(build_storage.os, "read", read_then_change)

    with pytest.raises(ValueError, match="changed while it was read"):
        build_storage.load_stable_build_execution(receipt)


def test_load_stable_build_execution_rejects_parent_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "evidence"
    parent.mkdir()
    receipt = parent / "build-execution.json"
    raw = b'{"schema_version":1}'
    receipt.write_bytes(raw)
    detached = tmp_path / "detached-evidence"
    real_read = os.read
    replaced = False

    def read_then_replace_parent(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        chunk = real_read(descriptor, count)
        if chunk and not replaced:
            replaced = True
            parent.rename(detached)
            parent.mkdir()
            (parent / receipt.name).write_bytes(raw)
        return chunk

    monkeypatch.setattr(build_storage.os, "read", read_then_replace_parent)

    with pytest.raises(ValueError, match="changed while it was read"):
        build_storage.load_stable_build_execution(receipt)


def test_schema_3_rejects_context_argv_even_when_rehashed() -> None:
    value = _build_receipt(schema_version=3, host_storage_preflight=_non_wsl_preflight())
    for command in value["commands"]:
        command["argv"][1:3] = ["--context", value["docker"]["context"]]
    _rehash(value)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        build_storage.validate_build_execution_envelope(value)


def test_schema_two_host_reader_binds_commands_to_the_exact_checkout(
    tmp_path: Path,
) -> None:
    (tmp_path / "neqo-qcsd").mkdir()
    dockerfile = tmp_path / "Dockerfile"
    uv_lock = tmp_path / "uv.lock"
    cargo_lock = tmp_path / "neqo-qcsd/Cargo.lock"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    uv_lock.write_text("uv\n", encoding="utf-8")
    cargo_lock.write_text("cargo\n", encoding="utf-8")
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["dockerfile_sha256"] = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
    value["build_inputs"]["uv_lock_sha256"] = hashlib.sha256(uv_lock.read_bytes()).hexdigest()
    value["build_inputs"]["cargo_lock_sha256"] = hashlib.sha256(cargo_lock.read_bytes()).hexdigest()
    for target in ("collection", "prepare"):
        value["role_provenance"]["build_inputs"][target] = dict(value["build_inputs"])
    for command in value["commands"]:
        iidfile_index = command["argv"].index("--iidfile") + 1
        command["argv"][iidfile_index] = str(
            tmp_path / "artifacts/buflo-study/.build-iids-v34.ABC123" / f"{command['target']}.iid"
        )
        command["argv"][-2] = str(dockerfile)
        command["argv"][-1] = str(tmp_path)
    _rehash(value)

    build_storage.validate_build_execution_envelope(
        value,
        expected_probe_sha256=PROBE_SHA256,
        checkout_root=tmp_path,
        expected_build_root=tmp_path,
    )

    for command in value["commands"]:
        iidfile_index = command["argv"].index("--iidfile") + 1
        command["argv"][iidfile_index] = (
            f"/unrelated/tree/artifacts/buflo-study/.build-iids-v34.ABC123/{command['target']}.iid"
        )
        command["argv"][-2] = "/unrelated/tree/Dockerfile"
        command["argv"][-1] = "/unrelated/tree"
    _rehash(value)
    with pytest.raises(ValueError, match="command root differs"):
        build_storage.validate_build_execution_envelope(
            value,
            expected_probe_sha256=PROBE_SHA256,
            checkout_root=tmp_path,
            expected_build_root=tmp_path,
        )


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_observation_rejects_missing_and_unknown_fields(mutation: str) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    if mutation == "missing":
        del value["file_system"]
    else:
        value["unexpected"] = None

    with pytest.raises(ValueError, match="observation schema is invalid"):
        _validate_observation(value)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_preflight_rejects_missing_and_unknown_fields(mutation: str) -> None:
    value = _wsl_preflight()
    if mutation == "missing":
        del value["platform_detection"]
    else:
        value["unexpected"] = None

    with pytest.raises(ValueError, match="preflight schema is invalid"):
        build_storage.validate_build_host_storage_preflight(value)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_platform_detection_rejects_missing_and_unknown_fields(mutation: str) -> None:
    value = _wsl_preflight()
    if mutation == "missing":
        del value["platform_detection"]["kernel_release"]
    else:
        value["platform_detection"]["unexpected"] = None

    with pytest.raises(ValueError, match="platform detection is invalid"):
        build_storage.validate_build_host_storage_preflight(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wsl_interop_env_present", 1),
        ("wsl_distro_name_env_present", 0),
        ("run_wsl_directory_present", "true"),
    ],
)
def test_platform_detection_rejects_non_boolean_signal_values(field: str, value: Any) -> None:
    preflight = _wsl_preflight()
    preflight["platform_detection"][field] = value

    with pytest.raises(ValueError, match="platform detection is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize("field", ["kernel_release", "proc_version"])
@pytest.mark.parametrize("value", [None, True, 1])
def test_platform_detection_rejects_non_string_version_signals(field: str, value: Any) -> None:
    preflight = _wsl_preflight()
    preflight["platform_detection"][field] = value

    with pytest.raises(ValueError, match="platform detection is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_build_envelope_rejects_missing_and_unknown_fields(mutation: str) -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    if mutation == "missing":
        del value["commands"]
    else:
        value["unexpected"] = None
    _rehash(value)

    with pytest.raises(ValueError, match="receipt schema is invalid"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize("mutation", ["missing", "unknown"])
def test_schema_2_docker_identity_rejects_missing_and_unknown_fields(
    mutation: str,
) -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    if mutation == "missing":
        del value["docker"]["server_id"]
    else:
        value["docker"]["unexpected"] = "value"
    _rehash(value)

    with pytest.raises(ValueError, match="Docker identity is invalid"):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    "volume_id",
    [
        "12345678-1234-1234-1234-123456789abc",
        "\\\\?\\Volume{12345678123412341234123456789abc}\\",
        "\\\\.\\Volume{12345678-1234-1234-1234-123456789abc}\\",
        "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}",
        "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\extra",
    ],
)
def test_observation_rejects_malformed_or_noncanonical_volume_guid(
    volume_id: str,
) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["backing_volume_unique_id"] = volume_id

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


def test_available_space_threshold_is_inclusive_and_fail_closed_below_it() -> None:
    threshold = build_storage.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES
    exact = _observation(*BOUNDARY_TIMES[0], available_bytes=threshold)
    assert _validate_observation(exact)["available_bytes"] == threshold

    below = _observation(*BOUNDARY_TIMES[0], available_bytes=threshold - 1)
    with pytest.raises(ValueError, match=rf"requires at least {threshold} available bytes"):
        _validate_observation(below)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("data_vhd_file_length_bytes", True),
        ("total_bytes", True),
        ("available_bytes", True),
    ],
)
def test_observation_rejects_boolean_integer_substitutions(field: str, value: bool) -> None:
    observation = _observation(*BOUNDARY_TIMES[0])
    observation[field] = value

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(observation)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("applicable", 1),
        ("required_available_bytes", True),
        ("passed", 1),
    ],
)
def test_preflight_rejects_boolean_substitutions(field: str, value: Any) -> None:
    preflight = _wsl_preflight()
    preflight[field] = value

    with pytest.raises(ValueError, match="preflight schema is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


def test_preflight_rejects_boolean_minimum_summary() -> None:
    preflight = _wsl_preflight()
    preflight["minimum_available_bytes"] = True

    with pytest.raises(ValueError):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    "location_source",
    ["", "local-appdata-guess", "wsl-logical-free-space"],
)
def test_observation_rejects_unreceipted_location_sources(
    location_source: str,
) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["location_source"] = location_source

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


def test_build_envelope_rejects_source_collection_image_mismatch() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["source"]["image_digest"] = "sha256:" + "f" * 64
    _rehash(value)

    with pytest.raises(ValueError, match="one concrete clean collection image"):
        build_storage.validate_build_execution_envelope(value)


def test_build_envelope_rejects_rehashed_cache_enabled_schema_2_receipt() -> None:
    value = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    value["cache_policy"]["no_cache"] = False
    _rehash(value)

    with pytest.raises(ValueError):
        build_storage.validate_build_execution_envelope(value)


@pytest.mark.parametrize(
    ("path", "drive_letter"),
    [
        ("relative\\docker_data.vhdx", "C"),
        ("C:/Docker/wsl/data/docker_data.vhdx", "C"),
        ("C:\\Docker\\..\\data\\docker_data.vhdx", "C"),
        ("C:\\Docker\\data\\docker_data.raw", "C"),
        ("C:\\Docker\\data\\docker_data.vhdx\\child", "C"),
        ("C:\\Docker\\data\\docker_data.vhdx", "D"),
    ],
)
def test_observation_rejects_noncanonical_or_mismatched_vhd_paths(
    path: str, drive_letter: str
) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["data_vhd_path"] = path
    value["drive_letter"] = drive_letter

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


@pytest.mark.parametrize("probe_sha256", ["", "A" * 64, "1" * 63, "g" * 64])
def test_observation_rejects_malformed_probe_hash(probe_sha256: str) -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["probe_sha256"] = probe_sha256

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


def test_observation_rejects_probe_hash_different_from_source_file() -> None:
    value = _observation(*BOUNDARY_TIMES[0])

    with pytest.raises(ValueError, match="observation is invalid"):
        build_storage.validate_build_host_storage_observation(
            value,
            expected_boundary="before-collection",
            expected_probe_sha256="2" * 64,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("file_system", ""),
        ("health_status", "Warning"),
        ("operational_status", []),
        ("operational_status", ["OK", "Degraded"]),
        ("operational_status", "OK"),
    ],
)
def test_observation_rejects_unhealthy_or_ambiguous_volume_state(field: str, value: Any) -> None:
    observation = _observation(*BOUNDARY_TIMES[0])
    observation[field] = value

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(observation)


def test_observation_rejects_wrong_boundary() -> None:
    value = _observation(*BOUNDARY_TIMES[0])
    value["boundary"] = "before-prepare"

    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("data_vhd_path", "D:\\Docker\\wsl\\data\\ext4.vhdx"),
        (
            "backing_volume_unique_id",
            "\\\\?\\Volume{87654321-4321-4321-4321-cba987654321}\\",
        ),
        ("location_source", "docker-settings-store"),
        ("file_system", "ReFS"),
        ("probe_sha256", "2" * 64),
    ],
)
def test_preflight_rejects_storage_identity_changes_mid_build(field: str, value: Any) -> None:
    preflight = _wsl_preflight()
    preflight["observations"][2][field] = value
    if field == "data_vhd_path":
        preflight["observations"][2]["drive_letter"] = "D"

    with pytest.raises(ValueError):
        build_storage.validate_build_host_storage_preflight(preflight)


def test_preflight_rejects_boundary_reordering() -> None:
    preflight = _wsl_preflight()
    preflight["observations"][1]["boundary"] = "before-reference"

    with pytest.raises(ValueError, match="observation is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


def test_preflight_rejects_stale_minimum_summary() -> None:
    preflight = _wsl_preflight()
    preflight["minimum_available_bytes"] += 1

    with pytest.raises(ValueError, match="preflight is inconsistent"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    "mutation",
    ["non_wsl_marked_applicable", "wsl_marked_non_applicable", "observations_present"],
)
def test_preflight_rejects_platform_applicability_contradictions(
    mutation: str,
) -> None:
    preflight = _non_wsl_preflight()
    if mutation == "non_wsl_marked_applicable":
        preflight["applicable"] = True
        preflight["platform"] = "windows-wsl2"
    elif mutation == "wsl_marked_non_applicable":
        preflight["platform_detection"]["kernel_release"] = "6.6.87.2-microsoft-standard-WSL2"
    else:
        preflight["observations"] = [_observation(*BOUNDARY_TIMES[0])]

    with pytest.raises(ValueError):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    ("signal", "value"),
    [
        ("kernel_release", "6.6.87.2-microsoft-standard-WSL2"),
        ("proc_version", "Linux version 6.6.87.2-microsoft-standard-WSL2"),
        ("wsl_interop_env_present", True),
        ("wsl_distro_name_env_present", True),
        ("run_wsl_directory_present", True),
    ],
)
def test_each_individual_wsl_signal_requires_applicable_preflight(signal: str, value: Any) -> None:
    preflight = _non_wsl_preflight()
    preflight["platform_detection"][signal] = value

    with pytest.raises(ValueError, match="non-WSL host-storage preflight is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    ("signal", "value"),
    [
        ("kernel_release", "6.6.87.2-microsoft-standard-WSL2"),
        ("proc_version", "Linux version 6.6.87.2-microsoft-standard-WSL2"),
        ("wsl_interop_env_present", True),
        ("wsl_distro_name_env_present", True),
        ("run_wsl_directory_present", True),
    ],
)
def test_each_individual_wsl_signal_suffices_for_applicable_preflight(
    signal: str, value: Any
) -> None:
    preflight = _wsl_preflight()
    preflight["platform_detection"] = _non_wsl_preflight()["platform_detection"]
    preflight["platform_detection"][signal] = value

    validated = build_storage.validate_build_host_storage_preflight(
        preflight,
        expected_probe_sha256=PROBE_SHA256,
    )

    assert validated["applicable"] is True


@pytest.mark.parametrize(
    "timestamps",
    [
        ("2026-09-01T00:00:00", None),
        ("not-a-timestamp", None),
        ("2026-09-01T00:00:03+00:00", "2026-09-01T00:00:02+00:00"),
        ("2026-09-01T00:00:02+00:00", "2026-09-01T00:00:02+00:00"),
    ],
)
def test_observation_and_preflight_reject_invalid_or_reversed_times(
    timestamps: tuple[str, str | None],
) -> None:
    first, second = timestamps
    if second is None:
        observation = _observation("before-collection", first)
        with pytest.raises(ValueError, match="timestamp"):
            _validate_observation(observation)
        return

    preflight = _wsl_preflight()
    preflight["observations"][1]["observed_at"] = first
    preflight["observations"][2]["observed_at"] = second
    with pytest.raises(ValueError, match="preflight is inconsistent"):
        build_storage.validate_build_host_storage_preflight(preflight)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("started_at", "2026-09-01T00:00:02.500000+00:00", "host-storage timing"),
        ("finished_at", "2026-09-01T00:00:03.500000+00:00", "host-storage timing"),
        ("finished_at", "2026-08-31T23:59:59+00:00", "duration is invalid"),
        ("started_at", "2026-09-01T00:00:01", "timestamp is not timezone-aware"),
    ],
)
def test_build_envelope_rejects_invalid_storage_or_receipt_timing(
    field: str, value: str, message: str
) -> None:
    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt[field] = value
    _rehash(receipt)

    with pytest.raises(ValueError, match=message):
        build_storage.validate_build_execution_envelope(receipt)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("context", "remote-builder"),
        ("endpoint", "tcp://192.0.2.10:2376"),
        ("server_os_type", "windows"),
    ],
)
def test_build_envelope_rejects_nonlocal_or_non_linux_docker_endpoint(
    field: str, value: str
) -> None:
    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt["docker"][field] = value
    _rehash(receipt)

    with pytest.raises(ValueError, match="endpoint is not local and supported"):
        build_storage.validate_build_execution_envelope(receipt)


@pytest.mark.parametrize("field", ["context", "endpoint", "server_id", "server_name"])
def test_build_envelope_rejects_empty_docker_identity(field: str) -> None:
    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt["docker"][field] = ""
    _rehash(receipt)

    with pytest.raises(ValueError, match="Docker identity is invalid"):
        build_storage.validate_build_execution_envelope(receipt)


def test_wsl_build_requires_docker_desktop_server_identity() -> None:
    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt["docker"]["server_operating_system"] = "Ubuntu 24.04"
    _rehash(receipt)

    with pytest.raises(ValueError, match="local Docker Desktop engine"):
        build_storage.validate_build_execution_envelope(receipt)


def test_build_envelope_rejects_boolean_cohort_version() -> None:
    receipt = _build_receipt(schema_version=1)
    receipt["cohort_version"] = True
    _rehash(receipt)

    with pytest.raises(ValueError, match="cohort version is not a positive integer"):
        build_storage.validate_build_execution_envelope(receipt)


def test_all_nested_schema_versions_reject_boolean_alias_for_one() -> None:
    observation = _observation(*BOUNDARY_TIMES[0])
    observation["schema_version"] = True
    with pytest.raises(ValueError, match="observation is invalid"):
        _validate_observation(observation)

    preflight = _wsl_preflight()
    preflight["schema_version"] = True
    with pytest.raises(ValueError, match="preflight schema is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)

    preflight = _wsl_preflight()
    preflight["platform_detection"]["schema_version"] = True
    with pytest.raises(ValueError, match="platform detection is invalid"):
        build_storage.validate_build_host_storage_preflight(preflight)

    receipt = _build_receipt(schema_version=1)
    receipt["schema_version"] = True
    _rehash(receipt)
    with pytest.raises(ValueError, match="receipt schema is invalid"):
        build_storage.validate_build_execution_envelope(receipt)

    receipt = _build_receipt(schema_version=2, host_storage_preflight=_wsl_preflight())
    receipt["role_provenance"]["schema_version"] = True
    _rehash(receipt)
    with pytest.raises(ValueError, match="role provenance is invalid"):
        build_storage.validate_build_execution_envelope(receipt)
