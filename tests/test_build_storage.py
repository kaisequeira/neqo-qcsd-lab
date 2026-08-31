from __future__ import annotations

import hashlib
import json
from pathlib import Path
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
    if schema_version == 2:
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
            if schema_version == 2
            else f"neqo-qcsd-lab-{target}:test"
        )
        argv = ["docker"]
        if schema_version == 2:
            argv.extend(["--context", docker["context"]])
        argv.extend(["build", "--pull", "--no-cache"])
        if schema_version == 2:
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
                    if schema_version == 2
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
    if schema_version == 2:
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
