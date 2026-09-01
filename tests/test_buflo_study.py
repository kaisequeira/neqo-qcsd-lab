from __future__ import annotations

import base64
import csv
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import (
    buflo_evaluation,
    buflo_handoff,
    buflo_study,
    build_storage,
    capture_session,
    orchestrator,
)
from qcsd_lab.buflo_study import (
    DEBIAN_BASE_IMAGE,
    PARAMETER_FILES,
    RUST_BASE_IMAGE,
    STUDY_PLAN,
    generated_stage_cells,
    load_study_plan,
    run_study_action,
    validate_campaign_matrix,
    validate_controlled_campaign_receipt,
    validate_established_seven_baseline,
    validate_formal_capture_capacity,
    validate_parameters,
    validate_reference_gate_receipt,
    validate_staged_capture_prerequisites,
    validate_study_environment_receipt,
    validate_validation_attestation,
)
from qcsd_lab.capture_session import (
    _client_resource_usage_valid,
    _merge_runner_wakeup_metrics,
    _parse_client_resource_usage,
    _runner_wakeup_metrics_valid,
)
from qcsd_lab.defenses import (
    DEFENSE_ADAPTATIONS,
    DEFENSE_ORDER,
    DEFENSE_RUNTIME_KINDS,
    DEFENSE_VARIANT_LABELS,
)
from qcsd_lab.fidelity import (
    BUFLO_SCHEDULE_STOP_POLICY,
    BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS,
    BUFLO_SCHEDULE_STOP_V4_KEYS,
    BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS,
    BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
    BUFLO_TERMINAL_SUBCELL_POLICY,
    CS_BUFLO_STOP_DRAIN_V4_KEYS,
    CS_BUFLO_TERMINATION_STOP_POLICY,
    RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
    RUNNER_WAKEUP_V7_SEMANTICS,
    RUNNER_WAKEUP_V8_SEMANTICS,
    SCHEDULE_PREFIX_FIELDS,
    SCHEDULE_QCSD_FIELDS,
    _cs_buflo_padding_targets_match,
    _cs_buflo_payload_padding_target,
    _schedule_realization_metrics,
    fidelity_eligible,
    new_defense_terminal_receipts_valid,
)
from qcsd_lab.fidelity import (
    _runner_wakeup_metrics_valid as _fidelity_runner_wakeup_metrics_valid,
)
from qcsd_lab.util import LAB_ROOT


def test_rust_code_gate_sidecar_hash_binds_exact_unsorted_json_bytes(
    tmp_path: Path,
) -> None:
    sidecar = tmp_path / "source.json"
    raw = b'{"z":1,"a":2}\n'
    sidecar.write_bytes(raw)
    expected = {"a": 2, "z": 1}

    buflo_study._validate_embedded_json_receipt(
        sidecar,
        expected=expected,
        claimed_sha256=hashlib.sha256(raw).hexdigest(),
        label="test",
    )

    # A semantically equivalent rewrite is still a different embedded receipt.
    sidecar.write_bytes(b'{"z":1, "a":2}\n')
    with pytest.raises(ValueError, match="sidecar hash is invalid"):
        buflo_study._validate_embedded_json_receipt(
            sidecar,
            expected=expected,
            claimed_sha256=hashlib.sha256(raw).hexdigest(),
            label="test",
        )


def test_rust_code_gate_sidecar_rejects_content_mismatch_and_symlink(
    tmp_path: Path,
) -> None:
    sidecar = tmp_path / "source.json"
    raw = b'{"z":1,"a":2}\n'
    sidecar.write_bytes(raw)
    with pytest.raises(ValueError, match="sidecar content is inconsistent"):
        buflo_study._validate_embedded_json_receipt(
            sidecar,
            expected={"a": 3, "z": 1},
            claimed_sha256=hashlib.sha256(raw).hexdigest(),
            label="test",
        )

    link = tmp_path / "source-link.json"
    link.symlink_to(sidecar)
    with pytest.raises(ValueError, match="sidecar is absent or unsafe"):
        buflo_study._validate_embedded_json_receipt(
            link,
            expected={"a": 2, "z": 1},
            claimed_sha256=hashlib.sha256(raw).hexdigest(),
            label="test",
        )


def _reference_execution_fixture(tmp_path: Path, *, build_schema_version: int = 1) -> Path:
    build_execution = _build_execution_value(schema_version=build_schema_version)
    source = {
        "image_digest": "sha256:" + "e" * 64,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": buflo_study.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": buflo_study.EMPTY_SHA256,
    }
    isolation = {
        "environment_marker": "QCSD_REFERENCE_ISOLATED=1",
        "docker_network_mode": "none",
        "observed_interfaces": ["lo"],
        "reference_inputs_read_only": True,
        "output_mount_writable": True,
        "output_create_only": True,
        "ordinary_collection_contains_author_code": False,
    }
    value = buflo_study._reference_execution_value(
        source=source,
        build_execution={
            "sha256": hashlib.sha256(
                (json.dumps(build_execution, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "receipt": build_execution,
        },
        isolation=isolation,
        execution_id="d" * 32,
        started_at="2026-08-27T00:00:00+00:00",
        finished_at="2026-08-27T00:00:00+00:00",
        duration_seconds=0.0,
    )
    destination = tmp_path / "reference-execution.json"
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _build_execution_value(
    image_id: str = "sha256:" + "a" * 64,
    *,
    cohort_version: int = 1,
    schema_version: int = 1,
) -> dict[str, object]:
    source = {
        "image_digest": image_id,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": buflo_study.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": buflo_study.EMPTY_SHA256,
    }
    images = {
        target: {
            "tag": (
                build_storage.BUILD_IMAGE_TAGS[target]
                if schema_version == 2
                else f"neqo-qcsd-lab-{target}:test"
            ),
            "id": image_id if target == "collection" else "sha256:" + digest * 64,
            "repo_digests": [],
        }
        for target, digest in (("collection", "a"), ("prepare", "d"), ("reference", "e"))
    }
    commands = [
        {
            "target": target,
            "argv": [
                "docker",
                *(["--context", "default"] if schema_version == 2 else []),
                "build",
                "--pull",
                "--no-cache",
                *(
                    [
                        "--iidfile",
                        str(
                            LAB_ROOT
                            / (f"artifacts/buflo-study/.build-iids-v{cohort_version}.ABC123")
                            / f"{target}.iid"
                        ),
                    ]
                    if schema_version == 2
                    else []
                ),
                "--target",
                target,
                "--tag",
                images[target]["tag"],
                "--file",
                str((LAB_ROOT / "Dockerfile").resolve()),
                str(LAB_ROOT.resolve()),
            ],
            "exit_code": 0,
            "image_id": images[target]["id"],
        }
        for target in ("collection", "prepare", "reference")
    ]
    value: dict[str, object] = {
        "schema_version": schema_version,
        "artifact_type": buflo_study.BUILD_EXECUTION_ARTIFACT_TYPE,
        "cohort_version": cohort_version,
        "started_at": "2026-08-27T00:00:00+00:00",
        "finished_at": "2026-08-27T00:00:01+00:00",
        "duration_seconds": 1.0,
        "docker": {"client_version": "29.0.1", "server_version": "29.0.1"},
        "commands": commands,
        "images": images,
        "source": source,
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": RUST_BASE_IMAGE,
            "debian_base_image": DEBIAN_BASE_IMAGE,
            "uv_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "uv.lock"),
            "cargo_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "neqo-qcsd/Cargo.lock"),
        },
        "dockerfile_sha256": buflo_study.sha256_file(LAB_ROOT / "Dockerfile"),
        "cache_policy": {
            "pull": True,
            "no_cache": True,
            "scope": "Docker-layer-cache-disabled;declared-BuildKit-dependency-cache-mounts-only",
        },
    }
    if schema_version == 2:
        value["docker"] = {
            **value["docker"],
            "context": "default",
            "endpoint": "unix:///var/run/docker.sock",
            "server_name": "docker-desktop",
            "server_operating_system": "Docker Desktop",
            "server_os_type": "linux",
            "server_architecture": "x86_64",
            "server_id": "12345678-1234-1234-1234-123456789abc",
        }
        boundaries = (
            ("before-collection", "2026-08-26T23:59:59+00:00"),
            ("before-prepare", "2026-08-27T00:00:00.200000+00:00"),
            ("before-reference", "2026-08-27T00:00:00.400000+00:00"),
            ("after-reference", "2026-08-27T00:00:00.800000+00:00"),
        )
        probe_sha256 = buflo_study.sha256_file(LAB_ROOT / "tools/windows_docker_storage_probe.ps1")
        observations = [
            {
                "schema_version": 1,
                "probe": "powershell-get-volume-docker-data-vhdx-v1",
                "probe_sha256": probe_sha256,
                "boundary": boundary,
                "observed_at": observed_at,
                "location_source": "wsl-lxss-docker-desktop-data",
                "data_vhd_path": "C:\\Docker\\wsl\\data\\ext4.vhdx",
                "data_vhd_file_length_bytes": 512 * 1024**3,
                "backing_volume_unique_id": (
                    r"\\?\Volume{12345678-1234-1234-1234-123456789abc}" + "\\"
                ),
                "drive_letter": "C",
                "file_system": "NTFS",
                "health_status": "Healthy",
                "operational_status": ["OK"],
                "total_bytes": 1024**4,
                "available_bytes": 128 * 1024**3,
            }
            for boundary, observed_at in boundaries
        ]
        value["host_storage_preflight"] = {
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
            "policy": "docker-data-vhdx-backing-volume-minimum-v1",
            "required_available_bytes": (buflo_study.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES),
            "observations": observations,
            "minimum_available_bytes": 128 * 1024**3,
            "passed": True,
        }
        value["role_provenance"] = {
            "schema_version": 1,
            "sources": {
                target: {**source, "image_digest": images[target]["id"]}
                for target in ("collection", "prepare", "reference")
            },
            "build_inputs": {
                "collection": dict(value["build_inputs"]),
                "prepare": dict(value["build_inputs"]),
                "reference": None,
            },
        }
    value["payload_sha256"] = buflo_study._canonical_digest(value)
    return value


def _install_fake_wsl_storage_probe(root: Path, binary_root: Path) -> None:
    tools = root / "tools"
    tools.mkdir(exist_ok=True)
    (tools / "windows_docker_storage_probe.ps1").write_bytes(
        (LAB_ROOT / "tools/windows_docker_storage_probe.ps1").read_bytes()
    )
    package = root / "src/qcsd_lab"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_bytes((LAB_ROOT / "src/qcsd_lab/__init__.py").read_bytes())
    (package / "build_storage.py").write_bytes(
        (LAB_ROOT / "src/qcsd_lab/build_storage.py").read_bytes()
    )
    uname = binary_root / "uname"
    uname.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        '[ "${1:-}" = "-r" ]\n'
        "printf '%s\\n' '6.6.87.2-microsoft-standard-WSL2'\n",
        encoding="utf-8",
    )
    uname.chmod(0o755)
    wslpath = binary_root / "wslpath"
    wslpath.write_text(
        '#!/bin/sh\nset -eu\nfor argument do last="$argument"; done\nprintf \'%s\\n\' "$last"\n',
        encoding="utf-8",
    )
    wslpath.chmod(0o755)
    powershell = binary_root / "powershell.exe"
    powershell.write_text(
        """#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

if os.environ.get("QCSD_TEST_WSL_PROBE_FAIL") == "1":
    raise SystemExit(9)
if os.environ.get("QCSD_TEST_WSL_MALFORMED") == "1":
    print("not-json")
    raise SystemExit(0)
boundary = sys.argv[sys.argv.index("-Boundary") + 1]
probe_path = Path(sys.argv[sys.argv.index("-File") + 1])
marker = os.environ.get("QCSD_TEST_POWERSHELL_MARKER")
if marker:
    with Path(marker).open("a", encoding="utf-8") as output:
        output.write(boundary + "\\n")
available = int(
    os.environ.get("QCSD_TEST_WSL_AVAILABLE_BYTES", str(128 * 1024**3))
)
if os.environ.get("QCSD_TEST_WSL_LOW_BOUNDARY") == boundary:
    available = 64 * 1024**3 - 1
slash = chr(92)
path = os.environ.get(
    "QCSD_TEST_WSL_DATA_PATH",
    "C:" + slash + slash.join(("Docker", "wsl", "data", "ext4.vhdx")),
)
volume = slash * 2 + "?" + slash + "Volume{12345678-1234-1234-1234-123456789abc}" + slash
if os.environ.get("QCSD_TEST_WSL_IDENTITY_CHANGE_BOUNDARY") == boundary:
    volume = slash * 2 + "?" + slash + "Volume{87654321-4321-4321-4321-cba987654321}" + slash
value = {
    "schema_version": 1,
    "probe": "powershell-get-volume-docker-data-vhdx-v1",
    "probe_sha256": hashlib.sha256(probe_path.read_bytes()).hexdigest(),
    "boundary": boundary,
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "location_source": os.environ.get(
        "QCSD_TEST_WSL_LOCATION_SOURCE", "wsl-lxss-docker-desktop-data"
    ),
    "data_vhd_path": path,
    "data_vhd_file_length_bytes": 512 * 1024**3,
    "backing_volume_unique_id": volume,
    "drive_letter": path[0].upper(),
    "file_system": "NTFS",
    "health_status": "Healthy",
    "operational_status": ["OK"],
    "total_bytes": 1024**4,
    "available_bytes": available,
}
print(json.dumps(value, separators=(",", ":")))
""",
        encoding="utf-8",
    )
    powershell.chmod(0o755)


def _install_fake_boundary_docker(binary_root: Path, build_marker: Path) -> None:
    docker = binary_root / "docker"
    inventory_marker = build_marker.with_name(f"{build_marker.name}-inventory")
    docker.write_text(
        f"""#!/bin/sh
set -eu
if [ "${{1:-}}" = "--context" ]; then
  shift 2
fi
command="$1"
shift
case "$command" in
  build)
    printf 'build\\n' >> {str(build_marker)!r}
    iidfile=""
    target=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --iidfile) iidfile="$2"; shift 2 ;;
        --target) target="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    case "$target" in
      collection) image_number=1 ;;
      prepare) image_number=2 ;;
      reference) image_number=3 ;;
      *) exit 1 ;;
    esac
    [ -n "$iidfile" ] || exit 1
    if [ "${{QCSD_TEST_IID_TARGET:-}}" = "$target" ]; then
      case "${{QCSD_TEST_IID_MODE:-}}" in
        missing) : ;;
        malformed) printf '%s\\n' 'not-an-image-id' > "$iidfile" ;;
        mismatch) printf 'sha256:%064d\\n' 9 > "$iidfile" ;;
        *) exit 1 ;;
      esac
    else
      printf 'sha256:%064d\\n' "$image_number" > "$iidfile"
    fi
    ;;
  context)
    case "$1" in
      show) printf '%s\\n' "${{QCSD_TEST_DOCKER_CONTEXT:-default}}" ;;
      inspect) printf '%s\\n' "${{QCSD_TEST_DOCKER_ENDPOINT:-unix:///var/run/docker.sock}}" ;;
      *) exit 1 ;;
    esac
    ;;
  info)
    if [ "$#" -eq 0 ]; then exit 0; fi
    build_count=0
    if [ -f {str(build_marker)!r} ]; then
      build_count="$(wc -l < {str(build_marker)!r})"
    fi
    server_name="${{QCSD_TEST_DOCKER_SERVER_NAME:-docker-desktop}}"
    server_id="${{QCSD_TEST_DOCKER_SERVER_ID:-12345678-1234-1234-1234-123456789abc}}"
    if [ -n "${{QCSD_TEST_DOCKER_CHANGE_AFTER_BUILDS:-}}" ] &&
       [ "$build_count" -ge "${{QCSD_TEST_DOCKER_CHANGE_AFTER_BUILDS}}" ]; then
      server_name="${{server_name}}-changed"
    fi
    if [ -n "${{QCSD_TEST_DOCKER_ID_CHANGE_AFTER_BUILDS:-}}" ] &&
       [ "$build_count" -ge "${{QCSD_TEST_DOCKER_ID_CHANGE_AFTER_BUILDS}}" ]; then
      server_id="87654321-4321-4321-4321-cba987654321"
    fi
    if [ -f {str(inventory_marker)!r} ]; then
      server_id="87654321-4321-4321-4321-cba987654321"
    fi
    case "$2" in
      '{{{{json .}}}}')
        printf '{{"Name":"%s","OperatingSystem":"%s","OSType":"linux","Architecture":"x86_64","ID":"%s"}}\\n' \
          "$server_name" "${{QCSD_TEST_DOCKER_OPERATING_SYSTEM:-Docker Desktop}}" "$server_id"
        ;;
      '{{{{.Name}}}}') printf '%s\\n' "$server_name" ;;
      '{{{{.OperatingSystem}}}}') printf '%s\\n' "${{QCSD_TEST_DOCKER_OPERATING_SYSTEM:-Docker Desktop}}" ;;
      '{{{{.OSType}}}}') printf '%s\\n' 'linux' ;;
      '{{{{.Architecture}}}}') printf '%s\\n' 'x86_64' ;;
      *) exit 1 ;;
    esac
    ;;
  version)
    if [ "${{QCSD_TEST_DOCKER_ID_CHANGE_AFTER_INVENTORY:-0}}" = "1" ]; then
      : > {str(inventory_marker)!r}
    fi
    printf '%s\\n' '{{"Client":{{"Version":"29.0.1"}},"Server":{{"Version":"29.0.1"}}}}'
    ;;
  image)
    shift
    format=""
    last=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--format" ]; then format="$2"; shift 2; continue; fi
      last="$1"; shift
    done
    case "$format" in
      '{{{{.Id}}}}')
        case "$last" in
          *collection*) printf 'sha256:%064d\\n' 1 ;;
          *prepare*) printf 'sha256:%064d\\n' 2 ;;
          *reference*) printf 'sha256:%064d\\n' 3 ;;
          *) printf '%s\\n' "$last" ;;
        esac
        ;;
      '{{{{json .RepoDigests}}}}') printf '%s\\n' '[]' ;;
      *) exit 1 ;;
    esac
    ;;
  run)
    case "$*" in
      */source.json)
        if [ -n "${{QCSD_TEST_SOURCE_CHANGE_IMAGE_ID:-}}" ] &&
           case "$*" in *"${{QCSD_TEST_SOURCE_CHANGE_IMAGE_ID}}"*) true ;; *) false ;; esac; then
          printf '%s\\n' '{{"lab_commit":"ffffffffffffffffffffffffffffffffffffffff","lab_dirty":false,"lab_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","neqo_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_pinned_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_dirty":false,"neqo_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}'
        else
          printf '%s\\n' '{{"lab_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","lab_dirty":false,"lab_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","neqo_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_pinned_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_dirty":false,"neqo_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}'
        fi
        ;;
      */study-build-inputs.json)
        if [ "${{QCSD_TEST_INVALID_BUILD_INPUTS:-0}}" = "1" ]; then
          printf '%s\\n' '{{}}'
        else
          printf '%s\\n' '{{"artifact_type":"qcsd-study-build-inputs","cargo_lock_sha256":"d8c9f2728aa278ebcd33ccedf3ad309a866870ad5fb93a03526b4b7655c9e911","debian_base_image":"docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818","rust_base_image":"docker.io/library/rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f","schema_version":1,"uv_lock_sha256":"d8c9f2728aa278ebcd33ccedf3ad309a866870ad5fb93a03526b4b7655c9e911"}}'
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)


def _launcher_boundary_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, str]]:
    launcher = tmp_path / "qcsd-lab"
    launcher.write_bytes((LAB_ROOT / "qcsd-lab").read_bytes())
    launcher.chmod(0o755)
    (tmp_path / "neqo-qcsd").mkdir()
    (tmp_path / "neqo-qcsd/Cargo.lock").write_text("lock\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("lock\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    _install_fake_wsl_storage_probe(tmp_path, binary_root)
    build_marker = tmp_path / "docker-builds"
    _install_fake_boundary_docker(binary_root, build_marker)
    environment = dict(os.environ)
    environment["PATH"] = f"{binary_root}:{environment['PATH']}"
    identity = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:32]
    environment["QCSD_TEST_DOCKER_SERVER_ID"] = (
        f"{identity[:8]}-{identity[8:12]}-{identity[12:16]}-{identity[16:20]}-{identity[20:]}"
    )
    return launcher, build_marker, environment


def _marked_build_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines()) if path.exists() else 0


def _runner_wakeup_receipt() -> dict[str, object]:
    return {
        "schema_version": 1,
        "semantics": (
            "actual_select_return_source; socket_wins_simultaneous_readiness; "
            "controller_subset_is_effective_earliest_deadline; "
            "scheduled_cells_are_not_wakeups"
        ),
        "wait_returns": 12,
        "socket_readiness_wakeups": 7,
        "timer_wakeups": 5,
        "controller_deadline_timer_wakeups": 4,
        "other_timer_wakeups": 1,
    }


def _runner_wakeup_receipt_v2() -> dict[str, object]:
    value = _runner_wakeup_receipt()
    value.update(
        {
            "schema_version": 2,
            "semantics": (
                f"{value['semantics']}; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                "buflo_exact_release_active_wait_tail_us=250; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_output_is_interrupted_at_guard"
            ),
            "buflo_exact_release_guard_entries": 0,
            "buflo_exact_release_guard_wait_nanoseconds": 0,
            "buflo_exact_release_active_wait_nanoseconds": 0,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 0,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 0,
        }
    )
    return value


def _runner_wakeup_receipt_v3() -> dict[str, object]:
    value = _runner_wakeup_receipt_v2()
    value.update(
        {
            "schema_version": 3,
            "semantics": str(value["semantics"]).replace(
                "buflo_exact_release_active_wait_tail_us=250",
                "buflo_exact_release_active_wait_tail_us=5000",
            ),
        }
    )
    return value


def _runner_wakeup_receipt_v4() -> dict[str, object]:
    value = _runner_wakeup_receipt_v3()
    value.update(
        {
            "schema_version": 4,
            "semantics": (
                f"{_runner_wakeup_receipt()['semantics']}; "
                "buflo_ordinary_output_admission_is_one_realization_window_before_guard; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                "buflo_exact_release_active_wait_tail_us=5000; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_ordinary_output_stops_at_admission; "
                "buflo_exact_release_guard_begins_at_guard; "
                "cs_exact_incoming_retry_phases=1/4,1/2,3/4"
            ),
            "cs_exact_incoming_retry_drives": 0,
            "cs_exact_incoming_retry_resolutions": 0,
            "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 0,
        }
    )
    return value


def _runner_wakeup_receipt_v5() -> dict[str, object]:
    value = _runner_wakeup_receipt_v4()
    value.update(
        {
            "schema_version": 5,
            "semantics": (
                f"{value['semantics']}; "
                "buflo_exact_incoming_retry_wakeups="
                "transport_callback_or_1/4,1/2,3/4,deadline; "
                "buflo_exact_incoming_retry_drives="
                "count_owner_endpoint_output_drive_invocations_"
                "including_immediate_and_error; "
                "buflo_exact_incoming_retry_resolutions="
                "count_drive_invocations_clearing_at_least_one_captured_identity; "
                "buflo_exact_incoming_retry_max_wake_lateness_"
                "includes_terminal_deadline=true; "
                "buflo_exact_incoming_inventory="
                "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
                "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
            ),
            "buflo_exact_incoming_retry_drives": 0,
            "buflo_exact_incoming_retry_resolutions": 0,
            "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 0,
        }
    )
    return value


def _runner_wakeup_receipt_v6() -> dict[str, object]:
    value = _runner_wakeup_receipt_v5()
    value.update(
        {
            "schema_version": 6,
            "semantics": (
                f"{_runner_wakeup_receipt()['semantics']}; "
                "buflo_ordinary_output_admission_lead_us=10000; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                "buflo_exact_release_guard_lead_us=10000; "
                "buflo_exact_release_active_wait_tail_us=10000; "
                "buflo_exact_release_guard_coincides_with_output_admission=true; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_ordinary_output_stops_at_admission; "
                "buflo_exact_release_guard_begins_at_guard; "
                "cs_exact_incoming_retry_phases=1/4,1/2,3/4; "
                "buflo_exact_incoming_retry_wakeups="
                "transport_callback_or_1/4,1/2,3/4,deadline; "
                "buflo_exact_incoming_retry_drives="
                "count_owner_endpoint_output_drive_invocations_"
                "including_immediate_and_error; "
                "buflo_exact_incoming_retry_resolutions="
                "count_drive_invocations_clearing_at_least_one_captured_identity; "
                "buflo_exact_incoming_retry_max_wake_lateness_"
                "includes_terminal_deadline=true; "
                "buflo_exact_incoming_inventory="
                "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
                "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
            ),
        }
    )
    return value


def _runner_wakeup_receipt_v7(
    *,
    guard_entries: int = 0,
    dispatch_lateness_nanoseconds: int = 7,
    release_skew_nanoseconds: int = 0,
) -> dict[str, object]:
    if not 0 <= release_skew_nanoseconds <= 999:
        raise ValueError("release skew must fit the sub-microsecond normalisation")
    if guard_entries == 0:
        dispatch_lateness_nanoseconds = 0
        release_skew_nanoseconds = 0
    deadline_skew_nanoseconds = (
        0 if release_skew_nanoseconds == 0 else 1_000 - release_skew_nanoseconds
    )
    release_nanoseconds = 20_000_000 + release_skew_nanoseconds
    deadline_nanoseconds = 25_000_000 - deadline_skew_nanoseconds
    actual_window_nanoseconds = deadline_nanoseconds - release_nanoseconds
    guard_nanoseconds = release_nanoseconds - 2 * actual_window_nanoseconds
    active_wait_per_guard = 2 * actual_window_nanoseconds + dispatch_lateness_nanoseconds
    active_wait_total = guard_entries * active_wait_per_guard
    dispatch_counts = [0] * 8
    spin_counts = [0] * 8
    if guard_entries:
        dispatch_bucket = sum(
            dispatch_lateness_nanoseconds > upper
            for upper in RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS
        )
        dispatch_counts[dispatch_bucket] = guard_entries
        spin_counts[0] = guard_entries
    value = _runner_wakeup_receipt_v6()
    value.update(
        {
            "schema_version": 7,
            "semantics": RUNNER_WAKEUP_V7_SEMANTICS,
            "buflo_exact_release_guard_entries": guard_entries,
            "buflo_exact_release_guard_wait_nanoseconds": active_wait_total,
            "buflo_exact_release_active_wait_nanoseconds": active_wait_total,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 0,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": (
                dispatch_lateness_nanoseconds
            ),
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 0,
            "buflo_exact_release_passive_sleep_calls": 0,
            "buflo_exact_release_passive_sleep_requested_nanoseconds": 0,
            "buflo_exact_release_passive_sleep_elapsed_nanoseconds": 0,
            "buflo_exact_release_max_passive_sleep_overrun_nanoseconds": 0,
            "buflo_exact_release_active_wait_iterations": guard_entries,
            "buflo_exact_release_active_spin_interruptions": 0,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 0,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 0,
            "buflo_exact_release_aux_clock_source": (
                "linux-clock-gettime-monotonic-raw-and-thread-cputime-id-v1"
            ),
            "buflo_exact_release_active_wait_aux_clock_guards": guard_entries,
            "buflo_exact_release_active_wait_aux_clock_unavailable_guards": 0,
            "buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards": 0,
            "buflo_exact_release_active_wait_monotonic_raw_nanoseconds": (active_wait_total),
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds": (active_wait_total),
            "buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds": 0,
            "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds": 0,
            "buflo_exact_release_dispatch_at_or_after_deadline_guards": (
                guard_entries if dispatch_lateness_nanoseconds >= actual_window_nanoseconds else 0
            ),
            "buflo_exact_release_dispatch_lateness_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": dispatch_counts,
            },
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": spin_counts,
            },
            "buflo_exact_release_worst_guard": (
                {
                    "endpoint": 0,
                    "slot": 1,
                    "phase": "committed",
                    "packet_timestamp_us": 20_000,
                    "guard_at_defense_nanoseconds": guard_nanoseconds,
                    "entered_at_defense_nanoseconds": guard_nanoseconds,
                    "active_wait_at_defense_nanoseconds": guard_nanoseconds,
                    "active_wait_started_at_defense_nanoseconds": guard_nanoseconds,
                    "release_at_defense_nanoseconds": release_nanoseconds,
                    "deadline_at_defense_nanoseconds": deadline_nanoseconds,
                    "dispatch_at_defense_nanoseconds": (
                        release_nanoseconds + dispatch_lateness_nanoseconds
                    ),
                    "guard_entry_lateness_nanoseconds": 0,
                    "passive_sleep_calls": 0,
                    "passive_sleep_requested_nanoseconds": 0,
                    "passive_sleep_elapsed_nanoseconds": 0,
                    "max_passive_sleep_overrun_nanoseconds": 0,
                    "active_wait_iterations": 1,
                    "active_wait_monotonic_nanoseconds": active_wait_per_guard,
                    "active_wait_monotonic_raw_nanoseconds": active_wait_per_guard,
                    "active_wait_thread_cpu_nanoseconds": active_wait_per_guard,
                    "active_wait_estimated_off_cpu_nanoseconds": 0,
                    "active_wait_monotonic_raw_divergence_nanoseconds": 0,
                    "active_spin_interruptions": 0,
                    "active_spin_interruption_nanoseconds": 0,
                    "max_active_spin_gap_nanoseconds": 0,
                    "dispatch_lateness_nanoseconds": dispatch_lateness_nanoseconds,
                    "dispatch_at_or_after_deadline": (
                        dispatch_lateness_nanoseconds >= actual_window_nanoseconds
                    ),
                    "dispatch_after_deadline_nanoseconds": max(
                        dispatch_lateness_nanoseconds - actual_window_nanoseconds, 0
                    ),
                }
                if guard_entries
                else None
            ),
        }
    )
    return value


def _runner_wakeup_receipt_v8(
    *,
    guard_entries: int = 0,
    dispatch_lateness_nanoseconds: int = 7,
    release_skew_nanoseconds: int = 0,
) -> dict[str, object]:
    value = _runner_wakeup_receipt_v7(
        guard_entries=guard_entries,
        dispatch_lateness_nanoseconds=dispatch_lateness_nanoseconds,
        release_skew_nanoseconds=release_skew_nanoseconds,
    )
    value.update(
        {
            "schema_version": 8,
            "semantics": RUNNER_WAKEUP_V8_SEMANTICS,
        }
    )
    return value


def test_runner_wakeup_schema_eight_binds_barrier_free_poll_semantics() -> None:
    historical = _runner_wakeup_receipt_v7(guard_entries=1)
    current = _runner_wakeup_receipt_v8(guard_entries=1)

    assert set(current) == set(historical)
    assert current["semantics"] == (
        f"{historical['semantics']}; "
        "buflo_exact_release_active_wait_poll=poll_instant_without_arch_spin_hint"
    )
    assert _runner_wakeup_metrics_valid(historical)
    assert _fidelity_runner_wakeup_metrics_valid(historical)
    assert _runner_wakeup_metrics_valid(current)
    assert _fidelity_runner_wakeup_metrics_valid(current)
    assert not _runner_wakeup_metrics_valid(
        {**historical, "semantics": current["semantics"]}
    )
    assert not _fidelity_runner_wakeup_metrics_valid(
        {**historical, "semantics": current["semantics"]}
    )
    assert not _runner_wakeup_metrics_valid({**current, "semantics": historical["semantics"]})
    assert not _fidelity_runner_wakeup_metrics_valid(
        {**current, "semantics": historical["semantics"]}
    )


def test_runner_wakeup_schema_six_has_exact_semantics_and_v5_metric_keys() -> None:
    historical_v5 = _runner_wakeup_receipt_v5()
    current_v6 = _runner_wakeup_receipt_v6()

    assert set(current_v6) == set(historical_v5)
    assert current_v6["semantics"] == (
        "actual_select_return_source; socket_wins_simultaneous_readiness; "
        "controller_subset_is_effective_earliest_deadline; scheduled_cells_are_not_wakeups; "
        "buflo_ordinary_output_admission_lead_us=10000; "
        "buflo_exact_release_guard_reserves_candidate_window; "
        "buflo_exact_release_guard_lead_us=10000; "
        "buflo_exact_release_active_wait_tail_us=10000; "
        "buflo_exact_release_guard_coincides_with_output_admission=true; "
        "buflo_exact_release_guards_are_separately_receipted_active_waits; "
        "buflo_active_defense_socket_drains_are_single_batch; "
        "buflo_active_defense_http_drains_are_single_event; "
        "buflo_ordinary_output_stops_at_admission; "
        "buflo_exact_release_guard_begins_at_guard; "
        "cs_exact_incoming_retry_phases=1/4,1/2,3/4; "
        "buflo_exact_incoming_retry_wakeups=transport_callback_or_1/4,1/2,3/4,deadline; "
        "buflo_exact_incoming_retry_drives="
        "count_owner_endpoint_output_drive_invocations_including_immediate_and_error; "
        "buflo_exact_incoming_retry_resolutions="
        "count_drive_invocations_clearing_at_least_one_captured_identity; "
        "buflo_exact_incoming_retry_max_wake_lateness_includes_terminal_deadline=true; "
        "buflo_exact_incoming_inventory="
        "all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; "
        "buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss"
    )
    assert _runner_wakeup_metrics_valid(historical_v5)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v5)
    assert _runner_wakeup_metrics_valid(current_v6)
    assert _fidelity_runner_wakeup_metrics_valid(current_v6)

    wrong_semantics = {**current_v6, "semantics": historical_v5["semantics"]}
    assert not _runner_wakeup_metrics_valid(wrong_semantics)
    assert not _fidelity_runner_wakeup_metrics_valid(wrong_semantics)
    assert not _runner_wakeup_metrics_valid({**current_v6, "unexpected": 0})
    assert not _fidelity_runner_wakeup_metrics_valid({**current_v6, "unexpected": 0})


def test_runner_wakeup_schema_seven_binds_exact_release_timing_evidence() -> None:
    historical_v6 = _runner_wakeup_receipt_v6()
    current_v7 = _runner_wakeup_receipt_v7(guard_entries=2)

    assert _runner_wakeup_metrics_valid(historical_v6)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v6)
    assert _runner_wakeup_metrics_valid(current_v7)
    assert _fidelity_runner_wakeup_metrics_valid(current_v7)
    assert current_v7["semantics"].endswith(
        "buflo_exact_release_10000us_lead_fields_are_configured_maxima=true"
    )
    assert (
        sum(current_v7["buflo_exact_release_dispatch_lateness_histogram"]["counts"])
        == current_v7["buflo_exact_release_guard_entries"]
    )

    at_deadline = _runner_wakeup_receipt_v7(
        guard_entries=1, dispatch_lateness_nanoseconds=5_000_000
    )
    assert _runner_wakeup_metrics_valid(at_deadline)
    assert _fidelity_runner_wakeup_metrics_valid(at_deadline)
    assert at_deadline["buflo_exact_release_dispatch_at_or_after_deadline_guards"] == 1
    assert at_deadline["buflo_exact_release_worst_guard"]["dispatch_at_or_after_deadline"] is True

    late_inside_window = _runner_wakeup_receipt_v7(
        guard_entries=1, dispatch_lateness_nanoseconds=2_000_000
    )
    late_inside_window.update(
        {
            "buflo_exact_release_guard_wait_nanoseconds": 0,
            "buflo_exact_release_active_wait_nanoseconds": 0,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 12_000_000,
            "buflo_exact_release_max_guard_entry_lateness_nanoseconds": 12_000_000,
            "buflo_exact_release_active_wait_monotonic_raw_nanoseconds": 0,
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds": 0,
        }
    )
    late_worst = late_inside_window["buflo_exact_release_worst_guard"]
    late_worst.update(
        {
            "entered_at_defense_nanoseconds": 22_000_000,
            "active_wait_started_at_defense_nanoseconds": 22_000_000,
            "dispatch_at_defense_nanoseconds": 22_000_000,
            "guard_entry_lateness_nanoseconds": 12_000_000,
            "active_wait_monotonic_nanoseconds": 0,
            "active_wait_monotonic_raw_nanoseconds": 0,
            "active_wait_thread_cpu_nanoseconds": 0,
        }
    )
    assert _runner_wakeup_metrics_valid(late_inside_window)
    assert _fidelity_runner_wakeup_metrics_valid(late_inside_window)

    raw_clock_divergence = _runner_wakeup_receipt_v7(guard_entries=1)
    active_wait = raw_clock_divergence["buflo_exact_release_active_wait_nanoseconds"]
    raw_elapsed = active_wait - 1_000_000
    raw_clock_divergence.update(
        {
            "buflo_exact_release_active_wait_monotonic_raw_nanoseconds": raw_elapsed,
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds": 0,
            "buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds": active_wait,
            "buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds": active_wait,
            "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds": 1_000_000,
        }
    )
    divergent_worst = raw_clock_divergence["buflo_exact_release_worst_guard"]
    divergent_worst.update(
        {
            "active_wait_monotonic_raw_nanoseconds": raw_elapsed,
            "active_wait_thread_cpu_nanoseconds": 0,
            "active_wait_estimated_off_cpu_nanoseconds": active_wait,
            "active_wait_monotonic_raw_divergence_nanoseconds": 1_000_000,
        }
    )
    assert _runner_wakeup_metrics_valid(raw_clock_divergence)
    assert _fidelity_runner_wakeup_metrics_valid(raw_clock_divergence)

    invalid_histogram = json.loads(json.dumps(current_v7))
    invalid_histogram["buflo_exact_release_dispatch_lateness_histogram"]["counts"][0] -= 1
    assert not _runner_wakeup_metrics_valid(invalid_histogram)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_histogram)

    invalid_spin = json.loads(json.dumps(current_v7))
    invalid_spin["buflo_exact_release_max_active_spin_gap_nanoseconds"] = 50_001
    assert not _runner_wakeup_metrics_valid(invalid_spin)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_spin)


def test_runner_wakeup_schema_seven_accepts_fractional_adapter_window() -> None:
    fractional = _runner_wakeup_receipt_v7(
        guard_entries=1,
        dispatch_lateness_nanoseconds=4_999_000,
        release_skew_nanoseconds=456,
    )
    worst = fractional["buflo_exact_release_worst_guard"]

    assert worst["guard_at_defense_nanoseconds"] == 10_002_456
    assert worst["release_at_defense_nanoseconds"] == 20_000_456
    assert worst["deadline_at_defense_nanoseconds"] == 24_999_456
    assert worst["dispatch_at_or_after_deadline"] is True
    assert worst["dispatch_after_deadline_nanoseconds"] == 0
    assert _runner_wakeup_metrics_valid(fractional)
    assert _fidelity_runner_wakeup_metrics_valid(fractional)

    malformed_ceil_floor = json.loads(json.dumps(fractional))
    malformed_ceil_floor["buflo_exact_release_worst_guard"]["deadline_at_defense_nanoseconds"] += 1
    assert not _runner_wakeup_metrics_valid(malformed_ceil_floor)
    assert not _fidelity_runner_wakeup_metrics_valid(malformed_ceil_floor)


def test_runner_wakeup_schema_seven_accepts_mixed_window_deadline_count() -> None:
    mixed = _runner_wakeup_receipt_v7(guard_entries=2, dispatch_lateness_nanoseconds=4_999_800)
    mixed["buflo_exact_release_dispatch_at_or_after_deadline_guards"] = 1

    assert mixed["buflo_exact_release_worst_guard"]["dispatch_at_or_after_deadline"] is False
    assert _runner_wakeup_metrics_valid(mixed)
    assert _fidelity_runner_wakeup_metrics_valid(mixed)

    impossible_all_outside = json.loads(json.dumps(mixed))
    impossible_all_outside["buflo_exact_release_dispatch_at_or_after_deadline_guards"] = 2
    assert not _runner_wakeup_metrics_valid(impossible_all_outside)
    assert not _fidelity_runner_wakeup_metrics_valid(impossible_all_outside)

    impossible_zero_outside = _runner_wakeup_receipt_v7(
        guard_entries=1,
        dispatch_lateness_nanoseconds=4_999_000,
        release_skew_nanoseconds=456,
    )
    impossible_zero_outside["buflo_exact_release_dispatch_at_or_after_deadline_guards"] = 0
    assert not _runner_wakeup_metrics_valid(impossible_zero_outside)
    assert not _fidelity_runner_wakeup_metrics_valid(impossible_zero_outside)


def test_runner_wakeup_schema_seven_binds_aux_pairs_and_spin_histogram() -> None:
    partial_aux = _runner_wakeup_receipt_v7(guard_entries=1)
    partial_aux.update(
        {
            "buflo_exact_release_active_wait_aux_clock_guards": 0,
            "buflo_exact_release_active_wait_aux_clock_unavailable_guards": 1,
            "buflo_exact_release_active_wait_thread_cpu_nanoseconds": 0,
        }
    )
    partial_worst = partial_aux["buflo_exact_release_worst_guard"]
    partial_worst["active_wait_thread_cpu_nanoseconds"] = None
    partial_worst["active_wait_estimated_off_cpu_nanoseconds"] = None
    assert _runner_wakeup_metrics_valid(partial_aux)
    assert _fidelity_runner_wakeup_metrics_valid(partial_aux)

    invalid_aux_formula = json.loads(json.dumps(partial_aux))
    invalid_aux_formula["buflo_exact_release_worst_guard"][
        "active_wait_monotonic_raw_divergence_nanoseconds"
    ] = 1
    invalid_aux_formula[
        "buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds"
    ] = 1
    assert not _runner_wakeup_metrics_valid(invalid_aux_formula)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_aux_formula)

    interrupted = _runner_wakeup_receipt_v7(guard_entries=1)
    interrupted.update(
        {
            "buflo_exact_release_active_spin_interruptions": 1,
            "buflo_exact_release_active_spin_interruption_nanoseconds": 60_000,
            "buflo_exact_release_max_active_spin_gap_nanoseconds": 60_000,
            "buflo_exact_release_active_spin_gap_histogram": {
                "upper_bounds_nanoseconds": RUNNER_WAKEUP_V7_HISTOGRAM_UPPER_BOUNDS,
                "counts": [0, 1, 0, 0, 0, 0, 0, 0],
            },
        }
    )
    interrupted_worst = interrupted["buflo_exact_release_worst_guard"]
    interrupted_worst.update(
        {
            "active_spin_interruptions": 1,
            "active_spin_interruption_nanoseconds": 60_000,
            "max_active_spin_gap_nanoseconds": 60_000,
        }
    )
    assert _runner_wakeup_metrics_valid(interrupted)
    assert _fidelity_runner_wakeup_metrics_valid(interrupted)

    missing_spin_bucket = json.loads(json.dumps(interrupted))
    missing_spin_bucket["buflo_exact_release_active_spin_gap_histogram"]["counts"] = [
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    assert not _runner_wakeup_metrics_valid(missing_spin_bucket)
    assert not _fidelity_runner_wakeup_metrics_valid(missing_spin_bucket)

    threshold_is_strict = json.loads(json.dumps(interrupted))
    threshold_is_strict["buflo_exact_release_max_active_spin_gap_nanoseconds"] = 50_000
    threshold_is_strict["buflo_exact_release_active_spin_interruption_nanoseconds"] = 50_000
    threshold_is_strict["buflo_exact_release_active_spin_gap_histogram"]["counts"] = [
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    threshold_worst = threshold_is_strict["buflo_exact_release_worst_guard"]
    threshold_worst["active_spin_interruption_nanoseconds"] = 50_000
    threshold_worst["max_active_spin_gap_nanoseconds"] = 50_000
    assert not _runner_wakeup_metrics_valid(threshold_is_strict)
    assert not _fidelity_runner_wakeup_metrics_valid(threshold_is_strict)


def test_registry_appends_two_candidate_scientific_identities() -> None:
    assert DEFENSE_ORDER[-2:] == ("buflo", "cs-buflo")
    assert DEFENSE_RUNTIME_KINDS["buflo"] == "buflo"
    assert DEFENSE_RUNTIME_KINDS["cs-buflo"] == "cs_buflo"
    assert DEFENSE_ADAPTATIONS["buflo"].implementation_status == "candidate"
    assert DEFENSE_ADAPTATIONS["cs-buflo"].implementation_status == "candidate"
    assert DEFENSE_VARIANT_LABELS == {
        "cs-buflo-ctsp": "CS-BuFLO (CTSP)",
        "cs-buflo-cpsp": "CS-BuFLO (CPSP)",
    }


def test_study_plan_binds_existing_parameter_paths_and_exact_counts() -> None:
    plan = load_study_plan()
    treatments = {item["name"]: item for item in plan["treatments"]}

    for name, (_kind, expected) in PARAMETER_FILES.items():
        if name in treatments:
            assert (STUDY_PLAN.parent / treatments[name]["parameters"]).resolve() == expected
            assert expected.is_file()
    assert plan["controlled"]["expected_samples"] == 160
    assert plan["implementation_baselines"] == {
        "lab_commit": "8988a48a8e43cc9d47505cae12ee7758bc7fa5ee",
        "neqo_commit": "6aceaac85243d6e0e34354108e010705d3c83088",
    }
    assert plan["established_seven_baseline_oracle"] == {
        "path": "config/buflo-study/v1/established-seven-baseline.json",
        "sha256": buflo_study.ESTABLISHED_SEVEN_BASELINE_SHA256,
    }
    assert plan["historical_corpus_guard"]["historical_exporter"] == {
        "path": "tools/classifier_handoff.py",
        "sha256": "f91964df8b6af3b1d89a8c2ff2de1997a59e9ffe36124fa8e20c694515152a72",
    }
    assert plan["regression"]["expected_samples"] == 18
    assert plan["public_stages"]["smoke"]["expected_samples"] == 20
    assert plan["public_stages"]["rehearsal"]["expected_samples"] == 40
    assert plan["public_stages"]["formal"]["expected_samples"] == 1_500
    assert plan["public_stages"]["formal"]["bootstrap_draws"] == 10_000
    assert (
        plan["public_stages"]["formal"]["bootstrap_contract"]
        == buflo_study.FORMAL_BOOTSTRAP_CONTRACT
    )
    assert plan["public_stages"]["formal"]["treatments"] == [
        "undefended",
        "buflo",
        "cs-buflo",
    ]
    assert "cs-buflo-cpsp" not in plan["public_stages"]["formal"]["treatments"]
    assert plan["capture_admission"] == {
        "staged_prerequisites": {
            "smoke": ["regression"],
            "rehearsal": ["regression", "smoke"],
            "formal": ["regression", "smoke", "rehearsal"],
        },
        "reference_gate": "isolated-create-only-conformance-receipt",
        "formal_code_gate": "validated-create-only-code-gate-receipt",
        "source_lineage": "one-exact-clean-collection-image",
        "formal_minimum_available_hours": 12.5,
        "formal_disk_safety_multiplier": 3,
        "formal_disk_projection_basis": ("verified-smoke-plus-rehearsal-bytes-per-sample"),
    }
    assert buflo_study.formal_evaluation_contract_for_cohort(14) is None
    assert (
        buflo_study.formal_evaluation_contract_for_cohort(15)
        == buflo_study.FORMAL_BOOTSTRAP_CONTRACT
    )
    tampered = json.loads(json.dumps(plan))
    tampered["public_stages"]["formal"]["bootstrap_draws"] = 9_999
    with pytest.raises(ValueError, match="formal stage matrix"):
        buflo_study.validate_study_plan(tampered)


def test_established_seven_baseline_rechecks_config_and_behavior_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = validate_established_seven_baseline()
    assert evidence["defenses"] == list(DEFENSE_ORDER[:7])
    assert evidence["passed"] is True

    monkeypatch.setitem(DEFENSE_RUNTIME_KINDS, "front", "tamaraw")
    with pytest.raises(ValueError, match="identities changed"):
        validate_established_seven_baseline()


def test_cs_buflo_provenance_explicitly_receipts_source_live_estimator_divergence() -> None:
    expected = {
        "source_semantics": (
            "author-oracle-advances-16KiB-boundaries-on-actually-transmitted-"
            "real-plus-junk-bytes-per-endpoint-and-direction"
        ),
        "live_semantics": (
            "qcsd-live-advances-16KiB-boundaries-on-exact-fresh-application-"
            "stream-bytes-outgoing-excludes-retransmission-and-defense-added-"
            "bytes-and-uses-consumed-application-offsets-incoming"
        ),
        "rate_boundary_translation_version": 2,
        "rate_boundary_counter_semantics": (
            "client_only_quic_fresh_application_stream_bytes_outgoing_"
            "retransmission_excluded_and_consumed_application_offsets_incoming"
        ),
        "author_rate_boundary_counter_semantics": (
            "per_direction_actually_transmitted_real_plus_junk_bytes"
        ),
        "translation_classification": "expected-client-only-qcsd-adaptation-difference",
        "early_termination_semantics": (
            "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing"
        ),
        "expected_difference": (
            "adaptation-boundary-crossings-and-rate-transition-times-may-differ-"
            "from-the-author-artifact"
        ),
    }
    for treatment in ("cs-buflo-ctsp", "cs-buflo-cpsp"):
        parameter = PARAMETER_FILES[treatment][1]
        provenance = json.loads(
            parameter.with_name(parameter.name + ".provenance.json").read_text(encoding="utf-8")
        )
        assert {key: provenance[key] for key in expected} == expected


def test_buflo_provenance_binds_exact_terminal_summary_contract() -> None:
    parameter = PARAMETER_FILES["buflo"][1]
    provenance = json.loads(
        parameter.with_name(parameter.name + ".provenance.json").read_text(encoding="utf-8")
    )
    assert provenance["terminal_subcell_policy"] == (
        "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
    )
    assert provenance["terminal_subcell_observer_effect"] == (
        "typed_stop_sending_and_reset_stream_defense_control_may_follow_the_last_exact_cell"
    )
    assert provenance["terminal_subcell_policy"] == BUFLO_TERMINAL_SUBCELL_POLICY
    assert provenance["terminal_subcell_observer_effect"] == BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT
    assert provenance["terminal_translation_version"] == 2
    assert provenance["terminal_parser_safety"] == (
        "latch-requires-zero-live-parser-lease-bytes-and-zero-pending-"
        "application-parser-boundaries;pending-reviewed-chaff-parser-"
        "boundaries-are-counted-and-cancelled-with-their-streams"
    )


def _formal_performance_evaluation_fixture() -> dict[str, object]:
    modes = ("undefended", "buflo", "cs-buflo")
    defended = ("buflo", "cs-buflo")
    workloads = buflo_study.WORKLOADS
    directional = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "direction": direction,
            "samples": 10,
        }
        for mode in modes
        for workload in workloads
        for block in range(10)
        for direction in ("outgoing", "incoming")
    ]
    client = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": 10,
        }
        for mode in modes
        for workload in workloads
        for block in range(10)
    ]
    paired_directional = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "direction": direction,
            "pairs": 10,
        }
        for mode in defended
        for workload in workloads
        for block in range(10)
        for direction in ("outgoing", "incoming")
    ]
    paired_client = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "pairs": 10,
        }
        for mode in defended
        for workload in workloads
        for block in range(10)
    ]
    required_costs = (
        "user_cpu_seconds",
        "system_cpu_seconds",
        "wall_time_seconds",
        "maximum_rss_bytes",
        "voluntary_context_switches",
        "involuntary_context_switches",
        "timer_wakeups",
        "transport_retransmissions",
    )
    mode_client = [
        {
            "defense": mode,
            "pairs": 500,
            "paired_client_costs": {metric: {"available": True} for metric in required_costs},
            "completion_ratio_block_workload_bootstrap_95": {},
            "added_seconds_block_workload_bootstrap_95": {},
            "goodput_ratio_block_workload_bootstrap_95": {},
        }
        for mode in defended
    ]
    algorithm_strata = [
        {
            "defense": mode,
            "workload_id": workload,
            "acquisition_block_index": block,
            "direction": direction,
            "samples": 10,
        }
        for mode in modes
        for workload in workloads
        for block in range(10)
        for direction in ("outgoing", "incoming")
    ]
    tail = [
        {
            "defense": "buflo",
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": 10,
            "samples_with_cancellation": 0,
            "terminal_subcell_policy": [BUFLO_TERMINAL_SUBCELL_POLICY],
            "terminal_subcell_observer_effect": [BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT],
            "control_evidence_semantics": [BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS],
            "stream_cancellations": 0,
            "receipt_cancellations": 0,
            "typed_cancellation_action_events": 0,
            "pending_request_cancellations": 0,
            "open_streams_at_latch": 0,
            "parser_lease_bytes_at_latch": 0,
            "pending_parser_boundaries_at_latch": 0,
            "pending_application_parser_boundaries_at_latch": 0,
            "exact_capacity_bytes_cancelled": {
                "total": 0,
                "minimum": 0,
                "maximum": 0,
                "p50": 0.0,
                "p90": 0.0,
                "p95": 0.0,
            },
            "terminal_latched_at_us": {
                "p50": 10_000_001.0,
                "p90": 10_000_002.0,
                "p95": 10_000_003.0,
            },
            "post_cancellation_unscheduled_defense_control_packets": 0,
            "post_cancellation_unscheduled_defense_control_bytes": 0,
        }
        for workload in workloads
        for block in range(10)
    ]
    schedule_stop = [
        {
            "defense": "buflo",
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": 10,
            "policy": [BUFLO_SCHEDULE_STOP_POLICY],
            "terminal_time_semantics": [BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS],
            "latched_samples": 10,
            "latched_at_us": {
                "minimum": 10_000_000,
                "maximum": 10_000_003,
                "p50": 10_000_001.0,
                "p90": 10_000_002.0,
                "p95": 10_000_003.0,
            },
            "available_bytes": {
                "total": 0,
                "minimum": 0,
                "maximum": 0,
                "p50": 0.0,
                "p90": 0.0,
                "p95": 0.0,
            },
            "required_bytes": [1_200],
            "samples_with_incoming_drain": 10,
            "directions": {
                "outgoing": {
                    "scheduled_cells_at_stop": 50,
                    "terminal_cells_at_stop": 50,
                    "drained_cells_after_stop": 0,
                    "last_scheduled_target_us": {
                        "minimum": 10_000_000,
                        "maximum": 10_000_000,
                        "p50": 10_000_000.0,
                        "p90": 10_000_000.0,
                        "p95": 10_000_000.0,
                    },
                    "last_terminal_at_us": {
                        "minimum": 9_999_990,
                        "maximum": 9_999_999,
                        "p50": 9_999_995.0,
                        "p90": 9_999_998.0,
                        "p95": 9_999_999.0,
                    },
                    "terminal_cells_strictly_before_stop": 50,
                    "terminal_cells_at_or_before_stop": 50,
                    "terminal_cells_at_stop_timestamp": 0,
                },
                "incoming": {
                    "scheduled_cells_at_stop": 50,
                    "terminal_cells_at_stop": 40,
                    "drained_cells_after_stop": 10,
                    "last_scheduled_target_us": {
                        "minimum": 10_000_000,
                        "maximum": 10_000_000,
                        "p50": 10_000_000.0,
                        "p90": 10_000_000.0,
                        "p95": 10_000_000.0,
                    },
                    "last_terminal_at_us": {
                        "minimum": 10_000_001,
                        "maximum": 10_000_010,
                        "p50": 10_000_005.0,
                        "p90": 10_000_009.0,
                        "p95": 10_000_010.0,
                    },
                    "terminal_cells_strictly_before_stop": 40,
                    "terminal_cells_at_or_before_stop": 40,
                    "terminal_cells_at_stop_timestamp": 0,
                },
            },
        }
        for workload in workloads
        for block in range(10)
    ]
    cs_local_et = [
        {
            "defense": "cs-buflo",
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": 10,
            "before_application_complete_samples": 0,
            "latched_at_us": {
                "p50": 2_000_001.0,
                "p90": 2_000_002.0,
                "p95": 2_000_003.0,
            },
            "pending_request_cancellations": 0,
            "stream_cancellations": 0,
            "application_receive_streams_handed_off": 0,
            "application_parser_boundaries_handed_off": 0,
            "application_parser_lease_bytes_handed_off": 0,
            "application_send_endpoints_released": 0,
            "post_local_et_natural_outgoing_bytes": 0,
            "post_local_et_natural_incoming_bytes": 0,
        }
        for workload in workloads
        for block in range(10)
    ]
    return {
        "performance_breakdowns": {
            "directional": directional,
            "client": client,
            "paired_directional_by_workload_block": paired_directional,
            "paired_client_by_workload_block": paired_client,
            "paired_mode_direction_block_workload_bootstrap_95": [
                {
                    "defense": mode,
                    "direction": direction,
                    "pairs": 500,
                }
                for mode in defended
                for direction in ("outgoing", "incoming")
            ],
            "paired_mode_client_block_workload_bootstrap_95": mode_client,
        },
        "algorithm_breakdowns": {
            "schema_version": 3,
            "available": True,
            "classifier_input": False,
            "strata": algorithm_strata,
            "buflo_terminal_tail_strata": tail,
            "buflo_schedule_stop_strata": schedule_stop,
            "cs_buflo_local_termination_strata": cs_local_et,
        },
        "paired_per_visit": [{} for _ in range(1_000)],
        "paired_metrics": {
            "buflo": {"pairs": 500},
            "cs-buflo": {"pairs": 500},
        },
    }


def test_formal_performance_gate_requires_exact_axes_and_terminal_tail() -> None:
    value = _formal_performance_evaluation_fixture()
    evidence = buflo_study._validate_formal_performance_evidence(value)
    assert evidence["buflo_terminal_tail_strata"] == 50
    assert evidence["buflo_terminal_tail_samples"] == 500
    assert evidence["buflo_schedule_stop_strata"] == 50
    assert evidence["buflo_schedule_stop_samples"] == 500
    assert evidence["buflo_schedule_stop_incoming_drained_cells"] == 500
    assert evidence["cs_buflo_local_termination_strata"] == 50

    mutations = []
    duplicate_algorithm = json.loads(json.dumps(value))
    duplicate_algorithm["algorithm_breakdowns"]["strata"][0].update(
        duplicate_algorithm["algorithm_breakdowns"]["strata"][1]
    )
    mutations.append(duplicate_algorithm)
    duplicate_performance = json.loads(json.dumps(value))
    duplicate_performance["performance_breakdowns"]["directional"][0].update(
        duplicate_performance["performance_breakdowns"]["directional"][1]
    )
    mutations.append(duplicate_performance)
    nonzero_zero_tail = json.loads(json.dumps(value))
    capacity = nonzero_zero_tail["algorithm_breakdowns"]["buflo_terminal_tail_strata"][0][
        "exact_capacity_bytes_cancelled"
    ]
    capacity.update({"total": 10, "minimum": 1, "maximum": 1, "p50": 1, "p90": 1, "p95": 1})
    mutations.append(nonzero_zero_tail)
    parser_backlog = json.loads(json.dumps(value))
    parser_backlog["algorithm_breakdowns"]["buflo_terminal_tail_strata"][0][
        "parser_lease_bytes_at_latch"
    ] = 1
    mutations.append(parser_backlog)
    wrong_policy = json.loads(json.dumps(value))
    wrong_policy["algorithm_breakdowns"]["buflo_terminal_tail_strata"][0][
        "terminal_subcell_policy"
    ] = ["drifted"]
    mutations.append(wrong_policy)
    mismatched_counters = json.loads(json.dumps(value))
    mismatched_counters["algorithm_breakdowns"]["buflo_terminal_tail_strata"][0][
        "receipt_cancellations"
    ] = 1
    mutations.append(mismatched_counters)
    wrong_stop_policy = json.loads(json.dumps(value))
    wrong_stop_policy["algorithm_breakdowns"]["buflo_schedule_stop_strata"][0]["policy"] = [
        "drifted"
    ]
    mutations.append(wrong_stop_policy)
    wrong_time_semantics = json.loads(json.dumps(value))
    wrong_time_semantics["algorithm_breakdowns"]["buflo_schedule_stop_strata"][0][
        "terminal_time_semantics"
    ] = ["drifted"]
    mutations.append(wrong_time_semantics)
    outgoing_drain = json.loads(json.dumps(value))
    outgoing_drain["algorithm_breakdowns"]["buflo_schedule_stop_strata"][0]["directions"][
        "outgoing"
    ]["drained_cells_after_stop"] = 1
    mutations.append(outgoing_drain)
    missing_schedule_stop = json.loads(json.dumps(value))
    missing_schedule_stop["algorithm_breakdowns"]["buflo_schedule_stop_strata"].pop()
    mutations.append(missing_schedule_stop)
    missing_handoff = json.loads(json.dumps(value))
    missing_handoff["algorithm_breakdowns"]["cs_buflo_local_termination_strata"][0][
        "before_application_complete_samples"
    ] = 1
    mutations.append(missing_handoff)
    post_without_early_et = json.loads(json.dumps(value))
    post_without_early_et["algorithm_breakdowns"]["cs_buflo_local_termination_strata"][0][
        "post_local_et_natural_outgoing_bytes"
    ] = 1
    mutations.append(post_without_early_et)
    zero_latch = json.loads(json.dumps(value))
    zero_latch["algorithm_breakdowns"]["cs_buflo_local_termination_strata"][0]["latched_at_us"][
        "p50"
    ] = 0
    mutations.append(zero_latch)

    for changed in mutations:
        with pytest.raises(ValueError, match="formal"):
            buflo_study._validate_formal_performance_evidence(changed)


@pytest.mark.parametrize(
    ("rank", "observed"),
    (
        (0, [{"kind": "noqueue", "root": True}]),
        (
            1,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "limit": 1_000,
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                    },
                }
            ],
        ),
        (
            2,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                        "rate": {
                            "rate": 625_000,
                            "packetoverhead": 0,
                            "cellsize": 0,
                            "celloverhead": 0,
                        },
                        "limit": 100,
                    },
                }
            ],
        ),
        (
            3,
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "limit": 1_000,
                        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
                        "loss-random": {"loss": 0.01, "correlation": 0},
                    },
                }
            ],
        ),
    ),
)
def test_historical_controlled_receipt_requires_exact_bilateral_qdisc_evidence(
    rank: int, observed: list[dict[str, object]]
) -> None:
    profile = load_study_plan()["controlled"]["netem_profiles"][rank]
    endpoint = {
        "interface": "eth0",
        "applied_qdisc": profile["client_qdisc"],
        "observed_qdisc": observed,
    }
    receipt = {
        "schema_version": 2,
        "stage": "controlled",
        "netem_profile": profile["id"],
        "netem_rank": rank,
        "client_qdisc": profile["client_qdisc"],
        "server_qdisc": profile["server_qdisc"],
        "workload_aliases": {
            "local-large": "local-large",
            "local-small": "local-small",
        },
        "fixture_scope": "controlled-live-manifests-including-two-origin-local-large",
        "treatment_order": [
            "undefended",
            "buflo",
            "cs-buflo-cpsp",
            "cs-buflo-ctsp",
        ],
        "evidence_class": "controlled-test-only-nonformal",
        "network": {
            "schema_version": 1,
            "artifact_type": "qcsd-buflo-controlled-network-v1",
            "image_digest": "sha256:" + "a" * 64,
            "network": "qcsd-buflo-study-v1",
            "client": {"role": "client", **endpoint},
            "servers": [
                {
                    "role": "server",
                    "alias": alias,
                    **endpoint,
                    "applied_qdisc": profile["server_qdisc"],
                }
                for alias in (
                    "qcsd-buflo-server-one",
                    "qcsd-buflo-server-two",
                )
            ],
            "directional_coverage": {
                "client_to_server": {
                    "shaped_egress": "client:eth0",
                    "opposite_ingress": "servers:eth0",
                },
                "server_to_client": {
                    "shaped_egress": "servers:eth0",
                    "opposite_ingress": "client:eth0",
                },
            },
        },
    }

    assert validate_controlled_campaign_receipt(receipt)["netem_rank"] == rank
    historical = dict(receipt)
    historical.pop("fixture_scope")
    historical["schema_version"] = 1
    assert validate_controlled_campaign_receipt(historical)["netem_rank"] == rank
    stripped = dict(receipt)
    stripped.pop("fixture_scope")
    with pytest.raises(ValueError, match="fields are invalid"):
        validate_controlled_campaign_receipt(stripped)
    changed_scope = json.loads(json.dumps(receipt))
    changed_scope["fixture_scope"] = "same-origin-regression-surrogates"
    with pytest.raises(ValueError, match="matrix binding"):
        validate_controlled_campaign_receipt(changed_scope)
    changed = json.loads(json.dumps(receipt))
    changed["network"]["directional_coverage"]["server_to_client"]["opposite_ingress"] = (
        "unobserved"
    )
    with pytest.raises(ValueError, match="bilateral"):
        validate_controlled_campaign_receipt(changed)


def _shared_router_address(interface: str, ipv4: str | None) -> list[dict[str, object]]:
    addr_info: list[dict[str, object]] = []
    if ipv4 is not None:
        address, prefix = ipv4.split("/")
        addr_info.append({"family": "inet", "local": address, "prefixlen": int(prefix)})
    return [
        {
            "ifname": interface,
            "flags": ["BROADCAST", "UP", "LOWER_UP"],
            "mtu": 1_500,
            "addr_info": addr_info,
        }
    ]


def _shared_router_offloads(interface: str) -> list[dict[str, object]]:
    return [
        {
            "ifname": interface,
            "generic-receive-offload": {"active": False},
            "generic-segmentation-offload": {"active": False},
            "tcp-segmentation-offload": {"active": False},
            "tx-udp-segmentation": {"active": False},
        }
    ]


def _shared_router_netem(profile: str, handle: str) -> dict[str, object]:
    options: dict[str, object] = {
        "limit": 100 if "limit 100" in profile else 1_000,
        "delay": {"delay": 0.025, "jitter": 0, "correlation": 0},
        "ecn": False,
        "gap": 0,
    }
    if "rate 5mbit" in profile:
        options["rate"] = {
            "rate": 625_000,
            "packetoverhead": 0,
            "cellsize": 0,
            "celloverhead": 0,
        }
    if "loss 1%" in profile:
        options["loss-random"] = {"loss": 0.01, "correlation": 0}
    return {"kind": "netem", "handle": handle, "root": True, "options": options}


def _shared_router_routes(
    own_subnet: str,
    own_gateway: str,
    own_ip: str,
    remote_subnet: str,
    remote_router: str,
    interface: str,
) -> list[dict[str, object]]:
    return [
        {"dst": "default", "gateway": own_gateway, "dev": interface, "flags": []},
        {
            "dst": own_subnet,
            "dev": interface,
            "flags": [],
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": own_ip,
        },
        {"dst": remote_subnet, "gateway": remote_router, "dev": interface, "flags": []},
    ]


def _shared_router_receipt(
    monkeypatch: pytest.MonkeyPatch, rank: int, *, handle_suffix: str = ""
) -> dict[str, object]:
    profile = load_study_plan()["controlled"]["netem_profiles"][rank]
    client_name = "qcsd-buflo-study-v15-client"
    server_name = "qcsd-buflo-study-v15-server"
    client_subnet, server_subnet, base = buflo_study._controlled_network_pair(
        client_name, server_name
    )
    client_gateway = str(client_subnet.network_address + 1)
    router_client = str(client_subnet.network_address + 2)
    client_ip = str(client_subnet.network_address + 3)
    server_gateway = str(server_subnet.network_address + 1)
    router_server = str(server_subnet.network_address + 2)
    server_ips = [
        str(server_subnet.network_address + 3),
        str(server_subnet.network_address + 4),
    ]
    noqueue = [{"kind": "noqueue", "root": True, "options": {}}]
    ifb_default = [{"kind": "fq_codel", "root": True, "options": {}}]
    impaired = rank != 0
    router_eth0_qdisc = (
        [
            _shared_router_netem(profile["server_qdisc"], f"20{handle_suffix}:"),
            {"kind": "ingress", "handle": "ffff:", "parent": "ffff:fff1", "options": {}},
        ]
        if impaired
        else noqueue
    )
    router_ifb_qdisc = (
        [_shared_router_netem(profile["client_qdisc"], f"10{handle_suffix}:")]
        if impaired
        else ifb_default
    )
    ingress_filter: list[dict[str, object]] = []
    if impaired:
        ingress_filter = [
            {"protocol": "all", "kind": "u32"},
            {"protocol": "all", "kind": "u32", "options": {"ht_divisor": 1}},
            {
                "protocol": "all",
                "kind": "u32",
                "options": {
                    "match": {"value": "0", "mask": "0", "off": 0},
                    "actions": [
                        {
                            "kind": "mirred",
                            "mirred_action": "redirect",
                            "direction": "egress",
                            "to_dev": "ifb0",
                            "control_action": {"type": "stolen"},
                        }
                    ],
                },
            },
        ]
    router_routes = [
        {"dst": "default", "gateway": client_gateway, "dev": "eth0", "flags": []},
        {
            "dst": str(client_subnet),
            "dev": "eth0",
            "flags": [],
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": router_client,
        },
        {
            "dst": str(server_subnet),
            "dev": "eth1",
            "flags": [],
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": router_server,
        },
    ]
    servers = []
    for suffix, alias, server_ip in zip(
        ("one", "two"),
        ("qcsd-buflo-server-one", "qcsd-buflo-server-two"),
        server_ips,
        strict=True,
    ):
        servers.append(
            {
                "container": f"{base}-server-{suffix}",
                "alias": alias,
                "addresses": {"eth0": _shared_router_address("eth0", f"{server_ip}/24")},
                "qdiscs": {"eth0": noqueue},
                "offloads": {"eth0": _shared_router_offloads("eth0")},
                "routes": _shared_router_routes(
                    str(server_subnet),
                    server_gateway,
                    server_ip,
                    str(client_subnet),
                    router_server,
                    "eth0",
                ),
            }
        )
    raw = {
        "schema_version": 1,
        "client_network": {
            "name": client_name,
            "ipam": [{"Subnet": str(client_subnet), "IPRange": "", "Gateway": client_gateway}],
        },
        "server_network": {
            "name": server_name,
            "ipam": [{"Subnet": str(server_subnet), "IPRange": "", "Gateway": server_gateway}],
        },
        "router": {
            "container": f"{base}-router",
            "addresses": {
                "eth0": _shared_router_address("eth0", f"{router_client}/24"),
                "eth1": _shared_router_address("eth1", f"{router_server}/24"),
                "ifb0": _shared_router_address("ifb0", None),
            },
            "qdiscs": {
                "eth0": router_eth0_qdisc,
                "eth1": noqueue,
                "ifb0": router_ifb_qdisc,
            },
            "offloads": {
                "eth0": _shared_router_offloads("eth0"),
                "eth1": _shared_router_offloads("eth1"),
            },
            "routes": router_routes,
            "client_ingress_filters": ingress_filter,
            "ip_forward": 1,
        },
        "servers": servers,
    }
    client_observation = {
        "addresses": {"eth0": _shared_router_address("eth0", f"{client_ip}/24")},
        "qdiscs": {"eth0": noqueue},
        "offloads": {"eth0": _shared_router_offloads("eth0")},
        "routes": _shared_router_routes(
            str(client_subnet),
            client_gateway,
            client_ip,
            str(server_subnet),
            router_client,
            "eth0",
        ),
        "hosts": {
            "qcsd-buflo-server-one": [server_ips[0]],
            "qcsd-buflo-server-two": [server_ips[1]],
        },
    }
    monkeypatch.setattr(buflo_study, "_observe_client_namespace", lambda: client_observation)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)
    evidence = base64.b64encode(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    network_receipt = buflo_study._build_shared_router_network_receipt(
        network=client_name,
        controlled_network_evidence_b64=evidence,
        client_qdisc=profile["client_qdisc"],
        server_qdisc=profile["server_qdisc"],
        cohort_version=15,
    )
    return {
        "schema_version": buflo_study.LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        "stage": "controlled",
        "netem_profile": profile["id"],
        "netem_rank": rank,
        "client_qdisc": profile["client_qdisc"],
        "server_qdisc": profile["server_qdisc"],
        "workload_aliases": {"local-large": "local-large", "local-small": "local-small"},
        "fixture_scope": "controlled-live-manifests-including-two-origin-local-large",
        "cohort_version": 15,
        "treatment_order": ["undefended", "buflo", "cs-buflo-cpsp", "cs-buflo-ctsp"],
        "evidence_class": "controlled-test-only-nonformal",
        "network": network_receipt,
    }


@pytest.mark.parametrize("rank", range(4))
def test_shared_router_receipt_binds_exact_once_per_direction_topology(
    monkeypatch: pytest.MonkeyPatch, rank: int
) -> None:
    receipt = _shared_router_receipt(monkeypatch, rank)
    assert validate_controlled_campaign_receipt(receipt)["netem_rank"] == rank
    assert receipt["network"]["capture_point"]["endpoint_impairment_qdiscs"] == 0
    if rank == 2:
        assert receipt["network"]["rate_aggregation"]["scope"] == (
            "one-shared-qdisc-per-direction-across-both-server-origins"
        )


def test_regression_receipt_binds_the_separate_two_origin_nine_mode_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _shared_router_receipt(monkeypatch, 0)
    receipt.update(
        {
            "stage": "regression",
            "workload_aliases": {"complex": "local-large", "simple": "local-small"},
            "fixture_scope": (
                "single-origin-prefix-regression-plus-bound-two-origin-nine-mode-compatibility"
            ),
            "treatment_order": list(load_study_plan()["regression"]["treatments"]),
        }
    )

    assert validate_controlled_campaign_receipt(receipt)["fixture_scope"].endswith(
        "nine-mode-compatibility"
    )
    historical = {
        **receipt,
        "schema_version": buflo_study.PREVIOUS_LOCAL_CAMPAIGN_RECEIPT_SCHEMA_VERSION,
        "fixture_scope": "same-origin-regression-surrogates",
    }
    assert validate_controlled_campaign_receipt(historical)["schema_version"] == 3
    invalid_current = {**receipt, "fixture_scope": "same-origin-regression-surrogates"}
    with pytest.raises(ValueError, match="matrix binding"):
        validate_controlled_campaign_receipt(invalid_current)


def test_shared_router_receipt_normalizes_nondeterministic_qdisc_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _shared_router_receipt(monkeypatch, 2, handle_suffix="1")
    second = _shared_router_receipt(monkeypatch, 2, handle_suffix="9")
    assert first == second


@pytest.mark.parametrize(
    ("location", "key"),
    (
        ("top", "distribution"),
        ("delay", "reorder"),
        ("rate", "slot"),
        ("loss-random", "seed"),
    ),
)
def test_shared_router_netem_rejects_unknown_raw_options(location: str, key: str) -> None:
    options = _shared_router_netem("netem delay 25ms rate 5mbit limit 100 loss 1%", "10:")[
        "options"
    ]
    assert isinstance(options, dict)
    if location == "top":
        options[key] = 1
    else:
        nested = options[location]
        assert isinstance(nested, dict)
        nested[key] = 1
    with pytest.raises(ValueError, match="controlled netem"):
        buflo_study._canonical_netem_options(options)


def test_shared_router_route_rejects_unreceipted_packetization_attributes() -> None:
    routes = [
        {
            "dst": "default",
            "gateway": "10.0.0.1",
            "dev": "eth0",
            "flags": [],
            "mtu": 576,
        }
    ]
    with pytest.raises(ValueError, match="controlled route row"):
        buflo_study._canonical_routes(routes)


@pytest.mark.parametrize(
    "tamper",
    (
        "ip-forward",
        "router-interface",
        "client-route",
        "client-hosts",
        "ifb-netem",
        "ingress-filter",
        "client-qdisc",
        "server-qdisc",
        "router-offload",
        "coverage-count",
        "aggregate-scope",
        "cohort-version",
    ),
)
def test_shared_router_receipt_rejects_network_evidence_tampering(
    monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    receipt = _shared_router_receipt(monkeypatch, 2)
    changed = json.loads(json.dumps(receipt))
    network = changed["network"]
    if tamper == "ip-forward":
        network["router"]["ip_forward"] = 0
    elif tamper == "router-interface":
        network["router"]["observed_addresses"]["eth0"]["ipv4"] = network["router"][
            "observed_addresses"
        ]["eth1"]["ipv4"]
    elif tamper == "client-route":
        network["client"]["observed_routes"][0]["gateway"] = "10.0.0.254"
    elif tamper == "client-hosts":
        network["client"]["observed_hosts"]["qcsd-buflo-server-one"] = ["10.0.0.9"]
    elif tamper == "ifb-netem":
        network["router"]["observed_qdiscs"]["ifb0"][0]["netem"]["rate_bytes_per_second"] = (
            1_250_000
        )
    elif tamper == "ingress-filter":
        network["router"]["observed_client_ingress_filter"]["action"]["to_device"] = "eth1"
    elif tamper == "client-qdisc":
        network["client"]["observed_qdiscs"] = network["router"]["observed_qdiscs"]["ifb0"]
    elif tamper == "server-qdisc":
        network["servers"][0]["observed_qdiscs"] = network["router"]["observed_qdiscs"]["eth0"]
    elif tamper == "router-offload":
        network["router"]["observed_offloads"]["eth0"]["gso"] = True
    elif tamper == "coverage-count":
        network["directional_coverage"]["client_to_server"]["impairment_applications"] = 2
    elif tamper == "aggregate-scope":
        network["rate_aggregation"]["scope"] = "per-origin"
    elif tamper == "cohort-version":
        changed["cohort_version"] = 16
    with pytest.raises(ValueError, match="controlled"):
        validate_controlled_campaign_receipt(changed)


def test_validation_attestation_promotion_is_fail_closed(tmp_path: Path) -> None:
    attestation = tmp_path / "validation-attestation.json"
    attestation.write_text(
        json.dumps({"implementation_status": "validated-client-only-qcsd-adaptation"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="typed evidence is missing"):
        validate_validation_attestation(attestation)


def test_new_formal_artifacts_cannot_bypass_v15_contract(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="formal cohort creation requires cohort version 15"):
        buflo_study.create_formal_cohort_manifest(
            tmp_path / "cohort.json",
            cohort_id="legacy-new-formal",
            results_root=tmp_path / "results",
            historical_pre_snapshot=tmp_path / "pre.json",
            cohort_version=14,
        )

    with pytest.raises(ValueError, match="formal capture admission requires cohort version 15"):
        buflo_study.create_capture_admission(
            tmp_path / "admission.json",
            stage="formal",
            reference_receipt=tmp_path / "reference.json",
            qualification_receipt=tmp_path / "qualification.json",
            prerequisite_result_roots=(),
            results_root=tmp_path / "results",
            cohort_version=14,
        )


def test_validation_attestation_rejects_each_hard_gate_identity_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {
        "reference_receipt": {"path": "reference.json"},
        "code_gate_receipt": {"path": "code-gate.json"},
        "qualification_receipt": {"path": "qualification.json"},
        "regression_results": [{"root": "regression"}],
        "controlled_results": [{"root": "controlled"}],
        "smoke_result": {"root": "smoke"},
        "rehearsal_result": {"root": "rehearsal"},
        "formal_results": [{"root": f"formal-{index}"} for index in range(10)],
        "capture_admission": {"path": "admission.json"},
        "formal_cohort": {"path": "cohort.json"},
        "handoff": {"root": "handoff"},
        "evaluation_receipt": {"path": "evaluation.json"},
        "comparison_review": {"path": "comparison.json"},
        "historical_pre_snapshot": {"path": "pre.json"},
        "historical_post_snapshot": {"path": "post.json"},
    }
    canonical = {
        "schema_version": 2,
        "artifact_type": buflo_study.ATTESTATION_ARTIFACT_TYPE,
        "study_id": buflo_study.BUFLO_STUDY_ID,
        "cohort_version": 15,
        "qualification_set": "buflo-study-public5-v15",
        "study_plan": {"path": "study.json", "sha256": "b" * 64},
        "implementation_status": buflo_study.VALIDATED_STATUS,
        "implementation_status_description": buflo_study.VALIDATED_STATUS_DESCRIPTION,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "no_waivers": True,
        "source": {},
        "evidence": evidence,
        "validation_summary": {},
        "hard_gates": buflo_study._hard_gate_records(["a" * 64], schema_version=2),
        "all_hard_gates_passed": True,
    }
    monkeypatch.setattr(
        buflo_study,
        "_validation_attestation_value",
        lambda **_kwargs: canonical,
    )
    valid = tmp_path / "valid-attestation.json"
    valid.write_text(json.dumps(canonical), encoding="utf-8")
    assert validate_validation_attestation(valid, deep_code_gate=False)["cohort_version"] == 15

    for index in range(len(buflo_study.HARD_GATE_IDENTITIES)):
        tampered = json.loads(json.dumps(canonical))
        forged_gate = tampered["hard_gates"][index]["gate"] + "-tampered"
        tampered["hard_gates"][index]["gate"] = forged_gate
        tampered["hard_gates"][index]["gate_identity_sha256"] = (
            buflo_study._hard_gate_identity_sha256(index + 1, forged_gate)
        )
        path = tmp_path / f"tampered-gate-{index + 1:02d}.json"
        path.write_text(json.dumps(tampered), encoding="utf-8")
        with pytest.raises(ValueError, match=f"ordinal {index + 1}"):
            validate_validation_attestation(path, deep_code_gate=False)


def test_study_plan_rejects_each_hard_gate_identity_tamper() -> None:
    plan = load_study_plan()
    for index in range(len(buflo_study.HARD_GATE_IDENTITIES)):
        tampered = json.loads(json.dumps(plan))
        tampered["hard_gates"][index] += "-tampered"
        with pytest.raises(ValueError, match="immutable ordered identities"):
            buflo_study.validate_study_plan(tampered)


def test_local_workload_preparation_freezes_real_probe_receipts_without_synthesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = {
        "resources": [
            buflo_study._local_resource(
                0,
                "https://qcsd-buflo-server-one:4433/1024",
                "Document",
                1_024,
            )
        ]
    }
    response = {
        "resource_id": 0,
        "status": 200,
        "bytes": 1_024,
        "body_sha256": "a" * 64,
        "complete": True,
        "outcome": "succeeded",
        "request_headers": [["accept", "text/html"]],
    }
    runs = [
        {
            "neqo_version": "test-neqo",
            "neqo_base_commit": "1" * 40,
            "published_qcsd_commit": "2" * 40,
            "migration_commit": "3" * 40,
            "responses": [response],
        }
        for _index in range(3)
    ]
    directional_statistics = {
        "packet_count": 1,
        "observed_udp_payload_max": 1_200,
        "oversized_packet_count": 0,
    }
    total_statistics = {**directional_statistics, "packet_count": 2}
    udp = {
        "schema_version": 1,
        "configured_udp_payload_ceiling": 1_200,
        "runs": [
            {
                "run_index": index,
                "packets_sha256": chr(ord("d") + index) * 64,
                "incoming": directional_statistics,
                "outgoing": directional_statistics,
                "total": total_statistics,
            }
            for index in range(3)
        ],
    }

    def probe(
        *_args: object, **_kwargs: object
    ) -> tuple[dict[str, object], list[dict[str, object]], dict[str, object]]:
        return (
            {
                "runs": 3,
                "stable_resource_ids": [0],
                "expected_responses": [
                    {
                        key: response[key]
                        for key in ("resource_id", "status", "bytes", "body_sha256")
                    }
                ],
            },
            runs,
            udp,
        )

    monkeypatch.setattr("qcsd_lab.prepare._probe_response_stability", probe)
    monkeypatch.setattr(
        buflo_study,
        "source_metadata",
        lambda: {
            "image_digest": "sha256:" + "9" * 64,
            "lab_commit": "4" * 40,
            "lab_dirty": True,
            "lab_patch_sha256": "5" * 64,
            "neqo_commit": "3" * 40,
            "neqo_pinned_commit": "3" * 40,
            "neqo_dirty": True,
            "neqo_patch_sha256": "6" * 64,
        },
    )
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "9" * 64)

    buflo_study._prepare_local_workloads(
        tmp_path,
        {"local-probe": workload},
        label="test local workload",
    )

    frozen = json.loads((tmp_path / "local-probe.json").read_text(encoding="utf-8"))
    preparation = frozen["preparation"]
    assert preparation["chromium_version"] == "not-applicable-deterministic-local-server"
    assert preparation["lab_source"]["lab_dirty"] is True
    assert [run["packets_sha256"] for run in preparation["udp_payload_qualification"]["runs"]] == [
        "d" * 64,
        "e" * 64,
        "f" * 64,
    ]
    assert preparation["expected_responses"][0]["body_sha256"] == "a" * 64


def test_controlled_rate_driver_is_separate_bounded_and_live_size_gated() -> None:
    values = {
        workload_id: buflo_study._csbuflo_rate_driver_value(workload_id)
        for workload_id in ("local-small", "local-large")
    }
    assert len(set(values.values())) == 2
    assert all(
        len(value.encode("ascii")) == buflo_study.CSBUFLO_RATE_DRIVER_VALUE_BYTES
        for value in values.values()
    )
    assert buflo_study.CSBUFLO_RATE_DRIVER_VALUE_BYTES < 384 * 1_024
    assert (
        buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
        == buflo_study.CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES
        + 4 * buflo_study.CSBUFLO_RATE_DRIVER_CELL_BYTES
    )

    driver = buflo_study._controlled_csbuflo_rate_driver(1, "local-small")
    resources = [
        buflo_study._local_resource(
            0,
            "https://qcsd-buflo-server-one:4433/131072",
            "Document",
            131_072,
        ),
        driver,
    ]
    response = {
        "resource_id": 1,
        "complete": True,
        "outcome": "succeeded",
        "request_headers": driver["headers"],
        "request_stream_bytes": buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES,
    }
    proof = buflo_study._validate_controlled_csbuflo_rate_driver(
        "local-small",
        resources,
        runs=[{"responses": [response]} for _index in range(3)],
    )
    assert (
        proof["encoded_request_stream_bytes"]
        == [buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES] * 3
    )
    observation = buflo_study._controlled_csbuflo_rate_driver_observation(
        "local-small", {"responses": [response]}
    )
    assert observation["post_boundary_cells"] == 4

    too_short = {**response, "request_stream_bytes": 16_384}
    with pytest.raises(ValueError, match="did not encode beyond"):
        buflo_study._validate_controlled_csbuflo_rate_driver(
            "local-small", resources, runs=[{"responses": [too_short]}]
        )


def test_controlled_driver_does_not_change_regression_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, dict[str, dict[str, object]], bool]] = []

    def capture(
        _root: Path,
        manifests: dict[str, dict[str, object]],
        *,
        label: str,
        require_csbuflo_rate_driver: bool = False,
    ) -> None:
        calls.append((label, manifests, require_csbuflo_rate_driver))

    monkeypatch.setattr(buflo_study, "_prepare_local_workloads", capture)
    buflo_study._create_local_workloads(tmp_path)
    buflo_study._create_regression_workloads(tmp_path)
    buflo_study._create_regression_multi_origin_workload(tmp_path)

    _controlled_label, controlled, controlled_gate = calls[0]
    _regression_label, regression, regression_gate = calls[1]
    _compatibility_label, compatibility, compatibility_gate = calls[2]
    assert controlled_gate is True
    assert regression_gate is False
    assert compatibility_gate is False
    assert [len(controlled[name]["resources"]) for name in ("local-small", "local-large")] == [
        2,
        5,
    ]
    assert [len(regression[name]["resources"]) for name in ("simple", "complex")] == [1, 4]
    assert {
        resource["url"].split("/", 3)[2] for resource in controlled["local-large"]["resources"]
    } == {"qcsd-buflo-server-one:4433", "qcsd-buflo-server-two:4434"}
    assert {
        resource["url"].split("/", 3)[2] for resource in regression["complex"]["resources"]
    } == {"qcsd-buflo-server-one:4433"}
    assert {
        resource["url"].split("/", 3)[2] for resource in compatibility["complex"]["resources"]
    } == {"qcsd-buflo-server-one:4433", "qcsd-buflo-server-two:4434"}
    for workload_id in ("local-small", "local-large"):
        proof = buflo_study._validate_controlled_csbuflo_rate_driver(
            workload_id, controlled[workload_id]["resources"]
        )
        assert proof["resource_id"] == (1 if workload_id == "local-small" else 4)
    assert all(
        buflo_study.CSBUFLO_RATE_DRIVER_HEADER_NAME
        not in {header[0] for resource in manifest["resources"] for header in resource["headers"]}
        for manifest in regression.values()
    )


def _regression_prefix_manifest(workload_id: str) -> dict[str, object]:
    resources = [
        buflo_study._local_resource(
            0,
            "https://qcsd-buflo-server-one:4433/131072",
            "Document",
            131_072,
        )
    ]
    if workload_id == "complex":
        resources.extend(
            [
                buflo_study._local_resource(
                    1,
                    "https://qcsd-buflo-server-one:4433/1024",
                    "Script",
                    1_024,
                    depends_on=[0],
                ),
                buflo_study._local_resource(
                    2,
                    "https://qcsd-buflo-server-one:4433/4096",
                    "Script",
                    4_096,
                    depends_on=[0],
                ),
                buflo_study._local_resource(
                    3,
                    "https://qcsd-buflo-server-one:4433/2048",
                    "Image",
                    2_048,
                    depends_on=[2],
                ),
            ]
        )
    return {
        "preparation": {
            "source_url": resources[0]["url"],
            "final_url": resources[0]["url"],
            "approved_origins": [
                "https://qcsd-buflo-server-one:4433",
            ],
            "expected_responses": [
                {
                    "resource_id": resource["id"],
                    "status": 200,
                    "bytes": resource["data_length"],
                    "body_sha256": f"{resource['id'] + 1:x}" * 64,
                }
                for resource in resources
            ],
        },
        "resources": resources,
    }


def _regression_multi_origin_identity_manifest() -> dict[str, object]:
    manifest = _regression_prefix_manifest("complex")
    resources = manifest["resources"]
    assert isinstance(resources, list)
    for resource in resources:
        if resource["id"] in {2, 3}:
            resource["url"] = resource["url"].replace(
                "qcsd-buflo-server-one:4433", "qcsd-buflo-server-two:4434"
            )
    preparation = manifest["preparation"]
    assert isinstance(preparation, dict)
    preparation["approved_origins"] = list(buflo_study.MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
    preparation["observed_origins"] = list(buflo_study.MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
    return manifest


def _multi_origin_attempt_ledger_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    Path,
    Path,
    Path,
    tuple[SimpleNamespace, ...],
    dict[str, str],
    list[dict[str, object]],
]:
    root = tmp_path / "compatibility"
    mode_root = root / "attempts/wtf-pad"
    rejected = mode_root / "attempt-01"
    accepted = mode_root / "attempt-02"
    rejected.mkdir(parents=True)
    accepted.mkdir()
    (rejected / "attempt.json").write_text(
        json.dumps(
            {
                "success": False,
                "failure": {
                    "stage": "capture",
                    "reason": "direct/runner reconciliation failed",
                },
            }
        ),
        encoding="utf-8",
    )
    (accepted / "attempt.json").write_text(
        json.dumps({"success": True}),
        encoding="utf-8",
    )

    def evidence(
        attempt: Path,
        _application_path: Path,
        _projected_chaff_path: Path,
        defense: SimpleNamespace,
        *,
        seed: int,
        historical_candidate_source: dict[str, object] | None = None,
    ) -> dict[str, object]:
        assert historical_candidate_source is None
        result = json.loads((attempt / "attempt.json").read_text(encoding="utf-8"))
        if result.get("success") is not True:
            raise ValueError("attempt is rejected")
        return {"attempt": str(attempt), "mode": defense.name, "seed": seed}

    monkeypatch.setattr(
        buflo_study,
        "_regression_multi_origin_attempt_evidence",
        evidence,
    )
    application_path = root / "application.json"
    projected_chaff_path = root / "chaff.json"
    defenses = (SimpleNamespace(name="wtf-pad"),)
    relative = "attempts/wtf-pad/attempt-02"
    files = buflo_study._regression_multi_origin_raw_attempt_inventory(accepted)
    samples: list[dict[str, object]] = [
        {
            "mode": "wtf-pad",
            "attempt": relative,
            "files": files,
            "files_sha256": buflo_study._canonical_digest(files),
        }
    ]
    return (
        root,
        application_path,
        projected_chaff_path,
        defenses,
        {"wtf-pad": relative},
        samples,
    )


def _multi_origin_attempt_ledgers(
    fixture: tuple[
        Path,
        Path,
        Path,
        tuple[SimpleNamespace, ...],
        dict[str, str],
        list[dict[str, object]],
    ],
) -> list[dict[str, object]]:
    return buflo_study._regression_multi_origin_attempt_ledgers(*fixture)


def test_regression_multi_origin_attempt_ledger_binds_rejection_before_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)

    [ledger] = _multi_origin_attempt_ledgers(fixture)

    assert ledger["mode"] == "wtf-pad"
    assert ledger["attempt_count"] == 2
    assert ledger["rejected_attempts"] == 1
    assert ledger["accepted_attempt"] == "attempts/wtf-pad/attempt-02"
    rejected, accepted = ledger["attempts"]
    assert rejected["outcome"] == "rejected"
    assert rejected["failure"] == {
        "source": "attempt.json",
        "details": {
            "stage": "capture",
            "reason": "direct/runner reconciliation failed",
        },
    }
    assert rejected["file_count"] == len(rejected["files"]) == 1
    assert accepted["outcome"] == "accepted"
    assert accepted["failure"] is None


def test_regression_multi_origin_attempt_ledger_rejects_tampered_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    original = _multi_origin_attempt_ledgers(fixture)
    attempt = fixture[0] / "attempts/wtf-pad/attempt-01/attempt.json"
    value = json.loads(attempt.read_text(encoding="utf-8"))
    value["failure"]["reason"] = "changed"
    attempt.write_text(json.dumps(value), encoding="utf-8")

    reconstructed = _multi_origin_attempt_ledgers(fixture)
    with pytest.raises(ValueError, match="attempt ledger changed"):
        buflo_study._validate_regression_multi_origin_attempt_ledger_receipt(
            original,
            reconstructed,
        )


def test_regression_multi_origin_attempt_ledger_rejects_deleted_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    (fixture[0] / "attempts/wtf-pad/attempt-01/attempt.json").unlink()

    with pytest.raises(ValueError, match="no terminal evidence"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    mode_root = fixture[0] / "attempts/wtf-pad"
    (mode_root / "attempt-01").rename(tmp_path / "detached-attempt")

    with pytest.raises(ValueError, match="not exact and contiguous"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_attempt_after_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    extra = fixture[0] / "attempts/wtf-pad/attempt-03"
    extra.mkdir()
    (extra / "attempt.json").write_text(
        json.dumps(
            {
                "success": False,
                "failure": {"stage": "capture", "reason": "late extra attempt"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="outcomes are not terminal"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_missing_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    rejected = fixture[0] / "attempts/wtf-pad/attempt-01/attempt.json"
    rejected.write_text(json.dumps({"success": False}), encoding="utf-8")

    with pytest.raises(ValueError, match="lacks its reason"):
        buflo_study._regression_multi_origin_rejection_failure(rejected.parent)
    with pytest.raises(ValueError, match="lacks its reason"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_nonterminal_failure_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    rejected = fixture[0] / "attempts/wtf-pad/attempt-01/attempt.json"
    value = json.loads(rejected.read_text(encoding="utf-8"))
    value["success"] = True
    rejected.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="lacks its reason"):
        buflo_study._regression_multi_origin_rejection_failure(rejected.parent)
    with pytest.raises(ValueError, match="attempt outcomes are not terminal"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejection_marker_is_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    accepted = fixture[0] / "attempts/wtf-pad/attempt-02"
    reason = {
        "schema_version": 1,
        "artifact_type": buflo_study.MULTI_ORIGIN_COMPATIBILITY_ATTEMPT_ERROR_TYPE,
        "failure": {
            "stage": "multi-origin-compatibility-eligibility",
            "type": "ValueError",
            "message": "persisted terminal rejection",
        },
    }
    (accepted / "multi-origin-compatibility-error.json").write_text(
        json.dumps(reason),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="attempt outcomes are not terminal"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_attempt_ledger_rejects_special_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _multi_origin_attempt_ledger_fixture(tmp_path, monkeypatch)
    special = fixture[0] / "attempts/wtf-pad/attempt-01/unbound-fifo"
    os.mkfifo(special)

    with pytest.raises(ValueError, match="special filesystem entry"):
        _multi_origin_attempt_ledgers(fixture)


def test_regression_multi_origin_existing_interrupted_attempt_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt = tmp_path / "attempt-01"
    attempt.mkdir()

    def rejected(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise ValueError("not eligible")

    monkeypatch.setattr(
        buflo_study,
        "_regression_multi_origin_attempt_evidence",
        rejected,
    )
    with pytest.raises(ValueError, match="lacks its reason"):
        buflo_study._regression_multi_origin_existing_attempt_evidence(
            attempt,
            tmp_path / "application.json",
            tmp_path / "chaff.json",
            SimpleNamespace(name="wtf-pad"),
            seed=1,
        )
    assert not (attempt / "multi-origin-compatibility-error.json").exists()


def test_regression_multi_origin_existing_terminal_rejection_is_resume_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt = tmp_path / "attempt-01"
    attempt.mkdir()
    reason = {
        "schema_version": 1,
        "artifact_type": buflo_study.MULTI_ORIGIN_COMPATIBILITY_ATTEMPT_ERROR_TYPE,
        "failure": {
            "stage": "multi-origin-compatibility-collection",
            "type": "RuntimeError",
            "message": "collector failed",
        },
    }
    reason_path = attempt / "multi-origin-compatibility-error.json"
    reason_path.write_text(json.dumps(reason), encoding="utf-8")

    def otherwise_eligible(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"passed": True}

    monkeypatch.setattr(
        buflo_study,
        "_regression_multi_origin_attempt_evidence",
        otherwise_eligible,
    )
    before = reason_path.read_bytes()
    assert (
        buflo_study._regression_multi_origin_existing_attempt_evidence(
            attempt,
            tmp_path / "application.json",
            tmp_path / "chaff.json",
            SimpleNamespace(name="wtf-pad"),
            seed=1,
        )
        is None
    )
    assert reason_path.read_bytes() == before


def test_v36_historical_candidate_schema_path_requires_exact_sealed_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = (
        tmp_path
        / "buflo-study-regression-v36"
        / "multi-origin-nine-mode-compatibility"
        / "receipt.json"
    )
    receipt.parent.mkdir(parents=True)
    receipt.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        buflo_study,
        "source_metadata",
        lambda: {
            **buflo_study.HISTORICAL_MULTI_ORIGIN_V36_SOURCE,
            "lab_commit": "0" * 40,
        },
    )
    monkeypatch.setattr(
        buflo_study,
        "sha256_file",
        lambda path: (
            buflo_study.HISTORICAL_MULTI_ORIGIN_V36_RECEIPT_SHA256
            if Path(path) == receipt
            else "0" * 64
        ),
    )

    selected = buflo_study._regression_multi_origin_historical_candidate_source(
        receipt,
        buflo_study.HISTORICAL_MULTI_ORIGIN_V36_SOURCE,
    )

    assert selected == buflo_study.HISTORICAL_MULTI_ORIGIN_V36_SOURCE
    with pytest.raises(ValueError, match="explicitly frozen source"):
        buflo_study._regression_multi_origin_historical_candidate_source(
            receipt,
            {
                **buflo_study.HISTORICAL_MULTI_ORIGIN_V36_SOURCE,
                "neqo_commit": "0" * 40,
            },
        )


def test_regression_multi_origin_checkpoint_binding_rejects_tamper_and_wrong_acceptance(
    tmp_path: Path,
) -> None:
    root = tmp_path / "compatibility"
    root.mkdir()
    checkpoint = root / "checkpoint.json"
    accepted = {
        mode: f"attempts/{mode}/attempt-01" for mode in buflo_study.MULTI_ORIGIN_COMPATIBILITY_MODES
    }
    value = {
        "schema_version": 1,
        "artifact_type": buflo_study.MULTI_ORIGIN_COMPATIBILITY_CHECKPOINT_TYPE,
        "accepted_attempts": accepted,
    }
    checkpoint.write_text(json.dumps(value), encoding="utf-8")
    binding = {
        "path": "checkpoint.json",
        "sha256": hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
    }
    assert (
        buflo_study._regression_multi_origin_bound_path(
            root,
            binding,
            label="checkpoint",
        )
        == checkpoint.resolve()
    )
    assert (
        buflo_study._validate_regression_multi_origin_checkpoint(
            value,
            require_complete=True,
        )
        == accepted
    )

    value["accepted_attempts"]["wtf-pad"] = "attempts/front/attempt-01"
    checkpoint.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="checkpoint changed"):
        buflo_study._regression_multi_origin_bound_path(
            root,
            binding,
            label="checkpoint",
        )
    with pytest.raises(ValueError, match="checkpoint path is invalid"):
        buflo_study._validate_regression_multi_origin_checkpoint(
            value,
            require_complete=True,
        )


def test_regression_multi_origin_chaff_projection_changes_only_application_hash() -> None:
    strict = {
        "schema_version": 2,
        "application_workload_sha256": "1" * 64,
        "application_resource_id": 0,
        "selected_chaff_resource_id": 0,
        "resources": [{"id": 0, "url": "https://qcsd-buflo-server-one:4433/131072"}],
        "qualification_identity": {"sha256": "2" * 64},
    }
    original = json.loads(json.dumps(strict))

    projected = buflo_study._project_regression_chaff_manifest(
        strict,
        surrogate_sha256="1" * 64,
        application_sha256="3" * 64,
    )

    assert strict == original
    assert projected == {
        **original,
        "application_workload_sha256": "3" * 64,
    }


def test_regression_multi_origin_identity_retains_both_endpoints_and_all_resources_in_every_mode(
    tmp_path: Path,
) -> None:
    from qcsd_lab.fitting_walkie_talkie import receiver_continuation_contract

    manifest = _regression_multi_origin_identity_manifest()
    resources = manifest["resources"]
    preparation = manifest["preparation"]
    assert isinstance(resources, list) and isinstance(preparation, dict)
    expected = {response["resource_id"]: response for response in preparation["expected_responses"]}
    run = {
        "endpoints": [
            {"id": 0, "origin": "https://qcsd-buflo-server-one:4433"},
            {"id": 1, "origin": "https://qcsd-buflo-server-two:4434"},
        ],
        "responses": [
            {
                "resource_id": resource["id"],
                "url": resource["url"],
                "status": expected[resource["id"]]["status"],
                "bytes": expected[resource["id"]]["bytes"],
                "body_sha256": expected[resource["id"]]["body_sha256"],
                "complete": True,
                "outcome": "succeeded",
            }
            for resource in resources
        ],
    }

    source_value = buflo_study.load_json(LAB_ROOT / "config/defense-params/walkie-talkie-live.json")
    source_value.update(
        {
            "schema_version": 6,
            "generated_by": "qcsd-buflo-study-controlled-regression-v1",
            "receiver_continuation": receiver_continuation_contract(),
            "qualification_bindings": [
                {
                    "workload_id": "complex",
                    "chaff_qualification_sidecar_sha256": "1" * 64,
                    "prefix_pack_spec_sha256": "2" * 64,
                    "qualified_chaff_manifest_sha256": "3" * 64,
                    "application_resource_id": 0,
                    "selected_chaff_resource_id": 0,
                    "qualified_parallel_chaff_streams": 5,
                    "walkie_talkie_required_chaff_streams": 1,
                }
            ],
        }
    )
    source_path = tmp_path / "walkie-talkie-prefix-source.json"
    buflo_study.atomic_json(source_path, source_value)
    parameter_path = tmp_path / "walkie-talkie.json"
    provenance_path = tmp_path / "walkie-talkie.provenance.json"
    buflo_study._write_regression_multi_origin_walkie_talkie(
        source_path,
        parameter_path,
        provenance_path,
        application_sha256="a" * 64,
        projected_manifest_sha256="b" * 64,
    )
    defenses = buflo_study._regression_multi_origin_defenses(
        parameter_path,
        provenance_path,
        application_sha256="a" * 64,
    )
    evidence = [
        buflo_study._regression_multi_origin_run_identity(
            run,
            manifest,
            mode=defense.name,
        )
        for defense in defenses
    ]

    assert [row["mode"] for row in evidence] == list(buflo_study.MULTI_ORIGIN_COMPATIBILITY_MODES)
    assert [defense.kind for defense in defenses] == [
        "none",
        "static",
        "front",
        "tamaraw",
        "traffic_morphing",
        "wtf_pad",
        "walkie_talkie",
        "buflo",
        "cs_buflo",
    ]
    assert all(
        row["endpoint_coverage"]["observed_endpoint_count"] == 2
        and row["resource_ids"] == [0, 1, 2, 3]
        and {resource["origin"] for resource in row["resources"]}
        == set(buflo_study.MULTI_ORIGIN_COMPATIBILITY_ORIGINS)
        for row in evidence
    )

    missing = json.loads(json.dumps(run))
    missing["responses"].pop()
    with pytest.raises(ValueError, match="lost or duplicated"):
        buflo_study._regression_multi_origin_run_identity(
            missing,
            manifest,
            mode="walkie-talkie",
        )


@pytest.mark.parametrize(
    ("workload_id", "horizon", "survivors", "required_streams"),
    (("simple", 1, 2, 2), ("complex", 3, 4, 4)),
)
def test_regression_prefix_spec_uses_current_full_capacity_schema(
    tmp_path: Path,
    workload_id: str,
    horizon: int,
    survivors: int,
    required_streams: int,
) -> None:
    from qcsd_lab.chaff_qualification import validate_prefix_pack_spec

    manifest = _regression_prefix_manifest(workload_id)
    historical = json.loads(
        (LAB_ROOT / "config/defense-params/walkie-talkie-live.json").read_text(encoding="utf-8")
    )
    profile = buflo_study._current_regression_walkie_talkie_profile(
        next(profile for profile in historical["profiles"] if profile["real"] == workload_id),
        historical["packet_size"],
    )
    destination = tmp_path / f"{workload_id}.json"

    buflo_study._write_regression_prefix_spec(
        destination,
        workload_id,
        profile["bursts"],
        application_manifest=manifest,
    )

    value = json.loads(destination.read_text(encoding="utf-8"))
    validated = validate_prefix_pack_spec(
        value,
        workload_id=workload_id,
        application_manifest=manifest,
    )
    assert validated["numeric_profile"]["bursts"] == profile["bursts"]
    assert validated["application_resource_id"] == 0
    assert validated["selected_chaff_resource_id"] == 0
    assert validated["maximum_receiver_continuation_reserve_horizon"] == horizon
    assert validated["required_chaff_survivors"] == survivors
    assert validated["required_chaff_streams"] == required_streams
    assert len(validated["stream_activation_stages"]) == len(profile["bursts"])


def test_regression_prefix_spec_rejects_runtime_mould_drift(tmp_path: Path) -> None:
    manifest = _regression_prefix_manifest("simple")

    with pytest.raises(ValueError, match="differs from runtime mould"):
        buflo_study._write_regression_prefix_spec(
            tmp_path / "simple.json",
            "simple",
            [{"outgoing": 5, "incoming": 129}],
            application_manifest=manifest,
        )


def test_local_regression_prefix_spec_source_policy_is_fail_closed(tmp_path: Path) -> None:
    from qcsd_lab.chaff_qualification import validate_prefix_pack_spec

    manifest = _regression_prefix_manifest("simple")
    historical = json.loads(
        (LAB_ROOT / "config/defense-params/walkie-talkie-live.json").read_text(encoding="utf-8")
    )
    profile = buflo_study._current_regression_walkie_talkie_profile(
        next(profile for profile in historical["profiles"] if profile["real"] == "simple"),
        historical["packet_size"],
    )
    destination = tmp_path / "simple.json"
    buflo_study._write_regression_prefix_spec(
        destination,
        "simple",
        profile["bursts"],
        application_manifest=manifest,
    )
    value = json.loads(destination.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(value, workload_id="simple")

    outside = json.loads(json.dumps(value))
    outside["workload_id"] = "outside-local-regression"
    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(
            outside,
            workload_id="outside-local-regression",
            application_manifest=manifest,
        )

    source_tamper = json.loads(json.dumps(value))
    source_tamper["source_walkie_talkie_artifact_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="binding is invalid"):
        validate_prefix_pack_spec(
            source_tamper,
            workload_id="simple",
            application_manifest=manifest,
        )

    numeric_tamper = json.loads(json.dumps(value))
    numeric_tamper["numeric_profile"]["bursts"][0]["outgoing"] += 1
    with pytest.raises(ValueError, match="numeric derivation is invalid"):
        validate_prefix_pack_spec(
            numeric_tamper,
            workload_id="simple",
            application_manifest=manifest,
        )


def test_controlled_and_regression_generators_are_exact_and_unique() -> None:
    controlled = generated_stage_cells("controlled")
    regression = generated_stage_cells("regression")

    assert len(controlled) == 160
    assert len({json.dumps(cell, sort_keys=True) for cell in controlled}) == 160
    assert len(regression) == 18
    assert len({json.dumps(cell, sort_keys=True) for cell in regression}) == 18
    matrix = Counter(
        (cell["workload"], cell["treatment"], cell["netem_profile"]) for cell in controlled
    )
    assert set(matrix.values()) == {5}
    qdiscs = {
        cell["netem_profile"]: (cell["client_qdisc"], cell["server_qdisc"]) for cell in controlled
    }
    assert qdiscs == {
        "clean": ("none", "none"),
        "symmetric-50ms-rtt": ("netem delay 25ms", "netem delay 25ms"),
        "symmetric-5mbit-50ms-rtt-100-packet-queue": (
            "netem delay 25ms rate 5mbit limit 100",
            "netem delay 25ms rate 5mbit limit 100",
        ),
        "symmetric-1pct-loss-50ms-rtt": (
            "netem delay 25ms loss 1%",
            "netem delay 25ms loss 1%",
        ),
    }


def test_ctsp_cpsp_gate_requires_oracle_and_controlled_aggregate() -> None:
    proof = buflo_study._ctsp_cpsp_oracle_proof()
    assert proof["ctsp_greater_than_or_equal_cpsp"] is True
    assert {tuple((row["natural_bytes"], row["cover_bytes"])) for row in proof["anchors"]} == {
        (1_000, 24),
        (1_000, 1_100),
    }
    costs = {
        (profile, workload, visit): {
            "cs-buflo-ctsp": {"wire_bytes": 4_096, "udp_payload_bytes": 4_000},
            "cs-buflo-cpsp": {"wire_bytes": 3_072, "udp_payload_bytes": 3_000},
        }
        for profile in ("clean", "symmetric-50ms-rtt", "symmetric-rate-delay", "symmetric-loss")
        for workload in ("local-small", "local-large")
        for visit in range(5)
    }
    evidence = [f"{index:064x}" for index in range(4)]
    result = buflo_study._validate_ctsp_cpsp_ordering(
        costs,
        evidence_sha256s=evidence,
        explanation_receipt=None,
    )
    assert result["controlled_ctsp_greater_than_or_equal_cpsp"] is True
    assert result["reviewed_explanation"] is None

    changed = {
        key: {
            "cs-buflo-ctsp": {"wire_bytes": 2_000, "udp_payload_bytes": 2_000},
            "cs-buflo-cpsp": {"wire_bytes": 3_000, "udp_payload_bytes": 3_000},
        }
        for key in costs
    }
    with pytest.raises(ValueError, match="without a reviewed explanation"):
        buflo_study._validate_ctsp_cpsp_ordering(
            changed,
            evidence_sha256s=evidence,
            explanation_receipt=None,
        )

    # Preserve tuple keys while making one pair contrary and another pair large
    # enough that the aggregate alone would still pass.
    masked_costs = {
        key: {mode: dict(metrics) for mode, metrics in value.items()}
        for key, value in costs.items()
    }
    first, second = list(masked_costs)[:2]
    masked_costs[first]["cs-buflo-ctsp"] = {
        "wire_bytes": 2_000,
        "udp_payload_bytes": 2_000,
    }
    masked_costs[second]["cs-buflo-ctsp"] = {
        "wire_bytes": 8_192,
        "udp_payload_bytes": 8_000,
    }
    with pytest.raises(ValueError, match="paired result"):
        buflo_study._validate_ctsp_cpsp_ordering(
            masked_costs,
            evidence_sha256s=evidence,
            explanation_receipt=None,
        )


def test_sustained_capacity_gate_requires_all_clean_cells() -> None:
    values = [
        {
            "treatment": treatment,
            "workload": workload,
            "visit": visit,
            "capacity": {
                "passed": True,
                "cell_size_bytes": 1_200 if treatment == "buflo" else 600,
                "minimum_interval_us": (20_000 if treatment == "buflo" else 4_096),
                "outgoing_opportunities": 10,
                "incoming_opportunities": 10,
                "outgoing_full_cells": 10,
                "incoming_consumed_bytes": (12_000 if treatment == "buflo" else 6_000),
                "incoming_advertised_bytes": (12_000 if treatment == "buflo" else 6_000),
                "incoming_terminal_cells": 10,
                "incoming_consumption_delay_us_max": 1_000,
                "runner_full_extended_schema_validated": True,
                "runner_algorithm_evidence_sha256": "a" * 64,
                "minimum_interval_exercised": True,
                "exact_target_sizes": True,
                "no_unresolved_credit": True,
                **(
                    {
                        "terminal_subcell": {
                            "schema_version": 3,
                            "terminal_subcell_policy": (BUFLO_TERMINAL_SUBCELL_POLICY),
                            "terminal_subcell_observer_effect": (
                                BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT
                            ),
                            "control_evidence_semantics": (
                                "post-cancellation unscheduled packet composition "
                                "proves defense-control bytes but does not expose "
                                "individual QUIC frame identity"
                            ),
                            "terminal_latched": True,
                            "terminal_latched_at_us": 10_000_001,
                            "open_streams_at_latch": 1,
                            "stream_cancellations": 1,
                            "receipt_cancellations": 1,
                            "typed_cancellation_action_events": 1,
                            "pending_request_cancellations": 0,
                            "parser_lease_bytes_at_latch": 0,
                            "pending_parser_boundaries_at_latch": 1,
                            "pending_application_parser_boundaries_at_latch": 0,
                            "exact_capacity_bytes_cancelled": 1_199,
                            "whole_cell_floor_bytes": 1_200,
                            "first_cancellation_monotonic_us": 10_000_010,
                            "last_exact_outgoing_cell_monotonic_us": 9_999_990,
                            "last_scheduled_terminal_monotonic_us": 10_000_000,
                            "schedule_stop": {
                                "policy": BUFLO_SCHEDULE_STOP_POLICY,
                                "terminal_time_semantics": (
                                    BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS
                                ),
                                "latched": True,
                                "latched_at_us": 10_000_000,
                                "available_bytes": 1_199,
                                "required_bytes": 1_200,
                                "directions": {
                                    "outgoing": {
                                        "scheduled_cells_at_stop": 10,
                                        "terminal_cells_at_stop": 10,
                                        "drained_cells_after_stop": 0,
                                        "last_scheduled_target_us": 10_000_000,
                                        "last_terminal_at_us": 9_999_990,
                                        "terminal_cells_strictly_before_stop": 10,
                                        "terminal_cells_at_or_before_stop": 10,
                                        "terminal_cells_at_stop_timestamp": 0,
                                    },
                                    "incoming": {
                                        "scheduled_cells_at_stop": 10,
                                        "terminal_cells_at_stop": 9,
                                        "drained_cells_after_stop": 1,
                                        "last_scheduled_target_us": 10_000_000,
                                        "last_terminal_at_us": 10_000_001,
                                        "terminal_cells_strictly_before_stop": 9,
                                        "terminal_cells_at_or_before_stop": 9,
                                        "terminal_cells_at_stop_timestamp": 0,
                                    },
                                },
                            },
                            "post_cancellation_unscheduled_defense_control_packets": 1,
                            "post_cancellation_unscheduled_defense_control_bytes": 4,
                            "first_post_cancellation_defense_control_monotonic_us": 10_000_020,
                            "last_post_cancellation_defense_control_monotonic_us": 10_000_020,
                            "paper_equivalent": False,
                            "implementation_scope": "client_only_quic",
                        }
                    }
                    if treatment == "buflo"
                    else {}
                ),
                **(
                    {
                        f"{direction}_minimum_interval_{field}": 2
                        for direction in ("outgoing", "incoming")
                        for field in ("opportunities", "terminal", "full")
                    }
                    if treatment != "buflo"
                    else {}
                ),
                **(
                    {
                        "incoming_minimum_interval_local_realized": 2,
                        "incoming_local_realized_cells": 10,
                        "request_rate_driver_resource_id": (1 if workload == "local-small" else 4),
                        "request_rate_driver_request_stream_bytes": (
                            buflo_study.CSBUFLO_RATE_DRIVER_MIN_REQUEST_STREAM_BYTES
                        ),
                        "request_rate_driver_boundary_bytes": (
                            buflo_study.CSBUFLO_RATE_DRIVER_BOUNDARY_BYTES
                        ),
                        "request_rate_driver_post_boundary_cells": (
                            buflo_study.CSBUFLO_RATE_DRIVER_POST_BOUNDARY_CELLS
                        ),
                    }
                    if treatment != "buflo"
                    else {}
                ),
            },
        }
        for treatment in ("buflo", "cs-buflo-ctsp", "cs-buflo-cpsp")
        for workload in ("local-small", "local-large")
        for visit in range(5)
    ]
    proof = buflo_study._validate_sustained_cell_capacity(values)
    assert proof["samples"] == 30
    assert proof["profiles"]["buflo"]["cell_size_bytes"] == 1_200
    assert proof["profiles"]["buflo"]["terminal_subcell"]["schema_version"] == 3
    assert (
        proof["profiles"]["buflo"]["terminal_subcell"]["pending_parser_boundaries_at_latch"] == 10
    )
    assert (
        proof["profiles"]["buflo"]["terminal_subcell"][
            "pending_application_parser_boundaries_at_latch"
        ]
        == 0
    )
    assert (
        proof["profiles"]["buflo"]["terminal_subcell"]["exact_capacity_bytes_cancelled"]["maximum"]
        == 1_199
    )
    schedule_stop = proof["profiles"]["buflo"]["terminal_subcell"]["schedule_stop"]
    assert schedule_stop["policy"] == BUFLO_SCHEDULE_STOP_POLICY
    assert schedule_stop["terminal_time_semantics"] == BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS
    assert schedule_stop["latched_samples"] == 10
    assert schedule_stop["samples_with_incoming_drain"] == 10
    assert schedule_stop["directions"]["outgoing"]["drained_cells_after_stop"] == 0
    assert schedule_stop["directions"]["incoming"]["drained_cells_after_stop"] == 10
    assert proof["profiles"]["cs-buflo-ctsp"]["minimum_interval_us"] == 4_096
    for index, key, changed in (
        (0, "passed", False),
        (10, "incoming_minimum_interval_local_realized", 1),
        (20, "incoming_local_realized_cells", 9),
        (10, "incoming_advertised_bytes", 5_999),
        (10, "incoming_terminal_cells", 9),
        (10, "runner_full_extended_schema_validated", False),
        (10, "request_rate_driver_request_stream_bytes", 16_384),
        (10, "request_rate_driver_post_boundary_cells", 3),
    ):
        original = values[index]["capacity"][key]
        values[index]["capacity"][key] = changed
        with pytest.raises(ValueError, match="does not sustain"):
            buflo_study._validate_sustained_cell_capacity(values)
        values[index]["capacity"][key] = original

    tail = values[0]["capacity"]["terminal_subcell"]
    tail["parser_lease_bytes_at_latch"] = 1
    with pytest.raises(ValueError, match="does not sustain"):
        buflo_study._validate_sustained_cell_capacity(values)
    tail["parser_lease_bytes_at_latch"] = 0
    tail["pending_application_parser_boundaries_at_latch"] = 1
    with pytest.raises(ValueError, match="does not sustain"):
        buflo_study._validate_sustained_cell_capacity(values)
    tail["pending_application_parser_boundaries_at_latch"] = 0
    tail["pending_parser_boundaries_at_latch"] = 2
    with pytest.raises(ValueError, match="does not sustain"):
        buflo_study._validate_sustained_cell_capacity(values)
    tail["pending_parser_boundaries_at_latch"] = 1
    tail["schedule_stop"]["directions"]["outgoing"]["drained_cells_after_stop"] = 1
    with pytest.raises(ValueError, match="does not sustain"):
        buflo_study._validate_sustained_cell_capacity(values)
    tail["schedule_stop"]["directions"]["outgoing"]["drained_cells_after_stop"] = 0


def test_controlled_endpoint_gate_names_all_new_mode_two_origin_cells() -> None:
    endpoints = [
        {"id": 0, "origin": "https://qcsd-buflo-server-one:4433/"},
        {"id": 1, "origin": "https://qcsd-buflo-server-two:4434/"},
    ]
    coverage = buflo_study._controlled_endpoint_coverage(
        endpoints,
        workload="local-large",
    )
    assert coverage["observed_endpoint_count"] == 2
    assert coverage["passed"] is True

    values = [
        {
            "treatment": cell["treatment"],
            "workload": cell["workload"],
            "visit": cell["visit"],
            "netem_profile": cell["netem_profile"],
            "endpoint_coverage": coverage,
        }
        for cell in generated_stage_cells("controlled")
        if cell["workload"] == "local-large"
        and cell["treatment"] in {"buflo", "cs-buflo-ctsp", "cs-buflo-cpsp"}
    ]
    proof = buflo_study._validate_controlled_multi_endpoint_coverage(values)
    assert proof["samples"] == 60
    assert proof["treatments"] == {
        "buflo": 20,
        "cs-buflo-ctsp": 20,
        "cs-buflo-cpsp": 20,
    }
    assert proof["passed"] is True

    with pytest.raises(ValueError, match="all 60 cells"):
        buflo_study._validate_controlled_multi_endpoint_coverage(values[:-1])
    with pytest.raises(ValueError, match="exact expected endpoint set"):
        buflo_study._controlled_endpoint_coverage(
            [endpoints[0], {"id": 1, "origin": endpoints[0]["origin"]}],
            workload="local-large",
        )


@pytest.mark.parametrize("stage", ("controlled", "regression"))
def test_standard_campaign_receipt_maps_every_local_stage_cell_exactly(stage: str) -> None:
    plan = load_study_plan()
    treatments = (
        tuple(plan["controlled"]["treatments"])
        if stage == "controlled"
        else tuple(plan["regression"]["treatments"])
    )
    workload_aliases = (
        {"local-large": "local-large", "local-small": "local-small"}
        if stage == "controlled"
        else {"complex": "local-large", "simple": "local-small"}
    )
    actual_ids = tuple(workload_aliases)
    aliases_by_target = {target: source for source, target in workload_aliases.items()}
    cells = generated_stage_cells(stage)
    profile_ranks = (
        {profile["id"]: rank for rank, profile in enumerate(plan["controlled"]["netem_profiles"])}
        if stage == "controlled"
        else {"clean": 0}
    )

    for profile, rank in profile_ranks.items():
        selected = [cell for cell in cells if cell["netem_profile"] == profile]
        campaign = SimpleNamespace(
            workloads=tuple(SimpleNamespace(id=value) for value in actual_ids),
            study_controlled={
                "stage": stage,
                "treatment_order": treatments,
                "workload_aliases": workload_aliases,
                "netem_rank": rank,
                "netem_profile": profile,
                "client_qdisc": selected[0]["client_qdisc"],
                "server_qdisc": selected[0]["server_qdisc"],
            },
        )
        observed = {
            json.dumps(
                orchestrator._controlled_study_cell(
                    campaign,
                    {
                        "workload_id": aliases_by_target[cell["workload"]],
                        "visit": cell["visit"],
                        "defense": cell["treatment"],
                    },
                ),
                sort_keys=True,
            )
            for cell in selected
        }
        expected = {
            json.dumps(
                {key: value for key, value in cell.items() if key != "sample_index"},
                sort_keys=True,
            )
            for cell in selected
        }
        assert observed == expected


def test_public_campaigns_are_exact_and_formal_is_latin_balanced() -> None:
    all_campaigns = validate_campaign_matrix()
    formal = validate_campaign_matrix("formal")

    assert all_campaigns["samples"] == 1_560
    assert formal["samples"] == 1_500
    assert len(formal["campaigns"]) == 10
    assert formal["formal_position_counts"]
    assert all(
        max(counts) - min(counts) <= 1 for counts in formal["formal_position_counts"].values()
    )


def test_cohort_v2_resolves_create_only_campaign_without_mutating_v1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = LAB_ROOT / "config/campaigns/buflo-study-v1-smoke.yml"
    original = source.read_bytes()
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")

    resolved = buflo_study.campaign_paths(
        "smoke",
        cohort_version=2,
        create_resolved=True,
    )[0]
    document = buflo_study.yaml.safe_load(resolved.read_text(encoding="utf-8"))

    assert resolved == tmp_path / "cohort-inputs/v2/campaigns" / source.name
    assert document["chaff_qualification_set"] == "buflo-study-public5-v2"
    assert source.read_bytes() == original
    assert resolved.read_bytes() == buflo_study._rendered_campaign_bytes(
        source,
        cohort_version=2,
    )
    resolved.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="deterministic source"):
        buflo_study.campaign_paths("smoke", cohort_version=2)


def test_pre_formal_snapshot_binds_selected_cohort_campaigns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")
    monkeypatch.setattr(
        buflo_study,
        "source_metadata",
        lambda: {"source": "test", "image_digest": "sha256:" + "a" * 64},
    )
    monkeypatch.setattr(buflo_study, "_validate_clean_source", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        buflo_study,
        "validate_historical_corpus_guard",
        lambda *args, **kwargs: {"passed": True},
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_build_execution_receipt",
        lambda *args, **kwargs: {
            "path": str(tmp_path / "build-execution-v2.json"),
            "sha256": "a" * 64,
        },
    )

    snapshot = buflo_study._historical_snapshot_value(
        phase="pre-formal",
        cohort_version=2,
        create_resolved_campaigns=True,
    )

    assert snapshot["cohort_version"] == 2
    assert snapshot["qualification_set"] == "buflo-study-public5-v2"
    assert len(snapshot["formal_campaigns"]) == 10
    assert all(
        "/cohort-inputs/v2/campaigns/" in row["path"] for row in snapshot["formal_campaigns"]
    )


def test_live_parameters_bind_scope_modes_sampling_and_guard() -> None:
    assert len(validate_parameters()) == 3
    buflo = json.loads((LAB_ROOT / "config/defense-params/buflo-live.json").read_text())
    ctsp = json.loads((LAB_ROOT / "config/defense-params/cs-buflo-ctsp-live.json").read_text())
    cpsp = json.loads((LAB_ROOT / "config/defense-params/cs-buflo-cpsp-live.json").read_text())
    assert buflo == {
        "schema_version": 1,
        "interval_us": 20_000,
        "minimum_duration_us": 10_000_000,
        "packet_size": 1_200,
        "max_events": 6_000,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
    }
    assert buflo["interval_us"] * buflo["max_events"] == 120_000_000
    common = {
        "incoming_padding_mode": "payload",
        "timing_sample_limit": 1_000,
        "jitter_denominator": 100,
        "jitter_max_numerator": 200,
        "early_termination": "local",
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
    }
    assert {key: ctsp[key] for key in common} == common
    assert {key: cpsp[key] for key in common} == common
    assert ctsp["outgoing_padding_mode"] == "total"
    assert cpsp["outgoing_padding_mode"] == "payload"


def test_reference_action_cannot_bypass_isolated_create_only_gate(tmp_path: Path) -> None:
    result = run_study_action(
        "reference",
        reference_root=tmp_path,
        destination=tmp_path / "receipt.json",
    )

    assert result.status == "blocked"
    assert any("network-isolated reference image" in blocker for blocker in result.blockers)
    assert not (tmp_path / "receipt.json").exists()


def test_executed_reference_receipt_semantically_binds_all_oracles_and_sources(
    tmp_path: Path,
) -> None:
    execution = _reference_execution_fixture(tmp_path)
    receipt = validate_reference_gate_receipt(execution)

    assert receipt["profiles_checked"] == 8
    assert receipt["archive"] == {
        "total_records": 4_000,
        "included_records": 3_824,
        "zero_baseline_records": 176,
        "defended_bytes": 7_592_598_380,
        "baseline_bytes": 3_326_013_453,
        "excluded_defended_bytes": 18_656_832,
    }
    assert receipt["sha256"] == hashlib.sha256(execution.read_bytes()).hexdigest()
    assert "dyer-paper-pdf" in receipt["external_sources"]
    assert "csbuflo-preprint-pdf" in receipt["external_sources"]


def test_reference_gate_accepts_a_fully_validated_schema_two_build(
    tmp_path: Path,
) -> None:
    execution = _reference_execution_fixture(tmp_path, build_schema_version=2)

    receipt = validate_reference_gate_receipt(execution)

    assert receipt["build_execution"]["cohort_version"] == 1
    assert receipt["profiles_checked"] == 8


def test_executed_reference_receipt_rejects_self_declared_source_substitution(
    tmp_path: Path,
) -> None:
    canonical = (
        LAB_ROOT / "config/reference/buflo-csbuflo/buflo-csbuflo-conformance-v1.receipt.json"
    )
    value = json.loads(canonical.read_text(encoding="utf-8"))
    by_id = {source["source_id"]: source for source in value["external_sources"]}
    assert by_id["csbuflo-clientloop-c"]["sha256"] == (
        "6f0148c8891756e39980edf47f2d5fbc254d2da7b4a8096a678cf3bb7777a36e"
    )
    assert by_id["csbuflo-serverloop-c"]["sha256"] == (
        "abc798cecb918d5c89ccec825224d543862e95a9650334bb0b5d4dd99e17a3a9"
    )
    by_id["csbuflo-clientloop-c"]["sha256"] = "0" * 64
    substituted = tmp_path / "substituted-reference-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="immutable checked-in oracle"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    by_id = {source["source_id"]: source for source in value["external_sources"]}
    by_id["csbuflo-serverloop-c"]["url"] = by_id["csbuflo-serverloop-c"]["url"].replace(
        "serverloop.c", "clientloop.c"
    )
    substituted = tmp_path / "substituted-reference-url-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="immutable checked-in oracle"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_recomputes_slice_aggregate_and_golden_vectors(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    slices = value["csbuflo_author_conformance"]["source_extraction"]["segment_sha256"]
    slices["jitter_function"] = "0" * 64
    substituted = tmp_path / "substituted-slice-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="source-slice inventory"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_author_conformance"]["source_extraction_input_sha256"] = "0" * 64
    substituted = tmp_path / "substituted-slice-aggregate-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="source-slice aggregate"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_author_conformance"]["golden_vectors"]["jitter"]["raw_1"] = 82
    substituted = tmp_path / "substituted-golden-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="author harness"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_binds_rate_quantization_discrepancy(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    discrepancy = value["csbuflo_paper_internal_discrepancies"][0]
    discrepancy["paper_prose_rule"] = "round-down-rho-to-a-power-of-two"
    substituted = tmp_path / "substituted-rate-discrepancy-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="paper-internal discrepancy"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_estimator_contract"]["rate_quantization_resolution"] = "paper-prose-round-up"
    substituted = tmp_path / "substituted-rate-resolution-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="estimator contract"):
        buflo_study._validate_canonical_reference_receipt(substituted)


def test_executed_reference_receipt_recomputes_archive_ratio_and_byte_hash(
    tmp_path: Path,
) -> None:
    canonical = buflo_study.CONFORMANCE_RECEIPT
    value = json.loads(canonical.read_text(encoding="utf-8"))
    value["csbuflo_archive_conformance"]["bandwidth_ratio"] = 2.28279
    substituted = tmp_path / "substituted-archive-receipt.json"
    substituted.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="archive conformance"):
        buflo_study._validate_canonical_reference_receipt(substituted)

    whitespace_changed = tmp_path / "whitespace-changed-receipt.json"
    whitespace_changed.write_text(canonical.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert json.loads(whitespace_changed.read_text(encoding="utf-8")) == json.loads(
        canonical.read_text(encoding="utf-8")
    )
    assert hashlib.sha256(whitespace_changed.read_bytes()).hexdigest() != (
        buflo_study.CONFORMANCE_RECEIPT_SHA256
    )
    with pytest.raises(ValueError, match="receipt SHA-256"):
        buflo_study._validate_canonical_reference_receipt(whitespace_changed)


def test_reference_execution_rejects_static_or_copied_canonical_receipt(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="execution receipt identity"):
        validate_reference_gate_receipt(buflo_study.CONFORMANCE_RECEIPT)
    copied = tmp_path / "copied-canonical.json"
    copied.write_bytes(buflo_study.CONFORMANCE_RECEIPT.read_bytes())
    with pytest.raises(ValueError, match="execution receipt identity"):
        validate_reference_gate_receipt(copied)


def test_reference_execution_receipt_rejects_tamper(tmp_path: Path) -> None:
    execution = _reference_execution_fixture(tmp_path)
    value = json.loads(execution.read_text(encoding="utf-8"))
    value["isolation"]["docker_network_mode"] = "bridge"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    execution.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="isolation evidence"):
        validate_reference_gate_receipt(execution)


def test_staged_capture_rejects_missing_exact_prior_cohorts() -> None:
    with pytest.raises(ValueError, match="exact prerequisite set"):
        validate_staged_capture_prerequisites("formal", ())


def test_formal_capacity_requires_12_5_hours_and_threefold_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = {
        "public": {
            "smoke": {
                "samples": 20,
                "authoritative_bytes": 20_000,
                "elapsed_seconds": 600,
            },
            "rehearsal": {
                "samples": 40,
                "authoritative_bytes": 40_000,
                "elapsed_seconds": 1_200,
            },
        }
    }
    monkeypatch.setattr(
        buflo_study.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=4_500_000),
    )

    capacity = validate_formal_capture_capacity(
        staged,
        available_window_hours=12.5,
        results_root=tmp_path,
    )

    assert capacity["minimum_sequential_cooldown_seconds"] == 45_000
    assert capacity["measured_projection_seconds"] == 45_000
    assert capacity["expected_formal_wall_seconds"] == 45_000
    assert capacity["projected_formal_bytes"] == 1_500_000
    assert capacity["required_free_bytes"] == 4_500_000
    with pytest.raises(ValueError, match="at least 12.5"):
        validate_formal_capture_capacity(
            staged,
            available_window_hours=12.49,
            results_root=tmp_path,
        )


def test_first_formal_block_uses_frozen_projected_storage_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign = tmp_path / "buflo-study-v1-formal-01.yml"
    campaign.write_text("name: buflo-study-v1-formal-01\n", encoding="utf-8")
    result_root = tmp_path / "results" / "buflo-study-v1-formal-01"
    admission_value = {
        "stage": "formal",
        "results_root": str(tmp_path / "results"),
        "allowed_campaigns": [
            {
                "campaign_path": str(campaign.resolve()),
                "campaign_sha256": buflo_study.sha256_file(campaign),
                "result_root": str(result_root),
            }
        ],
        "formal_capacity": {"projected_formal_bytes": 1_000_000},
    }
    monkeypatch.setattr(
        buflo_study,
        "validate_capture_admission",
        lambda _admission: admission_value,
    )
    disk_probes: list[Path] = []
    monkeypatch.setattr(
        buflo_study.shutil,
        "disk_usage",
        lambda path: (disk_probes.append(Path(path)), SimpleNamespace(free=3_000_000))[1],
    )

    assert (
        buflo_study.admitted_result_root(
            tmp_path / "admission.json", campaign, require_sequence=True
        )
        == result_root
    )
    assert disk_probes == [tmp_path / "results"]


def test_capture_admission_rejects_cohort_mismatch_before_replay(tmp_path: Path) -> None:
    admission = tmp_path / "capture-admission.json"
    admission.write_text(json.dumps({"cohort_version": 2}), encoding="utf-8")

    with pytest.raises(ValueError, match="cohort version does not match"):
        buflo_study.validate_capture_admission(
            admission,
            expected_cohort_version=1,
        )


def test_v15_formal_capture_admission_requires_code_gate_before_freeze_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = {"image_digest": "sha256:" + "a" * 64}
    build = {
        "path": "build.json",
        "sha256": "b" * 64,
        "collection_image": source["image_digest"],
        "started_at": "2026-08-27T00:00:00+00:00",
        "finished_at": "2026-08-27T00:01:00+00:00",
    }
    identity = {
        "cohort_version": 15,
        "sha256": build["sha256"],
        "collection_image": build["collection_image"],
        "started_at": build["started_at"],
        "finished_at": build["finished_at"],
    }
    scheduler = buflo_study._capture_scheduler_environment_contract()
    environment = {
        "schema_version": 2,
        "capture_scheduler": scheduler,
        "docker": {"ncpu": 12},
    }
    regression = {"results": [{"root": "regression", "environment": environment}]}
    staged = {
        "source": source,
        "regression": regression,
        "public": {
            "smoke": {"root": "smoke", "environment": environment},
            "rehearsal": {"root": "rehearsal", "environment": environment},
        },
    }
    qualification = {
        "source": source,
        "build_execution": {"path": build["path"], "sha256": build["sha256"]},
        "controlled_results": {"results": [{"environment": environment}]},
    }
    monkeypatch.setattr(
        buflo_study,
        "validate_reference_gate_receipt",
        lambda *_args, **_kwargs: {"build_execution": identity},
    )
    monkeypatch.setattr(
        buflo_study, "validate_qualification_receipt", lambda *_args, **_kwargs: qualification
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_staged_capture_prerequisites",
        lambda *_args, **_kwargs: staged,
    )
    monkeypatch.setattr(
        buflo_study, "validate_build_execution_receipt", lambda *_args, **_kwargs: build
    )
    monkeypatch.setattr(buflo_study, "_one_build_execution_identity", lambda _values: identity)
    results_root = tmp_path / "results"
    results_root.mkdir()

    with pytest.raises(ValueError, match="validated code-gate receipt"):
        buflo_study._capture_admission_value(
            stage="formal",
            reference_receipt=tmp_path / "reference.json",
            qualification_receipt=tmp_path / "qualification.json",
            prerequisite_result_roots=(),
            results_root=results_root,
            formal_cohort_manifest=tmp_path / "cohort.json",
            historical_pre_snapshot=tmp_path / "pre.json",
            cohort_version=15,
        )

    pre = tmp_path / "pre.json"
    cohort_path = tmp_path / "cohort.json"
    code_path = tmp_path / "code-gate.json"
    for path in (pre, cohort_path, code_path):
        path.write_text("{}\n", encoding="utf-8")
    code_gate = {
        **buflo_study._file_binding(code_path),
        "source": source,
        "build_execution_receipt": {"path": build["path"], "sha256": build["sha256"]},
        "live_regression": regression,
    }
    monkeypatch.setattr(
        buflo_study, "validate_code_gate_receipt", lambda *_args, **_kwargs: code_gate
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_historical_guard_snapshot",
        lambda *_args, **_kwargs: {"source": source},
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_formal_cohort_manifest",
        lambda *_args, **_kwargs: {
            "cohort_version": 15,
            "qualification_set": "buflo-study-public5-v15",
            "source": source,
            "historical_pre_formal_snapshot": buflo_study._file_binding(pre),
            "results_root": str(results_root.resolve()),
            "formal_campaigns": [],
            "formal_evaluation": buflo_study.FORMAL_BOOTSTRAP_CONTRACT,
        },
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_formal_capture_capacity",
        lambda *_args, **_kwargs: {"available_window_hours": 12.5},
    )
    admitted = buflo_study._capture_admission_value(
        stage="formal",
        reference_receipt=tmp_path / "reference.json",
        qualification_receipt=tmp_path / "qualification.json",
        prerequisite_result_roots=(),
        results_root=results_root,
        formal_cohort_manifest=cohort_path,
        historical_pre_snapshot=pre,
        code_gate_receipt=code_path,
        formal_window_hours=12.5,
        cohort_version=15,
    )
    assert admitted["schema_version"] == 3
    assert admitted["code_gate"] == code_gate


def test_formal_prelaunch_estimate_is_visible_only_on_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    buflo_study._report_frozen_formal_prelaunch(
        {
            "expected_formal_wall_hours": 12.5,
            "conservative_upper_seconds": 50_400,
            "projected_formal_bytes": 1_500_000,
            "required_free_bytes": 4_500_000,
        }
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "expected=12.500h" in captured.err
    assert "3x_required=4500000 bytes" in captured.err


def test_attestation_destination_cannot_overlap_result_inputs(tmp_path: Path) -> None:
    result_root = tmp_path / "formal-result"
    result_root.mkdir()
    with pytest.raises(ValueError, match="overlaps protected input"):
        buflo_study.create_validation_attestation(
            result_root / "attestation.json",
            formal_result_roots=(result_root,),
        )


def test_qualification_rejects_sidecar_from_non_prepare_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qcsd_lab import chaff_qualification

    qualification_root = tmp_path / "sets"
    selected = qualification_root / "buflo-study-public5-v2"
    selected.mkdir(parents=True)
    for workload in buflo_study.WORKLOADS:
        (selected / f"{workload}.json").write_text(
            json.dumps({"qualification_image_digest": "sha256:" + "e" * 64}),
            encoding="utf-8",
        )
    monkeypatch.setattr(buflo_study, "QUALIFICATION_SET_ROOT", qualification_root)
    monkeypatch.setattr(
        buflo_study,
        "_qualification_build_binding",
        lambda *_args: (
            {"path": "build.json", "sha256": "f" * 64},
            "sha256:" + "d" * 64,
        ),
    )
    monkeypatch.setattr(chaff_qualification, "load_response_qualified_chaff", lambda *a, **k: None)

    ready, status = buflo_study.qualification_status(
        require_controlled=False,
        cohort_version=2,
    )
    assert ready is False
    assert "exact no-cache prepare image" in status


def test_launcher_requires_clean_capture_image_and_no_cache_build() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert 'verify_qualification_checkout "buflo-study capture"' in launcher
    assert 'verify_qualification_checkout "buflo study campaign run"' in launcher
    direct_run_guard = launcher.split('verify_qualification_checkout "buflo-study capture"', 1)[
        1
    ].split('verify_qualification_checkout "buflo-study qualify"', 1)[0]
    assert '"${1:-}" == "run"' in direct_run_guard
    assert "buflo-study-v1-(smoke|rehearsal|formal-[0-9]{2})" in direct_run_guard
    assert '"${1:-}" == "resume"' not in direct_run_guard
    assert launcher.count('docker --context "${build_docker_context}" build --pull --no-cache') == 3
    assert "WSL_HOST_BUILD_MIN_AVAILABLE_BYTES=68719476736" in launcher
    assert launcher.count('wsl_host_build_storage_probe "') == 4
    assert "windows_docker_storage_probe.ps1" in launcher
    assert '"schema_version": 2' in launcher
    assert '"host_storage_preflight": host_storage' in launcher
    assert launcher.count('"${ROOT}/src/qcsd_lab/build_storage.py" receipt') == 2
    assert "validate_build_execution_envelope" in launcher
    assert launcher.count('--iidfile "${') == 3
    assert "acquire_evidence_build_lock" in launcher
    assert "reject_evidence_build_image_overrides" in launcher
    assert "reject_docker_endpoint_overrides" in launcher
    assert launcher.count("validate_local_docker_build_endpoint") == 6
    assert "artifacts/buflo-study/build-execution-v${study_cohort_version}.json" in launcher
    assert '"artifact_type": "qcsd-buflo-study-no-cache-build-execution"' in launcher
    assert '"build_execution": {' in launcher


def test_launcher_applies_least_privilege_rr1_capture_partition() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    entrypoint = (LAB_ROOT / "docker/collection-entrypoint").read_text(encoding="utf-8")
    network_probe = launcher.split("buflo_namespace_evidence()", 1)[1].split(
        "buflo_controlled_evidence_base64()", 1
    )[0]

    assert 'study_capture_scheduler_contract="qcsd-client-rr1-cpu10-v1"' in launcher
    assert 'runtime+=(--cpuset-cpus "10-11" --ulimit "rtprio=1:1")' in launcher
    assert "--cpuset-cpus 10-11" in launcher
    assert "--ulimit rtprio=1:1" in launcher
    assert "docker ps --format '{{.ID}}'" in launcher
    assert "docker-inspect-all-running-containers-prelaunch-v1" in launcher
    assert "container_set_matches_expected = set(expected) == observed_names" in launcher
    assert "refuses a running Docker container without the" in launcher
    assert "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64" in launcher
    assert launcher.count('--label "org.qcsd.owner=qcsd-lab"') >= 5
    # Acceptance server, ordinary controlled server, and shared router helpers
    # remain outside the isolated client CPU partition.
    assert launcher.count("--cpuset-cpus 0-9") == 3
    assert "SYS_NICE" not in launcher
    assert "--cpu-rt-runtime" not in launcher
    assert "unsupported capture scheduler contract" in entrypoint
    assert "taskset --cpu-list 11 qcsd-lab-internal" in entrypoint
    assert "+sys_nice" not in entrypoint
    assert 'docker exec "${container_name}" /usr/bin/python3 -c' in network_probe
    assert "/usr/local/bin/python3" not in network_probe


def test_versioned_build_receipts_coexist_and_reject_path_or_request_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = {version: tmp_path / f"build-execution-v{version}.json" for version in (1, 2)}
    monkeypatch.setattr(
        buflo_study,
        "build_execution_receipt_path",
        lambda cohort_version=1: paths[cohort_version],
    )
    for version, path in paths.items():
        path.write_text(
            json.dumps(
                _build_execution_value(cohort_version=version),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    v1_sha256 = buflo_study.sha256_file(paths[1])

    assert (
        buflo_study.validate_build_execution_receipt(paths[1], expected_cohort_version=1)[
            "cohort_version"
        ]
        == 1
    )
    assert (
        buflo_study.validate_build_execution_receipt(paths[2], expected_cohort_version=2)[
            "cohort_version"
        ]
        == 2
    )
    assert buflo_study.sha256_file(paths[1]) == v1_sha256
    with pytest.raises(ValueError, match="cohort version differs from the request"):
        buflo_study.validate_build_execution_receipt(paths[1], expected_cohort_version=2)

    copied = tmp_path / "copied-v1-as-v2.json"
    copied.write_bytes(paths[1].read_bytes())
    with pytest.raises(ValueError, match="path does not match its cohort version"):
        buflo_study.validate_build_execution_receipt(copied)


def test_all_public_v2_campaign_matrices_render_and_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(buflo_study, "COHORT_INPUT_ROOT", tmp_path / "cohort-inputs")

    assert buflo_study.validate_campaign_matrix("smoke", cohort_version=2)["samples"] == 20
    assert buflo_study.validate_campaign_matrix("rehearsal", cohort_version=2)["samples"] == 40
    assert buflo_study.validate_campaign_matrix("formal", cohort_version=2)["samples"] == 1_500


def test_versioned_public5_outputs_are_narrowly_ignored() -> None:
    versioned = "config/chaff-response-qualification-store/sets/buflo-study-public5-v2/receipt.json"
    unrelated = "config/chaff-response-qualification-store/sets/unrelated-public5-v2/receipt.json"
    ignored = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", versioned],
        cwd=LAB_ROOT,
        check=False,
    )
    visible = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", unrelated],
        cwd=LAB_ROOT,
        check=False,
    )
    dockerignore = (LAB_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    dockerfile = (LAB_ROOT / "Dockerfile").read_text(encoding="utf-8")
    collection_packages = (
        dockerfile.split("FROM lab-runtime AS collection", 1)[1]
        .split("RUN uv lock --check", 1)[0]
        .split()
    )

    assert ignored.returncode == 0
    assert visible.returncode == 1
    assert "git" in collection_packages
    assert "config/chaff-response-qualification-store/sets/buflo-study-public5-v*/" in dockerignore
    assert "config/chaff-response-qualification-store/sets/*" not in dockerignore


def test_launcher_selects_exact_versioned_build_images_and_frozen_resume_admission() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert 'BUILD_COHORT_VERSION="${build_cohort_version}"' in launcher
    assert '"cohort_version": int(os.environ["BUILD_COHORT_VERSION"])' in launcher
    assert 'COLLECTION_IMAGE="${study_build_fields[1]}"' in launcher
    assert 'PREPARE_IMAGE="${study_build_fields[2]}"' in launcher
    assert 'REFERENCE_IMAGE="${study_build_fields[3]}"' in launcher
    assert 'QCSD_LAB_PREPARE_IMAGE="${PREPARE_IMAGE}"' in launcher
    assert (
        'study_capture_admission_host="${study_resume_root}/inputs/capture-admission.json"'
        in launcher
    )
    assert 'read_capture_admission_binding "${study_capture_admission_host}"' in launcher
    assert (
        '--volume "${reference_cohort_inputs}:'
        '/lab/artifacts/buflo-study/cohort-inputs:rw"' in launcher
    )


@pytest.mark.parametrize(
    ("variable", "value"),
    (
        ("QCSD_TEST_WSL_AVAILABLE_BYTES", str(64 * 1024**3 - 1)),
        ("QCSD_TEST_WSL_MALFORMED", "1"),
        ("QCSD_TEST_WSL_PROBE_FAIL", "1"),
    ),
)
def test_build_preflight_failure_prevents_any_docker_build_or_receipt(
    tmp_path: Path, variable: str, value: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = value

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "71"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v71.json").exists()


@pytest.mark.parametrize(
    ("variable", "value", "expected_builds", "message"),
    (
        (
            "QCSD_TEST_WSL_IDENTITY_CHANGE_BOUNDARY",
            "before-prepare",
            1,
            "backing-volume identity changed",
        ),
        (
            "QCSD_TEST_WSL_LOW_BOUNDARY",
            "after-reference",
            3,
            "requires at least",
        ),
        (
            "QCSD_TEST_DOCKER_CHANGE_AFTER_BUILDS",
            "1",
            1,
            "daemon identity changed",
        ),
        (
            "QCSD_TEST_DOCKER_ID_CHANGE_AFTER_BUILDS",
            "1",
            1,
            "daemon identity changed",
        ),
    ),
)
def test_build_boundary_failure_stops_at_exact_image_and_creates_no_receipt(
    tmp_path: Path,
    variable: str,
    value: str,
    expected_builds: int,
    message: str,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = value

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "72"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert _marked_build_count(build_marker) == expected_builds
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v72.json").exists()


def test_build_final_daemon_recheck_catches_post_inventory_id_change(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_DOCKER_ID_CHANGE_AFTER_INVENTORY"] = "1"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "74"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "daemon identity changed" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v74.json").exists()


@pytest.mark.parametrize(
    ("variable", "value", "message"),
    (
        ("DOCKER_HOST", "tcp://example.invalid:2375", "rejects Docker endpoint"),
        (
            "QCSD_TEST_DOCKER_ENDPOINT",
            "tcp://example.invalid:2375",
            "requires a local Docker Desktop endpoint",
        ),
        (
            "QCSD_TEST_DOCKER_OPERATING_SYSTEM",
            "Remote Linux",
            "requires the local Docker Desktop Linux engine",
        ),
    ),
)
def test_build_rejects_endpoint_bypass_before_any_image_build(
    tmp_path: Path, variable: str, value: str, message: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = value

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "73"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v73.json").exists()


@pytest.mark.parametrize(
    "variable",
    (
        "QCSD_LAB_COLLECTION_IMAGE",
        "QCSD_LAB_PREPARE_IMAGE",
        "QCSD_LAB_REFERENCE_IMAGE",
    ),
)
def test_build_rejects_image_role_overrides_before_any_image_build(
    tmp_path: Path, variable: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment[variable] = "neqo-qcsd-lab-collection:aliased"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "75"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "rejects image-role override" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v75.json").exists()


def test_build_global_lock_rejects_concurrent_role_tag_mutation(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    daemon_lock_identity = "\t".join(
        (
            environment["QCSD_TEST_DOCKER_SERVER_ID"],
            "linux",
            "x86_64",
        )
    )
    lock_parent = Path(f"/tmp/qcsd-lab-evidence-build-{os.getuid()}")
    lock_parent.mkdir(mode=0o700, exist_ok=True)
    lock_parent.chmod(0o700)
    lock_path = lock_parent / (f"{hashlib.sha256(daemon_lock_identity.encode()).hexdigest()}.lock")
    with lock_path.open("a+", encoding="utf-8") as held_lock:
        lock_path.chmod(0o600)
        fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        environment["QCSD_TEST_DOCKER_CONTEXT"] = "desktop-linux"
        result = subprocess.run(
            [str(launcher), "build", "--cohort-version", "76"],
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    assert result.returncode != 0
    assert "user/WSL instance's Docker-daemon lock" in result.stderr
    assert _marked_build_count(build_marker) == 0
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v76.json").exists()


def test_build_self_validation_rejects_invalid_inputs_before_receipt_write(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_INVALID_BUILD_INPUTS"] = "1"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "77"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "build inputs are invalid" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v77.json").exists()


def test_build_rejects_cross_role_source_snapshot_change(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_SOURCE_CHANGE_IMAGE_ID"] = "sha256:" + f"{2:064d}"

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "80"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "different source snapshots" in result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v80.json").exists()


@pytest.mark.parametrize(
    ("mode", "message"),
    (
        ("missing", "did not create a regular IID file"),
        ("malformed", "invalid immutable image ID"),
        ("mismatch", "tag no longer binds its build-produced ID"),
    ),
)
def test_build_rejects_missing_malformed_or_mismatched_iid_evidence(
    tmp_path: Path, mode: str, message: str
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    environment["QCSD_TEST_IID_TARGET"] = "collection"
    environment["QCSD_TEST_IID_MODE"] = mode

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "81"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert _marked_build_count(build_marker) == 1
    assert not (tmp_path / "artifacts/buflo-study/build-execution-v81.json").exists()


def test_build_validator_cannot_be_shadowed_from_the_caller_directory(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    shadow_root = tmp_path / "caller"
    shadow_package = shadow_root / "qcsd_lab"
    shadow_package.mkdir(parents=True)
    marker = shadow_root / "shadow-imported"
    (shadow_package / "__init__.py").write_text("", encoding="utf-8")
    (shadow_package / "build_storage.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('shadowed')\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "78"],
        cwd=shadow_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert _marked_build_count(build_marker) == 3
    assert not marker.exists()
    assert (tmp_path / "artifacts/buflo-study/build-execution-v78.json").is_file()


def test_build_canonicalises_a_symlinked_launcher_root_before_execution(
    tmp_path: Path,
) -> None:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    symlink_root = tmp_path / "invocation-root"
    symlink_root.symlink_to(tmp_path, target_is_directory=True)

    result = subprocess.run(
        [str(symlink_root / launcher.name), "build", "--cohort-version", "79"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert _marked_build_count(build_marker) == 3
    receipt = json.loads(
        (tmp_path / "artifacts/buflo-study/build-execution-v79.json").read_text(encoding="utf-8")
    )
    assert {command["argv"][-1] for command in receipt["commands"]} == {str(tmp_path.resolve())}
    assert all(
        "invocation-root" not in item for command in receipt["commands"] for item in command["argv"]
    )


def test_windows_storage_probe_is_valid_windows_powershell_syntax() -> None:
    if shutil.which("powershell.exe") is None:
        pytest.skip("Windows PowerShell interop is unavailable")
    probe = LAB_ROOT / "tools/windows_docker_storage_probe.ps1"
    parser = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$source=[Console]::In.ReadToEnd(); "
                "$tokens=$null; $errors=$null; "
                "[System.Management.Automation.Language.Parser]::ParseInput("
                "$source,[ref]$tokens,[ref]$errors) > $null; "
                "if ($errors.Count -ne 0) { $errors | Out-String | Write-Error; exit 1 }"
            ),
        ],
        input=probe.read_text(encoding="utf-8"),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert parser.returncode == 0, parser.stderr


def test_windows_storage_probe_rejects_registration_settings_conflict(
    tmp_path: Path,
) -> None:
    if shutil.which("powershell.exe") is None:
        pytest.skip("Windows PowerShell interop is unavailable")
    probe = (LAB_ROOT / "tools/windows_docker_storage_probe.ps1").read_text(encoding="utf-8")
    function = probe.split("function Get-CanonicalDataVhd {", 1)[1].split(
        "\n\n$resolved = Get-CanonicalDataVhd", 1
    )[0]
    harness = tmp_path / "probe-conflict.ps1"
    harness.write_text(
        """
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0
$env:APPDATA = "C:\\Users\\test\\AppData\\Roaming"
function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    return (
        $LiteralPath -eq "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss" -or
        $LiteralPath -eq "C:\\Users\\test\\AppData\\Roaming\\Docker\\settings-store.json"
    )
}
function Get-ChildItem {
    param([string]$LiteralPath)
    return [pscustomobject]@{ PSPath = "registry-item" }
}
function Get-ItemProperty {
    param([string]$LiteralPath)
    return [pscustomobject]@{
        DistributionName = "docker-desktop-data"
        BasePath = "C:\\RegisteredDockerData"
        VhdFileName = "ext4.vhdx"
    }
}
function Get-Content {
    param([switch]$Raw, [string]$LiteralPath)
    return '{"diskImageLocation":"C:\\\\ConfiguredDockerData"}'
}
function Get-CanonicalDataVhd {
"""
        + function
        + """
try {
    Get-CanonicalDataVhd | Out-Null
    Write-Error "conflicting authoritative locations were accepted"
    exit 2
}
catch {
    if ($_.Exception.Message -notlike "*registration and settings contain conflicting*") {
        Write-Error $_
        exit 3
    }
}
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr


def test_windows_storage_probe_smoke_reports_the_actual_backing_volume() -> None:
    if shutil.which("powershell.exe") is None or shutil.which("wslpath") is None:
        pytest.skip("Windows PowerShell interop is unavailable")
    probe = LAB_ROOT / "tools/windows_docker_storage_probe.ps1"
    mapped = subprocess.run(
        ["wslpath", "-w", "--", str(probe)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            mapped,
            "-Boundary",
            "before-collection",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        unavailable = (
            "active data location is not authoritatively configured",
            "expected exactly one Docker data VHDX; found 0",
        )
        if any(reason in result.stderr for reason in unavailable):
            pytest.skip(f"authoritative Docker data VHDX is unavailable: {result.stderr}")
        pytest.fail(f"Windows Docker storage probe failed: {result.stderr}")
    observation = json.loads(result.stdout)
    probe_sha256 = hashlib.sha256(probe.read_bytes()).hexdigest()

    assert observation["probe_sha256"] == probe_sha256
    assert observation["location_source"] in (
        "wsl-lxss-docker-desktop-data",
        "docker-settings-store",
        "docker-legacy-settings",
    )
    assert observation["data_vhd_path"].lower().endswith(".vhdx")
    if observation["available_bytes"] < build_storage.BUILD_WSL_HOST_MIN_AVAILABLE_BYTES:
        with pytest.raises(ValueError, match="requires at least"):
            build_storage.validate_build_host_storage_observation(
                observation,
                expected_boundary="before-collection",
                expected_probe_sha256=probe_sha256,
            )
    else:
        build_storage.validate_build_host_storage_observation(
            observation,
            expected_boundary="before-collection",
            expected_probe_sha256=probe_sha256,
        )


def test_launcher_build_v2_is_create_only_and_preserves_v1(tmp_path: Path) -> None:
    launcher = tmp_path / "qcsd-lab"
    launcher.write_bytes((LAB_ROOT / "qcsd-lab").read_bytes())
    launcher.chmod(0o755)
    (tmp_path / "neqo-qcsd").mkdir()
    (tmp_path / "neqo-qcsd/Cargo.lock").write_text("lock\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("lock\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    _install_fake_wsl_storage_probe(tmp_path, binary_root)
    docker = binary_root / "docker"
    docker.write_text(
        """#!/bin/sh
set -eu
if [ "${1:-}" = "--context" ]; then
  shift 2
fi
command="$1"
shift
case "$command" in
  build)
    iidfile=""
    target=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --iidfile) iidfile="$2"; shift 2 ;;
        --target) target="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    case "$target" in
      collection) image_number=1 ;;
      prepare) image_number=2 ;;
      reference) image_number=3 ;;
      *) exit 1 ;;
    esac
    [ -n "$iidfile" ] || exit 1
    printf 'sha256:%064d\n' "$image_number" > "$iidfile"
    ;;
  context)
    case "$1" in
      show) printf '%s\n' 'default' ;;
      inspect) printf '%s\n' 'unix:///var/run/docker.sock' ;;
      *) exit 1 ;;
    esac
    ;;
  info)
    if [ "$#" -eq 0 ]; then exit 0; fi
    case "$2" in
      '{{json .}}') printf '%s\n' '{"Name":"docker-desktop","OperatingSystem":"Docker Desktop","OSType":"linux","Architecture":"x86_64","ID":"12345678-1234-1234-1234-123456789abc"}' ;;
      '{{.Name}}') printf '%s\n' 'docker-desktop' ;;
      '{{.OperatingSystem}}') printf '%s\n' 'Docker Desktop' ;;
      '{{.OSType}}') printf '%s\n' 'linux' ;;
      '{{.Architecture}}') printf '%s\n' 'x86_64' ;;
      *) exit 1 ;;
    esac
    ;;
  version)
    printf '%s\n' '{"Client":{"Version":"29.0.1"},"Server":{"Version":"29.0.1"}}'
    ;;
  image)
    shift
    format=""
    last=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--format" ]; then format="$2"; shift 2; continue; fi
      last="$1"; shift
    done
    case "$format" in
      '{{.Id}}')
        case "$last" in
          *collection*) printf 'sha256:%064d\n' 1 ;;
          *prepare*) printf 'sha256:%064d\n' 2 ;;
          *reference*) printf 'sha256:%064d\n' 3 ;;
          *) printf '%s\n' "$last" ;;
        esac
        ;;
      '{{json .RepoDigests}}') printf '%s\n' '[]' ;;
      *) exit 0 ;;
    esac
    ;;
  run)
    case "$*" in
      */source.json)
        printf '%s\n' '{"lab_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","lab_dirty":false,"lab_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","neqo_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_pinned_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","neqo_dirty":false,"neqo_patch_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
        ;;
      */study-build-inputs.json)
        printf '%s\n' '{"artifact_type":"qcsd-study-build-inputs","cargo_lock_sha256":"d8c9f2728aa278ebcd33ccedf3ad309a866870ad5fb93a03526b4b7655c9e911","debian_base_image":"docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818","rust_base_image":"docker.io/library/rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f","schema_version":1,"uv_lock_sha256":"d8c9f2728aa278ebcd33ccedf3ad309a866870ad5fb93a03526b4b7655c9e911"}'
        ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = f"{binary_root}:{environment['PATH']}"
    environment["QCSD_TEST_WSL_AVAILABLE_BYTES"] = str(64 * 1024**3)
    environment["QCSD_TEST_WSL_DATA_PATH"] = r"D:\DockerData\disk\docker_data.vhdx"
    powershell_marker = tmp_path / "powershell-boundaries"
    environment["QCSD_TEST_POWERSHELL_MARKER"] = str(powershell_marker)

    first = subprocess.run(
        [str(launcher), "build"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr
    v1 = tmp_path / "artifacts/buflo-study/build-execution-v1.json"
    v1_sha256 = hashlib.sha256(v1.read_bytes()).hexdigest()
    second = subprocess.run(
        [str(launcher), "build", "--cohort-version", "2"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert second.returncode == 0, second.stderr
    v2 = tmp_path / "artifacts/buflo-study/build-execution-v2.json"
    assert json.loads(v1.read_text(encoding="utf-8"))["cohort_version"] == 1
    v2_value = json.loads(v2.read_text(encoding="utf-8"))
    assert v2_value["cohort_version"] == 2
    assert v2_value["schema_version"] == 2
    assert v2_value["docker"]["context"] == "default"
    preflight = v2_value["host_storage_preflight"]
    assert preflight["required_available_bytes"] == 64 * 1024**3
    assert [item["boundary"] for item in preflight["observations"]] == [
        "before-collection",
        "before-prepare",
        "before-reference",
        "after-reference",
    ]
    assert {item["data_vhd_path"] for item in preflight["observations"]} == {
        r"D:\DockerData\disk\docker_data.vhdx"
    }
    assert {item["drive_letter"] for item in preflight["observations"]} == {"D"}
    assert len(powershell_marker.read_text(encoding="utf-8").splitlines()) == 8
    assert hashlib.sha256(v1.read_bytes()).hexdigest() == v1_sha256

    duplicate = subprocess.run(
        [str(launcher), "build", "--cohort-version=2"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert duplicate.returncode == 1
    assert "absent create-only receipt" in duplicate.stderr
    assert len(powershell_marker.read_text(encoding="utf-8").splitlines()) == 8


def test_build_execution_receipt_rejects_semantically_rehashed_cache_enabled_command() -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    value["commands"][0]["argv"].remove("--no-cache")
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


def test_build_execution_receipt_accepts_consistent_host_paths_from_container() -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    for command in value["commands"]:
        command["argv"][-2] = "/host-checkout/neqo-qcsd-lab/Dockerfile"
        command["argv"][-1] = "/host-checkout/neqo-qcsd-lab"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    assert buflo_study._validate_build_execution_value(value)["cohort_version"] == 1

    value["commands"][0]["argv"][-1] = "/different-build-context"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


def test_schema_two_container_reader_preserves_validated_physical_host_paths() -> None:
    value = json.loads(json.dumps(_build_execution_value(schema_version=2)))
    host_root = Path("/physical-host-checkout/neqo-qcsd-lab")
    for command in value["commands"]:
        iidfile_index = command["argv"].index("--iidfile") + 1
        command["argv"][iidfile_index] = str(
            host_root / "artifacts/buflo-study/.build-iids-v1.ABC123" / f"{command['target']}.iid"
        )
        command["argv"][-2] = str(host_root / "Dockerfile")
        command["argv"][-1] = str(host_root)
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    assert buflo_study._validate_build_execution_value(value)["cohort_version"] == 1

    value = json.loads(json.dumps(_build_execution_value()))
    value["commands"][1]["argv"][-2] = "/other-host-checkout/Dockerfile"
    value["commands"][1]["argv"][-1] = "/other-host-checkout"
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)
    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


@pytest.mark.parametrize(
    ("dockerfile", "build_root"),
    [
        ("/Dockerfile", "/"),
        ("//host/repo/Dockerfile", "//host/repo"),
        ("/host/a/../repo/Dockerfile", "/host/a/../repo"),
        ("relative/repo/Dockerfile", "relative/repo"),
    ],
)
def test_build_execution_receipt_rejects_noncanonical_or_unsafe_build_roots(
    dockerfile: str, build_root: str
) -> None:
    value = json.loads(json.dumps(_build_execution_value()))
    for command in value["commands"]:
        command["argv"][-2] = dockerfile
        command["argv"][-1] = build_root
    payload = dict(value)
    del payload["payload_sha256"]
    value["payload_sha256"] = buflo_study._canonical_digest(payload)

    with pytest.raises(ValueError, match="--pull --no-cache"):
        buflo_study._validate_build_execution_value(value)


@pytest.mark.parametrize(
    "name",
    [
        "buflo-study-v1-public-smoke-1200",
        "buflo-study-v1-public-rehearsal-1200",
        "buflo-study-v1-formal-01-1200",
        "buflo-study-v1-formal-10-1200",
    ],
)
def test_public_campaign_identity_cannot_bypass_capture_admission(name: str) -> None:
    assert orchestrator._public_buflo_campaign(name)


@pytest.mark.parametrize(
    "name",
    [
        "buflo-study-v1-smoke",
        "buflo-study-v1-formal-01",
        "buflo-study-v1-formal-1-1200",
        "buflo-study-v1-controlled-00-1200",
        "other-buflo-study-v1-public-smoke-1200",
    ],
)
def test_public_campaign_identity_rejects_near_miss_names(name: str) -> None:
    assert not orchestrator._public_buflo_campaign(name)


def test_public_campaign_run_requires_typed_admission_before_creating_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("QCSD_BUFLO_CAPTURE_ADMISSION", raising=False)
    campaign = SimpleNamespace(
        name="buflo-study-v1-public-smoke-1200",
        purpose="smoke",
    )

    with pytest.raises(ValueError, match="typed capture admission"):
        orchestrator._run_loaded_campaign(campaign, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_launcher_qualification_is_restartable_build_then_semantic_verify() -> None:
    launcher = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert "requires controlled roots and exactly one --destination" in launcher
    assert 'if [[ ! -e "${qualification_target}" ]]' in launcher
    assert "existing public5 evidence must be a non-symlink directory" in launcher
    assert '"${ROOT}/qcsd-lab" qualify-response-chaff' in launcher
    assert '--env "QCSD_BUFLO_QUALIFY_CONTROLLED_ONLY=1"' in launcher
    assert "QCSD_BUFLO_QUALIFY_VERIFY_ONLY=1" in launcher
    assert '--env "QCSD_BUFLO_QUALIFY_VERIFY_ONLY=1"' in launcher
    assert 'verify_qualification_checkout "buflo-study qualify"' in launcher
    assert 'qualification_set="buflo-study-public5-v${qualification_cohort_version}"' in launcher
    assert '--volume "${ROOT}/handoffs:/lab/handoffs:ro"' in launcher


def test_launcher_rejects_duplicate_qualification_cohort_version(tmp_path: Path) -> None:
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    docker = binary_root / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = f"{binary_root}:{environment['PATH']}"

    completed = subprocess.run(
        [
            "/bin/bash",
            str(LAB_ROOT / "qcsd-lab"),
            "buflo-study",
            "qualify",
            "--controlled-result",
            str(tmp_path / "controlled"),
            "--destination",
            str(tmp_path / "receipt.json"),
            "--cohort-version",
            "2",
            "--cohort-version",
            "3",
        ],
        cwd=LAB_ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 2
    assert "at most one --cohort-version" in completed.stderr


def test_study_environment_receipt_binds_minimized_docker_bases_and_locks() -> None:
    build_execution = _build_execution_value()
    value = {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-environment",
        "docker": {
            "client_version": "29.0.1",
            "server_version": "29.0.1",
            "server_os": "linux",
            "server_arch": "arm64",
            "ncpu": 8,
            "mem_total_bytes": 16_000_000_000,
            "storage_driver": "overlayfs",
        },
        "collection_image": {
            "id": "sha256:" + "a" * 64,
            "repo_digests": ["collection@example.invalid@sha256:" + "b" * 64],
        },
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "rust_base_image": RUST_BASE_IMAGE,
            "debian_base_image": DEBIAN_BASE_IMAGE,
            "uv_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "uv.lock"),
            "cargo_lock_sha256": buflo_study.sha256_file(LAB_ROOT / "neqo-qcsd/Cargo.lock"),
        },
        "build_execution": {
            "sha256": hashlib.sha256(
                (json.dumps(build_execution, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "receipt": build_execution,
        },
        "clock_status": {
            "relationship": "container-shares-host-kernel-realtime-clock",
            "host": {
                "source": "timedatectl-NTPSynchronized-and-python-clock-gettime",
                "synchronized": True,
                "status_evidence": "NTPSynchronized=yes",
                "unavailable_reason": None,
                "realtime_unix_ns": 1_000_000_000_000,
                "monotonic_ns": 10_000,
            },
            "container": {
                "source": "python-clock-gettime-inside-collection-image",
                "synchronized": None,
                "status_evidence": None,
                "unavailable_reason": (
                    "container shares the host kernel clock and has no independent NTP service"
                ),
                "realtime_unix_ns": 1_000_000_000_001,
                "monotonic_ns": 20_000,
            },
        },
    }

    assert (
        validate_study_environment_receipt(value, expected_image_digest="sha256:" + "a" * 64)[
            "image_id"
        ]
        == "sha256:" + "a" * 64
    )
    scheduled = json.loads(json.dumps(value))
    scheduled["schema_version"] = 2
    scheduled["docker"]["ncpu"] = 12
    scheduled["capture_scheduler"] = buflo_study._capture_scheduler_environment_contract()
    validated = validate_study_environment_receipt(
        scheduled, expected_image_digest="sha256:" + "a" * 64
    )
    assert validated["capture_scheduler"]["client_affinity_cpus"] == [10]
    wrong_topology = json.loads(json.dumps(scheduled))
    wrong_topology["docker"]["ncpu"] = 16
    with pytest.raises(ValueError, match="exact 12-CPU topology"):
        validate_study_environment_receipt(wrong_topology)
    wrong_partition = json.loads(json.dumps(scheduled))
    wrong_partition["capture_scheduler"]["client_affinity_cpus"] = [9]
    with pytest.raises(ValueError, match="scheduler environment"):
        validate_study_environment_receipt(wrong_partition)
    changed = json.loads(json.dumps(value))
    changed["build_inputs"]["uv_lock_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="base image or lockfile"):
        validate_study_environment_receipt(changed)


def test_public_study_network_receipt_proves_bridge_has_no_netem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QCSD_STUDY_NETWORK_CONDITION", "public-docker-bridge-no-netem")
    monkeypatch.setattr(
        capture_session,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout='[{"kind":"noqueue","root":true}]',
        ),
    )
    receipt = capture_session._public_study_network_condition("eth0", {"verified": True})

    assert receipt is not None and receipt["valid"] is True
    diagnostics = {
        "network_condition": receipt,
        "offloads": [{"interface": "eth0", "verified": True}],
    }
    buflo_study._validate_public_network_condition(diagnostics)

    changed = json.loads(json.dumps(receipt))
    changed["observed_qdisc"] = [{"kind": "netem", "root": True}]
    changed["netem_present"] = True
    changed["valid"] = False
    with pytest.raises(ValueError, match="no-netem"):
        buflo_study._validate_public_network_condition(
            {**diagnostics, "network_condition": changed}
        )


def test_redirect_attestation_explicitly_binds_empty_prepared_and_final_sequences(
    tmp_path: Path,
) -> None:
    workload_id = "getbootstrap-home-r4"
    data = json.loads(
        (LAB_ROOT / f"config/workloads/{workload_id}.json").read_text(encoding="utf-8")
    )
    expected = {row["resource_id"]: row for row in data["preparation"]["expected_responses"]}
    responses = []
    for resource in data["resources"]:
        identity = expected[resource["id"]]
        responses.append(
            {
                "resource_id": resource["id"],
                "url": resource["url"],
                "status": identity["status"],
                "complete": True,
                "outcome": "succeeded",
            }
        )
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    (neqo / "run.json").write_text(json.dumps({"responses": responses}), encoding="utf-8")

    receipt = orchestrator._redirect_attestation(
        SimpleNamespace(id=workload_id, data=data),
        tmp_path,
    )

    assert receipt["all_redirect_sequences_empty"] is True
    assert receipt["navigation"]["redirect_sequence"] == []
    assert all(
        row["prepared_redirect_sequence"] == [] and row["final_redirect_sequence"] == []
        for row in receipt["resources"]
    )


def test_client_resource_usage_parser_has_exact_nullable_contract(tmp_path: Path) -> None:
    source = tmp_path / "time.txt"
    source.write_text(
        "user_cpu_seconds=1.25\n"
        "system_cpu_seconds=0.50\n"
        "maximum_rss_kib=42\n"
        "voluntary_context_switches=7\n"
        "involuntary_context_switches=2\n",
        encoding="utf-8",
    )

    usage = _parse_client_resource_usage(source, 2.5)

    assert _client_resource_usage_valid(usage)
    assert usage["maximum_rss_bytes"] == 42 * 1_024
    assert usage["timer_wakeups"] is None
    assert usage["timer_wakeups_unavailable_reason"]
    assert usage["rapl_energy_joules"] is None
    assert usage["rapl_unavailable_reason"]


def test_completed_buflo_resource_receipt_binds_runner_timer_wakeups(tmp_path: Path) -> None:
    source = tmp_path / "time.txt"
    source.write_text(
        "user_cpu_seconds=1.25\n"
        "system_cpu_seconds=0.50\n"
        "maximum_rss_kib=42\n"
        "voluntary_context_switches=7\n"
        "involuntary_context_switches=2\n",
        encoding="utf-8",
    )
    usage = _parse_client_resource_usage(source, 2.5)
    metrics = {
        "schema_version": 1,
        "semantics": (
            "actual_select_return_source; socket_wins_simultaneous_readiness; "
            "controller_subset_is_effective_earliest_deadline; "
            "scheduled_cells_are_not_wakeups"
        ),
        "wait_returns": 31,
        "socket_readiness_wakeups": 11,
        "timer_wakeups": 20,
        "controller_deadline_timer_wakeups": 17,
        "other_timer_wakeups": 3,
    }

    assert _runner_wakeup_metrics_valid(metrics)
    assert _fidelity_runner_wakeup_metrics_valid(metrics)
    measured = _merge_runner_wakeup_metrics(usage, metrics, required=True)
    assert measured["source"] == "gnu-time-python-monotonic-and-runner-select-v1"
    assert measured["timer_wakeups"] == 20
    assert measured["timer_wakeups_unavailable_reason"] is None
    assert _client_resource_usage_valid(measured)

    historical_v2 = dict(metrics)
    historical_v2.update(
        {
            "schema_version": 2,
            "semantics": (
                f"{metrics['semantics']}; "
                "buflo_exact_release_guard_reserves_candidate_window; "
                "buflo_exact_release_active_wait_tail_us=250; "
                "buflo_exact_release_guards_are_separately_receipted_active_waits; "
                "buflo_active_defense_socket_drains_are_single_batch; "
                "buflo_active_defense_http_drains_are_single_event; "
                "buflo_output_is_interrupted_at_guard"
            ),
            "buflo_exact_release_guard_entries": 19,
            "buflo_exact_release_guard_wait_nanoseconds": 190_000_000,
            "buflo_exact_release_active_wait_nanoseconds": 4_750_000,
            "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 73,
            "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 41,
        }
    )
    assert _runner_wakeup_metrics_valid(historical_v2)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v2)
    historical_measured = _merge_runner_wakeup_metrics(usage, historical_v2, required=True)
    assert historical_measured["timer_wakeups"] == 20

    historical_v3 = dict(historical_v2)
    historical_v3.update(
        {
            "schema_version": 3,
            "semantics": str(historical_v2["semantics"]).replace(
                "buflo_exact_release_active_wait_tail_us=250",
                "buflo_exact_release_active_wait_tail_us=5000",
            ),
        }
    )
    assert _runner_wakeup_metrics_valid(historical_v3)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v3)

    historical_v4 = dict(historical_v3)
    v4_fields = _runner_wakeup_receipt_v4()
    for key in (
        "schema_version",
        "semantics",
        "cs_exact_incoming_retry_drives",
        "cs_exact_incoming_retry_resolutions",
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
    ):
        historical_v4[key] = v4_fields[key]
    assert _runner_wakeup_metrics_valid(historical_v4)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v4)
    historical_v4_measured = _merge_runner_wakeup_metrics(usage, historical_v4, required=True)
    assert historical_v4_measured["timer_wakeups"] == 20

    historical_v5 = dict(historical_v4)
    v5_fields = _runner_wakeup_receipt_v5()
    for key in (
        "schema_version",
        "semantics",
        "buflo_exact_incoming_retry_drives",
        "buflo_exact_incoming_retry_resolutions",
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
    ):
        historical_v5[key] = v5_fields[key]
    historical_v5.update(
        {
            "buflo_exact_incoming_retry_drives": 3,
            "buflo_exact_incoming_retry_resolutions": 1,
            "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 250,
        }
    )
    assert _runner_wakeup_metrics_valid(historical_v5)
    assert _fidelity_runner_wakeup_metrics_valid(historical_v5)

    current = _runner_wakeup_receipt_v8(guard_entries=19)
    for key in (
        "wait_returns",
        "socket_readiness_wakeups",
        "timer_wakeups",
        "controller_deadline_timer_wakeups",
        "other_timer_wakeups",
        "buflo_exact_incoming_retry_drives",
        "buflo_exact_incoming_retry_resolutions",
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
        "cs_exact_incoming_retry_drives",
        "cs_exact_incoming_retry_resolutions",
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
    ):
        current[key] = historical_v5[key]
    assert _runner_wakeup_metrics_valid(current)
    assert _fidelity_runner_wakeup_metrics_valid(current)
    current_measured = _merge_runner_wakeup_metrics(usage, current, required=True)
    assert current_measured["timer_wakeups"] == 20
    assert not any(key.startswith("buflo_exact_incoming_retry_") for key in current_measured)

    inclusive_guard_boundary = dict(current)
    inclusive_guard_boundary["buflo_exact_release_active_wait_nanoseconds"] = current[
        "buflo_exact_release_guard_wait_nanoseconds"
    ]
    assert _runner_wakeup_metrics_valid(inclusive_guard_boundary)
    assert _fidelity_runner_wakeup_metrics_valid(inclusive_guard_boundary)

    invalid_active = dict(current)
    invalid_active["buflo_exact_release_active_wait_nanoseconds"] = (
        int(current["buflo_exact_release_guard_wait_nanoseconds"]) + 1
    )
    assert not _runner_wakeup_metrics_valid(invalid_active)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_active)

    invalid_empty = dict(current)
    invalid_empty["buflo_exact_release_guard_entries"] = 0
    assert not _runner_wakeup_metrics_valid(invalid_empty)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_empty)

    wrong_semantics = dict(current)
    wrong_semantics["semantics"] = historical_v2["semantics"]
    assert not _runner_wakeup_metrics_valid(wrong_semantics)
    assert not _fidelity_runner_wakeup_metrics_valid(wrong_semantics)

    missing_field = dict(current)
    missing_field.pop("buflo_exact_release_max_guard_exit_lateness_nanoseconds")
    assert not _runner_wakeup_metrics_valid(missing_field)
    assert not _fidelity_runner_wakeup_metrics_valid(missing_field)

    extra_field = {**current, "unexpected": 0}
    assert not _runner_wakeup_metrics_valid(extra_field)
    assert not _fidelity_runner_wakeup_metrics_valid(extra_field)

    for aliased_version in (True, 3.0):
        invalid_version = {**current, "schema_version": aliased_version}
        assert not _runner_wakeup_metrics_valid(invalid_version)
        assert not _fidelity_runner_wakeup_metrics_valid(invalid_version)

    invalid_retry_resolution = {
        **current,
        "cs_exact_incoming_retry_resolutions": 1,
    }
    assert not _runner_wakeup_metrics_valid(invalid_retry_resolution)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_retry_resolution)

    invalid_retry_lateness = {
        **current,
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 1,
    }
    assert not _runner_wakeup_metrics_valid(invalid_retry_lateness)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_retry_lateness)

    invalid_buflo_retry_resolution = {
        **current,
        "buflo_exact_incoming_retry_drives": 0,
        "buflo_exact_incoming_retry_resolutions": 1,
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 0,
    }
    assert not _runner_wakeup_metrics_valid(invalid_buflo_retry_resolution)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid_buflo_retry_resolution)

    terminal_deadline_lateness_without_retry_drives = {
        **current,
        "buflo_exact_incoming_retry_drives": 0,
        "buflo_exact_incoming_retry_resolutions": 0,
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 1,
    }
    assert _runner_wakeup_metrics_valid(terminal_deadline_lateness_without_retry_drives)
    assert _fidelity_runner_wakeup_metrics_valid(terminal_deadline_lateness_without_retry_drives)

    with pytest.raises(ValueError, match="lacks runner wakeup metrics"):
        _merge_runner_wakeup_metrics(usage, None, required=True)

    invalid = dict(metrics)
    invalid["wait_returns"] += 1
    assert not _runner_wakeup_metrics_valid(invalid)
    assert not _fidelity_runner_wakeup_metrics_valid(invalid)
    with pytest.raises(ValueError, match="wake.*invalid"):
        _merge_runner_wakeup_metrics(usage, invalid, required=True)


def test_extended_schedule_reconciles_typed_partial_composition(tmp_path: Path) -> None:
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    path = neqo / "schedule.csv"
    fields = SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS
    rows = [
        _typed_schedule_row(0, "outgoing", "full", 600, 600, 3),
        _typed_schedule_row(
            1,
            "outgoing",
            "partial",
            600,
            500,
            9,
            reason="congestion_limited",
        ),
        _typed_schedule_row(
            2,
            "outgoing",
            "suppressed",
            600,
            0,
            4,
            reason="congestion_limited",
        ),
        _typed_schedule_row(3, "incoming", "satisfied", 600, None, None),
    ]
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    metrics = _schedule_realization_metrics(tmp_path)

    assert metrics["typed_congestion_reason_column"] is True
    assert metrics["typed_credit_advertisement_columns"] is True
    assert metrics["typed_credit_consumption_columns"] is True
    assert metrics["typed_controller_terminal_time_column"] is True
    assert len(metrics["terminal_defense_elapsed_us_values"]) == 4
    assert metrics["incoming_credit_advertised_events"] == 1
    assert metrics["incoming_credit_consumed_events"] == 1
    assert metrics["incoming_credit_advertisement_delay_us_max"] == 100
    assert metrics["incoming_credit_consumption_delay_us_max"] == 500
    assert metrics["invalid_typed_outcome_rows"] == 0
    assert metrics["invalid_congestion_reason_events"] == 0
    assert metrics["terminal_slots_unique"] is True
    assert metrics["terminal_desired_outgoing_bytes"] == 1_800
    assert metrics["terminal_observed_outgoing_bytes"] == 1_100
    assert metrics["typed_lateness_us_total"] == 16
    assert metrics["typed_lateness_us_max"] == 9
    assert sum(metrics["typed_composition_bytes"].values()) == 1_100

    rows[-1]["credit_consumed_at_us"] = 50
    rows[-1]["credit_consumption_delay_us"] = 50
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    invalid = _schedule_realization_metrics(tmp_path)
    assert invalid["incoming_credit_consumed_events"] == 0
    assert invalid["invalid_credit_consumption_events"] == 1


def test_buflo_fidelity_requires_every_zero_error_and_typed_terminal_once() -> None:
    diagnostics = {
        **_incoming_credit(501 * 1_200),
        "buflo_paper_equivalent": False,
        "buflo_client_only": True,
        "buflo_scheduled_outgoing_cells": 501,
        "buflo_scheduled_incoming_cells": 501,
        "buflo_full_outgoing_cells": 501,
        "buflo_partial_outgoing_cells": 0,
        "buflo_suppressed_outgoing_cells": 0,
        "buflo_missed_outgoing_cells": 0,
        "buflo_missed_incoming_cells": 0,
        "buflo_outgoing_unresolved_cells": 0,
        "buflo_incoming_unresolved_cells": 0,
        "buflo_catch_up_outgoing_cells": 0,
        "buflo_catch_up_incoming_cells": 0,
        "buflo_egress_backlog_pending": False,
        "buflo_application_complete": True,
        "buflo_minimum_duration_reached": True,
        "buflo_event_guard_triggered": False,
        "buflo_terminal_subcell_pending_request_cancellations": 0,
        "buflo_terminal_subcell_stream_cancellations": 0,
        "buflo_terminal_subcell_exact_capacity_bytes_cancelled": 0,
        "buflo_terminal_subcell_latched": True,
        "buflo_terminal_subcell_latched_at_us": 10_000_001,
        "buflo_terminal_subcell_open_streams_at_latch": 0,
        "buflo_terminal_subcell_parser_lease_bytes_at_latch": 0,
        "buflo_terminal_subcell_pending_parser_boundaries_at_latch": 0,
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch": 0,
        "buflo_schedule_stop_latched": True,
        "buflo_schedule_stop_latched_at_us": 10_000_000,
        "buflo_schedule_stop_available_bytes": 0,
        "buflo_schedule_stop_required_bytes": 1_200,
        "buflo_schedule_stop_scheduled_incoming_cells": 501,
        "buflo_schedule_stop_scheduled_outgoing_cells": 501,
        "buflo_schedule_stop_terminal_incoming_cells": 501,
        "buflo_schedule_stop_terminal_outgoing_cells": 501,
    }
    schedule = _schedule_metrics(outgoing=501, incoming=501)
    canonical_targets = list(range(0, 10_000_001, 20_000))
    schedule.update(
        terminal_satisfactions={"satisfied": 1_002},
        target_times_us_by_direction={
            "outgoing": canonical_targets,
            "incoming": canonical_targets,
        },
        scheduled_sizes_by_direction={
            "outgoing": [1_200] * 501,
            "incoming": [1_200] * 501,
        },
    )

    assert fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    terminally_reordered = {
        **schedule,
        "target_times_us_by_direction": {
            "outgoing": canonical_targets,
            # Incoming rows are emitted at credit consumption.  Preserve the
            # complete cadence while emulating one credit consumed after later
            # targets on another stream or endpoint.
            "incoming": [
                *canonical_targets[:114],
                *canonical_targets[115:155],
                canonical_targets[114],
                *canonical_targets[155:],
            ],
        },
    }
    assert fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=terminally_reordered,
    )
    missing_cadence_target = {
        **terminally_reordered,
        "target_times_us_by_direction": {
            **terminally_reordered["target_times_us_by_direction"],
            "incoming": [
                *terminally_reordered["target_times_us_by_direction"]["incoming"][:-1],
                canonical_targets[-2],
            ],
        },
    }
    assert not fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=missing_cadence_target,
    )
    inside_advertisement_limit = {
        **schedule,
        "incoming_credit_advertisement_delay_us_max": 4_999,
    }
    assert fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=inside_advertisement_limit,
    )
    at_advertisement_limit = {
        **schedule,
        "incoming_credit_advertisement_delay_us_max": 5_000,
    }
    assert not fidelity_eligible(
        "buflo",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=at_advertisement_limit,
    )
    run = {
        "completion_status": "complete",
        "error": None,
        "runner_wakeup_metrics": _runner_wakeup_receipt(),
        "resolved_configuration": {"schema_version": 2, "defense": {"kind": "buflo"}},
        "defense_diagnostics": diagnostics,
        "buflo_summary": {
            "schema_version": 4,
            "kind": "buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "incoming_opportunity_semantics": (
                "client_receive_credit_and_response_qualified_chaff_attempt"
            ),
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "terminal_subcell_policy": (
                "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
            ),
            "terminal_subcell_observer_effect": (
                "typed_stop_sending_and_reset_stream_defense_control_may_follow_the_last_exact_cell"
            ),
            "terminal_schedule_stop_policy": BUFLO_SCHEDULE_STOP_POLICY,
            "diagnostics": diagnostics,
        },
        "chaff_responses": [],
        "cs_buflo_summary": None,
    }
    assert new_defense_terminal_receipts_valid(run, "buflo", require_application_complete=True)
    contradictory_error = json.loads(json.dumps(run))
    contradictory_error["error_class"] = "client-defense-fidelity-v1"
    assert not new_defense_terminal_receipts_valid(
        contradictory_error, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        run,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v2_wakeups = json.loads(json.dumps(run))
    historical_v2_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v2(),
        "buflo_exact_release_guard_entries": 19,
        "buflo_exact_release_guard_wait_nanoseconds": 190_000_000,
        "buflo_exact_release_active_wait_nanoseconds": 4_750_000,
        "buflo_exact_release_max_passive_wake_lateness_nanoseconds": 73,
        "buflo_exact_release_max_guard_exit_lateness_nanoseconds": 41,
    }
    assert new_defense_terminal_receipts_valid(
        historical_v2_wakeups, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v2_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v3_wakeups = json.loads(json.dumps(historical_v2_wakeups))
    historical_v3_wakeups["runner_wakeup_metrics"] = {
        **historical_v2_wakeups["runner_wakeup_metrics"],
        "schema_version": 3,
        "semantics": _runner_wakeup_receipt_v3()["semantics"],
    }
    assert new_defense_terminal_receipts_valid(
        historical_v3_wakeups, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v3_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v4_wakeups = json.loads(json.dumps(historical_v3_wakeups))
    historical_v4_wakeups["runner_wakeup_metrics"].update(
        {
            key: value
            for key, value in _runner_wakeup_receipt_v4().items()
            if key
            in {
                "schema_version",
                "semantics",
                "cs_exact_incoming_retry_drives",
                "cs_exact_incoming_retry_resolutions",
                "cs_exact_incoming_retry_max_phase_lateness_nanoseconds",
            }
        }
    )
    assert new_defense_terminal_receipts_valid(
        historical_v4_wakeups, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v4_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v5_wakeups = json.loads(json.dumps(historical_v4_wakeups))
    historical_v5_wakeups["runner_wakeup_metrics"].update(
        {
            key: value
            for key, value in _runner_wakeup_receipt_v5().items()
            if key
            in {
                "schema_version",
                "semantics",
                "buflo_exact_incoming_retry_drives",
                "buflo_exact_incoming_retry_resolutions",
                "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds",
            }
        }
    )
    historical_v5_wakeups["runner_wakeup_metrics"].update(
        {
            "buflo_exact_incoming_retry_drives": 3,
            "buflo_exact_incoming_retry_resolutions": 1,
            "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 250,
        }
    )
    assert new_defense_terminal_receipts_valid(
        historical_v5_wakeups, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v5_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    current_wakeups = json.loads(json.dumps(historical_v5_wakeups))
    current_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v8(guard_entries=500),
        "buflo_exact_incoming_retry_drives": 3,
        "buflo_exact_incoming_retry_resolutions": 1,
        "buflo_exact_incoming_retry_max_wake_lateness_nanoseconds": 250,
    }
    assert new_defense_terminal_receipts_valid(
        current_wakeups,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    invalid_cs_retry_metrics = json.loads(json.dumps(current_wakeups))
    invalid_cs_retry_metrics["runner_wakeup_metrics"]["cs_exact_incoming_retry_drives"] = 1
    assert not new_defense_terminal_receipts_valid(
        invalid_cs_retry_metrics, "buflo", require_application_complete=True
    )
    historical_v3 = json.loads(json.dumps(current_wakeups))
    historical_v3["buflo_summary"]["schema_version"] = 3
    historical_v3["buflo_summary"].pop("terminal_schedule_stop_policy")
    for key in BUFLO_SCHEDULE_STOP_V4_KEYS:
        historical_v3["defense_diagnostics"].pop(key)
        historical_v3["buflo_summary"]["diagnostics"].pop(key)
    assert new_defense_terminal_receipts_valid(
        historical_v3, "buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v3,
        "buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    legacy_run = json.loads(json.dumps(historical_v3))
    legacy_run["buflo_summary"]["schema_version"] = 2
    legacy_run["defense_diagnostics"].pop(
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    )
    legacy_run["buflo_summary"]["diagnostics"].pop(
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    )
    assert new_defense_terminal_receipts_valid(
        legacy_run, "buflo", require_application_complete=True
    )
    for missing in BUFLO_SCHEDULE_STOP_V4_KEYS:
        partial = json.loads(json.dumps(current_wakeups))
        partial["defense_diagnostics"].pop(missing)
        partial["buflo_summary"]["diagnostics"].pop(missing)
        assert not new_defense_terminal_receipts_valid(
            partial, "buflo", require_application_complete=True
        )
    for key, changed in (
        ("buflo_schedule_stop_latched", False),
        ("buflo_schedule_stop_latched_at_us", 10_000_002),
        ("buflo_schedule_stop_available_bytes", 1_200),
        ("buflo_schedule_stop_required_bytes", 1_199),
        ("buflo_schedule_stop_scheduled_incoming_cells", 500),
        ("buflo_schedule_stop_scheduled_outgoing_cells", 500),
        ("buflo_schedule_stop_terminal_incoming_cells", 502),
        ("buflo_schedule_stop_terminal_outgoing_cells", 500),
    ):
        invalid = json.loads(json.dumps(current_wakeups))
        invalid["defense_diagnostics"][key] = changed
        invalid["buflo_summary"]["diagnostics"][key] = changed
        assert not new_defense_terminal_receipts_valid(
            invalid, "buflo", require_application_complete=True
        )
    drifted_policy = json.loads(json.dumps(current_wakeups))
    drifted_policy["buflo_summary"]["terminal_schedule_stop_policy"] = "drifted"
    assert not new_defense_terminal_receipts_valid(
        drifted_policy, "buflo", require_application_complete=True
    )
    for key in (
        "buflo_partial_outgoing_cells",
        "buflo_missed_outgoing_cells",
        "buflo_catch_up_incoming_cells",
        "buflo_outgoing_unresolved_cells",
    ):
        changed = dict(diagnostics)
        changed[key] = 1
        assert not fidelity_eligible(
            "buflo",
            changed,
            sample_eligible=True,
            missed_events=0,
            outgoing_size_mismatches=0,
            schedule_metrics=schedule,
        )


def test_cs_buflo_fidelity_reconciles_typed_composition_and_rate_state() -> None:
    composition = {
        "application_stream_bytes": 400,
        "retransmission_stream_bytes": 100,
        "chaff_stream_bytes": 200,
        "defense_control_bytes": 2,
        "quic_padding_bytes": 300,
        "other_quic_bytes": 98,
    }
    diagnostics = {
        **_incoming_credit(600),
        "cs_buflo_paper_equivalent": False,
        "cs_buflo_client_only": True,
        "cs_buflo_payload_padding": True,
        "cs_buflo_total_padding": False,
        "cs_buflo_early_termination_semantics": (
            "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing"
        ),
        "cs_buflo_scheduled_outgoing_cells": 2,
        "cs_buflo_scheduled_incoming_cells": 1,
        "cs_buflo_full_outgoing_cells": 1,
        "cs_buflo_partial_outgoing_cells": 1,
        "cs_buflo_suppressed_outgoing_cells": 0,
        "cs_buflo_missed_outgoing_cells": 0,
        "cs_buflo_missed_incoming_cells": 0,
        "cs_buflo_desired_udp_bytes": 1_200,
        "cs_buflo_realized_udp_bytes": 1_100,
        **{f"cs_buflo_{key}": value for key, value in composition.items()},
        "cs_buflo_lateness_us_total": 12,
        "cs_buflo_lateness_us_max": 9,
        "cs_buflo_natural_outgoing_bytes": 500,
        "cs_buflo_natural_incoming_bytes": 300,
        "cs_buflo_cover_outgoing_bytes": 100,
        "cs_buflo_cover_incoming_bytes": 212,
        "cs_buflo_real_bearing_outgoing_bytes": 400,
        "cs_buflo_real_bearing_incoming_bytes": 300,
        "cs_buflo_realized_incoming_credit_bytes": 600,
        "cs_buflo_outgoing_padding_basis_natural_bytes": 500,
        "cs_buflo_incoming_padding_basis_natural_bytes": 300,
        "cs_buflo_outgoing_padding_basis_cover_bytes": 100,
        "cs_buflo_incoming_padding_basis_cover_bytes": 212,
        "cs_buflo_outgoing_padding_basis_total_bytes": 600,
        "cs_buflo_incoming_padding_basis_total_bytes": 512,
        "cs_buflo_reference_tcp_write_size_bytes": 548,
        "cs_buflo_reference_nominal_tcp_packet_size_bytes": 600,
        "cs_buflo_runtime_udp_packet_size_bytes": 600,
        "cs_buflo_outgoing_termination_accounted_bytes": 1_100,
        "cs_buflo_incoming_termination_accounted_bytes": 600,
        "cs_buflo_outgoing_last_termination_increment_bytes": 100,
        "cs_buflo_incoming_last_termination_increment_bytes": 600,
        "cs_buflo_outgoing_power_of_two_crossed": True,
        "cs_buflo_incoming_power_of_two_crossed": True,
        "cs_buflo_early_termination_translation_version": 2,
        "cs_buflo_termination_stop_policy": CS_BUFLO_TERMINATION_STOP_POLICY,
        "cs_buflo_outgoing_termination_stop_latched": True,
        "cs_buflo_incoming_termination_stop_latched": True,
        "cs_buflo_outgoing_termination_stop_crossing_total_bytes": 1_100,
        "cs_buflo_incoming_termination_stop_crossing_total_bytes": 0,
        "cs_buflo_outgoing_termination_stop_crossing_increment_bytes": 100,
        "cs_buflo_incoming_termination_stop_crossing_increment_bytes": 0,
        "cs_buflo_outgoing_termination_stop_reason": "power_of_two_crossing",
        "cs_buflo_incoming_termination_stop_reason": "padding_target_reached",
        "cs_buflo_outgoing_termination_stop_phase": "application_complete",
        "cs_buflo_incoming_termination_stop_phase": "application_complete",
        "cs_buflo_outgoing_termination_stop_latched_at_us": 1_900_000,
        "cs_buflo_incoming_termination_stop_latched_at_us": 1_800_000,
        "cs_buflo_outgoing_termination_stop_scheduled_cells_at_stop": 2,
        "cs_buflo_incoming_termination_stop_scheduled_cells_at_stop": 1,
        "cs_buflo_outgoing_termination_stop_terminal_cells_at_stop": 2,
        "cs_buflo_incoming_termination_stop_terminal_cells_at_stop": 1,
        "cs_buflo_outgoing_termination_stop_progress_bytes_at_stop": 600,
        "cs_buflo_incoming_termination_stop_progress_bytes_at_stop": 512,
        "cs_buflo_outgoing_termination_stop_padding_target_bytes_at_stop": 1_024,
        "cs_buflo_incoming_termination_stop_padding_target_bytes_at_stop": 512,
        "cs_buflo_outgoing_termination_stop_provisional_invalidation_count": 0,
        "cs_buflo_incoming_termination_stop_provisional_invalidation_count": 0,
        "cs_buflo_outgoing_padding_target_bytes": 1_024,
        "cs_buflo_incoming_padding_target_bytes": 512,
        "cs_buflo_outgoing_interval_us": 8_192,
        "cs_buflo_incoming_interval_us": 8_192,
        "cs_buflo_outgoing_rate_adaptations": 0,
        "cs_buflo_incoming_rate_adaptations": 0,
        "cs_buflo_rate_boundary_translation_version": 2,
        "cs_buflo_rate_boundary_counter_semantics": (
            "client_only_quic_fresh_application_stream_bytes_outgoing_"
            "retransmission_excluded_and_consumed_application_offsets_incoming"
        ),
        "cs_buflo_author_rate_boundary_counter_semantics": (
            "per_direction_actually_transmitted_real_plus_junk_bytes"
        ),
        "cs_buflo_rate_transitions": [],
        "cs_buflo_next_outgoing_adaptation_boundary_bytes": 16_384,
        "cs_buflo_next_incoming_adaptation_boundary_bytes": 16_384,
        "cs_buflo_outgoing_estimator_samples": 4,
        "cs_buflo_incoming_estimator_samples": 2,
        "cs_buflo_outgoing_minimum_interval_opportunities": 0,
        "cs_buflo_incoming_minimum_interval_opportunities": 0,
        "cs_buflo_incoming_minimum_interval_local_realized": 0,
        "cs_buflo_outgoing_minimum_interval_terminal": 0,
        "cs_buflo_incoming_minimum_interval_terminal": 0,
        "cs_buflo_outgoing_minimum_interval_full": 0,
        "cs_buflo_incoming_minimum_interval_full": 0,
        "cs_buflo_incoming_local_realized_cells": 1,
        "cs_buflo_outgoing_unresolved_cells": 0,
        "cs_buflo_incoming_unresolved_cells": 0,
        "cs_buflo_egress_backlog_pending": False,
        "cs_buflo_application_complete": True,
        "cs_buflo_quiet_time_reached": True,
        "cs_buflo_local_termination_latched": True,
        "cs_buflo_local_et_pending_request_cancellations": 0,
        "cs_buflo_local_et_stream_cancellations": 0,
        "cs_buflo_local_et_latched_at_us": 2_000_000,
        "cs_buflo_local_et_before_application_complete": False,
        "cs_buflo_local_et_application_receive_streams_handed_off": 0,
        "cs_buflo_local_et_application_parser_boundaries_handed_off": 0,
        "cs_buflo_local_et_application_parser_lease_bytes_handed_off": 0,
        "cs_buflo_local_et_application_send_endpoints_released": 0,
        "cs_buflo_post_local_et_natural_outgoing_bytes": 0,
        "cs_buflo_post_local_et_natural_incoming_bytes": 0,
        "cs_buflo_event_guard_triggered": False,
    }
    schedule = _schedule_metrics(outgoing=2, incoming=1)
    schedule.update(
        terminal_satisfactions={"full": 1, "partial": 1, "satisfied": 1},
        terminal_desired_outgoing_bytes=1_200,
        terminal_observed_outgoing_bytes=1_100,
        congestion_reasons={"congestion_limited": 1},
        typed_composition_bytes=composition,
        typed_lateness_us_total=12,
        typed_lateness_us_max=9,
        typed_real_bearing_outgoing_bytes=400,
    )

    assert fidelity_eligible(
        "cs-buflo-cpsp",
        diagnostics,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    run = {
        "completion_status": "complete",
        "error": None,
        "runner_wakeup_metrics": _runner_wakeup_receipt(),
        "resolved_configuration": {
            "schema_version": 2,
            "defense": {"kind": "cs_buflo"},
        },
        "defense_diagnostics": diagnostics,
        "buflo_summary": None,
        "cs_buflo_summary": {
            "schema_version": 4,
            "kind": "cs_buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "incoming_opportunity_semantics": (
                "client_receive_credit_and_response_qualified_chaff_attempt"
            ),
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "incoming_cadence_boundary": ("complete_local_on_wire_max_stream_data_advertisement"),
            "incoming_terminal_boundary": "eventual_peer_stream_offset_consumption",
            "incoming_boundary_separation": (
                "advertisement_rearms_cadence_but_does_not_claim_peer_datagram_or_consumption"
            ),
            "early_termination_semantics": (
                "client_only_outgoing_observed_udp_and_incoming_consumed_credit_"
                "power_of_two_crossing"
            ),
            "early_termination_translation_version": 2,
            "termination_stop_policy": CS_BUFLO_TERMINATION_STOP_POLICY,
            "diagnostics": diagnostics,
        },
    }
    assert new_defense_terminal_receipts_valid(run, "cs_buflo", require_application_complete=True)
    assert not new_defense_terminal_receipts_valid(
        run,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    invalid_summary_version = json.loads(json.dumps(run))
    invalid_summary_version["cs_buflo_summary"]["early_termination_translation_version"] = 2.0
    assert not new_defense_terminal_receipts_valid(
        invalid_summary_version, "cs_buflo", require_application_complete=True
    )
    invalid_stop = json.loads(json.dumps(run))
    invalid_stop["defense_diagnostics"]["cs_buflo_incoming_termination_stop_latched"] = False
    invalid_stop["cs_buflo_summary"]["diagnostics"][
        "cs_buflo_incoming_termination_stop_latched"
    ] = False
    assert not new_defense_terminal_receipts_valid(
        invalid_stop, "cs_buflo", require_application_complete=True
    )
    invalid_crossing = json.loads(json.dumps(run))
    invalid_crossing["defense_diagnostics"][
        "cs_buflo_incoming_termination_stop_crossing_total_bytes"
    ] = 700
    invalid_crossing["cs_buflo_summary"]["diagnostics"][
        "cs_buflo_incoming_termination_stop_crossing_total_bytes"
    ] = 700
    assert not new_defense_terminal_receipts_valid(
        invalid_crossing, "cs_buflo", require_application_complete=True
    )

    historical_v2_wakeups = json.loads(json.dumps(run))
    historical_v2_wakeups["runner_wakeup_metrics"] = _runner_wakeup_receipt_v2()
    assert new_defense_terminal_receipts_valid(
        historical_v2_wakeups, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v2_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v3_wakeups = json.loads(json.dumps(run))
    historical_v3_wakeups["runner_wakeup_metrics"] = _runner_wakeup_receipt_v3()
    assert new_defense_terminal_receipts_valid(
        historical_v3_wakeups, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v3_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v4_wakeups = json.loads(json.dumps(run))
    historical_v4_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v4(),
        "cs_exact_incoming_retry_drives": 3,
        "cs_exact_incoming_retry_resolutions": 1,
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 250,
    }
    assert new_defense_terminal_receipts_valid(
        historical_v4_wakeups, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v4_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    historical_v5_wakeups = json.loads(json.dumps(historical_v4_wakeups))
    historical_v5_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v5(),
        "cs_exact_incoming_retry_drives": 3,
        "cs_exact_incoming_retry_resolutions": 1,
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 250,
    }
    assert new_defense_terminal_receipts_valid(
        historical_v5_wakeups, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        historical_v5_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    current_wakeups = json.loads(json.dumps(historical_v5_wakeups))
    current_wakeups["runner_wakeup_metrics"] = {
        **_runner_wakeup_receipt_v8(),
        "cs_exact_incoming_retry_drives": 3,
        "cs_exact_incoming_retry_resolutions": 1,
        "cs_exact_incoming_retry_max_phase_lateness_nanoseconds": 250,
    }
    assert new_defense_terminal_receipts_valid(
        current_wakeups,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )
    invalid_wakeups = json.loads(json.dumps(current_wakeups))
    invalid_wakeups["runner_wakeup_metrics"]["buflo_exact_release_guard_entries"] = 1
    invalid_wakeups["runner_wakeup_metrics"]["buflo_exact_release_guard_wait_nanoseconds"] = 1
    assert not new_defense_terminal_receipts_valid(
        invalid_wakeups, "cs_buflo", require_application_complete=True
    )
    invalid_buflo_retry_wakeups = json.loads(json.dumps(current_wakeups))
    invalid_buflo_retry_wakeups["runner_wakeup_metrics"]["buflo_exact_incoming_retry_drives"] = 1
    assert not new_defense_terminal_receipts_valid(
        invalid_buflo_retry_wakeups, "cs_buflo", require_application_complete=True
    )

    legacy_v3 = json.loads(json.dumps(run))
    legacy_v3["cs_buflo_summary"]["schema_version"] = 3
    legacy_v3["cs_buflo_summary"].pop("early_termination_translation_version")
    legacy_v3["cs_buflo_summary"].pop("termination_stop_policy")
    legacy_v3["defense_diagnostics"]["cs_buflo_early_termination_semantics"] = (
        "udp_client_only_observed_udp_power_of_two_crossing"
    )
    legacy_v3["cs_buflo_summary"]["early_termination_semantics"] = (
        "udp_client_only_observed_udp_power_of_two_crossing"
    )
    legacy_v3["cs_buflo_summary"]["diagnostics"]["cs_buflo_early_termination_semantics"] = (
        "udp_client_only_observed_udp_power_of_two_crossing"
    )
    for key in CS_BUFLO_STOP_DRAIN_V4_KEYS:
        legacy_v3["defense_diagnostics"].pop(key)
        legacy_v3["cs_buflo_summary"]["diagnostics"].pop(key)
    assert new_defense_terminal_receipts_valid(
        legacy_v3, "cs_buflo", require_application_complete=True
    )
    assert not new_defense_terminal_receipts_valid(
        legacy_v3,
        "cs_buflo",
        require_application_complete=True,
        require_current_schema=True,
    )

    legacy = json.loads(json.dumps(legacy_v3))
    legacy["cs_buflo_summary"]["schema_version"] = 2
    for key in (
        "cs_buflo_local_et_latched_at_us",
        "cs_buflo_local_et_before_application_complete",
        "cs_buflo_local_et_application_receive_streams_handed_off",
        "cs_buflo_local_et_application_parser_boundaries_handed_off",
        "cs_buflo_local_et_application_parser_lease_bytes_handed_off",
        "cs_buflo_local_et_application_send_endpoints_released",
        "cs_buflo_post_local_et_natural_outgoing_bytes",
        "cs_buflo_post_local_et_natural_incoming_bytes",
    ):
        legacy["defense_diagnostics"].pop(key)
        legacy["cs_buflo_summary"]["diagnostics"].pop(key)
    assert new_defense_terminal_receipts_valid(
        legacy, "cs_buflo", require_application_complete=True
    )
    wrong_boundary = json.loads(json.dumps(run))
    wrong_boundary["cs_buflo_summary"]["incoming_terminal_boundary"] = "local-advertisement"
    assert not new_defense_terminal_receipts_valid(
        wrong_boundary, "cs_buflo", require_application_complete=True
    )
    wrong_nested = json.loads(json.dumps(run))
    wrong_nested["cs_buflo_summary"]["diagnostics"]["scheduled_incoming_consumed_bytes"] -= 1
    assert not new_defense_terminal_receipts_valid(
        wrong_nested, "cs_buflo", require_application_complete=True
    )
    quiet_only = json.loads(json.dumps(run))
    quiet_only["defense_diagnostics"]["cs_buflo_application_complete"] = False
    quiet_only["cs_buflo_summary"]["diagnostics"]["cs_buflo_application_complete"] = False
    quiet_only["defense_diagnostics"]["cs_buflo_local_et_before_application_complete"] = True
    quiet_only["cs_buflo_summary"]["diagnostics"][
        "cs_buflo_local_et_before_application_complete"
    ] = True
    quiet_only["defense_diagnostics"]["cs_buflo_local_et_application_send_endpoints_released"] = 1
    quiet_only["cs_buflo_summary"]["diagnostics"][
        "cs_buflo_local_et_application_send_endpoints_released"
    ] = 1
    assert new_defense_terminal_receipts_valid(quiet_only, "cs_buflo")
    assert not new_defense_terminal_receipts_valid(
        quiet_only, "cs_buflo", require_application_complete=True
    )
    pre_onload = dict(diagnostics)
    pre_onload.update(
        cs_buflo_local_et_before_application_complete=True,
        cs_buflo_local_et_application_receive_streams_handed_off=1,
        cs_buflo_post_local_et_natural_outgoing_bytes=50,
        cs_buflo_post_local_et_natural_incoming_bytes=25,
        cs_buflo_natural_outgoing_bytes=550,
        cs_buflo_natural_incoming_bytes=325,
    )
    assert fidelity_eligible(
        "cs-buflo-cpsp",
        pre_onload,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    for key, value in (
        ("cs_buflo_local_et_application_receive_streams_handed_off", 0),
        ("cs_buflo_natural_outgoing_bytes", 549),
        ("cs_buflo_real_bearing_incoming_bytes", 301),
    ):
        invalid_pre_onload = dict(pre_onload)
        invalid_pre_onload[key] = value
        assert not fidelity_eligible(
            "cs-buflo-cpsp",
            invalid_pre_onload,
            sample_eligible=True,
            missed_events=0,
            outgoing_size_mismatches=0,
            schedule_metrics=schedule,
        )
    changed = dict(diagnostics)
    changed["cs_buflo_quic_padding_bytes"] += 1
    assert not fidelity_eligible(
        "cs-buflo",
        changed,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    changed = dict(diagnostics)
    changed["cs_buflo_rate_boundary_counter_semantics"] = "author-counter"
    assert not fidelity_eligible(
        "cs-buflo",
        changed,
        sample_eligible=True,
        missed_events=0,
        outgoing_size_mismatches=0,
        schedule_metrics=schedule,
    )
    for key, value in (
        ("cs_buflo_incoming_local_realized_cells", 0),
        ("cs_buflo_incoming_minimum_interval_local_realized", 1),
        ("scheduled_incoming_advertised_bytes", 599),
    ):
        changed = dict(diagnostics)
        changed[key] = value
        assert not fidelity_eligible(
            "cs-buflo",
            changed,
            sample_eligible=True,
            missed_events=0,
            outgoing_size_mismatches=0,
            schedule_metrics=schedule,
        )


def test_cs_buflo_rate_transition_vector_is_causally_validated() -> None:
    from qcsd_lab.fidelity import _cs_buflo_rate_transition_vector_valid

    transition = {
        "schema_version": 1,
        "direction": "outgoing",
        "at_us": 50_000,
        "boundary_bytes": 16_384,
        "real_bearing_bytes": 17_000,
        "eligible_samples": 4,
        "median_interval_us": 6_000,
        "previous_interval_us": 8_192,
        "resulting_interval_us": 4_096,
        "retained_current_interval": False,
    }
    assert _cs_buflo_rate_transition_vector_valid([transition])
    for key, value in (
        ("boundary_bytes", 32_768),
        ("real_bearing_bytes", 1_000),
        ("resulting_interval_us", 8_192),
        ("retained_current_interval", True),
    ):
        changed = {**transition, key: value}
        assert not _cs_buflo_rate_transition_vector_valid([changed])


@pytest.mark.parametrize(
    ("natural", "cover", "expected"),
    ((1_000, 24, 1_024), (1_000, 1_100, 3_072)),
)
def test_cs_buflo_cpsp_target_uses_power_of_two_quantum_not_power_of_two_target(
    natural: int, cover: int, expected: int
) -> None:
    assert _cs_buflo_payload_padding_target(natural, cover) == expected


def test_cs_buflo_padding_gate_distinguishes_cpsp_3072_from_ctsp_4096() -> None:
    common = {
        "cs_buflo_natural_outgoing_bytes": 1_000,
        "cs_buflo_natural_incoming_bytes": 1_000,
        "cs_buflo_cover_outgoing_bytes": 1_100,
        "cs_buflo_cover_incoming_bytes": 1_100,
        "cs_buflo_realized_udp_bytes": 4_096,
        "cs_buflo_realized_incoming_credit_bytes": 3_072,
        "cs_buflo_outgoing_padding_basis_natural_bytes": 1_000,
        "cs_buflo_incoming_padding_basis_natural_bytes": 1_000,
        "cs_buflo_outgoing_padding_basis_cover_bytes": 1_100,
        "cs_buflo_incoming_padding_basis_cover_bytes": 1_100,
        "cs_buflo_outgoing_padding_basis_total_bytes": 2_100,
        "cs_buflo_incoming_padding_basis_total_bytes": 2_100,
        "cs_buflo_incoming_termination_accounted_bytes": 3_072,
        "cs_buflo_incoming_last_termination_increment_bytes": 1_100,
        "cs_buflo_incoming_power_of_two_crossed": True,
        "cs_buflo_incoming_padding_target_bytes": 3_072,
    }
    cpsp = {
        **common,
        "cs_buflo_payload_padding": True,
        "cs_buflo_total_padding": False,
        "cs_buflo_outgoing_termination_accounted_bytes": 4_096,
        "cs_buflo_outgoing_last_termination_increment_bytes": 2_100,
        "cs_buflo_outgoing_power_of_two_crossed": True,
        "cs_buflo_outgoing_padding_target_bytes": 3_072,
    }
    ctsp = {
        **common,
        "cs_buflo_payload_padding": False,
        "cs_buflo_total_padding": True,
        "cs_buflo_outgoing_termination_accounted_bytes": 4_096,
        "cs_buflo_outgoing_last_termination_increment_bytes": 0,
        "cs_buflo_outgoing_power_of_two_crossed": False,
        "cs_buflo_outgoing_padding_target_bytes": 4_096,
    }

    assert _cs_buflo_padding_targets_match(cpsp)
    assert _cs_buflo_padding_targets_match(ctsp)
    assert not _cs_buflo_padding_targets_match(
        {**cpsp, "cs_buflo_outgoing_padding_target_bytes": 4_096}
    )
    assert not _cs_buflo_padding_targets_match(
        {**ctsp, "cs_buflo_outgoing_padding_target_bytes": 3_072}
    )


def _incoming_credit(value: int) -> dict[str, int]:
    return {
        "scheduled_incoming_requested_bytes": value,
        "scheduled_incoming_advertised_bytes": value,
        "scheduled_incoming_consumed_bytes": value,
        "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0,
    }


def _schedule_metrics(*, outgoing: int, incoming: int) -> dict[str, object]:
    return {
        "scheduled_events": outgoing + incoming,
        "scheduled_outgoing_events": outgoing,
        "scheduled_incoming_events": incoming,
        "terminal_slots_unique": True,
        "duplicate_terminal_slots": 0,
        "invalid_terminal_rows": 0,
        "typed_congestion_reason_column": True,
        "typed_credit_advertisement_columns": True,
        "typed_credit_consumption_columns": True,
        "typed_controller_terminal_time_column": True,
        "invalid_congestion_reason_events": 0,
        "invalid_typed_outcome_rows": 0,
        "incoming_credit_advertised_events": incoming,
        "incoming_credit_consumed_events": incoming,
        "incoming_credit_missing_events": 0,
        "incoming_credit_consumption_missing_events": 0,
        "invalid_credit_advertisement_events": 0,
        "invalid_credit_consumption_events": 0,
        "incoming_credit_advertisement_delay_us_total": incoming * 100,
        "incoming_credit_advertisement_delay_us_max": 100 if incoming else 0,
        "incoming_credit_advertisement_delay_us_values": [100] * incoming,
        "incoming_credit_consumption_delay_us_total": incoming * 500,
        "incoming_credit_consumption_delay_us_max": 500 if incoming else 0,
        "incoming_credit_consumption_delay_us_values": [500] * incoming,
        "terminal_defense_elapsed_us_values": [0] * (outgoing + incoming),
        "terminal_satisfactions": {"satisfied": outgoing + incoming},
        "terminal_desired_outgoing_bytes": 0,
        "terminal_observed_outgoing_bytes": 0,
        "typed_composition_bytes": {},
        "typed_lateness_us_total": 0,
        "typed_lateness_us_max": 0,
        "typed_real_bearing_outgoing_bytes": 0,
        "target_times_us_by_direction": {"outgoing": [], "incoming": []},
        "scheduled_sizes_by_direction": {"outgoing": [], "incoming": []},
    }


def _typed_schedule_row(
    slot: int,
    direction: str,
    satisfaction: str,
    desired: int,
    observed: int | None,
    lateness: int | None,
    *,
    reason: str = "",
) -> dict[str, object]:
    row: dict[str, object] = {field: "" for field in SCHEDULE_PREFIX_FIELDS + SCHEDULE_QCSD_FIELDS}
    row.update(
        target_time_us=slot * 1_000,
        direction=direction,
        size=desired,
        connection=0,
        action_time_us=slot * 1_000,
        satisfaction=satisfaction,
        observed_size=("" if observed is None or satisfaction == "suppressed" else observed),
        miss_reason={"congestion_limited": "CongestionLimited"}.get(reason, ""),
        slot_id=slot,
        qcsd_outcome_schema_version=3,
        send_policy=("exact" if satisfaction == "satisfied" else "congestion_sensitive"),
        desired_udp_bytes=desired,
        observed_udp_bytes="" if observed is None else observed,
        congestion_reason=reason,
        terminal_defense_elapsed_us=(
            slot * 1_000 + (500 if direction == "incoming" else (lateness or 0))
        ),
    )
    if satisfaction in {"full", "partial", "suppressed"}:
        assert observed is not None and lateness is not None
        row.update(
            application_stream_bytes=observed,
            retransmission_stream_bytes=0,
            chaff_stream_bytes=0,
            defense_control_bytes=0,
            quic_padding_bytes=0,
            other_quic_bytes=0,
            lateness_us=lateness,
        )
    if direction == "incoming":
        row.update(
            credit_advertised_at_us=slot * 1_000 + 100,
            credit_advertisement_delay_us=100,
            credit_consumed_at_us=slot * 1_000 + 500,
            credit_consumption_delay_us=500,
        )
    return row


def test_comparison_review_cannot_omit_declared_csbuflo_incoming_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    for name in ("SHA256SUMS", "dataset.json", "samples.jsonl"):
        (handoff / name).write_text(name + "\n", encoding="utf-8")
    evaluation_receipt = tmp_path / "evaluation.json"
    evaluation_receipt.write_text("{}\n", encoding="utf-8")

    common = [
        {"difference": "transport-and-observation-layer"},
        {"difference": "endpoint-cooperation-and-peer-datagram-unavailability"},
        {"difference": "closed-world-dataset-and-classifier-protocol"},
    ]
    qcsd_rows = [
        {
            "defense": "buflo",
            "known_expected_differences": [
                *common,
                {"difference": ("buflo-terminal-subcell-client-local-cancellation")},
            ],
        },
        {
            "defense": "cs-buflo",
            "known_expected_differences": [
                *common,
                {
                    "difference": (
                        "csbuflo-author-total-transmitted-vs-live-fresh-"
                        "application-stream-byte-adaptation-counter"
                    )
                },
                {"difference": "csbuflo-incoming-boundary-translation"},
                {
                    "difference": (
                        "csbuflo-paper-source-and-client-only-early-termination-translation"
                    )
                },
            ],
        },
    ]
    historical_rows = [
        {
            "anchor_id": "buflo-tau0-rho40-d1000",
            "metrics": {"extra_bandwidth_percent": 93.5},
        },
        {
            "anchor_id": "csbuflo-sites200-ctsp-et1",
            "metrics": {"bandwidth_ratio": 2.796},
        },
    ]
    anchor_inventory = list(buflo_evaluation.historical_anchor_metric_inventory(historical_rows))
    evaluation = {
        "original_study_comparison": {
            "qcsd_rows": qcsd_rows,
            "historical_rows": historical_rows,
            "anchor_metric_inventory": anchor_inventory,
        }
    }
    monkeypatch.setattr(
        buflo_evaluation,
        "validate_evaluation_receipt",
        lambda *_args, **_kwargs: evaluation,
    )
    monkeypatch.setattr(
        buflo_handoff,
        "validate_study_handoff",
        lambda *_args, **_kwargs: handoff.resolve(),
    )

    required_ids = buflo_study._comparison_required_difference_ids(qcsd_rows)
    assert "csbuflo-incoming-boundary-translation" in required_ids
    required_ids.remove("csbuflo-incoming-boundary-translation")
    review = {
        "schema_version": 2,
        "artifact_type": buflo_study.COMPARISON_REVIEW_ARTIFACT_TYPE,
        "formal": True,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "evaluation": buflo_study._file_binding(evaluation_receipt),
        "handoff": {
            "root": str(handoff.resolve()),
            "sha256sums_sha256": hashlib.sha256((handoff / "SHA256SUMS").read_bytes()).hexdigest(),
            "dataset_sha256": hashlib.sha256((handoff / "dataset.json").read_bytes()).hexdigest(),
            "samples_sha256": hashlib.sha256((handoff / "samples.jsonl").read_bytes()).hexdigest(),
        },
        "reviewer": "independent-reviewer",
        "reviewed_at": "2026-08-27T00:00:00+00:00",
        "rows": [
            {
                "defense": ("buflo" if item["anchor_id"].startswith("buflo-") else "cs-buflo"),
                "evaluation_row_sha256": buflo_study._canonical_digest(
                    next(
                        row
                        for row in qcsd_rows
                        if row["defense"]
                        == ("buflo" if item["anchor_id"].startswith("buflo-") else "cs-buflo")
                    )
                ),
                "anchor_id": item["anchor_id"],
                "historical_row_sha256": item["historical_row_sha256"],
                "metric": metric,
                "classification": "expected",
                "explanation": (
                    f"For {item['anchor_id']} metric {metric}, the QCSD client-only QUIC "
                    "transport and Ethernet observation layer differ materially from the "
                    "published TCP experiment, so the numeric value is contextual."
                ),
            }
            for item in anchor_inventory
            for metric in item["metric_paths"]
        ],
        "required_differences": [
            {
                "difference": identifier,
                "classification": "expected",
                "explanation": (
                    f"The {identifier} difference is expected because the QCSD client-only "
                    "QUIC transport, endpoint, dataset, and observation protocol are "
                    "explicitly distinct from the original study context."
                ),
            }
            for identifier in sorted(required_ids)
        ],
        "passed": True,
    }
    review_path = tmp_path / "comparison-review.json"
    review_path.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="required-difference inventory"):
        buflo_study.validate_comparison_review(
            review_path,
            evaluation_receipt=evaluation_receipt,
            handoff=handoff,
            formal=True,
        )

    missing_identifier = "csbuflo-incoming-boundary-translation"
    complete = json.loads(json.dumps(review))
    complete["required_differences"].append(
        {
            "difference": missing_identifier,
            "classification": "expected",
            "explanation": (
                f"The {missing_identifier} difference is expected because QCSD client-only "
                "QUIC uses a local endpoint and observation protocol that cannot reproduce "
                "the modified server boundary from the original study."
            ),
        }
    )
    review_path.write_text(json.dumps(complete, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert (
        buflo_study.validate_comparison_review(
            review_path,
            evaluation_receipt=evaluation_receipt,
            handoff=handoff,
            formal=True,
        )["passed"]
        is True
    )

    generic = json.loads(json.dumps(complete))
    generic["rows"][0]["explanation"] = "reviewed"
    review_path.write_text(json.dumps(generic, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="row inventory or digest"):
        buflo_study.validate_comparison_review(
            review_path,
            evaluation_receipt=evaluation_receipt,
            handoff=handoff,
            formal=True,
        )
