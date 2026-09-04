from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from tests.test_buflo_study import _launcher_boundary_fixture, _marked_build_count


RUN_PREFIX = "qcsd-docker-supervisor."
NETWORK_PREFIX = "qcsd-docker-network-supervisor."
DOCKER_HOST = "unix:///var/run/docker.sock"


def _install_stateful_docker(
    binary_root: Path, state_path: Path, operation_log: Path
) -> None:
    base = binary_root / "docker-base"
    (binary_root / "docker").rename(base)
    wrapper = binary_root / "docker"
    wrapper.write_text(
        f"""#!/usr/bin/python3
import json
import os
import sys
from pathlib import Path

base = {str(base)!r}
state_path = Path({str(state_path)!r})
operation_log = Path({str(operation_log)!r})
arguments = sys.argv[1:]
command_arguments = list(arguments)
if len(command_arguments) >= 2 and command_arguments[0] in ("--context", "--host"):
    command_arguments = command_arguments[2:]
if not command_arguments:
    raise SystemExit(2)
command = command_arguments[0]
tail = command_arguments[1:]

def load_state():
    return json.loads(state_path.read_text(encoding="utf-8"))

def save_state(value):
    staged = state_path.with_name(state_path.name + ".next")
    staged.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    staged.replace(state_path)

def option_value(items, option):
    for index, item in enumerate(items[:-1]):
        if item == option:
            return items[index + 1]
    return ""

def log(value):
    with operation_log.open("a", encoding="utf-8") as output:
        output.write(value + "\\n")

state = load_state()
containers = state["containers"]
networks = state["networks"]

if command == "container" and tail and tail[0] == "ls":
    filter_value = option_value(tail[1:], "--filter")
    log("container-ls:" + filter_value)
    selected = []
    if filter_value.startswith("label=org.qcsd.supervisor.instance="):
        token = filter_value.rsplit("=", 1)[1]
        selected = [cid for cid, value in containers.items() if value["token"] == token]
    elif filter_value.startswith("id="):
        wanted = filter_value.split("=", 1)[1]
        selected = [cid for cid in containers if cid == wanted]
    if selected:
        print("\\n".join(sorted(selected)))
    raise SystemExit(0)

if command == "container" and tail and tail[0] == "inspect":
    cid = tail[-1]
    value = containers.get(cid)
    if value is None:
        raise SystemExit(1)
    running = "true" if value["running"] else "false"
    print(f"{{cid}}|{{value['token']}}|{{running}}")
    raise SystemExit(0)

if command == "rm":
    cid = tail[-1]
    log("container-rm:" + cid)
    if cid not in containers:
        raise SystemExit(1)
    del containers[cid]
    save_state(state)
    print(cid)
    raise SystemExit(0)

if command == "network" and tail and tail[0] == "ls":
    filter_value = option_value(tail[1:], "--filter")
    log("network-ls:" + filter_value)
    selected = []
    if filter_value.startswith("label=org.qcsd.supervisor.instance="):
        token = filter_value.rsplit("=", 1)[1]
        selected = [network_id for network_id, value in networks.items() if value == token]
    elif filter_value.startswith("id="):
        wanted = filter_value.split("=", 1)[1]
        selected = [network_id for network_id in networks if network_id == wanted]
    if selected:
        print("\\n".join(sorted(selected)))
    raise SystemExit(0)

if command == "network" and tail and tail[0] == "inspect":
    network_id = tail[-1]
    token = networks.get(network_id)
    if token is None:
        raise SystemExit(1)
    print(f"{{network_id}}|{{token}}")
    raise SystemExit(0)

if command == "network" and tail and tail[0] == "rm":
    network_id = tail[-1]
    log("network-rm:" + network_id)
    if network_id not in networks:
        raise SystemExit(1)
    if any(network_id in value.get("networks", []) for value in containers.values()):
        raise SystemExit(1)
    del networks[network_id]
    save_state(state)
    print(network_id)
    raise SystemExit(0)

os.execv(base, [base, *arguments])
""",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)


@pytest.fixture
def launcher_boundary(
    tmp_path: Path,
) -> Iterator[tuple[Path, Path, Path, Path, dict[str, str], list[Path]]]:
    launcher, build_marker, environment = _launcher_boundary_fixture(tmp_path)
    supervisor_tmp = tmp_path / "supervisor-tmp"
    supervisor_tmp.mkdir(mode=0o700)
    launcher_source = launcher.read_text(encoding="utf-8")
    replacements = {
        "readonly _QCSD_DOCKER_STALE_RUN_SETTLE_SECONDS=5": (
            "readonly _QCSD_DOCKER_STALE_RUN_SETTLE_SECONDS=0.5"
        ),
        "readonly _QCSD_DOCKER_STALE_NETWORK_SETTLE_SECONDS=5": (
            "readonly _QCSD_DOCKER_STALE_NETWORK_SETTLE_SECONDS=0.5"
        ),
        "run_roots=(/tmp/qcsd-docker-supervisor.*)": (
            f"run_roots=({supervisor_tmp}/qcsd-docker-supervisor.*)"
        ),
        "network_roots=(/tmp/qcsd-docker-network-supervisor.*)": (
            f"network_roots=({supervisor_tmp}/qcsd-docker-network-supervisor.*)"
        ),
        "legacy_roots=(/tmp/qcsd-docker-supervisor.* /tmp/qcsd-docker-network-supervisor.*)": (
            f"legacy_roots=({supervisor_tmp}/qcsd-docker-supervisor.* "
            f"{supervisor_tmp}/qcsd-docker-network-supervisor.*)"
        ),
    }
    for original, replacement in replacements.items():
        assert launcher_source.count(original) == 1
        launcher_source = launcher_source.replace(original, replacement)
    launcher.write_text(launcher_source, encoding="utf-8")
    launcher.chmod(0o755)
    state_path = tmp_path / "docker-state.json"
    operation_log = tmp_path / "docker-operations.log"
    state_path.write_text(
        json.dumps({"containers": {}, "networks": {}}, sort_keys=True),
        encoding="utf-8",
    )
    operation_log.write_text("", encoding="utf-8")
    binary_root = tmp_path / "bin"
    _install_stateful_docker(binary_root, state_path, operation_log)
    probe_marker = tmp_path / "probe-invocations"
    probe_python = binary_root / "python3"
    probe_python.write_text(
        "#!/bin/sh\n"
        "if [ \"${1:-}\" = -m ] && [ \"${2:-}\" = qcsd_lab.etf_probe ]; then\n"
        "  printf '%s\\n' \"$*\" >> \"${QCSD_TEST_PROBE_MARKER}\"\n"
        "  exit 0\n"
        "fi\n"
        f"exec {str(Path(sys.executable).resolve())!r} \"$@\"\n",
        encoding="utf-8",
    )
    probe_python.chmod(0o755)
    environment["QCSD_TEST_DOCKER_STATE"] = str(state_path)
    environment["QCSD_TEST_DOCKER_OPERATION_LOG"] = str(operation_log)
    environment["QCSD_TEST_PROBE_MARKER"] = str(probe_marker)
    environment["QCSD_TEST_SUPERVISOR_TMP"] = str(supervisor_tmp)
    roots: list[Path] = []
    yield launcher, build_marker, state_path, operation_log, environment, roots
    for root in reversed(roots):
        try:
            root_metadata = root.lstat()
        except FileNotFoundError:
            continue
        if root.is_symlink():
            root.unlink()
            continue
        lifecycle_base = Path(environment["QCSD_TEST_LIFECYCLE_BASE"])
        if root.parent == supervisor_tmp:
            assert re.fullmatch(
                rf"(?:{re.escape(RUN_PREFIX)}|{re.escape(NETWORK_PREFIX)})[0-9a-f]{{8}}",
                root.name,
            )
        else:
            assert root.parent == lifecycle_base
            assert re.fullmatch(
                r"(?:run|network|build|transaction)\.[0-9a-f]{32}", root.name
            )
        assert stat.S_ISDIR(root_metadata.st_mode)
        assert root_metadata.st_uid == os.getuid()
        for child in root.iterdir():
            assert child.parent == root
            child.unlink()
        root.rmdir()


def _new_root(
    roots: list[Path],
    environment: dict[str, str],
    *,
    network: bool = False,
    suffix: str | None = None,
) -> Path:
    prefix = NETWORK_PREFIX if network else RUN_PREFIX
    supervisor_tmp = Path(environment["QCSD_TEST_SUPERVISOR_TMP"])
    while True:
        candidate = supervisor_tmp / f"{prefix}{suffix or secrets.token_hex(4)}"
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            if suffix is not None:
                raise
            continue
        roots.append(candidate)
        return candidate


def _process_identity(pid: int) -> tuple[str, str, str, str]:
    stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = stat_line.rsplit(") ", 1)[1].split()
    return str(pid), fields[19], fields[3], fields[2]


def _dead_identity(offset: int = 0) -> tuple[str, str, str, str]:
    pid = 999_900_000 + offset
    return str(pid), str(100 + offset), str(pid), str(pid)


def _write_record(root: Path, name: str, fields: Sequence[tuple[str, str]]) -> Path:
    record = root / name
    record.write_text(
        "".join(f"{key}={value}\n" for key, value in fields), encoding="ascii"
    )
    record.chmod(0o600)
    return record


def _common_fields(
    environment: dict[str, str], supervisor: tuple[str, str, str, str], token: str
) -> list[tuple[str, str]]:
    return [
        ("supervisor_pid", supervisor[0]),
        ("supervisor_start_time", supervisor[1]),
        ("supervisor_session", supervisor[2]),
        ("supervisor_process_group", supervisor[3]),
    ]


def _run_supervision_fields(
    root: Path,
    environment: dict[str, str],
    *,
    supervisor: tuple[str, str, str, str] | None = None,
    token: str | None = None,
) -> list[tuple[str, str]]:
    supervisor = supervisor or _dead_identity()
    token = token or secrets.token_hex(16)
    server_id = environment["QCSD_TEST_DOCKER_SERVER_ID"]
    return [
        ("object", "docker-run-scope-launcher"),
        ("process_identity_role", "local-systemd-run-scope-launcher"),
        *_common_fields(environment, supervisor, token),
        ("mode", "attached"),
        ("scope_launcher_pid", "unavailable"),
        ("scope_launcher_start_time", "unavailable"),
        ("scope_launcher_session", "unavailable"),
        ("scope_launcher_process_group", "unavailable"),
        ("cli_pid", "unavailable"),
        ("cli_start_time", "unavailable"),
        ("cli_session", "unavailable"),
        ("cli_process_group", "unavailable"),
        ("container_id", "unavailable"),
        ("docker_context", "default"),
        ("docker_host", DOCKER_HOST),
        ("docker_server_id", server_id),
        ("docker_daemon_id", server_id),
        ("supervisor_label", f"org.qcsd.supervisor.instance={token}"),
        ("scope_required", "1"),
        ("scope_unit", f"qcsd-docker-run-{secrets.token_hex(16)}.scope"),
        ("scope_control_group", "unavailable"),
        ("scope_state", "declared"),
        ("host_boot_id", Path("/proc/sys/kernel/random/boot_id").read_text().strip()),
        ("status_file", str(root / "run.status")),
        ("status_file_state", "declared"),
        ("requested_signal", "none"),
        ("forwarded_target_signal", "none"),
        ("target_state", "launching"),
    ]


def _run_interim_recovery_fields(
    root: Path,
    environment: dict[str, str],
    *,
    container_id: str = "unavailable",
    target_state: str = "absent",
    token: str | None = None,
    supervisor: tuple[str, str, str, str] | None = None,
) -> list[tuple[str, str]]:
    supervisor = supervisor or _dead_identity(1)
    token = token or secrets.token_hex(16)
    launcher = _dead_identity(2)
    server_id = environment["QCSD_TEST_DOCKER_SERVER_ID"]
    return [
        ("object", "docker-run-scope-launcher"),
        ("process_identity_role", "local-systemd-run-scope-launcher"),
        *_common_fields(environment, supervisor, token),
        ("mode", "attached"),
        ("scope_launcher_pid", launcher[0]),
        ("scope_launcher_start_time", launcher[1]),
        ("scope_launcher_session", launcher[2]),
        ("scope_launcher_process_group", launcher[3]),
        ("cli_pid", launcher[0]),
        ("cli_start_time", launcher[1]),
        ("cli_session", launcher[2]),
        ("cli_process_group", launcher[3]),
        ("container_id", container_id),
        ("docker_context", "default"),
        ("docker_host", DOCKER_HOST),
        ("docker_server_id", server_id),
        ("docker_daemon_id", server_id),
        ("supervisor_label", f"org.qcsd.supervisor.instance={token}"),
        ("scope_required", "1"),
        ("scope_unit", f"qcsd-docker-run-{secrets.token_hex(16)}.scope"),
        ("scope_control_group", "unavailable"),
        ("scope_state", "absent"),
        ("host_boot_id", Path("/proc/sys/kernel/random/boot_id").read_text().strip()),
        ("status_file", str(root / "run.status")),
        ("status_file_state", "missing"),
        ("requested_signal", "none"),
        ("interruption_reason", "internal_abort"),
        ("planned_target_signal", "INT"),
        ("target_signal_attempted", "0"),
        ("target_signal_api_outcome", "not_attempted"),
        ("forwarded_target_signal", "none"),
        ("target_state", target_state),
        ("phase", "interrupted-before-daemon-teardown"),
    ]


def _run_final_unproved_scope_fields(
    root: Path, environment: dict[str, str], *, token: str | None = None
) -> list[tuple[str, str]]:
    token = token or secrets.token_hex(16)
    supervisor = _dead_identity(8)
    launcher = _dead_identity(9)
    server_id = environment["QCSD_TEST_DOCKER_SERVER_ID"]
    return [
        ("object", "docker-run-scope-launcher"),
        ("process_identity_role", "local-systemd-run-scope-launcher"),
        *_common_fields(environment, supervisor, token),
        ("mode", "attached"),
        ("scope_launcher_pid", launcher[0]),
        ("scope_launcher_start_time", launcher[1]),
        ("scope_launcher_session", launcher[2]),
        ("scope_launcher_process_group", launcher[3]),
        ("cli_pid", launcher[0]),
        ("cli_start_time", launcher[1]),
        ("cli_session", launcher[2]),
        ("cli_process_group", launcher[3]),
        ("container_id", "unavailable"),
        ("docker_context", "default"),
        ("docker_host", DOCKER_HOST),
        ("docker_server_id", server_id),
        ("docker_daemon_id", server_id),
        ("supervisor_label", f"org.qcsd.supervisor.instance={token}"),
        ("scope_required", "1"),
        ("scope_unit", f"qcsd-docker-run-{secrets.token_hex(16)}.scope"),
        ("scope_control_group", "unavailable"),
        ("scope_final_state", "unknown"),
        ("scope_leak_detected", "1"),
        ("scope_kill_attempted", "1"),
        ("scope_kill_outcome", "accepted"),
        ("scope_empty_proven", "0"),
        ("host_boot_id", Path("/proc/sys/kernel/random/boot_id").read_text().strip()),
        ("status_file", str(root / "run.status")),
        ("status_file_state", "missing"),
        ("status_file_matches", "0"),
        ("docker_command_status", "unavailable"),
        ("systemd_run_status", "137"),
        ("requested_signal", "none"),
        ("interruption_reason", "internal_abort"),
        ("planned_target_signal", "INT"),
        ("target_signal_attempted", "0"),
        ("target_signal_api_outcome", "not_attempted"),
        ("forwarded_target_signal", "none"),
        ("target_state", "absent"),
        ("forced_without_bound_target", "0"),
        ("interrupted_without_bound_target", "1"),
        ("docker_cli_forced", "1"),
        ("docker_cli_force_attempted", "1"),
        ("docker_cli_force_outcome", "accepted"),
        ("target_forced", "0"),
        ("target_force_attempted", "0"),
        ("target_force_api_outcome", "not_attempted"),
    ]


def _network_fields(
    environment: dict[str, str],
    *,
    record_name: str,
    network_id: str = "unavailable",
    network_state: str | None = None,
    token: str | None = None,
    supervisor: tuple[str, str, str, str] | None = None,
) -> list[tuple[str, str]]:
    supervisor = supervisor or _dead_identity(3)
    token = token or secrets.token_hex(16)
    server_id = environment["QCSD_TEST_DOCKER_SERVER_ID"]
    if network_state is None:
        network_state = "launching" if record_name == "SUPERVISION" else "absent"
    return [
        ("object", "network"),
        *_common_fields(environment, supervisor, token),
        ("network_id", network_id),
        ("docker_context", "default"),
        ("docker_host", DOCKER_HOST),
        ("docker_server_id", server_id),
        ("docker_daemon_id", server_id),
        ("host_boot_id", Path("/proc/sys/kernel/random/boot_id").read_text().strip()),
        ("supervisor_label", f"org.qcsd.supervisor.instance={token}"),
        ("requested_signal", "none"),
        ("network_state", network_state),
    ]


def _replace_field(
    fields: Sequence[tuple[str, str]], key: str, value: str
) -> list[tuple[str, str]]:
    replaced = [(name, value if name == key else current) for name, current in fields]
    assert replaced != list(fields)
    return replaced


def _write_state(
    state_path: Path,
    *,
    containers: dict[str, dict[str, object]] | None = None,
    networks: dict[str, str] | None = None,
) -> None:
    state_path.write_text(
        json.dumps(
            {"containers": containers or {}, "networks": networks or {}},
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _new_lifecycle_root(
    roots: list[Path],
    environment: dict[str, str],
    kind: str,
    *,
    token: str | None = None,
) -> tuple[Path, str]:
    token = token or secrets.token_hex(16)
    assert re.fullmatch(r"(?:run|network|build|transaction)", kind)
    root = Path(environment["QCSD_TEST_LIFECYCLE_BASE"]) / f"{kind}.{token}"
    root.mkdir(mode=0o700)
    roots.append(root)
    return root, token


def _durable_identity_fields(
    launcher: Path,
    root: Path,
    token: str,
    environment: dict[str, str],
    state: str,
) -> list[tuple[str, str]]:
    helper = (launcher.parent / "tools/docker_signal_supervisor.sh").resolve()
    metadata = helper.stat()
    server_id = environment["QCSD_TEST_DOCKER_SERVER_ID"]
    return [
        ("lifecycle_schema", "1"),
        ("lifecycle_state", state),
        ("lifecycle_root", str(root)),
        ("lifecycle_token", token),
        ("supervisor_source_path", str(helper)),
        ("supervisor_source_sha256", hashlib.sha256(helper.read_bytes()).hexdigest()),
        ("supervisor_source_device", str(metadata.st_dev)),
        ("supervisor_source_inode", str(metadata.st_ino)),
        ("docker_context", "default"),
        ("docker_host", DOCKER_HOST),
        ("docker_server_id", server_id),
        ("docker_request_revalidation", "in-scope-immediately-before-mutation"),
        ("docker_daemon_id", server_id),
        ("host_boot_id", Path("/proc/sys/kernel/random/boot_id").read_text().strip()),
    ]


def _durable_run_handoff_fields(
    launcher: Path,
    root: Path,
    token: str,
    environment: dict[str, str],
    container_id: str,
) -> list[tuple[str, str]]:
    supervisor = _dead_identity(40)
    scope_launcher = _dead_identity(42)
    return [
        ("object", "docker-run-scope-launcher"),
        ("process_identity_role", "local-systemd-run-scope-launcher"),
        *_durable_identity_fields(
            launcher, root, token, environment, "handed-off"
        ),
        ("supervisor_pid", supervisor[0]),
        ("supervisor_start_time", supervisor[1]),
        ("supervisor_session", supervisor[2]),
        ("supervisor_process_group", supervisor[3]),
        ("mode", "detached"),
        ("scope_launcher_pid", scope_launcher[0]),
        ("scope_launcher_start_time", scope_launcher[1]),
        ("scope_launcher_session", scope_launcher[2]),
        ("scope_launcher_process_group", scope_launcher[3]),
        ("cli_pid", scope_launcher[0]),
        ("cli_start_time", scope_launcher[1]),
        ("cli_session", scope_launcher[2]),
        ("cli_process_group", scope_launcher[3]),
        ("container_id", container_id),
        ("supervisor_label", f"org.qcsd.supervisor.instance={token}"),
        ("request_argv_sha256", "a" * 64),
        ("scope_required", "1"),
        ("scope_unit", f"qcsd-docker-run-{token}.scope"),
        ("scope_control_group", "unavailable"),
        ("status_file", str(root / "run.status")),
        ("status_file_state", "valid"),
        ("scope_final_state", "absent"),
        ("scope_empty_proven", "1"),
        ("status_file_matches", "1"),
        ("docker_command_status", "0"),
        ("systemd_run_status", "0"),
        ("requested_signal", "none"),
        ("forwarded_target_signal", "none"),
        ("target_state", "running"),
        ("ownership", "caller-cleanup-array"),
        ("registration_name", "QCSD_DOCKER_IDS_SIDECARS"),
    ]


def _durable_run_request_fields(
    launcher: Path,
    root: Path,
    token: str,
    environment: dict[str, str],
) -> list[tuple[str, str]]:
    fields = _durable_run_handoff_fields(
        launcher, root, token, environment, "f" * 64
    )
    remove = {
        "scope_final_state", "scope_empty_proven", "status_file_matches",
        "docker_command_status", "systemd_run_status", "ownership",
        "registration_name",
    }
    fields = [(key, value) for key, value in fields if key not in remove]
    replacements = {
        "lifecycle_state": "request-authorised",
        "mode": "attached",
        "container_id": "unavailable",
        "scope_state": "declared",
        "status_file_state": "declared",
        "target_state": "launching",
    }
    result = []
    for key, value in fields:
        result.append((key, replacements.get(key, value)))
        if key == "scope_control_group":
            result.append(("scope_state", "declared"))
    return result


def _durable_transaction_fields(
    launcher: Path,
    root: Path,
    token: str,
    environment: dict[str, str],
    tmp_path: Path,
) -> list[tuple[str, str]]:
    return [
        ("object", "docker-build-transaction"),
        *_durable_identity_fields(
            launcher, root, token, environment, "request-authorised"
        ),
        ("working_directory", str(launcher.parent.resolve())),
        ("cohort_version", "23"),
        ("receipt_path", str((tmp_path / "build-receipt.json").resolve())),
        ("transaction_state", "uncommitted-static-tag-mutation"),
    ]


def _durable_build_declared_fields(
    launcher: Path, root: Path, token: str, environment: dict[str, str], lock: Path
) -> list[tuple[str, str]]:
    metadata = lock.stat()
    return [
        ("object", "docker-build-scope-launcher"),
        ("process_identity_role", "local-systemd-run-scope-launcher"),
        *_durable_identity_fields(launcher, root, token, environment, "declared"),
        ("scope_launcher_pid", "unavailable"),
        ("scope_launcher_start_time", "unavailable"),
        ("scope_launcher_session", "unavailable"),
        ("scope_launcher_process_group", "unavailable"),
        ("build_lock_path", str(lock)),
        ("build_lock_device", str(metadata.st_dev)),
        ("build_lock_inode", str(metadata.st_ino)),
        ("working_directory", str(launcher.parent.resolve())),
        ("build_argv_sha256", "c" * 64),
        ("scope_required", "1"),
        ("scope_unit", f"qcsd-docker-build-{token}.scope"),
        ("scope_control_group", "unavailable"),
        ("scope_state", "declared"),
        ("status_file", str(root / "build.status")),
        ("status_file_state", "declared"),
        ("requested_signal", "none"),
        ("forwarded_cli_signal", "none"),
        ("daemon_cancellation", "unavailable-client-disconnect-only"),
    ]


def _durable_network_handoff_fields(
    launcher: Path,
    root: Path,
    token: str,
    environment: dict[str, str],
    network_id: str,
) -> list[tuple[str, str]]:
    supervisor = _dead_identity(41)
    return [
        ("object", "network"),
        *_durable_identity_fields(launcher, root, token, environment, "handed-off"),
        ("supervisor_pid", supervisor[0]),
        ("supervisor_start_time", supervisor[1]),
        ("supervisor_session", supervisor[2]),
        ("supervisor_process_group", supervisor[3]),
        ("network_id", network_id),
        ("supervisor_label", f"org.qcsd.supervisor.instance={token}"),
        ("request_argv_sha256", "b" * 64),
        ("requested_signal", "none"),
        ("network_state", "present"),
        ("ownership", "caller-cleanup-array"),
        ("registration_name", "QCSD_DOCKER_IDS_NETWORKS"),
    ]


def _invoke_etf(
    launcher: Path, environment: dict[str, str], tmp_path: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(launcher), "etf-probe", "--output", str(tmp_path / "etf.json")],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )


def test_legacy_idless_run_is_quarantined_before_host_probe(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, _state, operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment)
    _write_record(root, "SUPERVISION", _run_supervision_fields(root, environment))
    (tmp_path / "neqo-qcsd/Cargo.lock").unlink()
    state_before = _state.read_bytes()
    operations_before = operations.read_bytes()

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0, result.stderr
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert root.exists(), result.stderr
    marker = Path(environment["QCSD_TEST_PROBE_MARKER"])
    assert not marker.exists()
    assert _state.read_bytes() == state_before
    assert operations.read_bytes() == operations_before


def test_legacy_live_supervisor_is_quarantined_without_probe_or_cleanup(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state, operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment)
    _write_record(
        root,
        "SUPERVISION",
        _run_supervision_fields(
            root, environment, supervisor=_process_identity(os.getpid())
        ),
    )

    state_before = state.read_bytes()
    operations_before = operations.read_bytes()
    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert root.exists()
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()
    assert state.read_bytes() == state_before
    assert operations.read_bytes() == operations_before


@pytest.mark.parametrize(
    "mutation",
    (
        "record-mode",
        "root-mode",
        "record-symlink",
        "root-symlink",
        "recordless",
        "unexpected-entry",
        "cross-kind-file",
        "staged",
        "context",
        "host",
        "server",
        "daemon",
        "boot",
        "label",
        "container-id",
        "cidfile",
        "supervisor-pid",
        "declared-signal",
        "field-order",
    ),
)
def test_malformed_or_unbound_run_state_blocks_fail_closed(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    mutation: str,
) -> None:
    launcher, _builds, _state, _operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment)
    fields = _run_supervision_fields(root, environment)
    if mutation == "context":
        fields = _replace_field(fields, "docker_context", "different-context")
    elif mutation == "host":
        fields = _replace_field(fields, "docker_host", "unix:///different/docker.sock")
    elif mutation == "server":
        fields = _replace_field(fields, "docker_server_id", "different-daemon")
    elif mutation == "daemon":
        fields = _replace_field(fields, "docker_daemon_id", "different-daemon")
    elif mutation == "boot":
        fields = _replace_field(
            fields, "host_boot_id", "00000000-0000-0000-0000-000000000001"
        )
    elif mutation == "label":
        fields = _replace_field(fields, "supervisor_label", "forged")
    elif mutation == "container-id":
        fields = _replace_field(fields, "container_id", "abc123")
    elif mutation == "supervisor-pid":
        fields = _replace_field(fields, "supervisor_pid", "0")
    elif mutation == "declared-signal":
        fields = _replace_field(fields, "requested_signal", "TERM")
    elif mutation == "field-order":
        fields[-1], fields[-2] = fields[-2], fields[-1]
    record = _write_record(root, "SUPERVISION", fields)
    if mutation == "record-mode":
        record.chmod(0o644)
    elif mutation == "root-mode":
        root.chmod(0o755)
    elif mutation == "record-symlink":
        target = tmp_path / "foreign-supervision-record"
        target.write_bytes(record.read_bytes())
        target.chmod(0o600)
        record.unlink()
        record.symlink_to(target)
    elif mutation == "root-symlink":
        record.unlink()
        root.rmdir()
        target = tmp_path / "foreign-supervisor-root"
        target.mkdir()
        root.symlink_to(target, target_is_directory=True)
    elif mutation == "recordless":
        record.unlink()
    elif mutation == "unexpected-entry":
        unexpected = root / "unowned-state"
        unexpected.write_text("unexpected\n", encoding="ascii")
        unexpected.chmod(0o600)
    elif mutation == "cross-kind-file":
        impossible = root / "build.status"
        impossible.write_text("0\n", encoding="ascii")
        impossible.chmod(0o600)
    elif mutation == "cidfile":
        cidfile = root / "container.cid"
        cidfile.write_text("short-id\n", encoding="ascii")
        cidfile.chmod(0o600)
    elif mutation == "staged":
        staged = root / "SUPERVISION.next"
        staged.write_text("staged\n", encoding="ascii")
        staged.chmod(0o600)

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "Docker admission" in result.stderr
    assert root.exists()
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


@pytest.mark.parametrize("case", ["conflict", "duplicate-cidfile-only"])
def test_all_cidfiles_validate_before_any_multi_root_mutation(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    case: str,
) -> None:
    launcher, _builds, _state, operations, environment, roots = launcher_boundary
    first, first_token = _new_lifecycle_root(roots, environment, "run")
    second, second_token = _new_lifecycle_root(roots, environment, "run")
    first_id = "a" * 64
    second_id = "b" * 64
    _write_record(
        first,
        "HANDOFF",
        _durable_run_handoff_fields(
            launcher, first, first_token, environment, first_id
        ),
    )
    if case == "conflict":
        second_fields = _durable_run_handoff_fields(
            launcher, second, second_token, environment, second_id
        )
        cid = first_id
    else:
        second_fields = _durable_run_request_fields(
            launcher, second, second_token, environment
        )
        cid = first_id
    _write_record(second, "HANDOFF" if case == "conflict" else "SUPERVISION", second_fields)
    cidfile = second / "container.cid"
    cidfile.write_text(f"{cid}\n", encoding="ascii")
    cidfile.chmod(0o600)

    before = operations.read_text(encoding="utf-8")
    result = _invoke_etf(launcher, environment, tmp_path)
    after = operations.read_text(encoding="utf-8")[len(before):]

    assert result.returncode != 0
    assert "Docker lifecycle admission found malformed state" in result.stderr or case == "duplicate-cidfile-only"
    assert "container-rm:" not in after
    assert "container-kill:" not in after
    assert first.exists() and second.exists()


@pytest.mark.parametrize(
    ("kind", "impossible_name"),
    [
        ("run", "build.status"),
        ("network", "container.cid"),
        ("build", "run.status"),
        ("transaction", "build.status"),
    ],
)
def test_durable_root_rejects_cross_kind_private_children_before_mutation(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
    impossible_name: str,
) -> None:
    launcher, _builds, _state, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, kind)
    if kind == "run":
        name = "HANDOFF"
        fields = _durable_run_handoff_fields(
            launcher, root, token, environment, "a" * 64
        )
    elif kind == "network":
        name = "HANDOFF"
        fields = _durable_network_handoff_fields(
            launcher, root, token, environment, "b" * 64
        )
    elif kind == "transaction":
        name = "SUPERVISION"
        fields = _durable_transaction_fields(
            launcher, root, token, environment, tmp_path
        )
    else:
        name = "SUPERVISION"
        lock = tmp_path / "build.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        fields = _durable_build_declared_fields(
            launcher, root, token, environment, lock
        )
    _write_record(root, name, fields)
    impossible = root / impossible_name
    impossible.write_text("0\n", encoding="ascii")
    impossible.chmod(0o600)
    before = operations.read_text(encoding="utf-8")

    result = _invoke_etf(launcher, environment, tmp_path)
    after = operations.read_text(encoding="utf-8")[len(before):]

    assert result.returncode != 0
    assert "Docker lifecycle admission found malformed state" in result.stderr
    assert "container-rm:" not in after
    assert "network-rm:" not in after
    assert "container-kill:" not in after
    assert root.exists()


def test_legacy_dual_network_records_are_quarantined_without_inspection(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, _state, operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment, network=True)
    token = secrets.token_hex(16)
    supervisor = _dead_identity(4)
    _write_record(
        root,
        "SUPERVISION",
        _network_fields(
            environment,
            record_name="SUPERVISION",
            token=token,
            supervisor=supervisor,
        ),
    )
    _write_record(
        root,
        "RECOVERY",
        _network_fields(
            environment,
            record_name="RECOVERY",
            token=token,
            supervisor=supervisor,
        ),
    )

    state_before = _state.read_bytes()
    operations_before = operations.read_bytes()
    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0, result.stderr
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert root.exists()
    assert _state.read_bytes() == state_before
    assert operations.read_bytes() == operations_before
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


def test_legacy_mismatched_dual_records_are_quarantined_and_preserved(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state, operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment, network=True)
    supervisor = _dead_identity(5)
    _write_record(
        root,
        "SUPERVISION",
        _network_fields(
            environment,
            record_name="SUPERVISION",
            token="1" * 32,
            supervisor=supervisor,
        ),
    )
    _write_record(
        root,
        "RECOVERY",
        _network_fields(
            environment,
            record_name="RECOVERY",
            token="2" * 32,
            supervisor=supervisor,
        ),
    )

    state_before = state.read_bytes()
    operations_before = operations.read_bytes()
    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert root.exists()
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()
    assert state.read_bytes() == state_before
    assert operations.read_bytes() == operations_before


def test_legacy_labelled_container_is_quarantined_without_removal(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment)
    token = secrets.token_hex(16)
    container_id = "a" * 64
    _write_state(
        state_path,
        containers={container_id: {"token": token, "running": True}},
    )
    _write_record(
        root,
        "RECOVERY",
        _run_interim_recovery_fields(
            root,
            environment,
            container_id=container_id,
            target_state="running",
            token=token,
        ),
    )

    state_before = state_path.read_bytes()
    operations_before = operations.read_bytes()
    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0, result.stderr
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert root.exists()
    assert state_path.read_bytes() == state_before
    assert operations.read_bytes() == operations_before
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


def test_legacy_unproved_scope_record_is_quarantined_without_recovery(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, _state, operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment)
    _write_record(root, "RECOVERY", _run_final_unproved_scope_fields(root, environment))

    state_before = _state.read_bytes()
    operations_before = operations.read_bytes()
    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0, result.stderr
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert root.exists()
    assert _state.read_bytes() == state_before
    assert operations.read_bytes() == operations_before
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


def test_legacy_ambiguous_labelled_containers_are_quarantined_unchanged(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment)
    token = secrets.token_hex(16)
    first_id = "a" * 64
    second_id = "b" * 64
    _write_state(
        state_path,
        containers={
            first_id: {"token": token, "running": True},
            second_id: {"token": token, "running": False},
        },
    )
    _write_record(
        root,
        "RECOVERY",
        _run_interim_recovery_fields(
            root, environment, target_state="unknown", token=token
        ),
    )

    state_before = state_path.read_bytes()
    operations_before = operations.read_bytes()
    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert root.exists()
    assert state_path.read_bytes() == state_before
    assert operations.read_bytes() == operations_before
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


def test_legacy_labelled_network_is_quarantined_without_removal(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment, network=True)
    token = secrets.token_hex(16)
    network_id = "c" * 64
    _write_state(state_path, networks={network_id: token})
    _write_record(
        root,
        "RECOVERY",
        _network_fields(
            environment,
            record_name="RECOVERY",
            network_id=network_id,
            network_state="present",
            token=token,
        ),
    )

    state_before = state_path.read_bytes()
    operations_before = operations.read_bytes()
    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0, result.stderr
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert root.exists()
    assert state_path.read_bytes() == state_before
    assert operations.read_bytes() == operations_before
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


def test_full_admission_set_is_validated_before_any_exact_object_removal(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    valid_root = _new_root(roots, environment, suffix="00000000")
    invalid_root = _new_root(roots, environment, suffix="ffffffff")
    token = secrets.token_hex(16)
    container_id = "d" * 64
    _write_state(
        state_path,
        containers={container_id: {"token": token, "running": True}},
    )
    _write_record(
        valid_root,
        "RECOVERY",
        _run_interim_recovery_fields(
            valid_root,
            environment,
            container_id=container_id,
            target_state="running",
            token=token,
        ),
    )
    invalid_record = _write_record(
        invalid_root,
        "SUPERVISION",
        _run_supervision_fields(invalid_root, environment),
    )
    invalid_record.chmod(0o644)

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "container-rm:" not in operations.read_text(encoding="utf-8")
    assert container_id in json.loads(state_path.read_text(encoding="utf-8"))["containers"]
    assert valid_root.exists()
    assert invalid_root.exists()


def test_legacy_duplicate_nonce_roots_are_quarantined_unchanged(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    first_root = _new_root(roots, environment, suffix="00000001")
    second_root = _new_root(roots, environment, suffix="fffffffe")
    token = secrets.token_hex(16)
    container_id = "e" * 64
    _write_state(
        state_path,
        containers={container_id: {"token": token, "running": True}},
    )
    _write_record(
        first_root,
        "RECOVERY",
        _run_interim_recovery_fields(
            first_root,
            environment,
            container_id=container_id,
            target_state="running",
            token=token,
            supervisor=_dead_identity(6),
        ),
    )
    _write_record(
        second_root,
        "SUPERVISION",
        _run_supervision_fields(
            second_root,
            environment,
            token=token,
            supervisor=_dead_identity(7),
        ),
    )

    state_before = state_path.read_bytes()
    operations_before = operations.read_bytes()
    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "Docker admission quarantines legacy /tmp ownership state" in result.stderr
    assert first_root.exists() and second_root.exists()
    assert state_path.read_bytes() == state_before
    assert operations.read_bytes() == operations_before
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


@pytest.mark.parametrize(
    ("kind", "staged_name"),
    (
        ("run", None),
        ("run", "SUPERVISION.next"),
        ("network", "SUPERVISION.next"),
        ("build", "SUPERVISION.next"),
        ("transaction", "SUPERVISION.next"),
    ),
)
def test_durable_unpublished_lifecycle_roots_are_recovered_before_docker_work(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
    staged_name: str | None,
) -> None:
    launcher, _builds, _state, operations, environment, roots = launcher_boundary
    root, _token = _new_lifecycle_root(roots, environment, kind)
    if staged_name is not None:
        staged = root / staged_name
        staged.write_text("partial-pre-request-receipt\n", encoding="ascii")
        staged.chmod(0o600)

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode == 1, result.stderr
    assert "etf-probe is disabled" in result.stderr
    assert "Recovered unpublished Docker" in result.stderr
    assert not root.exists()
    assert "container-rm:" not in operations.read_text(encoding="utf-8")
    assert "network-rm:" not in operations.read_text(encoding="utf-8")


def test_durable_handoff_is_recovered_by_exact_label_and_full_container_id(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, "run")
    container_id = "e" * 64
    _write_state(
        state_path,
        containers={container_id: {"token": token, "running": True}},
    )
    _write_record(
        root,
        "HANDOFF",
        _durable_run_handoff_fields(
            launcher, root, token, environment, container_id
        ),
    )

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode == 1, result.stderr
    assert "etf-probe is disabled" in result.stderr
    assert not root.exists()
    assert json.loads(state_path.read_text(encoding="utf-8"))["containers"] == {}
    log = operations.read_text(encoding="utf-8")
    assert log.count(f"container-rm:{container_id}") == 1
    assert log.count(f"container-ls:id={container_id}") >= 2


def test_durable_recovery_removes_attached_run_before_its_network(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    run_root, run_token = _new_lifecycle_root(roots, environment, "run")
    network_root, network_token = _new_lifecycle_root(roots, environment, "network")
    container_id = "8" * 64
    network_id = "9" * 64
    _write_state(
        state_path,
        containers={
            container_id: {
                "token": run_token,
                "running": True,
                "networks": [network_id],
            }
        },
        networks={network_id: network_token},
    )
    _write_record(
        run_root,
        "HANDOFF",
        _durable_run_handoff_fields(
            launcher, run_root, run_token, environment, container_id
        ),
    )
    _write_record(
        network_root,
        "HANDOFF",
        _durable_network_handoff_fields(
            launcher, network_root, network_token, environment, network_id
        ),
    )

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode == 1, result.stderr
    assert not run_root.exists()
    assert not network_root.exists()
    log = operations.read_text(encoding="utf-8")
    assert log.index(f"container-rm:{container_id}") < log.index(
        f"network-rm:{network_id}"
    )


@pytest.mark.parametrize("kind", ["run", "network"])
@pytest.mark.parametrize("publish_delay", [0.25, 2.0, None])
def test_authorised_recovery_waits_for_delayed_daemon_object(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
    publish_delay: float | None,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, kind)
    object_id = ("6" if kind == "run" else "7") * 64
    if kind == "run":
        fields = _durable_run_handoff_fields(
            launcher, root, token, environment, "unavailable"
        )
        fields = _replace_field(fields, "lifecycle_state", "unresolved")
        fields = _replace_field(fields, "target_state", "unknown")
        fields = [
            item
            for item in fields
            if item[0]
            not in {
                "ownership",
                "registration_name",
                "scope_final_state",
                "scope_empty_proven",
                "status_file_matches",
                "docker_command_status",
                "systemd_run_status",
            }
        ]
        fields.extend(
            [
                ("scope_state", "absent"),
                ("interruption_reason", "internal_abort"),
                ("planned_target_signal", "TERM"),
                ("target_signal_attempted", "0"),
                ("target_signal_api_outcome", "not_attempted"),
                ("phase", "interrupted-before-daemon-teardown"),
            ]
        )
    else:
        fields = _durable_network_handoff_fields(
            launcher, root, token, environment, "unavailable"
        )
        fields = _replace_field(fields, "lifecycle_state", "unresolved")
        fields = _replace_field(fields, "network_state", "unknown")
        fields = [
            item for item in fields if item[0] not in {"ownership", "registration_name"}
        ]
    fields.append(("daemon_request_authorised", "1"))
    _write_record(root, "RECOVERY", fields)
    environment["_QCSD_DOCKER_STALE_RUN_SETTLE_SECONDS"] = "0.5"
    environment["_QCSD_DOCKER_STALE_NETWORK_SETTLE_SECONDS"] = "0.5"

    def publish_delayed_object() -> None:
        assert publish_delay is not None
        time.sleep(publish_delay)
        if kind == "run":
            _write_state(
                state_path,
                containers={object_id: {"token": token, "running": True}},
            )
        else:
            _write_state(state_path, networks={object_id: token})

    publisher = (
        threading.Thread(target=publish_delayed_object)
        if publish_delay is not None
        else None
    )
    if publisher is not None:
        publisher.start()
    result = _invoke_etf(launcher, environment, tmp_path)
    if publisher is not None:
        publisher.join(timeout=3)

    assert publisher is None or not publisher.is_alive()
    assert result.returncode == 1, result.stderr
    if publish_delay is None or publish_delay > 0.5:
        assert root.exists(), result.stderr
        assert "-rm:" not in operations.read_text(encoding="utf-8")
        return
    assert not root.exists(), result.stderr
    log = operations.read_text(encoding="utf-8")
    expected = f"container-rm:{object_id}" if kind == "run" else f"network-rm:{object_id}"
    assert log.count(expected) == 1
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "containers": {},
        "networks": {},
    }


def test_durable_source_mismatch_blocks_without_touching_exact_container(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, "run")
    container_id = "f" * 64
    _write_state(
        state_path,
        containers={container_id: {"token": token, "running": True}},
    )
    fields = _durable_run_handoff_fields(
        launcher, root, token, environment, container_id
    )
    fields = _replace_field(fields, "supervisor_source_sha256", "0" * 64)
    _write_record(root, "HANDOFF", fields)

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "malformed state" in result.stderr
    assert root.exists()
    assert container_id in json.loads(state_path.read_text(encoding="utf-8"))["containers"]
    assert "container-rm:" not in operations.read_text(encoding="utf-8")


def test_unresolved_durable_transaction_blocks_complete_set_before_mutation(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    run_root, run_token = _new_lifecycle_root(roots, environment, "run")
    container_id = "d" * 64
    _write_state(
        state_path,
        containers={container_id: {"token": run_token, "running": True}},
    )
    _write_record(
        run_root,
        "HANDOFF",
        _durable_run_handoff_fields(
            launcher, run_root, run_token, environment, container_id
        ),
    )
    transaction_root, transaction_token = _new_lifecycle_root(
        roots, environment, "transaction"
    )
    _write_record(
        transaction_root,
        "SUPERVISION",
        _durable_transaction_fields(
            launcher,
            transaction_root,
            transaction_token,
            environment,
            tmp_path,
        ),
    )

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "blocked by unresolved build state" in result.stderr
    assert run_root.exists()
    assert transaction_root.exists()
    assert container_id in json.loads(state_path.read_text(encoding="utf-8"))["containers"]
    assert "container-rm:" not in operations.read_text(encoding="utf-8")


def test_build_path_runs_same_admission_gate_before_first_docker_build(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, build_marker, _state, _operations, environment, roots = launcher_boundary
    root = _new_root(roots, environment)
    record = _write_record(
        root, "SUPERVISION", _run_supervision_fields(root, environment)
    )
    record.chmod(0o644)

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", "901"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )

    assert result.returncode != 0
    assert "Docker admission" in result.stderr
    assert _marked_build_count(build_marker) == 0


def test_mixed_legacy_and_durable_namespaces_block_before_any_mutation(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    durable_root, token = _new_lifecycle_root(roots, environment, "run")
    container_id = "8" * 64
    _write_state(
        state_path,
        containers={container_id: {"token": token, "running": True}},
    )
    _write_record(
        durable_root,
        "HANDOFF",
        _durable_run_handoff_fields(
            launcher, durable_root, token, environment, container_id
        ),
    )
    legacy_root = _new_root(roots, environment, suffix="abcdef12")
    _write_record(
        legacy_root,
        "SUPERVISION",
        _run_supervision_fields(legacy_root, environment),
    )

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode != 0
    assert "refuses mixed legacy and durable ownership namespaces" in result.stderr
    assert durable_root.exists() and legacy_root.exists()
    assert container_id in json.loads(state_path.read_text(encoding="utf-8"))["containers"]
    log = operations.read_text(encoding="utf-8")
    assert "container-rm:" not in log
    assert "network-rm:" not in log
