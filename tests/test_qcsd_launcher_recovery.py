from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
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
import signal
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

drift_counter = os.environ.get("QCSD_TEST_FINAL_DAEMON_DRIFT_COUNTER", "")
if command == "info" and drift_counter:
    counter_path = Path(drift_counter)
    if counter_path.exists():
        count = int(counter_path.read_text(encoding="ascii")) + 1
        counter_path.write_text(str(count), encoding="ascii")
        if count >= 2:
            os.environ["QCSD_TEST_DOCKER_SERVER_ID"] = (
                "87654321-4321-4321-4321-cba987654321"
            )

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

def maybe_freeze_absent_snapshot(kind, token):
    if os.environ.get("QCSD_TEST_FREEZE_ABSENCE_KIND") != kind:
        return
    if os.environ.get("QCSD_TEST_FREEZE_ABSENCE_TOKEN") != token:
        return
    marker = Path(os.environ["QCSD_TEST_FREEZE_ABSENCE_MARKER"])
    marker.write_text(str(os.getpid()), encoding="ascii")
    os.kill(os.getpid(), signal.SIGSTOP)

def maybe_publish_deferred(kind, token):
    if os.environ.get("QCSD_TEST_DEFERRED_PUBLISH_KIND") != kind:
        return
    if os.environ.get("QCSD_TEST_DEFERRED_PUBLISH_TOKEN") != token:
        return
    counter_path = state_path.with_name("deferred-" + kind + "-list-count")
    count = (
        int(counter_path.read_text(encoding="ascii"))
        if counter_path.exists()
        else 0
    ) + 1
    counter_path.write_text(str(count), encoding="ascii")
    trigger = int(os.environ["QCSD_TEST_DEFERRED_PUBLISH_AFTER_LISTS"])
    if count != trigger:
        return
    object_id = os.environ["QCSD_TEST_DEFERRED_PUBLISH_ID"]
    if kind == "run":
        containers[object_id] = dict(token=token, running=True)
    else:
        networks[object_id] = token
    save_state(state)

if command == "container" and tail and tail[0] == "ls":
    filter_value = option_value(tail[1:], "--filter")
    log("container-ls:" + filter_value)
    selected = []
    if filter_value.startswith("label=org.qcsd.supervisor.instance="):
        token = filter_value.rsplit("=", 1)[1]
        maybe_freeze_absent_snapshot("run", token)
        maybe_publish_deferred("run", token)
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
        maybe_freeze_absent_snapshot("network", token)
        maybe_publish_deferred("network", token)
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
    supervisor = launcher.parent / "tools/docker_signal_supervisor.sh"
    with supervisor.open("a", encoding="utf-8") as output:
        output.write(
            r'''

# Test-only local-root equivalent of the production bounded namespace check.
_qcsd_secure_lifecycle_base() {
  local entry canonical metadata operation_count=0
  _qcsd_lifecycle_base="${QCSD_TEST_LIFECYCLE_BASE:?}"
  [[ "${_qcsd_lifecycle_base}" == /* && ! -L "${_qcsd_lifecycle_base}" &&
      -d "${_qcsd_lifecycle_base}" ]] || return 1
  canonical="$(readlink -f -- "${_qcsd_lifecycle_base}")" || return 1
  [[ "${canonical}" == "${_qcsd_lifecycle_base}" ]] || return 1
  metadata="$(stat -Lc '%u:%a:%F' -- "${_qcsd_lifecycle_base}")" || return 1
  [[ "${metadata}" == "$(id -u):700:directory" ]] || return 1
  for entry in "${_qcsd_lifecycle_base}"/*; do
    [[ -e "${entry}" || -L "${entry}" ]] || continue
    [[ "${entry##*/}" =~ ^(run|network|build|transaction)[.][0-9a-f]{32}$ &&
        ! -L "${entry}" && -d "${entry}" ]] || return 1
    (( operation_count += 1 ))
    _qcsd_validate_lifecycle_root_contents "${entry}" || return 1
  done
  (( operation_count <= _QCSD_MAX_LIFECYCLE_OPERATIONS ))
}
'''
        )
    guardian = launcher.parent / "tools/docker_lifecycle_lock_guardian.py"
    guardian_source = guardian.read_text(encoding="utf-8")
    shared_socket = "qcsd-docker-lifecycle-guardian-{os.getuid()}"
    isolated_socket = (
        shared_socket + f"-{hashlib.sha256(str(tmp_path).encode()).hexdigest()[:16]}"
    )
    assert guardian_source.count(shared_socket) == 2
    guardian.write_text(
        guardian_source.replace(shared_socket, isolated_socket), encoding="utf-8"
    )
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
        "if [ \"${1:-}\" = -c ]; then\n"
        "  case \"${2:-}\" in\n"
        "    *'from qcsd_lab.etf_probe import prepare_supervised_request'*)\n"
        "      printf '%s\\n' \"$*\" >> \"${QCSD_TEST_PROBE_MARKER}\"\n"
        "      exit 1\n"
        "      ;;\n"
        "  esac\n"
        "fi\n"
        "if [ \"${1:-}\" = -I ] && [ \"${2:-}\" = -c ]; then\n"
        "  case \"${3:-}\" in\n"
        "    *'from qcsd_lab.etf_probe import prepare_supervised_request'*)\n"
        "      printf '%s\\n' \"$*\" >> \"${QCSD_TEST_PROBE_MARKER}\"\n"
        "      exit 1\n"
        "      ;;\n"
        "  esac\n"
        "fi\n"
        f"exec {str(Path(sys.executable).resolve())!r} \"$@\"\n",
        encoding="utf-8",
    )
    probe_python.chmod(0o755)
    copied_launcher = launcher.read_text(encoding="utf-8")
    trusted_python_assignment = 'etf_probe_python="/usr/bin/python3"'
    assert copied_launcher.count(trusted_python_assignment) == 2
    launcher.write_text(
        copied_launcher.replace(
            trusted_python_assignment,
            f'etf_probe_python="{probe_python.resolve()}"',
        ),
        encoding="utf-8",
    )
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


def _wait_for_process_state(pid: int, wanted: str) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        except FileNotFoundError:
            break
        if stat_line.rsplit(") ", 1)[1].split()[0] == wanted:
            return
        time.sleep(0.01)
    raise AssertionError(f"process {pid} did not reach state {wanted}")


def _start_etf(
    launcher: Path, environment: dict[str, str], tmp_path: Path
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [str(launcher), "etf-probe", "--destination", str(tmp_path / "etf.json")],
        cwd=tmp_path,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def _wait_for_stopped_marker_process(
    marker: Path,
    owner: subprocess.Popen[str],
    *,
    executable: Path | None = None,
) -> int:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if marker.exists():
            try:
                pid = int(marker.read_text(encoding="ascii"))
            except (OSError, ValueError):
                pass
            else:
                _wait_for_process_state(pid, "T")
                if executable is not None:
                    observed = Path(f"/proc/{pid}/exe").resolve()
                    assert observed == executable.resolve()
                return pid
        if owner.poll() is not None:
            stdout, stderr = owner.communicate()
            raise AssertionError(
                "launcher exited before the boundary process stopped:\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        time.sleep(0.01)
    raise AssertionError(f"boundary process did not publish {marker}")


def _kill_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=5)


def _install_stopped_settle_sleep(
    environment: dict[str, str], tmp_path: Path
) -> Path:
    marker = tmp_path / "stopped-settle-sleep.pid"
    wrapper = Path(environment["QCSD_TEST_BINARY_ROOT"]) / "sleep"
    assert not wrapper.exists()
    wrapper.write_text(
        "#!/bin/sh\n"
        'if [ "$#" -eq 1 ] && [ "$1" = 0.5 ] && '
        '[ -n "${QCSD_TEST_SETTLE_SLEEP_MARKER:-}" ]; then\n'
        "  /usr/bin/sleep \"$@\" &\n"
        "  settle_pid=$!\n"
        '  while [ "$(/usr/bin/readlink -f "/proc/$settle_pid/exe" 2>/dev/null)" '
        '!= /usr/bin/sleep ]; do\n'
        '    kill -0 "$settle_pid" 2>/dev/null || exit 1\n'
        "  done\n"
        '  kill -STOP "$settle_pid"\n'
        '  printf \'%s\\n\' "$settle_pid" >"$QCSD_TEST_SETTLE_SLEEP_MARKER"\n'
        '  wait "$settle_pid"\n'
        "  exit $?\n"
        "fi\n"
        'exec /usr/bin/sleep "$@"\n',
        encoding="ascii",
    )
    wrapper.chmod(0o755)
    environment["QCSD_TEST_SETTLE_SLEEP_MARKER"] = str(marker)
    return marker


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


def _publish_daemon_object(
    state_path: Path, kind: str, token: str, object_id: str
) -> None:
    if kind == "run":
        _write_state(
            state_path,
            containers={object_id: {"token": token, "running": True}},
        )
    else:
        assert kind == "network"
        _write_state(state_path, networks={object_id: token})


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


def _durable_network_request_fields(
    launcher: Path,
    root: Path,
    token: str,
    environment: dict[str, str],
) -> list[tuple[str, str]]:
    replacements = {
        "lifecycle_state": "request-authorised",
        "network_id": "unavailable",
        "network_state": "launching",
    }
    return [
        (key, replacements.get(key, value))
        for key, value in _durable_network_handoff_fields(
            launcher, root, token, environment, "f" * 64
        )
        if key not in {"ownership", "registration_name"}
    ]


def _authorised_unresolved_recovery_fields(
    launcher: Path,
    root: Path,
    token: str,
    environment: dict[str, str],
    kind: str,
) -> list[tuple[str, str]]:
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
        assert kind == "network"
        fields = _durable_network_handoff_fields(
            launcher, root, token, environment, "unavailable"
        )
        fields = _replace_field(fields, "lifecycle_state", "unresolved")
        fields = _replace_field(fields, "network_state", "unknown")
        fields = [
            item for item in fields if item[0] not in {"ownership", "registration_name"}
        ]
    fields.append(("daemon_request_authorised", "1"))
    return fields


def _install_batch_settle_trace(launcher: Path) -> None:
    helper = launcher.parent / "tools/docker_signal_supervisor.sh"
    helper_source = helper.read_text(encoding="utf-8")
    assert helper_source.count(
        'sleep "${_QCSD_DOCKER_STALE_RUN_SETTLE_SECONDS:-5}"'
    ) == 1
    assert helper_source.count(
        'sleep "${_QCSD_DOCKER_STALE_NETWORK_SETTLE_SECONDS:-5}"'
    ) == 1
    helper.write_text(
        helper_source
        + r'''

# Test-only replacement: record each logical batch wait without wall-clock delay.
_qcsd_lifecycle_settle_recovery_batch() {
  local kind="${1:-}" pid state states="" separator=""
  for pid in ${QCSD_TEST_CONTAINMENT_PIDS:-}; do
    state=gone
    if _qcsd_read_process_identity "${pid}"; then
      state="${_qcsd_process_state}"
    fi
    states="${states}${separator}${state}"
    separator=,
  done
  printf 'settle:%s:%s\n' "${kind}" "${states}" >> \
    "${QCSD_TEST_DOCKER_OPERATION_LOG:?}"
}
''',
        encoding="utf-8",
    )


def _install_final_recovery_boundary_drift(
    launcher: Path,
    environment: dict[str, str],
    tmp_path: Path,
    kind: str,
) -> tuple[Path, Path]:
    assert kind in {"run", "network"}
    helper = launcher.parent / "tools/docker_signal_supervisor.sh"
    drift = tmp_path / f"{kind}-final-boundary-drift"
    observations = tmp_path / f"{kind}-final-boundary-observations"
    if kind == "run":
        override = r'''

# Test-only model: an exact unit with the recorded name is recreated while the
# shared daemon-settle sleep is stopped.
eval "$(declare -f _qcsd_wait_user_scope_inactive | sed \
  '1s/_qcsd_wait_user_scope_inactive/_qcsd_test_original_wait_user_scope_inactive/')"
_qcsd_wait_user_scope_inactive() {
  if [[ -e "${QCSD_TEST_FINAL_RECOVERY_BOUNDARY_DRIFT:?}" ]]; then
    printf 'blocked:run:%s\n' "$1" >> \
      "${QCSD_TEST_FINAL_RECOVERY_BOUNDARY_OBSERVATIONS:?}"
    return 1
  fi
  _qcsd_test_original_wait_user_scope_inactive "$@"
}
'''
    else:
        override = r'''

# Test-only model: the recorded network supervisor identity is no longer
# provably stale when the shared daemon-settle sleep ends.
eval "$(declare -f _qcsd_lifecycle_require_stale_supervisor | sed \
  '1s/_qcsd_lifecycle_require_stale_supervisor/_qcsd_test_original_require_stale_supervisor/')"
_qcsd_lifecycle_require_stale_supervisor() {
  if [[ -e "${QCSD_TEST_FINAL_RECOVERY_BOUNDARY_DRIFT:?}" ]]; then
    printf 'blocked:network\n' >> \
      "${QCSD_TEST_FINAL_RECOVERY_BOUNDARY_OBSERVATIONS:?}"
    return 1
  fi
  _qcsd_test_original_require_stale_supervisor "$@"
}
'''
    with helper.open("a", encoding="utf-8") as output:
        output.write(override)
    environment.update(
        QCSD_TEST_FINAL_RECOVERY_BOUNDARY_DRIFT=str(drift),
        QCSD_TEST_FINAL_RECOVERY_BOUNDARY_OBSERVATIONS=str(observations),
    )
    return drift, observations


def _invoke_etf(
    launcher: Path, environment: dict[str, str], tmp_path: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(launcher), "etf-probe", "--destination", str(tmp_path / "etf.json")],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )


def _install_final_reproof_drift(
    launcher: Path,
    environment: dict[str, str],
    tmp_path: Path,
    drift_kind: str,
) -> None:
    assert drift_kind in {"daemon", "boot"}
    source = launcher.read_text(encoding="utf-8")
    final_daemon_reproof = (
        "  reconcile_stale_docker_supervisors || exit 1\n"
        "  observed_server_id=\"$(_qcsd_docker_api info --format "
        "'{{.ID}}' 2>/dev/null)\""
    )
    assert source.count(final_daemon_reproof) == 1
    source = source.replace(
        final_daemon_reproof,
        "  reconcile_stale_docker_supervisors || exit 1\n"
        '  case "${QCSD_TEST_FINAL_REPROOF_DRIFT:-}" in\n'
        "    daemon)\n"
        "      printf '0\\n' >"
        '"${QCSD_TEST_FINAL_DAEMON_DRIFT_COUNTER:?}"\n'
        "      ;;\n"
        "    boot)\n"
        "      printf '%s\\n' ffffffff-ffff-ffff-ffff-ffffffffffff "
        '>"${QCSD_TEST_FINAL_BOOT_ID_FILE:?}"\n'
        "      ;;\n"
        "    *) exit 98 ;;\n"
        "  esac\n"
        "  observed_server_id=\"$(_qcsd_docker_api info --format "
        "'{{.ID}}' 2>/dev/null)\"",
    )
    final_boot_reproof = """  IFS= read -r observed_boot_id </proc/sys/kernel/random/boot_id ||
    observed_boot_id=""
  if [[ "${observed_boot_id}" != "${pinned_boot_id}" ]]; then
    echo "qcsd-lab host boot changed across lifecycle reconciliation" >&2"""
    assert source.count(final_boot_reproof) == 1
    source = source.replace(
        final_boot_reproof,
        "  IFS= read -r observed_boot_id "
        '<"${QCSD_TEST_FINAL_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}" ||\n'
        '    observed_boot_id=""\n'
        '  if [[ "${observed_boot_id}" != "${pinned_boot_id}" ]]; then\n'
        '    echo "qcsd-lab host boot changed across lifecycle reconciliation" >&2',
    )
    launcher.write_text(source, encoding="utf-8")
    boot_file = tmp_path / "final-reproof-boot-id"
    boot_file.write_text(
        Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii"),
        encoding="ascii",
    )
    environment.update(
        QCSD_TEST_FINAL_DAEMON_DRIFT_COUNTER=str(
            tmp_path / "final-daemon-info-count"
        ),
        QCSD_TEST_FINAL_BOOT_ID_FILE=str(boot_file),
        QCSD_TEST_FINAL_REPROOF_DRIFT=drift_kind,
    )


@pytest.mark.parametrize(
    ("root_count", "reaches_record_validation"), ((7, True), (8, False))
)
def test_lifecycle_operation_bound_precedes_recovery_mutation(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    root_count: int,
    reaches_record_validation: bool,
) -> None:
    launcher, _builds, state, operations, environment, roots = launcher_boundary
    kinds = ("run", "network", "build", "transaction")
    created: list[Path] = []
    for index in range(root_count):
        root, _token = _new_lifecycle_root(
            roots,
            environment,
            kinds[index % len(kinds)],
            token=f"{index + 1:032x}",
        )
        created.append(root)
    _write_record(created[0], "SUPERVISION", [("invalid", "record")])
    state_before = state.read_bytes()
    operations_before = operations.read_bytes()

    result = subprocess.run(
        [str(launcher), "lifecycle-recover"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )

    assert result.returncode != 0
    if reaches_record_validation:
        assert "Docker lifecycle admission found malformed state" in result.stderr
    else:
        assert "Docker lifecycle admission found malformed state" not in result.stderr
    assert all(root.is_dir() and not root.is_symlink() for root in created)
    assert state.read_bytes() == state_before
    assert operations.read_bytes() == operations_before


@pytest.mark.parametrize(
    ("drift_kind", "expected_error"),
    (
        ("daemon", "qcsd-lab Docker daemon changed across lifecycle admission"),
        ("boot", "qcsd-lab host boot changed across lifecycle reconciliation"),
    ),
)
def test_final_lifecycle_reproof_rejects_daemon_or_boot_drift_without_mutation(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    drift_kind: str,
    expected_error: str,
) -> None:
    launcher, _builds, state, operations, environment, roots = launcher_boundary
    _install_final_reproof_drift(launcher, environment, tmp_path, drift_kind)
    assert roots == []
    state_before = state.read_bytes()
    operations_before = operations.read_bytes()

    result = subprocess.run(
        [str(launcher), "lifecycle-recover"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr
    assert "Docker lifecycle reconciliation completed" not in result.stderr
    if drift_kind == "daemon":
        counter = Path(environment["QCSD_TEST_FINAL_DAEMON_DRIFT_COUNTER"])
        assert counter.read_text(encoding="ascii") == "2"
    else:
        boot = Path(environment["QCSD_TEST_FINAL_BOOT_ID_FILE"])
        assert boot.read_text(encoding="ascii") == (
            "ffffffff-ffff-ffff-ffff-ffffffffffff\n"
        )
    assert state.read_bytes() == state_before
    assert operations.read_bytes() == operations_before


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
    assert "etf-probe is disabled" not in result.stderr
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
    assert "etf-probe is disabled" not in result.stderr
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
    marker = Path(environment["QCSD_TEST_PROBE_MARKER"])
    assert "prepare_supervised_request" in marker.read_text(encoding="utf-8")


def test_multi_root_recovery_batches_settles_after_run_containment(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    _install_batch_settle_trace(launcher)
    children: list[subprocess.Popen[bytes]] = []
    try:
        for _index in range(2):
            child = subprocess.Popen(["/usr/bin/sleep", "60"], start_new_session=True)
            children.append(child)
            os.kill(child.pid, signal.SIGSTOP)
            _wait_for_process_state(child.pid, "T")

        run_entries: list[tuple[Path, str, str]] = []
        network_entries: list[tuple[Path, str, str]] = []
        for index, child in enumerate(children):
            run_root, run_token = _new_lifecycle_root(roots, environment, "run")
            network_root, network_token = _new_lifecycle_root(
                roots, environment, "network"
            )
            container_id = ("a" if index == 0 else "b") * 64
            network_id = ("c" if index == 0 else "d") * 64
            fields = _durable_run_request_fields(
                launcher, run_root, run_token, environment
            )
            identity = _process_identity(child.pid)
            for prefix in ("scope_launcher", "cli"):
                for suffix, value in zip(
                    ("pid", "start_time", "session", "process_group"),
                    identity,
                    strict=True,
                ):
                    fields = _replace_field(fields, f"{prefix}_{suffix}", value)
            _write_record(run_root, "SUPERVISION", fields)
            _write_record(
                network_root,
                "SUPERVISION",
                _durable_network_request_fields(
                    launcher, network_root, network_token, environment
                ),
            )
            run_entries.append((run_root, run_token, container_id))
            network_entries.append((network_root, network_token, network_id))

        _write_state(
            state_path,
            containers={
                container_id: {
                    "token": token,
                    "running": True,
                    "networks": [network_entries[index][2]],
                }
                for index, (_root, token, container_id) in enumerate(run_entries)
            },
            networks={
                network_id: token
                for _root, token, network_id in network_entries
            },
        )
        environment["QCSD_TEST_CONTAINMENT_PIDS"] = " ".join(
            str(child.pid) for child in children
        )

        result = _invoke_etf(launcher, environment, tmp_path)

        assert result.returncode == 1, result.stderr
        assert all(not root.exists() for root, _token, _id in run_entries)
        assert all(not root.exists() for root, _token, _id in network_entries)
        events = operations.read_text(encoding="utf-8").splitlines()
        run_settle = "settle:run:Z,Z"
        network_settle = "settle:network:Z,Z"
        assert events.count(run_settle) == 1
        assert events.count(network_settle) == 1
        container_removals = [
            events.index(f"container-rm:{container_id}")
            for _root, _token, container_id in run_entries
        ]
        network_removals = [
            events.index(f"network-rm:{network_id}")
            for _root, _token, network_id in network_entries
        ]
        assert events.index(run_settle) < min(container_removals)
        assert max(container_removals) < events.index(network_settle)
        assert events.index(network_settle) < min(network_removals)
    finally:
        for child in children:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait(timeout=5)


@pytest.mark.parametrize("kind", ["run", "network"])
def test_authorised_recovery_observes_object_published_on_first_post_settle_list(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, kind)
    object_id = ("6" if kind == "run" else "7") * 64
    _write_record(
        root,
        "RECOVERY",
        _authorised_unresolved_recovery_fields(
            launcher, root, token, environment, kind
        ),
    )
    environment.update(
        QCSD_TEST_DEFERRED_PUBLISH_KIND=kind,
        QCSD_TEST_DEFERRED_PUBLISH_TOKEN=token,
        QCSD_TEST_DEFERRED_PUBLISH_ID=object_id,
        QCSD_TEST_DEFERRED_PUBLISH_AFTER_LISTS="1",
    )

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode == 1, result.stderr
    assert not root.exists(), result.stderr
    log = operations.read_text(encoding="utf-8")
    expected = f"container-rm:{object_id}" if kind == "run" else f"network-rm:{object_id}"
    assert log.count(expected) == 1
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "containers": {},
        "networks": {},
    }
    assert Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


@pytest.mark.parametrize("kind", ["run", "network"])
def test_authorised_recovery_observes_object_published_while_settle_sleep_stopped(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, kind)
    object_id = ("4" if kind == "run" else "5") * 64
    _write_record(
        root,
        "RECOVERY",
        _authorised_unresolved_recovery_fields(
            launcher, root, token, environment, kind
        ),
    )
    sleep_marker = _install_stopped_settle_sleep(environment, tmp_path)
    process = _start_etf(launcher, environment, tmp_path)
    settle_pid: int | None = None
    try:
        settle_pid = _wait_for_stopped_marker_process(
            sleep_marker, process, executable=Path("/usr/bin/sleep")
        )
        label_list = (
            "container-ls:" if kind == "run" else "network-ls:"
        ) + f"label=org.qcsd.supervisor.instance={token}"
        assert label_list not in operations.read_text(encoding="utf-8").splitlines()
        _publish_daemon_object(state_path, kind, token, object_id)
        os.kill(settle_pid, signal.SIGCONT)
        _stdout, stderr = process.communicate(timeout=15)
    finally:
        if settle_pid is not None:
            try:
                os.kill(settle_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            _kill_process_group(process)

    assert process.returncode == 1, stderr
    assert not root.exists(), stderr
    events = operations.read_text(encoding="utf-8").splitlines()
    expected = f"container-rm:{object_id}" if kind == "run" else f"network-rm:{object_id}"
    assert label_list in events
    assert events.count(expected) == 1
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "containers": {},
        "networks": {},
    }


@pytest.mark.parametrize("kind", ["run", "network"])
def test_final_recovery_boundary_drift_during_shared_settle_blocks_mutation(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, kind)
    object_id = ("2" if kind == "run" else "3") * 64
    drift, observations = _install_final_recovery_boundary_drift(
        launcher, environment, tmp_path, kind
    )
    _write_record(
        root,
        "RECOVERY",
        _authorised_unresolved_recovery_fields(
            launcher, root, token, environment, kind
        ),
    )
    sleep_marker = _install_stopped_settle_sleep(environment, tmp_path)
    process = _start_etf(launcher, environment, tmp_path)
    settle_pid: int | None = None
    try:
        settle_pid = _wait_for_stopped_marker_process(
            sleep_marker, process, executable=Path("/usr/bin/sleep")
        )
        _publish_daemon_object(state_path, kind, token, object_id)
        drift.touch()
        os.kill(settle_pid, signal.SIGCONT)
        _stdout, stderr = process.communicate(timeout=15)
    finally:
        if settle_pid is not None:
            try:
                os.kill(settle_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            _kill_process_group(process)

    assert process.returncode == 125, stderr
    assert root.exists(), stderr
    events = operations.read_text(encoding="utf-8").splitlines()
    removal = (
        f"container-rm:{object_id}"
        if kind == "run"
        else f"network-rm:{object_id}"
    )
    assert removal not in events
    state = json.loads(state_path.read_text(encoding="utf-8"))
    collection = "containers" if kind == "run" else "networks"
    assert object_id in state[collection]
    assert observations.read_text(encoding="utf-8").splitlines() == [
        f"blocked:{kind}"
        + (f":qcsd-docker-run-{token}.scope" if kind == "run" else "")
    ]
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


@pytest.mark.parametrize("kind", ["run", "network"])
def test_receipt_inode_drift_during_settle_precedes_that_roots_docker_removal(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    peer_root, peer_token = _new_lifecycle_root(
        roots, environment, kind, token="1" * 32
    )
    target_root, target_token = _new_lifecycle_root(
        roots, environment, kind, token="2" * 32
    )
    peer_id = ("a" if kind == "run" else "b") * 64
    target_id = ("c" if kind == "run" else "d") * 64
    for identity_offset, (root, token) in enumerate(
        ((peer_root, peer_token), (target_root, target_token)), start=100
    ):
        fields = _authorised_unresolved_recovery_fields(
            launcher, root, token, environment, kind
        )
        if kind == "run":
            identity = _dead_identity(identity_offset)
            for prefix in ("scope_launcher", "cli"):
                for suffix, value in zip(
                    ("pid", "start_time", "session", "process_group"),
                    identity,
                    strict=True,
                ):
                    fields = _replace_field(fields, f"{prefix}_{suffix}", value)
        _write_record(
            root,
            "RECOVERY",
            fields,
        )
    target_receipt = target_root / "RECOVERY"
    original_inode = target_receipt.stat().st_ino
    sleep_marker = _install_stopped_settle_sleep(environment, tmp_path)
    process = _start_etf(launcher, environment, tmp_path)
    settle_pid: int | None = None
    try:
        settle_pid = _wait_for_stopped_marker_process(
            sleep_marker, process, executable=Path("/usr/bin/sleep")
        )
        if kind == "run":
            _write_state(
                state_path,
                containers={
                    peer_id: {"token": peer_token, "running": True},
                    target_id: {"token": target_token, "running": True},
                },
            )
        else:
            _write_state(
                state_path,
                networks={peer_id: peer_token, target_id: target_token},
            )
        replacement = target_root / "RECOVERY.replacement"
        replacement.write_bytes(target_receipt.read_bytes())
        replacement.chmod(0o600)
        assert replacement.stat().st_ino != original_inode
        replacement.replace(target_receipt)
        assert target_receipt.stat().st_ino != original_inode
        os.kill(settle_pid, signal.SIGCONT)
        _stdout, stderr = process.communicate(timeout=15)
    finally:
        if settle_pid is not None:
            try:
                os.kill(settle_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            _kill_process_group(process)

    assert process.returncode == 125, stderr
    assert not peer_root.exists(), stderr
    assert target_root.exists(), stderr
    events = operations.read_text(encoding="utf-8").splitlines()
    peer_removal = f"container-rm:{peer_id}" if kind == "run" else f"network-rm:{peer_id}"
    target_removal = (
        f"container-rm:{target_id}" if kind == "run" else f"network-rm:{target_id}"
    )
    assert events.count(peer_removal) == 1
    assert target_removal not in events
    state = json.loads(state_path.read_text(encoding="utf-8"))
    collection = "containers" if kind == "run" else "networks"
    assert target_id in state[collection]


@pytest.mark.parametrize("kind", ["run", "network"])
def test_authorised_recovery_retains_receipt_when_object_remains_absent(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
) -> None:
    launcher, _builds, _state, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, kind)
    _write_record(
        root,
        "RECOVERY",
        _authorised_unresolved_recovery_fields(
            launcher, root, token, environment, kind
        ),
    )

    result = _invoke_etf(launcher, environment, tmp_path)

    assert result.returncode == 125, result.stderr
    assert root.exists(), result.stderr
    assert "-rm:" not in operations.read_text(encoding="utf-8")
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


@pytest.mark.parametrize("kind", ["run", "network"])
def test_authorised_recovery_retains_late_object_after_frozen_absence_snapshot(
    launcher_boundary: tuple[Path, Path, Path, Path, dict[str, str], list[Path]],
    tmp_path: Path,
    kind: str,
) -> None:
    launcher, _builds, state_path, operations, environment, roots = launcher_boundary
    root, token = _new_lifecycle_root(roots, environment, kind)
    object_id = ("8" if kind == "run" else "9") * 64
    _write_record(
        root,
        "RECOVERY",
        _authorised_unresolved_recovery_fields(
            launcher, root, token, environment, kind
        ),
    )
    absence_marker = tmp_path / "frozen-absence.pid"
    environment.update(
        QCSD_TEST_FREEZE_ABSENCE_KIND=kind,
        QCSD_TEST_FREEZE_ABSENCE_TOKEN=token,
        QCSD_TEST_FREEZE_ABSENCE_MARKER=str(absence_marker),
    )
    process = _start_etf(launcher, environment, tmp_path)
    docker_pid: int | None = None
    try:
        docker_pid = _wait_for_stopped_marker_process(absence_marker, process)
        _publish_daemon_object(state_path, kind, token, object_id)
        os.kill(docker_pid, signal.SIGCONT)
        _stdout, stderr = process.communicate(timeout=15)
    finally:
        if docker_pid is not None:
            try:
                os.kill(docker_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            _kill_process_group(process)

    assert process.returncode == 125, stderr
    assert root.exists(), stderr
    expected = f"container-rm:{object_id}" if kind == "run" else f"network-rm:{object_id}"
    assert expected not in operations.read_text(encoding="utf-8").splitlines()
    state = json.loads(state_path.read_text(encoding="utf-8"))
    collection = "containers" if kind == "run" else "networks"
    assert object_id in state[collection]
    assert not Path(environment["QCSD_TEST_PROBE_MARKER"]).exists()


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
