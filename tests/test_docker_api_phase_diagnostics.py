"""Real dispatcher bodies with fixture-only service I/O; no Docker/systemd access."""
import os
import hashlib
import json
from pathlib import Path
import re
import shlex
import signal
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/docker_signal_supervisor.sh"
BASE = "b8483c7507250112cd6655b1541ee7e872ac8eb1"
FUNCTIONS = ("_qcsd_docker_api", "_qcsd_docker_api_with_timeout",
             "_qcsd_docker_api_raw_with_timeout", "_qcsd_pinned_docker_api_with_timeout",
             "_qcsd_valid_pinned_docker_host", "_qcsd_docker_api_service_with_timeout",
             "_qcsd_completed_topology_remove")
SENTINEL = "PRIVATE_OBJECT_ENV_SCRIPT_SECRET_SENTINEL"
FIXTURE = ROOT / "tests/fixtures/b848-docker-api-source.json"
FIXTURE_SHA = "ec910ad1b3f134d4b2100d4d663f94268c03ead90cf8c22d0a7895ba956e3ca3"

def historical():
    raw = FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA
    value = json.loads(raw)
    assert value["base_lab_commit"] == BASE and set(value["functions"]) == set(FUNCTIONS)
    for row in value["functions"].values():
        assert hashlib.sha256(row["source"].encode()).hexdigest() == row["sha256"]
    return value

def baseline(relative):
    assert relative == "tools/docker_signal_supervisor.sh"
    return "\n".join(historical()["functions"][name]["source"] for name in FUNCTIONS)

def body(source, name):
    start = source.index(name + "() {")
    end = source.index("\n}\n", start) + 3
    return source[start:end]

def harness(tmp_path, args, *, code=125, pinned=False, current=True,
            phase="router-uplink", caller="direct", stderr_closed=False, child_signal=False, duration="3"):
    fixture = tmp_path / "lifecycle"
    fixture.mkdir(exist_ok=True)
    capture = tmp_path / ("current-argv" if current else "baseline-argv")
    source = HELPER.read_text() if current else baseline("tools/docker_signal_supervisor.sh")
    # Native/cgroup/source I/O is fixture-only. The production API routing,
    # status capture/return and new diagnostic branch remain exact.
    preamble = r'''
set -euo pipefail
_QCSD_DOCKER_API_TIMEOUT_SECONDS=3
_QCSD_DOCKER_COMPLETED_TOPOLOGY_TIMEOUT_SECONDS=17
_QCSD_LIFETIME_SIGNAL_STATUS=0
_QCSD_LIFECYCLE_QCSD_PID=1234
_QCSD_LIFECYCLE_QCSD_START=5678
_QCSD_LIFECYCLE_NATIVE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
_qcsd_revalidate_helper_source_identity() { return 0; }
_qcsd_require_user_cgroup_manager() { return 0; }
_qcsd_supervisor_token() { printf '00000000000000000000000000000000\n'; }
_qcsd_query_user_scope() { _qcsd_scope_state=absent; return 0; }
_qcsd_retirement_native_op() {
  printf '%s\0' "$@" >"$CAPTURE_ARGV"
  printf 'original API stdout\n'
'''
    if child_signal:
        preamble += "  bash -c 'kill -TERM $$'\n"
    else:
        preamble += f"  return {code}\n"
    preamble += "}\n"
    preamble = preamble.replace("_QCSD_DOCKER_API_TIMEOUT_SECONDS=3", "_QCSD_DOCKER_API_TIMEOUT_SECONDS=" + duration)
    preamble += "_qcsd_lifecycle_base=" + shlex.quote(str(fixture)) + "\n"
    preamble += "CAPTURE_ARGV=" + shlex.quote(str(capture)) + "\n"
    preamble += "_qcsd_api_phase=" + shlex.quote(phase) + "\n"
    preamble += "_qcsd_api_action=" + shlex.quote(SENTINEL + "\ninjected action") + "\n"
    if pinned:
        preamble += "_QCSD_DOCKER_PINNED_HOST=unix:///fixture/docker.sock\n_QCSD_DOCKER_PINNED_SERVER_ID=fixture-daemon\n_QCSD_DOCKER_PINNED_CONTEXT=default\n"
    script = preamble + "\n".join(body(source, name) for name in FUNCTIONS) + "\n"
    command = "_qcsd_docker_api " + shlex.join(args)
    if caller == "conditional":
        script += f"if {command}; then printf 'caller-success\\n'; else status=$?; printf 'caught=%d\\n' \"$status\"; fi\n"
    elif caller == "errexit":
        script += command + "\nprintf 'unreachable\\n'\n"
    elif caller == "cleanup":
        script += "set +e\n_qcsd_completed_topology_remove 0 " + shlex.join(args) + "\nstatus=$?\nprintf 'restored=%s\\n' \"$_qcsd_api_phase\"\nexit \"$status\"\n"
    else:
        script += "set +e\n" + command + "\nexit \"$?\"\n"
    if stderr_closed:
        script = "exec 2>&-\n" + script
    result = subprocess.run(["bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, timeout=5)
    arguments = capture.read_bytes().split(b"\0")[:-1] if capture.exists() else []
    return result, arguments

@pytest.mark.parametrize("code", [0, 1, 125, 130, 137, 143, 255])
@pytest.mark.parametrize("pinned", [False, True])
def test_exact_status_stdout_argv_and_fixed_failed_diagnostic(tmp_path, code, pinned):
    args = ["network", "connect", "--gw-priority", "1", SENTINEL, SENTINEL + "\nscript"]
    current, current_argv = harness(tmp_path, args, code=code, pinned=pinned)
    old, old_argv = harness(tmp_path, args, code=code, pinned=pinned, current=False)
    assert current.returncode == old.returncode == code
    assert current.stdout == old.stdout == b"original API stdout\n"
    assert current_argv == old_argv
    assert current.stderr == (f"qcsd-api-failure phase=router-uplink action=network-connect status={code} bound_s=3\n".encode() if code else b"")
    assert SENTINEL.encode() not in current.stderr

@pytest.mark.parametrize("args,action", [
    (["--context", "default", "container", "inspect", SENTINEL], "container-inspect"),
    (["exec", SENTINEL, "/bin/sh", "-c", SENTINEL], "container-exec"),
    (["network", "rm", "a" * 64], "network-remove"),
    ([SENTINEL, SENTINEL], "other"),
])
def test_only_known_action_enums_leave_dispatcher(tmp_path, args, action):
    current, argv = harness(tmp_path, args, code=42)
    old, old_argv = harness(tmp_path, args, code=42, current=False)
    assert argv == old_argv and current.returncode == old.returncode == 42
    assert current.stderr == f"qcsd-api-failure phase=router-uplink action={action} status=42 bound_s=3\n".encode()

@pytest.mark.parametrize("caller", ["conditional", "errexit"])
def test_conditional_and_errexit_caller_semantics_do_not_change(tmp_path, caller):
    args = ["exec", SENTINEL, SENTINEL]
    current, argv = harness(tmp_path, args, code=37, caller=caller)
    old, old_argv = harness(tmp_path, args, code=37, caller=caller, current=False)
    assert current.returncode == old.returncode == (0 if caller == "conditional" else 37)
    assert current.stdout == old.stdout
    assert argv == old_argv
    assert b"unreachable" not in current.stdout
    assert current.stderr == b"qcsd-api-failure phase=router-uplink action=container-exec status=37 bound_s=3\n"

def test_actual_child_term_status_is_not_reinterpreted_as_timeout(tmp_path):
    current, argv = harness(tmp_path, ["exec", SENTINEL], child_signal=True)
    old, old_argv = harness(tmp_path, ["exec", SENTINEL], child_signal=True, current=False)
    assert current.returncode == old.returncode == 128 + signal.SIGTERM
    assert current.stdout == old.stdout and argv == old_argv
    assert current.stderr == old.stderr + b"qcsd-api-failure phase=router-uplink action=container-exec status=143 bound_s=3\n"
    assert b"timeout" not in current.stderr

def test_secret_phase_is_rejected_and_closed_stderr_preserves_failure(tmp_path):
    current, _ = harness(tmp_path, [SENTINEL], code=41, phase=SENTINEL + "\nsecret")
    assert current.returncode == 41
    assert current.stderr == b"qcsd-api-failure phase=unspecified action=other status=41 bound_s=3\n"
    closed, argv = harness(tmp_path, ["exec", SENTINEL], code=41, stderr_closed=True)
    old, old_argv = harness(tmp_path, ["exec", SENTINEL], code=41, stderr_closed=True, current=False)
    assert closed.returncode == old.returncode == 41
    assert closed.stdout == old.stdout and argv == old_argv and closed.stderr == b""

@pytest.mark.parametrize("args,phase,action", [
    (["rm", "--force", "a" * 64], "cleanup-router", "container-remove"),
    (["network", "rm", "b" * 64], "cleanup-network", "network-remove"),
])
def test_cleanup_phase_is_local_and_keeps_exact_longer_service_argv(tmp_path, args, phase, action):
    current, argv = harness(tmp_path, args, code=19, phase="client-birth", caller="cleanup")
    old, old_argv = harness(tmp_path, args, code=19, phase="client-birth", caller="cleanup", current=False)
    assert current.returncode == old.returncode == 19
    assert current.stdout == old.stdout == b"original API stdout\nrestored=client-birth\n"
    assert argv == old_argv and b"17" in argv
    assert current.stderr == f"qcsd-api-failure phase={phase} action={action} status=19 bound_s=17\n".encode()

def test_launcher_contains_only_shell_local_literal_phase_annotations():
    current = (ROOT / "qcsd-lab").read_text()
    stripped = re.sub(r"^  (?:local )?_qcsd_api_phase=[a-z-]+\n", "", current, flags=re.MULTILINE)
    for name, expected in historical()["qcsd_units"].items():
        if name == "public-launch":
            start = stripped.index('  kernel_tx_public_router_name="qcsd-kernel-tx-public-router-$$"')
            end = stripped.index("\nfi\n\n# The role starts", start) + 4
            unit = stripped[start:end]
        else:
            unit = body(stripped, name)
        assert hashlib.sha256(unit.encode()).hexdigest() == expected
    assert "export _qcsd_api_phase" not in current
    assert "trap '.*ERR" not in current


def test_pathological_private_duration_is_not_changed_or_printed_unbounded(tmp_path):
    duration = "9" * 200
    current, argv = harness(tmp_path, ["exec", SENTINEL], code=43, duration=duration)
    old, old_argv = harness(tmp_path, ["exec", SENTINEL], code=43, duration=duration, current=False)
    assert current.returncode == old.returncode == 43
    assert argv == old_argv and duration.encode() in argv
    assert current.stdout == old.stdout
    assert current.stderr == b"qcsd-api-failure phase=router-uplink action=container-exec status=43 bound_s=unreported\n"
    assert len(current.stderr) < 128
