from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import textwrap
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/docker_signal_supervisor.sh"
CONTAINER_ID = "a" * 64
NETWORK_ID = "b" * 64


LIFECYCLE_ISOLATION_SHIM = r'''\
# Helper-level tests must never share the production durability namespace.
# Preserve its root/type/mode contract, but bind discovery and mutation to one
# fixture-owned directory.
_qcsd_secure_lifecycle_base() {
  local uid entry entry_name operation_kind operation_token expected_kind
  local expected_mode metadata canonical nullglob_was_set=0 dotglob_was_set=0
  local -a entries=()
  local -A operation_kinds=()
  uid="${EUID}"
  [[ "${uid}" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  _qcsd_lifecycle_base="${QCSD_TEST_LIFECYCLE_BASE:?}"
  [[ "${_qcsd_lifecycle_base}" == /* && ! -L "${_qcsd_lifecycle_base}" &&
      -d "${_qcsd_lifecycle_base}" ]] || return 1
  canonical="$(readlink -f -- "${_qcsd_lifecycle_base}" 2>/dev/null)" || return 1
  [[ "${canonical}" == "${_qcsd_lifecycle_base}" ]] || return 1
  metadata="$(stat -Lc '%u:%a:%F' -- "${_qcsd_lifecycle_base}" 2>/dev/null)" ||
    return 1
  [[ "${metadata}" == "${uid}:700:directory" ]] || return 1

  shopt -q nullglob && nullglob_was_set=1
  shopt -q dotglob && dotglob_was_set=1
  shopt -s nullglob dotglob
  entries=("${_qcsd_lifecycle_base}"/*)
  (( nullglob_was_set != 0 )) || shopt -u nullglob
  (( dotglob_was_set != 0 )) || shopt -u dotglob
  for entry in "${entries[@]}"; do
    entry_name="${entry##*/}"
    if [[ "${entry_name}" =~ ^(run|network|build|transaction)[.]([0-9a-f]{32})$ ]]; then
      operation_kind="${BASH_REMATCH[1]}"; operation_token="${BASH_REMATCH[2]}"
      expected_kind=directory; expected_mode=700
    elif [[ "${entry_name}" =~ ^[.]retired[.](run|network|build|transaction)[.]([0-9a-f]{32})$ ]]; then
      operation_kind="${BASH_REMATCH[1]}"; operation_token="${BASH_REMATCH[2]}"
      expected_kind=directory; expected_mode=700
    elif [[ "${entry_name}" =~ ^retirement[.](run|network|build|transaction)[.]([0-9a-f]{32})([.]next)?$ ]]; then
      operation_kind="${BASH_REMATCH[1]}"; operation_token="${BASH_REMATCH[2]}"
      expected_kind="regular file"; expected_mode=600
    else
      return 1
    fi
    [[ -z "${operation_kinds[${operation_token}]+x}" ||
        "${operation_kinds[${operation_token}]}" == "${operation_kind}" ]] || return 1
    operation_kinds["${operation_token}"]="${operation_kind}"
    canonical="$(readlink -f -- "${entry}" 2>/dev/null)" || return 1
    [[ "${canonical}" == "${entry}" ]] || return 1
    metadata="$(stat -Lc '%u:%a:%F' -- "${entry}" 2>/dev/null)" || return 1
    if [[ "${expected_kind}" == directory ]]; then
      [[ "${metadata}" == "${uid}:${expected_mode}:directory" ]] || return 1
      _qcsd_validate_lifecycle_root_contents "${entry}" || return 1
    else
      [[ "${metadata}" == "${uid}:${expected_mode}:regular file" ||
          "${metadata}" == "${uid}:${expected_mode}:regular empty file" ]] || return 1
    fi
  done
  (( ${#operation_kinds[@]} <= _QCSD_MAX_LIFECYCLE_OPERATIONS ))
}
_qcsd_lifecycle_lock_path() {
  printf '%s.lock\n' "${QCSD_TEST_LIFECYCLE_BASE:?}"
}
'''


FAKE_DOCKER = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root = Path(os.environ["FAKE_DOCKER_STATE"])
root.mkdir(parents=True, exist_ok=True)
args = sys.argv[1:]
docker_context = os.environ.get("FAKE_DOCKER_CONTEXT", "default")
docker_host = "unavailable"
if args[:1] == ["--context"]:
    if len(args) < 3:
        raise SystemExit(2)
    docker_context = args[1]
    args = args[2:]
elif args[:1] == ["--host"]:
    if len(args) < 3:
        raise SystemExit(2)
    docker_host = args[1]
    args = args[2:]

def log(*parts):
    with (root / "calls.log").open("a", encoding="utf-8") as target:
        target.write(" ".join(str(part) for part in parts) + "\n")

def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(value, encoding="ascii")
    os.replace(temporary, path)

def remove_container():
    for name in ("container", "container-token", "running"):
        (root / name).unlink(missing_ok=True)

def container_records():
    records = []
    for prefix in ("", "foreign-"):
        cid_path = root / f"{prefix}container"
        token_path = root / f"{prefix}container-token"
        if cid_path.exists() and token_path.exists():
            records.append((
                cid_path.read_text(encoding="ascii"),
                token_path.read_text(encoding="ascii"),
                (root / f"{prefix}running").exists(),
                prefix,
            ))
    return records

def record_for_id(cid):
    return next((record for record in container_records() if record[0] == cid), None)

def remove_container_id(cid):
    record = record_for_id(cid)
    if record is None:
        return
    prefix = record[3]
    for name in ("container", "container-token", "running"):
        (root / f"{prefix}{name}").unlink(missing_ok=True)

def network_records():
    records = []
    for prefix in ("", "foreign-"):
        id_path = root / f"{prefix}network"
        token_path = root / f"{prefix}network-token"
        if id_path.exists() and token_path.exists():
            records.append((
                id_path.read_text(encoding="ascii"),
                token_path.read_text(encoding="ascii"),
                prefix,
            ))
    return records

def network_for_id(network_id):
    return next((record for record in network_records() if record[0] == network_id), None)

def remove_network_id(network_id):
    record = network_for_id(network_id)
    if record is None:
        return
    prefix = record[2]
    (root / f"{prefix}network").unlink(missing_ok=True)
    (root / f"{prefix}network-token").unlink(missing_ok=True)

def create_container(cid, token):
    write(root / "container", cid)
    write(root / "container-token", token)
    write(root / "running", "true")
    write(root / "run-ready", str(os.getpid()))

def spawn_escaped_child(kind):
    descendant_code = r"""
import os
from pathlib import Path
import signal
import sys
import time

state = Path(sys.argv[1])
kind = sys.argv[2]
for requested in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
    signal.signal(requested, signal.SIG_IGN)
(state / f"{kind}-escaped-pid").write_text(str(os.getpid()), encoding="ascii")
(state / f"{kind}-escaped-cgroup").write_text(
    Path("/proc/self/cgroup").read_text(encoding="ascii"), encoding="ascii"
)
(state / f"{kind}-escaped-ready").write_text(str(os.getpid()), encoding="ascii")
while True:
    time.sleep(0.02)
"""
    descendant = subprocess.Popen(
        [sys.executable, "-c", descendant_code, str(root), kind],
        start_new_session=True,
        close_fds=False,
        stdin=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 2
    while not (root / f"{kind}-escaped-ready").exists():
        if time.monotonic() >= deadline:
            raise SystemExit(125)
        time.sleep(0.01)

if args and args[0] == "__delayed_container":
    time.sleep(float(os.environ.get("FAKE_DELAY_SECONDS", "1.1")))
    create_container(args[1], args[2])
    log("DELAYED_CREATE", args[1])
    raise SystemExit(0)

# Model the real Docker CLI closing unrelated inherited descriptors, including
# the acquisition flock descriptor retained by the supervising shell. Selected
# build tests deliberately keep inherited descriptors open so they can prove
# that the shell wrapper itself closes the explicitly supplied build-lock FD.
if not (
    args[:1] == ["build"]
    and os.environ.get("FAKE_BUILD_KEEP_INHERITED_FDS") == "1"
):
    os.closerange(3, 256)

if not args:
    raise SystemExit(2)

with (root / "cgroups.log").open("a", encoding="utf-8") as target:
    target.write(Path("/proc/self/cgroup").read_text(encoding="ascii"))

with (root / "contexts.log").open("a", encoding="utf-8") as target:
    binding = docker_context if docker_host == "unavailable" else docker_host
    target.write(binding + " " + " ".join(args[:2]) + "\n")

if os.environ.get("FAKE_EXPECT_DOCKER_ENV_STRIPPED") == "1":
    forbidden = (
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    )
    if any(name in os.environ for name in forbidden):
        log("AMBIENT_DOCKER_ENV_LEAK", *forbidden)
        raise SystemExit(124)

if args[:2] == ["context", "show"]:
    print(os.environ.get("FAKE_DOCKER_CONTEXT", "default"))
    raise SystemExit(0)

if args[:1] == ["info"]:
    log("INFO", docker_host)
    write(
        root / "last-api-cgroup",
        Path("/proc/self/cgroup").read_text(encoding="ascii"),
    )
    if os.environ.get("FAKE_ESCAPE_ON_COMMAND") == "info":
        spawn_escaped_child("api")
    attempt_counter_path = root / "info-attempt-counter"
    attempt_counter = (
        int(attempt_counter_path.read_text(encoding="ascii"))
        if attempt_counter_path.exists()
        else 0
    )
    write(attempt_counter_path, str(attempt_counter + 1))
    info_delays = os.environ.get(
        "FAKE_INFO_DELAY_SEQUENCE", os.environ.get("FAKE_INFO_DELAY", "0")
    ).split(",")
    info_delay = float(info_delays[min(attempt_counter, len(info_delays) - 1)])
    if info_delay:
        time.sleep(info_delay)
    server_ids = os.environ.get(
        "FAKE_DOCKER_SERVER_ID_SEQUENCE",
        os.environ.get("FAKE_DOCKER_SERVER_ID", "daemon-test-id"),
    ).split(",")
    counter_path = root / "info-counter"
    counter = int(counter_path.read_text(encoding="ascii")) if counter_path.exists() else 0
    write(counter_path, str(counter + 1))
    print(server_ids[min(counter, len(server_ids) - 1)])
    raise SystemExit(0)

if args[0] == "build":
    behavior = os.environ.get("FAKE_BUILD_BEHAVIOR", "natural0")
    write(root / "build-cli-pid", str(os.getpid()))
    try:
        cgroup = Path("/proc/self/cgroup").read_text(encoding="ascii").strip()
    except OSError:
        cgroup = "unavailable"
    write(root / "build-cgroup", cgroup)
    log("BUILD", os.getpid(), behavior)
    if behavior.startswith("natural"):
        raise SystemExit(int(behavior.removeprefix("natural")))
    if behavior == "surviving-descendant":
        descendant_code = r"""
import os
from pathlib import Path
import signal
import sys
import time

state = Path(sys.argv[1])
for requested in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
    signal.signal(requested, signal.SIG_IGN)
(state / "build-descendant-pid").write_text(str(os.getpid()), encoding="ascii")
(state / "build-descendant-ready").write_text(str(os.getpid()), encoding="ascii")
while True:
    time.sleep(0.02)
"""
        descendant = subprocess.Popen(
            [sys.executable, "-c", descendant_code, str(root)],
            close_fds=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 2
        while not (root / "build-descendant-ready").exists():
            if time.monotonic() >= deadline:
                raise SystemExit(125)
            time.sleep(0.01)
        time.sleep(float(os.environ.get("FAKE_BUILD_PARENT_EXIT_DELAY", "0")))
        raise SystemExit(37)
    if behavior == "escaped-descendant":
        descendant_code = r"""
import os
from pathlib import Path
import signal
import sys
import time

state = Path(sys.argv[1])
for requested in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
    signal.signal(requested, signal.SIG_IGN)
(state / "build-escaped-descendant-pid").write_text(
    str(os.getpid()), encoding="ascii"
)
(state / "build-escaped-descendant-ready").write_text(
    str(os.getpid()), encoding="ascii"
)
while True:
    time.sleep(0.02)
"""
        descendant = subprocess.Popen(
            [sys.executable, "-c", descendant_code, str(root)],
            start_new_session=True,
            close_fds=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 2
        while not (root / "build-escaped-descendant-ready").exists():
            if time.monotonic() >= deadline:
                raise SystemExit(125)
            time.sleep(0.01)
        time.sleep(float(os.environ.get("FAKE_BUILD_PARENT_EXIT_DELAY", "0")))
        raise SystemExit(0)
    if behavior == "cooperative":
        def stop_build(_signum, _frame):
            log("BUILD_INT", os.getpid())
            if os.environ.get("FAKE_BUILD_SIGNAL_GATE") == "1":
                write(root / "build-int-blocked", str(os.getpid()))
                deadline = time.monotonic() + 5
                while not (root / "build-int-release").exists():
                    if time.monotonic() >= deadline:
                        log("BUILD_INT_GATE_TIMEOUT", os.getpid())
                        raise SystemExit(125)
                    time.sleep(0.01)
            else:
                time.sleep(float(os.environ.get("FAKE_BUILD_SIGNAL_DELAY", "0")))
            raise SystemExit(130)
        signal.signal(signal.SIGINT, stop_build)
    elif behavior == "ignore-int":
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    else:
        raise SystemExit(2)
    write(root / "build-ready", str(os.getpid()))
    while True:
        time.sleep(0.02)

if args[0] == "run":
    cid = os.environ.get("FAKE_DOCKER_CONTAINER_ID", "a" * 64)
    cidfile = Path(args[args.index("--cidfile") + 1])
    assert args.count("--sig-proxy=false") == 1
    label = args[args.index("--label") + 1]
    token = label.split("=", 1)[1]
    behavior = os.environ.get("FAKE_DOCKER_BEHAVIOR", "attached")
    write(root / "cli-pid", str(os.getpid()))
    log("RUN", os.getpid(), behavior, label)
    if "FAKE_RUN_STDOUT" in os.environ:
        print(os.environ["FAKE_RUN_STDOUT"])
    if behavior == "no-cid":
        write(root / "run-ready", str(os.getpid()))
        while True:
            time.sleep(0.05)
    if behavior == "early-no-cid":
        write(root / "run-ready", str(os.getpid()))
        time.sleep(0.15)
        raise SystemExit(42)
    if behavior == "delayed-create":
        subprocess.Popen(
            [sys.executable, __file__, "__delayed_container", cid, token],
            env=os.environ.copy(),
            start_new_session=True,
            close_fds=True,
        )
        write(root / "run-ready", str(os.getpid()))
        while True:
            time.sleep(0.05)
    cidfile.write_text(cid + "\n", encoding="ascii")
    cidfile.chmod(0o600)
    if behavior == "ambiguous-label":
        write(root / "container", cid)
        write(root / "container-token", token)
        write(root / "running", "true")
        write(root / "foreign-container", "c" * 64)
        write(root / "foreign-container-token", token)
        write(root / "foreign-running", "true")
        cidfile.unlink()
        write(root / "run-ready", str(os.getpid()))
        while True:
            time.sleep(0.05)
    if behavior == "mislabelled-cid":
        create_container(cid, "foreign-token")
    else:
        create_container(cid, token)
    if behavior == "natural0":
        remove_container()
        raise SystemExit(0)
    if behavior == "escaped-cli-descendant":
        spawn_escaped_child("run")
        remove_container()
        raise SystemExit(0)
    if behavior == "natural37":
        remove_container()
        raise SystemExit(37)
    if behavior == "natural37-leak":
        raise SystemExit(37)
    if behavior == "success-leak":
        raise SystemExit(0)
    if behavior == "detached-stopped":
        (root / "running").unlink(missing_ok=True)
        raise SystemExit(0)
    if behavior == "detached-delay":
        time.sleep(float(os.environ.get("FAKE_DETACHED_DELAY", "0.5")))
        raise SystemExit(0)
    if "--detach" in args or "-d" in args:
        raise SystemExit(0)
    while (root / "container").exists():
        time.sleep(0.02)
    raise SystemExit(0)

if args[:2] == ["container", "ls"]:
    log("CONTAINER_LS")
    if os.environ.get("FAKE_CONTAINER_LS_DELAY"):
        time.sleep(float(os.environ["FAKE_CONTAINER_LS_DELAY"]))
    if os.environ.get("FAKE_DOCKER_API_HANG") == "1":
        time.sleep(2)
    if os.environ.get("FAKE_DOCKER_DAEMON_UNKNOWN") == "1":
        raise SystemExit(125)
    if os.environ.get("FAKE_CONTAINER_LS_UNKNOWN_ONCE") == "1":
        counter_path = root / "container-ls-unknown-once-counter"
        counter = (
            int(counter_path.read_text(encoding="ascii"))
            if counter_path.exists()
            else 0
        )
        write(counter_path, str(counter + 1))
        if counter == 0:
            raise SystemExit(125)
    selected = container_records()
    if "--filter" in args:
        filter_value = args[args.index("--filter") + 1]
        if filter_value.startswith("id="):
            wanted = filter_value.split("=", 1)[1]
            selected = [record for record in selected if record[0] == wanted]
        elif filter_value.startswith("label=org.qcsd.supervisor.instance="):
            wanted = filter_value.split("=", 2)[2]
            selected = [record for record in selected if record[1] == wanted]
        else:
            selected = []
    if os.environ.get("FAKE_CONTAINER_LS_AMBIGUOUS") == "1":
        wanted = os.environ.get("FAKE_DOCKER_CONTAINER_ID", "a" * 64)
        print(wanted)
        print(wanted)
        raise SystemExit(0)
    for record in selected:
        print(record[0])
    raise SystemExit(0)

if args[:2] == ["container", "inspect"]:
    log("CONTAINER_INSPECT", args[-1])
    if os.environ.get("FAKE_DOCKER_API_HANG") == "1":
        time.sleep(2)
    if os.environ.get("FAKE_DOCKER_DAEMON_UNKNOWN") == "1":
        raise SystemExit(125)
    record = record_for_id(args[-1])
    if record is None:
        raise SystemExit(1)
    cid, token, running, _prefix = record
    format_value = args[args.index("--format") + 1]
    if format_value == "{{.State.Running}}":
        print("true" if running else "false")
    else:
        print(f"{cid}|{token}|{'true' if running else 'false'}")
    raise SystemExit(0)

if args[:2] == ["container", "wait"]:
    cid = args[-1]
    log("CONTAINER_WAIT", cid)
    while True:
        record = record_for_id(cid)
        if record is None or not record[2]:
            raise SystemExit(0)
        time.sleep(0.02)

if args[0] == "kill":
    cid = args[-1]
    requested = args[args.index("--signal") + 1]
    log("KILL", requested, cid)
    time.sleep(float(os.environ.get("FAKE_KILL_DELAY", "0")))
    if os.environ.get("FAKE_KILL_ERROR") == "1":
        raise SystemExit(125)
    if os.environ.get("FAKE_DOCKER_BEHAVIOR") != "ignore-kill":
        remove_container_id(cid)
    raise SystemExit(0)

if args[0] == "rm":
    cid = args[-1]
    log("RM", cid)
    if os.environ.get("FAKE_RM_STAYS") != "1":
        remove_container_id(cid)
    if os.environ.get("FAKE_RM_ERROR_AFTER_REMOVE") == "1":
        raise SystemExit(1)
    raise SystemExit(0)

if args[0] == "exec":
    log("EXEC", args[1])
    raise SystemExit(0)

if args[:2] == ["network", "create"]:
    network_id = os.environ.get("FAKE_DOCKER_NETWORK_ID", "b" * 64)
    label = args[args.index("--label") + 1]
    token = label.split("=", 1)[1]
    log("NETWORK_CREATE_BEGIN", label)
    if os.environ.get("FAKE_NETWORK_FAIL_NO_ID") == "1":
        raise SystemExit(125)
    time.sleep(float(os.environ.get("FAKE_NETWORK_DELAY", "0")))
    write(root / "network", network_id)
    write(root / "network-token", token)
    if os.environ.get("FAKE_ESCAPE_ON_COMMAND") == "network-create":
        spawn_escaped_child("network")
    log("NETWORK_CREATE_END", network_id)
    print(network_id)
    raise SystemExit(0)

if args[:2] == ["network", "ls"]:
    log("NETWORK_LS")
    if os.environ.get("FAKE_NETWORK_LS_UNKNOWN_ONCE") == "1":
        counter_path = root / "network-ls-unknown-once-counter"
        counter = (
            int(counter_path.read_text(encoding="ascii"))
            if counter_path.exists()
            else 0
        )
        write(counter_path, str(counter + 1))
        if counter == 0:
            raise SystemExit(125)
    selected = network_records()
    if "--filter" in args:
        filter_value = args[args.index("--filter") + 1]
        if filter_value.startswith("id="):
            wanted = filter_value.split("=", 1)[1]
            selected = [record for record in selected if record[0] == wanted]
        elif filter_value.startswith("label=org.qcsd.supervisor.instance="):
            wanted = filter_value.split("=", 2)[2]
            selected = [record for record in selected if record[1] == wanted]
        else:
            selected = []
    if os.environ.get("FAKE_NETWORK_LS_AMBIGUOUS") == "1":
        wanted = os.environ.get("FAKE_DOCKER_NETWORK_ID", "b" * 64)
        print(wanted)
        print(wanted)
        raise SystemExit(0)
    for record in selected:
        print(record[0])
    raise SystemExit(0)

if args[:2] == ["network", "inspect"]:
    log("NETWORK_INSPECT", args[-1])
    record = network_for_id(args[-1])
    if record is None:
        raise SystemExit(1)
    network_id, token, _prefix = record
    print(f"{network_id}|{token}")
    raise SystemExit(0)

if args[:2] == ["network", "rm"]:
    log("NETWORK_RM", args[-1])
    if os.environ.get("FAKE_NETWORK_RM_STAYS") != "1":
        remove_network_id(args[-1])
    raise SystemExit(0)

log("UNEXPECTED", *args)
raise SystemExit(2)
'''


ATTACHED_HARNESS = r'''
set -euo pipefail
source "$HELPER"
_QCSD_DOCKER_GRACE_SECONDS=0.8
_QCSD_DOCKER_REAP_POLLS=8
if [[ -n "${FAKE_API_TIMEOUT_OVERRIDE:-}" ]]; then
  _QCSD_DOCKER_API_TIMEOUT_SECONDS="$FAKE_API_TIMEOUT_OVERRIDE"
fi
if [[ "${FAKE_PREWAIT_DELAY:-0}" == "1" ]]; then
  eval "$(declare -f _qcsd_job_is_running | sed '1s/_qcsd_job_is_running/_qcsd_original_job_is_running/')"
  _qcsd_job_is_running() {
    if [[ ! -e "$FAKE_DOCKER_STATE/prewait-entered" ]]; then
      : >"$FAKE_DOCKER_STATE/prewait-entered"
      sleep 0.5 || true
    fi
    _qcsd_original_job_is_running "$@"
  }
fi
if [[ "${FAKE_BIND_MISMATCH:-0}" == "1" ]]; then
  eval "$(declare -f _qcsd_read_process_identity | sed '1s/_qcsd_read_process_identity/_qcsd_original_read_process_identity/')"
  _qcsd_read_process_identity() {
    _qcsd_original_read_process_identity "$@" || return
    _qcsd_process_session=0
    _qcsd_process_group=0
  }
fi
exec 9>"$LOCK_PATH"
flock -n 9
printf 'ready\n' >"$HARNESS_READY"
cleanup_ids=()
cleanup() {
  trap - EXIT
  trap '' INT TERM
  printf 'OUTER_CLEANUP\n' >>"$FAKE_DOCKER_STATE/calls.log"
  local cid
  for cid in "${cleanup_ids[@]}"; do
    docker rm --force "$cid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
set +e
qcsd_run_attached_docker docker run fake-image
status=$?
set -e
printf 'STATUS %s\n' "$status" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''


BUILD_HARNESS = r'''
set -euo pipefail
source "$HELPER"
_QCSD_DOCKER_BUILD_GRACE_POLLS=50
_QCSD_DOCKER_BUILD_GRACE_DELAY_SECONDS=0.02
_QCSD_DOCKER_REAP_POLLS=20
_QCSD_DOCKER_REAP_DELAY_SECONDS=0.01
if [[ -n "${FAKE_BUILD_STATUS_TAMPER:-}" ]]; then
  eval "$(declare -f _qcsd_private_exit_status | sed '1s/_qcsd_private_exit_status/_qcsd_original_private_exit_status/')"
  _qcsd_private_exit_status() {
    case "$FAKE_BUILD_STATUS_TAMPER" in
      missing) unlink -- "$1" ;;
      malformed) printf 'not-a-status\n' >"$1" ;;
      mismatch)
        local observed
        observed="$(<"$1")"
        if [[ "$observed" == 0 ]]; then
          printf '1\n' >"$1"
        else
          printf '0\n' >"$1"
        fi
        ;;
      *) return 125 ;;
    esac
    _qcsd_original_private_exit_status "$1"
  }
fi
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH"
flock -n 9
_QCSD_DOCKER_BUILD_LOCK_FD=9
printf 'ready\n' >"$HARNESS_READY"
cleanup() {
  trap - EXIT
  trap '' HUP INT QUIT TERM
  printf 'BUILD_OUTER_CLEANUP\n' >>"$FAKE_DOCKER_STATE/calls.log"
}
trap cleanup EXIT
set +e
qcsd_run_docker_build docker --context default build fake-context
status=$?
set -e
printf 'BUILD_STATUS %s\n' "$status" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''


SIGNAL_CLEAN_BASH = (
    "/usr/bin/env",
    "--default-signal=HUP,INT,QUIT,TERM",
    "--",
    "/bin/bash",
    "-c",
)


@pytest.fixture
def fake_environment(tmp_path: Path):
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    docker = binary_root / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    lifecycle_base = tmp_path / "isolated-lifecycle"
    lifecycle_base.mkdir(mode=0o700)
    lifecycle_isolation_shim = tmp_path / "lifecycle-isolation-shim.sh"
    lifecycle_isolation_shim.write_text(
        textwrap.dedent(LIFECYCLE_ISOLATION_SHIM), encoding="ascii"
    )
    lifecycle_isolation_shim.chmod(0o600)
    mktemp = binary_root / "mktemp"
    mktemp.write_text(
        textwrap.dedent(
            r'''#!/usr/bin/env bash
set -euo pipefail
created="$(/usr/bin/mktemp "$@")"
case "${created}" in
  /tmp/qcsd-docker-supervisor.*|\
  /tmp/qcsd-docker-network-supervisor.*|\
  /tmp/qcsd-docker-build-supervisor.*)
    printf '%s\n' "${created}" >>"${FAKE_DOCKER_STATE}/supervisor-roots.log"
    ;;
esac
printf '%s\n' "${created}"
'''
        ),
        encoding="utf-8",
    )
    mktemp.chmod(0o755)
    helper_wrapper = tmp_path / "docker-signal-supervisor-test-wrapper.sh"
    helper_wrapper.write_text(
        textwrap.dedent(
            r'''\
source "$PRODUCTION_HELPER"
source "$QCSD_TEST_LIFECYCLE_SHIM"
_qcsd_lifecycle_root_created_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}
# Direct helper unit tests do not run inside the guardian. Keep their historical
# private-root setup local; the real dual-lease creation protocol has dedicated
# guardian and retirement integration coverage.
_qcsd_begin_lifecycle_root_creation() {
  local root_name="${1:?}" metadata
  mkdir -m 700 -- "${_qcsd_lifecycle_base}/${root_name}" || return 1
  sync -f "${_qcsd_lifecycle_base}" || return 1
  metadata="$(stat -Lc '%d:%i' -- "${_qcsd_lifecycle_base}/${root_name}")" || return 1
  _QCSD_CREATION_ROOT_DEVICE="${metadata%%:*}"
  _QCSD_CREATION_ROOT_INODE="${metadata##*:}"
  _QCSD_CREATION_HOLDER_PID=fixture
}
_qcsd_commit_lifecycle_root_creation() {
  unset _QCSD_CREATION_HOLDER_PID _QCSD_CREATION_ROOT_DEVICE
  unset _QCSD_CREATION_ROOT_INODE
}
_qcsd_cancel_lifecycle_root_creation() {
  local entry
  shopt -s nullglob dotglob
  for entry in "${_qcsd_lifecycle_root}"/*; do
    [[ -f "${entry}" && ! -L "${entry}" ]] || return 1
    rm -f -- "${entry}" || return 1
  done
  rmdir -- "${_qcsd_lifecycle_root}" || return 1
  sync -f "${_qcsd_lifecycle_base}" || return 1
  unset _QCSD_CREATION_HOLDER_PID _QCSD_CREATION_ROOT_DEVICE
  unset _QCSD_CREATION_ROOT_INODE
}
# Retirement state-machine crash coverage lives in its dedicated test module.
# These helper tests retain a strict, local removal primitive after production
# selection, absence, receipt, manifest, and source gates authorise retirement.
_qcsd_lifecycle_remove_root() {
  local root="${1:?}" root_identity entry nullglob_setting dotglob_setting
  local -a entries=()
  _qcsd_validate_lifecycle_root_contents "${root}" || return 1
  [[ -d "${root}" && ! -L "${root}" ]] || return 1
  root_identity="$(stat -Lc '%d:%i' -- "${root}")" || return 1
  nullglob_setting="$(shopt -p nullglob)"
  dotglob_setting="$(shopt -p dotglob)"
  shopt -s nullglob dotglob
  entries=("${root}"/*)
  eval "${nullglob_setting}"
  eval "${dotglob_setting}"
  for entry in "${entries[@]}"; do
    [[ ( -f "${entry}" || -p "${entry}" ) && ! -L "${entry}" ]] || return 1
  done
  for entry in "${entries[@]}"; do
    [[ "$(stat -Lc '%d:%i' -- "${root}")" == "${root_identity}" ]] || return 1
    rm -f -- "${entry}" || return 1
  done
  [[ "$(stat -Lc '%d:%i' -- "${root}")" == "${root_identity}" ]] || return 1
  rmdir -- "${root}" || return 1
  sync -f "${_qcsd_lifecycle_base}" || return 1
}
# Unit tests retain the former direct transient-unit boundary so fake Docker
# remains observable through the fixture environment. Production's leased
# native service controller is exercised by the guardian integration suite.
_qcsd_docker_api_service_with_timeout() {
  local duration="${1:?}" duration_whole outer_duration unit variable
  local -a environment_arguments=()
  shift
  if [[ "${duration}" =~ ^([0-9]+)([.][0-9]+)?$ ]]; then
    duration_whole="${BASH_REMATCH[1]}"
    outer_duration=$((10#${duration_whole} + 3))
    [[ -z "${BASH_REMATCH[2]}" ]] || outer_duration=$((outer_duration + 1))
  else
    return 125
  fi
  unit="qcsd-docker-api-$(printf '%032x' "$RANDOM$RANDOM").service"
  while IFS= read -r variable; do
    environment_arguments+=("--setenv=${variable}=${!variable}")
  done < <(compgen -e)
  setsid timeout --signal=KILL --kill-after=1 "${outer_duration}s" \
    /usr/bin/systemd-run --user --wait --pipe --collect --quiet --same-dir \
      --expand-environment=no --service-type=exec --unit="${unit}" \
      --property=ExitType=cgroup --property=KillMode=control-group \
      --property=KillSignal=SIGKILL --property=TimeoutStopSec=1s \
      --property="RuntimeMaxSec=${duration}s" \
      "${environment_arguments[@]}" -- "$@"
}
_qcsd_build_wait_ready_hook() {
  if [[ "${FAKE_BUILD_SUPERVISOR_SIGNAL_GATE:-}" == 1 ]]; then
    printf 'ready\n' >"$FAKE_DOCKER_STATE/build-supervisor-signal-ready"
    while (( requested_status == 0 )); do
      IFS= read -r -t 0.05 -u "${wait_fd}" _qcsd_test_wait_byte || true
    done
    printf 'latched\n' >"$FAKE_DOCKER_STATE/build-supervisor-signal-latched"
  fi
}
_qcsd_run_wait_ready_hook() {
  if [[ "${FAKE_RUN_SUPERVISOR_SIGNAL_GATE:-}" == 1 ]]; then
    printf 'ready\n' >"$FAKE_DOCKER_STATE/run-supervisor-signal-ready"
    while (( requested_status == 0 )); do
      IFS= read -r -t 0.05 -u "${wait_fd}" _qcsd_test_wait_byte || true
    done
    printf 'latched\n' >"$FAKE_DOCKER_STATE/run-supervisor-signal-latched"
  fi
}
'''
        ),
        encoding="utf-8",
    )
    helper_wrapper.chmod(0o600)
    environment = os.environ.copy()
    environment.update(
        PATH=f"{binary_root}:{environment['PATH']}",
        DOCKER_CONTEXT="default",
        FAKE_DOCKER_STATE=str(state),
        HELPER=str(helper_wrapper),
        REAL_HELPER=str(helper_wrapper),
        PRODUCTION_HELPER=str(HELPER),
        LOCK_PATH=str(tmp_path / "supervisor.lock"),
        HARNESS_READY=str(tmp_path / "harness-ready"),
        _QCSD_DOCKER_PINNED_CONTEXT="default",
        _QCSD_DOCKER_PINNED_HOST="unix:///var/run/docker.sock",
        _QCSD_DOCKER_PINNED_SERVER_ID="daemon-test-id",
        _QCSD_DOCKER_PINNED_BOOT_ID=(
            Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        ),
        _QCSD_DOCKER_BUILD_DAEMON_ID="daemon-test-id",
        QCSD_TEST_LIFECYCLE_BASE=str(lifecycle_base),
        QCSD_TEST_LIFECYCLE_SHIM=str(lifecycle_isolation_shim),
    )
    yield environment

    recorded_roots: set[Path] = set()
    permitted_lifecycle_bases = {lifecycle_base}
    roots_log = state / "supervisor-roots.log"
    if roots_log.exists():
        for raw_path in roots_log.read_text(encoding="utf-8").splitlines():
            root = Path(raw_path)
            assert root.is_absolute(), raw_path
            assert root.parent in permitted_lifecycle_bases, raw_path
            assert re.fullmatch(
                r"(?:run|network|build)\.[0-9a-f]{32}", root.name
            ), raw_path
            recorded_roots.add(root)

    unit_pattern = re.compile(
        r"qcsd-docker-(?:api-[0-9a-f]{32}\.service|"
        r"(?:run|build)-[0-9a-f]{32}\.scope)"
    )
    owned_units: set[str] = set()
    for evidence_path in state.glob("*cgroup*"):
        if evidence_path.is_file():
            owned_units.update(
                unit_pattern.findall(
                    evidence_path.read_text(encoding="utf-8", errors="strict")
                )
            )
    for root in recorded_roots:
        if not root.exists():
            continue
        assert not root.is_symlink()
        root_stat = root.stat()
        assert root_stat.st_uid == os.getuid()
        assert root_stat.st_mode & 0o777 == 0o700
        for evidence_path in root.iterdir():
            if evidence_path.is_file() and not evidence_path.is_symlink():
                owned_units.update(
                    unit_pattern.findall(
                        evidence_path.read_text(
                            encoding="utf-8", errors="strict"
                        )
                    )
                )

    for unit in sorted(owned_units):
        subprocess.run(
            [
                "systemctl",
                "--user",
                "kill",
                "--kill-whom=all",
                "--signal=KILL",
                "--",
                unit,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        subprocess.run(
            ["systemctl", "--user", "stop", "--", unit],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        subprocess.run(
            ["systemctl", "--user", "reset-failed", "--", unit],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        _assert_user_scope_inactive(unit)

    launcher_cleanup_errors: list[str] = []
    for root in sorted(recorded_roots):
        if not root.exists():
            continue
        try:
            _terminate_authenticated_stopped_launcher(root)
        except AssertionError as error:
            launcher_cleanup_errors.append(f"{root}: {error}")

    for pid_name in (
        "cli-pid",
        "build-cli-pid",
        "build-descendant-pid",
        "build-escaped-descendant-pid",
        "api-escaped-pid",
        "run-escaped-pid",
        "network-escaped-pid",
    ):
        pid_path = state / pid_name
        if pid_path.exists():
            pid = int(pid_path.read_text(encoding="ascii"))
            try:
                command = Path(f"/proc/{pid}/cmdline").read_bytes()
            except FileNotFoundError:
                command = b""
            expected_marker = (
                os.fsencode(state)
                if pid_name
                in {
                    "build-descendant-pid",
                    "build-escaped-descendant-pid",
                    "api-escaped-pid",
                    "run-escaped-pid",
                    "network-escaped-pid",
                }
                else os.fsencode(docker)
            )
            if expected_marker in command:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _wait_not_live(pid)

    # A malformed or identity-mismatched birth record must retain its durable
    # evidence.  In particular, never turn a teardown parsing failure into
    # permission to recursively delete the only record binding a stopped PID.
    assert not launcher_cleanup_errors, "; ".join(launcher_cleanup_errors)

    for root in recorded_roots:
        if root.exists():
            assert not root.is_symlink()
            root_stat = root.stat()
            assert root_stat.st_uid == os.getuid()
            assert root_stat.st_mode & 0o777 == 0o700
            shutil.rmtree(root)
        assert not root.exists()


@pytest.fixture
def isolated_recovery_environment(
    fake_environment: dict[str, str],
) -> dict[str, str]:
    """Name the already-private environment used by crash/recovery tests."""
    return fake_environment


def _wait(path: Path, *, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def _wait_for_text(path: Path, expected: str, *, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and expected in path.read_text(encoding="utf-8"):
            return
        time.sleep(0.01)
    observed = path.read_text(encoding="utf-8") if path.exists() else "<missing>"
    raise AssertionError(
        f"timed out waiting for {expected!r} in {path}; observed {observed!r}"
    )


def _lock_available(path: Path) -> bool:
    with path.open("a", encoding="ascii") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(lock, fcntl.LOCK_UN)
    return True


def _process_state(pid: int) -> str | None:
    try:
        stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    return stat_line.rsplit(") ", 1)[1].split(maxsplit=1)[0]


def _process_identity(pid: int) -> tuple[str, int, int, int] | None:
    try:
        stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    fields = stat_line.rsplit(") ", 1)[1].split()
    assert len(fields) >= 20, stat_line
    state = fields[0]
    process_group = int(fields[2])
    session = int(fields[3])
    start_time = int(fields[19])
    return state, start_time, session, process_group


def _private_launcher_birth(root: Path) -> tuple[int, int, int, int] | None:
    birth = root / "launcher.birth"
    if not birth.exists() and not birth.is_symlink():
        return None
    assert not birth.is_symlink(), birth
    assert birth.is_file(), birth
    metadata = birth.stat()
    assert metadata.st_uid == os.getuid(), birth
    assert metadata.st_mode & 0o777 == 0o600, birth
    assert metadata.st_nlink == 1, birth
    assert 0 < metadata.st_size <= 2048, birth
    try:
        contents = birth.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise AssertionError(f"cannot read private launcher birth {birth}: {error}") from error
    assert contents.endswith("\n") and "\r" not in contents, birth
    assert all(character == "\n" or " " <= character <= "~" for character in contents), birth
    lines = contents.splitlines()
    root_match = re.fullmatch(r"(run|build)\.([0-9a-f]{32})", root.name)
    assert root_match is not None, root
    kind, token = root_match.groups()
    assert lines[:4] == [
        "birth_schema=1",
        f"launcher_kind={kind}",
        f"lifecycle_root={root}",
        f"lifecycle_token={token}",
    ], birth
    assert len(lines) == 8, birth
    expected_keys = (
        "launcher_pid",
        "launcher_start_time",
        "launcher_session",
        "launcher_process_group",
    )
    values: list[int] = []
    for line, key in zip(lines[4:], expected_keys, strict=True):
        prefix = f"{key}="
        assert line.startswith(prefix), birth
        value = line.removeprefix(prefix)
        assert re.fullmatch(r"[1-9][0-9]*", value), birth
        values.append(int(value))
    pid, start_time, session, process_group = values
    assert session == pid and process_group == pid, birth
    return pid, start_time, session, process_group


def _terminate_authenticated_stopped_launcher(root: Path) -> None:
    """Kill only the exact pre-exec launcher authenticated by its birth record."""
    assert root.is_absolute(), root
    assert root.exists() and root.is_dir() and not root.is_symlink(), root
    root_metadata = root.stat()
    assert root_metadata.st_uid == os.getuid(), root
    assert root_metadata.st_mode & 0o777 == 0o700, root
    expected = _private_launcher_birth(root)
    if expected is None:
        return
    pid, start_time, session, process_group = expected
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        observed = _process_identity(pid)
        if observed is None:
            return
        state, observed_start, observed_session, observed_group = observed
        assert observed_start == start_time, (
            f"launcher PID {pid} birth changed: {observed_start} != {start_time}"
        )
        assert observed_session == session and observed_group == process_group, (
            f"launcher PID {pid} session/group changed: "
            f"{observed_session}/{observed_group} != {session}/{process_group}"
        )
        if state == "Z":
            return
        assert state == "T", f"launcher PID {pid} is not stopped: state={state}"
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        except FileNotFoundError:
            return
        kind, token = root.name.split(".", 1)
        required_argv = {
            os.fsencode(f"qcsd-docker-{kind}-scope-launcher"),
            os.fsencode(root),
            os.fsencode(root / "launcher.birth"),
            token.encode("ascii"),
            kind.encode("ascii"),
        }
        assert required_argv.issubset(argv), (
            f"launcher PID {pid} command does not bind {root}: {argv!r}"
        )
        # Reprove the tuple and stopped state immediately before signalling.
        assert _process_identity(pid) == (
            "T",
            start_time,
            session,
            process_group,
        ), f"launcher PID {pid} changed before teardown signal"
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            return
    finally:
        os.close(pidfd)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        observed = _process_identity(pid)
        if observed is None or observed[0] == "Z" or observed[1] != start_time:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            return
        time.sleep(0.01)
    raise AssertionError(
        f"authenticated launcher PID {pid} remains live: {_process_identity(pid)}"
    )


def _wait_not_live(pid: int, *, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _process_state(pid) in (None, "Z"):
            return
        time.sleep(0.01)
    raise AssertionError(f"process {pid} remains live with state {_process_state(pid)}")


def _fixture_helper_shims(fake_environment: dict[str, str]) -> str:
    wrapper = Path(fake_environment["REAL_HELPER"]).read_text(encoding="utf-8")
    prefix = '\\\nsource "$PRODUCTION_HELPER"\n'
    assert wrapper.startswith(prefix)
    return wrapper.removeprefix(prefix)


@pytest.mark.parametrize("kind", ["run", "build"])
@pytest.mark.parametrize("boundary", ["forked", "birth_bound"])
def test_sigkill_at_launcher_birth_boundaries_is_restart_recoverable(
    isolated_recovery_environment: dict[str, str],
    request: pytest.FixtureRequest,
    kind: str,
    boundary: str,
) -> None:
    fake_environment = isolated_recovery_environment
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    lifecycle_base = Path(fake_environment["QCSD_TEST_LIFECYCLE_BASE"])
    crash_wrapper = state.parent / f"crash-{kind}-{boundary}.sh"
    crash_wrapper.write_text(
        textwrap.dedent(
            f'''\
source "$REAL_HELPER"
_qcsd_lifecycle_root_created_hook() {{
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}}
_qcsd_launcher_{boundary}_hook() {{
  printf '%s %s\n' "$2" "$3" >"$FAKE_DOCKER_STATE/crash-child"
  kill -KILL "$BASHPID"
}}
'''
        ),
        encoding="utf-8",
    )
    crash_wrapper.chmod(0o600)
    environment = {**fake_environment, "HELPER": str(crash_wrapper)}
    Path(environment["LOCK_PATH"]).touch(mode=0o600)
    Path(environment["LOCK_PATH"]).chmod(0o600)
    process = _start_attached(environment) if kind == "run" else _start_build(environment)
    assert process.wait(timeout=10) == -signal.SIGKILL
    _wait(state / "crash-child")
    child_pid = int((state / "crash-child").read_text().split()[0])
    root = _created_lifecycle_roots(
        state, kind, lifecycle_base=lifecycle_base
    )[-1]
    _wait(root / "launcher.birth")
    request.addfinalizer(
        lambda: _terminate_authenticated_stopped_launcher(root)
        if root.exists()
        else None
    )

    # Model the exact parent-poll-timeout suffix: the final pre-authorisation
    # recovery receipt has an unavailable tuple, while the child completes its
    # authenticated birth publication just afterwards.  Applying that late
    # birth must promote only this exact auth0/unresolved identity.
    promote = subprocess.run(
        [
            "bash",
            "-c",
            r'''
set -euo pipefail
source "$REAL_HELPER"
declare -A delayed=(
  [lifecycle_state]=unresolved
  [lifecycle_token]="$TOKEN"
  [scope_launcher_pid]=unavailable
  [scope_launcher_start_time]=unavailable
  [scope_launcher_session]=unavailable
  [scope_launcher_process_group]=unavailable
  [daemon_request_authorised]=0
)
if [[ "$KIND" == run ]]; then
  delayed[cli_pid]=unavailable
  delayed[cli_start_time]=unavailable
  delayed[cli_session]=unavailable
  delayed[cli_process_group]=unavailable
fi
_qcsd_lifecycle_apply_launcher_birth "$LIFECYCLE_ROOT" "$KIND" delayed
printf '%s\n' "${delayed[scope_launcher_pid]}"
''',
        ],
        env={
            **fake_environment,
            "REAL_HELPER": fake_environment["REAL_HELPER"],
            "LIFECYCLE_ROOT": str(root),
            "TOKEN": root.name.split(".", 1)[1],
            "KIND": kind,
        },
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert promote.returncode == 0, promote.stderr
    assert promote.stdout.strip() == str(child_pid)

    recovery = subprocess.run(
        [
            "bash",
            "-c",
            'set -euo pipefail; source "$REAL_HELPER"; '
            "qcsd_reconcile_docker_lifecycle",
        ],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert recovery.returncode == 0, recovery.stderr
    assert not root.exists()
    _wait_not_live(child_pid)
    process.communicate(timeout=2)


@pytest.mark.parametrize("kind", ["run", "build"])
def test_child_exit_before_birth_produces_recoverable_unbound_identity(
    isolated_recovery_environment: dict[str, str], tmp_path: Path, kind: str
) -> None:
    fake_environment = isolated_recovery_environment
    lifecycle_base = Path(fake_environment["QCSD_TEST_LIFECYCLE_BASE"])
    wrapper = tmp_path / f"child-exit-before-birth-{kind}.sh"
    wrapper.write_text(
        textwrap.dedent(
            r'''\
source "$REAL_HELPER"
_qcsd_lifecycle_root_created_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}
_qcsd_launcher_forked_hook() {
  kill -KILL "$2" 2>/dev/null || true
}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {**fake_environment, "HELPER": str(wrapper)}
    Path(environment["LOCK_PATH"]).touch(mode=0o600)
    Path(environment["LOCK_PATH"]).chmod(0o600)
    process = _start_attached(environment) if kind == "run" else _start_build(environment)
    stdout, stderr = _communicate(process, timeout=30)
    assert process.returncode == 1, (stdout, stderr)
    assert "cannot bind the isolated Docker" in stderr
    calls_path = Path(environment["FAKE_DOCKER_STATE"], "calls.log")
    calls = calls_path.read_text(encoding="utf-8") if calls_path.exists() else ""
    assert " RUN " not in f" {calls} "
    assert " BUILD " not in f" {calls} "
    for root in _created_lifecycle_roots(
        Path(environment["FAKE_DOCKER_STATE"]),
        kind,
        lifecycle_base=lifecycle_base,
    ):
        if root.exists():
            recovery = subprocess.run(
                [
                    "bash",
                    "-c",
                    'set -euo pipefail; source "$REAL_HELPER"; '
                    "qcsd_reconcile_docker_lifecycle",
                ],
                env=fake_environment,
                text=True,
                capture_output=True,
                timeout=15,
            )
            if kind == "build":
                # Docker cannot prove cancellation of an interrupted build;
                # its valid taint receipt must remain a deliberate admission
                # blocker rather than being rejected as malformed.
                assert recovery.returncode == 1, recovery.stderr
                assert "unresolved build state" in recovery.stderr
                assert "malformed" not in recovery.stderr
                assert root.exists()
            else:
                assert recovery.returncode == 0, recovery.stderr
                assert not root.exists()


@pytest.mark.parametrize("kind", ["run", "build"])
def test_late_birth_after_parent_poll_timeout_validates_full_recovery_record(
    isolated_recovery_environment: dict[str, str],
    request: pytest.FixtureRequest,
    tmp_path: Path,
    kind: str,
) -> None:
    fake_environment = isolated_recovery_environment
    lifecycle_base = Path(fake_environment["QCSD_TEST_LIFECYCLE_BASE"])
    wrapper = tmp_path / f"late-birth-full-recovery-{kind}.sh"
    wrapper.write_text(
        textwrap.dedent(
            r'''\
source "$REAL_HELPER"
eval "$(declare -f _qcsd_read_process_identity | sed \
  '1s/_qcsd_read_process_identity/_qcsd_original_read_process_identity/')"
_QCSD_FORCE_READ_FAIL=0
_qcsd_lifecycle_root_created_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
  _QCSD_FORCE_READ_FAIL=1
}
_qcsd_read_process_identity() {
  [[ "$_QCSD_FORCE_READ_FAIL" == 0 ]] || return 1
  _qcsd_original_read_process_identity "$@"
}
eval "$(declare -f _qcsd_publish_supervision_file | sed \
  '1s/_qcsd_publish_supervision_file/_qcsd_original_publish_supervision_file/')"
_qcsd_publish_supervision_file() {
  _qcsd_original_publish_supervision_file "$@" || return
  if [[ "$2" == */RECOVERY ]]; then
    kill -KILL "$BASHPID"
  fi
}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {**fake_environment, "HELPER": str(wrapper)}
    Path(environment["LOCK_PATH"]).touch(mode=0o600)
    Path(environment["LOCK_PATH"]).chmod(0o600)
    process = _start_attached(environment) if kind == "run" else _start_build(environment)
    assert process.wait(timeout=15) == -signal.SIGKILL
    state = Path(environment["FAKE_DOCKER_STATE"])
    root = _created_lifecycle_roots(
        state, kind, lifecycle_base=lifecycle_base
    )[-1]
    _wait(root / "RECOVERY")
    _wait(root / "launcher.birth")
    request.addfinalizer(
        lambda: _terminate_authenticated_stopped_launcher(root)
        if root.exists()
        else None
    )
    birth = (root / "launcher.birth").read_text(encoding="ascii")
    child_pid = int(re.search(r"^launcher_pid=([1-9][0-9]*)$", birth, re.MULTILINE).group(1))
    recovery = subprocess.run(
        [
            "bash", "-c",
            'set -euo pipefail; source "$REAL_HELPER"; qcsd_reconcile_docker_lifecycle',
        ],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=15,
    )
    calls_path = state / "calls.log"
    calls = calls_path.read_text(encoding="utf-8") if calls_path.exists() else ""
    assert " RUN " not in f" {calls} " and " BUILD " not in f" {calls} "
    assert "malformed state" not in recovery.stderr
    _wait_not_live(child_pid)
    if kind == "run":
        assert recovery.returncode == 0, recovery.stderr
        assert not root.exists()
    else:
        assert recovery.returncode == 1
        assert "unresolved build state" in recovery.stderr
        assert root.exists()
        shutil.rmtree(root)
    process.communicate(timeout=2)


def test_failed_recovery_teardown_reaps_authenticated_stopped_launcher(
    isolated_recovery_environment: dict[str, str], tmp_path: Path
) -> None:
    environment = isolated_recovery_environment
    state = Path(environment["FAKE_DOCKER_STATE"])
    lifecycle_base = Path(environment["QCSD_TEST_LIFECYCLE_BASE"])
    wrapper = tmp_path / "failed-recovery-launcher.sh"
    wrapper.write_text(
        textwrap.dedent(
            r'''\
source "$REAL_HELPER"
_qcsd_lifecycle_root_created_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}
_qcsd_launcher_birth_bound_hook() {
  kill -KILL "$BASHPID"
}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {**environment, "HELPER": str(wrapper)}
    Path(environment["LOCK_PATH"]).touch(mode=0o600)
    Path(environment["LOCK_PATH"]).chmod(0o600)
    process = _start_attached(environment)
    root: Path | None = None
    blocker: Path | None = None
    child_pid: int | None = None
    try:
        assert process.wait(timeout=10) == -signal.SIGKILL
        root = _created_lifecycle_roots(
            state, "run", lifecycle_base=lifecycle_base
        )[-1]
        _wait(root / "launcher.birth")
        birth_identity = _private_launcher_birth(root)
        assert birth_identity is not None
        child_pid = birth_identity[0]
        assert _process_state(child_pid) == "T"

        blocker_token = hashlib.sha256(os.fsencode(tmp_path)).hexdigest()[:32]
        blocker = lifecycle_base / f"build.{blocker_token}"
        blocker.mkdir(mode=0o700)
        blocker.chmod(0o700)
        malformed = blocker / "RECOVERY"
        malformed.write_text("not-a-lifecycle-record\n", encoding="ascii")
        malformed.chmod(0o600)
        recovery = subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; source "$REAL_HELPER"; '
                "qcsd_reconcile_docker_lifecycle",
            ],
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert recovery.returncode != 0, recovery.stderr
        assert "malformed state" in recovery.stderr
        assert _process_state(child_pid) == "T"

        _terminate_authenticated_stopped_launcher(root)
        _wait_not_live(child_pid)
        assert root.exists()
        shutil.rmtree(root)
        assert not root.exists()
    finally:
        if root is not None and root.exists():
            _terminate_authenticated_stopped_launcher(root)
            shutil.rmtree(root)
        if blocker is not None and blocker.exists():
            shutil.rmtree(blocker)
        if child_pid is not None:
            _wait_not_live(child_pid)
        process.communicate(timeout=2)


def _process_fd_targets(pid: int) -> set[Path]:
    targets: set[Path] = set()
    for fd_path in Path(f"/proc/{pid}/fd").iterdir():
        try:
            targets.add(fd_path.resolve(strict=True))
        except FileNotFoundError:
            continue
    return targets


def _build_scope_unit(state: Path) -> str:
    cgroup = (state / "build-cgroup").read_text(encoding="ascii").strip()
    match = re.search(
        r"/(qcsd-docker-build-[0-9a-f]{32}\.scope)(?:/|$)",
        cgroup,
    )
    assert match is not None, cgroup
    return match.group(1)


def _unit_from_cgroup(path: Path, prefix: str, suffix: str) -> str:
    cgroup = path.read_text(encoding="ascii").strip()
    match = re.search(
        rf"/({re.escape(prefix)}-[0-9a-f]{{32}}\.{re.escape(suffix)})(?:/|$)",
        cgroup,
    )
    assert match is not None, cgroup
    return match.group(1)


def _assert_user_scope_inactive(unit: str) -> None:
    result = subprocess.run(
        [
            "systemctl",
            "--user",
            "show",
            unit,
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=ControlGroup",
        ],
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    fields = dict(
        line.split("=", 1)
        for line in result.stdout.splitlines()
        if "=" in line
    )
    assert fields.get("ActiveState") == "inactive", fields
    if fields.get("LoadState") == "not-found":
        assert fields.get("ControlGroup") == "", fields
    else:
        assert fields.get("LoadState") == "loaded", fields
        assert fields.get("ControlGroup", "").endswith(f"/{unit}"), fields


def _assert_scoped_build_receipt(
    receipt: str,
    *,
    unit: str,
    command_status: str,
    systemd_status: str,
    status_state: str = "valid",
    status_matches: int = 1,
) -> None:
    assert "object=docker-build-scope-launcher\n" in receipt
    assert "process_identity_role=local-systemd-run-scope-launcher\n" in receipt
    assert re.search(r"^scope_launcher_pid=[1-9][0-9]*$", receipt, re.MULTILINE)
    assert re.search(
        r"^scope_launcher_start_time=[1-9][0-9]*$", receipt, re.MULTILINE
    )
    assert re.search(
        r"^scope_launcher_session=[1-9][0-9]*$", receipt, re.MULTILINE
    )
    assert re.search(
        r"^scope_launcher_process_group=[1-9][0-9]*$", receipt, re.MULTILINE
    )
    assert "scope_required=1\n" in receipt
    assert f"scope_unit={unit}\n" in receipt
    assert "scope_empty_proven=1\n" in receipt
    assert f"status_file_state={status_state}\n" in receipt
    assert f"status_file_matches={status_matches}\n" in receipt
    assert f"docker_command_status={command_status}\n" in receipt
    assert f"systemd_run_status={systemd_status}\n" in receipt


def _start_attached(environment: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(ATTACHED_HARNESS)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def _start_build(environment: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(BUILD_HARNESS)],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def _communicate(
    process: subprocess.Popen[str], *, timeout: float
) -> tuple[str, str]:
    try:
        return process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as initial_timeout:
        os.killpg(process.pid, signal.SIGKILL)
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            # The launcher deliberately owns a separate session/systemd scope
            # and can retain the capture pipes until fixture teardown kills
            # that exact scope. Preserve the original harness timeout rather
            # than replacing it with this secondary pipe-drain timeout.
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        raise initial_timeout


def _recovery_path(stderr: str) -> Path:
    match = re.search(
        r"preserving (/[^\r\n ]+/run\.[0-9a-f]{32})",
        stderr,
    )
    assert match, stderr
    root = Path(match.group(1))
    _assert_private_lifecycle_root_path(root, "run")
    return root


def _network_recovery_path(stderr: str) -> Path:
    match = re.search(
        r"preserving (/[^\r\n ]+/network\.[0-9a-f]{32})",
        stderr,
    )
    assert match, stderr
    root = Path(match.group(1))
    _assert_private_lifecycle_root_path(root, "network")
    return root


def _build_recovery_path(stderr: str) -> Path:
    match = re.search(
        r"preserving (/[^\r\n ]+/build\.[0-9a-f]{32})",
        stderr,
    )
    assert match, stderr
    root = Path(match.group(1))
    _assert_private_lifecycle_root_path(root, "build")
    return root


def _assert_private_lifecycle_root_path(root: Path, kind: str) -> None:
    production_base = Path(f"/var/tmp/qcsd-docker-lifecycle-{os.getuid()}")
    assert root.is_absolute(), root
    assert root.parent != production_base, root
    assert root.parent.name == "isolated-lifecycle", root
    assert re.fullmatch(rf"{re.escape(kind)}\.[0-9a-f]{{32}}", root.name), root
    parent = root.parent
    assert not parent.is_symlink(), parent
    assert parent.resolve(strict=True) == parent, parent
    metadata = parent.stat()
    assert metadata.st_uid == os.getuid(), parent
    assert metadata.st_mode & 0o777 == 0o700, parent


def _assert_recovery_security(root: Path) -> None:
    root_stat = root.stat()
    receipt = root / "RECOVERY"
    receipt_stat = receipt.stat()
    assert not root.is_symlink()
    assert not receipt.is_symlink()
    assert root_stat.st_uid == os.getuid()
    assert receipt_stat.st_uid == os.getuid()
    assert root_stat.st_mode & 0o777 == 0o700
    assert receipt_stat.st_mode & 0o777 == 0o600
    assert receipt_stat.st_nlink == 1


def _created_lifecycle_roots(
    state: Path, kind: str, *, lifecycle_base: Path | None = None
) -> list[Path]:
    roots_log = state / "supervisor-roots.log"
    assert roots_log.is_file()
    if lifecycle_base is None:
        lifecycle_base = state.parent / "isolated-lifecycle"
    pattern = re.compile(
        rf"{re.escape(os.fspath(lifecycle_base))}/"
        rf"{re.escape(kind)}\.[0-9a-f]{{32}}"
    )
    roots = [
        Path(line)
        for line in roots_log.read_text(encoding="utf-8").splitlines()
        if pattern.fullmatch(line)
    ]
    assert roots
    return roots


def _wait_for_build_supervision_bound(state: Path) -> Path:
    """Wait until the supervisor's durable bound record is externally visible."""
    roots = _created_lifecycle_roots(state, "build")
    assert len(roots) == 1
    root = roots[0]
    _wait_for_text(root / "SUPERVISION", "lifecycle_state=bound\n")
    return root


def _wait_for_build_signal_ready(state: Path) -> Path:
    """Wait until bound publication has returned and the host trap can run."""

    root = _wait_for_build_supervision_bound(state)
    _wait(state / "build-supervisor-signal-ready")
    return root


def _wait_for_run_supervision_authorised(state: Path) -> Path:
    """Wait until the run supervisor has durably entered its bounded wait."""

    roots = _created_lifecycle_roots(state, "run")
    assert len(roots) == 1
    root = roots[0]
    _wait_for_text(
        root / "SUPERVISION",
        "status_file_state=awaiting-command-status\n",
        timeout=10,
    )
    return root


def _wait_for_run_signal_ready(state: Path) -> Path:
    """Wait until run publication has returned and the host trap can run."""

    root = _wait_for_run_supervision_authorised(state)
    _wait(state / "run-supervisor-signal-ready")
    return root


def _assert_lifecycle_receipt_identity(root: Path, receipt: str, state: str) -> None:
    source = HELPER.resolve()
    _assert_private_lifecycle_root_path(root, root.name.split(".", 1)[0])
    assert re.fullmatch(r"(?:run|network|build)\.[0-9a-f]{32}", root.name)
    assert not root.is_symlink()
    metadata = root.stat()
    assert metadata.st_uid == os.getuid()
    assert metadata.st_mode & 0o777 == 0o700
    assert "lifecycle_schema=1\n" in receipt
    assert f"lifecycle_state={state}\n" in receipt
    assert f"lifecycle_root={root}\n" in receipt
    assert f"lifecycle_token={root.name.split('.', 1)[1]}\n" in receipt
    assert f"supervisor_source_path={source}\n" in receipt
    assert (
        f"supervisor_source_sha256={hashlib.sha256(source.read_bytes()).hexdigest()}\n"
        in receipt
    )
    assert re.search(r"^supervisor_source_device=[1-9][0-9]*$", receipt, re.MULTILINE)
    assert re.search(r"^supervisor_source_inode=[1-9][0-9]*$", receipt, re.MULTILINE)


def test_fake_environment_binds_lifecycle_namespace_and_lock_to_private_paths(
    fake_environment: dict[str, str], tmp_path: Path
) -> None:
    expected_base = tmp_path / "isolated-lifecycle"
    result = subprocess.run(
        [
            "bash",
            "-c",
            r'''\
set -euo pipefail
source "$HELPER"
_qcsd_secure_lifecycle_base
printf 'base=%s\nlock=%s\n' \
  "$_qcsd_lifecycle_base" "$(_qcsd_lifecycle_lock_path)"
''',
        ],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == f"base={expected_base}\nlock={expected_base}.lock\n"
    assert "/var/tmp/qcsd-docker-lifecycle-" not in result.stdout


def test_production_lifecycle_lock_path_identity_is_unchanged() -> None:
    result = subprocess.run(
        [
            "bash",
            "-c",
            'set -euo pipefail; source "$HELPER"; _qcsd_lifecycle_lock_path',
        ],
        env={**os.environ, "HELPER": str(HELPER)},
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == f"/var/tmp/qcsd-docker-lifecycle-{os.getuid()}.lock\n"


@pytest.mark.parametrize("status", [0, 37, 127])
def test_build_natural_status_preserves_nonzero_taint_contract(
    fake_environment: dict[str, str], status: int
) -> None:
    fake_environment["FAKE_BUILD_BEHAVIOR"] = f"natural{status}"
    process = _start_build(fake_environment)
    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == status, (stdout, stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    scope_unit = _build_scope_unit(state)
    _assert_user_scope_inactive(scope_unit)
    assert f"BUILD_STATUS {status}" in calls
    assert calls.index(f"BUILD_STATUS {status}") < calls.index("BUILD_OUTER_CLEANUP")
    if status == 0:
        assert "Docker build CLI teardown is unresolved; preserving" not in stderr
        return

    recovery_root = _build_recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        _assert_scoped_build_receipt(
            receipt,
            unit=scope_unit,
            command_status=str(status),
            systemd_status=str(status),
        )
        assert "docker_context=default\n" in receipt
        assert "scope_leak_detected=0\n" in receipt
        assert "scope_kill_attempted=0\n" in receipt
        assert "scope_kill_outcome=not_attempted\n" in receipt
        assert "requested_signal=none\n" in receipt
        assert "forwarded_cli_signal=none\n" in receipt
        assert "cli_signal_attempted=0\n" in receipt
        assert "cli_signal_outcome=not_attempted\n" in receipt
        assert "cli_forced=0\n" in receipt
        assert "cli_force_attempted=0\n" in receipt
        assert "cli_force_outcome=not_attempted\n" in receipt
        assert (
            "daemon_cancellation=unavailable-client-disconnect-only\n" in receipt
        )
    finally:
        shutil.rmtree(recovery_root)


def test_external_build_cli_sigkill_preserves_status_and_secure_taint(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_BUILD_BEHAVIOR="cooperative",
        FAKE_BUILD_KEEP_INHERITED_FDS="1",
    )
    process = _start_build(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    lock = Path(fake_environment["LOCK_PATH"]).resolve()
    _wait(state / "build-ready")
    _wait_for_build_supervision_bound(state)
    cli_pid = int((state / "build-cli-pid").read_text(encoding="ascii"))

    assert not _lock_available(lock)
    assert not Path(f"/proc/{cli_pid}/fd/9").exists()
    assert lock not in _process_fd_targets(cli_pid)
    os.kill(cli_pid, signal.SIGKILL)
    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == 137, (stdout, stderr)
    assert _lock_available(lock)
    _wait_not_live(cli_pid)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    scope_unit = _build_scope_unit(state)
    _assert_user_scope_inactive(scope_unit)
    assert "BUILD_STATUS 137" in calls
    assert calls.index("BUILD_STATUS 137") < calls.index("BUILD_OUTER_CLEANUP")
    recovery_root = _build_recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        _assert_scoped_build_receipt(
            receipt,
            unit=scope_unit,
            command_status="137",
            systemd_status="137",
        )
        assert "requested_signal=none\n" in receipt
        assert "forwarded_cli_signal=none\n" in receipt
        assert "cli_signal_attempted=0\n" in receipt
        assert "cli_signal_outcome=not_attempted\n" in receipt
        assert "cli_forced=0\n" in receipt
        assert "cli_force_attempted=0\n" in receipt
        assert "cli_force_outcome=not_attempted\n" in receipt
        assert (
            "daemon_cancellation=unavailable-client-disconnect-only\n" in receipt
        )
    finally:
        shutil.rmtree(recovery_root)


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        (signal.SIGHUP, 129),
        (signal.SIGINT, 130),
        (signal.SIGQUIT, 131),
        (signal.SIGTERM, 143),
    ],
)
def test_build_signal_maps_host_status_and_preserves_cooperative_taint(
    fake_environment: dict[str, str],
    requested: signal.Signals,
    expected: int,
) -> None:
    fake_environment.update(
        FAKE_BUILD_BEHAVIOR="cooperative",
        FAKE_BUILD_SIGNAL_GATE="1",
        FAKE_BUILD_SUPERVISOR_SIGNAL_GATE="1",
    )
    # The production guardian resets and unblocks every forwarded signal
    # before exec. Start from an ignored disposition so this harness cannot
    # silently depend on the pytest launcher's signal state.
    previous_handler = signal.getsignal(requested)
    signal.signal(requested, signal.SIG_IGN)
    try:
        process = _start_build(fake_environment)
    finally:
        signal.signal(requested, previous_handler)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    lock = Path(fake_environment["LOCK_PATH"])
    _wait(state / "build-ready")
    _wait_for_build_signal_ready(state)
    assert not _lock_available(lock)

    os.kill(process.pid, requested)
    _wait(state / "build-supervisor-signal-latched")
    _wait(state / "build-int-blocked")
    lock_held_during_cancellation = not _lock_available(lock)
    (state / "build-int-release").write_text("release\n", encoding="ascii")
    stdout, stderr = _communicate(process, timeout=10)

    assert lock_held_during_cancellation
    assert process.returncode == expected, (stdout, stderr)
    assert _lock_available(lock)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "BUILD_INT" in calls
    assert f"BUILD_STATUS {expected}" in calls
    assert calls.index("BUILD_INT") < calls.index("BUILD_OUTER_CLEANUP")
    recovery_root = _build_recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        assert f"requested_signal={requested.name.removeprefix('SIG')}\n" in receipt
        assert "forwarded_cli_signal=INT\n" in receipt
        assert "cli_signal_attempted=1\n" in receipt
        assert "cli_signal_outcome=accepted\n" in receipt
        assert "cli_forced=0\n" in receipt
        assert "cli_force_attempted=0\n" in receipt
        assert "cli_force_outcome=not_attempted\n" in receipt
        assert (
            "daemon_cancellation=unavailable-client-disconnect-only\n" in receipt
        )
    finally:
        shutil.rmtree(recovery_root)


def test_build_cli_is_isolated_and_caller_group_signal_is_supervised(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_BUILD_BEHAVIOR"] = "cooperative"
    process = _start_build(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "build-ready")
    _wait_for_build_supervision_bound(state)
    cli_pid = int((state / "build-cli-pid").read_text(encoding="ascii"))
    scope_unit = _build_scope_unit(state)
    cli_session = os.getsid(cli_pid)
    cli_process_group = os.getpgid(cli_pid)

    assert cli_session == cli_process_group
    assert cli_session != process.pid
    os.killpg(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == 143, (stdout, stderr)
    assert not Path(f"/proc/{cli_pid}").exists()
    _assert_user_scope_inactive(scope_unit)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "BUILD_INT" in calls
    assert calls.index("BUILD_INT") < calls.index("BUILD_OUTER_CLEANUP")
    recovery_root = _build_recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        assert "object=docker-build-scope-launcher\n" in receipt
        assert f"scope_launcher_pid={cli_session}\n" in receipt
        assert f"scope_launcher_session={cli_session}\n" in receipt
        assert f"scope_launcher_process_group={cli_process_group}\n" in receipt
        assert f"scope_unit={scope_unit}\n" in receipt
        assert "scope_empty_proven=1\n" in receipt
        assert "requested_signal=TERM\n" in receipt
        assert "forwarded_cli_signal=INT\n" in receipt
        assert "cli_forced=0\n" in receipt
    finally:
        shutil.rmtree(recovery_root)


def test_build_exit_with_surviving_group_descendant_forces_group_and_taints(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_BUILD_BEHAVIOR="surviving-descendant",
        FAKE_BUILD_KEEP_INHERITED_FDS="1",
        FAKE_BUILD_PARENT_EXIT_DELAY="0.4",
    )
    process = _start_build(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    lock = Path(fake_environment["LOCK_PATH"]).resolve()
    _wait(state / "build-descendant-ready")
    cli_pid = int((state / "build-cli-pid").read_text(encoding="ascii"))
    descendant_pid = int(
        (state / "build-descendant-pid").read_text(encoding="ascii")
    )
    scope_unit = _build_scope_unit(state)
    cli_session = os.getsid(cli_pid)
    cli_process_group = os.getpgid(cli_pid)

    assert cli_session == cli_process_group
    assert os.getsid(descendant_pid) == cli_session
    assert os.getpgid(descendant_pid) == cli_process_group
    assert not _lock_available(lock)
    assert not Path(f"/proc/{cli_pid}/fd/9").exists()
    assert not Path(f"/proc/{descendant_pid}/fd/9").exists()
    assert lock not in _process_fd_targets(cli_pid)
    assert lock not in _process_fd_targets(descendant_pid)
    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == 37, (stdout, stderr)
    assert _lock_available(lock)
    _wait_not_live(cli_pid)
    _wait_not_live(descendant_pid)
    _assert_user_scope_inactive(scope_unit)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "BUILD_STATUS 37" in calls
    assert calls.index("BUILD_STATUS 37") < calls.index("BUILD_OUTER_CLEANUP")
    recovery_root = _build_recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        _assert_scoped_build_receipt(
            receipt,
            unit=scope_unit,
            command_status="37",
            systemd_status="37",
        )
        assert "scope_leak_detected=1\n" in receipt
        assert "scope_kill_attempted=1\n" in receipt
        assert "scope_kill_outcome=accepted\n" in receipt
        assert "requested_signal=none\n" in receipt
        assert "forwarded_cli_signal=none\n" in receipt
        assert "cli_signal_attempted=0\n" in receipt
        assert "cli_signal_outcome=not_attempted\n" in receipt
        assert "cli_forced=0\n" in receipt
        assert "cli_force_attempted=0\n" in receipt
        assert "cli_force_outcome=not_attempted\n" in receipt
        assert (
            "daemon_cancellation=unavailable-client-disconnect-only\n" in receipt
        )
    finally:
        shutil.rmtree(recovery_root)


def test_build_scope_contains_and_kills_a_setsid_descendant(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_BUILD_BEHAVIOR="escaped-descendant",
        FAKE_BUILD_KEEP_INHERITED_FDS="1",
        FAKE_BUILD_PARENT_EXIT_DELAY="0.4",
    )
    process = _start_build(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    lock = Path(fake_environment["LOCK_PATH"]).resolve()
    _wait(state / "build-escaped-descendant-ready")
    descendant_pid = int(
        (state / "build-escaped-descendant-pid").read_text(encoding="ascii")
    )
    scope_unit = _build_scope_unit(state)

    assert os.getsid(descendant_pid) == descendant_pid
    assert os.getpgid(descendant_pid) == descendant_pid
    descendant_cgroup = Path(f"/proc/{descendant_pid}/cgroup").read_text(
        encoding="ascii"
    )
    assert f"/{scope_unit}" in descendant_cgroup
    assert not Path(f"/proc/{descendant_pid}/fd/9").exists()
    assert lock not in _process_fd_targets(descendant_pid)

    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == 1, (stdout, stderr)
    assert _lock_available(lock)
    _wait_not_live(descendant_pid)
    _assert_user_scope_inactive(scope_unit)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "BUILD_STATUS 1" in calls
    recovery_root = _build_recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        _assert_scoped_build_receipt(
            receipt,
            unit=scope_unit,
            command_status="0",
            systemd_status="0",
        )
        assert "scope_leak_detected=1\n" in receipt
        assert "scope_kill_attempted=1\n" in receipt
        assert "scope_kill_outcome=accepted\n" in receipt
    finally:
        shutil.rmtree(recovery_root)


@pytest.mark.parametrize(
    ("tamper", "status_state", "command_status"),
    [
        ("missing", "missing", "unavailable"),
        ("malformed", "invalid", "unavailable"),
        ("mismatch", "status-mismatch", "1"),
    ],
)
def test_build_rejects_missing_malformed_or_mismatched_private_status(
    fake_environment: dict[str, str],
    tamper: str,
    status_state: str,
    command_status: str,
) -> None:
    fake_environment.update(
        FAKE_BUILD_BEHAVIOR="natural0",
        FAKE_BUILD_STATUS_TAMPER=tamper,
    )
    process = _start_build(fake_environment)
    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == 1, (stdout, stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    scope_unit = _build_scope_unit(state)
    _assert_user_scope_inactive(scope_unit)
    recovery_root = _build_recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        _assert_scoped_build_receipt(
            receipt,
            unit=scope_unit,
            command_status=command_status,
            systemd_status="0",
            status_state=status_state,
            status_matches=0,
        )
        assert "scope_leak_detected=0\n" in receipt
        assert "scope_kill_attempted=0\n" in receipt
    finally:
        shutil.rmtree(recovery_root)


def test_uncooperative_build_is_forced_and_preserves_a_secure_taint_receipt(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_BUILD_BEHAVIOR"] = "ignore-int"
    process = _start_build(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    lock = Path(fake_environment["LOCK_PATH"])
    _wait(state / "build-ready")
    _wait_for_build_supervision_bound(state)
    cli_pid = int((state / "build-cli-pid").read_text(encoding="ascii"))

    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == 143, (stdout, stderr)
    assert _lock_available(lock)
    assert not Path(f"/proc/{cli_pid}").exists()
    scope_unit = _build_scope_unit(state)
    _assert_user_scope_inactive(scope_unit)
    recovery_root = _build_recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        expected_hash = hashlib.sha256(
            b"docker\0--host\0unix:///var/run/docker.sock\0"
            b"build\0fake-context\0"
        ).hexdigest()
        assert "object=docker-build-scope-launcher\n" in receipt
        assert "process_identity_role=local-systemd-run-scope-launcher\n" in receipt
        assert re.search(r"^scope_launcher_pid=[1-9][0-9]*$", receipt, re.MULTILINE)
        assert re.search(
            r"^scope_launcher_start_time=[1-9][0-9]*$", receipt, re.MULTILINE
        )
        assert f"scope_unit={scope_unit}\n" in receipt
        assert "scope_empty_proven=1\n" in receipt
        assert "docker_context=default\n" in receipt
        lock_metadata = Path(fake_environment["LOCK_PATH"]).stat()
        assert f"build_lock_path={Path(fake_environment['LOCK_PATH']).resolve()}\n" in receipt
        assert f"build_lock_device={lock_metadata.st_dev}\n" in receipt
        assert f"build_lock_inode={lock_metadata.st_ino}\n" in receipt
        assert f"working_directory={ROOT.resolve()}\n" in receipt
        assert f"build_argv_sha256={expected_hash}\n" in receipt
        assert "requested_signal=TERM\n" in receipt
        assert "forwarded_cli_signal=INT\n" in receipt
        assert "cli_signal_attempted=1\n" in receipt
        assert "cli_signal_outcome=accepted\n" in receipt
        assert "cli_forced=1\n" in receipt
        assert "cli_force_attempted=1\n" in receipt
        assert "cli_force_outcome=accepted\n" in receipt
        assert (
            "daemon_cancellation=unavailable-client-disconnect-only\n" in receipt
        )
    finally:
        shutil.rmtree(recovery_root)


@pytest.mark.parametrize(
    "invocation",
    [
        "qcsd_run_docker_build docker build fake-context",
        "qcsd_run_docker_build podman --context default build fake-context",
        "qcsd_run_docker_build docker --context default run fake-context",
        "qcsd_run_docker_build docker --context ../escape build fake-context",
    ],
)
def test_build_supervisor_rejects_invalid_argv_or_context_before_launch(
    fake_environment: dict[str, str], invocation: str
) -> None:
    script = f'''\
set -euo pipefail
source "$HELPER"
set +e
{invocation}
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 2, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert not (state / "calls.log").exists()
    assert not (state / "contexts.log").exists()


@pytest.mark.parametrize(
    ("declaration", "destination"),
    [
        ("", "QCSD_DOCKER_OUTPUT_UNDECLARED"),
        ("QCSD_DOCKER_OUTPUT_WRONG=()", "QCSD_DOCKER_OUTPUT_WRONG"),
        ("readonly QCSD_DOCKER_OUTPUT_READONLY=''", "QCSD_DOCKER_OUTPUT_READONLY"),
        ("captured_output=''", "captured_output"),
        ("captured=''", "captured"),
    ],
)
def test_attached_capture_rejects_unsafe_destination_before_docker_invocation(
    fake_environment: dict[str, str], declaration: str, destination: str
) -> None:
    script = f'''\
set -euo pipefail
source "$HELPER"
{declaration}
set +e
qcsd_capture_attached_docker_output {destination} \
  docker --context default run fake-image
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "Docker stdout capture requires an existing safe caller variable" in (
        result.stderr
    )
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert not (state / "calls.log").exists()
    assert not (state / "contexts.log").exists()


@pytest.mark.parametrize(
    ("declaration", "destination"),
    [
        ("", "QCSD_DOCKER_IDS_UNDECLARED"),
        ("QCSD_DOCKER_IDS_WRONG=''", "QCSD_DOCKER_IDS_WRONG"),
        ("readonly -a QCSD_DOCKER_IDS_READONLY=()", "QCSD_DOCKER_IDS_READONLY"),
        ("ids=()", "ids"),
        ("registration=()", "registration"),
    ],
)
def test_network_rejects_unsafe_registration_before_docker_invocation(
    fake_environment: dict[str, str], declaration: str, destination: str
) -> None:
    script = f'''\
set -euo pipefail
source "$HELPER"
{declaration}
set +e
qcsd_create_docker_network {destination} docker network create test-network
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "Docker network supervision requires an indexed cleanup array" in (
        result.stderr
    )
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert not (state / "calls.log").exists()
    assert not (state / "contexts.log").exists()


@pytest.mark.parametrize(
    ("declaration", "destination"),
    [
        ("", "QCSD_DOCKER_IDS_UNDECLARED"),
        ("QCSD_DOCKER_IDS_WRONG=''", "QCSD_DOCKER_IDS_WRONG"),
        ("readonly -a QCSD_DOCKER_IDS_READONLY=()", "QCSD_DOCKER_IDS_READONLY"),
        ("ids=()", "ids"),
        ("registration=()", "registration"),
    ],
)
def test_detached_run_rejects_unsafe_registration_before_docker_invocation(
    fake_environment: dict[str, str], declaration: str, destination: str
) -> None:
    script = f'''\
set -euo pipefail
source "$HELPER"
{declaration}
set +e
qcsd_run_detached_docker {destination} docker run fake-image
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "Detached Docker supervision requires an indexed cleanup array" in (
        result.stderr
    )
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert not (state / "calls.log").exists()
    assert not (state / "contexts.log").exists()


def test_build_supervisor_uses_explicit_context_not_ambient_context(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH"
flock -n 9
_QCSD_DOCKER_BUILD_LOCK_FD=9
qcsd_run_docker_build docker --context evidence-context build fake-context
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env={
            **fake_environment,
            "DOCKER_CONTEXT": "ambient-context",
            "_QCSD_DOCKER_PINNED_CONTEXT": "evidence-context",
            "FAKE_BUILD_BEHAVIOR": "natural0",
        },
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    contexts = Path(fake_environment["FAKE_DOCKER_STATE"], "contexts.log").read_text(
        encoding="utf-8"
    )
    assert "unix:///var/run/docker.sock build fake-context\n" in contexts
    assert "ambient-context build fake-context\n" not in contexts


@pytest.mark.parametrize("errexit", [False, True])
def test_build_success_restores_all_caller_traps_and_shell_options(
    fake_environment: dict[str, str], errexit: bool
) -> None:
    script = r'''
set -uo pipefail
source "$HELPER"
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH"
flock -n 9
_QCSD_DOCKER_BUILD_LOCK_FD=9
trap ':' HUP
trap ':' INT
trap ':' QUIT
trap ':' TERM
before_hup="$(trap -p HUP)"
before_int="$(trap -p INT)"
before_quit="$(trap -p QUIT)"
before_term="$(trap -p TERM)"
if [[ "$WANT_ERREXIT" == 1 ]]; then set -e; else set +e; fi
qcsd_run_docker_build docker --context default build fake-context
status=$?
[[ "$(trap -p HUP)" == "$before_hup" ]]
[[ "$(trap -p INT)" == "$before_int" ]]
[[ "$(trap -p QUIT)" == "$before_quit" ]]
[[ "$(trap -p TERM)" == "$before_term" ]]
[[ "$-" == *u* ]]
shopt -qo pipefail
if [[ "$WANT_ERREXIT" == 1 ]]; then [[ "$-" == *e* ]]; else [[ "$-" != *e* ]]; fi
exit "$status"
'''
    result = subprocess.run(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
        cwd=ROOT,
        env={
            **fake_environment,
            "FAKE_BUILD_BEHAVIOR": "natural0",
            "WANT_ERREXIT": "1" if errexit else "0",
        },
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.parametrize(("requested", "expected"), [
    (signal.SIGHUP, 129),
    (signal.SIGINT, 130),
    (signal.SIGQUIT, 131),
    (signal.SIGTERM, 143),
])
def test_direct_signal_is_forwarded_and_host_lock_lives_through_cleanup(
    fake_environment: dict[str, str],
    requested: signal.Signals,
    expected: int,
) -> None:
    fake_environment.update(
        FAKE_KILL_DELAY="0.3",
        FAKE_RUN_SUPERVISOR_SIGNAL_GATE="1",
    )
    previous_handler = signal.getsignal(requested)
    signal.signal(requested, signal.SIG_IGN)
    try:
        process = _start_attached(fake_environment)
    finally:
        signal.signal(requested, previous_handler)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    lock = Path(fake_environment["LOCK_PATH"])
    _wait(state / "run-ready")
    _wait_for_run_signal_ready(state)
    assert not _lock_available(lock)

    os.kill(process.pid, requested)
    _wait(state / "run-supervisor-signal-latched")
    time.sleep(0.05)
    assert not _lock_available(lock)
    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == expected, (stdout, stderr)
    assert _lock_available(lock)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert f"KILL INT {CONTAINER_ID}" in calls
    assert calls.index("KILL INT") < calls.index("OUTER_CLEANUP")
    assert not (state / "container").exists()


def test_natural_arbitrary_status_is_preserved(fake_environment: dict[str, str]) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "natural37"
    process = _start_attached(fake_environment)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 37, (stdout, stderr)
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").read_text()
    assert "STATUS 37" in calls
    assert " KILL " not in f" {calls}"


def test_loaded_helper_rejects_mid_process_source_replacement_before_api(
    fake_environment: dict[str, str], tmp_path: Path
) -> None:
    copied = tmp_path / "replaceable-helper.sh"
    fixture_shims = _fixture_helper_shims(fake_environment)
    copied.write_bytes(
        HELPER.read_bytes()
        + fixture_shims.encode()
        + b"\n_qcsd_verify_pinned_docker_daemon() { return 0; }\n"
    )
    copied.chmod(0o600)
    script = r'''
set -euo pipefail
source "$REPLACEABLE_HELPER"
replacement=${REPLACEABLE_HELPER}.replacement
cp -- "$REPLACEABLE_HELPER" "$replacement"
printf '\n# replaced after source\n' >>"$replacement"
chmod 600 -- "$replacement"
mv -f -- "$replacement" "$REPLACEABLE_HELPER"
set +e
_qcsd_docker_api version >/dev/null
status=$?
set -e
printf 'STATUS=%s\n' "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env={**fake_environment, "REPLACEABLE_HELPER": str(copied)},
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "STATUS=125\n"
    assert "source identity changed" in result.stderr
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log")
    assert not calls.exists() or calls.read_text(encoding="utf-8") == ""


@pytest.mark.parametrize("kind", ["run", "build"])
@pytest.mark.skip(reason="FD-backed source replacement is covered by guardian integration")
def test_source_replacement_at_bound_birth_prevents_launcher_release(
    fake_environment: dict[str, str], tmp_path: Path, kind: str
) -> None:
    copied = tmp_path / f"replaceable-{kind}-helper.sh"
    fixture_shims = _fixture_helper_shims(fake_environment)
    copied.write_bytes(
        HELPER.read_bytes()
        + fixture_shims.encode()
        + b"\n_qcsd_verify_pinned_docker_daemon() { return 0; }\n"
    )
    copied.chmod(0o600)
    wrapper = tmp_path / f"replace-{kind}-wrapper.sh"
    wrapper.write_text(
        textwrap.dedent(
            r'''\
source "$REAL_HELPER"
_qcsd_lifecycle_root_created_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}
_qcsd_launcher_birth_bound_hook() {
  replacement=${REAL_HELPER}.replacement
  cp -- "$REAL_HELPER" "$replacement"
  printf '\n# replaced at durable birth boundary\n' >>"$replacement"
  chmod 600 -- "$replacement"
  mv -f -- "$replacement" "$REAL_HELPER"
}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {
        **fake_environment,
        "HELPER": str(wrapper),
        "REAL_HELPER": str(copied),
    }
    Path(environment["LOCK_PATH"]).touch(mode=0o600)
    Path(environment["LOCK_PATH"]).chmod(0o600)
    process = _start_attached(environment) if kind == "run" else _start_build(environment)
    stdout, stderr = _communicate(process, timeout=30)
    assert process.returncode == 1, (stdout, stderr)
    assert "source changed before request authorisation" in stderr
    calls = Path(environment["FAKE_DOCKER_STATE"], "calls.log").read_text(
        encoding="utf-8"
    )
    assert " RUN " not in f" {calls} "
    assert " BUILD " not in f" {calls} "


@pytest.mark.parametrize("kind", ["run", "build"])
@pytest.mark.skip(reason="FD-backed source replacement is covered by guardian integration")
def test_source_replacement_after_authorisation_prevents_sigcont(
    fake_environment: dict[str, str], tmp_path: Path, kind: str
) -> None:
    copied = tmp_path / f"release-{kind}-helper.sh"
    fixture_shims = _fixture_helper_shims(fake_environment)
    copied.write_bytes(HELPER.read_bytes() + fixture_shims.encode())
    copied.chmod(0o600)
    wrapper = tmp_path / f"release-{kind}-wrapper.sh"
    wrapper.write_text(
        textwrap.dedent(
            r'''\
source "$REAL_HELPER"
_qcsd_lifecycle_root_created_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}
_qcsd_pre_cont_signal_hook() {
  replacement=${REAL_HELPER}.replacement
  cp -- "$REAL_HELPER" "$replacement"
  printf '\n# replaced after request authorisation\n' >>"$replacement"
  chmod 600 -- "$replacement"
  mv -f -- "$replacement" "$REAL_HELPER"
}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {
        **fake_environment,
        "HELPER": str(wrapper),
        "REAL_HELPER": str(copied),
    }
    Path(environment["LOCK_PATH"]).touch(mode=0o600)
    Path(environment["LOCK_PATH"]).chmod(0o600)
    process = _start_attached(environment) if kind == "run" else _start_build(environment)
    stdout, stderr = _communicate(process, timeout=30)
    assert process.returncode == 1, (stdout, stderr)
    assert "cannot release the bound Docker" in stderr
    calls = Path(environment["FAKE_DOCKER_STATE"], "calls.log").read_text(
        encoding="utf-8"
    )
    assert " RUN " not in f" {calls} "
    assert " BUILD " not in f" {calls} "


@pytest.mark.parametrize("kind", ["run", "build", "network"])
def test_latched_signal_at_final_release_boundary_prevents_docker_launch(
    fake_environment: dict[str, str], tmp_path: Path, kind: str
) -> None:
    wrapper = tmp_path / f"signal-release-{kind}.sh"
    hook = (
        "_qcsd_pre_cont_signal_hook"
        if kind in {"run", "build"}
        else "_qcsd_pre_mutation_release_hook"
    )
    wrapper.write_text(
        textwrap.dedent(
            f'''\
source "$REAL_HELPER"
_qcsd_lifecycle_root_created_hook() {{
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}}
{hook}() {{
  kill -TERM "$BASHPID"
}}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {**fake_environment, "HELPER": str(wrapper)}
    Path(environment["LOCK_PATH"]).touch(mode=0o600)
    Path(environment["LOCK_PATH"]).chmod(0o600)
    if kind == "run":
        process = _start_attached(environment)
    elif kind == "build":
        process = _start_build(environment)
    else:
        process = subprocess.Popen(
            [
                *SIGNAL_CLEAN_BASH,
                'set -euo pipefail; source "$HELPER"; QCSD_DOCKER_IDS_TEST=(); '
                "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create test-network",
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    stdout, stderr = _communicate(process, timeout=30)
    assert process.returncode == 143, (stdout, stderr)
    calls = Path(environment["FAKE_DOCKER_STATE"], "calls.log")
    call_text = calls.read_text(encoding="utf-8") if calls.exists() else ""
    assert " RUN " not in f" {call_text} "
    assert " BUILD " not in f" {call_text} "
    assert "NETWORK_CREATE" not in call_text


def test_natural_zero_is_preserved_without_cleanup_intervention(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "natural0"
    process = _start_attached(fake_environment)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 0, (stdout, stderr)
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").read_text()
    assert "STATUS 0" in calls
    assert " KILL " not in f" {calls}"
    assert f"RM {CONTAINER_ID}" not in calls


def test_attached_stdout_capture_assigns_caller_variable_without_subshell(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="natural0",
        FAKE_RUN_STDOUT="bound-output",
    )
    script = r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_OUTPUT_TEST=""
qcsd_capture_attached_docker_output QCSD_DOCKER_OUTPUT_TEST docker run fake-image
[[ "$QCSD_DOCKER_OUTPUT_TEST" == bound-output ]]
printf 'CAPTURED=%s\n' "$QCSD_DOCKER_OUTPUT_TEST"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == "CAPTURED=bound-output\n"


def test_natural_nonzero_survives_unresolved_exact_cleanup(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="natural37-leak",
        FAKE_RM_STAYS="1",
    )
    process = _start_attached(fake_environment)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 37, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        _assert_recovery_security(recovery)
        assert "target_state=running" in (recovery / "RECOVERY").read_text()
    finally:
        shutil.rmtree(recovery)
        state = Path(fake_environment["FAKE_DOCKER_STATE"])
        for name in ("container", "container-token", "running"):
            (state / name).unlink(missing_ok=True)


def test_failed_rm_is_accepted_only_when_exact_absence_is_proven(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="success-leak",
        FAKE_RM_ERROR_AFTER_REMOVE="1",
    )
    process = _start_attached(fake_environment)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 0, (stdout, stderr)
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").read_text()
    assert f"RM {CONTAINER_ID}" in calls
    assert "preserving" not in stderr


def test_cleanup_failure_after_natural_success_becomes_one(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="success-leak",
        FAKE_RM_STAYS="1",
    )
    process = _start_attached(fake_environment)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 1, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        assert "target_state=running" in (recovery / "RECOVERY").read_text()
    finally:
        shutil.rmtree(recovery)
        state = Path(fake_environment["FAKE_DOCKER_STATE"])
        for name in ("container", "container-token", "running"):
            (state / name).unlink(missing_ok=True)


def test_uncooperative_target_is_forcibly_removed_before_outer_cleanup(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "ignore-kill"
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.index(f"KILL INT {CONTAINER_ID}") < calls.index(f"RM {CONTAINER_ID}")
    assert calls.index(f"RM {CONTAINER_ID}") < calls.index("OUTER_CLEANUP")
    assert "required exact-target forced removal" in stderr


def test_failed_signal_api_gets_one_grace_period_then_exact_forced_removal(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_KILL_ERROR"] = "1"
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    started = time.monotonic()
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)
    elapsed = time.monotonic() - started
    assert process.returncode == 143, (stdout, stderr)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count(f"KILL INT {CONTAINER_ID}") == 1
    assert calls.count(f"CONTAINER_WAIT {CONTAINER_ID}") == 1
    assert f"RM {CONTAINER_ID}" in calls
    # The signal path permits one three-second daemon API bound before exact
    # removal, plus bounded local process/scope reconciliation.  Leave enough
    # scheduling margin for a fully loaded test host while still proving that
    # a second grace period was not entered.
    assert elapsed < 8
    assert "required exact-target forced removal" in stderr


def test_failed_signal_api_is_recorded_as_unknown_not_forwarded(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(FAKE_KILL_ERROR="1", FAKE_RM_STAYS="1")
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        _assert_recovery_security(recovery)
        receipt = (recovery / "RECOVERY").read_text(encoding="utf-8")
        assert "requested_signal=TERM" in receipt
        assert "planned_target_signal=INT" in receipt
        assert "target_signal_attempted=1" in receipt
        assert "target_signal_api_outcome=unknown" in receipt
        assert "forwarded_target_signal=none" in receipt
        assert "target_forced=1" in receipt
    finally:
        shutil.rmtree(recovery)
        for name in ("container", "container-token", "running"):
            (state / name).unlink(missing_ok=True)


@pytest.mark.parametrize("late_reason", ["internal_abort", "none"])
def test_late_signal_latch_remains_a_valid_recovery_suffix(
    fake_environment: dict[str, str], late_reason: str
) -> None:
    fake_environment.update(FAKE_KILL_ERROR="1", FAKE_RM_STAYS="1")
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        receipt_path = recovery / "RECOVERY"
        receipt = receipt_path.read_text(encoding="ascii")
        receipt = receipt.replace(
            "interruption_reason=host_signal", f"interruption_reason={late_reason}"
        )
        if late_reason == "none":
            replacements = {
                "planned_target_signal=INT": "planned_target_signal=none",
                "target_signal_attempted=1": "target_signal_attempted=0",
                "target_signal_api_outcome=unknown": (
                    "target_signal_api_outcome=not_attempted"
                ),
            }
            for old, new in replacements.items():
                assert old in receipt
                receipt = receipt.replace(old, new)
            receipt = re.sub(
                r"^target_forced=[01]$", "target_forced=0", receipt,
                flags=re.MULTILINE,
            )
            receipt = re.sub(
                r"^target_force_attempted=[01]$",
                "target_force_attempted=0",
                receipt,
                flags=re.MULTILINE,
            )
            receipt = re.sub(
                r"^target_force_api_outcome=(?:accepted|unknown)$",
                "target_force_api_outcome=not_attempted",
                receipt,
                flags=re.MULTILINE,
            )
        receipt_path.write_text(receipt, encoding="ascii")
        receipt_path.chmod(0o600)
        check = subprocess.run(
            [
                "bash",
                "-c",
                    'set -euo pipefail; source "$REAL_HELPER"; '
                    '_qcsd_secure_lifecycle_base; '
                    '_qcsd_lifecycle_validate_root "$LIFECYCLE_ROOT" run',
            ],
            env={
                **fake_environment,
                "LIFECYCLE_ROOT": str(recovery),
                "REAL_HELPER": fake_environment["REAL_HELPER"],
            },
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert check.returncode == 0, check.stderr
    finally:
        shutil.rmtree(recovery)
        for name in ("container", "container-token", "running"):
            (state / name).unlink(missing_ok=True)


@pytest.mark.parametrize("kind", ["run", "network"])
def test_handoff_cannot_transition_to_unauthorised_recovery(
    fake_environment: dict[str, str], kind: str
) -> None:
    script = r'''
set -euo pipefail
source "$REAL_HELPER"
declare -A handoff=(
  [lifecycle_state]=handed-off
  [daemon_request_authorised]=1
)
declare -A recovery=(
  [lifecycle_state]=unresolved
  [daemon_request_authorised]=0
)
set +u
! _qcsd_lifecycle_records_match handoff recovery
'''
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            **fake_environment,
            "RECORD_KIND": kind,
            "REAL_HELPER": fake_environment["REAL_HELPER"],
        },
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("state", "control_group", "accepted"),
    [
        ("active", "/user.slice/qcsd.scope", True),
        ("active", "unavailable", False),
        ("inactive", "/user.slice/qcsd.scope", True),
        ("inactive", "unavailable", True),
        ("absent", "unavailable", True),
        ("absent", "/user.slice/qcsd.scope", False),
    ],
)
def test_observed_scope_binding_partition(
    fake_environment: dict[str, str], state: str, control_group: str, accepted: bool
) -> None:
    result = subprocess.run(
        [
            "bash",
            "-c",
            'set -euo pipefail; source "$REAL_HELPER"; '
            '_qcsd_lifecycle_validate_observed_scope_binding "$STATE" "$CG"',
        ],
        env={
            **fake_environment,
            "REAL_HELPER": fake_environment["REAL_HELPER"],
            "STATE": state,
            "CG": control_group,
        },
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert (result.returncode == 0) is accepted, result.stderr


@pytest.mark.parametrize(
    ("exact_leader", "required_state", "observed_state", "accepted"),
    [
        (False, "", "R", False),
        (True, "", "R", True),
        (True, "T", "T", True),
        (True, "T", "R", False),
    ],
)
def test_process_group_signal_requires_exact_live_bound_leader(
    fake_environment: dict[str, str],
    exact_leader: bool,
    required_state: str,
    observed_state: str,
    accepted: bool,
) -> None:
    script = r'''
set -euo pipefail
source "$REAL_HELPER"
_qcsd_job_is_running() {
  _qcsd_process_state="$OBSERVED_STATE"
  [[ "$EXACT_LEADER" == 1 ]]
}
_qcsd_process_group_has_live_members() { return 0; }
kill() { printf '%s\n' "$*" >>"$FAKE_DOCKER_STATE/group-signals"; }
if [[ -n "$REQUIRED_STATE" ]]; then
  _qcsd_signal_bound_process_group 424242 17 424242 424242 TERM "$REQUIRED_STATE"
else
  _qcsd_signal_bound_process_group 424242 17 424242 424242 TERM
fi
'''
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            **fake_environment,
            "REAL_HELPER": fake_environment["REAL_HELPER"],
            "EXACT_LEADER": "1" if exact_leader else "0",
            "REQUIRED_STATE": required_state,
            "OBSERVED_STATE": observed_state,
        },
        text=True,
        capture_output=True,
        timeout=10,
    )
    signals = Path(fake_environment["FAKE_DOCKER_STATE"], "group-signals")
    assert (result.returncode == 0) is accepted, result.stderr
    assert signals.exists() is accepted


def test_preauthorised_stopped_child_that_disappears_at_containment_is_quarantined(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$REAL_HELPER"
calls=0
_qcsd_job_is_running() {
  calls=$((calls + 1))
  _qcsd_process_state=T
  (( calls == 1 ))
}
_qcsd_kill_user_scope() { printf '%s\n' "$*" >>"$FAKE_DOCKER_STATE/scope-kills"; }
_qcsd_wait_user_scope_inactive() { return 0; }
_qcsd_bound_process_is_gone() { return 0; }
declare -A stale=(
  [scope_launcher_pid]=424242
  [scope_launcher_start_time]=17
  [scope_launcher_session]=424242
  [scope_launcher_process_group]=424242
  [scope_unit]=qcsd-docker-run-00000000000000000000000000000000.scope
  [host_boot_id]="$BOOT"
)
_qcsd_lifecycle_stop_stale_scope stale "$BOOT" 1
[[ "$_QCSD_PREAUTH_CONTRADICTION_AT_CONTAINMENT" == 1 ]]
test -s "$FAKE_DOCKER_STATE/scope-kills"
'''
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env={
            **fake_environment,
            "REAL_HELPER": fake_environment["REAL_HELPER"],
            "BOOT": boot,
        },
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.parametrize("accepted", [False, True])
def test_build_scope_interrupt_is_established_before_cli_signal(
    fake_environment: dict[str, str], accepted: bool
) -> None:
    script = r'''
set -euo pipefail
source "$REAL_HELPER"
build_scope_required=1
build_scope_unit=qcsd-docker-build-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope
scope_signal_attempted=0
scope_signal_outcome=not_attempted
_qcsd_kill_user_scope() { [[ "$ACCEPTED" == 1 ]]; }
_qcsd_build_ensure_scope_interrupt
[[ "$scope_signal_attempted" == 1 ]]
if [[ "$ACCEPTED" == 1 ]]; then
  [[ "$scope_signal_outcome" == accepted ]]
else
  [[ "$scope_signal_outcome" == unknown ]]
fi
'''
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            **fake_environment,
            "REAL_HELPER": fake_environment["REAL_HELPER"],
            "ACCEPTED": "1" if accepted else "0",
        },
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("sequence", "forced", "outcome"),
    [
        ("unknown", "0", "unknown"),
        ("accepted", "1", "accepted"),
        ("accepted unknown", "1", "accepted"),
    ],
)
def test_cli_force_result_preserves_accepted_aggregate(
    fake_environment: dict[str, str], sequence: str, forced: str, outcome: str
) -> None:
    script = r'''
set -euo pipefail
source "$REAL_HELPER"
cli_forced=0
cli_force_outcome=not_attempted
for result in $SEQUENCE; do _qcsd_record_cli_force_result "$result"; done
[[ "$cli_forced:$cli_force_outcome" == "$EXPECTED" ]]
'''
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            **fake_environment,
            "REAL_HELPER": fake_environment["REAL_HELPER"],
            "SEQUENCE": sequence,
            "EXPECTED": f"{forced}:{outcome}",
        },
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_target_force_result_preserves_accepted_across_later_unknown(
    fake_environment: dict[str, str]
) -> None:
    script = r'''
set -euo pipefail
source "$REAL_HELPER"
target_force_attempted=0
target_forced=0
target_force_api_outcome=not_attempted
calls=0
_qcsd_target_docker_api() {
  calls=$((calls + 1))
  (( calls == 1 ))
}
_qcsd_force_remove_target aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
! _qcsd_force_remove_target aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[[ "$target_force_attempted:$target_forced:$target_force_api_outcome" == \
   1:1:accepted ]]
'''
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            **fake_environment,
            "REAL_HELPER": fake_environment["REAL_HELPER"],
        },
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_first_dispatched_signal_is_latched_when_a_second_signal_arrives(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "ignore-kill"
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    # Bash defers traps while it waits for some foreground external commands.
    # Waiting for the first signal's exact-target action proves that TERM was
    # dispatched before injecting INT, rather than relying on two pending
    # standard signals to retain kernel arrival order.
    _wait_for_text(state / "calls.log", f"KILL INT {CONTAINER_ID}")
    os.kill(process.pid, signal.SIGINT)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert f"KILL INT {CONTAINER_ID}" in calls
    assert "KILL TERM" not in calls


def test_signal_latch_is_safe_at_a_command_substitution_boundary(
    fake_environment: dict[str, str],
) -> None:
    """Force TERM into Bash 5.2's recursive-substitution dispatch window."""
    ready = Path(fake_environment["FAKE_DOCKER_STATE"]) / "substitution-ready"
    release = Path(fake_environment["FAKE_DOCKER_STATE"]) / "substitution-release"
    script = r'''
set -euo pipefail
source "$REAL_HELPER"
exercise_latch() {
  local requested_signal="" requested_status=0 first second
  local saved_term
  saved_term="$(trap -p TERM || true)"
  trap '_qcsd_latch_requested_signal TERM 143' TERM
  first="$(
    : >"$SUBSTITUTION_READY"
    while [[ ! -e "$SUBSTITUTION_RELEASE" ]]; do
      sleep 0.01
    done
    printf first
  )"
  # Bash 5.2 corrupts the trap parser if these two substitutions are arguments
  # of one simple command.  Separate assignments are the production invariant.
  second="$(printf second)"
  _qcsd_restore_signal_trap "$saved_term" TERM
  printf '%s:%s:%s:%s\n' "$requested_signal" "$requested_status" "$first" "$second"
}
exercise_latch
'''
    previous_handler = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        process = subprocess.Popen(
            [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
            env={
                **fake_environment,
                "SUBSTITUTION_READY": str(ready),
                "SUBSTITUTION_RELEASE": str(release),
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    _wait(ready)
    os.kill(process.pid, signal.SIGTERM)
    # Keep the signal pending until the first substitution completes so trap
    # dispatch occurs at the parser boundary rather than during its child.
    time.sleep(0.05)
    release.touch()
    stdout, stderr = _communicate(process, timeout=5)
    assert process.returncode == 0, (stdout, stderr)
    assert stdout == "TERM:143:first:second\n"
    assert "unexpected EOF" not in stderr


def _multiple_command_substitution_blocks(source_text: str) -> list[tuple[int, str]]:
    """Find supported simple-command blocks containing multiple ``$(...)``."""
    source = source_text.splitlines()
    blocks: list[tuple[int, str]] = []
    current: list[str] = []
    start = 0
    conditional_depth = 0
    array_assignment_open = False
    for line_number, line in enumerate(source, start=1):
        if not current:
            start = line_number
        current.append(line)
        conditional_depth += line.count("[[") - line.count("]]")
        if not array_assignment_open and re.search(
            r"(?:^|[;&|\s])[A-Za-z_][A-Za-z0-9_]*(?:\[[^]\n]+\])?"
            r"\+?=\(\s*(?:#.*)?$",
            line,
        ):
            array_assignment_open = True
        elif array_assignment_open and re.fullmatch(
            r"\s*\)\s*(?:[;&|].*)?", line
        ):
            array_assignment_open = False
        if (
            line.rstrip().endswith("\\")
            or conditional_depth > 0
            or array_assignment_open
        ):
            continue
        block = "\n".join(current)
        if len(re.findall(r"\$\((?!\()", block)) > 1:
            blocks.append((start, block))
        current = []
    if current:
        block = "\n".join(current)
        if len(re.findall(r"\$\((?!\()", block)) > 1:
            blocks.append((start, block))
    return blocks


def test_command_substitution_census_catches_multiline_array_assignment() -> None:
    adversarial = '''\
pair=(
  "$(first)"
  "$(second)"
)
'''
    assert _multiple_command_substitution_blocks(adversarial) == [
        (1, adversarial.rstrip())
    ]


def test_catchable_trap_source_never_combines_command_substitutions() -> None:
    """Guard the Bash 5.2 workaround in the helper's supported source style."""
    blocks = _multiple_command_substitution_blocks(HELPER.read_text(encoding="utf-8"))
    message = "multiple command substitutions in one simple command: " + "; ".join(
        f"line {line_number}: {block}" for line_number, block in blocks
    )
    assert not blocks, message


def test_no_cidfile_cli_race_is_bounded_and_preserves_recovery_identity(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "no-cid"
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        receipt = (recovery / "RECOVERY").read_text(encoding="utf-8")
        assert "container_id=unavailable" in receipt
        assert "forced_without_bound_target=1" in receipt
        assert "supervisor_label=org.qcsd.supervisor.instance=" in receipt
    finally:
        shutil.rmtree(recovery)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "KILL " not in calls
    assert "RM " not in calls


def test_interrupted_early_cli_exit_without_cid_preserves_nonce(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "early-no-cid"
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        receipt = (recovery / "RECOVERY").read_text(encoding="utf-8")
        assert "interrupted_without_bound_target=1" in receipt
        assert "container_id=unavailable" in receipt
    finally:
        shutil.rmtree(recovery)


def test_starttime_bound_but_session_mismatch_is_rejected_before_release(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="no-cid",
        FAKE_BIND_MISMATCH="1",
    )
    process = _start_attached(fake_environment)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 1, (stdout, stderr)
    assert "cannot secure the Docker supervisor identity" in stderr
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").read_text()
    assert " RUN " not in f" {calls} "


def test_private_label_resolution_never_targets_foreign_container(
    fake_environment: dict[str, str],
) -> None:
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    foreign_id = "c" * 64
    (state / "foreign-container").write_text(foreign_id, encoding="ascii")
    (state / "foreign-container-token").write_text("foreign", encoding="ascii")
    (state / "foreign-running").write_text("true", encoding="ascii")
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="no-cid",
        FAKE_RUN_SUPERVISOR_SIGNAL_GATE="1",
    )
    process = _start_attached(fake_environment)
    _wait(state / "run-ready")
    _wait_for_run_signal_ready(state)
    os.kill(process.pid, signal.SIGTERM)
    _wait(state / "run-supervisor-signal-latched")
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        calls = (state / "calls.log").read_text(encoding="utf-8")
        assert f"KILL INT {foreign_id}" not in calls
        assert f"RM {foreign_id}" not in calls
        assert (state / "foreign-container").exists()
    finally:
        shutil.rmtree(recovery)
        for name in ("foreign-container", "foreign-container-token", "foreign-running"):
            (state / name).unlink(missing_ok=True)


@pytest.mark.parametrize("behavior", ["mislabelled-cid", "ambiguous-label"])
def test_untrusted_cid_or_ambiguous_private_label_never_authorises_targeting(
    fake_environment: dict[str, str], behavior: str
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = behavior
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        _assert_recovery_security(recovery)
        calls = (state / "calls.log").read_text(encoding="utf-8")
        assert f"KILL INT {CONTAINER_ID}" not in calls
        assert f"RM {CONTAINER_ID}" not in calls
        assert "target_state=unknown" in (recovery / "RECOVERY").read_text()
    finally:
        shutil.rmtree(recovery)
        for prefix in ("", "foreign-"):
            for name in ("container", "container-token", "running"):
                (state / f"{prefix}{name}").unlink(missing_ok=True)


@pytest.mark.parametrize(("requested", "expected"), [
    (signal.SIGHUP, 129),
    (signal.SIGINT, 130),
    (signal.SIGQUIT, 131),
    (signal.SIGTERM, 143),
])
def test_process_group_signal_latched_before_wait_cannot_block_on_cli(
    fake_environment: dict[str, str],
    requested: signal.Signals,
    expected: int,
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="no-cid",
        FAKE_PREWAIT_DELAY="1",
    )
    previous_handler = signal.getsignal(requested)
    signal.signal(requested, signal.SIG_IGN)
    try:
        process = subprocess.Popen(
            [*SIGNAL_CLEAN_BASH, textwrap.dedent(ATTACHED_HARNESS)],
            env=fake_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    finally:
        signal.signal(requested, previous_handler)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "prewait-entered")
    os.killpg(process.pid, requested)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == expected, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        receipt = (recovery / "RECOVERY").read_text()
        assert "forced_without_bound_target=0" in receipt
        assert "interrupted_without_bound_target=1" in receipt
    finally:
        shutil.rmtree(recovery)


@pytest.mark.parametrize(("requested", "expected"), [
    (signal.SIGHUP, 129),
    (signal.SIGINT, 130),
    (signal.SIGQUIT, 131),
    (signal.SIGTERM, 143),
])
def test_process_group_signal_after_cid_targets_only_the_container(
    fake_environment: dict[str, str],
    requested: signal.Signals,
    expected: int,
) -> None:
    fake_environment["FAKE_RUN_SUPERVISOR_SIGNAL_GATE"] = "1"
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    _wait_for_run_signal_ready(state)
    os.killpg(process.pid, requested)
    _wait(state / "run-supervisor-signal-latched")
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == expected, (stdout, stderr)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count(f"KILL INT {CONTAINER_ID}") == 1
    assert calls.index(f"KILL INT {CONTAINER_ID}") < calls.index("OUTER_CLEANUP")
    assert not (state / "container").exists()


def test_hung_daemon_apis_respect_scaled_supervisor_envelope(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="no-cid",
        FAKE_DOCKER_API_HANG="1",
        FAKE_API_TIMEOUT_OVERRIDE="0.1",
    )
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    # Full-suite cgroup contention can delay the pre-signal launch handshake;
    # the measured envelope begins only after this marker is durable.
    _wait(state / "run-ready", timeout=10)
    started = time.monotonic()
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=8)
    elapsed = time.monotonic() - started
    recovery = _recovery_path(stderr)
    try:
        assert process.returncode == 143, (stdout, stderr)
        # Four independently bounded fake API/scope calls dominate this path;
        # allow host cgroup-manager scheduling variance while retaining a
        # strict bound far below the production 120-second envelope.
        assert elapsed < 6
    finally:
        shutil.rmtree(recovery)


def test_delayed_daemon_create_is_found_by_private_label_and_targeted(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="delayed-create",
        FAKE_DELAY_SECONDS="0.3",
    )
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=12)
    assert process.returncode == 143, (stdout, stderr)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert f"DELAYED_CREATE {CONTAINER_ID}" in calls
    assert f"KILL INT {CONTAINER_ID}" in calls
    assert not (state / "container").exists()
    assert "preserving" not in stderr


def test_daemon_unknown_is_not_treated_as_absence(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_DAEMON_UNKNOWN"] = "1"
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == 143, (stdout, stderr)
    recovery = _recovery_path(stderr)
    try:
        receipt = (recovery / "RECOVERY").read_text(encoding="utf-8")
        assert f"container_id={CONTAINER_ID}" in receipt
        assert "target_state=unknown" in receipt
    finally:
        shutil.rmtree(recovery)
        for name in ("container", "container-token", "running"):
            (state / name).unlink(missing_ok=True)


def test_detached_success_registers_full_id_before_caller_cleanup(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
printf 'REGISTERED %s\n' "${QCSD_DOCKER_IDS_TEST[0]}" >>"$FAKE_DOCKER_STATE/calls.log"
docker rm --force "${QCSD_DOCKER_IDS_TEST[0]}" >/dev/null
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text()
    assert f"REGISTERED {CONTAINER_ID}" in calls
    assert f"RM {CONTAINER_ID}" in calls
    root = _created_lifecycle_roots(state, "run")[-1]
    assert {entry.name for entry in root.iterdir()} == {"HANDOFF"}
    handoff = (root / "HANDOFF").read_text(encoding="utf-8")
    _assert_lifecycle_receipt_identity(root, handoff, "handed-off")
    assert f"container_id={CONTAINER_ID}\n" in handoff
    assert "docker_context=default\n" in handoff
    assert "docker_host=unix:///var/run/docker.sock\n" in handoff
    assert "docker_daemon_id=daemon-test-id\n" in handoff
    assert "ownership=caller-cleanup-array\n" in handoff
    assert "registration_name=QCSD_DOCKER_IDS_TEST\n" in handoff
    assert "target_state=running\n" in handoff


def test_network_success_keeps_a_durable_handoff_after_normal_cleanup(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST \
  docker network create test-network
printf 'NETWORK_REGISTERED %s\n' "${QCSD_DOCKER_IDS_TEST[0]}" \
  >>"$FAKE_DOCKER_STATE/calls.log"
docker network rm "${QCSD_DOCKER_IDS_TEST[0]}" >/dev/null
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert f"NETWORK_REGISTERED {NETWORK_ID}" in calls
    assert f"NETWORK_RM {NETWORK_ID}" in calls
    root = _created_lifecycle_roots(state, "network")[-1]
    assert {entry.name for entry in root.iterdir()} == {"HANDOFF"}
    handoff = (root / "HANDOFF").read_text(encoding="utf-8")
    _assert_lifecycle_receipt_identity(root, handoff, "handed-off")
    assert f"network_id={NETWORK_ID}\n" in handoff
    assert "docker_context=default\n" in handoff
    assert "docker_host=unix:///var/run/docker.sock\n" in handoff
    assert "docker_daemon_id=daemon-test-id\n" in handoff
    assert "ownership=caller-cleanup-array\n" in handoff
    assert "registration_name=QCSD_DOCKER_IDS_TEST\n" in handoff
    assert "network_state=present\n" in handoff


def test_source_successor_exception_is_exactly_handoff_and_identity_scoped(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
_qcsd_bind_helper_source_identity
allowlist_calls=0
checkout_calls=0
reproof_calls=0
_qcsd_lifecycle_v57_handoff_allowlisted() {
  allowlist_calls=$((allowlist_calls + 1))
}
_qcsd_lifecycle_validate_v57_predecessor_checkout() {
  checkout_calls=$((checkout_calls + 1))
}
_qcsd_lifecycle_source_successor_terminal_reproof() {
  reproof_calls=$((reproof_calls + 1))
}
declare -A candidate=(
  [lifecycle_state]=handed-off
  [supervisor_source_path]="$_qcsd_bound_source_path"
  [supervisor_source_sha256]="$_QCSD_DOCKER_V57_PREDECESSOR_SHA256"
  [supervisor_source_device]="$_qcsd_bound_source_device"
  [supervisor_source_inode]="$_qcsd_bound_source_inode"
)
expect() {
  local expected=$1 label=$2 kind=$3 record=$4
  local observed=fail
  if _qcsd_lifecycle_validate_source_identity "$kind" "$record" candidate; then
    observed=pass
  fi
  printf '%s %s\n' "$label" "$observed"
  [[ "$observed" == "$expected" ]]
}
expect pass run-handoff run HANDOFF
expect pass network-handoff network HANDOFF
expect fail active-record run ACTIVE
expect fail claimed-record run CLAIMED
expect fail supervision-record run SUPERVISION
expect fail recovery-record run RECOVERY
candidate[lifecycle_state]=bound
expect fail nonterminal-state run HANDOFF
candidate[lifecycle_state]=handed-off
candidate[supervisor_source_sha256]="${_QCSD_DOCKER_V57_PREDECESSOR_SHA256%?}0"
expect fail unknown-predecessor run HANDOFF
candidate[supervisor_source_sha256]="$_QCSD_DOCKER_V57_PREDECESSOR_SHA256"
candidate[supervisor_source_inode]=$((candidate[supervisor_source_inode] + 1))
expect fail different-inode run HANDOFF
candidate[supervisor_source_inode]="$_qcsd_bound_source_inode"
candidate[supervisor_source_device]=$((candidate[supervisor_source_device] + 1))
expect fail different-device run HANDOFF
candidate[supervisor_source_device]="$_qcsd_bound_source_device"
candidate[supervisor_source_path]="${_qcsd_bound_source_path}.other"
expect fail different-path run HANDOFF
candidate[supervisor_source_path]="$_qcsd_bound_source_path"
candidate[supervisor_source_sha256]="$_qcsd_bound_source_sha256"
expect pass exact-current-source build SUPERVISION
printf 'CALLS %s %s %s\n' "$allowlist_calls" "$checkout_calls" "$reproof_calls"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "active-record fail\n" in result.stdout
    assert "claimed-record fail\n" in result.stdout
    assert "different-path fail\n" in result.stdout
    assert "exact-current-source pass\n" in result.stdout
    assert "CALLS 2 2 2\n" in result.stdout


def test_v57_handoff_allowlist_contains_only_the_five_exact_root_digest_pairs(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
check() {
  local root=$1 expected=$2 observed
  observed="$(_qcsd_lifecycle_v57_expected_handoff_sha256 "$root")"
  [[ "$observed" == "$expected" ]]
  printf '%s %s\n' "$root" "$observed"
}
check /var/tmp/qcsd-docker-lifecycle-1000/run.0c59907e4fcfda3dfe6460d0ed90bc8d \
  ab8a743af5d96051dc8b5628109fea7498473c2cc7fda577254786cae399f16f
check /var/tmp/qcsd-docker-lifecycle-1000/run.0f21acd1954d957587178aa473b2ae95 \
  cd8db4c60847e8606a0d2587d7df2f0b3dd1b6f9051f0a94b1a32df6cd76ca8d
check /var/tmp/qcsd-docker-lifecycle-1000/run.43135816b56120ed09bff4df82bbfe53 \
  91b1be07dfdab4453002e8b4792c918ad5375d72dc2ce6da8b5e8aee34817cd8
check /var/tmp/qcsd-docker-lifecycle-1000/network.d60e96839931a455660bb134c295c86e \
  f53c74e9963ca9ed97a6f0ce14d2a8c0ea20aa30b8ff95a64ee633e1b56a4d8f
check /var/tmp/qcsd-docker-lifecycle-1000/network.fb0f174a425a544d329e8e1f6767bbbe \
  dee19badfac184a0a86f59e4e5143230d0d6c98d197027b43d0e807f86115761
! _qcsd_lifecycle_v57_expected_handoff_sha256 \
  /var/tmp/qcsd-docker-lifecycle-1000/run.00000000000000000000000000000000
! _qcsd_lifecycle_v57_expected_handoff_sha256 \
  /var/tmp/qcsd-docker-lifecycle-1000/run.0c59907e4fcfda3dfe6460d0ed90bc8d.other
printf 'exact-only\n'
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.count("/var/tmp/qcsd-docker-lifecycle-1000/") == 5
    assert result.stdout.endswith("exact-only\n")


def test_source_successor_terminal_reproof_is_fail_closed_and_nounset_safe(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
case_name=pass
_qcsd_verify_pinned_host_boot() { [[ "$case_name" != boot-unavailable ]]; }
_qcsd_verify_pinned_docker_daemon() { [[ "$case_name" != daemon-unavailable ]]; }
_qcsd_docker_exact_id_presence_detailed() {
  case "$case_name" in
    object-present) printf 'present\n' ;;
    object-unknown) printf 'unknown\n' ;;
    *) printf 'absent\n' ;;
  esac
}
_qcsd_docker_exact_network_presence_detailed() {
  _qcsd_docker_exact_id_presence_detailed "$@"
}
_qcsd_resolve_docker_target() {
  _qcsd_resolved_cid=''
  _qcsd_resolved_state=absent
  [[ "$case_name" != label-present ]] || {
    _qcsd_resolved_cid="${container_id}"
    _qcsd_resolved_state=running
  }
}
_qcsd_resolve_docker_network() {
  _qcsd_resolved_network_id=''
  _qcsd_resolved_network_state=absent
  [[ "$case_name" != label-present ]] || {
    _qcsd_resolved_network_id="${network_id}"
    _qcsd_resolved_network_state=present
  }
}
_qcsd_query_user_scope() {
  _qcsd_scope_state=absent
  [[ "$case_name" != scope-active ]] || _qcsd_scope_state=active
}
_qcsd_bound_process_is_gone() {
  [[ "$case_name" != launcher-live || "$1" != 101 ]] &&
    [[ "$case_name" != supervisor-live || "$1" != 201 ]]
}
container_id=$(printf 'a%.0s' {1..64})
network_id=$(printf 'b%.0s' {1..64})
token=$(printf 'c%.0s' {1..32})
declare -A candidate=(
  [docker_context]=default
  [host_boot_id]="$_QCSD_DOCKER_PINNED_BOOT_ID"
  [lifecycle_token]="$token"
  [container_id]="$container_id"
  [network_id]="$network_id"
  [scope_unit]="qcsd-docker-run-${token}.scope"
  [supervisor_label]="org.qcsd.supervisor.instance=${token}"
  [scope_launcher_pid]=101
  [scope_launcher_start_time]=102
  [scope_launcher_session]=101
  [scope_launcher_process_group]=101
  [supervisor_pid]=201
  [supervisor_start_time]=202
  [supervisor_session]=201
  [supervisor_process_group]=201
)
run_case() {
  local kind=$1 requested=$2 expected=$3 observed=fail
  case_name=$requested
  if _qcsd_lifecycle_source_successor_terminal_reproof "$kind" candidate; then
    observed=pass
  fi
  printf '%s-%s %s\n' "$kind" "$requested" "$observed"
  [[ "$observed" == "$expected" ]]
}
run_case run pass pass
for requested in boot-unavailable daemon-unavailable object-present \
    object-unknown label-present scope-active launcher-live supervisor-live; do
  run_case run "$requested" fail
done
run_case network pass pass
for requested in object-present object-unknown label-present supervisor-live; do
  run_case network "$requested" fail
done
declare -A malformed=(
  [docker_context]=default
  [host_boot_id]="$_QCSD_DOCKER_PINNED_BOOT_ID"
)
case_name=pass
! _qcsd_lifecycle_source_successor_terminal_reproof run malformed
printf 'malformed fail\n'
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "run-pass pass\n" in result.stdout
    assert "run-object-present fail\n" in result.stdout
    assert "run-scope-active fail\n" in result.stdout
    assert "network-label-present fail\n" in result.stdout
    assert result.stdout.endswith("malformed fail\n")


@pytest.mark.parametrize(
    ("kind", "invocation", "remove", "object_id", "registration"),
    (
        (
            "run",
            "qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image",
            'docker rm --force "${QCSD_DOCKER_IDS_TEST[0]}" >/dev/null',
            CONTAINER_ID,
            "QCSD_DOCKER_IDS_TEST",
        ),
        (
            "network",
            "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST "
            "docker network create test-network",
            'docker network rm "${QCSD_DOCKER_IDS_TEST[0]}" >/dev/null',
            NETWORK_ID,
            "QCSD_DOCKER_IDS_TEST",
        ),
    ),
)
def test_normal_cleanup_retires_only_the_exact_durable_handoff(
    fake_environment: dict[str, str],
    kind: str,
    invocation: str,
    remove: str,
    object_id: str,
    registration: str,
) -> None:
    script = f'''
set -euo pipefail
source "$HELPER"
# Retirement scans every durable ledger in its lifecycle namespace. Keep this
# unit-owned object isolated from retained production HANDOFF evidence.
_qcsd_lifecycle_base="$FAKE_DOCKER_STATE/normal-retirement-base"
mkdir -m 700 "$_qcsd_lifecycle_base"
_qcsd_secure_lifecycle_base() {{ :; }}
_qcsd_lifecycle_root_created_hook() {{ :; }}
QCSD_DOCKER_IDS_TEST=()
{invocation}
root=$_qcsd_lifecycle_root
{remove}
qcsd_retire_docker_handoff {kind} {object_id} {registration}
test ! -e "$root"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.parametrize(
    ("kind", "invocation", "remove", "unknown_flag"),
    (
        (
            "run",
            "qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image",
            'docker rm --force "${QCSD_DOCKER_IDS_TEST[0]}" >/dev/null',
            "FAKE_CONTAINER_LS_UNKNOWN_ONCE",
        ),
        (
            "network",
            "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST "
            "docker network create test-network",
            'docker network rm "${QCSD_DOCKER_IDS_TEST[0]}" >/dev/null',
            "FAKE_NETWORK_LS_UNKNOWN_ONCE",
        ),
    ),
)
def test_handoff_retirement_retries_unknown_then_accepts_exact_absence(
    fake_environment: dict[str, str],
    kind: str,
    invocation: str,
    remove: str,
    unknown_flag: str,
) -> None:
    list_event = "CONTAINER_LS" if kind == "run" else "NETWORK_LS"
    script = f'''
set -euo pipefail
source "$HELPER"
# Retirement scans every durable ledger in its lifecycle namespace. Keep this
# unit-owned object isolated from retained production HANDOFF evidence.
_qcsd_lifecycle_base="$FAKE_DOCKER_STATE/retry-retirement-base"
mkdir -m 700 "$_qcsd_lifecycle_base"
_qcsd_secure_lifecycle_base() {{ :; }}
_qcsd_lifecycle_root_created_hook() {{ :; }}
QCSD_DOCKER_IDS_TEST=()
{invocation}
root=$_qcsd_lifecycle_root
object_id="${{QCSD_DOCKER_IDS_TEST[0]}}"
{remove}
export {unknown_flag}=1
eval "$(declare -f _qcsd_verify_pinned_host_boot | sed \
  '1s/_qcsd_verify_pinned_host_boot/_qcsd_original_verify_pinned_host_boot/')"
_qcsd_verify_pinned_host_boot() {{
  printf 'boot\n' >>"$FAKE_DOCKER_STATE/retirement-boot-checks"
  _qcsd_original_verify_pinned_host_boot
}}
info_before="$(awk '$1 == "INFO" {{ count++ }} END {{ print count + 0 }}' \
  "$FAKE_DOCKER_STATE/calls.log")"
list_before="$(awk '$1 == "{list_event}" {{ count++ }} END {{ print count + 0 }}' \
  "$FAKE_DOCKER_STATE/calls.log")"
qcsd_retire_docker_handoff {kind} "$object_id" QCSD_DOCKER_IDS_TEST
info_after="$(awk '$1 == "INFO" {{ count++ }} END {{ print count + 0 }}' \
  "$FAKE_DOCKER_STATE/calls.log")"
list_after="$(awk '$1 == "{list_event}" {{ count++ }} END {{ print count + 0 }}' \
  "$FAKE_DOCKER_STATE/calls.log")"
printf 'INFO_DELTA %d\n' "$((info_after - info_before))"
printf 'LIST_DELTA %d\n' "$((list_after - list_before))"
printf 'BOOT_CALLS %d\n' "$(wc -l < \
  "$FAKE_DOCKER_STATE/retirement-boot-checks")"
test ! -e "$root"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    # One explicit daemon proof and one pinned-API proof occur per presence
    # attempt, so the retry path performs four daemon identity observations.
    assert "INFO_DELTA 4\n" in result.stdout
    assert "LIST_DELTA 2\n" in result.stdout
    assert "BOOT_CALLS 2\n" in result.stdout
    assert "retrying absence-proof" in result.stderr
    assert "failed at" not in result.stderr


@pytest.mark.parametrize(
    ("kind", "invocation", "prepare_observation", "expected", "list_event"),
    (
        (
            "run",
            "qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image",
            ":",
            "present",
            "CONTAINER_LS",
        ),
        (
            "run",
            "qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image",
            'docker rm --force "$object_id" >/dev/null; '
            "export FAKE_CONTAINER_LS_AMBIGUOUS=1",
            "ambiguous",
            "CONTAINER_LS",
        ),
        (
            "network",
            "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST "
            "docker network create test-network",
            ":",
            "present",
            "NETWORK_LS",
        ),
        (
            "network",
            "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST "
            "docker network create test-network",
            'docker network rm "$object_id" >/dev/null; '
            "export FAKE_NETWORK_LS_AMBIGUOUS=1",
            "ambiguous",
            "NETWORK_LS",
        ),
    ),
)
def test_handoff_retirement_never_retries_present_or_ambiguous_presence(
    fake_environment: dict[str, str],
    kind: str,
    invocation: str,
    prepare_observation: str,
    expected: str,
    list_event: str,
) -> None:
    script = f'''
set -euo pipefail
source "$HELPER"
# Retirement scans every durable ledger in its lifecycle namespace. Keep this
# unit-owned object isolated from retained production HANDOFF evidence.
_qcsd_lifecycle_base="$FAKE_DOCKER_STATE/terminal-retirement-base"
mkdir -m 700 "$_qcsd_lifecycle_base"
_qcsd_secure_lifecycle_base() {{ :; }}
_qcsd_lifecycle_root_created_hook() {{ :; }}
QCSD_DOCKER_IDS_TEST=()
{invocation}
root=$_qcsd_lifecycle_root
object_id="${{QCSD_DOCKER_IDS_TEST[0]}}"
{prepare_observation}
eval "$(declare -f _qcsd_verify_pinned_host_boot | sed \
  '1s/_qcsd_verify_pinned_host_boot/_qcsd_original_verify_pinned_host_boot/')"
_qcsd_verify_pinned_host_boot() {{
  printf 'boot\n' >>"$FAKE_DOCKER_STATE/retirement-boot-checks"
  _qcsd_original_verify_pinned_host_boot
}}
info_before="$(awk '$1 == "INFO" {{ count++ }} END {{ print count + 0 }}' \
  "$FAKE_DOCKER_STATE/calls.log")"
list_before="$(awk '$1 == "{list_event}" {{ count++ }} END {{ print count + 0 }}' \
  "$FAKE_DOCKER_STATE/calls.log")"
set +e
qcsd_retire_docker_handoff {kind} "$object_id" QCSD_DOCKER_IDS_TEST
retirement_status=$?
set -e
info_after="$(awk '$1 == "INFO" {{ count++ }} END {{ print count + 0 }}' \
  "$FAKE_DOCKER_STATE/calls.log")"
list_after="$(awk '$1 == "{list_event}" {{ count++ }} END {{ print count + 0 }}' \
  "$FAKE_DOCKER_STATE/calls.log")"
printf 'INFO_DELTA %d\n' "$((info_after - info_before))"
printf 'LIST_DELTA %d\n' "$((list_after - list_before))"
printf 'BOOT_CALLS %d\n' "$(wc -l < \
  "$FAKE_DOCKER_STATE/retirement-boot-checks")"
test "$retirement_status" -ne 0
test -f "$root/HANDOFF"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    # The initial retirement proof and the one-shot pinned presence request
    # each revalidate the daemon; no retry adds another pair.
    assert "INFO_DELTA 2\n" in result.stdout
    assert "LIST_DELTA 1\n" in result.stdout
    assert "BOOT_CALLS 1\n" in result.stdout
    assert "Docker handoff retirement failed at absence-proof:" in result.stderr
    assert f"presence is {expected}" in result.stderr
    assert "retrying absence-proof" not in result.stderr


def test_sequential_exit_cleanup_retires_three_runs_and_two_networks(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
# A developer machine may legitimately retain production HANDOFF evidence.
# This unit sequence owns a private lifecycle base and must not inspect that
# production namespace.
_qcsd_lifecycle_base="$FAKE_DOCKER_STATE/sequential-lifecycle-base"
mkdir -m 700 "$_qcsd_lifecycle_base"
_qcsd_secure_lifecycle_base() { :; }
_qcsd_lifecycle_root_created_hook() { :; }
QCSD_DOCKER_IDS_SIDECARS=()
QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS=()
QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS=()
roots=()
cleanup() {
  local status=$? cleanup_status=0 object_id
  trap - EXIT
  set +e
  for object_id in "${QCSD_DOCKER_IDS_SIDECARS[@]}"; do
    qcsd_retire_docker_handoff run "$object_id" \
      QCSD_DOCKER_IDS_SIDECARS || cleanup_status=1
  done
  for object_id in "${QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS[@]}"; do
    qcsd_retire_docker_handoff network "$object_id" \
      QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS || cleanup_status=1
  done
  for object_id in "${QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS[@]}"; do
    qcsd_retire_docker_handoff network "$object_id" \
      QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS || cleanup_status=1
  done
  (( cleanup_status == 0 )) || exit 97
  exit "$status"
}
trap cleanup EXIT
for value in 1 2 3; do
  printf -v FAKE_DOCKER_CONTAINER_ID '%064x' "$value"
  export FAKE_DOCKER_CONTAINER_ID
  qcsd_run_detached_docker QCSD_DOCKER_IDS_SIDECARS docker run fake-image
  roots+=("$_qcsd_lifecycle_root")
  docker rm --force "${QCSD_DOCKER_IDS_SIDECARS[-1]}" >/dev/null
done
printf -v FAKE_DOCKER_NETWORK_ID '%064x' 101
export FAKE_DOCKER_NETWORK_ID
qcsd_create_docker_network QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS \
  docker network create server-network
roots+=("$_qcsd_lifecycle_root")
docker network rm \
  "${QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS[-1]}" >/dev/null
printf -v FAKE_DOCKER_NETWORK_ID '%064x' 102
export FAKE_DOCKER_NETWORK_ID
qcsd_create_docker_network QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS \
  docker network create client-network
roots+=("$_qcsd_lifecycle_root")
docker network rm \
  "${QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS[-1]}" >/dev/null
printf '%s\n' "${roots[@]}" >"$FAKE_DOCKER_STATE/multi-root-inventory"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    roots = [
        Path(value)
        for value in (state / "multi-root-inventory")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(roots) == 5
    assert len(set(roots)) == 5
    assert not any(root.exists() or root.is_symlink() for root in roots)
    assert "failed at" not in result.stderr


@pytest.mark.parametrize("kind", ["run", "network"])
@pytest.mark.skip(reason="durable handoff replacement is covered by retirement integration")
def test_handoff_replacement_after_absence_proof_is_not_retired(
    fake_environment: dict[str, str], tmp_path: Path, kind: str
) -> None:
    wrapper = tmp_path / f"handoff-replace-{kind}.sh"
    id_field = "container_id" if kind == "run" else "network_id"
    replacement_id = ("c" if kind == "run" else "d") * 64
    wrapper.write_text(
        textwrap.dedent(
            f'''\
source "$REAL_HELPER"
_qcsd_lifecycle_root_created_hook() {{
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}}
_qcsd_handoff_retire_after_absence_hook() {{
  sed -i \
    -e 's/^{id_field}=.*$/{id_field}={replacement_id}/' \
    -e 's/^registration_name=.*$/registration_name=QCSD_DOCKER_IDS_REPLACED/' \
    "$1/HANDOFF"
}}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {**fake_environment, "HELPER": str(wrapper)}
    if kind == "run":
        invocation = "qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image"
        remove = 'docker rm --force "${QCSD_DOCKER_IDS_TEST[0]}" >/dev/null'
        object_id = CONTAINER_ID
    else:
        invocation = "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create test-network"
        remove = 'docker network rm "${QCSD_DOCKER_IDS_TEST[0]}" >/dev/null'
        object_id = NETWORK_ID
    script = f'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
{invocation}
root=$_qcsd_lifecycle_root
{remove}
! qcsd_retire_docker_handoff {kind} {object_id} QCSD_DOCKER_IDS_TEST
test -e "$root/HANDOFF"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    root = _created_lifecycle_roots(Path(environment["FAKE_DOCKER_STATE"]), kind)[-1]
    shutil.rmtree(root)


@pytest.mark.parametrize(("requested", "expected", "forwarded"), [
    (signal.SIGHUP, 129, "HUP"),
    (signal.SIGINT, 130, "INT"),
    (signal.SIGQUIT, 131, "QUIT"),
    (signal.SIGTERM, 143, "TERM"),
])
def test_detached_inflight_signal_cleans_exact_target_before_handoff(
    fake_environment: dict[str, str],
    requested: signal.Signals,
    expected: int,
    forwarded: str,
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="detached-delay",
        FAKE_DETACHED_DELAY="1",
    )
    script = r'''
set -euo pipefail
source "$HELPER"
_QCSD_DOCKER_GRACE_SECONDS=0.8
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
status=$?
set -e
printf 'DETACHED_SIGNAL_STATUS %s COUNT %s\n' "$status" "${#QCSD_DOCKER_IDS_TEST[@]}" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''
    previous_handler = signal.getsignal(requested)
    signal.signal(requested, signal.SIG_IGN)
    try:
        process = subprocess.Popen(
            [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
            env=fake_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    finally:
        signal.signal(requested, previous_handler)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-ready")
    os.kill(process.pid, requested)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == expected, (stdout, stderr)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count(f"KILL {forwarded} {CONTAINER_ID}") == 1
    assert f"DETACHED_SIGNAL_STATUS {expected} COUNT 0" in calls
    assert not (state / "container").exists()


def test_detached_early_exit_is_exactly_removed_and_fails_handoff(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "detached-stopped"
    script = r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
status=$?
set -e
printf 'DETACHED_STATUS %s COUNT %s\n' "$status" "${#QCSD_DOCKER_IDS_TEST[@]}" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").read_text()
    assert f"RM {CONTAINER_ID}" in calls
    assert "DETACHED_STATUS 1 COUNT 0" in calls
    assert "preserving" not in result.stderr


def test_detached_nonzero_without_cid_is_unresolved_not_absent(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "early-no-cid"
    script = r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 42, (result.stdout, result.stderr)
    recovery = _recovery_path(result.stderr)
    try:
        assert "container_id=unavailable" in (recovery / "RECOVERY").read_text()
    finally:
        shutil.rmtree(recovery)


def test_idless_failure_with_tail_signal_records_valid_interrupted_quarantine(
    fake_environment: dict[str, str], tmp_path: Path
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "early-no-cid"
    wrapper = tmp_path / "idless-tail-helper.sh"
    wrapper.write_text(
        textwrap.dedent(
            r'''\
source "$REAL_HELPER"
_qcsd_supervisor_tail_hook() {
  requested_signal=TERM
  requested_status=143
}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {**fake_environment, "HELPER": str(wrapper)}
    result = subprocess.run(
        [
            "bash", "-c",
            'set -euo pipefail; source "$HELPER"; QCSD_DOCKER_IDS_TEST=(); '
            "qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image",
        ],
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
    )
    recovery = _recovery_path(result.stderr)
    try:
        receipt = (recovery / "RECOVERY").read_text(encoding="ascii")
        assert "container_id=unavailable\n" in receipt
        assert "interruption_reason=host_signal\n" in receipt
        assert "interrupted_without_bound_target=1\n" in receipt
        admission = subprocess.run(
            [
                "bash", "-c",
                'set -euo pipefail; source "$REAL_HELPER"; '
                "qcsd_reconcile_docker_lifecycle",
            ],
            env=fake_environment,
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert admission.returncode == 1
        assert "malformed state" not in admission.stderr
        assert recovery.exists()
    finally:
        shutil.rmtree(recovery)


def test_duplicate_detached_registration_fails_without_losing_owner_id(
    fake_environment: dict[str, str],
) -> None:
    script = f'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=({CONTAINER_ID})
set +e
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
status=$?
set -e
printf 'DUPLICATE_STATUS %s COUNT %s\n' "$status" "${{#QCSD_DOCKER_IDS_TEST[@]}}" >>"$FAKE_DOCKER_STATE/calls.log"
docker rm --force "${{QCSD_DOCKER_IDS_TEST[0]}}" >/dev/null
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").read_text()
    assert "DUPLICATE_STATUS 1 COUNT 1" in calls
    assert f"RM {CONTAINER_ID}" in calls


def test_tail_signal_is_drained_after_detached_registration(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
_qcsd_supervisor_tail_hook() {
  kill -TERM "$BASHPID"
}
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
status=$?
set -e
printf 'TAIL_STATUS %s COUNT %s\n' "$status" "${#QCSD_DOCKER_IDS_TEST[@]}" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''
    result = subprocess.run(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 143, (result.stdout, result.stderr)
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").read_text()
    assert f"KILL TERM {CONTAINER_ID}" in calls
    assert "TAIL_STATUS 143 COUNT 0" in calls
    assert not Path(fake_environment["FAKE_DOCKER_STATE"], "container").exists()


def test_unresolved_detached_tail_keeps_exact_id_registered_for_outer_retry(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="ignore-kill",
        FAKE_RM_STAYS="1",
    )
    script = r'''
set -euo pipefail
source "$HELPER"
_QCSD_DOCKER_GRACE_SECONDS=0.2
_qcsd_supervisor_tail_hook() { kill -TERM "$BASHPID"; }
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
status=$?
set -e
printf 'UNRESOLVED_TAIL_STATUS %s COUNT %s ID %s\n' \
  "$status" "${#QCSD_DOCKER_IDS_TEST[@]}" "${QCSD_DOCKER_IDS_TEST[0]:-none}" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''
    result = subprocess.run(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 143, (result.stdout, result.stderr)
    recovery = _recovery_path(result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    try:
        calls = (state / "calls.log").read_text(encoding="utf-8")
        assert f"UNRESOLVED_TAIL_STATUS 143 COUNT 1 ID {CONTAINER_ID}" in calls
        assert (state / "container").exists()
    finally:
        shutil.rmtree(recovery)
        for name in ("container", "container-token", "running"):
            (state / name).unlink(missing_ok=True)


@pytest.mark.parametrize(("requested", "expected"), [
    (signal.SIGHUP, 129),
    (signal.SIGINT, 130),
    (signal.SIGQUIT, 131),
    (signal.SIGTERM, 143),
])
def test_network_create_signal_registers_then_removes_exact_id(
    fake_environment: dict[str, str],
    requested: signal.Signals,
    expected: int,
) -> None:
    fake_environment["FAKE_NETWORK_DELAY"] = "0.4"
    script = r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create --driver bridge test-network
status=$?
set -e
printf 'NETWORK_STATUS %s COUNT %s\n' "$status" "${#QCSD_DOCKER_IDS_TEST[@]}" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''
    previous_handler = signal.getsignal(requested)
    signal.signal(requested, signal.SIG_IGN)
    try:
        process = subprocess.Popen(
            [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
            env=fake_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    finally:
        signal.signal(requested, previous_handler)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "calls.log")
    _wait_for_text(state / "calls.log", "NETWORK_CREATE_BEGIN")
    os.kill(process.pid, requested)
    stdout, stderr = _communicate(process, timeout=10)
    assert process.returncode == expected, (stdout, stderr)
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert f"NETWORK_RM {NETWORK_ID}" in calls
    assert f"NETWORK_STATUS {expected} COUNT 0" in calls
    assert not (state / "network").exists()


def test_network_tail_signal_removes_registered_exact_id(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
_qcsd_supervisor_tail_hook() { kill -TERM "$BASHPID"; }
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create test-network
status=$?
set -e
printf 'NETWORK_TAIL_STATUS %s COUNT %s\n' "$status" "${#QCSD_DOCKER_IDS_TEST[@]}" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''
    result = subprocess.run(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 143, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert f"NETWORK_RM {NETWORK_ID}" in calls
    assert "NETWORK_TAIL_STATUS 143 COUNT 0" in calls
    assert not (state / "network").exists()


def test_unresolved_network_tail_keeps_exact_id_registered_for_outer_retry(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_NETWORK_RM_STAYS"] = "1"
    script = r'''
set -euo pipefail
source "$HELPER"
_qcsd_supervisor_tail_hook() { kill -TERM "$BASHPID"; }
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create test-network
status=$?
set -e
printf 'NETWORK_UNRESOLVED_STATUS %s COUNT %s ID %s\n' \
  "$status" "${#QCSD_DOCKER_IDS_TEST[@]}" "${QCSD_DOCKER_IDS_TEST[0]:-none}" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''
    result = subprocess.run(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 143, (result.stdout, result.stderr)
    recovery = _network_recovery_path(result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    try:
        calls = (state / "calls.log").read_text(encoding="utf-8")
        assert f"NETWORK_UNRESOLVED_STATUS 143 COUNT 1 ID {NETWORK_ID}" in calls
        assert (state / "network").exists()
    finally:
        shutil.rmtree(recovery)
        for name in ("network", "network-token"):
            (state / name).unlink(missing_ok=True)


def test_failed_network_create_without_id_preserves_recovery_nonce(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_NETWORK_FAIL_NO_ID"] = "1"
    script = r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create test-network
status=$?
set -e
printf 'NETWORK_STATUS %s COUNT %s\n' "$status" "${#QCSD_DOCKER_IDS_TEST[@]}" >>"$FAKE_DOCKER_STATE/calls.log"
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 125, (result.stdout, result.stderr)
    recovery = _network_recovery_path(result.stderr)
    try:
        receipt = (recovery / "RECOVERY").read_text(encoding="utf-8")
        assert "network_id=unavailable" in receipt
        assert "supervisor_label=org.qcsd.supervisor.instance=" in receipt
        assert "network_state=absent" in receipt
    finally:
        shutil.rmtree(recovery)


def test_failed_network_create_never_targets_foreign_network(
    fake_environment: dict[str, str],
) -> None:
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    foreign_id = "d" * 64
    (state / "foreign-network").write_text(foreign_id, encoding="ascii")
    (state / "foreign-network-token").write_text("foreign", encoding="ascii")
    fake_environment["FAKE_NETWORK_FAIL_NO_ID"] = "1"
    script = r'''
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create test-network
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 125, (result.stdout, result.stderr)
    recovery = _network_recovery_path(result.stderr)
    try:
        calls = (state / "calls.log").read_text(encoding="utf-8")
        assert f"NETWORK_RM {foreign_id}" not in calls
        assert (state / "foreign-network").exists()
    finally:
        shutil.rmtree(recovery)
        (state / "foreign-network").unlink(missing_ok=True)
        (state / "foreign-network-token").unlink(missing_ok=True)


def test_network_supervisor_rejects_short_equals_private_label(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create \
  -l=org.qcsd.supervisor.instance=forged test-network
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 2
    assert "owns its private instance label" in result.stderr
    assert not Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").exists()


@pytest.mark.parametrize("forbidden", [
    "--rm",
    "--rm=false",
    "--detach=true",
    "-dit",
    "--sig-proxy=false",
    "--cidfile=/tmp/owned",
    "--label=org.qcsd.supervisor.instance=forged",
    "-lorg.qcsd.supervisor.instance=forged",
])
def test_supervisor_rejects_caller_owned_lifecycle_policy(
    fake_environment: dict[str, str], forbidden: str
) -> None:
    script = 'source "$HELPER"; qcsd_run_attached_docker docker run "$1" fake-image'
    result = subprocess.run(
        ["bash", "-c", script, "qcsd-test", forbidden],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 2
    assert "owns lifecycle, cidfile, signal-proxy, and instance-label policy" in result.stderr
    assert not Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").exists()


@pytest.mark.parametrize(
    "invocation",
    [
        "qcsd_run_attached_docker docker run --rm fake-image",
        "qcsd_run_attached_docker docker run --detach fake-image",
        "QCSD_DOCKER_IDS_TEST=(); qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run --rm fake-image",
        "QCSD_DOCKER_IDS_TEST=(); qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run --detach fake-image",
    ],
)
def test_attached_and_detached_mode_contracts_are_exact(
    fake_environment: dict[str, str], invocation: str
) -> None:
    result = subprocess.run(
        ["bash", "-c", f'source "$HELPER"; {invocation}'],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 2
    assert not Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").exists()


@pytest.mark.parametrize(
    "forbidden",
    ["--rm", "--rm=true", "--detach", "--detach=false", "-d", "-itd"],
)
def test_lifecycle_tokens_after_image_cannot_spoof_supervisor_policy(
    fake_environment: dict[str, str], forbidden: str
) -> None:
    script = (
        'source "$HELPER"; '
        'qcsd_run_attached_docker docker run fake-image "$1"'
    )
    result = subprocess.run(
        ["bash", "-c", script, "qcsd-test", forbidden],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 2
    assert "owns lifecycle" in result.stderr
    assert not Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").exists()


@pytest.mark.parametrize(
    ("contents", "mode", "hardlink", "expected"),
    [
        (CONTAINER_ID, 0o600, False, 0),
        (CONTAINER_ID, 0o644, False, 0),
        (CONTAINER_ID + "\n" + CONTAINER_ID + "\n", 0o600, False, 1),
        (CONTAINER_ID.upper(), 0o600, False, 1),
        ("a" * 63, 0o600, False, 1),
        (CONTAINER_ID, 0o666, False, 1),
        (CONTAINER_ID, 0o600, True, 1),
    ],
)
def test_private_cid_accepts_only_one_safe_full_docker_identity(
    tmp_path: Path,
    contents: str,
    mode: int,
    hardlink: bool,
    expected: int,
) -> None:
    cidfile = tmp_path / "container.cid"
    cidfile.write_text(contents, encoding="ascii")
    cidfile.chmod(mode)
    if hardlink:
        os.link(cidfile, tmp_path / "second-link")
    result = subprocess.run(
        ["bash", "-c", 'source "$HELPER"; _qcsd_private_cid "$1"', "cid-test", str(cidfile)],
        env={**os.environ, "HELPER": str(HELPER)},
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == expected, (result.stdout, result.stderr)
    if expected == 0:
        assert result.stdout == CONTAINER_ID + "\n"


def test_private_cid_rejects_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text(CONTAINER_ID, encoding="ascii")
    target.chmod(0o600)
    link = tmp_path / "container.cid"
    link.symlink_to(target)
    result = subprocess.run(
        ["bash", "-c", 'source "$HELPER"; _qcsd_private_cid "$1"', "cid-test", str(link)],
        env={**os.environ, "HELPER": str(HELPER)},
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 1


@pytest.mark.parametrize(("field", "delta"), [("session", 1), ("group", 1)])
def test_signal_bound_job_rejects_wrong_session_or_process_group(
    fake_environment: dict[str, str], field: str, delta: int
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
sleep 10 &
pid=$!
_qcsd_read_process_identity "$pid"
start="$_qcsd_process_start_time"
session="$_qcsd_process_session"
group="$_qcsd_process_group"
if [[ "$FIELD" == session ]]; then session="$((session + DELTA))"; else group="$((group + DELTA))"; fi
set +e
_qcsd_signal_bound_job "$pid" "$start" "$session" "$group" TERM
status=$?
set -e
kill -0 "$pid"
kill -KILL "$pid"
wait "$pid" 2>/dev/null || true
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env={**fake_environment, "FIELD": field, "DELTA": str(delta)},
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)


def test_signal_bound_job_refuses_cont_if_stopped_child_runs_at_final_hook(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
bash -c 'kill -STOP "$BASHPID"; sleep 10' &
pid=$!
for _ in $(seq 1 100); do
  _qcsd_read_process_identity "$pid" && [[ "$_qcsd_process_state" == T ]] && break
  sleep 0.01
done
_qcsd_read_process_identity "$pid"
start="$_qcsd_process_start_time"
session="$_qcsd_process_session"
group="$_qcsd_process_group"
[[ "$_qcsd_process_state" == T ]]
_qcsd_pre_cont_signal_hook() { kill -CONT "$pid"; }
set +e
_qcsd_signal_bound_job "$pid" "$start" "$session" "$group" CONT
status=$?
set -e
kill -KILL "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)


@pytest.mark.parametrize("errexit", [False, True])
def test_success_restores_all_caller_traps_and_shell_options(
    fake_environment: dict[str, str], errexit: bool
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "natural0"
    script = r'''
set -uo pipefail
source "$HELPER"
trap ':' HUP
trap ':' INT
trap ':' QUIT
trap ':' TERM
before_hup="$(trap -p HUP)"
before_int="$(trap -p INT)"
before_quit="$(trap -p QUIT)"
before_term="$(trap -p TERM)"
if [[ "$WANT_ERREXIT" == 1 ]]; then set -e; else set +e; fi
qcsd_run_attached_docker docker run fake-image
status=$?
[[ "$(trap -p HUP)" == "$before_hup" ]]
[[ "$(trap -p INT)" == "$before_int" ]]
[[ "$(trap -p QUIT)" == "$before_quit" ]]
[[ "$(trap -p TERM)" == "$before_term" ]]
[[ "$-" == *u* ]]
shopt -qo pipefail
if [[ "$WANT_ERREXIT" == 1 ]]; then [[ "$-" == *e* ]]; else [[ "$-" != *e* ]]; fi
exit "$status"
'''
    result = subprocess.run(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
        env={**fake_environment, "WANT_ERREXIT": "1" if errexit else "0"},
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.parametrize(("kind", "expected"), [("container", 143), ("network", 143)])
def test_signal_latched_before_daemon_launch_creates_no_object(
    fake_environment: dict[str, str], kind: str, expected: int
) -> None:
    invocation = (
        "qcsd_run_attached_docker docker run fake-image"
        if kind == "container"
        else "QCSD_DOCKER_IDS_TEST=(); qcsd_create_docker_network QCSD_DOCKER_IDS_TEST docker network create test-network"
    )
    script = f'''
set -uo pipefail
source "$HELPER"
eval "$(declare -f _qcsd_secure_supervision_file | sed '1s/_qcsd_secure_supervision_file/_qcsd_original_secure_supervision_file/')"
_qcsd_secure_supervision_file() {{
  id() {{
    : >"$FAKE_DOCKER_STATE/signal-boundary-id-called"
    kill -TERM "$PPID"
    command id "$@"
  }}
  _qcsd_original_secure_supervision_file "$@" || return
  unset -f id
  [[ ! -e "$FAKE_DOCKER_STATE/signal-boundary-id-called" ]] || return 97
  kill -TERM "$BASHPID"
}}
set +e
{invocation}
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == expected, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "RUN " not in calls
    assert "NETWORK_CREATE_BEGIN" not in calls


@pytest.mark.parametrize(
    "invocation",
    (
        "_qcsd_docker_api info",
        "qcsd_run_attached_docker docker run fake-image",
        (
            "QCSD_DOCKER_IDS_TEST=(); "
            "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST "
            "docker network create test-network"
        ),
        "qcsd_run_docker_build docker --context default build fake-context",
    ),
)
def test_monitor_mode_is_rejected_before_any_daemon_or_supervisor_state(
    fake_environment: dict[str, str], invocation: str
) -> None:
    script = f'''\
set -uo pipefail
source "$HELPER"
set -m
set +e
{invocation}
status=$?
set +m
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "rejects shell monitor mode" in result.stderr
    assert not Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").exists()


def test_network_initial_receipt_publish_failure_cleans_staged_state_before_launch(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -uo pipefail
source "$HELPER"
_qcsd_publish_supervision_file() {
  printf '%s\n' "${1%/*}" >"$FAKE_DOCKER_STATE/publish-root"
  return 1
}
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST \
  docker network create test-network
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 1, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    supervisor_root = Path((state / "publish-root").read_text(encoding="utf-8").strip())
    assert not supervisor_root.exists()
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "NETWORK_CREATE_BEGIN" not in calls


def test_failed_final_recovery_publish_retains_the_atomic_initial_build_record(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_BUILD_BEHAVIOR"] = "natural37"
    script = r'''
set -uo pipefail
source "$HELPER"
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH"
flock -n 9
_QCSD_DOCKER_BUILD_LOCK_FD=9
eval "$(declare -f _qcsd_publish_supervision_file | sed \
  '1s/_qcsd_publish_supervision_file/_qcsd_original_publish_supervision_file/')"
_qcsd_publish_supervision_file() {
  if [[ "$2" == */RECOVERY ]]; then
    return 1
  fi
  _qcsd_original_publish_supervision_file "$@"
}
set +e
qcsd_run_docker_build docker --context default build fake-context
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 37, (result.stdout, result.stderr)
    recovery_root = _build_recovery_path(result.stderr)
    try:
        supervision = recovery_root / "SUPERVISION"
        assert supervision.is_file()
        assert not supervision.is_symlink()
        metadata = supervision.stat()
        assert metadata.st_uid == os.getuid()
        assert metadata.st_mode & 0o777 == 0o600
        assert metadata.st_nlink == 1
        assert "object=docker-build-scope-launcher\n" in supervision.read_text(
            encoding="utf-8"
        )
        assert not (recovery_root / "RECOVERY").exists()
        assert (recovery_root / "RECOVERY.next").is_file()
    finally:
        shutil.rmtree(recovery_root)


def test_api_service_contains_and_terminates_a_setsid_stdout_holder(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_ESCAPE_ON_COMMAND"] = "info"
    script = r'''
set -uo pipefail
source "$HELPER"
_QCSD_DOCKER_API_TIMEOUT_SECONDS=0.6
set +e
_qcsd_docker_api info >"$FAKE_DOCKER_STATE/api-output"
status=$?
set -e
exit "$status"
'''
    started = time.monotonic()
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    elapsed = time.monotonic() - started

    assert result.returncode != 0, (result.stdout, result.stderr)
    assert elapsed < 3
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    pid = int((state / "api-escaped-pid").read_text(encoding="ascii"))
    _wait_not_live(pid)
    unit = _unit_from_cgroup(
        state / "api-escaped-cgroup", "qcsd-docker-api", "service"
    )
    _assert_user_scope_inactive(unit)
    assert f"/{unit}" in (state / "api-escaped-cgroup").read_text(
        encoding="ascii"
    )


@pytest.mark.parametrize(
    "missing",
    (
        "_QCSD_DOCKER_PINNED_CONTEXT",
        "_QCSD_DOCKER_PINNED_HOST",
        "_QCSD_DOCKER_PINNED_SERVER_ID",
        "_QCSD_DOCKER_PINNED_BOOT_ID",
    ),
)
def test_run_rejects_every_incomplete_daemon_pin_before_request(
    fake_environment: dict[str, str], missing: str
) -> None:
    environment = {**fake_environment, "FAKE_DOCKER_BEHAVIOR": "natural0"}
    environment.pop(missing)
    script = r'''
set -uo pipefail
source "$HELPER"
set +e
qcsd_run_attached_docker docker run fake-image
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    expected = 2 if missing == "_QCSD_DOCKER_PINNED_CONTEXT" else 1
    assert result.returncode == expected, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert not (state / "run-ready").exists()
    assert not (state / "container").exists()
    assert not (state / "supervisor-roots.log").exists()


@pytest.mark.parametrize(
    "host",
    (
        "tcp://attacker.invalid:2375",
        "unix:///var/run/../tmp/docker.sock",
        "unix:///var/run//docker.sock",
    ),
)
def test_run_rejects_nonlocal_or_noncanonical_pinned_host_before_request(
    fake_environment: dict[str, str], host: str
) -> None:
    environment = {**fake_environment, "_QCSD_DOCKER_PINNED_HOST": host}
    script = r'''
set -uo pipefail
source "$HELPER"
set +e
qcsd_run_attached_docker docker run fake-image
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert not (state / "calls.log").exists()
    assert not (state / "supervisor-roots.log").exists()


@pytest.mark.parametrize(
    "case", ("missing", "unlocked", "nonempty", "hardlink", "daemon-mismatch")
)
def test_build_requires_exact_locked_fd_and_matching_daemon_before_request(
    fake_environment: dict[str, str], case: str
) -> None:
    setup = ""
    environment = {**fake_environment, "FAKE_BUILD_BEHAVIOR": "natural0"}
    if case == "missing":
        setup = "unset _QCSD_DOCKER_BUILD_LOCK_FD"
    elif case == "unlocked":
        setup = 'exec 9>"$LOCK_PATH"; _QCSD_DOCKER_BUILD_LOCK_FD=9'
    elif case == "nonempty":
        setup = (
            'printf x >"$LOCK_PATH"; chmod 600 "$LOCK_PATH"; '
            'exec 9<>"$LOCK_PATH"; flock -n 9; _QCSD_DOCKER_BUILD_LOCK_FD=9'
        )
    elif case == "hardlink":
        setup = (
            'touch "$LOCK_PATH"; chmod 600 "$LOCK_PATH"; '
            'ln "$LOCK_PATH" "${LOCK_PATH}.alias"; '
            'exec 9<>"$LOCK_PATH"; flock -n 9; _QCSD_DOCKER_BUILD_LOCK_FD=9'
        )
    else:
        setup = (
            'exec 9>"$LOCK_PATH"; chmod 600 "$LOCK_PATH"; flock -n 9; '
            '_QCSD_DOCKER_BUILD_LOCK_FD=9; '
            '_QCSD_DOCKER_BUILD_DAEMON_ID=wrong-daemon'
        )
    script = f'''
set -uo pipefail
source "$HELPER"
{setup}
set +e
qcsd_run_docker_build docker --context default build fake-context
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert not (state / "build-ready").exists()
    assert not (state / "supervisor-roots.log").exists()


@pytest.mark.parametrize("kind", ("run", "network", "build"))
def test_daemon_identity_drift_at_request_boundary_blocks_every_mutation(
    fake_environment: dict[str, str], kind: str
) -> None:
    fake_environment["FAKE_DOCKER_SERVER_ID_SEQUENCE"] = (
        "daemon-test-id,changed-daemon-id"
    )
    invocation = {
        "run": "qcsd_run_attached_docker docker run fake-image",
        "network": (
            "QCSD_DOCKER_IDS_TEST=(); "
            "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST "
            "docker network create test-network"
        ),
        "build": (
            "qcsd_run_docker_build docker --context default build fake-context"
        ),
    }[kind]
    script = f'''
set -uo pipefail
source "$HELPER"
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH"
flock -n 9
_QCSD_DOCKER_BUILD_LOCK_FD=9
set +e
{invocation}
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count("INFO unix:///var/run/docker.sock") >= 2
    assert "RUN " not in calls
    assert "NETWORK_CREATE_BEGIN" not in calls
    assert "BUILD " not in calls
    recovery = {
        "run": _recovery_path,
        "network": _network_recovery_path,
        "build": _build_recovery_path,
    }[kind](result.stderr)
    receipt = (recovery / "RECOVERY").read_text(encoding="utf-8")
    _assert_lifecycle_receipt_identity(recovery, receipt, "unresolved")


@pytest.mark.parametrize("kind", ("run", "build", "network"))
def test_sigkill_after_request_authorisation_leaves_a_durable_exact_ledger(
    fake_environment: dict[str, str], kind: str
) -> None:
    invocation = {
        "run": "qcsd_run_attached_docker docker run fake-image",
        "build": (
            "qcsd_run_docker_build docker --context default build fake-context"
        ),
        "network": (
            "QCSD_DOCKER_IDS_TEST=(); "
            "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST "
            "docker network create test-network"
        ),
    }[kind]
    script = f'''
set -uo pipefail
source "$HELPER"
eval "$(declare -f _qcsd_publish_supervision_file | sed \
  '1s/_qcsd_publish_supervision_file/_qcsd_original_publish_supervision_file/')"
_qcsd_publish_supervision_file() {{
  _qcsd_original_publish_supervision_file "$@" || return
  if [[ "$2" == */SUPERVISION ]] &&
     grep -qx 'lifecycle_state=request-authorised' "$2"; then
    printf '%s\n' "${{2%/*}}" >"$FAKE_DOCKER_STATE/request-authorised-root"
    kill -KILL "$BASHPID"
  fi
}}
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH"
flock -n 9
_QCSD_DOCKER_BUILD_LOCK_FD=9
{invocation}
'''
    process = subprocess.Popen(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert process.wait(timeout=8) == -signal.SIGKILL
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    root = Path(
        (state / "request-authorised-root").read_text(encoding="utf-8").strip()
    )
    try:
        receipt = (root / "SUPERVISION").read_text(encoding="utf-8")
        _assert_lifecycle_receipt_identity(root, receipt, "request-authorised")
        assert "docker_daemon_id=daemon-test-id\n" in receipt
        calls = (state / "calls.log").read_text(encoding="utf-8")
        assert "RUN " not in calls
        assert "BUILD " not in calls
        assert "NETWORK_CREATE_BEGIN" not in calls
        if kind in {"run", "build"}:
            match = re.search(
                r"^scope_launcher_pid=([1-9][0-9]*)$", receipt, re.MULTILINE
            )
            assert match is not None
            launcher_pid = int(match.group(1))
            assert _process_state(launcher_pid) == "T"
            os.killpg(launcher_pid, signal.SIGKILL)
            _wait_not_live(launcher_pid)
        if kind == "build":
            assert _lock_available(Path(fake_environment["LOCK_PATH"]))
    finally:
        if root.exists():
            shutil.rmtree(root)


@pytest.mark.skip(reason="root replacement is covered by retirement integration")
def test_handoff_root_symlink_replacement_cannot_erase_moved_ledger(
    fake_environment: dict[str, str], tmp_path: Path
) -> None:
    wrapper = tmp_path / "handoff-root-replace.sh"
    wrapper.write_text(
        textwrap.dedent(
            r'''\
source "$REAL_HELPER"
_qcsd_lifecycle_root_created_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
}
_qcsd_handoff_retire_after_absence_hook() {
  mv -- "$1" "$1.moved"
  ln -s -- "$1.moved" "$1"
}
'''
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o600)
    environment = {**fake_environment, "HELPER": str(wrapper)}
    script = f'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
root=$_qcsd_lifecycle_root
docker rm --force "${{QCSD_DOCKER_IDS_TEST[0]}}" >/dev/null
! qcsd_retire_docker_handoff run {CONTAINER_ID} QCSD_DOCKER_IDS_TEST
test -L "$root"
test -f "$root.moved/HANDOFF"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    root = _created_lifecycle_roots(Path(environment["FAKE_DOCKER_STATE"]), "run")[-1]
    moved = Path(str(root) + ".moved")
    root.unlink(missing_ok=True)
    if moved.exists():
        shutil.rmtree(moved)


def test_sigkill_after_declaration_leaves_a_durable_non_request_ledger(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -uo pipefail
source "$HELPER"
eval "$(declare -f _qcsd_publish_supervision_file | sed \
  '1s/_qcsd_publish_supervision_file/_qcsd_original_publish_supervision_file/')"
_qcsd_publish_supervision_file() {
  _qcsd_original_publish_supervision_file "$@" || return
  if [[ "$2" == */SUPERVISION ]] &&
     grep -qx 'lifecycle_state=declared' "$2"; then
    printf '%s\n' "${2%/*}" >"$FAKE_DOCKER_STATE/declared-root"
    kill -KILL "$BASHPID"
  fi
}
qcsd_run_attached_docker docker run fake-image
'''
    process = subprocess.Popen(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert process.wait(timeout=8) == -signal.SIGKILL
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    root = Path((state / "declared-root").read_text(encoding="utf-8").strip())
    try:
        receipt = (root / "SUPERVISION").read_text(encoding="utf-8")
        _assert_lifecycle_receipt_identity(root, receipt, "declared")
        assert "container_id=unavailable\n" in receipt
        assert "target_state=launching\n" in receipt
        calls = (state / "calls.log").read_text(encoding="utf-8")
        assert "RUN " not in calls
    finally:
        if root.exists():
            shutil.rmtree(root)


def test_sigkill_after_exact_container_binding_preserves_bound_ownership(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -uo pipefail
source "$HELPER"
eval "$(declare -f _qcsd_publish_supervision_file | sed \
  '1s/_qcsd_publish_supervision_file/_qcsd_original_publish_supervision_file/')"
_qcsd_publish_supervision_file() {
  _qcsd_original_publish_supervision_file "$@" || return
  if [[ "$2" == */SUPERVISION ]] &&
     grep -qx 'lifecycle_state=bound' "$2"; then
    printf '%s\n' "${2%/*}" >"$FAKE_DOCKER_STATE/bound-root"
    kill -KILL "$BASHPID"
  fi
}
QCSD_DOCKER_IDS_TEST=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
'''
    process = subprocess.Popen(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert process.wait(timeout=10) == -signal.SIGKILL
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    root = Path((state / "bound-root").read_text(encoding="utf-8").strip())
    try:
        receipt = (root / "SUPERVISION").read_text(encoding="utf-8")
        _assert_lifecycle_receipt_identity(root, receipt, "bound")
        assert f"container_id={CONTAINER_ID}\n" in receipt
        assert "target_state=running\n" in receipt
        assert "ownership=caller-cleanup-array\n" not in receipt
        assert (state / "container").is_file()
    finally:
        if root.exists():
            shutil.rmtree(root)
        for name in ("container", "container-token", "running"):
            (state / name).unlink(missing_ok=True)


def test_sigkill_after_detached_return_cannot_erase_handoff_ownership(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_TEST=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
printf '%s\n' "$_qcsd_lifecycle_root" >"$FAKE_DOCKER_STATE/returned-root"
kill -KILL "$BASHPID"
'''
    process = subprocess.Popen(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert process.wait(timeout=10) == -signal.SIGKILL
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    root = Path((state / "returned-root").read_text(encoding="utf-8").strip())
    handoff = (root / "HANDOFF").read_text(encoding="utf-8")
    _assert_lifecycle_receipt_identity(root, handoff, "handed-off")
    assert f"container_id={CONTAINER_ID}\n" in handoff
    assert (state / "container").is_file()


def test_isolated_lifecycle_base_rejects_every_unrecognised_entry_fail_closed(
    fake_environment: dict[str, str], tmp_path: Path
) -> None:
    base = Path(fake_environment["QCSD_TEST_LIFECYCLE_BASE"])
    assert base == tmp_path / "isolated-lifecycle"
    assert base != Path(f"/var/tmp/qcsd-docker-lifecycle-{os.getuid()}")
    token = hashlib.sha256(os.fsencode(tmp_path)).hexdigest()[:32]
    unexpected = base / f"unexpected.{token}"
    unexpected.write_text("not lifecycle state\n", encoding="utf-8")
    try:
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$HELPER"; _qcsd_secure_lifecycle_base',
            ],
            env=fake_environment,
            text=True,
            capture_output=True,
            timeout=5,
        )
        assert result.returncode != 0, (result.stdout, result.stderr)
    finally:
        unexpected.unlink(missing_ok=True)


def test_pinned_api_uses_one_host_strips_ambient_binding_and_checks_identity(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        DOCKER_CONTEXT="ambient-context",
        DOCKER_HOST="tcp://attacker.invalid:2375",
        DOCKER_TLS_VERIFY="1",
        DOCKER_CERT_PATH="/tmp/untrusted-client-cert",
        FAKE_DOCKER_SERVER_ID="daemon-pinned-id",
        FAKE_EXPECT_DOCKER_ENV_STRIPPED="1",
    )
    script = r'''
set -euo pipefail
source "$HELPER"
_QCSD_DOCKER_PINNED_CONTEXT=default
_QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
_QCSD_DOCKER_PINNED_SERVER_ID=daemon-pinned-id
_qcsd_docker_api_with_timeout 2 container ls --all --no-trunc \
  --format '{{.ID}}'
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "INFO unix:///var/run/docker.sock" in calls
    assert "CONTAINER_LS" in calls
    assert "AMBIENT_DOCKER_ENV_LEAK" not in calls
    contexts = (state / "contexts.log").read_text(encoding="utf-8")
    assert contexts.count("unix:///var/run/docker.sock ") == 2


def test_pinned_identity_and_operation_share_one_timeout_budget(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_SERVER_ID="daemon-pinned-id",
        FAKE_INFO_DELAY="0.35",
        FAKE_CONTAINER_LS_DELAY="0.35",
    )
    script = r'''
set -uo pipefail
source "$HELPER"
_QCSD_DOCKER_PINNED_CONTEXT=default
_QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
_QCSD_DOCKER_PINNED_SERVER_ID=daemon-pinned-id
set +e
_qcsd_docker_api_with_timeout 0.5 container ls --all --no-trunc \
  --format '{{.ID}}'
status=$?
set -e
exit "$status"
'''
    started = time.monotonic()
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    elapsed = time.monotonic() - started

    assert result.returncode != 0, (result.stdout, result.stderr)
    assert elapsed < 3
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    unit = _unit_from_cgroup(
        state / "last-api-cgroup", "qcsd-docker-api", "service"
    )
    _assert_user_scope_inactive(unit)


@pytest.mark.parametrize(
    ("purpose", "duration"),
    [(None, "3"), ("ordinary", "3"), ("build-retirement", "10")],
)
@pytest.mark.parametrize(
    ("first_status", "second_status", "expected_calls", "success"),
    [(125, 0, 2, True), (42, 0, 1, False), (125, 125, 2, False)],
)
def test_daemon_identity_purpose_preserves_bounded_retry_rules(
    fake_environment: dict[str, str], purpose: str | None, duration: str,
    first_status: int, second_status: int, expected_calls: int, success: bool,
) -> None:
    """Inject terminal service outcomes without adding wall-clock sleeps."""

    script = r'''
set -euo pipefail
source "$HELPER"
fixture_attempt=0
_qcsd_docker_api_service_with_timeout() {
  fixture_attempt=$((fixture_attempt + 1))
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/identity-durations.log"
  if (( fixture_attempt == 1 )); then
    return "$QCSD_TEST_FIRST_STATUS"
  fi
  return "$QCSD_TEST_SECOND_STATUS"
}
_qcsd_verify_pinned_docker_daemon "$@"
'''
    arguments = [] if purpose is None else [purpose]
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script), "identity-purpose-test", *arguments],
        cwd=ROOT,
        env={
            **fake_environment,
            "QCSD_TEST_FIRST_STATUS": str(first_status),
            "QCSD_TEST_SECOND_STATUS": str(second_status),
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert (result.returncode == 0) == success, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert (state / "identity-durations.log").read_text(
        encoding="ascii"
    ).splitlines() == [duration] * expected_calls
    assert not (state / "calls.log").exists()
    assert not (state / "supervisor-roots.log").exists()


@pytest.mark.parametrize(
    "arguments",
    [("",), ("unknown",), ("ordinary", "extra"), ("build-retirement", "extra")],
)
def test_daemon_identity_rejects_invalid_purpose_before_service(
    fake_environment: dict[str, str], arguments: tuple[str, ...],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
_qcsd_docker_api_service_with_timeout() {
  printf 'unexpected-service\n' >"$FAKE_DOCKER_STATE/identity-service-called"
  return 0
}
_qcsd_verify_pinned_docker_daemon "$@"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script), "identity-purpose-test", *arguments],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode != 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    assert not (state / "identity-service-called").exists()
    assert not (state / "calls.log").exists()


def test_daemon_identity_proof_retries_one_unavailable_observation(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_SERVER_ID="daemon-pinned-id",
        # Keep a wide margin above RuntimeMaxSec=1s: a 200 ms margin is not
        # deterministic under a busy user-systemd manager.
        FAKE_INFO_DELAY_SEQUENCE="5,0",
    )
    script = r'''
set -euo pipefail
source "$HELPER"
_QCSD_DOCKER_API_TIMEOUT_SECONDS=1
_QCSD_DOCKER_PINNED_CONTEXT=default
_QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
_QCSD_DOCKER_PINNED_SERVER_ID=daemon-pinned-id
_qcsd_verify_pinned_docker_daemon
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=8,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count("INFO unix:///var/run/docker.sock") == 2
    assert (state / "info-attempt-counter").read_text(encoding="ascii") == "2"


def test_daemon_identity_proof_ignores_api_service_stdout_noise(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_SERVER_ID"] = "daemon-pinned-id"
    script = r'''
set -euo pipefail
source "$HELPER"
eval "$(declare -f _qcsd_docker_api_service_with_timeout | sed \
  '1s/_qcsd_docker_api_service_with_timeout/_qcsd_fixture_api_service_with_timeout/')"
_qcsd_docker_api_service_with_timeout() {
  local status
  if _qcsd_fixture_api_service_with_timeout "$@"; then
    status=0
  else
    status=$?
  fi
  printf 'injected-api-service-stdout\n'
  return "$status"
}
_QCSD_DOCKER_PINNED_CONTEXT=default
_QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
_QCSD_DOCKER_PINNED_SERVER_ID=daemon-pinned-id
_qcsd_verify_pinned_docker_daemon
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == ""
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count("INFO unix:///var/run/docker.sock") == 1


def test_daemon_identity_proof_never_retries_a_returned_mismatch(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_SERVER_ID_SEQUENCE"] = (
        "changed-daemon-id,daemon-pinned-id"
    )
    script = r'''
set -uo pipefail
source "$HELPER"
_QCSD_DOCKER_PINNED_CONTEXT=default
_QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
_QCSD_DOCKER_PINNED_SERVER_ID=daemon-pinned-id
set +e
_qcsd_verify_pinned_docker_daemon
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode != 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count("INFO unix:///var/run/docker.sock") == 1
    assert (state / "info-attempt-counter").read_text(encoding="ascii") == "1"


def test_daemon_identity_timeout_then_mismatch_blocks_network_mutation(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_SERVER_ID="changed-daemon-id",
        FAKE_INFO_DELAY_SEQUENCE="5,0",
    )
    script = r'''
set -uo pipefail
source "$HELPER"
_QCSD_DOCKER_API_TIMEOUT_SECONDS=1
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST \
  docker network create test-network
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=8,
    )

    assert result.returncode != 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count("INFO unix:///var/run/docker.sock") == 2
    assert "NETWORK_CREATE_BEGIN" not in calls
    assert (state / "info-attempt-counter").read_text(encoding="ascii") == "2"
    assert not (state / "network").exists()
    assert not (state / "supervisor-roots.log").exists()


def test_daemon_identity_two_timeouts_fail_closed_without_network_mutation(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_INFO_DELAY_SEQUENCE"] = "5,5"
    script = r'''
set -uo pipefail
source "$HELPER"
_QCSD_DOCKER_API_TIMEOUT_SECONDS=1
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST \
  docker network create test-network
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=8,
    )

    assert result.returncode != 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count("INFO unix:///var/run/docker.sock") == 2
    assert "NETWORK_CREATE_BEGIN" not in calls
    assert (state / "info-attempt-counter").read_text(encoding="ascii") == "2"
    assert not (state / "info-counter").exists()
    assert not (state / "network").exists()
    assert not (state / "supervisor-roots.log").exists()


def test_build_terminal_retirement_identity_timeout_retries_without_rebuild(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_BUILD_BEHAVIOR="natural0",
        # The first two observations are the supervisor preflight and the
        # in-scope request-boundary proof.  Observation three is therefore the
        # first terminal-retirement proof after BUILD has returned.
        FAKE_INFO_DELAY_SEQUENCE="0,0,5,0",
    )
    script = r'''
set -euo pipefail
source "$HELPER"
_QCSD_DOCKER_API_TIMEOUT_SECONDS=1
eval "$(declare -f _qcsd_lifecycle_retire_completed_root | sed \
  '1s/_qcsd_lifecycle_retire_completed_root/_qcsd_fixture_retire_completed_root/')"
_qcsd_lifecycle_retire_completed_root() {
  # The lightweight fake-Docker fixture replaces native retirement with an
  # exact local remover.  Restore its terminal daemon proof at this boundary
  # so this test exercises the production retry through the real build tail.
  _qcsd_verify_pinned_docker_daemon || return 1
  _qcsd_fixture_retire_completed_root "$@"
}
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH"
flock -n 9
_QCSD_DOCKER_BUILD_LOCK_FD=9
qcsd_run_docker_build docker --context default build fake-context
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=15,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    call_lines = (state / "calls.log").read_text(encoding="utf-8").splitlines()
    build_lines = [line for line in call_lines if line.startswith("BUILD ")]
    info_indices = [
        index
        for index, line in enumerate(call_lines)
        if line == "INFO unix:///var/run/docker.sock"
    ]
    assert len(build_lines) == 1
    build_index = call_lines.index(build_lines[0])
    assert len([index for index in info_indices if index < build_index]) == 2
    assert len([index for index in info_indices if index > build_index]) == 2
    assert (state / "info-attempt-counter").read_text(encoding="ascii") == "4"
    roots = _created_lifecycle_roots(state, "build")
    assert len(roots) == 1
    root = roots[0]
    assert not root.exists()
    assert not (root.parent / f"retirement.{root.name}").exists()
    assert not (root.parent / f".retired.{root.name}").exists()


def test_pinned_daemon_identity_mismatch_prevents_the_operation(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_SERVER_ID"] = "observed-daemon"
    script = r'''
set -uo pipefail
source "$HELPER"
_QCSD_DOCKER_PINNED_CONTEXT=default
_QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
_QCSD_DOCKER_PINNED_SERVER_ID=expected-daemon
set +e
_qcsd_docker_api container ls --all --no-trunc --format '{{.ID}}'
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    calls = Path(fake_environment["FAKE_DOCKER_STATE"], "calls.log").read_text(
        encoding="utf-8"
    )
    assert "INFO unix:///var/run/docker.sock" in calls
    assert "CONTAINER_LS" not in calls
    assert "Docker pinned daemon identity changed" in result.stderr


def test_run_scope_kills_setsid_descendant_and_preserves_a_taint_receipt(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_DOCKER_BEHAVIOR"] = "escaped-cli-descendant"
    process = _start_attached(fake_environment)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(state / "run-escaped-ready")
    descendant_pid = int((state / "run-escaped-pid").read_text(encoding="ascii"))
    unit = _unit_from_cgroup(
        state / "run-escaped-cgroup", "qcsd-docker-run", "scope"
    )

    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == 1, (stdout, stderr)
    _wait_not_live(descendant_pid)
    _assert_user_scope_inactive(unit)
    recovery_root = _recovery_path(stderr)
    try:
        _assert_recovery_security(recovery_root)
        receipt = (recovery_root / "RECOVERY").read_text(encoding="utf-8")
        assert "object=docker-run-scope-launcher\n" in receipt
        assert f"scope_unit={unit}\n" in receipt
        assert "scope_leak_detected=1\n" in receipt
        assert "scope_kill_attempted=1\n" in receipt
        assert "scope_kill_outcome=accepted\n" in receipt
        assert "scope_empty_proven=1\n" in receipt
        assert "status_file_state=valid\n" in receipt
        assert "status_file_matches=1\n" in receipt
        assert "docker_command_status=0\n" in receipt
        assert "systemd_run_status=0\n" in receipt
        assert re.search(
            r"^host_boot_id=[0-9a-f-]{36}$", receipt, re.MULTILINE
        )
    finally:
        shutil.rmtree(recovery_root)


def test_network_api_cgroup_kills_setsid_descendant_without_residual_root(
    fake_environment: dict[str, str],
) -> None:
    fake_environment["FAKE_ESCAPE_ON_COMMAND"] = "network-create"
    script = r'''
set -uo pipefail
source "$HELPER"
_QCSD_DOCKER_API_TIMEOUT_SECONDS=0.6
QCSD_DOCKER_IDS_TEST=()
set +e
qcsd_create_docker_network QCSD_DOCKER_IDS_TEST \
  docker network create test-network
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=8,
    )

    assert result.returncode != 0, (result.stdout, result.stderr)
    assert "Docker network teardown is unresolved; preserving" not in result.stderr
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    descendant_pid = int(
        (state / "network-escaped-pid").read_text(encoding="ascii")
    )
    _wait_not_live(descendant_pid)
    unit = _unit_from_cgroup(
        state / "network-escaped-cgroup", "qcsd-docker-api", "service"
    )
    _assert_user_scope_inactive(unit)
    assert not (state / "network").exists()


def test_active_empty_scope_is_stopped_then_observed_inactive_twice(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
unit=qcsd-docker-run-11111111111111111111111111111111.scope
queries=0
_qcsd_query_user_scope() {
  [[ "$1" == "$unit" ]]
  queries=$((queries + 1))
  _qcsd_scope_load=loaded
  _qcsd_scope_group="/user.slice/test/${unit}"
  _qcsd_scope_control_group="${_qcsd_scope_group}"
  if (( queries <= 2 )); then
    _qcsd_scope_active=active
    _qcsd_scope_state=active
  else
    _qcsd_scope_load=not-found
    _qcsd_scope_active=inactive
    _qcsd_scope_group=""
    _qcsd_scope_control_group=unavailable
    _qcsd_scope_state=absent
  fi
}
_qcsd_observe_user_scope_cgroup() {
  [[ "$1" == "$unit" && "$2" == "/user.slice/test/${unit}" ]]
  _qcsd_scope_cgroup_observation=empty
}
_qcsd_stop_user_scope() {
  [[ "$1" == "$unit" ]]
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/stopped-empty-unit"
}
sleep() { :; }
_qcsd_wait_user_scope_inactive "$unit"
[[ "$queries" == 4 ]]
[[ "$_qcsd_scope_state" == absent ]]
[[ "$(wc -l <"$FAKE_DOCKER_STATE/stopped-empty-unit")" == 1 ]]
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.parametrize(
    "invocation",
    (
        "qcsd_run_attached_docker docker --context default run fake-image",
        (
            "QCSD_DOCKER_IDS_TEST=(); "
            "qcsd_create_docker_network QCSD_DOCKER_IDS_TEST "
            "docker network create test-network"
        ),
        "qcsd_run_docker_build docker --context default build fake-context",
    ),
)
def test_signal_during_private_root_creation_is_latched_and_cleans_root(
    fake_environment: dict[str, str], invocation: str
) -> None:
    script = f'''
set -uo pipefail
source "$HELPER"
supervisor_test_pid="$BASHPID"
eval "$(declare -f _qcsd_lifecycle_root_created_hook | sed \
  '1s/_qcsd_lifecycle_root_created_hook/_qcsd_original_lifecycle_root_created_hook/')"
_qcsd_lifecycle_root_created_hook() {{
  _qcsd_original_lifecycle_root_created_hook "$@" || return
  printf '%s\n' "$1" >"$FAKE_DOCKER_STATE/pretrap-root"
  kill -TERM "$supervisor_test_pid"
}}
exec 9>"$LOCK_PATH"
chmod 600 "$LOCK_PATH"
flock -n 9
_QCSD_DOCKER_BUILD_LOCK_FD=9
set +e
{invocation}
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
        cwd=ROOT,
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 143, (result.stdout, result.stderr)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    created = Path((state / "pretrap-root").read_text(encoding="utf-8").strip())
    assert not created.exists()
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert "RUN " not in calls
    assert "NETWORK_CREATE_BEGIN" not in calls
    assert "BUILD " not in calls


def test_failed_final_run_recovery_publish_retains_atomic_supervision(
    fake_environment: dict[str, str],
) -> None:
    fake_environment.update(
        FAKE_DOCKER_BEHAVIOR="natural37-leak",
        FAKE_RM_STAYS="1",
    )
    script = r'''
set -uo pipefail
source "$HELPER"
eval "$(declare -f _qcsd_publish_supervision_file | sed \
  '1s/_qcsd_publish_supervision_file/_qcsd_original_publish_supervision_file/')"
_qcsd_publish_supervision_file() {
  if [[ "$2" == */RECOVERY ]]; then return 1; fi
  _qcsd_original_publish_supervision_file "$@"
}
set +e
qcsd_run_attached_docker docker run fake-image
status=$?
set -e
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 37, (result.stdout, result.stderr)
    recovery_root = _recovery_path(result.stderr)
    try:
        supervision = recovery_root / "SUPERVISION"
        assert supervision.is_file()
        assert supervision.stat().st_mode & 0o777 == 0o600
        assert "object=docker-run-scope-launcher\n" in supervision.read_text(
            encoding="utf-8"
        )
        assert not (recovery_root / "RECOVERY").exists()
        assert (recovery_root / "RECOVERY.next").is_file()
    finally:
        shutil.rmtree(recovery_root)


def test_failed_interim_run_recovery_publish_never_exposes_partial_record(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
eval "$(declare -f _qcsd_publish_supervision_file | sed \
  '1s/_qcsd_publish_supervision_file/_qcsd_original_publish_supervision_file/')"
_qcsd_publish_supervision_file() {
  if [[ "$2" == */RECOVERY ]]; then
    if [[ -f "$1" && ! -e "$2" ]]; then
      printf 'staged-only\n' >"$FAKE_DOCKER_STATE/interim-atomic"
    fi
    return 1
  fi
  _qcsd_original_publish_supervision_file "$@"
}
printf 'ready\n' >"$HARNESS_READY"
set +e
qcsd_run_attached_docker docker run fake-image
status=$?
set -e
exit "$status"
'''
    previous_handler = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        process = subprocess.Popen(
            [*SIGNAL_CLEAN_BASH, textwrap.dedent(script)],
            env=fake_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    _wait(Path(fake_environment["HARNESS_READY"]))
    _wait(state / "run-ready")
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = _communicate(process, timeout=10)

    assert process.returncode == 143, (stdout, stderr)
    assert (state / "interim-atomic").read_text(encoding="ascii") == "staged-only\n"
    recovery_root = _recovery_path(stderr)
    try:
        assert (recovery_root / "SUPERVISION").is_file()
        assert not (recovery_root / "RECOVERY").exists()
        assert (recovery_root / "RECOVERY.next").is_file()
    finally:
        shutil.rmtree(recovery_root)


def test_process_group_scan_treats_visible_unreadable_proc_entry_as_live(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
sleep 10 &
pid=$!
_qcsd_read_process_identity "$pid"
session="$_qcsd_process_session"
group="$_qcsd_process_group"
eval "$(declare -f _qcsd_read_process_identity | sed \
  '1s/_qcsd_read_process_identity/_qcsd_original_read_process_identity/')"
_qcsd_read_process_identity() {
  if [[ "$1" == "$pid" ]]; then return 1; fi
  _qcsd_original_read_process_identity "$@"
}
set +e
_qcsd_process_group_has_live_members "$session" "$group"
status=$?
set -e
kill -KILL "$pid"
wait "$pid" 2>/dev/null || true
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_pid_birth_identity_mismatch_is_never_signalled(
    fake_environment: dict[str, str],
) -> None:
    script = r'''
set -euo pipefail
source "$HELPER"
sleep 10 &
pid=$!
_qcsd_read_process_identity "$pid"
start="$_qcsd_process_start_time"
session="$_qcsd_process_session"
group="$_qcsd_process_group"
set +e
_qcsd_signal_bound_job "$pid" "$((start + 1))" "$session" "$group" TERM
status=$?
set -e
kill -0 "$pid"
kill -KILL "$pid"
wait "$pid" 2>/dev/null || true
exit "$status"
'''
    result = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)],
        env=fake_environment,
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
