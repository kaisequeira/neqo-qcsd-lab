from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import textwrap
import time
from types import ModuleType

import pytest

from tests.test_docker_signal_supervisor import FAKE_DOCKER


ROOT = Path(__file__).resolve().parents[1]
GUARDIAN = ROOT / "tools/docker_lifecycle_lock_guardian.py"
NATIVE = ROOT / "tools/docker_lifecycle_native.py"
HELPER = ROOT / "tools/docker_signal_supervisor.sh"


FAKE_QCSD = r'''#!/bin/bash
set -euo pipefail

state=$2
mkdir -p "$state"
printf '%s\n' "$$" >"$state/inner-pid"

lock_matches() {
  /usr/bin/python3 - "$1" <<'PY'
import os
from pathlib import Path
import sys

destination = Path(sys.argv[1])
wanted = (
    int(os.environ["QCSD_DOCKER_LOCK_GUARDIAN_LOCK_DEVICE"]),
    int(os.environ["QCSD_DOCKER_LOCK_GUARDIAN_LOCK_INODE"]),
)
matches = []
for candidate in Path("/proc/self/fd").iterdir():
    try:
        value = candidate.stat()
    except OSError:
        continue
    if (value.st_dev, value.st_ino) == wanted:
        matches.append(candidate.name)
destination.write_text(",".join(matches), encoding="ascii")
PY
}

ready() {
  local ready_fd=$QCSD_DOCKER_LOCK_GUARDIAN_READY_FD
  local go_fd=$QCSD_DOCKER_LOCK_GUARDIAN_GO_FD
  local admitted
  printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_NONCE" >&"$ready_fd"
  eval "exec ${ready_fd}>&-"
  IFS= read -r admitted <&"$go_fd"
  eval "exec ${go_fd}<&-"
  [[ "$admitted" == "$QCSD_DOCKER_LOCK_GUARDIAN_GO_NONCE" ]] || exit 125
}

load_real_helper_with_guardian_proof() {
  _QCSD_LIFECYCLE_BOOT_ID=$QCSD_DOCKER_LOCK_GUARDIAN_BOOT_ID
  _QCSD_LIFECYCLE_GUARD_SOURCE_PATH=$QCSD_DOCKER_LOCK_GUARDIAN_SOURCE_PATH
  _QCSD_LIFECYCLE_GUARD_SOURCE_DEVICE=$QCSD_DOCKER_LOCK_GUARDIAN_SOURCE_DEVICE
  _QCSD_LIFECYCLE_GUARD_SOURCE_INODE=$QCSD_DOCKER_LOCK_GUARDIAN_SOURCE_INODE
  _QCSD_LIFECYCLE_GUARD_SOURCE_SHA256=$QCSD_DOCKER_LOCK_GUARDIAN_SOURCE_SHA256
  _QCSD_LIFECYCLE_QCSD_SOURCE_PATH=$QCSD_DOCKER_LOCK_GUARDIAN_QCSD_SOURCE_PATH
  _QCSD_LIFECYCLE_QCSD_SOURCE_DEVICE=$QCSD_DOCKER_LOCK_GUARDIAN_QCSD_SOURCE_DEVICE
  _QCSD_LIFECYCLE_QCSD_SOURCE_INODE=$QCSD_DOCKER_LOCK_GUARDIAN_QCSD_SOURCE_INODE
  _QCSD_LIFECYCLE_QCSD_SOURCE_SHA256=$QCSD_DOCKER_LOCK_GUARDIAN_QCSD_SOURCE_SHA256
  _QCSD_LIFECYCLE_HELPER_SOURCE_PATH=$QCSD_DOCKER_LOCK_GUARDIAN_HELPER_SOURCE_PATH
  _QCSD_LIFECYCLE_HELPER_SOURCE_DEVICE=$QCSD_DOCKER_LOCK_GUARDIAN_HELPER_SOURCE_DEVICE
  _QCSD_LIFECYCLE_HELPER_SOURCE_INODE=$QCSD_DOCKER_LOCK_GUARDIAN_HELPER_SOURCE_INODE
  _QCSD_LIFECYCLE_HELPER_SHA256=$QCSD_DOCKER_LOCK_GUARDIAN_HELPER_SOURCE_SHA256
  _QCSD_LIFECYCLE_NATIVE_PATH=$QCSD_DOCKER_LOCK_GUARDIAN_NATIVE_SOURCE_PATH
  _QCSD_LIFECYCLE_NATIVE_SOURCE_DEVICE=$QCSD_DOCKER_LOCK_GUARDIAN_NATIVE_SOURCE_DEVICE
  _QCSD_LIFECYCLE_NATIVE_SOURCE_INODE=$QCSD_DOCKER_LOCK_GUARDIAN_NATIVE_SOURCE_INODE
  _QCSD_LIFECYCLE_NATIVE_SHA256=$QCSD_DOCKER_LOCK_GUARDIAN_NATIVE_SOURCE_SHA256
  _QCSD_LIFECYCLE_LEASE_SOCKET=$QCSD_DOCKER_LOCK_GUARDIAN_LEASE_SOCKET
  _QCSD_LIFECYCLE_LEASE_NONCE=$QCSD_DOCKER_LOCK_GUARDIAN_LEASE_NONCE
  _QCSD_LIFECYCLE_QCSD_PID=$QCSD_DOCKER_LOCK_GUARDIAN_INNER_PID
  _QCSD_LIFECYCLE_QCSD_START=$QCSD_DOCKER_LOCK_GUARDIAN_INNER_START_TIME
  _QCSD_LIFECYCLE_LOCK_PATH=$QCSD_DOCKER_LOCK_GUARDIAN_LOCK_PATH
  _QCSD_LIFECYCLE_LOCK_DEVICE=$QCSD_DOCKER_LOCK_GUARDIAN_LOCK_DEVICE
  _QCSD_LIFECYCLE_LOCK_INODE=$QCSD_DOCKER_LOCK_GUARDIAN_LOCK_INODE
  lock_parent=${_QCSD_LIFECYCLE_LOCK_PATH%/*}
  _QCSD_LIFECYCLE_LOCK_PARENT_DEVICE=$(stat -Lc %d "$lock_parent")
  _QCSD_LIFECYCLE_LOCK_PARENT_INODE=$(stat -Lc %i "$lock_parent")
  _QCSD_LIFECYCLE_DOCKER_CONFIG_PATH=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH
  _QCSD_LIFECYCLE_DOCKER_CONFIG_DEVICE=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_DEVICE
  _QCSD_LIFECYCLE_DOCKER_CONFIG_INODE=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_INODE
  _QCSD_LIFECYCLE_BUILDX_CONFIG_PATH=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
  _QCSD_LIFECYCLE_BUILDX_CONFIG_DEVICE=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_DEVICE
  _QCSD_LIFECYCLE_BUILDX_CONFIG_INODE=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_INODE
  export DOCKER_CONFIG=$_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH
  export BUILDX_CONFIG=$_QCSD_LIFECYCLE_BUILDX_CONFIG_PATH
  source "$QCSD_DOCKER_LOCK_GUARDIAN_HELPER_SOURCE_PATH"
}

case "$1" in
  success)
    printf '%s\n' "$PATH" >"$state/inner-path"
    env | grep '^_QCSD_' >"$state/internal-environment" || true
    env | grep '^PYTHON' >"$state/python-environment" || true
    env | grep '^GIT_' >"$state/git-environment" || true
    env | grep -E '^(DOCKER_|BUILDX_|BUILDKIT_)' \
      >"$state/docker-environment" || true
    env | grep -E '^(DBUS_|SYSTEMD_|XDG_|TMP=|TEMP=|TMPDIR=)' \
      >"$state/runtime-environment" || true
    stat -Lc '%d:%i:%u:%a:%h:%F' \
      "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH" \
      >"$state/docker-config-identity"
    find "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH" \
      -mindepth 1 -maxdepth 1 -print >"$state/docker-config-children"
    printf '%s:%s\n' \
      "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_DEVICE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_INODE" \
      >"$state/docker-config-expected"
    command -v powershell.exe >"$state/powershell-path" 2>/dev/null || true
    lock_matches "$state/inner-lock-fds"
    ready
    /usr/bin/python3 - "$state/grandchild-lock-fds" <<'PY'
import os
from pathlib import Path
import sys

wanted = (
    int(os.environ["QCSD_DOCKER_LOCK_GUARDIAN_LOCK_DEVICE"]),
    int(os.environ["QCSD_DOCKER_LOCK_GUARDIAN_LOCK_INODE"]),
)
matches = []
for candidate in Path("/proc/self/fd").iterdir():
    try:
        value = candidate.stat()
    except OSError:
        continue
    if (value.st_dev, value.st_ino) == wanted:
        matches.append(candidate.name)
Path(sys.argv[1]).write_text(",".join(matches), encoding="ascii")
PY
    ;;
  buildx-write)
    buildx_config=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
    printf '%s\n' "$buildx_config" >"$state/buildx-config-path"
    ready
    mkdir "$buildx_config/instances"
    printf 'opaque-buildx-state\n' >"$buildx_config/instances/default"
    printf 'written\n' >"$state/buildx-written"
    ;;
  docker-buildx-probe)
    export DOCKER_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH
    export BUILDX_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
    ready
    docker context show >"$state/docker-context"
    docker buildx ls >"$state/docker-buildx-ls"
    ;;
  systemd-probe)
    ready
    systemctl --user show-environment >"$state/systemd-environment"
    ;;
  wait)
    ready
    printf 'ready\n' >"$state/ready"
    while [[ ! -e "$state/release" ]]; do sleep 0.02; done
    ;;
  exit-at-cmdline-read)
    ready
    printf 'ready\n' >"$state/cmdline-exit-ready"
    while [[ ! -e "$state/release-cmdline-exit" ]]; do sleep 0.005; done
    exit 1
    ;;
  acquisition-wait)
    acquisition_fd=$QCSD_CLASS_ACQUISITION_LOCK_FD
    stat -Lc '%d:%i' "/proc/$BASHPID/fd/$acquisition_fd" \
      >"$state/acquisition-identity"
    ready
    printf 'ready\n' >"$state/ready"
    while [[ ! -e "$state/release" ]]; do sleep 0.02; done
    ;;
  pre-ready-signal)
    signals=0
    trap 'signals=$((signals + 1)); printf "%s\n" "$signals" \
      >"$state/signals"; exit 143' TERM
    printf 'pre-ready\n' >"$state/pre-ready"
    sleep 0.3
    ready
    printf 'mutated\n' >"$state/mutation-after-go"
    while :; do sleep 0.02; done
    ;;
  never-ready)
    while :; do sleep 0.02; done
    ;;
  ready-cmdline-drift)
    ready_fd=$QCSD_DOCKER_LOCK_GUARDIAN_READY_FD
    printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_NONCE" >&"$ready_fd"
    eval "exec ${ready_fd}>&-"
    exec -a qcsd-cmdline-drift /bin/sleep 30
    ;;
  child-kill)
    ready
    (
      trap '' HUP INT QUIT TERM
      printf '%s\n' "$BASHPID" >"$state/orphan-pid"
      while :; do sleep 0.02; done
    ) &
    kill -KILL "$$"
    ;;
  lease)
    ready
    base="$state/native-base"
    mkdir -m 700 "$base"
    base_device=$(stat -Lc %d "$base")
    base_inode=$(stat -Lc %i "$base")
    (
      printf 'retirement_schema=1\n'
      sleep 1.5
    ) | /usr/bin/python3 -I "$QCSD_DOCKER_LOCK_GUARDIAN_NATIVE_SOURCE_PATH" \
      --lease "$QCSD_DOCKER_LOCK_GUARDIAN_LEASE_SOCKET" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_LEASE_NONCE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_INNER_PID" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_INNER_START_TIME" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_HELPER_SOURCE_SHA256" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_LOCK_DEVICE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_LOCK_INODE" \
      publish "$base" "$(id -u)" "$base_device" "$base_inode" \
      retirement.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.next \
      retirement.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa &
    native_pid=$!
    /usr/bin/python3 - "$native_pid" "$state/lease-ready" <<'PY'
import os
from pathlib import Path
import sys
import time

pid = int(sys.argv[1])
marker = Path(sys.argv[2])
wanted = (
    int(os.environ["QCSD_DOCKER_LOCK_GUARDIAN_LOCK_DEVICE"]),
    int(os.environ["QCSD_DOCKER_LOCK_GUARDIAN_LOCK_INODE"]),
)
deadline = time.monotonic() + 3
while time.monotonic() < deadline:
    try:
        descriptors = tuple(Path(f"/proc/{pid}/fd").iterdir())
    except OSError:
        descriptors = ()
    for descriptor in descriptors:
        try:
            value = descriptor.stat()
        except OSError:
            continue
        if (value.st_dev, value.st_ino) == wanted:
            marker.write_text(str(pid), encoding="ascii")
            raise SystemExit(0)
    time.sleep(0.01)
raise SystemExit(98)
PY
    wait "$native_pid"
    ;;
  creation-hold|creation-cancel|creation-reject)
    ready
    base="$state/creation-base"
    mkdir -m 700 "$base"
    base_device=$(stat -Lc %d "$base")
    base_inode=$(stat -Lc %i "$base")
    coproc CREATION_HOLDER {
      exec /usr/bin/python3 -I \
        "$QCSD_DOCKER_LOCK_GUARDIAN_NATIVE_SOURCE_PATH" \
        --lease "$QCSD_DOCKER_LOCK_GUARDIAN_LEASE_SOCKET" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_LEASE_NONCE" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_INNER_PID" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_INNER_START_TIME" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_HELPER_SOURCE_SHA256" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_LOCK_DEVICE" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_LOCK_INODE" \
        hold-creation "$base" "$(id -u)" "$base_device" "$base_inode" \
        run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        "$QCSD_DOCKER_LOCK_GUARDIAN_INNER_PID" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_INNER_START_TIME" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_INNER_SESSION" \
        "$QCSD_DOCKER_LOCK_GUARDIAN_INNER_PROCESS_GROUP"
    }
    IFS= read -r holder_ready <&"${CREATION_HOLDER[0]}"
    [[ "$holder_ready" =~ ^QCSD-CREATION-HOLD-READY-V1\ [0-9]+\ [0-9]+$ ]]
    printf '%s\n' "$CREATION_HOLDER_PID" >"$state/creation-holder-pid"
    root="$base/run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    if [[ "$1" == creation-reject ]]; then
      printf 'QCSD-CREATION-HOLD-COMMIT-V1\n' >&"${CREATION_HOLDER[1]}"
      eval "exec ${CREATION_HOLDER[1]}>&-"
      IFS= read -r holder_result <&"${CREATION_HOLDER[0]}"
      [[ "$holder_result" == QCSD-CREATION-HOLD-REJECTED-V1 ]]
      printf '%s\n' "$holder_result" >"$state/creation-result"
      exit 125
    fi
    if [[ "$1" == creation-cancel ]]; then
      printf 'partial\n' >"$root/SUPERVISION.next"
      chmod 600 "$root/SUPERVISION.next"
      printf 'QCSD-CREATION-HOLD-CANCEL-V1\n' >&"${CREATION_HOLDER[1]}"
      eval "exec ${CREATION_HOLDER[1]}>&-"
      IFS= read -r holder_result <&"${CREATION_HOLDER[0]}"
      [[ "$holder_result" == QCSD-CREATION-HOLD-CANCELLED-V1 ]]
      wait "$CREATION_HOLDER_PID"
      [[ ! -e "$root" ]]
      printf 'cancelled\n' >"$state/creation-cancelled"
      exit 0
    fi
    {
      printf 'object=docker-run-scope-launcher\n'
      printf 'lifecycle_root=%s\n' "$root"
      printf 'lifecycle_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
    } >"$root/SUPERVISION"
    chmod 600 "$root/SUPERVISION"
    (
      trap '' HUP INT QUIT TERM
      sleep 1.2
    ) &
    printf '%s\n' "$!" >"$state/creation-descendant-pid"
    printf 'held\n' >"$state/creation-held"
    while [[ ! -e "$state/release" ]]; do sleep 0.02; done
    printf 'QCSD-CREATION-HOLD-COMMIT-V1\n' >&"${CREATION_HOLDER[1]}"
    eval "exec ${CREATION_HOLDER[1]}>&-"
    IFS= read -r holder_result <&"${CREATION_HOLDER[0]}"
    [[ "$holder_result" == QCSD-CREATION-HOLD-COMMITTED-V1 ]]
    wait "$CREATION_HOLDER_PID"
    ;;
  api-command-substitution)
    ready
    load_real_helper_with_guardian_proof
    _qcsd_lifecycle_base="$state/api-base"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    export DOCKER_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH
    export BUILDX_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
    mkdir "$BUILDX_CONFIG/instances"
    _qcsd_supervisor_token() { printf '%032x\n' "$BASHPID"; }
    api_output="$(_qcsd_docker_api_service_with_timeout 5 /bin/sh -c '
      printf "%s\n" "$$" >"$1/service-pid"
      printf "started\n" >"$1/api-started"
      if test -e "$1/require-config-gate"; then
        while test ! -e "$1/open-configs-now"; do sleep 0.02; done
      fi
      test -d "$DOCKER_CONFIG"
      test -d "$BUILDX_CONFIG"
      find -H "$DOCKER_CONFIG" -mindepth 1 -maxdepth 1 -print -quit \
        | grep -q . && exit 91
      printf "opened\n" >"$1/api-configs-opened"
      sleep 1.1
      printf "completed\n" >"$1/api-completed"
      printf "captured-output\n"
    ' qcsd-api-service "$state")"
    printf '%s\n' "$api_output" >"$state/api-output"
    ;;
  api-successor)
    ready
    load_real_helper_with_guardian_proof
    _qcsd_lifecycle_base="$state/api-successor-base"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    export DOCKER_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH
    export BUILDX_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
    _qcsd_supervisor_token() { printf '%032x\n' "$BASHPID"; }
    _qcsd_docker_api_service_with_timeout 5 /bin/sh -c '
      printf "started\n" >"$1/successor-api-started"
    ' qcsd-api-successor "$state"
    ;;
  real-helper-reject-*)
    ready
    kind=${1#real-helper-reject-}
    [[ "$kind" =~ ^(run|network|build|transaction)$ ]]
    load_real_helper_with_guardian_proof
    _qcsd_lifecycle_base="$state/real-helper-base-$kind"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    trap 'printf "exit\n" >"$state/real-helper-exit-trap"' EXIT
    _qcsd_secure_lifecycle_base() { :; }
    _qcsd_create_lifecycle_root "$kind" "$token"
    printf '%s\n' "$_QCSD_CREATION_HOLDER_PID" \
      >"$state/real-helper-holder-pid"
    printf '%s/%s.%s\n' "$_qcsd_lifecycle_base" "$kind" "$token" \
      >"$state/real-helper-root"
    # No final SUPERVISION exists: the real helper must consume REJECTED and
    # terminate qcsd immediately instead of waiting on the rejecting holder.
    _qcsd_commit_lifecycle_root_creation
    exit 99
    ;;
  real-helper-recover-*)
    ready
    kind=${1#real-helper-recover-}
    [[ "$kind" =~ ^(run|network|build|transaction)$ ]]
    load_real_helper_with_guardian_proof
    _qcsd_lifecycle_base="$state/real-helper-base-$kind"
    _QCSD_DOCKER_PINNED_CONTEXT=default
    export DOCKER_CONTEXT=default
    _QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
    _QCSD_DOCKER_PINNED_SERVER_ID=daemon-test-id
    _QCSD_DOCKER_PINNED_BOOT_ID=$(</proc/sys/kernel/random/boot_id)
    _qcsd_verify_pinned_docker_daemon() { :; }
    _qcsd_secure_lifecycle_base() { :; }
    _qcsd_resolve_docker_target() {
      _qcsd_resolved_state=absent
      _qcsd_resolved_cid=''
    }
    _qcsd_resolve_docker_network() {
      _qcsd_resolved_network_state=absent
      _qcsd_resolved_network_id=''
    }
    _qcsd_retirement_boundary_hook() {
      printf '%s\n' "$1" >>"$state/real-helper-recovery-boundaries"
    }
    if ! qcsd_reconcile_docker_lifecycle validate; then
      printf 'validate-failed\n' >"$state/real-helper-recovery-stage"
      exit 91
    fi
    if ! qcsd_reconcile_docker_lifecycle recover; then
      printf 'recover-failed\n' >"$state/real-helper-recovery-stage"
      exit 92
    fi
    [[ ! -e "$_qcsd_lifecycle_base/$kind.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]]
    printf 'recovered\n' >"$state/real-helper-recovered"
    ;;
  real-helper-h3-api-run)
    ready
    load_real_helper_with_guardian_proof
    _qcsd_lifecycle_base="$state/real-helper-base-run"
    _QCSD_DOCKER_PINNED_CONTEXT=default
    _QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
    _QCSD_DOCKER_PINNED_SERVER_ID=daemon-test-id
    _QCSD_DOCKER_PINNED_BOOT_ID=$(</proc/sys/kernel/random/boot_id)
    _qcsd_verify_pinned_docker_daemon() { :; }
    _qcsd_secure_lifecycle_base() { :; }
    _qcsd_resolve_docker_target() {
      _qcsd_resolved_state=absent
      _qcsd_resolved_cid=''
    }
    mkdir "$BUILDX_CONFIG/instances"
    stat -Lc '%h' "$BUILDX_CONFIG" >"$state/h3-buildx-nlink"
    printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH" \
      >"$state/h3-old-docker-config"
    printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH" \
      >"$state/h3-old-buildx-config"
    _qcsd_supervisor_token() { printf '%032x\n' "$BASHPID"; }
    _qcsd_docker_api_service_with_timeout 10 /bin/sh -c '
      printf "started\n" >"$1/h3-api-started"
      while test ! -e "$1/h3-api-release"; do sleep 0.02; done
      printf "terminal\n" >"$1/h3-api-terminal"
    ' qcsd-h3-api "$state" &
    while [[ ! -e "$state/h3-api-started" ]]; do sleep 0.02; done
    _qcsd_retirement_boundary_hook() {
      if [[ "$1" == H3 ]]; then
        printf 'h3\n' >"$state/h3-seen"
        kill -KILL "$QCSD_DOCKER_LOCK_GUARDIAN_PID"
        while :; do sleep 1; done
      fi
    }
    qcsd_reconcile_docker_lifecycle recover
    exit 99
    ;;
  real-helper-launch-crash-*)
    kind=${1#real-helper-launch-crash-}
    [[ "$kind" =~ ^(run|build)$ ]]
    ready
    load_real_helper_with_guardian_proof
    export PATH="$state/bin:$PATH" FAKE_DOCKER_STATE="$state"
    export DOCKER_CONTEXT=default
    _qcsd_lifecycle_base="$state/real-helper-base-$kind"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    _QCSD_DOCKER_PINNED_CONTEXT=default
    _QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
    _QCSD_DOCKER_PINNED_SERVER_ID=daemon-test-id
    _QCSD_DOCKER_PINNED_BOOT_ID=$(</proc/sys/kernel/random/boot_id)
    _qcsd_verify_pinned_docker_daemon() { :; }
    _qcsd_secure_lifecycle_base() { :; }
    _qcsd_launcher_forked_hook() {
      local hook_kind="$1" launcher_pid="$2" root="$3" deadline stat_line state_value
      deadline=$((SECONDS + 8))
      while :; do
        stat_line=$(<"/proc/$launcher_pid/stat") || exit 97
        state_value=${stat_line##*) }; state_value=${state_value%% *}
        [[ -f "$root/launcher.birth" && "$state_value" == T ]] && break
        (( SECONDS < deadline )) || exit 97
        sleep 0.01
      done
      printf '%s %s\n' "$launcher_pid" "$root" >"$state/real-launch-crash"
      kill -KILL "$QCSD_DOCKER_LOCK_GUARDIAN_PID"
      while :; do sleep 1; done
    }
    if [[ "$kind" == run ]]; then
      QCSD_DOCKER_IDS_REAL=()
      qcsd_run_detached_docker QCSD_DOCKER_IDS_REAL docker run fake-image
    else
      _QCSD_DOCKER_BUILD_DAEMON_ID=daemon-test-id
      exec {_QCSD_DOCKER_BUILD_LOCK_FD}>"$state/build-domain.lock"
      chmod 600 "$state/build-domain.lock"
      flock -n "$_QCSD_DOCKER_BUILD_LOCK_FD"
      qcsd_run_docker_build docker --context default build fake-context
    fi
    exit 99
    ;;
  non-native-lease|foreign-session-lease)
    ready
    /usr/bin/python3 - "$state" "$1" <<'PY'
import array
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

state = Path(sys.argv[1])
mode = sys.argv[2]
if mode == "foreign-session-lease":
    os.setsid()
prefix = "QCSD_DOCKER_LOCK_GUARDIAN_"
pid = os.getpid()
fields = (
    Path(f"/proc/{pid}/stat")
    .read_text(encoding="ascii")
    .rsplit(") ", 1)[1]
    .split()
)
cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
request = {
    "action": "publish",
    "argv_sha256": hashlib.sha256(cmdline).hexdigest(),
    "helper_source_sha256": os.environ[prefix + "HELPER_SOURCE_SHA256"],
    "lease_nonce": os.environ[prefix + "LEASE_NONCE"],
    "qcsd_pid": int(os.environ[prefix + "INNER_PID"]),
    "qcsd_start_time": int(os.environ[prefix + "INNER_START_TIME"]),
    "requester_pid": pid,
    "requester_start_time": int(fields[19]),
    "schema": 1,
}
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
client.connect("\0" + os.environ[prefix + "LEASE_SOCKET"][1:])
payload = json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n"
client.sendall(payload.encode("ascii"))
client.shutdown(socket.SHUT_WR)
fds = array.array("i")
message, ancillary, _, _ = client.recvmsg(64, socket.CMSG_SPACE(8 * fds.itemsize))
for level, kind, data in ancillary:
    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
        fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
for descriptor in fds:
    os.close(descriptor)
(state / f"{mode}-result").write_text(f"{message!r}:{len(fds)}", encoding="ascii")
if message or fds:
    raise SystemExit(99)
PY
    ;;
  *) exit 97 ;;
esac
'''


def _wait(path: Path, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def _process_state(pid: int) -> str | None:
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError:
        return None
    return value.rsplit(") ", maxsplit=1)[1].split(maxsplit=1)[0]


def _wait_gone(pid: int, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _process_state(pid) in (None, "Z"):
            return
        time.sleep(0.01)
    raise AssertionError(f"process {pid} remains {_process_state(pid)}")


@pytest.fixture
def guardian_bundle(tmp_path: Path):
    project = tmp_path / "project"
    tools = project / "tools"
    tools.mkdir(parents=True)
    guardian = tools / GUARDIAN.name
    native = tools / NATIVE.name
    helper = tools / "docker_signal_supervisor.sh"
    qcsd = project / "qcsd-lab"
    shutil.copyfile(GUARDIAN, guardian)
    guardian.chmod(0o600)
    shutil.copyfile(NATIVE, native)
    native.chmod(0o600)
    shutil.copyfile(HELPER, helper)
    helper.chmod(0o600)
    qcsd.write_text(FAKE_QCSD, encoding="ascii")
    qcsd.chmod(0o700)
    lock_parent = tmp_path / "locks"
    lock_parent.mkdir(mode=0o700)
    state = tmp_path / "state"
    state.mkdir()
    fake_bin = state / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(FAKE_DOCKER, encoding="utf-8")
    fake_docker.chmod(0o755)
    socket_name = f"@qcsd-docker-lifecycle-guardian-{os.getuid()}"

    def socket_count() -> int:
        return sum(
            line.rstrip().endswith(socket_name)
            for line in Path("/proc/net/unix").read_text(encoding="ascii").splitlines()
        )

    socket_deadline = time.monotonic() + 2
    while socket_count() and time.monotonic() < socket_deadline:
        time.sleep(0.01)
    socket_baseline = socket_count()
    assert socket_baseline == 0
    bundle = (guardian, qcsd, lock_parent, state)
    yield bundle

    leaked: list[int] = []
    project_bytes = os.fsencode(project)
    for candidate in Path("/proc").iterdir():
        if not candidate.name.isdigit():
            continue
        try:
            cmdline = (candidate / "cmdline").read_bytes()
            owner = candidate.stat().st_uid
        except OSError:
            continue
        if owner == os.getuid() and project_bytes in cmdline:
            leaked.append(int(candidate.name))
    for pid in leaked:
        try:
            value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            fields = value.rsplit(") ", 1)[1].split()
            process_group, session = int(fields[2]), int(fields[3])
            if process_group == session:
                os.killpg(process_group, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError, IndexError):
            pass
    deadline = time.monotonic() + 2
    while leaked and time.monotonic() < deadline:
        leaked = [pid for pid in leaked if Path(f"/proc/{pid}").exists()]
        time.sleep(0.01)
    assert leaked == [], f"guardian test leaked exact bundle processes: {leaked}"
    socket_deadline = time.monotonic() + 2
    while socket_count() != socket_baseline and time.monotonic() < socket_deadline:
        time.sleep(0.01)
    assert socket_count() == socket_baseline


def _guardian_command(
    bundle: tuple[Path, Path, Path, Path],
    mode: str,
    *,
    ready_timeout: float | None = None,
    inject_wait_failure: bool = False,
    replace_qcsd_before_fork: bool = False,
    signal_during_cleanup: bool = False,
    exit_at_cmdline_read: bool = False,
    reap_during_buildx_census: bool = False,
) -> list[str]:
    guardian, qcsd, lock_parent, state = bundle
    harness = textwrap.dedent(
        """\
        import importlib.util
        from pathlib import Path
        import sys

        source = Path(sys.argv[1])
        spec = importlib.util.spec_from_file_location(
            "qcsd_guardian_under_test", source
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        if sys.argv[6] != "default":
            module.READY_TIMEOUT_SECONDS = float(sys.argv[6])
        if sys.argv[7] == "fail-wait":
            def fail_wait(*_args, **_kwargs):
                import time
                marker = Path(sys.argv[4]) / "inner-pid"
                deadline = time.monotonic() + 1
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                raise module.GuardianError("injected post-fork failure")
            module._wait_for_child = fail_wait
        if sys.argv[8] == "replace-qcsd":
            real_fork = module.os.fork
            def replace_then_fork():
                module.os.fork = real_fork
                qcsd = Path(sys.argv[2])
                moved = qcsd.with_name("captured-qcsd")
                qcsd.rename(moved)
                qcsd.write_text(
                    "#!/bin/bash\\n"
                    f"touch {str(Path(sys.argv[4]) / 'replacement-executed')!r}\\n"
                    "exit 99\\n",
                    encoding="ascii",
                )
                qcsd.chmod(0o700)
                return real_fork()
            module.os.fork = replace_then_fork
        if sys.argv[9] == "signal-cleanup":
            real_sigmask = module.signal.pthread_sigmask
            block_calls = [0]
            def block_then_signal(how, mask):
                result = real_sigmask(how, mask)
                if how == module.signal.SIG_BLOCK:
                    block_calls[0] += 1
                    if block_calls[0] == 4:
                        module.os.kill(module.os.getpid(), module.signal.SIGTERM)
                return result
            module.signal.pthread_sigmask = block_then_signal
        if sys.argv[10] == "exit-at-cmdline-read":
            real_read_cmdline = module._read_cmdline
            injected = [False]
            def exit_between_identity_and_cmdline(pid):
                ready = Path(sys.argv[4]) / "cmdline-exit-ready"
                if ready.exists() and not injected[0]:
                    injected[0] = True
                    (Path(sys.argv[4]) / "release-cmdline-exit").touch()
                    deadline = module.time.monotonic() + 2
                    while module.time.monotonic() < deadline:
                        try:
                            state = module._process_record(pid)[0]
                        except module.GuardianError:
                            state = ""
                        if state == "Z":
                            break
                        module.time.sleep(0.002)
                    else:
                        raise module.GuardianError(
                            "injected child did not become a zombie"
                        )
                return real_read_cmdline(pid)
            module._read_cmdline = exit_between_identity_and_cmdline
        if sys.argv[11] == "reap-during-buildx-census":
            real_read_references = module._read_buildx_process_references
            injected = [False]
            def fail_after_exact_reap(candidate, paths, path_bytes):
                target = int((Path(sys.argv[4]) / "census-reap-pid").read_text())
                if int(candidate.name) == target and not injected[0]:
                    injected[0] = True
                    (Path(sys.argv[4]) / "census-reap-inspection").touch()
                    deadline = module.time.monotonic() + 5
                    while not (Path(sys.argv[4]) / "census-reap-complete").exists():
                        if module.time.monotonic() >= deadline:
                            raise AssertionError("test census candidate was not reaped")
                        module.time.sleep(0.002)
                    raise FileNotFoundError("injected procfs disappearance after reap")
                return real_read_references(candidate, paths, path_bytes)
            module._read_buildx_process_references = fail_after_exact_reap
        raise SystemExit(module.guard(
            (sys.argv[2], sys.argv[3], sys.argv[4]),
            source_path=source,
            lock_parent=Path(sys.argv[5]),
        ))
        """
    )
    return [
        sys.executable,
        "-I",
        "-c",
        harness,
        str(guardian),
        str(qcsd),
        mode,
        str(state),
        str(lock_parent),
        "default" if ready_timeout is None else str(ready_timeout),
        "fail-wait" if inject_wait_failure else "normal",
        "replace-qcsd" if replace_qcsd_before_fork else "normal",
        "signal-cleanup" if signal_during_cleanup else "normal",
        "exit-at-cmdline-read" if exit_at_cmdline_read else "normal",
        "reap-during-buildx-census" if reap_during_buildx_census else "normal",
    ]


def _run_guardian(
    bundle: tuple[Path, Path, Path, Path], mode: str, timeout: float = 10
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _guardian_command(bundle, mode),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout,
    )


def _lock_path(bundle: tuple[Path, Path, Path, Path]) -> Path:
    return bundle[2] / f"qcsd-docker-lifecycle-{os.getuid()}.lock"


def _load_guardian(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("qcsd_guardian_direct_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_native(path: Path) -> ModuleType:
    name = f"qcsd_lifecycle_native_direct_test_{os.urandom(8).hex()}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _buildx_census_ledger(module: ModuleType, lock_parent: Path, start_time: int):
    config = module.ConfigDirectoryIdentity(
        lock_parent / "unused-config", 0, 0, os.getuid(), 0o700, 0
    )
    authority = module.RecordIdentity("unused-authority", 0, 0)
    return module.BuildxLedger(
        "a" * 64,
        "unused-config",
        lock_parent / "unused-root",
        lock_parent / "unused-exported",
        config,
        authority,
        {
            "boot_id": module._boot_id(),
            "guardian_start_time": str(start_time),
        },
    )


def _direct_buildx_context(
    bundle: tuple[Path, Path, Path, Path],
) -> tuple[ModuleType, int, int, object, int, object]:
    module = _load_guardian(bundle[0])
    parent_fd, _ = module._open_lock_parent(bundle[2])
    lock_fd, lock = module._open_lock(parent_fd, bundle[2])
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    source_fd, source = module._capture_source_identity(bundle[0])
    return module, parent_fd, lock_fd, lock, source_fd, source


def _can_lock(path: Path) -> bool:
    with path.open("r+", encoding="ascii") as descriptor:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return True


def test_guardian_and_grandchild_never_inherit_the_lifecycle_lock(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    state = guardian_bundle[3]
    assert (state / "inner-lock-fds").read_text(encoding="ascii") == ""
    assert (state / "grandchild-lock-fds").read_text(encoding="ascii") == ""
    expected = (state / "docker-config-expected").read_text(
        encoding="ascii"
    ).strip()
    observed = (state / "docker-config-identity").read_text(
        encoding="ascii"
    ).strip()
    device, inode = expected.split(":")
    assert observed == f"{device}:{inode}:{os.getuid()}:700:0:directory"
    assert (state / "docker-config-children").read_text(encoding="ascii") == ""
    assert _can_lock(_lock_path(guardian_bundle))


def test_exit_between_identity_and_cmdline_preserves_exact_child_status(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "exit-at-cmdline-read",
            exit_at_cmdline_read=True,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / "release-cmdline-exit").exists()
    assert _can_lock(_lock_path(guardian_bundle))


def test_guardian_recovers_only_exact_empty_docker_config_residue(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = guardian_bundle[2]
    residue = lock_parent / (
        f".qcsd-docker-config-{os.getuid()}." + "a" * 64
    )
    residue.mkdir(mode=0o700)

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not residue.exists()
    assert not tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


@pytest.mark.parametrize("case", ["malformed-name", "nonempty"])
def test_guardian_fails_closed_on_unsafe_docker_config_residue(
    guardian_bundle: tuple[Path, Path, Path, Path], case: str
) -> None:
    lock_parent = guardian_bundle[2]
    suffix = "not-a-token" if case == "malformed-name" else "b" * 64
    residue = lock_parent / f".qcsd-docker-config-{os.getuid()}.{suffix}"
    residue.mkdir(mode=0o700)
    if case == "nonempty":
        (residue / "foreign").write_text("foreign\n", encoding="ascii")

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode != 0, (result.stdout, result.stderr)
    assert residue.is_dir()
    assert not (guardian_bundle[3] / "inner-pid").exists()


def test_linked_buildx_config_accepts_writes_then_is_removed_authority_last(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "buildx-write")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / "buildx-written").read_text(
        encoding="ascii"
    ) == "written\n"
    config_path = Path(
        (guardian_bundle[3] / "buildx-config-path")
        .read_text(encoding="ascii")
        .strip()
    )
    assert not config_path.exists()
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))


def test_real_docker_buildx_accepts_guardian_configs(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
    probe = subprocess.run(
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("Docker daemon is unavailable")

    result = _run_guardian(guardian_bundle, "docker-buildx-probe", timeout=20)

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / "docker-context").read_text(
        encoding="ascii"
    ).strip() == "default"
    assert "NAME/NODE" in (guardian_bundle[3] / "docker-buildx-ls").read_text(
        encoding="utf-8"
    )
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))


def test_real_user_systemd_accepts_guardian_runtime_environment(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    probe = subprocess.run(
        ["/usr/bin/systemctl", "--user", "show-environment"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=5,
    )
    if probe.returncode != 0:
        pytest.skip("user systemd manager is unavailable")

    result = _run_guardian(guardian_bundle, "systemd-probe")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / "systemd-environment").is_file()


def test_terminal_signal_during_final_cleanup_sets_exit_status(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle, "success", signal_during_cleanup=True
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 143, (result.stdout, result.stderr)
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    assert _can_lock(_lock_path(guardian_bundle))


def test_real_qcsd_fd_entry_verifier_go_and_docker_admission(
    tmp_path: Path,
) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
    probe = subprocess.run(
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("Docker daemon is unavailable")

    project = tmp_path / "real-project"
    tools = project / "tools"
    tools.mkdir(parents=True)
    lifecycle_parent = tmp_path / "real-locks"
    lifecycle_parent.mkdir(mode=0o700)
    qcsd = project / "qcsd-lab"
    guardian = tools / GUARDIAN.name
    helper = tools / HELPER.name
    native = tools / NATIVE.name
    shutil.copyfile(ROOT / "qcsd-lab", qcsd)
    qcsd.chmod(0o755)
    guardian_text = GUARDIAN.read_text(encoding="utf-8").replace(
        'LOCK_PARENT = Path("/var/tmp")',
        f"LOCK_PARENT = Path({str(lifecycle_parent)!r})",
    )
    guardian_text = guardian_text.replace(
        "if parent == LOCK_PARENT and (", "if False and ("
    ).replace("if parent != LOCK_PARENT and (", "if (")
    guardian.write_text(guardian_text, encoding="utf-8")
    guardian.chmod(0o644)
    helper_text = HELPER.read_text(encoding="utf-8").replace(
        "/var/tmp", str(lifecycle_parent)
    )
    helper_text = helper_text.replace(
        '"0:1777:directory"', '"${uid}:700:directory"'
    )
    helper.write_text(helper_text, encoding="utf-8")
    helper.chmod(0o644)
    shutil.copyfile(NATIVE, native)
    native.chmod(0o644)

    result = subprocess.run(
        [str(qcsd), "etf-probe", "disabled"],
        cwd=project,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode in {1, 125}, (result.stdout, result.stderr)
    assert "etf-probe is disabled" in result.stderr
    assert "lifecycle guardian authority is invalid" not in result.stderr
    assert not tuple(lifecycle_parent.glob(".qcsd-buildx-*"))


def test_qcsd_rejects_caller_selected_guardian_verifier(tmp_path: Path) -> None:
    """Ambient handshake fields cannot select code that vouches for itself."""
    marker = tmp_path / "forged-verifier-ran"
    verifier = tmp_path / "fake-guardian.py"
    verifier.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran')\n",
        encoding="ascii",
    )
    verifier.chmod(0o644)
    harness = r'''
import os
from pathlib import Path
import sys

qcsd = sys.argv[1]
verifier = sys.argv[2]
qcsd_fd = os.open(qcsd, os.O_RDONLY)
verifier_fd = os.open(verifier, os.O_RDONLY)
pid = os.fork()
if pid == 0:
    own = os.getpid()
    raw = Path(f"/proc/{own}/stat").read_text().rsplit(") ", 1)[1].split()
    source = os.fstat(verifier_fd)
    prefix = "QCSD_DOCKER_LOCK_GUARDIAN_"
    os.environ.update({
        prefix + "PID": str(os.getppid()),
        prefix + "SOURCE_FD": str(verifier_fd),
        prefix + "SOURCE_PATH": verifier,
        prefix + "SOURCE_DEVICE": str(source.st_dev),
        prefix + "SOURCE_INODE": str(source.st_ino),
        prefix + "QCSD_SOURCE_FD": str(qcsd_fd),
        prefix + "QCSD_SOURCE_PATH": qcsd,
        prefix + "INNER_PID": str(own),
        prefix + "INNER_START_TIME": raw[19],
        prefix + "INNER_SESSION": raw[3],
        prefix + "INNER_PROCESS_GROUP": raw[2],
    })
    os.set_inheritable(qcsd_fd, True)
    os.set_inheritable(verifier_fd, True)
    os.execv("/bin/bash", ["/bin/bash", "--noprofile", "--norc",
                              f"/proc/{os.getppid()}/fd/{qcsd_fd}",
                              "etf-probe", "disabled"])
_, status = os.waitpid(pid, 0)
raise SystemExit(os.waitstatus_to_exitcode(status))
'''
    result = subprocess.run(
        [sys.executable, "-I", "-c", harness, str(ROOT / "qcsd-lab"), str(verifier)],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode != 0
    assert "lifecycle guardian authority is invalid" in result.stderr
    assert not marker.exists()


def test_buildx_crash_authority_is_deferred_until_successor_exit(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    _wait(state / "ready")
    child = int((state / "inner-pid").read_text(encoding="ascii"))
    os.kill(process.pid, signal.SIGKILL)
    assert process.wait(timeout=5) == -signal.SIGKILL
    _wait_gone(child)
    residues = tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    assert any("authority" in path.name for path in residues)
    assert any("config" in path.name for path in residues)

    successor = _run_guardian(guardian_bundle, "success")

    assert successor.returncode == 0, (successor.stdout, successor.stderr)
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))


@pytest.mark.parametrize("reference", ["environment", "cwd", "descriptor"])
def test_buildx_crash_root_is_not_removed_while_process_refers(
    guardian_bundle: tuple[Path, Path, Path, Path], reference: str
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    _wait(state / "ready")
    child = int((state / "inner-pid").read_text(encoding="ascii"))
    os.kill(process.pid, signal.SIGKILL)
    assert process.wait(timeout=5) == -signal.SIGKILL
    _wait_gone(child)
    authority = next(guardian_bundle[2].glob(".qcsd-buildx-authority-*"))
    record = json.loads(authority.read_text(encoding="ascii"))
    root = guardian_bundle[2] / record["root_name"]
    holder_environment = dict(os.environ)
    holder_command = ["/bin/sleep", "30"]
    holder_cwd: Path | None = None
    if reference == "environment":
        holder_environment["BUILDX_CONFIG"] = record["exported_path"]
    elif reference == "cwd":
        holder_cwd = root
    else:
        held = root / "held-by-process"
        held.write_text("held\n", encoding="ascii")
        holder_environment["HOLD_BUILDX_PATH"] = str(held)
        holder_command = [
            "/usr/bin/python3",
            "-I",
            "-c",
            "import os,time; f=open(os.environ['HOLD_BUILDX_PATH']); time.sleep(30)",
        ]
    holder = subprocess.Popen(
        holder_command,
        env=holder_environment,
        cwd=holder_cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        successor = _run_guardian(guardian_bundle, "success")
        assert successor.returncode != 0, (
            successor.stdout,
            successor.stderr,
        )
        assert root.is_dir()
        assert authority.is_file()
    finally:
        os.killpg(holder.pid, signal.SIGKILL)
        holder.wait(timeout=5)

    final = _run_guardian(guardian_bundle, "success")
    assert final.returncode == 0, (final.stdout, final.stderr)
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))


def test_buildx_user_census_tolerates_only_exact_zombie_transition(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    _, _, _, _, child_start = module._process_record(child)
    injected = False
    reaped = False

    def reap_during_reference_snapshot(candidate, _paths, _path_bytes):
        nonlocal injected, reaped
        if int(candidate.name) == child and not injected:
            injected = True
            os.kill(child, signal.SIGKILL)
            assert os.waitpid(child, 0)[1] == signal.SIGKILL
            reaped = True
            raise FileNotFoundError("injected procfs disappearance after exact reap")
        return False

    monkeypatch.setattr(
        module,
        "_read_buildx_process_references",
        reap_during_reference_snapshot,
    )
    try:
        assert module._process_references_buildx_candidate(
            child,
            Path(f"/proc/{child}"),
            threshold=child_start,
            paths=(guardian_bundle[2] / "unused-root",),
            path_bytes=(b"unused-root",),
        ) is False
        assert injected
        assert reaped
    finally:
        if not reaped:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)


def test_buildx_user_census_retries_live_procfs_failure_then_detects_reference(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    _, _, _, _, child_start = module._process_record(child)
    attempts = 0

    def fail_once_then_reference(_candidate, _paths, _path_bytes):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise FileNotFoundError("injected live fd-entry disappearance")
        return True

    monkeypatch.setattr(module, "BUILDX_CENSUS_RETRY_SECONDS", 0)
    monkeypatch.setattr(
        module,
        "_read_buildx_process_references",
        fail_once_then_reference,
    )
    try:
        assert module._process_references_buildx_candidate(
            child,
            Path(f"/proc/{child}"),
            threshold=child_start,
            paths=(guardian_bundle[2] / "unused-root",),
            path_bytes=(b"unused-root",),
        ) is True
        assert attempts == 2
    finally:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)


def test_buildx_user_census_live_indeterminate_failure_remains_fail_closed(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    _, _, _, _, child_start = module._process_record(child)
    attempts = 0

    def always_fail(_candidate, _paths, _path_bytes):
        nonlocal attempts
        attempts += 1
        raise PermissionError("injected live procfs denial")

    monkeypatch.setattr(module, "BUILDX_CENSUS_RETRY_SECONDS", 0)
    monkeypatch.setattr(module, "_read_buildx_process_references", always_fail)
    try:
        with pytest.raises(
            module.GuardianError,
            match="cannot inspect a possible Buildx config user",
        ):
            module._process_references_buildx_candidate(
                child,
                Path(f"/proc/{child}"),
                threshold=child_start,
                paths=(guardian_bundle[2] / "unused-root",),
                path_bytes=(b"unused-root",),
            )
        assert attempts == module.BUILDX_CENSUS_ATTEMPTS
    finally:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)


def test_buildx_user_census_pid_reuse_identity_change_fails_closed(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    real_process_record = module._process_record
    _, _, _, _, child_start = real_process_record(child)
    reads = 0

    def reused_identity(pid: int):
        nonlocal reads
        observed = real_process_record(pid)
        if pid == child:
            reads += 1
            if reads > 1:
                return (*observed[:4], observed[4] + 1)
        return observed

    monkeypatch.setattr(module, "_process_record", reused_identity)
    monkeypatch.setattr(module, "_read_buildx_process_references", lambda *_args: False)
    try:
        with pytest.raises(
            module.GuardianError,
            match="Buildx process census identity changed",
        ):
            module._process_references_buildx_candidate(
                child,
                Path(f"/proc/{child}"),
                threshold=child_start,
                paths=(guardian_bundle[2] / "unused-root",),
                path_bytes=(b"unused-root",),
            )
    finally:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)


def test_buildx_user_census_reinspects_numeric_pid_after_terminal_binding(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    _, _, _, _, child_start = module._process_record(child)
    real_open = module._open_process_pidfd
    opens = 0
    polls = 0

    def counted_open(pid: int):
        nonlocal opens
        opens += 1
        return real_open(pid)

    def old_binding_then_live_replacement(_pidfd: int, _timeout_ms: int = 0):
        nonlocal polls
        polls += 1
        return polls == 1

    monkeypatch.setattr(module, "_open_process_pidfd", counted_open)
    monkeypatch.setattr(module, "_pidfd_is_terminal", old_binding_then_live_replacement)
    monkeypatch.setattr(module, "_read_buildx_process_references", lambda *_args: True)
    try:
        assert module._process_references_buildx_candidate(
            child,
            Path(f"/proc/{child}"),
            threshold=child_start,
            paths=(guardian_bundle[2] / "unused-root",),
            path_bytes=(b"unused-root",),
        ) is True
        assert opens == 2
    finally:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)


def test_buildx_user_census_pidfd_resource_failure_remains_fail_closed(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])

    def fail_pidfd_open(_pid: int, _flags: int):
        raise OSError(errno.EMFILE, "injected pidfd resource exhaustion")

    monkeypatch.setattr(module.os, "pidfd_open", fail_pidfd_open)
    with pytest.raises(
        module.GuardianError,
        match=r"cannot bind a possible Buildx config user PID 12345 \(errno 24\)",
    ):
        module._process_references_buildx_candidate(
            12345,
            Path("/proc/12345"),
            threshold=1,
            paths=(guardian_bundle[2] / "unused-root",),
            path_bytes=(b"unused-root",),
        )


def test_buildx_user_census_restarts_whole_snapshot_after_pid_becomes_tid(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    _, _, _, _, child_start = module._process_record(child)
    ledger = _buildx_census_ledger(module, guardian_bundle[2], child_start)
    real_pidfd_open = module.os.pidfd_open
    child_opens = 0

    def invalid_tid_once(pid: int, flags: int):
        nonlocal child_opens
        if pid == child:
            child_opens += 1
            if child_opens == 1:
                raise OSError(errno.EINVAL, "injected numeric PID to TID reuse")
        return real_pidfd_open(pid, flags)

    monkeypatch.setattr(module.os, "pidfd_open", invalid_tid_once)
    monkeypatch.setattr(
        module,
        "_read_buildx_process_references",
        lambda candidate, _paths, _path_bytes: int(candidate.name) == child,
    )
    try:
        assert module._process_references_buildx(ledger) is True
        assert child_opens == 2
    finally:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)


def test_buildx_user_census_pid_to_tid_churn_exhaustion_fails_closed(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    _, _, _, _, child_start = module._process_record(child)
    ledger = _buildx_census_ledger(module, guardian_bundle[2], child_start)
    real_pidfd_open = module.os.pidfd_open
    child_opens = 0

    def persistent_tid_reuse(pid: int, flags: int):
        nonlocal child_opens
        if pid == child:
            child_opens += 1
            raise OSError(errno.EINVAL, "injected persistent PID to TID churn")
        return real_pidfd_open(pid, flags)

    monkeypatch.setattr(module, "BUILDX_CENSUS_RETRY_SECONDS", 0)
    monkeypatch.setattr(module.os, "pidfd_open", persistent_tid_reuse)
    try:
        with pytest.raises(
            module.GuardianError,
            match="Buildx process census did not reach a stable process list",
        ):
            module._process_references_buildx(ledger)
        assert child_opens == module.BUILDX_CENSUS_ATTEMPTS
    finally:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)


@pytest.mark.parametrize("field", ["boot_id", "guardian_pid"])
def test_corrupt_buildx_authority_is_quarantined_without_mutation(
    guardian_bundle: tuple[Path, Path, Path, Path], field: str
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    _wait(state / "ready")
    child = int((state / "inner-pid").read_text(encoding="ascii"))
    inner_marker = (state / "inner-pid").read_bytes()
    os.kill(process.pid, signal.SIGKILL)
    assert process.wait(timeout=5) == -signal.SIGKILL
    _wait_gone(child)
    authority = next(guardian_bundle[2].glob(".qcsd-buildx-authority-*"))
    record = json.loads(authority.read_text(encoding="ascii"))
    if field == "boot_id":
        record[field] = "x" * 36
    else:
        record[field] = int(record[field]) + 1
    corrupted = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    authority.write_text(corrupted, encoding="ascii")
    before = authority.read_bytes()
    root = guardian_bundle[2] / record["root_name"]

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode != 0, (result.stdout, result.stderr)
    assert authority.read_bytes() == before
    assert root.is_dir()
    assert (state / "inner-pid").read_bytes() == inner_marker


def test_unknown_buildx_root_is_quarantined_without_child_admission(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    root = guardian_bundle[2] / (
        f".qcsd-buildx-config-{os.getuid()}." + "c" * 64
    )
    root.mkdir(mode=0o700)

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode != 0, (result.stdout, result.stderr)
    assert root.is_dir()
    assert not (guardian_bundle[3] / "inner-pid").exists()


def test_buildx_intent_only_empty_root_recovers_without_authorising_content(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module, parent_fd, lock_fd, lock, source_fd, source = (
        _direct_buildx_context(guardian_bundle)
    )
    token = "d" * 64
    root_name = f".qcsd-buildx-config-{os.getuid()}.{token}"
    intent_name = f".qcsd-buildx-intent-{os.getuid()}.{token}"
    parent = os.fstat(parent_fd)
    try:
        module._write_exact_record(
            parent_fd,
            intent_name,
            module._intent_value(token, root_name, parent, lock, source),
        )
        os.mkdir(root_name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)

        recovered = module._recover_buildx_ledgers(
            parent_fd, os.getpid(), lock
        )

        assert recovered == []
        assert not (guardian_bundle[2] / root_name).exists()
        assert not (guardian_bundle[2] / intent_name).exists()
    finally:
        os.close(source_fd)
        os.close(lock_fd)
        os.close(parent_fd)


def test_buildx_staged_authority_is_reproved_and_promoted_on_restart(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module, parent_fd, lock_fd, lock, source_fd, source = (
        _direct_buildx_context(guardian_bundle)
    )
    buildx_fd = -1
    try:
        buildx_fd, _, ledgers = module._prepare_buildx_config(
            parent_fd, os.getpid(), lock, source
        )
        ledger = ledgers[-1]
        staged_name = ledger.authority.name + ".next"
        os.rename(
            ledger.authority.name,
            staged_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        parent = os.fstat(parent_fd)
        intent_name = f".qcsd-buildx-intent-{os.getuid()}.{ledger.token}"
        module._write_exact_record(
            parent_fd,
            intent_name,
            module._intent_value(
                ledger.token, ledger.root_name, parent, lock, source
            ),
        )
        os.fsync(parent_fd)

        recovered = module._recover_buildx_ledgers(
            parent_fd, os.getpid(), lock
        )

        assert len(recovered) == 1
        assert recovered[0].authority.name == ledger.authority.name
        assert not (guardian_bundle[2] / staged_name).exists()
        assert not (guardian_bundle[2] / intent_name).exists()
        module._cleanup_buildx_ledgers(
            parent_fd, os.getpid(), lock, recovered
        )
        assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    finally:
        if buildx_fd >= 0:
            os.close(buildx_fd)
        os.close(source_fd)
        os.close(lock_fd)
        os.close(parent_fd)


def test_only_validated_acquisition_lock_is_preserved_into_inner(
    guardian_bundle: tuple[Path, Path, Path, Path], tmp_path: Path
) -> None:
    acquisition = tmp_path / "acquisition.lock"
    acquisition.touch(mode=0o600)
    descriptor = os.open(acquisition, os.O_RDWR | os.O_CLOEXEC)
    process: subprocess.Popen[str] | None = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        environment = {
            **os.environ,
            "QCSD_CLASS_ACQUISITION_LOCK_FD": str(descriptor),
        }
        process = subprocess.Popen(
            _guardian_command(guardian_bundle, "acquisition-wait"),
            env=environment,
            pass_fds=(descriptor,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        state = guardian_bundle[3]
        _wait(state / "ready")
        expected = acquisition.stat(follow_symlinks=False)
        assert (state / "acquisition-identity").read_text(encoding="ascii").strip() == (
            f"{expected.st_dev}:{expected.st_ino}"
        )
        guardian_matches = []
        for candidate in Path(f"/proc/{process.pid}/fd").iterdir():
            try:
                observed = candidate.stat()
            except OSError:
                continue
            if (observed.st_dev, observed.st_ino) == (
                expected.st_dev,
                expected.st_ino,
            ):
                guardian_matches.append(candidate.name)
        assert guardian_matches == []
        (state / "release").touch()
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, (stdout, stderr)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(descriptor)


def test_guardian_sigkill_kills_inner_and_releases_unleased_lock(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    _wait(state / "ready")
    child = int((state / "inner-pid").read_text(encoding="ascii"))
    assert not _can_lock(_lock_path(guardian_bundle))

    os.kill(process.pid, signal.SIGKILL)
    assert process.wait(timeout=5) == -signal.SIGKILL
    _wait_gone(child)
    assert _can_lock(_lock_path(guardian_bundle))


def test_child_sigkill_drains_same_session_orphan_before_unlock(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "child-kill")

    assert result.returncode == 137, (result.stdout, result.stderr)
    orphan = int((guardian_bundle[3] / "orphan-pid").read_text(encoding="ascii"))
    _wait_gone(orphan)
    assert _can_lock(_lock_path(guardian_bundle))


def test_signal_before_ready_is_forwarded_once_after_handshake(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "pre-ready-signal"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    _wait(state / "pre-ready")
    os.kill(process.pid, signal.SIGTERM)
    os.kill(process.pid, signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=8)

    assert process.returncode == 143, (stdout, stderr)
    assert (state / "signals").read_text(encoding="ascii").strip() == "1"
    assert not (state / "mutation-after-go").exists()
    assert _can_lock(_lock_path(guardian_bundle))


def test_pending_signal_at_admission_linearisation_cannot_publish_go(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    latch = module._SignalLatch()
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    monkeypatch.setattr(module.signal, "sigpending", lambda: {signal.SIGTERM})
    try:
        admitted, failed = module._publish_admission_decision(
            write_fd,
            "a" * 64,
            latch,
            ready=True,
            failed=False,
        )
        os.close(write_fd)
        write_fd = -1

        assert not admitted
        assert not failed
        assert os.read(read_fd, 64) == b"ABORT\n"
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)


def test_bad_client_flood_cannot_starve_signal_or_child_exit(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    clients: list[socket.socket] = []
    state = guardian_bundle[3]
    try:
        _wait(state / "ready")
        endpoint = f"\0qcsd-docker-lifecycle-guardian-{os.getuid()}"
        for _ in range(8):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(1)
            client.connect(endpoint)
            client.sendall(b"{")
            clients.append(client)

        started = time.monotonic()
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=1.5)
        elapsed = time.monotonic() - started

        assert process.returncode == 143, (stdout, stderr)
        assert elapsed < 1.5
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        for client in clients:
            client.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_ready_timeout_kills_inner_before_admission(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = subprocess.run(
        _guardian_command(guardian_bundle, "never-ready", ready_timeout=0.15),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    inner = int((guardian_bundle[3] / "inner-pid").read_text(encoding="ascii"))
    _wait_gone(inner)
    assert _can_lock(_lock_path(guardian_bundle))


def test_ready_then_qcsd_cmdline_drift_is_aborted_without_go(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "ready-cmdline-drift")

    assert result.returncode == 125, (result.stdout, result.stderr)
    inner = int((guardian_bundle[3] / "inner-pid").read_text(encoding="ascii"))
    _wait_gone(inner)
    assert _can_lock(_lock_path(guardian_bundle))


def test_post_fork_guardian_exception_drains_inner_before_unlock(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "never-ready",
            inject_wait_failure=True,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )

    assert result.returncode != 0
    inner = int((guardian_bundle[3] / "inner-pid").read_text(encoding="ascii"))
    _wait_gone(inner)
    assert _can_lock(_lock_path(guardian_bundle))


@pytest.mark.parametrize("mode", ["non-native-lease", "foreign-session-lease"])
def test_lease_is_denied_to_every_non_native_requester(
    guardian_bundle: tuple[Path, Path, Path, Path], mode: str
) -> None:
    result = _run_guardian(guardian_bundle, mode)

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / f"{mode}-result").read_text(
        encoding="ascii"
    ) == "b'':0"
    assert _can_lock(_lock_path(guardian_bundle))


def test_native_source_never_exposes_a_flock_unlock() -> None:
    source = NATIVE.read_text(encoding="utf-8")

    assert "import fcntl" not in source
    assert "LOCK_UN" not in source
    assert "MSG_CMSG_CLOEXEC" in source


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")),
        lambda value: json.dumps(value, sort_keys=False) + "\n",
        lambda value: json.dumps(
            {**value, "schema": True}, sort_keys=True, separators=(",", ":")
        )
        + "\n",
        lambda value: json.dumps(
            {key: item for key, item in value.items() if key != "action"},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    ],
)
def test_malformed_lease_requests_are_rejected_before_identity_use(
    mutation, guardian_bundle: tuple[Path, Path, Path, Path]
) -> None:
    module = _load_guardian(guardian_bundle[0])
    valid = {
        "action": "publish",
        "argv_sha256": "a" * 64,
        "helper_source_sha256": "b" * 64,
        "lease_nonce": "c" * 64,
        "qcsd_pid": 10,
        "qcsd_start_time": 20,
        "requester_pid": 30,
        "requester_start_time": 40,
        "schema": 1,
    }

    with pytest.raises(module.GuardianError):
        module._canonical_lease_request(mutation(valid).encode("ascii"))


def test_guardian_sigkill_leaves_lock_with_only_the_active_native_lease(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "lease"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    _wait(state / "lease-ready")
    lease_holder = int((state / "lease-ready").read_text(encoding="ascii"))
    original_lock = _lock_path(guardian_bundle)
    moved_lock = original_lock.with_name("superseded-lifecycle.lock")
    original_lock.rename(moved_lock)
    original_lock.touch(mode=0o600)
    os.kill(process.pid, signal.SIGKILL)
    assert process.wait(timeout=5) == -signal.SIGKILL

    assert _process_state(lease_holder) not in (None, "Z")
    competitor: subprocess.Popen[str] | None = None
    try:
        competitor = subprocess.Popen(
            _guardian_command(guardian_bundle, "success"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        time.sleep(0.15)
        assert competitor.poll() is None
        assert not _can_lock(moved_lock)
        _wait_gone(lease_holder, timeout=4)
        stdout, stderr = competitor.communicate(timeout=5)
        # Once the leased mutation releases the singleton, the durable Buildx
        # authority still binds the superseded lock inode. A new guardian must
        # quarantine the replacement instead of admitting.
        assert competitor.returncode != 0, (stdout, stderr)
        assert _can_lock(moved_lock)
        assert _can_lock(original_lock)
        assert _can_lock(moved_lock)
    finally:
        if competitor is not None and competitor.poll() is None:
            os.killpg(competitor.pid, signal.SIGKILL)
            competitor.wait(timeout=5)


def test_guardian_sigkill_creation_holder_blocks_until_writers_drain(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "creation-hold"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    competitor: subprocess.Popen[str] | None = None
    state = guardian_bundle[3]
    try:
        _wait(state / "creation-held")
        holder = int((state / "creation-holder-pid").read_text(encoding="ascii"))
        descendant = int(
            (state / "creation-descendant-pid").read_text(encoding="ascii")
        )
        os.kill(process.pid, signal.SIGKILL)
        assert process.wait(timeout=5) == -signal.SIGKILL
        assert _process_state(holder) not in (None, "Z")
        assert _process_state(descendant) not in (None, "Z")

        competitor = subprocess.Popen(
            _guardian_command(guardian_bundle, "success"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        time.sleep(0.15)
        assert competitor.poll() is None
        assert not _can_lock(_lock_path(guardian_bundle))

        _wait_gone(descendant, timeout=3)
        _wait_gone(holder, timeout=3)
        stdout, stderr = competitor.communicate(timeout=5)
        assert competitor.returncode == 0, (stdout, stderr)
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        for candidate in (process, competitor):
            if candidate is not None and candidate.poll() is None:
                os.killpg(candidate.pid, signal.SIGKILL)
                candidate.wait(timeout=5)


def test_creation_holder_releases_only_after_durable_supervision_commit(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "creation-hold"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    try:
        _wait(state / "creation-held")
        assert not _can_lock(_lock_path(guardian_bundle))
        (state / "release").touch()
        stdout, stderr = process.communicate(timeout=5)

        assert process.returncode == 0, (stdout, stderr)
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_creation_holder_cancel_removes_only_its_bound_partial_root(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "creation-cancel")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / "creation-cancelled").is_file()
    assert not (
        guardian_bundle[3]
        / "creation-base"
        / f"run.{'a' * 32}"
    ).exists()
    assert _can_lock(_lock_path(guardian_bundle))


def test_creation_holder_rejects_before_parent_exits_and_leases_drain(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "creation-reject")

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / "creation-result").read_text(
        encoding="ascii"
    ).strip() == "QCSD-CREATION-HOLD-REJECTED-V1"
    assert _can_lock(_lock_path(guardian_bundle))


def test_api_holder_runs_from_a_command_substitution_and_returns_output(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "api-command-substitution")
    state = guardian_bundle[3]

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (state / "api-started").read_text(encoding="ascii") == "started\n"
    assert (state / "api-completed").read_text(encoding="ascii") == "completed\n"
    assert (state / "api-output").read_text(
        encoding="ascii"
    ) == "captured-output\n"


@pytest.mark.parametrize(
    ("kill_target", "requested"),
    [
        ("guardian", signal.SIGKILL),
        ("guardian", signal.SIGTERM),
        ("inner", signal.SIGKILL),
    ],
)
def test_guardian_exit_cannot_admit_a_successor_during_api_service(
    guardian_bundle: tuple[Path, Path, Path, Path],
    kill_target: str,
    requested: signal.Signals,
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "api-command-substitution"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    competitor: subprocess.Popen[str] | None = None
    state = guardian_bundle[3]
    try:
        (state / "require-config-gate").write_text("required\n", encoding="ascii")
        _wait(state / "api-started", timeout=8)
        service_pid = int((state / "service-pid").read_text(encoding="ascii"))
        target_pid = process.pid
        if kill_target == "inner":
            target_pid = int((state / "inner-pid").read_text(encoding="ascii"))
        os.kill(target_pid, requested)
        observed_status = process.wait(timeout=5)
        if kill_target == "guardian" and requested == signal.SIGKILL:
            assert observed_status == -signal.SIGKILL
        else:
            assert observed_status != 0
        assert _process_state(service_pid) not in (None, "Z")
        (state / "open-configs-now").write_text("open\n", encoding="ascii")
        _wait(state / "api-configs-opened", timeout=5)

        competitor = subprocess.Popen(
            _guardian_command(guardian_bundle, "api-successor"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        time.sleep(0.2)
        assert competitor.poll() is None
        assert not _can_lock(_lock_path(guardian_bundle))
        assert not (state / "successor-api-started").exists()

        _wait(state / "api-completed", timeout=5)
        _wait_gone(service_pid, timeout=5)
        stdout, stderr = competitor.communicate(timeout=8)
        assert competitor.returncode == 0, (stdout, stderr)
        assert (state / "successor-api-started").is_file()
        original_unit = f"qcsd-docker-api-{'a':0>32}.service"
        unit = subprocess.run(
            [
                "/usr/bin/systemctl",
                "--user",
                "show",
                "--property=LoadState",
                "--property=ControlGroup",
                "--",
                original_unit,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert unit.returncode == 0, unit.stderr
        assert "LoadState=not-found\n" in unit.stdout
        assert "ControlGroup=\n" in unit.stdout
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        for candidate in (process, competitor):
            if candidate is not None and candidate.poll() is None:
                os.killpg(candidate.pid, signal.SIGKILL)
                candidate.wait(timeout=5)


@pytest.mark.parametrize("failure", ["outside-unit", "manager-drift"])
def test_api_transfer_denies_unbound_or_drifting_same_uid_wrapper(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    native = _load_native(guardian_bundle[0].parent / NATIVE.name)
    listener, endpoint = native._api_listener()
    nonce = "d" * 64
    marker = guardian_bundle[3] / "racing-wrapper-rights"
    client_source = textwrap.dedent(
        """\
        import array, hashlib, json, os, socket, sys
        payload = open('/proc/self/cmdline', 'rb').read()
        stat = open('/proc/self/stat', encoding='ascii').read().rsplit(') ', 1)[1].split()
        request = {
            'argv_sha256': hashlib.sha256(payload).hexdigest(),
            'nonce': sys.argv[2],
            'pid': os.getpid(),
            'schema': 1,
            'start_time': int(stat[19]),
            'watcher_pid': int(sys.argv[3]),
            'watcher_start_time': int(sys.argv[4]),
        }
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect('\\0' + sys.argv[1][1:])
        encoded = json.dumps(request, sort_keys=True, separators=(',', ':'))
        connection.sendall((encoded + '\\n').encode('ascii'))
        descriptors = array.array('i')
        message, ancillary, flags, _ = connection.recvmsg(64, socket.CMSG_SPACE(8))
        open(sys.argv[5], 'w', encoding='ascii').write(str(len(ancillary)))
        """
    )
    watcher_pid = os.getpid()
    watcher_start = native._process_start_time(watcher_pid)
    command = (
        sys.executable,
        "-I",
        "-c",
        client_source,
        endpoint,
        nonce,
        str(watcher_pid),
        str(watcher_start),
        str(marker),
    )
    client = subprocess.Popen(command)
    lock_path = guardian_bundle[3] / "fake-api-lock"
    lock_path.touch(mode=0o600)
    lock_fd = os.open(lock_path, os.O_RDONLY | os.O_CLOEXEC)
    docker_config = guardian_bundle[3] / "fake-docker-config"
    buildx_config = guardian_bundle[3] / "fake-buildx-config"
    docker_config.mkdir(mode=0o700)
    buildx_config.mkdir(mode=0o700)
    docker_config_fd = os.open(docker_config, os.O_RDONLY | os.O_DIRECTORY)
    buildx_config_fd = os.open(buildx_config, os.O_RDONLY | os.O_DIRECTORY)
    try:
        unit = f"qcsd-docker-api-{'e' * 32}.service"
        control_group = (
            f"/user.slice/user-{os.getuid()}.slice/"
            f"user@{os.getuid()}.service/app.slice/{unit}"
        )
        snapshots = iter(
            [
                ("loaded", "active", control_group, client.pid),
                ("loaded", "active", control_group, client.pid + 1),
            ]
        )
        if failure == "outside-unit":
            monkeypatch.setattr(
                native,
                "_systemd_unit_snapshot",
                lambda _unit: (
                    "loaded", "active", control_group, client.pid + 1
                ),
            )
        else:
            monkeypatch.setattr(
                native, "_systemd_unit_snapshot", lambda _unit: next(snapshots)
            )
            original_read_text = native.Path.read_text

            def read_text(path: Path, *args: object, **kwargs: object) -> str:
                if path == Path(f"/proc/{client.pid}/cgroup"):
                    return f"0::{control_group}\n"
                return original_read_text(path, *args, **kwargs)

            monkeypatch.setattr(native.Path, "read_text", read_text)
        deadline = time.monotonic() + 3
        while True:
            try:
                accepted = native._transfer_api_lease(
                    listener,
                    unit=unit,
                    expected_command=command,
                    nonce=nonce,
                    watcher_pid=watcher_pid,
                    watcher_start=watcher_start,
                    lease_fd=lock_fd,
                    singleton_fd=listener.fileno(),
                    docker_config_fd=docker_config_fd,
                    buildx_config_fd=buildx_config_fd,
                )
            except RuntimeError as error:
                expected = (
                    "outside its exact unit"
                    if failure == "outside-unit"
                    else "raced manager validation"
                )
                assert expected in str(error)
                break
            if accepted:
                raise AssertionError("non-unit wrapper received lifecycle authority")
            if time.monotonic() >= deadline:
                raise AssertionError("racing wrapper did not connect")
            time.sleep(0.01)
        assert client.wait(timeout=3) == 0
        assert marker.read_text(encoding="ascii") == "0"
    finally:
        listener.close()
        os.close(lock_fd)
        os.close(docker_config_fd)
        os.close(buildx_config_fd)


def test_normal_pretransfer_manager_rejection_releases_safely(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _load_native(guardian_bundle[0].parent / NATIVE.name)

    class RejectedLauncher:
        returncode = 1

        @staticmethod
        def poll() -> int:
            return 1

    monkeypatch.setattr(native, "_systemd_unit_snapshot", lambda _unit: (
        "not-found", "inactive", "", 0
    ))
    monkeypatch.setattr(native.subprocess, "Popen", lambda *_args, **_kwargs: RejectedLauncher())
    singleton, _ = native._api_listener()
    lock_path = guardian_bundle[3] / "manager-rejection-lock"
    lock_path.touch(mode=0o600)
    lock_fd = os.open(lock_path, os.O_RDONLY | os.O_CLOEXEC)
    source_fd = os.open(guardian_bundle[0].parent / NATIVE.name, os.O_RDONLY)
    docker_config_fd = os.open(guardian_bundle[3], os.O_RDONLY | os.O_DIRECTORY)
    buildx_config_fd = os.dup(docker_config_fd)
    try:
        assert native._watch_api_service(
            unit=f"qcsd-docker-api-{'f' * 32}.service",
            duration=1,
            command=("/bin/true",),
            native_source_fd=source_fd,
            native_source_hash=hashlib.sha256(
                (guardian_bundle[0].parent / NATIVE.name).read_bytes()
            ).hexdigest(),
            lease_fd=lock_fd,
            singleton_fd=singleton.fileno(),
            docker_config_fd=docker_config_fd,
            buildx_config_fd=buildx_config_fd,
        ) == 125
    finally:
        os.close(source_fd)
        os.close(lock_fd)
        os.close(docker_config_fd)
        os.close(buildx_config_fd)
        singleton.close()


@pytest.mark.parametrize("ambiguous_status", [124, 137])
def test_pretransfer_timeout_or_signal_retains_authority(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    ambiguous_status: int,
) -> None:
    native = _load_native(guardian_bundle[0].parent / NATIVE.name)

    class AmbiguousLauncher:
        returncode = ambiguous_status

        @staticmethod
        def poll() -> int:
            return ambiguous_status

    monkeypatch.setattr(native, "_systemd_unit_snapshot", lambda _unit: (
        "not-found", "inactive", "", 0
    ))
    monkeypatch.setattr(native.subprocess, "Popen", lambda *_args, **_kwargs: AmbiguousLauncher())
    singleton, _ = native._api_listener()
    lock_path = guardian_bundle[3] / f"ambiguous-{ambiguous_status}-lock"
    lock_path.touch(mode=0o600)
    lock_fd = os.open(lock_path, os.O_RDONLY | os.O_CLOEXEC)
    source_fd = os.open(guardian_bundle[0].parent / NATIVE.name, os.O_RDONLY)
    docker_config_fd = os.open(guardian_bundle[3], os.O_RDONLY | os.O_DIRECTORY)
    buildx_config_fd = os.dup(docker_config_fd)
    child = os.fork()
    if child == 0:
        native._watch_api_service(
            unit=f"qcsd-docker-api-{'f' * 32}.service",
            duration=1,
            command=("/bin/true",),
            native_source_fd=source_fd,
            native_source_hash="f" * 64,
            lease_fd=lock_fd,
            singleton_fd=singleton.fileno(),
            docker_config_fd=docker_config_fd,
            buildx_config_fd=buildx_config_fd,
        )
        os._exit(99)
    try:
        time.sleep(0.25)
        assert os.waitpid(child, os.WNOHANG) == (0, 0)
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(child, 0)
        os.close(source_fd)
        os.close(lock_fd)
        os.close(docker_config_fd)
        os.close(buildx_config_fd)
        singleton.close()


@pytest.mark.parametrize("kind", ["run", "network", "build", "transaction"])
def test_real_helper_rejection_exits_without_waiting_and_drains_holder(
    guardian_bundle: tuple[Path, Path, Path, Path], kind: str
) -> None:
    result = _run_guardian(guardian_bundle, f"real-helper-reject-{kind}")
    state = guardian_bundle[3]

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert (state / "real-helper-exit-trap").read_text(
        encoding="ascii"
    ) == "exit\n"
    holder_path = state / "real-helper-holder-pid"
    assert holder_path.is_file(), (
        result.stdout,
        result.stderr,
        tuple(path.name for path in state.iterdir()),
    )
    holder = int(holder_path.read_text(encoding="ascii"))
    _wait_gone(holder)
    assert _can_lock(_lock_path(guardian_bundle))

    root = Path((state / "real-helper-root").read_text(encoding="ascii").strip())
    successor = _run_guardian(guardian_bundle, f"real-helper-recover-{kind}")
    assert successor.returncode == 0, (successor.stdout, successor.stderr)
    assert (state / "real-helper-recovered").is_file()
    assert not root.exists()


def test_real_guardian_successor_resumes_h3_after_escaped_api(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    first = _run_guardian(guardian_bundle, "real-helper-reject-run")
    assert first.returncode == 125, (first.stdout, first.stderr)
    root = Path((state / "real-helper-root").read_text(encoding="ascii").strip())
    authority = root.parent / f"retirement.{root.name}"

    creator = subprocess.Popen(
        _guardian_command(guardian_bundle, "real-helper-h3-api-run"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    _wait(state / "h3-api-started", timeout=10)
    _wait(state / "h3-seen", timeout=10)
    assert creator.wait(timeout=10) == -signal.SIGKILL
    assert root.is_dir() and authority.is_file()
    assert int((state / "h3-buildx-nlink").read_text(encoding="ascii")) > 2
    old_docker = Path((state / "h3-old-docker-config").read_text().strip())
    old_buildx = Path((state / "h3-old-buildx-config").read_text().strip())
    assert not old_docker.exists()
    assert not old_buildx.exists()
    buildx_authorities = tuple(
        guardian_bundle[2].glob(f".qcsd-buildx-authority-{os.getuid()}.*")
    )
    assert len(buildx_authorities) == 1
    buildx_record = json.loads(buildx_authorities[0].read_text(encoding="ascii"))
    linked_buildx = guardian_bundle[2] / buildx_record["root_name"]
    linked_identity = linked_buildx.stat(follow_symlinks=False)
    assert linked_identity.st_nlink > 2

    census_candidate = subprocess.Popen(
        ["/bin/sleep", "30"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    (state / "census-reap-pid").write_text(
        f"{census_candidate.pid}\n", encoding="ascii"
    )
    successor: subprocess.Popen[str] | None = None
    try:
        successor = subprocess.Popen(
            _guardian_command(
                guardian_bundle,
                "real-helper-recover-run",
                reap_during_buildx_census=True,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        time.sleep(0.25)
        assert successor.poll() is None
        assert root.is_dir() and authority.is_file()
        current_linked = linked_buildx.stat(follow_symlinks=False)
        assert (current_linked.st_dev, current_linked.st_ino) == (
            linked_identity.st_dev,
            linked_identity.st_ino,
        )
        assert not (state / "real-helper-recovered").exists()

        (state / "h3-api-release").touch()
        _wait(state / "census-reap-inspection", timeout=10)
        census_candidate.kill()
        assert census_candidate.wait(timeout=5) == -signal.SIGKILL
        (state / "census-reap-complete").touch()
        successor_stdout, successor_stderr = successor.communicate(timeout=15)
        assert successor.returncode == 0, (successor_stdout, successor_stderr)
        assert (state / "census-reap-inspection").is_file()
        assert (state / "h3-api-terminal").is_file()
        assert (state / "real-helper-recovered").is_file()
        assert not root.exists() and not authority.exists()
        assert not tuple(root.parent.glob(".retired.*"))
        assert not linked_buildx.exists()
        assert not buildx_authorities[0].exists()
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if census_candidate.poll() is None:
            census_candidate.kill()
        census_candidate.wait(timeout=5)
        if successor is not None and successor.poll() is None:
            os.killpg(successor.pid, signal.SIGKILL)
            successor.communicate(timeout=5)


@pytest.mark.parametrize("kind", ["run", "build"])
def test_real_guardian_successor_contains_authenticated_stopped_launcher(
    guardian_bundle: tuple[Path, Path, Path, Path], kind: str
) -> None:
    state = guardian_bundle[3]
    decoy = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
    launcher: int | None = None
    creator = subprocess.Popen(
        _guardian_command(guardian_bundle, f"real-helper-launch-crash-{kind}"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 12
        while not (state / "real-launch-crash").exists() and time.monotonic() < deadline:
            if creator.poll() is not None:
                out, err = creator.communicate()
                raise AssertionError((creator.returncode, out, err))
            time.sleep(0.01)
        assert (state / "real-launch-crash").is_file()
        launcher_text, root_text = (state / "real-launch-crash").read_text(
            encoding="ascii"
        ).split()
        launcher = int(launcher_text)
        root = Path(root_text)
        assert creator.wait(timeout=10) == -signal.SIGKILL
        assert _process_state(launcher) == "T"
        supervision = (root / "SUPERVISION").read_text(encoding="ascii")
        birth = (root / "launcher.birth").read_text(encoding="ascii")
        assert "lifecycle_state=declared\n" in supervision
        assert f"launcher_kind={kind}\n" in birth
        assert f"launcher_pid={launcher}\n" in birth
        assert decoy.poll() is None

        successor = _run_guardian(
            guardian_bundle, f"real-helper-recover-{kind}", timeout=15
        )
        assert successor.returncode == 0, (successor.stdout, successor.stderr)
        _wait_gone(launcher)
        assert not root.exists()
        assert decoy.poll() is None
        calls = (state / "calls.log").read_text(encoding="ascii") \
            if (state / "calls.log").exists() else ""
        assert "RUN " not in calls and "BUILD " not in calls
    finally:
        if creator.poll() is None:
            os.killpg(creator.pid, signal.SIGKILL)
            creator.wait(timeout=5)
        if launcher is not None and _process_state(launcher) is not None:
            os.killpg(launcher, signal.SIGKILL)
            _wait_gone(launcher)
        if decoy.poll() is None:
            os.killpg(decoy.pid, signal.SIGKILL)
            decoy.wait(timeout=5)


@pytest.mark.parametrize("case", ["early", "cross-root", "wrong-token"])
def test_creation_commit_rejects_missing_or_misbound_supervision(
    guardian_bundle: tuple[Path, Path, Path, Path], case: str
) -> None:
    native = _load_native(guardian_bundle[0].parent / NATIVE.name)
    base = guardian_bundle[3] / "commit-base"
    base.mkdir(mode=0o700)
    root_name = f"run.{'a' * 32}"
    root = base / root_name
    root.mkdir(mode=0o700)
    if case != "early":
        destination = root
        token = "b" * 32 if case == "wrong-token" else "a" * 32
        if case == "cross-root":
            destination = base / f"run.{'b' * 32}"
            destination.mkdir(mode=0o700)
        supervision = destination / "SUPERVISION"
        supervision.write_text(
            "object=docker-run-scope-launcher\n"
            f"lifecycle_root={destination}\n"
            f"lifecycle_token={token}\n",
            encoding="ascii",
        )
        supervision.chmod(0o600)
    base_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    root_value = root.stat(follow_symlinks=False)
    try:
        assert not native._durable_initial_supervision(
            base_fd,
            str(base),
            os.getuid(),
            root_name,
            root_value.st_dev,
            root_value.st_ino,
        )
    finally:
        os.close(base_fd)


def test_guardian_detects_its_source_changing_before_ready(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    guardian = guardian_bundle[0]
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "pre-ready-signal"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    _wait(state / "pre-ready")
    guardian.write_bytes(guardian.read_bytes() + b"\n")
    guardian.chmod(0o600)
    stdout, stderr = process.communicate(timeout=8)

    assert process.returncode == 125, (stdout, stderr)
    assert _can_lock(_lock_path(guardian_bundle))


def test_held_entry_source_rejects_atomic_path_replacement_before_admission(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    guardian, qcsd, lock_parent, state = guardian_bundle
    harness = textwrap.dedent(
        """\
        import importlib.util
        import os
        from pathlib import Path
        import sys

        source = Path(sys.argv[1])
        spec = importlib.util.spec_from_file_location(
            "qcsd_guardian_entry_race", source
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        descriptor = os.open(source, os.O_RDONLY)
        moved = source.with_name("loaded-guardian")
        source.rename(moved)
        source.write_bytes(moved.read_bytes() + b"\\n")
        source.chmod(0o600)
        try:
            module.guard(
                (sys.argv[2], "success", sys.argv[3]),
                source_path=source,
                source_descriptor=descriptor,
                lock_parent=Path(sys.argv[4]),
            )
        except module.GuardianError:
            raise SystemExit(125)
        raise SystemExit(99)
        """
    )

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            harness,
            str(guardian),
            str(qcsd),
            str(state),
            str(lock_parent),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert not _lock_path(guardian_bundle).exists()
    assert not (state / "inner-pid").exists()


def test_captured_qcsd_fd_prevents_replacement_execution_before_ready(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "pre-ready-signal",
            replace_qcsd_before_fork=True,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert not (guardian_bundle[3] / "replacement-executed").exists()
    assert _can_lock(_lock_path(guardian_bundle))


@pytest.mark.parametrize("replacement", ["file", "directory", "symlink"])
def test_lock_path_replacement_does_not_change_the_held_authority(
    guardian_bundle: tuple[Path, Path, Path, Path], replacement: str
) -> None:
    guardian, _qcsd, lock_parent, _state = guardian_bundle
    module = _load_guardian(guardian)
    parent_fd, _ = module._open_lock_parent(lock_parent)
    lock_fd, identity = module._open_lock(parent_fd, lock_parent)
    original = _lock_path(guardian_bundle)
    moved = lock_parent / "moved-lock"
    original.rename(moved)
    if replacement == "file":
        original.write_text("replacement\n", encoding="ascii")
        original.chmod(0o600)
    elif replacement == "directory":
        original.mkdir(mode=0o700)
    else:
        original.symlink_to(moved)
    with pytest.raises(module.GuardianError):
        module._verify_lock_identity(parent_fd, lock_fd, identity)
    os.close(lock_fd)
    os.close(parent_fd)


def test_handshake_fields_are_not_accepted_from_the_ambient_environment(
    guardian_bundle: tuple[Path, Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    forged = {
        "QCSD_DOCKER_LOCK_GUARDIAN_PID": "1",
        "QCSD_DOCKER_LOCK_GUARDIAN_NONCE": "0" * 64,
        "QCSD_DOCKER_LOCK_GUARDIAN_LOCK_INODE": "1",
    }
    for key, value in forged.items():
        monkeypatch.setenv(key, value)

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert _can_lock(_lock_path(guardian_bundle))


def test_shell_startup_and_path_injection_are_removed_before_inner_exec(
    guardian_bundle: tuple[Path, Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "environment-injection"
    bash_environment = tmp_path / "bash-env"
    bash_environment.write_text(f"touch {marker}\n", encoding="ascii")
    hostile_bin = tmp_path / "bin"
    hostile_bin.mkdir()
    hostile_mkdir = hostile_bin / "mkdir"
    hostile_mkdir.write_text(
        f"#!/bin/sh\ntouch {marker}\nexec /usr/bin/mkdir \"$@\"\n",
        encoding="ascii",
    )
    hostile_mkdir.chmod(0o700)
    monkeypatch.setenv("BASH_ENV", str(bash_environment))
    monkeypatch.setenv("ENV", str(bash_environment))
    monkeypatch.setenv("PATH", str(hostile_bin))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "hostile-python-home"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "hostile-python-path"))
    monkeypatch.setenv("PYTHONSTARTUP", str(bash_environment))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(bash_environment))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(bash_environment))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "hostile-git-dir"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "hostile-work-tree"))
    monkeypatch.setenv("GIT_TRACE2_EVENT", str(marker))
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "hostile-docker-config"))
    monkeypatch.setenv("DOCKER_HOST", "tcp://hostile.invalid:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "hostile-context")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    monkeypatch.setenv("DOCKER_CERT_PATH", str(tmp_path / "hostile-certs"))
    monkeypatch.setenv("BUILDX_CONFIG", str(tmp_path / "hostile-buildx"))
    monkeypatch.setenv("BUILDKIT_HOST", "tcp://hostile.invalid:1234")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/hostile-bus")
    monkeypatch.setenv("SYSTEMD_BUS_TIMEOUT", "999999")
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "hostile-runtime"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "hostile-xdg-config"))
    monkeypatch.setenv("TMPDIR", str(tmp_path / "hostile-tmpdir"))
    monkeypatch.setenv("TMP", str(tmp_path / "hostile-tmp"))
    monkeypatch.setenv("TEMP", str(tmp_path / "hostile-temp"))
    monkeypatch.setenv("_QCSD_LIFECYCLE_LOCK_MODE", "exclusive")
    monkeypatch.setenv("_QCSD_LIFECYCLE_LEASE_SOCKET", "@forged")
    monkeypatch.setenv("_QCSD_LIFECYCLE_HELPER_SHA256", "f" * 64)
    monkeypatch.setenv(
        "BASH_FUNC_mkdir%%",
        f"() {{ touch {marker}; command /usr/bin/mkdir \"$@\"; }}",
    )

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not marker.exists()
    assert (guardian_bundle[3] / "internal-environment").read_text(
        encoding="ascii"
    ) == ""
    assert (guardian_bundle[3] / "python-environment").read_text(
        encoding="ascii"
    ) == ""
    assert (guardian_bundle[3] / "git-environment").read_text(
        encoding="ascii"
    ) == ""
    assert (guardian_bundle[3] / "docker-environment").read_text(
        encoding="ascii"
    ) == ""
    runtime_environment = dict(
        line.split("=", 1)
        for line in (guardian_bundle[3] / "runtime-environment")
        .read_text(encoding="ascii")
        .splitlines()
    )
    assert runtime_environment == {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus",
        "TMPDIR": "/tmp",
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
    }
    inner_path = (guardian_bundle[3] / "inner-path").read_text(
        encoding="ascii"
    ).strip()
    assert inner_path.startswith(
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )
    fixed_powershell = Path(
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    if fixed_powershell.exists():
        assert (guardian_bundle[3] / "powershell-path").read_text(
            encoding="ascii"
        ).strip() == str(fixed_powershell)
