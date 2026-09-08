from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import textwrap
import threading
import time
from types import ModuleType, SimpleNamespace

import pytest

from tests.test_docker_signal_supervisor import FAKE_DOCKER


ROOT = Path(__file__).resolve().parents[1]
GUARDIAN = ROOT / "tools/docker_lifecycle_lock_guardian.py"
NATIVE = ROOT / "tools/docker_lifecycle_native.py"
HELPER = ROOT / "tools/docker_signal_supervisor.sh"
V57_CHECKOUT_COMMIT = "b7811dab7124ffdde113fae111ef8bab4810ebba"


FAKE_QCSD = r'''#!/bin/bash
set -euo pipefail

action=$1
if [[ "$action" == build ]]; then
  state=${QCSD_GUARDIAN_TEST_STATE:?}
else
  state=$2
fi
mkdir -p "$state"
printf '%s\n' "$$" >"$state/inner-pid"
printf '%s\n' "$-" >"$state/inner-shell-flags"

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

cohort_lock_matches() {
  /usr/bin/python3 - "$1" <<'PY'
import os
from pathlib import Path
import sys

destination = Path(sys.argv[1])
wanted = (
    int(os.environ["QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_DEVICE"]),
    int(os.environ["QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_INODE"]),
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
  [[ "$admitted" == "$QCSD_DOCKER_LOCK_GUARDIAN_GO_NONCE" ]] || exit 125
  extra=''
  if IFS= read -r extra <&"$go_fd" || [[ -n "$extra" ]]; then exit 125; fi
  eval "exec ${go_fd}<&-"
  if [[ "$action" != real-helper-recover-* &&
        "$action" != real-helper-h3-api-run &&
        "$action" != recovery-wait &&
        "$action" != recovery-api-current &&
        "$action" != recovery-frame-* &&
        "$action" != close-final-go &&
        "$action" != exit-before-final &&
        "$action" != final-ready-ignore-signal ]]; then
    recovery_complete
  fi
}

recovery_complete() {
  local recovery_fd=$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_READY_FD
  local final_go_fd=$QCSD_DOCKER_LOCK_GUARDIAN_FINAL_GO_FD
  local admitted
  printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_NONCE" >&"$recovery_fd"
  eval "exec ${recovery_fd}>&-"
  IFS= read -r admitted <&"$final_go_fd"
  [[ "$admitted" == "$QCSD_DOCKER_LOCK_GUARDIAN_FINAL_GO_NONCE" ]] || exit 125
  extra=''
  if IFS= read -r extra <&"$final_go_fd" || [[ -n "$extra" ]]; then exit 125; fi
  eval "exec ${final_go_fd}<&-"
}

load_real_helper_with_guardian_proof() {
  _QCSD_LIFECYCLE_BOOT_ID=$QCSD_DOCKER_LOCK_GUARDIAN_BOOT_ID
  _QCSD_LIFECYCLE_GUARD_START=$QCSD_DOCKER_LOCK_GUARDIAN_START_TIME
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
  build)
    printf '%s\n' \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_REQUIRED" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_VERSION" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_FD" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_PATH" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_DEVICE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_INODE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_PARENT_DEVICE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_PARENT_INODE" \
      >"$state/cohort-handshake"
    cohort_lock_matches "$state/cohort-inner-fds"
    ready
    cohort_lock_matches "$state/cohort-grandchild-fds"
    if [[ -e "$state/spawn-operation-orphan" ]]; then
      /usr/bin/python3 - \
        "${QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_PATH%/*}/.allocation-operation.lock" \
        "$state/operation-orphan-ready" \
        "$state/release-operation-orphan" \
        "$state/operation-orphan-pid" <<'PY' &
import fcntl
import os
from pathlib import Path
import sys
import time

lock = Path(sys.argv[1])
ready = Path(sys.argv[2])
release = Path(sys.argv[3])
pid_path = Path(sys.argv[4])
descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
fcntl.flock(descriptor, fcntl.LOCK_EX)
pid_path.write_text(str(os.getpid()), encoding="ascii")
ready.touch()
while not release.exists():
    time.sleep(0.01)
fcntl.flock(descriptor, fcntl.LOCK_UN)
os.close(descriptor)
PY
    fi
    printf 'ready\n' >"$state/cohort-ready"
    while [[ ! -e "$state/release" ]]; do sleep 0.02; done
    :
    ;;
  success)
    printf '%s\n' \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_REQUIRED" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_VERSION" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_FD" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_PATH" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_DEVICE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_INODE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_PARENT_DEVICE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_COHORT_LOCK_PARENT_INODE" \
      >"$state/cohort-handshake"
    [[ "${QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH%/*}" == \
        "${QCSD_DOCKER_LOCK_GUARDIAN_LOCK_PATH%/*}" &&
        ! -L "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH" ]]
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
    printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH" \
      >"$state/docker-config-path"
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
    # Keep the exact qcsd Bash process alive through the terminal command.
    # Otherwise Bash may exec-optimise the final Python command, creating a
    # load-sensitive /proc/<pid>/cmdline transition that the guardian correctly
    # rejects as an inner-command identity change.
    :
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
  docker-buildx-pinned-metadata-probe)
    export DOCKER_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH
    export BUILDX_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
    ready
    frontend='docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e'
    docker info --format '{{json .ClientInfo.Plugins}}' \
      >"$state/docker-client-plugins.json"
    docker buildx version >"$state/docker-buildx-version"
    docker buildx imagetools inspect "$frontend" >"$state/buildx-metadata"
    [[ "${DOCKER_CONFIG%/*}" == \
        "${QCSD_DOCKER_LOCK_GUARDIAN_LOCK_PATH%/*}" && ! -L "$DOCKER_CONFIG" ]]
    stat -Lc '%d:%i:%u:%a:%h:%F' "$DOCKER_CONFIG" \
      >"$state/buildx-docker-config-identity"
    printf '%s\n' "$DOCKER_CONFIG" >"$state/buildx-docker-config-path"
    find "$DOCKER_CONFIG" -mindepth 1 -maxdepth 1 -print \
      >"$state/buildx-docker-config-children"
    stat -Lc '%u:%a:%h:%F' "$BUILDX_CONFIG" \
      >"$state/buildx-config-identity"
    find "$BUILDX_CONFIG" -mindepth 1 -maxdepth 1 -print \
      >"$state/buildx-config-children"
    ;;
  docker-buildx-pinned-frontend-probe)
    export DOCKER_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH
    export BUILDX_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
    ready
    context=$state/pinned-frontend-context
    mkdir -m 700 "$context"
    printf '%s\n%s\n' \
      '# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e' \
      'FROM scratch' >"$context/Dockerfile"
    docker --context default build --pull --no-cache --check "$context" \
      >"$state/pinned-frontend-build" 2>&1
    [[ "${DOCKER_CONFIG%/*}" == \
        "${QCSD_DOCKER_LOCK_GUARDIAN_LOCK_PATH%/*}" && ! -L "$DOCKER_CONFIG" ]]
    stat -Lc '%d:%i:%u:%a:%h:%F' "$DOCKER_CONFIG" \
      >"$state/frontend-docker-config-identity"
    printf '%s\n' "$DOCKER_CONFIG" >"$state/frontend-docker-config-path"
    find "$DOCKER_CONFIG" -mindepth 1 -maxdepth 1 -print \
      >"$state/frontend-docker-config-children"
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
  recovery-wait)
    ready
    printf 'recovery\n' >"$state/recovery-phase"
    while [[ ! -e "$state/release-recovery" ]]; do sleep 0.02; done
    recovery_complete
    printf 'mutated\n' >"$state/post-final-mutation"
    ;;
  initial-frame-*)
    ready_fd=$QCSD_DOCKER_LOCK_GUARDIAN_READY_FD
    case "$1" in
      initial-frame-wrong) printf '%064d\n' 0 >&"$ready_fd" ;;
      initial-frame-short) printf '%s\n' "${QCSD_DOCKER_LOCK_GUARDIAN_NONCE%?}" >&"$ready_fd" ;;
      initial-frame-long) printf '%sa\n' "$QCSD_DOCKER_LOCK_GUARDIAN_NONCE" >&"$ready_fd" ;;
      initial-frame-unterminated) printf '%s' "$QCSD_DOCKER_LOCK_GUARDIAN_NONCE" >&"$ready_fd" ;;
      initial-frame-extra) printf '%s\nextra\n' "$QCSD_DOCKER_LOCK_GUARDIAN_NONCE" >&"$ready_fd" ;;
      *) exit 97 ;;
    esac
    eval "exec ${ready_fd}>&-"
    sleep 1
    ;;
  recovery-frame-*)
    ready
    recovery_fd=$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_READY_FD
    case "$1" in
      recovery-frame-wrong) printf '%064d\n' 0 >&"$recovery_fd" ;;
      recovery-frame-short) printf '%s\n' "${QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_NONCE%?}" >&"$recovery_fd" ;;
      recovery-frame-long) printf '%sa\n' "$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_NONCE" >&"$recovery_fd" ;;
      recovery-frame-unterminated) printf '%s' "$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_NONCE" >&"$recovery_fd" ;;
      recovery-frame-extra) printf '%s\nextra\n' "$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_NONCE" >&"$recovery_fd" ;;
      *) exit 97 ;;
    esac
    eval "exec ${recovery_fd}>&-"
    sleep 1
    ;;
  recovery-api-current)
    ready
    printf '%s:%s\n' \
      "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_DEVICE" \
      "$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_INODE" \
      >"$state/docker-config-expected"
    load_real_helper_with_guardian_proof
    _qcsd_lifecycle_base="$state/recovery-api-base"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    export DOCKER_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH
    export BUILDX_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
    _qcsd_supervisor_token() { printf '%032x\n' "$BASHPID"; }
    _qcsd_docker_api_service_with_timeout 5 /bin/sh -c '
      stat -Lc "%d:%i" "$DOCKER_CONFIG" \
        >"$1/recovery-api-docker-identity"
    ' qcsd-recovery-api "$state"
    recovery_complete
    printf 'complete\n' >"$state/recovery-api-complete"
    ;;
  close-initial-go)
    ready_fd=$QCSD_DOCKER_LOCK_GUARDIAN_READY_FD
    go_fd=$QCSD_DOCKER_LOCK_GUARDIAN_GO_FD
    eval "exec ${go_fd}<&-"
    printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_NONCE" >&"$ready_fd"
    eval "exec ${ready_fd}>&-"
    sleep 1
    ;;
  close-final-go)
    ready
    recovery_fd=$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_READY_FD
    final_go_fd=$QCSD_DOCKER_LOCK_GUARDIAN_FINAL_GO_FD
    eval "exec ${final_go_fd}<&-"
    printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_NONCE" >&"$recovery_fd"
    eval "exec ${recovery_fd}>&-"
    sleep 1
    ;;
  exit-before-final)
    ready
    exit 0
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
  pre-ready-ignore-signal)
    trap '' TERM
    printf 'pre-ready\n' >"$state/pre-ready"
    sleep 0.3
    ready_fd=$QCSD_DOCKER_LOCK_GUARDIAN_READY_FD
    go_fd=$QCSD_DOCKER_LOCK_GUARDIAN_GO_FD
    printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_NONCE" >&"$ready_fd"
    eval "exec ${ready_fd}>&-"
    admitted=''
    if IFS= read -r admitted <&"$go_fd"; then
      printf '%s\n' "$admitted" >"$state/initial-decision-observed"
    else
      printf 'eof\n' >"$state/initial-decision-observed"
    fi
    printf 'mutated\n' >"$state/mutation-after-go"
    while :; do sleep 0.02; done
    ;;
  final-ready-ignore-signal)
    trap '' TERM
    ready
    printf 'pre-final\n' >"$state/pre-final"
    sleep 0.3
    recovery_fd=$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_READY_FD
    final_go_fd=$QCSD_DOCKER_LOCK_GUARDIAN_FINAL_GO_FD
    printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_NONCE" \
      >&"$recovery_fd"
    eval "exec ${recovery_fd}>&-"
    admitted=''
    if IFS= read -r admitted <&"$final_go_fd"; then
      printf '%s\n' "$admitted" >"$state/final-decision-observed"
    else
      printf 'eof\n' >"$state/final-decision-observed"
    fi
    printf 'mutated\n' >"$state/mutation-after-final-go"
    while :; do sleep 0.02; done
    ;;
  post-final-ignore-signal)
    trap '' TERM
    ready
    printf 'post-final\n' >"$state/post-final"
    while :; do sleep 0.02; done
    ;;
  post-final-signal-cleanup-lease)
    ready
    load_real_helper_with_guardian_proof
    _qcsd_lifecycle_base="$state/post-final-cleanup-base"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    export DOCKER_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_DOCKER_CONFIG_PATH
    export BUILDX_CONFIG=$QCSD_DOCKER_LOCK_GUARDIAN_BUILDX_CONFIG_PATH
    _qcsd_supervisor_token() { printf '%032x\n' "$BASHPID"; }
    cleanup_after_signal() {
      trap - TERM
      _qcsd_docker_api_service_with_timeout 5 /bin/sh -c '
        printf "served\n" >"$1/post-final-cleanup-lease-served"
      ' qcsd-post-final-cleanup "$state"
      printf 'complete\n' >"$state/post-final-cleanup-complete"
      exit 143
    }
    trap cleanup_after_signal TERM
    printf 'post-final\n' >"$state/post-final"
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
  api-fast-identity-sequence)
    ready
    load_real_helper_with_guardian_proof
    _qcsd_lifecycle_base="$state/api-fast-identity-base"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    export PATH="$state/bin:$PATH" FAKE_DOCKER_STATE="$state"
    export DOCKER_CONTEXT=default
    _QCSD_DOCKER_PINNED_CONTEXT=default
    _QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
    _QCSD_DOCKER_PINNED_SERVER_ID=daemon-test-id
    _QCSD_DOCKER_PINNED_BOOT_ID=$(</proc/sys/kernel/random/boot_id)
    for iteration in 1 2 3 4 5; do
      _qcsd_verify_pinned_docker_daemon
    done
    printf 'completed\n' >"$state/api-fast-identity-completed"
    ;;
  handoff-sequential-retirement|handoff-predecessor-sequential-retirement|\
  handoff-predecessor-reconcile)
    ready
    load_real_helper_with_guardian_proof
    export PATH="$state/bin:$PATH" FAKE_DOCKER_STATE="$state"
    export DOCKER_CONTEXT=default
    _qcsd_lifecycle_base="$state/handoff-retirement-base"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    _qcsd_secure_lifecycle_base() { :; }
    _QCSD_DOCKER_PINNED_CONTEXT=default
    _QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
    _QCSD_DOCKER_PINNED_SERVER_ID=daemon-test-id
    _QCSD_DOCKER_PINNED_BOOT_ID=$(</proc/sys/kernel/random/boot_id)
    QCSD_DOCKER_IDS_SIDECARS=()
    QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS=()
    QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS=()
    roots=()
    use_predecessor=0
    use_reconcile=0
    [[ "$1" == handoff-sequential-retirement ]] || use_predecessor=1
    [[ "$1" != handoff-predecessor-reconcile ]] || use_reconcile=1
    if (( use_predecessor != 0 )); then
      # Production's fixed allowlist is independently unit-tested. These
      # private random-token ledgers exercise every remaining guardian/native
      # successor and retirement boundary.
      _qcsd_lifecycle_v57_handoff_allowlisted() { :; }
    fi
    make_predecessor_handoff() {
      (( use_predecessor != 0 )) || return 0
      sed -i \
        -e "s/^supervisor_source_sha256=.*/supervisor_source_sha256=${_QCSD_DOCKER_V57_PREDECESSOR_SHA256}/" \
        -e 's/^supervisor_pid=.*/supervisor_pid=99999999/' \
        -e 's/^supervisor_start_time=.*/supervisor_start_time=1/' \
        -e 's/^supervisor_session=.*/supervisor_session=99999999/' \
        -e 's/^supervisor_process_group=.*/supervisor_process_group=99999999/' \
        "$_qcsd_lifecycle_root/HANDOFF"
      chmod 600 "$_qcsd_lifecycle_root/HANDOFF"
    }
    cleanup() {
      local status=$? cleanup_status=0 object_id
      trap - EXIT
      set +e
      if (( use_reconcile != 0 )); then
        qcsd_reconcile_docker_lifecycle validate || cleanup_status=1
        (( cleanup_status != 0 )) || \
          qcsd_reconcile_docker_lifecycle recover || cleanup_status=1
      else
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
      fi
      printf '%s\n' "$cleanup_status" >"$state/handoff-cleanup-status"
      awk '$1 == "RM" || $1 == "NETWORK_RM" { count++ } \
        END { print count + 0 }' "$state/calls.log" \
        >"$state/handoff-removals-after"
      (( cleanup_status == 0 )) || exit 97
      exit "$status"
    }
    trap cleanup EXIT
    for value in 1 2 3; do
      printf -v FAKE_DOCKER_CONTAINER_ID '%064x' "$value"
      export FAKE_DOCKER_CONTAINER_ID
      qcsd_run_detached_docker QCSD_DOCKER_IDS_SIDECARS \
        docker run fake-image
      make_predecessor_handoff
      roots+=("$_qcsd_lifecycle_root")
      docker rm --force "${QCSD_DOCKER_IDS_SIDECARS[-1]}" >/dev/null
    done
    printf -v FAKE_DOCKER_NETWORK_ID '%064x' 101
    export FAKE_DOCKER_NETWORK_ID
    qcsd_create_docker_network QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS \
      docker network create server-network
    make_predecessor_handoff
    roots+=("$_qcsd_lifecycle_root")
    docker network rm \
      "${QCSD_DOCKER_IDS_CONTROLLED_SERVER_NETWORKS[-1]}" >/dev/null
    printf -v FAKE_DOCKER_NETWORK_ID '%064x' 102
    export FAKE_DOCKER_NETWORK_ID
    qcsd_create_docker_network QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS \
      docker network create client-network
    make_predecessor_handoff
    roots+=("$_qcsd_lifecycle_root")
    docker network rm \
      "${QCSD_DOCKER_IDS_CONTROLLED_CLIENT_NETWORKS[-1]}" >/dev/null
    awk '$1 == "RM" || $1 == "NETWORK_RM" { count++ } \
      END { print count + 0 }' "$state/calls.log" \
      >"$state/handoff-removals-before"
    printf '%s\n' "${roots[@]}" >"$state/handoff-root-inventory"
    ;;
  handoff-predecessor-retirement-race)
    ready
    load_real_helper_with_guardian_proof
    export PATH="$state/bin:$PATH" FAKE_DOCKER_STATE="$state"
    export DOCKER_CONTEXT=default
    _qcsd_lifecycle_base="$state/handoff-predecessor-race-base"
    mkdir -m 700 "$_qcsd_lifecycle_base"
    _qcsd_secure_lifecycle_base() { :; }
    _QCSD_DOCKER_PINNED_CONTEXT=default
    _QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
    _QCSD_DOCKER_PINNED_SERVER_ID=daemon-test-id
    _QCSD_DOCKER_PINNED_BOOT_ID=$(</proc/sys/kernel/random/boot_id)
    _qcsd_lifecycle_v57_handoff_allowlisted() { :; }
    QCSD_DOCKER_IDS_TEST=()
    qcsd_run_detached_docker QCSD_DOCKER_IDS_TEST docker run fake-image
    root=$_qcsd_lifecycle_root
    object_id=${QCSD_DOCKER_IDS_TEST[0]}
    token=${root##*.}
    sed -i \
      -e "s/^supervisor_source_sha256=.*/supervisor_source_sha256=${_QCSD_DOCKER_V57_PREDECESSOR_SHA256}/" \
      -e 's/^supervisor_pid=.*/supervisor_pid=99999999/' \
      -e 's/^supervisor_start_time=.*/supervisor_start_time=1/' \
      -e 's/^supervisor_session=.*/supervisor_session=99999999/' \
      -e 's/^supervisor_process_group=.*/supervisor_process_group=99999999/' \
      "$root/HANDOFF"
    chmod 600 "$root/HANDOFF"
    docker rm --force "$object_id" >/dev/null
    rm_before=$(awk '$1 == "RM" { count++ } END { print count + 0 }' \
      "$state/calls.log")
    _qcsd_handoff_retire_after_absence_hook() {
      case "$(<"$state/race-observation")" in
        present)
          printf '%s' "$object_id" >"$state/container"
          printf '%s' "$token" >"$state/container-token"
          printf 'true' >"$state/running"
          ;;
        ambiguous) export FAKE_CONTAINER_LS_AMBIGUOUS=1 ;;
        unknown) export FAKE_DOCKER_DAEMON_UNKNOWN=1 ;;
        *) return 91 ;;
      esac
    }
    set +e
    qcsd_retire_docker_handoff run "$object_id" QCSD_DOCKER_IDS_TEST
    retirement_status=$?
    set -e
    rm_after=$(awk '$1 == "RM" { count++ } END { print count + 0 }' \
      "$state/calls.log")
    [[ "$retirement_status" -ne 0 && "$rm_before" == "$rm_after" &&
        -f "$root/HANDOFF" ]]
    printf '%s %s %s %s\n' "$retirement_status" "$rm_before" "$rm_after" \
      "$root" >"$state/handoff-predecessor-race-result"
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
    recovery_complete
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


def _isolated_guardian_socket_suffix(lock_parent: Path) -> str:
    return hashlib.sha256(os.fsencode(lock_parent)).hexdigest()[:16]


def _isolated_guardian_socket_template(lock_parent: Path) -> str:
    suffix = _isolated_guardian_socket_suffix(lock_parent)
    return f"qcsd-docker-lifecycle-guardian-{{os.getuid()}}-{suffix}"


def _isolated_guardian_socket_proc_name(lock_parent: Path) -> str:
    suffix = _isolated_guardian_socket_suffix(lock_parent)
    return f"@qcsd-docker-lifecycle-guardian-{os.getuid()}-{suffix}"


def _isolated_guardian_socket_endpoint(lock_parent: Path) -> str:
    suffix = _isolated_guardian_socket_suffix(lock_parent)
    return f"\0qcsd-docker-lifecycle-guardian-{os.getuid()}-{suffix}"


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
    source = guardian.read_text(encoding="utf-8")
    shared_socket = "qcsd-docker-lifecycle-guardian-{os.getuid()}"
    isolated_socket = _isolated_guardian_socket_template(tmp_path / "locks")
    assert source.count(shared_socket) == 2
    guardian.write_text(
        source.replace(shared_socket, isolated_socket), encoding="utf-8"
    )
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
    socket_name = _isolated_guardian_socket_proc_name(lock_parent)

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


@pytest.fixture
def isolated_guardian_bundle(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> tuple[Path, Path, Path, Path]:
    """Compatibility name: every copied guardian is already per-test isolated."""

    return guardian_bundle


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
    fail_buildx_cleanup: bool = False,
    prepare_failure: str | None = None,
    fail_listener_close: bool = False,
    recovery_timeout: float | None = None,
    recovery_idle_timeout: float | None = None,
    failure_cleanup_timeout: float | None = None,
    cleanup_failure: str | None = None,
    read_failure: str | None = None,
    pause_residue_drain: bool = False,
    inner_arguments: tuple[str, ...] | None = None,
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
        if sys.argv[15] != "default":
            module.RECOVERY_TIMEOUT_SECONDS = float(sys.argv[15])
        if sys.argv[19] != "default":
            module.RECOVERY_IDLE_TIMEOUT_SECONDS = float(sys.argv[19])
        if sys.argv[20] != "default":
            module.FAILURE_CLEANUP_SECONDS = float(sys.argv[20])
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
            signal_cleanup_delegate = module._cleanup_private_config
            cleanup_signalled = [False]
            def cleanup_then_signal(*args, **kwargs):
                result = signal_cleanup_delegate(*args, **kwargs)
                if not cleanup_signalled[0]:
                    cleanup_signalled[0] = True
                    module.os.kill(module.os.getpid(), module.signal.SIGTERM)
                return result
            module._cleanup_private_config = cleanup_then_signal
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
        if sys.argv[12] == "fail-buildx-cleanup":
            def fail_buildx_cleanup(*_args, **_kwargs):
                raise module.GuardianError("injected Buildx cleanup failure")
            module._cleanup_buildx_ledgers = fail_buildx_cleanup
        if sys.argv[13] == "pre-open":
            real_open = module.os.open
            def fail_construction_open(path, *args, **kwargs):
                if isinstance(path, str) and ".construct.v2." in path:
                    raise OSError(module.errno.EIO, "injected construction open failure")
                return real_open(path, *args, **kwargs)
            module.os.open = fail_construction_open
        elif sys.argv[13] == "rename":
            rename_delegate = module._rename_noreplace
            def fail_publication_rename(parent_fd, source_name, destination_name, **kwargs):
                if ".construct.v2." in str(source_name):
                    raise OSError(module.errno.EIO, "injected publication rename failure")
                return rename_delegate(parent_fd, source_name, destination_name, **kwargs)
            module._rename_noreplace = fail_publication_rename
        elif sys.argv[13] == "post-rename-fsync":
            rename_delegate = module._rename_noreplace
            real_fsync = module.os.fsync
            fail_next_fsync = [False]
            def arm_publication_fsync(parent_fd, source_name, destination_name, **kwargs):
                if ".construct.v2." in str(source_name):
                    fail_next_fsync[0] = True
                return rename_delegate(parent_fd, source_name, destination_name, **kwargs)
            def fail_publication_fsync(descriptor):
                if fail_next_fsync[0]:
                    fail_next_fsync[0] = False
                    raise OSError(module.errno.EIO, "injected publication fsync failure")
                return real_fsync(descriptor)
            module._rename_noreplace = arm_publication_fsync
            module.os.fsync = fail_publication_fsync
        if sys.argv[14] == "fail-listener-close":
            real_abstract_lease_socket = module._abstract_lease_socket
            class FailingCloseListener:
                def __init__(self, listener):
                    self.listener = listener
                def __getattr__(self, name):
                    return getattr(self.listener, name)
                def close(self):
                    self.listener.close()
                    raise OSError(module.errno.EIO, "injected listener close failure")
            def failing_close_listener(*args, **kwargs):
                listener, name = real_abstract_lease_socket(*args, **kwargs)
                return FailingCloseListener(listener), name
            module._abstract_lease_socket = failing_close_listener
        if sys.argv[16] == "current-rmdir":
            real_rmdir = module.os.rmdir
            def fail_docker_config_rmdir(path, *args, **kwargs):
                if str(path).startswith(f".qcsd-docker-config-{module.os.getuid()}."):
                    raise OSError(module.errno.EIO, "injected Docker config rmdir failure")
                return real_rmdir(path, *args, **kwargs)
            module.os.rmdir = fail_docker_config_rmdir
        elif sys.argv[16] == "current-fsync-recreate":
            real_rmdir = module.os.rmdir
            real_fsync = module.os.fsync
            removed_name = [None]
            def arm_docker_config_fsync(path, *args, **kwargs):
                result = real_rmdir(path, *args, **kwargs)
                if str(path).startswith(f".qcsd-docker-config-{module.os.getuid()}."):
                    removed_name[0] = str(path)
                return result
            def fail_after_recreating_path(descriptor):
                if removed_name[0] is not None:
                    name = removed_name[0]
                    removed_name[0] = None
                    module.os.mkdir(name, 0o700, dir_fd=descriptor)
                    raise OSError(module.errno.EIO, "injected parent fsync failure")
                return real_fsync(descriptor)
            module.os.rmdir = arm_docker_config_fsync
            module.os.fsync = fail_after_recreating_path
        elif sys.argv[16] == "current-close":
            close_cleanup_delegate = module._cleanup_private_config
            real_close = module.os.close
            fail_descriptors = set()
            def arm_docker_config_close(parent_fd, descriptor, expected, **kwargs):
                result = close_cleanup_delegate(
                    parent_fd, descriptor, expected, **kwargs
                )
                fail_descriptors.add(descriptor)
                return result
            def fail_docker_config_close(descriptor):
                if descriptor in fail_descriptors:
                    fail_descriptors.remove(descriptor)
                    real_close(descriptor)
                    raise OSError(module.errno.EIO, "injected config close failure")
                return real_close(descriptor)
            module._cleanup_private_config = arm_docker_config_close
            module.os.close = fail_docker_config_close
        elif sys.argv[16] == "second-residue":
            residue_cleanup_delegate = module._cleanup_private_config
            cleanup_count = [0]
            blocked_identity = [None]
            def fail_second_residue(parent_fd, descriptor, expected, **kwargs):
                cleanup_count[0] += 1
                identity = (expected.device, expected.inode)
                if cleanup_count[0] == 2:
                    blocked_identity[0] = identity
                if identity == blocked_identity[0]:
                    raise module.GuardianError("injected second residue cleanup failure")
                return residue_cleanup_delegate(
                    parent_fd, descriptor, expected, **kwargs
                )
            module._cleanup_private_config = fail_second_residue
        elif sys.argv[16] == "pause-current":
            retirement_delegate = module._retire_private_config_residue
            paused = [False]
            def pause_current_retirement(*args, **kwargs):
                if not paused[0]:
                    paused[0] = True
                    state = Path(sys.argv[4])
                    (state / "terminal-cleanup-entered").touch()
                    deadline = module.time.monotonic() + 5
                    while not (state / "release-terminal-cleanup").exists():
                        if module.time.monotonic() >= deadline:
                            raise AssertionError("test did not release terminal cleanup")
                        module.time.sleep(0.005)
                return retirement_delegate(*args, **kwargs)
            module._retire_private_config_residue = pause_current_retirement
        elif sys.argv[16] == "pause-cohort-drain":
            drain_delegate = module._lock_cohort_operation_for_cleanup
            def pause_after_cohort_drain(*args, **kwargs):
                result = drain_delegate(*args, **kwargs)
                state = Path(sys.argv[4])
                (state / "cohort-terminal-drain-entered").touch()
                deadline = module.time.monotonic() + 5
                while not (state / "release-cohort-terminal-drain").exists():
                    if module.time.monotonic() >= deadline:
                        raise AssertionError("test did not release terminal cohort drain")
                    module.time.sleep(0.005)
                return result
            module._lock_cohort_operation_for_cleanup = pause_after_cohort_drain
        if sys.argv[17] in {"initial", "recovery"}:
            wait_delegate = module._wait_for_child
            def fail_channel_read(*args, **kwargs):
                target = args[1] if sys.argv[17] == "initial" else args[5]
                read_delegate = module.os.read
                injected = [False]
                def injected_read(descriptor, size):
                    if descriptor == target and not injected[0]:
                        injected[0] = True
                        raise OSError(module.errno.EIO, "injected channel read failure")
                    return read_delegate(descriptor, size)
                module.os.read = injected_read
                try:
                    return wait_delegate(*args, **kwargs)
                finally:
                    module.os.read = read_delegate
            module._wait_for_child = fail_channel_read
        if sys.argv[18] == "pause-residue-drain":
            census_delegate = module._process_references_docker_config
            paused = [False]
            def pause_first_residue_census(*args, **kwargs):
                if not paused[0]:
                    paused[0] = True
                    state = Path(sys.argv[4])
                    (state / "residue-drain-entered").touch()
                    deadline = module.time.monotonic() + 5
                    while not (state / "release-residue-drain").exists():
                        if module.time.monotonic() >= deadline:
                            raise AssertionError("test did not release residue drain")
                        module.time.sleep(0.005)
                return census_delegate(*args, **kwargs)
            module._process_references_docker_config = pause_first_residue_census
        try:
            inner = (
                (sys.argv[2], sys.argv[3], sys.argv[4])
                if len(sys.argv) == 21
                else (sys.argv[2], *sys.argv[21:])
            )
            result = module.guard(
                inner,
                source_path=source,
                lock_parent=Path(sys.argv[5]),
            )
        except module.GuardianError as error:
            print(
                f"qcsd-lab Docker lifecycle guardian: {error}",
                file=sys.stderr,
            )
            result = 125
        raise SystemExit(result)
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
        "fail-buildx-cleanup" if fail_buildx_cleanup else "normal",
        "normal" if prepare_failure is None else prepare_failure,
        "fail-listener-close" if fail_listener_close else "normal",
        "default" if recovery_timeout is None else str(recovery_timeout),
        "normal" if cleanup_failure is None else cleanup_failure,
        "normal" if read_failure is None else read_failure,
        "pause-residue-drain" if pause_residue_drain else "normal",
        "default" if recovery_idle_timeout is None else str(recovery_idle_timeout),
        "default" if failure_cleanup_timeout is None else str(failure_cleanup_timeout),
        *(inner_arguments or ()),
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


def _commit_v57_helper_successor(
    bundle: tuple[Path, Path, Path, Path],
) -> str:
    """Give the copied helper an exact, clean descendant of the v57 commit."""
    helper = bundle[0].parent / HELPER.name
    project = helper.parent.parent

    def git(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(project), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=10,
        )

    git("init", "--quiet")
    git("fetch", "--quiet", "--no-tags", str(ROOT), V57_CHECKOUT_COMMIT)
    fetched = git("rev-parse", "--verify", "FETCH_HEAD^{commit}").stdout.strip()
    assert fetched == V57_CHECKOUT_COMMIT
    git("update-ref", "refs/heads/qcsd-successor-test", fetched)
    git("symbolic-ref", "HEAD", "refs/heads/qcsd-successor-test")
    git("read-tree", "HEAD")
    git("add", "--", "tools/docker_signal_supervisor.sh")
    git(
        "-c",
        "user.name=QCSD lifecycle test",
        "-c",
        "user.email=qcsd-lifecycle-test.invalid",
        "commit",
        "--quiet",
        "-m",
        "Test committed helper successor",
    )
    head = git("rev-parse", "--verify", "HEAD^{commit}").stdout.strip()
    git("merge-base", "--is-ancestor", V57_CHECKOUT_COMMIT, head)
    assert git(
        "status", "--porcelain=v1", "--", "tools/docker_signal_supervisor.sh"
    ).stdout == ""
    return head


def _lock_path(bundle: tuple[Path, Path, Path, Path]) -> Path:
    return bundle[2] / f"qcsd-docker-lifecycle-{os.getuid()}.lock"


def _cohort_lock_path(bundle: tuple[Path, Path, Path, Path]) -> Path:
    return (
        bundle[1].parent
        / "artifacts/buflo-study/cohort-claims-v1/.allocation.lock"
    )


def _cohort_operation_lock_path(
    bundle: tuple[Path, Path, Path, Path],
) -> Path:
    return _cohort_lock_path(bundle).with_name(".allocation-operation.lock")


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


def _load_allocator(path: Path) -> ModuleType:
    name = f"qcsd_cohort_allocator_direct_test_{os.urandom(8).hex()}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_guardian_and_allocator_use_the_same_cohort_operation_lock() -> None:
    guardian = _load_guardian(GUARDIAN)
    allocator = _load_allocator(ROOT / "src/qcsd_lab/cohort_allocation.py")

    assert (
        guardian.COHORT_OPERATION_LOCK_NAME
        == allocator.COHORT_OPERATION_LOCK_NAME
        == ".allocation-operation.lock"
    )


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


def _matching_process_fds(pid: int, value: os.stat_result) -> list[str]:
    matches: list[str] = []
    for candidate in Path(f"/proc/{pid}/fd").iterdir():
        try:
            observed = candidate.stat()
        except OSError:
            continue
        if (observed.st_dev, observed.st_ino) == (value.st_dev, value.st_ino):
            matches.append(candidate.name)
    return sorted(matches, key=int)


def _self_start_time() -> int:
    fields = Path("/proc/self/stat").read_text(encoding="ascii").rsplit(") ", 1)[1]
    return int(fields.split()[19])


def _boot_token() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii"
    ).strip().replace("-", "")


def _docker_config_name(
    nonce: str,
    *,
    start: int | None = None,
    boot_token: str | None = None,
) -> str:
    actual_start = _self_start_time() if start is None else start
    actual_boot = _boot_token() if boot_token is None else boot_token
    return (
        f".qcsd-docker-config-{os.getuid()}.v2."
        f"{actual_boot}.{actual_start}.{nonce}"
    )


def _docker_config_construction_name(
    nonce: str,
    *,
    start: int | None = None,
    boot_token: str | None = None,
) -> str:
    actual_start = _self_start_time() if start is None else start
    actual_boot = _boot_token() if boot_token is None else boot_token
    return (
        f".qcsd-docker-config-{os.getuid()}.construct.v2."
        f"{actual_boot}.{actual_start}.{nonce}"
    )


def _docker_config_quarantine_name(
    nonce: str,
    *,
    start: int | None = None,
    boot_token: str | None = None,
) -> str:
    actual_start = _self_start_time() if start is None else start
    actual_boot = _boot_token() if boot_token is None else boot_token
    return (
        f".qcsd-docker-config-{os.getuid()}.retiring.v2."
        f"{actual_boot}.{actual_start}.{nonce}"
    )


def _docker_config_namespace_snapshot(
    lock_parent: Path,
) -> dict[str, tuple[int, int, int, int, int, int]]:
    prefix = f".qcsd-docker-config-{os.getuid()}."
    snapshot: dict[str, tuple[int, int, int, int, int, int]] = {}
    for path in lock_parent.iterdir():
        if not path.name.startswith(prefix):
            continue
        value = path.stat(follow_symlinks=False)
        snapshot[path.name] = (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            stat.S_IFMT(value.st_mode),
            stat.S_IMODE(value.st_mode),
            value.st_nlink,
        )
    return snapshot


def _assert_retired_linked_docker_path(
    recorded: Path, lock_parent: Path
) -> None:
    path = Path(recorded.read_text(encoding="ascii").strip())
    assert path.is_absolute()
    assert path.parent == lock_parent
    assert re.fullmatch(
        rf"[.]qcsd-docker-config-{os.getuid()}[.]v2[.]"
        rf"[0-9a-f]{{32}}[.][1-9][0-9]*[.][0-9a-f]{{64}}",
        path.name,
    )
    assert not path.exists() and not path.is_symlink()


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
    assert observed == f"{device}:{inode}:{os.getuid()}:500:2:directory"
    assert (state / "docker-config-children").read_text(encoding="ascii") == ""
    _assert_retired_linked_docker_path(
        state / "docker-config-path", guardian_bundle[2]
    )
    assert _can_lock(_lock_path(guardian_bundle))


def test_non_build_guardian_exposes_no_cohort_lock_authority(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / "cohort-handshake").read_text(
        encoding="ascii"
    ).splitlines() == ["0", *("unavailable" for _ in range(7))]
    assert not _cohort_lock_path(guardian_bundle).parent.exists()


@pytest.mark.parametrize(
    "inner_arguments",
    [
        ("build", "--cohort-version", "34"),
        ("build", "--cohort-version=34"),
    ],
)
def test_build_guardian_exclusively_holds_uninherited_cohort_lock(
    guardian_bundle: tuple[Path, Path, Path, Path],
    inner_arguments: tuple[str, ...],
) -> None:
    state = guardian_bundle[3]
    environment = {
        **os.environ,
        "QCSD_GUARDIAN_TEST_STATE": str(state),
    }
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "unused",
            inner_arguments=inner_arguments,
        ),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait(state / "cohort-ready")
        fields = (state / "cohort-handshake").read_text(
            encoding="ascii"
        ).splitlines()
        assert len(fields) == 8
        (
            required,
            cohort,
            guardian_fd,
            recorded_path,
            device,
            inode,
            parent_device,
            parent_inode,
        ) = fields
        assert (required, cohort) == ("1", "34")
        lock_path = _cohort_lock_path(guardian_bundle)
        assert recorded_path == str(lock_path)
        lock_value = lock_path.stat(follow_symlinks=False)
        parent_value = lock_path.parent.stat(follow_symlinks=False)
        assert stat.S_ISREG(lock_value.st_mode)
        assert stat.S_IMODE(lock_value.st_mode) == 0o600
        assert lock_value.st_nlink == 1 and lock_value.st_size == 0
        assert stat.S_ISDIR(parent_value.st_mode)
        assert stat.S_IMODE(parent_value.st_mode) == 0o700
        assert (device, inode) == (str(lock_value.st_dev), str(lock_value.st_ino))
        assert (parent_device, parent_inode) == (
            str(parent_value.st_dev),
            str(parent_value.st_ino),
        )
        assert _matching_process_fds(process.pid, lock_value) == [guardian_fd]
        inner_pid = int((state / "inner-pid").read_text(encoding="ascii"))
        assert _matching_process_fds(inner_pid, lock_value) == []
        assert (state / "cohort-inner-fds").read_text(encoding="ascii") == ""
        assert (state / "cohort-grandchild-fds").read_text(encoding="ascii") == ""
        assert not _can_lock(lock_path)
        operation_path = _cohort_operation_lock_path(guardian_bundle)
        operation_value = operation_path.stat(follow_symlinks=False)
        assert stat.S_ISREG(operation_value.st_mode)
        assert stat.S_IMODE(operation_value.st_mode) == 0o600
        assert operation_value.st_nlink == 1 and operation_value.st_size == 0
        assert (operation_value.st_dev, operation_value.st_ino) != (
            lock_value.st_dev,
            lock_value.st_ino,
        )
        assert len(_matching_process_fds(process.pid, operation_value)) == 1
        assert _matching_process_fds(inner_pid, operation_value) == []
        assert _can_lock(operation_path)

        (state / "release").touch()
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, (stdout, stderr)
        assert _can_lock(lock_path)
        assert _can_lock(operation_path)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.parametrize(
    "inner_arguments",
    [
        ("build",),
        ("build", "--cohort-version", "0"),
        ("build", "--cohort-version", "01"),
        ("build", "--cohort-version", "34", "extra"),
        ("build", "--cohort-version=34", "extra"),
        ("build", "--cohort-version", "34", "--cohort-version", "35"),
    ],
)
def test_guardian_rejects_noncanonical_build_cohort_argv_before_child(
    guardian_bundle: tuple[Path, Path, Path, Path],
    inner_arguments: tuple[str, ...],
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "unused",
            inner_arguments=inner_arguments,
        ),
        env={
            **os.environ,
            "QCSD_GUARDIAN_TEST_STATE": str(guardian_bundle[3]),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "does not select one exact cohort" in result.stderr
    assert not (guardian_bundle[3] / "inner-pid").exists()
    assert not _cohort_lock_path(guardian_bundle).parent.exists()


def test_build_guardian_detects_cohort_lock_path_replacement_and_kills_inner(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "unused",
            inner_arguments=("build", "--cohort-version", "34"),
        ),
        env={**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    replacement_fd = -1
    try:
        _wait(state / "cohort-ready")
        inner_pid = int((state / "inner-pid").read_text(encoding="ascii"))
        lock_path = _cohort_lock_path(guardian_bundle)
        moved = lock_path.with_name(".allocation.lock.replaced")
        lock_path.rename(moved)
        replacement_fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        os.close(replacement_fd)
        replacement_fd = -1

        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 125, (stdout, stderr)
        assert "runtime integrity check failed" in stderr
        assert "lock path changed" in stderr
        _wait_gone(inner_pid)
        assert _can_lock(moved)
        assert _can_lock(lock_path)
    finally:
        if replacement_fd >= 0:
            os.close(replacement_fd)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_build_guardian_detects_operation_lock_path_replacement_and_kills_inner(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "unused",
            inner_arguments=("build", "--cohort-version", "34"),
        ),
        env={**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    replacement_fd = -1
    try:
        _wait(state / "cohort-ready")
        inner_pid = int((state / "inner-pid").read_text(encoding="ascii"))
        operation_path = _cohort_operation_lock_path(guardian_bundle)
        moved = operation_path.with_name(".allocation-operation.lock.replaced")
        operation_path.rename(moved)
        replacement_fd = os.open(
            operation_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        os.close(replacement_fd)
        replacement_fd = -1

        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 125, (stdout, stderr)
        assert "runtime integrity check failed" in stderr
        assert "lock path changed" in stderr
        _wait_gone(inner_pid)
        assert _can_lock(moved)
        assert _can_lock(operation_path)
    finally:
        if replacement_fd >= 0:
            os.close(replacement_fd)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_guardian_sigkill_drops_cohort_lock_and_pdeathsig_kills_inner(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "unused",
            inner_arguments=("build", "--cohort-version=34"),
        ),
        env={**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait(state / "cohort-ready")
        lock_path = _cohort_lock_path(guardian_bundle)
        assert not _can_lock(lock_path)
        inner_pid = int((state / "inner-pid").read_text(encoding="ascii"))

        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        assert process.returncode == -signal.SIGKILL
        _wait_gone(inner_pid)
        deadline = time.monotonic() + 2
        while not _can_lock(lock_path) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _can_lock(lock_path)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_build_guardian_retains_cohort_lock_through_terminal_cleanup(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "unused",
            cleanup_failure="pause-current",
            inner_arguments=("build", "--cohort-version", "34"),
        ),
        env={**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait(state / "cohort-ready")
        lock_path = _cohort_lock_path(guardian_bundle)
        (state / "release").touch()
        _wait(state / "terminal-cleanup-entered")

        assert process.poll() is None
        assert not _can_lock(lock_path)
        inner_pid = int((state / "inner-pid").read_text(encoding="ascii"))
        _wait_gone(inner_pid)

        (state / "release-terminal-cleanup").touch()
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, (stdout, stderr)
        assert _can_lock(lock_path)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_build_guardian_terminally_drains_b_before_releasing_a(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "unused",
            cleanup_failure="pause-cohort-drain",
            inner_arguments=("build", "--cohort-version", "34"),
        ),
        env={**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait(state / "cohort-ready")
        cohort_lock = _cohort_lock_path(guardian_bundle)
        operation_lock = _cohort_operation_lock_path(guardian_bundle)
        inner_pid = int((state / "inner-pid").read_text(encoding="ascii"))
        (state / "release").touch()
        _wait(state / "cohort-terminal-drain-entered")

        assert process.poll() is None
        _wait_gone(inner_pid)
        assert not _can_lock(cohort_lock)
        assert not _can_lock(operation_lock)

        (state / "release-cohort-terminal-drain").touch()
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, (stdout, stderr)
        assert _can_lock(cohort_lock)
        assert _can_lock(operation_lock)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_inherited_acquisition_lock_cannot_alias_build_cohort_lock(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_path = _cohort_lock_path(guardian_bundle)
    lock_path.parent.mkdir(parents=True, mode=0o700)
    lock_path.parent.chmod(0o700)
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run(
            _guardian_command(
                guardian_bundle,
                "unused",
                inner_arguments=("build", "--cohort-version", "34"),
            ),
            env={
                **os.environ,
                "QCSD_CLASS_ACQUISITION_LOCK_FD": str(descriptor),
                "QCSD_GUARDIAN_TEST_STATE": str(guardian_bundle[3]),
            },
            pass_fds=(descriptor,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )

        assert result.returncode == 125, (result.stdout, result.stderr)
        assert "aliases the cohort-allocation lock" in result.stderr
        assert not (guardian_bundle[3] / "inner-pid").exists()
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink", "writable"])
def test_build_guardian_rejects_unsafe_cohort_operation_lock(
    guardian_bundle: tuple[Path, Path, Path, Path],
    kind: str,
) -> None:
    operation_path = _cohort_operation_lock_path(guardian_bundle)
    operation_path.parent.mkdir(parents=True, mode=0o700)
    operation_path.parent.chmod(0o700)
    outside = guardian_bundle[3] / "outside-operation-lock"
    outside.write_bytes(b"")
    outside.chmod(0o600)
    if kind == "symlink":
        operation_path.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(operation_path, 0o600)
    elif kind == "hardlink":
        os.link(outside, operation_path)
    else:
        operation_path.write_bytes(b"")
        operation_path.chmod(0o620)

    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "unused",
            inner_arguments=("build", "--cohort-version", "34"),
        ),
        env={
            **os.environ,
            "QCSD_GUARDIAN_TEST_STATE": str(guardian_bundle[3]),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "operation lock" in result.stderr
    assert not (guardian_bundle[3] / "inner-pid").exists()


def test_inherited_acquisition_lock_cannot_alias_cohort_operation_lock(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    operation_path = _cohort_operation_lock_path(guardian_bundle)
    operation_path.parent.mkdir(parents=True, mode=0o700)
    operation_path.parent.chmod(0o700)
    descriptor = os.open(
        operation_path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run(
            _guardian_command(
                guardian_bundle,
                "unused",
                inner_arguments=("build", "--cohort-version", "34"),
            ),
            env={
                **os.environ,
                "QCSD_CLASS_ACQUISITION_LOCK_FD": str(descriptor),
                "QCSD_GUARDIAN_TEST_STATE": str(guardian_bundle[3]),
            },
            pass_fds=(descriptor,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )

        assert result.returncode == 125, (result.stdout, result.stderr)
        assert "operation lock aliases another authority lock" in result.stderr
        assert not (guardian_bundle[3] / "inner-pid").exists()
    finally:
        os.close(descriptor)


def test_build_guardian_drains_operation_lock_after_lifecycle_and_cohort_locks(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    operation_path = _cohort_operation_lock_path(guardian_bundle)
    operation_path.parent.mkdir(parents=True, mode=0o700)
    operation_path.parent.chmod(0o700)
    operation_fd = os.open(
        operation_path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    process: subprocess.Popen[str] | None = None
    try:
        fcntl.flock(operation_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process = subprocess.Popen(
            _guardian_command(
                guardian_bundle,
                "unused",
                inner_arguments=("build", "--cohort-version", "34"),
            ),
            env={**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        lifecycle_lock = _lock_path(guardian_bundle)
        cohort_lock = _cohort_lock_path(guardian_bundle)
        deadline = time.monotonic() + 5
        while (
            (
                not lifecycle_lock.exists()
                or not cohort_lock.exists()
                or _can_lock(lifecycle_lock)
                or _can_lock(cohort_lock)
            )
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert lifecycle_lock.exists() and not _can_lock(lifecycle_lock)
        assert cohort_lock.exists() and not _can_lock(cohort_lock)
        assert not (state / "inner-pid").exists()

        fcntl.flock(operation_fd, fcntl.LOCK_UN)
        _wait(state / "cohort-ready")
        inner_pid = int((state / "inner-pid").read_text(encoding="ascii"))
        operation_value = operation_path.stat(follow_symlinks=False)
        assert _matching_process_fds(inner_pid, operation_value) == []
        assert _can_lock(operation_path)
        (state / "release").touch()
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, (stdout, stderr)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(operation_fd)


def test_signal_while_guardian_waits_for_operation_drain_fails_closed(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    operation_path = _cohort_operation_lock_path(guardian_bundle)
    operation_path.parent.mkdir(parents=True, mode=0o700)
    operation_path.parent.chmod(0o700)
    operation_fd = os.open(
        operation_path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    process: subprocess.Popen[str] | None = None
    try:
        fcntl.flock(operation_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process = subprocess.Popen(
            _guardian_command(
                guardian_bundle,
                "unused",
                inner_arguments=("build", "--cohort-version", "34"),
            ),
            env={**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        cohort_lock = _cohort_lock_path(guardian_bundle)
        deadline = time.monotonic() + 5
        while (
            (not cohort_lock.exists() or _can_lock(cohort_lock))
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert not _can_lock(cohort_lock)
        assert not (state / "inner-pid").exists()

        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 125, (stdout, stderr)
        assert "signal received before cohort-allocation operation drain" in stderr
        assert _can_lock(cohort_lock)
        assert not _can_lock(operation_path)
        assert not (state / "inner-pid").exists()
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(operation_fd)


def test_successor_guardian_drains_allocator_orphan_after_guardian_sigkill(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    (state / "spawn-operation-orphan").touch()
    command = _guardian_command(
        guardian_bundle,
        "unused",
        inner_arguments=("build", "--cohort-version", "34"),
    )
    environment = {**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)}
    first = subprocess.Popen(
        command,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    successor: subprocess.Popen[str] | None = None
    orphan_pid = -1
    try:
        _wait(state / "operation-orphan-ready")
        _wait(state / "cohort-ready")
        orphan_pid = int(
            (state / "operation-orphan-pid").read_text(encoding="ascii")
        )
        first_inner = int((state / "inner-pid").read_text(encoding="ascii"))
        assert not _can_lock(_cohort_operation_lock_path(guardian_bundle))

        os.kill(first.pid, signal.SIGKILL)
        first.wait(timeout=5)
        assert first.returncode == -signal.SIGKILL
        _wait_gone(first_inner)
        assert Path(f"/proc/{orphan_pid}").exists()
        assert not _can_lock(_cohort_operation_lock_path(guardian_bundle))

        (state / "spawn-operation-orphan").unlink()
        (state / "inner-pid").unlink()
        (state / "cohort-ready").unlink()
        successor = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        cohort_lock = _cohort_lock_path(guardian_bundle)
        deadline = time.monotonic() + 5
        while (
            (not cohort_lock.exists() or _can_lock(cohort_lock))
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert not _can_lock(cohort_lock)
        time.sleep(0.1)
        assert not (state / "inner-pid").exists()

        (state / "release-operation-orphan").touch()
        _wait_gone(orphan_pid)
        _wait(state / "cohort-ready")
        successor_inner = int(
            (state / "inner-pid").read_text(encoding="ascii")
        )
        assert successor_inner != first_inner
        (state / "release").touch()
        stdout, stderr = successor.communicate(timeout=10)
        assert successor.returncode == 0, (stdout, stderr)
    finally:
        if successor is not None and successor.poll() is None:
            os.killpg(successor.pid, signal.SIGKILL)
            successor.wait(timeout=5)
        if first.poll() is None:
            os.killpg(first.pid, signal.SIGKILL)
            first.wait(timeout=5)
        if orphan_pid > 1 and Path(f"/proc/{orphan_pid}").exists():
            os.kill(orphan_pid, signal.SIGKILL)
            _wait_gone(orphan_pid)


def test_build_guardian_acquires_lifecycle_lock_before_cohort_lock(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    state = guardian_bundle[3]
    cohort_lock = _cohort_lock_path(guardian_bundle)
    cohort_lock.parent.mkdir(parents=True, mode=0o700)
    cohort_lock.parent.chmod(0o700)
    cohort_fd = os.open(
        cohort_lock,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    process: subprocess.Popen[str] | None = None
    try:
        fcntl.flock(cohort_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process = subprocess.Popen(
            _guardian_command(
                guardian_bundle,
                "unused",
                inner_arguments=("build", "--cohort-version", "34"),
            ),
            env={**os.environ, "QCSD_GUARDIAN_TEST_STATE": str(state)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        lifecycle_lock = _lock_path(guardian_bundle)
        deadline = time.monotonic() + 5
        while (
            (not lifecycle_lock.exists() or _can_lock(lifecycle_lock))
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert lifecycle_lock.exists() and not _can_lock(lifecycle_lock)
        assert not (state / "inner-pid").exists()

        fcntl.flock(cohort_fd, fcntl.LOCK_UN)
        _wait(state / "cohort-ready")
        (state / "release").touch()
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, (stdout, stderr)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(cohort_fd)


def test_guardian_normalizes_a_maximally_restrictive_inherited_umask(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    command = _guardian_command(isolated_guardian_bundle, "success")
    command = [command[0], "-B", *command[1:]]
    result = subprocess.run(
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            'umask 0777; exec "$@"',
            "qcsd-guardian-umask-test",
            *command,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    lock_parent = isolated_guardian_bundle[2]
    lock_value = _lock_path(isolated_guardian_bundle).stat(follow_symlinks=False)
    assert stat.S_ISREG(lock_value.st_mode)
    assert stat.S_IMODE(lock_value.st_mode) == 0o600
    assert lock_value.st_nlink == 1
    assert lock_value.st_size == 0
    assert not tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert not tuple(lock_parent.glob(".qcsd-buildx-*"))


@pytest.mark.parametrize("raises", [False, True])
def test_guard_scopes_and_restores_its_private_umask(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    raises: bool,
) -> None:
    module = _load_guardian(isolated_guardian_bundle[0])
    internal_umasks: list[int] = []

    def observe_private_umask(*_args: object, **_kwargs: object) -> int:
        observed = os.umask(0o077)
        os.umask(observed)
        internal_umasks.append(observed)
        if raises:
            raise module.GuardianError("injected guarded failure")
        return 23

    monkeypatch.setattr(module, "_require_unprivileged_identity", lambda: None)
    monkeypatch.setattr(module, "_guard_with_private_umask", observe_private_umask)
    caller_umask = 0o027
    original_umask = os.umask(caller_umask)
    try:
        if raises:
            with pytest.raises(module.GuardianError, match="injected guarded failure"):
                module.guard(
                    ("unused",),
                    lock_parent=isolated_guardian_bundle[2],
                )
        else:
            assert (
                module.guard(
                    ("unused",),
                    lock_parent=isolated_guardian_bundle[2],
                )
                == 23
            )
        restored = os.umask(caller_umask)
        assert restored == caller_umask
    finally:
        os.umask(original_umask)

    assert internal_umasks == [0o077]


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


def test_cmdline_loss_waits_for_exact_waitable_child(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    expected = module.ChildIdentity(43210, 9876, 43210, 43210, ("success",))
    waitable = iter((False, False, True))
    observations = 0
    anchors: list[object] = []

    monkeypatch.setattr(
        module,
        "_process_record",
        lambda pid: ("R", 1, expected.process_group, expected.session, expected.start_time),
    )
    monkeypatch.setattr(module, "_process_uid", lambda pid: os.getuid())

    def unavailable_cmdline(pid: int) -> tuple[str, ...]:
        raise module.GuardianError("injected terminal cmdline loss")

    def observe_child_exit(child: object) -> bool:
        nonlocal observations
        observations += 1
        return next(waitable)

    monkeypatch.setattr(module, "_read_cmdline", unavailable_cmdline)
    monkeypatch.setattr(module, "_observe_child_exit", observe_child_exit)
    monkeypatch.setattr(
        module, "_verify_exited_child_anchor", lambda child: anchors.append(child)
    )
    monkeypatch.setattr(module, "CHILD_EXIT_CONFIRM_ATTEMPTS", 3)
    monkeypatch.setattr(module, "CHILD_EXIT_CONFIRM_RETRY_SECONDS", 0)

    assert module._verify_inner_process(expected) is False
    assert observations == 3
    assert anchors == [expected]


def test_live_cmdline_loss_remains_an_integrity_failure(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    expected = module.ChildIdentity(43210, 9876, 43210, 43210, ("success",))
    observations = 0

    monkeypatch.setattr(
        module,
        "_process_record",
        lambda pid: ("R", 1, expected.process_group, expected.session, expected.start_time),
    )
    monkeypatch.setattr(module, "_process_uid", lambda pid: os.getuid())

    def unavailable_cmdline(pid: int) -> tuple[str, ...]:
        raise module.GuardianError("injected live cmdline loss")

    def child_remains_live(child: object) -> bool:
        nonlocal observations
        observations += 1
        return False

    monkeypatch.setattr(module, "_read_cmdline", unavailable_cmdline)
    monkeypatch.setattr(module, "_observe_child_exit", child_remains_live)
    monkeypatch.setattr(module, "CHILD_EXIT_CONFIRM_ATTEMPTS", 3)
    monkeypatch.setattr(module, "CHILD_EXIT_CONFIRM_RETRY_SECONDS", 0)

    with pytest.raises(module.GuardianError, match="injected live cmdline loss"):
        module._verify_inner_process(expected)
    assert observations == 3


def test_child_binding_retries_the_exec_cmdline_transition(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    pid = 43210
    start_time = 9876
    command = ("/bound/qcsd-lab", "success")
    exact = ("/bin/bash", "--noprofile", "--norc", "-p", *command)
    observations = 0

    monkeypatch.setattr(
        module,
        "_process_record",
        lambda observed_pid: ("R", 1, pid, pid, start_time),
    )
    monkeypatch.setattr(module, "_process_uid", lambda observed_pid: os.getuid())
    monkeypatch.setattr(module, "_observe_child_exit", lambda child: False)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)

    def transitioning_cmdline(observed_pid: int) -> tuple[str, ...]:
        nonlocal observations
        assert observed_pid == pid
        observations += 1
        if observations == 1:
            raise module.GuardianError("injected empty exec cmdline")
        if observations == 2:
            return ("/usr/bin/python3", "guardian-parent")
        return exact

    monkeypatch.setattr(module, "_read_cmdline", transitioning_cmdline)

    child = module._bind_child_identity(pid, command)

    assert child == module.ChildIdentity(pid, start_time, pid, pid, command)
    assert observations == 3


def test_child_binding_waits_for_the_exact_post_exec_command(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    guardian = guardian_bundle[0]
    source = guardian.read_text(encoding="utf-8")
    transition = "        os.setsid()\n        child_pid = os.getpid()\n"
    assert source.count(transition) == 1
    guardian.write_text(
        source.replace(
            transition,
            "        os.setsid()\n"
            "        # Hold the exact post-setsid/pre-exec transition open.\n"
            "        time.sleep(0.25)\n"
            "        child_pid = os.getpid()\n",
        ),
        encoding="utf-8",
    )

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not tuple(
        guardian_bundle[2].glob(
            f".qcsd-docker-config-{os.getuid()}.*"
        )
    )


@pytest.mark.parametrize("construction_mode", [0o700, 0o500])
def test_guardian_recovers_only_exact_empty_docker_config_residue(
    guardian_bundle: tuple[Path, Path, Path, Path],
    construction_mode: int,
) -> None:
    lock_parent = guardian_bundle[2]
    residue = lock_parent / _docker_config_construction_name("a" * 64)
    residue.mkdir(mode=construction_mode)

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not residue.exists()
    assert not tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_guardian_recovers_exact_quarantined_docker_config_residue(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = isolated_guardian_bundle[2]
    residue = lock_parent / _docker_config_quarantine_name("6" * 64)
    residue.mkdir(mode=0o500)

    result = _run_guardian(isolated_guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not residue.exists()
    assert not tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_guardian_retains_recovered_quarantine_until_inode_user_exits(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = guardian_bundle[2]
    residue = lock_parent / _docker_config_quarantine_name("7" * 64)
    residue.mkdir(mode=0o500)
    original = residue.stat(follow_symlinks=False)
    holder = subprocess.Popen(
        ["/bin/sleep", "30"],
        cwd=residue,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        blocked = _run_guardian(guardian_bundle, "success", timeout=20)

        assert blocked.returncode != 0, (blocked.stdout, blocked.stderr)
        assert "still has a live reference" in blocked.stderr
        observed = residue.stat(follow_symlinks=False)
        assert (observed.st_dev, observed.st_ino, observed.st_nlink) == (
            original.st_dev,
            original.st_ino,
            2,
        )
        assert holder.poll() is None
        assert not (guardian_bundle[3] / "grandchild-lock-fds").exists()

        os.killpg(holder.pid, signal.SIGKILL)
        holder.wait(timeout=5)

        successor = _run_guardian(guardian_bundle, "success", timeout=20)
        assert successor.returncode == 0, (successor.stdout, successor.stderr)
        assert not residue.exists()
        assert not tuple(
            lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
        )
    finally:
        if holder.poll() is None:
            os.killpg(holder.pid, signal.SIGKILL)
            holder.wait(timeout=5)
        if residue.exists():
            residue.chmod(0o700)
            residue.rmdir()


def test_quarantine_ignores_stale_published_docker_config_environment(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = guardian_bundle[2]
    nonce = "8" * 64
    residue = lock_parent / _docker_config_quarantine_name(nonce)
    published = lock_parent / _docker_config_name(nonce)
    residue.mkdir(mode=0o500)
    environment = os.environ.copy()
    environment["DOCKER_CONFIG"] = str(published)
    holder = subprocess.Popen(
        ["/bin/sleep", "30"],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        result = _run_guardian(guardian_bundle, "success", timeout=20)

        assert result.returncode == 0, (result.stdout, result.stderr)
        assert holder.poll() is None
        assert not published.exists()
        assert not residue.exists()
        assert not tuple(
            lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
        )
    finally:
        if holder.poll() is None:
            os.killpg(holder.pid, signal.SIGKILL)
            holder.wait(timeout=5)
        if residue.exists():
            residue.chmod(0o700)
            residue.rmdir()


@pytest.mark.parametrize("case", ["malformed-name", "wrong-mode"])
def test_guardian_fails_closed_on_unsafe_quarantined_docker_config_residue(
    guardian_bundle: tuple[Path, Path, Path, Path], case: str
) -> None:
    lock_parent = guardian_bundle[2]
    if case == "malformed-name":
        residue = lock_parent / (
            f".qcsd-docker-config-{os.getuid()}.retiring.v2."
            f"{_boot_token()}.{_self_start_time()}.short"
        )
        mode = 0o700
        expected_error = "config residue name is malformed"
    else:
        residue = lock_parent / _docker_config_quarantine_name("9" * 64)
        mode = 0o755
        expected_error = "config residue is not an exact empty directory"
    residue.mkdir(mode=mode)
    try:
        result = _run_guardian(guardian_bundle, "success")

        assert result.returncode != 0, (result.stdout, result.stderr)
        assert expected_error in result.stderr
        assert residue.is_dir()
        assert not (guardian_bundle[3] / "inner-pid").exists()
    finally:
        residue.chmod(0o700)
        residue.rmdir()


def test_duplicate_published_and_quarantined_generation_is_rejected(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = guardian_bundle[2]
    published = lock_parent / _docker_config_name("5" * 64)
    retiring = lock_parent / _docker_config_quarantine_name("5" * 64)
    published.mkdir(mode=0o500)
    retiring.mkdir(mode=0o500)
    try:
        result = _run_guardian(guardian_bundle, "success")

        assert result.returncode != 0, (result.stdout, result.stderr)
        assert "config residue generation is duplicated" in result.stderr
        assert published.is_dir()
        assert retiring.is_dir()
        assert not (guardian_bundle[3] / "inner-pid").exists()
    finally:
        published.chmod(0o700)
        published.rmdir()
        retiring.chmod(0o700)
        retiring.rmdir()


@pytest.mark.parametrize("removable_state", ["construction", "legacy"])
@pytest.mark.parametrize("blocking_state", ["malformed", "duplicate", "over-cap"])
def test_docker_config_scan_failure_does_not_mutate_an_earlier_safe_residue(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
    removable_state: str,
    blocking_state: str,
) -> None:
    lock_parent = isolated_guardian_bundle[2]
    prefix = f".qcsd-docker-config-{os.getuid()}."
    removable_name = (
        _docker_config_construction_name("0" * 64)
        if removable_state == "construction"
        else prefix + "0" * 64
    )
    created = [lock_parent / removable_name]
    created[0].mkdir(mode=0o700)

    if blocking_state == "malformed":
        created.append(lock_parent / f"{prefix}zz-malformed")
        created[-1].mkdir(mode=0o700)
        expected_error = "config residue name is malformed"
    elif blocking_state == "duplicate":
        nonce = "d" * 64
        created.extend(
            [
                lock_parent / _docker_config_quarantine_name(nonce),
                lock_parent / _docker_config_name(nonce),
            ]
        )
        for path in created[-2:]:
            path.mkdir(mode=0o500)
        expected_error = "config residue generation is duplicated"
    else:
        created.extend(
            lock_parent / _docker_config_name(f"{index:064x}")
            for index in range(1, 9)
        )
        for path in created[-8:]:
            path.mkdir(mode=0o500)
        expected_error = "config residue count exceeds its recovery bound"

    before = _docker_config_namespace_snapshot(lock_parent)
    try:
        result = _run_guardian(isolated_guardian_bundle, "success")

        assert result.returncode != 0, (result.stdout, result.stderr)
        assert expected_error in result.stderr
        assert _docker_config_namespace_snapshot(lock_parent) == before
        assert not (isolated_guardian_bundle[3] / "inner-pid").exists()
        assert not tuple(lock_parent.glob(".qcsd-buildx-*"))
    finally:
        for path in reversed(created):
            if path.exists():
                path.chmod(0o700)
                path.rmdir()


@pytest.mark.parametrize("residue_count", [8, 9])
def test_guardian_enforces_and_reserves_recoverable_docker_config_bound(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path], residue_count: int
) -> None:
    module = _load_guardian(isolated_guardian_bundle[0])
    lock_parent = isolated_guardian_bundle[2]
    paths = [
        lock_parent / _docker_config_name(f"{index:064x}")
        for index in range(1, residue_count + 1)
    ]
    for path in paths:
        path.mkdir(mode=0o500)
    parent_fd, _ = module._open_lock_parent(lock_parent)
    config_fd = -1
    identity = None
    residues: list[object] = []
    try:
        if residue_count == 9:
            with pytest.raises(
                module.GuardianError,
                match="config residue count exceeds its recovery bound",
            ):
                module._prepare_private_config(parent_fd, os.getpid())
            assert all(path.is_dir() for path in paths)
        else:
            config_fd, identity, residues = module._prepare_private_config(
                parent_fd, os.getpid()
            )
            assert len(residues) == residue_count - 1
            assert not paths[0].exists()
            assert {residue.config.path for residue in residues} == set(paths[1:])
            namespace = {
                path
                for path in lock_parent.iterdir()
                if path.name.startswith(
                    f".qcsd-docker-config-{os.getuid()}."
                )
            }
            assert identity is not None
            assert namespace == {
                identity.path,
                *(residue.config.path for residue in residues),
            }
            assert len(namespace) == module.MAX_RECOVERABLE_CONFIG_RESIDUES
            module._verify_private_config_residues(parent_fd, residues)
    finally:
        for residue in residues:
            module._cleanup_private_config(
                parent_fd,
                residue.descriptor,
                residue.config,
            )
            os.close(residue.descriptor)
        if config_fd >= 0 and identity is not None:
            module._cleanup_private_config(parent_fd, config_fd, identity)
            os.close(config_fd)
        for path in paths:
            if path.exists():
                path.chmod(0o700)
                path.rmdir()
        os.close(parent_fd)


def test_successor_recovers_maximum_crash_residue_state(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module = _load_guardian(isolated_guardian_bundle[0])
    lock_parent = isolated_guardian_bundle[2]
    paths = [
        lock_parent / _docker_config_name(f"{index:064x}")
        for index in range(1, module.MAX_RECOVERABLE_CONFIG_RESIDUES + 1)
    ]
    for path in paths:
        path.mkdir(mode=0o500)

    parent_fd = -1
    crashed_descriptors: list[int] = []
    try:
        parent_fd, _ = module._open_lock_parent(lock_parent)
        config_fd, current, residues = module._prepare_private_config(
            parent_fd, os.getpid()
        )
        crashed_descriptors = [
            config_fd,
            *(residue.descriptor for residue in residues),
        ]
        crash_namespace = _docker_config_namespace_snapshot(lock_parent)
        assert set(crash_namespace) == {
            current.path.name,
            *(residue.config.path.name for residue in residues),
        }
        assert len(crash_namespace) == module.MAX_RECOVERABLE_CONFIG_RESIDUES

        for descriptor in crashed_descriptors:
            os.close(descriptor)
        crashed_descriptors.clear()
        os.close(parent_fd)
        parent_fd = -1

        successor = _run_guardian(
            isolated_guardian_bundle, "success", timeout=20
        )

        assert successor.returncode == 0, (successor.stdout, successor.stderr)
        assert _docker_config_namespace_snapshot(lock_parent) == {}
    finally:
        for descriptor in crashed_descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if parent_fd >= 0:
            os.close(parent_fd)
        for path in lock_parent.glob(
            f".qcsd-docker-config-{os.getuid()}.*"
        ):
            path.chmod(0o700)
            path.rmdir()


def test_signal_during_full_capacity_prepublication_drain_aborts_recoverably(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module = _load_guardian(isolated_guardian_bundle[0])
    lock_parent = isolated_guardian_bundle[2]
    state = isolated_guardian_bundle[3]
    roots = [
        lock_parent / _docker_config_name(f"{index:064x}")
        for index in range(1, module.MAX_RECOVERABLE_CONFIG_RESIDUES + 1)
    ]
    for root in roots:
        root.mkdir(mode=0o500)
    before = _docker_config_namespace_snapshot(lock_parent)
    assert len(before) == module.MAX_RECOVERABLE_CONFIG_RESIDUES

    process = subprocess.Popen(
        _guardian_command(
            isolated_guardian_bundle,
            "success",
            pause_residue_drain=True,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait(state / "residue-drain-entered")
        assert not (state / "inner-pid").exists()
        started = time.monotonic()
        os.kill(process.pid, signal.SIGTERM)
        (state / "release-residue-drain").touch()
        stdout, stderr = process.communicate(timeout=4)
        elapsed = time.monotonic() - started

        assert process.returncode != 0, (stdout, stderr)
        assert "signal received during Docker config preparation" in stderr
        assert elapsed < 4
        assert not (state / "inner-pid").exists()
        assert _docker_config_namespace_snapshot(lock_parent) == before
        assert not tuple(lock_parent.glob(".qcsd-buildx-*"))
        assert _can_lock(_lock_path(isolated_guardian_bundle))

        successor = _run_guardian(
            isolated_guardian_bundle,
            "success",
            timeout=20,
        )
        assert successor.returncode == 0, (successor.stdout, successor.stderr)
        assert _docker_config_namespace_snapshot(lock_parent) == {}
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        for root in lock_parent.glob(
            f".qcsd-docker-config-{os.getuid()}.*"
        ):
            root.chmod(0o700)
            root.rmdir()


@pytest.mark.parametrize("failed_fsync", ["lock", "parent"])
def test_lock_creation_fsync_failure_closes_new_descriptor(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    failed_fsync: str,
) -> None:
    module = _load_guardian(isolated_guardian_bundle[0])
    lock_parent = isolated_guardian_bundle[2]
    parent_fd, _ = module._open_lock_parent(lock_parent)
    created: list[int] = []
    real_open = module.os.open
    real_fsync = module.os.fsync

    def record_created_lock(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if flags & module.os.O_CREAT:
            created.append(descriptor)
        return descriptor

    def fail_creation_barrier(descriptor: int) -> None:
        target = created[0] if failed_fsync == "lock" and created else parent_fd
        if descriptor == target:
            raise OSError(errno.EIO, "injected lock creation fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(module.os, "open", record_created_lock)
    monkeypatch.setattr(module.os, "fsync", fail_creation_barrier)
    try:
        with pytest.raises(module.GuardianError, match="cannot create lifecycle lock"):
            module._open_lock(parent_fd, lock_parent)

        assert len(created) == 1
        with pytest.raises(OSError) as closed:
            os.fstat(created[0])
        assert closed.value.errno == errno.EBADF
    finally:
        for descriptor in created:
            try:
                os.close(descriptor)
            except OSError:
                pass
        lock_path = lock_parent / f"qcsd-docker-lifecycle-{os.getuid()}.lock"
        if lock_path.exists():
            lock_path.unlink()
        os.close(parent_fd)


def test_buildx_root_fstat_failure_closes_new_descriptor(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(isolated_guardian_bundle[0])
    lock_parent = isolated_guardian_bundle[2]
    root_name = f".qcsd-buildx-config-{os.getuid()}." + "a" * 64
    root = lock_parent / root_name
    root.mkdir(mode=0o700)
    parent_fd, _ = module._open_lock_parent(lock_parent)
    opened: list[int] = []
    real_open = module.os.open
    real_fstat = module.os.fstat

    def record_buildx_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == root_name:
            opened.append(descriptor)
        return descriptor

    def fail_buildx_fstat(descriptor: int) -> os.stat_result:
        if opened and descriptor == opened[0]:
            raise OSError(errno.EIO, "injected Buildx root fstat failure")
        return real_fstat(descriptor)

    monkeypatch.setattr(module.os, "open", record_buildx_open)
    monkeypatch.setattr(module.os, "fstat", fail_buildx_fstat)
    try:
        with pytest.raises(module.GuardianError, match="cannot bind Buildx config root"):
            module._open_buildx_root(parent_fd, os.getpid(), root_name)

        assert len(opened) == 1
        with pytest.raises(OSError) as closed:
            real_fstat(opened[0])
        assert closed.value.errno == errno.EBADF
    finally:
        for descriptor in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass
        os.close(parent_fd)
        root.rmdir()


@pytest.mark.parametrize("residue_state", ["published", "retiring"])
def test_guardian_rejects_mode_0700_published_docker_config_residue(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
    residue_state: str,
) -> None:
    lock_parent = isolated_guardian_bundle[2]
    name_factory = (
        _docker_config_name
        if residue_state == "published"
        else _docker_config_quarantine_name
    )
    residue = lock_parent / name_factory("7" * 64)
    residue.mkdir(mode=0o700)
    try:
        result = _run_guardian(isolated_guardian_bundle, "success")

        assert result.returncode != 0, (result.stdout, result.stderr)
        assert "config residue is not an exact empty directory" in result.stderr
        observed = residue.stat(follow_symlinks=False)
        assert stat.S_IMODE(observed.st_mode) == 0o700
        assert observed.st_nlink == 2
        assert not (isolated_guardian_bundle[3] / "inner-pid").exists()
    finally:
        if residue.exists():
            residue.rmdir()


@pytest.mark.parametrize(
    ("interruption", "expected_status"),
    [("signal", 143), ("child-exit", 125)],
)
def test_final_admission_aborts_if_continuation_ends_during_residue_drain(
    guardian_bundle: tuple[Path, Path, Path, Path],
    interruption: str,
    expected_status: int,
) -> None:
    residue = guardian_bundle[2] / _docker_config_name("8" * 64)
    residue.mkdir(mode=0o500)
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "success",
            pause_residue_drain=True,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait(guardian_bundle[3] / "residue-drain-entered")
        if interruption == "signal":
            os.kill(process.pid, signal.SIGTERM)
        else:
            inner_pid = int(
                (guardian_bundle[3] / "inner-pid")
                .read_text(encoding="ascii")
                .strip()
            )
            os.killpg(inner_pid, signal.SIGKILL)
        (guardian_bundle[3] / "release-residue-drain").touch()
        stdout, stderr = process.communicate(timeout=8)

        assert process.returncode == expected_status, (stdout, stderr)
        assert not (guardian_bundle[3] / "grandchild-lock-fds").exists()
        assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
        assert not tuple(
            guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
        )
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_guardian_recovers_exact_legacy_construction_residue(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = guardian_bundle[2]
    residue = lock_parent / (
        f".qcsd-docker-config-{os.getuid()}." + "d" * 64
    )
    residue.mkdir(mode=0o700)

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not residue.exists()
    assert not tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_guardian_recovers_exact_transitional_construction_residue(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = guardian_bundle[2]
    residue = lock_parent / (
        f".qcsd-docker-config-{os.getuid()}.{_self_start_time()}."
        + "e" * 64
    )
    residue.mkdir(mode=0o700)

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not residue.exists()
    assert not tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_guardian_defers_published_docker_config_residue_until_users_drain(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    residue = guardian_bundle[2] / _docker_config_name("c" * 64)
    residue.mkdir(mode=0o500)
    holder = subprocess.Popen(
        ["/bin/sleep", "30"],
        cwd=residue,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        result = _run_guardian(guardian_bundle, "success")

        assert result.returncode != 0, (result.stdout, result.stderr)
        assert "still has a live reference" in result.stderr
        assert residue.is_dir()
        # The trusted inner process may enter the recovery-only phase, but it
        # cannot cross final admission while an unrelated user retains the
        # old published root.
        assert (guardian_bundle[3] / "inner-pid").is_file()
        assert not (guardian_bundle[3] / "grandchild-lock-fds").exists()
    finally:
        os.killpg(holder.pid, signal.SIGKILL)
        holder.wait(timeout=5)

    final = _run_guardian(guardian_bundle, "success")
    assert final.returncode == 0, (final.stdout, final.stderr)
    assert not residue.exists()


def test_forged_future_docker_config_start_is_rejected_before_census(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    residue = guardian_bundle[2] / _docker_config_name(
        "f" * 64, start=999999999999999999
    )
    residue.mkdir(mode=0o500)
    holder = subprocess.Popen(
        ["/bin/sleep", "30"],
        cwd=residue,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        result = _run_guardian(guardian_bundle, "success")
        assert result.returncode != 0, (result.stdout, result.stderr)
        assert "newer than the current guardian" in result.stderr
        assert residue.is_dir()
        assert not (guardian_bundle[3] / "inner-pid").exists()
    finally:
        holder.kill()
        holder.wait(timeout=5)
        residue.chmod(0o700)
        residue.rmdir()


def test_prior_boot_docker_config_does_not_compare_start_ticks_across_boots(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    foreign_boot = "0" * 32 if _boot_token() != "0" * 32 else "1" * 32
    residue = guardian_bundle[2] / _docker_config_name(
        "9" * 64,
        start=999999999999999999,
        boot_token=foreign_boot,
    )
    residue.mkdir(mode=0o500)

    result = _run_guardian(guardian_bundle, "success")

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not residue.exists()
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    ), result.stderr


def test_docker_config_residue_census_threshold_is_boot_relative(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module = _load_guardian(guardian_bundle[0])
    lock_parent = guardian_bundle[2]
    foreign_boot = "0" * 32 if _boot_token() != "0" * 32 else "1" * 32
    same_boot_start = 1
    foreign_start = 999999999999999999
    same_boot = lock_parent / _docker_config_name(
        "1" * 64, start=same_boot_start
    )
    foreign = lock_parent / _docker_config_name(
        "2" * 64,
        start=foreign_start,
        boot_token=foreign_boot,
    )
    same_boot.mkdir(mode=0o500)
    foreign.mkdir(mode=0o500)
    parent_fd, _ = module._open_lock_parent(lock_parent)
    config_fd = -1
    identity = None
    residues: list[object] = []
    try:
        config_fd, identity, residues = module._prepare_private_config(
            parent_fd, os.getpid()
        )
        by_path = {residue.config.path: residue for residue in residues}
        assert by_path[same_boot].guardian_start == same_boot_start
        assert by_path[same_boot].census_start == same_boot_start
        assert by_path[foreign].guardian_start == foreign_start
        assert by_path[foreign].census_start == module._process_start_time(
            os.getpid()
        )
    finally:
        for residue in residues:
            module._cleanup_private_config(
                parent_fd,
                residue.descriptor,
                residue.config,
            )
            os.close(residue.descriptor)
        if config_fd >= 0 and identity is not None:
            module._cleanup_private_config(parent_fd, config_fd, identity)
            os.close(config_fd)
        os.close(parent_fd)


def test_failed_post_publish_preparation_retires_only_new_config(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    parent_fd, _ = module._open_lock_parent(guardian_bundle[2])
    residue = guardian_bundle[2] / _docker_config_name("8" * 64)
    residue.mkdir(mode=0o500)
    try:
        monkeypatch.setattr(
            module,
            "_verify_private_config_namespace",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                module.GuardianError("injected namespace failure")
            ),
        )
        with pytest.raises(module.GuardianError, match="injected namespace failure"):
            module._prepare_private_config(parent_fd, os.getpid())

        assert residue.is_dir()
        assert tuple(
            guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
        ) == (residue,)
    finally:
        residue.chmod(0o700)
        residue.rmdir()
        os.close(parent_fd)


def test_failed_config_cleanup_rejects_mode_0700_published_root(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module = _load_guardian(isolated_guardian_bundle[0])
    lock_parent = isolated_guardian_bundle[2]
    root = lock_parent / _docker_config_name("b" * 64)
    root.mkdir(mode=0o700)
    original = root.stat(follow_symlinks=False)
    parent_fd, _ = module._open_lock_parent(lock_parent)
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    identity = module.ConfigDirectoryIdentity(
        path=root,
        device=original.st_dev,
        inode=original.st_ino,
        owner=original.st_uid,
        mode=stat.S_IMODE(original.st_mode),
        links=original.st_nlink,
    )
    try:
        with pytest.raises(
            module.GuardianError,
            match="failed Docker config construction identity is unsafe",
        ):
            module._cleanup_failed_private_config(parent_fd, descriptor, identity)

        observed = root.stat(follow_symlinks=False)
        assert (
            observed.st_dev,
            observed.st_ino,
            stat.S_IMODE(observed.st_mode),
            observed.st_nlink,
        ) == (original.st_dev, original.st_ino, 0o700, 2)
    finally:
        os.close(descriptor)
        os.close(parent_fd)
        if root.exists():
            root.rmdir()


def test_docker_config_publication_never_replaces_existing_residue(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    parent_fd, _ = module._open_lock_parent(guardian_bundle[2])
    residue = guardian_bundle[2] / _docker_config_name("a" * 64)
    residue.mkdir(mode=0o500)
    original = residue.stat(follow_symlinks=False)
    monkeypatch.setattr(module.os, "urandom", lambda size: b"\xaa" * size)
    try:
        with pytest.raises(module.GuardianError, match="promote Docker config root"):
            module._prepare_private_config(parent_fd, os.getpid())

        observed = residue.stat(follow_symlinks=False)
        assert (observed.st_dev, observed.st_ino, observed.st_nlink) == (
            original.st_dev,
            original.st_ino,
            2,
        )
        assert tuple(
            guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
        ) == (residue,)
    finally:
        residue.rmdir()
        os.close(parent_fd)


@pytest.mark.parametrize("reference_kind", ["environment", "descriptor"])
def test_docker_config_census_detects_non_cwd_references(
    guardian_bundle: tuple[Path, Path, Path, Path], reference_kind: str
) -> None:
    module = _load_guardian(guardian_bundle[0])
    root = guardian_bundle[2] / "census-root"
    root.mkdir(mode=0o500)
    environment = os.environ.copy()
    inherited = -1
    pass_fds: tuple[int, ...] = ()
    if reference_kind == "environment":
        environment["DOCKER_CONFIG"] = str(root)
    else:
        inherited = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        pass_fds = (inherited,)
    process = subprocess.Popen(
        ["/bin/sleep", "30"],
        env=environment,
        pass_fds=pass_fds,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if inherited >= 0:
        os.close(inherited)
    try:
        assert (
            module._process_references_docker_config(
                root, _self_start_time()
            )
            == process.pid
        )
    finally:
        process.kill()
        process.wait(timeout=5)


def test_docker_config_reference_between_clear_passes_blocks_removal(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    observations = iter((None,))
    monkeypatch.setattr(module, "_verify_private_config", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        module,
        "_process_references_docker_config",
        lambda root, threshold, **kwargs: next(observations, 43210),
    )
    residue = module.DockerConfigResidue(
        descriptor=99,
        config=module.ConfigDirectoryIdentity(
            path=guardian_bundle[2]
            / _docker_config_name("e" * 64, start=1),
            device=1,
            inode=2,
            owner=os.getuid(),
            mode=0o500,
            links=2,
        ),
        boot_token=_boot_token(),
        guardian_start=1,
        census_start=1,
    )

    with pytest.raises(module.GuardianError, match="live reference.*43210"):
        module._wait_for_private_config_drain(
            -1, residue, drain_seconds=0.1
        )


def test_quarantine_retains_and_later_retires_a_late_inode_reference(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    root = guardian_bundle[2] / _docker_config_name("f" * 64)
    root.mkdir(mode=0o500)
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    parent_fd = os.open(
        guardian_bundle[2],
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    value = os.fstat(descriptor)
    census_start = _self_start_time()
    residue = module.DockerConfigResidue(
        descriptor=descriptor,
        config=module.ConfigDirectoryIdentity(
            path=root,
            device=value.st_dev,
            inode=value.st_ino,
            owner=os.getuid(),
            mode=0o500,
            links=2,
        ),
        boot_token=_boot_token(),
        guardian_start=census_start,
        census_start=census_start,
    )
    rename = module._rename_noreplace
    holder: subprocess.Popen[bytes] | None = None

    def acquire_immediately_before_quarantine(
        *args: object, **kwargs: object
    ) -> None:
        nonlocal holder
        if kwargs.get("context") == "Docker config retirement":
            holder = subprocess.Popen(
                ["/bin/sleep", "30"],
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        rename(*args, **kwargs)

    monkeypatch.setattr(
        module, "_rename_noreplace", acquire_immediately_before_quarantine
    )
    try:
        with pytest.raises(
            module.GuardianError,
            match="still has a live reference",
        ):
            module._retire_private_config_residue(
                parent_fd,
                residue,
                deadline=time.monotonic() + 2,
            )
        assert holder is not None
        assert not root.exists()
        retiring = guardian_bundle[2] / _docker_config_quarantine_name("f" * 64)
        observed = retiring.stat(follow_symlinks=False)
        assert (observed.st_dev, observed.st_ino, observed.st_nlink) == (
            value.st_dev,
            value.st_ino,
            2,
        )
        assert residue.quarantined
        assert residue.config.path == retiring
        assert not residue.removed
        assert (
            os.stat(f"/proc/{holder.pid}/cwd").st_dev,
            os.stat(f"/proc/{holder.pid}/cwd").st_ino,
        ) == (value.st_dev, value.st_ino)
        os.killpg(holder.pid, signal.SIGKILL)
        holder.wait(timeout=5)
        module._retire_private_config_residue(
            parent_fd,
            residue,
            deadline=time.monotonic() + 2,
        )
        assert residue.removed
        assert not retiring.exists()
    finally:
        if holder is not None and holder.poll() is None:
            os.killpg(holder.pid, signal.SIGKILL)
            holder.wait(timeout=5)
        os.close(descriptor)
        os.close(parent_fd)


def test_quarantine_state_survives_parent_fsync_failure(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    root = guardian_bundle[2] / _docker_config_name("d" * 64)
    root.mkdir(mode=0o500)
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    parent_fd = os.open(
        guardian_bundle[2],
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    value = os.fstat(descriptor)
    census_start = _self_start_time()
    residue = module.DockerConfigResidue(
        descriptor=descriptor,
        config=module.ConfigDirectoryIdentity(
            path=root,
            device=value.st_dev,
            inode=value.st_ino,
            owner=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
            links=value.st_nlink,
        ),
        boot_token=_boot_token(),
        guardian_start=census_start,
        census_start=census_start,
    )
    real_fsync = module.os.fsync
    failed = False

    def fail_first_quarantine_fsync(fd: int) -> None:
        nonlocal failed
        if fd == parent_fd and residue.quarantined and not failed:
            failed = True
            raise OSError(errno.EIO, "injected quarantine fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(module.os, "fsync", fail_first_quarantine_fsync)
    retiring = guardian_bundle[2] / _docker_config_quarantine_name("d" * 64)
    try:
        with pytest.raises(
            module.GuardianError,
            match="cannot persist quarantined Docker config root",
        ):
            module._quarantine_private_config_residue(parent_fd, residue)
        assert failed
        assert residue.quarantined
        assert not residue.removed
        assert residue.config.path == retiring
        assert not root.exists()
        assert retiring.is_dir()

        module._retire_private_config_residue(
            parent_fd, residue, deadline=time.monotonic() + 2
        )
        assert residue.removed
        assert not retiring.exists()
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def test_quarantine_rename_never_replaces_an_existing_destination(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module = _load_guardian(guardian_bundle[0])
    nonce = "b" * 64
    root = guardian_bundle[2] / _docker_config_name(nonce)
    retiring = guardian_bundle[2] / _docker_config_quarantine_name(nonce)
    root.mkdir(mode=0o500)
    retiring.mkdir(mode=0o500)
    original = root.stat(follow_symlinks=False)
    collision = retiring.stat(follow_symlinks=False)
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    parent_fd = os.open(
        guardian_bundle[2],
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    census_start = _self_start_time()
    residue = module.DockerConfigResidue(
        descriptor=descriptor,
        config=module.ConfigDirectoryIdentity(
            path=root,
            device=original.st_dev,
            inode=original.st_ino,
            owner=original.st_uid,
            mode=stat.S_IMODE(original.st_mode),
            links=original.st_nlink,
        ),
        boot_token=_boot_token(),
        guardian_start=census_start,
        census_start=census_start,
    )
    try:
        with pytest.raises(
            module.GuardianError, match="cannot promote Docker config retirement"
        ):
            module._quarantine_private_config_residue(parent_fd, residue)
        assert not residue.quarantined
        assert not residue.removed
        assert residue.config.path == root
        assert (root.stat().st_dev, root.stat().st_ino) == (
            original.st_dev,
            original.st_ino,
        )
        assert (retiring.stat().st_dev, retiring.stat().st_ino) == (
            collision.st_dev,
            collision.st_ino,
        )
    finally:
        os.close(descriptor)
        root.chmod(0o700)
        root.rmdir()
        retiring.chmod(0o700)
        retiring.rmdir()
        os.close(parent_fd)


def test_removed_state_survives_parent_fsync_failure(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    root = guardian_bundle[2] / _docker_config_name("e" * 64)
    root.mkdir(mode=0o500)
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    parent_fd = os.open(
        guardian_bundle[2],
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    value = os.fstat(descriptor)
    census_start = _self_start_time()
    residue = module.DockerConfigResidue(
        descriptor=descriptor,
        config=module.ConfigDirectoryIdentity(
            path=root,
            device=value.st_dev,
            inode=value.st_ino,
            owner=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
            links=value.st_nlink,
        ),
        boot_token=_boot_token(),
        guardian_start=census_start,
        census_start=census_start,
    )
    real_fsync = module.os.fsync
    failed = False

    def fail_first_removed_fsync(fd: int) -> None:
        nonlocal failed
        if fd == parent_fd and residue.removed and not failed:
            failed = True
            raise OSError(errno.EIO, "injected removal fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(module.os, "fsync", fail_first_removed_fsync)
    retiring = guardian_bundle[2] / _docker_config_quarantine_name("e" * 64)
    try:
        with pytest.raises(
            module.GuardianError, match="cannot remove exact Docker config root"
        ):
            module._retire_private_config_residue(
                parent_fd, residue, deadline=time.monotonic() + 2
            )
        assert failed
        assert residue.quarantined
        assert residue.removed
        assert not root.exists()
        assert not retiring.exists()

        module._retire_private_config_residue(
            parent_fd, residue, deadline=time.monotonic() + 2
        )
        assert residue.removed
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def test_docker_config_drain_aborts_before_cleanup_on_signal(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    root = guardian_bundle[2] / _docker_config_name("7" * 64)
    root.mkdir(mode=0o500)
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    parent_fd = os.open(
        guardian_bundle[2],
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    value = os.fstat(descriptor)
    residue = module.DockerConfigResidue(
        descriptor=descriptor,
        config=module.ConfigDirectoryIdentity(
            path=root,
            device=value.st_dev,
            inode=value.st_ino,
            owner=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
            links=value.st_nlink,
        ),
        boot_token=_boot_token(),
        guardian_start=_self_start_time(),
        census_start=_self_start_time(),
    )
    latch = module._SignalLatch()
    cleanup_calls: list[bool] = []

    def census(*args: object, **kwargs: object) -> None:
        latch.handler(signal.SIGTERM, None)
        return None

    def continuation() -> None:
        if latch.first is not None:
            raise module.GuardianError(
                "signal received before final lifecycle admission"
            )

    monkeypatch.setattr(module, "_process_references_docker_config", census)
    monkeypatch.setattr(
        module,
        "_cleanup_private_config",
        lambda *args, **kwargs: cleanup_calls.append(True),
    )
    try:
        with pytest.raises(module.GuardianError, match="signal received"):
            module._retire_private_config_residue(
                parent_fd,
                residue,
                deadline=time.monotonic() + 1,
                continuation_check=continuation,
            )
        observed = root.stat(follow_symlinks=False)
        assert (observed.st_dev, observed.st_ino, observed.st_nlink) == (
            value.st_dev,
            value.st_ino,
            2,
        )
        assert cleanup_calls == []
    finally:
        os.close(parent_fd)
        os.close(descriptor)
        root.chmod(0o700)
        root.rmdir()


def test_docker_config_second_clear_pass_cannot_cross_deadline(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    times = iter((0.0, 0.1, 0.2, 1.1))
    observations: list[bool] = []
    monkeypatch.setattr(module, "_verify_private_config", lambda *args, **kwargs: None)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(module.time, "sleep", lambda value: None)
    monkeypatch.setattr(
        module,
        "_process_references_docker_config",
        lambda *args, **kwargs: observations.append(True),
    )
    residue = module.DockerConfigResidue(
        descriptor=99,
        config=module.ConfigDirectoryIdentity(
            path=guardian_bundle[2] / _docker_config_name("6" * 64, start=1),
            device=1,
            inode=2,
            owner=os.getuid(),
            mode=0o500,
            links=2,
        ),
        boot_token=_boot_token(),
        guardian_start=1,
        census_start=1,
    )

    with pytest.raises(module.GuardianError, match="stable clear censuses"):
        module._wait_for_private_config_drain(-1, residue, deadline=1.0)
    assert observations == [True, True]


def test_new_reserved_docker_root_during_recovery_blocks_final_admission(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "recovery-wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    injected = guardian_bundle[2] / _docker_config_name("1" * 64)
    try:
        _wait(guardian_bundle[3] / "recovery-phase")
        injected.mkdir(mode=0o700)
        (guardian_bundle[3] / "release-recovery").touch()
        stdout, stderr = process.communicate(timeout=8)
        assert process.returncode != 0, (stdout, stderr)
        assert "reserved Docker config namespace changed" in stderr
        assert not (guardian_bundle[3] / "post-final-mutation").exists()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if injected.is_dir():
            injected.rmdir()


def test_published_residue_replacement_during_recovery_blocks_final_admission(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    residue = guardian_bundle[2] / _docker_config_name("5" * 64)
    residue.mkdir(mode=0o500)
    replacement = guardian_bundle[3] / "replacement-config"
    replacement.mkdir(mode=0o700)
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "recovery-wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        _wait(guardian_bundle[3] / "recovery-phase")
        residue.chmod(0o700)
        residue.rmdir()
        residue.symlink_to(replacement, target_is_directory=True)
        (guardian_bundle[3] / "release-recovery").touch()
        stdout, stderr = process.communicate(timeout=8)

        assert process.returncode == 125, (stdout, stderr)
        assert "private config identity changed" in stderr
        assert residue.is_symlink()
        assert not (guardian_bundle[3] / "post-final-mutation").exists()
        assert tuple(
            guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
        ) == (residue,)
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        residue.unlink(missing_ok=True)
        replacement.rmdir()

    successor = _run_guardian(guardian_bundle, "success")
    assert successor.returncode == 0, (successor.stdout, successor.stderr)


def test_published_residue_becoming_nonempty_during_recovery_is_retained(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    residue = guardian_bundle[2] / _docker_config_name("5" * 64)
    residue.mkdir(mode=0o500)
    original = residue.stat(follow_symlinks=False)
    process = subprocess.Popen(
        _guardian_command(guardian_bundle, "recovery-wait"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    foreign = residue / "foreign"
    try:
        _wait(guardian_bundle[3] / "recovery-phase")
        residue.chmod(0o700)
        foreign.write_text("unexpected\n", encoding="ascii")
        residue.chmod(0o500)
        (guardian_bundle[3] / "release-recovery").touch()
        stdout, stderr = process.communicate(timeout=8)

        assert process.returncode == 125, (stdout, stderr)
        assert "config root is not empty" in stderr
        assert not (guardian_bundle[3] / "post-final-mutation").exists()
        observed = residue.stat(follow_symlinks=False)
        assert (observed.st_dev, observed.st_ino, observed.st_nlink) == (
            original.st_dev,
            original.st_ino,
            2,
        )
        blocked = _run_guardian(guardian_bundle, "success")
        assert blocked.returncode == 125, (blocked.stdout, blocked.stderr)
        assert residue.is_dir()
        assert not (guardian_bundle[3] / "grandchild-lock-fds").exists()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        residue.chmod(0o700)
        if foreign.exists():
            foreign.unlink()
        residue.chmod(0o500)

    successor = _run_guardian(guardian_bundle, "success")
    assert successor.returncode == 0, (successor.stdout, successor.stderr)
    assert not residue.exists()


def test_reserved_root_added_after_final_admission_is_terminal_failure(
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
    injected = guardian_bundle[2] / _docker_config_name("4" * 64)
    try:
        _wait(guardian_bundle[3] / "ready")
        injected.mkdir(mode=0o700)
        (guardian_bundle[3] / "release").touch()
        stdout, stderr = process.communicate(timeout=8)

        assert process.returncode == 125, (stdout, stderr)
        assert "reserved Docker config namespace changed" in stderr
        assert injected.is_dir()
        assert tuple(
            guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
        ) == (injected,)
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if injected.is_dir():
            injected.rmdir()

    successor = _run_guardian(guardian_bundle, "success")
    assert successor.returncode == 0, (successor.stdout, successor.stderr)


@pytest.mark.parametrize("action", ["close-initial-go", "close-final-go"])
def test_closed_admission_reader_fails_cleanly(
    guardian_bundle: tuple[Path, Path, Path, Path], action: str
) -> None:
    result = _run_guardian(guardian_bundle, action)

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "Traceback" not in result.stderr
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))


@pytest.mark.parametrize(
    "action",
    [
        "initial-frame-wrong",
        "initial-frame-short",
        "initial-frame-long",
        "initial-frame-unterminated",
        "initial-frame-extra",
        "recovery-frame-wrong",
        "recovery-frame-short",
        "recovery-frame-long",
        "recovery-frame-unterminated",
        "recovery-frame-extra",
    ],
)
def test_malformed_guardian_handshake_frame_fails_cleanly(
    guardian_bundle: tuple[Path, Path, Path, Path], action: str
) -> None:
    result = _run_guardian(guardian_bundle, action)

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "Traceback" not in result.stderr
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    assert _can_lock(_lock_path(guardian_bundle))


@pytest.mark.parametrize(
    ("channel", "diagnostic"),
    [
        ("initial", "cannot read the lifecycle readiness channel"),
        ("recovery", "cannot read the lifecycle recovery channel"),
    ],
)
def test_guardian_channel_read_oserror_fails_cleanly(
    guardian_bundle: tuple[Path, Path, Path, Path],
    channel: str,
    diagnostic: str,
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "success",
            read_failure=channel,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert diagnostic in result.stderr
    assert "Traceback" not in result.stderr
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert _can_lock(_lock_path(guardian_bundle))


def test_child_cannot_return_success_before_final_admission(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "exit-before-final")

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_recovery_timeout_denies_final_admission_and_cleans_current_state(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    started = time.monotonic()
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "recovery-wait",
            recovery_timeout=0.1,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )
    elapsed = time.monotonic() - started

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert elapsed < 3
    assert not (guardian_bundle[3] / "post-final-mutation").exists()
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert _can_lock(_lock_path(guardian_bundle))


def test_recovery_idle_timeout_denies_final_admission_and_cleans_current_state(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    started = time.monotonic()
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "recovery-wait",
            recovery_timeout=5,
            recovery_idle_timeout=0.1,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )
    elapsed = time.monotonic() - started

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert elapsed < 3
    assert not (guardian_bundle[3] / "post-final-mutation").exists()
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert _can_lock(_lock_path(guardian_bundle))


class _DeadlineClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, duration: float) -> None:
        self.now += duration
        if self.now > 2.0:
            raise AssertionError("guardian deadline model did not terminate")


def _run_isolated_recovery_deadline_model(
    monkeypatch: pytest.MonkeyPatch,
    *,
    lease_events: list[tuple[float, str, float]],
    recovery_at: float | None,
    recovery_timeout: float,
    recovery_idle_timeout: float,
) -> tuple[
    int,
    list[tuple[str, bool, bool]],
    list[tuple[float, float, str, float | None]],
    float,
]:
    """Drive the recovery state machine without a process or public socket."""

    module = _load_guardian(GUARDIAN)
    clock = _DeadlineClock()
    ready_fd = 101
    recovery_fd = 102
    ready_chunks = [b"a" * 64 + b"\n", b""]
    recovery_stage = 0
    pending_events = list(lease_events)
    decisions: list[tuple[str, bool, bool]] = []
    served: list[tuple[float, float, str, float | None]] = []
    killed = False

    def read_channel(descriptor: int, _size: int) -> bytes:
        nonlocal recovery_stage
        if descriptor == ready_fd:
            return ready_chunks.pop(0)
        assert descriptor == recovery_fd
        if recovery_at is None or clock.now + 1e-9 < recovery_at:
            raise BlockingIOError
        if recovery_stage == 0:
            recovery_stage = 1
            return b"c" * 64 + b"\n"
        recovery_stage = 2
        return b""

    def serve_lease(*_args: object, **kwargs: object) -> str:
        if not pending_events or clock.now + 1e-9 < pending_events[0][0]:
            return "none"
        _scheduled, outcome, duration = pending_events.pop(0)
        started = clock.now
        clock.now += duration
        served.append((started, clock.now, outcome, kwargs.get("deadline")))
        return outcome

    def publish_decision(
        _descriptor: int,
        nonce: str,
        _latch: object,
        _child: object,
        forwarded: bool,
        *,
        ready: bool,
        failed: bool,
    ) -> tuple[bool, bool, bool, bool]:
        decisions.append((nonce, ready, failed))
        return ready and not failed, failed, forwarded, True

    def kill_child(*_args: object, **_kwargs: object) -> None:
        nonlocal killed
        killed = True

    monkeypatch.setattr(
        module,
        "os",
        SimpleNamespace(
            close=lambda _descriptor: None,
            getpid=os.getpid,
            read=read_channel,
            set_blocking=lambda _descriptor, _blocking: None,
        ),
    )
    monkeypatch.setattr(
        module,
        "time",
        SimpleNamespace(monotonic=clock.monotonic, sleep=clock.sleep),
    )
    monkeypatch.setattr(module, "RECOVERY_TIMEOUT_SECONDS", recovery_timeout)
    monkeypatch.setattr(
        module, "RECOVERY_IDLE_TIMEOUT_SECONDS", recovery_idle_timeout
    )
    monkeypatch.setattr(module, "INTEGRITY_CHECK_SECONDS", 10.0)
    monkeypatch.setattr(module, "_serve_one_lease", serve_lease)
    monkeypatch.setattr(module, "_publish_admission_decision", publish_decision)
    monkeypatch.setattr(module, "_kill_child_group", kill_child)
    monkeypatch.setattr(
        module,
        "_observe_child_exit",
        lambda _child: killed or len(decisions) >= 2,
    )
    monkeypatch.setattr(module, "_reap_drained_child", lambda _child: 0)
    monkeypatch.setattr(module, "_verify_inner_process", lambda _child: True)
    for verifier in (
        "_verify_buildx_config",
        "_verify_lock_identity",
        "_verify_private_config",
        "_verify_private_config_namespace",
        "_verify_private_config_residues",
        "_verify_guardian_lock",
        "_verify_runtime_environment",
        "_verify_source_identity",
    ):
        monkeypatch.setattr(module, verifier, lambda *_args, **_kwargs: None)

    result = module._wait_for_child(
        child=module.ChildIdentity(424242, 1, 424242, 424242, ("qcsd",)),
        ready_read=ready_fd,
        nonce="a" * 64,
        go_write=103,
        go_nonce="b" * 64,
        recovery_read=recovery_fd,
        recovery_nonce="c" * 64,
        final_go_write=104,
        final_go_nonce="d" * 64,
        lease_listener=object(),
        lease_socket="@isolated-deadline-model",
        lease_nonce="e" * 64,
        latch=module._SignalLatch(),
        parent_fd=-1,
        lock_fd=-1,
        lock_identity=None,
        source_fd=-1,
        source_identity=None,
        qcsd_fd=-1,
        qcsd_identity=None,
        helper_fd=-1,
        helper_identity=None,
        native_fd=-1,
        native_identity=None,
        docker_config_fd=-1,
        docker_config_identity=None,
        docker_config_residues=[],
        buildx_config_fd=-1,
        buildx_config_identity=None,
        runtime_identity=None,
    )
    return result, decisions, served, clock.now


@pytest.mark.parametrize(
    (
        "case",
        "lease_events",
        "expected_status",
        "expected_decisions",
    ),
    [
        ("timely-admitted", [(0.05, "admitted", 0.0)], 0, 2),
        ("timely-rejected", [(0.05, "rejected", 0.0)], 125, 1),
        ("late-admitted", [(0.09, "admitted", 0.03)], 125, 1),
    ],
)
def test_recovery_idle_refresh_requires_a_timely_admitted_lease(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: str,
    lease_events: list[tuple[float, str, float]],
    expected_status: int,
    expected_decisions: int,
) -> None:
    result, decisions, served, _finished = _run_isolated_recovery_deadline_model(
        monkeypatch,
        lease_events=lease_events,
        recovery_at=0.12,
        recovery_timeout=0.5,
        recovery_idle_timeout=0.1,
    )
    error = capsys.readouterr().err

    assert result == expected_status
    assert len(decisions) == expected_decisions
    assert [event[2] for event in served] == [lease_events[0][1]]
    service_deadline = served[0][3]
    assert service_deadline is not None
    if case == "timely-admitted":
        assert error == ""
        assert served[0][1] < service_deadline
    else:
        assert "lifecycle recovery made no bounded progress" in error
    if case == "late-admitted":
        assert served[0][0] < service_deadline <= served[0][1]


def test_authenticated_progress_cannot_extend_absolute_recovery_deadline(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result, decisions, served, finished = _run_isolated_recovery_deadline_model(
        monkeypatch,
        lease_events=[
            (0.04, "admitted", 0.0),
            (0.08, "admitted", 0.0),
            (0.12, "admitted", 0.0),
        ],
        recovery_at=None,
        recovery_timeout=0.15,
        recovery_idle_timeout=0.05,
    )
    error = capsys.readouterr().err

    assert result == 125
    assert len(decisions) == 1
    assert [event[2] for event in served] == ["admitted"] * 3
    assert 0.15 <= finished < 0.20
    assert "lifecycle recovery exceeded its deadline" in error


def test_buildx_cleanup_failure_preserves_stale_and_current_docker_roots(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = guardian_bundle[2]
    stale = lock_parent / _docker_config_name("4" * 64)
    stale.mkdir(mode=0o500)
    stale_value = stale.stat(follow_symlinks=False)

    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "exit-before-final",
            fail_buildx_cleanup=True,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "injected Buildx cleanup failure" in result.stderr
    roots = tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert len(roots) == 2
    identities = {
        (value.st_dev, value.st_ino, value.st_nlink)
        for root in roots
        for value in (root.stat(follow_symlinks=False),)
    }
    assert (stale_value.st_dev, stale_value.st_ino, 2) in identities
    assert all(links == 2 for _, _, links in identities)

    successor = _run_guardian(guardian_bundle, "success", timeout=20)
    assert successor.returncode == 0, (successor.stdout, successor.stderr)
    assert not tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert not tuple(lock_parent.glob(".qcsd-buildx-*"))


@pytest.mark.parametrize(
    ("failure", "retained_construction"),
    [
        ("pre-open", True),
        ("rename", False),
        ("post-rename-fsync", False),
    ],
)
def test_docker_config_preparation_oserror_is_typed_and_recoverable(
    guardian_bundle: tuple[Path, Path, Path, Path],
    failure: str,
    retained_construction: bool,
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "success",
            prepare_failure=failure,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "cannot prepare exact Docker config" in result.stderr
    assert "Traceback" not in result.stderr
    roots = tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert bool(roots) is retained_construction
    if retained_construction:
        assert len(roots) == 1
        assert ".construct.v2." in roots[0].name
        assert stat.S_IMODE(roots[0].stat(follow_symlinks=False).st_mode) == 0o700

    successor = _run_guardian(guardian_bundle, "success", timeout=20)
    assert successor.returncode == 0, (successor.stdout, successor.stderr)
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_listener_close_failure_is_typed_after_safe_cleanup(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "success",
            fail_listener_close=True,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "cannot close lifecycle lease listener" in result.stderr
    assert "Traceback" not in result.stderr
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert _can_lock(_lock_path(guardian_bundle))


@pytest.mark.parametrize(
    ("failure", "retained_path"),
    [
        ("current-rmdir", True),
        ("current-fsync-recreate", True),
        ("current-close", False),
    ],
)
def test_current_docker_config_cleanup_fault_is_typed_and_recoverable(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
    failure: str,
    retained_path: bool,
) -> None:
    guardian_bundle = isolated_guardian_bundle
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "success",
            cleanup_failure=failure,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "terminal cleanup incomplete" in result.stderr
    assert "Traceback" not in result.stderr
    roots = tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert bool(roots) is retained_path
    if failure == "current-rmdir":
        assert stat.S_IMODE(roots[0].stat(follow_symlinks=False).st_mode) == 0o500
    elif failure == "current-fsync-recreate":
        expected = (guardian_bundle[3] / "docker-config-expected").read_text(
            encoding="ascii"
        ).strip()
        observed = roots[0].stat(follow_symlinks=False)
        assert f"{observed.st_dev}:{observed.st_ino}" != expected
        assert stat.S_IMODE(observed.st_mode) == 0o700
    assert _can_lock(_lock_path(guardian_bundle))

    successor = _run_guardian(guardian_bundle, "success", timeout=20)
    if failure == "current-fsync-recreate":
        assert successor.returncode != 0, (
            successor.stdout,
            successor.stderr,
        )
        assert (
            "config residue is not an exact empty directory"
            in successor.stderr
        )
        assert roots[0].is_dir()
        roots[0].rmdir()
    else:
        assert successor.returncode == 0, (
            successor.stdout,
            successor.stderr,
        )
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_multiple_residue_cleanup_failure_preserves_only_failed_identity(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    lock_parent = guardian_bundle[2]
    first = lock_parent / _docker_config_name("1" * 64)
    second = lock_parent / _docker_config_name("2" * 64)
    first.mkdir(mode=0o500)
    second.mkdir(mode=0o500)
    second_value = second.stat(follow_symlinks=False)
    second_retiring = lock_parent / _docker_config_quarantine_name("2" * 64)

    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "success",
            cleanup_failure="second-residue",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "injected second residue cleanup failure" in result.stderr
    assert not first.exists()
    assert not second.exists()
    observed = second_retiring.stat(follow_symlinks=False)
    assert (observed.st_dev, observed.st_ino, observed.st_nlink) == (
        second_value.st_dev,
        second_value.st_ino,
        2,
    )
    roots = tuple(lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*"))
    assert roots == (second_retiring,)
    assert "Traceback" not in result.stderr

    successor = _run_guardian(guardian_bundle, "success", timeout=20)
    assert successor.returncode == 0, (successor.stdout, successor.stderr)
    assert not tuple(
        lock_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_cleanup_failure_takes_precedence_over_cleanup_signal(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = subprocess.run(
        _guardian_command(
            guardian_bundle,
            "success",
            signal_during_cleanup=True,
            cleanup_failure="current-close",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "terminal cleanup incomplete" in result.stderr
    assert "Traceback" not in result.stderr
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    ), result.stderr
    assert _can_lock(_lock_path(guardian_bundle))


def test_linked_docker_config_is_exact_read_only_empty_and_unwritable(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module = _load_guardian(guardian_bundle[0])
    native = _load_native(guardian_bundle[0].parent / NATIVE.name)
    parent_fd, _ = module._open_lock_parent(guardian_bundle[2])
    config_fd = -1
    identity = None
    try:
        config_fd, identity, residues = module._prepare_private_config(
            parent_fd, os.getpid()
        )
        assert residues == []
        value = os.fstat(config_fd)
        assert (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            stat.S_IMODE(value.st_mode),
            value.st_nlink,
        ) == (
            identity.device,
            identity.inode,
            os.getuid(),
            module.DOCKER_CONFIG_MODE,
            2,
        )
        assert identity.path.parent == guardian_bundle[2]
        matched = re.fullmatch(
            rf"[.]qcsd-docker-config-{os.getuid()}[.]v2[.]"
            rf"([0-9a-f]{{32}})[.]([1-9][0-9]*)[.][0-9a-f]{{64}}",
            identity.path.name,
        )
        assert matched is not None
        assert matched.group(1) == _boot_token()
        assert int(matched.group(2)) == _self_start_time()
        assert identity.path.is_dir()
        assert os.listdir(config_fd) == []
        assert native._exact_configuration_descriptor(
            config_fd,
            expected_mode=native.DOCKER_CONFIG_MODE,
            expected_links=2,
            exact_links=True,
            require_empty=True,
        )

        with pytest.raises(OSError) as failure:
            os.open(
                ".token_seed.lock",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=config_fd,
            )
        assert failure.value.errno in {errno.EACCES, errno.EROFS}
        assert os.listdir(config_fd) == []

        os.fchmod(config_fd, 0o700)
        writable = module.ConfigDirectoryIdentity(
            path=identity.path,
            device=identity.device,
            inode=identity.inode,
            owner=identity.owner,
            mode=0o700,
            links=identity.links,
        )
        with pytest.raises(module.GuardianError, match="not linked"):
            module._verify_private_config(
                parent_fd, config_fd, writable, require_empty=True
            )
        assert not native._exact_configuration_descriptor(
            config_fd,
            expected_mode=native.DOCKER_CONFIG_MODE,
            expected_links=2,
            exact_links=True,
            require_empty=True,
        )
        child_fd = os.open(
            "foreign",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=config_fd,
        )
        os.close(child_fd)
        os.fchmod(config_fd, module.DOCKER_CONFIG_MODE)
        assert not native._exact_configuration_descriptor(
            config_fd,
            expected_mode=native.DOCKER_CONFIG_MODE,
            expected_links=2,
            exact_links=True,
            require_empty=True,
        )
        os.fchmod(config_fd, 0o700)
        os.unlink("foreign", dir_fd=config_fd)
    finally:
        if config_fd >= 0 and identity is not None:
            os.fchmod(config_fd, module.DOCKER_CONFIG_MODE)
            module._cleanup_private_config(parent_fd, config_fd, identity)
            os.close(config_fd)
        os.close(parent_fd)


@pytest.mark.parametrize(
    "identity_getter",
    ["getuid", "geteuid", "getgid", "getegid", "getresuid", "getresgid"],
)
def test_guardian_rejects_root_or_split_process_identity(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    identity_getter: str,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    replacement: object = (0, 0, 0) if identity_getter.startswith("getres") else 0
    monkeypatch.setattr(module.os, identity_getter, lambda: replacement)

    with pytest.raises(module.GuardianError, match="matching non-root UID/GID"):
        module._require_unprivileged_identity()


@pytest.mark.parametrize("capability", ["CapInh", "CapPrm", "CapEff", "CapAmb"])
def test_guardian_rejects_dac_override_in_every_acquirable_capability_set(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capability: str,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    original = module.Path.read_text

    def privileged_status(path: Path, *args: object, **kwargs: object) -> str:
        text = original(path, *args, **kwargs)
        if path == Path("/proc/self/status"):
            text, count = re.subn(
                rf"(?m)^{capability}:\s+[0-9a-fA-F]+$",
                f"{capability}:\t0000000000000002",
                text,
            )
            assert count == 1
        return text

    monkeypatch.setattr(module.Path, "read_text", privileged_status)
    with pytest.raises(module.GuardianError, match="without CAP_DAC_OVERRIDE"):
        module._require_unprivileged_identity()


@pytest.mark.parametrize(
    "case",
    [
        "malformed-name",
        "nonempty",
        "construction-malformed",
        "construction-nonempty",
        "legacy-published",
        "transitional-published",
    ],
)
def test_guardian_fails_closed_on_unsafe_docker_config_residue(
    guardian_bundle: tuple[Path, Path, Path, Path], case: str
) -> None:
    lock_parent = guardian_bundle[2]
    if case == "malformed-name":
        suffix = "not-a-token"
    elif case == "construction-malformed":
        suffix = f"construct.v2.{_boot_token()}.{_self_start_time()}.short"
    elif case == "construction-nonempty":
        suffix = _docker_config_construction_name("6" * 64).removeprefix(
            f".qcsd-docker-config-{os.getuid()}."
        )
    elif case == "legacy-published":
        suffix = "b" * 64
    elif case == "transitional-published":
        suffix = f"{_self_start_time()}.{'c' * 64}"
    else:
        suffix = f"{_self_start_time()}.{'b' * 64}"
    residue = lock_parent / f".qcsd-docker-config-{os.getuid()}.{suffix}"
    residue.mkdir(mode=0o500 if case.endswith("published") else 0o700)
    if case in {"nonempty", "construction-nonempty"}:
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


def test_real_buildx_pinned_metadata_keeps_guardian_docker_config_empty(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    if os.environ.get("QCSD_RUN_PINNED_BUILDX_METADATA_PROBE") != "1":
        pytest.skip("pinned registry metadata probe is opt-in")

    result = _run_guardian(
        guardian_bundle, "docker-buildx-pinned-metadata-probe", timeout=30
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    plugins = json.loads(
        (guardian_bundle[3] / "docker-client-plugins.json").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(plugins, list)
    buildx_plugins = [
        plugin
        for plugin in plugins
        if isinstance(plugin, dict) and plugin.get("Name") == "buildx"
    ]
    assert len(buildx_plugins) == 1
    buildx_plugin = buildx_plugins[0]
    assert isinstance(buildx_plugin.get("Path"), str)
    assert Path(buildx_plugin["Path"]).is_absolute()
    assert Path(buildx_plugin["Path"]).name == "docker-buildx"
    assert isinstance(buildx_plugin.get("Version"), str)
    assert buildx_plugin["Version"]
    buildx_version = (guardian_bundle[3] / "docker-buildx-version").read_text(
        encoding="utf-8"
    ).strip()
    assert buildx_version
    assert buildx_plugin["Version"] in buildx_version
    digest = "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
    assert digest in (guardian_bundle[3] / "buildx-metadata").read_text(
        encoding="utf-8"
    )
    identity = (guardian_bundle[3] / "buildx-docker-config-identity").read_text(
        encoding="ascii"
    )
    assert identity.strip().endswith(f":{os.getuid()}:500:2:directory")
    assert (guardian_bundle[3] / "buildx-docker-config-children").read_text(
        encoding="ascii"
    ) == ""
    _assert_retired_linked_docker_path(
        guardian_bundle[3] / "buildx-docker-config-path",
        guardian_bundle[2],
    )
    buildx_identity = (guardian_bundle[3] / "buildx-config-identity").read_text(
        encoding="ascii"
    ).strip().split(":")
    assert buildx_identity[:2] == [str(os.getuid()), "700"]
    assert int(buildx_identity[2]) >= 2
    assert buildx_identity[3] == "directory"
    assert (guardian_bundle[3] / "buildx-config-children").read_text(
        encoding="utf-8"
    ).strip()
    assert not tuple(guardian_bundle[2].glob(".qcsd-buildx-*"))


def test_real_pinned_frontend_build_uses_read_only_linked_docker_config(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    if os.environ.get("QCSD_RUN_PINNED_BUILDX_FRONTEND_PROBE") != "1":
        pytest.skip("pinned Dockerfile frontend build probe is opt-in")

    result = _run_guardian(
        guardian_bundle, "docker-buildx-pinned-frontend-probe", timeout=120
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (guardian_bundle[3] / "pinned-frontend-build").is_file()
    identity = (
        guardian_bundle[3] / "frontend-docker-config-identity"
    ).read_text(encoding="ascii")
    assert identity.strip().endswith(f":{os.getuid()}:500:2:directory")
    assert (guardian_bundle[3] / "frontend-docker-config-children").read_text(
        encoding="ascii"
    ) == ""
    _assert_retired_linked_docker_path(
        guardian_bundle[3] / "frontend-docker-config-path",
        guardian_bundle[2],
    )
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
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
        [str(qcsd), "etf-probe", "--destination", str(tmp_path / "etf.json")],
        cwd=project,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode in {1, 125}, (result.stdout, result.stderr)
    assert "etf-probe is disabled" not in result.stderr
    assert "lifecycle guardian authority is invalid" not in result.stderr
    assert "final Docker lifecycle admission failed" not in result.stderr
    assert not tuple(lifecycle_parent.glob(".qcsd-buildx-*"))


def test_real_qcsd_loader_completes_two_stage_recovery_without_docker(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    guardian, qcsd, lifecycle_parent, state = guardian_bundle
    qcsd_source = (ROOT / "qcsd-lab").read_text(encoding="utf-8")
    anchor = "\nreconcile_stale_docker_supervisors() {"
    assert qcsd_source.count(anchor) == 1
    test_dispatch = r'''
if [[ "${1:-}" == "__test-two-stage-lifecycle" ]]; then
  if [[ -z "${QCSD_DOCKER_LOCK_GUARDIAN_PID:-}" ]]; then
    _qcsd_enter_lifecycle_guardian || exit 1
  fi
  _qcsd_validate_lifecycle_guardian || exit 91
  [[ "${_QCSD_LIFECYCLE_RECOVERY_STATE}" == armed ]] || exit 92
  state=$2
  printf 'validated\n' >"$state/production-loader-validated"
  lifecycle_parent=${_QCSD_LIFECYCLE_LOCK_PATH%/*}
  current=${_QCSD_LIFECYCLE_DOCKER_CONFIG_PATH}
  shopt -s nullglob
  roots=("$lifecycle_parent"/.qcsd-docker-config-*)
  shopt -u nullglob
  stale=()
  for root in "${roots[@]}"; do
    [[ "$root" == "$current" ]] || stale+=("$root")
  done
  (( ${#stale[@]} == 1 )) || exit 93
  printf '%s\n' "${stale[0]}" >"$state/production-loader-stale"
  _qcsd_complete_lifecycle_recovery || exit 94
  [[ "${_QCSD_LIFECYCLE_RECOVERY_STATE}" == complete ]] || exit 95
  [[ ! -e "${stale[0]}" && ! -L "${stale[0]}" ]] || exit 96
  [[ -d "$current" && ! -L "$current" ]] || exit 97
  printf 'complete\n' >"$state/production-loader-complete"
  exit 0
fi
'''
    qcsd.write_text(
        qcsd_source.replace(anchor, test_dispatch + anchor),
        encoding="utf-8",
    )
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
    (guardian.parent / HELPER.name).chmod(0o644)
    (guardian.parent / NATIVE.name).chmod(0o644)
    residue = lifecycle_parent / _docker_config_name("3" * 64)
    residue.mkdir(mode=0o500)

    result = subprocess.run(
        [str(qcsd), "__test-two-stage-lifecycle", str(state)],
        cwd=qcsd.parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (state / "production-loader-validated").read_text(
        encoding="ascii"
    ) == "validated\n"
    assert (state / "production-loader-complete").read_text(
        encoding="ascii"
    ) == "complete\n"
    assert (state / "production-loader-stale").read_text(
        encoding="ascii"
    ).strip() == str(residue)
    assert not tuple(
        lifecycle_parent.glob(f".qcsd-docker-config-{os.getuid()}.*")
    )
    assert not tuple(lifecycle_parent.glob(".qcsd-buildx-*"))
    assert _can_lock(_lock_path(guardian_bundle))


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
    os.execv("/bin/bash", ["/bin/bash", "--noprofile", "--norc", "-p",
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


def test_replacement_pidfd_poll_failure_closes_new_binding(
    isolated_guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(isolated_guardian_bundle[0])
    pidfd = os.pidfd_open(os.getpid())

    monkeypatch.setattr(module, "_open_process_pidfd", lambda _pid: pidfd)

    def fail_pidfd_poll(_pidfd: int, _timeout_ms: int = 0) -> bool:
        raise module.GuardianError("injected replacement pidfd poll failure")

    monkeypatch.setattr(module, "_pidfd_is_terminal", fail_pidfd_poll)
    try:
        with pytest.raises(
            module.GuardianError,
            match="injected replacement pidfd poll failure",
        ):
            module._replacement_pidfd_after_terminal(os.getpid())

        with pytest.raises(OSError) as closed:
            os.fstat(pidfd)
        assert closed.value.errno == errno.EBADF
    finally:
        try:
            os.close(pidfd)
        except OSError:
            pass


def test_inner_guardian_proof_holds_pidfd_across_complete_remote_proof(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    pidfd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    events: list[str] = []

    def open_pidfd(pid: int, flags: int) -> int:
        assert (pid, flags) == (4242, 0)
        events.append("open")
        return pidfd

    def terminal(observed: int) -> bool:
        assert observed == pidfd
        events.append("poll")
        return False

    def identity(pid: int, start: int) -> None:
        assert (pid, start) == (4242, 9191)
        os.fstat(pidfd)
        events.append("identity")

    def proof() -> dict[str, object]:
        os.fstat(pidfd)
        events.append("proof")
        return {"bound": True}

    monkeypatch.setattr(module.os, "pidfd_open", open_pidfd)
    monkeypatch.setattr(module, "_guardian_pidfd_is_terminal", terminal)
    monkeypatch.setattr(module, "_verify_guardian_process_identity", identity)

    assert module._run_guardian_bound_proof(4242, 9191, proof) == {
        "bound": True
    }
    assert events == ["open", "poll", "identity", "proof", "identity", "poll"]
    with pytest.raises(OSError) as closed:
        os.fstat(pidfd)
    assert closed.value.errno == errno.EBADF


def test_inner_guardian_proof_rejects_identity_dead_before_remote_reads(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    pidfd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    proof_called = False

    monkeypatch.setattr(module.os, "pidfd_open", lambda _pid, _flags: pidfd)
    monkeypatch.setattr(module, "_guardian_pidfd_is_terminal", lambda _fd: True)

    def proof() -> dict[str, object]:
        nonlocal proof_called
        proof_called = True
        return {}

    with pytest.raises(
        module.GuardianError, match="guardian process identity changed"
    ):
        module._run_guardian_bound_proof(4242, 9191, proof)
    assert proof_called is False
    with pytest.raises(OSError) as closed:
        os.fstat(pidfd)
    assert closed.value.errno == errno.EBADF


def test_inner_guardian_proof_rejects_terminal_binding_after_pid_reuse_window(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    pidfd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    terminal_samples = iter((False, True))
    identity_samples = 0
    proof_called = False

    monkeypatch.setattr(module.os, "pidfd_open", lambda _pid, _flags: pidfd)
    monkeypatch.setattr(
        module,
        "_guardian_pidfd_is_terminal",
        lambda observed: next(terminal_samples) if observed == pidfd else False,
    )

    def identity(_pid: int, _start: int) -> None:
        nonlocal identity_samples
        identity_samples += 1

    def proof() -> dict[str, object]:
        nonlocal proof_called
        proof_called = True
        return {}

    monkeypatch.setattr(module, "_verify_guardian_process_identity", identity)
    with pytest.raises(
        module.GuardianError, match="guardian process identity changed"
    ):
        module._run_guardian_bound_proof(4242, 9191, proof)
    assert proof_called is True
    assert identity_samples == 2
    with pytest.raises(OSError) as closed:
        os.fstat(pidfd)
    assert closed.value.errno == errno.EBADF


def test_inner_guardian_proof_rejects_identity_drift_while_pidfd_is_live(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    pidfd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    identities = iter(
        (
            (1, 4242, 4242, 9191),
            (1, 4242, 4242, 9192),
        )
    )
    polls = 0

    monkeypatch.setattr(module.os, "pidfd_open", lambda _pid, _flags: pidfd)

    def live(_fd: int) -> bool:
        nonlocal polls
        polls += 1
        return False

    monkeypatch.setattr(module, "_guardian_pidfd_is_terminal", live)
    monkeypatch.setattr(module, "_process_identity", lambda _pid: next(identities))
    monkeypatch.setattr(module, "_process_uid", lambda _pid: os.getuid())

    with pytest.raises(
        module.GuardianError, match="guardian process identity changed"
    ):
        module._run_guardian_bound_proof(4242, 9191, lambda: {})
    assert polls == 1
    with pytest.raises(OSError) as closed:
        os.fstat(pidfd)
    assert closed.value.errno == errno.EBADF


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
    _wait(state / "ready", timeout=10)
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


def test_inherited_acquisition_lock_accepts_external_flock_owner_zero(
    guardian_bundle: tuple[Path, Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardian, _qcsd, _lock_parent, _state = guardian_bundle
    module = _load_guardian(guardian)
    acquisition = tmp_path / "acquisition.lock"
    descriptor = os.open(
        acquisition,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
        0o600,
    )
    try:
        acquired = subprocess.run(
            ["/usr/bin/flock", "-n", str(descriptor)],
            pass_fds=(descriptor,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert acquired.returncode == 0, (acquired.stdout, acquired.stderr)
        lock_rows = module._descriptor_lock_rows(os.getpid(), descriptor)
        assert len(lock_rows) == 1
        assert lock_rows[0][4] == "0"
        expected = acquisition.stat(follow_symlinks=False)
        with pytest.raises(
            module.GuardianError,
            match="explicit live owner is required",
        ):
            module._verify_descriptor_lock(
                expected.st_dev,
                expected.st_ino,
                os.getpid(),
                descriptor,
                failure="explicit live owner is required",
                owner=os.getpid(),
            )

        monkeypatch.setenv(
            "QCSD_CLASS_ACQUISITION_LOCK_FD",
            str(descriptor),
        )
        captured = module._capture_inherited_acquisition_lock()

        assert captured is not None
        assert captured.descriptor == descriptor
        assert (captured.device, captured.inode) == (
            expected.st_dev,
            expected.st_ino,
        )
    finally:
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
    try:
        _wait(state / "pre-ready")
        os.kill(process.pid, signal.SIGTERM)
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=8)

        assert process.returncode == 143, (stdout, stderr)
        assert (state / "signals").read_text(encoding="ascii").strip() == "1"
        assert not (state / "mutation-after-go").exists()
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_signal_denial_retains_initial_channel_until_bounded_escalation(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "pre-ready-ignore-signal",
            failure_cleanup_timeout=0.15,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    try:
        _wait(state / "pre-ready")
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)

        assert process.returncode == 143, (stdout, stderr)
        assert not (state / "initial-decision-observed").exists()
        assert not (state / "mutation-after-go").exists()
        inner = int((state / "inner-pid").read_text(encoding="ascii"))
        _wait_gone(inner)
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_signal_denial_retains_final_channel_until_bounded_escalation(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "final-ready-ignore-signal",
            failure_cleanup_timeout=0.15,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    try:
        _wait(state / "pre-final")
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)

        assert process.returncode == 143, (stdout, stderr)
        assert not (state / "final-decision-observed").exists()
        assert not (state / "mutation-after-final-go").exists()
        inner = int((state / "inner-pid").read_text(encoding="ascii"))
        _wait_gone(inner)
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_ignored_signal_after_final_admission_has_bounded_escalation(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "post-final-ignore-signal",
            failure_cleanup_timeout=0.15,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    try:
        _wait(state / "post-final")
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)

        assert process.returncode == 137, (stdout, stderr)
        inner = int((state / "inner-pid").read_text(encoding="ascii"))
        _wait_gone(inner)
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_signal_after_final_admission_can_lease_cleanup_before_exit(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    process = subprocess.Popen(
        _guardian_command(
            guardian_bundle,
            "post-final-signal-cleanup-lease",
            failure_cleanup_timeout=3.0,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    state = guardian_bundle[3]
    try:
        _wait(state / "post-final")
        started = time.monotonic()
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=8)
        elapsed = time.monotonic() - started

        assert process.returncode == 143, (stdout, stderr)
        assert (state / "post-final-cleanup-lease-served").is_file()
        assert (state / "post-final-cleanup-complete").is_file()
        assert elapsed < 3.0
        assert _can_lock(_lock_path(guardian_bundle))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def test_pending_signal_at_admission_linearisation_cannot_publish_go(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    latch = module._SignalLatch()
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    os.set_blocking(read_fd, False)
    forwarded_signals: list[tuple[int, int]] = []

    def capture_forwarded_signal(pid: int, requested: int) -> None:
        with pytest.raises(BlockingIOError):
            os.read(read_fd, 64)
        forwarded_signals.append((pid, requested))

    child = SimpleNamespace(pid=987_654_321)
    monkeypatch.setattr(module.signal, "sigpending", lambda: {signal.SIGTERM})
    monkeypatch.setattr(module, "_kill_child_group", capture_forwarded_signal)
    try:
        admitted, failed, forwarded, resolved = (
            module._publish_admission_decision(
                write_fd,
                "a" * 64,
                latch,
                child,
                False,
                ready=True,
                failed=False,
            )
        )

        assert not admitted
        assert not failed
        assert forwarded
        assert not resolved
        assert forwarded_signals == [(child.pid, signal.SIGTERM)]
        with pytest.raises(BlockingIOError):
            os.read(read_fd, 64)
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)


def test_admission_rejection_does_not_forward_a_latched_signal_twice(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(guardian_bundle[0])
    latch = module._SignalLatch()
    latch.handler(signal.SIGTERM, None)
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    forwarded_signals: list[tuple[int, int]] = []
    child = SimpleNamespace(pid=987_654_321)
    monkeypatch.setattr(
        module,
        "_kill_child_group",
        lambda pid, requested: forwarded_signals.append((pid, requested)),
    )
    try:
        admitted, failed, forwarded, resolved = (
            module._publish_admission_decision(
                write_fd,
                "a" * 64,
                latch,
                child,
                True,
                ready=True,
                failed=False,
            )
        )

        assert not admitted
        assert not failed
        assert forwarded
        assert not resolved
        assert forwarded_signals == []
        os.set_blocking(read_fd, False)
        with pytest.raises(BlockingIOError):
            os.read(read_fd, 64)
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)


def test_non_signal_admission_failure_publishes_abort_and_resolves_channel(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    module = _load_guardian(guardian_bundle[0])
    latch = module._SignalLatch()
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    child = SimpleNamespace(pid=987_654_321)
    try:
        admitted, failed, forwarded, resolved = (
            module._publish_admission_decision(
                write_fd,
                "a" * 64,
                latch,
                child,
                False,
                ready=True,
                failed=True,
            )
        )
        os.close(write_fd)
        write_fd = -1

        assert not admitted
        assert failed
        assert not forwarded
        assert resolved
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
        endpoint = _isolated_guardian_socket_endpoint(guardian_bundle[2])
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


def test_lease_request_drip_cannot_renew_total_service_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_guardian(GUARDIAN)
    monkeypatch.setattr(module, "LEASE_SERVICE_SECONDS", 0.08)
    listener = socket.socket(
        socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
    )
    client = socket.socket(
        socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
    )
    endpoint = tmp_path / "isolated-lease.sock"
    listener.bind(str(endpoint))
    listener.listen(1)
    listener.setblocking(False)
    client.connect(str(endpoint))
    stop = threading.Event()
    started_drip = threading.Event()
    sent: list[float] = []

    def drip_request() -> None:
        final = time.monotonic() + 1.0
        try:
            while not stop.is_set() and time.monotonic() < final:
                client.sendall(b"{")
                sent.append(time.monotonic())
                started_drip.set()
                time.sleep(0.01)
        except OSError:
            pass
        finally:
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    worker = threading.Thread(target=drip_request, daemon=True)
    try:
        worker.start()
        assert started_drip.wait(timeout=1)
        started = time.monotonic()
        outcome = module._serve_one_lease(
            listener,
            lease_socket="@isolated-unused",
            lease_nonce="a" * 64,
            child=None,
            parent_fd=-1,
            lock_fd=-1,
            lock_identity=None,
            source_fd=-1,
            source_identity=None,
            qcsd_fd=-1,
            qcsd_identity=None,
            helper_fd=-1,
            helper_identity=None,
            native_fd=-1,
            native_identity=None,
            docker_config_fd=-1,
            docker_config_identity=None,
            docker_config_residues=(),
            buildx_config_fd=-1,
            buildx_config_identity=None,
            runtime_identity=None,
        )
        elapsed = time.monotonic() - started
        still_dripping = worker.is_alive()
    finally:
        stop.set()
        worker.join(timeout=1)
        client.close()
        listener.close()

    assert outcome == "rejected"
    assert len(sent) >= 3
    assert still_dripping
    assert 0.04 <= elapsed < 0.30


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


def test_recovery_api_receives_current_config_not_stale_residue(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    stale = guardian_bundle[2] / _docker_config_name("3" * 64)
    stale.mkdir(mode=0o500)
    stale_value = stale.stat(follow_symlinks=False)

    result = _run_guardian(guardian_bundle, "recovery-api-current", timeout=20)
    state = guardian_bundle[3]

    assert result.returncode == 0, (result.stdout, result.stderr)
    expected = (state / "docker-config-expected").read_text(
        encoding="ascii"
    ).strip()
    observed = (state / "recovery-api-docker-identity").read_text(
        encoding="ascii"
    ).strip()
    assert observed == expected
    assert observed != f"{stale_value.st_dev}:{stale_value.st_ino}"
    assert (state / "recovery-api-complete").read_text(
        encoding="ascii"
    ) == "complete\n"
    assert not stale.exists()
    assert not tuple(
        guardian_bundle[2].glob(f".qcsd-docker-config-{os.getuid()}.*")
    )


def test_real_api_holder_accepts_five_fast_daemon_identity_proofs(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "api-fast-identity-sequence", timeout=20)
    state = guardian_bundle[3]

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (state / "api-fast-identity-completed").read_text(
        encoding="ascii"
    ) == "completed\n"
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count("INFO unix:///var/run/docker.sock") == 5
    assert _can_lock(_lock_path(guardian_bundle))


def test_real_guardian_retires_three_runs_and_two_networks_sequentially(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    result = _run_guardian(guardian_bundle, "handoff-sequential-retirement", timeout=60)
    state = guardian_bundle[3]

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (state / "handoff-cleanup-status").read_text(
        encoding="ascii"
    ) == "0\n"
    roots = tuple(
        Path(value)
        for value in (state / "handoff-root-inventory")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert len(roots) == 5
    assert len(set(roots)) == 5
    assert not any(root.exists() or root.is_symlink() for root in roots)
    assert "failed at" not in result.stderr
    assert _can_lock(_lock_path(guardian_bundle))


def test_real_guardian_retires_five_v57_predecessor_handoffs_from_clean_successor(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    successor_head = _commit_v57_helper_successor(guardian_bundle)
    assert successor_head != V57_CHECKOUT_COMMIT

    result = _run_guardian(
        guardian_bundle, "handoff-predecessor-sequential-retirement", timeout=90
    )
    state = guardian_bundle[3]

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (state / "handoff-cleanup-status").read_text(
        encoding="ascii"
    ) == "0\n"
    roots = tuple(
        Path(value)
        for value in (state / "handoff-root-inventory")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert len(roots) == 5
    assert len(set(roots)) == 5
    assert not any(root.exists() or root.is_symlink() for root in roots)
    assert "failed at" not in result.stderr
    assert _can_lock(_lock_path(guardian_bundle))


def test_real_guardian_reconciles_five_v57_handoffs_without_docker_removal(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    successor_head = _commit_v57_helper_successor(guardian_bundle)
    assert successor_head != V57_CHECKOUT_COMMIT

    result = _run_guardian(
        guardian_bundle, "handoff-predecessor-reconcile", timeout=180
    )
    state = guardian_bundle[3]

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (state / "handoff-cleanup-status").read_text(
        encoding="ascii"
    ) == "0\n"
    assert (state / "handoff-removals-before").read_text(
        encoding="ascii"
    ) == "5\n"
    assert (state / "handoff-removals-after").read_text(
        encoding="ascii"
    ) == "5\n"
    roots = tuple(
        Path(value)
        for value in (state / "handoff-root-inventory")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert len(roots) == 5
    assert not any(root.exists() or root.is_symlink() for root in roots)
    assert "Recovered durable Docker run lifecycle state" in result.stderr
    assert "Recovered durable Docker network lifecycle state" in result.stderr
    assert _can_lock(_lock_path(guardian_bundle))


@pytest.mark.parametrize(
    "successor_drift",
    ("uncommitted-content", "executable-mode", "second-generation"),
)
def test_real_guardian_refuses_v57_predecessor_handoffs_without_exact_successor(
    guardian_bundle: tuple[Path, Path, Path, Path], successor_drift: str
) -> None:
    _commit_v57_helper_successor(guardian_bundle)
    helper = guardian_bundle[0].parent / HELPER.name
    if successor_drift == "uncommitted-content":
        helper.write_text(
            helper.read_text(encoding="utf-8") + "\n# uncommitted test drift\n",
            encoding="utf-8",
        )
        helper.chmod(0o600)
    elif successor_drift == "executable-mode":
        helper.chmod(0o700)
    else:
        project = helper.parent.parent
        subprocess.run(
            [
                "git",
                "-C",
                str(project),
                "-c",
                "user.name=QCSD lifecycle test",
                "-c",
                "user.email=qcsd-lifecycle-test.invalid",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "Disallowed second successor generation",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=10,
        )

    result = _run_guardian(
        guardian_bundle, "handoff-predecessor-sequential-retirement", timeout=60
    )
    state = guardian_bundle[3]

    assert result.returncode == 97, (result.stdout, result.stderr)
    roots = tuple(
        Path(value)
        for value in (state / "handoff-root-inventory")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert len(roots) == 5
    assert all(root.is_dir() and (root / "HANDOFF").is_file() for root in roots)
    assert (state / "handoff-removals-before").read_text(
        encoding="ascii"
    ) == "5\n"
    assert (state / "handoff-removals-after").read_text(
        encoding="ascii"
    ) == "5\n"
    assert "failed at root-validation" in result.stderr
    assert _can_lock(_lock_path(guardian_bundle))


@pytest.mark.parametrize("observation", ["present", "ambiguous", "unknown"])
def test_v57_successor_race_recheck_never_issues_docker_removal(
    guardian_bundle: tuple[Path, Path, Path, Path], observation: str
) -> None:
    _commit_v57_helper_successor(guardian_bundle)
    state = guardian_bundle[3]
    (state / "race-observation").write_text(observation, encoding="ascii")

    result = _run_guardian(
        guardian_bundle, "handoff-predecessor-retirement-race", timeout=60
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    status, before, after, raw_root = (
        state.joinpath("handoff-predecessor-race-result")
        .read_text(encoding="utf-8")
        .split()
    )
    root = Path(raw_root)
    assert int(status) != 0
    assert before == after == "1"
    assert root.is_dir() and (root / "HANDOFF").is_file()
    calls = (state / "calls.log").read_text(encoding="utf-8")
    assert calls.count(f"RM {'a' * 64}") == 1
    assert "NETWORK_RM" not in calls
    assert "failed at durable-root-removal" in result.stderr
    assert _can_lock(_lock_path(guardian_bundle))


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
    docker_config.mkdir(mode=0o500)
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


def test_transfer_wins_same_iteration_as_normal_launcher_exit(
    guardian_bundle: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _load_native(guardian_bundle[0].parent / NATIVE.name)
    unit = f"qcsd-docker-api-{'a' * 32}.service"
    control_group = (
        f"/user.slice/user-{os.getuid()}.slice/"
        f"user@{os.getuid()}.service/app.slice/{unit}"
    )
    transfer_count = 0

    class CompletedLauncher:
        returncode = 0

        @staticmethod
        def poll() -> int:
            return 0

    def transfer(*_args: object, **_kwargs: object) -> str:
        nonlocal transfer_count
        transfer_count += 1
        return control_group

    monkeypatch.setattr(
        native,
        "_systemd_unit_snapshot",
        lambda _unit: ("not-found", "inactive", "", 0),
    )
    monkeypatch.setattr(native, "_transfer_api_lease", transfer)
    monkeypatch.setattr(
        native.select,
        "select",
        lambda readable, _writable, _exceptional, _timeout: (readable, (), ()),
    )
    monkeypatch.setattr(native, "_cgroup_terminal", lambda _group: True)
    monkeypatch.setattr(native.time, "sleep", lambda _duration: None)
    monkeypatch.setattr(
        native.subprocess,
        "Popen",
        lambda *_args, **_kwargs: CompletedLauncher(),
    )
    singleton, _ = native._api_listener()
    lock_path = guardian_bundle[3] / "same-iteration-transfer-lock"
    lock_path.touch(mode=0o600)
    lock_fd = os.open(lock_path, os.O_RDONLY | os.O_CLOEXEC)
    source_fd = os.open(guardian_bundle[0].parent / NATIVE.name, os.O_RDONLY)
    docker_config_fd = os.open(guardian_bundle[3], os.O_RDONLY | os.O_DIRECTORY)
    buildx_config_fd = os.dup(docker_config_fd)
    try:
        result = native._watch_api_service(
            unit=unit,
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
        )
    finally:
        os.close(source_fd)
        os.close(lock_fd)
        os.close(docker_config_fd)
        os.close(buildx_config_fd)
        singleton.close()

    assert transfer_count == 1
    assert result == 0


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
    assert old_docker.is_dir()
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
        try:
            _wait(state / "census-reap-inspection", timeout=10)
        except AssertionError as error:
            successor_stdout, successor_stderr = successor.communicate(timeout=5)
            raise AssertionError(
                (successor.returncode, successor_stdout, successor_stderr)
            ) from error
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
        assert not old_docker.exists()
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


def test_guardian_lock_proof_is_bound_to_the_exact_locked_descriptor(
    guardian_bundle: tuple[Path, Path, Path, Path],
) -> None:
    guardian, _qcsd, lock_parent, _state = guardian_bundle
    module = _load_guardian(guardian)
    parent_fd, _ = module._open_lock_parent(lock_parent)
    lock_fd, identity = module._open_lock(parent_fd, lock_parent)
    independent_fd = -1
    duplicate_fd = -1
    try:
        module._acquire_lock(lock_fd, module._SignalLatch())
        module._verify_guardian_lock(identity, os.getpid(), lock_fd)

        duplicate_fd = os.dup(lock_fd)
        module._verify_guardian_lock(identity, os.getpid(), duplicate_fd)

        independent_fd = os.open(identity.path, os.O_RDWR | os.O_CLOEXEC)
        with pytest.raises(
            module.GuardianError,
            match="guardian does not exclusively own the lifecycle flock",
        ):
            module._verify_guardian_lock(identity, os.getpid(), independent_fd)
        with pytest.raises(
            module.GuardianError,
            match="guardian does not exclusively own the lifecycle flock",
        ):
            module._verify_descriptor_lock(
                identity.device,
                identity.inode,
                os.getpid(),
                lock_fd,
                failure="guardian does not exclusively own the lifecycle flock",
                owner=os.getpid() + 1,
            )
    finally:
        if independent_fd >= 0:
            os.close(independent_fd)
        if duplicate_fd >= 0:
            os.close(duplicate_fd)
        os.close(lock_fd)
        os.close(parent_fd)


def test_guardian_lock_proof_survives_unrelated_flock_table_churn(
    guardian_bundle: tuple[Path, Path, Path, Path], tmp_path: Path
) -> None:
    guardian, _qcsd, lock_parent, _state = guardian_bundle
    module = _load_guardian(guardian)
    parent_fd, _ = module._open_lock_parent(lock_parent)
    lock_fd, identity = module._open_lock(parent_fd, lock_parent)
    module._acquire_lock(lock_fd, module._SignalLatch())
    churn_root = tmp_path / "unrelated-flocks"
    churn_root.mkdir()
    paths = tuple(churn_root / f"lock-{index:04d}" for index in range(512))
    for path in paths:
        path.touch(mode=0o600)
    stop = threading.Event()
    started = threading.Barrier(5)
    failures: list[BaseException] = []

    def churn(shard: int) -> None:
        descriptors: list[int] = []
        try:
            selected = paths[shard::4]
            started.wait(timeout=5)
            while not stop.is_set():
                for path in selected:
                    descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC)
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    descriptors.append(descriptor)
                while descriptors:
                    os.close(descriptors.pop())
        except BaseException as error:
            failures.append(error)
            stop.set()
        finally:
            while descriptors:
                os.close(descriptors.pop())

    workers = [threading.Thread(target=churn, args=(index,)) for index in range(4)]
    for worker in workers:
        worker.start()
    try:
        started.wait(timeout=5)
        for _ in range(2_000):
            module._verify_guardian_lock(identity, os.getpid(), lock_fd)
    finally:
        stop.set()
        for worker in workers:
            worker.join(timeout=5)
        os.close(lock_fd)
        os.close(parent_fd)
    assert not failures
    assert all(not worker.is_alive() for worker in workers)


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
    assert "p" in (guardian_bundle[3] / "inner-shell-flags").read_text(
        encoding="ascii"
    )
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
