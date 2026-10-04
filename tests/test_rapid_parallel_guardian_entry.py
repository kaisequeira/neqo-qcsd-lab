"""Real guardian deadlines around the actual shell parallel entry block.

Only the Docker API/recovery work and immutable runtime/science producers are
fixture boundaries. The guardian owns real children, pipes, source descriptors,
locks, and private config directories; no Docker executable is invoked.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from tests.test_docker_lifecycle_lock_guardian import (
    _can_lock,
    _guardian_command,
    _lock_path,
    guardian_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
READY_LIMIT = 0.8
IDLE_LIMIT = 0.3
SCIENCE_DELAY = 1.1


def _between(source: str, start: str, end: str) -> str:
    assert source.count(start) == 1 and source.count(end) == 1
    return source.split(start, 1)[1].split(end, 1)[0]


@pytest.fixture
def entry_bundle(guardian_bundle):
    guardian, qcsd, lock_parent, state = guardian_bundle
    source = (ROOT / "qcsd-lab").read_text()
    marker = 'if [[ "${1:-}" == "parallel-diagnostic-run" || "${1:-}" == "parallel-formal-run" ]]; then\n'
    preamble = marker + _between(source, marker, '\nstudy_cohort_version=""\n')
    environment_rows = 'parallel_environment_rows() {\n' + _between(
        source, 'parallel_environment_rows() {\n', marker)
    read_frame = '_qcsd_read_exact_lifecycle_frame() {\n' + _between(
        source, '_qcsd_read_exact_lifecycle_frame() {\n', '_qcsd_validate_lifecycle_guardian() {\n')
    recovery = '_qcsd_complete_lifecycle_recovery() {\n' + _between(
        source, '_qcsd_complete_lifecycle_recovery() {\n', '_qcsd_enter_lifecycle_guardian() {\n')
    deferred_marker = 'if [[ "${qcsd_deferred_generic_docker:-0}" == "1" ]]; then\n'
    deferred = deferred_marker + _between(source, deferred_marker, '\ncase "${1:-}" in\n  prepare|derive-chaff-prefix-specs')
    execution = qcsd.parent
    output = execution / "results" / "fresh-pair"
    output.mkdir(parents=True)
    authority = execution / "authority.json"
    authority.write_text(json.dumps({"runtime_valid": True}) + "\n")
    worker = {"campaign_path": str(execution / "campaign.yaml"),
              "dns_path": str(state / "dns.json"), "environment": {}}
    script = r'''#!/bin/bash
set -euo pipefail
unset _QCSD_LIFECYCLE_ENTRY_VALIDATED
QCSD_ORIGINAL_ARGV=("$@")
ROOT=__ROOT__
state=__STATE__
printf '%s\n' "$$" >"$state/inner-pid"
printf '%s\n' "${QCSD_ORIGINAL_ARGV[@]}" >"$state/original-argv"
parallel_diagnostic=0
parallel_formal=0
parallel_host_python=""
qcsd_deferred_generic_docker=1
event() { printf '%s\n' "$1" >>"$state/events"; }
parallel_select_host_python() { printf '%s\n' __PYTHON__; }
parallel_python() {
  case "$1" in
    lifecycle-inputs)
      event lifecycle-inputs
      __PYTHON__ -I -c 'import hashlib,json,sys; raw=open(sys.argv[1],"rb").read(); assert hashlib.sha256(raw).hexdigest()==sys.argv[2]; assert json.loads(raw)["runtime_valid"] is True' "$3" "$7"
      ;;
    formal-entry-inputs)
      event science-start
      __PYTHON__ -I -c 'import time; time.sleep(float(__DELAY__))'
      if [[ "${QCSD_TEST_REPLACE_HELPER:-0}" == 1 ]]; then
        printf '\n# replaced during science\n' >>"$ROOT/tools/docker_signal_supervisor.sh"
        __PYTHON__ -I -c 'import time; time.sleep(0.6)'
      fi
      [[ "${QCSD_TEST_SCIENCE_FAIL:-0}" != 1 ]] || return 19
      event science-end
      printf '%s\n' __WORKER__
      ;;
    *) event unexpected-producer; return 99 ;;
  esac
}
__READ_FRAME__
__RECOVERY__
require_docker() {
  event require-docker
  local ready_fd=$QCSD_DOCKER_LOCK_GUARDIAN_READY_FD
  local go_fd=$QCSD_DOCKER_LOCK_GUARDIAN_GO_FD
  printf '%s\n' "$QCSD_DOCKER_LOCK_GUARDIAN_NONCE" >&"$ready_fd"
  eval "exec ${ready_fd}>&-"
  _qcsd_read_exact_lifecycle_frame "$go_fd" "$QCSD_DOCKER_LOCK_GUARDIAN_GO_NONCE"
  eval "exec ${go_fd}<&-"
  event authenticated-go
  _QCSD_LIFECYCLE_RECOVERY_STATE=armed
  _QCSD_LIFECYCLE_RECOVERY_READY_FD=$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_READY_FD
  _QCSD_LIFECYCLE_RECOVERY_NONCE=$QCSD_DOCKER_LOCK_GUARDIAN_RECOVERY_NONCE
  _QCSD_LIFECYCLE_FINAL_GO_FD=$QCSD_DOCKER_LOCK_GUARDIAN_FINAL_GO_FD
  _QCSD_LIFECYCLE_FINAL_GO_NONCE=$QCSD_DOCKER_LOCK_GUARDIAN_FINAL_GO_NONCE
  event recovery
  _qcsd_complete_lifecycle_recovery
  event authenticated-final-go
  if [[ "${QCSD_TEST_CHANGE_BINDING:-0}" == 1 ]]; then
    printf '{"runtime_valid":false}\n' >"$ROOT/authority.json"
  fi
}
__ENV_ROWS__
__PREAMBLE__
__DEFERRED__
printf '%s\n' "$1" "$2" >"$state/final-argv"
printf '%s\n' "$qcsd_deferred_generic_docker" >"$state/deferred"
'''
    replacements = {"__ROOT__": shlex.quote(str(execution)),
        "__STATE__": shlex.quote(str(state)), "__PYTHON__": shlex.quote(sys.executable),
        "__DELAY__": repr(str(SCIENCE_DELAY)), "__WORKER__": shlex.quote(json.dumps(worker)),
        "__READ_FRAME__": read_frame, "__RECOVERY__": recovery,
        "__ENV_ROWS__": environment_rows, "__PREAMBLE__": preamble,
        "__DEFERRED__": deferred}
    for key, value in replacements.items():
        script = script.replace(key, value)
    qcsd.write_text(script)
    return {"bundle": guardian_bundle, "authority": authority, "output": output,
            "preamble": preamble, "worker": worker}


def _run(context, **environment):
    authority = context["authority"]
    command = _guardian_command(context["bundle"], "parallel-formal-run",
        ready_timeout=READY_LIMIT, recovery_idle_timeout=IDLE_LIMIT,
        recovery_timeout=0.7,
        inner_arguments=("parallel-formal-run", str(authority), str(context["output"])))
    env = dict(os.environ, QCSD_PARALLEL_AUTHORITY_SHA256=hashlib.sha256(authority.read_bytes()).hexdigest(),
               **environment)
    return subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, env=env, timeout=10)


def _events(context):
    path = context["bundle"][3] / "events"
    return path.read_text().splitlines() if path.exists() else []


def test_actual_preamble_completes_both_admissions_before_slow_science(entry_bundle):
    result = _run(entry_bundle)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert SCIENCE_DELAY > READY_LIMIT and SCIENCE_DELAY > IDLE_LIMIT
    assert _events(entry_bundle) == ["lifecycle-inputs", "require-docker", "authenticated-go",
        "recovery", "authenticated-final-go", "lifecycle-inputs", "science-start", "science-end"]
    state = entry_bundle["bundle"][3]
    assert (state / "original-argv").read_text().splitlines() == ["parallel-formal-run",
        str(entry_bundle["authority"]), str(entry_bundle["output"])]
    assert (state / "final-argv").read_text().splitlines() == ["run", entry_bundle["worker"]["campaign_path"]]
    assert (state / "deferred").read_text().strip() == "0"
    assert _can_lock(_lock_path(entry_bundle["bundle"]))


def test_old_late_admission_order_reproduces_guardian_125(entry_bundle):
    qcsd = entry_bundle["bundle"][1]
    source = qcsd.read_text()
    before = "    require_docker\n    qcsd_deferred_generic_docker=0\n"
    assert source.count(before) == 1
    qcsd.write_text(source.replace(before, "", 1))
    result = _run(entry_bundle)
    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "initial READY handshake timed out before admission" in result.stderr
    assert "science-start" in _events(entry_bundle)
    assert "science-end" not in _events(entry_bundle)
    assert "recovery" not in _events(entry_bundle)
    assert _can_lock(_lock_path(entry_bundle["bundle"]))


def test_invalid_lightweight_binding_never_enters_recovery(entry_bundle):
    entry_bundle["authority"].write_text('{"runtime_valid":false}\n')
    result = _run(entry_bundle)
    assert result.returncode == 125
    assert _events(entry_bundle) == ["lifecycle-inputs"]
    assert "binding failed before admission" in result.stderr


def test_binding_changed_during_admission_stops_before_science(entry_bundle):
    result = _run(entry_bundle, QCSD_TEST_CHANGE_BINDING="1")
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert _events(entry_bundle)[-1] == "lifecycle-inputs"
    assert "science-start" not in _events(entry_bundle)
    assert "binding changed while awaiting admission" in result.stderr


def test_ambient_admission_flags_cannot_skip_scientific_failure(entry_bundle):
    result = _run(entry_bundle, _QCSD_LIFECYCLE_ENTRY_VALIDATED="1",
                  qcsd_deferred_generic_docker="0", parallel_formal="0", QCSD_TEST_SCIENCE_FAIL="1")
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert _events(entry_bundle).count("science-start") == 1
    assert "science-end" not in _events(entry_bundle)
    assert "worker input validation failed" in result.stderr
    assert not (entry_bundle["bundle"][3] / "final-argv").exists()


def test_guardian_still_rejects_source_replacement_during_science(entry_bundle):
    result = _run(entry_bundle, QCSD_TEST_REPLACE_HELPER="1")
    assert result.returncode == 125, (result.stdout, result.stderr)
    assert "runtime integrity check failed" in result.stderr
    assert "science-end" not in _events(entry_bundle)
    assert _can_lock(_lock_path(entry_bundle["bundle"]))
