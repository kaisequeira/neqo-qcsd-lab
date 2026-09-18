from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

from qcsd_lab import etf_probe
from tests.test_etf_probe import _valid_pair


LAB_ROOT = Path(__file__).parents[1]
NETWORK_ID = "a" * 64
RECEIVER_ID = "b" * 64


def _launcher_branch() -> str:
    source = (LAB_ROOT / "qcsd-lab").read_text(encoding="utf-8")
    start = source.index('if [[ "${1:-}" == "etf-probe" ]]')
    end = source.index('\nif [[ "${1:-}" == "build" ]]', start)
    return source[start:end]


def _write_probe_outputs(tmp_path: Path) -> tuple[Path, Path]:
    sender, receiver = _valid_pair()
    sender_path = tmp_path / "sender-fixture.json"
    receiver_path = tmp_path / "receiver-fixture.json"
    sender_path.write_text(json.dumps(sender, sort_keys=True), encoding="utf-8")
    receiver_path.write_text(json.dumps(receiver, sort_keys=True), encoding="utf-8")
    return sender_path, receiver_path


def _synthetic_launcher(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    sender_path, receiver_path = _write_probe_outputs(tmp_path)
    operation_log = tmp_path / "operations.log"
    operation_log.write_text("", encoding="utf-8")
    launcher = tmp_path / "etf-launcher"
    image_observation = json.dumps(
        {
            "Id": f"sha256:{'c' * 64}",
            "RepoDigests": [f"qcsd-test@sha256:{'d' * 64}"],
            "Architecture": "amd64",
            "Os": "linux",
        },
        separators=(",", ":"),
    )
    prelude = f"""#!/usr/bin/env bash
set -euo pipefail
ROOT={shlex.quote(str(LAB_ROOT))}
_QCSD_LIFETIME_SIGNAL_STATUS=0
_QCSD_LIFETIME_CLEANUP_ACTIVE=0
readonly _QCSD_DOCKER_METADATA_TIMEOUT_SECONDS=10
etf_probe_network_present=0
etf_probe_receiver_present=0

_qcsd_log() {{
  printf '%s\\n' "$1" >>"${{QCSD_TEST_OPERATION_LOG}}"
}}

_qcsd_latch_lifetime_signal() {{
  local received_status="$1"
  if (( _QCSD_LIFETIME_SIGNAL_STATUS == 0 )); then
    _QCSD_LIFETIME_SIGNAL_STATUS="${{received_status}}"
  fi
  if (( _QCSD_LIFETIME_CLEANUP_ACTIVE == 0 )); then
    exit "${{_QCSD_LIFETIME_SIGNAL_STATUS}}"
  fi
}}
trap '_qcsd_latch_lifetime_signal 129' HUP
trap '_qcsd_latch_lifetime_signal 130' INT
trap '_qcsd_latch_lifetime_signal 131' QUIT
trap '_qcsd_latch_lifetime_signal 143' TERM

require_docker() {{
  _qcsd_log require-docker
}}

_qcsd_supervisor_token() {{
  printf '%s\\n' '11111111111111111111111111111111'
}}

_qcsd_docker_api() {{
  case "$1 ${{2:-}}" in
    'version --format')
      printf '%s\\n' '{{"Client":{{"Version":"test"}},"Server":{{"Version":"test"}}}}'
      ;;
    'info --format')
      printf '%s\\n' '{{"ID":"test-daemon","Architecture":"x86_64","OSType":"linux","NCPU":12}}'
      ;;
    'image inspect')
      printf '%s\\n' {shlex.quote(image_observation)}
      ;;
    'network inspect'|'container inspect')
      return 1
      ;;
    'rm --force')
      [[ "$3" == {shlex.quote(RECEIVER_ID)} ]]
      _qcsd_log receiver-remove
      etf_probe_receiver_present=0
      ;;
    'network rm')
      [[ "$3" == {shlex.quote(NETWORK_ID)} ]]
      _qcsd_log network-remove
      etf_probe_network_present=0
      ;;
    *)
      printf 'unexpected synthetic Docker call: %s\\n' "$*" >&2
      return 2
      ;;
  esac
}}

qcsd_create_docker_network() {{
  local registration_name="$1"
  local -n registration="${{registration_name}}"
  _qcsd_log network-create
  etf_probe_network_present=1
  registration+=({shlex.quote(NETWORK_ID)})
}}

qcsd_run_detached_docker() {{
  local registration_name="$1"
  local -n registration="${{registration_name}}"
  _qcsd_log receiver-detached
  etf_probe_receiver_present=1
  registration+=({shlex.quote(RECEIVER_ID)})
  cp -- "${{QCSD_TEST_RECEIVER_FIXTURE}}" "${{etf_probe_output}}/receiver.json"
  printf 'ready\\n' >"${{etf_probe_output}}/receiver.ready"
}}

qcsd_run_attached_docker() {{
  _qcsd_log sender-attached
  cp -- "${{QCSD_TEST_SENDER_FIXTURE}}" "${{etf_probe_output}}/sender.json"
  case "${{QCSD_TEST_MODE}}" in
    sender-failure) return 7 ;;
    signal)
      kill -TERM "$$"
      return 143
      ;;
  esac
}}

_qcsd_docker_api_with_timeout() {{
  local duration="${{1:?}}"
  shift
  if [[ "$duration" == "$_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS" &&
        "$#" == 3 && "$1" == info && "$2" == --format &&
        "$3" == '{{{{json .}}}}' ]]; then
    _qcsd_docker_api "$@"
  elif [[ "$duration" == 15 && "$#" == 3 &&
          "$1" == container && "$2" == wait &&
          "$3" == {shlex.quote(RECEIVER_ID)} ]]; then
    _qcsd_log receiver-wait
    printf '%s\\n' 0
  else
    printf 'unexpected bounded synthetic Docker call: %s %s\\n' \\
      "$duration" "$*" >&2
    return 2
  fi
}}

_qcsd_docker_exact_id_presence() {{
  if (( etf_probe_receiver_present != 0 )); then
    _qcsd_log receiver-presence-present
    printf '%s\\n' present
  else
    _qcsd_log receiver-presence-absent
    printf '%s\\n' absent
  fi
}}

_qcsd_docker_exact_network_presence() {{
  if (( etf_probe_network_present != 0 )); then
    _qcsd_log network-presence-present
    printf '%s\\n' present
  else
    _qcsd_log network-presence-absent
    printf '%s\\n' absent
  fi
}}

qcsd_retire_docker_handoff() {{
  local kind="$1" object_id="$2" registration_name="$3"
  local -n registration="${{registration_name}}"
  if [[ "${{QCSD_TEST_MODE}}" == retirement-failure && "${{kind}}" == run ]]; then
    _qcsd_log retire-run-failed
    return 1
  fi
  if [[ "${{kind}}" == run ]]; then
    [[ "${{object_id}}" == {shlex.quote(RECEIVER_ID)} &&
       "${{etf_probe_receiver_present}}" == 0 ]]
    _qcsd_log retire-run
  else
    [[ "${{kind}}" == network && "${{object_id}}" == {shlex.quote(NETWORK_ID)} &&
       "${{etf_probe_network_present}}" == 0 ]]
    _qcsd_log retire-network
  fi
  registration=()
}}
"""
    launcher.write_text(prelude + "\n" + _launcher_branch() + "\n", encoding="utf-8")
    launcher.chmod(0o755)
    environment = dict(os.environ)
    environment.update(
        {
            "QCSD_TEST_OPERATION_LOG": str(operation_log),
            "QCSD_TEST_SENDER_FIXTURE": str(sender_path),
            "QCSD_TEST_RECEIVER_FIXTURE": str(receiver_path),
            "QCSD_TEST_MODE": "success",
        }
    )
    return launcher, environment


def _run_launcher(
    tmp_path: Path,
    *,
    mode: str = "success",
    existing: bytes | None = None,
    caller_cwd: Path = LAB_ROOT,
    environment_overrides: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path, list[str]]:
    launcher, environment = _synthetic_launcher(tmp_path)
    environment["QCSD_TEST_MODE"] = mode
    if environment_overrides is not None:
        environment.update(environment_overrides)
    destination = tmp_path / "etf-receipt.json"
    if existing is not None:
        destination.write_bytes(existing)
    result = subprocess.run(
        [
            str(launcher),
            "etf-probe",
            "--destination",
            str(destination),
            "--image",
            "qcsd-test:fixed",
        ],
        cwd=caller_cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    operations = Path(environment["QCSD_TEST_OPERATION_LOG"]).read_text(
        encoding="utf-8"
    ).splitlines()
    return result, destination, operations


_SUCCESS_OPERATIONS = [
    "require-docker",
    "network-create",
    "receiver-detached",
    "sender-attached",
    "receiver-wait",
    "receiver-presence-present",
    "receiver-remove",
    "receiver-presence-absent",
    "retire-run",
    "network-presence-present",
    "network-remove",
    "network-presence-absent",
    "retire-network",
]


def test_supervised_launcher_executes_and_retires_in_exact_order(
    tmp_path: Path,
) -> None:
    result, destination, operations = _run_launcher(tmp_path)

    assert result.returncode == 0, result.stderr
    assert operations == _SUCCESS_OPERATIONS
    receipt = etf_probe.validate_probe_receipt(destination)
    assert receipt["status"] == "passed"
    assert receipt["cleanup_passed"] is True
    assert receipt["cleanup"]["receiver"]["handoff_retired"] is True
    assert receipt["cleanup"]["network"]["handoff_retired"] is True


def test_supervised_launcher_sender_failure_cleans_up_and_fails_receipt(
    tmp_path: Path,
) -> None:
    result, destination, operations = _run_launcher(tmp_path, mode="sender-failure")

    assert result.returncode == 1, result.stderr
    assert operations == _SUCCESS_OPERATIONS
    receipt = etf_probe.validate_probe_receipt(destination)
    assert receipt["status"] == "failed"
    assert receipt["container_exit_codes"] == {"sender": 7, "receiver": 0}
    assert receipt["cleanup_passed"] is True
    assert receipt["validation"]["gates"]["sender_exit_code"]["passed"] is False


def test_supervised_launcher_signal_cleans_up_before_returning_signal_status(
    tmp_path: Path,
) -> None:
    result, destination, operations = _run_launcher(tmp_path, mode="signal")

    assert result.returncode == 143, result.stderr
    assert operations == [
        item for item in _SUCCESS_OPERATIONS if item != "receiver-wait"
    ]
    receipt = etf_probe.validate_probe_receipt(destination)
    supervision = receipt["lifecycle_supervision"]
    assert receipt["status"] == "failed"
    assert supervision["latched_signal_status"] == 143
    assert supervision["terminal_stage"] == "sender-run"
    assert receipt["cleanup_passed"] is True


def test_supervised_launcher_continues_network_cleanup_after_retirement_failure(
    tmp_path: Path,
) -> None:
    result, destination, operations = _run_launcher(
        tmp_path, mode="retirement-failure"
    )

    assert result.returncode == 1, result.stderr
    expected = list(_SUCCESS_OPERATIONS)
    expected[expected.index("retire-run")] = "retire-run-failed"
    assert operations == expected
    receipt = etf_probe.validate_probe_receipt(destination)
    assert receipt["status"] == "failed"
    assert receipt["cleanup_passed"] is False
    assert receipt["cleanup"]["receiver"]["handoff_retired"] is False
    assert receipt["cleanup"]["network"]["handoff_retired"] is True


def test_supervised_launcher_preserves_existing_destination_before_docker_work(
    tmp_path: Path,
) -> None:
    original = b"immutable-existing-receipt\n"
    result, destination, operations = _run_launcher(tmp_path, existing=original)

    assert result.returncode != 0
    assert destination.read_bytes() == original
    assert operations == ["require-docker"]
    assert "already exists" in result.stderr


def test_supervised_launcher_cannot_import_caller_shadow_package(
    tmp_path: Path,
) -> None:
    caller = tmp_path / "untrusted-caller"
    shadow = caller / "qcsd_lab"
    shadow.mkdir(parents=True)
    (shadow / "__init__.py").write_text("", encoding="utf-8")
    (shadow / "etf_probe.py").write_text(
        "raise RuntimeError('caller-local qcsd_lab was imported')\n",
        encoding="utf-8",
    )

    result, destination, operations = _run_launcher(
        tmp_path,
        caller_cwd=caller,
    )

    assert result.returncode == 0, result.stderr
    assert "caller-local qcsd_lab was imported" not in result.stderr
    assert operations == _SUCCESS_OPERATIONS
    assert etf_probe.validate_probe_receipt(destination)["status"] == "passed"


def test_supervised_launcher_overrides_ambient_qcsd_lab_root(tmp_path: Path) -> None:
    attacker_root = tmp_path / "attacker-selected-root"
    attacker_root.mkdir()

    result, destination, operations = _run_launcher(
        tmp_path,
        environment_overrides={"QCSD_LAB_ROOT": str(attacker_root)},
    )

    assert result.returncode == 0, result.stderr
    assert operations == _SUCCESS_OPERATIONS
    receipt = etf_probe.validate_probe_receipt(destination)
    assert receipt["status"] == "passed"
    assert receipt["source"]["lab_commit"] == subprocess.run(
        ["/usr/bin/git", "-C", str(LAB_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_etf_help_cannot_import_caller_shadow_package(tmp_path: Path) -> None:
    caller = tmp_path / "untrusted-help-caller"
    shadow = caller / "qcsd_lab"
    shadow.mkdir(parents=True)
    (shadow / "__init__.py").write_text("", encoding="utf-8")
    (shadow / "etf_probe.py").write_text(
        "raise RuntimeError('caller-local help package was imported')\n",
        encoding="utf-8",
    )

    environment = dict(os.environ)
    environment["QCSD_LAB_ROOT"] = str(tmp_path / "attacker-help-root")
    result = subprocess.run(
        [str(LAB_ROOT / "qcsd-lab"), "etf-probe", "--help"],
        cwd=caller,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert "caller-local help package was imported" not in result.stderr
    assert "--destination" in result.stdout
