"""Run actual cleanup shell; replace only the Docker service boundary."""
from __future__ import annotations

from pathlib import Path
import shlex
import subprocess
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
ROUTER = "a" * 64
NETWORK = "b" * 64


def _public_cleanup(tmp_path, *, case="ok", entry=0, signal_status=0, delay=0):
    source = (ROOT / "qcsd-lab").read_text()
    cleanup = "cleanup_kernel_tx_public_topology() {" + source.split(
        "cleanup_kernel_tx_public_topology() {", 1
    )[1].split("\n}\n", 1)[0] + "\n}\n"
    helpers = "_qcsd_latch_cleanup_signal() {" + source.split(
        "_qcsd_latch_cleanup_signal() {", 1
    )[1].split("\ncleanup_kernel_tx_public_topology() {", 1)[0]
    capture = tmp_path / "capture"
    capture.mkdir()
    for identity in (ROUTER, NETWORK):
        (tmp_path / identity).touch()
    script = f"""
set -euo pipefail
source {shlex.quote(str(ROOT / 'tools/docker_signal_supervisor.sh'))}
state={shlex.quote(str(tmp_path))}
case={shlex.quote(case)}
delay={delay}
_QCSD_LIFETIME_SIGNAL_STATUS={signal_status}
_QCSD_LIFETIME_CLEANUP_ACTIVE=0
_qcsd_latch_lifetime_signal() {{
  (( _QCSD_LIFETIME_SIGNAL_STATUS != 0 )) || _QCSD_LIFETIME_SIGNAL_STATUS=$1
}}
trap '_qcsd_latch_lifetime_signal 143' TERM
{helpers}
{cleanup}
_qcsd_revalidate_helper_source_identity() {{ [[ "$case" != source-change ]]; }}
_qcsd_docker_api_service_with_timeout() {{
  local duration=$1; shift
  [[ "$1" != docker ]] || shift
  printf '%s %s\\n' "$duration" "$*" >>"$state/services"
  if [[ "$1" == rm || ( "$1" == network && "$2" == rm ) ]]; then
    local identity=${{@: -1}}
    if [[ "$identity" == {ROUTER} ]]; then
      if [[ "$case" == signal-during-removal ]]; then kill -TERM $$; fi
      timeout --signal=KILL "$duration" /bin/sleep "$delay" || return $?
    fi
    if [[ "$case" == mutation-failure || ( "$case" == network-failure && "$1" == network ) ]]; then
      return 41
    fi
    [[ "$case" == remains-present ]] || /usr/bin/unlink "$state/$identity"
    [[ "$case" != error-after-removal ]] || return 42
  elif [[ "$1" == container && "$2" == inspect ]]; then
    if [[ "$case" == signal-at-inspect ]]; then kill -TERM $$; fi
    printf 'true\\n'
  elif [[ "$1" == exec ]]; then
    [[ "$case" != active-dumpcap ]]
  fi
}}
_qcsd_docker_exact_id_presence() {{
  printf '3 container-presence\\n' >>"$state/reads"
  if [[ "$case" == unknown ]]; then printf 'unknown\\n'
  elif [[ -e "$state/$1" ]]; then printf 'present\\n'; else printf 'absent\\n'; fi
}}
_qcsd_docker_exact_network_presence() {{
  printf '3 network-presence\\n' >>"$state/reads"
  if [[ -e "$state/$1" ]]; then printf 'present\\n'; else printf 'absent\\n'; fi
}}
qcsd_retire_docker_handoff() {{
  printf '%s\\n' "$*" >>"$state/retirements"
  [[ "$case" != retirement-failure ]]
}}
remove_study_environment_transport() {{ :; }}
QCSD_DOCKER_IDS_PUBLIC_ROUTERS=({ROUTER})
QCSD_DOCKER_IDS_PUBLIC_NETWORKS=({NETWORK})
kernel_tx_public_topology_started=1
kernel_tx_public_capture_root="$state/capture"
cleanup_kernel_tx_public_topology {entry}
"""
    started = time.monotonic()
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=12)
    return result, time.monotonic() - started


def test_completed_router_removal_longer_than_three_seconds_succeeds(tmp_path):
    result, elapsed = _public_cleanup(tmp_path, delay=3.25)
    assert result.returncode == 0, result.stderr
    assert 3.2 < elapsed < 10
    calls = (tmp_path / "services").read_text().splitlines()
    assert [row for row in calls if "rm " in row] == [
        f"30 rm --force {ROUTER}", f"30 network rm {NETWORK}"
    ]
    assert sum(row.startswith("3 ") for row in calls) == 2
    assert (tmp_path / "retirements").read_text().splitlines() == [
        f"run {ROUTER} QCSD_DOCKER_IDS_PUBLIC_ROUTERS",
        f"network {NETWORK} QCSD_DOCKER_IDS_PUBLIC_NETWORKS",
    ]
    assert not (tmp_path / "capture").exists()


@pytest.mark.parametrize("case", [
    "mutation-failure", "network-failure", "error-after-removal",
    "remains-present", "unknown", "retirement-failure", "active-dumpcap", "source-change",
])
def test_completed_topology_does_not_promote_failed_cleanup(tmp_path, case):
    result, _ = _public_cleanup(tmp_path, case=case)
    assert result.returncode == 1, result.stderr
    if case == "source-change":
        assert not (tmp_path / "services").exists()
    if case in {"remains-present", "unknown"}:
        rows = (tmp_path / "retirements").read_text().splitlines() if (tmp_path / "retirements").exists() else []
        assert not any(row.startswith(f"run {ROUTER}") for row in rows)


@pytest.mark.parametrize("entry,signal_status,expected", [(1, 0, 1), (143, 0, 143), (0, 143, 143)])
def test_failed_and_terminal_signal_cleanup_keeps_three_second_bound(tmp_path, entry, signal_status, expected):
    result, elapsed = _public_cleanup(tmp_path, entry=entry, signal_status=signal_status, delay=3.25)
    assert result.returncode == expected, result.stderr
    assert elapsed < 7
    calls = (tmp_path / "services").read_text().splitlines()
    assert f"3 rm --force {ROUTER}" in calls
    assert f"3 network rm {NETWORK}" in calls
    assert not any(row.startswith("30 ") for row in calls)
    assert (tmp_path / ROUTER).exists()


def test_signal_received_during_cleanup_selects_short_removal_bound(tmp_path):
    result, _ = _public_cleanup(tmp_path, case="signal-at-inspect")
    assert result.returncode == 143, result.stderr
    assert f"3 rm --force {ROUTER}" in (tmp_path / "services").read_text().splitlines()


def test_inflight_completed_removal_remains_bounded_and_subsequent_signal_cleanup_is_short(tmp_path):
    result, elapsed = _public_cleanup(tmp_path, case="signal-during-removal", delay=0.2)
    assert result.returncode == 143, result.stderr
    assert elapsed < 3
    calls = (tmp_path / "services").read_text().splitlines()
    assert f"30 rm --force {ROUTER}" in calls
    assert f"3 network rm {NETWORK}" in calls


def test_pinned_removal_retains_fresh_identity_and_short_dedicated_reads(tmp_path):
    log = tmp_path / "services"
    script = f"""
set -euo pipefail
source {shlex.quote(str(ROOT / 'tools/docker_signal_supervisor.sh'))}
_qcsd_revalidate_helper_source_identity() {{ :; }}
_QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock
_QCSD_DOCKER_PINNED_SERVER_ID=original-daemon
_QCSD_DOCKER_PINNED_CONTEXT=default
_QCSD_LIFETIME_SIGNAL_STATUS=0
_qcsd_docker_api_service_with_timeout() {{ printf '%s\\n' "$*" >>{shlex.quote(str(log))}; }}
_qcsd_read_docker_daemon_id "$_QCSD_DOCKER_PINNED_HOST"
_qcsd_completed_topology_remove 0 rm --force {ROUTER}
_qcsd_verify_pinned_docker_daemon ordinary
"""
    result = subprocess.run(["bash", "-c", script], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert log.read_text().splitlines() == [
        "3 qcsd-native-docker-id unix:///var/run/docker.sock",
        f"30 qcsd-native-docker-exec unix:///var/run/docker.sock original-daemon -- rm --force {ROUTER}",
        "3 qcsd-native-docker-verify unix:///var/run/docker.sock original-daemon",
    ]


@pytest.mark.parametrize("arguments", [
    [], ["0", "image", "rm", ROUTER], ["0", "rm", "--force", "short"],
    ["0", "rm", "--force", ROUTER, NETWORK], ["256", "rm", "--force", ROUTER],
    ["x", "rm", "--force", ROUTER], ["0", "network", "create", NETWORK],
])
def test_removal_allowance_rejects_unrelated_or_ambiguous_requests(tmp_path, arguments):
    script = f"""
source {shlex.quote(str(ROOT / 'tools/docker_signal_supervisor.sh'))}
_qcsd_docker_api_with_timeout() {{ touch {shlex.quote(str(tmp_path / 'called'))}; }}
_qcsd_completed_topology_remove "$@"
"""
    result = subprocess.run(["bash", "-c", script, "test", *arguments], capture_output=True, text=True)
    assert result.returncode != 0
    assert not (tmp_path / "called").exists()


def test_identity_and_signal_envelopes_remain_unchanged():
    helper = (ROOT / "tools/docker_signal_supervisor.sh").read_text()
    native = (ROOT / "tools/docker_lifecycle_native.py").read_text()
    assert "\n_QCSD_DOCKER_API_TIMEOUT_SECONDS=3\n" in helper
    assert "\n_QCSD_DOCKER_SUPERVISOR_SIGNAL_ENVELOPE_SECONDS=120\n" in helper
    assert "DOCKER_IDENTITY_TIMEOUT_SECONDS = 10" in native
