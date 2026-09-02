from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

import qcsd_lab.capture_session as capture_session
import qcsd_lab.prepare as prepare
import qcsd_lab.process_scheduler as process_scheduler
import qcsd_lab.util as util


class _TimeoutProcess:
    def __init__(self, expirations: int) -> None:
        self.pid = 4242
        self.expirations = expirations
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False
        self.communicate_timeouts: list[float | None] = []

    def communicate(self, timeout: float | None = None) -> tuple[str, None]:
        self.communicate_timeouts.append(timeout)
        if self.expirations:
            self.expirations -= 1
            raise subprocess.TimeoutExpired(["neqo"], timeout)
        self.returncode = -9 if self.killed else -15
        return "partial client output", None

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def _install_process(monkeypatch: pytest.MonkeyPatch, process: _TimeoutProcess) -> dict[str, Any]:
    invocation: dict[str, Any] = {}

    def popen(command: list[str], **options: Any) -> _TimeoutProcess:
        invocation.update(command=command, options=options)
        return process

    monkeypatch.setattr(util.subprocess, "Popen", popen)
    return invocation


def test_bounded_process_is_terminated_and_timeout_is_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _TimeoutProcess(expirations=1)
    invocation = _install_process(monkeypatch, process)
    log = tmp_path / "neqo.log"

    with pytest.raises(util.ProcessTimeoutError) as raised:
        util.run(["neqo", "run"], log=log, check=False, timeout=7)

    assert process.terminated is True
    assert process.killed is False
    assert process.communicate_timeouts == [7, util.PROCESS_TERMINATE_GRACE_SECONDS]
    assert invocation["command"] == ["neqo", "run"]
    assert invocation["options"]["stdout"] is subprocess.PIPE
    assert raised.value.result.returncode == -15
    assert raised.value.timeout_seconds == 7
    assert raised.value.killed is False
    assert "partial client output" in log.read_text(encoding="utf-8")
    assert "outer host timeout after 7s; process terminated" in log.read_text(encoding="utf-8")


def test_bounded_process_is_killed_when_terminate_grace_expires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _TimeoutProcess(expirations=2)
    _install_process(monkeypatch, process)
    log = tmp_path / "neqo.log"

    with pytest.raises(util.ProcessTimeoutError) as raised:
        util.run(["neqo", "probe"], log=log, check=False, timeout=9)

    assert process.terminated is True
    assert process.killed is True
    assert process.communicate_timeouts == [9, util.PROCESS_TERMINATE_GRACE_SECONDS, None]
    assert raised.value.result.returncode == -9
    assert raised.value.killed is True
    assert "outer host timeout after 9s; process killed after terminate grace" in log.read_text(
        encoding="utf-8"
    )


def test_bounded_process_reports_the_exact_started_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _TimeoutProcess(expirations=0)
    _install_process(monkeypatch, process)
    observed: list[int] = []

    util.run(
        ["neqo", "run"],
        check=False,
        timeout=7,
        terminate_process_group=True,
        process_started=observed.append,
    )

    assert observed == [process.pid]


def test_bounded_process_receives_the_explicit_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _TimeoutProcess(expirations=0)
    invocation = _install_process(monkeypatch, process)

    util.run(
        ["neqo", "run"],
        check=False,
        timeout=7,
        env={"QCSD_SAFE_CHILD_VALUE": "retained"},
    )

    assert invocation["options"]["env"] == {"QCSD_SAFE_CHILD_VALUE": "retained"}


def test_prepare_client_adds_host_grace_and_reports_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}
    timeout_result = subprocess.CompletedProcess(
        ["neqo", "probe"],
        -15,
        "[qcsd-lab] outer host timeout after 35s; process terminated\n",
    )

    def timed_out(command: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        observed.update(command=command, options=options)
        raise util.ProcessTimeoutError(timeout_result, 35, killed=False)

    monkeypatch.setattr(prepare, "run", timed_out)

    with pytest.raises(prepare.PreparationError, match="enforced 35s host timeout"):
        prepare._run_neqo(
            ["neqo", "probe"],
            log=tmp_path / "probe.log",
            configured_timeout_seconds=30,
            label="Neqo HTTP/3 probe",
        )

    assert observed["options"] == {
        "log": tmp_path / "probe.log",
        "check": False,
        "timeout": 35.0,
    }


def test_prepare_client_applies_the_measured_rr1_scheduler_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}

    def completed(command: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        observed.update(command=command, options=options)
        return subprocess.CompletedProcess(command, 0, "")

    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", "qcsd-client-rr1-cpu10-v1")
    monkeypatch.setattr(process_scheduler.os, "sched_getaffinity", lambda _pid: {11})
    monkeypatch.setattr(
        process_scheduler.resource,
        "getrlimit",
        lambda limit: (1, 1)
        if limit == process_scheduler.resource.RLIMIT_RTPRIO
        else pytest.fail("unexpected resource limit"),
    )
    monkeypatch.setattr(prepare, "run", completed)

    result = prepare._run_neqo(
        ["neqo", "probe"],
        log=tmp_path / "probe.log",
        configured_timeout_seconds=30,
        label="Neqo HTTP/3 probe",
    )

    assert result.returncode == 0
    assert observed["command"] == [
        "/usr/bin/taskset",
        "--cpu-list",
        "10",
        "/usr/bin/chrt",
        "--rr",
        "1",
        "/usr/bin/setpriv",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "--",
        "neqo",
        "probe",
    ]
    assert observed["options"] == {
        "log": tmp_path / "probe.log",
        "check": False,
        "timeout": 35.0,
    }


def test_buflo_etf_scheduler_retains_only_bounded_socket_setup_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "QCSD_CAPTURE_SCHEDULER_CONTRACT",
        "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
    )
    monkeypatch.setattr(process_scheduler.os, "sched_getaffinity", lambda _pid: {11})
    monkeypatch.setattr(
        process_scheduler.resource,
        "getrlimit",
        lambda limit: (1, 1)
        if limit == process_scheduler.resource.RLIMIT_RTPRIO
        else pytest.fail("unexpected resource limit"),
    )

    assert process_scheduler.capture_scheduler_launch_prefix() == [
        "/usr/bin/taskset",
        "--cpu-list",
        "10",
        "/usr/bin/chrt",
        "--rr",
        "1",
        "/usr/bin/setpriv",
        "--bounding-set=-all,+net_admin,+setpcap",
        "--inh-caps=+net_admin,+setpcap",
        "--ambient-caps=+net_admin,+setpcap",
        "--no-new-privs",
        "--",
    ]


def test_collection_client_adds_host_grace_and_preserves_timeout_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}
    monkeypatch.setenv("QCSD_TEST_SAFE_CHILD_VALUE", "retained")
    for name in capture_session._MEASURED_CLIENT_CAPTURE_ENVIRONMENT:
        monkeypatch.setenv(name, "sensitive")
    timeout_result = subprocess.CompletedProcess(
        ["neqo", "run"],
        -9,
        "[qcsd-lab] outer host timeout after 50s; process killed after terminate grace\n",
    )

    def timed_out(command: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        observed.update(command=command, options=options)
        raise util.ProcessTimeoutError(timeout_result, 50, killed=True)

    monkeypatch.setattr(capture_session, "run", timed_out)

    result, did_time_out, host_timeout = capture_session._run_neqo_client(
        ["neqo", "run"],
        log=tmp_path / "client.log",
        configured_timeout_seconds=45,
    )

    assert result is timeout_result
    assert did_time_out is True
    assert host_timeout == 50.0
    child_environment = observed["options"].pop("env")
    assert child_environment["QCSD_TEST_SAFE_CHILD_VALUE"] == "retained"
    assert not capture_session._MEASURED_CLIENT_CAPTURE_ENVIRONMENT.intersection(
        child_environment
    )
    assert observed["options"] == {
        "log": tmp_path / "client.log",
        "check": False,
        "timeout": 50.0,
        "terminate_process_group": True,
    }
    assert observed["command"][:2] == ["/usr/bin/time", "--quiet"]
    assert observed["command"][-3:] == ["--", "neqo", "run"]


def test_collection_client_applies_rr1_only_after_gnu_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}
    timeout_result = subprocess.CompletedProcess(["neqo", "run"], -15, "timeout\n")

    def timed_out(command: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        observed.update(command=command, options=options)
        raise util.ProcessTimeoutError(timeout_result, 50, killed=False)

    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", "qcsd-client-rr1-cpu10-v1")
    monkeypatch.setattr(process_scheduler.os, "sched_getaffinity", lambda _pid: {11})
    monkeypatch.setattr(
        process_scheduler.resource,
        "getrlimit",
        lambda limit: (1, 1)
        if limit == process_scheduler.resource.RLIMIT_RTPRIO
        else pytest.fail("unexpected resource limit"),
    )
    monkeypatch.setattr(capture_session, "run", timed_out)

    result, did_time_out, host_timeout = capture_session._run_neqo_client(
        ["neqo", "run"],
        log=tmp_path / "client.log",
        configured_timeout_seconds=45,
    )

    assert result is timeout_result
    assert did_time_out is True
    assert host_timeout == 50.0
    separator = observed["command"].index("--")
    assert observed["command"][separator + 1 :] == [
        "/usr/bin/taskset",
        "--cpu-list",
        "10",
        "/usr/bin/chrt",
        "--rr",
        "1",
        "/usr/bin/setpriv",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "--",
        "neqo",
        "run",
    ]


@pytest.mark.parametrize(
    ("affinity", "rtprio", "message"),
    [
        ({10, 11}, (1, 1), "orchestrator CPU 11"),
        ({11}, (0, 0), "RLIMIT_RTPRIO"),
    ],
)
def test_collection_client_scheduler_contract_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    affinity: set[int],
    rtprio: tuple[int, int],
    message: str,
) -> None:
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", "qcsd-client-rr1-cpu10-v1")
    monkeypatch.setattr(process_scheduler.os, "sched_getaffinity", lambda _pid: affinity)
    monkeypatch.setattr(process_scheduler.resource, "getrlimit", lambda _limit: rtprio)

    with pytest.raises(ValueError, match=message):
        capture_session._capture_scheduler_launch_prefix()
