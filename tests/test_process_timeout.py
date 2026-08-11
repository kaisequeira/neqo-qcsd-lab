from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

import qcsd_lab.capture_session as capture_session
import qcsd_lab.prepare as prepare
import qcsd_lab.util as util


class _TimeoutProcess:
    def __init__(self, expirations: int) -> None:
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


def test_collection_client_adds_host_grace_and_preserves_timeout_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}
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
    assert observed["options"] == {
        "log": tmp_path / "client.log",
        "check": False,
        "timeout": 50.0,
    }
