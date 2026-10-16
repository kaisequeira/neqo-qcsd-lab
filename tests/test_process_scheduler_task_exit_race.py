"""Real monitor/receipt controls over temporary procfs; no Docker or traffic.

The three fixture helpers are copied unchanged from test_process_scheduler.py.
Only the named task's read/enumeration boundary is controlled; finish() and the
runtime-evidence validator execute their original implementations.
"""
from __future__ import annotations

import errno
from pathlib import Path

import pytest

from qcsd_lab.process_scheduler import (
    PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    CaptureSchedulerMonitor,
    build_peer_host_partition,
    capture_scheduler_runtime_evidence_valid,
)


def _peer_inputs() -> tuple[list[dict], list[dict], dict[str, str]]:
    workers = [
        {"id": "a" * 64, "name": "lane-a", "image_id": "sha256:" + "d" * 64,
         "client_cpu": 2, "orchestrator_cpu": 4},
        {"id": "b" * 64, "name": "lane-b", "image_id": "sha256:" + "d" * 64,
         "client_cpu": 7, "orchestrator_cpu": 9},
    ]
    inspected = []
    for worker in workers:
        inspected.append({
            "Id": worker["id"], "Name": "/" + worker["name"], "Image": worker["image_id"],
            "Config": {"Labels": {"org.qcsd.owner": "qcsd-lab", "org.qcsd.role": "capture"}},
            "HostConfig": {"CpusetCpus": f'{worker["client_cpu"]},{worker["orchestrator_cpu"]}'},
            "State": {"Status": "created", "Running": False},
        })
    inspected.append({
        "Id": "c" * 64, "Name": "/sidecar", "Image": "sha256:" + "e" * 64,
        "Config": {"Labels": {"org.qcsd.owner": "qcsd-lab", "org.qcsd.role": "server"}},
        "HostConfig": {"CpusetCpus": "0"},
        "State": {"Status": "running", "Running": True},
    })
    return inspected, workers, {"sidecar": "c" * 64}


def _write_task(
    proc_root: Path,
    *,
    tgid: int,
    tid: int,
    process_group: int,
    cpus: str,
    name: str,
) -> None:
    task = proc_root / str(tgid) / "task" / str(tid)
    task.mkdir(parents=True)
    (task / "status").write_text(
        f"Name:\t{name}\nTgid:\t{tgid}\nCpus_allowed_list:\t{cpus}\n",
        encoding="ascii",
    )
    (task / "stat").write_text(
        f"{tid} ({name}) S 1 {process_group} 0 0 0\n",
        encoding="ascii",
    )


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    proc_root = tmp_path / "proc"
    (proc_root / "self/ns").mkdir(parents=True)
    (proc_root / "self/ns/pid").write_text("pid namespace\n", encoding="ascii")
    (proc_root / "stat").write_text(
        "cpu 1 2 3 4 5 6 7 0 0 0\ncpu10 1 2 3 4 5 6 7 0 0 0\n",
        encoding="ascii",
    )
    _write_task(
        proc_root,
        tgid=1,
        tid=1,
        process_group=1,
        cpus="11",
        name="orchestrator",
    )
    cpu_stat = tmp_path / "cpu.stat"
    cpu_stat.write_text(
        "usage_usec 10\nuser_usec 6\nsystem_usec 4\n"
        "nr_periods 2\nnr_throttled 0\nthrottled_usec 0\n",
        encoding="ascii",
    )
    return proc_root, cpu_stat


def _started_monitor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT_V4)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    proc_root, cpu_stat = _fixture(tmp_path)
    (proc_root / "1/task/1/status").write_text(
        "Name:\torchestrator\nTgid:\t1\nCpus_allowed_list:\t4\n", encoding="ascii",
    )
    (proc_root / "stat").write_text("cpu2 1 2 3 4 5 6 7 0 0 0\n", encoding="ascii")
    inspected, workers, sidecars = _peer_inputs()
    partition = build_peer_host_partition(
        inspected, [0, 2, 4, 7, 9], workers, sidecars, workers[0]["id"], docker_ncpu=16,
    )
    monitor = CaptureSchedulerMonitor(
        proc_root=proc_root, cgroup_cpu_stat_paths=(cpu_stat,),
        interval_us=1_000_000, host_partition=partition,
    )
    _write_task(proc_root, tgid=77, tid=77, process_group=77, cpus="2", name="neqo-qcsd-client")
    monitor.process_started(77)
    # The measured client was genuinely observed by process_started(). Task97
    # appears only afterward, so every injected disappearance belongs to the
    # real final scan, not an invented positive expected-process observation.
    _write_task(proc_root, tgid=77, tid=97, process_group=77, cpus="4", name="exiting-helper")
    return monitor, proc_root, proc_root / "77/task/97"


def _inject_read_error(monkeypatch: pytest.MonkeyPatch, target: Path, kind, number: int):
    original = Path.read_text
    calls = []

    def read_text(path, *args, **kwargs):
        if path == target:
            calls.append(path)
            raise kind(number, "controlled proc task read")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    return calls


def _assert_strict_error(evidence):
    assert evidence["valid"] is False
    assert evidence["guest_task_monitor"]["scan_errors"]
    assert not capture_scheduler_runtime_evidence_valid(evidence)
    # The independent reader must refuse the actual error even if its claimed
    # top-level validity is changed; no monitor/reader predicate is mocked.
    evidence["valid"] = True
    assert not capture_scheduler_runtime_evidence_valid(evidence)


def test_real_monitor_without_task_race_remains_valid(tmp_path, monkeypatch):
    monitor, _, _ = _started_monitor(tmp_path, monkeypatch)
    evidence = monitor.finish()
    assert evidence["valid"] is True
    assert capture_scheduler_runtime_evidence_valid(evidence)


@pytest.mark.parametrize("leaf", ["status", "stat"])
@pytest.mark.parametrize("kind,number", [
    (FileNotFoundError, errno.ENOENT),
    (ProcessLookupError, errno.ESRCH),
])
def test_task_exit_during_status_or_stat_read_preserves_valid_evidence(
    tmp_path, monkeypatch, leaf, kind, number,
):
    monitor, _, task = _started_monitor(tmp_path, monkeypatch)
    calls = _inject_read_error(monkeypatch, task / leaf, kind, number)
    evidence = monitor.finish()
    assert calls, "real monitor.finish must encounter the selected proc read"
    assert evidence["guest_task_monitor"]["expected_client_cpu_task_observed"] is True
    assert evidence["guest_task_monitor"]["scan_errors"] == []
    assert evidence["valid"] is True
    assert capture_scheduler_runtime_evidence_valid(evidence)


@pytest.mark.parametrize("leaf", ["status", "stat"])
@pytest.mark.parametrize("kind,number", [(PermissionError, errno.EACCES), (OSError, errno.EIO)])
def test_task_permission_or_io_read_failure_remains_strict(tmp_path, monkeypatch, leaf, kind, number):
    monitor, _, task = _started_monitor(tmp_path, monkeypatch)
    calls = _inject_read_error(monkeypatch, task / leaf, kind, number)
    evidence = monitor.finish()
    assert calls
    assert evidence["guest_task_monitor"]["scan_errors"][0].startswith("cannot inspect task 97:")
    _assert_strict_error(evidence)


@pytest.mark.parametrize("leaf,raw", [
    ("status", b"Name:\texiting-helper\nCpus_allowed_list:\t4\n"),
    ("status", b"Name:\texiting-helper\nTgid:\tbad\nCpus_allowed_list:\t4\n"),
    ("status", b"Name:\texiting-helper\nTgid:\t77\nCpus_allowed_list:\tx\n"),
    ("stat", b"malformed task stat\n"),
    ("stat", b"97 (exiting-helper) S 1 bad 0 0 0\n"),
])
def test_malformed_task_proc_data_remains_strict(tmp_path, monkeypatch, leaf, raw):
    monitor, _, task = _started_monitor(tmp_path, monkeypatch)
    (task / leaf).write_bytes(raw)
    evidence = monitor.finish()
    assert evidence["guest_task_monitor"]["scan_errors"][0].startswith("cannot inspect task 97:")
    _assert_strict_error(evidence)


@pytest.mark.parametrize("which", ["processes", "tasks"])
def test_processlookup_during_outer_enumeration_remains_strict(tmp_path, monkeypatch, which):
    monitor, proc_root, _ = _started_monitor(tmp_path, monkeypatch)
    target = proc_root if which == "processes" else proc_root / "77/task"
    original = Path.glob
    calls = []

    def glob(path, *args, **kwargs):
        if path == target:
            calls.append(path)
            raise ProcessLookupError(errno.ESRCH, "controlled outer enumeration")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "glob", glob)
    evidence = monitor.finish()
    assert calls
    assert evidence["guest_task_monitor"]["scan_errors"][0].startswith("cannot enumerate ")
    _assert_strict_error(evidence)
