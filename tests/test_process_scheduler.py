from __future__ import annotations

import copy
from pathlib import Path

import pytest

from qcsd_lab.process_scheduler import (
    CAPTURE_CLIENT_CPU,
    CaptureSchedulerMonitor,
    _host_partition_valid,
    capture_scheduler_runtime_evidence_valid,
)


def _host_partition() -> dict:
    return {
        "schema_version": 1,
        "source": "docker-inspect-all-running-containers-prelaunch-v1",
        "captured_at_unix_ns": 1,
        "client_cpu": CAPTURE_CLIENT_CPU,
        "owner_label": "org.qcsd.owner=qcsd-lab",
        "docker_ncpu": 12,
        "expected_sidecar_names": [],
        "running_study_containers": [],
        "overlapping_container_ids": [],
        "running_container_set_matches_expected": True,
        "valid": True,
        "verified_scope": (
            "all running Docker containers at prelaunch; each must carry the qcsd-lab owner label"
        ),
        "unavailable_scope": [
            "non-container host processes",
            "the measured client container itself, which does not exist at prelaunch",
            "containers or cpuset changes after the prelaunch observation",
            "host-kernel and hypervisor scheduling of the selected logical CPUs",
        ],
    }


def _host_partition_v2() -> dict:
    return {
        "schema_version": 2,
        "source": "docker-inspect-all-running-containers-prelaunch-v2",
        "captured_at_unix_ns": 1,
        "protected_cpus": [10, 11],
        "owner_label": "org.qcsd.owner=qcsd-lab",
        "docker_ncpu": 12,
        "expected_sidecar_names": [],
        "running_study_containers": [],
        "overlapping_container_ids_by_cpu": {"10": [], "11": []},
        "running_container_set_matches_expected": True,
        "valid": True,
        "verified_scope": (
            "all running Docker containers at prelaunch; every container must carry the "
            "qcsd-lab owner label and avoid protected logical CPUs 10 and 11"
        ),
        "unavailable_scope": [
            "non-container host processes",
            "the measured client container itself, which does not exist at prelaunch",
            "containers or cpuset changes after the prelaunch observation",
            "host-kernel and hypervisor scheduling of the selected logical CPUs",
        ],
    }


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


def _monitor(tmp_path: Path) -> tuple[CaptureSchedulerMonitor, Path, Path]:
    proc_root, cpu_stat = _fixture(tmp_path)
    monitor = CaptureSchedulerMonitor(
        proc_root=proc_root,
        cgroup_cpu_stat_paths=(cpu_stat,),
        interval_us=1_000_000,
        host_partition=_host_partition(),
    )
    _write_task(
        proc_root,
        tgid=77,
        tid=77,
        process_group=77,
        cpus="10",
        name="neqo-qcsd-client",
    )
    monitor.process_started(77)
    return monitor, proc_root, cpu_stat


def test_scheduler_runtime_receipt_proves_portable_guest_scope(tmp_path: Path) -> None:
    monitor, _proc_root, _cpu_stat = _monitor(tmp_path)

    evidence = monitor.finish()

    assert capture_scheduler_runtime_evidence_valid(evidence)
    assert evidence["cgroup_cpu_stat"]["nr_throttled_delta"] == 0
    assert evidence["proc_stat_steal"]["steal_ticks_delta"] == 0
    assert evidence["guest_task_monitor"]["expected_client_cpu_task_observed"] is True
    assert evidence["guest_task_monitor"]["unexpected_client_cpu_tasks"] == []
    assert (
        "host-kernel and hypervisor physical-CPU placement or isolation"
        in evidence["unavailable_scope"]
    )


def test_kernel_timed_scheduler_receipts_both_protected_cpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "QCSD_CAPTURE_SCHEDULER_CONTRACT",
        "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
    )
    proc_root, cpu_stat = _fixture(tmp_path)
    monitor = CaptureSchedulerMonitor(
        proc_root=proc_root,
        cgroup_cpu_stat_paths=(cpu_stat,),
        interval_us=1_000_000,
        host_partition=_host_partition_v2(),
    )
    _write_task(
        proc_root,
        tgid=77,
        tid=77,
        process_group=77,
        cpus="10",
        name="neqo-qcsd-client",
    )
    monitor.process_started(77)

    evidence = monitor.finish()

    assert evidence["schema_version"] == 2
    assert evidence["contract"] == "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"
    assert evidence["host_partition"]["protected_cpus"] == [10, 11]
    assert capture_scheduler_runtime_evidence_valid(evidence)


def test_kernel_timed_host_partition_rejects_cpu11_overlap() -> None:
    receipt = _host_partition_v2()
    receipt["running_study_containers"] = [
        {
            "id": "c" * 64,
            "name": "competing-helper",
            "study": "other-study",
            "role": "worker",
            "configured_cpuset": "11",
            "effective_cpus": [11],
            "protected_cpu_overlaps": [11],
            "expected_sidecar": False,
        }
    ]
    receipt["overlapping_container_ids_by_cpu"]["11"] = ["c" * 64]
    receipt["valid"] = False

    assert not _host_partition_valid(receipt)


def test_scheduler_runtime_receipt_rejects_cgroup_throttling(tmp_path: Path) -> None:
    monitor, _proc_root, cpu_stat = _monitor(tmp_path)
    cpu_stat.write_text(
        "usage_usec 110\nuser_usec 66\nsystem_usec 44\n"
        "nr_periods 3\nnr_throttled 1\nthrottled_usec 75\n",
        encoding="ascii",
    )

    evidence = monitor.finish()

    assert evidence["cgroup_cpu_stat"]["nr_throttled_delta"] == 1
    assert evidence["cgroup_cpu_stat"]["throttled_duration_delta"] == 75
    assert evidence["valid"] is False
    assert not capture_scheduler_runtime_evidence_valid(evidence)


def test_scheduler_runtime_receipt_rejects_guest_cpu10_competitor(
    tmp_path: Path,
) -> None:
    monitor, proc_root, _cpu_stat = _monitor(tmp_path)
    _write_task(
        proc_root,
        tgid=88,
        tid=88,
        process_group=88,
        cpus="9-10",
        name="unexpected-sidecar",
    )

    evidence = monitor.finish()

    assert evidence["valid"] is False
    assert evidence["guest_task_monitor"]["unexpected_client_cpu_tasks"] == [
        {
            "tgid": 88,
            "tid": 88,
            "name": "unexpected-sidecar",
            "process_group_id": 88,
            "allowed_cpus": [9, 10],
        }
    ]


def test_scheduler_runtime_receipt_rejects_guest_visible_steal(
    tmp_path: Path,
) -> None:
    monitor, proc_root, _cpu_stat = _monitor(tmp_path)
    (proc_root / "stat").write_text(
        "cpu 1 2 3 4 5 6 7 0 0 0\ncpu10 1 2 3 4 5 6 7 1 0 0\n",
        encoding="ascii",
    )

    evidence = monitor.finish()

    assert evidence["proc_stat_steal"]["steal_ticks_delta"] == 1
    assert evidence["valid"] is False


def test_scheduler_runtime_receipt_records_unexpected_monitor_thread_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc_root, cpu_stat = _fixture(tmp_path)
    monitor = CaptureSchedulerMonitor(
        proc_root=proc_root,
        cgroup_cpu_stat_paths=(cpu_stat,),
        interval_us=1_000,
        host_partition=_host_partition(),
    )
    _write_task(
        proc_root,
        tgid=77,
        tid=77,
        process_group=77,
        cpus="10",
        name="neqo-qcsd-client",
    )
    original_scan = monitor._scan_once
    calls = 0

    def fail_after_start_scan() -> None:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RuntimeError("injected monitor failure")
        original_scan()

    monkeypatch.setattr(monitor, "_scan_once", fail_after_start_scan)
    monitor.process_started(77)
    assert monitor._thread is not None
    monitor._thread.join(timeout=1)

    evidence = monitor.finish()

    assert evidence["valid"] is False
    assert evidence["guest_task_monitor"]["scan_errors"] == [
        "scheduler monitor thread failed: RuntimeError: injected monitor failure",
        "scheduler monitor final scan failed: RuntimeError: injected monitor failure",
    ]
    assert not capture_scheduler_runtime_evidence_valid(evidence)


def test_host_partition_rejects_labelled_container_on_client_cpu() -> None:
    receipt = _host_partition()
    receipt["running_study_containers"] = [
        {
            "id": "a" * 64,
            "name": "competing-study",
            "study": "other-study",
            "role": "worker",
            "configured_cpuset": "",
            "effective_cpus": list(range(12)),
            "client_cpu_overlap": True,
            "expected_sidecar": False,
        }
    ]
    receipt["overlapping_container_ids"] = ["a" * 64]
    receipt["valid"] = False

    assert not _host_partition_valid(receipt)

    falsely_promoted = copy.deepcopy(receipt)
    falsely_promoted["valid"] = True
    assert not _host_partition_valid(falsely_promoted)


def test_host_partition_rejects_extra_qcsd_container_off_client_cpu() -> None:
    receipt = _host_partition()
    receipt["running_study_containers"] = [
        {
            "id": "b" * 64,
            "name": "stale-worker",
            "study": "older-study",
            "role": "worker",
            "configured_cpuset": "0-9",
            "effective_cpus": list(range(10)),
            "client_cpu_overlap": False,
            "expected_sidecar": False,
        }
    ]

    assert receipt["running_container_set_matches_expected"] is True
    assert receipt["valid"] is True
    assert not _host_partition_valid(receipt)
