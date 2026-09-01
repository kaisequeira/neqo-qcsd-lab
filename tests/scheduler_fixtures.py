from __future__ import annotations

import hashlib
import json
from typing import Any, MutableMapping

from qcsd_lab.experiment import SCHEDULER_RUNTIME_RECEIPT_KEY, scheduler_runtime_receipt


def process_scheduler_receipt() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": "linux-sched-and-procfs-v1",
        "policy": "SCHED_RR",
        "priority": 1,
        "affinity_cpus": [10],
        "rlimit_rtprio": {"soft": 1, "hard": 1},
        "no_new_privileges": True,
        "effective_capabilities_hex": "0000000000000000",
        "cgroup_effective_cpuset": "10-11",
        "affinity_scope": ("qcsd_container_affinity_partition_not_physical_cpu_isolation"),
        "contract": "qcsd-client-rr1-cpu10-v1",
        "contract_valid": True,
    }


def scheduler_runtime_evidence() -> dict[str, Any]:
    host_partition = {
        "schema_version": 1,
        "source": "docker-inspect-all-running-containers-prelaunch-v1",
        "captured_at_unix_ns": 1,
        "client_cpu": 10,
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
    counters = {
        "usage_usec": 10,
        "user_usec": 6,
        "system_usec": 4,
        "nr_periods": 2,
        "nr_throttled": 0,
        "throttled_usec": 0,
    }
    return {
        "schema_version": 1,
        "source": "linux-cgroup-procfs-monitor-and-docker-host-prelaunch-v1",
        "contract": "qcsd-client-rr1-cpu10-v1",
        "client_cpu": 10,
        "orchestrator_cpu": 11,
        "cgroup_cpu_stat": {
            "available": True,
            "scope": "entire collection container cgroup, not the client process alone",
            "path": "/sys/fs/cgroup/cpu.stat",
            "unavailable_reason": None,
            "throttled_duration_key": "throttled_usec",
            "throttled_duration_unit": "microseconds",
            "before": counters,
            "after": counters,
            "delta": {key: 0 for key in counters},
            "nr_throttled_delta": 0,
            "throttled_duration_delta": 0,
        },
        "proc_stat_steal": {
            "available": True,
            "scope": ("guest-visible aggregate for logical CPU 10, not client-process attribution"),
            "path": "/proc/stat",
            "unavailable_reason": None,
            "clock_ticks_per_second": 100,
            "before_steal_ticks": 0,
            "after_steal_ticks": 0,
            "steal_ticks_delta": 0,
        },
        "guest_task_monitor": {
            "source": "procfs-task-affinity-sampled-v1",
            "scope": "tasks visible in the collection container PID namespace",
            "client_cpu": 10,
            "sampling_interval_us": 10_000,
            "samples": 3,
            "pid_namespace_inode": 1,
            "expected_process_group_id": 77,
            "expected_client_cpu_task_observed": True,
            "visible_tasks_max": 1,
            "client_cpu_eligible_tasks_max": 1,
            "expected_client_cpu_tasks_max": 1,
            "unexpected_client_cpu_tasks": [],
            "unexpected_task_receipt_overflow": False,
            "scan_errors": [],
        },
        "host_partition": host_partition,
        "verified_scope": [
            "measured process-group eligibility for logical CPU 10 in the collection PID namespace",
            "collection-cgroup CPU throttling counters over the measured client interval",
            "guest-visible logical CPU 10 steal ticks over the measured client interval when exposed",
            "all running Docker container cpusets at host prelaunch, with every container QCSD-owned",
        ],
        "unavailable_scope": [
            "non-container host processes",
            "the measured client container itself, whose cpuset is bound separately by the launch contract",
            "host interrupt handling and kernel work not represented as visible tasks",
            "host-kernel and hypervisor physical-CPU placement or isolation",
            "Docker container starts or cpuset changes after the host prelaunch observation",
        ],
        "valid": True,
    }


def install_scheduler_runtime_receipt(
    run: MutableMapping[str, Any],
    diagnostics: MutableMapping[str, Any],
) -> None:
    run.setdefault("runner_wakeup_metrics", {"schema_version": 7})
    run["process_scheduler"] = process_scheduler_receipt()
    evidence = scheduler_runtime_evidence()
    encoded = json.dumps(evidence, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    diagnostics[SCHEDULER_RUNTIME_RECEIPT_KEY] = scheduler_runtime_receipt(
        evidence=evidence,
        evidence_sha256=hashlib.sha256(encoded).hexdigest(),
        process_scheduler_required=True,
        process_scheduler_valid=True,
        evidence_valid=True,
    )
