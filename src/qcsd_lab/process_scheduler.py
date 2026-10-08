"""Fail-closed launch and runtime evidence for a measured study client."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import resource
import threading
import time
from pathlib import Path
from typing import Any, Mapping

CAPTURE_SCHEDULER_CONTRACT = "qcsd-client-rr1-cpu10-v1"
BUFLO_ETF_SCHEDULER_CONTRACT = "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"
PORTABLE_ETF_SCHEDULER_CONTRACT = "qcsd-client-rr1-portable-etf-helper-v3"
PORTABLE_ETF_SCHEDULER_CONTRACT_V4 = "qcsd-client-rr1-portable-etf-helper-v4"
CAPTURE_ORCHESTRATOR_CPU = 11
CAPTURE_CLIENT_CPU = 10
CAPTURE_SCHEDULER_RUNTIME_SCHEMA_VERSION = 1
BUFLO_ETF_SCHEDULER_RUNTIME_SCHEMA_VERSION = 2
PORTABLE_ETF_SCHEDULER_RUNTIME_SCHEMA_VERSION = 3
PORTABLE_ETF_SCHEDULER_RUNTIME_V4_SCHEMA_VERSION = 4
CAPTURE_SCHEDULER_RUNTIME_SOURCE = "linux-cgroup-procfs-monitor-and-docker-host-prelaunch-v1"
BUFLO_ETF_SCHEDULER_RUNTIME_SOURCE = (
    "linux-cgroup-procfs-monitor-and-docker-host-prelaunch-v2"
)
PORTABLE_ETF_SCHEDULER_RUNTIME_SOURCE = (
    "linux-cgroup-procfs-monitor-and-docker-host-prelaunch-v3"
)
PORTABLE_ETF_SCHEDULER_RUNTIME_V4_SOURCE = (
    "linux-cgroup-procfs-monitor-and-docker-host-prelaunch-v4"
)
CAPTURE_SCHEDULER_HOST_ENV = "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64"
CAPTURE_SCHEDULER_HOST_FILE_ENV = "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_FILE"
CAPTURE_SCHEDULER_HOST_SHA256_ENV = "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_SHA256"
PEER_HOST_PARTITION_CONTRACT = "qcsd-two-lane-peer-cpu-partition-v1"
RESOURCE_STUDY_PEER_HOST_PARTITION_CONTRACT = "qcsd-resource-study-peer-cpu-partition-v1"
PEER_SCHEDULER_RUNTIME_SCHEMA_VERSION = 5
PEER_SCHEDULER_RUNTIME_SOURCE = (
    "linux-cgroup-procfs-monitor-and-docker-host-prelaunch-v5"
)
_PEER_HOST_SCOPE = (
    "all running Docker containers and both declared workers at prelaunch; "
    "exact worker identities use disjoint CPU pairs and all sidecars use the residual CPUs"
)
_RESOURCE_STUDY_HOST_SCOPE = (
    "all running Docker containers and all declared resource-study workers at prelaunch; "
    "exact worker identities use disjoint CPU pairs and all sidecars use the residual CPUs"
)
_PEER_HOST_UNAVAILABLE_SCOPE = [
    "non-container host processes",
    "containers or cpuset changes after the prelaunch observation",
    "host-kernel and hypervisor scheduling of the selected logical CPUs",
]
_PEER_WORKER_KEYS = {"id", "name", "image_id", "client_cpu", "orchestrator_cpu"}
_PEER_HOST_KEYS = {
    "schema_version", "source", "peer_contract", "captured_at_unix_ns",
    "protected_cpus", "available_cpus", "owner_label", "docker_ncpu",
    "expected_sidecars", "declared_workers", "measured_container_id",
    "inspected_containers", "overlapping_container_ids_by_cpu",
    "inspected_container_set_matches_expected", "valid", "verified_scope",
    "unavailable_scope",
}
CAPTURE_SCHEDULER_MONITOR_INTERVAL_US = 10_000

_CGROUP_CPU_STAT_PATHS = (
    Path("/sys/fs/cgroup/cpu.stat"),
    Path("/sys/fs/cgroup/cpu/cpu.stat"),
)
_PROC_ROOT = Path("/proc")
_MAX_RECORDED_TASKS = 64
_MAX_RECORDED_SCAN_ERRORS = 16
_HOST_PARTITION_KEYS = {
    "schema_version",
    "source",
    "captured_at_unix_ns",
    "client_cpu",
    "owner_label",
    "docker_ncpu",
    "expected_sidecar_names",
    "running_study_containers",
    "overlapping_container_ids",
    "running_container_set_matches_expected",
    "valid",
    "verified_scope",
    "unavailable_scope",
}
_HOST_CONTAINER_KEYS = {
    "id",
    "name",
    "study",
    "role",
    "configured_cpuset",
    "effective_cpus",
    "client_cpu_overlap",
    "expected_sidecar",
}
_HOST_PARTITION_V2_KEYS = {
    "schema_version",
    "source",
    "captured_at_unix_ns",
    "protected_cpus",
    "owner_label",
    "docker_ncpu",
    "expected_sidecar_names",
    "running_study_containers",
    "overlapping_container_ids_by_cpu",
    "running_container_set_matches_expected",
    "valid",
    "verified_scope",
    "unavailable_scope",
}
_HOST_PARTITION_V4_KEYS = _HOST_PARTITION_V2_KEYS | {"available_cpus"}
_HOST_CONTAINER_V2_KEYS = {
    "id",
    "name",
    "study",
    "role",
    "configured_cpuset",
    "effective_cpus",
    "protected_cpu_overlaps",
    "expected_sidecar",
}
_PEER_CONTAINER_KEYS = _HOST_CONTAINER_V2_KEYS | {"image_id", "state", "expected_worker"}
_CPU_STAT_EVIDENCE_KEYS = {
    "available",
    "scope",
    "path",
    "unavailable_reason",
    "throttled_duration_key",
    "throttled_duration_unit",
    "before",
    "after",
    "delta",
    "nr_throttled_delta",
    "throttled_duration_delta",
}
_STEAL_EVIDENCE_KEYS = {
    "available",
    "scope",
    "path",
    "unavailable_reason",
    "clock_ticks_per_second",
    "before_steal_ticks",
    "after_steal_ticks",
    "steal_ticks_delta",
}
_TASK_MONITOR_KEYS = {
    "source",
    "scope",
    "client_cpu",
    "sampling_interval_us",
    "samples",
    "pid_namespace_inode",
    "expected_process_group_id",
    "expected_client_cpu_task_observed",
    "visible_tasks_max",
    "client_cpu_eligible_tasks_max",
    "expected_client_cpu_tasks_max",
    "unexpected_client_cpu_tasks",
    "unexpected_task_receipt_overflow",
    "scan_errors",
}
_PEER_TASK_MONITOR_KEYS = _TASK_MONITOR_KEYS | {
    "protected_cpus", "unexpected_pair_escape_tasks", "pair_escape_task_receipt_overflow",
}


def capture_scheduler_contract() -> str | None:
    """Return the one supported measured-client scheduler contract, if selected."""

    value = os.environ.get("QCSD_CAPTURE_SCHEDULER_CONTRACT")
    if value in {None, ""}:
        return None
    if value not in {
        CAPTURE_SCHEDULER_CONTRACT,
        BUFLO_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    }:
        raise ValueError(f"unsupported capture scheduler contract: {value}")
    return value


def capture_scheduler_cpus(contract: str | None = None) -> tuple[int, int]:
    """Read the selected launch partition; keep historical contracts immutable."""

    selected = contract or capture_scheduler_contract()
    if selected not in {
        PORTABLE_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    }:
        return CAPTURE_CLIENT_CPU, CAPTURE_ORCHESTRATOR_CPU
    raw_client = os.environ.get("QCSD_CAPTURE_CLIENT_CPU", "")
    raw_orchestrator = os.environ.get("QCSD_CAPTURE_ORCHESTRATOR_CPU", "")
    if not raw_client.isdecimal() or not raw_orchestrator.isdecimal():
        raise ValueError("portable capture scheduler CPUs were not supplied")
    client, orchestrator = int(raw_client), int(raw_orchestrator)
    if (
        client < 1
        or orchestrator <= client
        or (selected == PORTABLE_ETF_SCHEDULER_CONTRACT and orchestrator != client + 1)
    ):
        raise ValueError("portable capture scheduler CPU partition is invalid")
    return client, orchestrator


def scheduler_receipt_cpus(
    value: Mapping[str, Any], contract: str | None
) -> tuple[int, int] | None:
    """Validate the runner's observed partition without trusting launch env."""

    if contract in {CAPTURE_SCHEDULER_CONTRACT, BUFLO_ETF_SCHEDULER_CONTRACT}:
        return CAPTURE_CLIENT_CPU, CAPTURE_ORCHESTRATOR_CPU
    if contract not in {
        PORTABLE_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    }:
        return None
    affinity = value.get("affinity_cpus")
    if (
        not isinstance(affinity, list)
        or len(affinity) != 1
        or type(affinity[0]) is not int
        or affinity[0] < 1
    ):
        return None
    client_cpu = affinity[0]
    if contract == PORTABLE_ETF_SCHEDULER_CONTRACT:
        orchestrator_cpu = client_cpu + 1
        if value.get("cgroup_effective_cpuset") != f"{client_cpu}-{orchestrator_cpu}":
            return None
    else:
        cpuset = value.get("cgroup_effective_cpuset")
        if not isinstance(cpuset, str):
            return None
        try:
            observed = _cpu_list(cpuset)
        except ValueError:
            return None
        if len(observed) != 2 or client_cpu != min(observed):
            return None
        orchestrator_cpu = max(observed)
    return client_cpu, orchestrator_cpu


def capture_scheduler_launch_prefix() -> list[str]:
    """Fail closed on the container partition before elevating only the client."""

    peer_file_selected = (
        CAPTURE_SCHEDULER_HOST_FILE_ENV in os.environ
        or CAPTURE_SCHEDULER_HOST_SHA256_ENV in os.environ
    )
    if capture_scheduler_contract() is None:
        if peer_file_selected:
            raise ValueError("prospective peer partition requires the portable v4 Native scheduler contract")
        return []
    client_cpu, orchestrator_cpu = capture_scheduler_cpus()
    if peer_file_selected:
        host = _load_host_partition()
        if not _host_partition_peer_valid(host):
            raise ValueError("prospective peer host partition failed before client launch")
        worker = next(worker for worker in host["declared_workers"] if worker["id"] == host["measured_container_id"])
        if [client_cpu, orchestrator_cpu] != [worker["client_cpu"], worker["orchestrator_cpu"]]:
            raise ValueError("measured worker CPU pair differs from the hash-bound peer partition")
    affinity = os.sched_getaffinity(0)
    if affinity != {orchestrator_cpu}:
        raise ValueError(
            f"capture scheduler parent must be confined to orchestrator CPU "
            f"{orchestrator_cpu}"
        )
    rtprio = resource.getrlimit(resource.RLIMIT_RTPRIO)
    if rtprio != (1, 1):
        raise ValueError("capture scheduler requires RLIMIT_RTPRIO soft/hard 1")
    prefix = [
        "/usr/bin/taskset",
        "--cpu-list",
        str(client_cpu),
        "/usr/bin/chrt",
        "--rr",
        "1",
        "/usr/bin/setpriv",
    ]
    if capture_scheduler_contract() in {
        BUFLO_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    }:
        # BuFLO's real UDP sockets must select CLOCK_TAI while the Linux ETF
        # qdisc still performs its normal socket consistency check.  Retain
        # exactly CAP_NET_ADMIN and CAP_SETPCAP for that bounded setup phase;
        # the Rust runner configures every socket, drops both capabilities and
        # the bounding set, verifies the capability-free state, and only then
        # starts the selected timed-egress helper CPU. A complete run whose kernel
        # receipt does not prove that transition is rejected by the Lab.
        prefix.extend(
            [
                "--bounding-set=-all,+net_admin,+setpcap",
                "--inh-caps=-all,+net_admin,+setpcap",
                "--ambient-caps=-all,+net_admin,+setpcap",
            ]
        )
    else:
        prefix.extend(
            [
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
            ]
        )
    prefix.extend(["--no-new-privs", "--"])
    return prefix


def _uint(value: Any) -> bool:
    return type(value) is int and value >= 0


def _cpu_list(value: str) -> set[int]:
    """Parse Linux/Docker comma-separated CPU ranges without accepting aliases."""

    if not value or value.strip() != value:
        raise ValueError("CPU list is empty or not canonical")
    cpus: set[int] = set()
    for component in value.split(","):
        if not component:
            raise ValueError("CPU list has an empty component")
        start_text, separator, end_text = component.partition("-")
        if not start_text.isdecimal() or (separator and not end_text.isdecimal()):
            raise ValueError("CPU list has a non-numeric component")
        start = int(start_text)
        end = int(end_text) if separator else start
        if end < start:
            raise ValueError("CPU list range is reversed")
        cpus.update(range(start, end + 1))
    return cpus


def _host_partition_v1_valid(value: Any) -> bool:
    """Validate the frozen CPU-10-only Docker prelaunch receipt."""

    if not isinstance(value, Mapping) or set(value) != _HOST_PARTITION_KEYS:
        return False
    containers = value.get("running_study_containers")
    expected = value.get("expected_sidecar_names")
    overlaps = value.get("overlapping_container_ids")
    if (
        value.get("schema_version") != 1
        or value.get("source") != "docker-inspect-all-running-containers-prelaunch-v1"
        or not _uint(value.get("captured_at_unix_ns"))
        or value["captured_at_unix_ns"] == 0
        or value.get("client_cpu") != CAPTURE_CLIENT_CPU
        or value.get("owner_label") != "org.qcsd.owner=qcsd-lab"
        or not _uint(value.get("docker_ncpu"))
        or value["docker_ncpu"] <= CAPTURE_ORCHESTRATOR_CPU
        or not isinstance(expected, list)
        or any(not isinstance(item, str) or not item for item in expected)
        or len(expected) != len(set(expected))
        or not isinstance(containers, list)
        or not isinstance(overlaps, list)
        or any(not isinstance(item, str) or not item for item in overlaps)
        or len(overlaps) != len(set(overlaps))
        or value.get("running_container_set_matches_expected") is not True
        or value.get("valid") is not True
        or value.get("verified_scope")
        != ("all running Docker containers at prelaunch; each must carry the qcsd-lab owner label")
        or value.get("unavailable_scope")
        != [
            "non-container host processes",
            "the measured client container itself, which does not exist at prelaunch",
            "containers or cpuset changes after the prelaunch observation",
            "host-kernel and hypervisor scheduling of the selected logical CPUs",
        ]
    ):
        return False
    expected_set = set(expected)
    ids: set[str] = set()
    names: set[str] = set()
    derived_overlaps: list[str] = []
    observed_expected: set[str] = set()
    for container in containers:
        if not isinstance(container, Mapping) or set(container) != _HOST_CONTAINER_KEYS:
            return False
        container_id = container.get("id")
        name = container.get("name")
        configured = container.get("configured_cpuset")
        effective = container.get("effective_cpus")
        if (
            not isinstance(container_id, str)
            or len(container_id) != 64
            or any(character not in "0123456789abcdef" for character in container_id)
            or container_id in ids
            or not isinstance(name, str)
            or not name
            or name in names
            or not isinstance(container.get("study"), str)
            or not isinstance(container.get("role"), str)
            or not isinstance(configured, str)
            or not isinstance(effective, list)
            or any(type(cpu) is not int or cpu < 0 for cpu in effective)
            or effective != sorted(set(effective))
            or container.get("client_cpu_overlap") is not (CAPTURE_CLIENT_CPU in effective)
            or container.get("expected_sidecar") is not (name in expected_set)
        ):
            return False
        if configured:
            try:
                if effective != sorted(_cpu_list(configured)):
                    return False
            except ValueError:
                return False
        elif effective != list(range(value["docker_ncpu"])):
            return False
        if name in expected_set:
            observed_expected.add(name)
            if effective != list(range(CAPTURE_CLIENT_CPU)):
                return False
        if CAPTURE_CLIENT_CPU in effective:
            derived_overlaps.append(container_id)
        ids.add(container_id)
        names.add(name)
    return (
        observed_expected == expected_set
        and names == expected_set
        and overlaps == sorted(derived_overlaps)
        and not overlaps
    )


def _host_partition_v2_valid(
    value: Any, *, portable: bool = False, sparse: bool = False
) -> bool:
    """Validate a kernel-timed partition against its versioned topology."""

    if not isinstance(value, Mapping) or set(value) != (
        _HOST_PARTITION_V4_KEYS if sparse else _HOST_PARTITION_V2_KEYS
    ):
        return False
    containers = value.get("running_study_containers")
    expected = value.get("expected_sidecar_names")
    overlaps = value.get("overlapping_container_ids_by_cpu")
    ncpu = value.get("docker_ncpu")
    if sparse:
        available_cpus = value.get("available_cpus")
        if (
            not isinstance(available_cpus, list)
            or len(available_cpus) < 3
            or any(type(cpu) is not int or cpu < 0 for cpu in available_cpus)
            or available_cpus != sorted(set(available_cpus))
        ):
            return False
        protected_cpus = available_cpus[-2:]
        sidecar_cpus = available_cpus[:-2]
    elif portable:
        if not _uint(ncpu) or ncpu < 3:
            return False
        protected_cpus = [ncpu - 2, ncpu - 1]
        sidecar_cpus = list(range(ncpu - 2))
    else:
        protected_cpus = [CAPTURE_CLIENT_CPU, CAPTURE_ORCHESTRATOR_CPU]
        sidecar_cpus = list(range(CAPTURE_CLIENT_CPU))
    client_cpu, orchestrator_cpu = protected_cpus
    version = 4 if sparse else (3 if portable else 2)
    if (
        value.get("schema_version") != version
        or value.get("source")
        != f"docker-inspect-all-running-containers-prelaunch-v{version}"
        or not _uint(value.get("captured_at_unix_ns"))
        or value["captured_at_unix_ns"] == 0
        or value.get("protected_cpus") != protected_cpus
        or value.get("owner_label") != "org.qcsd.owner=qcsd-lab"
        or not _uint(value.get("docker_ncpu"))
        or (not sparse and value["docker_ncpu"] <= orchestrator_cpu)
        or not isinstance(expected, list)
        or any(not isinstance(item, str) or not item for item in expected)
        or len(expected) != len(set(expected))
        or not isinstance(containers, list)
        or not isinstance(overlaps, Mapping)
        or set(overlaps) != {str(cpu) for cpu in protected_cpus}
        or any(
            not isinstance(items, list)
            or any(not isinstance(item, str) or not item for item in items)
            or len(items) != len(set(items))
            for items in overlaps.values()
        )
        or value.get("running_container_set_matches_expected") is not True
        or value.get("valid") is not True
        or value.get("verified_scope")
        != (
            "all running Docker containers at prelaunch; every container must carry the "
            f"qcsd-lab owner label and avoid protected logical CPUs {client_cpu} and {orchestrator_cpu}"
        )
        or value.get("unavailable_scope")
        != [
            "non-container host processes",
            "the measured client container itself, which does not exist at prelaunch",
            "containers or cpuset changes after the prelaunch observation",
            "host-kernel and hypervisor scheduling of the selected logical CPUs",
        ]
    ):
        return False
    expected_set = set(expected)
    ids: set[str] = set()
    names: set[str] = set()
    observed_expected: set[str] = set()
    derived_overlaps = {str(cpu): [] for cpu in protected_cpus}
    for container in containers:
        if not isinstance(container, Mapping) or set(container) != _HOST_CONTAINER_V2_KEYS:
            return False
        container_id = container.get("id")
        name = container.get("name")
        configured = container.get("configured_cpuset")
        effective = container.get("effective_cpus")
        expected_overlaps = [cpu for cpu in protected_cpus if cpu in (effective or [])]
        if (
            not isinstance(container_id, str)
            or len(container_id) != 64
            or any(character not in "0123456789abcdef" for character in container_id)
            or container_id in ids
            or not isinstance(name, str)
            or not name
            or name in names
            or not isinstance(container.get("study"), str)
            or not isinstance(container.get("role"), str)
            or not isinstance(configured, str)
            or not isinstance(effective, list)
            or any(type(cpu) is not int or cpu < 0 for cpu in effective)
            or effective != sorted(set(effective))
            or container.get("protected_cpu_overlaps") != expected_overlaps
            or container.get("expected_sidecar") is not (name in expected_set)
        ):
            return False
        if configured:
            try:
                configured_cpus = _cpu_list(configured)
                if (sparse and not configured_cpus.issubset(available_cpus)) or effective != sorted(configured_cpus):
                    return False
            except ValueError:
                return False
        elif effective != (available_cpus if sparse else list(range(value["docker_ncpu"]))):
            return False
        if name in expected_set:
            observed_expected.add(name)
            if effective != sidecar_cpus:
                return False
        for cpu in expected_overlaps:
            derived_overlaps[str(cpu)].append(container_id)
        ids.add(container_id)
        names.add(name)
    return bool(
        observed_expected == expected_set
        and names == expected_set
        and all(overlaps[key] == sorted(derived_overlaps[key]) for key in overlaps)
        and all(not items for items in overlaps.values())
    )


def _docker_id(value: Any) -> bool:
    return bool(
        isinstance(value, str) and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _image_id(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _docker_id(value[7:])


def _peer_partition_workers(value: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], list[int]] | None:
    available = value.get("available_cpus")
    workers = value.get("declared_workers")
    resource_study = value.get("peer_contract") == RESOURCE_STUDY_PEER_HOST_PARTITION_CONTRACT
    if (
        not isinstance(available, list) or len(available) < 5
        or any(not _uint(cpu) for cpu in available)
        or available != sorted(set(available))
        or not isinstance(workers, list)
        or (len(workers) < 2 if resource_study else len(workers) != 2)
    ):
        return None
    by_id: dict[str, Mapping[str, Any]] = {}
    names: set[str] = set()
    protected: set[int] = set()
    for worker in workers:
        if not isinstance(worker, Mapping) or set(worker) != _PEER_WORKER_KEYS:
            return None
        container_id, name = worker["id"], worker["name"]
        client, helper = worker["client_cpu"], worker["orchestrator_cpu"]
        if (
            not _docker_id(container_id) or container_id in by_id
            or not isinstance(name, str) or not name or name in names
            or not _image_id(worker["image_id"])
            or not _uint(client) or client < 1 or not _uint(helper) or helper <= client
            or not {client, helper}.issubset(available)
            or protected.intersection({client, helper})
        ):
            return None
        by_id[container_id] = worker
        names.add(name)
        protected.update((client, helper))
    if (
        not _docker_id(value.get("measured_container_id"))
        or value["measured_container_id"] not in by_id or not set(available) - protected
    ):
        return None
    return by_id, sorted(protected)


def _peer_scope(value: Mapping[str, Any]) -> str:
    return (_RESOURCE_STUDY_HOST_SCOPE
        if value.get("peer_contract") == RESOURCE_STUDY_PEER_HOST_PARTITION_CONTRACT else _PEER_HOST_SCOPE)


def _host_partition_peer_valid(value: Any) -> bool:
    """Validate the exact historical pair or explicit prospective resource workers."""

    if not isinstance(value, Mapping) or set(value) != _PEER_HOST_KEYS:
        return False
    partition = _peer_partition_workers(value)
    if partition is None:
        return False
    workers, protected = partition
    available = value["available_cpus"]
    residual = sorted(set(available) - set(protected))
    expected = value.get("expected_sidecars")
    containers = value.get("inspected_containers")
    overlaps = value.get("overlapping_container_ids_by_cpu")
    if (
        value.get("schema_version") != 5
        or value.get("source") != "docker-inspect-all-running-containers-and-declared-workers-prelaunch-v5"
        or value.get("peer_contract") not in {PEER_HOST_PARTITION_CONTRACT, RESOURCE_STUDY_PEER_HOST_PARTITION_CONTRACT}
        or not _uint(value.get("captured_at_unix_ns")) or value["captured_at_unix_ns"] == 0
        or value.get("protected_cpus") != protected
        or value.get("owner_label") != "org.qcsd.owner=qcsd-lab"
        or not _uint(value.get("docker_ncpu")) or value["docker_ncpu"] < len(available)
        or not isinstance(expected, Mapping)
        or any(not isinstance(name, str) or not name or not _docker_id(cid) for name, cid in expected.items())
        or len(set(expected.values())) != len(expected)
        or set(expected.values()).intersection(workers)
        or set(expected).intersection(worker["name"] for worker in workers.values())
        or not isinstance(containers, list)
        or not isinstance(overlaps, Mapping) or set(overlaps) != {str(cpu) for cpu in protected}
        or value.get("inspected_container_set_matches_expected") is not True
        or value.get("valid") is not True
        or value.get("verified_scope") != _peer_scope(value)
        or value.get("unavailable_scope") != _PEER_HOST_UNAVAILABLE_SCOPE
    ):
        return False
    ids: set[str] = set()
    names: set[str] = set()
    derived = {str(cpu): [] for cpu in protected}
    for container in containers:
        if not isinstance(container, Mapping) or set(container) != _PEER_CONTAINER_KEYS:
            return False
        cid, name = container.get("id"), container.get("name")
        effective, configured = container.get("effective_cpus"), container.get("configured_cpuset")
        if (
            not _docker_id(cid) or cid in ids
            or not isinstance(name, str) or not name or name in names
            or not _image_id(container.get("image_id"))
            or not isinstance(container.get("study"), str) or not isinstance(container.get("role"), str)
            or not isinstance(configured, str) or not configured
            or not isinstance(effective, list) or any(not _uint(cpu) for cpu in effective)
            or effective != sorted(set(effective))
            or not set(effective).issubset(available)
            or container.get("state") not in {"created", "running"}
            or container.get("expected_worker") is not (cid in workers)
            or container.get("expected_sidecar") is not (expected.get(name) == cid)
        ):
            return False
        try:
            if sorted(_cpu_list(configured)) != effective:
                return False
        except ValueError:
            return False
        worker = workers.get(cid)
        if worker is not None:
            if (
                name != worker["name"] or container["image_id"] != worker["image_id"]
                or effective != [worker["client_cpu"], worker["orchestrator_cpu"]]
            ):
                return False
        elif expected.get(name) != cid or effective != residual or container["state"] != "running":
            return False
        actual_overlaps = [cpu for cpu in protected if cpu in effective]
        if container.get("protected_cpu_overlaps") != actual_overlaps:
            return False
        for cpu in actual_overlaps:
            derived[str(cpu)].append(cid)
        ids.add(cid)
        names.add(name)
    return bool(
        ids == set(workers) | set(expected.values())
        and names == {worker["name"] for worker in workers.values()} | set(expected)
        and all(overlaps[key] == sorted(derived[key]) for key in derived)
    )


def build_peer_host_partition(
    inspected: list[Mapping[str, Any]], available_cpus: list[int],
    declared_workers: list[Mapping[str, Any]], expected_sidecars: Mapping[str, str],
    measured_container_id: str, *, docker_ncpu: int, resource_study: bool = False,
) -> dict[str, Any]:
    """Build a prospective proof from actual Docker inspect records after create.

    The caller supplies every running container and all declared workers.
    Only explicit resource_study=True selects the prospective N-worker contract.
    Docker IDs and image IDs are observed identities, never guessed launch names.
    """

    if type(resource_study) is not bool:
        raise ValueError("resource-study partition selection must be boolean")
    value: dict[str, Any] = {
        "schema_version": 5,
        "source": "docker-inspect-all-running-containers-and-declared-workers-prelaunch-v5",
        "peer_contract": (RESOURCE_STUDY_PEER_HOST_PARTITION_CONTRACT if resource_study else PEER_HOST_PARTITION_CONTRACT),
        "captured_at_unix_ns": time.time_ns(),
        "available_cpus": list(available_cpus), "docker_ncpu": docker_ncpu,
        "owner_label": "org.qcsd.owner=qcsd-lab",
        "declared_workers": [dict(worker) for worker in declared_workers],
        "measured_container_id": measured_container_id,
        "expected_sidecars": dict(expected_sidecars),
        "inspected_container_set_matches_expected": True, "valid": True,
        "verified_scope": _RESOURCE_STUDY_HOST_SCOPE if resource_study else _PEER_HOST_SCOPE,
        "unavailable_scope": list(_PEER_HOST_UNAVAILABLE_SCOPE),
    }
    partition = _peer_partition_workers(value)
    if partition is None or not isinstance(inspected, list):
        raise ValueError("resource-study CPU partition requires disjoint pairs and a residual CPU pool"
            if resource_study else "two-worker CPU partition requires two disjoint pairs and a residual CPU pool")
    workers, protected = partition
    value["protected_cpus"] = protected
    containers = []
    for item in inspected:
        if not isinstance(item, Mapping):
            raise ValueError("Docker inspect record is not an object")
        config, host, state = item.get("Config"), item.get("HostConfig"), item.get("State")
        if not all(isinstance(part, Mapping) for part in (config, host, state)):
            raise ValueError("Docker inspect record lacks configuration or state")
        labels = config.get("Labels") or {}
        if not isinstance(labels, Mapping) or labels.get("org.qcsd.owner") != "qcsd-lab":
            raise ValueError("peer partition refuses a container without the qcsd-lab owner label")
        status = state.get("Status")
        if status not in {"created", "running"} or state.get("Running") is not (status == "running"):
            raise ValueError("peer partition requires created workers or running containers")
        configured = host.get("CpusetCpus")
        if not isinstance(configured, str) or not configured:
            raise ValueError("peer partition requires an explicit Docker cpuset")
        effective = sorted(_cpu_list(configured))
        name = item.get("Name")
        if not isinstance(name, str):
            raise ValueError("Docker inspect record lacks a name")
        name = name.removeprefix("/")
        cid = item.get("Id")
        containers.append({
            "id": cid, "name": name, "image_id": item.get("Image"), "state": status,
            "study": labels.get("org.qcsd.study", ""), "role": labels.get("org.qcsd.role", ""),
            "configured_cpuset": configured, "effective_cpus": effective,
            "protected_cpu_overlaps": [cpu for cpu in protected if cpu in effective],
            "expected_sidecar": expected_sidecars.get(name) == cid,
            "expected_worker": cid in workers,
        })
    value["inspected_containers"] = sorted(containers, key=lambda item: (item["name"], item["id"]))
    value["overlapping_container_ids_by_cpu"] = {
        str(cpu): sorted(item["id"] for item in containers if cpu in item["effective_cpus"])
        for cpu in protected
    }
    if not _host_partition_peer_valid(value):
        raise ValueError("Docker peer partition identities, CPU pairs, or container inventory failed verification")
    return value


def _host_partition_valid(value: Any) -> bool:
    """Validate either immutable scheduler-host receipt by its explicit version."""

    if not isinstance(value, Mapping):
        return False
    if value.get("schema_version") == 1:
        return _host_partition_v1_valid(value)
    if value.get("schema_version") == 2:
        return _host_partition_v2_valid(value)
    if value.get("schema_version") == 3:
        return _host_partition_v2_valid(value, portable=True)
    if value.get("schema_version") == 4:
        return _host_partition_v2_valid(value, sparse=True)
    if value.get("schema_version") == 5:
        return _host_partition_peer_valid(value)
    return False


def _unavailable_host_partition_v1(reason: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": "docker-inspect-all-running-containers-prelaunch-v1",
        "captured_at_unix_ns": 0,
        "client_cpu": CAPTURE_CLIENT_CPU,
        "owner_label": "org.qcsd.owner=qcsd-lab",
        "docker_ncpu": 0,
        "expected_sidecar_names": [],
        "running_study_containers": [],
        "overlapping_container_ids": [],
        "running_container_set_matches_expected": False,
        "valid": False,
        "verified_scope": (
            "all running Docker containers at prelaunch; each must carry the qcsd-lab owner label"
        ),
        "unavailable_scope": [
            "non-container host processes",
            "the measured client container itself, which does not exist at prelaunch",
            "containers or cpuset changes after the prelaunch observation",
            "host-kernel and hypervisor scheduling of the selected logical CPUs",
        ],
        "error": reason,
    }


def _unavailable_host_partition_v2(reason: str) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "source": "docker-inspect-all-running-containers-prelaunch-v2",
        "captured_at_unix_ns": 0,
        "protected_cpus": [CAPTURE_CLIENT_CPU, CAPTURE_ORCHESTRATOR_CPU],
        "owner_label": "org.qcsd.owner=qcsd-lab",
        "docker_ncpu": 0,
        "expected_sidecar_names": [],
        "running_study_containers": [],
        "overlapping_container_ids_by_cpu": {
            str(CAPTURE_CLIENT_CPU): [],
            str(CAPTURE_ORCHESTRATOR_CPU): [],
        },
        "running_container_set_matches_expected": False,
        "valid": False,
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
        "error": reason,
    }


def _unavailable_host_partition(reason: str) -> dict[str, Any]:
    if capture_scheduler_contract() in {
        PORTABLE_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    }:
        sparse = capture_scheduler_contract() == PORTABLE_ETF_SCHEDULER_CONTRACT_V4
        value = _unavailable_host_partition_v2(reason)
        value["schema_version"] = 4 if sparse else 3
        value["source"] = (
            "docker-inspect-all-running-containers-prelaunch-v4" if sparse else
            "docker-inspect-all-running-containers-prelaunch-v3"
        )
        try:
            client_cpu, orchestrator_cpu = capture_scheduler_cpus()
        except ValueError:
            client_cpu, orchestrator_cpu = -1, -1
        value["protected_cpus"] = [client_cpu, orchestrator_cpu]
        if sparse:
            value["available_cpus"] = []
        value["overlapping_container_ids_by_cpu"] = {
            str(client_cpu): [], str(orchestrator_cpu): []
        }
        value["verified_scope"] = (
            "all running Docker containers at prelaunch; every container must carry the "
            f"qcsd-lab owner label and avoid protected logical CPUs {client_cpu} and {orchestrator_cpu}"
        )
        return value
    if capture_scheduler_contract() == BUFLO_ETF_SCHEDULER_CONTRACT:
        return _unavailable_host_partition_v2(reason)
    return _unavailable_host_partition_v1(reason)


def _load_host_partition() -> dict[str, Any]:
    supplied_file = os.environ.get(CAPTURE_SCHEDULER_HOST_FILE_ENV)
    supplied_digest = os.environ.get(CAPTURE_SCHEDULER_HOST_SHA256_ENV)
    encoded = os.environ.get(CAPTURE_SCHEDULER_HOST_ENV)
    if supplied_file is not None or supplied_digest is not None:
        try:
            if encoded or not supplied_file or not _docker_id(supplied_digest):
                raise ValueError("host partition file requires its sole, explicit SHA256 binding")
            path = Path(supplied_file)
            if path.is_symlink() or not path.is_file():
                raise ValueError("host partition file is absent or a symlink")
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != supplied_digest:
                raise ValueError("host partition file SHA256 changed")
            value = json.loads(raw)
            if capture_scheduler_contract() != PORTABLE_ETF_SCHEDULER_CONTRACT_V4 or not _host_partition_peer_valid(value):
                raise ValueError("host partition file is not the prospective peer contract")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            return _unavailable_host_partition(f"invalid host partition file: {error}")
        return dict(value)
    if not encoded:
        return _unavailable_host_partition(
            f"{CAPTURE_SCHEDULER_HOST_ENV} was not supplied by the Docker launcher"
        )
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        return _unavailable_host_partition(f"invalid host partition receipt: {error}")
    if not _host_partition_valid(value):
        return _unavailable_host_partition("host partition receipt failed validation")
    return dict(value)


def _read_cpu_stat(paths: tuple[Path, ...]) -> dict[str, Any]:
    errors: list[str] = []
    for path in paths:
        try:
            lines = path.read_text(encoding="ascii").splitlines()
        except OSError as error:
            errors.append(f"{path}: {error.strerror or type(error).__name__}")
            continue
        counters: dict[str, int] = {}
        try:
            for line in lines:
                key, separator, raw = line.partition(" ")
                if not separator or not key or not raw.isdecimal() or key in counters:
                    raise ValueError("malformed or duplicate counter")
                counters[key] = int(raw)
        except ValueError as error:
            errors.append(f"{path}: {error}")
            continue
        duration_key = next(
            (key for key in ("throttled_usec", "throttled_time") if key in counters), None
        )
        if "nr_throttled" not in counters or duration_key is None:
            errors.append(f"{path}: required throttling counters are absent")
            continue
        return {
            "available": True,
            "path": str(path),
            "unavailable_reason": None,
            "throttled_duration_key": duration_key,
            "throttled_duration_unit": (
                "microseconds" if duration_key == "throttled_usec" else "nanoseconds"
            ),
            "counters": counters,
        }
    return {
        "available": False,
        "path": None,
        "unavailable_reason": "; ".join(errors) or "no cgroup cpu.stat path configured",
        "throttled_duration_key": None,
        "throttled_duration_unit": None,
        "counters": None,
    }


def _read_cpu_steal(proc_root: Path, client_cpu: int = CAPTURE_CLIENT_CPU) -> dict[str, Any]:
    path = proc_root / "stat"
    try:
        lines = path.read_text(encoding="ascii").splitlines()
        line = next(line for line in lines if line.startswith(f"cpu{client_cpu} "))
        fields = line.split()[1:]
        if len(fields) < 8 or any(not field.isdecimal() for field in fields):
            raise ValueError("per-CPU stat lacks the Linux steal field")
        ticks_per_second = os.sysconf("SC_CLK_TCK")
        if type(ticks_per_second) is not int or ticks_per_second <= 0:
            raise ValueError("SC_CLK_TCK is unavailable")
    except (OSError, StopIteration, ValueError) as error:
        return {
            "available": False,
            "path": str(path),
            "unavailable_reason": str(error),
            "clock_ticks_per_second": None,
            "steal_ticks": None,
        }
    return {
        "available": True,
        "path": str(path),
        "unavailable_reason": None,
        "clock_ticks_per_second": ticks_per_second,
        "steal_ticks": int(fields[7]),
    }


def _stat_process_group(path: Path) -> int:
    raw = path.read_text(encoding="ascii")
    marker = raw.rfind(") ")
    if marker < 0:
        raise ValueError("task stat lacks a delimited command name")
    suffix = raw[marker + 2 :].split()
    if len(suffix) < 3 or not suffix[2].isdecimal():
        raise ValueError("task stat lacks a process-group identifier")
    return int(suffix[2])


class CaptureSchedulerMonitor:
    """Observe guest-visible hazards without scheduling work on the client CPU."""

    def __init__(
        self,
        *,
        proc_root: Path = _PROC_ROOT,
        cgroup_cpu_stat_paths: tuple[Path, ...] = _CGROUP_CPU_STAT_PATHS,
        interval_us: int = CAPTURE_SCHEDULER_MONITOR_INTERVAL_US,
        host_partition: Mapping[str, Any] | None = None,
    ) -> None:
        if type(interval_us) is not int or interval_us <= 0:
            raise ValueError("scheduler monitor interval must be a positive integer")
        self._proc_root = proc_root
        self._cgroup_paths = cgroup_cpu_stat_paths
        self._interval_us = interval_us
        self._contract = capture_scheduler_contract() or CAPTURE_SCHEDULER_CONTRACT
        self._client_cpu, self._orchestrator_cpu = capture_scheduler_cpus(self._contract)
        self._host_partition = dict(host_partition or _load_host_partition())
        self._cpu_stat_before = _read_cpu_stat(self._cgroup_paths)
        self._steal_before = _read_cpu_steal(self._proc_root, self._client_cpu)
        self._pid_namespace_inode = self._namespace_inode()
        self._expected_process_group_id: int | None = None
        self._expected_task_observed = False
        self._sample_count = 0
        self._visible_tasks_max = 0
        self._client_cpu_tasks_max = 0
        self._expected_tasks_max = 0
        self._unexpected: dict[tuple[int, int], dict[str, Any]] = {}
        self._pair_escapes: dict[tuple[int, int], dict[str, Any]] = {}
        self._overflowed_pair_escapes = False
        self._peer = self._host_partition.get("schema_version") == 5
        self._scan_errors: list[str] = []
        self._overflowed_unexpected = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._finished = False
        self._scan_once()

    def _namespace_inode(self) -> int | None:
        try:
            return (self._proc_root / "self/ns/pid").stat().st_ino
        except OSError:
            return None

    def process_started(self, pid: int) -> None:
        """Bind the one measured process group and begin periodic observation."""

        if self._expected_process_group_id is not None or self._finished:
            raise ValueError("scheduler monitor can observe exactly one client process")
        if type(pid) is not int or pid <= 0:
            raise ValueError("measured process-group identifier is invalid")
        self._expected_process_group_id = pid
        self._scan_once()
        self._thread = threading.Thread(
            target=self._monitor,
            name="qcsd-cpu-partition-monitor",
            daemon=True,
        )
        self._thread.start()

    def _monitor(self) -> None:
        try:
            while not self._stop.wait(self._interval_us / 1_000_000):
                self._scan_once()
        except BaseException as error:  # noqa: BLE001 - thread failure must be receipted.
            self._record_scan_error(
                f"scheduler monitor thread failed: {type(error).__name__}: {error}"
            )

    def _record_scan_error(self, message: str) -> None:
        bounded = message[:512]
        if bounded not in self._scan_errors and len(self._scan_errors) < _MAX_RECORDED_SCAN_ERRORS:
            self._scan_errors.append(bounded)

    def _scan_once(self) -> None:
        visible = 0
        eligible = 0
        expected = 0
        try:
            process_paths = tuple(self._proc_root.glob("[0-9]*"))
        except OSError as error:
            self._record_scan_error(f"cannot enumerate {self._proc_root}: {error}")
            self._sample_count += 1
            return
        for process_path in process_paths:
            task_root = process_path / "task"
            try:
                task_paths = tuple(task_root.glob("[0-9]*"))
            except OSError as error:
                self._record_scan_error(f"cannot enumerate {task_root}: {error}")
                continue
            for task_path in task_paths:
                try:
                    tid = int(task_path.name)
                    status_lines = (task_path / "status").read_text(encoding="ascii").splitlines()
                    selected = {
                        key: value.strip()
                        for line in status_lines
                        for key, separator, value in (line.partition(":"),)
                        if separator and key in {"Name", "Tgid", "Cpus_allowed_list"}
                    }
                    tgid = int(selected["Tgid"])
                    cpus = _cpu_list(selected["Cpus_allowed_list"])
                    process_group = _stat_process_group(task_path / "stat")
                except FileNotFoundError:
                    continue
                except (KeyError, OSError, ValueError) as error:
                    self._record_scan_error(
                        f"cannot inspect task {task_path.name}: {type(error).__name__}: {error}"
                    )
                    continue
                visible += 1
                if self._peer and not cpus.issubset({self._client_cpu, self._orchestrator_cpu}):
                    key = (tgid, tid)
                    if len(self._pair_escapes) < _MAX_RECORDED_TASKS:
                        self._pair_escapes.setdefault(key, {
                            "tgid": tgid, "tid": tid, "name": selected.get("Name", ""),
                            "process_group_id": process_group, "allowed_cpus": sorted(cpus),
                        })
                    else:
                        self._overflowed_pair_escapes = True
                if self._client_cpu not in cpus:
                    continue
                eligible += 1
                if process_group == self._expected_process_group_id:
                    expected += 1
                    self._expected_task_observed = True
                    continue
                key = (tgid, tid)
                if len(self._unexpected) < _MAX_RECORDED_TASKS:
                    self._unexpected.setdefault(
                        key,
                        {
                            "tgid": tgid,
                            "tid": tid,
                            "name": selected.get("Name", ""),
                            "process_group_id": process_group,
                            "allowed_cpus": sorted(cpus),
                        },
                    )
                else:
                    self._overflowed_unexpected = True
        self._sample_count += 1
        self._visible_tasks_max = max(self._visible_tasks_max, visible)
        self._client_cpu_tasks_max = max(self._client_cpu_tasks_max, eligible)
        self._expected_tasks_max = max(self._expected_tasks_max, expected)

    def finish(self) -> dict[str, Any]:
        """Stop monitoring and return the immutable per-attempt evidence value."""

        if self._finished:
            raise ValueError("scheduler monitor evidence was already finalised")
        self._finished = True
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self._interval_us / 100_000))
            if self._thread.is_alive():
                self._record_scan_error("scheduler monitor thread did not terminate")
        try:
            self._scan_once()
        except BaseException as error:  # noqa: BLE001 - final failure must be receipted.
            self._record_scan_error(
                f"scheduler monitor final scan failed: {type(error).__name__}: {error}"
            )
        cpu_stat_after = _read_cpu_stat(self._cgroup_paths)
        steal_after = _read_cpu_steal(self._proc_root, self._client_cpu)
        cpu_stat = _cpu_stat_delta(self._cpu_stat_before, cpu_stat_after)
        steal = _steal_delta(self._steal_before, steal_after, self._client_cpu)
        monitor = {
            "source": "procfs-task-affinity-sampled-v1",
            "scope": "tasks visible in the collection container PID namespace",
            "client_cpu": self._client_cpu,
            "sampling_interval_us": self._interval_us,
            "samples": self._sample_count,
            "pid_namespace_inode": self._pid_namespace_inode,
            "expected_process_group_id": self._expected_process_group_id,
            "expected_client_cpu_task_observed": self._expected_task_observed,
            "visible_tasks_max": self._visible_tasks_max,
            "client_cpu_eligible_tasks_max": self._client_cpu_tasks_max,
            "expected_client_cpu_tasks_max": self._expected_tasks_max,
            "unexpected_client_cpu_tasks": [
                self._unexpected[key] for key in sorted(self._unexpected)
            ],
            "unexpected_task_receipt_overflow": self._overflowed_unexpected,
            "scan_errors": list(self._scan_errors),
        }
        if self._peer:
            monitor.update({
                "protected_cpus": [self._client_cpu, self._orchestrator_cpu],
                "unexpected_pair_escape_tasks": [self._pair_escapes[key] for key in sorted(self._pair_escapes)],
                "pair_escape_task_receipt_overflow": self._overflowed_pair_escapes,
            })
        portable = self._contract == PORTABLE_ETF_SCHEDULER_CONTRACT
        sparse = self._contract == PORTABLE_ETF_SCHEDULER_CONTRACT_V4
        kernel_timed = self._contract in {
            BUFLO_ETF_SCHEDULER_CONTRACT,
            PORTABLE_ETF_SCHEDULER_CONTRACT,
            PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
        }
        expected_partition_schema = 5 if self._peer else (4 if sparse else (3 if portable else (2 if kernel_timed else 1)))
        declared_workers = self._host_partition.get("declared_workers", [])
        measured_worker = next((
            worker for worker in (declared_workers if isinstance(declared_workers, list) else [])
            if isinstance(worker, Mapping) and worker.get("id") == self._host_partition.get("measured_container_id")
        ), {}) if self._peer else {}
        valid = bool(
            _host_partition_valid(self._host_partition)
            and self._host_partition.get("schema_version") == expected_partition_schema
            and (
                not (portable or sparse) or self._peer
                or self._host_partition.get("protected_cpus")
                == [self._client_cpu, self._orchestrator_cpu]
            )
            and (
                not self._peer or sparse
                and [measured_worker.get("client_cpu"), measured_worker.get("orchestrator_cpu")]
                == [self._client_cpu, self._orchestrator_cpu]
                and not self._pair_escapes and not self._overflowed_pair_escapes
            )
            and cpu_stat["available"] is True
            and cpu_stat["nr_throttled_delta"] == 0
            and cpu_stat["throttled_duration_delta"] == 0
            and (steal["available"] is False or steal["steal_ticks_delta"] == 0)
            and self._expected_process_group_id is not None
            and self._expected_task_observed
            and self._sample_count >= 3
            and not self._unexpected
            and not self._overflowed_unexpected
            and not self._scan_errors
        )
        verified_scope = [
            f"measured process-group eligibility for logical CPU {self._client_cpu} in the collection PID namespace",
            "collection-cgroup CPU throttling counters over the measured client interval",
            f"guest-visible logical CPU {self._client_cpu} steal ticks over the measured client interval when exposed",
            (
                "all running Docker container cpusets at host prelaunch, with every container "
                f"QCSD-owned and logical CPUs {self._client_cpu} and {self._orchestrator_cpu} protected"
                if kernel_timed
                else (
                    "all running Docker container cpusets at host prelaunch, with every "
                    "container QCSD-owned"
                )
            ),
        ]
        if self._peer:
            verified_scope[-1] = _peer_scope(self._host_partition)
            verified_scope.append("visible task affinities stay within the declared measured worker CPU pair")
        return {
            "schema_version": (
                PEER_SCHEDULER_RUNTIME_SCHEMA_VERSION if self._peer else
                PORTABLE_ETF_SCHEDULER_RUNTIME_V4_SCHEMA_VERSION if sparse else
                PORTABLE_ETF_SCHEDULER_RUNTIME_SCHEMA_VERSION if portable else
                BUFLO_ETF_SCHEDULER_RUNTIME_SCHEMA_VERSION if kernel_timed else
                CAPTURE_SCHEDULER_RUNTIME_SCHEMA_VERSION
            ),
            "source": (
                PEER_SCHEDULER_RUNTIME_SOURCE if self._peer else
                PORTABLE_ETF_SCHEDULER_RUNTIME_V4_SOURCE if sparse else
                PORTABLE_ETF_SCHEDULER_RUNTIME_SOURCE if portable else
                BUFLO_ETF_SCHEDULER_RUNTIME_SOURCE if kernel_timed else
                CAPTURE_SCHEDULER_RUNTIME_SOURCE
            ),
            "contract": self._contract,
            "client_cpu": self._client_cpu,
            "orchestrator_cpu": self._orchestrator_cpu,
            "cgroup_cpu_stat": cpu_stat,
            "proc_stat_steal": steal,
            "guest_task_monitor": monitor,
            "host_partition": self._host_partition,
            "verified_scope": verified_scope,
            "unavailable_scope": [
                "non-container host processes",
                "the measured client container itself, whose cpuset is bound separately by the launch contract",
                "host interrupt handling and kernel work not represented as visible tasks",
                "host-kernel and hypervisor physical-CPU placement or isolation",
                "Docker container starts or cpuset changes after the host prelaunch observation",
            ],
            "valid": valid,
        }


def _cpu_stat_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    available = bool(
        before.get("available") is True
        and after.get("available") is True
        and before.get("path") == after.get("path")
        and before.get("throttled_duration_key") == after.get("throttled_duration_key")
        and isinstance(before.get("counters"), Mapping)
        and isinstance(after.get("counters"), Mapping)
        and set(before["counters"]) == set(after["counters"])
    )
    unavailable = {
        "available": False,
        "scope": "entire collection container cgroup, not the client process alone",
        "path": before.get("path") or after.get("path"),
        "unavailable_reason": (
            before.get("unavailable_reason")
            or after.get("unavailable_reason")
            or "cgroup cpu.stat changed shape during observation"
        ),
        "throttled_duration_key": None,
        "throttled_duration_unit": None,
        "before": None,
        "after": None,
        "delta": None,
        "nr_throttled_delta": None,
        "throttled_duration_delta": None,
    }
    if not available:
        return unavailable
    before_counters = dict(before["counters"])
    after_counters = dict(after["counters"])
    if any(after_counters[key] < value for key, value in before_counters.items()):
        return {**unavailable, "unavailable_reason": "cgroup cpu.stat counters decreased"}
    delta = {key: after_counters[key] - value for key, value in before_counters.items()}
    duration_key = before["throttled_duration_key"]
    return {
        "available": True,
        "scope": "entire collection container cgroup, not the client process alone",
        "path": before["path"],
        "unavailable_reason": None,
        "throttled_duration_key": duration_key,
        "throttled_duration_unit": before["throttled_duration_unit"],
        "before": before_counters,
        "after": after_counters,
        "delta": delta,
        "nr_throttled_delta": delta["nr_throttled"],
        "throttled_duration_delta": delta[duration_key],
    }


def _steal_delta(
    before: Mapping[str, Any], after: Mapping[str, Any], client_cpu: int = CAPTURE_CLIENT_CPU
) -> dict[str, Any]:
    available = bool(
        before.get("available") is True
        and after.get("available") is True
        and before.get("path") == after.get("path")
        and before.get("clock_ticks_per_second") == after.get("clock_ticks_per_second")
        and _uint(before.get("steal_ticks"))
        and _uint(after.get("steal_ticks"))
        and after["steal_ticks"] >= before["steal_ticks"]
    )
    if not available:
        return {
            "available": False,
            "scope": f"guest-visible aggregate for logical CPU {client_cpu}, not client-process attribution",
            "path": before.get("path") or after.get("path"),
            "unavailable_reason": (
                before.get("unavailable_reason")
                or after.get("unavailable_reason")
                or "per-CPU steal counters changed incompatibly during observation"
            ),
            "clock_ticks_per_second": None,
            "before_steal_ticks": None,
            "after_steal_ticks": None,
            "steal_ticks_delta": None,
        }
    return {
        "available": True,
        "scope": f"guest-visible aggregate for logical CPU {client_cpu}, not client-process attribution",
        "path": before["path"],
        "unavailable_reason": None,
        "clock_ticks_per_second": before["clock_ticks_per_second"],
        "before_steal_ticks": before["steal_ticks"],
        "after_steal_ticks": after["steal_ticks"],
        "steal_ticks_delta": after["steal_ticks"] - before["steal_ticks"],
    }


def capture_scheduler_runtime_evidence_valid(value: Any) -> bool:
    """Validate current per-attempt scheduler evidence without accepting history aliases."""

    expected_keys = {
        "schema_version",
        "source",
        "contract",
        "client_cpu",
        "orchestrator_cpu",
        "cgroup_cpu_stat",
        "proc_stat_steal",
        "guest_task_monitor",
        "host_partition",
        "verified_scope",
        "unavailable_scope",
        "valid",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        return False
    contract = value.get("contract")
    if contract not in {
        CAPTURE_SCHEDULER_CONTRACT,
        BUFLO_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    }:
        return False
    portable = contract == PORTABLE_ETF_SCHEDULER_CONTRACT
    sparse = contract == PORTABLE_ETF_SCHEDULER_CONTRACT_V4
    kernel_timed = contract in {
        BUFLO_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT,
        PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    }
    host_partition = value.get("host_partition")
    peer = isinstance(host_partition, Mapping) and host_partition.get("schema_version") == 5
    if peer and not sparse:
        return False
    if portable or sparse:
        if not _host_partition_valid(host_partition):
            return False
        if peer:
            worker = next(worker for worker in host_partition["declared_workers"] if worker["id"] == host_partition["measured_container_id"])
            client_cpu, orchestrator_cpu = worker["client_cpu"], worker["orchestrator_cpu"]
        elif sparse:
            client_cpu, orchestrator_cpu = host_partition["available_cpus"][-2:]
        else:
            ncpu = host_partition["docker_ncpu"]
            client_cpu, orchestrator_cpu = ncpu - 2, ncpu - 1
    else:
        client_cpu, orchestrator_cpu = CAPTURE_CLIENT_CPU, CAPTURE_ORCHESTRATOR_CPU
    expected_schema = (
        PEER_SCHEDULER_RUNTIME_SCHEMA_VERSION if peer else
        PORTABLE_ETF_SCHEDULER_RUNTIME_V4_SCHEMA_VERSION if sparse else
        PORTABLE_ETF_SCHEDULER_RUNTIME_SCHEMA_VERSION if portable else
        BUFLO_ETF_SCHEDULER_RUNTIME_SCHEMA_VERSION if kernel_timed else
        CAPTURE_SCHEDULER_RUNTIME_SCHEMA_VERSION
    )
    expected_source = (
        PEER_SCHEDULER_RUNTIME_SOURCE if peer else
        PORTABLE_ETF_SCHEDULER_RUNTIME_V4_SOURCE if sparse else
        PORTABLE_ETF_SCHEDULER_RUNTIME_SOURCE if portable else
        BUFLO_ETF_SCHEDULER_RUNTIME_SOURCE if kernel_timed else
        CAPTURE_SCHEDULER_RUNTIME_SOURCE
    )
    expected_partition_schema = 5 if peer else (4 if sparse else (3 if portable else (2 if kernel_timed else 1)))
    expected_verified_scope = [
        f"measured process-group eligibility for logical CPU {client_cpu} in the collection PID namespace",
        "collection-cgroup CPU throttling counters over the measured client interval",
        f"guest-visible logical CPU {client_cpu} steal ticks over the measured client interval when exposed",
        (
            "all running Docker container cpusets at host prelaunch, with every container "
            f"QCSD-owned and logical CPUs {client_cpu} and {orchestrator_cpu} protected"
            if kernel_timed
            else (
                "all running Docker container cpusets at host prelaunch, with every "
                "container QCSD-owned"
            )
        ),
    ]
    if peer:
        expected_verified_scope[-1] = _peer_scope(host_partition)
        expected_verified_scope.append("visible task affinities stay within the declared measured worker CPU pair")
    cpu_stat = value.get("cgroup_cpu_stat")
    steal = value.get("proc_stat_steal")
    monitor = value.get("guest_task_monitor")
    if (
        value.get("schema_version") != expected_schema
        or value.get("source") != expected_source
        or value.get("client_cpu") != client_cpu
        or value.get("orchestrator_cpu") != orchestrator_cpu
        or value.get("valid") is not True
        or not _host_partition_valid(host_partition)
        or value["host_partition"].get("schema_version") != expected_partition_schema
        or not isinstance(cpu_stat, Mapping)
        or set(cpu_stat) != _CPU_STAT_EVIDENCE_KEYS
        or cpu_stat.get("available") is not True
        or cpu_stat.get("scope")
        != "entire collection container cgroup, not the client process alone"
        or cpu_stat.get("unavailable_reason") is not None
        or cpu_stat.get("nr_throttled_delta") != 0
        or cpu_stat.get("throttled_duration_delta") != 0
        or not isinstance(steal, Mapping)
        or set(steal) != _STEAL_EVIDENCE_KEYS
        or steal.get("scope")
        != f"guest-visible aggregate for logical CPU {client_cpu}, not client-process attribution"
        or not isinstance(monitor, Mapping)
        or set(monitor) != (_PEER_TASK_MONITOR_KEYS if peer else _TASK_MONITOR_KEYS)
        or monitor.get("source") != "procfs-task-affinity-sampled-v1"
        or monitor.get("scope") != "tasks visible in the collection container PID namespace"
        or monitor.get("client_cpu") != client_cpu
        or not _uint(monitor.get("sampling_interval_us"))
        or not _uint(monitor.get("samples"))
        or monitor["samples"] < 3
        or not _uint(monitor.get("expected_process_group_id"))
        or monitor["expected_process_group_id"] == 0
        or monitor.get("expected_client_cpu_task_observed") is not True
        or not _uint(monitor.get("visible_tasks_max"))
        or not _uint(monitor.get("client_cpu_eligible_tasks_max"))
        or not _uint(monitor.get("expected_client_cpu_tasks_max"))
        or monitor["expected_client_cpu_tasks_max"] < 1
        or monitor.get("unexpected_client_cpu_tasks") != []
        or monitor.get("unexpected_task_receipt_overflow") is not False
        or monitor.get("scan_errors") != []
        or peer and (
            monitor.get("protected_cpus") != [client_cpu, orchestrator_cpu]
            or monitor.get("unexpected_pair_escape_tasks") != []
            or monitor.get("pair_escape_task_receipt_overflow") is not False
        )
        or value.get("verified_scope") != expected_verified_scope
        or value.get("unavailable_scope")
        != [
            "non-container host processes",
            "the measured client container itself, whose cpuset is bound separately by the launch contract",
            "host interrupt handling and kernel work not represented as visible tasks",
            "host-kernel and hypervisor physical-CPU placement or isolation",
            "Docker container starts or cpuset changes after the host prelaunch observation",
        ]
    ):
        return False
    before = cpu_stat.get("before")
    after = cpu_stat.get("after")
    delta = cpu_stat.get("delta")
    duration_key = cpu_stat.get("throttled_duration_key")
    if (
        not isinstance(cpu_stat.get("path"), str)
        or not cpu_stat["path"]
        or duration_key not in {"throttled_usec", "throttled_time"}
        or cpu_stat.get("throttled_duration_unit")
        != ("microseconds" if duration_key == "throttled_usec" else "nanoseconds")
        or not isinstance(before, Mapping)
        or not isinstance(after, Mapping)
        or not isinstance(delta, Mapping)
        or set(before) != set(after)
        or set(before) != set(delta)
        or "nr_throttled" not in before
        or duration_key not in before
        or any(not _uint(item) for item in (*before.values(), *after.values(), *delta.values()))
        or any(after[key] - before[key] != delta[key] for key in before)
        or cpu_stat["nr_throttled_delta"] != delta["nr_throttled"]
        or cpu_stat["throttled_duration_delta"] != delta[duration_key]
    ):
        return False
    namespace_inode = monitor.get("pid_namespace_inode")
    if namespace_inode is not None and (not _uint(namespace_inode) or namespace_inode == 0):
        return False
    if steal.get("available") is True:
        if (
            steal.get("unavailable_reason") is not None
            or steal.get("steal_ticks_delta") != 0
            or not _uint(steal.get("before_steal_ticks"))
            or not _uint(steal.get("after_steal_ticks"))
            or not _uint(steal.get("clock_ticks_per_second"))
            or steal["clock_ticks_per_second"] == 0
            or steal["after_steal_ticks"] - steal["before_steal_ticks"]
            != steal["steal_ticks_delta"]
            or not isinstance(steal.get("path"), str)
            or not steal["path"]
        ):
            return False
    elif (
        steal.get("available") is not False
        or not isinstance(steal.get("unavailable_reason"), str)
        or not steal["unavailable_reason"]
        or steal.get("clock_ticks_per_second") is not None
        or steal.get("before_steal_ticks") is not None
        or steal.get("after_steal_ticks") is not None
        or steal.get("steal_ticks_delta") is not None
    ):
        return False
    return True
