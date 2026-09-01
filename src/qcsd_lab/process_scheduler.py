"""Fail-closed launch and runtime evidence for a measured study client."""

from __future__ import annotations

import base64
import binascii
import json
import os
import resource
import threading
from pathlib import Path
from typing import Any, Mapping

CAPTURE_SCHEDULER_CONTRACT = "qcsd-client-rr1-cpu10-v1"
CAPTURE_ORCHESTRATOR_CPU = 11
CAPTURE_CLIENT_CPU = 10
CAPTURE_SCHEDULER_RUNTIME_SCHEMA_VERSION = 1
CAPTURE_SCHEDULER_RUNTIME_SOURCE = "linux-cgroup-procfs-monitor-and-docker-host-prelaunch-v1"
CAPTURE_SCHEDULER_HOST_ENV = "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64"
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


def capture_scheduler_contract() -> str | None:
    """Return the one supported measured-client scheduler contract, if selected."""

    value = os.environ.get("QCSD_CAPTURE_SCHEDULER_CONTRACT")
    if value in {None, ""}:
        return None
    if value != CAPTURE_SCHEDULER_CONTRACT:
        raise ValueError(f"unsupported capture scheduler contract: {value}")
    return value


def capture_scheduler_launch_prefix() -> list[str]:
    """Fail closed on the container partition before elevating only the client."""

    if capture_scheduler_contract() is None:
        return []
    affinity = os.sched_getaffinity(0)
    if affinity != {CAPTURE_ORCHESTRATOR_CPU}:
        raise ValueError(
            f"capture scheduler parent must be confined to orchestrator CPU "
            f"{CAPTURE_ORCHESTRATOR_CPU}"
        )
    rtprio = resource.getrlimit(resource.RLIMIT_RTPRIO)
    if rtprio != (1, 1):
        raise ValueError("capture scheduler requires RLIMIT_RTPRIO soft/hard 1")
    return [
        "/usr/bin/taskset",
        "--cpu-list",
        str(CAPTURE_CLIENT_CPU),
        "/usr/bin/chrt",
        "--rr",
        "1",
        "/usr/bin/setpriv",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "--",
    ]


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


def _host_partition_valid(value: Any) -> bool:
    """Validate host Docker-inspect evidence supplied by the launcher."""

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


def _unavailable_host_partition(reason: str) -> dict[str, Any]:
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


def _load_host_partition() -> dict[str, Any]:
    encoded = os.environ.get(CAPTURE_SCHEDULER_HOST_ENV)
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


def _read_cpu_steal(proc_root: Path) -> dict[str, Any]:
    path = proc_root / "stat"
    try:
        lines = path.read_text(encoding="ascii").splitlines()
        line = next(line for line in lines if line.startswith(f"cpu{CAPTURE_CLIENT_CPU} "))
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
        self._host_partition = dict(host_partition or _load_host_partition())
        self._cpu_stat_before = _read_cpu_stat(self._cgroup_paths)
        self._steal_before = _read_cpu_steal(self._proc_root)
        self._pid_namespace_inode = self._namespace_inode()
        self._expected_process_group_id: int | None = None
        self._expected_task_observed = False
        self._sample_count = 0
        self._visible_tasks_max = 0
        self._client_cpu_tasks_max = 0
        self._expected_tasks_max = 0
        self._unexpected: dict[tuple[int, int], dict[str, Any]] = {}
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
                if CAPTURE_CLIENT_CPU not in cpus:
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
        steal_after = _read_cpu_steal(self._proc_root)
        cpu_stat = _cpu_stat_delta(self._cpu_stat_before, cpu_stat_after)
        steal = _steal_delta(self._steal_before, steal_after)
        monitor = {
            "source": "procfs-task-affinity-sampled-v1",
            "scope": "tasks visible in the collection container PID namespace",
            "client_cpu": CAPTURE_CLIENT_CPU,
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
        valid = bool(
            _host_partition_valid(self._host_partition)
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
        return {
            "schema_version": CAPTURE_SCHEDULER_RUNTIME_SCHEMA_VERSION,
            "source": CAPTURE_SCHEDULER_RUNTIME_SOURCE,
            "contract": CAPTURE_SCHEDULER_CONTRACT,
            "client_cpu": CAPTURE_CLIENT_CPU,
            "orchestrator_cpu": CAPTURE_ORCHESTRATOR_CPU,
            "cgroup_cpu_stat": cpu_stat,
            "proc_stat_steal": steal,
            "guest_task_monitor": monitor,
            "host_partition": self._host_partition,
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


def _steal_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
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
            "scope": "guest-visible aggregate for logical CPU 10, not client-process attribution",
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
        "scope": "guest-visible aggregate for logical CPU 10, not client-process attribution",
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
    cpu_stat = value.get("cgroup_cpu_stat")
    steal = value.get("proc_stat_steal")
    monitor = value.get("guest_task_monitor")
    if (
        value.get("schema_version") != CAPTURE_SCHEDULER_RUNTIME_SCHEMA_VERSION
        or value.get("source") != CAPTURE_SCHEDULER_RUNTIME_SOURCE
        or value.get("contract") != CAPTURE_SCHEDULER_CONTRACT
        or value.get("client_cpu") != CAPTURE_CLIENT_CPU
        or value.get("orchestrator_cpu") != CAPTURE_ORCHESTRATOR_CPU
        or value.get("valid") is not True
        or not _host_partition_valid(value.get("host_partition"))
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
        != "guest-visible aggregate for logical CPU 10, not client-process attribution"
        or not isinstance(monitor, Mapping)
        or set(monitor) != _TASK_MONITOR_KEYS
        or monitor.get("source") != "procfs-task-affinity-sampled-v1"
        or monitor.get("scope") != "tasks visible in the collection container PID namespace"
        or monitor.get("client_cpu") != CAPTURE_CLIENT_CPU
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
        or value.get("verified_scope")
        != [
            "measured process-group eligibility for logical CPU 10 in the collection PID namespace",
            "collection-cgroup CPU throttling counters over the measured client interval",
            "guest-visible logical CPU 10 steal ticks over the measured client interval when exposed",
            "all running Docker container cpusets at host prelaunch, with every container QCSD-owned",
        ]
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
