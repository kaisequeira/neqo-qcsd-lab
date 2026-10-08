from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab.capture_session import _process_scheduler_receipt_valid
from qcsd_lab.kernel_tx import _process_scheduler_valid as _kernel_process_scheduler_valid
from qcsd_lab.process_scheduler import (
    CAPTURE_CLIENT_CPU,
    PORTABLE_ETF_SCHEDULER_CONTRACT,
    PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    PEER_HOST_PARTITION_CONTRACT,
    RESOURCE_STUDY_PEER_HOST_PARTITION_CONTRACT,
    CaptureSchedulerMonitor,
    _host_partition_valid,
    _load_host_partition,
    build_peer_host_partition,
    capture_scheduler_launch_prefix,
    capture_scheduler_runtime_evidence_valid,
)
from tests.scheduler_fixtures import process_scheduler_receipt


def _resource_peer_inputs(count: int, cpu_count: int) -> tuple[list[dict], list[dict], dict[str, str]]:
    workers = [{"id": f"{index + 1:064x}", "name": f"resource-{index}", "image_id": "sha256:" + "d" * 64,
        "client_cpu": 2 * index + 1, "orchestrator_cpu": 2 * index + 2} for index in range(count)]
    inspected = [{"Id": worker["id"], "Name": "/" + worker["name"], "Image": worker["image_id"],
        "Config": {"Labels": {"org.qcsd.owner": "qcsd-lab", "org.qcsd.role": "capture"}},
        "HostConfig": {"CpusetCpus": f'{worker["client_cpu"]},{worker["orchestrator_cpu"]}'},
        "State": {"Status": "created", "Running": False}} for worker in workers]
    residual = sorted(set(range(cpu_count)) - {cpu for worker in workers for cpu in (worker["client_cpu"], worker["orchestrator_cpu"])})
    inspected.append({"Id": "f" * 64, "Name": "/resource-observer", "Image": "sha256:" + "e" * 64,
        "Config": {"Labels": {"org.qcsd.owner": "qcsd-lab", "org.qcsd.role": "observer"}},
        "HostConfig": {"CpusetCpus": ",".join(map(str, residual))}, "State": {"Status": "running", "Running": True}})
    return inspected, workers, {"resource-observer": "f" * 64}


@pytest.mark.parametrize("count,cpus", [(2, 6), (4, 9)])
def test_resource_study_peer_partition_uses_actual_capacity(count: int, cpus: int) -> None:
    inspected, workers, sidecars = _resource_peer_inputs(count, cpus)
    for worker in workers:
        proof = build_peer_host_partition(inspected, list(range(cpus)), workers, sidecars,
            worker["id"], docker_ncpu=cpus, resource_study=True)
        assert proof["peer_contract"] == RESOURCE_STUDY_PEER_HOST_PARTITION_CONTRACT
        assert _host_partition_valid(proof)
        assert len(proof["protected_cpus"]) == 2 * count


@pytest.mark.parametrize("failure", ["eight-cpus", "overlap", "foreign", "missing", "single-worker", "unregistered-contract", "downgraded-contract"])
def test_resource_study_peer_partition_refuses_capacity_or_identity_failure(failure: str) -> None:
    cpus = 8 if failure == "eight-cpus" else 9
    count = 1 if failure == "single-worker" else 4
    inspected, workers, sidecars = _resource_peer_inputs(count, cpus)
    if failure == "overlap": workers[1]["client_cpu"] = workers[0]["client_cpu"]
    elif failure == "foreign": inspected[-1]["Config"]["Labels"]["org.qcsd.owner"] = "foreign"
    elif failure == "missing": inspected.pop(1)
    if failure.endswith("contract"):
        proof = build_peer_host_partition(inspected, list(range(cpus)), workers, sidecars,
            workers[0]["id"], docker_ncpu=cpus, resource_study=True)
        proof["peer_contract"] = "unregistered-resource-partition" if failure.startswith("unregistered") else PEER_HOST_PARTITION_CONTRACT
        assert not _host_partition_valid(proof)
    else:
        with pytest.raises(ValueError):
            build_peer_host_partition(inspected, list(range(cpus)), workers, sidecars,
                workers[0]["id"], docker_ncpu=cpus, resource_study=True)


def test_historical_peer_builder_still_requires_exactly_two_workers() -> None:
    inspected, workers, sidecars = _resource_peer_inputs(4, 9)
    with pytest.raises(ValueError, match="two-worker"):
        build_peer_host_partition(inspected, list(range(9)), workers, sidecars,
            workers[0]["id"], docker_ncpu=9)
    assert _peer_host_partition()["peer_contract"] == PEER_HOST_PARTITION_CONTRACT


@pytest.mark.parametrize("measured", [0, 3])
def test_resource_study_four_worker_runtime_keeps_native_v4_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, measured: int) -> None:
    inspected, workers, sidecars = _resource_peer_inputs(4, 9)
    proof = build_peer_host_partition(inspected, list(range(9)), workers, sidecars,
        workers[measured]["id"], docker_ncpu=9, resource_study=True)
    worker = workers[measured]; client, helper = worker["client_cpu"], worker["orchestrator_cpu"]
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT_V4)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", str(client))
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", str(helper))
    proc_root, cpu_stat = _fixture(tmp_path)
    (proc_root / "1/task/1/status").write_text(f"Name:\torchestrator\nTgid:\t1\nCpus_allowed_list:\t{helper}\n", encoding="ascii")
    (proc_root / "stat").write_text(f"cpu{client} 1 2 3 4 5 6 7 0 0 0\n", encoding="ascii")
    monitor = CaptureSchedulerMonitor(proc_root=proc_root, cgroup_cpu_stat_paths=(cpu_stat,), interval_us=1_000_000, host_partition=proof)
    _write_task(proc_root, tgid=77, tid=77, process_group=77, cpus=str(client), name="neqo-qcsd-client")
    _write_task(proc_root, tgid=77, tid=78, process_group=77, cpus=str(helper), name="qcsd-etf-helper")
    monitor.process_started(77); evidence = monitor.finish()
    assert evidence["contract"] == PORTABLE_ETF_SCHEDULER_CONTRACT_V4
    assert capture_scheduler_runtime_evidence_valid(evidence)
    altered = copy.deepcopy(evidence); altered["host_partition"]["measured_container_id"] = workers[1 if measured == 0 else 2]["id"]
    assert not capture_scheduler_runtime_evidence_valid(altered)


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


def _peer_host_partition(measured: int = 0) -> dict:
    inspected, workers, sidecars = _peer_inputs()
    return build_peer_host_partition(
        inspected, [0, 2, 4, 7, 9], workers, sidecars,
        workers[measured]["id"], docker_ncpu=16,
    )


@pytest.mark.parametrize("measured", [0, 1])
def test_peer_partition_accepts_created_workers_and_declared_running_peer(measured: int) -> None:
    inspected, workers, sidecars = _peer_inputs()
    inspected[1 - measured]["State"] = {"Status": "running", "Running": True}
    proof = build_peer_host_partition(
        inspected, [0, 2, 4, 7, 9], workers, sidecars,
        workers[measured]["id"], docker_ncpu=16,
    )
    assert _host_partition_valid(proof)
    assert proof["overlapping_container_ids_by_cpu"]["7"] == ["b" * 64]
    assert proof["declared_workers"] == workers


@pytest.mark.parametrize("failure", [
    "wrong_image", "wrong_name", "cross_pair", "undeclared_protected",
    "undeclared_residual", "missing_peer", "wrong_sidecar_id", "sidecar_overlap",
    "unowned", "reused_worker_id", "insufficient_cpus", "stopped_peer",
])
def test_peer_builder_rejects_actual_identity_inventory_or_partition_failure(failure: str) -> None:
    inspected, workers, sidecars = _peer_inputs()
    available = [0, 2, 4, 7, 9]
    if failure == "wrong_image":
        inspected[1]["Image"] = "sha256:" + "f" * 64
    elif failure == "wrong_name":
        inspected[1]["Name"] = "/another-lane"
    elif failure == "cross_pair":
        inspected[1]["HostConfig"]["CpusetCpus"] = "4,7,9"
    elif failure.startswith("undeclared"):
        extra = copy.deepcopy(inspected[2])
        extra.update(Id="f" * 64, Name="/undeclared")
        extra["HostConfig"]["CpusetCpus"] = "4" if failure.endswith("protected") else "0"
        inspected.append(extra)
    elif failure == "missing_peer":
        inspected.pop(1)
    elif failure == "wrong_sidecar_id":
        sidecars["sidecar"] = "f" * 64
    elif failure == "sidecar_overlap":
        inspected[2]["HostConfig"]["CpusetCpus"] = "0,7"
    elif failure == "unowned":
        inspected[1]["Config"]["Labels"]["org.qcsd.owner"] = "other"
    elif failure == "reused_worker_id":
        workers[1]["id"] = workers[0]["id"]
    elif failure == "insufficient_cpus":
        available = [2, 4, 7, 9]
    elif failure == "stopped_peer":
        inspected[1]["State"] = {"Status": "exited", "Running": False}
    with pytest.raises(ValueError):
        build_peer_host_partition(
            inspected, available, workers, sidecars, workers[0]["id"], docker_ncpu=16,
        )


def test_peer_host_receipt_reopens_declared_overlap_and_measured_identity() -> None:
    proof = _peer_host_partition()
    for field, changed in [
        ("measured_container_id", "f" * 64),
        ("overlapping_container_ids_by_cpu", {"2": [], "4": [], "7": [], "9": []}),
        ("protected_cpus", [2, 4]),
    ]:
        altered = copy.deepcopy(proof)
        altered[field] = changed
        assert not _host_partition_valid(altered)


def test_peer_host_file_is_exact_hash_bound_and_has_one_delivery_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = _peer_host_partition()
    raw = json.dumps(proof).encode()
    path = tmp_path / "partition.json"
    path.write_bytes(raw)
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT_V4)
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_FILE", str(path))
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.delenv("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64", raising=False)
    assert _load_host_partition() == proof
    path.write_bytes(raw + b"\n")
    assert not _host_partition_valid(_load_host_partition())
    path.write_bytes(raw)
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64", "other")
    assert not _host_partition_valid(_load_host_partition())


def test_peer_launch_rejects_wrong_lane_before_client_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import resource

    raw = json.dumps(_peer_host_partition()).encode()
    path = tmp_path / "partition.json"
    path.write_bytes(raw)
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT_V4)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_FILE", str(path))
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.delenv("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64", raising=False)
    monkeypatch.setattr(os, "sched_getaffinity", lambda _pid: {4})
    monkeypatch.setattr(resource, "getrlimit", lambda _which: (1, 1))
    assert capture_scheduler_launch_prefix()[2] == "2"
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "7")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "9")
    with pytest.raises(ValueError, match="hash-bound peer partition"):
        capture_scheduler_launch_prefix()
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    path.write_bytes(raw + b"\n")
    with pytest.raises(ValueError, match="before client launch"):
        capture_scheduler_launch_prefix()
    monkeypatch.delenv("QCSD_CAPTURE_SCHEDULER_CONTRACT")
    with pytest.raises(ValueError, match="v4 Native scheduler contract"):
        capture_scheduler_launch_prefix()


@pytest.mark.parametrize("measured", [0, 1])
def test_peer_runtime_accepts_each_own_pair_with_unchanged_native_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, measured: int,
) -> None:
    proof = _peer_host_partition(measured)
    worker = proof["declared_workers"][measured]
    client, helper = worker["client_cpu"], worker["orchestrator_cpu"]
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT_V4)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", str(client))
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", str(helper))
    proc_root, cpu_stat = _fixture(tmp_path)
    (proc_root / "1/task/1/status").write_text(
        f"Name:\torchestrator\nTgid:\t1\nCpus_allowed_list:\t{helper}\n", encoding="ascii",
    )
    (proc_root / "stat").write_text(f"cpu{client} 1 2 3 4 5 6 7 0 0 0\n", encoding="ascii")
    monitor = CaptureSchedulerMonitor(
        proc_root=proc_root, cgroup_cpu_stat_paths=(cpu_stat,),
        interval_us=1_000_000, host_partition=proof,
    )
    _write_task(proc_root, tgid=77, tid=77, process_group=77, cpus=str(client), name="neqo-qcsd-client")
    _write_task(proc_root, tgid=77, tid=78, process_group=77, cpus=str(helper), name="qcsd-etf-helper")
    monitor.process_started(77)
    evidence = monitor.finish()
    assert evidence["schema_version"] == 5
    assert evidence["contract"] == PORTABLE_ETF_SCHEDULER_CONTRACT_V4
    assert capture_scheduler_runtime_evidence_valid(evidence)
    altered = copy.deepcopy(evidence)
    altered["host_partition"]["measured_container_id"] = proof["declared_workers"][1 - measured]["id"]
    assert not capture_scheduler_runtime_evidence_valid(altered)


@pytest.mark.parametrize("escaped_cpu", [0, 7, 9])
def test_peer_runtime_rejects_visible_helper_escape_and_prevents_false_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, escaped_cpu: int,
) -> None:
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT_V4)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    proc_root, cpu_stat = _fixture(tmp_path)
    (proc_root / "1/task/1/status").write_text("Name:\torchestrator\nTgid:\t1\nCpus_allowed_list:\t4\n", encoding="ascii")
    (proc_root / "stat").write_text("cpu2 1 2 3 4 5 6 7 0 0 0\n", encoding="ascii")
    monitor = CaptureSchedulerMonitor(
        proc_root=proc_root, cgroup_cpu_stat_paths=(cpu_stat,),
        interval_us=1_000_000, host_partition=_peer_host_partition(),
    )
    _write_task(proc_root, tgid=77, tid=77, process_group=77, cpus="2", name="neqo-qcsd-client")
    _write_task(proc_root, tgid=77, tid=78, process_group=77, cpus=str(escaped_cpu), name="qcsd-etf-helper")
    monitor.process_started(77)
    evidence = monitor.finish()
    assert evidence["valid"] is False
    assert evidence["guest_task_monitor"]["unexpected_pair_escape_tasks"][0]["tid"] == 78
    evidence["valid"] = True
    assert not capture_scheduler_runtime_evidence_valid(evidence)


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


def _host_partition_v3(ncpu: int) -> dict:
    client_cpu, helper_cpu = ncpu - 2, ncpu - 1
    receipt = _host_partition_v2()
    receipt.update(
        schema_version=3,
        source="docker-inspect-all-running-containers-prelaunch-v3",
        protected_cpus=[client_cpu, helper_cpu],
        docker_ncpu=ncpu,
        overlapping_container_ids_by_cpu={str(client_cpu): [], str(helper_cpu): []},
        verified_scope=(
            "all running Docker containers at prelaunch; every container must carry the "
            f"qcsd-lab owner label and avoid protected logical CPUs {client_cpu} and {helper_cpu}"
        ),
    )
    return receipt


def _host_partition_v4(available_cpus: list[int], ncpu: int = 8) -> dict:
    client_cpu, helper_cpu = available_cpus[-2:]
    receipt = _host_partition_v3(ncpu)
    receipt.update(
        schema_version=4,
        source="docker-inspect-all-running-containers-prelaunch-v4",
        available_cpus=available_cpus,
        protected_cpus=[client_cpu, helper_cpu],
        overlapping_container_ids_by_cpu={str(client_cpu): [], str(helper_cpu): []},
        verified_scope=(
            "all running Docker containers at prelaunch; every container must carry the "
            f"qcsd-lab owner label and avoid protected logical CPUs {client_cpu} and {helper_cpu}"
        ),
    )
    return receipt


@pytest.mark.parametrize("available_cpus", [[2, 4, 7], [4, 5, 6], [0, 1, 2]])
def test_sparse_partition_monitor_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, available_cpus: list[int]
) -> None:
    client_cpu, helper_cpu = available_cpus[-2:]
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT_V4)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", str(client_cpu))
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", str(helper_cpu))
    proc_root, cpu_stat = _fixture(tmp_path)
    (proc_root / "stat").write_text(
        f"cpu 1 2 3 4 5 6 7 0 0 0\ncpu{client_cpu} 1 2 3 4 5 6 7 0 0 0\n",
        encoding="ascii",
    )
    monitor = CaptureSchedulerMonitor(
        proc_root=proc_root,
        cgroup_cpu_stat_paths=(cpu_stat,),
        interval_us=1_000_000,
        host_partition=_host_partition_v4(available_cpus),
    )
    _write_task(
        proc_root,
        tgid=77,
        tid=77,
        process_group=77,
        cpus=str(client_cpu),
        name="neqo-qcsd-client",
    )
    monitor.process_started(77)
    evidence = monitor.finish()
    assert evidence["schema_version"] == 4
    assert capture_scheduler_runtime_evidence_valid(evidence)
    altered = copy.deepcopy(evidence)
    altered["host_partition"]["available_cpus"][-1] += 1
    assert not capture_scheduler_runtime_evidence_valid(altered)

    receipt = process_scheduler_receipt()
    receipt.update(
        affinity_cpus=[client_cpu],
        cgroup_effective_cpuset=(
            f"{client_cpu}-{helper_cpu}" if helper_cpu == client_cpu + 1
            else f"{client_cpu},{helper_cpu}"
        ),
        contract=PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
    )
    assert _process_scheduler_receipt_valid(
        receipt,
        expected_contract=PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
        allowed_capabilities=frozenset({"0000000000000000"}),
    )
    assert _kernel_process_scheduler_valid(receipt)
    receipt["cgroup_effective_cpuset"] = f"{client_cpu},{helper_cpu},99"
    assert not _process_scheduler_receipt_valid(
        receipt,
        expected_contract=PORTABLE_ETF_SCHEDULER_CONTRACT_V4,
        allowed_capabilities=frozenset({"0000000000000000"}),
    )


@pytest.mark.parametrize("ncpu", [3, 8])
def test_portable_partition_monitor_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ncpu: int
) -> None:
    client_cpu, helper_cpu = ncpu - 2, ncpu - 1
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", str(client_cpu))
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", str(helper_cpu))
    proc_root, cpu_stat = _fixture(tmp_path)
    (proc_root / "stat").write_text(
        f"cpu 1 2 3 4 5 6 7 0 0 0\ncpu{client_cpu} 1 2 3 4 5 6 7 0 0 0\n",
        encoding="ascii",
    )
    monitor = CaptureSchedulerMonitor(
        proc_root=proc_root,
        cgroup_cpu_stat_paths=(cpu_stat,),
        interval_us=1_000_000,
        host_partition=_host_partition_v3(ncpu),
    )
    _write_task(
        proc_root,
        tgid=77,
        tid=77,
        process_group=77,
        cpus=str(client_cpu),
        name="neqo-qcsd-client",
    )
    monitor.process_started(77)
    evidence = monitor.finish()
    assert evidence["schema_version"] == 3
    assert evidence["client_cpu"] == client_cpu
    assert evidence["orchestrator_cpu"] == helper_cpu
    assert capture_scheduler_runtime_evidence_valid(evidence)

    altered = copy.deepcopy(evidence)
    altered["host_partition"]["protected_cpus"] = [client_cpu, client_cpu]
    assert not capture_scheduler_runtime_evidence_valid(altered)


@pytest.mark.parametrize("ncpu", [3, 8])
def test_portable_client_process_receipt(ncpu: int) -> None:
    client_cpu, helper_cpu = ncpu - 2, ncpu - 1
    receipt = process_scheduler_receipt()
    receipt.update(
        affinity_cpus=[client_cpu],
        cgroup_effective_cpuset=f"{client_cpu}-{helper_cpu}",
        contract=PORTABLE_ETF_SCHEDULER_CONTRACT,
    )
    assert _process_scheduler_receipt_valid(
        receipt,
        expected_contract=PORTABLE_ETF_SCHEDULER_CONTRACT,
        allowed_capabilities=frozenset({"0000000000000000"}),
    )
    assert _kernel_process_scheduler_valid(receipt)

    receipt["cgroup_effective_cpuset"] = f"0-{helper_cpu}"
    assert not _process_scheduler_receipt_valid(
        receipt,
        expected_contract=PORTABLE_ETF_SCHEDULER_CONTRACT,
        allowed_capabilities=frozenset({"0000000000000000"}),
    )
    assert not _kernel_process_scheduler_valid(receipt)


@pytest.mark.parametrize("ncpu", [3, 8])
def test_portable_client_launch_prefix_uses_selected_cpu(
    monkeypatch: pytest.MonkeyPatch, ncpu: int
) -> None:
    import os
    import resource

    client_cpu, helper_cpu = ncpu - 2, ncpu - 1
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", PORTABLE_ETF_SCHEDULER_CONTRACT)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", str(client_cpu))
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", str(helper_cpu))
    monkeypatch.setattr(os, "sched_getaffinity", lambda _pid: {helper_cpu})
    monkeypatch.setattr(resource, "getrlimit", lambda _kind: (1, 1))
    prefix = capture_scheduler_launch_prefix()
    assert prefix[:3] == ["/usr/bin/taskset", "--cpu-list", str(client_cpu)]
    assert "--bounding-set=-all,+net_admin,+setpcap" in prefix


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
