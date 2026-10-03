"""Bounded parallel control checks; Docker and traffic are never actuated."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_parallel_capture as parallel
from qcsd_lab.experiment import scheduler_runtime_receipt
from qcsd_lab.process_scheduler import CaptureSchedulerMonitor, capture_scheduler_runtime_evidence_valid
from tests.test_process_scheduler import _fixture, _peer_inputs, _write_task


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_B64",
                 "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_FILE",
                 "QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_SHA256"):
        monkeypatch.delenv(name, raising=False)
    runtime, execution, output = (tmp_path / name for name in ("runtime", "execution", "output"))
    for directory in (runtime, execution, output):
        directory.mkdir()
    project = Path(__file__).resolve().parents[1]
    for root in (runtime, execution):
        (root / "config/defense-params").mkdir(parents=True)
        for name in ("buflo-live.json", "buflo-live.json.provenance.json",
                     "cs-buflo-ctsp-live.json", "cs-buflo-ctsp-live.json.provenance.json"):
            (root / "config/defense-params" / name).write_bytes((project / "config/defense-params" / name).read_bytes())
    for path in (runtime / "qcsd-lab", execution / "qcsd-lab"):
        path.write_bytes(b"identical frozen launcher\n")
    client = runtime / "client"
    client.write_bytes(b"retained native client\n")
    source_path = runtime / "source.json"
    _write(source_path, {"lab_commit": "1" * 40, "lab_dirty": False,
                         "neqo_commit": "2" * 40, "neqo_pinned_commit": "2" * 40,
                         "neqo_dirty": False})
    campaigns = []
    for name in ("buflo", "cs-buflo"):
        path = execution / f"config/campaigns/{name}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        kind, parameter = (("buflo", "buflo-live.json") if name == "buflo"
                           else ("cs_buflo", "cs-buflo-ctsp-live.json"))
        path.write_text(yaml.safe_dump({"defenses": [{"name": name, "kind": kind,
            "parameters": "../defense-params/" + parameter}]}))
        campaigns.append({"path": str(path), "sha256": parallel.sha(path.read_bytes())})
    inspected, workers, sidecars = _peer_inputs()
    second = copy.deepcopy(inspected[-1])
    second.update(Id="f" * 64, Name="/sidecar-b")
    inspected.append(second)
    sidecars["sidecar-b"] = "f" * 64
    authority = {"schema_version": 1, "artifact_type": parallel.AUTHORITY_TYPE,
        "runtime": {"runtime_source_root": str(runtime), "module_root": str(runtime),
                    "execution_root": str(execution), "source_manifest": str(source_path),
                    "client_binary": str(client), "base_launcher": str(runtime / "qcsd-lab"),
                    "host_launcher": str(execution / "qcsd-lab"),
                    "collection_image_digest": workers[0]["image_id"]}, "campaigns": campaigns}
    path = tmp_path / "authority.json"
    _write(path, authority)
    digest = parallel.sha(path.read_bytes())
    workload = execution / "config/workloads/site.json"
    workload.parent.mkdir(parents=True)
    workload.write_bytes(b"bound multi-origin workload graph\n")
    preflight = {"authority_sha256": digest,
                 "approved_hostnames": ["example.com"], "campaigns": [{"name": "buflo"}, {"name": "cs-buflo"}],
                 "input_files": {str(workload): parallel.sha(workload.read_bytes())},
                 "formal_accepted_trace_count": 0, "scientific_credit": False}
    _write(output / "image-preflight.json", preflight)
    _write(output / "dns-pins.json", {"schema_version": 1, "campaign": "buflo", "hosts": [["example.com", "1.1.1.1"]]})
    actual = {"workers": workers, "sidecars": sidecars,
              "inspected_containers": inspected, "available_cpus": [0, 2, 4, 7, 9],
              "docker_ncpu": 16,
              "lane_resources": [{"router_id": "c" * 64, "network_id": "3" * 64},
                                 {"router_id": "f" * 64, "network_id": "4" * 64}]}
    return SimpleNamespace(path=path, authority=authority, digest=digest, runtime=runtime,
                           source_path=source_path, output=output, workload=workload, actual=actual)


def _released(context) -> None:
    parallel.initialize(context.path, context.output, context.digest, context.actual["available_cpus"])
    parallel.put(context.output / "actual-launch.json", context.actual)
    parallel.release(context.path, context.output, context.actual)


def test_authority_reopens_actual_paths_source_and_campaign_hashes(context) -> None:
    assert parallel.authority(context.path) == context.authority
    campaign = Path(context.authority["campaigns"][0]["path"])
    campaign.write_bytes(campaign.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="campaign binding"):
        parallel.authority(context.path)


@pytest.mark.parametrize("failure", ["parent_escape", "relative", "newline", "duplicate", "runtime_escape", "symlink"])
def test_authority_rejects_noncanonical_or_ambiguous_paths(context, failure: str) -> None:
    value = copy.deepcopy(context.authority)
    original = Path(value["campaigns"][0]["path"])
    if failure == "parent_escape":
        value["campaigns"][0]["path"] = str(original.parent / ".." / "campaigns" / original.name)
    elif failure == "relative":
        value["campaigns"][0]["path"] = "config/campaigns/buflo.yml"
    elif failure == "newline":
        value["campaigns"][0]["path"] += "\n"
    elif failure == "duplicate":
        value["campaigns"][1] = value["campaigns"][0]
    elif failure == "runtime_escape":
        value["runtime"]["module_root"] = str(context.runtime / ".." / "runtime")
    else:
        link = original.parent / "symlink.yml"
        link.symlink_to(original)
        value["campaigns"][0]["path"] = str(link)
    _write(context.path, value)
    with pytest.raises(ValueError):
        parallel.authority(context.path)


def test_sparse_optional_pairs_leave_residual_cpu_ids() -> None:
    assert parallel.select_pairs([0, 2, 4, 7, 9]) == {"pairs": [[2, 4], [7, 9]], "sidecar_cpus": [0]}
    assert parallel.select_pairs([0, 1, 2, 4, 7, 9])["sidecar_cpus"] == [0, 1]


@pytest.mark.parametrize("cpus", [[0, 1, 2], [2, 4, 7, 9], [0, 2, 2, 7, 9], [0, 2, 4, 9, 7], [False, 2, 4, 7, 9]])
def test_five_cpu_requirement_applies_only_to_optional_pair_selection(cpus) -> None:
    with pytest.raises(ValueError):
        parallel.select_pairs(cpus)


def test_preflight_input_drift_blocks_before_lane_allocation(context) -> None:
    context.workload.write_bytes(b"changed origin graph\n")
    with pytest.raises(ValueError, match="inputs changed"):
        parallel.initialize(context.path, context.output, context.digest, context.actual["available_cpus"])
    assert not (context.output / "lane-1").exists()


@pytest.mark.parametrize("failure", ["missing_origin", "extra_origin", "private_address"])
def test_dns_pins_cover_only_the_complete_paired_origin_graph(context, failure):
    value = parallel.load(context.output / "dns-pins.json")
    if failure == "missing_origin":
        value["hosts"] = []
    elif failure == "extra_origin":
        value["hosts"].append(["other.example", "1.0.0.1"])
    else:
        value["hosts"][0][1] = "127.0.0.1"
    _write(context.output / "dns-pins.json", value)
    with pytest.raises(ValueError, match="DNS pins"):
        parallel.initialize(context.path, context.output, context.digest, context.actual["available_cpus"])
    assert not (context.output / "lane-1").exists()


def test_actual_release_binds_both_workers_and_grants_zero_credit(context) -> None:
    _released(context)
    for index, worker in enumerate(context.actual["workers"]):
        gate = context.output / f"lane-{index+1}/gate"
        release = parallel.load(gate / "release.json")
        partition = parallel.load(gate / "host-partition.json")
        assert partition["schema_version"] == 5
        assert partition["measured_container_id"] == release["worker_id"] == worker["id"]
        assert parallel.sha((gate / "host-partition.json").read_bytes()) == release["host_partition_sha256"]
    launch = parallel.load(context.output / "batch-launch.json")
    assert launch["formal_accepted_trace_count"] == 0 and launch["scientific_credit"] is False
    parallel.reopen_launch(context.path, context.output, context.authority)


@pytest.mark.parametrize("failure", ["raw_identity", "launch_identity", "wrong_lane", "partition_hash", "campaign"])
def test_independent_reopen_rejects_changed_actual_launch_or_gate(context, failure):
    _released(context)
    if failure in {"raw_identity", "launch_identity"}:
        file = context.output / ("actual-launch.json" if failure == "raw_identity" else "batch-launch.json")
        value = parallel.load(file)
        actual = value if failure == "raw_identity" else value["actual"]
        actual["workers"][0]["id"] = "9" * 64
    else:
        file = context.output / "lane-1/gate/release.json"
        value = parallel.load(file)
        if failure == "wrong_lane":
            value["worker_id"] = context.actual["workers"][1]["id"]
        elif failure == "campaign":
            value["campaign"] = "/lab/config/campaigns/cs-buflo.yml"
        else:
            value["host_partition_sha256"] = "0" * 64
    _write(file, value)
    with pytest.raises(ValueError):
        parallel.reopen_launch(context.path, context.output, context.authority)


@pytest.mark.parametrize("failure", ["worker_image", "peer_overlap", "preflight_hash", "input_drift"])
def test_release_failure_keeps_both_traffic_gates_closed(context, failure: str) -> None:
    parallel.initialize(context.path, context.output, context.digest, context.actual["available_cpus"])
    if failure == "worker_image":
        context.actual["workers"][1]["image_id"] = "sha256:" + "5" * 64
    elif failure == "peer_overlap":
        context.actual["inspected_containers"][1]["HostConfig"]["CpusetCpus"] = "4,7,9"
    elif failure == "preflight_hash":
        with (context.output / "image-preflight.json").open("ab") as stream:
            stream.write(b"\n")
    else:
        context.workload.write_bytes(b"changed qualification inputs\n")
    with pytest.raises(ValueError):
        parallel.release(context.path, context.output, context.actual)
    assert not list(context.output.glob("lane-*/gate/release.json"))


@pytest.mark.parametrize("failure", [None, "wrong_lane", "partition_hash", "source_dirty", "authority_hash", "own_cpu", "index"])
def test_gate_executes_only_the_exact_authority_lane(context, monkeypatch, failure) -> None:
    _released(context)
    monkeypatch.setenv("QCSD_LAB_UID", str(os.geteuid()))
    monkeypatch.setenv("QCSD_LAB_GID", str(os.getegid()))
    gate = context.output / "lane-1/gate"
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    calls = []
    monkeypatch.setattr(parallel.os, "execv", lambda command, argv: calls.append((command, argv)))
    index, digest = 0, context.digest
    if failure == "wrong_lane":
        index = 1
    elif failure == "partition_hash":
        with (gate / "host-partition.json").open("ab") as stream:
            stream.write(b"\n")
    elif failure == "source_dirty":
        source = parallel.load(context.source_path)
        source["lab_dirty"] = True
        _write(context.source_path, source)
    elif failure == "authority_hash":
        digest = "0" * 64
    elif failure == "own_cpu":
        monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "9")
    elif failure == "index":
        index = 2
    if failure:
        with pytest.raises(ValueError):
            parallel.gate(gate, digest, index, context.path)
        assert calls == []
    else:
        parallel.gate(gate, digest, index, context.path)
        assert calls == [("/usr/local/bin/collection-entrypoint",
                          ["collection-entrypoint", "run", "/lab/config/campaigns/buflo.yml"])]
        assert parallel.os.environ["QCSD_CAPTURE_SCHEDULER_HOST_PARTITION_FILE"] == str(gate / "host-partition.json")


def _retirement(context, index: int) -> dict:
    terminal = copy.deepcopy(context.actual["inspected_containers"][index])
    terminal["State"] = {"Status": "exited", "Running": False, "ExitCode": 0}
    peer = copy.deepcopy(context.actual["inspected_containers"][1-index])
    peer["State"] = {"Status": "running", "Running": True}
    resources = context.actual["lane_resources"][index]
    return {"worker_terminal": terminal, "worker_exit_code": 0, "peer_state": peer,
            "absent_ids": sorted([terminal["Id"], resources["router_id"], resources["network_id"]])}


def test_retirement_preserves_running_peer_and_later_reopens_its_prior_retirement(context) -> None:
    _released(context)
    parallel.retire_lane(context.output, 0, _retirement(context, 0))
    assert not (context.output / "lane-2/retirement.json").exists()
    actual = _retirement(context, 1)
    actual.pop("peer_state")
    actual["peer_retirement_sha256"] = parallel.sha((context.output / "lane-1/retirement.json").read_bytes())
    parallel.retire_lane(context.output, 1, actual)
    assert parallel.load(context.output / "lane-2/retirement.json")["scientific_credit"] is False


@pytest.mark.parametrize("failure", ["peer_resource", "peer_identity", "prior_hash"])
def test_retirement_rejects_cross_lane_absence_or_wrong_peer(context, failure: str) -> None:
    _released(context)
    actual = _retirement(context, 0)
    if failure == "peer_resource":
        actual["absent_ids"][0] = context.actual["workers"][1]["id"]
    elif failure == "peer_identity":
        actual["peer_state"]["Image"] = "sha256:" + "5" * 64
    else:
        actual["peer_retirement_sha256"] = "0" * 64
        _write(context.output / "lane-2/retirement.json", _retirement(context, 1))
    with pytest.raises(ValueError):
        parallel.retire_lane(context.output, 0, actual)
    assert not (context.output / "lane-1/retirement.json").exists()


@pytest.mark.parametrize("host_returncode", [0, 1])
def test_nonzero_host_blocks_success_even_when_both_lanes_deep_pass(context, monkeypatch, host_returncode) -> None:
    from qcsd_lab import verification, parameters
    from qcsd_lab.rapid_lane_evidence import HOST_GATE_SCRIPT

    campaigns = []
    preflight = parallel.load(context.output / "image-preflight.json")
    for index, supplied in enumerate(context.authority["campaigns"]):
        name = preflight["campaigns"][index]["name"]
        campaigns.append(SimpleNamespace(name=name, source_bytes=Path(supplied["path"]).read_bytes(),
            workloads=[SimpleNamespace(id="site")], defenses=[SimpleNamespace(name=name)]))
        preflight["campaigns"][index].update(workloads={"site": parallel.sha(context.workload.read_bytes())},
                                           qualification_manifest_sha256="6" * 64)
    _write(context.output / "image-preflight.json", preflight)
    original_parameter_root = parameters.LAB_ROOT
    def parsed_campaigns(_value):
        assert parameters.LAB_ROOT == Path(context.authority["runtime"]["execution_root"])
        return campaigns
    monkeypatch.setattr(parallel, "_campaigns", parsed_campaigns)
    _released(context)
    parallel.retire_lane(context.output, 0, _retirement(context, 0))
    second_retirement = _retirement(context, 1)
    second_retirement.pop("peer_state")
    second_retirement["peer_retirement_sha256"] = parallel.sha(parallel.read(context.output / "lane-1/retirement.json"))
    parallel.retire_lane(context.output, 1, second_retirement)

    command = [context.authority["runtime"]["host_launcher"], "parallel-diagnostic-run", str(context.path), str(context.output)]
    started = parallel.load(context.output / "batch-launch.json")["started_at"]
    _write(context.output / "operator-intent.json", {"command": command, "authority_sha256": context.digest})
    _write(context.output / "host-start.json", {"command": command, "authority_sha256": context.digest,
        "started_at": started, "gate_script_sha256": parallel.sha(HOST_GATE_SCRIPT.encode()),
        "host": {"argv": ["python", "-c", HOST_GATE_SCRIPT, json.dumps(command), "3"]}})
    (context.output / "host.stdout").write_bytes(b"both workers completed\n")
    (context.output / "host.stderr").write_bytes(b"cleanup failure\n" if host_returncode else b"")
    _write(context.output / "host-process.json", {"command": command, "started_at": started,
        "completed_at": parallel.now(), "returncode": host_returncode,
        "host_start_sha256": parallel.sha(parallel.read(context.output / "host-start.json")),
        "stdout_sha256": parallel.sha(parallel.read(context.output / "host.stdout")),
        "stderr_sha256": parallel.sha(parallel.read(context.output / "host.stderr"))})

    deep_results = {}
    for index, campaign in enumerate(campaigns):
        root = context.output / f"lane-{index+1}/results/{campaign.name}/run"
        root.mkdir(parents=True)
        (root / "evidence.sha256").write_bytes(b"deep-verifier seal fixture\n")
        partition = parallel.load(context.output / f"lane-{index+1}/gate/host-partition.json")
        deep_results[root] = SimpleNamespace(experiment={"status": "complete", "purpose": "smoke",
            "name": campaign.name, "started_at": started, "configuration": {
                "campaign_sha256": parallel.sha(campaign.source_bytes),
                "workloads": [{"id": "site", "sha256": preflight["campaigns"][index]["workloads"]["site"]}],
                "chaff_qualification_set_manifest_sha256": "6" * 64},
            "source": {"image_digest": context.authority["runtime"]["collection_image_digest"],
                       "lab_commit": "1" * 40, "lab_dirty": False},
            "samples": [{"workload_id": "site", "visit": 0, "defense": campaign.name, "state": "accepted",
                "diagnostics": {"scheduler_runtime_receipt": {"scheduler_runtime_evidence": {
                    "schema_version": 5, "host_partition": partition}}}}], "summary": {"passed": True}})
    verified = []
    def deep_pass(root):
        verified.append(root)
        return deep_results[root]
    monkeypatch.setattr(verification, "verify_result", deep_pass)

    result = parallel.verify_results(context.path, context.output)
    assert parameters.LAB_ROOT == original_parameter_root
    assert verified == list(deep_results)
    assert all(lane["valid"] and lane["accepted"] == 1 for lane in result["lanes"])
    assert result["host_returncode"] == host_returncode
    assert result["valid"] is (host_returncode == 0)
    assert result["formal_accepted_trace_count"] == 0 and result["scientific_credit"] is False


@pytest.mark.parametrize("failure", [None, "serial", "wrong_peer", "not_accepted"])
def test_result_binding_requires_actual_peer_runtime_after_deep_verification(context, tmp_path, monkeypatch, failure) -> None:
    _released(context)
    partition = parallel.load(context.output / "lane-1/gate/host-partition.json")
    monkeypatch.setenv("QCSD_CAPTURE_SCHEDULER_CONTRACT", parallel.NATIVE_CONTRACT)
    monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", "2")
    monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", "4")
    proc_root, cpu_stat = _fixture(tmp_path / "measured")
    (proc_root / "1/task/1/status").write_text("Name:\torchestrator\nTgid:\t1\nCpus_allowed_list:\t4\n")
    (proc_root / "stat").write_text("cpu2 1 2 3 4 5 6 7 0 0 0\n")
    monitor = CaptureSchedulerMonitor(proc_root=proc_root, cgroup_cpu_stat_paths=(cpu_stat,),
                                      interval_us=1_000_000, host_partition=partition)
    _write_task(proc_root, tgid=77, tid=77, process_group=77, cpus="2", name="neqo-qcsd-client")
    monitor.process_started(77)
    evidence = monitor.finish()
    assert capture_scheduler_runtime_evidence_valid(evidence)
    retained = scheduler_runtime_receipt(evidence=evidence,
        evidence_sha256=parallel.sha((json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()),
        process_scheduler_required=True, process_scheduler_valid=True, evidence_valid=True)
    sample = {"state": "accepted", "diagnostics": {"scheduler_runtime_receipt": retained}}
    if failure == "serial":
        evidence["schema_version"] = 4
        retained["scheduler_runtime_evidence"]["schema_version"] = 4
    elif failure == "wrong_peer":
        retained["scheduler_runtime_evidence"]["host_partition"] = parallel.load(context.output / "lane-2/gate/host-partition.json")
    elif failure == "not_accepted":
        sample["state"] = "failed"
    if failure:
        with pytest.raises(ValueError):
            parallel.verify_peer_sample_bindings({"samples": [sample]}, partition)
    else:
        parallel.verify_peer_sample_bindings({"samples": [sample]}, partition)
