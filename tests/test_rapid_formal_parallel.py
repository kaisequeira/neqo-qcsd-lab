"""Official formal lane lifecycle with image/network and capture reads replaced."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from qcsd_lab import class_acquisition, orchestrator, runtime_provenance
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as evidence
from qcsd_lab import rapid_parallel_capture as shared
from tests.test_process_scheduler import _peer_inputs
from tests.test_rapid_lane_evidence import setup as ordinary_setup


VERIFY_LANE_RESULT = plan.verify_lane_result


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(evidence._json(value))


def _snapshot(*roots: Path):
    return {
        str(path): (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino)
        for root in roots for path in root.rglob("*") if path.is_file()
    }


@pytest.fixture
def formal_setup(ordinary_setup, monkeypatch):
    setup = ordinary_setup
    spec = replace(setup.spec, module_root=setup.spec.runtime_source_root)
    spec.host_launcher.write_bytes(spec.base_launcher.read_bytes())
    project = Path(__file__).resolve().parents[1]
    for name in ("rapid_parallel_capture.py", "rapid_formal_parallel.py"):
        target = spec.runtime_source_root / "src/qcsd_lab" / name
        target.write_bytes((project / "src/qcsd_lab" / name).read_bytes())

    qualification_rows = []
    qualification_digests = {}
    for index in range(10):
        name = f"shard-{index}"
        sidecar = spec.campaign_dir.parent / "chaff-response-qualification-store/sets" / name
        sidecar.mkdir(parents=True, exist_ok=True)
        manifest = sidecar / "_qualification-set.json"
        manifest.write_bytes(f"immutable response qualification for {name}\n".encode())
        qualification_digests[name] = shared.sha(manifest.read_bytes())
        qualification_rows.append(dict(qualification_set=name, manifest=str(manifest),
                                       sidecar_root=str(sidecar), prefix_spec_root=None))
    _write(spec.qualification_spec, dict(schema_version=1, qualification_sets=qualification_rows))
    sites = []
    for index in range(50):
        name = f"site-{index}"
        raw = evidence._json({"preparation": {"approved_origins": [
            f"https://site{index}.example", f"https://cdn{index // 5}.example",
        ]}})
        (spec.workload_root / f"{name}.json").write_bytes(raw)
        shard = f"shard-{index // 5}"
        sites.append(plan.Site(f"candidate-{index}", name, shared.sha(raw),
                               f"https://site{index}.example", shard, qualification_digests[shard]))
    sites = tuple(sites)
    lanes = plan.plan_lanes(sites, final=True, study_version=5)
    lane_lookup = {lane.campaign_name: lane for lane in lanes}
    bindings = setup.proof["bindings"]

    def write_plan(path, selected):
        rows = []
        for lane in selected:
            raw = plan.render_lane_campaign(lane, sites)
            rows.append({**asdict(lane), "campaign_sha256": shared.sha(raw)})
        payload = {"cohort_generation": "final-50", "bindings": bindings,
                   "acquisition_provenance_sha256": "e" * 64,
                   "sites": [asdict(site) for site in sites], "lanes": rows}
        _write(path, evidence.admission._bind(evidence.PLAN_TYPE, payload))

    write_plan(spec.plan_receipt, lanes)
    # Only the lanes used by these bounded tests need physical campaign inputs.
    for lane in lanes[:15]:
        (spec.campaign_dir / f"{lane.campaign_name}.yml").write_bytes(plan.render_lane_campaign(lane, sites))
    spec_path = spec.data_root / "formal-capture-spec.json"
    _write(spec_path, {"schema_version": 1, "artifact_type": evidence.SPEC_TYPE,
                       "inputs": spec.serializable()})

    def plan_inputs(args):
        payload = evidence._payload(args.output, evidence.PLAN_TYPE)
        return (SimpleNamespace(provenance_sha256="e" * 64), sites,
                SimpleNamespace(digests=lambda: bindings), "final-50", "f" * 64)

    setup.fake_plan._inputs = plan_inputs
    image_calls = []

    def image_actuator(command, **options):
        assert command[:2] == ["docker", "run"]
        assert "--network" in command and command[command.index("--network")+1] == "none"
        image_calls.append(command)
        proof = evidence.executed_image_plan_check(json.loads(command[-1]))
        return subprocess.CompletedProcess(command, 0, json.dumps(proof), "retained image diagnostic\n")

    monkeypatch.setattr(evidence.subprocess, "run", image_actuator)
    installed_files = dict(setup.implementation["source_files"])
    for name in ("rapid_parallel_capture.py", "rapid_formal_parallel.py"):
        relative = f"src/qcsd_lab/{name}"
        installed_files[relative] = shared.sha((spec.runtime_source_root / relative).read_bytes())
    monkeypatch.setattr(runtime_provenance, "validate_runtime_receipt",
                        lambda **kwargs: {"schema_version": 2, "source_files": installed_files})

    # The image fixture exposes the parsed campaign inventory for its prepared
    # graphs. Plan/campaign bytes and every source/qualification hash still pass
    # the ordinary intent and image-proof validators unchanged.
    def installed_campaign(path):
        lane = lane_lookup[Path(path).stem]
        workloads = []
        for name in lane.workload_ids:
            workload_path = spec.workload_root / f"{name}.json"
            manifest = (spec.campaign_dir.parent / "chaff-response-qualification-store/sets" /
                        f"shard-{int(name.removeprefix('site-')) // 5}" / "_qualification-set.json")
            workloads.append(SimpleNamespace(id=name, path=workload_path,
                data=shared.load(workload_path), sha256=shared.sha(workload_path.read_bytes()),
                visits=lane.visits_per_workload, chaff_qualification_path=None,
                chaff_manifest_path=None, qualification_set_manifest_path=manifest if lane.qualification_set else None))
        parameters = None
        if lane.mode == "buflo":
            parameters = spec.execution_root / "config/defense-params/buflo-live.json"
        elif lane.mode == "cs-buflo":
            parameters = spec.execution_root / "config/defense-params/cs-buflo-ctsp-live.json"
        return SimpleNamespace(path=Path(path), workloads=workloads,
            defenses=[SimpleNamespace(parameters_path=parameters, parameters_provenance_path=None)])

    monkeypatch.setattr(orchestrator, "load_campaign", installed_campaign)
    capture_reads = []

    def capture_reader(path):
        capture_reads.append(Path(path))
        return SimpleNamespace(experiment=shared.load(Path(path) / "experiment.json"))

    monkeypatch.setattr(plan, "verify_lane_result", VERIFY_LANE_RESULT)
    monkeypatch.setattr(plan, "verify_result", capture_reader)
    return SimpleNamespace(spec=spec, spec_path=spec_path, root=setup.root, sites=sites,
        lanes=lanes, lane_lookup=lane_lookup, write_plan=write_plan,
        image_calls=image_calls, capture_reads=capture_reads, sequence=0)


def _dns(setup, lane):
    hosts = set()
    for name in lane.workload_ids:
        workload = shared.load(setup.spec.workload_root / f"{name}.json")
        hosts.update(urlsplit(origin).hostname for origin in workload["preparation"]["approved_origins"])
    return {"schema_version": 1, "campaign": lane.campaign_name,
            "hosts": [[host, "8.8.8.8"] for host in sorted(hosts)]}


def _prepare(setup, lanes=None, *, spec_path=None, second_spec=None, predecessors=None):
    setup.sequence += 1
    lanes = lanes or [setup.lanes[0], setup.lanes[8]]
    output = setup.spec.execution_root / "results" / f"parallel-batch-{setup.sequence}"
    output.mkdir(parents=True)
    path = setup.spec.data_root / f"formal-authority-{setup.sequence}.json"
    options = {"predecessors": predecessors} if predecessors is not None else {}
    if second_spec is not None:
        options["second_spec"] = second_spec
    formal.prepare_batch(spec_path or setup.spec_path, setup.root,
                         [lane.campaign_name for lane in lanes], path, **options)
    return SimpleNamespace(path=path, output=output, lanes=lanes, value=formal.authority(path),
                           digest=shared.sha(path.read_bytes()), setup=setup)


def _initialize(batch):
    for index, lane in enumerate(batch.lanes):
        inputs = formal.worker_inputs(batch.path, index)
        _write(Path(inputs["dns_path"]), _dns(batch.setup, lane))
    _write(batch.output / "image-preflight.json", formal.image_preflight(batch.path, batch.digest))
    cpu = formal.initialize(batch.path, batch.output, batch.digest, [0, 2, 4, 7, 9])
    assert cpu == {"pairs": [[2, 4], [7, 9]], "sidecar_cpus": [0]}
    inspected, workers, sidecars = _peer_inputs()
    extra = copy.deepcopy(inspected[-1])
    extra.update(Id="f" * 64, Name="/sidecar-b")
    inspected.append(extra)
    sidecars["sidecar-b"] = extra["Id"]
    for index, worker in enumerate(workers):
        worker["image_id"] = batch.setup.spec.collection_image_digest
        observed = inspected[index]
        observed["Image"] = worker["image_id"]
        observed["State"].update(Status="running", Running=True, ExitCode=0)
        inputs = formal.worker_inputs(batch.path, index)
        observed["Config"]["Env"] = [key+"="+value for key, value in sorted(inputs["environment"].items())]
        observed["Mounts"] = [
            dict(Source=str(batch.setup.spec.execution_root), Destination="/lab", RW=False),
            dict(Source=str(batch.setup.spec.execution_root / "results"), Destination="/lab/results", RW=False),
            dict(Source=inputs["result_namespace"], Destination="/lab/results/"+inputs["campaign_name"], RW=True),
        ]
        observed["HostConfig"]["ExtraHosts"] = [host+":"+address for host, address in _dns(batch.setup, batch.lanes[index])["hosts"]]
        _write(batch.output / f"lane-{index+1}/worker-argv.json", [
            "docker", "run", "--name", worker["name"], "--cpuset-cpus", observed["HostConfig"]["CpusetCpus"],
            "--volume", inputs["result_namespace"]+":/lab/results/"+inputs["campaign_name"]+":rw",
            "--entrypoint", "/usr/bin/tini", worker["image_id"], "--", "/bin/sh", "-eu", "-c",
            "exec /opt/qcsd-venv/bin/python3 -I -m qcsd_lab.rapid_parallel_capture gate \"$@\"",
            "qcsd-parallel-affinity", "--output", "/parallel-gate", "--authority", "/parallel-authority.json",
            "--sha256", batch.digest, "--index", str(index),
        ])
    batch.actual = dict(workers=workers, sidecars=sidecars, inspected_containers=inspected,
        available_cpus=[0, 2, 4, 7, 9], docker_ncpu=16,
        lane_resources=[dict(worker_id=workers[0]["id"], router_id="c"*64, network_id="3"*64),
                        dict(worker_id=workers[1]["id"], router_id="f"*64, network_id="4"*64)])
    _write(batch.output / "actual-launch.json", batch.actual)
    command = [str(batch.setup.spec.host_launcher), "parallel-formal-run", str(batch.path), str(batch.output)]
    _write(batch.output / "operator-intent.json", dict(command=command, authority_sha256=batch.digest))
    host = evidence._process_identity(os.getpid())
    host["argv"] = [sys.executable, "-c", evidence.HOST_GATE_SCRIPT, json.dumps(command), "7"]
    _write(batch.output / "host-start.json", dict(command=command, authority_sha256=batch.digest,
        started_at=shared.now(), host=host, gate_script_sha256=shared.sha(evidence.HOST_GATE_SCRIPT.encode())))
    return batch


def _release(batch):
    formal.release(batch.path, batch.output, batch.actual)
    return batch


def _result(batch, index, *, count=20):
    setup, lane = batch.setup, batch.lanes[index]
    partition = shared.load(batch.output / f"lane-{index+1}/gate/host-partition.json")
    samples = [dict(workload_id=name, visit=visit, defense=lane.mode, state="accepted",
                    request_policy="as-defined", diagnostics={"scheduler_runtime_receipt": {
                        "scheduler_runtime_evidence": {"schema_version": 5, "host_partition": partition}}})
               for name in lane.workload_ids for visit in range(lane.visits_per_workload)][:count]
    result = setup.spec.execution_root / "results" / lane.campaign_name / "attempt-001"
    result.mkdir()
    _write(result / "experiment.json", dict(started_at=shared.now(), status="complete", name=lane.campaign_name,
        purpose="evaluation", source=dict(image_digest=setup.spec.collection_image_digest,
            lab_commit="b"*40, lab_dirty=False), summary=dict(planned=20, accepted=count, failed=0, passed=True),
        configuration=dict(campaign_sha256=shared.sha((setup.spec.campaign_dir / f"{lane.campaign_name}.yml").read_bytes()),
            profile="research-1200", request_policies=["as-defined"], chaff_qualification_set=lane.qualification_set,
            chaff_qualification_set_manifest_sha256=(next(site.qualification_set_manifest_sha256 for site in setup.sites
                if site.workload_id == lane.workload_ids[0]) if lane.qualification_set else None),
            defenses=[dict(name=lane.mode)], workloads=[dict(id=name, visits=4,
                sha256=shared.sha((setup.spec.workload_root / f"{name}.json").read_bytes())) for name in lane.workload_ids]),
        samples=samples))
    (result / "evidence.sha256").write_bytes(b"immutable capture seal fixture\n")
    return result


def _retire(batch, index, status, *, peer_running=True):
    observed = copy.deepcopy(batch.actual["inspected_containers"][index])
    observed["State"].update(Status="exited", Running=False, ExitCode=status)
    resources = batch.actual["lane_resources"][index]
    actual = dict(worker_terminal=observed, worker_exit_code=status,
                  absent_ids=sorted([batch.actual["workers"][index]["id"], resources["router_id"], resources["network_id"]]))
    if peer_running:
        actual["peer_state"] = copy.deepcopy(batch.actual["inspected_containers"][1-index])
    else:
        actual["peer_retirement_sha256"] = shared.sha((batch.output / f"lane-{2-index}/retirement.json").read_bytes())
    lane = batch.output / f"lane-{index+1}"
    (lane / "worker.stdout").write_bytes(f"actual observed worker {index} output\n".encode())
    (lane / "worker.stderr").write_bytes(f"actual retained worker {index} diagnostics\n".encode())
    formal.retire_lane(batch.output, index, actual)
    return actual


def _close(batch, status):
    (batch.output / "host.stdout").write_bytes(b"actual batch host output\n")
    (batch.output / "host.stderr").write_bytes(b"actual retained batch diagnostics\n")
    start = shared.load(batch.output / "host-start.json")
    _write(batch.output / "host-process.json", dict(command=start["command"], returncode=status,
        started_at=start["started_at"], completed_at=shared.now(),
        host_start_sha256=shared.sha((batch.output / "host-start.json").read_bytes()),
        stdout_sha256=shared.sha((batch.output / "host.stdout").read_bytes()),
        stderr_sha256=shared.sha((batch.output / "host.stderr").read_bytes())))


def _complete_pair(setup, *, failed_first=False):
    batch = _release(_initialize(_prepare(setup)))
    batch.results = [_result(batch, 0), _result(batch, 1)]
    _retire(batch, 0, 1 if failed_first else 0)
    _retire(batch, 1, 0, peer_running=False)
    _close(batch, 1 if failed_first else 0)
    return batch


def test_preparation_claims_ordinary_twenty_slot_intents_without_completion(formal_setup):
    setup = formal_setup
    batch = _prepare(setup)
    assert len(setup.lanes) == 800 and sum(lane.sample_count for lane in setup.lanes) == 16000
    assert batch.value["artifact_type"] == formal.AUTHORITY_TYPE
    assert setup.image_calls
    for index, lane in enumerate(batch.lanes):
        inputs = formal.worker_inputs(batch.path, index)
        intent_path = Path(batch.value["lane_intents"][index]["path"])
        intent, lineage, verified_lane, sites = evidence._intent_and_lineage(setup.spec, setup.root, intent_path)
        assert verified_lane == lane and lane.sample_count == 20 and len(sites) == 50
        assert intent["actuator"] == formal.ACTUATOR and intent["scientific_credit"] is False
        assert lineage["equivalent_to_cohort"] is True
        assert inputs["result_namespace"] == str(setup.spec.execution_root / "results" / lane.campaign_name)
        assert inputs["dns_path"] == str(intent_path.parent / "dns.json")
        assert not Path(inputs["result_namespace"]).exists()
        assert not (intent_path.parent / "complete.json").exists()
    with pytest.raises(FileExistsError):
        _prepare(setup)


def test_release_binds_actual_peer_partitions_to_both_ordinary_worker_births(formal_setup):
    batch = _release(_initialize(_prepare(formal_setup)))
    formal.reopen_launch(batch.path, batch.output, batch.value)
    for index, lane in enumerate(batch.lanes):
        intent_path = Path(batch.value["lane_intents"][index]["path"])
        start_path = intent_path.parent / "host-start.json"
        assert evidence._load(start_path.read_bytes())["receipt_type"] == formal.START_TYPE
        start = evidence._validated_host_start(start_path.read_bytes(), intent_path.read_bytes(), campaign_name=lane.campaign_name)
        gate = shared.load(batch.output / f"lane-{index+1}/gate/host-partition.json")
        assert gate["schema_version"] == 5 and gate["measured_container_id"] == batch.actual["workers"][index]["id"]
        assert gate["declared_workers"] == batch.actual["workers"]
        assert start["worker_index"] == index and start["campaign_name"] == lane.campaign_name
        assert start["host_partition_sha256"] == shared.sha((batch.output / f"lane-{index+1}/gate/host-partition.json").read_bytes())


def test_dns_resolution_uses_each_complete_origin_graph(formal_setup, monkeypatch):
    batch = _prepare(formal_setup)
    queries = []
    def resolve(origins):
        queries.append(tuple(origins))
        return {origin: "8.8.8.8" for origin in origins}
    monkeypatch.setattr(class_acquisition, "public_origin_ip_pins", resolve)
    for index, lane in enumerate(batch.lanes):
        value = formal.resolve_dns(batch.path, index)
        assert value == _dns(formal_setup, lane)
        assert evidence.verify_dns_receipt(evidence._json(value), lane.campaign_name,
            {name: (formal_setup.spec.workload_root / f"{name}.json").read_bytes() for name in lane.workload_ids})
    assert set(queries[0]).isdisjoint(queries[1])


@pytest.mark.parametrize("mutation", ["missing-origin", "private", "wrong-campaign", "copied-peer"])
def test_invalid_independent_dns_claims_neither_worker_namespace(formal_setup, mutation):
    batch = _prepare(formal_setup)
    for index, lane in enumerate(batch.lanes):
        value = _dns(formal_setup, lane)
        if index == 1:
            if mutation == "missing-origin": value["hosts"].pop()
            elif mutation == "private": value["hosts"][0][1] = "127.0.0.1"
            elif mutation == "wrong-campaign": value["campaign"] = batch.lanes[0].campaign_name
            else: value = _dns(formal_setup, batch.lanes[0])
        _write(Path(formal.worker_inputs(batch.path, index)["dns_path"]), value)
    _write(batch.output / "image-preflight.json", formal.image_preflight(batch.path, batch.digest))
    with pytest.raises(ValueError, match="DNS"):
        formal.initialize(batch.path, batch.output, batch.digest, [0, 2, 4, 7, 9])
    assert not (batch.output / "batch-intent.json").exists()
    assert all(not (formal_setup.spec.execution_root / "results" / lane.campaign_name).exists() for lane in batch.lanes)


@pytest.mark.parametrize("mutation", ["peer-namespace", "writable-base", "extra-dns", "worker-image"])
def test_actual_worker_isolation_failure_releases_neither_gate(formal_setup, mutation):
    batch = _initialize(_prepare(formal_setup))
    worker = batch.actual["inspected_containers"][1]
    if mutation == "peer-namespace": worker["Mounts"][-1]["Source"] = str(formal_setup.spec.execution_root / "results" / batch.lanes[0].campaign_name)
    elif mutation == "writable-base": worker["Mounts"][1]["RW"] = True
    elif mutation == "extra-dns": worker["HostConfig"]["ExtraHosts"].append("inherited.example:1.1.1.1")
    else: worker["Image"] = "sha256:"+"9"*64
    with pytest.raises(ValueError):
        formal.release(batch.path, batch.output, batch.actual)
    assert not (batch.output / "batch-launch.json").exists()
    assert all(not (batch.output / f"lane-{index+1}/gate/release.json").exists() for index in range(2))


def test_failed_first_worker_retains_zero_credit_and_completed_peer_verifies_independently(formal_setup):
    batch = _complete_pair(formal_setup, failed_first=True)
    first, second = [Path(row["path"]).parent for row in batch.value["lane_intents"]]
    assert (first / "completion-failure.json").is_file() and not (first / "complete.json").exists()
    assert evidence._payload(first / "host-process.json", formal.PROCESS_TYPE)["returncode"] == 1
    assert evidence._payload(first / "retirement.json", formal.RETIREMENT_TYPE)["scientific_credit"] is False
    assert shared.load(batch.output / "lane-1/retirement.json")["actual"]["peer_state"]["State"]["Running"] is True
    facts = evidence.verify_launch_receipt(second / "complete.json", spec=formal_setup.spec, evidence_root=formal_setup.root)
    assert facts["accepted"] == 20 and facts["host_returncode"] == 0
    assert facts["scientific_credit"] == "formal-only-if-bound-to-final-50-plan"
    assert len(shared.load(batch.results[1] / "experiment.json")["samples"]) == 20
    report = formal.verify_results(batch.path, batch.output)
    assert report["valid"] is False and report["formal_accepted_trace_count"] == 20
    assert [row["accepted"] for row in report["lanes"]] == [0, 20]
    assert report["host_returncode"] == 1
    with pytest.raises(ValueError, match="missing or unregistered logical lanes"):
        evidence.formal_manifest_rows(formal_setup.spec, formal_setup.root)


def test_two_complete_workers_publish_two_ordinary_twenty_slot_receipts(formal_setup):
    batch = _complete_pair(formal_setup)
    report = formal.verify_results(batch.path, batch.output)
    assert report["valid"] is True and report["formal_accepted_trace_count"] == 40
    assert [row["accepted"] for row in report["lanes"]] == [20, 20]
    assert formal_setup.capture_reads
    for row in report["lanes"]:
        assert evidence._load(Path(row["launch_receipt"]).read_bytes())["receipt_type"] == evidence.COMPLETE_TYPE


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong-visit", "rejected"])
def test_resealed_partial_or_wrong_slot_vector_cannot_complete(formal_setup, mutation):
    batch = _release(_initialize(_prepare(formal_setup)))
    result = _result(batch, 1)
    experiment = shared.load(result / "experiment.json")
    if mutation == "missing": experiment["samples"].pop()
    elif mutation == "duplicate": experiment["samples"][-1] = copy.deepcopy(experiment["samples"][0])
    elif mutation == "wrong-visit": experiment["samples"][-1]["visit"] = 4
    else: experiment["samples"][-1]["state"] = "rejected"
    _write(result / "experiment.json", experiment)
    _retire(batch, 1, 0)
    directory = Path(batch.value["lane_intents"][1]["path"]).parent
    assert not (directory / "complete.json").exists()
    failure = shared.load(directory / "completion-failure.json")
    assert failure["formal_accepted_trace_count"] == 0 and failure["scientific_credit"] is False
    assert "planned sample" in failure["message"]


@pytest.mark.parametrize("mutation", ["source", "dns", "seal", "argv", "worker", "sample-partition", "boolean-exit"])
def test_reopened_completion_rejects_changed_source_dns_seal_or_worker(formal_setup, mutation):
    batch = _complete_pair(formal_setup)
    directory = Path(batch.value["lane_intents"][1]["path"]).parent
    if mutation == "source":
        source = formal_setup.spec.runtime_source_root / "src/qcsd_lab/orchestrator.py"
        source.write_bytes(source.read_bytes()+b"changed source\n")
    elif mutation == "dns":
        dns = shared.load(directory / "dns.json"); dns["hosts"][0][1] = "1.1.1.1"
        _write(directory / "dns.json", dns)
    elif mutation == "seal":
        (batch.results[1] / "evidence.sha256").write_bytes(b"different seal\n")
    elif mutation == "argv":
        path = batch.output / "lane-2/worker-argv.json"
        argv = shared.load(path); argv.append("changed launch input")
        _write(path, argv)
    elif mutation == "worker":
        path = batch.output / "lane-2/retirement.json"
        retired = shared.load(path); retired["actual"]["worker_terminal"]["Name"] = "/different-worker"
        _write(path, retired)
    elif mutation == "sample-partition":
        path = batch.results[1] / "experiment.json"
        experiment = shared.load(path)
        experiment["samples"][0]["diagnostics"]["scheduler_runtime_receipt"]["scheduler_runtime_evidence"]["host_partition"]["measured_container_id"] = batch.actual["workers"][0]["id"]
        _write(path, experiment)
    else:
        process = evidence._payload(directory / "host-process.json", formal.PROCESS_TYPE)
        process["returncode"] = False
        _write(directory / "host-process.json", evidence.admission._bind(formal.PROCESS_TYPE, process))
    with pytest.raises(ValueError):
        evidence.verify_launch_receipt(directory / "complete.json", spec=formal_setup.spec, evidence_root=formal_setup.root)


def test_failed_only_g02_uses_fresh_plan_and_preserves_completed_peer(formal_setup):
    setup = formal_setup
    first_batch = _complete_pair(setup, failed_first=True)
    first_intent, peer_intent = [Path(row["path"]) for row in first_batch.value["lane_intents"]]
    retained = _snapshot(first_intent.parent, peer_intent.parent, *first_batch.results)
    frozen = (setup.spec_path.read_bytes(), setup.spec.plan_receipt.read_bytes())
    successor = plan.successor_lane(first_batch.lanes[0], 2)
    setup.lane_lookup[successor.campaign_name] = successor
    (setup.spec.campaign_dir / f"{successor.campaign_name}.yml").write_bytes(plan.render_lane_campaign(successor, setup.sites))
    successor_plan = setup.spec.data_root / "failed-lane-g02-plan.json"
    setup.write_plan(successor_plan, [successor])
    successor_spec = replace(setup.spec, plan_receipt=successor_plan)
    successor_spec_path = setup.spec.data_root / "failed-lane-g02-spec.json"
    _write(successor_spec_path, {"schema_version": 1, "artifact_type": evidence.SPEC_TYPE,
                                "inputs": successor_spec.serializable()})
    recovery = _prepare(setup, [successor, setup.lanes[11]], spec_path=successor_spec_path,
                        second_spec=setup.spec_path, predecessors=[first_intent, None])
    intent_path = Path(recovery.value["lane_intents"][0]["path"])
    _, lineage, lane, _ = evidence._intent_and_lineage(successor_spec, setup.root, intent_path)
    assert lane.generation == 2 and lane.logical_name == first_batch.lanes[0].logical_name
    assert lineage["predecessor_campaign_name"] == first_batch.lanes[0].campaign_name
    assert lineage["predecessor_intent"]["sha256"] == shared.sha(first_intent.read_bytes())
    assert lineage["predecessor_attempt"]["host_process"] and lineage["predecessor_attempt"]["retirement"]
    assert lineage["predecessor_attempt"]["result_inventory"]
    _release(_initialize(recovery))
    recovery.results = [_result(recovery, 0), _result(recovery, 1)]
    _retire(recovery, 0, 0)
    _retire(recovery, 1, 0, peer_running=False)
    _close(recovery, 0)
    recovered = evidence.verify_launch_receipt(intent_path.parent / "complete.json", spec=setup.spec, evidence_root=setup.root)
    assert recovered["accepted"] == 20 and recovered["campaign_name"] == successor.campaign_name
    assert formal.verify_results(recovery.path, recovery.output)["formal_accepted_trace_count"] == 40
    assert (setup.spec_path.read_bytes(), setup.spec.plan_receipt.read_bytes()) == frozen
    assert _snapshot(first_intent.parent, peer_intent.parent, *first_batch.results) == retained
    evidence.verify_launch_receipt(peer_intent.parent / "complete.json", spec=setup.spec, evidence_root=setup.root)

    peer_successor = plan.successor_lane(first_batch.lanes[1], 2)
    setup.lane_lookup[peer_successor.campaign_name] = peer_successor
    (setup.spec.campaign_dir / f"{peer_successor.campaign_name}.yml").write_bytes(plan.render_lane_campaign(peer_successor, setup.sites))
    peer_plan = setup.spec.data_root / "forbidden-peer-g02-plan.json"
    setup.write_plan(peer_plan, [peer_successor])
    peer_spec = replace(setup.spec, plan_receipt=peer_plan)
    peer_spec_path = setup.spec.data_root / "forbidden-peer-g02-spec.json"
    _write(peer_spec_path, {"schema_version": 1, "artifact_type": evidence.SPEC_TYPE, "inputs": peer_spec.serializable()})
    with pytest.raises(ValueError, match="completed lane"):
        _prepare(setup, [peer_successor, setup.lanes[12]], spec_path=peer_spec_path,
                 second_spec=setup.spec_path, predecessors=[peer_intent, None])
    assert not (setup.root / "lanes" / peer_successor.campaign_name).exists()
    assert not (setup.root / "lanes" / setup.lanes[12].campaign_name).exists()
    assert _snapshot(first_intent.parent, peer_intent.parent, *first_batch.results) == retained
