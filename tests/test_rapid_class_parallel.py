"""Class receipt control seams and actual typed Docker lifecycle validators.

Block declarations, installed-source checks, retry inventories, formal geometry,
DNS, capture clocks and peer scheduler result bindings use their real validators.
Isolated cases replace the Docker boundary; the registered case reopens actual
typed birth/process/retirement receipts with the real container fixture inventory.
"""

from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_class_epochs as epochs
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_capture as shared
from qcsd_lab import orchestrator, runtime_provenance
from qcsd_lab.process_scheduler import build_peer_host_partition
from tests.test_process_scheduler import _peer_inputs
from tests.test_rapid_class_epochs import block, lane_setup, rewrite, study
from tests.test_rapid_formal_parallel import (
    _close as _close_actual_batch,
    _initialize as _initialize_actual_batch,
    _release as _release_actual_batch,
    _result as _actual_result,
    _retire as _retire_actual_worker,
)


def _snapshot(*roots):
    return {str(path): (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino)
            for root in roots for path in root.rglob("*") if path.is_file()}


def _claim(study, declaration, mode, **kwargs):
    with lanes.capture_lock(study.spec.execution_root):
        return epochs.prepare_block_lane_intent(study.spec, study.root, declaration,
                                                mode=mode, **kwargs)


@pytest.fixture
def parallel(study, monkeypatch):
    state = SimpleNamespace(study=study, actuate=lanes._actuate_host, records={}, closure_calls=[])
    inspected, workers, sidecars = _peer_inputs()
    for index, worker in enumerate(workers):
        worker["image_id"] = study.spec.collection_image_digest
        inspected[index]["Image"] = worker["image_id"]
    state.partitions = [build_peer_host_partition(inspected, [0, 2, 4, 7, 9], workers,
                         sidecars, worker["id"], docker_ncpu=16) for worker in workers]

    def verified(raw, root, intent_raw, campaign):
        value = lanes.admission._unpack(raw, formal.PROCESS_TYPE)
        record = state.records[campaign]
        assert root == study.root
        if (value != record.process or intent_raw != record.intent.read_bytes()
                or type(value["returncode"]) is not int):
            raise ValueError("fixture actual typed Docker process changed")
        return {**value, "actuator": formal.ACTUATOR, "campaign_name": campaign,
                "batch_root": str(record.batch), "worker_index": record.index}

    def closure(process):
        state.closure_calls.append(process["campaign_name"])
        if not (Path(process["batch_root"]) / "closed.json").is_file():
            raise ValueError("fixture actual batch operator is still active")

    monkeypatch.setattr(formal, "verified_worker_process", verified)
    monkeypatch.setattr(formal, "require_batch_closure", closure)
    return state


def _capture(parallel, declaration, mode, *, index=0, batch=None, generation=1, predecessor=None):
    study = parallel.study
    intent = _claim(study, declaration, mode, generation=generation,
                    predecessor_intent=predecessor, actuator=formal.ACTUATOR)
    batch = batch or study.spec.execution_root / "results" / "fixture-parallel-batch"
    gate = batch / f"lane-{index+1}" / "gate"
    gate.mkdir(parents=True, exist_ok=True)
    shared.put(gate / "host-partition.json", parallel.partitions[index])
    env = dict(os.environ)
    env["QCSD_RAPID_EPOCH_LAUNCH_INPUT"] = json.dumps({
        "spec": study.spec.serializable(), "root": str(study.root), "intent": str(intent),
        "intent_sha256": epochs._sha(intent.read_bytes())})
    command = [str(study.spec.host_launcher), "run", str(study.spec.campaign_dir / f"{intent.parent.name}.yml")]
    with lanes.capture_lock(study.spec.execution_root) as descriptor:
        parallel.actuate(study.spec, study.root, intent.parent, command, env, descriptor)
    result = next((study.spec.execution_root / "results" / intent.parent.name).iterdir())
    experiment_path = result / "experiment.json"
    experiment = shared.load(experiment_path)
    for sample in experiment["samples"]:
        sample["diagnostics"] = {"scheduler_runtime_receipt": {"scheduler_runtime_evidence": {
            "schema_version": 5, "host_partition": parallel.partitions[index]}}}
    experiment_path.write_bytes(lanes._json(experiment))
    process = epochs._open(intent.parent / "host-process.json", lanes.PROCESS_TYPE)
    process["command"] = [str(study.spec.host_launcher), "parallel-formal-run",
                          str(study.spec.data_root / "fixture-authority.json"), str(batch)]
    process["retirement"] = lanes._put_object(study.root, b"fixture independently verified Docker retirement\n")
    rewrite(intent.parent / "host-process.json", formal.PROCESS_TYPE, process)
    record = SimpleNamespace(intent=intent, result=result, process=process, batch=batch, index=index)
    parallel.records[intent.parent.name] = record
    return record


def _close(batch):
    shared.put(batch / "closed.json", {"actual_operator_closed": True})


def test_helper_claims_create_only_parallel_intent_after_real_image_check(study, monkeypatch):
    declaration = block(study)
    checked = epochs.check_bound_image(study.spec, study.root, declaration)
    monkeypatch.setattr(epochs, "check_bound_image", lambda *args: pytest.fail("supplied image check was ignored"))
    intent = _claim(study, declaration, "buflo", checked=checked, actuator=formal.ACTUATOR)
    value, _, sites, lane = epochs._intent(study.spec, study.root, intent)
    assert value["actuator"] == formal.ACTUATOR
    assert len(sites) == 50 and lane.sample_count == 20 and value["scientific_credit"] is False
    assert not (intent.parent / "host-start.json").exists()
    assert not (study.spec.execution_root / "results" / lane.campaign_name).exists()
    before = _snapshot(intent.parent)
    with pytest.raises(FileExistsError, match="previously claimed"):
        _claim(study, declaration, "buflo", checked=checked, actuator=formal.ACTUATOR)
    assert _snapshot(intent.parent) == before


@pytest.mark.parametrize("mutation", ["actuator", "image-proof", "source", "result-symlink"])
def test_helper_rejects_unbound_authority_before_intent_creation(study, mutation):
    declaration = block(study)
    checked = epochs.check_bound_image(study.spec, study.root, declaration)
    actuator = formal.ACTUATOR
    if mutation == "actuator":
        actuator = "diagnostic"
    elif mutation == "image-proof":
        checked = copy.deepcopy(checked)
        checked["proof"]["base_proof"]["client_sha256"] = "0" * 64
    elif mutation == "source":
        study.spec.base_launcher.write_bytes(study.spec.base_launcher.read_bytes() + b"changed installed source\n")
    else:
        value, sites = epochs.verify_block(study.spec, study.root, declaration)
        lane = epochs._epoch_lane(value, sites, "buflo")
        namespace = study.spec.execution_root / "results" / lane.campaign_name
        namespace.parent.mkdir(exist_ok=True)
        namespace.symlink_to(namespace.parent / "missing")
    with pytest.raises((ValueError, FileExistsError)):
        _claim(study, declaration, "buflo", checked=checked, actuator=actuator)
    assert not list((declaration.parent / "lanes").glob("*/intent.json"))


def test_typed_worker_completes_independently_and_requires_closed_batch(parallel, monkeypatch):
    study = parallel.study
    declaration = block(study)
    first = _capture(parallel, declaration, "buflo")
    monkeypatch.setattr(lanes, "_validated_host_start", lambda *args, **kwargs: pytest.fail("typed worker invoked serial birth"))
    monkeypatch.setattr(lanes, "_retired_identity", lambda *args: pytest.fail("typed worker invoked serial process census"))
    receipt = epochs.complete_lane(study.spec, study.root, first.intent)
    assert epochs._open(receipt, epochs.COMPLETE_TYPE)["accepted"] == 20
    with pytest.raises(ValueError, match="operator is still active"):
        epochs.verify_lane(study.spec, study.root, receipt)
    _close(first.batch)
    checked = epochs.verify_lane(study.spec, study.root, receipt)
    assert checked["scientific_credit"] == "conditional-on-matched-block-commit"
    assert parallel.closure_calls == [first.intent.parent.name] * 2


@pytest.mark.parametrize("mutation", ["serial-process", "serial-intent"])
def test_parallel_intent_and_terminal_receipt_must_use_the_same_actuator(parallel, mutation):
    study = parallel.study
    declaration = block(study)
    record = _capture(parallel, declaration, "front")
    if mutation == "serial-process":
        process = dict(record.process)
        del process["retirement"]
        process["command"] = [str(study.spec.host_launcher), "run",
                              str(study.spec.campaign_dir / f"{record.intent.parent.name}.yml")]
        rewrite(record.intent.parent / "host-process.json", lanes.PROCESS_TYPE, process)
    else:
        intent = epochs._open(record.intent, lanes.INTENT_TYPE)
        intent["actuator"] = "run"
        rewrite(record.intent, lanes.INTENT_TYPE, intent)
    with pytest.raises(ValueError, match="actuator differs"):
        epochs.complete_lane(study.spec, study.root, record.intent)


@pytest.mark.parametrize("mutation", ["nonzero-exit", "missing-slot", "wrong-epoch", "clock", "dns", "peer", "source"])
def test_typed_worker_preserves_ordinary_deep_guards(parallel, mutation):
    study = parallel.study
    declaration = block(study)
    record = _capture(parallel, declaration, "cs-buflo")
    path = record.result / "experiment.json"
    experiment = shared.load(path)
    if mutation == "nonzero-exit":
        record.process["returncode"] = 1
        rewrite(record.intent.parent / "host-process.json", formal.PROCESS_TYPE, record.process)
    elif mutation == "missing-slot":
        experiment["samples"].pop()
    elif mutation == "wrong-epoch":
        experiment["name"] = experiment["name"].replace("-e0001", "-e0002")
    elif mutation == "clock":
        experiment["completed_at"] = "2099-01-01T00:00:00Z"
    elif mutation == "dns":
        dns_path = record.intent.parent / "dns.json"
        dns = shared.load(dns_path)
        dns["hosts"].pop()
        dns_path.write_bytes(lanes._json(dns))
    elif mutation == "peer":
        experiment["samples"][0]["diagnostics"]["scheduler_runtime_receipt"]["scheduler_runtime_evidence"]["host_partition"] = parallel.partitions[1]
    else:
        study.spec.base_launcher.write_bytes(study.spec.base_launcher.read_bytes() + b"changed installed source\n")
    path.write_bytes(lanes._json(experiment))
    with pytest.raises(ValueError):
        epochs.complete_lane(study.spec, study.root, record.intent)
    assert not (record.intent.parent / "complete.json").exists()


def test_failed_only_g02_keeps_completed_peer_and_actual_predecessor_immutable(parallel):
    study = parallel.study
    declaration = block(study)
    study.fail_mode = "buflo"
    failed = _capture(parallel, declaration, "buflo")
    with pytest.raises(ValueError, match="failed formal worker"):
        epochs.complete_lane(study.spec, study.root, failed.intent)
    study.fail_mode = None
    peer = _capture(parallel, declaration, "cs-buflo", index=1, batch=failed.batch)
    peer_receipt = epochs.complete_lane(study.spec, study.root, peer.intent)
    _close(failed.batch)
    assert epochs.verify_lane(study.spec, study.root, peer_receipt)["accepted"] == 20
    preserved = _snapshot(failed.intent.parent, failed.result, peer.intent.parent, peer.result)
    with pytest.raises(ValueError, match="immediate incomplete"):
        _claim(study, declaration, "cs-buflo", generation=2,
               predecessor_intent=peer.intent, actuator=formal.ACTUATOR)
    successor = _capture(parallel, declaration, "buflo", generation=2, predecessor=failed.intent,
                         batch=study.spec.execution_root / "results" / "fixture-successor-batch")
    receipt = epochs.complete_lane(study.spec, study.root, successor.intent)
    _close(successor.batch)
    assert epochs.verify_lane(study.spec, study.root, receipt)["generation"] == 2
    intent = epochs._open(successor.intent, lanes.INTENT_TYPE)
    assert intent["predecessor_attempt"] == epochs._attempt_inventory(study.spec, study.root, failed.intent,
        epochs._intent(study.spec, study.root, failed.intent)[3])
    assert _snapshot(failed.intent.parent, failed.result, peer.intent.parent, peer.result) == preserved
    raw = next(failed.result.rglob("run.json"))
    raw.write_bytes(raw.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="predecessor evidence"):
        epochs.verify_lane(study.spec, study.root, receipt)


def test_parallel_complete_capture_without_publication_cannot_become_g02(parallel):
    study = parallel.study
    declaration = block(study)
    complete = _capture(parallel, declaration, "front")
    with pytest.raises(ValueError, match="actual incomplete"):
        _claim(study, declaration, "front", generation=2,
               predecessor_intent=complete.intent, actuator=formal.ACTUATOR)
    assert not list(study.spec.campaign_dir.glob("*-g02-e0001.yml"))


def test_default_serial_launch_keeps_original_receipt_and_actuator(study):
    declaration = block(study)
    receipt = epochs.launch_block_lane(study.spec, study.root, declaration, mode="undefended")
    intent = epochs._open(receipt.parent / "intent.json", lanes.INTENT_TYPE)
    process = epochs._open(receipt.parent / "host-process.json", lanes.PROCESS_TYPE)
    assert intent["actuator"] == "run"
    assert process["command"] == [str(study.spec.host_launcher), "run",
                                  str(study.spec.campaign_dir / f"{receipt.parent.name}.yml")]
    assert epochs.verify_lane(study.spec, study.root, receipt)["accepted"] == 20


@pytest.fixture
def registered_study(lane_setup, monkeypatch):
    """Install the authentic coordinator beside the class fixture's source."""
    state = lane_setup
    state.spec = replace(state.spec, module_root=state.spec.runtime_source_root)
    state.spec.host_launcher.write_bytes(state.spec.base_launcher.read_bytes())
    project = Path(__file__).resolve().parents[1]
    source_files = dict(state.implementation["source_files"])
    for name in ("rapid_parallel_capture.py", "rapid_formal_parallel.py"):
        relative = f"src/qcsd_lab/{name}"
        target = state.spec.runtime_source_root / relative
        target.write_bytes((project / relative).read_bytes())
        source_files[relative] = shared.sha(target.read_bytes())
    state = study.__wrapped__(state, monkeypatch)
    monkeypatch.setattr(runtime_provenance, "validate_runtime_receipt",
                        lambda **kwargs: {"schema_version": 2, "source_files": source_files})
    state.spec_path = state.spec.data_root / "registered-capture-spec.json"
    shared.put(state.spec_path, {"schema_version": 1, "artifact_type": lanes.SPEC_TYPE,
                               "inputs": state.spec.serializable()})
    state.lane_lookup = {}
    state.sequence = 0

    def installed_campaign(path):
        lane = state.lane_lookup[Path(path).stem]
        workloads = []
        for name in lane.workload_ids:
            workload = state.spec.workload_root / f"{name}.json"
            manifest = (state.spec.campaign_dir.parent / "chaff-response-qualification-store/sets" /
                        f"shard-{int(name.removeprefix('site-')) // 5}" / "_qualification-set.json")
            workloads.append(SimpleNamespace(id=name, path=workload, data=shared.load(workload),
                sha256=shared.sha(workload.read_bytes()), visits=lane.visits_per_workload,
                chaff_qualification_path=None, chaff_manifest_path=None,
                qualification_set_manifest_path=manifest if lane.qualification_set else None))
        parameters = None
        if lane.mode == "buflo":
            parameters = state.spec.execution_root / "config/defense-params/buflo-live.json"
        elif lane.mode == "cs-buflo":
            parameters = state.spec.execution_root / "config/defense-params/cs-buflo-ctsp-live.json"
        return SimpleNamespace(path=Path(path), workloads=workloads,
            defenses=[SimpleNamespace(parameters_path=parameters, parameters_provenance_path=None)])

    monkeypatch.setattr(orchestrator, "load_campaign", installed_campaign)
    return state


def _registered_batch(state, declaration, modes, *, generations=(1, 1), predecessors=(None, None)):
    state.sequence += 1
    block_value, sites = epochs.verify_block(state.spec, state.root, declaration)
    selected = [epochs._epoch_lane(block_value, sites, mode, generation)
                for mode, generation in zip(modes, generations, strict=True)]
    state.lane_lookup.update({lane.campaign_name: lane for lane in selected})
    output = state.spec.execution_root / "results" / f"registered-batch-{state.sequence}"
    output.mkdir(parents=True)
    path = state.spec.data_root / f"registered-authority-{state.sequence}.json"
    requests = [dict(declaration=declaration, mode=mode, generation=generation,
                     predecessor=predecessor, activation=None)
                for mode, generation, predecessor in zip(modes, generations, predecessors, strict=True)]
    formal.prepare_registered_batch(state.spec_path, state.root, requests, path)
    batch = SimpleNamespace(path=path, output=output, lanes=selected, value=formal.authority(path),
                            digest=shared.sha(path.read_bytes()), setup=state)
    _initialize_actual_batch(batch)
    for index, lane in enumerate(selected):
        inputs = formal.worker_inputs(path, index)
        env = inputs["environment"]
        assert set(env) == {"QCSD_RAPID_EPOCH_LAUNCH_INPUT"}
        epochs.validate_host_epoch_launch(json.loads(env["QCSD_RAPID_EPOCH_LAUNCH_INPUT"]),
            expected_campaign=lane.campaign_name, actual_image=state.spec.collection_image_digest)
        argv_path = output / f"lane-{index+1}" / "worker-argv.json"
        argv = shared.load(argv_path)
        offset = argv.index("--entrypoint")
        argv[offset:offset] = [item for key, value in sorted(env.items()) for item in ("--env", key+"="+value)]
        argv_path.write_bytes(lanes._json(argv))
        batch.actual["inspected_containers"][index]["Config"]["Env"] = [key+"="+value for key, value in env.items()]
    (output / "actual-launch.json").write_bytes(lanes._json(batch.actual))
    return _release_actual_batch(batch)


def _registered_result(batch, index, *, failed=False):
    result = _actual_result(batch, index)
    experiment = shared.load(result / "experiment.json")
    intent = lanes._host_intent(Path(batch.value["lane_intents"][index]["path"]).read_bytes())
    experiment["source"] = intent["runtime_identity"]["runtime_source"]
    experiment["completed_at"] = shared.now()
    if failed:
        experiment["status"] = "incomplete"
        experiment["samples"][0]["state"] = "failed"
        experiment["samples"][0]["failure"] = {"type": "TransportFailure", "message": "fixture actual worker failure"}
        experiment["summary"] = {"planned": 20, "accepted": 19, "failed": 1, "passed": False}
    (result / "experiment.json").write_bytes(lanes._json(experiment))
    return result


@pytest.mark.parametrize("invalid_peer", ["boolean-generation", "claimed-intent"])
def test_registered_invalid_peer_cannot_claim_first_intent(registered_study, invalid_peer):
    state = registered_study
    declaration = block(state)
    block_value, sites = epochs.verify_block(state.spec, state.root, declaration)
    first = epochs._epoch_lane(block_value, sites, "buflo")
    if invalid_peer == "claimed-intent":
        peer = _claim(state, declaration, "cs-buflo", actuator=formal.ACTUATOR)
        preserved = _snapshot(peer.parent)
    requests = [dict(declaration=declaration, mode=mode,
                     generation=True if index == 1 and invalid_peer == "boolean-generation" else 1,
                     predecessor=None, activation=None)
                for index, mode in enumerate(("buflo", "cs-buflo"))]
    output = state.spec.data_root / "invalid-registered-authority.json"
    with pytest.raises((ValueError, FileExistsError)):
        formal.prepare_registered_batch(state.spec_path, state.root, requests, output)
    assert not (declaration.parent / "lanes" / first.campaign_name / "intent.json").exists()
    assert not (state.spec.execution_root / "results" / first.campaign_name).exists()
    assert not output.exists()
    if invalid_peer == "claimed-intent":
        assert _snapshot(peer.parent) == preserved


def test_registered_class_batch_reopens_actual_workers_and_failed_only_g02(registered_study):
    state = registered_study
    declaration = block(state)
    first = _registered_batch(state, declaration, ("buflo", "cs-buflo"))
    failed_result = _registered_result(first, 0, failed=True)
    failed_actual = _retire_actual_worker(first, 0, 1)
    assert failed_actual["peer_state"]["State"]["Running"] is True
    peer_result = _registered_result(first, 1)
    _retire_actual_worker(first, 1, 0, peer_running=False)
    _close_actual_batch(first, 1)
    first_checked = formal.verify_results(first.path, first.output)
    assert [lane["accepted"] for lane in first_checked["lanes"]] == [0, 20]
    assert first_checked["lanes"][1]["scientific_credit"] == "conditional-on-matched-block-commit"
    failed_intent, peer_intent = [Path(row["path"]) for row in first.value["lane_intents"]]
    preserved = _snapshot(failed_intent.parent, failed_result, peer_intent.parent, peer_result)
    successor = _registered_batch(state, declaration, ("buflo", "front"), generations=(2, 1),
                                  predecessors=(failed_intent, None))
    for index in range(2):
        _registered_result(successor, index)
        _retire_actual_worker(successor, index, 0, peer_running=index == 0)
    _close_actual_batch(successor, 0)
    checked = formal.verify_results(successor.path, successor.output)
    assert checked["valid"] is True and [row["accepted"] for row in checked["lanes"]] == [20, 20]
    assert checked["formal_accepted_trace_count"] == 0
    successor_intent = Path(successor.value["lane_intents"][0]["path"])
    assert epochs.verify_lane(state.spec, state.root, successor_intent.parent / "complete.json")["generation"] == 2
    assert _snapshot(failed_intent.parent, failed_result, peer_intent.parent, peer_result) == preserved
    assert epochs.verify_lane(state.spec, state.root, peer_intent.parent / "complete.json")["accepted"] == 20
    for mode in ("undefended", "tamaraw"):
        epochs.launch_block_lane(state.spec, state.root, declaration, mode=mode)
    commit = epochs.commit_block(state.spec, state.root, declaration)
    committed = epochs.verify_commit(state.spec, state.root, commit)
    assert committed["accepted"] == 100 and len(committed["unselected_attempts"]) == 1
    assert committed["unselected_attempts"][0]["result_inventory"]
    assert _snapshot(failed_intent.parent, failed_result, peer_intent.parent, peer_result) == preserved
