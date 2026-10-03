"""Runtime repair integration with only image/network/packet actuation replaced.

The separate compatibility suite exercises actual source-role derivation. Here
image outputs are fixtures; real planner slots, intent ancestry, process/DNS
bindings, deep result contract, canary chronology and block commits run intact.
These tests grant no live capture authority.
"""
import copy
import json
import os
import sys
from dataclasses import replace

import pytest

from qcsd_lab import rapid_class_epochs as classes
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_runtime_epochs as runtime
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_class_epochs import study, block, rewrite
from tests.test_rapid_lane_evidence import setup as lane_setup
from tests.test_rapid_runtime_compatibility import (
    original_sources, changed_sources, runtime as make_runtime, review as make_review,
)
from qcsd_lab import chaff_qualification as qualification


@pytest.fixture
def repair(study, monkeypatch):
    spec, root = study.spec, study.root
    # The existing unit fixture has synthetic sources outside its data root.
    # Full real-source compatibility and layout rejection have separate tests.
    monkeypatch.setattr(runtime, "_matching_layout", lambda base, proposed: None)
    monkeypatch.setattr(runtime, "durable_create", classes.durable_create)
    monkeypatch.setattr(runtime, "_sources", lambda current: {"collector": b"fixture source"})
    bridge = {"source_roles": "fixture image/source actuation"}
    monkeypatch.setattr(runtime.compatibility, "validate_compatibility", lambda *args: copy.deepcopy(bridge))
    runtime.initialize_policy(spec, root)
    declaration = block(study)
    study.unchanged = classes.launch_block_lane(spec, root, declaration, mode="front")
    study.unchanged_raw = study.unchanged.read_bytes()
    study.fail_mode = "buflo"
    with pytest.raises(ValueError):
        classes.launch_block_lane(spec, root, declaration, mode="buflo")
    study.fail_mode = None
    value, sites = classes.verify_block(spec, root, declaration)
    failed_lane = classes._epoch_lane(value, sites, "buflo")
    study.failed = declaration.parent / "lanes" / failed_lane.campaign_name / "intent.json"
    study.failed_raw = study.failed.read_bytes()
    study.runtime_spec = replace(spec, collection_image_digest="sha256:" + "7" * 64,
                                 execution_generation="reviewed-repair-002")
    new_proof = copy.deepcopy(runtime._runtime_projection(study.proof))
    new_proof["collection_image_digest"] = study.runtime_spec.collection_image_digest
    new_proof["runtime_source"]["image_digest"] = study.runtime_spec.collection_image_digest
    new_proof["runtime_source"]["lab_commit"] = "8" * 40
    new_proof["qualification_implementation"]["source"]["lab_commit"] = "8" * 40
    study.new_proof = copy.deepcopy(new_proof)
    study.fail_new = False

    def check_candidate(base, proposed, evidence_root, old_proof, review):
        started = admission._now()
        proof = {"runtime_proof": copy.deepcopy(new_proof), "compatibility_bridge": copy.deepcopy(bridge)}
        execution = {"command": runtime._candidate_command(base, proposed, old_proof, review), "returncode": 0,
            "started_at": started, "completed_at": admission._now(),
            "stdout": lanes._put_object(root, admission._json(proof)), "stderr": lanes._put_object(root, b""),
            "validator_script_sha256": classes._sha(runtime.CANDIDATE_SCRIPT.encode())}
        return {"execution": execution, "proof": proof}

    monkeypatch.setattr(runtime, "_check_candidate", check_candidate)
    original_actuate = lanes._actuate_host
    monkeypatch.setattr(lanes, "executed_image_runtime_check", lambda inputs:
        copy.deepcopy(new_proof) if inputs["collection_image_digest"] == study.runtime_spec.collection_image_digest
        else copy.deepcopy(runtime._runtime_projection(study.proof)))

    def actuate(current_spec, current_root, directory, command, env, descriptor):
        kind = runtime._kind(directory / "intent.json")
        if kind == lanes.INTENT_TYPE:
            return original_actuate(current_spec, current_root, directory, command, env, descriptor)
        intent = runtime.open_intent(directory / "intent.json")
        if kind == runtime.CANARY_INTENT_TYPE:
            proposal = classes._open(classes._child(root, intent["proposal"]), runtime.PROPOSAL_TYPE)
            lane, effective = runtime._canary_lane(spec, root, proposal, intent["mode"])
            declared, _ = classes.verify_block(spec, root, classes._child(root, proposal["declaration"]))
        else:
            intent, declared, effective, lane = runtime.validate_intent(spec, root, directory / "intent.json")
        assert env[runtime.COMPATIBILITY_ENV]
        capsule, _ = runtime.validate_capsule(__import__("pathlib").Path(env[runtime.COMPATIBILITY_ENV]),
                                            actual_image=current_spec.collection_image_digest)
        assert capsule["intent_sha256"] == classes._sha((directory / "intent.json").read_bytes())
        classes.validate_host_epoch_launch(json.loads(env["QCSD_RAPID_EPOCH_LAUNCH_INPUT"]),
            expected_campaign=lane.campaign_name, actual_image=current_spec.collection_image_digest)
        started = admission._now()
        identity = lanes._process_identity(os.getpid())
        start = {"command": command, "execution_root": str(spec.execution_root), "started_at": started,
            "intent_sha256": classes._sha((directory / "intent.json").read_bytes()),
            "host": {**identity, "argv": [sys.executable, "-c", lanes.HOST_GATE_SCRIPT, json.dumps(command), "7"]},
            "supervisor": {**identity, "argv": [sys.executable, "-c", lanes.SUPERVISOR_SCRIPT,
                json.dumps({"command": command, "execution_root": str(spec.execution_root)}), "8"]},
            "gate_script_sha256": classes._sha(lanes.HOST_GATE_SCRIPT.encode()),
            "supervisor_script_sha256": classes._sha(lanes.SUPERVISOR_SCRIPT.encode())}
        classes._write(directory / "host-start.json", lanes.PROCESS_START_TYPE, start)
        hosts = sorted({"cdn.example", *(f"site{index}.example" for index in range((lane.shard - 1) * 5, lane.shard * 5))})
        (directory / "dns.json").write_bytes(admission._json({"schema_version": 1, "campaign": lane.campaign_name,
                                                           "hosts": [[host, "8.8.8.8"] for host in hosts]}))
        result = spec.execution_root / "results" / lane.campaign_name / "run-001"
        result.mkdir(parents=True)
        samples = [{"sample_id": f"{index + 1:064x}", "workload_id": identifier, "visit": visit,
                    "defense": lane.mode, "state": "accepted", "request_policy": "as-defined", "attempts": 1,
                    "failure": None} for index, (identifier, visit) in enumerate(
                        (identifier, visit) for identifier in lane.workload_ids for visit in range(lane.visits_per_workload))]
        experiment = {"name": lane.campaign_name, "purpose": "smoke" if lane.role == "diagnostic" else "evaluation",
            "status": "complete", "started_at": admission._now(), "completed_at": admission._now(),
            "source": intent["runtime_identity"]["runtime_source"], "samples": samples,
            "configuration": {"campaign_sha256": intent["campaign_sha256"], "profile": "research-1200",
                "request_policies": ["as-defined"], "chaff_qualification_set": lane.qualification_set,
                "chaff_qualification_set_manifest_sha256": declared["qualification"]["manifest_sha256"] if lane.qualification_set else None,
                "defenses": [{"name": lane.mode}], "workloads": [{"id": site.workload_id, "sha256": site.workload_sha256,
                    "visits": lane.visits_per_workload} for site in effective if site.workload_id in lane.workload_ids]},
            "summary": {"planned": lane.sample_count, "accepted": lane.sample_count, "failed": 0, "passed": True}}
        if study.fail_new:
            experiment["status"] = "incomplete"
            samples[0]["state"] = "failed"
            experiment["summary"] = {"planned": lane.sample_count, "accepted": lane.sample_count - 1, "failed": 1, "passed": False}
        (result / "experiment.json").write_bytes(admission._json(experiment))
        (result / "evidence.sha256").write_bytes(b"fixture ordinary packet seal\n")
        (directory / "host.stdout.log").write_bytes(b"fixture actual host stdout\n")
        (directory / "host.stderr.log").write_bytes(b"")
        classes._write(directory / "host-process.json", lanes.PROCESS_TYPE, {"command": command,
            "execution_root": str(spec.execution_root), "started_at": started, "completed_at": admission._now(),
            "returncode": 1 if study.fail_new else 0, "interruption": None,
            "start": lanes._put_object(root, (directory / "host-start.json").read_bytes()),
            "stdout": lanes._put_object(root, (directory / "host.stdout.log").read_bytes()),
            "stderr": lanes._put_object(root, (directory / "host.stderr.log").read_bytes())})

    monkeypatch.setattr(lanes, "_actuate_host", actuate)
    study.review = {"fixture": "source role review is exercised independently"}
    study.proposal = runtime.propose_epoch(spec, root, study.runtime_spec,
                                           failed_intent=study.failed, review=study.review)
    return study


def activate(state):
    for mode in ("undefended", "buflo"):
        receipt = runtime.launch_canary(state.spec, state.root, state.proposal, mode=mode)
        assert runtime.verify_canary(state.spec, state.root, receipt)["accepted"] == 5
    return runtime.activate_epoch(state.spec, state.root, state.proposal)


def test_failed_defense_repairs_only_its_lane_and_keeps_finished_old_runtime(repair):
    activation = activate(repair)
    receipt = runtime.launch_repaired_lane(repair.spec, repair.root, activation)
    checked = classes.verify_lane(repair.spec, repair.root, receipt)
    assert checked["accepted"] == 20
    assert checked["runtime_epoch"] == classes._reference(repair.root, activation)
    assert "-g02-e0001" in checked["campaign_name"]
    assert classes.verify_lane(repair.spec, repair.root, repair.unchanged)["accepted"] == 20
    assert repair.unchanged.read_bytes() == repair.unchanged_raw
    assert repair.failed.read_bytes() == repair.failed_raw
    declaration = classes._child(repair.root, classes._open(repair.failed, lanes.INTENT_TYPE)["epoch_declaration"])
    for mode in ("undefended", "tamaraw", "cs-buflo"):
        classes.launch_block_lane(repair.spec, repair.root, declaration, mode=mode)
    committed = classes.commit_block(repair.spec, repair.root, declaration)
    assert classes.verify_commit(repair.spec, repair.root, committed)["accepted"] == 100


def test_incomplete_or_absent_canaries_cannot_activate(repair):
    with pytest.raises((ValueError, FileNotFoundError)):
        runtime.activate_epoch(repair.spec, repair.root, repair.proposal)
    repair.fail_new = True
    with pytest.raises(ValueError, match="successful terminal"):
        runtime.launch_canary(repair.spec, repair.root, repair.proposal, mode="undefended")
    with pytest.raises((ValueError, FileNotFoundError)):
        runtime.activate_epoch(repair.spec, repair.root, repair.proposal)


def test_failed_candidate_can_retire_and_next_epoch_preserves_it(repair):
    repair.fail_new = True
    with pytest.raises(ValueError):
        runtime.launch_canary(repair.spec, repair.root, repair.proposal, mode="buflo")
    retirement = runtime.retire_candidate(repair.spec, repair.root, repair.proposal, reason="observer failure diagnosed")
    assert runtime.verify_candidate_retirement(repair.spec, repair.root, retirement)["formal_accepted_trace_count"] == 0
    repair.fail_new = False
    second = runtime.propose_epoch(repair.spec, repair.root, repair.runtime_spec,
                                   failed_intent=repair.failed, review=repair.review)
    assert second.parent.name == "e0003"
    with pytest.raises(ValueError, match="retired"):
        runtime.launch_canary(repair.spec, repair.root, repair.proposal, mode="undefended")
    # A sealed successor cannot conceal the actual failed candidate history.
    retirement.unlink()
    with pytest.raises(ValueError, match="previous candidate"):
        runtime.verify_proposal(repair.spec, repair.root, second)


def test_same_runtime_transient_retry_does_not_repeat_canary(repair):
    activation = activate(repair)
    repair.fail_new = True
    with pytest.raises(ValueError):
        runtime.launch_repaired_lane(repair.spec, repair.root, activation)
    declaration = classes._child(repair.root, classes._open(repair.failed, lanes.INTENT_TYPE)["epoch_declaration"])
    failed = next(path for path in (declaration.parent / "lanes").glob("*g02*/intent.json"))
    repair.fail_new = False
    result = runtime.launch_repaired_lane(repair.spec, repair.root, activation, predecessor_intent=failed)
    assert classes.verify_lane(repair.spec, repair.root, result)["generation"] == 3
    assert len(list(activation.parent.glob("canaries/*/complete.json"))) == 2


@pytest.mark.parametrize("mutation", ["slots", "condition", "image", "predecessor"])
def test_resealed_repaired_intent_cannot_change_slots_or_runtime(repair, mutation):
    receipt = runtime.launch_repaired_lane(repair.spec, repair.root, activate(repair))
    path = receipt.parent / "intent.json"
    value = classes._open(path, runtime.INTENT_TYPE)
    if mutation == "slots":
        value["generation"] = 4
    elif mutation == "condition":
        value["mode"] = "front"
    elif mutation == "image":
        value["runtime_identity"]["collection_image_digest"] = repair.spec.collection_image_digest
    else:
        value["predecessor_intent"] = classes._reference(repair.root, repair.unchanged.parent / "intent.json")
    rewrite(path, runtime.INTENT_TYPE, value)
    with pytest.raises(ValueError):
        classes.verify_lane(repair.spec, repair.root, receipt)


def test_resealed_canary_completion_cannot_invent_extra_visits(repair):
    path = runtime.launch_canary(repair.spec, repair.root, repair.proposal, mode="undefended")
    value = classes._open(path, runtime.CANARY_COMPLETE_TYPE)
    value["accepted"] = 20
    rewrite(path, runtime.CANARY_COMPLETE_TYPE, value)
    with pytest.raises(ValueError, match="actual ordinary deep"):
        runtime.verify_canary(repair.spec, repair.root, path)


def test_runtime_policy_must_precede_any_formal_attempt(study, monkeypatch):
    monkeypatch.setattr(runtime, "_matching_layout", lambda *args: None)
    declaration = block(study)
    classes.launch_block_lane(study.spec, study.root, declaration, mode="front")
    with pytest.raises(ValueError, match="precede"):
        runtime.initialize_policy(study.spec, study.root)


def test_resealed_policy_cannot_promote_an_earlier_formal_attempt(repair):
    path = repair.root / "runtime-epochs/policy.json"
    value = classes._open(path, runtime.POLICY_TYPE)
    value["published_at"] = admission._now()
    rewrite(path, runtime.POLICY_TYPE, value)
    with pytest.raises(ValueError, match="predates prospective"):
        classes._intent(repair.spec, repair.root, repair.unchanged.parent / "intent.json")


def test_resealed_proposal_cannot_predate_runtime_policy(repair):
    value = classes._open(repair.proposal, runtime.PROPOSAL_TYPE)
    value["proposed_at"] = "2000-01-01T00:00:00+00:00"
    rewrite(repair.proposal, runtime.PROPOSAL_TYPE, value)
    with pytest.raises(ValueError, match="predates prospective"):
        runtime.verify_proposal(repair.spec, repair.root, repair.proposal)


def test_full_corpus_reopens_all_16000_slots_with_one_repaired_runtime(repair):
    activation = activate(repair)
    runtime.launch_repaired_lane(repair.spec, repair.root, activation)
    for number in range(1, 17):
        for shard in range(1, 11):
            if (number, shard) == (1, 1):
                declaration = classes._child(repair.root, classes._open(repair.failed, lanes.INTENT_TYPE)["epoch_declaration"])
                modes = ("undefended", "tamaraw", "cs-buflo")
            else:
                declaration = block(repair, number=number, shard=shard)
                modes = ("undefended", "front", "tamaraw", "buflo", "cs-buflo")
            for mode in modes:
                classes.launch_block_lane(repair.spec, repair.root, declaration, mode=mode)
            classes.commit_block(repair.spec, repair.root, declaration)
    manifest = classes.corpus_manifest(repair.spec, repair.root)
    assert manifest["accepted"] == 16000
    assert manifest["artifact_type"] == runtime.CORPUS_TYPE
    assert len(manifest["blocks"]) == 160
    assert manifest["collection_runtime_epochs"] == [{"activation": classes._reference(repair.root, activation)}]
    assert classes.verify_corpus_manifest(repair.spec, repair.root, manifest)["accepted"] == 16000
    assert repair.unchanged.read_bytes() == repair.unchanged_raw


def test_current_qualification_rejects_changed_collector_without_registered_authority(original_sources, monkeypatch):
    old, new, _ = changed_sources(original_sources)
    original = make_runtime(old)["qualification_implementation"]
    current = make_runtime(new, successor=True)["qualification_implementation"]
    monkeypatch.delenv(runtime.COMPATIBILITY_ENV, raising=False)
    monkeypatch.setattr(qualification, "implementation_receipt", lambda **kwargs: current)
    monkeypatch.setattr(qualification, "_implementation_source_files", lambda: current["source_files"])
    with pytest.raises(ValueError, match="source files have changed"):
        qualification._validate_implementation_receipt(original, require_current=True)


def test_opt_in_current_qualification_uses_reopened_actual_role_bridge(original_sources, monkeypatch):
    old, new, functions = changed_sources(original_sources)
    before, after = make_runtime(old), make_runtime(new, successor=True)
    bridge = runtime.compatibility.validate_compatibility(before, after, old, new, make_review(old, new, functions))
    observed = []
    def capsule(path, *, actual_image):
        observed.append((str(path), actual_image))
        return {}, bridge
    monkeypatch.setattr(runtime, "validate_capsule", capsule)
    monkeypatch.setenv(runtime.COMPATIBILITY_ENV, "/lab/config/rapid-runtime-epochs/bound-capsule.json")
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", after["collection_image_digest"])
    monkeypatch.setattr(qualification, "implementation_receipt", lambda **kwargs: after["qualification_implementation"])
    qualification._validate_implementation_receipt(before["qualification_implementation"], require_current=True)
    assert observed == [("/lab/config/rapid-runtime-epochs/bound-capsule.json", after["collection_image_digest"])]
    changed = copy.deepcopy(after["qualification_implementation"])
    changed["neqo_qcsd_client"]["sha256"] = "0" * 64
    changed["sha256"] = qualification._implementation_aggregate(changed)
    monkeypatch.setattr(qualification, "implementation_receipt", lambda **kwargs: changed)
    with pytest.raises(ValueError, match="another installed"):
        qualification._validate_implementation_receipt(before["qualification_implementation"], require_current=True)
