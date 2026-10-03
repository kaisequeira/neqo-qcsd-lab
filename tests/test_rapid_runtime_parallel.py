"""Activated runtime workers retain real class, retry and canary authority.

Image/network and packet reads use the existing repair fixtures. Registered
coverage reopens actual typed worker starts, process exits and Docker retirement.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_class_epochs as classes
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_capture as shared
from qcsd_lab import rapid_runtime_epochs as runtime
from tests.test_rapid_class_epochs import block, lane_setup, rewrite, study
from tests.test_rapid_class_parallel import (
    _registered_result,
    _snapshot,
    registered_study,
)
from tests.test_rapid_formal_parallel import (
    _close as close_actual_batch,
    _initialize as initialize_actual_batch,
    _release as release_actual_batch,
    _retire as retire_actual_worker,
)
from tests.test_rapid_runtime_epochs import activate, repair


def _claim(state, activation, **kwargs):
    with lanes.capture_lock(state.spec.execution_root):
        return runtime.prepare_repaired_lane_intent(state.spec, state.root, activation, **kwargs)


def _preserved(state):
    peer = next((state.spec.execution_root / "results" / state.unchanged.parent.name).iterdir())
    failed = next((state.spec.execution_root / "results" / state.failed.parent.name).iterdir())
    return (state.unchanged.parent, peer, state.failed.parent, failed)


def test_activated_parallel_intent_preserves_actual_failed_and_completed_peer(repair):
    state = repair
    activation = activate(state)
    roots = _preserved(state)
    before = _snapshot(*roots)
    intent_path = _claim(state, activation, actuator=formal.ACTUATOR)
    intent, block_value, sites, lane = runtime.validate_intent(state.spec, state.root, intent_path)
    assert intent["actuator"] == formal.ACTUATOR and intent["scientific_credit"] is False
    assert lane.mode == "buflo" and lane.generation == 2 and lane.sample_count == 20 and len(sites) == 50
    assert intent["runtime_epoch"] == classes._reference(state.root, activation)
    assert intent["runtime_identity"] == classes._runtime_identity(state.new_proof)
    assert intent["predecessor_attempt"] == classes._attempt_inventory(state.spec, state.root, state.failed,
        classes._intent(state.spec, state.root, state.failed)[3])
    assert not (intent_path.parent / "host-start.json").exists()
    assert not (state.spec.execution_root / "results" / lane.campaign_name).exists()
    assert _snapshot(*roots) == before
    assert classes.verify_lane(state.spec, state.root, state.unchanged)["accepted"] == 20
    with pytest.raises(FileExistsError, match="previously claimed"):
        _claim(state, activation, actuator=formal.ACTUATOR)


@pytest.mark.parametrize("mutation", ["activation", "block", "generation", "condition", "source"])
def test_resealed_parallel_repair_intent_rejects_changed_authority(repair, mutation):
    state = repair
    activation = activate(state)
    intent_path = _claim(state, activation, actuator=formal.ACTUATOR)
    intent = runtime.open_intent(intent_path)
    if mutation == "activation":
        intent["runtime_epoch"] = classes._reference(state.root, state.unchanged)
    elif mutation == "block":
        other = block(state, number=2)
        intent["epoch_declaration"] = classes._reference(state.root, other)
        intent["lineage"] = intent["epoch_declaration"]
    elif mutation == "generation":
        intent["generation"] = 3
    elif mutation == "condition":
        intent["mode"] = "cs-buflo"
    else:
        intent["runtime_identity"]["collection_image_digest"] = state.spec.collection_image_digest
    rewrite(intent_path, runtime.INTENT_TYPE, intent)
    with pytest.raises(ValueError):
        runtime.validate_intent(state.spec, state.root, intent_path)


@pytest.mark.parametrize("predecessor", ["finished-peer", "finished-repaired"])
def test_parallel_repair_cannot_consume_a_completed_predecessor(repair, predecessor):
    state = repair
    activation = activate(state)
    if predecessor == "finished-peer":
        previous = state.unchanged.parent / "intent.json"
    else:
        completed = runtime.launch_repaired_lane(state.spec, state.root, activation)
        previous = completed.parent / "intent.json"
    before = _snapshot(*_preserved(state), previous.parent)
    with pytest.raises(ValueError, match="immediate failed lane|actual incomplete"):
        _claim(state, activation, predecessor_intent=previous, actuator=formal.ACTUATOR)
    assert _snapshot(*_preserved(state), previous.parent) == before


def test_parallel_same_runtime_g03_binds_actual_incomplete_g02_without_new_canary(repair):
    state = repair
    activation = activate(state)
    state.fail_new = True
    with pytest.raises(ValueError):
        runtime.launch_repaired_lane(state.spec, state.root, activation)
    declaration = classes._child(state.root, classes._open(state.failed, lanes.INTENT_TYPE)["epoch_declaration"])
    predecessor = next((declaration.parent / "lanes").glob("*-g02-*/intent.json"))
    predecessor_lane = runtime.validate_intent(state.spec, state.root, predecessor)[3]
    roots = (*_preserved(state), predecessor.parent,
             state.spec.execution_root / "results" / predecessor_lane.campaign_name, activation.parent)
    before = _snapshot(*roots)
    intent_path = _claim(state, activation, predecessor_intent=predecessor, actuator=formal.ACTUATOR)
    intent, _, _, lane = runtime.validate_intent(state.spec, state.root, intent_path)
    assert lane.generation == 3 and intent["runtime_identity"] == runtime.open_intent(predecessor)["runtime_identity"]
    assert intent["predecessor_attempt"] == classes._attempt_inventory(state.spec, state.root, predecessor, predecessor_lane)
    assert len(list(activation.parent.glob("canaries/*/complete.json"))) == 2
    assert _snapshot(*roots) == before


@pytest.fixture
def registered_runtime(registered_study, monkeypatch):
    state = repair.__wrapped__(registered_study, monkeypatch)
    state.buflo_activation = activate(state)
    declaration = classes._child(state.root, classes._open(state.failed, lanes.INTENT_TYPE)["epoch_declaration"])
    state.fail_mode = "cs-buflo"
    with pytest.raises(ValueError):
        classes.launch_block_lane(state.spec, state.root, declaration, mode="cs-buflo")
    state.fail_mode = None
    declared, sites = classes.verify_block(state.spec, state.root, declaration)
    failed_lane = classes._epoch_lane(declared, sites, "cs-buflo")
    state.cs_failed = declaration.parent / "lanes" / failed_lane.campaign_name / "intent.json"
    state.cs_proposal = runtime.propose_epoch(state.spec, state.root, state.runtime_spec,
                                             failed_intent=state.cs_failed, review=state.review)
    for mode in ("undefended", "cs-buflo"):
        runtime.launch_canary(state.spec, state.root, state.cs_proposal, mode=mode)
    state.cs_activation = runtime.activate_epoch(state.spec, state.root, state.cs_proposal)
    state.declaration = declaration
    return state


def test_registered_activated_runtime_pair_reopens_its_actual_image_and_workers(registered_runtime):
    state = registered_runtime
    preserved_roots = (*_preserved(state), state.cs_failed.parent,
        state.spec.execution_root / "results" / state.cs_failed.parent.name)
    before = _snapshot(*preserved_roots)
    declared, sites = classes.verify_block(state.spec, state.root, state.declaration)
    selected = [classes._epoch_lane(declared, sites, mode, 2) for mode in ("buflo", "cs-buflo")]
    state.lane_lookup.update({lane.campaign_name: lane for lane in selected})
    path = state.spec.data_root / "activated-pair-authority.json"
    requests = [dict(declaration=state.declaration, mode=mode, generation=2,
                     predecessor=None, activation=activation)
                for mode, activation in zip(("buflo", "cs-buflo"),
                    (state.buflo_activation, state.cs_activation), strict=True)]
    formal.prepare_registered_batch(state.spec_path, state.root, requests, path)
    output = state.spec.execution_root / "results" / "activated-pair-batch"
    output.mkdir()
    batch = SimpleNamespace(path=path, output=output, lanes=selected, value=formal.authority(path),
        digest=shared.sha(path.read_bytes()), setup=SimpleNamespace(spec=state.runtime_spec, root=state.root,
                                                                  sites=state.sites))
    initialize_actual_batch(batch)
    proof = shared.load(output / "image-preflight.json")
    assert proof["worker_epoch_proofs"] == [None, None]
    assert proof["worker_runtime_proofs"] == [state.new_proof, state.new_proof]
    for index, lane in enumerate(selected):
        inputs = formal.worker_inputs(path, index)
        environment = inputs["environment"]
        assert set(environment) == {"QCSD_RAPID_EPOCH_LAUNCH_INPUT", runtime.COMPATIBILITY_ENV}
        capsule, _ = runtime.validate_capsule(Path(environment[runtime.COMPATIBILITY_ENV]),
                                              actual_image=state.runtime_spec.collection_image_digest)
        assert capsule["intent_sha256"] == shared.sha(Path(batch.value["lane_intents"][index]["path"]).read_bytes())
        assert inputs["campaign_name"] == lane.campaign_name
    release_actual_batch(batch)
    for index in range(2):
        _registered_result(batch, index)
        retire_actual_worker(batch, index, 0, peer_running=index == 0)
    close_actual_batch(batch, 0)
    checked = formal.verify_results(path, output)
    assert checked["valid"] is True and [row["accepted"] for row in checked["lanes"]] == [20, 20]
    assert checked["formal_accepted_trace_count"] == 0
    for row in batch.value["lane_intents"]:
        intent_path = Path(row["path"])
        assert classes.verify_lane(state.spec, state.root, intent_path.parent / "complete.json")["runtime_epoch"]
    assert _snapshot(*preserved_roots) == before
