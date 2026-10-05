"""Remaining-slot planning and ordinary serial lineage; no physical effects.

The current admission/qualification/image boundary uses the established HOST
fixture. A separately supplied real progress fixture reopens its unchanged
original lane plans, deep outputs and experiment seals without granting credit.
"""
from dataclasses import asdict, replace
from pathlib import Path
import copy
import hashlib
import json
import os

import pytest
import yaml

from qcsd_lab import rapid_slot_chunks as chunks
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_rapid_lane_evidence import setup
from tests.test_rapid_rolling_capture import rolling_setup, _planned, _proof, _sites
from tools import rapid_rolling_capture as cli


def test_remaining_ranges_preserve_old_tamaraw_slots_and_gaps():
    assert chunks.ranges(set()) == ((0, 16), (16, 16), (32, 16), (48, 16))
    assert chunks.ranges(set(range(8, 32))) == ((0, 8), (32, 16), (48, 16))
    assert chunks.ranges(set(range(4))) == ((4, 16), (20, 16), (36, 16), (52, 12))
    assert chunks.ranges(set(range(64))) == ()


@pytest.mark.parametrize("accepted,maximum", [({True}, 16), ({-1}, 16), ({64}, 16), (set(), True), (set(), 17), (set(), 0)])
def test_unregistered_slot_bounds_refuse_before_planning(accepted, maximum):
    with pytest.raises(ValueError):
        chunks.ranges(accepted, maximum=maximum)


def test_five_modes_keep_64_slots_with_four_chunks_per_virgin_class():
    sites = _sites(5)
    classes = [{"workload_id": site.workload_id, "class_index": i + 1} for i, site in enumerate(sites)]
    policy = {"prior_slots": [], "modes": list(plan.MODES), "maximum_visits": 16}
    values = chunks.planned_lanes(sites, classes, policy, {"path": "/unused-policy", "sha256": "f" * 64}, shard=3)
    assert len(values) == 20 and sum(value.sample_count for value in values) == 5 * 5 * 64
    for mode in plan.MODES:
        selected = [value for value in values if value.mode == mode]
        assert [value.slot_start for value in selected] == [0, 16, 32, 48]
        assert all(value.visits_per_workload == 16 for value in selected)
        document = yaml.safe_load(chunks.render(selected[0], sites))
        assert document["workloads"] == {site.workload_id: 16 for site in sites}
        assert document["limits"] == plan.V5_CAPTURE_LIMITS
        if mode in plan.PARAMETER_REFERENCES:
            assert document["defenses"][0]["parameters"] == plan.PARAMETER_REFERENCES[mode]
    old = plan.plan_lanes(sites, final=True, study_version=6, rolling_batch=3)
    assert len(old) == 80 and all(value.visits_per_workload == 4 for value in old)


def test_different_prior_offsets_refuse_before_changing_named_qualification_membership():
    sites = _sites(2)
    classes = [{"workload_id": site.workload_id, "class_index": i + 1} for i, site in enumerate(sites)]
    old = [[1, "tamaraw", visit] for visit in range(8, 32)]
    with pytest.raises(ValueError, match="exact named qualification cohort"):
        chunks.planned_lanes(sites, classes, {"prior_slots": old, "modes": ["tamaraw"], "maximum_visits": 16},
                             {"path": "/unused-policy", "sha256": "f" * 64}, shard=3)


def test_singleton_existing_gap_and_tail_keep_explicit_logical_offsets():
    sites = _sites(1)
    classes = [{"workload_id": sites[0].workload_id, "class_index": 1}]
    old = [[1, "tamaraw", visit] for visit in range(8, 32)]
    values = chunks.planned_lanes(sites, classes, {"prior_slots": old, "modes": ["tamaraw"], "maximum_visits": 16},
                                  {"path": "/unused-policy", "sha256": "f" * 64}, shard=1)
    assert [(value.slot_start, value.visits_per_workload) for value in values] == [(0, 8), (32, 16), (48, 16)]
    assert sum(value.sample_count for value in values) == 40


@pytest.mark.parametrize("response,recording", [(16 * 1024 * 1024, 64), (64 * 1024 * 1024, 256)])
def test_chunks_preserve_whole_class_response_and_recording_budgets(response, recording):
    from qcsd_lab.supplied_static_admission import capture_limits
    sites = _sites(1)
    classes = [{"workload_id": sites[0].workload_id, "class_index": 1}]
    values = chunks.planned_lanes(sites, classes, {"prior_slots": [], "modes": list(plan.MODES), "maximum_visits": 16},
                                  {"path": "/unused-policy", "sha256": "f" * 64}, shard=1)
    declared = capture_limits(response, recording)
    for value in values:
        document = yaml.safe_load(chunks.render(value, sites, static_capture_limits=declared))
        assert document["limits"] == declared and document["workloads"] == {sites[0].workload_id: 16}
    malformed = asdict(values[0])
    malformed["workload_ids"] = "abc"
    with pytest.raises(ValueError, match="ordered list"):
        chunks.checked_lane(malformed)


@pytest.fixture
def chunk_setup(rolling_setup, monkeypatch):
    base, _ = _planned(rolling_setup, modes=("undefended", "front", "buflo", "tamaraw", "cs-buflo"))
    path = rolling_setup.root / "prior-slot-host-fixture.json"
    path.write_bytes(receipts._json({"engineering_fixture": "original Root progress is separately tested"}))
    prior_closed_at = lanes.plan_payload(base.plan_receipt.read_bytes())["declared_at"]
    # Substitutes only the retained external Root progress boundary. All new
    # policy/plan/campaign/layout and ordinary lineage validation stay real.
    monkeypatch.setattr(chunks, "prior_progress", lambda reference, classes:
        ({"closed_at": prior_closed_at}, set(), {rolling._open_ref(reference)}))
    policy = chunks.publish_policy(base, rolling._ref(path), rolling_setup.root / "chunk-policy.json",
                                   modes=list(plan.MODES))
    output = chunks.publish_plan(base, rolling._ref(policy), rolling_setup.root / "chunk-plan.json")
    return rolling_setup, base, replace(base, plan_receipt=output), policy


def test_public_chunk_plan_spec_and_image_proof_retain_current_qualified_inputs(chunk_setup):
    fixture, base, spec, policy = chunk_setup
    sites, value = rolling.verify_capture_plan(spec)
    assert len(value["lanes"]) == 20 and value["planned_trace_count"] == 320
    assert value["base_four_visit_plan"] == rolling._ref(base.plan_receipt)
    spec_path = fixture.root / "chunk-spec.json"
    rolling._write_spec(spec_path, spec)
    assert lanes.load_capture_spec(spec_path) == spec
    lane = lanes._lane({"plan_payload": value}, value["lanes"][0]["campaign_name"])
    assert isinstance(lane, chunks.ChunkLane) and lane.sample_count == 16
    assert lanes._render_lane_campaign(spec, lane, sites) == (spec.campaign_dir / (lane.campaign_name + ".yml")).read_bytes()
    assert policy.parent in rolling.enrollment_roots(spec)
    args = cli._parser().parse_args(["chunk-plan", "--spec", str(spec_path), "--slot-chunk-policy", str(policy),
                                    "--output", str(fixture.root / "new.json"), "--spec-output", str(fixture.root / "new-spec.json")])
    assert args.command == "chunk-plan"


@pytest.mark.parametrize("field", ["slot_start", "visits_per_workload", "slot_policy_sha256", "workload_ids"])
def test_rehashed_chunk_plan_cannot_change_registered_slots_or_graphs(chunk_setup, field):
    fixture, _, spec, _ = chunk_setup
    value = lanes.plan_payload(spec.plan_receipt.read_bytes())
    row = value["lanes"][0]
    row[field] = {"slot_start": 1, "visits_per_workload": 15, "slot_policy_sha256": "0" * 64,
                  "workload_ids": ["invented-workload"]}[field]
    path = rolling._write(fixture.root / ("changed-" + field + ".json"), chunks.PLAN_TYPE, value)
    with pytest.raises(ValueError):
        rolling.verify_capture_plan(replace(spec, plan_receipt=path))


def test_chunk_current_source_and_policy_tampering_refuse(chunk_setup):
    fixture, _, spec, policy_path = chunk_setup
    value = receipts._unpack(policy_path.read_bytes(), chunks.POLICY_TYPE)
    value["implementation_sources"]["rapid_slot_chunks"] = "0" * 64
    changed = rolling._write(fixture.root / "changed-policy.json", chunks.POLICY_TYPE, value)
    with pytest.raises(ValueError, match="Source"):
        chunks.validate_policy(rolling._ref(changed))
    context = OperationFacts()
    with context.scope():
        rolling.verify_capture_plan(spec, _context=context)
        original = policy_path.read_bytes()
        policy_path.write_bytes(original + b" ")
        with pytest.raises(ValueError, match="bytes or mode"):
            context.check()
        policy_path.write_bytes(original)


def chunk_proof(fixture, spec):
    for root in (spec.runtime_source_root, spec.module_root):
        path = root / "src/qcsd_lab/rapid_slot_chunks.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(Path(chunks.__file__).read_bytes())
    return _proof(fixture, spec)


def checked(fixture, proof):
    return {"proof": proof, "execution": {"returncode": 0,
        "validator_script_sha256": lanes._sha(lanes.IMAGE_CHECK_SCRIPT.encode()),
        "stdout": lanes._put_object(fixture.root, lanes._json(proof)), "started_at": receipts._now()}}


def test_chunk_failed_only_g02_keeps_peer_and_exact_slots(chunk_setup):
    fixture, _, spec, _ = chunk_setup
    proof = chunk_proof(fixture, spec)
    first, peer = [row["campaign_name"] for row in proof["plan_payload"]["lanes"][:2]]
    first_intent = lanes.prepare_lane_intent(spec, fixture.root, first, checked(fixture, proof))
    peer_intent = lanes.prepare_lane_intent(spec, fixture.root, peer, checked(fixture, proof))
    fixture.base.proof.clear()
    fixture.base.proof.update(proof)
    lanes._actuate_host(spec, fixture.root, first_intent.parent,
        [str(spec.host_launcher), "run", str(spec.campaign_dir / (first + ".yml"))],
        {"QCSD_RAPID_V5_PROFILE_PATH": str(spec.execution_root / lanes.STUDY_PROFILE_FILE),
         "QCSD_RAPID_DNS_RECEIPT_PATH": str(first_intent.parent / "dns.json")}, 0)
    peer_before = {path.relative_to(peer_intent.parent).as_posix(): path.read_bytes()
                   for path in peer_intent.parent.rglob("*") if path.is_file()}
    output = rolling.publish_successor(spec, first, 2, fixture.root / "chunk-g02.json")
    successor_spec = replace(spec, plan_receipt=output)
    new_proof = chunk_proof(fixture, successor_spec)
    successor_name = new_proof["plan_payload"]["lanes"][0]["campaign_name"]
    with pytest.raises(ValueError, match="immediate predecessor"):
        lanes.prepare_lane_intent(successor_spec, fixture.root, successor_name, checked(fixture, new_proof))
    intent = lanes.prepare_lane_intent(successor_spec, fixture.root, successor_name, checked(fixture, new_proof),
                                       predecessor_intent=first_intent)
    _, lineage, lane, _ = lanes._intent_and_lineage(successor_spec, fixture.root, intent)
    assert lane.generation == 2 and lane.slot_start == 0 and lane.visits_per_workload == 16
    assert lineage["predecessor_campaign_name"] == first
    assert peer_before == {path.relative_to(peer_intent.parent).as_posix(): path.read_bytes()
                           for path in peer_intent.parent.rglob("*") if path.is_file()}
    (peer_intent.parent / "complete.json").write_bytes(b"completed peer boundary fixture")
    peer_plan = rolling.publish_successor(spec, peer, 2, fixture.root / "peer-g02.json")
    peer_spec = replace(spec, plan_receipt=peer_plan)
    peer_proof = chunk_proof(fixture, peer_spec)
    with pytest.raises(ValueError, match="completed lane"):
        lanes.prepare_lane_intent(peer_spec, fixture.root, peer + "-g02", checked(fixture, peer_proof),
                                  predecessor_intent=peer_intent)
    with pytest.raises(ValueError, match="one generation"):
        rolling.publish_successor(spec, first, 3, fixture.root / "skip-g03.json")


def test_genuine_retained_progress_maps_exact_original_local_visits(tmp_path):
    name, digest = os.environ.get("QCSD_TEST_PRIOR_PROGRESS"), os.environ.get("QCSD_TEST_PRIOR_PROGRESS_SHA256")
    if not name or not digest:
        pytest.skip("provide a genuine hash-bound original progress fixture")
    path = Path(name)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    value = json.loads(path.read_bytes())
    known = {row["candidate_id"]: row["class_index"] for row in value["accepted_formal_slots"]}
    classes = [{"candidate_id": candidate, "class_index": index} for candidate, index in known.items()]
    _, slots, files = chunks.prior_progress(rolling._ref(path), classes)
    assert len(slots) == value["formal_accepted_trace_count"]
    assert path in files and any(item.name == "experiment.json" for item in files)
    changed = copy.deepcopy(value)
    changed["accepted_formal_slots"][0]["visit"] = 63
    mutation = tmp_path / "moved-slot.json"
    mutation.write_bytes(receipts._json(changed))
    with pytest.raises(ValueError, match="sealed original lane identities"):
        chunks.prior_progress(rolling._ref(mutation), classes)


def test_policy_closes_prior_dependency_before_creating_output(tmp_path, monkeypatch):
    """Synthetic current-control boundary; the actual durability fence is real."""
    root = tmp_path / "study"
    root.mkdir()
    old = root / "prior-progress.json"
    old.write_bytes(b"original accepted-slot metadata")
    policy = root / "policy.json"
    policy.write_bytes(b"synthetic enrollment authority")
    now = receipts._now()
    monkeypatch.setattr(chunks, "_base_spec", lambda spec: base)
    monkeypatch.setattr(rolling, "verify_capture_plan", lambda *a, **k: ((), {"readiness": {"tamaraw": {}}, "runtime": {}}))
    monkeypatch.setattr(rolling, "_verify_enrollment", lambda *a: ({"policy": rolling._ref(policy)}, [], {}))
    monkeypatch.setattr(rolling, "_runtime", lambda value: value)
    monkeypatch.setattr(chunks, "prior_progress", lambda *a: ({"closed_at": now}, set(), {old}))
    class Base:
        cohort = root / "enrollment.json"
        plan_receipt = root / "base-plan.json"
        @staticmethod
        def serializable():
            return {}
    base = Base()
    base.cohort.write_bytes(b"synthetic membership")
    base.plan_receipt.write_bytes(b"synthetic qualified base")
    def mutated_sources():
        old.write_bytes(b"different accepted-slot metadata")
        return {}
    monkeypatch.setattr(chunks, "sources", mutated_sources)
    output = root / "never-created.json"
    with pytest.raises(ValueError, match="bytes or mode"):
        chunks.publish_policy(base, rolling._ref(old), output, modes=["tamaraw"])
    assert not output.exists()


def test_successor_scope_keeps_existing_owner_and_refuses_changed_inputs_before_effect(tmp_path, monkeypatch):
    authority = tmp_path / "bound-plan.json"
    authority.write_bytes(b"original plan")
    output = tmp_path / "outside" / "never-created.json"
    policy = tmp_path / "study" / "policy.json"
    policy.parent.mkdir()
    policy.write_bytes(b"synthetic enrollment authority")
    context = OperationFacts()
    seen = []
    def verified(*args, **kwargs):
        from qcsd_lab.rapid_operation_facts import current_context
        seen.append(current_context())
        current_context().watch_file(authority)
        return (), {"slot_chunk_policy": {}}
    monkeypatch.setattr(rolling, "verify_capture_plan", verified)
    monkeypatch.setattr(chunks, "validate_policy", lambda *args: ({}, {"policy": rolling._ref(policy)}, [], {}))
    with context.scope():
        with pytest.raises(ValueError, match="enrollment study"):
            chunks.publish_successor(None, "unused", 2, output)
        assert seen == [context]
        authority.write_bytes(b"changed original plan")
        with pytest.raises(ValueError, match="bytes or mode"):
            context.check()
    assert not output.exists()


def test_prospective_chunk_progress_preserves_old_and_new_explicit_slot_contracts():
    site = _sites(1)[0]
    classes = [{"workload_id": site.workload_id, "class_index": 1}]
    lane = chunks.planned_lanes((site,), classes,
        {"prior_slots": [[1, "tamaraw", i] for i in range(4)], "modes": ["tamaraw"], "maximum_visits": 16},
        {"path": "/unused-policy", "sha256": "f" * 64}, shard=1)[0]
    assert list(chunks._registered_slots(lane, 16, chunks.PROGRESS_TYPE)) == list(range(4, 20))
    with pytest.raises(ValueError, match="explicit new accepted-slot contract"):
        chunks._registered_slots(lane, 16, "root-reopened-rolling-static-scientific-progress")
    with pytest.raises(ValueError, match="accepted lane count"):
        chunks._registered_slots(lane, True, chunks.PROGRESS_TYPE)
    old = plan.Lane("formal", 3, 1, "tamaraw", plan._campaign_name("formal", 3, 1, "tamaraw", 1, 6),
                    (site.workload_id,), 4, site.qualification_set, 1, 6)
    for kind in (chunks.PROGRESS_TYPE, "root-reopened-rolling-static-scientific-progress"):
        assert list(chunks._registered_slots(old, 4, kind)) == [8, 9, 10, 11]


def test_publication_refuses_aliased_existing_and_linked_study_paths(tmp_path):
    study = tmp_path / "study"
    study.mkdir()
    proposed = study / "new-policy.json"
    assert chunks._publication_path(proposed, study) == proposed
    existing = study / "claimed.json"
    existing.write_bytes(b"preserved policy")
    linked = study / "linked-parent"
    linked.symlink_to(tmp_path, target_is_directory=True)
    for path in (existing, study, tmp_path / "outside.json", study / ".." / "aliased.json",
                 linked / "new.json"):
        with pytest.raises(ValueError, match="unclaimed nonlinked"):
            chunks._publication_path(path, study)
    assert existing.read_bytes() == b"preserved policy"
