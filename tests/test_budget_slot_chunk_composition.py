"""HOST composition: genuine q53 raw proof; no installed or traffic authority.

The creation audit/runtime boundaries use the held per-class HOST fixtures.
The CLI ownership cases substitute its physical handler and installed proof.
No original files, public evidence, network or scientific counters are changed.
"""
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_slot_chunks as chunks
from qcsd_lab.application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
from qcsd_lab.rapid_operation_facts import OperationFacts, current_context
from tests.test_per_class_selected_budget import actual_q53_input, genuine_seed, fixture_enrollment
from tools import rapid_rolling_capture as cli


@pytest.mark.parametrize("maximum", [1, 16])
def test_real_budget_class_chunks_preserve_graph_caps_and_current_body_policy(
        actual_q53_input, genuine_seed, monkeypatch, maximum):
    enrollment, _, _, manifest = fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch)
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    assert len(classes) == 12 and classes[-1]["class_index"] == 12
    before = manifest.read_bytes()
    limits = rolling._effective_capture_limits(batch, classes, policy)
    assert limits["max_response_bytes"] == 64 * 1024 * 1024
    assert limits["capture_megabytes"] == 256
    site = plan.Site(classes[-1]["candidate_id"], classes[-1]["workload_id"],
        sha256(before).hexdigest(), "https://fixture.invalid", "current-host-fixture", "a" * 64)
    values = chunks.planned_lanes([site], classes,
        {"prior_slots": [], "modes": ["tamaraw"], "maximum_visits": maximum},
        {"path": "/host-only-unused-slot-policy", "sha256": "b" * 64}, shard=batch["ordinal"])
    assert sum(lane.sample_count for lane in values) == 64
    slots = [chunks.logical_slot(lane, visit) for lane in values
        for visit in range(lane.visits_per_workload)]
    assert slots == list(range(64))
    for lane in (values[0], values[-1]):
        document = yaml.safe_load(chunks.render(lane, [site], static_capture_limits=limits,
            application_body_identity_policy=COMPLETE_APPLICATION_DELIVERY_POLICY))
        assert document["limits"] == limits
        assert document["workloads"] == {site.workload_id: lane.visits_per_workload}
        assert document["application_body_identity_policy"] == COMPLETE_APPLICATION_DELIVERY_POLICY
    assert manifest.read_bytes() == before


def test_new_per_class_role_refuses_parallel_before_any_public_plan_write(
        actual_q53_input, genuine_seed, monkeypatch):
    enrollment, root, runtime, _ = fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch)
    output = root / "must-not-exist.json"
    with pytest.raises(ValueError, match="only its prospective serial authority"):
        rolling.publish_plan(root, enrollment, root / "not-read-qualifier.json", output,
            readiness={"tamaraw": {}}, runtime_inputs=runtime,
            scheduling={"path": "/must-not-open-a-parallel-capsule", "sha256": "c" * 64})
    assert not output.exists()


def test_public_launch_and_chunk_plan_preserve_fresh_and_borrowed_facts(monkeypatch, tmp_path):
    dependency = tmp_path / "immutable-input"
    dependency.write_bytes(b"original")
    spec = lanes.CaptureSpec(**{key: tmp_path for key in lanes.PATH_KEYS},
        collection_image_digest="sha256:" + "d" * 64, execution_generation="host-fixture")
    observed = []
    monkeypatch.setattr(lanes, "load_capture_spec", lambda path: spec)
    monkeypatch.setattr(lanes, "_payload", lambda *args: {
        "study_version": 6, "cohort_generation": "rolling-50"})
    monkeypatch.setattr(rolling, "verify_capture_plan", lambda *args, **kwargs: (
        (), {"planned_trace_count": 1}))
    monkeypatch.setattr(rolling, "_ref", lambda path: {"path": str(path), "sha256": "e" * 64})
    monkeypatch.setattr(rolling, "_write_spec", lambda *args: None)

    def handler(*args, _context=None, **kwargs):
        assert _context is current_context()
        _context.watch_file(dependency)
        observed.append(_context)
        return tmp_path / "no-physical-effect"

    monkeypatch.setattr(lanes, "launch_lane", handler)
    monkeypatch.setattr(chunks, "publish_plan", handler)
    launch = SimpleNamespace(command="launch", spec=tmp_path, evidence_root=tmp_path,
        lane="host-fixture", predecessor_intent=None)
    chunk = SimpleNamespace(command="chunk-plan", spec=tmp_path, slot_chunk_policy=tmp_path,
        output=tmp_path, spec_output=tmp_path)
    cli.run(launch)
    cli.run(chunk)
    assert observed[0] is not observed[1] and current_context() is None
    borrowed = OperationFacts()
    with borrowed.scope():
        cli.run(chunk, _context=borrowed)
        assert observed[-1] is borrowed and current_context() is borrowed
        borrowed.check()
    assert current_context() is None


def test_public_launch_closing_fence_rejects_mutated_dependency(monkeypatch, tmp_path):
    dependency = tmp_path / "immutable-input"
    dependency.write_bytes(b"original")
    spec = SimpleNamespace(plan_receipt=tmp_path)
    monkeypatch.setattr(lanes, "load_capture_spec", lambda path: spec)
    monkeypatch.setattr(lanes, "_payload", lambda *args: {
        "study_version": 6, "cohort_generation": "rolling-50"})

    def handler(*args, _context=None, **kwargs):
        assert _context is current_context()
        _context.watch_file(dependency)
        dependency.write_bytes(b"changed")
        return tmp_path / "no-physical-effect"

    monkeypatch.setattr(lanes, "launch_lane", handler)
    args = SimpleNamespace(command="launch", spec=tmp_path, evidence_root=tmp_path,
        lane="host-fixture", predecessor_intent=None)
    with pytest.raises(ValueError, match="bytes or mode"):
        cli.run(args)
    assert current_context() is None
