"""Exercise both opt-in authorities through their actual combined plan path.

The existing fixture substitutes only admission, installed runtime/capsule,
qualification and packet backends. Plan/manifest derivation, CLI dispatch,
current qualifier bindings and FRONT canary checks remain actual consumers.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_rolling_schedule as schedule
from tests.test_rapid_lane_evidence import setup as ordinary_setup
from tests.test_rapid_rolling_capture import rolling_setup
from tests.test_rapid_rolling_parallel import setup, parallel_setup
from tests.test_rapid_front_capture_amendment import amended, planned
from tools import rapid_rolling_capture as cli


VALIDATE_READY_CANARY = schedule.validate_ready_canary


@pytest.fixture
def combined(amended, parallel_setup, monkeypatch):
    a, p = amended, parallel_setup
    base, _, _, lane = planned(a)
    # Both runtimes in this fixture have the same current FRONT policy, Source,
    # client and qualification. The capsule cannot authorize a policy change.
    p.fixture.runtime = a.runtime
    p.fixture.base.spec = base
    p.state["base_spec"] = base.serializable()
    monkeypatch.setattr(schedule, "validate_ready_canary", VALIDATE_READY_CANARY)
    a.schedule = p.reference
    a.lane = lane
    return a


def merged_plan(a, name="combined-plan.json"):
    args = cli._parser().parse_args([
        "plan", "--evidence-root", str(a.f.root), "--enrollment", str(a.enrollment),
        "--qualification-spec", str(a.qualifier), "--runtime-spec", str(a.f.root / "runtime.json"),
        "--readiness", str(a.f.root / "readiness.json"),
        "--scheduling", a.schedule["path"], "--front-capture-amendment", str(a.declaration),
        "--output", str(a.f.root / name), "--spec-output", str(a.f.root / (name + ".spec.json"))])
    (a.f.root / "runtime.json").write_bytes(lanes._json({
        "schema_version": 1, "artifact_type": rolling.RUNTIME_TYPE, "inputs": a.runtime}))
    (a.f.root / "readiness.json").write_bytes(lanes._json({"front": a.canary}))
    result = cli.run(args)
    return lanes.load_capture_spec(Path(result["spec"])), result


def test_actual_cli_plan_and_installed_check_preserve_both_authorities(combined):
    a = combined
    before = {p: p.read_bytes() for p in (a.original, a.enrollment, a.f.root / "policy.json")}
    spec, result = merged_plan(a)
    sites, payload = rolling.verify_capture_plan(spec)
    assert payload["front_capture_amendment"] == rolling._ref(a.declaration)
    assert payload["scheduling"] == a.schedule
    assert result["ready_settings"] == ["front"] and result["planned_traces"] == 320
    assert len(payload["lanes"]) == 80
    assert sites[0].workload_sha256 == lanes._sha(a.target.read_bytes())
    assert sites[0].workload_sha256 != lanes._sha(a.original.read_bytes())
    assert rolling.require_mode_readiness(spec, a.lane) == a.canary
    from tests.test_rapid_rolling_capture import _proof
    from qcsd_lab import rapid_front_capture_amendment as front
    for root in (spec.runtime_source_root, spec.module_root):
        module = root / "src/qcsd_lab/rapid_front_capture_amendment.py"
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_bytes(Path(front.__file__).read_bytes())
    proof = _proof(a.f, spec)
    assert proof["plan_payload"]["scheduling"] == a.schedule
    assert proof["plan_payload"]["front_capture_amendment"] == rolling._ref(a.declaration)
    assert all(p.read_bytes() == raw for p, raw in before.items())


@pytest.mark.parametrize("field", ["manifest", "graph"])
def test_scheduled_readiness_cannot_skip_front_canary_binding(combined, monkeypatch, field):
    a = combined
    spec, _ = merged_plan(a)
    def changed(*args, **kwargs):
        facts = a.checked(*args, **kwargs)
        if field == "manifest":
            facts["workload_sha256"] = lanes._sha(a.original.read_bytes())
        else:
            facts["full_graph"]["resource_records_sha256"] = "e" * 64
        return facts
    monkeypatch.setattr(readiness, "validate_canary", changed)
    with pytest.raises(ValueError, match="FRONT canary"):
        rolling.require_mode_readiness(spec, a.lane)
    assert not (a.f.root / "lanes" / a.lane.campaign_name / "intent.json").exists()


@pytest.mark.parametrize("field", ["source", "epoch"])
def test_scheduling_cannot_replace_fresh_front_qualification(combined, field):
    a = combined
    value = lanes._load(a.sidecar.read_bytes())
    if field == "source":
        value["qualification_source"]["lab_commit"] = "e" * 40
    else:
        value["candidate_attempts"][0]["connection_epochs"][0]["receipt"]["started_unix_ns"] = 0
    a.sidecar.write_bytes(lanes._json(value))
    with pytest.raises(ValueError, match="fresh qualification|qualification began before"):
        merged_plan(a, "rejected-combined-plan.json")
    assert not (a.f.root / "rejected-combined-plan.json").exists()


@pytest.mark.parametrize("field", ["scheduling", "front_capture_amendment"])
def test_combined_plan_keeps_explicit_null_rejection(combined, field):
    spec, _ = merged_plan(combined)
    payload = copy.deepcopy(lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE))
    payload[field] = None
    spec.plan_receipt.write_bytes(lanes._json(lanes.admission._bind(lanes.PLAN_TYPE, payload)))
    with pytest.raises((ValueError, TypeError)):
        rolling.verify_capture_plan(spec)
