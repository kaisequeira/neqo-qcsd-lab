"""Real BuFLO target wrapper traffic checks with controlled physical proofs.

Public target policy/plan/capsule validators, Source identities, graph and slot
guards run. Original admission, installed canonical and packet/deep proofs use
the explicit HOST boundaries in the imported fixtures; no scientific credit.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_capture_traffic as traffic
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as runtime
from qcsd_lab import rapid_target_chunks as chunks
from qcsd_lab import rapid_target_parallel_schedule as workers
from tests.test_rapid_target_chunks import case, current, duration_case, planned


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def duration_pair(duration_case, monkeypatch):
    case = duration_case
    source = case.source
    case.current.payload["readiness"] = {"buflo": case.current.canary}
    case.current.payload["sites"] = [asdict(site) for site in case.current.sites]
    case.current.spec.plan_receipt.write_bytes(rolling.admission._json(
        rolling.admission._bind(lanes.PLAN_TYPE, case.current.payload)))
    for relative in workers.CONTROL_FILES:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        original = ROOT / relative
        path.write_bytes(original.read_bytes())
        path.chmod(original.stat().st_mode & 0o7777)
    for root in {Path(case.current.runtime[key]) for key in
                 ("runtime_source_root", "module_root", "execution_root")}:
        for relative, _ in traffic.files(traffic.budget.POLICY).values():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / relative).read_bytes())
    monkeypatch.setattr(runtime, "reopen_runtime", lambda ref, actual, **options: (
        case.current.canonical, {relative: (source / relative).read_bytes()
                                 for relative in workers.CONTROL_FILES}))
    def admitted_inputs(spec, sites, *, _context=None):
        # The imported fixture controls the original admission/GET validator.
        # Register its complete synthetic physical files and raw tree here;
        # target inputs and Source validation continue through real code.
        files = {spec.cohort, spec.qualification_spec, spec.plan_receipt,
                 spec.source_manifest, spec.client_binary, spec.base_launcher, spec.host_launcher}
        files.update(spec.workload_root / (site.workload_id + ".json") for site in sites)
        for root in {spec.runtime_source_root, spec.module_root, spec.execution_root}:
            files.update(root / relative for relative, _ in traffic.spec_files(spec).values())
        trees = {case.current.raw_root}
        for path in files:
            _context.watch_file(path)
        for path in trees:
            _context.watch_tree(path)
        return files, trees
    monkeypatch.setattr(workers.old_workers, "input_dependencies", admitted_inputs)
    base, policy = planned(case)
    reference = workers.publish_schedule(base, case.current.runtime, base.qualification_spec,
        case.current.canonical_ref, case.current.canonical_ref,
        case.current.root / "buflo-target-worker-capsule.json", reason="prospective HOST BuFLO traffic check")
    path = workers.publish_plan(base, reference, case.current.root / "buflo-target-worker-plan.json")
    spec = replace(base, plan_receipt=path)
    payload = lanes._payload(path, lanes.PLAN_TYPE)
    return SimpleNamespace(case=case, base=base, spec=spec, payload=payload, reference=reference, policy=policy)


def test_published_buflo_target_wrapper_preserves_traffic_graphs_caps_and_practice(duration_pair):
    a = duration_pair
    original = deepcopy(a.case.current.payload["capture_limits"])
    held = {path: path.read_bytes() for path in
            (a.case.current.spec.plan_receipt, a.case.current.spec.cohort,
             a.case.current.spec.qualification_spec, a.case.result / "experiment.json",
             *(a.spec.workload_root / (site.workload_id + ".json") for site in a.case.current.sites))}
    historical = deepcopy(lanes.TRAFFIC_FILES)
    assert traffic.declared(a.payload) == traffic.budget.POLICY
    assert traffic.plan_files(a.payload) == traffic.spec_files(a.spec) == traffic.files(traffic.budget.POLICY)
    actual = traffic.spec_files(a.spec)
    for key in historical:
        if key not in {"buflo_parameters_sha256", "buflo_parameter_provenance_sha256"}:
            assert actual[key] == historical[key]
    assert actual["buflo_parameters_sha256"] == (traffic.budget.PARAMETER_PATH, traffic.budget.PARAMETER_SHA256)
    assert actual["buflo_parameter_provenance_sha256"] == (traffic.PROVENANCE_PATH, traffic.PROVENANCE_SHA256)
    assert lanes.TRAFFIC_FILES == historical
    assert a.payload["capture_limits"] == original
    assert (original["timeout_seconds"], original["capture_seconds"], original["max_attempts"]) == (120, 180, 3)
    policy, _, _ = chunks.validate_policy(chunks.target.reference(a.policy))
    assert policy["capture_limits"] == {**original, "timeout_seconds": 240, "capture_seconds": 300}
    practice = json.loads((a.case.result / "experiment.json").read_bytes())["configuration"]["limits"]
    assert practice == {**policy["capture_limits"], "max_attempts": 1}
    sites, verified = rolling.verify_capture_plan(a.spec, require_current=True)
    assert verified == a.payload and a.payload["sites"] == a.case.current.payload["sites"]
    selected = [lanes._lane({"plan_payload": a.payload}, row["campaign_name"]) for row in a.payload["lanes"][:2]]
    workers.require_disjoint([(a.spec, a.payload, lane, sites) for lane in selected])
    for lane in selected:
        campaign = yaml.safe_load(lanes._render_lane_campaign(a.spec, lane, sites))
        assert campaign["limits"] == policy["capture_limits"]
        assert campaign["defenses"][0]["parameters"].endswith("/buflo-duration200.json")
    traffic.artifacts(a.case.current.runtime, traffic.budget.POLICY)
    assert all(path.read_bytes() == raw for path, raw in held.items())


@pytest.mark.parametrize("change", ["type", "contract", "condition_sha256", "capture_limits",
    "control_sources", "mode", "target_id", "unknown-field", "current-source-bytes", "current-source-mode"])
def test_traffic_refuses_rehashed_altered_or_unknown_target_capsules(duration_pair, change):
    a = duration_pair
    value = json.loads(Path(a.reference["path"]).read_bytes())
    if change == "type":
        value["artifact_type"] = "qcsd-unknown-scheduling-capsule"
    elif change == "capture_limits":
        value[change]["max_attempts"] += 1
    elif change == "control_sources":
        value[change]["src/qcsd_lab/rapid_capture_traffic.py"]["sha256"] = "0" * 64
    elif change == "unknown-field":
        value["unregistered_traffic"] = True
    elif change.startswith("current-source"):
        path = a.spec.runtime_source_root / "src/qcsd_lab/rapid_capture_traffic.py"
        if change == "current-source-bytes":
            path.write_bytes(path.read_bytes() + b"\n# changed Source\n")
        else:
            path.chmod((path.stat().st_mode & 0o7777) ^ 0o020)
    else:
        value[change] = "unregistered"
    path = a.case.current.root / ("altered-" + change + ".json")
    path.write_bytes(lanes._json(value))
    payload = {**a.payload, "scheduling": rolling._ref(path)}
    for check in (traffic.declared, traffic.plan_files):
        with pytest.raises(ValueError):
            check(payload)
    forged = rolling._write(a.case.current.root / ("altered-" + change + "-plan.json"), workers.PLAN_TYPE, payload)
    with pytest.raises(ValueError):
        traffic.spec_files(replace(a.spec, plan_receipt=forged))


@pytest.mark.parametrize("change", ["capture_limits", "lanes", "sites", "static_capture_amendment",
                                   workers.FIELD, workers.BASE_FIELD, "unknown-field"])
def test_traffic_refuses_changed_target_wrapper_authority(duration_pair, change):
    a = duration_pair
    payload = deepcopy(a.payload)
    if change == "capture_limits":
        payload[change]["timeout_seconds"] += 1
    elif change == "lanes":
        payload[change][0]["slot_start"] += 1
    elif change == "sites":
        payload[change][0]["workload_sha256"] = "0" * 64
    elif change == workers.BASE_FIELD:
        payload[change]["execution_generation"] = "unregistered"
    elif change == "unknown-field":
        payload["unregistered_traffic"] = True
    else:
        payload[change] = "unregistered"
    with pytest.raises(ValueError):
        traffic.plan_files(payload)
    path = rolling._write(a.case.current.root / ("forged-" + change + ".json"), workers.PLAN_TYPE, payload)
    with pytest.raises(ValueError):
        traffic.spec_files(replace(a.spec, plan_receipt=path))


@pytest.mark.parametrize("mode", ["undefended", "front", "tamaraw", "buflo", "cs-buflo"])
def test_historical_modes_retain_their_original_traffic_tuple(tmp_path, mode):
    payload = {"study_version": 6, "lanes": [{"mode": mode}]}
    path = rolling._write(tmp_path / "historical-plan.json", lanes.PLAN_TYPE, payload)
    spec = SimpleNamespace(plan_receipt=path)
    historical = deepcopy(lanes.TRAFFIC_FILES)
    assert traffic.declared(payload) is None
    assert traffic.plan_files(payload) == traffic.spec_files(spec) == historical
    assert traffic.files() == lanes.TRAFFIC_FILES == historical
