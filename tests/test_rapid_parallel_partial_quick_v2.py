"""Genuine saved V2 material/schema controls; no incomplete deep proof claim.

The retained Source60 workers remain complete accepted1/failed0. Mutated
capsules and caller lanes are separate test inputs under pytest's temporary
directory; no original profile, report, evidence or runtime is rewritten.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_partial_lane as reader
from qcsd_lab import rapid_front_quick_compatibility as quick_compatibility
from qcsd_lab import rapid_quick_profile as quick
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab.rapid_operation_facts import OperationFacts


FIXTURE = Path(__file__).parent / "fixtures" / "rapid_parallel_partial_source60_v2.json"


def _read_genuine(reference):
    path = Path(reference["path"])
    assert not any(item.is_symlink() for item in (path, *path.parents))
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == reference["sha256"]
    assert stat.S_IMODE(path.stat().st_mode) == reference["mode"]
    return json.loads(raw)


@pytest.fixture(scope="module")
def saved_v2():
    fixture = json.loads(FIXTURE.read_bytes())
    references = [fixture[name] for name in ("profile", "spec", "plan", "intent", "lineage")] + fixture["experiments"]
    if any(not Path(item["path"]).is_file() for item in references):
        pytest.skip("authentic saved Source60 V2 material is unavailable; no synthetic proof substitutes")
    assert fixture["fixture_role"] == "genuine-saved-Source60-V2-profile-and-complete-config-schema-only"
    assert fixture["scientific_credit"] is False and fixture["incomplete_proof_claim"] is False
    capsule = _read_genuine(fixture["profile"])
    raw_spec = _read_genuine(fixture["spec"])
    spec = lanes.load_capture_spec(Path(fixture["spec"]["path"]))
    assert spec.serializable() == raw_spec["inputs"]
    payload = lanes.plan_payload(Path(fixture["plan"]["path"]).read_bytes())
    _read_genuine(fixture["plan"])
    experiments = [_read_genuine(item) for item in fixture["experiments"]]
    return SimpleNamespace(fixture=fixture, capsule=capsule, spec=spec, payload=payload, experiments=experiments)


def _copied_capsule(tmp_path, capsule):
    path = tmp_path / "synthetic-mutated-profile-schema-only.json"
    path.write_text(json.dumps(capsule, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    return rolling._ref(path)


def test_saved_source60_v2_material_plan_worker_and_actual_complete_config(saved_v2):
    saved = saved_v2
    for module in (quick, schedule):
        path = Path(module.__file__)
        raw = path.read_bytes()
        if module is quick:
            # The complete new FRONT dispatcher must restore the original
            # Source60 stock guard before this old complete-schema regression.
            raw = quick_compatibility.restore("quick", raw)
        assert hashlib.sha256(raw).hexdigest() == saved.fixture["stock_guards"][path.name]
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
    context = OperationFacts()
    capsule = quick.validate_profile({key: saved.fixture["profile"][key] for key in ("path", "sha256")}, _context=context)
    context.check()
    assert capsule == saved.capsule
    assert capsule["artifact_type"] == quick.MODE_CAPSULE_TYPE and capsule["schema_version"] == 2
    assert capsule["mode_selection"]["mode"] == "front" and set(capsule["mode_selection"]) == {"mode", "readiness"}
    assert capsule["permitted_slots"] == list(range(64))
    assert capsule["formal_accepted_trace_count"] == 0 and capsule["scientific_credit"] is False
    sites, checked = quick.verify_plan(saved.spec)
    assert checked == saved.payload and len(sites) == 1
    lane = lanes._lane({"plan_payload": checked}, checked["lanes"][0]["campaign_name"])
    quick.require_worker(checked, lane, sites, saved.spec)
    assert (lane.mode, lane.slot_start, lane.visits_per_workload) == ("front", 0, 1)
    assert checked["scientific_credit"] is False and checked["formal_accepted_trace_count"] == 0
    assert saved.experiments[0]["configuration"] == saved.fixture["configuration"]
    for experiment in saved.experiments:
        assert experiment["status"] == "complete"
        assert experiment["summary"] == {"accepted": 1, "eligible": 1, "failed": 0, "passed": True, "planned": 1}
        assert len(experiment["samples"]) == 1
        assert experiment["samples"][0]["state"] == "accepted" and experiment["samples"][0]["eligible"] is True
        config = experiment["configuration"]
        assert set(config) == set(saved.fixture["configuration"])
        assert config["defenses"] == [{"baseline": False, "kind": "front", "name": "front"}]
        assert config["chaff_qualification_set"] == lane.qualification_set
        assert config["chaff_qualification_set_manifest_sha256"] == sites[0].qualification_set_manifest_sha256
        workload = config["workloads"][0]
        assert workload["id"] == sites[0].workload_id and workload["sha256"] == sites[0].workload_sha256
        assert (workload["resource_count"], workload["origin_count"], workload["visits"]) == (58, 2, 1)
        assert "manifest" in workload and "path" not in workload
        assert experiment["source"] == {**capsule["source"], "image_digest": saved.fixture["image_digest"]}
    for reference in [saved.fixture["profile"], *saved.fixture["experiments"]]:
        _read_genuine(reference)


def test_saved_v2_complete_schema_exercises_partial_reader_binding_without_partial_claim(saved_v2):
    saved = saved_v2
    intent = _read_genuine(saved.fixture['intent'])['payload']
    lineage = _read_genuine(saved.fixture['lineage'])['payload']
    lane = lanes._lane({'plan_payload': saved.payload}, saved.payload['lanes'][0]['campaign_name'])
    runtime = saved.capsule['runtime']
    # These dictionaries are schema inputs, not an original deep report or a
    # published Source binding. Every borrowed material file remains genuine.
    source_schema = {'root': runtime['module_root'], 'files': {
        'src/qcsd_lab/' + name + '.py': reader.reference(
            Path(runtime['module_root']) / 'src/qcsd_lab' / (name + '.py'))
        for name in ('rapid_lane_evidence', 'rapid_quick_profile',
                     'rapid_rolling_capture', 'rapid_rolling_schedule', 'rapid_slot_chunks')},
        'binding': {'runtime_identity': {'source': saved.capsule['source'],
            'collection_image_digest': saved.fixture['image_digest'],
            'client_sha256': saved.fixture['client_sha256']},
            'runtime': runtime, 'canonical': saved.capsule['current_canonical']}}
    report_schema = {'schema_only_fixture': True, 'scientific_credit': False,
        'formal_accepted_trace_count': 0, 'spec': saved.spec.serializable(),
        'intent': intent, 'lineage': lineage, 'lane': asdict(lane),
        'sites': saved.payload['sites'], 'experiment': saved.experiments[0],
        'read_dependencies': [reader.reference(saved.fixture[name]['path'])
                              for name in ('plan', 'profile')]}
    original = deepcopy((source_schema, report_schema))
    joined = reader._measurement_binding(report_schema, source_schema)
    assert (source_schema, report_schema) == original
    assert joined['chunk_bindings'] == {
        'plan': reader.reference(saved.fixture['plan']['path']),
        'policy': reader.reference(saved.fixture['profile']['path'])}
    assert joined['image_metadata_join']['original_report_rewritten'] is False
    assert joined['experiment']['status'] == 'complete'
    assert joined['experiment']['summary']['accepted'] == 1
    assert joined['schema_only_fixture'] is True and joined['scientific_credit'] is False
    assert joined['formal_accepted_trace_count'] == 0
    with pytest.raises(ValueError, match='original incomplete formal contract'):
        reader._accepted_subset(joined)


@pytest.mark.parametrize("change,message", [
    ("mode", "own original formal lanes"),
    ("readiness", "changed original readiness"),
    ("fullgraph", "changed or pruned a complete multi-origin graph"),
    ("slot", "exact archived membership/settings seed"),
])
def test_saved_v2_copied_capsule_cannot_change_bound_authority(saved_v2, tmp_path, change, message):
    capsule = deepcopy(saved_v2.capsule)
    if change == "mode":
        capsule["mode_selection"]["mode"] = "undefended"
    elif change == "readiness":
        capsule["mode_selection"]["readiness"]["deep"]["completed"]["sha256"] = "0" * 64
    elif change == "fullgraph":
        graph = capsule["graphs"][saved_v2.fixture["configuration"]["workloads"][0]["id"]]
        graph["resources_sha256"] = "0" * 64
    else:
        capsule["permitted_slots"] = list(range(1, 64))
    with pytest.raises(ValueError, match=message):
        quick.validate_profile(_copied_capsule(tmp_path, capsule))
    assert _read_genuine(saved_v2.fixture["profile"]) == saved_v2.capsule


@pytest.mark.parametrize("change", ["qualification", "logical-slot"])
def test_saved_v2_worker_cannot_substitute_qualification_or_slot(saved_v2, change):
    sites, payload = quick.verify_plan(saved_v2.spec)
    lane = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    altered = replace(lane, qualification_set="synthetic-wrong-qualification") if change == "qualification" else replace(lane, slot_start=1)
    with pytest.raises(ValueError, match="worker differs from its exact prospective plan"):
        quick.require_worker(payload, altered, sites, saved_v2.spec)
    assert _read_genuine(saved_v2.fixture["profile"]) == saved_v2.capsule
