"""Exercise rolling authority with real plan/ordinary lane boundaries.

Only external admission, qualification and Docker actuation are substituted in
the small deterministic fixture. The retained-admission test additionally
reopens the original real terminal records and complete prepared graph.
"""
from __future__ import annotations

import copy
import contextlib
import io
import json
import os
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_lane_evidence import setup
from tools import rapid_rolling_capture as cli


def _sites(count):
    return tuple(plan.Site(f"candidate-{i}", f"workload-{i}", f"{i+1:064x}",
                           f"https://site{i}.example", "qualified-batch", "f"*64)
                 for i in range(count))


@pytest.mark.parametrize("count,batch", [(1, 1), (5, 2), (1, 50)])
def test_registered_batch_has_exact_64_visits_per_setting_and_unchanged_parameters(count, batch):
    sites = _sites(count)
    values = plan.plan_lanes(sites, final=True, study_version=6, rolling_batch=batch)
    assert len(values) == 80
    assert sum(item.sample_count for item in values) == count*5*64
    for mode in plan.MODES:
        chosen = [item for item in values if item.mode == mode]
        assert len(chosen) == 16 and sum(item.visits_per_workload for item in chosen) == 64
        document = yaml.safe_load(plan.render_lane_campaign(chosen[0], sites))
        assert document["workloads"] == {site.workload_id: 4 for site in sites}
        assert document["purpose"] == "evaluation" and document["limits"] == plan.V5_CAPTURE_LIMITS
        if mode in plan.PARAMETER_REFERENCES:
            assert document["defenses"][0]["parameters"] == plan.PARAMETER_REFERENCES[mode]


@pytest.mark.parametrize("count,final,batch", [(0, True, 1), (6, True, 1), (1, False, 1), (1, True, 0), (1, True, 51), (1, True, True)])
def test_rolling_grid_rejects_wrong_size_role_or_ordinal(count, final, batch):
    with pytest.raises(ValueError):
        plan.plan_lanes(_sites(count), final=final, study_version=6, rolling_batch=batch)


def test_historical_final_and_shakedown_requirements_stay_strict():
    for count, final in ((1, True), (5, True), (1, False), (5, False)):
        with pytest.raises(ValueError):
            plan.plan_lanes(_sites(count), final=final, study_version=5)
    historical = tuple(replace(site, qualification_set=f"shard-{index//5}") for index, site in enumerate(_sites(50)))
    assert len(plan.plan_lanes(historical, final=True, study_version=5)) == 800


@pytest.fixture
def rolling_setup(setup, monkeypatch):
    spec, root = setup.spec, setup.root
    context = SimpleNamespace(root=spec.acquisition_root, profile_bytes=b"profile", source_bytes=b"catalogue source",
        catalogue_bytes=b"full catalogue", selection_amendment_revision=12, selection_amendment_sha256="d"*64,
        candidates=[{"candidate_id": f"candidate-{index}"} for index in range(55)])
    (context.root / "provenance.json").write_bytes(admission._json(
        {"engineering_fixture": "retained original admission source"}))
    terminals = []
    for index in range(55):
        directory = context.root / "attempts" / f"candidate-{index}" / "attempt-000001"
        directory.mkdir(parents=True)
        graph = {"preparation": {"final_url": f"https://site{index}.example/", "approved_origins":
                 [f"https://site{index}.example", "https://cdn.example"]},
                 "resources": [{"id": 0, "url": f"https://site{index}.example/"},
                               {"id": 1, "url": "https://cdn.example/whole-resource.js"}]}
        workload = directory / f"site-{index}.json"
        workload.write_bytes(admission._json(graph))
        (spec.workload_root / workload.name).write_bytes(workload.read_bytes())
        application = spec.workload_root / (workload.stem + "-application-response-evidence")
        application.mkdir()
        (application / "fixture.json").write_bytes(admission._json(
            {"engineering_fixture": "named qualification primitive substituted below"}))
        preparation = directory / "preparation.json"
        preparation.write_bytes(admission._json(admission._bind(admission.PREPARATION_TYPE,
            {"prepared_workload": admission.evidence_reference(context.root, workload)})))
        terminal = directory / "terminal.json"
        terminal.write_bytes(admission._json(admission._bind(admission.TERMINAL_TYPE,
            {"preparation": admission.evidence_reference(context.root, preparation), "facts":
             {"candidate_id": f"candidate-{index}", "outcome": "admitted",
              "admission": {"prepared_workload_sha256": lanes._sha(workload.read_bytes())}}})))
        terminals.append(admission.evidence_reference(context.root, terminal))
    monkeypatch.setattr(admission, "load_admission_context", lambda path: context if Path(path) == context.root else None)
    monkeypatch.setattr(admission, "verify_site_terminal", lambda path, ctx: admission._unpack(lanes._read(path), admission.TERMINAL_TYPE)["facts"])
    status = {"terminal_prefix": terminals[:1]}
    monkeypatch.setattr(admission, "acquisition_status", lambda ctx: status)
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", lambda *args, **kwargs: None)
    def verified_canary(reference, *, runtime, mode):
        return {"mode": mode, "authority_source": {**lanes._load(lanes._read(Path(runtime["source_manifest"]))),
            "image_digest": runtime["collection_image_digest"]},
            "client_sha256": lanes._sha(lanes._read(Path(runtime["client_binary"]))),
            "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}}
    monkeypatch.setattr(readiness, "validate_canary", verified_canary)
    monkeypatch.setattr(readiness, "readiness_mount_roots", lambda reference, **kwargs: [])
    qualifier = lanes._load(lanes._read(spec.qualification_spec))
    qualifier["qualification_sets"] = qualifier["qualification_sets"][:1]
    Path(qualifier["qualification_sets"][0]["manifest"]).write_bytes(lanes._json({"fixture": "named-set primitive substituted only in this fixture"}))
    spec.qualification_spec.write_bytes(lanes._json(qualifier))
    runtime = {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    rolling.initialize_study(context.root, root, runtime)
    return SimpleNamespace(base=setup, context=context, status=status, terminals=terminals, runtime=runtime, root=root)


def _planned(fixture, *, modes=("undefended",)):
    enrollment = rolling.enroll(fixture.root)
    output = fixture.root / "batch-one-plan.json"
    rolling.publish_plan(fixture.root, enrollment, fixture.base.spec.qualification_spec, output,
                         readiness={mode: {"retained-canary": mode} for mode in modes})
    spec = rolling.capture_spec(fixture.root, enrollment, fixture.base.spec.qualification_spec, output)
    return spec, enrollment


def test_first_site_public_plan_does_not_wait_for_50_or_ten_site_shakedown(rolling_setup):
    spec, enrollment = _planned(rolling_setup)
    sites, payload = rolling.verify_capture_plan(spec)
    assert len(sites) == 1 and payload["planned_trace_count"] == 320 and len(payload["lanes"]) == 80
    assert payload["readiness"] == {"undefended": {"retained-canary": "undefended"}}
    path = rolling_setup.root / "operator-spec.json"
    rolling._write_spec(path, spec)
    assert lanes.load_capture_spec(path) == spec
    assert cli._parser().parse_args(["launch", "--spec", str(path), "--evidence-root", str(rolling_setup.root),
                                   "--lane", payload["lanes"][0]["campaign_name"]]).command == "launch"


def test_future_batch_can_group_five_without_changing_first_singleton(rolling_setup):
    first = rolling.enroll(rolling_setup.root)
    held = first.read_bytes()
    rolling_setup.status["terminal_prefix"] = rolling_setup.terminals[:6]
    second = rolling.enroll(rolling_setup.root, count=5)
    value, classes = rolling.verify_enrollment(second)
    assert value["ordinal"] == 2 and len(value["selected_candidate_ids"]) == 5
    assert [row["class_index"] for row in classes] == list(range(1, 7))
    assert first.read_bytes() == held


@pytest.mark.parametrize("duplicate", ["origin", "workload"])
def test_later_batch_cannot_reuse_an_earlier_physical_class(rolling_setup, duplicate):
    first = rolling.enroll(rolling_setup.root)
    original_bytes = first.read_bytes()
    context = rolling_setup.context
    terminal_path = admission._child(context.root, rolling_setup.terminals[1])
    terminal = admission._unpack(terminal_path.read_bytes(), admission.TERMINAL_TYPE)
    preparation_path = admission._child(context.root, terminal["preparation"])
    preparation = admission._unpack(preparation_path.read_bytes(), admission.PREPARATION_TYPE)
    workload_path = admission._child(context.root, preparation["prepared_workload"])
    if duplicate == "origin":
        workload = lanes._load(workload_path.read_bytes())
        workload["preparation"]["final_url"] = "https://site0.example/another-page"
        workload_path.write_bytes(admission._json(workload))
    else:
        replacement = workload_path.with_name("site-0.json")
        replacement.write_bytes(workload_path.read_bytes())
        workload_path = replacement
    preparation["prepared_workload"] = admission.evidence_reference(context.root, workload_path)
    preparation_path.write_bytes(admission._json(admission._bind(admission.PREPARATION_TYPE, preparation)))
    terminal["preparation"] = admission.evidence_reference(context.root, preparation_path)
    terminal["facts"]["admission"]["prepared_workload_sha256"] = lanes._sha(workload_path.read_bytes())
    terminal_path.write_bytes(admission._json(admission._bind(admission.TERMINAL_TYPE, terminal)))
    rolling_setup.terminals[1] = admission.evidence_reference(context.root, terminal_path)
    rolling_setup.status["terminal_prefix"] = rolling_setup.terminals[:2]
    with pytest.raises(ValueError, match="earlier class's"):
        rolling.enroll(rolling_setup.root)
    assert first.read_bytes() == original_bytes


@pytest.mark.parametrize("mutation", ["skip", "parent", "terminal", "duplicate", "hole"])
def test_enrollment_rejects_reordered_or_changed_frozen_evidence(rolling_setup, mutation):
    first = rolling.enroll(rolling_setup.root)
    if mutation == "hole":
        (rolling_setup.root / "batches/b0003").mkdir()
        with pytest.raises(ValueError, match="hole"):
            rolling.enroll(rolling_setup.root)
        return
    value = admission._unpack(first.read_bytes(), rolling.ENROLLMENT_TYPE)
    if mutation == "skip":
        value["decisions"][0]["position"] = 2
    elif mutation == "parent":
        value["parent"] = rolling._ref(first)
    elif mutation == "terminal":
        value["decisions"][0]["terminal"]["sha256"] = "0"*64
    else:
        value["selected_candidate_ids"].append(value["selected_candidate_ids"][0])
    first.write_bytes(admission._json(admission._bind(rolling.ENROLLMENT_TYPE, value)))
    with pytest.raises(ValueError):
        rolling.verify_enrollment(first)


def test_setting_readiness_is_independent_and_full_graph_is_immutable(rolling_setup):
    spec, _ = _planned(rolling_setup, modes=("front",))
    sites, payload = rolling.verify_capture_plan(spec)
    front = next(plan.Lane(**{key: tuple(item) if key == "workload_ids" else item for key,item in row.items()
                            if key != "campaign_sha256"}) for row in payload["lanes"] if row["mode"] == "front")
    assert rolling.require_mode_readiness(spec, front) == {"retained-canary": "front"}
    with pytest.raises(ValueError, match="buflo lacks"):
        rolling.require_mode_readiness(spec, replace(front, mode="buflo"))
    workload = spec.workload_root / f"{sites[0].workload_id}.json"
    data = lanes._load(workload.read_bytes())
    data["resources"].pop()
    workload.write_bytes(lanes._json(data))
    with pytest.raises(ValueError, match="pruned"):
        rolling.verify_capture_plan(spec)


def test_successor_uses_exact_same_inputs_and_fresh_namespace(rolling_setup):
    spec, _ = _planned(rolling_setup)
    _, payload = rolling.verify_capture_plan(spec)
    initial = payload["lanes"][0]
    held = spec.plan_receipt.read_bytes()
    successor = rolling_setup.root / "successor-plan.json"
    rolling.publish_successor(spec, initial["campaign_name"], 2, successor)
    repaired = replace(spec, plan_receipt=successor)
    _, new = rolling.verify_capture_plan(repaired)
    assert len(new["lanes"]) == 1 and new["lanes"][0]["generation"] == 2
    assert new["lanes"][0]["workload_ids"] == initial["workload_ids"] and new["planned_trace_count"] == 4
    assert spec.plan_receipt.read_bytes() == held
    with pytest.raises(FileExistsError):
        rolling.publish_successor(spec, initial["campaign_name"], 2, rolling_setup.root / "cannot-reuse.json")
    with pytest.raises(ValueError, match="immediate"):
        rolling.publish_successor(spec, initial["campaign_name"], 3, rolling_setup.root / "cannot-skip.json")


def test_actual_installed_deep_command_keeps_all_inputs_source_and_private_writes(rolling_setup):
    spec, _ = _planned(rolling_setup)
    _, payload = rolling.verify_capture_plan(spec)
    target = rolling_setup.root / "lanes" / payload["lanes"][0]["campaign_name"] / "intent.json"
    command = rolling.lane_check_command(spec, rolling_setup.root, target, complete=True)
    assert command[command.index("--network")+1] == "none"
    assert spec.collection_image_digest in command and "--read-only" in command
    assert f"{rolling_setup.root}:{rolling_setup.root}:rw" in command
    assert f"{spec.runtime_source_root}:{spec.runtime_source_root}:ro" in command
    assert "e.executed_image_plan_check" in command[-2] and "e.verify_launch_receipt" in command[-2]
    token = "1" * 32
    owned = rolling.lane_check_command(spec, rolling_setup.root, target, complete=True, operation_token=token)
    assert owned[owned.index("--name") + 1] == "qcsd-rapid-lane-check-" + token
    assert [owned[index + 1] for index, item in enumerate(owned) if item == "--label"] == [
        "org.qcsd.owner=qcsd-lab", "org.qcsd.role=rolling-installed-lane-check",
        "org.qcsd.operation=" + token]
    assert owned[owned.index("--cidfile") + 1] == str(rolling_setup.root / "lane-checks" / token / "container.id")


def _proof(fixture, spec):
    own = Path(rolling.__file__).read_bytes()
    for root in (spec.runtime_source_root, spec.module_root):
        path = root / "src/qcsd_lab/rapid_rolling_capture.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(own)
    return lanes.executed_image_plan_check(spec.serializable())


def test_real_ordinary_intent_is_serial_setting_bound_and_not_formal_from_a_filename(rolling_setup):
    spec, _ = _planned(rolling_setup, modes=("front",))
    proof = _proof(rolling_setup, spec)
    checked = {"proof": proof, "execution": {"returncode": 0, "validator_script_sha256": lanes._sha(lanes.IMAGE_CHECK_SCRIPT.encode()),
        "stdout": lanes._put_object(rolling_setup.root, lanes._json(proof)), "started_at": admission._now()}}
    front = next(row["campaign_name"] for row in proof["plan_payload"]["lanes"] if row["mode"] == "front")
    buflo = next(row["campaign_name"] for row in proof["plan_payload"]["lanes"] if row["mode"] == "buflo")
    with pytest.raises(ValueError, match="buflo lacks"):
        lanes.prepare_lane_intent(spec, rolling_setup.root, buflo, checked)
    assert not (rolling_setup.root / "lanes" / buflo).exists()
    with pytest.raises(ValueError, match="serial"):
        lanes.prepare_lane_intent(spec, rolling_setup.root, front, checked, actuator="parallel-formal-worker")
    intent = lanes.prepare_lane_intent(spec, rolling_setup.root, front, checked)
    facts, lineage, lane, sites = lanes._intent_and_lineage(spec, rolling_setup.root, intent)
    assert facts["actuator"] == "run" and lane.sample_count == 4 and len(sites) == 1
    assert lineage["rolling_readiness"] == {"retained-canary": "front"}
    before = intent.read_bytes()
    with pytest.raises(FileExistsError):
        lanes.prepare_lane_intent(spec, rolling_setup.root, front, checked)
    assert intent.read_bytes() == before


def test_later_failure_of_one_setting_does_not_gate_the_already_proved_peer(rolling_setup, monkeypatch):
    fixture = rolling_setup
    spec, _ = _planned(fixture, modes=("front", "buflo"))
    primitive = readiness.validate_canary
    def current_canary(reference, **kwargs):
        if kwargs["mode"] == "buflo":
            raise ValueError("affected Buflo canary unavailable")
        return primitive(reference, **kwargs)
    monkeypatch.setattr(readiness, "validate_canary", current_canary)
    proof = _proof(fixture, spec)
    checked = {"proof": proof, "execution": {"returncode": 0, "started_at": admission._now()}}
    front = next(row["campaign_name"] for row in proof["plan_payload"]["lanes"] if row["mode"] == "front")
    intent = lanes.prepare_lane_intent(spec, fixture.root, front, checked)
    assert intent.is_file()
    buflo = next(row["campaign_name"] for row in proof["plan_payload"]["lanes"] if row["mode"] == "buflo")
    with pytest.raises(ValueError, match="affected Buflo"):
        lanes.prepare_lane_intent(spec, fixture.root, buflo, checked)
    assert not (fixture.root / "lanes" / buflo).exists()


def test_intent_checks_readiness_once_at_image_start_and_closure_reopens_it(rolling_setup, monkeypatch):
    spec, _ = _planned(rolling_setup, modes=("front",))
    proof = _proof(rolling_setup, spec)
    checked = {"proof": proof, "execution": {"returncode": 0, "started_at": admission._now(),
        "validator_script_sha256": lanes._sha(lanes.IMAGE_CHECK_SCRIPT.encode()),
        "stdout": lanes._put_object(rolling_setup.root, lanes._json(proof))}}
    name = next(row["campaign_name"] for row in proof["plan_payload"]["lanes"] if row["mode"] == "front")
    primitive = rolling.require_mode_readiness
    calls = []
    def current_readiness(actual_spec, lane, *, before=None):
        calls.append((actual_spec, lane.campaign_name, before))
        return primitive(actual_spec, lane, before=before)
    monkeypatch.setattr(rolling, "require_mode_readiness", current_readiness)
    intent = lanes.prepare_lane_intent(spec, rolling_setup.root, name, checked)
    assert calls == [(spec, name, checked["execution"]["started_at"])]
    def changed_canary(*args, **kwargs):
        raise ValueError("retained canary changed before closure")
    monkeypatch.setattr(readiness, "validate_canary", changed_canary)
    with pytest.raises(ValueError, match="changed before closure"):
        lanes._intent_and_lineage(spec, rolling_setup.root, intent)
    assert calls == [(spec, name, checked["execution"]["started_at"])] * 2


def test_failed_readiness_publishes_neither_artifacts_nor_intent(rolling_setup, monkeypatch):
    spec, _ = _planned(rolling_setup, modes=("front",))
    proof = _proof(rolling_setup, spec)
    checked = {"proof": proof, "execution": {"returncode": 0, "started_at": admission._now()}}
    name = next(row["campaign_name"] for row in proof["plan_payload"]["lanes"] if row["mode"] == "front")
    writes = []
    primitive = lanes._put_object
    def put(root, raw):
        writes.append(raw)
        return primitive(root, raw)
    monkeypatch.setattr(lanes, "_put_object", put)
    def unavailable(*args, **kwargs):
        raise ValueError("current full canary unavailable")
    monkeypatch.setattr(readiness, "validate_canary", unavailable)
    with pytest.raises(ValueError, match="canary unavailable"):
        lanes.prepare_lane_intent(spec, rolling_setup.root, name, checked)
    assert writes == []
    assert not (rolling_setup.root / "lanes" / name).exists()


def test_plan_reopens_each_enrollment_once_and_public_wrappers_stay_fresh(rolling_setup, monkeypatch):
    first = rolling.enroll(rolling_setup.root)
    rolling_setup.status["terminal_prefix"] = rolling_setup.terminals[:2]
    second = rolling.enroll(rolling_setup.root)
    output = rolling_setup.root / "second-plan.json"
    rolling.publish_plan(rolling_setup.root, second, rolling_setup.base.spec.qualification_spec, output, readiness={})
    spec = rolling.capture_spec(rolling_setup.root, second, rolling_setup.base.spec.qualification_spec, output)
    primitive = rolling._verify_enrollment
    calls = Counter()
    def verify(path, **kwargs):
        calls[Path(path)] += 1
        return primitive(path, **kwargs)
    monkeypatch.setattr(rolling, "_verify_enrollment", verify)
    sites, payload = rolling.verify_capture_plan(spec)
    assert calls == Counter({first: 1, second: 1})
    for independent in (
        lambda: rolling._sites(second, spec.qualification_spec, spec.workload_root),
        lambda: rolling._bindings(second),
        lambda: rolling.capture_spec(rolling_setup.root, second, spec.qualification_spec, output),
    ):
        calls.clear()
        result = independent()
        assert calls == Counter({first: 1, second: 1})
        assert result in (sites, payload["bindings"], spec)


@pytest.mark.parametrize("changed", ["prefix", "workload", "qualifier", "plan", "runtime"])
def test_factored_plan_rejects_changed_inputs_on_each_new_call(rolling_setup, changed):
    spec, _ = _planned(rolling_setup)
    rolling.verify_capture_plan(spec)
    if changed == "prefix":
        path = admission._child(rolling_setup.context.root, rolling_setup.terminals[0])
        value = admission._unpack(path.read_bytes(), admission.TERMINAL_TYPE)
        value["facts"]["candidate_id"] = "replaced-original-candidate"
        path.write_bytes(admission._json(admission._bind(admission.TERMINAL_TYPE, value)))
    elif changed == "workload":
        path = spec.workload_root / "site-0.json"
        value = lanes._load(path.read_bytes())
        value["resources"].pop()
        path.write_bytes(lanes._json(value))
    elif changed == "qualifier":
        value = lanes._load(spec.qualification_spec.read_bytes())
        path = Path(value["qualification_sets"][0]["manifest"])
        path.write_bytes(lanes._json({"changed": "qualified content"}))
    elif changed == "plan":
        value = admission._unpack(spec.plan_receipt.read_bytes(), lanes.PLAN_TYPE)
        value["lanes"][0]["visits_per_workload"] += 1
        spec.plan_receipt.write_bytes(admission._json(admission._bind(lanes.PLAN_TYPE, value)))
    else:
        spec = replace(spec, collection_image_digest="sha256:" + "e" * 64)
    with pytest.raises(ValueError):
        rolling.verify_capture_plan(spec)


@pytest.mark.parametrize("version,generation", [(5, "final-50"), (True, "rolling-50"), (6.0, "rolling-50"), (6, "final-50")])
def test_rolling_cli_launch_rejects_nonrolling_role_before_actuation(rolling_setup, monkeypatch, version, generation):
    spec, _ = _planned(rolling_setup)
    value = admission._unpack(spec.plan_receipt.read_bytes(), lanes.PLAN_TYPE)
    value.update(study_version=version, cohort_generation=generation)
    spec.plan_receipt.write_bytes(admission._json(admission._bind(lanes.PLAN_TYPE, value)))
    path = rolling_setup.root / "operator-spec.json"
    rolling._write_spec(path, spec)
    calls = []
    monkeypatch.setattr(lanes, "launch_lane", lambda *args, **kwargs: calls.append(args))
    args = cli._parser().parse_args(["launch", "--spec", str(path), "--evidence-root", str(rolling_setup.root),
                                   "--lane", value["lanes"][0]["campaign_name"]])
    with pytest.raises(ValueError, match="version-six"):
        cli.run(args)
    assert calls == []


def test_rolling_cli_launch_defers_full_check_to_mandatory_launch_boundary(rolling_setup, monkeypatch):
    spec, _ = _planned(rolling_setup)
    proof = _proof(rolling_setup, spec)
    name = proof["plan_payload"]["lanes"][0]["campaign_name"]
    path = rolling_setup.root / "operator-spec.json"
    rolling._write_spec(path, spec)
    changed = spec.workload_root / "site-0.json"
    value = lanes._load(changed.read_bytes())
    value["resources"].pop()
    changed.write_bytes(lanes._json(value))
    calls = []
    primitive = lanes.launch_lane
    def launch(*args, **kwargs):
        calls.append("launch-boundary")
        return primitive(*args, **kwargs)
    monkeypatch.setattr(lanes, "launch_lane", launch)
    def no_docker(*args, **kwargs):
        pytest.fail("changed graph must fail before Docker or capture")
    monkeypatch.setattr(lanes.subprocess, "run", no_docker)
    args = cli._parser().parse_args(["launch", "--spec", str(path), "--evidence-root", str(rolling_setup.root), "--lane", name])
    with pytest.raises(ValueError, match="pruned or changed"):
        cli.run(args)
    assert calls == ["launch-boundary"]
    assert not (rolling_setup.root / "lanes" / name).exists()


def test_source_equivalence_must_precede_plan_and_actual_lane_claim(rolling_setup, monkeypatch):
    spec, _ = _planned(rolling_setup)
    _, payload = rolling.verify_capture_plan(spec)
    lane = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    primitive = readiness.validate_canary
    def late_equivalence(reference, **kwargs):
        return {**primitive(reference, **kwargs), "source_equivalence_published_at":
                (admission._utc(payload["declared_at"])+timedelta(seconds=1)).isoformat()}
    monkeypatch.setattr(readiness, "validate_canary", late_equivalence)
    with pytest.raises(ValueError, match="prospectively"):
        rolling.require_mode_readiness(spec, lane, before=payload["declared_at"])


def test_public_image_host_authority_rederives_and_rejects_changed_mounts(rolling_setup):
    spec, _ = _planned(rolling_setup)
    proof = _proof(rolling_setup, spec)
    name = proof["plan_payload"]["lanes"][0]["campaign_name"]
    checked = {"proof": proof, "execution": {"returncode": 0, "started_at": admission._now(),
        "validator_script_sha256": lanes._sha(lanes.IMAGE_CHECK_SCRIPT.encode()),
        "stdout": lanes._put_object(rolling_setup.root, lanes._json(proof))}}
    intent = lanes.prepare_lane_intent(spec, rolling_setup.root, name, checked)
    value = {"spec": spec.serializable(), "root": str(rolling_setup.root), "intent": str(intent),
             "intent_sha256": lanes._sha(intent.read_bytes()), "readiness_mount_roots": []}
    rolling.validate_host_launch(value, expected_campaign=name, actual_image=spec.collection_image_digest)
    value["readiness_mount_roots"] = [str(spec.data_root)]
    with pytest.raises(ValueError, match="derived read-only"):
        rolling.validate_host_launch(value, expected_campaign=name, actual_image=spec.collection_image_digest)


def test_real_failed_only_generation_preserves_completed_peer_and_reopens_original_birth(rolling_setup, monkeypatch):
    spec, _ = _planned(rolling_setup, modes=("undefended", "front"))
    proof = _proof(rolling_setup, spec)
    checked = {"proof": proof, "execution": {"returncode": 0, "validator_script_sha256": lanes._sha(lanes.IMAGE_CHECK_SCRIPT.encode()),
        "stdout": lanes._put_object(rolling_setup.root, lanes._json(proof)), "started_at": admission._now()}}
    baseline = proof["plan_payload"]["lanes"][0]["campaign_name"]
    front = proof["plan_payload"]["lanes"][1]["campaign_name"]
    original = lanes.prepare_lane_intent(spec, rolling_setup.root, baseline, checked)
    peer = lanes.prepare_lane_intent(spec, rolling_setup.root, front, checked)
    # The existing fixture actuates only the external host boundary, producing
    # the real ordinary host-start/terminal schema and raw objects.
    rolling_setup.base.proof.clear()
    rolling_setup.base.proof.update(proof)
    env = {"QCSD_RAPID_V5_PROFILE_PATH": str(spec.execution_root / lanes.STUDY_PROFILE_FILE),
           "QCSD_RAPID_DNS_RECEIPT_PATH": str(original.parent / "dns.json")}
    lanes._actuate_host(spec, rolling_setup.root, original.parent,
        [str(spec.host_launcher), "run", str(spec.campaign_dir / f"{baseline}.yml")], env, 0)
    retained = {path.relative_to(original.parent).as_posix(): path.read_bytes() for path in original.parent.rglob("*") if path.is_file()}
    peer_before = {path.relative_to(peer.parent).as_posix(): path.read_bytes() for path in peer.parent.rglob("*") if path.is_file()}
    output = rolling_setup.root / "recovery-plan.json"
    rolling.publish_successor(spec, baseline, 2, output)
    repaired = replace(spec, plan_receipt=output)
    new_proof = _proof(rolling_setup, repaired)
    new_checked = {"proof": new_proof, "execution": {"returncode": 0, "validator_script_sha256": lanes._sha(lanes.IMAGE_CHECK_SCRIPT.encode()),
        "stdout": lanes._put_object(rolling_setup.root, lanes._json(new_proof)), "started_at": admission._now()}}
    name = new_proof["plan_payload"]["lanes"][0]["campaign_name"]
    with pytest.raises(ValueError, match="immediate predecessor"):
        lanes.prepare_lane_intent(repaired, rolling_setup.root, name, new_checked)
    successor = lanes.prepare_lane_intent(repaired, rolling_setup.root, name, new_checked, predecessor_intent=original)
    _, lineage, lane, _ = lanes._intent_and_lineage(repaired, rolling_setup.root, successor)
    assert lane.generation == 2 and lineage["predecessor_campaign_name"] == baseline
    assert {path.relative_to(original.parent).as_posix(): path.read_bytes() for path in original.parent.rglob("*") if path.is_file()} == retained
    assert {path.relative_to(peer.parent).as_posix(): path.read_bytes() for path in peer.parent.rglob("*") if path.is_file()} == peer_before
    # A completion marker blocks recovery before any new physical claim.
    (peer.parent / "complete.json").write_bytes(b"existing completed peer")
    peer_plan = rolling_setup.root / "forbidden-peer-recovery.json"
    rolling.publish_successor(spec, front, 2, peer_plan)
    peer_spec = replace(spec, plan_receipt=peer_plan)
    peer_proof = _proof(rolling_setup, peer_spec)
    peer_checked = {"proof": peer_proof, "execution": {"returncode": 0, "started_at": admission._now()}}
    with pytest.raises(ValueError, match="completed lane"):
        lanes.prepare_lane_intent(peer_spec, rolling_setup.root, front+"-g02", peer_checked, predecessor_intent=peer)


def test_final_corpus_never_promotes_first_site_to_fifty(rolling_setup):
    rolling.enroll(rolling_setup.root)
    with pytest.raises(ValueError, match="exactly fifty"):
        rolling.publish_corpus(rolling_setup.root, [], rolling_setup.root / "final.json")
    assert not (rolling_setup.root / "final.json").exists()


@pytest.mark.parametrize("mutation", [None, "missing", "duplicate", "wrong-setting", "diagnostic", "wrong-count"])
def test_fifty_site_manifest_derives_every_visit_slot_from_actual_batch_grouping(rolling_setup, monkeypatch, mutation):
    fixture = rolling_setup
    fixture.status["terminal_prefix"] = fixture.terminals[:50]
    cases = {}
    references = []
    for batch_number in range(1, 11):
        enrollment = rolling.enroll(fixture.root, count=5)
        batch, _ = rolling.verify_enrollment(enrollment)
        selected = [f"candidate-{(batch_number-1)*5+index}" for index in range(5)]
        sites = tuple(plan.Site(candidate, candidate, "a"*64, f"https://site{index}.example", "q", "b"*64)
                      for index, candidate in enumerate(selected))
        spec = replace(fixture.base.spec, cohort=enrollment)
        for lane in plan.plan_lanes(sites, final=True, study_version=6, rolling_batch=batch_number):
            key = lane.campaign_name
            reference = {"path": key, "sha256": "f"*64}
            references.append(reference)
            receipt = fixture.root / "lanes" / key / "complete.json"
            receipt.parent.mkdir(parents=True)
            receipt.write_bytes(b"external actual image deep boundary substituted only for slot-closure test")
            cases[key] = (spec, receipt, {"accepted": lane.sample_count, "result_seal_sha256": "e"*64}, lane, sites)
    monkeypatch.setattr(rolling, "_reopen_lane_check", lambda reference: cases[reference["path"]])
    if mutation == "missing":
        references.pop()
    elif mutation == "duplicate":
        references[-1] = references[0]
    elif mutation in {"wrong-setting", "diagnostic", "wrong-count"}:
        key = references[0]["path"]
        spec, receipt, facts, lane, sites = cases[key]
        if mutation == "wrong-setting":
            lane = replace(lane, mode="invented")
        elif mutation == "diagnostic":
            lane = replace(lane, role="diagnostic")
        else:
            facts = {**facts, "accepted": 19}
        cases[key] = spec, receipt, facts, lane, sites
    if mutation is not None:
        with pytest.raises(ValueError):
            rolling.publish_corpus(fixture.root, references, fixture.root / "complete-corpus.json")
        return
    facts = rolling.publish_corpus(fixture.root, references, fixture.root / "complete-corpus.json")
    assert facts["accepted"] == 16000 and facts["lane_count"] == 800
    assert rolling.verify_corpus_manifest(fixture.root, fixture.root / "complete-corpus.json") == facts


def test_failed_actual_image_deep_record_preserves_command_logs_and_gives_no_completion(rolling_setup, monkeypatch):
    spec, _ = _planned(rolling_setup)
    _, payload = rolling.verify_capture_plan(spec)
    intent = rolling_setup.root / "lanes" / payload["lanes"][0]["campaign_name"] / "intent.json"
    intent.parent.mkdir(parents=True)
    intent.write_bytes(b"unexecuted target fixture")
    monkeypatch.setattr(rolling.subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "actual failed deep stdout", "actual strict failure"))
    with pytest.raises(ValueError, match="raw records retained"):
        rolling.check_lane_in_image(spec, rolling_setup.root, intent, complete=True)
    records = list((rolling_setup.root / "lane-checks").glob("*/actual-completed.json"))
    assert len(records) == 1
    actual = lanes._load(records[0].read_bytes())
    assert actual["returncode"] == 1 and lanes._object(rolling_setup.root, actual["stderr"]) == b"actual strict failure"
    assert not (intent.parent / "complete.json").exists()
    assert not list((rolling_setup.root / "lane-checks").glob("*/closure.json"))


@pytest.mark.parametrize("case,expected_status,removed", [
    ("cidfile", "removed", True),
    ("name-fallback", "removed", True),
    ("wrong-owner", "identity-mismatch", False),
    ("wrong-id", "identity-mismatch", False),
    ("invalid-cidfile", "cleanup-error", False),
    ("inspect-timeout", "cleanup-error", False),
    ("remove-failed", "remove-failed", True),
])
def test_timed_out_installed_deep_records_budget_and_cleans_only_exact_owned_actor(
        rolling_setup, monkeypatch, case, expected_status, removed):
    spec, _ = _planned(rolling_setup)
    _, payload = rolling.verify_capture_plan(spec)
    lane = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    intent = rolling_setup.root / "lanes" / lane.campaign_name / "intent.json"
    intent.parent.mkdir(parents=True)
    intent.write_bytes(b"unexecuted timeout target")
    container_id = "a" * 64
    commands = []
    def timed_out(command, **kwargs):
        commands.append(command)
        if command[:2] == ["docker", "run"]:
            assert kwargs["timeout"] == 300 + lane.sample_count * plan.V5_CAPTURE_LIMITS["timeout_seconds"]
            assert kwargs["timeout"] > 600
            cidfile = Path(command[command.index("--cidfile") + 1])
            assert cidfile.parent.is_dir()
            if case != "name-fallback":
                cidfile.write_text("invalid\n" if case == "invalid-cidfile" else container_id + "\n")
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"partial deep output",
                                            stderr=b"timed out deep verifier")
        if command[:3] == ["docker", "container", "inspect"]:
            if case == "inspect-timeout":
                raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"inspect partial", stderr=b"inspect timeout")
            token = next(item.split("=", 1)[1] for item in commands[0] if item.startswith("org.qcsd.operation="))
            name = "qcsd-rapid-lane-check-" + token
            assert command[-1] == (name if case == "name-fallback" else container_id)
            observed = {"Id": "b" * 64 if case == "wrong-id" else container_id, "Name": "/" + name,
                        "Config": {"Image": spec.collection_image_digest, "Labels": {
                            "org.qcsd.owner": "different-owner" if case == "wrong-owner" else "qcsd-lab",
                            "org.qcsd.role": "rolling-installed-lane-check",
                            "org.qcsd.operation": token}}}
            return subprocess.CompletedProcess(command, 0, json.dumps([observed]), "")
        if command[:3] == ["docker", "rm", "-f"]:
            assert command[-1] == container_id
            return subprocess.CompletedProcess(command, 1 if case == "remove-failed" else 0,
                                               "", "remove failed" if case == "remove-failed" else "")
        raise AssertionError("unexpected Docker action")
    monkeypatch.setattr(rolling.subprocess, "run", timed_out)
    with pytest.raises(ValueError, match="raw records retained"):
        rolling.check_lane_in_image(spec, rolling_setup.root, intent, complete=True)
    records = list((rolling_setup.root / "lane-checks").glob("*/actual-completed.json"))
    assert len(records) == 1
    end = lanes._load(records[0].read_bytes())
    start = lanes._load((records[0].parent / "actual-started.json").read_bytes())
    assert start["operation_token"] == end["operation_token"]
    assert start["timeout_seconds"] == end["timeout_seconds"] == 300 + lane.sample_count * plan.V5_CAPTURE_LIMITS["timeout_seconds"]
    assert end["returncode"] is None and end["invocation_error"]["type"] == "TimeoutExpired"
    cleanup = end["invocation_error"]["cleanup"]
    assert cleanup["status"] == expected_status
    if cleanup["inspect"] is not None:
        assert cleanup["inspect"]["command"][:3] == ["docker", "container", "inspect"]
        assert lanes._object(rolling_setup.root, cleanup["inspect"]["stdout"])
    if case == "inspect-timeout":
        assert cleanup["error"]["type"] == "TimeoutExpired" and cleanup["remove"] is None
    if case == "remove-failed":
        assert cleanup["remove"]["returncode"] == 1
        assert lanes._object(rolling_setup.root, cleanup["remove"]["stderr"]) == b"remove failed"
    assert lanes._object(rolling_setup.root, end["stdout"]) == b"partial deep output"
    assert lanes._object(rolling_setup.root, end["stderr"]) == b"timed out deep verifier"
    assert bool([command for command in commands if command[:3] == ["docker", "rm", "-f"]]) == removed
    assert not (intent.parent / "complete.json").exists()
    assert not list((rolling_setup.root / "lane-checks").glob("*/closure.json"))


def test_actual_completion_script_then_host_reopen_seals_exact_lane_and_rejects_changed_raw_output(rolling_setup, monkeypatch):
    fixture = rolling_setup
    spec, _ = _planned(fixture)
    proof = _proof(fixture, spec)
    checked = {"proof": proof, "execution": {"returncode": 0, "validator_script_sha256": lanes._sha(lanes.IMAGE_CHECK_SCRIPT.encode()),
        "stdout": lanes._put_object(fixture.root, lanes._json(proof)), "started_at": admission._now()}}
    campaign = proof["plan_payload"]["lanes"][0]["campaign_name"]
    intent = lanes.prepare_lane_intent(spec, fixture.root, campaign, checked)
    fixture.base.proof.clear()
    fixture.base.proof.update(proof)
    env = {"QCSD_RAPID_V5_PROFILE_PATH": str(spec.execution_root / lanes.STUDY_PROFILE_FILE),
           "QCSD_RAPID_DNS_RECEIPT_PATH": str(intent.parent / "dns.json")}
    lanes._actuate_host(spec, fixture.root, intent.parent,
        [str(spec.host_launcher), "run", str(spec.campaign_dir / f"{campaign}.yml")], env, 0)
    (intent.parent / "dns.json").write_bytes(lanes._json({"schema_version": 1, "campaign": campaign,
        "hosts": [["cdn.example", "8.8.8.8"], ["site0.example", "8.8.8.8"]]}))
    result = spec.execution_root / "results" / campaign / "attempt-001"
    for name in ("inputs", "samples", "failures"):
        (result / name).mkdir()
    (result / "evidence.sha256").write_text(f"{lanes._sha((result/'experiment.json').read_bytes())}  experiment.json\n")
    deep_calls = []
    def measured_result(path, lane, **kwargs):
        deep_calls.append(path)
        return {"accepted": lane.sample_count, "result_seal_sha256": lanes._sha((path/"evidence.sha256").read_bytes()),
                "scientific_credit": "formal-only-if-bound-to-rolling-enrollment"}
    monkeypatch.setattr(plan, "verify_lane_result", measured_result)
    def installed(command, **kwargs):
        assert command[-2] == rolling.LANE_CHECK_SCRIPT
        output = io.StringIO()
        with monkeypatch.context() as process:
            process.setattr(sys, "argv", ["-c", command[-1]])
            with contextlib.redirect_stdout(output):
                exec(command[-2], {"__name__": "__main__"})
        return subprocess.CompletedProcess(command, 0, output.getvalue(), "")
    monkeypatch.setattr(rolling.subprocess, "run", installed)
    closed = rolling.check_lane_in_image(spec, fixture.root, intent, complete=True)
    assert closed["accepted"] == 4 and Path(closed["receipt"]).is_file()
    assert deep_calls == [result]
    assert rolling._reopen_lane_check(closed["closure"])[3].mode == "undefended"
    rechecked = rolling.check_lane_in_image(spec, fixture.root, Path(closed["receipt"]), complete=False)
    assert deep_calls == [result, result]
    original = admission._unpack(Path(rechecked["closure"]["path"]).read_bytes(), rolling.LANE_CHECK_TYPE)
    legacy = fixture.root / "lane-checks" / "legacy-complete-false"
    legacy.mkdir()
    old_command = rolling.lane_check_command(spec, fixture.root, Path(closed["receipt"]), complete=False)
    started = lanes._load(rolling._open_ref(original["started"]).read_bytes())
    completed = lanes._load(rolling._open_ref(original["completed"]).read_bytes())
    for record in (started, completed):
        record["command"] = old_command
        record.pop("operation_token")
        record.pop("timeout_seconds")
    admission.durable_create(legacy / "actual-started.json", admission._json(started))
    admission.durable_create(legacy / "actual-completed.json", admission._json(completed))
    old_closure = {**original, "started": rolling._ref(legacy / "actual-started.json"),
                   "completed": rolling._ref(legacy / "actual-completed.json")}
    legacy_closure = rolling._write(legacy / "closure.json", rolling.LANE_CHECK_TYPE, old_closure)
    assert rolling._reopen_lane_check(rolling._ref(legacy_closure))[2]["accepted"] == 4
    experiment = result / "experiment.json"
    original_experiment = experiment.read_bytes()
    experiment.write_bytes(original_experiment + b"\n")
    with pytest.raises(ValueError, match="rolling result bytes differ from the actual deep-verified seal"):
        rolling._reopen_lane_check(closed["closure"])
    experiment.write_bytes(original_experiment)
    closure = Path(closed["closure"]["path"])
    value = admission._unpack(closure.read_bytes(), rolling.LANE_CHECK_TYPE)
    actual = lanes._load(rolling._open_ref(value["completed"]).read_bytes())
    object_path = admission._child(fixture.root, actual["stdout"])
    object_path.write_bytes(b"changed installed deep output")
    with pytest.raises(ValueError):
        rolling._reopen_lane_check(closed["closure"])


@pytest.mark.parametrize("authority,resume,status", [(False, False, 1), (True, False, 0), (True, True, 2)])
def test_actual_shell_selector_requires_rolling_authority_and_disables_resume(tmp_path, authority, resume, status):
    name = plan.plan_lanes(_sites(1), final=True, study_version=6, rolling_batch=1)[0].campaign_name
    root = tmp_path / "execution"
    campaign = root / "config/campaigns" / f"{name}.yml"
    campaign.parent.mkdir(parents=True)
    campaign.write_text("source-bound campaign fixture")
    frozen = root / "results" / name / "attempt-001" / "inputs/campaign.yml"
    frozen.parent.mkdir(parents=True)
    frozen.write_bytes(campaign.read_bytes())
    script = (Path(__file__).parents[1] / "qcsd-lab").read_text()
    start = script.index("rapid_v2_diagnostic_pattern=")
    end = script.index('study_build_execution_path=""', start)
    selected = script[start:end]
    invocation = ["resume", str(frozen.parent.parent)] if resume else ["run", str(campaign)]
    environment = dict(os.environ, ROOT=str(root), study_campaign_name=campaign.name,
        study_resume_name=name, study_resume_root=str(frozen.parent.parent),
        QCSD_RAPID_ROLLING_LAUNCH_INPUT="bound-intent" if authority else "")
    result = subprocess.run(["bash", "-c", selected+'\nprintf "%s %s\\n" "$rapid_capture_version" "$rapid_capture_mode"', "selector", *invocation],
        env=environment, text=True, capture_output=True)
    assert result.returncode == status
    if status == 0:
        assert result.stdout.strip() == "v6 undefended"


def test_retained_real_admission_enrolls_first_eligible_with_all_graph_bytes(setup, monkeypatch):
    root_text = os.environ.get("QCSD_RETAINED_ADMISSION_ROOT")
    if not root_text:
        pytest.skip("requires explicitly selected immutable admission fixture")
    root = Path(root_text)
    context = admission.load_admission_context(root)
    checkpoint = sorted((root / "checkpoints").glob("checkpoint-*.json"))[-1]
    prefix = lanes._load(checkpoint.read_bytes())["payload"]["status"]["terminal_prefix"]
    # Freeze the actual retained ordered prefix; no current browser or status call.
    monkeypatch.setattr(admission, "acquisition_status", lambda ctx: {"terminal_prefix": prefix})
    runtime = {key: setup.spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    rolling.initialize_study(root, setup.root, runtime)
    enrollment = rolling.enroll(setup.root)
    batch, selected = rolling.verify_enrollment(enrollment)
    assert len(selected) == 1 and batch["decisions"][-1]["outcome"] == "admitted"
    candidate = selected[0]
    terminal = admission._unpack(lanes._read(rolling._open_ref(candidate["terminal"])), admission.TERMINAL_TYPE)
    preparation = admission._unpack(lanes._read(admission._child(root, terminal["preparation"])), admission.PREPARATION_TYPE)
    workload = admission._child(root, preparation["prepared_workload"])
    raw = workload.read_bytes()
    actual = lanes._load(raw)
    assert len(actual["resources"]) >= 2 and len(actual["preparation"]["approved_origins"]) >= 2
    assert lanes._sha(raw) == preparation["prepared_workload"]["sha256"]
    mutated = copy.deepcopy(batch)
    mutated["decisions"] = mutated["decisions"][1:]
    enrollment.write_bytes(admission._json(admission._bind(rolling.ENROLLMENT_TYPE, mutated)))
    with pytest.raises(ValueError, match="reordered|skipped|differs"):
        rolling.verify_enrollment(enrollment)
