"""Rolling parallel closure with real plans, intents and typed worker receipts.

The closed scheduling/runtime primitive and packet verifier are fixture seams.
Docker calls execute the actual installed-validator script locally; no Docker
daemon, Native compilation or recorded scientific result is used by this file.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import orchestrator, runtime_provenance, verification
from qcsd_lab import chaff_qualification as qualification, util
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_capture as shared
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_rolling_schedule as schedule
from tests.test_rapid_lane_evidence import setup as ordinary_setup
from tests.test_rapid_rolling_capture import rolling_setup
from tests.test_rapid_formal_parallel import _initialize, _release, _retire, _close, _snapshot, _write
from tools import rapid_formal_parallel as cli

VERIFY_LANE_RESULT = plan.verify_lane_result


@pytest.fixture
def setup(ordinary_setup):
    fixture = ordinary_setup
    fixture.spec = replace(fixture.spec, module_root=fixture.spec.runtime_source_root)
    fixture.spec.host_launcher.write_bytes(fixture.spec.base_launcher.read_bytes())
    source = Path(__file__).parents[1]
    for name in ("rapid_parallel_capture.py", "rapid_formal_parallel.py", "rapid_rolling_capture.py"):
        target = fixture.spec.runtime_source_root / "src/qcsd_lab" / name
        target.write_bytes((source / "src/qcsd_lab" / name).read_bytes())
    for name in ("buflo-live.json", "buflo-live.json.provenance.json",
                 "cs-buflo-ctsp-live.json", "cs-buflo-ctsp-live.json.provenance.json"):
        relative = Path("config/defense-params") / name
        for root in (fixture.spec.runtime_source_root, fixture.spec.execution_root):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source / relative).read_bytes())
    return fixture


@pytest.fixture
def parallel_setup(rolling_setup, monkeypatch, tmp_path):
    fixture = rolling_setup
    # The scheduling constructor has its own actual twelve-operation fixtures.
    # This boundary exposes a closed capsule so the real rolling/ordinary lane
    # validators and create-only ordering remain exercised here.
    capsule = tmp_path / "closed-runtime-proof" / "schedule.json"
    capsule.parent.mkdir()
    _write(capsule, {"fixture": "closed scheduling primitive"})
    reference = rolling._ref(capsule)
    state = {"base_spec": None}
    def validate(reference_value, *, runtime=None, before=None):
        assert formal._reference(reference_value) == capsule
        if runtime is not None:
            assert runtime == fixture.runtime
        return {"base_spec": state["base_spec"], "runtime": fixture.runtime,
                "qualification_spec": rolling._ref(fixture.base.spec.qualification_spec)}
    def require(reference_value, spec, *, declared_at, started_at=None):
        value = validate(reference_value, runtime={key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS})
        assert lanes.admission._utc(declared_at) <= lanes.admission._utc(lanes.admission._now())
        if started_at is not None:
            assert lanes.admission._utc(declared_at) <= lanes.admission._utc(started_at)
        assert spec.cohort == Path(value["base_spec"]["cohort"])
        return value
    def canary(reference_value, schedule_reference, *, mode, before=None):
        validate(schedule_reference)
        assert reference_value == {"retained-canary": mode}
        return readiness.validate_canary(reference_value,
            runtime={key: fixture.runtime[key] for key in lanes.RUNTIME_KEYS}, mode=mode)
    monkeypatch.setattr(schedule, "validate_schedule", validate)
    monkeypatch.setattr(schedule, "require_schedule", require)
    monkeypatch.setattr(schedule, "validate_ready_canary", canary)
    monkeypatch.setattr(schedule, "mount_roots", lambda reference_value: [formal._reference(reference_value).parent])
    installed = dict(fixture.base.implementation["source_files"])
    for name in ("rapid_parallel_capture.py", "rapid_formal_parallel.py", "rapid_rolling_capture.py"):
        key = "src/qcsd_lab/" + name
        installed[key] = shared.sha((fixture.base.spec.runtime_source_root / key).read_bytes())
    monkeypatch.setattr(runtime_provenance, "validate_runtime_receipt",
        lambda **kwargs: {"schema_version": 2, "source_files": installed})
    commands = []
    def image(command, **options):
        assert command[:2] == ["docker", "run"]
        assert command[command.index("--network")+1] == "none" and "--read-only" in command
        commands.append(command)
        stdout = io.StringIO()
        argv = sys.argv
        prior = dict(os.environ)
        try:
            for index, word in enumerate(command):
                if word == "--env":
                    key, item = command[index+1].split("=", 1)
                    os.environ[key] = item
            sys.argv = ["-c", command[-1]]
            with contextlib.redirect_stdout(stdout):
                exec(compile(command[-2], "<actual-installed-validator-fixture>", "exec"), {})
            return subprocess.CompletedProcess(command, 0, stdout.getvalue(), "actual fixture image output\n")
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            return subprocess.CompletedProcess(command, 1, stdout.getvalue(), f"{type(error).__name__}: {error}\n")
        finally:
            sys.argv = argv
            os.environ.clear()
            os.environ.update(prior)
    monkeypatch.setattr(lanes.subprocess, "run", image)
    def installed_campaign(path):
        document = shared.load(Path(path)) if Path(path).suffix == ".json" else None
        import yaml
        document = document or yaml.safe_load(Path(path).read_bytes())
        return SimpleNamespace(path=Path(path), workloads=[SimpleNamespace(id=name,
            path=fixture.base.spec.workload_root / f"{name}.json",
            data=shared.load(fixture.base.spec.workload_root / f"{name}.json"), visits=count,
            sha256=shared.sha((fixture.base.spec.workload_root / f"{name}.json").read_bytes()),
            chaff_qualification_path=None, chaff_manifest_path=None, qualification_set_manifest_path=None)
            for name, count in document["workloads"].items()], defenses=[SimpleNamespace(
                parameters_path=None, parameters_provenance_path=None)])
    monkeypatch.setattr(orchestrator, "load_campaign", installed_campaign)
    reads = []
    def packets(path):
        path = Path(path)
        reads.append(path)
        files = verification.authoritative_files(path)
        checksums = verification._read_checksums(path, path / "evidence.sha256")
        if set(files) != set(checksums) or any(shared.sha(item.read_bytes()) != checksums[name] for name,item in files.items()):
            raise ValueError("fixture packet boundary received changed authoritative bytes")
        return SimpleNamespace(experiment=shared.load(path / "experiment.json"))
    monkeypatch.setattr(plan, "verify_result", packets)
    monkeypatch.setattr(plan, "verify_lane_result", VERIFY_LANE_RESULT)
    return SimpleNamespace(fixture=fixture, reference=reference, state=state, commands=commands,
                           reads=reads, sequence=0)


def _plan(fixture, count=1, *, scheduling=True):
    seed = fixture.fixture
    seed.status["terminal_prefix"] = seed.terminals[:count]
    enrollment = rolling.enroll(seed.root, count=count)
    fixture.state["base_spec"] = replace(seed.base.spec, cohort=enrollment).serializable()
    output = seed.root / "parallel-plan.json"
    rolling.publish_plan(seed.root, enrollment, seed.base.spec.qualification_spec, output,
        readiness={"undefended": {"retained-canary": "undefended"}},
        **({"scheduling": fixture.reference} if scheduling else {}))
    spec = rolling.capture_spec(seed.root, enrollment, seed.base.spec.qualification_spec, output)
    sites, payload = rolling.verify_capture_plan(spec)
    values = [lanes._lane({"plan_payload": payload}, row["campaign_name"])
              for row in payload["lanes"] if row["mode"] == "undefended"]
    path = seed.root / "parallel-spec.json"
    rolling._write_spec(path, spec)
    return SimpleNamespace(spec=spec, spec_path=path, root=seed.root, sites=sites,
        lanes=values, sequence=0, fixture=fixture)


def _prepare(setup, selected=None, *, first_spec=None, second_spec=None, predecessors=None):
    setup.sequence += 1
    selected = selected or setup.lanes[:2]
    path = setup.root / f"parallel-authority-{setup.sequence}.json"
    output = setup.spec.execution_root / "results" / f"rolling-parallel-{setup.sequence}"
    output.mkdir(parents=True)
    formal.prepare_batch(first_spec or setup.spec_path, setup.root,
        [lane.campaign_name for lane in selected], path, predecessors, second_spec=second_spec)
    return SimpleNamespace(setup=setup, lanes=selected, path=path, output=output,
        digest=shared.sha(path.read_bytes()), value=formal.authority(path))


def _result(batch, index):
    lane, spec = batch.lanes[index], batch.setup.spec
    partition = shared.load(batch.output / f"lane-{index+1}/gate/host-partition.json")
    samples = [dict(workload_id=name, visit=visit, defense=lane.mode, state="accepted", request_policy="as-defined",
        diagnostics={"scheduler_runtime_receipt": {"scheduler_runtime_evidence": {"schema_version": 5,
            "host_partition": partition}}}) for name in lane.workload_ids for visit in range(4)]
    result = spec.execution_root / "results" / lane.campaign_name / "attempt-001"
    for name in verification.AUTHORITATIVE_DIRECTORIES:
        (result / name).mkdir(parents=True)
    _write(result / "experiment.json", dict(started_at=shared.now(), status="complete", name=lane.campaign_name,
        purpose="evaluation", source=dict(image_digest=spec.collection_image_digest, lab_commit="b"*40, lab_dirty=False),
        summary=dict(planned=lane.sample_count, accepted=lane.sample_count, failed=0, passed=True),
        configuration=dict(campaign_sha256=shared.sha((spec.campaign_dir / f"{lane.campaign_name}.yml").read_bytes()),
            profile="research-1200", request_policies=["as-defined"], chaff_qualification_set=None,
            chaff_qualification_set_manifest_sha256=None, defenses=[dict(name=lane.mode)],
            workloads=[dict(id=name, visits=4, sha256=shared.sha((spec.workload_root / f"{name}.json").read_bytes()))
                       for name in lane.workload_ids]), samples=samples))
    _seal(result)
    return result


def _seal(result):
    # Packet actuation is the explicit fixture seam. Retain a real exact file
    # index so the installed closure still checks every governed byte.
    files = verification.authoritative_files(result)
    (result / "evidence.sha256").write_text("".join(
        f"{shared.sha(path.read_bytes())}  {name}\n" for name, path in files.items()))


def _terminal(setup, *, failed_first=False):
    batch = _release(_initialize(_prepare(setup)))
    batch.results = [_result(batch, index) for index in range(2)]
    _retire(batch, 0, 1 if failed_first else 0)
    assert not (setup.root / "lanes" / batch.lanes[0].campaign_name / "complete.json").exists()
    assert not (setup.root / "lane-checks").exists()
    _retire(batch, 1, 0, peer_running=False)
    _close(batch, 1 if failed_first else 0)
    return batch


@pytest.mark.parametrize("count", [1, 5])
def test_real_rolling_workers_close_in_installed_image_with_exact_four_visit_geometry(parallel_setup, count):
    setup = _plan(parallel_setup, count)
    batch = _terminal(setup)
    report = formal.verify_results(batch.path, batch.output)
    assert report["valid"] and report["formal_accepted_trace_count"] == 8*count, report
    for index, row in enumerate(report["lanes"]):
        assert row["accepted"] == 4*count
        assert row["scientific_credit"] == "formal-only-if-bound-to-rolling-enrollment"
        spec, receipt, facts, lane, sites = rolling._reopen_lane_check(row["installed_deep"])
        assert spec == setup.spec and lane == batch.lanes[index] and sites == setup.sites
        assert receipt.name == "complete.json" and facts["accepted"] == 4*count
    assert parallel_setup.reads
    inputs = [formal.worker_inputs(batch.path, index) for index in range(2)]
    for index, value in enumerate(inputs):
        launch = json.loads(value["environment"]["QCSD_RAPID_ROLLING_LAUNCH_INPUT"])
        assert launch["intent"] == str(setup.root / "lanes" / batch.lanes[index].campaign_name / "intent.json")
        assert str(Path(parallel_setup.reference["path"]).parent) in value["mount_roots"]
        assert value["environment"]["QCSD_RAPID_COLLECTION_COMPATIBILITY"] == parallel_setup.reference["path"]
        assert "QCSD_RAPID_EPOCH_LAUNCH_INPUT" not in value["environment"]
    count_before = len(parallel_setup.commands)
    held = _snapshot(*(setup.root / "lanes" / lane.campaign_name for lane in batch.lanes))
    assert formal.verify_results(batch.path, batch.output) == report
    assert len(parallel_setup.commands) == count_before and held == _snapshot(*(setup.root / "lanes" / lane.campaign_name for lane in batch.lanes))


def test_failed_only_g02_retains_completed_peer_and_original_worker_inputs(parallel_setup):
    setup = _plan(parallel_setup)
    batch = _terminal(setup, failed_first=True)
    report = formal.verify_results(batch.path, batch.output)
    assert not report["valid"] and report["lanes"][0]["actual_exit_code"] == 1
    assert report["lanes"][0]["accepted"] == 0 and report["lanes"][1]["accepted"] == 4
    failed = setup.root / "lanes" / batch.lanes[0].campaign_name / "intent.json"
    peer = setup.root / "lanes" / batch.lanes[1].campaign_name
    retained = _snapshot(failed.parent, peer, *batch.results)
    successor = setup.root / "g02-plan.json"
    rolling.publish_successor(setup.spec, batch.lanes[0].campaign_name, 2, successor)
    repaired = replace(setup.spec, plan_receipt=successor)
    repaired_path = setup.root / "g02-spec.json"
    rolling._write_spec(repaired_path, repaired)
    _, payload = rolling.verify_capture_plan(repaired)
    g02 = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    recovery = _release(_initialize(_prepare(setup, [g02, setup.lanes[2]],
        first_spec=repaired_path, second_spec=setup.spec_path, predecessors=[failed, None])))
    assert retained == _snapshot(failed.parent, peer, *batch.results)
    recovery.results = [_result(recovery, index) for index in range(2)]
    _retire(recovery, 0, 0)
    _retire(recovery, 1, 0, peer_running=False)
    _close(recovery, 0)
    assert formal.verify_results(recovery.path, recovery.output)["formal_accepted_trace_count"] == 8
    assert retained == _snapshot(failed.parent, peer, *batch.results)
    old_peer_plan = setup.root / "forbidden-peer-g02.json"
    rolling.publish_successor(setup.spec, batch.lanes[1].campaign_name, 2, old_peer_plan)
    forbidden_spec = replace(setup.spec, plan_receipt=old_peer_plan)
    forbidden_path = setup.root / "forbidden-peer-spec.json"
    rolling._write_spec(forbidden_path, forbidden_spec)
    _, payload = rolling.verify_capture_plan(forbidden_spec)
    forbidden = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    with pytest.raises(ValueError, match="completed lane"):
        _prepare(setup, [setup.lanes[3], forbidden], second_spec=forbidden_path,
                 predecessors=[None, peer / "intent.json"])
    assert not (setup.root / "lanes" / setup.lanes[3].campaign_name).exists()
    assert retained == _snapshot(failed.parent, peer, *batch.results)


def test_installed_closure_rejects_changed_bound_worker_evidence(parallel_setup):
    setup = _plan(parallel_setup)
    batch = _terminal(setup)
    report = formal.verify_results(batch.path, batch.output)
    assert report["valid"]
    source = setup.spec.runtime_source_root / "src/qcsd_lab/rapid_formal_parallel.py"
    dns = setup.root / "lanes" / batch.lanes[0].campaign_name / "dns.json"
    seal, experiment = batch.results[0] / "evidence.sha256", batch.results[0] / "experiment.json"
    launch, capsule = batch.output / "actual-launch.json", Path(parallel_setup.reference["path"])
    original = {path: path.read_bytes() for path in (source, dns, seal, experiment, launch, capsule)}
    peer_roots = (setup.root / "lanes" / batch.lanes[1].campaign_name, batch.results[1], batch.output / "lane-2")
    peer = _snapshot(*peer_roots)
    # Each mutation starts with exactly the same completed pair. This retains
    # the six independent checks without actuating six duplicate fixture pairs.
    for mutation in ("source", "dns", "seal", "worker", "schedule", "slot"):
        try:
            if mutation == "source":
                source.write_bytes(original[source] + b"# changed bound runtime\n")
            elif mutation == "dns":
                value = shared.load(dns); value["hosts"][0][1] = "1.1.1.1"; _write(dns, value)
            elif mutation == "seal":
                seal.write_bytes(original[seal] + b"invalid appended index\n")
            elif mutation == "worker":
                value = shared.load(launch); value["workers"][0]["id"] = "0"*64; _write(launch, value)
            elif mutation == "schedule":
                _write(capsule, {"changed": "capsule"})
            else:
                value = shared.load(experiment); value["samples"][0]["visit"] = 3; _write(experiment, value)
                _seal(batch.results[0])
            with pytest.raises((OSError, ValueError, AssertionError)):
                rolling._reopen_lane_check(report["lanes"][0]["installed_deep"])
        finally:
            for path, raw in original.items():
                path.write_bytes(raw)
        assert _snapshot(*peer_roots) == peer, mutation


def test_unbound_v6_plan_cannot_claim_either_worker(parallel_setup):
    setup = _plan(parallel_setup, scheduling=False)
    with pytest.raises(ValueError, match="scheduling"):
        _prepare(setup)
    assert all(not (setup.root / "lanes" / lane.campaign_name).exists() for lane in setup.lanes[:2])


def test_public_formal_tool_uses_existing_arguments_for_schedule_bound_v6(parallel_setup, capsys):
    setup = _plan(parallel_setup)
    path = setup.root / "tool-authority.json"
    assert cli.main(["--spec", str(setup.spec_path), "--evidence-root", str(setup.root),
        "--lane", setup.lanes[0].campaign_name, "--lane", setup.lanes[1].campaign_name,
        "--output", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["scientific_credit"] is False
    assert all(fact[5].study_version == 6 for fact in formal._audit(path)[1])


@pytest.fixture
def serial_source_recovery(parallel_setup, monkeypatch, tmp_path):
    """Exercise source recovery using the existing external host fixture seam.

    The real ordinary intent/start/process/object schemas remain in use. The
    substituted host actuation reports failure; no old result is deep verified
    or credited. Runtime closure is the same explicit scheduling primitive as
    the other integration cases in this file.
    """
    seed = parallel_setup.fixture
    # Relative qualifier refs support relocation with exactly the same sealed
    # spec bytes. Establish that layout before any old plan or intent exists.
    original_qualifier = seed.base.spec.execution_root / "config" / "copied-qualification-spec.json"
    qualifier = shared.load(seed.base.spec.qualification_spec)
    for row in qualifier["qualification_sets"]:
        for key in ("manifest", "sidecar_root"):
            row[key] = Path(row[key]).relative_to(original_qualifier.parent).as_posix()
    _write(original_qualifier, qualifier)
    seed.base.spec = replace(seed.base.spec, qualification_spec=original_qualifier)
    old = _plan(parallel_setup, scheduling=False)
    checked = lanes.check_bound_image(old.spec, old.root)
    original = lanes.prepare_lane_intent(old.spec, old.root, old.lanes[0].campaign_name, checked)
    seed.base.proof.clear()
    seed.base.proof.update(checked["proof"])
    create = lanes._create
    def failed_host_record(root, output, receipt_type, payload):
        if receipt_type == lanes.PROCESS_TYPE:
            payload = {**payload, "returncode": 1}
        return create(root, output, receipt_type, payload)
    with monkeypatch.context() as boundary:
        boundary.setattr(lanes, "_create", failed_host_record)
        lanes._actuate_host(old.spec, old.root, original.parent,
            [str(old.spec.host_launcher), "run", str(old.spec.campaign_dir / f"{old.lanes[0].campaign_name}.yml")],
            {"QCSD_RAPID_V5_PROFILE_PATH": str(old.spec.execution_root / lanes.STUDY_PROFILE_FILE),
             "QCSD_RAPID_DNS_RECEIPT_PATH": str(original.parent / "dns.json")}, 0)
    original_result = old.spec.execution_root / "results" / old.lanes[0].campaign_name
    assert lanes._payload(original, lanes.INTENT_TYPE)["actuator"] == "run"
    assert lanes._payload(original.parent / "host-process.json", lanes.PROCESS_TYPE)["returncode"] == 1
    assert not (original.parent / "complete.json").exists()
    retained = _snapshot(original.parent, original_result)

    current_root = tmp_path / "new-installed-control-source"
    shutil.copytree(old.spec.runtime_source_root, current_root)
    execution = old.spec.data_root / "new-control-execution"
    shutil.copytree(old.spec.execution_root, execution, ignore=shutil.ignore_patterns("results"))
    qualifier_path = execution / "config" / "copied-qualification-spec.json"
    assert qualifier_path.read_bytes() == old.spec.qualification_spec.read_bytes()
    source = copy.deepcopy(shared.load(old.spec.source_manifest))
    source["lab_commit"] = "d" * 40
    source_path = old.spec.data_root / "new-control-source.json"
    _write(source_path, source)
    current = replace(old.spec, runtime_source_root=current_root, module_root=current_root,
        source_manifest=source_path, base_launcher=current_root / "qcsd-lab",
        execution_root=execution, host_launcher=execution / "qcsd-lab",
        campaign_dir=execution / "config/campaigns", workload_root=execution / "config/workloads",
        qualification_spec=qualifier_path,
        collection_image_digest="sha256:" + "e" * 64, execution_generation="new-control-runtime")
    implementation = copy.deepcopy(seed.base.implementation)
    implementation["source"] = source
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    actual_source = {**source, "image_digest": current.collection_image_digest}
    monkeypatch.setattr(qualification, "_qualification_execution_context",
        lambda: (implementation, actual_source, current.collection_image_digest))
    monkeypatch.setattr(util, "source_metadata", lambda: actual_source)

    # The original failed launch precedes this prospective capsule, and its
    # base_spec is the actual original serial plan rather than a placeholder.
    parallel_setup.state["base_spec"] = old.spec.serializable()
    seed.runtime.clear()
    seed.runtime.update({key: current.serializable()[key] for key in rolling.RUNTIME_FIELDS})
    published_at = lanes.admission._now()
    _write(Path(parallel_setup.reference["path"]), {"fixture": "closed scheduling primitive", "published_at": published_at})
    parallel_setup.reference.update(rolling._ref(Path(parallel_setup.reference["path"])))
    validate = schedule.validate_schedule
    require = schedule.require_schedule
    monkeypatch.setattr(schedule, "validate_schedule", lambda *args, **kwargs:
        {**validate(*args, **kwargs), "published_at": published_at,
         "qualification_spec": rolling._ref(qualifier_path)})
    monkeypatch.setattr(schedule, "require_schedule", lambda *args, **kwargs:
        {**require(*args, **kwargs), "published_at": published_at,
         "qualification_spec": rolling._ref(qualifier_path)})
    new_plan = old.root / "new-control-plan.json"
    rolling.publish_plan(old.root, old.spec.cohort, qualifier_path, new_plan,
        runtime_inputs=seed.runtime, readiness={"undefended": {"retained-canary": "undefended"}},
        scheduling=parallel_setup.reference)
    current = replace(current, plan_receipt=new_plan)
    successor_plan = old.root / "new-control-g02.json"
    rolling.publish_successor(current, old.lanes[0].campaign_name, 2, successor_plan)
    current = replace(current, plan_receipt=successor_plan)
    new_checked = lanes.check_bound_image(current, old.root)
    lane = lanes._lane(new_checked["proof"], new_checked["proof"]["plan_payload"]["lanes"][0]["campaign_name"])
    assert old.spec.collection_image_digest != current.collection_image_digest
    assert checked["proof"]["runtime_source"] != new_checked["proof"]["runtime_source"]
    assert checked["proof"]["client_sha256"] == new_checked["proof"]["client_sha256"]
    assert current.execution_root != old.spec.execution_root and current.host_launcher != old.spec.host_launcher
    assert current.workload_root != old.spec.workload_root and current.campaign_dir != old.spec.campaign_dir
    assert current.qualification_spec != old.spec.qualification_spec
    assert retained == _snapshot(original.parent, original_result)
    return SimpleNamespace(old=old, current=current, original=original, checked=new_checked, lane=lane,
        original_result=original_result, retained=retained, capsule=parallel_setup, source_path=source_path)


def test_original_failed_serial_source_reopens_under_prospective_control_g02(serial_source_recovery):
    value = serial_source_recovery
    intent = lanes.prepare_lane_intent(value.current, value.old.root, value.lane.campaign_name,
        value.checked, predecessor_intent=value.original, actuator="parallel-formal-worker")
    reopened, lineage, lane, sites = lanes._intent_and_lineage(value.current, value.old.root, intent)
    assert reopened["actuator"] == "parallel-formal-worker" and lane.generation == 2
    assert sites == value.old.sites
    old_intent = lanes._payload(value.original, lanes.INTENT_TYPE)
    assert lanes.admission._unpack(lanes._object(value.old.root, lineage["predecessor_intent"]), lanes.INTENT_TYPE) == old_intent
    process = lanes._verified_host_process(lanes._object(value.old.root, lineage["predecessor_attempt"]["host_process"]),
        value.old.root, value.original.read_bytes(), value.old.lanes[0].campaign_name)
    assert process["returncode"] == 1 and "actuator" not in process
    result_inventory = lineage["predecessor_attempt"]["result_inventory"]
    assert result_inventory
    assert {name: lanes._object(value.old.root, reference) for name, reference in result_inventory.items()} == {
        path.relative_to(value.original_result).as_posix(): path.read_bytes()
        for path in value.original_result.rglob("*") if path.is_file()}
    assert not (value.current.execution_root / "results" / value.old.lanes[0].campaign_name).exists()
    assert old_intent["runtime_identity"] != reopened["runtime_identity"]
    assert value.retained == _snapshot(value.original.parent, value.original_result)
    marker = value.original.parent / "complete.json"
    marker.write_bytes(b"post-claim completion namespace guard fixture\n")
    try:
        with pytest.raises(ValueError, match="completed"):
            lanes._intent_and_lineage(value.current, value.old.root, intent)
    finally:
        marker.unlink()
    assert value.retained == _snapshot(value.original.parent, value.original_result)


def test_source_recovery_rejects_unbound_or_changed_originals_before_claim(serial_source_recovery):
    value = serial_source_recovery
    state = value.capsule.state
    original_base = copy.deepcopy(state["base_spec"])
    source_raw = value.source_path.read_bytes()
    original_raw = value.original.read_bytes()
    for mutation in ("wrong-base", "wrong-original", "absent-capsule", "completed", "changed-native"):
        spec, checked = value.current, copy.deepcopy(value.checked)
        try:
            if mutation == "wrong-base":
                state["base_spec"] = value.current.serializable()
            elif mutation == "wrong-original":
                original = lanes._payload(value.original, lanes.INTENT_TYPE)
                original["logical_lane"] = value.old.lanes[1].logical_name
                _write(value.original, lanes.admission._bind(lanes.INTENT_TYPE, original))
            elif mutation == "absent-capsule":
                payload = lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE)
                payload.pop("scheduling")
                unbound = value.old.root / "unbound-control-g02.json"
                _write(unbound, lanes.admission._bind(lanes.PLAN_TYPE, payload))
                spec = replace(spec, plan_receipt=unbound)
                checked = lanes.check_bound_image(spec, value.old.root)
            elif mutation == "completed":
                # Existing completion namespace is itself a failed-only guard;
                # this sentinel is not asserted to be a scientific receipt.
                (value.original.parent / "complete.json").write_bytes(b"completion namespace guard fixture\n")
            else:
                source = shared.load(value.source_path)
                source.update(neqo_commit="f" * 40, neqo_pinned_commit="f" * 40)
                _write(value.source_path, source)
            with pytest.raises((OSError, ValueError, AssertionError)):
                lanes.prepare_lane_intent(spec, value.old.root, value.lane.campaign_name,
                    checked, predecessor_intent=value.original, actuator="parallel-formal-worker")
            assert not (value.old.root / "lanes" / value.lane.campaign_name).exists(), mutation
        finally:
            state["base_spec"] = copy.deepcopy(original_base)
            value.source_path.write_bytes(source_raw)
            if value.original.read_bytes() != original_raw:
                value.original.write_bytes(original_raw)
            (value.original.parent / "complete.json").unlink(missing_ok=True)
        # Mutation tests restore content, then the positive case independently
        # checks inode/mtime preservation without rewriting the old evidence.
        assert {name: facts[0] for name, facts in _snapshot(value.original.parent, value.original_result).items()} == {
            name: facts[0] for name, facts in value.retained.items()}, mutation
