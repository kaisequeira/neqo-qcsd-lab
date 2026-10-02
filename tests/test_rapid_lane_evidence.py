"""Exercise real adapter boundaries with only Docker/network actuation replaced."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_lane_evidence as evidence
from qcsd_lab import util


@pytest.fixture
def setup(tmp_path, monkeypatch):
    data = tmp_path / "data"
    runtime = tmp_path / "runtime"
    modules = tmp_path / "modules"
    execution = data / "execution"
    root = data / "capture-evidence"
    acquisition = data / "acquisition"
    workloads = execution / "config/workloads"
    campaigns = execution / "config/campaigns"
    for path in (data, runtime, modules, execution, root, acquisition, workloads, campaigns):
        path.mkdir(parents=True, exist_ok=True)
    lock_parent = tmp_path / "shared-locks"
    lock_parent.mkdir(mode=0o700)
    monkeypatch.setattr(evidence, "CAPTURE_LOCK_PARENT", lock_parent)
    for relative in qualification.IMPLEMENTATION_FILES:
        path = runtime / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"actual executed source {relative}\n")
    host = execution / "qcsd-lab"
    host.write_text("#!/bin/sh\n# prospective DNS sink and resume guard\n")
    for relative in ("src/qcsd_lab/rapid_lane_evidence.py", "tools/rapid_plan.py", "tools/rapid_capture.py"):
        path = modules / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"frozen external study source {relative}\n")
    authoring = Path(__file__).parents[1]
    for _, (relative, _) in evidence.TRAFFIC_FILES.items():
        path = execution / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((authoring / relative).read_bytes())
    profile = execution / evidence.STUDY_PROFILE_FILE
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_bytes((authoring / evidence.STUDY_PROFILE_FILE).read_bytes())
    client = data / "neqo-qcsd-client"
    client.write_bytes(b"actual installed client snapshot")
    source = {"image_digest": None, "lab_commit": "b" * 40, "lab_dirty": False,
              "lab_patch_sha256": evidence._sha(b""), "neqo_commit": "c" * 40,
              "neqo_pinned_commit": "c" * 40, "neqo_dirty": False, "neqo_patch_sha256": evidence._sha(b"")}
    source_path = data / "source.json"
    source_path.write_bytes(evidence._json(source))
    image = "sha256:" + "a" * 64
    actual_source = {**source, "image_digest": image}
    files = {relative: evidence._sha((runtime / relative).read_bytes()) for relative in qualification.IMPLEMENTATION_FILES}
    implementation = {
        "schema_version": 2, "artifact_type": "qcsd-chaff-qualification-implementation",
        "domain": qualification.IMPLEMENTATION_RECEIPT_DOMAIN, "source": source, "source_files": files,
        "installed_modules": {relative: {"path": f"/installed/{relative}", "sha256": files[relative]}
                              for relative in qualification.IMPLEMENTATION_PYTHON_FILES},
        "installed_entrypoint": {"path": "/installed/qcsd-lab", "sha256": files["qcsd-lab"]},
        "neqo_qcsd_client": {"path": "/installed/neqo-qcsd-client", "sha256": evidence._sha(client.read_bytes())},
    }
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    qualification._validate_implementation_receipt(implementation, require_current=False)
    monkeypatch.setattr(qualification, "_qualification_execution_context", lambda: (implementation, actual_source, image))
    monkeypatch.setattr(qualification, "_bound_neqo_client", lambda value: (client, evidence._sha(client.read_bytes())))
    monkeypatch.setattr(util, "source_metadata", lambda: actual_source)
    monkeypatch.setenv("QCSD_LAB_ROOT", str(runtime))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", image)
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", "/usr/share/qcsd-lab/source.json")
    sites = []
    for index in range(10):
        name = f"site-{index}"
        raw = evidence._json({"preparation": {"approved_origins": [f"https://site{index}.example", "https://cdn.example"]}})
        (workloads / f"{name}.json").write_bytes(raw)
        sites.append(plan.Site(f"candidate-{index}", name, evidence._sha(raw), f"https://site{index}.example",
                               f"shard-{index // 5}", f"{index // 5 + 1:064x}"))
    sites = tuple(sites)
    cohort = data / "cohort.json"
    cohort.write_bytes(b"actual frozen prospective cohort\n")
    qualifier = data / "qualification-spec.json"
    qualifier_rows = []
    for index in range(2):
        name = f"shard-{index}"
        sidecar = campaigns.parent / "chaff-response-qualification-store/sets" / name
        sidecar.mkdir(parents=True)
        manifest = sidecar / "_qualification-set.json"
        manifest.write_bytes(b"actual strict named qualification bytes\n")
        qualifier_rows.append({"qualification_set": name, "manifest": str(manifest),
                               "sidecar_root": str(sidecar), "prefix_spec_root": None})
    qualifier.write_bytes(evidence._json({"schema_version": 1, "qualification_sets": qualifier_rows}))
    bindings = {"profile_sha256": "d" * 64, "cohort_sha256": evidence._sha(cohort.read_bytes()), "study_version": "v5"}
    lanes = plan.plan_lanes(sites, final=False, study_version=5)
    hashes = {}
    for lane in lanes:
        raw = plan.render_lane_campaign(lane, sites)
        (campaigns / f"{lane.campaign_name}.yml").write_bytes(raw)
        hashes[lane.campaign_name] = evidence._sha(raw)
    payload = {"cohort_generation": "launch-10", "bindings": bindings,
               "acquisition_provenance_sha256": "e" * 64, "sites": [asdict(site) for site in sites],
               "lanes": [{**asdict(lane), "campaign_sha256": hashes[lane.campaign_name]} for lane in lanes]}
    plan_path = data / "plan.json"
    plan_path.write_bytes(evidence._json(evidence.admission._bind(evidence.PLAN_TYPE, payload)))
    spec = evidence.CaptureSpec(data, runtime, modules, execution, acquisition, cohort, qualifier, workloads,
                                campaigns, plan_path, source_path, client, runtime / "qcsd-lab", host, image, "clean-runtime-001")
    fake_plan = SimpleNamespace(run=lambda args: {"valid": True, "formal_accepted_trace_count": 0},
                                _inputs=lambda args: (SimpleNamespace(provenance_sha256="e" * 64), sites,
                                                      SimpleNamespace(digests=lambda: bindings), "launch-10", "f" * 64))
    monkeypatch.setattr(evidence, "_plan_module", lambda path: fake_plan)
    proof = evidence.executed_image_plan_check(spec.serializable())
    calls = []

    def actuator(command, **options):
        calls.append(command)
        if command[0] == "docker":
            return subprocess.CompletedProcess(command, 0, json.dumps(proof), "")
        assert command[:2] == [str(host), "run"]
        assert options["env"]["QCSD_RAPID_V5_PROFILE_PATH"] == str(profile)
        campaign_name = Path(command[2]).stem
        lane = evidence._lane(proof, campaign_name)
        dns = {"schema_version": 1, "campaign": campaign_name,
               "hosts": [[name, "8.8.8.8"] for name in sorted({"cdn.example", *(f"site{index}.example" for index in range(5))})]}
        Path(options["env"]["QCSD_RAPID_DNS_RECEIPT_PATH"]).write_bytes(evidence._json(dns))
        result = execution / "results" / campaign_name / "attempt-001"
        result.mkdir(parents=True)
        (result / "experiment.json").write_bytes(evidence._json({"started_at": evidence._now()}))
        (result / "evidence.sha256").write_bytes(b"actual sealed complete lane\n")
        options["stdout"].write(b"actual host output\n")
        options["stderr"].write(b"actual retained diagnostics\n")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(evidence.subprocess, "run", actuator)
    def actuate_host(spec, root, directory, command, env, descriptor):
        started = evidence._now()
        start = {"command": command, "execution_root": str(spec.execution_root), "started_at": started,
                 "intent_sha256": evidence._sha((directory / "intent.json").read_bytes()),
                 "host": evidence._process_identity(__import__("os").getpid()),
                 "supervisor": evidence._process_identity(__import__("os").getpid()),
                 "gate_script_sha256": evidence._sha(evidence.HOST_GATE_SCRIPT.encode()),
                 "supervisor_script_sha256": evidence._sha(evidence.SUPERVISOR_SCRIPT.encode())}
        start["host"]["argv"] = [__import__("sys").executable, "-c", evidence.HOST_GATE_SCRIPT, json.dumps(command), "7"]
        start["supervisor"]["argv"] = [__import__("sys").executable, "-c", evidence.SUPERVISOR_SCRIPT,
                                           json.dumps({"command": command, "execution_root": str(spec.execution_root)}), "8"]
        evidence._create(root, directory / "host-start.json", evidence.PROCESS_START_TYPE, start)
        with (directory / "host.stdout.log").open("xb") as stdout, (directory / "host.stderr.log").open("xb") as stderr:
            result = actuator(command, env=env, stdout=stdout, stderr=stderr)
        evidence._create(root, directory / "host-process.json", evidence.PROCESS_TYPE, {
            "command": command, "execution_root": str(spec.execution_root), "started_at": started,
            "completed_at": evidence._now(), "returncode": result.returncode, "interruption": None,
            "start": evidence._put_object(root, (directory / "host-start.json").read_bytes()),
            "stdout": evidence._put_object(root, (directory / "host.stdout.log").read_bytes()),
            "stderr": evidence._put_object(root, (directory / "host.stderr.log").read_bytes()),
        })
    monkeypatch.setattr(evidence, "_actuate_host", actuate_host)
    verification_calls = []

    def deep_verify(path, lane, **kwargs):
        verification_calls.append((path, lane, kwargs))
        return {"accepted": lane.sample_count, "result_seal_sha256": evidence._sha((path / "evidence.sha256").read_bytes()),
                "scientific_credit": "none-diagnostic"}

    monkeypatch.setattr(plan, "verify_lane_result", deep_verify)
    return SimpleNamespace(spec=spec, root=root, sites=sites, lanes=lanes, proof=proof, calls=calls,
                           verification_calls=verification_calls, implementation=implementation, fake_plan=fake_plan)


def test_real_image_bridge_checks_runtime_without_fabricated_cohort(setup):
    value = evidence.executed_image_runtime_check({key: setup.spec.serializable()[key] for key in evidence.RUNTIME_KEYS})
    assert value["scientific_credit"] is False
    assert value["formal_accepted_trace_count"] == 0
    assert value["client_sha256"] == evidence._sha(setup.spec.client_binary.read_bytes())


def test_missing_or_mutated_frozen_profile_fails_before_image_or_lane_claim(setup):
    profile = setup.spec.execution_root / evidence.STUDY_PROFILE_FILE
    profile.write_bytes(profile.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="frozen v5 profile"):
        evidence.launch_lane(setup.spec, setup.root, setup.lanes[0].campaign_name)
    assert setup.calls == []
    assert not (setup.root / "lanes" / setup.lanes[0].campaign_name).exists()
    profile.unlink()
    with pytest.raises(ValueError, match="regular"):
        evidence.executed_image_runtime_check({key: setup.spec.serializable()[key] for key in evidence.RUNTIME_KEYS})


def test_readonly_preflight_failure_does_not_consume_physical_lane(setup):
    setup.fake_plan.run = lambda args: {"valid": False, "formal_accepted_trace_count": 0}
    def rejected(command, **options):
        return subprocess.CompletedProcess(command, 1, "", "actual installed image rejected plan")
    original = evidence.subprocess.run
    evidence.subprocess.run = rejected
    try:
        with pytest.raises(ValueError, match="raw execution output retained"):
            evidence.launch_lane(setup.spec, setup.root, setup.lanes[0].campaign_name)
    finally:
        evidence.subprocess.run = original
    assert not (setup.root / "lanes" / setup.lanes[0].campaign_name).exists()
    assert list(setup.root.glob("image-check-*.json"))
    receipt = evidence.launch_lane(setup.spec, setup.root, setup.lanes[0].campaign_name)
    assert receipt.is_file()


@pytest.mark.parametrize("field", ["manifest", "sidecar_root", "prefix_spec_root"])
def test_host_qualification_layout_is_bound_before_image_actuation(setup, field):
    value = evidence._load(setup.spec.qualification_spec.read_bytes())
    value["qualification_sets"][0][field] = str(setup.spec.data_root / "qualifiers-somewhere-else")
    setup.spec.qualification_spec.write_bytes(evidence._json(value))
    with pytest.raises(ValueError, match="response-only|response-set layout"):
        evidence.launch_lane(setup.spec, setup.root, setup.lanes[0].campaign_name)
    assert setup.calls == []
    assert not (setup.root / "lanes" / setup.lanes[0].campaign_name).exists()


def test_actual_plan_check_never_accepts_native_or_failed_qualifier(setup, monkeypatch):
    monkeypatch.delenv("QCSD_LAB_ROOT")
    with pytest.raises(ValueError, match="source bridge"):
        evidence.executed_image_plan_check(setup.spec.serializable())
    monkeypatch.setenv("QCSD_LAB_ROOT", str(setup.spec.runtime_source_root))

    def fail():
        raise ValueError("installed qualification gate failed")

    monkeypatch.setattr(qualification, "_qualification_execution_context", fail)
    with pytest.raises(ValueError, match="installed qualification gate"):
        evidence.executed_image_plan_check(setup.spec.serializable())


def test_actual_first_launch_dns_deep_verification_and_receipt_reopening(setup):
    lane = setup.lanes[0]
    receipt = evidence.launch_lane(setup.spec, setup.root, lane.campaign_name)
    facts = evidence.verify_launch_receipt(receipt, spec=setup.spec, evidence_root=setup.root)
    lineage = evidence.verify_execution_lineage(receipt.parent / "lineage.json", spec=setup.spec, evidence_root=setup.root)
    assert facts["accepted"] == 5
    assert facts["scientific_credit"] == "none-diagnostic"
    assert lineage["equivalent_to_cohort"] is True
    assert len(setup.calls) == 2  # Actual bound image check then exact host actuator.
    assert len(setup.verification_calls) == 2  # Completion and independent reopening.
    assert (receipt.parent / "intent.json").exists()
    assert (receipt.parent / "host.stdout.log").read_bytes() == b"actual host output\n"
    with pytest.raises(FileExistsError):
        evidence.launch_lane(setup.spec, setup.root, lane.campaign_name)
    assert len(setup.calls) == 2


@pytest.mark.parametrize("mutation", ["client", "base-launcher", "host-launcher", "traffic", "overlay", "image", "boolean-exit"])
def test_resealed_or_mutated_launch_authority_is_rejected(setup, mutation):
    receipt = evidence.launch_lane(setup.spec, setup.root, setup.lanes[0].campaign_name)
    if mutation in ("image", "boolean-exit"):
        path = receipt.parent / "lineage.json"
        payload = evidence._payload(path, evidence.LINEAGE_TYPE)
        if mutation == "image":
            payload["image_check"]["proof"]["collection_image_digest"] = "sha256:" + "f" * 64
        else:
            payload["image_check"]["execution"]["returncode"] = False
        path.write_bytes(evidence._json(evidence.admission._bind(evidence.LINEAGE_TYPE, payload)))
        intent_path = receipt.parent / "intent.json"
        intent = evidence._payload(intent_path, evidence.INTENT_TYPE)
        intent["lineage"]["sha256"] = evidence._sha(path.read_bytes())
        intent_path.write_bytes(evidence._json(evidence.admission._bind(evidence.INTENT_TYPE, intent)))
        completed = evidence._payload(receipt, evidence.COMPLETE_TYPE)
        completed["intent"]["sha256"] = evidence._sha(intent_path.read_bytes())
        receipt.write_bytes(evidence._json(evidence.admission._bind(evidence.COMPLETE_TYPE, completed)))
    else:
        path = {"client": setup.spec.client_binary, "base-launcher": setup.spec.base_launcher,
                "host-launcher": setup.spec.host_launcher,
                "traffic": setup.spec.execution_root / next(iter(evidence.TRAFFIC_FILES.values()))[0],
                "overlay": setup.spec.module_root / "tools/rapid_plan.py"}[mutation]
        path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ValueError):
        evidence.verify_launch_receipt(receipt, spec=setup.spec, evidence_root=setup.root)


@pytest.mark.parametrize("mutation", ["private", "missing", "duplicate", "wrong-campaign", "boolean-schema"])
def test_dns_receipt_is_rederived_from_all_full_workload_origins(setup, mutation):
    lane = setup.lanes[0]
    workloads = {site.workload_id: (setup.spec.workload_root / f"{site.workload_id}.json").read_bytes()
                 for site in setup.sites[:5]}
    value = {"schema_version": 1, "campaign": lane.campaign_name,
             "hosts": [[host, "8.8.8.8"] for host in sorted({"cdn.example", *(f"site{index}.example" for index in range(5))})]}
    if mutation == "private":
        value["hosts"][0][1] = "127.0.0.1"
    elif mutation == "missing":
        value["hosts"].pop()
    elif mutation == "duplicate":
        value["hosts"].append(value["hosts"][-1])
    elif mutation == "wrong-campaign":
        value["campaign"] = "another-campaign"
    else:
        value["schema_version"] = True
    with pytest.raises(ValueError):
        evidence.verify_dns_receipt(evidence._json(value), lane.campaign_name, workloads)


def test_incomplete_lane_cannot_receive_complete_receipt(setup, monkeypatch):
    def incomplete(*args, **kwargs):
        raise ValueError("sealed incomplete lane")

    monkeypatch.setattr(plan, "verify_lane_result", incomplete)
    lane = setup.lanes[0]
    with pytest.raises(ValueError, match="sealed incomplete"):
        evidence.launch_lane(setup.spec, setup.root, lane.campaign_name)
    directory = setup.root / "lanes" / lane.campaign_name
    assert (directory / "intent.json").exists()
    assert (directory / "host-process.json").exists()
    assert (directory / "host.stderr.log").exists()
    assert not (directory / "complete.json").exists()


def test_old_unbound_result_and_diagnostics_never_gain_formal_credit(setup):
    lane = setup.lanes[0]
    (setup.spec.execution_root / "results" / lane.campaign_name / "old").mkdir(parents=True)
    with pytest.raises(FileExistsError, match="unbound or prior"):
        evidence.launch_lane(setup.spec, setup.root, lane.campaign_name)
    assert len(setup.calls) == 1  # Isolated source/plan check; no new capture.
    with pytest.raises(ValueError, match="zero formal"):
        evidence.formal_manifest_rows(setup.spec, setup.root)


def test_same_image_successor_requires_immediate_actual_predecessor_and_retains_failure(setup, monkeypatch):
    original_verify = plan.verify_lane_result

    def fail(*args, **kwargs):
        raise ValueError("actual first generation incomplete")

    monkeypatch.setattr(plan, "verify_lane_result", fail)
    original = setup.lanes[0]
    with pytest.raises(ValueError, match="first generation incomplete"):
        evidence.launch_lane(setup.spec, setup.root, original.campaign_name)
    previous = setup.root / "lanes" / original.campaign_name
    retained = {path.relative_to(previous).as_posix(): path.read_bytes() for path in previous.rglob("*") if path.is_file()}
    successor = plan.successor_lane(original, 2)
    raw = plan.render_lane_campaign(successor, setup.sites)
    (setup.spec.campaign_dir / f"{successor.campaign_name}.yml").write_bytes(raw)
    payload = evidence.admission._unpack(setup.spec.plan_receipt.read_bytes(), evidence.PLAN_TYPE)
    payload["lanes"] = [{**asdict(successor), "campaign_sha256": evidence._sha(raw)}]
    setup.spec.plan_receipt.write_bytes(evidence._json(evidence.admission._bind(evidence.PLAN_TYPE, payload)))
    new_proof = evidence.executed_image_plan_check(setup.spec.serializable())
    setup.proof.clear()
    setup.proof.update(new_proof)
    monkeypatch.setattr(plan, "verify_lane_result", original_verify)
    receipt = evidence.launch_lane(setup.spec, setup.root, successor.campaign_name,
                                   predecessor_intent=previous / "intent.json")
    facts = evidence.verify_launch_receipt(receipt, spec=setup.spec, evidence_root=setup.root)
    assert facts["campaign_name"] == successor.campaign_name
    assert evidence.verify_execution_lineage(receipt.parent / "lineage.json", spec=setup.spec,
                                             evidence_root=setup.root)["predecessor_campaign_name"] == original.campaign_name
    assert {path.relative_to(previous).as_posix(): path.read_bytes() for path in previous.rglob("*") if path.is_file()} == retained
    assert (setup.spec.execution_root / "results" / original.campaign_name / "attempt-001").is_dir()


def test_plan_verifier_bool_counter_and_missing_final_lanes_are_rejected(setup):
    setup.fake_plan.run = lambda args: {"valid": True, "formal_accepted_trace_count": False}
    with pytest.raises(ValueError, match="independently verify"):
        evidence.executed_image_plan_check(setup.spec.serializable())
    stored = evidence.admission._unpack(setup.spec.plan_receipt.read_bytes(), evidence.PLAN_TYPE)
    stored["cohort_generation"] = "final-50"
    for index in range(10, 50):
        stored["sites"].append({"candidate_id": f"candidate-{index}", "workload_id": f"site-{index}",
                                "workload_sha256": f"{index:064x}", "primary_origin": f"https://site{index}.example",
                                "qualification_set": f"shard-{index // 5}",
                                "qualification_set_manifest_sha256": f"{index // 5 + 1:064x}"})
    setup.spec.plan_receipt.write_bytes(evidence._json(evidence.admission._bind(evidence.PLAN_TYPE, stored)))
    with pytest.raises(ValueError, match="missing or unregistered"):
        evidence.formal_manifest_rows(setup.spec, setup.root)


def test_real_flock_rejects_competing_evidence_roots_and_copied_execution_roots(setup, tmp_path):
    other_evidence = setup.spec.data_root / "other-capture-evidence"
    other_evidence.mkdir()
    copied_execution = tmp_path / "copied-lab"
    copied_execution.mkdir()
    with evidence.capture_lock(setup.spec.execution_root):
        with pytest.raises(BlockingIOError):
            evidence.launch_lane(setup.spec, other_evidence, setup.lanes[0].campaign_name)
        with pytest.raises(BlockingIOError):
            with evidence.capture_lock(copied_execution):
                pytest.fail("copied Lab roots cannot overlap this user's rapid topology")
    assert not setup.calls
    assert not (other_evidence / "lanes").exists()
    with evidence.capture_lock(copied_execution):
        pass


def _wait_for_file(path, child, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        if child.poll() is not None:
            raise AssertionError(f"parent exited {child.returncode} before {path}")
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


@pytest.mark.parametrize("interruption", [signal.SIGTERM, signal.SIGKILL])
def test_actual_parent_interruption_keeps_orphan_serialized_and_retains_terminal_bytes(tmp_path, monkeypatch, interruption):
    root = tmp_path / "evidence"
    execution = tmp_path / "execution"
    directory = root / "lanes/campaign-001"
    locks = tmp_path / "locks"
    for path in (root, execution, directory, locks):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    monkeypatch.setattr(evidence, "CAPTURE_LOCK_PARENT", locks)
    host = execution / "qcsd-lab"
    release = execution / "release"
    partial = execution / "partial.capture"
    host.write_text(f"#!/bin/sh\nprintf retained-raw-packets > '{partial}'\nwhile [ ! -f '{release}' ]; do sleep 0.02; done\nexit 7\n")
    host.chmod(0o700)
    campaign = execution / "campaign-001.yml"
    campaign.write_bytes(b"retained frozen campaign\n")
    evidence._create(root, directory / "intent.json", evidence.INTENT_TYPE,
                     {"campaign_name": "campaign-001", "started_at": evidence._now()})
    module_root = Path(__file__).parents[1]
    value = {"root": str(root), "execution": str(execution), "directory": str(directory), "locks": str(locks),
             "modules": str(module_root), "command": [str(host), "run", str(campaign)]}
    script = """
import json,os,sys
from pathlib import Path
from types import SimpleNamespace
from qcsd_lab import rapid_lane_evidence as e
v=json.loads(sys.argv[1]); e.CAPTURE_LOCK_PARENT=Path(v['locks'])
with e.capture_lock(Path(v['execution'])) as fd:
    e._actuate_host(SimpleNamespace(module_root=Path(v['modules']),execution_root=Path(v['execution'])),
                    Path(v['root']),Path(v['directory']),v['command'],dict(os.environ),fd)
"""
    env = {**os.environ, "PYTHONPATH": str(module_root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    parent = subprocess.Popen([sys.executable, "-c", script, json.dumps(value)], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        _wait_for_file(directory / "host-start.json", parent)
        _wait_for_file(partial, parent)
        start = evidence._validated_host_start((directory / "host-start.json").read_bytes(),
                                              (directory / "intent.json").read_bytes(), campaign_name="campaign-001")
        os.kill(parent.pid, interruption)
        parent.wait(timeout=5)
        with pytest.raises(BlockingIOError):
            with evidence.capture_lock(execution):
                pytest.fail("orphaned actual host lost shared serialization")
        assert partial.read_bytes() == b"retained-raw-packets"
        with pytest.raises(ValueError, match="still alive"):
            evidence._retired_identity(start["host"])
        release.write_bytes(b"finish bounded host\n")
        deadline = time.monotonic() + 8
        while not (directory / "host-process.json").is_file() and time.monotonic() < deadline:
            time.sleep(0.02)
        process = evidence._payload(directory / "host-process.json", evidence.PROCESS_TYPE)
        assert process["returncode"] == 7
        assert evidence._object(root, process["start"]) == (directory / "host-start.json").read_bytes()
        assert partial.read_bytes() == b"retained-raw-packets"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                evidence._retired_identity(start["supervisor"])
                break
            except ValueError:
                time.sleep(0.02)
        with evidence.capture_lock(execution):
            pass
    finally:
        release.touch()
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if parent.stderr:
            parent.stderr.close()


def test_closure_mount_replaces_duplicate_destination(setup):
    import importlib.util
    path = Path(__file__).parents[1] / "tools/rapid_capture.py"
    loader = importlib.util.spec_from_file_location("rapid_capture_mount_test", path)
    module = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(module)
    for publish in (False, True):
        command = module.closure_command(setup.spec, setup.spec.data_root,
                                         setup.spec.data_root / "formal.json", publish=publish)
        mounts = [command[index + 1] for index, item in enumerate(command) if item == "--volume"]
        selected = [item for item in mounts if item.split(":")[1] == str(setup.spec.data_root)]
        assert selected == [f"{setup.spec.data_root}:{setup.spec.data_root}:{'rw' if publish else 'ro'}"]


def test_actual_retired_birth_and_raw_inventory_allow_only_fresh_successor(setup, monkeypatch, tmp_path):
    original_actuation = evidence._actuate_host
    births = []
    original = setup.lanes[0]
    def lost_supervisor(spec, root, directory, command, env, descriptor):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
        try:
            identity = evidence._process_identity(child.pid)
            host = {**identity, "argv": [sys.executable, "-c", evidence.HOST_GATE_SCRIPT, json.dumps(command), "7"]}
            supervisor = {**identity, "argv": [sys.executable, "-c", evidence.SUPERVISOR_SCRIPT,
                                                   json.dumps({"command": command, "execution_root": str(spec.execution_root)}), "8"]}
            start = {"command": command, "execution_root": str(spec.execution_root), "started_at": evidence._now(),
                     "intent_sha256": evidence._sha((directory / "intent.json").read_bytes()), "host": host,
                     "supervisor": supervisor, "gate_script_sha256": evidence._sha(evidence.HOST_GATE_SCRIPT.encode()),
                     "supervisor_script_sha256": evidence._sha(evidence.SUPERVISOR_SCRIPT.encode())}
            evidence._create(root, directory / "host-start.json", evidence.PROCESS_START_TYPE, start)
            births.append(start)
        finally:
            child.kill()
            child.wait(timeout=5)
        (directory / "host.stdout.log").write_bytes(b"actual retained interrupted output\n")
        (directory / "host.stderr.log").write_bytes(b"supervisor killed before terminal publication\n")
        result = spec.execution_root / "results" / original.campaign_name / "partial-001"
        result.mkdir(parents=True)
        (result / "raw.capture").write_bytes(b"unaltered partial capture\n")
        raise RuntimeError("actual supervisor failed")
    monkeypatch.setattr(evidence, "_actuate_host", lost_supervisor)
    with pytest.raises(RuntimeError, match="supervisor failed"):
        evidence.launch_lane(setup.spec, setup.root, original.campaign_name)
    previous = setup.root / "lanes" / original.campaign_name
    assert not (previous / "host-process.json").exists()
    locks = tmp_path / "lifecycle-locks"
    locks.mkdir(mode=0o700)
    monkeypatch.setattr(evidence, "LIFECYCLE_LOCK_PARENT", locks)
    def actual_observations(root, descriptor):
        metadata = os.fstat(descriptor)
        executions = []
        for operation in (("ps", "--all", "--quiet"), ("network", "ls", "--quiet")):
            executions.append({"command": ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", "/retained/empty-config",
                                            *operation, "--filter", "label=org.qcsd.owner=qcsd-lab"], "returncode": 0,
                               "stdout": evidence._put_object(root, b""), "stderr": evidence._put_object(root, b"")})
        return {"lifecycle_lock": {"path": str(locks / f"qcsd-docker-lifecycle-{os.getuid()}.lock"),
                                    "device": metadata.st_dev, "inode": metadata.st_ino, "uid": metadata.st_uid,
                                    "mode": 0o600, "links": 1, "size": 0}, "guardian_processes": [], "lifecycle_entries": [],
                "guardian_sockets": evidence._put_object(root, b"Num RefCount Protocol Flags Type St Inode Path\n"),
                "docker_executions": executions}
    monkeypatch.setattr(evidence, "_retirement_quiescence", actual_observations)
    retirement = evidence.retire_lane(setup.spec, setup.root, previous / "intent.json")
    facts = evidence._verified_retirement(retirement.read_bytes(), setup.root, (previous / "intent.json").read_bytes(), original.campaign_name)
    assert facts["scientific_credit"] is False
    assert facts["retired_processes"] == {"host": "absent", "supervisor": "absent"}
    retained = {path.relative_to(previous).as_posix(): path.read_bytes() for path in previous.rglob("*") if path.is_file()}
    successor = plan.successor_lane(original, 2)
    raw = plan.render_lane_campaign(successor, setup.sites)
    (setup.spec.campaign_dir / f"{successor.campaign_name}.yml").write_bytes(raw)
    payload = evidence.admission._unpack(setup.spec.plan_receipt.read_bytes(), evidence.PLAN_TYPE)
    payload["lanes"] = [{**asdict(successor), "campaign_sha256": evidence._sha(raw)}]
    setup.spec.plan_receipt.write_bytes(evidence._json(evidence.admission._bind(evidence.PLAN_TYPE, payload)))
    setup.proof.clear()
    setup.proof.update(evidence.executed_image_plan_check(setup.spec.serializable()))
    monkeypatch.setattr(evidence, "_actuate_host", original_actuation)
    receipt = evidence.launch_lane(setup.spec, setup.root, successor.campaign_name, predecessor_intent=previous / "intent.json")
    evidence.verify_launch_receipt(receipt, spec=setup.spec, evidence_root=setup.root)
    assert {path.relative_to(previous).as_posix(): path.read_bytes() for path in previous.rglob("*") if path.is_file()} == retained
    assert (setup.spec.execution_root / "results" / original.campaign_name / "partial-001/raw.capture").read_bytes() == b"unaltered partial capture\n"
    forged = evidence._payload(retirement, evidence.RETIREMENT_TYPE)
    forged["checks"]["docker_executions"][0]["returncode"] = False
    with pytest.raises(ValueError, match="actual empty owned Docker"):
        evidence._verified_retirement(evidence._json(evidence.admission._bind(evidence.RETIREMENT_TYPE, forged)),
                                     setup.root, (previous / "intent.json").read_bytes(), original.campaign_name)


@pytest.mark.parametrize("failure", [None, "container", "query-exit"])
def test_retirement_actual_docker_query_boundary_preserves_outputs_without_calling_docker(tmp_path, monkeypatch, failure):
    root = tmp_path / "evidence"
    root.mkdir()
    calls = []
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted.example:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "untrusted")
    def actuator(command, **options):
        calls.append(command)
        assert command[:3] == ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
        assert "DOCKER_HOST" not in options["env"] and "DOCKER_CONTEXT" not in options["env"]
        config = Path(command[4])
        assert config.is_dir() and not list(config.iterdir())
        assert command[-2:] == ["--filter", "label=org.qcsd.owner=qcsd-lab"]
        return subprocess.CompletedProcess(command, 2 if failure == "query-exit" else 0,
                                           "actual-owned-container\n" if failure == "container" else "", "retained actual query diagnostic\n")
    monkeypatch.setattr(evidence.subprocess, "run", actuator)
    if failure:
        with pytest.raises(ValueError, match="actual absence query failed"):
            evidence._retirement_docker_absence(root)
        assert len(calls) == 1
    else:
        value = evidence._retirement_docker_absence(root)
        assert len(calls) == 2
        assert calls[0][5:8] == ["ps", "--all", "--quiet"]
        assert calls[1][5:8] == ["network", "ls", "--quiet"]
        assert all(evidence._object(root, record["stdout"]) == b"" for record in value)
    assert len(list(root.glob("retirement-check-*.json"))) == len(calls)


def test_resealed_host_birth_and_boolean_terminal_exit_are_rejected(setup):
    receipt = evidence.launch_lane(setup.spec, setup.root, setup.lanes[0].campaign_name)
    process_path = receipt.parent / "host-process.json"
    process = evidence._payload(process_path, evidence.PROCESS_TYPE)
    process["returncode"] = False
    process_path.write_bytes(evidence._json(evidence.admission._bind(evidence.PROCESS_TYPE, process)))
    with pytest.raises(ValueError, match="terminal host-process schema"):
        evidence.verify_launch_receipt(receipt, spec=setup.spec, evidence_root=setup.root)
