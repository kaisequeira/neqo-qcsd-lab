"""Pre-birth validation with real file fences and inspected worker guards.

The expensive scientific/image/admission validators expose controlled facts;
these are explicitly engineering fixtures, not actual installed proofs. Files,
typed receipt envelopes, source/tree membership, DNS, mounted namespaces,
peer CPU partitions and retained release receipts use the production code.
"""
from __future__ import annotations

import copy
from dataclasses import asdict
from datetime import timedelta
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_capture as shared
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import verification
from tests.test_process_scheduler import _peer_inputs


PROJECT = Path(__file__).resolve().parents[1]


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else lanes._json(value))
    return path


def _ref(path):
    return {"path": str(path), "sha256": shared.sha(path.read_bytes())}


def _receipt(path, kind, payload):
    return _write(path, lanes.admission._bind(kind, payload))


@pytest.fixture
def release_context(tmp_path, monkeypatch):
    data = tmp_path / "data"
    root, execution = data / "evidence", data / "execution"
    source = data / "current-source"
    old_source = data / "original-source"
    for directory in (root, execution / "results", execution / "config/campaigns",
                      execution / "config/workloads", source, old_source):
        directory.mkdir(parents=True)
    for directory in (source, old_source):
        _write(directory / "qcsd-lab", b"#!/bin/sh\n# bound engineering source fixture\n")
        _write(directory / "src/qcsd_lab/control.py", b"# immutable source bytes\n")
        _write(directory / "neqo-qcsd/transport.rs", b"// immutable Native source fixture\n")
    _write(execution / "qcsd-lab", (source / "qcsd-lab").read_bytes())
    for relative, _ in lanes.TRAFFIC_FILES.values():
        _write(execution / relative, (PROJECT / relative).read_bytes())
    _write(execution / lanes.STUDY_PROFILE_FILE, (PROJECT / lanes.STUDY_PROFILE_FILE).read_bytes())
    metadata = {"lab_commit": "b" * 40, "lab_dirty": False,
        "neqo_commit": "c" * 40, "neqo_pinned_commit": "c" * 40, "neqo_dirty": False}
    source_manifest = _write(data / "export/source.json", metadata)
    client = _write(data / "export/client", b"engineering host path fixture; not a Native artifact\n")
    qualifiers = execution / "config/chaff-response-qualification-store/sets/batch"
    manifest = _write(qualifiers / "_qualification-set.json", {"engineering_fixture": "named120"})
    sidecar = _write(qualifiers / "site.json", {"engineering_fixture": "120 response bytes"})
    qualifier_spec = _write(execution / "config/qualification-spec.json", {"schema_version": 1,
        "qualification_sets": [{"qualification_set": "batch", "manifest": str(manifest),
            "sidecar_root": str(qualifiers), "prefix_spec_root": None}]})
    workload = _write(execution / "config/workloads/site.json", {"preparation": {
        "approved_origins": ["https://cdn.example", "https://site.example"]}})
    application = _write(execution / "config/workloads/site-application-response-evidence/response.json",
        {"engineering_fixture": "complete immutable application response proof"})
    site = plan.Site("candidate", "site", shared.sha(workload.read_bytes()),
        "https://site.example", "batch", shared.sha(manifest.read_bytes()))
    selected = [plan.Lane("formal", index + 1, 1, "undefended",
        plan._campaign_name("formal", index + 1, 1, "undefended", 1, 6),
        (site.workload_id,), 4, None, 1, 6) for index in range(2)]
    campaigns = []
    for lane in selected:
        path = _write(execution / f"config/campaigns/{lane.campaign_name}.yml",
            plan.render_lane_campaign(lane, (site,)))
        campaigns.append(_ref(path))

    initial, acquisition = data / "initial-admission", data / "current-admission"
    for context in (initial, acquisition):
        dependency = _write(context / "source-dependency.py", b"# frozen admission dependency\n")
        _write(context / "provenance.json", {"engineering_fixture": "admission proof",
            "dependency": _ref(dependency)})
    terminal = _receipt(acquisition / "sites/candidate/attempt-001/terminal.json",
        lanes.admission.TERMINAL_TYPE, {"engineering_fixture": "ordered admitted terminal",
            "raw": _ref(_write(acquisition / "sites/candidate/attempt-001/discovery.raw", b"raw admission facts\n"))})
    policy = _receipt(root / "policy.json", rolling.POLICY_TYPE,
        {"initial_admission_root": str(initial), "engineering_fixture": "rolling policy"})
    parent = _receipt(root / "batches/b0000/enrollment.json", rolling.ENROLLMENT_TYPE,
        {"policy": _ref(policy), "admission_root": str(initial), "parent": None, "decisions": []})
    cohort = _receipt(root / "batches/b0001/enrollment.json", rolling.ENROLLMENT_TYPE,
        {"policy": _ref(policy), "admission_root": str(acquisition), "parent": _ref(parent),
            "decisions": [{"terminal": _ref(terminal)}]})

    canonical_paths = []
    for name, clean in (("original-runtime", old_source), ("current-runtime", source)):
        directory = data / name
        shutil.copytree(clean, directory / "image-context/source")
        inventory = _write(directory / "source-inventory.json", readiness._inventory(clean))
        operation = "collection-installed-verification"
        raw = _write(directory / (operation + ".stdout.log"), b"closed runtime raw bytes\n")
        stderr = _write(directory / (operation + ".stderr.log"), b"")
        started = _write(directory / (operation + "-started.json"), {
            "engineering_fixture": "recorded operation boundary", "command": ["offline-primitive-fixture"]})
        completed = _write(directory / (operation + "-completed.json"), {
            "stdout_sha256": shared.sha(raw.read_bytes()), "stderr_sha256": shared.sha(stderr.read_bytes()),
            "engineering_fixture": "closed recorded runtime boundary"})
        canonical_paths.append(_write(directory / "canonical-runtime.json",
            {"engineering_fixture": "bound runtime canonical; full validator replaced",
                "source_inventory_sha256": shared.sha(inventory.read_bytes()),
                "actual_operation_completions": {operation: {
                    "started_record_sha256": shared.sha(started.read_bytes()),
                    "record_sha256": shared.sha(completed.read_bytes())}}}))
    capsule = _write(data / "schedule.json", {"original_canonical": _ref(canonical_paths[0]),
        "current_canonical": _ref(canonical_paths[1]), "base_spec": {"runtime_source_root": str(old_source)},
        "runtime": {"runtime_source_root": str(source)}, "qualified_inputs": {
            "qualification_files": readiness._inventory(qualifiers), "workloads": {
                site.workload_id: {"application_evidence": readiness._inventory(application.parent)}}}})
    canary = data / "canary"
    canary_clean, canary_execution = canary / "clean", canary / "execution"
    _write(canary_clean / "module.py", b"# original passed canary source\n")
    _write(canary_execution / "module.py", b"# original passed canary source\n")
    inventory = _write(canary / "source-inventory.json", readiness._inventory(canary_clean))
    canary_plan = _write(canary / "plan.json", {"clean_runtime_root": str(canary_clean),
        "execution_root": str(canary_execution), "canonical_runtime": {
            "source_inventory_sha256": shared.sha(inventory.read_bytes())}})
    result = canary_execution / "results/canary/attempt-001"
    for name in verification.AUTHORITATIVE_DIRECTORIES:
        (result / name).mkdir(parents=True)
    _write(result / "experiment.json", {"engineering_fixture": "retained sealed canary boundary"})
    canary_raw = _write(result / "samples/slot-001/packets.raw", b"retained complete canary packets\n")
    sealed = verification.authoritative_files(result)
    seal = _write(result / "evidence.sha256", verification._format_checksums(
        {name: shared.sha(path.read_bytes()) for name, path in sealed.items()}).encode())
    deep = _write(canary / "deep.json", {"root": "/lab/results/canary/attempt-001",
        "evidence_index_sha256": shared.sha(seal.read_bytes())})
    canary_reference = {"plan": _ref(canary_plan), "deep_receipt": _ref(deep),
        "capture_record": _ref(_write(canary / "capture-completed.json", {"returncode": 0}))}
    payload = {"study_version": 6, "cohort_generation": "rolling-50",
        "sites": [asdict(site)], "lanes": [{**asdict(lane), "workload_ids": list(lane.workload_ids),
            "campaign_sha256": campaigns[index]["sha256"]} for index, lane in enumerate(selected)],
        "scheduling": _ref(capsule), "readiness": {"undefended": canary_reference}}
    plan_path = _receipt(data / "plan.json", lanes.PLAN_TYPE, payload)
    spec = lanes.CaptureSpec(data, source, source, execution, acquisition, cohort, qualifier_spec,
        workload.parent, execution / "config/campaigns", plan_path, source_manifest, client,
        source / "qcsd-lab", execution / "qcsd-lab", "sha256:" + "d" * 64, "release-fixture")
    spec_path = _write(data / "spec.json", {"schema_version": 1, "artifact_type": lanes.SPEC_TYPE,
        "inputs": spec.serializable()})
    facts = []
    for lane in selected:
        directory = root / "lanes" / lane.campaign_name
        lineage = {"image_check": {"proof": {"plan_payload": payload, "sites": [asdict(site)]}}}
        lineage_path = _receipt(directory / "lineage.json", lanes.LINEAGE_TYPE, lineage)
        intent = {"campaign_name": lane.campaign_name, "actuator": formal.ACTUATOR,
            "lineage": {"path": str(lineage_path.relative_to(root)), "sha256": shared.sha(lineage_path.read_bytes())}}
        intent_path = _receipt(directory / "intent.json", lanes.INTENT_TYPE, intent)
        _write(directory / "dns.json", {"schema_version": 1, "campaign": lane.campaign_name,
            "hosts": [["cdn.example", "8.8.4.4"], ["site.example", "8.8.8.8"]]})
        facts.append((spec, root, intent_path, intent, lineage, lane, (site,)))
    value = {"schema_version": 1, "artifact_type": formal.AUTHORITY_TYPE,
        "runtime": {key: spec.serializable()[key] for key in shared.RUNTIME_KEYS},
        "campaigns": campaigns, "capture_spec": _ref(spec_path), "lane_specs": [_ref(spec_path), _ref(spec_path)],
        "evidence_root": str(root), "lane_intents": [_ref(fact[2]) for fact in facts], "installation": None}
    path = _write(data / "authority.json", value)
    digest = shared.sha(path.read_bytes())
    output = data / "batch"
    output.mkdir()
    for index in range(2):
        (output / f"lane-{index+1}/gate").mkdir(parents=True)
        (execution / "results" / selected[index].campaign_name).mkdir()
    proof = {"authority_sha256": digest, "input_files": {str(Path(row["path"])): row["sha256"] for row in campaigns},
        "engineering_fixture": "expensive image validator boundary"}
    _write(output / "image-preflight.json", proof)
    _write(output / "batch-intent.json", {"authority_sha256": digest, "authority": value,
        "authority_path": str(path), "created_at": "2000-01-01T00:00:00Z",
        "cpu_selection": {"pairs": [[2, 4], [7, 9]], "sidecar_cpus": [0]},
        "image_preflight_sha256": shared.sha((output / "image-preflight.json").read_bytes()),
        "dns_pins": formal._dns_bindings(value, facts=facts)})
    command = [str(spec.host_launcher), "parallel-formal-run", str(path), str(output)]
    _write(output / "operator-intent.json", {"command": command, "authority_sha256": digest})
    _write(output / "host-start.json", {"command": command, "authority_sha256": digest,
        "gate_script_sha256": shared.sha(lanes.HOST_GATE_SCRIPT.encode()),
        "host": {"argv": [sys.executable, "-c", lanes.HOST_GATE_SCRIPT, json.dumps(command), "7"]}})
    calls = []
    def audit(target, **_options):
        assert target == path
        calls.append("audit")
        assert shared.load(target) == value
        shared._runtime_authority(value)
        return value, facts
    def preflight(_value, _output, authority_sha256, **_options):
        calls.append("image-proof")
        assert _value == value and _output == output
        return shared.reopen_preflight(output, authority_sha256)
    def readiness_roots(_spec, _campaign):
        calls.append("readiness")
        assert _spec == spec and _campaign in {lane.campaign_name for lane in selected}
        return [data, canary, source]
    monkeypatch.setattr(formal, "_audit", audit)
    monkeypatch.setattr(formal, "_preflight", preflight)
    monkeypatch.setattr(rolling, "readiness_roots", readiness_roots)
    return SimpleNamespace(path=path, output=output, value=value, spec=spec, facts=facts,
        lanes=selected, calls=calls, sidecar=sidecar, application=application, canary_raw=canary_raw,
        source_file=source / "src/qcsd_lab/control.py", native_file=source / "neqo-qcsd/transport.rs",
        canonical=canonical_paths[1], raw=canonical_paths[1].parent / "collection-installed-verification.stdout.log",
        acquisition=acquisition, qualifiers=qualifiers, monkeypatch=monkeypatch)


def _prepared(context):
    digest = formal.prepare_release(context.path, context.output)
    assert digest == shared.sha((context.output / "release-prepared.json").read_bytes())
    assert "audit" in context.calls and "image-proof" in context.calls and "readiness" in context.calls
    def forbidden(*_args, **_kwargs):
        pytest.fail("post-birth release must not replay full authority/readiness validators")
    context.monkeypatch.setattr(formal, "_audit", forbidden)
    context.monkeypatch.setattr(formal, "_preflight", forbidden)
    context.monkeypatch.setattr(rolling, "readiness_roots", forbidden)
    context.monkeypatch.setattr(rolling, "require_mode_readiness", forbidden)
    context.monkeypatch.setattr(schedule, "validate_schedule", forbidden)
    return digest


def _birth(context, digest):
    frame = shared.load(context.output / "release-prepared.json")
    inspected, workers, sidecars = _peer_inputs()
    extra = copy.deepcopy(inspected[-1])
    extra.update(Id="f" * 64, Name="/sidecar-b")
    inspected.append(extra)
    sidecars["sidecar-b"] = extra["Id"]
    for index, (worker, fact) in enumerate(zip(workers, context.facts, strict=True)):
        spec, _, intent_path, _, _, lane, _ = fact
        worker["image_id"] = spec.collection_image_digest
        observed = inspected[index]
        observed["Image"] = worker["image_id"]
        observed["Created"] = (lanes.admission._utc(frame["prepared_at"]) + timedelta(microseconds=1)).isoformat()
        observed["Config"]["Labels"]["org.qcsd.release-preparation-sha256"] = digest
        observed["Config"]["Env"] = [key + "=" + value for key, value in sorted(frame["environments"][index].items())]
        observed["Mounts"] = [dict(Source=str(spec.execution_root), Destination="/lab", RW=False),
            dict(Source=str(spec.execution_root / "results"), Destination="/lab/results", RW=False),
            dict(Source=str(spec.execution_root / "results" / lane.campaign_name),
                Destination="/lab/results/" + lane.campaign_name, RW=True)]
        dns = shared.load(intent_path.parent / "dns.json")
        observed["HostConfig"]["ExtraHosts"] = [host + ":" + address for host, address in dns["hosts"]]
        _write(context.output / f"lane-{index+1}/worker-argv.json", ["docker", "run", "--name", worker["name"]])
    return dict(workers=workers, sidecars=sidecars, inspected_containers=inspected,
        available_cpus=[0, 2, 4, 7, 9], docker_ncpu=16)


def _unreleased(context):
    assert not (context.output / "batch-launch.json").exists()
    for index, fact in enumerate(context.facts):
        assert not (fact[2].parent / "host-start.json").exists()
        assert not (context.output / f"lane-{index+1}/gate/release.json").exists()


def test_prepared_release_retains_real_worker_checks_without_replaying_authority(release_context):
    context = release_context
    digest = _prepared(context)
    frame = shared.load(context.output / "release-prepared.json")
    for index in range(2):
        inputs = formal.prepared_worker_inputs(context.path, context.output, index, digest)
        assert inputs["campaign_name"] == context.lanes[index].campaign_name
        assert inputs["environment"] == frame["environments"][index]
        assert inputs["result_namespace"] == str(context.spec.execution_root / "results" / context.lanes[index].campaign_name)
    actual = _birth(context, digest)
    formal.release(context.path, context.output, actual, prepared_sha256=digest)
    launch = shared.load(context.output / "batch-launch.json")
    assert launch["actual"] == actual and launch["formal_accepted_trace_count"] == 0
    for index, fact in enumerate(context.facts):
        start = lanes._payload(fact[2].parent / "host-start.json", formal.START_TYPE)
        gate = shared.load(context.output / f"lane-{index+1}/gate/release.json")
        assert start["intent_sha256"] == shared.sha(fact[2].read_bytes())
        assert gate["worker_id"] == actual["workers"][index]["id"]
        assert gate["host_partition_sha256"] == shared.sha((context.output / f"lane-{index+1}/gate/host-partition.json").read_bytes())


@pytest.mark.parametrize("name", ["source_file", "native_file", "sidecar", "raw", "canonical", "application", "canary_raw"])
def test_immutable_file_changes_after_prepare_block_both_releases(release_context, name):
    context = release_context
    digest = _prepared(context)
    actual = _birth(context, digest)
    path = getattr(context, name)
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        formal.release(context.path, context.output, actual, prepared_sha256=digest)
    _unreleased(context)


@pytest.mark.parametrize("membership", ["source", "qualification", "runtime", "canary"])
def test_finite_tree_membership_changes_block_release(release_context, membership):
    context = release_context
    digest = _prepared(context)
    actual = _birth(context, digest)
    parent = {"source": context.source_file.parent, "qualification": context.qualifiers,
        "runtime": context.canonical.parent, "canary": context.canary_raw.parent}[membership]
    _write(parent / "unexpected-input.raw", b"new file after pre-birth validation\n")
    with pytest.raises(ValueError, match="changed|differs"):
        formal.release(context.path, context.output, actual, prepared_sha256=digest)
    _unreleased(context)


def test_rederived_fence_rejects_forged_omitted_tree_member(release_context):
    context = release_context
    _prepared(context)
    frame = shared.load(context.output / "release-prepared.json")
    fence = copy.deepcopy(frame["input_fence"])
    del fence["files"][str(context.source_file)]
    with pytest.raises(ValueError, match="input bytes or inventory changed"):
        formal._check_release_fence(fence, context.path, context.value, context.facts,
            shared.reopen_preflight(context.output, shared.sha(context.path.read_bytes())))


@pytest.mark.parametrize("forgery", ["recomputed-fence", "environment"])
def test_forged_frame_cannot_replace_independently_carried_digest(release_context, forgery):
    context = release_context
    digest = _prepared(context)
    actual = _birth(context, digest)
    frame_path = context.output / "release-prepared.json"
    frame = shared.load(frame_path)
    if forgery == "recomputed-fence":
        context.source_file.write_bytes(b"# changed source with forged current fence\n")
        record = {"sha256": shared.sha(context.source_file.read_bytes()), "executable": False}
        frame["input_fence"]["files"][str(context.source_file)] = record
        frame["input_fence"]["trees"][str(context.spec.runtime_source_root)][
            str(context.source_file.relative_to(context.spec.runtime_source_root))] = record
    else:
        frame["environments"][0]["QCSD_RAPID_ROLLING_LAUNCH_INPUT"] = "forged source authority"
        actual["inspected_containers"][0]["Config"]["Env"] = [key + "=" + value
            for key, value in sorted(frame["environments"][0].items())]
    _write(frame_path, frame)
    with pytest.raises(ValueError):
        formal.release(context.path, context.output, actual, prepared_sha256=digest)
    _unreleased(context)


@pytest.mark.parametrize("name", ["source_file", "sidecar", "canary_raw", "raw"])
def test_fence_mint_cannot_adopt_an_input_changed_after_full_validation(release_context, name):
    context = release_context
    actual_fence = formal._release_fence
    def mutate_then_fence(*args, **kwargs):
        path = getattr(context, name)
        path.write_bytes(path.read_bytes() + b"\n")
        return actual_fence(*args, **kwargs)
    context.monkeypatch.setattr(formal, "_release_fence", mutate_then_fence)
    with pytest.raises(ValueError, match="changed|differs"):
        formal.prepare_release(context.path, context.output)
    assert "audit" in context.calls and "image-proof" in context.calls
    assert not (context.output / "release-prepared.json").exists()
    _unreleased(context)


@pytest.mark.parametrize("failure", ["missing-digest", "wrong-digest", "wrong-worker-label"])
def test_original_prepared_digest_is_mandatory_and_bound_to_actual_workers(release_context, failure):
    context = release_context
    digest = _prepared(context)
    actual = _birth(context, digest)
    supplied = digest
    if failure == "missing-digest":
        supplied = None
    elif failure == "wrong-digest":
        supplied = "e" * 64
    else:
        actual["inspected_containers"][1]["Config"]["Labels"]["org.qcsd.release-preparation-sha256"] = "e" * 64
    with pytest.raises(ValueError):
        formal.release(context.path, context.output, actual, prepared_sha256=supplied)
    _unreleased(context)


def test_explicit_digest_cannot_fall_back_to_legacy_when_prepared_frame_is_missing(release_context):
    context = release_context
    digest = _prepared(context)
    actual = _birth(context, digest)
    (context.output / "release-prepared.json").unlink()
    with pytest.raises(ValueError, match="prepar|frame"):
        formal.release(context.path, context.output, actual, prepared_sha256=digest)
    _unreleased(context)


@pytest.mark.parametrize("guard", ["cpu", "dns", "mount", "environment", "argv", "created"])
def test_prepared_release_keeps_inspected_cpu_dns_mount_and_birth_guards(release_context, guard):
    context = release_context
    digest = _prepared(context)
    actual = _birth(context, digest)
    worker = actual["inspected_containers"][0]
    if guard == "cpu":
        worker["HostConfig"]["CpusetCpus"] = "2,4,7"
    elif guard == "dns":
        worker["HostConfig"]["ExtraHosts"] = ["site.example:1.1.1.1"]
    elif guard == "mount":
        worker["Mounts"][1]["RW"] = True
    elif guard == "environment":
        worker["Config"]["Env"] = []
    elif guard == "argv":
        _write(context.output / "lane-1/worker-argv.json", [])
    else:
        frame = shared.load(context.output / "release-prepared.json")
        worker["Created"] = (lanes.admission._utc(frame["prepared_at"]) - timedelta(microseconds=1)).isoformat()
    with pytest.raises(ValueError):
        formal.release(context.path, context.output, actual, prepared_sha256=digest)
    _unreleased(context)


@pytest.mark.parametrize("existing", ["actual-launch.json", "batch-launch.json"])
def test_preparation_cannot_be_minted_after_worker_launch(release_context, existing):
    context = release_context
    _write(context.output / existing, {"engineering_fixture": "already born"})
    with pytest.raises(FileExistsError, match="precede actual worker launch"):
        formal.prepare_release(context.path, context.output)
    assert not (context.output / "release-prepared.json").exists()


def test_no_frame_release_keeps_legacy_fresh_authority_and_readiness(release_context):
    context = release_context
    # Build the same observed mounts and DNS without leaving a prepared frame.
    digest = formal.prepare_release(context.path, context.output)
    actual = _birth(context, digest)
    (context.output / "release-prepared.json").unlink()
    context.calls.clear()
    formal.release(context.path, context.output, actual)
    assert context.calls[0] == "audit" and "image-proof" in context.calls and "readiness" in context.calls
    assert (context.output / "batch-launch.json").is_file()
