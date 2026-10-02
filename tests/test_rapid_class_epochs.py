"""Epoch protocol boundaries; Docker, admission and packet seals are fixtures.

These checks exercise real immutable file bindings, planner arithmetic, launch
receipts and response drift. They do not claim live study capture authority.
"""

from __future__ import annotations

import copy
import json
import subprocess
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_class_epochs as epochs
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_lane_evidence import setup as lane_setup
from tests.test_rapid_site_admission import context as admission_context
from tests.test_rapid_primary_document_admission import _prepared_variable_workload

REAL_LANE_VERIFIER = plan.verify_lane_result


def rewrite(path: Path, kind: str, payload: dict) -> None:
    path.write_bytes(admission._json(admission._bind(kind, payload)))


@pytest.fixture
def study(lane_setup, monkeypatch):
    state = lane_setup
    spec, root = state.spec, state.root
    def fixture_create(path, raw):
        # Existing durability tests cover fsync/rename. These protocol fixtures
        # still enforce create-only writes without paying a disk flush per
        # each of the 50 mocked class receipts in every parametrized case.
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    monkeypatch.setattr(epochs, "durable_create", fixture_create)
    monkeypatch.setattr(lanes, "durable_create", fixture_create)
    sites = []
    for index in range(50):
        identifier = f"site-{index}"
        resources = [{"id": 0, "url": f"https://site{index}.example/", "type": "Document", "depends_on": [],
                      "known_valid": True, "chaff_priority": True, "headers": []},
                     {"id": 1, "url": "https://cdn.example/style.css", "type": "Stylesheet", "depends_on": [0],
                      "known_valid": True, "chaff_priority": False, "headers": []}]
        manifest = {"resources": resources, "preparation": {
            "source_url": f"https://site{index}.example/", "final_url": f"https://site{index}.example/",
            "approved_origins": [f"https://site{index}.example", "https://cdn.example"],
            "expected_responses": [{"resource_id": item["id"], "status": 200, "bytes": 1200,
                                    "body_sha256": "a" * 64} for item in resources]}}
        raw = admission._json(manifest)
        (spec.workload_root / f"{identifier}.json").write_bytes(raw)
        sites.append(plan.Site(f"candidate-{index}", identifier, epochs._sha(raw), f"https://site{index}.example",
                               f"shard-{index // 5}", f"{index // 5 + 1:064x}"))
    sites = tuple(sites)
    qualifiers = []
    for shard in range(10):
        name = f"shard-{shard}"
        directory = spec.campaign_dir.parent / "chaff-response-qualification-store/sets" / name
        directory.mkdir(parents=True, exist_ok=True)
        manifest_path = directory / "_qualification-set.json"
        manifest_path.write_bytes(admission._json({"qualification_set": name,
            "workload_ids": [site.workload_id for site in sites[shard * 5:(shard + 1) * 5]]}))
        for site in sites[shard * 5:(shard + 1) * 5]:
            (directory / f"{site.workload_id}.json").write_bytes(admission._json({
                "qualification_image_digest": spec.collection_image_digest,
                "qualification_source": state.proof["runtime_source"],
                "implementation_receipt": state.implementation}))
        sites = tuple(replace(site, qualification_set_manifest_sha256=epochs._sha(manifest_path.read_bytes()))
                      if index // 5 == shard else site for index, site in enumerate(sites))
        qualifiers.append({"qualification_set": name, "manifest": str(manifest_path),
                           "sidecar_root": str(directory), "prefix_spec_root": None})
    spec.qualification_spec.write_bytes(admission._json({"schema_version": 1, "qualification_sets": qualifiers}))
    parent_plan = admission._unpack(spec.plan_receipt.read_bytes(), lanes.PLAN_TYPE)
    parent_plan["cohort_generation"] = "final-50"
    parent_plan["sites"] = [asdict(site) for site in sites]
    parent_plan["lanes"] = [{**asdict(item), "campaign_sha256": "f" * 64}
                            for item in plan.plan_lanes(sites, final=True, study_version=5)]
    rewrite(spec.plan_receipt, lanes.PLAN_TYPE, parent_plan)
    state.fake_plan._inputs = lambda args: (SimpleNamespace(provenance_sha256="e" * 64), sites,
        SimpleNamespace(digests=lambda: parent_plan["bindings"]), "final-50", "f" * 64)
    proof = lanes.executed_image_plan_check(spec.serializable())
    rows = [{"candidate_id": site.candidate_id, "selected_url": site.primary_origin + "/",
             "original_terminal_sha256": f"{index + 1:064x}", "initial_site": asdict(site)}
            for index, site in enumerate(sites)]
    monkeypatch.setattr(epochs, "_classes", lambda current_spec, current_proof: copy.deepcopy(rows))
    state.sites, state.proof = sites, proof
    monkeypatch.setattr(lanes, "_retired_identity", lambda identity: "absent")
    monkeypatch.setattr(lanes, "LIFECYCLE_LOCK_PARENT", lanes.CAPTURE_LOCK_PARENT)

    def image_execute(command, **options):
        assert command[0] == "docker"
        if command[-2] == lanes.IMAGE_CHECK_SCRIPT:
            output = lanes.executed_image_plan_check(spec.serializable())
        else:
            assert command[-2] == epochs.IMAGE_SCRIPT
            output = epochs.executed_image_epoch_check(json.loads(command[-1]))
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    monkeypatch.setattr(epochs.subprocess, "run", image_execute)
    def strict_set(value, **kwargs):
        assert value["qualification_set"] == kwargs["expected_qualification_set"]
        assert value["workload_ids"] == kwargs["expected_workload_ids"]
        return value
    monkeypatch.setattr(qualification, "validate_named_qualification_set_manifest", strict_set)
    monkeypatch.setattr(plan, "verify_lane_result", REAL_LANE_VERIFIER)
    def sealed_result(path):
        return SimpleNamespace(experiment=admission._load((path / "experiment.json").read_bytes()))
    monkeypatch.setattr(plan, "verify_result", sealed_result)
    monkeypatch.setattr(epochs, "verify_result", sealed_result)
    state.fail_mode = None

    def actuate(current_spec, current_root, directory, command, env, descriptor):
        intent = epochs._open(directory / "intent.json", lanes.INTENT_TYPE)
        declaration = admission._child(root, intent["epoch_declaration"])
        block, effective = epochs.verify_block(spec, root, declaration)
        lane = epochs._epoch_lane(block, effective, intent["mode"], intent["generation"])
        launch_input = json.loads(env["QCSD_RAPID_EPOCH_LAUNCH_INPUT"])
        state.last_host_epoch_input = launch_input
        state.last_host_epoch_campaign = lane.campaign_name
        checked = epochs.validate_host_epoch_launch(launch_input, expected_campaign=lane.campaign_name,
                                                    actual_image=spec.collection_image_digest)
        assert checked["declaration"] == epochs._reference(root, declaration)
        if getattr(state, "host_preflight_check", None):
            state.host_preflight_check(launch_input, lane.campaign_name)
        start_time = admission._now()
        identity = lanes._process_identity(__import__("os").getpid())
        start = {"command": command, "execution_root": str(spec.execution_root), "started_at": start_time,
                 "intent_sha256": epochs._sha((directory / "intent.json").read_bytes()),
                 "host": {**identity, "argv": [__import__("sys").executable, "-c", lanes.HOST_GATE_SCRIPT, json.dumps(command), "7"]},
                 "supervisor": {**identity, "argv": [__import__("sys").executable, "-c", lanes.SUPERVISOR_SCRIPT,
                     json.dumps({"command": command, "execution_root": str(spec.execution_root)}), "8"]},
                 "gate_script_sha256": epochs._sha(lanes.HOST_GATE_SCRIPT.encode()),
                 "supervisor_script_sha256": epochs._sha(lanes.SUPERVISOR_SCRIPT.encode())}
        epochs._write(directory / "host-start.json", lanes.PROCESS_START_TYPE, start)
        hosts = sorted({"cdn.example", *(f"site{index}.example" for index in range((lane.shard - 1) * 5, lane.shard * 5))})
        (directory / "dns.json").write_bytes(admission._json({"schema_version": 1, "campaign": lane.campaign_name,
                                                            "hosts": [[host, "8.8.8.8"] for host in hosts]}))
        result = spec.execution_root / "results" / lane.campaign_name / "run-001"
        result.mkdir(parents=True)
        configuration = {"campaign_sha256": intent["campaign_sha256"], "profile": "research-1200",
            "request_policies": ["as-defined"], "chaff_qualification_set": lane.qualification_set,
            "chaff_qualification_set_manifest_sha256": block["qualification"]["manifest_sha256"] if lane.qualification_set else None,
            "defenses": [{"name": lane.mode}], "workloads": [{"id": site.workload_id, "sha256": site.workload_sha256,
                "visits": lane.visits_per_workload} for site in effective if site.workload_id in lane.workload_ids]}
        samples = [{"sample_id": f"{index + 1:064x}", "workload_id": item, "visit": visit,
                    "defense": lane.mode, "state": "accepted", "request_policy": "as-defined",
                    "failure": None, "attempts": 1}
                   for index, (item, visit) in enumerate((item, visit) for item in lane.workload_ids
                                                         for visit in range(lane.visits_per_workload))]
        experiment = {"name": lane.campaign_name, "purpose": "evaluation", "status": "complete",
                      "started_at": admission._now(), "source": intent["runtime_identity"]["runtime_source"],
                      "configuration": configuration, "samples": samples,
                      "summary": {"planned": 20, "accepted": 20, "failed": 0, "passed": True}}
        if state.fail_mode == lane.mode:
            from qcsd_lab.experiment import resolved_attempt_directory
            from qcsd_lab.orchestrator import _prepared_response_identity_failure
            sample = samples[0]
            sample["state"] = "failed"
            (result / "failures").mkdir()
            attempt = resolved_attempt_directory(result, sample)
            (attempt / "neqo").mkdir(parents=True)
            manifest = admission._load((spec.workload_root / f"{sample['workload_id']}.json").read_bytes())
            run = {"completion_status": "complete", "error": None, "responses": [
                {"resource_id": item["id"], "url": item["url"], "status": 200, "bytes": 1200,
                 "body_sha256": "b" * 64 if item["id"] == 0 else "a" * 64,
                 "outcome": "succeeded", "complete": True} for item in manifest["resources"]]}
            (attempt / "neqo/run.json").write_bytes(admission._json(run))
            sample["failure"] = _prepared_response_identity_failure(SimpleNamespace(id=sample["workload_id"], data=manifest), attempt)
            experiment["status"] = "incomplete"
            experiment["summary"] = {"planned": 20, "accepted": 19, "failed": 1, "passed": False}
        experiment["completed_at"] = admission._now()
        (result / "experiment.json").write_bytes(admission._json(experiment))
        (result / "evidence.sha256").write_bytes(b"fixture packet/experiment seal\n")
        (directory / "host.stdout.log").write_bytes(b"fixture actual host stdout\n")
        (directory / "host.stderr.log").write_bytes(b"")
        epochs._write(directory / "host-process.json", lanes.PROCESS_TYPE, {
            "command": command, "execution_root": str(spec.execution_root), "started_at": start_time,
            "completed_at": admission._now(), "returncode": 1 if state.fail_mode == lane.mode else 0, "interruption": None,
            "start": lanes._put_object(root, (directory / "host-start.json").read_bytes()),
            "stdout": lanes._put_object(root, (directory / "host.stdout.log").read_bytes()),
            "stderr": lanes._put_object(root, (directory / "host.stderr.log").read_bytes())})
    monkeypatch.setattr(lanes, "_actuate_host", actuate)
    # initialize_study requires an unused tree; the original adapter fixture
    # has not created evidence yet.
    state.policy = epochs.initialize_study(spec, root)
    state.qualifier = spec.campaign_dir.parent / "chaff-response-qualification-store/sets/shard-0/_qualification-set.json"
    return state


def block(study, *, number=1, shard=1):
    qualifier = study.spec.campaign_dir.parent / f"chaff-response-qualification-store/sets/shard-{shard - 1}/_qualification-set.json"
    return epochs.declare_block(study.spec, study.root, block=number, shard=shard, qualification_manifest=qualifier)


def test_initial_policy_keeps_fifty_labels_and_exact_urls(study):
    value = epochs.verify_policy(study.spec, study.root)
    assert len(value["classes"]) == 50
    assert value["block_count"] == 160
    assert value["formal_trace_target"] == 16000
    assert len(list((study.root / "classes").glob("*/e0001.json"))) == 50
    for item in value["classes"]:
        receipt = study.root / "classes" / item["candidate_id"] / "e0001.json"
        assert epochs.verify_class_epoch(study.spec, study.root, receipt)["selected_url"] == item["selected_url"]


@pytest.mark.parametrize("mutation", ["label", "url", "count", "bool-count", "rule"])
def test_resealed_policy_cannot_change_membership_or_protocol(study, mutation):
    value = epochs._open(study.policy, epochs.POLICY_TYPE)
    if mutation == "label":
        value["classes"][0]["candidate_id"] = "replacement-class"
    elif mutation == "url":
        value["classes"][0]["selected_url"] += "new-page"
    elif mutation == "count":
        value["formal_trace_target"] = 8000
    elif mutation == "bool-count":
        value["visits_per_condition"] = True
    else:
        value["selection_rule"] = "select-newest"
    rewrite(study.policy, epochs.POLICY_TYPE, value)
    with pytest.raises(ValueError, match="classes|protocol"):
        epochs.verify_policy(study.spec, study.root)


def test_epoch_namespace_is_separate_from_transient_generation_and_legacy_bytes(study):
    declaration = block(study)
    value, sites = epochs.verify_block(study.spec, study.root, declaration)
    first = epochs._epoch_lane(value, sites, "buflo")
    second = epochs._epoch_lane(value, sites, "buflo", 2)
    assert first.campaign_name.endswith("-e0001")
    assert second.campaign_name.endswith("-g02-e0001")
    assert first.logical_name == second.logical_name
    original = plan.plan_lanes(study.sites, final=True, study_version=5)[3]
    before = plan.render_lane_campaign(original, study.sites)
    assert plan.render_lane_campaign(original, study.sites) == before
    assert "-e0001" not in before.decode()
    assert epochs.render_epoch_lane(first, sites, 1) != before
    with pytest.raises(FileExistsError):
        block(study)


@pytest.mark.parametrize("mutation", ["swap", "omit", "late", "campaign", "bool-epoch", "qualification"])
def test_resealed_block_cannot_change_its_epoch_vector_or_conditions(study, mutation):
    declaration = block(study)
    value = epochs._open(declaration, epochs.BLOCK_TYPE)
    if mutation == "swap":
        value["epochs"].reverse()
    elif mutation == "omit":
        del value["campaigns"]["front"]
    elif mutation == "late":
        value["declared_at"] = "2020-01-01T00:00:00Z"
    elif mutation == "campaign":
        value["campaigns"]["front"]["sha256"] = "b" * 64
    elif mutation == "bool-epoch":
        value["ordinal"] = True
    else:
        value["qualification"]["manifest_sha256"] = "b" * 64
    rewrite(declaration, epochs.BLOCK_TYPE, value)
    with pytest.raises(ValueError):
        epochs.verify_block(study.spec, study.root, declaration)


def test_complete_block_commits_only_after_all_five_conditions_and_stays_immutable(study):
    declaration = block(study)
    for mode in plan.MODES[:-1]:
        receipt = epochs.launch_block_lane(study.spec, study.root, declaration, mode=mode)
        assert epochs.verify_lane(study.spec, study.root, receipt)["accepted"] == 20
    with pytest.raises(ValueError, match="all five"):
        epochs.commit_block(study.spec, study.root, declaration)
    epochs.launch_block_lane(study.spec, study.root, declaration, mode="cs-buflo")
    commit = epochs.commit_block(study.spec, study.root, declaration)
    assert epochs.verify_commit(study.spec, study.root, commit)["accepted"] == 100
    before = {path.relative_to(declaration.parent).as_posix(): path.read_bytes()
              for path in declaration.parent.rglob("*") if path.is_file()}
    with pytest.raises(ValueError, match="committed"):
        epochs.launch_block_lane(study.spec, study.root, declaration, mode="front", generation=2)
    with pytest.raises(ValueError, match="committed"):
        epochs.retire_block(study.spec, study.root, declaration)
    assert before == {path.relative_to(declaration.parent).as_posix(): path.read_bytes()
                      for path in declaration.parent.rglob("*") if path.is_file()}
    with pytest.raises(ValueError, match="160"):
        epochs.corpus_manifest(study.spec, study.root)


def test_g02_requires_an_incomplete_immediate_predecessor_in_the_same_epoch(study):
    declaration = block(study)
    with pytest.raises(ValueError, match="immediate"):
        epochs.launch_block_lane(study.spec, study.root, declaration, mode="front", generation=2)
    receipt = epochs.launch_block_lane(study.spec, study.root, declaration, mode="front")
    with pytest.raises(ValueError, match="incomplete"):
        epochs.launch_block_lane(study.spec, study.root, declaration, mode="front", generation=2,
                                 predecessor_intent=receipt.parent / "intent.json")


def test_actual_complete_capture_cannot_retry_when_completion_publication_is_missing(study):
    declaration = block(study)
    receipt = epochs.launch_block_lane(study.spec, study.root, declaration, mode="front")
    receipt.unlink()  # Private fixture models a lost receipt-publication step.
    with pytest.raises(ValueError, match="actual incomplete"):
        epochs.launch_block_lane(study.spec, study.root, declaration, mode="front", generation=2,
                                 predecessor_intent=receipt.parent / "intent.json")
    assert not (study.spec.campaign_dir / (receipt.parent.name.replace("-e0001", "-g02-e0001") + ".yml")).exists()


def test_successful_g02_binds_actual_failed_raw_predecessor_inventory(study):
    declaration = block(study)
    study.fail_mode = "front"
    with pytest.raises(ValueError):
        epochs.launch_block_lane(study.spec, study.root, declaration, mode="front")
    previous = next((declaration.parent / "lanes").glob("*/intent.json"))
    study.fail_mode = None
    successor = epochs.launch_block_lane(study.spec, study.root, declaration, mode="front", generation=2,
                                        predecessor_intent=previous)
    for mode in plan.MODES:
        if mode != "front":
            epochs.launch_block_lane(study.spec, study.root, declaration, mode=mode)
    commit = epochs.commit_block(study.spec, study.root, declaration)
    checked = epochs.verify_commit(study.spec, study.root, commit)
    assert len(checked["unselected_attempts"]) == 1
    assert checked["unselected_attempts"][0]["result_inventory"]
    assert epochs.verify_lane(study.spec, study.root, successor)["generation"] == 2
    raw = next((study.spec.execution_root / "results" / previous.parent.name).rglob("run.json"))
    raw.write_bytes(raw.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="predecessor evidence|unselected"):
        epochs.verify_commit(study.spec, study.root, commit)


@pytest.mark.parametrize("entry", ["orphan", "extra-file", "symlink"])
def test_block_cannot_hide_unregistered_physical_lane_inventory(study, entry):
    declaration = block(study)
    epochs.launch_block_lane(study.spec, study.root, declaration, mode="front")
    lane_root = declaration.parent / "lanes"
    if entry == "orphan":
        (lane_root / "interrupted-before-intent").mkdir()
    elif entry == "extra-file":
        (lane_root / "hidden-launch").write_bytes(b"unregistered attempt")
    else:
        (lane_root / "linked-launch").symlink_to(next(lane_root.iterdir()), target_is_directory=True)
    with pytest.raises(ValueError, match="physical|unexpected"):
        epochs.commit_block(study.spec, study.root, declaration)


def test_epoch_capture_completion_must_fit_its_actual_terminal_host_clock(study):
    declaration = block(study)
    receipt = epochs.launch_block_lane(study.spec, study.root, declaration, mode="front")
    result = next((study.spec.execution_root / "results" / receipt.parent.name).iterdir())
    path = result / "experiment.json"
    experiment = admission._load(path.read_bytes())
    experiment["completed_at"] = "2099-01-01T00:00:00Z"
    path.write_bytes(admission._json(experiment))
    with pytest.raises(ValueError, match="host execution"):
        epochs.verify_lane(study.spec, study.root, receipt)


@pytest.mark.parametrize("mutation", ["image", "intent-hash", "campaign", "extra-input"])
def test_actual_host_epoch_preflight_rejects_tampered_launch_before_actuation(study, mutation):
    declaration = block(study)

    def reject(value, campaign):
        changed = copy.deepcopy(value)
        image = study.spec.collection_image_digest
        if mutation == "image":
            image = "sha256:" + "b" * 64
        elif mutation == "intent-hash":
            changed["intent_sha256"] = "b" * 64
        elif mutation == "campaign":
            campaign = campaign.replace("-s01-", "-s02-")
        else:
            changed["grant_authority"] = True
        with pytest.raises(ValueError):
            epochs.validate_host_epoch_launch(changed, expected_campaign=campaign, actual_image=image)

    study.host_preflight_check = reject
    epochs.launch_block_lane(study.spec, study.root, declaration, mode="undefended")
    # The same predeclared intent is unusable once its physical attempt ends.
    with pytest.raises(ValueError, match="already attempted"):
        epochs.validate_host_epoch_launch(study.last_host_epoch_input,
            expected_campaign=study.last_host_epoch_campaign, actual_image=study.spec.collection_image_digest)


def test_real_one_byte_identity_drift_is_preserved_and_cannot_commit(study):
    declaration = block(study)
    study.fail_mode = "undefended"
    with pytest.raises(ValueError, match="complete frozen plan"):
        epochs.launch_block_lane(study.spec, study.root, declaration, mode="undefended")
    drift = epochs._observed_drift(study.spec, study.root, declaration)
    assert drift[0]["candidate_id"] == "candidate-0"
    assert drift[0]["failure"]["details"][0]["differing_resource_ids"] == [0]
    assert not (declaration.parent / "commit.json").exists()
    with pytest.raises(ValueError, match="all five"):
        epochs.commit_block(study.spec, study.root, declaration)


def test_transport_loss_is_not_epoch_refresh_authority(study):
    declaration = block(study)
    study.fail_mode = "undefended"
    with pytest.raises(ValueError):
        epochs.launch_block_lane(study.spec, study.root, declaration, mode="undefended")
    run = next((study.spec.execution_root / "results").glob("*-e0001/run-001/failures/*/attempt-001/neqo/run.json"))
    value = admission._load(run.read_bytes())
    value["completion_status"] = "partial"
    run.write_bytes(admission._json(value))
    with pytest.raises(ValueError, match="transport failure"):
        epochs._observed_drift(study.spec, study.root, declaration)


@pytest.fixture
def fresh_raw(study, monkeypatch):
    from datetime import UTC, datetime, timedelta
    from qcsd_lab.application_response_policy import TERMINAL_HTTP_ERROR_POLICY
    from qcsd_lab.prepare import neqo_host_timeout
    spec = study.spec
    workload = spec.workload_root / "site-0-fresh.json"
    manifest = admission._load((spec.workload_root / "site-0.json").read_bytes())
    preparation = manifest["preparation"]
    preparation.update(application_response_policy=TERMINAL_HTTP_ERROR_POLICY, stability_runs=3,
        timeout_seconds=120, max_response_bytes=1048576, neqo_version="fixture-client",
        neqo_base_commit="b" * 40, published_qcsd_commit="c" * 40, migration_commit="c" * 40)
    workload.write_bytes(admission._json(manifest))
    graph = spec.data_root / "fresh-full-graph.json"
    graph.write_bytes(admission._json(manifest["resources"]))
    source = study.proof["runtime_source"]
    context = SimpleNamespace(application_response_policy=TERMINAL_HTTP_ERROR_POLICY, expected_runtime_source=source)
    monkeypatch.setattr(admission, "load_admission_context", lambda root: context)
    def prepared(path, graph_path, current, *, selected_page_url):
        assert selected_page_url == manifest["preparation"]["source_url"]
        assert admission._load(graph_path.read_bytes()) == manifest["resources"]
        return {"selected_page_url": selected_page_url, "prepared_workload_sha256": epochs._sha(path.read_bytes())}
    monkeypatch.setattr(admission, "verify_prepared_workload", prepared)
    base_time = datetime.now(UTC) - timedelta(seconds=30)
    time = lambda offset: (base_time + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
    original = spec.data_root / ".site-0-fresh-prepare-fixture"
    artifacts = {name: admission._json(manifest) for name in ("probe-input.json", "probe-output.json", "stability-input.json")}
    def child(command, start, end):
        return {"schema_version": 1, "command": command, "returncode": 0,
                "configured_timeout_seconds": 120, "host_timeout_seconds": neqo_host_timeout(120),
                "started_at": time(start), "completed_at": time(end), "stdout": "",
                "stdout_sha256": epochs._sha(b"")}
    artifacts["probe.log.execution.json"] = admission._json(child(["/fixture/client", "probe"], 1, 2))
    artifacts["probe-output.probe-head/run.json"] = b"{}"
    artifacts["probe-output.probe-get/run.json"] = b"{}"
    for index in range(3):
        start, end = 3 + index * 4, 4 + index * 4
        command = ["/fixture/client", "run", "--application-response-policy", TERMINAL_HTTP_ERROR_POLICY,
                   "--workload", str(original / "stability-input.json"), "--profile", "live", "--defense", "none",
                   "--seed", "0", "--output-dir", str(original / f"stability-{index}"),
                   "--max-response-bytes", "1048576", "--timeout-seconds", "120"]
        artifacts[f"stability-{index}.log.execution.json"] = admission._json(child(command, start, end))
        run_start = int((base_time + timedelta(seconds=start, milliseconds=100)).timestamp() * 1e9)
        run_end = int((base_time + timedelta(seconds=end, milliseconds=-100)).timestamp() * 1e9)
        run = {"application_response_policy": TERMINAL_HTTP_ERROR_POLICY, "completion_status": "complete",
               "error": None, "error_class": None, "terminal_evidence_render_errors": [],
               "started_unix_ns": run_start, "ended_unix_ns": run_end, "time_anchor_unix_ns": run_start,
               "workload_hash_sha256": epochs._sha(artifacts["stability-input.json"]),
               **{key: preparation[key] for key in ("neqo_version", "neqo_base_commit", "published_qcsd_commit", "migration_commit")},
               "endpoints": [{"origin": value + "/", "negotiated_protocol": "h3"}
                             for value in preparation["approved_origins"]],
               "responses": [{"resource_id": item["id"], "url": item["url"], "status": 200, "bytes": 1200,
                              "body_sha256": "a" * 64, "outcome": "succeeded", "complete": True}
                             for item in manifest["resources"]]}
        artifacts[f"stability-{index}/run.json"] = admission._json(run)
    directory = workload.parent / f"{workload.stem}-application-response-evidence"
    def publish_inventory():
        files = {}
        for name, raw in artifacts.items():
            path = directory / "artifacts" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            files[name] = {"sha256": epochs._sha(raw), "size": len(raw)}
        (directory / "inventory.json").write_bytes(admission._json({"schema_version": 1,
            "artifact_type": "qcsd-application-response-preparation-evidence", "workload_id": workload.stem,
            "original_directory": str(original), "capture_source_before": source, "capture_source_after": source,
            "started_at": time(0), "completed_at": time(15), "policy_evidence": None,
            "files": files, "scientific_credit": False}))
    publish_inventory()
    row = {"candidate_id": "candidate-0", "selected_url": "https://site0.example/",
           "initial_site": asdict(study.sites[0])}
    return SimpleNamespace(spec=spec, root=study.root, workload=workload, graph=graph, row=row,
                           not_before=time(-1), time=time, artifacts=artifacts, publish=publish_inventory)


def test_fresh_raw_preparation_reopens_every_actual_complete_repeat(fresh_raw):
    state = fresh_raw
    facts = epochs._fresh_preparation(state.spec, state.root, state.row, state.workload, state.graph,
                                      not_before=state.not_before)
    assert facts["workload_sha256"] == epochs._sha(state.workload.read_bytes())


@pytest.mark.parametrize("negative", [True, False])
def test_epoch_refresh_reopens_registered_variable_primary_producer(
    admission_context, tmp_path, monkeypatch, negative,
):
    from qcsd_lab import prepare
    from tests import test_prepare_application_response_policy as producer_fixture
    original_fixture = producer_fixture.install_fake_preparation
    def full_graph_native(monkeypatch, *args, **kwargs):
        result = original_fixture(monkeypatch, *args, **kwargs)
        native = prepare.run
        def actual(command, **options):
            completed = native(command, **options)
            if command[1] == "run":
                target = Path(command[command.index("--output-dir") + 1]) / "run.json"
                run = admission._load(target.read_bytes())
                workload = admission._load(Path(command[command.index("--workload") + 1]).read_bytes())
                origins = sorted({admission.origin(row["url"]) for row in workload["resources"]})
                # The general preparation fixture contains only one endpoint;
                # this epoch fixture models actual full-graph HTTP/3 delivery.
                run["endpoints"] = [{"id": index, "origin": origin + "/", "negotiated_protocol": "h3"}
                                    for index, origin in enumerate(origins)]
                target.write_bytes(admission._json(run))
            return completed
        monkeypatch.setattr(prepare, "run", actual)
        return result
    monkeypatch.setattr(producer_fixture, "install_fake_preparation", full_graph_native)
    context, prepared, graph = _prepared_variable_workload(admission_context, tmp_path, monkeypatch,
                                                         negative=negative)
    monkeypatch.setattr(admission, "load_admission_context", lambda root: context)
    spec = SimpleNamespace(acquisition_root=context.root, data_root=context.root)
    row = {"selected_url": "https://page.test/", "initial_site": {"primary_origin": "https://page.test"}}
    facts = epochs._fresh_preparation(spec, context.root, row, prepared.path, graph,
                                      not_before=context.page_policy_not_before_utc.isoformat())
    assert facts["raw_inventory_sha256"] == epochs._sha(
        (prepared.application_response_evidence_path / "inventory.json").read_bytes())
    assert facts["facts"]["primary_document_identity_policy"] == "variable-primary-document-body-v1"


@pytest.mark.parametrize("mutation", ["body", "http2", "missing", "stale", "clock", "prune", "source"])
def test_fresh_raw_preparation_rejects_resealed_inconsistent_witnesses(fresh_raw, mutation):
    state = fresh_raw
    if mutation == "stale":
        state.not_before = state.time(1)
    elif mutation == "prune":
        value = admission._load(state.artifacts["probe-input.json"])
        value["resources"].pop()
        state.artifacts["probe-input.json"] = admission._json(value)
    else:
        name = "stability-1/run.json"
        value = admission._load(state.artifacts[name])
        if mutation == "body":
            value["responses"][1]["body_sha256"] = "b" * 64
        elif mutation == "http2":
            value["endpoints"][0]["negotiated_protocol"] = "h2"
        elif mutation == "missing":
            value["responses"].pop()
        elif mutation == "clock":
            value["started_unix_ns"] = 1
            value["time_anchor_unix_ns"] = 1
        elif mutation == "source":
            value["migration_commit"] = "f" * 40
        state.artifacts[name] = admission._json(value)
    state.publish()
    with pytest.raises(ValueError):
        epochs._fresh_preparation(state.spec, state.root, state.row, state.workload, state.graph,
                                  not_before=state.not_before)


def fixture_quiescence(monkeypatch):
    def observation(root, descriptor):
        import os
        metadata = os.fstat(descriptor)
        command = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", "/fixture-config"]
        executions = [{"command": [*command, *operation, "--filter", "label=org.qcsd.owner=qcsd-lab"],
                       "returncode": 0, "stdout": lanes._put_object(root, b""),
                       "stderr": lanes._put_object(root, b"fixture Docker observation\n")}
                      for operation in (("ps", "--all", "--quiet"), ("network", "ls", "--quiet"))]
        return {"lifecycle_lock": {"path": str(lanes.LIFECYCLE_LOCK_PARENT / f"qcsd-docker-lifecycle-{os.getuid()}.lock"),
                    "device": metadata.st_dev, "inode": metadata.st_ino, "uid": metadata.st_uid,
                    "mode": metadata.st_mode & 0o7777, "links": metadata.st_nlink, "size": metadata.st_size},
                "guardian_processes": [], "guardian_sockets": lanes._put_object(root, b"fixture empty process census\n"),
                "lifecycle_entries": [], "docker_executions": executions}
    monkeypatch.setattr(lanes, "_retirement_quiescence", observation)


def test_block_retirement_freshness_follows_actual_terminal_attempt(study, monkeypatch):
    fixture_quiescence(monkeypatch)
    declaration = block(study)
    study.fail_mode = "front"
    with pytest.raises(ValueError):
        epochs.launch_block_lane(study.spec, study.root, declaration, mode="front")
    retired = epochs.retire_block(study.spec, study.root, declaration)
    value = epochs._open(retired, epochs.RETIREMENT_TYPE)
    value["observed_at"] = epochs._open(declaration, epochs.BLOCK_TYPE)["declared_at"]
    rewrite(retired, epochs.RETIREMENT_TYPE, value)
    with pytest.raises(ValueError, match="terminal host"):
        epochs.verify_block_retirement(study.spec, study.root, retired)


def test_observed_retirement_refreshes_one_class_and_preserves_another_block(study, monkeypatch):
    fixture_quiescence(monkeypatch)
    unrelated = block(study, number=2)
    for mode in plan.MODES:
        epochs.launch_block_lane(study.spec, study.root, unrelated, mode=mode)
    unrelated_commit = epochs.commit_block(study.spec, study.root, unrelated)
    retained = {path.relative_to(unrelated.parent).as_posix(): path.read_bytes()
                for path in unrelated.parent.rglob("*") if path.is_file()}
    failed = block(study)
    # A completed condition remains retained when a later condition drifts.
    epochs.launch_block_lane(study.spec, study.root, failed, mode="front")
    study.fail_mode = "undefended"
    with pytest.raises(ValueError):
        epochs.launch_block_lane(study.spec, study.root, failed, mode="undefended")
    retired = epochs.retire_block(study.spec, study.root, failed)
    observed = epochs.verify_block_retirement(study.spec, study.root, retired)
    assert observed["drifting_candidates"] == ["candidate-0"]
    assert observed["attempts"][0]["retired_processes"] == {"host": "absent", "supervisor": "absent"}
    before_failed = {path.relative_to(failed.parent).as_posix(): path.read_bytes()
                     for path in failed.parent.rglob("*") if path.is_file()}
    old = study.spec.workload_root / "site-0.json"
    refreshed = study.spec.workload_root / "site-0-epoch2.json"
    refreshed.write_bytes(old.read_bytes() + b"\n")
    graph = study.spec.data_root / "fresh-graph.json"
    graph.write_bytes(b"fixture independently reopened full fresh graph\n")
    def preparation(spec, root, row, workload, graph, *, not_before):
        assert workload == refreshed and row["candidate_id"] == "candidate-0"
        return {"workload_path": epochs._data_reference(spec, workload), "graph_path": epochs._data_reference(spec, graph),
                "workload_sha256": epochs._sha(workload.read_bytes()), "graph_sha256": epochs._sha(graph.read_bytes()),
                "raw_inventory_sha256": "f" * 64, "facts": {}, "started_at": admission._now(),
                "completed_at": admission._now()}
    # Raw production preparation checks receive independent focused coverage;
    # this fixture isolates selection, predecessor and lane propagation.
    facts = preparation(study.spec, study.root, {"candidate_id": "candidate-0"}, refreshed, graph,
                        not_before=observed["observed_at"])
    monkeypatch.setattr(epochs, "_fresh_preparation", lambda *args, **kw: facts)
    epoch = epochs.register_class_epoch(study.spec, study.root, candidate_id="candidate-0", workload=refreshed,
                                      graph=graph, retirement=retired)
    with pytest.raises(ValueError, match="actual fresh registered epoch"):
        epochs.declare_block(study.spec, study.root, block=1, shard=1,
            qualification_manifest=study.qualifier, predecessor_retirement=retired)
    assert not epochs._block_directory(study.root, 1, 1, 2).exists()
    with pytest.raises(ValueError, match="original class"):
        epochs.register_class_epoch(study.spec, study.root, candidate_id="candidate-1", workload=refreshed,
                                     graph=graph, retirement=retired)
    qualifier = study.spec.campaign_dir.parent / "chaff-response-qualification-store/sets/shard-0-epoch2/_qualification-set.json"
    qualifier.parent.mkdir(parents=True)
    names = ["site-0-epoch2", "site-1", "site-2", "site-3", "site-4"]
    qualifier.write_bytes(admission._json({"qualification_set": "shard-0-epoch2", "workload_ids": names}))
    for name, previous in zip(names, ["site-0", "site-1", "site-2", "site-3", "site-4"], strict=True):
        (qualifier.parent / f"{name}.json").write_bytes((study.qualifier.parent / f"{previous}.json").read_bytes())
    replacement = epochs.declare_block(study.spec, study.root, block=1, shard=1,
        epochs={"candidate-0": epoch}, qualification_manifest=qualifier, predecessor_retirement=retired)
    block_value, sites = epochs.verify_block(study.spec, study.root, replacement)
    assert block_value["ordinal"] == 2
    assert sites[0].workload_id == "site-0-epoch2"
    assert [site.candidate_id for site in sites] == [site.candidate_id for site in study.sites]
    study.fail_mode = None
    for mode in plan.MODES:
        receipt = epochs.launch_block_lane(study.spec, study.root, replacement, mode=mode)
        assert receipt.parent.name.endswith("-e0002")
        assert epochs.verify_lane(study.spec, study.root, receipt)["accepted"] == 20
    assert epochs.verify_commit(study.spec, study.root, epochs.commit_block(study.spec, study.root, replacement))["accepted"] == 100
    assert epochs.verify_commit(study.spec, study.root, unrelated_commit)["accepted"] == 100
    assert retained == {path.relative_to(unrelated.parent).as_posix(): path.read_bytes()
                        for path in unrelated.parent.rglob("*") if path.is_file()}
    assert before_failed == {path.relative_to(failed.parent).as_posix(): path.read_bytes()
                            for path in failed.parent.rglob("*") if path.is_file()}


def test_corpus_requires_all_160_explicit_commits_and_rejects_hidden_epoch(study, monkeypatch):
    # Exercise the full grid selection/counting layer without manufacturing
    # 16,000 packet captures. Real commit/lane verification is tested above.
    monkeypatch.setattr(epochs, "verify_block", lambda spec, root, path, **kw: (
        epochs._open(path, epochs.BLOCK_TYPE), study.sites))
    monkeypatch.setattr(epochs, "verify_commit", lambda spec, root, path: epochs._open(path, epochs.COMMIT_TYPE))
    for number in range(1, 17):
        for shard in range(1, 11):
            directory = epochs._block_directory(study.root, number, shard, 1)
            declaration = epochs._write(directory / "declaration.json", epochs.BLOCK_TYPE, {
                "block": number, "shard": shard, "ordinal": 1,
                "epochs": [{"candidate_id": item.candidate_id} for item in study.sites[(shard - 1) * 5:shard * 5]]})
            epochs._write(directory / "commit.json", epochs.COMMIT_TYPE, {
                "block": number, "shard": shard, "ordinal": 1, "declaration": epochs._reference(study.root, declaration)})
    manifest = epochs.corpus_manifest(study.spec, study.root)
    assert len(manifest["blocks"]) == 160
    assert manifest["accepted"] == 16000
    tampered = copy.deepcopy(manifest)
    tampered["blocks"].pop()
    with pytest.raises(ValueError, match="selections"):
        epochs.verify_corpus_manifest(study.spec, study.root, tampered)
    hidden = epochs._block_directory(study.root, 1, 1, 2)
    epochs._write(hidden / "declaration.json", epochs.BLOCK_TYPE, {
        "block": 1, "shard": 1, "ordinal": 2, "epochs": []})
    with pytest.raises(ValueError, match="unfinished"):
        epochs.corpus_manifest(study.spec, study.root)
