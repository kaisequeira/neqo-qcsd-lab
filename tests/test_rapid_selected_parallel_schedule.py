"""Selected parallel HOST contracts; physical boundaries are synthetic.

Real complete-GET reconstruction, selected inputs, additive membership,
amendments, public plans, lane intents and dependency fences run here.
Runtime installation, named120 execution, canary capture/deep and Docker
actuation are explicit fixture boundaries. No scientific credit is claimed.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from qcsd_lab import application_response_policy as app
from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_capture_traffic as traffic
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as operation
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_rolling_schedule as dispatch
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_selected_parallel_schedule as parallel
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import response_budget_qualification as budget
from qcsd_lab import selected_capture_amendment as amendment
from qcsd_lab import supplied_static_graph as graph
from tests.test_selected_capture_input import (
    additive_case, selected_graph, qualifier_fixture, forbid_history,
    REPOSITORY, load, write,
)
from tests.test_selected_capture_amendment import publish as fixed_policy, canary as fixed_canary
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_get import actual_contract_fixture


@pytest.fixture(params=list(rolling.plan.MODES))
def setting(additive_case, monkeypatch, request):
    c, mode = additive_case, request.param
    runtime = c["runtime"]
    for relative in parallel.CONTROL_FILES:
        path = Path(runtime["runtime_source_root"]) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((REPOSITORY / relative).read_bytes())
    for relative, digest in traffic.files().values():
        raw = (REPOSITORY / relative).read_bytes()
        assert graph.digest(raw) == digest
        path = Path(runtime["runtime_source_root"]) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    amendment_path, authority = None, None
    if mode in {"front", "buflo"}:
        amendment_path, qualifier, authority = fixed_policy(c, monkeypatch, mode)
        canary, facts = fixed_canary(c, authority, mode)
        manifest = Path(authority["workloads"][0]["capture_manifest"]["path"])
    else:
        qualifier = qualifier_fixture(c, monkeypatch)
        manifest = Path(runtime["workload_root"]) / c["second"]["prepared"].name
        canary_path = c["new_study"] / (mode + "-canary.json")
        write(canary_path, {"mode": mode, "synthetic_current_capture_and_deep": True})
        canary = {"plan": rolling._ref(canary_path)}
        resources = load(manifest)["resources"]
        facts = {"workload_sha256": rolling._ref(manifest)["sha256"],
            "authority_source": {**load(Path(runtime["source_manifest"])), "image_digest": runtime["collection_image_digest"]},
            "client_sha256": graph.digest(Path(runtime["client_binary"]).read_bytes()),
            "traffic_hashes": traffic.expected(),
            "full_graph": {"resource_count": len(resources),
                "resource_records_sha256": readiness._sha(readiness._encoded(resources)),
                "origins": sorted({rolling.origin(row["url"]) for row in resources})}}
    facts[app.APPLICATION_BODY_IDENTITY_FIELD] = app.COMPLETE_APPLICATION_DELIVERY_POLICY
    facts["content_equality_across_visits_claimed"] = False
    q = load(qualifier)["qualification_sets"][0]
    sidecars = Path(q["sidecar_root"])
    named = Path(q["manifest"])
    write(named, {"artifact_type": budget.NAMED_ARTIFACT_TYPE,
        "qualification_sidecar_schema_version": budget.SIDECAR_SCHEMA_VERSION,
        "synthetic_current_full120_boundary": True})
    sidecar_path = sidecars / manifest.name
    sidecar = load(sidecar_path)
    sidecar.update(schema_version=budget.SIDECAR_SCHEMA_VERSION)
    sidecar["implementation_receipt"]["sha256"] = "9" * 64
    write(sidecar_path, sidecar)
    calls = {"named120": 0, "canary": 0}
    def named_boundary(value, **kwargs):
        calls["named120"] += 1
        assert value["artifact_type"] == budget.NAMED_ARTIFACT_TYPE
        assert kwargs["expected_workload_ids"] == [manifest.stem]
        assert kwargs["expected_qualification_scope"] == "response-only"
        assert kwargs["prefix_spec_root"] is None
        assert kwargs["require_current_implementation"] is False
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", named_boundary)
    monkeypatch.setattr(budget, "validate_named_qualification_set_manifest", named_boundary)
    def canary_boundary(reference, *, runtime: dict, mode: str):
        calls["canary"] += 1
        assert reference == canary and mode == request.param
        assert runtime == {key: c["runtime"][key] for key in lanes.RUNTIME_KEYS}
        return facts
    monkeypatch.setattr(readiness, "validate_canary", canary_boundary)
    # The capture/deep receipt is synthetic. Fence its actual fixture refs,
    # without pretending there are physical result/index objects.
    bind = operation.OperationFacts.bind_canary
    def canary_fence(context, reference, runtime=None):
        if reference != canary:
            return bind(context, reference, runtime)
        context._references(reference, c["new_study"])
    monkeypatch.setattr(operation.OperationFacts, "bind_canary", canary_fence)
    monkeypatch.setattr(receipts, "_now", lambda: datetime.now(UTC).isoformat())
    forbid_history(monkeypatch)
    serial = c["new_study"] / (mode + "-serial.json")
    rolling.publish_plan(c["new_study"], c["new_enrollment"], qualifier, serial,
        readiness={mode: canary}, static_capture_amendment=amendment_path,
        application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY)
    spec = rolling.capture_spec(c["new_study"], c["new_enrollment"], qualifier, serial)
    metadata = load(spec.source_manifest)
    canonical = {"source": metadata, "collection_image_digest": spec.collection_image_digest,
        "installed_client_sha256": rolling._ref(spec.client_binary)["sha256"],
        "checks": {"collection": {"qualification_implementation_sha256": "9" * 64}},
        "verified_at": "2026-10-04T00:13:30Z"}
    path = c["new_study"] / "runtime/canonical.json"
    path.parent.mkdir()
    write(path, canonical)
    reference = rolling._ref(path)
    def runtime_boundary(ref, current, *, _inspector=False):
        assert _inspector is True
        if ref != rolling._ref(path) or current != runtime:
            raise ValueError("synthetic current runtime changed")
        return load(path), {relative: (Path(runtime["runtime_source_root"]) / relative).read_bytes()
                            for relative in parallel.CONTROL_FILES}
    monkeypatch.setattr(dispatch, "reopen_runtime", runtime_boundary)
    return SimpleNamespace(case=c, mode=mode, spec=spec, canonical=reference, canary=canary,
        facts=facts, manifest=manifest, qualifier=qualifier, sidecar=sidecar_path,
        amendment=amendment_path, calls=calls, output=c["new_study"] / "selected-capsule.json")


def capsule(c):
    return parallel.publish_schedule(c.spec, c.case["runtime"], c.qualifier, c.canonical,
        c.canonical, c.output, reason="prospective selected parallel HOST contract")


def scheduled(c, reference):
    path = c.case["new_study"] / "selected-parallel-plan.json"
    rolling.publish_plan(c.case["new_study"], c.case["new_enrollment"], c.qualifier, path,
        readiness={c.mode: c.canary}, scheduling=reference, static_capture_amendment=c.amendment,
        application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY)
    return replace(c.spec, plan_receipt=path)


def test_each_mode_public_capsule_plan_intents_and_failed_only_successor(setting, monkeypatch):
    c = setting
    before = {path: path.read_bytes() for path in (c.case["new_enrollment"], c.case["progress"],
        c.case["second"]["input"], c.case["second"]["raw"] / "native/run.json", c.spec.plan_receipt)}
    reference = capsule(c)
    value = dispatch.validate_schedule(reference, runtime=c.case["runtime"])
    assert value["data_role"] == selected.ROLE and value["schema_version"] == 2
    assert value["membership"]["classes"][0]["class_index"] == 2
    spec = scheduled(c, reference)
    sites, payload = rolling.verify_capture_plan(spec)
    workers = [row for row in payload["lanes"] if row["mode"] == c.mode][:2]
    assert len(payload["lanes"]) == 80 and payload["planned_trace_count"] == 320
    assert len({row["campaign_name"] for row in workers}) == 2
    assert all(row["generation"] == 1 and row["visits_per_workload"] == 4 for row in workers)
    roots = dispatch.mount_roots(reference)
    files, trees = parallel.input_dependencies(spec.cohort, spec.workload_root, payload["sites"])
    assert all(any(path.is_relative_to(root) for root in roots) for path in files | trees)
    assert c.case["raw"] not in trees  # unrelated seed class raw GET
    proof = {"plan_payload": payload, "bindings": payload["bindings"],
        "runtime_source": c.facts["authority_source"], "client_sha256": c.facts["client_sha256"],
        "base_launcher_sha256": rolling._ref(spec.base_launcher)["sha256"],
        "host_launcher_sha256": rolling._ref(spec.host_launcher)["sha256"],
        "traffic_hashes": traffic.expected(payload.get(traffic.FIELD))}
    monkeypatch.setattr(lanes, "_validate_image_proof", lambda *args, **kwargs: sites)
    evidence = c.case["new_study"] / "worker-evidence"
    evidence.mkdir()
    checked = {"proof": proof, "execution": {"started_at": datetime.now(UTC).isoformat()}}
    intents = [lanes.prepare_lane_intent(spec, evidence, row["campaign_name"], checked) for row in workers]
    assert len(set(intents)) == 2 and not any((spec.execution_root / "results" / row["campaign_name"]).exists() for row in workers)
    peer = spec.campaign_dir / (workers[1]["campaign_name"] + ".yml")
    peer_bytes = peer.read_bytes()
    successor = c.case["new_study"] / "failed-only-generation-two.json"
    rolling.publish_successor(spec, workers[0]["campaign_name"], 2, successor)
    _, recovered = rolling.verify_capture_plan(replace(spec, plan_receipt=successor))
    assert len(recovered["lanes"]) == 1 and recovered["lanes"][0]["generation"] == 2
    assert recovered["lanes"][0]["block"] == workers[0]["block"]
    assert recovered["scheduling"] == reference
    assert peer.read_bytes() == peer_bytes and all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize("setting", ["tamaraw"], indirect=True)
def test_selected_operation_scope_fences_exact_inputs_without_output_parent(setting):
    c = setting
    ref = capsule(c)
    value = load(c.output)
    context = operation.OperationFacts()
    with context.scope():
        context.bind_schedule(value)
        dispatch.validate_schedule(ref, _context=context)
        (c.case["new_study"] / "legitimate-next-operation.json").write_bytes(b"{}\n")
        context.check()
        raw = c.case["second"]["raw"] / "native/run.json"
        raw.write_bytes(raw.read_bytes() + b"\n")
        with pytest.raises(ValueError, match="bytes or mode|tree bytes"):
            context.check()


@pytest.mark.parametrize("setting", ["tamaraw"], indirect=True)
@pytest.mark.parametrize("mutation", ["membership", "graph", "get-raw", "qualification-source", "qualification-schema", "canary-graph", "control"])
def test_selected_authority_changes_refuse_before_capsule(setting, mutation):
    c = setting
    if mutation == "membership":
        value = load(c.case["new_enrollment"])
        value["payload"]["first_class_index"] += 1
        write(c.case["new_enrollment"], value)
    elif mutation == "graph":
        value = load(c.manifest); value["resources"].pop(); write(c.manifest, value)
    elif mutation == "get-raw":
        raw = c.case["second"]["raw"] / "native/run.json"; raw.write_bytes(raw.read_bytes() + b"\n")
    elif mutation.startswith("qualification"):
        value = load(c.sidecar)
        if mutation.endswith("source"): value["qualification_source"]["lab_commit"] = "f" * 40
        else: value["schema_version"] = 2
        write(c.sidecar, value)
    elif mutation == "canary-graph": c.facts["full_graph"]["resource_count"] -= 1
    else:
        path = c.spec.runtime_source_root / parallel.CONTROL_FILES[-1]
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises((ValueError, OSError, AssertionError)):
        capsule(c)
    assert not c.output.exists()


@pytest.mark.parametrize("setting", ["tamaraw"], indirect=True)
def test_selected_capsule_cannot_import_old_static_mode_or_delivery_witness(setting):
    c = setting
    reference = capsule(c)
    original = c.output.read_bytes()
    for key, changed in (("mode", "front"), ("scientific_credit", True), ("schema_version", True),
        ("data_role", "supplied-static-preparation-v1"), ("application_body_identity_policy", None),
        ("qualification_delivery_compatibility", c.canonical)):
        value = json.loads(original); value[key] = changed; write(c.output, value)
        with pytest.raises(ValueError): dispatch.validate_schedule(rolling._ref(c.output))
    c.output.write_bytes(original)
    with pytest.raises(ValueError, match="same-mode"):
        rolling.publish_plan(c.case["new_study"], c.case["new_enrollment"], c.qualifier,
            c.case["new_study"] / "mixed-settings.json", scheduling=reference,
            readiness={"tamaraw": c.canary, "undefended": c.canary},
            application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY)


def test_public_selected_scheduling_parser_and_flat_shell_selector():
    from tools.rapid_rolling_capture import _parser
    args = _parser().parse_args(["selected-scheduling", *sum((["--" + name, "/tmp/" + name]
        for name in ("spec", "runtime-spec", "qualification-spec", "original-canonical", "current-canonical", "output")), []), "--reason", "prospective typed setting"])
    assert args.command == "selected-scheduling"
    shell = (REPOSITORY / "qcsd-lab").read_text()
    assert shell.count('"${rapid_scheduling_kind}" == "' + parallel.CAPSULE_TYPE + '"') == 1


@pytest.mark.parametrize("setting", ["tamaraw"], indirect=True)
def test_actual_release_fence_binds_selected_raw_and_allows_next_output(setting, monkeypatch):
    """Real typed release reducer; installed/canary physics remain synthetic."""
    from qcsd_lab import rapid_formal_parallel as formal
    from qcsd_lab import rapid_parallel_capture as shared
    from qcsd_lab import verification
    c = setting
    canonical_path = rolling._open_ref(c.canonical)
    inventory = readiness._inventory(c.spec.runtime_source_root)
    write(canonical_path.parent / "source-inventory.json", inventory)
    export = canonical_path.parent / "image-context/source"
    shutil.copytree(c.spec.runtime_source_root, export)
    canonical = load(canonical_path)
    canonical.update(actual_operation_completions={},
        source_inventory_sha256=rolling._ref(canonical_path.parent / "source-inventory.json")["sha256"])
    write(canonical_path, canonical)
    c.canonical = rolling._ref(canonical_path)
    canary_source = c.case["new_study"] / "synthetic-canary-source"
    canary_execution = c.case["new_study"] / "synthetic-canary-execution"
    shutil.copytree(c.spec.runtime_source_root, canary_source)
    shutil.copytree(c.spec.runtime_source_root, canary_execution)
    write(c.case["new_study"] / "source-inventory.json", inventory)
    result = canary_execution / "results/retained-canary"
    result.mkdir(parents=True)
    observed = result / "run.json"
    write(observed, {"synthetic_current_h3_capture_boundary": True})
    index = result / "evidence.sha256"
    index.write_bytes((rolling._ref(observed)["sha256"] + "  run.json\n").encode())
    deep = c.case["new_study"] / "synthetic-deep.json"
    write(deep, {"root": "/lab/results/retained-canary", "evidence_index_sha256": rolling._ref(index)["sha256"]})
    plan_path = rolling._open_ref(c.canary["plan"])
    write(plan_path, {"clean_runtime_root": str(canary_source), "execution_root": str(canary_execution),
        "canonical_runtime": {"source_inventory_sha256": rolling._ref(c.case["new_study"] / "source-inventory.json")["sha256"]}})
    c.canary.clear(); c.canary.update(plan=rolling._ref(plan_path), deep_receipt=rolling._ref(deep))
    # Update the synthetic serial writer's retained canary ref, never a real
    # receipt. All actual selected graph/membership inputs remain unchanged.
    serial = load(c.spec.plan_receipt)
    serial["payload"]["readiness"] = {c.mode: c.canary}
    write(c.spec.plan_receipt, receipts._bind(lanes.PLAN_TYPE, serial["payload"]))
    ref = capsule(c)
    spec = scheduled(c, ref)
    sites, payload = rolling.verify_capture_plan(spec)
    rows = [row for row in payload["lanes"] if row["mode"] == c.mode][:2]
    evidence = c.case["new_study"] / "release-evidence"
    evidence.mkdir()
    worker_facts = []
    for row in rows:
        lane = lanes._lane({"plan_payload": payload}, row["campaign_name"])
        directory = evidence / row["campaign_name"]
        directory.mkdir()
        for name in ("intent.json", "lineage.json", "dns.json"):
            write(directory / name, {"synthetic_prevalidated_intent_boundary": name})
        worker_facts.append((spec, evidence, directory / "intent.json", {}, {}, lane, sites))
    authority = c.case["new_study"] / "release-authority.json"
    value = {"evidence_root": str(evidence), "scientific_credit": False}
    write(authority, value)
    monkeypatch.setattr(verification, "authoritative_files", lambda root: {"run.json": observed})
    monkeypatch.setattr(verification, "_read_checksums", lambda *args: {"run.json": rolling._ref(observed)["sha256"]})
    fence = formal._release_fence(authority, value, worker_facts, {"input_files": []})
    assert str(c.case["second"]["raw"] / "native/run.json") in fence["files"]
    assert str(c.case["new_enrollment"]) in fence["files"]
    assert str(c.case["raw"]) not in fence["trees"]
    (spec.execution_root / "results/legitimate-worker-output").mkdir(parents=True)
    assert formal._release_fence(authority, value, worker_facts, {"input_files": []}) == fence
    observed.write_bytes(observed.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="changed"):
        formal._check_release_fence(fence, authority, value, worker_facts, {"input_files": []})


@pytest.mark.parametrize("setting", ["tamaraw"], indirect=True)
def test_qualification_enforced_layout_is_mounted_and_arbitrary_layout_refuses(setting, tmp_path):
    c = setting
    q = load(c.qualifier)
    row = q["qualification_sets"][0]
    declared = tmp_path / "declared-layout"
    declared.mkdir()
    execution = declared / "execution"
    shutil.copytree(c.spec.execution_root, execution)
    workloads = declared / "workloads"
    shutil.copytree(c.spec.workload_root, workloads)
    sidecars = declared / "chaff-response-qualification-store/sets" / row["qualification_set"]
    shutil.copytree(row["sidecar_root"], sidecars)
    named = sidecars / "_qualification-set.json"
    row.update(manifest=str(named), sidecar_root=str(sidecars))
    write(c.qualifier, q)
    # The protected CaptureSpec permits a registered campaign root equal to
    # its execution root. Its enforced response store is then a sibling;
    # this closes the actual dependency without bypassing _check_spec.
    c.case["runtime"].update(execution_root=str(execution), campaign_dir=str(execution),
        workload_root=str(workloads), host_launcher=str(execution / "qcsd-lab"))
    serial = c.case["new_study"] / "declared-layout-serial.json"
    rolling.publish_plan(c.case["new_study"], c.case["new_enrollment"], c.qualifier, serial,
        readiness={c.mode: c.canary}, runtime_inputs=c.case["runtime"],
        application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY)
    c.spec = replace(c.spec, plan_receipt=serial, execution_root=execution,
        campaign_dir=execution, workload_root=workloads, host_launcher=execution / "qcsd-lab")
    reference = capsule(c)
    roots = dispatch.mount_roots(reference)
    assert any(named.is_relative_to(root) for root in roots)
    assert any(sidecars.is_relative_to(root) for root in roots)
    assert any(sidecars.parent.is_relative_to(root) or sidecars == root for root in roots)
    raw = sidecars / c.manifest.name
    raw.write_bytes(raw.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="changed"):
        dispatch.mount_roots(reference)
    arbitrary = declared / "arbitrary-sidecars"
    shutil.copytree(sidecars, arbitrary)
    row.update(sidecar_root=str(arbitrary), manifest=str(arbitrary / "_qualification-set.json"))
    write(c.qualifier, q)
    with pytest.raises(ValueError, match="actual installed response-set layout"):
        capsule(c)
