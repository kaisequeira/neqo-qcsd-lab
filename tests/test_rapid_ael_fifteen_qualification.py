"""HOST controls: Native/process/current-image labels are explicit fixtures.

The original receipt reducer, wire identity, packet evidence and Source-file
checks execute unchanged. No live response, capture or scientific credit.
"""
from copy import deepcopy
import ast
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_ael_fifteen_qualification as ael
from qcsd_lab import chaff_qualification as original
from qcsd_lab.util import sha256_file
from tests.test_class_mode_flight_control import recipe


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    workload = root / "config/workloads/cloudflare-quiche-r3.json"
    value = json.loads(workload.read_bytes())
    for resource in value["resources"]:
        for header in resource["headers"]:
            if header[0] == "accept-encoding":
                header[1] = "identity"
    path = tmp_path / workload.name
    path.write_text(json.dumps(value))
    # Reuse only four unchanged pure receipt builders. Importing the historical
    # whole test module would eagerly open an unrelated private prefix archive.
    tree = ast.parse((root / "tests/test_chaff_qualification.py").read_bytes())
    names = {"_response", "_packet_log", "_statistics", "_response_receipt"}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(nodes) == len(names)
    namespace = {"WORKLOAD": path, "load_json": lambda p: json.loads(p.read_bytes()),
        "qualification": original, "sha256_bytes": lambda raw: hashlib.sha256(raw).hexdigest()}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "pure_original_receipt_fixtures", "exec"), namespace)
    source = {"image_digest": "sha256:" + "a"*64, "lab_commit": "b"*40,
        "lab_dirty": False, "lab_patch_sha256": original.EMPTY_SHA256,
        "neqo_commit": "c"*40, "neqo_pinned_commit": "c"*40,
        "neqo_dirty": False, "neqo_patch_sha256": original.EMPTY_SHA256}
    native = {"neqo_base_commit": "d"*40, "published_qcsd_commit": "e"*40, "migration_commit": "c"*40}
    implementation = original.implementation_receipt()
    implementation["source"] = {**source, "image_digest": None}
    implementation["sha256"] = original._implementation_aggregate(implementation)
    headers = original.project_compact_headers(value["resources"][0])
    receipts = [namespace["_response_receipt"](run_index=index,
        application_sha256=sha256_file(path), url=value["resources"][0]["url"],
        headers=headers, source=native, parallel_requests=5) for index in range(3)]
    runs = [original._response_run_record(index, row) for index, row in enumerate(receipts)]
    sidecar = {"schema_version": 1, "artifact_type": original.RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE,
        "qualification_scope": "response-only", "workload_id": "cloudflare-quiche-r3",
        "base_manifest": {"path": path.name, "sha256": sha256_file(path)},
        "selection_policy": original.SELECTION_POLICY, "application_resource_id": 0,
        "selected_chaff_resource_id": 0, "qualified_parallel_chaff_streams": 5,
        "header_projection": list(original.HEADER_PROJECTION), "method": "GET",
        "qualification_policy": {"qualification_scope": "response-only", "response_runs": 3,
            "parallel_response_requests": 5, "qualified_parallel_chaff_streams": 5,
            "profile": "research-1200", "response_defense": "none", "seed": 0,
            "udp_payload_ceiling": 1200, "max_response_bytes": 1048576, "separate_chaff_namespace": True},
        "qualification_source": source, "qualification_image_digest": source["image_digest"],
        "neqo_provenance": original._stable_neqo_provenance(receipts), "implementation_receipt": implementation,
        "resource": {"resource_id": 0, "url": value["resources"][0]["url"], "headers": headers,
            "request_stream_bytes": 163, "expected_response": namespace["_response"](), "response_runs": runs,
            "response_qualification_sha256": original.qualification_digest("qcsd-chaff-response-qualification-v2", runs)}}
    return path, value, sidecar


def test_original_full_legacy_reducer_accepts_fifteen_gzip_wire_completions(prepared):
    path, manifest, sidecar = prepared
    before = deepcopy(manifest)
    checked = ael.validate_sidecar(sidecar, path, "cloudflare-quiche-r3", require_current=False)
    assert checked.manifest["schema_version"] == 3
    assert checked.manifest["resources"][0]["chaff_qualification"]["expected_response"]["content_encoding"] == "gzip"
    runs = sidecar["resource"]["response_runs"]
    assert len(runs) == 3 and all(len(row["receipt"]["requests"]) == 5 for row in runs)
    assert json.loads(path.read_bytes()) == before


def test_named_schema_one_loads_schema_three_through_current_capture_facades(prepared, tmp_path):
    from qcsd_lab import qualification_control_authority as facade
    from qcsd_lab import capture_session
    path, _, sidecar = prepared
    sidecars, store = tmp_path / "sidecars", tmp_path / "store"
    sidecars.mkdir(); store.mkdir()
    (sidecars / path.name).write_text(json.dumps(sidecar))
    named = facade.publish_named_qualification_set(["cloudflare-quiche-r3"],
        qualification_set="prospective-ael", qualification_scope="response-only",
        workload_root=path.parent, sidecar_root=sidecars, publication_root=store,
        qualification_sidecar_schema_version=1, require_current_implementation=False,
        body_policy="complete-current-application-delivery-v1")
    value = json.loads(named.manifest_path.read_bytes())
    from qcsd_lab import response_budget_qualification as budget
    budget.validate_named_qualification_set_manifest(value, workload_root=path.parent,
        sidecar_root=named.path, expected_qualification_scope="response-only",
        expected_workload_ids=["cloudflare-quiche-r3"], require_current_implementation=False)
    loaded = facade.load_response_qualified_chaff(named.path / path.name,
        workload_id="cloudflare-quiche-r3", base_manifest_path=path,
        expected_sidecar_schema_version=1, require_current_implementation=False,
        body_policy="complete-current-application-delivery-v1")
    assert value["qualification_sidecar_schema_version"] == 1
    assert loaded.manifest["schema_version"] == 3
    resource = loaded.manifest["resources"][0]
    expected = resource["chaff_qualification"]["expected_response"]
    runtime_manifest = tmp_path / "capture-chaff.json"
    runtime_manifest.write_text(json.dumps(loaded.manifest))
    receipt = {"resource_id": resource["id"], "request_id": 0, "url": resource["url"],
        "request_headers": resource["headers"], "request_stream_bytes": 163,
        "expected_request_stream_bytes": 163,
        "response_headers": [[":status", str(expected["status"])], ["content-encoding", expected["content_encoding"]]],
        "status": expected["status"],
        "content_encoding": expected["content_encoding"], "bytes": expected["body_bytes"],
        "body_sha256": expected["body_sha256"], "complete": True, "status_match": True,
        "content_encoding_match": True, "body_bytes_match": True, "body_sha256_match": True,
        "identity_verified": True, "outcome": "succeeded"}
    run = {"chaff_responses": [receipt], "defense_diagnostics": {}}
    capture_session._validate_chaff_response_receipts(run, runtime_manifest, "tamaraw")
    receipt["content_encoding"] = "identity"
    with pytest.raises(ValueError):
        capture_session._validate_chaff_response_receipts(run, runtime_manifest, "tamaraw")


@pytest.mark.parametrize("mutation", ["falsepassed", "bodysha", "wirebytes", "status", "packet", "extraheaders", "primitive"])
def test_original_reducer_refuses_invalid_native_or_wire_proofs(prepared, mutation):
    path, _, sidecar = prepared
    receipt = sidecar["resource"]["response_runs"][0]["receipt"]
    if mutation == "falsepassed":
        receipt["passed"] = False
    elif mutation == "bodysha":
        receipt["requests"][0]["body_sha256"] = "f"*64
    elif mutation == "wirebytes":
        receipt["requests"][0]["body_bytes"] += 1
    elif mutation == "status":
        receipt["requests"][0]["status"] = 201
    elif mutation == "packet":
        receipt["packet_observations"][0]["udp_payload_bytes"] = 65536
    elif mutation == "extraheaders":
        sidecar["resource"]["headers"].append(["x-new", "unqualified"])
    else:
        sidecar["schema_version"] = 2
    # Authenticate the changed object to reach its semantic reducer, not just a
    # stale outer digest. The negative is still deliberately synthetic.
    if mutation not in {"extraheaders", "primitive"}:
        row = sidecar["resource"]["response_runs"][0]
        row["receipt_object_sha256"] = original.qualification_digest(
            "qcsd-chaff-response-receipt-object-v2", [receipt])
        sidecar["resource"]["response_qualification_sha256"] = original.qualification_digest(
            "qcsd-chaff-response-qualification-v2", sidecar["resource"]["response_runs"])
    with pytest.raises(ValueError):
        ael.validate_sidecar(sidecar, path, "cloudflare-quiche-r3", require_current=False)


@pytest.mark.parametrize("mutation", ["encoding", "duplicate", "uppercase", "overcap"])
def test_selection_refuses_changed_request_projection_and_wire_cap(prepared, mutation):
    _, manifest, _ = prepared
    root = manifest["resources"][0]
    if mutation == "encoding":
        root["headers"][1][1] = "gzip"
    elif mutation == "duplicate":
        root["headers"].append(["accept-encoding", "identity"])
    elif mutation == "uppercase":
        root["headers"][1][0] = "Accept-Encoding"
    else:
        manifest["preparation"]["expected_responses"][0]["bytes"] = ael.MAX_WIRE_BYTES + 1
    with pytest.raises(ValueError):
        ael.selection(manifest, "cloudflare-quiche-r3")


def test_rehashed_stale_implementation_is_not_current(prepared, monkeypatch):
    path, _, sidecar = prepared
    current = deepcopy(sidecar["implementation_receipt"])
    monkeypatch.setattr(original, "implementation_receipt", lambda **kwargs: current)
    monkeypatch.setattr(original, "source_metadata", lambda: sidecar["qualification_source"])
    ael.validate_sidecar(sidecar, path, "cloudflare-quiche-r3")
    implementation = sidecar["implementation_receipt"]
    relative = next(iter(implementation["source_files"]))
    implementation["source_files"][relative] = "e"*64
    if relative in implementation["installed_modules"]:
        implementation["installed_modules"][relative]["sha256"] = "e"*64
    implementation["sha256"] = original._implementation_aggregate(implementation)
    with pytest.raises(ValueError, match="source files have changed"):
        ael.validate_sidecar(sidecar, path, "cloudflare-quiche-r3")


def test_public_qualification_dispatch_keeps_full_group_and_legacy_named_readers(tmp_path, recipe, monkeypatch):
    from qcsd_lab import qualification_control_authority as publisher
    output, execution = tmp_path / "out", tmp_path / "execution"
    output.mkdir()
    plan = {ael.FIELD: ael.POLICY, "campaigns": [{"mode": "tamaraw"}],
        "selected_classes": [{"workload_id": "site-one"}, {"workload_id": "site-two"}],
        "capture_limits": {"max_response_bytes": 16777216, "timeout_seconds": 120},
        "reuse": None, "group_qualification_set": "fixture-group", "qualification_set": "fixture-single",
        "workload_id": "site-one", "workload_sha256": "a"*64}
    monkeypatch.setattr(recipe, "checked_plan", lambda *args, **kwargs: (plan, output, execution))
    calls, groups = [], []
    def qualify(identifier, **kwargs):
        calls.append((identifier, kwargs))
        recipe.create(kwargs["qualification_root"] / (identifier + ".json"), b"{}\n")
    def publish(ids, **kwargs):
        groups.append((ids, kwargs))
        return SimpleNamespace(manifest_sha256="b"*64, qualification_set=kwargs["qualification_set"])
    monkeypatch.setattr(ael, "qualify", qualify)
    published_prerequisites = []
    monkeypatch.setattr(ael, "publish_prerequisite", lambda named, **kwargs: published_prerequisites.append((named, kwargs)))
    monkeypatch.setattr(publisher, "publish_named_qualification_set", publish)
    recipe.image_action(SimpleNamespace(command="qualify-image", plan_sha256="c"*64))
    assert [identifier for identifier, _ in calls] == ["site-one", "site-two"]
    assert all(kwargs == {"qualification_root": execution / "config/static-response-sidecars/fixture-group",
        "workload_root": execution / "config/workloads", "timeout_seconds": 120} for _, kwargs in calls)
    assert [ids for ids, _ in groups] == [["site-one", "site-two"], ["site-one"]]
    assert all(kwargs["qualification_sidecar_schema_version"] == 1 for _, kwargs in groups)
    assert len(published_prerequisites) == 2
    value = json.loads((output / "qualification-complete.json").read_bytes())
    assert value["response_qualification_prerequisite"] == ael.record()
    assert value["formal_accepted_trace_count"] == 0 and not value["scientific_credit"]


@pytest.mark.parametrize("scope,mode", [({ael.FIELD: "unsupported"}, "tamaraw"),
    ({ael.FIELD: ael.POLICY}, "undefended"),
    ({ael.FIELD: ael.POLICY, "reuse": {}}, "tamaraw"),
    ({ael.FIELD: ael.POLICY, "qualification_delivery_compatibility": {}}, "front"),
    ({ael.FIELD: ael.POLICY, "ordinary_renewal": None}, "cs-buflo")])
def test_explicit_policy_refuses_unsupported_or_historical_intake(scope, mode):
    with pytest.raises(ValueError):
        ael.validate_scope(scope, mode)


def test_wrapper_uses_original_api_and_closes_manifest_bytes(prepared, tmp_path, monkeypatch):
    path, _, sidecar = prepared
    destination = tmp_path / "sidecar.json"
    calls = []
    def qualify(identifier, **kwargs):
        calls.append((identifier, kwargs))
        destination.write_text(json.dumps(sidecar))
        return SimpleNamespace(path=destination)
    monkeypatch.setattr(original, "qualify_response_chaff", qualify)
    monkeypatch.setattr(ael, "validate_sidecar", lambda *args, **kwargs: None)
    result = ael.qualify("cloudflare-quiche-r3", qualification_root=tmp_path,
        workload_root=path.parent, timeout_seconds=120)
    assert result.path == destination
    assert calls[0][1] == {"qualification_root": tmp_path, "workload_root": path.parent,
        "timeout_seconds": 120, "interval_seconds": 30}
    def mutate(*args, **kwargs):
        path.write_bytes(path.read_bytes() + b" ")
    monkeypatch.setattr(ael, "validate_sidecar", mutate)
    with pytest.raises(ValueError, match="dependency bytes or mode changed"):
        ael.qualify("cloudflare-quiche-r3", qualification_root=tmp_path,
            workload_root=path.parent, timeout_seconds=120)


def test_public_stage_flag_is_explicit_and_default_absent(recipe, monkeypatch):
    import sys
    required = ["stage", "--runtime-build-root", "/r", "--clean-runtime-root", "/s",
        "--canonical-sha256", "a"*64, "--python", "/python", "--enrollment", "/e",
        "--study-root", "/study", "--output", "/new", "--expected-lab-commit", "b"*40,
        "--expected-native-commit", "c"*40, "--name", "fresh", "--campaign-seed", "1", "--mode", "tamaraw"]
    calls = []
    monkeypatch.setattr(recipe, "stage", lambda args: calls.append(args) or {})
    for extra in ([], ["--response-qualification-policy", ael.POLICY]):
        monkeypatch.setattr(sys, "argv", ["flight", *required, *extra])
        recipe.main()
    assert calls[0].response_qualification_policy is None
    assert calls[1].response_qualification_policy == ael.POLICY


def test_actual_class_eight_preserves_thirteen_nodes_and_exact_wire_candidate():
    path = Path(os.environ["QCSD_AEL_CLASS_EIGHT_MANIFEST"])
    assert sha256_file(path) == "07bb57e237b0f69af4191891dfd4ccf0c9068d4e684c8abed834be648d4ebd46"
    value = json.loads(path.read_bytes())
    before = deepcopy(value)
    selected = ael.selection(value, path.stem)
    assert len(value["resources"]) == 13 and value == before
    assert selected["resource_id"] == 0 and selected["prepared_response"]["bytes"] == 885228
    assert selected["headers"] == original.project_identity_chaff_headers(value["resources"][0])


@pytest.fixture
def named_current(prepared, tmp_path, monkeypatch):
    path, manifest, sidecar = prepared
    # Executing-image/client labels are synthetic; raw Source and full original
    # receipt reduction remain real. This never represents a live Native pass.
    current = deepcopy(sidecar["implementation_receipt"])
    monkeypatch.setattr(original, "source_metadata", lambda: sidecar["qualification_source"])
    monkeypatch.setattr(original, "implementation_receipt", lambda **kwargs: current)
    sidecars = tmp_path / "native-sidecars"; sidecars.mkdir()
    (sidecars / path.name).write_text(json.dumps(sidecar))
    config = tmp_path / "config"
    store = config / "chaff-response-qualification-store/sets"; store.mkdir(parents=True)
    named = original.publish_named_qualification_set(["cloudflare-quiche-r3"],
        qualification_set="explicit-ael", qualification_scope="response-only",
        workload_root=path.parent, sidecar_root=sidecars, publication_root=store,
        qualification_sidecar_schema_version=1)
    return path, manifest, sidecar, config, named


def test_real_fresh_and_frozen_orchestrator_paths_require_authenticated_marker(named_current, tmp_path):
    import shutil
    from qcsd_lab import orchestrator
    path, manifest, _, config, named = named_current
    raw = path.read_bytes()
    workload = orchestrator.Workload("cloudflare-quiche-r3", 1, path, raw, sha256_file(path), manifest, 1, 1)
    kwargs = {"qualification_scope": "response-only", "qualification_set": "explicit-ael",
        "config_root": config, "workload_root": path.parent,
        "body_policy": "complete-current-application-delivery-v1"}
    with pytest.raises(ValueError, match="schema version is unexpected"):
        orchestrator._load_qualified_chaff_inputs(config / "campaigns/fresh.yml", (workload,), frozen_inputs=None, **kwargs)
    old_native = named.manifest_path.read_bytes()
    ael.publish_prerequisite(named, workload_root=path.parent)
    [qualified] = orchestrator._load_qualified_chaff_inputs(config / "campaigns/fresh.yml", (workload,), frozen_inputs=None, **kwargs)
    assert qualified.chaff_manifest_data["schema_version"] == 3
    assert named.manifest_path.read_bytes() == old_native
    frozen = tmp_path / "frozen"
    quals, chaffs = frozen / "chaff-qualifications", frozen / "chaff-manifests"
    quals.mkdir(parents=True); chaffs.mkdir()
    shutil.copy2(named.manifest_path, quals / named.manifest_path.name)
    shutil.copy2(named.path / path.name, quals / path.name)
    ael.freeze_prerequisite(named.manifest_path, quals, workload_root=path.parent)
    (chaffs / path.name).write_bytes(original.canonical_bytes(qualified.chaff_manifest_data))
    [reopened] = orchestrator._load_qualified_chaff_inputs(config / "campaigns/fresh.yml", (workload,),
        frozen_inputs=frozen, **kwargs)
    assert reopened.chaff_manifest_sha256 == qualified.chaff_manifest_sha256
    assert (quals / ael.PREREQUISITE_FILE).read_bytes() == (named.path / ael.PREREQUISITE_FILE).read_bytes()


@pytest.mark.parametrize("mutation", ["schema2", "policy", "source", "namedsha", "falsepassed", "header", "overcap"])
def test_marker_cannot_transplant_or_waive_original_native_contract(named_current, mutation):
    path, _, _, _, named = named_current
    ael.publish_prerequisite(named, workload_root=path.parent)
    marker_path = named.path / ael.PREREQUISITE_FILE
    marker = json.loads(marker_path.read_bytes())
    if mutation == "policy":
        marker["policy"] = "other"
    elif mutation == "source":
        marker["producer_sources"]["policy"]["sha256"] = "e"*64
    elif mutation == "namedsha":
        marker["named_manifest_sha256"] = "f"*64
    elif mutation == "schema2":
        value = json.loads(named.manifest_path.read_bytes())
        value["qualification_sidecar_schema_version"] = 2
        named.manifest_path.write_text(json.dumps(value))
        marker["named_manifest_sha256"] = sha256_file(named.manifest_path)
    else:
        native_path = named.path / path.name
        sidecar = json.loads(native_path.read_bytes())
        if mutation == "falsepassed":
            sidecar["resource"]["response_runs"][0]["receipt"]["passed"] = False
        elif mutation == "header":
            sidecar["resource"]["headers"].append(["x-new", "unqualified"])
        else:
            sidecar["qualification_policy"]["max_response_bytes"] = ael.MAX_WIRE_BYTES + 1
        native_path.write_text(json.dumps(sidecar))
    marker_path.write_text(json.dumps(marker))
    with pytest.raises(ValueError):
        ael.selected_schema(named.manifest_path, workload_root=path.parent, sidecar_root=named.path,
            historical_schema=2, require_current=True)
