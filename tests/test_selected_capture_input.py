"""HOST raw-contract tests; original-audit process boundary is synthetic.

Native bootstrap/full GET, resource/header/DAG/Source/runtime reconstruction
uses the ordinary strict fixture validators. No installed/image/GET credit.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys

import pytest

from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_operation_facts as operation
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import supplied_static_preparation as preparation
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import application_response_policy as responses
from qcsd_lab import manifest as manifests
from qcsd_lab import static_evidence_transport as transport
from qcsd_lab import rapid_lane_evidence as lanes
from tests.test_supplied_static_get import actual_contract_fixture, load, write, reseal_outputs
from tests.test_supplied_static_preparation import fixed_graph, POLICIES, seal


REPOSITORY = Path(__file__).resolve().parents[1]


def runtime(tmp_path):
    """Synthetic HOST runtime; the Native text fixture is an exact c24 Git blob."""
    data, source = tmp_path / "capture-data", tmp_path / "source"
    execution, study = data / "execution", data / "study"
    campaigns, workloads = execution / "config/campaigns", execution / "config/workloads"
    for path in (data, source, execution, study, campaigns, workloads):
        path.mkdir(parents=True, exist_ok=True)
    (source / "qcsd-lab").write_bytes(b"synthetic exact launcher\n")
    (execution / "qcsd-lab").write_bytes((source / "qcsd-lab").read_bytes())
    for relative, digest in lanes.TRAFFIC_FILES.values():
        raw = (REPOSITORY / ("tests/fixtures/selected-input-native-c24-research-1200.toml"
            if relative == "neqo-qcsd/neqo-csdef/profiles/research-1200.toml" else relative)).read_bytes()
        assert graph.digest(raw) == digest
        target = execution / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    target = execution / lanes.STUDY_PROFILE_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((REPOSITORY / lanes.STUDY_PROFILE_FILE).read_bytes())
    (source / "client").write_bytes(b"synthetic actual client identity")
    metadata = {"image_digest": None, "lab_commit": "d" * 40,
        "neqo_commit": "5" * 40, "neqo_pinned_commit": "5" * 40,
        "lab_dirty": False, "neqo_dirty": False,
        "lab_patch_sha256": selected.get._EMPTY, "neqo_patch_sha256": selected.get._EMPTY}
    write(source / "source.json", metadata)
    return study, {"data_root": str(tmp_path), "runtime_source_root": str(source),
        "module_root": str(REPOSITORY), "execution_root": str(execution),
        "workload_root": str(workloads), "campaign_dir": str(campaigns),
        "source_manifest": str(source / "source.json"), "client_binary": str(source / "client"),
        "base_launcher": str(source / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "collection_image_digest": "sha256:" + "a" * 64,
        "execution_generation": "selected-test-001"}


def audit_fixture(directory, *, context, terminal, manifest, source, seed):
    directory.mkdir()
    terminal_facts = static.verify_terminal(terminal, context)
    candidate = next(row for row in context.candidates if row["candidate_id"] == terminal_facts["candidate_id"])
    row = {"candidate": candidate, "manifest": rolling._ref(manifest), "terminal": rolling._ref(terminal),
        "context": rolling._ref(context.root / "provenance.json"), "capture_limits": static.context_limits(context),
        "facts": terminal_facts}
    mode = "enrollment" if seed is not None else "static-terminal"
    minute = "00" if seed is not None else "11"
    result = {"audit_mode": mode, "seed": seed, "classes": [row], "scientific_credit": False}
    authority = Path(seed["enrollment"]["path"]) if seed is not None else context.root / "provenance.json"
    command = [sys.executable, "-I", "-B", "-c", selected._LEGACY_PROGRAM, str(source.parent),
        mode, str(authority if seed is not None else context.root), "" if seed is not None else str(terminal)]
    started = {"schema_version": 1, "command": command, "started_at": f"2026-10-04T00:{minute}:30Z",
        "original_source_manifest": selected.reference(source), "original_source": load(source),
        "authority": selected.reference(authority), "terminal": None if seed is not None else selected.reference(terminal)}
    write(directory / "audit-started.json", started)
    write(directory / "audit.stdout.log", result)
    (directory / "audit.stderr.log").write_bytes(b"")
    completed = {"schema_version": 1, "returncode": 0, "elapsed_seconds": 1.0,
        "completed_at": f"2026-10-04T00:{minute}:31Z", "started": selected.reference(directory / "audit-started.json"),
        "stdout": selected.reference(directory / "audit.stdout.log"), "stderr": selected.reference(directory / "audit.stderr.log")}
    write(directory / "audit-completed.json", completed)
    value = {"contract": selected.CONTRACT, "original_source_root": str(source.parent),
        "original_source_manifest": selected.reference(source),
        "legacy_program_sha256": graph.digest(selected._LEGACY_PROGRAM.encode()),
        **{key: selected.reference(directory / name) for key, name in
            (("started", "audit-started.json"), ("completed", "audit-completed.json"),
             ("stdout", "audit.stdout.log"), ("stderr", "audit.stderr.log"))},
        "result": result, "published_at": f"2026-10-04T00:{minute}:32Z", "scientific_credit": False}
    path = directory / "selection-audit.json"
    write(path, receipts._bind(selected.AUDIT_TYPE, value))
    return path


@pytest.fixture
def selected_graph(fixed_graph, tmp_path, monkeypatch):
    raw_root, arguments, context = fixed_graph
    terminal = static.admit(context, 1, raw_root, policies=POLICIES)
    original, manifest = static.prepared_workload(context, terminal)
    study, capture_runtime = runtime(tmp_path)
    rolling.initialize_study(context.root, study, capture_runtime, supplied_static=True)
    enrollment = rolling.enroll(study)
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    seed = {"enrollment": rolling._ref(enrollment), "policy": batch["policy"], "ordinal": batch["ordinal"],
        "last_candidate_position": batch["last_candidate_position"], "classes": classes}
    audit = audit_fixture(tmp_path / "audit", context=context, terminal=terminal, manifest=original,
        source=Path(capture_runtime["source_manifest"]), seed=seed)
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:02:00Z")
    # The separate original subprocess/audit is a synthetic HOST boundary.
    monkeypatch.setattr(selected, "_legacy_source", lambda root, source_manifest: load(Path(source_manifest["path"])))
    path = selected.publish_input(tmp_path / "selected-input.json", audit=audit, candidate_id=classes[0]["candidate_id"])
    output_dir = tmp_path / "selected"
    output_dir.mkdir()
    prepared = selected.prepare_input(path, output_dir / original.name)
    return {"raw": raw_root, "input": path, "prepared": prepared, "original": original, "manifest": manifest,
        "context": context, "terminal": terminal, "audit": audit, "runtime": capture_runtime,
        "seed": seed, "policy": policy, "study": study}


def second_selected(case, tmp_path, monkeypatch, *, domain="second.example", name="second"):
    """A second complete synthetic emitter graph, separately declared/admitted."""
    directory = tmp_path / name
    directory.mkdir()
    raw, arguments = actual_contract_fixture.__wrapped__(directory)
    for path in raw.rglob("*.json"):
        path.write_bytes(path.read_bytes().replace(b"sample.example", domain.encode()))
    second_rows = load(raw / "source-list.json")
    source_bytes = graph.canonical_bytes(second_rows)
    (raw / "source-list.json").write_bytes(source_bytes)
    neutral, binding = graph.import_graph(source_bytes, graph.digest(source_bytes), domain)
    write(raw / "native-input.json", neutral)
    write(raw / "input-binding.json", binding)
    declaration = load(raw / "declaration.json")
    declaration.update(source_sha256=graph.digest(source_bytes), native_input_sha256=graph.digest(graph.canonical_bytes(neutral)),
        input_binding_sha256=graph.digest(graph.canonical_bytes(binding)))
    write(raw / "declaration.json", declaration)
    started = load(raw / "native-started.json")
    started["declaration_sha256"] = graph.digest((raw / "declaration.json").read_bytes())
    write(raw / "native-started.json", started)
    run = load(raw / "native/run.json")
    run["workload_hash_sha256"] = declaration["native_input_sha256"]
    write(raw / "native/run.json", run)
    arguments.update(domain=domain, source_sha256=graph.digest(source_bytes))
    reseal_outputs(raw)
    fixed_graph.__wrapped__((raw, arguments), directory, monkeypatch)
    pending = copy.deepcopy(second_rows[0])
    pending["crUX_domain"] = "pending.example"
    active = copy.deepcopy(second_rows[0])
    active["crUX_domain"] = "second.example"
    source_bytes = graph.canonical_bytes(load(case["raw"] / "source-list.json") + [pending, active])
    (raw / "source-list.json").write_bytes(source_bytes)
    _, binding = graph.import_graph(source_bytes, graph.digest(source_bytes), domain)
    write(raw / "input-binding.json", binding)
    arguments["source_sha256"] = graph.digest(source_bytes)
    appended = directory / "appended-context"
    appended.mkdir()
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:09:00Z")
    static.initialize_context(appended, raw / "source-list.json", source_sha256=arguments["source_sha256"],
        expected_runtime=arguments["expected_runtime"], parent_context=case["context"].root)
    context = static.load_context(appended)
    candidate = next(row for row in context.candidates if row["domain"] == domain)
    def later(value, key=""):
        if isinstance(value, dict): return {key: later(item, key) for key, item in value.items()}
        if isinstance(value, list): return [later(item, key) for item in value]
        if type(value) is int and key.endswith("unix_ns"): return value + 600_000_000_000
        if isinstance(value, str): return value.replace("2026-10-04T00:00:", "2026-10-04T00:10:")
        return value
    for path in raw.rglob("*.json"):
        if path.name != "full-get-proof.json": write(path, later(load(path)))
    declaration = load(raw / "declaration.json")
    declaration.update(context=preparation.reference(appended / "provenance.json"),
        source_sha256=arguments["source_sha256"], input_binding_sha256=graph.digest(graph.canonical_bytes(binding)),
        candidate_queue_position=candidate["position"], candidate_source_position=candidate["source_position"])
    write(raw / "declaration.json", declaration)
    for step in (raw, raw / "bootstrap"):
        started = load(step / "native-started.json")
        started["declaration_sha256"] = graph.digest((raw / "declaration.json").read_bytes())
        write(step / "native-started.json", started)
        reseal_outputs(step)
    seal(raw, **arguments)
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:11:00Z")
    terminal = static.admit(context, candidate["position"], raw, policies=POLICIES)
    original, manifest = static.prepared_workload(context, terminal)
    audit = audit_fixture(directory / "audit", context=context, terminal=terminal, manifest=original,
        source=Path(case["runtime"]["source_manifest"]), seed=None)
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:12:00Z")
    input_path = selected.publish_input(directory / "input.json", audit=audit, candidate_id=candidate["candidate_id"])
    prepared_dir = directory / "selected"
    prepared_dir.mkdir()
    prepared = selected.prepare_input(input_path, prepared_dir / original.name)
    return {"raw": raw, "context": context, "input": input_path, "prepared": prepared, "audit": audit, "candidate": candidate}


@pytest.fixture
def additive_case(selected_graph, tmp_path, monkeypatch):
    case = selected_graph
    progress = tmp_path / "retained-progress.json"
    original = case["seed"]["classes"][0]
    write(progress, {"accepted_formal_slots": [{"candidate_id": original["candidate_id"],
        "class_index": 1, "mode": "undefended", "visit": 0}], "actual_installed_deep_reopened": True,
        "measurement_epochs_preserve_original_source_and_runtime_labels": True, "formal_accepted_trace_count": 1})
    study = tmp_path / "selected-study"
    study.mkdir()
    additive.initialize(study, seed_enrollment=Path(case["seed"]["enrollment"]["path"]),
        runtime=case["runtime"], seed_selection_audit=case["audit"],
        seed_inputs={original["candidate_id"]: selected.reference(case["input"])}, seed_progress=selected.reference(progress))
    second = second_selected(case, tmp_path, monkeypatch)
    candidate_id = second["candidate"]["candidate_id"]
    enrollment = additive.enroll(study, acquisition_root=second["context"].root,
        inputs={candidate_id: selected.reference(second["input"])},
        prepared_workloads={candidate_id: selected.reference(second["prepared"])})
    return {**case, "new_study": study, "new_enrollment": enrollment, "second": second, "progress": progress}


def forbid_history(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("selected trace must not replay acquisition history")
    monkeypatch.setattr(static, "load_context", denied)
    monkeypatch.setattr(selected.whole, "load_context", denied)
    monkeypatch.setattr(rolling, "_context_for_policy", denied)


def qualifier_fixture(case, monkeypatch):
    """Only actual named120/image/canary primitives are synthetic boundaries."""
    from qcsd_lab import rapid_rolling_readiness as readiness
    second = case["second"]
    runtime = case["runtime"]
    workload = Path(runtime["workload_root"]) / second["prepared"].name
    workload.write_bytes(second["prepared"].read_bytes())
    sidecars = Path(runtime["campaign_dir"]).parent / "chaff-response-qualification-store/sets/selected-test"
    sidecars.mkdir(parents=True)
    write(sidecars / "_qualification-set.json", {"synthetic_named120_boundary": True})
    write(sidecars / (workload.stem + ".json"), {
        "qualification_source": {**load(Path(runtime["source_manifest"])), "image_digest": runtime["collection_image_digest"]},
        "qualification_image_digest": runtime["collection_image_digest"],
        "implementation_receipt": {"neqo_qcsd_client": {"sha256": graph.digest(Path(runtime["client_binary"]).read_bytes())}},
        "candidate_attempts": [{"connection_epochs": [{"receipt": {
            "started_unix_ns": selected.get._unix_ns("2026-10-04T00:13:00Z")}}]}]})
    qualifier = case["new_study"] / "qualifier.json"
    write(qualifier, {"schema_version": 1, "qualification_sets": [{"qualification_set": "selected-test",
        "manifest": str(sidecars / "_qualification-set.json"), "sidecar_root": str(sidecars), "prefix_spec_root": None}]})
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", lambda *args, **kwargs: None)
    monkeypatch.setattr(readiness, "validate_canary", lambda *args, **kwargs: {
        "authority_source": {**load(Path(runtime["source_manifest"])), "image_digest": runtime["collection_image_digest"]},
        "client_sha256": graph.digest(Path(runtime["client_binary"]).read_bytes()),
        "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}})
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:14:00Z")
    return qualifier


def test_public_selected_enrollment_plan_parser_and_serial_campaign_retain_full_graph(additive_case, monkeypatch):
    import yaml
    case = additive_case
    qualifier = qualifier_fixture(case, monkeypatch)
    forbid_history(monkeypatch)
    batch, classes = rolling.verify_enrollment(case["new_enrollment"])
    assert [row["class_index"] for row in classes] == [1, 2]
    assert classes[0]["candidate_id"] == case["seed"]["classes"][0]["candidate_id"]
    assert batch["ordinal"] == case["seed"]["ordinal"] + 1
    assert batch["scientific_credit"] is False and batch["unassessed_reservations"] == [{
        "position": 2, "candidate_id": case["second"]["context"].candidates[1]["candidate_id"],
        "assessment": "unassessed-by-this-ledger"}]
    output = case["new_study"] / "plan.json"
    rolling.publish_plan(case["new_study"], case["new_enrollment"], qualifier, output,
        readiness={"tamaraw": {"synthetic_current_canary_boundary": True}})
    spec = rolling.capture_spec(case["new_study"], case["new_enrollment"], qualifier, output)
    spec_path = case["new_study"] / "spec.json"
    write(spec_path, {"schema_version": 1, "artifact_type": "qcsd-rapid-v6-rolling-capture-spec", "inputs": spec.serializable()})
    loaded = lanes.load_capture_spec(spec_path)
    sites, payload = rolling.verify_capture_plan(loaded)
    assert payload["data_role"] == selected.ROLE and payload["planned_trace_count"] == 320
    assert len(payload["lanes"]) == 80
    first = next(row for row in payload["lanes"] if row["mode"] == "tamaraw")
    lane = rolling.plan.Lane(**{key: tuple(item) if key == "workload_ids" else item
        for key, item in first.items() if key != "campaign_sha256"})
    raw = lanes._render_lane_campaign(loaded, lane, sites)
    assert raw == (loaded.campaign_dir / (lane.campaign_name + ".yml")).read_bytes()
    assert yaml.safe_load(raw)["limits"] == case["policy"]["capture_limits"]
    assert load(loaded.workload_root / case["second"]["prepared"].name)["resources"] == load(case["second"]["prepared"])["resources"]
    roots = rolling.enrollment_roots(loaded)
    assert any(case["second"]["raw"].is_relative_to(root) for root in roots)
    # Only the executed image-proof primitive is substituted. The public
    # serial intent writer, rolling readiness, campaign and lineage run here.
    checked = {"proof": {"plan_payload": payload, "bindings": payload["bindings"],
        "runtime_source": {**load(loaded.source_manifest), "image_digest": loaded.collection_image_digest},
        "client_sha256": graph.digest(loaded.client_binary.read_bytes()),
        "base_launcher_sha256": graph.digest(loaded.base_launcher.read_bytes()),
        "host_launcher_sha256": graph.digest(loaded.host_launcher.read_bytes()),
        "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}},
        "execution": {"started_at": "2026-10-04T00:15:00Z"}}
    monkeypatch.setattr(lanes, "_validate_image_proof", lambda *args, **kwargs: sites)
    evidence = case["new_study"] / "serial-evidence"
    evidence.mkdir()
    intent = lanes.prepare_lane_intent(loaded, evidence, lane.campaign_name, checked)
    value = receipts._unpack(intent.read_bytes(), lanes.INTENT_TYPE)
    assert value["campaign_name"] == lane.campaign_name and value["scientific_credit"] is False
    assert not (loaded.execution_root / "results" / lane.campaign_name).exists()


@pytest.mark.parametrize("mode", ["front", "buflo"])
def test_selected_modes_cannot_import_old_fixed_policy_before_new_declaration(additive_case, monkeypatch, mode):
    case = additive_case
    qualifier = qualifier_fixture(case, monkeypatch)
    with pytest.raises(ValueError, match="prospective fixed capture policy"):
        rolling.publish_plan(case["new_study"], case["new_enrollment"], qualifier,
            case["new_study"] / (mode + ".json"), readiness={mode: {"not_accepted": True}})


def test_additive_pending_gaps_cannot_be_fabricated_or_old_classes_reordered(additive_case, monkeypatch):
    case = additive_case
    forbid_history(monkeypatch)
    path = case["new_enrollment"]
    raw = path.read_bytes()
    for change in ("remove-pending", "fake-terminal", "first-class", "selected-id", "seed", "ordinal"):
        value = receipts._unpack(raw, additive.ENROLLMENT_TYPE)
        if change == "remove-pending": value["unassessed_reservations"] = []
        elif change == "fake-terminal": value["unassessed_reservations"][0]["assessment"] = "input-ineligible"
        elif change == "first-class": value["first_class_index"] = 1
        elif change == "selected-id": value["selected_candidate_ids"] = [case["seed"]["classes"][0]["candidate_id"]]
        elif change == "seed": value["seed"] = None
        else: value["ordinal"] += 1
        write(path, receipts._bind(additive.ENROLLMENT_TYPE, value))
        with pytest.raises(ValueError): additive.verify_enrollment(path)
        path.write_bytes(raw)
    membership = additive.membership_inputs(path)
    assert not any(file.is_relative_to(case["raw"]) for file in membership)
    old_run = case["raw"] / "native/run.json"
    old_run.write_bytes(old_run.read_bytes() + b"\n")
    # Unrelated old selected-class raw data is not a prerequisite for class2.
    additive.verify_enrollment(path)
    selected.validate_input(case["second"]["input"])
    with pytest.raises(ValueError): selected.validate_input(case["input"])


def test_earlier_pending_reservation_can_join_later_without_renumbering(additive_case, tmp_path, monkeypatch):
    case = additive_case
    first_raw = case["new_enrollment"].read_bytes()
    _, first_classes, _ = additive.verify_enrollment(case["new_enrollment"])
    pending = second_selected(case, tmp_path, monkeypatch, domain="pending.example", name="later-pending")
    candidate_id = pending["candidate"]["candidate_id"]
    later = additive.enroll(case["new_study"], acquisition_root=pending["context"].root,
        inputs={candidate_id: selected.reference(pending["input"])},
        prepared_workloads={candidate_id: selected.reference(pending["prepared"])})
    forbid_history(monkeypatch)
    batch, classes, _ = additive.verify_enrollment(later)
    assert classes[:2] == first_classes and classes[-1]["class_index"] == 3
    assert [row["position"] for row in batch["decisions"]] == [2]
    assert batch["unassessed_reservations"] == []
    assert case["new_enrollment"].read_bytes() == first_raw
    additive.verify_enrollment(case["new_enrollment"])


def test_seed_sample_identity_preserves_logical_block_and_raw_visit():
    classes = [{"candidate_id": "one", "class_index": 1}]
    old = {"candidate_id": "one", "class_index": 1, "mode": "tamaraw", "visit": 0}
    block4 = {"candidate_id": "one", "class_index": 1, "mode": "tamaraw", "visit": 12,
        "registered_block": 4, "actual_local_visit": 0,
        "campaign_name": "rapid-curated-tranco50-v6-formal-b04-s01-tamaraw-1200"}
    value = {"accepted_formal_slots": [old, block4], "formal_accepted_trace_count": 2,
        "actual_installed_deep_reopened": True, "measurement_epochs_preserve_original_source_and_runtime_labels": True}
    additive._progress(value, classes)
    assert value["accepted_formal_slots"][0] == old
    for change in ("visit", "block", "local", "duplicate"):
        altered = copy.deepcopy(value)
        if change == "visit": altered["accepted_formal_slots"][1]["visit"] = 0
        elif change == "block": altered["accepted_formal_slots"][1]["registered_block"] = True
        elif change == "local": altered["accepted_formal_slots"][1]["actual_local_visit"] = 4
        else: altered["accepted_formal_slots"][1] = old
        with pytest.raises(ValueError): additive._progress(altered, classes)


def test_normal_manifest_and_response_paths_reprove_selected_get_without_history(selected_graph, monkeypatch):
    case = selected_graph
    forbid_history(monkeypatch)
    value, original, proof = selected.validate_input(case["input"])
    manifest = load(case["prepared"])
    manifests.validate_manifest(manifest)
    manifests.validate_research_preparation(manifest, workload_id=case["prepared"].stem)
    responses.validate_primary_document_identity_evidence(manifest)
    responses.validate_application_response_policy_evidence(manifest)
    response_graph = responses.validate_prepared_response_graph(manifest)
    assert original == case["manifest"] and manifest["resources"] == original["resources"]
    assert proof["resource_count"] == 3 and response_graph["resource_ids"] == [0, 1, 2]
    assert value["scientific_credit"] is False and value["formal_accepted_trace_count"] == 0


@pytest.mark.parametrize("change", ["body", "mode", "membership"])
def test_own_complete_get_bytes_modes_membership_reject_after_receipt(selected_graph, change):
    root = selected_graph["raw"]
    if change == "body":
        (root / "native/run.json").write_bytes((root / "native/run.json").read_bytes() + b"\n")
    elif change == "mode":
        (root / "native/run.json").chmod(0o400)
    else:
        (root / "unexpected-later-output").write_bytes(b"mutation")
    with pytest.raises(ValueError, match="tree bytes, modes or membership"):
        selected.validate_input(selected_graph["input"])


@pytest.mark.parametrize("change", ["header", "occurrence", "dependency"])
def test_normal_manifest_refuses_changed_full_graph(selected_graph, change):
    manifest = load(selected_graph["prepared"])
    if change == "header": manifest["resources"][1]["headers"].append(["accept", "changed"])
    elif change == "occurrence": manifest["resources"].pop()
    else: manifest["resources"][2]["depends_on"] = []
    with pytest.raises(ValueError):
        manifests.validate_manifest(manifest)


def test_selected_transport_and_operation_fence_cover_all_actual_reads_without_parent_membership(selected_graph, monkeypatch):
    case = selected_graph
    manifest = load(case["prepared"])
    forbid_history(monkeypatch)
    observed = set()
    old = selected.get._read
    def read(path):
        observed.add(Path(path).absolute())
        return old(path)
    monkeypatch.setattr(selected.get, "_read", read)
    files, trees = selected.preparation_inputs(manifest["preparation"], manifest["resources"])
    assert all(path in files or any(path.is_relative_to(tree) for tree in trees) for path in observed), sorted(
        str(path) for path in observed if path not in files and not any(path.is_relative_to(tree) for tree in trees))
    roots = transport.manifest_roots(manifest)
    assert all(any(path.is_relative_to(root) for root in roots) for path in observed)
    assert trees == {case["raw"]}
    context = operation.OperationFacts()
    for file in files: context.watch_file(file)
    for tree in trees: context.watch_tree(tree)
    (case["audit"].parent.parent / "unrelated-later-operation.json").write_bytes(b"not an input")
    context.check()
    source = Path(case["runtime"]["source_manifest"])
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="dependency"):
        context.check()


def test_selected_transport_stays_exact_when_installed_import_paths_differ(selected_graph, tmp_path, monkeypatch):
    manifest = load(selected_graph["prepared"])
    roots = transport.manifest_roots(manifest)
    alias = tmp_path.with_name(tmp_path.name + "-installed-module-alias")
    alias.mkdir()
    for module in selected._direct_modules():
        original = Path(module.__file__)
        copy_path = alias / original.name
        copy_path.write_bytes(original.read_bytes())
        monkeypatch.setattr(module, "__file__", str(copy_path))
    assert transport.manifest_roots(manifest) == roots
    files, _ = selected.preparation_inputs(manifest["preparation"], manifest["resources"])
    assert {alias / Path(module.__file__).name for module in selected._direct_modules()} <= files
    assert not any(alias.is_relative_to(root) for root in roots)


@pytest.mark.parametrize("field", ["candidate_id", "capture_limits", "recorded_producer_sources", "direct_validator_sources", "direct_validator_files"])
def test_input_cannot_relabel_original_candidate_caps_or_sources(selected_graph, field):
    path = selected_graph["input"]
    value = receipts._unpack(path.read_bytes(), selected.RECEIPT_TYPE)
    if field == "candidate_id": value[field] = "foreign"
    elif field == "capture_limits": value[field]["max_response_bytes"] *= 2
    elif field == "direct_validator_files": value[field][next(iter(value[field]))]["sha256"] = "0" * 64
    else: value[field][next(iter(value[field]))] = "0" * 64
    write(path, receipts._bind(selected.RECEIPT_TYPE, value))
    with pytest.raises(ValueError):
        selected.validate_input(path)


def test_failed_audit_cannot_publish_input_or_mutate_get_history(selected_graph, tmp_path):
    value = receipts._unpack(selected_graph["audit"].read_bytes(), selected.AUDIT_TYPE)
    completed = Path(value["completed"]["path"])
    document = load(completed); document["returncode"] = 1; write(completed, document)
    value["completed"] = selected.reference(completed)
    write(selected_graph["audit"], receipts._bind(selected.AUDIT_TYPE, value))
    output = tmp_path / "attempted-failed-audit-input.json"
    with pytest.raises(ValueError):
        selected.publish_input(output, audit=selected_graph["audit"], candidate_id=selected_graph["seed"]["classes"][0]["candidate_id"])
    assert not output.exists()


@pytest.mark.parametrize("duplicate", ["candidate", "workload", "canonical-alias", "class-index"])
def test_append_only_class_mapping_rejects_duplicates_without_history(duplicate):
    first = {"candidate_id": "one", "workload_id": "one", "class_index": 1, "canonical_sites": ["one.example"]}
    second = {"candidate_id": "two", "workload_id": "two", "class_index": 2, "canonical_sites": ["two.example"]}
    if duplicate == "candidate": second["candidate_id"] = "one"
    elif duplicate == "workload": second["workload_id"] = "one"
    elif duplicate == "canonical-alias": second["canonical_sites"] = ["one.example"]
    else: second["class_index"] = 1
    with pytest.raises(ValueError):
        additive._deduplicate([first, second])
