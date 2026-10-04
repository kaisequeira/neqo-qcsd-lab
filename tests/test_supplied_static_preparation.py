"""Synthetic emitter-contract fixtures; no actual Native/HTTP3 credit."""
from __future__ import annotations

import copy
import csv
import io
from pathlib import Path

import pytest

from tests.test_supplied_static_get import actual_contract_fixture, load, write, csv_bytes, reseal_outputs
from qcsd_lab import supplied_static_get as get
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as prep
from qcsd_lab import supplied_static_bootstrap_get as bootstrap
from qcsd_lab import supplied_static_admission as admission
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import capture_acceptance_policy as capture
from qcsd_lab import application_response_policy as responses
from qcsd_lab import manifest as manifests
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_readiness as readiness

POLICIES = {capture.FIELD: capture.ACK_START_POLICY, capture.TAMARAW_FIELD: capture.TAMARAW_POLICY,
            capture.FRONT_FIELD: capture.FRONT_WINDOW_POLICY, capture.TERMINAL_PRIMARY_FIELD: capture.TERMINAL_PRIMARY_POLICY}
REPOSITORY = Path(__file__).parents[1]
MAX_BYTES = 16_777_216


def seal(root, **arguments):
    proof = bootstrap.build_proof(root, **arguments)
    write(root / "full-get-proof.json", proof)
    return proof


@pytest.fixture
def fixed_graph(actual_contract_fixture, tmp_path, monkeypatch):
    root, arguments = actual_contract_fixture
    context_root = tmp_path / "static-context"
    context_root.mkdir()
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-03T23:59:59Z")
    admission.initialize_context(context_root, root / "source-list.json",
                                source_sha256=arguments["source_sha256"], expected_runtime=arguments["expected_runtime"])
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:00:20Z")
    context = admission.load_context(context_root)
    neutral = load(root / "native-input.json")
    (root / "neutral-input.json").write_bytes((root / "native-input.json").read_bytes())
    _, _, primary, full = bootstrap._inputs((root / "source-list.json").read_bytes(), arguments["source_sha256"], arguments["domain"])
    write(root / "native-input.json", full)
    old_declaration = load(root / "declaration.json")
    declaration = {key: value for key, value in old_declaration.items() if key not in {"native_input_sha256"}}
    declaration.update(schema_version=2, record_type=bootstrap.PROOF_TYPE, producer_role=bootstrap.PRODUCER_ROLE,
                       max_response_bytes=MAX_BYTES,
                       producer_sources=bootstrap.producer_sources(), context=prep.reference(context_root / "provenance.json"),
                       candidate_queue_position=1, candidate_source_position=1,
                       neutral_input_sha256=graph.digest(graph.canonical_bytes(neutral)),
                       bootstrap_input_sha256=graph.digest(graph.canonical_bytes(primary)),
                       full_input_sha256=graph.digest(graph.canonical_bytes(full)))
    write(root / "declaration.json", declaration)
    original_run = load(root / "native/run.json")
    original_run["max_response_bytes"] = MAX_BYTES
    original_run["responses"][0]["response_headers"].append(["content-type", "text/html; charset=utf-8"])
    for response in original_run["responses"][1:]:
        response.update(bytes=1500, content_length=1500, body_sha256=graph.digest(b"a" * 1500))
        response["response_headers"][1][1] = "1500"
    primary_root = root / "bootstrap"
    primary_root.mkdir()
    (primary_root / "native").mkdir()
    write(primary_root / "native-input.json", primary)
    primary_run = copy.deepcopy(original_run)
    primary_run["application_response_policy"] = bootstrap.STRICT_POLICY
    primary_run["workload_hash_sha256"] = declaration["bootstrap_input_sha256"]
    primary_run["responses"] = [primary_run["responses"][0]]
    primary_run["endpoints"] = [primary_run["endpoints"][1]]
    primary_run["endpoints"][0]["id"] = 0
    write(primary_root / "native/run.json", primary_run)
    for name in ("native.stdout.log", "native.stderr.log", "native/schedule.csv"):
        (primary_root / name).write_bytes((root / name).read_bytes())
    events = list(csv.DictReader(io.StringIO((root / "native/events.csv").read_text())))
    selected = [row for row in events if row["connection"] == "1"]
    for row in selected:
        row["connection"] = "0"
        if row["event"] == "observation":
            detail = get._load(row["details"].encode())
            if "endpoint" in detail:
                detail["endpoint"] = 0
            row["details"] = graph.canonical_bytes(detail).decode().strip()
    (primary_root / "native/events.csv").write_bytes(csv_bytes(list(selected[0]), selected))
    packets = [{"connection": "0", "direction": direction, "observed_udp_length": "1200"} for direction in ("incoming", "outgoing")]
    (primary_root / "native/packets.csv").write_bytes(csv_bytes(list(packets[0]), packets))
    dns = load(root / "dns.json")
    primary_dns = copy.deepcopy(dns)
    primary_dns["observations"] = [primary_dns["observations"][1]]
    write(primary_root / "dns.json", primary_dns)
    primary_started = load(root / "native-started.json")
    primary_started["command"] = bootstrap._command(primary_root, MAX_BYTES, 120, bootstrap.STRICT_POLICY)
    primary_started["declaration_sha256"] = graph.digest((root / "declaration.json").read_bytes())
    write(primary_root / "native-started.json", primary_started)
    primary_completed = load(root / "native-completed.json")
    write(primary_root / "native-completed.json", primary_completed)
    reseal_outputs(primary_root)
    original_run["started_unix_ns"] += 2_000_000_000
    original_run["time_anchor_unix_ns"] += 2_000_000_000
    original_run["ended_unix_ns"] += 2_000_000_000
    for endpoint in original_run["endpoints"]:
        endpoint["receive_lifecycle"]["polling_stopped_at_unix_ns"] += 2_000_000_000
    original_run["workload_hash_sha256"] = declaration["full_input_sha256"]
    write(root / "native/run.json", original_run)
    full_packets = [{"connection": str(endpoint), "direction": direction, "observed_udp_length": "1200"}
                    for endpoint in (0, 1) for direction in ("incoming", "outgoing") for _ in range(4)]
    (root / "native/packets.csv").write_bytes(csv_bytes(list(full_packets[0]), full_packets))
    started = load(root / "native-started.json")
    started.update(started_at="2026-10-04T00:00:03Z", declaration_sha256=primary_started["declaration_sha256"])
    started["command"] = bootstrap._command(root, MAX_BYTES, 120, get.RESPONSE_POLICY)
    write(root / "native-started.json", started)
    completed = load(root / "native-completed.json")
    completed["completed_at"] = "2026-10-04T00:00:04Z"
    write(root / "native-completed.json", completed)
    reseal_outputs(root)
    seal(root, **arguments)
    return root, arguments, context


def prepared(fixture):
    root, arguments, _ = fixture
    return prep.build_preparation(root, **arguments, policies=POLICIES)


def test_complete_primary_bootstrap_preserves_neutral_and_all_listed_graph_bytes(fixed_graph):
    root, arguments, _ = fixed_graph
    proof = bootstrap.validate_proof(root, **arguments)
    neutral = load(root / "neutral-input.json")
    full = load(root / "native-input.json")
    full["resources"][0].pop("known_valid")
    assert full == neutral
    assert load(root / "bootstrap/native-input.json") == {"resources": [neutral["resources"][0]]}
    assert proof["resource_count"] == 3 and proof["origin_count"] == 2
    assert proof["bootstrap_native"]["endpoint_completion"][0]["resource_ids"] == [0]
    assert not proof["scientific_credit"] and proof["formal_accepted_trace_count"] == 0


def test_static_preparation_feeds_real_manifest_chaff_and_response_validators_without_browser_claim(fixed_graph):
    value = prepared(fixed_graph)
    manifests.validate_research_preparation(value, workload_id="fixed-resource-site")
    projected = manifests.runtime_manifest(value)
    assert [row["url"] for row in projected["resources"]] == [row["url"] for row in value["resources"]]
    assert all(row["depends_on"] == ([] if row["id"] == 0 else [0]) for row in projected["resources"])
    assert value["preparation"]["complete_get_runs"] == 1
    assert not any(key in value["preparation"] for key in ("chromium_version", "stability_runs", "render_observation", "discovery_event_audit"))
    from qcsd_lab.chaff_qualification import selected_navigation_root, response_only_candidate_resources
    assert selected_navigation_root(value, "fixed-resource-site")["id"] == 0
    assert len(response_only_candidate_resources(value, "fixed-resource-site")) >= 1
    assert responses.validate_application_responses(value, load(fixed_graph[0] / "native/run.json"))["resource_ids"] == [0, 1, 2]


def test_one_get_primary_is_variable_only_under_new_static_evidence_and_auxiliary_identity_stays_exact(fixed_graph):
    value = prepared(fixed_graph)
    run = load(fixed_graph[0] / "native/run.json")
    run["primary_document_identity_policy"] = responses.VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
    row = run["responses"][0]
    row.update(bytes=8, content_length=8, body_sha256=graph.digest(b"changed!"))
    row["response_headers"][1][1] = "8"
    responses.validate_application_responses(value, run)
    run["responses"][1]["body_sha256"] = graph.digest(b"different aux")
    with pytest.raises(ValueError, match="prepared response identity"):
        responses.validate_application_responses(value, run)


@pytest.mark.parametrize("mutation", ["missing-bootstrap-fin", "bootstrap-policy", "bootstrap-old-native", "full-before-bootstrap", "fake-root-marker", "pruned-neutral", "wrong-context", "source-drift"])
def test_bootstrap_cannot_be_fabricated_or_detached_from_actual_complete_native_inputs(fixed_graph, mutation):
    root, arguments, context = fixed_graph
    if mutation == "missing-bootstrap-fin":
        rows = list(csv.DictReader(io.StringIO((root / "bootstrap/native/events.csv").read_text())))
        rows = [row for row in rows if "stream_finished" not in row["details"]]
        (root / "bootstrap/native/events.csv").write_bytes(csv_bytes(list(rows[0]), rows))
        reseal_outputs(root / "bootstrap")
    elif mutation in ("bootstrap-policy", "bootstrap-old-native"):
        run = load(root / "bootstrap/native/run.json")
        run["application_response_policy" if mutation == "bootstrap-policy" else "migration_commit"] = get.RESPONSE_POLICY if mutation == "bootstrap-policy" else "a" * 40
        write(root / "bootstrap/native/run.json", run)
        reseal_outputs(root / "bootstrap")
    elif mutation == "full-before-bootstrap":
        row = load(root / "native-started.json")
        row["started_at"] = "2026-10-04T00:00:01.500000Z"
        write(root / "native-started.json", row)
    elif mutation == "fake-root-marker":
        row = load(root / "native-input.json")
        row["resources"][0]["known_valid"] = False
        write(root / "native-input.json", row)
    elif mutation == "pruned-neutral":
        row = load(root / "neutral-input.json")
        row["resources"].pop()
        write(root / "neutral-input.json", row)
    elif mutation == "wrong-context":
        row = load(root / "declaration.json")
        row["context"]["sha256"] = "f" * 64
        write(root / "declaration.json", row)
    else:
        row = load(root / "declaration.json")
        row["producer_sources"]["qcsd_lab.supplied_static_bootstrap_get"] = "e" * 64
        write(root / "declaration.json", row)
    with pytest.raises(ValueError):
        bootstrap.build_proof(root, **arguments)


@pytest.mark.parametrize("mutation", ["drop", "headers", "dependency", "status", "browser-claim", "stability", "role", "policy", "forged-evidence"])
def test_static_prepared_manifest_reconstructs_every_resource_and_source_fact(fixed_graph, mutation):
    value = prepared(fixed_graph)
    if mutation == "drop": value["resources"].pop()
    elif mutation == "headers": value["resources"][1]["headers"][0][1] = "text/plain"
    elif mutation == "dependency": value["resources"][1]["depends_on"] = []
    elif mutation == "status": value["preparation"]["expected_responses"][1]["status"] = 404
    elif mutation == "browser-claim": value["preparation"]["browser_discovery_claim"] = True
    elif mutation == "stability": value["preparation"]["stability_runs"] = 3
    elif mutation == "role": value["preparation"]["data_role"] = "browser"
    elif mutation == "policy": value["preparation"][capture.FIELD] = "unknown-policy"
    else: value["preparation"]["primary_document_identity_evidence"]["complete_get_primary_responses"][0]["body_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        manifests.validate_research_preparation(value, workload_id="fixed-resource-site")


def mapped(fixture, tmp_path):
    root, arguments, _ = fixture
    execution = Path("/evidence") / root.name
    for child, target, policy in ((root, execution, get.RESPONSE_POLICY), (root / "bootstrap", execution / "bootstrap", bootstrap.STRICT_POLICY)):
        value = load(child / "native-started.json")
        value["command"] = bootstrap._command(target, MAX_BYTES, 120, policy)
        write(child / "native-started.json", value)
    outer = tmp_path / "outer"
    outer.mkdir()
    (outer / "stdout").write_bytes(b"synthetic actual recorder stdout\n")
    (outer / "stderr").write_bytes(b"")
    write(outer / "started.json", {"command": ["docker", "run", "--mount", f"type=bind,src={root.parent},dst=/evidence",
            arguments["expected_runtime"]["image_digest"], "python3", "-I", "operator.py", "execute-get", "--get-root", str(execution)],
            "started_at": "2026-10-03T23:59:59Z", "cwd": None})
    write(outer / "completed.json", {"returncode": 0, "completed_at": "2026-10-04T00:00:05Z", "elapsed_seconds": 6.0,
            "stdout_sha256": graph.digest((outer / "stdout").read_bytes()), "stderr_sha256": graph.digest(b"")})
    mapping = prep.namespace_mapping(root, execution, started=outer / "started.json", completed=outer / "completed.json",
            stdout=outer / "stdout", stderr=outer / "stderr", expected_runtime=arguments["expected_runtime"])
    return mapping, outer


def test_recorded_mount_namespace_reopens_original_native_commands_on_host(fixed_graph, tmp_path):
    mapping, _ = mapped(fixed_graph, tmp_path)
    root, arguments, _ = fixed_graph
    proof = seal(root, **arguments, namespace=mapping)
    assert bootstrap.validate_proof(root, **arguments, namespace=mapping) == proof
    assert prep.build_preparation(root, **arguments, policies=POLICIES, namespace=mapping)["preparation"]["static_get_evidence"]["namespace"] == mapping
    with pytest.raises(ValueError, match="command"):
        bootstrap.validate_proof(root, **arguments)


@pytest.mark.parametrize("mutation", ["wrong-mount", "duplicate-mount", "readonly", "wrong-image", "fake-zero", "changed-log", "late-outer"])
def test_namespace_is_closed_against_actual_mount_command_and_process_raws(fixed_graph, tmp_path, mutation):
    mapping, outer = mapped(fixed_graph, tmp_path)
    if mutation in ("wrong-mount", "duplicate-mount", "readonly", "wrong-image"):
        value = load(outer / "started.json")
        if mutation == "wrong-mount": value["command"][3] = value["command"][3].replace("dst=/evidence", "dst=/other")
        elif mutation == "duplicate-mount": value["command"][4:4] = ["--mount", value["command"][3]]
        elif mutation == "readonly": value["command"][3] += ",readonly"
        else: value["command"][4] = "sha256:" + "f" * 64
        write(outer / "started.json", value)
        mapping["outer_started"] = prep.reference(outer / "started.json")
    elif mutation == "changed-log":
        (outer / "stderr").write_bytes(b"changed")
        mapping["outer_stderr"] = prep.reference(outer / "stderr")
    else:
        value = load(outer / "completed.json")
        value["returncode" if mutation == "fake-zero" else "completed_at"] = 1 if mutation == "fake-zero" else "2026-10-04T00:00:02Z"
        write(outer / "completed.json", value)
        mapping["outer_completed"] = prep.reference(outer / "completed.json")
    with pytest.raises(ValueError):
        bootstrap.build_proof(fixed_graph[0], **fixed_graph[1], namespace=mapping)


def test_static_terminal_and_rolling_policy_cannot_pool_browser_decisions_or_fabricated_membership(fixed_graph, tmp_path):
    root, arguments, context = fixed_graph
    terminal = admission.admit(context, 1, root, policies=POLICIES)
    facts = admission.verify_terminal(terminal, context)
    assert facts["outcome"] == "admitted" and facts["data_role"] == prep.ROLE
    assert admission.acquisition_status(context)["terminal_prefix"][0]["sha256"] == graph.digest(terminal.read_bytes())
    raw = load(terminal)
    raw["receipt_type"] = receipts.TERMINAL_TYPE
    write(terminal, raw)
    with pytest.raises(ValueError):
        admission.verify_terminal(terminal, context)


def test_real_failed_native_deferral_never_grants_eligibility_and_fake_exit_zero_rejects(fixed_graph):
    root, arguments, context = fixed_graph
    value = load(root / "native-completed.json")
    value["returncode"] = 1
    write(root / "native-completed.json", value)
    failure = bootstrap.failure_proof(root, **arguments)
    assert failure["outcome"] == "operational-deferred"
    terminal = admission.record_get_deferral(context, 1, root)
    assert admission.verify_terminal(terminal, context)["admission"] is None
    value["returncode"] = 0
    write(root / "native-completed.json", value)
    with pytest.raises(ValueError, match="failed Native"):
        admission.verify_terminal(terminal, context)


def test_pure_input_rejection_requires_actual_exact_source_reason(fixed_graph, tmp_path):
    root, arguments, context = fixed_graph
    with pytest.raises(ValueError, match="invented"):
        admission.record_input_rejection(context, 1)
    directory = tmp_path / "empty-context"
    directory.mkdir()
    source = tmp_path / "empty-source.json"
    source.write_bytes(graph.canonical_bytes([{"crUX_domain": "empty.example", "resources": []}]))
    admission.initialize_context(directory, source, source_sha256=graph.digest(source.read_bytes()), expected_runtime=arguments["expected_runtime"])
    other = admission.load_context(directory)
    terminal = admission.record_input_rejection(other, 1)
    assert admission.verify_terminal(terminal, other)["outcome"] == "input-ineligible"


def runtime(tmp_path):
    data, source = tmp_path / "capture-data", tmp_path / "source"
    execution, study = data / "execution", data / "study"
    campaigns, workloads = execution / "config/campaigns", execution / "config/workloads"
    for path in (data, source, execution, study, campaigns, workloads): path.mkdir(parents=True, exist_ok=True)
    (source / "qcsd-lab").write_bytes(b"synthetic exact launcher\n")
    (execution / "qcsd-lab").write_bytes((source / "qcsd-lab").read_bytes())
    for relative, _ in lanes.TRAFFIC_FILES.values():
        target = execution / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    target = execution / lanes.STUDY_PROFILE_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((REPOSITORY / lanes.STUDY_PROFILE_FILE).read_bytes())
    (source / "client").write_bytes(b"synthetic actual client identity")
    metadata = {"image_digest": None, "lab_commit": "d" * 40, "neqo_commit": "5" * 40, "neqo_pinned_commit": "5" * 40,
                "lab_dirty": False, "neqo_dirty": False, "lab_patch_sha256": get._EMPTY, "neqo_patch_sha256": get._EMPTY}
    write(source / "source.json", metadata)
    return study, {"data_root": str(data), "runtime_source_root": str(source), "module_root": str(REPOSITORY),
        "execution_root": str(execution), "workload_root": str(workloads), "campaign_dir": str(campaigns),
        "source_manifest": str(source / "source.json"), "client_binary": str(source / "client"),
        "base_launcher": str(source / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "collection_image_digest": "sha256:" + "a" * 64, "execution_generation": "static-test-001"}


def test_public_static_enrollment_and_real_plan_keep_64_slots_per_setting_and_ordinary_deep_path(fixed_graph, tmp_path, monkeypatch):
    root, arguments, context = fixed_graph
    terminal = admission.admit(context, 1, root, policies=POLICIES)
    study, capture_runtime = runtime(tmp_path)
    rolling.initialize_study(context.root, study, capture_runtime, supplied_static=True)
    assert rolling.verify_policy(study)["contract"] == rolling.STATIC_CONTRACT
    successor_context = append_context(fixed_graph, tmp_path, monkeypatch)
    enrollment = rolling.enroll(study, acquisition_root=successor_context.root)
    batch, classes = rolling.verify_enrollment(enrollment)
    assert len(classes) == 1 and classes[0]["terminal"]["sha256"] == graph.digest(terminal.read_bytes())
    original, manifest = admission.prepared_workload(context, terminal)
    workload_root = Path(capture_runtime["workload_root"])
    (workload_root / original.name).write_bytes(original.read_bytes())
    sidecars = Path(capture_runtime["campaign_dir"]).parent / "chaff-response-qualification-store/sets/static-test"
    sidecars.mkdir(parents=True)
    write(sidecars / "_qualification-set.json", {"external_qualification_primitive": "substituted only in this HOST fixture"})
    qualifier = study / "qualifier-spec.json"
    write(qualifier, {"schema_version": 1, "qualification_sets": [{"qualification_set": "static-test",
        "manifest": str(sidecars / "_qualification-set.json"), "sidecar_root": str(sidecars), "prefix_spec_root": None}]})
    # Only external qualifier/canary primitives are substituted; context, GET,
    # preparation, policy, enrollment, all resource bindings and plan are real.
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", lambda *args, **kwargs: None)
    monkeypatch.setattr(readiness, "validate_canary", lambda *args, **kwargs: {})
    output = study / "plan.json"
    rolling.publish_plan(study, enrollment, qualifier, output, readiness={"undefended": {"synthetic_canary": True}})
    spec = rolling.capture_spec(study, enrollment, qualifier, output)
    sites, payload = rolling.verify_capture_plan(spec)
    assert payload["data_role"] == prep.ROLE and payload["planned_trace_count"] == 320
    assert len(payload["lanes"]) == 80
    for mode in rolling.plan.MODES:
        assert sum(len(row["workload_ids"]) * row["visits_per_workload"]
                   for row in payload["lanes"] if row["mode"] == mode) == 64
    assert payload["readiness"] == {"undefended": {"synthetic_canary": True}}
    import yaml
    first_row = payload["lanes"][0]
    lane = rolling.plan.Lane(**{key: tuple(value) if key == "workload_ids" else value
                               for key, value in first_row.items() if key != "campaign_sha256"})
    actual_campaign = (spec.campaign_dir / (lane.campaign_name + ".yml")).read_bytes()
    assert lanes._render_lane_campaign(spec, lane, sites) == actual_campaign
    assert yaml.safe_load(actual_campaign)["limits"] == admission.context_limits(context)
    successor = rolling.plan.successor_lane(lane, 2)
    assert yaml.safe_load(lanes._render_lane_campaign(spec, successor, sites))["limits"]["max_response_bytes"] == MAX_BYTES
    assert rolling.plan.V5_CAPTURE_LIMITS["max_response_bytes"] == 1_048_576
    assert root in rolling.enrollment_roots(spec)
    assert context.root in rolling.enrollment_roots(spec) and successor_context.root in rolling.enrollment_roots(spec)
    (workload_root / original.name).write_bytes(graph.canonical_bytes({"resources": manifest["resources"][:-1]}))
    with pytest.raises(ValueError, match="pruned"):
        rolling.verify_capture_plan(spec)


def test_browser_default_cannot_initialize_from_static_context(fixed_graph, tmp_path):
    study, capture_runtime = runtime(tmp_path)
    with pytest.raises(ValueError):
        rolling.initialize_study(fixed_graph[2].root, study, capture_runtime)


def test_explicit_large_application_body_is_preserved_and_actual_overflow_rejects(fixed_graph):
    root, arguments, _ = fixed_graph
    run = load(root / "native/run.json")
    count = 1_048_577
    response = run["responses"][1]
    response.update(bytes=count, content_length=count, body_sha256=graph.digest(b"x" * count))
    response["response_headers"][1][1] = str(count)
    write(root / "native/run.json", run)
    reseal_outputs(root)
    seal(root, **arguments)
    value = prepared(fixed_graph)
    assert value["resources"][1]["data_length"] == count
    assert value["preparation"]["max_response_bytes"] == MAX_BYTES
    response.update(bytes=MAX_BYTES + 1, content_length=MAX_BYTES + 1)
    response["response_headers"][1][1] = str(MAX_BYTES + 1)
    write(root / "native/run.json", run)
    reseal_outputs(root)
    with pytest.raises(ValueError, match="truncated"):
        bootstrap.build_proof(root, **arguments)


@pytest.mark.parametrize("max_bytes,timeout", [(1_048_576, 120), (MAX_BYTES, 121), (True, 120)])
def test_get_rejects_undeclared_budget_before_any_installed_or_network_operation(fixed_graph, tmp_path, monkeypatch, max_bytes, timeout):
    def forbidden(*args, **kwargs):
        pytest.fail("budget rejection must precede image, DNS and Native work")
    monkeypatch.setattr(get.chaff_qualification, "_qualification_execution_context", forbidden)
    monkeypatch.setattr(bootstrap.socket, "getaddrinfo", forbidden)
    with pytest.raises(ValueError, match="prospectively declared"):
        bootstrap.execute(fixed_graph[2].root, 1, tmp_path / "never-created", max_response_bytes=max_bytes, timeout_seconds=timeout)
    assert not (tmp_path / "never-created").exists()


def append_context(fixture, tmp_path, monkeypatch, *, mutation=None):
    _, arguments, parent = fixture
    source_rows = get._load(parent.source_bytes)
    new_row = copy.deepcopy(source_rows[0])
    new_row["crUX_domain"] = "second.example"
    if mutation == "prefix": source_rows[0]["resources"][0]["resource_urls"][0] += "&changed-declared-resource"
    if mutation == "no-append": rows = source_rows
    else: rows = source_rows + [new_row]
    source = tmp_path / "appended-source.json"
    source.write_bytes(graph.canonical_bytes(rows))
    directory = tmp_path / "appended-context"
    directory.mkdir()
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:01:00Z")
    admission.initialize_context(directory, source, source_sha256=graph.digest(source.read_bytes()),
                                 expected_runtime=arguments["expected_runtime"], parent_context=parent.root,
                                 max_response_bytes=1_048_576 if mutation == "cap" else MAX_BYTES)
    return admission.load_context(directory)


def test_append_only_real_graph_pool_retains_original_admission_labels_and_order(fixed_graph, tmp_path, monkeypatch):
    root, _, parent = fixed_graph
    terminal = admission.admit(parent, 1, root, policies=POLICIES)
    original = terminal.read_bytes()
    child = append_context(fixed_graph, tmp_path, monkeypatch)
    assert len(child.candidates) == len(parent.candidates) + 1
    assert child.candidates[:len(parent.candidates)] == parent.candidates
    assert admission.identity(child) == admission.identity(parent)
    assert admission.terminal_path(child, 1) == terminal
    assert admission.verify_terminal(terminal, child)["outcome"] == "admitted"
    assert admission.prepared_workload(child, terminal) == admission.prepared_workload(parent, terminal)
    assert admission.acquisition_status(child)["terminal_prefix"] == [prep.reference(terminal)]
    assert parent.root in admission.roots(child)
    assert terminal.read_bytes() == original
    with pytest.raises(ValueError, match="inherited"):
        admission.admit(child, 1, root, policies=POLICIES)


@pytest.mark.parametrize("mutation", ["prefix", "no-append", "cap"])
def test_successor_context_rejects_reordered_pruned_or_changed_budget_pool(fixed_graph, tmp_path, monkeypatch, mutation):
    with pytest.raises(ValueError, match="append"):
        append_context(fixed_graph, tmp_path, monkeypatch, mutation=mutation)


def test_successor_context_cannot_fake_or_skip_an_inherited_terminal(fixed_graph, tmp_path, monkeypatch):
    admission.admit(fixed_graph[2], 1, fixed_graph[0], policies=POLICIES)
    child = append_context(fixed_graph, tmp_path, monkeypatch)
    provenance = receipts._unpack((child.root / "provenance.json").read_bytes(), admission.PROVENANCE_TYPE)
    provenance["inherited_terminals"][0]["path"] = str(child.root / "attempts/candidate-000001/terminal.json")
    (child.root / "provenance.json").write_bytes(receipts._json(receipts._bind(admission.PROVENANCE_TYPE, provenance)))
    with pytest.raises((ValueError, OSError)):
        admission.load_context(child.root)


def test_identical_other_context_cannot_claim_actual_get_declared_for_original(fixed_graph, tmp_path, monkeypatch):
    root, arguments, original = fixed_graph
    other_root = tmp_path / "other-static-context"
    other_root.mkdir()
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-03T23:59:59Z")
    admission.initialize_context(other_root, root / "source-list.json", source_sha256=arguments["source_sha256"],
                                 expected_runtime=arguments["expected_runtime"])
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:00:20Z")
    other = admission.load_context(other_root)
    assert admission.identity(other) == admission.identity(original)
    with pytest.raises(ValueError, match="prospective"):
        admission.admit(other, 1, root, policies=POLICIES)


def test_prospective_queue_permutation_preserves_source_and_every_candidate_graph(fixed_graph, tmp_path):
    _, arguments, original = fixed_graph
    rows = get._load(original.source_bytes)
    for domain in ("priority.example", "last.example"):
        row = copy.deepcopy(rows[0])
        row["crUX_domain"] = domain
        rows.append(row)
    source = tmp_path / "complete-source.json"
    raw = graph.canonical_bytes(rows)
    source.write_bytes(raw)
    digest = graph.digest(raw)
    default_root, priority_root = tmp_path / "default-order", tmp_path / "priority-order"
    default_root.mkdir(); priority_root.mkdir()
    admission.initialize_context(default_root, source, source_sha256=digest, expected_runtime=arguments["expected_runtime"])
    admission.initialize_context(priority_root, source, source_sha256=digest, expected_runtime=arguments["expected_runtime"],
                                 candidate_order=[2, 1, 3], ordering_rationale="Start with an independently checked root; all remaining source positions stay ordered.")
    default, priority = admission.load_context(default_root), admission.load_context(priority_root)
    assert default.source_bytes == priority.source_bytes == raw
    assert [row["source_position"] for row in default.candidates] == [1, 2, 3]
    assert [row["source_position"] for row in priority.candidates] == [2, 1, 3]
    assert [row["position"] for row in priority.candidates] == [1, 2, 3]
    assert priority.provenance["ordering_policy"] == "operator-declared-permutation-v1"
    assert default.provenance["ordering_policy"] == "original-source-order-v1"
    assert bootstrap._candidate_identity(priority, "priority.example") == {"candidate_queue_position": 1, "candidate_source_position": 2}
    for row in priority.candidates:
        assert graph.import_graph(priority.source_bytes, digest, row["domain"]) == graph.import_graph(default.source_bytes, digest, row["domain"])
    assert admission.identity(priority)["candidate_order_sha256"] != admission.identity(default)["candidate_order_sha256"]
    # Editing and resealing only the queue file cannot silently reorder the
    # already sealed candidate rows and enrolled decisions.
    (priority.root / "candidate-order.json").chmod(0o600)
    write(priority.root / "candidate-order.json", [1, 2, 3])
    provenance = receipts._unpack((priority.root / "provenance.json").read_bytes(), admission.PROVENANCE_TYPE)
    provenance["candidate_order"] = prep.reference(priority.root / "candidate-order.json")
    (priority.root / "provenance.json").write_bytes(receipts._json(receipts._bind(admission.PROVENANCE_TYPE, provenance)))
    with pytest.raises(ValueError, match="order"):
        admission.load_context(priority.root)


@pytest.mark.parametrize("order,rationale", [([1, 1], "duplicate"), ([2], "outside"), ([True], "boolean"), ([1], None), (None, "no permutation")])
def test_declared_order_rejects_duplicates_holes_and_unpaired_rationale(fixed_graph, tmp_path, order, rationale):
    root, arguments, _ = fixed_graph
    destination = tmp_path / "invalid-order"
    destination.mkdir()
    with pytest.raises(ValueError, match="order|permutation"):
        admission.initialize_context(destination, root / "source-list.json", source_sha256=arguments["source_sha256"],
                                     expected_runtime=arguments["expected_runtime"], candidate_order=order, ordering_rationale=rationale)
    assert not (destination / "provenance.json").exists()


@pytest.mark.parametrize("field", ["candidate_queue_position", "candidate_source_position"])
def test_actual_get_cannot_claim_a_different_queue_or_source_position(fixed_graph, field):
    root, arguments, _ = fixed_graph
    declaration = load(root / "declaration.json")
    declaration[field] = 2
    write(root / "declaration.json", declaration)
    with pytest.raises(ValueError, match="declaration"):
        bootstrap.build_proof(root, **arguments)
