"""HOST emitter-contract integration; no network, installed image or credit."""
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
import shutil

import pytest
import yaml

from qcsd_lab import supplied_static_budget_successor as budget
from qcsd_lab import static_budget_capture as capture
from qcsd_lab import static_budget_capture_amendment as amendment
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_bootstrap_get as bootstrap
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as prep
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import manifest, application_response_policy as app
from tests.test_static_budget_successor import budget_fixture
from tests.test_supplied_static_get import actual_contract_fixture, load, write, reseal_outputs
from tests.test_supplied_static_preparation import fixed_graph, POLICIES, runtime
from tests.test_whole_graph_supplement import supplemented

REPOSITORY = Path(__file__).parents[1]


@pytest.fixture
def admitted_budget(budget_fixture, tmp_path, monkeypatch):
    context, original, before = budget_fixture
    root = tmp_path / "fresh-complete-get"
    shutil.copytree(original, root)
    declaration = load(root / "declaration.json")
    declaration.update(context=prep.reference(context.active.root / "provenance.json"),
        declared_at="2026-10-04T00:00:21Z", max_response_bytes=budget.RESPONSE_BYTES)
    write(root / "declaration.json", declaration)
    for child, policy, started_at, completed_at in (
            (root / "bootstrap", bootstrap.STRICT_POLICY, "2026-10-04T00:00:22Z", "2026-10-04T00:00:23Z"),
            (root, bootstrap.get.RESPONSE_POLICY, "2026-10-04T00:00:23Z", "2026-10-04T00:00:24Z")):
        run = load(child / "native/run.json")
        run["max_response_bytes"] = budget.RESPONSE_BYTES
        if child == root:
            run["completion_status"] = "complete"
            run["responses"][1].update(bytes=1500, content_length=1500, complete=True,
                outcome="succeeded", body_sha256=graph.digest(b"a" * 1500))
            run["responses"][1]["response_headers"][1][1] = "1500"
        shift = 21_000_000_000 if child != root else 20_000_000_000
        for name in ("started_unix_ns", "time_anchor_unix_ns", "ended_unix_ns"):
            run[name] += shift
        for endpoint in run["endpoints"]:
            endpoint["receive_lifecycle"]["polling_stopped_at_unix_ns"] += shift
        write(child / "native/run.json", run)
        dns = load(child / "dns.json")
        for observation in dns["observations"]:
            for field in ("started_at", "completed_at"):
                observation[field] = (datetime.fromisoformat(observation[field]) + timedelta(seconds=21)).isoformat()
        write(child / "dns.json", dns)
        started = load(child / "native-started.json")
        started.update(started_at=started_at,
            declaration_sha256=graph.digest((root / "declaration.json").read_bytes()),
            command=bootstrap._command(child, budget.RESPONSE_BYTES, 120, policy))
        write(child / "native-started.json", started)
        completed = load(child / "native-completed.json")
        completed["completed_at"] = completed_at
        write(child / "native-completed.json", completed)
        reseal_outputs(child)
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-04T00:00:30Z")
    arguments = static._get_arguments(context.active, 53)
    write(root / "full-get-proof.json", bootstrap.build_proof(root, **arguments))
    static.admit(context.active, 53, root, policies=POLICIES)
    terminal = capture.account_terminal(context, 53)
    return context, terminal, root, before


def test_real_typed_wrapper_hash_manifest_response_and_limits(admitted_budget):
    context, terminal, root, before = admitted_budget
    path, workload = capture.prepared_workload(context, terminal)
    facts = capture.verify_terminal(terminal, context)
    assert facts["admission"]["prepared_workload_sha256"] == graph.digest(path.read_bytes())
    original = load(prep.open_reference(workload["preparation"][budget.FIELD]["original_manifest"]))
    assert workload["resources"] == original["resources"]
    keys = ("id", "url", "type", "depends_on", "headers")
    assert [{key: row[key] for key in keys} for row in workload["resources"]] == [
        {key: row[key] for key in keys} for row in load(root / "native-input.json")["resources"]]
    manifest.validate_research_preparation(workload, workload_id=path.stem)
    assert app.validate_application_responses(workload, load(root / "native/run.json"))["resource_ids"] == [0, 1, 2]
    assert capture.selected_capture_limits([workload], budget.context_limits(context)) == static.capture_limits(budget.RESPONSE_BYTES, 256)
    assert all(Path(name).read_bytes() == raw for name, raw in before.items())
    assert capture.acquisition_status(context)["terminal_count"] == 53


def test_public_enrollment_and_all_five_campaigns_use_authenticated_class_limits(admitted_budget, tmp_path, monkeypatch):
    context, terminal, _, _ = admitted_budget
    study, inputs = runtime(tmp_path)
    rolling.initialize_study(context.original.root, study, inputs, supplied_static=True)
    enrollment = rolling.enroll(study, acquisition_root=context.root)
    batch, classes = rolling.verify_enrollment(enrollment)
    assert len(batch["decisions"]) == 53 and classes[0]["class_index"] == 1
    path, workload = capture.prepared_workload(context, terminal)
    target = Path(inputs["workload_root"]) / path.name
    target.write_bytes(path.read_bytes())
    sidecars = study / "qualification"
    sidecars.mkdir()
    write(sidecars / "_qualification-set.json", {"external_qualification_primitive": "synthetic HOST seam only"})
    qualifier = study / "qualifier.json"
    write(qualifier, {"schema_version": 1, "qualification_sets": [{"qualification_set": "fixture",
        "manifest": str(sidecars / "_qualification-set.json"), "sidecar_root": str(sidecars), "prefix_spec_root": None}]})
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", lambda *a, **k: None)
    from qcsd_lab import rapid_rolling_readiness as readiness
    monkeypatch.setattr(readiness, "validate_canary", lambda *a, **k: {})
    output = study / "plan.json"
    rolling.publish_plan(study, enrollment, qualifier, output, readiness={"undefended": {"synthetic_canary": True}})
    spec = rolling.capture_spec(study, enrollment, qualifier, output)
    _, payload = rolling.verify_capture_plan(spec)
    expected = static.capture_limits(budget.RESPONSE_BYTES, 256)
    assert payload["capture_limits"] == expected and payload["planned_trace_count"] == 320
    assert rolling.verify_policy(study)["capture_limits"] == static.capture_limits(16_777_216, 64)
    assert set(row["mode"] for row in payload["lanes"]) == set(rolling.plan.MODES)
    for row in payload["lanes"]:
        campaign = yaml.safe_load((spec.campaign_dir / (row["campaign_name"] + ".yml")).read_bytes())
        assert campaign["limits"] == expected
    changed = static.receipts._unpack(output.read_bytes(), rolling.lanes.PLAN_TYPE)
    changed["capture_limits"]["capture_megabytes"] = 64
    output.write_bytes(static.receipts._json(static.receipts._bind(rolling.lanes.PLAN_TYPE, changed)))
    with pytest.raises(ValueError, match="scientific data role"):
        rolling.verify_capture_plan(spec)


def test_new_amendment_keeps_whole_graph_and_budget_limits_and_rejects_recording_mutation(admitted_budget, tmp_path):
    context, terminal, _, _ = admitted_budget
    study, inputs = runtime(tmp_path)
    rolling.initialize_study(context.original.root, study, inputs, supplied_static=True)
    enrollment = rolling.enroll(study, acquisition_root=context.root)
    for relative in amendment.authority_files().values():
        target = Path(inputs["runtime_source_root"]) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    output = study / "front-amendment.json"
    amendment.publish_amendment(enrollment, inputs, output, front_policy=amendment.old.capture.FRONT_RESERVE_POLICY)
    closed = amendment.validate_amendment(output, enrollment=enrollment, runtime=inputs)
    row = closed["workloads"][0]
    derived = load(prep.open_reference(row["capture_manifest"]))
    original = load(prep.open_reference(row["original_manifest"]))
    assert derived["resources"] == original["resources"]
    assert closed["capture_limits"] == static.capture_limits(budget.RESPONSE_BYTES, 256)
    manifest.validate_research_preparation(derived, workload_id=row["workload_id"])
    path = prep.open_reference(closed["declaration"])
    declaration = static.receipts._unpack(path.read_bytes(), amendment.DECLARATION_TYPE)
    declaration["capture_limits"]["capture_megabytes"] = 64
    path.write_bytes(static.receipts._json(static.receipts._bind(amendment.DECLARATION_TYPE, declaration)))
    with pytest.raises(ValueError, match="response budget amendment changed"):
        amendment._declaration(path)


def test_budget_raw_fence_binds_old_partial_and_complete_new_get_without_context_parent(admitted_budget, tmp_path):
    context, terminal, root, _ = admitted_budget
    study, inputs = runtime(tmp_path)
    rolling.initialize_study(context.original.root, study, inputs, supplied_static=True)
    enrollment = rolling.enroll(study, acquisition_root=context.root)
    files, trees = capture.terminal_inputs(enrollment)
    assert root in trees and Path(context.provenance["retained_attempt"]["root"]) in trees
    assert context.root not in trees and context.active.root not in trees
    assert context.root / "provenance.json" in files and terminal in files
    from qcsd_lab.rapid_operation_facts import OperationFacts
    path, _ = capture.prepared_workload(context, terminal)
    facts = OperationFacts()
    for tree in facts._workload_evidence_trees(path):
        facts.watch_tree(tree)
    (context.root / "unrelated-next-output.json").write_bytes(b"later output")
    facts.check()
    (root / "native.stdout.log").write_bytes(b"changed actual raw output")
    with pytest.raises(ValueError):
        facts.check()


def test_whole_only_new_selector_amendment_retains_real_occurrences_dag_and_original_limits(supplemented):
    from qcsd_lab import whole_graph_supplement as whole
    root, context, _ = supplemented
    terminal = whole.admit(context, 2, root)
    _, original = whole.prepared_workload(context, terminal)
    assert amendment._validate_original(original)["resource_count"] == 3
    derived = amendment._derived(original, {"path": "/synthetic/declaration.json", "sha256": "a" * 64},
        amendment.old.policies(front_policy=amendment.old.capture.FRONT_RESERVE_POLICY), None)
    assert derived["resources"] == original["resources"]
    assert derived["resources"][1]["url"] == derived["resources"][2]["url"]
    assert derived["resources"][2]["depends_on"] == [1]
    assert capture.selected_capture_limits([original], static.context_limits(context.original)) == static.capture_limits(16_777_216, 64)


def test_mixed_cap_enrollment_refuses_before_create_only_batch(admitted_budget, tmp_path, monkeypatch):
    context, terminal, _, _ = admitted_budget
    study, inputs = runtime(tmp_path)
    rolling.initialize_study(context.original.root, study, inputs, supplied_static=True)
    _, new = capture.prepared_workload(context, terminal)
    # Only ordered admission selection is substituted at this HOST boundary;
    # the complete new wrapper was genuinely reconstructed above.
    old = {"preparation": {"max_response_bytes": 16_777_216}, "resources": []}
    refs = [rolling._ref(terminal), rolling._ref(terminal)]
    monkeypatch.setattr(capture, "acquisition_status", lambda value: {"terminal_prefix": refs})
    monkeypatch.setattr(rolling, "_terminal_row", lambda ctx, pos, ref: (
        {"position": pos, "outcome": "admitted", "terminal": ref, "candidate_id": str(pos)},
        {"outcome": "admitted", "candidate_id": str(pos)}))
    values = iter([new, old])
    monkeypatch.setattr(rolling, "_prepared_workload", lambda *args: (Path("synthetic.json"), next(values)))
    monkeypatch.setattr(rolling, "_write", lambda *a: pytest.fail("mixed limits reached publication"))
    with pytest.raises(ValueError, match="homogeneous"):
        rolling.enroll(study, acquisition_root=context.root, count=2)
    assert not (study / "batches").exists()


def test_account_missing_or_repeated_public_terminal_cannot_claim_wrapper(budget_fixture):
    context, _, _ = budget_fixture
    with pytest.raises((ValueError, OSError)):
        capture.account_terminal(context, 53)
    assert not (context.root / "attempts").exists()
    with pytest.raises(ValueError, match="skip/repeat"):
        capture.account_terminal(context, 54)


def test_genuine_mixed_selector_preserves_budget_prefix_and_whole_tail_in_same_study(admitted_budget, tmp_path, monkeypatch):
    from qcsd_lab import whole_graph_input as inputs
    from qcsd_lab import whole_graph_supplement as whole
    head, _, old_get, _ = admitted_budget
    root = tmp_path / "complete-whole-tail-get"
    shutil.copytree(old_get, root)
    # Reproduce the reviewed synthetic external-discovery boundary only; all
    # subsequent graph, Native raw proof, terminal and enrollment checks run.
    neutral = load(root / "neutral-input.json")
    for resource in neutral["resources"]:
        resource.update(url=resource["url"].replace("sample.example", "tail.example"),
            known_valid=False, chaff_priority=False, content_length=None, data_length=0)
    neutral["resources"][2].update(url=neutral["resources"][1]["url"], depends_on=[1])
    discovered = tmp_path / "synthetic-tail-discovery"
    discovered.mkdir()
    write(discovered / "native-input.json", neutral)
    candidate = {"catalogue_position": 7, "candidate_id": "tranco-0000007", "domain": "tail.example",
        "rank": 7, "stratum": "1-1000", "source_url": "https://tail.example/"}
    plan_path = discovered / "plan.json"
    prefix = {key: inputs.reference(head.original.root / name) for key, name in
        (("context", "provenance.json"), ("source_list", "source-list.json"), ("profile", "profile.json"), ("candidate_order", "candidate-order.json"))}
    producer = REPOSITORY / "tools/whole_graph_discovery_v1"
    write(plan_path, {"schema_version": 1, "artifact_type": inputs.PLAN_TYPE, "contract": inputs.CONTRACT,
        "producer_sources": {name: inputs.reference(producer / name) for name in inputs.PRODUCERS},
        "original_prefix": prefix, "candidates": [candidate], "reserved_candidates": [], **inputs.ZERO})
    graph_input = discovered / "whole-graph-input.json"
    discovery_runtime = {"image_digest": "sha256:" + "1" * 64, "role": "synthetic-discovery-fixture"}
    write(graph_input, {"schema_version": 1, "artifact_type": inputs.INPUT_TYPE, "contract": inputs.CONTRACT,
        "plan": inputs.reference(plan_path), "candidate": candidate, "runtime": discovery_runtime,
        "native_manifest": inputs.reference(discovered / "native-input.json"),
        "approved_origin_union": ["https://cdn.example", "https://tail.example"],
        "observed_origins": ["https://cdn.example", "https://tail.example"],
        "resource_graph_sha256": inputs.discovery_digest(neutral["resources"]), "resource_count": 3,
        "completed_at": "2026-10-04T00:00:30Z", "http3_get_performed": False,
        "admission_state": "unqualified-graph-input-only", **inputs.ZERO})
    monkeypatch.setattr(inputs, "_verify_external", lambda *args: None)
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-04T00:00:31Z")
    whole_root = tmp_path / "whole-tail-context"
    whole.initialize_context(whole_root, original_context=head.original.root, plans=[plan_path],
        graph_inputs=[graph_input], expected_runtime=head.original.provenance["runtime_binding"])
    tail = whole.load_context(whole_root)
    primary, full = whole._manifests(neutral)
    write(root / "neutral-input.json", neutral)
    write(root / "native-input.json", full)
    write(root / "bootstrap/native-input.json", primary)
    previous = load(root / "declaration.json")
    declaration = {"schema_version": 1, "record_type": whole.PROOF_TYPE, "declared_at": "2026-10-04T00:00:31Z",
        "context": prep.reference(whole_root / "provenance.json"), "position": 54,
        "candidate_id": candidate["candidate_id"], "domain": candidate["domain"], "graph_input": inputs.reference(graph_input),
        "discovery_runtime": discovery_runtime, "runtime_binding": previous["runtime_binding"], "producer_sources": whole.producer_sources(),
        "neutral_input_sha256": graph.digest(graph.canonical_bytes(neutral)),
        "bootstrap_input_sha256": graph.digest(graph.canonical_bytes(primary)), "full_input_sha256": graph.digest(graph.canonical_bytes(full)),
        "max_response_bytes": 16_777_216, **{key: previous[key] for key in ("timeout_seconds", "primary_claim", "public_origin_policy")}, **inputs.ZERO}
    write(root / "declaration.json", declaration)
    for child, policy, start, end in ((root / "bootstrap", bootstrap.STRICT_POLICY, 32, 33),
                                      (root, bootstrap.get.RESPONSE_POLICY, 33, 34)):
        run = load(child / "native/run.json")
        run["max_response_bytes"] = 16_777_216
        run["workload_hash_sha256"] = declaration["bootstrap_input_sha256" if child != root else "full_input_sha256"]
        for response in run["responses"]:
            response["url"] = (primary if child != root else full)["resources"][response["resource_id"]]["url"]
        for name in ("started_unix_ns", "time_anchor_unix_ns", "ended_unix_ns"):
            run[name] += 10_000_000_000
        for endpoint in run["endpoints"]:
            endpoint["origin"] = endpoint["origin"].replace("sample.example", "tail.example")
            endpoint["receive_lifecycle"]["polling_stopped_at_unix_ns"] += 10_000_000_000
        write(child / "native/run.json", run)
        dns = load(child / "dns.json")
        for row in dns["observations"]:
            row["origin"] = row["origin"].replace("sample.example", "tail.example")
            for field in ("started_at", "completed_at"):
                row[field] = (datetime.fromisoformat(row[field]) + timedelta(seconds=10)).isoformat()
        write(child / "dns.json", dns)
        events = child / "native/events.csv"
        events.write_bytes(events.read_bytes().replace(b"sample.example", b"tail.example"))
        started = load(child / "native-started.json")
        started.update(started_at=f"2026-10-04T00:00:{start:02d}Z", declaration_sha256=graph.digest((root / "declaration.json").read_bytes()),
            command=bootstrap._command(child, 16_777_216, 120, policy))
        write(child / "native-started.json", started)
        completed = load(child / "native-completed.json")
        completed["completed_at"] = f"2026-10-04T00:00:{end:02d}Z"
        write(child / "native-completed.json", completed)
        reseal_outputs(child)
    write(root / "full-get-proof.json", whole.build_proof(root, context=tail, position=54))
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-04T00:00:40Z")
    whole.admit(tail, 54, root)
    mixed_root = tmp_path / "mixed-capture-context"
    capture.initialize_context(mixed_root, budget_context=head.root, supplement_context=tail.root)
    mixed = capture.load_context(mixed_root)
    assert mixed.candidates[:53] == head.candidates and mixed.candidates[53]["candidate_id"] == candidate["candidate_id"]
    assert capture.acquisition_status(mixed)["terminal_count"] == 54
    study, capture_runtime = runtime(tmp_path)
    rolling.initialize_study(head.original.root, study, capture_runtime, supplied_static=True)
    with pytest.raises(ValueError, match="homogeneous"):
        rolling.enroll(study, acquisition_root=mixed.root, count=2)
    assert not (study / "batches").exists()
    first = rolling.enroll(study, acquisition_root=mixed.root)
    first_raw = first.read_bytes()
    second = rolling.enroll(study, acquisition_root=mixed.root)
    batch, classes, policy = rolling._verify_enrollment(second)
    assert first.read_bytes() == first_raw and [row["class_index"] for row in classes] == [1, 2]
    assert rolling._effective_capture_limits(batch, classes, policy) == static.capture_limits(16_777_216, 64)
    for relative in amendment.authority_files().values():
        target = Path(capture_runtime["runtime_source_root"]) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    output = study / "whole-tail-front-amendment.json"
    amendment.publish_amendment(second, capture_runtime, output, front_policy=amendment.old.capture.FRONT_RESERVE_POLICY)
    closed = amendment.validate_amendment(output, enrollment=second, runtime=capture_runtime)
    assert closed["capture_limits"] == static.capture_limits(16_777_216, 64)
    assert closed["workloads"][0]["original_data_role"] == whole.ROLE
    _, derived = capture.prepared_workload(mixed, rolling._open_ref(classes[-1]["terminal"]))
    assert derived["resources"][1]["url"] == derived["resources"][2]["url"] and derived["resources"][2]["depends_on"] == [1]


def test_new_budget_buflo200_binds_four_traffic_files_and_keeps_per_class_response_recording_limits(admitted_budget, tmp_path):
    from qcsd_lab import rapid_capture_traffic as traffic
    from qcsd_lab import buflo_duration_budget as duration
    context, _, _, _ = admitted_budget
    study, inputs = runtime(tmp_path)
    rolling.initialize_study(context.original.root, study, inputs, supplied_static=True)
    enrollment = rolling.enroll(study, acquisition_root=context.root)
    for relative in amendment.authority_files(duration.POLICY).values():
        target = Path(inputs["runtime_source_root"]) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    for key in ("runtime_source_root", "execution_root"):
        for relative, _ in traffic.files(duration.POLICY).values():
            target = Path(inputs[key]) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPOSITORY / relative).read_bytes())
    output = study / "buflo200-amendment.json"
    amendment.publish_amendment(enrollment, inputs, output,
        buflo_policy=amendment.old.capture.BUFLO_KERNEL_PREPARATION_POLICY, buflo_duration_policy=duration.POLICY)
    closed = amendment.validate_amendment(output, enrollment=enrollment, runtime=inputs)
    assert closed["modes"] == ["buflo"] and closed[traffic.FIELD] == duration.POLICY
    assert len(closed["traffic_artifacts"]) == 2 and closed["capture_limits"] == static.capture_limits(budget.RESPONSE_BYTES, 256)
    row = closed["workloads"][0]
    derived = load(prep.open_reference(row["capture_manifest"]))
    manifest.validate_research_preparation(derived, workload_id=row["workload_id"])
    site = rolling.plan.Site(row["candidate_id"], row["workload_id"], row["capture_manifest"]["sha256"],
        derived["preparation"]["approved_origins"][0], "fixture", "a" * 64)
    lanes = rolling.plan.plan_lanes([site], final=True, study_version=6, rolling_batch=1)
    lane = next(value for value in lanes if value.mode == "buflo")
    policy = rolling.verify_policy(study)
    campaign = yaml.safe_load(rolling._render_campaign(lane, [site], policy,
        capture_limits=closed["capture_limits"], buflo_duration_policy=duration.POLICY))
    assert campaign["limits"]["max_response_bytes"] == budget.RESPONSE_BYTES
    assert campaign["limits"]["capture_megabytes"] == 256
    assert campaign["limits"] == duration.capture_limits("buflo", closed["capture_limits"], policy=duration.POLICY)
