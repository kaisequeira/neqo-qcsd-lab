"""HOST emitter-contract fixtures; no discovery, HTTP3, installed image or credit.

Only the separately tested external discovery subprocess is substituted in the
synthetic integration fixture. Native process/output/DNS/resource proof checks,
typed context order, preparation reconstruction and old static roles are real.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import application_response_policy as app
from qcsd_lab import manifest
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_get as get
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as prep
from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab import whole_graph_capture_amendment as amendment
from tests.test_supplied_static_get import actual_contract_fixture, load, write, reseal_outputs
from tests.test_supplied_static_preparation import fixed_graph, runtime as capture_runtime

REPOSITORY = Path(__file__).parents[1]
HELD_PRODUCER = REPOSITORY / "tools/whole_graph_discovery_v1"


def rows():
    def row(i, url, edges, headers):
        return {"id": i, "url": url, "type": "Document" if i == 0 else "Other", "content_length": None,
            "data_length": 0, "known_valid": False, "chaff_priority": False, "depends_on": edges, "headers": headers}
    return [row(0, "https://a.example/", [], []),
        row(1, "https://b.example/repeat?q=exact", [0], [["accept", "image/*"]]),
        row(2, "https://b.example/repeat?q=exact", [1], [["accept", "image/*"]]),
        row(3, "https://a.example/script", [0, 2], [["x-label", "café"]])]


def test_projection_preserves_all_occurrences_dag_queries_headers_and_unused_approved_origins():
    data = rows()
    union = ["https://a.example", "https://b.example", "https://previous-pass.example"]
    envelope = {"approved_origin_union": union, "resource_graph_sha256": inputs.discovery_digest(data), "resource_count": 4}
    result = inputs.project(envelope, {"resources": data})
    assert result["resources"] == data
    assert result["resources"][1]["url"] == result["resources"][2]["url"]
    assert result["resources"][3]["depends_on"] == [0, 2]
    result["resources"][1]["headers"][0][1] = "changed"
    assert data[1]["headers"][0][1] == "image/*" and envelope["approved_origin_union"] == union


@pytest.mark.parametrize("change", ["missing-occurrence", "future-edge", "bool-id", "known-valid", "foreign-origin", "changed-header"])
def test_projection_rejects_pruning_or_changed_graph_identity(change):
    data = rows()
    envelope = {"approved_origin_union": ["https://a.example", "https://b.example"],
        "resource_graph_sha256": inputs.discovery_digest(data), "resource_count": 4}
    if change == "missing-occurrence": data.pop()
    elif change == "future-edge": data[1]["depends_on"] = [3]
    elif change == "bool-id": data[0]["id"] = False
    elif change == "known-valid": data[0]["known_valid"] = True
    elif change == "foreign-origin": data[1]["url"] = "https://foreign.example/r"
    else: data[2]["headers"][0][1] = "changed"
    with pytest.raises(ValueError): inputs.project(envelope, {"resources": data})


def test_reference_modes_leaf_symlinks_and_unrecognized_producer_fail_before_execution(tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    write(path, {"data": True})
    reference = inputs.reference(path)
    path.chmod(0o444)
    with pytest.raises(ValueError): inputs.reopen(reference)
    link = tmp_path / "alias.json"
    link.symlink_to(path)
    with pytest.raises(ValueError): inputs.reference(link)
    monkeypatch.setattr(inputs.subprocess, "run", lambda *a, **k: pytest.fail("unknown Source must not execute"))
    with pytest.raises(ValueError): inputs._producer({"producer_sources": {name: inputs.reference(path) for name in inputs.PRODUCERS}})


def test_external_reopener_uses_only_isolated_host_action_and_rejects_nonzero(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "secret-image")
    monkeypatch.setenv("PYTHONPATH", "ambient-source")
    def invoke(argv, **kwargs):
        seen.append((argv, kwargs))
        return SimpleNamespace(returncode=1, stdout=b"private", stderr=b"private")
    monkeypatch.setattr(inputs.subprocess, "run", invoke)
    with pytest.raises(ValueError, match="independent whole graph discovery reopening failed"):
        inputs._verify_external(tmp_path / "operator.py", "verify-input", "--input", tmp_path / "input.json")
    argv, kwargs = seen[0]
    assert argv[1:3] == ["-I", "-B"] and argv[4:6] == ["verify-input", "--input"]
    assert "QCSD_LAB_IMAGE_DIGEST" not in kwargs["env"] and "PYTHONPATH" not in kwargs["env"]
    assert kwargs["timeout"] == 60 and kwargs["check"] is False


@pytest.mark.parametrize("version", [1, 2, 3])
def test_reviewed_producer_versions_are_portable_tracked_exact_bytes(version):
    kind = {1: inputs.PLAN_TYPE, 2: inputs.SEEDED_PLAN_TYPE, 3: inputs.CATALOGUE_PLAN_TYPE}[version]
    spec = inputs.VERSIONS[kind]
    package = REPOSITORY / "tools" / ("whole_graph_discovery_v" + str(version))
    value = {"schema_version": spec[0], "artifact_type": kind, "contract": spec[1],
        "producer_sources": {name: inputs.reference(package / name) for name in spec[3]}}
    assert inputs._producer(value) == package / "operator.py"
    assert all(inputs.reference(package / name)["sha256"] == digest for name, digest in spec[3].items())


@pytest.fixture
def supplemented(fixed_graph, tmp_path, monkeypatch):
    root, old_arguments, old_context = fixed_graph
    # Separate synthetic original prefix: no original class is silently
    # replaced by the supplemental candidate's sample.example graph.
    source = tmp_path / "prefix-source.json"
    write(source, [{"crUX_domain": "original.example", "resources": []}])
    prefix_root = tmp_path / "original-prefix"
    prefix_root.mkdir()
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-03T23:59:56Z")
    static.initialize_context(prefix_root, source, source_sha256=graph.digest(source.read_bytes()),
        expected_runtime=old_arguments["expected_runtime"])
    prefix = static.load_context(prefix_root)
    static.record_input_rejection(prefix, 1)
    candidate = {"catalogue_position": 7, "candidate_id": "tranco-0000007", "domain": "sample.example",
        "rank": 7, "stratum": "1-1000", "source_url": "https://sample.example/"}
    neutral = load(root / "neutral-input.json")
    for resource in neutral["resources"]:
        resource.update(content_length=None, data_length=0, known_valid=False, chaff_priority=False)
    neutral["resources"][2]["url"] = neutral["resources"][1]["url"]
    neutral["resources"][2]["depends_on"] = [1]
    input_root = tmp_path / "synthetic-discovery"
    input_root.mkdir()
    write(input_root / "native-input.json", neutral)
    plan_path = input_root / "plan.json"
    original_prefix = {key: inputs.reference(prefix_root / name) for key, name in
        (("context", "provenance.json"), ("source_list", "source-list.json"), ("profile", "profile.json"), ("candidate_order", "candidate-order.json"))}
    plan = {"schema_version": 1, "artifact_type": inputs.PLAN_TYPE, "contract": inputs.CONTRACT,
        "producer_sources": {name: inputs.reference(HELD_PRODUCER / name) for name in inputs.PRODUCERS},
        "original_prefix": original_prefix, "candidates": [candidate], "reserved_candidates": [], **inputs.ZERO}
    write(plan_path, plan)
    envelope = {"schema_version": 1, "artifact_type": inputs.INPUT_TYPE, "contract": inputs.CONTRACT, "plan": inputs.reference(plan_path),
        "candidate": candidate, "runtime": {"image_digest": "sha256:" + "1" * 64, "role": "synthetic-discovery-fixture"},
        "native_manifest": inputs.reference(input_root / "native-input.json"), "approved_origin_union": ["https://cdn.example", "https://sample.example"],
        "observed_origins": ["https://cdn.example", "https://sample.example"], "resource_graph_sha256": inputs.discovery_digest(neutral["resources"]),
        "resource_count": 3, "completed_at": "2026-10-03T23:59:58Z", "http3_get_performed": False,
        "admission_state": "unqualified-graph-input-only", **inputs.ZERO}
    input_path = input_root / "whole-graph-input.json"
    write(input_path, envelope)
    # Only independently reviewed external-producer execution is substituted.
    monkeypatch.setattr(inputs, "_verify_external", lambda *args: None)
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-03T23:59:59Z")
    context_root = tmp_path / "supplement-context"
    whole.initialize_context(context_root, original_context=prefix_root, plans=[plan_path], graph_inputs=[input_path],
        expected_runtime=old_arguments["expected_runtime"])
    context = whole.load_context(context_root)
    primary, full = whole._manifests(neutral)
    write(root / "neutral-input.json", neutral)
    write(root / "native-input.json", full)
    write(root / "bootstrap/native-input.json", primary)
    old_declaration = load(root / "declaration.json")
    declaration = {"schema_version": 1, "record_type": whole.PROOF_TYPE, "declared_at": old_declaration["declared_at"],
        "context": prep.reference(context_root / "provenance.json"), "position": 2, "candidate_id": candidate["candidate_id"],
        "domain": candidate["domain"], "graph_input": inputs.reference(input_path), "discovery_runtime": envelope["runtime"],
        "runtime_binding": old_arguments["expected_runtime"], "producer_sources": whole.producer_sources(),
        "neutral_input_sha256": graph.digest(graph.canonical_bytes(neutral)), "bootstrap_input_sha256": graph.digest(graph.canonical_bytes(primary)),
        "full_input_sha256": graph.digest(graph.canonical_bytes(full)),
        **{key: old_declaration[key] for key in ("max_response_bytes", "timeout_seconds", "primary_claim", "public_origin_policy")}, **inputs.ZERO}
    write(root / "declaration.json", declaration)
    run = load(root / "native/run.json")
    run["workload_hash_sha256"] = declaration["full_input_sha256"]
    run["responses"][2]["url"] = neutral["resources"][2]["url"]
    write(root / "native/run.json", run)
    first_run = load(root / "bootstrap/native/run.json")
    first_run["workload_hash_sha256"] = declaration["bootstrap_input_sha256"]
    write(root / "bootstrap/native/run.json", first_run)
    for child in (root, root / "bootstrap"):
        started = load(child / "native-started.json")
        started["declaration_sha256"] = graph.digest((root / "declaration.json").read_bytes())
        write(child / "native-started.json", started)
        reseal_outputs(child)
    proof = whole.build_proof(root, context=context, position=2)
    write(root / "full-get-proof.json", proof)
    monkeypatch.setattr(static.receipts, "_now", lambda: "2026-10-04T00:00:20Z")
    return root, context, input_path


def test_separate_discovery_get_runtime_full_raw_preparation_and_native_projection(supplemented):
    root, context, _ = supplemented
    proof = whole.reopen_get(root, context=context, position=2)
    assert proof["discovery_runtime"]["image_digest"] != proof["runtime_binding"]["image_digest"]
    result = whole.build_preparation(root, context=context, position=2)
    manifest.validate_research_preparation(result, workload_id="supplement")
    app.validate_primary_document_identity_evidence(result)
    app.validate_application_response_policy_evidence(result)
    runtime = manifest.runtime_manifest(result)
    assert runtime["resources"][1]["url"] == runtime["resources"][2]["url"]
    assert runtime["resources"][2]["depends_on"] == [1]
    assert [row["headers"] for row in result["resources"]] == [row["headers"] for row in load(root / "neutral-input.json")["resources"]]
    assert not proof["scientific_credit"] and proof["formal_accepted_trace_count"] == 0


@pytest.mark.parametrize("key", ["graph_input", "discovery_runtime", "runtime_binding", "producer_sources", "position"])
def test_complete_get_rejects_foreign_input_runtime_source_or_queue_position(supplemented, key):
    root, context, _ = supplemented
    value = load(root / "declaration.json")
    value[key] = {} if key != "position" else True
    write(root / "declaration.json", value)
    with pytest.raises(ValueError): whole.build_proof(root, context=context, position=2)


def test_typed_admission_keeps_original_prefix_and_shared_rolling_identity(supplemented):
    root, context, _ = supplemented
    old = context.original
    before = (old.root / "provenance.json").read_bytes()
    terminal = whole.admit(context, 2, root)
    facts = whole.verify_terminal(terminal, context)
    assert facts["outcome"] == "admitted" and facts["data_role"] == whole.ROLE
    assert whole.identity(context) == static.identity(old) == rolling._admission_identity(context)
    assert rolling._context_for_policy({"contract": rolling.STATIC_CONTRACT}, context.root).root == context.root
    assert len(whole.acquisition_status(context)["terminal_prefix"]) == 2
    assert (old.root / "provenance.json").read_bytes() == before
    with pytest.raises(FileExistsError): whole.admit(context, 2, root)
    with pytest.raises(ValueError): whole.execute_get(context.root, 1, root.parent / "invalid-original-reinterpretation")


def test_graph_input_does_not_grant_admission_and_host_cannot_execute_get(supplemented, monkeypatch):
    root, context, input_path = supplemented
    monkeypatch.delenv("QCSD_LAB_IMAGE_DIGEST", raising=False)
    monkeypatch.delenv("QCSD_LAB_SOURCE_METADATA", raising=False)
    target = root.parent / "host-get-forbidden"
    with pytest.raises(ValueError): whole.execute_get(context.root, 2, target)
    assert not target.exists()
    assert load(input_path)["admission_state"] == "unqualified-graph-input-only"
    with pytest.raises(ValueError): whole.record_deferral(context, 2, get_root=root)


def test_source_corruption_blocks_instead_of_inventing_site_deferral(supplemented):
    root, context, _ = supplemented
    value = load(root / "runtime.json")
    value["source_manifest_text"] += "changed"
    write(root / "runtime.json", value)
    with pytest.raises(ValueError): whole.record_deferral(context, 2, get_root=root)
    assert not whole.terminal_path(context, 2).exists()


def test_closed_get_non_html_primary_is_accounted_without_admission_or_pruning(supplemented):
    root, context, _ = supplemented
    run = load(root / "native/run.json")
    run["responses"][0]["response_headers"][-1] = ["content-type", "application/json"]
    write(root / "native/run.json", run)
    reseal_outputs(root)
    write(root / "full-get-proof.json", whole.build_proof(root, context=context, position=2))
    terminal = whole.record_deferral(context, 2, get_root=root)
    facts = whole.verify_terminal(terminal, context)
    assert facts["outcome"] == "operational-deferred" and facts["admission"] is None
    assert len(load(root / "neutral-input.json")["resources"]) == 3
    assert not load(terminal)["payload"]["scientific_credit"]


def test_mixed_amendment_derivation_keeps_whole_graph_old_evidence_and_explicit_new_role(supplemented):
    root, context, _ = supplemented
    original = whole.build_preparation(root, context=context, position=2)
    reference = {"path": "/prospective/declaration.json", "sha256": "a" * 64}
    selected = amendment.old.policies(front_policy=amendment.old.capture.FRONT_RESERVE_POLICY)
    derived = amendment._derived(original, reference, selected, None)
    assert derived["resources"] == original["resources"]
    assert derived["preparation"]["whole_graph_get_evidence"] == original["preparation"]["whole_graph_get_evidence"]
    assert derived["preparation"]["data_role"] == amendment.ROLE
    assert amendment.old.is_amended(derived["preparation"])
    assert amendment.authority_files().items() >= amendment.old.SOURCE_FILES.items()


def test_version2_retry_preserves_original_reservation_slots_and_all_prior_input_refs(supplemented, monkeypatch):
    _, context, input_path = supplemented
    original_path = input_path.with_name("plan.json")
    original_value = load(original_path)
    second = dict(original_value["candidates"][0], candidate_id="tranco-0000008", domain="another.example", catalogue_position=8,
                  source_url="https://another.example/")
    original_value["candidates"].append(second)
    write(original_path, original_value)
    package = REPOSITORY / "tools/whole_graph_discovery_v2"
    retry = {**copy.deepcopy(original_value), "schema_version": 2, "artifact_type": inputs.SEEDED_PLAN_TYPE,
        "contract": inputs.SEEDED_CONTRACT, "reserved_candidates": original_value["candidates"],
        "producer_sources": {name: inputs.reference(package / name) for name in inputs.SEEDED_PRODUCERS},
        "retry": {"original_plan": inputs.reference(original_path), "retry_original_indices": [1, 2],
                  "new_catalogue_reservations": False, "prior_outcomes_reclassified": False}}
    tail = whole._plan_rows([original_value, retry], context.original)
    assert len(tail) == 2 and [row["position"] for row in tail] == [2, 3]
    assert [row["catalogue_candidate"] for row in tail] == original_value["candidates"]
    changed = copy.deepcopy(retry)
    changed["candidates"].reverse()
    with pytest.raises(ValueError): whole._plan_rows([original_value, changed], context.original)
    with pytest.raises(ValueError): whole._plan_rows([retry], context.original)


def test_public_mixed_enrollment_and_serial_all_five_mode_plan_preserve_full_new_graph(supplemented, tmp_path, monkeypatch):
    root, context, _ = supplemented
    whole.admit(context, 2, root)
    study, runtime = capture_runtime(tmp_path)
    rolling.initialize_study(context.original.root, study, runtime, supplied_static=True)
    enrollment = rolling.enroll(study, acquisition_root=context.root)
    batch, classes = rolling.verify_enrollment(enrollment)
    assert [row["outcome"] for row in batch["decisions"]] == ["input-ineligible", "admitted"]
    assert classes[0]["class_index"] == 1 and len(classes) == 1
    path, workload = whole.prepared_workload(context, rolling._open_ref(classes[0]["terminal"]))
    target = Path(runtime["workload_root"]) / path.name
    target.write_bytes(path.read_bytes())
    sidecars = study / "qualification"
    sidecars.mkdir()
    write(sidecars / "_qualification-set.json", {"external_qualification_primitive": "synthetic HOST seam only"})
    qualifier = study / "qualifier.json"
    write(qualifier, {"schema_version": 1, "qualification_sets": [{"qualification_set": "fixture", "manifest": str(sidecars / "_qualification-set.json"),
        "sidecar_root": str(sidecars), "prefix_spec_root": None}]})
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", lambda *a, **k: None)
    from qcsd_lab import rapid_rolling_readiness as readiness
    monkeypatch.setattr(readiness, "validate_canary", lambda *a, **k: {})
    output = study / "plan.json"
    rolling.publish_plan(study, enrollment, qualifier, output, readiness={"undefended": {"synthetic_canary": True}})
    spec = rolling.capture_spec(study, enrollment, qualifier, output)
    _, payload = rolling.verify_capture_plan(spec)
    assert payload["planned_trace_count"] == 320 and len(payload["lanes"]) == 80
    assert set(lane["mode"] for lane in payload["lanes"]) == set(rolling.plan.MODES)
    assert rolling.verify_policy(study)["formal_trace_target"] == 16000
    assert load(target)["resources"] == workload["resources"]


def test_whole_context_init_static_policy_uses_exact_original_identity_and_budgets(supplemented, tmp_path):
    _, context, _ = supplemented
    study, runtime = capture_runtime(tmp_path)
    rolling.initialize_study(context.root, study, runtime, supplied_static=True)
    policy = rolling.verify_policy(study)
    assert policy["admission_identity"] == static.identity(context.original)
    assert policy["capture_limits"] == static.context_limits(context.original)
    assert policy["class_target"] == 50 and policy["formal_trace_target"] == 16000


def test_accounted_decision_rejects_another_get_before_installed_runtime_or_output(supplemented, tmp_path):
    root, context, _ = supplemented
    whole.admit(context, 2, root)
    target = tmp_path / "redundant-get"
    with pytest.raises(ValueError, match="already accounted"):
        whole.execute_get(context.root, 2, target)
    assert not target.exists()


def test_failed_only_get_namespace_requires_actual_nonzero_outer_and_retains_raw_failure(supplemented, tmp_path, monkeypatch):
    from tests.test_supplied_static_preparation import mapped
    root, context, _ = supplemented
    _, outer = mapped((root, {"expected_runtime": context.provenance["runtime_binding"]}, context.original), tmp_path)
    completion = load(root / "native-completed.json")
    completion["returncode"] = 1
    write(root / "native-completed.json", completion)
    outer_completion = load(outer / "completed.json")
    outer_completion["returncode"] = 1
    write(outer / "completed.json", outer_completion)
    arguments = {"started": outer / "started.json", "completed": outer / "completed.json",
        "stdout": outer / "stdout", "stderr": outer / "stderr", "expected_runtime": context.provenance["runtime_binding"]}
    execution = Path("/evidence") / root.name
    mapping = whole.namespace_mapping(root, execution, **arguments, failed_phase="full")
    failure = whole.failure_proof(root, context=context, position=2, namespace=mapping)
    assert failure["phase"] == "full" and failure["outcome"] == "operational-deferred"
    assert inputs.reopen(failure["files"]["native-completed.json"]) == root / "native-completed.json"
    with pytest.raises(ValueError, match="closed actual outer"):
        whole.namespace_mapping(root, execution, **arguments)
    terminal = whole.record_deferral(context, 2, get_root=root, namespace=mapping)
    assert whole.verify_terminal(terminal, context)["admission"] is None
    # The synthetic discovery fixture substitutes only the external producer's
    # graph roots. Context/terminal/GET/namespace validators remain actual.
    monkeypatch.setattr(inputs, "plan_roots", lambda path: [path.parent])
    monkeypatch.setattr(inputs, "roots", lambda path: [path.parent])
    successor_root = tmp_path / "successor-context"
    whole.initialize_context(successor_root, original_context=context.original.root,
        plans=[inputs.reopen(ref) for ref in context.provenance["plans"]],
        graph_inputs=[inputs.reopen(ref) for ref in context.provenance["graph_inputs"].values()],
        expected_runtime=context.provenance["runtime_binding"], parent_context=context.root)
    later_mutable = tmp_path / "later-mutable-attempt"
    later_mutable.mkdir()
    reads, read = set(), get._read

    def observed(path):
        if path.is_relative_to(tmp_path):
            reads.add(path)
        return read(path)

    monkeypatch.setattr(get, "_read", observed)
    successor = whole.load_context(successor_root)
    dependency_roots = whole.sealed_context_roots(successor)
    assert root in dependency_roots and outer in dependency_roots
    assert reads and all(any(path.is_relative_to(parent) for parent in dependency_roots) for path in reads)
    assert not any(later_mutable.is_relative_to(parent) for parent in dependency_roots)
    assert root in whole.roots(successor) and outer in whole.roots(successor)
    outer_completion["returncode"] = 0
    write(outer / "completed.json", outer_completion)
    with pytest.raises(ValueError):
        whole.verify_terminal(terminal, context)


def test_public_current_mixed_front_amendment_reopens_complete_get_and_rejects_source_or_graph_mutation(supplemented, tmp_path):
    root, context, _ = supplemented
    whole.admit(context, 2, root)
    study, runtime = capture_runtime(tmp_path)
    rolling.initialize_study(context.original.root, study, runtime, supplied_static=True)
    enrollment = rolling.enroll(study, acquisition_root=context.root)
    source = Path(runtime["runtime_source_root"])
    for relative in amendment.authority_files().values():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    changed_authority = source / amendment.ADAPTER_FILES["whole_graph_input"]
    changed_authority.write_bytes(changed_authority.read_bytes() + b"\n")
    output = study / "front-amendment.json"
    with pytest.raises(ValueError, match="actual current frozen Source"):
        amendment.publish_amendment(enrollment, runtime, output, front_policy=amendment.old.capture.FRONT_RESERVE_POLICY)
    assert not output.exists() and not output.with_name("front-amendment-declaration.json").exists()
    changed_authority.write_bytes((REPOSITORY / amendment.ADAPTER_FILES["whole_graph_input"]).read_bytes())
    from qcsd_lab import supplied_static_capture_amendment as dispatcher
    dispatcher.publish_amendment(enrollment, runtime, output, front_policy=amendment.old.capture.FRONT_RESERVE_POLICY)
    closed = dispatcher.validate_amendment(output, enrollment=enrollment, runtime=runtime)
    assert closed["modes"] == ["front"]
    assert closed["workloads"][0]["original_data_role"] == whole.ROLE
    original_path = rolling._open_ref(closed["workloads"][0]["original_manifest"])
    derived_path = rolling._open_ref(closed["workloads"][0]["capture_manifest"])
    original_value, derived = load(original_path), load(derived_path)
    assert original_path != derived_path and original_value["resources"] == derived["resources"]
    assert whole.validate_preparation(original_value["preparation"], original_value["resources"])["resource_count"] == 3
    assert dispatcher.validate_preparation(derived["preparation"], derived["resources"])["resource_count"] == 3
    derived["resources"][2]["depends_on"] = [0]
    write(derived_path, derived)
    with pytest.raises(ValueError, match="pruned or changed"):
        dispatcher.validate_amendment(output, enrollment=enrollment, runtime=runtime)

def test_version3_next_queue_appends_after_retry_without_reusing_reserved_slots(supplemented):
    _, context, input_path = supplemented
    original_path = input_path.with_name("plan.json")
    original_value = load(original_path)
    retry_package = REPOSITORY / "tools/whole_graph_discovery_v2"
    retry = {**copy.deepcopy(original_value), "schema_version": 2, "artifact_type": inputs.SEEDED_PLAN_TYPE,
        "contract": inputs.SEEDED_CONTRACT, "reserved_candidates": original_value["candidates"],
        "producer_sources": {name: inputs.reference(retry_package / name) for name in inputs.SEEDED_PRODUCERS},
        "retry": {"original_plan": inputs.reference(original_path), "retry_original_indices": [1],
                  "new_catalogue_reservations": False, "prior_outcomes_reclassified": False}}
    new_candidate = dict(original_value["candidates"][0], candidate_id="tranco-0000008",
        domain="next.example", catalogue_position=8, source_url="https://next.example/")
    package = REPOSITORY / "tools/whole_graph_discovery_v3"
    next_plan = {**copy.deepcopy(original_value), "schema_version": 3, "artifact_type": inputs.CATALOGUE_PLAN_TYPE,
        "contract": inputs.CATALOGUE_CONTRACT, "reserved_candidates": original_value["candidates"],
        "candidates": [new_candidate],
        "producer_sources": {name: inputs.reference(package / name) for name in inputs.CATALOGUE_PRODUCERS}}
    tail = whole._plan_rows([original_value, retry, next_plan], context.original)
    assert [row["position"] for row in tail] == [2, 3]
    assert [row["catalogue_candidate"] for row in tail] == [*original_value["candidates"], new_candidate]
    changed = copy.deepcopy(next_plan)
    changed["reserved_candidates"] = []
    with pytest.raises(ValueError, match="earlier declared"):
        whole._plan_rows([original_value, retry, changed], context.original)
    changed = copy.deepcopy(next_plan)
    changed["candidates"] = original_value["candidates"]
    with pytest.raises(ValueError, match="repeats"):
        whole._plan_rows([original_value, retry, changed], context.original)


def _synthetic_discovery_inventory(monkeypatch):
    # The external verifier is already substituted by this fixture. Supply
    # its finite file inventory, while retaining actual context/GET/Source
    # reconstruction and OperationFacts byte/mode checks.
    monkeypatch.setattr(inputs, "plan_files", lambda path: ([path], [HELD_PRODUCER]))
    monkeypatch.setattr(inputs, "input_files",
        lambda path: ([path, inputs.reopen(load(path)["native_manifest"])], [HELD_PRODUCER]))


def test_whole_operation_fence_ignores_later_context_attempts_but_rejects_changed_raw_get(supplemented, tmp_path, monkeypatch):
    from qcsd_lab.rapid_operation_facts import OperationFacts
    root, context, input_path = supplemented
    _synthetic_discovery_inventory(monkeypatch)
    workload_path = tmp_path / "operation-workload.json"
    write(workload_path, whole.build_preparation(root, context=context, position=2))
    facts = OperationFacts()
    trees = facts._workload_evidence_trees(workload_path)
    assert root in trees and context.root not in trees and input_path.parent not in trees
    assert context.root / "provenance.json" in facts._files
    assert inputs.reopen(load(input_path)["native_manifest"]) in facts._files
    for tree in trees:
        facts.watch_tree(tree)
    later = context.root / "attempts" / "candidate-999999"
    later.mkdir(parents=True)
    write(later / "later-mutable.json", {"no_previous_evidence_credit": True})
    write(input_path.parent / "later-closed-input.json", {"other_candidate": True})
    facts.check()
    (root / "native.stdout.log").write_bytes(b"changed actual raw GET")
    with pytest.raises(ValueError, match="dependency tree"):
        facts.check()


def test_mixed_operation_fence_binds_declaration_file_without_watching_mutable_parent(supplemented, tmp_path, monkeypatch):
    from qcsd_lab.rapid_operation_facts import OperationFacts
    root, context, _ = supplemented
    _synthetic_discovery_inventory(monkeypatch)
    whole.admit(context, 2, root)
    study, runtime = capture_runtime(tmp_path)
    rolling.initialize_study(context.original.root, study, runtime, supplied_static=True)
    enrollment = rolling.enroll(study, acquisition_root=context.root)
    source = Path(runtime["runtime_source_root"])
    for relative in amendment.authority_files().values():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    output = study / "operation-amendment.json"
    amendment.publish_amendment(enrollment, runtime, output,
        front_policy=amendment.old.capture.FRONT_RESERVE_POLICY)
    closed = amendment.validate_amendment(output)
    target = rolling._open_ref(closed["workloads"][0]["capture_manifest"])
    declaration_path = rolling._open_ref(closed["declaration"])
    facts = OperationFacts()
    trees = facts._workload_evidence_trees(target)
    assert root in trees and study not in trees and context.root not in trees
    assert declaration_path in facts._files and output in facts._files and enrollment in facts._files
    for tree in trees:
        facts.watch_tree(tree)
    write(study / "other-future-lane-record.json", {"other_lane": True})
    facts.check()
    declaration_path.write_bytes(declaration_path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="dependency bytes"):
        facts.check()


def test_mixed_original_static_namespace_fence_reopens_old_role_and_ignores_other_outer_operations(fixed_graph, tmp_path, monkeypatch):
    from qcsd_lab.rapid_operation_facts import OperationFacts
    from tests.test_supplied_static_preparation import mapped, seal, POLICIES
    get_root, arguments, original_context = fixed_graph
    namespace, outer = mapped(fixed_graph, tmp_path)
    seal(get_root, **arguments, namespace=namespace)
    static.admit(original_context, 1, get_root, policies=POLICIES, namespace=namespace)
    discovery = tmp_path / "additional-declaration"
    discovery.mkdir()
    plan_path = discovery / "plan.json"
    prefix = {key: inputs.reference(original_context.root / name) for key, name in (
        ("context", "provenance.json"), ("source_list", "source-list.json"),
        ("profile", "profile.json"), ("candidate_order", "candidate-order.json"))}
    candidate = {"catalogue_position": 8, "candidate_id": "tranco-0000008", "domain": "new.example",
        "rank": 8, "stratum": "1-1000", "source_url": "https://new.example/"}
    write(plan_path, {"schema_version": 1, "artifact_type": inputs.PLAN_TYPE, "contract": inputs.CONTRACT,
        "producer_sources": {name: inputs.reference(HELD_PRODUCER/name) for name in inputs.PRODUCERS},
        "original_prefix": prefix, "reserved_candidates": [], "candidates": [candidate], **inputs.ZERO})
    monkeypatch.setattr(inputs, "_verify_external", lambda *args: None)
    _synthetic_discovery_inventory(monkeypatch)
    context_root = tmp_path / "mixed-original-context"
    whole.initialize_context(context_root, original_context=original_context.root, plans=[plan_path],
        graph_inputs=[], expected_runtime=arguments["expected_runtime"])
    study, runtime = capture_runtime(tmp_path)
    rolling.initialize_study(original_context.root, study, runtime, supplied_static=True)
    enrollment = rolling.enroll(study, acquisition_root=context_root)
    source = Path(runtime["runtime_source_root"])
    for relative in amendment.authority_files().values():
        target = source/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY/relative).read_bytes())
    output = study/"mixed-original-amendment.json"
    amendment.publish_amendment(enrollment, runtime, output,
        front_policy=amendment.old.capture.FRONT_RESERVE_POLICY)
    closed = amendment.validate_amendment(output)
    assert closed["workloads"][0]["original_data_role"] == prep.ROLE
    target = rolling._open_ref(closed["workloads"][0]["capture_manifest"])
    facts = OperationFacts()
    trees = facts._workload_evidence_trees(target)
    assert get_root in trees and outer not in trees
    assert original_context.root/"provenance.json" in facts._files
    for name in ("started.json", "completed.json", "stdout", "stderr"):
        assert outer/name in facts._files
    for tree in trees:
        facts.watch_tree(tree)
    write(outer/"other-operation.json", {"other_closed_operation": True})
    facts.check()
    (outer/"stderr").write_bytes(b"changed actual prior operation")
    with pytest.raises(ValueError, match="dependency bytes"):
        facts.check()
