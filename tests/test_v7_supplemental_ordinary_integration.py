"""V7/current ordinary integration with explicit HOST primitive boundaries.

Original external browser verifier, original class-selection audit process,
installed runtime and capture/packet canary are controlled fixtures. The V7
pair/control selection, queue, full Native raw GET reducers, admission, selected
proof, renewal, plan and current Source guards execute unchanged production.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

from qcsd_lab import application_response_policy as app
from qcsd_lab import manifest
from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_ordinary_group_canary as group
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import rapid_undefended_capture as ordinary
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as preparation
from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_supplied_static_get import actual_contract_fixture, load, write, reseal_outputs
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_whole_graph_supplement import supplemented
from tests.test_selected_capture_input import runtime as capture_runtime
from tests.test_whole_graph_external_controls import plan as external_plan

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def continued(supplemented, tmp_path, monkeypatch):
    raw, old, input_path = supplemented
    envelope = load(input_path)
    sample = deepcopy(envelope["candidate"])
    sample["catalogue_position"] = 12
    candidates = [{"catalogue_position": 11, "candidate_id": "tranco-0000011",
        "domain": "failed11.example", "rank": 11, "stratum": "1-1000",
        "source_url": "https://failed11.example/"}, sample]
    candidates += [{"catalogue_position": n, "candidate_id": f"tranco-{n:07d}",
        "domain": f"pending{n}.example", "rank": n, "stratum": "1-1000",
        "source_url": f"https://pending{n}.example/"} for n in (13, 14, 15)]
    old_plan = load(inputs.reopen(envelope["plan"]))
    source_metadata = input_path.parent / "original-browser-source.json"
    write(source_metadata, {"lab_commit": "2b-original-browser-fixture",
                            "native_commit": "c24-original-client-fixture"})
    original = external_plan(4)
    original.update(original_prefix=old_plan["original_prefix"], candidates=candidates,
        reserved_candidates=[], declared_at="2026-10-03T23:59:55Z",
        source_metadata=inputs.reference(source_metadata),
        browser_image="sha256:" + "b" * 64, max_origin_passes=4, **inputs.ZERO)
    original_path = input_path.parent / "original-v4-plan.json"
    write(original_path, original)
    continuation = external_plan(7)
    continuation.update(original_prefix=original["original_prefix"],
        candidates=candidates[1:], reserved_candidates=candidates,
        declared_at="2026-10-03T23:59:56Z", source_metadata=original["source_metadata"],
        browser_image=original["browser_image"], max_origin_passes=4,
        previous_plans=[inputs.reference(original_path)],
        reservation_continuation={"refs": {"original_plan": inputs.reference(original_path)},
            "original_candidate_indices": [2, 3, 4, 5],
            "original_failed_candidate": candidates[0]}, **inputs.ZERO)
    continuation_path = input_path.parent / "continuation-v7-plan.json"
    write(continuation_path, continuation)
    failure_root = tmp_path / "retained-failed11"
    failure_root.mkdir()
    (failure_root / "image-source-metadata.json").write_bytes(source_metadata.read_bytes())
    write(failure_root / "started.json", {"schema_version": 1,
        "plan": inputs.reference(original_path), "candidate": candidates[0],
        "started_at": "2026-10-03T23:59:56Z", "runtime": {
            "image_digest": original["browser_image"], "source_metadata": load(source_metadata),
            "installed_metadata_sha256": graph.digest(source_metadata.read_bytes()),
            "execution_role": "actual-browser-image-navigation-seeded-graph-input-only-v4"},
        **inputs.ZERO})
    failure_path = failure_root / "failed.json"
    write(failure_path, {"schema_version": 1, "plan": inputs.reference(original_path),
        "candidate": candidates[0], "completed_at": "2026-10-03T23:59:57Z",
        "elapsed_ns": 1, "error_type": "RecoverableAcquisitionError",
        "message": "controlled original failed seed", "traceback": "HOST fixture",
        "completed_passes": [], "completed_navigation": None,
        "failure_stage": "navigation", "outcome": "operational-discovery-failure-no-admission",
        **inputs.ZERO})
    spec = inputs.VERSIONS[inputs.CONTINUATION_PLAN_TYPE]
    envelope.update(schema_version=7, artifact_type=spec[2], contract=spec[1],
        plan=inputs.reference(continuation_path), candidate=sample,
        runtime={"image_digest": original["browser_image"],
            "external_discovery_control": continuation["discovery_control"],
            "execution_role": "actual-browser-image-navigation-seeded-graph-input-only-v7"})
    write(input_path, envelope)
    # The inherited fixture controls only the original external verifier.
    assert inputs._producer(continuation).parent == ROOT / "tools/whole_graph_discovery_v7"
    before = (old.original.root / "provenance.json").read_bytes()
    context_root = tmp_path / "current-v7-context"
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-03T23:59:59Z")
    whole.initialize_context(context_root, original_context=old.original.root,
        plans=[original_path, continuation_path], graph_inputs=[input_path],
        failed_discoveries=[failure_path], expected_runtime=old.provenance["runtime_binding"])
    context = whole.load_context(context_root)
    assert before == (old.original.root / "provenance.json").read_bytes()
    declaration = load(raw / "declaration.json")
    declaration.update(context=preparation.reference(context_root / "provenance.json"),
        position=3, graph_input=inputs.reference(input_path), discovery_runtime=envelope["runtime"])
    write(raw / "declaration.json", declaration)
    for child in (raw, raw / "bootstrap"):
        started = load(child / "native-started.json")
        started["declaration_sha256"] = graph.digest((raw / "declaration.json").read_bytes())
        write(child / "native-started.json", started)
        reseal_outputs(child)
    write(raw / "full-get-proof.json", whole.build_proof(raw, context=context, position=3))
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:00:20Z")
    whole.record_deferral(context, 2)
    terminal = whole.admit(context, 3, raw)
    return {"raw": raw, "context": context, "input": input_path,
        "terminal": terminal, "candidate": sample, "original": original_path,
        "continuation": continuation_path, "failed": failure_path}


def selection_audit(case, source, directory):
    """Record the exact old audit ABI; its isolated process is synthetic."""
    directory.mkdir()
    context, terminal = case["context"], case["terminal"]
    path, _ = whole.prepared_workload(context, terminal)
    row = {"candidate": context.candidates[2], "manifest": rolling._ref(path),
        "terminal": rolling._ref(terminal), "context": rolling._ref(context.root / "provenance.json"),
        "capture_limits": whole.context_limits(context),
        "facts": whole.verify_terminal(terminal, context)}
    value = {"audit_mode": "whole-terminal", "seed": None, "classes": [row],
             "scientific_credit": False}
    started = {"schema_version": 1,
        "command": [sys.executable, "-I", "-B", "-c", selected._LEGACY_PROGRAM,
                    str(source.parent), "whole-terminal", str(context.root), str(terminal)],
        "started_at": "2026-10-04T00:11:30Z", "original_source_manifest": selected.reference(source),
        "original_source": load(source), "authority": selected.reference(context.root / "provenance.json"),
        "terminal": selected.reference(terminal)}
    write(directory / "started.json", started)
    write(directory / "stdout.log", value)
    (directory / "stderr.log").write_bytes(b"")
    write(directory / "completed.json", {"schema_version": 1, "returncode": 0,
        "elapsed_seconds": 1.0, "completed_at": "2026-10-04T00:11:31Z",
        "started": selected.reference(directory / "started.json"),
        "stdout": selected.reference(directory / "stdout.log"),
        "stderr": selected.reference(directory / "stderr.log")})
    audit = {"contract": selected.CONTRACT, "original_source_root": str(source.parent),
        "original_source_manifest": selected.reference(source),
        "legacy_program_sha256": graph.digest(selected._LEGACY_PROGRAM.encode()),
        **{key: selected.reference(directory / filename) for key, filename in
           (("started", "started.json"), ("completed", "completed.json"),
            ("stdout", "stdout.log"), ("stderr", "stderr.log"))},
        "result": value, "published_at": "2026-10-04T00:11:32Z", "scientific_credit": False}
    output = directory / "selection-audit.json"
    write(output, receipts._bind(selected.AUDIT_TYPE, audit))
    return output, path


def test_v7_continuation_full_get_admission_keeps_failed_seed_and_all_resources(continued):
    case = continued
    context = case["context"]
    assert [row["source_position"] for row in context.candidates[1:]] == [11, 12, 13, 14, 15]
    status = whole.acquisition_status(context)
    assert len(status["terminal_prefix"]) == 3
    assert whole.verify_terminal(whole.terminal_path(context, 2), context)["outcome"] == "operational-deferred"
    path, prepared = whole.prepared_workload(context, case["terminal"])
    neutral = load(case["raw"] / "neutral-input.json")
    assert len(prepared["resources"]) == len(neutral["resources"]) == 3
    assert [row["url"] for row in prepared["resources"]] == [row["url"] for row in neutral["resources"]]
    assert [row["depends_on"] for row in prepared["resources"]] == [row["depends_on"] for row in neutral["resources"]]
    manifest.validate_research_preparation(prepared, workload_id=path.stem)
    assert whole.reopen_get(case["raw"], context=context, position=3)["discovery_runtime"] != context.provenance["runtime_binding"]
    assert load(case["failed"])["outcome"] == "operational-discovery-failure-no-admission"
    assert not whole.terminal_path(context, 4).exists()


@pytest.mark.parametrize("mutation", ["input-mode", "graph-pruning", "get-body"])
def test_v7_import_and_admission_refuse_changed_original_evidence(continued, mutation):
    case = continued
    if mutation == "input-mode": case["input"].chmod(0o600)
    elif mutation == "graph-pruning":
        path = case["raw"] / "neutral-input.json"
        value = load(path)
        value["resources"].pop()
        write(path, value)
    else:
        path = case["raw"] / "native/run.json"
        value = load(path)
        value["responses"][1]["body_sha256"] = "0" * 64
        write(path, value)
        reseal_outputs(case["raw"])
    with pytest.raises(ValueError): whole.verify_terminal(case["terminal"], case["context"])


def test_v7_selected_renewal_current_ordinary_plan_and_canary_route(continued, tmp_path, monkeypatch):
    case = continued
    study, runtime = capture_runtime(tmp_path)
    audit, original = selection_audit(case, Path(runtime["source_manifest"]), tmp_path / "selection-audit")
    monkeypatch.setattr(selected, "_legacy_source", lambda root, ref: load(Path(ref["path"])))
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:12:00Z")
    receipt = selected.publish_input(tmp_path / "current-selected-input.json", audit=audit,
        candidate_id=case["candidate"]["candidate_id"])
    prepared = selected.prepare_input(receipt, tmp_path / original.name)
    value, baseline, proof = selected.validate_input(receipt)
    assert value["original_role"] == whole.ROLE and proof["all_occurrences_and_edges_retained"] is True
    manifest.validate_research_preparation(load(prepared), workload_id=prepared.stem)
    assert baseline["resources"] == load(prepared)["resources"]
    row = {"candidate_id": value["candidate_id"], "class_index": 1,
        "workload_id": prepared.stem, "prepared_workload": selected.reference(prepared),
        "terminal": rolling._ref(case["terminal"]), "admission_root": str(case["context"].root),
        "capture_input": selected.reference(receipt)}
    row["canonical_sites"] = value["canonical_sites"]
    enrollment = study / "enrollment.json"
    write(enrollment, receipts._bind(additive.ENROLLMENT_TYPE, {"fixture": "original selection ledger boundary"}))
    policy_path = study / "policy.json"
    write(policy_path, {"fixture": "original selected ledger boundary"})
    limits = whole.context_limits(case["context"])
    policy = {"contract": additive.CONTRACT, "runtime": runtime, "capture_limits": limits,
        "data_role": selected.ROLE, "admission_identity": static.identity(case["context"].original),
        "published_at": "2026-10-04T00:12:00Z"}
    batch = {"selected_candidate_ids": [row["candidate_id"]], "policy": rolling._ref(policy_path),
        "ordinal": 3, "admission_root": str(case["context"].root), "declared_at": policy["published_at"]}
    # Only prior selected ledger semantics are controlled. Own selected raw
    # proof and all current renewal/plan/Source validators remain genuine.
    monkeypatch.setattr(rolling, "_verify_enrollment", lambda path: (batch, [row], policy))
    monkeypatch.setattr(rolling, "verify_enrollment", lambda path: (batch, [row]))
    monkeypatch.setattr(rolling, "verify_policy", lambda root: policy)
    monkeypatch.setattr(additive, "membership_inputs", lambda path:
        {enrollment, policy_path, receipt, prepared, *selected.audit_inputs(audit)})
    source = Path(runtime["runtime_source_root"])
    for name in ("rapid_undefended_capture.py", "rapid_capture_plan.py", "rapid_lane_evidence.py", "rapid_rolling_capture.py"):
        dest = source / "src/qcsd_lab" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((ROOT / "src/qcsd_lab" / name).read_bytes())
    target = Path(runtime["workload_root"]) / prepared.name
    target.write_bytes(prepared.read_bytes())
    renewal = ordinary.publish_renewal(enrollment, study / "current-renewal.json")
    rv = ordinary.validate_renewal(renewal, enrollment)[0]
    assert rv["renewals"][row["candidate_id"]]["input"] == selected.reference(receipt)
    ordinary_input = ordinary.publish_inputs(enrollment, runtime, study / "ordinary-input.json",
        renewal=rolling._ref(renewal))
    ordinary.validate_inputs(ordinary_input, enrollment=enrollment, runtime=runtime, require_current=True)
    marker = study / "canary-controlled-packet-boundary.json"
    write(marker, {"original_capture_and_deep_boundary": "synthetic HOST only"})
    ref = rolling._ref(marker)
    canary = group.reference({"schema_version": 1, "plan": ref, "deep_receipt": ref,
        "capture": {key: ref for key in readiness.OPERATION_KEYS},
        "deep": {key: ref for key in readiness.OPERATION_KEYS}})
    monkeypatch.setattr(OperationFacts, "bind_canary", lambda self, value, rt: self.watch_file(marker))
    calls = []
    def packet_boundary(reference, *, runtime, mode):
        assert reference == canary and mode == "undefended"
        calls.append(mode)
        return {"mode": mode, "recorded_image_deep_reopened": True,
            "workload_sha256": graph.digest(target.read_bytes()),
            "application_body_identity_policy": app.COMPLETE_APPLICATION_DELIVERY_POLICY}
    monkeypatch.setattr(readiness, "validate_canary", packet_boundary)
    output = rolling.publish_plan(study, enrollment, ordinary_input, study / "plan.json",
        readiness={"undefended": canary}, runtime_inputs=runtime,
        application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY)
    spec = rolling.capture_spec(study, enrollment, ordinary_input, output)
    sites, payload = rolling.verify_capture_plan(spec, require_current=True)
    assert calls and payload[ordinary.FIELD] == ordinary.CONTRACT
    assert len(sites) == 1 and sites[0].qualification_set is None
    assert {lane["mode"] for lane in payload["lanes"]} == {"undefended"}
    assert load(target)["resources"] == baseline["resources"]
    assert "qualification_delivery_compatibility" not in payload
    assert canary["schema_version"] == 5 and canary["artifact_type"] == group.TYPE
    assert not rv["scientific_credit"] and rv["formal_accepted_trace_count"] == 0
