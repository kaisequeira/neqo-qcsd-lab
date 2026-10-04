"""Exercise prospective FRONT inputs through real enrollment and plan reopening.

The small admission/image/qualification backends come from the existing rolling
fixture. The new declaration, exact input copying, plans, runtime identities and
readiness-to-derived-graph checks execute without substitution.
"""
from __future__ import annotations

import copy
import os
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_front_capture_amendment as front
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_lane_evidence import setup
from tests.test_rapid_rolling_capture import rolling_setup, _planned, _proof
from tools import rapid_rolling_capture as cli


@pytest.fixture
def amended(rolling_setup, monkeypatch, request):
    f = rolling_setup
    terminal_path = admission._child(f.context.root, f.terminals[0])
    terminal = admission._unpack(terminal_path.read_bytes(), admission.TERMINAL_TYPE)
    prep_path = admission._child(f.context.root, terminal["preparation"])
    prep = admission._unpack(prep_path.read_bytes(), admission.PREPARATION_TYPE)
    original = admission._child(f.context.root, prep["prepared_workload"])
    graph = lanes._load(original.read_bytes())
    graph["preparation"][front.FIELD] = front.ORIGINAL_POLICY
    # Preserve a proof and executable metadata alongside the complete graph.
    evidence = front._directory(original)
    evidence.mkdir()
    proof = evidence / "raw/response.json"
    proof.parent.mkdir()
    proof.write_bytes(b'{"original_application_bytes":"unchanged"}\n')
    proof.chmod(0o700)
    (evidence / "headers.json").write_bytes(b'{"status":200}\n')
    original.write_bytes(lanes._json(graph))
    prep["prepared_workload"] = admission.evidence_reference(f.context.root, original)
    prep_path.write_bytes(admission._json(admission._bind(admission.PREPARATION_TYPE, prep)))
    terminal["preparation"] = admission.evidence_reference(f.context.root, prep_path)
    terminal["facts"]["admission"]["prepared_workload_sha256"] = lanes._sha(original.read_bytes())
    terminal_path.write_bytes(admission._json(admission._bind(admission.TERMINAL_TYPE, terminal)))
    f.terminals[0] = admission.evidence_reference(f.context.root, terminal_path)
    f.status["terminal_prefix"] = f.terminals[:1]
    enrollment = rolling.enroll(f.root)
    # A new config layout, never the original study's capture inputs.
    config = Path(f.runtime["execution_root"]) / "front-config"
    workloads, campaigns = config / "workloads", config / "campaigns"
    workloads.mkdir(parents=True); campaigns.mkdir()
    runtime = {**f.runtime, "workload_root": str(workloads), "campaign_dir": str(campaigns)}
    declaration = f.root / "front-amendment.json"
    front.publish_amendment(enrollment, runtime, declaration,
                            capture_policy=getattr(request, "param", front.CAPTURE_POLICY))
    target = workloads / original.name
    qualifier_root = config / "chaff-response-qualification-store/sets/front-new"
    qualifier_root.mkdir(parents=True)
    named = qualifier_root / "_qualification-set.json"
    named.write_bytes(b'{"fixture":"fresh named qualification primitive"}\n')
    sidecar = qualifier_root / original.name
    sidecar.write_bytes(lanes._json({"qualification_source": {
        **lanes._load(lanes._read(Path(runtime["source_manifest"]))), "image_digest": runtime["collection_image_digest"]},
        "qualification_image_digest": runtime["collection_image_digest"],
        "implementation_receipt": {"neqo_qcsd_client": {"sha256": lanes._sha(lanes._read(Path(runtime["client_binary"])))}},
        "candidate_attempts": [{"connection_epochs": [{"receipt": {"started_unix_ns": time.time_ns()}}]}]}))
    qualifier = config / "qualification-spec.json"
    qualifier.write_bytes(lanes._json({"schema_version": 1, "qualification_sets": [{
        "qualification_set": "front-new", "manifest": str(named), "sidecar_root": str(qualifier_root), "prefix_spec_root": None}]}))
    canary_path = f.root / "new-front-canary-plan.json"
    canary_path.write_bytes(lanes._json({"front_capture_amendment": rolling._ref(declaration)}))
    start = f.root / "new-front-start.json"
    start.write_bytes(lanes._json({"started_at": admission._now()}))
    canary_ref = {"plan": rolling._ref(canary_path), "capture": {"started": rolling._ref(start)}}
    def checked(reference, *, runtime, mode):
        return {"mode": mode, "authority_source": {**lanes._load(lanes._read(Path(runtime["source_manifest"]))),
            "image_digest": runtime["collection_image_digest"]},
            "client_sha256": lanes._sha(lanes._read(Path(runtime["client_binary"]))),
            "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()},
            "workload_sha256": lanes._sha(target.read_bytes()),
            "full_graph": {"resource_records_sha256": lanes._sha(lanes._json(graph["resources"]))}}
    monkeypatch.setattr(readiness, "validate_canary", checked)
    return SimpleNamespace(f=f, enrollment=enrollment, runtime=runtime, declaration=declaration,
        original=original, target=target, graph=graph, qualifier=qualifier, named=named, sidecar=sidecar,
        canary=canary_ref, canary_path=canary_path, start=start, checked=checked)


def planned(a):
    output = a.f.root / "front-plan.json"
    rolling.publish_plan(a.f.root, a.enrollment, a.qualifier, output,
        readiness={"front": a.canary}, runtime_inputs=a.runtime, front_capture_amendment=a.declaration)
    spec = rolling.capture_spec(a.f.root, a.enrollment, a.qualifier, output)
    sites, payload = rolling.verify_capture_plan(spec)
    lane = lanes._lane({"plan_payload": payload}, next(row["campaign_name"] for row in payload["lanes"] if row["mode"] == "front"))
    return spec, sites, payload, lane


def rewrite_amendment(a, mutate):
    value = admission._unpack(a.declaration.read_bytes(), front.RECEIPT_TYPE)
    mutate(value)
    a.declaration.write_bytes(admission._json(admission._bind(front.RECEIPT_TYPE, value)))


def test_public_declaration_and_front_plan_retain_original_enrollment_and_application_bytes(amended):
    a = amended
    before = {path: path.read_bytes() for path in (a.enrollment, a.original, a.f.root / "policy.json")}
    declaration = front.validate_amendment(a.declaration, enrollment=a.enrollment, runtime=a.runtime)
    assert a.target.read_bytes() == a.original.read_bytes().replace(
        ('"' + front.ORIGINAL_POLICY + '"').encode(), ('"' + front.CAPTURE_POLICY + '"').encode(), 1)
    assert front._inventory(front._directory(a.target)) == front._inventory(front._directory(a.original))
    spec, sites, payload, lane = planned(a)
    assert sites[0].workload_sha256 == lanes._sha(a.target.read_bytes()) != lanes._sha(a.original.read_bytes())
    assert payload["bindings"]["cohort_sha256"] == lanes._sha(a.enrollment.read_bytes())
    assert payload["front_capture_amendment"] == rolling._ref(a.declaration)
    assert payload["planned_trace_count"] == 5 * 64 and len(payload["lanes"]) == 80
    assert declaration["formal_accepted_trace_count"] == 0 and declaration["scientific_credit"] is False
    assert rolling.require_mode_readiness(spec, lane) == a.canary
    with pytest.raises(ValueError, match="buflo lacks"):
        rolling.require_mode_readiness(spec, replace(lane, mode="buflo"))
    # The unchanged image proof / lane-intent consumer binds derived SHA and
    # keeps all original cohort objects. No real capture is produced here.
    for root in (spec.runtime_source_root, spec.module_root):
        module = root / "src/qcsd_lab/rapid_front_capture_amendment.py"
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_bytes(Path(front.__file__).read_bytes())
    proof = _proof(a.f, spec)
    checked = {"proof": proof, "execution": {"returncode": 0,
        "validator_script_sha256": lanes._sha(lanes.IMAGE_CHECK_SCRIPT.encode()),
        "stdout": lanes._put_object(a.f.root, lanes._json(proof)), "started_at": admission._now()}}
    intent = lanes.prepare_lane_intent(spec, a.f.root, lane.campaign_name, checked)
    assert intent.is_file()
    assert all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize("kind", ["field", "resource", "headers", "proof", "executable", "symlink", "extra-proof"])
def test_actual_capture_input_changes_are_rejected_on_reopen(amended, kind):
    a = amended
    if kind in {"field", "resource", "headers"}:
        value = lanes._load(a.target.read_bytes())
        if kind == "field": value["preparation"]["settle_ms"] = 0
        elif kind == "resource": value["resources"].pop()
        else: value["resources"][0]["headers"] = {"changed": "value"}
        a.target.write_bytes(lanes._json(value))
        # Even a rehashed declaration cannot authorize a second change.
        rewrite_amendment(a, lambda x: x["workloads"][0].update(capture_manifest=rolling._ref(a.target)))
    else:
        proof = front._directory(a.target) / "raw/response.json"
        if kind == "proof": proof.write_bytes(b"changed real proof bytes")
        elif kind == "executable": proof.chmod(0o600)
        elif kind == "extra-proof": (proof.parent / "extra.json").write_bytes(b"extra")
        else:
            proof.unlink(); proof.symlink_to(front._directory(a.original) / "raw/response.json")
    with pytest.raises(ValueError):
        front.validate_amendment(a.declaration, enrollment=a.enrollment, runtime=a.runtime)


@pytest.mark.parametrize("field", ["enrollment", "admission_provenance", "runtime_source_manifest", "client_binary"])
def test_closed_original_and_runtime_references_cannot_be_relabelled(amended, field):
    rewrite_amendment(amended, lambda x: x[field].update(sha256="0" * 64))
    with pytest.raises(ValueError):
        front.validate_amendment(amended.declaration, enrollment=amended.enrollment, runtime=amended.runtime)


@pytest.mark.parametrize("mutation", ["mode", "image", "extra", "credit", "candidate", "manifest", "graph", "bool", "future"])
def test_rehashed_closed_declaration_rejects_changed_authority(amended, mutation):
    def mutate(x):
        if mutation == "mode": x["mode"] = "buflo"
        elif mutation == "image": x["collection_image_digest"] = "sha256:" + "f" * 64
        elif mutation == "extra": x["unreviewed"] = True
        elif mutation == "credit": x["formal_accepted_trace_count"] = False
        elif mutation == "candidate": x["workloads"][0]["candidate_id"] = "other-candidate"
        elif mutation == "manifest": x["workloads"][0]["original_manifest"] = rolling._ref(amended.target)
        elif mutation == "graph": x["workloads"][0]["resource_records_sha256"] = "e" * 64
        elif mutation == "bool": x["workloads"][0]["application_evidence_files"]["headers.json"]["executable"] = 0
        else: x["published_at"] = "2099-01-01T00:00:00Z"
    rewrite_amendment(amended, mutate)
    with pytest.raises(ValueError):
        front.validate_amendment(amended.declaration, enrollment=amended.enrollment, runtime=amended.runtime)


@pytest.mark.parametrize("input_kind", ["source", "client", "image"])
def test_actual_runtime_change_requires_a_new_amendment(amended, input_kind):
    runtime = dict(amended.runtime)
    if input_kind == "image": runtime["collection_image_digest"] = "sha256:" + "e" * 64
    else:
        Path(runtime["source_manifest" if input_kind == "source" else "client_binary"]).write_bytes(
            lanes._json({**lanes._load(Path(runtime["source_manifest"]).read_bytes()), "lab_commit": "e"*40})
            if input_kind == "source" else b"different native client")
    with pytest.raises(ValueError):
        front.validate_amendment(amended.declaration, enrollment=amended.enrollment, runtime=runtime)


@pytest.mark.parametrize("kind", ["source", "client", "image"])
def test_current_named_qualifier_must_match_new_capture_runtime_before_plan_publication(amended, kind):
    value = lanes._load(amended.sidecar.read_bytes())
    if kind == "source": value["qualification_source"]["lab_commit"] = "f" * 40
    elif kind == "client": value["implementation_receipt"]["neqo_qcsd_client"]["sha256"] = "f" * 64
    else: value["qualification_image_digest"] = "sha256:" + "f" * 64
    amended.sidecar.write_bytes(lanes._json(value))
    with pytest.raises(ValueError, match="fresh qualification"):
        planned(amended)
    assert not (amended.f.root / "front-plan.json").exists()


@pytest.mark.parametrize("kind", ["amendment", "graph", "manifest", "chronology"])
def test_new_canary_must_bind_actual_derived_input_and_prospective_declaration(amended, monkeypatch, kind):
    a = amended
    if kind == "amendment": a.canary_path.write_bytes(b"{}\n"); a.canary["plan"] = rolling._ref(a.canary_path)
    elif kind == "chronology":
        a.start.write_bytes(lanes._json({"started_at": "2020-01-01T00:00:00Z"}))
        a.canary["capture"]["started"] = rolling._ref(a.start)
    else:
        def mismatch(*args, **kwargs):
            facts = a.checked(*args, **kwargs)
            if kind == "manifest": facts["workload_sha256"] = lanes._sha(a.original.read_bytes())
            else: facts["full_graph"]["resource_records_sha256"] = "e" * 64
            return facts
        monkeypatch.setattr(readiness, "validate_canary", mismatch)
    with pytest.raises(ValueError, match="FRONT canary"):
        planned(a)
    assert not (a.f.root / "front-plan.json").exists()
    assert list(Path(a.runtime["campaign_dir"]).iterdir()) == []


@pytest.mark.parametrize("readiness_modes", [(), ("undefended",), ("front", "buflo")])
def test_amended_plan_never_authorizes_other_modes(amended, readiness_modes):
    with pytest.raises(ValueError, match="only.*FRONT"):
        rolling.publish_plan(amended.f.root, amended.enrollment, amended.qualifier,
            amended.f.root / "invalid-plan.json", runtime_inputs=amended.runtime,
            readiness={key: amended.canary for key in readiness_modes}, front_capture_amendment=amended.declaration)


def test_declaration_is_create_only_and_preserves_previous_inputs(amended):
    before = amended.target.read_bytes(), amended.declaration.read_bytes()
    with pytest.raises(ValueError, match="fresh declaration"):
        front.publish_amendment(amended.enrollment, amended.runtime, amended.declaration)
    with pytest.raises(ValueError, match="overwrites"):
        front.publish_amendment(amended.enrollment, amended.runtime, amended.f.root / "second-declaration.json")
    assert before == (amended.target.read_bytes(), amended.declaration.read_bytes())
    assert not (amended.f.root / "second-declaration.json").exists()


def test_legacy_plan_has_exact_original_keyset_and_no_policy_amendment(rolling_setup):
    spec, _ = _planned(rolling_setup, modes=("front",))
    _, payload = rolling.verify_capture_plan(spec)
    assert "front_capture_amendment" not in payload
    value = copy.deepcopy(payload); value["front_capture_amendment"] = None
    spec.plan_receipt.write_bytes(admission._json(admission._bind(lanes.PLAN_TYPE, value)))
    with pytest.raises(ValueError, match="reference"):
        rolling.verify_capture_plan(spec)


def test_plan_cli_has_explicit_amendment_and_legacy_absence_is_none():
    required = ["--evidence-root", "/evidence", "--enrollment", "/batch", "--qualification-spec", "/qual",
                "--output", "/plan", "--spec-output", "/spec"]
    assert cli._parser().parse_args(["plan", *required]).front_capture_amendment is None
    assert cli._parser().parse_args(["plan", *required, "--front-capture-amendment", "/amendment"]).front_capture_amendment == Path("/amendment")


def test_qualification_epoch_must_postdate_amendment_publication(amended):
    value = lanes._load(amended.sidecar.read_bytes())
    value["candidate_attempts"][0]["connection_epochs"][0]["receipt"]["started_unix_ns"] = 0
    amended.sidecar.write_bytes(lanes._json(value))
    with pytest.raises(ValueError, match="qualification began before"):
        planned(amended)
    assert not (amended.f.root / "front-plan.json").exists()


def test_image_plan_check_rejects_changed_installed_amendment_authority(amended):
    spec, _, _, _ = planned(amended)
    for root in (spec.runtime_source_root, spec.module_root):
        module = root / "src/qcsd_lab/rapid_front_capture_amendment.py"
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_bytes(Path(front.__file__).read_bytes())
    _proof(amended.f, spec)
    (spec.runtime_source_root / "src/qcsd_lab/rapid_front_capture_amendment.py").write_bytes(b"changed installed authority\n")
    with pytest.raises(ValueError, match="FRONT amendment authority differs"):
        _proof(amended.f, spec)


def test_qualification_base_binding_cannot_be_relabelled_for_derived_manifest(amended):
    from qcsd_lab import chaff_qualification as qualification
    # Exercise the real schema-two validator's raw-input binding. This
    # synthetic sidecar is deliberately incomplete beyond that boundary;
    # it is not a successful qualification receipt or a remote execution.
    old = {key: None for key in qualification.RESPONSE_ONLY_V2_SIDECAR_KEYS}
    old.update(schema_version=2, artifact_type=qualification.RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE,
        qualification_scope="response-only", workload_id=amended.original.stem,
        selection_policy=qualification.RESPONSE_ONLY_APPROVED_ORIGINS_SELECTION_POLICY,
        application_resource_id=0, selected_chaff_resource_id=1,
        qualified_parallel_chaff_streams=5, method="GET",
        request_header_primitive=qualification.response_only_request_header_primitive(),
        qualification_policy=qualification.response_only_v2_qualification_policy(),
        base_manifest={"path": amended.original.name, "sha256": lanes._sha(amended.original.read_bytes())})
    with pytest.raises(ValueError, match="base manifest mismatch"):
        qualification.validate_response_only_sidecar(old, workload_id=amended.original.stem, base_manifest_path=amended.target,
            expected_sidecar_schema_version=2, require_current_implementation=False)
