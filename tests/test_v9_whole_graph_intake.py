"""Prospective V9 ABI fixtures; no browser, Native GET, image or actual credit.

The external history subprocess is the controlled boundary. Exact producer and
raw reference readers, occurrence projection, current GET raw reconciliation,
typed preparation, ordered decisions and public enrollment remain production.
"""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_preparation as prep
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import manifest
from tests.test_supplied_static_get import actual_contract_fixture, load, write, reseal_outputs
from tests.test_supplied_static_preparation import fixed_graph, runtime as capture_runtime
from tests.test_whole_graph_supplement import supplemented

ROOT = Path(__file__).parents[1]


@pytest.fixture
def v9_intake(supplemented, tmp_path, monkeypatch):
    root, old_context, old_input = supplemented
    monkeypatch.setattr(inputs,"_verify_external",lambda *args,**kwargs:None)
    candidate32 = load(old_input)["candidate"]
    candidates = [dict(candidate32, candidate_id=f"fixture-reserved-{n}", domain=f"site{n}.example",
        source_url=f"https://site{n}.example/", catalogue_position=n) for n in range(31,36)]
    candidates[1] = candidate32
    prefix = load(old_input.with_name("plan.json"))["original_prefix"]
    old_pair = ROOT / "tools/whole_graph_discovery_v8"
    policy, control = inputs.CONTROL_SOURCES[8]
    metadata = tmp_path / "browser-metadata.json"
    write(metadata, {"fixture": "original-c24-browser-runtime-only"})
    original = {"schema_version":8,
        "artifact_type":"qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v8",
        "contract":inputs.VERSIONS["qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v8"][1],
        "producer_sources":{name:inputs.reference(old_pair/name) for name in inputs.PRODUCERS},
        "discovery_control":{"policy":policy,"sources":{name:inputs.reference(old_pair/name) for name in control},
            "installed_image_source_changed":False,"module_loading":"explicit-separate-modules-no-installed-module-replacement"},
        "original_prefix":prefix,"candidates":candidates,"reserved_candidates":[],
        "browser_image":"sha256:"+"1"*64,"source_metadata":inputs.reference(metadata),
        "declared_at":"2026-10-03T23:59:56Z","max_origin_passes":4,**inputs.ZERO}
    original_path = tmp_path / "original-v8-plan.json";write(original_path,original)
    fixture_pair = ROOT / "tools/whole_graph_discovery_v9"
    retained = tmp_path / "controlled-retained-interruption.json"
    write(retained,{"fixture_only":"independent external history reconstruction boundary"})
    continuation = {**deepcopy(original),"schema_version":9,"artifact_type":inputs.V9_CONTINUATION_PLAN_TYPE,
        "contract":inputs.V9_CONTRACT,
        "producer_sources":{name:inputs.reference(fixture_pair/name) for name in inputs.V9_PRODUCERS},
        "action_local_sources":{name:inputs.reference(fixture_pair/name) for name in inputs.V9_ACTION_SOURCES},
        "original_plan":inputs.reference(original_path),"retained_interruption":inputs.reference(retained),
        "previous_plan":None,"previous_batch":None,"original_candidate_indices":[2,3,4,5],
        "local_candidate_indices":[1,2,3,4],"candidates":candidates[1:],"reserved_candidates":candidates}
    plan = tmp_path / "new-v9-plan.json";write(plan,continuation)
    runtime = {"image_digest":original["browser_image"],"source_metadata":load(metadata),
        "installed_metadata_sha256":inputs.graph.digest(metadata.read_bytes()),
        "execution_role":"actual-browser-image-navigation-seeded-graph-input-only-v9",
        "external_discovery_control":original["discovery_control"]}
    value = load(old_input)
    value.update(schema_version=9,artifact_type=inputs.V9_INPUT_TYPE,contract=inputs.V9_CONTRACT,
        plan=inputs.reference(plan),runtime=runtime,all_occurrences_and_edges_retained=True)
    input_path=old_input.with_name("new-v9-input.json");write(input_path,value)
    failure_root=tmp_path/"original31-failure";failure_root.mkdir()
    failure_runtime={**runtime,"execution_role":"actual-browser-image-navigation-seeded-graph-input-only-v8"}
    (failure_root/"image-source-metadata.json").write_bytes(metadata.read_bytes())
    write(failure_root/"started.json",{"schema_version":1,"plan":inputs.reference(original_path),
        "candidate":candidates[0],"runtime":failure_runtime,"started_at":"2026-10-03T23:59:57Z",**inputs.ZERO})
    write(failure_root/"failed.json",{"schema_version":1,"plan":inputs.reference(original_path),
        "candidate":candidates[0],"completed_at":"2026-10-03T23:59:58Z","elapsed_ns":1,
        "error_type":"ControlledDiscoveryFailure","message":"fixture","traceback":"fixture",
        "completed_passes":[],"completed_navigation":None,"failure_stage":"navigation",
        "outcome":"operational-discovery-failure-no-admission","exception_evidence":None,
        "exception_evidence_sha256":inputs.discovery_digest(None),**inputs.ZERO})
    monkeypatch.setattr(static.receipts,"_now",lambda:"2026-10-03T23:59:59Z")
    context_root=tmp_path/"v9-context"
    whole.initialize_context(context_root,original_context=old_context.original.root,
        plans=[original_path,plan],graph_inputs=[input_path],failed_discoveries=[failure_root/"failed.json"],
        expected_runtime=old_context.provenance["runtime_binding"])
    context=whole.load_context(context_root)
    declaration=load(root/"declaration.json")
    declaration.update(context=prep.reference(context_root/"provenance.json"),position=3,
        graph_input=inputs.reference(input_path),discovery_runtime=runtime,producer_sources=whole.producer_sources())
    write(root/"declaration.json",declaration)
    for child in (root,root/"bootstrap"):
        started=load(child/"native-started.json");started["declaration_sha256"]=inputs.graph.digest((root/"declaration.json").read_bytes())
        write(child/"native-started.json",started);reseal_outputs(child)
    write(root/"full-get-proof.json",whole.build_proof(root,context=context,position=3))
    monkeypatch.setattr(static.receipts,"_now",lambda:"2026-10-04T00:00:20Z")
    return root,context,input_path,original_path,plan


def test_v9_whole_graph_current_get_preparation_and_public_enrollment_retain_queue_and_graph(v9_intake,tmp_path):
    root,context,input_path,_,_=v9_intake
    neutral=load(root/"neutral-input.json")
    _,projected=inputs.load_input(input_path)
    assert projected==neutral and len(projected["resources"])==3
    assert projected["resources"][1]["url"]==projected["resources"][2]["url"]
    assert [r["depends_on"] for r in projected["resources"]]==[[],[0],[1]]
    original_context_bytes=(context.original.root/"provenance.json").read_bytes()
    whole.record_deferral(context,2)
    terminal=whole.admit(context,3,root)
    preparation=whole.build_preparation(root,context=context,position=3)
    manifest.validate_research_preparation(preparation,workload_id="v9-fixture")
    assert whole.verify_terminal(terminal,context)["outcome"]=="admitted"
    study,runtime=capture_runtime(tmp_path)
    rolling.initialize_study(context.original.root,study,runtime,supplied_static=True)
    enrollment=rolling.enroll(study,acquisition_root=context.root)
    batch,classes=rolling.verify_enrollment(enrollment)
    assert len(classes)==1 and classes[0]["terminal"]==prep.reference(terminal)
    assert [r["outcome"] for r in batch["decisions"]]==["input-ineligible","operational-deferred","admitted"]
    policy=rolling.verify_policy(study)
    assert policy["class_target"]==50 and policy["formal_trace_target"]==16000
    assert (context.original.root/"provenance.json").read_bytes()==original_context_bytes
    assert whole._plan_rows([load(v9_intake[3]),load(v9_intake[4])],context.original)==whole._plan_rows([load(v9_intake[3])],context.original)


@pytest.mark.parametrize("fault",["pair","action-reader","control-mode","indices","omitted-old-plan","graph-pruning","native-runtime"])
def test_v9_intake_refuses_foreign_identity_order_graph_or_current_get(v9_intake,monkeypatch,fault):
    root,context,input_path,original_path,plan_path=v9_intake
    plan=load(plan_path)
    if fault in {"pair","action-reader","control-mode"}:
        if fault=="pair":plan["producer_sources"]["graph_input.py"]["sha256"]="0"*64
        elif fault=="action-reader":plan["action_local_sources"]["controller.py"]["sha256"]="0"*64
        else:plan["discovery_control"]["sources"]["navigation_control.py"]["mode"]="0755"
        with pytest.raises(ValueError):inputs._producer(plan)
    elif fault in {"indices","omitted-old-plan"}:
        if fault=="indices":plan["original_candidate_indices"]=[1,2,3,4]
        with pytest.raises(ValueError):whole._plan_rows([plan] if fault=="omitted-old-plan" else [load(original_path),plan],context.original)
    elif fault=="graph-pruning":
        value=load(input_path);native=load(inputs.reopen(value["native_manifest"]));native["resources"].pop()
        with pytest.raises(ValueError):inputs.project(value,native)
    else:
        declaration=load(root/"declaration.json");declaration["runtime_binding"]["native_commit"]="0"*40
        write(root/"declaration.json",declaration)
        with pytest.raises(ValueError):whole.build_proof(root,context=context,position=3)


def test_v9_graph_alone_cannot_authorize_host_get_or_site_credit(v9_intake,monkeypatch):
    root,context,input_path,_,_=v9_intake
    monkeypatch.delenv("QCSD_LAB_IMAGE_DIGEST",raising=False)
    target=root.parent/"forbidden-host-get"
    with pytest.raises(ValueError):whole.execute_get(context.root,3,target)
    assert not target.exists() and load(input_path)["site_credit"]==0
    assert load(input_path)["http3_get_performed"] is False


def singleton_context(fixture,tmp_path,monkeypatch,*,complete=True):
    _,context,input_path,original_path,plan_path=fixture
    value=load(input_path);path=inputs.reopen(value["native_manifest"]);neutral=load(path)
    primary_origin=inputs.get._origin(neutral["resources"][0]["url"])
    for resource in neutral["resources"][1:]:
        resource["url"]=primary_origin+"/repeated?q=exact"
    write(path,neutral)
    value.update(native_manifest=inputs.reference(path),resource_graph_sha256=inputs.discovery_digest(neutral["resources"]),
        all_occurrences_and_edges_retained=complete)
    write(input_path,value)
    # Keep the approved union's unused second origin. The entry guard must
    # count the actual full resource set, never a previous-pass allowlist.
    assert len(value["approved_origin_union"])==2
    target=tmp_path/"singleton-context"
    whole.initialize_context(target,original_context=context.original.root,plans=[original_path,plan_path],
        graph_inputs=[input_path],failed_discoveries=[inputs.reopen(v["record"]) for v in context.provenance["failed_discoveries"].values()],
        expected_runtime=context.provenance["runtime_binding"])
    return whole.load_context(target),value,neutral


def test_public_complete_single_origin_rejection_binds_profile_full_graph_and_unassessed_http3(v9_intake,tmp_path,monkeypatch):
    import importlib.util
    context,value,neutral=singleton_context(v9_intake,tmp_path,monkeypatch)
    spec=importlib.util.spec_from_file_location("controlled_public_whole_cli",ROOT/"tools/rapid_whole_graph_supplement.py")
    cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
    whole.record_deferral(context,2)
    args=cli.parser().parse_args(["record-input-rejection","--context",str(context.root),"--position","3"])
    result=cli.run(args)
    terminal=Path(result["terminal"]);record=load(terminal)["payload"]
    assert result["outcome"]=="input-ineligible" and whole.verify_terminal(terminal,context)["admission"] is None
    evidence=record["failure"]["evidence"]
    assert evidence["actual_resource_origin_count"]==1 and evidence["resource_count"]==3
    assert evidence["resource_graph_sha256"]==value["resource_graph_sha256"]
    assert inputs.reopen(evidence["graph_input"])==v9_intake[2]
    assert evidence["http3_assessment"]=="unassessed" and evidence["site_universally_invalid_claimed"] is False
    assert record["get_evidence_root"] is None and record["namespace"] is None
    assert len(whole.acquisition_status(context)["terminal_prefix"])==3
    assert inputs.project(value,neutral)["resources"]==neutral["resources"]
    assert not list(context.root.rglob("native-started.json"))
    with pytest.raises(ValueError):whole.record_input_rejection(context,3)


@pytest.mark.parametrize("fault",["two-origins","incomplete","missing-input","wrong-count","claim-get","profile"])
def test_graph_entry_rejection_refuses_eligible_partial_missing_or_relabelled_evidence(v9_intake,tmp_path,monkeypatch,fault):
    if fault=="two-origins":
        with pytest.raises(ValueError):whole.record_input_rejection(v9_intake[1],3)
        return
    context,_,_=singleton_context(v9_intake,tmp_path,monkeypatch,complete=fault!="incomplete")
    if fault=="missing-input":
        # A declared reserved candidate with no complete input remains pending.
        with pytest.raises(ValueError):whole.record_input_rejection(context,4)
        return
    if fault=="profile":
        profile=prep.open_reference(context.original.provenance["profile"])
        # The original fixture deliberately seals its prefix read-only. Open
        # only this controlled file for the mutation, then restore its mode so
        # the production reader must reject changed bytes under the old ref.
        original_mode=profile.stat().st_mode & 0o7777
        original_bytes=profile.read_bytes()
        profile.chmod(original_mode | 0o200)
        payload=load(profile);payload["minimum_origins"]=1;write(profile,payload)
        profile.chmod(original_mode)
        try:
            with pytest.raises(ValueError):whole.record_input_rejection(context,3)
        finally:
            profile.chmod(original_mode | 0o200)
            profile.write_bytes(original_bytes)
            profile.chmod(original_mode)
        return
    if fault in {"wrong-count","claim-get"}:
        terminal=whole.record_input_rejection(context,3)
        payload=load(terminal);evidence=payload["payload"]["failure"]["evidence"]
        if fault=="wrong-count":evidence["actual_resource_origin_count"]=0
        else:payload["payload"]["get_evidence_root"]="/fabricated/get"
        static._write(terminal.with_name("altered.json"),whole.TERMINAL_TYPE,payload["payload"])
        terminal.write_bytes(terminal.with_name("altered.json").read_bytes())
        with pytest.raises(ValueError):whole.verify_terminal(terminal,context)
    else:
        with pytest.raises(ValueError):whole.record_input_rejection(context,3)
    if fault=="incomplete":assert not whole.terminal_path(context,3).exists()
