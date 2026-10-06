"""Portable HOST contracts; installed processes and retained seed are controlled.

No browser, GET or scientific credit is produced. The production V9 input
reader, lossless graph, Native raw proof, selected input and new enrollment
paths run against the original synthetic emitter fixtures.
"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from qcsd_lab import rapid_supplemental_cohort as cohort
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as prep
from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import whole_graph_supplement as whole
from tests.test_v9_whole_graph_intake import v9_intake
from tests.test_whole_graph_supplement import supplemented
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_get import actual_contract_fixture, load, write as emitter_write, reseal_outputs

FIXTURE_NATIVE = "818d89398a5b0bc725e424b648d878185d18125d"
FIXTURE_CLIENT = "2c9f170e1e087d116a66571e2637e605967352501131ba9a4ef0052d19321dac"


def write(path, value):
    emitter_write(path, value)
    return path


def transport_fixture(plan_path,input_path,tmp_path):
    """Supply the external boundary's full transport shape, without certifying it."""
    plan=load(plan_path);old_path=inputs.reopen(plan["original_plan"]);old=load(old_path)
    source_root=tmp_path/"controlled-discovery-source";source_root.mkdir()
    source_file=source_root/"fixture.py";source_file.write_text("# controlled external Source boundary\n")
    catalogue=write(tmp_path/"controlled-catalogue.json",{"fixture_boundary":"external catalogue verifier"})
    source={"root":str(source_root),"files":{"fixture.py":{
        "sha256":inputs.graph.digest(source_file.read_bytes()),"mode":source_file.stat().st_mode & 0o7777}}}
    for value in (old,plan):value.update(catalogue=inputs.reference(catalogue),source=source)
    old.update(previous_plans=[],history_batches=[],history=[],reservation_retirements=[])
    write(old_path,old);plan["original_plan"]=inputs.reference(old_path)
    retained_path=inputs.reopen(plan["retained_interruption"]);retained=load(retained_path)
    interrupted=tmp_path/"controlled-interrupted-prefix";interrupted.mkdir()
    prefix=write(interrupted/"started.json",{"fixture_boundary":"retained external interruption"})
    retained.update(original_root=str(interrupted),files={"started.json":inputs.reference(prefix)})
    write(retained_path,retained);plan["retained_interruption"]=inputs.reference(retained_path)
    write(plan_path,plan)
    value=load(input_path);value["plan"]=inputs.reference(plan_path)
    def raw(name):
        return inputs.reference(write(input_path.parent/name,{"fixture_boundary":"external discovery verifier", "name":name}))
    value.update(passes=[{key:raw("pass-01-"+key+".json") for key in ("started","result","completed")}],
        navigation={key:raw("navigation-"+key+".json") for key in ("started","result","completed","control")})
    value["final_discovery"]=value["passes"][0]["result"]
    write(input_path.parent/"image-source-metadata.json",load(inputs.reopen(plan["source_metadata"])))
    write(input_path.parent/"started.json",{"fixture_boundary":"external discovery start"})
    write(input_path,value)


@pytest.fixture
def cohort_case(v9_intake, tmp_path, monkeypatch):
    raw, previous, input_path, _, plan_path = v9_intake
    transport_fixture(plan_path,input_path,tmp_path)
    directory = tmp_path / "retained-ledger"; directory.mkdir()
    batches = directory / "batches"; batches.mkdir()
    first = batches / "b0001"; first.mkdir()
    seed = first / "enrollment.json"
    write(seed, {"fixture_boundary": "previously verified selected membership"})
    retained = [{"candidate_id": "retained-fixture-class", "class_index": 1,
        "canonical_sites": ["retained.example"], "primary_origin": "https://retained.example",
        "workload_id": "retained-fixture-class", "capture_limits": static.capture_limits(16*1024*1024,64)}]
    policy = {"contract": ledger.CONTRACT, "class_target": 50, "formal_trace_target": 16000,
        "seed_classes": retained, "seed_batch_ordinal": 1,
        "seed_enrollment": prep.reference(seed), "published_at": "2026-10-03T23:59:55Z",
        "admission_identity": {"fixture": "retained-original-admission-identity"}}
    policy_path = directory / "policy.json"
    write(policy_path, receipts._bind(ledger.POLICY_TYPE, policy))
    batch = {"policy": prep.reference(policy_path), "declared_at": policy["published_at"]}
    original_verify = ledger.verify_enrollment
    monkeypatch.setattr(ledger, "verify_enrollment", lambda path: (batch, deepcopy(retained), deepcopy(policy))
        if path == seed else original_verify(path))
    original_membership = ledger.membership_inputs
    monkeypatch.setattr(ledger, "membership_inputs", lambda path: {seed, policy_path}
        if path == seed else original_membership(path))
    monkeypatch.setattr(ledger, "verify_policy", lambda root: deepcopy(policy) if root == directory else
        (_ for _ in ()).throw(ValueError("foreign fixture ledger")))
    monkeypatch.setattr(ledger, "_batches", lambda root, policy: [])

    runtime = deepcopy(previous.provenance["runtime_binding"])
    for child in (raw, raw / "bootstrap"):
        installed = load(child / "runtime.json") if (child / "runtime.json").exists() else load(raw / "runtime.json")
        metadata = inputs.get._load(installed["source_manifest_text"].encode())
        metadata.update(neqo_commit=FIXTURE_NATIVE, neqo_pinned_commit=FIXTURE_NATIVE)
        installed["source_manifest_text"] = graph.canonical_bytes(metadata).decode()
        implementation = installed["qualification_implementation"]
        implementation["source"] = metadata
        implementation["neqo_qcsd_client"]["sha256"] = FIXTURE_CLIENT
        implementation["sha256"] = inputs.get.chaff_qualification._implementation_aggregate(implementation)
        if child == raw:
            write(raw / "runtime.json", installed)
            runtime.update(native_commit=FIXTURE_NATIVE, client_sha256=FIXTURE_CLIENT,
                source_manifest_sha256=graph.digest(installed["source_manifest_text"].encode()))
        run = load(child / "native/run.json"); run["migration_commit"] = FIXTURE_NATIVE
        write(child / "native/run.json", run)
        started = load(child / "native-started.json"); started["client_sha256"] = FIXTURE_CLIENT
        write(child / "native-started.json", started)
        completed = load(child / "native-completed.json")
        completed.update(client_sha256=FIXTURE_CLIENT, source_manifest_sha256=runtime["source_manifest_sha256"])
        write(child / "native-completed.json", completed); reseal_outputs(child)
    profile = prep.open_reference(previous.original.provenance["profile"])
    monkeypatch.setattr(static, "load_context", lambda *a, **k:
        (_ for _ in ()).throw(AssertionError("supplement must not replay original87 acquisition")))
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-03T23:59:59Z")
    root = tmp_path / "independent-cohort"
    cohort.initialize(root, seed_enrollment=seed, profile=profile, plans=[plan_path],
        graph_inputs=[input_path], failed_discoveries=[], expected_runtime=runtime)
    context = whole.load_context(root)
    declaration = load(raw / "declaration.json")
    declaration.update(context=prep.reference(root / "provenance.json"), position=1,
        graph_input=inputs.reference(input_path),runtime_binding=runtime, producer_sources=whole.producer_sources())
    write(raw / "declaration.json", declaration)
    for child in (raw, raw / "bootstrap"):
        started = load(child / "native-started.json")
        started["declaration_sha256"] = graph.digest((raw / "declaration.json").read_bytes())
        write(child / "native-started.json", started); reseal_outputs(child)
    write(raw / "full-get-proof.json", whole.build_proof(raw, context=context, position=1))
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:00:20Z")
    return {"raw":raw, "context":context, "seed":seed, "retained":retained,
        "policy":policy, "ledger":directory, "profile":profile, "plan":plan_path, "input":input_path}


def audit(case, tmp_path):
    terminal = whole.admit(case["context"], 1, case["raw"])
    original_manifest, _ = whole.prepared_workload(case["context"], terminal)
    row = {"candidate":case["context"].candidates[0], "manifest":prep.reference(original_manifest),
        "terminal":prep.reference(terminal), "context":prep.reference(case["context"].root/"provenance.json"),
        "capture_limits":case["context"].provenance["capture_limits"],
        "facts":whole.verify_terminal(terminal,case["context"])}
    result = {"audit_mode":"whole-terminal", "seed":None, "classes":[row], "scientific_credit":False}
    source = tmp_path/"controlled-source.json"; write(source,{"fixture_only":"separate original audit process"})
    directory=tmp_path/"controlled-audit"; directory.mkdir()
    command=[sys.executable,"-I","-B","-c",selected._LEGACY_PROGRAM,str(tmp_path),"whole-terminal",
        str(case["context"].root),str(terminal)]
    start=write(directory/"audit-started.json", {"schema_version":1,"command":command,
        "started_at":"2026-10-04T00:00:21Z","original_source_manifest":selected.reference(source),
        "original_source":load(source),"authority":selected.reference(case["context"].root/"provenance.json"),
        "terminal":selected.reference(terminal)})
    stdout=write(directory/"audit.stdout.log",result); stderr=directory/"audit.stderr.log";stderr.write_bytes(b"")
    end=write(directory/"audit-completed.json",{"schema_version":1,"returncode":0,"elapsed_seconds":1.0,
        "completed_at":"2026-10-04T00:00:22Z","started":selected.reference(start),
        "stdout":selected.reference(stdout),"stderr":selected.reference(stderr)})
    value={"contract":selected.CONTRACT,"original_source_root":str(tmp_path),
        "original_source_manifest":selected.reference(source),"legacy_program_sha256":graph.digest(selected._LEGACY_PROGRAM.encode()),
        "started":selected.reference(start),"completed":selected.reference(end),"stdout":selected.reference(stdout),
        "stderr":selected.reference(stderr),"result":result,"published_at":"2026-10-04T00:00:23Z","scientific_credit":False}
    return write(directory/"selection-audit.json",receipts._bind(selected.AUDIT_TYPE,value))


def test_independent_v9_get_selected_and_perclass_append_preserve_graph_and_seed(cohort_case,tmp_path,monkeypatch):
    case=cohort_case; before=case["seed"].read_bytes(); projected=inputs.load_input(case["input"])[1]
    assert len(case["context"].original.candidates)==0
    assert case["context"].candidates[0]["catalogue_candidate"]==load(case["plan"])["candidates"][0]
    files=set()
    assert cohort.metadata(case["policy"],case["context"].root/"provenance.json",files)==case["context"].provenance
    assert {case["seed"],case["ledger"]/"policy.json",case["input"],case["plan"]} <= files
    assert set(inputs.input_files(case["input"])[0]) <= files
    roots=whole.sealed_context_roots(case["context"])
    assert {path.parent for path in files} <= roots
    assert all(path.is_dir() and not path.is_symlink() for path in roots)
    audit_path=audit(case,tmp_path)
    monkeypatch.setattr(selected,"_legacy_source",lambda *a,**k:load(tmp_path/"controlled-source.json"))
    monkeypatch.setattr(receipts,"_now",lambda:"2026-10-04T00:00:30Z")
    identifier=case["context"].candidates[0]["candidate_id"]
    direct=selected.publish_input(tmp_path/"selected-input.json",audit=audit_path,candidate_id=identifier)
    prepared=selected.prepare_input(direct,tmp_path/(identifier+".json"))
    actual=load(prepared)
    assert [(r["id"],r["url"],r["headers"],r["depends_on"]) for r in actual["resources"]]==[
        (r["id"],r["url"],r["headers"],r["depends_on"]) for r in projected["resources"]]
    enrollment=ledger.enroll(case["ledger"],acquisition_root=case["context"].root,
        inputs={identifier:selected.reference(direct)},prepared_workloads={identifier:selected.reference(prepared)})
    _,classes,_=ledger.verify_enrollment(enrollment)
    assert classes[:1]==case["retained"] and classes[1]["class_index"]==2
    assert classes[1]["candidate_id"]==identifier and case["seed"].read_bytes()==before
    assert selected.validate_input(direct)[2]["full_list_coverage"] is True
    assert case["context"].provenance["formal_accepted_trace_count"]==0


@pytest.mark.parametrize("field",["seed_classes","candidates","capture_limits","reader_sources","profile","graph_inputs"])
def test_resealed_cohort_cannot_replace_membership_reservations_caps_sources_or_graph(cohort_case,field):
    case=cohort_case; path=case["context"].root/"provenance.json"
    value=receipts._unpack(path.read_bytes(),cohort.CONTEXT_TYPE)
    if field=="seed_classes":value[field][0]["class_index"]=2
    elif field=="candidates":value[field].reverse()
    elif field=="capture_limits":value[field]["max_response_bytes"]*=4
    elif field=="reader_sources":value[field]={}
    elif field=="profile":value[field]["sha256"]="0"*64
    else:value[field][next(iter(value[field]))]["sha256"]="0"*64
    write(path,receipts._bind(cohort.CONTEXT_TYPE,value))
    with pytest.raises(ValueError):whole.load_context(case["context"].root)


@pytest.mark.parametrize("field",["native_commit","client_sha256"])
def test_cohort_refuses_invalid_native_or_client_before_namespace(cohort_case,tmp_path,field):
    case=cohort_case; runtime=deepcopy(case["context"].provenance["runtime_binding"])
    runtime[field]="invalid-runtime-digest"
    output=tmp_path/"wrong-runtime"
    with pytest.raises(ValueError):cohort.initialize(output,seed_enrollment=case["seed"],profile=case["profile"],
        plans=[case["plan"]],graph_inputs=[case["input"]],failed_discoveries=[],expected_runtime=runtime)
    assert not output.exists()


def test_declared_runtime_accepts_a_different_valid_rebuild_without_source_edits():
    declared={"lab_commit":"1"*40,"native_commit":"2"*40,"client_sha256":"3"*64,
        "image_digest":"sha256:"+"4"*64,"source_manifest_sha256":"5"*64}
    assert cohort._runtime(declared)==declared
    assert "NATIVE" not in vars(cohort) and "CLIENT" not in vars(cohort)


def test_foreign_declared_client_cannot_execute_get_or_admit_installed_bytes(cohort_case,tmp_path,monkeypatch):
    case=cohort_case;claim=deepcopy(case["context"].provenance["runtime_binding"])
    claim["client_sha256"]="3"*64
    root=tmp_path/"foreign-installed-client"
    monkeypatch.setattr(receipts,"_now",lambda:"2026-10-03T23:59:59Z")
    cohort.initialize(root,seed_enrollment=case["seed"],profile=case["profile"],plans=[case["plan"]],
        graph_inputs=[case["input"]],failed_discoveries=[],expected_runtime=claim)
    monkeypatch.setattr(receipts,"_now",lambda:"2026-10-04T00:00:20Z")
    context=whole.load_context(root)
    actual=load(case["raw"]/"runtime.json")
    metadata=tmp_path/"installed-source.json";metadata.write_text(actual["source_manifest_text"])
    monkeypatch.setattr(inputs.get.util,"DEFAULT_SOURCE_METADATA",metadata)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST",claim["image_digest"])
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA",str(metadata))
    monkeypatch.setattr(inputs.get.chaff_qualification,"_qualification_execution_context",
        lambda:(actual["qualification_implementation"],None,None))
    monkeypatch.setattr(inputs.get.chaff_qualification,"_bound_neqo_client",lambda implementation:(inputs.get.CLIENT,FIXTURE_CLIENT))
    output=tmp_path/"must-not-start-GET"
    with pytest.raises(ValueError,match="installed client"):
        whole.execute_get(root,1,output)
    assert not output.exists()
    # Even a resealed declaration claiming the new client cannot admit raw
    # bytes whose independently bound installed implementation is different.
    declaration=load(case["raw"]/"declaration.json")
    declaration.update(context=prep.reference(root/"provenance.json"),runtime_binding=claim)
    write(case["raw"]/"declaration.json",declaration)
    with pytest.raises(ValueError,match="installed client"):
        whole.admit(context,1,case["raw"])
    assert not whole.terminal_path(context,1).exists()


def test_missing_earlier_declared_candidate_refuses_get_and_terminal(cohort_case,tmp_path):
    case=cohort_case
    with pytest.raises(ValueError,match="skip"):cohort.require_get(case["context"],2)
    with pytest.raises(ValueError,match="skip"):whole.record_deferral(case["context"],2)
    assert not whole.terminal_path(case["context"],2).exists()


def test_complete_graph_wrong_native_response_is_not_admission(cohort_case):
    case=cohort_case; run=load(case["raw"]/"native/run.json")
    run["responses"][1]["url"]="https://foreign.example/changed"
    write(case["raw"]/"native/run.json",run);reseal_outputs(case["raw"])
    with pytest.raises(ValueError):whole.admit(case["context"],1,case["raw"])
    assert not whole.terminal_path(case["context"],1).exists()


def test_single_origin_precheck_uses_resource_origins_not_approved_chaff_union(cohort_case,monkeypatch):
    case=cohort_case; original=whole._candidate_input
    def only_primary(context,position):
        row,ref,value,neutral=original(context,position)
        neutral["resources"]=[neutral["resources"][0]]
        return row,ref,value,neutral
    monkeypatch.setattr(whole,"_candidate_input",only_primary)
    with pytest.raises(ValueError,match="two-origin"):cohort.require_get(case["context"],1)


def test_independent_cohort_refuses_other_ledger_metadata(cohort_case):
    with pytest.raises(ValueError,match="another selected ledger"):
        cohort.metadata({**cohort_case["policy"],"class_target":20},cohort_case["context"].root/"provenance.json")


def test_public_fixed_target_refusal_reports_original_error_without_creating_output(tmp_path,monkeypatch,capsys):
    path=Path(__file__).resolve().parents[1]/"tools/rapid_fixed_condition_target.py"
    spec=importlib.util.spec_from_file_location("controlled_fixed_target_cli",path)
    cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
    progress=write(tmp_path/"controlled-progress.json",{"controlled_reader_boundary":True})
    output=tmp_path/"not-published.json"
    def refuse(*args,**kwargs):
        raise ValueError("membership dependency changed: whole_graph_input.py")
    monkeypatch.setattr(cli.reader,"publish_chunk_inputs",refuse)
    assert cli.main(["chunk-inputs","--progress",str(progress),"--progress-sha256",
        cli.reader.reference(progress)["sha256"],"--classes","17","18","--mode","undefended",
        "--output",str(output)])==1
    result=json.loads(capsys.readouterr().out)
    assert result=={"operation":"chunk-inputs","status":"refused","error_type":"ValueError",
        "error_message":"membership dependency changed: whole_graph_input.py"}
    assert not output.exists()


@pytest.mark.parametrize("candidate",[
    {"candidate_id":"tranco-new-id","domain":"www.retained.example","catalogue_position":32},
    {"candidate_id":"supplied-other-id","domain":"Retained.Example.","catalogue_position":32},
])
def test_cross_namespace_declared_primary_alias_cannot_repeat_enrolled_site(candidate):
    retained=[{"candidate_id":"original-supplied-id","canonical_sites":["retained.example"]}]
    with pytest.raises(ValueError,match="repeats"):
        cohort._rows([{"candidates":[candidate]}],retained)


def test_actual_final_primary_alias_refuses_enrollment_while_repeated_resource_urls_remain_legal():
    # The candidate's initial domain is distinct; its authenticated final host
    # joins a previously enrolled alias under the unchanged selected policy.
    candidate={"candidate_id":"tranco-new-id","domain":"different.example","catalogue_position":32}
    retained={"candidate_id":"supplied-original-id","workload_id":"old-workload","class_index":1,
        "canonical_sites":["retained.example"]}
    assert cohort._rows([{"candidates":[candidate]}],[retained])[0]["candidate_id"]==candidate["candidate_id"]
    prepared={"preparation":{"final_url":"https://www.retained.example/"},
        "resources":[{"url":"https://cdn.example/repeat"},{"url":"https://cdn.example/repeat"}]}
    aliases=ledger.old._aliases(candidate,prepared)
    assert aliases==["different.example","retained.example"]
    with pytest.raises(ValueError,match="canonical primary site"):
        ledger.old._deduplicate([retained,{"candidate_id":candidate["candidate_id"],
            "workload_id":"new-workload","class_index":2,"canonical_sites":aliases}])
    assert prepared["resources"][0]["url"]==prepared["resources"][1]["url"]
