"""Synthetic controls for a NEW parallel partial reader; no scientific credit."""
from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
import textwrap
import zlib

import pytest

from qcsd_lab import rapid_parallel_partial_lane as reader
from qcsd_lab import rapid_chunk_partial_lane as serial
from qcsd_lab import rapid_fixed_condition_target as target
from tests.test_rapid_chunk_partial_lane import report, chunk_original

def peer_report():
    value=report(1,0,1,"undefended")
    value["intent"]["actuator"]=reader.ACTUATOR
    authority={"path":"/synthetic/authority.json","sha256":"a"*64,"mode":420}
    partition={"path":"/synthetic/host-partition.json","sha256":"b"*64,"mode":420}
    value["read_dependencies"]=[authority,partition]
    value["parallel_binding"]={"actuator":reader.ACTUATOR,"authority":authority,
        "partition":partition,"worker_index":0,"batch_root":"/synthetic/batch",
        "peer_processes":[{"worker_index":0,"returncode":1},{"worker_index":1,"returncode":1}],
        "peer_proof_scope":"original-deep-accepted-subset-after-unchanged-full-result-verification-v1",
        "global_session_retirement_pass_claim":False}
    return value

def test_parallel_role_keeps_full_original_failed_aggregate_and_offsets():
    value=peer_report();before=deepcopy(value)
    facts=reader.accepted_subset(value)
    assert value==before
    assert facts["accepted_count"]==1 and len(facts["remaining_samples"])==4
    assert facts["actuator"]==reader.ACTUATOR
    assert facts["registered_layout"]==reader.LAYOUT and facts["slot_start"]==0
    assert facts["aggregate_status"]=="incomplete" and facts["aggregate_summary"]["passed"] is False
    assert facts["aggregate_formal_credit"]==0 and facts["lane_pass_claim"] is False
    assert facts["global_session_retirement_pass_claim"] is False
    with pytest.raises(ValueError):
        serial.accepted_subset(value)

@pytest.mark.parametrize("change",["serial","missing-peer","failed-promoted","running","graph","partition","worker-index","global-pass"])
def test_parallel_role_refuses_promotions_or_lost_peer_authority(change):
    value=peer_report()
    if change=="serial":value["intent"]["actuator"]="run"
    elif change=="missing-peer":value["parallel_binding"]["peer_processes"].pop()
    elif change=="failed-promoted":value["experiment"]["samples"][1]["artifacts"]={"fake":"f"*64}
    elif change=="running":value["experiment"]["samples"][-1]["state"]="running"
    elif change=="graph":value["experiment"]["configuration"]["workloads"][0]["sha256"]="f"*64
    elif change=="partition":value["read_dependencies"].pop()
    elif change=="worker-index":value["parallel_binding"]["worker_index"]=True
    else:value["parallel_binding"]["global_session_retirement_pass_claim"]=True
    with pytest.raises(ValueError):
        reader.accepted_subset(value)

def predecessor_bytes():
    path=Path(__file__).parent/"fixtures/rapid_fixed_condition_target_source58.py.zlib.b85.txt"
    raw=zlib.decompress(base64.b85decode(path.read_bytes().strip()))
    assert hashlib.sha256(raw).hexdigest()=="76eb0532100db6bfbd247aa9bbac0006902d25502de37ee42d1bb3148659444c"
    return raw

def test_fixed_reader_adds_only_exact_new_role_seams_and_keeps_old_scientific_ast():
    old=predecessor_bytes();new=Path(target.__file__).read_bytes()
    assert target._reader_code_projection(old,"target")==target._reader_code_projection(
        target._parallel_partial_source_projection(new),"target")

def test_fixed_reader_compatibility_does_not_remove_changed_old_scientific_predicate():
    new=Path(target.__file__).read_bytes().replace(
        b"row['client_sha256']!=target['target_identity']['client_sha256']",
        b"False")
    assert target._reader_code_projection(predecessor_bytes(),"target")!=target._reader_code_projection(
        target._parallel_partial_source_projection(new),"target")

def parallel_fixture(tmp_path,monkeypatch,effect=None):
    """Reuse controlled original APIs, then stub explicitly synthetic parallel APIs."""
    source,inputs=chunk_original(tmp_path,effect=effect)
    source["files"]["src/qcsd_lab/rapid_partial_lane.py"] = reader.reference(
        Path(reader.original.__file__).absolute())
    source["files"]["src/qcsd_lab/verification.py"] = reader.reference(
        Path(serial.__file__).with_name("verification.py"))
    package=Path(source["root"])/"src/qcsd_lab"
    raw=json.loads((package/"report.json").read_bytes())
    raw["intent"].update(actuator=reader.ACTUATOR,campaign_name=raw["lane"]["campaign_name"])
    (package/"report.json").write_text(json.dumps(raw))
    Path(inputs["intent"]["path"]).write_text(json.dumps(raw["intent"]))
    inputs["intent"]=reader.reference(inputs["intent"]["path"])
    batch=tmp_path/"batch";(batch/"lane-1/gate").mkdir(parents=True)
    partition=batch/"lane-1/gate/host-partition.json";partition.write_text('{"controlled_partition":true}')
    (batch/"host-process.json").write_text('{"returncode":1,"closed":true}')
    authority=tmp_path/"authority.json"
    peer=tmp_path/"evidence/peer";peer.mkdir()
    peer_intent=peer/"intent.json";peer_intent.write_text(json.dumps(raw["intent"]))
    (peer/"host-process.json").write_text('{"index":1}')
    Path(inputs["intent"]["path"]).with_name("host-process.json").write_text('{"index":0}')
    value={"lane_intents":[{"path":inputs["intent"]["path"]},{"path":str(peer_intent)}],
        "lane_specs":[{"path":inputs["spec"]["path"]},{"path":inputs["spec"]["path"]}]}
    authority.write_text(json.dumps(value))
    module=package/"rapid_lane_evidence.py"
    body=module.read_text()
    old="def _verified_host_process(raw,root,intent_raw,campaign_name):"
    start=body.index(old);end=body.index("def _object(",start)
    replacement=textwrap.dedent(f'''\
        def _host_intent(raw):return json.loads(raw)
        def _verified_host_process(raw,root,intent_raw,campaign_name):
            index=json.loads(raw)['index']
            return {{'start':{{}},'command':['synthetic','run'],'started_at':'2026-10-05T00:00:00+00:00','completed_at':'2026-10-05T00:03:00+00:00','returncode':1,'interruption':None,'actuator':'parallel-formal-worker','worker_index':index,'authority':{{'path':{str(authority)!r}}},'batch_root':{str(batch)!r},'_authority_value':json.loads(Path({str(authority)!r}).read_text()),'retirement':{{'controlled':index}}}}
        ''')
    module.write_text(body[:start]+replacement+body[end:])
    (package/"rapid_formal_parallel.py").write_text(textwrap.dedent('''\
        import json
        from pathlib import Path
        def _reference(ref):return Path(ref['path'])
        def require_batch_closure(process):
            value=json.loads((Path(process['batch_root'])/'host-process.json').read_text())
            if value!={'returncode':1,'closed':True}:raise ValueError('synthetic host closure changed')
        '''))
    (package/"rapid_parallel_capture.py").write_text(textwrap.dedent('''\
        import json
        from pathlib import Path
        def load(path):return json.loads(Path(path).read_text())
        def verify_peer_sample_bindings(experiment,partition):
            if partition!={'controlled_partition':True}:raise ValueError('synthetic partition changed')
            if not experiment['samples'] or any(sample['state']!='accepted' for sample in experiment['samples']):
                raise ValueError('synthetic peer predicate got a nonaccepted projection')
        '''))
    binding=tmp_path/"source-binding.json";binding.write_text("{}")
    reader_binding=tmp_path/"reader-binding.json";reader_binding.write_text("{}")
    inputs.update(source_binding=reader.reference(binding),reader_binding=reader.reference(reader_binding),
        root_offline_endpoint_replay=False)
    monkeypatch.setattr(serial,"_source",lambda ref:source)
    monkeypatch.setattr(reader,"_reader",lambda ref:{"reader_source":{"files":{}}})
    return source,inputs,batch,raw

def test_actual_isolated_new_parallel_program_and_fresh_verify_keep_original_capture_bytes(tmp_path,monkeypatch):
    source,inputs,batch,raw=parallel_fixture(tmp_path,monkeypatch)
    before={p:p.read_bytes() for p in Path(inputs["result"]["path"]).rglob("*") if p.is_file()}
    receipt=reader.declare(source_binding=inputs["source_binding"],reader_binding=inputs["reader_binding"],
        spec=Path(inputs["spec"]["path"]),evidence_root=Path(inputs["evidence_root"]),intent=Path(inputs["intent"]["path"]),
        result=Path(inputs["result"]["path"]),audit_root=tmp_path/"declare-proof",output=tmp_path/"partial.json")
    verified=reader.verify(receipt,audit_root=tmp_path/"independent-proof")
    value=reader._document(receipt,reader.TYPE)
    assert value["deep_operation"]!=verified["fresh_deep_operation"]
    assert verified["accepted_count"]==5 and value["actuator"]==reader.ACTUATOR
    assert value["aggregate_status"]=="incomplete" and value["aggregate_summary"]["failed"]==5
    assert reader._PROGRAM!=serial._PROGRAM
    assert all(path.read_bytes()==body for path,body in before.items())

@pytest.mark.parametrize("effect",["write","network","docker"])
def test_new_parallel_program_preserves_original_read_only_effect_fence(tmp_path,monkeypatch,effect):
    source,inputs,batch,raw=parallel_fixture(tmp_path,monkeypatch,effect=effect)
    with pytest.raises(ValueError,match="raw audit"):
        reader._run_original(source,inputs,tmp_path/"proof")
    assert json.loads((tmp_path/"proof/completed.json").read_bytes())["returncode"]!=0
    assert not (Path(inputs["result"]["path"])/"forbidden.txt").exists()


def reader_git_fixture(tmp_path):
    """Real paired Git fixture with the private full mode from actual H005."""
    from tests.test_rapid_chunk_partial_lane import git
    root=tmp_path/"reader-git";root.mkdir()
    native=root/"neqo-qcsd";native.mkdir()
    (native/"Cargo.lock").write_text("controlled Native bytes\n")
    git(native,"init");git(native,"add","Cargo.lock")
    git(native,"-c","user.name=fixture","-c","user.email=fixture@example.invalid",
        "commit","-m","controlled Native")
    native_head=git(native,"rev-parse","HEAD")
    for name in reader._READER_MODULE_ROLES:
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text("# controlled registered role: "+name+"\n")
    private=root/"config/curated-sources/private.json";private.parent.mkdir(parents=True)
    private.write_text('{"controlled":true}\n');private.chmod(0o600)
    executable=root/"qcsd-lab";executable.write_text("#!/bin/sh\nexit 0\n");executable.chmod(0o755)
    git(root,"init");git(root,"add","src","tools","config","qcsd-lab")
    git(root,"update-index","--add","--cacheinfo","160000,"+native_head+",neqo-qcsd")
    git(root,"-c","user.name=fixture","-c","user.email=fixture@example.invalid",
        "commit","-m","controlled prospective reader")
    return root,git(root,"rev-parse","HEAD"),native_head,private


def test_reader_source_separates_stock_real_git_mode_refusal_and_exact_reader_modes(tmp_path,monkeypatch):
    root,lab_head,native_head,private=reader_git_fixture(tmp_path)
    with pytest.raises(ValueError,match="original verifier Source bytes or mode differ from release"):
        serial.release_snapshot(root,lab_head,native_head)
    # The old function genuinely refused the real paired Git checkout above.
    # The new snapshot must authenticate its own contract without calling it.
    def forbidden(*args,**kwargs):
        raise AssertionError("prospective reader called the measurement release snapshot")
    monkeypatch.setattr(serial,"release_snapshot",forbidden)
    snapshot=reader.reader_source_snapshot(root,lab_head,native_head)
    assert snapshot["contract"]==reader.READER_SOURCE_CONTRACT
    assert snapshot["files"]["config/curated-sources/private.json"]==reader.reference(private)
    assert snapshot["mode_pairs"]["config/curated-sources/private.json"]=={
        "git_mode":"100644","observed_full_mode":0o600}
    assert snapshot["mode_pairs"]["qcsd-lab"]=={
        "git_mode":"100755","observed_full_mode":0o755}
    assert set(snapshot["files"])==set(snapshot["mode_pairs"])
    assert snapshot["module_roles"]=={name:{"role":role,"reference":snapshot["files"][name]}
        for name,role in reader._READER_MODULE_ROLES.items()}
    private.chmod(0o644)
    # Both permission classes are legal initially, but the published exact
    # full-mode dependency and complete snapshot cannot reopen as the old one.
    with pytest.raises(ValueError,match="bytes or mode changed"):
        reader.reopen(snapshot["files"]["config/curated-sources/private.json"])
    assert reader.reader_source_snapshot(root,lab_head,native_head)!=snapshot


@pytest.mark.parametrize("change",["bytes","untracked-import","missing-role","native-head","unsafe-mode","exec-class"])
def test_reader_source_rejects_changed_bytes_membership_native_and_permission_roles(tmp_path,change):
    from tests.test_rapid_chunk_partial_lane import git
    root,lab_head,native_head,private=reader_git_fixture(tmp_path)
    if change=="bytes":private.write_text('{"controlled":false}\n')
    elif change=="untracked-import":
        (root/"src/qcsd_lab/unbound.py").write_text("# unbound\n")
    elif change=="missing-role":
        relative="tools/rapid_parallel_partial_lane.py"
        git(root,"rm",relative)
        git(root,"-c","user.name=fixture","-c","user.email=fixture@example.invalid",
            "commit","-m","remove required role")
        lab_head=git(root,"rev-parse","HEAD")
    elif change=="native-head":native_head="0"*40
    elif change=="unsafe-mode":private.chmod(0o666)
    else:(root/"qcsd-lab").chmod(0o600)
    with pytest.raises(ValueError,match="prospective reader"):
        reader.reader_source_snapshot(root,lab_head,native_head)

