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
from tests.test_rapid_quick_profile import direct

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


def saved_current_config_report():
    """Authentic current configuration over synthetic partial/peer records."""
    path=Path(__file__).parent/'fixtures/rapid_parallel_partial_current_undefended_configuration.json'
    fixture=json.loads(path.read_bytes())
    assert fixture['source_raw_report_sha256']=='04e8a87b400a58f0b4ef95be93c00dde27e43b67ac470c1ffa10a3112822ac6e'
    config=fixture['configuration']
    assert set(config)=={'application_body_identity_policy','campaign_sha256','defenses',
        'limits','profile','request_policies','workloads'}
    value=peer_report()
    old_ids=value['lane']['workload_ids']
    rows=config['workloads']
    names={old:row['id'] for old,row in zip(old_ids,rows,strict=True)}
    value['lane']['workload_ids']=[row['id'] for row in rows]
    value['experiment']['configuration']=config
    value['intent']['campaign_sha256']=config['campaign_sha256']
    for site,row in zip(value['sites'],rows,strict=True):
        site.update(workload_id=row['id'],workload_sha256=row['sha256'],
            qualification_set=None,qualification_set_manifest_sha256=None)
    for sample in value['experiment']['samples']:
        sample['workload_id']=names[sample['workload_id']]
    return value


def test_saved_current_undefended_configuration_omits_chaff_fields_and_stays_exact():
    value=saved_current_config_report();before=deepcopy(value)
    facts=reader.accepted_subset(value)
    assert value==before and facts['configuration']==before['experiment']['configuration']
    assert 'chaff_qualification_set' not in facts['configuration']
    assert 'chaff_qualification_set_manifest_sha256' not in facts['configuration']
    assert facts['accepted_count']==1 and len(facts['remaining_samples'])==4
    assert facts['aggregate_status']=='incomplete' and facts['aggregate_formal_credit']==0
    assert facts['lane_pass_claim'] is False


def test_current_undefended_configuration_refuses_a_qualified_set():
    value=saved_current_config_report()
    value['experiment']['configuration']['chaff_qualification_set']='unbound-qualified-set'
    with pytest.raises(ValueError,match='partial lane changes original incomplete formal contract'):
        reader.accepted_subset(value)


@pytest.mark.parametrize('change',['missing-set','null-set','wrong-set','wrong-manifest'])
def test_defended_configuration_still_requires_exact_set_and_full_manifest(change):
    value=report(1,0,1,'front')
    value['intent']['actuator']=reader.ACTUATOR
    config=value['experiment']['configuration']
    if change=='missing-set':del config['chaff_qualification_set']
    elif change=='null-set':config['chaff_qualification_set']=None
    elif change=='wrong-set':config['chaff_qualification_set']='other-qualified-set'
    else:config['chaff_qualification_set_manifest_sha256']='f'*64
    with pytest.raises(ValueError):
        reader._accepted_subset(value)


@pytest.fixture
def parallel_rows(tmp_path):
    """Stock current manifest schema and real files; deep authority is synthetic."""
    from tests.test_rapid_fixed_condition_target import setting, write
    root=tmp_path/'result';root.mkdir()
    graph={'resources':[{'id':0,'url':'https://main.example/','headers':[]},
        {'id':1,'url':'https://cdn.example/asset','headers':[],'dependencies':[0]}],
        'primary_resource_id':0,'preparation':{'final_url':'https://main.example/',
        'approved_origins':['https://main.example','https://cdn.example']}}
    manifest=write(root/'inputs/workloads/whole.json',graph)
    config,run=setting('undefended')
    config['limits']={'max_response_bytes':16777216,'capture_megabytes':64,
        'capture_seconds':180,'max_attempts':3,'per_origin_cooldown_seconds':0,
        'settle_seconds':2,'timeout_seconds':120}
    config['workloads']=[{'id':'whole','manifest':'inputs/workloads/whole.json',
        'sha256':manifest['sha256'],'visits':1,'origin_count':2,'resource_count':2}]
    run_ref=write(root/'samples/accepted/neqo/run.json',run)
    source_binding=write(tmp_path/'source-binding.json',{'synthetic':True})
    source={'binding_reference':source_binding,'binding':{'runtime_identity':{'client_sha256':'c'*64}}}
    report={'result_root':str(root),'experiment':{'configuration':config,'samples':[
        {'sample_id':'accepted','workload_id':'whole','path':'samples/accepted',
        'state':'accepted','eligible':True}]},'read_dependencies':[manifest,run_ref]}
    facts={'actuator':reader.ACTUATOR,'registered_layout':reader.LAYOUT,
        'configuration':config,'intent':{'started_at':'2026-10-01T00:00:00+00:00'},
        'measurement_source':{'lab_commit':'a'*40,'neqo_commit':'818d89398a5b0bc725e424b648d878185d18125d',
            'neqo_pinned_commit':'818d89398a5b0bc725e424b648d878185d18125d'},
        'accepted_samples':[{'candidate_id':'candidate','workload_id':'whole','sample_id':'accepted',
            'logical_visit':3,'actual_local_visit':0,'mode':'undefended','workload_sha256':manifest['sha256']}]}
    return source,report,facts


@pytest.mark.parametrize('layout',['manifest','legacy-path','same-both'])
def test_parallel_target_rows_use_observed_complete_manifest_and_keep_actual_condition(parallel_rows,layout):
    source,report,facts=parallel_rows
    workload=report['experiment']['configuration']['workloads'][0]
    if layout=='legacy-path':workload['path']=workload.pop('manifest')
    elif layout=='same-both':workload['path']=workload['manifest']
    before_source,before_report,before_facts=deepcopy(source),deepcopy(report),deepcopy(facts)
    rows=target._partial_rows(source,report,facts)
    assert source==before_source and report==before_report and facts==before_facts
    assert len(rows)==1 and rows[0]['visit']==rows[0]['logical_visit']==3
    assert rows[0]['original_graph_sha256']==target.membership.graph_identity(
        Path(report['result_root'])/'inputs/workloads/whole.json')
    assert rows[0]['source_binding']==source['binding_reference']
    assert rows[0]['measurement_source']==facts['measurement_source']
    assert rows[0]['capture_limits']==facts['configuration']['limits']
    assert rows[0]['aggregate_status']=='incomplete' and rows[0]['aggregate_formal_credit']==0
    assert rows[0]['lane_pass_claim'] is False


@pytest.mark.parametrize('change',['conflicting-path','missing-manifest','absolute-manifest',
    'escaping-manifest','unobserved-graph','unobserved-run','graph-hash','graph-mode'])
def test_parallel_target_rows_refuse_unbound_or_escaping_full_graph(parallel_rows,change):
    source,report,facts=parallel_rows
    workload=report['experiment']['configuration']['workloads'][0]
    if change=='conflicting-path':workload['path']='inputs/workloads/other.json'
    elif change=='missing-manifest':del workload['manifest']
    elif change=='absolute-manifest':workload['manifest']=str(Path(report['result_root'])/workload['manifest'])
    elif change=='escaping-manifest':workload['manifest']='../outside.json'
    elif change=='unobserved-graph':report['read_dependencies'].pop(0)
    elif change=='unobserved-run':report['read_dependencies'].pop()
    elif change=='graph-hash':facts['accepted_samples'][0]['workload_sha256']='f'*64
    else:
        path=Path(report['result_root'])/workload['manifest']
        path.chmod(0o600 if target.reference(path)['mode']!=0o600 else 0o644)
    with pytest.raises(ValueError):target._partial_rows(source,report,facts)


def test_parallel_row_dispatch_projection_keeps_every_old_partial_row_predicate():
    raw=Path(target.__file__).read_bytes()
    changed=raw.replace(b"manifest_ref['sha256']!=slot['workload_sha256']",b'False')
    assert raw!=changed
    assert target._reader_code_projection(target._parallel_partial_source_projection(raw),'target')!=\
        target._reader_code_projection(target._parallel_partial_source_projection(changed),'target')

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


def image_join_fixture(tmp_path):
    """Real original chunk join with controlled export/capture image roles."""
    source,inputs=chunk_original(tmp_path)
    raw=json.loads((Path(source["root"])/"src/qcsd_lab/report.json").read_bytes())
    identity=source["binding"]["runtime_identity"]
    identity["source"]={**identity["source"],"image_digest":None}
    raw["intent"]["runtime_identity"]["runtime_source"]={
        **raw["intent"]["runtime_identity"]["runtime_source"],
        "image_digest":identity["collection_image_digest"]}
    raw["read_dependencies"] = [
        reader.reference(raw["spec"]["plan_receipt"]),
        reader.reference(tmp_path/"chunk-policy.json")]
    return source,raw


def test_export_capture_image_join_keeps_original_guards_report_and_source_bytes(tmp_path):
    source,raw=image_join_fixture(tmp_path)
    before_source,before_raw=deepcopy(source),deepcopy(raw)
    with pytest.raises(ValueError,match="chunk partial measurement Source or image differs"):
        serial._measurement_binding(raw,source)
    joined=reader._measurement_binding(raw,source)
    assert source==before_source and raw==before_raw
    assert joined["chunk_bindings"]["plan"]==reader.reference(raw["spec"]["plan_receipt"])
    assert joined["image_metadata_join"]["installed_export_source"]["image_digest"] is None
    assert joined["image_metadata_join"]["captured_source"]==raw["experiment"]["source"]
    assert joined["image_metadata_join"]["projection_scope"]=="in-memory-installed-source-identity-image-field-only"
    assert joined["image_metadata_join"]["original_report_rewritten"] is False
    assert joined["image_metadata_join"]["source_binding_rewritten"] is False
    # The original function and unchanged original inputs continue to refuse.
    with pytest.raises(ValueError,match="chunk partial measurement Source or image differs"):
        serial._measurement_binding(raw,source)


@pytest.mark.parametrize("change",["captured-image","export-image","native","dirty","extra-source-field",
    "intent-client","intent-image","spec-image","spec-module","experiment-image","missing-export-image",
    "runtime-copy-mode","runtime-copy-bytes"])
def test_export_capture_image_join_refuses_all_other_identity_and_original_runtime_changes(tmp_path,change):
    source,raw=image_join_fixture(tmp_path)
    wrong="sha256:"+"f"*64
    if change=="captured-image":raw["intent"]["runtime_identity"]["runtime_source"]["image_digest"]=wrong
    elif change=="export-image":source["binding"]["runtime_identity"]["source"]["image_digest"]=wrong
    elif change=="native":raw["intent"]["runtime_identity"]["runtime_source"]["neqo_commit"]="f"*40
    elif change=="dirty":raw["intent"]["runtime_identity"]["runtime_source"]["lab_dirty"]=True
    elif change=="extra-source-field":raw["intent"]["runtime_identity"]["runtime_source"]["unbound"]=True
    elif change=="intent-client":raw["intent"]["runtime_identity"]["client_sha256"]="f"*64
    elif change=="intent-image":raw["intent"]["runtime_identity"]["collection_image_digest"]=wrong
    elif change=="spec-image":raw["spec"]["collection_image_digest"]=wrong
    elif change=="spec-module":raw["spec"]["module_root"]=str(tmp_path/"unbound-module-root")
    elif change=="experiment-image":raw["experiment"]["source"]["image_digest"]=wrong
    elif change=="missing-export-image":del source["binding"]["runtime_identity"]["source"]["image_digest"]
    else:
        copy=tmp_path/"unbound-client-copy"
        copy.write_bytes(Path(source["binding"]["runtime"]["client_binary"]).read_bytes()
            if change=="runtime-copy-mode" else b"wrong client bytes")
        copy.chmod(0o700 if change=="runtime-copy-mode" else 0o755)
        raw["spec"]["client_binary"]=str(copy)
    with pytest.raises(ValueError):
        reader._measurement_binding(raw,source)


@pytest.fixture
def quick_join(direct, tmp_path):
    """Real stock quick guards over a synthetic material profile; no deep proof."""
    from dataclasses import asdict, replace
    from datetime import datetime, timezone
    from qcsd_lab import rapid_lane_evidence as lanes
    from qcsd_lab import rapid_quick_profile as quick
    from qcsd_lab import rapid_rolling_capture as rolling
    from qcsd_lab import rapid_rolling_schedule as schedule
    from qcsd_lab import rapid_slot_chunks as geometry
    from tests.test_rapid_quick_profile import write

    metadata = {**direct.capsule['source'], 'image_digest':None}
    write(direct.spec.source_manifest, metadata)
    canonical = json.loads(direct.canonical.read_bytes())
    canonical.update(source=metadata,
        exported_source_manifest_sha256=lanes._sha(direct.spec.source_manifest.read_bytes()))
    write(direct.canonical, canonical)
    direct.capsule.update(source=metadata, current_canonical=rolling._ref(direct.canonical),
        original_canonical=rolling._ref(direct.canonical))
    direct.capsule['material_files'] = [rolling._ref(path) for path in direct.material]
    write(direct.path, direct.capsule)
    profile = rolling._ref(direct.path)
    path = quick.publish_plan(direct.spec, profile, tmp_path/'quick-plan.json', slot_start=4, slot_count=2)
    spec = replace(direct.spec, plan_receipt=path)
    payload = lanes.plan_payload(path.read_bytes())
    lane = lanes._lane({'plan_payload':payload}, payload['lanes'][0]['campaign_name'])
    captured = {**metadata, 'image_digest':spec.collection_image_digest}
    source = {'root':str(spec.module_root), 'files':{
        'src/qcsd_lab/' + module.__name__.rsplit('.', 1)[-1] + '.py':reader.reference(Path(module.__file__).absolute())
        for module in (lanes, quick, rolling, schedule, geometry)},
        'binding':{'runtime_identity':{'source':metadata,
            'collection_image_digest':spec.collection_image_digest,
            'client_sha256':lanes._sha(spec.client_binary.read_bytes())},
            'runtime':{key:spec.serializable()[key] for key in serial.RUNTIME_KEYS},
            'canonical':rolling._ref(direct.canonical)}}
    raw = peer_report()
    raw.update(spec=spec.serializable(), lane=asdict(lane), sites=payload['sites'])
    raw['experiment']['source'] = captured
    raw['intent'].update(runtime_identity={'runtime_source':captured,
        'collection_image_digest':spec.collection_image_digest,
        'client_sha256':source['binding']['runtime_identity']['client_sha256']},
        started_at=datetime.now(timezone.utc).isoformat())
    raw['lineage']['image_check'] = {'proof':{'plan_payload':payload,
        'plan_receipt_sha256':reader.reference(path)['sha256']}}
    raw['read_dependencies'] = [reader.reference(path), reader.reference(direct.path)]
    return source, raw, direct


def test_direct_quick_join_keeps_real_plan_profile_and_original_report(quick_join):
    from qcsd_lab import rapid_quick_profile as quick
    source, raw, direct = quick_join
    before_source, before_raw = deepcopy(source), deepcopy(raw)
    joined = reader._measurement_binding(raw, source)
    assert source == before_source and raw == before_raw
    assert joined['chunk_bindings'] == {'plan':reader.reference(raw['spec']['plan_receipt']),
        'policy':reader.reference(direct.path)}
    assert json.loads(direct.path.read_bytes())['artifact_type'] == quick.CAPSULE_TYPE
    payload = raw['lineage']['image_check']['proof']['plan_payload']
    assert 'lane_layout' not in payload and 'slot_chunk_policy' not in payload
    assert joined['image_metadata_join']['captured_source'] == raw['experiment']['source']
    assert joined['image_metadata_join']['original_report_rewritten'] is False
    projected = {**source, 'binding':{**source['binding'], 'runtime_identity':{
        **source['binding']['runtime_identity'], 'source':raw['experiment']['source']}}}
    with pytest.raises(ValueError, match='chunk partial plan differs from original executed chunk authority'):
        serial._measurement_binding(raw, projected)


@pytest.mark.parametrize('change', ['executed-payload','executed-plan-sha','profile-sha','profile-ref-sha','lane-policy',
    'missing-plan','missing-profile','plan-mode','profile-mode','lane-mode','site-graph',
    'module-root','runtime-source-root','intent-image','intent-client','experiment-image',
    'runtime-copy-mode','runtime-copy-bytes','current-material-bytes','current-material-mode',
    'retained-guard','retained-guard-mode','intent-before-plan'])
def test_direct_quick_join_preserves_plan_profile_full_modes_and_current_runtime_guards(quick_join, tmp_path, monkeypatch, change):
    from dataclasses import asdict, replace
    from qcsd_lab import rapid_slot_chunks as geometry
    source, raw, direct = quick_join
    if change == 'executed-payload':
        raw['lineage']['image_check']['proof']['plan_payload']['planned_trace_count'] += 1
    elif change == 'executed-plan-sha':
        raw['lineage']['image_check']['proof']['plan_receipt_sha256'] = 'f'*64
    elif change == 'profile-sha':
        raw['lineage']['image_check']['proof']['plan_payload']['scheduling']['sha256'] = 'f'*64
    elif change == 'profile-ref-sha':
        from qcsd_lab import rapid_lane_evidence as lanes
        from qcsd_lab import rapid_quick_profile as quick
        from tests.test_rapid_quick_profile import write
        payload = raw['lineage']['image_check']['proof']['plan_payload']
        payload['scheduling']['sha256'] = 'f'*64
        path = Path(raw['spec']['plan_receipt'])
        write(path, lanes.admission._bind(quick.PLAN_TYPE, payload))
        changed = reader.reference(path)
        raw['lineage']['image_check']['proof']['plan_receipt_sha256'] = changed['sha256']
        raw['read_dependencies'][0] = changed
    elif change == 'lane-policy':
        lane = replace(geometry.checked_lane(raw['lane']), slot_policy_sha256='f'*64)
        raw['lane'] = asdict(replace(lane, campaign_name=geometry.name(lane, lane.generation)))
    elif change in ('missing-plan','missing-profile'):
        raw['read_dependencies'].pop(0 if change == 'missing-plan' else 1)
    elif change in ('plan-mode','profile-mode'):
        path = Path(raw['spec']['plan_receipt'] if change == 'plan-mode' else direct.path)
        path.chmod(0o644 if reader.reference(path)['mode'] == 0o600 else 0o600)
    elif change == 'lane-mode':
        lane = replace(geometry.checked_lane(raw['lane']), mode='front', qualification_set='other')
        raw['lane'] = asdict(replace(lane, campaign_name=geometry.name(lane, lane.generation)))
    elif change == 'site-graph':raw['sites'][0]['workload_sha256'] = 'f'*64
    elif change == 'module-root':raw['spec']['module_root'] = str(tmp_path/'other-module')
    elif change == 'runtime-source-root':raw['spec']['runtime_source_root'] = str(tmp_path/'other-runtime')
    elif change == 'intent-image':raw['intent']['runtime_identity']['collection_image_digest'] = 'sha256:'+'f'*64
    elif change == 'intent-client':raw['intent']['runtime_identity']['client_sha256'] = 'f'*64
    elif change == 'experiment-image':raw['experiment']['source']['image_digest'] = 'sha256:'+'f'*64
    elif change in ('runtime-copy-mode','runtime-copy-bytes'):
        copy = tmp_path/'other-client'
        copy.write_bytes(direct.spec.client_binary.read_bytes() if change == 'runtime-copy-mode' else b'changed client')
        copy.chmod(0o600 if change == 'runtime-copy-mode' else 0o644)
        raw['spec']['client_binary'] = str(copy)
    elif change == 'current-material-bytes':direct.manifest.write_bytes(direct.manifest.read_bytes()+b'\nchanged')
    elif change == 'current-material-mode':direct.manifest.chmod(0o600)
    elif change == 'retained-guard':source['files']['src/qcsd_lab/rapid_quick_profile.py']['sha256'] = 'f'*64
    elif change == 'retained-guard-mode':
        from qcsd_lab import rapid_quick_profile as quick
        copy = tmp_path/'quick-guard.py'
        copy.write_bytes(Path(quick.__file__).read_bytes())
        copy.chmod(0o600 if reader.reference(quick.__file__)['mode'] != 0o600 else 0o644)
        monkeypatch.setattr(quick, '__file__', str(copy))
    else:raw['intent']['started_at'] = '1999-01-01T00:00:00Z'
    with pytest.raises(ValueError):
        reader._measurement_binding(raw, source)
