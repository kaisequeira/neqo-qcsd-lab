"""HOST target controls; installed/deep acceptance primitives are controlled.

Fixtures exercise real files, graph hashes, Source/mode/membership closing and
public ledger readers. They neither simulate actual scientific eligibility nor
award credit. The external actual8192 facts file is a zero-credit contract.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import application_response_policy as app
from qcsd_lab import tamaraw_fixed_configuration as tam
from qcsd_lab.supplied_static_admission import capture_limits
from qcsd_lab.rapid_operation_facts import OperationFacts

NATIVE='c24da2afeec2944a67c48b38eba957dcd543728d'
CLIENT=hashlib.sha256(b'controlled client').hexdigest()
def time_before(seconds=1):return (datetime.now(timezone.utc)-timedelta(seconds=seconds)).isoformat()
def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(target._json(value));return target.reference(path)
def artifact(path,kind,value):return target.epoch._write(path,kind,value)


def setting(mode):
    configuration={'profile':'research-1200','request_policies':['as-defined'],
        'defenses':[{'name':mode,'kind':'none' if mode=='undefended' else mode,'baseline':mode=='undefended'}]}
    run={'resolved_configuration':None,'defense_parameters':None,
        'application_response_policy':app.COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        'primary_document_identity_policy':app.VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY}
    if mode!='undefended':
        run['resolved_configuration']=tam.resolved_configuration()
        if mode!='tamaraw':
            run['resolved_configuration']['initial_max_stream_data']=16
            run['resolved_configuration']['defense']={'kind':mode,'fixed_parameter':1200}
    if mode=='tamaraw':
        configuration.update({tam.FIELD:tam.POLICY,'tamaraw_configuration_sha256':tam.configuration_sha256(),
            app.APPLICATION_BODY_IDENTITY_FIELD:app.COMPLETE_APPLICATION_DELIVERY_POLICY})
    return configuration,run


def duration_setting():
    """Use the checked-in parameter bytes and the genuine typed Native policy."""
    configuration, run = setting('buflo')
    root = Path(__file__).resolve().parents[1]
    path = root / target.duration.PARAMETER_PATH
    raw = path.read_bytes()
    assert raw == target.duration.parameter_bytes()
    provenance = Path(str(path) + '.provenance.json')
    assert hashlib.sha256(provenance.read_bytes()).hexdigest() == target.traffic.PROVENANCE_SHA256
    configuration['defenses'][0].update(parameters=str(path),
        parameters_sha256=target.duration.PARAMETER_SHA256, provenance=str(provenance),
        provenance_sha256=target.traffic.PROVENANCE_SHA256)
    run['method'] = 'GET'
    run['resolved_configuration']['defense'] = {'kind': 'buflo', 'parameters': str(path)}
    run['defense_parameters'] = {'kind': 'buflo', 'path': str(path),
        'sha256': target.duration.PARAMETER_SHA256, 'implementation_scope': 'client_only_quic',
        'paper_equivalent': False, target.duration.RUN_FIELD: dict(target.duration.RECEIPT)}
    target.duration.validate_native_receipt(run, raw, expected_path=str(path))
    return configuration, run


@pytest.fixture
def case(tmp_path,monkeypatch):
    conditions={}
    for mode in target.MODES:
        config,run=setting(mode)
        conditions[mode]=target.describe_condition(write(tmp_path/(mode+'-configuration.json'),config),
            write(tmp_path/(mode+'-run.json'),run),mode,tmp_path/(mode+'-condition.json'))
    rows=[]
    for index in range(1,4):
        manifest={'resources':[{'id':0,'url':f'https://host{index}.example/',
            'headers':[['accept','*/*']]},{'id':1,'url':f'https://secondary{index}.example/asset',
            'headers':[['accept-encoding','gzip']],'dependencies':[0]},
            {'id':2,'url':f'https://secondary{index}.example/asset','headers':[['accept-encoding','gzip']],
             'dependencies':[0]}], 'primary_resource_id':0,
            'preparation':{'final_url':f'https://host{index}.example/','approved_origins':
                [f'https://host{index}.example',f'https://secondary{index}.example']}}
        path=tmp_path/f'class-{index}.json';manifest_ref=write(path,manifest)
        rows.append({'class_index':index,'candidate_id':f'candidate-{index}','workload_id':f'whole-{index}',
            'canonical_sites':[f'host{index}.example'],'original_manifest':manifest_ref,
            'original_graph_sha256':target.membership.graph_identity(path),'capture_limits':capture_limits(16*1024*1024,64)})
    enrollment=write(tmp_path/'enrollment.json',{'classes':rows[:2]})
    calls=[]
    def declared_membership(ref):
        target._open(ref);calls.append(ref)
        return json.loads(Path(ref['path']).read_bytes())['classes'],{'files':[ref],'trees':[]}
    monkeypatch.setattr(target,'_membership',declared_membership)
    history=write(tmp_path/'retained-history.json',{'historical_count':44,'old_tamaraw':32})
    declarations=SimpleNamespace(root=tmp_path,conditions=conditions,rows=rows,enrollment=enrollment,
        history=history,membership_calls=calls)
    declarations.target=target.publish_target(namespace='prospective-fixed-example',enrollment=enrollment,
        conditions=conditions,native_head=NATIVE,client_sha256=CLIENT,history=[history],output=tmp_path/'target.json')
    return declarations


@pytest.fixture
def duration_case(case):
    configuration, run = duration_setting()
    case.conditions['buflo'] = target.describe_condition(write(case.root/'duration-configuration.json', configuration),
        write(case.root/'duration-run.json', run), 'buflo', case.root/'duration-condition.json')
    case.target = target.publish_target(namespace='prospective-fixed-duration-example', enrollment=case.enrollment,
        conditions=case.conditions, native_head=NATIVE, client_sha256=CLIENT, history=[case.history],
        output=case.root/'duration-target.json')
    return case


def audit_rows(case,mode,slots,*,row_change=None,partial=False):
    identity=target.condition_identity(*setting(mode),mode)
    rows=[]
    for i,slot in enumerate(slots):
        member=case.rows[0]
        row={'candidate_id':member['candidate_id'],'workload_id':member['workload_id'],
            'original_graph_sha256':member['original_graph_sha256'],'mode':mode,'logical_visit':slot,
            'actual_local_visit':i,'sample_id':f'{mode}-{slot}','result_root':str(case.root/('result-'+mode)),
            'condition':identity,'capture_limits':member['capture_limits'],'client_sha256':CLIENT,
            'measurement_source':{'lab_commit':'a'*40,'neqo_commit':NATIVE,'neqo_pinned_commit':NATIVE},
            'intent_started_at':datetime.now(timezone.utc).isoformat()}
        if partial:row.update(aggregate_status='incomplete',lane_pass_claim=False,aggregate_formal_credit=0)
        if row_change:row_change(row)
        rows.append(row)
    return {'rows':rows,'completed_at':datetime.now(timezone.utc).isoformat()}


def proof(case,monkeypatch,mode,slots,**kwargs):
    record=audit_rows(case,mode,slots,**kwargs)
    path=case.root/(mode+'-'+str(len(list(case.root.glob('proof-*'))))+'.json')
    path=case.root/('proof-'+path.name)
    ref=write(path,record)
    # Original installed/deep acceptance is an explicit controlled boundary.
    monkeypatch.setattr(target,'validate_audit',lambda r: json.loads(target._open(r).read_bytes()))
    return ref


def duration_proof(case, monkeypatch, change=None):
    def row_change(row):
        row['condition'] = target.condition_identity(*duration_setting(), 'buflo')
        row['capture_limits'] = target.duration.capture_limits('buflo', case.rows[0]['capture_limits'],
            policy=target.duration.POLICY)
        if change is not None: change(row)
    return proof(case, monkeypatch, 'buflo', [4], row_change=row_change)


def test_fixed_buflo200_intake_and_chunk_inputs_keep_original_caps_and_source_labels(duration_case, monkeypatch):
    case = duration_case; original = deepcopy(case.rows[0]['capture_limits'])
    initial = target.initialize_progress(target=case.target, proofs=[], output=case.root/'duration-initial.json')
    updated = target.append_progress(progress=initial, proofs=[duration_proof(case, monkeypatch)],
        output=case.root/'duration-next.json')
    value = target.validate_progress(updated); row = value['accepted_rows'][0]
    assert row['capture_limits'] == {**original, 'timeout_seconds': 240, 'capture_seconds': 300}
    assert row['measurement_source']['lab_commit'] == 'a'*40 and row['logical_visit'] == 4
    assert value['classes'][0]['capture_limits'] == original == case.rows[0]['capture_limits']
    inputs = target.chunk_inputs(updated, [1], 'buflo')
    assert inputs['capture_limits'] == row['capture_limits'] and inputs['capture_limits']['max_attempts'] == 3
    assert inputs['classes'][0]['capture_limits'] == original and 4 not in inputs['remaining_slots']
    path = target.publish_chunk_inputs(updated, [1], 'buflo', output=case.root/'duration-input.json')
    assert target.read_chunk_inputs(path)['inputs'] == inputs


@pytest.mark.parametrize('field', list(capture_limits(16*1024*1024,64)))
def test_fixed_buflo200_intake_refuses_each_changed_formal_cap(field, duration_case, monkeypatch):
    case = duration_case
    initial = target.initialize_progress(target=case.target, proofs=[], output=case.root/'duration-initial.json')
    def change(row): row['capture_limits'][field] += 1
    p = duration_proof(case, monkeypatch, change)
    output = case.root/'duration-refused.json'
    with pytest.raises(ValueError, match='caps'):
        target.append_progress(progress=initial, proofs=[p], output=output)
    assert not output.exists()


@pytest.mark.parametrize('change', ['parameter', 'provenance', 'scope', 'receipt', 'missing-receipt', 'resolved'])
def test_fixed_buflo200_caps_require_the_exact_declared_policy(change):
    condition = target.condition_identity(*duration_setting(), 'buflo')
    if change == 'parameter': condition['defense']['parameters_sha256'] = '0'*64
    elif change == 'provenance': condition['defense']['provenance_sha256'] = '0'*64
    elif change == 'scope': condition['defense_parameters']['implementation_scope'] = 'bilateral'
    elif change == 'receipt': condition['defense_parameters'][target.duration.RUN_FIELD]['max_events'] = 9999
    elif change == 'missing-receipt': del condition['defense_parameters'][target.duration.RUN_FIELD]
    else: condition['resolved_configuration']['defense']['parameters']['sha256'] = '0'*64
    with pytest.raises(ValueError): target._capture_limits('buflo', capture_limits(16*1024*1024,64), condition)


@pytest.mark.parametrize('mode', target.MODES)
def test_all_existing_fixed_conditions_keep_exact_original_caps(mode):
    original = capture_limits(16*1024*1024,64)
    assert target._capture_limits(mode, original, target.condition_identity(*setting(mode), mode)) == original


@pytest.mark.parametrize('mode', ['undefended', 'tamaraw'])
def test_target_intake_accepts_equivalent_seconds_without_rewriting_original_rows(mode, case, monkeypatch):
    initial = target.initialize_progress(target=case.target, proofs=[], output=case.root/'numeric-initial.json')
    def change(row):
        row['capture_limits'] = {**row['capture_limits'],
            'settle_seconds': 2.0, 'per_origin_cooldown_seconds': 0.0}
    original = proof(case, monkeypatch, mode, [4], row_change=change)
    updated = target.append_progress(progress=initial, proofs=[original], output=case.root/'numeric-next.json')
    value = target.validate_progress(updated)
    row = value['accepted_rows'][0]
    declaration = target.validate_target(case.target)
    assert value['target_id'] == declaration['target_id']
    assert value['target_accepted_count'] == 1 and row['logical_visit'] == 4
    assert type(row['capture_limits']['settle_seconds']) is float
    assert type(row['capture_limits']['per_origin_cooldown_seconds']) is float
    assert row['capture_limits'] == json.loads(Path(original['path']).read_bytes())['rows'][0]['capture_limits']
    assert type(value['classes'][0]['capture_limits']['settle_seconds']) is int
    assert row['condition'] == declaration['conditions'][mode]['identity']
    assert row['client_sha256'] == declaration['target_identity']['client_sha256']
    assert row['measurement_source']['neqo_commit'] == NATIVE
    assert target.chunk_inputs(updated, [1], mode)['capture_limits'] == case.rows[0]['capture_limits']


@pytest.mark.parametrize('field,value', [
    ('settle_seconds', 2.1), ('per_origin_cooldown_seconds', 0.1),
    ('settle_seconds', True), ('per_origin_cooldown_seconds', False),
    ('settle_seconds', '2'), ('capture_megabytes', 64.0),
    ('max_response_bytes', 16777216.0), ('max_attempts', 3.0),
])
def test_target_intake_refuses_changed_seconds_and_noninteger_caps(field, value, case, monkeypatch):
    initial = target.initialize_progress(target=case.target, proofs=[], output=case.root/'refusal-initial.json')
    def change(row): row['capture_limits'] = {**row['capture_limits'], field: value}
    original = proof(case, monkeypatch, 'undefended', [4], row_change=change)
    output = case.root/'refused-numeric-progress.json'
    with pytest.raises(ValueError, match='caps'):
        target.append_progress(progress=initial, proofs=[original], output=output)
    assert not output.exists()


@pytest.mark.parametrize('field', ['capture_seconds', 'timeout_seconds', 'settle_seconds',
                                  'per_origin_cooldown_seconds'])
def test_capture_limits_seconds_are_finite_numeric_values(field):
    expected = capture_limits(16*1024*1024,64)
    actual = {**expected, field: float(expected[field])}
    assert target._capture_limits_equal(actual, expected)
    assert target._capture_limits_equal(expected, actual)
    for invalid in [True, False, '2', None, float('nan'), float('inf'), -float('inf')]:
        assert not target._capture_limits_equal({**expected, field: invalid}, expected)
        assert not target._capture_limits_equal(expected, {**expected, field: invalid})


@pytest.mark.parametrize('field', ['capture_megabytes', 'max_response_bytes', 'max_attempts'])
def test_capture_limits_counts_remain_exact_integers(field):
    expected = capture_limits(16*1024*1024,64)
    for invalid in [float(expected[field]), True, False, str(expected[field]), None]:
        assert not target._capture_limits_equal({**expected, field: invalid}, expected)
        assert not target._capture_limits_equal(expected, {**expected, field: invalid})


def test_capture_limits_comparison_keeps_closed_fields_and_condition_types():
    expected = capture_limits(16*1024*1024,64)
    assert not target._capture_limits_equal({**expected, 'unknown': 0}, expected)
    assert not target._capture_limits_equal({k: v for k, v in expected.items() if k != 'settle_seconds'}, expected)
    assert not target._typed_equal({'initial_max_stream_data': 8192.0}, {'initial_max_stream_data': 8192})


def test_numeric_repair_does_not_waive_original_reader_source_authority(tmp_path):
    producer = deepcopy(target._sources())
    changed = tmp_path/'original-target-reader.py'
    changed.write_bytes(Path(target.__file__).read_bytes() + b'\n# distinct retained reader\n')
    producer['target'] = target.reference(changed)
    with pytest.raises(ValueError, match='producer/reader'):
        target._compatible_sources(producer)


def test_exact_source53_installed_deep_and_owned_timeout_project_to_source52_membership():
    source53 = Path(target.__file__).with_name('rapid_rolling_capture.py').read_bytes()
    assert hashlib.sha256(source53).hexdigest() == 'b6f8db16953987f60a3c7ea0003fdad187dd41343b875233e3abacb5f2e4fe14'
    assert hashlib.sha256(target._epoch_dispatch_source_projection(source53)).hexdigest() == (
        '080b519e94e2b7b2ec6ff47daf45e4779f1d544877ff5c47735377d2d3ed10c1')


@pytest.mark.parametrize('before,after', [
    (b"receipt=e.complete_lane(spec,root,target) if value['complete'] else target", b'receipt=target'),
    (b"_manifest_already_deep_verified=value['complete']", b'_manifest_already_deep_verified=True'),
    (b'check=False, timeout=timeout_seconds)', b'check=False, timeout=None)'),
    (b'labels.get("org.qcsd.owner") != "qcsd-lab"', b'False'),
    (b'recorded_docker(["docker", "rm", "-f", actual_id])', b'recorded_docker(["docker", "rm", "-f", name])'),
])
def test_source53_installed_deep_projection_rejects_skipped_completion_or_pertrace_check(before, after):
    source53 = Path(target.__file__).with_name('rapid_rolling_capture.py').read_bytes()
    assert source53.count(before) == 1
    changed = source53.replace(before, after, 1)
    with pytest.raises(ValueError, match='outside the exact published Source pair'):
        target._epoch_dispatch_source_projection(changed)


def test_initial_history_is_separate_tam_is_zero_and_available_prefix_can_plan(case):
    progress=target.initialize_progress(target=case.target,proofs=[],output=case.root/'progress.json')
    value=target.validate_progress(progress)
    assert value['target_accepted_count']==0 and value['final_target']==16000
    assert value['retained_history']==[case.history] and value['history_counts_as_target_credit'] is False
    assert all(row['remaining_slots']==list(range(64)) for row in value['remaining_vectors'])
    inputs=target.chunk_inputs(progress,[1,2],'tamaraw',maximum=16)
    assert inputs['ranges']==[{'slot_start':n,'slot_count':16} for n in (0,16,32,48)]
    assert inputs['old_capsule_or_chunk_authority_inferred'] is False
    snapshot=target.publish_chunk_inputs(progress,[1,2],'tamaraw',maximum=16,output=case.root/'chunk-input.json')
    assert target.read_chunk_inputs(snapshot)['inputs']==inputs
    with pytest.raises(ValueError):target.publish_final(progress,case.root/'corpus.json')
    assert not (case.root/'corpus.json').exists()


def test_original_none_and_front_can_carry_only_exact_conditions_and_slots(case,monkeypatch):
    ordinary=proof(case,monkeypatch,'undefended',[0,1,2,3])
    front=proof(case,monkeypatch,'front',[12,13,14,15])
    progress=target.initialize_progress(target=case.target,proofs=[ordinary,front],output=case.root/'progress.json')
    value=target.validate_progress(progress)
    assert value['target_accepted_count']==8
    assert [r['logical_visit'] for r in value['accepted_rows'] if r['mode']=='front']==[12,13,14,15]
    assert all(r['remaining_slots']==list(range(64)) for r in value['remaining_vectors'] if r['mode']=='tamaraw')
    assert value['accepted_rows'][0]['measurement_source']['lab_commit']=='a'*40


@pytest.mark.parametrize('change',['condition','graph','headers','caps','client','native','bool-slot','outside-slot','unknown-mode'])
def test_carry_refuses_changed_identity_graph_limits_and_malformed_slot(change,case,monkeypatch):
    def altered(row):
        if change=='condition':row['condition']['application_body_identity_policy']=app.COMPLETE_APPLICATION_DELIVERY_POLICY
        elif change=='graph':row['original_graph_sha256']='0'*64
        elif change=='headers':row['condition']['capture_policies']={'front_capture_policy':'changed'}
        elif change=='caps':row['capture_limits']={**row['capture_limits'],'max_response_bytes':64*1024*1024}
        elif change=='client':row['client_sha256']='0'*64
        elif change=='native':row['measurement_source']['neqo_commit']='0'*40
        elif change=='bool-slot':row['logical_visit']=True
        elif change=='outside-slot':row['logical_visit']=64
        else:row['mode']='unknown'
    p=proof(case,monkeypatch,'undefended',[0],row_change=altered)
    with pytest.raises(ValueError):target.initialize_progress(target=case.target,proofs=[p],output=case.root/'bad-progress.json')
    assert not (case.root/'bad-progress.json').exists()


def test_tam_initial_or_predeclaration_credit_is_refused(case,monkeypatch):
    p=proof(case,monkeypatch,'tamaraw',[0])
    with pytest.raises(ValueError):target.initialize_progress(target=case.target,proofs=[p],output=case.root/'initial-tam.json')
    initial=target.initialize_progress(target=case.target,proofs=[],output=case.root/'initial.json')
    raw=json.loads(Path(p['path']).read_bytes());raw['rows'][0]['intent_started_at']=time_before(100)
    p=write(Path(p['path']),raw)
    with pytest.raises(ValueError):target.append_progress(progress=initial,proofs=[p],output=case.root/'early-tam.json')
    assert not (case.root/'early-tam.json').exists()


def test_new_tam_partial_individual_slot_enters_without_promoting_failed_aggregate(case,monkeypatch):
    initial=target.initialize_progress(target=case.target,proofs=[],output=case.root/'initial.json')
    p=proof(case,monkeypatch,'tamaraw',[4],partial=True)
    updated=target.append_progress(progress=initial,proofs=[p],output=case.root/'next.json')
    value=target.validate_progress(updated)
    assert value['target_accepted_count']==1 and value['aggregate_status']=='incomplete'
    row=value['accepted_rows'][0]
    assert row['aggregate_status']=='incomplete' and row['lane_pass_claim'] is False and row['aggregate_formal_credit']==0
    assert [r for r in value['remaining_vectors'] if r['mode']=='tamaraw' and r['class_index']==1][0]['remaining_slots']==[v for v in range(64) if v!=4]


@pytest.mark.parametrize('duplicate',['logical','physical'])
def test_retries_cannot_duplicate_logical_or_physical_slots(duplicate,case,monkeypatch):
    p=proof(case,monkeypatch,'undefended',[0,1])
    raw=json.loads(Path(p['path']).read_bytes())
    if duplicate=='logical':raw['rows'][1]['logical_visit']=0
    else:raw['rows'][1]['sample_id']=raw['rows'][0]['sample_id']
    p=write(Path(p['path']),raw)
    with pytest.raises(ValueError):target.initialize_progress(target=case.target,proofs=[p],output=case.root/'duplicate.json')


def test_membership_extension_preserves_indices_graphs_and_slot_history(case):
    initial=target.initialize_progress(target=case.target,proofs=[],output=case.root/'initial.json')
    enrollment=write(case.root/'enrollment-next.json',{'classes':case.rows})
    extended=target.publish_target(namespace='prospective-fixed-example',enrollment=enrollment,
        conditions=case.conditions,native_head=NATIVE,client_sha256=CLIENT,history=[case.history],
        parent=case.target,output=case.root/'target-next.json')
    next_progress=target.append_progress(progress=initial,proofs=[],target=extended,output=case.root/'progress-next.json')
    value=target.validate_progress(next_progress)
    assert len(value['classes'])==3 and value['target_id']==target.validate_target(case.target)['target_id']
    assert value['classes'][:2]==case.rows[:2]
    changed=deepcopy(case.rows);changed[0]['capture_limits']=capture_limits(64*1024*1024,256)
    enrollment=write(case.root/'enrollment-changed.json',{'classes':changed})
    with pytest.raises(ValueError):target.publish_target(namespace='prospective-fixed-example',enrollment=enrollment,
        conditions=case.conditions,native_head=NATIVE,client_sha256=CLIENT,history=[case.history],
        parent=case.target,output=case.root/'replacement.json')


@pytest.mark.parametrize('changed',['class-prefix','condition','unknown','false-complete','count-bool'])
def test_closed_readers_refuse_rehashed_counter_and_authority_changes(changed,case):
    progress=target.initialize_progress(target=case.target,proofs=[],output=case.root/'initial.json')
    value=target.validate_progress(progress)
    if changed=='false-complete':value['aggregate_status']='complete'
    elif changed=='count-bool':value['target_accepted_count']=False
    elif changed=='unknown':value['waiver']=True
    elif changed=='class-prefix':value['classes'][0]['class_index']=2
    else:value['target_id']='0'*64
    altered=artifact(case.root/'altered.json',target.PROGRESS_TYPE,value)
    with pytest.raises(ValueError):target.validate_progress(altered)


def test_chunk_groups_split_when_gaps_or_caps_differ(case,monkeypatch):
    p=proof(case,monkeypatch,'undefended',[0])
    progress=target.initialize_progress(target=case.target,proofs=[p],output=case.root/'progress.json')
    with pytest.raises(ValueError,match='identical remaining'):target.chunk_inputs(progress,[1,2],'undefended')
    assert target.chunk_inputs(progress,[1],'undefended')['ranges'][0]=={'slot_start':1,'slot_count':16}
    case.rows[1]['capture_limits']=capture_limits(64*1024*1024,256)
    enrollment=write(case.root/'mixed.json',{'classes':case.rows[:2]})
    declaration=target.publish_target(namespace='mixed-explicit-target',enrollment=enrollment,conditions=case.conditions,
        native_head=NATIVE,client_sha256=CLIENT,history=[],output=case.root/'mixed-target.json')
    mixed=target.initialize_progress(target=declaration,proofs=[],output=case.root/'mixed-progress.json')
    with pytest.raises(ValueError,match='homogeneous'):target.chunk_inputs(mixed,[1,2],'front')


@pytest.mark.parametrize('mutation',['bytes','mode','membership'])
def test_raw_fence_refuses_before_new_progress_claim(mutation,case,monkeypatch):
    watched=case.root/'original-raw';watched.mkdir();leaf=watched/'packets.csv';leaf.write_bytes(b'exact retained raw')
    original=target._sources
    def sources():
        values=original();target._close([target.reference(leaf)],[target.epoch._directory(watched)])
        return values
    monkeypatch.setattr(target,'_sources',sources)
    original_write=target._write
    def effect_boundary(*args,**kwargs):
        if mutation=='bytes':leaf.write_bytes(b'drift')
        elif mutation=='mode':leaf.chmod(leaf.stat().st_mode ^ 0o100)
        else:(watched/'extra').write_bytes(b'extra')
        return original_write(*args,**kwargs)
    monkeypatch.setattr(target,'_write',effect_boundary)
    with pytest.raises(ValueError):target.initialize_progress(target=case.target,proofs=[],output=case.root/'unborn.json')
    assert not (case.root/'unborn.json').exists()


def test_owner_borrows_caller_scope_and_fresh_actions_never_cache_old_bytes(case):
    facts=OperationFacts();facts.begin_action()
    with facts.scope():
        target.validate_target(case.target)
        assert target.current_context() is facts
    assert target.current_context() is None and target._OBSERVATIONS.get() is None
    Path(case.enrollment['path']).write_bytes(b'changed after previous action')
    with pytest.raises(ValueError):target.validate_target(case.target)


def test_actual8192_full_condition_is_declared_without_diagnostic_credit(tmp_path):
    path=Path(os.environ['QCSD_TAM_FIXED_HOST_FACTS']);declaration=json.loads(path.read_bytes())
    for r in declaration.values():target._open(r)
    run=json.loads(Path(declaration['run']['path']).read_bytes())
    config,_=setting('tamaraw')
    result=target.describe_condition(write(tmp_path/'prospective-config.json',config),declaration['run'],
        'tamaraw',tmp_path/'condition.json')
    value=target._document(result,target.CONDITION_TYPE)
    assert value['identity']['resolved_configuration']==run['resolved_configuration']
    assert value['scientific_credit'] is False
    malformed=deepcopy(run);malformed['resolved_configuration']['initial_max_stream_data']=4096
    with pytest.raises(ValueError):target.condition_identity(config,malformed,'tamaraw')


def test_public_cli_binds_exact_input_sha_and_returns_no_raw_resources(case,capsys):
    path=Path(__file__).parents[1]/'tools/rapid_fixed_condition_target.py'
    spec=importlib.util.spec_from_file_location('target_public_control',path)
    tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
    progress=target.initialize_progress(target=case.target,proofs=[],output=case.root/'progress.json')
    argv=['check','--progress',progress['path'],'--progress-sha256',progress['sha256']]
    assert tool.main(argv)==0
    output=json.loads(capsys.readouterr().out)
    assert output['result']['target_accepted_count']==0 and 'classes' in output['result']
    assert 'https://' not in json.dumps(output)
    argv[-1]='0'*64
    assert tool.main(argv)==1 and json.loads(capsys.readouterr().out)['status']=='refused'


def original_report_fixture(case,monkeypatch):
    """Only installation and original physics are synthetic, explicitly."""
    root=case.root/'measurement-source';root.mkdir()
    client=root/'client';client.write_bytes(b'controlled client')
    # Give the controlled installation boundary a real, closed paired release.
    # Its Native Gitlink retains the same exact original c24 identity as the
    # fixture target; no candidate checkout or retained receipt is mutated.
    native=root/'neqo-qcsd'
    source_native=Path(target.__file__).resolve().parents[2]/'neqo-qcsd'
    subprocess.run(['git','clone','--quiet','--no-hardlinks',str(source_native),str(native)],check=True)
    subprocess.run(['git','-C',str(native),'checkout','--quiet','--detach',NATIVE],check=True)
    (root/'src').mkdir();(root/'tools').mkdir()
    subprocess.run(['git','init','--quiet',str(root)],check=True)
    subprocess.run(['git','-C',str(root),'add','client'],check=True)
    subprocess.run(['git','-C',str(root),'update-index','--add','--cacheinfo',
        f'160000,{NATIVE},neqo-qcsd'],check=True)
    subprocess.run(['git','-C',str(root),'-c','user.name=fixture','-c','user.email=fixture@example.test',
        '-c','commit.gpgsign=false','commit','--quiet','-m','controlled paired release'],check=True)
    lab_head=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD']).decode().strip()
    release=target.dynamic.release_snapshot(root,lab_head,NATIVE)
    source_ref=write(case.root/'installed-source-binding.json',{'controlled':'actual installed runtime boundary'})
    source={**release,
        'binding':{'release':release,'runtime_identity':{'source':{'lab_commit':lab_head,'neqo_commit':NATIVE,'neqo_pinned_commit':NATIVE},
            'collection_image_digest':'sha256:'+'a'*64,'client_sha256':CLIENT},
            'read_dependencies':[],'directory_dependencies':[],'reader_sources':{},'runtime_operation':{},'canonical':source_ref}}
    result=case.root/'original-result';result.mkdir()
    config,run=setting('undefended');config['limits']=case.rows[0]['capture_limits']
    frozen=result/'inputs/workloads/whole-1.json';frozen.parent.mkdir(parents=True)
    frozen.write_bytes(Path(case.rows[0]['original_manifest']['path']).read_bytes())
    sample={'sample_id':'original-accepted','path':'samples/accepted','state':'accepted','eligible':True,
        'workload_id':'whole-1','visit':0,'defense':'undefended'}
    run_ref=write(result/'samples/accepted/neqo/run.json',run)
    experiment=write(result/'experiment.json',{'configuration':config,'samples':[sample]})
    evidence=case.root/'lane-evidence';evidence.mkdir()
    receipt=write(evidence/'complete-reference.json',{'original':'controlled physics closure'})
    intent=write(evidence/'intent.json',{'payload':{'started_at':time_before(1)}})
    slot={'candidate_id':'candidate-1','class_index':1,'workload_id':'whole-1',
        'original_graph_sha256':case.rows[0]['original_graph_sha256'],'mode':'undefended',
        'visit':0,'actual_local_visit':0,'sample_id':sample['sample_id']}
    closure=write(evidence/'closed-lane.json',{'payload':{'facts':{'result_root':str(result)}}})
    lane={'measurement_source':{**source['binding']['runtime_identity']['source'],'image_digest':'sha256:'+'a'*64},
        'spec':{'collection_image_digest':'sha256:'+'a'*64,'module_root':str(root),'client_binary':str(client)},
        'facts':{'result_root':str(result)},'receipt':receipt,'samples':[slot],'configuration':config,
        'mode':'undefended','closure':closure}
    dependencies=[experiment,intent,run_ref,target.reference(frozen)]
    report={'read_only':True,'membership':None,'lanes':[lane],'read_dependencies':dependencies,
        'directory_dependencies':[target.epoch._directory(result/'samples/accepted/neqo')]}
    monkeypatch.setattr(target.dynamic,'_source',lambda ref: {**deepcopy(source),'binding_reference':ref})
    return source_ref,source,closure,report,sample,frozen


def test_complete_audit_uses_original_program_and_cross_binds_installed_labels(case,monkeypatch):
    source_ref,source,closure,report,_,_=original_report_fixture(case,monkeypatch)
    commands=[]
    def original_proof(src,enrollment,closures,directory):
        assert enrollment is None and closures==[closure]
        directory.mkdir();request={'source_root':src['root'],'enrollment':None,'closures':closures}
        started={'command':[sys.executable,'-I','-B','-c',target.epoch._PROGRAM],
            'request':request,'started_at':time_before(1)}
        commands.append(started['command'])
        start=write(directory/'started.json',started)
        stdout=write(directory/'stdout.log',report);stderr=write(directory/'stderr.log',{})
        end=write(directory/'completed.json',{**started,'completed_at':datetime.now(timezone.utc).isoformat(),
            'returncode':0,'stdout':stdout,'stderr':stderr})
        return {'report':report,'started':start,'completed':end}
    monkeypatch.setattr(target.epoch,'_run_epoch',original_proof)
    audit=target.audit_complete(source_binding=source_ref,closures=[closure],audit_root=case.root/'original-deep-audit',
        output=case.root/'audit.json')
    value=target.validate_audit(audit)
    assert commands==[[sys.executable,'-I','-B','-c',target.epoch._PROGRAM]]
    assert value['rows'][0]['logical_visit']==0 and value['scientific_credit'] is False
    progress=target.initialize_progress(target=case.target,proofs=[audit],output=case.root/'progress.json')
    assert target.validate_progress(progress)['target_accepted_count']==1
    facts=OperationFacts();facts.begin_action()
    with facts.scope():
        target.validate_audit(audit)
        leaf=Path(value['rows'][0]['run']['path']);leaf.write_bytes(b'raw mutation after original proof')
        with pytest.raises(ValueError):facts.check()


@pytest.mark.parametrize('field',['measurement_source','collection_image_digest','client_binary'])
def test_complete_rows_refuse_unbound_actual_source_image_or_client(field,case,monkeypatch):
    _,source,_,report,_,_=original_report_fixture(case,monkeypatch)
    source['binding_reference']=target.reference(case.root/'installed-source-binding.json')
    if field=='measurement_source':report['lanes'][0][field]['lab_commit']='0'*40
    elif field=='collection_image_digest':report['lanes'][0]['spec'][field]='sha256:'+'0'*64
    else:
        client=case.root/'wrong-client';client.write_bytes(b'different client');report['lanes'][0]['spec'][field]=str(client)
    with pytest.raises(ValueError):target._run_rows(source,report)


def test_selected_proof_is_once_per_action_with_fresh_raw_closing(case,monkeypatch):
    original=proof(case,monkeypatch,'undefended',[0])
    calls=[]
    def original_audit(ref):
        calls.append(ref)
        return json.loads(target._open(ref).read_bytes())
    monkeypatch.setattr(target,'validate_audit',original_audit)
    facts=OperationFacts();facts.begin_action()
    with facts.scope():
        declaration=target.validate_target(case.target)
        first=target._select(declaration,[original],initial=True)
        assert target._select(declaration,[original],initial=True)==first
        assert calls==[original]
        Path(original['path']).write_bytes(b'changed original proof')
        with pytest.raises(ValueError):facts.check()


def test_original_interpreter_command_must_resolve_to_exact_bound_binary(case,monkeypatch):
    source_ref,_,closure,report,_,_=original_report_fixture(case,monkeypatch)
    directory=case.root/'original-command-proof';directory.mkdir()
    start={'command':[sys.executable,'-I','-B','-c',target.epoch._PROGRAM],
        'request':{'source_root':str(case.root/'measurement-source'),'enrollment':None,'closures':[closure]},
        'started_at':time_before(1)}
    stdout=write(directory/'stdout.log',report);stderr=write(directory/'stderr.log',{})
    end={**start,'completed_at':datetime.now(timezone.utc).isoformat(),'returncode':0,'stdout':stdout,'stderr':stderr}
    operation={'started':write(directory/'started.json',start),'completed':write(directory/'completed.json',end),
        'interpreter':{'command':sys.executable,'binary':target.reference(Path(sys.executable).resolve())}}
    assert target._complete_operation(source_ref,operation)[1]==report
    other=case.root/'another-executable';other.write_bytes(b'different executable');other.chmod(0o755)
    altered=deepcopy(operation);altered['interpreter']['command']=str(other)
    start['command'][0]=str(other);end['command'][0]=str(other)
    altered['started']=write(directory/'started-other.json',start)
    altered['completed']=write(directory/'completed-other.json',end)
    with pytest.raises(ValueError,match='bound binary'):
        target._complete_operation(source_ref,altered)


def partial_fixture(case,monkeypatch):
    source_ref,source,closure,complete,sample,frozen=original_report_fixture(case,monkeypatch)
    report={'experiment':json.loads((case.root/'original-result/experiment.json').read_bytes()),
        'result_root':str(case.root/'original-result'),'read_dependencies':complete['read_dependencies'],
        'directory_dependencies':complete['directory_dependencies']}
    report['experiment']['configuration']['workloads']=[{'id':'whole-1','path':'inputs/workloads/whole-1.json'}]
    facts={'registered_layout':target.dynamic.FOUR_LAYOUT,'slot_start':0,'slot_count':4,'accepted_count':1,
        'aggregate_status':'incomplete','lane_pass_claim':False,'aggregate_formal_credit':0,
        'accepted_samples':[{'candidate_id':'candidate-1','workload_id':'whole-1','sample_id':sample['sample_id'],
            'logical_visit':0,'actual_local_visit':0,'mode':'undefended','workload_sha256':target.reference(frozen)['sha256']}],
        'configuration':report['experiment']['configuration'],'intent':{'started_at':time_before(20)},
        'measurement_source':complete['lanes'][0]['measurement_source']}
    records={};operations=[]
    for index in (1,2):
        directory=case.root/f'original-partial-deep-{index}';directory.mkdir()
        started=write(directory/'started.json',{'started_at':time_before(10 if index==1 else 3)})
        completed=write(directory/'completed.json',{'completed_at':time_before(8 if index==1 else 1)})
        operation={'started.json':started,'completed.json':completed}
        records[started['path']]=(report,json.loads(Path(completed['path']).read_bytes()));operations.append(operation)
    monkeypatch.setattr(target.dynamic,'_recorded_operation',lambda src,inputs,operation:deepcopy(records[operation['started.json']['path']]))
    monkeypatch.setattr(target.dynamic,'partial_subset',lambda observed:deepcopy(facts))
    first=target.dynamic._input_closure(source,source_ref,report,operations[0])
    second=target.dynamic._input_closure(source,source_ref,report,operations[1])
    kind,contract=target.dynamic._kind(facts['registered_layout'])
    receipt=artifact(case.root/'original-partial.json',kind,{'contract':contract,'inputs':{'source_binding':source_ref},
        'deep_operation':operations[0],'reader_sources':target.dynamic._reader_sources(),**first,**facts,
        'published_at':time_before(6)})
    verification={key:facts[key] for key in ('accepted_count','registered_layout','slot_start','slot_count',
        'aggregate_status','lane_pass_claim','aggregate_formal_credit')}
    verification.update(fresh_deep_operation=operations[1],**second)
    monkeypatch.setattr(target.dynamic,'verify',lambda ref,*,audit_root:deepcopy(verification))
    return receipt,verification


def test_partial_audit_keeps_both_original_proofs_and_incomplete_labels(case,monkeypatch):
    receipt,verification=partial_fixture(case,monkeypatch)
    audit=target.audit_partial(receipt=receipt,audit_root=case.root/'separate-verification',output=case.root/'audit.json')
    value=target.validate_audit(audit)
    assert value['operation']['receipt']==receipt and value['operation']['verification']==verification
    assert value['rows'][0]['aggregate_status']=='incomplete' and value['rows'][0]['aggregate_formal_credit']==0
    progress=target.initialize_progress(target=case.target,proofs=[audit],output=case.root/'progress.json')
    assert target.validate_progress(progress)['target_accepted_count']==1


@pytest.mark.parametrize('change',['same-proof','chronology','false-pass','count','layout'])
def test_partial_intake_refuses_missing_independence_or_aggregate_promotion(change,case,monkeypatch):
    receipt,verification=partial_fixture(case,monkeypatch)
    if change=='same-proof':verification['fresh_deep_operation']=target.dynamic._document(receipt,target.dynamic.FOUR_TYPE)['deep_operation']
    elif change=='chronology':
        start=verification['fresh_deep_operation']['started.json']
        verification['fresh_deep_operation']['started.json']=write(Path(start['path']),{'started_at':time_before(100)})
    elif change=='false-pass':verification['lane_pass_claim']=True
    elif change=='count':verification['accepted_count']=2
    else:verification['registered_layout']='parallel-worker-unregistered'
    with pytest.raises(ValueError):target._partial_operation({'receipt':receipt,'verification':verification})
