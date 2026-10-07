"""HOST controls; synthetic installed/deep boundaries grant no trace credit."""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap

import pytest

from qcsd_lab import rapid_chunk_partial_lane as reader
from qcsd_lab import rapid_partial_lane as original
from qcsd_lab import rapid_slot_chunks as chunks
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_partial_lane import formal_report, original_fixture


def report(count=4, start=12, generation=1, mode='tamaraw'):
    r = formal_report()
    lane = chunks.ChunkLane('formal', 4, 3, mode, '', tuple(r['lane']['workload_ids']), count,
        None if mode == 'undefended' else 'synthetic-full-five', start, 'b' * 64, generation)
    lane = replace(lane, campaign_name=chunks.name(lane, generation))
    r['lane'] = asdict(lane)
    e = r['experiment']; e['name'] = lane.campaign_name
    e['configuration']['defenses'][0]['name'] = mode
    e['configuration']['chaff_qualification_set'] = lane.qualification_set
    for row in e['configuration']['workloads']: row['visits'] = count
    templates = {s['workload_id']: s for s in e['samples'] if s['visit'] == 0}
    e['samples'] = []
    for workload in lane.workload_ids:
        for visit in range(count):
            sample = deepcopy(templates[workload]); sid = workload + '-' + str(visit)
            sample.update(visit=visit, sample_id=sid, defense=mode, path='samples/' + sid)
            sample['artifacts'] = {'samples/' + sid + '/run.json': 'd' * 64} if sample['state'] == 'accepted' else {}
            e['samples'].append(sample)
    e['summary'].update(planned=5 * count, accepted=count, failed=count)
    r['accepted_samples'] = {s['sample_id']: s['artifacts'] for s in e['samples'] if s['state'] == 'accepted'}
    r['chunk_bindings'] = {'plan': {'path': '/controlled/plan', 'sha256': 'c' * 64, 'mode': 420},
                           'policy': {'path': '/controlled/policy', 'sha256': lane.slot_policy_sha256, 'mode': 420}}
    return r


@pytest.mark.parametrize('count,start,generation,mode', [(1, 0, 1, 'undefended'), (16, 48, 1, 'tamaraw'), (5, 12, 2, 'tamaraw')])
def test_genuine_chunk_join_keeps_offsets_retry_identity_and_every_unaccepted_slot(count, start, generation, mode):
    r = report(count, start, generation, mode); before = deepcopy(r)
    facts = reader.accepted_subset(r)
    assert r == before and facts['registered_layout'] == reader.LAYOUT
    assert [s['logical_visit'] for s in facts['accepted_samples']] == list(range(start, start + count))
    assert facts['accepted_count'] == count and len(facts['remaining_samples']) == 4 * count
    assert facts['configuration'] == r['experiment']['configuration']
    assert facts['lane']['generation'] == generation and facts['slot_count'] == count
    assert facts['chunk_plan'] == r['chunk_bindings']['plan'] and facts['slot_policy'] == r['chunk_bindings']['policy']
    assert facts['aggregate_formal_credit'] == 0 and facts['lane_pass_claim'] is False


@pytest.mark.parametrize('case', ['old-four', 'offset', 'count', 'recovery-name', 'missing-slot', 'duplicate-slot',
    'running-slot', 'changed-graph', 'changed-group', 'wrong-source', 'ineligible', 'promoted-failure', 'parallel'])
def test_closed_chunk_and_original_accepted_join_refuse_changes(case):
    r = report(); e = r['experiment']
    if case == 'old-four': r['lane'] = formal_report()['lane']
    elif case == 'offset': r['lane']['slot_start'] = 63
    elif case == 'count': r['lane']['visits_per_workload'] = 17
    elif case == 'recovery-name': r['lane']['generation'] = 2
    elif case == 'missing-slot': e['samples'].pop()
    elif case == 'duplicate-slot': e['samples'][1]['visit'] = 0
    elif case == 'running-slot': e['samples'][-1]['state'] = 'running'
    elif case == 'changed-graph': e['configuration']['workloads'][0]['sha256'] = 'e' * 64
    elif case == 'changed-group': e['configuration']['chaff_qualification_set_manifest_sha256'] = 'e' * 64
    elif case == 'wrong-source': e['source']['lab_commit'] = 'e' * 40
    elif case == 'ineligible': e['samples'][0]['eligible'] = False
    elif case == 'promoted-failure': e['samples'][4]['artifacts'] = {'fake': 'e' * 64}
    else: r['intent']['actuator'] = 'parallel-formal-worker'
    with pytest.raises(ValueError): reader.accepted_subset(r)


def chunk_original(tmp_path, *, effect=None):
    """Real isolated program with explicitly controlled original deep/actuation authority."""
    r = report(5, 12, 2)
    source, inputs = original_fixture(tmp_path, r, effect=effect)
    root = Path(source['root']); package = root / 'src/qcsd_lab'
    old_result = Path(inputs['result']['path']); namespace = old_result.parent
    moved = namespace.parent / r['lane']['campaign_name']; namespace.rename(moved)
    result = moved / old_result.name
    inputs['result'] = {'path': str(result), 'seal': reader.reference(result / 'evidence.sha256')}
    r['result_root'], r['result_seal'] = str(result), inputs['result']['seal']
    metadata = {'lab_commit': 'a' * 40, 'neqo_commit': 'b' * 40, 'neqo_pinned_commit': 'b' * 40,
        'lab_dirty': False, 'neqo_dirty': False, 'lab_patch_sha256': hashlib.sha256(b'').hexdigest(),
        'neqo_patch_sha256': hashlib.sha256(b'').hexdigest()}
    image = r['spec']['collection_image_digest']
    runtime = {'module_root': str(root), 'runtime_source_root': str(root), 'collection_image_digest': image}
    for name in ('source_manifest', 'client_binary', 'base_launcher', 'host_launcher'):
        p = tmp_path / name
        p.write_bytes(reader.encoded(metadata) if name == 'source_manifest' else b'controlled runtime\n')
        p.chmod(0o755 if name != 'source_manifest' else 0o644); runtime[name] = str(p)
    policy = tmp_path / 'chunk-policy.json'
    policy.write_bytes(admission._json(admission._bind(chunks.POLICY_TYPE, {'controlled': True})))
    r['lane']['slot_policy_sha256'] = reader.reference(policy)['sha256']
    lane = chunks.checked_lane({**r['lane'], 'campaign_name': chunks.name(chunks.ChunkLane(**r['lane']), 2)})
    r['lane'] = asdict(lane)
    renamed = result.parent.parent / lane.campaign_name; result.parent.rename(renamed); result = renamed / result.name
    inputs['result'] = {'path': str(result), 'seal': reader.reference(result / 'evidence.sha256')}
    r['result_root'], r['result_seal'] = str(result), inputs['result']['seal']; r['experiment']['name'] = lane.campaign_name
    payload = {'lane_layout': chunks.LAYOUT, 'slot_chunk_policy': {k: reader.reference(policy)[k] for k in ('path', 'sha256')}}
    plan = tmp_path / 'chunk-plan.json'; plan.write_bytes(admission._json(admission._bind(chunks.PLAN_TYPE, payload)))
    r['spec'].update(runtime, plan_receipt=str(plan))
    r['experiment']['source'] = {**metadata, 'image_digest': image}
    r['intent']['runtime_identity'] = {'runtime_source': metadata, 'collection_image_digest': image,
                                     'client_sha256': reader.reference(runtime['client_binary'])['sha256']}
    r['lineage']['image_check'] = {'proof': {'plan_payload': payload}}
    (package / 'report.json').write_text(json.dumps(r))
    p = package / 'rapid_lane_evidence.py'; raw = p.read_text()
    raw = raw.replace('qualification_set:str;generation:int', 'qualification_set:str;generation:int;slot_start:int;slot_policy_sha256:str;lane_layout:str')
    raw = raw.replace("_read(path);return R['intent']", "_read(path);_read(Path(R['spec']['plan_receipt']));_read(Path(R['lineage']['image_check']['proof']['plan_payload']['slot_chunk_policy']['path']));return R['intent']")
    raw = raw.replace("def load_capture_spec(p): _read(p);return Spec()", "def load_capture_spec(p):\n    _read(p)\n    for k in ('source_manifest','client_binary','base_launcher','host_launcher'): _read(Path(R['spec'][k]))\n    return Spec()")
    p.write_text(raw)
    source['files'] = {}
    source['binding'] = {'read_dependencies': [], 'directory_dependencies': [], 'reader_sources': {}, 'runtime_operation': {}, 'canonical': reader.reference(tmp_path/'spec.json'), 'runtime': runtime, 'runtime_identity': {'source': metadata, 'collection_image_digest': image,
                         'client_sha256': reader.reference(runtime['client_binary'])['sha256']}}
    return source, inputs


def test_public_declare_and_independent_verify_keep_original_deep_program_and_audits(tmp_path, monkeypatch):
    source, inputs = chunk_original(tmp_path)
    # Runtime installation is a controlled boundary here; its real isolated reader is tested below.
    monkeypatch.setattr(reader, '_source', lambda ref: source)
    binding=tmp_path/'controlled-source-binding.json'; binding.write_text('{}')
    inputs['source_binding']=reader.reference(binding)
    target = tmp_path / 'partial.json'
    receipt = reader.declare(**{k: inputs[k]['path'] if k in {'spec', 'intent'} else inputs[k] for k in ('source_binding', 'spec', 'evidence_root', 'intent')},
        result=inputs['result']['path'], audit_root=tmp_path / 'declare-audit', output=target)
    verified = reader.verify(receipt, audit_root=tmp_path / 'verify-audit')
    payload = reader._document(receipt, reader.TYPE)
    assert payload['accepted_count'] == 5 and verified['accepted_count'] == 5
    assert payload['deep_operation'] != verified['fresh_deep_operation']
    command = json.loads(Path(payload['deep_operation']['started.json']['path']).read_bytes())['command']
    assert command[-1] == original._PROGRAM == reader._PROGRAM
    assert payload['slot_start'] == 12 and payload['slot_count'] == 5
    assert not verified['lane_pass_claim'] and verified['aggregate_formal_credit'] == 0
    assert Path(inputs['result']['path'], 'evidence.sha256').read_text() == 'synthetic seal\n'


@pytest.mark.parametrize('case', ['source', 'plan', 'policy', 'copy-mode', 'bytes', 'membership'])
def test_measurement_join_and_original_fences_refuse_changed_current_authority(tmp_path, case):
    source, inputs = chunk_original(tmp_path)
    report, _ = original._run_original(source, inputs, tmp_path / 'audit')
    if case == 'source': report['experiment']['source']['neqo_commit'] = 'c' * 40
    elif case == 'plan': report['lineage']['image_check']['proof']['plan_payload']['extra'] = True
    elif case == 'policy': report['lane']['slot_policy_sha256'] = 'c' * 64
    elif case == 'copy-mode': Path(report['spec']['host_launcher']).chmod(0o700)
    elif case == 'bytes': Path(inputs['intent']['path']).write_text('changed')
    else: (Path(inputs['result']['path']).parent / 'unexpected').mkdir()
    with pytest.raises(ValueError):
        joined = reader._measurement_binding(report, source)
        reader._close_dependencies(joined)


@pytest.mark.parametrize('effect', ['write', 'network', 'docker'])
def test_original_child_still_refuses_effects_without_touching_result(tmp_path, effect):
    source, inputs = chunk_original(tmp_path, effect=effect)
    with pytest.raises(ValueError, match='raw audit'):
        reader._run_original(source, inputs, tmp_path / 'audit')
    assert not Path(inputs['result']['path'], 'forbidden.txt').exists()


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).stdout.decode().strip()


def installed_fixture(tmp_path):
    """Actual paired Git/audit processes; installed twelve-op validator is explicitly synthetic."""
    root = tmp_path / 'release'; package = root / 'src/qcsd_lab'; package.mkdir(parents=True)
    native = root / 'neqo-qcsd'; native.mkdir()
    (native / 'Cargo.lock').write_text('controlled Native dependency\n')
    git(native, 'init'); git(native, 'add', 'Cargo.lock'); git(native, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'native fixture')
    native_head = git(native, 'rev-parse', 'HEAD')
    for name in ('__init__', 'rapid_lane_evidence', 'verification', 'rapid_operation_facts'):
        (package / (name + '.py')).write_text('')
    (package / 'rapid_operation_facts.py').write_text('class OperationFacts: pass\n')
    (package / 'rapid_rolling_schedule.py').write_text(textwrap.dedent('''\
        import json
        from pathlib import Path
        def reopen_runtime(ref, runtime, _inspector):
            # Controlled installed-provenance body. Production invokes the release's full validator.
            canonical=json.loads(Path(ref['path']).read_bytes())
            Path(canonical['dependency']).read_bytes()
            sources={name:(Path(runtime['runtime_source_root'])/name).read_bytes() for name in canonical['fixture_files']}
            return canonical,sources
        '''))
    (root / 'qcsd-lab').write_text('#!/bin/sh\nexit 0\n'); (root / 'qcsd-lab').chmod(0o755)
    git(root, 'init'); git(root, 'add', 'src', 'qcsd-lab')
    git(root, 'update-index', '--add', '--cacheinfo', '160000,' + native_head + ',neqo-qcsd')
    git(root, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'paired release fixture')
    lab_head = git(root, 'rev-parse', 'HEAD'); release = reader.release_snapshot(root, lab_head, native_head)
    installed = tmp_path / 'runtime'; installed.mkdir()
    source = installed / 'source'
    for name, ref in release['files'].items():
        p = source / name; p.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(ref['path'], p); p.chmod(ref['mode'])
    empty = hashlib.sha256(b'').hexdigest()
    metadata = {'lab_commit': lab_head, 'neqo_commit': native_head, 'neqo_pinned_commit': native_head,
                'lab_dirty': False, 'neqo_dirty': False, 'lab_patch_sha256': empty, 'neqo_patch_sha256': empty}
    (installed / 'source.json').write_bytes(reader.encoded(metadata))
    (installed / 'client').write_bytes(b'controlled client'); (installed / 'client').chmod(0o755)
    (installed / 'dependency.json').write_bytes(b'controlled installed operation raw proof')
    runtime = {'runtime_source_root': str(source), 'module_root': str(source), 'base_launcher': str(source / 'qcsd-lab'),
        'host_launcher': str(source / 'qcsd-lab'), 'source_manifest': str(installed / 'source.json'),
        'client_binary': str(installed / 'client'), 'collection_image_digest': 'sha256:' + 'd' * 64}
    canonical = {'source': metadata, 'collection_image_digest': runtime['collection_image_digest'],
        'installed_client_sha256': reader.reference(installed / 'client')['sha256'],
        'fixture_files': list(release['files']), 'dependency': str(installed / 'dependency.json')}
    (installed / 'canonical.json').write_bytes(reader.encoded(canonical))
    return root, reader.reference(installed / 'canonical.json'), runtime


def test_dynamic_binding_uses_actual_git_heads_and_recorded_isolated_runtime_not_literal_allowlist(tmp_path, monkeypatch):
    root, canonical, runtime = installed_fixture(tmp_path)
    # Controlled trusted runtime consumer; the actual current consumer is tested as a refusal below.
    monkeypatch.setattr(reader, '_consumer_root', lambda: root)
    authenticated_readers = reader._reader_sources()
    original_compatible = reader._compatible_reader_sources
    def controlled_compatible(observed):
        if observed != authenticated_readers:
            raise ValueError('controlled reader set changed')
        original_compatible(observed)
        return str(root)
    # The synthetic installed release is the recorded consumer root in this
    # fixture; retain the real reader-byte check before mapping that root.
    monkeypatch.setattr(reader, '_compatible_reader_sources', controlled_compatible)
    binding = reader.bind_source(root=root, canonical=canonical, runtime=runtime, audit_root=tmp_path / 'runtime-audit', output=tmp_path / 'binding.json')
    source = reader._source(binding)
    assert source['lab_head'] not in original.ORIGINAL_RELEASES
    assert source['binding']['canonical'] == canonical
    assert source['binding']['runtime_identity']['client_sha256'] == reader.reference(runtime['client_binary'])['sha256']
    assert reader._PROGRAM == original._PROGRAM


@pytest.mark.parametrize('case', ['source-bytes', 'source-mode', 'source-membership', 'runtime-raw', 'runtime-mode', 'image', 'raw-status'])
def test_dynamic_binding_closes_git_runtime_operation_and_mode_membership(tmp_path, monkeypatch, case):
    root, canonical, runtime = installed_fixture(tmp_path)
    monkeypatch.setattr(reader, '_consumer_root', lambda: root)
    authenticated_readers = reader._reader_sources()
    original_compatible = reader._compatible_reader_sources
    def controlled_compatible(observed):
        if observed != authenticated_readers:
            raise ValueError('controlled reader set changed')
        original_compatible(observed)
        return str(root)
    monkeypatch.setattr(reader, '_compatible_reader_sources', controlled_compatible)
    binding = reader.bind_source(root=root, canonical=canonical, runtime=runtime, audit_root=tmp_path / 'runtime-audit', output=tmp_path / 'binding.json')
    payload = reader._document(binding, reader.SOURCE_TYPE)
    if case == 'source-bytes': (root / 'qcsd-lab').write_text('changed')
    elif case == 'source-mode': (root / 'qcsd-lab').chmod(0o700)
    elif case == 'source-membership': (root / 'src/unbound.py').write_text('')
    elif case == 'runtime-raw': (Path(canonical['path']).parent / 'dependency.json').write_text('changed')
    elif case == 'runtime-mode': (Path(canonical['path']).parent / 'dependency.json').chmod(0o600)
    else:
        name = 'stdout.log' if case == 'image' else 'completed.json'
        p = Path(payload['runtime_operation'][name]['path']); value = json.loads(p.read_bytes())
        if case == 'image': value['collection_image_digest'] = 'sha256:' + 'e' * 64
        else: value['returncode'] = 1
        p.write_bytes(reader.encoded(value)); payload['runtime_operation'][name] = reader.reference(p)
        if case == 'image':
            c = Path(payload['runtime_operation']['completed.json']['path']); v = json.loads(c.read_bytes())
            v['stdout_sha256'] = reader.reference(p)['sha256']; c.write_bytes(reader.encoded(v))
            payload['runtime_operation']['completed.json'] = reader.reference(c)
        binding = reader._write(tmp_path / 'changed-binding.json', reader.SOURCE_TYPE, payload)
    with pytest.raises(ValueError): reader._source(binding)


def test_candidate_release_cannot_use_its_fake_runtime_validator_to_register_itself(tmp_path):
    root, canonical, runtime = installed_fixture(tmp_path)
    assert reader._consumer_root() != root
    with pytest.raises(ValueError, match='runtime reopening refused'):
        reader.bind_source(root=root, canonical=canonical, runtime=runtime,
            audit_root=tmp_path/'runtime-audit', output=tmp_path/'binding.json')
    start=json.loads((tmp_path/'runtime-audit/started.json').read_bytes())
    assert start['request']['source_root'] == str(reader._consumer_root())
    assert not (tmp_path/'binding.json').exists()


def four_original(tmp_path, mode='undefended'):
    """Controlled serial four-visit proof, genuinely typed independently of chunks."""
    from qcsd_lab import rapid_capture_plan as plan
    from qcsd_lab import rapid_lane_evidence as lanes
    source, inputs = chunk_original(tmp_path)
    package = Path(source['root'])/'src/qcsd_lab'
    r=json.loads((package/'report.json').read_bytes())
    lane=plan.Lane('formal',2,3,mode,plan._campaign_name('formal',2,3,mode,2,6),
        tuple(r['lane']['workload_ids']),4,None if mode=='undefended' else 'synthetic-full-five',2,6)
    r['lane']=asdict(lane);e=r['experiment'];e['name']=lane.campaign_name
    e['configuration']['defenses'][0]['name']=mode
    e['configuration']['chaff_qualification_set']=lane.qualification_set
    if lane.qualification_set is None:e['configuration']['chaff_qualification_set_manifest_sha256']=None
    for row in e['configuration']['workloads']:row['visits']=4
    e['samples']=[s for s in e['samples'] if s['visit']<4]
    for sample in e['samples']:sample['defense']=mode
    e['summary'].update(planned=20,accepted=4,failed=4)
    r['accepted_samples']={s['sample_id']:s['artifacts'] for s in e['samples'] if s['state']=='accepted'}
    old=Path(inputs['result']['path']);parent=old.parent.parent/lane.campaign_name;old.parent.rename(parent)
    result=parent/old.name;inputs['result']={'path':str(result),'seal':reader.reference(result/'evidence.sha256')}
    r['result_root'],r['result_seal']=str(result),inputs['result']['seal']
    payload={'lanes':[{**asdict(lane),'campaign_sha256':e['configuration']['campaign_sha256']}]}
    Path(r['spec']['plan_receipt']).write_bytes(admission._json(admission._bind(lanes.PLAN_TYPE,payload)))
    r['lineage']['image_check']['proof']['plan_payload']=payload
    (package/'report.json').write_text(json.dumps(r))
    p=package/'rapid_lane_evidence.py';s=p.read_text()
    s=s.replace(';slot_start:int;slot_policy_sha256:str;lane_layout:str','')
    s=s.replace("_read(Path(R['lineage']['image_check']['proof']['plan_payload']['slot_chunk_policy']['path']));",'')
    p.write_text(s)
    return source,inputs


@pytest.mark.parametrize('mode',['undefended','tamaraw'])
def test_dynamic_four_visit_public_receipt_preserves_exact_original_acceptance_and_offset(tmp_path,monkeypatch,mode):
    source,inputs=four_original(tmp_path,mode)
    monkeypatch.setattr(reader,'_source',lambda ref:source)
    b=tmp_path/'source-binding.json';b.write_text('{}');binding=reader.reference(b)
    receipt=reader.declare(source_binding=binding,spec=inputs['spec']['path'],evidence_root=inputs['evidence_root'],
        intent=inputs['intent']['path'],result=inputs['result']['path'],audit_root=tmp_path/'declare',output=tmp_path/'four.json')
    value=reader._document(receipt,reader.FOUR_TYPE)
    verified=reader.verify(receipt,audit_root=tmp_path/'verify')
    recorded,_=original._recorded_operation(source,value['inputs'],value['deep_operation'])
    exact=original.accepted_subset(recorded)
    assert all(value[k]==v for k,v in exact.items())
    assert value['registered_layout']==reader.FOUR_LAYOUT!=reader.LAYOUT
    assert 'slot_policy' not in value and 'chunk_plan' not in value
    assert value['slot_start']==4 and value['slot_count']==4
    assert [row['logical_visit'] for row in value['accepted_samples']]==[4,5,6,7]
    assert verified['registered_layout']==reader.FOUR_LAYOUT and verified['accepted_count']==4
    assert value['deep_operation']!=verified['fresh_deep_operation']
    assert value['lane']['generation']==2 and value['lane_pass_claim'] is False


@pytest.mark.parametrize('case',['five-visits','block17','wrong-name','false-qualification','chunk-label','missing-plan-row','wrong-plan-row'])
def test_dynamic_four_refuses_coercion_or_unbound_legacy_plan_identity(tmp_path,case):
    source,inputs=four_original(tmp_path)
    r,_=original._run_original(source,inputs,tmp_path/'audit')
    if case=='five-visits':r['lane']['visits_per_workload']=5
    elif case=='block17':r['lane']['block']=17
    elif case=='wrong-name':r['lane']['campaign_name']='synthetic-unregistered'
    elif case=='false-qualification':r['lane']['qualification_set']='invented-padding-group'
    elif case=='chunk-label':r['lane']['lane_layout']=chunks.LAYOUT
    else:
        payload=r['lineage']['image_check']['proof']['plan_payload']
        if case=='missing-plan-row':payload['lanes']=[]
        else:payload['lanes'][0]['workload_ids'].pop()
        Path(r['spec']['plan_receipt']).write_bytes(admission._json(admission._bind(__import__('qcsd_lab.rapid_lane_evidence',fromlist=['PLAN_TYPE']).PLAN_TYPE,payload)))
        # The bytes are altered as well; an original proof/dependency close must refuse.
    with pytest.raises(ValueError):
        joined=reader._measurement_binding(r,source)
        reader.partial_subset(joined);reader._close_dependencies(joined)


def test_four_receipt_cannot_claim_chunk_type_before_independent_verifier(tmp_path,monkeypatch):
    source,inputs=four_original(tmp_path)
    monkeypatch.setattr(reader,'_source',lambda ref:source)
    b=tmp_path/'source-binding.json';b.write_text('{}')
    receipt=reader.declare(source_binding=reader.reference(b),spec=inputs['spec']['path'],evidence_root=inputs['evidence_root'],
        intent=inputs['intent']['path'],result=inputs['result']['path'],audit_root=tmp_path/'declare',output=tmp_path/'four.json')
    value=reader._document(receipt,reader.FOUR_TYPE)
    wrong=reader._write(tmp_path/'wrong-kind.json',reader.TYPE,value)
    with pytest.raises(ValueError):reader.verify(wrong,audit_root=tmp_path/'must-not-exist')
    assert not (tmp_path/'must-not-exist').exists()
