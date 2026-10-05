"""HOST controls with explicit controlled installed/deep primitive boundaries.

Real tiny paired Git releases, original operation records and closing fences
are exercised. The genuine ordinary20 case reads sealed metadata only; it does
not replay the original physical/deep proof or award scientific credit.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_target_overlay_source as overlay
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab.rapid_operation_facts import OperationFacts


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(target._json(value))
    return target.reference(path)


def full(ref):
    return {**ref, 'size': Path(ref['path']).stat().st_size}


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)


def release(root, native=None, text='unchanged module'):
    root.mkdir()
    if native is None:
        native = root / 'neqo-qcsd'; native.mkdir()
        git(native, 'init', '-q'); (native / 'native.rs').write_text('unchanged Native\n')
        git(native, 'add', '.'); git(native, '-c', 'user.name=HOST fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Native fixture')
    else:
        subprocess.run(['git', 'clone', '--no-local', str(native), str(root / 'neqo-qcsd')],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        native = root / 'neqo-qcsd'
    (root / 'src/qcsd_lab').mkdir(parents=True); (root / 'tools').mkdir()
    (root / 'src/qcsd_lab/__init__.py').write_text('raise RuntimeError("measurement release must not authorize installation")\n')
    (root / 'src/qcsd_lab/reader.py').write_text('# '+text+'\n')
    (root / 'tools/reader.py').write_text('# controlled public tool\n')
    (root / 'qcsd-lab').write_text('#!/bin/sh\nexit 0\n'); (root / 'qcsd-lab').chmod(0o755)
    git(root, 'init', '-q'); git(root, 'add', 'src', 'tools', 'qcsd-lab', 'neqo-qcsd')
    git(root, '-c', 'user.name=HOST fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Lab fixture')
    return overlay.dynamic.release_snapshot(root, git(root, 'rev-parse', 'HEAD').decode().strip(),
        git(native, 'rev-parse', 'HEAD').decode().strip())


@pytest.fixture
def case(tmp_path, monkeypatch):
    runtime_release = release(tmp_path / 'runtime')
    module_release = release(tmp_path / 'module', Path(runtime_release['root']) / 'neqo-qcsd', 'reviewed overlay')
    inputs = tmp_path / 'original-runtime'; inputs.mkdir()
    client = inputs / 'client'; client.write_bytes(b'controlled immutable client'); client.chmod(0o755)
    manifest = write(inputs / 'source.json', {'lab_commit': runtime_release['lab_head']})
    canonical = write(inputs / 'canonical.json', {'controlled_installed_primitive': True})
    runtime_binding = write(inputs / 'runtime-binding.json', {'controlled_trusted_runtime_binding': True})
    runtime = {'runtime_source_root':runtime_release['root'], 'module_root':runtime_release['root'],
        'base_launcher':str(Path(runtime_release['root'])/'qcsd-lab'),
        'host_launcher':str(Path(runtime_release['root'])/'qcsd-lab'),
        'source_manifest':manifest['path'], 'client_binary':str(client),
        'collection_image_digest':'sha256:'+'a'*64}
    identity = {'source':{'lab_commit':runtime_release['lab_head'], 'neqo_commit':runtime_release['native_head'],
        'neqo_pinned_commit':runtime_release['native_head'], 'lab_dirty':False, 'neqo_dirty':False},
        'collection_image_digest':runtime['collection_image_digest'], 'client_sha256':target.reference(client)['sha256']}
    bound = {**runtime_release, 'binding':{'runtime':runtime, 'runtime_identity':identity,
        'canonical':canonical, 'read_dependencies':[*runtime_release['files'].values(), canonical, manifest, target.reference(client)],
        'directory_dependencies':[], 'reader_sources':{}, 'runtime_operation':{},
        'published_at':(datetime.now(timezone.utc)-timedelta(seconds=2)).isoformat()}}
    calls=[]
    def trusted_runtime(reference):
        assert reference == runtime_binding
        target._open(reference); calls.append(reference)
        return deepcopy(bound)
    # Installation is an explicitly controlled independent primitive, never a
    # callback imported from the proposed measurement release.
    monkeypatch.setattr(overlay.dynamic, '_source', trusted_runtime)
    author = tmp_path / 'reviewed-author'
    inventory = write(tmp_path / 'publication/inventory.json', {'source_root':str(author),
        'files':{name:{'path':str(author/name), 'sha256':ref['sha256'], 'mode':ref['mode'],
                      'size':Path(ref['path']).stat().st_size} for name,ref in module_release['files'].items()}})
    closure = write(tmp_path / 'publication/closure.json', {'source_root':str(author),
        'native_head':module_release['native_head'], 'native_unchanged':True,
        'source_before_after_unchanged':True, 'source_file_count':len(module_release['files']),
        'source_inventory':full(inventory)})
    review = write(tmp_path / 'publication/review.json', {'source_root':str(author),
        'outcome':'no-concrete-blocker', 'closure':full(closure)})
    publication = write(tmp_path / 'publication/actual.json', {
        'actual_measured_runtime_source_unchanged':True, 'actual_runtime_rebuilt':False,
        'base_lab_commit':runtime_release['lab_head'], 'clean_reader_overlay':module_release['root'],
        'formal_credit_added':0, 'lab_commit':module_release['lab_head'], 'native_commit':module_release['native_head'],
        'published_branches':['main','desktop-portability-2026-09-26'],
        'review':{k:review[k] for k in ('path','sha256')}, 'source_closure':{k:closure[k] for k in ('path','sha256')}})
    return SimpleNamespace(root=tmp_path, module=module_release, runtime=bound, runtime_binding=runtime_binding,
        trusted_runtime=trusted_runtime,
        publication=publication, review=review, closure=closure, inventory=inventory, calls=calls)


def bind(case):
    return overlay.bind_source(module_root=case.module['root'], module_publication=case.publication,
        runtime_source_binding=case.runtime_binding, output=case.root/'overlay-registration.json')


def lane(case, source):
    runtime=case.runtime['binding']['runtime']; identity=case.runtime['binding']['runtime_identity']
    return {'spec':{**runtime, 'module_root':case.module['root']}, 'runtime_source_root':case.runtime['root'],
        'measurement_source':{**identity['source'],'image_digest':identity['collection_image_digest']},
        'overlay_source_hashes':source['overlay_registration']['module_overlay_hashes']}


def test_separate_registration_calls_trusted_consumer_without_importing_module(case):
    registration=bind(case); source=overlay._source(registration)
    assert source['lab_head'] != source['binding']['runtime_identity']['source']['lab_commit']
    assert source['overlay_registration']['module_installed_claim'] is False
    assert source['overlay_registration']['scientific_credit'] is False
    assert source['binding']['runtime']['module_root'] == case.runtime['root']
    overlay.validate_lane(source,lane(case,source))
    assert case.calls and all(ref==case.runtime_binding for ref in case.calls)
    assert target._measurement_source(registration)==source
    # Absent overlay tag still dispatches unchanged installed-equality reader.
    assert target._measurement_source(case.runtime_binding)==case.runtime


@pytest.mark.parametrize('change',['overlay-hash','module-root','runtime-root','image','client-mode','launcher-bytes'])
def test_original_lane_cannot_substitute_module_or_runtime_roles(change,case):
    source=overlay._source(bind(case)); record=lane(case,source)
    if change=='overlay-hash':record['overlay_source_hashes']={**record['overlay_source_hashes'],'src/qcsd_lab/reader.py':'0'*64}
    elif change=='module-root':record['spec']['module_root']=case.runtime['root']
    elif change=='runtime-root':record['runtime_source_root']=case.module['root']
    elif change=='image':record['spec']['collection_image_digest']='sha256:'+'0'*64
    elif change=='client-mode':
        copy=case.root/'other-client';copy.write_bytes(Path(record['spec']['client_binary']).read_bytes());copy.chmod(0o644)
        record['spec']['client_binary']=str(copy)
    else:
        copy=case.root/'other-launcher';copy.write_bytes(b'different launcher');copy.chmod(0o755)
        record['spec']['host_launcher']=str(copy)
    with pytest.raises(ValueError):overlay.validate_lane(source,record)


@pytest.mark.parametrize('change',['installed-claim','inventory-mode','native-head','unreviewed'])
def test_publication_requires_complete_reviewed_source_and_separate_runtime(change,case):
    value=json.loads(Path(case.publication['path']).read_bytes())
    if change=='installed-claim':value['actual_runtime_rebuilt']=True
    elif change=='native-head':value['native_commit']='0'*40
    elif change=='unreviewed':
        review=json.loads(Path(case.review['path']).read_bytes());review['outcome']='blocked'
        new=write(case.root/'publication/unreviewed.json',review);value['review']={k:new[k] for k in ('path','sha256')}
    else:
        inventory=json.loads(Path(case.inventory['path']).read_bytes());inventory['files']['src/qcsd_lab/reader.py']['mode']=0o755
        new=write(case.root/'publication/wrong-inventory.json',inventory)
        closure=json.loads(Path(case.closure['path']).read_bytes());closure['source_inventory']=full(new)
        new_closure=write(case.root/'publication/wrong-closure.json',closure)
        review=json.loads(Path(case.review['path']).read_bytes());review['closure']=full(new_closure)
        new_review=write(case.root/'publication/wrong-review.json',review)
        value['source_closure']={k:new_closure[k] for k in ('path','sha256')}
        value['review']={k:new_review[k] for k in ('path','sha256')}
    case.publication=write(case.root/'publication/altered.json',value)
    with pytest.raises(ValueError):bind(case)


@pytest.mark.parametrize('change',['source-bytes','source-mode','import-membership'])
def test_overlay_raw_source_fence_closes_before_effect(change,case):
    ref=bind(case); facts=OperationFacts();facts.begin_action()
    with facts.scope():
        overlay._source(ref)
        path=Path(case.module['root'])/'src/qcsd_lab/reader.py'
        if change=='source-bytes':path.write_bytes(b'mutated Source')
        elif change=='source-mode':path.chmod(0o755)
        else:(path.parent/'unbound.py').write_bytes(b'# new importable Source')
        with pytest.raises(ValueError):target._check_action()


def test_genuine_ordinary_twenty_metadata_has_separate_module_runtime_and_independent_proof():
    path=Path(os.environ['QCSD_TARGET_OVERLAY_ACTUAL_FACTS'])
    expected=os.environ['QCSD_TARGET_OVERLAY_ACTUAL_FACTS_SHA256']
    raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==expected
    facts=json.loads(raw)
    def document(ref):return json.loads(target._open(ref).read_bytes())
    publication=document(facts['module_publication'])
    release=overlay.dynamic.release_snapshot(facts['module_root'],publication['lab_commit'],publication['native_commit'])
    dependencies=overlay._publication(facts['module_publication'],release)
    assert len(dependencies)==4
    spec=document(facts['spec'])['inputs'];lineage=document(facts['lineage'])['payload']
    proof=lineage['image_check']['proof'];independent=document(facts['independent_closure'])['payload']
    batch=document(facts['independent_batch'])
    hashes={name:ref['sha256'] for name,ref in release['files'].items()
        if Path(name).parent.as_posix() in ('src/qcsd_lab','tools') and name.endswith('.py')}
    assert proof['overlay_source_hashes']==hashes and len(hashes)>100
    assert spec['module_root']==release['root'] and spec['runtime_source_root']!=release['root']
    assert proof['runtime_source']['lab_commit']!=release['lab_head']
    assert spec['collection_image_digest']==proof['runtime_source']['image_digest']
    assert independent['facts']['accepted']==20 and independent['facts']['host_returncode']==0
    assert facts['independent_closure']!=facts['automatic_closure']
    assert batch['revised_fixed_condition_target_intake_pending'] is True
    assert batch['independently_verified_trace_count']==20
    assert release['native_head']==proof['runtime_source']['neqo_commit']


from tests.test_rapid_fixed_condition_target import case as target_case


def test_public_overlay_complete_audit_and_target_join_use_original_program(case,target_case,monkeypatch):
    from tests.test_rapid_fixed_condition_target import original_report_fixture, time_before
    _,_,closure,report,_,_=original_report_fixture(target_case,monkeypatch)
    monkeypatch.setattr(overlay.dynamic,'_source',case.trusted_runtime)
    registration=bind(case);source=overlay._source(registration)
    record=report['lanes'][0];record.update(lane(case,source))
    declaration=target.publish_target(namespace='overlay-controlled-target',enrollment=target_case.enrollment,
        conditions=target_case.conditions,native_head=source['native_head'],
        client_sha256=source['binding']['runtime_identity']['client_sha256'],history=[target_case.history],
        output=case.root/'overlay-target.json')
    calls=[]
    def original_proof(src,enrollment,closures,directory):
        assert enrollment is None and closures==[closure] and src['root']==case.module['root']
        directory.mkdir();started={'command':[__import__('sys').executable,'-I','-B','-c',target.epoch._PROGRAM],
            'request':{'source_root':src['root'],'enrollment':None,'closures':closures},'started_at':time_before(1)}
        calls.append(started['command']);start=write(directory/'started.json',started)
        stdout=write(directory/'stdout.log',report);stderr=write(directory/'stderr.log',{})
        end=write(directory/'completed.json',{**started,'completed_at':datetime.now(timezone.utc).isoformat(),
            'returncode':0,'stdout':stdout,'stderr':stderr})
        return {'report':report,'started':start,'completed':end}
    # Only original deep acceptance is controlled here; actual operation shape,
    # Source separation, target equality and fresh raw closing are real readers.
    monkeypatch.setattr(target.epoch,'_run_epoch',original_proof)
    audit=target.audit_complete(source_binding=registration,closures=[closure],
        audit_root=case.root/'controlled-original-deep',output=case.root/'overlay-audit.json')
    value=target.validate_audit(audit)
    assert len(calls)==1 and calls[0][-1]==target.epoch._PROGRAM
    assert value['rows'][0]['measurement_source']['lab_commit']==case.runtime['lab_head']
    progress=target.initialize_progress(target=declaration,proofs=[audit],output=case.root/'overlay-progress.json')
    result=target.validate_progress(progress)
    assert result['target_accepted_count']==1 and result['final_target']==16000
    assert all(vector['remaining_slots']==list(range(64)) for vector in target.remaining_vectors(progress)
               if vector['mode']=='tamaraw')
