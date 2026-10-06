"""HOST dispatch/recovery controls; installed actors and packets stay controlled.

The real epoch wrapper, full-graph plan, original formal preparation/audit,
partial binding and pre-birth byte fence run. These fixtures grant no credit.
"""
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from qcsd_lab import rapid_epoch_target_parallel_schedule as workers
from qcsd_lab import rapid_epoch_target_chunks as chunks
from qcsd_lab import rapid_chunk_partial_lane as partial
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_parallel_capture as shared
from qcsd_lab import verification
from tests.test_rapid_epoch_target_parallel import epoch_pair, original_pair, epoch_case, case, current

ROOT = Path(__file__).resolve().parents[1]


def _original(relative):
    return subprocess.run(['git', 'show', 'HEAD:' + relative], cwd=ROOT,
                          check=True, stdout=subprocess.PIPE).stdout


@pytest.fixture
def original_readers(tmp_path):
    package = tmp_path / 'original-source/src/qcsd_lab'
    package.mkdir(parents=True)
    sources = {}
    for role, current_ref in target._sources().items():
        original = Path(current_ref['path'])
        path = package / original.name
        path.write_bytes(_original(original.relative_to(ROOT).as_posix()))
        path.chmod(current_ref['mode'])
        sources[role] = target.reference(path)
    return sources


def test_exact_historical_source_roles_retain_all_protected_ast(original_readers):
    assert target._compatible_sources(original_readers)
    for name, projection in (
            ('rapid_rolling_capture.py', target._epoch_dispatch_source_projection),
            ('rapid_rolling_schedule.py', target._parallel_schedule_source_projection),
            ('rapid_operation_facts.py', target._parallel_facts_source_projection),
            ('rapid_chunk_partial_lane.py', target._epoch_dynamic_source_projection)):
        relative = 'src/qcsd_lab/' + name
        old, new = _original(relative), (ROOT / relative).read_bytes()
        assert projection(old) == projection(new)
        with pytest.raises(ValueError, match='exact|Source pair'):
            projection(new + b'\nUNREVIEWED_SCIENTIFIC_RULE = True\n')


@pytest.mark.parametrize('change', ['protected-code', 'mode'])
def test_historical_facts_compatibility_refuses_unreviewed_code_and_full_mode(change, original_readers):
    path = Path(original_readers['facts']['path'])
    if change == 'protected-code':
        path.write_bytes(path.read_bytes().replace(b'def check(self)', b'def unreviewed_check(self)', 1))
    else:
        path.chmod(0o600)
    original_readers['facts'] = target.reference(path)
    with pytest.raises(ValueError):
        target._compatible_sources(original_readers)


def test_original_installed_reader_binding_preserves_original_locations(tmp_path):
    package = tmp_path / 'original-bound-source/src/qcsd_lab'
    package.mkdir(parents=True)
    refs = {}
    for name, current_ref in partial._reader_sources().items():
        original = Path(current_ref['path'])
        path = package / original.name
        path.write_bytes(_original(original.relative_to(ROOT).as_posix()))
        path.chmod(current_ref['mode'])
        refs[name] = partial.reference(path)
    assert partial._compatible_reader_sources(refs) == str(package.parent.parent)
    path = Path(refs['qcsd_lab.rapid_rolling_schedule']['path'])
    path.write_bytes(path.read_bytes() + b'\nUNREVIEWED_RUNTIME_RULE = True\n')
    refs['qcsd_lab.rapid_rolling_schedule'] = partial.reference(path)
    with pytest.raises(ValueError):
        partial._compatible_reader_sources(refs)


def test_membership_projection_authenticates_original_facts_and_rolling_bytes(original_readers):
    package = Path(original_readers['target']['path']).parent
    old_files, new_files = [], []
    for name in ('rapid_fixed_condition_target.py', 'rapid_rolling_capture.py', 'rapid_operation_facts.py'):
        old = package / name
        if not old.exists():
            current_path = ROOT / 'src/qcsd_lab' / name
            old.write_bytes(_original('src/qcsd_lab/' + name))
            old.chmod(current_path.stat().st_mode & 0o7777)
        old_files.append(target.reference(old))
        new_files.append(target.reference(ROOT / 'src/qcsd_lab' / name))
    assert target._compatible_membership({'files': old_files, 'trees': []},
        {'files': new_files, 'trees': []}, original_readers)


def test_real_formal_preparation_checks_epoch_workers_before_any_actor_claim(epoch_pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = epoch_pair
    path = case.current.root / 'epoch-worker-spec.json'
    rolling._write_spec(path, spec)
    proof = {'plan_payload': payload, 'cohort_generation': 'rolling-50'}
    monkeypatch.setattr(lanes, 'check_bound_image', lambda *a, **kw: {'proof': proof})
    monkeypatch.setattr(lanes, '_validate_image_proof', lambda *a, **kw: sites)
    reached = []
    class ActorBoundary(Exception):
        pass
    def lineage(worker_spec, lane, check, root, predecessor, **kwargs):
        reached.append(lane.campaign_name)
        raise ActorBoundary()
    monkeypatch.setattr(lanes, '_lineage_payload', lineage)
    evidence = case.current.root / 'prospective-epoch-worker-evidence'
    evidence.mkdir()
    with pytest.raises(ActorBoundary):
        formal.prepare_batch(path, evidence, [lane.campaign_name for lane in chosen],
                             case.current.root / 'epoch-pair-authority.json')
    assert reached == [chosen[0].campaign_name]
    assert not (evidence / 'lanes').exists()


@pytest.mark.parametrize('change', ['none', 'generation', 'mixed-plan'])
def test_formal_audit_accepts_exact_epoch_workers_and_refuses_changed_lineage(change, epoch_pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = epoch_pair
    root = case.current.root / 'controlled-formal-audit'
    root.mkdir()
    spec_path = root / 'spec.json'
    rolling._write_spec(spec_path, spec)
    facts, intents = [], []
    for index, lane in enumerate(chosen):
        intent_path = root / 'lanes' / lane.logical_name / 'g01/intent.json'
        intent_path.parent.mkdir(parents=True)
        intent = {'actuator': formal.ACTUATOR, 'campaign_sha256': payload['lanes'][index]['campaign_sha256'],
                  'started_at': rolling.admission._now()}
        intent_path.write_bytes(lanes._json(rolling.admission._bind(lanes.INTENT_TYPE, intent)))
        lineage = {'image_check': {'proof': {'plan_payload': payload, 'cohort_generation': 'rolling-50'}}}
        facts.append((spec, root, intent_path, intent, lineage, lane, sites))
        intents.append(rolling._ref(intent_path))
    if change == 'generation':
        facts[1][4]['image_check']['proof']['cohort_generation'] = 'final-50'
    elif change == 'mixed-plan':
        facts[1][4]['image_check']['proof']['plan_payload'] = case.current.payload
    authority = {'schema_version': 1, 'artifact_type': formal.AUTHORITY_TYPE,
        'runtime': {key: spec.serializable()[key] for key in shared.RUNTIME_KEYS},
        'campaigns': [{'path': str(spec.campaign_dir / (lane.campaign_name + '.yml')),
                       'sha256': intent['campaign_sha256']} for _, _, _, intent, _, lane, _ in facts],
        'capture_spec': rolling._ref(spec_path), 'lane_specs': [rolling._ref(spec_path)] * 2,
        'evidence_root': str(root), 'lane_intents': intents, 'installation': None}
    path = root / 'authority.json'
    path.write_bytes(lanes._json(authority))
    # Actor/runtime installation semantics are the controlled boundary; the
    # original authority read, typed epoch gates and two-worker chronology run.
    monkeypatch.setattr(shared, '_runtime_authority', lambda *a, **kw: None)
    monkeypatch.setattr(formal, '_lane', lambda value, index, **kw: facts[index])
    if change == 'none':
        actual, reopened = formal._audit(path)
        assert actual == authority and reopened == facts
    else:
        with pytest.raises(ValueError):
            formal._audit(path)


@pytest.mark.parametrize('early', [False, True])
def test_original_partial_measurement_dispatch_keeps_epoch_wrapper_policy_and_schedule(early, epoch_pair):
    case, spec, sites, payload, chosen, reference = epoch_pair
    identity = {'source': case.current.canonical['source'],
                'collection_image_digest': spec.collection_image_digest,
                'client_sha256': lanes._sha(spec.client_binary.read_bytes())}
    source = {'root': str(spec.module_root), 'binding': {
        'runtime_identity': identity, 'runtime': spec.serializable()}}
    report = {'lane': asdict(chosen[0]), 'spec': spec.serializable(),
        'experiment': {'source': {**identity['source'], 'image_digest': spec.collection_image_digest}},
        'intent': {'runtime_identity': {'runtime_source': identity['source'],
            'collection_image_digest': spec.collection_image_digest, 'client_sha256': identity['client_sha256']},
            'started_at': '2019-01-01T00:00:00Z' if early else rolling.admission._now()},
        'lineage': {'image_check': {'proof': {'plan_payload': payload}}},
        'read_dependencies': [target.reference(spec.plan_receipt),
            target.reference(Path(payload[chunks.FIELD]['path'])),
            target.reference(Path(reference['path'])),
            target.reference(Path(payload[workers.BASE_FIELD]['plan_receipt']))]}
    if early:
        with pytest.raises(ValueError):
            partial._measurement_binding(report, source)
    else:
        bound = partial._measurement_binding(report, source)
        assert bound['chunk_bindings']['plan'] == target.reference(spec.plan_receipt)
        assert bound['chunk_bindings']['policy']['sha256'] == chosen[0].slot_policy_sha256
        assert bound['chunk_bindings']['scheduling'] == target.reference(Path(reference['path']))


def _canary_boundary(root):
    directory = root / 'controlled-sealed-canary'
    directory.mkdir()
    source, execution = directory / 'source', directory / 'execution'
    source.mkdir(); execution.mkdir()
    (source / 'control.py').write_bytes(b'controlled original deep Source')
    (execution / 'control.py').write_bytes((source / 'control.py').read_bytes())
    inventory_path = directory / 'source-inventory.json'
    inventory_path.write_bytes(lanes._json(readiness._inventory(source)))
    plan_path = directory / 'plan.json'
    plan_path.write_bytes(lanes._json({'canonical_runtime': {
        'source_inventory_sha256': shared.sha(inventory_path.read_bytes())},
        'clean_runtime_root': str(source), 'execution_root': str(execution)}))
    result = execution / 'results/attempt'
    for name in verification.AUTHORITATIVE_DIRECTORIES:
        (result / name).mkdir(parents=True)
    (result / 'experiment.json').write_bytes(lanes._json({'engineering_fixture': 'controlled packet boundary'}))
    files = verification.authoritative_files(result)
    index = result / 'evidence.sha256'
    index.write_text(''.join(f'{shared.sha(path.read_bytes())}  {name}\n' for name, path in files.items()))
    deep = directory / 'deep.json'
    deep.write_bytes(lanes._json({'root': '/lab/results/attempt', 'evidence_index_sha256': shared.sha(index.read_bytes())}))
    return {'plan': rolling._ref(plan_path), 'deep_receipt': rolling._ref(deep)}


def _runtime_boundary(case):
    """Seal the expanded controlled Source without altering the inherited one."""
    directory = case.current.root / 'controlled-expanded-runtime-closure'
    directory.mkdir()
    inventory = readiness._inventory(case.source)
    inventory_path = directory / 'source-inventory.json'
    inventory_path.write_bytes(lanes._json(inventory))
    shutil.copytree(case.source, directory / 'image-context/source')
    canonical = deepcopy(case.current.canonical)
    canonical['source_inventory_sha256'] = shared.sha(inventory_path.read_bytes())
    path = directory / 'canonical.json'
    path.write_bytes(lanes._json(canonical))
    return rolling._ref(path)


@pytest.mark.parametrize('change', ['raw-bytes', 'raw-mode', 'raw-membership'])
def test_epoch_pre_birth_fence_authenticates_joined_dependencies_and_full_raw_modes(change, epoch_pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = epoch_pair
    intent = case.current.root / 'controlled-fence/intent.json'
    intent.parent.mkdir()
    for name in ('intent.json', 'lineage.json', 'dns.json'):
        intent.with_name(name).write_bytes(lanes._json({}))
    canary = _canary_boundary(case.current.root)
    fence_payload = {**payload, 'readiness': {chosen[0].mode: canary}}
    # The real capsule is already validated; the finite fence consumes a
    # separately controlled, actually sealed original-canary packet boundary.
    capsule = deepcopy(workers.validate_schedule(reference))
    # The inherited ordinary fixture closes only its original control files.
    # Installation semantics stay controlled, with real expanded Source bytes
    # and an exact image copy supplied to the unchanged finite fence.
    capsule['current_canonical'] = _runtime_boundary(case)
    monkeypatch.setattr(workers, 'require_plan', lambda value: capsule)
    monkeypatch.setattr(lanes, '_payload', lambda path, kind: fence_payload)
    lineage = {'image_check': {'proof': {'plan_payload': fence_payload}}}
    facts = [(spec, case.current.root, intent, {}, lineage, chosen[0], sites)]
    authority = {'evidence_root': str(case.current.root), 'lane_specs': [], 'lane_intents': []}
    fence = formal._release_fence(intent, authority, facts, {'input_files': []})
    assert case.current.raw_root.as_posix() in fence['trees']
    assert case.inputs_ref['path'] in fence['files']
    assert case.binding_ref['path'] in fence['files']
    assert all('mode' in row for row in fence['files'].values())
    raw = case.current.raw_root / 'raw.bin'
    if change == 'raw-bytes':
        raw.write_bytes(raw.read_bytes() + b'changed retained response')
    elif change == 'raw-mode':
        raw.chmod(0o600 if raw.stat().st_mode & 0o777 != 0o600 else 0o644)
    else:
        (case.current.raw_root / 'late.bin').write_bytes(b'changed raw membership')
    with pytest.raises(ValueError, match='changed'):
        formal._check_release_fence(fence, intent, authority, facts, {'input_files': []})
