"""HOST epoch-worker seams; original GET, packet and installation boundaries controlled.

The public serial epoch policy, parallel wrapper, rendering, dependency selector
and immediate successor all run. These controls grant no concurrent-capture credit.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_epoch_target_parallel_schedule as workers
from qcsd_lab import rapid_epoch_target_chunks as chunks
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as runtime
from qcsd_lab import rapid_lane_evidence as lanes
from tests.test_rapid_target_parallel import pair as original_pair
from tests.test_rapid_epoch_target_chunks import epoch_case
from tests.test_rapid_target_chunks import case
from tests.test_rapid_ordinary_parallel import current


@pytest.fixture
def epoch_pair(original_pair, epoch_case, monkeypatch):
    case = epoch_case; source = case.source
    root = Path(__file__).resolve().parents[1]
    for relative in workers.CONTROL_FILES:
        path = source / relative; path.parent.mkdir(parents=True, exist_ok=True)
        original = root / relative; path.write_bytes(original.read_bytes()); path.chmod(original.stat().st_mode & 0o7777)
    monkeypatch.setattr(runtime, 'reopen_runtime', lambda ref, actual, **kw: (
        case.current.canonical, {relative: (source / relative).read_bytes() for relative in workers.CONTROL_FILES}))
    policy = chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref,
        case.current.root / 'epoch-worker-policy.json')
    serial = chunks.publish_plan(case.current.spec, target.reference(policy), case.current.root / 'epoch-worker-serial.json')
    base = replace(case.current.spec, plan_receipt=serial)
    reference = workers.publish_schedule(base, case.current.runtime, base.qualification_spec,
        case.current.canonical_ref, case.current.canonical_ref, case.current.root / 'epoch-worker-capsule.json',
        reason='prospective HOST declared epoch worker fixture')
    path = workers.publish_plan(base, reference, case.current.root / 'epoch-worker-plan.json')
    spec = replace(base, plan_receipt=path)
    sites, payload = rolling.verify_capture_plan(spec, require_current=True)
    chosen = [lanes._lane({'plan_payload': payload}, row['campaign_name']) for row in payload['lanes'][:2]]
    return case, spec, sites, payload, chosen, reference


def _tool():
    path = Path(__file__).parents[1] / 'tools/rapid_epoch_target_parallel.py'
    spec = importlib.util.spec_from_file_location('epoch_worker_public_tool', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def _flags(name, ref):
    return ['--' + name, ref['path'], '--' + name + '-sha256', ref['sha256']]


def test_public_epoch_capsule_plan_check_preserves_serial_authority_and_directory_mounts(epoch_pair):
    case, spec, sites, payload, chosen, reference = epoch_pair
    tool = _tool(); base = runtime._spec(payload[workers.BASE_FIELD])
    base_path = case.current.root / 'public-base-spec.json'; rolling._write_spec(base_path, base)
    capsule = case.current.root / 'public-capsule.json'
    assert tool.main(['capsule', *_flags('spec', target.reference(base_path)),
        *_flags('canonical', case.canonical_ref), '--output', str(capsule)]) == 0
    plan = case.current.root / 'public-worker-plan.json'; selected = case.current.root / 'public-worker-spec.json'
    assert tool.main(['plan', *_flags('spec', target.reference(base_path)), *_flags('capsule', target.reference(capsule)),
        '--output', str(plan), '--spec-output', str(selected)]) == 0
    assert tool.main(['check', *_flags('spec', target.reference(selected))]) == 0
    capsule_value = workers.validate_schedule(reference)
    assert {key: capsule_value[key] for key in workers.EPOCH_FIELDS} == {
        key: chunks.validate_policy(payload[chunks.FIELD])[0][key] for key in workers.EPOCH_FIELDS}
    assert workers.prepared_sites(payload, payload['sites']) == sites
    assert [workers.prepared_lane(asdict(lane)) for lane in chosen] == chosen
    workers.require_disjoint([(spec, payload, lane, sites) for lane in chosen])
    assert len(workers.require_worker(payload, chosen[0], sites, spec)) == 16 * len(sites)
    assert payload[chunks.FIELD]['sha256'] == chosen[0].slot_policy_sha256
    assert payload['sites'] == case.current.payload['sites']
    assert payload['capture_limits'] == case.current.payload['capture_limits']
    assert runtime.require_schedule(reference, spec, declared_at=payload['declared_at']) == capsule_value
    argv = lanes.image_check_command(spec, inherit_environment=False)
    mounts = [Path(argv[index+1].split(':',1)[0]) for index,arg in enumerate(argv) if arg == '--volume']
    assert mounts and all(path.is_dir() and not path.is_symlink() for path in mounts)
    assert case.inputs_ref['path'] in {str(path) for path in workers.input_dependencies(base, sites)[0]}
    assert capsule_value['formal_accepted_trace_count'] == 0 and capsule_value['scientific_credit'] is False


def test_historical_serial_target_cannot_be_promoted_to_epoch_workers(epoch_pair):
    case, spec, sites, payload, chosen, reference = epoch_pair
    output = case.current.root / 'refused-old-target-capsule.json'
    with pytest.raises(ValueError, match='serial epoch'):
        workers.publish_schedule(case.current.spec, case.current.runtime, case.current.spec.qualification_spec,
            case.current.canonical_ref, case.current.canonical_ref, output, reason='wrong original target role')
    assert not output.exists()


@pytest.mark.parametrize('field', ['epoch_index', 'native_head', 'client_sha256', 'epoch_progress', 'source_binding', 'epoch_declared_at'])
def test_resealed_capsule_refuses_epoch_native_client_progress_binding_and_stamp(field, epoch_pair):
    case, spec, sites, payload, chosen, reference = epoch_pair
    value = json.loads(Path(reference['path']).read_bytes())
    value[field] = True if field == 'epoch_index' else 'substitution'
    path = case.current.root / ('altered-epoch-' + field + '.json'); path.write_bytes(lanes._json(value))
    with pytest.raises(ValueError): workers.validate_schedule(rolling._ref(path))


def test_same_condition_peers_refuse_overlap_mixed_contract_and_another_epoch(epoch_pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = epoch_pair
    with pytest.raises(ValueError, match='repeat'):
        workers.require_disjoint([(spec,payload,chosen[0],sites)]*2)
    with pytest.raises(ValueError, match='mix'):
        workers.require_disjoint([(spec,payload,chosen[0],sites),(case.current.spec,case.current.payload,chosen[1],sites)])
    with pytest.raises(ValueError, match='registered'):
        workers.require_worker(payload,replace(chosen[0],mode='tamaraw'),sites,spec)
    # Isolate the peer join after capsule validation: two individually checked
    # capsule projections with an otherwise identical fixed condition still
    # cannot cross the selected epoch boundary.
    capsule = workers.require_plan(payload); other = deepcopy(capsule); other['epoch_index'] += 1
    second = deepcopy(payload)
    checked = workers.require_plan
    monkeypatch.setattr(workers,'require_plan',lambda value,**kw: other if value is second else checked(value,**kw))
    with pytest.raises(ValueError, match='same joined'):
        workers.require_disjoint([(spec,payload,chosen[0],sites),(spec,second,chosen[1],sites)])


def test_public_successor_keeps_epoch_slots_and_all_original_peer_bytes(epoch_pair):
    case, spec, sites, payload, chosen, reference = epoch_pair
    held_paths = [spec.plan_receipt, Path(reference['path']),
        runtime._spec(payload[workers.BASE_FIELD]).plan_receipt,
        *(spec.campaign_dir / (lane.campaign_name+'.yml') for lane in chosen)]
    held = {path:path.read_bytes() for path in held_paths}
    spec_path = case.current.root / 'worker-recovery-source-spec.json'; rolling._write_spec(spec_path,spec)
    refused = case.current.root / 'skipped-worker.json'
    assert _tool().main(['successor',*_flags('spec',target.reference(spec_path)),
        '--lane',chosen[0].campaign_name,'--generation','3','--output',str(refused),
        '--spec-output',str(case.current.root/'skipped-spec.json')]) == 1
    assert not refused.exists() and not refused.with_name('skipped-worker-serial.json').exists()
    output = case.current.root / 'next-worker.json'; selected = case.current.root / 'next-worker-spec.json'
    assert _tool().main(['successor',*_flags('spec',target.reference(spec_path)),
        '--lane',chosen[0].campaign_name,'--generation','2','--output',str(output),'--spec-output',str(selected)]) == 0
    _, recovered = rolling.verify_capture_plan(lanes.load_capture_spec(selected))
    assert len(recovered['lanes']) == 1 and recovered['lanes'][0]['generation'] == 2
    assert recovered['lanes'][0]['slot_start'] == chosen[0].slot_start
    assert recovered['lanes'][0]['visits_per_workload'] == chosen[0].visits_per_workload
    assert recovered[chunks.FIELD] == payload[chunks.FIELD]
    assert workers.require_plan(recovered)['epoch_progress'] == workers.require_plan(payload)['epoch_progress']
    assert all(path.read_bytes() == raw for path,raw in held.items())


def test_partial_original_proof_requires_all_epoch_wrapper_authorities_and_prospective_intent(epoch_pair):
    case, spec, sites, payload, chosen, reference = epoch_pair
    refs = [target.reference(spec.plan_receipt),target.reference(target._open(payload[chunks.FIELD])),
        target.reference(rolling._open_ref(reference)),target.reference(runtime._spec(payload[workers.BASE_FIELD]).plan_receipt)]
    report = {'lane':asdict(chosen[0]),'spec':spec.serializable(),'read_dependencies':refs,
        'intent':{'started_at':payload['declared_at']},'lineage':{'image_check':{'proof':{'plan_payload':payload}}}}
    checked = workers.require_partial_binding(report)
    assert set(checked['chunk_bindings']) == {'plan','policy','scheduling','serial_plan'}
    for omitted in refs:
        altered = deepcopy(report); altered['read_dependencies'].remove(omitted)
        with pytest.raises(ValueError,match='omitted'): workers.require_partial_binding(altered)
    early = deepcopy(report); early['intent']['started_at'] = '2019-01-01T00:00:00+00:00'
    with pytest.raises(ValueError,match='predates'): workers.require_partial_binding(early)


@pytest.mark.parametrize('change',['bytes','mode'])
def test_actual_executing_epoch_worker_source_must_match_both_explicit_mounts(change,epoch_pair):
    case, spec, sites, payload, chosen, reference = epoch_pair
    path = case.source/'src/qcsd_lab/rapid_epoch_target_parallel_schedule.py'
    raw,mode = path.read_bytes(),path.stat().st_mode & 0o7777
    try:
        if change == 'bytes': path.write_bytes(raw+b'\n# altered only in bound mounted Source\n')
        else: path.chmod(mode^0o100)
        with pytest.raises(ValueError,match='Source'): workers.validate_schedule(reference)
    finally:
        path.chmod(mode);path.write_bytes(raw)
