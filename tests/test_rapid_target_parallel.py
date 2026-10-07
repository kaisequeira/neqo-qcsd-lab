"""Current target worker guards; packet/installation/retirement proofs controlled.

Real target policy/plan rendering and public worker/failed-peer reducers run.
These HOST controls claim no actual concurrent capture or successful canary.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_target_parallel_schedule as workers
from qcsd_lab import rapid_target_chunks as chunks
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as runtime
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_parallel_capture as shared
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_rapid_target_chunks import case, planned
from tests.test_rapid_ordinary_parallel import current

_REAL_BIND_CAPTURE = OperationFacts.bind_capture


@pytest.fixture
def pair(case, monkeypatch):
    source = case.source
    root = Path(__file__).resolve().parents[1]
    for relative in workers.CONTROL_FILES:
        path = source / relative; path.parent.mkdir(parents=True, exist_ok=True)
        original = root / relative; path.write_bytes(original.read_bytes()); path.chmod(original.stat().st_mode & 0o7777)
    # The original GET/admission semantic boundary remains controlled. Supply
    # its genuine prepared-input receipt shape so the current dependency reader
    # authenticates full-mode refs, retained validator Source and raw trees.
    from qcsd_lab import rapid_selected_capture_input as selected
    from qcsd_lab import rapid_undefended_capture as ordinary
    support = case.current.root / 'controlled-original-selected-inputs'
    validators = {}
    for module in selected._direct_modules():
        original = Path(module.__file__)
        relative = Path('src') / Path(*module.__name__.split('.')).with_suffix('.py')
        for path in (source / relative, support / relative):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(original.read_bytes()); path.chmod(original.stat().st_mode & 0o7777)
        validators[module.__name__] = selected.reference(support / relative)
    for row in case.current.classes:
        path = selected.reopen(row['prepared_workload'])
        manifest = json.loads(path.read_bytes())
        original = support / 'original-manifests' / path.name
        original.parent.mkdir(parents=True, exist_ok=True); original.write_bytes(lanes._json(manifest))
        proof = case.current.raw_root / row['workload_id'] / 'full-get-proof.json'
        proof.parent.mkdir(); proof.write_bytes(lanes._json({'controlled_original_GET_boundary': True}))
        audit = support / (row['workload_id'] + '-audit.json')
        audit.write_bytes(lanes._json({'controlled_original_admission_boundary': True}))
        receipt = support / (row['workload_id'] + '-input.json')
        payload = {'engineering_fixture': 'original GET semantics controlled; no scientific authority',
            'original_manifest': selected.reference(original), 'proof': selected.reference(proof),
            'selection_audit': selected.reference(audit), 'raw_root': str(case.current.raw_root),
            'direct_validator_files': validators,
            'direct_validator_sources': {name: ref['sha256'] for name, ref in validators.items()},
            'scientific_credit': False, 'formal_accepted_trace_count': 0}
        receipt.write_bytes(lanes._json(rolling.admission._bind(selected.RECEIPT_TYPE, payload)))
        manifest['preparation']['selected_input_evidence'] = {'schema_version': 1,
            'record_type': selected.RECEIPT_TYPE, 'receipt': selected.reference(receipt)}
        raw = lanes._json(manifest); path.write_bytes(raw)
        (case.current.spec.workload_root / path.name).write_bytes(raw)
        row['prepared_workload'] = selected.reference(path)
    def selected_dependencies(preparation, resources):
        receipt = selected.reopen(preparation['selected_input_evidence']['receipt'])
        payload = rolling.admission._unpack(receipt.read_bytes(), selected.RECEIPT_TYPE)
        original = selected.reopen(payload['original_manifest'])
        manifest = json.loads(original.read_bytes())
        assert resources == manifest['resources']
        assert preparation == {**manifest['preparation'],
            'selected_input_evidence': preparation['selected_input_evidence']}
        return ({receipt, original, selected.reopen(payload['proof']),
            selected.reopen(payload['selection_audit']), case.current.canary_file,
            *selected._bound_validator_files(payload),
            *(Path(module.__file__).absolute() for module in selected._direct_modules())},
            {case.current.raw_root})
    monkeypatch.setattr(selected, 'preparation_inputs', selected_dependencies)
    case.current.facts['workload_sha256'] = case.current.classes[0]['prepared_workload']['sha256']
    batch, _, _ = rolling._verify_enrollment(case.current.spec.cohort)
    policy_root = Path(batch['policy']['path']).parent
    inputs = ordinary.publish_inputs(case.current.spec.cohort, case.current.runtime,
        case.current.root / 'target-current-input.json')
    serial = rolling.publish_plan(policy_root, case.current.spec.cohort, inputs,
        case.current.root / 'target-current-serial-plan.json', readiness={'undefended': case.current.canary},
        runtime_inputs=case.current.runtime,
        application_body_identity_policy=case.current.payload.get('application_body_identity_policy'))
    case.current.spec = rolling.capture_spec(policy_root, case.current.spec.cohort, inputs, serial)
    case.current.sites, case.current.payload = rolling.verify_capture_plan(case.current.spec, require_current=True)
    monkeypatch.setattr(runtime, 'reopen_runtime', lambda ref, actual, **kw: (
        case.current.canonical, {relative: (source / relative).read_bytes() for relative in workers.CONTROL_FILES}))
    base, policy = planned(case)
    reference = workers.publish_schedule(base, case.current.runtime, base.qualification_spec,
        case.current.canonical_ref, case.current.canonical_ref, case.current.root / 'target-worker-capsule.json',
        reason='prospective HOST target-worker control')
    path = workers.publish_plan(base, reference, case.current.root / 'target-worker-plan.json')
    spec = replace(base, plan_receipt=path); sites, payload = rolling.verify_capture_plan(spec, require_current=True)
    chosen = [lanes._lane({'plan_payload': payload}, row['campaign_name']) for row in payload['lanes'][:2]]
    return case, spec, sites, payload, chosen, reference


def test_two_target_workers_bind_disjoint_slots_same_condition_and_original_graphs(pair):
    case, spec, sites, payload, chosen, reference = pair
    assert workers.prepared_sites(payload, payload['sites']) == sites
    assert [workers.prepared_lane(asdict(lane)) for lane in chosen] == chosen
    workers.require_disjoint([(spec, payload, lane, sites) for lane in chosen])
    assert len(workers.require_worker(payload, chosen[0], sites, spec)) == 16 * len(sites)
    assert payload['capture_limits'] == case.current.payload['capture_limits']
    assert payload['sites'] == case.current.payload['sites']
    capsule = runtime.require_schedule(reference, spec, declared_at=payload['declared_at'])
    assert capsule['mode'] == 'undefended' and capsule['condition_sha256'] == case.inputs['inputs']['condition']['identity_sha256']
    assert capsule['scientific_credit'] is False and capsule['formal_accepted_trace_count'] == 0
    assert rolling.enrollment_roots(spec)
    assert runtime.validate_ready_canary(case.current.canary, reference, mode='undefended', before=payload['declared_at']) == case.current.facts


def test_duplicate_mixed_and_changed_mode_workers_refuse(pair):
    case, spec, sites, payload, chosen, reference = pair
    with pytest.raises(ValueError, match='repeat'):
        workers.require_disjoint([(spec, payload, chosen[0], sites)] * 2)
    with pytest.raises(ValueError, match='mix'):
        workers.require_disjoint([(spec, payload, chosen[0], sites), (case.current.spec, case.current.payload, chosen[1], sites)])
    with pytest.raises(ValueError, match='registered'):
        workers.require_worker(payload, replace(chosen[0], mode='tamaraw'), sites, spec)


@pytest.mark.parametrize('field', ['condition_sha256', 'capture_limits', 'control_sources'])
def test_rehashed_worker_capsule_cannot_change_condition_caps_or_source(field, pair):
    case, spec, sites, payload, chosen, reference = pair
    value = json.loads(Path(reference['path']).read_bytes()); value[field] = 'substitution'
    path = case.current.root / ('altered-' + field + '.json'); path.write_bytes(lanes._json(value))
    with pytest.raises(ValueError): runtime.validate_schedule(rolling._ref(path))


def test_real_formal_prepare_reaches_typed_target_worker_guard_before_actor_boundary(pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = pair
    spec_path = case.current.root / 'target-worker-spec.json'; rolling._write_spec(spec_path, spec)
    proof = {'plan_payload': payload, 'cohort_generation': 'rolling-50'}
    monkeypatch.setattr(lanes, 'check_bound_image', lambda *a, **kw: {'proof': proof})
    monkeypatch.setattr(lanes, '_validate_image_proof', lambda *a, **kw: sites)
    reached = []
    class ActorBoundary(Exception): pass
    def lineage(worker_spec, lane, check, root, predecessor, **kwargs):
        reached.append(lane.campaign_name); raise ActorBoundary()
    monkeypatch.setattr(lanes, '_lineage_payload', lineage)
    evidence = case.current.root / 'worker-evidence'; evidence.mkdir()
    with pytest.raises(ActorBoundary):
        formal.prepare_batch(spec_path, evidence, [lane.campaign_name for lane in chosen], case.current.root / 'batch-authority.json')
    assert reached == [chosen[0].campaign_name]
    assert not (evidence / 'lanes').exists()


def test_failed_worker_retains_accepted_peer_and_successor_target_offsets(pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = pair
    output = case.current.root / 'terminal-worker-fixture'; output.mkdir()
    authority = output / 'authority.json'; authority.write_bytes(lanes._json({}))
    facts = []
    for index, lane in enumerate(chosen):
        intent = output / ('worker-' + str(index)) / 'intent.json'; intent.parent.mkdir()
        intent.write_bytes(lanes._json({'engineering_fixture': 'original actor birth'}))
        intent.with_name('host-process.json').write_bytes(lanes._json({'returncode': 1 if index == 0 else 0}))
        intent.with_name('complete.json').write_bytes(lanes._json({'accepted': lane.sample_count}))
        facts.append((spec, case.current.root, intent, {}, {}, lane, sites))
    monkeypatch.setattr(formal, '_audit', lambda path, **_options: ({'runtime': {}}, facts))
    monkeypatch.setattr(shared, 'verify_operator_closure', lambda *a: None)
    monkeypatch.setattr(formal, 'reopen_launch', lambda *a, **kw: None)
    monkeypatch.setattr(lanes, '_verified_host_process', lambda raw, *a: json.loads(raw))
    monkeypatch.setattr(rolling, 'check_lane_in_image', lambda *a, **kw: {'closure': {'path': str(output / 'deep.json'), 'sha256': 'a' * 64}})
    monkeypatch.setattr(rolling, '_reopen_lane_check', lambda ref: (spec, facts[1][2].with_name('complete.json'),
        {'accepted': chosen[1].sample_count, 'scientific_credit': 'formal-only-if-bound-to-rolling-enrollment'}, chosen[1], sites))
    (output / 'lane-2').mkdir(); (output / 'host-process.json').write_bytes(lanes._json({'returncode': 1}))
    held = {str(path): path.read_bytes() for path in output.rglob('*') if path.is_file()}
    report = formal.verify_results(authority, output)
    assert report['valid'] is False and report['lanes'][0]['accepted'] == 0
    assert report['lanes'][1]['valid'] is True and report['formal_accepted_trace_count'] == chosen[1].sample_count
    successor = rolling.publish_successor(spec, chosen[0].campaign_name, 2, case.current.root / 'target-recovery-plan.json')
    _, recovered = rolling.verify_capture_plan(replace(spec, plan_receipt=successor))
    row = recovered['lanes'][0]
    assert row['slot_start'] == chosen[0].slot_start and row['visits_per_workload'] == chosen[0].visits_per_workload
    assert row['slot_policy_sha256'] == chosen[0].slot_policy_sha256 and row['generation'] == 2
    assert all(Path(path).read_bytes() == raw for path, raw in held.items())


def test_target_parallel_cannot_use_serial_partial_authority(pair):
    case, spec, sites, payload, chosen, reference = pair
    report = {'lane': asdict(chosen[0]), 'spec': spec.serializable(), 'lineage': {'image_check': {'proof': {'plan_payload': payload}}}, 'read_dependencies': []}
    with pytest.raises(ValueError): chunks.require_partial_binding(report)


@pytest.mark.parametrize('change', ['bytes', 'mode'])
def test_real_capture_facts_registers_target_policy_inputs_and_closes_mutation(change, pair, monkeypatch):
    case, spec, sites, payload, chosen, reference = pair
    # Only the original enrollment proof is controlled; the actual Facts
    # binder, target dependency selector and mutation fence run unchanged.
    monkeypatch.setattr(OperationFacts, '_enrollment', lambda self, path: self.watch_file(path))
    context = OperationFacts(); context.begin_action()
    with context.scope():
        _REAL_BIND_CAPTURE(context, spec)
        path = Path(case.inputs_ref['path']); raw, mode = path.read_bytes(), path.stat().st_mode & 0o7777
        assert path in context._files
        try:
            if change == 'bytes': path.write_bytes(raw + b' ')
            else: path.chmod(mode ^ 0o100)
            with pytest.raises(ValueError): context.check()
        finally:
            path.chmod(mode); path.write_bytes(raw)


@pytest.mark.parametrize('change', ['none', 'bytes', 'mode', 'unknown-key'])
def test_identical_relocated_target_reader_code_requires_original_bytes_and_full_modes(change, tmp_path, monkeypatch):
    first, second = tmp_path / 'owned-original.py', tmp_path / 'relocated-reader.py'
    first.write_bytes(b'original unchanged deep reader authority'); first.chmod(0o644)
    second.write_bytes(first.read_bytes()); second.chmod(0o644)
    producer, current = {'epoch': target.reference(first)}, {'epoch': target.reference(second)}
    monkeypatch.setattr(target, '_sources', lambda: current)
    if change == 'bytes': second.write_bytes(b'changed reader')
    elif change == 'mode': second.chmod(0o600)
    elif change == 'unknown-key': producer['unexpected'] = target.reference(first)
    if change == 'none': assert target._compatible_sources(producer)
    else:
        with pytest.raises(ValueError): target._compatible_sources(producer)


@pytest.mark.parametrize('kind', ['code', 'raw-metadata'])
def test_membership_relocation_normalizes_only_bound_reader_code_not_raw_authority(kind, tmp_path, monkeypatch):
    old, new = tmp_path / 'original-source', tmp_path / 'reader-source'
    producer_sources, executing_sources = {}, {}
    for name in ('target', 'epoch'):
        relative = Path('src/qcsd_lab') / (name + '.py')
        for root in (old, new):
            path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'controlled identical reader Source'); path.chmod(0o644)
        producer_sources[name], executing_sources[name] = target.reference(old / relative), target.reference(new / relative)
    monkeypatch.setattr(target, '__file__', str(new / 'src/qcsd_lab/target.py'))
    monkeypatch.setattr(target, '_sources', lambda: executing_sources)
    relative = Path('src/qcsd_lab/dependency.py') if kind == 'code' else Path('raw/input.json')
    for root in (old, new):
        path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'identical bytes remain independently authenticated'); path.chmod(0o644)
    producer = {'files': [target.reference(old / relative)], 'trees': []}
    executing = {'files': [target.reference(new / relative)], 'trees': []}
    assert target._compatible_membership(producer, executing, producer_sources) is (kind == 'code')
