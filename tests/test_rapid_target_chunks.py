"""Target chunk boundary controls; installed/raw eligibility is controlled.

The fixture uses the real public serial plan, full manifest fingerprints,
current code copies, policy/plan parsers, rendering and closing fences. Only
original target progress, canonical installation, admission/GET, named120 and
canary packet/deep acceptance primitives are synthetic. No scientific credit.
"""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_target_chunks as chunks
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_slot_chunks as geometry
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as runtime
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import application_response_policy as app
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_rapid_ordinary_parallel import current
from tests.test_rapid_rolling_capture import _sites
from tests.test_rapid_fixed_condition_target import duration_setting


@pytest.fixture
def case(current, monkeypatch):
    current.spec.cohort.write_bytes(target._json({'receipt_type': 'qcsd-prospective-additive-static-enrollment-batch-v1'}))
    from qcsd_lab import rapid_undefended_capture as ordinary
    inputs = json.loads(current.spec.qualification_spec.read_bytes())
    inputs['enrollment'] = ordinary._reference(current.spec.cohort)
    current.spec.qualification_spec.write_bytes(target._json(inputs))
    current.payload['qualification_spec_sha256'] = lanes._sha(current.spec.qualification_spec.read_bytes())
    current.payload['bindings'] = rolling._bindings_from_enrollment(current.spec.cohort, current.policy)
    current.spec.plan_receipt.write_bytes(rolling.admission._json(rolling.admission._bind(lanes.PLAN_TYPE, current.payload)))
    source = current.spec.runtime_source_root
    controls = chunks.sources()
    for relative, ref in controls.items():
        path = source / relative; path.parent.mkdir(parents=True, exist_ok=True)
        original = Path(ref['path']); path.write_bytes(original.read_bytes()); path.chmod(ref['mode'])
    source_label = json.loads(current.spec.source_manifest.read_bytes())
    client = lanes._sha(current.spec.client_binary.read_bytes())
    current.canonical['installed_client_sha256'] = client
    monkeypatch.setattr(runtime, 'reopen_runtime', lambda ref, actual, **kw: (
        current.canonical, {relative: (source / relative).read_bytes() for relative in controls}))
    manifest = json.loads((current.spec.workload_root / (current.sites[0].workload_id + '.json')).read_bytes())
    configuration = {'profile': 'research-1200', 'request_policies': ['as-defined'],
        'defenses': [{'name': 'undefended', 'kind': 'none', 'baseline': True}]}
    if 'application_body_identity_policy' in current.payload:
        configuration['application_body_identity_policy'] = current.payload['application_body_identity_policy']
    run = {'resolved_configuration': None, 'defense_parameters': None,
        'application_response_policy': app.application_response_policy(manifest),
        'primary_document_identity_policy': app.primary_document_identity_policy(manifest)}
    condition = target.condition_identity(configuration, run, 'undefended')
    result = current.root / 'original-current-canary-result'
    path = result / 'accepted/sample/neqo'; path.mkdir(parents=True)
    (path / 'run.json').write_bytes(target._json(run))
    (result / 'experiment.json').write_bytes(target._json({'configuration': configuration,
        'samples': [{'path': 'accepted/sample', 'state': 'accepted', 'defense': 'undefended'}]}))
    current.facts.update(result_root=str(result))
    members = [{'class_index': i + 1, 'candidate_id': site.candidate_id, 'workload_id': site.workload_id,
        'capture_limits': current.payload['capture_limits'],
        'original_graph_sha256': target.membership.graph_identity(current.spec.workload_root / (site.workload_id + '.json'))}
        for i, site in enumerate(current.sites)]
    progress = current.root / 'target-progress-boundary.json'
    progress.write_bytes(target._json({'original_target_progress_boundary': True}))
    input_path = current.root / 'target-input-boundary.json'
    input_path.write_bytes(target._json({'original_target_chunk_input_boundary': True}))
    inputs = {'mode': 'undefended', 'maximum': 16, 'inputs': {'target': target.reference(progress),
        'progress': target.reference(progress), 'target_id': 'a' * 64,
        'condition': {'identity': condition, 'identity_sha256': target._digest(condition)},
        'classes': members, 'capture_limits': current.payload['capture_limits'],
        'remaining_slots': list(range(4, 64)),
        'ranges': [{'slot_start': start, 'slot_count': count} for start, count in ((4,16),(20,16),(36,16),(52,12))]}}
    def read_input(ref):
        target._open(ref); target._open(inputs['inputs']['progress'])
        return deepcopy(inputs)
    monkeypatch.setattr(target, 'read_chunk_inputs', read_input)
    monkeypatch.setattr(target, 'validate_target', lambda ref: {'target_identity': {
        'native_head': source_label['neqo_commit'], 'client_sha256': client}})
    monkeypatch.setattr(target, 'input_files', lambda ref: [target.reference(target._open(ref))])
    monkeypatch.setattr(target, 'roots', lambda ref: (target._open(ref),))
    from qcsd_lab import rapid_ordinary_transport_control as transport
    # This inherited input has no real renewal. The original enrollment/raw
    # transport proof is controlled; target roots and all reference fences run.
    monkeypatch.setattr(transport, 'enrollment_roots', lambda spec, payload: {
        current.raw_root, current.spec.cohort.parent, current.spec.qualification_spec.parent})
    monkeypatch.setattr(readiness, 'readiness_mount_roots', lambda *args, **kwargs: {current.canary_file.parent})
    case = SimpleNamespace(current=current, inputs=inputs, inputs_ref=target.reference(input_path),
        canonical_ref=target.reference(Path(current.canonical_ref['path'])), result=result, source=source)
    return case


@pytest.fixture
def duration_case(case, monkeypatch):
    current = case.current; base = current.payload
    current.sites = tuple(rolling.plan.Site(site.candidate_id, site.workload_id, site.workload_sha256,
        site.primary_origin, 'controlled-buflo-named120', 'f'*64) for site in current.sites)
    base[target.traffic.FIELD] = target.duration.POLICY
    # Original admission/amendment proof is the same explicit HOST boundary as
    # the inherited fixture; the declared policy and renderer run unchanged.
    base['static_capture_amendment'] = {'path': 'controlled-original-amendment', 'sha256': 'f'*64}
    for row in base['lanes']: row.update(mode='buflo', qualification_set='controlled-buflo-named120')
    current.canary['schema_version'] = 1
    configuration, run = duration_setting()
    run['application_response_policy'] = case.inputs['inputs']['condition']['identity']['application_response_policy']
    run['primary_document_identity_policy'] = case.inputs['inputs']['condition']['identity']['primary_document_identity_policy']
    configuration['limits'] = {**target.duration.capture_limits('buflo', base['capture_limits'],
        policy=target.duration.POLICY), 'max_attempts': 1}
    (case.result/'accepted/sample/neqo/run.json').write_bytes(target._json(run))
    (case.result/'experiment.json').write_bytes(target._json({'configuration': configuration,
        'samples': [{'path': 'accepted/sample', 'state': 'accepted', 'defense': 'buflo'}]}))
    condition = target.condition_identity(configuration, run, 'buflo')
    case.inputs['mode'] = 'buflo'
    case.inputs['inputs']['condition'] = {'identity': condition, 'identity_sha256': target._digest(condition)}
    case.inputs['inputs']['capture_limits'] = target.duration.capture_limits('buflo', base['capture_limits'],
        policy=target.duration.POLICY)
    current.facts['traffic_hashes'] = target.traffic.expected(target.duration.POLICY)
    monkeypatch.setattr(chunks, '_base', lambda spec: (current.sites, base))
    return case


def test_fixed_buflo200_chunk_condition_and_policy_derive_only_capture_duration(duration_case):
    case = duration_case; base = case.current.payload; original = deepcopy(base['capture_limits'])
    reference, identity = chunks._condition(case.current.spec, case.current.sites, base, 'buflo')
    assert reference == case.current.canary and identity == case.inputs['inputs']['condition']['identity']
    p = policy(case); value, sites, kept = chunks.validate_policy(target.reference(p))
    assert value['capture_limits'] == {**original, 'timeout_seconds': 240, 'capture_seconds': 300}
    assert value['capture_limits']['max_attempts'] == 3 and kept['capture_limits'] == original
    lane = chunks.planned_lanes(value, target.reference(p), sites, shard=3)[0]
    rendered = yaml.safe_load(geometry.render(lane, sites, **geometry._render_options(base)))
    assert rendered['limits'] == value['capture_limits'] and rendered['workloads'] == {s.workload_id: 16 for s in sites}
    assert case.inputs['inputs']['classes'][0]['capture_limits'] == original


@pytest.mark.parametrize('field', list(target.duration.capture_limits('buflo',
    {'timeout_seconds': 120, 'capture_seconds': 180}, policy=target.duration.POLICY)) +
    ['max_attempts', 'max_response_bytes', 'capture_megabytes', 'settle_seconds', 'per_origin_cooldown_seconds'])
def test_fixed_buflo200_chunk_refuses_each_changed_formal_cap(field, duration_case):
    case = duration_case; case.inputs['inputs']['capture_limits'][field] += 1
    output = case.current.root/'refused-duration-policy.json'
    with pytest.raises(ValueError, match='caps'):
        chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref, output)
    assert not output.exists()


@pytest.mark.parametrize('change', ['practice-retries', 'practice-timeout', 'practice-response', 'undeclared-policy'])
def test_fixed_buflo200_chunk_condition_refuses_changed_practice_or_missing_plan_policy(change, duration_case):
    case = duration_case; base = case.current.payload
    if change == 'undeclared-policy':
        del base[target.traffic.FIELD]
        case.current.facts['traffic_hashes'] = target.traffic.expected()
    else:
        path = case.result/'experiment.json'; value = json.loads(path.read_bytes())
        field = {'practice-retries': 'max_attempts', 'practice-timeout': 'timeout_seconds',
            'practice-response': 'max_response_bytes'}[change]
        value['configuration']['limits'][field] += 1
        path.write_bytes(target._json(value))
    with pytest.raises(ValueError, match='exact practice caps'):
        chunks._condition(case.current.spec, case.current.sites, base, 'buflo')


def policy(case, suffix='one'):
    return chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref,
        case.current.root / (suffix + '-target-policy.json'))


def planned(case):
    p = policy(case)
    output = chunks.publish_plan(case.current.spec, target.reference(p), case.current.root / 'target-plan.json')
    return replace(case.current.spec, plan_receipt=output), p


def test_public_plan_reaches_original_slot_geometry_render_and_serial_dispatch(case):
    spec, p = planned(case)
    sites, value = rolling.verify_capture_plan(spec, require_current=True)
    assert geometry.is_plan(spec.plan_receipt) is False and chunks.is_plan(spec.plan_receipt)
    assert chunks.FIELD in value and 'slot_chunk_policy' not in value
    assert [(r['slot_start'], r['visits_per_workload']) for r in value['lanes']] == [(4,16),(20,16),(36,16),(52,12)]
    assert value['planned_trace_count'] == 60 * len(sites)
    lane = lanes._lane({'plan_payload': value}, value['lanes'][0]['campaign_name'])
    assert isinstance(lane, geometry.ChunkLane) and lane.slot_policy_sha256 == target.reference(p)['sha256']
    raw = lanes._render_lane_campaign(spec, lane, sites)
    assert raw == (spec.campaign_dir / (lane.campaign_name + '.yml')).read_bytes()
    document = yaml.safe_load(raw); assert document['workloads'] == {s.workload_id: 16 for s in sites}
    assert document['limits'] == case.current.payload['capture_limits']
    path = case.current.root / 'target-spec.json'; rolling._write_spec(path, spec)
    assert lanes.load_capture_spec(path) == spec
    assert case.inputs_ref['path'] in {str(path) for path in chunks.input_files(value)}
    assert Path(case.inputs_ref['path']).parent in rolling.enrollment_roots(spec)
    assert value['scientific_credit'] is False and value['formal_accepted_trace_count'] == 0


@pytest.mark.parametrize('change', ['membership', 'graph', 'caps', 'condition', 'empty', 'historical-canary', 'image', 'client'])
def test_policy_refuses_changed_target_and_current_measurement_boundaries_before_create(change, case):
    if change == 'membership': case.inputs['inputs']['classes'][0]['candidate_id'] = 'different-candidate'
    elif change == 'graph': case.inputs['inputs']['classes'][0]['original_graph_sha256'] = '0' * 64
    elif change == 'caps': case.inputs['inputs']['capture_limits']['max_response_bytes'] += 1
    elif change == 'condition': case.inputs['inputs']['condition']['identity']['primary_document_identity_policy'] = 'different'
    elif change == 'empty': case.inputs['inputs']['ranges'] = []
    elif change == 'historical-canary': case.current.canary['schema_version'] = 3
    elif change == 'image': case.current.facts['source'] = {**case.current.facts['source'], 'image_digest': 'sha256:' + '0' * 64}
    else: case.current.canonical['installed_client_sha256'] = '0' * 64
    output = case.current.root / 'refused-target-policy.json'
    with pytest.raises(ValueError):
        chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref, output)
    assert not output.exists()


@pytest.mark.parametrize('mode', list(target.MODES))
def test_all_five_fixed_modes_have_explicit_bounded_zero_credit_geometry(mode):
    sites = _sites(2)
    value = {'classes': [{'candidate_id': s.candidate_id, 'workload_id': s.workload_id} for s in sites],
        'mode': mode, 'remaining_slots': list(range(64)), 'maximum_visits': 16,
        'ranges': [{'slot_start': start, 'slot_count': 16} for start in (0,16,32,48)]}
    ref = {'sha256': 'f' * 64}
    planned = chunks.planned_lanes(value, ref, sites, shard=2)
    assert sum(lane.sample_count for lane in planned) == 128
    assert all(lane.mode == mode and lane.slot_policy_sha256 == ref['sha256'] for lane in planned)
    assert {geometry.logical_slot(lane, local) for lane in planned for local in range(lane.visits_per_workload)} == set(range(64))


@pytest.mark.parametrize('field', ['slot_start', 'visits_per_workload', 'workload_ids', 'slot_policy_sha256', 'target_chunk_policy'])
def test_rehashed_plan_cannot_change_slots_membership_or_target_authority(field, case):
    spec, p = planned(case); value = lanes.plan_payload(spec.plan_receipt.read_bytes())
    if field == 'target_chunk_policy':
        value[field] = target.reference(case.current.spec.plan_receipt)
    else:
        value['lanes'][0][field] = {'slot_start': 0, 'visits_per_workload': 15,
            'workload_ids': ['different-workload'], 'slot_policy_sha256': '0' * 64}[field]
    path = rolling._write(case.current.root / ('changed-' + field + '.json'), chunks.PLAN_TYPE, value)
    with pytest.raises(ValueError): rolling.verify_capture_plan(replace(spec, plan_receipt=path))


def test_recovery_preserves_target_offset_and_refuses_skipped_or_reused_generation(case):
    spec, p = planned(case); first = lanes.plan_payload(spec.plan_receipt.read_bytes())['lanes'][0]
    path = rolling.publish_successor(spec, first['campaign_name'], 2, case.current.root / 'g02-target-plan.json')
    _, recovered = rolling.verify_capture_plan(replace(spec, plan_receipt=path))
    current = recovered['lanes'][0]
    assert current['slot_start'] == first['slot_start'] and current['slot_policy_sha256'] == first['slot_policy_sha256']
    assert current['workload_ids'] == first['workload_ids'] and current['generation'] == 2
    assert recovered['target_chunk_policy'] == first_ref(spec)
    assert recovered['previous_target_chunk_plan'] == target.reference(spec.plan_receipt)
    with pytest.raises(ValueError):
        rolling.publish_successor(spec, first['campaign_name'], 3, case.current.root / 'skipped.json')
    with pytest.raises(FileExistsError):
        rolling.publish_successor(spec, first['campaign_name'], 2, case.current.root / 'another-g02.json')


def first_ref(spec): return lanes.plan_payload(spec.plan_receipt.read_bytes())[chunks.FIELD]


@pytest.mark.parametrize('kind', ['bytes', 'mode'])
def test_owned_policy_current_control_fence_rejects_mutation_before_publication(kind, case):
    relative = 'src/qcsd_lab/rapid_target_chunks.py'; path = case.source / relative
    before, mode = path.read_bytes(), path.stat().st_mode & 0o7777
    try:
        if kind == 'bytes': path.write_bytes(before + b'\n')
        else: path.chmod(mode ^ 0o100)
        with pytest.raises(ValueError, match='Source'):
            policy(case, 'refused-source')
        assert not (case.current.root / 'refused-source-target-policy.json').exists()
    finally:
        path.chmod(mode); path.write_bytes(before)


def test_borrowed_action_retains_target_input_byte_mode_and_membership_fence(case):
    with OperationFacts().scope() as context:
        p = policy(case); spec = replace(case.current.spec, plan_receipt=chunks.publish_plan(
            case.current.spec, target.reference(p), case.current.root / 'closed-plan.json'))
        rolling.verify_capture_plan(spec, _context=context)
        path = Path(case.inputs_ref['path']); raw = path.read_bytes()
        try:
            path.write_bytes(raw + b' ')
            with pytest.raises(ValueError): context.check()
        finally: path.write_bytes(raw)


def test_public_tool_forwards_hash_bound_policy_plan_and_refuses_old_plan(case):
    root = Path(__file__).resolve().parents[1]
    entry = importlib.util.spec_from_file_location('public_target_chunk_control', root / 'tools/rapid_target_chunks.py')
    cli = importlib.util.module_from_spec(entry); entry.loader.exec_module(cli)
    spec_path = case.current.root / 'base-spec.json'; rolling._write_spec(spec_path, case.current.spec)
    common = ['--spec', str(spec_path), '--spec-sha256', target.reference(spec_path)['sha256']]
    output = case.current.root / 'public-policy.json'
    assert cli.main(['policy', *common, '--chunk-inputs', case.inputs_ref['path'], '--chunk-inputs-sha256', case.inputs_ref['sha256'],
        '--canonical', case.canonical_ref['path'], '--canonical-sha256', case.canonical_ref['sha256'], '--output', str(output)]) == 0
    spec_out, plan_out = case.current.root / 'public-target-spec.json', case.current.root / 'public-target-plan.json'
    assert cli.main(['plan', *common, '--policy', str(output), '--policy-sha256', target.reference(output)['sha256'],
        '--output', str(plan_out), '--spec-output', str(spec_out)]) == 0
    assert cli.main(['check', '--spec', str(spec_out), '--spec-sha256', target.reference(spec_out)['sha256']]) == 0
    assert cli.main(['check', *common]) == 1
    assert cli.main(['policy', *common, '--chunk-inputs', case.inputs_ref['path'], '--chunk-inputs-sha256', '0' * 64,
        '--canonical', case.canonical_ref['path'], '--canonical-sha256', case.canonical_ref['sha256'],
        '--output', str(case.current.root / 'wrong-hash.json')]) == 1
