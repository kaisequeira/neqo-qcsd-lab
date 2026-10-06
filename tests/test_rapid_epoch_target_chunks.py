"""Prospective epoch chunks use joined gaps and the original serial lane gates.

Only the historical proof producer, canary packet evidence and clean-runtime
receipt are controlled. Public policy/plan/check, rendering and dispatch run.
"""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

from qcsd_lab import rapid_epoch_target_chunks as chunks
from qcsd_lab import rapid_per_mode_native_target as epochs
from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as runtime
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_slot_chunks as geometry
from tests.test_rapid_target_chunks import case
from tests.test_rapid_ordinary_parallel import current


@pytest.fixture
def epoch_case(case, monkeypatch):
    current = case.current
    controls = chunks.sources()
    for relative, ref in controls.items():
        path = case.source / relative
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(Path(ref['path']).read_bytes())
            path.chmod(ref['mode'])
    monkeypatch.setattr(runtime, 'reopen_runtime', lambda ref, actual, **kw: (
        current.canonical, {relative: (case.source / relative).read_bytes() for relative in controls}))
    source = current.canonical['source']
    pair = {'native_head': source['neqo_commit'], 'client_sha256': current.canonical['installed_client_sha256'],
            'condition_sha256': case.inputs['inputs']['condition']['identity_sha256']}
    reference = fixed.reference(current.root / 'target-progress-boundary.json')
    binding_path = current.root / 'prospective-installed-binding.json'
    binding_path.write_bytes(b'controlled installed binding')
    binding = fixed.reference(binding_path)
    values = deepcopy(case.inputs)
    selected = values['inputs']
    selected.update(target=reference, progress=reference, target_id='e' * 64,
        epoch_index=1, epoch=pair, epoch_declared_at='2020-01-01T00:00:00+00:00',
        source_binding=binding)
    bound = {'native_head': pair['native_head'], 'binding': {'canonical': case.canonical_ref, 'runtime_identity': {
        'source': source, 'collection_image_digest': current.spec.collection_image_digest,
        'client_sha256': pair['client_sha256']}}}
    monkeypatch.setattr(epochs, 'read_chunk_inputs', lambda ref: deepcopy(values) if fixed._open(ref) else None)
    original_pair = {'native_head': 'c' * 40, 'client_sha256': 'd' * 64,
                     'condition_sha256': pair['condition_sha256']}
    declared = {'target_id': selected['target_id'], 'published_at': '2020-01-01T00:00:01+00:00',
        'carry_progress': reference,
        'mode_targets': {'undefended': [
            {'target': reference, 'source_binding': None},
            {'target': reference, 'source_binding': deepcopy(binding)}]},
        'identity': {'epochs': {'undefended': [original_pair, deepcopy(pair)]}},
        'epoch_declared_at': {'undefended': [None, selected['epoch_declared_at']]}}
    monkeypatch.setattr(epochs, 'validate_target', lambda ref: deepcopy(declared))
    monkeypatch.setattr(epochs, 'validate_progress', lambda ref: {
        'target': selected['target'], 'target_id': selected['target_id'],
        'published_at': '2020-01-01T00:00:02+00:00',
        'mode_progress': {'undefended': [reference]}, 'parent': None, 'previous_progress': None})
    monkeypatch.setattr(epochs, '_binding', lambda ref, selected_pair: deepcopy(bound))
    monkeypatch.setattr(epochs, 'input_files', lambda ref: [reference])
    monkeypatch.setattr(epochs, 'directory_dependencies', lambda ref: [])
    case.values = values
    case.binding = bound
    case.binding_ref = binding
    return case


def _public_tool():
    path = Path(__file__).parents[1] / 'tools/rapid_epoch_target_chunks.py'
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location('epoch_chunk_tool', path))
    module.__spec__.loader.exec_module(module)
    return module


def _flags(name, ref):
    return ['--' + name, ref['path'], '--' + name + '-sha256', ref['sha256']]


def _policy(case, *, name='epoch-policy.json'):
    return chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref,
                                 case.current.root / name)


def test_public_epoch_policy_plan_check_and_serial_dispatch_skip_original_four(epoch_case, capsys):
    case = epoch_case; tool = _public_tool()
    policy_path = case.current.root / 'public-epoch-policy.json'
    # Use the real public CLI with the existing captured spec serialized once.
    spec_path = case.current.root / 'base-epoch-spec.json'
    rolling._write_spec(spec_path, case.current.spec)
    assert tool.main(['policy', *_flags('spec', fixed.reference(spec_path)),
        *_flags('chunk-inputs', case.inputs_ref), *_flags('canonical', case.canonical_ref),
        '--output', str(policy_path)]) == 0
    policy_ref = fixed.reference(policy_path)
    plan_path = case.current.root / 'public-epoch-plan.json'
    selected_spec = case.current.root / 'public-epoch-spec.json'
    assert tool.main(['plan', *_flags('spec', fixed.reference(spec_path)),
        *_flags('policy', policy_ref), '--output', str(plan_path),
        '--spec-output', str(selected_spec)]) == 0
    assert tool.main(['check', *_flags('spec', fixed.reference(selected_spec))]) == 0
    spec = lanes.load_capture_spec(selected_spec)
    sites, plan = rolling.verify_capture_plan(spec, require_current=True)
    assert chunks.is_plan(plan_path) and not geometry.is_plan(plan_path)
    assert chunks.FIELD in plan and 'target_chunk_policy' not in plan and 'slot_chunk_policy' not in plan
    assert [(row['slot_start'], row['visits_per_workload']) for row in plan['lanes']] == [
        (4, 16), (20, 16), (36, 16), (52, 12)]
    assert plan['planned_trace_count'] == 60 * len(sites)
    lane = lanes._lane({'plan_payload': plan}, plan['lanes'][0]['campaign_name'])
    assert isinstance(lane, geometry.ChunkLane)
    assert lane.slot_policy_sha256 == policy_ref['sha256']
    assert lanes._render_lane_campaign(spec, lane, sites) == (
        spec.campaign_dir / (lane.campaign_name + '.yml')).read_bytes()
    assert plan['scientific_credit'] is False and plan['formal_accepted_trace_count'] == 0
    assert case.inputs_ref['path'] in {str(path) for path in chunks.input_files(plan)}
    assert Path(case.inputs_ref['path']).parent in rolling.enrollment_roots(spec)
    command = lanes.image_check_command(spec, inherit_environment=False)
    mounts = [Path(command[index + 1].split(':', 1)[0]) for index, arg in enumerate(command)
              if arg == '--volume']
    assert mounts and all(path.is_dir() and not path.is_symlink() for path in mounts)
    assert Path(case.inputs_ref['path']).parent in mounts
    assert Path(case.inputs_ref['path']) not in mounts


@pytest.mark.parametrize('change', ['native', 'client', 'binding', 'source', 'stamp', 'epoch-index',
                                    'epoch-condition', 'slots', 'graph', 'caps'])
def test_policy_refuses_epoch_pair_binding_time_and_original_graph_changes(epoch_case, change):
    case = epoch_case; selected = case.values['inputs']
    if change == 'native': selected['epoch']['native_head'] = '0' * 40
    elif change == 'client': selected['epoch']['client_sha256'] = '0' * 64
    elif change == 'binding': selected['source_binding'] = None
    elif change == 'source': case.binding['binding']['runtime_identity']['source']['neqo_commit'] = '0' * 40
    elif change == 'stamp': selected['epoch_declared_at'] = '2999-01-01T00:00:00+00:00'
    elif change == 'epoch-index': selected['epoch_index'] = 0
    elif change == 'epoch-condition': selected['epoch']['condition_sha256'] = '0' * 64
    elif change == 'slots': selected['ranges'][0]['slot_start'] = 0
    elif change == 'graph': selected['classes'][0]['original_graph_sha256'] = '0' * 64
    else: selected['capture_limits']['max_response_bytes'] += 1
    with pytest.raises(ValueError): _policy(case, name='refused-epoch-policy.json')
    assert not (case.current.root / 'refused-epoch-policy.json').exists()


def test_public_old_target_plan_cannot_be_claimed_as_epoch_plan(epoch_case, capsys):
    case = epoch_case
    spec_path = case.current.root / 'old-plan-spec.json'
    rolling._write_spec(spec_path, case.current.spec)
    assert _public_tool().main(['check', *_flags('spec', fixed.reference(spec_path))]) == 1
    assert 'refused' in capsys.readouterr().out


def test_epoch_intent_requires_prospective_declaration_and_policy(epoch_case):
    case = epoch_case; ref = fixed.reference(_policy(case))
    with pytest.raises(ValueError, match='predates'):
        chunks.require_intent(ref, '2019-12-31T23:59:59+00:00')
    assert chunks.require_intent(ref, '2999-01-01T00:00:00+00:00')['epoch_index'] == 1


def test_original_native_epoch_cannot_use_current_repaired_runtime(epoch_case):
    case = epoch_case; selected = case.values['inputs']
    selected.update(epoch_index=0, epoch_declared_at=None, source_binding=None)
    selected['epoch']['native_head'] = 'c' * 40
    selected['epoch']['client_sha256'] = 'd' * 64
    with pytest.raises(ValueError, match='Native|client'):
        _policy(case, name='wrong-original-native-policy.json')
    assert not (case.current.root / 'wrong-original-native-policy.json').exists()


def test_clean_lab_image_successor_keeps_same_declared_native_pair(epoch_case):
    case = epoch_case
    bound = case.binding['binding']
    bound['canonical'] = {'path': '/earlier/clean-installed-canonical.json', 'sha256': 'f' * 64}
    bound['runtime_identity']['source'] = {**bound['runtime_identity']['source'],
        'lab_commit': 'a' * 40}
    bound['runtime_identity']['collection_image_digest'] = 'sha256:' + 'b' * 64
    policy = _policy(case, name='clean-source-successor-policy.json')
    assert chunks.validate_policy(fixed.reference(policy))[0]['source_binding'] == case.binding_ref


def test_recovery_keeps_exact_epoch_policy_progress_and_logical_offsets(epoch_case):
    case = epoch_case
    policy_ref = fixed.reference(_policy(case))
    plan_path = chunks.publish_plan(case.current.spec, policy_ref, case.current.root / 'first-epoch-plan.json')
    spec = replace(case.current.spec, plan_receipt=plan_path)
    _, original = rolling.verify_capture_plan(spec)
    first = original['lanes'][0]
    with pytest.raises(ValueError):
        chunks.publish_successor(spec, first['campaign_name'], 3, case.current.root / 'skipped-epoch-plan.json')
    assert not (case.current.root / 'skipped-epoch-plan.json').exists()
    next_path = chunks.publish_successor(spec, first['campaign_name'], 2, case.current.root / 'next-epoch-plan.json')
    _, next_plan = rolling.verify_capture_plan(replace(spec, plan_receipt=next_path))
    assert next_plan[chunks.FIELD] == original[chunks.FIELD] == policy_ref
    assert next_plan['previous_epoch_target_chunk_plan'] == fixed.reference(plan_path)
    assert len(next_plan['lanes']) == 1
    assert next_plan['lanes'][0]['generation'] == 2
    assert (next_plan['lanes'][0]['slot_start'], next_plan['lanes'][0]['visits_per_workload']) == (4, 16)
    assert chunks.validate_policy(policy_ref)[0]['epoch_progress'] == case.values['inputs']['progress']


def test_resealed_epoch_plan_cannot_launder_old_policy_field(epoch_case):
    case = epoch_case
    policy_ref = fixed.reference(_policy(case))
    path = chunks.publish_plan(case.current.spec, policy_ref, case.current.root / 'one-epoch-plan.json')
    raw = json.loads(path.read_bytes())
    raw['payload']['target_chunk_policy'] = policy_ref
    from qcsd_lab import rapid_site_admission as receipts
    path.write_bytes(receipts._json(receipts._bind(chunks.PLAN_TYPE, raw['payload'])))
    with pytest.raises(ValueError): rolling.verify_capture_plan(replace(case.current.spec, plan_receipt=path))


@pytest.mark.parametrize('name, projection', [
    ('rapid_rolling_capture.py', fixed._epoch_dispatch_source_projection),
    ('rapid_chunk_partial_lane.py', fixed._epoch_dynamic_source_projection),
])
def test_historical_dispatch_pair_preserves_residual_and_refuses_changed_bytes(name, projection):
    relative = 'src/qcsd_lab/' + name
    old = subprocess.check_output(['git', 'show', 'HEAD:' + relative])
    new = Path(relative).read_bytes()
    assert projection(old) == projection(new)
    with pytest.raises(ValueError, match='exact'): projection(new + b'\nREPLACED_SCIENTIFIC_GUARD = True\n')


def test_original_dynamic_reader_pair_accepts_only_its_exact_published_successor(tmp_path):
    relative = 'src/qcsd_lab/rapid_chunk_partial_lane.py'
    predecessor = tmp_path / 'rapid_chunk_partial_lane.py'
    predecessor.write_bytes(subprocess.check_output(['git', 'show', 'HEAD:' + relative]))
    successor = Path(relative).absolute()
    assert fixed._compatible_code_ref('dynamic', fixed.reference(predecessor), fixed.reference(successor))
    predecessor.write_bytes(predecessor.read_bytes() + b'\nFORGED_SCIENTIFIC_GUARD = True\n')
    with pytest.raises(ValueError):
        fixed._compatible_code_ref('dynamic', fixed.reference(predecessor), fixed.reference(successor))
