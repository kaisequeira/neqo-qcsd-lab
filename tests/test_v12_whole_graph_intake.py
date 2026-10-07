"""Exact V12 successor and historical compatibility; no browser, GET or capture.

QCSD_V12_PLAN_PATH binds the genuine next-five declaration. Its exact external
check reconstructs the unchanged V8 interruption and completed V11 predecessor.
QCSD_V12_BATCH_CLOSURE may bind a real completed V12 batch after Root execution.
QCSD_V12_NEXT_PLAN_PATH and QCSD_V12_NEXT_BATCH_CLOSURE optionally bind the
actual consecutive V12 declaration and batch, using the same producer bytes.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import rapid_fixed_condition_target as fixed
from tests.test_supplemental_cohort_reader_compatibility import membership_case, source44

V11_INPUT_SHA = '7477a9735dd949cc894bf3a457c69638851615c64ca0f4c5723bf439f98b33bf'


def _actual_path(name):
    raw = os.environ.get(name)
    if not raw:
        pytest.skip(f'{name} is not bound to an actual immutable artifact')
    path = Path(raw).absolute()
    if not path.is_file():
        pytest.fail(f'{name} does not name an actual immutable file')
    return path


def _actual_plan():
    path = _actual_path('QCSD_V12_PLAN_PATH')
    return path, inputs.load_plan(path)


def test_v12_registration_is_distinct_and_retains_v11_authority():
    assert inputs.VERSIONS[inputs.V12_PLAN_TYPE] == (
        12, inputs.V12_CONTRACT, inputs.V12_INPUT_TYPE, inputs.V12_PRODUCERS)
    assert inputs.VERSIONS[inputs.V11_PLAN_TYPE][0] == 11
    assert inputs.V12_PRODUCERS != inputs.V11_PRODUCERS
    assert inputs.V12_ACTION_SOURCES != inputs.V11_ACTION_SOURCES
    assert inputs.CONTROL_SOURCES[12] == inputs.CONTROL_SOURCES[8]


def test_v12_projection_restores_every_historical_v11_byte(tmp_path):
    current = Path(inputs.__file__)
    before_raw = fixed._v12_input_reader_source_projection(current.read_bytes())
    assert hashlib.sha256(before_raw).hexdigest() == V11_INPUT_SHA
    assert hashlib.sha256(fixed._v11_input_reader_source_projection(current.read_bytes())).hexdigest() == (
        '455aa51a397f025d4a6b0145c5a963d6455c0af51159b03535c69b506150d47b')
    before = tmp_path / 'whole_graph_input.py'
    before.write_bytes(before_raw); before.chmod(0o644)
    assert fixed._compatible_acquisition_code('src/qcsd_lab/whole_graph_input.py',
        fixed.reference(before), fixed.reference(current))
    with pytest.raises(ValueError):
        fixed._v12_input_reader_source_projection(current.read_bytes() + b'\n# altered\n')
    before.write_bytes(before_raw + b'\n# changed historical source\n')
    with pytest.raises(ValueError):
        fixed._compatible_acquisition_code('src/qcsd_lab/whole_graph_input.py',
            fixed.reference(before), fixed.reference(current))


def test_bound_v11_reader_membership_is_reopened_without_rewriting(membership_case):
    old, current, sources, package, _ = membership_case
    previous = Path(sources['target']['path']).parent / 'whole_graph_input.py'
    previous.write_bytes(fixed._v12_input_reader_source_projection(
        (package / 'whole_graph_input.py').read_bytes()))
    previous.chmod(0o644)
    old['files'].append(fixed.reference(previous))
    snapshot = deepcopy((old, current))
    assert fixed._compatible_membership(old, current, sources)
    assert (old, current) == snapshot
    previous.chmod(0o444)
    old['files'][-1] = fixed.reference(previous)
    with pytest.raises(ValueError):
        fixed._compatible_membership(old, current, sources)


def test_genuine_source60_fixed_target_keeps_every_protected_reader_unit():
    previous = _actual_path('QCSD_SOURCE60_TARGET_PATH')
    before = fixed.reference(previous)
    assert before['sha256'] == 'd485db59ab1e976382e0e544522ea0f15aa638bbe7ca16b62373b5089528de00'
    assert fixed._compatible_code_ref('target', before, fixed.reference(Path(fixed.__file__)))


def test_genuine_v12_plan_retains_candidates_and_complete_authority_transport():
    path, plan = _actual_plan()
    previous = inputs.load_plan(inputs.reopen(plan['previous_plan']))
    batch_path = inputs.reopen(plan['previous_batch'])
    batch = json.loads(batch_path.read_bytes())
    assert previous['schema_version'] == 11
    assert batch['plan'] == plan['previous_plan'] and inputs.zero(batch)
    assert plan['original_plan'] == previous['original_plan']
    assert plan['retained_interruption'] == previous['retained_interruption']
    assert plan['prebirth_failure'] == previous['prebirth_failure']
    assert [(row['catalogue_position'], row['candidate_id']) for row in plan['candidates']] == [
        (41, 'tranco-0000563'), (42, 'tranco-0000115'), (43, 'tranco-0000748'),
        (44, 'tranco-0000192'), (45, 'tranco-0000927')]
    assert inputs.zero(plan)
    assert plan['outer_budget']['setup_seconds'] == 240
    assert plan['candidate_deadline_seconds'] == 180
    files, roots = inputs.plan_files(path)
    files, roots = set(files), set(roots)
    assert inputs.reopen(plan['previous_plan']) in files and batch_path in files
    assert batch_path.parent in roots
    assert {p for p in batch_path.parent.rglob('*') if p.is_file()} <= files
    for entry in plan['action_local_sources'].values():
        assert inputs.reopen(entry) in files
    refusal = plan['prebirth_failure']
    assert inputs.reopen(refusal['plan']) in files and Path(refusal['root']) in roots
    assert {inputs.reopen(ref) for ref in refusal['tree']['files'].values()} <= files
    retained = json.loads(inputs.reopen(plan['retained_interruption']).read_bytes())
    original = json.loads(inputs.reopen(retained['original_root_inputs']).read_bytes())
    driver = inputs.reopen(original['driver'])
    assert driver in files and driver.with_name('authorities.json') in files
    assert {inputs.reopen(original[key]) for key in ('producer_closure', 'producer_review')} <= files


@pytest.mark.parametrize('group,key', [
    ('producer_sources', 'graph_input.py'), ('producer_sources', 'operator.py'),
    ('action_local_sources', 'controller.py'), ('action_local_sources', 'action_facts.py')])
@pytest.mark.parametrize('field,changed', [('sha256', '0' * 64), ('mode', '0444')])
def test_genuine_v12_reader_substitution_refuses_before_external_execution(monkeypatch, group, key, field, changed):
    _, plan = _actual_plan()
    altered = deepcopy(plan)
    altered[group][key][field] = changed
    monkeypatch.setattr(inputs.subprocess, 'run', lambda *a, **k: pytest.fail('must refuse before subprocess'))
    with pytest.raises(ValueError):
        inputs._producer(altered)


def _assert_actual_batch(path, plan, batch_path):
    batch = json.loads(batch_path.read_bytes())
    assert batch_path.name == 'batch-closed.json' and batch['plan'] == inputs.reference(path)
    assert inputs.zero(batch) and len(batch['candidates']) == len(plan['candidates'])
    for local, row in enumerate(batch['candidates'], 1):
        assert row['local_index'] == local and row['candidate'] == plan['candidates'][local - 1]
        assert inputs.zero(row)
        evidence = inputs.reopen(row['evidence'])
        assert evidence.parent == batch_path.parent / 'attempts' / f'candidate-{local:06d}'
        if row['discovery_returncode'] == 0:
            envelope, neutral = inputs.load_input(evidence)
            assert evidence.name == 'whole-graph-input.json'
            assert envelope['plan'] == inputs.reference(path)
            assert envelope['candidate'] == row['candidate'] and neutral['resources']
            assert envelope['http3_get_performed'] is False and inputs.zero(envelope)
            assert evidence in inputs.input_files(evidence)[0]
        else:
            assert row['discovery_returncode'] == 1 and evidence.name == 'failed.json'
            failure = inputs.load_failure(evidence)
            assert failure['plan'] == inputs.reference(path)
            assert failure['candidate'] == row['candidate'] and inputs.zero(failure)
            assert failure['outcome'] == 'operational-discovery-failure-no-admission'


def test_genuine_v12_batch_inputs_and_operational_failures_keep_zero_credit():
    path, plan = _actual_plan()
    _assert_actual_batch(path, plan, _actual_path('QCSD_V12_BATCH_CLOSURE'))


def test_genuine_consecutive_v12_plan_reuses_exact_producer_and_complete_transport():
    path, plan = _actual_plan()
    first_batch_path = _actual_path('QCSD_V12_BATCH_CLOSURE')
    assert json.loads(first_batch_path.read_bytes())['plan'] == inputs.reference(path)
    next_path = _actual_path('QCSD_V12_NEXT_PLAN_PATH')
    following = inputs.load_plan(next_path)
    assert following['schema_version'] == 12
    previous_path = inputs.reopen(following['previous_plan'])
    previous = inputs.load_plan(previous_path)
    batch_path = inputs.reopen(following['previous_batch'])
    assert previous['schema_version'] == 12
    assert json.loads(batch_path.read_bytes())['plan'] == following['previous_plan']
    for key in ('producer_sources', 'action_local_sources', 'original_plan',
                'retained_interruption', 'prebirth_failure', 'source',
                'source_metadata', 'browser_image', 'catalogue', 'discovery_control'):
        assert following[key] == previous[key] == plan[key]
    assert inputs._producer(following) == inputs._producer(previous) == inputs._producer(plan)
    assert len(following['candidates']) == len(previous['candidates']) == 5
    assert all(row in following['reserved_candidates'] for row in
               [*previous['reserved_candidates'], *previous['candidates']])
    assert {row['candidate_id'] for row in following['candidates']}.isdisjoint(
        {row['candidate_id'] for row in following['reserved_candidates']})
    assert min(row['catalogue_position'] for row in following['candidates']) > max(
        row['catalogue_position'] for row in previous['candidates'])
    assert following['local_candidate_indices'] == following['original_candidate_indices'] == [1, 2, 3, 4, 5]
    assert inputs.zero(following)
    first_files, first_roots = inputs.plan_files(path)
    previous_files, previous_roots = inputs.plan_files(previous_path)
    next_files, next_roots = inputs.plan_files(next_path)
    assert set(first_files) <= set(previous_files)
    assert set(first_roots) <= set(previous_roots)
    assert set(previous_files) <= set(next_files)
    assert set(previous_roots) <= set(next_roots)
    assert path in next_files and previous_path in next_files
    assert first_batch_path in next_files and batch_path in next_files
    assert batch_path.parent in next_roots
    assert {p for p in batch_path.parent.rglob('*') if p.is_file()} <= set(next_files)


def test_genuine_consecutive_v12_batch_keeps_exact_inputs_and_zero_credit():
    path = _actual_path('QCSD_V12_NEXT_PLAN_PATH')
    plan = inputs.load_plan(path)
    _assert_actual_batch(path, plan, _actual_path('QCSD_V12_NEXT_BATCH_CLOSURE'))
