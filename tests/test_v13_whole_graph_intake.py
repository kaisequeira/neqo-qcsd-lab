"""Finite V13 intake and exact Source62 compatibility; no network or capture.

QCSD_V13_PLAN_PATH, QCSD_V13_BATCH_CLOSURE, QCSD_V13_NEXT_PLAN_PATH and
    QCSD_V13_NEXT_BATCH_CLOSURE bind genuine prospective declarations and closed
batches. QCSD_SOURCE62_TARGET_PATH binds the frozen predecessor target reader.
Unbound actual-evidence checks skip rather than manufacture a passing batch.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import whole_graph_supplement as supplement
from qcsd_lab import rapid_supplemental_cohort as cohort
from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab.rapid_operation_facts import OperationFacts

SOURCE62_INPUT_SHA = '5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5'
SOURCE62_SUPPLEMENT_SHA = '164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7'
SOURCE62_TARGET_SHA = '80783154a4c0097fa8729b69c3ea5dd6ca8f617dd655ce286c7e929874ba8f45'
SOURCE62_COHORT_SHA = '12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be'


def _actual_path(name):
    raw = os.environ.get(name)
    if not raw:
        pytest.skip(f'{name} is not bound to an actual immutable artifact')
    path = Path(raw).absolute()
    if not path.is_file():
        pytest.fail(f'{name} does not name an actual immutable file')
    return path


def _producer_plan():
    root = Path(inputs.__file__).parent.parent.parent
    producer = root / 'tools' / 'whole_graph_discovery_v13'
    return {'schema_version': 13, 'artifact_type': inputs.V13_PLAN_TYPE,
            'contract': inputs.V13_CONTRACT,
            'producer_sources': {name: inputs.reference(producer / name)
                                 for name in inputs.V13_PRODUCERS}}


def test_v13_registration_keeps_the_frozen_v12_producer_distinct():
    assert inputs.VERSIONS[inputs.V13_PLAN_TYPE] == (
        13, inputs.V13_CONTRACT, inputs.V13_INPUT_TYPE, inputs.V13_PRODUCERS)
    assert inputs.VERSIONS[inputs.V12_PLAN_TYPE][0] == 12
    assert set(inputs.V13_PRODUCERS) == {'graph_input.py', 'operator.py', 'canonical_homepage.py'}
    plan = _producer_plan()
    assert inputs._producer(plan) == inputs.reopen(plan['producer_sources']['operator.py'])


@pytest.mark.parametrize('name', ['graph_input.py', 'operator.py', 'canonical_homepage.py'])
@pytest.mark.parametrize('field,changed', [('sha256', '0' * 64), ('mode', '0444')])
def test_v13_refuses_producer_substitution_before_external_execution(monkeypatch, name, field, changed):
    plan = _producer_plan()
    plan['producer_sources'][name][field] = changed
    monkeypatch.setattr(inputs.subprocess, 'run',
                        lambda *a, **k: pytest.fail('must refuse before subprocess'))
    with pytest.raises(ValueError):
        inputs._producer(plan)


def test_v13_refuses_an_unregistered_producer_role_before_external_execution(monkeypatch):
    plan = _producer_plan()
    plan['producer_sources']['extra.py'] = deepcopy(plan['producer_sources']['graph_input.py'])
    monkeypatch.setattr(inputs.subprocess, 'run',
                        lambda *a, **k: pytest.fail('must refuse before subprocess'))
    with pytest.raises(ValueError):
        inputs._producer(plan)


def test_v13_input_projection_restores_every_source62_and_older_byte(tmp_path):
    current = Path(inputs.__file__)
    retained = fixed._v13_input_reader_source_projection(current.read_bytes())
    assert hashlib.sha256(retained).hexdigest() == SOURCE62_INPUT_SHA
    assert hashlib.sha256(fixed._v12_input_reader_source_projection(current.read_bytes())).hexdigest() == (
        '7477a9735dd949cc894bf3a457c69638851615c64ca0f4c5723bf439f98b33bf')
    assert hashlib.sha256(fixed._v11_input_reader_source_projection(current.read_bytes())).hexdigest() == (
        '455aa51a397f025d4a6b0145c5a963d6455c0af51159b03535c69b506150d47b')
    previous = tmp_path / 'whole_graph_input.py'
    previous.write_bytes(retained); previous.chmod(0o644)
    assert fixed._compatible_acquisition_code('src/qcsd_lab/whole_graph_input.py',
                                             fixed.reference(previous), fixed.reference(current))
    with pytest.raises(ValueError):
        fixed._v13_input_reader_source_projection(current.read_bytes() + b'\n# altered\n')
    previous.chmod(0o444)
    with pytest.raises(ValueError):
        fixed._compatible_acquisition_code('src/qcsd_lab/whole_graph_input.py',
                                          fixed.reference(previous), fixed.reference(current))


def test_source62_get_pair_keeps_all_original_supplement_bytes(tmp_path):
    current = Path(supplement.__file__)
    retained = fixed._v13_supplement_reader_source_projection(current.read_bytes())
    assert hashlib.sha256(retained).hexdigest() == SOURCE62_SUPPLEMENT_SHA
    previous = tmp_path / 'whole_graph_supplement.py'
    previous.write_bytes(retained); previous.chmod(0o644)
    assert fixed._compatible_acquisition_code('src/qcsd_lab/whole_graph_supplement.py',
                                             fixed.reference(previous), fixed.reference(current))
    with pytest.raises(ValueError):
        fixed._v13_supplement_reader_source_projection(current.read_bytes() + b'\n# altered\n')
    source62 = {**supplement.producer_sources(), 'qcsd_lab.whole_graph_input': SOURCE62_INPUT_SHA,
                'qcsd_lab.whole_graph_supplement': SOURCE62_SUPPLEMENT_SHA}
    assert supplement._recognized_producer_sources(source62)
    for key in ('qcsd_lab.whole_graph_input', 'qcsd_lab.whole_graph_supplement'):
        altered = dict(source62); altered[key] = '0' * 64
        assert not supplement._recognized_producer_sources(altered)


def test_genuine_source62_target_keeps_all_protected_scientific_units():
    previous = _actual_path('QCSD_SOURCE62_TARGET_PATH')
    retained = fixed.reference(previous)
    assert retained['sha256'] == SOURCE62_TARGET_SHA and retained['mode'] == 0o644
    assert fixed._compatible_code_ref('target', retained, fixed.reference(Path(fixed.__file__)))


def test_source62_cohort_projection_restores_every_original_byte(tmp_path):
    current = Path(cohort.__file__)
    retained = fixed._v13_cohort_reader_source_projection(current.read_bytes())
    assert hashlib.sha256(retained).hexdigest() == SOURCE62_COHORT_SHA
    previous = tmp_path / 'rapid_supplemental_cohort.py'
    previous.write_bytes(retained); previous.chmod(0o644)
    assert fixed._compatible_acquisition_code('src/qcsd_lab/rapid_supplemental_cohort.py',
                                             fixed.reference(previous), fixed.reference(current))
    with pytest.raises(ValueError):
        fixed._v13_cohort_reader_source_projection(current.read_bytes() + b'\n# altered\n')


def test_genuine_source62_cohort_reader_family_is_bound_and_not_mixed():
    package = _actual_path('QCSD_SOURCE62_TARGET_PATH').parent
    refs = {name: inputs.reference(package / (name.rsplit('.', 1)[1] + '.py'))
            for name in cohort.reader_sources()}
    assert cohort._recognized_reader_sources(refs)
    mixed = deepcopy(refs)
    name = 'qcsd_lab.rapid_per_class_selected_enrollment'
    mixed[name] = cohort.reader_sources()[name]
    assert not cohort._recognized_reader_sources(mixed)
    for field, changed in [('sha256', '0' * 64), ('mode', '0444')]:
        altered = deepcopy(refs); altered[name][field] = changed
        with pytest.raises(ValueError):
            cohort._recognized_reader_sources(altered)


def test_genuine_source62_cohort_reopens_without_rewriting_existing_evidence():
    path = _actual_path('QCSD_SOURCE62_COHORT_PATH')
    original = path.read_bytes()
    facts = OperationFacts()
    facts.begin_action()
    with facts.scope():
        context = cohort.load_context(path.parent)
        facts.check()
    assert context.root == path.parent and inputs.zero(context.provenance)
    assert path.read_bytes() == original


def test_genuine_v13_declaration_binds_original_candidates_and_complete_predecessor():
    path = _actual_path('QCSD_V13_PLAN_PATH')
    plan = inputs.load_plan(path)
    assert plan['schema_version'] == 13 and inputs.zero(plan)
    assert all(row['source_url'] == f"https://{row['domain']}/" for row in plan['candidates'])
    previous_path = inputs.reopen(plan['previous_plan'])
    previous = inputs.load_plan(previous_path)
    batch_path = inputs.reopen(plan['previous_batch'])
    batch = json.loads(batch_path.read_bytes())
    assert previous['schema_version'] in (12, 13)
    assert batch['plan'] == plan['previous_plan'] and inputs.zero(batch)
    assert plan['reserved_candidates'] == [*previous['reserved_candidates'], *previous['candidates']]
    files, roots = inputs.plan_files(path)
    assert previous_path in files and batch_path in files and batch_path.parent in roots
    assert {item for item in batch_path.parent.rglob('*') if item.is_file()} <= set(files)
    assert {inputs.reopen(ref) for ref in plan['producer_sources'].values()} <= set(files)


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
            value, neutral = inputs.load_input(evidence)
            assert value['candidate'] == row['candidate'] and inputs.zero(value)
            assert value['http3_get_performed'] is False
            canonical_path = inputs.reopen(value['canonical_homepage'])
            canonical = json.loads(canonical_path.read_bytes())
            assert canonical['candidate'] == value['candidate']
            assert canonical['initial_url'] == value['candidate']['source_url']
            assert canonical['final_url'] == value['final_source_url'] == neutral['resources'][0]['url']
            assert inputs.zero(canonical)
            assert neutral == json.loads(inputs.reopen(value['native_manifest']).read_bytes())
            files, _ = inputs.input_files(evidence)
            assert evidence in files and canonical_path in files
            assert inputs.reopen(value['host_validation']) in files
            for hop in canonical['hops']:
                assert {inputs.reopen(ref) for ref in hop.values()} <= set(files)
        else:
            assert row['discovery_returncode'] == 1 and evidence.name == 'failed.json'
            failure = inputs.load_failure(evidence)
            assert failure['plan'] == inputs.reference(path) and failure['candidate'] == row['candidate']
            assert inputs.zero(failure) and failure['outcome'] == 'operational-discovery-failure-no-admission'


def test_genuine_v13_closed_batch_keeps_complete_new_graphs_and_failed_attempts():
    path = _actual_path('QCSD_V13_PLAN_PATH')
    _assert_actual_batch(path, inputs.load_plan(path), _actual_path('QCSD_V13_BATCH_CLOSURE'))


def test_genuine_consecutive_v13_batch_reuses_the_same_portable_producer():
    first_path = _actual_path('QCSD_V13_PLAN_PATH')
    first = inputs.load_plan(first_path)
    batch_path = _actual_path('QCSD_V13_BATCH_CLOSURE')
    following_path = _actual_path('QCSD_V13_NEXT_PLAN_PATH')
    following = inputs.load_plan(following_path)
    assert following['schema_version'] == 13 and inputs.zero(following)
    assert following['previous_plan'] == inputs.reference(first_path)
    assert following['previous_batch'] == inputs.reference(batch_path)
    assert following['producer_sources'] == first['producer_sources']
    assert following['canonical_homepage_policy'] == first['canonical_homepage_policy']
    assert following['reserved_candidates'] == [*first['reserved_candidates'], *first['candidates']]
    assert {row['candidate_id'] for row in following['candidates']}.isdisjoint(
        row['candidate_id'] for row in following['reserved_candidates'])
    first_files, first_roots = inputs.plan_files(first_path)
    following_files, following_roots = inputs.plan_files(following_path)
    assert set(first_files) <= set(following_files) and set(first_roots) <= set(following_roots)
    _assert_actual_batch(following_path, following, _actual_path('QCSD_V13_NEXT_BATCH_CLOSURE'))
