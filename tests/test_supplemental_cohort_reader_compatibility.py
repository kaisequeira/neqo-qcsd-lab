"""Finite old-reader and membership controls; no browser, GET or trace replay."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import zlib

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_selected_capture_input as plain
from qcsd_lab import rapid_selected_budget_input as budget
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab.rapid_operation_facts import OperationFacts

FIXTURES = Path(__file__).parent / 'fixtures'
LEGACY = FIXTURES / 'v9_reader_predecessors'
PLAIN44 = 'f12460f830c4f4ba7a2d5c5600be59c7fd9800ee0d974692b24bba84ed356308'
WHOLE44 = '80bd66d3d710f5f14cf4827b43245d96af75e8ec0994418bed480e3c2a348357'
LEDGER44 = '3436b935a6f0e2124bd64195bffadfeec7870f3824c76726d7f5e3c7bc8a5fad'
BUDGET44 = '3f03bae31b667535adab316fea98cc34f19bf9292bc1b041f428eb3a02dee3cb'


@pytest.fixture
def source44(tmp_path):
    value = json.loads((FIXTURES / 'supplemental_cohort_source44_readers.json').read_bytes())
    result = {}
    for name, item in value['files'].items():
        raw = zlib.decompress(base64.b64decode(item['zlib_base64']))
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
        assert len(raw) == item['size_bytes'] and item['mode'] == 0o644
        path = tmp_path / 'source44/src/qcsd_lab' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw); path.chmod(item['mode']); result[name] = path
    return result


@pytest.mark.parametrize('name', ['rapid_selected_capture_input.py',
    'rapid_per_class_selected_enrollment.py', 'whole_graph_supplement.py',
    'rapid_fixed_condition_target.py'])
def test_exact_source44_readers_preserve_protected_bodies(source44, name):
    before = fixed.reference(source44[name])
    after = fixed.reference(Path(fixed.__file__).parent / name)
    if name == 'rapid_fixed_condition_target.py':
        assert fixed._compatible_code_ref('target', before, after)
    else:
        assert fixed._compatible_acquisition_code('src/qcsd_lab/' + name, before, after)


@pytest.mark.parametrize('name', ['rapid_selected_capture_input.py',
    'rapid_selected_budget_input.py', 'rapid_per_class_selected_enrollment.py',
    'whole_graph_supplement.py'])
def test_earlier_finite_reader_projection_remains_valid(name):
    assert fixed._compatible_acquisition_code('src/qcsd_lab/' + name,
        fixed.reference(LEGACY / name), fixed.reference(Path(fixed.__file__).parent / name))


def source44_direct(source44, expected):
    sources = {**expected, plain.__name__: PLAIN44, whole.__name__: WHOLE44}
    if budget.__name__ in expected: sources[budget.__name__] = BUDGET44
    files = {plain.__name__: plain.reference(source44['rapid_selected_capture_input.py']),
        whole.__name__: plain.reference(source44['whole_graph_supplement.py'])}
    return {'direct_validator_sources': sources, 'direct_validator_files': files}


@pytest.mark.parametrize('typed', [False, True])
def test_source44_direct_dictionary_keeps_original_labels(source44, typed):
    expected = budget.direct_sources() if typed else plain.direct_sources()
    value = source44_direct(source44, expected); before = deepcopy(value)
    assert plain._compatible_direct_validator_sources(value, expected)
    assert value == before


@pytest.mark.parametrize('mutation', ['hybrid', 'other-role', 'extra'])
def test_invented_direct_dictionary_is_refused(source44, mutation):
    expected = budget.direct_sources(); value = source44_direct(source44, expected)
    if mutation == 'hybrid': value['direct_validator_sources'][plain.__name__] = expected[plain.__name__]
    elif mutation == 'other-role': value['direct_validator_sources']['qcsd_lab.application_response_policy'] = '0' * 64
    else: value['direct_validator_sources']['qcsd_lab.unknown'] = '0' * 64
    assert not plain._compatible_direct_validator_sources(value, expected)


def test_source44_ledger_dictionary_and_cross_epoch_refusal():
    value = {**ledger._sources(), plain.__name__: PLAIN44,
        budget.__name__: BUDGET44, ledger.__name__: LEDGER44}
    before = deepcopy(value); assert ledger._policy_sources(value); assert value == before
    value[plain.__name__] = 'ef14e839e0c1ab1b1540a9b8c024f0e8545c1a3cf5478deec30a500134aff337'
    with pytest.raises(ValueError, match='historical or current'): ledger._policy_sources(value)


@pytest.fixture
def membership_case(tmp_path, monkeypatch, source44):
    original = Path(fixed.__file__)
    package = tmp_path / 'executing/src/qcsd_lab'; package.mkdir(parents=True)
    target = package / original.name; target.write_bytes(original.read_bytes()); target.chmod(0o644)
    for item in fixed._acquisition_reader_sources().values():
        path = package / Path(item['path']).name
        path.write_bytes(Path(item['path']).read_bytes()); path.chmod(item['mode'])
    data = tmp_path / 'retained-selected.json'; data.write_bytes(b'original selected metadata\n'); data.chmod(0o600)
    old_target = fixed.reference(source44['rapid_fixed_condition_target.py'])
    current_target = fixed.reference(target)
    old = {'files': [old_target, fixed.reference(data)], 'trees': []}
    current = {'files': [current_target, fixed.reference(data),
        fixed.reference(package / 'whole_graph_input.py'),
        fixed.reference(package / 'rapid_supplemental_cohort.py')], 'trees': []}
    monkeypatch.setattr(fixed, '__file__', str(target))
    # These controls isolate read-set normalization. Separate tests above use
    # the genuine source projections; membership_close and file guards run here.
    monkeypatch.setattr(fixed, '_compatible_sources', lambda sources: True)
    monkeypatch.setattr(fixed, '_sources', lambda: {'target': current_target})
    return old, current, {'target': old_target}, package, data


def test_added_readers_are_authenticated_without_rewriting_historical_membership(membership_case):
    old, current, sources, _, _ = membership_case
    before = deepcopy((old, current))
    assert fixed._compatible_membership(old, current, sources)
    assert (old, current) == before


@pytest.mark.parametrize('mutation', ['unknown-current', 'unknown-producer', 'lost-original',
    'duplicate-added', 'missing-added-file', 'corrupted-added', 'changed-added-mode'])
def test_membership_mutations_remain_refused(membership_case, mutation):
    old, current, sources, package, data = membership_case
    if mutation in ('unknown-current', 'unknown-producer'):
        root = package if mutation == 'unknown-current' else Path(sources['target']['path']).parent
        extra = root / 'unlisted_reader.py'; extra.write_bytes(b'unknown reader\n'); extra.chmod(0o644)
        (current if mutation == 'unknown-current' else old)['files'].append(fixed.reference(extra))
    elif mutation == 'lost-original':
        current['files'] = [item for item in current['files'] if item['path'] != str(data)]
    elif mutation == 'duplicate-added':
        current['files'].append(deepcopy(current['files'][-1]))
    elif mutation == 'missing-added-file':
        (package / 'whole_graph_input.py').unlink()
    elif mutation == 'corrupted-added':
        path = package / 'whole_graph_input.py'; path.write_bytes(path.read_bytes() + b'\n# changed\n')
        current['files'][2] = fixed.reference(path)
    else:
        path = package / 'rapid_supplemental_cohort.py'; path.chmod(0o444)
        current['files'][3] = fixed.reference(path)
    try:
        assert fixed._compatible_membership(old, current, sources) is False
    except (ValueError, FileNotFoundError):
        pass


def test_added_reader_final_fence_rejects_mutation_after_cached_reference(membership_case):
    old, current, sources, package, _ = membership_case
    context = OperationFacts()
    with context.scope():
        assert fixed._compatible_membership(old, current, sources)
        path = package / 'rapid_supplemental_cohort.py'
        path.write_bytes(path.read_bytes() + b'\n# changed after hit\n')
        with pytest.raises(ValueError): context.check()


def test_cohort_reader_cannot_waive_protected_old_graph_code(source44, tmp_path):
    raw = Path(whole.__file__).read_bytes()
    path = tmp_path / 'whole-mutated.py'
    path.write_bytes(raw.replace(b'def policies()', b'def changed_policies()', 1)); path.chmod(0o644)
    with pytest.raises(ValueError):
        fixed._compatible_acquisition_code('src/qcsd_lab/whole_graph_supplement.py',
            fixed.reference(source44['whole_graph_supplement.py']), fixed.reference(path))
