"""Finite reader compatibility controls; no GET, image or raw trace replay.

The source dictionaries are copied from genuine class17/class35 inputs and the
b0010 policy. Predecessor code is exact Source43. Complete raw proof readers
remain separate authorities; these tests exercise only the new source seam.
"""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_selected_capture_input as plain
from qcsd_lab import rapid_selected_budget_input as budget
from qcsd_lab import rapid_per_class_selected_enrollment as perclass
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab.rapid_operation_facts import OperationFacts

FIXTURES = Path(__file__).parent / 'fixtures/v9_reader_predecessors'


def selected(index):
    sources = json.loads((FIXTURES / f'class{index}-direct-sources.json').read_bytes())
    changed = (plain.__name__, whole.__name__, budget.__name__)
    return {'direct_validator_sources': sources,
        'direct_validator_files': {name: plain.reference(FIXTURES / (name.rsplit('.', 1)[1] + '.py'))
            for name in changed if name in sources}}


@pytest.mark.parametrize('index', [17, 35])
def test_genuine_historical_source_dictionaries_keep_original_identity(index):
    value = selected(index); before = deepcopy(value)
    expected = plain.direct_sources() if index == 17 else budget.direct_sources()
    assert plain._compatible_direct_validator_sources(value, expected)
    assert value == before


@pytest.mark.parametrize('mutation', ['unknown', 'missing', 'extra', 'other-role', 'hybrid'])
def test_resealed_dictionary_changes_and_invented_hybrids_are_refused(mutation):
    value = selected(35); expected = budget.direct_sources()
    if mutation == 'unknown': value['direct_validator_sources'][whole.__name__] = '0' * 64
    elif mutation == 'missing': value['direct_validator_sources'].pop(whole.__name__)
    elif mutation == 'extra': value['direct_validator_sources']['qcsd_lab.unknown'] = '0' * 64
    elif mutation == 'other-role': value['direct_validator_sources']['qcsd_lab.application_response_policy'] = '0' * 64
    else: value['direct_validator_sources'][plain.__name__] = expected[plain.__name__]
    assert not plain._compatible_direct_validator_sources(value, expected)


def test_old_whole_reader_cannot_invent_current_application_policy_dictionary():
    value = selected(17)
    value['direct_validator_sources'][whole.__name__] = '726c0d6215830730f3938b69545f3b4acc8c727dda3b4528a34732701f8d9f07'
    assert not plain._compatible_direct_validator_sources(value, plain.direct_sources())


def test_full_mode_change_in_historical_verifier_is_refused(tmp_path):
    value = selected(17); path = tmp_path / 'historical.py'
    path.write_bytes((FIXTURES / 'rapid_selected_capture_input.py').read_bytes()); path.chmod(0o444)
    value['direct_validator_files'][plain.__name__] = plain.reference(path)
    with pytest.raises(ValueError, match='full mode'):
        plain._compatible_direct_validator_sources(value, plain.direct_sources())


def test_original_ledger_dictionary_is_retained_and_cross_stage_pair_is_refused():
    value = json.loads((FIXTURES / 'b0010-policy-sources.json').read_bytes()); before = deepcopy(value)
    assert perclass._policy_sources(value)
    assert value == before
    value[budget.__name__] = '6283ef9cafac972d9df8696c1c4d0249c920db855f7a83fc8fcd8fce434d079d'
    with pytest.raises(ValueError, match='historical or current'):
        perclass._policy_sources(value)


@pytest.mark.parametrize('stage', ['legacy', 'v3'])
def test_historical_source_recognition_preserves_typed_audit_antirelabel(stage, monkeypatch):
    value = selected(35)
    value['selection_audit'] = {'controlled': 'audit raw boundary only'}
    value['direct_validator_sources'][budget.__name__] = (
        budget.LEGACY_SELECTED_SOURCE_SHA256 if stage == 'legacy' else budget.V3_SELECTED_SOURCE_SHA256)
    monkeypatch.setattr(budget, 'input_metadata', lambda ref: (value, {}))
    monkeypatch.setattr(plain, 'reference', lambda path: {})
    monkeypatch.setattr(plain, 'reopen', lambda ref: Path('/controlled-audit-boundary'))
    monkeypatch.setattr(plain, '_compatible_direct_validator_sources', lambda *args: True)
    monkeypatch.setattr(budget, 'read_audit', lambda path: {'host_authority': {},
        'program_sha256': budget.graph.digest(budget._AUDIT_PROGRAM_V3_SCOPED.encode())})
    with pytest.raises(ValueError, match='cannot claim'):
        budget._validate_input_uncached(Path('/controlled-input-metadata'))


@pytest.mark.parametrize('relative', ['rapid_selected_capture_input.py',
    'rapid_selected_budget_input.py', 'rapid_per_class_selected_enrollment.py', 'whole_graph_supplement.py'])
def test_exact_source43_code_projection_retains_all_unmodified_units(relative):
    assert fixed._compatible_acquisition_code('src/qcsd_lab/' + relative,
        fixed.reference(FIXTURES / relative), fixed.reference(Path(fixed.__file__).parent / relative))


def test_protected_graph_unit_mutation_refused_even_when_identity_boundary_is_controlled(tmp_path, monkeypatch):
    relative = 'src/qcsd_lab/whole_graph_supplement.py'
    path = tmp_path / 'whole_graph_supplement.py'
    raw = Path(whole.__file__).read_bytes()
    assert b'def policies()' in raw
    path.write_bytes(raw.replace(b'def policies()', b'def changed_policies()', 1)); path.chmod(0o644)
    after = fixed.reference(path)
    monkeypatch.setattr(fixed, '_acquisition_reader_sources', lambda: {relative: after})
    with pytest.raises(ValueError, match='protected graph'):
        fixed._compatible_acquisition_code(relative, fixed.reference(FIXTURES / path.name), after)


def test_current_file_mode_mutation_is_refused_by_source_guard(tmp_path, monkeypatch):
    (tmp_path / 'rapid_fixed_condition_target.py').write_bytes(Path(fixed.__file__).read_bytes())
    for path in fixed._acquisition_reader_sources().values():
        destination = tmp_path / Path(path['path']).name
        destination.write_bytes(Path(path['path']).read_bytes()); destination.chmod(path['mode'])
    (tmp_path / 'whole_graph_input.py').chmod(0o444)
    monkeypatch.setattr(fixed, '__file__', str(tmp_path / 'rapid_fixed_condition_target.py'))
    with pytest.raises(ValueError, match='exact prospective Source'):
        fixed._acquisition_reader_sources()


def test_action_final_fence_rejects_current_source_mutation_after_hit(tmp_path, monkeypatch):
    (tmp_path / 'rapid_fixed_condition_target.py').write_bytes(Path(fixed.__file__).read_bytes())
    for path in fixed._acquisition_reader_sources().values():
        destination = tmp_path / Path(path['path']).name
        destination.write_bytes(Path(path['path']).read_bytes()); destination.chmod(path['mode'])
    monkeypatch.setattr(fixed, '__file__', str(tmp_path / 'rapid_fixed_condition_target.py'))
    context = OperationFacts()
    with context.scope():
        fixed._acquisition_reader_sources()
        (tmp_path / 'whole_graph_input.py').write_bytes(b'changed after initial read')
        fixed._acquisition_reader_sources()
        with pytest.raises(ValueError): context.check()


def test_current_whole_get_reader_pair_and_historical_pair_are_exact():
    value = whole.producer_sources(); assert whole._recognized_producer_sources(value)
    historical = {**value,
        'qcsd_lab.whole_graph_input': '4b999d64aa59c7ebc91a2d65f29e091752920891d41539f9f079c99bc7dde583',
        whole.__name__: 'a12ba1de531fd37a4e6ab8abbc8497911ea51d4d45e54d452e3afc927058db66'}
    before = deepcopy(historical); assert whole._recognized_producer_sources(historical)
    assert historical == before
    historical['qcsd_lab.whole_graph_input'] = value['qcsd_lab.whole_graph_input']
    assert not whole._recognized_producer_sources(historical)


def test_fixed_source43_predecessor_projection_retains_protected_scientific_body():
    assert fixed._compatible_code_ref('target', fixed.reference(FIXTURES / 'rapid_fixed_condition_target.py'),
        fixed.reference(Path(fixed.__file__)))
