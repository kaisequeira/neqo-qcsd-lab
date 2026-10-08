"""Exact Source64/prospective GET reader controls; no network or trace credit."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_supplemental_cohort as cohort
from qcsd_lab import supplied_static_get as get
from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab.rapid_operation_facts import OperationFacts

SOURCE64_WHOLE = '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0'
CURRENT_WHOLE = 'dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98'
SOURCE64_COHORT = 'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d'
CURRENT_COHORT = 'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad'
SOURCE64_FAMILY = {
    'qcsd_lab.whole_graph_input': '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c',
    'qcsd_lab.whole_graph_supplement': SOURCE64_WHOLE,
    'qcsd_lab.rapid_per_class_selected_enrollment': '4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0',
    'qcsd_lab.rapid_supplemental_cohort': SOURCE64_COHORT,
}
SOURCE64_ADDITION = b"    }, {\n        \"qcsd_lab.whole_graph_input\": \"7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c\",\n        \"qcsd_lab.whole_graph_supplement\": \"4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0\",\n        \"qcsd_lab.rapid_per_class_selected_enrollment\": \"4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0\",\n        \"qcsd_lab.rapid_supplemental_cohort\": \"c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d\",\n"


@pytest.fixture
def source64(tmp_path):
    """Build exact old reader bytes, authenticating their published full hashes."""
    directory = tmp_path / 'source64/src/qcsd_lab'
    directory.mkdir(parents=True)
    refs = {}
    for name, current in cohort.reader_sources().items():
        raw = inputs.reopen(current).read_bytes()
        if name == whole.__name__:
            assert hashlib.sha256(raw).hexdigest() == CURRENT_WHOLE
            raw = fixed._required_parent_get_source_projection(raw)
        elif name == cohort.__name__:
            assert hashlib.sha256(raw).hexdigest() == CURRENT_COHORT
            assert raw.count(SOURCE64_ADDITION) == 1
            raw = raw.replace(SOURCE64_ADDITION, b'', 1)
        assert hashlib.sha256(raw).hexdigest() == SOURCE64_FAMILY[name]
        path = directory / (name.rsplit('.', 1)[1] + '.py')
        path.write_bytes(raw)
        path.chmod(0o644)
        refs[name] = inputs.reference(path)
    return refs


def test_exact_source64_whole_reader_bytes_are_recovered(source64):
    current = Path(whole.__file__)
    original = inputs.reopen(source64[whole.__name__])
    assert fixed._required_parent_get_source_projection(current.read_bytes()) == original.read_bytes()
    assert fixed._compatible_acquisition_code('src/qcsd_lab/whole_graph_supplement.py',
        fixed.reference(original), fixed.reference(current))
    assert hashlib.sha256(fixed._v13_supplement_reader_source_projection(current.read_bytes())).hexdigest() == (
        '164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7')


def test_exact_source64_cohort_family_retains_all_original_references(source64):
    before = deepcopy(source64)
    with OperationFacts().scope() as action:
        assert cohort._recognized_reader_sources(source64)
        action.check()
    assert source64 == before
    current = Path(cohort.__file__)
    assert fixed._compatible_acquisition_code('src/qcsd_lab/rapid_supplemental_cohort.py',
        fixed.reference(inputs.reopen(source64[cohort.__name__])), fixed.reference(current))
    assert hashlib.sha256(fixed._v13_cohort_reader_source_projection(current.read_bytes())).hexdigest() == (
        '12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be')


@pytest.mark.parametrize('mutation', ['bytes', 'full-mode', 'mixed-family', 'missing', 'extra'])
def test_source64_cohort_family_refuses_modified_material(source64, mutation):
    refs = deepcopy(source64)
    name = whole.__name__
    path = Path(refs[name]['path'])
    if mutation == 'bytes':
        path.write_bytes(path.read_bytes() + b'\n# changed scientific source\n')
        refs[name] = inputs.reference(path)
    elif mutation == 'full-mode':
        path.chmod(0o4644)
        refs[name] = inputs.reference(path)
    elif mutation == 'mixed-family':
        refs[name] = inputs.reference(Path(whole.__file__))
    elif mutation == 'missing':
        path.unlink()
    else:
        refs['qcsd_lab.unlisted'] = deepcopy(refs[name])
    try:
        accepted = cohort._recognized_reader_sources(refs)
    except (ValueError, OSError):
        return
    assert accepted is False


@pytest.mark.parametrize('mutation', ['bytes', 'full-mode'])
def test_source64_family_final_action_fence_reopens_cached_material(source64, mutation):
    action = OperationFacts()
    action.begin_action()
    with action.scope():
        assert cohort._recognized_reader_sources(source64)
        path = Path(source64[whole.__name__]['path'])
        if mutation == 'bytes':
            path.write_bytes(path.read_bytes() + b'\n# changed after authenticated read\n')
        else:
            path.chmod(0o4644)
        with pytest.raises(ValueError):
            action.check()


@pytest.mark.parametrize('mutation', ['policy-body', 'declaration-body', 'extra-unit'])
def test_required_parent_projection_refuses_changed_producer_bytes(mutation):
    raw = Path(whole.__file__).read_bytes()
    if mutation == 'policy-body':
        original = b'row["known_valid"] = not terminal_http_error_resource_allowed(row, resources)'
        assert raw.count(original) == 1
        raw = raw.replace(original, b'row["known_valid"] = True', 1)
    elif mutation == 'declaration-body':
        original = b'declaration = {"schema_version": 2, "record_type": PROOF_TYPE,'
        assert raw.count(original) == 1
        raw = raw.replace(original, b'declaration = {"schema_version": 1, "record_type": PROOF_TYPE,', 1)
    else:
        raw += b'\ndef unlisted_scientific_guard():\n    return True\n'
    with pytest.raises(ValueError):
        fixed._required_parent_get_source_projection(raw)


def test_saved_source64_argument_failure_keeps_legacy_probe_and_zero_credit():
    root_value = os.environ.get('QCSD_SOURCE64_FAILED_GET_ROOT')
    context_value = os.environ.get('QCSD_SOURCE64_COHORT_PATH')
    if root_value is None or context_value is None:
        pytest.skip('requires Root-saved authentic Source64 GET failure and cohort references')
    root = Path(root_value)
    context_root = Path(context_value)
    assert root.is_absolute() and context_root.is_absolute()
    declaration_path = root / 'declaration.json'
    assert declaration_path.stat().st_mode & 0o7777 == 0o444
    assert hashlib.sha256(declaration_path.read_bytes()).hexdigest() == (
        '6029563f9ba7ed9af43f557d900a0013cf7d8ca832d136661c3852f02639473b')
    declaration = get._load(declaration_path.read_bytes())
    assert type(declaration['schema_version']) is int and declaration['schema_version'] == 1
    assert 'manifest_policy' not in declaration
    assert declaration['producer_sources'][whole.__name__] == SOURCE64_WHOLE
    full = get._load((root / 'native-input.json').read_bytes())
    assert len(full['resources']) == 137 and full['resources'][2]['known_valid'] is False
    completed = get._load((root / 'native-completed.json').read_bytes())
    assert completed['returncode'] == 1 and completed['timed_out'] is False
    with OperationFacts().scope() as action:
        context = whole.load_context(context_root)
        proof = whole.failure_proof(root, context=context, position=2)
        action.check()
    assert proof['phase'] == 'full' and proof['outcome'] == 'operational-deferred'
    assert proof['scientific_credit'] is False and proof['formal_accepted_trace_count'] == 0
