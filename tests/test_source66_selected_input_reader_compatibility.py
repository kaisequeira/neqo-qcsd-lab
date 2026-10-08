"""Finite selected-input reader registration; no GET or capture credit."""
import base64
import hashlib
import json
from pathlib import Path
import zlib

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab.rapid_operation_facts import OperationFacts

RELATIVE = 'src/qcsd_lab/rapid_selected_capture_input.py'
SOURCE65 = 'ba8caa645d219a52eb1e177285bb7e9f9198a1b59c46fdb37692f95206230442'
CURRENT = '72933db93fef22fd599dce35b2ae27dd2f525b112bc6140134540d1f1cad1fb1'
FIXTURES = Path(__file__).parent / 'fixtures'


@pytest.fixture
def source65(tmp_path):
    current = Path(selected.__file__)
    assert current.stat().st_mode & 0o7777 == 0o644
    assert hashlib.sha256(current.read_bytes()).hexdigest() == CURRENT
    raw = fixed._source65_selected_input_source_projection(current.read_bytes())
    assert hashlib.sha256(raw).hexdigest() == SOURCE65
    path = tmp_path / 'source65/src/qcsd_lab/rapid_selected_capture_input.py'
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    path.chmod(0o644)
    return path


def test_exact_source65_selected_bytes_and_membership_route_are_retained(source65):
    current = Path(selected.__file__)
    raw = source65.read_bytes()
    assert fixed._source65_selected_input_source_projection(current.read_bytes()) == raw
    assert fixed._source65_selected_input_source_projection(raw) == raw
    assert fixed._cohort_acquisition_source_projection(current.read_bytes(), RELATIVE) == raw
    before, after = fixed.reference(source65), fixed.reference(current)
    assert fixed._compatible_acquisition_code(RELATIVE, before, after)
    assert fixed._compatible_selected_membership_code(RELATIVE, before, after)


@pytest.mark.parametrize('version', ['source43', 'source44'])
def test_earlier_selected_reader_science_is_preserved(tmp_path, version):
    if version == 'source43':
        raw = (FIXTURES / 'v9_reader_predecessors/rapid_selected_capture_input.py').read_bytes()
        expected = 'ef14e839e0c1ab1b1540a9b8c024f0e8545c1a3cf5478deec30a500134aff337'
    else:
        item = json.loads((FIXTURES / 'supplemental_cohort_source44_readers.json').read_bytes())[
            'files']['rapid_selected_capture_input.py']
        assert item['mode'] == 0o644
        raw = zlib.decompress(base64.b64decode(item['zlib_base64']))
        assert len(raw) == item['size_bytes']
        expected = 'f12460f830c4f4ba7a2d5c5600be59c7fd9800ee0d974692b24bba84ed356308'
        assert item['sha256'] == expected
    assert hashlib.sha256(raw).hexdigest() == expected
    path = tmp_path / version / 'rapid_selected_capture_input.py'
    path.parent.mkdir()
    path.write_bytes(raw)
    path.chmod(0o644)
    assert fixed._compatible_acquisition_code(RELATIVE,
        fixed.reference(path), fixed.reference(Path(selected.__file__)))


@pytest.mark.parametrize('mutation', [
    'before-bytes', 'before-resealed-body', 'before-full-mode', 'before-missing',
    'before-link', 'after-resealed-body', 'after-full-mode',
])
def test_selected_reader_registration_refuses_changed_material(source65, tmp_path, mutation):
    before = fixed.reference(source65)
    after = fixed.reference(Path(selected.__file__))
    assert fixed._compatible_acquisition_code(RELATIVE, before, after)
    if mutation == 'before-bytes':
        source65.write_bytes(source65.read_bytes() + b'\n# changed after reference\n')
    elif mutation == 'before-resealed-body':
        source65.write_bytes(source65.read_bytes() + b'\ndef unreviewed_science():\n    return True\n')
        before = fixed.reference(source65)
    elif mutation == 'before-full-mode':
        source65.chmod(0o4644)
        before = fixed.reference(source65)
    elif mutation == 'before-missing':
        source65.unlink()
    elif mutation == 'before-link':
        original = source65.with_suffix('.retained')
        source65.rename(original)
        source65.symlink_to(original)
    else:
        path = tmp_path / 'changed-current.py'
        path.write_bytes(Path(selected.__file__).read_bytes())
        path.chmod(0o644)
        if mutation == 'after-resealed-body':
            path.write_bytes(path.read_bytes() + b'\ndef unreviewed_science():\n    return True\n')
        else:
            path.chmod(0o4644)
        after = fixed.reference(path)
    with pytest.raises((ValueError, OSError)):
        fixed._compatible_acquisition_code(RELATIVE, before, after)


@pytest.mark.parametrize('mutation', ['bytes', 'full-mode'])
def test_selected_reader_final_action_fence_reopens_original_material(source65, mutation):
    action = OperationFacts()
    action.begin_action()
    with action.scope():
        assert fixed._compatible_acquisition_code(RELATIVE,
            fixed.reference(source65), fixed.reference(Path(selected.__file__)))
        if mutation == 'bytes':
            source65.write_bytes(source65.read_bytes() + b'\n# changed after authenticated read\n')
        else:
            source65.chmod(0o4644)
        with pytest.raises(ValueError):
            action.check()


@pytest.mark.parametrize('mutation', ['typed-policy', 'raw-proof-join', 'extra-unit'])
def test_selected_projection_refuses_unreviewed_current_bytes(mutation):
    raw = Path(selected.__file__).read_bytes()
    if mutation == 'typed-policy':
        old = b'policy = whole._declaration_manifest_policy(declaration)'
        assert raw.count(old) == 1
        raw = raw.replace(old, b'policy = whole.REQUIRED_PARENT_MANIFEST_POLICY', 1)
    elif mutation == 'raw-proof-join':
        old = b'primary, full = _selected_get_manifests(value, declaration, neutral)'
        assert raw.count(old) == 1
        raw = raw.replace(old, b'primary, full = whole._manifests(neutral)', 1)
    else:
        raw += b'\ndef unreviewed_science():\n    return True\n'
    with pytest.raises(ValueError, match='exact Source65/66 pair'):
        fixed._source65_selected_input_source_projection(raw)
