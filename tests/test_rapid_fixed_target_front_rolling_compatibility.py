"""Exact future FRONT planning bytes preserve original F264 enrollment authority.

The optional saved-reader control uses authenticated historical bytes only.
The membership boundary controls isolate already-validated outer Source authority;
the real rolling comparison, full modes, data refs and normalization execute.
"""
import hashlib
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed

CURRENT = '6f5fc34f6d8ee14390378200d2ebba55d4de9fc205d6788453c960739f138881'
ORIGINAL = '23e64994de9127aad06e952dae996d7e7b24fd5d44e5c5877eb658d845d64e9b'
PROJECTED = '080b519e94e2b7b2ec6ff47daf45e4779f1d544877ff5c47735377d2d3ed10c1'


def current_bytes():
    raw = Path(fixed.__file__).with_name('rapid_rolling_capture.py').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CURRENT
    return raw


def test_registered_front_planner_retains_original_membership_units():
    assert hashlib.sha256(fixed._epoch_dispatch_source_projection(current_bytes())).hexdigest() == PROJECTED


@pytest.mark.parametrize('before,after', [
    (b'source["neqo_commit"] != source["neqo_pinned_commit"]', b'False'),
    (b'        if (facts.get("client_sha256") != lanes._sha(lanes._read(spec.client_binary))\n', b'        if (False\n'),
    (b'value, classes, policy = per_class.verify_enrollment(path)', b'value, classes, policy = ({}, [], {})'),
    (b'front.policy(facts) != front.policy(payload)', b'False'),
    (b'receipt=e.complete_lane(spec,root,target) if value[\'complete\'] else target', b'receipt=target'),
])
def test_future_front_inverse_refuses_native_client_graph_policy_and_deep_mutations(before, after):
    raw = current_bytes()
    assert raw.count(before) == 1
    changed = raw.replace(before, after, 1)
    assert changed != raw
    with pytest.raises(ValueError, match='outside the exact published Source pair'):
        fixed._epoch_dispatch_source_projection(changed)


@pytest.fixture
def historical_bytes():
    value = os.environ.get('QCSD_ORIGINAL_F264_ROLLING_PATH')
    if not value:
        pytest.skip('set QCSD_ORIGINAL_F264_ROLLING_PATH to the authenticated original Source36 rolling reader')
    path = Path(value)
    assert path.is_absolute() and not path.is_symlink()
    assert path.stat().st_mode & 0o7777 == 0o644
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ORIGINAL
    return raw


def membership_case(tmp_path, monkeypatch, historical_bytes):
    def put(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
        return fixed.reference(path)

    old = tmp_path / 'original' / 'src' / 'qcsd_lab'
    new = tmp_path / 'current' / 'src' / 'qcsd_lab'
    before = put(old / 'rapid_rolling_capture.py', historical_bytes)
    after = put(new / 'rapid_rolling_capture.py', current_bytes())
    old_target = put(old / 'rapid_fixed_condition_target.py', b'# controlled original Source locator\n')
    new_target = put(new / 'rapid_fixed_condition_target.py', b'# controlled current Source locator\n')
    data = put(tmp_path / 'original-full-graph.json', b'{"resources":[{"url":"https://example.test/","body_sha256":"original"}]}\n')
    producer = {'files': [before, data], 'trees': []}
    current = {'files': [after, data], 'trees': []}
    sources = {'target': old_target}
    monkeypatch.setattr(fixed, '_sources', lambda: {'target': new_target})
    monkeypatch.setattr(fixed, '_compatible_sources', lambda _sources: True)
    monkeypatch.setattr(fixed, '_acquisition_reader_sources', lambda: {})
    return producer, current, sources, new


def test_saved_original_membership_uses_finite_front_epoch_route(tmp_path, monkeypatch, historical_bytes):
    producer, current, sources, _new = membership_case(tmp_path, monkeypatch, historical_bytes)
    assert fixed._compatible_membership(producer, current, sources)


@pytest.mark.parametrize('change', ['full-mode', 'protected-source', 'original-full-graph'])
def test_membership_route_refuses_mode_source_and_raw_graph_substitution(change, tmp_path, monkeypatch, historical_bytes):
    producer, current, sources, new = membership_case(tmp_path, monkeypatch, historical_bytes)
    if change == 'full-mode':
        path = new / 'rapid_rolling_capture.py'
        path.chmod(0o600)
        current['files'][0] = fixed.reference(path)
    elif change == 'protected-source':
        path = new / 'rapid_rolling_capture.py'
        raw = path.read_bytes()
        before = b'source["neqo_commit"] != source["neqo_pinned_commit"]'
        assert raw.count(before) == 1
        path.write_bytes(raw.replace(before, b'False', 1))
        current['files'][0] = fixed.reference(path)
    else:
        path = tmp_path / 'substituted-full-graph.json'
        path.write_bytes(b'{"resources":[]}\n')
        path.chmod(0o644)
        current['files'][1] = fixed.reference(path)
    assert not fixed._compatible_membership(producer, current, sources)
