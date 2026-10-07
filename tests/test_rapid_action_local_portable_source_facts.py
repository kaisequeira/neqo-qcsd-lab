"""Portable V2 memo controls retain authentic Git/installed closures.

The installed fixture has explicitly controlled runtime provenance and grants
no capture credit. The original V2 binding reader, real paired Git release,
recorded isolated runtime operation and OperationFacts fences all remain live.
"""
from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_action_local_source_facts as memo
from qcsd_lab import rapid_chunk_partial_lane as dynamic
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_rapid_action_local_source_facts import source_case
from tests.test_rapid_chunk_portable_source import controlled_reader


@pytest.fixture
def portable_case(tmp_path, monkeypatch):
    root, canonical, runtime, private, installed = controlled_reader(tmp_path, monkeypatch)
    installed_root = Path(runtime['runtime_source_root'])
    # Empty tools trees are part of this fixture's Source import boundary.
    (root / 'tools').mkdir()
    (installed_root / 'tools').mkdir()
    ref = dynamic.bind_portable_source(root=root, canonical=canonical, runtime=runtime,
        audit_root=tmp_path / 'portable-audit', output=tmp_path / 'portable-binding.json')
    original = dynamic._source
    calls = []

    def counted(reference):
        result = original(reference)
        calls.append(reference)
        return result

    monkeypatch.setattr(dynamic, '_source', counted)
    return root, installed_root, private, installed, ref, calls


def test_scoped_v2_memo_preserves_both_modes_and_full_release(portable_case):
    root, installed_root, private, installed, ref, calls = portable_case
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        first = target._measurement_source(ref)
        assert set(first) == {'root', 'lab_head', 'native_head', 'files',
                              'installed_files', 'mode_pairs', 'binding'}
        assert first['root'] == str(root)
        release = {key: value for key, value in first.items() if key != 'binding'}
        assert release == first['binding']['release']
        assert release == dynamic.portable_release_snapshot(root, first['lab_head'],
            first['native_head'], installed_root)
        assert private.stat().st_mode & 0o7777 == 0o600
        assert installed.stat().st_mode & 0o7777 == 0o664
        assert first['mode_pairs']['neqo-qcsd/Cargo.lock'] == {
            'git_mode': '100644', 'observed_mode': 0o600, 'installed_mode': 0o664}
        first['installed_files'].clear()
        first['mode_pairs'].clear()
        second = target._measurement_source(ref)
        assert second['installed_files'] and second['mode_pairs'] and len(calls) == 1
        assert all(Path(row['path']) in facts._files
                   for row in second['installed_files'].values())
        assert (installed_root / 'src', False) in facts._trees
        assert (installed_root / 'tools', False) in facts._trees
        assert (root / '.git', False) in facts._trees
        assert (root / 'neqo-qcsd/.git', False) in facts._trees
        facts.check()


@pytest.mark.parametrize('mutation', [
    'installed-bytes', 'installed-mode', 'measured-mode', 'installed-member',
    'measured-member', 'git-head', 'git-index', 'runtime-raw', 'runtime-operation',
])
def test_v2_memo_hit_cannot_hide_file_mode_git_membership_or_raw_mutation(portable_case, mutation):
    root, installed_root, private, installed, ref, calls = portable_case
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        target._measurement_source(ref); source = target._measurement_source(ref)
        if mutation == 'installed-bytes': installed.write_text('changed installed Native bytes\n')
        elif mutation == 'installed-mode': installed.chmod(0o644)
        elif mutation == 'measured-mode': private.chmod(0o644)
        elif mutation == 'installed-member': (installed_root / 'src/unbound.py').write_text('pass\n')
        elif mutation == 'measured-member': (root / 'src/unbound.py').write_text('pass\n')
        elif mutation == 'git-head': (root / '.git/HEAD').write_text('0' * 40 + '\n')
        elif mutation == 'git-index': (root / '.git/index').write_bytes(b'changed public index')
        elif mutation == 'runtime-raw':
            raw = Path(source['binding']['canonical']['path']).parent / 'dependency.json'
            assert raw in facts._files
            raw.write_text('changed original runtime dependency\n')
        else:
            raw = Path(source['binding']['runtime_operation']['started.json']['path'])
            assert raw in facts._files
            raw.write_text('changed original runtime operation\n')
        with pytest.raises(ValueError): facts.check()
    assert len(calls) == 1


@pytest.mark.parametrize('mutation', ['permission-pair', 'release-alias', 'installed-root'])
def test_v2_registration_rechecks_authenticated_permission_pairs_aliases_and_runtime_root(
        portable_case, monkeypatch, mutation):
    root, installed_root, private, installed, ref, calls = portable_case
    original = dynamic._source

    def changed_after_authentication(reference):
        source = deepcopy(original(reference))
        source['binding']['release'] = deepcopy(source['binding']['release'])
        if mutation == 'permission-pair':
            source['mode_pairs']['neqo-qcsd/Cargo.lock']['installed_mode'] = 0o600
            source['binding']['release']['mode_pairs']['neqo-qcsd/Cargo.lock']['installed_mode'] = 0o600
        elif mutation == 'release-alias':
            source['binding']['release']['installed_files']['neqo-qcsd/Cargo.lock']['path'] = str(private)
        else:
            source['binding']['runtime']['runtime_source_root'] = str(root)
        return source

    monkeypatch.setattr(dynamic, '_source', changed_after_authentication)
    facts = OperationFacts(); facts.begin_action()
    with facts.scope(), pytest.raises(ValueError):
        target._measurement_source(ref)
    assert len(calls) == 1


def test_v2_registration_reopens_installed_mode_between_reader_and_memo(portable_case, monkeypatch):
    root, installed_root, private, installed, ref, calls = portable_case
    original = dynamic._source

    def change_after_reader(reference):
        source = original(reference)
        installed.chmod(0o644)
        return source

    monkeypatch.setattr(dynamic, '_source', change_after_reader)
    facts = OperationFacts(); facts.begin_action()
    with facts.scope(), pytest.raises(ValueError):
        target._measurement_source(ref)
    assert len(calls) == 1


def test_v1_memo_keeps_original_strict_git_mode_requirement(source_case):
    root, runtime, raw, ref, calls = source_case
    (root / 'neqo-qcsd/Cargo.lock').chmod(0o600)
    facts = OperationFacts(); facts.begin_action()
    with facts.scope(), pytest.raises(ValueError, match='bytes or mode'):
        target._measurement_source(ref)
    assert not calls


def test_target_memo_pin_is_exact_and_only_two_reviewed_pins_project(monkeypatch):
    raw = Path(target.__file__).read_bytes()
    current = target._ACTION_LOCAL_SOURCE_FACTS_SHA256.encode()
    previous = b'34586599ad4eeeb1f765eb5ff7ca0d36559be2ef0a7d7521eff0fc7a681e4c0c'
    marker = b"_ACTION_LOCAL_SOURCE_FACTS_SHA256 = '" + current + b"'"
    assert raw.count(marker) == 1
    old = raw.replace(marker, b"_ACTION_LOCAL_SOURCE_FACTS_SHA256 = '" + previous + b"'", 1)
    assert target._reader_code_projection(old, 'target') == target._reader_code_projection(raw, 'target')
    unknown = raw.replace(marker, b"_ACTION_LOCAL_SOURCE_FACTS_SHA256 = '" + b'0' * 64 + b"'", 1)
    with pytest.raises(ValueError, match='reviewed Source'):
        target._reader_code_projection(unknown, 'target')
    monkeypatch.setattr(target, '_ACTION_LOCAL_SOURCE_FACTS_SHA256', '0' * 64)

    @memo.selection
    def selector(reference):
        raise AssertionError('unreviewed helper must refuse before validation')

    facts = OperationFacts(); facts.begin_action()
    with facts.scope(), pytest.raises(ValueError, match='reviewed bytes'):
        selector(None)


def test_genuine_saved_v2_binding_reopens_under_owned_source_memo():
    name = os.environ.get('QCSD_PORTABLE_V2_SOURCE_BINDING_PATH')
    if not name:
        pytest.skip('set QCSD_PORTABLE_V2_SOURCE_BINDING_PATH to an actual original V2 binding')
    ref = target.reference(Path(name))
    assert json.loads(Path(name).read_bytes())['artifact_type'] == dynamic.SOURCE_V2_TYPE
    @target._owned
    def reopen():
        source = target._measurement_source(ref)
        release = {key: source[key] for key in ('root', 'lab_head', 'native_head',
                                               'files', 'installed_files', 'mode_pairs')}
        assert release == source['binding']['release']
        assert source == target._measurement_source(ref)
        return source

    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        reopen()
        facts.check()
