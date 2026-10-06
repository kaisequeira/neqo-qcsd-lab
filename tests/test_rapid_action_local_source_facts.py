"""Action-local reuse controls; no installed or scientific authority is mocked.

The original installed reader is controlled at its unchanged boundary. A real
paired Git release, raw runtime file, membership and all closing fences remain
live so memo hits cannot hide mutations or grant an image/trace pass.
"""
from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import zlib

import pytest

from qcsd_lab import rapid_action_local_source_facts as memo
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_chunk_partial_lane as dynamic
from qcsd_lab.rapid_operation_facts import OperationFacts


ROOT = Path(__file__).resolve().parents[1]


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)


def commit(root):
    git(root, 'add', '-A')
    git(root, '-c', 'user.name=HOST fixture', '-c', 'user.email=fixture@example.invalid',
        'commit', '-qm', 'controlled release')
    return git(root, 'rev-parse', 'HEAD').decode().strip()


@pytest.fixture
def source_case(tmp_path, monkeypatch):
    root = tmp_path / 'release'; root.mkdir()
    git(root, 'init', '-q')
    for name in ('src/qcsd_lab', 'tools', 'neqo-qcsd'):
        (root / name).mkdir(parents=True)
    (root / 'src/qcsd_lab/__init__.py').write_text('# controlled Source\n')
    (root / 'tools/check.py').write_text('pass\n')
    (root / 'qcsd-lab').write_text('# controlled launcher\n')
    native = root / 'neqo-qcsd'; git(native, 'init', '-q')
    (native / 'Cargo.lock').write_text('# controlled Native\n')
    (root / '.gitmodules').write_text('[submodule "neqo-qcsd"]\n\tpath = neqo-qcsd\n\turl = ./neqo-qcsd\n')
    native_head = commit(native); lab_head = commit(root)
    release = dynamic.release_snapshot(root, lab_head, native_head)
    runtime = tmp_path / 'runtime'; runtime.mkdir()
    raw = runtime / 'installation.json'; raw.write_text('{"scientific_credit": false}\n')
    reference = target.reference(raw)
    operations = {}
    for name in ('started.json', 'completed.json', 'stdout.log', 'stderr.log'):
        path = tmp_path / name; path.write_text('{"controlled_record": true}\n')
        operations[name] = target.reference(path)
    directory = target.epoch._directory(runtime)
    binding = {'release': release, 'read_dependencies': [reference],
               'directory_dependencies': [directory], 'runtime_operation': operations,
               'canonical': reference, 'reader_sources': {}}
    source = {**release, 'binding': binding}
    binding_path = tmp_path / 'binding.json'
    binding_path.write_text(json.dumps({'artifact_type': dynamic.SOURCE_TYPE}))
    bound = target.reference(binding_path); calls = []

    def original_boundary(ref):
        target._open(ref)
        assert dynamic.release_snapshot(root, lab_head, native_head) == release
        dynamic.original._close_dependencies(binding)
        calls.append(ref)
        return deepcopy(source)

    monkeypatch.setattr(dynamic, '_source', original_boundary)
    return root, runtime, raw, bound, calls


def test_source_validates_once_returns_independent_results_and_closes(source_case):
    root, runtime, raw, ref, calls = source_case
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        first = target._measurement_source(ref)
        first['files'].clear()
        second = target._measurement_source(ref)
        assert second['files'] and len(calls) == 1
        assert raw.absolute() in facts._files
        assert (root / '.git', False) in facts._trees
        assert (root / 'neqo-qcsd/.git', False) in facts._trees
        facts.check()


def test_source_memo_never_crosses_actions_or_contexts(source_case):
    *_, ref, calls = source_case
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        target._measurement_source(ref); target._measurement_source(ref)
        facts.check(); facts.begin_action(); target._measurement_source(ref)
    other = OperationFacts(); other.begin_action()
    with other.scope():
        target._measurement_source(ref); other.check()
    assert len(calls) == 3


@pytest.mark.parametrize('field', ['sha256', 'mode'])
def test_changed_binding_identity_cannot_hit_previous_memo(source_case, field):
    *_, ref, calls = source_case
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        target._measurement_source(ref)
        wrong = {**ref, field: '0' * 64 if field == 'sha256' else ref['mode'] ^ 0o100}
        with pytest.raises(ValueError): target._measurement_source(wrong)
    assert len(calls) == 1


@pytest.mark.parametrize('mutation', ['source', 'source-mode', 'runtime', 'runtime-mode',
                                      'import-member', 'git-head', 'git-index', 'directory-mode'])
def test_mutation_after_memo_hit_is_refused_by_unchanged_fence(source_case, mutation):
    root, runtime, raw, ref, calls = source_case
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        target._measurement_source(ref); target._measurement_source(ref)
        if mutation == 'source': (root / 'qcsd-lab').write_text('changed Source\n')
        elif mutation == 'source-mode': (root / 'qcsd-lab').chmod(0o600)
        elif mutation == 'runtime': raw.write_text('changed runtime\n')
        elif mutation == 'runtime-mode': raw.chmod(0o600)
        elif mutation == 'import-member': (root / 'src/qcsd_lab/unbound.py').write_text('pass\n')
        elif mutation == 'git-head': (root / '.git/HEAD').write_text('0' * 40 + '\n')
        elif mutation == 'git-index': (root / '.git/index').write_bytes(b'changed index')
        elif mutation == 'directory-mode': runtime.chmod(0o700)
        with pytest.raises(ValueError): facts.check()
    assert len(calls) == 1


def test_cached_source_retains_symlink_refusal(source_case):
    root, runtime, raw, ref, calls = source_case
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        target._measurement_source(ref)
        raw.unlink(); raw.symlink_to(root / 'qcsd-lab')
        with pytest.raises(ValueError): facts.check()


def test_recorded_runtime_operation_outside_read_set_is_still_fenced(source_case):
    root, runtime, raw, ref, calls = source_case
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        target._measurement_source(ref); target._measurement_source(ref)
        started = root.parent / 'started.json'
        assert started in facts._files
        started.write_text('changed original runtime operation\n')
        with pytest.raises(ValueError): facts.check()


def test_original_submodule_gitfile_cannot_retarget_memoized_source(source_case):
    root, runtime, raw, ref, calls = source_case
    git(root, 'submodule', 'absorbgitdirs')
    gitfile = root / 'neqo-qcsd/.git'
    assert gitfile.is_file()
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        target._measurement_source(ref); target._measurement_source(ref)
        assert gitfile in facts._files
        gitfile.write_text('gitdir: /unbound/git/metadata\n')
        with pytest.raises(ValueError): facts.check()


def test_reader_identity_is_part_of_memo_key_and_fence(source_case, tmp_path, monkeypatch):
    *_, ref, calls = source_case
    original = target._sources
    readers = tmp_path / 'reader.py'; readers.write_text('pass\n')
    monkeypatch.setattr(target, '_sources', lambda: {**original(), 'controlled-reader': target.reference(readers)})
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        target._measurement_source(ref)
        readers.write_text('raise RuntimeError()\n')
        target._measurement_source(ref)
        with pytest.raises(ValueError): facts.check()
    assert len(calls) == 1


def test_recursive_selector_is_once_per_exact_ref_and_keeps_all_dependencies(tmp_path):
    refs = []
    for index in range(4):
        p = tmp_path / f'{index}.json'; p.write_text(str(index))
        refs.append(target.reference(p))
    calls = []

    @memo.selection
    def selector(ref):
        calls.append(ref)
        target._open(ref)
        for member in refs: target._open(member)
        return [ref, *refs]

    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        assert selector(refs[0]) == selector(refs[0])
        selector(refs[1])
        assert len(calls) == 2 and all(Path(r['path']) in facts._files for r in refs)
        refs[3]['mode'] ^= 0o100
        # Mutation of the returned ref cannot change the remembered authority.
        assert selector(refs[0])[-1]['mode'] != refs[3]['mode']
        (tmp_path / '3.json').write_text('changed bytes')
        with pytest.raises(ValueError): facts.check()


def test_exact_source40_reader_projection_and_protected_body_refusal(tmp_path):
    # Exact published predecessor bytes, carried with the tests so an ordinary
    # fresh/shallow checkout needs neither the private workspace nor Git history.
    fixture = ROOT / 'tests/fixtures/rapid_fixed_condition_target_source40.py.zlib.b85.txt'
    predecessor = zlib.decompress(base64.b85decode(b''.join(fixture.read_bytes().split())))
    assert hashlib.sha256(predecessor).hexdigest() == '5efeb8f9bdce65d4eb43e781e6388ac84a83453378812d456dc40862bd955b36'
    old_path = tmp_path / 'published-source40-target.py'
    old_path.write_bytes(predecessor); old_path.chmod(0o644)
    old = target.reference(old_path)
    current = target.reference(Path(target.__file__))
    assert target._compatible_code_ref('target', old, current)
    raw = Path(target.__file__).read_bytes()
    changed = tmp_path / 'changed.py'
    changed.write_bytes(raw.replace(b'files[ref[\'path\']]=ref;_open(ref)',
                                   b'files[ref[\'path\']]=ref;pass', 1))
    assert changed.read_bytes() != raw
    with pytest.raises(ValueError): target._compatible_code_ref('target', old, target.reference(changed))


def test_current_control_map_requires_reviewed_memo_helper():
    from qcsd_lab import rapid_target_chunks as chunks
    relative = 'src/qcsd_lab/rapid_action_local_source_facts.py'
    assert relative in chunks.CONTROL_FILENAMES
    assert chunks._executing_source_path(relative, {'module_root': str(ROOT)}) == Path(memo.__file__)
