"""Controlled portable Source transport; these fixtures grant no capture credit."""
import json
from pathlib import Path
import shutil

import pytest

from qcsd_lab import rapid_chunk_partial_lane as reader
from tests.test_rapid_chunk_partial_lane import installed_fixture


def portable_fixture(tmp_path):
    root, canonical, runtime = installed_fixture(tmp_path)
    installed = Path(canonical['path']).parent
    source = installed / 'image-context' / 'source'
    shutil.copytree(installed / 'source', source)
    (source / 'neqo-qcsd' / 'Cargo.lock').chmod(0o664)
    (source / 'qcsd-lab').chmod(0o775)
    runtime.update(runtime_source_root=str(source), module_root=str(source),
                   base_launcher=str(source / 'qcsd-lab'), host_launcher=str(source / 'qcsd-lab'))
    measured_private = root / 'neqo-qcsd' / 'Cargo.lock'
    measured_private.chmod(0o600)
    return root, canonical, runtime, measured_private, source / 'neqo-qcsd' / 'Cargo.lock'


def controlled_reader(tmp_path, monkeypatch):
    root, canonical, runtime, private, installed = portable_fixture(tmp_path)
    monkeypatch.setattr(reader, '_consumer_root', lambda: root)
    authenticated = reader._reader_sources()
    original = reader._compatible_reader_sources

    def compatible(observed):
        if observed != authenticated:
            raise ValueError('controlled reader sources changed')
        original(observed)
        return str(root)

    monkeypatch.setattr(reader, '_compatible_reader_sources', compatible)
    return root, canonical, runtime, private, installed


def test_portable_source_records_both_actual_modes_and_preserves_v1_strictness(tmp_path, monkeypatch):
    root, canonical, runtime, private, installed = controlled_reader(tmp_path, monkeypatch)
    metadata = json.loads(Path(canonical['path']).read_bytes())['source']
    with pytest.raises(ValueError, match='bytes or mode'):
        reader.release_snapshot(root, metadata['lab_commit'], metadata['neqo_commit'])
    release = reader.portable_release_snapshot(root, metadata['lab_commit'], metadata['neqo_commit'],
        runtime['runtime_source_root'])
    name = 'neqo-qcsd/Cargo.lock'
    assert release['files'][name]['mode'] == 0o600
    assert release['mode_pairs'][name] == {'git_mode': '100644', 'observed_mode': 0o600,
                                          'installed_mode': 0o664}
    assert reader.reference(installed)['mode'] == 0o664
    assert release['mode_pairs']['qcsd-lab'] == {'git_mode': '100755', 'observed_mode': 0o755,
                                                'installed_mode': 0o775}
    binding = reader.bind_portable_source(root=root, canonical=canonical, runtime=runtime,
        audit_root=tmp_path / 'portable-audit', output=tmp_path / 'portable-binding.json')
    source = reader._source(binding)
    assert source['root'] == str(root) and source['binding']['runtime']['module_root'] == str(installed.parents[1])
    assert source['installed_files'][name]['mode'] == 0o664
    assert source['binding']['runtime_identity']['client_sha256'] == reader.reference(runtime['client_binary'])['sha256']
    assert reader._PROGRAM is reader.original._PROGRAM


@pytest.mark.parametrize('case', ['nonexec-mode', 'exec-mode', 'measured-bytes', 'untracked-import',
    'runtime-root', 'installed-invalid-mode', 'installed-wrong-exec', 'installed-mode',
    'installed-bytes', 'changed-binding-pair', 'changed-image',
    'changed-launcher-mode', 'changed-client'])
def test_portable_source_refuses_mode_membership_and_runtime_substitution(tmp_path, monkeypatch, case):
    root, canonical, runtime, private, installed = controlled_reader(tmp_path, monkeypatch)
    if case in ('nonexec-mode', 'exec-mode', 'measured-bytes', 'untracked-import', 'runtime-root',
                'installed-invalid-mode', 'installed-wrong-exec'):
        if case == 'nonexec-mode': private.chmod(0o640)
        elif case == 'exec-mode': (root / 'qcsd-lab').chmod(0o700)
        elif case == 'measured-bytes': private.write_text('changed Native bytes\n')
        elif case == 'untracked-import': (root / 'src' / 'unbound.py').write_text('')
        elif case == 'runtime-root': runtime['runtime_source_root'] = str(root)
        elif case == 'installed-invalid-mode': installed.chmod(0o640)
        else: Path(runtime['base_launcher']).chmod(0o664)
        with pytest.raises(ValueError):
            reader.bind_portable_source(root=root, canonical=canonical, runtime=runtime,
                audit_root=tmp_path / 'portable-audit', output=tmp_path / 'portable-binding.json')
        assert not (tmp_path / 'portable-binding.json').exists()
        return
    binding = reader.bind_portable_source(root=root, canonical=canonical, runtime=runtime,
        audit_root=tmp_path / 'portable-audit', output=tmp_path / 'portable-binding.json')
    if case == 'installed-mode': installed.chmod(0o644)
    elif case == 'installed-bytes': installed.write_text('changed installed bytes\n')
    elif case == 'changed-launcher-mode': Path(runtime['base_launcher']).chmod(0o700)
    elif case == 'changed-client': Path(runtime['client_binary']).write_bytes(b'changed client')
    elif case == 'changed-image':
        raw = json.loads(Path(canonical['path']).read_bytes())
        raw['collection_image_digest'] = 'sha256:' + 'e' * 64
        Path(canonical['path']).write_bytes(reader.encoded(raw))
    else:
        payload = reader._document(binding, reader.SOURCE_V2_TYPE)
        payload['release']['mode_pairs']['neqo-qcsd/Cargo.lock']['installed_mode'] = 0o600
        binding = reader._write(tmp_path / 'changed-binding.json', reader.SOURCE_V2_TYPE, payload)
    with pytest.raises(ValueError): reader._source(binding)


def test_portable_source_rechecks_observed_mode_at_publication_fence(tmp_path, monkeypatch):
    root, canonical, runtime, private, _ = controlled_reader(tmp_path, monkeypatch)
    original = reader._run_portable_runtime

    def change_after_runtime(*args, **kwargs):
        value = original(*args, **kwargs)
        private.chmod(0o644)
        return value

    monkeypatch.setattr(reader, '_run_portable_runtime', change_after_runtime)
    with pytest.raises(ValueError, match='release or executing reader changed'):
        reader.bind_portable_source(root=root, canonical=canonical, runtime=runtime,
            audit_root=tmp_path / 'portable-audit', output=tmp_path / 'portable-binding.json')
    assert not (tmp_path / 'portable-binding.json').exists()


def test_portable_source_rechecks_installed_mode_at_publication_fence(tmp_path, monkeypatch):
    root, canonical, runtime, _, installed = controlled_reader(tmp_path, monkeypatch)
    original = reader._run_portable_runtime

    def change_after_runtime(*args, **kwargs):
        value = original(*args, **kwargs)
        installed.chmod(0o644)
        return value

    monkeypatch.setattr(reader, '_run_portable_runtime', change_after_runtime)
    with pytest.raises(ValueError, match='release or executing reader changed'):
        reader.bind_portable_source(root=root, canonical=canonical, runtime=runtime,
            audit_root=tmp_path / 'portable-audit', output=tmp_path / 'portable-binding.json')
    assert not (tmp_path / 'portable-binding.json').exists()


def test_portable_measurement_keeps_original_module_root_identity(tmp_path, monkeypatch):
    root, canonical, runtime, _, _ = controlled_reader(tmp_path, monkeypatch)
    binding = reader.bind_portable_source(root=root, canonical=canonical, runtime=runtime,
        audit_root=tmp_path / 'portable-audit', output=tmp_path / 'portable-binding.json')
    source = reader._source(binding)
    identity = source['binding']['runtime_identity']
    report = {'experiment': {'source': {**identity['source'], 'image_digest': identity['collection_image_digest']}},
        'spec': {'module_root': runtime['module_root'], 'collection_image_digest': identity['collection_image_digest']},
        'intent': {'runtime_identity': {'runtime_source': identity['source'],
            'collection_image_digest': identity['collection_image_digest'], 'client_sha256': identity['client_sha256']}}}
    with pytest.raises(ValueError, match='measurement Source or image'):
        reader._measurement_binding(report, source)
