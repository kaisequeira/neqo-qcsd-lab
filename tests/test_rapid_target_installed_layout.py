"""HOST installed geometry; original canary/GET proof semantics are not replayed.

Each child imports an actual copied package under opt/qcsd-venv/lib/python3.11/
site-packages, with no tools beside that prefix. Executing code, mounted Source,
inventory bytes and full modes are real. Only the genuine ordinary spec's final
semantic check_layout boundary is controlled in the import regression.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


SOURCE = Path(__file__).resolve().parents[1]
WORKSPACE = SOURCE.parents[1]
ACTUAL_SPEC = WORKSPACE / ('diagnostic-rehearsals/'
    'rapid-curated-tranco50-v7-b03-ordinary-current-nativec24-v29-001/plans/g01-spec.json')
ACTUAL_SHA = '731862fcbbeee8c171e075ccdf64a4b5b35c28bf8a520b4195612cae675bb76e'


@pytest.fixture
def installed(tmp_path):
    site = tmp_path / 'opt/qcsd-venv/lib/python3.11/site-packages'
    shutil.copytree(SOURCE / 'src/qcsd_lab', site / 'qcsd_lab',
        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    assert not (site.parent / 'tools').exists()
    return site


def run(installed, body):
    prefix = '''
import json, shutil, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from qcsd_lab import rapid_target_chunks as chunks
from qcsd_lab import rapid_target_parallel_schedule as workers
from qcsd_lab.rapid_operation_facts import OperationFacts
source = Path(sys.argv[2])
root = Path(sys.argv[1]).parents[4]
runtime = {'module_root': str(root/'mounted-module'),
           'runtime_source_root': str(root/'mounted-runtime')}
for mount in runtime.values():
    for relative in workers.CONTROL_FILES:
        path = Path(mount)/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source/relative, path)
blobs = {relative: (Path(runtime['runtime_source_root'])/relative).read_bytes()
         for relative in workers.CONTROL_FILES}
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', prefix + body,
        str(installed), str(SOURCE), str(ACTUAL_SPEC)], cwd=installed.parents[4],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_installed_import_and_genuine_current_ordinary_spec_reach_layout_dispatch(installed):
    assert hashlib.sha256(ACTUAL_SPEC.read_bytes()).hexdigest() == ACTUAL_SHA
    assert ACTUAL_SPEC.stat().st_mode & 0o7777 == 0o600
    # A fresh interpreter reproduces the exact original lanes -> target worker
    # import path; no chunk sources may be opened just to declare its filenames.
    script = '''
import hashlib, importlib, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_target_chunks as chunks
assert 'site-packages' in chunks.__file__
original = chunks.target.reference
chunks.target.reference = lambda *_: (_ for _ in ()).throw(AssertionError('Source read at import'))
importlib.import_module('qcsd_lab.rapid_target_parallel_schedule')
chunks.target.reference = original
try: chunks.sources()
except ValueError as error: assert 'explicitly bound runtime' in str(error)
else: raise AssertionError('installed Source guessed a Lab parent')
p = Path(sys.argv[2]); raw = p.read_bytes()
assert hashlib.sha256(raw).hexdigest() == sys.argv[3]
spec = lanes.CaptureSpec(**{k: Path(v) if k in lanes.PATH_KEYS else v
                           for k, v in json.loads(raw)['inputs'].items()})
from qcsd_lab import rapid_undefended_capture as ordinary
calls = []
def checked(received, inputs):
    assert received == spec and ordinary.is_inputs(inputs)
    assert inputs['mode'] == 'undefended' and len(inputs['sites']) == 5
    assert inputs['capture_limits']['max_attempts'] == 3
    calls.append(received)
ordinary.check_layout = checked
lanes._qualification_layout(spec)
assert calls == [spec]
assert not (Path(chunks.__file__).parents[2]/'tools/rapid_target_chunks.py').exists()
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
        str(installed), str(ACTUAL_SPEC), ACTUAL_SHA], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_installed_chunk_and_worker_sources_bind_explicit_mounts_and_same_host_refs(installed):
    run(installed, '''
with OperationFacts().scope() as context:
    chunk_refs = chunks._checked_sources(runtime, blobs, chunks.CONTROL_FILENAMES)
    assert chunk_refs == chunks.sources(runtime)
    worker_refs = chunks._checked_sources(runtime, blobs, workers.CONTROL_FILES)
    assert set(worker_refs) == set(workers.CONTROL_FILES)
    assert set(chunk_refs) == set(chunks.CONTROL_FILENAMES)
    for relative, ref in worker_refs.items():
        assert ref['path'] == str(Path(runtime['module_root'])/relative)
        if relative.startswith('src/qcsd_lab/'):
            executing = chunks._executing_source_path(relative, runtime)
            assert 'site-packages' in str(executing)
            assert executing in context._files
        else:
            assert chunks._executing_source_path(relative, runtime) == Path(ref['path'])
    context.check()
''')


@pytest.mark.parametrize(('role', 'change'), [
    ('executing-python', 'bytes'), ('executing-python', 'mode'),
    ('runtime-python', 'bytes'), ('runtime-python', 'mode'),
    ('module-tool', 'bytes'), ('module-tool', 'mode'),
    ('runtime-tool', 'bytes'), ('runtime-tool', 'mode'),
    ('installed-inventory', 'bytes'), ('module-tool', 'missing'),
])
def test_installed_source_authority_rejects_each_changed_bytes_mode_or_missing_tool(installed, role, change):
    run(installed, f'''
role, change = {role!r}, {change!r}
relative = 'tools/rapid_target_chunks.py' if 'tool' in role else 'src/qcsd_lab/rapid_target_chunks.py'
if role == 'installed-inventory': blobs[relative] += b' changed'
else:
    path = (chunks._executing_source_path(relative, runtime) if role == 'executing-python'
        else Path(runtime['module_root' if role.startswith('module') else 'runtime_source_root'])/relative)
    if change == 'bytes': path.write_bytes(path.read_bytes()+b'\\n# changed')
    elif change == 'mode': path.chmod((path.stat().st_mode & 0o7777)^0o100)
    else: path.unlink()
try: chunks._checked_sources(runtime, blobs, workers.CONTROL_FILES)
except (ValueError, FileNotFoundError): pass
else: raise AssertionError('changed installed control accepted')
''')


@pytest.mark.parametrize('change', ['bytes', 'mode'])
def test_installed_authority_retains_executing_and_mounted_closing_fences(installed, change):
    run(installed, f'''
with OperationFacts().scope() as context:
    chunks._checked_sources(runtime, blobs, workers.CONTROL_FILES)
    for path in (chunks._executing_source_path('src/qcsd_lab/rapid_target_chunks.py', runtime),
                 Path(runtime['module_root'])/'tools/rapid_target_chunks.py'):
        raw, mode = path.read_bytes(), path.stat().st_mode & 0o7777
        if {change!r} == 'bytes': path.write_bytes(raw+b'\\n# changed after proof')
        else: path.chmod(mode^0o100)
        try: context.check()
        except ValueError: pass
        else: raise AssertionError('closing Source fence did not refuse mutation')
        path.write_bytes(raw); path.chmod(mode)
''')
