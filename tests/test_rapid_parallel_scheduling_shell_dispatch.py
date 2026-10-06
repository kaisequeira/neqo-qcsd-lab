"""Exercise the launcher's actual scheduling transport before Docker starts."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FLAT_FAMILIES = (
    "qcsd-rapid-v6-prospective-parallel-scheduling",
    "qcsd-rapid-v6-current-static-parallel-scheduling",
    "qcsd-rapid-v6-current-selected-parallel-scheduling",
    "qcsd-rapid-v6-current-ordinary-parallel-scheduling-v1",
    "qcsd-current-fixed-condition-target-parallel-scheduling-v1",
    "qcsd-per-mode-native-epoch-target-parallel-scheduling-v1",
    "qcsd-rapid-v6-current-original-static-parallel-scheduling",
)


def _actual_branch() -> str:
    source = (ROOT / "qcsd-lab").read_text()
    start = source.index('    rapid_scheduling_kind="$(/usr/bin/python3 -I -c')
    end = source.index("    mapfile -t rapid_compatibility_mounts", start)
    return source[start:end]


def _run_branch(capsule: Path, execution: Path, image: str) -> subprocess.CompletedProcess[str]:
    script = "\n".join((
        "set -euo pipefail",
        "rapid_compatibility_host=" + shlex.quote(str(capsule)),
        "parallel_host_python=" + shlex.quote(sys.executable),
        "ROOT=" + shlex.quote(str(execution)),
        "image_id=" + shlex.quote(image),
        "QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION=",
        _actual_branch(),
        'printf "%s\\n" "$rapid_compatibility_rows"',
    ))
    return subprocess.run(["/bin/bash", "-c", script], text=True,
                          capture_output=True, timeout=20, check=False)


def _fake_installed_reader(root: Path, *, drift=None, phase="mount") -> Path:
    """Control only the scientific reader; execute the real shell and Python bridge."""
    module_root = root / "module"
    package = module_root / "src/qcsd_lab"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    # The action scope and its raw-byte/full-mode/membership fences are real.
    # Only scientific schedule derivation is controlled, granting no authority.
    (package / "rapid_operation_facts.py").write_bytes(
        (ROOT / "src/qcsd_lab/rapid_operation_facts.py").read_bytes())
    dependency = root / "immutable"
    dependency.mkdir()
    (dependency / "control.py").write_bytes(b"unchanged bound reader\n")
    (dependency / "control.py").chmod(0o644)
    (package / "rapid_rolling_capture.py").write_text(
        "import hashlib\n"
        "def _ref(path): return {'path': str(path), "
        "'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}\n")
    (package / "rapid_rolling_schedule.py").write_text(
        "import json\nfrom pathlib import Path\n"
        "from .rapid_operation_facts import current_context\n"
        f"DEPENDENCY = Path({str(dependency)!r})\n"
        f"EVENTS = Path({str(root / 'reader-events.jsonl')!r})\n"
        f"DRIFT = {drift!r}\nPHASE = {phase!r}\n"
        "def event(kind, context, ref, **values):\n"
        "    with EVENTS.open('a') as handle:\n"
        "        handle.write(json.dumps(dict(kind=kind, context=id(context), ref=ref, **values))+'\\n')\n"
        "def mutate(ref):\n"
        "    control = DEPENDENCY/'control.py'\n"
        "    if DRIFT == 'bytes': control.write_bytes(b'changed bound reader\\n')\n"
        "    elif DRIFT == 'full-mode': control.chmod(0o664)\n"
        "    elif DRIFT == 'directory-mode': DEPENDENCY.chmod(DEPENDENCY.stat().st_mode ^ 0o020)\n"
        "    elif DRIFT == 'tree-membership': (DEPENDENCY/'new-empty-directory').mkdir()\n"
        "    elif DRIFT == 'capsule-bytes':\n"
        "        path = Path(ref['path']); path.write_bytes(path.read_bytes()+b' ')\n"
        "def validate_schedule(ref, *, _context=None):\n"
        "    assert _context is not None and _context is current_context()\n"
        "    raw = _context.watch_file(Path(ref['path']))\n"
        "    _context.watch_file(DEPENDENCY/'control.py'); _context.watch_tree(DEPENDENCY)\n"
        "    key = ('controlled-schedule', ref['path'], ref['sha256'])\n"
        "    hit = _context.has(key); event('validate', _context, ref, hit=hit)\n"
        "    if not hit: _context.remember(key, json.loads(raw))\n"
        "    if PHASE == 'validate' and not hit: mutate(ref)\n"
        "    return _context.get(key)\n"
        "def mount_roots(ref, *, _context=None):\n"
        "    assert _context is not None and _context is current_context()\n"
        "    event('mount', _context, ref); validate_schedule(ref, _context=_context)\n"
        "    if PHASE == 'mount': mutate(ref)\n"
        "    return [Path(__file__).resolve().parents[2]]\n")
    return module_root


@pytest.mark.parametrize("kind", FLAT_FAMILIES)
def test_each_flat_scheduling_family_uses_actual_authenticated_transport(tmp_path: Path, kind: str):
    module_root = _fake_installed_reader(tmp_path)
    execution = tmp_path / "execution"
    execution.mkdir()
    capsule = tmp_path / "capsule.json"
    capsule.write_text(json.dumps({"artifact_type": kind, "runtime": {
        "module_root": str(module_root), "execution_root": str(execution),
        "collection_image_digest": "sha256:controlled-image"}}))
    result = _run_branch(capsule, execution, "sha256:controlled-image")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["rolling-scheduling", str(capsule), "-", str(module_root)]


@pytest.mark.parametrize("change", ("execution_root", "collection_image_digest"))
def test_flat_transport_rejects_changed_runtime_before_mounts(tmp_path: Path, change: str):
    module_root = _fake_installed_reader(tmp_path)
    execution = tmp_path / "execution"
    execution.mkdir()
    runtime = {"module_root": str(module_root), "execution_root": str(execution),
               "collection_image_digest": "sha256:controlled-image"}
    runtime[change] = "changed"
    capsule = tmp_path / "capsule.json"
    capsule.write_text(json.dumps({"artifact_type": FLAT_FAMILIES[-3], "runtime": runtime}))
    result = _run_branch(capsule, execution, "sha256:controlled-image")
    assert result.returncode != 0
    assert "another execution root or installed image" in result.stderr
    assert not result.stdout
    events = [json.loads(line) for line in (tmp_path / "reader-events.jsonl").read_text().splitlines()]
    assert [event["kind"] for event in events] == ["validate"]


def test_flat_transport_reuses_one_action_context_and_one_cold_validation(tmp_path: Path):
    module_root = _fake_installed_reader(tmp_path)
    execution = tmp_path / "execution"
    execution.mkdir()
    capsule = tmp_path / "capsule.json"
    capsule.write_text(json.dumps({"artifact_type": FLAT_FAMILIES[-3], "runtime": {
        "module_root": str(module_root), "execution_root": str(execution),
        "collection_image_digest": "sha256:controlled-image"}}))
    result = _run_branch(capsule, execution, "sha256:controlled-image")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["rolling-scheduling", str(capsule), "-", str(module_root)]
    events = [json.loads(line) for line in (tmp_path / "reader-events.jsonl").read_text().splitlines()]
    assert [event["kind"] for event in events] == ["validate", "mount", "validate"]
    assert len({event["context"] for event in events}) == 1
    assert all(event["ref"] == events[0]["ref"] for event in events)
    assert [event["hit"] for event in events if event["kind"] == "validate"] == [False, True]


@pytest.mark.parametrize("phase", ("validate", "mount"))
@pytest.mark.parametrize("drift", ("bytes", "full-mode", "directory-mode", "tree-membership", "capsule-bytes"))
def test_flat_transport_closes_both_dependency_fences_before_emitting_rows(tmp_path: Path, phase: str, drift: str):
    module_root = _fake_installed_reader(tmp_path, drift=drift, phase=phase)
    execution = tmp_path / "execution"
    execution.mkdir()
    capsule = tmp_path / "capsule.json"
    capsule.write_text(json.dumps({"artifact_type": FLAT_FAMILIES[-3], "runtime": {
        "module_root": str(module_root), "execution_root": str(execution),
        "collection_image_digest": "sha256:controlled-image"}}))
    result = _run_branch(capsule, execution, "sha256:controlled-image")
    assert result.returncode != 0
    assert "operation dependency" in result.stderr
    assert not result.stdout
    events = [json.loads(line) for line in (tmp_path / "reader-events.jsonl").read_text().splitlines()]
    assert [event["kind"] for event in events] == (["validate"] if phase == "validate" else
                                                  ["validate", "mount", "validate"])


def test_existing_enveloped_installation_still_uses_legacy_transport(tmp_path: Path):
    data = tmp_path / "data"
    execution = tmp_path / "execution"
    runtime = tmp_path / "runtime"
    module = tmp_path / "module"
    for path in (data, execution, runtime, module):
        path.mkdir()
    evidence = data / "evidence"
    evidence.mkdir()
    spec = {"data_root": str(data), "execution_root": str(execution),
            "runtime_source_root": str(runtime), "module_root": str(module),
            "source_manifest": str(runtime / "source.json"),
            "client_binary": str(runtime / "client"),
            "base_launcher": str(runtime / "qcsd-lab"),
            "collection_image_digest": "sha256:controlled-image"}
    capsule = evidence / "installation.json"
    capsule.write_text(json.dumps({"receipt_type":
        "qcsd-rapid-v5-capture-control-installation-v2", "payload": {
        "base_spec": spec, "runtime_spec": spec, "evidence_root": str(evidence)}}))
    result = _run_branch(capsule, execution, "sha256:controlled-image")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[:3] == [
        "capture-control-installation", str(capsule), str(capsule)]
