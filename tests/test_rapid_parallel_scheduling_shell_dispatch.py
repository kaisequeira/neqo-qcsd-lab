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


def _fake_installed_reader(root: Path) -> Path:
    """Control only the scientific reader; execute the real shell and Python bridge."""
    module_root = root / "module"
    package = module_root / "src/qcsd_lab"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "rapid_rolling_capture.py").write_text(
        "def _ref(path): return {'path': str(path), 'sha256': 'controlled'}\n")
    (package / "rapid_rolling_schedule.py").write_text(
        "import json\nfrom pathlib import Path\n"
        "def validate_schedule(ref): return json.loads(Path(ref['path']).read_bytes())\n"
        "def mount_roots(ref): return [Path(__file__).resolve().parents[2]]\n")
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
