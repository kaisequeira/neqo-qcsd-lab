"""Execute the launcher's real selector/import seam without Docker or authority.

Temporary roots expose the actual current Source modules. Fake executable
candidates model only a failed probe; successful probes and formal dispatch
always use a real interpreter and the unmodified formal module.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest


SOURCE_ROOT = Path(__file__).resolve().parents[1]
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@pytest.fixture
def shell(tmp_path):
    root = tmp_path / "execution with spaces"
    root.mkdir()
    (root / "src").symlink_to(SOURCE_ROOT / "src", target_is_directory=True)
    source = (SOURCE_ROOT / "qcsd-lab").read_text()
    block = "parallel_diagnostic=0\n" + source.split("parallel_diagnostic=0\n", 1)[1].split(
        'study_cohort_version=""\n', 1)[0]
    helpers = block.split('if [[ "${1:-}" == "parallel-diagnostic-run" ||', 1)[0]
    def run(code, *, operator=None, path=SYSTEM_PATH, dispatch=False, args=()):
        env = {key: value for key, value in os.environ.items() if not key.startswith("QCSD_")}
        if operator is not None:
            env["QCSD_PARALLEL_HOST_PYTHON"] = str(operator)
        prefix = "set -euo pipefail\nROOT=" + shlex.quote(str(root)) + "\nreadonly PATH=" + shlex.quote(path) + "\nexport PATH\n"
        return subprocess.run(["/bin/bash", "-p", "-c", prefix + (block if dispatch else helpers) + "\n" + code,
                               "formal-host-python-fixture", *map(str, args)], env=env,
                              text=True, capture_output=True, check=False, timeout=20)
    return root, run


def root_venv(root, executable=sys.executable):
    path = root / ".venv/bin/python"
    path.parent.mkdir(parents=True)
    path.symlink_to(executable)
    config = Path(sys.prefix) / "pyvenv.cfg"
    if config.is_file():
        (root / ".venv/pyvenv.cfg").write_bytes(config.read_bytes())
        (root / ".venv/lib").symlink_to(Path(sys.prefix) / "lib", target_is_directory=True)
    return path


def test_real_selector_prefers_literal_root_venv_path_with_spaces(shell, tmp_path):
    root, run = shell
    expected = root_venv(root)
    bad_operator = tmp_path / "unsupported-operator"
    bad_operator.write_text("#!/bin/sh\nexit 2\n")
    bad_operator.chmod(0o755)
    selected = run("parallel_select_host_python", operator=bad_operator)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.strip() == str(expected)
    result = run("parallel_formal=1\nparallel_python formal-inputs --authority missing.json --index 0")
    assert result.returncode != 0 and "parallel input must be a regular file" in result.stderr
    assert "ImportError" not in result.stderr and "ModuleNotFoundError" not in result.stderr


def test_archived_root_uses_actual_operator_venv_despite_sealed_system_path(shell):
    root, run = shell
    assert not (root / ".venv").exists()
    selected = run("parallel_select_host_python", operator=sys.executable)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.strip() == sys.executable
    result = run("parallel_formal=1\nparallel_python formal-inputs --authority missing.json --index 0",
                 operator=sys.executable)
    assert result.returncode != 0 and "parallel input must be a regular file" in result.stderr
    assert "cannot import name 'UTC'" not in result.stderr


@pytest.mark.parametrize("failure", ["missing", "unsupported", "broken"])
def test_failed_root_candidate_falls_back_to_actual_operator(shell, failure):
    root, run = shell
    if failure == "missing":
        root_venv(root, root / "nonexistent-python")
    else:
        path = root / ".venv/bin/python"
        path.parent.mkdir(parents=True)
        path.write_text("#!/bin/sh\n" + ("exit 2\n" if failure == "unsupported" else "exit 127\n"))
        path.chmod(0o755)
    result = run("parallel_select_host_python", operator=sys.executable)
    assert result.returncode == 0 and result.stdout.strip() == sys.executable


def test_available_compatible_path_python_is_checked_with_actual_source_import(shell, tmp_path):
    _, run = shell
    path = tmp_path / "compatible path"
    path.mkdir()
    candidate = path / "python3.11"
    candidate.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + ' "$@"\n')
    candidate.chmod(0o755)
    result = run("parallel_select_host_python", path=str(path))
    assert result.returncode == 0 and result.stdout.strip() == str(path / "python3.11")


def test_all_failed_candidates_stop_before_first_dispatch_or_worker_initialization(shell, tmp_path):
    root, run = shell
    path = tmp_path / "unsupported path"
    path.mkdir()
    for name in ("python3.11", "python3", "python"):
        candidate = path / name
        candidate.write_text("#!/bin/sh\nexit 2\n")
        candidate.chmod(0o755)
    # The authentic dispatcher needs these shell utilities before selecting
    # Python. No actual container or worker initialization is invoked.
    for name in ("realpath", "sha256sum"):
        (path / name).symlink_to(shutil.which(name))
    authority = root / "authority.json"
    authority.write_text(json.dumps({"artifact_type": "qcsd-two-worker-formal-lane-authority"}))
    output = root / "results/pair"
    output.mkdir(parents=True)
    before = authority.read_bytes()
    result = run("printf 'DISPATCH_COMPLETED\\n'", path=str(path), dispatch=True,
                 args=("parallel-formal-run", authority, output))
    assert result.returncode == 2
    assert "Python >=3.11 with project dependencies" in result.stderr
    assert "DISPATCH_COMPLETED" not in result.stdout
    assert list(output.iterdir()) == [] and authority.read_bytes() == before


def test_first_formal_authority_select_already_uses_real_compatible_interpreter(shell):
    root, run = shell
    authority = root / "authority.json"
    authority.write_text(json.dumps({"artifact_type": "qcsd-two-worker-formal-lane-authority"}))
    output = root / "results/pair"
    output.mkdir(parents=True)
    result = run("printf 'DISPATCH_COMPLETED\\n'", operator=sys.executable, dispatch=True,
                 args=("parallel-formal-run", authority, output))
    assert result.returncode != 0
    assert "formal parallel authority fields differ" in result.stderr
    assert "cannot import name 'UTC'" not in result.stderr
    assert "DISPATCH_COMPLETED" not in result.stdout and list(output.iterdir()) == []


def test_diagnostic_helper_keeps_historical_interpreter_without_operator_selection(shell):
    _, run = shell
    result = run("parallel_python --help", operator="deliberately-invalid-relative-override")
    assert result.returncode == 0, result.stderr
    assert "formal-inputs" in result.stdout
    assert "operator Python must" not in result.stderr


def test_selector_rejects_relative_operator_or_absent_explicit_source(shell):
    root, run = shell
    result = run("parallel_select_host_python", operator="python3.11")
    assert result.returncode == 2 and "absolute executable path" in result.stderr
    (root / "src").unlink()
    result = run("parallel_select_host_python", operator=sys.executable)
    assert result.returncode == 2 and "project dependencies" in result.stderr


def test_real_unsupported_host_python_cannot_authorize_formal_import(shell):
    _, run = shell
    candidate = shutil.which("python3")
    version = json.loads(subprocess.check_output([candidate, "-I", "-c",
        "import json,sys;print(json.dumps(list(sys.version_info[:2])))"]))
    if version >= [3, 11]:
        pytest.skip("No older system Python on this portable test host")
    result = run("parallel_select_host_python", operator=candidate, path="/nonexistent-compatible-path")
    assert result.returncode == 2 and "Python >=3.11" in result.stderr


def test_later_raw_receipt_helpers_still_run_on_system_python(tmp_path):
    # Execute both real post-select host scripts. These only seal raw JSON;
    # formal lane/class/runtime validation runs through the selected helper or
    # the image interpreter and must never be imported here on Python 3.10.
    source = (SOURCE_ROOT / "qcsd-lab").read_text()
    def script_containing(needle):
        at = source.index(needle)
        start = source.rfind("/usr/bin/python3 -I -c '\n", 0, at)
        assert start >= 0
        return source[start:].split("-c '\n", 1)[1].split("\n' ", 1)[0]
    preflight = {"schema_version": 1, "valid": True}
    completed = subprocess.run(["/usr/bin/python3", "-I", "-B", "-c",
        script_containing('put(Path(sys.argv[2])/"image-preflight.json"'),
        str(SOURCE_ROOT), str(tmp_path), json.dumps(preflight)], text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    assert json.loads((tmp_path / "image-preflight.json").read_bytes()) == preflight
    inputs = {"campaign_name": "formal-lane-fixture", "dns_path": str(tmp_path / "dns.json")}
    dns = {"schema_version": 1, "campaign": inputs["campaign_name"],
           "hosts": [["example.com", "8.8.8.8"]]}
    command = ["/usr/bin/python3", "-I", "-B", "-c",
        script_containing('raise ValueError("formal DNS receipt repeats a key")'),
        str(SOURCE_ROOT), json.dumps(inputs), json.dumps(dns)]
    completed = subprocess.run(command, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    before = (tmp_path / "dns.json").read_bytes()
    assert json.loads(before) == dns
    repeated = subprocess.run(command, text=True, capture_output=True)
    assert repeated.returncode != 0 and (tmp_path / "dns.json").read_bytes() == before


@pytest.mark.parametrize("formal", [False, True])
def test_operator_transports_its_actual_python_only_for_formal_launch(tmp_path, monkeypatch, formal):
    spec = importlib.util.spec_from_file_location("formal_host_operator", SOURCE_ROOT / "tools/rapid_parallel_capture.py")
    operator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(operator)
    execution = tmp_path / "execution"
    (execution / "results").mkdir(parents=True)
    path = tmp_path / "authority.json"
    path.write_bytes(b"retained fixture authority\n")
    value = {"artifact_type": "qcsd-two-worker-formal-lane-authority" if formal else operator.parallel.AUTHORITY_TYPE,
        "runtime": {"execution_root": str(execution), "host_launcher": "/fixture/host-launcher",
                    "collection_image_digest": "sha256:" + "a" * 64, "base_launcher": "/fixture/base-launcher"}}
    monkeypatch.setattr(operator.parallel, "authority", lambda *args: value)
    monkeypatch.setattr(operator.parallel, "host_source", lambda *args: None)
    monkeypatch.setattr(operator.parallel, "verify_results", lambda *args: {"valid": False, "scientific_credit": False})
    from qcsd_lab import rapid_formal_parallel
    monkeypatch.setattr(rapid_formal_parallel, "worker_environment", lambda *args: {})
    actual = []
    real_spawn = subprocess.Popen
    def spawn(command, **options):
        actual.append(options["env"])
        # Consume the real operator gate without executing a host launcher.
        # A fake child would close its inherited read side and break os.write.
        return real_spawn([sys.executable, "-c",
            "import os,sys;raise SystemExit(0 if os.read(int(sys.argv[1]),1)==b'G' else 2)",
            command[-1]], **options)
    monkeypatch.setattr(operator.subprocess, "Popen", spawn)
    operator.launch(path, execution / "results/pair")
    assert len(actual) == 1
    if formal:
        assert actual[0]["QCSD_PARALLEL_HOST_PYTHON"] == sys.executable
    else:
        assert "QCSD_PARALLEL_HOST_PYTHON" not in actual[0]
