"""Real isolated imports and host-source rejection before authority replay.

Temporary Git checkouts/client/campaigns are explicitly host guard fixtures,
not installed runtime, capture, or scientific proof. Only the expensive full
authority boundary is replaced; runtime paths, Gitlink and package guards run.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_parallel_capture as parallel


PROJECT = Path(__file__).resolve().parents[1]
TOOL = PROJECT / "tools/rapid_parallel_capture.py"


def _operator():
    spec = importlib.util.spec_from_file_location("parallel_operator_guard_fixture", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _git(root, *args):
    return subprocess.run(["git", "-C", str(root), "-c", "core.hooksPath=/dev/null",
        "-c", "user.name=Host guard fixture", "-c", "user.email=host-guard@example.invalid",
        *args], check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, stdin=subprocess.DEVNULL).stdout.strip()


@pytest.fixture
def host_context(tmp_path):
    root = tmp_path / "declared-source"
    package = root / "src/qcsd_lab"
    for source in (PROJECT / "src/qcsd_lab").rglob("*.py"):
        target = package / source.relative_to(PROJECT / "src/qcsd_lab")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    native = root / "neqo-qcsd"
    native.mkdir()
    (native / "README").write_bytes(b"temporary host Gitlink guard fixture; no Native artifact\n")
    _git(native, "init", "--quiet")
    _git(native, "add", "README")
    _git(native, "commit", "--quiet", "-m", "Native identity guard fixture")
    native_commit = _git(native, "rev-parse", "HEAD")
    launcher = root / "qcsd-lab"
    launcher.write_bytes(b"#!/bin/sh\nexit 0\n")
    _git(root, "init", "--quiet")
    _git(root, "add", "src/qcsd_lab", "qcsd-lab", "neqo-qcsd")
    _git(root, "commit", "--quiet", "-m", "Host source guard fixture")
    execution = tmp_path / "execution"
    execution.mkdir()
    (execution / "results").mkdir()
    (execution / "qcsd-lab").write_bytes(launcher.read_bytes())
    client = tmp_path / "client"
    client.write_bytes(b"declared host path guard fixture; not an executable Native artifact\n")
    source_manifest = tmp_path / "source.json"
    source = {"lab_commit": _git(root, "rev-parse", "HEAD"), "lab_dirty": False,
        "neqo_commit": native_commit, "neqo_pinned_commit": native_commit, "neqo_dirty": False}
    _write(source_manifest, source)
    campaigns = []
    for index in range(2):
        path = execution / f"campaign-{index}.yaml"
        path.write_bytes(f"# host input guard fixture {index}\n".encode())
        campaigns.append({"path": str(path), "sha256": parallel.sha(path.read_bytes())})
    authority = {"schema_version": 1, "artifact_type": parallel.AUTHORITY_TYPE,
        "runtime": {"runtime_source_root": str(root), "module_root": str(root),
            "execution_root": str(execution), "source_manifest": str(source_manifest),
            "client_binary": str(client), "base_launcher": str(launcher),
            "host_launcher": str(execution / "qcsd-lab"),
            "collection_image_digest": "sha256:" + "a" * 64}, "campaigns": campaigns}
    path = tmp_path / "authority.json"
    _write(path, authority)
    return SimpleNamespace(root=root, package=package, native=native, source=source,
        source_manifest=source_manifest, execution=execution, authority=authority, path=path,
        output=execution / "results/new-batch")


def _full_boundary(monkeypatch, value):
    calls = []
    def full(path):
        calls.append(Path(path))
        return value
    monkeypatch.setattr(parallel, "authority", full)
    return calls


def test_real_isolated_script_selects_its_checkout():
    probe = (
        "import runpy,sys; "
        "value=runpy.run_path(sys.argv[1],run_name='isolated_operator_guard_fixture'); "
        "print(value['parallel'].__file__)"
    )
    result = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(TOOL)],
        capture_output=True, text=True, check=True, timeout=30)
    assert Path(result.stdout.strip()).resolve() == PROJECT / "src/qcsd_lab/rapid_parallel_capture.py"
    help_result = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--help"],
        capture_output=True, text=True, check=True, timeout=30)
    assert "retire-session" in help_result.stdout


def test_actual_foreign_editable_import_is_overridden_under_isolation():
    result = subprocess.run([sys.executable, "-I", "-B", "-c",
        "import qcsd_lab.rapid_parallel_capture as p; print(p.__file__)"],
        capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        pytest.skip("this interpreter has no installed foreign editable qcsd_lab")
    foreign = Path(result.stdout.strip()).resolve()
    if foreign == PROJECT / "src/qcsd_lab/rapid_parallel_capture.py":
        pytest.skip("this interpreter's installed package already names this checkout")
    probe = (
        "import runpy,sys; "
        "value=runpy.run_path(sys.argv[1],run_name='foreign_editable_guard_fixture'); "
        "print(value['parallel'].__file__)"
    )
    selected = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(TOOL)],
        capture_output=True, text=True, check=True, timeout=30)
    assert Path(selected.stdout.strip()).resolve() == PROJECT / "src/qcsd_lab/rapid_parallel_capture.py"
    assert Path(selected.stdout.strip()).resolve() != foreign


@pytest.mark.parametrize("artifact_type", [parallel.AUTHORITY_TYPE, "qcsd-two-worker-formal-lane-authority"])
def test_real_host_guard_precedes_full_authority_and_is_rechecked(host_context, monkeypatch, artifact_type):
    context = host_context
    context.authority["artifact_type"] = artifact_type
    _write(context.path, context.authority)
    calls = []
    actual_host = parallel.host_source
    def host(value):
        calls.append("host")
        actual_host(value)
    def full(path):
        assert path == context.path
        calls.append("full")
        return context.authority
    monkeypatch.setattr(parallel, "host_source", host)
    monkeypatch.setattr(parallel, "authority", full)
    assert _operator()._host_authority(context.path) == context.authority
    assert calls == ["host", "full", "host"]
    assert not context.output.exists()


@pytest.mark.parametrize("mutation, message", [
    ("wrong-commit", "exact clean collection checkout"),
    ("dirty-source", "exact clean collection checkout"),
    ("native-commit", "exact clean collection checkout"),
    ("untracked-package", "untracked source"),
    ("declared-package", "verifier package differs"),
    ("launcher", "launcher must use"),
])
def test_real_source_or_package_changes_reject_before_full_authority(host_context, monkeypatch, mutation, message):
    context = host_context
    if mutation == "wrong-commit":
        context.source["lab_commit"] = "0" * 40
        _write(context.source_manifest, context.source)
    elif mutation == "dirty-source":
        (context.package / "__init__.py").write_bytes(b"# changed tracked source\n")
    elif mutation == "native-commit":
        (context.native / "README").write_bytes(b"new Native identity\n")
        _git(context.native, "add", "README")
        _git(context.native, "commit", "--quiet", "-m", "Different Native fixture")
    elif mutation == "untracked-package":
        (context.package / "untracked_guard_fixture.py").write_bytes(b"# untracked input\n")
    elif mutation == "declared-package":
        # Keep the new declared checkout clean: rejection must compare the
        # actual imported package, rather than merely observe a dirty tree.
        (context.package / "__init__.py").write_bytes(b"# clean but different package\n")
        _git(context.root, "add", "src/qcsd_lab/__init__.py")
        _git(context.root, "commit", "--quiet", "-m", "Different declared package")
        context.source["lab_commit"] = _git(context.root, "rev-parse", "HEAD")
        _write(context.source_manifest, context.source)
        assert _git(context.root, "status", "--porcelain", "--untracked-files=no") == ""
    else:
        (context.execution / "qcsd-lab").write_bytes(b"#!/bin/sh\nexit 1\n")
    full_calls = _full_boundary(monkeypatch, context.authority)
    with pytest.raises(ValueError, match=message):
        _operator()._host_authority(context.path)
    assert full_calls == []
    assert not context.output.exists()


def test_full_reopen_cannot_remove_the_final_source_boundary(host_context, monkeypatch):
    context = host_context
    def full(path):
        assert path == context.path
        (context.package / "__init__.py").write_bytes(b"# changed during full replay\n")
        return context.authority
    monkeypatch.setattr(parallel, "authority", full)
    with pytest.raises(ValueError, match="exact clean collection checkout"):
        _operator()._host_authority(context.path)
    assert not context.output.exists()


@pytest.mark.parametrize("field, value", [("schema_version", True), ("artifact_type", "unknown-authority")])
def test_authority_type_is_guarded_before_host_or_full_replay(host_context, monkeypatch, field, value):
    context = host_context
    context.authority[field] = value
    _write(context.path, context.authority)
    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid authority must not enter either validation boundary")
    monkeypatch.setattr(parallel, "authority", forbidden)
    monkeypatch.setattr(parallel, "host_source", forbidden)
    with pytest.raises(ValueError, match="type or schema differs"):
        _operator()._host_authority(context.path)


@pytest.mark.parametrize("action", ["launch", "verify"])
def test_public_actions_reject_wrong_source_before_replay_or_output(host_context, monkeypatch, capsys, action):
    context = host_context
    context.source["lab_commit"] = "0" * 40
    _write(context.source_manifest, context.source)
    full_calls = _full_boundary(monkeypatch, context.authority)
    def forbidden(*_args, **_kwargs):
        pytest.fail("wrong source must not launch or dispatch installed verification")
    monkeypatch.setattr(parallel, "verify_results_in_image", forbidden)
    assert _operator().main([action, "--authority", str(context.path), "--output", str(context.output)]) == 2
    assert "exact clean collection checkout" in capsys.readouterr().err
    assert full_calls == [] and not context.output.exists()


def test_isolated_launch_rejects_source_before_expensive_boundary(host_context):
    context = host_context
    context.source["lab_commit"] = "0" * 40
    _write(context.source_manifest, context.source)
    probe = """
import runpy, sys
operator = runpy.run_path(sys.argv[1], run_name='isolated_early_guard_fixture')
def expensive(*args, **kwargs):
    raise RuntimeError('EXPENSIVE AUTHORITY MUST NOT BE OPENED')
operator['parallel'].authority = expensive
raise SystemExit(operator['main'](['launch', '--authority', sys.argv[2], '--output', sys.argv[3]]))
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", probe,
        str(TOOL), str(context.path), str(context.output)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 2
    assert "exact clean collection checkout" in result.stderr
    assert "EXPENSIVE AUTHORITY" not in result.stderr
    assert not context.output.exists()


def test_retire_session_keeps_its_existing_dispatch(host_context, monkeypatch, capsys):
    context = host_context
    operator = _operator()
    def forbidden(*_args, **_kwargs):
        pytest.fail("retirement must keep the existing retirement authority path")
    operator._host_authority = forbidden
    calls = []
    def retire(path, output):
        calls.append((path, output))
        return {"valid": True}
    monkeypatch.setattr(parallel, "retire_session", retire)
    assert operator.main(["retire-session", "--authority", str(context.path), "--output", str(context.output)]) == 0
    assert json.loads(capsys.readouterr().out) == {"valid": True}
    assert calls == [(context.path, context.output)]
    assert not context.output.exists()
