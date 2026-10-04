"""A failed host launch cannot trigger expensive reconstruction or invent birth."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_parallel_capture as shared


ROOT = Path(__file__).resolve().parents[1]
BIRTH_FILES = ("image-preflight.json", "batch-intent.json", "actual-launch.json", "batch-launch.json")
FORMAL_TYPE = "qcsd-two-worker-formal-lane-authority"


@pytest.fixture
def operator():
    specification = importlib.util.spec_from_file_location(
        "qcsd_fail_first_operator_fixture", ROOT / "tools/rapid_parallel_capture.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write(path, value):
    path.write_bytes(value if isinstance(value, bytes) else
                     (json.dumps(value, sort_keys=True) + "\n").encode())


def _evidence(tmp_path, *, missing=None, artifact_type=FORMAL_TYPE):
    authority = tmp_path / "authority.json"
    _write(authority, {"schema_version": 1, "artifact_type": artifact_type})
    output = tmp_path / "prebirth-output"
    output.mkdir()
    _write(output / "operator-intent.json", {"formal_accepted_trace_count": 0, "scientific_credit": False})
    _write(output / "host-start.json", {"started_at": "2026-10-04T00:00:00Z"})
    _write(output / "host.stdout", b"authenticated runtime recovery completed\n")
    _write(output / "host.stderr", b"image preflight: Argument list too long\n")
    _write(output / "host-process.json", {"returncode": 126, "formal_accepted_trace_count": 0,
                                           "scientific_credit": False})
    for name in BIRTH_FILES:
        if missing is not None and name != missing:
            _write(output / name, {"fixture": "durable presence, not validated scientific evidence"})
    return authority, output


def _snapshot(root):
    return {str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mode,
                                         path.stat().st_ino, path.stat().st_mtime_ns)
            for path in root.rglob("*") if path.is_file()}


def _invoke(entry, operator, authority, output):
    if entry == "host-tool":
        return operator.main(["verify", "--authority", str(authority), "--output", str(output)])
    return getattr(shared, entry)(authority, output)


@pytest.mark.parametrize("entry", ["verify_results", "verify_results_in_image", "host-tool"])
@pytest.mark.parametrize("missing", [None, *BIRTH_FILES])
def test_missing_birth_rejects_before_expensive_authority_and_preserves_failure_evidence(
        tmp_path, monkeypatch, operator, capsys, entry, missing):
    authority, output = _evidence(tmp_path, missing=missing)
    before = _snapshot(tmp_path)
    called = []

    def forbidden(*args, **kwargs):
        called.append("expensive authority or HOST entry")
        raise AssertionError("a prebirth failure must be rejected before scientific reconstruction")

    monkeypatch.setattr(shared, "authority", forbidden)
    monkeypatch.setattr(shared, "host_source", forbidden)
    monkeypatch.setattr(shared, "result_verification_command", forbidden)
    monkeypatch.setattr(formal, "_audit", forbidden)
    monkeypatch.setattr(operator, "_host_authority", forbidden)
    if entry == "host-tool":
        # The tool itself must reject before entering the shared image verifier.
        monkeypatch.setattr(shared, "verify_results_in_image", forbidden)
        assert _invoke(entry, operator, authority, output) == 2
        captured = capsys.readouterr()
        assert "lacks durable preflight or worker birth" in captured.err
        assert (missing or BIRTH_FILES[0]) in captured.err
        assert not captured.out
    else:
        with pytest.raises(ValueError, match="lacks durable preflight or worker birth") as rejected:
            _invoke(entry, operator, authority, output)
        assert (missing or BIRTH_FILES[0]) in str(rejected.value)
    assert not called
    assert _snapshot(tmp_path) == before
    assert shared.load(output / "host-process.json")["returncode"] == 126
    assert not (output / (missing or BIRTH_FILES[0])).exists()
    assert not (output / "deep-verification.json").exists()
    assert not list(output.glob("image-verification-*"))


@pytest.mark.parametrize("entry", ["verify_results", "verify_results_in_image"])
@pytest.mark.parametrize("artifact_type", [shared.AUTHORITY_TYPE, FORMAL_TYPE])
def test_present_birth_only_allows_original_full_validator_entry(
        tmp_path, monkeypatch, operator, entry, artifact_type):
    authority, output = _evidence(tmp_path, missing="none", artifact_type=artifact_type)
    before = _snapshot(tmp_path)
    called = []

    def full_validator(*args, **kwargs):
        called.append((args, kwargs))
        raise RuntimeError("original full scientific validator entered")

    if artifact_type == shared.AUTHORITY_TYPE:
        monkeypatch.setattr(shared, "authority", full_validator)
    else:
        monkeypatch.setattr(formal, "_audit", full_validator)
    with pytest.raises(RuntimeError, match="original full scientific validator entered"):
        _invoke(entry, operator, authority, output)
    assert len(called) == 1
    assert called[0][0][0] == authority
    assert _snapshot(tmp_path) == before


def test_host_tool_present_birth_still_enters_full_host_authority(
        tmp_path, monkeypatch, operator, capsys):
    authority, output = _evidence(tmp_path, missing="none")
    before = _snapshot(tmp_path)
    called = []

    def full_host_authority(*args, **kwargs):
        called.append(args)
        raise RuntimeError("original full HOST authority entered")

    def image_before_authority(*args, **kwargs):
        raise AssertionError("complete birth cannot bypass full HOST authority")

    monkeypatch.setattr(operator, "_host_authority", full_host_authority)
    monkeypatch.setattr(shared, "verify_results_in_image", image_before_authority)
    assert _invoke("host-tool", operator, authority, output) == 2
    assert called == [(authority,)]
    captured = capsys.readouterr()
    assert "original full HOST authority entered" in captured.err
    assert not captured.out
    assert _snapshot(tmp_path) == before
