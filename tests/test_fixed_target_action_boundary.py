"""The fixed target reuses nested facts, then closes them at the action boundary."""
import ast
import hashlib
from pathlib import Path
import subprocess

import pytest

from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_operation_facts as facts


BASE = Path(__file__).parents[1]
SOURCE = "src/qcsd_lab/rapid_fixed_condition_target.py"
OLD_RELEASES = (
    "16e61c556bd3b90c62532e7c321679639dc2563f",
    "d15d2e6d2dbb5f264f9653fd340041e75c08125c",
    "75b8d5fa7b5c9357f7bd364041c07336f089ec4c",
)


def _old_source(commit):
    return subprocess.check_output(["git", "-C", str(BASE), "show", f"{commit}:{SOURCE}"])


def _change_owned(raw):
    original = b"answer = function(*args, **kwargs)"
    assert raw.count(original) == 1
    return raw.replace(original, b"answer = function(*args, **kwargs) or None")


def test_nested_reader_reuses_real_file_observation_and_checks_once(monkeypatch, tmp_path):
    observed = tmp_path / "observed.json"
    observed.write_bytes(b"original evidence")
    original_file = facts._file
    original_check = target._check_action
    reads = []
    checks = []

    def counted_file(path):
        reads.append(Path(path))
        return original_file(path)

    def counted_check():
        checks.append(True)
        return original_check()

    monkeypatch.setattr(facts, "_file", counted_file)
    monkeypatch.setattr(target, "_check_action", counted_check)

    @target._owned
    def inner():
        return target.reference(observed)

    @target._owned
    def outer():
        assert inner() == inner()
        return "read"

    assert outer() == "read"
    assert len(checks) == 1
    assert reads == [observed, observed]  # Initial bytes, then final byte fence.
    assert target._OBSERVATIONS.get() is None
    assert facts.current_context() is None


@pytest.mark.parametrize("mutation", ["file", "directory"])
def test_nested_observation_mutation_is_refused_at_final_boundary(tmp_path, mutation):
    root = tmp_path / "evidence"
    root.mkdir()
    observed = root / "trace.json"
    observed.write_bytes(b"original trace")

    @target._owned
    def inner():
        target.reference(observed)
        facts.current_context().watch_directory(root)
        target._close([], [target.epoch._directory(root)])

    @target._owned
    def outer():
        inner()
        if mutation == "file":
            observed.write_bytes(b"modified trace")
        else:
            (root / "new.json").write_bytes(b"new member")
        return "must not finish"

    with pytest.raises(ValueError, match="changed"):
        outer()
    assert target._OBSERVATIONS.get() is None
    assert facts.current_context() is None


def test_publication_checks_observations_before_creating_output(tmp_path):
    observed = tmp_path / "trace.json"
    observed.write_bytes(b"original")
    output = tmp_path / "published.json"

    @target._owned
    def inner():
        target.reference(observed)

    @target._owned
    def outer():
        inner()
        observed.write_bytes(b"changed")
        target._write(output, "controlled-test", {"credit": False})

    with pytest.raises(ValueError, match="dependency bytes or mode changed"):
        outer()
    assert not output.exists()


@pytest.mark.parametrize("commit", OLD_RELEASES)
def test_exact_old_source_remains_compatible_and_owned_mutation_is_refused(tmp_path, commit):
    original = _old_source(commit)
    old_path = tmp_path / "old-target.py"
    old_path.write_bytes(original)
    old = target.reference(old_path)
    current = target.reference(Path(target.__file__))
    assert target._compatible_code_ref("target", old, current)
    with pytest.raises(ValueError, match="action boundary|original shape"):
        target._reader_code_projection(_change_owned(original), "target",
                                       legacy=commit == OLD_RELEASES[0])


def test_current_owned_shape_is_exact_and_other_science_stays_in_projection():
    raw = Path(target.__file__).read_bytes()
    with pytest.raises(ValueError, match="action boundary"):
        target._reader_code_projection(_change_owned(raw), "target")
    tree = ast.parse(raw)
    owned = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_owned")
    assert hashlib.sha256(ast.dump(owned, include_attributes=False).encode()).hexdigest() == (
        "4e2825b98c6221ea6c4f66da8e7503ec6eb12d3da7319764334144c41ac5b45b")
    baseline = target._reader_code_projection(raw, "target")
    changed_science = raw.replace(b"def _identity(value):", b"def _identity(value):\n    pass", 1)
    assert target._reader_code_projection(changed_science, "target") != baseline
