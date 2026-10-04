from __future__ import annotations

import errno
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/docker_signal_supervisor.sh"


def _bash(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", f"source {shlex.quote(str(HELPER))}\n{script}", "fsync-test", *args],
        text=True, capture_output=True, timeout=5, check=False,
    )


def _function(name: str, successor: str) -> str:
    source = (ROOT / "qcsd-lab").read_text()
    return source[source.index(f"{name}() {{"):source.index(f"{successor}() {{")]


def _inline_program() -> str:
    source = HELPER.read_text()
    body = source.split("_qcsd_fsync_path() {\n", 1)[1].split("\n}\n", 1)[0]
    return body.split(" -c '\n", 1)[1].rsplit("\n' \"$@\"", 1)[0]


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_exact_file_and_directory_barriers_accept_existing_public_permissions(
    tmp_path: Path, kind: str,
) -> None:
    target = tmp_path / "ordinary target with $literal and spaces"
    if kind == "file":
        target.write_text("durable receipt\n")
        target.chmod(0o644)
    else:
        target.mkdir(mode=0o755)
    result = _bash('_qcsd_fsync_path "$1" "$2"', kind, str(target))
    assert result.returncode == 0, result.stderr
    assert not result.stdout


@pytest.mark.parametrize("case", ["file-symlink", "directory-symlink", "fifo", "wrong-type"])
def test_unsupported_or_symlink_targets_fail_without_blocking(tmp_path: Path, case: str) -> None:
    target = tmp_path / "target"
    kind = "file"
    if case.endswith("symlink"):
        original = tmp_path / "original"
        if case == "directory-symlink":
            original.mkdir()
            kind = "directory"
        else:
            original.write_text("preserve\n")
        target.symlink_to(original)
    elif case == "fifo":
        os.mkfifo(target)
    else:
        target.mkdir()
    result = _bash('_qcsd_fsync_path "$1" "$2"', kind, str(target))
    assert result.returncode != 0
    assert target.exists()


@pytest.mark.parametrize("failure", ["fsync-error", "path-replacement"])
def test_failed_or_replaced_opened_file_never_reports_durable_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    target = tmp_path / "receipt"
    target.write_text("original\n")
    real_fsync = os.fsync
    invoked: list[int] = []

    def barrier(descriptor: int) -> None:
        invoked.append(descriptor)
        if failure == "fsync-error":
            raise OSError(errno.EIO, "injected target barrier failure")
        target.rename(tmp_path / "original-inode")
        target.write_text("replacement\n")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", barrier)
    monkeypatch.setattr(sys, "argv", ["scoped-fsync", "file", str(target)])
    with pytest.raises(SystemExit, match="1"):
        exec(compile(_inline_program(), str(HELPER), "exec"), {})
    assert len(invoked) == 1
    with pytest.raises(OSError):
        os.fstat(invoked[0])


@pytest.mark.parametrize("failure", ["none", "file", "directory"])
def test_publication_preserves_file_before_rename_and_parent_failure_taint(
    tmp_path: Path, failure: str,
) -> None:
    root = tmp_path / "run.example"
    root.mkdir(mode=0o700)
    staged, published, trace = root / "SUPERVISION.next", root / "SUPERVISION", tmp_path / "trace"
    staged.write_text("new receipt\n")
    published.write_text("old receipt\n")
    published.chmod(0o600)
    # These tests isolate durability from record-schema fixtures. Production
    # private-file checks, rename, failure status and replacement flag remain.
    script = r'''
definition="$(declare -f _qcsd_fsync_path)"
eval "${definition/_qcsd_fsync_path/_qcsd_real_fsync_path}"
_qcsd_fsync_path() {
  printf '%s\n' "$1" >>"$trace"
  [[ "$1" != "$failure" ]] || return 1
  _qcsd_real_fsync_path "$@"
}
_qcsd_lifecycle_parse_record() { return 0; }
_qcsd_lifecycle_validate_record() { return 0; }
failure=$1; trace=$4
_qcsd_publish_supervision_file "$2" "$3"
status=$?
printf '%s %s\n' "$status" "$_QCSD_PUBLISH_REPLACED"
'''
    result = _bash(script, failure, str(staged), str(published), str(trace))
    assert result.returncode == 0, result.stderr
    expected = {"none": "0 1", "file": "1 0", "directory": "1 1"}
    assert result.stdout.strip() == expected[failure]
    assert published.read_text() == ("old receipt\n" if failure == "file" else "new receipt\n")
    assert staged.exists() == (failure == "file")
    assert trace.read_text().splitlines() == (["file"] if failure == "file" else ["file", "directory"])


@pytest.mark.parametrize("case", ["success", "first-barrier-fails", "unexpected-entry"])
def test_recovered_root_deletion_preserves_guards_and_failure_evidence(
    tmp_path: Path, case: str,
) -> None:
    root = tmp_path / "recovered"
    root.mkdir(mode=0o700)
    for name in ["SUPERVISION", "RECOVERY", "container.cid", "run.status", "stdout"]:
        path = root / name
        path.write_text("preserved actual evidence\n")
        path.chmod(0o600)
    if case == "unexpected-entry":
        (root / "unowned").write_text("preserve\n")
    trace = tmp_path / "trace"
    definitions = _function("_qcsd_admission_validate_root_entries", "_qcsd_admission_validate_common_record")
    definitions += _function("_qcsd_admission_remove_recovered_root", "_qcsd_admission_root_manifest_sha256")
    script = definitions + r'''
definition="$(declare -f _qcsd_fsync_path)"
eval "${definition/_qcsd_fsync_path/_qcsd_real_fsync_path}"
_qcsd_fsync_path() {
  printf '%s\n' "$2" >>"$trace"
  [[ "$case" != "first-barrier-fails" ]] || return 1
  _qcsd_real_fsync_path "$@"
}
case=$1; trace=$3
_qcsd_admission_remove_recovered_root "$2" run
'''
    result = _bash(script, case, str(root), str(trace))
    if case == "success":
        assert result.returncode == 0, result.stderr
        assert not root.exists()
        assert trace.read_text().splitlines() == [str(root)] * 3 + ["/tmp"]
    else:
        assert result.returncode != 0
        assert (root / "SUPERVISION").exists() and (root / "RECOVERY").exists()
        assert trace.exists() == (case == "first-barrier-fails")
