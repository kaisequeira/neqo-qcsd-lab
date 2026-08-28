from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_CONTAINER_LAB_ROOT = Path("/lab")
_NATIVE_LAB_ROOT = Path(__file__).resolve().parents[2]
LAB_ROOT = Path(
    os.environ.get(
        "QCSD_LAB_ROOT",
        str(_CONTAINER_LAB_ROOT if _CONTAINER_LAB_ROOT.is_dir() else _NATIVE_LAB_ROOT),
    )
).resolve()
DEFAULT_SOURCE_METADATA = Path("/usr/share/qcsd-lab/source.json")
NEQO_HOST_TIMEOUT_GRACE_SECONDS = 5.0
PROCESS_TERMINATE_GRACE_SECONDS = 2.0
ATOMIC_TEMP_MARKER = ".qcsd-tmp-"
SOURCE_METADATA_KEYS = {
    "image_digest",
    "lab_commit",
    "lab_dirty",
    "lab_patch_sha256",
    "neqo_commit",
    "neqo_pinned_commit",
    "neqo_dirty",
    "neqo_patch_sha256",
}


def require_disjoint_path(
    destination: Path,
    protected: list[Path] | tuple[Path, ...],
    *,
    label: str,
) -> Path:
    """Reject equality or ancestor/descendant overlap before an output is created."""

    candidate = Path(destination).absolute().resolve(strict=False)
    for value in protected:
        boundary = Path(value).absolute().resolve(strict=False)
        if (
            candidate == boundary
            or candidate.is_relative_to(boundary)
            or boundary.is_relative_to(candidate)
        ):
            raise ValueError(f"{label} overlaps protected input: {boundary}")
    return candidate


class ProcessTimeoutError(TimeoutError):
    """A child exceeded its host-enforced deadline and was reaped."""

    def __init__(
        self,
        result: subprocess.CompletedProcess[str],
        timeout_seconds: float,
        *,
        killed: bool,
    ) -> None:
        self.result = result
        self.timeout_seconds = timeout_seconds
        self.killed = killed
        action = "killed after the terminate grace expired" if killed else "terminated"
        super().__init__(
            f"command exceeded the {timeout_seconds:g}s host timeout and was {action}: "
            f"{' '.join(result.args)}"
        )


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            dir=path.parent,
            prefix=f".{path.name}{ATOMIC_TEMP_MARKER}",
            delete=False,
            encoding="utf-8",
        ) as out:
            json.dump(value, out, indent=2, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
            temporary = Path(out.name)
        temporary.replace(path)
        fsync_directory(path.parent)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def atomic_text(path: Path, value: str) -> None:
    """Durably replace a UTF-8 text file without exposing partial checkpoints."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            dir=path.parent,
            prefix=f".{path.name}{ATOMIC_TEMP_MARKER}",
            delete=False,
            encoding="utf-8",
        ) as out:
            out.write(value)
            out.flush()
            os.fsync(out.fileno())
            temporary = Path(out.name)
        temporary.replace(path)
        fsync_directory(path.parent)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def durable_create(path: Path, value: bytes) -> None:
    """Create a complete file exactly once and durably publish its name.

    Writing directly through ``open("xb")`` can leave a partial but
    permanently claimed evidence file after power loss.  A same-directory
    hard link publishes only a fully flushed temporary file and retains
    create-only collision semantics.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=path.parent,
            prefix=f".{path.name}{ATOMIC_TEMP_MARKER}",
            delete=False,
        ) as out:
            out.write(value)
            out.flush()
            os.fsync(out.fileno())
            temporary = Path(out.name)
        os.link(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def fsync_directory(path: Path) -> None:
    """Flush directory-entry changes required by crash-durable checkpoints."""

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def discard_atomic_write_temps(root: Path) -> list[Path]:
    """Remove only recognizable uncommitted atomic-write files before resume."""

    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"result root is not a regular directory: {root}")
    discarded = []
    for path in root.rglob("*"):
        if ATOMIC_TEMP_MARKER not in path.name:
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"atomic-write temporary path is unsafe: {path}")
        path.unlink()
        discarded.append(path)
    return discarded


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    log: Path | None = None,
    check: bool = True,
    timeout: float | None = None,
    terminate_process_group: bool = False,
) -> subprocess.CompletedProcess[str]:
    if timeout is not None:
        return _run_bounded(
            command,
            cwd=cwd,
            log=log,
            check=check,
            timeout=timeout,
            terminate_process_group=terminate_process_group,
        )
    if terminate_process_group:
        raise ValueError("process-group termination requires a bounded command")
    result = subprocess.run(
        command,
        cwd=cwd or (LAB_ROOT if LAB_ROOT.is_dir() else None),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if log:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(result.stdout, encoding="utf-8")
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}"
        )
    return result


def neqo_host_timeout(configured_timeout_seconds: int | float) -> float:
    """Leave Neqo a small shutdown/reporting grace beyond its own deadline."""

    if (
        not isinstance(configured_timeout_seconds, (int, float))
        or isinstance(configured_timeout_seconds, bool)
        or configured_timeout_seconds <= 0
    ):
        raise ValueError("configured Neqo timeout must be positive")
    return float(configured_timeout_seconds) + NEQO_HOST_TIMEOUT_GRACE_SECONDS


def _run_bounded(
    command: list[str],
    *,
    cwd: Path | None,
    log: Path | None,
    check: bool,
    timeout: float,
    terminate_process_group: bool = False,
) -> subprocess.CompletedProcess[str]:
    if timeout <= 0:
        raise ValueError("host timeout must be positive")
    process = subprocess.Popen(
        command,
        cwd=cwd or (LAB_ROOT if LAB_ROOT.is_dir() else None),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=terminate_process_group,
    )
    try:
        stdout, _stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if terminate_process_group:
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        killed = False
        try:
            stdout, _stderr = process.communicate(timeout=PROCESS_TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            if terminate_process_group:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            killed = True
            stdout, _stderr = process.communicate()
        action = "killed after terminate grace" if killed else "terminated"
        diagnostic = f"[qcsd-lab] outer host timeout after {timeout:g}s; process {action}\n"
        separator = "" if not stdout or stdout.endswith("\n") else "\n"
        stdout = f"{stdout or ''}{separator}{diagnostic}"
        result = subprocess.CompletedProcess(
            command,
            process.returncode if process.returncode is not None else 124,
            stdout,
        )
        _write_log(log, stdout)
        raise ProcessTimeoutError(result, timeout, killed=killed) from None
    result = subprocess.CompletedProcess(command, process.returncode, stdout)
    _write_log(log, stdout)
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}"
        )
    return result


def _write_log(log: Path | None, stdout: str) -> None:
    if log is None:
        return
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(stdout, encoding="utf-8")


def git_commit(path: Path) -> str:
    try:
        result = run(["git", "-C", str(path), "rev-parse", "HEAD"], check=False)
    except FileNotFoundError:
        return "unknown"
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def source_metadata() -> dict[str, Any]:
    """Return provenance for the source that produced the running image.

    Runtime images contain build-time metadata. The live-checkout fallback is
    retained for native unit tests and intentionally reports unknown dirty
    state rather than pretending that a checkout necessarily built a binary.
    """
    path = Path(os.environ.get("QCSD_LAB_SOURCE_METADATA", DEFAULT_SOURCE_METADATA))
    try:
        value = load_json(path)
    except (OSError, ValueError, TypeError):
        lab_commit = git_commit(LAB_ROOT)
        neqo_commit = git_commit(LAB_ROOT / "neqo-qcsd")
        return {
            "image_digest": os.environ.get("QCSD_LAB_IMAGE_DIGEST"),
            "lab_commit": lab_commit,
            "lab_dirty": None,
            "lab_patch_sha256": None,
            "neqo_commit": neqo_commit,
            "neqo_pinned_commit": neqo_commit,
            "neqo_dirty": None,
            "neqo_patch_sha256": None,
        }
    if not isinstance(value, dict) or set(value) != SOURCE_METADATA_KEYS:
        raise ValueError(f"invalid source metadata in {path}")
    value = dict(value)
    runtime_image = os.environ.get("QCSD_LAB_IMAGE_DIGEST")
    if runtime_image:
        value["image_digest"] = runtime_image
    image_digest = value["image_digest"]
    if image_digest is not None and (not isinstance(image_digest, str) or not image_digest.strip()):
        raise ValueError(f"invalid source metadata in {path}")
    return value


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def response_signature(sample: Path) -> list[tuple[Any, ...]] | None:
    """Return the defense-independent delivered-content identity for one sample."""

    run_json = sample / "neqo" / "run.json"
    if not run_json.is_file():
        return None
    return sorted(
        (
            response.get("resource_id"),
            response.get("status"),
            response.get("bytes"),
            response.get("body_sha256"),
            response.get("outcome"),
        )
        for response in load_json(run_json).get("responses", [])
    )


def padding_event_guard_triggered(run_data: dict[str, Any]) -> bool:
    """Return whether the runtime's bounded-padding safety guard fired."""

    diagnostics = run_data.get("defense_diagnostics")
    return isinstance(diagnostics, dict) and any(
        diagnostics.get(key) is True
        for key in (
            "padding_event_guard_triggered",
            "buflo_event_guard_triggered",
            "cs_buflo_event_guard_triggered",
        )
    )
