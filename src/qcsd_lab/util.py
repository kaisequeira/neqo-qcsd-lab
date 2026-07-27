from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

LAB_ROOT = Path(os.environ.get("QCSD_LAB_ROOT", "/lab")).resolve()
DEFAULT_SOURCE_METADATA = Path("/usr/share/qcsd-lab/source.json")
SOURCE_METADATA_KEYS = {
    "development_build",
    "lab_commit",
    "lab_dirty",
    "lab_patch_sha256",
    "neqo_commit",
    "neqo_pinned_commit",
    "neqo_dirty",
    "neqo_patch_sha256",
}


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
        temporary = Path(out.name)
    temporary.replace(path)


def atomic_text(path: Path, value: str) -> None:
    """Durably replace a UTF-8 text file without exposing partial checkpoints."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as out:
        out.write(value)
        out.flush()
        os.fsync(out.fileno())
        temporary = Path(out.name)
    temporary.replace(path)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_checksums(root: Path, paths: Iterable[Path]) -> None:
    lines = []
    for path in sorted(paths):
        if path.is_file():
            lines.append(f"{sha256_file(path)}  {path.relative_to(root)}")
    atomic_text(root / "SHA256SUMS", "\n".join(lines) + "\n")


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    log: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd or LAB_ROOT,
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
            "development_build": None,
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
