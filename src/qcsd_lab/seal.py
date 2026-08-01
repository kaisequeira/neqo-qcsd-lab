from __future__ import annotations

import re
from pathlib import Path

from .util import sha256_file


_SHA256 = re.compile(r"[0-9a-f]{64}")


def verify_checksum_seal(root: Path, *, exact: bool = True) -> dict[str, str]:
    """Verify a path-safe SHA256SUMS seal and return its relative-path mapping."""

    root = root.resolve()
    manifest = root / "SHA256SUMS"
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(),
        1,
    ):
        try:
            expected, relative = line.split("  ", 1)
        except ValueError as error:
            raise ValueError(
                f"invalid SHA256SUMS line {line_number}: expected two-space separator"
            ) from error
        relative_path = Path(relative)
        if (
            _SHA256.fullmatch(expected) is None
            or not relative
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path.as_posix() != relative
        ):
            raise ValueError(f"invalid SHA256SUMS line {line_number}")
        resolved = (root / relative_path).resolve()
        if not resolved.is_relative_to(root):
            raise ValueError(f"checksum path escapes sealed root: {relative}")
        if relative in checksums:
            raise ValueError(f"duplicate SHA256SUMS entry: {relative}")
        checksums[relative] = expected
    if not checksums:
        raise ValueError(f"empty SHA256SUMS seal: {root}")

    listed_paths = set(checksums)
    if exact:
        actual_paths = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path != manifest
        }
        if listed_paths != actual_paths:
            missing = sorted(actual_paths - listed_paths)
            unexpected = sorted(listed_paths - actual_paths)
            details = []
            if missing:
                details.append(f"missing {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected {', '.join(unexpected)}")
            raise ValueError(
                "SHA256SUMS does not exactly cover sealed files: " + "; ".join(details)
            )

    for relative, expected in checksums.items():
        path = root / relative
        if not path.is_file() or sha256_file(path) != expected:
            raise ValueError(f"checksum mismatch: {relative}")
    return checksums
