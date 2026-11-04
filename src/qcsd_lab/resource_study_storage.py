"""Measure both the capture filesystem and its sparse loop-volume backing disk."""
from __future__ import annotations

import os
from pathlib import Path


def storage_snapshot(root: Path) -> dict:
    root = root.absolute()
    info = root.stat()
    volume = os.statvfs(root)
    result = {"capture_available_bytes": volume.f_bavail * volume.f_frsize,
              "capture_capacity_bytes": volume.f_blocks * volume.f_frsize}
    loop = Path(f"/sys/dev/block/{os.major(info.st_dev)}:{os.minor(info.st_dev)}/loop/backing_file")
    if os.major(info.st_dev) == 7 and not loop.is_file():
        raise ValueError("loop capture volume backing disk cannot be measured")
    if loop.is_file():
        backing = Path(loop.read_text().strip())
        if not backing.is_absolute() or not backing.is_file():
            raise ValueError("sparse capture volume backing disk cannot be measured")
        disk = os.statvfs(backing)
        result.update({"backing_file": str(backing), "physical_available_bytes": disk.f_bavail * disk.f_frsize,
                       "physical_capacity_bytes": disk.f_blocks * disk.f_frsize})
    result["available_bytes"] = min(result["capture_available_bytes"], result.get("physical_available_bytes", result["capture_available_bytes"]))
    return result


def require_storage(root: Path, *, reserve_bytes: int = 2 * 1024 ** 3) -> dict:
    if type(reserve_bytes) is not int or reserve_bytes < 0:
        raise ValueError("storage reserve must be a nonnegative byte count")
    value = storage_snapshot(root)
    if value["available_bytes"] <= reserve_bytes:
        raise RuntimeError("capture paused: physical or capture filesystem free space is below the declared reserve")
    return value
