"""Explicit reserve pools from Native URL inventories, never live admission.

Historical response/status fields are preserved as provenance. They neither
filter the pool nor grant completion, HTTP/3, chaff or scientific authority.
The caller must explicitly opt in and perform current live enrollment.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
from typing import Any, Iterable
from urllib.parse import urlsplit

from . import resource_study_inputs as inputs

TYPE = "qcsd-resource-domain-supplemental-inventory-catalogue-v1"
LIMIT = 16 * 1024 * 1024


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError("Native inventory contains duplicate JSON fields")
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError("Native inventory contains a nonfinite JSON value: " + value)


def _stamp(path):
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("Native inventory path contains a symbolic link")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Native inventory must be one regular unlinked file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, stat.S_IMODE(info.st_mode), info.st_nlink)


def _read(path):
    before = _stamp(path)
    with path.open("rb") as handle:
        raw = handle.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Native inventory exceeds the parser byte limit")
    if _stamp(path) != before:
        raise ValueError("Native inventory changed while reading")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_nonfinite)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Native inventory must be UTF-8 JSON") from error
    if not isinstance(value, dict) or not isinstance(value.get("urls"), list):
        raise ValueError("Native inventory needs a top-level urls list")
    # Metadata beside urls remains bound by the complete raw file hash.
    return raw, value["urls"], before


def load_inventory_candidates(paths: Iterable[str | Path]) -> dict[str, Any]:
    """Return exact-host pools in first file/row order with immutable provenance.

    The API performs no network or writes. A row must be an object with a url
    field. Invalid HTTPS URL values are reported, not silently removed. Valid
    URLs are normalized by the approved input module, preserving queries, and
    deduplicated across files without losing their original occurrence records.
    Pools with fewer than twenty distinct URLs remain explicitly ineligible.
    """
    if isinstance(paths, (str, bytes, Path)):
        raise ValueError("inventories require an explicit collection of file paths")
    try:
        selected = list(paths)
    except TypeError as error:
        raise ValueError("inventories require a collection of file paths") from error
    if not selected:
        raise ValueError("at least one explicit Native inventory is required")
    files, excluded, fences = [], [], []
    candidates, seen = {}, {}
    for file_index, value in enumerate(selected, 1):
        try:
            path = Path(value)
        except TypeError as error:
            raise ValueError("Native inventory path is invalid") from error
        if ".." in path.parts:
            raise ValueError("Native inventory path contains parent traversal")
        path = path.absolute()
        if any(item[0] == path for item in fences):
            raise ValueError("the same Native inventory was supplied twice")
        raw, records, stamp = _read(path)
        digest = hashlib.sha256(raw).hexdigest()
        ref = {"path": str(path), "sha256": digest, "mode": f"{stamp[5]:04o}",
               "size": len(raw), "record_count": len(records)}
        files.append(ref)
        fences.append((path, stamp))
        for record_index, record in enumerate(records, 1):
            if not isinstance(record, dict) or "url" not in record:
                raise ValueError("Native inventory row needs an object with a url field")
            occurrence = {"inventory_index": file_index, "record_index": record_index,
                          "inventory": dict(ref), "record": record}
            try:
                normalized = inputs.normalize_url(record["url"])
            except ValueError as error:
                excluded.append({**occurrence, "reason": str(error)})
                continue
            hostname = urlsplit(normalized).hostname
            candidate = candidates.setdefault(hostname, {
                "hostname": hostname, "urls": [], "url_count": 0, "eligible": False,
                "sources": [], "source_occurrences": [],
            })
            if str(path) not in candidate["sources"]:
                candidate["sources"].append(str(path))
            unique = seen.setdefault(hostname, set())
            if normalized not in unique:
                candidate["urls"].append(normalized)
                unique.add(normalized)
            candidate["source_occurrences"].append({**occurrence, "normalized_url": normalized})
    for path, stamp in fences:
        if _stamp(path) != stamp:
            raise ValueError("Native inventory changed while building the catalogue")
    for candidate in candidates.values():
        candidate["url_count"] = len(candidate["urls"])
        candidate["eligible"] = candidate["url_count"] >= inputs.RESOURCES_PER_SESSION
    values = list(candidates.values())
    return {"schema_version": 1, "artifact_type": TYPE,
            "scientific_credit": False, "opt_in_required": True,
            "resources_per_session": inputs.RESOURCES_PER_SESSION,
            "inventory_files": files, "candidates": values,
            "eligible_count": sum(candidate["eligible"] for candidate in values),
            "excluded_records": excluded}
