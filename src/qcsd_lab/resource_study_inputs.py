"""Strict source pools and Native inputs for the resource-host study.

These functions describe inputs. They neither qualify a resource nor establish
that a session completed it. Source occurrences remain available even when
normalized URLs are deduplicated for the resource count.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit


MODES = ("undefended", "front", "tamaraw", "buflo", "cs-buflo")
CLASS_COUNT = 50
RESOURCES_PER_SESSION = 20
SESSIONS_PER_MODE = 400

_MAX_SOURCE_BYTES = 16 * 1024 * 1024
_U64_MAX = (1 << 64) - 1
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def canonical_json(value: Any) -> bytes:
    """Encode deterministic UTF-8 JSON, including its terminal newline."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def sha256_file(path: str | Path) -> str:
    """Hash file bytes without interpreting their contents."""
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _hostname(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("hostname must be a nonempty DNS name")
    try:
        hostname = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("hostname is not valid IDNA") from error
    if hostname.endswith("."):
        hostname = hostname[:-1]
    labels = hostname.split(".")
    if (len(hostname) > 253 or len(labels) < 2
            or any(_HOST_LABEL.fullmatch(label) is None for label in labels)):
        raise ValueError("hostname must be a canonical DNS name")
    return hostname


def normalize_url(url: str) -> str:
    """Normalize HTTPS authority and fragments without changing path or query.

    Hosts use lowercase IDNA, a terminal DNS dot and explicit port443 are
    removed, and an absent path becomes '/'. Credentials, nondefault ports,
    whitespace, controls and backslashes are refused.
    """
    if (not isinstance(url, str) or not url
            or any(ord(char) <= 0x20 or ord(char) == 0x7f or char.isspace()
                   for char in url) or "\\" in url):
        raise ValueError("resource URL must be a nonempty HTTPS address")
    try:
        parts = urlsplit(url)
        if (parts.scheme != "https" or parts.hostname is None
                or parts.username is not None or parts.password is not None
                or parts.port not in (None, 443) or parts.netloc.endswith(":")):
            raise ValueError("resource URL needs credential-free HTTPS on port443")
        hostname = _hostname(parts.hostname)
    except ValueError as error:
        raise ValueError("resource URL has an invalid HTTPS authority") from error
    normalized = urlunsplit(("https", hostname, parts.path or "/", parts.query, ""))
    # An explicitly empty query is still part of the supplied request address.
    if not parts.query and "?" in url.split("#", 1)[0]:
        normalized += "?"
    return normalized


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("source JSON contains a duplicate field")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise ValueError(f"source JSON contains a nonfinite number: {value}")


def _read_source(path: str | Path) -> bytes:
    with Path(path).open("rb") as handle:
        raw = handle.read(_MAX_SOURCE_BYTES + 1)
    if len(raw) > _MAX_SOURCE_BYTES:
        raise ValueError("resource source exceeds the parser byte limit")
    return raw


def _candidates(raw: bytes) -> list[dict[str, Any]]:
    try:
        rows = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_nonfinite)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("resource source must be UTF-8 JSON") from error
    if not isinstance(rows, list) or not rows:
        raise ValueError("resource source needs a nonempty list")
    candidates: dict[str, dict[str, Any]] = {}
    seen_urls: dict[str, set[str]] = {}
    for source_index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or set(row) != {"crUX_domain", "resources"}:
            raise ValueError("resource source row fields differ")
        source = _hostname(row["crUX_domain"])
        if not isinstance(row["resources"], list):
            raise ValueError("resource groups must be a list")
        for group_index, group in enumerate(row["resources"], 1):
            if (not isinstance(group, dict)
                    or set(group) != {"resource_domain", "resource_urls"}):
                raise ValueError("resource group fields differ")
            hostname = _hostname(group["resource_domain"])
            urls = group["resource_urls"]
            if not isinstance(urls, list):
                raise ValueError("resource URLs must be a list")
            candidate = candidates.setdefault(hostname, {
                "hostname": hostname, "urls": [], "sources": [],
                "eligible": False, "url_count": 0, "source_occurrences": [],
            })
            seen = seen_urls.setdefault(hostname, set())
            if source not in candidate["sources"]:
                candidate["sources"].append(source)
            for url in urls:
                normalized = normalize_url(url)
                if urlsplit(normalized).hostname != hostname:
                    raise ValueError("resource URL hostname differs from its group label")
                if normalized not in seen:
                    candidate["urls"].append(normalized)
                    seen.add(normalized)
            candidate["source_occurrences"].append({
                "source_index": source_index, "group_index": group_index,
                "crUX_domain": row["crUX_domain"],
                "resource_domain": group["resource_domain"],
                "resource_urls": list(urls),
            })
    for candidate in candidates.values():
        candidate["url_count"] = len(candidate["urls"])
        candidate["eligible"] = candidate["url_count"] >= RESOURCES_PER_SESSION
    return list(candidates.values())


def load_candidates(path: str | Path) -> list[dict[str, Any]]:
    """Return all exact-host pools in their first source occurrence order."""
    return _candidates(_read_source(path))


def candidate_catalogue(path: str | Path) -> dict[str, Any]:
    """Bind the catalogue and source hash to one read of the supplied bytes."""
    raw = _read_source(path)
    candidates = _candidates(raw)
    return {
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "candidates": candidates,
        "eligible_count": sum(candidate["eligible"] for candidate in candidates),
        "target_classes": CLASS_COUNT,
        "resources_per_session": RESOURCES_PER_SESSION,
        "modes": list(MODES),
        "sessions_per_mode": SESSIONS_PER_MODE,
        "total_sessions": CLASS_COUNT * len(MODES) * SESSIONS_PER_MODE,
    }


def native_manifest(hostname: str, urls: Iterable[str],
                    lengths: Mapping[str, int] | None = None, *,
                    require_twenty: bool = True) -> dict[str, Any]:
    """Build the direct Native JSON for a chosen, immutable same-host URL set.

    Formal inputs require exactly20 distinct normalized URLs. A probe may use
    another nonempty count with require_twenty=False. Unknown content length is
    null; Native's u64 data_length uses its default zero until actual lengths
    are supplied. known_valid is the requested Native configuration flag, not
    a qualification receipt or a completed-resource claim.
    """
    hostname = _hostname(hostname)
    if not isinstance(require_twenty, bool) or isinstance(urls, (str, bytes)):
        raise ValueError("manifest URLs need a collection and an explicit count policy")
    try:
        normalized = [normalize_url(url) for url in urls]
    except TypeError as error:
        raise ValueError("manifest URLs must be iterable") from error
    if not normalized or (require_twenty and len(normalized) != RESOURCES_PER_SESSION):
        raise ValueError("manifest needs exactly20 URLs, or a nonempty explicit probe")
    if len(set(normalized)) != len(normalized):
        raise ValueError("manifest resources must have distinct normalized URLs")
    if any(urlsplit(url).hostname != hostname for url in normalized):
        raise ValueError("manifest resource hostname differs from its class")
    actual_lengths: dict[str, int] = {}
    if lengths is not None:
        if not isinstance(lengths, Mapping):
            raise ValueError("resource lengths must map selected URLs to integers")
        for url, length in lengths.items():
            key = normalize_url(url)
            if (key in actual_lengths or not isinstance(length, int)
                    or isinstance(length, bool) or not 0 <= length <= _U64_MAX):
                raise ValueError("resource lengths must be unambiguous u64 integers")
            actual_lengths[key] = length
        if set(actual_lengths) != set(normalized):
            raise ValueError("resource lengths must cover exactly the selected URLs")
    return {"resources": [
        {"id": index, "url": url, "type": "Other",
         "content_length": actual_lengths.get(url),
         "data_length": actual_lengths.get(url, 0),
         "chaff_priority": False, "known_valid": True,
         "depends_on": [], "headers": []}
        for index, url in enumerate(normalized)
    ]}
