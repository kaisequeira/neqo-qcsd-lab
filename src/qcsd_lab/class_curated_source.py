"""Import an external domain list without assigning class-study eligibility.

The supplied resource URLs are observations about the source, not workload
instructions.  Only their origins, counts, and hashes enter the receipt.  A
later study-specific adapter must decide whether and how to use its domains.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .class_acquisition import DOMAIN_SAFETY_POLICY, unsafe_catalogue_domain_reason
from .class_study import (
    bind_receipt,
    canonical_domain,
    canonical_json_bytes,
    canonical_json_sha256,
    validate_hash_bound_receipt,
    write_create_only_json,
)

RECEIPT_TYPE = "qcsd-curated-domain-source"
SOURCE_FORMAT = "crux-domain-resources-v1"
ORDERING_POLICY = "source-order-no-rank-eligibility-or-resource-filter-v1"

# Parsing limits protect the local importer from an oversized untrusted file.
# They are not acquisition quotas or scientific eligibility rules.
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_RECEIPT_BYTES = 128 * 1024 * 1024
MAX_DOMAINS = 10_000
MAX_RESOURCE_GROUPS_PER_DOMAIN = 256
MAX_RESOURCE_URLS_PER_DOMAIN = 50_000
MAX_RESOURCE_URL_BYTES = 16_384

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"curated source repeats JSON field {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"curated source contains non-JSON number {value!r}")


def _parse_json(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from error


def _read_regular_bounded(path: Path, *, label: str, limit: int | None = None) -> bytes:
    if limit is None:
        limit = MAX_SOURCE_BYTES
    source = Path(os.path.abspath(path))
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"{label} is not a regular file: {source}")
    try:
        with source.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as error:
        raise ValueError(f"cannot read {label}: {source}") from error
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte parser limit")
    return raw


def _source_domain(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("curated domain must be a non-empty string")
    if any(ord(character) <= 0x20 or character.isspace() for character in value):
        raise ValueError("curated domain contains whitespace or control characters")
    try:
        canonical = value.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as error:
        raise ValueError("curated domain is not valid IDNA") from error
    return canonical_domain(canonical)


def _https_resource_host(url: Any) -> str:
    if not isinstance(url, str) or not url:
        raise ValueError("curated resource URL must be a non-empty string")
    try:
        encoded = url.encode("utf-8")
    except UnicodeError as error:
        raise ValueError("curated resource URL is not valid UTF-8") from error
    if len(encoded) > MAX_RESOURCE_URL_BYTES:
        raise ValueError("curated resource URL exceeds the parser length limit")
    if any(ord(character) <= 0x20 or character.isspace() for character in url):
        raise ValueError("curated resource URL contains whitespace or control characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as error:
        raise ValueError("curated resource URL has an invalid authority") from error
    if (
        parts.scheme.lower() != "https"
        or not parts.netloc
        or parts.hostname is None
        or parts.username is not None
        or parts.password is not None
        or port is not None
        or parts.fragment
    ):
        raise ValueError(
            "curated resource URL must be absolute default-port HTTPS "
            "without user info or fragment"
        )
    return _source_domain(parts.hostname)


def _candidate_id(domain: str) -> str:
    return f"curated-{hashlib.sha256(domain.encode('ascii')).hexdigest()[:20]}"


def build_curated_source_receipt(raw: bytes) -> dict[str, Any]:
    """Freeze all supplied domains and compact, non-authoritative URL hints."""

    if not isinstance(raw, bytes) or len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("curated source must be bounded raw bytes")
    source = _parse_json(raw, label="curated source")
    if not isinstance(source, list) or not 1 <= len(source) <= MAX_DOMAINS:
        raise ValueError("curated source must be a non-empty bounded list")

    candidates: list[dict[str, Any]] = []
    safety_matches: list[dict[str, str]] = []
    seen_domains: set[str] = set()
    total_urls = 0
    for index, item in enumerate(source, start=1):
        if not isinstance(item, dict) or set(item) != {"crUX_domain", "resources"}:
            raise ValueError(f"curated source item {index} has invalid fields")
        domain = _source_domain(item["crUX_domain"])
        if domain in seen_domains:
            raise ValueError(f"curated source repeats domain {domain!r}")
        seen_domains.add(domain)
        groups = item["resources"]
        if not isinstance(groups, list) or len(groups) > MAX_RESOURCE_GROUPS_PER_DOMAIN:
            raise ValueError(f"curated source item {index} has invalid resource groups")

        hints: list[dict[str, Any]] = []
        seen_origins: set[str] = set()
        domain_url_count = 0
        for group in groups:
            if not isinstance(group, dict) or set(group) != {"resource_domain", "resource_urls"}:
                raise ValueError(f"curated source item {index} has invalid resource group fields")
            resource_domain = _source_domain(group["resource_domain"])
            if resource_domain in seen_origins:
                raise ValueError(
                    f"curated source item {index} repeats resource origin {resource_domain!r}"
                )
            seen_origins.add(resource_domain)
            urls = group["resource_urls"]
            if not isinstance(urls, list):
                raise ValueError(f"curated source item {index} resource URLs must be a list")
            domain_url_count += len(urls)
            if domain_url_count > MAX_RESOURCE_URLS_PER_DOMAIN:
                raise ValueError(f"curated source item {index} exceeds the URL parser limit")
            for url in urls:
                if _https_resource_host(url) != resource_domain:
                    raise ValueError(
                        f"curated source item {index} resource URL host differs from its group"
                    )
            hints.append(
                {
                    "origin": f"https://{resource_domain}",
                    "url_count": len(urls),
                    "urls_sha256": canonical_json_sha256(urls),
                }
            )
        total_urls += domain_url_count
        candidates.append(
            {
                "candidate_id": _candidate_id(domain),
                "domain": domain,
                "source_index": index,
                "observed_resource_url_count": domain_url_count,
                "origin_hints": hints,
            }
        )
        reason = unsafe_catalogue_domain_reason(domain)
        if reason is not None:
            safety_matches.append({"domain": domain, "reason": reason})

    return bind_receipt(
        {
            "source_format": SOURCE_FORMAT,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "source_byte_count": len(raw),
            "ordering_policy": ORDERING_POLICY,
            "candidate_count": len(candidates),
            "observed_resource_url_count": total_urls,
            "domain_safety_policy": {
                "policy": DOMAIN_SAFETY_POLICY["policy"],
                "sha256": canonical_json_sha256(DOMAIN_SAFETY_POLICY),
            },
            "pre_browser_safety_matches": safety_matches,
            "candidates": candidates,
        },
        receipt_type=RECEIPT_TYPE,
    )


def validate_curated_source_receipt(
    value: Mapping[str, Any], *, source_bytes: bytes | None = None
) -> tuple[str, ...]:
    """Check receipt structure and, when supplied, its exact source bytes."""

    payload = validate_hash_bound_receipt(value, expected_type=RECEIPT_TYPE)
    if set(payload) != {
        "source_format",
        "source_sha256",
        "source_byte_count",
        "ordering_policy",
        "candidate_count",
        "observed_resource_url_count",
        "domain_safety_policy",
        "pre_browser_safety_matches",
        "candidates",
    }:
        raise ValueError("curated source receipt fields differ from the contract")
    if (
        payload["source_format"] != SOURCE_FORMAT
        or payload["ordering_policy"] != ORDERING_POLICY
        or not isinstance(payload["source_sha256"], str)
        or _SHA256.fullmatch(payload["source_sha256"]) is None
        or type(payload["source_byte_count"]) is not int
        or not 1 <= payload["source_byte_count"] <= MAX_SOURCE_BYTES
        or payload["domain_safety_policy"]
        != {
            "policy": DOMAIN_SAFETY_POLICY["policy"],
            "sha256": canonical_json_sha256(DOMAIN_SAFETY_POLICY),
        }
    ):
        raise ValueError("curated source receipt identity or policy differs from the contract")
    candidates = payload["candidates"]
    if (
        not isinstance(candidates, list)
        or not 1 <= len(candidates) <= MAX_DOMAINS
        or type(payload["candidate_count"]) is not int
        or payload["candidate_count"] != len(candidates)
    ):
        raise ValueError("curated source receipt candidate count is invalid")

    domains: list[str] = []
    seen_domains: set[str] = set()
    total_urls = 0
    for index, candidate in enumerate(candidates, start=1):
        if not isinstance(candidate, dict) or set(candidate) != {
            "candidate_id", "domain", "source_index", "observed_resource_url_count", "origin_hints"
        }:
            raise ValueError("curated source receipt candidate fields are invalid")
        domain = canonical_domain(candidate["domain"])
        if domain in seen_domains or candidate["candidate_id"] != _candidate_id(domain):
            raise ValueError("curated source receipt candidate identity is invalid")
        seen_domains.add(domain)
        if type(candidate["source_index"]) is not int or candidate["source_index"] != index:
            raise ValueError("curated source receipt order is invalid")
        hints = candidate["origin_hints"]
        if not isinstance(hints, list) or len(hints) > MAX_RESOURCE_GROUPS_PER_DOMAIN:
            raise ValueError("curated source receipt origin hints are invalid")
        seen_origins: set[str] = set()
        domain_url_count = 0
        for hint in hints:
            if not isinstance(hint, dict) or set(hint) != {"origin", "url_count", "urls_sha256"}:
                raise ValueError("curated source receipt origin hint fields are invalid")
            origin = hint["origin"]
            if not isinstance(origin, str) or not origin.startswith("https://"):
                raise ValueError("curated source receipt origin hint is invalid")
            host = canonical_domain(origin.removeprefix("https://"))
            if origin != f"https://{host}" or host in seen_origins:
                raise ValueError("curated source receipt origin hint is invalid")
            seen_origins.add(host)
            count = hint["url_count"]
            digest = hint["urls_sha256"]
            if (
                type(count) is not int
                or count < 0
                or not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
            ):
                raise ValueError("curated source receipt URL hint is invalid")
            domain_url_count += count
        if (
            domain_url_count > MAX_RESOURCE_URLS_PER_DOMAIN
            or type(candidate["observed_resource_url_count"]) is not int
            or candidate["observed_resource_url_count"] != domain_url_count
        ):
            raise ValueError("curated source receipt URL count is invalid")
        total_urls += domain_url_count
        domains.append(domain)

    if (
        type(payload["observed_resource_url_count"]) is not int
        or payload["observed_resource_url_count"] != total_urls
        or payload["pre_browser_safety_matches"]
        != [
            {"domain": domain, "reason": reason}
            for domain in domains
            if (reason := unsafe_catalogue_domain_reason(domain)) is not None
        ]
    ):
        raise ValueError("curated source receipt totals or safety matches are invalid")
    if source_bytes is not None and value != build_curated_source_receipt(source_bytes):
        raise ValueError("curated source receipt differs from its exact source bytes")
    return tuple(domains)


def write_curated_source_receipt(path: Path, value: Mapping[str, Any]) -> Path:
    validate_curated_source_receipt(value)
    return write_create_only_json(path, value)


def load_curated_source_receipt(
    path: Path, *, source_path: Path | None = None
) -> tuple[dict[str, Any], tuple[str, ...]]:
    raw = _read_regular_bounded(
        path, label="curated source receipt", limit=MAX_RECEIPT_BYTES
    )
    value = _parse_json(raw, label="curated source receipt")
    if not isinstance(value, dict):
        raise ValueError("curated source receipt must be a JSON object")
    source_bytes = (
        _read_regular_bounded(source_path, label="curated source")
        if source_path is not None
        else None
    )
    return value, validate_curated_source_receipt(value, source_bytes=source_bytes)


def import_curated_source(source_path: Path, destination: Path) -> dict[str, Any]:
    """Read one source file and publish its validated receipt create-only."""

    raw = _read_regular_bounded(source_path, label="curated source")
    receipt = build_curated_source_receipt(raw)
    validate_curated_source_receipt(receipt, source_bytes=raw)
    write_curated_source_receipt(destination, receipt)
    return {
        "receipt_path": str(Path(os.path.abspath(destination))),
        "receipt_sha256": hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
        "source_sha256": receipt["payload"]["source_sha256"],
        "source_byte_count": receipt["payload"]["source_byte_count"],
        "candidate_count": receipt["payload"]["candidate_count"],
        "observed_resource_url_count": receipt["payload"]["observed_resource_url_count"],
        "pre_browser_safety_match_count": len(receipt["payload"]["pre_browser_safety_matches"]),
    }
