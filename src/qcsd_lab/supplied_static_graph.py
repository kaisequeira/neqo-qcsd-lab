"""Import a supplied GET list without claiming browser or admission evidence.

The native input is deliberately a bare resource manifest. The separate binding
is a zero-credit input record, not research preparation or a qualified workload.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit

from .manifest import validate_manifest


INPUT_ROLE = "supplied-static-fixed-resource-replay-input-v1"
DAG_POLICY = "explicit-root-then-source-ordered-listed-GETs-v1"
HEADERS = (("accept", "*/*"), ("accept-encoding", "identity"),
           ("accept-language", "en-US,en;q=0.9"))
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("supplied JSON contains a duplicate key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ValueError("supplied JSON contains a non-finite number")


def _domain(value: Any) -> str:
    if (not isinstance(value, str) or _DOMAIN.fullmatch(value) is None
        or "." not in value or ".." in value
        or any(not label or len(label) > 63 or label.startswith("-")
               or label.endswith("-") for label in value.split("."))
        or len(value) > 253):
        raise ValueError("supplied domain is not canonical DNS")
    return value


def _source(raw: bytes, expected_sha256: str) -> list[dict[str, Any]]:
    if (not isinstance(raw, bytes) or not isinstance(expected_sha256, str)
        or _SHA.fullmatch(expected_sha256) is None or digest(raw) != expected_sha256):
        raise ValueError("supplied source differs from its explicit byte hash")
    try:
        rows = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("supplied source is not UTF-8 JSON") from error
    if not isinstance(rows, list) or not rows:
        raise ValueError("supplied source needs an ordered list of domains")
    seen_domains = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"crUX_domain", "resources"}:
            raise ValueError("supplied domain fields differ")
        domain = _domain(row["crUX_domain"])
        if domain in seen_domains:
            raise ValueError("supplied domain repeats")
        seen_domains.add(domain)
        if not isinstance(row["resources"], list):
            raise ValueError("supplied resource groups must be an ordered list")
        groups, urls = set(), set()
        for group in row["resources"]:
            if (not isinstance(group, dict)
                or set(group) != {"resource_domain", "resource_urls"}):
                raise ValueError("supplied resource group fields differ")
            host = _domain(group["resource_domain"])
            if host in groups:
                raise ValueError("supplied resource domain repeats")
            groups.add(host)
            if not isinstance(group["resource_urls"], list) or not group["resource_urls"]:
                raise ValueError("supplied resource group is empty")
            for url in group["resource_urls"]:
                if not isinstance(url, str) or any(c.isspace() for c in url):
                    raise ValueError("supplied resource address is malformed")
                try:
                    parsed = urlsplit(url)
                    valid = (parsed.scheme == "https" and parsed.netloc == host
                             and bool(parsed.path) and not parsed.fragment
                             and parsed.username is None and parsed.password is None)
                except ValueError:
                    valid = False
                if not valid or url in urls:
                    raise ValueError("supplied resource address is invalid or repeated")
                urls.add(url)
    return rows


def import_graph(source_bytes: bytes, expected_source_sha256: str,
                 domain: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return an unqualified Native input and its exact source-list binding."""
    domain = _domain(domain)
    rows = _source(source_bytes, expected_source_sha256)
    selected = [(index, row) for index, row in enumerate(rows, 1)
                if row["crUX_domain"] == domain]
    if len(selected) != 1:
        raise ValueError("selected domain is absent from supplied source")
    position, row = selected[0]
    if not row["resources"]:
        raise ValueError("selected domain has no supplied resource graph")
    primary = f"https://{domain}/"
    resources = [{"id": 0, "url": primary, "type": "Document", "depends_on": [],
                  "headers": [list(header) for header in HEADERS]}]
    by_url = {primary: 0}
    supplied_ids = []
    for group in row["resources"]:
        for url in group["resource_urls"]:
            if url not in by_url:
                by_url[url] = len(resources)
                resources.append({"id": len(resources), "url": url, "type": "Other",
                                  "depends_on": [0],
                                  "headers": [list(header) for header in HEADERS]})
            supplied_ids.append(by_url[url])
    origins = sorted({f"https://{urlsplit(resource['url']).netloc}"
                      for resource in resources})
    if len(origins) < 2:
        raise ValueError("supplied graph has no resource outside its primary origin")
    manifest = {"resources": resources}
    validate_manifest(manifest)
    binding = {
        "schema_version": 1, "record_type": INPUT_ROLE,
        "scientific_credit": False, "site_credit": 0,
        "formal_accepted_trace_count": 0, "source_sha256": expected_source_sha256,
        "domain": domain, "source_position": position,
        "supplied_candidate_sha256": digest(canonical_bytes(row)),
        "supplied_resource_count": len(supplied_ids), "supplied_resource_ids": supplied_ids,
        "primary_resource_id": 0, "primary_added": primary not in {
            url for group in row["resources"] for url in group["resource_urls"]},
        "dag_policy": DAG_POLICY, "request_header_role": "fixed-replay-client-headers-v1",
        "origins": origins, "native_manifest_sha256": digest(canonical_bytes(manifest)),
        "evidence_state": "unqualified-input-only",
        "browser_discovery_claim": False,
    }
    return manifest, binding


def verify_import(source_bytes: bytes, expected_source_sha256: str, domain: str,
                  manifest: dict[str, Any], binding: dict[str, Any]) -> None:
    """Rebuild rather than trusting self-declared graph/hash/count fields."""
    actual_manifest, actual_binding = import_graph(source_bytes, expected_source_sha256, domain)
    if (canonical_bytes(manifest) != canonical_bytes(actual_manifest)
        or canonical_bytes(binding) != canonical_bytes(actual_binding)):
        raise ValueError("imported graph or binding differs from the complete supplied list")
