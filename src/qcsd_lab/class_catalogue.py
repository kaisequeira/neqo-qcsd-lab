"""Pinned class-catalogue and page-stability contracts for the 100-class study.

This module is intentionally network independent.  It validates bytes supplied
by a caller, chooses deterministic candidates, and validates observations made
by an injected browser/capture implementation.  Importing it never downloads a
Tranco list, opens a URL, waits for a probe, or mutates an evidence directory.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from qcsd_lab.class_study import (
    CANDIDATES_PER_STRATUM,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    canonical_domain,
    deterministic_candidate_order,
    rank_stratum,
    validate_hash_bound_receipt,
    write_create_only_json,
)

TRANCO_MAX_RANK = 1_000_000
TRANCO_RECEIPT_TYPE = "qcsd-class-study-tranco-snapshot"
STABILITY_RECEIPT_TYPE = "qcsd-class-study-page-stability"
CANDIDATE_RECEIPT_TYPE = "qcsd-class-study-candidate-catalogue"
CATALOGUE_SCHEMA_VERSION = 1

MAX_DISCOVERED_PAGES = 4
MAX_PAGE_CANDIDATES = 1 + MAX_DISCOVERED_PAGES
MAX_HTML_BODY_BYTES = 1_048_576

HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})
FORBIDDEN_PAGE_TOKENS = frozenset(
    {
        "account",
        "accounts",
        "admin",
        "auth",
        "basket",
        "cart",
        "checkout",
        "dashboard",
        "forgot-password",
        "login",
        "logout",
        "password",
        "payment",
        "profile",
        "register",
        "search",
        "session",
        "settings",
        "sign-in",
        "signin",
        "sign-out",
        "signout",
        "sign-up",
        "signup",
        "user",
        "users",
    }
)
FORBIDDEN_FILE_SUFFIXES = frozenset(
    {
        ".7z",
        ".avi",
        ".bin",
        ".csv",
        ".doc",
        ".docx",
        ".dmg",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".json",
        ".m4a",
        ".mov",
        ".mp3",
        ".mp4",
        ".pdf",
        ".png",
        ".ppt",
        ".pptx",
        ".rar",
        ".rss",
        ".svg",
        ".tar",
        ".tgz",
        ".txt",
        ".wav",
        ".webm",
        ".webp",
        ".xls",
        ".xlsx",
        ".xml",
        ".zip",
    }
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_LIST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_TRANCO_LABEL_RE = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")


@dataclass(frozen=True)
class ProbeWindow:
    """One preregistered elapsed-time window, measured from one baseline."""

    probe_id: str
    target_ms: int
    earliest_ms: int
    latest_ms: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "target_ms": self.target_ms,
            "earliest_ms": self.earliest_ms,
            "latest_ms": self.latest_ms,
        }


# The short probe has a five-second scheduling allowance.  Long probes have a
# fifteen-minute allowance to tolerate host suspend/resume and runner startup,
# while still preventing an arbitrary collection time from being relabelled.
STABILITY_PROBE_WINDOWS = (
    ProbeWindow("t+30s", 30_000, 25_000, 35_000),
    ProbeWindow("t+24h", 86_400_000, 85_500_000, 87_300_000),
    ProbeWindow("t+72h", 259_200_000, 258_300_000, 260_100_000),
)


@dataclass(frozen=True)
class TrancoEntry:
    rank: int
    domain: str

    def as_dict(self) -> dict[str, Any]:
        return {"rank": self.rank, "domain": self.domain}


@dataclass(frozen=True)
class TrancoSnapshotMetadata:
    list_id: str
    list_sha256: str
    source_url: str
    retrieved_at: str
    row_count: int
    entries_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "list_id": self.list_id,
            "list_sha256": self.list_sha256,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "row_count": self.row_count,
            "entries_sha256": self.entries_sha256,
        }


@dataclass(frozen=True)
class TrancoSnapshot:
    metadata: TrancoSnapshotMetadata
    entries: tuple[TrancoEntry, ...]


@dataclass(frozen=True)
class DiscoveredLink:
    """A browser-supplied navigation candidate; no fetch is performed here."""

    url: str
    content_type: str


@dataclass(frozen=True)
class PageCandidate:
    candidate_domain: str
    registrable_domain: str
    url: str
    source: str
    ordinal: int
    discovery_content_type: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "candidate_domain": self.candidate_domain,
            "registrable_domain": self.registrable_domain,
            "url": self.url,
            "source": self.source,
            "ordinal": self.ordinal,
            "discovery_content_type": self.discovery_content_type,
        }


@dataclass(frozen=True)
class StabilityObservation:
    """One browser/preparation result supplied at a requested probe window."""

    probe_id: str
    observed_at: str
    elapsed_ms: int
    final_url: str
    status: int
    content_type: str
    body_bytes: int
    body_sha256: str
    resource_graph_sha256: str
    prepared_workload_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "observed_at": self.observed_at,
            "elapsed_ms": self.elapsed_ms,
            "final_url": self.final_url,
            "status": self.status,
            "content_type": self.content_type,
            "body_bytes": self.body_bytes,
            "body_sha256": self.body_sha256,
            "resource_graph_sha256": self.resource_graph_sha256,
            "prepared_workload_sha256": self.prepared_workload_sha256,
        }


@dataclass(frozen=True)
class StabilityDecision:
    eligible: bool
    reasons: tuple[str, ...]
    stable_values: Mapping[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "reasons": list(self.reasons),
            "stable_values": dict(self.stable_values) if self.stable_values is not None else None,
        }


ProbeCallback = Callable[[PageCandidate, ProbeWindow], StabilityObservation]


def parse_tranco_csv(
    data: bytes,
    *,
    list_id: str,
    expected_sha256: str,
    source_url: str,
    retrieved_at: str,
    expected_rows: int = TRANCO_MAX_RANK,
) -> TrancoSnapshot:
    """Parse and hash-check one complete rank/domain Tranco CSV snapshot.

    The production default requires ranks 1 through 1,000,000 without gaps.
    ``expected_rows`` exists so the same parser can be exercised using small
    fixtures; callers selecting the study cohort still need 120 entries in each
    fixed rank stratum.
    """

    if not isinstance(data, bytes):
        raise ValueError("Tranco CSV input must be bytes")
    digest = _validate_sha256(expected_sha256, label="Tranco list SHA-256")
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Tranco CSV SHA-256 does not match its pin")
    _validate_list_id(list_id)
    _validate_source_url(source_url)
    _parse_utc_timestamp(retrieved_at, label="Tranco retrieval timestamp")
    if type(expected_rows) is not int or not (1 <= expected_rows <= TRANCO_MAX_RANK):
        raise ValueError("expected Tranco row count must be in 1..1,000,000")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("Tranco CSV must not contain a UTF-8 byte-order mark")
    if b"\x00" in data:
        raise ValueError("Tranco CSV must not contain NUL bytes")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("Tranco CSV is not strict UTF-8") from error

    entries: list[TrancoEntry] = []
    domains: set[str] = set()
    try:
        rows = csv.reader(io.StringIO(text, newline=""), strict=True)
        for expected_rank, row in enumerate(rows, start=1):
            if len(row) != 2:
                raise ValueError("every Tranco CSV row must have exactly two columns")
            rank_text, domain_text = row
            if rank_text != str(expected_rank):
                raise ValueError(
                    f"Tranco CSV rank {expected_rank} is missing, duplicated, or non-canonical"
                )
            domain = _canonical_tranco_domain(domain_text)
            if domain in domains:
                raise ValueError(f"Tranco CSV contains a duplicate domain: {domain}")
            domains.add(domain)
            entries.append(TrancoEntry(expected_rank, domain))
    except csv.Error as error:
        raise ValueError("Tranco CSV is malformed") from error
    if len(entries) != expected_rows:
        raise ValueError(
            f"Tranco CSV must contain exactly {expected_rows} rows; found {len(entries)}"
        )

    frozen = tuple(entries)
    metadata = TrancoSnapshotMetadata(
        list_id=list_id,
        list_sha256=digest,
        source_url=source_url,
        retrieved_at=retrieved_at,
        row_count=len(frozen),
        entries_sha256=tranco_entries_sha256(frozen),
    )
    snapshot = TrancoSnapshot(metadata, frozen)
    validate_tranco_snapshot(snapshot)
    return snapshot


def tranco_entries_sha256(entries: Iterable[TrancoEntry]) -> str:
    """Hash a canonical parsed rank/domain stream independently of CSV newlines."""

    digest = hashlib.sha256()
    for entry in entries:
        if not isinstance(entry, TrancoEntry):
            raise ValueError("Tranco entries must be TrancoEntry values")
        digest.update(f"{entry.rank},{entry.domain}\n".encode())
    return digest.hexdigest()


def validate_tranco_snapshot(snapshot: TrancoSnapshot) -> None:
    """Validate a parsed or reconstructed snapshot before selection/receipting."""

    if not isinstance(snapshot, TrancoSnapshot):
        raise ValueError("Tranco snapshot has the wrong type")
    metadata = snapshot.metadata
    _validate_list_id(metadata.list_id)
    _validate_sha256(metadata.list_sha256, label="Tranco list SHA-256")
    _validate_source_url(metadata.source_url)
    _parse_utc_timestamp(metadata.retrieved_at, label="Tranco retrieval timestamp")
    if type(metadata.row_count) is not int or metadata.row_count != len(snapshot.entries):
        raise ValueError("Tranco snapshot row count does not match its entries")
    if not (1 <= metadata.row_count <= TRANCO_MAX_RANK):
        raise ValueError("Tranco snapshot row count is outside 1..1,000,000")
    if metadata.entries_sha256 != tranco_entries_sha256(snapshot.entries):
        raise ValueError("Tranco parsed-entry SHA-256 does not verify")

    previous_rank = 0
    domains: set[str] = set()
    ranks: set[int] = set()
    for entry in snapshot.entries:
        if type(entry.rank) is not int or not (1 <= entry.rank <= TRANCO_MAX_RANK):
            raise ValueError("Tranco entry rank is outside 1..1,000,000")
        if entry.rank <= previous_rank:
            raise ValueError("Tranco snapshot ranks must be strictly increasing")
        if entry.rank in ranks:
            raise ValueError("Tranco snapshot contains a duplicate rank")
        _canonical_tranco_domain(entry.domain)
        if entry.domain in domains:
            raise ValueError("Tranco snapshot contains a duplicate domain")
        previous_rank = entry.rank
        ranks.add(entry.rank)
        domains.add(entry.domain)


def build_tranco_snapshot_receipt(snapshot: TrancoSnapshot) -> dict[str, Any]:
    """Build a compact receipt for the exact pinned source and parsed stream."""

    validate_tranco_snapshot(snapshot)
    payload = {
        "study_id": STUDY_ID,
        "catalogue_schema_version": CATALOGUE_SCHEMA_VERSION,
        "snapshot": snapshot.metadata.as_dict(),
        "parser_contract": {
            "encoding": "utf-8-strict-no-bom",
            "columns": ["rank", "canonical_tranco_domain"],
            "production_rank_range": [1, TRANCO_MAX_RANK],
            "rank_order": "strictly-increasing",
            "duplicate_domains": "rejected",
        },
    }
    return bind_receipt(payload, receipt_type=TRANCO_RECEIPT_TYPE)


def validate_tranco_snapshot_receipt(value: Mapping[str, Any]) -> TrancoSnapshotMetadata:
    """Validate a compact snapshot receipt and return its pinned metadata."""

    payload = validate_hash_bound_receipt(value, expected_type=TRANCO_RECEIPT_TYPE)
    if set(payload) != {"study_id", "catalogue_schema_version", "snapshot", "parser_contract"}:
        raise ValueError("Tranco snapshot receipt payload fields differ from the contract")
    if payload["study_id"] != STUDY_ID or payload["catalogue_schema_version"] != 1:
        raise ValueError("Tranco snapshot receipt identifies the wrong study or schema")
    raw = payload["snapshot"]
    if not isinstance(raw, Mapping) or set(raw) != {
        "list_id",
        "list_sha256",
        "source_url",
        "retrieved_at",
        "row_count",
        "entries_sha256",
    }:
        raise ValueError("Tranco snapshot receipt metadata fields differ from the contract")
    metadata = TrancoSnapshotMetadata(
        list_id=raw["list_id"],
        list_sha256=raw["list_sha256"],
        source_url=raw["source_url"],
        retrieved_at=raw["retrieved_at"],
        row_count=raw["row_count"],
        entries_sha256=raw["entries_sha256"],
    )
    _validate_list_id(metadata.list_id)
    _validate_sha256(metadata.list_sha256, label="Tranco list SHA-256")
    _validate_source_url(metadata.source_url)
    _parse_utc_timestamp(metadata.retrieved_at, label="Tranco retrieval timestamp")
    _validate_sha256(metadata.entries_sha256, label="Tranco entry-stream SHA-256")
    if type(metadata.row_count) is not int or not (1 <= metadata.row_count <= TRANCO_MAX_RANK):
        raise ValueError("Tranco snapshot receipt row count is invalid")

    expected_parser = {
        "encoding": "utf-8-strict-no-bom",
        "columns": ["rank", "canonical_tranco_domain"],
        "production_rank_range": [1, TRANCO_MAX_RANK],
        "rank_order": "strictly-increasing",
        "duplicate_domains": "rejected",
    }
    if payload["parser_contract"] != expected_parser:
        raise ValueError("Tranco snapshot receipt parser contract differs from the implementation")
    return metadata


def sample_tranco_candidates(snapshot: TrancoSnapshot) -> tuple[ClassCandidate, ...]:
    """Select exactly 120 hash-ordered candidates from each fixed rank stratum."""

    validate_tranco_snapshot(snapshot)
    selected: list[ClassCandidate] = []
    for stratum in TRANCO_RANK_STRATA:
        members: list[ClassCandidate] = []
        for entry in snapshot.entries:
            if not stratum.contains(entry.rank):
                continue
            try:
                domain = canonical_domain(entry.domain)
            except ValueError:
                # The official Tranco stream can contain syntactically valid
                # ranking entries such as ``_wildcard_.ph``.  They remain in
                # the raw-list hash but cannot become browser targets.
                continue
            members.append(
                ClassCandidate(
                    candidate_id=f"tranco-{entry.rank:07d}",
                    domain=domain,
                    rank=entry.rank,
                    eligible=False,
                )
            )
        if len(members) < CANDIDATES_PER_STRATUM:
            raise ValueError(
                f"Tranco snapshot has only {len(members)} entries in stratum {stratum.id}; "
                f"{CANDIDATES_PER_STRATUM} are required"
            )
        ordered = deterministic_candidate_order(
            members,
            tranco_list_sha256=snapshot.metadata.list_sha256,
        )
        selected.extend(ordered[:CANDIDATES_PER_STRATUM])
    return deterministic_candidate_order(
        selected,
        tranco_list_sha256=snapshot.metadata.list_sha256,
    )


def build_candidate_catalogue_receipt(snapshot: TrancoSnapshot) -> dict[str, Any]:
    """Freeze the 600-domain prospective population before any availability probe."""

    candidates = sample_tranco_candidates(snapshot)
    payload = {
        "study_id": STUDY_ID,
        "catalogue_schema_version": CATALOGUE_SCHEMA_VERSION,
        "tranco": snapshot.metadata.as_dict(),
        "selection": {
            "rank_strata": [stratum.as_dict() for stratum in TRANCO_RANK_STRATA],
            "per_stratum": CANDIDATES_PER_STRATUM,
            "ordering": "sha256(list_sha256 || study_id || canonical_domain)",
            "outcome_fields_used": [],
        },
        "candidates": [candidate.as_dict() for candidate in candidates],
    }
    return bind_receipt(payload, receipt_type=CANDIDATE_RECEIPT_TYPE)


def validate_candidate_catalogue_receipt(
    value: Mapping[str, Any],
) -> tuple[ClassCandidate, ...]:
    """Validate the prospective list without consulting later probe outcomes."""

    payload = validate_hash_bound_receipt(value, expected_type=CANDIDATE_RECEIPT_TYPE)
    if set(payload) != {
        "study_id",
        "catalogue_schema_version",
        "tranco",
        "selection",
        "candidates",
    }:
        raise ValueError("candidate catalogue receipt fields differ from the contract")
    if payload["study_id"] != STUDY_ID or payload["catalogue_schema_version"] != 1:
        raise ValueError("candidate catalogue identifies the wrong study or schema")
    tranco = payload["tranco"]
    if not isinstance(tranco, Mapping) or set(tranco) != {
        "list_id",
        "list_sha256",
        "source_url",
        "retrieved_at",
        "row_count",
        "entries_sha256",
    }:
        raise ValueError("candidate catalogue Tranco binding is invalid")
    metadata = TrancoSnapshotMetadata(
        list_id=tranco["list_id"],
        list_sha256=tranco["list_sha256"],
        source_url=tranco["source_url"],
        retrieved_at=tranco["retrieved_at"],
        row_count=tranco["row_count"],
        entries_sha256=tranco["entries_sha256"],
    )
    _validate_list_id(metadata.list_id)
    _validate_sha256(metadata.list_sha256, label="Tranco list SHA-256")
    _validate_source_url(metadata.source_url)
    _parse_utc_timestamp(metadata.retrieved_at, label="Tranco retrieval timestamp")
    _validate_sha256(metadata.entries_sha256, label="Tranco entry-stream SHA-256")
    if metadata.row_count != TRANCO_MAX_RANK:
        raise ValueError("candidate catalogue requires a complete one-million-row Tranco list")
    expected_selection = {
        "rank_strata": [stratum.as_dict() for stratum in TRANCO_RANK_STRATA],
        "per_stratum": CANDIDATES_PER_STRATUM,
        "ordering": "sha256(list_sha256 || study_id || canonical_domain)",
        "outcome_fields_used": [],
    }
    if payload["selection"] != expected_selection:
        raise ValueError("candidate catalogue selection policy differs from the contract")
    raw_candidates = payload["candidates"]
    if not isinstance(raw_candidates, list):
        raise ValueError("candidate catalogue candidates must be a list")
    candidates: list[ClassCandidate] = []
    for raw in raw_candidates:
        if not isinstance(raw, Mapping) or set(raw) != {
            "candidate_id",
            "domain",
            "rank",
            "stratum",
            "eligible",
        }:
            raise ValueError("candidate catalogue candidate fields are invalid")
        candidate = ClassCandidate(
            candidate_id=raw["candidate_id"],
            domain=raw["domain"],
            rank=raw["rank"],
            eligible=raw["eligible"],
        )
        if candidate.eligible is not False or raw["stratum"] != rank_stratum(candidate.rank).id:
            raise ValueError("prospective candidate carries an outcome or incorrect stratum")
        candidates.append(candidate)
    ordered = deterministic_candidate_order(
        candidates,
        tranco_list_sha256=metadata.list_sha256,
    )
    if tuple(candidates) != ordered:
        raise ValueError("candidate catalogue order differs from its Tranco-bound hash order")
    if len(ordered) != CANDIDATES_PER_STRATUM * len(TRANCO_RANK_STRATA):
        raise ValueError(
            f"candidate catalogue must contain exactly "
            f"{CANDIDATES_PER_STRATUM * len(TRANCO_RANK_STRATA)} domains"
        )
    for stratum in TRANCO_RANK_STRATA:
        if sum(candidate.stratum == stratum for candidate in ordered) != CANDIDATES_PER_STRATUM:
            raise ValueError(f"candidate catalogue stratum {stratum.id} is incomplete")
    return ordered


def write_candidate_catalogue_receipt(path: Path, value: Mapping[str, Any]) -> Path:
    validate_candidate_catalogue_receipt(value)
    return write_create_only_json(path, value)


def load_candidate_catalogue_receipt(
    path: Path,
) -> tuple[dict[str, Any], tuple[ClassCandidate, ...]]:
    source = Path(os.path.abspath(path))
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"candidate catalogue is not a regular file: {source}")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"candidate catalogue is not valid JSON: {source}") from error
    if not isinstance(value, dict):
        raise ValueError("candidate catalogue must be a JSON object")
    return value, validate_candidate_catalogue_receipt(value)


def select_page_candidates(
    candidate_domain: str,
    *,
    registrable_domain: str,
    discovered_links: Iterable[DiscoveredLink],
) -> tuple[PageCandidate, ...]:
    """Return the canonical homepage plus at most four safe deterministic links.

    The hostname boundary is an explicit caller-supplied input.  Production
    class acquisition passes the exact frozen Tranco candidate domain (and its
    subdomains); this helper never widens it with a local suffix heuristic.
    """

    domain = canonical_domain(candidate_domain)
    registrable = canonical_domain(registrable_domain)
    if not _same_registrable_domain(domain, registrable):
        raise ValueError("candidate domain is not within the supplied registrable domain")

    homepage = PageCandidate(
        candidate_domain=domain,
        registrable_domain=registrable,
        url=f"https://{domain}/",
        source="canonical-homepage",
        ordinal=0,
        discovery_content_type=None,
    )
    accepted: dict[str, str] = {}
    for raw in discovered_links:
        if not isinstance(raw, DiscoveredLink):
            raise ValueError("discovered links must be DiscoveredLink values")
        media_type = _normalise_media_type(raw.content_type)
        if media_type not in HTML_MEDIA_TYPES:
            continue
        try:
            url = canonical_query_free_html_url(
                raw.url,
                registrable_domain=registrable,
            )
        except ValueError:
            continue
        if url == homepage.url or _has_forbidden_page_component(url):
            continue
        accepted[url] = media_type

    def order_key(item: tuple[str, str]) -> tuple[str, str]:
        url, _ = item
        digest = hashlib.sha256(f"{STUDY_ID}\0{domain}\0{url}".encode()).hexdigest()
        return digest, url

    links = sorted(accepted.items(), key=order_key)[:MAX_DISCOVERED_PAGES]
    pages = [homepage]
    pages.extend(
        PageCandidate(
            candidate_domain=domain,
            registrable_domain=registrable,
            url=url,
            source="same-registrable-domain-link",
            ordinal=index,
            discovery_content_type=content_type,
        )
        for index, (url, content_type) in enumerate(links, start=1)
    )
    result = tuple(pages)
    for page in result:
        validate_page_candidate(page)
    return result


def canonical_query_free_html_url(url: str, *, registrable_domain: str) -> str:
    """Canonicalise one conservative HTTPS page URL or fail closed."""

    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError("page URL must be a non-empty bounded string")
    if any(ord(character) < 0x20 or character.isspace() for character in url):
        raise ValueError("page URL contains whitespace or control characters")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.netloc:
        raise ValueError("page URL must use absolute HTTPS")
    if parts.username is not None or parts.password is not None:
        raise ValueError("page URL must not contain user information")
    try:
        port = parts.port
    except ValueError as error:
        raise ValueError("page URL has an invalid port") from error
    if port is not None:
        raise ValueError("page URL must not contain an explicit port")
    if parts.query or parts.fragment:
        raise ValueError("page URL must be query- and fragment-free")
    host = _canonical_url_host(parts.hostname)
    registrable = canonical_domain(registrable_domain)
    if not _same_registrable_domain(host, registrable):
        raise ValueError("page URL is outside the supplied registrable domain")

    path = parts.path or "/"
    if len(path) > 2048 or "\\" in path or "%" in path:
        raise ValueError("page URL path uses an unsafe or ambiguous spelling")
    decoded = unquote(path, errors="strict")
    if any(ord(character) < 0x20 for character in decoded):
        raise ValueError("page URL path contains control characters")
    segments = decoded.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise ValueError("page URL path contains dot segments")
    lowered = decoded.lower().rstrip("/")
    if any(lowered.endswith(suffix) for suffix in FORBIDDEN_FILE_SUFFIXES):
        raise ValueError("page URL points to a non-HTML file suffix")
    return urlunsplit(("https", host, path, "", ""))


def validate_page_candidate(page: PageCandidate) -> None:
    """Validate a page candidate independently of its discovery caller."""

    if not isinstance(page, PageCandidate):
        raise ValueError("page candidate has the wrong type")
    domain = canonical_domain(page.candidate_domain)
    registrable = canonical_domain(page.registrable_domain)
    if not _same_registrable_domain(domain, registrable):
        raise ValueError("page candidate domain is outside its registrable domain")
    canonical = canonical_query_free_html_url(page.url, registrable_domain=registrable)
    if canonical != page.url:
        raise ValueError("page candidate URL is not canonical")
    if page.source == "canonical-homepage":
        if page.ordinal != 0 or page.url != f"https://{domain}/":
            raise ValueError("canonical homepage candidate identity is invalid")
        if page.discovery_content_type is not None:
            raise ValueError("canonical homepage has no discovery content type")
    elif page.source == "same-registrable-domain-link":
        if type(page.ordinal) is not int or not (1 <= page.ordinal <= MAX_DISCOVERED_PAGES):
            raise ValueError("discovered page ordinal is invalid")
        if _normalise_media_type(page.discovery_content_type) not in HTML_MEDIA_TYPES:
            raise ValueError("discovered page must have an HTML media type")
        if _has_forbidden_page_component(page.url):
            raise ValueError("discovered page contains a forbidden semantic token")
    else:
        raise ValueError("page candidate source is invalid")


def collect_stability_observations(
    page: PageCandidate,
    *,
    probe: ProbeCallback,
) -> tuple[StabilityObservation, ...]:
    """Invoke an explicit acquisition callback for the three fixed windows.

    The callback owns sleeping, HTTP/browser execution, workload preparation,
    and capture.  This function merely supplies the immutable schedule and
    validates the returned observation identities.
    """

    validate_page_candidate(page)
    if not callable(probe):
        raise ValueError("stability probe callback must be callable")
    observations = tuple(probe(page, window) for window in STABILITY_PROBE_WINDOWS)
    _validate_observation_shapes(observations)
    return observations


def derive_stability_decision(
    page: PageCandidate,
    *,
    baseline_started_at: str,
    observations: Sequence[StabilityObservation],
) -> StabilityDecision:
    """Apply the exact three-probe timing, acquisition, and drift gates."""

    validate_page_candidate(page)
    baseline = _parse_utc_timestamp(baseline_started_at, label="stability baseline timestamp")
    values = tuple(observations)
    _validate_observation_shapes(values)

    reasons: list[str] = []
    signatures: list[dict[str, Any]] = []
    previous_observed: datetime | None = None
    for window, observation in zip(STABILITY_PROBE_WINDOWS, values, strict=True):
        observed = _parse_utc_timestamp(
            observation.observed_at,
            label=f"{window.probe_id} observation timestamp",
        )
        if previous_observed is not None and observed <= previous_observed:
            _add_reason(reasons, "observation-timestamps-not-increasing")
        previous_observed = observed
        actual_elapsed_ms = round((observed - baseline).total_seconds() * 1000)
        if not window.earliest_ms <= observation.elapsed_ms <= window.latest_ms:
            _add_reason(reasons, f"{window.probe_id}-outside-schedule-window")
        if abs(actual_elapsed_ms - observation.elapsed_ms) > 1_000:
            _add_reason(reasons, f"{window.probe_id}-timestamp-elapsed-mismatch")

        try:
            final_url = canonical_query_free_html_url(
                observation.final_url,
                registrable_domain=page.registrable_domain,
            )
        except ValueError:
            final_url = observation.final_url
            _add_reason(reasons, f"{window.probe_id}-unsafe-final-url")
        else:
            if _has_forbidden_page_component(final_url):
                _add_reason(reasons, f"{window.probe_id}-forbidden-final-page")
        if observation.status != 200:
            _add_reason(reasons, f"{window.probe_id}-status-not-200")
        media_type = _normalise_media_type(observation.content_type)
        if media_type not in HTML_MEDIA_TYPES:
            _add_reason(reasons, f"{window.probe_id}-non-html-response")
        if observation.body_bytes <= 0:
            _add_reason(reasons, f"{window.probe_id}-empty-body")
        if observation.body_bytes > MAX_HTML_BODY_BYTES:
            _add_reason(reasons, f"{window.probe_id}-body-over-1mib")
        signatures.append(
            {
                "final_url": final_url,
                "status": observation.status,
                "content_type": media_type,
                "body_bytes": observation.body_bytes,
                "body_sha256": observation.body_sha256,
                "resource_graph_sha256": observation.resource_graph_sha256,
                "prepared_workload_sha256": observation.prepared_workload_sha256,
            }
        )

    comparisons = (
        ("final_url", "final-url-drift"),
        ("status", "status-drift"),
        ("content_type", "content-type-drift"),
        ("body_bytes", "body-length-drift"),
        ("body_sha256", "body-sha256-drift"),
        ("resource_graph_sha256", "resource-graph-sha256-drift"),
    )
    for field, reason in comparisons:
        if len({signature[field] for signature in signatures}) != 1:
            _add_reason(reasons, reason)
    # The full prepared manifest includes per-run packet qualification and
    # provenance, so its byte hash is not a longitudinal identity.  The first
    # probe is the immutable workload admitted after the independently stable
    # replay graph and response identities pass all three windows.
    stable = signatures[0] if not reasons else None
    return StabilityDecision(not reasons, tuple(reasons), stable)


def build_stability_receipt(
    candidate: ClassCandidate,
    page: PageCandidate,
    *,
    tranco_list_id: str,
    tranco_list_sha256: str,
    baseline_started_at: str,
    observations: Sequence[StabilityObservation],
) -> dict[str, Any]:
    """Build one hash-bound stability receipt without writing it."""

    _validate_candidate_identity(candidate)
    validate_page_candidate(page)
    if candidate.domain != page.candidate_domain:
        raise ValueError("stability candidate and page domain differ")
    _validate_list_id(tranco_list_id)
    list_sha = _validate_sha256(tranco_list_sha256, label="Tranco list SHA-256")
    _parse_utc_timestamp(baseline_started_at, label="stability baseline timestamp")
    frozen_observations = tuple(observations)
    decision = derive_stability_decision(
        page,
        baseline_started_at=baseline_started_at,
        observations=frozen_observations,
    )
    payload = _stability_payload(
        candidate,
        page,
        tranco_list_id=tranco_list_id,
        tranco_list_sha256=list_sha,
        baseline_started_at=baseline_started_at,
        observations=frozen_observations,
        decision=decision,
    )
    return bind_receipt(payload, receipt_type=STABILITY_RECEIPT_TYPE)


def validate_stability_receipt(value: Mapping[str, Any]) -> StabilityDecision:
    """Recompute every stability field and return the derived eligibility."""

    payload = validate_hash_bound_receipt(value, expected_type=STABILITY_RECEIPT_TYPE)
    expected_fields = {
        "study_id",
        "catalogue_schema_version",
        "candidate",
        "page",
        "tranco",
        "baseline_started_at",
        "probe_schedule",
        "observations",
        "decision",
    }
    if set(payload) != expected_fields:
        raise ValueError("stability receipt payload fields differ from the contract")
    if payload["study_id"] != STUDY_ID or payload["catalogue_schema_version"] != 1:
        raise ValueError("stability receipt identifies the wrong study or schema")
    candidate = _candidate_from_identity(payload["candidate"])
    page = _page_candidate_from_dict(payload["page"])
    if candidate.domain != page.candidate_domain:
        raise ValueError("stability receipt candidate and page domains differ")
    tranco = payload["tranco"]
    if not isinstance(tranco, Mapping) or set(tranco) != {"list_id", "list_sha256"}:
        raise ValueError("stability receipt Tranco binding is invalid")
    _validate_list_id(tranco["list_id"])
    _validate_sha256(tranco["list_sha256"], label="Tranco list SHA-256")
    if payload["probe_schedule"] != [window.as_dict() for window in STABILITY_PROBE_WINDOWS]:
        raise ValueError("stability receipt probe schedule differs from the contract")
    raw_observations = payload["observations"]
    if not isinstance(raw_observations, list):
        raise ValueError("stability receipt observations must be a list")
    observations = tuple(_observation_from_dict(raw) for raw in raw_observations)
    decision = derive_stability_decision(
        page,
        baseline_started_at=payload["baseline_started_at"],
        observations=observations,
    )
    expected_payload = _stability_payload(
        candidate,
        page,
        tranco_list_id=tranco["list_id"],
        tranco_list_sha256=tranco["list_sha256"],
        baseline_started_at=payload["baseline_started_at"],
        observations=observations,
        decision=decision,
    )
    if payload != expected_payload:
        raise ValueError("stability receipt differs from the independently derived contract")
    return decision


def choose_first_stable_page(
    candidate: ClassCandidate,
    pages: Sequence[PageCandidate],
    receipts_by_url: Mapping[str, Mapping[str, Any]],
) -> PageCandidate | None:
    """Choose the first eligible page in the preregistered homepage/link order."""

    _validate_candidate_identity(candidate)
    values = tuple(pages)
    _validate_page_sequence(candidate.domain, values)
    allowed_urls = {page.url for page in values}
    if set(receipts_by_url) - allowed_urls:
        raise ValueError("stability receipt map contains an unselected page URL")
    for page in values:
        receipt = receipts_by_url.get(page.url)
        if receipt is None:
            continue
        decision = validate_stability_receipt(receipt)
        payload = validate_hash_bound_receipt(receipt, expected_type=STABILITY_RECEIPT_TYPE)
        if (
            payload["candidate"] != _candidate_identity(candidate)
            or payload["page"] != page.as_dict()
        ):
            raise ValueError("stability receipt is bound to a different candidate or page")
        if decision.eligible:
            return page
    return None


def apply_stability_eligibility(
    candidate: ClassCandidate,
    pages: Sequence[PageCandidate],
    receipts_by_url: Mapping[str, Mapping[str, Any]],
) -> tuple[ClassCandidate, PageCandidate | None]:
    """Return a candidate whose sole eligibility bit reflects stable-page success."""

    selected = choose_first_stable_page(candidate, pages, receipts_by_url)
    return replace(candidate, eligible=selected is not None), selected


def write_tranco_snapshot_receipt(path: Path, value: Mapping[str, Any]) -> Path:
    validate_tranco_snapshot_receipt(value)
    return write_create_only_json(path, value)


def write_stability_receipt(path: Path, value: Mapping[str, Any]) -> Path:
    validate_stability_receipt(value)
    return write_create_only_json(path, value)


def load_stability_receipt(path: Path) -> tuple[dict[str, Any], StabilityDecision]:
    source = Path(os.path.abspath(path))
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"stability receipt is not a regular file: {source}")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"stability receipt is not valid JSON: {source}") from error
    if not isinstance(value, dict):
        raise ValueError("stability receipt must be a JSON object")
    return value, validate_stability_receipt(value)


def _stability_payload(
    candidate: ClassCandidate,
    page: PageCandidate,
    *,
    tranco_list_id: str,
    tranco_list_sha256: str,
    baseline_started_at: str,
    observations: Sequence[StabilityObservation],
    decision: StabilityDecision,
) -> dict[str, Any]:
    return {
        "study_id": STUDY_ID,
        "catalogue_schema_version": CATALOGUE_SCHEMA_VERSION,
        "candidate": _candidate_identity(candidate),
        "page": page.as_dict(),
        "tranco": {
            "list_id": tranco_list_id,
            "list_sha256": tranco_list_sha256,
        },
        "baseline_started_at": baseline_started_at,
        "probe_schedule": [window.as_dict() for window in STABILITY_PROBE_WINDOWS],
        "observations": [observation.as_dict() for observation in observations],
        "decision": decision.as_dict(),
    }


def _validate_observation_shapes(observations: Sequence[StabilityObservation]) -> None:
    if len(observations) != len(STABILITY_PROBE_WINDOWS):
        raise ValueError("stability evidence must contain exactly three observations")
    for window, observation in zip(STABILITY_PROBE_WINDOWS, observations, strict=True):
        if not isinstance(observation, StabilityObservation):
            raise ValueError("stability observations have the wrong type")
        if observation.probe_id != window.probe_id:
            raise ValueError("stability observation order/identity differs from the schedule")
        _parse_utc_timestamp(observation.observed_at, label="stability observation timestamp")
        if type(observation.elapsed_ms) is not int or observation.elapsed_ms < 0:
            raise ValueError("stability elapsed time must be a non-negative integer")
        if type(observation.status) is not int or not (100 <= observation.status <= 599):
            raise ValueError("stability response status is invalid")
        if type(observation.body_bytes) is not int or observation.body_bytes < 0:
            raise ValueError("stability response body length is invalid")
        if not isinstance(observation.content_type, str):
            raise ValueError("stability response content type must be a string")
        for label, digest in (
            ("body SHA-256", observation.body_sha256),
            ("resource-graph SHA-256", observation.resource_graph_sha256),
            ("prepared-workload SHA-256", observation.prepared_workload_sha256),
        ):
            _validate_sha256(digest, label=label)
        if not isinstance(observation.final_url, str):
            raise ValueError("stability final URL must be a string")


def _observation_from_dict(value: Any) -> StabilityObservation:
    fields = {
        "probe_id",
        "observed_at",
        "elapsed_ms",
        "final_url",
        "status",
        "content_type",
        "body_bytes",
        "body_sha256",
        "resource_graph_sha256",
        "prepared_workload_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("stability observation fields differ from the contract")
    return StabilityObservation(**{field: value[field] for field in fields})


def _candidate_identity(candidate: ClassCandidate) -> dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "domain": candidate.domain,
        "rank": candidate.rank,
        "stratum": candidate.stratum.id,
    }


def _candidate_from_identity(value: Any) -> ClassCandidate:
    if not isinstance(value, Mapping) or set(value) != {
        "candidate_id",
        "domain",
        "rank",
        "stratum",
    }:
        raise ValueError("stability candidate identity fields differ from the contract")
    candidate = ClassCandidate(value["candidate_id"], value["domain"], value["rank"], False)
    _validate_candidate_identity(candidate)
    if value["stratum"] != candidate.stratum.id:
        raise ValueError("stability candidate has the wrong rank stratum")
    return candidate


def _validate_candidate_identity(candidate: ClassCandidate) -> None:
    if not isinstance(candidate, ClassCandidate):
        raise ValueError("class candidate has the wrong type")
    if not isinstance(candidate.candidate_id, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{0,127}", candidate.candidate_id
    ):
        raise ValueError("class candidate ID is invalid")
    canonical_domain(candidate.domain)
    rank_stratum(candidate.rank)
    if not isinstance(candidate.eligible, bool):
        raise ValueError("class candidate eligibility must be boolean")


def _page_candidate_from_dict(value: Any) -> PageCandidate:
    fields = {
        "candidate_domain",
        "registrable_domain",
        "url",
        "source",
        "ordinal",
        "discovery_content_type",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("stability page fields differ from the contract")
    page = PageCandidate(**{field: value[field] for field in fields})
    validate_page_candidate(page)
    return page


def _validate_page_sequence(domain: str, pages: Sequence[PageCandidate]) -> None:
    if not pages or len(pages) > MAX_PAGE_CANDIDATES:
        raise ValueError("page sequence must contain a homepage and at most four links")
    if tuple(page.ordinal for page in pages) != tuple(range(len(pages))):
        raise ValueError("page sequence ordinals must be contiguous from zero")
    if len({page.url for page in pages}) != len(pages):
        raise ValueError("page sequence contains duplicate URLs")
    for page in pages:
        validate_page_candidate(page)
        if page.candidate_domain != domain:
            raise ValueError("page sequence is bound to another candidate domain")


def _canonical_url_host(hostname: str | None) -> str:
    if not hostname:
        raise ValueError("page URL is missing a hostname")
    try:
        host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as error:
        raise ValueError("page URL hostname is not valid IDNA") from error
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("page URL hostname must not be an IP address")
    return canonical_domain(host)


def _same_registrable_domain(host: str, registrable_domain: str) -> bool:
    return host == registrable_domain or host.endswith(f".{registrable_domain}")


def _has_forbidden_page_component(url: str) -> bool:
    parts = urlsplit(url)
    path_tokens = _semantic_tokens(unquote(parts.path).lower())
    host_tokens = _semantic_tokens((parts.hostname or "").lower())
    return bool((path_tokens | host_tokens) & FORBIDDEN_PAGE_TOKENS)


def _semantic_tokens(value: str) -> set[str]:
    components = _TOKEN_RE.findall(value)
    tokens = set(components)
    tokens.update(
        f"{left}-{right}" for left, right in zip(components, components[1:], strict=False)
    )
    return tokens


def _normalise_media_type(content_type: Any) -> str:
    if not isinstance(content_type, str):
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def _validate_list_id(value: Any) -> str:
    if not isinstance(value, str) or not _LIST_ID_RE.fullmatch(value):
        raise ValueError("Tranco list ID is invalid")
    return value


def _canonical_tranco_domain(domain: Any) -> str:
    """Validate an exact list token while retaining non-browsable wildcard PLDs."""

    if not isinstance(domain, str) or not domain or domain != domain.lower().rstrip("."):
        raise ValueError(f"Tranco domain is not canonical: {domain!r}")
    if len(domain) > 253 or "." not in domain:
        raise ValueError(f"Tranco domain is not canonical: {domain!r}")
    try:
        domain.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"Tranco domain is not canonical ASCII: {domain!r}") from error
    if any(_TRANCO_LABEL_RE.fullmatch(label) is None for label in domain.split(".")):
        raise ValueError(f"Tranco domain contains an invalid label: {domain!r}")
    return domain


def _validate_source_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Tranco source URL must be a non-empty string")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
        raise ValueError("Tranco source URL must be an absolute credential-free HTTPS URL")
    return value


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _parse_utc_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{label} is not a valid timestamp") from error
    if parsed.tzinfo != UTC:
        raise ValueError(f"{label} must use UTC")
    return parsed


def _add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)
