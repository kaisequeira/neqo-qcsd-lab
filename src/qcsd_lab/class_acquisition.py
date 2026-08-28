"""Resumable, provenance-bound acquisition for the 100-class study.

The runner deliberately performs only work whose probe window is currently due.
Network operations are behind :class:`AcquisitionBackend`, which makes the
state machine independently testable while allowing the production adapter to
reuse ``discover_page`` and ``prepare_workload``.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .class_catalogue import (
    HTML_MEDIA_TYPES,
    STABILITY_PROBE_WINDOWS,
    DiscoveredLink,
    PageCandidate,
    StabilityObservation,
    load_candidate_catalogue_receipt,
    select_page_candidates,
)
from .class_study import bind_receipt, canonical_json_bytes, validate_hash_bound_receipt
from .discover import DiscoveryResult, _host_resolver_rules, discover_page, origin
from .manifest import runtime_manifest, validate_research_preparation
from .prepare import PreparedWorkload, prepare_workload
from .util import (
    ATOMIC_TEMP_MARKER,
    atomic_json,
    durable_create,
    fsync_directory,
    load_json,
    sha256_bytes,
    sha256_file,
    source_metadata,
)

SCHEMA_VERSION = 1
PROVENANCE_TYPE = "qcsd-class-study-acquisition-provenance"
TERMINAL_TYPE = "qcsd-class-study-acquisition-terminal"
COMPLETION_TYPE = "qcsd-class-study-acquisition-completion"
CHECKPOINT_TYPE = "qcsd-class-study-acquisition-checkpoint"
MAX_ORIGIN_PASSES = 8
MAX_APPROVED_ORIGINS = 32
MAX_OBSERVED_AUDIT_ORIGINS = 512
MAX_PROBE_ATTEMPTS = 3
MAX_ACQUISITION_BACKEND_TIMEOUT_MS = 60_000
PENDING_BASELINE_GUARD_MS = (
    MAX_PROBE_ATTEMPTS * MAX_ACQUISITION_BACKEND_TIMEOUT_MS + 10_000
)
TERMINAL_KINDS = frozenset(
    {
        "eligible",
        "stable-page-unavailable",
        "pre-probe-rejection",
        "probe-window-missed",
    }
)
NAVIGATION_REJECTION_KINDS = frozenset(
    {
        "captcha-or-challenge",
        "navigation-returned-no-response",
        "navigation-time-budget-exhausted",
        "non-html-primary-response",
        "playwright-navigation-failure",
        "redirect-has-query-fragment-or-userinfo",
        "redirect-outside-candidate-boundary",
    }
)


def validate_class_study_preparation(
    manifest: dict[str, Any], *, workload_id: str
) -> None:
    """Require the class study's bounded complete-coverage preparation contract."""

    validate_research_preparation(manifest, workload_id=workload_id)
    preparation = manifest["preparation"]
    if "coverage_admission" not in preparation:
        raise ValueError(
            f"class-study workload {workload_id!r} requires a complete-coverage "
            "admission binding every approved origin and rendered resource"
        )
    unapproved_get_exclusions = [
        item
        for item in preparation["exclusions"]
        if item["reason"] == "origin not approved"
    ]
    if unapproved_get_exclusions:
        raise ValueError(
            f"class-study workload {workload_id!r} complete coverage cannot contain "
            "unapproved-origin HTTPS GET exclusions: "
            + ", ".join(
                sorted({item["url"] for item in unapproved_get_exclusions})
            )
        )
    approved_origins = preparation["approved_origins"]
    observed_origins = preparation["observed_origins"]
    if len(approved_origins) > MAX_APPROVED_ORIGINS:
        raise ValueError(
            f"class-study workload {workload_id!r} exceeds the "
            f"{MAX_APPROVED_ORIGINS}-origin admission cap"
        )
    if len(observed_origins) > MAX_OBSERVED_AUDIT_ORIGINS:
        raise ValueError(
            f"class-study workload {workload_id!r} exceeds the "
            f"{MAX_OBSERVED_AUDIT_ORIGINS}-origin audit cap"
        )


class MissedProbeWindow(ValueError):
    """A valid acquisition checkpoint whose next mandatory window expired."""


class TerminalProbePolicyError(ValueError):
    """A deterministic safety, policy, or finite-cap probe rejection."""


DOMAIN_SAFETY_POLICY = {
    "policy": "frozen-domain-safety-deny-v2",
    # Deterministic pre-browser safety policy, not a content classifier.  It
    # covers explicit-content and gambling labels present in the pinned input,
    # plus unambiguous abuse labels.  Rejections stay visible in attrition.
    "denied_substrings": [
        "adult",
        "bet",
        "casino",
        "escort",
        "gambl",
        "hentai",
        "malware",
        "phishing",
        "porn",
        "sex",
        "xxx",
    ],
    "denied_exact_domains": [
        "deep-nudes.com",
        "ebonyfacial.net",
        "greenxh.live",
        "hanime.tv",
        "joyclub.de",
        "mygirls.me",
        "xvideos.tube",
        "xnxx.com",
    ],
}


@dataclass(frozen=True)
class NavigationRejection:
    url: str
    kind: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"url": self.url, "kind": self.kind, "reason": self.reason}


@dataclass(frozen=True)
class NavigationDiscovery:
    registrable_domain: str
    links: tuple[DiscoveredLink, ...]
    observed_origins: tuple[str, ...] = ()
    rejections: tuple[NavigationRejection, ...] = ()
    page_observed_origins: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True)
class PreparedProbe:
    observed_at: str
    final_url: str
    status: int
    content_type: str
    body_bytes: int
    body_sha256: str
    resource_graph_sha256: str
    prepared: PreparedWorkload
    chromium_version: str
    neqo_provenance: Mapping[str, str]


class AcquisitionBackend(Protocol):
    def discover_navigation(self, domain: str) -> NavigationDiscovery: ...

    def discover(self, url: str, approved_origins: Sequence[str]) -> DiscoveryResult: ...

    def prepare(
        self,
        workload_id: str,
        url: str,
        approved_origins: Sequence[str],
        output_root: Path,
    ) -> PreparedProbe: ...


class ExistingAcquisitionBackend:
    """Production bridge to the existing browser and complete-coverage preparer.

    Navigation extraction remains injectable for deterministic state-machine
    tests.  Production uses the exact frozen catalogue-domain boundary.
    """

    def __init__(
        self,
        *,
        navigation: Callable[[str], NavigationDiscovery] | None = None,
        content_type_probe: Callable[[str, Sequence[str], int], str] | None = None,
        timeout_ms: int = 60_000,
    ) -> None:
        if (
            type(timeout_ms) is not int
            or not 1 <= timeout_ms <= MAX_ACQUISITION_BACKEND_TIMEOUT_MS
        ):
            raise ValueError("acquisition backend timeout must be in [1, 60000] ms")
        self._navigation = navigation
        self._content_type_probe = content_type_probe or browser_document_content_type
        self._timeout_ms = timeout_ms

    def discover_navigation(self, domain: str) -> NavigationDiscovery:
        if self._navigation is not None:
            return self._navigation(domain)
        return catalogue_boundary_navigation(domain, timeout_ms=self._timeout_ms)

    def discover(self, url: str, approved_origins: Sequence[str]) -> DiscoveryResult:
        pins = public_origin_ip_pins(approved_origins)
        return discover_page(
            url,
            allow_origins=list(approved_origins),
            timeout_ms=self._timeout_ms,
            origin_ip_pins=pins,
        )

    def prepare(
        self,
        workload_id: str,
        url: str,
        approved_origins: Sequence[str],
        output_root: Path,
    ) -> PreparedProbe:
        pins = public_origin_ip_pins(approved_origins)
        prepared = prepare_workload(
            workload_id,
            url,
            list(approved_origins),
            output_root=output_root,
            require_complete_coverage=True,
            # Research preparation has its own three-run live replay gate;
            # the outer t+30 s/t+24 h/t+72 h class probes are an additional
            # longitudinal stability boundary, not a replacement for it.
            stability_runs=3,
            stability_interval_seconds=0,
            origin_ip_pins=pins,
        )
        manifest = load_json(prepared.path)
        validate_class_study_preparation(manifest, workload_id=workload_id)
        preparation = manifest["preparation"]
        expected_matches = tuple(
            item for item in preparation["expected_responses"] if item["resource_id"] == 0
        )
        if len(expected_matches) != 1:
            raise TerminalProbePolicyError(
                "prepared navigation has no unique primary response"
            )
        [expected] = expected_matches
        if (
            type(expected["status"]) is not int
            or type(expected["bytes"]) is not int
            or expected["bytes"] < 1
            or not isinstance(expected["body_sha256"], str)
            or len(expected["body_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in expected["body_sha256"])
        ):
            raise TerminalProbePolicyError("prepared primary response identity is invalid")
        content_type = self._content_type_probe(url, approved_origins, self._timeout_ms)
        return PreparedProbe(
            observed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            final_url=preparation["final_url"],
            status=expected["status"],
            content_type=content_type,
            body_bytes=expected["bytes"],
            body_sha256=expected["body_sha256"],
            resource_graph_sha256=_prepared_replay_identity_sha256(manifest),
            prepared=prepared,
            chromium_version=preparation["chromium_version"],
            neqo_provenance={
                key: str(preparation[key])
                for key in (
                    "neqo_version",
                    "neqo_base_commit",
                    "published_qcsd_commit",
                    "migration_commit",
                )
            },
        )


def _prepared_replay_identity_sha256(manifest: Mapping[str, Any]) -> str:
    """Hash stable replay semantics while excluding run-specific evidence.

    A prepared manifest intentionally contains packet-capture qualification
    hashes and other provenance.  Those values prove one preparation run but
    are not expected to repeat 30 seconds, 24 hours, and 72 hours later.  Page
    stability instead binds the complete Neqo runtime graph plus every stable
    response identity and navigation/origin boundary.
    """

    preparation = manifest.get("preparation")
    if not isinstance(preparation, Mapping):
        raise ValueError("prepared replay identity requires preparation evidence")
    expected = preparation.get("expected_responses")
    approved = preparation.get("approved_origins")
    if not isinstance(expected, list) or not isinstance(approved, list):
        raise ValueError("prepared replay identity is incomplete")
    identity = {
        "schema_version": 1,
        "source_url": preparation.get("source_url"),
        "final_url": preparation.get("final_url"),
        "approved_origins": approved,
        "expected_responses": expected,
        "runtime_manifest": runtime_manifest(dict(manifest)),
    }
    return sha256_bytes(canonical_json_bytes(identity))


def catalogue_boundary_navigation(domain: str, *, timeout_ms: int = 60_000) -> NavigationDiscovery:
    """Extract navigation candidates using the frozen catalogue domain boundary.

    The Tranco candidate domain itself is the preregistered boundary.  This is
    stricter than guessing an eTLD+1 and fails closed for links outside that
    exact host boundary (subdomains included by the catalogue selector).
    """

    if timeout_ms < 1:
        raise ValueError("navigation timeout must be positive")
    deadline = time.monotonic() + timeout_ms / 1_000
    if reason := unsafe_catalogue_domain_reason(domain):
        raise TerminalProbePolicyError(reason)
    registrable = domain
    navigation_origins = [f"https://{domain}"]
    www_origin = f"https://www.{domain}"
    try:
        public_origin_ip_pins((www_origin,))
    except OSError:
        pass
    else:
        navigation_origins.append(www_origin)
    navigation_pins = public_origin_ip_pins(navigation_origins)
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError("navigation discovery requires the discovery Docker image") from error

    def remaining_timeout() -> int:
        return max(0, round((deadline - time.monotonic()) * 1_000))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"),
            args=[
                "--no-sandbox",
                "--host-resolver-rules=" + _host_resolver_rules(navigation_pins),
            ],
        )
        try:
            context = browser.new_context(ignore_https_errors=False, service_workers="block")
            observed_origins: set[str] = set()
            current_page_origins: set[str] = set()
            page_observed_origins: list[tuple[str, tuple[str, ...]]] = []

            def route_request(route: Any) -> None:
                request = route.request
                if not _navigation_request_allowed(request.method, request.url, domain):
                    route.abort()
                else:
                    # Only document-navigation origins are discovery seeds.
                    # Same-domain and cross-origin subresources belong to the
                    # later iterative resource-graph discovery.  Keeping them
                    # out here also prevents a late request from the previous
                    # optional page from contaminating the next page's seed.
                    if request.is_navigation_request():
                        request_origin = origin(request.url)
                        if request_origin is not None:
                            observed_origins.add(request_origin)
                            current_page_origins.add(request_origin)
                    route.continue_()

            context.route("**/*", route_request)
            page = context.new_page()
            homepage_budget = remaining_timeout()
            if homepage_budget < 1:
                raise ValueError("navigation exhausted its total timeout before homepage")
            current_page_origins.clear()
            homepage_response = page.goto(
                f"https://{domain}/", wait_until="load", timeout=homepage_budget
            )
            if homepage_response is None:
                raise ValueError("canonical homepage navigation returned no response")
            homepage_type = _normalise_content_type(
                str(homepage_response.headers.get("content-type", ""))
            )
            if homepage_type not in HTML_MEDIA_TYPES or not _navigation_request_allowed(
                "GET", page.url, domain
            ):
                raise TerminalProbePolicyError(
                    "canonical homepage did not resolve to an in-boundary HTML document"
                )
            if challenge := browser_challenge_reason(page):
                raise TerminalProbePolicyError(challenge)
            page_observed_origins.append(
                (f"https://{domain}/", tuple(sorted(current_page_origins)))
            )
            hrefs = tuple(
                str(value)
                for value in page.locator("a[href]").evaluate_all(
                    "elements => elements.map(element => element.href)"
                )
            )
            provisional = select_page_candidates(
                domain,
                registrable_domain=registrable,
                discovered_links=tuple(
                    DiscoveredLink(url=url, content_type="text/html") for url in hrefs
                ),
            )[1:]
            verified: list[DiscoveredLink] = []
            rejections: list[NavigationRejection] = []
            for candidate_index, candidate in enumerate(provisional):
                link_budget = remaining_timeout()
                if link_budget < 1:
                    rejections.extend(
                        NavigationRejection(
                            url=remaining.url,
                            kind="navigation-time-budget-exhausted",
                            reason="total navigation timeout expired before optional link",
                        )
                        for remaining in provisional[candidate_index:]
                    )
                    break
                try:
                    current_page_origins.clear()
                    response = page.goto(
                        candidate.url,
                        wait_until="domcontentloaded",
                        timeout=link_budget,
                    )
                except PlaywrightError as error:
                    # Link verification is optional; an unreachable or slow
                    # secondary page must not invalidate a valid homepage.
                    rejections.append(
                        NavigationRejection(
                            url=candidate.url,
                            kind="playwright-navigation-failure",
                            reason=str(error),
                        )
                    )
                    continue
                if response is None:
                    rejections.append(
                        NavigationRejection(
                            url=candidate.url,
                            kind="navigation-returned-no-response",
                            reason="optional link navigation returned no response",
                        )
                    )
                    continue
                policy_rejection = _navigation_link_policy_rejection(
                    final_url=page.url,
                    content_type=str(response.headers.get("content-type", "")),
                    boundary=domain,
                )
                if policy_rejection is not None:
                    kind, reason = policy_rejection
                    rejections.append(
                        NavigationRejection(
                            url=candidate.url,
                            kind=kind,
                            reason=reason,
                        )
                    )
                    continue
                verified_link = _verified_navigation_link(
                    candidate,
                    final_url=page.url,
                    content_type=str(response.headers.get("content-type", "")),
                    boundary=domain,
                )
                if verified_link is not None:
                    if challenge := browser_challenge_reason(page):
                        rejections.append(
                            NavigationRejection(
                                url=candidate.url,
                                kind="captcha-or-challenge",
                                reason=challenge,
                            )
                        )
                        continue
                    verified.append(verified_link)
                    page_observed_origins.append(
                        (candidate.url, tuple(sorted(current_page_origins)))
                    )
            page.close()
        finally:
            browser.close()
    if len(observed_origins) > MAX_APPROVED_ORIGINS:
        raise TerminalProbePolicyError(
            "navigation discovery exceeded its finite origin cap"
        )
    return NavigationDiscovery(
        registrable,
        tuple(verified),
        tuple(sorted(observed_origins)),
        tuple(rejections),
        tuple(page_observed_origins),
    )


def initialise_runner(
    root: Path,
    *,
    candidate_catalogue_path: Path,
    foundation_attestation: Path,
    started_at: str,
    browser_tool: str,
) -> Path:
    """Create the immutable provenance and initial resumable checkpoint."""

    catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
    started = _timestamp(started_at)
    foundation = _foundation_attestation_binding(foundation_attestation)
    destination = _new_directory(root)
    (destination / "terminals").mkdir()
    durable_create(destination / ".class-study-acquisition.lock", b"")
    provenance = bind_receipt(
        {
            "study_id": "classifier-multiorigin100-v1",
            "acquisition_schema_version": SCHEMA_VERSION,
            "candidate_catalogue_sha256": sha256_file(candidate_catalogue_path),
            "candidate_catalogue_payload_sha256": catalogue["payload_sha256"],
            "candidate_count": len(candidates),
            "foundation_attestation": foundation,
            "started_at": _format_time(started),
            "image_digest": os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native"),
            "source": source_metadata(),
            "browser_tool": browser_tool,
            "navigation_implementation": "playwright-cdp-catalogue-domain-boundary-v1",
            "registrable_domain_policy": "exact-frozen-tranco-candidate-domain",
            "domain_safety_policy": DOMAIN_SAFETY_POLICY,
            "domain_safety_policy_sha256": sha256_bytes(canonical_json_bytes(DOMAIN_SAFETY_POLICY)),
            "origin_policy": {
                "max_passes": MAX_ORIGIN_PASSES,
                "max_origins": MAX_APPROVED_ORIGINS,
                "max_observed_audit_origins": MAX_OBSERVED_AUDIT_ORIGINS,
                "max_navigation_attempts": MAX_PROBE_ATTEMPTS,
                "max_probe_attempts_per_window": MAX_PROBE_ATTEMPTS,
                "pending_baseline_guard_ms": PENDING_BASELINE_GUARD_MS,
                "navigation_seed_scope": ("page-specific-document-navigation-origins-only"),
                "resource_graph_scope": ("iteratively-converged-public-https-get-origins"),
                "dns": "all-answers-global-and-browser-host-resolver-pinned",
                "neqo": "QCSD_PUBLIC_ORIGIN_ONLY-resolve-once-connect-exact-address",
            },
            "eligibility_inputs": ["page-safety", "three-window-technical-stability"],
            "prohibited_inputs": [
                "classifier",
                "defence",
                "latency",
                "bandwidth",
                "privacy",
            ],
        },
        receipt_type=PROVENANCE_TYPE,
    )
    _create_json(destination / "provenance.json", provenance)
    checkpoint = _checkpoint(
        provenance_sha256=sha256_file(destination / "provenance.json"),
        catalogue_sha256=sha256_file(candidate_catalogue_path),
        candidates={
            candidate.candidate_id: {"state": "pending", "pages": [], "terminal": None}
            for candidate in candidates
        },
    )
    atomic_json(destination / "checkpoint.json", checkpoint)
    return destination


def run_due_acquisition(
    root: Path,
    *,
    candidate_catalogue_path: Path,
    stability_root: Path,
    workload_root: Path,
    backend: AcquisitionBackend,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
    max_candidates: int = 1,
) -> dict[str, Any]:
    """Process bounded due work and return progress plus the next due instant."""

    if max_candidates < 1:
        raise ValueError("max_candidates must be positive")
    if now is not None and clock is not None:
        raise ValueError("supply now or clock, not both")
    clock_function = clock or (lambda: datetime.now(UTC))
    initial_time = now or clock_function()
    if initial_time.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    runner = _regular_directory(root)
    provenance_path = runner / "provenance.json"
    provenance = load_json(provenance_path)
    provenance_payload = validate_hash_bound_receipt(provenance, expected_type=PROVENANCE_TYPE)
    _validate_runner_runtime(provenance_payload)
    _catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
    if provenance_payload["candidate_catalogue_sha256"] != sha256_file(candidate_catalogue_path):
        raise ValueError("runner provenance is bound to another catalogue")
    checkpoint_path = runner / "checkpoint.json"
    checkpoint = _load_checkpoint(checkpoint_path, provenance_path, candidate_catalogue_path)
    states = checkpoint["payload"]["candidates"]
    processed = 0
    while processed < max_candidates:
        # Re-read the clock and priority set after every network-bound item.
        # A long navigation/preparation can make a 30-second probe due while
        # this invocation is still running; that due probe must pre-empt the
        # next unused baseline rather than being missed by a stale snapshot.
        current = initial_time if now is not None else clock_function()
        due_candidates: set[str] = set()
        missed_candidates: set[str] = set()
        for candidate in candidates:
            state = states[candidate.candidate_id]
            if state["terminal"] is not None or state["state"] != "probing":
                continue
            try:
                if _due_pages(state, current, candidate_id=candidate.candidate_id):
                    due_candidates.add(candidate.candidate_id)
            except MissedProbeWindow:
                missed_candidates.add(candidate.candidate_id)
        ordered_candidates = tuple(
            candidate
            for candidate in candidates
            if (candidate.candidate_id in missed_candidates)
            or (not missed_candidates and candidate.candidate_id in due_candidates)
            or (
                not missed_candidates
                and not due_candidates
                and not _pending_baseline_blocked(states, current)
                and states[candidate.candidate_id]["terminal"] is None
                and states[candidate.candidate_id]["state"] == "pending"
            )
        )
        if not ordered_candidates:
            break
        candidate = ordered_candidates[0]
        state = states[candidate.candidate_id]
        if state["terminal"] is not None:
            continue
        if candidate.candidate_id in missed_candidates:
            _terminalise(
                runner,
                state,
                candidate.candidate_id,
                "probe-window-missed",
                "host resumed after the latest admissible probe window",
                provenance_path,
            )
            processed += 1
            _save_acquisition_checkpoint(
                checkpoint_path,
                provenance_path=provenance_path,
                catalogue_path=candidate_catalogue_path,
                candidates=states,
            )
            continue
        if state["state"] == "pending":
            attempts = state.setdefault("navigation_attempts", [])
            pending_navigation = state.get("pending_navigation")
            if pending_navigation is not None:
                attempt, started = _validate_pending_navigation(pending_navigation)
                attempts.append(
                    {
                        "attempt": attempt,
                        "started_at": _format_time(started),
                        "completed_at": _format_time(
                            current if now is not None else clock_function()
                        ),
                        "outcome": "interrupted",
                        "reason": "prior invocation ended before recording an outcome",
                    }
                )
                state.pop("pending_navigation", None)
            navigation = None
            pages = None
            navigation_origins_by_page = None
            navigation_final = bool(
                attempts
                and attempts[-1]["outcome"] == "terminal-policy-rejection"
            )
            while len(attempts) < MAX_PROBE_ATTEMPTS and not navigation_final:
                attempt = 1 + max(
                    (item["attempt"] for item in attempts),
                    default=0,
                )
                started = current if now is not None else clock_function()
                state["pending_navigation"] = {
                    "attempt": attempt,
                    "started_at": _format_time(started),
                }
                _save_acquisition_checkpoint(
                    checkpoint_path,
                    provenance_path=provenance_path,
                    catalogue_path=candidate_catalogue_path,
                    candidates=states,
                )
                try:
                    navigation = backend.discover_navigation(candidate.domain)
                    try:
                        pages = select_page_candidates(
                            candidate.domain,
                            registrable_domain=navigation.registrable_domain,
                            discovered_links=navigation.links,
                        )
                        navigation_origins_by_page = _navigation_origins_by_page(
                            navigation, pages
                        )
                    except (TypeError, ValueError) as error:
                        raise TerminalProbePolicyError(str(error)) from error
                except TerminalProbePolicyError as error:
                    outcome = "terminal-policy-rejection"
                    reason = str(error)
                except Exception as error:  # noqa: BLE001 - recoverable navigation boundary
                    outcome = "recoverable-failure"
                    reason = str(error)
                else:
                    outcome = "completed"
                    reason = None
                completion = current if now is not None else clock_function()
                attempts.append(
                    {
                        "attempt": attempt,
                        "started_at": _format_time(started),
                        "completed_at": _format_time(completion),
                        "outcome": outcome,
                        "reason": reason,
                    }
                )
                state.pop("pending_navigation", None)
                if outcome != "completed":
                    _save_acquisition_checkpoint(
                        checkpoint_path,
                        provenance_path=provenance_path,
                        catalogue_path=candidate_catalogue_path,
                        candidates=states,
                    )
                if outcome == "completed" or outcome == "terminal-policy-rejection":
                    break
            if navigation is None or pages is None or navigation_origins_by_page is None:
                if attempts[-1]["outcome"] == "terminal-policy-rejection":
                    rejection_reason = attempts[-1]["reason"]
                else:
                    rejection_reason = (
                        f"recoverable navigation failures exhausted "
                        f"{MAX_PROBE_ATTEMPTS} attempts: {attempts[-1]['reason']}"
                    )
                _terminalise(
                    runner,
                    state,
                    candidate.candidate_id,
                    "pre-probe-rejection",
                    rejection_reason,
                    provenance_path,
                )
                processed += 1
                _save_acquisition_checkpoint(
                    checkpoint_path,
                    provenance_path=provenance_path,
                    catalogue_path=candidate_catalogue_path,
                    candidates=states,
                )
                continue
            state.update(
                {
                    "state": "probing",
                    "baseline_started_at": _format_time(
                        current if now is not None else clock_function()
                    ),
                    "pages": [
                        {
                            "page": page.as_dict(),
                            "observations": [],
                            "probe_attempts": [],
                            "approved_origins": [],
                            "navigation_observed_origins": list(
                                navigation_origins_by_page[page.url]
                            ),
                        }
                        for page in pages
                    ],
                    "navigation_observed_origins": list(navigation.observed_origins),
                    "navigation_rejections": [
                        rejection.as_dict() for rejection in navigation.rejections
                    ],
                }
            )
            processed += 1
            _save_acquisition_checkpoint(
                checkpoint_path,
                provenance_path=provenance_path,
                catalogue_path=candidate_catalogue_path,
                candidates=states,
            )
            continue
        due_pages = _due_pages(state, current, candidate_id=candidate.candidate_id)
        if not due_pages:
            continue
        retry_pages = list(due_pages)
        window_missed = False
        while retry_pages:
            runnable_pages: list[dict[str, Any]] = []
            attempt_clock = current if now is not None else clock_function()
            for due_page in retry_pages:
                probe_index = len(due_page["observations"])
                probe_id = STABILITY_PROBE_WINDOWS[probe_index].probe_id
                attempts = due_page.setdefault("probe_attempts", [])
                pending_probe = due_page.get("pending_probe")
                if pending_probe is None:
                    attempt = 1 + max(
                        (
                            item["attempt"]
                            for item in attempts
                            if item.get("probe_id") == probe_id
                        ),
                        default=0,
                    )
                else:
                    attempt, _original_start = _validate_pending_probe(
                        pending_probe,
                        candidate_id=candidate.candidate_id,
                        page_ordinal=due_page["page"]["ordinal"],
                        probe_id=probe_id,
                    )
                    attempts.append(
                        {
                            **pending_probe,
                            "completed_at": _format_time(attempt_clock),
                            "outcome": "interrupted",
                            "reason": "prior invocation ended before recording an outcome",
                        }
                    )
                    due_page.pop("pending_probe", None)
                    attempt += 1
                if attempt > MAX_PROBE_ATTEMPTS:
                    due_page["rejection"] = {
                        "kind": "probe-retry-exhausted",
                        "reason": (
                            f"recoverable acquisition failures exhausted "
                            f"{MAX_PROBE_ATTEMPTS} attempts"
                        ),
                    }
                    continue
                # Every retry gets a new create-only preparation identity and
                # its real start is checkpointed before any network work.
                due_page["pending_probe"] = {
                    "probe_id": probe_id,
                    "workload_id": _probe_attempt_workload_id(
                        candidate.candidate_id,
                        due_page["page"]["ordinal"],
                        probe_id,
                        attempt,
                    ),
                    "attempt": attempt,
                    "observed_at": _format_time(attempt_clock),
                }
                runnable_pages.append(due_page)
            _save_acquisition_checkpoint(
                checkpoint_path,
                provenance_path=provenance_path,
                catalogue_path=candidate_catalogue_path,
                candidates=states,
            )
            if not runnable_pages:
                break

            def acquire_page(
                due_page: dict[str, Any],
                *,
                candidate_id: str = candidate.candidate_id,
                baseline_started_at: str = state["baseline_started_at"],
            ) -> tuple[dict[str, Any], Any]:
                page = PageCandidate(**due_page["page"])
                probe_index = len(due_page["observations"])
                pending_probe = due_page["pending_probe"]
                probe_started = _timestamp(pending_probe["observed_at"])
                try:
                    approved, discovery = _converge_origins(
                        backend,
                        page.url,
                        seed_origins=tuple(due_page["navigation_observed_origins"]),
                    )
                    probe_id = STABILITY_PROBE_WINDOWS[probe_index].probe_id
                    prepared = backend.prepare(
                        pending_probe["workload_id"],
                        page.url,
                        approved,
                        runner / "prepared-probes",
                    )
                    started_at = _format_time(probe_started)
                    elapsed = round(
                        (probe_started - _timestamp(baseline_started_at)).total_seconds()
                        * 1000
                    )
                    observation = StabilityObservation(
                        probe_id=probe_id,
                        observed_at=started_at,
                        elapsed_ms=elapsed,
                        final_url=prepared.final_url,
                        status=prepared.status,
                        content_type=prepared.content_type,
                        body_bytes=prepared.body_bytes,
                        body_sha256=prepared.body_sha256,
                        resource_graph_sha256=prepared.resource_graph_sha256,
                        prepared_workload_sha256=prepared.prepared.sha256,
                    )
                    return due_page, {
                        "approved_origins": approved,
                        "completed_at": prepared.observed_at,
                        "observation": {
                            **observation.as_dict(),
                            "runner_provenance_sha256": sha256_file(provenance_path),
                            "approved_origins": approved,
                            "discovery_observed_origins": discovery.observed_origins,
                            "discovery_expandable_origins": discovery.expandable_origins,
                            "discovery_origin_ip_pins": discovery.origin_ip_pins,
                            "chromium_version": prepared.chromium_version,
                            "neqo_provenance": dict(prepared.neqo_provenance),
                            "prepared_path": str(prepared.prepared.path.resolve()),
                            "probe_completed_at": prepared.observed_at,
                        },
                    }
                except TerminalProbePolicyError as error:
                    return due_page, {"terminal_policy_error": str(error)}
                except Exception as error:  # noqa: BLE001 - recoverable probe boundary
                    return due_page, {"recoverable_error": str(error)}

            with ThreadPoolExecutor(max_workers=min(5, len(runnable_pages))) as executor:
                outcomes = tuple(executor.map(acquire_page, runnable_pages))
            retry_pages = []
            completion_clock = current if now is not None else clock_function()
            for due_page, outcome in outcomes:
                pending_probe = due_page.pop("pending_probe")
                attempt_record = {
                    **pending_probe,
                    "completed_at": outcome.get(
                        "completed_at", _format_time(completion_clock)
                    ),
                    "outcome": "completed",
                    "reason": None,
                }
                if "terminal_policy_error" in outcome:
                    attempt_record.update(
                        outcome="terminal-policy-rejection",
                        reason=outcome["terminal_policy_error"],
                    )
                    due_page["rejection"] = {
                        "kind": "probe-policy-rejection",
                        "reason": outcome["terminal_policy_error"],
                    }
                elif "recoverable_error" in outcome:
                    attempt_record.update(
                        outcome="recoverable-failure",
                        reason=outcome["recoverable_error"],
                    )
                    if pending_probe["attempt"] >= MAX_PROBE_ATTEMPTS:
                        due_page["rejection"] = {
                            "kind": "probe-retry-exhausted",
                            "reason": (
                                f"recoverable acquisition failures exhausted "
                                f"{MAX_PROBE_ATTEMPTS} attempts: "
                                f"{outcome['recoverable_error']}"
                            ),
                        }
                    else:
                        retry_pages.append(due_page)
                else:
                    due_page["approved_origins"] = outcome["approved_origins"]
                    due_page["observations"].append(outcome["observation"])
                due_page.setdefault("probe_attempts", []).append(attempt_record)
            _save_acquisition_checkpoint(
                checkpoint_path,
                provenance_path=provenance_path,
                catalogue_path=candidate_catalogue_path,
                candidates=states,
            )
            if retry_pages:
                retry_clock = current if now is not None else clock_function()
                try:
                    _due_pages(state, retry_clock, candidate_id=candidate.candidate_id)
                except MissedProbeWindow:
                    window_missed = True
                    break
        if window_missed:
            _terminalise(
                runner,
                state,
                candidate.candidate_id,
                "probe-window-missed",
                "recoverable probe retries exceeded the latest admissible window",
                provenance_path,
            )
        if all(
            page.get("rejection") is not None
            or len(page["observations"]) == len(STABILITY_PROBE_WINDOWS)
            for page in state["pages"]
        ):
            stable_receipts: list[Path] = []
            for page_state in state["pages"]:
                if page_state.get("rejection") is not None:
                    continue
                page = PageCandidate(**page_state["page"])
                observations = tuple(
                    StabilityObservation(
                        **{key: item[key] for key in StabilityObservation.__dataclass_fields__}
                    )
                    for item in page_state["observations"]
                )
                from .class_pipeline import admit_stability_observations

                receipt = admit_stability_observations(
                    candidate_catalogue_path,
                    stability_root,
                    candidate_id=candidate.candidate_id,
                    page=page,
                    baseline_started_at=state["baseline_started_at"],
                    observations=observations,
                )
                from .class_catalogue import load_stability_receipt

                _value, decision = load_stability_receipt(receipt)
                if decision.eligible:
                    stable_receipts.append(receipt)
            if stable_receipts:
                selected = stable_receipts[0]
                selected_ordinal = int(selected.stem.removeprefix("page-"))
                selected_page = next(
                    page for page in state["pages"] if page["page"]["ordinal"] == selected_ordinal
                )
                _publish_admitted_workload(
                    Path(selected_page["observations"][0]["prepared_path"]),
                    workload_root / f"{candidate.candidate_id}.json",
                    selected_page["observations"][0]["prepared_workload_sha256"],
                )
                _terminalise(
                    runner,
                    state,
                    candidate.candidate_id,
                    "eligible",
                    None,
                    provenance_path,
                    stability_receipt=selected,
                    admitted_workload=workload_root / f"{candidate.candidate_id}.json",
                )
            else:
                _terminalise(
                    runner,
                    state,
                    candidate.candidate_id,
                    "stable-page-unavailable",
                    "no page passed all stability gates",
                    provenance_path,
                )
        processed += 1
        _save_acquisition_checkpoint(
            checkpoint_path,
            provenance_path=provenance_path,
            catalogue_path=candidate_catalogue_path,
            candidates=states,
        )
    _save_acquisition_checkpoint(
        checkpoint_path,
        provenance_path=provenance_path,
        catalogue_path=candidate_catalogue_path,
        candidates=states,
    )
    return acquisition_status(
        runner,
        candidate_catalogue_path=candidate_catalogue_path,
        now=initial_time if now is not None else clock_function(),
    )


def acquisition_status(
    root: Path,
    *,
    candidate_catalogue_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("status time must be timezone-aware")
    current = current.astimezone(UTC)
    checkpoint, recovery_required = _load_checkpoint_state(
        Path(root) / "checkpoint.json",
        Path(root) / "provenance.json",
        candidate_catalogue_path,
        persist_recoveries=False,
    )
    states = checkpoint["payload"]["candidates"]
    next_due: datetime | None = None
    pending = 0
    probing = 0
    due_now = 0
    missed = 0
    for candidate_id, state in states.items():
        if state["terminal"] is None and state["state"] == "pending":
            pending += 1
        if state["terminal"] is None and state["state"] == "probing":
            probing += 1
            try:
                if _due_pages(state, current, candidate_id=candidate_id):
                    due_now += 1
            except MissedProbeWindow:
                missed += 1
            for page in state["pages"]:
                if page.get("rejection") is not None:
                    continue
                index = len(page["observations"])
                if index < len(STABILITY_PROBE_WINDOWS):
                    baseline = _timestamp(state["baseline_started_at"])
                    due = baseline + timedelta(
                        milliseconds=STABILITY_PROBE_WINDOWS[index].earliest_ms
                    )
                    if due > current:
                        next_due = due if next_due is None or due < next_due else next_due
    terminal = sum(state["terminal"] is not None for state in states.values())
    pending_blocked = bool(pending) and _pending_baseline_blocked(states, current)
    return {
        "candidate_count": len(states),
        "terminal_count": terminal,
        "pending_count": pending,
        "probing_count": probing,
        "due_now_count": due_now,
        "missed_window_count": missed,
        "recovery_required_count": recovery_required,
        "pending_start_blocked": pending_blocked,
        "work_due_now": bool(
            recovery_required or due_now or missed or (pending and not pending_blocked)
        ),
        "complete": terminal == len(states) and recovery_required == 0,
        "next_due": _format_time(next_due) if next_due else None,
    }


def write_acquisition_completion(root: Path, *, candidate_catalogue_path: Path) -> Path:
    provenance_value = validate_hash_bound_receipt(
        load_json(Path(root) / "provenance.json"), expected_type=PROVENANCE_TYPE
    )
    _validate_runner_runtime(provenance_value)
    status = acquisition_status(root, candidate_catalogue_path=candidate_catalogue_path)
    if not status["complete"]:
        raise ValueError("acquisition completion requires terminal evidence for all candidates")
    runner = Path(root)
    checkpoint = _load_checkpoint(
        runner / "checkpoint.json", runner / "provenance.json", candidate_catalogue_path
    )
    terminals = checkpoint["payload"]["candidates"]
    provenance = validate_hash_bound_receipt(
        load_json(runner / "provenance.json"), expected_type=PROVENANCE_TYPE
    )
    observed_toolchain = _validate_observation_provenance(
        terminals,
        provenance_sha256=sha256_file(runner / "provenance.json"),
        runner_provenance=provenance,
    )
    receipt = bind_receipt(
        {
            "study_id": "classifier-multiorigin100-v1",
            "acquisition_schema_version": SCHEMA_VERSION,
            "candidate_catalogue_sha256": sha256_file(candidate_catalogue_path),
            "provenance_sha256": sha256_file(runner / "provenance.json"),
            "checkpoint_payload_sha256": checkpoint["payload_sha256"],
            "observed_toolchain": observed_toolchain,
            "terminal_receipts": {
                candidate_id: state["terminal"] for candidate_id, state in terminals.items()
            },
        },
        receipt_type=COMPLETION_TYPE,
    )
    destination = runner / "completion.json"
    _create_json(destination, receipt)
    return destination


def validate_acquisition_completion(
    value: Mapping[str, Any], *, candidate_catalogue_path: Path, runner_root: Path
) -> Mapping[str, Any]:
    payload = validate_hash_bound_receipt(value, expected_type=COMPLETION_TYPE)
    _catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
    if payload["candidate_catalogue_sha256"] != sha256_file(candidate_catalogue_path):
        raise ValueError("completion is bound to another catalogue")
    checkpoint = _load_checkpoint(
        runner_root / "checkpoint.json",
        runner_root / "provenance.json",
        candidate_catalogue_path,
    )
    expected = {candidate.candidate_id for candidate in candidates}
    checkpoint_terminals = {
        candidate_id: state["terminal"]
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
    }
    if (
        set(payload["terminal_receipts"]) != expected
        or payload["terminal_receipts"] != checkpoint_terminals
        or payload["checkpoint_payload_sha256"] != checkpoint["payload_sha256"]
    ):
        raise ValueError("completion does not bind the complete current checkpoint")
    provenance = validate_hash_bound_receipt(
        load_json(runner_root / "provenance.json"), expected_type=PROVENANCE_TYPE
    )
    observed_toolchain = _validate_observation_provenance(
        checkpoint["payload"]["candidates"],
        provenance_sha256=payload["provenance_sha256"],
        runner_provenance=provenance,
    )
    if payload.get("observed_toolchain") != observed_toolchain:
        raise ValueError("completion observed toolchain identity differs from checkpoint")
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    for candidate_id, binding in payload["terminal_receipts"].items():
        if not isinstance(binding, Mapping) or set(binding) != {"path", "sha256"}:
            raise ValueError("terminal evidence binding is malformed")
        if binding["path"] != f"terminals/{candidate_id}.json":
            raise ValueError("terminal evidence path is not canonical")
        verified = _validated_terminal_binding(
            runner_root / binding["path"],
            candidate=candidate_by_id[candidate_id],
            provenance_sha256=payload["provenance_sha256"],
        )
        if dict(binding) != verified:
            raise ValueError("terminal evidence SHA-256 mismatch")
    return payload


def _converge_origins(
    backend: AcquisitionBackend,
    url: str,
    *,
    seed_origins: Sequence[str] = (),
) -> tuple[list[str], DiscoveryResult]:
    initial = origin(url)
    if initial is None:
        raise TerminalProbePolicyError("page URL is not HTTPS")
    approved = {initial}
    for value in seed_origins:
        approved_origin = origin(value)
        if approved_origin is None:
            raise TerminalProbePolicyError("navigation supplied a non-HTTPS origin")
        approved.add(approved_origin)
    if len(approved) > MAX_APPROVED_ORIGINS:
        raise TerminalProbePolicyError("navigation origins exceeded the finite origin cap")
    for _pass in range(MAX_ORIGIN_PASSES):
        result = backend.discover(url, sorted(approved))
        expandable = result.expandable_origins
        if expandable is None:
            raise TerminalProbePolicyError(
                "discovery omitted its HTTPS-GET-only expandable-origin ledger"
            )
        if not isinstance(expandable, list):
            raise TerminalProbePolicyError(
                "discovery HTTPS-GET-only expandable-origin ledger is not a list"
            )
        canonical_expandable: list[str] = []
        for value in expandable:
            expandable_origin = origin(value) if isinstance(value, str) else None
            if expandable_origin is None or expandable_origin != value:
                raise TerminalProbePolicyError(
                    "discovery HTTPS-GET-only expandable-origin ledger contains a "
                    "non-canonical HTTPS origin"
                )
            canonical_expandable.append(expandable_origin)
        if canonical_expandable != sorted(set(canonical_expandable)):
            raise TerminalProbePolicyError(
                "discovery HTTPS-GET-only expandable-origin ledger is not sorted and unique"
            )
        audited_origins = {
            observed_origin
            for value in result.observed_origins
            if isinstance(value, str) and (observed_origin := origin(value)) is not None
        }
        if not set(canonical_expandable).issubset(audited_origins):
            raise TerminalProbePolicyError(
                "discovery HTTPS-GET-only expandable origins exceed its observed-origin ledger"
            )
        observed = set(canonical_expandable)
        expanded = approved | observed
        if len(expanded) > MAX_APPROVED_ORIGINS:
            raise TerminalProbePolicyError(
                "approved-origin discovery exceeded its finite origin cap"
            )
        if expanded == approved:
            return sorted(approved), result
        approved = expanded
    raise TerminalProbePolicyError(
        "approved-origin discovery did not converge within its pass cap"
    )


def browser_document_content_type(
    url: str,
    approved_origins: Sequence[str],
    timeout_ms: int,
) -> str:
    """Observe the primary browser response MIME type under the frozen origin set."""

    if timeout_ms < 1:
        raise ValueError("content-type probe timeout must be positive")
    approved = {origin(value) for value in approved_origins}
    if None in approved or not approved or len(approved) > MAX_APPROVED_ORIGINS:
        raise TerminalProbePolicyError("content-type probe approved origins are invalid")
    pins = public_origin_ip_pins(tuple(value for value in approved if value is not None))
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError(
            "content-type verification requires the discovery Docker image"
        ) from error
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"),
            args=[
                "--no-sandbox",
                "--host-resolver-rules=" + _host_resolver_rules(pins),
            ],
        )
        context = browser.new_context(ignore_https_errors=False, service_workers="block")

        def route_request(route: Any) -> None:
            request = route.request
            if request.method != "GET" or origin(request.url) not in approved:
                route.abort()
            else:
                route.continue_()

        context.route("**/*", route_request)
        page = context.new_page()
        response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        if response is None or origin(page.url) not in approved:
            raise TerminalProbePolicyError(
                "content-type probe did not finish on an approved origin"
            )
        if challenge := browser_challenge_reason(page):
            raise TerminalProbePolicyError(challenge)
        media_type = _normalise_content_type(str(response.headers.get("content-type", "")))
        page.close()
        browser.close()
    if media_type not in HTML_MEDIA_TYPES:
        raise TerminalProbePolicyError("primary response is not HTML")
    return media_type


def _normalise_content_type(value: str) -> str:
    return value.partition(";")[0].strip().lower()


def _navigation_request_allowed(method: str, url: str, boundary: str) -> bool:
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower().rstrip(".")
    frozen = boundary.lower().rstrip(".")
    return (
        method == "GET"
        and parts.scheme.lower() == "https"
        and (hostname == frozen or hostname.endswith(f".{frozen}"))
    )


def unsafe_catalogue_domain_reason(domain: str) -> str | None:
    canonical = domain.lower().rstrip(".")
    if canonical in DOMAIN_SAFETY_POLICY["denied_exact_domains"]:
        return "domain-safety-policy-rejected:exact-domain"
    for substring in DOMAIN_SAFETY_POLICY["denied_substrings"]:
        if any(substring in label for label in canonical.split(".")):
            return f"domain-safety-policy-rejected:{substring}"
    return None


def _is_public_network_address(
    value: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Mirror Neqo's exact ``QCSD_PUBLIC_ORIGIN_ONLY`` address policy."""

    if isinstance(value, str):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
    elif isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        address = value
    else:
        return False

    octets = address.packed
    if isinstance(address, ipaddress.IPv4Address):
        a, b, c, _d = octets
        return not (
            a == 0
            or a == 10
            or a == 127
            or a >= 224
            or (a == 100 and 64 <= b <= 127)
            or (a == 169 and b == 254)
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 0)
            or (a == 192 and b == 168)
            or (a == 192 and b == 88 and c == 99)
            or (a == 198 and b in {18, 19})
            or (a == 198 and b == 51 and c == 100)
            or (a == 203 and b == 0 and c == 113)
        )

    global_unicast = octets[0] & 0xE0 == 0x20
    ietf_special = octets[0] == 0x20 and octets[1] == 0x01 and octets[2] & 0xFE == 0
    deprecated_6to4 = octets[0] == 0x20 and octets[1] == 0x02
    documentation = octets[:4] == bytes((0x20, 0x01, 0x0D, 0xB8)) or (
        octets[0] == 0x3F and octets[1] == 0xFF and octets[2] & 0xF0 == 0
    )
    return global_unicast and not ietf_special and not deprecated_6to4 and not documentation


def public_origin_ip_pins(origins: Sequence[str]) -> dict[str, str]:
    """Resolve and pin public DNS answers, rejecting every non-public answer."""

    pins: dict[str, str] = {}
    for value in sorted(set(origins)):
        approved = origin(value)
        if approved is None:
            raise TerminalProbePolicyError(
                "public-origin policy requires absolute HTTPS origins"
            )
        hostname = urlsplit(approved).hostname
        if hostname is None:
            raise TerminalProbePolicyError(
                "public-origin policy found an origin without a hostname"
            )
        canonical = hostname.lower().rstrip(".")
        try:
            ipaddress.ip_address(canonical)
        except ValueError:
            pass
        else:
            raise TerminalProbePolicyError(
                "public-origin policy rejects IP-literal origins"
            )
        if canonical == "localhost" or canonical.endswith(
            (".localhost", ".local", ".internal", ".home", ".lan")
        ):
            raise TerminalProbePolicyError("public-origin policy rejects local hostnames")
        answers = {
            ipaddress.ip_address(record[4][0])
            for record in socket.getaddrinfo(
                canonical,
                443,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        }
        if not answers or any(not _is_public_network_address(address) for address in answers):
            raise TerminalProbePolicyError(
                f"public-origin policy rejected DNS answers for {canonical}"
            )
        selected = min(answers, key=lambda address: (address.version, int(address)))
        pins[approved] = selected.compressed
    return pins


def browser_challenge_reason(page: Any) -> str | None:
    """Reject common interstitial/CAPTCHA documents before stability probing."""

    title = str(page.title()).casefold()
    body = str(page.locator("body").inner_text(timeout=5_000))[:200_000].casefold()
    selectors = (
        "iframe[src*='captcha' i]",
        "iframe[src*='challenge' i]",
        "[id*='captcha' i]",
        "[class*='captcha' i]",
        "script[src*='turnstile' i]",
        "script[src*='recaptcha' i]",
    )
    if any(page.locator(selector).count() for selector in selectors):
        return "page-safety-rejected:captcha-or-challenge-widget"
    phrases = (
        "verify you are human",
        "verify that you are human",
        "checking your browser",
        "complete the captcha",
        "security verification",
        "enable javascript and cookies to continue",
    )
    if any(phrase in title or phrase in body for phrase in phrases):
        return "page-safety-rejected:captcha-or-challenge-interstitial"
    return None


def _verified_navigation_link(
    candidate: PageCandidate,
    *,
    final_url: str,
    content_type: str,
    boundary: str,
) -> DiscoveredLink | None:
    if (
        _navigation_link_policy_rejection(
            final_url=final_url,
            content_type=content_type,
            boundary=boundary,
        )
        is not None
    ):
        return None
    media_type = _normalise_content_type(content_type)
    return DiscoveredLink(url=candidate.url, content_type=media_type)


def _navigation_link_policy_rejection(
    *, final_url: str, content_type: str, boundary: str
) -> tuple[str, str] | None:
    media_type = _normalise_content_type(content_type)
    if media_type not in HTML_MEDIA_TYPES:
        return (
            "non-html-primary-response",
            f"optional link returned unsupported media type {media_type!r}",
        )
    parts = urlsplit(final_url)
    if not _navigation_request_allowed("GET", final_url, boundary):
        return (
            "redirect-outside-candidate-boundary",
            "optional link redirected outside the frozen candidate-domain boundary",
        )
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        return (
            "redirect-has-query-fragment-or-userinfo",
            "optional link redirect introduced forbidden URL components",
        )
    return None


def _navigation_origins_by_page(
    navigation: NavigationDiscovery,
    pages: Sequence[PageCandidate],
) -> dict[str, tuple[str, ...]]:
    """Validate and retain navigation seeds for the page that observed them.

    Production navigation records each page independently so a redirect seen
    on one optional page cannot overconstrain a different page's discovery
    graph.  The global union remains in the checkpoint for audit, but is never
    substituted for missing page-specific evidence.
    """

    global_origins = _canonical_navigation_origins(
        navigation.observed_origins,
        label="global navigation origin ledger",
    )
    page_urls = {page.url for page in pages}
    raw_page_origins = navigation.page_observed_origins
    if not isinstance(raw_page_origins, tuple):
        raise TypeError("per-page navigation origin ledger is not a tuple")
    if not raw_page_origins:
        raise ValueError("per-page navigation origin ledger is required")
    result: dict[str, tuple[str, ...]] = {}
    for entry in raw_page_origins:
        if (
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or entry[0] in result
        ):
            raise ValueError("per-page navigation origin ledger is malformed")
        page_url, values = entry
        if page_url not in page_urls:
            raise ValueError("per-page navigation origin ledger names another page")
        origins = _canonical_navigation_origins(
            values,
            label="per-page navigation origin ledger",
        )
        if not set(origins).issubset(global_origins):
            raise ValueError("per-page navigation origins exceed the global ledger")
        result[page_url] = origins
    if set(result) != page_urls:
        raise ValueError("per-page navigation origin ledger is incomplete")
    return result


def _canonical_navigation_origins(
    values: object,
    *,
    label: str,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise TypeError(f"{label} is not a sequence")
    if len(values) > MAX_APPROVED_ORIGINS:
        raise ValueError(f"{label} is malformed")
    canonical: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{label} contains a non-string origin")
        canonical_origin = origin(value)
        if canonical_origin is None or canonical_origin != value:
            raise ValueError(f"{label} contains a non-canonical HTTPS origin")
        canonical.append(canonical_origin)
    if canonical != sorted(set(canonical)):
        raise ValueError(f"{label} is not a sorted unique origin set")
    return tuple(canonical)


def _validate_navigation_rejections(value: object, *, boundary: str) -> None:
    if not isinstance(value, list) or len(value) > 4:
        raise ValueError("navigation rejection ledger is malformed")
    for rejection in value:
        if not isinstance(rejection, Mapping) or set(rejection) != {
            "url",
            "kind",
            "reason",
        }:
            raise ValueError("navigation rejection record is malformed")
        if (
            rejection["kind"] not in NAVIGATION_REJECTION_KINDS
            or not isinstance(rejection["reason"], str)
            or not _navigation_request_allowed("GET", rejection["url"], boundary)
        ):
            raise ValueError("navigation rejection record violates its policy")


def _verified_bound_file(binding: Mapping[str, Any], *, label: str) -> Path:
    if set(binding) != {"path", "sha256"} or not isinstance(binding["path"], str):
        raise ValueError(f"{label} binding is malformed")
    path = Path(binding["path"])
    if path.is_symlink() or not path.is_file() or sha256_file(path) != binding["sha256"]:
        raise ValueError(f"{label} binding does not verify")
    return path


def _validated_terminal_binding(
    terminal: Path,
    *,
    candidate: Any,
    provenance_sha256: str,
) -> dict[str, str]:
    """Validate an immutable terminal deeply enough to recover its checkpoint."""

    if terminal.is_symlink() or not terminal.is_file():
        raise ValueError("terminal evidence is not a regular file")
    receipt = load_json(terminal)
    if terminal.read_bytes() != canonical_json_bytes(receipt):
        raise ValueError("terminal evidence is not canonically encoded")
    payload = validate_hash_bound_receipt(receipt, expected_type=TERMINAL_TYPE)
    if set(payload) != {
        "candidate_id",
        "kind",
        "reason",
        "provenance_sha256",
        "stability_receipt",
        "admitted_workload",
    }:
        raise ValueError("terminal evidence fields differ from the contract")
    if (
        payload["candidate_id"] != candidate.candidate_id
        or payload["provenance_sha256"] != provenance_sha256
    ):
        raise ValueError("terminal evidence identity/provenance mismatch")
    kind = payload["kind"]
    reason = payload["reason"]
    if kind not in TERMINAL_KINDS:
        raise ValueError("terminal evidence has an unsupported outcome kind")
    if (kind == "eligible" and reason is not None) or (
        kind != "eligible" and not isinstance(reason, str)
    ):
        raise ValueError("terminal evidence reason differs from its outcome kind")
    stability_binding = payload["stability_receipt"]
    workload_binding = payload["admitted_workload"]
    if kind == "eligible":
        if not isinstance(stability_binding, Mapping) or not isinstance(workload_binding, Mapping):
            raise ValueError("eligible terminal lacks transitive evidence bindings")
        stability_path = _verified_bound_file(stability_binding, label="eligible stability receipt")
        workload_path = _verified_bound_file(workload_binding, label="eligible admitted workload")
        from .class_catalogue import load_stability_receipt

        stability_value, decision = load_stability_receipt(stability_path)
        stability_payload = validate_hash_bound_receipt(
            stability_value, expected_type="qcsd-class-study-page-stability"
        )
        if (
            not decision.eligible
            or stability_payload["candidate"]["candidate_id"] != candidate.candidate_id
            or stability_payload["candidate"]["domain"] != candidate.domain
            or stability_payload["decision"]["stable_values"]["prepared_workload_sha256"]
            != sha256_file(workload_path)
        ):
            raise ValueError("eligible terminal stability/workload binding is invalid")
    elif stability_binding is not None or workload_binding is not None:
        raise ValueError("ineligible terminal unexpectedly binds admitted evidence")
    return {
        "path": f"terminals/{candidate.candidate_id}.json",
        "sha256": sha256_file(terminal),
    }


def _foundation_attestation_binding(path: Path) -> dict[str, str]:
    source = Path(os.path.abspath(path))
    if source.is_symlink() or not source.is_file():
        raise ValueError("class acquisition foundation must be a regular file")
    value = load_json(source)
    if not isinstance(value, Mapping):
        raise TypeError("class acquisition foundation is not an object")
    if source.read_bytes() != canonical_json_bytes(value):
        raise ValueError("class acquisition foundation is not canonically encoded")
    validate_hash_bound_receipt(
        value,
        expected_type="qcsd-class-study-foundation-attestation",
    )
    return {"path": str(source), "sha256": sha256_file(source)}


def _validate_runner_runtime(provenance: Mapping[str, Any]) -> None:
    """Prevent later stability probes from changing the frozen prepare image."""

    foundation = provenance.get("foundation_attestation")
    if not isinstance(foundation, Mapping):
        raise ValueError("class acquisition provenance has no foundation binding")
    foundation_path = _verified_bound_file(foundation, label="class acquisition foundation")
    if _foundation_attestation_binding(foundation_path) != dict(foundation):
        raise ValueError("class acquisition foundation binding changed")
    current_image = os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native")
    current_source = source_metadata()
    if (
        provenance.get("image_digest") != current_image
        or provenance.get("source") != current_source
    ):
        raise ValueError("class acquisition runtime differs from its frozen source/prepare image")


def _validate_observation_provenance(
    states: Mapping[str, Any],
    *,
    provenance_sha256: str,
    runner_provenance: Mapping[str, Any],
) -> dict[str, Any] | None:
    identities: dict[str, dict[str, Any]] = {}
    for state in states.values():
        if state.get("terminal") is None:
            continue
        for page in state.get("pages", []):
            approved = page.get("approved_origins", [])
            if not isinstance(approved, list) or len(approved) > MAX_APPROVED_ORIGINS:
                raise ValueError("checkpoint approved-origin evidence is invalid")
            for observation in page.get("observations", []):
                observation_approved = observation.get("approved_origins")
                discovered = observation.get("discovery_observed_origins")
                expandable = observation.get("discovery_expandable_origins")
                pins = observation.get("discovery_origin_ip_pins")
                neqo = observation.get("neqo_provenance")
                chromium = observation.get("chromium_version")
                if (
                    observation.get("runner_provenance_sha256") != provenance_sha256
                    or not _is_canonical_origin_ledger(
                        observation_approved,
                        maximum=MAX_APPROVED_ORIGINS,
                        allow_empty=False,
                    )
                    or not _is_canonical_origin_ledger(
                        discovered,
                        maximum=MAX_OBSERVED_AUDIT_ORIGINS,
                        allow_empty=False,
                    )
                    or not _is_canonical_origin_ledger(
                        expandable,
                        maximum=MAX_APPROVED_ORIGINS,
                        allow_empty=False,
                    )
                    or not set(expandable).issubset(discovered)
                    or not set(expandable).issubset(observation_approved)
                    or not isinstance(pins, Mapping)
                    or set(pins) != set(observation_approved)
                    or any(
                        not isinstance(address, str) or not _is_public_network_address(address)
                        for address in pins.values()
                    )
                    or not isinstance(chromium, str)
                    or not chromium
                    or not isinstance(neqo, Mapping)
                    or not neqo
                    or _timestamp(observation["probe_completed_at"])
                    < _timestamp(observation["observed_at"])
                ):
                    raise ValueError("checkpoint observation provenance is invalid")
                identity = {"chromium_version": chromium, "neqo_provenance": dict(neqo)}
                identities[sha256_bytes(canonical_json_bytes(identity))] = identity
    if not identities:
        return None
    if len(identities) != 1:
        raise ValueError("checkpoint mixes browser or Neqo toolchain identities")
    [identity] = identities.values()
    return {
        **identity,
        "image_digest": runner_provenance["image_digest"],
        "source": runner_provenance["source"],
    }


def _is_canonical_origin_ledger(
    value: object,
    *,
    maximum: int,
    allow_empty: bool,
) -> bool:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or len(value) > maximum
        or any(not isinstance(candidate, str) for candidate in value)
        or value != sorted(set(value))
    ):
        return False
    return all(origin(candidate) == candidate for candidate in value)


def _probe_attempt_workload_id(
    candidate_id: str, page_ordinal: int, probe_id: str, attempt: int
) -> str:
    if (
        not isinstance(candidate_id, str)
        or not candidate_id
        or type(page_ordinal) is not int
        or page_ordinal < 0
        or probe_id not in {window.probe_id for window in STABILITY_PROBE_WINDOWS}
        or type(attempt) is not int
        or attempt < 1
    ):
        raise ValueError("acquisition probe attempt identity is invalid")
    return f"{candidate_id}-p{page_ordinal:02d}-{probe_id.replace('+', '')}-a{attempt:03d}"


def _validate_pending_probe(
    pending: object,
    *,
    candidate_id: str,
    page_ordinal: int,
    probe_id: str,
) -> tuple[int, datetime]:
    if not isinstance(pending, Mapping) or set(pending) != {
        "probe_id",
        "workload_id",
        "attempt",
        "observed_at",
    }:
        raise ValueError("pending acquisition probe checkpoint is malformed")
    attempt = pending["attempt"]
    if (
        type(attempt) is not int
        or attempt < 1
        or pending["probe_id"] != probe_id
        or pending["workload_id"]
        != _probe_attempt_workload_id(candidate_id, page_ordinal, probe_id, attempt)
        or not isinstance(pending["observed_at"], str)
    ):
        raise ValueError("pending acquisition probe checkpoint is malformed")
    return attempt, _timestamp(pending["observed_at"])


def _validate_pending_navigation(pending: object) -> tuple[int, datetime]:
    if not isinstance(pending, Mapping) or set(pending) != {"attempt", "started_at"}:
        raise ValueError("pending acquisition navigation checkpoint is malformed")
    attempt = pending["attempt"]
    if (
        type(attempt) is not int
        or not 1 <= attempt <= MAX_PROBE_ATTEMPTS
        or not isinstance(pending["started_at"], str)
    ):
        raise ValueError("pending acquisition navigation checkpoint is malformed")
    return attempt, _timestamp(pending["started_at"])


def _validate_navigation_attempts(state: Mapping[str, Any]) -> None:
    attempts = state.get("navigation_attempts", [])
    if not isinstance(attempts, list) or len(attempts) > MAX_PROBE_ATTEMPTS:
        raise ValueError("acquisition navigation-attempt ledger is malformed")
    expected_attempt = 1
    completed = 0
    finalised = False
    for item in attempts:
        if not isinstance(item, Mapping) or set(item) != {
            "attempt",
            "started_at",
            "completed_at",
            "outcome",
            "reason",
        }:
            raise ValueError("acquisition navigation-attempt ledger is malformed")
        if (
            item["attempt"] != expected_attempt
            or finalised
            or item["outcome"]
            not in {
                "completed",
                "interrupted",
                "recoverable-failure",
                "terminal-policy-rejection",
            }
            or not isinstance(item["started_at"], str)
            or not isinstance(item["completed_at"], str)
            or _timestamp(item["completed_at"]) < _timestamp(item["started_at"])
            or (item["outcome"] == "completed" and item["reason"] is not None)
            or (
                item["outcome"] != "completed"
                and (not isinstance(item["reason"], str) or not item["reason"])
            )
        ):
            raise ValueError("acquisition navigation-attempt ledger is malformed")
        completed += item["outcome"] == "completed"
        finalised = item["outcome"] in {
            "completed",
            "terminal-policy-rejection",
        }
        expected_attempt += 1
    if completed > 1:
        raise ValueError("acquisition navigation-attempt ledger duplicates success")
    if completed and state.get("state") == "pending":
        raise ValueError("pending acquisition candidate already completed navigation")
    pending = state.get("pending_navigation")
    if pending is not None:
        attempt, _started = _validate_pending_navigation(pending)
        if attempt != expected_attempt:
            raise ValueError("pending acquisition navigation attempt is not sequential")


def _validate_probe_attempts(
    page: Mapping[str, Any],
    *,
    candidate_id: str,
    baseline_started_at: str | None = None,
) -> None:
    attempts = page.get("probe_attempts", [])
    if not isinstance(attempts, list):
        raise ValueError("acquisition probe-attempt ledger is malformed")
    seen: set[tuple[str, int]] = set()
    successful: set[str] = set()
    finalised: set[str] = set()
    probe_ids = tuple(window.probe_id for window in STABILITY_PROBE_WINDOWS)
    expected_attempts = {probe_id: 1 for probe_id in probe_ids}
    for item in attempts:
        if not isinstance(item, Mapping) or set(item) != {
            "probe_id",
            "workload_id",
            "attempt",
            "observed_at",
            "completed_at",
            "outcome",
            "reason",
        }:
            raise ValueError("acquisition probe-attempt ledger is malformed")
        probe_id = item["probe_id"]
        attempt = item["attempt"]
        probe_index = probe_ids.index(probe_id) if probe_id in probe_ids else -1
        observed_at = (
            _timestamp(item["observed_at"])
            if isinstance(item.get("observed_at"), str)
            else None
        )
        start_in_window = True
        if observed_at is not None and baseline_started_at is not None and probe_index >= 0:
            elapsed_ms = round(
                (observed_at - _timestamp(baseline_started_at)).total_seconds() * 1000
            )
            window = STABILITY_PROBE_WINDOWS[probe_index]
            start_in_window = window.earliest_ms <= elapsed_ms <= window.latest_ms
        if (
            probe_index < 0
            or any(previous not in successful for previous in probe_ids[:probe_index])
            or type(attempt) is not int
            or not 1 <= attempt <= MAX_PROBE_ATTEMPTS
            or attempt != expected_attempts.get(probe_id)
            or probe_id in finalised
            or item["workload_id"]
            != _probe_attempt_workload_id(
                candidate_id,
                page["page"]["ordinal"],
                probe_id,
                attempt,
            )
            or (probe_id, attempt) in seen
            or item["outcome"]
            not in {
                "completed",
                "interrupted",
                "recoverable-failure",
                "terminal-policy-rejection",
            }
            or not isinstance(item["observed_at"], str)
            or not start_in_window
            or not isinstance(item["completed_at"], str)
            or _timestamp(item["completed_at"]) < _timestamp(item["observed_at"])
            or (
                item["outcome"] == "completed"
                and item["reason"] is not None
            )
            or (
                item["outcome"] != "completed"
                and (not isinstance(item["reason"], str) or not item["reason"])
            )
        ):
            raise ValueError("acquisition probe-attempt ledger is malformed")
        seen.add((probe_id, attempt))
        expected_attempts[probe_id] += 1
        if item["outcome"] == "completed":
            if probe_id in successful:
                raise ValueError("acquisition probe-attempt ledger duplicates success")
            successful.add(probe_id)
            finalised.add(probe_id)
        elif item["outcome"] == "terminal-policy-rejection":
            finalised.add(probe_id)
    observations = page.get("observations", [])
    if (
        not isinstance(observations, list)
        or len(observations) > len(probe_ids)
        or any(not isinstance(observation, Mapping) for observation in observations)
    ):
        raise ValueError("acquisition probe observation sequence is malformed")
    observation_sequence = [observation.get("probe_id") for observation in observations]
    if observation_sequence != list(probe_ids[: len(observation_sequence)]):
        raise ValueError("acquisition probe observation sequence is malformed")
    observation_ids = set(observation_sequence)
    if successful != observation_ids:
        raise ValueError("acquisition probe-attempt success ledger is inconsistent")
    pending = page.get("pending_probe")
    if pending is not None:
        observation_count = len(page.get("observations", []))
        if observation_count >= len(STABILITY_PROBE_WINDOWS):
            raise ValueError("completed acquisition page retains a pending probe")
        probe_id = STABILITY_PROBE_WINDOWS[observation_count].probe_id
        attempt, _started = _validate_pending_probe(
            pending,
            candidate_id=candidate_id,
            page_ordinal=page["page"]["ordinal"],
            probe_id=probe_id,
        )
        if attempt != expected_attempts[probe_id] or probe_id in finalised:
            raise ValueError("pending acquisition probe attempt is not sequential")


def _due_pages(
    state: Mapping[str, Any], now: datetime, *, candidate_id: str
) -> list[dict[str, Any]]:
    baseline = _timestamp(state["baseline_started_at"])
    result: list[dict[str, Any]] = []
    for page in state["pages"]:
        if page.get("rejection") is not None:
            continue
        index = len(page["observations"])
        if index >= len(STABILITY_PROBE_WINDOWS):
            continue
        window = STABILITY_PROBE_WINDOWS[index]
        pending = page.get("pending_probe")
        if pending is not None:
            _attempt, pending_started = _validate_pending_probe(
                pending,
                candidate_id=candidate_id,
                page_ordinal=page["page"]["ordinal"],
                probe_id=window.probe_id,
            )
            pending_elapsed = round((pending_started - baseline).total_seconds() * 1000)
            elapsed = round((now - baseline).total_seconds() * 1000)
            if (
                not window.earliest_ms <= pending_elapsed <= window.latest_ms
                or now < pending_started
            ):
                raise ValueError("pending acquisition probe time is malformed")
            # A start checkpoint proves only that work was about to begin.  It
            # is not evidence that a completed network acquisition occurred.
            # Once the outer window closes, never run fresh work under that old
            # timestamp; terminalise the candidate as a missed probe instead.
            if elapsed > window.latest_ms:
                raise MissedProbeWindow(f"missed mandatory acquisition window {window.probe_id}")
            result.append(page)
            continue
        elapsed = round((now - baseline).total_seconds() * 1000)
        if elapsed > window.latest_ms:
            raise MissedProbeWindow(f"missed mandatory acquisition window {window.probe_id}")
        if elapsed >= window.earliest_ms:
            result.append(page)
    return result


def _pending_baseline_blocked(states: Mapping[str, Any], now: datetime) -> bool:
    guard = timedelta(milliseconds=PENDING_BASELINE_GUARD_MS)
    for state in states.values():
        if state.get("terminal") is not None or state.get("state") != "probing":
            continue
        baseline = _timestamp(state["baseline_started_at"])
        for page in state["pages"]:
            if page.get("rejection") is not None:
                continue
            index = len(page["observations"])
            if index >= len(STABILITY_PROBE_WINDOWS) or page.get("pending_probe"):
                continue
            earliest = baseline + timedelta(milliseconds=STABILITY_PROBE_WINDOWS[index].earliest_ms)
            if now < earliest <= now + guard:
                return True
    return False


def _terminalise(
    root: Path,
    state: dict[str, Any],
    candidate_id: str,
    kind: str,
    reason: str | None,
    provenance_path: Path,
    *,
    stability_receipt: Path | None = None,
    admitted_workload: Path | None = None,
) -> None:
    payload = {
        "candidate_id": candidate_id,
        "kind": kind,
        "reason": reason,
        "provenance_sha256": sha256_file(provenance_path),
        "stability_receipt": (
            {
                "path": str(stability_receipt.resolve()),
                "sha256": sha256_file(stability_receipt),
            }
            if stability_receipt
            else None
        ),
        "admitted_workload": (
            {
                "path": str(admitted_workload.resolve()),
                "sha256": sha256_file(admitted_workload),
            }
            if admitted_workload
            else None
        ),
    }
    receipt = bind_receipt(payload, receipt_type=TERMINAL_TYPE)
    relative = f"terminals/{candidate_id}.json"
    (root / "terminals").mkdir(exist_ok=True)
    destination = root / relative
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != canonical_json_bytes(receipt)
        ):
            raise FileExistsError(f"immutable acquisition terminal already differs: {destination}")
    else:
        _create_json(destination, receipt)
    state["terminal"] = {"path": relative, "sha256": sha256_file(root / relative)}
    state["state"] = "terminal"


def _publish_admitted_workload(source: Path, destination: Path, expected_sha256: str) -> None:
    if source.is_symlink() or not source.is_file() or sha256_file(source) != expected_sha256:
        raise ValueError("selected prepared workload does not match its observation")
    validate_class_study_preparation(load_json(source), workload_id=destination.stem)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or sha256_file(destination) != expected_sha256
        ):
            raise FileExistsError("immutable admitted workload already differs")
        return
    with destination.open("xb") as output, source.open("rb") as input_file:
        shutil.copyfileobj(input_file, output)
        output.flush()
        os.fsync(output.fileno())
    fsync_directory(destination.parent)


def _checkpoint(
    *, provenance_sha256: str, catalogue_sha256: str, candidates: Mapping[str, Any]
) -> dict[str, Any]:
    return bind_receipt(
        {
            "provenance_sha256": provenance_sha256,
            "candidate_catalogue_sha256": catalogue_sha256,
            "candidates": candidates,
        },
        receipt_type=CHECKPOINT_TYPE,
    )


def _save_acquisition_checkpoint(
    path: Path,
    *,
    provenance_path: Path,
    catalogue_path: Path,
    candidates: Mapping[str, Any],
) -> None:
    atomic_json(
        path,
        _checkpoint(
            provenance_sha256=sha256_file(provenance_path),
            catalogue_sha256=sha256_file(catalogue_path),
            candidates=candidates,
        ),
    )


def _load_checkpoint(path: Path, provenance_path: Path, catalogue_path: Path) -> dict[str, Any]:
    value, _recoveries = _load_checkpoint_state(
        path,
        provenance_path,
        catalogue_path,
        persist_recoveries=True,
    )
    return value


def _load_checkpoint_state(
    path: Path,
    provenance_path: Path,
    catalogue_path: Path,
    *,
    persist_recoveries: bool,
) -> tuple[dict[str, Any], int]:
    value = load_json(path)
    payload = validate_hash_bound_receipt(value, expected_type=CHECKPOINT_TYPE)
    if payload["provenance_sha256"] != sha256_file(provenance_path) or payload[
        "candidate_catalogue_sha256"
    ] != sha256_file(catalogue_path):
        raise ValueError("acquisition checkpoint bindings do not verify")
    _catalogue, candidates = load_candidate_catalogue_receipt(catalogue_path)
    states = payload.get("candidates")
    expected_ids = {candidate.candidate_id for candidate in candidates}
    if not isinstance(states, Mapping) or set(states) != expected_ids:
        raise ValueError("acquisition checkpoint candidate set is invalid")
    terminals = path.parent / "terminals"
    if terminals.exists() or terminals.is_symlink():
        if terminals.is_symlink() or not terminals.is_dir():
            raise ValueError("acquisition terminal root is not a regular directory")
    elif persist_recoveries:
        terminals.mkdir()
        fsync_directory(path.parent)
    else:
        raise ValueError("acquisition terminal root does not exist")
    expected_names = {f"{candidate_id}.json" for candidate_id in expected_ids}
    for entry in terminals.iterdir():
        if ATOMIC_TEMP_MARKER in entry.name:
            if entry.is_symlink() or not entry.is_file():
                raise ValueError("acquisition terminal temporary path is unsafe")
            continue
        if entry.name not in expected_names:
            raise ValueError(f"unexpected acquisition terminal path: {entry}")

    provenance_sha256 = sha256_file(provenance_path)
    recoveries: list[tuple[dict[str, Any], dict[str, str]]] = []
    for candidate in candidates:
        state = states[candidate.candidate_id]
        if not isinstance(state, dict) or state.get("state") not in {
            "pending",
            "probing",
            "terminal",
        }:
            raise ValueError("acquisition checkpoint candidate state is invalid")
        _validate_navigation_attempts(state)
        if "navigation_rejections" in state:
            _validate_navigation_rejections(
                state["navigation_rejections"], boundary=candidate.domain
            )
        if "navigation_observed_origins" in state:
            global_origins = _canonical_navigation_origins(
                state["navigation_observed_origins"],
                label="checkpoint global navigation origin ledger",
            )
            pages = state.get("pages")
            if not isinstance(pages, list):
                raise TypeError("checkpoint page ledger is not a list")
            for page_state in pages:
                if not isinstance(page_state, Mapping):
                    raise TypeError("checkpoint page ledger contains a non-object")
                _validate_probe_attempts(
                    page_state,
                    candidate_id=candidate.candidate_id,
                    baseline_started_at=state["baseline_started_at"],
                )
                page_origins = _canonical_navigation_origins(
                    page_state.get("navigation_observed_origins"),
                    label="checkpoint per-page navigation origin ledger",
                )
                if not set(page_origins).issubset(global_origins):
                    raise ValueError(
                        "checkpoint per-page navigation origins exceed the global ledger"
                    )
        elif state["state"] == "probing" or state.get("pages"):
            raise ValueError("checkpoint lacks its navigation origin ledger")
        binding = state.get("terminal")
        terminal = terminals / f"{candidate.candidate_id}.json"
        if terminal.exists() or terminal.is_symlink():
            verified = _validated_terminal_binding(
                terminal,
                candidate=candidate,
                provenance_sha256=provenance_sha256,
            )
            if binding is None:
                recoveries.append((state, verified))
            elif state["state"] != "terminal" or binding != verified:
                raise ValueError("checkpoint terminal binding is inconsistent")
        elif binding is not None or state["state"] == "terminal":
            raise ValueError("checkpoint references missing terminal evidence")
    if recoveries and persist_recoveries:
        for state, binding in recoveries:
            state["state"] = "terminal"
            state["terminal"] = binding
        _save_acquisition_checkpoint(
            path,
            provenance_path=provenance_path,
            catalogue_path=catalogue_path,
            candidates=states,
        )
        value = load_json(path)
    return value, len(recoveries)


def _new_directory(path: Path) -> Path:
    target = Path(os.path.abspath(path))
    target.mkdir(parents=True, exist_ok=False)
    return target


def _regular_directory(path: Path) -> Path:
    target = Path(os.path.abspath(path))
    if target.is_symlink() or not target.is_dir():
        raise ValueError("acquisition root must be a regular directory")
    return target


def _create_json(path: Path, value: Mapping[str, Any]) -> None:
    durable_create(path, canonical_json_bytes(value))


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(UTC)


def _format_time(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat().replace("+00:00", "Z")
