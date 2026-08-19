from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .manifest import https_origin, safe_discovery_headers

SETTLE_MS = 3_000


@dataclass
class DiscoveredRequest:
    url: str
    resource_type: str
    headers: dict[str, str]
    initiator_urls: set[str] = field(default_factory=set)


@dataclass
class DiscoveryResult:
    """Browser request graph and the evidence needed to audit its preparation."""

    source_url: str
    final_url: str
    chromium_version: str
    settle_ms: int
    observed_request_count: int
    observed_origins: list[str]
    approved_origins: list[str]
    exclusions: list[dict[str, str]]
    resources: list[dict[str, Any]]


@dataclass
class _RequestAdmission:
    """Record and enforce the discovery request policy before network I/O."""

    approved_origins: set[str]
    observed_request_count: int = 0
    observed_origins: set[str] = field(default_factory=set)
    exclusions: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)

    def exclude(self, url: str, reason: str) -> None:
        self.exclusions[(url, reason)] = {"url": url, "reason": reason}

    def enforce(self, session: Any, event: dict[str, Any]) -> None:
        """Continue an approved HTTPS GET or fail it while still request-stage paused."""

        request_id = str(event.get("requestId", ""))
        if not request_id:
            raise RuntimeError("Chromium request interception omitted its request identifier")
        request = event.get("request", {})
        url = str(request.get("url", ""))
        method = str(request.get("method", ""))
        self.observed_request_count += 1
        request_origin = origin(url)
        if request_origin:
            self.observed_origins.add(request_origin)
        reason = exclusion_reason(method, url, self.approved_origins)
        if reason:
            # Record before failing so an interception error cannot erase the
            # audit reason for a request that was denied network admission.
            self.exclude(url, reason)
            session.send(
                "Fetch.failRequest",
                {"requestId": request_id, "errorReason": "BlockedByClient"},
            )
            return
        session.send("Fetch.continueRequest", {"requestId": request_id})


def origin(url: str) -> str | None:
    return https_origin(url)


def discover_page(
    url: str,
    *,
    allow_origins: list[str],
    timeout_ms: int,
) -> DiscoveryResult:
    """Discover one page graph while retaining only explicitly approved origins."""

    if origin(url) is None:
        raise ValueError(f"source URL is not absolute HTTPS: {url}")
    if timeout_ms < 1:
        raise ValueError("discovery timeout must be positive")
    approved = sorted({_normalize_origin(value) for value in allow_origins})
    if not approved:
        raise ValueError("workload preparation requires at least one approved origin")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError("discovery requires the discovery Docker image") from error

    admission = _RequestAdmission(set(approved))
    discovered: dict[str, DiscoveredRequest] = {}
    final_url = url
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"),
            args=["--disable-quic=false", "--enable-quic", "--no-sandbox"],
        )
        chromium_version = browser.version
        # Fetch interception does not see frame-owned requests already handled
        # by a service worker.  Blocking registration makes the request-stage
        # policy the only path from this fresh context to the network.
        context = browser.new_context(ignore_https_errors=False, service_workers="block")
        page = context.new_page()
        session = context.new_cdp_session(page)
        request_urls: dict[str, str] = {}
        pending_extra_headers: dict[str, dict[str, str]] = {}

        def request_seen(event: dict[str, Any]) -> None:
            request = event.get("request", {})
            url = str(request.get("url", ""))
            method = str(request.get("method", ""))
            reason = exclusion_reason(method, url, admission.approved_origins)
            if reason:
                # Network.requestWillBeSent can precede Fetch.requestPaused.
                # Keep this defensive record, while Fetch remains the only
                # callback that decides whether bytes may leave Chromium.
                admission.exclude(url, reason)
                return
            initiator = event.get("initiator", {})
            initiators = {
                str(value)
                for value in (
                    event.get("documentURL"),
                    initiator.get("url"),
                    *(
                        frame.get("url")
                        for frame in initiator.get("stack", {}).get("callFrames", [])
                    ),
                )
                if value
            }
            entry = discovered.setdefault(
                url,
                DiscoveredRequest(
                    url=url,
                    resource_type=str(event.get("type", "Other")),
                    headers={},
                ),
            )
            merge_request_headers(entry.headers, request.get("headers", {}))
            entry.initiator_urls.update(initiators)
            request_id = str(event.get("requestId", ""))
            if request_id:
                request_urls[request_id] = url
                merge_request_headers(
                    entry.headers,
                    pending_extra_headers.pop(request_id, {}),
                )

        def extra_headers_seen(event: dict[str, Any]) -> None:
            request_id = str(event.get("requestId", ""))
            headers = event.get("headers", {})
            if not request_id or not headers:
                return
            url = request_urls.get(request_id)
            if url is None:
                pending = pending_extra_headers.setdefault(request_id, {})
                merge_request_headers(pending, headers)
            elif url in discovered:
                # ExtraInfo contains Chromium's final wire request headers, so
                # it deliberately wins over requestWillBeSent.
                merge_request_headers(discovered[url].headers, headers)

        session.on("Network.requestWillBeSent", request_seen)
        session.on("Network.requestWillBeSentExtraInfo", extra_headers_seen)
        session.on("Fetch.requestPaused", lambda event: admission.enforce(session, event))
        session.send("Network.enable")
        session.send(
            "Fetch.enable",
            {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
        )
        page.goto(url, wait_until="load", timeout=timeout_ms)
        page.wait_for_timeout(SETTLE_MS)
        final_url = page.url
        page.close()
        browser.close()

    if origin(final_url) not in approved:
        raise ValueError("the final page origin was not explicitly approved")
    resources = build_resources(list(discovered.values()))
    if not resources:
        raise ValueError("browser discovery left no approved HTTPS GET resources")
    return DiscoveryResult(
        source_url=url,
        final_url=final_url,
        chromium_version=chromium_version,
        settle_ms=SETTLE_MS,
        observed_request_count=admission.observed_request_count,
        observed_origins=sorted(admission.observed_origins),
        approved_origins=approved,
        exclusions=sorted(
            admission.exclusions.values(), key=lambda item: (item["url"], item["reason"])
        ),
        resources=resources,
    )


def exclusion_reason(method: str, url: str, approved: set[str]) -> str | None:
    if method != "GET":
        return f"unsafe method: {method or 'unknown'}"
    request_origin = origin(url)
    if request_origin is None:
        return "not an absolute HTTPS request"
    if request_origin not in approved:
        return "origin not approved"
    return None


def merge_request_headers(target: dict[str, str], headers: dict[str, Any]) -> None:
    """Merge HTTP headers case-insensitively, with the new observation winning."""

    for raw_name, raw_value in headers.items():
        target[str(raw_name).lower()] = str(raw_value)


def build_resources(ordered: list[DiscoveredRequest]) -> list[dict[str, Any]]:
    url_to_id = {request.url: index for index, request in enumerate(ordered)}
    resources = []
    for resource_id, request in enumerate(ordered):
        dependencies = sorted(
            {
                dependency
                for initiator in request.initiator_urls
                if (dependency := url_to_id.get(initiator)) is not None
                and dependency != resource_id
            }
        )
        resources.append(
            {
                "id": resource_id,
                "url": request.url,
                "type": request.resource_type,
                "content_length": None,
                "data_length": 0,
                "chaff_priority": False,
                "known_valid": False,
                "depends_on": dependencies,
                "headers": safe_discovery_headers(request.headers),
            }
        )
    return resources


def _normalize_origin(value: str) -> str:
    normalized = origin(value)
    if normalized is None:
        raise ValueError(f"approved origin is not absolute HTTPS: {value}")
    parts = urlsplit(value)
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError(f"approved origin must not contain a path: {value}")
    return normalized
