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

    discovered: dict[str, DiscoveredRequest] = {}
    observed_origins: set[str] = set()
    exclusions: dict[tuple[str, str], dict[str, str]] = {}
    observed_request_count = 0
    final_url = url
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"),
            args=["--disable-quic=false", "--enable-quic", "--no-sandbox"],
        )
        chromium_version = browser.version
        context = browser.new_context(ignore_https_errors=False)
        page = context.new_page()
        session = context.new_cdp_session(page)
        session.send("Network.enable")
        request_urls: dict[str, str] = {}
        pending_extra_headers: dict[str, dict[str, str]] = {}

        def exclude(url: str, reason: str) -> None:
            exclusions[(url, reason)] = {"url": url, "reason": reason}

        def request_seen(event: dict[str, Any]) -> None:
            nonlocal observed_request_count
            observed_request_count += 1
            request = event.get("request", {})
            url = str(request.get("url", ""))
            method = str(request.get("method", ""))
            request_origin = origin(url)
            if request_origin:
                observed_origins.add(request_origin)
            reason = exclusion_reason(method, url, set(approved))
            if reason:
                exclude(url, reason)
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
        page.goto(url, wait_until="load", timeout=timeout_ms)
        page.wait_for_timeout(SETTLE_MS)
        final_url = page.url
        page.close()
        browser.close()

    missing = set(approved) - observed_origins
    if missing:
        raise ValueError(f"approved origins were not observed: {', '.join(sorted(missing))}")
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
        observed_request_count=observed_request_count,
        observed_origins=sorted(observed_origins),
        approved_origins=approved,
        exclusions=sorted(exclusions.values(), key=lambda item: (item["url"], item["reason"])),
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
