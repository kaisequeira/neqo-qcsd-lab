from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .manifest import safe_discovery_headers, write_frozen_manifest

SETTLE_MS = 3_000


@dataclass
class DiscoveredRequest:
    url: str
    resource_type: str
    headers: dict[str, str]
    initiator_urls: set[str] = field(default_factory=set)


def origin(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        return None
    return f"https://{parts.netloc}"


def discover(
    urls: list[str],
    output: Path,
    *,
    allow_origins: list[str],
    timeout_ms: int,
    force: bool,
) -> str:
    """Discover one page graph and retain only explicitly reviewed origins."""

    if len(urls) != 1:
        raise ValueError("replay discovery requires exactly one final page URL")
    reviewed = sorted({_normalize_origin(value) for value in allow_origins})
    if not reviewed:
        raise ValueError("replay discovery requires at least one --allow-origin")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError("discovery requires the discovery Docker image") from error

    discovered: dict[str, DiscoveredRequest] = {}
    observed_origins: set[str] = set()
    exclusions: dict[tuple[str, str], dict[str, str]] = {}
    observed_request_count = 0
    final_url = urls[0]
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
            reason = exclusion_reason(method, url, set(reviewed))
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
                    headers={str(k): str(v) for k, v in request.get("headers", {}).items()},
                ),
            )
            entry.initiator_urls.update(initiators)
            request_id = str(event.get("requestId", ""))
            if request_id:
                request_urls[request_id] = url
                entry.headers.update(pending_extra_headers.pop(request_id, {}))

        def extra_headers_seen(event: dict[str, Any]) -> None:
            request_id = str(event.get("requestId", ""))
            headers = {
                str(name): str(value) for name, value in event.get("headers", {}).items()
            }
            if not request_id or not headers:
                return
            url = request_urls.get(request_id)
            if url is None:
                pending_extra_headers[request_id] = headers
            elif url in discovered:
                discovered[url].headers.update(headers)

        session.on("Network.requestWillBeSent", request_seen)
        session.on("Network.requestWillBeSentExtraInfo", extra_headers_seen)
        page.goto(urls[0], wait_until="load", timeout=timeout_ms)
        page.wait_for_timeout(SETTLE_MS)
        final_url = page.url
        page.close()
        browser.close()

    missing = set(reviewed) - observed_origins
    if missing:
        raise ValueError(f"reviewed origins were not observed: {', '.join(sorted(missing))}")
    resources = build_resources(list(discovered.values()))
    manifest = {
        "header_policy": {
            "mode": "fresh-browser",
            "overrides": [],
            "allow_conditional": False,
            "allow_range": False,
        },
        "resources": resources,
        "replay": {
            "source_url": urls[0],
            "final_url": final_url,
            "chromium_version": chromium_version,
            "settle_ms": SETTLE_MS,
            "observed_request_count": observed_request_count,
            "observed_origins": sorted(observed_origins),
            "reviewed_origins": reviewed,
            "exclusions": sorted(exclusions.values(), key=lambda item: (item["url"], item["reason"])),
        },
    }
    return write_frozen_manifest(output, manifest, force=force)


def exclusion_reason(method: str, url: str, reviewed: set[str]) -> str | None:
    if method != "GET":
        return f"unsafe method: {method or 'unknown'}"
    request_origin = origin(url)
    if request_origin is None:
        return "not an absolute HTTPS request"
    if request_origin not in reviewed:
        return "origin not reviewed"
    return None


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
        raise ValueError(f"reviewed origin is not absolute HTTPS: {value}")
    parts = urlsplit(value)
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError(f"reviewed origin must not contain a path: {value}")
    return normalized
