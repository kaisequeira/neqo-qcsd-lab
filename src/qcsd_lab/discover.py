from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .manifest import safe_discovery_headers, write_frozen_manifest


@dataclass
class DiscoveredRequest:
    url: str
    resource_type: str
    headers: dict[str, str]
    initiator_urls: list[str] = field(default_factory=list)


def discover(urls: list[str], output: Path, *, timeout_ms: int, force: bool) -> str:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError("discovery requires the discovery Docker image") from error

    discovered: dict[str, DiscoveredRequest] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"),
            args=["--disable-quic=false", "--enable-quic", "--no-sandbox"],
        )
        context = browser.new_context(ignore_https_errors=False)
        for page_url in urls:
            page = context.new_page()
            session = context.new_cdp_session(page)
            session.send("Network.enable")
            request_urls: dict[str, str] = {}
            pending_extra_headers: dict[str, dict[str, str]] = {}

            def request_seen(event: dict[str, Any]) -> None:
                request = event.get("request", {})
                url = request.get("url", "")
                if request.get("method") != "GET" or not url.startswith("https://"):
                    return
                initiator = event.get("initiator", {})
                stack_urls = ([initiator["url"]] if initiator.get("url") else []) + [
                    frame.get("url", "")
                    for frame in initiator.get("stack", {}).get("callFrames", [])
                    if frame.get("url")
                ]
                entry = discovered.setdefault(
                    url,
                    DiscoveredRequest(
                        url=url,
                        resource_type=event.get("type", "Other"),
                        headers={str(k): str(v) for k, v in request.get("headers", {}).items()},
                        initiator_urls=stack_urls,
                    ),
                )
                request_id = str(event.get("requestId", ""))
                if request_id:
                    request_urls[request_id] = url
                    entry.headers.update(pending_extra_headers.pop(request_id, {}))

            def extra_headers_seen(event: dict[str, Any]) -> None:
                request_id = str(event.get("requestId", ""))
                headers = {
                    str(name): str(value)
                    for name, value in event.get("headers", {}).items()
                }
                if not request_id or not headers:
                    return
                url = request_urls.get(request_id)
                if url is None:
                    pending_extra_headers[request_id] = headers
                elif url in discovered:
                    discovered[url].headers.update(headers)

            session.on("Network.requestWillBeSent", request_seen)
            # CDP's base request event can omit transport-added fields such as
            # Accept-Encoding. ExtraInfo carries the complete on-wire request
            # headers; events may arrive in either order, hence the request-ID
            # join above.
            session.on("Network.requestWillBeSentExtraInfo", extra_headers_seen)
            page.goto(page_url, wait_until="networkidle", timeout=timeout_ms)
            page.close()
        browser.close()

    ordered = list(discovered.values())
    url_to_id = {request.url: index for index, request in enumerate(ordered)}
    resources = []
    for resource_id, request in enumerate(ordered):
        dependencies = []
        for initiator in request.initiator_urls:
            dependency = url_to_id.get(initiator)
            if dependency is not None and dependency != resource_id:
                dependencies.append(dependency)
                break
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
    manifest = {
        "schema_version": 2,
        "header_policy": {
            "mode": "fresh-browser",
            "overrides": [],
            "allow_conditional": False,
            "allow_range": False,
        },
        "resources": resources,
    }
    return write_frozen_manifest(output, manifest, force=force)
