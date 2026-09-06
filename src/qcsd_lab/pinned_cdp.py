"""Create and verify the real pinned Playwright/Chromium topology receipt.

The probe is deliberately loopback-only.  Docker supplies ``--network none``
and drops every capability; this module independently records and checks the
observable process/network state before exercising the recursive CDP target
router.  Only a minimised topology summary is retained, never request headers
or bodies.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import socket
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .buflo_study import validate_build_execution_receipt
from .cdp_targets import CDP_TARGET_INSTRUMENTATION_POLICY, RecursiveCdpTargetRouter
from .class_study import (
    STUDY_ID,
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    validate_hash_bound_receipt,
    write_create_only_json,
)
from .discover import (
    DiscoveredRequest,
    _RequestExtraInfoAssociator,
    _RequestObservationLedger,
)
from .util import load_json, require_disjoint_path, sha256_file, source_metadata

RECEIPT_TYPE = "qcsd-class-study-pinned-cdp-probe"
PROBE_SCHEMA_VERSION = 1
EXPECTED_PLAYWRIGHT_VERSION = "1.52.0"
EXPECTED_CHROMIUM_EXECUTABLE = "/usr/bin/chromium"
PROBE_OBSERVATION_TIMEOUT_MS = 10_000
PROBE_QUIET_INTERVAL_MS = 250
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SOURCE_KEYS = {
    "image_digest",
    "lab_commit",
    "lab_dirty",
    "lab_patch_sha256",
    "neqo_commit",
    "neqo_pinned_commit",
    "neqo_dirty",
    "neqo_patch_sha256",
}

PROBE_CONTRACT: dict[str, Any] = {
    "schema_version": 1,
    "policy": "pinned-playwright-chromium-recursive-target-topology-v1",
    "instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
    "playwright_version": EXPECTED_PLAYWRIGHT_VERSION,
    "chromium_executable": EXPECTED_CHROMIUM_EXECUTABLE,
    "network_scope": "docker-network-none-loopback-only",
    "observation_timeout_ms": PROBE_OBSERVATION_TIMEOUT_MS,
    "required_quiet_interval_ms": PROBE_QUIET_INTERVAL_MS,
    "required_target_types": ["iframe", "shared_worker", "worker"],
    "required_observations": [
        "cross-site-iframe-network-request",
        "dedicated-and-shared-worker-network-requests",
        "worker-fetch-paused-on-owning-page-session",
        "duplicate-url-occurrences-remain-distinct",
        "redirect-terminal-request-observed",
        "router-ledger-extra-info-and-server-shutdown-complete",
    ],
}
PROBE_CONTRACT_SHA256 = canonical_json_sha256(PROBE_CONTRACT)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path == "/":
            body = b"""<iframe src='http://b.test:PORT/frame'></iframe><script>
            new Worker('/worker.js'); new SharedWorker('/worker.js');
            fetch('/duplicate'); fetch('/duplicate'); fetch('/redirect');
            </script>""".replace(b"PORT", str(self.server.server_port).encode())
            kind = "text/html"
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.end_headers()
            return
        elif self.path == "/frame":
            body, kind = b"<script>fetch('/frame-data')</script>", "text/html"
        elif self.path == "/worker.js":
            body, kind = b"fetch('/worker-data')", "text/javascript"
        else:
            body, kind = b"ok", "text/plain"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def run_pinned_cdp_probe(*, expected_uid: int, expected_gid: int) -> dict[str, Any]:
    """Run the real topology probe and return its sanitised observation."""

    isolation = _observe_isolation(expected_uid=expected_uid, expected_gid=expected_gid)
    playwright_version = importlib.metadata.version("playwright")
    if playwright_version != EXPECTED_PLAYWRIGHT_VERSION:
        raise ValueError("pinned CDP probe Playwright version differs from the contract")
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH")
    if executable != EXPECTED_CHROMIUM_EXECUTABLE:
        raise ValueError("pinned CDP probe Chromium executable differs from the contract")
    executable_path = Path(executable)
    if not executable_path.exists() or not os.access(executable_path, os.X_OK):
        raise ValueError("pinned CDP probe Chromium executable is unavailable")

    from playwright.sync_api import sync_playwright

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    observed_events: list[tuple[str, str, str]] = []
    chromium_version = ""
    router_closed = False
    ledger_closed = False
    extra_info_closed = False
    browser_closed = False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=executable,
                headless=True,
                args=[
                    "--no-sandbox",
                    "--no-proxy-server",
                    "--site-per-process",
                    "--host-resolver-rules=MAP a.test 127.0.0.1,MAP b.test 127.0.0.1",
                ],
            )
            chromium_version = browser.version
            try:
                context = browser.new_context(service_workers="block")
                page = context.new_page()
                page.set_default_timeout(PROBE_OBSERVATION_TIMEOUT_MS)
                page.set_default_navigation_timeout(PROBE_OBSERVATION_TIMEOUT_MS)
                session = context.new_cdp_session(page)
                router: RecursiveCdpTargetRouter
                ledger = _RequestObservationLedger(
                    eligible=lambda method, url: method == "GET" and url.startswith("http://")
                )
                extra_info = _RequestExtraInfoAssociator()

                def event(source: Any, method: str, payload: Mapping[str, Any]) -> None:
                    request = payload.get("request", {})
                    url = str(request.get("url", "")) if isinstance(request, Mapping) else ""
                    observed_events.append((source.target_type, method, url))
                    if method == "Network.requestWillBeSent":
                        redirected = payload.get("redirectResponse") is not None
                        extra_info.add_request(
                            source.request_chain_key(str(payload["requestId"])),
                            DiscoveredRequest(url, str(payload.get("type", "Other")), {}),
                            redirected=redirected,
                            redirect_has_extra_info=(
                                payload.get("redirectHasExtraInfo") if redirected else None
                            ),
                        )
                        ledger.add_network(
                            source,
                            request_id=str(payload["requestId"]),
                            method=str(request.get("method", "")),
                            url=url,
                        )
                    elif method == "Network.requestWillBeSentExtraInfo":
                        extra_info.add_extra_info(
                            source.request_chain_key(str(payload["requestId"])),
                            payload.get("headers"),
                        )
                    elif method == "Network.responseReceived":
                        extra_info.add_response(
                            source.request_chain_key(str(payload["requestId"])),
                            payload.get("hasExtraInfo"),
                        )
                    elif method in {"Network.loadingFinished", "Network.loadingFailed"}:
                        ledger.add_terminal(source, str(payload["requestId"]))
                        extra_info.add_terminal(
                            source.request_chain_key(str(payload["requestId"])),
                            failed=method == "Network.loadingFailed",
                        )
                    elif method == "Fetch.requestPaused":
                        ledger.add_interception(source, payload)
                        router.send(
                            source,
                            "Fetch.continueRequest",
                            {"requestId": payload["requestId"]},
                            label="probe-policy",
                        )

                router = RecursiveCdpTargetRouter(session, on_event=event)
                router.start()
                page.goto(f"http://a.test:{server.server_port}/", wait_until="load")
                _wait_for_required_observations(page, router, observed_events)
                router.begin_shutdown()
                context.close()
                router.finish()
                router_closed = True
                ledger.finish()
                ledger_closed = True
                extra_info.finish()
                extra_info_closed = True
            finally:
                browser.close()
                browser_closed = True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    topology = {
        **_event_topology(observed_events),
        "router_closed": router_closed,
        "ledger_closed": ledger_closed,
        "extra_info_closed": extra_info_closed,
        "browser_closed": browser_closed,
        "server_thread_stopped": not thread.is_alive(),
    }
    observation = {
        "playwright_version": playwright_version,
        "chromium_version": chromium_version,
        "chromium_executable": executable,
        "isolation": isolation,
        "topology": topology,
    }
    return _validate_observation(observation)


def _event_topology(events: Sequence[tuple[str, str, str]]) -> dict[str, Any]:
    return {
        "observed_target_types": sorted(
            {target_type for target_type, _method, _url in events}
        ),
        "event_count": len(events),
        "cross_site_iframe_request": any(
            target_type == "iframe"
            and method == "Network.requestWillBeSent"
            and url.endswith("/frame-data")
            for target_type, method, url in events
        ),
        "duplicate_request_occurrences": sum(
            method == "Network.requestWillBeSent" and url.endswith("/duplicate")
            for _target_type, method, url in events
        ),
        "redirect_terminal_request": any(
            method == "Network.requestWillBeSent" and url.endswith("/redirected")
            for _target_type, method, url in events
        ),
        "worker_network_target_types": sorted(
            {
                target_type
                for target_type, method, url in events
                if method == "Network.requestWillBeSent" and url.endswith("/worker-data")
            }
        ),
        "worker_fetch_paused_on_page": any(
            target_type == "page"
            and method == "Fetch.requestPaused"
            and url.endswith("/worker-data")
            for target_type, method, url in events
        ),
    }


def _required_event_topology_observed(events: Sequence[tuple[str, str, str]]) -> bool:
    topology = _event_topology(events)
    return (
        topology["observed_target_types"]
        == ["iframe", "page", "shared_worker", "worker"]
        and topology["cross_site_iframe_request"] is True
        and topology["duplicate_request_occurrences"] == 2
        and topology["redirect_terminal_request"] is True
        and topology["worker_network_target_types"] == ["shared_worker", "worker"]
        and topology["worker_fetch_paused_on_page"] is True
    )


def _wait_for_required_observations(
    page: Any,
    router: RecursiveCdpTargetRouter,
    events: Sequence[tuple[str, str, str]],
) -> None:
    """Wait for required topology and a quiet, request-free convergence interval."""

    deadline = time.monotonic() + PROBE_OBSERVATION_TIMEOUT_MS / 1_000
    quiet_since: float | None = None
    previous_count = -1
    while time.monotonic() < deadline:
        page.wait_for_timeout(25)
        router.raise_if_failed()
        now = time.monotonic()
        event_count = len(events)
        if event_count != previous_count:
            previous_count = event_count
            quiet_since = None
        elif _required_event_topology_observed(events) and not router.active_request_identities:
            if quiet_since is None:
                quiet_since = now
            elif (now - quiet_since) * 1_000 >= PROBE_QUIET_INTERVAL_MS:
                return
        else:
            quiet_since = None
    raise RuntimeError("pinned CDP probe did not converge on its required topology")


def create_pinned_cdp_receipt(
    destination: Path,
    *,
    build_execution_receipt: Path,
    cohort_version: int,
    expected_uid: int,
    expected_gid: int,
) -> Path:
    """Run the probe and create its source/build/image-bound receipt once."""

    if type(cohort_version) is not int or cohort_version < 1:
        raise ValueError("pinned CDP probe cohort version must be a positive integer")
    if type(expected_uid) is not int or expected_uid < 0:
        raise ValueError("pinned CDP probe expected UID is invalid")
    if type(expected_gid) is not int or expected_gid < 0:
        raise ValueError("pinned CDP probe expected GID is invalid")
    destination = require_disjoint_path(
        destination,
        (build_execution_receipt,),
        label="pinned CDP probe receipt destination",
    )
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"create-only pinned CDP probe receipt exists: {destination}")
    build = validate_build_execution_receipt(
        build_execution_receipt,
        expected_cohort_version=cohort_version,
    )
    prepare_source = {**build["source"], "image_digest": build["images"]["prepare"]["id"]}
    if source_metadata() != prepare_source:
        raise ValueError("pinned CDP probe runtime differs from the no-cache prepare image")
    observation = run_pinned_cdp_probe(expected_uid=expected_uid, expected_gid=expected_gid)
    recorded_at = datetime.now(UTC).isoformat()
    build_value = load_json(Path(build["path"]))
    payload = {
        "probe_schema_version": PROBE_SCHEMA_VERSION,
        "artifact_type": RECEIPT_TYPE,
        "study_id": STUDY_ID,
        "cohort_version": cohort_version,
        "recorded_at": recorded_at,
        "result": "pass",
        "build_execution": {
            "path": _canonical_build_receipt_path(cohort_version),
            "sha256": build["sha256"],
            "payload_sha256": build_value["payload_sha256"],
        },
        "build_execution_identity": {
            "cohort_version": build["cohort_version"],
            "sha256": build["sha256"],
            "collection_image": build["collection_image"],
            "started_at": build["started_at"],
            "finished_at": build["finished_at"],
        },
        "collection_source": build["source"],
        "prepare_source": prepare_source,
        "prepare_image_digest": build["images"]["prepare"]["id"],
        "probe_contract": PROBE_CONTRACT,
        "probe_contract_sha256": PROBE_CONTRACT_SHA256,
        "observation": observation,
    }
    _validate_payload(
        payload,
        build_execution_receipt=build_execution_receipt,
        expected_cohort_version=cohort_version,
        runtime_role="prepare",
    )
    output = write_create_only_json(destination, bind_receipt(payload, receipt_type=RECEIPT_TYPE))
    validate_pinned_cdp_receipt(
        output,
        build_execution_receipt=build_execution_receipt,
        expected_cohort_version=cohort_version,
        runtime_role="prepare",
    )
    return output


def validate_pinned_cdp_receipt(
    path: Path,
    *,
    build_execution_receipt: Path | None = None,
    expected_cohort_version: int | None = None,
    runtime_role: str | None = None,
) -> dict[str, Any]:
    """Reconstruct and validate one pinned-CDP receipt."""

    receipt_path = Path(os.path.abspath(path))
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("pinned CDP probe receipt is not a regular file")
    raw = receipt_path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("pinned CDP probe receipt is not valid UTF-8 JSON") from error
    if raw != canonical_json_bytes(value):
        raise ValueError("pinned CDP probe receipt is not canonically encoded")
    payload = validate_hash_bound_receipt(value, expected_type=RECEIPT_TYPE)
    validated = _validate_payload(
        payload,
        build_execution_receipt=build_execution_receipt,
        expected_cohort_version=expected_cohort_version,
        runtime_role=runtime_role,
    )
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": value["payload_sha256"],
        **validated,
    }


def _validate_payload(
    payload: Mapping[str, Any],
    *,
    build_execution_receipt: Path | None,
    expected_cohort_version: int | None,
    runtime_role: str | None,
) -> dict[str, Any]:
    if expected_cohort_version is not None and (
        type(expected_cohort_version) is not int or expected_cohort_version < 1
    ):
        raise ValueError("expected pinned CDP probe cohort version is invalid")
    expected_keys = {
        "probe_schema_version",
        "artifact_type",
        "study_id",
        "cohort_version",
        "recorded_at",
        "result",
        "build_execution",
        "build_execution_identity",
        "collection_source",
        "prepare_source",
        "prepare_image_digest",
        "probe_contract",
        "probe_contract_sha256",
        "observation",
    }
    if set(payload) != expected_keys:
        raise ValueError("pinned CDP probe payload fields differ from the contract")
    cohort_version = payload.get("cohort_version")
    if (
        payload.get("probe_schema_version") != PROBE_SCHEMA_VERSION
        or payload.get("artifact_type") != RECEIPT_TYPE
        or payload.get("study_id") != STUDY_ID
        or type(cohort_version) is not int
        or cohort_version < 1
        or payload.get("result") != "pass"
    ):
        raise ValueError("pinned CDP probe identity or result is invalid")
    if expected_cohort_version is not None and cohort_version != expected_cohort_version:
        raise ValueError("pinned CDP probe cohort version differs from the request")
    recorded_at = _timestamp(payload.get("recorded_at"), label="pinned CDP probe")
    binding = payload.get("build_execution")
    if (
        not isinstance(binding, Mapping)
        or set(binding) != {"path", "sha256", "payload_sha256"}
        or not isinstance(binding.get("path"), str)
        or _DIGEST.fullmatch(str(binding.get("sha256"))) is None
        or _DIGEST.fullmatch(str(binding.get("payload_sha256"))) is None
    ):
        raise ValueError("pinned CDP probe build binding is invalid")
    build_path = (
        Path(build_execution_receipt)
        if build_execution_receipt is not None
        else Path(str(binding["path"]))
    )
    build = validate_build_execution_receipt(
        build_path,
        expected_cohort_version=cohort_version,
    )
    build_value = load_json(Path(build["path"]))
    expected_binding = {
        "path": _canonical_build_receipt_path(cohort_version),
        "sha256": build["sha256"],
        "payload_sha256": build_value["payload_sha256"],
    }
    identity = {
        "cohort_version": build["cohort_version"],
        "sha256": build["sha256"],
        "collection_image": build["collection_image"],
        "started_at": build["started_at"],
        "finished_at": build["finished_at"],
    }
    prepare_image = build["images"]["prepare"]["id"]
    collection_source = build["source"]
    prepare_source = {**collection_source, "image_digest": prepare_image}
    _validate_clean_source(collection_source, label="pinned CDP collection source")
    _validate_clean_source(prepare_source, label="pinned CDP prepare source")
    if (
        dict(binding) != expected_binding
        or payload.get("build_execution_identity") != identity
        or payload.get("collection_source") != collection_source
        or payload.get("prepare_source") != prepare_source
        or payload.get("prepare_image_digest") != prepare_image
        or payload.get("probe_contract") != PROBE_CONTRACT
        or payload.get("probe_contract_sha256") != PROBE_CONTRACT_SHA256
    ):
        raise ValueError("pinned CDP probe differs from its source/build/prepare image")
    if recorded_at < _timestamp(build["finished_at"], label="no-cache build finish"):
        raise ValueError("pinned CDP probe predates its no-cache build")
    _validate_observation(payload.get("observation"))
    if runtime_role is not None:
        if runtime_role not in {"collection", "prepare"}:
            raise ValueError("pinned CDP probe runtime role is invalid")
        expected_source = prepare_source if runtime_role == "prepare" else collection_source
        if source_metadata() != expected_source:
            raise ValueError("pinned CDP probe validation runtime differs from its build")
    return json.loads(canonical_json_bytes(payload))


def _validate_observation(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "playwright_version",
        "chromium_version",
        "chromium_executable",
        "isolation",
        "topology",
    }:
        raise ValueError("pinned CDP probe observation fields are invalid")
    isolation = value.get("isolation")
    topology = value.get("topology")
    if (
        value.get("playwright_version") != EXPECTED_PLAYWRIGHT_VERSION
        or not isinstance(value.get("chromium_version"), str)
        or not str(value["chromium_version"]).strip()
        or value.get("chromium_executable") != EXPECTED_CHROMIUM_EXECUTABLE
    ):
        raise ValueError("pinned CDP probe browser evidence is invalid")
    _validate_isolation(isolation)
    if not isinstance(topology, Mapping) or set(topology) != {
        "observed_target_types",
        "event_count",
        "cross_site_iframe_request",
        "duplicate_request_occurrences",
        "redirect_terminal_request",
        "worker_network_target_types",
        "worker_fetch_paused_on_page",
        "router_closed",
        "ledger_closed",
        "extra_info_closed",
        "browser_closed",
        "server_thread_stopped",
    }:
        raise ValueError("pinned CDP probe topology fields are invalid")
    target_types = topology.get("observed_target_types")
    expected_types = ["iframe", "page", "shared_worker", "worker"]
    boolean_fields = (
        "cross_site_iframe_request",
        "redirect_terminal_request",
        "worker_fetch_paused_on_page",
        "router_closed",
        "ledger_closed",
        "extra_info_closed",
        "browser_closed",
        "server_thread_stopped",
    )
    if (
        not isinstance(target_types, list)
        or target_types != expected_types
        or any(not isinstance(item, str) or not item for item in target_types)
        or type(topology.get("event_count")) is not int
        or topology["event_count"] < 1
        or topology.get("duplicate_request_occurrences") != 2
        or topology.get("worker_network_target_types") != ["shared_worker", "worker"]
        or any(topology.get(field) is not True for field in boolean_fields)
    ):
        raise ValueError("pinned CDP probe topology evidence did not pass")
    return json.loads(canonical_json_bytes(value))


def _validate_isolation(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "real_uid",
            "effective_uid",
            "real_gid",
            "effective_gid",
            "expected_uid",
            "expected_gid",
            "effective_capabilities",
            "no_new_privileges",
            "observed_interfaces",
        }
        or any(
            type(value.get(field)) is not int or value[field] < 0
            for field in (
                "real_uid",
                "effective_uid",
                "real_gid",
                "effective_gid",
                "expected_uid",
                "expected_gid",
            )
        )
        or value["real_uid"] != value["expected_uid"]
        or value["effective_uid"] != value["expected_uid"]
        or value["real_gid"] != value["expected_gid"]
        or value["effective_gid"] != value["expected_gid"]
        or value.get("effective_capabilities") != "0000000000000000"
        or value.get("no_new_privileges") is not True
        or value.get("observed_interfaces") != ["lo"]
    ):
        raise ValueError("pinned CDP probe isolation evidence is invalid")
    return json.loads(canonical_json_bytes(value))


def _observe_isolation(*, expected_uid: int, expected_gid: int) -> dict[str, Any]:
    status: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        name, separator, raw = line.partition(":")
        if separator:
            status[name] = raw.strip()
    capabilities = status.get("CapEff", "").lower()
    if not re.fullmatch(r"[0-9a-f]{16}", capabilities):
        raise ValueError("pinned CDP probe cannot read effective capabilities")
    interfaces = sorted(name for _index, name in socket.if_nameindex())
    value = {
        "real_uid": os.getuid(),
        "effective_uid": os.geteuid(),
        "real_gid": os.getgid(),
        "effective_gid": os.getegid(),
        "expected_uid": expected_uid,
        "expected_gid": expected_gid,
        "effective_capabilities": capabilities,
        "no_new_privileges": status.get("NoNewPrivs") == "1",
        "observed_interfaces": interfaces,
    }
    return _validate_isolation(value)


def _validate_clean_source(value: object, *, label: str) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != _SOURCE_KEYS
        or _IMAGE_DIGEST.fullmatch(str(value.get("image_digest"))) is None
        or _COMMIT.fullmatch(str(value.get("lab_commit"))) is None
        or _COMMIT.fullmatch(str(value.get("neqo_commit"))) is None
        or value.get("neqo_commit") != value.get("neqo_pinned_commit")
        or value.get("lab_dirty") is not False
        or value.get("neqo_dirty") is not False
        or value.get("lab_patch_sha256") != _EMPTY_SHA256
        or value.get("neqo_patch_sha256") != _EMPTY_SHA256
    ):
        raise ValueError(f"{label} is not one clean immutable image source")


def _canonical_build_receipt_path(cohort_version: int) -> str:
    """Return the container-neutral evidence namespace stored in receipts."""

    return f"/lab/artifacts/buflo-study/build-execution-v{cohort_version}.json"


def _timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{label} timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="create a pinned CDP topology receipt")
    parser.add_argument("--build-execution-receipt", required=True, type=Path)
    parser.add_argument("--cohort-version", required=True, type=int)
    parser.add_argument("--destination", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        expected_uid = int(os.environ["QCSD_PINNED_CDP_EXPECTED_UID"])
        expected_gid = int(os.environ["QCSD_PINNED_CDP_EXPECTED_GID"])
        output = create_pinned_cdp_receipt(
            arguments.destination,
            build_execution_receipt=arguments.build_execution_receipt,
            cohort_version=arguments.cohort_version,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        result = validate_pinned_cdp_receipt(
            output,
            build_execution_receipt=arguments.build_execution_receipt,
            expected_cohort_version=arguments.cohort_version,
            runtime_role="prepare",
        )
    except (FileExistsError, KeyError, OSError, RuntimeError, ValueError) as error:
        print(f"pinned CDP probe failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
