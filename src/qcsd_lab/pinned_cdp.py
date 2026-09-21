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
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    NonReplayableEgressGuard,
    build_fail_closed_host_resolver_argument,
    install_context_egress_guards,
    launch_pinned_cdp_probe_browser,
    validate_browser_egress_command_line_projection,
    validate_fail_closed_host_resolver_argument,
    validate_non_replayable_egress_success_summary,
)
from .buflo_study import validate_build_execution_receipt
from .cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    NORMAL_SHUTDOWN_DISPOSAL_POLICY,
    NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION,
    SRCDOC_PSEUDO_DOCUMENT_POLICY,
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
    BrowserSharedWorkerGuard,
    RecursiveCdpTargetRouter,
    validate_bootstrap_prearm_summary,
    validate_egress_prearm_summary,
    validate_normal_shutdown_disposal_summary,
    validate_srcdoc_pseudo_document_summary,
)
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
    _abort_rejected_render,
    _dispose_failed_context,
    _finish_render_shutdown,
    _RequestExtraInfoAssociator,
    _RequestObservationLedger,
)
from .playwright_driver import (
    DEFAULT_CONFIGURED_EXECUTABLE,
    EXPECTED_BROWSERS_JSON_SHA256,
    EXPECTED_CHROMIUM_SHA256,
    EXPECTED_CHROMIUM_VERSION,
    EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
    LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
    LEGACY_OWNERSHIP_POLICY_RECEIPT,
    OWNERSHIP_POLICY_RECEIPT,
    PLAYWRIGHT_VERSION,
    PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
    PREVIOUS_OWNERSHIP_POLICY_RECEIPT,
    pinned_chromium_executable_path,
    playwright_driver_session,
    validate_default_playwright_driver_once,
)
from .playwright_driver import (
    DEFAULT_RECEIPT as PLAYWRIGHT_DRIVER_RECEIPT,
)
from .util import load_json, require_disjoint_path, sha256_file, source_metadata

_PINNED_CDP_APPROVED_ORIGINS = ("http://localhost", "http://b.test")
_PINNED_CDP_ORIGIN_IP_PINS = {
    "http://localhost": "127.0.0.1",
    "http://b.test": "127.0.0.1",
}
_PINNED_CDP_RESOLVER_PROJECTION = validate_fail_closed_host_resolver_argument(
    build_fail_closed_host_resolver_argument(
        approved_origins=_PINNED_CDP_APPROVED_ORIGINS,
        origin_ip_pins=_PINNED_CDP_ORIGIN_IP_PINS,
    )
)
# Probe schemas 8, 9, and 11 used ``a.test`` and ``b.test`` as their two
# loopback-pinned origins.  Keep the exact resulting projection immutable so a
# later live-topology change cannot silently reinterpret historical evidence.
_HISTORICAL_PINNED_CDP_RESOLVER_PROJECTION = {
    "schema_version": 1,
    "mode": "approved-map-or-exclude-then-not-found",
    "rule_count": 3,
    "mapped_host_count": 2,
    "excluded_host_count": 0,
    "catch_all_not_found": True,
    "canonical_rules_sha256": (
        "d4cb9b5a5ce3719322dedccb391ca058c130a47df7cf22fb1ec436993876e102"
    ),
}

RECEIPT_TYPE = "qcsd-class-study-pinned-cdp-probe"
PROBE_SCHEMA_VERSION = 18
HISTORICAL_PROBE_SCHEMA_VERSION = 8
HISTORICAL_PROBE_SCHEMA_VERSIONS = frozenset({8, 9, 11, 12, 13, 14, 16, 17})
EXPECTED_PLAYWRIGHT_VERSION = PLAYWRIGHT_VERSION
EXPECTED_CHROMIUM_EXECUTABLE = str(DEFAULT_CONFIGURED_EXECUTABLE)
PROBE_OBSERVATION_TIMEOUT_MS = 10_000
PROBE_QUIET_INTERVAL_MS = 250
TARGET_ACTIVITY_SCHEMA_VERSION = 1
WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION = 1
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


def _probe_contract(
    *,
    schema_version: int,
    policy: str,
    instrumentation_policy: str,
    playwright_driver_ownership_policy: Mapping[str, Any],
    playwright_driver_binding: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "policy": policy,
        "instrumentation_policy": instrumentation_policy,
        "playwright_version": EXPECTED_PLAYWRIGHT_VERSION,
        "chromium_executable": EXPECTED_CHROMIUM_EXECUTABLE,
        "chromium_version": EXPECTED_CHROMIUM_VERSION,
        "playwright_driver_ownership_policy": dict(playwright_driver_ownership_policy),
        "playwright_driver_binding": dict(playwright_driver_binding),
        "playwright_browsers_json_sha256": EXPECTED_BROWSERS_JSON_SHA256,
        "chromium_executable_sha256": EXPECTED_CHROMIUM_SHA256,
        "network_scope": "docker-network-none-loopback-only",
        "observation_timeout_ms": PROBE_OBSERVATION_TIMEOUT_MS,
        "required_quiet_interval_ms": PROBE_QUIET_INTERVAL_MS,
        "target_activity_schema_version": TARGET_ACTIVITY_SCHEMA_VERSION,
        "required_target_types": ["iframe", "shared_worker", "worker"],
        "required_observations": [
            "cross-site-iframe-network-request",
            "dedicated-and-shared-worker-network-requests",
            "dedicated-worker-fetch-paused-on-owning-page-session",
            "shared-worker-fetch-paused-on-guarded-shared-worker-session",
            "shared-worker-bootstrap-held-through-secondary-fetch-prearm",
            "target-lifecycle-activity-resets-quiescence",
            "duplicate-url-occurrences-remain-distinct",
            "all-deterministic-http-responses-finished-successfully",
            "router-ledger-extra-info-and-server-shutdown-complete",
            "all-runnable-targets-prearmed-against-non-urlloader-egress",
            "context-websocket-route-installed-before-first-page",
            "zero-service-worker-and-non-replayable-egress-attempts",
            "required-effective-chromium-egress-switches",
            "unprivileged-zero-capability-runtime",
        ],
        "non_replayable_egress_policy": NON_REPLAYABLE_EGRESS_POLICY,
        "packet_level_egress_completeness_claimed": False,
    }


_HISTORICAL_PROBE_CONTRACT = _probe_contract(
    schema_version=8,
    policy="pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v8",
    instrumentation_policy=(
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v10"
    ),
    playwright_driver_ownership_policy=LEGACY_OWNERSHIP_POLICY_RECEIPT,
    playwright_driver_binding=LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
)
_HISTORICAL_PROBE_CONTRACT_SHA256 = canonical_json_sha256(_HISTORICAL_PROBE_CONTRACT)

_HISTORICAL_PROBE_CONTRACT_V11: dict[str, Any] = _probe_contract(
    schema_version=10,
    policy="pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v10",
    instrumentation_policy=(
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v12"
    ),
    playwright_driver_ownership_policy=PREVIOUS_OWNERSHIP_POLICY_RECEIPT,
    playwright_driver_binding=PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
)
_HISTORICAL_PROBE_CONTRACT_V11["required_observations"].extend(
    [
        "paused-runnable-target-first-script-prearmed-before-execution",
        "dedicated-and-shared-worker-response-bodies-consumed",
        "document-only-playwright-route-with-recursive-cdp-subresource-ownership",
        "shared-worker-guardian-real-detach-ordered-before-final-proof",
    ]
)
_HISTORICAL_PROBE_CONTRACT_V11_SHA256 = canonical_json_sha256(_HISTORICAL_PROBE_CONTRACT_V11)


def _worker_webtransport_probe_contract(
    *,
    schema_version: int,
    policy: str,
    instrumentation_policy: str,
    playwright_driver_ownership_policy: Mapping[str, Any],
    playwright_driver_binding: Mapping[str, Any],
) -> dict[str, Any]:
    contract = _probe_contract(
        schema_version=schema_version,
        policy=policy,
        instrumentation_policy=instrumentation_policy,
        playwright_driver_ownership_policy=playwright_driver_ownership_policy,
        playwright_driver_binding=playwright_driver_binding,
    )
    contract["required_observations"].remove(
        "zero-service-worker-and-non-replayable-egress-attempts"
    )
    contract["required_observations"].extend(
        [
            "zero-unsanctioned-service-worker-and-non-replayable-egress-attempts",
            "paused-runnable-target-first-script-prearmed-before-execution",
            "dedicated-and-shared-worker-response-bodies-consumed",
            "document-only-playwright-route-with-recursive-cdp-subresource-ownership",
            "shared-worker-guardian-real-detach-ordered-before-final-proof",
            "potentially-trustworthy-loopback-worker-origin",
            "dedicated-and-shared-worker-webtransport-blocked-after-prearm-with-exact-telemetry",
        ]
    )
    contract["worker_webtransport_probe_schema_version"] = (
        WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION
    )
    return contract


# Probe schema 12 is immutable v83 evidence. It has the current resolver,
# driver, build identity, and worker-WebTransport observation, but predates the
# router's narrowly receipted Chromium error-document lifecycle exception.
_HISTORICAL_PROBE_CONTRACT_V12 = _worker_webtransport_probe_contract(
    schema_version=11,
    policy="pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v11",
    instrumentation_policy=(
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v13"
    ),
    playwright_driver_ownership_policy=PREVIOUS_OWNERSHIP_POLICY_RECEIPT,
    playwright_driver_binding=PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
)
_HISTORICAL_PROBE_CONTRACT_V12_SHA256 = canonical_json_sha256(
    _HISTORICAL_PROBE_CONTRACT_V12
)

# Outer schema 13 is immutable v95 evidence. It binds the error-document
# lifecycle router policy and corrected v8 driver, before the catalogue-only
# exact InvalidInterceptionId correlation was introduced.
_HISTORICAL_PROBE_CONTRACT_V13 = _worker_webtransport_probe_contract(
    schema_version=12,
    policy="pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v12",
    instrumentation_policy=(
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v15"
    ),
    playwright_driver_ownership_policy=OWNERSHIP_POLICY_RECEIPT,
    playwright_driver_binding=EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
)
_HISTORICAL_PROBE_CONTRACT_V13_SHA256 = canonical_json_sha256(
    _HISTORICAL_PROBE_CONTRACT_V13
)

# Outer schema 14 is immutable v96 evidence.  It binds the v16 router lifecycle
# but predates the exact root ``about:srcdoc`` loader-bound orphan-abort proof.
_HISTORICAL_PROBE_CONTRACT_V14 = _worker_webtransport_probe_contract(
    schema_version=13,
    policy="pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v13",
    instrumentation_policy=(
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v16"
    ),
    playwright_driver_ownership_policy=OWNERSHIP_POLICY_RECEIPT,
    playwright_driver_binding=EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
)
_HISTORICAL_PROBE_CONTRACT_V14_SHA256 = canonical_json_sha256(
    _HISTORICAL_PROBE_CONTRACT_V14
)

# Outer schema 16 is immutable v100/v101 evidence.  It binds the v19 router and
# one exact, identifier-minimised root ``about:srcdoc`` loader-bound orphan
# terminal lifecycle.  Failed, unpublished outer schema 15 is deliberately not
# a historical evidence format.
_HISTORICAL_PROBE_CONTRACT_V16: dict[str, Any] = _worker_webtransport_probe_contract(
    schema_version=15,
    policy="pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v15",
    instrumentation_policy=(
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v19"
    ),
    playwright_driver_ownership_policy=OWNERSHIP_POLICY_RECEIPT,
    playwright_driver_binding=EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
)
_HISTORICAL_PROBE_CONTRACT_V16["required_observations"].append(
    "root-about-srcdoc-loader-bound-orphan-abort-or-33-byte-finish-lifecycle"
)
_HISTORICAL_PROBE_CONTRACT_V16["srcdoc_pseudo_document_summary_schema_version"] = (
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION
)
_HISTORICAL_PROBE_CONTRACT_V16["srcdoc_pseudo_document_policy"] = (
    SRCDOC_PSEUDO_DOCUMENT_POLICY
)
_HISTORICAL_PROBE_CONTRACT_V16["required_srcdoc_pseudo_document_count"] = 1
_HISTORICAL_PROBE_CONTRACT_V16_SHA256 = canonical_json_sha256(
    _HISTORICAL_PROBE_CONTRACT_V16
)

# Outer schema 17 is immutable v102 evidence.  It binds the v20 router and the
# first exact normal-shutdown Network/Fetch reconciliation contract.
_HISTORICAL_PROBE_CONTRACT_V17: dict[str, Any] = _worker_webtransport_probe_contract(
    schema_version=16,
    policy="pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v16",
    instrumentation_policy=(
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v20"
    ),
    playwright_driver_ownership_policy=OWNERSHIP_POLICY_RECEIPT,
    playwright_driver_binding=EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
)
_HISTORICAL_PROBE_CONTRACT_V17["required_observations"].append(
    "root-about-srcdoc-loader-bound-orphan-abort-or-33-byte-finish-lifecycle"
)
_HISTORICAL_PROBE_CONTRACT_V17["required_observations"].append(
    "terminal-normal-shutdown-disposal-network-fetch-reconciliation"
)
_HISTORICAL_PROBE_CONTRACT_V17["srcdoc_pseudo_document_summary_schema_version"] = (
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION
)
_HISTORICAL_PROBE_CONTRACT_V17["srcdoc_pseudo_document_policy"] = (
    SRCDOC_PSEUDO_DOCUMENT_POLICY
)
_HISTORICAL_PROBE_CONTRACT_V17["required_srcdoc_pseudo_document_count"] = 1
_HISTORICAL_PROBE_CONTRACT_V17[
    "normal_shutdown_disposal_summary_schema_version"
] = 2
_HISTORICAL_PROBE_CONTRACT_V17["normal_shutdown_disposal_policy"] = (
    "chromium-143-post-quiescence-context-disposal-v1"
)
_HISTORICAL_PROBE_CONTRACT_V17_SHA256 = canonical_json_sha256(
    _HISTORICAL_PROBE_CONTRACT_V17
)

# Outer schema 18 binds the v21 router and its explicitly accounted singleton
# Fetch-only context-disposal Ping contract.
PROBE_CONTRACT: dict[str, Any] = _worker_webtransport_probe_contract(
    schema_version=17,
    policy="pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v17",
    instrumentation_policy=CDP_TARGET_INSTRUMENTATION_POLICY,
    playwright_driver_ownership_policy=OWNERSHIP_POLICY_RECEIPT,
    playwright_driver_binding=EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
)
PROBE_CONTRACT["required_observations"].append(
    "root-about-srcdoc-loader-bound-orphan-abort-or-33-byte-finish-lifecycle"
)
PROBE_CONTRACT["required_observations"].append(
    "terminal-normal-shutdown-disposal-network-fetch-or-singleton-ping-reconciliation"
)
PROBE_CONTRACT["srcdoc_pseudo_document_summary_schema_version"] = (
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION
)
PROBE_CONTRACT["srcdoc_pseudo_document_policy"] = SRCDOC_PSEUDO_DOCUMENT_POLICY
PROBE_CONTRACT["required_srcdoc_pseudo_document_count"] = 1
PROBE_CONTRACT["normal_shutdown_disposal_summary_schema_version"] = (
    NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION
)
PROBE_CONTRACT["normal_shutdown_disposal_policy"] = NORMAL_SHUTDOWN_DISPOSAL_POLICY
PROBE_CONTRACT_SHA256 = canonical_json_sha256(PROBE_CONTRACT)

_TARGET_ACTIVITY_EVENTS = (
    "target-attached",
    "target-info-changed",
    "target-detached",
    "target-destroyed",
)
_TARGET_ACTIVITY_TYPES = ("iframe", "page", "shared_worker", "worker")

_EXPECTED_HTTP_STATUS_COUNTS: dict[str, dict[str, int]] = {
    "/": {"200": 1},
    "/dedicated-data": {"200": 1},
    "/dedicated-worker.js": {"200": 1},
    "/duplicate": {"200": 2},
    "/frame": {"200": 1},
    "/frame-data": {"200": 1},
    "/redirect": {"302": 1},
    "/redirected": {"200": 1},
    "/shared-data": {"200": 1},
    "/shared-worker.js": {"200": 1},
}
_EXPECTED_SERVER_REQUEST_COUNTS = {
    path: sum(statuses.values()) for path, statuses in _EXPECTED_HTTP_STATUS_COUNTS.items()
}
_EXPECTED_WORKER_RESPONSE_CONSUMPTION = {
    "dedicated_worker": "qcsd-dedicated-response-consumed",
    "shared_worker": "qcsd-shared-response-consumed",
}
_EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT = {
    "resolved_type": "function",
    "own_descriptor": "data",
    "action_issued": True,
    "action_succeeded": False,
    "exception_name": "TypeError",
}
_WORKER_WEBTRANSPORT_TARGET_TYPES = ("shared_worker", "worker")
_EXPECTED_WORKER_WEBTRANSPORT_PROBE = {
    "schema_version": WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION,
    "by_target_type": {
        target_type: {
            "measurement": dict(_EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT),
            "guard_telemetry": {
                "notification_count": 1,
                "api": "WebTransport",
                "mechanism": "paused-target-runtime-shim",
                "url": None,
            },
        }
        for target_type in _WORKER_WEBTRANSPORT_TARGET_TYPES
    },
}
_WORKER_WEBTRANSPORT_ACTION_EXPRESSION = r"""
(() => {
  const api = 'WebTransport';
  let descriptor;
  let owner = globalThis;
  while (owner !== null && descriptor === undefined) {
    descriptor = Object.getOwnPropertyDescriptor(owner, api);
    owner = Object.getPrototypeOf(owner);
  }
  const resolvedType = typeof Reflect.get(globalThis, api);
  const ownDescriptor = descriptor === undefined
    ? 'absent'
    : ('value' in descriptor ? 'data' : 'accessor');
  let actionSucceeded = false;
  let exceptionName = null;
  try {
    new globalThis.WebTransport('https://unapproved.invalid/qcsd-pinned-cdp-worker');
    actionSucceeded = true;
  } catch (error) {
    exceptionName = error && typeof error.name === 'string' ? error.name : 'UnknownError';
  }
  return {
    resolved_type: resolvedType,
    own_descriptor: ownDescriptor,
    action_issued: true,
    action_succeeded: actionSucceeded,
    exception_name: exceptionName,
  };
})()
""".strip()
_EXPECTED_PINNED_BOOTSTRAP_PREARM_SUMMARY = {
    "schema_version": 1,
    "held_total": 1,
    "released_total": 1,
    "pending_total": 0,
    "release_before_setup_envelopes_total": 0,
    "by_worker_type": {
        "worker": {
            "held": 0,
            "released": 0,
            "pending": 0,
            "released_after_setup_envelopes": 0,
            "owner_target_types": {
                "page": 0,
                "iframe": 0,
                "worker": 0,
                "shared_worker": 0,
            },
        },
        "shared_worker": {
            "held": 1,
            "released": 1,
            "pending": 0,
            "released_after_setup_envelopes": 1,
            "owner_target_types": {
                "page": 1,
                "iframe": 0,
                "worker": 0,
                "shared_worker": 0,
            },
        },
    },
}
_EVENT_METHODS = (
    "Fetch.requestPaused",
    "Network.loadingFailed",
    "Network.loadingFinished",
    "Network.requestServedFromCache",
    "Network.requestWillBeSent",
    "Network.requestWillBeSentExtraInfo",
    "Network.responseReceived",
)


class _ProbeServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int]) -> None:
        super().__init__(server_address, _Handler)
        self.request_counts: Counter[str] = Counter()
        self.request_lock = threading.Lock()

    def record_request(self, path: str) -> None:
        with self.request_lock:
            self.request_counts[path] += 1

    def request_count_snapshot(self) -> dict[str, int]:
        with self.request_lock:
            return dict(sorted(self.request_counts.items()))


class _TargetActivityLedger:
    """Count target-only lifecycle work without retaining protocol identities."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._generation = 0
        self._event_counts = {target_type: Counter[str]() for target_type in _TARGET_ACTIVITY_TYPES}
        self._max_source_generation: dict[str, int | None] = {
            target_type: None for target_type in _TARGET_ACTIVITY_TYPES
        }

    def record(self, source: Any, event: str) -> None:
        target_type = getattr(source, "target_type", None)
        source_generation = getattr(source, "generation", None)
        if (
            target_type not in _TARGET_ACTIVITY_TYPES
            or event not in _TARGET_ACTIVITY_EVENTS
            or type(source_generation) is not int
            or source_generation < 0
        ):
            raise ValueError("pinned CDP target activity is malformed")
        with self._lock:
            self._generation += 1
            self._event_counts[target_type][event] += 1
            current = self._max_source_generation[target_type]
            if current is None or source_generation > current:
                self._max_source_generation[target_type] = source_generation

    @property
    def generation(self) -> int:
        """Return a monotonic generation that changes on target-only activity."""

        with self._lock:
            return self._generation

    def snapshot(self) -> dict[str, Any]:
        """Return the identity-free activity aggregate at this evidence boundary."""

        with self._lock:
            value = {
                "schema_version": TARGET_ACTIVITY_SCHEMA_VERSION,
                "generation": self._generation,
                "by_target_type": {
                    target_type: {
                        "total": sum(self._event_counts[target_type].values()),
                        "max_source_generation": self._max_source_generation[target_type],
                        "event_counts": {
                            event: self._event_counts[target_type][event]
                            for event in _TARGET_ACTIVITY_EVENTS
                        },
                    }
                    for target_type in _TARGET_ACTIVITY_TYPES
                },
            }
        return _validate_target_activity_summary(value)


class _WorkerWebTransportGuardCollector:
    """Consume only the two explicitly armed worker self-test notifications."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._armed = False
        self._telemetry: dict[str, dict[str, Any]] = {}

    def arm(self) -> None:
        with self._lock:
            if self._armed or self._telemetry:
                raise RuntimeError("pinned CDP worker WebTransport self-test was armed twice")
            self._armed = True

    def consume(
        self,
        *,
        source: object | None,
        api: object,
        mechanism: object,
        url: object | None,
    ) -> bool:
        """Return true only for one exact, armed notification per worker type."""

        target_type = getattr(source, "target_type", None)
        with self._lock:
            if (
                not self._armed
                or target_type not in _WORKER_WEBTRANSPORT_TARGET_TYPES
                or target_type in self._telemetry
                or api != "WebTransport"
                or mechanism != "paused-target-runtime-shim"
                or url is not None
            ):
                return False
            self._telemetry[target_type] = {
                "notification_count": 1,
                "api": api,
                "mechanism": mechanism,
                "url": url,
            }
            return True

    def receipt_if_complete(
        self,
        measurements: Mapping[str, object | None],
    ) -> dict[str, Any] | None:
        with self._lock:
            if (
                not self._armed
                or set(self._telemetry) != set(_WORKER_WEBTRANSPORT_TARGET_TYPES)
                or set(measurements) != set(_WORKER_WEBTRANSPORT_TARGET_TYPES)
                or any(measurements[target_type] is None for target_type in measurements)
            ):
                return None
            value = {
                "schema_version": WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION,
                "by_target_type": {
                    target_type: {
                        "measurement": measurements[target_type],
                        "guard_telemetry": dict(self._telemetry[target_type]),
                    }
                    for target_type in _WORKER_WEBTRANSPORT_TARGET_TYPES
                },
            }
        return _validate_worker_webtransport_probe(value)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        server = self.server
        if not isinstance(server, _ProbeServer):
            raise RuntimeError("pinned CDP probe server has an invalid type")
        server.record_request(path)
        if path == "/":
            body = b"""<link rel='icon' href='data:,'>
            <iframe srcdoc='<p>qcsd-root-srcdoc-lifecycle</p>'></iframe>
            <iframe src='http://b.test:PORT/frame'></iframe><script>
            window.qcsdWorkerResponses = {
                dedicated_worker: null,
                shared_worker: null,
            };
            window.qcsdWorkerWebTransportResults = {
                worker: null,
                shared_worker: null,
            };
            window.qcsdDedicatedWorker = new Worker('/dedicated-worker.js');
            window.qcsdDedicatedWorker.onmessage = event => {
                window.qcsdWorkerResponses.dedicated_worker = event.data.response_consumption;
                window.qcsdWorkerWebTransportResults.worker = event.data.measurement;
            };
            window.qcsdSharedWorker = new SharedWorker('/shared-worker.js');
            window.qcsdSharedWorker.port.onmessage = event => {
                window.qcsdWorkerResponses.shared_worker = event.data.response_consumption;
                window.qcsdWorkerWebTransportResults.shared_worker = event.data.measurement;
            };
            window.qcsdSharedWorker.port.start();
            fetch('/duplicate'); fetch('/duplicate'); fetch('/redirect');
            </script>""".replace(b"PORT", str(self.server.server_port).encode())
            kind = "text/html"
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.end_headers()
            return
        elif path == "/frame":
            body, kind = b"<script>fetch('/frame-data')</script>", "text/html"
        elif path == "/dedicated-worker.js":
            body = b"""const qcsdWebTransportMeasurement = __QCSD_WORKER_WEBTRANSPORT_ACTION__;
            (async () => {
                const response = await fetch('/dedicated-data');
                const value = await response.text();
                self.postMessage({
                    response_consumption: response.status === 200 && value === 'ok'
                        ? 'qcsd-dedicated-response-consumed'
                        : 'qcsd-dedicated-response-invalid',
                    measurement: qcsdWebTransportMeasurement,
                });
            })().catch(() => self.postMessage({
                response_consumption: 'qcsd-dedicated-response-error',
                measurement: qcsdWebTransportMeasurement,
            }));""".replace(
                b"__QCSD_WORKER_WEBTRANSPORT_ACTION__",
                _WORKER_WEBTRANSPORT_ACTION_EXPRESSION.encode(),
            )
            kind = "text/javascript"
        elif path == "/shared-worker.js":
            body = b"""const qcsdWebTransportMeasurement = __QCSD_WORKER_WEBTRANSPORT_ACTION__;
            self.onconnect = event => {
                const port = event.ports[0];
                port.start();
                (async () => {
                    const response = await fetch('/shared-data');
                    const value = await response.text();
                    port.postMessage({
                        response_consumption: response.status === 200 && value === 'ok'
                            ? 'qcsd-shared-response-consumed'
                            : 'qcsd-shared-response-invalid',
                        measurement: qcsdWebTransportMeasurement,
                    });
                })().catch(() => port.postMessage({
                    response_consumption: 'qcsd-shared-response-error',
                    measurement: qcsdWebTransportMeasurement,
                }));
            };""".replace(
                b"__QCSD_WORKER_WEBTRANSPORT_ACTION__",
                _WORKER_WEBTRANSPORT_ACTION_EXPRESSION.encode(),
            )
            kind = "text/javascript"
        elif path in {
            "/dedicated-data",
            "/duplicate",
            "/frame-data",
            "/redirected",
            "/shared-data",
        }:
            body, kind = b"ok", "text/plain"
        else:
            self.send_error(404)
            return
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
    driver_receipt = validate_default_playwright_driver_once()
    playwright_version = importlib.metadata.version("playwright")
    if playwright_version != EXPECTED_PLAYWRIGHT_VERSION:
        raise ValueError("pinned CDP probe Playwright version differs from the contract")
    executable = pinned_chromium_executable_path()
    if executable != EXPECTED_CHROMIUM_EXECUTABLE:
        raise ValueError("pinned CDP probe Chromium executable differs from the contract")
    executable_path = Path(executable)
    if not executable_path.exists() or not os.access(executable_path, os.X_OK):
        raise ValueError("pinned CDP probe Chromium executable is unavailable")

    from playwright.sync_api import sync_playwright

    server = _ProbeServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    observed_events: list[tuple[str, str, str]] = []
    target_activity = _TargetActivityLedger()
    http_status_counts: dict[str, Counter[str]] = {}
    bootstrap_prearm_summary: dict[str, Any] | None = None
    egress_prearm_summary: dict[str, Any] | None = None
    srcdoc_pseudo_document_summary: dict[str, Any] | None = None
    normal_shutdown_disposal_summary: dict[str, Any] | None = None
    non_replayable_egress_summary: dict[str, Any] | None = None
    browser_egress_command_line: dict[str, object] | None = None
    browser_context_service_worker_count: int | None = None
    quiescent_target_activity: dict[str, Any] | None = None
    worker_response_consumption: dict[str, str | None] | None = None
    worker_webtransport_probe: dict[str, Any] | None = None
    chromium_version = ""
    router_closed = False
    browser_guard_closed = False
    ledger_closed = False
    extra_info_closed = False
    browser_closed = False
    egress_guard: NonReplayableEgressGuard | None = None
    router: RecursiveCdpTargetRouter | None = None
    worker_webtransport_collector = _WorkerWebTransportGuardCollector()
    thread_started = False
    server_primary: BaseException | None = None
    try:
        thread.start()
        thread_started = True
        with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
            browser, browser_egress_command_line = launch_pinned_cdp_probe_browser(
                playwright,
                approved_origins=_PINNED_CDP_APPROVED_ORIGINS,
                origin_ip_pins=_PINNED_CDP_ORIGIN_IP_PINS,
            )
            context: Any | None = None
            browser_guard: BrowserSharedWorkerGuard | None = None
            normal_shutdown_started = False
            normal_shutdown_cleanup_started = False
            primary_error: BaseException | None = None
            try:
                chromium_version = browser.version
                context = browser.new_context(service_workers="block")
                egress_guard = NonReplayableEgressGuard()
                install_context_egress_guards(context, egress_guard)
                page = context.new_page()
                egress_guard.bind_root_page(page)
                page.set_default_timeout(PROBE_OBSERVATION_TIMEOUT_MS)
                page.set_default_navigation_timeout(PROBE_OBSERVATION_TIMEOUT_MS)
                session = context.new_cdp_session(page)
                browser_session = browser.new_browser_cdp_session()
                ledger = _RequestObservationLedger(
                    eligible=lambda method, url: method == "GET" and url.startswith("http://")
                )
                extra_info = _RequestExtraInfoAssociator()

                def event(source: Any, method: str, payload: Mapping[str, Any]) -> None:
                    request = payload.get("request", {})
                    url = str(request.get("url", "")) if isinstance(request, Mapping) else ""
                    observed_events.append((source.target_type, method, url))
                    if method == "Network.requestWillBeSent":
                        redirect_response = payload.get("redirectResponse")
                        redirected = redirect_response is not None
                        if isinstance(redirect_response, Mapping):
                            _record_http_status(http_status_counts, redirect_response)
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
                        response = payload.get("response")
                        if isinstance(response, Mapping):
                            _record_http_status(http_status_counts, response)
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

                def non_replayable_egress(
                    source: object | None,
                    api: object,
                    mechanism: object,
                    url: object | None,
                ) -> None:
                    if worker_webtransport_collector.consume(
                        source=source,
                        api=api,
                        mechanism=mechanism,
                        url=url,
                    ):
                        return
                    egress_guard.record(
                        source=source,
                        api=api,
                        mechanism=mechanism,
                        url=url,
                    )

                router = RecursiveCdpTargetRouter(
                    session,
                    on_event=event,
                    track_root_srcdoc_lifecycle=True,
                    on_target_activity=target_activity.record,
                    on_non_replayable_egress=non_replayable_egress,
                )
                router.start()
                browser_guard = BrowserSharedWorkerGuard(browser_session, router)
                browser_guard.start()
                worker_webtransport_collector.arm()
                load_seen = [False]
                page.on("load", lambda: load_seen.__setitem__(0, True))
                deadline = time.monotonic() + PROBE_OBSERVATION_TIMEOUT_MS / 1_000
                page.goto(
                    f"http://localhost:{server.server_port}/",
                    wait_until="commit",
                    timeout=max(1, round((deadline - time.monotonic()) * 1_000)),
                )
                _wait_for_page_load(
                    page,
                    router,
                    load_seen,
                    egress_guard,
                    deadline=deadline,
                )
                (
                    convergence_generation,
                    worker_response_consumption,
                    worker_webtransport_probe,
                ) = _wait_for_required_observations(
                    page,
                    router,
                    observed_events,
                    target_activity,
                    egress_guard,
                    worker_webtransport_collector,
                    deadline=deadline,
                )
                egress_guard.raise_if_failed()
                browser_context_service_worker_count = len(context.service_workers)
                if browser_context_service_worker_count:
                    raise RuntimeError("pinned CDP probe observed a browser service worker")
                router.begin_shutdown()
                normal_shutdown_started = True
                quiescent_target_activity = target_activity.snapshot()
                if (
                    quiescent_target_activity["generation"] != convergence_generation
                    or target_activity.generation != convergence_generation
                ):
                    raise RuntimeError("pinned CDP target activity changed after quiescence")
                bootstrap_prearm_summary = router.bootstrap_prearm_summary
                egress_prearm_summary = router.egress_prearm_summary
                srcdoc_pseudo_document_summary = _validate_required_srcdoc_summary(
                    router.srcdoc_pseudo_document_summary
                )
                non_replayable_egress_summary = egress_guard.success_summary()
                normal_shutdown_cleanup_started = True
                if _finish_render_shutdown(
                    context,
                    router,
                    browser_guard,
                    cleanup_label="pinned-CDP probe",
                ):
                    browser_guard_closed = True
                    router_closed = True
                normal_shutdown_disposal_summary = (
                    validate_normal_shutdown_disposal_summary(
                        router.normal_shutdown_disposal_summary,
                        require_terminal=True,
                    )
                )
                ledger.finish()
                ledger_closed = True
                extra_info.finish()
                extra_info_closed = True
            except BaseException as error:
                primary_error = error
                if not normal_shutdown_started:
                    if context is not None and router is not None and browser_guard is not None:
                        _abort_rejected_render(
                            context,
                            router,
                            browser_guard,
                            error,
                            cleanup_label="pinned-CDP probe",
                        )
                    elif context is not None:
                        _dispose_failed_context(
                            context,
                            error,
                            cleanup_label="pinned-CDP probe",
                        )
                elif (
                    not normal_shutdown_cleanup_started
                    and context is not None
                    and router is not None
                    and browser_guard is not None
                ):
                    _finish_render_shutdown(
                        context,
                        router,
                        browser_guard,
                        cleanup_label="pinned-CDP probe",
                        primary=error,
                    )
                raise
            finally:
                try:
                    browser.close()
                    browser_closed = True
                except BaseException as error:
                    if primary_error is None:
                        raise
                    primary_error.add_note(
                        f"pinned-CDP probe cleanup browser-close failed with {type(error).__name__}"
                    )
                finally:
                    if egress_guard is not None:
                        egress_guard.raise_if_failed()
                    if router is not None:
                        router.raise_if_failed()
            non_replayable_egress_summary = egress_guard.success_summary()
    except BaseException as error:
        server_primary = error
        raise
    finally:
        server_cleanup_errors: list[tuple[str, BaseException]] = []
        thread_alive = False
        if thread_started:
            try:
                thread_alive = thread.is_alive()
            except BaseException as error:  # noqa: BLE001 - preserve the probe primary
                server_cleanup_errors.append(("server-thread-state", error))
        if thread_alive:
            try:
                server.shutdown()
            except BaseException as error:  # noqa: BLE001 - preserve the probe primary
                server_cleanup_errors.append(("server-shutdown", error))
        try:
            server.server_close()
        except BaseException as error:  # noqa: BLE001 - preserve the probe primary
            server_cleanup_errors.append(("server-close", error))
        if thread_started:
            try:
                thread.join(timeout=2)
            except BaseException as error:  # noqa: BLE001 - preserve the probe primary
                server_cleanup_errors.append(("server-thread-join", error))
        if server_cleanup_errors:
            if server_primary is None:
                _step, cleanup_primary = server_cleanup_errors.pop(0)
                for step, error in server_cleanup_errors:
                    cleanup_primary.add_note(
                        "pinned-CDP probe cleanup "
                        f"{step} failed with {type(error).__name__}"
                    )
                raise cleanup_primary
            for step, error in server_cleanup_errors:
                server_primary.add_note(
                    f"pinned-CDP probe cleanup {step} failed with {type(error).__name__}"
                )

    topology = {
        **_event_topology(observed_events),
        "http_status_counts": {
            path: dict(sorted(counts.items()))
            for path, counts in sorted(http_status_counts.items())
        },
        "server_request_counts": server.request_count_snapshot(),
        "bootstrap_prearm_summary": bootstrap_prearm_summary,
        "egress_prearm_summary": egress_prearm_summary,
        "srcdoc_pseudo_document_summary": srcdoc_pseudo_document_summary,
        "normal_shutdown_disposal_summary": normal_shutdown_disposal_summary,
        "non_replayable_egress_summary": non_replayable_egress_summary,
        "browser_egress_command_line": browser_egress_command_line,
        "browser_context_service_worker_count": browser_context_service_worker_count,
        "worker_response_consumption": worker_response_consumption,
        "worker_webtransport_probe": worker_webtransport_probe,
        "quiescent_target_activity": quiescent_target_activity,
        "router_closed": router_closed,
        "browser_guard_closed": browser_guard_closed,
        "ledger_closed": ledger_closed,
        "extra_info_closed": extra_info_closed,
        "browser_closed": browser_closed,
        "server_thread_stopped": not thread.is_alive(),
    }
    observation = {
        "playwright_version": playwright_version,
        "chromium_version": chromium_version,
        "chromium_executable": executable,
        "playwright_driver": _driver_binding(driver_receipt),
        "isolation": isolation,
        "topology": topology,
    }
    return _validate_observation(observation)


def _record_http_status(
    status_counts: dict[str, Counter[str]],
    response: Mapping[str, Any],
) -> None:
    """Record only deterministic loopback response path/status aggregates."""

    url = response.get("url")
    status = response.get("status")
    if not isinstance(url, str) or not url.startswith("http://"):
        return
    if type(status) not in {int, float} or int(status) != status:
        raise ValueError("pinned CDP probe response status is malformed")
    path = urlsplit(url).path
    status_counts.setdefault(path, Counter())[str(int(status))] += 1


def _driver_binding(receipt: Mapping[str, Any]) -> dict[str, Any]:
    browser_manifest = receipt.get("browser_manifest")
    executable = receipt.get("chromium_executable")
    if not isinstance(browser_manifest, Mapping) or not isinstance(executable, Mapping):
        raise ValueError("Playwright ownership receipt omitted its browser binding")
    binding = {
        "receipt_sha256": sha256_file(PLAYWRIGHT_DRIVER_RECEIPT),
        "payload_sha256": receipt.get("payload_sha256"),
        "content_sha256": receipt.get("content_sha256"),
        "policy": receipt.get("policy"),
        "browsers_json_sha256": browser_manifest.get("sha256"),
        "chromium_executable_sha256": executable.get("sha256"),
    }
    if binding != EXPECTED_PLAYWRIGHT_DRIVER_BINDING:
        raise ValueError("Playwright ownership receipt differs from the pinned default binding")
    return json.loads(canonical_json_bytes(binding))


def _wait_for_page_load(
    page: Any,
    router: RecursiveCdpTargetRouter,
    load_seen: Sequence[bool],
    egress_guard: NonReplayableEgressGuard,
    *,
    deadline: float,
) -> None:
    """Pump Playwright while surfacing instrumentation failure before timeout."""

    while time.monotonic() < deadline:
        egress_guard.raise_if_failed()
        router.raise_if_failed()
        if load_seen[0]:
            if time.monotonic() >= deadline:
                break
            return
        remaining_ms = max(1, round((deadline - time.monotonic()) * 1_000))
        page.wait_for_timeout(min(25, remaining_ms))
    egress_guard.raise_if_failed()
    router.raise_if_failed()
    raise RuntimeError("pinned CDP probe page did not reach its real load event")


def _event_topology(events: Sequence[tuple[str, str, str]]) -> dict[str, Any]:
    method_counts = Counter(method for _target_type, method, _url in events)
    return {
        "observed_target_types": sorted({target_type for target_type, _method, _url in events}),
        "event_count": len(events),
        "event_method_counts": {method: method_counts[method] for method in _EVENT_METHODS},
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
        "redirect_target_request": any(
            method == "Network.requestWillBeSent" and url.endswith("/redirected")
            for _target_type, method, url in events
        ),
        "worker_network_target_types": sorted(
            {
                target_type
                for target_type, method, url in events
                if method == "Network.requestWillBeSent"
                and url.endswith(("/dedicated-data", "/shared-data"))
            }
        ),
        "dedicated_worker_network_request": any(
            target_type == "worker"
            and method == "Network.requestWillBeSent"
            and url.endswith("/dedicated-data")
            for target_type, method, url in events
        ),
        "shared_worker_network_request": any(
            target_type == "shared_worker"
            and method == "Network.requestWillBeSent"
            and url.endswith("/shared-data")
            for target_type, method, url in events
        ),
        "dedicated_worker_fetch_paused_on_page": any(
            target_type == "page"
            and method == "Fetch.requestPaused"
            and url.endswith("/dedicated-data")
            for target_type, method, url in events
        ),
        "shared_worker_fetch_paused_on_shared_worker": any(
            target_type == "shared_worker"
            and method == "Fetch.requestPaused"
            and url.endswith("/shared-data")
            for target_type, method, url in events
        ),
    }


def _required_event_topology_observed(events: Sequence[tuple[str, str, str]]) -> bool:
    topology = _event_topology(events)
    return (
        topology["observed_target_types"] == ["iframe", "page", "shared_worker", "worker"]
        and topology["cross_site_iframe_request"] is True
        and topology["duplicate_request_occurrences"] == 2
        and topology["redirect_target_request"] is True
        and topology["worker_network_target_types"] == ["shared_worker", "worker"]
        and topology["dedicated_worker_network_request"] is True
        and topology["shared_worker_network_request"] is True
        and topology["dedicated_worker_fetch_paused_on_page"] is True
        and topology["shared_worker_fetch_paused_on_shared_worker"] is True
    )


def _wait_for_required_observations(
    page: Any,
    router: RecursiveCdpTargetRouter,
    events: Sequence[tuple[str, str, str]],
    target_activity: _TargetActivityLedger,
    egress_guard: NonReplayableEgressGuard,
    worker_webtransport_collector: _WorkerWebTransportGuardCollector,
    *,
    deadline: float,
) -> tuple[int, dict[str, str | None], dict[str, Any]]:
    """Wait for required topology and a quiet, request-free convergence interval."""

    quiet_since: float | None = None
    previous_count = -1
    previous_target_generation = -1
    while time.monotonic() < deadline:
        egress_guard.raise_if_failed()
        remaining_ms = max(1, round((deadline - time.monotonic()) * 1_000))
        page.wait_for_timeout(min(25, remaining_ms))
        egress_guard.raise_if_failed()
        router.raise_if_failed()
        now = time.monotonic()
        event_count = len(events)
        target_generation = target_activity.generation
        if event_count != previous_count or target_generation != previous_target_generation:
            previous_count = event_count
            previous_target_generation = target_generation
            quiet_since = None
        elif (
            _required_event_topology_observed(events)
            and not router.active_request_identities
            and router.shutdown_ready
        ):
            worker_responses = _worker_response_consumption(page)
            if worker_responses == _EXPECTED_WORKER_RESPONSE_CONSUMPTION:
                worker_measurements = _worker_webtransport_measurements(page)
                worker_probe = worker_webtransport_collector.receipt_if_complete(
                    worker_measurements
                )
                if worker_probe is None:
                    quiet_since = None
                elif quiet_since is None:
                    quiet_since = now
                elif (now - quiet_since) * 1_000 >= PROBE_QUIET_INTERVAL_MS:
                    if now >= deadline:
                        break
                    return target_generation, worker_responses, worker_probe
            else:
                quiet_since = None
        else:
            quiet_since = None
    egress_guard.raise_if_failed()
    router.raise_if_failed()
    raise RuntimeError("pinned CDP probe did not converge on its required topology")


def _worker_response_consumption(page: Any) -> dict[str, str | None]:
    """Read the exact body-consumption acknowledgements from both probe workers."""

    value = page.evaluate("() => window.qcsdWorkerResponses")
    if not isinstance(value, Mapping) or set(value) != set(_EXPECTED_WORKER_RESPONSE_CONSUMPTION):
        raise RuntimeError("pinned CDP worker-response state is malformed")
    result: dict[str, str | None] = {}
    for worker_type, expected in _EXPECTED_WORKER_RESPONSE_CONSUMPTION.items():
        observed = value.get(worker_type)
        if observed is not None and observed != expected:
            raise RuntimeError("pinned CDP worker failed to consume its exact response")
        result[worker_type] = observed
    return result


def _worker_webtransport_measurements(page: Any) -> dict[str, object | None]:
    """Read and validate both workers' raw WebTransport constructor outcomes."""

    value = page.evaluate("() => window.qcsdWorkerWebTransportResults")
    if not isinstance(value, Mapping) or set(value) != set(_WORKER_WEBTRANSPORT_TARGET_TYPES):
        raise RuntimeError("pinned CDP worker WebTransport state is malformed")
    result: dict[str, object | None] = {}
    for target_type in _WORKER_WEBTRANSPORT_TARGET_TYPES:
        observed = value.get(target_type)
        if observed is not None and observed != _EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT:
            raise RuntimeError("pinned CDP worker WebTransport action was not blocked exactly")
        result[target_type] = observed
    return result


def _validate_worker_webtransport_probe(value: object) -> dict[str, Any]:
    """Validate exact action and guard telemetry from both worker target types."""

    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema_version", "by_target_type"}
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != WORKER_WEBTRANSPORT_PROBE_SCHEMA_VERSION
    ):
        raise ValueError("pinned CDP worker WebTransport probe fields are invalid")
    by_target_type = value.get("by_target_type")
    if not isinstance(by_target_type, Mapping) or set(by_target_type) != set(
        _WORKER_WEBTRANSPORT_TARGET_TYPES
    ):
        raise ValueError("pinned CDP worker WebTransport target inventory is invalid")
    for target_type in _WORKER_WEBTRANSPORT_TARGET_TYPES:
        item = by_target_type.get(target_type)
        if not isinstance(item, Mapping) or set(item) != {"measurement", "guard_telemetry"}:
            raise ValueError("pinned CDP worker WebTransport target fields are invalid")
        measurement = item.get("measurement")
        guard = item.get("guard_telemetry")
        if (
            not isinstance(measurement, Mapping)
            or set(measurement) != set(_EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT)
            or type(measurement.get("action_issued")) is not bool
            or type(measurement.get("action_succeeded")) is not bool
            or dict(measurement) != _EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT
            or not isinstance(guard, Mapping)
            or set(guard) != {"notification_count", "api", "mechanism", "url"}
            or type(guard.get("notification_count")) is not int
            or dict(guard)
            != _EXPECTED_WORKER_WEBTRANSPORT_PROBE["by_target_type"][target_type]["guard_telemetry"]
        ):
            raise ValueError("pinned CDP worker WebTransport action or telemetry did not pass")
    return json.loads(canonical_json_bytes(value))


def _validate_target_activity_summary(value: object) -> dict[str, Any]:
    """Validate the minimised lifecycle aggregate used by the quiet gate."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "generation",
        "by_target_type",
    }:
        raise ValueError("pinned CDP target-activity fields are invalid")
    generation = value.get("generation")
    by_target_type = value.get("by_target_type")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != TARGET_ACTIVITY_SCHEMA_VERSION
        or type(generation) is not int
        or generation < 0
        or not isinstance(by_target_type, Mapping)
        or set(by_target_type) != set(_TARGET_ACTIVITY_TYPES)
    ):
        raise ValueError("pinned CDP target-activity aggregate is invalid")
    observed_total = 0
    for target_type in _TARGET_ACTIVITY_TYPES:
        entry = by_target_type[target_type]
        if not isinstance(entry, Mapping) or set(entry) != {
            "total",
            "max_source_generation",
            "event_counts",
        }:
            raise ValueError("pinned CDP target-activity entry is invalid")
        total = entry.get("total")
        maximum = entry.get("max_source_generation")
        event_counts = entry.get("event_counts")
        if (
            type(total) is not int
            or total < 0
            or not isinstance(event_counts, Mapping)
            or set(event_counts) != set(_TARGET_ACTIVITY_EVENTS)
            or any(
                type(event_counts.get(event)) is not int or event_counts[event] < 0
                for event in _TARGET_ACTIVITY_EVENTS
            )
            or sum(event_counts.values()) != total
            or (total == 0 and maximum is not None)
            or (total > 0 and (type(maximum) is not int or maximum < 0))
        ):
            raise ValueError("pinned CDP target-activity aggregate is invalid")
        observed_total += total
    if observed_total != generation:
        raise ValueError("pinned CDP target-activity generation is inconsistent")
    return json.loads(canonical_json_bytes(value))


def _validate_required_srcdoc_summary(value: object) -> dict[str, Any]:
    """Require one exact identifier-minimised loader-bound lifecycle."""

    summary = validate_srcdoc_pseudo_document_summary(value, require_terminal=True)
    if (
        summary["enabled"] is not True
        or summary["total"] != 1
        or summary["resolved"] != 1
        or summary["pending"] != 0
        or summary["aborted"] != 0
        or summary["open_candidates"] != 0
        or summary["network_history_saturated"] is not False
        or summary["fetch_history_saturated"] is not False
        or summary["candidate_limit_saturated"] is not False
        or len(summary["diagnostics"]) != 1
    ):
        raise ValueError("pinned CDP srcdoc loader-bound topology evidence did not pass")
    return summary


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
    if type(expected_uid) is not int or expected_uid < 1:
        raise ValueError("pinned CDP probe expected UID is invalid")
    if type(expected_gid) is not int or expected_gid < 1:
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
        allow_historical=False,
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
        "build_execution_identity": _current_build_identity(build),
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
        allow_historical=False,
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
    allow_historical: bool = False,
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
        allow_historical=allow_historical,
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
    allow_historical: bool,
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
    probe_schema_version = payload.get("probe_schema_version")
    historical_probe = (
        type(probe_schema_version) is int
        and probe_schema_version in HISTORICAL_PROBE_SCHEMA_VERSIONS
    )
    if (
        type(probe_schema_version) is not int
        or probe_schema_version not in {*HISTORICAL_PROBE_SCHEMA_VERSIONS, PROBE_SCHEMA_VERSION}
        or (historical_probe and not allow_historical)
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
        allow_historical=(
            allow_historical and probe_schema_version == HISTORICAL_PROBE_SCHEMA_VERSION
        ),
    )
    build_value = load_json(Path(build["path"]))
    expected_binding = {
        "path": _canonical_build_receipt_path(cohort_version),
        "sha256": build["sha256"],
        "payload_sha256": build_value["payload_sha256"],
    }
    identity = (
        _legacy_build_identity(build)
        if probe_schema_version == HISTORICAL_PROBE_SCHEMA_VERSION
        else _current_build_identity(build)
    )
    if probe_schema_version in {8, 9}:
        expected_contract = _HISTORICAL_PROBE_CONTRACT
        expected_contract_sha256 = _HISTORICAL_PROBE_CONTRACT_SHA256
    elif probe_schema_version == 11:
        expected_contract = _HISTORICAL_PROBE_CONTRACT_V11
        expected_contract_sha256 = _HISTORICAL_PROBE_CONTRACT_V11_SHA256
    elif probe_schema_version == 12:
        expected_contract = _HISTORICAL_PROBE_CONTRACT_V12
        expected_contract_sha256 = _HISTORICAL_PROBE_CONTRACT_V12_SHA256
    elif probe_schema_version == 13:
        expected_contract = _HISTORICAL_PROBE_CONTRACT_V13
        expected_contract_sha256 = _HISTORICAL_PROBE_CONTRACT_V13_SHA256
    elif probe_schema_version == 14:
        expected_contract = _HISTORICAL_PROBE_CONTRACT_V14
        expected_contract_sha256 = _HISTORICAL_PROBE_CONTRACT_V14_SHA256
    elif probe_schema_version == 16:
        expected_contract = _HISTORICAL_PROBE_CONTRACT_V16
        expected_contract_sha256 = _HISTORICAL_PROBE_CONTRACT_V16_SHA256
    elif probe_schema_version == 17:
        expected_contract = _HISTORICAL_PROBE_CONTRACT_V17
        expected_contract_sha256 = _HISTORICAL_PROBE_CONTRACT_V17_SHA256
    else:
        expected_contract = PROBE_CONTRACT
        expected_contract_sha256 = PROBE_CONTRACT_SHA256
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
        or payload.get("probe_contract") != expected_contract
        or payload.get("probe_contract_sha256") != expected_contract_sha256
    ):
        raise ValueError("pinned CDP probe differs from its source/build/prepare image")
    if recorded_at < _timestamp(build["finished_at"], label="no-cache build finish"):
        raise ValueError("pinned CDP probe predates its no-cache build")
    observation = _validate_observation(
        payload.get("observation"),
        require_worker_response_consumption=probe_schema_version not in {8, 9},
        require_worker_webtransport_probe=probe_schema_version
        in {12, 13, 14, 16, 17, PROBE_SCHEMA_VERSION},
        require_srcdoc_pseudo_document_summary=(
            probe_schema_version in {16, 17, PROBE_SCHEMA_VERSION}
        ),
        require_normal_shutdown_disposal_summary=(
            probe_schema_version in {17, PROBE_SCHEMA_VERSION}
        ),
        allow_historical_normal_shutdown_disposal_summary=(
            probe_schema_version == 17
        ),
        expected_resolver_projection=(
            _HISTORICAL_PINNED_CDP_RESOLVER_PROJECTION
            if probe_schema_version in {8, 9, 11}
            else _PINNED_CDP_RESOLVER_PROJECTION
        ),
        expected_playwright_driver_binding=(
            LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
            if probe_schema_version in {8, 9}
            else (
                PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
                if probe_schema_version in {11, 12}
                else EXPECTED_PLAYWRIGHT_DRIVER_BINDING
            )
        ),
    )
    if runtime_role is not None:
        if runtime_role not in {"collection", "prepare"}:
            raise ValueError("pinned CDP probe runtime role is invalid")
        expected_source = prepare_source if runtime_role == "prepare" else collection_source
        if source_metadata() != expected_source:
            raise ValueError("pinned CDP probe validation runtime differs from its build")
        if runtime_role == "prepare" and observation.get("playwright_driver") != _driver_binding(
            validate_default_playwright_driver_once()
        ):
            raise ValueError("pinned CDP probe Playwright driver differs from the prepare runtime")
    return json.loads(canonical_json_bytes(payload))


def _validate_observation(
    value: object,
    *,
    require_worker_response_consumption: bool = True,
    require_worker_webtransport_probe: bool = True,
    require_srcdoc_pseudo_document_summary: bool = True,
    require_normal_shutdown_disposal_summary: bool = True,
    allow_historical_normal_shutdown_disposal_summary: bool = False,
    expected_playwright_driver_binding: Mapping[str, Any] = (EXPECTED_PLAYWRIGHT_DRIVER_BINDING),
    expected_resolver_projection: Mapping[str, Any] = (_PINNED_CDP_RESOLVER_PROJECTION),
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "playwright_version",
        "chromium_version",
        "chromium_executable",
        "playwright_driver",
        "isolation",
        "topology",
    }:
        raise ValueError("pinned CDP probe observation fields are invalid")
    isolation = value.get("isolation")
    topology = value.get("topology")
    driver = value.get("playwright_driver")
    if (
        value.get("playwright_version") != EXPECTED_PLAYWRIGHT_VERSION
        or value.get("chromium_version") != EXPECTED_CHROMIUM_VERSION
        or value.get("chromium_executable") != EXPECTED_CHROMIUM_EXECUTABLE
    ):
        raise ValueError("pinned CDP probe browser evidence is invalid")
    if driver != expected_playwright_driver_binding:
        raise ValueError("pinned CDP probe Playwright driver evidence is invalid")
    _validate_isolation(isolation)
    expected_topology_fields = {
        "observed_target_types",
        "event_count",
        "event_method_counts",
        "cross_site_iframe_request",
        "duplicate_request_occurrences",
        "redirect_target_request",
        "worker_network_target_types",
        "dedicated_worker_network_request",
        "shared_worker_network_request",
        "dedicated_worker_fetch_paused_on_page",
        "shared_worker_fetch_paused_on_shared_worker",
        "http_status_counts",
        "server_request_counts",
        "bootstrap_prearm_summary",
        "egress_prearm_summary",
        "non_replayable_egress_summary",
        "browser_egress_command_line",
        "browser_context_service_worker_count",
        "quiescent_target_activity",
        "router_closed",
        "browser_guard_closed",
        "ledger_closed",
        "extra_info_closed",
        "browser_closed",
        "server_thread_stopped",
    }
    if require_worker_response_consumption:
        expected_topology_fields.add("worker_response_consumption")
    if require_worker_webtransport_probe:
        expected_topology_fields.add("worker_webtransport_probe")
    if require_srcdoc_pseudo_document_summary:
        expected_topology_fields.add("srcdoc_pseudo_document_summary")
    if require_normal_shutdown_disposal_summary:
        expected_topology_fields.add("normal_shutdown_disposal_summary")
    if not isinstance(topology, Mapping) or set(topology) != expected_topology_fields:
        raise ValueError("pinned CDP probe topology fields are invalid")
    target_types = topology.get("observed_target_types")
    expected_types = ["iframe", "page", "shared_worker", "worker"]
    boolean_fields = (
        "cross_site_iframe_request",
        "redirect_target_request",
        "dedicated_worker_network_request",
        "shared_worker_network_request",
        "dedicated_worker_fetch_paused_on_page",
        "shared_worker_fetch_paused_on_shared_worker",
        "router_closed",
        "browser_guard_closed",
        "ledger_closed",
        "extra_info_closed",
        "browser_closed",
        "server_thread_stopped",
    )
    method_counts = topology.get("event_method_counts")
    if (
        not isinstance(method_counts, Mapping)
        or set(method_counts) != set(_EVENT_METHODS)
        or any(
            type(method_counts.get(method)) is not int or method_counts[method] < 0
            for method in _EVENT_METHODS
        )
        or sum(method_counts.values()) != topology.get("event_count")
        or method_counts["Network.loadingFailed"] != 0
        or method_counts["Network.requestServedFromCache"] != 0
    ):
        raise ValueError("pinned CDP probe event-method aggregate is invalid")
    prearm = validate_bootstrap_prearm_summary(
        topology.get("bootstrap_prearm_summary"),
        require_terminal=True,
    )
    egress_prearm = validate_egress_prearm_summary(
        topology.get("egress_prearm_summary"),
        require_terminal=True,
    )
    validate_non_replayable_egress_success_summary(topology.get("non_replayable_egress_summary"))
    browser_egress_projection = validate_browser_egress_command_line_projection(
        topology.get("browser_egress_command_line")
    )
    if browser_egress_projection.get("host_resolver_policy") != expected_resolver_projection:
        raise ValueError("pinned CDP probe host-resolver policy is invalid")
    target_activity = _validate_target_activity_summary(topology.get("quiescent_target_activity"))
    if require_worker_webtransport_probe:
        _validate_worker_webtransport_probe(topology.get("worker_webtransport_probe"))
    if require_srcdoc_pseudo_document_summary:
        _validate_required_srcdoc_summary(topology.get("srcdoc_pseudo_document_summary"))
    if require_normal_shutdown_disposal_summary:
        shutdown_summary = topology.get("normal_shutdown_disposal_summary")
        if allow_historical_normal_shutdown_disposal_summary and (
            not isinstance(shutdown_summary, Mapping)
            or shutdown_summary.get("schema_version")
            != _HISTORICAL_PROBE_CONTRACT_V17[
                "normal_shutdown_disposal_summary_schema_version"
            ]
            or shutdown_summary.get("policy")
            != _HISTORICAL_PROBE_CONTRACT_V17["normal_shutdown_disposal_policy"]
        ):
            raise ValueError(
                "historical pinned CDP shutdown disposal summary differs from its contract"
            )
        validate_normal_shutdown_disposal_summary(
            shutdown_summary,
            require_terminal=True,
            allow_historical=allow_historical_normal_shutdown_disposal_summary,
        )
    activity_by_type = target_activity["by_target_type"]
    http_status_counts = topology.get("http_status_counts")
    server_request_counts = topology.get("server_request_counts")
    if (
        not isinstance(http_status_counts, Mapping)
        or any(
            not isinstance(statuses, Mapping)
            or any(type(count) is not int for count in statuses.values())
            for statuses in http_status_counts.values()
        )
        or not isinstance(server_request_counts, Mapping)
        or any(type(count) is not int for count in server_request_counts.values())
    ):
        raise ValueError("pinned CDP probe topology evidence did not pass")
    if (
        not isinstance(target_types, list)
        or target_types != expected_types
        or any(not isinstance(item, str) or not item for item in target_types)
        or type(topology.get("event_count")) is not int
        or topology["event_count"] < sum(_EXPECTED_SERVER_REQUEST_COUNTS.values())
        or topology.get("duplicate_request_occurrences") != 2
        or topology.get("worker_network_target_types") != ["shared_worker", "worker"]
        or http_status_counts != _EXPECTED_HTTP_STATUS_COUNTS
        or server_request_counts != _EXPECTED_SERVER_REQUEST_COUNTS
        or prearm != _EXPECTED_PINNED_BOOTSTRAP_PREARM_SUMMARY
        or egress_prearm["target_total"] < 4
        or egress_prearm["installed_total"] != egress_prearm["target_total"]
        or egress_prearm["by_target_type"]["page"]["installed_count"] != 1
        or any(
            egress_prearm["by_target_type"][target_type]["installed_count"] < 1
            for target_type in ("iframe", "shared_worker", "worker")
        )
        or type(topology.get("browser_context_service_worker_count")) is not int
        or topology["browser_context_service_worker_count"] != 0
        or (
            require_worker_response_consumption
            and topology.get("worker_response_consumption") != _EXPECTED_WORKER_RESPONSE_CONSUMPTION
        )
        or activity_by_type["page"]["event_counts"]["target-attached"] != 0
        or any(
            activity_by_type[target_type]["event_counts"]["target-attached"] < 1
            for target_type in ("iframe", "shared_worker", "worker")
        )
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
            "saved_uid",
            "filesystem_uid",
            "real_gid",
            "effective_gid",
            "saved_gid",
            "filesystem_gid",
            "expected_uid",
            "expected_gid",
            "supplementary_groups",
            "inheritable_capabilities",
            "permitted_capabilities",
            "effective_capabilities",
            "bounding_capabilities",
            "ambient_capabilities",
            "no_new_privileges",
            "observed_interfaces",
        }
        or any(
            type(value.get(field)) is not int or value[field] < 1
            for field in (
                "real_uid",
                "effective_uid",
                "saved_uid",
                "filesystem_uid",
                "real_gid",
                "effective_gid",
                "saved_gid",
                "filesystem_gid",
                "expected_uid",
                "expected_gid",
            )
        )
        or any(
            value[field] != value["expected_uid"]
            for field in ("real_uid", "effective_uid", "saved_uid", "filesystem_uid")
        )
        or any(
            value[field] != value["expected_gid"]
            for field in ("real_gid", "effective_gid", "saved_gid", "filesystem_gid")
        )
        or not isinstance(value.get("supplementary_groups"), list)
        or any(
            type(group) is not int or group < 1 for group in value.get("supplementary_groups", [])
        )
        or value.get("supplementary_groups") != sorted(set(value.get("supplementary_groups", [])))
        or any(
            value.get(field) != "0000000000000000"
            for field in (
                "inheritable_capabilities",
                "permitted_capabilities",
                "effective_capabilities",
                "bounding_capabilities",
                "ambient_capabilities",
            )
        )
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
    uid_values = status.get("Uid", "").split()
    gid_values = status.get("Gid", "").split()
    if len(uid_values) != 4 or len(gid_values) != 4:
        raise ValueError("pinned CDP probe cannot read complete process credentials")
    capabilities = {
        field: status.get(status_name, "").lower()
        for field, status_name in (
            ("inheritable_capabilities", "CapInh"),
            ("permitted_capabilities", "CapPrm"),
            ("effective_capabilities", "CapEff"),
            ("bounding_capabilities", "CapBnd"),
            ("ambient_capabilities", "CapAmb"),
        )
    }
    if any(
        re.fullmatch(r"[0-9a-f]{16}", capability) is None for capability in capabilities.values()
    ):
        raise ValueError("pinned CDP probe cannot read complete capability sets")
    interfaces = sorted(name for _index, name in socket.if_nameindex())
    value = {
        "real_uid": int(uid_values[0]),
        "effective_uid": int(uid_values[1]),
        "saved_uid": int(uid_values[2]),
        "filesystem_uid": int(uid_values[3]),
        "real_gid": int(gid_values[0]),
        "effective_gid": int(gid_values[1]),
        "saved_gid": int(gid_values[2]),
        "filesystem_gid": int(gid_values[3]),
        "expected_uid": expected_uid,
        "expected_gid": expected_gid,
        "supplementary_groups": sorted(set(os.getgroups())),
        **capabilities,
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


def _canonical_build_completion_path(cohort_version: int) -> str:
    """Return the canonical persisted identity of a completed current build."""

    return f"/lab/artifacts/buflo-study/build-completion-v{cohort_version}.json"


def _legacy_build_identity(build: Mapping[str, Any]) -> dict[str, Any]:
    """Reproduce schema-8 identity only for explicit historical verification."""

    return {
        "cohort_version": build["cohort_version"],
        "sha256": build["sha256"],
        "collection_image": build["collection_image"],
        "started_at": build["started_at"],
        "finished_at": build["finished_at"],
    }


def _current_build_identity(build: Mapping[str, Any]) -> dict[str, Any]:
    """Project the complete current build identity without losing completion."""

    cohort_version = build.get("cohort_version")
    completion_sha256 = build.get("completion_sha256")
    completion_path = build.get("completion_path")
    build_path = build.get("path")
    if (
        type(cohort_version) is not int
        or cohort_version < 1
        or not isinstance(build_path, str)
        or not isinstance(completion_path, str)
        or not Path(completion_path).is_absolute()
        or Path(completion_path).resolve()
        != Path(build_path).resolve().with_name(f"build-completion-v{cohort_version}.json")
        or not isinstance(completion_sha256, str)
        or _DIGEST.fullmatch(completion_sha256) is None
    ):
        raise ValueError("pinned CDP requires a completed schema-5 build identity")
    return {
        "cohort_version": cohort_version,
        "sha256": build["sha256"],
        "completion_path": _canonical_build_completion_path(cohort_version),
        "completion_sha256": completion_sha256,
        "collection_image": build["collection_image"],
        "started_at": build["started_at"],
        "finished_at": build["finished_at"],
    }


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
