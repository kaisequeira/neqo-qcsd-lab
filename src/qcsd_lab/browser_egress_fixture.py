"""Frozen browser-egress qualification vectors and sink evidence contracts.

The live Docker runner is intentionally kept out of this module.  These pure
contracts make the browser action, its expected semantic outcome, and the
network sink evidence independently reviewable before any browser is started.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import select
import socket
import ssl
import struct
import threading
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol
from urllib.parse import quote

from .browser_egress import (
    BROWSER_EGRESS_NETWORK_PREDICTION_DISABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_NETWORK_PREDICTION_ENABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE,
    BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE,
    WEBSOCKET_POLICY_CLOSE_CODE,
    WEBSOCKET_POLICY_CLOSE_REASON,
)
from .class_study import canonical_json_bytes, canonical_json_sha256

QUALIFICATION_ID = "browser-egress-qualification-v1"
VECTOR_SCHEMA_VERSION = 3
SEMANTIC_OBSERVATION_SCHEMA_VERSION = 3
ACTION_CONTRACT_SCHEMA_VERSION = 3
SINK_RECEIPT_SCHEMA_VERSION = 1
VECTOR_COUNT = 110
BROWSER_LAUNCH_CONTRACT_SCHEMA_VERSION = 1
CLOSE_GRACE_MS = 5_000
REPORTING_NEL_LIVE_DWELL_MS = 2_000
REPORTING_NEL_CLOSE_AFTER_ACTION_MAX_MS = 2_000
SPECULATION_PREFETCH_DWELL_MS = 5_000
BROWSER_SERVICE_CONTROL_DWELL_MS = 5_000
POSITIVE_CONTROL_PAYLOAD = b"QCSD-BROWSER-EGRESS-CONTROL-V1!!"
CHROMIUM_NETWORK_PREDICTION_NEVER_POLICY = {
    "DnsOverHttpsMode": "off",
    "NetworkPredictionOptions": 2,
    "semantics": "never-predict",
    "sha256": "8293900f406510aaf6eb23ae7123d8c7321d91a00c98646671b21f58dbf41526",
}
CHROMIUM_NETWORK_PREDICTION_ENABLED_POLICY = {
    "DnsOverHttpsMode": "off",
    "NetworkPredictionOptions": 0,
    "semantics": "predict-on-any-connection",
    "sha256": "4566be4f014df0cfd45cf8bdeb4333b341bf4c666139e364992306c12873df03",
}
FIXTURE_CERTIFICATE = {
    "path": "config/class-study/v1/browser-egress-fixture-cert-v1.pem",
    "sha256": "e1fbe7f4b744ed0899eb5fcee39cbc44a2254b0e9a617b40cf4611bbc3a4c3c7",
    "spki_sha256_base64": "k3C2v8R8+ZvVlGwfaKCfUgaP5meJPA4oHibz7BFn2Zs=",
}
FIXTURE_PRIVATE_KEY = {
    "path": "config/class-study/v1/browser-egress-fixture-key-v1.pem",
    "sha256": "f65d278ee534629e16e52604696d848dbdaf981606cb49cc190e5df1b2e872bb",
}
PROXY_ENVIRONMENT_KEYS = (
    "ALL_PROXY",
    "FTP_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "all_proxy",
    "ftp_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)

CONSTRUCTOR_CONTEXTS = (
    "page",
    "same-origin-frame",
    "cross-origin-frame",
    "dedicated-worker",
    "shared-worker",
)
DOCUMENT_CONTEXTS = (
    "page",
    "same-origin-frame",
    "cross-origin-frame",
)
CONSTRUCTOR_SURFACES = (
    "websocket",
    "websocket-stream",
    "webtransport",
    "rtc-stun-udp",
    "rtc-stun-tcp",
    "rtc-turn-udp",
    "rtc-turn-tcp",
    "tcp-client",
    "tcp-server",
    "udp-socket",
)
SERVICE_WORKER_SURFACES = ("registration", "import", "fetch")
POPUP_SURFACES = (
    "window-open-omitted-target",
    "window-open-empty-target",
    "window-open-blank-target",
    "window-open-attacker-name",
    "window-open-existing-named-frame",
    "attached-anchor",
    "detached-anchor",
    "button-formtarget",
    "input-formtarget",
    "request-submit-submitter",
)
BROWSER_SERVICE_SURFACES = (
    "dns-prefetch",
    "preconnect",
    "speculation-prefetch",
    "speculation-prerender",
    "reporting-nel-live",
    "reporting-nel-close-flush",
    "fedcm",
    "protected-audience",
    "attribution",
    "shared-storage",
    "proxy",
    "pac",
    "idle-launch-close",
)
CONTROL_SURFACES = ("tcp", "udp", "dns")
BROWSER_SERVICE_CONTROL_SPECS = (
    (
        "off-the-record",
        "speculation-prefetch-disabled",
        "action-issued",
        "paired-network-prediction-suppression",
        "approved-speculation-prefetch-zero",
    ),
    (
        "off-the-record",
        "speculation-prefetch-enabled",
        "positive-control-observed",
        "paired-network-prediction-eligibility",
        "approved-speculation-prefetch-positive",
    ),
    (
        "default-profile",
        "dns-prefetch-disabled",
        "action-issued",
        "paired-network-prediction-suppression",
        "approved-dns-prefetch-zero",
    ),
    (
        "default-profile",
        "dns-prefetch-enabled",
        "positive-control-observed",
        "paired-network-prediction-eligibility",
        "approved-dns-prefetch-positive",
    ),
    (
        "default-profile",
        "preconnect-disabled",
        "action-issued",
        "paired-network-prediction-suppression",
        "approved-preconnect-zero",
    ),
    (
        "default-profile",
        "preconnect-enabled",
        "positive-control-observed",
        "paired-network-prediction-eligibility",
        "approved-preconnect-positive",
    ),
    (
        "default-profile",
        "speculation-prerender-disabled",
        "action-issued",
        "paired-network-prediction-suppression",
        "approved-speculation-prerender-zero",
    ),
    (
        "default-profile",
        "speculation-prerender-enabled",
        "positive-control-observed",
        "paired-network-prediction-eligibility",
        "approved-speculation-prerender-positive",
    ),
    (
        "default-profile",
        "reporting-disabled",
        "action-issued",
        "paired-reporting-feature-suppression",
        "approved-reporting-zero",
    ),
    (
        "default-profile",
        "reporting-enabled",
        "positive-control-observed",
        "paired-reporting-feature-eligibility",
        "approved-reporting-positive",
    ),
    (
        "default-profile",
        "network-error-logging-disabled",
        "action-issued",
        "paired-reporting-feature-suppression",
        "approved-network-error-logging-zero",
    ),
    (
        "default-profile",
        "network-error-logging-enabled",
        "positive-control-observed",
        "paired-reporting-feature-eligibility",
        "approved-network-error-logging-positive",
    ),
)

SEMANTIC_KINDS = frozenset(
    {
        "typed-policy-rejection",
        "websocket-route-block",
        "fetch-policy-denial",
        "disabled-unavailable",
        "action-issued",
        "idle-observation",
        "positive-control-observed",
        "configuration-verified",
    }
)
DESCRIPTOR_STATES = frozenset(
    {"present-callable", "policy-disabled", "absent-noncallable", "not-applicable"}
)
SEMANTIC_MECHANISMS = frozenset(
    {
        "playwright-websocket-route",
        "paused-target-runtime-shim",
        "recursive-cdp-fetch-denial",
        "context-init-popup-guard",
        "playwright-service-worker-block",
        "pinned-native-unavailable",
        "pinned-feature-disabled",
        "managed-network-prediction-policy",
        "browser-action-issued",
        "browser-idle-observation",
        "fixture-positive-control",
        "effective-command-line-environment",
        "paired-network-prediction-suppression",
        "paired-network-prediction-eligibility",
        "paired-reporting-feature-suppression",
        "paired-reporting-feature-eligibility",
    }
)

FIXTURE_TOPOLOGY: dict[str, Any] = {
    "schema_version": 1,
    "network": {
        "name": "qcsd-browser-egress-v1",
        "driver": "bridge",
        "internal": True,
        "ipv4_subnet": "172.30.98.0/24",
        "ipv6_subnet": "fd00:71:63:73:64:98::/96",
    },
    "browser_addresses": ["172.30.98.10", "fd00:71:63:73:64:98:0:10"],
    "fixture_addresses": ["172.30.98.11", "fd00:71:63:73:64:98:0:11"],
    "forbidden_sink_addresses": ["172.30.98.20", "fd00:71:63:73:64:98:0:20"],
    "dns_sink_addresses": ["172.30.98.53", "fd00:71:63:73:64:98:0:53"],
    "browser_dns_servers": ["172.30.98.53", "fd00:71:63:73:64:98:0:53"],
    "forbidden_dns_name": "forbidden.browser-egress.invalid",
    "ports": {
        "fixture_https": 14443,
        "fixture_cross_https": 14444,
        "fixture_preconnect_https": 14445,
        "fixture_nel_error_https": 14446,
        "forbidden_tcp": 18443,
        "forbidden_udp": 18444,
        "dns": 53,
    },
    "observer": {
        "network_namespace": "browser",
        "interface": "any",
        "capture_filter": None,
        "privileged": False,
        "cap_drop": ["ALL"],
        "cap_add": ["CAP_NET_RAW"],
    },
    "positive_control_payload": {
        "bytes": len(POSITIVE_CONTROL_PAYLOAD),
        "sha256": "48314e946eeadd754eb7170b265f2c31d9cc2b8f8781a3c0fa746ba2e6f6765d",
    },
    "positive_control_dns_names": [
        "udp4-control.egress.invalid",
        "udp6-control.egress.invalid",
        "tcp4-control.egress.invalid",
        "tcp6-control.egress.invalid",
    ],
    "positive_control_dns_action": {
        "actor": "fixture-control-client",
        "resolver_bypass": True,
        "udp": {
            "queries": 2,
            "qnames": [
                "udp4-control.egress.invalid",
                "udp6-control.egress.invalid",
            ],
            "qtype": "A",
        },
        "tcp": {
            "queries": 2,
            "qnames": [
                "tcp4-control.egress.invalid",
                "tcp6-control.egress.invalid",
            ],
            "qtype": "AAAA",
            "length_prefix": "rfc1035-two-octet",
        },
    },
    "browser_service_controls": {
        "approved_origins": [
            "https://fixture.test:14443",
            "https://fixture.test:14445",
            "https://fixture.test:14446",
        ],
        "origin_ip_pins": {
            "https://fixture.test:14443": "172.30.98.11",
            "https://fixture.test:14445": "172.30.98.11",
            "https://fixture.test:14446": "172.30.98.11",
        },
        "dns_exception_hostname": "dns-control.browser-egress.test",
        "dns_positive_query_count": 3,
        "preconnect_positive_accept_count": 1,
        "report_positive_post_count": 2,
        "report_types": {
            "reporting": "csp-violation",
            "network-error-logging": "network-error",
        },
    },
}


def _browser_control_mechanism(surface: str) -> str:
    for suffix in ("-disabled", "-enabled"):
        if surface.endswith(suffix):
            return surface[: -len(suffix)]
    raise ValueError(f"browser-service control has no paired suffix: {surface}")


def _browser_control_page(surface: str) -> bytes:
    ports = FIXTURE_TOPOLOGY["ports"]
    fixture_host = "fixture.test"
    primary = FIXTURE_TOPOLOGY["browser_service_controls"]["approved_origins"][0]
    mechanism = _browser_control_mechanism(surface)
    if mechanism == "speculation-prefetch":
        action = (
            '<script type="speculationrules">'
            + json.dumps(
                {
                    "prefetch": [
                        {
                            "source": "list",
                            "urls": [f"{primary}/speculation-prefetch-sentinel"],
                        }
                    ]
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "</script>"
        )
    elif mechanism == "dns-prefetch":
        dns_name = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
        action = (
            '<meta http-equiv="x-dns-prefetch-control" content="on">'
            f'<link rel="dns-prefetch" href="//{dns_name}">'
        )
    elif mechanism == "preconnect":
        action = (
            '<link rel="preconnect" crossorigin href="'
            f"https://{fixture_host}:{ports['fixture_preconnect_https']}/"
            '">'
        )
    elif mechanism == "speculation-prerender":
        action = (
            '<script type="speculationrules">'
            + json.dumps(
                {
                    "prerender": [
                        {
                            "source": "list",
                            "urls": [f"{primary}/speculation-prerender-sentinel"],
                        }
                    ]
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "</script>"
        )
    elif mechanism == "reporting":
        action = '<img src="/csp-report-trigger">'
    elif mechanism == "network-error-logging":
        action = (
            "<script>fetch("
            + json.dumps(
                f"https://{fixture_host}:{ports['fixture_nel_error_https']}/nel-network-error"
            )
            + ").catch(()=>{});</script>"
        )
    else:  # pragma: no cover - frozen vector construction guards this.
        raise ValueError(f"unknown browser-service control surface: {surface}")
    return (
        '<!doctype html><meta charset=utf-8><link rel="icon" href="data:,">'
        f"<title>QCSD {mechanism}</title>{action}"
    ).encode()


_FIXTURE_RESPONSES: dict[str, tuple[str, bytes]] = {
    "/": (
        "text/html; charset=utf-8",
        b'<!doctype html><meta charset=utf-8><link rel="icon" href="data:,">'
        b"<title>QCSD egress fixture</title><body></body>",
    ),
    "/frame": (
        "text/html; charset=utf-8",
        b"<!doctype html><meta charset=utf-8><title>QCSD frame</title><body></body>",
    ),
    "/dedicated-worker.js": (
        "text/javascript; charset=utf-8",
        (
            b"self.onmessage = async message => {\n"
            b"  const data = message.data;\n"
            b"  const fields = data && typeof data === 'object' && !Array.isArray(data)\n"
            b"    ? Object.keys(data).sort().join(',') : '';\n"
            b"  if (fields !== 'argument,expression,protocol' ||\n"
            b"      data.protocol !== 'qcsd-dedicated-worker-action-v1' ||\n"
            b"      typeof data.expression !== 'string' || !data.argument ||\n"
            b"      typeof data.argument !== 'object' || Array.isArray(data.argument)) {\n"
            b"    throw new TypeError('invalid QCSD dedicated-worker action');\n"
            b"  }\n"
            b"  const actor = (0, eval)(`(${data.expression})`);\n"
            b"  const result = await actor(data.argument);\n"
            b"  self.postMessage({protocol:data.protocol,result});\n"
            b"};\n"
            b"self.postMessage({protocol:'qcsd-dedicated-worker-action-v1',ready:true});\n"
        ),
    ),
    "/shared-worker.js": (
        "text/javascript; charset=utf-8",
        b"self.onconnect = event => {\n"
        b"  const port = event.ports[0];\n"
        b"  port.onmessage = async message => {\n"
        b"    const data = message.data;\n"
        b"    if (!data || data.protocol !== 'qcsd-shared-worker-action-v1' || typeof data.expression !== 'string') throw new TypeError('invalid QCSD shared-worker action');\n"
        b"    const actor = (0, eval)(`(${data.expression})`);\n"
        b"    const result = await actor(data.argument);\n"
        b"    port.postMessage({protocol:data.protocol,result});\n"
        b"  };\n"
        b"  port.start();\n"
        b"  port.postMessage({protocol:'qcsd-shared-worker-action-v1',ready:true});\n"
        b"};\n",
    ),
    "/service-worker-registration.js": (
        "text/javascript; charset=utf-8",
        b"self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));\n",
    ),
    "/service-worker-import.js": (
        "text/javascript; charset=utf-8",
        b"importScripts(new URL(self.location).searchParams.get('target'));\n",
    ),
    "/service-worker-fetch.js": (
        "text/javascript; charset=utf-8",
        b"fetch(new URL(self.location).searchParams.get('target'));\n",
    ),
    "/nel-trigger": ("text/plain; charset=utf-8", b"qcsd reporting trigger\n"),
    "/speculation-prefetch-sentinel": (
        "text/plain; charset=utf-8",
        b"qcsd same-origin speculation prefetch sentinel\n",
    ),
    "/speculation-prerender-sentinel": (
        "text/plain; charset=utf-8",
        b"qcsd same-origin speculation prerender sentinel\n",
    ),
    "/csp-report-trigger": (
        "image/png",
        b"not-an-image-by-design",
    ),
    "/report": ("text/plain; charset=utf-8", b"ok\n"),
}
for _context, _surface, *_rest in BROWSER_SERVICE_CONTROL_SPECS:
    _FIXTURE_RESPONSES[f"/control/{_browser_control_mechanism(_surface)}"] = (
        "text/html; charset=utf-8",
        _browser_control_page(_surface),
    )
FIXTURE_RESPONSE_BUNDLE_SHA256 = canonical_json_sha256(
    {
        path: {"content_type": content_type, "body_sha256": hashlib.sha256(body).hexdigest()}
        for path, (content_type, body) in sorted(_FIXTURE_RESPONSES.items())
    }
)


@dataclass(frozen=True)
class BrowserEgressVector:
    """One immutable, separately executed browser-egress experiment."""

    ordinal: int
    vector_id: str
    family: str
    context: str
    surface: str
    semantic_kind: str
    semantic_mechanism: str
    descriptor_state: str
    packet_policy: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VECTOR_SCHEMA_VERSION,
            "ordinal": self.ordinal,
            "vector_id": self.vector_id,
            "family": self.family,
            "context": self.context,
            "surface": self.surface,
            "semantic_kind": self.semantic_kind,
            "semantic_mechanism": self.semantic_mechanism,
            "descriptor_state": self.descriptor_state,
            "packet_policy": self.packet_policy,
            "action_contract": expected_action_contract(self),
            "browser_launch_contract": expected_browser_launch_contract(self),
            "fresh_image_run": True,
            "close_grace_ms": CLOSE_GRACE_MS,
            "minimum_live_dwell_ms": _minimum_live_dwell_ms(self),
            "maximum_close_after_action_ms": (
                REPORTING_NEL_CLOSE_AFTER_ACTION_MAX_MS
                if self.surface == "reporting-nel-close-flush"
                else None
            ),
        }


def _minimum_live_dwell_ms(vector: BrowserEgressVector) -> int | None:
    """Return the immutable action-observation floor for one vector."""

    if vector.family == "browser-service-control":
        return BROWSER_SERVICE_CONTROL_DWELL_MS
    if vector.surface == "reporting-nel-live":
        return REPORTING_NEL_LIVE_DWELL_MS
    if vector.surface == "speculation-prefetch":
        return SPECULATION_PREFETCH_DWELL_MS
    return None


def expected_browser_launch_contract(vector: BrowserEgressVector) -> dict[str, Any]:
    """Return the sole vector-to-launch mapping consumed by qualification.

    The twelve mechanism controls are intentionally non-production.  Their
    paired policy substitution, raw-default-profile use, certificate exception,
    and (for DNS only) resolver exception are explicit here; production callers
    cannot select any of these behaviours through their launch API.
    """

    if not isinstance(vector, BrowserEgressVector):
        raise ValueError("browser launch contract requires a frozen vector")
    if vector.family == "positive-control":
        return {
            "schema_version": BROWSER_LAUNCH_CONTRACT_SCHEMA_VERSION,
            "vector_id": vector.vector_id,
            "browser_launch_required": True,
            "qualification_only": False,
            "launch_profile": BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE,
            "managed_policy": dict(CHROMIUM_NETWORK_PREDICTION_NEVER_POLICY),
            "context_kind": "browser-only-plus-independent-control-emitter",
            "resolver_profile": "approved-map-or-exclude-then-not-found",
            "resolver_approved_origins": list(
                FIXTURE_TOPOLOGY["browser_service_controls"]["approved_origins"]
            ),
            "resolver_origin_ip_pins": dict(
                FIXTURE_TOPOLOGY["browser_service_controls"]["origin_ip_pins"]
            ),
            "resolver_approved_ip_exclusions": list(FIXTURE_TOPOLOGY["fixture_addresses"]),
            "dns_exception_hostname": None,
            "fixture_certificate": None,
            "control_document_path": None,
            "control_document_origin": None,
            "control_document_body_sha256": None,
        }

    control = vector.family == "browser-service-control"
    enabled = control and vector.surface.endswith("-enabled")
    reporting = control and vector.surface.startswith(("reporting-", "network-error-logging-"))
    if not control:
        profile = BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE
        policy = CHROMIUM_NETWORK_PREDICTION_NEVER_POLICY
        context_kind = (
            "browser-only"
            if vector.surface in {"proxy", "pac", "idle-launch-close"}
            else "off-the-record-playwright"
        )
        resolver_profile = "approved-map-or-exclude-then-not-found"
        dns_exception = None
        certificate = None
        control_document_path = None
        control_document_origin = None
        control_document_body_sha256 = None
    else:
        if reporting:
            profile = (
                BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE
                if enabled
                else BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE
            )
            policy = CHROMIUM_NETWORK_PREDICTION_NEVER_POLICY
        else:
            profile = (
                BROWSER_EGRESS_NETWORK_PREDICTION_ENABLED_CONTROL_PROFILE
                if enabled
                else BROWSER_EGRESS_NETWORK_PREDICTION_DISABLED_CONTROL_PROFILE
            )
            policy = (
                CHROMIUM_NETWORK_PREDICTION_ENABLED_POLICY
                if enabled
                else CHROMIUM_NETWORK_PREDICTION_NEVER_POLICY
            )
        context_kind = (
            "off-the-record-playwright"
            if vector.context == "off-the-record"
            else "raw-default-profile-cdp-unattached-target"
        )
        dns_control = vector.surface.startswith("dns-prefetch-")
        resolver_profile = (
            "qualification-single-dns-hostname-exception"
            if dns_control
            else "approved-map-or-exclude-then-not-found"
        )
        dns_exception = (
            FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
            if dns_control
            else None
        )
        certificate = FIXTURE_CERTIFICATE
        control_document_path = f"/control/{_browser_control_mechanism(vector.surface)}"
        control_document_origin = FIXTURE_TOPOLOGY["browser_service_controls"]["approved_origins"][
            0
        ]
        control_document_body_sha256 = hashlib.sha256(
            _browser_control_page(vector.surface)
        ).hexdigest()
    return {
        "schema_version": BROWSER_LAUNCH_CONTRACT_SCHEMA_VERSION,
        "vector_id": vector.vector_id,
        "browser_launch_required": True,
        "qualification_only": control,
        "launch_profile": profile,
        "managed_policy": dict(policy),
        "context_kind": context_kind,
        "resolver_profile": resolver_profile,
        "resolver_approved_origins": list(
            FIXTURE_TOPOLOGY["browser_service_controls"]["approved_origins"]
        ),
        "resolver_origin_ip_pins": dict(
            FIXTURE_TOPOLOGY["browser_service_controls"]["origin_ip_pins"]
        ),
        "resolver_approved_ip_exclusions": list(FIXTURE_TOPOLOGY["fixture_addresses"]),
        "dns_exception_hostname": dns_exception,
        "fixture_certificate": dict(certificate) if certificate is not None else None,
        "control_document_path": control_document_path,
        "control_document_origin": control_document_origin,
        "control_document_body_sha256": control_document_body_sha256,
    }


def expected_action_contract(vector: BrowserEgressVector) -> dict[str, Any] | None:
    """Return the exact raw outcome for a native browser action or kill switch."""

    disabled_browser_surface = (
        vector.family == "browser-service"
        and vector.surface in {"fedcm", "protected-audience", "attribution", "shared-storage"}
        and vector.semantic_kind == "disabled-unavailable"
    )
    if (
        vector.semantic_kind != "action-issued"
        and not disabled_browser_surface
        and vector.family != "browser-service-control"
    ):
        return None
    if not (
        vector.family == "service-worker"
        and vector.surface in SERVICE_WORKER_SURFACES
        or vector.family == "browser-service"
        and vector.surface not in {"proxy", "pac", "idle-launch-close"}
        and vector.surface in BROWSER_SERVICE_SURFACES
        or vector.family == "browser-service-control"
    ):
        raise ValueError("action-issued vector has no explicit per-surface contract")
    if disabled_browser_surface:
        raw_outcome = {
            "resolved_type": "undefined",
            "own_descriptor": "absent",
            "action_issued": False,
            "action_succeeded": False,
            "exception_name": None,
        }
        completion = "binding-absent-without-action"
    elif vector.family == "service-worker":
        raw_outcome = {
            "resolved_type": "function",
            "own_descriptor": "data",
            "action_issued": True,
            "action_succeeded": True,
            "exception_name": None,
        }
        completion = "native-operation-resolved"
    elif vector.family == "browser-service-control":
        raw_outcome = {
            "resolved_type": "not-applicable",
            "own_descriptor": "not-applicable",
            "action_issued": True,
            "action_succeeded": True,
            "exception_name": None,
        }
        completion = "static-action-document-observed"
    else:
        raw_outcome = {
            "resolved_type": "not-applicable",
            "own_descriptor": "not-applicable",
            "action_issued": True,
            "action_succeeded": True,
            "exception_name": None,
        }
        completion = "native-action-issued-and-dwell-completed"
    return {
        "schema_version": ACTION_CONTRACT_SCHEMA_VERSION,
        "family": vector.family,
        "surface": vector.surface,
        "completion": completion,
        "minimum_live_dwell_ms": _minimum_live_dwell_ms(vector),
        "raw_outcome": raw_outcome,
        "guard_counts": {
            "policy_event_count": 0,
            "fetch_denial_count": 0,
        },
    }


def _constructor_expectation(context: str, surface: str) -> tuple[str, str, str]:
    if surface in {"tcp-client", "tcp-server", "udp-socket"}:
        return "disabled-unavailable", "pinned-native-unavailable", "absent-noncallable"
    if surface.startswith("rtc-") and context in {"dedicated-worker", "shared-worker"}:
        return "disabled-unavailable", "pinned-native-unavailable", "absent-noncallable"
    if surface == "websocket" and context in {
        "page",
        "same-origin-frame",
        "cross-origin-frame",
    }:
        return "websocket-route-block", "playwright-websocket-route", "present-callable"
    return "typed-policy-rejection", "paused-target-runtime-shim", "present-callable"


def _append(
    rows: list[BrowserEgressVector],
    *,
    vector_id: str,
    family: str,
    context: str,
    surface: str,
    semantic_kind: str,
    semantic_mechanism: str,
    descriptor_state: str,
    packet_policy: str = "zero-forbidden-egress",
) -> None:
    rows.append(
        BrowserEgressVector(
            ordinal=len(rows) + 1,
            vector_id=vector_id,
            family=family,
            context=context,
            surface=surface,
            semantic_kind=semantic_kind,
            semantic_mechanism=semantic_mechanism,
            descriptor_state=descriptor_state,
            packet_policy=packet_policy,
        )
    )


def expected_vectors() -> tuple[BrowserEgressVector, ...]:
    """Generate the exact 110-vector v1 inventory in its frozen order."""

    rows: list[BrowserEgressVector] = []
    for context in CONSTRUCTOR_CONTEXTS:
        for surface in CONSTRUCTOR_SURFACES:
            kind, mechanism, descriptor = _constructor_expectation(context, surface)
            _append(
                rows,
                vector_id=f"constructor--{context}--{surface}",
                family="constructor-transport",
                context=context,
                surface=surface,
                semantic_kind=kind,
                semantic_mechanism=mechanism,
                descriptor_state=descriptor,
            )

    for surface in ("fetch", "xhr"):
        for context in CONSTRUCTOR_CONTEXTS:
            _append(
                rows,
                vector_id=f"urlloader--{context}--{surface}",
                family="urlloader",
                context=context,
                surface=surface,
                semantic_kind="fetch-policy-denial",
                semantic_mechanism="recursive-cdp-fetch-denial",
                descriptor_state="present-callable",
            )
    for surface in ("beacon", "trusted-anchor-ping", "legacy-csp-report"):
        for context in DOCUMENT_CONTEXTS:
            _append(
                rows,
                vector_id=f"urlloader--{context}--{surface}",
                family="urlloader",
                context=context,
                surface=surface,
                semantic_kind="fetch-policy-denial",
                semantic_mechanism="recursive-cdp-fetch-denial",
                descriptor_state="present-callable",
            )

    for surface in SERVICE_WORKER_SURFACES:
        _append(
            rows,
            vector_id=f"service-worker--page--{surface}",
            family="service-worker",
            context="page",
            surface=surface,
            semantic_kind="action-issued",
            semantic_mechanism="playwright-service-worker-block",
            descriptor_state="present-callable",
        )

    for surface in POPUP_SURFACES:
        named_existing = surface == "window-open-existing-named-frame"
        _append(
            rows,
            vector_id=f"popup--page--{surface}",
            family="popup-navigation",
            context="page",
            surface=surface,
            semantic_kind=("fetch-policy-denial" if named_existing else "typed-policy-rejection"),
            semantic_mechanism=(
                "recursive-cdp-fetch-denial" if named_existing else "context-init-popup-guard"
            ),
            descriptor_state="present-callable",
        )

    for surface in BROWSER_SERVICE_SURFACES:
        if surface == "idle-launch-close":
            kind = "idle-observation"
            mechanism = "browser-idle-observation"
            descriptor = "not-applicable"
        elif surface in {"proxy", "pac"}:
            kind = "configuration-verified"
            mechanism = "effective-command-line-environment"
            descriptor = "not-applicable"
        elif surface in {"fedcm", "protected-audience", "attribution", "shared-storage"}:
            kind = "disabled-unavailable"
            mechanism = "pinned-feature-disabled"
            descriptor = "absent-noncallable"
        elif surface == "speculation-prefetch":
            kind = "action-issued"
            mechanism = "managed-network-prediction-policy"
            descriptor = "not-applicable"
        else:
            kind = "action-issued"
            mechanism = "browser-action-issued"
            descriptor = "not-applicable"
        _append(
            rows,
            vector_id=f"browser-service--browser--{surface}",
            family="browser-service",
            context="browser",
            surface=surface,
            semantic_kind=kind,
            semantic_mechanism=mechanism,
            descriptor_state=descriptor,
        )

    for context, surface, kind, mechanism, packet_policy in BROWSER_SERVICE_CONTROL_SPECS:
        _append(
            rows,
            vector_id=f"browser-service-control--{context}--{surface}",
            family="browser-service-control",
            context=context,
            surface=surface,
            semantic_kind=kind,
            semantic_mechanism=mechanism,
            descriptor_state="not-applicable",
            packet_policy=packet_policy,
        )

    for surface in CONTROL_SURFACES:
        _append(
            rows,
            vector_id=f"positive-control--fixture--{surface}",
            family="positive-control",
            context="fixture",
            surface=surface,
            semantic_kind="positive-control-observed",
            semantic_mechanism="fixture-positive-control",
            descriptor_state="not-applicable",
            packet_policy=f"positive-{surface}-control",
        )

    if len(rows) != VECTOR_COUNT:  # pragma: no cover - construction invariant
        raise AssertionError(f"expected {VECTOR_COUNT} browser-egress vectors, got {len(rows)}")
    ids = [row.vector_id for row in rows]
    if len(set(ids)) != len(ids):  # pragma: no cover - construction invariant
        raise AssertionError("browser-egress vector IDs are not unique")
    return tuple(rows)


def expanded_vectors_sha256() -> str:
    return canonical_json_sha256([vector.as_dict() for vector in expected_vectors()])


def validate_vector_inventory(value: object) -> tuple[BrowserEgressVector, ...]:
    """Reject mutation, aliasing, omission, duplication, or reordering."""

    if not isinstance(value, list):
        raise ValueError("browser-egress vector inventory must be a JSON array")
    expected = [row.as_dict() for row in expected_vectors()]
    if canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise ValueError("browser-egress vector inventory differs from frozen v1 order/content")
    # A JSON round trip rejects custom Mapping/List subclasses at the boundary.
    detached = json.loads(canonical_json_bytes(value))
    if detached != expected:  # pragma: no cover - guarded above
        raise ValueError("browser-egress vector inventory is not JSON stable")
    return expected_vectors()


def vector_by_id(vector_id: str) -> BrowserEgressVector:
    if not isinstance(vector_id, str):
        raise ValueError("browser-egress vector ID must be a string")
    for vector in expected_vectors():
        if vector.vector_id == vector_id:
            return vector
    raise ValueError(f"unknown browser-egress vector: {vector_id!r}")


def expected_semantic_chronology(vector: BrowserEgressVector) -> tuple[str, ...]:
    if vector.family == "positive-control":
        return (
            "observer-ready",
            "sinks-ready",
            "browser-started",
            "control-emitter-started",
            "action-started",
            "positive-control-observed",
            "control-emitter-exited",
            "browser-exited",
            "reporting-grace-finished",
            "observer-stopped",
        )
    if vector.family == "browser-service-control":
        terminal = (
            "positive-control-observed"
            if vector.semantic_kind == "positive-control-observed"
            else "action-issued"
        )
        return (
            "observer-ready",
            "sinks-ready",
            "browser-started",
            "action-started",
            terminal,
            "browser-exited",
            "reporting-grace-finished",
            "observer-stopped",
        )
    base = ("observer-ready", "sinks-ready", "browser-started", "prearm-verified", "action-started")
    if vector.semantic_kind == "typed-policy-rejection":
        terminal = "typed-policy-rejection"
    elif vector.semantic_kind == "websocket-route-block":
        terminal = "websocket-route-block"
    elif vector.semantic_kind == "fetch-policy-denial":
        terminal = "fetch-policy-denial"
    elif vector.semantic_kind == "disabled-unavailable":
        terminal = "disabled-unavailable"
    elif vector.semantic_kind == "action-issued":
        terminal = "action-issued"
    elif vector.semantic_kind == "configuration-verified":
        terminal = "configuration-verified"
    elif vector.semantic_kind == "idle-observation":
        terminal = "idle-observation"
    else:
        terminal = "positive-control-observed"
    after_terminal = (
        ("reporting-live-dwell-finished", "browser-exited")
        if vector.surface == "reporting-nel-live"
        else ("browser-exited",)
    )
    return (*base, terminal, *after_terminal, "reporting-grace-finished", "observer-stopped")


class LiveBrowserRealm(Protocol):
    """Adapter implemented by the Docker runner for one genuinely live realm."""

    def evaluate(self, expression: str, argument: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def browser_service_action(
        self, vector: BrowserEgressVector, argument: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def browser_configuration_observation(self, surface: str) -> Mapping[str, Any]: ...

    def guard_counts(self) -> Mapping[str, int]: ...

    def prearm_verified(self) -> bool: ...


def _javascript_api_name(surface: str) -> str | None:
    if surface == "websocket":
        return "WebSocket"
    if surface == "websocket-stream":
        return "WebSocketStream"
    if surface == "webtransport":
        return "WebTransport"
    if surface.startswith("rtc-"):
        return "RTCPeerConnection"
    if surface == "tcp-client":
        return "TCPSocket"
    if surface == "tcp-server":
        return "TCPServerSocket"
    if surface == "udp-socket":
        return "UDPSocket"
    if surface in {"fetch", "xhr"}:
        return surface
    if surface == "beacon":
        return "sendBeacon"
    if surface == "trusted-anchor-ping":
        return "HTMLAnchorElement"
    if surface == "legacy-csp-report":
        return "Content-Security-Policy"
    if surface in SERVICE_WORKER_SURFACES:
        return "ServiceWorkerContainer"
    if surface in POPUP_SURFACES:
        return "window.open"
    return None


def browser_action_expression() -> str:
    """Return the generic live action actor evaluated in the selected realm.

    The expression returns raw descriptor/action/exception measurements only.
    It does not know the expected vector outcome and therefore cannot mint a
    passing semantic claim from the manifest.
    """

    expression = r"""
async ({family, surface, tcpUrl, tcpPort, udpHost, rtcHost, rtcPort, udpPort, forbiddenUrl, popupName,
        serviceWorkerRegistrationUrl, serviceWorkerImportUrl, serviceWorkerFetchUrl}) => {
  const apiNames = {
    'websocket': 'WebSocket', 'websocket-stream': 'WebSocketStream',
    'webtransport': 'WebTransport', 'rtc-stun-udp': 'RTCPeerConnection',
    'rtc-stun-tcp': 'RTCPeerConnection', 'rtc-turn-udp': 'RTCPeerConnection',
    'rtc-turn-tcp': 'RTCPeerConnection', 'tcp-client': 'TCPSocket',
    'tcp-server': 'TCPServerSocket', 'udp-socket': 'UDPSocket'
  };
  let target = globalThis;
  let api = apiNames[surface] || null;
  if (family === 'urlloader') {
    if (surface === 'fetch') api = 'fetch';
    else if (surface === 'xhr') api = 'XMLHttpRequest';
    else if (surface === 'beacon') { target = navigator; api = 'sendBeacon'; }
    else if (surface === 'trusted-anchor-ping') api = 'HTMLAnchorElement';
    else if (surface === 'legacy-csp-report') { target = document; api = 'createElement'; }
  } else if (family === 'service-worker') {
    target = navigator.serviceWorker; api = 'register';
  } else if (family === 'popup-navigation') {
    api = 'open';
  }
  let descriptor;
  let owner = target;
  while (api !== null && owner !== null && descriptor === undefined) {
    descriptor = Object.getOwnPropertyDescriptor(owner, api);
    owner = Object.getPrototypeOf(owner);
  }
  let resolvedType = api === null ? 'not-applicable' : typeof Reflect.get(target, api);
  let ownDescriptor = api === null ? 'not-applicable' : (descriptor === undefined ? 'absent'
    : ('value' in descriptor ? 'data' : 'accessor'));
  let actionIssued = false;
  let actionSucceeded = false;
  let exceptionName = null;
  if (api !== null && resolvedType !== 'function') {
    return {resolved_type: resolvedType, own_descriptor: ownDescriptor,
            action_issued: false, action_succeeded: false, exception_name: null};
  }
  try {
    actionIssued = true;
    if (surface === 'websocket') {
      const socket = new WebSocket(tcpUrl);
      await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error('QCSD_WEBSOCKET_POLICY_CLOSE_TIMEOUT')),
          1000,
        );
        socket.addEventListener('close', event => {
          clearTimeout(timer);
          if (event.code !== __QCSD_WEBSOCKET_POLICY_CLOSE_CODE__ ||
              event.reason !== __QCSD_WEBSOCKET_POLICY_CLOSE_REASON__ ||
              event.wasClean !== true) {
            reject(new Error('QCSD_WEBSOCKET_POLICY_CLOSE_MISMATCH'));
            return;
          }
          resolve();
        }, {once: true});
      });
    }
    else if (surface === 'websocket-stream') new WebSocketStream(tcpUrl);
    else if (surface === 'webtransport') new WebTransport(forbiddenUrl);
    else if (surface.startsWith('rtc-')) {
      const turn = surface.startsWith('rtc-turn');
      const tcp = surface.endsWith('-tcp');
      const scheme = turn ? 'turn' : 'stun';
      const query = tcp ? '?transport=tcp' : '?transport=udp';
      const pc = new RTCPeerConnection({iceServers: [{urls: `${scheme}:${rtcHost}:${rtcPort}${query}`}], iceTransportPolicy: turn ? 'relay' : 'all'});
      pc.createDataChannel('qcsd');
      await pc.setLocalDescription(await pc.createOffer());
      await new Promise(resolve => setTimeout(resolve, 250));
      pc.close();
    } else if (surface === 'tcp-client') new TCPSocket(udpHost, tcpPort);
    else if (surface === 'tcp-server') new TCPServerSocket({localPort: tcpPort});
    else if (surface === 'udp-socket') new UDPSocket({remoteAddress: udpHost, remotePort: udpPort});
    else if (family === 'urlloader' && surface === 'fetch') await fetch(forbiddenUrl);
    else if (surface === 'xhr') await new Promise((resolve, reject) => { const x = new XMLHttpRequest(); x.onload = resolve; x.onerror = reject; x.open('GET', forbiddenUrl); x.send(); });
    else if (surface === 'beacon') navigator.sendBeacon(forbiddenUrl, 'qcsd');
    else if (surface === 'trusted-anchor-ping') { const a = document.createElement('a'); a.href = 'about:blank'; a.ping = forbiddenUrl; document.body.append(a); a.click(); }
    else if (surface === 'legacy-csp-report') { const meta = document.createElement('meta'); meta.httpEquiv = 'Content-Security-Policy'; meta.content = `default-src 'none'; report-uri ${forbiddenUrl}`; document.head.append(meta); const s = document.createElement('script'); s.src = forbiddenUrl; document.body.append(s); }
    else if (family === 'service-worker' && surface === 'registration') await navigator.serviceWorker.register(serviceWorkerRegistrationUrl);
    else if (family === 'service-worker' && surface === 'import') await navigator.serviceWorker.register(serviceWorkerImportUrl);
    else if (family === 'service-worker' && surface === 'fetch') await navigator.serviceWorker.register(serviceWorkerFetchUrl);
    else if (surface === 'window-open-omitted-target') window.open(forbiddenUrl);
    else if (surface === 'window-open-empty-target') window.open(forbiddenUrl, '');
    else if (surface === 'window-open-blank-target') window.open(forbiddenUrl, '_blank');
    else if (surface === 'window-open-attacker-name') window.open(forbiddenUrl, popupName);
    else if (surface === 'window-open-existing-named-frame') window.open(forbiddenUrl, popupName);
    else if (surface === 'attached-anchor' || surface === 'detached-anchor') { const a = document.createElement('a'); a.href = forbiddenUrl; a.target = '_blank'; if (surface === 'attached-anchor') document.body.append(a); a.click(); }
    else if (surface === 'button-formtarget' || surface === 'input-formtarget' || surface === 'request-submit-submitter') { const f = document.createElement('form'); f.action = forbiddenUrl; const b = document.createElement(surface === 'input-formtarget' ? 'input' : 'button'); b.type = 'submit'; b.formTarget = '_blank'; f.append(b); document.body.append(f); if (surface === 'request-submit-submitter') f.requestSubmit(b); else b.click(); }
    else throw new Error('QCSD_BROWSER_ACTION_MUST_BE_RUN_BY_BROWSER_SERVICE_ADAPTER');
    actionSucceeded = true;
  } catch (error) {
    exceptionName = error && typeof error.name === 'string' ? error.name : 'UnknownError';
  }
  return {resolved_type: resolvedType, own_descriptor: ownDescriptor,
          action_issued: actionIssued, action_succeeded: actionSucceeded,
          exception_name: exceptionName};
}
""".strip()
    return expression.replace(
        "__QCSD_WEBSOCKET_POLICY_CLOSE_CODE__", str(WEBSOCKET_POLICY_CLOSE_CODE)
    ).replace(
        "__QCSD_WEBSOCKET_POLICY_CLOSE_REASON__",
        json.dumps(WEBSOCKET_POLICY_CLOSE_REASON),
    )


def browser_service_action_expression() -> str:
    """Return the exact M143 browser-service actor used by every live adapter."""

    return f"""
async ({{surface, forbiddenUrl, forbiddenHostnameUrl, reportingTriggerUrl,
         dnsPrefetchUrl, approvedPreconnectUrl,
         sameOriginSpeculationUrl, sameOriginPrerenderUrl}}) => {{
  const disabledBindings = {{
    'fedcm': [globalThis, 'IdentityCredential'],
    'protected-audience': [navigator, 'joinAdInterestGroup'],
    'attribution': [HTMLAnchorElement.prototype, 'attributionSrc'],
    'shared-storage': [globalThis, 'sharedStorage'],
  }};
  if (Object.hasOwn(disabledBindings, surface)) {{
    const [target, name] = disabledBindings[surface];
    let owner = target;
    let descriptor;
    while (owner !== null && descriptor === undefined) {{
      descriptor = Object.getOwnPropertyDescriptor(owner, name);
      owner = Object.getPrototypeOf(owner);
    }}
    return {{
      resolved_type: typeof Reflect.get(target, name),
      own_descriptor: descriptor === undefined ? 'absent'
        : ('value' in descriptor ? 'data' : 'accessor'),
      action_issued: false,
      action_succeeded: false,
      exception_name: null,
    }};
  }}
  let actionIssued = surface !== 'idle-launch-close';
  let actionSucceeded = false;
  let exceptionName = null;
  try {{
    if (surface === 'dns-prefetch' || surface === 'preconnect') {{
      const link = document.createElement('link');
      link.rel = surface;
      link.href = surface === 'dns-prefetch' ? dnsPrefetchUrl : approvedPreconnectUrl;
      document.head.append(link);
      await new Promise(resolve => setTimeout(resolve, 750));
      actionSucceeded = true;
    }} else if (surface === 'speculation-prefetch') {{
      const script = document.createElement('script');
      script.type = 'speculationrules';
      script.textContent = JSON.stringify({{prefetch:[{{source:'list',urls:[sameOriginSpeculationUrl]}}]}});
      document.head.append(script);
      await new Promise(resolve => setTimeout(resolve, {SPECULATION_PREFETCH_DWELL_MS}));
      actionSucceeded = true;
    }} else if (surface === 'speculation-prerender') {{
      const script = document.createElement('script');
      script.type = 'speculationrules';
      script.textContent = JSON.stringify({{prerender:[{{source:'list',urls:[sameOriginPrerenderUrl]}}]}});
      document.head.append(script);
      await new Promise(resolve => setTimeout(resolve, 750));
      actionSucceeded = true;
    }} else if (surface.startsWith('reporting-nel')) {{
      await fetch(reportingTriggerUrl, {{cache: 'no-store'}});
      actionSucceeded = true;
    }} else if (surface === 'idle-launch-close') {{
      actionSucceeded = false;
    }} else {{
      throw new Error('QCSD_UNKNOWN_BROWSER_SERVICE_SURFACE');
    }}
  }} catch (error) {{
    exceptionName = error && typeof error.name === 'string' ? error.name : 'UnknownError';
  }}
  return {{
    resolved_type: 'not-applicable',
    own_descriptor: 'not-applicable',
    action_issued: actionIssued,
    action_succeeded: actionSucceeded,
    exception_name: exceptionName,
  }};
}}
""".strip()


def expected_browser_action_arguments(vector: BrowserEgressVector) -> dict[str, Any]:
    """Return the exact vector-specific URLs supplied to the live actor.

    In particular, the three service-worker vectors issue registrations for
    three different scripts.  The import/fetch scripts contain the downstream
    forbidden action they would execute if registration were not blocked.
    """

    forbidden_host = FIXTURE_TOPOLOGY["forbidden_sink_addresses"][(vector.ordinal - 1) % 2]
    forbidden_url_host = f"[{forbidden_host}]" if ":" in forbidden_host else forbidden_host
    fixture_host = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    ports = FIXTURE_TOPOLOGY["ports"]
    forbidden_url = (
        f"https://{forbidden_url_host}:{ports['forbidden_tcp']}/{quote(vector.vector_id)}"
    )
    fixture_origin = f"https://{fixture_host}:{ports['fixture_https']}"
    forbidden_hostname_url = (
        f"https://{FIXTURE_TOPOLOGY['forbidden_dns_name']}:{ports['forbidden_tcp']}/"
        f"{quote(vector.vector_id)}"
    )
    return {
        "tcpUrl": (f"ws://{forbidden_url_host}:{ports['forbidden_tcp']}/{quote(vector.vector_id)}"),
        "tcpPort": ports["forbidden_tcp"],
        "udpHost": forbidden_host,
        "rtcHost": forbidden_url_host,
        "rtcPort": (
            ports["forbidden_tcp"] if vector.surface.endswith("-tcp") else ports["forbidden_udp"]
        ),
        "udpPort": ports["forbidden_udp"],
        "forbiddenUrl": forbidden_url,
        "forbiddenHostnameUrl": forbidden_hostname_url,
        "popupName": "qcsd-egress-popup-v1",
        "serviceWorkerRegistrationUrl": (f"{fixture_origin}/service-worker-registration.js"),
        "serviceWorkerImportUrl": (
            f"{fixture_origin}/service-worker-import.js?target={quote(forbidden_url, safe='')}"
        ),
        "serviceWorkerFetchUrl": (
            f"{fixture_origin}/service-worker-fetch.js?target={quote(forbidden_url, safe='')}"
        ),
        "reportingTriggerUrl": f"{fixture_origin}/nel-trigger",
        # This production negative must exercise the terminal ``^NOTFOUND``
        # resolver rule.  The separately typed paired DNS controls use their
        # sole qualification-only hostname exception instead.
        "dnsPrefetchUrl": forbidden_hostname_url,
        "approvedPreconnectUrl": (f"https://fixture.test:{ports['fixture_preconnect_https']}/"),
        "sameOriginSpeculationUrl": (f"{fixture_origin}/speculation-prefetch-sentinel"),
        "sameOriginPrerenderUrl": (f"{fixture_origin}/speculation-prerender-sentinel"),
    }


def dedicated_worker_action_message(vector: BrowserEgressVector) -> dict[str, Any]:
    """Return the sole sanctioned message evaluated by the dedicated-worker fixture."""

    if not isinstance(vector, BrowserEgressVector) or vector.context != "dedicated-worker":
        raise ValueError("dedicated-worker action message requires a dedicated-worker vector")
    return {
        "protocol": "qcsd-dedicated-worker-action-v1",
        "expression": browser_action_expression(),
        "argument": {
            **expected_browser_action_arguments(vector),
            "family": vector.family,
            "surface": vector.surface,
        },
    }


def dedicated_worker_ready_bridge_expression() -> str:
    """Return the exact page bridge that waits for the dedicated worker to run."""

    return """
url => new Promise((resolve, reject) => {
  const worker = new Worker(url);
  const timer = setTimeout(
    () => reject(new Error('dedicated worker readiness timeout')),
    5000,
  );
  worker.onmessage = event => {
    if (event.data &&
        event.data.protocol === 'qcsd-dedicated-worker-action-v1' &&
        event.data.ready === true) {
      clearTimeout(timer);
      window.__qcsdDedicatedWorker = worker;
      resolve(true);
    }
  };
  worker.onerror = () => {
    clearTimeout(timer);
    reject(new Error('dedicated worker readiness error'));
  };
})
""".strip()


def dedicated_worker_action_bridge_expression() -> str:
    """Return the exact page bridge for one frozen dedicated-worker action."""

    return """
message => new Promise((resolve, reject) => {
  const worker = window.__qcsdDedicatedWorker;
  const timer = setTimeout(
    () => reject(new Error('dedicated worker action timeout')),
    5000,
  );
  worker.onmessage = event => {
    if (event.data &&
        event.data.protocol === message.protocol &&
        'result' in event.data) {
      clearTimeout(timer);
      resolve(event.data.result);
    }
  };
  worker.onerror = () => {
    clearTimeout(timer);
    reject(new Error('dedicated worker action error'));
  };
  worker.postMessage(message);
})
""".strip()


def shared_worker_action_message(vector: BrowserEgressVector) -> dict[str, Any]:
    """Return the sole sanctioned message evaluated by the shared-worker fixture."""

    if vector.context != "shared-worker":
        raise ValueError("shared-worker action message requires a shared-worker vector")
    return {
        "protocol": "qcsd-shared-worker-action-v1",
        "expression": browser_action_expression(),
        "argument": {
            **expected_browser_action_arguments(vector),
            "family": vector.family,
            "surface": vector.surface,
        },
    }


def execute_live_browser_action(
    *,
    vector: BrowserEgressVector,
    realm: LiveBrowserRealm,
    action_arguments: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Exercise one live, prearmed realm and retain measured raw state."""

    if vector.family == "positive-control":
        raise ValueError("positive controls must use the independent control emitter")
    before = realm.guard_counts()
    if (
        not isinstance(before, Mapping)
        or set(before) != {"policy_event_count", "fetch_denial_count"}
        or any(type(before[key]) is not int or before[key] < 0 for key in before)
        or realm.prearm_verified() is not True
    ):
        raise ValueError("live browser realm is not exactly prearmed")
    started_ns = time.monotonic_ns()
    expected_arguments = expected_browser_action_arguments(vector)
    if action_arguments is not None and dict(action_arguments) != expected_arguments:
        raise ValueError("live browser action arguments differ from the frozen vector")
    argument = {**expected_arguments, "family": vector.family, "surface": vector.surface}
    configuration_observation: Mapping[str, Any] | None = None
    if vector.surface in {"proxy", "pac"}:
        configuration_observation = realm.browser_configuration_observation(vector.surface)
        raw = {
            "resolved_type": "not-applicable",
            "own_descriptor": "not-applicable",
            "action_issued": False,
            "action_succeeded": False,
            "exception_name": None,
        }
    elif vector.family == "browser-service":
        raw = realm.evaluate(browser_service_action_expression(), argument)
    else:
        raw = realm.evaluate(browser_action_expression(), argument)
    finished_ns = time.monotonic_ns()
    after = realm.guard_counts()
    if (
        not isinstance(raw, Mapping)
        or set(raw)
        != {
            "resolved_type",
            "own_descriptor",
            "action_issued",
            "action_succeeded",
            "exception_name",
        }
        or not isinstance(after, Mapping)
        or set(after) != set(before)
    ):
        raise ValueError("live browser semantic actor returned malformed measurements")
    deltas = {key: after[key] - before[key] for key in before}
    if any(type(value) is not int or value < 0 for value in deltas.values()):
        raise ValueError("live browser guard counters regressed")
    return {
        "started_ns": started_ns,
        "finished_ns": finished_ns,
        "measurement": {
            "resolved_type": raw["resolved_type"],
            "own_descriptor": raw["own_descriptor"],
            "prearm_verified": True,
            "action_issued": raw["action_issued"],
            "action_succeeded": raw["action_succeeded"],
            "policy_event_count": deltas["policy_event_count"],
            "fetch_denial_count": deltas["fetch_denial_count"],
            "exception_name": raw["exception_name"],
            "control_observed": False,
            "configuration_observation": (
                dict(configuration_observation) if configuration_observation is not None else None
            ),
        },
    }


def _validate_configuration_observation(
    value: object, *, vector: BrowserEgressVector
) -> dict[str, Any]:
    fields = {
        "surface",
        "effective_argv_projection_sha256",
        "child_environment_sha256",
        "no_proxy_server_argument_count",
        "antagonistic_proxy_switches_present",
        "proxy_environment_keys_present",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress configuration observation fields are invalid")
    for key in ("effective_argv_projection_sha256", "child_environment_sha256"):
        digest = value[key]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("browser-egress configuration observation digest is invalid")
    if (
        value["surface"] != vector.surface
        or vector.surface not in {"proxy", "pac"}
        or type(value["no_proxy_server_argument_count"]) is not int
        or value["no_proxy_server_argument_count"] < 0
        or not isinstance(value["antagonistic_proxy_switches_present"], list)
        or any(
            not isinstance(item, str) or not item
            for item in value["antagonistic_proxy_switches_present"]
        )
        or not isinstance(value["proxy_environment_keys_present"], list)
        or any(
            not isinstance(item, str) or not item
            for item in value["proxy_environment_keys_present"]
        )
    ):
        raise ValueError("browser-egress configuration observation is invalid")
    if (
        value["antagonistic_proxy_switches_present"]
        != sorted(set(value["antagonistic_proxy_switches_present"]))
        or value["proxy_environment_keys_present"]
        != sorted(set(value["proxy_environment_keys_present"]))
        or value["no_proxy_server_argument_count"] != 1
        or value["antagonistic_proxy_switches_present"] != []
        or value["proxy_environment_keys_present"] != []
    ):
        raise ValueError("browser-egress configuration observation is not canonical")
    return json.loads(canonical_json_bytes(value))


def _derived_semantic_claim(
    measurement: Mapping[str, Any], *, vector: BrowserEgressVector
) -> tuple[str, str]:
    if measurement["control_observed"]:
        if (
            measurement["action_issued"]
            and measurement["action_succeeded"]
            and measurement["policy_event_count"] == 0
            and measurement["fetch_denial_count"] == 0
            and measurement["exception_name"] is None
        ):
            return "positive-control-observed", "not-applicable"
        raise ValueError("browser-egress positive control did not complete cleanly")
    if measurement["configuration_observation"] is not None:
        _validate_configuration_observation(measurement["configuration_observation"], vector=vector)
        if (
            measurement["resolved_type"] == "not-applicable"
            and measurement["own_descriptor"] == "not-applicable"
            and not measurement["action_issued"]
            and not measurement["action_succeeded"]
            and measurement["policy_event_count"] == 0
            and measurement["fetch_denial_count"] == 0
            and measurement["exception_name"] is None
        ):
            return "configuration-verified", "not-applicable"
    if (
        vector.surface == "idle-launch-close"
        and not measurement["action_issued"]
        and not measurement["action_succeeded"]
        and measurement["policy_event_count"] == 0
        and measurement["fetch_denial_count"] == 0
        and measurement["exception_name"] is None
    ):
        return "idle-observation", "not-applicable"
    action_contract = expected_action_contract(vector)
    if action_contract is not None:
        guard_counts = action_contract["guard_counts"]
        raw_outcome = action_contract["raw_outcome"]
        if (
            all(measurement[key] == raw_outcome[key] for key in raw_outcome)
            and measurement["policy_event_count"] == guard_counts["policy_event_count"]
            and measurement["fetch_denial_count"] == guard_counts["fetch_denial_count"]
        ):
            return vector.semantic_kind, vector.descriptor_state
        raise ValueError(
            "browser-egress native-action vector did not satisfy its per-surface contract"
        )
    if (
        measurement["fetch_denial_count"] == 1
        and measurement["action_issued"]
        and measurement["resolved_type"] == "function"
    ):
        return "fetch-policy-denial", "present-callable"
    if (
        vector.semantic_mechanism == "playwright-websocket-route"
        and measurement["policy_event_count"] == 1
        and measurement["action_issued"]
        and measurement["action_succeeded"]
        and measurement["resolved_type"] == "function"
        and measurement["exception_name"] is None
    ):
        return "websocket-route-block", "present-callable"
    if (
        measurement["policy_event_count"] == 1
        and measurement["action_issued"]
        and not measurement["action_succeeded"]
        and measurement["exception_name"] == "TypeError"
        and measurement["resolved_type"] == "function"
    ):
        return "typed-policy-rejection", "present-callable"
    if (
        measurement["resolved_type"] == "undefined"
        and measurement["own_descriptor"] == "absent"
        and not measurement["action_issued"]
        and not measurement["action_succeeded"]
        and measurement["policy_event_count"] == 0
        and measurement["fetch_denial_count"] == 0
        and measurement["exception_name"] is None
    ):
        return "disabled-unavailable", "absent-noncallable"
    raise ValueError("browser-egress semantic outcome cannot be derived from raw measurement")


def assemble_live_semantic_observation(
    *,
    vector: BrowserEgressVector,
    actor_result: Mapping[str, Any],
    event_times: Mapping[str, int],
) -> dict[str, Any]:
    """Combine measured actor output with coordinator-owned lifecycle timestamps."""

    if not isinstance(actor_result, Mapping) or set(actor_result) != {
        "started_ns",
        "finished_ns",
        "measurement",
    }:
        raise ValueError("browser-egress actor result fields are invalid")
    measurement = actor_result["measurement"]
    if not isinstance(measurement, Mapping):
        raise ValueError("browser-egress actor measurement is invalid")
    started_ns = actor_result["started_ns"]
    finished_ns = actor_result["finished_ns"]
    minimum_dwell_ms = _minimum_live_dwell_ms(vector)
    if (
        type(started_ns) is not int
        or type(finished_ns) is not int
        or started_ns < 0
        or finished_ns <= started_ns
        or (
            vector.family == "browser-service-control"
            and minimum_dwell_ms is not None
            and finished_ns - started_ns < minimum_dwell_ms * 1_000_000
        )
    ):
        raise ValueError("browser-egress actor duration is invalid")
    kind, descriptor = _derived_semantic_claim(measurement, vector=vector)
    expected_events = expected_semantic_chronology(vector)
    if not isinstance(event_times, Mapping) or set(event_times) != set(expected_events):
        raise ValueError("browser-egress lifecycle event times are incomplete")
    if event_times["action-started"] != actor_result["started_ns"]:
        raise ValueError("browser-egress actor start differs from coordinator chronology")
    if event_times[kind] != actor_result["finished_ns"]:
        raise ValueError("browser-egress actor finish differs from coordinator chronology")
    observation = {
        "schema_version": SEMANTIC_OBSERVATION_SCHEMA_VERSION,
        "vector_id": vector.vector_id,
        "observed_kind": kind,
        "mechanism": vector.semantic_mechanism,
        "descriptor_state": descriptor,
        "action_invocations": (
            0
            if kind in {"idle-observation", "disabled-unavailable", "configuration-verified"}
            else 1
        ),
        "measurement": dict(measurement),
        "chronology": [
            {"sequence": sequence, "event": event, "monotonic_ns": event_times[event]}
            for sequence, event in enumerate(expected_events, 1)
        ],
    }
    return validate_semantic_observation(observation, vector=vector)


def _payload_receipt(payloads: list[bytes]) -> tuple[int, str | None]:
    joined = b"".join(payloads)
    return len(joined), hashlib.sha256(joined).hexdigest() if joined else None


def _peer_ip_version(address: tuple[Any, ...]) -> int:
    parsed = ipaddress.ip_address(str(address[0]))
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return 4
    return parsed.version


def _empty_family_payloads(*, count_key: str, byte_key: str) -> dict[str, dict[str, Any]]:
    return {
        family: {count_key: 0, byte_key: 0, "received_payload_sha256": None}
        for family in ("ipv4", "ipv6")
    }


def expected_fixture_response_headers(vector: BrowserEgressVector) -> dict[str, dict[str, str]]:
    """Return vector-specific response policy headers served by the fixture."""

    is_legacy_negative = vector.surface in {
        "reporting-nel-live",
        "reporting-nel-close-flush",
    }
    is_reporting_control = vector.family == "browser-service-control" and (
        vector.surface.startswith("reporting-")
        or vector.surface.startswith("network-error-logging-")
    )
    if not is_legacy_negative and not is_reporting_control:
        return {}
    fixture_host = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    endpoint_host = "fixture.test" if is_reporting_control else fixture_host
    endpoint = f"https://{endpoint_host}:{FIXTURE_TOPOLOGY['ports']['fixture_https']}/report"
    response_path = (
        "primary:/"
        if is_legacy_negative
        else f"primary:/control/{_browser_control_mechanism(vector.surface)}"
    )
    headers: dict[str, str] = {
        "Reporting-Endpoints": f'qcsd="{endpoint}"',
    }
    if is_legacy_negative or vector.surface.startswith("network-error-logging-"):
        headers.update(
            {
                "NEL": (
                    '{"failure_fraction":1.0,"include_subdomains":false,'
                    '"max_age":86400,"report_to":"qcsd","success_fraction":1.0}'
                ),
                "Report-To": (
                    '{"endpoints":[{"url":"' + endpoint + '"}],"group":"qcsd","max_age":86400}'
                ),
            }
        )
    if vector.surface.startswith("reporting-"):
        headers["Content-Security-Policy-Report-Only"] = "img-src 'none'; report-to qcsd"
    return {response_path: headers}


class _FixtureHttpServer(ThreadingHTTPServer):
    def __init__(
        self,
        address: tuple[str, int],
        origin_role: str,
        tls: ssl.SSLContext | None,
        vector: BrowserEgressVector,
    ) -> None:
        super().__init__(address, _FixtureHandler)
        self.origin_role = origin_role
        self.response_headers = expected_fixture_response_headers(vector)
        self.request_counts: Counter[str] = Counter()
        self.report_type_counts: Counter[str] = Counter()
        self.accepted_connections = 0
        self.request_lock = threading.Lock()
        if tls is not None:
            self.socket = tls.wrap_socket(self.socket, server_side=True)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        with self.request_lock:
            self.accepted_connections += 1
        return connection, address

    def record(self, path: str) -> None:
        with self.request_lock:
            self.request_counts[path] += 1


class _FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        server = self.server
        assert isinstance(server, _FixtureHttpServer)
        server.record(path)
        response = _FIXTURE_RESPONSES.get(path)
        if response is None:
            body = b"not found\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        else:
            content_type, body = response
            self.send_response(200)
            self.send_header("Content-Type", content_type)
        for name, header_value in sorted(
            server.response_headers.get(f"{server.origin_role}:{path}", {}).items()
        ):
            self.send_header(name, header_value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        server = self.server
        assert isinstance(server, _FixtureHttpServer)
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError:
            length = -1
        if length < 0 or length > 1_048_576:
            self.send_error(400)
            return
        body = self.rfile.read(length)
        report_types: Counter[str] = Counter()
        try:
            decoded = json.loads(body)
            rows = decoded if isinstance(decoded, list) else [decoded]
            for row in rows:
                if not isinstance(row, Mapping) or not isinstance(row.get("type"), str):
                    raise ValueError
                report_types[row["type"]] += 1
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            report_types["invalid"] += 1
        with server.request_lock:
            server.request_counts[path] += 1
            server.report_type_counts.update(report_types)
        response = _FIXTURE_RESPONSES.get(path)
        if response is None:
            content_type, response_body, status = "text/plain; charset=utf-8", b"not found\n", 404
        else:
            content_type, response_body = response
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, _format: str, *_arguments: object) -> None:
        return


def expected_fixture_requests(vector: BrowserEgressVector) -> dict[str, int]:
    if vector.family == "positive-control":
        return {}
    if vector.family == "browser-service-control":
        counts = {f"primary:/control/{_browser_control_mechanism(vector.surface)}": 1}
        if vector.surface == "speculation-prefetch-enabled":
            counts["primary:/speculation-prefetch-sentinel"] = 1
        elif vector.packet_policy == "approved-speculation-prerender-positive":
            counts["primary:/speculation-prerender-sentinel"] = 1
        elif vector.surface.startswith("reporting-"):
            counts["primary:/csp-report-trigger"] = 1
        if vector.packet_policy in {
            "approved-reporting-positive",
            "approved-network-error-logging-positive",
        }:
            counts["primary:/report"] = FIXTURE_TOPOLOGY["browser_service_controls"][
                "report_positive_post_count"
            ]
        return dict(sorted(counts.items()))
    counts = {"primary:/": 1}
    if (
        vector.context == "same-origin-frame"
        or vector.surface == "window-open-existing-named-frame"
    ):
        counts["primary:/frame"] = 1
    elif vector.context == "cross-origin-frame":
        counts["cross:/frame"] = 1
    elif vector.context == "dedicated-worker":
        counts["primary:/dedicated-worker.js"] = 1
    elif vector.context == "shared-worker":
        counts["primary:/shared-worker.js"] = 1
    if vector.surface in {"reporting-nel-live", "reporting-nel-close-flush"}:
        counts["primary:/nel-trigger"] = 1
    # Service workers are deliberately blocked before their script fetch.  A
    # script hit would contradict the exact production-context policy.
    return dict(sorted(counts.items()))


def expected_fixture_connection_counts(vector: BrowserEgressVector) -> dict[str, int]:
    return {
        "preconnect": (
            FIXTURE_TOPOLOGY["browser_service_controls"]["preconnect_positive_accept_count"]
            if vector.packet_policy == "approved-preconnect-positive"
            else 0
        )
    }


def expected_fixture_report_type_counts(vector: BrowserEgressVector) -> dict[str, int]:
    if vector.packet_policy == "approved-reporting-positive":
        key = FIXTURE_TOPOLOGY["browser_service_controls"]["report_types"]["reporting"]
    elif vector.packet_policy == "approved-network-error-logging-positive":
        key = FIXTURE_TOPOLOGY["browser_service_controls"]["report_types"]["network-error-logging"]
    else:
        return {}
    return {key: FIXTURE_TOPOLOGY["browser_service_controls"]["report_positive_post_count"]}


def validate_fixture_observation(value: object, *, vector: BrowserEgressVector) -> dict[str, Any]:
    fields = {
        "schema_version",
        "vector_id",
        "response_bundle_sha256",
        "response_headers_sha256",
        "tls_certificate_sha256",
        "origins",
        "request_counts",
        "connection_counts",
        "report_type_counts",
        "chronology",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress fixture observation fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["vector_id"] != vector.vector_id
        or value["response_bundle_sha256"] != FIXTURE_RESPONSE_BUNDLE_SHA256
        or value["response_headers_sha256"]
        != canonical_json_sha256(expected_fixture_response_headers(vector))
    ):
        raise ValueError("browser-egress fixture observation identity is invalid")
    digest = value["tls_certificate_sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("browser-egress fixture TLS certificate binding is invalid")
    expected_origins = {
        "primary": (
            f"https://{FIXTURE_TOPOLOGY['fixture_addresses'][0]}:"
            f"{FIXTURE_TOPOLOGY['ports']['fixture_https']}"
        ),
        "cross": (
            f"https://{FIXTURE_TOPOLOGY['fixture_addresses'][0]}:"
            f"{FIXTURE_TOPOLOGY['ports']['fixture_cross_https']}"
        ),
        "preconnect": (
            f"https://{FIXTURE_TOPOLOGY['fixture_addresses'][0]}:"
            f"{FIXTURE_TOPOLOGY['ports']['fixture_preconnect_https']}"
        ),
        "nel_error": (
            f"https://{FIXTURE_TOPOLOGY['fixture_addresses'][0]}:"
            f"{FIXTURE_TOPOLOGY['ports']['fixture_nel_error_https']}"
        ),
    }
    if (
        value["origins"] != expected_origins
        or value["request_counts"] != expected_fixture_requests(vector)
        or value["connection_counts"] != expected_fixture_connection_counts(vector)
        or value["report_type_counts"] != expected_fixture_report_type_counts(vector)
    ):
        raise ValueError("browser-egress fixture origin/request evidence is invalid")
    chronology = value["chronology"]
    keys = ("started_ns", "ready_ns", "stopped_ns")
    if not isinstance(chronology, Mapping) or set(chronology) != set(keys):
        raise ValueError("browser-egress fixture chronology fields are invalid")
    times = []
    for key in keys:
        timestamp = chronology[key]
        if type(timestamp) is not int or timestamp < 0:
            raise ValueError("browser-egress fixture chronology timestamp is invalid")
        times.append(timestamp)
    if not times[0] < times[1] < times[2]:
        raise ValueError("browser-egress fixture chronology is unordered")
    return json.loads(canonical_json_bytes(value))


class BrowserFixtureServer:
    """Genuine dual-origin HTTPS fixture plus an isolated preconnect endpoint."""

    def __init__(
        self,
        *,
        tls_context: ssl.SSLContext,
        tls_certificate_sha256: str,
        vector: BrowserEgressVector,
        host: str | None = None,
    ) -> None:
        self.host = host or FIXTURE_TOPOLOGY["fixture_addresses"][0]
        self.tls_context = tls_context
        self.tls_certificate_sha256 = tls_certificate_sha256
        self.vector = vector
        self.servers: dict[str, _FixtureHttpServer] = {}
        self.threads: list[threading.Thread] = []
        self.started_ns: int | None = None
        self.ready_ns: int | None = None

    def start(self) -> None:
        if self.servers:
            raise ValueError("browser fixture was already started")
        self.started_ns = time.monotonic_ns()
        for role, port_name, tls in (
            ("primary", "fixture_https", self.tls_context),
            ("cross", "fixture_cross_https", self.tls_context),
            ("preconnect", "fixture_preconnect_https", self.tls_context),
        ):
            server = _FixtureHttpServer(
                (self.host, FIXTURE_TOPOLOGY["ports"][port_name]),
                role,
                tls,
                self.vector,
            )
            thread = threading.Thread(
                target=server.serve_forever,
                name=f"qcsd-egress-fixture-{role}",
                daemon=True,
            )
            thread.start()
            self.servers[role] = server
            self.threads.append(thread)
        self.ready_ns = time.monotonic_ns()

    def stop(self, *, vector: BrowserEgressVector | None = None) -> dict[str, Any]:
        if vector is not None and vector != self.vector:
            raise ValueError("browser fixture stop vector differs from its start vector")
        vector = self.vector
        if self.started_ns is None or self.ready_ns is None or len(self.servers) != 3:
            raise ValueError("browser fixture was not started")
        for server in self.servers.values():
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
            if thread.is_alive():
                raise RuntimeError("browser fixture server thread did not stop")
        stopped_ns = time.monotonic_ns()
        counts: Counter[str] = Counter()
        report_types: Counter[str] = Counter()
        for role, server in self.servers.items():
            with server.request_lock:
                for path, count in server.request_counts.items():
                    counts[f"{role}:{path}"] += count
                report_types.update(server.report_type_counts)
        observation = {
            "schema_version": 2,
            "vector_id": vector.vector_id,
            "response_bundle_sha256": FIXTURE_RESPONSE_BUNDLE_SHA256,
            "response_headers_sha256": canonical_json_sha256(
                expected_fixture_response_headers(vector)
            ),
            "tls_certificate_sha256": self.tls_certificate_sha256,
            "origins": {
                "primary": (
                    f"https://{FIXTURE_TOPOLOGY['fixture_addresses'][0]}:"
                    f"{FIXTURE_TOPOLOGY['ports']['fixture_https']}"
                ),
                "cross": (
                    f"https://{FIXTURE_TOPOLOGY['fixture_addresses'][0]}:"
                    f"{FIXTURE_TOPOLOGY['ports']['fixture_cross_https']}"
                ),
                "preconnect": (
                    f"https://{FIXTURE_TOPOLOGY['fixture_addresses'][0]}:"
                    f"{FIXTURE_TOPOLOGY['ports']['fixture_preconnect_https']}"
                ),
                "nel_error": (
                    f"https://{FIXTURE_TOPOLOGY['fixture_addresses'][0]}:"
                    f"{FIXTURE_TOPOLOGY['ports']['fixture_nel_error_https']}"
                ),
            },
            "request_counts": dict(sorted(counts.items())),
            "connection_counts": {"preconnect": self.servers["preconnect"].accepted_connections},
            "report_type_counts": dict(sorted(report_types.items())),
            "chronology": {
                "started_ns": self.started_ns,
                "ready_ns": self.ready_ns,
                "stopped_ns": stopped_ns,
            },
        }
        return validate_fixture_observation(observation, vector=vector)


class IndependentTcpSink:
    """Application-level TCP accept/payload counter, independent from PCAP."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._accepts = 0
        self._payloads: list[bytes] = []
        self._family_payloads: dict[int, list[bytes]] = {4: [], 6: []}

    def start(self) -> None:
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        server = socket.socket(family, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        server.bind((self.host, self.port))
        self.port = int(server.getsockname()[1])
        server.listen()
        server.settimeout(0.1)
        self._socket = server
        self._thread = threading.Thread(target=self._serve, name="qcsd-egress-tcp", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                connection, address = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(0.1)
                chunks: list[bytes] = []
                while True:
                    try:
                        chunk = connection.recv(65_536)
                    except TimeoutError:
                        if self._stop.is_set():
                            break
                        continue
                    if not chunk:
                        break
                    chunks.append(chunk)
            with self._lock:
                self._accepts += 1
                payload = b"".join(chunks)
                self._payloads.append(payload)
                self._family_payloads[_peer_ip_version(address)].append(payload)

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                raise RuntimeError("TCP sink thread did not stop")
        with self._lock:
            size, digest = _payload_receipt(self._payloads)
            result = {
                "accepted_connections": self._accepts,
                "received_payload_bytes": size,
                "received_payload_sha256": digest,
                "ip_versions": _empty_family_payloads(
                    count_key="accepted_connections", byte_key="received_payload_bytes"
                ),
            }
            for version in (4, 6):
                payloads = self._family_payloads[version]
                family_size, family_digest = _payload_receipt(payloads)
                result["ip_versions"][f"ipv{version}"] = {
                    "accepted_connections": len(payloads),
                    "received_payload_bytes": family_size,
                    "received_payload_sha256": family_digest,
                }
            return result


class IndependentUdpSink:
    """Application-level UDP datagram/payload counter, independent from PCAP."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._payloads: list[bytes] = []
        self._family_payloads: dict[int, list[bytes]] = {4: [], 6: []}

    def start(self) -> None:
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        server = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        server.bind((self.host, self.port))
        self.port = int(server.getsockname()[1])
        server.settimeout(0.1)
        self._socket = server
        self._thread = threading.Thread(target=self._serve, name="qcsd-egress-udp", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                payload, address = self._socket.recvfrom(65_535)
            except TimeoutError:
                continue
            except OSError:
                break
            with self._lock:
                self._payloads.append(payload)
                self._family_payloads[_peer_ip_version(address)].append(payload)

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                raise RuntimeError("UDP sink thread did not stop")
        with self._lock:
            size, digest = _payload_receipt(self._payloads)
            result = {
                "datagrams_received": len(self._payloads),
                "payload_bytes_received": size,
                "received_payload_sha256": digest,
                "ip_versions": _empty_family_payloads(
                    count_key="datagrams_received", byte_key="payload_bytes_received"
                ),
            }
            for version in (4, 6):
                payloads = self._family_payloads[version]
                family_size, family_digest = _payload_receipt(payloads)
                result["ip_versions"][f"ipv{version}"] = {
                    "datagrams_received": len(payloads),
                    "payload_bytes_received": family_size,
                    "received_payload_sha256": family_digest,
                }
            return result


class IndependentDnsSink:
    """Separate UDP/TCP DNS query counter; it never consults packet evidence."""

    def __init__(self, host: str, port: int = 53) -> None:
        self.host = host
        self.port = port
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._udp_names: list[str] = []
        self._tcp_names: list[str] = []
        self._udp_names_by_version: dict[int, list[str]] = {4: [], 6: []}
        self._tcp_names_by_version: dict[int, list[str]] = {4: [], 6: []}

    def start(self) -> None:
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self._udp = socket.socket(family, socket.SOCK_DGRAM)
        self._tcp = socket.socket(family, socket.SOCK_STREAM)
        for sock in (self._udp, self._tcp):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self._udp.bind((self.host, self.port))
        self.port = int(self._udp.getsockname()[1])
        self._tcp.bind((self.host, self.port))
        for sock in (self._udp, self._tcp):
            sock.setblocking(False)
        self._tcp.listen()
        self._thread = threading.Thread(target=self._serve, name="qcsd-egress-dns", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._udp is not None and self._tcp is not None
        while not self._stop.is_set():
            readable, _writable, _errors = select.select([self._udp, self._tcp], [], [], 0.1)
            for sock in readable:
                if sock is self._udp:
                    try:
                        message, address = sock.recvfrom(65_535)
                        name = _dns_query_name(message)
                    except (OSError, ValueError):
                        continue
                    with self._lock:
                        self._udp_names.append(name)
                        self._udp_names_by_version[_peer_ip_version(address)].append(name)
                else:
                    try:
                        connection, address = sock.accept()
                    except OSError:
                        continue
                    with connection:
                        connection.settimeout(1)
                        try:
                            prefix = connection.recv(2)
                            if len(prefix) != 2:
                                continue
                            length = struct.unpack("!H", prefix)[0]
                            chunks = bytearray()
                            while len(chunks) < length:
                                chunk = connection.recv(length - len(chunks))
                                if not chunk:
                                    break
                                chunks.extend(chunk)
                            if len(chunks) != length:
                                continue
                            name = _dns_query_name(bytes(chunks))
                        except (OSError, ValueError):
                            continue
                    with self._lock:
                        self._tcp_names.append(name)
                        self._tcp_names_by_version[_peer_ip_version(address)].append(name)

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        for sock in (self._udp, self._tcp):
            if sock is not None:
                sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                raise RuntimeError("DNS sink thread did not stop")
        with self._lock:
            return {
                "udp_names": sorted(self._udp_names),
                "tcp_names": sorted(self._tcp_names),
                "ip_versions": {
                    f"ipv{version}": {
                        "udp_names": sorted(self._udp_names_by_version[version]),
                        "tcp_names": sorted(self._tcp_names_by_version[version]),
                    }
                    for version in (4, 6)
                },
            }


def _dns_query_name(message: bytes) -> str:
    if len(message) < 17:
        raise ValueError("DNS query is truncated")
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(message):
            raise ValueError("DNS query name is truncated")
        length = message[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(message):
            raise ValueError("DNS query label is invalid")
        labels.append(message[offset : offset + length].decode("ascii").lower())
        offset += length
    if not labels:
        raise ValueError("DNS query name is empty")
    return ".".join(labels)


def dns_query_message(name: str, *, identifier: int) -> bytes:
    if type(identifier) is not int or not 0 <= identifier <= 65_535:
        raise ValueError("DNS query identifier is invalid")
    labels = name.lower().rstrip(".").split(".")
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    return (
        struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", 1, 1)
    )


def combine_sink_receipt(
    *,
    vector: BrowserEgressVector,
    tcp: Mapping[str, Any],
    udp: Mapping[str, Any],
    dns: Mapping[str, Any],
    forbidden_ready_ns: int,
    dns_ready_ns: int,
    forbidden_stopped_ns: int,
    dns_stopped_ns: int,
) -> dict[str, Any]:
    """Combine outputs from three separate sink roles and validate the result."""

    receipt = {
        "schema_version": SINK_RECEIPT_SCHEMA_VERSION,
        "vector_id": vector.vector_id,
        "tcp": dict(tcp),
        "udp": dict(udp),
        "dns": {
            "udp_queries_received": len(dns["udp_names"]),
            "tcp_queries_received": len(dns["tcp_names"]),
            "query_names": sorted([*dns["udp_names"], *dns["tcp_names"]]),
            "ip_versions": {
                family: {
                    "udp_queries_received": len(dns["ip_versions"][family]["udp_names"]),
                    "tcp_queries_received": len(dns["ip_versions"][family]["tcp_names"]),
                    "query_names": sorted(
                        [
                            *dns["ip_versions"][family]["udp_names"],
                            *dns["ip_versions"][family]["tcp_names"],
                        ]
                    ),
                }
                for family in ("ipv4", "ipv6")
            },
        },
        "chronology": {
            "forbidden_ready_ns": forbidden_ready_ns,
            "dns_ready_ns": dns_ready_ns,
            "forbidden_stopped_ns": forbidden_stopped_ns,
            "dns_stopped_ns": dns_stopped_ns,
        },
    }
    return validate_sink_receipt(receipt, vector=vector)


def emit_positive_control(vector: BrowserEgressVector, *, timeout_seconds: float = 3.0) -> None:
    """Emit the exact actor-side TCP, UDP, or UDP+TCP DNS positive control."""

    if vector.family != "positive-control":
        raise ValueError("control emitter requires a positive-control vector")
    forbidden_hosts = FIXTURE_TOPOLOGY["forbidden_sink_addresses"]
    dns_hosts = FIXTURE_TOPOLOGY["dns_sink_addresses"]
    ports = FIXTURE_TOPOLOGY["ports"]
    if vector.surface == "tcp":
        for host in forbidden_hosts:
            with socket.create_connection(
                (host, ports["forbidden_tcp"]), timeout=timeout_seconds
            ) as connection:
                connection.sendall(POSITIVE_CONTROL_PAYLOAD)
    elif vector.surface == "udp":
        for host in forbidden_hosts:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as datagram:
                datagram.sendto(POSITIVE_CONTROL_PAYLOAD, (host, ports["forbidden_udp"]))
    elif vector.surface == "dns":
        names = FIXTURE_TOPOLOGY["positive_control_dns_names"]
        for index, host in enumerate(dns_hosts):
            udp_message = dns_query_message(names[index], identifier=0x5151 + index)
            tcp_message = dns_query_message(names[index + 2], identifier=0x5153 + index)
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as datagram:
                datagram.sendto(udp_message, (host, ports["dns"]))
            with socket.create_connection((host, ports["dns"]), timeout=timeout_seconds) as stream:
                stream.sendall(struct.pack("!H", len(tcp_message)) + tcp_message)
    else:  # pragma: no cover - vector contract guards this
        raise ValueError("unknown positive-control surface")


def execute_live_positive_control(
    vector: BrowserEgressVector, *, timeout_seconds: float = 3.0
) -> dict[str, Any]:
    """Run and time the independent control emitter for semantic assembly."""

    started_ns = time.monotonic_ns()
    emit_positive_control(vector, timeout_seconds=timeout_seconds)
    finished_ns = time.monotonic_ns()
    return {
        "started_ns": started_ns,
        "finished_ns": finished_ns,
        "measurement": {
            "resolved_type": "not-applicable",
            "own_descriptor": "not-applicable",
            "prearm_verified": False,
            "action_issued": True,
            "action_succeeded": True,
            "policy_event_count": 0,
            "fetch_denial_count": 0,
            "exception_name": None,
            "control_observed": True,
            "configuration_observation": None,
        },
    }


def browser_service_control_actor_result(
    vector: BrowserEgressVector, *, started_ns: int, finished_ns: int
) -> dict[str, Any]:
    """Record coordinator timing for a paired static browser-service control.

    The semantic record only claims that the exact static action document ran.
    Whether suppression or eligibility occurred is independently fixed by the
    fixture, sink and packet contracts; no actor-provided success bit can mint
    that network claim.
    """

    if vector.family != "browser-service-control":
        raise ValueError("browser-service control result requires a control vector")
    if (
        type(started_ns) is not int
        or type(finished_ns) is not int
        or started_ns < 0
        or finished_ns <= started_ns
        or finished_ns - started_ns < BROWSER_SERVICE_CONTROL_DWELL_MS * 1_000_000
    ):
        raise ValueError("browser-service control timing is invalid")
    observed = vector.semantic_kind == "positive-control-observed"
    return {
        "started_ns": started_ns,
        "finished_ns": finished_ns,
        "measurement": {
            "resolved_type": "not-applicable",
            "own_descriptor": "not-applicable",
            "prearm_verified": False,
            "action_issued": True,
            "action_succeeded": True,
            "policy_event_count": 0,
            "fetch_denial_count": 0,
            "exception_name": None,
            "control_observed": observed,
            "configuration_observation": None,
        },
    }


def validate_semantic_observation(value: object, *, vector: BrowserEgressVector) -> dict[str, Any]:
    """Validate exact in-browser/prearm evidence and its event chronology."""

    fields = {
        "schema_version",
        "vector_id",
        "observed_kind",
        "mechanism",
        "descriptor_state",
        "action_invocations",
        "measurement",
        "chronology",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress semantic observation fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != SEMANTIC_OBSERVATION_SCHEMA_VERSION
        or value["vector_id"] != vector.vector_id
        or value["observed_kind"] != vector.semantic_kind
        or value["observed_kind"] not in SEMANTIC_KINDS
        or value["mechanism"] != vector.semantic_mechanism
        or value["mechanism"] not in SEMANTIC_MECHANISMS
        or value["descriptor_state"] != vector.descriptor_state
        or value["descriptor_state"] not in DESCRIPTOR_STATES
        or type(value["action_invocations"]) is not int
    ):
        raise ValueError("browser-egress semantic observation is inconsistent with its vector")
    measurement = value["measurement"]
    if not isinstance(measurement, Mapping) or set(measurement) != {
        "resolved_type",
        "own_descriptor",
        "prearm_verified",
        "action_issued",
        "action_succeeded",
        "policy_event_count",
        "fetch_denial_count",
        "exception_name",
        "control_observed",
        "configuration_observation",
    }:
        raise ValueError("browser-egress semantic measurement fields are invalid")
    if measurement["resolved_type"] not in {
        "undefined",
        "object",
        "function",
        "not-applicable",
    } or measurement["own_descriptor"] not in {
        "absent",
        "data",
        "accessor",
        "not-applicable",
    }:
        raise ValueError("browser-egress raw descriptor measurement is invalid")
    for key in (
        "prearm_verified",
        "action_issued",
        "action_succeeded",
        "control_observed",
    ):
        if type(measurement[key]) is not bool:
            raise ValueError(f"browser-egress semantic measurement {key} must be boolean")
    for key in ("policy_event_count", "fetch_denial_count"):
        if type(measurement[key]) is not int or measurement[key] < 0:
            raise ValueError(f"browser-egress semantic measurement {key} is invalid")
    exception = measurement["exception_name"]
    if exception is not None and (not isinstance(exception, str) or not exception):
        raise ValueError("browser-egress semantic exception name is invalid")
    configuration = measurement["configuration_observation"]
    if vector.surface in {"proxy", "pac"}:
        _validate_configuration_observation(configuration, vector=vector)
    elif configuration is not None:
        raise ValueError("browser-egress unexpected configuration observation")

    derived_kind, derived_descriptor = _derived_semantic_claim(measurement, vector=vector)
    expected_invocations = (
        0
        if derived_kind in {"idle-observation", "disabled-unavailable", "configuration-verified"}
        else 1
    )
    if (
        derived_kind != value["observed_kind"]
        or derived_descriptor != value["descriptor_state"]
        or value["action_invocations"] != expected_invocations
        or (
            vector.family not in {"positive-control", "browser-service-control"}
            and not measurement["prearm_verified"]
        )
        or (
            vector.family in {"positive-control", "browser-service-control"}
            and measurement["prearm_verified"]
        )
    ):
        raise ValueError("browser-egress semantic claim is not derived from its raw measurement")
    chronology = value["chronology"]
    expected_events = expected_semantic_chronology(vector)
    if not isinstance(chronology, list) or len(chronology) != len(expected_events):
        raise ValueError("browser-egress semantic chronology length is invalid")
    previous_ns = -1
    for sequence, (entry, expected_event) in enumerate(zip(chronology, expected_events), 1):
        if not isinstance(entry, Mapping) or set(entry) != {
            "sequence",
            "event",
            "monotonic_ns",
        }:
            raise ValueError("browser-egress semantic chronology entry is invalid")
        timestamp = entry["monotonic_ns"]
        if (
            type(entry["sequence"]) is not int
            or entry["sequence"] != sequence
            or entry["event"] != expected_event
            or type(timestamp) is not int
            or timestamp < 0
            or timestamp <= previous_ns
        ):
            raise ValueError("browser-egress semantic chronology is unordered or inconsistent")
        previous_ns = timestamp
    event_times = {entry["event"]: entry["monotonic_ns"] for entry in chronology}
    minimum_dwell_ms = _minimum_live_dwell_ms(vector)
    if (
        vector.family == "browser-service-control"
        and minimum_dwell_ms is not None
        and event_times[value["observed_kind"]] - event_times["action-started"]
        < minimum_dwell_ms * 1_000_000
    ):
        raise ValueError("browser-egress control dwell is too short")
    if vector.surface == "reporting-nel-live" and (
        event_times["reporting-live-dwell-finished"] - event_times["action-issued"]
        < REPORTING_NEL_LIVE_DWELL_MS * 1_000_000
    ):
        raise ValueError("browser-egress live NEL dwell is too short")
    if vector.surface == "reporting-nel-close-flush" and (
        event_times["browser-exited"] - event_times["action-issued"]
        > REPORTING_NEL_CLOSE_AFTER_ACTION_MAX_MS * 1_000_000
    ):
        raise ValueError("browser-egress NEL close was not prompt")
    return json.loads(canonical_json_bytes(value))


def empty_sink_counters(vector_id: str) -> dict[str, Any]:
    vector_by_id(vector_id)
    return {
        "schema_version": SINK_RECEIPT_SCHEMA_VERSION,
        "vector_id": vector_id,
        "tcp": {
            "accepted_connections": 0,
            "received_payload_bytes": 0,
            "received_payload_sha256": None,
            "ip_versions": _empty_family_payloads(
                count_key="accepted_connections", byte_key="received_payload_bytes"
            ),
        },
        "udp": {
            "datagrams_received": 0,
            "payload_bytes_received": 0,
            "received_payload_sha256": None,
            "ip_versions": _empty_family_payloads(
                count_key="datagrams_received", byte_key="payload_bytes_received"
            ),
        },
        "dns": {
            "udp_queries_received": 0,
            "tcp_queries_received": 0,
            "query_names": [],
            "ip_versions": {
                family: {
                    "udp_queries_received": 0,
                    "tcp_queries_received": 0,
                    "query_names": [],
                }
                for family in ("ipv4", "ipv6")
            },
        },
        "chronology": {
            "forbidden_ready_ns": 1,
            "dns_ready_ns": 1,
            "forbidden_stopped_ns": 2,
            "dns_stopped_ns": 2,
        },
    }


def expected_sink_counters(vector: BrowserEgressVector) -> dict[str, Any]:
    """Return the exact independently observed sink evidence for one vector."""

    expected = empty_sink_counters(vector.vector_id)
    payload = FIXTURE_TOPOLOGY["positive_control_payload"]
    doubled_digest = hashlib.sha256(POSITIVE_CONTROL_PAYLOAD * 2).hexdigest()
    if vector.packet_policy == "positive-tcp-control":
        expected["tcp"] = {
            "accepted_connections": 2,
            "received_payload_bytes": payload["bytes"] * 2,
            "received_payload_sha256": doubled_digest,
            "ip_versions": {
                family: {
                    "accepted_connections": 1,
                    "received_payload_bytes": payload["bytes"],
                    "received_payload_sha256": payload["sha256"],
                }
                for family in ("ipv4", "ipv6")
            },
        }
    elif vector.packet_policy == "positive-udp-control":
        expected["udp"] = {
            "datagrams_received": 2,
            "payload_bytes_received": payload["bytes"] * 2,
            "received_payload_sha256": doubled_digest,
            "ip_versions": {
                family: {
                    "datagrams_received": 1,
                    "payload_bytes_received": payload["bytes"],
                    "received_payload_sha256": payload["sha256"],
                }
                for family in ("ipv4", "ipv6")
            },
        }
    elif vector.packet_policy == "positive-dns-control":
        expected["dns"] = {
            "udp_queries_received": 2,
            "tcp_queries_received": 2,
            "query_names": sorted(FIXTURE_TOPOLOGY["positive_control_dns_names"]),
            "ip_versions": {
                "ipv4": {
                    "udp_queries_received": 1,
                    "tcp_queries_received": 1,
                    "query_names": sorted(
                        [
                            FIXTURE_TOPOLOGY["positive_control_dns_names"][0],
                            FIXTURE_TOPOLOGY["positive_control_dns_names"][2],
                        ]
                    ),
                },
                "ipv6": {
                    "udp_queries_received": 1,
                    "tcp_queries_received": 1,
                    "query_names": sorted(
                        [
                            FIXTURE_TOPOLOGY["positive_control_dns_names"][1],
                            FIXTURE_TOPOLOGY["positive_control_dns_names"][3],
                        ]
                    ),
                },
            },
        }
    elif vector.packet_policy == "approved-dns-prefetch-positive":
        count = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_positive_query_count"]
        name = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
        expected["dns"] = {
            "udp_queries_received": count,
            "tcp_queries_received": 0,
            "query_names": [name] * count,
            "ip_versions": {
                "ipv4": {
                    "udp_queries_received": count,
                    "tcp_queries_received": 0,
                    "query_names": [name] * count,
                },
                "ipv6": {
                    "udp_queries_received": 0,
                    "tcp_queries_received": 0,
                    "query_names": [],
                },
            },
        }
    return expected


def validate_sink_receipt(value: object, *, vector: BrowserEgressVector) -> dict[str, Any]:
    """Validate independently recorded TCP/UDP/DNS sink counters."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "vector_id",
        "tcp",
        "udp",
        "dns",
        "chronology",
    }:
        raise ValueError("browser-egress sink receipt fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != SINK_RECEIPT_SCHEMA_VERSION
        or value["vector_id"] != vector.vector_id
    ):
        raise ValueError("browser-egress sink receipt identity is invalid")
    tcp = value["tcp"]
    udp = value["udp"]
    dns = value["dns"]
    chronology = value["chronology"]
    if not isinstance(tcp, Mapping) or set(tcp) != {
        "accepted_connections",
        "received_payload_bytes",
        "received_payload_sha256",
        "ip_versions",
    }:
        raise ValueError("browser-egress TCP sink fields are invalid")
    if not isinstance(udp, Mapping) or set(udp) != {
        "datagrams_received",
        "payload_bytes_received",
        "received_payload_sha256",
        "ip_versions",
    }:
        raise ValueError("browser-egress UDP sink fields are invalid")
    if not isinstance(dns, Mapping) or set(dns) != {
        "udp_queries_received",
        "tcp_queries_received",
        "query_names",
        "ip_versions",
    }:
        raise ValueError("browser-egress DNS sink fields are invalid")
    chronology_fields = {
        "forbidden_ready_ns",
        "dns_ready_ns",
        "forbidden_stopped_ns",
        "dns_stopped_ns",
    }
    if not isinstance(chronology, Mapping) or set(chronology) != chronology_fields:
        raise ValueError("browser-egress sink chronology fields are invalid")
    for key in chronology_fields:
        if type(chronology[key]) is not int or chronology[key] < 0:
            raise ValueError("browser-egress sink chronology timestamp is invalid")
    if not (
        chronology["forbidden_ready_ns"] < chronology["forbidden_stopped_ns"]
        and chronology["dns_ready_ns"] < chronology["dns_stopped_ns"]
    ):
        raise ValueError("browser-egress sink chronology is unordered")
    for mapping, keys in (
        (tcp, ("accepted_connections", "received_payload_bytes")),
        (udp, ("datagrams_received", "payload_bytes_received")),
        (dns, ("udp_queries_received", "tcp_queries_received")),
    ):
        for key in keys:
            if type(mapping[key]) is not int or mapping[key] < 0:
                raise ValueError(f"browser-egress sink counter is invalid: {key}")
    for mapping in (tcp, udp):
        digest = mapping["received_payload_sha256"]
        if digest is not None and (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("browser-egress sink payload digest is invalid")
    for mapping, count_key, byte_key in (
        (tcp, "accepted_connections", "received_payload_bytes"),
        (udp, "datagrams_received", "payload_bytes_received"),
    ):
        families = mapping["ip_versions"]
        if not isinstance(families, Mapping) or set(families) != {"ipv4", "ipv6"}:
            raise ValueError("browser-egress sink IP-family evidence is invalid")
        for family in ("ipv4", "ipv6"):
            record = families[family]
            if not isinstance(record, Mapping) or set(record) != {
                count_key,
                byte_key,
                "received_payload_sha256",
            }:
                raise ValueError("browser-egress sink IP-family payload fields are invalid")
            if type(record[count_key]) is not int or type(record[byte_key]) is not int:
                raise ValueError("browser-egress sink IP-family count is invalid")
            if record[count_key] < 0 or record[byte_key] < 0:
                raise ValueError("browser-egress sink IP-family count is invalid")
            digest = record["received_payload_sha256"]
            if digest is not None and (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ValueError("browser-egress sink IP-family digest is invalid")
        if (
            sum(families[family][count_key] for family in ("ipv4", "ipv6")) != mapping[count_key]
            or sum(families[family][byte_key] for family in ("ipv4", "ipv6")) != mapping[byte_key]
        ):
            raise ValueError("browser-egress sink IP-family totals do not reconcile")
    names = dns["query_names"]
    if (
        not isinstance(names, list)
        or any(not isinstance(name, str) or not name for name in names)
        or names != sorted(names)
    ):
        raise ValueError("browser-egress DNS query-name inventory is invalid")
    dns_families = dns["ip_versions"]
    if not isinstance(dns_families, Mapping) or set(dns_families) != {"ipv4", "ipv6"}:
        raise ValueError("browser-egress DNS IP-family evidence is invalid")
    for family in ("ipv4", "ipv6"):
        record = dns_families[family]
        if not isinstance(record, Mapping) or set(record) != {
            "udp_queries_received",
            "tcp_queries_received",
            "query_names",
        }:
            raise ValueError("browser-egress DNS IP-family fields are invalid")
        for key in ("udp_queries_received", "tcp_queries_received"):
            if type(record[key]) is not int or record[key] < 0:
                raise ValueError("browser-egress DNS IP-family counter is invalid")
        if (
            not isinstance(record["query_names"], list)
            or any(not isinstance(name, str) or not name for name in record["query_names"])
            or record["query_names"] != sorted(record["query_names"])
        ):
            raise ValueError("browser-egress DNS IP-family names are invalid")
    if (
        sum(dns_families[family]["udp_queries_received"] for family in ("ipv4", "ipv6"))
        != dns["udp_queries_received"]
        or sum(dns_families[family]["tcp_queries_received"] for family in ("ipv4", "ipv6"))
        != dns["tcp_queries_received"]
        or sorted(
            name for family in ("ipv4", "ipv6") for name in dns_families[family]["query_names"]
        )
        != names
    ):
        raise ValueError("browser-egress DNS IP-family totals do not reconcile")

    expected = expected_sink_counters(vector)
    if {key: value[key] for key in ("schema_version", "vector_id", "tcp", "udp", "dns")} != {
        key: expected[key] for key in ("schema_version", "vector_id", "tcp", "udp", "dns")
    }:
        raise ValueError("browser-egress sink counters differ from the vector contract")
    return json.loads(canonical_json_bytes(value))


def fixture_contract_sha256() -> str:
    return canonical_json_sha256(
        {
            "topology": FIXTURE_TOPOLOGY,
            "response_bundle_sha256": FIXTURE_RESPONSE_BUNDLE_SHA256,
            "response_header_profiles": {
                vector.vector_id: expected_fixture_response_headers(vector)
                for vector in expected_vectors()
            },
            "browser_action_expression_sha256": hashlib.sha256(
                browser_action_expression().encode()
            ).hexdigest(),
            "browser_action_arguments": {
                vector.vector_id: expected_browser_action_arguments(vector)
                for vector in expected_vectors()
                if vector.family != "positive-control"
            },
        }
    )


def validate_fixture_topology(value: object) -> dict[str, Any]:
    if canonical_json_bytes(value) != canonical_json_bytes(FIXTURE_TOPOLOGY):
        raise ValueError("browser-egress fixture topology differs from frozen v1")
    return json.loads(canonical_json_bytes(value))


def validate_vector(value: object) -> BrowserEgressVector:
    """Return the exact frozen vector represented by one JSON object."""

    if not isinstance(value, Mapping):
        raise ValueError("browser-egress vector must be a JSON object")
    vector_id = value.get("vector_id")
    vector = vector_by_id(vector_id) if isinstance(vector_id, str) else None
    if vector is None or canonical_json_bytes(value) != canonical_json_bytes(vector.as_dict()):
        raise ValueError("browser-egress vector differs from the frozen manifest")
    return vector


def inventory_json() -> list[dict[str, Any]]:
    """Return a detached JSON-compatible copy of the frozen inventory."""

    return json.loads(canonical_json_bytes([vector.as_dict() for vector in expected_vectors()]))


def require_exact_string_sequence(value: object, *, expected: Sequence[str], label: str) -> None:
    """Small shared primitive used by the later live fixture integration."""

    if not isinstance(value, list) or value != list(expected):
        raise ValueError(f"{label} differs from the frozen sequence")
