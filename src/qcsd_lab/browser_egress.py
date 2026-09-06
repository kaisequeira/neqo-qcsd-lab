"""Fail-closed browser guards for non-URLLoader network egress.

Chromium's Fetch domain is the admission boundary for ordinary HTTP(S)
URLLoader requests.  It is not an interception boundary for WebSocket,
WebTransport, WebRTC, or Direct Sockets.  This module supplies the separate,
content-minimised policy receipt and the JavaScript installed while each CDP
target is still held for debugging.

The CDP ``Network.*Created`` notifications used by the caller are only
tripwires.  They must never be described as pre-I/O interception.  Page/frame
WebSockets are blocked independently by Playwright's context WebSocket route;
the target shim is the pre-script boundary for worker WebSockets and the other
constructor-based APIs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from threading import Lock
from typing import Any, Callable
from urllib.parse import urlsplit

from .acquisition_errors import NonReplayableEgressPolicyError

NON_REPLAYABLE_EGRESS_POLICY = "blocked-non-urlloader-egress-v1"
NON_REPLAYABLE_EGRESS_SCHEMA_VERSION = 2
TARGET_EGRESS_SHIM_SCHEMA_VERSION = 1
TARGET_EGRESS_BINDING = "__qcsd_report_non_replayable_egress_v1"
POPUP_NAVIGATION_API = "PopupNavigation"
POPUP_GUARD_MARKER = "__qcsd_popup_navigation_guard_v1__"

# Playwright revision 1200 contributes the first ``--disable-features`` value.
# The second value is an intentional strict superset which retains every
# Playwright M143 default and adds the browser-process FedCM kill switch.  It
# must remain version-bound to the pinned driver rather than silently replacing
# Playwright's safety defaults.
BROWSER_EGRESS_PLAYWRIGHT_DISABLED_FEATURES = (
    "AcceptCHFrame",
    "AvoidUnnecessaryBeforeUnloadCheckSync",
    "DestroyProfileOnBrowserClose",
    "DialMediaRouteProvider",
    "GlobalMediaControls",
    "HttpsUpgrades",
    "LensOverlay",
    "MediaRouter",
    "PaintHolding",
    "ThirdPartyStoragePartitioning",
    "Translate",
    "AutoDeElevate",
    "RenderDocument",
    "OptimizationHints",
)
BROWSER_EGRESS_DISABLED_BASE_FEATURES = (
    *BROWSER_EGRESS_PLAYWRIGHT_DISABLED_FEATURES,
    "FedCm",
    "NetworkErrorLogging",
    "Reporting",
)
BROWSER_EGRESS_REPORTING_CONTROL_DISABLED_BASE_FEATURES = tuple(
    feature
    for feature in BROWSER_EGRESS_DISABLED_BASE_FEATURES
    if feature not in {"NetworkErrorLogging", "Reporting"}
)
BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES = ("CDPScreenshotNewSurface",)
BROWSER_EGRESS_REPORTING_CONTROL_ENABLED_FEATURES = (
    *BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES,
    "NetworkErrorLogging",
    "Reporting",
)
BROWSER_EGRESS_REPORTING_CONTROL_FEATURE_ARGUMENT = (
    "--disable-features="
    + ",".join(BROWSER_EGRESS_REPORTING_CONTROL_DISABLED_BASE_FEATURES)
)
BROWSER_EGRESS_REPORTING_CONTROL_ENABLE_ARGUMENT = (
    "--enable-features="
    + ",".join(BROWSER_EGRESS_REPORTING_CONTROL_ENABLED_FEATURES)
)
BROWSER_EGRESS_DISABLED_BLINK_FEATURES = (
    "Fledge",
    "AdInterestGroupAPI",
    "AttributionReporting",
    "SharedStorageAPI",
)
BROWSER_EGRESS_PLAYWRIGHT_FEATURE_ARGUMENT = (
    "--disable-features=" + ",".join(BROWSER_EGRESS_PLAYWRIGHT_DISABLED_FEATURES)
)
BROWSER_EGRESS_REQUIRED_FEATURE_ARGUMENTS = (
    "--disable-features=" + ",".join(BROWSER_EGRESS_DISABLED_BASE_FEATURES),
    "--disable-blink-features=" + ",".join(BROWSER_EGRESS_DISABLED_BLINK_FEATURES),
)
BROWSER_EGRESS_EFFECTIVE_FEATURE_ARGUMENTS = (
    BROWSER_EGRESS_PLAYWRIGHT_FEATURE_ARGUMENT,
    *BROWSER_EGRESS_REQUIRED_FEATURE_ARGUMENTS,
)
BROWSER_EGRESS_SUBPROCESS_WRAPPER_PATH = "/usr/local/libexec/qcsd-chromium-child"
BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT = (
    f"--browser-subprocess-path={BROWSER_EGRESS_SUBPROCESS_WRAPPER_PATH}"
)
BROWSER_EGRESS_EXPLICIT_BARE_CHROMIUM_ARGS = (
    "--disable-crashpad-for-testing",
    "--disable-domain-reliability",
    # M143's QUIC server-preferred-address probing consumes a server-supplied
    # socket address directly, outside both DNS MAP pins and Fetch policy.
    # Browser discovery therefore stays on TCP; Neqo remains the QUIC capture
    # client used by the research campaigns.
    "--disable-quic",
    "--no-pings",
    "--no-proxy-server",
    "--no-zygote",
)

# These switches suppress known ambient Chromium services and disable browser
# services whose M143 bindings can be proved absent.  They are defence in depth,
# not a complete packet admission boundary: recursive request-stage CDP Fetch
# policy, the fail-closed resolver below, and fresh-image packet qualification
# remain mandatory.
BROWSER_EGRESS_EXPLICIT_CHROMIUM_ARGS = (
    *BROWSER_EGRESS_EXPLICIT_BARE_CHROMIUM_ARGS,
    BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
    *BROWSER_EGRESS_REQUIRED_FEATURE_ARGUMENTS,
)
BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES = tuple(
    sorted(
        {
            *BROWSER_EGRESS_EXPLICIT_BARE_CHROMIUM_ARGS,
            "--disable-background-networking",
            "--disable-client-side-phishing-detection",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-sync",
            "--no-first-run",
            "--no-sandbox",
            "--no-service-autorun",
        }
    )
)
# Closed conflict inventory for the switches above.  Browser.getBrowserCommandLine
# is checked using argv entries, before its content-minimised projection is
# emitted.  Keep values out of the receipt: proxy URLs and profile paths are not
# evidence and may contain sensitive host data.
BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES = tuple(
    sorted(
        {
            "--disable-extensions-except",
            "--enable-background-networking",
            "--enable-client-side-phishing-detection",
            "--enable-component-update",
            "--enable-default-apps",
            "--enable-domain-reliability",
            "--enable-extensions",
            "--enable-pings",
            "--enable-quic",
            "--enable-service-autorun",
            "--enable-sync",
            "--first-run",
            "--force-first-run",
            "--force-first-run-ui",
            "--host-rules",
            "--load-extension",
            "--proxy-auto-detect",
            "--proxy-pac-url",
            "--proxy-server",
            "--service-autorun",
            "--single-process",
        }
    )
)
BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION = 4
BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE = "production-fail-closed"
BROWSER_EGRESS_NETWORK_PREDICTION_DISABLED_CONTROL_PROFILE = (
    "qualification-network-prediction-disabled-control"
)
BROWSER_EGRESS_NETWORK_PREDICTION_ENABLED_CONTROL_PROFILE = (
    "qualification-network-prediction-enabled-control"
)
BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE = (
    "qualification-reporting-disabled-control"
)
BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE = (
    "qualification-reporting-enabled-control"
)
# Backwards-internal alias retained while the qualification runner moves to the
# explicit enabled/disabled profile names.  It is not part of the production
# launch builder.
BROWSER_EGRESS_NETWORK_PREDICTION_CONTROL_PROFILE = (
    BROWSER_EGRESS_NETWORK_PREDICTION_ENABLED_CONTROL_PROFILE
)
BROWSER_EGRESS_REPORTING_CONTROL_PROFILE = BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE
BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES = (
    BROWSER_EGRESS_NETWORK_PREDICTION_DISABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_NETWORK_PREDICTION_ENABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE,
    BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE,
)
BROWSER_EGRESS_FIXTURE_CERTIFICATE_SPKI_SHA256_BASE64 = (
    "k3C2v8R8+ZvVlGwfaKCfUgaP5meJPA4oHibz7BFn2Zs="
)
BROWSER_EGRESS_FIXTURE_CERTIFICATE_ARGUMENT = (
    "--ignore-certificate-errors-spki-list="
    + BROWSER_EGRESS_FIXTURE_CERTIFICATE_SPKI_SHA256_BASE64
)
BROWSER_EGRESS_SHORT_REPORTING_DELAY_ARGUMENT = "--short-reporting-delay"
BROWSER_EGRESS_QUALIFICATION_ONLY_SWITCHES = (
    "--ignore-certificate-errors-spki-list",
    BROWSER_EGRESS_SHORT_REPORTING_DELAY_ARGUMENT,
)
HOST_RESOLVER_POLICY_SCHEMA_VERSION = 1
HOST_RESOLVER_SWITCH = "--host-resolver-rules"
HOST_RESOLVER_CATCH_ALL_RULE = "MAP * ^NOTFOUND"
QUALIFICATION_DNS_RESOLVER_POLICY_SCHEMA_VERSION = 1

PAGE_TARGET_EGRESS_APIS = (
    "WebSocketStream",
    "WebTransport",
    "RTCPeerConnection",
    "webkitRTCPeerConnection",
    "TCPSocket",
    "TCPServerSocket",
    "UDPSocket",
)
WORKER_TARGET_EGRESS_APIS = ("WebSocket", *PAGE_TARGET_EGRESS_APIS)
TARGET_EGRESS_APIS = tuple(sorted(set(WORKER_TARGET_EGRESS_APIS)))

_MECHANISMS = frozenset(
    {
        "playwright-websocket-route",
        "context-init-popup-guard",
        "browser-popup-tab-tripwire",
        "playwright-popup-navigation-route",
        "paused-target-runtime-shim",
        "cdp-network-tripwire",
        "browser-service-worker-tripwire",
    }
)


def install_context_egress_guards(context: Any, guard: "NonReplayableEgressGuard") -> None:
    """Install context-wide constructor, navigation, WebSocket, and worker guards.

    This must run before ``context.new_page()``.  Playwright implements a
    browser-context WebSocket route as an init binding/script for every page
    and frame; worker WebSockets are separately covered by the paused-target
    shim.  Calling ``close`` without ``connect_to_server`` keeps a routed
    page/frame socket from opening a server connection.
    """

    def block_websocket(route: Any) -> None:
        guard.record(
            api="WebSocket",
            mechanism="playwright-websocket-route",
            url=route.url,
        )
        route.close(code=1008, reason="QCSD non-replayable egress policy")

    def block_popup_navigation(route: Any) -> None:
        request = route.request
        if not request.is_navigation_request():
            route.continue_()
            return
        try:
            request_page = request.frame.page
        except Exception:
            request_page = None
        if guard.is_root_page(request_page):
            # This admits the root page and all of its frame navigations only;
            # recursive CDP Fetch remains the fine-grained HTTP(S) policy.
            route.continue_()
            return
        guard.record(
            api=POPUP_NAVIGATION_API,
            mechanism="playwright-popup-navigation-route",
            url=request.url,
        )
        route.abort("blockedbyclient")

    def reject_service_worker(worker: Any) -> None:
        guard.record(
            api="ServiceWorker",
            mechanism="browser-service-worker-tripwire",
            url=worker.url,
        )

    # This popup-safe init script runs before page/frame author code.  It blocks
    # even before the reporting CDP binding exists and starts reporting once
    # Runtime.addBinding makes that name available in the realm.
    context.add_init_script(script=context_page_egress_init_source())
    context.route("**/*", block_popup_navigation)
    context.route_web_socket("**", block_websocket)
    context.on("serviceworker", reject_service_worker)
    guard.mark_context_guards_installed()


def _rule_hostname(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            hostname = value.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError(f"{label} is not a valid hostname") from error
        if (
            hostname != value.lower()
            or any(character.isspace() for character in hostname)
            or any(character in hostname for character in ",*~[]")
            or hostname.startswith(".")
            or hostname.endswith(".")
            or ".." in hostname
        ):
            raise ValueError(f"{label} is not canonical")
        return hostname
    if address.compressed != value:
        raise ValueError(f"{label} must use canonical IP text")
    return f"[{address.compressed}]" if address.version == 6 else address.compressed


def _validated_rule_host_token(value: str, *, label: str) -> str:
    """Validate the exact host-token spelling used by Chromium rules."""

    if value.startswith("[") or value.endswith("]"):
        if not (value.startswith("[") and value.endswith("]")):
            raise ValueError(f"{label} has malformed IPv6 brackets")
        canonical = _rule_hostname(value[1:-1], label=label)
    else:
        canonical = _rule_hostname(value, label=label)
    if canonical != value:
        raise ValueError(f"{label} is not canonical")
    return canonical


def _canonical_ip_rule_token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty IP-address string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"{label} is not an IP address") from error
    if address.compressed != value:
        raise ValueError(f"{label} must use canonical IP text")
    return f"[{address.compressed}]" if address.version == 6 else address.compressed


def _origin_hostname(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("approved origin must be a non-empty string")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise ValueError("approved origin is malformed") from error
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("approved origin must be an absolute HTTP(S) origin")
    return _rule_hostname(parsed.hostname, label="approved origin hostname")


def build_fail_closed_host_resolver_argument(
    *,
    approved_origins: Sequence[str] = (),
    origin_ip_pins: Mapping[str, str] | None = None,
    approved_ip_exclusions: Sequence[str] = (),
) -> str:
    """Build Chromium's sole canonical deny-all resolver argument.

    Public acquisition supplies an exact origin-to-IP pin for every approved
    origin.  Local evidence fixtures instead exclude explicitly approved
    numeric addresses from the final ``MAP * ^NOTFOUND`` rule.  An origin can
    never silently fall back to ordinary DNS.
    """

    if isinstance(approved_origins, (str, bytes)) or not isinstance(
        approved_origins, Sequence
    ):
        raise ValueError("approved origins must be a sequence")
    origins = tuple(approved_origins)
    if len(set(origins)) != len(origins):
        raise ValueError("approved origins must be unique")
    origin_hosts = {origin: _origin_hostname(origin) for origin in origins}

    mapped: dict[str, str] = {}
    excluded: set[str] = set()
    if origins and origin_ip_pins is None:
        raise ValueError("approved origins require exact origin IP pins")
    if origin_ip_pins is not None:
        if not isinstance(origin_ip_pins, Mapping) or set(origin_ip_pins) != set(origins):
            raise ValueError("origin IP pins must cover the approved origin set exactly")
        for origin in origins:
            raw_address = origin_ip_pins[origin]
            destination = _canonical_ip_rule_token(raw_address, label="origin IP pin")
            hostname = origin_hosts[origin]
            previous = mapped.setdefault(hostname, destination)
            if previous != destination:
                raise ValueError("origin IP pins conflict for a shared hostname")

    if isinstance(approved_ip_exclusions, (str, bytes)) or not isinstance(
        approved_ip_exclusions, Sequence
    ):
        raise ValueError("approved IP exclusions must be a sequence")
    for raw_address in approved_ip_exclusions:
        excluded.add(
            _canonical_ip_rule_token(raw_address, label="approved IP exclusion")
        )

    if not mapped and not excluded:
        raise ValueError("fail-closed resolver requires at least one approved host or IP")
    if set(mapped).intersection(excluded):
        raise ValueError("a resolver host cannot be both mapped and excluded")
    rules = [f"MAP {host} {mapped[host]}" for host in sorted(mapped)]
    rules.append(HOST_RESOLVER_CATCH_ALL_RULE)
    rules.extend(f"EXCLUDE {host}" for host in sorted(excluded))
    argument = f"{HOST_RESOLVER_SWITCH}=" + ", ".join(rules)
    validate_fail_closed_host_resolver_argument(argument)
    return argument


def validate_fail_closed_host_resolver_argument(value: object) -> dict[str, object]:
    """Validate and content-minimise one canonical resolver argument."""

    prefix = f"{HOST_RESOLVER_SWITCH}="
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ValueError("host-resolver argument is malformed")
    raw_rules = value[len(prefix) :]
    rules = raw_rules.split(", ")
    if not raw_rules or ", ".join(rules) != raw_rules:
        raise ValueError("host-resolver rules are not canonically separated")
    mapped: dict[str, str] = {}
    excluded: set[str] = set()
    catch_all_index: int | None = None
    for index, rule in enumerate(rules):
        if rule == HOST_RESOLVER_CATCH_ALL_RULE:
            if catch_all_index is not None:
                raise ValueError("host-resolver catch-all rule is duplicated")
            catch_all_index = index
            continue
        if rule.startswith("MAP "):
            parts = rule.split(" ")
            if len(parts) != 3 or parts[1] == "*":
                raise ValueError("host-resolver MAP rule is malformed")
            host = _validated_rule_host_token(parts[1], label="mapped host")
            destination_token = parts[2]
            if destination_token.startswith("[") or destination_token.endswith("]"):
                if not (
                    destination_token.startswith("[")
                    and destination_token.endswith("]")
                ):
                    raise ValueError("mapped destination has malformed IPv6 brackets")
                destination = _canonical_ip_rule_token(
                    destination_token[1:-1], label="mapped destination"
                )
            else:
                destination = _canonical_ip_rule_token(
                    destination_token, label="mapped destination"
                )
            if destination != destination_token:
                raise ValueError("mapped destination is not canonical")
            if host in mapped:
                raise ValueError("host-resolver MAP host is duplicated")
            mapped[host] = destination
            continue
        if rule.startswith("EXCLUDE "):
            parts = rule.split(" ")
            if len(parts) != 2:
                raise ValueError("host-resolver EXCLUDE rule is malformed")
            raw_host = parts[1]
            if raw_host.startswith("[") or raw_host.endswith("]"):
                if not (raw_host.startswith("[") and raw_host.endswith("]")):
                    raise ValueError("excluded host has malformed IPv6 brackets")
                host = _canonical_ip_rule_token(
                    raw_host[1:-1], label="excluded host"
                )
            else:
                host = _canonical_ip_rule_token(raw_host, label="excluded host")
            if host != raw_host:
                raise ValueError("excluded host is not canonical")
            if host in excluded:
                raise ValueError("host-resolver EXCLUDE host is duplicated")
            excluded.add(host)
            continue
        raise ValueError("host-resolver rule is unsupported")
    if catch_all_index is None:
        raise ValueError("host-resolver policy omitted the deny-all rule")
    canonical_rules = [f"MAP {host} {mapped[host]}" for host in sorted(mapped)]
    canonical_rules.append(HOST_RESOLVER_CATCH_ALL_RULE)
    canonical_rules.extend(f"EXCLUDE {host}" for host in sorted(excluded))
    if rules != canonical_rules or set(mapped).intersection(excluded):
        raise ValueError("host-resolver policy is not canonical")
    return {
        "schema_version": HOST_RESOLVER_POLICY_SCHEMA_VERSION,
        "mode": "approved-map-or-exclude-then-not-found",
        "rule_count": len(rules),
        "mapped_host_count": len(mapped),
        "excluded_host_count": len(excluded),
        "catch_all_not_found": True,
        "canonical_rules_sha256": hashlib.sha256(_canonical_json_bytes(rules)).hexdigest(),
    }


def browser_egress_chromium_args(
    *,
    approved_origins: Sequence[str] = (),
    origin_ip_pins: Mapping[str, str] | None = None,
    approved_ip_exclusions: Sequence[str] = (),
) -> list[str]:
    """Return one canonical fail-closed argument list for a Chromium launch."""

    return [
        *BROWSER_EGRESS_EXPLICIT_CHROMIUM_ARGS,
        build_fail_closed_host_resolver_argument(
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
            approved_ip_exclusions=approved_ip_exclusions,
        ),
    ]


def _qualification_dns_control_resolver_argument(
    *,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    approved_ip_exclusions: Sequence[str],
    dns_exception_hostname: str,
) -> str:
    """Build the one typed DNS-eligibility exception used only by qualification.

    Production resolver parsing deliberately rejects hostname ``EXCLUDE``
    rules.  This helper is separate so no public acquisition caller can turn
    the exception on through a boolean or an optional production parameter.
    """

    hostname = _rule_hostname(dns_exception_hostname, label="DNS control hostname")
    try:
        ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError("DNS control exception must be a DNS hostname")
    if hostname != dns_exception_hostname:
        raise ValueError("DNS control hostname must be canonical")
    base = build_fail_closed_host_resolver_argument(
        approved_origins=approved_origins,
        origin_ip_pins=origin_ip_pins,
        approved_ip_exclusions=approved_ip_exclusions
    )
    rules = base.split("=", 1)[1].split(", ")
    rules.append(f"EXCLUDE {hostname}")
    return f"{HOST_RESOLVER_SWITCH}=" + ", ".join(rules)


def _validate_qualification_dns_control_resolver_argument(
    value: object,
    *,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    approved_ip_exclusions: Sequence[str],
    dns_exception_hostname: str,
) -> dict[str, object]:
    expected = _qualification_dns_control_resolver_argument(
        approved_origins=approved_origins,
        origin_ip_pins=origin_ip_pins,
        approved_ip_exclusions=approved_ip_exclusions,
        dns_exception_hostname=dns_exception_hostname,
    )
    if value != expected:
        raise ValueError("qualification DNS resolver policy differs from its exact topology")
    rules = expected.split("=", 1)[1].split(", ")
    safe_rules = rules[:-1]
    safe_projection = validate_fail_closed_host_resolver_argument(
        f"{HOST_RESOLVER_SWITCH}=" + ", ".join(safe_rules)
    )
    return {
        "schema_version": QUALIFICATION_DNS_RESOLVER_POLICY_SCHEMA_VERSION,
        "mode": "qualification-single-dns-hostname-exception",
        "rule_count": len(rules),
        "mapped_host_count": safe_projection["mapped_host_count"],
        "excluded_host_count": safe_projection["excluded_host_count"] + 1,
        "catch_all_not_found": True,
        "canonical_rules_sha256": hashlib.sha256(_canonical_json_bytes(rules)).hexdigest(),
    }


def browser_egress_qualification_control_chromium_args(
    *,
    launch_profile: str,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    approved_ip_exclusions: Sequence[str],
    dns_exception_hostname: str | None = None,
) -> list[str]:
    """Return an exact, visibly qualification-only Chromium control argv.

    This cannot weaken :func:`browser_egress_chromium_args`; callers must pick
    one of the four named paired-control profiles and every control is tied to
    the checked-in fixture certificate.  Only the DNS pair can request the one
    exact hostname resolver exception.
    """

    if launch_profile not in BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES:
        raise ValueError("browser egress qualification control profile is invalid")
    resolver = (
        _qualification_dns_control_resolver_argument(
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
            approved_ip_exclusions=approved_ip_exclusions,
            dns_exception_hostname=dns_exception_hostname,
        )
        if dns_exception_hostname is not None
        else build_fail_closed_host_resolver_argument(
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
            approved_ip_exclusions=approved_ip_exclusions
        )
    )
    arguments = [
        *BROWSER_EGRESS_EXPLICIT_BARE_CHROMIUM_ARGS,
        BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
        *(
            (
                BROWSER_EGRESS_REPORTING_CONTROL_FEATURE_ARGUMENT,
                BROWSER_EGRESS_REQUIRED_FEATURE_ARGUMENTS[1],
                BROWSER_EGRESS_REPORTING_CONTROL_ENABLE_ARGUMENT,
            )
            if launch_profile == BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE
            else BROWSER_EGRESS_REQUIRED_FEATURE_ARGUMENTS
        ),
        BROWSER_EGRESS_FIXTURE_CERTIFICATE_ARGUMENT,
    ]
    if launch_profile in {
        BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE,
        BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE,
    }:
        arguments.append(BROWSER_EGRESS_SHORT_REPORTING_DELAY_ARGUMENT)
    arguments.append(resolver)
    return arguments


def validate_production_browser_launch(
    browser: Any,
    *,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
) -> dict[str, object]:
    """Validate effective production argv before creating any browser context.

    The resolver comparison is call-site specific: a syntactically valid MAP
    policy for some other origin set is not admissible evidence for this
    launch.  Raw argv, hostnames, and IP addresses are discarded here.
    """

    expected_resolver = validate_fail_closed_host_resolver_argument(
        build_fail_closed_host_resolver_argument(
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
        )
    )
    try:
        session = browser.new_browser_cdp_session()
        response = session.send("Browser.getBrowserCommandLine")
    except Exception as error:  # noqa: BLE001 - browser adapter is an external boundary.
        raise ValueError("browser egress effective command line is unavailable") from error
    projection = validate_browser_egress_command_line(response)
    if projection["host_resolver_policy"] != expected_resolver:
        raise ValueError("browser egress effective resolver differs from the launch pins")
    return projection


def _launch_validated_production_browser(
    playwright: Any,
    *,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    pinned_cdp_probe: bool,
) -> tuple[Any, dict[str, object]]:
    """Own the sole ordinary full-Chromium production launch boundary."""

    from .playwright_driver import (
        chromium_child_environment,
        pinned_chromium_executable_path,
        validate_default_playwright_driver_once,
    )

    validate_default_playwright_driver_once()
    arguments = [
        *browser_egress_chromium_args(
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
        ),
        *(("--site-per-process",) if pinned_cdp_probe else ()),
    ]
    return _launch_browser_and_validate_command_line(
        playwright,
        executable_path=pinned_chromium_executable_path(),
        arguments=arguments,
        child_environment=chromium_child_environment(),
        validator=lambda browser: validate_production_browser_launch(
            browser,
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
        ),
    )


def _launch_browser_and_validate_command_line(
    playwright: Any,
    *,
    executable_path: str,
    arguments: Sequence[str],
    child_environment: Mapping[str, str],
    validator: Callable[[Any], dict[str, object]],
) -> tuple[Any, dict[str, object]]:
    """Launch once and validate effective argv before returning the browser."""

    browser = None
    try:
        browser = playwright.chromium.launch(
            headless=True,
            ignore_default_args=["--disable-popup-blocking"],
            executable_path=executable_path,
            args=list(arguments),
            env=dict(child_environment),
        )
        projection = validator(browser)
    except Exception:
        if browser is not None:
            try:
                browser.close()
            except Exception:  # noqa: BLE001 - preserve the validation failure.
                pass
        raise
    return browser, projection


def launch_qualification_browser(
    playwright: Any,
    *,
    launch_profile: str,
    expected_network_prediction_option: int,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    approved_ip_exclusions: Sequence[str],
    dns_exception_hostname: str | None = None,
) -> tuple[Any, dict[str, object], dict[str, Any]]:
    """Launch one exact local-fixture browser and validate it before any target.

    This is the only non-production launch API.  It accepts named profiles and
    an exact managed-policy value, never a generic guard-disabling boolean.
    """

    from .playwright_driver import (
        chromium_child_environment,
        pinned_chromium_executable_path,
        validate_qualification_playwright_driver_once,
    )

    if launch_profile == BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE:
        if expected_network_prediction_option != 2 or dns_exception_hostname is not None:
            raise ValueError("production-equivalent qualification launch requires policy 2")
        arguments = browser_egress_chromium_args(
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
            approved_ip_exclusions=approved_ip_exclusions,
        )
    else:
        if launch_profile in {
            BROWSER_EGRESS_NETWORK_PREDICTION_DISABLED_CONTROL_PROFILE,
            BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE,
            BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE,
        } and expected_network_prediction_option != 2:
            raise ValueError("disabled/reporting control requires policy 2")
        if (
            launch_profile == BROWSER_EGRESS_NETWORK_PREDICTION_ENABLED_CONTROL_PROFILE
            and expected_network_prediction_option != 0
        ):
            raise ValueError("network-prediction enabled control requires policy 0")
        arguments = browser_egress_qualification_control_chromium_args(
            launch_profile=launch_profile,
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
            approved_ip_exclusions=approved_ip_exclusions,
            dns_exception_hostname=dns_exception_hostname,
        )
    driver_projection = validate_qualification_playwright_driver_once(
        expected_network_prediction_option=expected_network_prediction_option
    )
    browser, command_line_projection = _launch_browser_and_validate_command_line(
        playwright,
        executable_path=pinned_chromium_executable_path(),
        arguments=arguments,
        child_environment=chromium_child_environment(),
        validator=lambda browser: _validate_qualification_browser_effective_command_line(
            browser,
            launch_profile=launch_profile,
            approved_origins=approved_origins,
            origin_ip_pins=origin_ip_pins,
            approved_ip_exclusions=approved_ip_exclusions,
            dns_exception_hostname=dns_exception_hostname,
        ),
    )
    return browser, command_line_projection, driver_projection


def _validate_qualification_browser_effective_command_line(
    browser: Any,
    *,
    launch_profile: str,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    approved_ip_exclusions: Sequence[str],
    dns_exception_hostname: str | None,
) -> dict[str, object]:
    try:
        session = browser.new_browser_cdp_session()
        response = session.send("Browser.getBrowserCommandLine")
    except Exception as error:  # noqa: BLE001 - external browser boundary.
        raise ValueError("qualification browser command line is unavailable") from error
    return validate_browser_egress_qualification_command_line(
        response,
        launch_profile=launch_profile,
        approved_origins=approved_origins,
        origin_ip_pins=origin_ip_pins,
        approved_ip_exclusions=approved_ip_exclusions,
        dns_exception_hostname=dns_exception_hostname,
    )


def launch_production_browser(
    playwright: Any,
    *,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
) -> tuple[Any, dict[str, object]]:
    """Launch and validate the public-acquisition browser before any context."""

    for origin in approved_origins:
        try:
            parsed = urlsplit(origin)
            hostname = parsed.hostname
        except (TypeError, ValueError) as error:
            raise ValueError("public browser origin is malformed") from error
        if parsed.scheme != "https" or hostname is None:
            raise ValueError("public browser origins must use HTTPS")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("public browser origins must use DNS hostnames")
    for address in origin_ip_pins.values():
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as error:
            raise ValueError("public browser origin pin is not an IP address") from error
        if parsed_address.compressed != address or not parsed_address.is_global:
            raise ValueError("public browser origin pins must be canonical global IPs")

    return _launch_validated_production_browser(
        playwright,
        approved_origins=approved_origins,
        origin_ip_pins=origin_ip_pins,
        pinned_cdp_probe=False,
    )


def launch_pinned_cdp_probe_browser(
    playwright: Any,
    *,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
) -> tuple[Any, dict[str, object]]:
    """Launch the loopback CDP probe with its sole extra isolation switch."""

    return _launch_validated_production_browser(
        playwright,
        approved_origins=approved_origins,
        origin_ip_pins=origin_ip_pins,
        pinned_cdp_probe=True,
    )


def _feature_token_arguments(
    arguments: Sequence[str], switch: str
) -> list[tuple[str, ...]]:
    prefix = f"{switch}="
    observed: list[tuple[str, ...]] = []
    for argument in arguments:
        if argument.split("=", 1)[0] != switch:
            continue
        if not argument.startswith(prefix):
            raise ValueError("browser egress feature switch has no value")
        tokens = tuple(argument[len(prefix) :].split(","))
        if (
            not tokens
            or any(
                not token
                or not token.isascii()
                or any(not (character.isalnum() or character == "_") for character in token)
                for token in tokens
            )
            or len(set(tokens)) != len(tokens)
        ):
            raise ValueError("browser egress feature token list is malformed")
        observed.append(tokens)
    return observed


def _expected_base_features_for_profile(profile: str) -> tuple[str, ...]:
    if not isinstance(profile, str):
        raise ValueError("browser egress launch profile is invalid")
    if profile in {
        BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE,
        BROWSER_EGRESS_NETWORK_PREDICTION_DISABLED_CONTROL_PROFILE,
        BROWSER_EGRESS_NETWORK_PREDICTION_ENABLED_CONTROL_PROFILE,
        BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE,
    }:
        return BROWSER_EGRESS_DISABLED_BASE_FEATURES
    if profile == BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE:
        return BROWSER_EGRESS_REPORTING_CONTROL_DISABLED_BASE_FEATURES
    raise ValueError("browser egress launch profile is invalid")


def _expected_enabled_feature_arguments_for_profile(
    profile: str,
) -> tuple[tuple[str, ...], ...]:
    _expected_base_features_for_profile(profile)
    playwright = BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES
    if profile == BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE:
        return (playwright, BROWSER_EGRESS_REPORTING_CONTROL_ENABLED_FEATURES)
    return (playwright,)


def _expected_qualification_arguments_for_profile(profile: str) -> tuple[str, ...]:
    if profile == BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE:
        return ()
    if profile not in BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES:
        raise ValueError("browser egress launch profile is invalid")
    arguments = [BROWSER_EGRESS_FIXTURE_CERTIFICATE_ARGUMENT]
    if profile in {
        BROWSER_EGRESS_REPORTING_DISABLED_CONTROL_PROFILE,
        BROWSER_EGRESS_REPORTING_ENABLED_CONTROL_PROFILE,
    }:
        arguments.append(BROWSER_EGRESS_SHORT_REPORTING_DELAY_ARGUMENT)
    return tuple(arguments)


def _validate_browser_egress_command_line(
    value: object,
    *,
    launch_profile: str,
    approved_origins: Sequence[str] | None = None,
    origin_ip_pins: Mapping[str, str] | None = None,
    approved_ip_exclusions: Sequence[str] | None = None,
    dns_exception_hostname: str | None = None,
    qualification_fixture: bool = False,
) -> dict[str, object]:
    """Validate one exact production or qualification-only Chromium profile."""

    if not isinstance(value, Mapping) or set(value) != {"arguments"}:
        raise ValueError("browser egress command-line response is malformed")
    arguments = value["arguments"]
    if (
        not isinstance(arguments, list)
        or not arguments
        or any(not isinstance(argument, str) for argument in arguments)
    ):
        raise ValueError("browser egress command-line arguments are malformed")
    from .playwright_driver import (
        DEFAULT_CONFIGURED_EXECUTABLE,
        DEFAULT_RESOLVED_EXECUTABLE,
    )

    accepted_executable_argv0 = {
        str(DEFAULT_CONFIGURED_EXECUTABLE),
        str(DEFAULT_RESOLVED_EXECUTABLE),
    }
    if arguments[0] not in accepted_executable_argv0:
        raise ValueError("browser egress executable argv[0] is not pinned")
    if any(not argument for argument in arguments[1:]):
        raise ValueError("browser egress command-line arguments are malformed")
    switch_arguments = [argument for argument in arguments if argument.startswith("--")]
    switch_names = [argument.split("=", 1)[0] for argument in switch_arguments]
    observed = {
        required for required in BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES if required in arguments
    }
    if observed != set(BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES):
        raise ValueError("browser egress command line omitted a required switch")
    if any(
        arguments.count(required) != 1
        for required in BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES
    ):
        raise ValueError("browser egress command line duplicated a required switch")
    if any(
        name in BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES and argument != name
        for argument, name in zip(switch_arguments, switch_names, strict=True)
    ):
        raise ValueError("browser egress command line used a valued required switch")
    observed_antagonistic = sorted(
        set(switch_names).intersection(BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES)
    )
    if observed_antagonistic:
        raise ValueError("browser egress command line contains an antagonistic switch")
    wrapper_arguments = [
        argument
        for argument in arguments
        if argument.split("=", 1)[0] == "--browser-subprocess-path"
    ]
    if wrapper_arguments != [BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT]:
        raise ValueError("browser egress subprocess wrapper is absent or conflicting")

    qualification_arguments = _expected_qualification_arguments_for_profile(
        launch_profile
    )
    for switch in BROWSER_EGRESS_QUALIFICATION_ONLY_SWITCHES:
        candidates = [
            argument
            for argument in arguments
            if argument.split("=", 1)[0] == switch
        ]
        expected_arguments = [
            argument
            for argument in qualification_arguments
            if argument.split("=", 1)[0] == switch
        ]
        if candidates != expected_arguments:
            raise ValueError(
                "browser egress qualification-only switch is absent or conflicting"
            )

    base_arguments = _feature_token_arguments(arguments, "--disable-features")
    blink_arguments = _feature_token_arguments(arguments, "--disable-blink-features")
    required_base = frozenset(_expected_base_features_for_profile(launch_profile))
    required_blink = frozenset(BROWSER_EGRESS_DISABLED_BLINK_FEATURES)
    playwright_base = frozenset(BROWSER_EGRESS_PLAYWRIGHT_DISABLED_FEATURES)
    if (
        len(base_arguments) != 2
        or frozenset(base_arguments[0]) != playwright_base
        or frozenset(base_arguments[-1]) != required_base
        or len(blink_arguments) != 1
        or frozenset(blink_arguments[0]) != required_blink
    ):
        raise ValueError("browser egress disabled-feature policy is incomplete or conflicting")
    enabled_arguments = _feature_token_arguments(arguments, "--enable-features")
    expected_enabled_arguments = _expected_enabled_feature_arguments_for_profile(
        launch_profile
    )
    if tuple(enabled_arguments) != expected_enabled_arguments:
        raise ValueError("browser egress enabled-feature policy is incomplete or conflicting")
    enabled_tokens = {token for item in enabled_arguments for token in item}
    if enabled_tokens.intersection(required_base | required_blink):
        raise ValueError("browser egress command line re-enabled a disabled feature")
    enabled_blink_arguments = _feature_token_arguments(
        arguments, "--enable-blink-features"
    )
    enabled_blink_tokens = {
        token for item in enabled_blink_arguments for token in item
    }
    if enabled_blink_tokens.intersection(required_blink):
        raise ValueError("browser egress command line re-enabled a disabled Blink feature")
    if enabled_blink_arguments:
        raise ValueError("browser egress command line contains enabled Blink features")
    resolver_arguments = [
        argument for argument in arguments if argument.split("=", 1)[0] == HOST_RESOLVER_SWITCH
    ]
    if len(resolver_arguments) != 1:
        raise ValueError("browser egress command line must contain one host-resolver policy")
    if launch_profile == BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE and not qualification_fixture:
        if (
            approved_origins is not None
            or origin_ip_pins is not None
            or approved_ip_exclusions is not None
            or dns_exception_hostname is not None
        ):
            raise ValueError("production launch cannot select qualification resolver inputs")
        host_resolver_policy = validate_fail_closed_host_resolver_argument(
            resolver_arguments[0]
        )
    else:
        if (
            approved_origins is None
            or origin_ip_pins is None
            or approved_ip_exclusions is None
        ):
            raise ValueError("qualification launch requires exact resolver inputs")
        if dns_exception_hostname is None:
            expected_resolver = build_fail_closed_host_resolver_argument(
                approved_origins=approved_origins,
                origin_ip_pins=origin_ip_pins,
                approved_ip_exclusions=approved_ip_exclusions
            )
            if resolver_arguments[0] != expected_resolver:
                raise ValueError(
                    "qualification resolver policy differs from its exact fixture topology"
                )
            host_resolver_policy = validate_fail_closed_host_resolver_argument(
                resolver_arguments[0]
            )
        else:
            host_resolver_policy = _validate_qualification_dns_control_resolver_argument(
                resolver_arguments[0],
                approved_origins=approved_origins,
                origin_ip_pins=origin_ip_pins,
                approved_ip_exclusions=approved_ip_exclusions,
                dns_exception_hostname=dns_exception_hostname,
            )
    projection = {
        "schema_version": BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION,
        "launch_profile": launch_profile,
        "required_switches": list(BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES),
        "observed_required_switches": sorted(observed),
        "antagonistic_switches": list(BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES),
        "observed_antagonistic_switches": observed_antagonistic,
        "required_disabled_feature_tokens": sorted(required_base),
        "observed_disabled_feature_tokens": sorted(
            {token for item in base_arguments for token in item}
        ),
        "required_disabled_blink_feature_tokens": sorted(required_blink),
        "observed_disabled_blink_feature_tokens": sorted(
            {token for item in blink_arguments for token in item}
        ),
        "required_enabled_feature_arguments": [
            list(tokens) for tokens in expected_enabled_arguments
        ],
        "observed_enabled_feature_arguments": [
            list(tokens) for tokens in enabled_arguments
        ],
        "feature_switch_argument_counts": {
            "disable_features": len(base_arguments),
            "disable_blink_features": len(blink_arguments),
            "enable_features": len(enabled_arguments),
            "enable_blink_features": len(enabled_blink_arguments),
        },
        "complete_feature_policy_is_last": True,
        "subprocess_wrapper_argument": BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
        "required_switches_are_bare_and_unique": True,
        "host_resolver_switch_is_unique": True,
        "host_resolver_is_fail_closed": True,
        "host_resolver_policy": host_resolver_policy,
        "no_pings_is_admission_boundary": False,
        "packet_level_completeness_claimed": False,
    }
    return validate_browser_egress_command_line_projection(projection)


def validate_browser_egress_command_line(value: object) -> dict[str, object]:
    """Validate the unconditional, fail-closed production launch profile."""

    return _validate_browser_egress_command_line(
        value, launch_profile=BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE
    )


def validate_browser_egress_qualification_control_command_line(
    value: object,
    *,
    launch_profile: str,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    approved_ip_exclusions: Sequence[str],
    dns_exception_hostname: str | None = None,
) -> dict[str, object]:
    """Validate one narrowly named, non-production eligibility-control launch."""

    if launch_profile not in BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES:
        raise ValueError("browser egress qualification control profile is invalid")
    return _validate_browser_egress_command_line(
        value,
        launch_profile=launch_profile,
        approved_origins=approved_origins,
        origin_ip_pins=origin_ip_pins,
        approved_ip_exclusions=approved_ip_exclusions,
        dns_exception_hostname=dns_exception_hostname,
        qualification_fixture=True,
    )


def validate_browser_egress_qualification_command_line(
    value: object,
    *,
    launch_profile: str,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    approved_ip_exclusions: Sequence[str],
    dns_exception_hostname: str | None = None,
) -> dict[str, object]:
    """Validate the exact local-fixture projection for any frozen vector."""

    if launch_profile not in {
        BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE,
        *BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES,
    }:
        raise ValueError("browser egress qualification launch profile is invalid")
    if (
        launch_profile == BROWSER_EGRESS_PRODUCTION_LAUNCH_PROFILE
        and dns_exception_hostname is not None
    ):
        raise ValueError("production-equivalent fixture profile cannot permit DNS")
    return _validate_browser_egress_command_line(
        value,
        launch_profile=launch_profile,
        approved_origins=approved_origins,
        origin_ip_pins=origin_ip_pins,
        approved_ip_exclusions=approved_ip_exclusions,
        dns_exception_hostname=dns_exception_hostname,
        qualification_fixture=True,
    )


def validate_browser_egress_command_line_projection(
    value: object,
) -> dict[str, object]:
    """Offline-validate the immutable, argument-content-minimised receipt."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "launch_profile",
        "required_switches",
        "observed_required_switches",
        "antagonistic_switches",
        "observed_antagonistic_switches",
        "required_disabled_feature_tokens",
        "observed_disabled_feature_tokens",
        "required_disabled_blink_feature_tokens",
        "observed_disabled_blink_feature_tokens",
        "required_enabled_feature_arguments",
        "observed_enabled_feature_arguments",
        "feature_switch_argument_counts",
        "complete_feature_policy_is_last",
        "subprocess_wrapper_argument",
        "required_switches_are_bare_and_unique",
        "host_resolver_switch_is_unique",
        "host_resolver_is_fail_closed",
        "host_resolver_policy",
        "no_pings_is_admission_boundary",
        "packet_level_completeness_claimed",
    }:
        raise ValueError("browser egress command-line projection fields are invalid")
    profile = value["launch_profile"]
    required_base = sorted(_expected_base_features_for_profile(profile))
    required_enabled = [
        list(tokens)
        for tokens in _expected_enabled_feature_arguments_for_profile(profile)
    ]
    expected = list(BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION
        or value["required_switches"] != expected
        or value["observed_required_switches"] != expected
        or value["antagonistic_switches"]
        != list(BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES)
        or value["observed_antagonistic_switches"] != []
        or value["required_disabled_feature_tokens"] != required_base
        or value["observed_disabled_feature_tokens"] != required_base
        or value["required_disabled_blink_feature_tokens"]
        != sorted(BROWSER_EGRESS_DISABLED_BLINK_FEATURES)
        or value["observed_disabled_blink_feature_tokens"]
        != sorted(BROWSER_EGRESS_DISABLED_BLINK_FEATURES)
        or value["required_enabled_feature_arguments"] != required_enabled
        or value["observed_enabled_feature_arguments"] != required_enabled
        or value["feature_switch_argument_counts"]
        != {
            "disable_features": 2,
            "disable_blink_features": 1,
            "enable_features": len(required_enabled),
            "enable_blink_features": 0,
        }
        or value["complete_feature_policy_is_last"] is not True
        or value["subprocess_wrapper_argument"]
        != BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT
        or value["required_switches_are_bare_and_unique"] is not True
        or value["host_resolver_switch_is_unique"] is not True
        or value["host_resolver_is_fail_closed"] is not True
        or value["no_pings_is_admission_boundary"] is not False
        or value["packet_level_completeness_claimed"] is not False
    ):
        raise ValueError("browser egress command-line projection is invalid")
    policy = value["host_resolver_policy"]
    if not isinstance(policy, Mapping) or set(policy) != {
        "schema_version",
        "mode",
        "rule_count",
        "mapped_host_count",
        "excluded_host_count",
        "catch_all_not_found",
        "canonical_rules_sha256",
    }:
        raise ValueError("browser egress host-resolver projection is invalid")
    digest = policy["canonical_rules_sha256"]
    permitted_policy_modes = {"approved-map-or-exclude-then-not-found"}
    if profile in BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES:
        permitted_policy_modes.add("qualification-single-dns-hostname-exception")
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != HOST_RESOLVER_POLICY_SCHEMA_VERSION
        or policy["mode"] not in permitted_policy_modes
        or type(policy["rule_count"]) is not int
        or type(policy["mapped_host_count"]) is not int
        or type(policy["excluded_host_count"]) is not int
        or policy["mapped_host_count"] < 0
        or policy["excluded_host_count"] < 0
        or policy["rule_count"]
        != policy["mapped_host_count"] + policy["excluded_host_count"] + 1
        or policy["rule_count"] < 2
        or policy["catch_all_not_found"] is not True
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("browser egress host-resolver projection is invalid")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _source_projection(source: object | None) -> dict[str, object] | None:
    if source is None:
        return None
    target_type = getattr(source, "target_type", None)
    generation = getattr(source, "generation", None)
    if not isinstance(target_type, str) or not target_type or type(generation) is not int:
        raise ValueError("non-replayable egress source is malformed")
    return {"target_type": target_type, "generation": generation}


def _url_projection(value: object | None) -> dict[str, str] | None:
    """Retain only scheme and origin; paths, queries, credentials, and payloads are forbidden."""

    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("non-replayable egress URL is malformed")
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise ValueError("non-replayable egress URL is malformed") from error
    if not scheme:
        return {"scheme": "unknown", "origin": "unknown"}
    if hostname is None:
        return {"scheme": scheme, "origin": f"{scheme}:"}
    default = 443 if scheme in {"https", "wss"} else 80 if scheme in {"http", "ws"} else None
    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = host if port is None or port == default else f"{host}:{port}"
    return {"scheme": scheme, "origin": f"{scheme}://{authority}"}


def target_egress_apis(target_type: str) -> tuple[str, ...]:
    if target_type in {"worker", "shared_worker"}:
        return WORKER_TARGET_EGRESS_APIS
    if target_type in {"page", "iframe"}:
        return PAGE_TARGET_EGRESS_APIS
    raise ValueError(f"unsupported target type for egress shim: {target_type}")


def target_egress_shim_source(target_type: str) -> str:
    """Return the deterministic constructor guard for one paused target type."""

    apis = json.dumps(target_egress_apis(target_type), separators=(",", ":"))
    binding = json.dumps(TARGET_EGRESS_BINDING)
    policy = json.dumps(NON_REPLAYABLE_EGRESS_POLICY)
    return f"""
(() => {{
  const schemaVersion = {TARGET_EGRESS_SHIM_SCHEMA_VERSION};
  const policy = {policy};
  const bindingName = {binding};
  const apiNames = {apis};
  const markerName = '__qcsd_non_replayable_egress_shim_v1__';
  const previous = globalThis[markerName];
  if (previous !== undefined)
    return {{...previous, already_installed: true}};
  const protectedApis = [];
  const unavailableApis = [];
  const failedApis = [];
  const proxies = new Map();
  const reportAndThrow = api => {{
    const report = globalThis[bindingName];
    if (typeof report === 'function')
      report(JSON.stringify({{schema_version: schemaVersion, policy, kind: 'attempt', api}}));
    throw new TypeError('QCSD blocked non-replayable browser egress: ' + api);
  }};
  for (const api of apiNames) {{
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, api);
    let nativeConstructor;
    try {{
      nativeConstructor = Reflect.get(globalThis, api);
    }} catch (_) {{
      failedApis.push(api);
      continue;
    }}
    // Accessor-backed and inherited constructors are live egress surfaces too.
    // "Unavailable" means the actual resolved global value is non-callable.
    if (typeof nativeConstructor !== 'function') {{
      unavailableApis.push(api);
      continue;
    }}
    let blocked = proxies.get(nativeConstructor);
    if (blocked === undefined) {{
      // Legacy aliases can name one native constructor.  The shared proxy
      // reports the first API in the frozen list as that family's canonical name.
      const canonicalApi = api;
      blocked = new Proxy(nativeConstructor, {{
        apply() {{ return reportAndThrow(canonicalApi); }},
        construct() {{ return reportAndThrow(canonicalApi); }},
      }});
      proxies.set(nativeConstructor, blocked);
      const prototype = nativeConstructor.prototype;
      if (prototype && (typeof prototype === 'object' || typeof prototype === 'function')) {{
        const constructorDescriptor = Object.getOwnPropertyDescriptor(prototype, 'constructor');
        if (constructorDescriptor && (constructorDescriptor.configurable || constructorDescriptor.writable)) {{
          try {{
            Object.defineProperty(prototype, 'constructor', {{value: blocked, configurable: false, enumerable: false, writable: false}});
          }} catch (_) {{
            failedApis.push(api);
            continue;
          }}
        }} else if (constructorDescriptor && constructorDescriptor.value !== blocked) {{
          failedApis.push(api);
          continue;
        }}
      }}
    }}
    try {{
      Object.defineProperty(globalThis, api, {{value: blocked, configurable: false, enumerable: descriptor ? descriptor.enumerable : false, writable: false}});
      protectedApis.push(api);
    }} catch (_) {{
      failedApis.push(api);
    }}
  }}
  protectedApis.sort();
  unavailableApis.sort();
  failedApis.sort();
  const receipt = {{schema_version: schemaVersion, policy, protected_apis: protectedApis, unavailable_apis: unavailableApis, failed_apis: failedApis, already_installed: false}};
  Object.defineProperty(globalThis, markerName, {{value: Object.freeze(receipt), configurable: false, enumerable: false, writable: false}});
  return receipt;
}})()
""".strip()


def popup_navigation_guard_source() -> str:
    """Return the pre-author guard for script-created browsing contexts."""

    binding = json.dumps(TARGET_EGRESS_BINDING)
    policy = json.dumps(NON_REPLAYABLE_EGRESS_POLICY)
    api = json.dumps(POPUP_NAVIGATION_API)
    return f"""
(() => {{
  const markerName = {json.dumps(POPUP_GUARD_MARKER)};
  if (globalThis[markerName] === true)
    return true;
  const bindingName = {binding};
  const policy = {policy};
  const api = {api};
  const Anchor = globalThis.HTMLAnchorElement;
  const Area = globalThis.HTMLAreaElement;
  const SvgAnchor = globalThis.SVGAElement;
  const Form = globalThis.HTMLFormElement;
  const Button = globalThis.HTMLButtonElement;
  const Input = globalThis.HTMLInputElement;
  const nativeGetAttribute = Element.prototype.getAttribute;
  const nativeQuerySelector = Document.prototype.querySelector;
  const nativeQuerySelectorAll = Document.prototype.querySelectorAll;
  const nativeComposedPath = Event.prototype.composedPath;
  const report = () => {{
    const binding = globalThis[bindingName];
    if (typeof binding === 'function')
      binding(JSON.stringify({{schema_version: {TARGET_EGRESS_SHIM_SCHEMA_VERSION}, policy, kind: 'attempt', api}}));
  }};
  const namedContextExists = (rawTarget, emptyIsSelf) => {{
    const target = String(rawTarget || '').trim();
    if (target === '')
      return emptyIsSelf;
    if (/^_(self|top|parent)$/i.test(target))
      return true;
    if (/^_blank$/i.test(target))
      return false;
    // Do not index Window by attacker-controlled name: ordinary properties
    // such as "location" and "length" are not browsing-context evidence.
    if (globalThis.name === target)
      return true;
    const frames = Reflect.apply(nativeQuerySelectorAll, document, ['iframe[name],frame[name]']);
    for (const frame of frames) {{
      if (Reflect.apply(nativeGetAttribute, frame, ['name']) === target)
        return true;
    }}
    return false;
  }};
  const reject = () => {{
    report();
    throw new TypeError('QCSD blocked popup navigation');
  }};
  const nativeOpen = globalThis.open;
  if (typeof nativeOpen !== 'function')
    throw new TypeError('QCSD popup guard cannot resolve window.open');
  const blockedOpen = new Proxy(nativeOpen, {{
    apply(target, thisArg, argumentsList) {{
      if (!namedContextExists(argumentsList[1], false)) return reject();
      return Reflect.apply(target, thisArg, argumentsList);
    }},
    construct(target, argumentsList, newTarget) {{
      if (!namedContextExists(argumentsList[1], false)) return reject();
      return Reflect.construct(target, argumentsList, newTarget);
    }},
  }});
  Object.defineProperty(globalThis, 'open', {{value: blockedOpen, configurable: false, enumerable: true, writable: false}});
  const prototypeOpen = Object.getOwnPropertyDescriptor(Window.prototype, 'open');
  if (prototypeOpen && typeof prototypeOpen.value === 'function') {{
    Object.defineProperty(Window.prototype, 'open', {{
      value: blockedOpen, configurable: false, enumerable: prototypeOpen.enumerable, writable: false,
    }});
  }}

  const nativePreventDefault = Event.prototype.preventDefault;
  const nativeStopImmediatePropagation = Event.prototype.stopImmediatePropagation;
  const effectiveTarget = (element, submitter = null) => {{
    if (submitter !== null) {{
      const override = Reflect.apply(nativeGetAttribute, submitter, ['formtarget']);
      if (override !== null) return override;
    }}
    const own = Reflect.apply(nativeGetAttribute, element, ['target']);
    if (own !== null) return own;
    const base = Reflect.apply(nativeQuerySelector, document, ['base[target]']);
    return base === null ? '' : Reflect.apply(nativeGetAttribute, base, ['target']);
  }};
  const popupTargetForElement = (element, submitter = null) => {{
    if ((typeof Anchor === 'function' && element instanceof Anchor) ||
        (typeof Area === 'function' && element instanceof Area) ||
        (typeof SvgAnchor === 'function' && element instanceof SvgAnchor))
      return effectiveTarget(element);
    if (typeof Form === 'function' && element instanceof Form)
      return effectiveTarget(element, submitter);
    if (((typeof Button === 'function' && element instanceof Button) ||
         (typeof Input === 'function' && element instanceof Input)) && element.form)
      return effectiveTarget(element.form, element);
    return null;
  }};
  const cancelPopupDefault = event => {{
    const path = typeof nativeComposedPath === 'function'
      ? Reflect.apply(nativeComposedPath, event, []) : [];
    const element = path.find(item => popupTargetForElement(item) !== null);
    const submitter = event.type === 'submit' ? event.submitter : null;
    const target = element ? popupTargetForElement(element, submitter) : null;
    if (target !== null && !namedContextExists(target, true)) {{
      Reflect.apply(nativePreventDefault, event, []);
      Reflect.apply(nativeStopImmediatePropagation, event, []);
      report();
    }}
  }};
  document.addEventListener('click', cancelPopupDefault, true);
  document.addEventListener('auxclick', cancelPopupDefault, true);
  document.addEventListener('submit', cancelPopupDefault, true);

  const nativeClickDescriptor = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'click');
  if (!nativeClickDescriptor || typeof nativeClickDescriptor.value !== 'function')
    throw new TypeError('QCSD popup guard cannot resolve element activation');
  const blockedClick = new Proxy(nativeClickDescriptor.value, {{
    apply(target, thisArg, argumentsList) {{
      const popupTarget = popupTargetForElement(thisArg);
      if (popupTarget !== null && !namedContextExists(popupTarget, true)) return reject();
      return Reflect.apply(target, thisArg, argumentsList);
    }},
  }});
  Object.defineProperty(HTMLElement.prototype, 'click', {{
    value: blockedClick, configurable: false, enumerable: nativeClickDescriptor.enumerable, writable: false,
  }});

  const dispatchDescriptor = Object.getOwnPropertyDescriptor(EventTarget.prototype, 'dispatchEvent');
  if (!dispatchDescriptor || typeof dispatchDescriptor.value !== 'function')
    throw new TypeError('QCSD popup guard cannot resolve event dispatch');
  const blockedDispatch = new Proxy(dispatchDescriptor.value, {{
    apply(target, thisArg, argumentsList) {{
      const event = argumentsList[0];
      const popupTarget = popupTargetForElement(thisArg);
      if (event && ['click', 'auxclick', 'submit'].includes(event.type) &&
          popupTarget !== null && !namedContextExists(popupTarget, true)) return reject();
      return Reflect.apply(target, thisArg, argumentsList);
    }},
  }});
  Object.defineProperty(EventTarget.prototype, 'dispatchEvent', {{
    value: blockedDispatch, configurable: false, enumerable: dispatchDescriptor.enumerable, writable: false,
  }});

  for (const methodName of ['submit', 'requestSubmit']) {{
    const descriptor = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, methodName);
    if (!descriptor || typeof descriptor.value !== 'function')
      throw new TypeError('QCSD popup guard cannot resolve form navigation');
    const nativeMethod = descriptor.value;
    const blockedMethod = new Proxy(nativeMethod, {{
      apply(target, thisArg, argumentsList) {{
        const submitter = methodName === 'requestSubmit' ? argumentsList[0] : null;
        if (thisArg instanceof Form &&
            !namedContextExists(effectiveTarget(thisArg, submitter), true))
          return reject();
        return Reflect.apply(target, thisArg, argumentsList);
      }},
    }});
    Object.defineProperty(HTMLFormElement.prototype, methodName, {{
      value: blockedMethod, configurable: false, enumerable: descriptor.enumerable, writable: false,
    }});
  }}
  Object.defineProperty(globalThis, markerName, {{value: true, configurable: false, enumerable: false, writable: false}});
  return true;
}})()
""".strip()


def context_page_egress_init_source() -> str:
    """One deterministically ordered context script for constructors and popups."""

    return target_egress_shim_source("page") + ";\n" + popup_navigation_guard_source()


def validate_target_egress_shim_result(value: object, *, target_type: str) -> dict[str, Any]:
    """Validate the by-value result of the paused-target Runtime evaluation."""

    fields = {
        "schema_version",
        "policy",
        "protected_apis",
        "unavailable_apis",
        "failed_apis",
        "already_installed",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("target egress shim result fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != TARGET_EGRESS_SHIM_SCHEMA_VERSION
        or value["policy"] != NON_REPLAYABLE_EGRESS_POLICY
        or type(value["already_installed"]) is not bool
    ):
        raise ValueError("target egress shim identity is invalid")
    sequences: dict[str, list[str]] = {}
    for field in ("protected_apis", "unavailable_apis", "failed_apis"):
        items = value[field]
        if (
            not isinstance(items, list)
            or any(not isinstance(item, str) or not item for item in items)
            or items != sorted(set(items))
        ):
            raise ValueError("target egress shim API inventory is invalid")
        sequences[field] = list(items)
    expected = set(target_egress_apis(target_type))
    observed = set().union(*(set(items) for items in sequences.values()))
    if observed != expected or sum(len(items) for items in sequences.values()) != len(expected):
        raise ValueError("target egress shim API inventory is incomplete or overlapping")
    if sequences["failed_apis"]:
        raise ValueError("target egress shim could not protect every available API")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


TARGET_EGRESS_SHIM_SHA256 = {
    target_type: hashlib.sha256(target_egress_shim_source(target_type).encode()).hexdigest()
    for target_type in ("page", "iframe", "worker", "shared_worker")
}

NON_REPLAYABLE_EGRESS_CONTRACT: dict[str, object] = {
    "schema_version": 2,
    "policy": NON_REPLAYABLE_EGRESS_POLICY,
    "target_shim_schema_version": TARGET_EGRESS_SHIM_SCHEMA_VERSION,
    "target_shim_sha256": dict(TARGET_EGRESS_SHIM_SHA256),
    "popup_navigation_guard_sha256": hashlib.sha256(
        popup_navigation_guard_source().encode()
    ).hexdigest(),
    "context_page_init_sha256": hashlib.sha256(
        context_page_egress_init_source().encode()
    ).hexdigest(),
    "context_init_target_type": "page",
    "chromium_popup_blocking": "default-enabled",
    "popup_urlloader_boundary": (
        "playwright-browser-context-navigation-route-before-first-page-bound-to-root-page"
    ),
    "browser_popup_tab_tripwire_is_pre_io": False,
    "required_chromium_switches": list(BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES),
    "no_pings_is_admission_boundary": False,
    "fresh_image_kernel_counter_qualification_required": True,
    "page_frame_websocket_boundary": "playwright-browser-context-route-before-first-page",
    "worker_websocket_boundary": "paused-target-runtime-shim",
    "service_worker_policy": "browser-context-block-plus-browser-target-tripwire",
    "cdp_tripwires_are_pre_io": False,
    "packet_level_completeness_claimed": False,
}


class NonReplayableEgressGuard:
    """Collect the first content-minimised egress violation and raise it in-band."""

    def __init__(self) -> None:
        self._started_ns = time.monotonic_ns()
        self._attempts: list[dict[str, object]] = []
        self._context_init_script_installed = False
        self._context_navigation_route_installed = False
        self._context_websocket_route_installed = False
        self._context_service_worker_listener_installed = False
        self._root_page: object | None = None
        self._lock = Lock()

    def mark_context_guards_installed(self) -> None:
        """Receipt all four context hooks after every registration call returns."""

        with self._lock:
            if (
                self._context_init_script_installed
                or self._context_navigation_route_installed
                or self._context_websocket_route_installed
                or self._context_service_worker_listener_installed
            ):
                raise ValueError("browser context egress guards were installed more than once")
            self._context_init_script_installed = True
            self._context_navigation_route_installed = True
            self._context_websocket_route_installed = True
            self._context_service_worker_listener_installed = True

    def bind_root_page(self, page: object) -> None:
        """Authorise exactly one Playwright Page for URLLoader navigations."""

        if page is None:
            raise ValueError("browser context egress root page is malformed")
        with self._lock:
            if not self._context_navigation_route_installed:
                raise ValueError("browser context navigation route was not installed")
            if self._root_page is not None:
                raise ValueError("browser context egress root page was bound more than once")
            self._root_page = page

    def is_root_page(self, page: object | None) -> bool:
        with self._lock:
            return self._root_page is not None and page is self._root_page

    def record(
        self,
        *,
        api: str,
        mechanism: str,
        source: object | None = None,
        url: object | None = None,
    ) -> None:
        if not isinstance(api, str) or not api:
            raise ValueError("non-replayable egress API is malformed")
        if mechanism not in _MECHANISMS:
            raise ValueError("non-replayable egress mechanism is invalid")
        attempt = {
            "sequence": 0,
            "monotonic_ms": max(0, (time.monotonic_ns() - self._started_ns) // 1_000_000),
            "api": api,
            "mechanism": mechanism,
            "source": _source_projection(source),
            "url": _url_projection(url),
        }
        with self._lock:
            attempt["sequence"] = len(self._attempts)
            self._attempts.append(attempt)

    @property
    def attempt_count(self) -> int:
        with self._lock:
            return len(self._attempts)

    def success_summary(self) -> dict[str, object]:
        with self._lock:
            has_attempts = bool(self._attempts)
            if not (
                self._context_init_script_installed
                and self._context_navigation_route_installed
                and self._context_websocket_route_installed
                and self._context_service_worker_listener_installed
                and self._root_page is not None
            ):
                raise ValueError("browser context egress guards were not completely installed")
        if has_attempts:
            # Preserve the typed, content-minimised policy evidence even when
            # the attempt arrives after an earlier provisional success check.
            self.raise_if_failed()
            raise AssertionError("non-replayable egress failure was not raised")
        return {
            "schema_version": NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
            "policy": NON_REPLAYABLE_EGRESS_POLICY,
            "attempt_count": 0,
            "protected_apis": list(TARGET_EGRESS_APIS),
            "context_init_script_installed": True,
            "context_navigation_route_installed": True,
            "root_page_bound": True,
            "context_websocket_route_installed": True,
            "context_service_worker_listener_installed": True,
            "cdp_tripwires_are_pre_io": False,
            "packet_level_completeness_claimed": False,
        }

    def raise_if_failed(self) -> None:
        with self._lock:
            if not self._attempts:
                return
            attempts = json.loads(json.dumps(self._attempts, sort_keys=True, separators=(",", ":")))
            init_script_installed = self._context_init_script_installed
            navigation_route_installed = self._context_navigation_route_installed
            root_page_bound = self._root_page is not None
            websocket_route_installed = self._context_websocket_route_installed
            service_worker_listener_installed = self._context_service_worker_listener_installed
        by_api = Counter(str(item["api"]) for item in attempts)
        receipt: dict[str, object] = {
            "schema_version": NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
            "policy": NON_REPLAYABLE_EGRESS_POLICY,
            "attempt_count": len(attempts),
            "by_api": {api: by_api[api] for api in sorted(by_api)},
            "attempts": attempts,
            "context_init_script_installed": init_script_installed,
            "context_navigation_route_installed": navigation_route_installed,
            "root_page_bound": root_page_bound,
            "context_websocket_route_installed": websocket_route_installed,
            "context_service_worker_listener_installed": service_worker_listener_installed,
            "cdp_tripwires_are_pre_io": False,
            "packet_level_completeness_claimed": False,
        }
        digest = hashlib.sha256(_canonical_json_bytes(receipt)).hexdigest()
        raise NonReplayableEgressPolicyError(
            "browser content attempted non-replayable network egress",
            evidence={
                "non_replayable_egress": receipt,
                "non_replayable_egress_sha256": digest,
            },
        )


def validate_non_replayable_egress_success_summary(value: object) -> dict[str, Any]:
    fields = {
        "schema_version",
        "policy",
        "attempt_count",
        "protected_apis",
        "context_init_script_installed",
        "context_navigation_route_installed",
        "root_page_bound",
        "context_websocket_route_installed",
        "context_service_worker_listener_installed",
        "cdp_tripwires_are_pre_io",
        "packet_level_completeness_claimed",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("non-replayable egress success fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != NON_REPLAYABLE_EGRESS_SCHEMA_VERSION
        or value["policy"] != NON_REPLAYABLE_EGRESS_POLICY
        or type(value["attempt_count"]) is not int
        or value["attempt_count"] != 0
        or value["context_init_script_installed"] is not True
        or value["context_navigation_route_installed"] is not True
        or value["root_page_bound"] is not True
        or value["context_websocket_route_installed"] is not True
        or value["context_service_worker_listener_installed"] is not True
        or value["cdp_tripwires_are_pre_io"] is not False
        or value["packet_level_completeness_claimed"] is not False
    ):
        raise ValueError("non-replayable egress success identity is invalid")
    apis = value["protected_apis"]
    if not isinstance(apis, list) or apis != list(TARGET_EGRESS_APIS):
        raise ValueError("non-replayable egress protected API inventory is invalid")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def validate_non_replayable_egress_failure_evidence(value: object) -> dict[str, Any]:
    """Validate and copy the only non-URLLoader evidence allowed in a ledger."""

    if not isinstance(value, Mapping) or set(value) != {
        "non_replayable_egress",
        "non_replayable_egress_sha256",
    }:
        raise ValueError("non-replayable egress failure evidence fields are invalid")
    receipt = value["non_replayable_egress"]
    fields = {
        "schema_version",
        "policy",
        "attempt_count",
        "by_api",
        "attempts",
        "context_init_script_installed",
        "context_navigation_route_installed",
        "root_page_bound",
        "context_websocket_route_installed",
        "context_service_worker_listener_installed",
        "cdp_tripwires_are_pre_io",
        "packet_level_completeness_claimed",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != fields:
        raise ValueError("non-replayable egress failure receipt fields are invalid")
    attempt_count = receipt["attempt_count"]
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != NON_REPLAYABLE_EGRESS_SCHEMA_VERSION
        or receipt["policy"] != NON_REPLAYABLE_EGRESS_POLICY
        or type(attempt_count) is not int
        or attempt_count < 1
        or receipt["context_init_script_installed"] is not True
        or receipt["context_navigation_route_installed"] is not True
        or receipt["root_page_bound"] is not True
        or receipt["context_websocket_route_installed"] is not True
        or receipt["context_service_worker_listener_installed"] is not True
        or receipt["cdp_tripwires_are_pre_io"] is not False
        or receipt["packet_level_completeness_claimed"] is not False
    ):
        raise ValueError("non-replayable egress failure receipt identity is invalid")
    by_api = receipt["by_api"]
    if (
        not isinstance(by_api, Mapping)
        or not by_api
        or any(
            not isinstance(api, str)
            or not api
            or type(count) is not int
            or count < 1
            for api, count in by_api.items()
        )
        or list(by_api) != sorted(by_api)
        or sum(by_api.values()) != attempt_count
    ):
        raise ValueError("non-replayable egress failure API counts are invalid")
    attempts = receipt["attempts"]
    if not isinstance(attempts, list) or len(attempts) != attempt_count:
        raise ValueError("non-replayable egress failure attempt ledger is invalid")
    observed = Counter()

    def projected_url_is_canonical(
        projected: object,
        *,
        schemes: frozenset[str] | None,
        required: bool,
    ) -> bool:
        if projected is None:
            return not required
        if (
            not isinstance(projected, Mapping)
            or set(projected) != {"scheme", "origin"}
            or not isinstance(projected.get("scheme"), str)
            or not projected["scheme"]
            or projected["scheme"] == "unknown"
            or schemes is not None
            and projected["scheme"] not in schemes
            or not isinstance(projected.get("origin"), str)
        ):
            return False
        try:
            return _url_projection(projected["origin"]) == dict(projected)
        except ValueError:
            return False

    for sequence, attempt in enumerate(attempts):
        if not isinstance(attempt, Mapping) or set(attempt) != {
            "sequence",
            "monotonic_ms",
            "api",
            "mechanism",
            "source",
            "url",
        }:
            raise ValueError("non-replayable egress failure attempt is malformed")
        api = attempt["api"]
        source = attempt["source"]
        url = attempt["url"]
        if (
            type(attempt["sequence"]) is not int
            or attempt["sequence"] != sequence
            or type(attempt["monotonic_ms"]) is not int
            or attempt["monotonic_ms"] < 0
            or not isinstance(api, str)
            or not api
            or attempt["mechanism"] not in _MECHANISMS
        ):
            raise ValueError("non-replayable egress failure attempt is malformed")
        if source is not None and (
            not isinstance(source, Mapping)
            or set(source) != {"target_type", "generation"}
            or source["target_type"] not in {"page", "iframe", "worker", "shared_worker"}
            or type(source["generation"]) is not int
            or source["generation"] < 0
        ):
            raise ValueError("non-replayable egress failure source is malformed")
        mechanism = attempt["mechanism"]
        if mechanism == "playwright-websocket-route":
            valid_semantics = (
                api == "WebSocket"
                and source is None
                and projected_url_is_canonical(
                    url, schemes=frozenset({"ws", "wss"}), required=True
                )
            )
        elif mechanism == "paused-target-runtime-shim":
            reportable = (
                set(target_egress_apis(source["target_type"]))
                if isinstance(source, Mapping)
                and source.get("target_type")
                in {"page", "iframe", "worker", "shared_worker"}
                else set()
            )
            valid_semantics = source is not None and api in reportable and url is None
        elif mechanism == "context-init-popup-guard":
            valid_semantics = (
                isinstance(source, Mapping)
                and source.get("target_type") in {"page", "iframe"}
                and api == POPUP_NAVIGATION_API
                and url is None
            )
        elif mechanism == "browser-popup-tab-tripwire":
            valid_semantics = (
                source is None
                and api == POPUP_NAVIGATION_API
                and projected_url_is_canonical(
                    # A newly created tab is a forbidden sibling even when its
                    # initial target is about:, data:, blob:, or another
                    # non-network scheme.  Chromium may expose that scheme in
                    # attachedToTarget; retaining only its canonical scheme/
                    # origin projection keeps the typed failure verifiable.
                    url, schemes=None, required=False
                )
            )
        elif mechanism == "playwright-popup-navigation-route":
            valid_semantics = (
                source is None
                and api == POPUP_NAVIGATION_API
                and projected_url_is_canonical(
                    url, schemes=frozenset({"http", "https"}), required=True
                )
            )
        elif mechanism == "cdp-network-tripwire":
            scheme_by_api = {
                "WebSocket": frozenset({"ws", "wss"}),
                "WebTransport": frozenset({"https"}),
                "TCPSocket": frozenset({"tcp"}),
                "UDPSocket": frozenset({"udp"}),
            }
            valid_semantics = (
                source is not None
                and api in scheme_by_api
                and projected_url_is_canonical(
                    url, schemes=scheme_by_api.get(api, frozenset()), required=False
                )
            )
        else:
            valid_semantics = (
                mechanism == "browser-service-worker-tripwire"
                and api == "ServiceWorker"
                and source is None
                and projected_url_is_canonical(
                    url, schemes=frozenset({"http", "https"}), required=False
                )
            )
        if not valid_semantics:
            raise ValueError("non-replayable egress failure mechanism semantics are invalid")
        observed[str(api)] += 1
    if dict(sorted(observed.items())) != dict(by_api):
        raise ValueError("non-replayable egress failure counts differ from attempts")
    if (
        not isinstance(value["non_replayable_egress_sha256"], str)
        or hashlib.sha256(_canonical_json_bytes(receipt)).hexdigest()
        != value["non_replayable_egress_sha256"]
    ):
        raise ValueError("non-replayable egress failure evidence hash is invalid")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))
