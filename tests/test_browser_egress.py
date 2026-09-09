from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab.acquisition_errors import NonReplayableEgressPolicyError
from qcsd_lab.browser_egress import (
    BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES,
    BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION,
    BROWSER_EGRESS_DISABLED_BLINK_FEATURES,
    BROWSER_EGRESS_DISABLED_BASE_FEATURES,
    BROWSER_EGRESS_PLAYWRIGHT_DISABLED_FEATURES,
    BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES,
    BROWSER_EGRESS_PLAYWRIGHT_FEATURE_ARGUMENT,
    BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES,
    BROWSER_EGRESS_REPORTING_CONTROL_ENABLE_ARGUMENT,
    BROWSER_EGRESS_REPORTING_CONTROL_FEATURE_ARGUMENT,
    BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES,
    BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
    NON_REPLAYABLE_EGRESS_POLICY,
    POPUP_NAVIGATION_API,
    WEBSOCKET_POLICY_CLOSE_CODE,
    WEBSOCKET_POLICY_CLOSE_REASON,
    NonReplayableEgressGuard,
    install_context_egress_guards,
    launch_production_browser,
    build_fail_closed_host_resolver_argument,
    browser_egress_qualification_control_chromium_args,
    target_egress_apis,
    validate_browser_egress_command_line,
    validate_browser_egress_command_line_projection,
    validate_browser_egress_qualification_control_command_line,
    validate_non_replayable_egress_failure_evidence,
    validate_target_egress_shim_result,
)
from qcsd_lab.browser_egress_fixture import (
    BROWSER_SERVICE_CONTROL_DWELL_MS,
    BROWSER_SERVICE_CONTROL_SPECS,
    assemble_live_semantic_observation,
    browser_service_control_actor_result,
    expected_browser_launch_contract,
    expected_fixture_response_headers,
    expected_semantic_chronology,
    expected_vectors,
    expanded_vectors_sha256,
    validate_semantic_observation,
    vector_by_id,
)
from qcsd_lab.playwright_driver import DEFAULT_CONFIGURED_EXECUTABLE


def _production_effective_arguments() -> list[str]:
    return [
        str(DEFAULT_CONFIGURED_EXECUTABLE),
        *BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES,
        BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
        "--disable-features=" + ",".join(BROWSER_EGRESS_PLAYWRIGHT_DISABLED_FEATURES),
        "--disable-features=" + ",".join(BROWSER_EGRESS_DISABLED_BASE_FEATURES),
        "--disable-blink-features=" + ",".join(BROWSER_EGRESS_DISABLED_BLINK_FEATURES),
        "--enable-features=" + ",".join(BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES),
        build_fail_closed_host_resolver_argument(
            approved_origins=("https://example.test",),
            origin_ip_pins={"https://example.test": "192.0.2.10"},
        ),
    ]


def _ready_guard() -> NonReplayableEgressGuard:
    guard = NonReplayableEgressGuard()
    guard.mark_context_guards_installed()
    guard.bind_root_page(object())
    return guard


def _failure(guard: NonReplayableEgressGuard) -> dict:
    with pytest.raises(NonReplayableEgressPolicyError) as caught:
        guard.raise_if_failed()
    return copy.deepcopy(caught.value.evidence)


def _reseal(evidence: dict) -> None:
    receipt = evidence["non_replayable_egress"]
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    evidence["non_replayable_egress_sha256"] = hashlib.sha256(encoded).hexdigest()


class _FakeContext:
    def __init__(self) -> None:
        self.calls = []
        self.handlers = {}

    def add_init_script(self, *, script):
        self.calls.append(("init", script))

    def route(self, pattern, handler):
        self.calls.append(("route", pattern))
        self.handlers["route"] = handler

    def route_web_socket(self, pattern, handler):
        self.calls.append(("websocket", pattern))
        self.handlers["websocket"] = handler

    def on(self, event, handler):
        self.calls.append(("event", event))
        self.handlers[event] = handler


class _FakeRoute:
    def __init__(self, request) -> None:
        self.request = request
        self.actions = []
        self._impl_obj = SimpleNamespace(
            _channel=SimpleNamespace(send_no_reply=self._send_no_reply)
        )

    @property
    def url(self):
        return self.request.url

    def continue_(self):
        self.actions.append(("continue",))

    def abort(self, reason):
        self.actions.append(("abort", reason))

    def close(self, *, code, reason):
        self.actions.append(("close", code, reason))

    def _send_no_reply(self, method, timeout_calculator, params):
        self.actions.append(("send_no_reply", method, timeout_calculator, params))


def _request(*, page, url="https://example.test/path", navigation=True):
    return SimpleNamespace(
        url=url,
        frame=SimpleNamespace(page=page),
        is_navigation_request=lambda: navigation,
    )


def test_context_guards_are_registered_before_root_binding_and_route_only_popups() -> None:
    context = _FakeContext()
    guard = NonReplayableEgressGuard()
    install_context_egress_guards(context, guard)
    assert [call[0] for call in context.calls] == ["init", "route", "websocket", "event"]
    with pytest.raises(ValueError, match="completely installed"):
        guard.success_summary()

    root = object()
    guard.bind_root_page(root)
    assert guard.success_summary()["root_page_bound"] is True

    root_route = _FakeRoute(_request(page=root))
    context.handlers["route"](root_route)
    assert root_route.actions == [("continue",)]

    worker_request = _FakeRoute(_request(page=object(), navigation=False))
    context.handlers["route"](worker_request)
    assert worker_request.actions == [("continue",)]

    popup_route = _FakeRoute(
        _request(page=object(), url="https://user:secret@popup.test/private?q=discard")
    )
    context.handlers["route"](popup_route)
    assert popup_route.actions == [("abort", "blockedbyclient")]
    evidence = _failure(guard)
    validate_non_replayable_egress_failure_evidence(evidence)
    assert evidence["non_replayable_egress"]["attempts"][-1] == {
        "sequence": 0,
        "monotonic_ms": evidence["non_replayable_egress"]["attempts"][0]["monotonic_ms"],
        "api": POPUP_NAVIGATION_API,
        "mechanism": "playwright-popup-navigation-route",
        "source": None,
        "url": {"scheme": "https", "origin": "https://popup.test"},
    }


def test_websocket_and_service_worker_context_hooks_are_typed_and_minimised() -> None:
    assert WEBSOCKET_POLICY_CLOSE_CODE == 1008
    assert WEBSOCKET_POLICY_CLOSE_REASON == "QCSD non-replayable egress policy"
    context = _FakeContext()
    guard = NonReplayableEgressGuard()
    install_context_egress_guards(context, guard)
    guard.bind_root_page(object())
    websocket = _FakeRoute(_request(page=object(), url="wss://[2001:db8::1]:444/private?secret=1"))
    context.handlers["websocket"](websocket)
    context.handlers["serviceworker"](SimpleNamespace(url="https://worker.test/sw.js?secret=1"))
    assert websocket.actions == [
        (
            "send_no_reply",
            "closePage",
            None,
            {
                "code": 1008,
                "reason": "QCSD non-replayable egress policy",
                "wasClean": True,
            },
        )
    ]
    evidence = _failure(guard)
    validate_non_replayable_egress_failure_evidence(evidence)
    attempts = evidence["non_replayable_egress"]["attempts"]
    assert attempts[0]["url"] == {
        "scheme": "wss",
        "origin": "wss://[2001:db8::1]:444",
    }
    assert attempts[1]["url"] == {
        "scheme": "https",
        "origin": "https://worker.test",
    }


def test_websocket_context_hook_fails_closed_without_pinned_adapter() -> None:
    context = _FakeContext()
    guard = NonReplayableEgressGuard()
    install_context_egress_guards(context, guard)
    guard.bind_root_page(object())
    route = SimpleNamespace(url="wss://example.test/private")

    with pytest.raises(RuntimeError, match="close adapter is unavailable"):
        context.handlers["websocket"](route)

    evidence = _failure(guard)
    validate_non_replayable_egress_failure_evidence(evidence)
    assert evidence["non_replayable_egress"]["attempt_count"] == 1


def test_late_attempt_turns_a_provisional_success_into_typed_failure() -> None:
    guard = _ready_guard()
    assert guard.success_summary()["attempt_count"] == 0
    guard.record(
        api="WebTransport",
        mechanism="paused-target-runtime-shim",
        source=SimpleNamespace(target_type="page", generation=0),
    )
    with pytest.raises(NonReplayableEgressPolicyError) as caught:
        guard.success_summary()
    validate_non_replayable_egress_failure_evidence(caught.value.evidence)


def test_browser_popup_tab_non_network_url_remains_typed_and_minimised() -> None:
    guard = _ready_guard()
    guard.record(
        api=POPUP_NAVIGATION_API,
        mechanism="browser-popup-tab-tripwire",
        url="about:blank?discard=this#too",
    )
    evidence = _failure(guard)
    validate_non_replayable_egress_failure_evidence(evidence)
    assert evidence["non_replayable_egress"]["attempts"][0]["url"] == {
        "scheme": "about",
        "origin": "about:",
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt.update(schema_version=True),
        lambda receipt: receipt.update(attempt_count=True),
        lambda receipt: receipt["by_api"].update(WebTransport=True),
        lambda receipt: receipt["attempts"][0].update(sequence=True),
        lambda receipt: receipt["attempts"][0]["source"].update(generation=True),
        lambda receipt: receipt["attempts"][0].update(api="InventedSocket"),
        lambda receipt: receipt["attempts"][0].update(
            url={"scheme": "https", "origin": "https://example.test/private"}
        ),
        lambda receipt: receipt["attempts"][0].update(mechanism="playwright-websocket-route"),
    ],
)
def test_failure_evidence_rejects_resealed_type_content_and_semantic_mutation(
    mutate,
) -> None:
    guard = _ready_guard()
    guard.record(
        api="WebTransport",
        mechanism="cdp-network-tripwire",
        source=SimpleNamespace(target_type="page", generation=0),
        url="https://example.test/private",
    )
    evidence = _failure(guard)
    mutate(evidence["non_replayable_egress"])
    _reseal(evidence)
    with pytest.raises(ValueError):
        validate_non_replayable_egress_failure_evidence(evidence)


def test_target_shim_receipt_rejects_boolean_schema_alias() -> None:
    receipt = {
        "schema_version": True,
        "policy": NON_REPLAYABLE_EGRESS_POLICY,
        "protected_apis": sorted(target_egress_apis("worker")),
        "unavailable_apis": [],
        "failed_apis": [],
        "already_installed": False,
    }
    with pytest.raises(ValueError, match="identity"):
        validate_target_egress_shim_result(receipt, target_type="worker")


def test_command_line_receipt_requires_every_effective_switch_and_exact_types() -> None:
    raw = {"arguments": _production_effective_arguments()}
    projection = validate_browser_egress_command_line(raw)
    assert validate_browser_egress_command_line_projection(projection) == projection
    assert projection["schema_version"] == BROWSER_EGRESS_COMMAND_LINE_SCHEMA_VERSION
    assert projection["launch_profile"] == "production-fail-closed"
    assert projection["observed_required_switches"] == list(
        BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES
    )
    assert projection["observed_antagonistic_switches"] == []
    assert projection["host_resolver_policy"]["mapped_host_count"] == 1
    assert projection["packet_level_completeness_claimed"] is False

    missing = copy.deepcopy(raw)
    missing["arguments"].remove("--no-proxy-server")
    with pytest.raises(ValueError, match="omitted"):
        validate_browser_egress_command_line(missing)

    forged = copy.deepcopy(projection)
    forged["schema_version"] = True
    with pytest.raises(ValueError, match="projection"):
        validate_browser_egress_command_line_projection(forged)


@pytest.mark.parametrize(
    "argv0",
    ("chromium", "./chromium", "/tmp/unpinned-chromium", ""),
)
def test_command_line_receipt_rejects_unpinned_executable_argv0(argv0: str) -> None:
    raw = _production_effective_arguments()
    raw[0] = argv0
    with pytest.raises(ValueError, match=r"argv\[0\].*not pinned"):
        validate_browser_egress_command_line({"arguments": raw})


@pytest.mark.parametrize("switch", BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES)
def test_command_line_receipt_rejects_every_antagonistic_switch(switch: str) -> None:
    raw = {
        "arguments": [
            *_production_effective_arguments(),
            f"{switch}=attacker-controlled-value",
        ]
    }
    with pytest.raises(ValueError, match="antagonistic"):
        validate_browser_egress_command_line(raw)


@pytest.mark.parametrize(
    "arguments",
    (
        ["--host-rules"],
        ["--host-rules=MAP * 203.0.113.7"],
        ["--host-rules=MAP * 203.0.113.7", "--host-rules=MAP * 203.0.113.8"],
    ),
)
def test_command_line_receipt_rejects_host_rules_alias(arguments: list[str]) -> None:
    """M143 treats --host-rules as an alias for --host-resolver-rules."""

    raw = {"arguments": [*_production_effective_arguments(), *arguments]}
    with pytest.raises(ValueError, match="antagonistic"):
        validate_browser_egress_command_line(raw)


def test_command_line_receipt_rejects_valued_or_duplicate_required_switches() -> None:
    valued = {
        "arguments": [
            *(
                argument
                for argument in _production_effective_arguments()
                if argument != "--no-proxy-server"
            ),
            "--no-proxy-server=false",
        ],
    }
    with pytest.raises(ValueError, match="omitted|valued"):
        validate_browser_egress_command_line(valued)

    duplicated = {
        "arguments": [
            *_production_effective_arguments(),
            "--no-proxy-server",
        ]
    }
    with pytest.raises(ValueError, match="duplicated"):
        validate_browser_egress_command_line(duplicated)


def test_quic_disable_is_one_exact_bare_required_switch_for_every_profile() -> None:
    raw = _production_effective_arguments()
    assert raw.count("--disable-quic") == 1
    assert "--disable-quic" in BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES
    assert "--disable-quic" not in BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES
    assert "--enable-quic" in BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES

    for replacement, message in (
        ([], "omitted"),
        (["--disable-quic=false"], "omitted|valued"),
        (["--disable-quic", "--disable-quic"], "duplicated"),
    ):
        mutated = [argument for argument in raw if argument != "--disable-quic"]
        mutated.extend(replacement)
        with pytest.raises(ValueError, match=message):
            validate_browser_egress_command_line({"arguments": mutated})

    for vector in expected_vectors():
        if vector.family != "browser-service-control":
            continue
        arguments = _qualification_control_effective_arguments(vector.vector_id)
        assert arguments.count("--disable-quic") == 1
        arguments.remove("--disable-quic")
        contract = expected_browser_launch_contract(vector)
        with pytest.raises(ValueError, match="omitted"):
            validate_browser_egress_qualification_control_command_line(
                {"arguments": arguments},
                launch_profile=contract["launch_profile"],
                approved_origins=contract["resolver_approved_origins"],
                origin_ip_pins=contract["resolver_origin_ip_pins"],
                approved_ip_exclusions=contract["resolver_approved_ip_exclusions"],
                dns_exception_hostname=contract["dns_exception_hostname"],
            )


def test_command_line_projection_cannot_reseal_an_antagonistic_observation() -> None:
    projection = validate_browser_egress_command_line(
        {"arguments": _production_effective_arguments()}
    )
    projection["observed_antagonistic_switches"] = ["--proxy-server"]
    with pytest.raises(ValueError, match="projection"):
        validate_browser_egress_command_line_projection(projection)


@pytest.mark.parametrize(
    "malicious",
    [
        "--host-resolver-rules=MAP example.test attacker.test, MAP * ^NOTFOUND",
        "--host-resolver-rules=MAP example.test 192.0.2.10, MAP * ^NOTFOUND, EXCLUDE attacker.test",
        "--host-resolver-rules=MAP example.test 192.0.2.10, MAP * ~NOTFOUND",
    ],
)
def test_production_resolver_rejects_hostname_destinations_exclusions_and_legacy_sentinel(
    malicious: str,
) -> None:
    arguments = [
        argument
        for argument in _production_effective_arguments()
        if not argument.startswith("--host-resolver-rules=")
    ]
    arguments.append(malicious)
    with pytest.raises(ValueError):
        validate_browser_egress_command_line({"arguments": arguments})


def test_production_rejects_enabled_blink_and_qualification_certificate_switches() -> None:
    for argument in (
        "--enable-blink-features=Fledge,AttributionReporting,SharedStorageAPI",
        "--ignore-certificate-errors-spki-list=attacker",
        "--short-reporting-delay",
    ):
        with pytest.raises(ValueError):
            validate_browser_egress_command_line(
                {"arguments": [*_production_effective_arguments(), argument]}
            )


@pytest.mark.parametrize(
    ("origin", "pin"),
    [
        ("http://example.test", "8.8.8.8"),
        ("https://192.0.2.10", "8.8.8.8"),
        ("https://example.test", "127.0.0.1"),
        ("https://example.test", "192.168.1.1"),
        ("https://example.test", "resolver.example"),
    ],
)
def test_public_launch_rejects_non_https_numeric_or_non_global_origin_pins(
    origin: str, pin: str
) -> None:
    with pytest.raises(ValueError, match="public browser"):
        launch_production_browser(
            None,
            approved_origins=(origin,),
            origin_ip_pins={origin: pin},
        )


def test_every_production_chromium_launch_uses_the_validated_central_boundary() -> None:
    root = Path(__file__).resolve().parents[1]
    launch_calls: list[tuple[str, str | None, str]] = []
    helper_calls: list[tuple[str, str | None, str]] = []
    qualification_helper_calls: list[tuple[str, str | None, str]] = []
    forbidden_calls: list[tuple[str, str | None, str]] = []
    for path in sorted((root / "src/qcsd_lab").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function: ast.AST = node.func
            name = (
                function.attr
                if isinstance(function, ast.Attribute)
                else function.id
                if isinstance(function, ast.Name)
                else ""
            )
            current: ast.AST | None = node
            owner: str | None = None
            while current is not None:
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = current.name
                    break
                current = parents.get(current)
            record = (path.name, owner, name)
            if name == "launch":
                launch_calls.append(record)
            if name in {
                "launch_persistent_context",
                "connect",
                "connect_over_cdp",
                "launch_server",
            }:
                forbidden_calls.append(record)
            if name in {"launch_production_browser", "launch_pinned_cdp_probe_browser"}:
                helper_calls.append(record)
            if name == "launch_qualification_browser":
                qualification_helper_calls.append(record)

    assert launch_calls == [
        (
            "browser_egress.py",
            "_launch_browser_and_validate_command_line",
            "launch",
        )
    ]
    assert forbidden_calls == []
    assert qualification_helper_calls == []
    assert helper_calls == [
        (
            "class_acquisition.py",
            "_catalogue_boundary_navigation_pass",
            "launch_production_browser",
        ),
        ("class_acquisition.py", "browser_document_content_type", "launch_production_browser"),
        ("discover.py", "discover_page", "launch_production_browser"),
        ("pinned_cdp.py", "run_pinned_cdp_probe", "launch_pinned_cdp_probe_browser"),
    ]

    tool_browser_api_calls: list[tuple[str, str | None, str]] = []
    tool_qualification_helper_calls: list[tuple[str, str | None, str]] = []
    for path in sorted((root / "tools").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = (
                function.attr
                if isinstance(function, ast.Attribute)
                else function.id
                if isinstance(function, ast.Name)
                else ""
            )
            current: ast.AST | None = node
            owner = None
            while current is not None:
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = current.name
                    break
                current = parents.get(current)
            record = (path.name, owner, name)
            if name in {
                "launch",
                "launch_persistent_context",
                "connect_over_cdp",
                "launch_server",
            }:
                tool_browser_api_calls.append(record)
            if name == "connect" and isinstance(function, ast.Attribute):
                expression = ast.unparse(function.value)
                if "chromium" in expression or "playwright" in expression:
                    tool_browser_api_calls.append(record)
            if name == "launch_qualification_browser":
                tool_qualification_helper_calls.append(record)
    assert tool_browser_api_calls == []
    assert len(tool_qualification_helper_calls) == 1
    assert tool_qualification_helper_calls[0][0] == "browser_egress_qualification.py"
    assert tool_qualification_helper_calls[0][1] is not None


def _qualification_control_effective_arguments(vector_id: str) -> list[str]:
    vector = vector_by_id(vector_id)
    contract = expected_browser_launch_contract(vector)
    explicit = browser_egress_qualification_control_chromium_args(
        launch_profile=contract["launch_profile"],
        approved_origins=contract["resolver_approved_origins"],
        origin_ip_pins=contract["resolver_origin_ip_pins"],
        approved_ip_exclusions=contract["resolver_approved_ip_exclusions"],
        dns_exception_hostname=contract["dns_exception_hostname"],
    )
    explicit_names = {argument.split("=", 1)[0] for argument in explicit}
    return [
        str(DEFAULT_CONFIGURED_EXECUTABLE),
        *(
            switch
            for switch in BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES
            if switch not in explicit_names
        ),
        BROWSER_EGRESS_PLAYWRIGHT_FEATURE_ARGUMENT,
        "--enable-features=" + ",".join(BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES),
        *explicit,
    ]


def test_all_control_profiles_validate_exact_argv_and_resolver_projection() -> None:
    seen_profiles = set()
    for vector in expected_vectors():
        if vector.family != "browser-service-control":
            continue
        contract = expected_browser_launch_contract(vector)
        seen_profiles.add(contract["launch_profile"])
        projection = validate_browser_egress_qualification_control_command_line(
            {"arguments": _qualification_control_effective_arguments(vector.vector_id)},
            launch_profile=contract["launch_profile"],
            approved_origins=contract["resolver_approved_origins"],
            origin_ip_pins=contract["resolver_origin_ip_pins"],
            approved_ip_exclusions=contract["resolver_approved_ip_exclusions"],
            dns_exception_hostname=contract["dns_exception_hostname"],
        )
        assert projection["launch_profile"] == contract["launch_profile"]
        assert projection["host_resolver_policy"]["mode"] == contract["resolver_profile"]
    assert seen_profiles == set(BROWSER_EGRESS_QUALIFICATION_CONTROL_PROFILES)


def test_twelve_browser_service_controls_form_six_exact_paired_treatments() -> None:
    controls = [
        vector for vector in expected_vectors() if vector.family == "browser-service-control"
    ]
    assert len(controls) == len(BROWSER_SERVICE_CONTROL_SPECS) == 12
    assert len(expected_vectors()) == 110
    mechanisms = (
        "speculation-prefetch",
        "dns-prefetch",
        "preconnect",
        "speculation-prerender",
        "reporting",
        "network-error-logging",
    )
    for mechanism in mechanisms:
        disabled = next(vector for vector in controls if vector.surface == f"{mechanism}-disabled")
        enabled = next(vector for vector in controls if vector.surface == f"{mechanism}-enabled")
        disabled_contract = expected_browser_launch_contract(disabled)
        enabled_contract = expected_browser_launch_contract(enabled)
        for contract in (disabled_contract, enabled_contract):
            contract.pop("vector_id")
            contract.pop("launch_profile")
            contract.pop("managed_policy")
        assert disabled_contract == enabled_contract
        assert expected_fixture_response_headers(disabled) == expected_fixture_response_headers(
            enabled
        )
        disabled_policy = expected_browser_launch_contract(disabled)["managed_policy"]
        enabled_policy = expected_browser_launch_contract(enabled)["managed_policy"]
        assert disabled_policy["DnsOverHttpsMode"] == "off"
        assert enabled_policy["DnsOverHttpsMode"] == "off"
        disabled_arguments = _qualification_control_effective_arguments(disabled.vector_id)
        enabled_arguments = _qualification_control_effective_arguments(enabled.vector_id)
        if mechanism in {"reporting", "network-error-logging"}:
            assert disabled_policy == enabled_policy
            assert disabled_policy["NetworkPredictionOptions"] == 2
            assert set(disabled_arguments).symmetric_difference(enabled_arguments) == {
                BROWSER_EGRESS_REPORTING_CONTROL_FEATURE_ARGUMENT,
                BROWSER_EGRESS_REPORTING_CONTROL_ENABLE_ARGUMENT,
                "--disable-features=" + ",".join(BROWSER_EGRESS_DISABLED_BASE_FEATURES),
            }
        else:
            assert disabled_policy["NetworkPredictionOptions"] == 2
            assert enabled_policy["NetworkPredictionOptions"] == 0
            assert disabled_arguments == enabled_arguments
        for vector in (disabled, enabled):
            assert vector.as_dict()["minimum_live_dwell_ms"] == (BROWSER_SERVICE_CONTROL_DWELL_MS)
            assert vector.as_dict()["action_contract"]["minimum_live_dwell_ms"] == (
                BROWSER_SERVICE_CONTROL_DWELL_MS
            )


def test_browser_service_controls_enforce_the_frozen_pair_dwell() -> None:
    vector = vector_by_id("browser-service-control--off-the-record--speculation-prefetch-disabled")
    duration_ns = BROWSER_SERVICE_CONTROL_DWELL_MS * 1_000_000
    assert (
        browser_service_control_actor_result(
            vector,
            started_ns=10,
            finished_ns=10 + duration_ns,
        )["finished_ns"]
        == 10 + duration_ns
    )
    with pytest.raises(ValueError, match="timing"):
        browser_service_control_actor_result(
            vector,
            started_ns=10,
            finished_ns=9 + duration_ns,
        )

    started_ns = 10_000_000_000
    finished_ns = started_ns + duration_ns
    actor = browser_service_control_actor_result(
        vector,
        started_ns=started_ns,
        finished_ns=finished_ns,
    )
    events = expected_semantic_chronology(vector)
    times = {
        "observer-ready": 1,
        "sinks-ready": 2,
        "browser-started": 3,
        "action-started": started_ns,
        "action-issued": finished_ns,
        "browser-exited": finished_ns + 1,
        "reporting-grace-finished": finished_ns + 2,
        "observer-stopped": finished_ns + 3,
    }
    assert tuple(times) == events
    observation = assemble_live_semantic_observation(
        vector=vector,
        actor_result=actor,
        event_times=times,
    )
    observation["chronology"][events.index("action-issued")]["monotonic_ns"] -= 1
    with pytest.raises(ValueError, match="dwell"):
        validate_semantic_observation(observation, vector=vector)


def test_vector_digest_and_order_bind_the_expanded_controls() -> None:
    vectors = expected_vectors()
    assert [vector.ordinal for vector in vectors] == list(range(1, 111))
    assert [vector.vector_id for vector in vectors[95:107]] == [
        f"browser-service-control--{context}--{surface}"
        for context, surface, *_rest in BROWSER_SERVICE_CONTROL_SPECS
    ]
    assert expanded_vectors_sha256() == (
        "9fecbeb7988fcb28d82803026ef9f3948d1494b14cc5a0930585e6e51e3a4179"
    )
