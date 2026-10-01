"""The opt-in rehearsal trace observes CDP failures without changing them."""

from collections import OrderedDict, deque
from hashlib import sha256
from types import SimpleNamespace

import pytest

import qcsd_lab.class_acquisition as class_acquisition
import qcsd_lab.cdp_targets as cdp_targets
import qcsd_lab.discover as discover_module
from tools.acquisition_root_cdp_trace import _event_summary, install

_ORIGINAL_OBSERVATION_LEDGER = discover_module._RequestObservationLedger


def _fixture_router(monkeypatch, emit):
    original = class_acquisition.RecursiveCdpTargetRouter
    monkeypatch.setattr(class_acquisition, "RecursiveCdpTargetRouter", original)
    monkeypatch.setattr(discover_module, "RecursiveCdpTargetRouter", original)
    monkeypatch.setattr(
        discover_module, "_RequestObservationLedger", _ORIGINAL_OBSERVATION_LEDGER
    )
    traced = install(emit)
    assert class_acquisition.RecursiveCdpTargetRouter is traced
    assert discover_module.RecursiveCdpTargetRouter is traced
    router = traced.__new__(traced)
    root = object()
    router._root_source = root
    router._root_frame_id = "frame"
    router._root_fetch_by_policy_identity = {}
    router._active_requests = {}
    router._root_terminal_requests = {}
    router._disabled_root_invalid_interception_networks = set()
    router._diagnostic_events = deque(maxlen=128)
    router._diagnostic_request_events = OrderedDict()
    router._diagnostic_root_fetches = deque(maxlen=128)
    router._shutting_down = False
    router._aborting = False
    router._diagnostic_current_event = (
        root,
        "Fetch.requestPaused",
        {
            "requestId": "fetch-secret",
            "networkId": "network-secret",
            "frameId": "frame",
            "resourceType": "Font",
            "request": {"url": "https://example.test/private", "method": "GET"},
        },
    )
    return original, traced, router


def test_trace_emits_hashed_failure_context_and_preserves_exception(monkeypatch):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )

    def invalid(_self, _method, _params):
        raise cdp_targets._RootInvalidInterception(fingerprint="synthetic")

    try:
        monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "_root_send", invalid)
        with pytest.raises(cdp_targets._RootInvalidInterception, match="synthetic"):
            router._root_send("Fetch.continueRequest", {"requestId": "fetch-secret"})
        assert len(records) == 1
        stage, context = records[0]
        assert stage == "root-invalid-interception-trace"
        assert context["current_event"]["resource_type"] == "Font"
        assert context["registered_recovery_decision"] is False
        assert context["active_root_network_occurrences"] == 0
        assert context["command_request_id_sha256"] == sha256(b"fetch-secret").hexdigest()
        assert "fetch-secret" not in str(context)
        assert "network-secret" not in str(context)
        assert "https://example.test/private" not in str(context)
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_trace_output_failure_cannot_change_router_failure(monkeypatch):
    def broken_emit(_stage, **_data):
        raise OSError("diagnostic sink failed")

    original, _traced, router = _fixture_router(monkeypatch, broken_emit)

    def invalid(_self, _method, _params):
        raise cdp_targets._RootInvalidInterception(fingerprint="synthetic")

    try:
        monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "_root_send", invalid)
        with pytest.raises(cdp_targets._RootInvalidInterception, match="synthetic"):
            router._root_send("Fetch.continueRequest", {"requestId": "fetch-secret"})
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_invalid_interception_trace_uses_command_fetch_not_reentrant_event(monkeypatch):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )
    command_fetch = {
        "requestId": "font-fetch",
        "networkId": "font-network",
        "frameId": "frame",
        "resourceType": "Font",
        "request": {"method": "GET", "url": "https://example.test/font-secret"},
    }
    router._diagnostic_root_fetches.append((router.root_source, command_fetch))
    router._diagnostic_current_event = (
        router.root_source,
        "Fetch.requestPaused",
        {
            "requestId": "other-fetch",
            "networkId": "other-network",
            "resourceType": "Other",
            "request": {"method": "GET", "url": "https://example.test/other-secret"},
        },
    )
    router._diagnostic_events.extend(
        (
            _event_summary(router.root_source, "Fetch.requestPaused", command_fetch),
            _event_summary(
                router.root_source,
                "Network.requestWillBeSent",
                {
                    "requestId": "font-network",
                    "frameId": "frame",
                    "type": "Font",
                    "request": {"method": "GET", "url": "https://example.test/font-secret"},
                },
            ),
        )
    )
    router._active_requests["font-network"] = [
        cdp_targets._ActiveRequest(
            source=router.root_source,
            request_id="font-network",
            loader_id=None,
            frame_id="frame",
            resource_type="Font",
            method="GET",
            url="https://example.test/font-secret",
        )
    ]

    def invalid(_self, _method, _params):
        raise cdp_targets._RootInvalidInterception(fingerprint="synthetic")

    try:
        monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "_root_send", invalid)
        with pytest.raises(cdp_targets._RootInvalidInterception, match="synthetic"):
            router._root_send("Fetch.continueRequest", {"requestId": "font-fetch"})
        stage, context = records[0]
        assert stage == "root-invalid-interception-trace"
        assert context["command_fetch_event"]["resource_type"] == "Font"
        assert context["current_event"]["resource_type"] == "Other"
        assert context["active_root_network_occurrences"] == 1
        assert context["exact_active_root_network_occurrences"] == 1
        assert context["command_recent_network_events"][0]["cdp_method"] == (
            "Network.requestWillBeSent"
        )
        for secret in ("font-fetch", "font-network", "font-secret", "other-network"):
            assert secret not in str(context)
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_invalid_interception_trace_links_exact_failed_terminal_before_command_fetch(
    monkeypatch,
):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )
    root = cdp_targets.CdpTargetSource((), "secret-root", target_type="page")
    router._root_source = root
    monkeypatch.setattr(
        cdp_targets.RecursiveCdpTargetRouter,
        "_handle_forwarded",
        lambda _self, _source, _method, _event: None,
    )
    monkeypatch.setattr(
        cdp_targets.RecursiveCdpTargetRouter,
        "_root_send",
        lambda _self, _method, _params: (_ for _ in ()).throw(
            cdp_targets._RootInvalidInterception(fingerprint="synthetic")
        ),
    )
    try:
        router._handle_forwarded(
            root,
            "Network.requestWillBeSent",
            {
                "requestId": "secret-network",
                "type": "Script",
                "request": {
                    "method": "GET",
                    "url": "https://example.test/private-script",
                },
            },
        )
        router._handle_forwarded(
            root,
            "Network.loadingFailed",
            {
                "requestId": "secret-network",
                "type": "Script",
                "errorText": "net::ERR_BLOCKED_BY_CLIENT",
                "canceled": False,
                "blockedReason": "inspector",
                "corsErrorStatus": {"private": "secret-cors"},
            },
        )
        router._handle_forwarded(
            root,
            "Fetch.requestPaused",
            {
                "requestId": "secret-fetch",
                "networkId": "secret-network",
                "resourceType": "Script",
                "request": {
                    "method": "GET",
                    "url": "https://example.test/private-script",
                },
            },
        )
        with pytest.raises(cdp_targets._RootInvalidInterception, match="synthetic"):
            router._root_send("Fetch.continueRequest", {"requestId": "secret-fetch"})
        assert len(records) == 1
        stage, context = records[0]
        assert stage == "root-invalid-interception-trace"
        assert context["command_fetch_identity_index"] == 2
        assert context["command_failed_terminal_count"] == 1
        terminal = context["command_failed_terminals"][0]
        assert terminal["identity_index"] == 1
        assert terminal["relative_to_command_fetch"] == "before"
        assert terminal["resource_type"] == "Script"
        assert terminal["terminal_failure"] == {
            "error_code": "net::ERR_BLOCKED_BY_CLIENT",
            "error_text_sha256": sha256(b"net::ERR_BLOCKED_BY_CLIENT").hexdigest(),
            "canceled": False,
            "blocked_reason_code": "inspector",
            "blocked_reason_sha256": sha256(b"inspector").hexdigest(),
            "cors_error_status_present": True,
        }
        assert [item["cdp_method"] for item in context["command_identity_events"]] == [
            "Network.requestWillBeSent",
            "Network.loadingFailed",
            "Fetch.requestPaused",
        ]
        for secret in (
            "secret-root",
            "secret-network",
            "secret-fetch",
            "private-script",
            "secret-cors",
        ):
            assert secret not in str(context)
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_event_summary_hashes_identifiers_and_marks_response_stage():
    event = _event_summary(
        object(),
        "Fetch.requestPaused",
        {
            "requestId": "secret-request",
            "networkId": "secret-network",
            "loaderId": "secret-loader",
            "frameId": "secret-frame",
            "documentURL": "chrome-error://chromewebdata/",
            "resourceType": "Stylesheet",
            "responseStatusCode": 200,
            "request": {"method": "GET", "url": "https://example.test/private"},
        },
    )
    assert event["response_stage"] is True
    assert event["resource_type"] == "Stylesheet"
    assert event["request_id_sha256"] == sha256(b"secret-request").hexdigest()
    assert event["loader_id_sha256"] == sha256(b"secret-loader").hexdigest()
    assert "secret-request" not in str(event)
    assert "secret-loader" not in str(event)
    assert "https://example.test/private" not in str(event)


def test_trace_collects_bounded_root_events_only(monkeypatch):
    original, _traced, router = _fixture_router(monkeypatch, lambda *_args, **_kwargs: None)
    previous = router._diagnostic_current_event
    monkeypatch.setattr(
        cdp_targets.RecursiveCdpTargetRouter,
        "_handle_forwarded",
        lambda _self, _source, _method, _event: None,
    )
    try:
        event = {
            "requestId": "network-secret",
            "frameId": "frame",
            "type": "Font",
            "request": {"method": "GET", "url": "https://example.test/private"},
        }
        router._handle_forwarded(router.root_source, "Network.requestWillBeSent", event)
        router._handle_forwarded(object(), "Network.requestWillBeSent", event)
        assert len(router._diagnostic_events) == 1
        assert router._diagnostic_events[0]["cdp_method"] == "Network.requestWillBeSent"
        assert router._diagnostic_current_event == previous
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


@pytest.mark.parametrize(
    ("message", "expected_stage"),
    (
        (
            "Chromium error-document resources were duplicated or reordered",
            "root-error-document-order-trace",
        ),
        (
            "Chromium error-document resource parser columns were inconsistent",
            "root-error-document-column-trace",
        ),
    ),
)
def test_error_document_order_trace_explains_state_without_exposing_ids(
    monkeypatch, message, expected_stage,
):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )
    lifecycle = SimpleNamespace(
        next_signature_index=1,
        initiator_column_base=624,
        complete=False,
        active=SimpleNamespace(signature_index=0, phase="awaiting-terminal"),
    )
    monkeypatch.setattr(
        router, "_error_document_resources_for_loader", lambda _source, _loader: lifecycle
    )
    monkeypatch.setattr(
        router, "_error_document_resource_signature", lambda _url: (1, 6366)
    )

    def reordered(_self, _source, _method, _event):
        raise cdp_targets.CdpTargetIntegrityError(message)

    monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "_handle_forwarded", reordered)
    event = {
        "requestId": "secret-request",
        "loaderId": "secret-loader",
        "frameId": "secret-frame",
        "documentURL": "chrome-error://chromewebdata/",
        "type": "Image",
        "request": {"url": "data:image/png;base64,secret-image", "method": "GET"},
        "initiator": {"url": "chrome-error://chromewebdata/", "columnNumber": 624},
    }
    try:
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="Chromium error-document"):
            router._handle_forwarded(router.root_source, "Network.requestWillBeSent", event)
        assert len(records) == 1
        stage, context = records[0]
        assert stage == expected_stage
        assert context["observed_signature_index"] == 1
        assert context["expected_signature_index"] == 1
        assert context["active_signature_index"] == 0
        assert context["active_phase"] == "awaiting-terminal"
        assert context["lifecycle_complete"] is False
        assert context["initiator_column"] == 624
        assert context["expected_initiator_column"] == 624
        assert context["historical_reference_column"] == 624
        assert context["current_event"]["loader_id_sha256"] == sha256(
            b"secret-loader"
        ).hexdigest()
        assert len(context["recent_protocol_events"]) == 1
        for secret in ("secret-request", "secret-loader", "secret-frame", "secret-image"):
            assert secret not in str(context)
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_error_document_request_signature_trace_identifies_failing_predicate(
    monkeypatch,
):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )
    lifecycle = SimpleNamespace(
        source=router.root_source,
        loader_id="secret-loader",
        frame_id="secret-frame",
        latest_timestamp=41.25,
    )
    monkeypatch.setattr(
        router, "_error_document_resources_for_loader", lambda _source, _loader: lifecycle
    )
    event = {
        "requestId": "secret-request",
        "loaderId": "secret-loader",
        "documentURL": "chrome-error://chromewebdata/",
        "request": {
            "url": "data:image/png;base64,secret-image",
            "method": "GET",
            "headers": {
                "User-Agent": cdp_targets._PINNED_ERROR_DOCUMENT_USER_AGENT,
                "Referer": "",
            },
            "mixedContentType": "none",
            "initialPriority": "High",
            "referrerPolicy": "strict-origin-when-cross-origin",
            "isSameSite": False,
        },
        "timestamp": 42.0,
        "wallTime": 1_725_000_000.0,
        "initiator": {
            "type": "parser",
            "url": "chrome-error://chromewebdata/",
            "lineNumber": 1504,
            "columnNumber": 624,
        },
        "redirectHasExtraInfo": False,
        "type": "Image",
        "frameId": "secret-frame",
        "hasUserGesture": False,
    }

    def invalid(_self, _source, _method, _event):
        raise cdp_targets.CdpTargetIntegrityError(
            "Chromium error-document resource request signature was invalid"
        )

    monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "_handle_forwarded", invalid)
    try:
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="signature was invalid"):
            router._handle_forwarded(router.root_source, "Network.requestWillBeSent", event)
        assert len(records) == 1
        stage, context = records[0]
        assert stage == "root-error-document-request-signature-trace"
        assert context["signature"]["failed_checks"] == ["initial_priority_low"]
        assert context["signature"]["observed_initiator_line_bounded"] == 1504
        assert context["signature"]["field_sets"]["request"]["missing_fields"] == []
        assert context["signature"]["field_sets"]["request"]["unexpected_field_hashes"] == []
        for secret in ("secret-request", "secret-loader", "secret-frame", "secret-image"):
            assert secret not in str(context)

        event["request"]["private-field-name"] = "private-value"
        event.pop("hasUserGesture")
        event["initiator"]["lineNumber"] = 4096
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="signature was invalid"):
            router._handle_forwarded(router.root_source, "Network.requestWillBeSent", event)
        signature = records[-1][1]["signature"]
        assert signature["failed_checks"] == [
            "outer_fields_exact",
            "has_user_gesture_false",
            "inner_fields_exact",
            "initial_priority_low",
            "initiator_line_bounded",
        ]
        assert signature["observed_initiator_line_bounded"] is None
        assert signature["field_sets"]["outer"]["missing_fields"] == ["hasUserGesture"]
        assert signature["field_sets"]["request"]["unexpected_field_hashes"] == [
            sha256(b"private-field-name").hexdigest()
        ]
        assert "private-field-name" not in str(records[-1])
        assert "private-value" not in str(records[-1])

        event["initiator"]["lineNumber"] = 10_000
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="signature was invalid"):
            router._handle_forwarded(router.root_source, "Network.requestWillBeSent", event)
        assert records[-1][1]["signature"]["observed_initiator_line_bounded"] is None
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_error_document_trace_sink_failure_preserves_integrity_error(monkeypatch):
    def broken_emit(_stage, **_data):
        raise OSError("diagnostic sink failed")

    original, _traced, router = _fixture_router(monkeypatch, broken_emit)
    monkeypatch.setattr(
        router, "_error_document_resources_for_loader", lambda _source, _loader: None
    )
    monkeypatch.setattr(
        router, "_error_document_resource_signature", lambda _url: (0, 4026)
    )

    def reordered(_self, _source, _method, _event):
        raise cdp_targets.CdpTargetIntegrityError(
            "Chromium error-document resources were duplicated or reordered"
        )

    monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "_handle_forwarded", reordered)
    try:
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="duplicated or reordered"):
            router._handle_forwarded(
                router.root_source,
                "Network.requestWillBeSent",
                {"request": {"url": "data:image/png;base64,secret-image"}},
            )
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def _shutdown_mismatch_fixture(router):
    source = cdp_targets.CdpTargetSource(
        session_path=("secret-session",),
        target_id="secret-target",
    )
    fetch = cdp_targets._NormalShutdownFetch(
        source=source,
        fetch_request_id="secret-fetch",
        network_id="secret-network",
        frame_id="secret-frame",
        resource_type="Image",
        method="GET",
        url="https://example.test/private-image",
        pre_shutdown_network_id_seen=True,
        root_page_context_disposal_candidate=False,
    )
    active = cdp_targets._ActiveRequest(
        source=source,
        request_id="secret-network",
        loader_id=None,
        frame_id="secret-frame",
        resource_type="Image",
        method="GET",
        url="https://example.test/other-image",
    )
    network = cdp_targets._NormalShutdownNetwork(active=active)
    router._normal_shutdown_disposal = SimpleNamespace(
        _fetches={fetch.network_id: [fetch]},
        _networks={fetch.network_id: [network]},
    )


def test_normal_shutdown_trace_explains_unmatched_pause_without_raw_ids(monkeypatch):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )
    _shutdown_mismatch_fixture(router)

    def mismatch(_self):
        raise cdp_targets.CdpTargetIntegrityError(
            "normal shutdown Fetch pause has no exact Network occurrence"
        )

    try:
        monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "finish", mismatch)
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="no exact Network occurrence"):
            router.finish()
        assert len(records) == 1
        stage, context = records[0]
        assert stage == "normal-shutdown-fetch-occurrence-trace"
        ledger = context["ledger"]
        assert ledger["network_total"] == 1
        assert ledger["unmatched_fetch_total"] == 1
        fetch = ledger["unmatched_fetches"][0]
        assert fetch["resource_type"] == "Image"
        assert fetch["pre_shutdown_network_id_seen"] is True
        assert fetch["same_id_network_total"] == 1
        assert fetch["network_id_sha256"] == sha256(b"secret-network").hexdigest()
        for secret in (
            "secret-fetch",
            "secret-network",
            "secret-frame",
            "secret-target",
            "https://example.test/private-image",
            "https://example.test/other-image",
        ):
            assert secret not in str(context)
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_normal_shutdown_trace_explains_unmatched_network_without_raw_ids(monkeypatch):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )
    _shutdown_mismatch_fixture(router)

    def mismatch(_self):
        raise cdp_targets.CdpTargetIntegrityError(
            "normal shutdown Network-only occurrence lacked exact local cancellation"
        )

    try:
        monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "finish", mismatch)
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="local cancellation"):
            router.finish()
        assert len(records) == 1
        stage, context = records[0]
        assert stage == "normal-shutdown-network-occurrence-trace"
        ledger = context["ledger"]
        assert ledger["unmatched_network_total"] == 1
        network = ledger["unmatched_networks"][0]
        assert network["network_id_sha256"] == sha256(b"secret-network").hexdigest()
        assert network["resource_type"] == "Image"
        assert network["same_id_fetch_total"] == 1
        assert network["same_id_fetches"][0]["resource_type"] == "Image"
        for secret in (
            "secret-fetch",
            "secret-network",
            "secret-frame",
            "secret-target",
            "https://example.test/private-image",
            "https://example.test/other-image",
        ):
            assert secret not in str(context)
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_normal_shutdown_trace_sink_failure_preserves_integrity_error(monkeypatch):
    def broken_emit(_stage, **_data):
        raise OSError("diagnostic sink failed")

    original, _traced, router = _fixture_router(monkeypatch, broken_emit)
    _shutdown_mismatch_fixture(router)

    def mismatch(_self):
        raise cdp_targets.CdpTargetIntegrityError(
            "normal shutdown Fetch pause has no exact Network occurrence"
        )

    try:
        monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "finish", mismatch)
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="no exact Network occurrence"):
            router.finish()
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_unmatched_terminal_trace_links_prior_request_across_targets(monkeypatch):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )
    source = cdp_targets.CdpTargetSource(
        session_path=("secret-session",),
        target_id="secret-target",
        target_type="iframe",
    )
    prior = {
        "requestId": "secret-network",
        "frameId": "secret-frame",
        "type": "Image",
        "request": {"method": "GET", "url": "https://example.test/secret-image"},
    }
    terminal = {"requestId": "secret-network", "timestamp": 42.0}

    def fail_terminal(_self, _source, method, _event):
        if method == "Network.loadingFinished":
            raise cdp_targets.CdpTargetIntegrityError(
                "CDP loading terminal event has no active request occurrence"
            )

    monkeypatch.setattr(
        cdp_targets.RecursiveCdpTargetRouter, "_handle_forwarded", fail_terminal
    )
    try:
        router._handle_forwarded(source, "Network.requestWillBeSent", prior)
        with pytest.raises(
            cdp_targets.CdpTargetIntegrityError,
            match="loading terminal event has no active",
        ):
            router._handle_forwarded(source, "Network.loadingFinished", terminal)
        assert len(records) == 1
        stage, context = records[0]
        assert stage == "unmatched-loading-terminal-trace"
        history = context["matching_identity_events"]
        assert [item["cdp_method"] for item in history] == [
            "Network.requestWillBeSent",
            "Network.loadingFinished",
        ]
        assert all(
            item["request_id_sha256"] == sha256(b"secret-network").hexdigest()
            for item in history
        )
        assert context["current_event"]["source_target_type"] == "iframe"
        assert context["active_same_id_count"] == 0
        assert context["shutting_down"] is False
        assert context["aborting"] is False
        for secret in ("secret-network", "secret-session", "secret-target", "secret-image"):
            assert secret not in str(context)
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_unmatched_terminal_trace_sink_failure_preserves_integrity_error(monkeypatch):
    def broken_emit(_stage, **_data):
        raise OSError("diagnostic sink failed")

    original, _traced, router = _fixture_router(monkeypatch, broken_emit)

    def fail_terminal(_self, _source, _method, _event):
        raise cdp_targets.CdpTargetIntegrityError(
            "CDP loading terminal event has no active request occurrence"
        )

    monkeypatch.setattr(
        cdp_targets.RecursiveCdpTargetRouter, "_handle_forwarded", fail_terminal
    )
    try:
        with pytest.raises(
            cdp_targets.CdpTargetIntegrityError,
            match="loading terminal event has no active",
        ):
            router._handle_forwarded(
                router.root_source,
                "Network.loadingFailed",
                {"requestId": "secret-network"},
            )
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_generic_router_trace_hashes_unknown_integrity_message(monkeypatch):
    records = []
    original, _traced, router = _fixture_router(
        monkeypatch, lambda stage, **data: records.append((stage, data))
    )
    message = "synthetic failure for https://example.test/private and secret-request"

    def fail(_self, _source, _method, _event):
        raise cdp_targets.CdpTargetIntegrityError(message)

    monkeypatch.setattr(cdp_targets.RecursiveCdpTargetRouter, "_handle_forwarded", fail)
    try:
        with pytest.raises(cdp_targets.CdpTargetIntegrityError, match="synthetic failure"):
            router._handle_forwarded(
                router.root_source,
                "Network.requestWillBeSent",
                {
                    "requestId": "secret-request",
                    "request": {
                        "method": "GET",
                        "url": "https://example.test/private",
                    },
                },
            )
        stage, context = records[0]
        assert stage == "router-integrity-trace"
        assert context["error_message_sha256"] == sha256(message.encode()).hexdigest()
        assert len(context["matching_identity_events"]) == 1
        assert message not in str(context)
        assert "secret-request" not in str(context)
        assert "https://example.test/private" not in str(context)
    finally:
        class_acquisition.RecursiveCdpTargetRouter = original


def test_discovery_ledger_trace_explains_unmatched_network_without_raw_url(monkeypatch):
    records = []
    _fixture_router(monkeypatch, lambda stage, **data: records.append((stage, data)))
    ledger = discover_module._RequestObservationLedger()
    source = cdp_targets.CdpTargetSource(
        session_path=("secret-session",),
        target_id="secret-target",
        target_type="iframe",
    )
    ledger.add_network(
        source,
        request_id="secret-network",
        method="GET",
        url="https://example.test/private",
        resource_type="Image",
    )
    with pytest.raises(
        cdp_targets.CdpTargetIntegrityError,
        match="observation and request-stage interception ledgers differ",
    ):
        ledger.finish()
    assert len(records) == 1
    stage, context = records[0]
    assert stage == "discovery-ledger-integrity-trace"
    assert context["ledger"]["unmatched_network_total"] == 1
    assert context["ledger"]["unmatched_fetch_total"] == 0
    unmatched = context["ledger"]["unmatched_networks"][0]
    assert unmatched["network_id_sha256"] == sha256(b"secret-network").hexdigest()
    assert unmatched["url_sha256"] == sha256(b"https://example.test/private").hexdigest()
    for secret in ("secret-session", "secret-target", "secret-network", "private"):
        assert secret not in str(context)


def test_discovery_ledger_trace_exposes_bounded_failed_preflight_causality(monkeypatch):
    records = []
    _fixture_router(monkeypatch, lambda stage, **data: records.append((stage, data)))
    ledger = discover_module._RequestObservationLedger(
        eligible=lambda _method, _url: True
    )
    source = cdp_targets.CdpTargetSource((), "secret-target", target_type="page")
    other_source = cdp_targets.CdpTargetSource(
        ("other-session",), "other-target", target_type="iframe"
    )
    url = "https://example.test/private-xhr?secret=1"
    ledger.add_network(
        source,
        request_id="secret-xhr-network",
        method="GET",
        url=url,
        resource_type="XHR",
        initiator_type="script",
        occurrence_id="secret-xhr-occurrence",
        audit_event={"mapping": {"kind": "resource", "resource_id": 7}},
    )

    def add_preflight(index, *, candidate_source=source, candidate_url=url):
        network_id = f"secret-preflight-network-{index}"
        occurrence_id = f"secret-preflight-occurrence-{index}"
        ledger.add_network(
            candidate_source,
            request_id=network_id,
            method="OPTIONS",
            url=candidate_url,
            resource_type="Other",
            initiator_type="preflight",
            initiator_request_id="secret-xhr-network",
            occurrence_id=occurrence_id,
            audit_event={
                "mapping": {"kind": "exclusion", "reason": "unsafe method: OPTIONS"}
            },
        )
        ledger.add_interception(
            candidate_source,
            {
                "requestId": f"secret-preflight-fetch-{index}",
                "networkId": network_id,
                "frameId": "secret-frame",
                "request": {"method": "OPTIONS", "url": candidate_url},
            },
            policy_decision="fail",
            policy_reason="unsafe method: OPTIONS",
        )
        ledger.add_terminal(
            candidate_source,
            network_id,
            outcome="failed",
            event={
                "errorText": "net::ERR_BLOCKED_BY_CLIENT",
                "canceled": False,
                "blockedReason": "inspector",
            },
        )

    for index in range(5):
        add_preflight(index)
    add_preflight("other-source", candidate_source=other_source)
    add_preflight("other-url", candidate_url="https://example.test/other-secret")
    ledger.add_terminal(
        source,
        "secret-xhr-network",
        outcome="failed",
        event={
            "errorText": "net::ERR_BLOCKED_BY_CLIENT",
            "canceled": False,
            "blockedReason": "other",
        },
    )

    with pytest.raises(
        cdp_targets.CdpTargetIntegrityError,
        match="observation and request-stage interception ledgers differ",
    ):
        ledger.finish()
    assert len(records) == 1
    stage, context = records[0]
    assert stage == "discovery-ledger-integrity-trace"
    summary = context["ledger"]
    assert summary["unmatched_network_total"] == 1
    unmatched = summary["unmatched_networks"][0]
    assert unmatched["request_method"] == "GET"
    assert unmatched["resource_type"] == "XHR"
    assert unmatched["initiator_request_id_sha256"] is None
    assert unmatched["terminal_failure"] == {
        "error_code": "net::ERR_BLOCKED_BY_CLIENT",
        "error_text_sha256": sha256(b"net::ERR_BLOCKED_BY_CLIENT").hexdigest(),
        "canceled": False,
        "blocked_reason_code": "other",
        "blocked_reason_sha256": sha256(b"other").hexdigest(),
        "cors_error_status_present": False,
    }
    assert unmatched["audit_mapping"]["kind"] == "resource"
    assert unmatched["preflight_candidate_total"] == 5
    assert unmatched["preflight_candidates_truncated"] is True
    assert len(unmatched["preflight_candidates"]) == 4
    candidate = unmatched["preflight_candidates"][0]
    assert candidate["initiator_request_id_sha256"] == sha256(
        b"secret-xhr-network"
    ).hexdigest()
    assert candidate["causes_unmatched_request"] is True
    assert candidate["terminal_failure"]["blocked_reason_code"] == "inspector"
    assert candidate["audit_mapping"]["reason"]["code"] == "unsafe method: OPTIONS"
    assert candidate["matching_fetch_total"] == 1
    assert candidate["matching_fetches"][0]["policy_decision"] == "fail"
    assert candidate["matching_fetches"][0]["policy_reason"]["code"] == (
        "unsafe method: OPTIONS"
    )
    assert candidate["sequence"] < candidate["terminal_sequence"]
    for secret in (
        "secret-target",
        "secret-xhr-network",
        "secret-xhr-occurrence",
        "secret-preflight-network",
        "secret-preflight-fetch",
        "private-xhr",
        "other-secret",
    ):
        assert secret not in str(context)


def test_discovery_ledger_trace_hashes_unknown_failure_and_mapping_text(monkeypatch):
    records = []
    _fixture_router(monkeypatch, lambda stage, **data: records.append((stage, data)))
    ledger = discover_module._RequestObservationLedger()
    source = cdp_targets.CdpTargetSource((), "secret-target", target_type="page")
    ledger.add_network(
        source,
        request_id="secret-network",
        method="GET",
        url="https://example.test/private",
        resource_type="XHR",
        initiator_type="script",
        initiator_request_id="secret-parent",
        audit_event={"mapping": {"kind": "secret-kind", "reason": "secret-reason"}},
    )
    ledger.add_terminal(
        source,
        "secret-network",
        outcome="failed",
        event={
            "errorText": "secret-error https://example.test/private",
            "canceled": True,
            "blockedReason": "secret-blocked-reason",
            "corsErrorStatus": {"private": "secret-cors"},
        },
    )
    with pytest.raises(cdp_targets.CdpTargetIntegrityError):
        ledger.finish()
    unmatched = records[0][1]["ledger"]["unmatched_networks"][0]
    assert unmatched["initiator_request_id_sha256"] == sha256(b"secret-parent").hexdigest()
    assert unmatched["terminal_failure"]["error_code"] is None
    assert unmatched["terminal_failure"]["error_text_sha256"] == sha256(
        b"secret-error https://example.test/private"
    ).hexdigest()
    assert unmatched["terminal_failure"]["blocked_reason_code"] is None
    assert unmatched["terminal_failure"]["canceled"] is True
    assert unmatched["terminal_failure"]["cors_error_status_present"] is True
    assert unmatched["audit_mapping"]["kind"] is None
    assert unmatched["audit_mapping"]["reason"]["code"] is None
    for secret in (
        "secret-parent",
        "secret-kind",
        "secret-reason",
        "secret-error",
        "secret-blocked-reason",
        "secret-cors",
        "https://example.test/private",
    ):
        assert secret not in str(records)


def test_discovery_ledger_trace_sink_failure_preserves_integrity_error(monkeypatch):
    def broken_emit(_stage, **_data):
        raise OSError("diagnostic sink failed")

    _fixture_router(monkeypatch, broken_emit)
    ledger = discover_module._RequestObservationLedger()
    source = cdp_targets.CdpTargetSource(session_path=(), target_id="root")
    ledger.add_network(
        source,
        request_id="secret-network",
        method="GET",
        url="https://example.test/private",
    )
    with pytest.raises(
        cdp_targets.CdpTargetIntegrityError,
        match="observation and request-stage interception ledgers differ",
    ):
        ledger.finish()
