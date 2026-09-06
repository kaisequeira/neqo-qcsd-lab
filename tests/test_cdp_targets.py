from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from qcsd_lab.acquisition_errors import NonReplayableEgressPolicyError
from qcsd_lab.browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    NonReplayableEgressGuard,
    POPUP_GUARD_MARKER,
    POPUP_NAVIGATION_API,
    TARGET_EGRESS_SHIM_SCHEMA_VERSION,
    target_egress_apis,
)
from qcsd_lab.cdp_targets import (
    BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION,
    BrowserSharedWorkerGuard,
    CDP_TARGET_INSTRUMENTATION_POLICY,
    CdpTargetIntegrityError,
    CdpTargetSource,
    RecursiveCdpTargetRouter,
    validate_bootstrap_prearm_summary,
)


class _FakeNonFlatSession:
    """Minimal recursive non-flat CDP transport with synchronous responses."""

    def __init__(
        self,
        *,
        hold_methods: set[str] | None = None,
        reject_methods: set[str] | None = None,
    ) -> None:
        self.handlers: dict[str, Any] = {}
        self.commands: list[tuple[tuple[str, ...], str, dict[str, Any]]] = []
        self.route_info: dict[tuple[str, ...], dict[str, Any]] = {
            (): {
                "targetId": "root-page",
                "type": "page",
                "url": "https://root.test/",
                "browserContextId": "root-context",
            }
        }
        self.hold_methods = hold_methods or set()
        self.reject_methods = reject_methods or set()
        self.held: list[tuple[tuple[str, ...], int, str, dict[str, Any]]] = []
        self.guard_adoptions: dict[str, tuple[str, dict[str, Any]]] = {}
        self.adoption_result_session_id: str | None = None
        self.emit_adoption_attachment = True
        self.before_adoption_attachment: Any = None
        self.before_nested_command: Any = None

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        parameters = dict(params or {})
        self.commands.append(((), method, parameters))
        if method == "Target.getTargetInfo":
            return {"targetInfo": dict(self.route_info[()])}
        if method == "Target.attachToTarget":
            target_id = parameters.get("targetId")
            if parameters.get("flatten") is not False or target_id not in self.guard_adoptions:
                raise AssertionError("unexpected guarded Target.attachToTarget command")
            page_session_id, target_info = self.guard_adoptions[target_id]
            route = (page_session_id,)
            self.route_info[route] = dict(target_info)
            before_attachment = self.before_adoption_attachment
            if before_attachment is not None:
                # Model Chromium delivering the owner-side Fetch pause while
                # the synchronous non-flat adoption command is still in
                # flight, before its child attachment event and result.
                self.before_adoption_attachment = None
                before_attachment()
            if self.emit_adoption_attachment:
                self.handlers["Target.attachedToTarget"](
                    {
                        "sessionId": page_session_id,
                        "targetInfo": dict(target_info),
                        "waitingForDebugger": False,
                    }
                )
            return {
                "sessionId": self.adoption_result_session_id or page_session_id,
            }
        if method == "Target.sendMessageToTarget":
            session_id = parameters["sessionId"]
            route = (session_id,)
            self._process(route, json.loads(parameters["message"]))
        return self._result((), method, parameters)

    def attach(
        self,
        parent_route: tuple[str, ...],
        *,
        session_id: str,
        target_id: str,
        target_type: str,
        waiting: bool = True,
        parent_frame_id: str | None = None,
        target_url: str | None = None,
        browser_context_id: str | None = "root-context",
    ) -> tuple[str, ...]:
        route = (*parent_route, session_id)
        target_info = {"targetId": target_id, "type": target_type}
        if target_url is not None:
            target_info["url"] = target_url
        if browser_context_id is not None:
            target_info["browserContextId"] = browser_context_id
        self.route_info[route] = target_info
        params = {
            "sessionId": session_id,
            "targetInfo": dict(target_info),
            "waitingForDebugger": waiting,
        }
        if parent_frame_id is not None:
            params["targetInfo"]["parentFrameId"] = parent_frame_id
        if parent_route:
            self._deliver(
                parent_route,
                {"method": "Target.attachedToTarget", "params": params},
            )
        else:
            self.handlers["Target.attachedToTarget"](params)
        return route

    def prepare_guarded_adoption(
        self,
        *,
        target_id: str,
        page_session_id: str,
        target_url: str | None,
        browser_context_id: str = "root-context",
    ) -> None:
        self.guard_adoptions[target_id] = (
            page_session_id,
            {
                "targetId": target_id,
                "type": "shared_worker",
                "url": target_url,
                "browserContextId": browser_context_id,
                "attached": True,
            },
        )

    def detach(self, parent_route: tuple[str, ...], *, session_id: str) -> None:
        route = (*parent_route, session_id)
        params = {
            "sessionId": session_id,
            "targetId": self.route_info[route]["targetId"],
        }
        if parent_route:
            self._deliver(
                parent_route,
                {"method": "Target.detachedFromTarget", "params": params},
            )
        else:
            self.handlers["Target.detachedFromTarget"](params)

    def emit(self, route: tuple[str, ...], method: str, params: Mapping[str, Any]) -> None:
        if route:
            self._deliver(route, {"method": method, "params": dict(params)})
        else:
            self.handlers[method](dict(params))

    def _process(self, route: tuple[str, ...], payload: Mapping[str, Any]) -> None:
        command_id = payload["id"]
        method = payload["method"]
        params = dict(payload.get("params", {}))
        self.commands.append((route, method, params))
        before_command = self.before_nested_command
        if before_command is not None:
            self.before_nested_command = None
            before_command(route, method)
        if method in self.reject_methods:
            raise RuntimeError(f"rejected test command: {method}")
        if method in self.hold_methods:
            self.held.append((route, command_id, method, self._result(route, method, params)))
            return
        self._deliver(route, {"id": command_id, "result": self._result(route, method, params)})
        if method == "Target.sendMessageToTarget":
            child_route = (*route, params["sessionId"])
            self._process(child_route, json.loads(params["message"]))

    def release_held(self, method: str) -> None:
        selected = next((item for item in self.held if item[2] == method), None)
        if selected is None:
            raise AssertionError(f"no held command for {method}")
        self.held.remove(selected)
        route, command_id, _method, result = selected
        self._deliver(route, {"id": command_id, "result": result})

    def _result(
        self,
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if method == "Target.getTargetInfo":
            return {"targetInfo": dict(self.route_info[route])}
        if method == "Page.addScriptToEvaluateOnNewDocument":
            return {"identifier": f"init-{'-'.join(route) or 'root'}"}
        if method == "Runtime.evaluate":
            expression = str((params or {}).get("expression", ""))
            if POPUP_GUARD_MARKER in expression and "=== true" in expression:
                return {"result": {"type": "boolean", "value": True}}
            target_type = str(self.route_info[route]["type"])
            return {
                "result": {
                    "type": "object",
                    "value": {
                        "schema_version": TARGET_EGRESS_SHIM_SCHEMA_VERSION,
                        "policy": NON_REPLAYABLE_EGRESS_POLICY,
                        "protected_apis": [],
                        "unavailable_apis": sorted(target_egress_apis(target_type)),
                        "failed_apis": [],
                        "already_installed": target_type in {"page", "iframe"},
                    },
                }
            }
        return {}

    def _deliver(self, route: tuple[str, ...], payload: Mapping[str, Any]) -> None:
        if not route:
            raise AssertionError("root events use their direct CDP event handler")
        nested: Mapping[str, Any] = payload
        for index in range(len(route) - 1, 0, -1):
            child_route = route[: index + 1]
            nested = {
                "method": "Target.receivedMessageFromTarget",
                "params": {
                    "sessionId": route[index],
                    "targetId": self.route_info[child_route]["targetId"],
                    "message": json.dumps(nested),
                },
            }
        first_route = route[:1]
        self.handlers["Target.receivedMessageFromTarget"](
            {
                "sessionId": route[0],
                "targetId": self.route_info[first_route]["targetId"],
                "message": json.dumps(nested),
            }
        )


class _FakeBrowserSession:
    """Minimal browser-level flat target guard transport."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.commands: list[tuple[str, dict[str, Any]]] = []
        self.detached = False
        self.close_success: object = True
        self.emit_popup_detach = True
        self.emit_popup_destroy = True
        self.auto_attach_root_tab = True
        self.attached_targets: dict[str, tuple[str, dict[str, Any]]] = {}
        self.root_tab_info: dict[str, Any] = {
            "targetId": "root-tab",
            "type": "tab",
            "url": "https://root.test/",
            "browserContextId": "root-context",
            "attached": True,
        }
        self.target_infos: list[dict[str, Any]] = [
            {
                "targetId": "root-page",
                "type": "page",
                "url": "https://root.test/",
                "browserContextId": "root-context",
                "attached": True,
            }
        ]

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        parameters = dict(params or {})
        self.commands.append((method, parameters))
        if (
            method == "Target.setAutoAttach"
            and parameters.get("autoAttach") is True
            and self.auto_attach_root_tab
        ):
            self.auto_attach_root_tab = False
            root_tab = dict(self.root_tab_info)
            self.attached_targets["root-tab-session"] = (
                "root-tab",
                dict(root_tab),
            )
            self.handlers["Target.attachedToTarget"](
                {
                    "sessionId": "root-tab-session",
                    "targetInfo": dict(root_tab),
                    "waitingForDebugger": False,
                }
            )
        if method == "Target.getTargets":
            return {"targetInfos": [dict(info) for info in self.target_infos]}
        if method == "Target.closeTarget":
            target_id = parameters.get("targetId")
            matching = [
                (session_id, info)
                for session_id, (attached_target_id, info) in self.attached_targets.items()
                if attached_target_id == target_id
            ]
            if self.emit_popup_detach and len(matching) == 1:
                session_id, _info = matching[0]
                self.handlers["Target.detachedFromTarget"](
                    {"sessionId": session_id, "targetId": target_id}
                )
            if self.emit_popup_destroy and isinstance(target_id, str):
                self.handlers["Target.targetDestroyed"]({"targetId": target_id})
            return {"success": self.close_success}
        return {}

    def page_target_event(
        self,
        *,
        target_id: str,
        browser_context_id: str,
        method: str = "Target.targetCreated",
    ) -> None:
        self.handlers[method](
            {
                "targetInfo": {
                    "targetId": target_id,
                    "type": "page",
                    "url": "about:blank",
                    "browserContextId": browser_context_id,
                    "attached": False,
                }
            }
        )

    def attach(
        self,
        *,
        guardian_session_id: str,
        target_id: str,
        target_type: str = "shared_worker",
        target_url: str,
        browser_context_id: str = "root-context",
        waiting: bool = True,
        attached: bool = True,
    ) -> None:
        target_info = {
            "targetId": target_id,
            "type": target_type,
            "url": target_url,
            "browserContextId": browser_context_id,
            "attached": attached,
        }
        self.attached_targets[guardian_session_id] = (target_id, dict(target_info))
        self.handlers["Target.attachedToTarget"](
            {
                "sessionId": guardian_session_id,
                "targetInfo": target_info,
                "waitingForDebugger": waiting,
            }
        )

    def detach(
        self,
        *,
        guardian_session_id: str | None = None,
        target_id: str | None = None,
    ) -> None:
        if guardian_session_id is None and target_id is None:
            self.detached = True
            return
        if guardian_session_id is None or target_id is None:
            raise AssertionError("guardian detach identity must be complete")
        self.handlers["Target.detachedFromTarget"](
            {"sessionId": guardian_session_id, "targetId": target_id}
        )


_ROUTER_GUARDS: dict[
    RecursiveCdpTargetRouter, tuple[_FakeBrowserSession, BrowserSharedWorkerGuard]
] = {}


def _router(
    session: _FakeNonFlatSession,
    *,
    fetch_policy: Any = None,
    on_non_replayable_egress: Any = None,
) -> tuple[
    RecursiveCdpTargetRouter,
    list[tuple[CdpTargetSource, str, Mapping[str, Any]]],
]:
    observed: list[tuple[CdpTargetSource, str, Mapping[str, Any]]] = []
    router_holder: list[RecursiveCdpTargetRouter] = []

    def on_event(source: CdpTargetSource, method: str, event: Mapping[str, Any]) -> None:
        observed.append((source, method, event))
        if method != "Fetch.requestPaused":
            return
        decision = (
            ("Fetch.continueRequest", {"requestId": event["requestId"]})
            if fetch_policy is None
            else fetch_policy(source, event)
        )
        if decision is not None:
            command, params = decision
            router_holder[0].send(
                source,
                command,
                params,
                label=f"test-policy:{command}",
            )

    router = RecursiveCdpTargetRouter(
        session,
        on_event=on_event,
        on_non_replayable_egress=on_non_replayable_egress,
    )
    router_holder.append(router)
    router.start()
    browser_session = _FakeBrowserSession()
    guard = BrowserSharedWorkerGuard(browser_session, router)
    guard.start()
    _ROUTER_GUARDS[router] = (browser_session, guard)
    return router, observed


def _guard_for(
    router: RecursiveCdpTargetRouter,
) -> tuple[_FakeBrowserSession, BrowserSharedWorkerGuard]:
    return _ROUTER_GUARDS[router]


def _begin_shutdown(router: RecursiveCdpTargetRouter) -> None:
    _browser_session, guard = _guard_for(router)
    router.begin_shutdown()
    guard.begin_shutdown()


def _finish(router: RecursiveCdpTargetRouter) -> None:
    _browser_session, guard = _guard_for(router)
    guard.finish()
    router.finish()


def _clean_shutdown(router: RecursiveCdpTargetRouter) -> None:
    _begin_shutdown(router)
    _finish(router)


def _complete_request(
    session: _FakeNonFlatSession,
    route: tuple[str, ...],
    request_id: str,
    url: str,
) -> None:
    session.emit(
        route,
        "Network.requestWillBeSent",
        {"requestId": request_id, "request": {"method": "GET", "url": url}},
    )
    session.emit(route, "Network.loadingFinished", {"requestId": request_id})


def _begin_script_bootstrap(
    session: _FakeNonFlatSession,
    route: tuple[str, ...],
    *,
    target_id: str,
    target_url: str,
    frame_id: str,
) -> None:
    session.emit(
        route,
        "Network.requestWillBeSent",
        {
            "requestId": target_id,
            "loaderId": f"loader-{target_id}",
            "frameId": frame_id,
            "type": "Script",
            "request": {"method": "GET", "url": target_url},
        },
    )


def _pause_script_bootstrap(
    session: _FakeNonFlatSession,
    route: tuple[str, ...],
    *,
    target_id: str,
    target_url: str,
    frame_id: str,
    request_id: str | None = None,
    resource_type: str = "Other",
) -> None:
    session.emit(
        route,
        "Fetch.requestPaused",
        {
            "requestId": request_id or f"fetch-{target_id}",
            "networkId": target_id,
            "frameId": frame_id,
            "resourceType": resource_type,
            "request": {"method": "GET", "url": target_url},
        },
    )


def _attach_worker(
    session: _FakeNonFlatSession,
    parent_route: tuple[str, ...],
    *,
    session_id: str,
    target_id: str,
    target_url: str | None = None,
    parent_frame_id: str | None = None,
    waiting: bool = True,
) -> tuple[str, ...]:
    url = target_url or f"https://worker.test/{target_id}.js"
    frame_id = parent_frame_id or (
        "root-frame" if not parent_route else session.route_info[parent_route]["targetId"]
    )
    _begin_script_bootstrap(
        session,
        parent_route,
        target_id=target_id,
        target_url=url,
        frame_id=frame_id,
    )
    worker_route = session.attach(
        parent_route,
        session_id=session_id,
        target_id=target_id,
        target_type="worker",
        waiting=waiting,
        parent_frame_id=frame_id,
        target_url=url,
    )
    _pause_script_bootstrap(
        session,
        parent_route,
        target_id=target_id,
        target_url=url,
        frame_id=frame_id,
    )
    return worker_route


def _start_shared_worker_guard(
    page_session: _FakeNonFlatSession,
    router: RecursiveCdpTargetRouter,
) -> tuple[_FakeBrowserSession, BrowserSharedWorkerGuard]:
    del page_session
    return _guard_for(router)


def test_policy_is_pinned_and_root_is_instrumented_before_navigation() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)

    assert CDP_TARGET_INSTRUMENTATION_POLICY == (
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v10"
    )
    assert [method for route, method, _params in session.commands if route == ()] == [
        "Target.getTargetInfo",
        "Debugger.enable",
        "Network.enable",
        "Network.setCacheDisabled",
        "Network.setBypassServiceWorker",
        "Runtime.enable",
        "Runtime.addBinding",
        "Page.addScriptToEvaluateOnNewDocument",
        "Runtime.evaluate",
        "Runtime.evaluate",
        "Fetch.enable",
        "Target.setAutoAttach",
        "Target.getTargetInfo",
    ]
    _clean_shutdown(router)


def test_oopif_and_worker_are_fully_configured_before_resume() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    worker = _attach_worker(session, (), session_id="worker-session", target_id="worker-target")

    iframe_expected = [
        "Debugger.enable",
        "Network.enable",
        "Network.setCacheDisabled",
        "Network.setBypassServiceWorker",
        "Runtime.enable",
        "Runtime.addBinding",
        "Page.addScriptToEvaluateOnNewDocument",
        "Fetch.enable",
        "Runtime.evaluate",
        "Runtime.evaluate",
        "Target.setAutoAttach",
        "Target.getTargetInfo",
        "Runtime.runIfWaitingForDebugger",
    ]
    worker_expected = [
        "Debugger.enable",
        "Network.enable",
        "Network.setCacheDisabled",
        "Network.setBypassServiceWorker",
        "Runtime.enable",
        "Runtime.addBinding",
        "Runtime.evaluate",
        "Target.setAutoAttach",
        "Target.getTargetInfo",
        "Runtime.runIfWaitingForDebugger",
    ]
    assert [
        method for seen, method, _params in session.commands if seen == iframe
    ] == iframe_expected
    assert [
        method for seen, method, _params in session.commands if seen == worker
    ] == worker_expected

    _complete_request(session, iframe, "same-request-id", "https://frame.test/a")
    _complete_request(session, worker, "same-request-id", "https://worker.test/a")
    request_sources = [
        source
        for source, method, event in observed
        if method == "Network.requestWillBeSent" and event.get("requestId") == "same-request-id"
    ]
    assert request_sources[0].request_chain_key("same-request-id") != (
        request_sources[1].request_chain_key("same-request-id")
    )

    session.detach((), session_id="iframe-session")
    session.detach((), session_id="worker-session")
    _clean_shutdown(router)


def test_iframe_attachment_rejects_an_explicit_foreign_browser_context() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)

    session.attach(
        (),
        session_id="foreign-iframe-session",
        target_id="foreign-iframe-target",
        target_type="iframe",
        parent_frame_id="root-frame",
        browser_context_id="foreign-context",
    )

    with pytest.raises(CdpTargetIntegrityError, match="foreign browser context"):
        router.raise_if_failed()


def test_iframe_attachment_accepts_an_omitted_optional_browser_context() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)

    route = session.attach(
        (),
        session_id="contextless-iframe-session",
        target_id="contextless-iframe-target",
        target_type="iframe",
        parent_frame_id="root-frame",
        browser_context_id=None,
    )
    router.raise_if_failed()
    session.detach((), session_id=route[-1])
    _clean_shutdown(router)


def test_iframe_setup_barrier_rejects_a_late_foreign_browser_context() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.hold_methods.add("Target.getTargetInfo")
    session.attach(
        (),
        session_id="changed-iframe-session",
        target_id="changed-iframe-target",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    held = next(item for item in session.held if item[2] == "Target.getTargetInfo")
    held[3]["targetInfo"]["browserContextId"] = "foreign-context"
    session.release_held("Target.getTargetInfo")

    with pytest.raises(CdpTargetIntegrityError, match="foreign browser context"):
        router.raise_if_failed()


@pytest.mark.parametrize("target_kind", ("root", "iframe"))
@pytest.mark.parametrize("policy_method", ("Fetch.continueRequest", "Fetch.failRequest"))
def test_fetch_policy_decision_requires_an_exact_empty_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
    target_kind: str,
    policy_method: str,
) -> None:
    session = _FakeNonFlatSession()
    original_result = session._result

    def non_empty_policy_result(
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if method == policy_method:
            return {"unexpected": True}
        return original_result(route, method, params)

    monkeypatch.setattr(session, "_result", non_empty_policy_result)

    def policy(_source: CdpTargetSource, event: Mapping[str, Any]):
        params: dict[str, Any] = {"requestId": event["requestId"]}
        if policy_method == "Fetch.failRequest":
            params["errorReason"] = "BlockedByClient"
        return policy_method, params

    router, _observed = _router(session, fetch_policy=policy)
    route: tuple[str, ...] = ()
    if target_kind == "iframe":
        route = session.attach(
            (),
            session_id="policy-iframe-session",
            target_id="policy-iframe-target",
            target_type="iframe",
            parent_frame_id="root-frame",
        )
    session.emit(
        route,
        "Fetch.requestPaused",
        {
            "requestId": f"{target_kind}-policy-request",
            "resourceType": "Image",
            "request": {"method": "GET", "url": "https://resource.test/image.png"},
        },
    )

    with pytest.raises(CdpTargetIntegrityError, match="exact empty result"):
        router.raise_if_failed()


def test_dedicated_worker_setup_waits_for_late_bootstrap_owner_before_resume() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    target_id = "late-worker-target"
    target_url = "https://worker.test/late-worker.js"
    route = session.attach(
        (),
        session_id="late-worker-session",
        target_id=target_id,
        target_type="worker",
        parent_frame_id="root-frame",
        target_url=target_url,
    )

    assert not any(
        command_route == route and method == "Runtime.runIfWaitingForDebugger"
        for command_route, method, _params in session.commands
    )

    _begin_script_bootstrap(
        session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    assert (
        sum(
            command_route == route and method == "Runtime.runIfWaitingForDebugger"
            for command_route, method, _params in session.commands
        )
        == 1
    )
    _pause_script_bootstrap(
        session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    assert (
        sum(
            command_route == route and method == "Runtime.runIfWaitingForDebugger"
            for command_route, method, _params in session.commands
        )
        == 1
    )
    assert any(
        command_route == ()
        and method == "Fetch.continueRequest"
        and params == {"requestId": f"fetch-{target_id}"}
        for command_route, method, params in session.commands
    )

    session.emit(route, "Network.loadingFinished", {"requestId": target_id})
    session.detach((), session_id=route[-1])
    _clean_shutdown(router)


def test_worker_subresource_extra_info_migrates_from_exact_bootstrap_owner() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    worker = _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    session.emit(
        worker,
        "Network.loadingFinished",
        {"requestId": "worker-target"},
    )
    session.emit(
        worker,
        "Network.requestWillBeSent",
        {
            "requestId": "worker-data",
            "type": "Fetch",
            "request": {
                "method": "GET",
                "url": "https://worker.test/data",
            },
        },
    )
    session.emit(
        (),
        "Network.requestWillBeSentExtraInfo",
        {"requestId": "worker-data", "headers": {}},
    )

    migrated = [
        source
        for source, method, event in observed
        if method == "Network.requestWillBeSentExtraInfo"
        and event.get("requestId") == "worker-data"
    ]
    assert len(migrated) == 1
    assert migrated[0].session_path == worker

    session.emit(worker, "Network.loadingFinished", {"requestId": "worker-data"})
    session.detach((), session_id="worker-session")
    _clean_shutdown(router)


def test_worker_subresource_extra_info_migration_must_be_unique() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    workers = [
        _attach_worker(
            session,
            (),
            session_id=f"worker-session-{index}",
            target_id=f"worker-target-{index}",
        )
        for index in range(2)
    ]
    for index, worker in enumerate(workers):
        session.emit(
            worker,
            "Network.requestWillBeSent",
            {
                "requestId": "colliding-worker-data",
                "type": "Fetch",
                "request": {
                    "method": "GET",
                    "url": f"https://worker.test/data-{index}",
                },
            },
        )
    session.emit(
        (),
        "Network.requestWillBeSentExtraInfo",
        {"requestId": "colliding-worker-data", "headers": {}},
    )

    with pytest.raises(CdpTargetIntegrityError, match="ExtraInfo migration is ambiguous"):
        router.raise_if_failed()


def test_nested_related_target_is_instrumented_through_parent_transport() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    nested = _attach_worker(
        session,
        iframe,
        session_id="nested-worker-session",
        target_id="nested-worker-target",
    )

    _complete_request(
        session,
        nested,
        "nested-request",
        "https://frame.test/worker-data.json",
    )
    session.emit(
        nested,
        "Network.loadingFinished",
        {"requestId": "nested-worker-target"},
    )
    assert any(source.session_path == nested for source, _method, _event in observed)
    assert any(
        route == iframe and method == "Target.sendMessageToTarget"
        for route, method, _params in session.commands
    )

    session.detach(iframe, session_id="nested-worker-session")
    session.detach((), session_id="iframe-session")
    _clean_shutdown(router)


def test_reattached_target_receives_a_new_collision_safe_generation() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    first = session.attach(
        (), session_id="first-session", target_id="frame-target", target_type="iframe"
    )
    _complete_request(session, first, "request", "https://frame.test/first")
    session.detach((), session_id="first-session")
    second = session.attach(
        (), session_id="second-session", target_id="frame-target", target_type="iframe"
    )
    _complete_request(session, second, "request", "https://frame.test/second")
    sources = [
        source
        for source, method, event in observed
        if method == "Network.requestWillBeSent" and event.get("requestId") == "request"
    ]
    assert [source.generation for source in sources] == [0, 1]
    assert sources[0].request_chain_key("request") != sources[1].request_chain_key("request")
    session.detach((), session_id="second-session")
    _clean_shutdown(router)


def test_oopif_terminal_events_route_to_the_root_request_occurrence() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    iframe = session.attach(
        (),
        session_id="iframe-session",
        target_id="frame-id",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    session.emit(
        (),
        "Network.requestWillBeSent",
        {
            "requestId": "navigation",
            "loaderId": "navigation",
            "frameId": "frame-id",
            "type": "Document",
            "request": {"method": "GET", "url": "https://frame.test/"},
        },
    )
    for method, payload in (
        ("Network.responseReceived", {"requestId": "navigation", "response": {}}),
        ("Network.requestWillBeSentExtraInfo", {"requestId": "navigation", "headers": {}}),
        ("Network.loadingFinished", {"requestId": "navigation"}),
    ):
        session.emit(iframe, method, payload)

    routed = [source for source, method, _event in observed if method.startswith("Network.")]
    assert len(routed) == 4
    assert all(source.session_path == () for source in routed)
    session.detach((), session_id="iframe-session")
    _clean_shutdown(router)


def test_oopif_redirect_request_keeps_the_root_canonical_source() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    iframe = session.attach((), session_id="iframe", target_id="frame-id", target_type="iframe")
    first = {
        "requestId": "navigation",
        "loaderId": "navigation",
        "frameId": "frame-id",
        "type": "Document",
        "request": {"method": "GET", "url": "https://frame.test/first"},
    }
    session.emit((), "Network.requestWillBeSent", first)
    session.emit(
        iframe,
        "Network.requestWillBeSent",
        {
            **first,
            "redirectResponse": {"status": 302},
            "request": {"method": "GET", "url": "https://frame.test/final"},
        },
    )
    session.emit(iframe, "Network.loadingFinished", {"requestId": "navigation"})
    sources = [source for source, method, _event in observed if method.startswith("Network.")]
    assert len(sources) == 3
    assert all(source.session_path == () for source in sources)
    session.detach((), session_id="iframe")
    _clean_shutdown(router)


def test_oopif_migration_with_two_plausible_origins_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach((), session_id="iframe", target_id="frame-id", target_type="iframe")
    worker = _attach_worker(session, (), session_id="worker", target_id="worker-id")
    event = {
        "requestId": "collision",
        "loaderId": "collision",
        "frameId": "frame-id",
        "type": "Document",
        "request": {"method": "GET", "url": "https://frame.test/"},
    }
    session.emit((), "Network.requestWillBeSent", event)
    session.emit(worker, "Network.requestWillBeSent", event)
    session.emit(
        iframe,
        "Network.requestWillBeSent",
        {**event, "redirectResponse": {"status": 302}},
    )
    with pytest.raises(CdpTargetIntegrityError, match="migration is ambiguous"):
        router.raise_if_failed()


def test_duplicate_session_identity_on_another_branch_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    _attach_worker(session, (), session_id="duplicate-session", target_id="first-worker")
    _attach_worker(
        session,
        iframe,
        session_id="duplicate-session",
        target_id="second-worker",
    )

    with pytest.raises(CdpTargetIntegrityError, match="identity was reused"):
        router.raise_if_failed()


@pytest.mark.parametrize("target_type", ["service_worker", "page", "other"])
def test_unsupported_related_target_types_fail_closed(target_type: str) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.attach(
        (),
        session_id="unsupported-session",
        target_id="unsupported-target",
        target_type=target_type,
    )

    with pytest.raises(CdpTargetIntegrityError, match="worker|unsupported"):
        router.raise_if_failed()


def test_child_network_event_during_enable_race_fails_closed() -> None:
    session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(session)
    worker = _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    session.emit(
        worker,
        "Network.requestWillBeSent",
        {
            "requestId": "too-early",
            "request": {"method": "GET", "url": "https://worker.test/data"},
        },
    )

    with pytest.raises(
        CdpTargetIntegrityError,
        match=r"worker target emitted Network\.requestWillBeSent.*during configuring",
    ):
        router.raise_if_failed()


def test_detach_during_setup_is_normal_for_a_short_lived_worker() -> None:
    session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(session)
    _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    session.detach((), session_id="worker-session")

    router.raise_if_failed()


def test_detach_with_active_request_or_live_descendant_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    _attach_worker(
        session,
        iframe,
        session_id="nested-session",
        target_id="nested-target",
    )
    session.emit(
        iframe,
        "Network.requestWillBeSent",
        {
            "requestId": "active",
            "request": {"method": "GET", "url": "https://frame.test/data"},
        },
    )
    session.detach((), session_id="iframe-session")

    with pytest.raises(CdpTargetIntegrityError, match="work pending"):
        router.raise_if_failed()


def test_deliberate_shutdown_drains_long_lived_child_before_detach() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    session.emit(
        worker,
        "Network.requestWillBeSent",
        {
            "requestId": "long-lived",
            "request": {"method": "GET", "url": "https://worker.test/events"},
        },
    )

    _begin_shutdown(router)
    session.emit(worker, "Network.loadingFailed", {"requestId": "long-lived"})
    session.detach((), session_id="worker-session")
    _finish(router)


def test_target_attachment_after_shutdown_boundary_is_positively_resumed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    _begin_shutdown(router)
    session.attach(
        (),
        session_id="late-session",
        target_id="late-target",
        target_type="worker",
        parent_frame_id="root-frame",
        target_url="https://worker.test/late.js",
    )

    _finish(router)
    assert [
        method for route, method, _params in session.commands if route == ("late-session",)
    ] == ["Runtime.runIfWaitingForDebugger"]


def test_late_shutdown_attachment_cannot_leave_resume_unresolved() -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.runIfWaitingForDebugger"})
    router, _observed = _router(session)
    _begin_shutdown(router)
    session.attach(
        (),
        session_id="late-session",
        target_id="late-target",
        target_type="worker",
        parent_frame_id="root-frame",
        target_url="https://worker.test/late.js",
    )
    with pytest.raises(CdpTargetIntegrityError, match="shutdown commands remain unresolved"):
        _finish(router)


@pytest.mark.parametrize(
    "method", ["Inspector.targetCrashed", "Target.targetCrashed", "Target.targetDestroyed"]
)
def test_child_crash_or_unknown_lifecycle_cannot_look_like_clean_detach(
    method: str,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    session.emit(worker, method, {"targetId": "worker-target"})
    session.detach((), session_id="worker-session")

    with pytest.raises(CdpTargetIntegrityError, match="crashed|destroyed"):
        router.raise_if_failed()


def test_known_target_info_change_and_post_detach_destruction_are_validated() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    session.emit(
        (),
        "Target.targetInfoChanged",
        {
            "targetInfo": {
                "targetId": "worker-target",
                "type": "worker",
                "url": "https://worker.test/worker.js",
            }
        },
    )
    session.detach((), session_id="worker-session")
    session.emit((), "Target.targetDestroyed", {"targetId": "worker-target"})

    _clean_shutdown(router)


def test_unknown_nested_target_lifecycle_message_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    session.emit(worker, "Target.futureLifecycleEvent", {})

    with pytest.raises(CdpTargetIntegrityError, match="unsupported nested"):
        router.raise_if_failed()


def test_child_cache_policy_violation_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    session.emit(worker, "Network.requestServedFromCache", {"requestId": "cached"})

    with pytest.raises(CdpTargetIntegrityError, match="served a request from cache"):
        router.raise_if_failed()


def test_result_bearing_child_command_is_rejected_instead_of_discarded() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    source = CdpTargetSource(worker, "worker-target")

    with pytest.raises(CdpTargetIntegrityError, match="result-bearing"):
        router.send(
            source,
            "Network.getResponseBody",
            {"requestId": "request"},
            label="response-body",
        )


def test_finish_tolerates_context_disposal_before_related_detach_callback() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    _attach_worker(session, (), session_id="worker-session", target_id="worker-target")
    _clean_shutdown(router)


def test_shared_worker_guard_installs_the_exact_browser_level_filter() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)

    assert browser_session.commands == [
        (
            "Target.setDiscoverTargets",
            {
                "discover": True,
                    "filter": [
                        {"type": "page", "exclude": False},
                        {"type": "service_worker", "exclude": False},
                        {"exclude": True},
                ],
            },
        ),
        (
            "Target.setAutoAttach",
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": True,
                "flatten": True,
                "filter": [
                    {"type": "shared_worker", "exclude": False},
                    {"type": "tab", "exclude": False},
                    {"exclude": True},
                ],
            },
        ),
        ("Target.getTargets", {}),
    ]
    _clean_shutdown(router)
    assert browser_session.commands[-1] == (
        "Target.setDiscoverTargets",
        {"discover": False},
    )
    assert browser_session.detached is True


def test_browser_guard_tracks_exactly_one_unpaused_root_tab_without_adoption() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)

    assert not [
        command
        for command in page_session.commands
        if command[1] == "Target.attachToTarget"
        and command[2].get("targetId") == "root-tab"
    ]
    assert not [command for command in browser_session.commands if command[0] == "Target.closeTarget"]
    router.raise_if_failed()
    _clean_shutdown(router)


def test_browser_guard_start_fails_without_the_unpaused_root_tab_attachment() -> None:
    page_session = _FakeNonFlatSession()
    router = RecursiveCdpTargetRouter(page_session, on_event=lambda *_args: None)
    router.start()
    browser_session = _FakeBrowserSession()
    browser_session.auto_attach_root_tab = False

    with pytest.raises(CdpTargetIntegrityError, match="exactly one unpaused root tab"):
        BrowserSharedWorkerGuard(browser_session, router).start()


def test_waiting_popup_tab_is_receipted_closed_and_never_adopted() -> None:
    attempts: list[tuple[CdpTargetSource | None, str, str, object | None]] = []
    page_session = _FakeNonFlatSession()
    router, _observed = _router(
        page_session,
        on_non_replayable_egress=lambda source, api, mechanism, url: attempts.append(
            (source, api, mechanism, url)
        ),
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)

    browser_session.attach(
        guardian_session_id="popup-tab-session",
        target_id="popup-tab",
        target_type="tab",
        target_url="https://popup.test/landing?private=discarded",
        waiting=True,
    )

    assert attempts == [
        (
            None,
            POPUP_NAVIGATION_API,
            "browser-popup-tab-tripwire",
            "https://popup.test/landing?private=discarded",
        )
    ]
    assert ("Target.closeTarget", {"targetId": "popup-tab"}) in browser_session.commands
    assert not [
        command
        for command in browser_session.commands
        if command[0] == "Runtime.runIfWaitingForDebugger"
    ]
    assert not [
        command
        for command in page_session.commands
        if command[1] == "Target.attachToTarget"
        and command[2].get("targetId") == "popup-tab"
    ]
    popup = guard._popup_tabs["popup-tab"]
    assert popup.close_requested is True
    assert popup.close_acknowledged is True
    assert popup.detached is True
    assert popup.destroyed is True
    router.raise_if_failed()

    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


def test_popup_tab_callback_produces_typed_content_minimised_evidence() -> None:
    egress_guard = NonReplayableEgressGuard()
    egress_guard.mark_context_guards_installed()
    egress_guard.bind_root_page(object())
    page_session = _FakeNonFlatSession()
    router, _observed = _router(
        page_session,
        on_non_replayable_egress=lambda source, api, mechanism, url: egress_guard.record(
            source=source,
            api=api,
            mechanism=mechanism,
            url=url,
        ),
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    browser_session.attach(
        guardian_session_id="popup-tab-session",
        target_id="popup-tab",
        target_type="tab",
        target_url="https://user:secret@popup.test/private/path?token=discard#fragment",
        waiting=True,
    )

    with pytest.raises(NonReplayableEgressPolicyError) as caught:
        egress_guard.raise_if_failed()
    attempt = caught.value.evidence["non_replayable_egress"]["attempts"][0]
    assert attempt == {
        "sequence": 0,
        "monotonic_ms": attempt["monotonic_ms"],
        "api": POPUP_NAVIGATION_API,
        "mechanism": "browser-popup-tab-tripwire",
        "source": None,
        "url": {"scheme": "https", "origin": "https://popup.test"},
    }

    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


@pytest.mark.parametrize("close_success", [False, 1, None, "true"])
def test_popup_tab_close_acknowledgement_is_exact(close_success: object) -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(
        page_session,
        on_non_replayable_egress=lambda *_args: None,
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    browser_session.close_success = close_success

    browser_session.attach(
        guardian_session_id="popup-tab-session",
        target_id="popup-tab",
        target_type="tab",
        target_url=None,
        waiting=True,
    )

    with pytest.raises(CdpTargetIntegrityError, match="close was not acknowledged"):
        router.raise_if_failed()
    router.begin_abort()
    guard.begin_abort()
    with pytest.raises(CdpTargetIntegrityError, match="acknowledgement remains unresolved"):
        guard.finish_abort()


def test_popup_tab_detach_and_destruction_lifecycle_is_identity_checked() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(
        page_session,
        on_non_replayable_egress=lambda *_args: None,
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    browser_session.emit_popup_detach = False
    browser_session.emit_popup_destroy = False
    browser_session.attach(
        guardian_session_id="popup-tab-session",
        target_id="popup-tab",
        target_type="tab",
        target_url="about:blank",
        waiting=True,
    )
    browser_session.detach(
        guardian_session_id="popup-tab-session",
        target_id="wrong-popup-tab",
    )

    with pytest.raises(CdpTargetIntegrityError, match="popup browser tab detach changed identity"):
        router.raise_if_failed()
    browser_session.detach(
        guardian_session_id="popup-tab-session",
        target_id="popup-tab",
    )
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


def test_popup_tab_duplicate_destruction_fails_closed() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(
        page_session,
        on_non_replayable_egress=lambda *_args: None,
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    browser_session.attach(
        guardian_session_id="popup-tab-session",
        target_id="popup-tab",
        target_type="tab",
        target_url="about:blank",
        waiting=True,
    )
    browser_session.handlers["Target.targetDestroyed"]({"targetId": "popup-tab"})

    with pytest.raises(CdpTargetIntegrityError, match="destruction violated"):
        router.raise_if_failed()
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


def test_popup_tab_abort_requires_close_ack_and_exact_detach_lifecycle() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(
        page_session,
        on_non_replayable_egress=lambda *_args: None,
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    browser_session.emit_popup_detach = False
    browser_session.emit_popup_destroy = False
    browser_session.attach(
        guardian_session_id="popup-tab-session",
        target_id="popup-tab",
        target_type="tab",
        target_url="about:blank",
        waiting=True,
    )
    router.begin_abort()
    guard.begin_abort()

    with pytest.raises(CdpTargetIntegrityError, match="exact detached lifecycle"):
        guard.finish_abort()
    assert sum(
        command == "Target.getTargets" for command, _parameters in browser_session.commands
    ) == 4
    assert not any(
        command == "Target.setAutoAttach" and parameters.get("autoAttach") is False
        for command, parameters in browser_session.commands
    )


def test_popup_tab_destroyed_event_is_optional_after_exact_detach() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(
        page_session,
        on_non_replayable_egress=lambda *_args: None,
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    browser_session.emit_popup_destroy = False
    browser_session.attach(
        guardian_session_id="popup-tab-session",
        target_id="popup-tab",
        target_type="tab",
        target_url="about:blank",
        waiting=True,
    )
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()

    assert browser_session.detached is True


def test_foreign_context_waiting_tab_is_closed_before_context_failure() -> None:
    attempts: list[tuple[CdpTargetSource | None, str, str, object | None]] = []
    page_session = _FakeNonFlatSession()
    router, _observed = _router(
        page_session,
        on_non_replayable_egress=lambda source, api, mechanism, url: attempts.append(
            (source, api, mechanism, url)
        ),
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)

    browser_session.attach(
        guardian_session_id="foreign-popup-session",
        target_id="foreign-popup",
        target_type="tab",
        target_url="https://foreign.test/private/path?discard=this",
        browser_context_id="foreign-context",
        waiting=True,
    )

    assert attempts == [
        (
            None,
            POPUP_NAVIGATION_API,
            "browser-popup-tab-tripwire",
            "https://foreign.test/private/path?discard=this",
        )
    ]
    assert ("Target.closeTarget", {"targetId": "foreign-popup"}) in browser_session.commands
    assert guard._popup_tabs["foreign-popup"].detached is True
    with pytest.raises(CdpTargetIntegrityError, match="waiting browser tab.*root browser context"):
        router.raise_if_failed()
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


def test_foreign_context_unpaused_tab_remains_an_integrity_failure() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)

    browser_session.attach(
        guardian_session_id="foreign-tab-session",
        target_id="foreign-tab",
        target_type="tab",
        target_url="about:blank",
        browser_context_id="foreign-context",
        waiting=False,
    )

    with pytest.raises(CdpTargetIntegrityError, match="unpaused browser tab.*root browser context"):
        router.raise_if_failed()
    assert ("Target.closeTarget", {"targetId": "foreign-tab"}) not in browser_session.commands
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


def test_second_unpaused_root_tab_fails_closed() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)

    browser_session.attach(
        guardian_session_id="second-root-tab-session",
        target_id="second-root-tab",
        target_type="tab",
        target_url="about:blank",
        waiting=False,
    )

    with pytest.raises(CdpTargetIntegrityError, match="more than one unpaused root tab"):
        router.raise_if_failed()
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


@pytest.mark.parametrize("method", ["Target.targetCreated", "Target.targetInfoChanged"])
def test_browser_guard_rejects_window_open_page_in_root_context(method: str) -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)

    browser_session.page_target_event(
        target_id="window-open-popup",
        browser_context_id="root-context",
        method=method,
    )

    with pytest.raises(CdpTargetIntegrityError, match="sibling popup/page"):
        router.raise_if_failed()
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()
    assert browser_session.detached is True


def test_browser_guard_allows_page_target_from_an_unrelated_context() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)

    browser_session.page_target_event(
        target_id="other-context-page",
        browser_context_id="other-context",
    )

    router.raise_if_failed()
    _clean_shutdown(router)


def test_browser_guard_barrier_rejects_preexisting_sibling_page() -> None:
    page_session = _FakeNonFlatSession()
    router = RecursiveCdpTargetRouter(page_session, on_event=lambda *_args: None)
    router.start()
    browser_session = _FakeBrowserSession()
    browser_session.target_infos.append(
        {
            "targetId": "preexisting-popup",
            "type": "page",
            "url": "about:blank",
            "browserContextId": "root-context",
            "attached": False,
        }
    )

    with pytest.raises(CdpTargetIntegrityError, match="sibling popup/page"):
        BrowserSharedWorkerGuard(browser_session, router).start()


def test_exact_guarded_shared_worker_is_adopted_once_and_fully_instrumented() -> None:
    page_session = _FakeNonFlatSession()
    router, observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    browser_session.attach(
        guardian_session_id="shared-guardian-session",
        target_id=target_id,
        target_url=target_url,
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    router.raise_if_failed()

    assert (
        (),
        "Target.attachToTarget",
        {"targetId": target_id, "flatten": False},
    ) in page_session.commands
    assert [
        method
        for route, method, _params in page_session.commands
        if route == ("shared-page-session",)
    ] == [
        "Debugger.enable",
        "Network.enable",
            "Network.setCacheDisabled",
            "Network.setBypassServiceWorker",
            "Runtime.enable",
            "Runtime.addBinding",
            "Fetch.enable",
            "Runtime.evaluate",
            "Target.setAutoAttach",
        "Target.getTargetInfo",
        "Runtime.runIfWaitingForDebugger",
    ]

    for method, payload in (
        (
            "Network.responseReceived",
            {"requestId": target_id, "response": {"url": target_url}},
        ),
        ("Network.requestWillBeSentExtraInfo", {"requestId": target_id, "headers": {}}),
        ("Network.loadingFinished", {"requestId": target_id}),
    ):
        page_session.emit(("shared-page-session",), method, payload)
    main_script_sources = [
        source
        for source, method, event in observed
        if method.startswith("Network.") and event.get("requestId") == target_id
    ]
    assert len(main_script_sources) == 4
    assert all(source == router.root_source for source in main_script_sources)

    page_session.detach((), session_id="shared-page-session")
    browser_session.detach(guardian_session_id="shared-guardian-session", target_id=target_id)
    _clean_shutdown(router)


def test_shared_bootstrap_is_released_after_initial_envelopes_not_inner_acks() -> None:
    page_session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "prearmed-shared-target"
    target_url = "https://worker.test/prearmed-shared.js"
    child_route = ("prearmed-shared-session",)
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id=child_route[0],
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    def pause_during_adoption() -> None:
        _pause_script_bootstrap(
            page_session,
            (),
            target_id=target_id,
            target_url=target_url,
            frame_id="root-frame",
        )
        assert not any(
            method == "Fetch.continueRequest" and params.get("requestId") == f"fetch-{target_id}"
            for _route, method, params in page_session.commands
        )

    page_session.before_adoption_attachment = pause_during_adoption
    browser_session.attach(
        guardian_session_id="prearmed-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )

    assert [method for route, method, _params in page_session.commands if route == child_route] == [
        "Debugger.enable",
        "Network.enable",
        "Network.setCacheDisabled",
        "Network.setBypassServiceWorker",
        "Runtime.enable",
        "Runtime.addBinding",
        "Fetch.enable",
    ]
    setup_indices = [
        index
        for index, (route, method, _params) in enumerate(page_session.commands)
        if route == child_route
        and method
        in {
            "Debugger.enable",
            "Network.enable",
            "Network.setCacheDisabled",
            "Network.setBypassServiceWorker",
            "Fetch.enable",
        }
    ]
    release_index = next(
        index
        for index, (route, method, _params) in enumerate(page_session.commands)
        if route == () and method == "Fetch.continueRequest"
    )
    assert len(setup_indices) == 5
    assert max(setup_indices) < release_index
    assert not any(
        route == child_route and method == "Runtime.runIfWaitingForDebugger"
        for route, method, _params in page_session.commands
    )
    expected_summary = {
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
    assert router.bootstrap_prearm_summary == expected_summary
    mutated = router.bootstrap_prearm_summary
    mutated["held_total"] = 99
    assert router.bootstrap_prearm_summary == expected_summary

    page_session.release_held("Network.enable")
    assert any(
        route == child_route and method == "Runtime.runIfWaitingForDebugger"
        for route, method, _params in page_session.commands
    )
    page_session.emit(child_route, "Network.loadingFinished", {"requestId": target_id})
    page_session.detach((), session_id=child_route[0])
    browser_session.detach(guardian_session_id="prearmed-shared-guardian", target_id=target_id)
    _clean_shutdown(router)


def test_oopif_owner_releases_its_exact_shared_bootstrap_after_prearm() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    iframe = page_session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    page_session.hold_methods.update({"Network.enable", "Fetch.continueRequest"})
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "oopif-shared-target"
    target_url = "https://worker.test/oopif-shared.js"
    child_route = ("oopif-shared-session",)
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id=child_route[0],
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        iframe,
        target_id=target_id,
        target_url=target_url,
        frame_id="iframe-target",
    )

    def pause_during_adoption() -> None:
        _pause_script_bootstrap(
            page_session,
            iframe,
            target_id=target_id,
            target_url=target_url,
            frame_id="iframe-target",
        )
        assert not any(
            route == iframe
            and method == "Fetch.continueRequest"
            and params.get("requestId") == f"fetch-{target_id}"
            for route, method, params in page_session.commands
        )

    page_session.before_adoption_attachment = pause_during_adoption
    browser_session.attach(
        guardian_session_id="oopif-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )

    assert any(
        route == iframe and method == "Fetch.continueRequest"
        for route, method, _params in page_session.commands
    )
    shared_summary = router.bootstrap_prearm_summary["by_worker_type"]["shared_worker"]
    assert shared_summary["owner_target_types"] == {
        "page": 0,
        "iframe": 1,
        "worker": 0,
        "shared_worker": 0,
    }
    assert shared_summary["released_after_setup_envelopes"] == 1
    assert router.shutdown_ready is False

    page_session.release_held("Fetch.continueRequest")
    page_session.release_held("Network.enable")
    page_session.emit(child_route, "Network.loadingFinished", {"requestId": target_id})
    page_session.detach((), session_id=child_route[0])
    browser_session.detach(guardian_session_id="oopif-shared-guardian", target_id=target_id)
    page_session.detach((), session_id=iframe[-1])
    _clean_shutdown(router)


def test_shared_bootstrap_terminal_before_adoption_release_fails_closed() -> None:
    page_session = _FakeNonFlatSession()
    page_session.emit_adoption_attachment = False
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "terminal-held-shared-target"
    target_url = "https://worker.test/terminal-held-shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="terminal-held-shared-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    page_session.before_adoption_attachment = lambda: _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="terminal-held-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )

    assert router.bootstrap_prearm_summary["pending_total"] == 1
    assert not any(
        method == "Fetch.continueRequest" and params.get("requestId") == f"fetch-{target_id}"
        for _route, method, params in page_session.commands
    )
    page_session.emit((), "Network.loadingFailed", {"requestId": target_id})

    with pytest.raises(CdpTargetIntegrityError, match="terminated.*held continue"):
        router.raise_if_failed()


def test_shared_bootstrap_guardian_detach_before_adoption_release_fails_closed() -> None:
    page_session = _FakeNonFlatSession()
    page_session.emit_adoption_attachment = False
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "detached-held-shared-target"
    target_url = "https://worker.test/detached-held-shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="detached-held-shared-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    page_session.before_adoption_attachment = lambda: _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="detached-held-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )
    browser_session.detach(guardian_session_id="detached-held-shared-guardian", target_id=target_id)

    with pytest.raises(CdpTargetIntegrityError, match="detached.*held bootstrap"):
        router.raise_if_failed()


def test_shared_bootstrap_child_detach_during_setup_never_releases_continue() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "reentrant-detached-shared-target"
    target_url = "https://worker.test/reentrant-detached-shared.js"
    route = ("reentrant-detached-shared-session",)
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id=route[0],
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    page_session.before_adoption_attachment = lambda: _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    def detach_on_first_setup(command_route: tuple[str, ...], method: str) -> None:
        assert command_route == route
        assert method == "Debugger.enable"
        page_session.detach((), session_id=route[0])

    page_session.before_nested_command = detach_on_first_setup
    browser_session.attach(
        guardian_session_id="reentrant-detached-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )

    assert not any(
        method == "Fetch.continueRequest" and params.get("requestId") == f"fetch-{target_id}"
        for _route, method, params in page_session.commands
    )
    assert router.bootstrap_prearm_summary["pending_total"] == 1
    with pytest.raises(CdpTargetIntegrityError, match="detached.*held bootstrap"):
        router.raise_if_failed()


def test_shared_bootstrap_outer_setup_send_failure_never_releases_continue() -> None:
    page_session = _FakeNonFlatSession(reject_methods={"Debugger.enable"})
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "setup-failed-shared-target"
    target_url = "https://worker.test/setup-failed-shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="setup-failed-shared-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    page_session.before_adoption_attachment = lambda: _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="setup-failed-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )

    assert not any(
        method == "Fetch.continueRequest" and params.get("requestId") == f"fetch-{target_id}"
        for _route, method, params in page_session.commands
    )
    assert router.bootstrap_prearm_summary["pending_total"] == 1
    with pytest.raises(CdpTargetIntegrityError, match="command.*failed"):
        router.raise_if_failed()


def test_dedicated_bootstrap_retains_immediate_policy_without_prearm() -> None:
    page_session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(page_session)
    target_id = "prearmed-dedicated-target"
    route = _attach_worker(
        page_session,
        (),
        session_id="prearmed-dedicated-session",
        target_id=target_id,
    )

    summary = router.bootstrap_prearm_summary
    assert summary["held_total"] == summary["released_total"] == 0
    assert summary["by_worker_type"]["worker"] == {
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
    }
    assert any(
        command_route == ()
        and method == "Fetch.continueRequest"
        and params == {"requestId": f"fetch-{target_id}"}
        for command_route, method, params in page_session.commands
    )
    page_session.release_held("Network.enable")
    page_session.emit(route, "Network.loadingFinished", {"requestId": target_id})
    page_session.detach((), session_id=route[-1])
    _clean_shutdown(router)


def test_duplicate_worker_urls_are_disambiguated_by_target_and_request_identity() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    target_url = "https://worker.test/reused.js"
    routes = [
        _attach_worker(
            page_session,
            (),
            session_id=f"duplicate-url-session-{index}",
            target_id=f"duplicate-url-target-{index}",
            target_url=target_url,
        )
        for index in range(2)
    ]

    summary = router.bootstrap_prearm_summary["by_worker_type"]["worker"]
    assert summary["held"] == summary["released"] == summary["pending"] == 0
    assert {
        params["requestId"]
        for route, method, params in page_session.commands
        if route == () and method == "Fetch.continueRequest"
    } >= {"fetch-duplicate-url-target-0", "fetch-duplicate-url-target-1"}

    for index, route in enumerate(routes):
        page_session.emit(
            route,
            "Network.loadingFinished",
            {"requestId": f"duplicate-url-target-{index}"},
        )
        page_session.detach((), session_id=route[-1])
    _clean_shutdown(router)


def test_ordinary_page_script_is_never_speculatively_held() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    _begin_script_bootstrap(
        page_session,
        (),
        target_id="ordinary-script-request",
        target_url="https://root.test/ordinary.js",
        frame_id="root-frame",
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id="ordinary-script-request",
        target_url="https://root.test/ordinary.js",
        frame_id="root-frame",
    )

    assert router.bootstrap_prearm_summary["held_total"] == 0
    assert any(
        route == ()
        and method == "Fetch.continueRequest"
        and params == {"requestId": "fetch-ordinary-script-request"}
        for route, method, params in page_session.commands
    )
    page_session.emit((), "Network.loadingFinished", {"requestId": "ordinary-script-request"})
    _clean_shutdown(router)


def test_bootstrap_denial_is_immediate_and_never_resumes_worker() -> None:
    def deny(_source: CdpTargetSource, event: Mapping[str, Any]):
        return (
            "Fetch.failRequest",
            {"requestId": event["requestId"], "errorReason": "BlockedByClient"},
        )

    page_session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(page_session, fetch_policy=deny)
    target_id = "denied-worker-target"
    route = _attach_worker(
        page_session,
        (),
        session_id="denied-worker-session",
        target_id=target_id,
    )

    assert router.bootstrap_prearm_summary["held_total"] == 0
    assert any(
        command_route == ()
        and method == "Fetch.failRequest"
        and params["requestId"] == f"fetch-{target_id}"
        for command_route, method, params in page_session.commands
    )
    assert not any(
        command_route == route and method == "Runtime.runIfWaitingForDebugger"
        for command_route, method, _params in page_session.commands
    )
    assert any(
        held_method == "Network.enable" for _route, _id, held_method, _result in page_session.held
    )
    assert router.shutdown_ready is False
    with pytest.raises(CdpTargetIntegrityError, match="setup|bootstrap|pending"):
        router.begin_shutdown()
    page_session.emit((), "Network.loadingFailed", {"requestId": target_id})
    page_session.detach((), session_id=route[-1])
    assert router.shutdown_ready is True
    _clean_shutdown(router)


def test_shared_bootstrap_denial_is_immediate_before_adoption_and_detaches_cleanly() -> None:
    def deny(_source: CdpTargetSource, event: Mapping[str, Any]):
        return (
            "Fetch.failRequest",
            {"requestId": event["requestId"], "errorReason": "BlockedByClient"},
        )

    page_session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(page_session, fetch_policy=deny)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "denied-shared-target"
    target_url = "https://worker.test/denied-shared.js"
    route = ("denied-shared-session",)
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id=route[0],
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    def deny_during_adoption() -> None:
        _pause_script_bootstrap(
            page_session,
            (),
            target_id=target_id,
            target_url=target_url,
            frame_id="root-frame",
        )
        assert any(
            command_route == ()
            and method == "Fetch.failRequest"
            and params.get("requestId") == f"fetch-{target_id}"
            for command_route, method, params in page_session.commands
        )
        assert not any(
            command_route == route for command_route, _method, _params in page_session.commands
        )

    page_session.before_adoption_attachment = deny_during_adoption
    browser_session.attach(
        guardian_session_id="denied-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )

    failure_index = next(
        index
        for index, (command_route, method, params) in enumerate(page_session.commands)
        if command_route == ()
        and method == "Fetch.failRequest"
        and params.get("requestId") == f"fetch-{target_id}"
    )
    setup_indices = [
        index
        for index, (command_route, _method, _params) in enumerate(page_session.commands)
        if command_route == route
    ]
    assert setup_indices and failure_index < min(setup_indices)
    assert any(
        held_method == "Network.enable" for _route, _id, held_method, _result in page_session.held
    )
    assert router.bootstrap_prearm_summary["held_total"] == 0
    assert not any(
        command_route == route
        and method in {"Fetch.continueRequest", "Runtime.runIfWaitingForDebugger"}
        for command_route, method, _params in page_session.commands
    )
    with pytest.raises(CdpTargetIntegrityError, match="setup|bootstrap|pending"):
        router.begin_shutdown()

    page_session.emit((), "Network.loadingFailed", {"requestId": target_id})
    page_session.detach((), session_id=route[-1])
    browser_session.detach(guardian_session_id="denied-shared-guardian", target_id=target_id)
    assert router.shutdown_ready is True
    _clean_shutdown(router)


@pytest.mark.parametrize(
    ("override", "match"),
    [
        ({"resourceType": "Script"}, "identity|type"),
        ({"request": {"method": "POST", "url": "https://worker.test/exact.js"}}, "method"),
        ({"request": {"method": "GET", "url": "https://worker.test/wrong.js"}}, "URL|Script"),
        ({"frameId": "wrong-frame"}, "Network Script"),
    ],
)
def test_bootstrap_fetch_must_match_exact_network_occurrence(
    override: dict[str, Any], match: str
) -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "exact-shared-target"
    target_url = "https://worker.test/exact.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="exact-shared-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="exact-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )
    event: dict[str, Any] = {
        "requestId": "exact-fetch",
        "networkId": target_id,
        "frameId": "root-frame",
        "resourceType": "Other",
        "request": {"method": "GET", "url": target_url},
    }
    event.update(override)
    page_session.emit((), "Fetch.requestPaused", event)

    with pytest.raises(CdpTargetIntegrityError, match=match):
        router.raise_if_failed()


def test_bootstrap_policy_callback_must_make_exactly_one_decision() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session, fetch_policy=lambda _source, _event: None)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "undecided-shared-target"
    target_url = "https://worker.test/undecided.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="undecided-shared-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="undecided-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    with pytest.raises(CdpTargetIntegrityError, match="without a decision"):
        router.raise_if_failed()


def test_bootstrap_redirect_is_rechecked_but_not_held_twice() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "redirect-shared-target"
    initial_url = "https://worker.test/initial.js"
    final_url = "https://cdn.test/final.js"
    route = ("redirect-shared-session",)
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id=route[0],
        target_url=initial_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=initial_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="redirect-shared-guardian",
        target_id=target_id,
        target_url=initial_url,
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=initial_url,
        frame_id="root-frame",
    )
    page_session.emit(
        (),
        "Network.requestWillBeSent",
        {
            "requestId": target_id,
            "loaderId": f"loader-{target_id}",
            "frameId": "root-frame",
            "type": "Script",
            "redirectResponse": {"status": 302},
            "request": {"method": "GET", "url": final_url},
        },
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=final_url,
        frame_id="root-frame",
        request_id="redirect-fetch",
    )

    continues = [
        params["requestId"]
        for command_route, method, params in page_session.commands
        if command_route == () and method == "Fetch.continueRequest"
    ]
    assert continues == [f"fetch-{target_id}", "redirect-fetch"]
    assert router.bootstrap_prearm_summary["held_total"] == 1
    assert router.bootstrap_prearm_summary["released_total"] == 1
    page_session.emit(route, "Network.loadingFinished", {"requestId": target_id})
    page_session.detach((), session_id=route[-1])
    browser_session.detach(guardian_session_id="redirect-shared-guardian", target_id=target_id)
    _clean_shutdown(router)


def test_duplicate_bootstrap_fetch_identity_fails_closed() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "duplicate-fetch-shared"
    target_url = f"https://worker.test/{target_id}.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="duplicate-fetch-shared-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="duplicate-fetch-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    with pytest.raises(CdpTargetIntegrityError, match="duplicated|reused"):
        router.raise_if_failed()


def test_guarded_shared_worker_waits_for_late_bootstrap_owner_before_adoption() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "late-shared-target"
    target_url = "https://worker.test/late-shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="late-shared-session",
        target_url=target_url,
    )

    browser_session.attach(
        guardian_session_id="late-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )
    assert not any(
        method == "Target.attachToTarget" for _route, method, _params in page_session.commands
    )

    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    assert (
        sum(method == "Target.attachToTarget" for _route, method, _params in page_session.commands)
        == 1
    )
    assert (
        sum(
            route == ("late-shared-session",) and method == "Runtime.runIfWaitingForDebugger"
            for route, method, _params in page_session.commands
        )
        == 1
    )

    page_session.emit(
        ("late-shared-session",),
        "Network.loadingFinished",
        {"requestId": target_id},
    )
    page_session.detach((), session_id="late-shared-session")
    browser_session.detach(
        guardian_session_id="late-shared-guardian",
        target_id=target_id,
    )
    _clean_shutdown(router)


def test_guarded_page_attachment_requires_an_exact_one_time_preauthorisation() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    page_session.attach(
        (),
        session_id="unsolicited-page-session",
        target_id=target_id,
        target_type="shared_worker",
        waiting=False,
        target_url=target_url,
    )

    with pytest.raises(CdpTargetIntegrityError, match="unpaused|preauthori|adoption"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    ("override", "match"),
    [
        ({"waiting": False}, "paused|waitingForDebugger|unpaused"),
        ({"target_type": "worker"}, "shared.worker|type"),
        ({"browser_context_id": "other-context"}, "browser context|context"),
        ({"attached": False}, "identity|attached"),
        ({"target_url": "https://worker.test/other.js"}, "URL|url|bootstrap"),
        ({"target_id": "other-target"}, "target|bootstrap|ownership|adoption"),
        ({"guardian_session_id": ""}, "session|malformed|unpaused"),
    ],
)
def test_browser_guard_rejects_non_exact_shared_worker_attachments(
    override: dict[str, Any], match: str
) -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    attachment: dict[str, Any] = {
        "guardian_session_id": "shared-guardian-session",
        "target_id": target_id,
        "target_type": "shared_worker",
        "target_url": target_url,
        "browser_context_id": "root-context",
        "waiting": True,
        "attached": True,
    }
    attachment.update(override)

    with pytest.raises(CdpTargetIntegrityError, match=match):
        browser_session.attach(**attachment)
        router.begin_shutdown()
        guard.begin_shutdown()


def test_shared_worker_bootstrap_ownership_must_be_unique() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    iframe = page_session.attach(
        (),
        session_id="iframe-session",
        target_id="iframe-target",
        target_type="iframe",
    )
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    for route, frame_id in (((), "root-frame"), (iframe, "iframe-target")):
        _begin_script_bootstrap(
            page_session,
            route,
            target_id=target_id,
            target_url=target_url,
            frame_id=frame_id,
        )

    with pytest.raises(CdpTargetIntegrityError, match="ambiguous|unique|ownership"):
        browser_session.attach(
            guardian_session_id="shared-guardian-session",
            target_id=target_id,
            target_url=target_url,
        )
        router.begin_shutdown()
        guard.begin_shutdown()


def test_guarded_shared_worker_can_bind_a_unique_oopif_script_occurrence() -> None:
    page_session = _FakeNonFlatSession()
    router, observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    iframe = page_session.attach(
        (),
        session_id="iframe-session",
        target_id="iframe-target",
        target_type="iframe",
    )
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        iframe,
        target_id=target_id,
        target_url=target_url,
        frame_id="iframe-target",
    )
    browser_session.attach(
        guardian_session_id="shared-guardian-session",
        target_id=target_id,
        target_url=target_url,
    )
    _pause_script_bootstrap(
        page_session,
        iframe,
        target_id=target_id,
        target_url=target_url,
        frame_id="iframe-target",
    )
    page_session.emit(
        ("shared-page-session",),
        "Network.loadingFinished",
        {"requestId": target_id},
    )

    sources = [
        source
        for source, method, event in observed
        if method.startswith("Network.") and event.get("requestId") == target_id
    ]
    assert len(sources) == 2
    assert all(source.session_path == iframe for source in sources)
    page_session.detach((), session_id="shared-page-session")
    browser_session.detach(guardian_session_id="shared-guardian-session", target_id=target_id)
    page_session.detach((), session_id="iframe-session")
    _clean_shutdown(router)


def test_browser_guard_rejects_guardian_identity_reuse() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    attachment = {
        "guardian_session_id": "shared-guardian-session",
        "target_id": target_id,
        "target_url": target_url,
    }
    browser_session.attach(**attachment)

    with pytest.raises(CdpTargetIntegrityError, match="reused|already|consumed"):
        browser_session.attach(**attachment)
        router.begin_shutdown()
        guard.begin_shutdown()


def test_guard_rejects_a_page_attach_result_with_a_different_session() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    page_session.adoption_result_session_id = "different-page-session"
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    with pytest.raises(CdpTargetIntegrityError, match="session|adoption"):
        browser_session.attach(
            guardian_session_id="shared-guardian-session",
            target_id=target_id,
            target_url=target_url,
        )
        router.begin_shutdown()
        guard.begin_shutdown()


def test_dedicated_worker_main_script_events_keep_the_root_occurrence() -> None:
    page_session = _FakeNonFlatSession()
    router, observed = _router(page_session)
    target_id = "dedicated-target"
    target_url = "https://worker.test/dedicated.js"
    worker = _attach_worker(
        page_session,
        (),
        session_id="dedicated-session",
        target_id=target_id,
        target_url=target_url,
        parent_frame_id="root-frame",
    )

    for method, payload in (
        (
            "Network.responseReceived",
            {"requestId": target_id, "response": {"url": target_url}},
        ),
        ("Network.requestWillBeSentExtraInfo", {"requestId": target_id, "headers": {}}),
        ("Network.loadingFinished", {"requestId": target_id}),
    ):
        page_session.emit(worker, method, payload)

    sources = [
        source
        for source, method, event in observed
        if method.startswith("Network.") and event.get("requestId") == target_id
    ]
    assert len(sources) == 4
    assert all(source == router.root_source for source in sources)
    page_session.detach((), session_id="dedicated-session")
    _clean_shutdown(router)


def test_worker_cannot_claim_an_arbitrary_same_id_request() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    worker = _attach_worker(
        page_session,
        (),
        session_id="dedicated-session",
        target_id="dedicated-target",
        parent_frame_id="root-frame",
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id="unrelated-script",
        target_url="https://worker.test/unrelated.js",
        frame_id="root-frame",
    )

    page_session.emit(
        worker,
        "Network.responseReceived",
        {
            "requestId": "unrelated-script",
            "response": {"url": "https://worker.test/unrelated.js"},
        },
    )
    with pytest.raises(
        CdpTargetIntegrityError,
        match="bootstrap|migration|occurrence|collided|unrelated",
    ):
        router.raise_if_failed()


def test_dedicated_worker_requires_a_script_bootstrap() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    target_id = "dedicated-target"
    target_url = "https://worker.test/dedicated.js"
    page_session.emit(
        (),
        "Network.requestWillBeSent",
        {
            "requestId": target_id,
            "loaderId": f"loader-{target_id}",
            "frameId": "root-frame",
            "type": "Document",
            "request": {"method": "GET", "url": target_url},
        },
    )

    page_session.attach(
        (),
        session_id="dedicated-session",
        target_id=target_id,
        target_type="worker",
        parent_frame_id="root-frame",
        target_url=target_url,
    )
    with pytest.raises(CdpTargetIntegrityError, match="Script|bootstrap"):
        router.raise_if_failed()


def test_dedicated_worker_requires_the_exact_parent_frame() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    target_id = "dedicated-target"
    target_url = "https://worker.test/dedicated.js"
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    page_session.attach(
        (),
        session_id="dedicated-session",
        target_id=target_id,
        target_type="worker",
        parent_frame_id="different-frame",
        target_url=target_url,
    )
    with pytest.raises(CdpTargetIntegrityError, match="parent frame|frame|bootstrap"):
        router.raise_if_failed()


def test_dedicated_worker_accepts_target_info_without_parent_frame_id() -> None:
    page_session = _FakeNonFlatSession()
    router, observed = _router(page_session)
    target_id = "dedicated-target"
    target_url = "https://worker.test/dedicated.js"
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    worker = page_session.attach(
        (),
        session_id="dedicated-session",
        target_id=target_id,
        target_type="worker",
        target_url=target_url,
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    page_session.emit(
        worker,
        "Network.responseReceived",
        {"requestId": target_id, "response": {"url": target_url}},
    )
    page_session.emit(worker, "Network.loadingFinished", {"requestId": target_id})

    router.raise_if_failed()
    bootstrap_sources = [
        source
        for source, method, event in observed
        if method.startswith("Network.") and event.get("requestId") == target_id
    ]
    assert len(bootstrap_sources) == 3
    assert all(source == router.root_source for source in bootstrap_sources)
    page_session.detach((), session_id="dedicated-session")
    _clean_shutdown(router)


def test_a_consumed_worker_bootstrap_cannot_authorise_a_new_generation() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    target_id = "dedicated-target"
    target_url = "https://worker.test/dedicated.js"
    first = _attach_worker(
        page_session,
        (),
        session_id="first-session",
        target_id=target_id,
        target_url=target_url,
        parent_frame_id="root-frame",
    )
    page_session.detach((), session_id=first[-1])

    page_session.attach(
        (),
        session_id="second-session",
        target_id=target_id,
        target_type="worker",
        parent_frame_id="root-frame",
        target_url=target_url,
    )
    with pytest.raises(CdpTargetIntegrityError, match="generation|consumed|bootstrap|reused"):
        router.raise_if_failed()


def test_unresolved_shared_worker_adoption_blocks_shutdown() -> None:
    page_session = _FakeNonFlatSession()
    page_session.emit_adoption_attachment = False
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="shared-guardian-session",
        target_id=target_id,
        target_url=target_url,
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    with pytest.raises(CdpTargetIntegrityError, match="adoption|attach|pending|unresolved"):
        router.begin_shutdown()


def test_unresolved_shared_worker_setup_blocks_router_shutdown() -> None:
    page_session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(page_session)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="shared-guardian-session",
        target_id=target_id,
        target_url=target_url,
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )

    with pytest.raises(CdpTargetIntegrityError, match="setup|pending"):
        router.begin_shutdown()


def test_abort_disposes_permanently_pending_shared_worker_prearm() -> None:
    page_session = _FakeNonFlatSession()
    page_session.emit_adoption_attachment = False
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    page_session.before_adoption_attachment = lambda: _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="shared-guardian-session",
        target_id=target_id,
        target_url=target_url,
    )
    assert router.bootstrap_prearm_summary["pending_total"] == 1
    assert router.shutdown_ready is False

    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()

    assert browser_session.detached is True
    with pytest.raises(CdpTargetIntegrityError, match="normal|abort|more than once"):
        router.finish()


def test_live_browser_guard_session_blocks_finish() -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    target_id = "shared-target"
    target_url = "https://worker.test/shared.js"
    page_session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id="shared-page-session",
        target_url=target_url,
    )
    _begin_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id="shared-guardian-session",
        target_id=target_id,
        target_url=target_url,
    )
    _pause_script_bootstrap(
        page_session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    page_session.emit(
        ("shared-page-session",),
        "Network.loadingFinished",
        {"requestId": target_id},
    )

    _begin_shutdown(router)
    page_session.detach((), session_id="shared-page-session")
    with pytest.raises(CdpTargetIntegrityError, match="guard|session|pending|unresolved"):
        guard.finish()


def _valid_bootstrap_prearm_summary(*, terminal: bool = True) -> dict[str, Any]:
    released = 1 if terminal else 0
    return {
        "schema_version": BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION,
        "held_total": 1,
        "released_total": released,
        "pending_total": 1 - released,
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
                "released": released,
                "pending": 1 - released,
                "released_after_setup_envelopes": released,
                "owner_target_types": {
                    "page": 1,
                    "iframe": 0,
                    "worker": 0,
                    "shared_worker": 0,
                },
            },
        },
    }


def test_bootstrap_prearm_summary_validator_accepts_live_and_terminal_states() -> None:
    live = _valid_bootstrap_prearm_summary(terminal=False)
    assert validate_bootstrap_prearm_summary(live, require_terminal=False) == live
    with pytest.raises(ValueError, match="terminal state"):
        validate_bootstrap_prearm_summary(live, require_terminal=True)

    terminal = _valid_bootstrap_prearm_summary()
    validated = validate_bootstrap_prearm_summary(terminal, require_terminal=True)
    assert validated == terminal
    validated["held_total"] = 99
    assert terminal["held_total"] == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(schema_version=2),
        lambda value: value.update(schema_version=True),
        lambda value: value.update(held_total=2),
        lambda value: value.update(released_total=True),
        lambda value: value.update(release_before_setup_envelopes_total=1),
        lambda value: value["by_worker_type"]["worker"].update(held=1, pending=1),
        lambda value: value["by_worker_type"]["shared_worker"].update(
            released_after_setup_envelopes=0
        ),
        lambda value: value["by_worker_type"]["shared_worker"]["owner_target_types"].update(page=0),
    ],
)
def test_bootstrap_prearm_summary_validator_rejects_inconsistent_states(mutate) -> None:
    value = _valid_bootstrap_prearm_summary()
    mutate(value)
    with pytest.raises(ValueError, match="prearm"):
        validate_bootstrap_prearm_summary(value, require_terminal=True)
