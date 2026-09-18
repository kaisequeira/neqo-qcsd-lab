from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

import pytest

import qcsd_lab.cdp_targets as cdp_targets_module
from qcsd_lab.acquisition_errors import NonReplayableEgressPolicyError
from qcsd_lab.browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    POPUP_GUARD_MARKER,
    POPUP_NAVIGATION_API,
    TARGET_EGRESS_BINDING,
    TARGET_EGRESS_SHIM_SCHEMA_VERSION,
    NonReplayableEgressGuard,
    target_egress_apis,
    target_egress_shim_source,
)
from qcsd_lab.cdp_targets import (
    _IFRAME_INSTALLATION_KIND,
    BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION,
    CDP_TARGET_INSTRUMENTATION_POLICY,
    BrowserSharedWorkerGuard,
    CdpTargetIntegrityError,
    CdpTargetSource,
    RecursiveCdpTargetRouter,
    _sanitised_protocol_error,
    validate_bootstrap_prearm_summary,
)


class _PinnedPlaywrightError(Exception):
    """Minimal exact-type stand-in for the optional Playwright dependency."""

    def __init__(self, message: str, *, name: str = "Error") -> None:
        super().__init__(message)
        self.message = message
        self.name = name


class _PinnedPlaywrightErrorSubclass(_PinnedPlaywrightError):
    pass


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
        self.auto_iframe_prearm = True
        self.iframe_context_before_resume_ack = True
        self.iframe_receipt_before_debugger_resume_ack = True
        self.iframe_contexts: dict[tuple[str, ...], tuple[int, str]] = {}
        self.iframe_pause_emitted: set[tuple[str, ...]] = set()
        self.iframe_installation_emitted: set[tuple[str, ...]] = set()
        self.auto_worker_prearm = True
        self.worker_pause_before_resume_ack = False
        self.worker_instrumentation_armed: set[tuple[str, ...]] = set()
        self.worker_script_parsed_emitted: set[tuple[str, ...]] = set()
        self.worker_pause_emitted: set[tuple[str, ...]] = set()

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
        is_worker = self.route_info[route]["type"] in {"worker", "shared_worker"}
        if is_worker and method == "Debugger.setInstrumentationBreakpoint":
            self.worker_instrumentation_armed.add(route)
        if method in self.hold_methods:
            self.held.append((route, command_id, method, self._result(route, method, params)))
            return
        result = self._result(route, method, params)
        is_iframe = self.route_info[route]["type"] == "iframe"
        if (
            self.auto_worker_prearm
            and is_worker
            and route in self.worker_instrumentation_armed
            and method == "Runtime.runIfWaitingForDebugger"
        ):
            self._complete_worker_initial_run(route, command_id, result)
            return
        if self.auto_iframe_prearm and is_iframe and method == "Runtime.runIfWaitingForDebugger":
            if self.iframe_context_before_resume_ack:
                self.emit_iframe_default_context(route)
            self._deliver(route, {"id": command_id, "result": result})
            if not self.iframe_context_before_resume_ack:
                self.emit_iframe_default_context(route)
            return
        if (
            self.auto_iframe_prearm
            and is_iframe
            and method == "Runtime.evaluate"
            and "uniqueContextId" in params
        ):
            if route not in self.iframe_pause_emitted:
                self.emit_iframe_instrumentation_pause(route)
            self._deliver(route, {"id": command_id, "result": result})
            return
        if self.auto_iframe_prearm and is_iframe and method == "Debugger.resume":
            if self.iframe_receipt_before_debugger_resume_ack:
                self.emit_iframe_installation_receipt(route)
            self._deliver(route, {"id": command_id, "result": result})
            if not self.iframe_receipt_before_debugger_resume_ack:
                self.emit_iframe_installation_receipt(route)
            return
        self._deliver(route, {"id": command_id, "result": result})
        if method == "Target.sendMessageToTarget":
            child_route = (*route, params["sessionId"])
            self._process(child_route, json.loads(params["message"]))

    def _complete_worker_initial_run(
        self,
        route: tuple[str, ...],
        command_id: int,
        result: Mapping[str, Any],
    ) -> None:
        if route not in self.worker_script_parsed_emitted:
            self.emit_worker_script_parsed(route)
        if self.worker_pause_before_resume_ack:
            self.emit_worker_instrumentation_pause(route)
        self._deliver(route, {"id": command_id, "result": dict(result)})
        if not self.worker_pause_before_resume_ack:
            self.emit_worker_instrumentation_pause(route)

    def emit_iframe_default_context(
        self,
        route: tuple[str, ...],
        *,
        context_id: int | None = None,
        unique_context_id: str | None = None,
        is_default: bool = True,
        context_type: str | None = None,
        frame_id: str | None = None,
    ) -> None:
        if context_id is None:
            context_id = 100 + len(self.iframe_contexts)
        if unique_context_id is None:
            unique_context_id = f"unique-{'-'.join(route)}-{context_id}"
        if is_default:
            self.iframe_contexts[route] = (context_id, unique_context_id)
        self.emit(
            route,
            "Runtime.executionContextCreated",
            {
                "context": {
                    "id": context_id,
                    "uniqueId": unique_context_id,
                    "origin": "https://frame.test",
                    "name": "",
                    "auxData": {
                        "isDefault": is_default,
                        "type": context_type or ("default" if is_default else "isolated"),
                        "frameId": frame_id or str(self.route_info[route]["targetId"]),
                    },
                }
            },
        )

    def emit_iframe_instrumentation_pause(
        self,
        route: tuple[str, ...],
        *,
        reason: str = "instrumentation",
        location: Mapping[str, Any] | None = None,
        hit_breakpoints: list[str] | None = None,
    ) -> None:
        instrumentation_id = f"instrumentation-{'-'.join(route)}"
        self.iframe_pause_emitted.add(route)
        self.emit(
            route,
            "Debugger.paused",
            {
                "reason": reason,
                "callFrames": [
                    {
                        "callFrameId": f"frame-{'-'.join(route)}",
                        "location": dict(
                            location
                            or {
                                "scriptId": f"script-{'-'.join(route)}",
                                "lineNumber": 0,
                                "columnNumber": 0,
                            }
                        ),
                    }
                ],
                "hitBreakpoints": (
                    [instrumentation_id] if hit_breakpoints is None else hit_breakpoints
                ),
            },
        )

    def emit_iframe_installation_receipt(
        self,
        route: tuple[str, ...],
        *,
        already_installed: bool = False,
        execution_context_id: int | None = None,
        mutate: Any = None,
    ) -> None:
        context = self.iframe_contexts.get(route)
        if context is None and execution_context_id is None:
            raise AssertionError("iframe installation receipt has no test context")
        receipt: dict[str, Any] = {
            "schema_version": TARGET_EGRESS_SHIM_SCHEMA_VERSION,
            "policy": NON_REPLAYABLE_EGRESS_POLICY,
            "kind": _IFRAME_INSTALLATION_KIND,
            "target_type": "iframe",
            "egress_shim": {
                "schema_version": TARGET_EGRESS_SHIM_SCHEMA_VERSION,
                "policy": NON_REPLAYABLE_EGRESS_POLICY,
                "protected_apis": [],
                "unavailable_apis": sorted(target_egress_apis("iframe")),
                "failed_apis": [],
                "already_installed": already_installed,
            },
            "popup_guard_installed": True,
        }
        if mutate is not None:
            mutate(receipt)
        self.iframe_installation_emitted.add(route)
        self.emit(
            route,
            "Runtime.bindingCalled",
            {
                "name": TARGET_EGRESS_BINDING,
                "payload": json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                "executionContextId": (
                    execution_context_id if execution_context_id is not None else context[0]
                ),
            },
        )

    def emit_worker_script_parsed(
        self,
        route: tuple[str, ...],
        *,
        script_id: str | None = None,
        url: str | None = None,
        start_line: int = 0,
        start_column: int = 0,
    ) -> None:
        self.worker_script_parsed_emitted.add(route)
        self.emit(
            route,
            "Debugger.scriptParsed",
            {
                "scriptId": script_id or f"worker-script-{'-'.join(route)}",
                "url": self.route_info[route].get("url", "") if url is None else url,
                "startLine": start_line,
                "startColumn": start_column,
            },
        )

    def emit_worker_instrumentation_pause(
        self,
        route: tuple[str, ...],
        *,
        reason: str = "instrumentation",
        call_frame_id: str | None = None,
        script_id: str | None = None,
        line_number: int = 0,
        column_number: int = 0,
        frame_url: str = "",
        function_name: str = "",
        hit_breakpoints: list[str] | None = None,
        data_script_id: str | None = None,
        data_url: str | None = None,
        function_script_id: str | None = None,
        function_line_number: int = 0,
        function_column_number: int = 0,
    ) -> None:
        expected_script_id = script_id or f"worker-script-{'-'.join(route)}"
        expected_url = str(self.route_info[route].get("url", ""))
        self.worker_pause_emitted.add(route)
        self.emit(
            route,
            "Debugger.paused",
            {
                "reason": reason,
                "data": {
                    "scriptId": data_script_id or expected_script_id,
                    "url": expected_url if data_url is None else data_url,
                },
                "callFrames": [
                    {
                        "callFrameId": call_frame_id or f"worker-frame-{'-'.join(route)}",
                        "functionName": function_name,
                        "url": frame_url,
                        "functionLocation": {
                            "scriptId": function_script_id or expected_script_id,
                            "lineNumber": function_line_number,
                            "columnNumber": function_column_number,
                        },
                        "location": {
                            "scriptId": expected_script_id,
                            "lineNumber": line_number,
                            "columnNumber": column_number,
                        },
                    }
                ],
                "hitBreakpoints": [] if hit_breakpoints is None else hit_breakpoints,
            },
        )

    def release_held(self, method: str) -> None:
        selected = next((item for item in self.held if item[2] == method), None)
        if selected is None:
            raise AssertionError(f"no held command for {method}")
        self.held.remove(selected)
        route, command_id, _method, result = selected
        if (
            self.auto_worker_prearm
            and method == "Runtime.runIfWaitingForDebugger"
            and route in self.worker_instrumentation_armed
        ):
            self._complete_worker_initial_run(route, command_id, result)
            return
        self._deliver(route, {"id": command_id, "result": result})

    def release_held_error(self, method: str, error: object) -> None:
        selected = next((item for item in self.held if item[2] == method), None)
        if selected is None:
            raise AssertionError(f"no held command for {method}")
        self.held.remove(selected)
        route, command_id, _method, _result = selected
        self._deliver(route, {"id": command_id, "error": error})

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
        if method == "Debugger.setInstrumentationBreakpoint":
            return {"breakpointId": f"instrumentation-{'-'.join(route)}"}
        if method == "Debugger.setBreakpoint":
            return {
                "breakpointId": f"conditional-{'-'.join(route)}",
                "actualLocation": dict((params or {})["location"]),
            }
        if method == "Debugger.evaluateOnCallFrame":
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
                        "already_installed": False,
                    },
                }
            }
        if method == "Runtime.evaluate":
            expression = str((params or {}).get("expression", ""))
            if (params or {}).get("uniqueContextId") is not None:
                return {"result": {"type": "boolean", "value": expression == "true"}}
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
        self.before_get_targets: Any = None
        self.get_targets_result: dict[str, Any] | None = None
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
            if self.before_get_targets is not None:
                self.before_get_targets()
            if self.get_targets_result is not None:
                return self.get_targets_result
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
    fetch_policy_label: str | None = None,
    root_continue_error_type: type[Exception] | None = _PinnedPlaywrightError,
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
                label=fetch_policy_label or f"test-policy:{command}",
            )

    router = RecursiveCdpTargetRouter(
        session,
        on_event=on_event,
        root_frame_id="root-frame",
        root_continue_error_type=root_continue_error_type,
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


def _clean_abort(router: RecursiveCdpTargetRouter) -> None:
    _browser_session, guard = _guard_for(router)
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


def _invalid_interception_error(
    message: str = (
        "CDPSession.send: Protocol error (Fetch.continueRequest): "
        "Invalid InterceptionId."
    ),
    *,
    name: str = "Error",
) -> _PinnedPlaywrightError:
    return _PinnedPlaywrightError(message, name=name)


def _invalid_interception_with_changed_message_attribute() -> _PinnedPlaywrightError:
    error = _invalid_interception_error()
    error.message = "different protocol error"
    return error


def _root_request_events(
    *,
    network_id: str,
    fetch_id: str,
    resource_type: str = "Font",
    url: str = "https://root.test/font.woff2",
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = {"method": "GET", "url": url}
    return (
        {
            "requestId": network_id,
            "loaderId": "root-loader",
            "frameId": "root-frame",
            "type": resource_type,
            "request": dict(request),
        },
        {
            "requestId": fetch_id,
            "networkId": network_id,
            "frameId": "root-frame",
            "resourceType": resource_type,
            "request": dict(request),
        },
    )


def _root_terminal_event(
    request_id: str,
    terminal_method: str,
    *,
    resource_type: str = "Font",
) -> dict[str, Any]:
    if terminal_method == "Network.loadingFinished":
        return {
            "requestId": request_id,
            "timestamp": 12.5,
            "encodedDataLength": 321,
        }
    if terminal_method == "Network.loadingFailed":
        return {
            "requestId": request_id,
            "timestamp": 12.5,
            "type": resource_type,
            "errorText": "net::ERR_ABORTED",
            "canceled": True,
        }
    raise AssertionError(f"unsupported terminal method: {terminal_method}")


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


_BLOCKED_DOCUMENT_REQUEST_ID = "blocked-document"
_BLOCKED_DOCUMENT_FETCH_ID = "interception-blocked-document"
_BLOCKED_DOCUMENT_FRAME_ID = "named-child-frame"
_BLOCKED_DOCUMENT_URL = "https://forbidden.test/named-frame"


def _deny_blocked_by_client(
    _source: CdpTargetSource,
    event: Mapping[str, Any],
) -> tuple[str, dict[str, str]]:
    return (
        "Fetch.failRequest",
        {"requestId": event["requestId"], "errorReason": "BlockedByClient"},
    )


def _begin_blocked_document(
    session: _FakeNonFlatSession,
    *,
    network_route: tuple[str, ...] = (),
    fetch_route: tuple[str, ...] = (),
    request_event: Mapping[str, Any] | None = None,
    fetch_event: Mapping[str, Any] | None = None,
) -> None:
    session.emit(
        network_route,
        "Network.requestWillBeSent",
        dict(
            request_event
            or {
                "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
                "loaderId": _BLOCKED_DOCUMENT_REQUEST_ID,
                "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
                "type": "Document",
                "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
            }
        ),
    )
    session.emit(
        fetch_route,
        "Fetch.requestPaused",
        dict(
            fetch_event
            or {
                "requestId": _BLOCKED_DOCUMENT_FETCH_ID,
                "networkId": _BLOCKED_DOCUMENT_REQUEST_ID,
                "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
                "resourceType": "Document",
                "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
            }
        ),
    )


def _blocked_document_failure(**changes: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "timestamp": 41.25,
        "type": "Document",
        "errorText": "net::ERR_BLOCKED_BY_CLIENT",
        "canceled": False,
        "blockedReason": "inspector",
    }
    event.update(changes)
    return event


def _error_document_finish(**changes: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "timestamp": 41.26,
        "encodedDataLength": 183_014,
    }
    event.update(changes)
    return event


def _error_document_abort(**changes: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "timestamp": 41.26,
        "type": "Document",
        "errorText": "net::ERR_ABORTED",
        "canceled": True,
    }
    event.update(changes)
    return event


def _invalid_error_document_aborts() -> list[tuple[str, dict[str, Any]]]:
    exact = _error_document_abort()
    return [
        *((f"missing-{field}", _without(exact, field)) for field in exact),
        ("equal-timestamp", _error_document_abort(timestamp=41.25)),
        ("earlier-timestamp", _error_document_abort(timestamp=41.24)),
        ("boolean-timestamp", _error_document_abort(timestamp=True)),
        ("string-timestamp", _error_document_abort(timestamp="41.26")),
        ("null-timestamp", _error_document_abort(timestamp=None)),
        ("nan-timestamp", _error_document_abort(timestamp=float("nan"))),
        ("infinite-timestamp", _error_document_abort(timestamp=float("inf"))),
        ("wrong-type", _error_document_abort(type="Image")),
        ("wrong-error", _error_document_abort(errorText="net::ERR_FAILED")),
        ("original-error", _error_document_abort(errorText="net::ERR_BLOCKED_BY_CLIENT")),
        ("false-canceled", _error_document_abort(canceled=False)),
        ("numeric-canceled", _error_document_abort(canceled=1)),
        ("string-canceled", _error_document_abort(canceled="true")),
        ("inspector-reason", _error_document_abort(blockedReason="inspector")),
        ("extra-field", _error_document_abort(extra=True)),
        ("empty-request", _error_document_abort(requestId="")),
        ("numeric-request", _error_document_abort(requestId=1)),
        ("unrelated-request", _error_document_abort(requestId="unrelated-document")),
    ]


def _without(event: Mapping[str, Any], field: str) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key != field}


def _invalid_blocked_document_failures() -> list[tuple[str, dict[str, Any]]]:
    exact = _blocked_document_failure()
    return [
        ("missing-timestamp", _without(exact, "timestamp")),
        ("boolean-timestamp", _blocked_document_failure(timestamp=True)),
        ("nan-timestamp", _blocked_document_failure(timestamp=float("nan"))),
        ("infinite-timestamp", _blocked_document_failure(timestamp=float("inf"))),
        ("wrong-type", _blocked_document_failure(type="Image")),
        ("wrong-error", _blocked_document_failure(errorText="net::ERR_FAILED")),
        ("truthy-canceled", _blocked_document_failure(canceled=True)),
        ("numeric-canceled", _blocked_document_failure(canceled=0)),
        ("wrong-blocked-reason", _blocked_document_failure(blockedReason="other")),
        ("extra-field", _blocked_document_failure(extra=True)),
    ]


def _invalid_error_document_finishes() -> list[tuple[str, dict[str, Any]]]:
    exact = _error_document_finish()
    return [
        ("missing-timestamp", _without(exact, "timestamp")),
        ("equal-timestamp", _error_document_finish(timestamp=41.25)),
        ("earlier-timestamp", _error_document_finish(timestamp=41.24)),
        ("boolean-timestamp", _error_document_finish(timestamp=True)),
        ("nan-timestamp", _error_document_finish(timestamp=float("nan"))),
        ("infinite-timestamp", _error_document_finish(timestamp=float("inf"))),
        ("zero-length", _error_document_finish(encodedDataLength=0)),
        ("negative-length", _error_document_finish(encodedDataLength=-1)),
        ("boolean-length", _error_document_finish(encodedDataLength=True)),
        ("nan-length", _error_document_finish(encodedDataLength=float("nan"))),
        ("infinite-length", _error_document_finish(encodedDataLength=float("inf"))),
        ("extra-field", _error_document_finish(extra=True)),
    ]


_SYNTHETIC_ERROR_RESOURCE_URLS = (
    "data:image/png;base64,qcsd-error-resource-zero",
    "data:image/png;base64,qcsd-error-resource-one",
    "data:image/png;base64,qcsd-error-resource-two",
)
_SYNTHETIC_ERROR_RESOURCE_COLUMNS = (624, 624, 625)
_REMOVE_FIELD = object()


@pytest.fixture
def pinned_error_resource_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, str, str]:
    """Pin compact test URLs without copying Chromium's multi-kilobyte data URLs."""

    signatures = tuple(
        (len(url), hashlib.sha256(url.encode()).hexdigest(), column)
        for url, column in zip(
            _SYNTHETIC_ERROR_RESOURCE_URLS,
            _SYNTHETIC_ERROR_RESOURCE_COLUMNS,
            strict=True,
        )
    )
    monkeypatch.setattr(
        cdp_targets_module,
        "_ERROR_DOCUMENT_RESOURCE_SIGNATURES",
        signatures,
    )
    return _SYNTHETIC_ERROR_RESOURCE_URLS


def _arm_error_document_resources(
    session: _FakeNonFlatSession,
) -> None:
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    session.emit((), "Network.loadingFinished", _error_document_finish())


def _error_resource_request(
    url: str,
    index: int,
    *,
    request_id: str | None = None,
    outer_changes: Mapping[str, Any] | None = None,
    request_changes: Mapping[str, Any] | None = None,
    initiator_changes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "url": url,
        "method": "GET",
        "headers": {
            "User-Agent": cdp_targets_module._PINNED_ERROR_DOCUMENT_USER_AGENT,
            "Referer": "",
        },
        "mixedContentType": "none",
        "initialPriority": "Low",
        "referrerPolicy": "strict-origin-when-cross-origin",
        "isSameSite": False,
    }
    request.update(request_changes or {})
    initiator: dict[str, Any] = {
        "type": "parser",
        "url": cdp_targets_module._ERROR_DOCUMENT_URL,
        "lineNumber": 1504,
        "columnNumber": _SYNTHETIC_ERROR_RESOURCE_COLUMNS[index],
    }
    initiator.update(initiator_changes or {})
    event: dict[str, Any] = {
        "requestId": request_id or f"error-resource-{index}",
        "loaderId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "documentURL": cdp_targets_module._ERROR_DOCUMENT_URL,
        "request": request,
        "timestamp": 42.0 + index,
        "wallTime": 1_725_000_000.0 + index,
        "initiator": initiator,
        "redirectHasExtraInfo": False,
        "type": "Image",
        "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
        "hasUserGesture": False,
    }
    event.update(outer_changes or {})
    return event


def _error_resource_response(
    url: str,
    index: int,
    *,
    request_id: str | None = None,
    outer_changes: Mapping[str, Any] | None = None,
    response_changes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "url": url,
        "status": 200,
        "statusText": "OK",
        "headers": {"Content-Type": "image/png"},
        "mimeType": "image/png",
        "charset": "",
        "connectionReused": False,
        "connectionId": 0,
        "fromDiskCache": False,
        "fromServiceWorker": False,
        "fromPrefetchCache": False,
        "encodedDataLength": 0,
        "protocol": "data",
        "securityState": "unknown",
        "isIpProtectionUsed": False,
    }
    response.update(response_changes or {})
    event: dict[str, Any] = {
        "requestId": request_id or f"error-resource-{index}",
        "loaderId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "timestamp": 42.1 + index,
        "type": "Image",
        "response": response,
        "hasExtraInfo": False,
        "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
    }
    event.update(outer_changes or {})
    return event


def _error_resource_terminal(
    index: int,
    *,
    request_id: str | None = None,
    **changes: Any,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "requestId": request_id or f"error-resource-{index}",
        "timestamp": 42.2 + index,
        "encodedDataLength": 0,
    }
    event.update(changes)
    return event


def _emit_error_resource(
    session: _FakeNonFlatSession,
    url: str,
    index: int,
    *,
    request_id: str | None = None,
) -> None:
    resource_id = request_id or f"error-resource-{index}"
    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(url, index, request_id=resource_id),
    )
    session.emit((), "Network.requestServedFromCache", {"requestId": resource_id})
    session.emit(
        (),
        "Network.responseReceived",
        _error_resource_response(url, index, request_id=resource_id),
    )
    session.emit(
        (),
        "Network.loadingFinished",
        _error_resource_terminal(index, request_id=resource_id),
    )


def _mutate_error_resource_event(
    event: Mapping[str, Any],
    section: str,
    field: str,
    value: object,
) -> dict[str, Any]:
    mutated = dict(event)
    target = mutated
    if section != "outer":
        target = dict(mutated[section])
        mutated[section] = target
    if value is _REMOVE_FIELD:
        target.pop(field)
    else:
        target[field] = value
    return mutated


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


def _attach_worker_kind(
    session: _FakeNonFlatSession,
    router: RecursiveCdpTargetRouter,
    *,
    target_type: str,
    stem: str,
) -> tuple[tuple[str, ...], _FakeBrowserSession | None, str, str]:
    target_id = f"{stem}-target"
    target_url = f"https://worker.test/{stem}.js"
    if target_type == "worker":
        route = _attach_worker(
            session,
            (),
            session_id=f"{stem}-session",
            target_id=target_id,
            target_url=target_url,
        )
        return route, None, target_id, target_url
    if target_type != "shared_worker":
        raise ValueError("test worker target type is invalid")
    browser_session, _guard = _start_shared_worker_guard(session, router)
    route = (f"{stem}-session",)
    session.prepare_guarded_adoption(
        target_id=target_id,
        page_session_id=route[0],
        target_url=target_url,
    )
    _begin_script_bootstrap(
        session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    browser_session.attach(
        guardian_session_id=f"{stem}-guardian",
        target_id=target_id,
        target_url=target_url,
    )
    _pause_script_bootstrap(
        session,
        (),
        target_id=target_id,
        target_url=target_url,
        frame_id="root-frame",
    )
    return route, browser_session, target_id, target_url


def _detach_worker_kind(
    session: _FakeNonFlatSession,
    router: RecursiveCdpTargetRouter,
    *,
    route: tuple[str, ...],
    browser_session: _FakeBrowserSession | None,
    target_id: str,
    stem: str,
) -> None:
    session.emit(route, "Network.loadingFinished", {"requestId": target_id})
    session.detach((), session_id=route[-1])
    if browser_session is not None:
        browser_session.detach(
            guardian_session_id=f"{stem}-guardian",
            target_id=target_id,
        )
    _clean_shutdown(router)


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
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v16"
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
        "Debugger.setInstrumentationBreakpoint",
        "Target.setAutoAttach",
        "Target.getTargetInfo",
        "Runtime.runIfWaitingForDebugger",
        "Runtime.evaluate",
        "Debugger.setBreakpoint",
        "Debugger.removeBreakpoint",
        "Debugger.resume",
        "Debugger.removeBreakpoint",
    ]
    worker_expected = [
        "Debugger.enable",
        "Network.enable",
        "Network.setCacheDisabled",
        "Network.setBypassServiceWorker",
        "Runtime.enable",
        "Runtime.addBinding",
        "Debugger.setInstrumentationBreakpoint",
        "Target.setAutoAttach",
        "Target.getTargetInfo",
        "Runtime.runIfWaitingForDebugger",
        "Debugger.evaluateOnCallFrame",
        "Debugger.removeBreakpoint",
        "Debugger.resume",
    ]
    assert [
        method for seen, method, _params in session.commands if seen == iframe
    ] == iframe_expected
    assert [
        method for seen, method, _params in session.commands if seen == worker
    ] == worker_expected
    iframe_commands = [
        (method, params) for seen, method, params in session.commands if seen == iframe
    ]
    synthetic = next(params for method, params in iframe_commands if method == "Runtime.evaluate")
    assert synthetic == {
        "expression": "true",
        "uniqueContextId": "unique-iframe-session-100",
        "returnByValue": True,
        "awaitPromise": False,
    }
    exact_breakpoint = next(
        params for method, params in iframe_commands if method == "Debugger.setBreakpoint"
    )
    assert exact_breakpoint["location"] == {
        "scriptId": "script-iframe-session",
        "lineNumber": 0,
        "columnNumber": 0,
    }
    assert "iframe-pre-author-installation" in exact_breakpoint["condition"]
    assert exact_breakpoint["condition"].rstrip().endswith("})()")
    assert [
        params for method, params in iframe_commands if method == "Debugger.removeBreakpoint"
    ] == [
        {"breakpointId": "instrumentation-iframe-session"},
        {"breakpointId": "conditional-iframe-session"},
    ]

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


@pytest.mark.parametrize("target_type", ["worker", "shared_worker"])
@pytest.mark.parametrize("pause_before_resume_ack", [True, False])
def test_worker_first_script_prearm_handles_both_initial_resume_orders(
    target_type: str,
    pause_before_resume_ack: bool,
) -> None:
    session = _FakeNonFlatSession()
    session.worker_pause_before_resume_ack = pause_before_resume_ack
    router, _observed = _router(session)
    stem = f"{target_type.replace('_', '-')}-{'pause-first' if pause_before_resume_ack else 'ack-first'}"
    route, browser_session, target_id, _target_url = _attach_worker_kind(
        session,
        router,
        target_type=target_type,
        stem=stem,
    )

    router.raise_if_failed()
    assert router.shutdown_ready is True
    commands = [(method, params) for seen, method, params in session.commands if seen == route]
    methods = [method for method, _params in commands]
    assert "Runtime.evaluate" not in methods
    assert methods.index("Debugger.setInstrumentationBreakpoint") < methods.index(
        "Runtime.runIfWaitingForDebugger"
    )
    assert methods[-3:] == [
        "Debugger.evaluateOnCallFrame",
        "Debugger.removeBreakpoint",
        "Debugger.resume",
    ]
    instrumentation = next(
        params for method, params in commands if method == "Debugger.setInstrumentationBreakpoint"
    )
    assert instrumentation == {"instrumentation": "beforeScriptExecution"}
    call_frame_evaluation = next(
        params for method, params in commands if method == "Debugger.evaluateOnCallFrame"
    )
    assert call_frame_evaluation == {
        "callFrameId": f"worker-frame-{route[0]}",
        "expression": target_egress_shim_source(target_type),
        "returnByValue": True,
    }
    assert next(params for method, params in commands if method == "Debugger.removeBreakpoint") == {
        "breakpointId": f"instrumentation-{route[0]}"
    }
    prearm = router.egress_prearm_summary["by_target_type"][target_type]
    assert prearm["target_count"] == 1
    assert prearm["installed_count"] == 1
    assert prearm["pending_count"] == 0

    _detach_worker_kind(
        session,
        router,
        route=route,
        browser_session=browser_session,
        target_id=target_id,
        stem=stem,
    )


@pytest.mark.parametrize(
    "held_method",
    [
        "Debugger.setInstrumentationBreakpoint",
        "Runtime.runIfWaitingForDebugger",
        "Debugger.evaluateOnCallFrame",
        "Debugger.removeBreakpoint",
        "Debugger.resume",
    ],
)
def test_worker_first_script_prearm_waits_for_every_command_ack(held_method: str) -> None:
    session = _FakeNonFlatSession(hold_methods={held_method})
    router, _observed = _router(session)
    stem = f"held-{held_method.rsplit('.', 1)[-1].lower()}"
    route, browser_session, target_id, _target_url = _attach_worker_kind(
        session,
        router,
        target_type="worker",
        stem=stem,
    )

    router.raise_if_failed()
    assert router.shutdown_ready is False
    assert any(method == held_method for _route, _id, method, _result in session.held)
    session.release_held(held_method)
    router.raise_if_failed()
    assert router.shutdown_ready is True

    _detach_worker_kind(
        session,
        router,
        route=route,
        browser_session=browser_session,
        target_id=target_id,
        stem=stem,
    )


@pytest.mark.parametrize(
    "pause_overrides",
    [
        {"reason": "other"},
        {"script_id": "wrong-script"},
        {"line_number": -1},
        {"column_number": -1},
        {"frame_url": "https://worker.test/wrong.js"},
        {"hit_breakpoints": ["wrong-breakpoint"]},
        {"data_script_id": "wrong-script"},
        {"data_url": "https://worker.test/wrong.js"},
        {"function_script_id": "wrong-script"},
        {"function_line_number": 1},
        {"function_line_number": False},
        {"function_line_number": 0.0},
        {"function_column_number": 1},
        {"function_column_number": False},
        {"function_column_number": 0.0},
    ],
)
def test_worker_first_script_pause_identity_is_exact(
    pause_overrides: dict[str, Any],
) -> None:
    session = _FakeNonFlatSession()
    session.auto_worker_prearm = False
    router, _observed = _router(session)
    route = _attach_worker(
        session,
        (),
        session_id="exact-pause-session",
        target_id="exact-pause-target",
    )
    session.emit_worker_script_parsed(route)
    session.emit_worker_instrumentation_pause(route, **pause_overrides)

    with pytest.raises(CdpTargetIntegrityError, match="first-script.*pause|call-frame"):
        router.raise_if_failed()


def test_worker_first_executable_location_may_follow_script_origin() -> None:
    session = _FakeNonFlatSession()
    session.auto_worker_prearm = False
    router, _observed = _router(session)
    route = _attach_worker(
        session,
        (),
        session_id="offset-pause-session",
        target_id="offset-pause-target",
    )
    session.emit_worker_script_parsed(route)
    session.emit_worker_instrumentation_pause(
        route,
        line_number=3,
        column_number=36,
    )

    router.raise_if_failed()
    assert router.shutdown_ready is True
    session.detach((), session_id=route[-1])
    _clean_shutdown(router)


def test_worker_bootstrap_script_identity_cannot_be_duplicated_or_reused() -> None:
    session = _FakeNonFlatSession()
    session.auto_worker_prearm = False
    router, _observed = _router(session)
    route = _attach_worker(
        session,
        (),
        session_id="duplicate-script-session",
        target_id="duplicate-script-target",
    )
    target_url = str(session.route_info[route]["url"])
    session.emit_worker_script_parsed(route)
    session.emit_worker_script_parsed(
        route,
        script_id="second-bootstrap-script",
        url=target_url,
    )

    with pytest.raises(CdpTargetIntegrityError, match="duplicated|reused"):
        router.raise_if_failed()


def test_post_ready_worker_scripts_are_ignored_and_not_retained() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    route = _attach_worker(
        session,
        (),
        session_id="post-ready-script-session",
        target_id="post-ready-script-target",
    )
    target_url = str(session.route_info[route]["url"])
    state = router._states[route]
    assert state.phase == "ready"
    assert state.worker_parsed_script_urls == {}

    for index in range(100):
        session.emit_worker_script_parsed(
            route,
            script_id=f"post-ready-script-{index}",
            url=target_url if index % 2 else "",
        )

    router.raise_if_failed()
    assert state.phase == "ready"
    assert state.worker_parsed_script_urls == {}
    session.detach((), session_id=route[-1])
    _clean_shutdown(router)


def test_worker_initial_resume_ack_requires_an_exact_empty_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    original_result = session._result

    def nonempty_resume_result(
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = original_result(route, method, params)
        if method == "Runtime.runIfWaitingForDebugger":
            return {"unexpected": True}
        return result

    monkeypatch.setattr(session, "_result", nonempty_resume_result)
    router, _observed = _router(session)
    _attach_worker(
        session,
        (),
        session_id="nonempty-resume-session",
        target_id="nonempty-resume-target",
    )

    with pytest.raises(CdpTargetIntegrityError, match="resume acknowledgement"):
        router.raise_if_failed()


def test_worker_initial_resume_ack_rejects_a_missing_result() -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.runIfWaitingForDebugger"})
    router, _observed = _router(session)
    _attach_worker(
        session,
        (),
        session_id="missing-resume-result-session",
        target_id="missing-resume-result-target",
    )
    selected = next(item for item in session.held if item[2] == "Runtime.runIfWaitingForDebugger")
    session.held.remove(selected)
    route, command_id, _method, _result = selected
    session._deliver(route, {"id": command_id})

    with pytest.raises(CdpTargetIntegrityError, match="returned malformed data"):
        router.raise_if_failed()


def test_worker_duplicate_first_script_pause_fails_closed() -> None:
    session = _FakeNonFlatSession()
    session.auto_worker_prearm = False
    router, _observed = _router(session)
    route = _attach_worker(
        session,
        (),
        session_id="duplicate-pause-session",
        target_id="duplicate-pause-target",
    )
    session.emit_worker_script_parsed(route)
    session.emit_worker_instrumentation_pause(route)
    router.raise_if_failed()
    session.emit_worker_instrumentation_pause(route)

    with pytest.raises(CdpTargetIntegrityError, match="first-script debugger pause"):
        router.raise_if_failed()


def test_worker_detach_before_first_script_prearm_finishes_fails_closed() -> None:
    session = _FakeNonFlatSession()
    session.auto_worker_prearm = False
    router, _observed = _router(session)
    route = _attach_worker(
        session,
        (),
        session_id="prearm-detach-session",
        target_id="prearm-detach-target",
    )
    session.detach((), session_id=route[-1])

    with pytest.raises(CdpTargetIntegrityError, match="work pending"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    "rejected_method",
    [
        "Debugger.setInstrumentationBreakpoint",
        "Debugger.evaluateOnCallFrame",
        "Debugger.removeBreakpoint",
        "Debugger.resume",
    ],
)
def test_worker_first_script_prearm_command_errors_fail_closed(rejected_method: str) -> None:
    session = _FakeNonFlatSession(reject_methods={rejected_method})
    router, _observed = _router(session)
    _attach_worker(
        session,
        (),
        session_id="rejected-command-session",
        target_id="rejected-command-target",
    )

    with pytest.raises(CdpTargetIntegrityError, match="instrumentation failed|command"):
        router.raise_if_failed()


def test_worker_first_script_shim_must_be_a_fresh_installation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    original_result = session._result

    def reused_worker_shim(
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = original_result(route, method, params)
        if method == "Debugger.evaluateOnCallFrame":
            result["result"]["value"]["already_installed"] = True
        return result

    monkeypatch.setattr(session, "_result", reused_worker_shim)
    router, _observed = _router(session)
    _attach_worker(
        session,
        (),
        session_id="reused-shim-session",
        target_id="reused-shim-target",
    )

    with pytest.raises(CdpTargetIntegrityError, match="installation order"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    ("context_before_resume_ack", "receipt_before_debugger_resume_ack"),
    [(True, True), (True, False), (False, True), (False, False)],
)
def test_iframe_pre_author_barrier_handles_both_context_resume_orders(
    context_before_resume_ack: bool,
    receipt_before_debugger_resume_ack: bool,
) -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.iframe_context_before_resume_ack = context_before_resume_ack
    session.iframe_receipt_before_debugger_resume_ack = receipt_before_debugger_resume_ack
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )

    iframe_commands = [
        (method, params) for route, method, params in session.commands if route == iframe
    ]
    methods = [method for method, _params in iframe_commands]
    assert methods.index("Debugger.setInstrumentationBreakpoint") < methods.index(
        "Runtime.runIfWaitingForDebugger"
    )
    assert methods.index("Target.getTargetInfo") < methods.index("Runtime.runIfWaitingForDebugger")
    assert methods[-1] == "Runtime.evaluate"
    assert "Debugger.setBreakpoint" not in methods
    assert iframe_commands[-1][1]["uniqueContextId"] == "unique-iframe-session-100"
    assert router.egress_prearm_summary["pending_total"] == 1

    session.emit_iframe_instrumentation_pause(iframe)
    session.release_held("Runtime.evaluate")
    router.raise_if_failed()
    assert router.egress_prearm_summary["pending_total"] == 0
    assert router.shutdown_ready is True

    session.detach((), session_id="iframe-session")
    _clean_shutdown(router)


def test_iframe_author_script_may_reach_the_barrier_before_initial_resume_ack() -> None:
    session = _FakeNonFlatSession(
        hold_methods={"Runtime.runIfWaitingForDebugger", "Runtime.evaluate"}
    )
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )

    session.emit_iframe_default_context(iframe)
    session.emit_iframe_instrumentation_pause(
        iframe,
        location={"scriptId": "author-script", "lineNumber": 4, "columnNumber": 7},
    )
    router.raise_if_failed()
    assert not any(
        route == iframe and method == "Runtime.evaluate"
        for route, method, _params in session.commands
    )

    session.release_held("Runtime.runIfWaitingForDebugger")
    synthetic_index = next(
        index
        for index, (route, method, _params) in enumerate(session.commands)
        if route == iframe and method == "Runtime.evaluate"
    )
    breakpoint_index = next(
        index
        for index, (route, method, _params) in enumerate(session.commands)
        if route == iframe and method == "Debugger.setBreakpoint"
    )
    assert breakpoint_index < synthetic_index
    session.release_held("Runtime.evaluate")
    router.raise_if_failed()
    assert router.egress_prearm_summary["pending_total"] == 0

    session.detach((), session_id="iframe-session")
    _clean_shutdown(router)


def test_iframe_synthetic_trigger_waits_for_an_exact_default_context() -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    assert not any(
        route == iframe and method == "Runtime.evaluate"
        for route, method, _params in session.commands
    )

    session.emit_iframe_default_context(
        iframe,
        context_id=91,
        unique_context_id="isolated-context",
        is_default=False,
    )
    router.raise_if_failed()
    assert not any(
        route == iframe and method == "Runtime.evaluate"
        for route, method, _params in session.commands
    )

    session.emit_iframe_default_context(iframe, context_id=92, unique_context_id="exact-default")
    command = next(
        params
        for route, method, params in session.commands
        if route == iframe and method == "Runtime.evaluate"
    )
    assert command["uniqueContextId"] == "exact-default"
    session.emit_iframe_instrumentation_pause(iframe)
    session.emit_iframe_installation_receipt(iframe)
    session.release_held("Runtime.evaluate")
    assert router.egress_prearm_summary["pending_total"] == 0

    session.detach((), session_id="iframe-session")
    _clean_shutdown(router)


@pytest.mark.parametrize(
    "event",
    [
        {
            "context": {
                "id": True,
                "uniqueId": "context",
                "auxData": {
                    "isDefault": True,
                    "type": "default",
                    "frameId": "iframe-target",
                },
            }
        },
        {
            "context": {
                "id": 7,
                "uniqueId": "",
                "auxData": {
                    "isDefault": True,
                    "type": "default",
                    "frameId": "iframe-target",
                },
            }
        },
        {
            "context": {
                "id": 7,
                "uniqueId": "context",
                "auxData": {
                    "isDefault": True,
                    "type": "isolated",
                    "frameId": "iframe-target",
                },
            }
        },
        {
            "context": {
                "id": 7,
                "uniqueId": "context",
                "auxData": {
                    "isDefault": True,
                    "type": "default",
                    "frameId": "other-frame",
                },
            }
        },
    ],
)
def test_iframe_malformed_default_context_fails_closed(event) -> None:
    session = _FakeNonFlatSession()
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )

    session.emit(iframe, "Runtime.executionContextCreated", event)
    with pytest.raises(CdpTargetIntegrityError, match="execution context|identity"):
        router.raise_if_failed()


def test_iframe_duplicate_or_destroyed_default_context_fails_closed() -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit_iframe_default_context(iframe, context_id=20, unique_context_id="first-default")
    session.emit_iframe_default_context(iframe, context_id=21, unique_context_id="second-default")
    with pytest.raises(CdpTargetIntegrityError, match="more than one default"):
        router.raise_if_failed()

    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit_iframe_default_context(
        iframe, context_id=22, unique_context_id="destroyed-default"
    )
    session.emit(
        iframe,
        "Runtime.executionContextDestroyed",
        {
            "executionContextId": 22,
            "executionContextUniqueId": "destroyed-default",
        },
    )
    with pytest.raises(CdpTargetIntegrityError, match="destroyed before prearm"):
        router.raise_if_failed()


def test_iframe_context_clear_and_unverified_detach_fail_closed() -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit(iframe, "Runtime.executionContextsCleared", {})
    router.raise_if_failed()
    session.emit_iframe_default_context(iframe)
    session.emit_iframe_instrumentation_pause(iframe)
    session.emit_iframe_installation_receipt(iframe)
    session.release_held("Runtime.evaluate")
    session.detach((), session_id="iframe-session")
    _clean_shutdown(router)

    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit_iframe_default_context(iframe)
    session.emit(iframe, "Runtime.executionContextsCleared", {})
    with pytest.raises(CdpTargetIntegrityError, match="cleared before prearm"):
        router.raise_if_failed()

    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit_iframe_default_context(iframe)
    session.detach((), session_id="iframe-session")
    with pytest.raises(CdpTargetIntegrityError, match="work pending"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    ("reason", "location", "message"),
    [
        ("other", None, "debugger pause"),
        (
            "instrumentation",
            {"scriptId": "", "lineNumber": 0, "columnNumber": 0},
            "call-frame location",
        ),
        (
            "instrumentation",
            {"scriptId": "script", "lineNumber": True, "columnNumber": 0},
            "call-frame location",
        ),
    ],
)
def test_iframe_malformed_instrumentation_pause_fails_closed(
    reason: str,
    location: Mapping[str, Any] | None,
    message: str,
) -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit_iframe_default_context(iframe)
    session.emit_iframe_instrumentation_pause(iframe, reason=reason, location=location)
    with pytest.raises(CdpTargetIntegrityError, match=message):
        router.raise_if_failed()


def test_iframe_duplicate_instrumentation_pause_fails_closed() -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit_iframe_default_context(iframe)
    session.emit_iframe_instrumentation_pause(iframe)
    router.raise_if_failed()
    session.emit_iframe_instrumentation_pause(iframe)
    with pytest.raises(CdpTargetIntegrityError, match="debugger pause is invalid"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    ("already_installed", "execution_context_id"),
    [(True, None), (False, 999)],
)
def test_iframe_installation_receipt_must_be_first_and_context_bound(
    already_installed: bool,
    execution_context_id: int | None,
) -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    session.auto_iframe_prearm = False
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit_iframe_default_context(iframe)
    session.emit_iframe_instrumentation_pause(iframe)
    session.emit_iframe_installation_receipt(
        iframe,
        already_installed=already_installed,
        execution_context_id=execution_context_id,
    )
    with pytest.raises(CdpTargetIntegrityError, match="installation order|receipt is invalid"):
        router.raise_if_failed()


def test_nested_protocol_error_preserves_bounded_code_and_message() -> None:
    session = _FakeNonFlatSession(hold_methods={"Debugger.setInstrumentationBreakpoint"})
    router, _observed = _router(session)
    session.auto_iframe_prearm = False
    session.attach((), session_id="iframe-session", target_id="iframe-target", target_type="iframe")

    session.release_held_error(
        "Debugger.setInstrumentationBreakpoint",
        {"code": -32000, "message": "Cannot find\ndefault execution context"},
    )
    with pytest.raises(
        CdpTargetIntegrityError,
        match=r"code=-32000, message=Cannot find default execution context",
    ):
        router.raise_if_failed()


def test_nested_protocol_error_rejects_unbounded_code_and_bounds_message() -> None:
    with pytest.raises(CdpTargetIntegrityError, match="malformed error"):
        _sanitised_protocol_error({"code": 10**1_000, "message": "arbitrary"})

    detail = _sanitised_protocol_error({"code": -32000, "message": "x" * 1_000})
    assert detail == f"code=-32000, message={'x' * 240}"
    assert len(detail) == len("code=-32000, message=") + 240


def test_iframe_synthetic_response_is_a_required_terminal_command() -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.evaluate"})
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.emit_iframe_instrumentation_pause(iframe)
    router.raise_if_failed()
    assert router.egress_prearm_summary["pending_total"] == 0
    assert router.shutdown_ready is False

    session.release_held_error(
        "Runtime.evaluate",
        {"code": -32000, "message": "synthetic context disappeared"},
    )
    with pytest.raises(
        CdpTargetIntegrityError,
        match=r"pre-author-trigger failed \(code=-32000, message=synthetic context disappeared\)",
    ):
        router.raise_if_failed()


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


def test_child_document_failure_state_waits_for_exact_nested_acknowledgement() -> None:
    session = _FakeNonFlatSession(hold_methods={"Fetch.failRequest"})
    acknowledged = [False]
    pending_chains: set[tuple[tuple[str, ...], str, int, str]] = set()
    router_holder: list[RecursiveCdpTargetRouter] = []

    def on_event(
        source: CdpTargetSource,
        method: str,
        event: Mapping[str, Any],
    ) -> None:
        if method != "Fetch.requestPaused":
            return
        chain_key = source.request_chain_key(str(event["networkId"]))

        def acknowledge(_result: Mapping[str, Any]) -> None:
            acknowledged[0] = True
            pending_chains.add(chain_key)

        router_holder[0]._send_policy_decision(
            source,
            "Fetch.failRequest",
            {"requestId": event["requestId"], "errorReason": "BlockedByClient"},
            label="child-document-policy:Fetch.failRequest",
            on_success=acknowledge,
        )

    router = RecursiveCdpTargetRouter(session, on_event=on_event)
    router_holder.append(router)
    router.start()
    browser_session = _FakeBrowserSession()
    guard = BrowserSharedWorkerGuard(browser_session, router)
    guard.start()
    _ROUTER_GUARDS[router] = (browser_session, guard)
    iframe = session.attach(
        (),
        session_id="held-document-policy-session",
        target_id="held-document-policy-target",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    chain_key = router._state(iframe).source.request_chain_key("child-document-network")

    session.emit(
        iframe,
        "Fetch.requestPaused",
        {
            "requestId": "child-document-fetch",
            "networkId": "child-document-network",
            "frameId": "held-document-policy-target",
            "resourceType": "Document",
            "request": {"method": "GET", "url": "https://frame.test/blocked"},
        },
    )

    assert acknowledged == [False]
    assert chain_key not in pending_chains
    assert sum(command.policy_decision for command in router._pending.values()) == 1
    session.release_held("Fetch.failRequest")
    assert acknowledged == [True]
    assert pending_chains == {chain_key}
    assert not any(command.policy_decision for command in router._pending.values())


def test_exact_root_invalid_interception_waits_for_matching_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal_method = "Network.loadingFinished"
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="root-font-network",
        fetch_id="root-font-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        result = original_send(method, params)
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return result

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)

    router.raise_if_failed()
    assert router.root_invalid_interception_summary == {
        "schema_version": 1,
        "total": 1,
        "resolved": 0,
        "pending": 1,
        "aborted": 0,
        "fetch_identity_saturated": False,
        "network_identity_saturated": False,
        "terminal_history_saturated": False,
        "terminal_outcomes": {
            "Network.loadingFinished": 0,
        },
        "diagnostics_truncated": 0,
        "diagnostics": [],
    }
    assert router.shutdown_ready is False
    with pytest.raises(CdpTargetIntegrityError, match="policy commands pending"):
        router.begin_shutdown()

    session.emit(
        (),
        terminal_method,
        _root_terminal_event("root-font-network", terminal_method),
    )
    summary = router.root_invalid_interception_summary
    assert summary["resolved"] == 1
    assert summary["pending"] == 0
    assert summary["terminal_outcomes"][terminal_method] == 1
    assert len(summary["diagnostics"]) == 1
    serialized = json.dumps(summary, sort_keys=True)
    assert "root-font-network" not in serialized
    assert "root-font-fetch" not in serialized
    assert "font.woff2" not in serialized
    _clean_shutdown(router)


def test_exact_root_invalid_interception_accepts_terminal_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="terminal-first-network",
        fetch_id="terminal-first-fetch",
        resource_type="Stylesheet",
        url="https://root.test/site.css",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event(
            "terminal-first-network",
            "Network.loadingFinished",
            resource_type="Stylesheet",
        ),
    )
    original_send = session.send

    def invalid_continue(method: str, params=None):
        result = original_send(method, params)
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return result

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)

    router.raise_if_failed()
    summary = router.root_invalid_interception_summary
    assert summary["total"] == summary["resolved"] == 1
    assert summary["pending"] == 0
    assert summary["diagnostics"][0]["terminal_before_policy"] is True
    _clean_shutdown(router)


def test_exact_root_invalid_interception_accepts_terminal_dispatched_during_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="reentrant-network",
        fetch_id="reentrant-fetch",
        resource_type="Stylesheet",
        url="https://root.test/reentrant.css",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def terminal_then_invalid(method: str, params=None):
        result = original_send(method, params)
        if method == "Fetch.continueRequest":
            session.emit(
                (),
                "Network.loadingFinished",
                _root_terminal_event(
                    "reentrant-network",
                    "Network.loadingFinished",
                    resource_type="Stylesheet",
                ),
            )
            raise _invalid_interception_error()
        return result

    monkeypatch.setattr(session, "send", terminal_then_invalid)
    session.emit((), "Fetch.requestPaused", fetch_event)

    router.raise_if_failed()
    summary = router.root_invalid_interception_summary
    assert summary["total"] == summary["resolved"] == 1
    assert summary["diagnostics"][0]["terminal_before_policy"] is False
    _clean_shutdown(router)


@pytest.mark.parametrize(
    ("frame_id", "resource_type", "label"),
    (
        (
            "in-process-child-frame",
            "Font",
            "catalogue-navigation-policy:Fetch.continueRequest",
        ),
        (
            "root-frame",
            "Image",
            "catalogue-navigation-policy:Fetch.continueRequest",
        ),
        ("root-frame", "Font", "request-stage-policy:Fetch.continueRequest"),
    ),
)
def test_exact_invalid_interception_recovery_has_a_narrow_policy_boundary(
    monkeypatch: pytest.MonkeyPatch,
    frame_id: str,
    resource_type: str,
    label: str,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy_label=label)
    network_event, fetch_event = _root_request_events(
        network_id="ineligible-network",
        fetch_id="ineligible-fetch",
        resource_type=resource_type,
        url="https://root.test/ineligible.bin",
    )
    network_event["frameId"] = frame_id
    fetch_event["frameId"] = frame_id
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_provisional_invalid_interception_rejects_a_malformed_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="malformed-terminal-network",
        fetch_id="malformed-terminal-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)
    session.emit(
        (),
        "Network.loadingFinished",
        {"requestId": "malformed-terminal-network"},
    )

    with pytest.raises(CdpTargetIntegrityError, match="malformed or ineligible"):
        router.raise_if_failed()


def test_provisional_invalid_interception_rejects_loading_failed_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="failed-terminal-network",
        fetch_id="failed-terminal-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)
    session.emit(
        (),
        "Network.loadingFailed",
        _root_terminal_event(
            "failed-terminal-network",
            "Network.loadingFailed",
        ),
    )

    with pytest.raises(CdpTargetIntegrityError, match="malformed or ineligible"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["resolved"] == 0
    assert router.root_invalid_interception_summary["pending"] == 1


def test_exact_invalid_interception_is_never_accepted_for_fail_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()

    def deny(_source: CdpTargetSource, event: Mapping[str, Any]):
        return "Fetch.failRequest", {
            "requestId": event["requestId"],
            "errorReason": "BlockedByClient",
        }

    router, _observed = _router(session, fetch_policy=deny)
    network_event, fetch_event = _root_request_events(
        network_id="denied-network",
        fetch_id="denied-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_failure(method: str, params=None):
        if method == "Fetch.failRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_failure)
    session.emit((), "Fetch.requestPaused", fetch_event)

    with pytest.raises(CdpTargetIntegrityError, match="exception_sha256"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_document_denial_lifecycle_never_enters_root_continue_recovery() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())

    router.raise_if_failed()
    summary = router.root_invalid_interception_summary
    assert summary["total"] == 0
    assert summary["resolved"] == 0
    assert summary["pending"] == 0
    assert summary["aborted"] == 0
    _clean_abort(router)


@pytest.mark.parametrize(
    "error_factory",
    (
        lambda: RuntimeError(
            "CDPSession.send: Protocol error (Fetch.continueRequest): "
            "Invalid InterceptionId."
        ),
        lambda: _invalid_interception_error("different protocol error"),
        lambda: _invalid_interception_error(name="TargetClosedError"),
        _invalid_interception_with_changed_message_attribute,
        lambda: _PinnedPlaywrightErrorSubclass(
            cdp_targets_module._ROOT_CONTINUE_INVALID_INTERCEPTION_MESSAGE,
            name="Error",
        ),
    ),
)
def test_root_continue_rejects_every_non_exact_transport_error(
    monkeypatch: pytest.MonkeyPatch,
    error_factory: Any,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="wrong-error-network",
        fetch_id="wrong-error-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def fail_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise error_factory()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", fail_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)

    with pytest.raises(CdpTargetIntegrityError, match="exception_sha256") as captured:
        router.raise_if_failed()
    assert "different protocol error" not in str(captured.value)
    assert router.root_invalid_interception_summary["total"] == 0


def test_exact_error_recovery_requires_an_explicit_error_type_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
        root_continue_error_type=None,
    )
    network_event, fetch_event = _root_request_events(
        network_id="no-opt-in-network",
        fetch_id="no-opt-in-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)

    with pytest.raises(CdpTargetIntegrityError, match="exception_sha256"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


@pytest.mark.parametrize("response_stage", [False, True])
def test_exact_error_recovery_rejects_changed_method_or_response_stage(
    monkeypatch: pytest.MonkeyPatch,
    response_stage: bool,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="wrong-stage-network",
        fetch_id="wrong-stage-fetch",
    )
    if response_stage:
        fetch_event["responseStatusCode"] = 200
    else:
        network_event["request"]["method"] = "POST"
        fetch_event["request"]["method"] = "POST"
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_exact_error_recovery_rejects_changed_continue_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()

    def changed_params(_source: CdpTargetSource, event: Mapping[str, Any]):
        return "Fetch.continueRequest", {
            "requestId": event["requestId"],
            "url": event["request"]["url"],
        }

    router, _observed = _router(
        session,
        fetch_policy=changed_params,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="changed-params-network",
        fetch_id="changed-params-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_exact_invalid_interception_requires_matching_network_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    _network_event, fetch_event = _root_request_events(
        network_id="missing-network",
        fetch_id="missing-fetch",
    )
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_root_fetch_rejects_mismatched_and_duplicate_policy_identities() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    network_event, fetch_event = _root_request_events(
        network_id="identity-network",
        fetch_id="identity-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    mismatched = dict(fetch_event)
    mismatched["request"] = {"method": "GET", "url": "https://root.test/other.css"}
    session.emit((), "Fetch.requestPaused", mismatched)
    with pytest.raises(CdpTargetIntegrityError, match="does not exactly match"):
        router.raise_if_failed()

    clean_session = _FakeNonFlatSession()
    clean_router, _observed = _router(clean_session)
    clean_session.emit((), "Network.requestWillBeSent", network_event)
    clean_session.emit((), "Fetch.requestPaused", fetch_event)
    clean_session.emit((), "Fetch.requestPaused", fetch_event)
    with pytest.raises(CdpTargetIntegrityError, match="duplicated or reused"):
        clean_router.raise_if_failed()


def test_distinct_fetch_id_cannot_claim_one_provisional_network_occurrence_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="double-claim-network",
        fetch_id="double-claim-fetch-a",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)
    second_fetch = dict(fetch_event)
    second_fetch["requestId"] = "double-claim-fetch-b"
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="claimed by more than one"):
        router.raise_if_failed()
    summary = router.root_invalid_interception_summary
    assert summary["total"] == 1
    assert summary["pending"] == 1


def test_distinct_fetch_id_cannot_reclaim_after_a_successful_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, first_fetch = _root_request_events(
        network_id="successful-double-claim-network",
        fetch_id="successful-double-claim-fetch-a",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    session.emit((), "Fetch.requestPaused", first_fetch)
    second_fetch = dict(first_fetch)
    second_fetch["requestId"] = "successful-double-claim-fetch-b"
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="claimed by more than one"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_distinct_fetch_id_cannot_reclaim_one_terminal_network_occurrence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="terminal-double-claim-network",
        fetch_id="terminal-double-claim-fetch-a",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event(
            "terminal-double-claim-network",
            "Network.loadingFinished",
        ),
    )
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)
    second_fetch = dict(fetch_event)
    second_fetch["requestId"] = "terminal-double-claim-fetch-b"
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="claimed by more than one"):
        router.raise_if_failed()
    summary = router.root_invalid_interception_summary
    assert summary["total"] == summary["resolved"] == 1


def test_distinct_redirect_legs_can_each_receive_successful_continue() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    first_network, first_fetch = _root_request_events(
        network_id="redirect-network",
        fetch_id="redirect-fetch-a",
        resource_type="Stylesheet",
        url="https://root.test/old.css",
    )
    session.emit((), "Network.requestWillBeSent", first_network)
    session.emit((), "Fetch.requestPaused", first_fetch)

    redirected_network = dict(first_network)
    redirected_network["redirectResponse"] = {"status": 302}
    redirected_network["request"] = {
        "method": "GET",
        "url": "https://root.test/new.css",
    }
    second_fetch = dict(first_fetch)
    second_fetch["requestId"] = "redirect-fetch-b"
    second_fetch["request"] = dict(redirected_network["request"])
    session.emit((), "Network.requestWillBeSent", redirected_network)
    session.emit((), "Fetch.requestPaused", second_fetch)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event(
            "redirect-network",
            "Network.loadingFinished",
            resource_type="Stylesheet",
        ),
    )

    router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0
    _clean_shutdown(router)


def test_redirect_cannot_replace_a_provisional_invalid_interception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="provisional-redirect-network",
        fetch_id="provisional-redirect-fetch",
        resource_type="Stylesheet",
        url="https://root.test/old.css",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)
    redirect = dict(network_event)
    redirect["redirectResponse"] = {"status": 302}
    redirect["request"] = {"method": "GET", "url": "https://root.test/new.css"}
    session.emit((), "Network.requestWillBeSent", redirect)

    with pytest.raises(CdpTargetIntegrityError, match="redirected while"):
        router.raise_if_failed()


def test_identical_field_redirect_disables_invalid_interception_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="identical-redirect-network",
        fetch_id="identical-redirect-fetch-a",
        resource_type="Stylesheet",
        url="https://root.test/same.css",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    session.emit((), "Fetch.requestPaused", fetch_event)
    redirect = dict(network_event)
    redirect["redirectResponse"] = {"status": 304}
    session.emit((), "Network.requestWillBeSent", redirect)
    second_fetch = dict(fetch_event)
    second_fetch["requestId"] = "identical-redirect-fetch-b"
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_nonadjacent_identical_redirect_leg_disables_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    first_network, delayed_fetch = _root_request_events(
        network_id="aba-redirect-network",
        fetch_id="aba-delayed-fetch",
        resource_type="Stylesheet",
        url="https://root.test/a.css",
    )
    session.emit((), "Network.requestWillBeSent", first_network)
    middle_network = dict(first_network)
    middle_network["redirectResponse"] = {"status": 302}
    middle_network["request"] = {
        "method": "GET",
        "url": "https://root.test/b.css",
    }
    session.emit((), "Network.requestWillBeSent", middle_network)
    final_network = dict(first_network)
    final_network["redirectResponse"] = {"status": 302}
    session.emit((), "Network.requestWillBeSent", final_network)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event(
            "aba-redirect-network",
            "Network.loadingFinished",
            resource_type="Stylesheet",
        ),
    )
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", delayed_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_raw_network_id_reuse_disables_invalid_interception_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    first_network, _first_fetch = _root_request_events(
        network_id="reused-network",
        fetch_id="old-fetch",
    )
    session.emit((), "Network.requestWillBeSent", first_network)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event("reused-network", "Network.loadingFinished"),
    )
    second_network, second_fetch = _root_request_events(
        network_id="reused-network",
        fetch_id="new-fetch",
    )
    session.emit((), "Network.requestWillBeSent", second_network)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_network_id_reuse_after_loading_failed_disables_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    first_network, _first_fetch = _root_request_events(
        network_id="failed-reuse-network",
        fetch_id="failed-reuse-old-fetch",
    )
    session.emit((), "Network.requestWillBeSent", first_network)
    session.emit(
        (),
        "Network.loadingFailed",
        _root_terminal_event(
            "failed-reuse-network",
            "Network.loadingFailed",
        ),
    )
    second_network, second_fetch = _root_request_events(
        network_id="failed-reuse-network",
        fetch_id="failed-reuse-new-fetch",
    )
    session.emit((), "Network.requestWillBeSent", second_network)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_fetch_identity_saturation_disables_invalid_interception_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cdp_targets_module, "_ROOT_FETCH_IDENTITY_LIMIT", 1)
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    first_network, first_fetch = _root_request_events(
        network_id="identity-cap-network-a",
        fetch_id="identity-cap-fetch-a",
    )
    session.emit((), "Network.requestWillBeSent", first_network)
    session.emit((), "Fetch.requestPaused", first_fetch)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event("identity-cap-network-a", "Network.loadingFinished"),
    )

    second_network, second_fetch = _root_request_events(
        network_id="identity-cap-network-b",
        fetch_id="identity-cap-fetch-b",
    )
    session.emit((), "Network.requestWillBeSent", second_network)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    summary = router.root_invalid_interception_summary
    assert summary["total"] == 0
    assert summary["fetch_identity_saturated"] is True


def test_network_identity_saturation_disables_invalid_interception_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cdp_targets_module, "_ROOT_NETWORK_IDENTITY_LIMIT", 1)
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    first_network, _first_fetch = _root_request_events(
        network_id="network-cap-a",
        fetch_id="network-cap-fetch-a",
    )
    session.emit((), "Network.requestWillBeSent", first_network)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event("network-cap-a", "Network.loadingFinished"),
    )
    second_network, second_fetch = _root_request_events(
        network_id="network-cap-b",
        fetch_id="network-cap-fetch-b",
    )
    session.emit((), "Network.requestWillBeSent", second_network)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
        router.raise_if_failed()
    summary = router.root_invalid_interception_summary
    assert summary["total"] == 0
    assert summary["network_identity_saturated"] is True


def test_exact_invalid_interception_is_not_available_to_child_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach(
        (),
        session_id="invalid-interception-child-session",
        target_id="invalid-interception-child-target",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    network_event, fetch_event = _root_request_events(
        network_id="child-network",
        fetch_id="child-fetch",
        resource_type="Font",
        url="https://frame.test/font.woff2",
    )
    network_event["frameId"] = "invalid-interception-child-target"
    fetch_event["frameId"] = "invalid-interception-child-target"
    session.emit(iframe, "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_child_transport(method: str, params=None):
        if method == "Target.sendMessageToTarget":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_child_transport)
    session.emit(iframe, "Fetch.requestPaused", fetch_event)

    with pytest.raises(CdpTargetIntegrityError, match="exception_sha256"):
        router.raise_if_failed()
    assert router.root_invalid_interception_summary["total"] == 0


def test_provisional_root_invalid_interception_rejects_child_terminal_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    child = session.attach(
        (),
        session_id="terminal-source-child-session",
        target_id="terminal-source-child-target",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    network_event, fetch_event = _root_request_events(
        network_id="terminal-source-network",
        fetch_id="terminal-source-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)
    session.emit(
        child,
        "Network.loadingFinished",
        _root_terminal_event("terminal-source-network", "Network.loadingFinished"),
    )

    with pytest.raises(CdpTargetIntegrityError, match="no active request occurrence"):
        router.raise_if_failed()
    summary = router.root_invalid_interception_summary
    assert summary["pending"] == 1
    assert summary["resolved"] == 0


def test_abort_retires_but_never_resolves_provisional_invalid_interception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    network_event, fetch_event = _root_request_events(
        network_id="aborted-network",
        fetch_id="aborted-fetch",
    )
    session.emit((), "Network.requestWillBeSent", network_event)
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", fetch_event)
    assert router.root_invalid_interception_summary["pending"] == 1

    _browser_session, guard = _guard_for(router)
    router.begin_abort()
    guard.begin_abort()
    assert router.root_invalid_interception_summary["pending"] == 1
    assert router.root_invalid_interception_summary["aborted"] == 0
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event("aborted-network", "Network.loadingFinished"),
    )
    assert router.root_invalid_interception_summary["resolved"] == 0
    assert router.root_invalid_interception_summary["pending"] == 1
    guard.finish_abort()
    router.finish_abort()
    assert router.root_invalid_interception_summary == {
        "schema_version": 1,
        "total": 1,
        "resolved": 0,
        "pending": 0,
        "aborted": 1,
        "fetch_identity_saturated": False,
        "network_identity_saturated": False,
        "terminal_history_saturated": False,
        "terminal_outcomes": {
            "Network.loadingFinished": 0,
        },
        "diagnostics_truncated": 0,
        "diagnostics": [],
    }


def test_invalid_interception_diagnostics_are_bounded_and_identifier_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cdp_targets_module, "_ROOT_CONTINUE_DIAGNOSTIC_LIMIT", 2)
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    raw_values: list[str] = []
    for index in range(3):
        network_id = f"bounded-network-{index}"
        fetch_id = f"bounded-fetch-{index}"
        url = f"https://root.test/private-{index}.css"
        raw_values.extend((network_id, fetch_id, url))
        network_event, fetch_event = _root_request_events(
            network_id=network_id,
            fetch_id=fetch_id,
            resource_type="Stylesheet",
            url=url,
        )
        session.emit((), "Network.requestWillBeSent", network_event)
        session.emit((), "Fetch.requestPaused", fetch_event)
        session.emit(
            (),
            "Network.loadingFinished",
            _root_terminal_event(
                network_id,
                "Network.loadingFinished",
                resource_type="Stylesheet",
            ),
        )

    summary = router.root_invalid_interception_summary
    assert summary["total"] == summary["resolved"] == 3
    assert len(summary["diagnostics"]) == 2
    assert summary["diagnostics_truncated"] == 1
    serialized = json.dumps(summary, sort_keys=True)
    assert all(value not in serialized for value in raw_values)
    _clean_shutdown(router)


def test_saturated_terminal_history_disables_late_recovery_without_eviction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cdp_targets_module, "_ROOT_TERMINAL_HISTORY_LIMIT", 1)
    session = _FakeNonFlatSession()
    router, _observed = _router(
        session,
        fetch_policy_label="catalogue-navigation-policy:Fetch.continueRequest",
    )
    first_network, _first_fetch = _root_request_events(
        network_id="retained-terminal-network",
        fetch_id="retained-terminal-fetch",
    )
    session.emit((), "Network.requestWillBeSent", first_network)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event(
            "retained-terminal-network",
            "Network.loadingFinished",
        ),
    )
    second_network, second_fetch = _root_request_events(
        network_id="unretained-terminal-network",
        fetch_id="unretained-terminal-fetch",
        resource_type="Stylesheet",
        url="https://root.test/unretained.css",
    )
    session.emit((), "Network.requestWillBeSent", second_network)
    session.emit(
        (),
        "Network.loadingFinished",
        _root_terminal_event(
            "unretained-terminal-network",
            "Network.loadingFinished",
            resource_type="Stylesheet",
        ),
    )
    assert router.root_invalid_interception_summary["terminal_history_saturated"] is True
    original_send = session.send

    def invalid_continue(method: str, params=None):
        if method == "Fetch.continueRequest":
            raise _invalid_interception_error()
        return original_send(method, params)

    monkeypatch.setattr(session, "send", invalid_continue)
    session.emit((), "Fetch.requestPaused", second_fetch)

    with pytest.raises(CdpTargetIntegrityError, match="InvalidInterceptionId"):
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


def test_exact_blocked_root_document_error_finish_is_consumed_once() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session, fetch_policy=_deny_blocked_by_client)

    _begin_blocked_document(session)
    assert any(
        route == ()
        and method == "Fetch.failRequest"
        and params
        == {
            "requestId": _BLOCKED_DOCUMENT_FETCH_ID,
            "errorReason": "BlockedByClient",
        }
        for route, method, params in session.commands
    )
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    assert router.active_request_identities == ()
    session.emit((), "Network.loadingFinished", _error_document_finish())
    router.raise_if_failed()

    terminal_methods = [
        method
        for _source, method, event in observed
        if event.get("requestId") == _BLOCKED_DOCUMENT_REQUEST_ID
        and method in {"Network.loadingFailed", "Network.loadingFinished"}
    ]
    assert terminal_methods == ["Network.loadingFailed"]
    _clean_shutdown(router)


def test_error_document_finish_is_optional_at_context_disposal() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)

    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    router.raise_if_failed()
    _clean_shutdown(router)


def test_exact_blocked_document_abort_is_consumed_only_during_exceptional_disposal() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    chain_key = router.root_source.request_chain_key(_BLOCKED_DOCUMENT_REQUEST_ID)
    assert chain_key in router._error_document_finishes
    _browser_session, guard = _guard_for(router)
    router.begin_abort()
    guard.begin_abort()

    session.emit((), "Network.loadingFailed", _error_document_abort())
    router.raise_if_failed()

    assert router.active_request_identities == ()
    assert chain_key not in router._error_document_finishes
    assert chain_key in router._retired_error_document_chains
    assert router._error_document_resources == {}
    assert router._error_resource_by_request_id == {}
    terminals = [
        (source, method, event)
        for source, method, event in observed
        if event.get("requestId") == _BLOCKED_DOCUMENT_REQUEST_ID
        and method in {"Network.loadingFailed", "Network.loadingFinished"}
    ]
    assert terminals == [(router.root_source, "Network.loadingFailed", _blocked_document_failure())]
    guard.finish_abort()
    router.finish_abort()
    with pytest.raises(CdpTargetIntegrityError, match="during abort"):
        router.finish()


@pytest.mark.parametrize("shutdown", [False, True])
def test_error_document_abort_requires_exceptional_not_normal_shutdown(shutdown: bool) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    if shutdown:
        _begin_shutdown(router)

    session.emit((), "Network.loadingFailed", _error_document_abort())
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()
    assert router._error_document_resources == {}


@pytest.mark.parametrize(
    "terminal",
    [pytest.param(event, id=name) for name, event in _invalid_error_document_aborts()],
)
def test_error_document_abort_requires_exact_later_signature(
    terminal: Mapping[str, Any],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    router.begin_abort()

    session.emit((), "Network.loadingFailed", terminal)
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()
    assert router._error_document_resources == {}


@pytest.mark.parametrize(
    "source_changes",
    [
        pytest.param({"target_id": "other-root"}, id="target"),
        pytest.param({"generation": 1}, id="generation"),
        pytest.param({"target_type": "iframe"}, id="type"),
        pytest.param({"parent_session_path": ("other-parent",)}, id="parent"),
        pytest.param({"parent_frame_id": "other-frame"}, id="frame"),
    ],
)
def test_error_document_abort_rejects_changed_source_identity(
    source_changes: dict[str, Any],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    router.begin_abort()

    with pytest.raises(CdpTargetIntegrityError):
        router._handle_forwarded(
            replace(router.root_source, **source_changes),
            "Network.loadingFailed",
            _error_document_abort(),
        )
    assert len(router._error_document_finishes) == 1
    assert router._error_document_resources == {}


@pytest.mark.parametrize("second_terminal", ["abort", "finish", "after-disposal"])
def test_consumed_error_document_abort_rejects_any_further_terminal(
    second_terminal: str,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    _browser_session, guard = _guard_for(router)
    router.begin_abort()
    guard.begin_abort()
    session.emit((), "Network.loadingFailed", _error_document_abort())
    router.raise_if_failed()
    if second_terminal == "after-disposal":
        guard.finish_abort()
        router.finish_abort()

    session.emit(
        (),
        "Network.loadingFinished" if second_terminal == "finish" else "Network.loadingFailed",
        _error_document_finish(timestamp=41.27)
        if second_terminal == "finish"
        else _error_document_abort(timestamp=41.27),
    )
    with pytest.raises(CdpTargetIntegrityError, match="retired Document"):
        router.raise_if_failed()
    assert router._error_document_resources == {}


def test_error_document_abort_cannot_replace_an_already_consumed_finish() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    session.emit((), "Network.loadingFinished", _error_document_finish())
    router.raise_if_failed()
    router.begin_abort()

    session.emit((), "Network.loadingFailed", _error_document_abort(timestamp=41.27))
    with pytest.raises(CdpTargetIntegrityError, match="retired Document"):
        router.raise_if_failed()


@pytest.mark.parametrize("policy_kind", ["continue", "wrong-failure", "no-document"])
def test_error_document_abort_requires_acknowledged_blocked_document(policy_kind: str) -> None:
    session = _FakeNonFlatSession()
    policy = None
    if policy_kind == "wrong-failure":

        def policy(
            _source: CdpTargetSource, event: Mapping[str, Any]
        ) -> tuple[str, dict[str, str]]:
            return (
                "Fetch.failRequest",
                {"requestId": event["requestId"], "errorReason": "Aborted"},
            )

    router, _observed = _router(session, fetch_policy=policy)
    if policy_kind != "no-document":
        _begin_blocked_document(session)
        session.emit((), "Network.loadingFailed", _blocked_document_failure())
    router.raise_if_failed()
    router.begin_abort()

    session.emit((), "Network.loadingFailed", _error_document_abort())
    with pytest.raises(CdpTargetIntegrityError, match="no active request"):
        router.raise_if_failed()
    assert router._error_document_resources == {}


def test_error_document_abort_rejects_failure_before_denial_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    original_result = session._result

    def failure_before_ack(
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if route == () and method == "Fetch.failRequest":
            session.emit((), "Network.loadingFailed", _blocked_document_failure())
        return original_result(route, method, params)

    monkeypatch.setattr(session, "_result", failure_before_ack)
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    with pytest.raises(CdpTargetIntegrityError, match="before its denial acknowledgement"):
        router.raise_if_failed()
    assert router._error_document_finishes == {}
    assert router._pending_blocked_documents == {}
    router.begin_abort()

    # Direct dispatch exposes the new event's rejection independently of the
    # earlier recorded integrity error, which must also remain unchanged.
    with pytest.raises(CdpTargetIntegrityError, match="no active request"):
        router._handle_forwarded(
            router.root_source, "Network.loadingFailed", _error_document_abort()
        )
    with pytest.raises(CdpTargetIntegrityError, match="before its denial acknowledgement"):
        router.raise_if_failed()
    assert router._error_document_resources == {}


def test_error_document_abort_rejects_same_raw_request_id_on_child_source() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    iframe = session.attach(
        (),
        session_id="error-abort-iframe-session",
        target_id="error-abort-iframe-target",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    router.begin_abort()

    session.emit(iframe, "Network.loadingFailed", _error_document_abort())
    with pytest.raises(CdpTargetIntegrityError, match="no active request"):
        router.raise_if_failed()
    assert len(router._error_document_finishes) == 1
    assert router._error_document_resources == {}


@pytest.mark.parametrize(
    "terminal",
    [pytest.param(event, id=name) for name, event in _invalid_blocked_document_failures()],
)
def test_blocked_document_requires_exact_loading_failed_signature(
    terminal: Mapping[str, Any],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)

    session.emit((), "Network.loadingFailed", terminal)
    with pytest.raises(CdpTargetIntegrityError, match="mismatched terminal"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    "terminal",
    [pytest.param(event, id=name) for name, event in _invalid_error_document_finishes()],
)
def test_error_document_finish_requires_exact_later_positive_signature(
    terminal: Mapping[str, Any],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())

    session.emit((), "Network.loadingFinished", terminal)
    with pytest.raises(CdpTargetIntegrityError, match="exact terminal signature"):
        router.raise_if_failed()


@pytest.mark.parametrize("policy_kind", ("continue", "wrong-failure"))
def test_non_matching_document_policy_does_not_authorise_a_second_terminal(
    policy_kind: str,
) -> None:
    def policy(
        _source: CdpTargetSource,
        event: Mapping[str, Any],
    ) -> tuple[str, dict[str, str]]:
        if policy_kind == "continue":
            return "Fetch.continueRequest", {"requestId": event["requestId"]}
        return (
            "Fetch.failRequest",
            {"requestId": event["requestId"], "errorReason": "Aborted"},
        )

    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=policy)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    router.raise_if_failed()

    session.emit((), "Network.loadingFinished", _error_document_finish())
    with pytest.raises(CdpTargetIntegrityError, match="no active request"):
        router.raise_if_failed()


def test_equal_fetch_and_network_ids_do_not_authorise_a_second_terminal() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(
        session,
        fetch_event={
            "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "networkId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
            "resourceType": "Document",
            "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
        },
    )
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    router.raise_if_failed()

    session.emit((), "Network.loadingFinished", _error_document_finish())
    with pytest.raises(CdpTargetIntegrityError, match="no active request"):
        router.raise_if_failed()


def test_eligible_document_pause_requires_one_callback_policy_decision() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=lambda _source, _event: None)

    _begin_blocked_document(session)
    with pytest.raises(CdpTargetIntegrityError, match="callback returned without a decision"):
        router.raise_if_failed()


def test_blocked_document_rejects_loading_finished_before_loading_failed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)

    session.emit((), "Network.loadingFinished", _error_document_finish())
    with pytest.raises(CdpTargetIntegrityError, match="mismatched terminal"):
        router.raise_if_failed()


def test_consumed_error_document_finish_rejects_a_third_terminal() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    session.emit((), "Network.loadingFinished", _error_document_finish())
    router.raise_if_failed()

    session.emit((), "Network.loadingFinished", _error_document_finish(timestamp=41.27))
    with pytest.raises(CdpTargetIntegrityError, match="repeated a terminal"):
        router.raise_if_failed()


@pytest.mark.parametrize("consume_finish", (False, True))
def test_blocked_document_chain_cannot_be_reused_before_source_disposal(
    consume_finish: bool,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    if consume_finish:
        session.emit((), "Network.loadingFinished", _error_document_finish())
    router.raise_if_failed()

    session.emit(
        (),
        "Network.requestWillBeSent",
        {
            "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "request": {"method": "GET", "url": "https://root.test/reuse"},
        },
    )
    with pytest.raises(CdpTargetIntegrityError, match="reused a request chain"):
        router.raise_if_failed()


def test_identical_field_redirect_after_block_decision_is_rejected_before_terminal() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)

    session.emit(
        (),
        "Network.requestWillBeSent",
        {
            "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "loaderId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
            "type": "Document",
            "redirectResponse": {"status": 302},
            "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
        },
    )
    with pytest.raises(CdpTargetIntegrityError, match="reused a request chain"):
        router.raise_if_failed()


def test_error_document_chain_is_independent_of_same_raw_id_on_child_source() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    iframe = session.attach(
        (),
        session_id="independent-iframe-session",
        target_id="independent-iframe-target",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())

    _complete_request(
        session,
        iframe,
        _BLOCKED_DOCUMENT_REQUEST_ID,
        "https://frame.test/independent",
    )
    session.emit((), "Network.loadingFinished", _error_document_finish())
    router.raise_if_failed()
    session.detach((), session_id=iframe[-1])
    _clean_shutdown(router)


def test_oopif_document_denial_does_not_receive_root_error_document_exception() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    iframe = session.attach(
        (),
        session_id="blocked-oopif-session",
        target_id=_BLOCKED_DOCUMENT_FRAME_ID,
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    _begin_blocked_document(session, fetch_route=iframe)
    session.emit(iframe, "Network.loadingFailed", _blocked_document_failure())
    router.raise_if_failed()

    session.emit(iframe, "Network.loadingFinished", _error_document_finish())
    with pytest.raises(CdpTargetIntegrityError, match="no active request"):
        router.raise_if_failed()


def test_document_denial_must_be_acknowledged_before_its_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    original_result = session._result

    def terminal_before_ack(
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if route == () and method == "Fetch.failRequest":
            session.emit((), "Network.loadingFailed", _blocked_document_failure())
        return original_result(route, method, params)

    monkeypatch.setattr(session, "_result", terminal_before_ack)
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)

    with pytest.raises(CdpTargetIntegrityError, match="before its denial acknowledgement"):
        router.raise_if_failed()


def test_document_denial_requires_an_exact_empty_policy_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    original_result = session._result

    def non_empty_ack(
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if route == () and method == "Fetch.failRequest":
            return {"unexpected": True}
        return original_result(route, method, params)

    monkeypatch.setattr(session, "_result", non_empty_ack)
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)

    with pytest.raises(CdpTargetIntegrityError, match="exact empty result"):
        router.raise_if_failed()
    assert router._pending_blocked_documents == {}


def test_duplicate_document_fetch_interception_is_rejected() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    _begin_blocked_document(session)
    router.raise_if_failed()

    session.emit(
        (),
        "Fetch.requestPaused",
        {
            "requestId": _BLOCKED_DOCUMENT_FETCH_ID,
            "networkId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
            "resourceType": "Document",
            "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
        },
    )
    with pytest.raises(CdpTargetIntegrityError, match="duplicated or reused"):
        router.raise_if_failed()


def test_document_fetch_with_ambiguous_raw_network_id_is_rejected() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach(
        (),
        session_id="colliding-document-session",
        target_id="colliding-document-target",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    request_event = {
        "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "loaderId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
        "type": "Document",
        "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
    }
    session.emit((), "Network.requestWillBeSent", request_event)
    session.emit(iframe, "Network.requestWillBeSent", request_event)
    session.emit(
        (),
        "Fetch.requestPaused",
        {
            "requestId": _BLOCKED_DOCUMENT_FETCH_ID,
            "networkId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
            "resourceType": "Document",
            "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
        },
    )
    with pytest.raises(CdpTargetIntegrityError, match="no unique active"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    "mismatch",
    ("loader", "resource-type", "method", "frame", "url"),
)
def test_document_fetch_partial_network_match_is_rejected(mismatch: str) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    request_event: dict[str, Any] = {
        "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "loaderId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
        "type": "Document",
        "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
    }
    fetch_event: dict[str, Any] = {
        "requestId": _BLOCKED_DOCUMENT_FETCH_ID,
        "networkId": _BLOCKED_DOCUMENT_REQUEST_ID,
        "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
        "resourceType": "Document",
        "request": {"method": "GET", "url": _BLOCKED_DOCUMENT_URL},
    }
    if mismatch == "loader":
        request_event["loaderId"] = "different-loader"
    elif mismatch == "resource-type":
        request_event["type"] = "Image"
    elif mismatch == "method":
        request_event["request"] = {"method": "POST", "url": _BLOCKED_DOCUMENT_URL}
    elif mismatch == "frame":
        fetch_event["frameId"] = "different-frame"
    elif mismatch == "url":
        fetch_event["request"] = {
            "method": "GET",
            "url": "https://forbidden.test/different",
        }

    session.emit((), "Network.requestWillBeSent", request_event)
    session.emit((), "Fetch.requestPaused", fetch_event)
    with pytest.raises(CdpTargetIntegrityError, match="does not exactly match"):
        router.raise_if_failed()


def test_oopif_redirect_after_root_block_decision_is_rejected() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    iframe = session.attach(
        (),
        session_id="redirected-block-session",
        target_id=_BLOCKED_DOCUMENT_FRAME_ID,
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    _begin_blocked_document(session)

    session.emit(
        iframe,
        "Network.requestWillBeSent",
        {
            "requestId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "loaderId": _BLOCKED_DOCUMENT_REQUEST_ID,
            "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
            "type": "Document",
            "redirectResponse": {"status": 302},
            "request": {"method": "GET", "url": "https://forbidden.test/redirect"},
        },
    )
    with pytest.raises(CdpTargetIntegrityError, match="redirected a request chain"):
        router.raise_if_failed()


def test_retired_document_chain_rejects_nonterminal_network_events() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _begin_blocked_document(session)
    session.emit((), "Network.loadingFailed", _blocked_document_failure())
    session.emit((), "Network.loadingFinished", _error_document_finish())
    router.raise_if_failed()

    session.emit(
        (),
        "Network.responseReceived",
        {"requestId": _BLOCKED_DOCUMENT_REQUEST_ID, "response": {}},
    )
    with pytest.raises(CdpTargetIntegrityError, match="retired Document chain"):
        router.raise_if_failed()


def test_exact_three_error_document_resources_are_suppressed_and_complete(
    pinned_error_resource_urls: tuple[str, str, str],
) -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    observed_before_resources = tuple(observed)

    for index, url in enumerate(pinned_error_resource_urls):
        session.emit(
            (),
            "Network.requestWillBeSent",
            _error_resource_request(url, index),
        )
        assert router.shutdown_ready is False
        session.emit(
            (),
            "Network.requestServedFromCache",
            {"requestId": f"error-resource-{index}"},
        )
        session.emit(
            (),
            "Network.responseReceived",
            _error_resource_response(url, index),
        )
        session.emit(
            (),
            "Network.loadingFinished",
            _error_resource_terminal(index),
        )
        router.raise_if_failed()

    assert tuple(observed) == observed_before_resources
    assert router.active_request_identities == ()
    assert router.shutdown_ready is True
    _clean_shutdown(router)


def test_error_resource_exception_does_not_weaken_ordinary_cache_rejection() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.emit(
        (),
        "Network.requestWillBeSent",
        {
            "requestId": "ordinary-cache",
            "request": {"method": "GET", "url": "https://root.test/cached"},
        },
    )
    session.emit((), "Network.requestServedFromCache", {"requestId": "ordinary-cache"})

    with pytest.raises(CdpTargetIntegrityError, match="disabled-cache policy"):
        router.raise_if_failed()


@pytest.mark.parametrize("owner_phase", ("absent", "before-error-finish"))
def test_error_resource_request_requires_consumed_denied_document_owner(
    pinned_error_resource_urls: tuple[str, str, str],
    owner_phase: str,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    if owner_phase == "before-error-finish":
        _begin_blocked_document(session)
        session.emit((), "Network.loadingFailed", _blocked_document_failure())

    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(pinned_error_resource_urls[0], 0),
    )
    with pytest.raises(CdpTargetIntegrityError, match="no denied Document owner"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("outer", "requestId", _REMOVE_FIELD),
        ("outer", "requestId", ""),
        ("outer", "requestId", _BLOCKED_DOCUMENT_REQUEST_ID),
        ("outer", "loaderId", _REMOVE_FIELD),
        ("outer", "loaderId", "wrong-loader"),
        ("outer", "frameId", "wrong-frame"),
        ("outer", "documentURL", "chrome-error://different/"),
        ("outer", "type", "Fetch"),
        ("outer", "redirectHasExtraInfo", True),
        ("outer", "hasUserGesture", True),
        ("outer", "timestamp", 41.26),
        ("outer", "timestamp", True),
        ("outer", "timestamp", float("nan")),
        ("outer", "wallTime", 0),
        ("outer", "wallTime", float("inf")),
        ("outer", "unexpected", True),
        ("request", "url", _REMOVE_FIELD),
        ("request", "method", "POST"),
        ("request", "headers", _REMOVE_FIELD),
        ("request", "headers", {"Referer": ""}),
        (
            "request",
            "headers",
            {
                "User-Agent": "different-agent",
                "Referer": "",
            },
        ),
        ("request", "mixedContentType", "blockable"),
        ("request", "initialPriority", "High"),
        ("request", "referrerPolicy", "no-referrer"),
        ("request", "isSameSite", True),
        ("request", "unexpected", True),
        ("initiator", "type", "script"),
        ("initiator", "url", _REMOVE_FIELD),
        ("initiator", "url", "chrome-error://different/"),
        ("initiator", "lineNumber", 1505),
        ("initiator", "columnNumber", True),
        ("initiator", "columnNumber", 999),
        ("initiator", "unexpected", True),
    ),
)
def test_error_resource_request_requires_exact_pinned_projection(
    pinned_error_resource_urls: tuple[str, str, str],
    section: str,
    field: str,
    value: object,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    event = _mutate_error_resource_event(
        _error_resource_request(pinned_error_resource_urls[0], 0),
        section,
        field,
        value,
    )

    session.emit((), "Network.requestWillBeSent", event)
    with pytest.raises(CdpTargetIntegrityError, match="Chromium error-document resource"):
        router.raise_if_failed()


@pytest.mark.parametrize("url_index", (1, 2))
def test_error_resource_rejects_reordered_known_url_hashes(
    pinned_error_resource_urls: tuple[str, str, str],
    url_index: int,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)

    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(pinned_error_resource_urls[url_index], url_index),
    )
    with pytest.raises(CdpTargetIntegrityError, match="duplicated or reordered"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    "unknown_url",
    (
        "https://root.test/not-inline.png",
        "data:image/png;base64,unknown-error-resource",
        "data:image/jpeg;base64,qcsd-error-resource-zero",
    ),
)
def test_error_resource_rejects_unpinned_url_hash_or_scheme(
    pinned_error_resource_urls: tuple[str, str, str],
    unknown_url: str,
) -> None:
    del pinned_error_resource_urls
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)

    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(unknown_url, 0),
    )
    with pytest.raises(CdpTargetIntegrityError, match="URL was not pinned"):
        router.raise_if_failed()


def test_error_resource_rejects_next_request_before_prior_terminal(
    pinned_error_resource_urls: tuple[str, str, str],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(pinned_error_resource_urls[0], 0),
    )

    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(pinned_error_resource_urls[1], 1),
    )
    with pytest.raises(CdpTargetIntegrityError, match="duplicated or reordered"):
        router.raise_if_failed()


def test_error_resource_rejects_retired_request_id_reuse(
    pinned_error_resource_urls: tuple[str, str, str],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    _emit_error_resource(session, pinned_error_resource_urls[0], 0, request_id="reused")
    router.raise_if_failed()

    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(
            pinned_error_resource_urls[1],
            1,
            request_id="reused",
        ),
    )
    with pytest.raises(CdpTargetIntegrityError, match="identity was reused"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    "bad_order",
    (
        "response-before-cache",
        "terminal-before-cache",
        "duplicate-cache",
        "terminal-before-response",
        "cache-after-response",
        "duplicate-response",
    ),
)
def test_error_resource_rejects_cache_response_terminal_reordering(
    pinned_error_resource_urls: tuple[str, str, str],
    bad_order: str,
) -> None:
    url = pinned_error_resource_urls[0]
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    session.emit((), "Network.requestWillBeSent", _error_resource_request(url, 0))
    if bad_order == "response-before-cache":
        method, event = "Network.responseReceived", _error_resource_response(url, 0)
    elif bad_order == "terminal-before-cache":
        method, event = "Network.loadingFinished", _error_resource_terminal(0)
    else:
        session.emit(
            (),
            "Network.requestServedFromCache",
            {"requestId": "error-resource-0"},
        )
        if bad_order == "duplicate-cache":
            method, event = (
                "Network.requestServedFromCache",
                {"requestId": "error-resource-0"},
            )
        elif bad_order == "terminal-before-response":
            method, event = "Network.loadingFinished", _error_resource_terminal(0)
        else:
            session.emit((), "Network.responseReceived", _error_resource_response(url, 0))
            if bad_order == "cache-after-response":
                method, event = (
                    "Network.requestServedFromCache",
                    {"requestId": "error-resource-0"},
                )
            else:
                method, event = "Network.responseReceived", _error_resource_response(url, 0)

    session.emit((), method, event)
    with pytest.raises(CdpTargetIntegrityError, match="invalid|out of order"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    "cache_event",
    (
        {},
        {"requestId": "error-resource-0", "unexpected": True},
    ),
)
def test_error_resource_cache_marker_requires_exact_field_set(
    pinned_error_resource_urls: tuple[str, str, str],
    cache_event: Mapping[str, Any],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(pinned_error_resource_urls[0], 0),
    )

    session.emit((), "Network.requestServedFromCache", cache_event)
    with pytest.raises(CdpTargetIntegrityError, match="cache|disabled-cache"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("outer", "loaderId", _REMOVE_FIELD),
        ("outer", "loaderId", "wrong-loader"),
        ("outer", "frameId", "wrong-frame"),
        ("outer", "type", "Fetch"),
        ("outer", "hasExtraInfo", True),
        ("outer", "response", _REMOVE_FIELD),
        ("outer", "timestamp", 42.0),
        ("outer", "timestamp", True),
        ("outer", "timestamp", float("nan")),
        ("outer", "unexpected", True),
        ("response", "url", _REMOVE_FIELD),
        ("response", "url", "data:image/png;base64,different"),
        ("response", "status", True),
        ("response", "status", 201),
        ("response", "statusText", ""),
        ("response", "headers", {}),
        ("response", "mimeType", "image/jpeg"),
        ("response", "charset", "utf-8"),
        ("response", "connectionReused", True),
        ("response", "connectionId", True),
        ("response", "connectionId", 1),
        ("response", "fromDiskCache", True),
        ("response", "fromServiceWorker", True),
        ("response", "fromPrefetchCache", True),
        ("response", "encodedDataLength", 1),
        ("response", "encodedDataLength", 0.0),
        ("response", "protocol", "http/1.1"),
        ("response", "securityState", "secure"),
        ("response", "isIpProtectionUsed", True),
        ("response", "unexpected", True),
    ),
)
def test_error_resource_response_requires_exact_pinned_projection(
    pinned_error_resource_urls: tuple[str, str, str],
    section: str,
    field: str,
    value: object,
) -> None:
    url = pinned_error_resource_urls[0]
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    session.emit((), "Network.requestWillBeSent", _error_resource_request(url, 0))
    session.emit(
        (),
        "Network.requestServedFromCache",
        {"requestId": "error-resource-0"},
    )
    response = _mutate_error_resource_event(
        _error_resource_response(url, 0),
        section,
        field,
        value,
    )

    session.emit((), "Network.responseReceived", response)
    with pytest.raises(CdpTargetIntegrityError, match="response signature was invalid"):
        router.raise_if_failed()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("timestamp", _REMOVE_FIELD),
        ("timestamp", 42.1),
        ("timestamp", True),
        ("timestamp", float("nan")),
        ("timestamp", float("inf")),
        ("encodedDataLength", _REMOVE_FIELD),
        ("encodedDataLength", 1),
        ("encodedDataLength", -1),
        ("encodedDataLength", True),
        ("encodedDataLength", float("nan")),
        ("unexpected", True),
    ),
)
def test_error_resource_terminal_requires_exact_later_zero_length(
    pinned_error_resource_urls: tuple[str, str, str],
    field: str,
    value: object,
) -> None:
    url = pinned_error_resource_urls[0]
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    session.emit((), "Network.requestWillBeSent", _error_resource_request(url, 0))
    session.emit(
        (),
        "Network.requestServedFromCache",
        {"requestId": "error-resource-0"},
    )
    session.emit((), "Network.responseReceived", _error_resource_response(url, 0))
    terminal = _error_resource_terminal(0)
    if value is _REMOVE_FIELD:
        terminal.pop(field)
    else:
        terminal[field] = value

    session.emit((), "Network.loadingFinished", terminal)
    with pytest.raises(CdpTargetIntegrityError, match="terminal was invalid"):
        router.raise_if_failed()


@pytest.mark.parametrize("terminal_kind", ("duplicate-terminal", "other-event", "fetch-pause"))
def test_error_resource_rejects_events_outside_exact_internal_lifecycle(
    pinned_error_resource_urls: tuple[str, str, str],
    terminal_kind: str,
) -> None:
    url = pinned_error_resource_urls[0]
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    if terminal_kind == "duplicate-terminal":
        _emit_error_resource(session, url, 0)
        method = "Network.loadingFinished"
        event = _error_resource_terminal(0, timestamp=42.3)
    else:
        session.emit((), "Network.requestWillBeSent", _error_resource_request(url, 0))
        if terminal_kind == "fetch-pause":
            method = "Fetch.requestPaused"
            event = {
                "requestId": "fetch-error-resource",
                "networkId": "error-resource-0",
                "frameId": _BLOCKED_DOCUMENT_FRAME_ID,
                "resourceType": "Image",
                "request": {"method": "GET", "url": url},
            }
        else:
            method = "Network.requestWillBeSentExtraInfo"
            event = {
                "requestId": "error-resource-0",
                "headers": {},
            }

    session.emit((), method, event)
    with pytest.raises(
        CdpTargetIntegrityError,
        match="inline resource|unexpected|identity was reused",
    ):
        router.raise_if_failed()


def test_error_resource_rejects_cross_source_loader_and_request_identity(
    pinned_error_resource_urls: tuple[str, str, str],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    iframe = session.attach(
        (),
        session_id="error-resource-iframe-session",
        target_id="error-resource-iframe",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    _arm_error_document_resources(session)

    session.emit(
        iframe,
        "Network.requestWillBeSent",
        _error_resource_request(pinned_error_resource_urls[0], 0),
    )
    with pytest.raises(CdpTargetIntegrityError, match="loader crossed target sources"):
        router.raise_if_failed()


def test_error_resource_rejects_cross_source_continuation_identity(
    pinned_error_resource_urls: tuple[str, str, str],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    iframe = session.attach(
        (),
        session_id="error-resource-continuation-session",
        target_id="error-resource-continuation-frame",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    _arm_error_document_resources(session)
    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(pinned_error_resource_urls[0], 0),
    )

    session.emit(
        iframe,
        "Network.requestServedFromCache",
        {"requestId": "error-resource-0"},
    )
    with pytest.raises(CdpTargetIntegrityError, match="crossed target sources"):
        router.raise_if_failed()


def test_started_error_resource_blocks_normal_shutdown_but_abort_cleans_it(
    pinned_error_resource_urls: tuple[str, str, str],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    session.emit(
        (),
        "Network.requestWillBeSent",
        _error_resource_request(pinned_error_resource_urls[0], 0),
    )
    router.raise_if_failed()

    assert router.shutdown_ready is False
    with pytest.raises(CdpTargetIntegrityError, match="pending"):
        router.begin_shutdown()
    _browser_session, guard = _guard_for(router)
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()


def test_zero_started_error_resource_owner_is_optional_at_context_disposal() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    router.raise_if_failed()

    assert router.shutdown_ready is True
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


def test_shutdown_resume_ack_requires_an_exact_empty_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeNonFlatSession()
    original_result = session._result

    def nonempty_shutdown_resume_result(
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = original_result(route, method, params)
        if method == "Runtime.runIfWaitingForDebugger":
            return {"unexpected": True}
        return result

    monkeypatch.setattr(session, "_result", nonempty_shutdown_resume_result)
    router, _observed = _router(session)
    _begin_shutdown(router)
    session.attach(
        (),
        session_id="late-nonempty-session",
        target_id="late-nonempty-target",
        target_type="worker",
        parent_frame_id="root-frame",
        target_url="https://worker.test/late-nonempty.js",
    )

    with pytest.raises(CdpTargetIntegrityError, match="shutdown resume acknowledgement"):
        router.raise_if_failed()


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
        if command[1] == "Target.attachToTarget" and command[2].get("targetId") == "root-tab"
    ]
    assert not [
        command for command in browser_session.commands if command[0] == "Target.closeTarget"
    ]
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
        if command[1] == "Target.attachToTarget" and command[2].get("targetId") == "popup-tab"
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
    assert (
        sum(command == "Target.getTargets" for command, _parameters in browser_session.commands)
        == 4
    )
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
        "Debugger.setInstrumentationBreakpoint",
        "Target.setAutoAttach",
        "Target.getTargetInfo",
        "Runtime.runIfWaitingForDebugger",
        "Debugger.evaluateOnCallFrame",
        "Debugger.removeBreakpoint",
        "Debugger.resume",
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
    assert shared_summary["released"] == 0
    assert shared_summary["pending"] == 1
    assert shared_summary["released_after_setup_envelopes"] == 0
    assert router.shutdown_ready is False
    assert not any(
        route == child_route and method == "Runtime.runIfWaitingForDebugger"
        for route, method, _params in page_session.commands
    )

    page_session.release_held("Fetch.continueRequest")
    shared_summary = router.bootstrap_prearm_summary["by_worker_type"]["shared_worker"]
    assert shared_summary["released"] == 1
    assert shared_summary["pending"] == 0
    assert shared_summary["released_after_setup_envelopes"] == 1
    assert not any(
        route == child_route and method == "Runtime.runIfWaitingForDebugger"
        for route, method, _params in page_session.commands
    )
    page_session.release_held("Network.enable")
    assert any(
        route == child_route and method == "Runtime.runIfWaitingForDebugger"
        for route, method, _params in page_session.commands
    )
    page_session.emit(child_route, "Network.loadingFinished", {"requestId": target_id})
    page_session.detach((), session_id=child_route[0])
    browser_session.detach(guardian_session_id="oopif-shared-guardian", target_id=target_id)
    page_session.detach((), session_id=iframe[-1])
    _clean_shutdown(router)


def test_oopif_shared_bootstrap_nonempty_continue_ack_never_releases_or_resumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page_session = _FakeNonFlatSession()
    router, _observed = _router(page_session)
    iframe = page_session.attach(
        (),
        session_id="nonempty-continue-owner-session",
        target_id="nonempty-continue-owner-target",
        target_type="iframe",
    )
    original_result = page_session._result

    def nonempty_continue_ack(
        route: tuple[str, ...],
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if route == iframe and method == "Fetch.continueRequest":
            return {"unexpected": True}
        return original_result(route, method, params)

    monkeypatch.setattr(page_session, "_result", nonempty_continue_ack)
    browser_session, _guard = _start_shared_worker_guard(page_session, router)
    target_id = "nonempty-continue-shared-target"
    target_url = "https://worker.test/nonempty-continue.js"
    child_route = ("nonempty-continue-shared-session",)
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
        frame_id="nonempty-continue-owner-target",
    )
    page_session.before_adoption_attachment = lambda: _pause_script_bootstrap(
        page_session,
        iframe,
        target_id=target_id,
        target_url=target_url,
        frame_id="nonempty-continue-owner-target",
    )

    browser_session.attach(
        guardian_session_id="nonempty-continue-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )

    shared_summary = router.bootstrap_prearm_summary["by_worker_type"]["shared_worker"]
    assert shared_summary["held"] == 1
    assert shared_summary["released"] == 0
    assert shared_summary["pending"] == 1
    assert shared_summary["released_after_setup_envelopes"] == 0
    assert not any(
        route == child_route and method == "Runtime.runIfWaitingForDebugger"
        for route, method, _params in page_session.commands
    )
    assert sum(
        route == iframe and method == "Fetch.continueRequest"
        for route, method, _params in page_session.commands
    ) == 1
    with pytest.raises(CdpTargetIntegrityError, match="exact empty result"):
        router.raise_if_failed()


def test_abort_detach_keeps_inflight_shared_bootstrap_continue_until_disposal() -> None:
    page_session = _FakeNonFlatSession(hold_methods={"Fetch.continueRequest"})
    router, _observed = _router(page_session)
    iframe = page_session.attach(
        (),
        session_id="inflight-continue-owner-session",
        target_id="inflight-continue-owner-target",
        target_type="iframe",
    )
    browser_session, guard = _start_shared_worker_guard(page_session, router)
    target_id = "inflight-continue-shared-target"
    target_url = "https://worker.test/inflight-continue.js"
    child_route = ("inflight-continue-shared-session",)
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
        frame_id="inflight-continue-owner-target",
    )
    page_session.before_adoption_attachment = lambda: _pause_script_bootstrap(
        page_session,
        iframe,
        target_id=target_id,
        target_url=target_url,
        frame_id="inflight-continue-owner-target",
    )
    browser_session.attach(
        guardian_session_id="inflight-continue-shared-guardian",
        target_id=target_id,
        target_url=target_url,
    )

    assert router.bootstrap_prearm_summary["pending_total"] == 1
    assert sum(command.policy_decision for command in router._pending.values()) == 1
    router.begin_abort()
    guard.begin_abort()
    page_session.detach((), session_id=iframe[-1])
    assert sum(command.policy_decision for command in router._pending.values()) == 1
    guard.finish_abort()
    assert sum(command.policy_decision for command in router._pending.values()) == 1

    router.finish_abort()
    assert router._pending == {}


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


def _shared_worker_ready_for_guardian_shutdown() -> tuple[
    RecursiveCdpTargetRouter,
    _FakeBrowserSession,
    BrowserSharedWorkerGuard,
    str,
]:
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
    return router, browser_session, guard, target_id


def test_live_browser_guard_session_blocks_finish() -> None:
    _router_value, _browser_session, guard, _target_id = (
        _shared_worker_ready_for_guardian_shutdown()
    )
    with pytest.raises(CdpTargetIntegrityError, match="guard|session|pending|unresolved"):
        guard.finish()


def test_guardian_shutdown_barrier_requires_real_detach_and_orders_cleanup() -> None:
    router, browser_session, guard, target_id = _shared_worker_ready_for_guardian_shutdown()

    def detach_on_barrier() -> None:
        browser_session.before_get_targets = None
        browser_session.detach(
            guardian_session_id="shared-guardian-session",
            target_id=target_id,
        )

    browser_session.before_get_targets = detach_on_barrier
    guard.finish()
    router.finish()

    assert [method for method, _params in browser_session.commands][-3:] == [
        "Target.getTargets",
        "Target.setAutoAttach",
        "Target.setDiscoverTargets",
    ]
    assert browser_session.detached is True


def test_guardian_shutdown_needs_no_barrier_after_prior_exact_detach() -> None:
    router, browser_session, guard, target_id = _shared_worker_ready_for_guardian_shutdown()
    browser_session.detach(
        guardian_session_id="shared-guardian-session",
        target_id=target_id,
    )
    initial_barriers = sum(
        method == "Target.getTargets" for method, _params in browser_session.commands
    )

    guard.finish()
    router.finish()

    assert (
        sum(method == "Target.getTargets" for method, _params in browser_session.commands)
        == initial_barriers
    )


def test_guardian_shutdown_barrier_retries_until_real_detach() -> None:
    router, browser_session, guard, target_id = _shared_worker_ready_for_guardian_shutdown()
    barrier_count = 0

    def detach_on_second_barrier() -> None:
        nonlocal barrier_count
        barrier_count += 1
        if barrier_count == 2:
            browser_session.before_get_targets = None
            browser_session.detach(
                guardian_session_id="shared-guardian-session",
                target_id=target_id,
            )

    browser_session.before_get_targets = detach_on_second_barrier
    guard.finish()
    router.finish()

    assert barrier_count == 2


@pytest.mark.parametrize(
    "result",
    [
        {},
        {"targetInfos": {}},
        {"targetInfos": [{}]},
        {
            "targetInfos": [
                {"targetId": "duplicate"},
                {"targetId": "duplicate"},
            ]
        },
    ],
)
def test_guardian_shutdown_barrier_rejects_malformed_target_inventory(
    result: dict[str, Any],
) -> None:
    _router_value, browser_session, guard, _target_id = _shared_worker_ready_for_guardian_shutdown()
    browser_session.get_targets_result = result

    with pytest.raises(CdpTargetIntegrityError, match="malformed"):
        guard.finish()


def test_guardian_shutdown_barrier_does_not_synthesise_missing_detach() -> None:
    _router_value, browser_session, guard, _target_id = _shared_worker_ready_for_guardian_shutdown()
    initial_barriers = sum(
        method == "Target.getTargets" for method, _params in browser_session.commands
    )

    with pytest.raises(CdpTargetIntegrityError, match="exact lifecycle"):
        guard.finish()

    assert (
        sum(method == "Target.getTargets" for method, _params in browser_session.commands)
        == initial_barriers + 3
    )
    assert browser_session.detached is False


def test_guardian_shutdown_requires_detached_target_to_be_absent() -> None:
    _router_value, browser_session, guard, target_id = _shared_worker_ready_for_guardian_shutdown()
    browser_session.target_infos.append(
        {
            "targetId": target_id,
            "type": "shared_worker",
            "url": "https://worker.test/shared.js",
            "browserContextId": "root-context",
            "attached": True,
        }
    )

    def detach_on_barrier() -> None:
        browser_session.before_get_targets = None
        browser_session.detach(
            guardian_session_id="shared-guardian-session",
            target_id=target_id,
        )

    browser_session.before_get_targets = detach_on_barrier
    with pytest.raises(CdpTargetIntegrityError, match="exact lifecycle"):
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


def _abort_fetch_pause(**changes: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "requestId": "abort-paused-favicon",
        "networkId": "abort-favicon-network",
        "frameId": "root-frame",
        "resourceType": "Other",
        "request": {"method": "GET", "url": "https://root.test/favicon.ico"},
    }
    event.update(changes)
    return event


@pytest.mark.parametrize("child", [False, True])
@pytest.mark.parametrize("resource_type", ["Other", "Document", "Script"])
@pytest.mark.parametrize("network_seen", [False, True])
def test_abort_fetch_stays_paused_without_callback_registration_or_io(
    monkeypatch: pytest.MonkeyPatch,
    child: bool,
    resource_type: str,
    network_seen: bool,
) -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    route = ()
    if child:
        route = session.attach(
            (),
            session_id="abort-fetch-child",
            target_id="abort-fetch-frame",
            target_type="iframe",
            parent_frame_id="root-frame",
        )
    event = _abort_fetch_pause(resourceType=resource_type)
    if network_seen:
        session.emit(
            route,
            "Network.requestWillBeSent",
            {
                "requestId": event["networkId"],
                "loaderId": event["networkId"],
                "frameId": event["frameId"],
                "type": resource_type,
                "request": event["request"],
            },
        )
    active_before = router.active_request_identities
    observed_before = list(observed)

    def forbidden_registration(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("exceptional disposal must not create a new Fetch decision")

    monkeypatch.setattr(router, "_register_document_fetch", forbidden_registration)
    monkeypatch.setattr(router, "_register_bootstrap_fetch", forbidden_registration)
    _browser_session, guard = _guard_for(router)
    router.begin_abort()
    guard.begin_abort()
    commands_before = list(session.commands)
    session.emit(route, "Fetch.requestPaused", event)
    router.raise_if_failed()

    assert session.commands == commands_before
    assert observed == observed_before
    assert router.active_request_identities == active_before
    assert router._document_fetch_by_policy_identity == {}
    assert router._pending_blocked_documents == {}
    guard.finish_abort()
    router.finish_abort()
    assert router.active_request_identities == ()
    assert observed == observed_before


@pytest.mark.parametrize("normal_shutdown", [False, True])
def test_abort_fetch_hold_does_not_change_normal_policy(normal_shutdown: bool) -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    if normal_shutdown:
        _begin_shutdown(router)
    event = _abort_fetch_pause()
    session.emit((), "Fetch.requestPaused", event)
    router.raise_if_failed()
    assert ((), "Fetch.continueRequest", {"requestId": event["requestId"]}) in session.commands
    assert observed[-1] == (router.root_source, "Fetch.requestPaused", event)
    if normal_shutdown:
        _finish(router)
    else:
        _clean_shutdown(router)


@pytest.mark.parametrize(
    "event",
    [
        pytest.param(_without(_abort_fetch_pause(), "requestId"), id="missing-id"),
        pytest.param(_abort_fetch_pause(requestId=""), id="empty-id"),
        pytest.param(_abort_fetch_pause(requestId=7), id="numeric-id"),
        pytest.param(_abort_fetch_pause(request=None), id="null-request"),
        pytest.param(_abort_fetch_pause(request=[]), id="array-request"),
        pytest.param(_abort_fetch_pause(request={"method": "GET"}), id="missing-url"),
        pytest.param(_abort_fetch_pause(request={"method": "GET", "url": 7}), id="numeric-url"),
        pytest.param(
            _abort_fetch_pause(request={"method": "", "url": "https://root.test/"}),
            id="empty-method",
        ),
        pytest.param(_abort_fetch_pause(networkId=1), id="numeric-network-id"),
        pytest.param(_abort_fetch_pause(networkId=""), id="empty-network-id"),
        pytest.param(_abort_fetch_pause(responseStatusCode=200), id="response-status"),
        pytest.param(_abort_fetch_pause(responseStatusText="OK"), id="response-status-text"),
        pytest.param(_abort_fetch_pause(responseHeaders=[]), id="response-headers"),
        pytest.param(_abort_fetch_pause(responseErrorReason="Failed"), id="response-error"),
    ],
)
def test_abort_fetch_hold_rejects_malformed_or_response_stage_pauses(
    event: Mapping[str, Any],
) -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    router.begin_abort()
    commands_before = list(session.commands)
    observed_before = list(observed)
    session.emit((), "Fetch.requestPaused", event)
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()
    assert session.commands == commands_before
    assert observed == observed_before


@pytest.mark.parametrize(
    "change", [{"generation": 1}, {"target_id": "other"}, {"target_type": "iframe"}]
)
def test_abort_fetch_hold_rejects_changed_source(change: dict[str, Any]) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    router.begin_abort()
    commands_before = list(session.commands)
    with pytest.raises(CdpTargetIntegrityError):
        router._handle_forwarded(
            replace(router.root_source, **change), "Fetch.requestPaused", _abort_fetch_pause()
        )
    assert session.commands == commands_before


def test_abort_fetch_hold_rejects_post_disposal_pauses() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    _browser_session, guard = _guard_for(router)
    router.begin_abort()
    guard.begin_abort()
    guard.finish_abort()
    router.finish_abort()
    commands_before = list(session.commands)
    session.emit((), "Fetch.requestPaused", _abort_fetch_pause())
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()
    assert session.commands == commands_before


def test_abort_fetch_hold_accepts_missing_optional_network_id() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    router.begin_abort()
    commands_before = list(session.commands)
    observed_before = list(observed)
    session.emit((), "Fetch.requestPaused", _without(_abort_fetch_pause(), "networkId"))
    router.raise_if_failed()
    assert session.commands == commands_before
    assert observed == observed_before


def test_abort_fetch_hold_rejects_detached_source() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    route = session.attach(
        (), session_id="aborted-detached", target_id="aborted-frame", target_type="iframe"
    )
    source = router._state(route).source
    session.detach((), session_id=route[-1])
    router.begin_abort()
    commands_before = list(session.commands)
    observed_before = list(observed)
    with pytest.raises(CdpTargetIntegrityError):
        router._handle_forwarded(source, "Fetch.requestPaused", _abort_fetch_pause())
    assert session.commands == commands_before
    assert observed == observed_before


@pytest.mark.parametrize("method", ["Fetch.continueRequest", "Fetch.failRequest"])
def test_abort_rejects_direct_fetch_policy_send_without_io(method: str) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    router.begin_abort()
    commands_before = list(session.commands)
    params = {"requestId": "abort-paused-favicon"}
    if method == "Fetch.failRequest":
        params["errorReason"] = "BlockedByClient"
    with pytest.raises(CdpTargetIntegrityError):
        router.send(router.root_source, method, params, label="test-abort-policy")
    assert session.commands == commands_before


def test_abort_fetch_hold_keeps_error_resource_integrity_check_first(
    pinned_error_resource_urls: tuple[str, str, str],
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session, fetch_policy=_deny_blocked_by_client)
    _arm_error_document_resources(session)
    session.emit(
        (), "Network.requestWillBeSent", _error_resource_request(pinned_error_resource_urls[0], 0)
    )
    router.begin_abort()
    commands_before = list(session.commands)
    session.emit(
        (),
        "Fetch.requestPaused",
        _abort_fetch_pause(
            networkId="error-resource-0",
            resourceType="Image",
            request={"method": "GET", "url": pinned_error_resource_urls[0]},
        ),
    )
    with pytest.raises(CdpTargetIntegrityError, match="inline resource entered Fetch"):
        router.raise_if_failed()
    assert session.commands == commands_before


def _data_cache_request(**changes: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "requestId": "inline-data-image",
        "type": "Image",
        "request": {"method": "GET", "url": "data:image/png;base64,AA=="},
    }
    event.update(changes)
    return event


@pytest.mark.parametrize("child", [False, True])
def test_inline_data_cache_marker_preserves_full_forwarded_lifecycle(child: bool) -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    route = ()
    if child:
        route = session.attach(
            (), session_id="data-cache-child", target_id="data-cache-frame", target_type="iframe"
        )
    event = _data_cache_request()
    request_id = event["requestId"]
    observed_before = len(observed)
    lifecycle = [
        ("Network.requestWillBeSent", event),
        ("Network.requestServedFromCache", {"requestId": request_id}),
        (
            "Network.responseReceived",
            {"requestId": request_id, "response": {"url": event["request"]["url"]}},
        ),
        ("Network.loadingFinished", {"requestId": request_id}),
    ]
    for method, payload in lifecycle:
        session.emit(route, method, payload)
    router.raise_if_failed()
    assert [(method, payload) for _, method, payload in observed[observed_before:]] == lifecycle
    assert all(source.session_path == route for source, _, _ in observed[observed_before:])
    assert router.active_request_identities == ()
    if child:
        session.detach((), session_id=route[-1])
    _clean_shutdown(router)


@pytest.mark.parametrize(
    "url",
    [
        "https://root.test/a",
        "http://root.test/a",
        "blob:https://root.test/id",
        "file:///tmp/a",
        "DATA:image/png;base64,AA==",
        " data:image/png;base64,AA==",
    ],
)
def test_inline_data_cache_exception_rejects_other_url_forms(url: str) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.emit(
        (), "Network.requestWillBeSent", _data_cache_request(request={"method": "GET", "url": url})
    )
    session.emit((), "Network.requestServedFromCache", {"requestId": "inline-data-image"})
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()


@pytest.mark.parametrize("method", ["POST", "HEAD", "get", ""])
def test_inline_data_cache_requires_exact_get(method: str) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.emit(
        (),
        "Network.requestWillBeSent",
        _data_cache_request(request={"method": method, "url": "data:text/plain,x"}),
    )
    session.emit((), "Network.requestServedFromCache", {"requestId": "inline-data-image"})
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()


@pytest.mark.parametrize(
    "marker",
    [{}, {"requestId": ""}, {"requestId": 1}, {"requestId": "inline-data-image", "extra": True}],
)
def test_inline_data_cache_requires_exact_marker_fields(marker: Mapping[str, Any]) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.emit((), "Network.requestWillBeSent", _data_cache_request())
    session.emit((), "Network.requestServedFromCache", marker)
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()


@pytest.mark.parametrize("state", ["unknown", "retired", "duplicate"])
def test_inline_data_cache_rejects_unknown_retired_and_duplicate_markers(state: str) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    if state != "unknown":
        session.emit((), "Network.requestWillBeSent", _data_cache_request())
        if state == "retired":
            session.emit((), "Network.loadingFinished", {"requestId": "inline-data-image"})
        else:
            session.emit((), "Network.requestServedFromCache", {"requestId": "inline-data-image"})
        router.raise_if_failed()
    session.emit((), "Network.requestServedFromCache", {"requestId": "inline-data-image"})
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()


def test_inline_data_cache_requires_same_source_not_oopif_migration() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="cache-migration", target_id="cache-frame", target_type="iframe"
    )
    session.emit(
        (),
        "Network.requestWillBeSent",
        _data_cache_request(type="Document", loaderId="inline-data-image", frameId="cache-frame"),
    )
    session.emit(iframe, "Network.requestServedFromCache", {"requestId": "inline-data-image"})
    with pytest.raises(CdpTargetIntegrityError):
        router.raise_if_failed()


def test_inline_data_cache_duplicate_tracking_is_per_active_occurrence() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    for terminal in ("Network.loadingFailed", "Network.loadingFinished"):
        session.emit((), "Network.requestWillBeSent", _data_cache_request())
        session.emit((), "Network.requestServedFromCache", {"requestId": "inline-data-image"})
        session.emit((), terminal, {"requestId": "inline-data-image"})
        router.raise_if_failed()
    assert (
        len([method for _, method, _ in observed if method == "Network.requestServedFromCache"])
        == 2
    )
    _clean_shutdown(router)
