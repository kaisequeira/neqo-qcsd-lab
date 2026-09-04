"""Race-free recursive CDP instrumentation for page-related network targets.

Playwright 1.52 does not expose child CDP sessions (notably dedicated workers)
to Python, nor can its public ``CDPSession.send`` attach a top-level flattened
``sessionId``.  This adapter therefore uses Chromium's public non-flat target
transport recursively.  Every child starts paused, acknowledges the complete
Network/Fetch/recursion setup, and only then resumes.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

CDP_TARGET_INSTRUMENTATION_POLICY = (
    "playwright-1.52-public-cdp-recursive-non-flat-paused-debugger-targets-v3"
)
_ALLOWED_CHILD_TARGET_TYPES = frozenset({"iframe", "shared_worker", "worker"})
_FORWARDED_METHODS = frozenset(
    {
        "Fetch.requestPaused",
        "Network.loadingFailed",
        "Network.loadingFinished",
        "Network.requestWillBeSent",
        "Network.requestWillBeSentExtraInfo",
        "Network.requestServedFromCache",
        "Network.responseReceived",
    }
)
_TARGET_LIFECYCLE_METHODS = frozenset(
    {
        "Inspector.targetCrashed",
        "Target.targetCrashed",
        "Target.targetCreated",
        "Target.targetDestroyed",
        "Target.targetInfoChanged",
    }
)
_EMPTY_RESULT_POLICY_COMMANDS = frozenset(
    {"Fetch.continueRequest", "Fetch.failRequest"}
)
_BASE_SETUP_COMMANDS = (
    # Network.Initiator.stack is populated for script-created requests only
    # when the Debugger domain was enabled before the relevant script ran.
    ("Debugger.enable", {}),
    ("Network.enable", {}),
    ("Network.setCacheDisabled", {"cacheDisabled": True}),
    ("Network.setBypassServiceWorker", {"bypass": True}),
)
_FETCH_SETUP_COMMAND = (
    "Fetch.enable",
    {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
)
_AUTO_ATTACH_COMMAND = (
    "Target.setAutoAttach",
    {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": False},
)
_TARGET_BARRIER_COMMAND = ("Target.getTargetInfo", {})


class CdpTargetIntegrityError(RuntimeError):
    """A malformed, incomplete, or uninstrumented related-target event stream."""


class _CdpSession(Protocol):
    def on(self, event: str, handler: Callable[[dict[str, Any]], None]) -> None: ...

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CdpTargetSource:
    """Globally collision-safe identity for one target session."""

    session_path: tuple[str, ...]
    target_id: str
    target_type: str = "page"
    generation: int = 0
    parent_session_path: tuple[str, ...] | None = None
    parent_frame_id: str | None = None

    @property
    def session_id(self) -> str:
        return self.session_path[-1] if self.session_path else "root"

    def request_chain_key(
        self, request_id: str
    ) -> tuple[tuple[str, ...], str, int, str]:
        if not isinstance(request_id, str) or not request_id:
            raise CdpTargetIntegrityError("CDP request identity is empty or malformed")
        return (self.session_path, self.target_id, self.generation, request_id)


@dataclass
class _TargetState:
    source: CdpTargetSource
    target_type: str
    phase: str
    setup_pending: set[str] = field(default_factory=set)
    active_request_ids: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class _ActiveRequest:
    source: CdpTargetSource
    request_id: str
    loader_id: str | None
    frame_id: str | None
    resource_type: str | None


@dataclass
class _PendingCommand:
    label: str
    on_success: Callable[[Mapping[str, Any]], None] | None = None
    policy_decision: bool = False


class RecursiveCdpTargetRouter:
    """Instrument a root page plus every recursively related iframe/worker target."""

    def __init__(
        self,
        session: _CdpSession,
        *,
        on_event: Callable[[CdpTargetSource, str, Mapping[str, Any]], None],
        on_target_activity: Callable[[CdpTargetSource, str], None] | None = None,
    ) -> None:
        self._session = session
        self._on_event = on_event
        self._on_target_activity = on_target_activity
        self._root_source: CdpTargetSource | None = None
        self._states: dict[tuple[str, ...], _TargetState] = {}
        self._target_routes: dict[str, tuple[str, ...]] = {}
        self._session_routes: dict[str, tuple[str, ...]] = {}
        self._pending: dict[tuple[tuple[str, ...], int], _PendingCommand] = {}
        self._next_command_id = 1
        self._failure: CdpTargetIntegrityError | None = None
        self._shutting_down = False
        self._target_generations: dict[str, int] = {}
        self._active_requests: dict[str, list[_ActiveRequest]] = {}

    @property
    def active_request_identities(self) -> tuple[tuple[CdpTargetSource, str], ...]:
        """Return every request live at the current observation boundary."""

        return tuple(
            sorted(
                (
                    (request.source, request.request_id)
                    for values in self._active_requests.values()
                    for request in values
                ),
                key=lambda item: (
                    item[0].session_path,
                    item[0].target_id,
                    item[0].generation,
                    item[1],
                ),
            )
        )

    @property
    def root_source(self) -> CdpTargetSource:
        if self._root_source is None:
            raise CdpTargetIntegrityError("CDP target instrumentation has not started")
        return self._root_source

    def start(self) -> CdpTargetSource:
        """Install root handlers and finish root setup before page navigation."""

        if self._root_source is not None:
            raise CdpTargetIntegrityError("CDP target instrumentation started more than once")
        for method in _FORWARDED_METHODS:
            self._session.on(
                method,
                self._guard(
                    lambda event, forwarded=method: self._handle_root_event(forwarded, event)
                ),
            )
        for method in _TARGET_LIFECYCLE_METHODS:
            self._session.on(
                method,
                self._guard(
                    lambda event, lifecycle=method: self._target_lifecycle_event(
                        lifecycle, event
                    )
                ),
            )
        self._session.on(
            "Target.attachedToTarget",
            self._guard(lambda event: self._attached((), event)),
        )
        self._session.on(
            "Target.detachedFromTarget",
            self._guard(lambda event: self._detached((), event)),
        )
        self._session.on(
            "Target.receivedMessageFromTarget",
            self._guard(lambda event: self._received((), event)),
        )

        target_info = self._root_send("Target.getTargetInfo", {}).get("targetInfo")
        if not isinstance(target_info, Mapping):
            raise CdpTargetIntegrityError("root CDP target identity response is malformed")
        target_id = target_info.get("targetId")
        target_type = target_info.get("type")
        if not isinstance(target_id, str) or not target_id or target_type != "page":
            raise CdpTargetIntegrityError("root CDP target is not an identified page")
        source = CdpTargetSource((), target_id, "page", 0, None, None)
        self._root_source = source
        self._states[()] = _TargetState(source, "page", "ready")
        self._target_routes[target_id] = ()

        for method, params in (*_BASE_SETUP_COMMANDS, _FETCH_SETUP_COMMAND, _AUTO_ATTACH_COMMAND):
            self._root_send(method, dict(params))
        # Chromium's auto-attach command has historically returned before all
        # existing related targets were reported. A following target query is
        # the explicit protocol barrier used by Playwright itself.
        barrier = self._root_send(*_TARGET_BARRIER_COMMAND)
        barrier_info = barrier.get("targetInfo")
        if (
            not isinstance(barrier_info, Mapping)
            or barrier_info.get("targetId") != target_id
            or barrier_info.get("type") != "page"
        ):
            raise CdpTargetIntegrityError("root CDP auto-attach barrier changed target identity")
        self.raise_if_failed()
        return source

    def send(
        self,
        source: CdpTargetSource,
        method: str,
        params: Mapping[str, Any],
        *,
        label: str,
    ) -> None:
        """Send an empty-result policy decision to its exact target session.

        Result-bearing commands (for example ``Network.getResponseBody``) are
        deliberately rejected because this transport validates their eventual
        response asynchronously. Browser bodies are not discovery evidence;
        the separately executed Neqo probe retrieves and hash-binds every body.
        """

        self.raise_if_failed()
        if method not in _EMPTY_RESULT_POLICY_COMMANDS:
            raise CdpTargetIntegrityError(
                f"result-bearing or unsupported routed CDP command was rejected: {method}"
            )
        state = self._state(source.session_path)
        if state.source != source or state.phase not in {"ready", "resuming"}:
            raise CdpTargetIntegrityError(
                f"cannot send {label} to an unready or detached CDP target"
            )
        if not source.session_path:
            self._root_send(method, dict(params))
            return
        self._queue_command(
            source,
            method,
            dict(params),
            label=label,
            policy_decision=True,
        )

    def begin_shutdown(self) -> None:
        """Freeze target creation after all setup/policy commands are acknowledged.

        The caller then closes the complete browser context, which deliberately
        terminates otherwise long-lived iframes/workers and lets their terminal
        network and detach events drain before :meth:`finish` validates them.
        """

        self.raise_if_failed()
        if self._shutting_down:
            raise CdpTargetIntegrityError("CDP target shutdown started more than once")
        if any(command.policy_decision for command in self._pending.values()) or any(
            state.phase not in {"ready", "detached", "destroyed"}
            for state in self._states.values()
        ):
            raise CdpTargetIntegrityError(
                "CDP target shutdown began with setup or policy commands pending"
            )
        self._shutting_down = True

    def raise_if_failed(self) -> None:
        if self._failure is not None:
            raise self._failure

    def finish(self) -> None:
        """Prove no child escaped setup and no target/protocol work remains pending."""

        self.raise_if_failed()
        if not self._shutting_down:
            raise CdpTargetIntegrityError(
                "CDP target instrumentation finished without a deliberate context shutdown"
            )
        if self._pending:
            labels = ", ".join(sorted(command.label for command in self._pending.values()))
            raise CdpTargetIntegrityError(
                f"CDP shutdown commands remain unresolved: {labels}"
            )
        # BrowserContext.close() is the disposal barrier. Chromium is not
        # required to deliver every descendant detach or loadingFailed event
        # before the root CDP session closes, so close any observation that was
        # live at the explicit evidence cutoff as a local shutdown cancellation.
        for state in self._states.values():
            for request_id in tuple(state.active_request_ids):
                self._terminalise_request(
                    state.source,
                    request_id,
                    synthetic_shutdown=True,
                )
        for route, state in self._states.items():
            if state.active_request_ids:
                raise CdpTargetIntegrityError("CDP target finished with active requests")
            if route and state.phase not in {"destroyed", "detached", "ready", "closing"}:
                raise CdpTargetIntegrityError("related CDP target did not reach a terminal state")
            if not route and state.phase != "ready":
                raise CdpTargetIntegrityError("root CDP target did not remain instrumented")

    def _guard(
        self, handler: Callable[[dict[str, Any]], None]
    ) -> Callable[[dict[str, Any]], None]:
        def dispatch(event: dict[str, Any]) -> None:
            if self._failure is not None:
                return
            try:
                handler(event)
            except Exception as error:  # noqa: BLE001 - retained for fail-closed finish
                self._record_failure(error)

        return dispatch

    def _record_failure(self, error: Exception) -> None:
        if self._failure is not None:
            return
        if isinstance(error, CdpTargetIntegrityError):
            self._failure = error
        else:
            self._failure = CdpTargetIntegrityError(
                f"CDP target instrumentation failed: {type(error).__name__}"
            )

    def _root_send(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        try:
            result = self._session.send(method, dict(params))
        except Exception as error:
            raise CdpTargetIntegrityError(
                f"root CDP command {method} failed: {type(error).__name__}"
            ) from error
        if not isinstance(result, dict):
            raise CdpTargetIntegrityError(f"root CDP command {method} returned malformed data")
        return result

    def _state(self, route: tuple[str, ...]) -> _TargetState:
        state = self._states.get(route)
        if state is None:
            raise CdpTargetIntegrityError("CDP event named an unknown child-session route")
        return state

    def _handle_root_event(self, method: str, event: Mapping[str, Any]) -> None:
        self._handle_forwarded(self.root_source, method, event)

    def _target_lifecycle_event(
        self, method: str, event: Mapping[str, Any]
    ) -> None:
        if method in {"Inspector.targetCrashed", "Target.targetCrashed"}:
            raise CdpTargetIntegrityError(f"CDP target crashed: {method}")
        if method == "Target.targetCreated":
            raise CdpTargetIntegrityError(
                "CDP reported a discovered target outside recursive auto-attach"
            )
        if method == "Target.targetInfoChanged":
            info = event.get("targetInfo")
            if not isinstance(info, Mapping):
                raise CdpTargetIntegrityError("CDP target-info update is malformed")
            target_id = info.get("targetId")
            route = self._target_routes.get(target_id) if isinstance(target_id, str) else None
            state = self._states.get(route) if route is not None else None
            if (
                state is None
                or info.get("type") != state.target_type
                or state.phase == "destroyed"
            ):
                raise CdpTargetIntegrityError(
                    "CDP target-info update named an unknown or changed target"
                )
            self._notify_target_activity(state.source, "target-info-changed")
            return
        if method == "Target.targetDestroyed":
            target_id = event.get("targetId")
            route = self._target_routes.get(target_id) if isinstance(target_id, str) else None
            state = self._states.get(route) if route is not None else None
            if state is None and isinstance(target_id, str):
                historical = [
                    candidate
                    for candidate in self._states.values()
                    if candidate.source.target_id == target_id
                    and candidate.phase == "detached"
                ]
                state = max(historical, key=lambda item: item.source.generation, default=None)
            if state is None or state.phase != "detached":
                raise CdpTargetIntegrityError(
                    "CDP destroyed an unknown or not-cleanly-detached target"
                )
            state.phase = "destroyed"
            self._notify_target_activity(state.source, "target-destroyed")
            return
        raise CdpTargetIntegrityError(f"unsupported CDP target lifecycle event: {method}")

    def _handle_forwarded(
        self,
        source: CdpTargetSource,
        method: str,
        event: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if state.phase not in {"ready", "resuming"}:
            raise CdpTargetIntegrityError(
                f"CDP target emitted {method} before instrumentation was acknowledged"
            )
        if method == "Network.requestServedFromCache":
            raise CdpTargetIntegrityError(
                "CDP served a request from cache despite the disabled-cache policy"
            )
        event_source = source
        if method == "Network.requestWillBeSent":
            request_id = event.get("requestId")
            if not isinstance(request_id, str) or not request_id:
                raise CdpTargetIntegrityError("CDP request event omitted its request ID")
            redirected = event.get("redirectResponse") is not None
            local = [
                item
                for item in self._active_requests.get(request_id, ())
                if item.source == source
            ]
            migrated = None
            if redirected and not local:
                migrated = self._resolve_active_request(
                    source, request_id, allow_oopif_migration=True
                )
            canonical_source = migrated.source if migrated is not None else source
            active = _ActiveRequest(
                source=canonical_source,
                request_id=request_id,
                loader_id=event.get("loaderId") if isinstance(event.get("loaderId"), str) else None,
                frame_id=event.get("frameId") if isinstance(event.get("frameId"), str) else None,
                resource_type=event.get("type") if isinstance(event.get("type"), str) else None,
            )
            if local and not redirected:
                raise CdpTargetIntegrityError(
                    "CDP reused an active request identity outside a redirect chain"
                )
            if len(local) > 1:
                raise CdpTargetIntegrityError("CDP request identity is ambiguous within one target")
            replaced = migrated or (local[0] if local else None)
            if replaced is not None:
                candidates = self._active_requests[request_id]
                candidates[candidates.index(replaced)] = active
                event_source = canonical_source
            else:
                state.active_request_ids.add(request_id)
                self._active_requests.setdefault(request_id, []).append(active)
        elif method in {"Network.loadingFinished", "Network.loadingFailed"}:
            request_id = event.get("requestId")
            if not isinstance(request_id, str):
                raise CdpTargetIntegrityError("CDP loading terminal event omitted its request ID")
            active = self._resolve_active_request(source, request_id, allow_oopif_migration=True)
            if active is None:
                raise CdpTargetIntegrityError(
                    "CDP loading terminal event has no active request occurrence"
                )
            event_source = active.source
            self._remove_active(active)
        elif method.startswith("Network."):
            request_id = event.get("requestId")
            if isinstance(request_id, str):
                active = self._resolve_active_request(
                    source, request_id, allow_oopif_migration=True
                )
                if active is not None:
                    event_source = active.source
        self._on_event(event_source, method, event)

    def _attached(self, parent_route: tuple[str, ...], event: Mapping[str, Any]) -> None:
        parent = self._state(parent_route)
        if parent.phase in {"destroyed", "detached"}:
            raise CdpTargetIntegrityError("detached CDP target attached a new child")
        session_id = event.get("sessionId")
        target_info = event.get("targetInfo")
        waiting = event.get("waitingForDebugger")
        if (
            not isinstance(session_id, str)
            or not session_id
            or not isinstance(target_info, Mapping)
            or waiting is not True
        ):
            raise CdpTargetIntegrityError("related CDP target attachment is malformed or unpaused")
        target_id = target_info.get("targetId")
        target_type = target_info.get("type")
        if not isinstance(target_id, str) or not target_id or not isinstance(target_type, str):
            raise CdpTargetIntegrityError("related CDP target identity is malformed")
        if target_type == "service_worker":
            raise CdpTargetIntegrityError(
                "service-worker target violated the blocked-worker policy"
            )
        if target_type not in _ALLOWED_CHILD_TARGET_TYPES:
            raise CdpTargetIntegrityError(
                f"unsupported related CDP target type cannot be instrumented: {target_type}"
            )
        route = (*parent_route, session_id)
        if (
            route in self._states
            or target_id in self._target_routes
            or session_id in self._session_routes
        ):
            raise CdpTargetIntegrityError("related CDP target/session identity was reused")
        generation = self._target_generations.get(target_id, -1) + 1
        self._target_generations[target_id] = generation
        parent_frame_id = target_info.get("parentFrameId")
        if not isinstance(parent_frame_id, str):
            parent_frame_id = None
        source = CdpTargetSource(
            route,
            target_id,
            target_type,
            generation,
            parent_route,
            parent_frame_id,
        )
        if self._shutting_down:
            state = _TargetState(source, target_type, "closing")
            state.setup_pending.add("Runtime.runIfWaitingForDebugger")
            self._states[route] = state
            self._target_routes[target_id] = route
            self._session_routes[session_id] = route
            self._notify_target_activity(source, "target-attached")
            self._queue_command(
                source,
                "Runtime.runIfWaitingForDebugger",
                {},
                label=f"{target_type}:shutdown-resume",
                on_success=lambda _result, child=source: self._shutdown_resume_ack(child),
            )
            return
        state = _TargetState(source, target_type, "configuring")
        setup = list(_BASE_SETUP_COMMANDS)
        if target_type == "iframe":
            setup.append(_FETCH_SETUP_COMMAND)
        state.setup_pending = {method for method, _params in setup}
        self._states[route] = state
        self._target_routes[target_id] = route
        self._session_routes[session_id] = route
        self._notify_target_activity(source, "target-attached")
        for method, params in setup:
            self._queue_command(
                source,
                method,
                dict(params),
                label=f"{target_type}:{method}",
                on_success=lambda result, setup_method=method, child=source: self._setup_ack(
                    child, setup_method, result
                ),
            )

    def _setup_ack(
        self,
        source: CdpTargetSource,
        method: str,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if state.phase != "configuring" or method not in state.setup_pending:
            raise CdpTargetIntegrityError("CDP child setup acknowledgement is out of sequence")
        if method == "Target.getTargetInfo":
            info = result.get("targetInfo")
            if (
                not isinstance(info, Mapping)
                or info.get("targetId") != source.target_id
                or info.get("type") != state.target_type
            ):
                raise CdpTargetIntegrityError("CDP child setup changed target identity")
        state.setup_pending.remove(method)
        if state.setup_pending:
            return
        if method not in {"Target.setAutoAttach", "Target.getTargetInfo"}:
            state.setup_pending.add("Target.setAutoAttach")
            self._queue_command(
                source,
                *_AUTO_ATTACH_COMMAND,
                label=f"{state.target_type}:Target.setAutoAttach",
                on_success=lambda result, child=source: self._setup_ack(
                    child, "Target.setAutoAttach", result
                ),
            )
            return
        if method == "Target.setAutoAttach":
            state.setup_pending.add("Target.getTargetInfo")
            self._queue_command(
                source,
                *_TARGET_BARRIER_COMMAND,
                label=f"{state.target_type}:Target.getTargetInfo",
                on_success=lambda result, child=source: self._setup_ack(
                    child, "Target.getTargetInfo", result
                ),
            )
            return
        state.phase = "resuming"
        self._queue_command(
            source,
            "Runtime.runIfWaitingForDebugger",
            {},
            label=f"{state.target_type}:Runtime.runIfWaitingForDebugger",
            on_success=lambda _result, child=source: self._resume_ack(child),
        )

    def _resume_ack(self, source: CdpTargetSource) -> None:
        state = self._state(source.session_path)
        if state.phase != "resuming":
            raise CdpTargetIntegrityError("CDP child resume acknowledgement is out of sequence")
        state.phase = "ready"

    def _shutdown_resume_ack(self, source: CdpTargetSource) -> None:
        state = self._state(source.session_path)
        if state.phase != "closing" or state.setup_pending != {
            "Runtime.runIfWaitingForDebugger"
        }:
            raise CdpTargetIntegrityError("CDP shutdown resume acknowledgement is out of sequence")
        state.setup_pending.clear()

    def _detached(self, parent_route: tuple[str, ...], event: Mapping[str, Any]) -> None:
        session_id = event.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise CdpTargetIntegrityError("related CDP target detach omitted its session ID")
        route = (*parent_route, session_id)
        state = self._state(route)
        target_id = event.get("targetId")
        if target_id is not None and target_id != state.source.target_id:
            raise CdpTargetIntegrityError("related CDP target detach changed target identity")
        descendants = [
            child
            for child_route, child in self._states.items()
            if len(child_route) > len(route)
            and child_route[: len(route)] == route
            and child.phase not in {"destroyed", "detached"}
        ]
        route_pending = [key for key in self._pending if key[0][: len(route)] == route]
        if state.phase == "configuring" and not state.active_request_ids:
            for key in route_pending:
                self._pending.pop(key, None)
            state.setup_pending.clear()
            state.phase = "detached"
            self._target_routes.pop(state.source.target_id, None)
            self._session_routes.pop(session_id, None)
            self._notify_target_activity(state.source, "target-detached")
            return
        if self._shutting_down:
            for request_id in tuple(state.active_request_ids):
                self._terminalise_request(state.source, request_id, synthetic_shutdown=True)
            for key in route_pending:
                self._pending.pop(key, None)
            state.phase = "detached"
            self._target_routes.pop(state.source.target_id, None)
            self._session_routes.pop(session_id, None)
            self._notify_target_activity(state.source, "target-detached")
            return
        if (
            state.phase != "ready"
            or state.active_request_ids
            or descendants
            or route_pending
        ):
            raise CdpTargetIntegrityError(
                "related CDP target detached with setup, request, descendant, or "
                "command work pending"
            )
        state.phase = "detached"
        self._target_routes.pop(state.source.target_id, None)
        self._session_routes.pop(session_id, None)
        self._notify_target_activity(state.source, "target-detached")

    def _notify_target_activity(self, source: CdpTargetSource, event: str) -> None:
        if self._on_target_activity is not None:
            self._on_target_activity(source, event)

    def _received(self, parent_route: tuple[str, ...], event: Mapping[str, Any]) -> None:
        session_id = event.get("sessionId")
        message = event.get("message")
        if not isinstance(session_id, str) or not session_id or not isinstance(message, str):
            raise CdpTargetIntegrityError("nested CDP message envelope is malformed")
        route = (*parent_route, session_id)
        state = self._state(route)
        if state.phase in {"destroyed", "detached"}:
            raise CdpTargetIntegrityError("detached CDP target emitted a protocol message")
        target_id = event.get("targetId")
        if target_id is not None and target_id != state.source.target_id:
            raise CdpTargetIntegrityError("nested CDP message changed target identity")
        try:
            payload = json.loads(message)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise CdpTargetIntegrityError("nested CDP message is not valid JSON") from error
        if not isinstance(payload, Mapping):
            raise CdpTargetIntegrityError("nested CDP message payload is not an object")
        self._handle_payload(state.source, payload)

    def _handle_payload(
        self, source: CdpTargetSource, payload: Mapping[str, Any]
    ) -> None:
        if "id" in payload:
            command_id = payload["id"]
            if type(command_id) is not int:
                raise CdpTargetIntegrityError("nested CDP response ID is malformed")
            pending = self._pending.pop((source.session_path, command_id), None)
            if pending is None:
                raise CdpTargetIntegrityError("nested CDP response has no pending command")
            if payload.get("error") is not None:
                raise CdpTargetIntegrityError(
                    f"nested CDP command {pending.label} failed"
                )
            result = payload.get("result", {})
            if not isinstance(result, Mapping):
                raise CdpTargetIntegrityError(
                    f"nested CDP command {pending.label} returned malformed data"
                )
            if pending.on_success is not None:
                pending.on_success(result)
            return
        method = payload.get("method")
        params = payload.get("params", {})
        if not isinstance(method, str) or not isinstance(params, Mapping):
            raise CdpTargetIntegrityError("nested CDP event is malformed")
        if method == "Target.attachedToTarget":
            self._attached(source.session_path, params)
        elif method == "Target.detachedFromTarget":
            self._detached(source.session_path, params)
        elif method == "Target.receivedMessageFromTarget":
            self._received(source.session_path, params)
        elif method in _TARGET_LIFECYCLE_METHODS:
            self._target_lifecycle_event(method, params)
        elif method in _FORWARDED_METHODS:
            self._handle_forwarded(source, method, params)
        elif method.startswith("Target."):
            raise CdpTargetIntegrityError(
                f"unsupported nested CDP target lifecycle event: {method}"
            )

    def _queue_command(
        self,
        source: CdpTargetSource,
        method: str,
        params: dict[str, Any],
        *,
        label: str,
        on_success: Callable[[Mapping[str, Any]], None] | None = None,
        policy_decision: bool = False,
    ) -> None:
        if not source.session_path:
            raise CdpTargetIntegrityError("nested CDP command has no child-session route")
        command_id = self._allocate_command_id()
        key = (source.session_path, command_id)
        self._pending[key] = _PendingCommand(label, on_success, policy_decision)
        self._send_raw(
            source.session_path,
            {"id": command_id, "method": method, "params": params},
            label=label,
        )

    def _send_raw(
        self,
        route: tuple[str, ...],
        payload: Mapping[str, Any],
        *,
        label: str,
    ) -> None:
        session_id = route[-1]
        message = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        parent_route = route[:-1]
        if not parent_route:
            self._root_send(
                "Target.sendMessageToTarget",
                {"sessionId": session_id, "message": message},
            )
            return
        wrapper_id = self._allocate_command_id()
        self._pending[(parent_route, wrapper_id)] = _PendingCommand(
            f"transport-forward:{label}"
        )
        self._send_raw(
            parent_route,
            {
                "id": wrapper_id,
                "method": "Target.sendMessageToTarget",
                "params": {"sessionId": session_id, "message": message},
            },
            label=f"transport-forward:{label}",
        )

    def _allocate_command_id(self) -> int:
        result = self._next_command_id
        self._next_command_id += 1
        return result

    def _resolve_active_request(
        self,
        source: CdpTargetSource,
        request_id: str,
        *,
        allow_oopif_migration: bool,
    ) -> _ActiveRequest | None:
        candidates = list(self._active_requests.get(request_id, ()))
        local = [item for item in candidates if item.source == source]
        if len(local) == 1:
            return local[0]
        if len(local) > 1:
            raise CdpTargetIntegrityError("CDP request identity is ambiguous within one target")
        if not allow_oopif_migration or source.target_type != "iframe":
            return None
        migrated = [
            item
            for item in candidates
            if item.resource_type == "Document"
            and item.loader_id == request_id
            and item.frame_id == source.target_id
        ]
        if len(migrated) > 1:
            raise CdpTargetIntegrityError("OOPIF request migration is ambiguous")
        return migrated[0] if migrated else None

    def _remove_active(self, active: _ActiveRequest) -> None:
        state = self._state(active.source.session_path)
        state.active_request_ids.discard(active.request_id)
        candidates = self._active_requests.get(active.request_id, [])
        if active in candidates:
            candidates.remove(active)
        if not candidates:
            self._active_requests.pop(active.request_id, None)

    def _terminalise_request(
        self,
        source: CdpTargetSource,
        request_id: str,
        *,
        synthetic_shutdown: bool,
    ) -> None:
        active = self._resolve_active_request(
            source, request_id, allow_oopif_migration=False
        )
        if active is None:
            return
        self._remove_active(active)
        if synthetic_shutdown:
            self._on_event(
                active.source,
                "Network.loadingFailed",
                {"requestId": request_id, "canceled": True, "qcsdShutdown": True},
            )
