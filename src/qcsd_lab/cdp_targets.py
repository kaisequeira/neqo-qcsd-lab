"""Race-free recursive CDP instrumentation for page-related network targets.

The image-level Playwright ownership patch prevents Playwright's private CDP
clients from attaching iframe, dedicated-worker, or shared-worker targets.
QCSD then owns every resume decision.  Page-related targets use Chromium's
public non-flat target transport recursively.  A separate browser-session
guard holds browser-level shared workers paused while the page transport adopts
them non-flat. The same public browser session discovers page targets and
rejects any sibling popup in the root context. Every child acknowledges its
complete Network/Fetch/recursion setup and exact bootstrap-request ownership
before it resumes.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    POPUP_GUARD_MARKER,
    POPUP_NAVIGATION_API,
    TARGET_EGRESS_BINDING,
    TARGET_EGRESS_SHIM_SCHEMA_VERSION,
    popup_navigation_guard_source,
    target_egress_apis,
    target_egress_shim_source,
    validate_target_egress_shim_result,
)

CDP_TARGET_INSTRUMENTATION_POLICY = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v13"
)
BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION = 1
EGRESS_PREARM_SUMMARY_SCHEMA_VERSION = 2
_BOOTSTRAP_WORKER_TYPES = ("worker", "shared_worker")
_BOOTSTRAP_OWNER_TYPES = ("page", "iframe", "worker", "shared_worker")
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
_NON_REPLAYABLE_NETWORK_EVENTS = frozenset(
    {
        "Network.webSocketCreated",
        "Network.webSocketWillSendHandshakeRequest",
        "Network.webSocketHandshakeResponseReceived",
        "Network.webSocketFrameSent",
        "Network.webTransportCreated",
        "Network.webTransportConnectionEstablished",
        "Network.directTCPSocketCreated",
        "Network.directTCPSocketOpened",
        "Network.directTCPSocketChunkSent",
        "Network.directUDPSocketCreated",
        "Network.directUDPSocketOpened",
        "Network.directUDPSocketChunkSent",
    }
)
_NON_REPLAYABLE_RUNTIME_EVENTS = frozenset({"Runtime.bindingCalled"})
_NON_REPLAYABLE_EGRESS_EVENTS = _NON_REPLAYABLE_NETWORK_EVENTS | _NON_REPLAYABLE_RUNTIME_EVENTS
_TARGET_LIFECYCLE_METHODS = frozenset(
    {
        "Inspector.targetCrashed",
        "Target.targetCrashed",
        "Target.targetCreated",
        "Target.targetDestroyed",
        "Target.targetInfoChanged",
    }
)
_EMPTY_RESULT_POLICY_COMMANDS = frozenset({"Fetch.continueRequest", "Fetch.failRequest"})
_BASE_SETUP_COMMANDS = (
    # Network.Initiator.stack is populated for script-created requests only
    # when the Debugger domain was enabled before the relevant script ran.
    ("Debugger.enable", {}),
    ("Network.enable", {}),
    ("Network.setCacheDisabled", {"cacheDisabled": True}),
    ("Network.setBypassServiceWorker", {"bypass": True}),
    ("Runtime.enable", {}),
    ("Runtime.addBinding", {"name": TARGET_EGRESS_BINDING}),
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
_PAGE_TARGET_TYPES = frozenset({"page", "iframe"})
_WORKER_TARGET_TYPES = frozenset({"worker", "shared_worker"})
_IFRAME_INSTRUMENTATION = "beforeScriptExecution"
_IFRAME_INSTALLATION_KIND = "iframe-pre-author-installation"
_IFRAME_SYNTHETIC_EXPRESSION = "true"
_IFRAME_INSTRUMENTATION_COMMAND = (
    "Debugger.setInstrumentationBreakpoint",
    {"instrumentation": _IFRAME_INSTRUMENTATION},
)
_WORKER_INSTRUMENTATION_COMMAND = (
    "Debugger.setInstrumentationBreakpoint",
    {"instrumentation": "beforeScriptExecution"},
)
_IFRAME_CONTEXT_EVENTS = frozenset(
    {
        "Runtime.executionContextCreated",
        "Runtime.executionContextDestroyed",
        "Runtime.executionContextsCleared",
    }
)
_CDP_PROTOCOL_ERROR_CODE_MIN = -(2**31)
_CDP_PROTOCOL_ERROR_CODE_MAX = 2**31 - 1
_CDP_PROTOCOL_ERROR_MESSAGE_MAX_CHARS = 240


def _egress_evaluate_command(target_type: str) -> tuple[str, dict[str, Any]]:
    return (
        "Runtime.evaluate",
        {
            "expression": target_egress_shim_source(target_type),
            "returnByValue": True,
            "awaitPromise": False,
        },
    )


def _worker_egress_evaluate_command(
    target_type: str,
    call_frame_id: str,
) -> tuple[str, dict[str, Any]]:
    if target_type not in _WORKER_TARGET_TYPES:
        raise ValueError("only worker targets accept first-script egress evaluation")
    if not isinstance(call_frame_id, str) or not call_frame_id:
        raise ValueError("worker first-script call-frame identity is malformed")
    return (
        "Debugger.evaluateOnCallFrame",
        {
            "callFrameId": call_frame_id,
            "expression": target_egress_shim_source(target_type),
            "returnByValue": True,
        },
    )


def _egress_new_document_command(target_type: str) -> tuple[str, dict[str, Any]]:
    if target_type not in _PAGE_TARGET_TYPES:
        raise ValueError("only page targets accept pre-document egress shims")
    return (
        "Page.addScriptToEvaluateOnNewDocument",
        {"source": target_egress_shim_source(target_type)},
    )


def _popup_guard_evaluate_command() -> tuple[str, dict[str, Any]]:
    return (
        "Runtime.evaluate",
        {
            "expression": f"globalThis[{json.dumps(POPUP_GUARD_MARKER)}] === true",
            "returnByValue": True,
            "awaitPromise": False,
        },
    )


def _iframe_breakpoint_condition() -> str:
    """Install both iframe guards synchronously before the paused script runs."""

    binding = json.dumps(TARGET_EGRESS_BINDING)
    policy = json.dumps(NON_REPLAYABLE_EGRESS_POLICY)
    kind = json.dumps(_IFRAME_INSTALLATION_KIND)
    return f"""
(() => {{
  const egressShim = ({target_egress_shim_source("iframe")});
  const popupGuardInstalled = ({popup_navigation_guard_source()});
  globalThis[{binding}](JSON.stringify({{
    schema_version: {TARGET_EGRESS_SHIM_SCHEMA_VERSION},
    policy: {policy},
    kind: {kind},
    target_type: 'iframe',
    egress_shim: egressShim,
    popup_guard_installed: popupGuardInstalled,
  }}));
  return false;
}})()
""".strip()


def _iframe_synthetic_trigger_command(unique_context_id: str) -> tuple[str, dict[str, Any]]:
    """Force the armed before-script barrier even when a frame has no author script."""

    if not isinstance(unique_context_id, str) or not unique_context_id:
        raise ValueError("iframe synthetic trigger requires an exact execution context")
    return (
        "Runtime.evaluate",
        {
            "expression": _IFRAME_SYNTHETIC_EXPRESSION,
            "uniqueContextId": unique_context_id,
            "returnByValue": True,
            "awaitPromise": False,
        },
    )


def _sanitised_protocol_error(error: object) -> str:
    """Return bounded CDP error evidence without reflecting arbitrary payload data."""

    if not isinstance(error, Mapping) or not {"code", "message"}.issubset(error):
        raise CdpTargetIntegrityError("nested CDP command returned a malformed error")
    code = error.get("code")
    message = error.get("message")
    if (
        type(code) is not int
        or not _CDP_PROTOCOL_ERROR_CODE_MIN <= code <= _CDP_PROTOCOL_ERROR_CODE_MAX
        or not isinstance(message, str)
    ):
        raise CdpTargetIntegrityError("nested CDP command returned a malformed error")
    message = " ".join(message.split())
    message = "".join(character if character.isprintable() else "?" for character in message)
    if not message:
        raise CdpTargetIntegrityError("nested CDP command returned a malformed error")
    return f"code={code}, message={message[:_CDP_PROTOCOL_ERROR_MESSAGE_MAX_CHARS]}"


_SHARED_WORKER_GUARD_FILTER = [
    {"type": "shared_worker", "exclude": False},
    # Browser-scope ``tab`` targets expose a paused creation tripwire for a
    # newly created popup before its page target is resumed. Packet tests show
    # that target creation itself may already perform transport I/O, so this is
    # defence-in-depth and lifecycle evidence, never a pre-I/O claim.
    # Do not select ``page`` here: the recursive non-flat page transport owns
    # page/OOPIF instrumentation and every resume decision inside the root tab.
    {"type": "tab", "exclude": False},
    {"exclude": True},
]
_SHARED_WORKER_GUARD_COMMAND = (
    "Target.setAutoAttach",
    {
        "autoAttach": True,
        "waitForDebuggerOnStart": True,
        "flatten": True,
        "filter": _SHARED_WORKER_GUARD_FILTER,
    },
)
_SHARED_WORKER_GUARD_BARRIER = ("Target.getTargets", {})
_BROWSER_TARGET_LIFECYCLE_BARRIER_LIMIT = 3
_PAGE_DISCOVERY_FILTER = [
    {"type": "page", "exclude": False},
    {"type": "service_worker", "exclude": False},
    {"exclude": True},
]
_PAGE_DISCOVERY_COMMAND = (
    "Target.setDiscoverTargets",
    {"discover": True, "filter": _PAGE_DISCOVERY_FILTER},
)
_PAGE_DISCOVERY_DISABLE_COMMAND = (
    "Target.setDiscoverTargets",
    {"discover": False},
)


class CdpTargetIntegrityError(RuntimeError):
    """A malformed, incomplete, or uninstrumented related-target event stream."""


def validate_bootstrap_prearm_summary(
    value: object,
    *,
    require_terminal: bool,
) -> dict[str, Any]:
    """Validate the content-minimised shared-worker bootstrap diagnostic.

    Dedicated-worker bootstraps deliberately retain their immediate-policy
    path, so every held prearm belongs to a guarded shared worker.  Successful
    evidence boundaries additionally require every held continue to have been
    released after all initial setup envelopes were issued.
    """

    fields = {
        "schema_version",
        "held_total",
        "released_total",
        "pending_total",
        "release_before_setup_envelopes_total",
        "by_worker_type",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("worker-bootstrap prearm summary fields are invalid")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION
    ):
        raise ValueError("worker-bootstrap prearm summary schema is invalid")
    for field_name in (
        "held_total",
        "released_total",
        "pending_total",
        "release_before_setup_envelopes_total",
    ):
        if type(value.get(field_name)) is not int or value[field_name] < 0:
            raise ValueError("worker-bootstrap prearm totals are invalid")
    by_worker_type = value.get("by_worker_type")
    if not isinstance(by_worker_type, Mapping) or set(by_worker_type) != set(
        _BOOTSTRAP_WORKER_TYPES
    ):
        raise ValueError("worker-bootstrap prearm worker inventory is invalid")

    held_total = 0
    released_total = 0
    pending_total = 0
    released_after_total = 0
    for worker_type in _BOOTSTRAP_WORKER_TYPES:
        summary = by_worker_type.get(worker_type)
        if not isinstance(summary, Mapping) or set(summary) != {
            "held",
            "released",
            "pending",
            "released_after_setup_envelopes",
            "owner_target_types",
        }:
            raise ValueError("worker-bootstrap prearm per-type fields are invalid")
        for field_name in (
            "held",
            "released",
            "pending",
            "released_after_setup_envelopes",
        ):
            if type(summary.get(field_name)) is not int or summary[field_name] < 0:
                raise ValueError("worker-bootstrap prearm per-type counts are invalid")
        owner_types = summary.get("owner_target_types")
        if (
            not isinstance(owner_types, Mapping)
            or set(owner_types) != set(_BOOTSTRAP_OWNER_TYPES)
            or any(
                type(owner_types.get(owner_type)) is not int or owner_types[owner_type] < 0
                for owner_type in _BOOTSTRAP_OWNER_TYPES
            )
        ):
            raise ValueError("worker-bootstrap prearm owner counts are invalid")
        held = summary["held"]
        released = summary["released"]
        pending = summary["pending"]
        released_after = summary["released_after_setup_envelopes"]
        if (
            released > held
            or pending != held - released
            or released_after > released
            or sum(owner_types.values()) != held
        ):
            raise ValueError("worker-bootstrap prearm counts are inconsistent")
        if worker_type == "worker" and any(
            (held, released, pending, released_after, *owner_types.values())
        ):
            raise ValueError("dedicated workers cannot use the shared-worker prearm")
        if require_terminal and (pending or released_after != released):
            raise ValueError("worker-bootstrap prearm did not reach a valid terminal state")
        held_total += held
        released_total += released
        pending_total += pending
        released_after_total += released_after
    if (
        value["held_total"] != held_total
        or value["released_total"] != released_total
        or value["pending_total"] != pending_total
        or value["release_before_setup_envelopes_total"] != 0
        or released_after_total != released_total
    ):
        raise ValueError("worker-bootstrap prearm aggregate is inconsistent")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def validate_egress_prearm_summary(
    value: object,
    *,
    require_terminal: bool,
) -> dict[str, Any]:
    """Validate aggregate proof that every runnable target received its shim."""

    fields = {
        "schema_version",
        "policy",
        "target_total",
        "installed_total",
        "pending_total",
        "popup_guard_required_total",
        "popup_guard_installed_total",
        "by_target_type",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("target egress prearm summary fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != EGRESS_PREARM_SUMMARY_SCHEMA_VERSION
        or value["policy"] != NON_REPLAYABLE_EGRESS_POLICY
    ):
        raise ValueError("target egress prearm summary identity is invalid")
    for field_name in (
        "target_total",
        "installed_total",
        "pending_total",
        "popup_guard_required_total",
        "popup_guard_installed_total",
    ):
        if type(value[field_name]) is not int or value[field_name] < 0:
            raise ValueError("target egress prearm totals are invalid")
    by_target_type = value["by_target_type"]
    target_types = {"page", "iframe", "worker", "shared_worker"}
    if not isinstance(by_target_type, Mapping) or set(by_target_type) != target_types:
        raise ValueError("target egress prearm type inventory is invalid")
    target_total = installed_total = pending_total = 0
    for target_type in sorted(target_types):
        item = by_target_type[target_type]
        if not isinstance(item, Mapping) or set(item) != {
            "target_count",
            "installed_count",
            "pending_count",
            "protected_api_observations",
            "unavailable_api_observations",
            "popup_guard_required_count",
            "popup_guard_installed_count",
        }:
            raise ValueError("target egress prearm per-type fields are invalid")
        for field_name in (
            "target_count",
            "installed_count",
            "pending_count",
            "protected_api_observations",
            "unavailable_api_observations",
            "popup_guard_required_count",
            "popup_guard_installed_count",
        ):
            if type(item[field_name]) is not int or item[field_name] < 0:
                raise ValueError("target egress prearm per-type counts are invalid")
        if (
            item["installed_count"] > item["target_count"]
            or item["pending_count"] != item["target_count"] - item["installed_count"]
            or item["protected_api_observations"] + item["unavailable_api_observations"]
            != item["installed_count"] * len(target_egress_apis(target_type))
            or item["popup_guard_required_count"]
            != (item["target_count"] if target_type in _PAGE_TARGET_TYPES else 0)
            or item["popup_guard_installed_count"] > item["popup_guard_required_count"]
        ):
            raise ValueError("target egress prearm per-type counts are inconsistent")
        target_total += item["target_count"]
        installed_total += item["installed_count"]
        pending_total += item["pending_count"]
    if (
        target_total != value["target_total"]
        or installed_total != value["installed_total"]
        or pending_total != value["pending_total"]
        or value["popup_guard_required_total"]
        != sum(
            by_target_type[target_type]["popup_guard_required_count"]
            for target_type in target_types
        )
        or value["popup_guard_installed_total"]
        != sum(
            by_target_type[target_type]["popup_guard_installed_count"]
            for target_type in target_types
        )
    ):
        raise ValueError("target egress prearm aggregate is inconsistent")
    if require_terminal and (
        pending_total
        or installed_total != target_total
        or value["popup_guard_installed_total"] != value["popup_guard_required_total"]
    ):
        raise ValueError("target egress prearm did not reach a terminal state")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


class _CdpSession(Protocol):
    def on(self, event: str, handler: Callable[[dict[str, Any]], None]) -> None: ...

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]: ...

    def detach(self) -> None: ...


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

    def request_chain_key(self, request_id: str) -> tuple[tuple[str, ...], str, int, str]:
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
    iframe_instrumentation_breakpoint_id: str | None = None
    iframe_regular_breakpoint_id: str | None = None
    iframe_pause_location: dict[str, Any] | None = None
    iframe_default_context_id: int | None = None
    iframe_default_context_unique_id: str | None = None
    iframe_initial_resume_acknowledged: bool = False
    iframe_synthetic_issued: bool = False
    iframe_synthetic_completed: bool = False
    iframe_pause_seen: bool = False
    iframe_debugger_paused: bool = False
    iframe_instrumentation_removed: bool = False
    iframe_debugger_resume_acknowledged: bool = False
    iframe_installation_received: bool = False
    iframe_regular_remove_issued: bool = False
    iframe_regular_removed: bool = False
    worker_instrumentation_breakpoint_id: str | None = None
    worker_parsed_script_urls: dict[str, str] = field(default_factory=dict)
    worker_bootstrap_script_id: str | None = None
    worker_pause_call_frame_id: str | None = None
    worker_initial_resume_acknowledged: bool = False
    worker_pause_seen: bool = False
    worker_debugger_paused: bool = False
    worker_egress_evaluation_issued: bool = False
    worker_egress_evaluation_acknowledged: bool = False
    worker_instrumentation_removed: bool = False
    worker_debugger_resume_acknowledged: bool = False


@dataclass(frozen=True)
class _ActiveRequest:
    source: CdpTargetSource
    request_id: str
    loader_id: str | None
    frame_id: str | None
    resource_type: str | None
    method: str | None
    url: str | None


@dataclass
class _WorkerBootstrap:
    source: CdpTargetSource | None
    url: str
    parent_route: tuple[str, ...]
    parent_frame_id: str | None
    browser_context_id: str
    guardian_session_id: str | None = None
    owner_source: CdpTargetSource | None = None
    attach_requested: bool = False
    attach_session_id: str | None = None
    attach_command_session_id: str | None = None
    attach_command_resolved: bool = False
    guardian_detached: bool = False
    initial_setup_envelopes_expected: int = 0
    initial_setup_envelopes_issued: int = 0
    fetch_source: CdpTargetSource | None = None
    fetch_request_id: str | None = None
    fetch_network_id: str | None = None
    fetch_policy_outcome: str | None = None
    fetch_released: bool = False
    fetch_release_after_setup_envelopes: bool | None = None


@dataclass
class _PendingCommand:
    label: str
    on_success: Callable[[Mapping[str, Any]], None] | None = None
    policy_decision: bool = False


@dataclass
class _BootstrapFetchDecision:
    bootstrap: _WorkerBootstrap
    prearm: bool
    decided: bool = False


class RecursiveCdpTargetRouter:
    """Instrument a root page plus every recursively related iframe/worker target."""

    def __init__(
        self,
        session: _CdpSession,
        *,
        on_event: Callable[[CdpTargetSource, str, Mapping[str, Any]], None],
        on_target_activity: Callable[[CdpTargetSource, str], None] | None = None,
        on_non_replayable_egress: (
            Callable[[CdpTargetSource | None, str, str, object | None], None] | None
        ) = None,
    ) -> None:
        self._session = session
        self._on_event = on_event
        self._on_target_activity = on_target_activity
        self._on_non_replayable_egress = on_non_replayable_egress
        self._root_source: CdpTargetSource | None = None
        self._states: dict[tuple[str, ...], _TargetState] = {}
        self._target_routes: dict[str, tuple[str, ...]] = {}
        self._session_routes: dict[str, tuple[str, ...]] = {}
        self._pending: dict[tuple[tuple[str, ...], int], _PendingCommand] = {}
        self._next_command_id = 1
        self._failure: CdpTargetIntegrityError | None = None
        self._shutting_down = False
        self._aborting = False
        self._abort_finished = False
        self._target_generations: dict[str, int] = {}
        self._active_requests: dict[str, list[_ActiveRequest]] = {}
        self._claimed_worker_bootstraps: set[tuple[CdpTargetSource, str]] = set()
        self._root_browser_context_id: str | None = None
        self._worker_bootstraps: dict[CdpTargetSource, _WorkerBootstrap] = {}
        self._pending_worker_sources: set[CdpTargetSource] = set()
        self._guarded_shared_workers: dict[str, _WorkerBootstrap] = {}
        self._guardian_target_by_session: dict[str, str] = {}
        self._bootstrap_fetch_by_policy_identity: dict[
            tuple[CdpTargetSource, str], _BootstrapFetchDecision
        ] = {}
        self._shared_guard_registered = False
        self._shared_guard_shutdown = False
        self._shared_guard_finished = False
        self._egress_shim_receipts: dict[CdpTargetSource, dict[str, Any]] = {}
        self._popup_guard_receipts: set[CdpTargetSource] = set()

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

    @property
    def root_browser_context_id(self) -> str:
        """Return the exact incognito context containing the observed page."""

        if self._root_browser_context_id is None:
            raise CdpTargetIntegrityError("root CDP browser-context identity is unavailable")
        return self._root_browser_context_id

    @property
    def bootstrap_prearm_summary(self) -> dict[str, Any]:
        """Return aggregate evidence for race-free worker-bootstrap release.

        The diagnostic deliberately excludes URLs and protocol identities.  A
        fresh mapping is returned on every access so callers cannot mutate the
        router's state.
        """

        by_worker_type: dict[str, dict[str, Any]] = {}
        bootstraps = {
            "worker": [
                bootstrap
                for source, bootstrap in self._worker_bootstraps.items()
                if source.target_type == "worker"
            ],
            "shared_worker": list(self._guarded_shared_workers.values()),
        }
        for worker_type in _BOOTSTRAP_WORKER_TYPES:
            held = [
                bootstrap
                for bootstrap in bootstraps[worker_type]
                if bootstrap.fetch_policy_outcome == "continue"
            ]
            released = [bootstrap for bootstrap in held if bootstrap.fetch_released]
            by_worker_type[worker_type] = {
                "held": len(held),
                "released": len(released),
                "pending": len(held) - len(released),
                "released_after_setup_envelopes": sum(
                    bootstrap.fetch_release_after_setup_envelopes is True for bootstrap in released
                ),
                "owner_target_types": {
                    owner_type: sum(
                        bootstrap.fetch_source is not None
                        and bootstrap.fetch_source.target_type == owner_type
                        for bootstrap in held
                    )
                    for owner_type in _BOOTSTRAP_OWNER_TYPES
                },
            }
        held_total = sum(value["held"] for value in by_worker_type.values())
        released_total = sum(value["released"] for value in by_worker_type.values())
        return {
            "schema_version": BOOTSTRAP_PREARM_SUMMARY_SCHEMA_VERSION,
            "held_total": held_total,
            "released_total": released_total,
            "pending_total": held_total - released_total,
            "release_before_setup_envelopes_total": sum(
                bootstrap.fetch_release_after_setup_envelopes is False
                for values in bootstraps.values()
                for bootstrap in values
                if bootstrap.fetch_released
            ),
            "by_worker_type": by_worker_type,
        }

    @property
    def egress_prearm_summary(self) -> dict[str, Any]:
        """Return aggregate proof that each observed target was shimmed before resume."""

        by_target_type: dict[str, dict[str, int]] = {}
        # Targets that detached or were positively resumed only for disposal
        # before completing setup never ran accepted author code.  Retain every
        # target that produced a receipt, plus every still-live target whose
        # prearm remains an obligation.
        states = tuple(
            state
            for state in self._states.values()
            if state.source in self._egress_shim_receipts
            or state.phase not in {"closing", "destroyed", "detached"}
        )
        for target_type in ("page", "iframe", "worker", "shared_worker"):
            sources = [state.source for state in states if state.target_type == target_type]
            receipts = [
                self._egress_shim_receipts[source]
                for source in sources
                if source in self._egress_shim_receipts
            ]
            by_target_type[target_type] = {
                "target_count": len(sources),
                "installed_count": len(receipts),
                "pending_count": len(sources) - len(receipts),
                "protected_api_observations": sum(
                    len(receipt["protected_apis"]) for receipt in receipts
                ),
                "unavailable_api_observations": sum(
                    len(receipt["unavailable_apis"]) for receipt in receipts
                ),
                "popup_guard_required_count": (
                    len(sources) if target_type in _PAGE_TARGET_TYPES else 0
                ),
                "popup_guard_installed_count": sum(
                    source in self._popup_guard_receipts for source in sources
                ),
            }
        target_total = sum(item["target_count"] for item in by_target_type.values())
        installed_total = sum(item["installed_count"] for item in by_target_type.values())
        popup_guard_required_total = sum(
            item["popup_guard_required_count"] for item in by_target_type.values()
        )
        popup_guard_installed_total = sum(
            item["popup_guard_installed_count"] for item in by_target_type.values()
        )
        return {
            "schema_version": EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
            "policy": NON_REPLAYABLE_EGRESS_POLICY,
            "target_total": target_total,
            "installed_total": installed_total,
            "pending_total": target_total - installed_total,
            "popup_guard_required_total": popup_guard_required_total,
            "popup_guard_installed_total": popup_guard_installed_total,
            "by_target_type": by_target_type,
        }

    @property
    def shutdown_ready(self) -> bool:
        """Whether the router can enter its fail-closed context-disposal boundary."""

        self.raise_if_failed()
        egress = self.egress_prearm_summary
        return (
            self._root_source is not None
            and self._shared_guard_registered
            and not self._shutting_down
            and egress["pending_total"] == 0
            and not self._has_pending_shutdown_work()
        )

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
        for method in _NON_REPLAYABLE_EGRESS_EVENTS:
            self._session.on(
                method,
                self._guard(
                    lambda event, egress_method=method: self._handle_non_replayable_egress(
                        self.root_source, egress_method, event
                    )
                ),
            )
        for method in _TARGET_LIFECYCLE_METHODS:
            self._session.on(
                method,
                self._guard(
                    lambda event, lifecycle=method: self._target_lifecycle_event(lifecycle, event)
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
        browser_context_id = target_info.get("browserContextId")
        if (
            not isinstance(target_id, str)
            or not target_id
            or target_type != "page"
            or not isinstance(browser_context_id, str)
            or not browser_context_id
        ):
            raise CdpTargetIntegrityError("root CDP target is not an identified page")
        source = CdpTargetSource((), target_id, "page", 0, None, None)
        self._root_source = source
        self._root_browser_context_id = browser_context_id
        self._states[()] = _TargetState(source, "page", "ready")
        self._target_routes[target_id] = ()

        for method, params in _BASE_SETUP_COMMANDS:
            self._root_send(method, dict(params))
        page_init = self._root_send(*_egress_new_document_command("page"))
        self._validate_page_init_result(page_init)
        evaluation = self._root_send(*_egress_evaluate_command("page"))
        self._record_egress_evaluation(source, evaluation)
        popup_evaluation = self._root_send(*_popup_guard_evaluate_command())
        self._record_popup_guard_evaluation(source, popup_evaluation)
        self._root_send(*_FETCH_SETUP_COMMAND)
        self._root_send(*_AUTO_ATTACH_COMMAND)
        # Chromium's auto-attach command has historically returned before all
        # existing related targets were reported. A following target query is
        # the explicit protocol barrier used by Playwright itself.
        barrier = self._root_send(*_TARGET_BARRIER_COMMAND)
        barrier_info = barrier.get("targetInfo")
        if (
            not isinstance(barrier_info, Mapping)
            or barrier_info.get("targetId") != target_id
            or barrier_info.get("type") != "page"
            or barrier_info.get("browserContextId") != browser_context_id
        ):
            raise CdpTargetIntegrityError("root CDP auto-attach barrier changed target identity")
        self.raise_if_failed()
        return source

    def register_shared_worker_guard(self) -> None:
        """Bind the one browser-level shared-worker guard to this router."""

        self.raise_if_failed()
        if self._root_source is None:
            raise CdpTargetIntegrityError("shared-worker guard started before root instrumentation")
        if self._shared_guard_registered:
            raise CdpTargetIntegrityError("shared-worker guard was registered more than once")
        if self._shutting_down:
            raise CdpTargetIntegrityError("shared-worker guard started during shutdown")
        self._shared_guard_registered = True

    @staticmethod
    def _validate_page_init_result(result: Mapping[str, Any]) -> None:
        identifier = result.get("identifier")
        if not isinstance(identifier, str) or not identifier:
            raise CdpTargetIntegrityError(
                "CDP pre-document egress shim returned no script identifier"
            )

    def _record_egress_evaluation(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
        *,
        expected_already_installed: bool | None = None,
    ) -> None:
        if result.get("exceptionDetails") is not None:
            raise CdpTargetIntegrityError("CDP target egress shim evaluation threw")
        remote = result.get("result")
        if not isinstance(remote, Mapping) or remote.get("type") != "object":
            raise CdpTargetIntegrityError("CDP target egress shim result is malformed")
        try:
            receipt = validate_target_egress_shim_result(
                remote.get("value"), target_type=source.target_type
            )
        except ValueError as error:
            raise CdpTargetIntegrityError("CDP target egress shim receipt is invalid") from error
        # Page/frame realms are protected first by the context init script so
        # sibling popups cannot execute before browser-target rejection.  The
        # CDP evaluation must therefore observe that exact idempotent receipt;
        # workers have no context init script and must be first-installed in
        # their fully initialised first-script call frame while it is paused.
        if expected_already_installed is None:
            expected_already_installed = source.target_type in _PAGE_TARGET_TYPES
        if receipt["already_installed"] is not expected_already_installed:
            raise CdpTargetIntegrityError(
                "CDP target egress shim installation order differs from policy"
            )
        if source in self._egress_shim_receipts:
            raise CdpTargetIntegrityError("CDP target egress shim receipt was reused")
        self._egress_shim_receipts[source] = receipt

    def _record_popup_guard_evaluation(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        if source.target_type not in _PAGE_TARGET_TYPES:
            raise CdpTargetIntegrityError("non-page target reported a popup guard")
        if result.get("exceptionDetails") is not None:
            raise CdpTargetIntegrityError("CDP popup-guard marker evaluation threw")
        remote = result.get("result")
        if (
            not isinstance(remote, Mapping)
            or remote.get("type") != "boolean"
            or remote.get("value") is not True
            or source in self._popup_guard_receipts
        ):
            raise CdpTargetIntegrityError("CDP target did not prove its context-init popup guard")
        self._popup_guard_receipts.add(source)

    def _record_iframe_installation_receipt(
        self,
        source: CdpTargetSource,
        event: Mapping[str, Any],
        decoded: Mapping[str, Any],
    ) -> None:
        """Bind the conditional-breakpoint receipt to its exact iframe realm."""

        state = self._state(source.session_path)
        expected_fields = {
            "schema_version",
            "policy",
            "kind",
            "target_type",
            "egress_shim",
            "popup_guard_installed",
        }
        execution_context_id = event.get("executionContextId")
        if (
            source.target_type != "iframe"
            or state.phase != "resuming"
            or not state.iframe_pause_seen
            or state.iframe_installation_received
            or set(decoded) != expected_fields
            or type(decoded.get("schema_version")) is not int
            or decoded.get("schema_version") != TARGET_EGRESS_SHIM_SCHEMA_VERSION
            or decoded.get("policy") != NON_REPLAYABLE_EGRESS_POLICY
            or decoded.get("kind") != _IFRAME_INSTALLATION_KIND
            or decoded.get("target_type") != "iframe"
            or type(execution_context_id) is not int
            or execution_context_id != state.iframe_default_context_id
            or decoded.get("popup_guard_installed") is not True
        ):
            raise CdpTargetIntegrityError("CDP iframe pre-author installation receipt is invalid")
        self._record_egress_evaluation(
            source,
            {
                "result": {
                    "type": "object",
                    "value": decoded.get("egress_shim"),
                }
            },
            expected_already_installed=False,
        )
        if source in self._popup_guard_receipts:
            raise CdpTargetIntegrityError("CDP iframe popup-guard receipt was reused")
        self._popup_guard_receipts.add(source)
        state.iframe_installation_received = True
        self._maybe_remove_iframe_regular_breakpoint(source)
        self._maybe_finish_iframe_prearm(source)

    def _handle_non_replayable_egress(
        self,
        source: CdpTargetSource,
        method: str,
        event: Mapping[str, Any],
    ) -> None:
        """Consume a constructor binding or a post-construction Network tripwire."""

        if method == "Runtime.bindingCalled":
            if event.get("name") != TARGET_EGRESS_BINDING:
                raise CdpTargetIntegrityError("CDP Runtime binding event changed identity")
            payload = event.get("payload")
            if not isinstance(payload, str):
                raise CdpTargetIntegrityError("CDP egress binding payload is malformed")
            try:
                decoded = json.loads(payload)
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise CdpTargetIntegrityError("CDP egress binding payload is not JSON") from error
            if not isinstance(decoded, Mapping):
                raise CdpTargetIntegrityError("CDP egress binding payload fields are invalid")
            if decoded.get("kind") == _IFRAME_INSTALLATION_KIND:
                self._record_iframe_installation_receipt(source, event, decoded)
                return
            if set(decoded) != {
                "schema_version",
                "policy",
                "kind",
                "api",
            }:
                raise CdpTargetIntegrityError("CDP egress binding payload fields are invalid")
            api = decoded.get("api")
            if (
                type(decoded.get("schema_version")) is not int
                or decoded.get("schema_version") != TARGET_EGRESS_SHIM_SCHEMA_VERSION
                or decoded.get("policy") != NON_REPLAYABLE_EGRESS_POLICY
                or decoded.get("kind") != "attempt"
                or api
                not in (
                    {*target_egress_apis(source.target_type), POPUP_NAVIGATION_API}
                    if source.target_type in _PAGE_TARGET_TYPES
                    else set(target_egress_apis(source.target_type))
                )
            ):
                raise CdpTargetIntegrityError("CDP egress binding payload is invalid")
            mechanism = (
                "context-init-popup-guard"
                if api == POPUP_NAVIGATION_API
                else "paused-target-runtime-shim"
            )
            url: object | None = None
        elif method in _NON_REPLAYABLE_NETWORK_EVENTS:
            api_by_method = {
                "Network.webSocketCreated": "WebSocket",
                "Network.webSocketWillSendHandshakeRequest": "WebSocket",
                "Network.webSocketHandshakeResponseReceived": "WebSocket",
                "Network.webSocketFrameSent": "WebSocket",
                "Network.webTransportCreated": "WebTransport",
                "Network.webTransportConnectionEstablished": "WebTransport",
                "Network.directTCPSocketCreated": "TCPSocket",
                "Network.directTCPSocketOpened": "TCPSocket",
                "Network.directTCPSocketChunkSent": "TCPSocket",
                "Network.directUDPSocketCreated": "UDPSocket",
                "Network.directUDPSocketOpened": "UDPSocket",
                "Network.directUDPSocketChunkSent": "UDPSocket",
            }
            api = api_by_method[method]
            mechanism = "cdp-network-tripwire"
            url = event.get("url") if method.endswith("Created") else None
        else:
            raise CdpTargetIntegrityError("unsupported non-replayable CDP egress event")
        if self._on_non_replayable_egress is None:
            raise CdpTargetIntegrityError(
                f"non-replayable browser egress reached an unguarded router: {api}"
            )
        self._on_non_replayable_egress(source, str(api), mechanism, url)

    def browser_service_worker_attempt(self, url: object) -> None:
        """Record browser-scope service-worker creation as typed egress."""

        if self._on_non_replayable_egress is None:
            raise CdpTargetIntegrityError(
                "service-worker target reached an unguarded browser context"
            )
        self._on_non_replayable_egress(
            None,
            "ServiceWorker",
            "browser-service-worker-tripwire",
            url,
        )

    def browser_popup_tab_attempt(self, url: object) -> None:
        """Send a popup-tab tripwire through the content-minimising callback."""

        if self._on_non_replayable_egress is None:
            raise CdpTargetIntegrityError("popup tab reached an unguarded browser context")
        self._on_non_replayable_egress(
            None,
            POPUP_NAVIGATION_API,
            "browser-popup-tab-tripwire",
            url,
        )

    def browser_target_info_changed(self, info: Mapping[str, Any]) -> None:
        """Record a browser-session root-page info change in the quiet ledger."""

        root = self.root_source
        if (
            info.get("targetId") != root.target_id
            or info.get("type") != "page"
            or info.get("browserContextId") != self.root_browser_context_id
        ):
            raise CdpTargetIntegrityError("browser root target-info update changed identity")
        self._notify_target_activity(root, "target-info-changed")

    def adopt_guarded_shared_worker(self, event: Mapping[str, Any]) -> None:
        """Validate a paused browser attachment and adopt it on the page transport.

        Chromium exposes shared workers only at browser scope.  The browser
        guard owns the flattened debugger hold, while this method creates the
        independently routable non-flat page session used for all policy and
        evidence commands.  The worker is not resumed until its exact root
        Script occurrence has also been bound.
        """

        self.raise_if_failed()
        if not self._shared_guard_registered or self._shared_guard_finished:
            raise CdpTargetIntegrityError(
                "shared-worker attachment arrived without an active browser guard"
            )
        guardian_session_id = event.get("sessionId")
        target_info = event.get("targetInfo")
        if (
            not isinstance(guardian_session_id, str)
            or not guardian_session_id
            or not isinstance(target_info, Mapping)
            or event.get("waitingForDebugger") is not True
        ):
            raise CdpTargetIntegrityError(
                "browser shared-worker attachment is malformed or unpaused"
            )
        target_id = target_info.get("targetId")
        target_type = target_info.get("type")
        url = target_info.get("url")
        browser_context_id = target_info.get("browserContextId")
        if (
            not isinstance(target_id, str)
            or not target_id
            or target_type != "shared_worker"
            or not isinstance(url, str)
            or not url
            or not isinstance(browser_context_id, str)
            or browser_context_id != self.root_browser_context_id
            or target_info.get("attached") is not True
        ):
            raise CdpTargetIntegrityError(
                "browser shared-worker target identity, URL, or context is invalid"
            )
        if (
            guardian_session_id in self._guardian_target_by_session
            or target_id in self._guarded_shared_workers
            or target_id in self._target_routes
        ):
            raise CdpTargetIntegrityError(
                "browser shared-worker target/session identity was reused"
            )
        bootstrap = _WorkerBootstrap(
            source=None,
            url=url,
            parent_route=(),
            parent_frame_id=None,
            browser_context_id=browser_context_id,
            guardian_session_id=guardian_session_id,
        )
        self._guarded_shared_workers[target_id] = bootstrap
        self._guardian_target_by_session[guardian_session_id] = target_id
        self._bind_bootstrap_owner(target_id, bootstrap, shared=True)
        if bootstrap.owner_source is not None or self._shutting_down:
            self._request_guarded_shared_worker_attach(target_id, bootstrap)

    def guarded_shared_worker_detached(self, event: Mapping[str, Any]) -> None:
        """Validate termination of the browser-level flattened guardian session."""

        if not self._aborting:
            self.raise_if_failed()
        session_id = event.get("sessionId")
        target_id = event.get("targetId")
        if not isinstance(session_id, str) or not session_id:
            raise CdpTargetIntegrityError(
                "browser shared-worker detach omitted its guardian session"
            )
        expected_target = self._guardian_target_by_session.get(session_id)
        if (
            expected_target is None
            or not isinstance(target_id, str)
            or target_id != expected_target
        ):
            raise CdpTargetIntegrityError(
                "browser shared-worker detach changed or reused target identity"
            )
        bootstrap = self._guarded_shared_workers[target_id]
        if bootstrap.guardian_detached:
            raise CdpTargetIntegrityError("browser shared-worker guardian detached more than once")
        bootstrap.guardian_detached = True
        self._guardian_target_by_session.pop(session_id, None)
        if (
            bootstrap.fetch_policy_outcome == "continue"
            and not bootstrap.fetch_released
            and not self._aborting
        ):
            raise CdpTargetIntegrityError(
                "browser shared worker detached with a held bootstrap request"
            )
        if (
            bootstrap.source is None
            and bootstrap.fetch_policy_outcome != "fail"
            and not self._shutting_down
        ):
            raise CdpTargetIntegrityError(
                "browser shared worker detached before guarded adoption completed"
            )

    def begin_shared_worker_guard_shutdown(self) -> None:
        """Bind the guard's shutdown boundary to the router shutdown boundary."""

        self.raise_if_failed()
        if not self._shared_guard_registered or self._shared_guard_shutdown:
            raise CdpTargetIntegrityError("shared-worker guard shutdown is missing or repeated")
        if not self._shutting_down:
            raise CdpTargetIntegrityError("shared-worker guard shut down before the target router")
        self._shared_guard_shutdown = True

    def begin_shared_worker_guard_abort(self) -> None:
        """Bind exceptional guard cleanup to an already-declared router abort."""

        if not self._shared_guard_registered or self._shared_guard_shutdown:
            raise CdpTargetIntegrityError("shared-worker guard abort is missing or repeated")
        if not self._shutting_down or not self._aborting:
            raise CdpTargetIntegrityError("shared-worker guard aborted before the target router")
        self._shared_guard_shutdown = True

    def finish_shared_worker_guard(self) -> None:
        """Prove every browser-level guardian reached a terminal detach."""

        self.raise_if_failed()
        if self._aborting:
            raise CdpTargetIntegrityError("normal shared-worker guard finish was used during abort")
        if not self._shared_guard_shutdown or self._shared_guard_finished:
            raise CdpTargetIntegrityError(
                "shared-worker guard finished without one deliberate shutdown"
            )
        unresolved = [
            target_id
            for target_id, bootstrap in self._guarded_shared_workers.items()
            if not bootstrap.guardian_detached
        ]
        if unresolved or self._guardian_target_by_session:
            raise CdpTargetIntegrityError(
                "browser shared-worker guardian sessions remain unresolved"
            )
        self._shared_guard_finished = True

    def shared_worker_guard_lifecycle_state(
        self,
    ) -> tuple[tuple[str, ...], tuple[str, ...], int]:
        """Return the strict internal guardian state for ordered shutdown barriers."""

        self.raise_if_failed()
        if not self._shared_guard_shutdown or self._shared_guard_finished or self._aborting:
            raise CdpTargetIntegrityError(
                "shared-worker guardian lifecycle was queried outside normal shutdown"
            )
        guarded = tuple(sorted(self._guarded_shared_workers))
        unresolved = tuple(
            sorted(
                target_id
                for target_id, bootstrap in self._guarded_shared_workers.items()
                if not bootstrap.guardian_detached
            )
        )
        return guarded, unresolved, len(self._guardian_target_by_session)

    def finish_shared_worker_guard_abort(self) -> None:
        """Retire guardian sessions after the complete context was disposed.

        ``BrowserContext.close()`` is the exceptional-disposal barrier. CDP is
        not required to report every target detach before it returns, so an
        abort locally retires remaining guardian identities. This deliberately
        cannot satisfy the strict successful finish above.
        """

        if not self._aborting or not self._shared_guard_shutdown or self._shared_guard_finished:
            raise CdpTargetIntegrityError(
                "shared-worker guard abort finished without context disposal"
            )
        for bootstrap in self._guarded_shared_workers.values():
            bootstrap.guardian_detached = True
        self._guardian_target_by_session.clear()
        self._shared_guard_finished = True

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
        parameters = dict(params)
        request_id = parameters.get("requestId")
        bootstrap_decision = (
            self._bootstrap_fetch_by_policy_identity.get((source, request_id))
            if isinstance(request_id, str)
            else None
        )
        if bootstrap_decision is not None:
            if bootstrap_decision.decided:
                raise CdpTargetIntegrityError(
                    "worker-bootstrap Fetch policy was decided more than once"
                )
            bootstrap_decision.decided = True
            bootstrap = bootstrap_decision.bootstrap
            if not bootstrap_decision.prearm:
                self._send_policy_decision(source, method, parameters, label=label)
                return
            if bootstrap.fetch_policy_outcome is not None:
                raise CdpTargetIntegrityError(
                    "worker-bootstrap prearm policy was decided more than once"
                )
            if method == "Fetch.failRequest":
                bootstrap.fetch_policy_outcome = "fail"
                self._send_policy_decision(source, method, parameters, label=label)
                return
            if set(parameters) != {"requestId"}:
                raise CdpTargetIntegrityError(
                    "worker-bootstrap continue command changed its exact request"
                )
            bootstrap.fetch_policy_outcome = "continue"
            self._maybe_release_bootstrap_continue(bootstrap)
            return
        self._send_policy_decision(source, method, parameters, label=label)

    def begin_shutdown(self) -> None:
        """Freeze target creation after all setup/policy commands are acknowledged.

        The caller then closes the complete browser context, which deliberately
        terminates otherwise long-lived iframes/workers and lets their terminal
        network and detach events drain before :meth:`finish` validates them.
        """

        self.raise_if_failed()
        if self._shutting_down:
            raise CdpTargetIntegrityError("CDP target shutdown started more than once")
        if not self._shared_guard_registered:
            raise CdpTargetIntegrityError(
                "CDP target shutdown began without the browser shared-worker guard"
            )
        if self._has_pending_shutdown_work():
            raise CdpTargetIntegrityError(
                "CDP target shutdown began with setup, ownership, adoption, "
                "bootstrap prearm, or policy commands pending"
            )
        self._shutting_down = True

    def begin_abort(self) -> None:
        """Begin exceptional disposal after an acquisition was rejected.

        Unlike normal shutdown this permits setup, policy, ownership, and
        shared-worker prearm work to remain pending. It is usable only with the
        separate abort finish after the browser context has been disposed.
        """

        if self._shutting_down or self._abort_finished:
            raise CdpTargetIntegrityError("CDP target abort started more than once")
        if self._root_source is None or not self._shared_guard_registered:
            raise CdpTargetIntegrityError("CDP target abort began before complete root/guard setup")
        self._aborting = True
        self._shutting_down = True

    def raise_if_failed(self) -> None:
        if self._failure is not None:
            raise self._failure

    def finish(self) -> None:
        """Prove no child escaped setup and no target/protocol work remains pending."""

        self.raise_if_failed()
        validate_egress_prearm_summary(self.egress_prearm_summary, require_terminal=True)
        if self._aborting:
            raise CdpTargetIntegrityError("normal CDP target finish was used during abort")
        if not self._shutting_down:
            raise CdpTargetIntegrityError(
                "CDP target instrumentation finished without a deliberate context shutdown"
            )
        if not self._shared_guard_finished:
            raise CdpTargetIntegrityError(
                "CDP target instrumentation finished before its shared-worker guard"
            )
        if self._pending:
            labels = ", ".join(sorted(command.label for command in self._pending.values()))
            raise CdpTargetIntegrityError(f"CDP shutdown commands remain unresolved: {labels}")
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

    def finish_abort(self) -> None:
        """Retire rejected observations after ``BrowserContext.close()``.

        No graph can be built from this state. Outstanding commands and target
        identities are cancelled only at that explicit disposal boundary; the
        original failure remains recorded and this path cannot become a normal
        successful :meth:`finish`.
        """

        if (
            not self._aborting
            or not self._shutting_down
            or not self._shared_guard_finished
            or self._abort_finished
        ):
            raise CdpTargetIntegrityError(
                "CDP target abort finished without complete context disposal"
            )
        for state in self._states.values():
            for request_id in tuple(state.active_request_ids):
                self._terminalise_request(
                    state.source,
                    request_id,
                    # The rejected audit is already frozen. Abort retirement
                    # cannot publish synthetic evidence into it.
                    synthetic_shutdown=False,
                )
            state.setup_pending.clear()
            if state.source.session_path and state.phase != "destroyed":
                state.phase = "detached"
        self._pending.clear()
        self._pending_worker_sources.clear()
        self._session_routes.clear()
        self._target_routes = {
            self.root_source.target_id: self.root_source.session_path,
        }
        self._abort_finished = True

    def _guard(self, handler: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
        def dispatch(event: dict[str, Any]) -> None:
            if self._failure is not None and not self._aborting:
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

    def _has_pending_shutdown_work(self) -> bool:
        unresolved_guarded = any(
            not (bootstrap.fetch_policy_outcome == "fail" and bootstrap.guardian_detached)
            and (
                bootstrap.source is None
                or not bootstrap.attach_command_resolved
                or bootstrap.attach_session_id != bootstrap.attach_command_session_id
            )
            for bootstrap in self._guarded_shared_workers.values()
        )
        unresolved_prearms = any(
            bootstrap.fetch_policy_outcome is None
            or (bootstrap.fetch_policy_outcome == "continue" and not bootstrap.fetch_released)
            for bootstrap in self._guarded_shared_workers.values()
        )
        return (
            any(command.policy_decision for command in self._pending.values())
            or any(
                state.phase not in {"ready", "detached", "destroyed"}
                for state in self._states.values()
            )
            or bool(self._pending_worker_sources)
            or unresolved_guarded
            or unresolved_prearms
        )

    def _send_policy_decision(
        self,
        source: CdpTargetSource,
        method: str,
        params: dict[str, Any],
        *,
        label: str,
    ) -> None:
        if not source.session_path:
            result = self._root_send(method, params)
            if type(result) is not dict or result != {}:
                raise CdpTargetIntegrityError(
                    f"root CDP policy command {label} did not return an exact empty result"
                )
            return
        self._queue_command(
            source,
            method,
            params,
            label=label,
            policy_decision=True,
        )

    def _guarded_shared_bootstrap_for_target_id(self, target_id: str) -> _WorkerBootstrap | None:
        return self._guarded_shared_workers.get(target_id)

    def _register_bootstrap_fetch(
        self,
        source: CdpTargetSource,
        event: Mapping[str, Any],
    ) -> _BootstrapFetchDecision | None:
        """Bind an owner-side Fetch pause only to a guarded shared worker.

        Ordinary page scripts are never speculatively held: the Fetch
        ``networkId`` must already name a guarded shared-worker bootstrap,
        and its exact owner-side Network Script occurrence must already exist.
        Dedicated-worker bootstrap Fetch can precede target attachment in
        Chromium and therefore retains the normal immediate policy path.
        """

        network_id = event.get("networkId")
        if not isinstance(network_id, str) or not network_id:
            return None
        bootstrap = self._guarded_shared_bootstrap_for_target_id(network_id)
        if bootstrap is None:
            return None
        request_id = event.get("requestId")
        request = event.get("request")
        resource_type = event.get("resourceType")
        frame_id = event.get("frameId")
        if (
            not isinstance(request_id, str)
            or not request_id
            or not isinstance(request, Mapping)
            or resource_type != "Other"
            or request.get("method") != "GET"
            or bootstrap.owner_source != source
        ):
            raise CdpTargetIntegrityError(
                "worker-bootstrap Fetch identity, type, method, URL, or owner is invalid"
            )
        owner_occurrences = [
            active
            for active in self._active_requests.get(network_id, ())
            if active.source == source
        ]
        if len(owner_occurrences) != 1:
            raise CdpTargetIntegrityError(
                "worker-bootstrap Fetch has no unique owner Network occurrence"
            )
        owner = owner_occurrences[0]
        if (
            owner.resource_type != "Script"
            or owner.method != "GET"
            or request.get("url") != owner.url
            or (frame_id is not None and frame_id != owner.frame_id)
        ):
            raise CdpTargetIntegrityError(
                "worker-bootstrap Fetch does not match its owner Network Script"
            )
        identity = (source, request_id)
        if identity in self._bootstrap_fetch_by_policy_identity:
            raise CdpTargetIntegrityError(
                "worker-bootstrap Fetch interception was duplicated or reused"
            )
        prearm = bootstrap.fetch_request_id is None
        if prearm:
            if owner.url != bootstrap.url:
                raise CdpTargetIntegrityError(
                    "initial worker-bootstrap Fetch changed its target URL"
                )
            bootstrap.fetch_source = source
            bootstrap.fetch_request_id = request_id
            bootstrap.fetch_network_id = network_id
        elif (
            bootstrap.fetch_policy_outcome != "continue"
            or not bootstrap.fetch_released
            or bootstrap.fetch_source != source
            or bootstrap.fetch_network_id != network_id
        ):
            raise CdpTargetIntegrityError(
                "worker-bootstrap redirect arrived before its exact prearm release"
            )
        decision = _BootstrapFetchDecision(bootstrap=bootstrap, prearm=prearm)
        self._bootstrap_fetch_by_policy_identity[identity] = decision
        return decision

    def _maybe_release_bootstrap_continue(self, bootstrap: _WorkerBootstrap) -> None:
        if bootstrap.fetch_policy_outcome != "continue" or bootstrap.fetch_released:
            return
        if bootstrap.source is None:
            return
        if (
            bootstrap.initial_setup_envelopes_expected <= 0
            or bootstrap.initial_setup_envelopes_issued
            != bootstrap.initial_setup_envelopes_expected
        ):
            return
        source = bootstrap.fetch_source
        request_id = bootstrap.fetch_request_id
        if source is None or request_id is None:
            raise CdpTargetIntegrityError(
                "worker-bootstrap continue lost its owner policy identity"
            )
        state = self._state(source.session_path)
        if state.source != source or state.phase not in {"ready", "resuming"}:
            raise CdpTargetIntegrityError(
                "worker-bootstrap owner detached before its held request was released"
            )
        self._send_policy_decision(
            source,
            "Fetch.continueRequest",
            {"requestId": request_id},
            label="worker-bootstrap-prearmed:Fetch.continueRequest",
        )
        bootstrap.fetch_released = True
        bootstrap.fetch_release_after_setup_envelopes = True
        child_state = self._state(bootstrap.source.session_path)
        if child_state.phase in {
            "awaiting-bootstrap-policy",
            "awaiting-bootstrap-release",
        }:
            self._resume_instrumented_child(bootstrap.source)

    def _handle_root_event(self, method: str, event: Mapping[str, Any]) -> None:
        self._handle_forwarded(self.root_source, method, event)

    def _target_lifecycle_event(self, method: str, event: Mapping[str, Any]) -> None:
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
            if state is None or info.get("type") != state.target_type or state.phase == "destroyed":
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
                    if candidate.source.target_id == target_id and candidate.phase == "detached"
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
            request = event.get("request")
            request_id = event.get("requestId")
            url = request.get("url") if isinstance(request, Mapping) else None
            raise CdpTargetIntegrityError(
                f"CDP {source.target_type} target emitted {method} for "
                f"request {request_id!r} ({url!r}) during {state.phase}"
            )
        if method == "Network.requestServedFromCache":
            raise CdpTargetIntegrityError(
                "CDP served a request from cache despite the disabled-cache policy"
            )
        event_source = source
        advance_bootstraps = False
        bootstrap_fetch: _BootstrapFetchDecision | None = None
        if method == "Network.requestWillBeSent":
            request_id = event.get("requestId")
            if not isinstance(request_id, str) or not request_id:
                raise CdpTargetIntegrityError("CDP request event omitted its request ID")
            redirected = event.get("redirectResponse") is not None
            local = [
                item for item in self._active_requests.get(request_id, ()) if item.source == source
            ]
            migrated = None
            if redirected and not local:
                migrated = self._resolve_active_request(
                    source, request_id, allow_target_migration=True
                )
            canonical_source = migrated.source if migrated is not None else source
            active = _ActiveRequest(
                source=canonical_source,
                request_id=request_id,
                loader_id=event.get("loaderId") if isinstance(event.get("loaderId"), str) else None,
                frame_id=event.get("frameId") if isinstance(event.get("frameId"), str) else None,
                resource_type=event.get("type") if isinstance(event.get("type"), str) else None,
                method=(
                    event.get("request", {}).get("method")
                    if isinstance(event.get("request"), Mapping)
                    and isinstance(event.get("request", {}).get("method"), str)
                    else None
                ),
                url=(
                    event.get("request", {}).get("url")
                    if isinstance(event.get("request"), Mapping)
                    and isinstance(event.get("request", {}).get("url"), str)
                    else None
                ),
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
            advance_bootstraps = True
        elif method in {"Network.loadingFinished", "Network.loadingFailed"}:
            request_id = event.get("requestId")
            if not isinstance(request_id, str):
                raise CdpTargetIntegrityError("CDP loading terminal event omitted its request ID")
            bootstrap = self._guarded_shared_bootstrap_for_target_id(request_id)
            if bootstrap is not None and bootstrap.fetch_policy_outcome is None:
                raise CdpTargetIntegrityError(
                    "worker-bootstrap request terminated before its exact Fetch policy"
                )
            if (
                bootstrap is not None
                and bootstrap.fetch_network_id == request_id
                and bootstrap.fetch_policy_outcome == "continue"
                and not bootstrap.fetch_released
            ):
                raise CdpTargetIntegrityError(
                    "worker-bootstrap request terminated before its held continue was released"
                )
            active = self._resolve_active_request(source, request_id, allow_target_migration=True)
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
                    source, request_id, allow_target_migration=True
                )
                if active is None and method == "Network.requestWillBeSentExtraInfo":
                    active = self._resolve_worker_subresource_extra_info(source, request_id)
                if active is not None:
                    event_source = active.source
                elif self._active_requests.get(request_id):
                    raise CdpTargetIntegrityError(
                        "CDP network event collided with an unrelated active request identity"
                    )
        elif method == "Fetch.requestPaused":
            bootstrap_fetch = self._register_bootstrap_fetch(source, event)
        self._on_event(event_source, method, event)
        if bootstrap_fetch is not None and not bootstrap_fetch.decided:
            raise CdpTargetIntegrityError(
                "worker-bootstrap Fetch policy callback returned without a decision"
            )
        if advance_bootstraps:
            # The evidence consumer must observe the owning Script occurrence
            # before resuming code in the target that it created.
            self._advance_pending_worker_bootstraps()

    def _bind_bootstrap_owner(
        self,
        target_id: str,
        bootstrap: _WorkerBootstrap,
        *,
        shared: bool,
    ) -> None:
        if bootstrap.owner_source is not None:
            return
        candidates = list(self._active_requests.get(target_id, ()))
        exact = [
            item
            for item in candidates
            if item.resource_type == "Script"
            and item.method == "GET"
            and item.url == bootstrap.url
            and (
                shared
                or (
                    item.source.session_path == bootstrap.parent_route
                    and (
                        bootstrap.parent_frame_id is None
                        or item.frame_id == bootstrap.parent_frame_id
                    )
                )
            )
        ]
        if len(exact) > 1:
            raise CdpTargetIntegrityError("worker bootstrap request ownership is ambiguous")
        if not exact:
            if candidates:
                raise CdpTargetIntegrityError(
                    "worker bootstrap request identity, URL, type, method, route, or "
                    "parent frame does not match"
                )
            return
        claim = (exact[0].source, exact[0].request_id)
        if claim in self._claimed_worker_bootstraps:
            raise CdpTargetIntegrityError("worker bootstrap request occurrence was already claimed")
        self._claimed_worker_bootstraps.add(claim)
        bootstrap.owner_source = exact[0].source
        if bootstrap.source is not None:
            self._pending_worker_sources.discard(bootstrap.source)
            state = self._states.get(bootstrap.source.session_path)
            if state is not None and state.phase == "awaiting-owner":
                self._resume_instrumented_child(bootstrap.source)

    def _advance_pending_worker_bootstraps(self) -> None:
        for source in tuple(self._pending_worker_sources):
            bootstrap = self._worker_bootstraps[source]
            self._bind_bootstrap_owner(source.target_id, bootstrap, shared=False)
        for target_id, bootstrap in tuple(self._guarded_shared_workers.items()):
            if bootstrap.source is not None or bootstrap.attach_requested:
                continue
            self._bind_bootstrap_owner(target_id, bootstrap, shared=True)
            if bootstrap.owner_source is not None:
                self._request_guarded_shared_worker_attach(target_id, bootstrap)

    def _request_guarded_shared_worker_attach(
        self,
        target_id: str,
        bootstrap: _WorkerBootstrap,
    ) -> None:
        if bootstrap.attach_requested:
            raise CdpTargetIntegrityError(
                "shared-worker page adoption was requested more than once"
            )
        bootstrap.attach_requested = True
        result = self._root_send(
            "Target.attachToTarget",
            {"targetId": target_id, "flatten": False},
        )
        session_id = result.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise CdpTargetIntegrityError(
                "shared-worker page adoption returned no session identity"
            )
        bootstrap.attach_command_session_id = session_id
        bootstrap.attach_command_resolved = True
        if bootstrap.attach_session_id is not None and bootstrap.attach_session_id != session_id:
            raise CdpTargetIntegrityError(
                "shared-worker adoption response changed its page session identity"
            )
        if bootstrap.source is not None:
            state = self._state(bootstrap.source.session_path)
            if state.phase == "awaiting-adoption-ack":
                self._resume_instrumented_child(bootstrap.source)
        self.raise_if_failed()

    def _resume_instrumented_child(self, source: CdpTargetSource) -> None:
        state = self._state(source.session_path)
        if (
            state.phase
            not in {
                "configuring",
                "awaiting-adoption-ack",
                "awaiting-bootstrap-policy",
                "awaiting-bootstrap-release",
                "awaiting-owner",
            }
            or state.setup_pending
        ):
            raise CdpTargetIntegrityError(
                "CDP child resume was attempted before setup and ownership converged"
            )
        bootstrap = self._worker_bootstraps.get(source)
        if source.target_type in {"worker", "shared_worker"} and (
            bootstrap is None or bootstrap.owner_source is None
        ):
            state.phase = "awaiting-owner"
            return
        if source.target_type == "shared_worker" and (
            bootstrap is None
            or not bootstrap.attach_command_resolved
            or bootstrap.attach_session_id != bootstrap.attach_command_session_id
        ):
            state.phase = "awaiting-adoption-ack"
            return
        if source.target_type == "shared_worker":
            if bootstrap is None or bootstrap.fetch_policy_outcome is None:
                state.phase = "awaiting-bootstrap-policy"
                return
            if bootstrap.fetch_policy_outcome == "fail":
                state.phase = "awaiting-bootstrap-failure"
                return
            if not bootstrap.fetch_released:
                state.phase = "awaiting-bootstrap-release"
                return
        state.phase = "resuming"
        self._queue_command(
            source,
            "Runtime.runIfWaitingForDebugger",
            {},
            label=f"{state.target_type}:Runtime.runIfWaitingForDebugger",
            on_success=lambda result, child=source: self._resume_ack(child, result),
        )

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
        ):
            raise CdpTargetIntegrityError("related CDP target attachment is malformed")
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
        guarded = self._guarded_shared_workers.get(target_id)
        if target_type == "shared_worker":
            if (
                parent_route
                or waiting is not False
                or guarded is None
                or not guarded.attach_requested
                or guarded.source is not None
                or target_info.get("url") != guarded.url
                or target_info.get("browserContextId") != guarded.browser_context_id
            ):
                raise CdpTargetIntegrityError(
                    "shared-worker page attachment was not exactly preauthorised by its "
                    "browser guard"
                )
            if (
                guarded.attach_command_session_id is not None
                and guarded.attach_command_session_id != session_id
            ):
                raise CdpTargetIntegrityError(
                    "shared-worker adoption returned a different page session"
                )
        elif waiting is not True:
            raise CdpTargetIntegrityError(
                "related CDP target attachment was not held for instrumentation"
            )
        if target_type == "iframe":
            browser_context_id = target_info.get("browserContextId")
            if (
                browser_context_id is not None
                and browser_context_id != self.root_browser_context_id
            ):
                raise CdpTargetIntegrityError("iframe target named a foreign browser context")
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
        bootstrap: _WorkerBootstrap | None = None
        if target_type == "shared_worker":
            assert guarded is not None
            guarded.source = source
            guarded.attach_session_id = session_id
            self._worker_bootstraps[source] = guarded
            bootstrap = guarded
        elif target_type == "worker" and not self._shutting_down:
            url = target_info.get("url")
            browser_context_id = target_info.get("browserContextId")
            if (
                not isinstance(url, str)
                or not url
                or not isinstance(browser_context_id, str)
                or browser_context_id != self.root_browser_context_id
            ):
                raise CdpTargetIntegrityError(
                    "dedicated-worker target omitted its URL or root context"
                )
            bootstrap = _WorkerBootstrap(
                source=source,
                url=url,
                parent_route=parent_route,
                parent_frame_id=parent_frame_id,
                browser_context_id=browser_context_id,
            )
            self._worker_bootstraps[source] = bootstrap
            self._pending_worker_sources.add(source)
            self._bind_bootstrap_owner(target_id, bootstrap, shared=False)
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
                on_success=lambda result, child=source: self._shutdown_resume_ack(child, result),
            )
            return
        state = _TargetState(source, target_type, "configuring")
        setup = list(_BASE_SETUP_COMMANDS)
        if target_type in _PAGE_TARGET_TYPES:
            setup.append(_egress_new_document_command(target_type))
        if target_type in {"iframe", "shared_worker"}:
            setup.append(_FETCH_SETUP_COMMAND)
        state.setup_pending = {method for method, _params in setup}
        self._states[route] = state
        self._target_routes[target_id] = route
        self._session_routes[session_id] = route
        self._notify_target_activity(source, "target-attached")
        if target_type == "shared_worker" and bootstrap is not None:
            if (
                bootstrap.initial_setup_envelopes_expected
                or bootstrap.initial_setup_envelopes_issued
            ):
                raise CdpTargetIntegrityError(
                    "worker-bootstrap initial setup envelopes were reused"
                )
            bootstrap.initial_setup_envelopes_expected = len(setup)
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
            # A nested target or transport event may be dispatched re-entrantly
            # while the outer send is in progress.  Never count that envelope,
            # or release a held bootstrap, after such an event failed the router.
            self.raise_if_failed()
            if target_type == "shared_worker" and bootstrap is not None:
                bootstrap.initial_setup_envelopes_issued += 1
        if target_type == "shared_worker" and bootstrap is not None:
            self._maybe_release_bootstrap_continue(bootstrap)

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
            bootstrap = self._worker_bootstraps.get(source)
            if bootstrap is not None and (
                info.get("url") != bootstrap.url
                or info.get("browserContextId") != bootstrap.browser_context_id
            ):
                raise CdpTargetIntegrityError("CDP worker setup changed its URL or browser context")
            if state.target_type == "iframe":
                browser_context_id = info.get("browserContextId")
                if (
                    browser_context_id is not None
                    and browser_context_id != self.root_browser_context_id
                ):
                    raise CdpTargetIntegrityError(
                        "CDP iframe setup named a foreign browser context"
                    )
        elif method == "Page.addScriptToEvaluateOnNewDocument":
            self._validate_page_init_result(result)
        elif method == "Debugger.setInstrumentationBreakpoint":
            breakpoint_id = result.get("breakpointId")
            if not isinstance(breakpoint_id, str) or not breakpoint_id:
                raise CdpTargetIntegrityError(
                    "CDP pre-author instrumentation breakpoint acknowledgement is invalid"
                )
            if state.target_type == "iframe":
                if state.iframe_instrumentation_breakpoint_id is not None:
                    raise CdpTargetIntegrityError(
                        "CDP iframe instrumentation breakpoint acknowledgement is invalid"
                    )
                state.iframe_instrumentation_breakpoint_id = breakpoint_id
            elif state.target_type in _WORKER_TARGET_TYPES:
                if state.worker_instrumentation_breakpoint_id is not None:
                    raise CdpTargetIntegrityError(
                        "CDP worker instrumentation breakpoint acknowledgement is invalid"
                    )
                state.worker_instrumentation_breakpoint_id = breakpoint_id
            else:
                raise CdpTargetIntegrityError(
                    "CDP target cannot use a pre-author instrumentation breakpoint"
                )
        elif method == "Runtime.evaluate:egress-shim":
            self._record_egress_evaluation(source, result)
        elif method == "Runtime.evaluate:popup-guard":
            self._record_popup_guard_evaluation(source, result)
        state.setup_pending.remove(method)
        if state.setup_pending:
            return
        if state.target_type == "iframe":
            if method not in {
                "Debugger.setInstrumentationBreakpoint",
                "Target.setAutoAttach",
                "Target.getTargetInfo",
            }:
                state.setup_pending.add("Debugger.setInstrumentationBreakpoint")
                self._queue_command(
                    source,
                    *_IFRAME_INSTRUMENTATION_COMMAND,
                    label="iframe:Debugger.setInstrumentationBreakpoint",
                    on_success=lambda result, child=source: self._setup_ack(
                        child, "Debugger.setInstrumentationBreakpoint", result
                    ),
                )
                return
            if method == "Debugger.setInstrumentationBreakpoint":
                state.setup_pending.add("Target.setAutoAttach")
                self._queue_command(
                    source,
                    *_AUTO_ATTACH_COMMAND,
                    label="iframe:Target.setAutoAttach",
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
                    label="iframe:Target.getTargetInfo",
                    on_success=lambda result, child=source: self._setup_ack(
                        child, "Target.getTargetInfo", result
                    ),
                )
                return
            self._resume_instrumented_child(source)
            return
        if state.target_type in _WORKER_TARGET_TYPES:
            if method not in {
                "Debugger.setInstrumentationBreakpoint",
                "Target.setAutoAttach",
                "Target.getTargetInfo",
            }:
                state.setup_pending.add("Debugger.setInstrumentationBreakpoint")
                self._queue_command(
                    source,
                    *_WORKER_INSTRUMENTATION_COMMAND,
                    label=f"{state.target_type}:Debugger.setInstrumentationBreakpoint",
                    on_success=lambda result, child=source: self._setup_ack(
                        child, "Debugger.setInstrumentationBreakpoint", result
                    ),
                )
                return
            if method == "Debugger.setInstrumentationBreakpoint":
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
            self._resume_instrumented_child(source)
            return
        if method not in {
            "Runtime.evaluate:egress-shim",
            "Runtime.evaluate:popup-guard",
            "Target.setAutoAttach",
            "Target.getTargetInfo",
        }:
            state.setup_pending.add("Runtime.evaluate:egress-shim")
            self._queue_command(
                source,
                *_egress_evaluate_command(state.target_type),
                label=f"{state.target_type}:Runtime.evaluate:egress-shim",
                on_success=lambda result, child=source: self._setup_ack(
                    child, "Runtime.evaluate:egress-shim", result
                ),
            )
            return
        if method == "Runtime.evaluate:egress-shim" and source.target_type in _PAGE_TARGET_TYPES:
            state.setup_pending.add("Runtime.evaluate:popup-guard")
            self._queue_command(
                source,
                *_popup_guard_evaluate_command(),
                label=f"{state.target_type}:Runtime.evaluate:popup-guard",
                on_success=lambda result, child=source: self._setup_ack(
                    child, "Runtime.evaluate:popup-guard", result
                ),
            )
            return
        if method in {"Runtime.evaluate:egress-shim", "Runtime.evaluate:popup-guard"}:
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
        self._resume_instrumented_child(source)

    def _handle_iframe_context_event(
        self,
        source: CdpTargetSource,
        method: str,
        event: Mapping[str, Any],
    ) -> None:
        """Track the one default realm used by the iframe pre-author barrier."""

        state = self._state(source.session_path)
        if source.target_type != "iframe":
            return
        if state.phase == "ready":
            # The pre-document script registered during setup protects later
            # document realms.  This barrier receipts the initial runnable realm.
            return
        if state.phase not in {"configuring", "resuming"}:
            raise CdpTargetIntegrityError(
                "CDP iframe execution-context event arrived outside prearm"
            )
        if method == "Runtime.executionContextCreated":
            context = event.get("context")
            if not isinstance(context, Mapping):
                raise CdpTargetIntegrityError("CDP iframe execution context is malformed")
            context_id = context.get("id")
            unique_context_id = context.get("uniqueId")
            aux_data = context.get("auxData")
            if (
                type(context_id) is not int
                or context_id < 0
                or not isinstance(unique_context_id, str)
                or not unique_context_id
                or not isinstance(aux_data, Mapping)
                or type(aux_data.get("isDefault")) is not bool
                or not isinstance(aux_data.get("type"), str)
                or not aux_data.get("type")
                or not isinstance(aux_data.get("frameId"), str)
                or aux_data.get("frameId") != source.target_id
            ):
                raise CdpTargetIntegrityError("CDP iframe execution context is malformed")
            is_default = aux_data["isDefault"]
            context_type = aux_data["type"]
            if (is_default is True) != (context_type == "default"):
                raise CdpTargetIntegrityError(
                    "CDP iframe default execution-context identity is inconsistent"
                )
            if not is_default:
                return
            if (
                state.iframe_default_context_id is not None
                or state.iframe_default_context_unique_id is not None
            ):
                raise CdpTargetIntegrityError(
                    "CDP iframe reported more than one default execution context during prearm"
                )
            state.iframe_default_context_id = context_id
            state.iframe_default_context_unique_id = unique_context_id
            self._maybe_trigger_iframe_synthetic(source)
            return
        if method == "Runtime.executionContextDestroyed":
            context_id = event.get("executionContextId")
            unique_context_id = event.get("executionContextUniqueId")
            if (
                type(context_id) is not int
                or context_id < 0
                or not isinstance(unique_context_id, str)
                or not unique_context_id
            ):
                raise CdpTargetIntegrityError(
                    "CDP iframe execution-context destruction is malformed"
                )
            selected_by_id = context_id == state.iframe_default_context_id
            selected_by_unique_id = unique_context_id == state.iframe_default_context_unique_id
            if selected_by_id != selected_by_unique_id:
                raise CdpTargetIntegrityError(
                    "CDP iframe execution-context destruction changed identity"
                )
            if selected_by_id:
                raise CdpTargetIntegrityError(
                    "CDP iframe default execution context was destroyed before prearm completed"
                )
            return
        if method != "Runtime.executionContextsCleared" or event:
            raise CdpTargetIntegrityError("CDP iframe execution-context event is malformed")
        if (
            state.iframe_default_context_id is None
            and state.iframe_default_context_unique_id is None
            and not state.iframe_synthetic_issued
            and not state.iframe_pause_seen
            and not state.iframe_installation_received
        ):
            # Chromium clears the provisional empty-document realm while the
            # held OOPIF commits.  No selected realm or barrier obligation has
            # been invalidated, and the instrumentation breakpoint remains armed.
            return
        raise CdpTargetIntegrityError(
            "CDP iframe execution contexts were cleared before prearm completed"
        )

    def _handle_worker_script_parsed(
        self,
        source: CdpTargetSource,
        event: Mapping[str, Any],
    ) -> None:
        """Bind the worker's first runnable script to its registered bootstrap URL."""

        if source.target_type not in _WORKER_TARGET_TYPES:
            return
        state = self._state(source.session_path)
        if state.phase in {"ready", "closing", "detached", "destroyed"}:
            # Once the exact bootstrap barrier has completed, later eval,
            # import, or debugger bookkeeping scripts are unrelated to prearm.
            # Do not retain their identities or reinterpret a repeated URL as
            # a second bootstrap script.
            return
        bootstrap = self._worker_bootstraps.get(source)
        script_id = event.get("scriptId")
        url = event.get("url")
        start_line = event.get("startLine")
        start_column = event.get("startColumn")
        if (
            bootstrap is None
            or not isinstance(script_id, str)
            or not script_id
            or not isinstance(url, str)
            or type(start_line) is not int
            or start_line < 0
            or type(start_column) is not int
            or start_column < 0
            or script_id in state.worker_parsed_script_urls
        ):
            raise CdpTargetIntegrityError("CDP worker parsed-script identity is invalid or reused")
        state.worker_parsed_script_urls[script_id] = url
        if url != bootstrap.url:
            return
        if (
            state.phase != "resuming"
            or state.worker_bootstrap_script_id is not None
            or start_line != 0
            or start_column != 0
        ):
            raise CdpTargetIntegrityError(
                "CDP worker bootstrap script was duplicated or parsed outside its exact origin"
            )
        state.worker_bootstrap_script_id = script_id

    def _handle_worker_debugger_paused(
        self,
        source: CdpTargetSource,
        event: Mapping[str, Any],
    ) -> None:
        """Install the worker egress shim in its fully initialised first-script realm."""

        state = self._state(source.session_path)
        bootstrap = self._worker_bootstraps.get(source)
        instrumentation_id = state.worker_instrumentation_breakpoint_id
        call_frames = event.get("callFrames")
        hit_breakpoints = event.get("hitBreakpoints", [])
        instrumentation_data = event.get("data")
        if (
            source.target_type not in _WORKER_TARGET_TYPES
            or bootstrap is None
            or state.phase != "resuming"
            or not isinstance(instrumentation_id, str)
            or not instrumentation_id
            or not isinstance(state.worker_bootstrap_script_id, str)
            or state.worker_pause_seen
            or state.worker_debugger_paused
            or state.worker_egress_evaluation_issued
            or event.get("reason") != "instrumentation"
            or not isinstance(call_frames, list)
            or not call_frames
            or not isinstance(hit_breakpoints, list)
            or hit_breakpoints not in ([], [instrumentation_id])
            or not isinstance(instrumentation_data, Mapping)
            or set(instrumentation_data) != {"scriptId", "url"}
            or instrumentation_data.get("scriptId") != state.worker_bootstrap_script_id
            or instrumentation_data.get("url") != bootstrap.url
        ):
            raise CdpTargetIntegrityError("CDP worker first-script debugger pause is invalid")
        first_frame = call_frames[0]
        location = first_frame.get("location") if isinstance(first_frame, Mapping) else None
        call_frame_id = first_frame.get("callFrameId") if isinstance(first_frame, Mapping) else None
        frame_url = first_frame.get("url") if isinstance(first_frame, Mapping) else None
        function_name = (
            first_frame.get("functionName") if isinstance(first_frame, Mapping) else None
        )
        function_location = (
            first_frame.get("functionLocation") if isinstance(first_frame, Mapping) else None
        )
        if (
            not isinstance(call_frame_id, str)
            or not call_frame_id
            or not isinstance(frame_url, str)
            or (frame_url and frame_url != bootstrap.url)
            or not isinstance(function_name, str)
            or not isinstance(location, Mapping)
            or location.get("scriptId") != state.worker_bootstrap_script_id
            or type(location.get("lineNumber")) is not int
            or location.get("lineNumber") < 0
            or type(location.get("columnNumber")) is not int
            or location.get("columnNumber") < 0
            or not isinstance(function_location, Mapping)
            or function_location.get("scriptId") != state.worker_bootstrap_script_id
            or type(function_location.get("lineNumber")) is not int
            or function_location.get("lineNumber") != 0
            or type(function_location.get("columnNumber")) is not int
            or function_location.get("columnNumber") != 0
        ):
            raise CdpTargetIntegrityError(
                "CDP worker first-script call-frame identity or location is invalid"
            )
        state.worker_pause_seen = True
        state.worker_debugger_paused = True
        state.worker_pause_call_frame_id = call_frame_id
        state.worker_egress_evaluation_issued = True
        self._queue_command(
            source,
            *_worker_egress_evaluate_command(source.target_type, call_frame_id),
            label=f"{source.target_type}:Debugger.evaluateOnCallFrame:egress-shim",
            on_success=lambda result, child=source: self._worker_egress_evaluation_ack(
                child, result
            ),
        )

    def _worker_egress_evaluation_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        breakpoint_id = state.worker_instrumentation_breakpoint_id
        if (
            source.target_type not in _WORKER_TARGET_TYPES
            or state.phase != "resuming"
            or not state.worker_pause_seen
            or not state.worker_debugger_paused
            or not state.worker_egress_evaluation_issued
            or state.worker_egress_evaluation_acknowledged
            or not isinstance(state.worker_pause_call_frame_id, str)
            or not isinstance(breakpoint_id, str)
            or not breakpoint_id
        ):
            raise CdpTargetIntegrityError(
                "CDP worker first-script egress evaluation acknowledgement is invalid"
            )
        self._record_egress_evaluation(
            source,
            result,
            expected_already_installed=False,
        )
        state.worker_egress_evaluation_acknowledged = True
        self._queue_command(
            source,
            "Debugger.removeBreakpoint",
            {"breakpointId": breakpoint_id},
            label=f"{source.target_type}:Debugger.removeBreakpoint:instrumentation",
            on_success=lambda response, child=source: self._worker_instrumentation_remove_ack(
                child, response
            ),
        )

    def _worker_instrumentation_remove_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if (
            source.target_type not in _WORKER_TARGET_TYPES
            or state.phase != "resuming"
            or not state.worker_debugger_paused
            or not state.worker_egress_evaluation_acknowledged
            or source not in self._egress_shim_receipts
            or state.worker_instrumentation_removed
            or result != {}
        ):
            raise CdpTargetIntegrityError(
                "CDP worker instrumentation-breakpoint removal is invalid"
            )
        state.worker_instrumentation_removed = True
        self._queue_command(
            source,
            "Debugger.resume",
            {},
            label=f"{source.target_type}:Debugger.resume:first-script-installation",
            on_success=lambda response, child=source: self._worker_debugger_resume_ack(
                child, response
            ),
        )

    def _worker_debugger_resume_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if (
            source.target_type not in _WORKER_TARGET_TYPES
            or state.phase != "resuming"
            or not state.worker_debugger_paused
            or not state.worker_instrumentation_removed
            or state.worker_debugger_resume_acknowledged
            or result != {}
        ):
            raise CdpTargetIntegrityError("CDP worker first-script debugger resume is invalid")
        state.worker_debugger_paused = False
        state.worker_debugger_resume_acknowledged = True
        self._maybe_finish_worker_prearm(source)

    def _handle_debugger_paused(
        self,
        source: CdpTargetSource,
        event: Mapping[str, Any],
    ) -> None:
        """Turn the first iframe instrumentation pause into an exact conditional barrier."""

        if source.target_type in _WORKER_TARGET_TYPES:
            self._handle_worker_debugger_paused(source, event)
            return

        state = self._state(source.session_path)
        instrumentation_id = state.iframe_instrumentation_breakpoint_id
        call_frames = event.get("callFrames")
        hit_breakpoints = event.get("hitBreakpoints", [])
        if (
            source.target_type != "iframe"
            or state.phase != "resuming"
            or not isinstance(instrumentation_id, str)
            or not instrumentation_id
            or state.iframe_pause_seen
            or state.iframe_debugger_paused
            or event.get("reason") != "instrumentation"
            or not isinstance(call_frames, list)
            or not call_frames
            or not isinstance(hit_breakpoints, list)
            or any(not isinstance(item, str) or not item for item in hit_breakpoints)
            or (hit_breakpoints and instrumentation_id not in hit_breakpoints)
        ):
            raise CdpTargetIntegrityError("CDP iframe debugger pause is invalid")
        first_frame = call_frames[0]
        location = first_frame.get("location") if isinstance(first_frame, Mapping) else None
        if not isinstance(location, Mapping):
            raise CdpTargetIntegrityError("CDP iframe debugger call-frame location is malformed")
        exact_location = {
            "scriptId": location.get("scriptId"),
            "lineNumber": location.get("lineNumber"),
            "columnNumber": location.get("columnNumber"),
        }
        if (
            not isinstance(exact_location["scriptId"], str)
            or not exact_location["scriptId"]
            or type(exact_location["lineNumber"]) is not int
            or exact_location["lineNumber"] < 0
            or type(exact_location["columnNumber"]) is not int
            or exact_location["columnNumber"] < 0
        ):
            raise CdpTargetIntegrityError("CDP iframe debugger call-frame location is malformed")
        state.iframe_pause_seen = True
        state.iframe_debugger_paused = True
        state.iframe_pause_location = exact_location
        self._queue_command(
            source,
            "Debugger.setBreakpoint",
            {
                "location": dict(exact_location),
                "condition": _iframe_breakpoint_condition(),
            },
            label="iframe:Debugger.setBreakpoint:pre-author-installation",
            on_success=lambda result, child=source: self._iframe_regular_breakpoint_ack(
                child, result
            ),
        )

    def _iframe_regular_breakpoint_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        breakpoint_id = result.get("breakpointId")
        actual_location = result.get("actualLocation")
        expected_location = state.iframe_pause_location
        if (
            state.phase != "resuming"
            or not state.iframe_debugger_paused
            or not isinstance(breakpoint_id, str)
            or not breakpoint_id
            or breakpoint_id == state.iframe_instrumentation_breakpoint_id
            or state.iframe_regular_breakpoint_id is not None
            or not isinstance(actual_location, Mapping)
            or not isinstance(expected_location, Mapping)
            or any(
                actual_location.get(field) != expected_location[field]
                for field in ("scriptId", "lineNumber", "columnNumber")
            )
        ):
            raise CdpTargetIntegrityError(
                "CDP iframe exact conditional breakpoint acknowledgement is invalid"
            )
        state.iframe_regular_breakpoint_id = breakpoint_id
        self._queue_command(
            source,
            "Debugger.removeBreakpoint",
            {"breakpointId": state.iframe_instrumentation_breakpoint_id},
            label="iframe:Debugger.removeBreakpoint:instrumentation",
            on_success=lambda response, child=source: self._iframe_instrumentation_remove_ack(
                child, response
            ),
        )

    def _iframe_instrumentation_remove_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if (
            state.phase != "resuming"
            or not state.iframe_debugger_paused
            or state.iframe_instrumentation_removed
            or result != {}
        ):
            raise CdpTargetIntegrityError(
                "CDP iframe instrumentation-breakpoint removal is invalid"
            )
        state.iframe_instrumentation_removed = True
        self._queue_command(
            source,
            "Debugger.resume",
            {},
            label="iframe:Debugger.resume:conditional-installation",
            on_success=lambda response, child=source: self._iframe_debugger_resume_ack(
                child, response
            ),
        )

    def _iframe_debugger_resume_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if (
            state.phase != "resuming"
            or not state.iframe_debugger_paused
            or not state.iframe_instrumentation_removed
            or state.iframe_debugger_resume_acknowledged
            or result != {}
        ):
            raise CdpTargetIntegrityError("CDP iframe debugger resume is invalid")
        state.iframe_debugger_paused = False
        state.iframe_debugger_resume_acknowledged = True
        self._maybe_remove_iframe_regular_breakpoint(source)
        self._maybe_trigger_iframe_synthetic(source)
        self._maybe_finish_iframe_prearm(source)

    def _maybe_trigger_iframe_synthetic(self, source: CdpTargetSource) -> None:
        state = self._state(source.session_path)
        unique_context_id = state.iframe_default_context_unique_id
        if (
            state.target_type != "iframe"
            or state.phase != "resuming"
            or not state.iframe_initial_resume_acknowledged
            or not isinstance(unique_context_id, str)
            or state.iframe_synthetic_issued
            or state.iframe_debugger_paused
        ):
            return
        state.iframe_synthetic_issued = True
        self._queue_command(
            source,
            *_iframe_synthetic_trigger_command(unique_context_id),
            label="iframe:Runtime.evaluate:pre-author-trigger",
            on_success=lambda result, child=source: self._iframe_synthetic_ack(child, result),
        )

    def _iframe_synthetic_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        remote = result.get("result")
        if (
            state.phase != "resuming"
            or not state.iframe_synthetic_issued
            or state.iframe_synthetic_completed
            or not state.iframe_pause_seen
            or state.iframe_debugger_paused
            or result.get("exceptionDetails") is not None
            or not isinstance(remote, Mapping)
            or remote.get("type") != "boolean"
            or remote.get("value") is not True
        ):
            raise CdpTargetIntegrityError("CDP iframe synthetic barrier result is invalid")
        state.iframe_synthetic_completed = True
        self._maybe_finish_iframe_prearm(source)

    def _maybe_remove_iframe_regular_breakpoint(self, source: CdpTargetSource) -> None:
        state = self._state(source.session_path)
        breakpoint_id = state.iframe_regular_breakpoint_id
        if (
            state.target_type != "iframe"
            or state.phase != "resuming"
            or not state.iframe_installation_received
            or not state.iframe_debugger_resume_acknowledged
            or not isinstance(breakpoint_id, str)
            or state.iframe_regular_remove_issued
        ):
            return
        state.iframe_regular_remove_issued = True
        self._queue_command(
            source,
            "Debugger.removeBreakpoint",
            {"breakpointId": breakpoint_id},
            label="iframe:Debugger.removeBreakpoint:conditional-installation",
            on_success=lambda result, child=source: self._iframe_regular_remove_ack(child, result),
        )

    def _iframe_regular_remove_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if (
            state.phase != "resuming"
            or not state.iframe_regular_remove_issued
            or state.iframe_regular_removed
            or result != {}
        ):
            raise CdpTargetIntegrityError("CDP iframe conditional-breakpoint removal is invalid")
        state.iframe_regular_removed = True
        self._maybe_finish_iframe_prearm(source)

    def _maybe_finish_iframe_prearm(self, source: CdpTargetSource) -> None:
        state = self._state(source.session_path)
        if state.target_type != "iframe" or state.phase != "resuming":
            return
        if all(
            (
                state.iframe_initial_resume_acknowledged,
                state.iframe_default_context_id is not None,
                state.iframe_default_context_unique_id is not None,
                state.iframe_synthetic_completed,
                state.iframe_pause_seen,
                not state.iframe_debugger_paused,
                state.iframe_instrumentation_removed,
                state.iframe_debugger_resume_acknowledged,
                state.iframe_installation_received,
                state.iframe_regular_removed,
                source in self._egress_shim_receipts,
                source in self._popup_guard_receipts,
            )
        ):
            state.phase = "ready"

    def _maybe_finish_worker_prearm(self, source: CdpTargetSource) -> None:
        state = self._state(source.session_path)
        if source.target_type not in _WORKER_TARGET_TYPES or state.phase != "resuming":
            return
        if all(
            (
                isinstance(state.worker_instrumentation_breakpoint_id, str),
                isinstance(state.worker_bootstrap_script_id, str),
                isinstance(state.worker_pause_call_frame_id, str),
                state.worker_initial_resume_acknowledged,
                state.worker_pause_seen,
                not state.worker_debugger_paused,
                state.worker_egress_evaluation_issued,
                state.worker_egress_evaluation_acknowledged,
                state.worker_instrumentation_removed,
                state.worker_debugger_resume_acknowledged,
                source in self._egress_shim_receipts,
            )
        ):
            # Parsed-script identities are needed only to bind the bootstrap
            # pause.  Clearing them makes the completed worker state bounded.
            state.worker_parsed_script_urls.clear()
            state.phase = "ready"

    def _resume_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if state.phase != "resuming" or result != {}:
            raise CdpTargetIntegrityError("CDP child resume acknowledgement is out of sequence")
        if state.target_type == "iframe":
            if state.iframe_initial_resume_acknowledged:
                raise CdpTargetIntegrityError(
                    "CDP iframe initial resume acknowledgement was duplicated"
                )
            state.iframe_initial_resume_acknowledged = True
            self._maybe_trigger_iframe_synthetic(source)
            self._maybe_finish_iframe_prearm(source)
            return
        if state.target_type in _WORKER_TARGET_TYPES:
            if state.worker_initial_resume_acknowledged:
                raise CdpTargetIntegrityError(
                    "CDP worker initial resume acknowledgement was duplicated"
                )
            state.worker_initial_resume_acknowledged = True
            self._maybe_finish_worker_prearm(source)
            return
        state.phase = "ready"

    def _shutdown_resume_ack(
        self,
        source: CdpTargetSource,
        result: Mapping[str, Any],
    ) -> None:
        state = self._state(source.session_path)
        if (
            state.phase != "closing"
            or state.setup_pending != {"Runtime.runIfWaitingForDebugger"}
            or result != {}
        ):
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
        bootstrap = self._worker_bootstraps.get(state.source)
        if (
            state.source.target_type == "shared_worker"
            and bootstrap is not None
            and bootstrap.fetch_policy_outcome is None
            and not self._shutting_down
        ):
            raise CdpTargetIntegrityError(
                "worker target detached before its exact bootstrap Fetch policy"
            )
        if (
            state.source.target_type == "shared_worker"
            and bootstrap is not None
            and bootstrap.fetch_policy_outcome == "continue"
            and not bootstrap.fetch_released
            and not self._aborting
        ):
            raise CdpTargetIntegrityError("worker target detached with a held bootstrap request")
        descendants = [
            child
            for child_route, child in self._states.items()
            if len(child_route) > len(route)
            and child_route[: len(route)] == route
            and child.phase not in {"destroyed", "detached"}
        ]
        route_pending = [key for key in self._pending if key[0][: len(route)] == route]
        if (
            state.phase
            in {
                "configuring",
                "awaiting-adoption-ack",
                "awaiting-bootstrap-failure",
                "awaiting-bootstrap-policy",
                "awaiting-owner",
            }
            and not state.active_request_ids
        ):
            for key in route_pending:
                self._pending.pop(key, None)
            state.setup_pending.clear()
            state.phase = "detached"
            self._pending_worker_sources.discard(state.source)
            self._target_routes.pop(state.source.target_id, None)
            self._session_routes.pop(session_id, None)
            self._notify_target_activity(state.source, "target-detached")
            return
        if self._shutting_down:
            for request_id in tuple(state.active_request_ids):
                self._terminalise_request(
                    state.source,
                    request_id,
                    synthetic_shutdown=not self._aborting,
                )
            for key in route_pending:
                self._pending.pop(key, None)
            state.phase = "detached"
            self._pending_worker_sources.discard(state.source)
            self._target_routes.pop(state.source.target_id, None)
            self._session_routes.pop(session_id, None)
            self._notify_target_activity(state.source, "target-detached")
            return
        if state.phase != "ready" or state.active_request_ids or descendants or route_pending:
            raise CdpTargetIntegrityError(
                "related CDP target detached with setup, request, descendant, or "
                "command work pending"
            )
        state.phase = "detached"
        self._pending_worker_sources.discard(state.source)
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

    def _handle_payload(self, source: CdpTargetSource, payload: Mapping[str, Any]) -> None:
        if "id" in payload:
            command_id = payload["id"]
            if type(command_id) is not int:
                raise CdpTargetIntegrityError("nested CDP response ID is malformed")
            pending = self._pending.pop((source.session_path, command_id), None)
            if pending is None:
                raise CdpTargetIntegrityError("nested CDP response has no pending command")
            if payload.get("error") is not None:
                detail = _sanitised_protocol_error(payload["error"])
                raise CdpTargetIntegrityError(
                    f"nested CDP command {pending.label} failed ({detail})"
                )
            if "result" not in payload or not isinstance(payload["result"], Mapping):
                raise CdpTargetIntegrityError(
                    f"nested CDP command {pending.label} returned malformed data"
                )
            if pending.policy_decision:
                if type(payload["result"]) is not dict:
                    raise CdpTargetIntegrityError(
                        f"nested CDP policy command {pending.label} returned malformed data"
                    )
                if payload["result"] != {}:
                    raise CdpTargetIntegrityError(
                        f"nested CDP policy command {pending.label} did not return an exact "
                        "empty result"
                    )
            result = payload["result"]
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
        elif method in _IFRAME_CONTEXT_EVENTS:
            self._handle_iframe_context_event(source, method, params)
        elif method == "Debugger.scriptParsed":
            self._handle_worker_script_parsed(source, params)
        elif method == "Debugger.paused":
            self._handle_debugger_paused(source, params)
        elif method in _NON_REPLAYABLE_EGRESS_EVENTS:
            self._handle_non_replayable_egress(source, method, params)
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
        self._pending[(parent_route, wrapper_id)] = _PendingCommand(f"transport-forward:{label}")
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
        allow_target_migration: bool,
    ) -> _ActiveRequest | None:
        candidates = list(self._active_requests.get(request_id, ()))
        local = [item for item in candidates if item.source == source]
        if len(local) == 1:
            return local[0]
        if len(local) > 1:
            raise CdpTargetIntegrityError("CDP request identity is ambiguous within one target")
        if not allow_target_migration:
            return None
        if source.target_type == "iframe":
            migrated = [
                item
                for item in candidates
                if item.resource_type == "Document"
                and item.loader_id == request_id
                and item.frame_id == source.target_id
            ]
            label = "OOPIF"
        elif source.target_type in {"worker", "shared_worker"}:
            bootstrap = self._worker_bootstraps.get(source)
            migrated = [
                item
                for item in candidates
                if bootstrap is not None
                and bootstrap.owner_source is not None
                and item.source == bootstrap.owner_source
                and item.request_id == source.target_id
                and item.resource_type == "Script"
                and item.method == "GET"
            ]
            label = "worker bootstrap"
        else:
            return None
        if len(migrated) > 1:
            raise CdpTargetIntegrityError(f"{label} request migration is ambiguous")
        return migrated[0] if migrated else None

    def _resolve_worker_subresource_extra_info(
        self,
        source: CdpTargetSource,
        request_id: str,
    ) -> _ActiveRequest | None:
        """Bind Chromium's owner-routed worker request-header evidence.

        Chromium 143 reports a worker subresource's primary Network events on
        the worker target, while ``requestWillBeSentExtraInfo`` is delivered
        on the exact page or OOPIF session that created that worker.  The
        ExtraInfo event carries no URL, loader, frame, or target identity, so
        it is migrated only when one live worker occurrence with the same raw
        request ID has that exact bootstrap owner.  Cross-owner or duplicate
        candidates remain fail-closed.
        """

        candidates: list[_ActiveRequest] = []
        for active in self._active_requests.get(request_id, ()):
            if active.source.target_type not in {"worker", "shared_worker"}:
                continue
            bootstrap = self._worker_bootstraps.get(active.source)
            if bootstrap is not None and bootstrap.owner_source == source:
                candidates.append(active)
        if len(candidates) > 1:
            raise CdpTargetIntegrityError("worker subresource ExtraInfo migration is ambiguous")
        return candidates[0] if candidates else None

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
        active = self._resolve_active_request(source, request_id, allow_target_migration=False)
        if active is None:
            return
        self._remove_active(active)
        if synthetic_shutdown:
            self._on_event(
                active.source,
                "Network.loadingFailed",
                {"requestId": request_id, "canceled": True, "qcsdShutdown": True},
            )


@dataclass
class _PopupTabTripwire:
    """Browser-scope lifecycle of one synchronously rejected popup tab."""

    session_id: str
    target_id: str
    close_requested: bool = False
    close_acknowledged: bool = False
    detached: bool = False
    destroyed: bool = False


class BrowserSharedWorkerGuard:
    """Guard shared workers and tripwire root-context popup tabs.

    Playwright's public browser CDP session exposes flattened attachment events
    but cannot address those child sessions.  The flattened session is used
    only as a debugger hold and lifecycle guardian.  The page router performs
    a separately validated non-flat adoption, configures the target, and is the
    sole component that resumes it. Browser-level ``tab`` auto-attachment
    additionally closes and receipts any root-context popup before its paused
    page is resumed. This is a post-creation tripwire: packet-level tests prove
    that tab creation itself can perform I/O before the attachment event.
    """

    def __init__(
        self,
        session: _CdpSession,
        router: RecursiveCdpTargetRouter,
    ) -> None:
        self._session = session
        self._router = router
        self._started = False
        self._shutting_down = False
        self._aborting = False
        self._finished = False
        self._page_discovery_started = False
        self._root_tab_session_id: str | None = None
        self._root_tab_target_id: str | None = None
        self._root_tab_detached = False
        self._popup_tabs: dict[str, _PopupTabTripwire] = {}
        self._popup_target_by_session: dict[str, str] = {}

    def start(self) -> None:
        """Install shared-worker holds and popup-tab tripwires before navigation."""

        if self._started:
            raise CdpTargetIntegrityError("browser shared-worker guard started more than once")
        self._router.register_shared_worker_guard()
        self._session.on("Target.attachedToTarget", self._dispatch_attached)
        self._session.on("Target.detachedFromTarget", self._dispatch_detached)
        self._session.on("Inspector.targetCrashed", self._dispatch_crashed)
        self._session.on("Target.targetCrashed", self._dispatch_crashed)
        self._session.on(
            "Target.targetCreated",
            lambda event: self._dispatch_browser_target("Target.targetCreated", event),
        )
        self._session.on(
            "Target.targetInfoChanged",
            lambda event: self._dispatch_browser_target("Target.targetInfoChanged", event),
        )
        self._session.on("Target.targetDestroyed", self._dispatch_target_destroyed)
        self._started = True
        self._send(*_PAGE_DISCOVERY_COMMAND)
        self._page_discovery_started = True
        self._send(*_SHARED_WORKER_GUARD_COMMAND)
        barrier = self._send(*_SHARED_WORKER_GUARD_BARRIER)
        infos = barrier.get("targetInfos")
        if not isinstance(infos, list) or not all(isinstance(info, Mapping) for info in infos):
            raise CdpTargetIntegrityError(
                "browser shared-worker guard barrier returned malformed targets"
            )
        root = self._router.root_source
        matching_roots = [
            info
            for info in infos
            if info.get("targetId") == root.target_id
            and info.get("type") == "page"
            and info.get("browserContextId") == self._router.root_browser_context_id
        ]
        if len(matching_roots) != 1:
            raise CdpTargetIntegrityError(
                "browser shared-worker guard barrier did not identify the root page"
            )
        if self._root_tab_target_id is None or self._root_tab_session_id is None:
            raise CdpTargetIntegrityError(
                "browser popup-tab tripwire did not identify exactly one unpaused root tab"
            )
        for info in infos:
            self._validate_page_target_info(info)
        self._router.raise_if_failed()

    def begin_shutdown(self) -> None:
        """Declare that context disposal is the next operation."""

        if not self._started or self._shutting_down or self._finished:
            raise CdpTargetIntegrityError(
                "browser shared-worker guard shutdown is missing or repeated"
            )
        self._router.begin_shared_worker_guard_shutdown()
        self._shutting_down = True

    def begin_abort(self) -> None:
        """Declare rejected-observation disposal as the next operation."""

        if not self._started or self._shutting_down or self._finished:
            raise CdpTargetIntegrityError(
                "browser shared-worker guard abort is missing or repeated"
            )
        self._router.begin_shared_worker_guard_abort()
        self._aborting = True
        self._shutting_down = True

    def finish(self) -> None:
        """Prove guardian detaches, disable auto-attach, and close the session."""

        if not self._shutting_down or self._aborting or self._finished:
            raise CdpTargetIntegrityError(
                "browser shared-worker guard finished without deliberate shutdown"
            )
        if self._popup_tabs:
            raise CdpTargetIntegrityError(
                "browser popup-tab tripwire cannot produce successful evidence"
            )
        self._prove_shared_worker_guard_lifecycles()
        self._router.finish_shared_worker_guard()
        self._disable_and_detach()
        self._finished = True
        self._router.raise_if_failed()

    def finish_abort(self) -> None:
        """Detach the browser guard after the rejected context was disposed."""

        if not self._shutting_down or not self._aborting or self._finished:
            raise CdpTargetIntegrityError(
                "browser shared-worker guard abort finished without disposal"
            )
        self._prove_popup_tab_close_lifecycles()
        self._router.finish_shared_worker_guard_abort()
        self._disable_and_detach()
        self._finished = True

    def _prove_popup_tab_close_lifecycles(self) -> None:
        """Drain ordered CDP barriers until every rejected tab has detached."""

        if not self._popup_tabs:
            return
        if any(not popup.close_acknowledged for popup in self._popup_tabs.values()):
            raise CdpTargetIntegrityError(
                "browser popup-tab close acknowledgement remains unresolved"
            )
        for _ in range(_BROWSER_TARGET_LIFECYCLE_BARRIER_LIMIT):
            barrier = self._send(*_SHARED_WORKER_GUARD_BARRIER)
            infos = barrier.get("targetInfos")
            if not isinstance(infos, list) or not all(isinstance(info, Mapping) for info in infos):
                raise CdpTargetIntegrityError(
                    "browser popup-tab lifecycle barrier returned malformed targets"
                )
            live_target_ids = {
                info.get("targetId") for info in infos if isinstance(info.get("targetId"), str)
            }
            if all(
                popup.detached and popup.target_id not in live_target_ids
                for popup in self._popup_tabs.values()
            ):
                return
        raise CdpTargetIntegrityError(
            "browser popup-tab close did not reach an exact detached lifecycle"
        )

    def _prove_shared_worker_guard_lifecycles(self) -> None:
        """Drain ordered browser events without synthesising guardian retirement."""

        _guarded, unresolved, guardian_session_count = (
            self._router.shared_worker_guard_lifecycle_state()
        )
        if not unresolved and guardian_session_count == 0:
            return
        for _ in range(_BROWSER_TARGET_LIFECYCLE_BARRIER_LIMIT):
            barrier = self._send(*_SHARED_WORKER_GUARD_BARRIER)
            infos = barrier.get("targetInfos")
            if not isinstance(infos, list) or not all(isinstance(info, Mapping) for info in infos):
                raise CdpTargetIntegrityError(
                    "browser shared-worker lifecycle barrier returned malformed targets"
                )
            live_target_ids: set[str] = set()
            for info in infos:
                target_id = info.get("targetId")
                if not isinstance(target_id, str) or not target_id or target_id in live_target_ids:
                    raise CdpTargetIntegrityError(
                        "browser shared-worker lifecycle barrier returned malformed identities"
                    )
                live_target_ids.add(target_id)
            guarded, unresolved, guardian_session_count = (
                self._router.shared_worker_guard_lifecycle_state()
            )
            if (
                not unresolved
                and guardian_session_count == 0
                and live_target_ids.isdisjoint(guarded)
            ):
                return
        raise CdpTargetIntegrityError(
            "browser shared-worker guardian detach did not reach an exact lifecycle"
        )

    def _disable_and_detach(self) -> None:
        if not self._page_discovery_started:
            raise CdpTargetIntegrityError(
                "browser page-target discovery was not active at guard finish"
            )
        self._send(
            "Target.setAutoAttach",
            {
                "autoAttach": False,
                "waitForDebuggerOnStart": False,
                "flatten": True,
            },
        )
        self._send(*_PAGE_DISCOVERY_DISABLE_COMMAND)
        self._page_discovery_started = False
        try:
            self._session.detach()
        except Exception as error:
            raise CdpTargetIntegrityError(
                "browser shared-worker guard session detach failed"
            ) from error

    def _validate_page_target_info(self, info: Mapping[str, Any]) -> None:
        """Reject sibling pages and browser-scope service workers in the root context."""

        target_type = info.get("type")
        if target_type not in {"page", "service_worker"}:
            return
        target_id = info.get("targetId")
        browser_context_id = info.get("browserContextId")
        if (
            not isinstance(target_id, str)
            or not target_id
            or not isinstance(browser_context_id, str)
            or not browser_context_id
        ):
            raise CdpTargetIntegrityError(
                "browser page-target discovery reported a malformed identity"
            )
        root = self._router.root_source
        root_context = self._router.root_browser_context_id
        if browser_context_id == root_context and target_type == "service_worker":
            service_worker_url = info.get("url")
            self._router.browser_service_worker_attempt(
                service_worker_url
                if isinstance(service_worker_url, str) and service_worker_url
                else None
            )
            raise CdpTargetIntegrityError(
                "service-worker target violated the blocked-worker policy"
            )
        if target_type != "page":
            return
        if target_id == root.target_id and browser_context_id != root_context:
            raise CdpTargetIntegrityError("root browser page target changed its context identity")
        if browser_context_id == root_context and target_id != root.target_id:
            raise CdpTargetIntegrityError(
                "sibling popup/page target escaped the recursive discovery graph"
            )

    def _send(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        try:
            result = self._session.send(method, dict(params))
        except Exception as error:
            raise CdpTargetIntegrityError(
                f"browser shared-worker guard command {method} failed"
            ) from error
        if not isinstance(result, dict):
            raise CdpTargetIntegrityError(
                f"browser shared-worker guard command {method} returned malformed data"
            )
        return result

    def _dispatch_attached(self, event: dict[str, Any]) -> None:
        target_info = event.get("targetInfo")
        if isinstance(target_info, Mapping) and target_info.get("type") == "tab":
            # Closing a waiting popup remains important even when an earlier,
            # later-stage page discovery event has already failed the router.
            self._dispatch(lambda: self._attached_tab(event), allow_after_failure=True)
            return
        self._dispatch(lambda: self._router.adopt_guarded_shared_worker(event))

    def _dispatch_detached(self, event: dict[str, Any]) -> None:
        session_id = event.get("sessionId")
        if session_id == self._root_tab_session_id or (
            isinstance(session_id, str) and session_id in self._popup_target_by_session
        ):
            self._dispatch(lambda: self._detached_tab(event), allow_after_failure=True)
            return
        self._dispatch(lambda: self._router.guarded_shared_worker_detached(event))

    def _attached_tab(self, event: Mapping[str, Any]) -> None:
        """Track the existing tab or synchronously close a waiting popup tab."""

        session_id = event.get("sessionId")
        info = event.get("targetInfo")
        waiting = event.get("waitingForDebugger")
        if (
            not isinstance(session_id, str)
            or not session_id
            or not isinstance(info, Mapping)
            or info.get("type") != "tab"
        ):
            raise CdpTargetIntegrityError("browser tab attachment is malformed")
        target_id = info.get("targetId")
        browser_context_id = info.get("browserContextId")
        if (
            not isinstance(target_id, str)
            or not target_id
            or not isinstance(browser_context_id, str)
            or not browser_context_id
            or info.get("attached") is not True
            or type(waiting) is not bool
        ):
            raise CdpTargetIntegrityError("browser tab attachment identity is malformed")
        if waiting is False:
            if browser_context_id != self._router.root_browser_context_id:
                raise CdpTargetIntegrityError(
                    "unpaused browser tab attachment escaped the root browser context"
                )
            if self._root_tab_target_id is not None or self._root_tab_session_id is not None:
                raise CdpTargetIntegrityError(
                    "browser popup-tab tripwire observed more than one unpaused root tab"
                )
            self._root_tab_target_id = target_id
            self._root_tab_session_id = session_id
            return
        if (
            target_id == self._root_tab_target_id
            or target_id in self._popup_tabs
            or session_id == self._root_tab_session_id
            or session_id in self._popup_target_by_session
        ):
            raise CdpTargetIntegrityError(
                "browser popup-tab tripwire reused a target or session identity"
            )
        popup = _PopupTabTripwire(session_id=session_id, target_id=target_id)
        self._popup_tabs[target_id] = popup
        self._popup_target_by_session[session_id] = target_id
        callback_error: Exception | None = None
        try:
            popup_url = info.get("url")
            self._router.browser_popup_tab_attempt(
                popup_url if isinstance(popup_url, str) and popup_url else None
            )
        except Exception as error:  # noqa: BLE001 - close still must be attempted
            callback_error = error
        popup.close_requested = True
        close_result = self._send("Target.closeTarget", {"targetId": target_id})
        if set(close_result) != {"success"} or close_result.get("success") is not True:
            raise CdpTargetIntegrityError("browser popup-tab tripwire close was not acknowledged")
        popup.close_acknowledged = True
        if callback_error is not None:
            raise callback_error
        if browser_context_id != self._router.root_browser_context_id:
            raise CdpTargetIntegrityError(
                "waiting browser tab attachment escaped the root browser context"
            )

    def _detached_tab(self, event: Mapping[str, Any]) -> None:
        """Validate exact flattened-session termination for a browser tab."""

        session_id = event.get("sessionId")
        target_id = event.get("targetId")
        if (
            not isinstance(session_id, str)
            or not session_id
            or not isinstance(target_id, str)
            or not target_id
        ):
            raise CdpTargetIntegrityError("browser tab detach identity is malformed")
        if session_id == self._root_tab_session_id:
            if target_id != self._root_tab_target_id or self._root_tab_detached:
                raise CdpTargetIntegrityError("root browser tab detach changed identity")
            self._root_tab_detached = True
            if not self._shutting_down:
                raise CdpTargetIntegrityError(
                    "root browser tab detached before the disposal boundary"
                )
            return
        expected_target = self._popup_target_by_session.get(session_id)
        if expected_target != target_id or target_id not in self._popup_tabs:
            raise CdpTargetIntegrityError("popup browser tab detach changed identity")
        popup = self._popup_tabs[target_id]
        if not popup.close_requested or popup.detached:
            raise CdpTargetIntegrityError("popup browser tab detached outside its close lifecycle")
        popup.detached = True

    def _dispatch_browser_target(self, method: str, event: dict[str, Any]) -> None:
        def validate() -> None:
            info = event.get("targetInfo")
            if not isinstance(info, Mapping):
                raise CdpTargetIntegrityError("browser page-target discovery event is malformed")
            self._validate_page_target_info(info)
            if (
                method == "Target.targetInfoChanged"
                and info.get("targetId") == self._router.root_source.target_id
            ):
                self._router.browser_target_info_changed(info)

        self._dispatch(validate)

    def _dispatch_target_destroyed(self, event: dict[str, Any]) -> None:
        def validate() -> None:
            target_id = event.get("targetId")
            if not isinstance(target_id, str) or not target_id:
                raise CdpTargetIntegrityError("browser page-target destruction event is malformed")
            if target_id in self._popup_tabs:
                popup = self._popup_tabs[target_id]
                if not popup.close_requested or popup.destroyed:
                    raise CdpTargetIntegrityError(
                        "popup browser tab destruction violated its close lifecycle"
                    )
                popup.destroyed = True
                return
            if not self._shutting_down and target_id in {
                self._router.root_source.target_id,
                self._root_tab_target_id,
            }:
                raise CdpTargetIntegrityError(
                    "root page/tab target was destroyed before the evidence cutoff"
                )

        self._dispatch(validate, allow_after_failure=True)

    def _dispatch_crashed(self, _event: dict[str, Any]) -> None:
        self._dispatch(self._raise_target_crashed)

    @staticmethod
    def _raise_target_crashed() -> None:
        raise CdpTargetIntegrityError("browser-level shared-worker target crashed")

    def _dispatch(
        self,
        operation: Callable[[], None],
        *,
        allow_after_failure: bool = False,
    ) -> None:
        if self._finished or (
            self._router._failure is not None
            and not self._router._aborting
            and not allow_after_failure
        ):
            return
        try:
            operation()
        except Exception as error:  # noqa: BLE001 - retained for fail-closed finish
            self._router._record_failure(error)
