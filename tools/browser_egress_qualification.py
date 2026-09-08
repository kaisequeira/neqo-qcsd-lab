#!/usr/bin/env python3
"""Host/container boundary for the browser-egress packet qualification.

The shell launcher owns Docker and its lifecycle lock.  This program owns the
typed Python boundaries on either side of Docker: immutable ledger operations,
independent live roles, and content-minimised Docker inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import ssl
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qcsd_lab.browser_egress_fixture import (
    BROWSER_SERVICE_CONTROL_DWELL_MS,
    FIXTURE_CERTIFICATE,
    FIXTURE_PRIVATE_KEY,
    FIXTURE_TOPOLOGY,
    PROXY_ENVIRONMENT_KEYS,
    BrowserFixtureServer,
    IndependentDnsSink,
    IndependentTcpSink,
    IndependentUdpSink,
    assemble_live_semantic_observation,
    combine_sink_receipt,
    browser_service_control_actor_result,
    execute_live_positive_control,
    expected_browser_launch_contract,
    expected_semantic_chronology,
    shared_worker_action_message,
    validate_fixture_observation,
    validate_sink_receipt,
    vector_by_id,
)
from qcsd_lab.browser_egress_observer import (
    LivePacketObserver,
    reconcile_sink_and_packet_evidence,
    validate_capture_receipt,
)
from qcsd_lab.browser_egress_qualification import (
    FINAL_FILENAME,
    FoundationVerificationMode,
    EFFECTIVE_ARGV_BINDING_SCHEMA_VERSION,
    DOCKER_INSPECT_PROJECTION_SCHEMA_VERSION,
    FIXTURE_TLS_MASK_TMPFS_OPTIONS,
    FIXTURE_TLS_MASK_DIRECTORY,
    POLICY_VOLUME_PROJECTION_SCHEMA_VERSION,
    POLICY_VOLUME_ROLE,
    POLICY_VOLUME_MANAGED_DIRECTORY,
    POLICY_VOLUME_POLICY_PATH,
    ROLE_TMPFS_OPTIONS,
    ZERO_DIGEST,
    append_result,
    build_attempt_topology_binding,
    begin_attempt,
    build_failure_result_receipt,
    build_foundation_payload,
    build_live_docker_daemon_binding,
    build_passed_result_receipt,
    create_final_receipt,
    create_qualification,
    deep_validate_foundation,
    load_checkpoint,
    recover_interrupted_attempt,
    reconcile_qualification_filesystem,
    require_live_docker_daemon,
    validate_docker_daemon_binding,
    validate_docker_inspect_projection,
    validate_runtime_binding,
    verify_qualification,
    resume_admission_plan,
    policy_volume_name,
)
from qcsd_lab.buflo_study import validate_build_execution_receipt
from qcsd_lab.class_study import canonical_json_bytes, validate_hash_bound_receipt
from qcsd_lab.util import LAB_ROOT, load_json, sha256_file, source_metadata


READY_PATH = Path("/tmp/qcsd-browser-egress-role.ready")
SUBJECT_STARTED_READY_PATH = Path(
    "/tmp/qcsd-browser-egress-subject-started.ready"
)
GRACE_READY_PATH = Path("/tmp/qcsd-browser-egress-grace.ready")
RECEIPT_READY_PATH = Path("/tmp/qcsd-browser-egress-receipt.ready")
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM)
ROLE_SCHEMA_VERSION = 1
SIGNAL_COORDINATED_COMMANDS = frozenset(
    {"actor", "control", "fixture", "forbidden-sink", "dns-sink", "observer"}
)
SIGNAL_COORDINATED_ROLE_DEADLINE_SECONDS = 115.0
SIGNAL_COORDINATED_ROLE_TIMEOUT_EXIT_CODE = 124
DOCKER_SUPERVISOR_LABEL = "org.qcsd.supervisor.instance"


def _require_same_current_build(
    binding: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    cohort_version: int,
    operation: str,
) -> None:
    """Require one receipt and its paired completion across an action boundary."""

    if (
        Path(str(binding.get("path"))).resolve()
        != Path(str(expected.get("path"))).resolve()
        or binding.get("sha256") != expected.get("sha256")
        or binding.get("completion_path")
        != f"/lab/artifacts/buflo-study/build-completion-v{cohort_version}.json"
        or binding.get("completion_sha256") != expected.get("completion_sha256")
    ):
        raise ValueError(f"browser-egress {operation} uses a different build execution")


def _validated_supervised_labels(
    value: object, *, expected: Mapping[str, str], label: str
) -> dict[str, str]:
    """Validate and remove only the lifecycle supervisor's transient label."""

    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise ValueError(f"{label} labels are invalid")
    supervisor = value.get(DOCKER_SUPERVISOR_LABEL)
    if not isinstance(supervisor, str) or re.fullmatch(r"[0-9a-f]{32}", supervisor) is None:
        raise ValueError(f"{label} lifecycle supervisor label is invalid")
    projected = {
        key: item
        for key, item in value.items()
        if key.startswith("org.qcsd.") and key != DOCKER_SUPERVISOR_LABEL
    }
    if projected != dict(expected):
        raise ValueError(f"{label} labels do not bind the attempt")
    return dict(expected)


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(dict(value)))
    sys.stdout.buffer.flush()


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _object(path: Path, *, label: str) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def _sole_stdout_object(path: Path, *, label: str) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} did not emit one JSON object") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError(f"{label} output is not one canonical JSON object")
    return value


def _install_stop_event() -> threading.Event:
    stopped = threading.Event()
    for item in STOP_SIGNALS:
        signal.signal(item, lambda _signum, _frame: stopped.set())
    return stopped


def _ready() -> int:
    if READY_PATH.exists() or READY_PATH.is_symlink():
        raise FileExistsError("browser-egress role readiness marker already exists")
    ready_ns = time.monotonic_ns()
    READY_PATH.write_text(f"{ready_ns}\n", encoding="ascii")
    return ready_ns


def _wait(stopped: threading.Event, *, timeout_seconds: float = 300.0) -> None:
    if not stopped.wait(timeout_seconds):
        raise TimeoutError("browser-egress role exceeded its coordinator deadline")


def _run_signal_coordinated_role(
    function: Any,
    args: argparse.Namespace,
    *,
    timeout_seconds: float = SIGNAL_COORDINATED_ROLE_DEADLINE_SECONDS,
) -> None:
    """Run a Docker role as tini's direct child under a monotonic hard guard.

    GNU ``timeout`` cannot sit between tini and these roles: it terminates on
    the USR1/USR2 phase signals instead of forwarding them to the Python
    process.  A daemon watchdog keeps the former 120-second container bound
    while leaving every coordinator signal addressed directly to this process.
    """

    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
        raise TypeError("browser-egress role deadline must be numeric")
    if timeout_seconds <= 0:
        raise ValueError("browser-egress role deadline must be positive")
    cancelled = threading.Event()
    deadline = time.monotonic() + float(timeout_seconds)

    def expire() -> None:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if cancelled.wait(remaining):
                return
        try:
            os.write(2, b"browser-egress role exceeded its monotonic hard deadline\n")
        finally:
            os._exit(SIGNAL_COORDINATED_ROLE_TIMEOUT_EXIT_CODE)

    watchdog = threading.Thread(
        target=expire,
        name="qcsd-browser-egress-role-watchdog",
        daemon=True,
    )
    watchdog.start()
    try:
        function(args)
    finally:
        cancelled.set()
        watchdog.join(timeout=1)


def _fixture(args: argparse.Namespace) -> None:
    vector = vector_by_id(args.vector_id)
    stopped = _install_stop_event()
    certificate = Path("/opt/qcsd-lab") / FIXTURE_CERTIFICATE["path"]
    private_key = Path("/opt/qcsd-lab") / FIXTURE_PRIVATE_KEY["path"]
    tls_material: dict[str, Any] = {"schema_version": 1}
    for label, path, expected, mode in (
        ("certificate", certificate, FIXTURE_CERTIFICATE, 0o444),
        ("private_key", private_key, FIXTURE_PRIVATE_KEY, 0o400),
    ):
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_nlink != 1
            or sha256_file(path) != expected["sha256"]
        ):
            raise ValueError("browser-egress fixture TLS material is invalid")
        tls_material[label] = {
            "path": str(path),
            "sha256": expected["sha256"],
            "size_bytes": metadata.st_size,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": f"0o{mode:o}",
            "nlink": metadata.st_nlink,
        }
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    server = BrowserFixtureServer(
        tls_context=context,
        tls_certificate_sha256=sha256_file(certificate),
        vector=vector,
    )
    server.start()
    _ready()
    try:
        _wait(stopped)
    finally:
        observation = server.stop(vector=vector)
    _emit(
        {
            "schema_version": ROLE_SCHEMA_VERSION,
            "role": "fixture",
            "vector_id": vector.vector_id,
            "tls_material": tls_material,
            "receipt": observation,
        }
    )


def _policy_volume_file_inventory() -> list[dict[str, Any]]:
    path = Path(POLICY_VOLUME_POLICY_PATH)
    metadata = path.lstat()
    entries = tuple(path.parent.iterdir())
    if (
        entries != (path,)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_nlink != 1
    ):
        raise ValueError("browser-egress policy volume file layout is invalid")
    return [
        {
            "path": str(path),
            "name": path.name,
            "type": "regular",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": "0o444",
            "nlink": metadata.st_nlink,
            "size_bytes": metadata.st_size,
            "sha256": sha256_file(path),
        }
    ]


def _launch_vector_browser(playwright: Any, vector: Any) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, str], list[dict[str, Any]] | None]:
    """Launch through the sole qualification API and minimise argv immediately."""

    from qcsd_lab.browser_egress import launch_qualification_browser
    from qcsd_lab.playwright_driver import chromium_child_environment

    contract = expected_browser_launch_contract(vector)
    browser, projection, driver = launch_qualification_browser(
        playwright,
        launch_profile=contract["launch_profile"],
        expected_network_prediction_option=contract["managed_policy"][
            "NetworkPredictionOptions"
        ],
        approved_origins=contract["resolver_approved_origins"],
        origin_ip_pins=contract["resolver_origin_ip_pins"],
        approved_ip_exclusions=contract["resolver_approved_ip_exclusions"],
        dns_exception_hostname=contract["dns_exception_hostname"],
    )
    effective = {
        "schema_version": EFFECTIVE_ARGV_BINDING_SCHEMA_VERSION,
        "projection_sha256": hashlib.sha256(canonical_json_bytes(projection)).hexdigest(),
        "command_line_projection": projection,
    }
    policy_inventory = (
        _policy_volume_file_inventory()
        if contract["managed_policy"]["NetworkPredictionOptions"] == 0
        else None
    )
    return browser, effective, driver, chromium_child_environment(), policy_inventory


def _forbidden_sink(args: argparse.Namespace) -> None:
    vector = vector_by_id(args.vector_id)
    stopped = _install_stop_event()
    tcp = IndependentTcpSink("::", FIXTURE_TOPOLOGY["ports"]["forbidden_tcp"])
    udp = IndependentUdpSink("::", FIXTURE_TOPOLOGY["ports"]["forbidden_udp"])
    tcp.start()
    udp.start()
    ready_ns = _ready()
    _wait(stopped)
    tcp_receipt = tcp.stop()
    udp_receipt = udp.stop()
    stopped_ns = time.monotonic_ns()
    _emit(
        {
            "schema_version": ROLE_SCHEMA_VERSION,
            "role": "forbidden-sink",
            "vector_id": vector.vector_id,
            "ready_ns": ready_ns,
            "stopped_ns": stopped_ns,
            "tcp": tcp_receipt,
            "udp": udp_receipt,
        }
    )


def _dns_sink(args: argparse.Namespace) -> None:
    vector = vector_by_id(args.vector_id)
    stopped = _install_stop_event()
    sink = IndependentDnsSink("::", FIXTURE_TOPOLOGY["ports"]["dns"])
    sink.start()
    ready_ns = _ready()
    _wait(stopped)
    receipt = sink.stop()
    stopped_ns = time.monotonic_ns()
    _emit(
        {
            "schema_version": ROLE_SCHEMA_VERSION,
            "role": "dns-sink",
            "vector_id": vector.vector_id,
            "ready_ns": ready_ns,
            "stopped_ns": stopped_ns,
            "receipt": receipt,
        }
    )


def _control(args: argparse.Namespace) -> None:
    vector = vector_by_id(args.vector_id)
    if vector.family != "positive-control":
        raise ValueError("control role requires a positive-control vector")
    start = threading.Event()
    signal.signal(signal.SIGUSR1, lambda _signum, _frame: start.set())
    _ready()
    _wait(start)
    from qcsd_lab.playwright_driver import (
        playwright_driver_session,
    )
    from playwright.sync_api import sync_playwright

    with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
        (
            browser,
            effective_argv,
            driver_runtime,
            child_environment,
            policy_volume_file_inventory,
        ) = _launch_vector_browser(
            playwright, vector
        )
        browser_started_ns = time.monotonic_ns()
        try:
            control_emitter_started_ns = time.monotonic_ns()
            actor_result = execute_live_positive_control(vector)
            control_emitter_exited_ns = time.monotonic_ns()
        finally:
            browser.close()
            browser_exited_ns = time.monotonic_ns()
    _emit(
        {
            "schema_version": ROLE_SCHEMA_VERSION,
            "role": "control",
            "vector_id": vector.vector_id,
            "browser_started_ns": browser_started_ns,
            "browser_exited_ns": browser_exited_ns,
            "actor_result": actor_result,
            "control_emitter_started_ns": control_emitter_started_ns,
            "control_emitter_exited_ns": control_emitter_exited_ns,
            "effective_argv": effective_argv,
            "driver_runtime": driver_runtime,
            "policy_volume_file_inventory": policy_volume_file_inventory,
            "child_environment": child_environment,
        }
    )


def _browser_service_control_actor(args: argparse.Namespace, vector: Any) -> None:
    from qcsd_lab.playwright_driver import playwright_driver_session
    from playwright.sync_api import sync_playwright

    contract = expected_browser_launch_contract(vector)
    target_url = contract["control_document_origin"] + contract["control_document_path"]
    with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
        (
            browser,
            effective_argv,
            driver_runtime,
            child_environment,
            policy_volume_file_inventory,
        ) = _launch_vector_browser(playwright, vector)
        browser_started_ns = time.monotonic_ns()
        target_id: str | None = None
        context = None
        started_ns = time.monotonic_ns()
        try:
            if contract["context_kind"] == "off-the-record-playwright":
                context = browser.new_context()
                page = context.new_page()
                page.goto(target_url, wait_until="load")
                page.wait_for_timeout(BROWSER_SERVICE_CONTROL_DWELL_MS)
            elif contract["context_kind"] == "raw-default-profile-cdp-unattached-target":
                session = browser.new_browser_cdp_session()
                created = session.send(
                    "Target.createTarget", {"url": target_url, "newWindow": False}
                )
                target_id = created.get("targetId") if isinstance(created, Mapping) else None
                if not isinstance(target_id, str) or not target_id:
                    raise ValueError("browser-service control target was not created")
                time.sleep(BROWSER_SERVICE_CONTROL_DWELL_MS / 1_000)
            else:
                raise ValueError("browser-service control context kind is invalid")
            finished_ns = time.monotonic_ns()
            actor_result = browser_service_control_actor_result(
                vector, started_ns=started_ns, finished_ns=finished_ns
            )
        finally:
            if context is not None:
                context.close()
            if target_id is not None:
                session.send("Target.closeTarget", {"targetId": target_id})
            browser.close()
            browser_exited_ns = time.monotonic_ns()
    _emit(
        {
            "schema_version": ROLE_SCHEMA_VERSION,
            "role": "actor",
            "vector_id": vector.vector_id,
            "browser_started_ns": browser_started_ns,
            "browser_exited_ns": browser_exited_ns,
            "actor_result": actor_result,
            "effective_argv": effective_argv,
            "driver_runtime": driver_runtime,
            "policy_volume_file_inventory": policy_volume_file_inventory,
            "child_environment": child_environment,
        }
    )


def _actor(args: argparse.Namespace) -> None:
    """Launch a fresh pinned Chromium and exercise one genuine requested realm."""

    from qcsd_lab.browser_egress import (
        NonReplayableEgressGuard,
        install_context_egress_guards,
    )
    from qcsd_lab.browser_egress_fixture import execute_live_browser_action
    from qcsd_lab.cdp_targets import BrowserSharedWorkerGuard, RecursiveCdpTargetRouter
    from qcsd_lab.playwright_driver import (
        playwright_driver_session,
    )
    from playwright.sync_api import sync_playwright

    vector = vector_by_id(args.vector_id)
    if vector.family == "positive-control":
        raise ValueError("browser actor rejects positive-control vectors")
    start = threading.Event()
    signal.signal(signal.SIGUSR1, lambda _signum, _frame: start.set())
    _ready()
    _wait(start)
    if vector.family == "browser-service-control":
        _browser_service_control_actor(args, vector)
        return
    guard = NonReplayableEgressGuard()
    fetch_denials = [0]
    effective_argv: dict[str, Any] | None = None
    driver_runtime: dict[str, Any] | None = None
    policy_volume_file_inventory: list[dict[str, Any]] | None = None
    child_environment: dict[str, str] | None = None
    prearm_verified_ns: int | None = None
    actor_result: dict[str, Any] | None = None
    reporting_live_dwell_finished_ns: int | None = None
    browser_started_ns: int | None = None
    browser_exited_ns: int | None = None
    fixture = FIXTURE_TOPOLOGY
    primary = f"https://{fixture['fixture_addresses'][0]}:{fixture['ports']['fixture_https']}"
    cross = f"https://{fixture['fixture_addresses'][0]}:{fixture['ports']['fixture_cross_https']}"

    with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
        (
            browser,
            effective_argv,
            driver_runtime,
            child_environment,
            policy_volume_file_inventory,
        ) = _launch_vector_browser(
            playwright, vector
        )
        browser_started_ns = time.monotonic_ns()
        browser_session = browser.new_browser_cdp_session()
        context = browser.new_context(ignore_https_errors=True, service_workers="block")
        install_context_egress_guards(context, guard)
        page = context.new_page()
        guard.bind_root_page(page)
        page.set_default_timeout(10_000)
        page.set_default_navigation_timeout(10_000)
        session = context.new_cdp_session(page)

        router: RecursiveCdpTargetRouter | None = None
        browser_guard: BrowserSharedWorkerGuard | None = None

        def on_event(source: Any, method: str, payload: Mapping[str, Any]) -> None:
            if method != "Fetch.requestPaused":
                return
            request = payload.get("request")
            url = request.get("url") if isinstance(request, Mapping) else None
            request_id = payload.get("requestId")
            if not isinstance(url, str) or not isinstance(request_id, str):
                raise ValueError("browser-egress Fetch event is malformed")
            if (
                url.startswith(f"{primary}/")
                or url.startswith(f"{cross}/")
            ):
                router.send(
                    source,
                    "Fetch.continueRequest",
                    {"requestId": request_id},
                    label="browser-egress-fixture-allow",
                )
            else:
                fetch_denials[0] += 1
                router.send(
                    source,
                    "Fetch.failRequest",
                    {"requestId": request_id, "errorReason": "BlockedByClient"},
                    label="browser-egress-forbidden-deny",
                )

        router = RecursiveCdpTargetRouter(
            session,
            on_event=on_event,
            on_non_replayable_egress=lambda source, api, mechanism, url: guard.record(
                source=source, api=api, mechanism=mechanism, url=url
            ),
        )
        try:
            router.start()
            browser_guard = BrowserSharedWorkerGuard(browser_session, router)
            browser_guard.start()
            page.goto(f"{primary}/", wait_until="load")
            evaluator: Any = page
            if vector.context in {"same-origin-frame", "cross-origin-frame"}:
                origin = primary if vector.context == "same-origin-frame" else cross
                with page.expect_event("framenavigated"):
                    handle = page.evaluate_handle(
                        "url => { const frame=document.createElement('iframe'); frame.src=url; document.body.append(frame); return frame; }",
                        f"{origin}/frame",
                    )
                element = handle.as_element()
                if element is None:
                    raise RuntimeError("browser-egress frame element was not created")
                evaluator = element.content_frame()
                if evaluator is None:
                    raise RuntimeError("browser-egress frame realm is unavailable")
            elif vector.context == "dedicated-worker":
                with page.expect_worker() as worker_info:
                    page.evaluate("url => { window.__qcsdWorker = new Worker(url); }", f"{primary}/dedicated-worker.js")
                evaluator = worker_info.value
            elif vector.context == "shared-worker":
                page.evaluate(
                    """url => new Promise((resolve, reject) => {
                      const worker = new SharedWorker(url);
                      const timer = setTimeout(() => reject(new Error('shared worker readiness timeout')), 5000);
                      worker.port.onmessage = event => {
                        if (event.data && event.data.ready === true) {
                          clearTimeout(timer); window.__qcsdSharedWorker = worker; resolve(true);
                        }
                      };
                      worker.port.start();
                    })""",
                    f"{primary}/shared-worker.js",
                )
                evaluator = _SharedWorkerEvaluator(page, vector, shared_worker_action_message)
            elif vector.surface == "window-open-existing-named-frame":
                page.evaluate(
                    "name => { const frame=document.createElement('iframe'); frame.name=name; frame.src='/frame'; document.body.append(frame); }",
                    "qcsd-egress-popup-v1",
                )
                page.wait_for_timeout(100)

            deadline = time.monotonic() + 10
            while not router.shutdown_ready:
                router.raise_if_failed()
                if time.monotonic() >= deadline:
                    raise TimeoutError("browser-egress target prearm did not converge")
                page.wait_for_timeout(10)
            prearm_verified_ns = time.monotonic_ns()
            realm = _PlaywrightRealm(
                evaluator=evaluator,
                page=page,
                guard=guard,
                fetch_denials=fetch_denials,
                prearmed=True,
                command_line_projection=effective_argv["command_line_projection"],
                child_environment=child_environment,
            )
            actor_result = execute_live_browser_action(vector=vector, realm=realm)
            if vector.surface == "reporting-nel-live":
                page.wait_for_timeout(2_100)
                reporting_live_dwell_finished_ns = time.monotonic_ns()
            router.raise_if_failed()
            router.begin_shutdown()
            browser_guard.begin_shutdown()
            context.close()
            browser_guard.finish()
            router.finish()
        finally:
            try:
                browser.close()
            finally:
                browser_exited_ns = time.monotonic_ns()
                if router is not None:
                    router.raise_if_failed()
    if (
        effective_argv is None
        or driver_runtime is None
        or child_environment is None
        or prearm_verified_ns is None
        or actor_result is None
        or browser_started_ns is None
        or browser_exited_ns is None
    ):
        raise RuntimeError("browser-egress actor did not produce complete evidence")
    output = {
        "schema_version": ROLE_SCHEMA_VERSION,
        "role": "actor",
        "vector_id": vector.vector_id,
        "browser_started_ns": browser_started_ns,
        "browser_exited_ns": browser_exited_ns,
        "prearm_verified_ns": prearm_verified_ns,
        "actor_result": actor_result,
        "effective_argv": effective_argv,
        "driver_runtime": driver_runtime,
        "policy_volume_file_inventory": policy_volume_file_inventory,
        "child_environment": child_environment,
    }
    if vector.surface == "reporting-nel-live":
        output["reporting_live_dwell_finished_ns"] = reporting_live_dwell_finished_ns
    _emit(output)


class _PlaywrightRealm:
    def __init__(
        self,
        *,
        evaluator: Any,
        page: Any,
        guard: Any,
        fetch_denials: list[int],
        prearmed: bool,
        command_line_projection: Mapping[str, Any],
        child_environment: Mapping[str, str],
    ) -> None:
        self.evaluator = evaluator
        self.page = page
        self.guard = guard
        self.fetch_denials = fetch_denials
        self.prearmed = prearmed
        self.command_line_projection = dict(command_line_projection)
        self.child_environment = dict(child_environment)

    def evaluate(self, expression: str, argument: Mapping[str, Any]) -> Mapping[str, Any]:
        result = self.evaluator.evaluate(expression, dict(argument))
        self.page.wait_for_timeout(300)
        return result

    def browser_configuration_observation(self, surface: str) -> Mapping[str, Any]:
        from qcsd_lab.browser_egress import BROWSER_EGRESS_ANTAGONISTIC_CHROMIUM_SWITCHES

        projection = self.command_line_projection
        return {
            "surface": surface,
            "effective_argv_projection_sha256": hashlib.sha256(
                canonical_json_bytes(projection)
            ).hexdigest(),
            "child_environment_sha256": hashlib.sha256(
                canonical_json_bytes(self.child_environment)
            ).hexdigest(),
            "no_proxy_server_argument_count": projection["observed_required_switches"].count(
                "--no-proxy-server"
            ),
            "antagonistic_proxy_switches_present": projection[
                "observed_antagonistic_switches"
            ],
            "proxy_environment_keys_present": sorted(
                set(self.child_environment).intersection(PROXY_ENVIRONMENT_KEYS)
            ),
        }

    def guard_counts(self) -> Mapping[str, int]:
        return {"policy_event_count": self.guard.attempt_count, "fetch_denial_count": self.fetch_denials[0]}

    def prearm_verified(self) -> bool:
        return self.prearmed


class _SharedWorkerEvaluator:
    def __init__(self, page: Any, vector: Any, message_builder: Any) -> None:
        self.page = page
        self.message = message_builder(vector)

    def evaluate(self, expression: str, argument: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.message["expression"] != expression or self.message["argument"] != dict(argument):
            raise ValueError("shared-worker action differs from its frozen message")
        return self.page.evaluate(
            """message => new Promise((resolve, reject) => {
              const port = window.__qcsdSharedWorker.port;
              const timer = setTimeout(() => reject(new Error('shared worker action timeout')), 5000);
              port.onmessage = event => {
                if (event.data && event.data.protocol === message.protocol && 'result' in event.data) {
                  clearTimeout(timer); resolve(event.data.result);
                }
              };
              port.postMessage(message);
            })""",
            self.message,
        )

def _observer(args: argparse.Namespace) -> None:
    vector = vector_by_id(args.vector_id)
    subject_started = threading.Event()
    subject_exited = threading.Event()
    finish_capture = threading.Event()
    stopped = _install_stop_event()
    signal.signal(signal.SIGUSR1, lambda _signum, _frame: subject_started.set())
    signal.signal(signal.SIGUSR2, lambda _signum, _frame: subject_exited.set())
    signal.signal(signal.SIGHUP, lambda _signum, _frame: finish_capture.set())
    observer = LivePacketObserver(pcap_path=args.pcap)
    observer.start()
    _ready()
    _wait(subject_started)
    observer.mark_subject_started()
    SUBJECT_STARTED_READY_PATH.write_text("ready\n", encoding="ascii")
    _wait(subject_exited)
    observer.mark_subject_exited()
    time.sleep(5.05)
    observer.mark_reporting_grace_finished()
    GRACE_READY_PATH.write_text("ready\n", encoding="ascii")
    _wait(finish_capture)
    receipt = observer.finish(vector=vector, pcap_relative_path=args.evidence_relative)
    _emit({"schema_version": ROLE_SCHEMA_VERSION, "role": "observer", "vector_id": vector.vector_id, "receipt": receipt})
    RECEIPT_READY_PATH.write_text("ready\n", encoding="ascii")
    # The capture lives on a mount-free tmpfs.  Keep the container alive until
    # the host has read the canonical receipt and copied the closed PCAP.
    _wait(stopped)


def _foundation(args: argparse.Namespace) -> None:
    build = validate_build_execution_receipt(
        args.build_execution_receipt,
        expected_cohort_version=args.cohort_version,
        allow_historical=False,
    )
    repo_digests = json.loads(args.prepare_repo_digests_json)
    if not isinstance(repo_digests, list):
        raise ValueError("prepare RepoDigests must be a JSON array")
    payload = build_foundation_payload(
        lab_root=LAB_ROOT,
        cohort_version=args.cohort_version,
        build_execution=build,
        prepare_repo_digests=repo_digests,
        runtime_source=source_metadata(),
        live_docker_daemon=_live_docker_argument(args),
    )
    _emit(create_qualification(args.result_root, payload, lab_root=LAB_ROOT))


def _admit_resume(args: argparse.Namespace) -> None:
    envelope = _object(args.result_root / "foundation.json", label="foundation")
    foundation = validate_hash_bound_receipt(
        envelope,
        expected_type="qcsd-browser-egress-qualification-foundation",
    )
    validated_foundation = deep_validate_foundation(
        foundation,
        lab_root=LAB_ROOT,
        mode=FoundationVerificationMode.EXECUTION,
    )
    require_live_docker_daemon(
        _live_docker_argument(args), expected=validated_foundation["docker_daemon"]
    )
    expected_build = validate_build_execution_receipt(
        args.build_execution_receipt,
        expected_cohort_version=args.cohort_version,
        allow_historical=False,
    )
    build_binding = validated_foundation["build_execution"]
    if validated_foundation["cohort_version"] != args.cohort_version:
        raise ValueError("browser-egress resume uses a different build execution")
    _require_same_current_build(
        build_binding,
        expected_build,
        cohort_version=args.cohort_version,
        operation="resume",
    )
    plan = resume_admission_plan(args.result_root)
    if plan["checkpoint_status"] not in {"running", "complete"}:
        raise ValueError("browser-egress qualification is not resumable")
    _emit(plan)


def _reconcile_filesystem(args: argparse.Namespace) -> None:
    envelope = _object(args.result_root / "foundation.json", label="foundation")
    foundation = validate_hash_bound_receipt(
        envelope,
        expected_type="qcsd-browser-egress-qualification-foundation",
    )
    validated_foundation = deep_validate_foundation(
        foundation,
        lab_root=LAB_ROOT,
        mode=FoundationVerificationMode.EXECUTION,
    )
    require_live_docker_daemon(
        _live_docker_argument(args), expected=validated_foundation["docker_daemon"]
    )
    expected_build = validate_build_execution_receipt(
        args.build_execution_receipt,
        expected_cohort_version=args.cohort_version,
        allow_historical=False,
    )
    build_binding = validated_foundation["build_execution"]
    if validated_foundation["cohort_version"] != args.cohort_version:
        raise ValueError("browser-egress reconciliation uses a different build execution")
    _require_same_current_build(
        build_binding,
        expected_build,
        cohort_version=args.cohort_version,
        operation="reconciliation",
    )
    _emit(reconcile_qualification_filesystem(args.result_root))


def _recover_resume(args: argparse.Namespace) -> None:
    envelope = _object(args.result_root / "foundation.json", label="foundation")
    foundation = validate_hash_bound_receipt(
        envelope,
        expected_type="qcsd-browser-egress-qualification-foundation",
    )
    validated_foundation = deep_validate_foundation(
        foundation,
        lab_root=LAB_ROOT,
        mode=FoundationVerificationMode.EXECUTION,
    )
    require_live_docker_daemon(
        _live_docker_argument(args), expected=validated_foundation["docker_daemon"]
    )
    expected_build = validate_build_execution_receipt(
        args.build_execution_receipt,
        expected_cohort_version=args.cohort_version,
        allow_historical=False,
    )
    build_binding = validated_foundation["build_execution"]
    if validated_foundation["cohort_version"] != args.cohort_version:
        raise ValueError("browser-egress recovery uses a different build execution")
    _require_same_current_build(
        build_binding,
        expected_build,
        cohort_version=args.cohort_version,
        operation="recovery",
    )
    checkpoint = recover_interrupted_attempt(args.result_root, finished_at=_timestamp())
    if checkpoint["status"] not in {"running", "complete"}:
        raise ValueError("browser-egress recovered qualification is terminally failed")
    _emit(checkpoint)


def _next(args: argparse.Namespace) -> None:
    checkpoint = load_checkpoint(args.result_root)
    if checkpoint["status"] == "complete":
        _emit({"schema_version": 1, "complete": True})
        return
    if checkpoint["status"] != "running":
        raise ValueError("browser-egress qualification is not resumable")
    ordinal = checkpoint["next_vector_ordinal"]
    from qcsd_lab.browser_egress_fixture import expected_vectors

    vector = expected_vectors()[ordinal - 1]
    prior = [item for item in checkpoint["attempts"] if item["vector_id"] == vector.vector_id]
    _emit(
        {
            "schema_version": 1,
            "complete": False,
            "vector": vector.as_dict(),
            "global_ordinal": len(checkpoint["attempts"]) + 1,
            "attempt_number": len(prior) + 1,
            "previous_result_sha256": checkpoint["chain_head_sha256"],
        }
    )


def _begin_attempt(args: argparse.Namespace) -> None:
    try:
        next_value = json.loads(args.next_plan_json)
    except json.JSONDecodeError as error:
        raise ValueError("next-vector plan must be JSON") from error
    if not isinstance(next_value, Mapping):
        raise ValueError("next-vector plan must be a JSON object")
    binding = begin_attempt(
        args.result_root,
        next_plan=next_value,
        vector_id=args.vector_id,
        started_at=args.started_at,
    )
    _emit({"schema_version": 1, "created": True, "intent": binding})


def _record_failure(args: argparse.Namespace) -> None:
    foundation_envelope = _object(args.result_root / "foundation.json", label="foundation")
    foundation = validate_hash_bound_receipt(
        foundation_envelope,
        expected_type="qcsd-browser-egress-qualification-foundation",
    )
    next_value = _object(args.next_json, label="next-vector plan")
    vector = vector_by_id(args.vector_id)
    if next_value.get("complete") is not False or next_value.get("vector") != vector.as_dict():
        raise ValueError("failure record differs from its next-vector plan")
    relative_directory = (
        f"evidence/{vector.ordinal:03d}--{vector.vector_id}/"
        f"attempt-{next_value['attempt_number']}"
    )
    root = args.result_root.resolve(strict=True)
    attempt_directory = (root / relative_directory).resolve(strict=True)
    if attempt_directory.parent.parent != root / "evidence":
        raise ValueError("failure evidence directory escaped the qualification root")
    diagnostic_path = attempt_directory / "failure.json"
    diagnostic = {
        "schema_version": 1,
        "vector_id": vector.vector_id,
        "attempt_number": next_value["attempt_number"],
        "failure_code": args.failure_code,
        "stage": args.stage,
    }
    descriptor = os.open(
        diagnostic_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, canonical_json_bytes(diagnostic))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(attempt_directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    artifacts: list[dict[str, Any]] = []
    for path in sorted(attempt_directory.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("failure evidence contains an unsafe artifact")
        artifacts.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    receipt = build_failure_result_receipt(
        foundation=foundation,
        global_ordinal=next_value["global_ordinal"],
        attempt_number=next_value["attempt_number"],
        previous_result_sha256=next_value.get("previous_result_sha256", ZERO_DIGEST),
        vector_id=vector.vector_id,
        started_at=args.started_at,
        finished_at=args.finished_at,
        verdict=args.verdict,
        failure_code=args.failure_code,
        failure_artifacts=artifacts,
    )
    _emit(append_result(args.result_root, receipt))


def _assemble(args: argparse.Namespace) -> None:
    foundation_envelope = _object(args.result_root / "foundation.json", label="foundation")
    foundation = validate_hash_bound_receipt(
        foundation_envelope,
        expected_type="qcsd-browser-egress-qualification-foundation",
    )
    next_value = _object(args.next_json, label="next-vector plan")
    vector = vector_by_id(args.vector_id)
    try:
        actor = _sole_stdout_object(args.actor_json, label="actor role")
    except (OSError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "semantic-observation-failed"})
        return
    expected_actor_fields = {
        "schema_version",
        "role",
        "vector_id",
        "actor_result",
        "effective_argv",
        "driver_runtime",
        "policy_volume_file_inventory",
        "child_environment",
        "browser_started_ns",
        "browser_exited_ns",
    }
    if vector.family == "positive-control":
        expected_actor_fields.update(
            {"control_emitter_started_ns", "control_emitter_exited_ns"}
        )
    elif vector.family != "browser-service-control":
        expected_actor_fields.add("prearm_verified_ns")
    if vector.surface == "reporting-nel-live":
        expected_actor_fields.add("reporting_live_dwell_finished_ns")
    expected_actor_role = "control" if vector.family == "positive-control" else "actor"
    if (
        set(actor) != expected_actor_fields
        or actor.get("schema_version") != ROLE_SCHEMA_VERSION
        or actor.get("role") != expected_actor_role
        or actor.get("vector_id") != vector.vector_id
    ):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "semantic-observation-failed"})
        return
    try:
        forbidden = _sole_stdout_object(args.forbidden_json, label="forbidden sink role")
        dns = _sole_stdout_object(args.dns_json, label="DNS sink role")
    except (OSError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "sink-reconciliation-failed"})
        return
    if (
        set(forbidden)
        != {"schema_version", "role", "vector_id", "ready_ns", "stopped_ns", "tcp", "udp"}
        or forbidden.get("schema_version") != ROLE_SCHEMA_VERSION
        or forbidden.get("role") != "forbidden-sink"
        or forbidden.get("vector_id") != vector.vector_id
        or set(dns)
        != {"schema_version", "role", "vector_id", "ready_ns", "stopped_ns", "receipt"}
        or dns.get("schema_version") != ROLE_SCHEMA_VERSION
        or dns.get("role") != "dns-sink"
        or dns.get("vector_id") != vector.vector_id
    ):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "sink-reconciliation-failed"})
        return
    try:
        fixture_role = _sole_stdout_object(args.fixture_json, label="fixture role")
    except (OSError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "fixture-observation-failed"})
        return
    if (
        set(fixture_role)
        != {"schema_version", "role", "vector_id", "tls_material", "receipt"}
        or fixture_role.get("schema_version") != ROLE_SCHEMA_VERSION
        or fixture_role.get("role") != "fixture"
        or fixture_role.get("vector_id") != vector.vector_id
    ):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "fixture-observation-failed"})
        return
    try:
        capture = _sole_stdout_object(args.capture_json, label="observer role")
    except (OSError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "capture-process-failed"})
        return
    if (
        set(capture) != {"schema_version", "role", "vector_id", "receipt"}
        or capture.get("schema_version") != ROLE_SCHEMA_VERSION
        or capture.get("role") != "observer"
        or capture.get("vector_id") != vector.vector_id
    ):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "capture-process-failed"})
        return
    try:
        runtime = _object(args.runtime_json, label="runtime binding")
    except (OSError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "runtime-binding-failed"})
        return
    try:
        validate_runtime_binding(
            runtime,
            foundation=foundation,
            vector_id=vector.vector_id,
            global_ordinal=next_value["global_ordinal"],
            attempt_number=next_value["attempt_number"],
            started_at=args.started_at,
        )
    except (KeyError, TypeError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "runtime-binding-failed"})
        return
    try:
        sink = combine_sink_receipt(
            vector=vector,
            tcp=forbidden["tcp"],
            udp=forbidden["udp"],
            dns=dns["receipt"],
            forbidden_ready_ns=forbidden["ready_ns"],
            dns_ready_ns=dns["ready_ns"],
            forbidden_stopped_ns=forbidden["stopped_ns"],
            dns_stopped_ns=dns["stopped_ns"],
        )
        validate_sink_receipt(sink, vector=vector)
    except (KeyError, TypeError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "sink-reconciliation-failed"})
        return
    try:
        actor_result = actor["actor_result"]
        capture_receipt = capture["receipt"]
        chronology = capture_receipt["chronology"]
        times = {
            "observer-ready": chronology["observer_ready_ns"],
            "sinks-ready": max(forbidden["ready_ns"], dns["ready_ns"]),
            "action-started": actor_result["started_ns"],
            vector.semantic_kind: actor_result["finished_ns"],
            "reporting-grace-finished": chronology["reporting_grace_finished_ns"],
            "observer-stopped": chronology["observer_stopped_ns"],
        }
        if vector.family == "positive-control":
            times["browser-started"] = actor["browser_started_ns"]
            times["control-emitter-started"] = actor["control_emitter_started_ns"]
            times["control-emitter-exited"] = actor["control_emitter_exited_ns"]
            times["browser-exited"] = actor["browser_exited_ns"]
        elif vector.family == "browser-service-control":
            times["browser-started"] = actor["browser_started_ns"]
            times["browser-exited"] = actor["browser_exited_ns"]
        else:
            times["browser-started"] = actor["browser_started_ns"]
            times["prearm-verified"] = actor["prearm_verified_ns"]
            times["browser-exited"] = actor["browser_exited_ns"]
        if vector.surface == "reporting-nel-live":
            times["reporting-live-dwell-finished"] = actor[
                "reporting_live_dwell_finished_ns"
            ]
        if set(times) != set(expected_semantic_chronology(vector)):
            raise ValueError("coordinator chronology is incomplete")
        semantic = assemble_live_semantic_observation(
            vector=vector, actor_result=actor_result, event_times=times
        )
    except (KeyError, TypeError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "semantic-observation-failed"})
        return
    try:
        validate_fixture_observation(fixture_role["receipt"], vector=vector)
    except (KeyError, TypeError, ValueError):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "fixture-observation-failed"})
        return
    process = capture_receipt.get("capture_process")
    if isinstance(process, Mapping) and (
        process.get("packets_dropped_by_kernel", 0) != 0
        or process.get("packets_dropped_by_interface", 0) != 0
    ):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "capture-dropped-packets"})
        return
    if not isinstance(process, Mapping) or process.get("exit_code") != 0:
        _emit({"schema_version": 1, "assembled": False, "failure_code": "capture-process-failed"})
        return
    try:
        validate_capture_receipt(
            capture_receipt,
            vector=vector,
            evidence_root=args.result_root,
            deep=True,
        )
    except ValueError as error:
        failure_code = (
            "packet-policy-failed"
            if str(error).startswith("browser-egress packet policy failed at ")
            else "capture-process-failed"
        )
        _emit({"schema_version": 1, "assembled": False, "failure_code": failure_code})
        return
    try:
        reconcile_sink_and_packet_evidence(
            vector=vector, analysis=capture_receipt["analysis"], sink=sink
        )
    except ValueError as error:
        failure_code = (
            "packet-policy-failed"
            if str(error).startswith("browser-egress packet policy failed at ")
            else "sink-reconciliation-failed"
        )
        _emit({"schema_version": 1, "assembled": False, "failure_code": failure_code})
        return
    fixture_times = fixture_role["receipt"]["chronology"]
    if not (
        fixture_times["ready_ns"] <= times["sinks-ready"]
        and chronology["reporting_grace_finished_ns"]
        <= fixture_times["stopped_ns"]
        <= chronology["observer_stopped_ns"]
    ):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "fixture-observation-failed"})
        return
    sink_times = sink["chronology"]
    if not (
        max(sink_times["forbidden_ready_ns"], sink_times["dns_ready_ns"])
        == times["sinks-ready"]
        and chronology["reporting_grace_finished_ns"]
        <= sink_times["forbidden_stopped_ns"]
        <= chronology["observer_stopped_ns"]
        and chronology["reporting_grace_finished_ns"]
        <= sink_times["dns_stopped_ns"]
        <= chronology["observer_stopped_ns"]
    ):
        _emit({"schema_version": 1, "assembled": False, "failure_code": "sink-reconciliation-failed"})
        return
    if getattr(args, "validate_only", False):
        _emit({"schema_version": 1, "assembled": True})
        return
    receipt = build_passed_result_receipt(
        foundation=foundation,
        global_ordinal=next_value["global_ordinal"],
        attempt_number=next_value["attempt_number"],
        previous_result_sha256=next_value.get("previous_result_sha256", ZERO_DIGEST),
        vector_id=vector.vector_id,
        started_at=args.started_at,
        finished_at=args.finished_at,
        runtime=runtime,
        semantic=semantic,
        fixture=fixture_role["receipt"],
        sink=sink,
        capture=capture_receipt,
    )
    _emit(
        {
            "schema_version": 1,
            "assembled": True,
            "checkpoint": append_result(args.result_root, receipt),
        }
    )


def _attempt_status(args: argparse.Namespace) -> None:
    """Reconcile one ambiguous append and report only its exact ledger state."""

    next_value = _object(args.next_json, label="next-vector plan")
    vector = vector_by_id(args.vector_id)
    expected_fields = {
        "schema_version",
        "complete",
        "vector",
        "global_ordinal",
        "attempt_number",
        "previous_result_sha256",
    }
    if (
        set(next_value) != expected_fields
        or next_value.get("schema_version") != 1
        or next_value.get("complete") is not False
        or next_value.get("vector") != vector.as_dict()
        or type(next_value.get("global_ordinal")) is not int
        or type(next_value.get("attempt_number")) is not int
        or next_value["global_ordinal"] < 1
        or next_value["attempt_number"] < 1
    ):
        raise ValueError("ambiguous browser-egress attempt plan is invalid")
    checkpoint = load_checkpoint(args.result_root, deep=True)
    global_ordinal = next_value["global_ordinal"]
    attempts = checkpoint["attempts"]
    if len(attempts) not in {global_ordinal - 1, global_ordinal}:
        raise ValueError("ambiguous browser-egress attempt is not at the ledger head")
    if len(attempts) == global_ordinal:
        entry = attempts[-1]
        if any(
            entry[key] != next_value[key]
            for key in ("global_ordinal", "attempt_number")
        ) or entry["vector_id"] != vector.vector_id:
            raise ValueError("published browser-egress attempt differs from its plan")
        _emit(
            {
                "schema_version": 1,
                "published": True,
                "verdict": entry["verdict"],
                "checkpoint": checkpoint,
            }
        )
        return
    if (
        checkpoint["status"] != "running"
        or checkpoint["next_vector_ordinal"] != vector.ordinal
        or checkpoint["chain_head_sha256"]
        != next_value["previous_result_sha256"]
    ):
        raise ValueError("unpublished browser-egress attempt differs from the ledger")
    prior = [item for item in attempts if item["vector_id"] == vector.vector_id]
    if next_value["attempt_number"] != len(prior) + 1:
        raise ValueError("unpublished browser-egress attempt number is invalid")
    _emit(
        {
            "schema_version": 1,
            "published": False,
            "verdict": None,
            "checkpoint": checkpoint,
        }
    )


def _finalize(args: argparse.Namespace) -> None:
    existed = (args.result_root / FINAL_FILENAME).exists()
    path = create_final_receipt(args.result_root, recorded_at=_timestamp())
    _emit({"schema_version": 1, "path": str(path), "created": not existed})


def _verify(args: argparse.Namespace) -> None:
    foundation_envelope = _object(args.result_root / "foundation.json", label="foundation")
    foundation = validate_hash_bound_receipt(
        foundation_envelope,
        expected_type="qcsd-browser-egress-qualification-foundation",
    )
    require_live_docker_daemon(
        _live_docker_argument(args), expected=foundation["docker_daemon"]
    )
    expected_build = validate_build_execution_receipt(
        args.build_execution_receipt,
        expected_cohort_version=args.cohort_version,
        allow_historical=False,
    )
    verified = verify_qualification(
        args.result_root,
        lab_root=LAB_ROOT,
        expected_cohort_version=args.cohort_version,
        verification_mode=FoundationVerificationMode.EXECUTION,
    )
    binding = verified["build_execution"]
    _require_same_current_build(
        binding,
        expected_build,
        cohort_version=args.cohort_version,
        operation="result",
    )
    _emit(verified)


def _project_runtime(args: argparse.Namespace) -> None:
    foundation_envelope = _object(args.result_root / "foundation.json", label="foundation")
    foundation = validate_hash_bound_receipt(
        foundation_envelope,
        expected_type="qcsd-browser-egress-qualification-foundation",
    )
    live_docker_daemon = require_live_docker_daemon(
        _live_docker_argument(args), expected=foundation["docker_daemon"]
    )
    attempt_topology = build_attempt_topology_binding(
        foundation=foundation,
        global_ordinal=args.global_ordinal,
        attempt_number=args.attempt_number,
        vector_id=args.vector_id,
        started_at=args.started_at,
    )
    actor = _sole_stdout_object(args.actor_json, label="actor role")
    fixture_role = _sole_stdout_object(args.fixture_json, label="fixture role")
    vector = vector_by_id(args.vector_id)
    expected_actor_role = "control" if vector.family == "positive-control" else "actor"
    expected_actor_fields = {
        "schema_version",
        "role",
        "vector_id",
        "actor_result",
        "effective_argv",
        "driver_runtime",
        "policy_volume_file_inventory",
        "child_environment",
        "browser_started_ns",
        "browser_exited_ns",
    }
    if vector.family == "positive-control":
        expected_actor_fields.update(
            {"control_emitter_started_ns", "control_emitter_exited_ns"}
        )
    elif vector.family != "browser-service-control":
        expected_actor_fields.add("prearm_verified_ns")
    if vector.surface == "reporting-nel-live":
        expected_actor_fields.add("reporting_live_dwell_finished_ns")
    if (
        set(actor) != expected_actor_fields
        or actor.get("schema_version") != ROLE_SCHEMA_VERSION
        or actor.get("role") != expected_actor_role
        or actor.get("vector_id") != vector.vector_id
        or "effective_argv" not in actor
        or "child_environment" not in actor
    ):
        raise ValueError("browser-egress subject output differs from its vector")
    network_raw = _object(args.network_inspect_json, label="Docker network inspection")
    containers_raw = load_json(args.container_inspect_json)
    volume_raw = load_json(args.volume_inspect_json)
    if (
        not isinstance(fixture_role, Mapping)
        or set(fixture_role)
        != {"schema_version", "role", "vector_id", "tls_material", "receipt"}
        or fixture_role.get("schema_version") != ROLE_SCHEMA_VERSION
        or fixture_role.get("role") != "fixture"
        or fixture_role.get("vector_id") != vector.vector_id
    ):
        raise ValueError("browser-egress fixture output differs from its vector")
    projection = _docker_projection(
        network_raw,
        containers_raw,
        volume_raw,
        vector_id=args.vector_id,
        prepare_image_id=foundation["prepare_image"]["id"],
        browser_uid=args.browser_uid,
        browser_gid=args.browser_gid,
        attempt_topology=attempt_topology,
        docker_root_dir=live_docker_daemon["docker_root_dir"],
        policy_file_inventory=actor["policy_volume_file_inventory"],
    )
    _emit(
        {
            "prepare_image_id": foundation["prepare_image"]["id"],
            "docker_daemon": live_docker_daemon,
            "source": foundation["source"],
            "browser": foundation["browser"],
            "effective_argv": actor["effective_argv"],
            "driver_runtime": actor["driver_runtime"],
            "fixture_tls_runtime": fixture_role["tls_material"],
            "child_environment": actor["child_environment"],
            "browser_identity": {"uid": args.browser_uid, "gid": args.browser_gid},
            "attempt_topology": attempt_topology,
            "subject_kind": (
                "idle-chromium-plus-independent-control-emitter"
                if vector.family == "positive-control"
                else "chromium-browser"
            ),
            "docker_inspect": projection,
            "fixture_contract_sha256": foundation["contracts"]["fixture_contract_sha256"],
        }
    )


def _live_docker_argument(args: argparse.Namespace) -> dict[str, Any]:
    try:
        value = json.loads(args.live_docker_json)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("live Docker daemon binding must be JSON") from error
    return validate_docker_daemon_binding(value)


def _live_docker_binding(args: argparse.Namespace) -> None:
    try:
        docker_version = json.loads(args.docker_version_json)
        docker_info = json.loads(args.docker_info_json)
    except json.JSONDecodeError as error:
        raise ValueError("Docker version/info response must be JSON") from error
    _emit(
        build_live_docker_daemon_binding(
            docker_version=docker_version,
            docker_info=docker_info,
            context=args.context,
            endpoint=args.endpoint,
            pinned_server_id=args.server_id,
        )
    )


def _stale_topology_cleanup_plan(args: argparse.Namespace) -> None:
    try:
        resume = json.loads(args.resume_plan_json)
        network_value = json.loads(args.network_inspect_json)
        containers = json.loads(args.container_inspect_json)
        volume_value = json.loads(args.volume_inspect_json)
    except json.JSONDecodeError as error:
        raise ValueError("stale Docker topology inputs must be JSON") from error
    if not isinstance(resume, Mapping) or set(resume) != {
        "schema_version",
        "checkpoint_publish_lag",
        "checkpoint_status",
        "prepare_image_id",
        "docker_root_dir",
        "cleanup",
    }:
        raise ValueError("browser-egress resume admission plan is invalid")
    cleanup = resume["cleanup"]
    if cleanup is not None and (
        not isinstance(cleanup, Mapping)
        or set(cleanup)
        != {
            "vector_id",
            "global_ordinal",
            "attempt_number",
            "evidence_directory",
            "topology_token",
            "cohort_version",
            "foundation_payload_sha256",
            "outstanding",
        }
    ):
        raise ValueError("browser-egress resume cleanup binding is invalid")
    if not isinstance(containers, list) or any(
        not isinstance(item, Mapping) for item in containers
    ):
        raise ValueError("stale Docker container inspection is invalid")
    if network_value is None:
        network = None
    elif isinstance(network_value, list) and len(network_value) == 1 and isinstance(
        network_value[0], Mapping
    ):
        network = network_value[0]
    else:
        raise ValueError("stale Docker network inspection is invalid")
    if volume_value is None:
        volume = None
    elif isinstance(volume_value, list) and len(volume_value) == 1 and isinstance(
        volume_value[0], Mapping
    ):
        volume = volume_value[0]
    else:
        raise ValueError("stale Docker policy-volume inspection is invalid")
    docker_root_dir = resume["docker_root_dir"]
    if not isinstance(docker_root_dir, str):
        raise ValueError("browser-egress resume Docker root directory is invalid")
    docker_root = Path(docker_root_dir)
    if not docker_root.is_absolute() or docker_root.as_posix() != docker_root_dir:
        raise ValueError("browser-egress resume Docker root directory is invalid")
    if cleanup is None:
        if containers or network is not None or volume is not None:
            raise ValueError("Docker topology exists without a bound attempt intent")
        _emit(
            {
                "schema_version": 1,
                "container_ids": [],
                "network_id": None,
                "volume_name": None,
            }
        )
        return

    vector_id = cleanup["vector_id"]
    if (
        not isinstance(vector_id, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", vector_id) is None
        or not isinstance(cleanup["evidence_directory"], str)
        or re.fullmatch(
            rf"evidence/[0-9]{{3}}--{re.escape(vector_id)}/attempt-[1-3]",
            cleanup["evidence_directory"],
        )
        is None
        or type(cleanup["global_ordinal"]) is not int
        or cleanup["global_ordinal"] < 1
        or type(cleanup["attempt_number"]) is not int
        or not 1 <= cleanup["attempt_number"] <= 3
        or type(cleanup["outstanding"]) is not bool
        or not isinstance(cleanup["topology_token"], str)
        or re.fullmatch(r"[0-9a-f]{32}", cleanup["topology_token"]) is None
        or type(cleanup["cohort_version"]) is not int
        or cleanup["cohort_version"] < 1
        or not isinstance(cleanup["foundation_payload_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", cleanup["foundation_payload_sha256"])
        is None
    ):
        raise ValueError("browser-egress resume cleanup binding is invalid")
    vector = vector_by_id(vector_id)
    if cleanup["evidence_directory"] != (
        f"evidence/{vector.ordinal:03d}--{vector_id}/"
        f"attempt-{cleanup['attempt_number']}"
    ):
        raise ValueError("browser-egress resume cleanup evidence path is invalid")
    if cleanup["outstanding"] is not True:
        if containers or network is not None or volume is not None:
            raise ValueError(
                "Docker topology exists without an outstanding attempt intent"
            )
        _emit(
            {
                "schema_version": 1,
                "container_ids": [],
                "network_id": None,
                "volume_name": None,
            }
        )
        return
    expected_labels = {
        "org.qcsd.owner": "qcsd-lab",
        "org.qcsd.study": "classifier-multiorigin100-v1",
        "org.qcsd.qualification": "browser-egress-qualification-v1",
        "org.qcsd.vector": vector_id,
        "org.qcsd.cohort-version": str(cleanup["cohort_version"]),
        "org.qcsd.foundation": cleanup["foundation_payload_sha256"],
        "org.qcsd.global-ordinal": str(cleanup["global_ordinal"]),
        "org.qcsd.attempt-number": str(cleanup["attempt_number"]),
        "org.qcsd.topology-token": cleanup["topology_token"],
    }
    topology = {
        key: cleanup[key]
        for key in (
            "cohort_version",
            "foundation_payload_sha256",
            "global_ordinal",
            "attempt_number",
            "topology_token",
        )
    }
    expected_volume_name = policy_volume_name(
        vector_id=vector_id, attempt_topology=topology
    )
    expected_roles = {
        "browser",
        "observer",
        "fixture",
        "forbidden_sink",
        "dns_sink",
    }
    if expected_volume_name is not None:
        expected_roles.add("policy_seed")
    direct_roles = {
        "browser",
        "fixture",
        "forbidden_sink",
        "dns_sink",
    }
    suffixes = {
        "browser": "browser",
        "observer": "observer",
        "fixture": "fixture",
        "forbidden_sink": "forbidden",
        "dns_sink": "dns",
        "policy_seed": "policy-seed",
    }
    addresses = {
        "browser": FIXTURE_TOPOLOGY["browser_addresses"],
        "fixture": FIXTURE_TOPOLOGY["fixture_addresses"],
        "forbidden_sink": FIXTURE_TOPOLOGY["forbidden_sink_addresses"],
        "dns_sink": FIXTURE_TOPOLOGY["dns_sink_addresses"],
    }
    if expected_volume_name is None:
        if volume is not None:
            raise ValueError("stale topology has an unauthorised policy volume")
    elif volume is not None:
        expected_volume_labels = {**expected_labels, "org.qcsd.role": POLICY_VOLUME_ROLE}
        volume_labels = volume.get("Labels")
        expected_mountpoint = (
            docker_root / "volumes" / expected_volume_name / "_data"
        ).as_posix()
        if (
            volume.get("Name") != expected_volume_name
            or volume.get("Driver") != "local"
            or volume.get("Scope") != "local"
            or (volume.get("Options") or {}) != {}
            or volume_labels != expected_volume_labels
            or volume.get("Mountpoint") != expected_mountpoint
        ):
            raise ValueError("stale policy volume is not safely attributable")
    by_role: dict[str, Mapping[str, Any]] = {}
    for item in containers:
        config = item.get("Config")
        host = item.get("HostConfig")
        state = item.get("State")
        network_settings = item.get("NetworkSettings")
        if not all(
            isinstance(value, Mapping)
            for value in (config, host, state, network_settings)
        ):
            raise ValueError("stale Docker container inspection is incomplete")
        labels = config.get("Labels")
        role = labels.get("org.qcsd.role") if isinstance(labels, Mapping) else None
        if role not in expected_roles or role in by_role:
            raise ValueError("stale Docker container roles are invalid")
        _validated_supervised_labels(
            labels,
            expected={**expected_labels, "org.qcsd.role": role},
            label="stale Docker container",
        )
        container_id = item.get("Id")
        expected_mounts: list[dict[str, Any]] = []
        if role == "browser" and expected_volume_name is not None:
            expected_mounts.append(
                {
                    "Type": "volume",
                    "Name": expected_volume_name,
                    "Destination": POLICY_VOLUME_MANAGED_DIRECTORY,
                    "RW": False,
                }
            )
        elif role == "policy_seed":
            expected_mounts.append(
                {
                    "Type": "volume",
                    "Name": expected_volume_name,
                    "Destination": "/qcsd-policy",
                    "RW": True,
                }
            )
        projected_mounts = []
        raw_mounts = item.get("Mounts")
        if isinstance(raw_mounts, list):
            projected_mounts = [
                {
                    "Type": mount.get("Type"),
                    "Name": mount.get("Name"),
                    "Destination": mount.get("Destination"),
                    "RW": mount.get("RW"),
                }
                for mount in raw_mounts
                if isinstance(mount, Mapping)
            ]
        expected_tmpfs = {
            "/tmp": (
                "rw,nosuid,nodev,noexec,mode=1777"
                if role == "policy_seed"
                else ROLE_TMPFS_OPTIONS
            )
        }
        if role != "fixture":
            expected_tmpfs[FIXTURE_TLS_MASK_DIRECTORY] = (
                FIXTURE_TLS_MASK_TMPFS_OPTIONS
            )
        expected_user = (
            r"[1-9][0-9]*:[1-9][0-9]*" if role == "browser" else r"0:0"
        )
        if (
            not isinstance(container_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or item.get("Image") != resume["prepare_image_id"]
            or not isinstance(raw_mounts, list)
            or len(projected_mounts) != len(raw_mounts)
            or projected_mounts != expected_mounts
            or state.get("Status")
            not in {"created", "running", "paused", "restarting", "exited", "dead"}
            or re.fullmatch(expected_user, str(config.get("User") or "0:0"))
            is None
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or (host.get("CapDrop") or []) != ["ALL"]
            or (host.get("CapAdd") or [])
            != (["CAP_NET_RAW"] if role == "observer" else [])
            or (host.get("SecurityOpt") or []) != ["no-new-privileges:true"]
            or (host.get("Tmpfs") or {}) != expected_tmpfs
            or (host.get("Dns") or [])
            != (FIXTURE_TOPOLOGY["browser_dns_servers"] if role == "browser" else [])
            or re.fullmatch(
                rf"/qcsd-be-{re.escape(cleanup['topology_token'])}-{suffixes[role]}",
                str(item.get("Name")),
            )
            is None
        ):
            raise ValueError("stale Docker container identity/isolation is invalid")
        networks = network_settings.get("Networks") or {}
        if not isinstance(networks, Mapping):
            raise ValueError("stale Docker container network state is invalid")
        if role == "policy_seed":
            if networks != {} or host.get("NetworkMode") != "none":
                raise ValueError("stale policy seeder is not network isolated")
        elif role == "observer":
            if networks != {} or re.fullmatch(
                r"container:[0-9a-f]{64}", str(host.get("NetworkMode"))
            ) is None:
                raise ValueError("stale observer does not share a browser namespace")
        else:
            if set(networks) != {"qcsd-browser-egress-v1"} or host.get(
                "NetworkMode"
            ) != "qcsd-browser-egress-v1":
                raise ValueError("stale Docker container has an unexpected attachment")
        by_role[role] = item

    networked_containers = [
        item
        for role, item in by_role.items()
        if role != "policy_seed"
    ]
    if networked_containers and network is None:
        raise ValueError("stale browser-egress containers have no canonical network")
    if expected_volume_name is not None and volume is None and (
        containers or network is not None
    ):
        raise ValueError("stale policy consumer has no bound policy volume")
    network_id: str | None = None
    if network is not None:
        network_id = network.get("Id")
        raw_members = network.get("Containers") or {}
        if (
            not isinstance(network_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
            or network.get("Name") != "qcsd-browser-egress-v1"
            or network.get("Driver") != "bridge"
            or network.get("Internal") is not True
            or network.get("Attachable") is not False
            or network.get("EnableIPv6") is not True
            or _validated_supervised_labels(
                network.get("Labels"),
                expected=expected_labels,
                label="stale canonical Docker network",
            )
            != expected_labels
            or not isinstance(raw_members, Mapping)
        ):
            raise ValueError("stale canonical Docker network is not safely attributable")
        direct_by_id = {
            item["Id"]: role for role, item in by_role.items() if role in direct_roles
        }
        if set(raw_members) != set(direct_by_id):
            raise ValueError("stale Docker network membership is not exact")
        for container_id, member in raw_members.items():
            role = direct_by_id[container_id]
            attachment = by_role[role]["NetworkSettings"]["Networks"][
                "qcsd-browser-egress-v1"
            ]
            expected_ipv4, expected_ipv6 = addresses[role]
            if (
                not isinstance(member, Mapping)
                or attachment.get("NetworkID") != network_id
                or attachment.get("EndpointID") != member.get("EndpointID")
                or attachment.get("IPAddress") != expected_ipv4
                or attachment.get("GlobalIPv6Address") != expected_ipv6
                or member.get("IPv4Address") != f"{expected_ipv4}/24"
                or member.get("IPv6Address") != f"{expected_ipv6}/96"
            ):
                raise ValueError("stale Docker endpoint binding is invalid")
    browser = by_role.get("browser")
    observer = by_role.get("observer")
    if observer is not None and browser is None:
        raise ValueError("stale observer has no bound browser namespace owner")
    if observer is not None and browser is not None and observer["HostConfig"].get(
        "NetworkMode"
    ) != f"container:{browser['Id']}":
        raise ValueError("stale observer namespace differs from the bound browser")
    _emit(
        {
            "schema_version": 1,
            "container_ids": [
                by_role[role]["Id"]
                for role in (
                    "policy_seed",
                    "observer",
                    "browser",
                    "fixture",
                    "forbidden_sink",
                    "dns_sink",
                )
                if role in by_role
            ],
            "network_id": network_id,
            "volume_name": (
                expected_volume_name if volume is not None else None
            ),
        }
    )


def _docker_projection(
    network: Mapping[str, Any],
    containers: object,
    volume: object,
    *,
    vector_id: str,
    prepare_image_id: str,
    browser_uid: int,
    browser_gid: int,
    attempt_topology: Mapping[str, Any],
    docker_root_dir: str,
    policy_file_inventory: object,
) -> dict[str, Any]:
    if not isinstance(containers, list) or len(containers) != 5:
        raise ValueError("Docker container inspection must contain five roles")
    expected_roles = {"browser", "observer", "fixture", "forbidden_sink", "dns_sink"}
    direct_roles = expected_roles - {"observer"}
    role_suffixes = {
        "browser": "browser",
        "observer": "observer",
        "fixture": "fixture",
        "forbidden_sink": "forbidden",
        "dns_sink": "dns",
    }
    labels = {
        "org.qcsd.owner": "qcsd-lab",
        "org.qcsd.study": "classifier-multiorigin100-v1",
        "org.qcsd.qualification": "browser-egress-qualification-v1",
        "org.qcsd.vector": vector_id,
        "org.qcsd.cohort-version": str(attempt_topology["cohort_version"]),
        "org.qcsd.foundation": attempt_topology["foundation_payload_sha256"],
        "org.qcsd.global-ordinal": str(attempt_topology["global_ordinal"]),
        "org.qcsd.attempt-number": str(attempt_topology["attempt_number"]),
        "org.qcsd.topology-token": attempt_topology["topology_token"],
    }
    role_values: dict[str, Any] = {}
    for item in containers:
        if not isinstance(item, Mapping):
            raise ValueError("Docker inspection contains a non-object container")
        config = item.get("Config", {})
        host = item.get("HostConfig", {})
        state = item.get("State", {})
        item_labels = config.get("Labels") or {}
        role = item_labels.get("org.qcsd.role")
        if role not in expected_roles:
            raise ValueError("Docker inspection contains an unknown browser-egress role")
        if role in role_values:
            raise ValueError("Docker inspection contains a duplicate browser-egress role")
        projected_labels = _validated_supervised_labels(
            item_labels,
            expected={**labels, "org.qcsd.role": role},
            label="Docker container",
        )
        if item.get("Name") != (
            f"/qcsd-be-{attempt_topology['topology_token']}-{role_suffixes[role]}"
        ):
            raise ValueError("Docker inspection contains an unbound topology name")
        networks = item.get("NetworkSettings", {}).get("Networks") or {}
        if not isinstance(networks, Mapping):
            raise ValueError("Docker container network attachments are invalid")
        network_attachments = sorted(
            (
                {
                    "name": name,
                    "network_id": attachment.get("NetworkID"),
                    "endpoint_id": attachment.get("EndpointID"),
                    "ipv4_address": attachment.get("IPAddress") or None,
                    "ipv6_address": attachment.get("GlobalIPv6Address") or None,
                }
                for name, attachment in networks.items()
                if isinstance(name, str) and isinstance(attachment, Mapping)
            ),
            key=lambda attachment: attachment["name"],
        )
        if len(network_attachments) != len(networks):
            raise ValueError("Docker container network attachments are malformed")
        canonical_attachment = next(
            (
                attachment
                for attachment in network_attachments
                if attachment["name"] == "qcsd-browser-egress-v1"
            ),
            {},
        )
        raw_cap_add = host.get("CapAdd") or []
        expected_raw_cap_add = ["CAP_NET_RAW"] if role == "observer" else []
        if raw_cap_add != expected_raw_cap_add:
            raise ValueError(f"browser-egress {role} raw Docker capabilities are invalid")
        role_values[role] = {
            "id": item.get("Id"),
            "image_id": item.get("Image"),
            "user": config.get("User") or "0:0",
            "privileged": host.get("Privileged"),
            "read_only_root": host.get("ReadonlyRootfs"),
            "cap_add": raw_cap_add,
            "cap_drop": host.get("CapDrop") or [],
            "security_options": host.get("SecurityOpt") or [],
            "network_mode": host.get("NetworkMode"),
            "network_attachments": network_attachments,
            "ipv4_address": canonical_attachment.get("ipv4_address"),
            "ipv6_address": canonical_attachment.get("ipv6_address"),
            "labels": projected_labels,
            "mounts": sorted(
                (
                    {
                        "type": mount.get("Type"),
                        "name": mount.get("Name") if mount.get("Type") == "volume" else None,
                        "destination": mount.get("Destination"),
                        "rw": mount.get("RW"),
                    }
                    for mount in item.get("Mounts", [])
                ),
                key=lambda mount: str(mount["destination"]),
            ),
            "tmpfs": sorted(
                (
                    {"destination": destination, "options": options}
                    for destination, options in (host.get("Tmpfs") or {}).items()
                ),
                key=lambda item: item["destination"],
            ),
            "dns_servers": host.get("Dns") or [],
            "running": state.get("Running"),
            "exit_code": state.get("ExitCode"),
        }
    if set(role_values) != expected_roles:
        raise ValueError("Docker inspection omits a browser-egress role")
    raw_members = network.get("Containers") or {}
    if not isinstance(raw_members, Mapping):
        raise ValueError("Docker network member inventory is invalid")
    roles_by_container_id = {
        role_values[role]["id"]: role for role in direct_roles
    }
    if (
        len(roles_by_container_id) != len(direct_roles)
        or set(raw_members) != set(roles_by_container_id)
    ):
        raise ValueError("Docker network member inventory is not the exact four roles")
    members = {}
    for container_id, member in raw_members.items():
        if not isinstance(member, Mapping):
            raise ValueError("Docker network member entry is invalid")
        role = roles_by_container_id[container_id]
        members[role] = {
            "container_id": container_id,
            "endpoint_id": member.get("EndpointID"),
            "ipv4_address": member.get("IPv4Address") or None,
            "ipv6_address": member.get("IPv6Address") or None,
        }
    projected_network_labels = _validated_supervised_labels(
        network.get("Labels"),
        expected=labels,
        label="Docker network",
    )
    network_projection = {
        "id": network.get("Id"),
        "name": network.get("Name"),
        "driver": network.get("Driver"),
        "internal": network.get("Internal"),
        "attachable": network.get("Attachable"),
        "enable_ipv6": network.get("EnableIPv6"),
        "ipam_config": [
            {"subnet": item.get("Subnet")}
            for item in network.get("IPAM", {}).get("Config", [])
        ],
        "labels": projected_network_labels,
        "members": members,
    }
    expected_volume_name = policy_volume_name(
        vector_id=vector_id, attempt_topology=attempt_topology
    )
    if expected_volume_name is None:
        if volume is not None or policy_file_inventory is not None:
            raise ValueError("Docker inspection contains an unauthorised policy volume")
        volume_projection = None
    else:
        if (
            not isinstance(volume, list)
            or len(volume) != 1
            or not isinstance(volume[0], Mapping)
        ):
            raise ValueError("Docker policy-volume inspection is invalid")
        raw_volume = volume[0]
        expected_mountpoint = (
            Path(docker_root_dir) / "volumes" / expected_volume_name / "_data"
        ).as_posix()
        if raw_volume.get("Mountpoint") != expected_mountpoint:
            raise ValueError("Docker policy-volume mountpoint is not canonical")
        volume_projection = {
            "schema_version": POLICY_VOLUME_PROJECTION_SCHEMA_VERSION,
            "name": raw_volume.get("Name"),
            "driver": raw_volume.get("Driver"),
            "scope": raw_volume.get("Scope"),
            "labels": raw_volume.get("Labels") or {},
            "options": raw_volume.get("Options") or {},
            "mountpoint_is_canonical": True,
            "mountpoint_sha256": hashlib.sha256(
                expected_mountpoint.encode("utf-8")
            ).hexdigest(),
            "file_inventory": policy_file_inventory,
        }
    value = {
        "schema_version": DOCKER_INSPECT_PROJECTION_SCHEMA_VERSION,
        "network": network_projection,
        "containers": role_values,
        "policy_volume": volume_projection,
    }
    return validate_docker_inspect_projection(
        value,
        vector_id=vector_id,
        prepare_image_id=prepare_image_id,
        browser_uid=browser_uid,
        browser_gid=browser_gid,
        attempt_topology=attempt_topology,
        docker_root_dir=docker_root_dir,
    )


def _common_vector(subparsers: Any, name: str, function: Any) -> None:
    parser = subparsers.add_parser(name)
    parser.add_argument("--vector-id", required=True)
    parser.set_defaults(function=function)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="qcsd-browser-egress-qualification")
    commands = result.add_subparsers(dest="command", required=True)
    _common_vector(commands, "actor", _actor)
    _common_vector(commands, "control", _control)
    _common_vector(commands, "fixture", _fixture)
    _common_vector(commands, "forbidden-sink", _forbidden_sink)
    _common_vector(commands, "dns-sink", _dns_sink)
    observer = commands.add_parser("observer")
    observer.add_argument("--vector-id", required=True)
    observer.add_argument("--pcap", type=Path, required=True)
    observer.add_argument("--evidence-relative", required=True)
    observer.set_defaults(function=_observer)
    live_docker = commands.add_parser("live-docker-binding")
    live_docker.add_argument("--docker-version-json", required=True)
    live_docker.add_argument("--docker-info-json", required=True)
    live_docker.add_argument("--context", required=True)
    live_docker.add_argument("--endpoint", required=True)
    live_docker.add_argument("--server-id", required=True)
    live_docker.set_defaults(function=_live_docker_binding)
    stale = commands.add_parser("stale-topology-cleanup-plan")
    stale.add_argument("--resume-plan-json", required=True)
    stale.add_argument("--network-inspect-json", required=True)
    stale.add_argument("--container-inspect-json", required=True)
    stale.add_argument("--volume-inspect-json", required=True)
    stale.set_defaults(function=_stale_topology_cleanup_plan)
    foundation = commands.add_parser("foundation")
    foundation.add_argument("--cohort-version", type=int, required=True)
    foundation.add_argument("--build-execution-receipt", type=Path, required=True)
    foundation.add_argument("--result-root", type=Path, required=True)
    foundation.add_argument("--prepare-repo-digests-json", required=True)
    foundation.add_argument("--live-docker-json", required=True)
    foundation.set_defaults(function=_foundation)
    next_parser = commands.add_parser("next")
    next_parser.add_argument("--result-root", type=Path, required=True)
    next_parser.set_defaults(function=_next)
    begin = commands.add_parser("begin-attempt")
    begin.add_argument("--result-root", type=Path, required=True)
    begin.add_argument("--vector-id", required=True)
    begin.add_argument("--next-plan-json", required=True)
    begin.add_argument("--started-at", required=True)
    begin.set_defaults(function=_begin_attempt)
    admit = commands.add_parser("admit-resume")
    admit.add_argument("--cohort-version", type=int, required=True)
    admit.add_argument("--build-execution-receipt", type=Path, required=True)
    admit.add_argument("--result-root", type=Path, required=True)
    admit.add_argument("--live-docker-json", required=True)
    admit.set_defaults(function=_admit_resume)
    reconcile = commands.add_parser("reconcile-filesystem")
    reconcile.add_argument("--cohort-version", type=int, required=True)
    reconcile.add_argument("--build-execution-receipt", type=Path, required=True)
    reconcile.add_argument("--result-root", type=Path, required=True)
    reconcile.add_argument("--live-docker-json", required=True)
    reconcile.set_defaults(function=_reconcile_filesystem)
    recover = commands.add_parser("recover-resume")
    recover.add_argument("--cohort-version", type=int, required=True)
    recover.add_argument("--build-execution-receipt", type=Path, required=True)
    recover.add_argument("--result-root", type=Path, required=True)
    recover.add_argument("--live-docker-json", required=True)
    recover.set_defaults(function=_recover_resume)
    assemble = commands.add_parser("assemble")
    assemble.add_argument("--result-root", type=Path, required=True)
    assemble.add_argument("--vector-id", required=True)
    assemble.add_argument("--next-json", type=Path, required=True)
    assemble.add_argument("--actor-json", type=Path, required=True)
    assemble.add_argument("--forbidden-json", type=Path, required=True)
    assemble.add_argument("--dns-json", type=Path, required=True)
    assemble.add_argument("--fixture-json", type=Path, required=True)
    assemble.add_argument("--capture-json", type=Path, required=True)
    assemble.add_argument("--runtime-json", type=Path, required=True)
    assemble.add_argument("--started-at", required=True)
    assemble.add_argument("--finished-at", required=True)
    assemble.add_argument("--validate-only", action="store_true")
    assemble.set_defaults(function=_assemble)
    attempt_status = commands.add_parser("attempt-status")
    attempt_status.add_argument("--result-root", type=Path, required=True)
    attempt_status.add_argument("--vector-id", required=True)
    attempt_status.add_argument("--next-json", type=Path, required=True)
    attempt_status.set_defaults(function=_attempt_status)
    failure = commands.add_parser("record-failure")
    failure.add_argument("--result-root", type=Path, required=True)
    failure.add_argument("--vector-id", required=True)
    failure.add_argument("--next-json", type=Path, required=True)
    failure.add_argument("--started-at", required=True)
    failure.add_argument("--finished-at", required=True)
    failure.add_argument(
        "--verdict",
        choices=("operational-failure", "semantic-failure"),
        required=True,
    )
    failure.add_argument("--failure-code", required=True)
    failure.add_argument("--stage", required=True)
    failure.set_defaults(function=_record_failure)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--result-root", type=Path, required=True)
    finalize.set_defaults(function=_finalize)
    verify = commands.add_parser("verify")
    verify.add_argument("--cohort-version", type=int, required=True)
    verify.add_argument("--build-execution-receipt", type=Path, required=True)
    verify.add_argument("--result-root", type=Path, required=True)
    verify.add_argument("--live-docker-json", required=True)
    verify.set_defaults(function=_verify)
    project = commands.add_parser("project-runtime")
    project.add_argument("--result-root", type=Path, required=True)
    project.add_argument("--vector-id", required=True)
    project.add_argument("--browser-uid", type=int, required=True)
    project.add_argument("--browser-gid", type=int, required=True)
    project.add_argument("--global-ordinal", type=int, required=True)
    project.add_argument("--attempt-number", type=int, required=True)
    project.add_argument("--started-at", required=True)
    project.add_argument("--actor-json", type=Path, required=True)
    project.add_argument("--network-inspect-json", type=Path, required=True)
    project.add_argument("--container-inspect-json", type=Path, required=True)
    project.add_argument("--volume-inspect-json", type=Path, required=True)
    project.add_argument("--fixture-json", type=Path, required=True)
    project.add_argument("--live-docker-json", required=True)
    project.set_defaults(function=_project_runtime)
    return result


def main(argv: Sequence[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.command in SIGNAL_COORDINATED_COMMANDS:
        _run_signal_coordinated_role(args.function, args)
    else:
        args.function(args)


if __name__ == "__main__":
    main()
