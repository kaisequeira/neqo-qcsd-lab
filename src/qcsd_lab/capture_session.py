"""One Neqo invocation observed by one direct packet capture.

This module deliberately knows nothing about campaigns, sample indexes, result
directories, retries, or evidence seals.  The orchestrator supplies a frozen
workload and a small capture context; this module returns the diagnostics for
that single attempt.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from .capture import (
    OFFLOAD_DISABLED,
    REQUIRED_OFFLOAD_FEATURES,
    extract_trace,
    offload_evidence_is_valid,
    parse_offload_state,
    recompute_offload_verification,
    tuple_filter,
    udp_ceiling_evidence,
    write_normalized_trace,
)
from .fidelity import reconcile_direct_runner_artifacts
from .manifest import https_origin
from .parameters import (
    PARAMETER_ARTIFACT_NAME,
    PARAMETER_PROVENANCE_ARTIFACT_NAME,
    validate_run_parameter_binding,
)
from .util import (
    ProcessTimeoutError,
    atomic_json,
    load_json,
    neqo_host_timeout,
    padding_event_guard_triggered,
    run,
    sha256_file,
)

NEQO_CLIENT = os.environ.get("NEQO_QCSD_CLIENT", "/usr/local/bin/neqo-qcsd-client")
STATIC_MODES = {"chaff-only", "chaff-and-shape"}
PARAMETER_FLAG_BY_KIND = {
    "traffic_morphing": "--morphing-matrix",
    "wtf_pad": "--wtf-pad-histograms",
    "walkie_talkie": "--walkie-talkie-molded",
}
SUPPORTED_DEFENSE_KINDS = {
    "none",
    "static",
    "front",
    "tamaraw",
    *PARAMETER_FLAG_BY_KIND,
}
RUNNER_KIND_BY_KIND = {
    "traffic_morphing": "traffic-morphing",
    "wtf_pad": "wtf-pad",
    "walkie_talkie": "walkie-talkie",
}


@dataclass(frozen=True)
class Limits:
    """Resource and retry limits shared by the orchestrator and one attempt."""

    timeout_seconds: int = 45
    max_response_bytes: int = 512 * 1024
    capture_seconds: int = 60
    capture_megabytes: int = 64
    max_attempts: int = 3
    per_origin_cooldown_seconds: float = 30.0
    settle_seconds: float = 1.0

    def as_dict(self) -> dict[str, int | float]:
        return asdict(self)


@dataclass(frozen=True)
class Defense:
    """A resolved runner defense, including any frozen external artifact."""

    name: str
    kind: str
    baseline: bool
    schedule: str | None = None
    schedule_path: Path | None = None
    schedule_sha256: str | None = None
    mode: str | None = None
    parameters: str | None = None
    parameters_path: Path | None = None
    parameters_sha256: str | None = None
    parameters_provenance: str | None = None
    parameters_provenance_path: Path | None = None
    parameters_provenance_sha256: str | None = None
    parameters_input_policy: str | None = None

    def as_dict(self, *, internal: bool = False) -> dict[str, Any]:
        result = asdict(self)
        result.pop("schedule_path")
        result.pop("parameters_path")
        result.pop("parameters_provenance_path")
        if internal and self.schedule_path:
            result["schedule_path"] = str(self.schedule_path)
        if internal and self.parameters_path:
            result["parameters_path"] = str(self.parameters_path)
        if internal and self.parameters_provenance_path:
            result["parameters_provenance_path"] = str(self.parameters_provenance_path)
        return {key: value for key, value in result.items() if value is not None}


class CaptureContext(Protocol):
    """The small portion of campaign state needed for one runner invocation."""

    qcsd_profile: str
    request_policy: str
    limits: Limits
    udp_payload_ceiling: int


@dataclass(frozen=True)
class _CaptureView:
    id: str
    interface: str
    link_type: str
    length_basis: str
    primary: bool

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["kind"] = self.id
        return result


_DIRECT_CAPTURE_VIEW = _CaptureView(
    id="direct-quic",
    interface="eth0",
    link_type="Ethernet",
    length_basis="frame.len",
    primary=True,
)


def slug(value: str) -> str:
    rendered = re.sub(r"[^A-Za-z0-9._-]", "-", value).strip("-")
    if rendered and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", rendered):
        rendered = ""
    if not rendered:
        raise ValueError(f"identifier has no filesystem-safe characters: {value!r}")
    return rendered


def stable_digest(*parts: object) -> str:
    digest = hashlib.sha256()
    for part in parts:
        encoded = str(part).encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _clock_anchor() -> dict[str, int]:
    """Sample the two host clocks bracketing one runner invocation."""

    return {
        "monotonic_ns": time.monotonic_ns(),
        "realtime_unix_ns": time.time_ns(),
    }


def _manifest_origins(manifest: dict[str, Any]) -> list[str]:
    origins = {https_origin(resource["url"]) for resource in manifest.get("resources", [])}
    return sorted(origin for origin in origins if origin is not None)


def _respect_origin_cooldown(
    manifest: dict[str, Any], context: CaptureContext, last: dict[str, float]
) -> None:
    origins = _manifest_origins(manifest)
    cooldown = context.limits.per_origin_cooldown_seconds
    wait = max(
        (last.get(origin, 0.0) + cooldown - time.monotonic() for origin in origins),
        default=0.0,
    )
    if wait > 0:
        time.sleep(wait)


def _mark_origin_completed(manifest: dict[str, Any], last: dict[str, float]) -> None:
    now = time.monotonic()
    for origin in _manifest_origins(manifest):
        last[origin] = now


def _offload_metadata(interface: str) -> dict[str, Any]:
    before = run(["ethtool", "-k", interface], check=False)
    changes = {
        short_name: run(
            ["ethtool", "-K", interface, feature, "off"],
            check=False,
        ).returncode
        for short_name, feature in REQUIRED_OFFLOAD_FEATURES.items()
    }
    after = run(["ethtool", "-k", interface], check=False)
    evidence = {
        "interface": interface,
        "requested": dict(OFFLOAD_DISABLED),
        "query_returncodes": {"before": before.returncode, "after": after.returncode},
        "change_returncodes": changes,
        "before_state": parse_offload_state(before.stdout),
        "after_state": parse_offload_state(after.stdout),
        "before_sha256": stable_digest(before.stdout),
        "after_sha256": stable_digest(after.stdout),
    }
    evidence["verified"] = recompute_offload_verification(evidence, interface=interface)
    return evidence


def _collect_attempt(
    attempt: Path,
    manifest: Path,
    chaff_manifest_or_workload_id: Path | str | None,
    workload_id_or_defense: str | Defense,
    defense_or_seed: Defense | int,
    seed_or_context: int | CaptureContext,
    context: CaptureContext | None = None,
    *,
    application_workload_source: Path | None = None,
) -> dict[str, Any]:
    """Capture and validate one Neqo run without promoting or sealing it."""

    # The explicit chaff path was added without invalidating the narrow
    # six-argument collector seam used by historical/read-only fixtures.
    if context is None:
        chaff_manifest: Path | None = None
        workload_id = str(chaff_manifest_or_workload_id)
        defense = workload_id_or_defense
        seed = defense_or_seed
        context = seed_or_context
    else:
        chaff_manifest = (
            chaff_manifest_or_workload_id
            if isinstance(chaff_manifest_or_workload_id, Path)
            else None
        )
        workload_id = str(workload_id_or_defense)
        defense = defense_or_seed
        seed = seed_or_context
    if not isinstance(defense, Defense) or type(seed) is not int or not hasattr(context, "limits"):
        raise TypeError("invalid capture-attempt arguments")
    if defense.baseline:
        if chaff_manifest is not None or application_workload_source is not None:
            raise ValueError("baseline capture forbids qualified chaff inputs")
    elif chaff_manifest is None or application_workload_source is None:
        raise ValueError("every defended capture requires prepared source and qualified chaff")

    if (
        defense.parameters_path is not None
        and defense.parameters_sha256 is not None
        and sha256_file(defense.parameters_path) != defense.parameters_sha256
    ):
        raise ValueError("defense parameter file changed after campaign resolution")
    if (
        defense.parameters_provenance_path is not None
        and defense.parameters_provenance_sha256 is not None
        and sha256_file(defense.parameters_provenance_path) != defense.parameters_provenance_sha256
    ):
        raise ValueError("defense parameter provenance changed after campaign resolution")

    attempt.mkdir(parents=True, exist_ok=False)
    diagnostics = attempt / "diagnostics"
    captures = attempt / "captures"
    traces = attempt / "traces"
    neqo = attempt / "neqo"
    for directory in (diagnostics, captures, traces):
        directory.mkdir()

    view = _DIRECT_CAPTURE_VIEW
    offloads = [_offload_metadata(view.interface)]
    offloads_valid = all(
        offload_evidence_is_valid(item, interface=view.interface) for item in offloads
    )
    raw = diagnostics / f"{view.id}-raw.pcapng"
    capture_log = diagnostics / f"dumpcap-{view.id}.log"
    handle = capture_log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            "dumpcap",
            "-q",
            "-i",
            view.interface,
            "-f",
            "udp",
            "-w",
            str(raw),
            "-a",
            f"duration:{context.limits.capture_seconds}",
            "-a",
            f"filesize:{context.limits.capture_megabytes * 1024}",
        ],
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    capture_active_through_settle = False
    try:
        _wait_for_capture_start(process, capture_log)
        clock_start = _clock_anchor()
        client, runner_timed_out, runner_host_timeout_seconds = _run_neqo_client(
            _client_command(
                manifest,
                chaff_manifest,
                workload_id,
                defense,
                seed,
                context,
                neqo,
                application_workload_source=application_workload_source,
            ),
            log=diagnostics / "neqo-client.log",
            configured_timeout_seconds=context.limits.timeout_seconds,
        )
        clock_end = _clock_anchor()
        capture_clock_anchors = {
            "start_realtime_unix_ns": clock_start["realtime_unix_ns"],
            "start_monotonic_ns": clock_start["monotonic_ns"],
            "end_realtime_unix_ns": clock_end["realtime_unix_ns"],
            "end_monotonic_ns": clock_end["monotonic_ns"],
        }
        if neqo.is_dir():
            _copy_defense_parameter_artifacts(defense, neqo)
        if context.limits.settle_seconds:
            time.sleep(context.limits.settle_seconds)
        capture_active_through_settle = process.poll() is None
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)
        handle.close()

    run_json = neqo / "run.json"
    runner_output_error: str | None = None
    try:
        run_data = load_json(run_json) if run_json.exists() else {}
    except (OSError, ValueError) as error:
        if not runner_timed_out:
            raise
        run_data = {}
        runner_output_error = f"run.json was incomplete after the host timeout: {error}"
    if runner_timed_out and not run_json.exists():
        runner_output_error = "run.json was not produced before the host timeout"
    manifest_data = load_json(manifest)
    expected_resource_ids = {resource["id"] for resource in manifest_data["resources"]}
    endpoints = run_data.get("endpoints", [])
    completion_status = run_data.get("completion_status")
    responses = run_data.get("responses", [])
    runner_complete = _runner_result_complete(run_data, expected_resource_ids)
    try:
        _validate_run_binding(
            run_data,
            manifest=manifest,
            chaff_manifest=chaff_manifest,
            application_workload_source=application_workload_source,
            workload_id=workload_id,
            defense=defense,
            seed=seed,
            context=context,
        )
        runner_binding_valid = True
    except ValueError as error:
        runner_binding_valid = False
        runner_binding_error = str(error)
    guard_triggered = padding_event_guard_triggered(run_data)
    expected_endpoint_count = len(_manifest_origins(manifest_data))
    endpoint_count_valid = len(endpoints) == expected_endpoint_count
    failures: list[dict[str, Any]] = []

    output = captures / f"{view.id}.pcapng"
    display_filter = tuple_filter(endpoints) if endpoints else "udp"
    filtered = run(
        ["tshark", "-r", str(raw), "-Y", display_filter, "-w", str(output)],
        log=diagnostics / f"filter-{view.id}.log",
        check=False,
    )
    capinfos = run(["capinfos", "-E", "-c", "-s", str(output)], check=False)
    limit = context.limits.capture_megabytes * 1024 * 1024
    truncated = raw.exists() and raw.stat().st_size >= int(limit * 0.99)
    try:
        trace = extract_trace(output, endpoints)
    except (KeyError, RuntimeError, ValueError) as error:
        trace = []
        failures.append({"view": view.id, "primary": True, "reason": str(error)})
    trace_path = traces / f"{view.id}.csv"
    if trace:
        write_normalized_trace(trace_path, trace)

    direct_runner_reconciliation_valid = False
    direct_runner_reconciliation: dict[str, Any] | None = None
    if runner_complete and trace_path.is_file():
        try:
            reconciliation = reconcile_direct_runner_artifacts(
                run_json,
                neqo / "packets.csv",
                trace_path,
                clock_anchors=capture_clock_anchors,
            )
            direct_runner_reconciliation_valid = reconciliation.evidence_eligible
            direct_runner_reconciliation = {
                **reconciliation.metrics,
                "evidence_eligible": reconciliation.evidence_eligible,
                "limitations": list(reconciliation.limitations),
            }
        except (OSError, ValueError) as error:
            failures.append(
                {
                    "view": view.id,
                    "primary": True,
                    "reason": f"direct/runner reconciliation failed: {error}",
                }
            )

    resolved_configuration = run_data.get("resolved_configuration")
    resolved_udp_payload_ceiling = (
        resolved_configuration.get("max_udp_payload_size")
        if isinstance(resolved_configuration, dict)
        else None
    )
    ceiling_evidence = udp_ceiling_evidence(trace, context.udp_payload_ceiling)
    runner_ceiling_valid = resolved_udp_payload_ceiling == context.udp_payload_ceiling
    ceiling_evidence.update(
        {
            "runner_resolved_udp_payload_ceiling": resolved_udp_payload_ceiling,
            "runner_binding_valid": runner_ceiling_valid,
            "valid": bool(ceiling_evidence["valid"] and runner_ceiling_valid),
        }
    )
    link_valid = view.link_type.lower() in capinfos.stdout.lower()
    valid = (
        process.returncode in {0, 2}
        and filtered.returncode == 0
        and capinfos.returncode == 0
        and output.is_file()
        and output.stat().st_size > 0
        and bool(trace)
        and not truncated
        and capture_active_through_settle
        and link_valid
        and offloads_valid
        and ceiling_evidence["valid"]
        and direct_runner_reconciliation_valid
    )
    if not valid:
        failures.append(
            {
                "view": view.id,
                "primary": True,
                "reason": "capture validation failed",
                "dumpcap_returncode": process.returncode,
                "filter_returncode": filtered.returncode,
                "capinfos_returncode": capinfos.returncode,
                "truncated": truncated,
                "capture_active_through_settle": capture_active_through_settle,
                "link_type_valid": link_valid,
                "capture_offloads_valid": offloads_valid,
                "udp_payload_ceiling_valid": ceiling_evidence["valid"],
                "direct_runner_reconciliation_valid": direct_runner_reconciliation_valid,
            }
        )

    record = {
        **view.as_dict(),
        "flow_filter": "udp filtered to the exact Neqo endpoint tuples",
        "direction_rule": "Neqo local endpoint tuple is outgoing",
        "capture_boundary": "before Neqo through defense tail and settle interval",
        "packet_count": len(trace),
        "truncated": truncated,
        "capture_active_through_settle": capture_active_through_settle,
        "capture_path": f"captures/{view.id}.pcapng",
        "trace_path": f"traces/{view.id}.csv",
        "capture_sha256": sha256_file(output) if output.exists() else None,
        "trace_sha256": sha256_file(trace_path) if trace_path.exists() else None,
        "pcapng_bytes": output.stat().st_size if output.exists() else 0,
        "udp_payload_ceiling_evidence": ceiling_evidence,
        "capture_offload_evidence": offloads[0],
        "capture_clock_anchors": capture_clock_anchors,
        "direct_runner_reconciliation": direct_runner_reconciliation,
        "valid": valid,
    }
    success = (
        not runner_timed_out
        and client.returncode == 0
        and runner_complete
        and runner_binding_valid
        and endpoint_count_valid
        and valid
    )
    result = {
        "success": success,
        "runner_returncode": client.returncode,
        "runner_timed_out": runner_timed_out,
        "runner_host_timeout_seconds": runner_host_timeout_seconds,
        "runner_output_error": runner_output_error,
        "runner_completion_status": completion_status,
        "runner_complete": runner_complete,
        "runner_binding_valid": runner_binding_valid,
        "endpoint_count": len(endpoints),
        "expected_endpoint_count": expected_endpoint_count,
        "endpoint_count_valid": endpoint_count_valid,
        "views": [record],
        "offloads": offloads,
        "defense_diagnostics": run_data.get("defense_diagnostics"),
        "operationally_valid": not guard_triggered,
        "failure": (
            None
            if success
            else {
                "stage": (
                    "runner-timeout"
                    if runner_timed_out
                    else (
                        "runner-binding"
                        if not runner_binding_valid
                        else (
                            "capture"
                            if client.returncode == 0 and runner_complete and endpoint_count_valid
                            else "runner"
                        )
                    )
                ),
                "details": [
                    {
                        "runner_returncode": client.returncode,
                        "runner_timed_out": runner_timed_out,
                        "runner_host_timeout_seconds": runner_host_timeout_seconds,
                        "runner_output_error": runner_output_error,
                        "completion_status": completion_status,
                        "runner_binding_error": (
                            None if runner_binding_valid else runner_binding_error
                        ),
                        "operational_failure": (
                            "wtf_pad_padding_event_guard_triggered" if guard_triggered else None
                        ),
                        "defense_diagnostics": run_data.get("defense_diagnostics"),
                        "incomplete_resources": [
                            response.get("resource_id")
                            for response in responses
                            if response.get("complete") is not True
                            or response.get("outcome") != "succeeded"
                        ],
                    },
                    *[item for item in failures if item.get("primary")],
                ],
            }
        ),
    }
    atomic_json(attempt / "attempt.json", result)
    return result


def _run_neqo_client(
    command: list[str],
    *,
    log: Path,
    configured_timeout_seconds: int,
) -> tuple[subprocess.CompletedProcess[str], bool, float]:
    """Run the collector client under an independent host-side deadline."""

    host_timeout = neqo_host_timeout(configured_timeout_seconds)
    try:
        result = run(command, log=log, check=False, timeout=host_timeout)
    except ProcessTimeoutError as error:
        return error.result, True, host_timeout
    return result, False, host_timeout


def _validate_run_binding(
    run_data: dict[str, Any],
    *,
    manifest: Path,
    chaff_manifest: Path | None = None,
    application_workload_source: Path | None = None,
    workload_id: str,
    defense: Defense,
    seed: int,
    context: CaptureContext,
) -> None:
    """Bind the runner receipt to every immutable launch input."""

    resolved = run_data.get("resolved_configuration")
    resolved_defense = resolved.get("defense") if isinstance(resolved, dict) else None
    if (
        run_data.get("seed") != seed
        or run_data.get("request_policy") != context.request_policy
        or run_data.get("workload_hash_sha256") != sha256_file(manifest)
        or run_data.get("max_response_bytes") != context.limits.max_response_bytes
        or not isinstance(resolved, dict)
        or resolved.get("max_udp_payload_size") != context.udp_payload_ceiling
        or not isinstance(resolved_defense, dict)
        or resolved_defense.get("kind") != defense.kind
    ):
        raise ValueError("runner receipt does not match the frozen sample inputs")
    expected_chaff_hash = (
        None if defense.baseline or chaff_manifest is None else sha256_file(chaff_manifest)
    )
    if defense.baseline:
        if chaff_manifest is not None or application_workload_source is not None:
            raise ValueError("baseline runner binding forbids qualified chaff inputs")
    elif chaff_manifest is None or application_workload_source is None:
        raise ValueError("defended runner binding requires prepared source and qualified chaff")
    if defense.baseline and (
        run_data.get("chaff_manifest_hash_sha256") is not None
        or run_data.get("chaff_responses", []) != []
    ):
        raise ValueError("baseline runner receipt contains unexpected chaff inputs")
    if (
        chaff_manifest is not None
        and run_data.get("chaff_manifest_hash_sha256") != expected_chaff_hash
    ):
        raise ValueError("runner chaff-manifest receipt does not match the frozen sample inputs")
    if chaff_manifest is not None:
        if application_workload_source is None or run_data.get(
            "application_workload_source_hash_sha256"
        ) != sha256_file(application_workload_source):
            raise ValueError("runner prepared application-source receipt is invalid")
        _validate_chaff_response_receipts(run_data, chaff_manifest)
    elif run_data.get("application_workload_source_hash_sha256") is not None:
        raise ValueError("runner receipt contains an unexpected prepared application source")
    if defense.kind in {"traffic_morphing", "walkie_talkie"} and (
        resolved_defense.get("workload_id") != workload_id
    ):
        raise ValueError("runner receipt does not match the frozen workload identity")
    parameter_path = defense.parameters_path or defense.schedule_path
    parameter_sha256 = defense.parameters_sha256 or defense.schedule_sha256
    if parameter_path is not None:
        validate_run_parameter_binding(
            run_data,
            kind=defense.kind,
            sha256=parameter_sha256,
            expected_path=parameter_path,
            expected_workload_id=(
                workload_id if defense.kind in {"traffic_morphing", "walkie_talkie"} else None
            ),
        )
    elif run_data.get("defense_parameters") is not None:
        raise ValueError("runner receipt contains unexpected defense parameters")


def _validate_chaff_response_receipts(run_data: dict[str, Any], chaff_manifest_path: Path) -> None:
    """Recompute every runtime chaff identity claim from the frozen manifest."""

    manifest = load_json(chaff_manifest_path)
    resources = manifest.get("resources")
    receipts = run_data.get("chaff_responses")
    if not isinstance(resources, list) or len(resources) != 1 or not isinstance(receipts, list):
        raise ValueError("runner chaff response receipt has an invalid schema")
    resource = resources[0]
    if not isinstance(resource, dict):
        raise ValueError("frozen chaff manifest resource is malformed")
    qualification = resource.get("chaff_qualification")
    if not isinstance(qualification, dict):
        raise ValueError("frozen chaff manifest lacks qualification identity")
    expected = qualification.get("expected_response")
    if not isinstance(expected, dict):
        raise ValueError("frozen chaff manifest lacks expected response identity")
    match_fields = (
        "status_match",
        "content_encoding_match",
        "body_bytes_match",
        "body_sha256_match",
        "identity_verified",
    )
    request_ids: set[int] = set()
    for receipt in receipts:
        if not isinstance(receipt, dict) or set(receipt) != {
            "resource_id",
            "request_id",
            "url",
            "request_headers",
            "request_stream_bytes",
            "expected_request_stream_bytes",
            "response_headers",
            "status",
            "content_encoding",
            "bytes",
            "body_sha256",
            "complete",
            "status_match",
            "content_encoding_match",
            "body_bytes_match",
            "body_sha256_match",
            "identity_verified",
            "outcome",
        }:
            raise ValueError("runner chaff response receipt is malformed")
        request_id = receipt.get("request_id")
        if type(request_id) is not int or request_id < 0 or request_id in request_ids:
            raise ValueError("runner chaff response request identity is invalid")
        request_ids.add(request_id)
        if (
            receipt.get("resource_id") != resource.get("id")
            or receipt.get("url") != resource.get("url")
            or receipt.get("request_headers") != resource.get("headers")
            or receipt.get("request_stream_bytes") != qualification.get("request_stream_bytes")
            or receipt.get("expected_request_stream_bytes")
            != qualification.get("request_stream_bytes")
            or not isinstance(receipt.get("response_headers"), list)
            or any(
                not isinstance(header, list)
                or len(header) != 2
                or any(not isinstance(item, str) for item in header)
                for header in receipt["response_headers"]
            )
            or type(receipt.get("bytes")) is not int
            or receipt["bytes"] < 0
        ):
            raise ValueError("runner chaff response does not match the qualified request")
        raw_statuses = [
            value for name, value in receipt["response_headers"] if name.lower() == ":status"
        ]
        raw_encodings = [
            value
            for name, value in receipt["response_headers"]
            if name.lower() == "content-encoding"
        ]
        if raw_statuses:
            if len(raw_statuses) != 1:
                raise ValueError("runner chaff response headers contradict qualified status")
            try:
                raw_status = int(raw_statuses[0])
            except ValueError:
                raise ValueError(
                    "runner chaff response headers contradict qualified status"
                ) from None
            if str(raw_status) != raw_statuses[0] or raw_status != expected.get("status"):
                raise ValueError("runner chaff response headers contradict qualified status")
        elif receipt.get("complete") is True:
            raise ValueError("completed chaff response lacks raw qualified status evidence")
        if raw_encodings:
            normalized_encodings = [value.strip().lower() for value in raw_encodings]
            if (
                len(normalized_encodings) != 1
                or "," in normalized_encodings[0]
                or normalized_encodings[0] != expected.get("content_encoding")
            ):
                raise ValueError(
                    "runner chaff response headers contradict qualified content encoding"
                )
        elif receipt["response_headers"] and expected.get("content_encoding") != "identity":
            # Once any final response headers have been observed, absence of
            # Content-Encoding has the wire meaning identity.
            raise ValueError("runner chaff response headers contradict qualified content encoding")
        if receipt.get("complete") is True:
            if (
                receipt.get("status") != expected.get("status")
                or receipt.get("content_encoding") != expected.get("content_encoding")
                or receipt.get("bytes") != expected.get("body_bytes")
                or receipt.get("body_sha256") != expected.get("body_sha256")
                or any(receipt.get(field) is not True for field in match_fields)
                or receipt.get("outcome") != "succeeded"
            ):
                raise ValueError("completed chaff response contradicts its qualified identity")
        elif (
            receipt.get("complete") is not False
            or receipt.get("status") is not None
            or receipt.get("content_encoding") is not None
            or receipt.get("body_sha256") is not None
            or receipt["bytes"] > expected.get("body_bytes")
            or any(receipt.get(field) is not None for field in match_fields)
            or receipt.get("outcome") not in {"incomplete", "reset", "endpoint_closed"}
        ):
            raise ValueError("partial chaff response contains an invalid identity claim")


def _copy_defense_parameter_artifacts(defense: Defense, neqo: Path) -> None:
    if defense.parameters_path is None:
        return
    if defense.parameters_provenance_path is None:
        raise ValueError("reactive defense parameters lack provenance")
    shutil.copy2(defense.parameters_path, neqo / PARAMETER_ARTIFACT_NAME)
    shutil.copy2(
        defense.parameters_provenance_path,
        neqo / PARAMETER_PROVENANCE_ARTIFACT_NAME,
    )


def _runner_result_complete(run_data: dict[str, Any], expected_resource_ids: set[int]) -> bool:
    responses = run_data.get("responses", [])
    observed_ids = [
        response.get("resource_id") for response in responses if isinstance(response, dict)
    ]
    return (
        run_data.get("completion_status") == "complete"
        and not padding_event_guard_triggered(run_data)
        and bool(expected_resource_ids)
        and len(observed_ids) == len(responses) == len(expected_resource_ids)
        and len(set(observed_ids)) == len(observed_ids)
        and set(observed_ids) == expected_resource_ids
        and all(
            isinstance(response, dict)
            and response.get("resource_id") in expected_resource_ids
            and response.get("complete") is True
            and response.get("outcome") == "succeeded"
            for response in responses
        )
    )


def _wait_for_capture_start(
    process: subprocess.Popen[str],
    log: Path,
    *,
    timeout_seconds: float = 5,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("dumpcap exited before capture start")
        if log.is_file() and "File:" in log.read_text(errors="replace"):
            time.sleep(1)
            return
        time.sleep(0.02)
    raise RuntimeError("dumpcap did not become ready")


def _client_command(
    manifest: Path,
    chaff_manifest_or_workload_id: Path | str | None,
    workload_id_or_defense: str | Defense,
    defense_or_seed: Defense | int,
    seed_or_context: int | CaptureContext,
    context_or_output: CaptureContext | Path,
    output: Path | None = None,
    *,
    application_workload_source: Path | None = None,
) -> list[str]:
    if output is None:
        chaff_manifest: Path | None = None
        workload_id = str(chaff_manifest_or_workload_id)
        defense = workload_id_or_defense
        seed = defense_or_seed
        context = seed_or_context
        output = context_or_output if isinstance(context_or_output, Path) else None
    else:
        chaff_manifest = (
            chaff_manifest_or_workload_id
            if isinstance(chaff_manifest_or_workload_id, Path)
            else None
        )
        workload_id = str(workload_id_or_defense)
        defense = defense_or_seed
        seed = seed_or_context
        context = context_or_output
    if (
        not isinstance(defense, Defense)
        or type(seed) is not int
        or output is None
        or not hasattr(context, "limits")
    ):
        raise TypeError("invalid client-command arguments")
    command = [
        NEQO_CLIENT,
        "run",
        "--workload",
        str(manifest),
        "--seed",
        str(seed),
        "--output-dir",
        str(output),
        "--max-response-bytes",
        str(context.limits.max_response_bytes),
        "--timeout-seconds",
        str(context.limits.timeout_seconds),
        "--request-policy",
        context.request_policy,
    ]
    if not defense.baseline:
        if chaff_manifest is None or application_workload_source is None:
            raise ValueError("every defended run requires prepared source and qualified chaff")
        command += [
            "--application-workload-source",
            str(application_workload_source),
            "--chaff-manifest",
            str(chaff_manifest),
        ]
    elif chaff_manifest is not None or application_workload_source is not None:
        raise ValueError("baseline run forbids qualified chaff inputs")
    runner_kind = RUNNER_KIND_BY_KIND.get(defense.kind, defense.kind)
    command += ["--profile", context.qcsd_profile, "--defense", runner_kind]
    if defense.kind == "static":
        command += [
            "--schedule",
            str(defense.schedule_path),
            "--static-mode",
            str(defense.mode),
        ]
    elif defense.kind in PARAMETER_FLAG_BY_KIND:
        command += [
            PARAMETER_FLAG_BY_KIND[defense.kind],
            str(defense.parameters_path),
        ]
        if defense.kind in {"traffic_morphing", "walkie_talkie"}:
            command += ["--workload-id", workload_id]
    return command
