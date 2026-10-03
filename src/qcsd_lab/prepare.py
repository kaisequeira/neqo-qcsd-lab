from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .acquisition_errors import (
    FullGraphH3PolicyError, PassiveRenderPolicyError, PreparationError,
    RecoverablePreparationError, ResponseStabilityPolicyError,
)
from .application_response_policy import (
    COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
    HTTP_2XX_ONLY_POLICY,
    VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
    build_primary_document_identity_evidence,
    validate_primary_document_identity_policy,
    validate_qualified_chaff_origin_policy,
    validate_primary_document_identity_evidence,
    validate_primary_document_response,
    terminal_http_error_resource_allowed,
    validate_application_response_policy,
    validate_application_response_policy_evidence,
    validate_application_responses,
)
from .discover import DiscoveryResult, discover_page, origin
from .discovery_evidence import (
    evidence_sha256,
    validate_passive_render_contract,
    validate_render_observation,
    verify_discovery_event_audit,
)
from .fidelity import _runner_csv_u64
from .manifest import (
    COMPLETE_COVERAGE_POLICY,
    canonical_bytes,
    project_stable_response_lengths,
    runtime_manifest,
    validate_manifest,
    validate_prepared_navigation_graph,
    write_frozen_manifest,
)
from .process_scheduler import capture_scheduler_launch_prefix
from .util import (
    LAB_ROOT,
    DEFAULT_SOURCE_METADATA,
    ProcessTimeoutError,
    load_json,
    neqo_host_timeout,
    run,
    durable_create,
    fsync_directory,
    sha256_file,
    source_metadata,
)

NEQO_CLIENT = os.environ.get("QCSD_NEQO_CLIENT", "/usr/local/bin/neqo-qcsd-client")
DEFAULT_TIMEOUT_MS = 60_000
DEFAULT_MAX_RESPONSE_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_STABILITY_RUNS = 3
DEFAULT_STABILITY_INTERVAL_SECONDS = 30
STABILITY_PROFILE = "live"
STABILITY_DEFENSE = "none"
STABILITY_SEED = 0
STABILITY_UDP_PAYLOAD_CEILING = 1_200
STABILITY_INCOMING_UDP_PAYLOAD_LIMIT = 65_527
UDP_PAYLOAD_QUALIFICATION_SCHEMA_VERSION = 2
PACKET_REQUIRED_COLUMNS = frozenset({"direction", "connection", "observed_udp_length"})
WORKLOAD_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
NEQO_PROVENANCE_KEYS = (
    "neqo_version",
    "neqo_base_commit",
    "published_qcsd_commit",
    "migration_commit",
)
FULL_GRAPH_H3_FAILURE_POLICY = "complete-discovered-graph-http3-unavailable-v1"
RESPONSE_STABILITY_FAILURE_POLICY = "complete-graph-repeated-response-identity-unavailable-v1"
PROBE_PEER_TRANSPORT_FAILURE_KIND = "exact-resource-origin-peer-transport-close-v1"
PROBE_UDP_PAYLOAD_CEILING = 1_450


def _failure_capture_source() -> dict[str, Any]:
    result = dict(source_metadata())
    if image := os.environ.get("QCSD_LAB_IMAGE_DIGEST"):
        result["image_digest"] = image
    return result


def _stamp_policy_failure(error: Exception, source: dict[str, Any], started_at: str) -> None:
    if _failure_capture_source() != source:
        raise PreparationError("preparation runtime source changed during its policy observation") from error
    error.capture_source = json.loads(json.dumps(source, allow_nan=False))
    error.capture_started_at = started_at
    error.capture_completed_at = datetime.now(UTC).isoformat()


def _snapshot_failure_artifacts(directory: Path) -> dict[str, dict[str, str]]:
    """Copy every actual preparation file into the exception before cleanup."""
    retained = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise PreparationError("preparation failure artifact is linked")
        if path.is_file():
            raw = path.read_bytes()
            retained[path.relative_to(directory).as_posix()] = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "content_base64": base64.b64encode(raw).decode("ascii"),
            }
    return retained


def _retain_preparation_diagnostics(
    directory: Path, destination: Path, *, workload_id: str, source_url: str,
    discovery: DiscoveryResult, capture_source: dict[str, Any], started_at: str,
    error: BaseException,
) -> None:
    """Retain actual failed-stage bytes without classifying the failure."""
    destination.mkdir()
    fsync_directory(destination.parent)
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise PreparationError("preparation diagnostic artifact is linked")
        if path.is_file():
            relative = path.relative_to(directory).as_posix()
            raw = path.read_bytes()
            durable_create(destination / "artifacts" / relative, raw)
            files[relative] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    producer = Path(__file__).read_bytes()
    durable_create(destination / "producer-prepare.py", producer)
    durable_create(destination / "discovery.json", canonical_bytes(asdict(discovery)))
    metadata_path = Path(os.environ.get("QCSD_LAB_SOURCE_METADATA", DEFAULT_SOURCE_METADATA))
    raw_source_sha256 = None
    if metadata_path.is_file() and not metadata_path.is_symlink():
        raw_source = metadata_path.read_bytes()
        durable_create(destination / "runtime-source.json", raw_source)
        raw_source_sha256 = hashlib.sha256(raw_source).hexdigest()
    durable_create(destination / "diagnostics.json", canonical_bytes({
        "schema_version": 1, "artifact_type": "qcsd-preparation-failure-diagnostics",
        "workload_id": workload_id, "source_url": source_url,
        "capture_source_before": capture_source, "capture_source_after": _failure_capture_source(),
        "runtime_source_raw_sha256": raw_source_sha256,
        "producer_source_sha256": hashlib.sha256(producer).hexdigest(),
        "started_at": started_at, "completed_at": datetime.now(UTC).isoformat(),
        "exception_type": f"{type(error).__module__}.{type(error).__qualname__}",
        "message": str(error), "files": files,
        "scientific_credit": False, "failure_classification": "none-diagnostic-only",
    }))


def _retain_application_response_evidence(
    directory: Path, destination: Path, *, workload_id: str,
    capture_source: dict[str, Any], started_at: str, stability_runs: int,
    policy_evidence: dict[str, Any] | None,
    primary_document_identity_evidence: dict[str, Any] | None = None,
) -> Path:
    """Keep only actual JSON ledgers required to reopen the opt-in proof."""
    names = [
        "probe-input.json", "probe-output.json", "probe.log.execution.json",
        "probe-output.probe-head/run.json", "probe-output.probe-get/run.json",
        "stability-input.json",
        *[name for index in range(stability_runs) for name in (
            f"stability-{index}/run.json", f"stability-{index}.log.execution.json",
        )],
    ]
    if primary_document_identity_evidence is not None:
        get_name = "probe-output.probe-get/run.json"
        if not (directory / get_name).exists() and not (directory / get_name).is_symlink() and policy_evidence is None:
            names.remove(get_name)
    source_after = _failure_capture_source()
    if source_after != capture_source:
        raise PreparationError("preparation runtime source changed before retaining its response proof")
    destination.mkdir()
    fsync_directory(destination.parent)
    files = {}
    for relative in names:
        path = directory / relative
        if path.is_symlink() or not path.is_file():
            raise PreparationError(f"application response raw evidence is missing or linked: {relative}")
        raw = path.read_bytes()
        durable_create(destination / "artifacts" / relative, raw)
        files[relative] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    durable_create(destination / "inventory.json", canonical_bytes({
        "schema_version": 2 if primary_document_identity_evidence is not None else 1,
        "artifact_type": "qcsd-application-response-preparation-evidence",
        "workload_id": workload_id,
        "original_directory": str(directory),
        "capture_source_before": capture_source,
        "capture_source_after": source_after,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "policy_evidence": policy_evidence,
        **({"primary_document_identity_policy": VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
            "primary_document_identity_evidence": primary_document_identity_evidence}
           if primary_document_identity_evidence is not None else {}),
        "files": files,
        "scientific_credit": False,
    }))
    return destination


@contextmanager
def _retained_preparation_directory(
    root: Path, *, workload_id: str, source_url: str, discovery: DiscoveryResult,
    capture_source: dict[str, Any], started_at: str,
):
    temporary = tempfile.TemporaryDirectory(prefix=f".{workload_id}-prepare-", dir=root)
    directory = Path(temporary.name)
    try:
        yield directory
    except BaseException as error:
        destination = root / f"{workload_id}-failure-evidence"
        try:
            _retain_preparation_diagnostics(
                directory, destination, workload_id=workload_id, source_url=source_url,
                discovery=discovery, capture_source=capture_source, started_at=started_at, error=error,
            )
        except BaseException as retention_error:
            # Storage/copy failure must neither erase the original bytes nor
            # replace the error that the caller must diagnose. The outer
            # attempt can retain this note, path and actual remaining bytes.
            temporary._finalizer.detach()
            error.preparation_failure_diagnostics = {
                "state": "original-directory-preserved-retention-incomplete",
                "path": str(directory), "partial_destination": str(destination),
                "retention_exception_type": type(retention_error).__name__,
                "retention_message": str(retention_error),
            }
            error.add_note(
                f"Preparation diagnostics could not be copied; raw directory preserved: {directory}; "
                f"{type(retention_error).__name__}: {retention_error}"
            )
        else:
            error.preparation_failure_diagnostics = {"state": "retained", "path": str(destination)}
            try:
                temporary.cleanup()
            except BaseException as cleanup_error:
                temporary._finalizer.detach()
                error.add_note(
                    f"Preparation diagnostic copy is complete; temporary cleanup failed: {directory}; "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        raise
    else:
        temporary.cleanup()


def _preparation_failure_evidence(
    stage: str, discovery: DiscoveryResult, resolved_probe: dict[str, Any] | None,
    replay_manifest: dict[str, Any] | None, response_runs: list[dict[str, Any]], *,
    require_complete_coverage: bool, artifacts: dict[str, dict[str, str]],
) -> dict[str, Any]:
    return json.loads(json.dumps({
        "schema_version": 1,
        "policy": FULL_GRAPH_H3_FAILURE_POLICY if stage == "full-graph-h3" else RESPONSE_STABILITY_FAILURE_POLICY,
        "stage": stage, "require_complete_coverage": require_complete_coverage,
        "discovery": asdict(discovery), "resolved_probe": resolved_probe,
        "replay_manifest": replay_manifest, "response_runs": response_runs, "artifacts": artifacts,
    }, allow_nan=False))


def _failure_artifact_bytes(value: Any) -> dict[str, bytes]:
    if not isinstance(value, dict) or not value:
        raise ValueError("preparation policy failure lacks retained raw artifacts")
    result = {}
    for relative, record in value.items():
        if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
            or ".." in Path(relative).parts or Path(relative).as_posix() != relative
            or not isinstance(record, dict) or set(record) != {"sha256", "content_base64"}
            or not isinstance(record["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or not isinstance(record["content_base64"], str)):
            raise ValueError("preparation policy raw artifact reference is invalid")
        try:
            raw = base64.b64decode(record["content_base64"], validate=True)
        except ValueError as error:
            raise ValueError("preparation policy raw artifact encoding is invalid") from error
        if hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise ValueError("preparation policy raw artifact bytes do not verify")
        result[relative] = raw
    return result


def _strict_failure_json(raw: bytes) -> Any:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("preparation failure raw JSON repeats a key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("preparation failure raw JSON contains a nonfinite constant")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("preparation failure artifact is not strict UTF-8 JSON") from error


def _require_failure_artifact_json(artifacts: dict[str, bytes], name: str, expected: Any) -> None:
    if name not in artifacts or canonical_bytes(_strict_failure_json(artifacts[name])) != canonical_bytes(expected):
        raise ValueError(f"preparation policy retained {name} differs from its raw stage facts")


def _failure_child_execution(
    artifacts: dict[str, bytes], name: str, operation: str, *, returncode: int,
) -> dict[str, Any]:
    if name not in artifacts:
        raise ValueError("preparation policy lacks actual child execution evidence")
    value = _strict_failure_json(artifacts[name])
    if (not isinstance(value, dict) or set(value) != {
        "schema_version", "command", "returncode", "configured_timeout_seconds", "host_timeout_seconds",
        "started_at", "completed_at", "stdout", "stdout_sha256",
    } or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or type(value["returncode"]) is not int or value["returncode"] != returncode
        or not isinstance(value["command"], list) or any(not isinstance(x, str) for x in value["command"])
        or operation not in value["command"] or not isinstance(value["stdout"], str)
        or hashlib.sha256(value["stdout"].encode()).hexdigest() != value["stdout_sha256"]
        or type(value["configured_timeout_seconds"]) is not int or value["configured_timeout_seconds"] < 1
        or type(value["host_timeout_seconds"]) not in (int, float)
        or value["host_timeout_seconds"] != neqo_host_timeout(value["configured_timeout_seconds"])):
        raise ValueError("preparation policy child execution was nonzero or malformed")
    try:
        started, completed = [datetime.fromisoformat(value[key]) for key in ("started_at", "completed_at")]
    except (TypeError, ValueError) as error:
        raise ValueError("preparation policy child execution timestamps are invalid") from error
    if started.tzinfo is None or completed.tzinfo is None or started > completed or completed > datetime.now(UTC):
        raise ValueError("preparation policy child execution timestamps are invalid")
    return value


def _require_successful_failure_stage(artifacts: dict[str, bytes], name: str, operation: str) -> None:
    _failure_child_execution(artifacts, name, operation, returncode=0)


def _probe_runtime_manifest_hash(resources: list[dict[str, Any]]) -> str:
    """Match ResourceManifest's declared Serde field order and pretty JSON.

    Probe HEAD/GET runs clear dependency edges only for independent preflight;
    the original complete discovered graph remains in the retained input.
    """
    fields = ("id", "url", "type", "content_length", "data_length",
              "chaff_priority", "known_valid", "depends_on", "headers")
    manifest = {"resources": [
        {key: [] if key == "depends_on" else row[key] for key in fields}
        for row in resources
    ]}
    raw = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _probe_run_proof(
    artifacts: dict[str, bytes], stage: str, resources: list[dict[str, Any]],
    execution: dict[str, Any], *, failed: bool,
) -> dict[str, Any]:
    name = f"probe-output.probe-{stage}"
    if f"{name}/run.json" not in artifacts or f"{name}/packets.csv" not in artifacts:
        raise ValueError("peer transport probe lacks actual raw run and packet evidence")
    value = _strict_failure_json(artifacts[f"{name}/run.json"])
    if (not isinstance(value, dict)
        or value.get("method") != ("HEAD" if stage == "head" else "GET")
        or value.get("request_policy") != "as-defined"
        or type(value.get("seed")) is not int or value["seed"] != 0
        or value.get("workload_hash_sha256") != _probe_runtime_manifest_hash(resources)
        or value.get("application_workload_source_hash_sha256") is not None
        or value.get("chaff_manifest_hash_sha256") is not None
        or value.get("defense_parameters") is not None
        or value.get("terminal_evidence_render_errors") != []
        or not isinstance(value.get("resolved_configuration"), dict)
        or value["resolved_configuration"].get("defense") != {"kind": "none"}
        or type(value.get("max_response_bytes")) is not int
        or value["max_response_bytes"] != (0 if stage == "head" else int(execution["command"][-3]))):
        raise ValueError("peer transport probe run changed its actual request contract")
    if failed:
        if value.get("completion_status") != "error" or value.get("error_class") != "runner-execution-v1":
            raise ValueError("peer transport probe is not a retained operational endpoint close")
    elif (value.get("completion_status") != "complete" or value.get("error") is not None
          or value.get("error_class") is not None):
        raise ValueError("GET fallback lacks a complete successful full-graph HEAD observation")
    if any(not isinstance(value.get(key), str) or not value[key] for key in NEQO_PROVENANCE_KEYS):
        raise ValueError("peer transport probe lacks actual client provenance")
    if re.fullmatch(r"[0-9a-f]{40,64}", value["migration_commit"]) is None:
        raise ValueError("peer transport probe client is not bound to a clean commit")
    if (type(value.get("started_unix_ns")) is not int or type(value.get("ended_unix_ns")) is not int
        or value.get("time_anchor_unix_ns") != value["started_unix_ns"]
        or not datetime.fromisoformat(execution["started_at"]).timestamp() * 1e9 - 1_000 <=
        value["started_unix_ns"] <= value["ended_unix_ns"] <=
        datetime.fromisoformat(execution["completed_at"]).timestamp() * 1e9 + 1_000):
        raise ValueError("peer transport probe run timestamps lie outside actual child execution")
    endpoints = value.get("endpoints")
    origins = sorted({origin(row["url"]) for row in resources}, key=lambda url: (
        urlsplit(url).hostname, urlsplit(url).port or 443,
    ))
    if (not isinstance(endpoints, list) or len(endpoints) != len(origins)
        or any(not isinstance(row, dict) or type(row.get("id")) is not int
               or row["id"] != index or row.get("origin") != f"{origins[index]}/"
               for index, row in enumerate(endpoints))):
        raise ValueError("peer transport probe endpoint IDs do not map to the retained request origins")
    by_id = {row["id"]: row for row in resources}
    responses = value.get("responses")
    if not isinstance(responses, list):
        raise ValueError("peer transport probe lacks a retained request ledger")
    seen = set()
    for row in responses:
        if (not isinstance(row, dict) or type(row.get("resource_id")) is not int
            or row["resource_id"] not in by_id or row["resource_id"] in seen
            or row.get("url") != by_id[row["resource_id"]]["url"]
            or type(row.get("complete")) is not bool or not isinstance(row.get("outcome"), str)
            or type(row.get("bytes")) is not int or row["bytes"] < 0
            or not isinstance(row.get("body_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", row["body_sha256"]) is None):
            raise ValueError("peer transport probe request ledger does not bind actual resource IDs/URLs")
        seen.add(row["resource_id"])
    if not failed and (seen != set(by_id) or any(
        row["complete"] is not True or row["outcome"] != "succeeded" for row in responses
    )):
        raise ValueError("GET fallback HEAD ledger is incomplete or unsuccessful")
    with tempfile.TemporaryDirectory(prefix="qcsd-peer-probe-packets-") as temporary:
        packets = Path(temporary) / "packets.csv"
        packets.write_bytes(artifacts[f"{name}/packets.csv"])
        try:
            _qualify_udp_payloads(value, packets, run_index=0, expected_ceiling=PROBE_UDP_PAYLOAD_CEILING)
        except PreparationError as error:
            raise ValueError("peer transport probe packet evidence is invalid") from error
    return value


def _peer_transport_probe_failure(
    artifacts: dict[str, bytes], resources: list[dict[str, Any]],
) -> dict[str, Any]:
    """Rederive only the exact peer-296 close from raw client stage evidence."""
    if "probe-output.json" in artifacts:
        raise ValueError("peer transport probe unexpectedly produced a resolved manifest")
    execution = _failure_child_execution(artifacts, "probe.log.execution.json", "probe", returncode=1)
    if artifacts.get("probe.log") != execution["stdout"].encode("utf-8"):
        raise ValueError("peer transport probe raw log differs from its actual child execution")
    command = execution["command"]
    index = command.index("probe")
    arguments = command[index + 1:]
    if (index == 0 or Path(command[index - 1]).name != "neqo-qcsd-client"
        or len(arguments) != 8 or arguments[::2] != [
            "--input-manifest", "--output", "--max-bytes", "--timeout-seconds",
        ] or Path(arguments[1]).name != "probe-input.json"
        or Path(arguments[3]).name != "probe-output.json"
        or Path(arguments[1]).parent != Path(arguments[3]).parent
        or not arguments[5].isdecimal() or int(arguments[5]) < 1
        or arguments[7] != str(execution["configured_timeout_seconds"])):
        raise ValueError("peer transport probe child command differs from its exact retained input")
    stage = "get" if "probe-output.probe-get/run.json" in artifacts else "head"
    selected = resources
    if stage == "get":
        head = _probe_run_proof(artifacts, "head", resources, execution, failed=False)
        missing = {row["resource_id"] for row in head["responses"] if (
            type(row.get("status")) is not int or not 200 <= row["status"] < 300
            or row.get("content_length") is None
        )}
        selected = [row for row in resources if row["id"] in missing]
        if not selected:
            raise ValueError("peer transport GET fallback is not derived from actual HEAD responses")
    run_data = _probe_run_proof(artifacts, stage, selected, execution, failed=True)
    match = re.fullmatch(
        r"run aborted: HTTP/3 endpoint (0|[1-9][0-9]*) closed before accepted run completion: Transport\(Peer\(296\)\)",
        str(run_data.get("error")),
    )
    if match is None:
        raise ValueError("peer transport probe lacks the exact supported peer-296 terminal error")
    endpoint_id = int(match[1])
    endpoints = run_data["endpoints"]
    if endpoint_id >= len(endpoints):
        raise ValueError("peer transport error identifies an absent request endpoint")
    failed_origin = origin(endpoints[endpoint_id]["origin"])
    resource_ids = sorted(row["id"] for row in selected if origin(row["url"]) == failed_origin)
    closed = [row for row in run_data["responses"] if row["resource_id"] in resource_ids]
    if (len(closed) != len(resource_ids) or any(
        row["complete"] is not False or row["outcome"] != "endpoint_closed"
        or row.get("status") is not None for row in closed
    )):
        raise ValueError("peer transport endpoint close does not identify its actual failed resources")
    expected_stdout = f'Error: RunAborted("{run_data["error"].removeprefix("run aborted: ")}")'
    if execution["stdout"].strip() != expected_stdout:
        raise ValueError("peer transport raw child error differs from its retained terminal run")
    packet_text = artifacts[f"probe-output.probe-{stage}/packets.csv"].decode("utf-8")
    directions = {row["direction"] for row in csv.DictReader(packet_text.splitlines())
                  if row["connection"] == str(endpoint_id)}
    if directions != {"incoming", "outgoing"}:
        raise ValueError("peer transport failed endpoint lacks bidirectional packet observations")
    return {"kind": PROBE_PEER_TRANSPORT_FAILURE_KIND, "probe_stage": stage,
            "endpoint_id": endpoint_id, "origin": failed_origin, "resource_ids": resource_ids,
            "peer_transport_code": 296,
            "client_provenance": {key: run_data[key] for key in NEQO_PROVENANCE_KEYS}}


def _validate_successful_policy_response_runs(
    runs: list[dict[str, Any]], resources: list[dict[str, Any]],
) -> None:
    """Separate actual response drift from missing or malformed runner output."""
    resolved = {row["id"]: row for row in resources}
    for run_data in runs:
        if (not isinstance(run_data, dict) or run_data.get("completion_status") != "complete"
            or run_data.get("error") is not None or run_data.get("error_class") is not None
            or not isinstance(run_data.get("responses"), list)):
            raise ValueError("response stability policy retained an incomplete or errored run")
        seen = set()
        for response in run_data["responses"]:
            if (not isinstance(response, dict) or type(response.get("resource_id")) is not int
                or response["resource_id"] in seen or response["resource_id"] not in resolved
                or response.get("url") != resolved[response["resource_id"]]["url"]
                or response.get("complete") is not True or response.get("outcome") != "succeeded"
                or type(response.get("status")) is not int or not 100 <= response["status"] <= 599
                or type(response.get("bytes")) is not int or response["bytes"] < 0
                or not isinstance(response.get("body_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", response["body_sha256"]) is None
                or not isinstance(response.get("request_headers"), list)
                or any(not isinstance(pair, list) or len(pair) != 2
                       or any(not isinstance(part, str) for part in pair)
                       for pair in response["request_headers"])):
                raise ValueError("response stability policy response ledger is malformed or unsuccessful")
            seen.add(response["resource_id"])
        if seen != set(resolved):
            raise ValueError("response stability policy response ledger omits a complete-graph resource")
    try:
        _neqo_provenance(runs)
    except PreparationError as error:
        raise ValueError("response stability policy client provenance is invalid") from error


def _variable_primary_stability_manifest(
    manifest: Mapping[str, Any], runs: list[dict[str, Any]], *, source_url: str,
    final_url: str, max_response_bytes: int, coverage_admission: Mapping[str, Any],
    stability_run_sha256s: list[str],
) -> dict[str, Any]:
    resources = json.loads(json.dumps(manifest["resources"]))
    _freeze_request_headers(resources, runs)
    result = {"resources": resources, "preparation": {
        "application_response_policy": COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        "primary_document_identity_policy": VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
        "source_url": source_url, "final_url": final_url,
        "max_response_bytes": max_response_bytes, "coverage_admission": coverage_admission,
        "stability_runs": len(runs),
        "expected_responses": [{key: response[key] for key in
            ("resource_id", "status", "bytes", "body_sha256")}
            for response in runs[0]["responses"]],
    }}
    result["preparation"]["primary_document_identity_evidence"] = build_primary_document_identity_evidence(
        result, runs, stability_run_sha256s=stability_run_sha256s,
    )
    return result


def _validate_variable_primary_stability_run(
    manifest: Mapping[str, Any], run_data: Mapping[str, Any],
) -> None:
    """Validate actual delivery before comparing auxiliary body identities.

    Each auxiliary body is checked against its own observed bytes and hash at
    this preparation stage. The following all-runs comparison still requires
    those identities to agree before any prepared workload can be published.
    URL, status, headers, full graph and the primary HTML proof stay fixed.
    Admission and capture continue to use the ordinary strict validator.
    """
    candidate = json.loads(json.dumps(manifest))
    responses = {row["resource_id"]: row for row in run_data["responses"]}
    for expected in candidate["preparation"]["expected_responses"]:
        if expected["resource_id"] != 0:
            actual = responses[expected["resource_id"]]
            expected["bytes"] = actual["bytes"]
            expected["body_sha256"] = actual["body_sha256"]
    validate_application_responses(candidate, run_data)


def validate_preparation_policy_failure_evidence(
    value: Any, *, source_url: str | None = None,
) -> dict[str, Any]:
    """Rederive a narrowly typed failure from complete retained raw stage data.

    The outer prospective receipt additionally binds candidate, runtime source,
    image, implementation bytes, amendment and observation freshness.
    """
    fields = {"schema_version", "policy", "stage", "require_complete_coverage", "discovery",
              "resolved_probe", "replay_manifest", "response_runs", "artifacts"}
    peer_failure = isinstance(value, dict) and type(value.get("schema_version")) is int and value["schema_version"] == 2
    variable_primary_failure = isinstance(value, dict) and type(value.get("schema_version")) is int and value["schema_version"] == 3
    if peer_failure:
        fields = fields | {"probe_failure"}
    if variable_primary_failure:
        fields = fields | {"primary_document_identity_manifest"}
    policies = {"full-graph-h3": FULL_GRAPH_H3_FAILURE_POLICY,
                "response-stability": RESPONSE_STABILITY_FAILURE_POLICY}
    if (not isinstance(value, dict) or set(value) != fields or type(value["schema_version"]) is not int
        or value["schema_version"] not in (1, 2, 3) or not isinstance(value["stage"], str)
        or value["stage"] not in policies or value["policy"] != policies[value["stage"]]
        or value["require_complete_coverage"] is not True
        or not isinstance(value["discovery"], dict)
        or set(value["discovery"]) != set(DiscoveryResult.__dataclass_fields__)):
        raise ValueError("preparation policy failure fields or stage are invalid")
    if variable_primary_failure and value["stage"] != "response-stability":
        raise ValueError("variable primary failure requires complete response stability evidence")
    discovery = DiscoveryResult(**value["discovery"])
    if source_url is not None and discovery.source_url != source_url:
        raise ValueError("preparation policy failure is for another exact selected page")
    try:
        validate_manifest({"resources": discovery.resources})
        _complete_coverage_admission(discovery)
        if peer_failure:
            if (value["stage"] != "full-graph-h3" or value["resolved_probe"] is not None
                or value["replay_manifest"] is not None or value["response_runs"] != []):
                raise ValueError("peer transport probe cannot claim a resolved manifest or replay")
            artifacts = _failure_artifact_bytes(value["artifacts"])
            _require_failure_artifact_json(artifacts, "probe-input.json", {"resources": discovery.resources})
            failure = _peer_transport_probe_failure(artifacts, discovery.resources)
            if canonical_bytes(value["probe_failure"]) != canonical_bytes(failure):
                raise ValueError("peer transport probe descriptor differs from its independently reopened raw evidence")
            return json.loads(json.dumps(value, allow_nan=False))
        probe = value["resolved_probe"]
        validate_manifest(probe)
    except (ValueError, PreparationError) as error:
        raise ValueError("preparation policy discovered/probed complete graph is invalid") from error
    original = {row["id"]: row for row in discovery.resources}
    resolved = {row["id"]: row for row in probe["resources"]}
    immutable = ("url", "type", "chaff_priority", "depends_on", "headers")
    if set(original) != set(resolved) or any(
        canonical_bytes(original[ident].get(key)) != canonical_bytes(resolved[ident].get(key))
        for ident in original for key in immutable
    ):
        raise ValueError("preparation policy probe changed the complete request graph")
    artifacts = _failure_artifact_bytes(value["artifacts"])
    _require_failure_artifact_json(artifacts, "probe-input.json", {"resources": discovery.resources})
    _require_failure_artifact_json(artifacts, "probe-output.json", probe)
    _require_successful_failure_stage(artifacts, "probe.log.execution.json", "probe")
    if value["stage"] == "full-graph-h3":
        if value["replay_manifest"] is not None or value["response_runs"] != [] or not any(
            resource["known_valid"] is not True for resource in resolved.values()
        ):
            raise ValueError("preparation policy raw probe does not prove unavailable resources")
    else:
        replay = value["replay_manifest"]
        if canonical_bytes(replay) != canonical_bytes({"resources": probe["resources"]}) or (
            not variable_primary_failure and any(
                resource["known_valid"] is not True for resource in resolved.values()
            )
        ):
            raise ValueError("response stability policy pruned or changed its complete graph")
        _require_failure_artifact_json(artifacts, "stability-input.json", replay)
        runs = value["response_runs"]
        if not isinstance(runs, list) or len(runs) != DEFAULT_STABILITY_RUNS:
            raise ValueError("response stability policy lacks all required live runs")
        _validate_successful_policy_response_runs(runs, probe["resources"])
        replay_limits = []
        with tempfile.TemporaryDirectory(prefix="qcsd-failure-packets-") as temporary:
            for index, run_data in enumerate(runs):
                _require_failure_artifact_json(artifacts, f"stability-{index}/run.json", run_data)
                execution = _failure_child_execution(
                    artifacts, f"stability-{index}.log.execution.json", "run", returncode=0,
                )
                if variable_primary_failure:
                    command = execution["command"]
                    position = command.index("run")
                    args = command[position + 1:]
                    flags = ["--application-response-policy", "--workload", "--profile", "--defense",
                             "--seed", "--output-dir", "--max-response-bytes", "--timeout-seconds"]
                    if (position == 0 or Path(command[position - 1]).name != "neqo-qcsd-client"
                        or len(args) != 2 * len(flags) or args[::2] != flags
                        or args[1] != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY
                        or Path(args[3]).name != "stability-input.json"
                        or args[5:10:2] != [STABILITY_PROFILE, STABILITY_DEFENSE, str(STABILITY_SEED)]
                        or Path(args[11]) != Path(args[3]).parent / f"stability-{index}"
                        or not args[13].isdecimal() or int(args[13]) < 1
                        or args[15] != str(execution["configured_timeout_seconds"])):
                        raise ValueError("variable primary failure replay changed its actual child command")
                    replay_limits.append(int(args[13]))
                packet_name = f"stability-{index}/packets.csv"
                if packet_name not in artifacts:
                    raise ValueError("response stability policy lacks raw packet evidence")
                packet_path = Path(temporary) / f"packets-{index}.csv"
                packet_path.write_bytes(artifacts[packet_name])
                try:
                    _qualify_udp_payloads(run_data, packet_path, run_index=index,
                                          expected_ceiling=STABILITY_UDP_PAYLOAD_CEILING)
                except PreparationError as error:
                    raise ValueError("response stability policy packet evidence is invalid") from error
        if variable_primary_failure:
            if len(set(replay_limits)) != 1:
                raise ValueError("variable primary failure replay changed its response limit")
            expected_primary = _variable_primary_stability_manifest(
                replay, runs, source_url=discovery.source_url, final_url=discovery.final_url,
                max_response_bytes=replay_limits[0], coverage_admission=_complete_coverage_admission(discovery),
                stability_run_sha256s=[hashlib.sha256(artifacts[f"stability-{index}/run.json"]).hexdigest()
                                      for index in range(DEFAULT_STABILITY_RUNS)],
            )
            if canonical_bytes(value["primary_document_identity_manifest"]) != canonical_bytes(expected_primary):
                raise ValueError("variable primary failure declaration differs from its actual full-graph witnesses")
            stable = set(response_stability_evidence(
                runs, primary_document_identity_policy=VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
                manifest=expected_primary,
            )["stable_resource_ids"])
        else:
            stable = set(response_stability_evidence(runs)["stable_resource_ids"])
        if not set(resolved) - stable:
            raise ValueError("response stability policy raw runs do not prove response drift")
    return json.loads(json.dumps(value, allow_nan=False))


def validate_passive_render_policy_failure_evidence(value: Any) -> dict[str, Any]:
    fields = {"passive_render_contract", "passive_render_contract_sha256",
              "render_observation", "render_observation_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("passive render policy failure fields are invalid")
    validate_passive_render_contract(value["passive_render_contract"], digest=value["passive_render_contract_sha256"])
    if evidence_sha256(value["render_observation"]) != value["render_observation_sha256"]:
        raise ValueError("passive render policy failure observation hash differs")
    validate_render_observation(value["render_observation"], allow_failure=True)
    if (type(value["render_observation"]["active_request_count"]) is not int
        or value["render_observation"]["cutoff_reason"] != "hard-cap-non-quiescent"):
        raise ValueError("passive render policy failure did not reach the typed hard cap")
    return json.loads(json.dumps(value, allow_nan=False))


@dataclass(frozen=True)
class PreparedWorkload:
    path: Path
    sha256: str
    resource_count: int
    origin_count: int
    application_response_evidence_path: Path | None = None


def prepare_workload(
    workload_id: str,
    source_url: str,
    approved_origins: list[str],
    *,
    output_root: Path | None = None,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    stability_runs: int = DEFAULT_STABILITY_RUNS,
    stability_interval_seconds: int = DEFAULT_STABILITY_INTERVAL_SECONDS,
    require_complete_coverage: bool = False,
    origin_ip_pins: Mapping[str, str] | None = None,
    application_response_policy: str | None = None,
    primary_document_identity_policy: str | None = None,
    qualified_chaff_origin_policy: str | None = None,
) -> PreparedWorkload:
    """Discover, probe, stability-check, and freeze one replay workload.

    The output path is deliberately derived from ``workload_id``. Preparation
    never updates an existing workload; a changed graph or response identity
    must receive a new ID.
    """

    selected_response_policy = validate_application_response_policy(application_response_policy)
    selected_primary_policy = validate_primary_document_identity_policy(primary_document_identity_policy)
    validate_qualified_chaff_origin_policy(qualified_chaff_origin_policy)
    if qualified_chaff_origin_policy is not None and not require_complete_coverage:
        raise ValueError("approved-origin chaff policy requires unchanged complete graph coverage")
    if selected_primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY and (
        selected_response_policy != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY
        or require_complete_coverage is not True or stability_runs != 3
    ):
        raise ValueError("variable primary document identity requires complete graph policy and three runs")
    if selected_response_policy == COMPLETED_TERMINAL_HTTP_ERRORS_POLICY and not require_complete_coverage:
        raise ValueError("terminal HTTP error policy requires unchanged complete graph coverage")
    _validate_arguments(
        workload_id,
        source_url,
        approved_origins,
        timeout_ms=timeout_ms,
        max_response_bytes=max_response_bytes,
        timeout_seconds=timeout_seconds,
        stability_runs=stability_runs,
        stability_interval_seconds=stability_interval_seconds,
        require_complete_coverage=require_complete_coverage,
    )
    root = output_root or (LAB_ROOT / "config" / "workloads")
    output = root / f"{workload_id}.json"
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"{output} already exists; choose a new workload ID")

    capture_source = _failure_capture_source()
    capture_started_at = datetime.now(UTC).isoformat()
    try:
        discovery = discover_page(
            source_url,
            allow_origins=approved_origins,
            timeout_ms=timeout_ms,
            origin_ip_pins=origin_ip_pins,
        )
    except PassiveRenderPolicyError as error:
        if type(error) is PassiveRenderPolicyError:
            _stamp_policy_failure(error, capture_source, capture_started_at)
        raise
    coverage_admission = (
        _complete_coverage_admission(discovery) if require_complete_coverage else None
    )
    browser_request_headers = [
        {"resource_id": resource["id"], "headers": resource.get("headers", [])}
        for resource in discovery.resources
    ]
    root.mkdir(parents=True, exist_ok=True)
    application_response_evidence_path = None
    with _retained_preparation_directory(
        root, workload_id=workload_id, source_url=source_url, discovery=discovery,
        capture_source=capture_source, started_at=capture_started_at,
    ) as directory:
        probe_input = {"resources": discovery.resources}
        validate_manifest(probe_input)
        try:
            probe_output = _probe(
                probe_input,
                directory,
                max_response_bytes=max_response_bytes,
                timeout_seconds=timeout_seconds,
            )
        except RecoverablePreparationError as error:
            if type(error) is RecoverablePreparationError and require_complete_coverage:
                artifacts = _snapshot_failure_artifacts(directory)
                try:
                    raw = _failure_artifact_bytes(artifacts)
                    failure = _peer_transport_probe_failure(raw, discovery.resources)
                    if failure["client_provenance"]["migration_commit"] != capture_source.get("neqo_commit"):
                        raise ValueError("peer transport probe client differs from the actual preparation source")
                    evidence = _preparation_failure_evidence(
                        "full-graph-h3", discovery, None, None, [],
                        require_complete_coverage=True, artifacts=artifacts,
                    )
                    evidence.update({"schema_version": 2, "probe_failure": failure})
                    validate_preparation_policy_failure_evidence(evidence, source_url=source_url)
                except (ValueError, TypeError, KeyError, UnicodeError):
                    # Missing/malformed artifacts and every other child failure
                    # remain operational; an exception string supplies no proof.
                    pass
                else:
                    policy_error = FullGraphH3PolicyError(
                        "complete coverage HTTP/3 probe recorded a peer transport close "
                        f"for origin {failure['origin']}, resource IDs {failure['resource_ids']}",
                        evidence=evidence,
                    )
                    _stamp_policy_failure(policy_error, capture_source, capture_started_at)
                    raise policy_error from error
            raise
        try:
            resources, exclusions = resolve_probe_output(
                discovery,
                probe_output,
                require_complete_coverage=require_complete_coverage,
                **({"application_response_policy": application_response_policy,
                    "probe_directory": directory} if application_response_policy is not None else {}),
            )
        except FullGraphH3PolicyError as error:
            error.evidence["artifacts"] = _snapshot_failure_artifacts(directory)
            _stamp_policy_failure(error, capture_source, capture_started_at)
            raise
        resolved = {"resources": resources}
        evidence, runs, udp_payload_qualification = _probe_response_stability(
            resolved,
            directory,
            max_response_bytes=max_response_bytes,
            timeout_seconds=timeout_seconds,
            stability_runs=stability_runs,
            stability_interval_seconds=stability_interval_seconds,
            **({"application_response_policy": application_response_policy,
                "source_url": discovery.source_url, "final_url": discovery.final_url}
               if application_response_policy is not None else {}),
            **({"primary_document_identity_policy": primary_document_identity_policy,
                "coverage_admission": coverage_admission}
               if primary_document_identity_policy is not None else {}),
        )
        required = {resource["id"] for resource in resources}
        stable = set(evidence["stable_resource_ids"])
        if unstable := required - stable:
            try:
                _validate_successful_policy_response_runs(runs, resources)
            except ValueError as error:
                raise RecoverablePreparationError(
                    f"response stability retained operationally invalid runner evidence: {error}"
                ) from error
            identifiers = ", ".join(map(str, sorted(unstable)))
            failure_evidence = _preparation_failure_evidence(
                "response-stability", discovery, probe_output, resolved, runs,
                require_complete_coverage=require_complete_coverage,
                artifacts=_snapshot_failure_artifacts(directory),
            )
            if selected_primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY:
                failure_evidence.update({
                    "schema_version": 3,
                    "primary_document_identity_manifest": evidence["primary_document_identity_manifest"],
                })
                try:
                    validate_preparation_policy_failure_evidence(failure_evidence, source_url=source_url)
                except (KeyError, TypeError, ValueError) as invalid:
                    raise RecoverablePreparationError(
                        f"variable primary response drift lacks intact actual stage proof: {invalid}"
                    ) from invalid
            error = ResponseStabilityPolicyError(
                f"repeated Neqo fetches changed or failed for resource IDs: {identifiers}",
                evidence=failure_evidence,
            )
            _stamp_policy_failure(error, capture_source, capture_started_at)
            raise error
        policy_evidence = (
            _terminal_http_error_policy_evidence(directory, resources, runs)
            if application_response_policy is not None and any(resource["known_valid"] is False for resource in resources)
            else None
        )
        primary_evidence = None
        if selected_primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY:
            provisional_resources = json.loads(json.dumps(resources))
            _freeze_request_headers(provisional_resources, runs)
            primary_manifest = {"resources": provisional_resources, "preparation": {
                "application_response_policy": application_response_policy,
                "primary_document_identity_policy": primary_document_identity_policy,
                "expected_responses": evidence["expected_responses"],
                "source_url": discovery.source_url, "final_url": discovery.final_url,
                "max_response_bytes": max_response_bytes, "coverage_admission": coverage_admission,
                "stability_runs": stability_runs,
            }}
            primary_evidence = build_primary_document_identity_evidence(primary_manifest, runs,
                stability_run_sha256s=[sha256_file(directory / f"stability-{index}/run.json")
                                      for index in range(stability_runs)])
        if policy_evidence is not None:
            provisional_resources = json.loads(json.dumps(resources))
            _freeze_request_headers(provisional_resources, runs)
            provisional = {"resources": provisional_resources, "preparation": {
                "application_response_policy": application_response_policy,
                "application_response_policy_evidence": policy_evidence,
                "expected_responses": evidence["expected_responses"],
                "source_url": discovery.source_url, "final_url": discovery.final_url,
                "stability_runs": stability_runs, **_neqo_provenance(runs),
            }}
            try:
                validate_application_response_policy_evidence(provisional)
            except (KeyError, TypeError, ValueError) as error:
                raise RecoverablePreparationError(
                    f"terminal HTTP error preflight/stability identities differ: {error}"
                ) from error
        if policy_evidence is not None or primary_evidence is not None:
            application_response_evidence_path = _retain_application_response_evidence(
                directory, root / f"{workload_id}-application-response-evidence",
                workload_id=workload_id, capture_source=capture_source,
                started_at=capture_started_at, stability_runs=stability_runs,
                policy_evidence=policy_evidence,
                **({"primary_document_identity_evidence": primary_evidence}
                   if primary_evidence is not None else {}),
            )
    try:
        resources = project_stable_response_lengths(resources, evidence["expected_responses"])
    except (KeyError, TypeError, ValueError) as error:
        raise PreparationError(
            f"stable response evidence cannot canonicalize resource lengths: {error}"
        ) from error
    _freeze_request_headers(resources, runs)
    provenance = _neqo_provenance(runs)
    discovery_evidence_values = {
        "passive_render_contract": discovery.passive_render_contract,
        "passive_render_contract_sha256": discovery.passive_render_contract_sha256,
        "render_observation": discovery.render_observation,
        "render_observation_sha256": discovery.render_observation_sha256,
        "discovery_event_audit": discovery.discovery_event_audit,
        "discovery_event_audit_sha256": discovery.discovery_event_audit_sha256,
    }
    present_discovery_evidence = {
        key: value for key, value in discovery_evidence_values.items() if value is not None
    }
    if present_discovery_evidence and len(present_discovery_evidence) != len(
        discovery_evidence_values
    ):
        raise PreparationError("browser discovery returned incomplete bounded-render evidence")
    manifest = {
        "preparation": {
            "source_url": discovery.source_url,
            "final_url": discovery.final_url,
            "chromium_version": discovery.chromium_version,
            "settle_ms": discovery.settle_ms,
            "observed_request_count": discovery.observed_request_count,
            "observed_origins": discovery.observed_origins,
            "approved_origins": discovery.approved_origins,
            **(
                {"origin_ip_pins": discovery.origin_ip_pins}
                if discovery.origin_ip_pins
                else {}
            ),
            "exclusions": exclusions,
            "browser_request_headers": browser_request_headers,
            "request_header_transformation": (
                "browser-safe-input-to-neqo-stability-frozen-runtime-v1"
            ),
            **present_discovery_evidence,
            "prepare_image_digest": os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native"),
            "lab_source": source_metadata(),
            "max_response_bytes": max_response_bytes,
            "timeout_seconds": timeout_seconds,
            "stability_runs": stability_runs,
            "stability_profile": STABILITY_PROFILE,
            "stability_defense": STABILITY_DEFENSE,
            "stability_seed": STABILITY_SEED,
            **({"application_response_policy": application_response_policy}
               if application_response_policy is not None else {}),
            **({"application_response_policy_evidence": policy_evidence}
               if policy_evidence is not None else {}),
            **({"primary_document_identity_policy": primary_document_identity_policy}
               if primary_document_identity_policy is not None else {}),
            **({"qualified_chaff_origin_policy": qualified_chaff_origin_policy}
               if qualified_chaff_origin_policy is not None else {}),
            **({"primary_document_identity_evidence": primary_evidence}
               if primary_evidence is not None else {}),
            "udp_payload_qualification": udp_payload_qualification,
            **(
                {"coverage_admission": coverage_admission} if coverage_admission is not None else {}
            ),
            **provenance,
            "expected_responses": evidence["expected_responses"],
        },
        "resources": resources,
    }
    digest = write_frozen_manifest(output, manifest, exclusive=True)
    return PreparedWorkload(
        path=output,
        sha256=digest,
        resource_count=len(resources),
        origin_count=len({origin(resource["url"]) for resource in resources}),
        application_response_evidence_path=application_response_evidence_path,
    )


def _validate_arguments(
    workload_id: str,
    source_url: str,
    approved_origins: list[str],
    *,
    timeout_ms: int,
    max_response_bytes: int,
    timeout_seconds: int,
    stability_runs: int,
    stability_interval_seconds: int,
    require_complete_coverage: bool,
) -> None:
    if not isinstance(workload_id, str) or not WORKLOAD_ID.fullmatch(workload_id):
        raise ValueError("workload ID must contain lowercase letters, digits, and single hyphens")
    if origin(source_url) is None:
        raise ValueError(f"source URL is not absolute HTTPS: {source_url}")
    if not isinstance(approved_origins, list) or not approved_origins:
        raise ValueError("workload preparation requires at least one approved origin")
    if not isinstance(require_complete_coverage, bool):
        raise ValueError("complete coverage admission must be boolean")
    values = {
        "discovery timeout": timeout_ms,
        "maximum response bytes": max_response_bytes,
        "request timeout": timeout_seconds,
    }
    for label, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{label} must be a positive integer")
    if (
        not isinstance(stability_runs, int)
        or isinstance(stability_runs, bool)
        or stability_runs < 2
    ):
        raise ValueError("response stability requires at least two runs")
    if (
        not isinstance(stability_interval_seconds, int)
        or isinstance(stability_interval_seconds, bool)
        or stability_interval_seconds < 0
    ):
        raise ValueError("stability interval must be a non-negative integer")


def _probe(
    manifest: dict[str, Any],
    directory: Path,
    *,
    max_response_bytes: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    runtime_input = directory / "probe-input.json"
    runtime_input.write_bytes(canonical_bytes(runtime_manifest(manifest)))
    output = directory / "probe-output.json"
    result = _run_neqo(
        [
            NEQO_CLIENT,
            "probe",
            "--input-manifest",
            str(runtime_input),
            "--output",
            str(output),
            "--max-bytes",
            str(max_response_bytes),
            "--timeout-seconds",
            str(timeout_seconds),
        ],
        log=directory / "probe.log",
        configured_timeout_seconds=timeout_seconds,
        label="Neqo HTTP/3 probe",
    )
    if result.returncode:
        _raise_neqo_execution_failure("Neqo HTTP/3 probe", result)
    try:
        resolved = load_json(output)
        validate_manifest(resolved)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise PreparationError(f"Neqo probe produced an invalid manifest: {error}") from error
    return resolved


def resolve_probe_output(
    discovery: DiscoveryResult,
    resolved: dict[str, Any],
    *,
    require_complete_coverage: bool = False,
    application_response_policy: str | None = None,
    probe_directory: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Retain the fetchable dependency closure without rewriting graph edges."""

    if not isinstance(require_complete_coverage, bool):
        raise ValueError("complete coverage admission must be boolean")
    selected_response_policy = validate_application_response_policy(application_response_policy)
    if selected_response_policy == COMPLETED_TERMINAL_HTTP_ERRORS_POLICY and not require_complete_coverage:
        raise ValueError("terminal HTTP error policy requires complete graph coverage")
    source_by_id = {resource["id"]: resource for resource in discovery.resources}
    resolved_by_id = {resource["id"]: resource for resource in resolved["resources"]}
    if set(source_by_id) != set(resolved_by_id):
        raise PreparationError("Neqo probe changed the discovered resource identifiers")
    immutable = ("url", "type", "chaff_priority", "depends_on", "headers")
    for resource_id, source in source_by_id.items():
        candidate = resolved_by_id[resource_id]
        if any(candidate.get(key) != source.get(key) for key in immutable):
            raise PreparationError(
                f"Neqo probe changed discovered request data for resource {resource_id}"
            )

    permitted_negative_ids = set()
    if selected_response_policy == COMPLETED_TERMINAL_HTTP_ERRORS_POLICY:
        permitted_negative_ids = set(_terminal_http_error_probe_records(
            discovery, resolved, probe_directory,
        ))
    unavailable = [resource for resource in resolved["resources"]
                   if resource.get("known_valid") is not True and resource["id"] not in permitted_negative_ids]
    if require_complete_coverage and unavailable:
        details = ", ".join(
            f"{resource['id']} ({resource['url']})"
            for resource in sorted(unavailable, key=lambda item: item["id"])
        )
        raise FullGraphH3PolicyError(
            "complete coverage requires every browser-rendered resource to pass the HTTP/3 "
            f"preflight; unavailable resource IDs/URLs: {details}",
            evidence=_preparation_failure_evidence(
                "full-graph-h3", discovery, resolved, None, [],
                require_complete_coverage=True, artifacts={},
            ),
        )
    retained_ids = {
        resource["id"] for resource in resolved["resources"]
        if resource.get("known_valid") is True or resource["id"] in permitted_negative_ids
    }
    while True:
        orphaned = {
            resource["id"]
            for resource in resolved["resources"]
            if resource["id"] in retained_ids
            and any(dependency not in retained_ids for dependency in resource.get("depends_on", []))
        }
        if not orphaned:
            break
        retained_ids -= orphaned
    resources = [
        dict(resource) for resource in resolved["resources"] if resource["id"] in retained_ids
    ]
    dependency_unavailable = [
        resource
        for resource in resolved["resources"]
        if resource.get("known_valid") is True and resource["id"] not in retained_ids
    ]
    try:
        validate_prepared_navigation_graph(
            resources,
            source_url=discovery.source_url,
            final_url=discovery.final_url,
        )
    except ValueError as error:
        raise PreparationError(f"Neqo preflight {error}") from error
    exclusions = [
        *discovery.exclusions,
        *(
            {"url": resource["url"], "reason": "HTTP/3 preflight unavailable"}
            for resource in unavailable
        ),
        *(
            {"url": resource["url"], "reason": "HTTP/3 dependency unavailable"}
            for resource in dependency_unavailable
        ),
    ]
    exclusions = sorted(
        {(item["url"], item["reason"]): item for item in exclusions}.values(),
        key=lambda item: (item["url"], item["reason"]),
    )
    prepared = {"resources": resources}
    validate_manifest(prepared)
    return resources, exclusions


def _terminal_http_error_probe_records(
    discovery: DiscoveryResult, resolved: dict[str, Any], directory: Path | None,
    *, execution_directory: Path | None = None,
) -> dict[int, dict[str, Any]]:
    """Reopen actual probe child and HEAD/GET ledgers; False alone grants nothing."""
    unavailable = [resource for resource in resolved["resources"] if resource.get("known_valid") is not True]
    if not unavailable:
        return {}
    if directory is None:
        raise PreparationError("terminal HTTP errors require the actual retained probe directory")
    directory = Path(directory)
    command_directory = directory if execution_directory is None else Path(execution_directory)
    required = ("probe-input.json", "probe-output.json", "probe.log.execution.json",
                "probe-output.probe-head/run.json", "probe-output.probe-get/run.json")
    raw = {}
    try:
        for name in required:
            path = directory / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("terminal HTTP error probe evidence is missing or linked")
            raw[name] = path.read_bytes()
        original = _strict_failure_json(raw["probe-input.json"])
        output = _strict_failure_json(raw["probe-output.json"])
        if original != {"resources": discovery.resources} or output != resolved:
            raise ValueError("terminal HTTP error probe input/output differs from the retained complete graph")
        execution = _failure_child_execution(raw, "probe.log.execution.json", "probe", returncode=0)
        command = execution["command"]
        if (command[command.index("--input-manifest") + 1] != str(command_directory / "probe-input.json")
            or command[command.index("--output") + 1] != str(command_directory / "probe-output.json")):
            raise ValueError("terminal HTTP error child command does not bind the actual graph files")
        max_bytes = int(command[command.index("--max-bytes") + 1])
        if max_bytes < 1:
            raise ValueError("terminal HTTP error probe did not retain response bodies")
        head = _strict_failure_json(raw["probe-output.probe-head/run.json"])
        get = _strict_failure_json(raw["probe-output.probe-get/run.json"])
        expected = {resource["id"]: resource for resource in discovery.resources}

        def verify_stage(value: Any, method: str, resources: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
            stage_resources = {resource["id"]: resource for resource in resources}
            if (not isinstance(value, dict) or value.get("method") != method
                or value.get("request_policy") != "as-defined" or type(value.get("seed")) is not int
                or value["seed"] != 0 or value.get("completion_status") not in {"complete", "partial"}
                or value.get("error") is not None or value.get("error_class") is not None
                or value.get("terminal_evidence_render_errors") != []
                or value.get("application_response_policy", HTTP_2XX_ONLY_POLICY) != HTTP_2XX_ONLY_POLICY
                or value.get("workload_hash_sha256") != _probe_runtime_manifest_hash(resources)
                or value.get("application_workload_source_hash_sha256") is not None
                or value.get("chaff_manifest_hash_sha256") is not None
                or value.get("defense_parameters") is not None
                or value.get("max_response_bytes") != (0 if method == "HEAD" else max_bytes)
                or not isinstance(value.get("resolved_configuration"), dict)
                or value["resolved_configuration"].get("defense") != {"kind": "none"}
                or any(not isinstance(value.get(key), str) or not value[key] for key in NEQO_PROVENANCE_KEYS)):
                raise ValueError("terminal HTTP error probe run changed its actual request/source contract")
            started, ended = value.get("started_unix_ns"), value.get("ended_unix_ns")
            bounds = [datetime.fromisoformat(execution[key]).timestamp() * 1e9
                      for key in ("started_at", "completed_at")]
            if (type(started) is not int or type(ended) is not int
                or value.get("time_anchor_unix_ns") != started
                or not bounds[0] - 1_000 <= started <= ended <= bounds[1] + 1_000):
                raise ValueError("terminal HTTP error probe timestamps are outside actual child execution")
            origins = sorted({origin(row["url"]) for row in resources}, key=lambda url: (
                urlsplit(url).hostname, urlsplit(url).port or 443,
            ))
            endpoints = value.get("endpoints")
            if (not isinstance(endpoints, list) or len(endpoints) != len(origins)
                or any(not isinstance(row, dict) or type(row.get("id")) is not int
                       or row["id"] != index or row.get("origin") != f"{origins[index]}/"
                       or row.get("negotiated_protocol") != "h3" for index, row in enumerate(endpoints))):
                raise ValueError("terminal HTTP error probe lacks its actual HTTP/3 origin endpoints")
            rows = value.get("responses")
            if not isinstance(rows, list):
                raise ValueError("terminal HTTP error probe has no response ledger")
            by_id = {}
            for row in rows:
                identifier = row.get("resource_id") if isinstance(row, dict) else None
                if (type(identifier) is not int or identifier in by_id or identifier not in stage_resources
                    or row.get("url") != stage_resources[identifier]["url"]):
                    raise ValueError("terminal HTTP error probe changed response identifiers/URLs")
                if method == "GET" and (row.get("complete") is not True
                    or type(row.get("status")) is not int or not 100 <= row["status"] <= 599
                    or type(row.get("bytes")) is not int or not 0 <= row["bytes"] <= max_bytes
                    or not isinstance(row.get("body_sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", row["body_sha256"]) is None
                    or row.get("outcome") != ("succeeded" if 200 <= row["status"] < 300 else "failed")
                    or not isinstance(row.get("request_headers"), list)
                    or any(not isinstance(pair, list) or len(pair) != 2
                           or any(not isinstance(part, str) for part in pair) for pair in row["request_headers"])):
                    raise ValueError("terminal HTTP error GET was incomplete, malformed or unretained")
                by_id[identifier] = row
            if set(by_id) != set(stage_resources):
                raise ValueError("terminal HTTP error probe response ledger omitted its actual stage resource")
            return by_id

        head_rows = verify_stage(head, "HEAD", discovery.resources)
        missing = {identifier for identifier, row in head_rows.items()
                   if type(row.get("status")) is not int or not 200 <= row["status"] < 300
                   or row.get("content_length") is None}
        fallback = [resource for resource in discovery.resources if resource["id"] in missing]
        get_rows = verify_stage(get, "GET", fallback)
        if any(head[key] != get[key] for key in NEQO_PROVENANCE_KEYS):
            raise ValueError("terminal HTTP error probe phases used different clients")
        permitted = {}
        for resource in unavailable:
            row = get_rows.get(resource["id"])
            if row is None or not 400 <= row["status"] <= 599:
                continue
            if not terminal_http_error_resource_allowed(resource, resolved["resources"]):
                continue
            if row.get("content_length") is not None and (
                type(row["content_length"]) is not int or row["content_length"] != row["bytes"]
            ):
                raise ValueError("terminal HTTP error GET did not retain its declared complete body")
            if resource.get("data_length") != row["bytes"]:
                raise ValueError("terminal HTTP error resolved response length differs from actual GET")
            permitted[resource["id"]] = row
        return permitted
    except (KeyError, IndexError, OSError, TypeError, ValueError) as error:
        raise PreparationError(f"terminal HTTP error preflight evidence is invalid: {error}") from error


def _terminal_http_error_policy_evidence(
    directory: Path, resources: list[dict[str, Any]], runs: list[dict[str, Any]],
) -> dict[str, Any]:
    identifiers = sorted(resource["id"] for resource in resources if resource.get("known_valid") is False)
    get_raw = (directory / "probe-output.probe-get/run.json").read_bytes()
    get = _strict_failure_json(get_raw)
    fields = ("resource_id", "url", "status", "bytes", "body_sha256", "complete", "outcome", "request_headers")
    select = lambda rows: [{key: row[key] for key in fields} for row in sorted(rows, key=lambda row: row["resource_id"])
                           if row["resource_id"] in identifiers]
    # The compact proof preserves the original failed HTTP status semantics;
    # the fresh opt-in runs are separate scheduling-success witnesses.
    return {
        "schema_version": 1, "policy": COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        "probe_input_sha256": sha256_file(directory / "probe-input.json"),
        "probe_output_sha256": sha256_file(directory / "probe-output.json"),
        "child_execution_sha256": sha256_file(directory / "probe.log.execution.json"),
        "get_run_sha256": hashlib.sha256(get_raw).hexdigest(),
        "client_provenance": {key: get[key] for key in NEQO_PROVENANCE_KEYS},
        "get_responses": select(get["responses"]),
        "get_endpoints": [{key: endpoint[key] for key in ("id", "origin", "negotiated_protocol")}
                          for endpoint in get["endpoints"]
                          if origin(endpoint["origin"]) in {origin(row["url"]) for row in get["responses"]
                                                             if row["resource_id"] in identifiers}],
        "stability_run_sha256s": [sha256_file(directory / f"stability-{index}/run.json")
                                 for index in range(len(runs))],
        "stability_responses": [select(run["responses"]) for run in runs],
    }


def _complete_coverage_admission(discovery: DiscoveryResult) -> dict[str, Any]:
    """Bind an opt-in requirement covering every approved origin and rendered GET."""

    expandable = discovery.expandable_origins
    if (
        not isinstance(discovery.origin_ip_pins, dict)
        or not discovery.origin_ip_pins
        or set(discovery.origin_ip_pins) != set(discovery.approved_origins)
    ):
        raise PreparationError(
            "complete coverage requires one frozen origin-IP pin for every approved origin"
        )
    if not isinstance(expandable, list):
        raise PreparationError(
            "complete coverage requires the final browser discovery's "
            "HTTPS-GET-only expandable-origin ledger"
        )
    canonical_expandable: list[str] = []
    for value in expandable:
        expandable_origin = origin(value) if isinstance(value, str) else None
        if expandable_origin is None or expandable_origin != value:
            raise PreparationError(
                "complete coverage requires canonical HTTPS origins in the final "
                "browser discovery's expandable-origin ledger"
            )
        canonical_expandable.append(expandable_origin)
    if canonical_expandable != sorted(set(canonical_expandable)):
        raise PreparationError(
            "complete coverage requires a sorted unique final browser "
            "expandable-origin ledger"
        )
    observed_origins = {
        observed_origin
        for value in discovery.observed_origins
        if isinstance(value, str) and (observed_origin := origin(value)) is not None
    }
    if not set(canonical_expandable).issubset(observed_origins):
        raise PreparationError(
            "complete coverage final browser expandable origins exceed its "
            "observed-origin ledger"
        )
    approved_origin_set = set(discovery.approved_origins)
    unreported_approved = approved_origin_set - set(canonical_expandable)
    if unreported_approved:
        raise RecoverablePreparationError(
            "complete coverage final browser expandable-origin ledger omits approved "
            "HTTPS GET origins: " + ", ".join(sorted(unreported_approved))
        )
    newly_observed = set(canonical_expandable) - approved_origin_set
    if newly_observed:
        raise RecoverablePreparationError(
            "complete coverage final browser discovery observed new HTTPS GET origins "
            "after convergence: " + ", ".join(sorted(newly_observed))
        )
    retained_origins = {origin(resource["url"]) for resource in discovery.resources}
    missing = set(discovery.approved_origins) - retained_origins
    if missing:
        raise RecoverablePreparationError(
            "complete coverage requires a browser-rendered HTTPS GET from every approved "
            "origin; missing origins: " + ", ".join(sorted(missing))
        )
    evidence_values = (
        discovery.passive_render_contract,
        discovery.passive_render_contract_sha256,
        discovery.render_observation,
        discovery.render_observation_sha256,
        discovery.discovery_event_audit,
        discovery.discovery_event_audit_sha256,
    )
    if any(value is None for value in evidence_values):
        raise PreparationError(
            "complete coverage requires current bounded-render discovery evidence"
        )
    validate_passive_render_contract(
        discovery.passive_render_contract,
        digest=discovery.passive_render_contract_sha256,
    )
    validate_render_observation(discovery.render_observation)
    if (
        evidence_sha256(discovery.render_observation)
        != discovery.render_observation_sha256
        or evidence_sha256(discovery.discovery_event_audit)
        != discovery.discovery_event_audit_sha256
    ):
        raise PreparationError("complete-coverage discovery evidence SHA-256 is invalid")
    summary = verify_discovery_event_audit(
        discovery.discovery_event_audit,
        render_observation=discovery.render_observation,
        resources=discovery.resources,
        exclusions=discovery.exclusions,
        approved_origins=discovery.approved_origins,
        observed_request_count=discovery.observed_request_count,
        expected_observed_origins=discovery.observed_origins,
    )
    return {
        "schema_version": 3,
        "policy": COMPLETE_COVERAGE_POLICY,
        "required_origins": list(discovery.approved_origins),
        "required_resources": [
            {"id": resource["id"], "url": resource["url"]} for resource in discovery.resources
        ],
        "passive_render_contract_sha256": discovery.passive_render_contract_sha256,
        "render_observation_sha256": discovery.render_observation_sha256,
        "discovery_event_audit_sha256": discovery.discovery_event_audit_sha256,
        "origin_ip_pins_sha256": evidence_sha256(discovery.origin_ip_pins),
        "browser_request_headers_sha256": evidence_sha256(
            [
                {"resource_id": resource["id"], "headers": resource.get("headers", [])}
                for resource in discovery.resources
            ]
        ),
        "network_request_count": summary["network_request_count"],
        "resource_occurrence_count": summary["resource_occurrence_count"],
        "exclusion_occurrence_count": summary["exclusion_occurrence_count"],
    }


def _probe_response_stability(
    manifest: dict[str, Any],
    directory: Path,
    *,
    max_response_bytes: int,
    timeout_seconds: int,
    stability_runs: int,
    stability_interval_seconds: int,
    application_response_policy: str | None = None,
    source_url: str | None = None,
    final_url: str | None = None,
    primary_document_identity_policy: str | None = None,
    coverage_admission: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    selected_response_policy = validate_application_response_policy(application_response_policy)
    selected_primary_policy = validate_primary_document_identity_policy(primary_document_identity_policy)
    runtime_input = directory / "stability-input.json"
    runtime_input.write_bytes(canonical_bytes(runtime_manifest(manifest)))
    runs: list[dict[str, Any]] = []
    packet_runs: list[dict[str, Any]] = []
    for index in range(stability_runs):
        if index:
            time.sleep(stability_interval_seconds)
        output = directory / f"stability-{index}"
        result = _run_neqo(
            [
                NEQO_CLIENT,
                "run",
                *(["--application-response-policy", application_response_policy]
                  if application_response_policy is not None else []),
                "--workload",
                str(runtime_input),
                "--profile",
                STABILITY_PROFILE,
                "--defense",
                STABILITY_DEFENSE,
                "--seed",
                str(STABILITY_SEED),
                "--output-dir",
                str(output),
                "--max-response-bytes",
                str(max_response_bytes),
                "--timeout-seconds",
                str(timeout_seconds),
            ],
            log=directory / f"stability-{index}.log",
            configured_timeout_seconds=timeout_seconds,
            label=f"Neqo stability run {index + 1}",
        )
        if result.returncode:
            _raise_neqo_execution_failure(f"Neqo stability run {index + 1}", result)
        try:
            run_data = load_json(output / "run.json")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise PreparationError(
                f"Neqo stability run {index + 1} produced invalid evidence: {error}"
            ) from error
        if (
            selected_response_policy == COMPLETED_TERMINAL_HTTP_ERRORS_POLICY
            and run_data.get("completion_status") != "complete"
        ):
            # An incomplete exchange cannot qualify under this policy. Stop
            # before another replay or sleep; retain the actual failed run so
            # a transport/runner defect can be diagnosed immediately.
            incomplete = [
                response for response in run_data.get("responses", [])
                if response.get("complete") is not True
                or response.get("outcome") != "succeeded"
            ]
            summary = [
                {"resource_id": response.get("resource_id"),
                 "outcome": response.get("outcome")}
                for response in incomplete[:12]
            ]
            raise RecoverablePreparationError(
                f"Neqo stability run {index + 1} is incomplete "
                f"({len(incomplete)} incomplete responses; first resources: {summary}); "
                f"inspect stability-{index}/run.json and stability-{index}/events.csv"
            )
        if selected_primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY:
            actual_resources = json.loads(json.dumps(manifest["resources"]))
            _freeze_request_headers(actual_resources, [run_data])
            actual = {"resources": actual_resources, "preparation": {
                "application_response_policy": application_response_policy,
                "primary_document_identity_policy": primary_document_identity_policy,
                "source_url": source_url, "final_url": final_url,
                "max_response_bytes": max_response_bytes, "coverage_admission": coverage_admission,
                "expected_responses": [{key: response.get(key) for key in
                    ("resource_id", "status", "bytes", "body_sha256")}
                    for response in run_data.get("responses", [])],
            }}
            try:
                primary_rows = [row for row in run_data.get("responses", []) if row.get("resource_id") == 0]
                if len(primary_rows) != 1:
                    raise ValueError("primary Document is missing or repeated")
                validate_primary_document_response(actual, primary_rows[0])
            except (KeyError, TypeError, ValueError) as error:
                raise RecoverablePreparationError(f"primary Document replay is invalid: {error}") from error
        packet_runs.append(
            _qualify_udp_payloads(
                run_data,
                output / "packets.csv",
                run_index=index,
                expected_ceiling=STABILITY_UDP_PAYLOAD_CEILING,
            )
        )
        runs.append(run_data)
    primary_manifest = None
    if selected_primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY:
        try:
            primary_manifest = _variable_primary_stability_manifest(
                manifest, runs, source_url=source_url, final_url=final_url,
                max_response_bytes=max_response_bytes, coverage_admission=coverage_admission,
                stability_run_sha256s=[sha256_file(directory / f"stability-{index}/run.json")
                                      for index in range(stability_runs)],
            )
            stability = response_stability_evidence(
                runs, primary_document_identity_policy=primary_document_identity_policy,
                manifest=primary_manifest,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RecoverablePreparationError(f"variable primary complete graph replay is invalid: {error}") from error
        if set(resource["id"] for resource in manifest["resources"]) - set(stability["stable_resource_ids"]):
            stability["primary_document_identity_manifest"] = primary_manifest
    else:
        stability = response_stability_evidence(runs)
    if selected_response_policy == COMPLETED_TERMINAL_HTTP_ERRORS_POLICY:
        # Every run must actually opt into the native semantics and retain all
        # completed graph resources. Identity changes still reach the ordinary
        # three-run stability failure rather than being silently discarded.
        by_id = {resource["id"]: resource for resource in manifest["resources"]}
        for run_data in runs:
            candidate_expected = [{key: response[key] for key in ("resource_id", "status", "bytes", "body_sha256")}
                                  for response in run_data.get("responses", [])]
            candidate = {"resources": list(by_id.values()), "preparation": {
                "application_response_policy": application_response_policy,
                "source_url": source_url, "final_url": final_url,
                "expected_responses": candidate_expected,
            }}
            try:
                validate_application_responses(candidate, run_data)
            except (KeyError, TypeError, ValueError) as error:
                raise RecoverablePreparationError(f"terminal HTTP error stability run is invalid: {error}") from error
    return (
        stability,
        runs,
        {
            "schema_version": UDP_PAYLOAD_QUALIFICATION_SCHEMA_VERSION,
            "outgoing_udp_payload_ceiling": STABILITY_UDP_PAYLOAD_CEILING,
            "incoming_udp_payload_limit": STABILITY_INCOMING_UDP_PAYLOAD_LIMIT,
            "runs": packet_runs,
        },
    )


def _qualify_udp_payloads(
    run_data: dict[str, Any],
    packets_path: Path,
    *,
    run_index: int,
    expected_ceiling: int,
) -> dict[str, Any]:
    """Prove outgoing packetization and incoming QUIC receive bounds."""

    resolved = run_data.get("resolved_configuration")
    resolved_ceiling = resolved.get("max_udp_payload_size") if isinstance(resolved, dict) else None
    if (
        not isinstance(resolved_ceiling, int)
        or isinstance(resolved_ceiling, bool)
        or resolved_ceiling != expected_ceiling
    ):
        raise PreparationError(
            f"Neqo stability run {run_index + 1} did not resolve the "
            f"{expected_ceiling}-byte UDP-payload ceiling"
        )
    reported_outgoing = run_data.get("outgoing_udp_payload_ceiling")
    reported_incoming = run_data.get("incoming_udp_payload_limit")
    if (
        type(reported_outgoing) is not int
        or reported_outgoing != expected_ceiling
        or type(reported_incoming) is not int
        or reported_incoming != STABILITY_INCOMING_UDP_PAYLOAD_LIMIT
    ):
        raise PreparationError(
            f"Neqo stability run {run_index + 1} did not report the expected "
            "directional UDP-payload limits"
        )

    try:
        with packets_path.open(newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source)
            fieldnames = reader.fieldnames
            if fieldnames is None:
                raise PreparationError(
                    f"Neqo stability run {run_index + 1} packets.csv has no header"
                )
            if len(fieldnames) != len(set(fieldnames)):
                raise PreparationError(
                    f"Neqo stability run {run_index + 1} packets.csv has duplicate columns"
                )
            missing = PACKET_REQUIRED_COLUMNS - set(fieldnames)
            if missing:
                raise PreparationError(
                    f"Neqo stability run {run_index + 1} packets.csv is missing required "
                    f"columns: {', '.join(sorted(missing))}"
                )
            rows = list(reader)
    except PreparationError:
        raise
    except (OSError, UnicodeError, csv.Error) as error:
        raise PreparationError(
            f"Neqo stability run {run_index + 1} packets.csv is unreadable: {error}"
        ) from error

    lengths: dict[str, list[int]] = {"incoming": [], "outgoing": []}
    for line_number, row in enumerate(rows, start=2):
        direction = row.get("direction")
        connection = row.get("connection")
        observed_length = row.get("observed_udp_length")
        if direction not in lengths:
            raise PreparationError(
                f"Neqo stability run {run_index + 1} packets.csv line {line_number} "
                "has an invalid direction"
            )
        try:
            _runner_csv_u64(connection, label="runner packet connection")
        except ValueError:
            raise PreparationError(
                f"Neqo stability run {run_index + 1} packets.csv line {line_number} "
                "has an invalid connection"
            ) from None
        try:
            parsed_length = _runner_csv_u64(
                observed_length, label="runner packet observed UDP length"
            )
        except ValueError:
            parsed_length = 0
        if parsed_length < 1:
            raise PreparationError(
                f"Neqo stability run {run_index + 1} packets.csv line {line_number} "
                "has an invalid observed_udp_length"
            )
        lengths[direction].append(parsed_length)

    missing_directions = [direction for direction, values in lengths.items() if not values]
    if missing_directions:
        raise PreparationError(
            f"Neqo stability run {run_index + 1} packets.csv contains no "
            f"{', '.join(missing_directions)} packets"
        )

    def statistics(values: list[int], ceiling: int) -> dict[str, int]:
        return {
            "packet_count": len(values),
            "observed_udp_payload_max": max(values),
            "oversized_packet_count": sum(value > ceiling for value in values),
        }

    incoming = statistics(
        lengths["incoming"], STABILITY_INCOMING_UDP_PAYLOAD_LIMIT
    )
    outgoing = statistics(lengths["outgoing"], expected_ceiling)
    total_values = lengths["incoming"] + lengths["outgoing"]
    total = {
        "packet_count": len(total_values),
        "observed_udp_payload_max": max(total_values),
        "oversized_packet_count": (
            incoming["oversized_packet_count"] + outgoing["oversized_packet_count"]
        ),
    }
    if total["oversized_packet_count"]:
        raise PreparationError(
            f"Neqo stability run {run_index + 1} observed "
            f"{total['oversized_packet_count']} UDP payload(s) above the "
            "directional limits (incoming "
            f"{incoming['oversized_packet_count']} above "
            f"{STABILITY_INCOMING_UDP_PAYLOAD_LIMIT}, outgoing "
            f"{outgoing['oversized_packet_count']} above {expected_ceiling}, maximum "
            f"{total['observed_udp_payload_max']})"
        )
    return {
        "run_index": run_index,
        "packets_sha256": sha256_file(packets_path),
        "total": total,
        "incoming": incoming,
        "outgoing": outgoing,
    }


def _run_neqo(
    command: list[str],
    *,
    log: Path,
    configured_timeout_seconds: int,
    label: str,
) -> subprocess.CompletedProcess[str]:
    """Run one preparation client under a deadline independent of Neqo."""

    host_timeout = neqo_host_timeout(configured_timeout_seconds)
    measured_command = [*capture_scheduler_launch_prefix(), *command]
    started_at = datetime.now(UTC).isoformat()
    try:
        result = run(measured_command, log=log, check=False, timeout=host_timeout)
    except ProcessTimeoutError as error:
        detail = error.result.stdout.strip() or "no client output"
        raise RecoverablePreparationError(
            f"{label} exceeded its enforced {host_timeout:g}s host timeout: {detail}"
        ) from error
    stdout = result.stdout or ""
    durable_create(Path(str(log) + ".execution.json"), canonical_bytes({
        "schema_version": 1, "command": measured_command, "returncode": result.returncode,
        "configured_timeout_seconds": configured_timeout_seconds, "host_timeout_seconds": host_timeout,
        "started_at": started_at, "completed_at": datetime.now(UTC).isoformat(),
        "stdout": stdout, "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
    }))
    return result


def _raise_neqo_execution_failure(
    label: str, result: subprocess.CompletedProcess[str]
) -> None:
    """Classify an exited preparation client without masking Rust panics.

    Rust's panic runtime conventionally exits with status 101.  Treat every
    such exit as an internal preparation failure even when its panic marker was
    truncated or suppressed; acquisition will durably checkpoint and abort it.
    Other non-zero exits retain the existing recoverable live-network policy.
    """

    if result.returncode == 0:
        raise ValueError("Neqo execution failure classifier requires a non-zero exit")
    detail = result.stdout.strip() or "no client output"
    message = f"{label} failed ({result.returncode}): {detail}"
    if result.returncode == 101:
        raise PreparationError(message)
    raise RecoverablePreparationError(message)


def response_stability_evidence(
    runs: list[dict[str, Any]], *, primary_document_identity_policy: str | None = None,
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return response identities that repeated exactly across complete runs."""

    if len(runs) < 2:
        raise ValueError("response stability requires at least two runs")
    variable_primary = validate_primary_document_identity_policy(primary_document_identity_policy) == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
    if variable_primary:
        if not isinstance(manifest, Mapping) or len(runs) != 3:
            raise ValueError("variable primary response stability requires its complete prepared declaration and three runs")
        validate_primary_document_identity_evidence(manifest)
        for actual_run in runs:
            _validate_variable_primary_stability_run(manifest, actual_run)
    signatures: list[dict[int, tuple[Any, ...]]] = []
    first_responses: dict[int, dict[str, Any]] = {}
    for run_data in runs:
        current: dict[int, tuple[Any, ...]] = {}
        # A partial/error run can still contain completed responses for other
        # independent resources.  Preserve those identities so the caller can
        # report only the resources that actually failed or changed.  A failed
        # or missing required resource is still absent here and therefore
        # cannot pass the all-runs comparison below.
        for response in run_data.get("responses", []):
            if response.get("complete") is not True or response.get("outcome") != "succeeded":
                continue
            resource_id = response.get("resource_id")
            if not isinstance(resource_id, int) or isinstance(resource_id, bool):
                continue
            signature = (
                response.get("status"),
                response.get("bytes"),
                response.get("body_sha256"),
                tuple(tuple(header) for header in response.get("request_headers", [])),
            )
            if variable_primary and resource_id == 0:
                signature = (response.get("status"), VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
                             VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY, signature[3])
            current[resource_id] = signature
            first_responses.setdefault(resource_id, response)
        signatures.append(current)
    all_ids = set().union(*(set(signature) for signature in signatures))
    stable_ids = [
        resource_id
        for resource_id in sorted(all_ids)
        if all(
            resource_id in signature and signature[resource_id] == signatures[0].get(resource_id)
            for signature in signatures
        )
    ]
    expected = [
        {
            "resource_id": resource_id,
            "status": first_responses[resource_id].get("status"),
            "bytes": first_responses[resource_id].get("bytes"),
            "body_sha256": first_responses[resource_id].get("body_sha256"),
        }
        for resource_id in stable_ids
    ]
    return {
        "runs": len(runs),
        "stable_resource_ids": stable_ids,
        "expected_responses": expected,
    }


def _freeze_request_headers(resources: list[dict[str, Any]], runs: list[dict[str, Any]]) -> None:
    first = {
        response["resource_id"]: response
        for response in runs[0].get("responses", [])
        if response.get("complete") is True and response.get("outcome") == "succeeded"
    }
    for resource in resources:
        try:
            headers = first[resource["id"]]["request_headers"]
        except (KeyError, TypeError) as error:
            raise PreparationError(
                f"Neqo did not record concrete request headers for resource {resource['id']}"
            ) from error
        if not isinstance(headers, list):
            raise PreparationError(
                f"Neqo recorded invalid request headers for resource {resource['id']}"
            )
        resource["headers"] = headers
    validate_manifest({"resources": resources})


def _neqo_provenance(runs: list[dict[str, Any]]) -> dict[str, str]:
    first = {key: runs[0].get(key) for key in NEQO_PROVENANCE_KEYS}
    if any(not isinstance(value, str) or not value for value in first.values()):
        raise PreparationError("Neqo stability evidence is missing client provenance")
    for run_data in runs[1:]:
        if any(run_data.get(key) != value for key, value in first.items()):
            raise PreparationError("Neqo client provenance changed across stability runs")
    return first  # type: ignore[return-value]
