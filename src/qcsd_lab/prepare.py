from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .discover import DiscoveryResult, discover_page, origin
from .manifest import (
    canonical_bytes,
    project_stable_response_lengths,
    runtime_manifest,
    validate_manifest,
    validate_prepared_navigation_graph,
    write_frozen_manifest,
)
from .util import (
    LAB_ROOT,
    ProcessTimeoutError,
    load_json,
    neqo_host_timeout,
    run,
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
UDP_PAYLOAD_QUALIFICATION_SCHEMA_VERSION = 1
PACKET_REQUIRED_COLUMNS = frozenset({"direction", "connection", "observed_udp_length"})
WORKLOAD_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
NEQO_PROVENANCE_KEYS = (
    "neqo_version",
    "neqo_base_commit",
    "published_qcsd_commit",
    "migration_commit",
)


class PreparationError(RuntimeError):
    """A browser discovery or direct Neqo preparation check failed."""


@dataclass(frozen=True)
class PreparedWorkload:
    path: Path
    sha256: str
    resource_count: int
    origin_count: int


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
) -> PreparedWorkload:
    """Discover, probe, stability-check, and freeze one replay workload.

    The output path is deliberately derived from ``workload_id``. Preparation
    never updates an existing workload; a changed graph or response identity
    must receive a new ID.
    """

    _validate_arguments(
        workload_id,
        source_url,
        approved_origins,
        timeout_ms=timeout_ms,
        max_response_bytes=max_response_bytes,
        timeout_seconds=timeout_seconds,
        stability_runs=stability_runs,
        stability_interval_seconds=stability_interval_seconds,
    )
    root = output_root or (LAB_ROOT / "config" / "workloads")
    output = root / f"{workload_id}.json"
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"{output} already exists; choose a new workload ID")

    discovery = discover_page(
        source_url,
        allow_origins=approved_origins,
        timeout_ms=timeout_ms,
    )
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{workload_id}-prepare-", dir=root) as temporary:
        directory = Path(temporary)
        probe_input = {"resources": discovery.resources}
        validate_manifest(probe_input)
        probe_output = _probe(
            probe_input,
            directory,
            max_response_bytes=max_response_bytes,
            timeout_seconds=timeout_seconds,
        )
        resources, exclusions = resolve_probe_output(discovery, probe_output)
        resolved = {"resources": resources}
        evidence, runs, udp_payload_qualification = _probe_response_stability(
            resolved,
            directory,
            max_response_bytes=max_response_bytes,
            timeout_seconds=timeout_seconds,
            stability_runs=stability_runs,
            stability_interval_seconds=stability_interval_seconds,
        )

    required = {resource["id"] for resource in resources}
    stable = set(evidence["stable_resource_ids"])
    if unstable := required - stable:
        identifiers = ", ".join(map(str, sorted(unstable)))
        raise PreparationError(
            f"repeated Neqo fetches changed or failed for resource IDs: {identifiers}"
        )
    try:
        resources = project_stable_response_lengths(resources, evidence["expected_responses"])
    except (KeyError, TypeError, ValueError) as error:
        raise PreparationError(
            f"stable response evidence cannot canonicalize resource lengths: {error}"
        ) from error
    _freeze_request_headers(resources, runs)
    provenance = _neqo_provenance(runs)
    manifest = {
        "preparation": {
            "source_url": discovery.source_url,
            "final_url": discovery.final_url,
            "chromium_version": discovery.chromium_version,
            "settle_ms": discovery.settle_ms,
            "observed_request_count": discovery.observed_request_count,
            "observed_origins": discovery.observed_origins,
            "approved_origins": discovery.approved_origins,
            "exclusions": exclusions,
            "prepare_image_digest": os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native"),
            "lab_source": source_metadata(),
            "max_response_bytes": max_response_bytes,
            "timeout_seconds": timeout_seconds,
            "stability_runs": stability_runs,
            "stability_profile": STABILITY_PROFILE,
            "stability_defense": STABILITY_DEFENSE,
            "stability_seed": STABILITY_SEED,
            "udp_payload_qualification": udp_payload_qualification,
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
) -> None:
    if not isinstance(workload_id, str) or not WORKLOAD_ID.fullmatch(workload_id):
        raise ValueError("workload ID must contain lowercase letters, digits, and single hyphens")
    if origin(source_url) is None:
        raise ValueError(f"source URL is not absolute HTTPS: {source_url}")
    if not isinstance(approved_origins, list) or not approved_origins:
        raise ValueError("workload preparation requires at least one approved origin")
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
        detail = result.stdout.strip() or "no client output"
        raise PreparationError(f"Neqo HTTP/3 probe failed ({result.returncode}): {detail}")
    try:
        resolved = load_json(output)
        validate_manifest(resolved)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise PreparationError(f"Neqo probe produced an invalid manifest: {error}") from error
    return resolved


def resolve_probe_output(
    discovery: DiscoveryResult,
    resolved: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Retain the fetchable dependency closure without rewriting graph edges."""

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

    unavailable = [
        resource for resource in resolved["resources"] if resource.get("known_valid") is not True
    ]
    retained_ids = {
        resource["id"] for resource in resolved["resources"] if resource.get("known_valid") is True
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


def _probe_response_stability(
    manifest: dict[str, Any],
    directory: Path,
    *,
    max_response_bytes: int,
    timeout_seconds: int,
    stability_runs: int,
    stability_interval_seconds: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
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
            detail = result.stdout.strip() or "no client output"
            raise PreparationError(
                f"Neqo stability run {index + 1} failed ({result.returncode}): {detail}"
            )
        try:
            run_data = load_json(output / "run.json")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise PreparationError(
                f"Neqo stability run {index + 1} produced invalid evidence: {error}"
            ) from error
        packet_runs.append(
            _qualify_udp_payloads(
                run_data,
                output / "packets.csv",
                run_index=index,
                expected_ceiling=STABILITY_UDP_PAYLOAD_CEILING,
            )
        )
        runs.append(run_data)
    return (
        response_stability_evidence(runs),
        runs,
        {
            "schema_version": UDP_PAYLOAD_QUALIFICATION_SCHEMA_VERSION,
            "configured_udp_payload_ceiling": STABILITY_UDP_PAYLOAD_CEILING,
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
    """Prove one preparation run respected the absolute UDP-payload ceiling."""

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
        if (
            not isinstance(connection, str)
            or not connection.isascii()
            or not connection.isdigit()
            or int(connection) > 2**64 - 1
        ):
            raise PreparationError(
                f"Neqo stability run {run_index + 1} packets.csv line {line_number} "
                "has an invalid connection"
            )
        if (
            not isinstance(observed_length, str)
            or not observed_length.isascii()
            or not observed_length.isdigit()
            or int(observed_length) < 1
        ):
            raise PreparationError(
                f"Neqo stability run {run_index + 1} packets.csv line {line_number} "
                "has an invalid observed_udp_length"
            )
        lengths[direction].append(int(observed_length))

    missing_directions = [direction for direction, values in lengths.items() if not values]
    if missing_directions:
        raise PreparationError(
            f"Neqo stability run {run_index + 1} packets.csv contains no "
            f"{', '.join(missing_directions)} packets"
        )

    def statistics(values: list[int]) -> dict[str, int]:
        return {
            "packet_count": len(values),
            "observed_udp_payload_max": max(values),
            "oversized_packet_count": sum(value > expected_ceiling for value in values),
        }

    incoming = statistics(lengths["incoming"])
    outgoing = statistics(lengths["outgoing"])
    total_values = lengths["incoming"] + lengths["outgoing"]
    total = statistics(total_values)
    if total["oversized_packet_count"]:
        raise PreparationError(
            f"Neqo stability run {run_index + 1} observed "
            f"{total['oversized_packet_count']} UDP payload(s) above the "
            f"{expected_ceiling}-byte ceiling (incoming "
            f"{incoming['oversized_packet_count']}, outgoing "
            f"{outgoing['oversized_packet_count']}, maximum "
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
    try:
        return run(command, log=log, check=False, timeout=host_timeout)
    except ProcessTimeoutError as error:
        detail = error.result.stdout.strip() or "no client output"
        raise PreparationError(
            f"{label} exceeded its enforced {host_timeout:g}s host timeout: {detail}"
        ) from error


def response_stability_evidence(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Return response identities that repeated exactly across complete runs."""

    if len(runs) < 2:
        raise ValueError("response stability requires at least two runs")
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
