"""Immutable qualification evidence for the distinct compact chaff substrate.

The application workload is never rewritten.  A qualification sidecar binds its
exact bytes, proves one deterministically selected compact same-origin response,
and derives the separate manifest accepted by the production chaff namespace.
"""

from __future__ import annotations

import json
import ctypes
import errno
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .manifest import canonical_bytes, runtime_manifest, validate_research_preparation
from .prepare import NEQO_PROVENANCE_KEYS, PreparationError, _run_neqo
from .util import (
    LAB_ROOT,
    SOURCE_METADATA_KEYS,
    load_json,
    sha256_bytes,
    sha256_file,
    source_metadata,
)

QUALIFICATION_SCHEMA_VERSION = 2
# The published response-only v1 sidecars and their schema-three runtime
# manifests are immutable verification inputs.  The stronger identity
# qualification therefore advances both namespaces rather than changing the
# meaning of either frozen schema.
RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION = 1
RESPONSE_ONLY_MANIFEST_SCHEMA_VERSION = 3
RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION = 2
RESPONSE_ONLY_MANIFEST_V2_SCHEMA_VERSION = 4
RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION = 3
IMPLEMENTATION_RECEIPT_SCHEMA_VERSION = 1
# Public compatibility name: this refers to qualification artifacts, not the
# separately versioned implementation receipt below.
SCHEMA_VERSION = QUALIFICATION_SCHEMA_VERSION
SIDECAR_ARTIFACT_TYPE = "qcsd-chaff-qualification"
CORE_ARTIFACT_TYPE = "qcsd-qualified-chaff-core"
MANIFEST_ARTIFACT_TYPE = "qcsd-qualified-chaff-manifest"
PREFIX_SPEC_ARTIFACT_TYPE = "qcsd-walkie-talkie-prefix-pack-spec"
RESPONSE_ARTIFACT_TYPE = "qcsd-chaff-response-qualification"
RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE = "qcsd-chaff-response-only-qualification"
RESPONSE_ONLY_QUALIFICATION_SCOPE = "response-only"
PREFIX_ARTIFACT_TYPE = "qcsd-chaff-prefix-pack-qualification"
HEADER_PROJECTION = ("accept", "accept-encoding", "accept-language")
SELECTION_POLICY = "qualified-largest-known-valid-same-origin-response-v2"
RESPONSE_ONLY_V2_SELECTION_POLICY = (
    "first-stable-identity-response-from-prepared-body-descending-prefix-v1"
)
IDENTITY_COPIED_HEADERS = ("accept", "accept-language")
IDENTITY_FORCED_HEADERS = (("accept-encoding", "identity"),)
IDENTITY_REQUEST_HEADER_MODE = "identity-chaff-v1"
METHOD = "GET"
QUALIFICATION_RUNS = 3
MAX_QUALIFIED_CHAFF_STREAMS = 20
MIN_CROSS_MODE_PARALLEL_CHAFF_STREAMS = 5
RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS = 5
RESPONSE_ONLY_WAVES_PER_EPOCH = 8
RESPONSE_ONLY_REQUESTS_PER_EPOCH = (
    RESPONSE_ONLY_WAVES_PER_EPOCH * RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
)
RESPONSE_ONLY_COMPLETIONS_PER_CANDIDATE = QUALIFICATION_RUNS * RESPONSE_ONLY_REQUESTS_PER_EPOCH
RESPONSE_ONLY_EPOCH_SPACING_SECONDS = 30
RESPONSE_ONLY_WAVE_SPACING_MILLISECONDS = 0
UDP_PAYLOAD_CEILING = 1_200
QUALIFICATION_SET_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
MAX_STREAM_DATA_EXCESS = 1_000
MAX_WALKIE_TALKIE_COMPONENT_CELLS = 2**32 - 1
SENDER_FRAMING_CELLS = 1
SOURCE_WALKIE_TALKIE_SHA256 = "16dc343e233f7531277d96fd914d177202e7a508a50f7becdf2d8c0102b8446c"
SCHEMA_FIVE_WALKIE_TALKIE_ARCHIVE = Path(
    "artifacts/research-1200-superseded-schema5-0a141768/walkie-talkie.json"
)
SEALED_WORKLOAD_IDS = (
    "getbootstrap-home-r3",
    "bootstrap-introduction-r3",
    "apache-traffic-server-docs-r3",
    "nginx-quic-r3",
    "cloudflare-quiche-r3",
    "nghttp2-ngtcp2-r3",
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IMAGE_IMPLEMENTATION_RECEIPT = Path(
    os.environ.get(
        "QCSD_QUALIFICATION_IMPLEMENTATION_RECEIPT",
        "/usr/share/qcsd-lab/qualification-implementation.json",
    )
)

# Every Python module is included because CLI imports make the whole package a
# transitive startup surface.  Data/docs-only commits may follow qualification.
IMPLEMENTATION_STATIC_FILES = (
    ".dockerignore",
    "Dockerfile",
    "docker/collection-entrypoint",
    "pyproject.toml",
    "qcsd-lab",
    "uv.lock",
)
IMPLEMENTATION_PYTHON_FILES = tuple(
    path.relative_to(LAB_ROOT).as_posix()
    for path in sorted((LAB_ROOT / "src/qcsd_lab").rglob("*.py"))
)
IMPLEMENTATION_FILES = IMPLEMENTATION_STATIC_FILES + IMPLEMENTATION_PYTHON_FILES

SIDECAR_KEYS = {
    "schema_version",
    "artifact_type",
    "workload_id",
    "base_manifest",
    "selection_policy",
    "application_resource_id",
    "selected_chaff_resource_id",
    "qualified_parallel_chaff_streams",
    "walkie_talkie_required_chaff_streams",
    "header_projection",
    "method",
    "qualification_policy",
    "qualification_source",
    "qualification_image_digest",
    "neqo_provenance",
    "implementation_receipt",
    "fitting_source",
    "schema_five_diagnostic",
    "schema_six_capacity_falsification_diagnostic",
    "schema_six_runtime_falsification_diagnostic",
    "schema_two_sender_framing_falsification_diagnostic",
    "prefix_pack_spec",
    "resource",
}
RESPONSE_ONLY_SIDECAR_KEYS = {
    "schema_version",
    "artifact_type",
    "qualification_scope",
    "workload_id",
    "base_manifest",
    "selection_policy",
    "application_resource_id",
    "selected_chaff_resource_id",
    "qualified_parallel_chaff_streams",
    "header_projection",
    "method",
    "qualification_policy",
    "qualification_source",
    "qualification_image_digest",
    "neqo_provenance",
    "implementation_receipt",
    "resource",
}
RESPONSE_ONLY_V2_SIDECAR_KEYS = {
    "schema_version",
    "artifact_type",
    "qualification_scope",
    "workload_id",
    "base_manifest",
    "selection_policy",
    "application_resource_id",
    "selected_chaff_resource_id",
    "qualified_parallel_chaff_streams",
    "request_header_primitive",
    "method",
    "qualification_policy",
    "qualification_source",
    "qualification_image_digest",
    "neqo_provenance",
    "implementation_receipt",
    "candidate_attempts",
    "resource",
}
BASE_MANIFEST_KEYS = {"path", "sha256"}
POLICY_KEYS = {
    "response_runs",
    "parallel_response_requests",
    "qualified_parallel_chaff_streams",
    "walkie_talkie_required_chaff_streams",
    "prefix_pack_runs",
    "profile",
    "response_defense",
    "seed",
    "udp_payload_ceiling",
    "max_stream_data_excess",
    "separate_chaff_namespace",
}
RESPONSE_ONLY_POLICY_KEYS = {
    "qualification_scope",
    "response_runs",
    "parallel_response_requests",
    "qualified_parallel_chaff_streams",
    "profile",
    "response_defense",
    "seed",
    "udp_payload_ceiling",
    "max_response_bytes",
    "separate_chaff_namespace",
}
RESPONSE_ONLY_V2_POLICY_KEYS = {
    "qualification_scope",
    "connection_epochs_per_candidate",
    "waves_per_connection_epoch",
    "parallel_requests_per_wave",
    "total_requests_per_connection_epoch",
    "total_completions_per_candidate",
    "connection_epoch_spacing_seconds",
    "inter_wave_spacing_milliseconds",
    "qualified_parallel_chaff_streams",
    "profile",
    "response_defense",
    "seed",
    "udp_payload_ceiling",
    "max_response_bytes",
    "separate_chaff_namespace",
}
REQUEST_HEADER_PRIMITIVE_KEYS = {
    "mode",
    "copied_from_application",
    "forced",
}
IMPLEMENTATION_KEYS = {
    "schema_version",
    "artifact_type",
    "domain",
    "source",
    "source_files",
    "installed_modules",
    "installed_entrypoint",
    "neqo_qcsd_client",
    "sha256",
}
FITTING_SOURCE_KEYS = {
    "evidence_sha256",
    "experiment_sha256",
    "samples_consumed",
    "qualification_bytes_excluded",
}
DIAGNOSTIC_KEYS = {
    "campaign",
    "evidence_sha256",
    "experiment_sha256",
    "status",
    "planned",
    "accepted",
    "eligible",
    "failed",
    "role",
    "qualification_bytes_excluded",
}
SCHEMA_SIX_CAPACITY_DIAGNOSTIC_KEYS = DIAGNOSTIC_KEYS | {
    "failed_workload_id",
    "failed_defense",
    "attempts",
}
SCHEMA_SIX_RUNTIME_FALSIFICATION_DIAGNOSTIC_KEYS = DIAGNOSTIC_KEYS | {
    "archive_manifest_path",
    "archive_manifest_sha256",
    "terminal_failures",
    "recovered_retries",
}
SCHEMA_SIX_RUNTIME_TERMINAL_FAILURE_KEYS = {
    "workload_id",
    "defense",
    "stage",
    "attempts",
}
SCHEMA_SIX_RUNTIME_RECOVERED_RETRY_KEYS = {
    "workload_id",
    "defense",
    "failed_attempts",
    "accepted_attempt",
}
SCHEMA_TWO_SENDER_FRAMING_DIAGNOSTIC_KEYS = {
    "archive_manifest_sha256",
    "failed_workload_id",
    "failed_phase",
    "failed_run_index",
    "receipt_sha256",
    "packets_sha256",
    "log_sha256",
    "role",
    "qualification_bytes_excluded",
}
RESOURCE_RECEIPT_KEYS = {
    "resource_id",
    "url",
    "headers",
    "request_stream_bytes",
    "expected_response",
    "response_runs",
    "response_qualification_sha256",
    "prefix_pack_runs",
    "prefix_pack_qualification_sha256",
}
RESPONSE_ONLY_RESOURCE_RECEIPT_KEYS = {
    "resource_id",
    "url",
    "headers",
    "request_stream_bytes",
    "expected_response",
    "response_runs",
    "response_qualification_sha256",
}
RESPONSE_ONLY_V2_RESOURCE_RECEIPT_KEYS = {
    "resource_id",
    "url",
    "headers",
    "request_stream_bytes",
    "expected_response",
    "response_qualification_sha256",
}
EXPECTED_RESPONSE_KEYS = {"status", "content_encoding", "body_bytes", "body_sha256"}
RESPONSE_RUN_KEYS = {
    "run_index",
    "receipt_object_sha256",
    "receipt",
}
RESPONSE_V2_RUN_KEYS = {
    "epoch_index",
    "process_exit_code",
    "receipt_object_sha256",
    "receipt",
}
CANDIDATE_ATTEMPT_KEYS = {
    "candidate_index",
    "resource_id",
    "url",
    "prepared_response",
    "headers",
    "outcome",
    "failure_class",
    "connection_epochs",
    "response_qualification_sha256",
}
PREPARED_CANDIDATE_RESPONSE_KEYS = {"status", "body_bytes", "body_sha256"}
PREFIX_RUN_KEYS = {"run_index", "receipt_object_sha256", "receipt"}
RESPONSE_RECEIPT_KEYS = {
    "schema_version",
    "artifact_type",
    "invocation_id",
    "neqo_version",
    "application_workload_sha256",
    "application_resource_id",
    "selected_chaff_resource_id",
    "qualified_parallel_chaff_streams",
    "method",
    "url",
    "request_headers",
    "parallel_requests",
    "connection_count",
    "requests_opened_before_first_network_output",
    "request_stream_bytes",
    "max_response_bytes",
    "udp_payload_ceiling",
    "started_unix_ns",
    "ended_unix_ns",
    "completion_status",
    "error",
    "source",
    "requests",
    "packet_observations",
    "packet_log_sha256",
    "packets",
    "passed",
}
RESPONSE_V2_RECEIPT_KEYS = RESPONSE_RECEIPT_KEYS | {
    "total_requests",
    "request_waves",
    "max_concurrent_requests",
    "request_header_mode",
    "failure_class",
}
RESPONSE_REQUEST_KEYS = {
    "request_index",
    "stream_id",
    "request_stream_bytes",
    "status",
    "content_encoding",
    "body_bytes",
    "body_sha256",
    "complete",
    "outcome",
}
RESPONSE_V2_REQUEST_KEYS = RESPONSE_REQUEST_KEYS | {"wave_index"}
PACKET_OBSERVATION_KEYS = {"sequence", "phase", "direction", "udp_payload_bytes"}
PREFIX_RECEIPT_KEYS = {
    "schema_version",
    "artifact_type",
    "invocation_id",
    "neqo_version",
    "application_workload_source_sha256",
    "runtime_workload_sha256",
    "chaff_core_sha256",
    "prefix_pack_spec_sha256",
    "application_resource_id",
    "selected_chaff_resource_id",
    "selected_chaff_body_bytes",
    "required_chaff_streams",
    "workload_id",
    "numeric_profile_sha256",
    "source_walkie_talkie_artifact_sha256",
    "packet_size",
    "max_stream_data_excess",
    "maximum_receiver_continuation_reserve_horizon",
    "required_chaff_survivors",
    "connection_count",
    "peer_settings_received",
    "warmup_stream_output_drained",
    "packet_cutoff_sequence",
    "requests_opened",
    "scheduled_target_slot_ids",
    "satisfied_target_slot_ids",
    "activation_stage_receipts",
    "streams",
    "stream_transmissions",
    "packet_observations",
    "packet_log_sha256",
    "packets",
    "post_slot_pending_stream_send",
    "post_slot_pending_required_prefix_stream_send",
    "qpack_decoder_stream_id",
    "qpack_decoder_handler_pending",
    "qpack_decoder_transport_pending",
    "allowed_pending_late_chaff_request_orders",
    "allowed_pending_late_chaff_stream_ids",
    "targetless_stream_bytes",
    "completion_status",
    "error",
    "started_unix_ns",
    "ended_unix_ns",
    "source",
    "passed",
}
PREFIX_STAGE_RECEIPT_KEYS = {
    "stage_index",
    "component_index",
    "application_resource_ids",
    "application_request_orders",
    "application_stream_ids",
    "target_slot_ids",
    "exact_target_cells",
    "scheduled_target_bytes",
    "required_active_chaff_streams",
    "newly_required_chaff_streams",
    "peer_acknowledged_active_chaff_streams",
    "newly_peer_acknowledged_request_orders",
    "newly_peer_acknowledged_stream_ids",
    "allowed_pending_chaff_request_orders",
    "allowed_pending_chaff_stream_ids",
    "targetless_stream_bytes_at_gate",
    "pending_required_prefix_stream_send",
    "passed",
}
PREFIX_STREAM_KEYS = {
    "request_order",
    "opening_stage_index",
    "role",
    "resource_id",
    "request_id",
    "stream_id",
    "request_stream_bytes",
    "qualified_request_stream_bytes",
    "transmitted_unique_ranges",
    "transmitted_unique_bytes",
    "fin_transmitted",
    "acknowledgements",
    "acknowledged_unique_ranges",
    "acknowledged_unique_bytes",
    "fin_acknowledged",
}
PREFIX_TRANSMISSION_KEYS = {
    "sequence",
    "stream",
    "role",
    "offset",
    "bytes",
    "fin",
    "slot",
}
PREFIX_ACK_KEYS = {"sequence", "offset", "bytes", "fin"}
STREAM_ACTIVATION_STAGE_KEYS = {
    "component_index",
    "application_resource_ids",
    "exact_target_cells",
    "outgoing_cells",
    "symmetric_incoming_cells",
    "adapted_incoming_cells",
    "application_body_floor_bytes",
    "base_chaff_bytes",
    "continuation_bytes",
    "required_active_chaff_streams",
    "newly_required_chaff_streams",
    "future_continuation_reserves",
    "exact_capacity_before_bytes",
    "ordinary_capacity_before_bytes",
    "exact_capacity_after_bytes",
    "early_continuation_required",
}


@dataclass(frozen=True)
class QualifiedChaffInput:
    """A validated sidecar and its deterministic final runtime manifest."""

    sidecar_path: Path
    sidecar_sha256: str
    manifest: dict[str, Any]
    manifest_sha256: str
    application_manifest_sha256: str
    application_resource_id: int
    selected_chaff_resource_id: int
    qualified_parallel_chaff_streams: int
    walkie_talkie_required_chaff_streams: int | None


@dataclass(frozen=True)
class QualifiedChaffOutput:
    path: Path
    sha256: str
    manifest_sha256: str


def implementation_receipt(
    root: Path = LAB_ROOT, *, executed_image: bool = False
) -> dict[str, Any]:
    """Load the executed receipt, with a source projection for native tests."""

    if executed_image:
        try:
            value = load_json(IMAGE_IMPLEMENTATION_RECEIPT)
        except (OSError, ValueError, TypeError) as error:
            raise ValueError(
                "qualification image lacks its executed-source implementation receipt"
            ) from error
        _validate_implementation_receipt(value, require_current=False)
        for record in [
            *value["installed_modules"].values(),
            value["installed_entrypoint"],
            value["neqo_qcsd_client"],
        ]:
            path = Path(record["path"])
            if path.is_symlink() or not path.is_file() or sha256_file(path) != record["sha256"]:
                raise ValueError("qualification image executable receipt does not match disk")
        return dict(value)

    files = _implementation_source_files(root)
    modules = {
        path: {"path": str((root / path).resolve()), "sha256": files[path]}
        for path in IMPLEMENTATION_PYTHON_FILES
    }
    receipt: dict[str, Any] = {
        "schema_version": IMPLEMENTATION_RECEIPT_SCHEMA_VERSION,
        "artifact_type": "qcsd-chaff-qualification-implementation",
        "domain": "qcsd-chaff-qualification-implementation-v1",
        "source": source_metadata(),
        "source_files": files,
        "installed_modules": modules,
        "installed_entrypoint": {
            "path": str((root / "qcsd-lab").resolve()),
            "sha256": files["qcsd-lab"],
        },
        # Native unit tests cannot assert a release binary.  Production
        # qualification always uses executed_image=True and rejects this
        # projection before any network call.
        "neqo_qcsd_client": {"path": "native-test-projection", "sha256": "0" * 64},
    }
    receipt["sha256"] = _implementation_aggregate(receipt)
    return receipt


def _implementation_source_files(root: Path = LAB_ROOT) -> dict[str, str]:
    root = root.resolve()
    files: dict[str, str] = {}
    for relative in IMPLEMENTATION_FILES:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"qualification implementation file is missing: {relative}")
        files[relative] = sha256_file(path)
    return files


def _implementation_aggregate(receipt: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in receipt.items() if key != "sha256"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(b"qcsd-chaff-qualification-implementation-v1\0" + encoded)


def qualification_digest(domain: str, values: Sequence[Mapping[str, Any]]) -> str:
    payload = json.dumps(list(values), sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(domain.encode("ascii") + b"\0" + payload)


def project_compact_headers(resource: Mapping[str, Any]) -> list[list[str]]:
    """Project exact existing AEL values in their original order, never synthesizing."""

    headers = resource.get("headers")
    if not isinstance(headers, list):
        raise ValueError("qualified application resource headers must be a list")
    projected = [list(header) for header in headers if header[0].lower() in HEADER_PROJECTION]
    names = [header[0] for header in projected]
    if names != list(HEADER_PROJECTION):
        raise ValueError(
            "qualified chaff headers must contain exact lowercase accept, accept-encoding, "
            "and accept-language values in application-manifest order"
        )
    return projected


def project_identity_chaff_headers(resource: Mapping[str, Any]) -> list[list[str]]:
    """Derive the response-only v2 request namespace without rewriting the app.

    Accept and Accept-Language are copied byte-for-byte from the frozen
    application resource.  Accept-Encoding is deliberately *not* copied: the
    distinct chaff request forces the literal value ``identity`` so its
    qualified representation cannot silently depend on content negotiation.
    """

    headers = resource.get("headers")
    if not isinstance(headers, list):
        raise ValueError("qualified application resource headers must be a list")
    by_name: dict[str, list[str]] = {}
    for header in headers:
        if (
            not isinstance(header, list)
            or len(header) != 2
            or not all(isinstance(part, str) for part in header)
        ):
            raise ValueError("qualified application resource headers must be pairs")
        name = header[0]
        normalized = name.lower()
        if normalized in {*IDENTITY_COPIED_HEADERS, "accept-encoding"}:
            if name != normalized:
                raise ValueError("identity chaff application headers must use lowercase names")
            if normalized in by_name:
                raise ValueError("identity chaff request headers must be unique")
            by_name[normalized] = list(header)
    if set(by_name) != {*IDENTITY_COPIED_HEADERS, "accept-encoding"}:
        raise ValueError(
            "identity chaff requires exact lowercase accept, accept-encoding, "
            "and accept-language application headers"
        )
    return [
        by_name["accept"],
        ["accept-encoding", "identity"],
        by_name["accept-language"],
    ]


def response_only_request_header_primitive() -> dict[str, Any]:
    """Return the exact schema-four request-header derivation primitive."""

    return {
        "mode": IDENTITY_REQUEST_HEADER_MODE,
        "copied_from_application": list(IDENTITY_COPIED_HEADERS),
        "forced": [list(header) for header in IDENTITY_FORCED_HEADERS],
    }


def selected_navigation_root(manifest: Mapping[str, Any], workload_id: str) -> dict[str, Any]:
    preparation = manifest.get("preparation")
    resources = manifest.get("resources")
    if not isinstance(preparation, Mapping) or not isinstance(resources, list):
        raise ValueError(f"qualified workload {workload_id!r} requires prepared resources")
    navigation = {preparation.get("source_url"), preparation.get("final_url")}
    roots = [
        resource
        for resource in resources
        if isinstance(resource, dict)
        and resource.get("type") == "Document"
        and resource.get("url") in navigation
        and resource.get("depends_on") == []
        and resource.get("known_valid") is True
    ]
    if len(roots) != 1 or roots[0].get("id") != 0:
        raise ValueError(
            f"qualified workload {workload_id!r} must have exactly one known-valid "
            "dependency-free navigation root with resource ID 0"
        )
    return dict(roots[0])


def _https_origin(value: object) -> tuple[str, str, int] | None:
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or parsed.hostname is None:
        return None
    try:
        port = parsed.port or 443
    except ValueError:
        return None
    return ("https", parsed.hostname.lower(), port)


def _prepared_expected_responses(manifest: Mapping[str, Any]) -> dict[int, dict[str, Any]]:
    preparation = manifest.get("preparation")
    values = preparation.get("expected_responses") if isinstance(preparation, Mapping) else None
    if not isinstance(values, list) or not values:
        raise ValueError("qualified workload requires frozen preparation.expected_responses")
    result: dict[int, dict[str, Any]] = {}
    for value in values:
        response = _exact_mapping(
            value,
            {"resource_id", "status", "bytes", "body_sha256"},
            "prepared expected response",
        )
        resource_id = response["resource_id"]
        if (
            type(resource_id) is not int
            or resource_id < 0
            or resource_id in result
            or type(response["status"]) is not int
            or not 200 <= response["status"] <= 299
            or type(response["bytes"]) is not int
            or response["bytes"] < 0
            or not _digest(response["body_sha256"])
        ):
            raise ValueError("prepared expected response identity is invalid")
        result[resource_id] = dict(response)
    return result


def selected_chaff_resource(
    manifest: Mapping[str, Any], workload_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Select the largest frozen, valid same-origin response deterministically.

    Selection is by the exact prepared response-body identity.  Declared
    ``content_length`` is intentionally not capacity evidence: a compressed
    representation can make it materially larger than bytes available to the
    receiver controller.
    """

    application = selected_navigation_root(manifest, workload_id)
    resources = manifest.get("resources")
    preparation = manifest.get("preparation")
    assert isinstance(resources, list) and isinstance(preparation, Mapping)
    expected = _prepared_expected_responses(manifest)
    application_origin = _https_origin(application["url"])
    approved = preparation.get("approved_origins")
    if (
        application_origin is None
        or not isinstance(approved, list)
        or application_origin not in {_https_origin(value) for value in approved}
    ):
        raise ValueError(f"qualified workload {workload_id!r} has no approved HTTPS origin")
    candidates: list[tuple[int, int, str, dict[str, Any], dict[str, Any]]] = []
    for value in resources:
        if not isinstance(value, dict):
            continue
        resource_id = value.get("id")
        response = expected.get(resource_id) if type(resource_id) is int else None
        if (
            response is None
            or value.get("known_valid") is not True
            or _https_origin(value.get("url")) != application_origin
            or response["bytes"] < UDP_PAYLOAD_CEILING
        ):
            continue
        try:
            project_compact_headers(value)
        except ValueError:
            continue
        candidates.append(
            (-response["bytes"], resource_id, str(value["url"]), dict(value), response)
        )
    if not candidates:
        raise ValueError(
            f"qualified workload {workload_id!r} has no valid same-origin response of one cell"
        )
    _negative_bytes, _resource_id, _url, resource, response = min(candidates)
    return resource, dict(response)


def response_only_candidate_resources(
    manifest: Mapping[str, Any], workload_id: str
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Return the frozen eligible candidate order used by response-only v2.

    Eligibility is intentionally decided from the immutable preparation
    evidence, not a live probe: known-valid, primary same-origin resources with
    at least one 1200-byte prepared body.  A candidate's separately negotiated
    identity response is only authoritative after sustained qualification.
    """

    application = selected_navigation_root(manifest, workload_id)
    resources = manifest.get("resources")
    preparation = manifest.get("preparation")
    assert isinstance(resources, list) and isinstance(preparation, Mapping)
    expected = _prepared_expected_responses(manifest)
    application_origin = _https_origin(application["url"])
    approved = preparation.get("approved_origins")
    if (
        application_origin is None
        or not isinstance(approved, list)
        or application_origin not in {_https_origin(value) for value in approved}
    ):
        raise ValueError(f"qualified workload {workload_id!r} has no approved HTTPS origin")
    candidates: list[tuple[int, int, str, dict[str, Any], dict[str, Any]]] = []
    for value in resources:
        if not isinstance(value, dict):
            continue
        resource_id = value.get("id")
        response = expected.get(resource_id) if type(resource_id) is int else None
        if (
            response is None
            or value.get("known_valid") is not True
            or _https_origin(value.get("url")) != application_origin
            or response["bytes"] < UDP_PAYLOAD_CEILING
        ):
            continue
        try:
            project_identity_chaff_headers(value)
        except ValueError:
            continue
        candidates.append(
            (-response["bytes"], resource_id, str(value["url"]), dict(value), dict(response))
        )
    if not candidates:
        raise ValueError(
            f"qualified workload {workload_id!r} has no eligible identity-response candidate"
        )
    return [(resource, response) for _, _, _, resource, response in sorted(candidates)]


def _application_resource_batches(manifest: Mapping[str, Any]) -> list[list[int]]:
    resources = manifest.get("resources")
    if not isinstance(resources, list):
        raise ValueError("prepared workload resources are missing")
    by_id = {
        resource["id"]: resource
        for resource in resources
        if isinstance(resource, Mapping) and type(resource.get("id")) is int
    }
    if len(by_id) != len(resources) or 0 not in by_id:
        raise ValueError("prepared workload resource identities are invalid")
    depths: dict[int, int] = {}
    visiting: set[int] = set()

    def depth(resource_id: int) -> int:
        if resource_id in depths:
            return depths[resource_id]
        if resource_id in visiting:
            raise ValueError("prepared workload dependency graph contains a cycle")
        visiting.add(resource_id)
        dependencies = by_id[resource_id].get("depends_on")
        if not isinstance(dependencies, list) or any(
            type(item) is not int or item not in by_id for item in dependencies
        ):
            raise ValueError("prepared workload dependency graph is invalid")
        result = 0 if not dependencies else max(depth(item) for item in dependencies) + 1
        visiting.remove(resource_id)
        depths[resource_id] = result
        return result

    for resource_id in by_id:
        depth(resource_id)
    maximum = max(depths.values())
    batches = [
        sorted(key for key, value in depths.items() if value == index)
        for index in range(maximum + 1)
    ]
    if batches[0] != [0]:
        raise ValueError("prepared workload must have only navigation root zero in batch zero")
    return batches


def _capacity_plan(
    *,
    bursts: Sequence[Mapping[str, int]],
    manifest: Mapping[str, Any],
    selected_chaff_body_bytes: int,
) -> tuple[int, list[dict[str, Any]]]:
    """Derive the minimal one-shot cohort and its exact component recurrence."""

    expected = _prepared_expected_responses(manifest)
    batches = _application_resource_batches(manifest)
    horizon = _maximum_receiver_continuation_reserve_horizon(bursts)
    initial = horizon + 1
    if initial > MAX_QUALIFIED_CHAFF_STREAMS:
        raise ValueError("receiver continuation horizon exceeds qualification stream ceiling")
    later_activation = next(
        (index for index, burst in enumerate(bursts[1:], start=1) if burst["outgoing"] > 0),
        None,
    )
    for required in range(initial, MAX_QUALIFIED_CHAFF_STREAMS + 1):
        if required > initial and later_activation is None:
            break
        active = 0
        capacity_after = 0
        rows: list[dict[str, Any]] = []
        feasible = True
        for component_index, burst in enumerate(bursts):
            target_active = initial
            if required > initial and component_index >= int(later_activation):
                target_active = required
            newly_required = target_active - active
            active = target_active
            exact_before = capacity_after + newly_required * selected_chaff_body_bytes
            future_reserves = sum(
                int(candidate["incoming"] > 0) for candidate in bursts[component_index:]
            )
            reserved_bytes = future_reserves * selected_chaff_body_bytes
            if exact_before < reserved_bytes:
                feasible = False
                break
            ordinary_before = exact_before - reserved_bytes
            resource_ids = batches[component_index] if component_index < len(batches) else []
            try:
                body_floor = sum(expected[resource_id]["bytes"] for resource_id in resource_ids)
            except KeyError as error:
                raise ValueError(
                    "application capacity batch lacks a frozen prepared response"
                ) from error
            adapted_incoming = burst["incoming"]
            symmetric_incoming = adapted_incoming - int(adapted_incoming > 0)
            base_chaff = max(
                symmetric_incoming * UDP_PAYLOAD_CEILING - body_floor,
                0,
            )
            continuation = UDP_PAYLOAD_CEILING if adapted_incoming > 0 else 0
            early = continuation > 0 and ordinary_before < base_chaff
            usable = ordinary_before
            if early:
                usable += selected_chaff_body_bytes - continuation
            if base_chaff > usable or exact_before < base_chaff + continuation:
                feasible = False
                break
            capacity_after = exact_before - base_chaff - continuation
            remaining_reserves = future_reserves - int(continuation > 0)
            if capacity_after < remaining_reserves * selected_chaff_body_bytes:
                feasible = False
                break
            rows.append(
                {
                    "component_index": component_index,
                    "application_resource_ids": resource_ids,
                    "exact_target_cells": burst["outgoing"],
                    "outgoing_cells": burst["outgoing"],
                    "symmetric_incoming_cells": symmetric_incoming,
                    "adapted_incoming_cells": adapted_incoming,
                    "application_body_floor_bytes": body_floor,
                    "base_chaff_bytes": base_chaff,
                    "continuation_bytes": continuation,
                    "required_active_chaff_streams": active,
                    "newly_required_chaff_streams": newly_required,
                    "future_continuation_reserves": future_reserves,
                    "exact_capacity_before_bytes": exact_before,
                    "ordinary_capacity_before_bytes": ordinary_before,
                    "exact_capacity_after_bytes": capacity_after,
                    "early_continuation_required": early,
                }
            )
        if feasible and len(rows) == len(bursts):
            return required, rows
    raise ValueError(
        "Walkie-Talkie mould is infeasible within the qualified one-shot stream ceiling"
    )


def prefix_pack_spec(
    workload_id: str,
    walkie_talkie: Mapping[str, Any],
    *,
    source_walkie_talkie_artifact_sha256: str,
    application_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project the sealed schema-five mould through current sender framing."""

    profile = _walkie_profile(walkie_talkie, workload_id)
    bursts = profile.get("bursts")
    packet_size = walkie_talkie.get("packet_size")
    if packet_size != UDP_PAYLOAD_CEILING or not isinstance(bursts, list) or not bursts:
        raise ValueError("Walkie-Talkie prefix-pack source has an invalid numeric profile")
    source_bursts = [
        {"outgoing": burst.get("outgoing"), "incoming": burst.get("incoming")}
        for burst in bursts
        if isinstance(burst, Mapping)
    ]
    if len(source_bursts) != len(bursts):
        raise ValueError("Walkie-Talkie prefix-pack source has malformed bursts")
    numeric = {
        "packet_size": packet_size,
        "bursts": _sender_frame_schema_five_bursts(source_bursts),
    }
    if any(
        type(burst[direction]) is not int
        or burst[direction] < 0
        or (direction == "outgoing" and burst[direction] == 0)
        for burst in numeric["bursts"]
        for direction in ("outgoing", "incoming")
    ):
        raise ValueError("Walkie-Talkie prefix-pack source has malformed bursts")
    horizon = _maximum_receiver_continuation_reserve_horizon(numeric["bursts"])
    if horizon < 1:
        raise ValueError("Walkie-Talkie prefix-pack source has no receiver continuation")
    numeric_digest = sha256_bytes(
        b"qcsd-walkie-talkie-numeric-profile-v1\0"
        + json.dumps(numeric, sort_keys=True, separators=(",", ":")).encode()
    )
    if application_manifest is None:
        application_manifest = load_json(LAB_ROOT / "config/workloads" / f"{workload_id}.json")
    application = selected_navigation_root(application_manifest, workload_id)
    selected, selected_response = selected_chaff_resource(application_manifest, workload_id)
    required_chaff_streams, stages = _capacity_plan(
        bursts=numeric["bursts"],
        manifest=application_manifest,
        selected_chaff_body_bytes=selected_response["bytes"],
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": PREFIX_SPEC_ARTIFACT_TYPE,
        "workload_id": workload_id,
        "packet_size": UDP_PAYLOAD_CEILING,
        "max_stream_data_excess": MAX_STREAM_DATA_EXCESS,
        "maximum_receiver_continuation_reserve_horizon": horizon,
        "required_chaff_survivors": horizon + 1,
        "numeric_profile_sha256": numeric_digest,
        "source_walkie_talkie_artifact_sha256": source_walkie_talkie_artifact_sha256,
        "application_resource_id": application["id"],
        "selected_chaff_resource_id": selected["id"],
        "selected_chaff_body_bytes": selected_response["bytes"],
        "required_chaff_streams": required_chaff_streams,
        "stream_activation_stages": stages,
        "numeric_profile": numeric,
    }


def _sender_frame_schema_five_bursts(
    bursts: Sequence[Mapping[str, Any]],
) -> list[dict[str, int]]:
    """Add the current fixed sender-framing cell to sealed schema-five targets."""

    result: list[dict[str, int]] = []
    for burst in bursts:
        outgoing = burst.get("outgoing")
        incoming = burst.get("incoming")
        if (
            type(outgoing) is not int
            or type(incoming) is not int
            or not 0 < outgoing <= MAX_WALKIE_TALKIE_COMPONENT_CELLS
            or not 0 <= incoming <= MAX_WALKIE_TALKIE_COMPONENT_CELLS
        ):
            raise ValueError("Walkie-Talkie prefix-pack source has malformed bursts")
        if outgoing > MAX_WALKIE_TALKIE_COMPONENT_CELLS - SENDER_FRAMING_CELLS:
            raise ValueError("Walkie-Talkie sender-framed prefix target exceeds u32")
        result.append(
            {
                "outgoing": outgoing + SENDER_FRAMING_CELLS,
                "incoming": incoming,
            }
        )
    return result


def _walkie_profile(value: Mapping[str, Any], workload_id: str) -> Mapping[str, Any]:
    profiles = value.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("Walkie-Talkie prefix-pack source has no profiles")
    matches = [
        profile
        for profile in profiles
        if isinstance(profile, Mapping)
        and workload_id in {profile.get("real"), profile.get("decoy")}
    ]
    if len(matches) != 1:
        raise ValueError(f"Walkie-Talkie prefix-pack source does not uniquely cover {workload_id}")
    return matches[0]


def _maximum_receiver_continuation_reserve_horizon(
    bursts: Sequence[Mapping[str, int]],
) -> int:
    return sum(int(burst["incoming"] > 0) for burst in bursts)


def validate_prefix_pack_spec(
    value: object,
    *,
    workload_id: str | None = None,
    application_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    keys = {
        "schema_version",
        "artifact_type",
        "workload_id",
        "packet_size",
        "max_stream_data_excess",
        "maximum_receiver_continuation_reserve_horizon",
        "required_chaff_survivors",
        "numeric_profile_sha256",
        "source_walkie_talkie_artifact_sha256",
        "application_resource_id",
        "selected_chaff_resource_id",
        "selected_chaff_body_bytes",
        "required_chaff_streams",
        "stream_activation_stages",
        "numeric_profile",
    }
    spec = _exact_mapping(value, keys, "prefix-pack specification")
    if (
        spec["schema_version"] != SCHEMA_VERSION
        or spec["artifact_type"] != PREFIX_SPEC_ARTIFACT_TYPE
        or not isinstance(spec["workload_id"], str)
        or (workload_id is not None and spec["workload_id"] != workload_id)
        or spec["packet_size"] != UDP_PAYLOAD_CEILING
        or spec["max_stream_data_excess"] != MAX_STREAM_DATA_EXCESS
        or type(spec["application_resource_id"]) is not int
        or spec["application_resource_id"] != 0
        or type(spec["selected_chaff_resource_id"]) is not int
        or spec["selected_chaff_resource_id"] < 0
        or type(spec["selected_chaff_body_bytes"]) is not int
        or spec["selected_chaff_body_bytes"] < UDP_PAYLOAD_CEILING
        or not _digest(spec["numeric_profile_sha256"])
        or spec["source_walkie_talkie_artifact_sha256"] != SOURCE_WALKIE_TALKIE_SHA256
    ):
        raise ValueError("prefix-pack specification binding is invalid")
    numeric = _exact_mapping(
        spec["numeric_profile"], {"packet_size", "bursts"}, "prefix-pack numeric profile"
    )
    bursts = numeric["bursts"]
    if numeric["packet_size"] != UDP_PAYLOAD_CEILING or not isinstance(bursts, list) or not bursts:
        raise ValueError("prefix-pack numeric profile is invalid")
    parsed: list[dict[str, int]] = []
    for burst in bursts:
        record = _exact_mapping(burst, {"outgoing", "incoming"}, "prefix-pack burst")
        if (
            any(type(record[key]) is not int or record[key] < 0 for key in record)
            or record["outgoing"] == 0
        ):
            raise ValueError("prefix-pack burst is invalid")
        parsed.append(dict(record))
    horizon = _maximum_receiver_continuation_reserve_horizon(parsed)
    expected_digest = sha256_bytes(
        b"qcsd-walkie-talkie-numeric-profile-v1\0"
        + json.dumps(dict(numeric), sort_keys=True, separators=(",", ":")).encode()
    )
    if (
        spec["numeric_profile_sha256"] != expected_digest
        or spec["maximum_receiver_continuation_reserve_horizon"] != horizon
        or spec["required_chaff_survivors"] != horizon + 1
        or not 1 <= spec["required_chaff_survivors"] <= MAX_QUALIFIED_CHAFF_STREAMS
        or type(spec["required_chaff_streams"]) is not int
        or not spec["required_chaff_survivors"]
        <= spec["required_chaff_streams"]
        <= MAX_QUALIFIED_CHAFF_STREAMS
    ):
        raise ValueError("prefix-pack specification numeric derivation is invalid")
    stages = spec["stream_activation_stages"]
    if not isinstance(stages, list) or len(stages) != len(parsed):
        raise ValueError("prefix-pack specification must prove every numeric component")
    previous_active = 0
    previous_capacity_after = 0
    application_ids: set[int] = set()
    for component_index, value_stage in enumerate(stages):
        stage = _exact_mapping(value_stage, STREAM_ACTIVATION_STAGE_KEYS, "prefix activation stage")
        burst = parsed[component_index]
        ids = stage["application_resource_ids"]
        if (
            stage["component_index"] != component_index
            or not isinstance(ids, list)
            or any(type(item) is not int or item < 0 for item in ids)
            or any(item in application_ids for item in ids)
            or len(ids) != len(set(ids))
            or stage["exact_target_cells"] != burst["outgoing"]
            or stage["exact_target_cells"] <= 0
            or stage["outgoing_cells"] != burst["outgoing"]
            or stage["adapted_incoming_cells"] != burst["incoming"]
            or type(stage["symmetric_incoming_cells"]) is not int
            or stage["symmetric_incoming_cells"] < 0
            or stage["adapted_incoming_cells"]
            != stage["symmetric_incoming_cells"] + int(stage["adapted_incoming_cells"] > 0)
            or any(
                type(stage[key]) is not int or stage[key] < 0
                for key in STREAM_ACTIVATION_STAGE_KEYS
                - {"application_resource_ids", "early_continuation_required"}
            )
            or type(stage["early_continuation_required"]) is not bool
        ):
            raise ValueError("prefix activation stage shape is invalid")
        application_ids.update(ids)
        expected_future = sum(int(item["incoming"] > 0) for item in parsed[component_index:])
        expected_base = max(
            stage["symmetric_incoming_cells"] * UDP_PAYLOAD_CEILING
            - stage["application_body_floor_bytes"],
            0,
        )
        expected_continuation = UDP_PAYLOAD_CEILING if stage["adapted_incoming_cells"] > 0 else 0
        active = stage["required_active_chaff_streams"]
        newly = active - previous_active
        expected_before = previous_capacity_after + newly * spec["selected_chaff_body_bytes"]
        reserved = expected_future * spec["selected_chaff_body_bytes"]
        if expected_before < reserved:
            raise ValueError("prefix activation stage cannot retain its future reserves")
        expected_ordinary = expected_before - reserved
        expected_early = expected_continuation > 0 and expected_ordinary < expected_base
        usable = expected_ordinary + (
            spec["selected_chaff_body_bytes"] - expected_continuation if expected_early else 0
        )
        expected_after = expected_before - expected_base - expected_continuation
        if (
            active < previous_active
            or newly != stage["newly_required_chaff_streams"]
            or active > spec["required_chaff_streams"]
            or (component_index == 0 and active != spec["required_chaff_survivors"])
            or stage["future_continuation_reserves"] != expected_future
            or stage["base_chaff_bytes"] != expected_base
            or stage["continuation_bytes"] != expected_continuation
            or stage["exact_capacity_before_bytes"] != expected_before
            or stage["ordinary_capacity_before_bytes"] != expected_ordinary
            or stage["exact_capacity_after_bytes"] != expected_after
            or stage["early_continuation_required"] is not expected_early
            or expected_base > usable
            or expected_after < 0
        ):
            raise ValueError("prefix activation stage capacity recurrence is invalid")
        previous_active = active
        previous_capacity_after = expected_after
    if previous_active != spec["required_chaff_streams"] or stages[0][
        "application_resource_ids"
    ] != [0]:
        raise ValueError("prefix activation stages do not bind the exact final cohort")
    if application_manifest is not None:
        selected, selected_response = selected_chaff_resource(
            application_manifest, spec["workload_id"]
        )
        expected_responses = _prepared_expected_responses(application_manifest)
        batches = _application_resource_batches(application_manifest)
        if (
            spec["selected_chaff_resource_id"] != selected["id"]
            or spec["selected_chaff_body_bytes"] != selected_response["bytes"]
        ):
            raise ValueError("prefix specification selected-resource binding is invalid")
        for index, stage in enumerate(stages):
            ids = batches[index] if index < len(batches) else []
            floor = sum(expected_responses[item]["bytes"] for item in ids)
            if (
                stage["application_resource_ids"] != ids
                or stage["application_body_floor_bytes"] != floor
            ):
                raise ValueError("prefix stage differs from frozen prepared body identities")
    return dict(spec)


def derive_prefix_pack_specs(
    *,
    source_path: Path | None = None,
    destination_root: Path | None = None,
    workload_root: Path | None = None,
) -> tuple[Path, ...]:
    """Create the six acyclic numeric qualification specs as one directory."""

    source_input = Path(
        os.path.abspath(source_path or LAB_ROOT / SCHEMA_FIVE_WALKIE_TALKIE_ARCHIVE)
    )
    source_parent = _regular_directory_without_symlinks(
        source_input.parent, "schema-five Walkie-Talkie artifact parent"
    )
    source = source_parent / source_input.name
    destination_input = Path(
        os.path.abspath(destination_root or LAB_ROOT / "config/chaff-prefix-specs/v2")
    )
    destination_parent = _regular_directory_without_symlinks(
        destination_input.parent, "prefix-spec destination parent"
    )
    destination = destination_parent / destination_input.name
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"{destination} already exists; prefix specs are create-only")
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"schema-five Walkie-Talkie artifact is not a regular file: {source}")
    artifact = _read_sealed_schema_five_walkie_talkie(source)
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    source_sha256 = SOURCE_WALKIE_TALKIE_SHA256
    profiles = artifact["profiles"]
    workload_ids = sorted(
        identity for profile in profiles for identity in (profile["real"], profile["decoy"])
    )
    if tuple(workload_ids) != tuple(sorted(SEALED_WORKLOAD_IDS)):
        raise ValueError("schema-five Walkie-Talkie artifact must cover the exact sealed cohort")
    with tempfile.TemporaryDirectory(
        prefix=f".{destination.name}.qcsd-prefix-specs-", dir=destination_parent
    ) as temporary:
        candidate = Path(temporary) / destination.name
        candidate.mkdir()
        for workload_id in workload_ids:
            workload_path = workloads / f"{workload_id}.json"
            if workload_path.is_symlink() or not workload_path.is_file():
                raise ValueError(f"workload manifest is not a regular file: {workload_path}")
            manifest = load_json(workload_path)
            validate_research_preparation(manifest, workload_id=workload_id)
            spec = prefix_pack_spec(
                workload_id,
                artifact,
                source_walkie_talkie_artifact_sha256=source_sha256,
                application_manifest=manifest,
            )
            path = candidate / f"{workload_id}.json"
            with path.open("xb") as output:
                output.write(canonical_bytes(spec))
                output.flush()
                os.fsync(output.fileno())
        entries = sorted(candidate.iterdir(), key=lambda path: path.name)
        expected_names = sorted(f"{workload_id}.json" for workload_id in SEALED_WORKLOAD_IDS)
        if [path.name for path in entries] != expected_names or any(
            path.is_symlink() or not path.is_file() for path in entries
        ):
            raise ValueError("prefix-spec candidate does not contain the exact sealed cohort")
        candidate_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(candidate_fd)
        finally:
            os.close(candidate_fd)
        _rename_noreplace(candidate, destination)
        parent_fd = os.open(destination_parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    return tuple(destination / f"{workload_id}.json" for workload_id in workload_ids)


def _read_sealed_schema_five_walkie_talkie(source: Path) -> dict[str, Any]:
    """Read, hash, and parse one immutable schema-five oracle snapshot."""

    # Reopening the path after hashing would let a concurrent host replacement
    # pair one file's digest with another file's numeric profiles despite a
    # container read-only mount.
    source_bytes = source.read_bytes()
    if sha256_bytes(source_bytes) != SOURCE_WALKIE_TALKIE_SHA256:
        raise ValueError("schema-five Walkie-Talkie artifact SHA-256 is not the sealed oracle")
    try:
        artifact = json.loads(source_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("schema-five Walkie-Talkie artifact is not valid JSON") from error
    _validate_schema_five_walkie_talkie_oracle(artifact)
    return artifact


def _validate_schema_five_walkie_talkie_oracle(value: object) -> None:
    artifact = _exact_mapping(
        value,
        {
            "adaptation",
            "burst_definition",
            "cell_byte_domain",
            "schema_version",
            "generated_by",
            "matching_algorithm",
            "paper_equivalent",
            "packet_size",
            "receiver_continuation",
            "profiles",
        },
        "sealed schema-five Walkie-Talkie artifact",
    )
    if (
        artifact["schema_version"] != 5
        or artifact["adaptation"] != "qcsd-client-only"
        or artifact["paper_equivalent"] is not False
        or artifact["packet_size"] != UDP_PAYLOAD_CEILING
        or not isinstance(artifact["profiles"], list)
        or len(artifact["profiles"]) != 3
    ):
        raise ValueError("sealed schema-five Walkie-Talkie artifact is invalid")
    # Reuse the immutable schema-five oracle without admitting it as a current
    # runnable contract or deriving from the later schema-six artifact.
    from .fitting import _validate_walkie_profile_schema

    for profile in artifact["profiles"]:
        _validate_walkie_profile_schema(profile)


def validate_sidecar(
    value: object,
    *,
    workload_id: str,
    base_manifest_path: Path,
    prefix_spec_path: Path,
    require_current_implementation: bool = True,
) -> QualifiedChaffInput:
    """Validate a sidecar against exact base bytes and derive its final manifest."""

    sidecar = _exact_mapping(value, SIDECAR_KEYS, "chaff qualification sidecar")
    if (
        sidecar["schema_version"] != SCHEMA_VERSION
        or sidecar["artifact_type"] != SIDECAR_ARTIFACT_TYPE
        or sidecar["workload_id"] != workload_id
        or sidecar["selection_policy"] != SELECTION_POLICY
        or type(sidecar["application_resource_id"]) is not int
        or sidecar["application_resource_id"] != 0
        or type(sidecar["selected_chaff_resource_id"]) is not int
        or type(sidecar["qualified_parallel_chaff_streams"]) is not int
        or type(sidecar["walkie_talkie_required_chaff_streams"]) is not int
        or sidecar["header_projection"] != list(HEADER_PROJECTION)
        or sidecar["method"] != METHOD
    ):
        raise ValueError("chaff qualification sidecar policy binding is invalid")
    base_receipt = _exact_mapping(sidecar["base_manifest"], BASE_MANIFEST_KEYS, "base manifest")
    if Path(str(base_receipt["path"])).name != base_manifest_path.name or base_receipt[
        "sha256"
    ] != sha256_file(base_manifest_path):
        raise ValueError("chaff qualification base manifest SHA-256 mismatch")
    base = load_json(base_manifest_path)
    validate_research_preparation(base, workload_id=workload_id)
    application = selected_navigation_root(base, workload_id)
    selected, _selected_response = selected_chaff_resource(base, workload_id)
    _validate_source(sidecar["qualification_source"], sidecar["qualification_image_digest"])
    _validate_implementation_receipt(
        sidecar["implementation_receipt"], require_current=require_current_implementation
    )
    if _source_execution_identity(sidecar["implementation_receipt"]["source"]) != (
        _source_execution_identity(sidecar["qualification_source"])
    ):
        raise ValueError("implementation receipt source differs from qualification source")
    if require_current_implementation:
        current_source = source_metadata()
        if current_source.get("neqo_commit") != sidecar["qualification_source"].get(
            "neqo_commit"
        ) or current_source.get("neqo_pinned_commit") != current_source.get("neqo_commit"):
            raise ValueError("Neqo source has changed since chaff qualification")
    _validate_neqo_provenance(
        sidecar["neqo_provenance"], qualification_source=sidecar["qualification_source"]
    )
    _validate_nontraining_receipts(
        sidecar["fitting_source"],
        sidecar["schema_five_diagnostic"],
        sidecar["schema_six_capacity_falsification_diagnostic"],
        sidecar["schema_six_runtime_falsification_diagnostic"],
        sidecar["schema_two_sender_framing_falsification_diagnostic"],
    )
    spec_receipt = _exact_mapping(sidecar["prefix_pack_spec"], {"path", "sha256"}, "prefix spec")
    if Path(str(spec_receipt["path"])).name != prefix_spec_path.name or spec_receipt[
        "sha256"
    ] != sha256_file(prefix_spec_path):
        raise ValueError("chaff qualification prefix-pack specification mismatch")
    prefix_spec = validate_prefix_pack_spec(
        load_json(prefix_spec_path), workload_id=workload_id, application_manifest=base
    )
    required = prefix_spec["required_chaff_streams"]
    qualified_parallel = max(MIN_CROSS_MODE_PARALLEL_CHAFF_STREAMS, required)
    if (
        sidecar["selected_chaff_resource_id"] != selected["id"]
        or sidecar["walkie_talkie_required_chaff_streams"] != required
        or sidecar["qualified_parallel_chaff_streams"] != qualified_parallel
    ):
        raise ValueError("chaff qualification sidecar capacity binding is invalid")
    _validate_policy(
        sidecar["qualification_policy"],
        qualified_parallel_chaff_streams=qualified_parallel,
        walkie_talkie_required_chaff_streams=required,
    )
    resource = _validate_resource_receipt(
        sidecar["resource"],
        selected,
        application_manifest_sha256=base_receipt["sha256"],
        application_manifest=base,
        prefix_spec=prefix_spec,
        prefix_spec_sha256=spec_receipt["sha256"],
        neqo_provenance=sidecar["neqo_provenance"],
    )
    manifest = derive_chaff_manifest(sidecar, selected, resource)
    return QualifiedChaffInput(
        sidecar_path=Path(),
        sidecar_sha256=sha256_bytes(canonical_bytes(dict(sidecar))),
        manifest=manifest,
        manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
        application_manifest_sha256=sha256_file(base_manifest_path),
        application_resource_id=application["id"],
        selected_chaff_resource_id=selected["id"],
        qualified_parallel_chaff_streams=qualified_parallel,
        walkie_talkie_required_chaff_streams=required,
    )


def load_qualified_chaff(
    sidecar_path: Path,
    *,
    workload_id: str,
    base_manifest_path: Path,
    prefix_spec_path: Path,
    require_current_implementation: bool = True,
) -> QualifiedChaffInput:
    if sidecar_path.is_symlink() or not sidecar_path.is_file():
        raise ValueError(f"chaff qualification sidecar is not a regular file: {sidecar_path}")
    raw = sidecar_path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"chaff qualification sidecar is invalid JSON: {sidecar_path}") from error
    result = validate_sidecar(
        value,
        workload_id=workload_id,
        base_manifest_path=base_manifest_path,
        prefix_spec_path=prefix_spec_path,
        require_current_implementation=require_current_implementation,
    )
    return QualifiedChaffInput(
        sidecar_path=sidecar_path.resolve(),
        sidecar_sha256=sha256_bytes(raw),
        manifest=result.manifest,
        manifest_sha256=result.manifest_sha256,
        application_manifest_sha256=result.application_manifest_sha256,
        application_resource_id=result.application_resource_id,
        selected_chaff_resource_id=result.selected_chaff_resource_id,
        qualified_parallel_chaff_streams=result.qualified_parallel_chaff_streams,
        walkie_talkie_required_chaff_streams=result.walkie_talkie_required_chaff_streams,
    )


def validate_response_only_sidecar(
    value: object,
    *,
    workload_id: str,
    base_manifest_path: Path,
    expected_sidecar_schema_version: int | None,
    require_current_implementation: bool = True,
) -> QualifiedChaffInput:
    """Validate one explicitly selected immutable response-only schema contract."""

    if not isinstance(value, Mapping) or type(value.get("schema_version")) is not int:
        raise ValueError("response-only chaff qualification schema version is invalid")
    if expected_sidecar_schema_version is not None and (
        type(expected_sidecar_schema_version) is not int
        or expected_sidecar_schema_version
        not in {
            RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION,
            RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        }
    ):
        raise ValueError("expected response-only sidecar schema version is invalid")
    if (
        expected_sidecar_schema_version is not None
        and value["schema_version"] != expected_sidecar_schema_version
    ):
        raise ValueError("response-only chaff qualification schema version is unexpected")
    if value["schema_version"] == RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION:
        return _validate_response_only_sidecar_v1(
            value,
            workload_id=workload_id,
            base_manifest_path=base_manifest_path,
            require_current_implementation=require_current_implementation,
        )
    if value["schema_version"] == RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION:
        return _validate_response_only_sidecar_v2(
            value,
            workload_id=workload_id,
            base_manifest_path=base_manifest_path,
            require_current_implementation=require_current_implementation,
        )
    raise ValueError("unsupported response-only chaff qualification schema version")


def _validate_response_only_sidecar_v1(
    value: object,
    *,
    workload_id: str,
    base_manifest_path: Path,
    require_current_implementation: bool = True,
) -> QualifiedChaffInput:
    """Validate a frozen v1 sidecar and derive its schema-three manifest."""

    sidecar = _exact_mapping(
        value,
        RESPONSE_ONLY_SIDECAR_KEYS,
        "response-only chaff qualification sidecar",
    )
    if (
        type(sidecar["schema_version"]) is not int
        or sidecar["schema_version"] != RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION
        or sidecar["artifact_type"] != RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE
        or sidecar["qualification_scope"] != RESPONSE_ONLY_QUALIFICATION_SCOPE
        or sidecar["workload_id"] != workload_id
        or sidecar["selection_policy"] != SELECTION_POLICY
        or type(sidecar["application_resource_id"]) is not int
        or sidecar["application_resource_id"] != 0
        or type(sidecar["selected_chaff_resource_id"]) is not int
        or type(sidecar["qualified_parallel_chaff_streams"]) is not int
        or sidecar["qualified_parallel_chaff_streams"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or sidecar["header_projection"] != list(HEADER_PROJECTION)
        or sidecar["method"] != METHOD
    ):
        raise ValueError("response-only chaff qualification policy binding is invalid")
    base_receipt = _exact_mapping(sidecar["base_manifest"], BASE_MANIFEST_KEYS, "base manifest")
    if Path(str(base_receipt["path"])).name != base_manifest_path.name or base_receipt[
        "sha256"
    ] != sha256_file(base_manifest_path):
        raise ValueError("response-only chaff qualification base manifest SHA-256 mismatch")
    base = load_json(base_manifest_path)
    validate_research_preparation(base, workload_id=workload_id)
    application = selected_navigation_root(base, workload_id)
    selected, _selected_response = selected_chaff_resource(base, workload_id)
    if sidecar["selected_chaff_resource_id"] != selected["id"]:
        raise ValueError("response-only chaff qualification resource binding is invalid")
    _validate_source(sidecar["qualification_source"], sidecar["qualification_image_digest"])
    _validate_implementation_receipt(
        sidecar["implementation_receipt"], require_current=require_current_implementation
    )
    if _source_execution_identity(sidecar["implementation_receipt"]["source"]) != (
        _source_execution_identity(sidecar["qualification_source"])
    ):
        raise ValueError("implementation receipt source differs from qualification source")
    if require_current_implementation:
        current_source = source_metadata()
        if current_source.get("neqo_commit") != sidecar["qualification_source"].get(
            "neqo_commit"
        ) or current_source.get("neqo_pinned_commit") != current_source.get("neqo_commit"):
            raise ValueError("Neqo source has changed since response-only chaff qualification")
    _validate_neqo_provenance(
        sidecar["neqo_provenance"], qualification_source=sidecar["qualification_source"]
    )
    _validate_response_only_policy(sidecar["qualification_policy"])
    resource = _validate_response_only_resource_receipt(
        sidecar["resource"],
        selected,
        application_manifest_sha256=base_receipt["sha256"],
        application_manifest=base,
        application_resource_id=application["id"],
        neqo_provenance=sidecar["neqo_provenance"],
    )
    manifest = derive_response_only_chaff_manifest(sidecar, selected, resource)
    return QualifiedChaffInput(
        sidecar_path=Path(),
        sidecar_sha256=sha256_bytes(canonical_bytes(dict(sidecar))),
        manifest=manifest,
        manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
        application_manifest_sha256=sha256_file(base_manifest_path),
        application_resource_id=application["id"],
        selected_chaff_resource_id=selected["id"],
        qualified_parallel_chaff_streams=RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        walkie_talkie_required_chaff_streams=None,
    )


def _validate_response_only_sidecar_v2(
    value: object,
    *,
    workload_id: str,
    base_manifest_path: Path,
    require_current_implementation: bool = True,
) -> QualifiedChaffInput:
    """Validate the sustained identity-response sidecar and schema-four manifest."""

    sidecar = _exact_mapping(
        value,
        RESPONSE_ONLY_V2_SIDECAR_KEYS,
        "response-only v2 chaff qualification sidecar",
    )
    if (
        type(sidecar["schema_version"]) is not int
        or sidecar["schema_version"] != RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
        or sidecar["artifact_type"] != RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE
        or sidecar["qualification_scope"] != RESPONSE_ONLY_QUALIFICATION_SCOPE
        or sidecar["workload_id"] != workload_id
        or sidecar["selection_policy"] != RESPONSE_ONLY_V2_SELECTION_POLICY
        or type(sidecar["application_resource_id"]) is not int
        or sidecar["application_resource_id"] != 0
        or type(sidecar["selected_chaff_resource_id"]) is not int
        or type(sidecar["qualified_parallel_chaff_streams"]) is not int
        or sidecar["qualified_parallel_chaff_streams"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or sidecar["method"] != METHOD
    ):
        raise ValueError("response-only v2 chaff qualification policy binding is invalid")
    _validate_response_only_request_header_primitive(sidecar["request_header_primitive"])
    _validate_response_only_v2_policy(sidecar["qualification_policy"])

    base_receipt = _exact_mapping(sidecar["base_manifest"], BASE_MANIFEST_KEYS, "base manifest")
    if Path(str(base_receipt["path"])).name != base_manifest_path.name or base_receipt[
        "sha256"
    ] != sha256_file(base_manifest_path):
        raise ValueError("response-only v2 chaff qualification base manifest mismatch")
    base = load_json(base_manifest_path)
    validate_research_preparation(base, workload_id=workload_id)
    application = selected_navigation_root(base, workload_id)
    candidates = response_only_candidate_resources(base, workload_id)

    _validate_source(sidecar["qualification_source"], sidecar["qualification_image_digest"])
    _validate_implementation_receipt(
        sidecar["implementation_receipt"], require_current=require_current_implementation
    )
    if _source_execution_identity(sidecar["implementation_receipt"]["source"]) != (
        _source_execution_identity(sidecar["qualification_source"])
    ):
        raise ValueError("implementation receipt source differs from qualification source")
    if require_current_implementation:
        current_source = source_metadata()
        if current_source.get("neqo_commit") != sidecar["qualification_source"].get(
            "neqo_commit"
        ) or current_source.get("neqo_pinned_commit") != current_source.get("neqo_commit"):
            raise ValueError("Neqo source has changed since response-only chaff qualification")
    _validate_neqo_provenance(
        sidecar["neqo_provenance"], qualification_source=sidecar["qualification_source"]
    )

    attempts = sidecar["candidate_attempts"]
    if not isinstance(attempts, list) or not attempts or len(attempts) > len(candidates):
        raise ValueError("response-only v2 candidate attempts must be a non-empty prefix")
    validated_attempts: list[dict[str, Any]] = []
    for candidate_index, value_attempt in enumerate(attempts):
        candidate, prepared = candidates[candidate_index]
        attempt = _validate_response_only_candidate_attempt(
            value_attempt,
            candidate_index=candidate_index,
            base_resource=candidate,
            prepared_response=prepared,
            application_manifest_sha256=base_receipt["sha256"],
            application_resource_id=application["id"],
            neqo_provenance=sidecar["neqo_provenance"],
        )
        expected_outcome = "qualified" if candidate_index == len(attempts) - 1 else "rejected"
        if attempt["outcome"] != expected_outcome:
            raise ValueError("response-only v2 candidate prefix outcome is invalid")
        validated_attempts.append(attempt)
    selected_attempt = validated_attempts[-1]
    selected_resource, _prepared = candidates[len(attempts) - 1]
    if (
        selected_attempt["failure_class"] is not None
        or sidecar["selected_chaff_resource_id"] != selected_resource["id"]
    ):
        raise ValueError("response-only v2 selected candidate binding is invalid")
    resource = _validate_response_only_v2_resource_receipt(
        sidecar["resource"],
        selected_resource,
        selected_attempt=selected_attempt,
    )
    manifest = derive_response_only_chaff_manifest_v2(sidecar, selected_resource, resource)
    return QualifiedChaffInput(
        sidecar_path=Path(),
        sidecar_sha256=sha256_bytes(canonical_bytes(dict(sidecar))),
        manifest=manifest,
        manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
        application_manifest_sha256=sha256_file(base_manifest_path),
        application_resource_id=application["id"],
        selected_chaff_resource_id=selected_resource["id"],
        qualified_parallel_chaff_streams=RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        walkie_talkie_required_chaff_streams=None,
    )


def load_response_qualified_chaff(
    sidecar_path: Path,
    *,
    workload_id: str,
    base_manifest_path: Path,
    expected_sidecar_schema_version: int | None,
    require_current_implementation: bool = True,
) -> QualifiedChaffInput:
    """Load one regular response-only sidecar without following a final symlink."""

    if sidecar_path.is_symlink() or not sidecar_path.is_file():
        raise ValueError(
            f"response-only chaff qualification sidecar is not a regular file: {sidecar_path}"
        )
    raw = sidecar_path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"response-only chaff qualification sidecar is invalid JSON: {sidecar_path}"
        ) from error
    result = validate_response_only_sidecar(
        value,
        workload_id=workload_id,
        base_manifest_path=base_manifest_path,
        expected_sidecar_schema_version=expected_sidecar_schema_version,
        require_current_implementation=require_current_implementation,
    )
    return QualifiedChaffInput(
        sidecar_path=sidecar_path.resolve(),
        sidecar_sha256=sha256_bytes(raw),
        manifest=result.manifest,
        manifest_sha256=result.manifest_sha256,
        application_manifest_sha256=result.application_manifest_sha256,
        application_resource_id=result.application_resource_id,
        selected_chaff_resource_id=result.selected_chaff_resource_id,
        qualified_parallel_chaff_streams=result.qualified_parallel_chaff_streams,
        walkie_talkie_required_chaff_streams=None,
    )


def derive_response_only_chaff_manifest(
    sidecar: Mapping[str, Any],
    base_resource: Mapping[str, Any],
    resource_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive the strict schema-three manifest used only by FRONT and Tamaraw."""

    resource = resource_receipt or dict(sidecar["resource"])
    response = resource["expected_response"]
    body_bytes = response["body_bytes"]
    qualified = {
        "id": base_resource["id"],
        "url": base_resource["url"],
        "type": base_resource.get("type", "Other"),
        "content_length": body_bytes,
        "data_length": body_bytes,
        "chaff_priority": base_resource.get("chaff_priority", False),
        "known_valid": True,
        "depends_on": [],
        "headers": resource["headers"],
        "chaff_qualification": {
            "schema_version": RESPONSE_ONLY_MANIFEST_SCHEMA_VERSION,
            "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
            "method": METHOD,
            "request_stream_bytes": resource["request_stream_bytes"],
            "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            "expected_response": response,
            "response_qualification_sha256": resource["response_qualification_sha256"],
        },
    }
    return {
        "schema_version": RESPONSE_ONLY_MANIFEST_SCHEMA_VERSION,
        "artifact_type": MANIFEST_ARTIFACT_TYPE,
        "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
        "application_workload_sha256": sidecar["base_manifest"]["sha256"],
        "application_resource_id": sidecar["application_resource_id"],
        "selected_chaff_resource_id": sidecar["selected_chaff_resource_id"],
        "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        "resources": [qualified],
    }


def derive_response_only_chaff_manifest_v2(
    sidecar: Mapping[str, Any],
    base_resource: Mapping[str, Any],
    resource_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive the schema-four FRONT/Tamaraw identity-chaff runtime input."""

    resource = resource_receipt or dict(sidecar["resource"])
    response = resource["expected_response"]
    body_bytes = response["body_bytes"]
    primitive = response_only_request_header_primitive()
    qualified = {
        "id": base_resource["id"],
        "url": base_resource["url"],
        "type": base_resource.get("type", "Other"),
        "content_length": body_bytes,
        "data_length": body_bytes,
        "chaff_priority": base_resource.get("chaff_priority", False),
        "known_valid": True,
        "depends_on": [],
        "headers": resource["headers"],
        "chaff_qualification": {
            "schema_version": RESPONSE_ONLY_MANIFEST_V2_SCHEMA_VERSION,
            "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
            "method": METHOD,
            "request_header_primitive": primitive,
            "request_stream_bytes": resource["request_stream_bytes"],
            "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            "qualified_completion_count": RESPONSE_ONLY_COMPLETIONS_PER_CANDIDATE,
            "expected_response": response,
            "response_qualification_sha256": resource["response_qualification_sha256"],
        },
    }
    return {
        "schema_version": RESPONSE_ONLY_MANIFEST_V2_SCHEMA_VERSION,
        "artifact_type": MANIFEST_ARTIFACT_TYPE,
        "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
        "application_workload_sha256": sidecar["base_manifest"]["sha256"],
        "application_resource_id": sidecar["application_resource_id"],
        "selected_chaff_resource_id": sidecar["selected_chaff_resource_id"],
        "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        "resources": [qualified],
    }


def derive_chaff_manifest(
    sidecar: Mapping[str, Any],
    base_resource: Mapping[str, Any],
    resource_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    resource = resource_receipt or dict(sidecar["resource"])
    response = resource["expected_response"]
    body_bytes = response["body_bytes"]
    qualified = {
        "id": base_resource["id"],
        "url": base_resource["url"],
        "type": base_resource.get("type", "Other"),
        "content_length": body_bytes,
        "data_length": body_bytes,
        "chaff_priority": base_resource.get("chaff_priority", False),
        "known_valid": True,
        "depends_on": [],
        "headers": resource["headers"],
        "chaff_qualification": {
            "schema_version": SCHEMA_VERSION,
            "method": METHOD,
            "request_stream_bytes": resource["request_stream_bytes"],
            "qualified_parallel_chaff_streams": sidecar["qualified_parallel_chaff_streams"],
            "walkie_talkie_required_chaff_streams": sidecar["walkie_talkie_required_chaff_streams"],
            "expected_response": response,
            "response_qualification_sha256": resource["response_qualification_sha256"],
            "prefix_pack_qualification_sha256": resource["prefix_pack_qualification_sha256"],
            "prefix_spec_sha256": sidecar["prefix_pack_spec"]["sha256"],
        },
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": MANIFEST_ARTIFACT_TYPE,
        "application_workload_sha256": sidecar["base_manifest"]["sha256"],
        "application_resource_id": sidecar["application_resource_id"],
        "selected_chaff_resource_id": sidecar["selected_chaff_resource_id"],
        "qualified_parallel_chaff_streams": sidecar["qualified_parallel_chaff_streams"],
        "walkie_talkie_required_chaff_streams": sidecar["walkie_talkie_required_chaff_streams"],
        "resources": [qualified],
    }


def derive_chaff_core(
    *,
    application_manifest_sha256: str,
    base_resource: Mapping[str, Any],
    headers: list[list[str]],
    request_stream_bytes: int,
    expected_response: Mapping[str, Any],
    response_qualification_sha256: str,
    application_resource_id: int,
    selected_chaff_resource_id: int,
    qualified_parallel_chaff_streams: int,
    walkie_talkie_required_chaff_streams: int,
) -> dict[str, Any]:
    body_bytes = expected_response["body_bytes"]
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": CORE_ARTIFACT_TYPE,
        "application_workload_sha256": application_manifest_sha256,
        "application_resource_id": application_resource_id,
        "selected_chaff_resource_id": selected_chaff_resource_id,
        "qualified_parallel_chaff_streams": qualified_parallel_chaff_streams,
        "walkie_talkie_required_chaff_streams": walkie_talkie_required_chaff_streams,
        "resources": [
            {
                "id": base_resource["id"],
                "url": base_resource["url"],
                "type": base_resource.get("type", "Other"),
                "content_length": body_bytes,
                "data_length": body_bytes,
                "chaff_priority": base_resource.get("chaff_priority", False),
                "known_valid": True,
                "depends_on": [],
                "headers": headers,
                "chaff_qualification_core": {
                    "schema_version": SCHEMA_VERSION,
                    "method": METHOD,
                    "request_stream_bytes": request_stream_bytes,
                    "qualified_parallel_chaff_streams": qualified_parallel_chaff_streams,
                    "walkie_talkie_required_chaff_streams": (walkie_talkie_required_chaff_streams),
                    "expected_response": dict(expected_response),
                    "response_qualification_sha256": response_qualification_sha256,
                },
            }
        ],
    }


def qualify_response_chaff(
    workload_id: str,
    *,
    qualification_root: Path,
    workload_root: Path | None = None,
    timeout_seconds: int = 30,
    interval_seconds: int = 30,
    _execution_context: tuple[dict[str, Any], dict[str, Any], str] | None = None,
) -> QualifiedChaffOutput:
    """Create one response-only sidecar after three independent five-way runs."""

    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", workload_id):
        raise ValueError("workload ID must contain lowercase letters, digits, and single hyphens")
    destination_root = _regular_directory_without_symlinks(
        qualification_root, "response qualification destination"
    )
    destination = destination_root / f"{workload_id}.json"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(
            f"{destination} already exists; response qualification is create-only"
        )
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    base_path = workloads / f"{workload_id}.json"
    if not base_path.is_file() or base_path.is_symlink():
        raise ValueError(f"workload manifest is not a regular file: {base_path}")
    executed_implementation, source, qualification_image = (
        _execution_context or _qualification_execution_context()
    )
    neqo_client, neqo_client_sha256 = _bound_neqo_client(executed_implementation)
    base = load_json(base_path)
    validate_research_preparation(base, workload_id=workload_id)
    application = selected_navigation_root(base, workload_id)
    selected, prepared_selected = selected_chaff_resource(base, workload_id)
    headers = project_compact_headers(selected)
    base_sha = sha256_file(base_path)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{workload_id}-response-qualification-evidence-",
            dir=destination_root,
        )
    )
    completed = False
    try:
        response_runs = _run_response_qualifications(
            base_path,
            temporary,
            selected_chaff_resource_id=selected["id"],
            qualified_parallel_chaff_streams=RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            neqo_client=neqo_client,
            neqo_client_sha256=neqo_client_sha256,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
        )
        expected_response, request_stream_bytes = _stable_response_identity(
            response_runs,
            application_manifest_sha256=base_sha,
            application_resource_id=application["id"],
            selected_chaff_resource_id=selected["id"],
            qualified_parallel_chaff_streams=RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            url=selected["url"],
            headers=headers,
        )
        if (
            expected_response["status"] != prepared_selected["status"]
            or expected_response["body_bytes"] != prepared_selected["bytes"]
            or expected_response["body_sha256"] != prepared_selected["body_sha256"]
        ):
            raise PreparationError(
                "qualified response differs from the frozen prepared response identity"
            )
        response_records = [
            _response_run_record(index, value) for index, value in enumerate(response_runs)
        ]
        response_digest = qualification_digest(
            "qcsd-chaff-response-qualification-v2", response_records
        )
        sidecar = {
            "schema_version": RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION,
            "artifact_type": RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE,
            "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
            "workload_id": workload_id,
            "base_manifest": {"path": base_path.name, "sha256": base_sha},
            "selection_policy": SELECTION_POLICY,
            "application_resource_id": application["id"],
            "selected_chaff_resource_id": selected["id"],
            "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            "header_projection": list(HEADER_PROJECTION),
            "method": METHOD,
            "qualification_policy": {
                "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
                "response_runs": QUALIFICATION_RUNS,
                "parallel_response_requests": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
                "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
                "profile": "research-1200",
                "response_defense": "none",
                "seed": 0,
                "udp_payload_ceiling": UDP_PAYLOAD_CEILING,
                "max_response_bytes": 1_048_576,
                "separate_chaff_namespace": True,
            },
            "qualification_source": source,
            "qualification_image_digest": qualification_image,
            "neqo_provenance": _stable_neqo_provenance(response_runs),
            "implementation_receipt": executed_implementation,
            "resource": {
                "resource_id": selected["id"],
                "url": selected["url"],
                "headers": headers,
                "request_stream_bytes": request_stream_bytes,
                "expected_response": expected_response,
                "response_runs": response_records,
                "response_qualification_sha256": response_digest,
            },
        }
        validated = validate_response_only_sidecar(
            sidecar,
            workload_id=workload_id,
            base_manifest_path=base_path,
            expected_sidecar_schema_version=RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION,
        )
        try:
            with destination.open("xb") as output:
                output.write(canonical_bytes(sidecar))
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            raise FileExistsError(
                f"{destination} already exists; response qualification is create-only"
            ) from None
        completed = True
    finally:
        if completed:
            shutil.rmtree(temporary)
    return QualifiedChaffOutput(
        destination,
        sha256_file(destination),
        validated.manifest_sha256,
    )


def qualify_response_chaff_v2(
    workload_id: str,
    *,
    qualification_root: Path,
    workload_root: Path | None = None,
    timeout_seconds: int = 30,
    interval_seconds: int = RESPONSE_ONLY_EPOCH_SPACING_SECONDS,
    _execution_context: tuple[dict[str, Any], dict[str, Any], str] | None = None,
) -> QualifiedChaffOutput:
    """Create one v2 sidecar from a sustained deterministic candidate prefix."""

    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", workload_id):
        raise ValueError("workload ID must contain lowercase letters, digits, and single hyphens")
    if type(interval_seconds) is not int or interval_seconds != RESPONSE_ONLY_EPOCH_SPACING_SECONDS:
        raise ValueError(
            "response-only v2 qualification requires the fixed 30-second epoch spacing"
        )
    destination_root = _regular_directory_without_symlinks(
        qualification_root, "response qualification destination"
    )
    destination = destination_root / f"{workload_id}.json"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(
            f"{destination} already exists; response qualification is create-only"
        )
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    base_path = workloads / f"{workload_id}.json"
    if not base_path.is_file() or base_path.is_symlink():
        raise ValueError(f"workload manifest is not a regular file: {base_path}")
    executed_implementation, source, qualification_image = (
        _execution_context or _qualification_execution_context()
    )
    neqo_client, neqo_client_sha256 = _bound_neqo_client(executed_implementation)
    base = load_json(base_path)
    validate_research_preparation(base, workload_id=workload_id)
    application = selected_navigation_root(base, workload_id)
    candidates = response_only_candidate_resources(base, workload_id)
    base_sha = sha256_file(base_path)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{workload_id}-response-v2-qualification-evidence-",
            dir=destination_root,
        )
    )
    completed = False
    attempts: list[dict[str, Any]] = []
    all_receipts: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None
    selected_response: dict[str, Any] | None = None
    selected_request_stream_bytes: int | None = None
    try:
        for candidate_index, (candidate, prepared_response) in enumerate(candidates):
            candidate_directory = temporary / (
                f"candidate-{candidate_index:03d}-resource-{candidate['id']}"
            )
            candidate_directory.mkdir()
            epochs = _run_response_qualifications_v2(
                base_path,
                candidate_directory,
                selected_chaff_resource_id=candidate["id"],
                application_manifest_sha256=base_sha,
                application_resource_id=application["id"],
                url=candidate["url"],
                headers=project_identity_chaff_headers(candidate),
                neqo_client=neqo_client,
                neqo_client_sha256=neqo_client_sha256,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
            )
            all_receipts.extend(receipt for _exit_code, receipt in epochs)
            attempt, expected_response, request_stream_bytes = _candidate_attempt_record_v2(
                candidate_index=candidate_index,
                base_resource=candidate,
                prepared_response=prepared_response,
                epochs=epochs,
                application_manifest_sha256=base_sha,
                application_resource_id=application["id"],
            )
            attempts.append(attempt)
            if attempt["outcome"] == "qualified":
                selected = candidate
                selected_response = expected_response
                selected_request_stream_bytes = request_stream_bytes
                break
        if selected is None or selected_response is None or selected_request_stream_bytes is None:
            raise PreparationError(
                "no frozen response-only candidate passed sustained identity qualification"
            )
        response_digest = attempts[-1]["response_qualification_sha256"]
        sidecar = {
            "schema_version": RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
            "artifact_type": RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE,
            "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
            "workload_id": workload_id,
            "base_manifest": {"path": base_path.name, "sha256": base_sha},
            "selection_policy": RESPONSE_ONLY_V2_SELECTION_POLICY,
            "application_resource_id": application["id"],
            "selected_chaff_resource_id": selected["id"],
            "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            "request_header_primitive": response_only_request_header_primitive(),
            "method": METHOD,
            "qualification_policy": response_only_v2_qualification_policy(),
            "qualification_source": source,
            "qualification_image_digest": qualification_image,
            "neqo_provenance": _stable_neqo_provenance(all_receipts),
            "implementation_receipt": executed_implementation,
            "candidate_attempts": attempts,
            "resource": {
                "resource_id": selected["id"],
                "url": selected["url"],
                "headers": project_identity_chaff_headers(selected),
                "request_stream_bytes": selected_request_stream_bytes,
                "expected_response": selected_response,
                "response_qualification_sha256": response_digest,
            },
        }
        validated = validate_response_only_sidecar(
            sidecar,
            workload_id=workload_id,
            base_manifest_path=base_path,
            expected_sidecar_schema_version=RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        )
        try:
            with destination.open("xb") as output:
                output.write(canonical_bytes(sidecar))
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            raise FileExistsError(
                f"{destination} already exists; response qualification is create-only"
            ) from None
        completed = True
    finally:
        if completed:
            shutil.rmtree(temporary)
    return QualifiedChaffOutput(
        destination,
        sha256_file(destination),
        validated.manifest_sha256,
    )


def qualify_all_response_chaff(
    workload_ids: Sequence[str],
    *,
    workload_root: Path | None = None,
    qualification_store: Path | None = None,
    qualification_set: str | None = None,
    timeout_seconds: int = 30,
    interval_seconds: int = 30,
) -> tuple[QualifiedChaffOutput, ...]:
    """Qualify and atomically publish one explicit five-workload response cohort."""

    cohort = tuple(workload_ids)
    if (
        len(cohort) != 5
        or len(set(cohort)) != 5
        or any(
            not isinstance(workload_id, str)
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", workload_id) is None
            for workload_id in cohort
        )
    ):
        raise ValueError("response qualification requires exactly five unique workload IDs")
    store_input = qualification_store or LAB_ROOT / "config/chaff-response-qualification-store"
    store = _regular_directory_without_symlinks(store_input, "response qualification store")
    if qualification_set is None:
        publication_root = store
        destination_name = "v2"
    else:
        destination_name = validate_qualification_set(qualification_set)
        publication_root = _regular_directory_without_symlinks(
            store / "sets", "response qualification sets root"
        )
    destination = publication_root / destination_name
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(
            f"{destination} already exists; batch response qualification is create-only"
        )
    stale = sorted(publication_root.glob(f".{destination_name}.qcsd-batch-*"))
    if stale:
        raise ValueError("response qualification store contains a stale unpublished batch")
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    input_hashes: dict[Path, str] = {}
    primary_origins: set[tuple[str, str, int]] = set()
    for workload_id in cohort:
        workload = workloads / f"{workload_id}.json"
        if workload.is_symlink() or not workload.is_file():
            raise ValueError(f"workload manifest is not a regular file: {workload}")
        manifest = load_json(workload)
        validate_research_preparation(manifest, workload_id=workload_id)
        application = selected_navigation_root(manifest, workload_id)
        primary_origin = _https_origin(application["url"])
        if primary_origin is None:
            raise ValueError(
                f"response qualification workload has no primary HTTPS origin: {workload_id}"
            )
        primary_origins.add(primary_origin)
        response_only_candidate_resources(manifest, workload_id)
        input_hashes[workload] = sha256_file(workload)
    if len(primary_origins) != 5:
        raise ValueError("response qualification requires five distinct primary HTTPS origins")
    execution_context = _qualification_execution_context()
    candidate = Path(
        tempfile.mkdtemp(prefix=f".{destination_name}.qcsd-batch-", dir=publication_root)
    )
    try:
        outputs = [
            qualify_response_chaff_v2(
                workload_id,
                workload_root=workloads,
                qualification_root=candidate,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
                _execution_context=execution_context,
            )
            for workload_id in cohort
        ]
        entries = sorted(candidate.iterdir(), key=lambda path: path.name)
        expected_names = sorted(f"{workload_id}.json" for workload_id in cohort)
        if (
            [path.name for path in entries] != expected_names
            or any(path.is_symlink() or not path.is_file() for path in entries)
            or any(
                sha256_file(output.path) != output.sha256
                for output in outputs
                if output.path.parent == candidate
            )
        ):
            raise ValueError(
                "batch response qualification did not produce the exact five-workload cohort"
            )
        if _regular_directory_without_symlinks(workloads, "workload root") != workloads:
            raise ValueError("batch response qualification input root changed before publication")
        for path, expected_sha256 in input_hashes.items():
            if path.is_symlink() or not path.is_file() or sha256_file(path) != expected_sha256:
                raise ValueError("batch response qualification input changed before publication")
        _bound_neqo_client(execution_context[0])
        directory_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _rename_noreplace(candidate, destination)
        store_fd = os.open(publication_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(store_fd)
        finally:
            os.close(store_fd)
    except Exception:
        # Retain one unpublished same-filesystem candidate for diagnosis.
        raise
    return tuple(
        QualifiedChaffOutput(
            destination / output.path.name,
            sha256_file(destination / output.path.name),
            output.manifest_sha256,
        )
        for output in outputs
    )


def validate_qualification_set(value: object) -> str:
    """Return one unambiguous create-only qualification-set path component."""

    if not isinstance(value, str) or QUALIFICATION_SET_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "chaff qualification set must be a lowercase hyphenated filesystem-safe slug"
        )
    return value


def qualify_chaff(
    workload_id: str,
    *,
    qualification_root: Path,
    workload_root: Path | None = None,
    prefix_spec_root: Path | None = None,
    timeout_seconds: int = 30,
    interval_seconds: int = 30,
    _execution_context: tuple[dict[str, Any], dict[str, Any], str] | None = None,
) -> QualifiedChaffOutput:
    """Create one sidecar atomically after six independent H3 qualifications."""

    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", workload_id):
        raise ValueError("workload ID must contain lowercase letters, digits, and single hyphens")
    destination_root = _regular_directory_without_symlinks(
        qualification_root, "qualification destination"
    )
    destination = destination_root / f"{workload_id}.json"
    # Refuse the canonical destination before source validation, temp creation,
    # sleeping, or any network-capable runner invocation.
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"{destination} already exists; qualification is create-only")
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    specs = _regular_directory_without_symlinks(
        prefix_spec_root or LAB_ROOT / "config/chaff-prefix-specs/v2", "prefix-spec root"
    )
    base_path = workloads / f"{workload_id}.json"
    spec_path = specs / f"{workload_id}.json"
    if not base_path.is_file() or base_path.is_symlink():
        raise ValueError(f"workload manifest is not a regular file: {base_path}")
    if not spec_path.is_file() or spec_path.is_symlink():
        raise ValueError(f"prefix-pack specification is not a regular file: {spec_path}")
    executed_implementation, source, qualification_image = (
        _execution_context or _qualification_execution_context()
    )
    neqo_client, neqo_client_sha256 = _bound_neqo_client(executed_implementation)
    base = load_json(base_path)
    validate_research_preparation(base, workload_id=workload_id)
    application = selected_navigation_root(base, workload_id)
    selected, prepared_selected = selected_chaff_resource(base, workload_id)
    headers = project_compact_headers(selected)
    prefix_spec = validate_prefix_pack_spec(
        load_json(spec_path), workload_id=workload_id, application_manifest=base
    )
    required = prefix_spec["required_chaff_streams"]
    qualified_parallel = max(MIN_CROSS_MODE_PARALLEL_CHAFF_STREAMS, required)
    base_sha = sha256_file(base_path)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{workload_id}-qualification-evidence-", dir=destination_root)
    )
    completed = False
    try:
        response_runs = _run_response_qualifications(
            base_path,
            temporary,
            selected_chaff_resource_id=selected["id"],
            qualified_parallel_chaff_streams=qualified_parallel,
            neqo_client=neqo_client,
            neqo_client_sha256=neqo_client_sha256,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
        )
        expected_response, request_stream_bytes = _stable_response_identity(
            response_runs,
            application_manifest_sha256=base_sha,
            application_resource_id=application["id"],
            selected_chaff_resource_id=selected["id"],
            qualified_parallel_chaff_streams=qualified_parallel,
            url=selected["url"],
            headers=headers,
        )
        if (
            expected_response["status"] != prepared_selected["status"]
            or expected_response["body_bytes"] != prepared_selected["bytes"]
            or expected_response["body_sha256"] != prepared_selected["body_sha256"]
        ):
            raise PreparationError(
                "qualified response differs from the frozen prepared response identity"
            )
        response_records = [
            _response_run_record(index, value) for index, value in enumerate(response_runs)
        ]
        response_digest = qualification_digest(
            "qcsd-chaff-response-qualification-v2", response_records
        )
        core = derive_chaff_core(
            application_manifest_sha256=base_sha,
            base_resource=selected,
            headers=headers,
            request_stream_bytes=request_stream_bytes,
            expected_response=expected_response,
            response_qualification_sha256=response_digest,
            application_resource_id=application["id"],
            selected_chaff_resource_id=selected["id"],
            qualified_parallel_chaff_streams=qualified_parallel,
            walkie_talkie_required_chaff_streams=required,
        )
        core_path = temporary / "chaff-core.json"
        core_path.write_bytes(canonical_bytes(core))
        runtime_path = temporary / "runtime-workload.json"
        runtime_path.write_bytes(canonical_bytes(runtime_manifest(base)))
        prefix_runs = _run_prefix_qualifications(
            base_path,
            runtime_path,
            core_path,
            spec_path,
            temporary,
            neqo_client=neqo_client,
            neqo_client_sha256=neqo_client_sha256,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
        )
        prefix_records = [
            _prefix_run_record(index, value) for index, value in enumerate(prefix_runs)
        ]
        prefix_digest = qualification_digest(
            "qcsd-chaff-prefix-pack-qualification-v2", prefix_records
        )
        neqo = _stable_neqo_provenance([*response_runs, *prefix_runs])
        sidecar = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": SIDECAR_ARTIFACT_TYPE,
            "workload_id": workload_id,
            "base_manifest": {"path": base_path.name, "sha256": base_sha},
            "selection_policy": SELECTION_POLICY,
            "application_resource_id": application["id"],
            "selected_chaff_resource_id": selected["id"],
            "qualified_parallel_chaff_streams": qualified_parallel,
            "walkie_talkie_required_chaff_streams": required,
            "header_projection": list(HEADER_PROJECTION),
            "method": METHOD,
            "qualification_policy": {
                "response_runs": QUALIFICATION_RUNS,
                "parallel_response_requests": qualified_parallel,
                "qualified_parallel_chaff_streams": qualified_parallel,
                "walkie_talkie_required_chaff_streams": required,
                "prefix_pack_runs": QUALIFICATION_RUNS,
                "profile": "research-1200",
                "response_defense": "none",
                "seed": 0,
                "udp_payload_ceiling": UDP_PAYLOAD_CEILING,
                "max_stream_data_excess": MAX_STREAM_DATA_EXCESS,
                "separate_chaff_namespace": True,
            },
            "qualification_source": source,
            "qualification_image_digest": qualification_image,
            "neqo_provenance": neqo,
            "implementation_receipt": executed_implementation,
            "fitting_source": _fitting_source_receipt(),
            "schema_five_diagnostic": _schema_five_diagnostic_receipt(),
            "schema_six_capacity_falsification_diagnostic": (
                _schema_six_capacity_falsification_diagnostic_receipt()
            ),
            "schema_six_runtime_falsification_diagnostic": (
                _schema_six_runtime_falsification_diagnostic_receipt()
            ),
            "schema_two_sender_framing_falsification_diagnostic": (
                _schema_two_sender_framing_falsification_diagnostic_receipt()
            ),
            "prefix_pack_spec": {"path": spec_path.name, "sha256": sha256_file(spec_path)},
            "resource": {
                "resource_id": selected["id"],
                "url": selected["url"],
                "headers": headers,
                "request_stream_bytes": request_stream_bytes,
                "expected_response": expected_response,
                "response_runs": response_records,
                "response_qualification_sha256": response_digest,
                "prefix_pack_runs": prefix_records,
                "prefix_pack_qualification_sha256": prefix_digest,
            },
        }
        validated = validate_sidecar(
            sidecar,
            workload_id=workload_id,
            base_manifest_path=base_path,
            prefix_spec_path=spec_path,
        )
        try:
            with destination.open("xb") as output:
                output.write(canonical_bytes(sidecar))
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            raise FileExistsError(
                f"{destination} already exists; qualification is create-only"
            ) from None
        completed = True
    finally:
        # A successful sidecar embeds the complete receipts, so its transient
        # runner files are redundant. On failure retain the exact receipt/log
        # tree inside the unpublished batch for diagnosis and audit.
        if completed:
            shutil.rmtree(temporary)
    return QualifiedChaffOutput(
        destination,
        sha256_file(destination),
        validated.manifest_sha256,
    )


def qualify_all_chaff(
    *,
    workload_root: Path | None = None,
    qualification_store: Path | None = None,
    prefix_spec_root: Path | None = None,
    schema_five_walkie_talkie_path: Path | None = None,
    timeout_seconds: int = 30,
    interval_seconds: int = 30,
) -> tuple[QualifiedChaffOutput, ...]:
    """Qualify the sealed cohort and publish one create-only directory."""

    store_input = qualification_store or LAB_ROOT / "config/chaff-qualification-store"
    store = _regular_directory_without_symlinks(store_input, "qualification store")
    destination = store / "v2"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"{destination} already exists; batch qualification is create-only")
    stale = sorted(store.glob(".v2.qcsd-batch-*"))
    if stale:
        raise ValueError("qualification store contains a stale unpublished batch")
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    specs = _regular_directory_without_symlinks(
        prefix_spec_root or LAB_ROOT / "config/chaff-prefix-specs/v2", "prefix-spec root"
    )
    oracle_input = Path(
        os.path.abspath(
            schema_five_walkie_talkie_path or LAB_ROOT / SCHEMA_FIVE_WALKIE_TALKIE_ARCHIVE
        )
    )
    oracle_parent = _regular_directory_without_symlinks(
        oracle_input.parent, "schema-five Walkie-Talkie artifact parent"
    )
    oracle_path = oracle_parent / oracle_input.name
    if oracle_path.is_symlink() or not oracle_path.is_file():
        raise ValueError(f"schema-five Walkie-Talkie artifact is not a regular file: {oracle_path}")
    oracle = _read_sealed_schema_five_walkie_talkie(oracle_path)
    # Validate the complete immutable input cohort before creating a candidate
    # directory or invoking the first network-capable qualification process.
    input_hashes: dict[Path, str] = {}
    for workload_id in SEALED_WORKLOAD_IDS:
        workload = workloads / f"{workload_id}.json"
        spec = specs / f"{workload_id}.json"
        if workload.is_symlink() or not workload.is_file():
            raise ValueError(f"workload manifest is not a regular file: {workload}")
        if spec.is_symlink() or not spec.is_file():
            raise ValueError(f"prefix-pack specification is not a regular file: {spec}")
        manifest = load_json(workload)
        validate_research_preparation(manifest, workload_id=workload_id)
        selected_chaff_resource(manifest, workload_id)
        observed_spec = validate_prefix_pack_spec(
            load_json(spec), workload_id=workload_id, application_manifest=manifest
        )
        expected_spec = prefix_pack_spec(
            workload_id,
            oracle,
            source_walkie_talkie_artifact_sha256=SOURCE_WALKIE_TALKIE_SHA256,
            application_manifest=manifest,
        )
        if canonical_bytes(observed_spec) != canonical_bytes(expected_spec):
            raise ValueError(
                "prefix-pack specification differs from the sealed schema-five numeric oracle"
            )
        input_hashes[workload] = sha256_file(workload)
        input_hashes[spec] = sha256_file(spec)
    execution_context = _qualification_execution_context()
    candidate = Path(tempfile.mkdtemp(prefix=".v2.qcsd-batch-", dir=store))
    try:
        outputs: list[QualifiedChaffOutput] = []
        for workload_id in SEALED_WORKLOAD_IDS:
            outputs.append(
                qualify_chaff(
                    workload_id,
                    workload_root=workloads,
                    qualification_root=candidate,
                    prefix_spec_root=specs,
                    timeout_seconds=timeout_seconds,
                    interval_seconds=interval_seconds,
                    _execution_context=execution_context,
                )
            )
        entries = sorted(candidate.iterdir(), key=lambda path: path.name)
        expected_names = sorted(f"{workload_id}.json" for workload_id in SEALED_WORKLOAD_IDS)
        if (
            [path.name for path in entries] != expected_names
            or any(path.is_symlink() or not path.is_file() for path in entries)
            or any(
                sha256_file(output.path) != output.sha256
                for output in outputs
                if output.path.parent == candidate
            )
        ):
            raise ValueError("batch chaff qualification did not produce the exact sealed cohort")
        # The batch can run for many minutes.  Read-only container mounts stop
        # the qualifier from changing A/S, but cannot prevent a concurrent host
        # process from replacing them.  Recheck the exact twelve raw inputs at
        # the publication boundary so v2 can only name the preflight cohort.
        if (
            _regular_directory_without_symlinks(workloads, "workload root") != workloads
            or _regular_directory_without_symlinks(specs, "prefix-spec root") != specs
        ):
            raise ValueError("batch chaff qualification input root changed before publication")
        for path, expected_sha256 in input_hashes.items():
            if path.is_symlink() or not path.is_file() or sha256_file(path) != expected_sha256:
                raise ValueError("batch chaff qualification input changed before publication")
        _bound_neqo_client(execution_context[0])
        directory_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _rename_noreplace(candidate, destination)
        store_fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(store_fd)
        finally:
            os.close(store_fd)
    except Exception:
        # Before rename, retain the unpublished same-filesystem candidate for
        # audit/recovery. After rename, a parent-fsync failure leaves a complete
        # canonical v2 which is deliberately rejected on the next invocation.
        raise
    return tuple(
        QualifiedChaffOutput(
            destination / output.path.name,
            sha256_file(destination / output.path.name),
            output.manifest_sha256,
        )
        for output in outputs
    )


def _qualification_execution_context() -> tuple[dict[str, Any], dict[str, Any], str]:
    """Bind the clean executed implementation once, before batch staging exists."""

    executed_implementation = implementation_receipt(executed_image=True)
    if executed_implementation["source_files"] != _implementation_source_files():
        raise ValueError(
            "mounted qualification sources do not match the code installed in the image"
        )
    source = source_metadata()
    qualification_image = os.environ.get("QCSD_LAB_IMAGE_DIGEST", str(source.get("image_digest")))
    _validate_source(source, qualification_image)
    if _source_execution_identity(executed_implementation["source"]) != (
        _source_execution_identity(source)
    ):
        raise ValueError("executed image source does not match runtime qualification source")
    return executed_implementation, source, qualification_image


def _bound_neqo_client(implementation: Mapping[str, Any]) -> tuple[Path, str]:
    """Resolve and rehash the exact Neqo executable named by image evidence."""

    record = _exact_mapping(
        implementation.get("neqo_qcsd_client"),
        {"path", "sha256"},
        "qualification Neqo client receipt",
    )
    path_value = record["path"]
    expected_sha256 = record["sha256"]
    if (
        not isinstance(path_value, str)
        or not path_value.startswith("/")
        or not _digest(expected_sha256)
    ):
        raise ValueError("qualification Neqo client receipt is invalid")
    path = Path(path_value)
    if path.is_symlink() or not path.is_file() or sha256_file(path) != expected_sha256:
        raise ValueError("qualification Neqo client executable does not match its image receipt")
    return path, expected_sha256


def _recheck_bound_neqo_client(path: Path, expected_sha256: str) -> None:
    if path.is_symlink() or not path.is_file() or sha256_file(path) != expected_sha256:
        raise ValueError("qualification Neqo client changed before execution")


def _regular_directory_without_symlinks(path: Path, label: str) -> Path:
    """Resolve an existing directory only after rejecting symlink components."""

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symbolic link: {current}")
    if not absolute.is_dir():
        raise ValueError(f"{label} is not a regular directory: {absolute}")
    return absolute.resolve(strict=True)


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a same-filesystem directory without replacement."""

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for create-only publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(f"{destination} changed during create-only batch publication")
    raise OSError(error, os.strerror(error), destination)


def _run_response_qualifications(
    application_path: Path,
    directory: Path,
    *,
    selected_chaff_resource_id: int,
    qualified_parallel_chaff_streams: int,
    neqo_client: Path,
    neqo_client_sha256: str,
    timeout_seconds: int,
    interval_seconds: int,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for index in range(QUALIFICATION_RUNS):
        if index:
            time.sleep(interval_seconds)
        _recheck_bound_neqo_client(neqo_client, neqo_client_sha256)
        output = directory / f"response-{index}"
        result = _run_neqo(
            [
                str(neqo_client),
                "qualify-chaff-response",
                "--workload",
                str(application_path),
                "--application-resource-id",
                "0",
                "--selected-chaff-resource-id",
                str(selected_chaff_resource_id),
                "--output-dir",
                str(output),
                "--timeout-seconds",
                str(timeout_seconds),
                "--max-response-bytes",
                "1048576",
                "--packet-size",
                str(UDP_PAYLOAD_CEILING),
                "--parallel-requests",
                str(qualified_parallel_chaff_streams),
            ],
            log=directory / f"response-{index}.log",
            configured_timeout_seconds=timeout_seconds,
            label=f"chaff response qualification {index + 1}",
        )
        if result.returncode:
            raise PreparationError(
                f"chaff response qualification {index + 1} failed ({result.returncode})"
            )
        receipt_path = output / "qualification.json"
        receipt = load_json(receipt_path)
        runs.append(receipt)
    return runs


def _run_response_qualifications_v2(
    application_path: Path,
    directory: Path,
    *,
    selected_chaff_resource_id: int,
    application_manifest_sha256: str,
    application_resource_id: int,
    url: str,
    headers: list[list[str]],
    neqo_client: Path,
    neqo_client_sha256: str,
    timeout_seconds: int,
    interval_seconds: int,
) -> list[tuple[int, dict[str, Any]]]:
    """Run three fresh sustained connection epochs for one candidate.

    Representation identity and response-capacity failures are complete
    measurements, so all three epochs are retained before the candidate is
    rejected.  Every network, name-resolution, timeout, or protocol failure is
    an environmental/transport failure and aborts the whole transaction.
    """

    runs: list[tuple[int, dict[str, Any]]] = []
    for index in range(QUALIFICATION_RUNS):
        if index:
            time.sleep(interval_seconds)
        _recheck_bound_neqo_client(neqo_client, neqo_client_sha256)
        output = directory / f"response-{index}"
        result = _run_neqo(
            [
                str(neqo_client),
                "qualify-chaff-response",
                "--workload",
                str(application_path),
                "--application-resource-id",
                "0",
                "--selected-chaff-resource-id",
                str(selected_chaff_resource_id),
                "--output-dir",
                str(output),
                "--timeout-seconds",
                str(timeout_seconds),
                "--max-response-bytes",
                "1048576",
                "--packet-size",
                str(UDP_PAYLOAD_CEILING),
                "--parallel-requests",
                str(RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS),
                "--total-requests",
                str(RESPONSE_ONLY_REQUESTS_PER_EPOCH),
                "--request-header-mode",
                IDENTITY_REQUEST_HEADER_MODE,
            ],
            log=directory / f"response-{index}.log",
            configured_timeout_seconds=timeout_seconds,
            label=f"sustained chaff response qualification {index + 1}",
        )
        receipt_path = output / "qualification.json"
        try:
            receipt = load_json(receipt_path)
        except (OSError, TypeError, ValueError) as error:
            raise PreparationError(
                f"sustained chaff response qualification {index + 1} lacks a valid receipt"
            ) from error
        if not isinstance(receipt, Mapping):
            raise PreparationError(
                f"sustained chaff response qualification {index + 1} receipt is not an object"
            )
        failure_class = receipt.get("failure_class")
        if result.returncode == 0:
            if receipt.get("passed") is not True or failure_class is not None:
                raise PreparationError(
                    "successful sustained response qualifier returned an inconsistent receipt"
                )
        elif failure_class not in {"identity", "capacity"}:
            rendered = failure_class if isinstance(failure_class, str) else "unclassified"
            raise PreparationError(
                "sustained response qualification aborted on "
                f"{rendered} failure in epoch {index + 1}"
            )
        try:
            _validate_response_receipt_v2(
                receipt,
                application_manifest_sha256=application_manifest_sha256,
                application_resource_id=application_resource_id,
                selected_chaff_resource_id=selected_chaff_resource_id,
                url=url,
                headers=headers,
            )
        except ValueError as error:
            raise PreparationError(
                f"sustained response qualification epoch {index + 1} is malformed: {error}"
            ) from error
        runs.append((result.returncode, dict(receipt)))
    return runs


def _run_prefix_qualifications(
    base_path: Path,
    runtime_path: Path,
    core_path: Path,
    spec_path: Path,
    directory: Path,
    *,
    neqo_client: Path,
    neqo_client_sha256: str,
    timeout_seconds: int,
    interval_seconds: int,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for index in range(QUALIFICATION_RUNS):
        if index:
            time.sleep(interval_seconds)
        _recheck_bound_neqo_client(neqo_client, neqo_client_sha256)
        output = directory / f"prefix-{index}"
        result = _run_neqo(
            [
                str(neqo_client),
                "qualify-chaff-prefix",
                "--workload",
                str(base_path),
                "--runtime-workload",
                str(runtime_path),
                "--chaff-core",
                str(core_path),
                "--application-resource-id",
                "0",
                "--prefix-pack-spec",
                str(spec_path),
                "--output-dir",
                str(output),
                "--timeout-seconds",
                str(timeout_seconds),
            ],
            log=directory / f"prefix-{index}.log",
            configured_timeout_seconds=timeout_seconds,
            label=f"chaff prefix-pack qualification {index + 1}",
        )
        if result.returncode:
            raise PreparationError(
                f"chaff prefix-pack qualification {index + 1} failed ({result.returncode})"
            )
        receipt_path = output / "qualification.json"
        receipt = load_json(receipt_path)
        runs.append(receipt)
    return runs


def _stable_response_identity(
    runs: Sequence[Mapping[str, Any]],
    *,
    application_manifest_sha256: str,
    application_resource_id: int,
    selected_chaff_resource_id: int,
    qualified_parallel_chaff_streams: int,
    url: str,
    headers: list[list[str]],
) -> tuple[dict[str, Any], int]:
    if len(runs) != QUALIFICATION_RUNS:
        raise PreparationError("exactly three response qualification invocations are required")
    identities: list[tuple[int, str, int, str]] = []
    sizes: list[int] = []
    invocation_ids: set[str] = set()
    prior_end = -1
    for run in runs:
        try:
            identity, size, started, ended, invocation_id = _validate_response_receipt(
                run,
                application_manifest_sha256=application_manifest_sha256,
                application_resource_id=application_resource_id,
                selected_chaff_resource_id=selected_chaff_resource_id,
                qualified_parallel_chaff_streams=qualified_parallel_chaff_streams,
                url=url,
                headers=headers,
            )
        except ValueError as error:
            raise PreparationError(str(error)) from error
        if invocation_id in invocation_ids or started <= prior_end:
            raise PreparationError("response qualifications are not independent invocations")
        invocation_ids.add(invocation_id)
        prior_end = ended
        identities.extend([identity] * qualified_parallel_chaff_streams)
        sizes.append(size)
    if len(set(identities)) != 1 or len(set(sizes)) != 1:
        raise PreparationError("chaff response identity or request size changed across runs")
    status, encoding, body_bytes, body_sha256 = identities[0]
    expected = {
        "status": status,
        "content_encoding": encoding,
        "body_bytes": body_bytes,
        "body_sha256": body_sha256,
    }
    _validate_expected_response(expected)
    return expected, sizes[0]


def _response_run_record(index: int, run: Mapping[str, Any]) -> dict[str, Any]:
    receipt = dict(run)
    return {
        "run_index": index,
        "receipt_object_sha256": qualification_digest(
            "qcsd-chaff-response-receipt-object-v2", [receipt]
        ),
        "receipt": receipt,
    }


def _validate_response_receipt(
    value: object,
    *,
    application_manifest_sha256: str,
    application_resource_id: int,
    selected_chaff_resource_id: int,
    qualified_parallel_chaff_streams: int,
    url: str,
    headers: list[list[str]],
) -> tuple[tuple[int, str, int, str], int, int, int, str]:
    receipt = _exact_mapping(value, RESPONSE_RECEIPT_KEYS, "response qualification receipt")
    started = receipt["started_unix_ns"]
    ended = receipt["ended_unix_ns"]
    invocation_id = receipt["invocation_id"]
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != QUALIFICATION_SCHEMA_VERSION
        or receipt["artifact_type"] != RESPONSE_ARTIFACT_TYPE
        or receipt["application_workload_sha256"] != application_manifest_sha256
        or type(receipt["application_resource_id"]) is not int
        or receipt["application_resource_id"] != application_resource_id
        or type(receipt["selected_chaff_resource_id"]) is not int
        or receipt["selected_chaff_resource_id"] != selected_chaff_resource_id
        or type(receipt["qualified_parallel_chaff_streams"]) is not int
        or receipt["qualified_parallel_chaff_streams"] != qualified_parallel_chaff_streams
        or receipt["method"] != METHOD
        or receipt["url"] != url
        or receipt["request_headers"] != headers
        or type(receipt["parallel_requests"]) is not int
        or receipt["parallel_requests"] != qualified_parallel_chaff_streams
        or type(receipt["connection_count"]) is not int
        or receipt["connection_count"] != 1
        or type(receipt["requests_opened_before_first_network_output"]) is not int
        or receipt["requests_opened_before_first_network_output"]
        != qualified_parallel_chaff_streams
        or type(receipt["request_stream_bytes"]) is not int
        or type(receipt["max_response_bytes"]) is not int
        or receipt["max_response_bytes"] != 1_048_576
        or type(receipt["udp_payload_ceiling"]) is not int
        or receipt["udp_payload_ceiling"] != UDP_PAYLOAD_CEILING
        or type(started) is not int
        or type(ended) is not int
        or started < 0
        or ended <= started
        or not isinstance(invocation_id, str)
        or not invocation_id.strip()
        or invocation_id != invocation_id.strip()
        or receipt["completion_status"] != "complete"
        or receipt["error"] is not None
        or receipt["passed"] is not True
    ):
        raise ValueError("response qualification receipt binding is invalid")
    _validate_receipt_neqo_provenance(receipt, label="response qualification")
    requests = receipt["requests"]
    if not isinstance(requests, list) or len(requests) != qualified_parallel_chaff_streams:
        raise ValueError("response qualification request count is invalid")
    identities: list[tuple[int, str, int, str]] = []
    sizes: list[int] = []
    stream_ids: set[int] = set()
    for index, value_request in enumerate(requests):
        request = _exact_mapping(
            value_request, RESPONSE_REQUEST_KEYS, "response qualification request"
        )
        status = request["status"]
        encoding = request["content_encoding"]
        body_bytes = request["body_bytes"]
        body_sha256 = request["body_sha256"]
        size = request["request_stream_bytes"]
        stream_id = request["stream_id"]
        if (
            type(request["request_index"]) is not int
            or request["request_index"] != index
            or type(stream_id) is not int
            or stream_id < 0
            or stream_id in stream_ids
            or type(size) is not int
            or size <= 0
            or type(status) is not int
            or not 200 <= status <= 299
            or not isinstance(encoding, str)
            or encoding != _normalize_content_encoding(encoding)
            or type(body_bytes) is not int
            or body_bytes < UDP_PAYLOAD_CEILING
            or not _digest(body_sha256)
            or request["complete"] is not True
            or request["outcome"] != "complete"
        ):
            raise ValueError("response qualification request is invalid")
        stream_ids.add(stream_id)
        identities.append((status, encoding, body_bytes, body_sha256))
        sizes.append(size)
    if len(set(identities)) != 1 or len(set(sizes)) != 1:
        raise ValueError("response qualification is unstable within one invocation")
    if receipt["request_stream_bytes"] != sizes[0]:
        raise ValueError("response qualification request size receipt is inconsistent")
    observations = receipt["packet_observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError("response qualification packet transcript is missing")
    normalized: list[dict[str, Any]] = []
    qualification_directions: set[str] = set()
    for sequence, value_observation in enumerate(observations):
        observation = _exact_mapping(
            value_observation, PACKET_OBSERVATION_KEYS, "response packet observation"
        )
        if (
            type(observation["sequence"]) is not int
            or observation["sequence"] != sequence
            or observation["phase"] not in {"handshake", "qualification"}
            or observation["direction"] not in {"incoming", "outgoing"}
            or type(observation["udp_payload_bytes"]) is not int
            or not 1 <= observation["udp_payload_bytes"] <= UDP_PAYLOAD_CEILING
        ):
            raise ValueError("response qualification packet transcript is invalid")
        if observation["phase"] == "qualification":
            qualification_directions.add(observation["direction"])
        normalized.append(observation)
    rust_ordered = [
        {
            "sequence": item["sequence"],
            "phase": item["phase"],
            "direction": item["direction"],
            "udp_payload_bytes": item["udp_payload_bytes"],
        }
        for item in normalized
    ]
    packet_log = json.dumps(rust_ordered, separators=(",", ":")).encode()
    if receipt["packet_log_sha256"] != sha256_bytes(packet_log) or qualification_directions != {
        "incoming",
        "outgoing",
    }:
        raise ValueError("response qualification packet transcript hash is invalid")
    _validate_udp_statistics(receipt["packets"], observations=rust_ordered)
    return identities[0], sizes[0], started, ended, invocation_id


def _validate_response_receipt_v2(
    value: object,
    *,
    application_manifest_sha256: str,
    application_resource_id: int,
    selected_chaff_resource_id: int,
    url: str,
    headers: list[list[str]],
) -> tuple[list[tuple[int, str, int, str]], int, int, int, str, str | None]:
    """Validate one sustained 8x5 response epoch without hiding a rejection."""

    receipt = _exact_mapping(
        value, RESPONSE_V2_RECEIPT_KEYS, "sustained response qualification receipt"
    )
    started = receipt["started_unix_ns"]
    ended = receipt["ended_unix_ns"]
    invocation_id = receipt["invocation_id"]
    failure_class = receipt["failure_class"]
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION
        or receipt["artifact_type"] != RESPONSE_ARTIFACT_TYPE
        or receipt["application_workload_sha256"] != application_manifest_sha256
        or type(receipt["application_resource_id"]) is not int
        or receipt["application_resource_id"] != application_resource_id
        or type(receipt["selected_chaff_resource_id"]) is not int
        or receipt["selected_chaff_resource_id"] != selected_chaff_resource_id
        or type(receipt["qualified_parallel_chaff_streams"]) is not int
        or receipt["qualified_parallel_chaff_streams"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or receipt["method"] != METHOD
        or receipt["url"] != url
        or receipt["request_headers"] != headers
        or receipt["request_header_mode"] != IDENTITY_REQUEST_HEADER_MODE
        or type(receipt["parallel_requests"]) is not int
        or receipt["parallel_requests"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or type(receipt["total_requests"]) is not int
        or receipt["total_requests"] != RESPONSE_ONLY_REQUESTS_PER_EPOCH
        or type(receipt["request_waves"]) is not int
        or receipt["request_waves"] != RESPONSE_ONLY_WAVES_PER_EPOCH
        or type(receipt["max_concurrent_requests"]) is not int
        or receipt["max_concurrent_requests"] != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or type(receipt["connection_count"]) is not int
        or receipt["connection_count"] != 1
        or type(receipt["requests_opened_before_first_network_output"]) is not int
        or receipt["requests_opened_before_first_network_output"]
        != RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        or type(receipt["request_stream_bytes"]) is not int
        or receipt["request_stream_bytes"] <= 0
        or type(receipt["max_response_bytes"]) is not int
        or receipt["max_response_bytes"] != 1_048_576
        or type(receipt["udp_payload_ceiling"]) is not int
        or receipt["udp_payload_ceiling"] != UDP_PAYLOAD_CEILING
        or type(started) is not int
        or type(ended) is not int
        or started < 0
        or ended <= started
        or not isinstance(invocation_id, str)
        or not invocation_id.strip()
        or invocation_id != invocation_id.strip()
        or receipt["completion_status"] != "complete"
        or failure_class not in {None, "identity", "capacity"}
    ):
        raise ValueError("sustained response qualification receipt binding is invalid")
    if receipt["passed"] is True:
        if failure_class is not None or receipt["error"] is not None:
            raise ValueError("passing sustained response receipt reports a failure")
    elif receipt["passed"] is False:
        if (
            failure_class not in {"identity", "capacity"}
            or not isinstance(receipt["error"], str)
            or not receipt["error"].strip()
            or receipt["error"] != receipt["error"].strip()
        ):
            raise ValueError("rejected sustained response receipt lacks an exact failure class")
    else:
        raise ValueError("sustained response qualification passed flag is invalid")

    _validate_receipt_neqo_provenance(receipt, label="sustained response qualification")
    requests = receipt["requests"]
    if not isinstance(requests, list) or len(requests) != RESPONSE_ONLY_REQUESTS_PER_EPOCH:
        raise ValueError("sustained response qualification request count is invalid")
    identities: list[tuple[int, str, int, str]] = []
    sizes: list[int] = []
    stream_ids: set[int] = set()
    for index, value_request in enumerate(requests):
        request = _exact_mapping(
            value_request, RESPONSE_V2_REQUEST_KEYS, "sustained response qualification request"
        )
        status = request["status"]
        encoding = request["content_encoding"]
        body_bytes = request["body_bytes"]
        body_sha256 = request["body_sha256"]
        size = request["request_stream_bytes"]
        stream_id = request["stream_id"]
        if (
            type(request["request_index"]) is not int
            or request["request_index"] != index
            or type(request["wave_index"]) is not int
            or request["wave_index"] != index // RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
            or type(stream_id) is not int
            or stream_id != index * 4
            or stream_id in stream_ids
            or type(size) is not int
            or size <= 0
            or type(status) is not int
            or not 100 <= status <= 599
            or not isinstance(encoding, str)
            or encoding != _normalize_content_encoding(encoding)
            or type(body_bytes) is not int
            or body_bytes < 0
            or body_bytes > receipt["max_response_bytes"]
            or not _digest(body_sha256)
            or request["complete"] is not True
            or request["outcome"] != "complete"
        ):
            raise ValueError("sustained response qualification request is invalid")
        stream_ids.add(stream_id)
        identities.append((status, encoding, body_bytes, body_sha256))
        sizes.append(size)
    if len(set(sizes)) != 1 or receipt["request_stream_bytes"] != sizes[0]:
        raise ValueError("sustained response qualification request primitive changed")
    capacity_failure = any(identity[2] < UDP_PAYLOAD_CEILING for identity in identities)
    identity_failure = len(set(identities)) != 1 or any(
        not 200 <= identity[0] <= 299 or identity[1] != "identity" for identity in identities
    )
    derived_failure = "capacity" if capacity_failure else "identity" if identity_failure else None
    if failure_class != derived_failure or receipt["passed"] is (derived_failure is not None):
        raise ValueError("sustained response qualification failure class is inconsistent")

    observations = receipt["packet_observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError("sustained response qualification packet transcript is missing")
    normalized: list[dict[str, Any]] = []
    qualification_directions: set[str] = set()
    for sequence, value_observation in enumerate(observations):
        observation = _exact_mapping(
            value_observation, PACKET_OBSERVATION_KEYS, "response packet observation"
        )
        if (
            type(observation["sequence"]) is not int
            or observation["sequence"] != sequence
            or observation["phase"] not in {"handshake", "qualification"}
            or observation["direction"] not in {"incoming", "outgoing"}
            or type(observation["udp_payload_bytes"]) is not int
            or not 1 <= observation["udp_payload_bytes"] <= UDP_PAYLOAD_CEILING
        ):
            raise ValueError("sustained response qualification packet transcript is invalid")
        if observation["phase"] == "qualification":
            qualification_directions.add(observation["direction"])
        normalized.append(observation)
    rust_ordered = [
        {
            "sequence": item["sequence"],
            "phase": item["phase"],
            "direction": item["direction"],
            "udp_payload_bytes": item["udp_payload_bytes"],
        }
        for item in normalized
    ]
    packet_log = json.dumps(rust_ordered, separators=(",", ":")).encode()
    if receipt["packet_log_sha256"] != sha256_bytes(packet_log) or qualification_directions != {
        "incoming",
        "outgoing",
    }:
        raise ValueError("sustained response qualification packet transcript hash is invalid")
    _validate_udp_statistics(receipt["packets"], observations=rust_ordered)
    return identities, sizes[0], started, ended, invocation_id, failure_class


def _response_v2_run_record(
    epoch_index: int, process_exit_code: int, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    value = dict(receipt)
    return {
        "epoch_index": epoch_index,
        "process_exit_code": process_exit_code,
        "receipt_object_sha256": qualification_digest(
            "qcsd-chaff-sustained-response-receipt-object-v3", [value]
        ),
        "receipt": value,
    }


def _prepared_candidate_response(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": value["status"],
        "body_bytes": value["bytes"],
        "body_sha256": value["body_sha256"],
    }


def _candidate_attempt_record_v2(
    *,
    candidate_index: int,
    base_resource: Mapping[str, Any],
    prepared_response: Mapping[str, Any],
    epochs: Sequence[tuple[int, Mapping[str, Any]]],
    application_manifest_sha256: str,
    application_resource_id: int,
    neqo_provenance: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None, int]:
    """Validate and bind all 120 completions for one deterministic candidate."""

    if len(epochs) != QUALIFICATION_RUNS:
        raise PreparationError("each response-only v2 candidate requires exactly three epochs")
    headers = project_identity_chaff_headers(base_resource)
    identities: list[tuple[int, str, int, str]] = []
    sizes: list[int] = []
    invocation_ids: set[str] = set()
    provenances: list[dict[str, Any]] = []
    prior_end = -1
    records: list[dict[str, Any]] = []
    explicit_failures: set[str] = set()
    for epoch_index, (exit_code, raw_receipt) in enumerate(epochs):
        if type(exit_code) is not int or exit_code < 0:
            raise PreparationError("sustained response qualifier exit code is invalid")
        try:
            epoch_identities, size, started, ended, invocation_id, failure_class = (
                _validate_response_receipt_v2(
                    raw_receipt,
                    application_manifest_sha256=application_manifest_sha256,
                    application_resource_id=application_resource_id,
                    selected_chaff_resource_id=base_resource["id"],
                    url=base_resource["url"],
                    headers=headers,
                )
            )
        except ValueError as error:
            raise PreparationError(str(error)) from error
        if (exit_code == 0) is (failure_class is not None):
            raise PreparationError("sustained response qualifier exit status is inconsistent")
        if invocation_id in invocation_ids or started <= prior_end:
            raise PreparationError("sustained response epochs are not independent invocations")
        if prior_end >= 0 and started - prior_end < RESPONSE_ONLY_EPOCH_SPACING_SECONDS * 10**9:
            raise PreparationError("sustained response epochs lack the fixed 30-second spacing")
        invocation_ids.add(invocation_id)
        prior_end = ended
        identities.extend(epoch_identities)
        sizes.append(size)
        provenance = _receipt_neqo_provenance(raw_receipt)
        provenances.append(provenance)
        if neqo_provenance is not None and provenance != dict(neqo_provenance):
            raise PreparationError("sustained response epoch Neqo provenance changed")
        if failure_class is not None:
            explicit_failures.add(failure_class)
        records.append(_response_v2_run_record(epoch_index, exit_code, raw_receipt))
    if len({json.dumps(value, sort_keys=True) for value in provenances}) != 1:
        raise PreparationError("sustained response epoch Neqo provenance changed")
    if len(set(sizes)) != 1:
        raise PreparationError("identity chaff request-stream bytes changed across epochs")
    capacity_failure = "capacity" in explicit_failures or any(
        identity[2] < UDP_PAYLOAD_CEILING for identity in identities
    )
    identity_failure = (
        "identity" in explicit_failures
        or len(set(identities)) != 1
        or any(
            not 200 <= identity[0] <= 299 or identity[1] != "identity" for identity in identities
        )
    )
    failure_class = "capacity" if capacity_failure else "identity" if identity_failure else None
    outcome = "qualified" if failure_class is None else "rejected"
    response_digest = qualification_digest(
        "qcsd-chaff-sustained-response-qualification-v3", records
    )
    expected_response: dict[str, Any] | None = None
    if failure_class is None:
        status, encoding, body_bytes, body_sha256 = identities[0]
        expected_response = {
            "status": status,
            "content_encoding": encoding,
            "body_bytes": body_bytes,
            "body_sha256": body_sha256,
        }
        _validate_expected_response(expected_response)
    attempt = {
        "candidate_index": candidate_index,
        "resource_id": base_resource["id"],
        "url": base_resource["url"],
        "prepared_response": _prepared_candidate_response(prepared_response),
        "headers": headers,
        "outcome": outcome,
        "failure_class": failure_class,
        "connection_epochs": records,
        "response_qualification_sha256": response_digest,
    }
    return attempt, expected_response, sizes[0]


def _validate_response_only_candidate_attempt(
    value: object,
    *,
    candidate_index: int,
    base_resource: Mapping[str, Any],
    prepared_response: Mapping[str, Any],
    application_manifest_sha256: str,
    application_resource_id: int,
    neqo_provenance: Mapping[str, Any],
) -> dict[str, Any]:
    attempt = _exact_mapping(value, CANDIDATE_ATTEMPT_KEYS, "response-only v2 candidate attempt")
    prepared = _exact_mapping(
        attempt["prepared_response"],
        PREPARED_CANDIDATE_RESPONSE_KEYS,
        "response-only v2 prepared candidate response",
    )
    if (
        type(attempt["candidate_index"]) is not int
        or attempt["candidate_index"] != candidate_index
        or type(attempt["resource_id"]) is not int
        or attempt["resource_id"] != base_resource.get("id")
        or attempt["url"] != base_resource.get("url")
        or attempt["headers"] != project_identity_chaff_headers(base_resource)
        or attempt["outcome"] not in {"qualified", "rejected"}
        or attempt["failure_class"] not in {None, "identity", "capacity"}
        or type(prepared["status"]) is not int
        or type(prepared["body_bytes"]) is not int
        or not _digest(prepared["body_sha256"])
    ):
        raise ValueError("response-only v2 candidate attempt binding is invalid")
    epochs_value = attempt["connection_epochs"]
    if not isinstance(epochs_value, list) or len(epochs_value) != QUALIFICATION_RUNS:
        raise ValueError("response-only v2 candidate requires exactly three epochs")
    epochs: list[tuple[int, Mapping[str, Any]]] = []
    for epoch_index, value_epoch in enumerate(epochs_value):
        epoch = _exact_mapping(value_epoch, RESPONSE_V2_RUN_KEYS, "sustained response epoch")
        receipt = epoch["receipt"]
        if not isinstance(receipt, Mapping):
            raise ValueError("sustained response epoch receipt must be an object")
        expected_sha256 = qualification_digest(
            "qcsd-chaff-sustained-response-receipt-object-v3", [receipt]
        )
        if (
            type(epoch["epoch_index"]) is not int
            or epoch["epoch_index"] != epoch_index
            or type(epoch["process_exit_code"]) is not int
            or epoch["process_exit_code"] < 0
            or epoch["receipt_object_sha256"] != expected_sha256
        ):
            raise ValueError("sustained response epoch binding is invalid")
        epochs.append((epoch["process_exit_code"], receipt))
    try:
        expected, _identity, _request_size = _candidate_attempt_record_v2(
            candidate_index=candidate_index,
            base_resource=base_resource,
            prepared_response=prepared_response,
            epochs=epochs,
            application_manifest_sha256=application_manifest_sha256,
            application_resource_id=application_resource_id,
            neqo_provenance=neqo_provenance,
        )
    except PreparationError as error:
        raise ValueError(str(error)) from error
    if dict(attempt) != expected:
        raise ValueError("response-only v2 candidate attempt derivation is inconsistent")
    return dict(attempt)


def _validate_response_only_v2_resource_receipt(
    value: object,
    base_resource: Mapping[str, Any],
    *,
    selected_attempt: Mapping[str, Any],
) -> dict[str, Any]:
    resource = _exact_mapping(
        value,
        RESPONSE_ONLY_V2_RESOURCE_RECEIPT_KEYS,
        "response-only v2 qualified chaff resource",
    )
    if (
        type(resource["resource_id"]) is not int
        or resource["resource_id"] != base_resource.get("id")
        or resource["url"] != base_resource.get("url")
        or resource["headers"] != project_identity_chaff_headers(base_resource)
        or type(resource["request_stream_bytes"]) is not int
        or resource["request_stream_bytes"] <= 0
        or resource["response_qualification_sha256"]
        != selected_attempt["response_qualification_sha256"]
    ):
        raise ValueError("response-only v2 qualified resource binding is invalid")
    _validate_expected_response(resource["expected_response"])
    if resource["expected_response"]["content_encoding"] != "identity":
        raise ValueError("response-only v2 authoritative response must use identity encoding")
    epochs = selected_attempt["connection_epochs"]
    identities: set[tuple[int, str, int, str]] = set()
    sizes: set[int] = set()
    for epoch in epochs:
        receipt = epoch["receipt"]
        for request in receipt["requests"]:
            identities.add(
                (
                    request["status"],
                    request["content_encoding"],
                    request["body_bytes"],
                    request["body_sha256"],
                )
            )
            sizes.add(request["request_stream_bytes"])
    expected_response = resource["expected_response"]
    expected_identity = {
        (
            expected_response["status"],
            expected_response["content_encoding"],
            expected_response["body_bytes"],
            expected_response["body_sha256"],
        )
    }
    if (
        selected_attempt["outcome"] != "qualified"
        or selected_attempt["failure_class"] is not None
        or identities != expected_identity
        or sizes != {resource["request_stream_bytes"]}
    ):
        raise ValueError("response-only v2 authoritative response identity is inconsistent")
    return dict(resource)


def _prefix_run_record(index: int, run: Mapping[str, Any]) -> dict[str, Any]:
    receipt = dict(run)
    if receipt.get("artifact_type") != PREFIX_ARTIFACT_TYPE or receipt.get("passed") is not True:
        raise PreparationError("chaff prefix-pack qualification did not pass")
    return {
        "run_index": index,
        "receipt_object_sha256": qualification_digest(
            "qcsd-chaff-prefix-pack-receipt-object-v2", [receipt]
        ),
        "receipt": receipt,
    }


def _validate_response_only_resource_receipt(
    value: object,
    base_resource: Mapping[str, Any],
    *,
    application_manifest_sha256: str,
    application_manifest: Mapping[str, Any],
    application_resource_id: int,
    neqo_provenance: Mapping[str, Any],
) -> dict[str, Any]:
    resource = _exact_mapping(
        value,
        RESPONSE_ONLY_RESOURCE_RECEIPT_KEYS,
        "response-only qualified chaff resource",
    )
    if (
        type(resource["resource_id"]) is not int
        or resource["resource_id"] != base_resource.get("id")
        or resource["url"] != base_resource.get("url")
        or resource["headers"] != project_compact_headers(base_resource)
        or type(resource["request_stream_bytes"]) is not int
        or resource["request_stream_bytes"] <= 0
    ):
        raise ValueError("response-only qualified chaff resource binding is invalid")
    _validate_expected_response(resource["expected_response"])
    prepared = _prepared_expected_responses(application_manifest)[resource["resource_id"]]
    if (
        resource["expected_response"]["status"] != prepared["status"]
        or resource["expected_response"]["body_bytes"] != prepared["bytes"]
        or resource["expected_response"]["body_sha256"] != prepared["body_sha256"]
    ):
        raise ValueError("response-only qualified chaff response differs from prepared identity")
    response_runs = resource["response_runs"]
    if not isinstance(response_runs, list) or len(response_runs) != QUALIFICATION_RUNS:
        raise ValueError("response-only qualified chaff requires exactly three response runs")
    prior_end = -1
    invocation_ids: set[str] = set()
    response_identities: list[tuple[int, str, int, str]] = []
    response_sizes: list[int] = []
    for index, run in enumerate(response_runs):
        record = _exact_mapping(run, RESPONSE_RUN_KEYS, "response qualification run")
        receipt = record["receipt"]
        expected_object_sha = qualification_digest(
            "qcsd-chaff-response-receipt-object-v2", [receipt]
        )
        if (
            type(record["run_index"]) is not int
            or record["run_index"] != index
            or record["receipt_object_sha256"] != expected_object_sha
        ):
            raise ValueError("response qualification run binding is invalid")
        identity, size, started, ended, invocation_id = _validate_response_receipt(
            receipt,
            application_manifest_sha256=application_manifest_sha256,
            application_resource_id=application_resource_id,
            selected_chaff_resource_id=resource["resource_id"],
            qualified_parallel_chaff_streams=RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            url=resource["url"],
            headers=resource["headers"],
        )
        if (
            invocation_id in invocation_ids
            or started <= prior_end
            or _receipt_neqo_provenance(receipt) != dict(neqo_provenance)
        ):
            raise ValueError("response qualifications are not independent invocations")
        invocation_ids.add(invocation_id)
        prior_end = ended
        response_identities.append(identity)
        response_sizes.append(size)
    expected_response = resource["expected_response"]
    expected_identity = (
        expected_response["status"],
        expected_response["content_encoding"],
        expected_response["body_bytes"],
        expected_response["body_sha256"],
    )
    if set(response_identities) != {expected_identity} or set(response_sizes) != {
        resource["request_stream_bytes"]
    }:
        raise ValueError("response-only qualification identity is inconsistent")
    expected_response_digest = qualification_digest(
        "qcsd-chaff-response-qualification-v2", response_runs
    )
    if resource["response_qualification_sha256"] != expected_response_digest:
        raise ValueError("response-only qualification aggregate SHA-256 mismatch")
    return resource


def _validate_resource_receipt(
    value: object,
    base_resource: Mapping[str, Any],
    *,
    application_manifest_sha256: str,
    application_manifest: Mapping[str, Any],
    prefix_spec: Mapping[str, Any],
    prefix_spec_sha256: str,
    neqo_provenance: Mapping[str, Any],
) -> dict[str, Any]:
    resource = _exact_mapping(value, RESOURCE_RECEIPT_KEYS, "qualified chaff resource")
    qualified_parallel = max(
        MIN_CROSS_MODE_PARALLEL_CHAFF_STREAMS, prefix_spec["required_chaff_streams"]
    )
    if (
        resource["resource_id"] != base_resource.get("id")
        or resource["url"] != base_resource.get("url")
        or resource["headers"] != project_compact_headers(base_resource)
        or type(resource["request_stream_bytes"]) is not int
        or resource["request_stream_bytes"] <= 0
    ):
        raise ValueError("qualified chaff resource binding is invalid")
    _validate_expected_response(resource["expected_response"])
    prepared = _prepared_expected_responses(application_manifest)[resource["resource_id"]]
    if (
        resource["expected_response"]["status"] != prepared["status"]
        or resource["expected_response"]["body_bytes"] != prepared["bytes"]
        or resource["expected_response"]["body_sha256"] != prepared["body_sha256"]
    ):
        raise ValueError("qualified chaff response differs from prepared identity")
    response_runs = resource["response_runs"]
    prefix_runs = resource["prefix_pack_runs"]
    if (
        not isinstance(response_runs, list)
        or len(response_runs) != QUALIFICATION_RUNS
        or not isinstance(prefix_runs, list)
        or len(prefix_runs) != QUALIFICATION_RUNS
    ):
        raise ValueError("qualified chaff resource requires exactly three response and prefix runs")
    prior_end = -1
    invocation_ids: set[str] = set()
    response_identities: list[tuple[int, str, int, str]] = []
    response_sizes: list[int] = []
    for index, run in enumerate(response_runs):
        record = _exact_mapping(run, RESPONSE_RUN_KEYS, "response qualification run")
        receipt = record["receipt"]
        expected_object_sha = qualification_digest(
            "qcsd-chaff-response-receipt-object-v2", [receipt]
        )
        if record["run_index"] != index or record["receipt_object_sha256"] != expected_object_sha:
            raise ValueError("response qualification run binding is invalid")
        identity, size, started, ended, invocation_id = _validate_response_receipt(
            receipt,
            application_manifest_sha256=application_manifest_sha256,
            application_resource_id=prefix_spec["application_resource_id"],
            selected_chaff_resource_id=resource["resource_id"],
            qualified_parallel_chaff_streams=qualified_parallel,
            url=resource["url"],
            headers=resource["headers"],
        )
        if (
            invocation_id in invocation_ids
            or started <= prior_end
            or _receipt_neqo_provenance(receipt) != dict(neqo_provenance)
        ):
            raise ValueError("response qualifications are not independent invocations")
        invocation_ids.add(invocation_id)
        prior_end = ended
        response_identities.append(identity)
        response_sizes.append(size)
    expected_response = resource["expected_response"]
    expected_identity = (
        expected_response["status"],
        expected_response["content_encoding"],
        expected_response["body_bytes"],
        expected_response["body_sha256"],
    )
    if set(response_identities) != {expected_identity} or set(response_sizes) != {
        resource["request_stream_bytes"]
    }:
        raise ValueError("response qualification identity is inconsistent")
    expected_response_digest = qualification_digest(
        "qcsd-chaff-response-qualification-v2", response_runs
    )
    if resource["response_qualification_sha256"] != expected_response_digest:
        raise ValueError("response qualification aggregate SHA-256 mismatch")
    expected_runtime_sha256 = sha256_bytes(canonical_bytes(runtime_manifest(application_manifest)))
    expected_core = derive_chaff_core(
        application_manifest_sha256=application_manifest_sha256,
        base_resource=base_resource,
        headers=resource["headers"],
        request_stream_bytes=resource["request_stream_bytes"],
        expected_response=resource["expected_response"],
        response_qualification_sha256=expected_response_digest,
        application_resource_id=prefix_spec["application_resource_id"],
        selected_chaff_resource_id=prefix_spec["selected_chaff_resource_id"],
        qualified_parallel_chaff_streams=qualified_parallel,
        walkie_talkie_required_chaff_streams=prefix_spec["required_chaff_streams"],
    )
    expected_core_sha256 = sha256_bytes(canonical_bytes(expected_core))
    for index, run in enumerate(prefix_runs):
        record = _exact_mapping(run, PREFIX_RUN_KEYS, "prefix-pack qualification run")
        receipt = record["receipt"]
        if (
            record["run_index"] != index
            or record["receipt_object_sha256"]
            != qualification_digest("qcsd-chaff-prefix-pack-receipt-object-v2", [receipt])
            or not isinstance(receipt, Mapping)
            or receipt.get("artifact_type") != PREFIX_ARTIFACT_TYPE
            or receipt.get("passed") is not True
        ):
            raise ValueError("prefix-pack qualification run binding is invalid")
        started, ended, invocation_id = _validate_prefix_receipt(
            receipt,
            application_manifest_sha256=application_manifest_sha256,
            runtime_manifest_sha256=expected_runtime_sha256,
            chaff_core_sha256=expected_core_sha256,
            resource_id=resource["resource_id"],
            request_stream_bytes=resource["request_stream_bytes"],
            prefix_spec=prefix_spec,
            prefix_spec_sha256=prefix_spec_sha256,
        )
        if (
            invocation_id in invocation_ids
            or started <= prior_end
            or _receipt_neqo_provenance(receipt) != dict(neqo_provenance)
        ):
            raise ValueError("prefix-pack qualifications are not independent invocations")
        invocation_ids.add(invocation_id)
        prior_end = ended
    expected_prefix_digest = qualification_digest(
        "qcsd-chaff-prefix-pack-qualification-v2", prefix_runs
    )
    if resource["prefix_pack_qualification_sha256"] != expected_prefix_digest:
        raise ValueError("prefix-pack qualification aggregate SHA-256 mismatch")
    return dict(resource)


def _validate_expected_response(value: object) -> None:
    response = _exact_mapping(value, EXPECTED_RESPONSE_KEYS, "qualified response")
    if (
        type(response["status"]) is not int
        or not 200 <= response["status"] <= 299
        or not isinstance(response["content_encoding"], str)
        or response["content_encoding"] != _normalize_content_encoding(response["content_encoding"])
        or type(response["body_bytes"]) is not int
        or response["body_bytes"] < UDP_PAYLOAD_CEILING
        or not _digest(response["body_sha256"])
    ):
        raise ValueError("qualified chaff expected response identity is invalid")


def _validate_prefix_receipt(
    value: object,
    *,
    application_manifest_sha256: str,
    runtime_manifest_sha256: str,
    chaff_core_sha256: str,
    resource_id: int,
    request_stream_bytes: int,
    prefix_spec: Mapping[str, Any],
    prefix_spec_sha256: str,
) -> tuple[int, int, str]:
    """Validate one every-component staged schema-two prefix proof."""

    receipt = _exact_mapping(value, PREFIX_RECEIPT_KEYS, "prefix-pack qualification receipt")
    scalar_bindings = {
        "application_resource_id": prefix_spec["application_resource_id"],
        "selected_chaff_resource_id": prefix_spec["selected_chaff_resource_id"],
        "selected_chaff_body_bytes": prefix_spec["selected_chaff_body_bytes"],
        "required_chaff_streams": prefix_spec["required_chaff_streams"],
        "packet_size": prefix_spec["packet_size"],
        "max_stream_data_excess": prefix_spec["max_stream_data_excess"],
        "maximum_receiver_continuation_reserve_horizon": prefix_spec[
            "maximum_receiver_continuation_reserve_horizon"
        ],
        "required_chaff_survivors": prefix_spec["required_chaff_survivors"],
    }
    if (
        receipt["schema_version"] != QUALIFICATION_SCHEMA_VERSION
        or receipt["artifact_type"] != PREFIX_ARTIFACT_TYPE
        or receipt["application_workload_source_sha256"] != application_manifest_sha256
        or receipt["runtime_workload_sha256"] != runtime_manifest_sha256
        or receipt["chaff_core_sha256"] != chaff_core_sha256
        or receipt["prefix_pack_spec_sha256"] != prefix_spec_sha256
        or receipt["workload_id"] != prefix_spec["workload_id"]
        or receipt["numeric_profile_sha256"] != prefix_spec["numeric_profile_sha256"]
        or receipt["source_walkie_talkie_artifact_sha256"]
        != prefix_spec["source_walkie_talkie_artifact_sha256"]
        or any(type(receipt[key]) is not int for key in scalar_bindings)
        or any(receipt[key] != expected for key, expected in scalar_bindings.items())
        or resource_id != prefix_spec["selected_chaff_resource_id"]
        or receipt["connection_count"] != 1
        or receipt["peer_settings_received"] is not True
        or receipt["warmup_stream_output_drained"] is not True
        or receipt["post_slot_pending_required_prefix_stream_send"] is not False
        or type(receipt["post_slot_pending_stream_send"]) is not bool
        or type(receipt["qpack_decoder_stream_id"]) is not int
        or receipt["qpack_decoder_stream_id"] < 0
        or type(receipt["qpack_decoder_handler_pending"]) is not bool
        or type(receipt["qpack_decoder_transport_pending"]) is not bool
        or receipt["targetless_stream_bytes"] != 0
        or receipt["allowed_pending_late_chaff_request_orders"] != []
        or receipt["allowed_pending_late_chaff_stream_ids"] != []
        or receipt["completion_status"] != "complete"
        or receipt["error"] is not None
        or receipt["passed"] is not True
        or type(receipt["started_unix_ns"]) is not int
        or type(receipt["ended_unix_ns"]) is not int
        or receipt["ended_unix_ns"] <= receipt["started_unix_ns"]
        or not isinstance(receipt["invocation_id"], str)
        or not receipt["invocation_id"].strip()
        or receipt["invocation_id"] != receipt["invocation_id"].strip()
    ):
        raise ValueError("prefix-pack qualification receipt binding is invalid")
    _validate_receipt_neqo_provenance(receipt, label="prefix-pack qualification")

    specifications = prefix_spec["stream_activation_stages"]
    stage_receipts = receipt["activation_stage_receipts"]
    scheduled = receipt["scheduled_target_slot_ids"]
    satisfied = receipt["satisfied_target_slot_ids"]
    if (
        not isinstance(stage_receipts, list)
        or len(stage_receipts) != len(specifications)
        or not isinstance(scheduled, list)
        or not isinstance(satisfied, list)
        or any(type(item) is not int or item < 0 for item in [*scheduled, *satisfied])
        or scheduled != sorted(set(scheduled))
        or satisfied != scheduled
        or len(scheduled) != sum(stage["exact_target_cells"] for stage in specifications)
    ):
        raise ValueError("prefix-pack staged target evidence is invalid")
    stage_slots: set[int] = set()
    stage_application_orders: dict[tuple[int, int], int] = {}
    for stage_index, (value_stage, specification) in enumerate(
        zip(stage_receipts, specifications, strict=True)
    ):
        stage = _exact_mapping(
            value_stage, PREFIX_STAGE_RECEIPT_KEYS, "prefix activation-stage receipt"
        )
        slots = stage["target_slot_ids"]
        application_ids = specification["application_resource_ids"]
        if (
            stage["stage_index"] != stage_index
            or stage["component_index"] != specification["component_index"]
            or stage["application_resource_ids"] != application_ids
            or not isinstance(stage["application_request_orders"], list)
            or not isinstance(stage["application_stream_ids"], list)
            or len(stage["application_request_orders"]) != len(application_ids)
            or len(stage["application_stream_ids"]) != len(application_ids)
            or not isinstance(slots, list)
            or slots != sorted(set(slots))
            or any(type(item) is not int or item < 0 or item in stage_slots for item in slots)
            or len(slots) != specification["exact_target_cells"]
            or stage["exact_target_cells"] != specification["exact_target_cells"]
            or stage["scheduled_target_bytes"]
            != specification["exact_target_cells"] * UDP_PAYLOAD_CEILING
            or stage["required_active_chaff_streams"]
            != specification["required_active_chaff_streams"]
            or stage["newly_required_chaff_streams"]
            != specification["newly_required_chaff_streams"]
            or stage["peer_acknowledged_active_chaff_streams"]
            != specification["required_active_chaff_streams"]
            or not isinstance(stage["newly_peer_acknowledged_request_orders"], list)
            or len(stage["newly_peer_acknowledged_request_orders"])
            != specification["newly_required_chaff_streams"]
            or not isinstance(stage["newly_peer_acknowledged_stream_ids"], list)
            or len(stage["newly_peer_acknowledged_stream_ids"])
            != specification["newly_required_chaff_streams"]
            or not isinstance(stage["allowed_pending_chaff_request_orders"], list)
            or len(stage["allowed_pending_chaff_request_orders"])
            != prefix_spec["required_chaff_streams"]
            - specification["required_active_chaff_streams"]
            or not isinstance(stage["allowed_pending_chaff_stream_ids"], list)
            or len(stage["allowed_pending_chaff_stream_ids"])
            != prefix_spec["required_chaff_streams"]
            - specification["required_active_chaff_streams"]
            or stage["targetless_stream_bytes_at_gate"] != 0
            or stage["pending_required_prefix_stream_send"] is not False
            or stage["passed"] is not True
        ):
            raise ValueError("prefix-pack activation-stage receipt is invalid")
        stage_slots.update(slots)
        for resource, order in zip(
            application_ids, stage["application_request_orders"], strict=True
        ):
            if type(order) is not int or order < 0:
                raise ValueError("prefix-pack application request order is invalid")
            stage_application_orders[(stage_index, resource)] = order
    if stage_slots != set(scheduled):
        raise ValueError("prefix-pack stage slots differ from the exact scheduled targets")

    streams = receipt["streams"]
    total_application = sum(len(stage["application_resource_ids"]) for stage in specifications)
    expected_stream_count = total_application + prefix_spec["required_chaff_streams"]
    if (
        not isinstance(streams, list)
        or len(streams) != expected_stream_count
        or receipt["requests_opened"] != expected_stream_count
    ):
        raise ValueError("prefix-pack qualification stream evidence is incomplete")
    parsed_streams = [
        _exact_mapping(stream, PREFIX_STREAM_KEYS, "prefix stream") for stream in streams
    ]
    transmissions = receipt["stream_transmissions"]
    if not isinstance(transmissions, list) or not transmissions:
        raise ValueError("prefix-pack post-cutoff transcript is empty")
    parsed_transmissions: list[dict[str, Any]] = []
    for sequence, row in enumerate(transmissions):
        transmission = _exact_mapping(row, PREFIX_TRANSMISSION_KEYS, "STREAM transmission")
        if (
            transmission["sequence"] != sequence
            or transmission["slot"] not in stage_slots
            or type(transmission["stream"]) is not int
            or transmission["stream"] < 0
            or type(transmission["offset"]) is not int
            or transmission["offset"] < 0
            or type(transmission["bytes"]) is not int
            or transmission["bytes"] < 0
            or type(transmission["fin"]) is not bool
            or (transmission["bytes"] == 0 and transmission["fin"] is not True)
        ):
            raise ValueError("prefix-pack transcript contains invalid STREAM data")
        parsed_transmissions.append(transmission)
    stream_ids: set[int] = set()
    chaff_request_ids: set[int] = set()
    for order, stream in enumerate(parsed_streams):
        stage_index = stream["opening_stage_index"]
        if (
            stream["request_order"] != order
            or type(stage_index) is not int
            or not 0 <= stage_index < len(specifications)
            or type(stream["stream_id"]) is not int
            or stream["stream_id"] < 0
            or stream["stream_id"] in stream_ids
        ):
            raise ValueError("prefix-pack request identity or order is invalid")
        stream_ids.add(stream["stream_id"])
        if stream["role"] == "application":
            expected_order = stage_application_orders.get((stage_index, stream["resource_id"]))
            if (
                expected_order != order
                or stream["request_id"] is not None
                or stream["qualified_request_stream_bytes"] is not None
            ):
                raise ValueError("prefix-pack application stream binding is invalid")
            expected_transport_role: object = "application"
            expected_size = None
        elif stream["role"] == "chaff":
            request_id = stream["request_id"]
            if (
                stream["resource_id"] != resource_id
                or stage_index != 0
                or type(request_id) is not int
                or request_id < 0
                or request_id in chaff_request_ids
                or stream["qualified_request_stream_bytes"] != request_stream_bytes
            ):
                raise ValueError("prefix-pack chaff stream binding is invalid")
            chaff_request_ids.add(request_id)
            expected_transport_role = {
                "chaff": {"resource_id": resource_id, "request_id": request_id}
            }
            expected_size = request_stream_bytes
        else:
            raise ValueError("prefix-pack stream role is invalid")
        stream_transmissions = [
            row for row in parsed_transmissions if row["stream"] == stream["stream_id"]
        ]
        if any(row["role"] != expected_transport_role for row in stream_transmissions):
            raise ValueError("prefix-pack transport role binding is invalid")
        _validate_prefix_stream(
            stream,
            transmissions=stream_transmissions,
            request_stream_bytes=expected_size,
            require_complete_transmission=True,
            require_ack=stream["role"] == "chaff",
        )
    if chaff_request_ids != set(range(prefix_spec["required_chaff_streams"])):
        raise ValueError("prefix-pack chaff request cohort is incomplete")
    chaff_by_request_id = {
        stream["request_id"]: stream for stream in parsed_streams if stream["role"] == "chaff"
    }
    for stage_index, (value_stage, specification) in enumerate(
        zip(stage_receipts, specifications, strict=True)
    ):
        active = specification["required_active_chaff_streams"]
        newly = specification["newly_required_chaff_streams"]
        first_new = active - newly
        expected_new = [chaff_by_request_id[index] for index in range(first_new, active)]
        expected_pending = [
            chaff_by_request_id[index]
            for index in range(active, prefix_spec["required_chaff_streams"])
        ]
        expected_application = [
            stream
            for resource_id in specification["application_resource_ids"]
            for stream in parsed_streams
            if stream["role"] == "application"
            and stream["opening_stage_index"] == stage_index
            and stream["resource_id"] == resource_id
        ]
        if (
            len(expected_application) != len(specification["application_resource_ids"])
            or value_stage["application_request_orders"]
            != [stream["request_order"] for stream in expected_application]
            or value_stage["application_stream_ids"]
            != [stream["stream_id"] for stream in expected_application]
            or value_stage["newly_peer_acknowledged_request_orders"]
            != [stream["request_order"] for stream in expected_new]
            or value_stage["newly_peer_acknowledged_stream_ids"]
            != [stream["stream_id"] for stream in expected_new]
            or value_stage["allowed_pending_chaff_request_orders"]
            != [stream["request_order"] for stream in expected_pending]
            or value_stage["allowed_pending_chaff_stream_ids"]
            != [stream["stream_id"] for stream in expected_pending]
        ):
            raise ValueError("prefix-pack staged chaff acknowledgement scope is invalid")
    if any(
        row["stream"] not in stream_ids and row["role"] is not None for row in parsed_transmissions
    ):
        raise ValueError("prefix-pack unregistered STREAM has a request role")
    if type(receipt["packet_cutoff_sequence"]) is not int or receipt["packet_cutoff_sequence"] < 0:
        raise ValueError("prefix-pack packet cutoff is invalid")
    observations = receipt["packet_observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError("prefix-pack packet transcript is missing")
    ordered = []
    for index, row in enumerate(observations):
        observation = _exact_mapping(row, PACKET_OBSERVATION_KEYS, "prefix packet observation")
        if (
            observation["sequence"] != index
            or observation["phase"] not in {"warmup", "qualification"}
            or observation["direction"] not in {"incoming", "outgoing"}
            or type(observation["udp_payload_bytes"]) is not int
            or not 1 <= observation["udp_payload_bytes"] <= UDP_PAYLOAD_CEILING
        ):
            raise ValueError("prefix-pack packet transcript is invalid")
        ordered.append(
            {
                "sequence": observation["sequence"],
                "phase": observation["phase"],
                "direction": observation["direction"],
                "udp_payload_bytes": observation["udp_payload_bytes"],
            }
        )
    if receipt["packet_log_sha256"] != sha256_bytes(
        json.dumps(ordered, separators=(",", ":")).encode()
    ):
        raise ValueError("prefix-pack packet transcript hash is invalid")
    qualification_outgoing = [
        item
        for item in ordered
        if item["phase"] == "qualification" and item["direction"] == "outgoing"
    ]
    if (
        not qualification_outgoing
        or sum(item["udp_payload_bytes"] == UDP_PAYLOAD_CEILING for item in qualification_outgoing)
        < len(scheduled)
        or any(
            (item["sequence"] < receipt["packet_cutoff_sequence"]) != (item["phase"] == "warmup")
            for item in ordered
        )
    ):
        raise ValueError("prefix-pack packet target/cutoff evidence is invalid")
    _validate_udp_statistics(receipt["packets"], observations=ordered)
    return receipt["started_unix_ns"], receipt["ended_unix_ns"], receipt["invocation_id"]


def _validate_prefix_stream(
    value: Mapping[str, Any],
    *,
    transmissions: Sequence[Mapping[str, Any]],
    request_stream_bytes: int | None,
    require_complete_transmission: bool,
    require_ack: bool,
) -> None:
    size = value["request_stream_bytes"]
    if (
        type(size) is not int
        or size <= 0
        or (request_stream_bytes is not None and size != request_stream_bytes)
    ):
        raise ValueError("prefix-pack request size is invalid")
    transmitted_ranges = _merge_offset_size_ranges(
        [(row["offset"], row["bytes"]) for row in transmissions]
    )
    transmitted_fin = any(row["fin"] for row in transmissions)
    recorded_transmitted = _exact_range_array(value["transmitted_unique_ranges"])
    if (
        recorded_transmitted != transmitted_ranges
        or type(value["transmitted_unique_bytes"]) is not int
        or value["transmitted_unique_bytes"] != _range_bytes(transmitted_ranges)
        or value["fin_transmitted"] is not transmitted_fin
    ):
        raise ValueError("prefix-pack transmitted STREAM aggregate is inconsistent")
    if require_complete_transmission and (
        transmitted_ranges != [(0, size)] or transmitted_fin is not True
    ):
        raise ValueError("prefix-pack request bytes are not fully transmitted")
    acknowledgements = value["acknowledgements"]
    if not isinstance(acknowledgements, list):
        raise ValueError("prefix-pack acknowledgements are malformed")
    parsed_acknowledgements: list[dict[str, Any]] = []
    prior_sequence = -1
    for acknowledgement in acknowledgements:
        record = _exact_mapping(acknowledgement, PREFIX_ACK_KEYS, "prefix acknowledgement")
        if (
            type(record["sequence"]) is not int
            or record["sequence"] <= prior_sequence
            or type(record["offset"]) is not int
            or record["offset"] < 0
            or type(record["bytes"]) is not int
            or record["bytes"] < 0
            or type(record["fin"]) is not bool
            or (record["bytes"] == 0 and record["fin"] is not True)
        ):
            raise ValueError("prefix-pack acknowledgement is invalid")
        prior_sequence = record["sequence"]
        parsed_acknowledgements.append(record)
    acknowledged_ranges = _merge_offset_size_ranges(
        [(row["offset"], row["bytes"]) for row in parsed_acknowledgements]
    )
    acknowledged_fin = any(row["fin"] for row in parsed_acknowledgements)
    recorded_acknowledged = _exact_range_array(value["acknowledged_unique_ranges"])
    if (
        recorded_acknowledged != acknowledged_ranges
        or type(value["acknowledged_unique_bytes"]) is not int
        or value["acknowledged_unique_bytes"] != _range_bytes(acknowledged_ranges)
        or value["fin_acknowledged"] is not acknowledged_fin
    ):
        raise ValueError("prefix-pack acknowledged STREAM aggregate is inconsistent")
    if require_ack and (acknowledged_fin is not True or acknowledged_ranges != [(0, size)]):
        raise ValueError("prefix-pack chaff request was not peer-acknowledged through FIN")


def _exact_range_array(value: object) -> list[tuple[int, int]]:
    if not isinstance(value, list):
        raise ValueError("prefix-pack range array is malformed")
    intervals: list[tuple[int, int]] = []
    for row in value:
        if (
            not isinstance(row, list)
            or len(row) != 2
            or type(row[0]) is not int
            or type(row[1]) is not int
            or row[0] < 0
            or row[1] <= row[0]
        ):
            raise ValueError("prefix-pack range array is malformed")
        intervals.append((row[0], row[1]))
    if intervals != sorted(intervals) or any(
        current[0] <= prior[1] for prior, current in zip(intervals, intervals[1:])
    ):
        raise ValueError("prefix-pack range array is not canonical")
    return intervals


def _merge_offset_size_ranges(value: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    intervals = sorted((offset, offset + size) for offset, size in value if size > 0)
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        elif end > merged[-1][1]:
            merged[-1] = (merged[-1][0], end)
    return merged


def _range_bytes(value: Sequence[tuple[int, int]]) -> int:
    return sum(end - start for start, end in value)


def _normalize_content_encoding(value: str) -> str:
    normalized = value.strip().lower()
    return normalized if normalized else "identity"


def _validate_policy(
    value: object,
    *,
    qualified_parallel_chaff_streams: int,
    walkie_talkie_required_chaff_streams: int,
) -> None:
    policy = _exact_mapping(value, POLICY_KEYS, "chaff qualification policy")
    if policy != {
        "response_runs": QUALIFICATION_RUNS,
        "parallel_response_requests": qualified_parallel_chaff_streams,
        "qualified_parallel_chaff_streams": qualified_parallel_chaff_streams,
        "walkie_talkie_required_chaff_streams": walkie_talkie_required_chaff_streams,
        "prefix_pack_runs": QUALIFICATION_RUNS,
        "profile": "research-1200",
        "response_defense": "none",
        "seed": 0,
        "udp_payload_ceiling": UDP_PAYLOAD_CEILING,
        "max_stream_data_excess": MAX_STREAM_DATA_EXCESS,
        "separate_chaff_namespace": True,
    }:
        raise ValueError("chaff qualification policy is not the exact research policy")


def _validate_response_only_policy(value: object) -> None:
    policy = _exact_mapping(
        value,
        RESPONSE_ONLY_POLICY_KEYS,
        "response-only chaff qualification policy",
    )
    integer_fields = (
        "response_runs",
        "parallel_response_requests",
        "qualified_parallel_chaff_streams",
        "seed",
        "udp_payload_ceiling",
        "max_response_bytes",
    )
    if (
        any(type(policy[field]) is not int for field in integer_fields)
        or policy["separate_chaff_namespace"] is not True
        or policy
        != {
            "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
            "response_runs": QUALIFICATION_RUNS,
            "parallel_response_requests": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            "profile": "research-1200",
            "response_defense": "none",
            "seed": 0,
            "udp_payload_ceiling": UDP_PAYLOAD_CEILING,
            "max_response_bytes": 1_048_576,
            "separate_chaff_namespace": True,
        }
    ):
        raise ValueError(
            "response-only chaff qualification policy is not the exact research policy"
        )


def response_only_v2_qualification_policy() -> dict[str, Any]:
    """Return the exact sustained response-only v2 acquisition primitive."""

    return {
        "qualification_scope": RESPONSE_ONLY_QUALIFICATION_SCOPE,
        "connection_epochs_per_candidate": QUALIFICATION_RUNS,
        "waves_per_connection_epoch": RESPONSE_ONLY_WAVES_PER_EPOCH,
        "parallel_requests_per_wave": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        "total_requests_per_connection_epoch": RESPONSE_ONLY_REQUESTS_PER_EPOCH,
        "total_completions_per_candidate": RESPONSE_ONLY_COMPLETIONS_PER_CANDIDATE,
        "connection_epoch_spacing_seconds": RESPONSE_ONLY_EPOCH_SPACING_SECONDS,
        "inter_wave_spacing_milliseconds": RESPONSE_ONLY_WAVE_SPACING_MILLISECONDS,
        "qualified_parallel_chaff_streams": RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
        "profile": "research-1200",
        "response_defense": "none",
        "seed": 0,
        "udp_payload_ceiling": UDP_PAYLOAD_CEILING,
        "max_response_bytes": 1_048_576,
        "separate_chaff_namespace": True,
    }


def _validate_response_only_v2_policy(value: object) -> None:
    policy = _exact_mapping(
        value,
        RESPONSE_ONLY_V2_POLICY_KEYS,
        "response-only v2 chaff qualification policy",
    )
    integer_fields = RESPONSE_ONLY_V2_POLICY_KEYS - {
        "qualification_scope",
        "profile",
        "response_defense",
        "separate_chaff_namespace",
    }
    if (
        any(type(policy[field]) is not int for field in integer_fields)
        or policy["separate_chaff_namespace"] is not True
        or dict(policy) != response_only_v2_qualification_policy()
    ):
        raise ValueError("response-only v2 qualification policy is not the exact sustained policy")


def _validate_response_only_request_header_primitive(value: object) -> None:
    primitive = _exact_mapping(
        value, REQUEST_HEADER_PRIMITIVE_KEYS, "response-only request-header primitive"
    )
    if dict(primitive) != response_only_request_header_primitive():
        raise ValueError("response-only request-header primitive is not exact")


def _validate_source(value: object, image: object) -> None:
    source = _exact_mapping(value, SOURCE_METADATA_KEYS, "qualification source")
    if (
        source["lab_dirty"] is not False
        or source["neqo_dirty"] is not False
        or source["lab_patch_sha256"] != EMPTY_SHA256
        or source["neqo_patch_sha256"] != EMPTY_SHA256
        or not isinstance(source["image_digest"], str)
        or not _IMAGE_DIGEST.fullmatch(source["image_digest"])
        or image != source["image_digest"]
        or any(
            not isinstance(source[key], str) or not _COMMIT.fullmatch(source[key])
            for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit")
        )
        or source["neqo_commit"] != source["neqo_pinned_commit"]
    ):
        raise ValueError("chaff qualification requires clean concrete source/image provenance")


def _validate_neqo_provenance(value: object, *, qualification_source: Mapping[str, Any]) -> None:
    receipt = _exact_mapping(value, set(NEQO_PROVENANCE_KEYS), "Neqo qualification provenance")
    version = receipt["neqo_version"]
    if (
        not isinstance(version, str)
        or not version.strip()
        or version != version.strip()
        or any(
            not isinstance(receipt[key], str) or not _COMMIT.fullmatch(receipt[key])
            for key in ("neqo_base_commit", "published_qcsd_commit", "migration_commit")
        )
    ):
        raise ValueError("Neqo qualification provenance is invalid")
    if receipt["migration_commit"] != qualification_source.get("neqo_commit"):
        raise ValueError("Neqo qualification provenance does not match the clean source commit")


def _validate_implementation_receipt(value: object, *, require_current: bool) -> None:
    receipt = _exact_mapping(value, IMPLEMENTATION_KEYS, "qualification implementation receipt")
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != IMPLEMENTATION_RECEIPT_SCHEMA_VERSION
        or receipt["artifact_type"] != "qcsd-chaff-qualification-implementation"
        or receipt["domain"] != "qcsd-chaff-qualification-implementation-v1"
        or not _digest(receipt["sha256"])
    ):
        raise ValueError("qualification implementation receipt is invalid")
    source = _exact_mapping(receipt["source"], SOURCE_METADATA_KEYS, "image source receipt")
    files = receipt["source_files"]
    if (
        not isinstance(files, Mapping)
        or set(files) != set(IMPLEMENTATION_FILES)
        or any(not _digest(item) for item in files.values())
    ):
        raise ValueError("qualification implementation file receipt is invalid")
    if (
        source["lab_dirty"] is not False
        or source["neqo_dirty"] is not False
        or source["lab_patch_sha256"] != EMPTY_SHA256
        or source["neqo_patch_sha256"] != EMPTY_SHA256
        or (
            source["image_digest"] is not None
            and (
                not isinstance(source["image_digest"], str)
                or not _IMAGE_DIGEST.fullmatch(source["image_digest"])
            )
        )
        or any(
            not isinstance(source[key], str) or not _COMMIT.fullmatch(source[key])
            for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit")
        )
        or source["neqo_commit"] != source["neqo_pinned_commit"]
    ):
        raise ValueError("qualification image source receipt is not clean and pinned")
    modules = receipt["installed_modules"]
    if not isinstance(modules, Mapping) or set(modules) != set(IMPLEMENTATION_PYTHON_FILES):
        raise ValueError("qualification installed-module receipt is incomplete")
    for relative, value in modules.items():
        installed = _exact_mapping(value, {"path", "sha256"}, "installed module receipt")
        if (
            not isinstance(installed["path"], str)
            or not installed["path"].startswith("/")
            or installed["sha256"] != files[relative]
        ):
            raise ValueError("qualification installed module differs from its source")
    for key in ("installed_entrypoint", "neqo_qcsd_client"):
        executable = _exact_mapping(receipt[key], {"path", "sha256"}, key)
        if not isinstance(executable["path"], str) or not _digest(executable["sha256"]):
            raise ValueError(f"qualification {key} receipt is invalid")
    if receipt["sha256"] != _implementation_aggregate(receipt):
        raise ValueError("qualification implementation aggregate SHA-256 mismatch")
    if require_current:
        if dict(files) != _implementation_source_files():
            raise ValueError("qualification source files have changed since qualification")
        current = implementation_receipt(executed_image=True)
        if _implementation_runtime_identity(current) != _implementation_runtime_identity(receipt):
            raise ValueError("qualification executables have changed since qualification")


def _implementation_runtime_identity(receipt: Mapping[str, Any]) -> dict[str, Any]:
    source = receipt["source"]
    return {
        "schema_version": receipt["schema_version"],
        "artifact_type": receipt["artifact_type"],
        "domain": receipt["domain"],
        "source_files": receipt["source_files"],
        "installed_modules": receipt["installed_modules"],
        "installed_entrypoint": receipt["installed_entrypoint"],
        "neqo_qcsd_client": receipt["neqo_qcsd_client"],
        "neqo_source": {
            key: source[key]
            for key in (
                "neqo_commit",
                "neqo_pinned_commit",
                "neqo_dirty",
                "neqo_patch_sha256",
            )
        },
    }


def _source_execution_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in SOURCE_METADATA_KEYS if key != "image_digest"}


def _validate_nontraining_receipts(
    fitting: object,
    schema_five_diagnostic: object,
    schema_six_capacity_diagnostic: object,
    schema_six_runtime_diagnostic: object,
    schema_two_sender_framing_diagnostic: object,
) -> None:
    source = _exact_mapping(fitting, FITTING_SOURCE_KEYS, "fitting source receipt")
    if (
        not _digest(source["evidence_sha256"])
        or not _digest(source["experiment_sha256"])
        or source["samples_consumed"] != 120
        or source["qualification_bytes_excluded"] is not True
    ):
        raise ValueError("fitting source receipt is invalid")
    record = _exact_mapping(
        schema_five_diagnostic, DIAGNOSTIC_KEYS, "schema-five diagnostic receipt"
    )
    if (
        record["campaign"] != "research-smoke-1200"
        or not _digest(record["evidence_sha256"])
        or not _digest(record["experiment_sha256"])
        or record["status"] != "incomplete"
        or (record["planned"], record["accepted"], record["eligible"], record["failed"])
        != (14, 12, 12, 2)
        or record["role"] != "schema-five-prefix-capacity-falsification-diagnostic"
        or record["qualification_bytes_excluded"] is not True
    ):
        raise ValueError("schema-five diagnostic receipt is invalid")
    _validate_schema_six_capacity_falsification_diagnostic_receipt(schema_six_capacity_diagnostic)
    _validate_schema_six_runtime_falsification_diagnostic_receipt(schema_six_runtime_diagnostic)
    _validate_schema_two_sender_framing_falsification_diagnostic_receipt(
        schema_two_sender_framing_diagnostic
    )


def _validate_schema_six_capacity_falsification_diagnostic_receipt(value: object) -> None:
    current = _exact_mapping(
        value,
        SCHEMA_SIX_CAPACITY_DIAGNOSTIC_KEYS,
        "schema-six capacity falsification diagnostic receipt",
    )
    if (
        any(
            type(current[field]) is not int
            for field in ("planned", "accepted", "eligible", "failed", "attempts")
        )
        or any(
            type(current[field]) is not str
            for field in (
                "campaign",
                "evidence_sha256",
                "experiment_sha256",
                "status",
                "failed_workload_id",
                "failed_defense",
                "role",
            )
        )
        or current["qualification_bytes_excluded"] is not True
        or current != _schema_six_capacity_falsification_diagnostic_receipt()
    ):
        raise ValueError("schema-six capacity falsification diagnostic receipt is invalid")


def _validate_schema_six_runtime_falsification_diagnostic_receipt(value: object) -> None:
    """Require the exact sealed q7 runtime-falsification archive receipt."""

    current = _exact_mapping(
        value,
        SCHEMA_SIX_RUNTIME_FALSIFICATION_DIAGNOSTIC_KEYS,
        "schema-six runtime falsification diagnostic receipt",
    )
    terminal_failures = current["terminal_failures"]
    recovered_retries = current["recovered_retries"]
    if (
        any(
            type(current[field]) is not int
            for field in ("planned", "accepted", "eligible", "failed")
        )
        or any(
            type(current[field]) is not str
            for field in (
                "archive_manifest_path",
                "archive_manifest_sha256",
                "campaign",
                "evidence_sha256",
                "experiment_sha256",
                "status",
                "role",
            )
        )
        or any(
            not _digest(current[field])
            for field in (
                "archive_manifest_sha256",
                "evidence_sha256",
                "experiment_sha256",
            )
        )
        or current["qualification_bytes_excluded"] is not True
        or not isinstance(terminal_failures, list)
        or not isinstance(recovered_retries, list)
    ):
        raise ValueError("schema-six runtime falsification diagnostic receipt is invalid")
    parsed_failures = [
        _exact_mapping(
            record,
            SCHEMA_SIX_RUNTIME_TERMINAL_FAILURE_KEYS,
            "schema-six runtime terminal failure",
        )
        for record in terminal_failures
    ]
    parsed_retries = [
        _exact_mapping(
            record,
            SCHEMA_SIX_RUNTIME_RECOVERED_RETRY_KEYS,
            "schema-six runtime recovered retry",
        )
        for record in recovered_retries
    ]
    if (
        any(
            any(type(record[field]) is not str for field in ("workload_id", "defense", "stage"))
            or type(record["attempts"]) is not int
            for record in parsed_failures
        )
        or any(
            any(type(record[field]) is not str for field in ("workload_id", "defense"))
            or type(record["failed_attempts"]) is not int
            or type(record["accepted_attempt"]) is not int
            for record in parsed_retries
        )
        or current != _schema_six_runtime_falsification_diagnostic_receipt()
    ):
        raise ValueError("schema-six runtime falsification diagnostic receipt is invalid")


def _validate_schema_two_sender_framing_falsification_diagnostic_receipt(
    value: object,
) -> None:
    sender_framing = _exact_mapping(
        value,
        SCHEMA_TWO_SENDER_FRAMING_DIAGNOSTIC_KEYS,
        "schema-two sender-framing falsification diagnostic receipt",
    )
    if (
        type(sender_framing["failed_run_index"]) is not int
        or any(
            type(sender_framing[field]) is not str
            for field in (
                "archive_manifest_sha256",
                "failed_workload_id",
                "failed_phase",
                "receipt_sha256",
                "packets_sha256",
                "log_sha256",
                "role",
            )
        )
        or any(
            not _digest(sender_framing[field])
            for field in (
                "archive_manifest_sha256",
                "receipt_sha256",
                "packets_sha256",
                "log_sha256",
            )
        )
        or sender_framing["qualification_bytes_excluded"] is not True
        or sender_framing != _schema_two_sender_framing_falsification_diagnostic_receipt()
    ):
        raise ValueError("schema-two sender-framing falsification diagnostic receipt is invalid")


def _validate_udp_statistics(
    value: object, *, observations: Sequence[Mapping[str, Any]] | None = None
) -> None:
    statistics = _exact_mapping(value, {"incoming", "outgoing", "total"}, "UDP statistics")
    parsed: dict[str, Mapping[str, Any]] = {}
    keys = {"packet_count", "observed_udp_payload_max", "oversized_packet_count"}
    for direction in ("incoming", "outgoing", "total"):
        record = _exact_mapping(statistics[direction], keys, "UDP statistic")
        if (
            any(type(record[key]) is not int or record[key] < 0 for key in keys)
            or record["packet_count"] < 1
            or not 1 <= record["observed_udp_payload_max"] <= UDP_PAYLOAD_CEILING
            or record["oversized_packet_count"] != 0
        ):
            raise ValueError("UDP qualification statistic is invalid")
        parsed[direction] = record
    if (
        parsed["total"]["packet_count"]
        != parsed["incoming"]["packet_count"] + parsed["outgoing"]["packet_count"]
    ):
        raise ValueError("UDP qualification packet counts disagree")
    if parsed["total"]["observed_udp_payload_max"] != max(
        parsed["incoming"]["observed_udp_payload_max"],
        parsed["outgoing"]["observed_udp_payload_max"],
    ):
        raise ValueError("UDP qualification maxima disagree")
    if observations is not None:
        for direction in ("incoming", "outgoing"):
            sizes = [
                item["udp_payload_bytes"] for item in observations if item["direction"] == direction
            ]
            if (
                parsed[direction]["packet_count"] != len(sizes)
                or parsed[direction]["observed_udp_payload_max"] != max(sizes, default=0)
                or parsed[direction]["oversized_packet_count"]
                != sum(size > UDP_PAYLOAD_CEILING for size in sizes)
            ):
                raise ValueError("UDP qualification statistics disagree with packet evidence")


def _receipt_neqo_provenance(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return _validate_receipt_neqo_provenance(receipt, label="qualification")


def _validate_receipt_neqo_provenance(receipt: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    source = _exact_mapping(
        receipt.get("source"),
        set(NEQO_PROVENANCE_KEYS) - {"neqo_version"},
        f"{label} source",
    )
    version = receipt.get("neqo_version")
    if (
        not isinstance(version, str)
        or not version.strip()
        or version != version.strip()
        or any(
            not isinstance(value, str) or not _COMMIT.fullmatch(value) for value in source.values()
        )
    ):
        raise ValueError(f"{label} source is invalid")
    return {"neqo_version": version, **source}


def _stable_neqo_provenance(runs: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    values = _receipt_neqo_provenance(runs[0])
    if any(not isinstance(value, str) or not value for value in values.values()):
        raise PreparationError("qualification evidence is missing Neqo provenance")
    for run in runs[1:]:
        observed = _receipt_neqo_provenance(run)
        if observed != values:
            raise PreparationError("Neqo provenance changed across qualification runs")
    return values  # type: ignore[return-value]


def _fitting_source_receipt() -> dict[str, Any]:
    return {
        "evidence_sha256": "655895ce7fe7259566f14d7099c6cb20719c2989a59e8296fe1d79703c058233",
        "experiment_sha256": "ac16442c46cbc8e44aecba14fb59e096fe9fcb07d4508391af2a0b649faea1cc",
        "samples_consumed": 120,
        "qualification_bytes_excluded": True,
    }


def _schema_five_diagnostic_receipt() -> dict[str, Any]:
    return {
        "campaign": "research-smoke-1200",
        "evidence_sha256": "161de34c5b8a6eda1b4eb82e2925735805cd18bec167e25c0dc2d2a6e79c7214",
        "experiment_sha256": "42e3721522f9c97a920eae17a4cf6945fd93a738367f95b4431b9d2e95e6beb9",
        "status": "incomplete",
        "planned": 14,
        "accepted": 12,
        "eligible": 12,
        "failed": 2,
        "role": "schema-five-prefix-capacity-falsification-diagnostic",
        "qualification_bytes_excluded": True,
    }


def _schema_six_capacity_falsification_diagnostic_receipt() -> dict[str, Any]:
    """Bind the sealed current-contract smoke that falsified the old capacity model."""

    return {
        "campaign": "research-smoke-1200",
        "evidence_sha256": "edbf1fa5dc0fb7b013a2d08a1c4c57a06a521dbfc6008bce36aa3b11d3b0119b",
        "experiment_sha256": "1c11072189fd79e4b4a1927bc096803d69403907efa3ceaf258399dec3beadd9",
        "status": "incomplete",
        "planned": 14,
        "accepted": 13,
        "eligible": 13,
        "failed": 1,
        "failed_workload_id": "cloudflare-quiche-r3",
        "failed_defense": "walkie-talkie",
        "attempts": 3,
        "role": "schema-six-walkie-talkie-capacity-falsification-diagnostic",
        "qualification_bytes_excluded": True,
    }


def _schema_six_runtime_falsification_diagnostic_receipt() -> dict[str, Any]:
    """Bind the sealed q7 smoke and its exact terminal/recovered outcomes."""

    return {
        "archive_manifest_path": (
            "results/chaff-qualification-diagnostics/"
            "q7-b19cb04-7ebcdb0-schema6-203eee42-runtime-falsification/MANIFEST.sha256"
        ),
        "archive_manifest_sha256": (
            "4ee68a930a344dc0e5874279e09069f92935a2f4f42bc7bb7e88077153b85aa9"
        ),
        "campaign": "research-smoke-1200",
        "evidence_sha256": "2b2bd50d0949ea216eb1badb8b6d702ef9eb487556b5b3f3fd7ab133a1c073fc",
        "experiment_sha256": ("ee124b7c0b2d9e022d25bd2107d0f25ec19de2987309d62e217dbdae2e15354e"),
        "status": "incomplete",
        "planned": 14,
        "accepted": 12,
        "eligible": 12,
        "failed": 2,
        "terminal_failures": [
            {
                "workload_id": "cloudflare-quiche-r3",
                "defense": "walkie-talkie",
                "stage": "runner",
                "attempts": 3,
            },
            {
                "workload_id": "bootstrap-introduction-r3",
                "defense": "front",
                "stage": "capture",
                "attempts": 3,
            },
        ],
        "recovered_retries": [
            {
                "workload_id": "bootstrap-introduction-r3",
                "defense": "walkie-talkie",
                "failed_attempts": 2,
                "accepted_attempt": 3,
            },
            {
                "workload_id": "bootstrap-introduction-r3",
                "defense": "traffic-morphing",
                "failed_attempts": 1,
                "accepted_attempt": 2,
            },
        ],
        "role": "schema-six-runtime-falsification-diagnostic",
        "qualification_bytes_excluded": True,
    }


def _schema_two_sender_framing_falsification_diagnostic_receipt() -> dict[str, Any]:
    """Bind the failed prefix proof that exposed missing sender framing capacity."""

    return {
        "archive_manifest_sha256": (
            "c40d4d9e629d701438ca93b232eb7173814b9e1cec79314e49477e9329076b73"
        ),
        "failed_workload_id": "nghttp2-ngtcp2-r3",
        "failed_phase": "prefix-pack",
        "failed_run_index": 0,
        "receipt_sha256": "6ee69445b84db197c6602a02f6c91d566d28087aa33f36f1d27df5e7b748d354",
        "packets_sha256": "1b18dd574295061115a55b6c31045fd557aa137d7768f1149e9931e594e093c1",
        "log_sha256": "4de19185892585e194779c35c8125300588f178bc5f80fda02f5749523269b09",
        "role": "schema-two-sender-framing-falsification-diagnostic",
        "qualification_bytes_excluded": True,
    }


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{label} has an invalid exact schema")
    return dict(value)


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None
