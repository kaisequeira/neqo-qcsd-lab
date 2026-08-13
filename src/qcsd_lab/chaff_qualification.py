"""Immutable qualification evidence for the distinct compact chaff substrate.

The application workload is never rewritten.  A qualification sidecar binds its
exact bytes, proves one compact navigation-root representation, and derives the
separate manifest accepted by the production chaff namespace.
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

SCHEMA_VERSION = 1
SIDECAR_ARTIFACT_TYPE = "qcsd-chaff-qualification"
CORE_ARTIFACT_TYPE = "qcsd-qualified-chaff-core"
MANIFEST_ARTIFACT_TYPE = "qcsd-qualified-chaff-manifest"
PREFIX_SPEC_ARTIFACT_TYPE = "qcsd-walkie-talkie-prefix-pack-spec"
RESPONSE_ARTIFACT_TYPE = "qcsd-chaff-response-qualification"
PREFIX_ARTIFACT_TYPE = "qcsd-chaff-prefix-pack-qualification"
HEADER_PROJECTION = ("accept", "accept-encoding", "accept-language")
SELECTION_POLICY = "qualified-navigation-root-only-v1"
METHOD = "GET"
QUALIFICATION_RUNS = 3
PARALLEL_RESPONSE_REQUESTS = 5
UDP_PAYLOAD_CEILING = 1_200
MAX_STREAM_DATA_EXCESS = 1_000
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
    "selected_base_resource_id",
    "header_projection",
    "method",
    "qualification_policy",
    "qualification_source",
    "qualification_image_digest",
    "neqo_provenance",
    "implementation_receipt",
    "fitting_source",
    "schema_five_diagnostic",
    "prefix_pack_spec",
    "resource",
}
BASE_MANIFEST_KEYS = {"path", "sha256"}
POLICY_KEYS = {
    "response_runs",
    "parallel_response_requests",
    "prefix_pack_runs",
    "profile",
    "response_defense",
    "seed",
    "udp_payload_ceiling",
    "max_stream_data_excess",
    "separate_chaff_namespace",
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
EXPECTED_RESPONSE_KEYS = {"status", "content_encoding", "body_bytes", "body_sha256"}
RESPONSE_RUN_KEYS = {
    "run_index",
    "receipt_object_sha256",
    "receipt",
}
PREFIX_RUN_KEYS = {"run_index", "receipt_object_sha256", "receipt"}
RESPONSE_RECEIPT_KEYS = {
    "schema_version",
    "artifact_type",
    "invocation_id",
    "neqo_version",
    "application_workload_sha256",
    "application_resource_id",
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
    "workload_id",
    "numeric_profile_sha256",
    "source_walkie_talkie_artifact_sha256",
    "packet_size",
    "max_stream_data_excess",
    "maximum_receiver_continuation_reserve_horizon",
    "required_chaff_survivors",
    "max_chaff_streams",
    "connection_count",
    "peer_settings_received",
    "warmup_stream_output_drained",
    "packet_cutoff_sequence",
    "requests_opened_before_first_target",
    "scheduled_target",
    "streams",
    "stream_transmissions",
    "packet_observations",
    "packet_log_sha256",
    "packets",
    "post_slot_pending_stream_send",
    "post_slot_pending_required_stream_send",
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
PREFIX_TARGET_KEYS = {
    "slot_id",
    "direction",
    "udp_payload_bytes",
    "scheduled_datagrams",
    "scheduled_bytes",
    "satisfied_datagrams",
    "satisfied_bytes",
}
PREFIX_STREAM_KEYS = {
    "request_order",
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


@dataclass(frozen=True)
class QualifiedChaffInput:
    """A validated sidecar and its deterministic final runtime manifest."""

    sidecar_path: Path
    sidecar_sha256: str
    manifest: dict[str, Any]
    manifest_sha256: str
    application_manifest_sha256: str


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
        "schema_version": SCHEMA_VERSION,
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


def prefix_pack_spec(
    workload_id: str,
    walkie_talkie: Mapping[str, Any],
    *,
    source_walkie_talkie_artifact_sha256: str,
) -> dict[str, Any]:
    """Project the acyclic numeric WT input consumed by the prefix qualifier."""

    profile = _walkie_profile(walkie_talkie, workload_id)
    bursts = profile.get("bursts")
    packet_size = walkie_talkie.get("packet_size")
    if packet_size != UDP_PAYLOAD_CEILING or not isinstance(bursts, list) or not bursts:
        raise ValueError("Walkie-Talkie prefix-pack source has an invalid numeric profile")
    numeric = {
        "packet_size": packet_size,
        "bursts": [
            {"outgoing": burst.get("outgoing"), "incoming": burst.get("incoming")}
            for burst in bursts
            if isinstance(burst, Mapping)
        ],
    }
    if len(numeric["bursts"]) != len(bursts) or any(
        type(burst[direction]) is not int or burst[direction] < 0
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
        "numeric_profile": numeric,
    }


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
    maximum = 0
    for index, burst in enumerate(bursts):
        if burst["incoming"] == 0:
            continue
        horizon = 0
        for offset, candidate in enumerate(bursts[index:]):
            if offset > 0 and candidate["outgoing"] > 0:
                break
            horizon += int(candidate["incoming"] > 0)
        maximum = max(maximum, horizon)
    return maximum


def validate_prefix_pack_spec(
    value: object,
    *,
    workload_id: str | None = None,
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
        if any(type(record[key]) is not int or record[key] < 0 for key in record):
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
        or not 1 <= spec["required_chaff_survivors"] <= 5
    ):
        raise ValueError("prefix-pack specification numeric derivation is invalid")
    return dict(spec)


def derive_prefix_pack_specs(
    *,
    source_path: Path | None = None,
    destination_root: Path | None = None,
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
        os.path.abspath(destination_root or LAB_ROOT / "config/chaff-prefix-specs")
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
            spec = prefix_pack_spec(
                workload_id,
                artifact,
                source_walkie_talkie_artifact_sha256=source_sha256,
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
        or sidecar["selected_base_resource_id"] != 0
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
    root = selected_navigation_root(base, workload_id)
    _validate_policy(sidecar["qualification_policy"])
    _validate_source(sidecar["qualification_source"], sidecar["qualification_image_digest"])
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
    _validate_implementation_receipt(
        sidecar["implementation_receipt"], require_current=require_current_implementation
    )
    _validate_nontraining_receipts(sidecar["fitting_source"], sidecar["schema_five_diagnostic"])
    spec_receipt = _exact_mapping(sidecar["prefix_pack_spec"], {"path", "sha256"}, "prefix spec")
    if Path(str(spec_receipt["path"])).name != prefix_spec_path.name or spec_receipt[
        "sha256"
    ] != sha256_file(prefix_spec_path):
        raise ValueError("chaff qualification prefix-pack specification mismatch")
    prefix_spec = validate_prefix_pack_spec(load_json(prefix_spec_path), workload_id=workload_id)
    resource = _validate_resource_receipt(
        sidecar["resource"],
        root,
        application_manifest_sha256=base_receipt["sha256"],
        application_manifest=base,
        prefix_spec=prefix_spec,
        prefix_spec_sha256=spec_receipt["sha256"],
        neqo_provenance=sidecar["neqo_provenance"],
    )
    manifest = derive_chaff_manifest(sidecar, root, resource)
    return QualifiedChaffInput(
        sidecar_path=Path(),
        sidecar_sha256=sha256_bytes(canonical_bytes(dict(sidecar))),
        manifest=manifest,
        manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
        application_manifest_sha256=sha256_file(base_manifest_path),
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
    )


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
        "application_resource_id": base_resource["id"],
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
) -> dict[str, Any]:
    body_bytes = expected_response["body_bytes"]
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": CORE_ARTIFACT_TYPE,
        "application_workload_sha256": application_manifest_sha256,
        "application_resource_id": base_resource["id"],
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
                    "expected_response": dict(expected_response),
                    "response_qualification_sha256": response_qualification_sha256,
                },
            }
        ],
    }


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
        prefix_spec_root or LAB_ROOT / "config/chaff-prefix-specs", "prefix-spec root"
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
    root = selected_navigation_root(base, workload_id)
    headers = project_compact_headers(root)
    validate_prefix_pack_spec(load_json(spec_path), workload_id=workload_id)
    base_sha = sha256_file(base_path)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{workload_id}-qualification-evidence-", dir=destination_root)
    )
    completed = False
    try:
        response_runs = _run_response_qualifications(
            base_path,
            temporary,
            neqo_client=neqo_client,
            neqo_client_sha256=neqo_client_sha256,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
        )
        expected_response, request_stream_bytes = _stable_response_identity(
            response_runs,
            application_manifest_sha256=base_sha,
            resource_id=root["id"],
            url=root["url"],
            headers=headers,
        )
        response_records = [
            _response_run_record(index, value) for index, value in enumerate(response_runs)
        ]
        response_digest = qualification_digest(
            "qcsd-chaff-response-qualification-v1", response_records
        )
        core = derive_chaff_core(
            application_manifest_sha256=base_sha,
            base_resource=root,
            headers=headers,
            request_stream_bytes=request_stream_bytes,
            expected_response=expected_response,
            response_qualification_sha256=response_digest,
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
            "qcsd-chaff-prefix-pack-qualification-v1", prefix_records
        )
        neqo = _stable_neqo_provenance([*response_runs, *prefix_runs])
        sidecar = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": SIDECAR_ARTIFACT_TYPE,
            "workload_id": workload_id,
            "base_manifest": {"path": base_path.name, "sha256": base_sha},
            "selection_policy": SELECTION_POLICY,
            "selected_base_resource_id": root["id"],
            "header_projection": list(HEADER_PROJECTION),
            "method": METHOD,
            "qualification_policy": {
                "response_runs": QUALIFICATION_RUNS,
                "parallel_response_requests": PARALLEL_RESPONSE_REQUESTS,
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
            "prefix_pack_spec": {"path": spec_path.name, "sha256": sha256_file(spec_path)},
            "resource": {
                "resource_id": root["id"],
                "url": root["url"],
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
    destination = store / "v1"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"{destination} already exists; batch qualification is create-only")
    stale = sorted(store.glob(".v1.qcsd-batch-*"))
    if stale:
        raise ValueError("qualification store contains a stale unpublished batch")
    workloads = _regular_directory_without_symlinks(
        workload_root or LAB_ROOT / "config/workloads", "workload root"
    )
    specs = _regular_directory_without_symlinks(
        prefix_spec_root or LAB_ROOT / "config/chaff-prefix-specs", "prefix-spec root"
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
        selected_navigation_root(manifest, workload_id)
        observed_spec = validate_prefix_pack_spec(load_json(spec), workload_id=workload_id)
        expected_spec = prefix_pack_spec(
            workload_id,
            oracle,
            source_walkie_talkie_artifact_sha256=SOURCE_WALKIE_TALKIE_SHA256,
        )
        if canonical_bytes(observed_spec) != canonical_bytes(expected_spec):
            raise ValueError(
                "prefix-pack specification differs from the sealed schema-five numeric oracle"
            )
        input_hashes[workload] = sha256_file(workload)
        input_hashes[spec] = sha256_file(spec)
    execution_context = _qualification_execution_context()
    candidate = Path(tempfile.mkdtemp(prefix=".v1.qcsd-batch-", dir=store))
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
        # the publication boundary so v1 can only name the preflight cohort.
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
        # canonical v1 which is deliberately rejected on the next invocation.
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
                "--output-dir",
                str(output),
                "--timeout-seconds",
                str(timeout_seconds),
                "--max-response-bytes",
                "1048576",
                "--packet-size",
                str(UDP_PAYLOAD_CEILING),
                "--parallel-requests",
                str(PARALLEL_RESPONSE_REQUESTS),
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
    resource_id: int,
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
                resource_id=resource_id,
                url=url,
                headers=headers,
            )
        except ValueError as error:
            raise PreparationError(str(error)) from error
        if invocation_id in invocation_ids or started <= prior_end:
            raise PreparationError("response qualifications are not independent invocations")
        invocation_ids.add(invocation_id)
        prior_end = ended
        identities.extend([identity] * PARALLEL_RESPONSE_REQUESTS)
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
            "qcsd-chaff-response-receipt-object-v1", [receipt]
        ),
        "receipt": receipt,
    }


def _validate_response_receipt(
    value: object,
    *,
    application_manifest_sha256: str,
    resource_id: int,
    url: str,
    headers: list[list[str]],
) -> tuple[tuple[int, str, int, str], int, int, int, str]:
    receipt = _exact_mapping(value, RESPONSE_RECEIPT_KEYS, "response qualification receipt")
    started = receipt["started_unix_ns"]
    ended = receipt["ended_unix_ns"]
    invocation_id = receipt["invocation_id"]
    if (
        receipt["schema_version"] != SCHEMA_VERSION
        or receipt["artifact_type"] != RESPONSE_ARTIFACT_TYPE
        or receipt["application_workload_sha256"] != application_manifest_sha256
        or receipt["application_resource_id"] != resource_id
        or receipt["method"] != METHOD
        or receipt["url"] != url
        or receipt["request_headers"] != headers
        or receipt["parallel_requests"] != PARALLEL_RESPONSE_REQUESTS
        or receipt["connection_count"] != 1
        or receipt["requests_opened_before_first_network_output"] != PARALLEL_RESPONSE_REQUESTS
        or receipt["max_response_bytes"] != 1_048_576
        or receipt["udp_payload_ceiling"] != UDP_PAYLOAD_CEILING
        or type(started) is not int
        or type(ended) is not int
        or started < 0
        or ended <= started
        or not isinstance(invocation_id, str)
        or not invocation_id
        or receipt["completion_status"] != "complete"
        or receipt["error"] is not None
        or receipt["passed"] is not True
    ):
        raise ValueError("response qualification receipt binding is invalid")
    source = _exact_mapping(
        receipt["source"], set(NEQO_PROVENANCE_KEYS) - {"neqo_version"}, "response source"
    )
    if any(not isinstance(item, str) or not item for item in source.values()) or (
        receipt["neqo_version"] is None
        or not isinstance(receipt["neqo_version"], str)
        or not receipt["neqo_version"]
    ):
        raise ValueError("response qualification source is invalid")
    requests = receipt["requests"]
    if not isinstance(requests, list) or len(requests) != PARALLEL_RESPONSE_REQUESTS:
        raise ValueError("response qualification requires five requests")
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
            request["request_index"] != index
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
    qualification_output = False
    for sequence, value_observation in enumerate(observations):
        observation = _exact_mapping(
            value_observation, PACKET_OBSERVATION_KEYS, "response packet observation"
        )
        if (
            observation["sequence"] != sequence
            or observation["phase"] not in {"handshake", "qualification"}
            or observation["direction"] not in {"incoming", "outgoing"}
            or type(observation["udp_payload_bytes"]) is not int
            or not 1 <= observation["udp_payload_bytes"] <= UDP_PAYLOAD_CEILING
        ):
            raise ValueError("response qualification packet transcript is invalid")
        qualification_output |= (
            observation["phase"] == "qualification" and observation["direction"] == "outgoing"
        )
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
    if receipt["packet_log_sha256"] != sha256_bytes(packet_log) or not qualification_output:
        raise ValueError("response qualification packet transcript hash is invalid")
    _validate_udp_statistics(receipt["packets"], observations=rust_ordered)
    return identities[0], sizes[0], started, ended, invocation_id


def _prefix_run_record(index: int, run: Mapping[str, Any]) -> dict[str, Any]:
    receipt = dict(run)
    if receipt.get("artifact_type") != PREFIX_ARTIFACT_TYPE or receipt.get("passed") is not True:
        raise PreparationError("chaff prefix-pack qualification did not pass")
    return {
        "run_index": index,
        "receipt_object_sha256": qualification_digest(
            "qcsd-chaff-prefix-pack-receipt-object-v1", [receipt]
        ),
        "receipt": receipt,
    }


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
    if (
        resource["resource_id"] != base_resource.get("id")
        or resource["url"] != base_resource.get("url")
        or resource["headers"] != project_compact_headers(base_resource)
        or type(resource["request_stream_bytes"]) is not int
        or resource["request_stream_bytes"] <= 0
    ):
        raise ValueError("qualified chaff resource binding is invalid")
    _validate_expected_response(resource["expected_response"])
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
            "qcsd-chaff-response-receipt-object-v1", [receipt]
        )
        if record["run_index"] != index or record["receipt_object_sha256"] != expected_object_sha:
            raise ValueError("response qualification run binding is invalid")
        identity, size, started, ended, invocation_id = _validate_response_receipt(
            receipt,
            application_manifest_sha256=application_manifest_sha256,
            resource_id=resource["resource_id"],
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
        "qcsd-chaff-response-qualification-v1", response_runs
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
    )
    expected_core_sha256 = sha256_bytes(canonical_bytes(expected_core))
    for index, run in enumerate(prefix_runs):
        record = _exact_mapping(run, PREFIX_RUN_KEYS, "prefix-pack qualification run")
        receipt = record["receipt"]
        if (
            record["run_index"] != index
            or record["receipt_object_sha256"]
            != qualification_digest("qcsd-chaff-prefix-pack-receipt-object-v1", [receipt])
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
        "qcsd-chaff-prefix-pack-qualification-v1", prefix_runs
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
    """Validate the stable prefix binding; transcript validation is schema-locked below."""

    receipt = _exact_mapping(value, PREFIX_RECEIPT_KEYS, "prefix-pack qualification receipt")
    if (
        receipt["schema_version"] != SCHEMA_VERSION
        or receipt["artifact_type"] != PREFIX_ARTIFACT_TYPE
        or receipt["application_workload_source_sha256"] != application_manifest_sha256
        or receipt["application_resource_id"] != resource_id
        or receipt["runtime_workload_sha256"] != runtime_manifest_sha256
        or receipt["chaff_core_sha256"] != chaff_core_sha256
        or receipt["prefix_pack_spec_sha256"] != prefix_spec_sha256
        or receipt["numeric_profile_sha256"] != prefix_spec["numeric_profile_sha256"]
        or receipt["source_walkie_talkie_artifact_sha256"]
        != prefix_spec["source_walkie_talkie_artifact_sha256"]
        or receipt["workload_id"] != prefix_spec["workload_id"]
        or receipt["packet_size"] != prefix_spec["packet_size"]
        or receipt["max_stream_data_excess"] != prefix_spec["max_stream_data_excess"]
        or receipt["maximum_receiver_continuation_reserve_horizon"]
        != prefix_spec["maximum_receiver_continuation_reserve_horizon"]
        or receipt["required_chaff_survivors"] != prefix_spec["required_chaff_survivors"]
        or any(
            type(receipt[key]) is not int
            for key in (
                "schema_version",
                "application_resource_id",
                "packet_size",
                "max_stream_data_excess",
                "maximum_receiver_continuation_reserve_horizon",
                "required_chaff_survivors",
                "max_chaff_streams",
                "connection_count",
                "packet_cutoff_sequence",
                "requests_opened_before_first_target",
                "targetless_stream_bytes",
                "started_unix_ns",
                "ended_unix_ns",
            )
        )
        or receipt["max_chaff_streams"] != 5
        or receipt["connection_count"] != 1
        or receipt["peer_settings_received"] is not True
        or receipt["warmup_stream_output_drained"] is not True
        or receipt["requests_opened_before_first_target"] != 6
        or type(receipt["post_slot_pending_stream_send"]) is not bool
        or receipt["post_slot_pending_required_stream_send"] is not False
        or receipt["targetless_stream_bytes"] != 0
        or receipt["completion_status"] != "complete"
        or receipt["error"] is not None
        or receipt["passed"] is not True
        or type(receipt["started_unix_ns"]) is not int
        or type(receipt["ended_unix_ns"]) is not int
        or receipt["ended_unix_ns"] <= receipt["started_unix_ns"]
        or not isinstance(receipt["invocation_id"], str)
        or not receipt["invocation_id"]
    ):
        raise ValueError("prefix-pack qualification receipt binding is invalid")
    source = _exact_mapping(
        receipt["source"], set(NEQO_PROVENANCE_KEYS) - {"neqo_version"}, "prefix source"
    )
    if (
        not isinstance(receipt["neqo_version"], str)
        or not receipt["neqo_version"]
        or any(not isinstance(item, str) or not item for item in source.values())
    ):
        raise ValueError("prefix-pack qualification source is invalid")
    target = _exact_mapping(receipt["scheduled_target"], PREFIX_TARGET_KEYS, "prefix target")
    if (
        type(target["slot_id"]) is not int
        or target["slot_id"] < 0
        or target["direction"] != "outgoing"
        or any(
            type(target[key]) is not int
            for key in (
                "udp_payload_bytes",
                "scheduled_datagrams",
                "scheduled_bytes",
                "satisfied_datagrams",
                "satisfied_bytes",
            )
        )
        or target["udp_payload_bytes"] != UDP_PAYLOAD_CEILING
        or target["scheduled_datagrams"] != 1
        or target["scheduled_bytes"] != UDP_PAYLOAD_CEILING
        or target["satisfied_datagrams"] != 1
        or target["satisfied_bytes"] != UDP_PAYLOAD_CEILING
    ):
        raise ValueError("prefix-pack target is invalid")
    streams = receipt["streams"]
    if not isinstance(streams, list) or len(streams) != 6:
        raise ValueError("prefix-pack qualification stream evidence is incomplete")
    parsed_streams = [
        _exact_mapping(stream, PREFIX_STREAM_KEYS, "prefix stream") for stream in streams
    ]
    slot_id = target["slot_id"]
    transmissions = receipt["stream_transmissions"]
    if not isinstance(transmissions, list) or not transmissions:
        raise ValueError("prefix-pack post-cutoff transcript is empty")
    parsed_transmissions: list[dict[str, Any]] = []
    for sequence, row in enumerate(transmissions):
        transmission = _exact_mapping(row, PREFIX_TRANSMISSION_KEYS, "STREAM transmission")
        if (
            transmission["sequence"] != sequence
            or transmission["slot"] != slot_id
            or type(transmission["stream"]) is not int
            or transmission["stream"] < 0
            or type(transmission["offset"]) is not int
            or transmission["offset"] < 0
            or type(transmission["bytes"]) is not int
            or transmission["bytes"] < 0
            or type(transmission["fin"]) is not bool
            or (transmission["bytes"] == 0 and transmission["fin"] is not True)
        ):
            raise ValueError("prefix-pack transcript contains invalid or targetless STREAM data")
        parsed_transmissions.append(transmission)
    if receipt["packet_cutoff_sequence"] < 0:
        raise ValueError("prefix-pack packet cutoff is invalid")
    stream_ids: set[int] = set()
    required = prefix_spec["required_chaff_survivors"]
    for order, stream in enumerate(parsed_streams):
        expected_role = "application" if order == 0 else "chaff"
        expected_request_id = None if order == 0 else order - 1
        expected_qualified = None if order == 0 else request_stream_bytes
        if (
            type(stream["request_order"]) is not int
            or stream["request_order"] != order
            or stream["role"] != expected_role
            or type(stream["resource_id"]) is not int
            or stream["resource_id"] != resource_id
            or (stream["request_id"] is not None and type(stream["request_id"]) is not int)
            or stream["request_id"] != expected_request_id
            or (
                stream["qualified_request_stream_bytes"] is not None
                and type(stream["qualified_request_stream_bytes"]) is not int
            )
            or stream["qualified_request_stream_bytes"] != expected_qualified
            or type(stream["stream_id"]) is not int
            or stream["stream_id"] < 0
            or stream["stream_id"] in stream_ids
        ):
            raise ValueError("prefix-pack request identity or order is invalid")
        stream_ids.add(stream["stream_id"])
        stream_transmissions = [
            row for row in parsed_transmissions if row["stream"] == stream["stream_id"]
        ]
        expected_transport_role: object = (
            "application"
            if order == 0
            else {"chaff": {"resource_id": resource_id, "request_id": order - 1}}
        )
        if any(row["role"] != expected_transport_role for row in stream_transmissions):
            raise ValueError("prefix-pack transport role binding is invalid")
        _validate_prefix_stream(
            stream,
            transmissions=stream_transmissions,
            request_stream_bytes=None if order == 0 else request_stream_bytes,
            require_complete_transmission=order == 0 or order <= required,
            require_ack=0 < order <= required,
        )
    expected_late_orders = list(range(required + 1, 6))
    expected_late_stream_ids = [
        parsed_streams[order]["stream_id"] for order in expected_late_orders
    ]
    if (
        receipt["allowed_pending_late_chaff_request_orders"] != expected_late_orders
        or receipt["allowed_pending_late_chaff_stream_ids"] != expected_late_stream_ids
        or any(type(item) is not int for item in expected_late_stream_ids)
    ):
        raise ValueError("prefix-pack allowed late-chaff pending scope is invalid")
    if any(
        row["stream"] not in stream_ids and row["role"] is not None for row in parsed_transmissions
    ):
        raise ValueError("prefix-pack unregistered STREAM has a request role")
    if (
        sum(row["bytes"] for row in parsed_transmissions if row["slot"] != slot_id)
        != receipt["targetless_stream_bytes"]
    ):
        raise ValueError("prefix-pack targetless STREAM byte total is inconsistent")
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
        or qualification_outgoing[0]["udp_payload_bytes"] != UDP_PAYLOAD_CEILING
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


def _validate_policy(value: object) -> None:
    policy = _exact_mapping(value, POLICY_KEYS, "chaff qualification policy")
    if policy != {
        "response_runs": QUALIFICATION_RUNS,
        "parallel_response_requests": PARALLEL_RESPONSE_REQUESTS,
        "prefix_pack_runs": QUALIFICATION_RUNS,
        "profile": "research-1200",
        "response_defense": "none",
        "seed": 0,
        "udp_payload_ceiling": UDP_PAYLOAD_CEILING,
        "max_stream_data_excess": MAX_STREAM_DATA_EXCESS,
        "separate_chaff_namespace": True,
    }:
        raise ValueError("chaff qualification policy is not the exact research policy")


def _validate_source(value: object, image: object) -> None:
    source = _exact_mapping(value, SOURCE_METADATA_KEYS, "qualification source")
    if (
        source["lab_dirty"] is not False
        or source["neqo_dirty"] is not False
        or source["lab_patch_sha256"] != EMPTY_SHA256
        or source["neqo_patch_sha256"] != EMPTY_SHA256
        or not _IMAGE_DIGEST.fullmatch(str(source["image_digest"]))
        or image != source["image_digest"]
        or any(
            not _COMMIT.fullmatch(str(source[key]))
            for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit")
        )
        or source["neqo_commit"] != source["neqo_pinned_commit"]
    ):
        raise ValueError("chaff qualification requires clean concrete source/image provenance")


def _validate_neqo_provenance(value: object, *, qualification_source: Mapping[str, Any]) -> None:
    receipt = _exact_mapping(value, set(NEQO_PROVENANCE_KEYS), "Neqo qualification provenance")
    if any(not isinstance(receipt[key], str) or not receipt[key] for key in NEQO_PROVENANCE_KEYS):
        raise ValueError("Neqo qualification provenance is invalid")
    if receipt["migration_commit"] != qualification_source.get("neqo_commit"):
        raise ValueError("Neqo qualification provenance does not match the clean source commit")


def _validate_implementation_receipt(value: object, *, require_current: bool) -> None:
    receipt = _exact_mapping(value, IMPLEMENTATION_KEYS, "qualification implementation receipt")
    if (
        receipt["schema_version"] != SCHEMA_VERSION
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


def _validate_nontraining_receipts(fitting: object, diagnostic: object) -> None:
    source = _exact_mapping(fitting, FITTING_SOURCE_KEYS, "fitting source receipt")
    if (
        not _digest(source["evidence_sha256"])
        or not _digest(source["experiment_sha256"])
        or source["samples_consumed"] != 120
        or source["qualification_bytes_excluded"] is not True
    ):
        raise ValueError("fitting source receipt is invalid")
    record = _exact_mapping(diagnostic, DIAGNOSTIC_KEYS, "schema-five diagnostic receipt")
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
    source = _exact_mapping(
        receipt.get("source"),
        set(NEQO_PROVENANCE_KEYS) - {"neqo_version"},
        "qualification source",
    )
    return {"neqo_version": receipt.get("neqo_version"), **source}


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


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{label} has an invalid exact schema")
    return dict(value)


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None
