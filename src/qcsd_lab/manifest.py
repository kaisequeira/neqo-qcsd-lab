from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .util import SOURCE_METADATA_KEYS, sha256_bytes

SENSITIVE = {"authorization", "cookie", "cookie2", "proxy-authorization"}
CONNECTION_SPECIFIC = {
    "connection",
    "host",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
}
CONDITIONAL = {
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "range",
}
MANIFEST_KEYS = {"preparation", "resources", "replay"}
RESOURCE_KEYS = {
    "id",
    "url",
    "type",
    "content_length",
    "data_length",
    "chaff_priority",
    "known_valid",
    "depends_on",
    "headers",
}
REPLAY_KEYS = {
    "source_url",
    "final_url",
    "chromium_version",
    "settle_ms",
    "observed_request_count",
    "observed_origins",
    "reviewed_origins",
    "exclusions",
    "response_stability",
}
PREPARATION_KEYS = {
    "source_url",
    "final_url",
    "chromium_version",
    "settle_ms",
    "observed_request_count",
    "observed_origins",
    "approved_origins",
    "exclusions",
    "max_response_bytes",
    "timeout_seconds",
    "stability_runs",
    "stability_profile",
    "stability_defense",
    "stability_seed",
    "neqo_version",
    "neqo_base_commit",
    "published_qcsd_commit",
    "migration_commit",
    "expected_responses",
    "lab_source",
    "prepare_image_digest",
}
EXPECTED_RESPONSE_KEYS = {"resource_id", "status", "bytes", "body_sha256"}
U32_MAX = 2**32 - 1
U64_MAX = 2**64 - 1
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
RESEARCH_MAX_RESPONSE_BYTES = 1_048_576
RESEARCH_PREPARATION_REQUIRED = (
    "requires a workload produced by ./qcsd-lab prepare with research-grade provenance"
)


def https_origin(value: str) -> str | None:
    """Return the canonical endpoint origin used by Neqo for an HTTPS URL."""

    parts = urlsplit(value)
    if (
        parts.scheme.lower() != "https"
        or parts.hostname is None
        or parts.username is not None
        or parts.password is not None
    ):
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" if port in {None, 443} else f"https://{host}:{port}"


def safe_discovery_headers(headers: dict[str, str]) -> list[list[str]]:
    safe: list[list[str]] = []
    for raw_name, value in headers.items():
        name = raw_name.lower()
        if (
            name.startswith(":")
            or name in SENSITIVE
            or name in CONNECTION_SPECIFIC
            or name in CONDITIONAL
        ):
            continue
        if name == "te" and value.lower() != "trailers":
            continue
        if any(character in value for character in ("\0", "\r", "\n")):
            continue
        safe.append([name, value])
    safe.sort()
    return safe


def validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    unknown = set(manifest) - MANIFEST_KEYS
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ValueError(f"manifest contains unsupported fields: {names}")
    if "replay" in manifest and "preparation" in manifest:
        raise ValueError("manifest cannot contain both replay and preparation metadata")
    if "replay" in manifest:
        _validate_replay(manifest["replay"])
    resources = manifest.get("resources")
    if not isinstance(resources, list) or not resources:
        raise ValueError("manifest requires at least one resource")
    if any(not isinstance(resource, dict) for resource in resources):
        raise ValueError("manifest resources must be objects")
    ids = [resource.get("id") for resource in resources]
    if any(
        not isinstance(resource_id, int)
        or isinstance(resource_id, bool)
        or not 0 <= resource_id <= U32_MAX
        for resource_id in ids
    ) or len(set(ids)) != len(resources):
        raise ValueError("resource IDs must be integers and unique")
    id_set = set(ids)
    graph: dict[int, list[int]] = {}
    for resource in resources:
        unknown_resource = set(resource) - RESOURCE_KEYS
        if unknown_resource:
            raise ValueError(
                "manifest resource contains unsupported fields: "
                + ", ".join(sorted(unknown_resource))
            )
        resource_url = resource.get("url", "")
        if not isinstance(resource_url, str):
            raise ValueError(f"resource {resource.get('id')} URL must be a string")
        if https_origin(resource_url) is None:
            raise ValueError(f"resource {resource.get('id')} is not absolute credential-free HTTPS")
        dependencies = resource.get("depends_on", [])
        if (
            not isinstance(dependencies, list)
            or any(
                not isinstance(dependency, int)
                or isinstance(dependency, bool)
                or not 0 <= dependency <= U32_MAX
                for dependency in dependencies
            )
            or len(dependencies) != len(set(dependencies))
            or resource["id"] in dependencies
            or not set(dependencies) <= id_set
        ):
            raise ValueError(f"invalid dependencies for resource {resource['id']}")
        graph[resource["id"]] = dependencies
        _validate_resource_fields(resource)
        headers = resource.get("headers", [])
        if not isinstance(headers, list) or any(
            not isinstance(header, list)
            or len(header) != 2
            or not all(isinstance(part, str) for part in header)
            for header in headers
        ):
            raise ValueError(f"resource {resource['id']} headers must be name/value pairs")
        for raw_name, value in headers:
            name = raw_name.lower()
            if (
                not raw_name
                or not raw_name.isascii()
                or any(
                    not (character.isalnum() or character in "!#$%&'*+-.^_`|~")
                    for character in raw_name
                )
                or name.startswith(":")
                or name in SENSITIVE
                or name in CONNECTION_SPECIFIC
                or name in CONDITIONAL
                or (name == "te" and value.lower() != "trailers")
            ):
                raise ValueError(f"header {raw_name!r} cannot be stored in a workload manifest")
            if any(character in value for character in ("\0", "\r", "\n")):
                raise ValueError(f"header {raw_name!r} has an unsafe value")
    visiting: set[int] = set()
    visited: set[int] = set()

    def visit(resource_id: int) -> None:
        if resource_id in visited:
            return
        if resource_id in visiting:
            raise ValueError(f"dependency cycle at resource {resource_id}")
        visiting.add(resource_id)
        for dependency in graph[resource_id]:
            visit(dependency)
        visiting.remove(resource_id)
        visited.add(resource_id)

    for resource_id in graph:
        visit(resource_id)
    if "preparation" in manifest:
        _validate_preparation(manifest["preparation"], id_set)


def validate_research_preparation(manifest: dict[str, Any], *, workload_id: str) -> None:
    """Require the exact clean preparation policy used by research campaigns.

    General manifest validation intentionally continues to accept the small
    bare and legacy replay manifests used by smoke tests.  This additional
    gate is for fitting and evaluation only: it first applies the complete
    manifest schema (including expected-response coverage), then tightens the
    preparation and build-provenance requirements.
    """

    validate_manifest(manifest)
    preparation = manifest.get("preparation")
    if not isinstance(preparation, dict):
        raise ValueError(f"research workload {workload_id!r} {RESEARCH_PREPARATION_REQUIRED}")

    required_policy = {
        "stability_runs": 3,
        "stability_profile": "live",
        "stability_defense": "none",
        "stability_seed": 0,
        "max_response_bytes": RESEARCH_MAX_RESPONSE_BYTES,
    }
    for field, expected in required_policy.items():
        if preparation[field] != expected:
            raise ValueError(
                f"research workload {workload_id!r} preparation {field} must be {expected!r}"
            )

    source = preparation["lab_source"]
    if source["lab_dirty"] is not False or source["neqo_dirty"] is not False:
        raise ValueError(
            f"research workload {workload_id!r} requires clean lab and Neqo preparation sources"
        )
    for field in ("lab_patch_sha256", "neqo_patch_sha256"):
        if source[field] != EMPTY_SHA256:
            raise ValueError(
                f"research workload {workload_id!r} preparation {field} must be the "
                "SHA-256 of an empty patch"
            )

    commit_fields = {
        "preparation.neqo_base_commit": preparation["neqo_base_commit"],
        "preparation.published_qcsd_commit": preparation["published_qcsd_commit"],
        "preparation.lab_source.lab_commit": source["lab_commit"],
        "preparation.lab_source.neqo_commit": source["neqo_commit"],
        "preparation.lab_source.neqo_pinned_commit": source["neqo_pinned_commit"],
    }
    for field, value in commit_fields.items():
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise ValueError(
                f"research workload {workload_id!r} {field} must be a 40-character "
                "lowercase hexadecimal commit"
            )
    if source["neqo_commit"] != source["neqo_pinned_commit"]:
        raise ValueError(
            f"research workload {workload_id!r} preparation Neqo commit must equal the "
            "pinned submodule commit"
        )

    images = {
        "preparation.prepare_image_digest": preparation["prepare_image_digest"],
        "preparation.lab_source.image_digest": source["image_digest"],
    }
    for field, value in images.items():
        if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            raise ValueError(
                f"research workload {workload_id!r} {field} must be a concrete "
                "sha256:<64 lowercase hex> image digest"
            )
    if preparation["prepare_image_digest"] != source["image_digest"]:
        raise ValueError(
            f"research workload {workload_id!r} preparation image digest does not match "
            "its source provenance"
        )


def _validate_resource_fields(resource: dict[str, Any]) -> None:
    for key in ("content_length", "data_length"):
        value = resource.get(key)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= U64_MAX
        ):
            raise ValueError(f"resource {resource['id']} {key} must be a non-negative integer")
    for key in ("chaff_priority", "known_valid"):
        if key in resource and not isinstance(resource[key], bool):
            raise ValueError(f"resource {resource['id']} {key} must be boolean")
    if "type" in resource and not isinstance(resource["type"], str):
        raise ValueError(f"resource {resource['id']} type must be a string")


def _validate_preparation(value: Any, resource_ids: set[int]) -> None:
    if not isinstance(value, dict):
        raise ValueError("manifest preparation metadata must be an object")
    unknown = set(value) - PREPARATION_KEYS
    if unknown:
        raise ValueError(
            "manifest preparation metadata contains unsupported fields: "
            + ", ".join(sorted(unknown))
        )
    missing = PREPARATION_KEYS - set(value)
    if missing:
        raise ValueError(f"manifest preparation metadata is missing: {', '.join(sorted(missing))}")
    for key in ("source_url", "final_url"):
        if https_origin(str(value[key])) is None:
            raise ValueError(f"manifest preparation {key} must be absolute credential-free HTTPS")
    for key in ("observed_origins", "approved_origins"):
        origins = value[key]
        if (
            not isinstance(origins, list)
            or any(not isinstance(candidate, str) for candidate in origins)
            or len(origins) != len(set(origins))
        ):
            raise ValueError(f"manifest preparation {key} must contain unique origins")
        for candidate in origins:
            parts = urlsplit(str(candidate))
            if (
                parts.scheme != "https"
                or not parts.netloc
                or parts.username is not None
                or parts.password is not None
                or parts.path not in {"", "/"}
                or parts.query
                or parts.fragment
            ):
                raise ValueError(f"manifest preparation {key} contains an invalid HTTPS origin")
    if not set(value["approved_origins"]) <= set(value["observed_origins"]):
        raise ValueError("approved origins must be a subset of observed origins")
    positive = ("max_response_bytes", "timeout_seconds", "stability_runs")
    non_negative = ("settle_ms", "observed_request_count", "stability_seed")
    if any(
        not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 1
        for key in positive
    ) or any(
        not isinstance(value[key], int)
        or isinstance(value[key], bool)
        or not 0 <= value[key] <= U64_MAX
        for key in non_negative
    ):
        raise ValueError("manifest preparation counts are invalid")
    if value["stability_runs"] < 2:
        raise ValueError("manifest preparation requires at least two stability runs")
    for key in (
        "chromium_version",
        "prepare_image_digest",
        "stability_profile",
        "stability_defense",
        "neqo_version",
        "neqo_base_commit",
        "published_qcsd_commit",
        "migration_commit",
    ):
        if not isinstance(value[key], str) or not value[key].strip():
            raise ValueError(f"manifest preparation {key} must be a non-empty string")
    lab_source = value["lab_source"]
    if not isinstance(lab_source, dict) or set(lab_source) != SOURCE_METADATA_KEYS:
        raise ValueError("manifest preparation lab_source provenance is invalid")
    for key in ("lab_dirty", "neqo_dirty"):
        if lab_source[key] is not None and not isinstance(lab_source[key], bool):
            raise ValueError("manifest preparation lab_source provenance is invalid")
    image_digest = lab_source["image_digest"]
    if image_digest is not None and (not isinstance(image_digest, str) or not image_digest.strip()):
        raise ValueError("manifest preparation lab_source provenance is invalid")
    for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"):
        if not isinstance(lab_source[key], str) or not lab_source[key]:
            raise ValueError("manifest preparation lab_source provenance is invalid")
    for key in ("lab_patch_sha256", "neqo_patch_sha256"):
        digest = lab_source[key]
        if digest is not None and (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("manifest preparation lab_source provenance is invalid")
    exclusions = value["exclusions"]
    if not isinstance(exclusions, list) or any(
        not isinstance(item, dict)
        or set(item) != {"url", "reason"}
        or not isinstance(item["url"], str)
        or not isinstance(item["reason"], str)
        or not item["reason"].strip()
        for item in exclusions
    ):
        raise ValueError("manifest preparation exclusions require url and reason")
    responses = value["expected_responses"]
    if not isinstance(responses, list) or len(responses) != len(resource_ids):
        raise ValueError("manifest preparation requires one expected response per resource")
    response_ids: set[int] = set()
    for response in responses:
        if not isinstance(response, dict) or set(response) != EXPECTED_RESPONSE_KEYS:
            raise ValueError(
                "manifest preparation expected responses require resource_id, status, bytes, "
                "and body_sha256"
            )
        resource_id = response["resource_id"]
        if (
            not isinstance(resource_id, int)
            or isinstance(resource_id, bool)
            or not 0 <= resource_id <= U32_MAX
        ):
            raise ValueError("manifest preparation response resource_id must be an integer")
        if (
            not isinstance(response["status"], int)
            or isinstance(response["status"], bool)
            or not 100 <= response["status"] <= 599
            or not isinstance(response["bytes"], int)
            or isinstance(response["bytes"], bool)
            or not 0 <= response["bytes"] <= U64_MAX
            or not isinstance(response["body_sha256"], str)
            or len(response["body_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in response["body_sha256"])
        ):
            raise ValueError("manifest preparation expected response identity is invalid")
        response_ids.add(resource_id)
    if response_ids != resource_ids or len(response_ids) != len(responses):
        raise ValueError("manifest preparation expected response IDs must match resources")


def _validate_replay(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("manifest replay metadata must be an object")
    unknown = set(value) - REPLAY_KEYS
    if unknown:
        raise ValueError(
            f"manifest replay metadata contains unsupported fields: {', '.join(sorted(unknown))}"
        )
    required = {
        "source_url",
        "final_url",
        "chromium_version",
        "settle_ms",
        "observed_request_count",
        "observed_origins",
        "reviewed_origins",
        "exclusions",
    }
    missing = required - set(value)
    if missing:
        raise ValueError(f"manifest replay metadata is missing: {', '.join(sorted(missing))}")
    for key in ("source_url", "final_url"):
        if https_origin(str(value[key])) is None:
            raise ValueError(f"manifest replay {key} must be absolute credential-free HTTPS")
    for key in ("observed_origins", "reviewed_origins"):
        origins = value[key]
        if not isinstance(origins, list) or len(origins) != len(set(origins)):
            raise ValueError(f"manifest replay {key} must contain unique origins")
        for origin in origins:
            parts = urlsplit(str(origin))
            if (
                parts.scheme != "https"
                or not parts.netloc
                or parts.username is not None
                or parts.password is not None
                or parts.path not in {"", "/"}
            ):
                raise ValueError(f"manifest replay {key} contains an invalid HTTPS origin")
    if not set(value["reviewed_origins"]) <= set(value["observed_origins"]):
        raise ValueError("reviewed origins must be a subset of observed origins")
    if int(value["settle_ms"]) < 0 or int(value["observed_request_count"]) < 1:
        raise ValueError("manifest replay counts must be non-negative")
    exclusions = value["exclusions"]
    if not isinstance(exclusions, list) or any(
        not isinstance(item, dict)
        or set(item) != {"url", "reason"}
        or not str(item["reason"]).strip()
        for item in exclusions
    ):
        raise ValueError("manifest replay exclusions require url and reason")
    stability = value.get("response_stability")
    if stability is not None:
        if not isinstance(stability, dict) or set(stability) != {
            "runs",
            "stable_resource_ids",
        }:
            raise ValueError(
                "manifest replay response_stability requires runs and stable_resource_ids"
            )
        stable_ids = stability["stable_resource_ids"]
        if (
            int(stability["runs"]) < 2
            or not isinstance(stable_ids, list)
            or len(stable_ids) != len(set(stable_ids))
            or any(not isinstance(resource_id, int) for resource_id in stable_ids)
        ):
            raise ValueError("manifest replay response_stability is invalid")


def runtime_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return only fields understood by the Neqo workload runner."""

    validate_manifest(manifest)
    # Preparation has already frozen every safe concrete request header on its
    # resource.  The lab deliberately exposes no second runtime policy layer.
    return {"resources": manifest["resources"]}


def canonical_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def write_frozen_manifest(
    path: Path,
    manifest: dict[str, Any],
    *,
    force: bool = False,
    exclusive: bool = False,
) -> str:
    validate_manifest(manifest)
    data = canonical_bytes(manifest)
    digest = sha256_bytes(data)
    if exclusive:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            raise FileExistsError(f"{path} already exists; choose a new workload ID") from None
        return digest
    if path.exists() and path.read_bytes() != data and not force:
        raise FileExistsError(f"{path} is immutable; choose a new version or pass --force")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return digest
