from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .util import sha256_bytes

SENSITIVE = {"authorization", "cookie", "cookie2", "proxy-authorization"}
CONNECTION_SPECIFIC = {
    "connection",
    "host",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
}
MANIFEST_KEYS = {"header_policy", "resources", "replay"}
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


def safe_discovery_headers(headers: dict[str, str]) -> list[list[str]]:
    safe: list[list[str]] = []
    for raw_name, value in headers.items():
        name = raw_name.lower()
        if name.startswith(":") or name in SENSITIVE or name in CONNECTION_SPECIFIC:
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
    policy = manifest.get("header_policy", {})
    if not isinstance(policy, dict):
        raise ValueError("manifest header_policy must be an object")
    if "replay" in manifest:
        _validate_replay(manifest["replay"])
    resources = manifest.get("resources")
    if not isinstance(resources, list) or not resources:
        raise ValueError("manifest requires at least one resource")
    ids = {resource.get("id") for resource in resources}
    if len(ids) != len(resources) or None in ids:
        raise ValueError("resource IDs must be present and unique")
    graph: dict[int, list[int]] = {}
    for resource in resources:
        if not isinstance(resource, dict):
            raise ValueError("manifest resources must be objects")
        parts = urlsplit(resource.get("url", ""))
        if parts.scheme != "https" or not parts.netloc:
            raise ValueError(f"resource {resource.get('id')} is not absolute HTTPS")
        dependencies = resource.get("depends_on", [])
        if resource["id"] in dependencies or not set(dependencies) <= ids:
            raise ValueError(f"invalid dependencies for resource {resource['id']}")
        graph[resource["id"]] = dependencies
        for raw_name, value in resource.get("headers", []):
            name = raw_name.lower()
            if (
                name.startswith(":")
                or name in SENSITIVE
                or name in CONNECTION_SPECIFIC
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
        raise ValueError(
            f"manifest replay metadata is missing: {', '.join(sorted(missing))}"
        )
    for key in ("source_url", "final_url"):
        parts = urlsplit(str(value[key]))
        if parts.scheme != "https" or not parts.netloc:
            raise ValueError(f"manifest replay {key} must be absolute HTTPS")
    for key in ("observed_origins", "reviewed_origins"):
        origins = value[key]
        if not isinstance(origins, list) or len(origins) != len(set(origins)):
            raise ValueError(f"manifest replay {key} must contain unique origins")
        for origin in origins:
            parts = urlsplit(str(origin))
            if parts.scheme != "https" or not parts.netloc or parts.path not in {"", "/"}:
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
    return {key: value for key, value in manifest.items() if key != "replay"}


def canonical_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def write_frozen_manifest(path: Path, manifest: dict[str, Any], *, force: bool = False) -> str:
    validate_manifest(manifest)
    data = canonical_bytes(manifest)
    digest = sha256_bytes(data)
    if path.exists() and path.read_bytes() != data and not force:
        raise FileExistsError(f"{path} is immutable; choose a new version or pass --force")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return digest
