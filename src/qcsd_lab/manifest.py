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
    if manifest.get("schema_version") not in (1, 2):
        raise ValueError("manifest schema_version must be 1 or 2")
    resources = manifest.get("resources")
    if not isinstance(resources, list) or not resources:
        raise ValueError("manifest requires at least one resource")
    ids = {resource.get("id") for resource in resources}
    if len(ids) != len(resources) or None in ids:
        raise ValueError("resource IDs must be present and unique")
    graph: dict[int, list[int]] = {}
    for resource in resources:
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
    path.with_suffix(path.suffix + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest
