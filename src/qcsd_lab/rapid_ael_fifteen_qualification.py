"""Prospective 3x5 qualification using the unchanged Native AEL primitive.

This role preserves the current identity request projection, exact prepared
wire response and the application's complete graph and capture limits.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

from . import chaff_qualification as original
from .rapid_operation_facts import OperationFacts, current_context

FIELD = "response_qualification_policy"
POLICY = "ael-equals-identity-three-by-five-stable-wire-response-v1"
TYPE = "qcsd-prospective-ael-fifteen-response-prerequisite-v1"
MAX_WIRE_BYTES = 1_048_576
PREREQUISITE_FILE = "_ael-fifteen-prerequisite.json"
MODES = {"front", "tamaraw", "buflo", "cs-buflo"}


def policy(value):
    requested = value.get(FIELD)
    if FIELD in value and requested != POLICY:
        raise ValueError("unknown explicit response qualification policy")
    return requested


def validate_scope(value, mode):
    chosen = policy(value)
    if chosen is not None and (mode not in MODES or value.get("reuse") is not None
            or value.get("qualification_delivery_compatibility") is not None
            or "ordinary_renewal" in value):
        raise ValueError("AEL fifteen requires its own fresh defended qualification")
    return chosen


def validate_projection(headers, resource):
    if (headers != original.project_compact_headers(resource)
            or headers != original.project_identity_chaff_headers(resource)):
        raise ValueError("AEL qualification would change the exact identity padding request")


def selection(manifest, workload_id):
    resource, response = original.selected_chaff_resource(manifest, workload_id)
    headers = original.project_compact_headers(resource)
    validate_projection(headers, resource)
    if (type(response["bytes"]) is not int
            or not 1200 <= response["bytes"] <= MAX_WIRE_BYTES):
        raise ValueError("AEL fifteen requires an exact prepared wire body within one MiB")
    return {"resource_id": resource["id"], "headers": headers,
        "prepared_response": response, "qualification_max_response_bytes": MAX_WIRE_BYTES}


def validate_sidecar(value, manifest_path, workload_id, *, require_current=True):
    manifest = json.loads(Path(manifest_path).read_bytes())
    chosen = selection(manifest, workload_id)
    checked = original.validate_response_only_sidecar(value, workload_id=workload_id,
        base_manifest_path=Path(manifest_path),
        expected_sidecar_schema_version=original.RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION,
        require_current_implementation=require_current)
    resource = value["resource"]
    validate_projection(resource["headers"], next(r for r in manifest["resources"]
        if r["id"] == chosen["resource_id"]))
    if (resource["resource_id"] != chosen["resource_id"]
            or value["qualification_policy"]["max_response_bytes"] != MAX_WIRE_BYTES):
        raise ValueError("AEL prerequisite changed its selected wire capacity")
    return checked


def qualify(workload_id, *, qualification_root, workload_root, timeout_seconds):
    """Create fresh old-schema evidence; genuine original Native passes are required."""
    existing = current_context()
    context = existing if existing is not None else OperationFacts()
    with context.scope():
        context.watch_file(Path(__file__))
        context.watch_file(Path(original.__file__))
        manifest = Path(workload_root) / (workload_id + ".json")
        selection(json.loads(context.watch_file(manifest)), workload_id)
        context.check()
        result = original.qualify_response_chaff(workload_id,
            qualification_root=Path(qualification_root), workload_root=Path(workload_root),
            timeout_seconds=timeout_seconds, interval_seconds=30)
        raw = context.watch_file(result.path)
        validate_sidecar(json.loads(raw), manifest, workload_id)
        context.check()
        return result


def record():
    return {"artifact_type": TYPE, "policy": POLICY, "native_passes_required": True,
        "connection_epochs": 3, "requests_per_epoch": 5, "total_completions": 15,
        "runtime_manifest_schema": 3, "sidecar_schema": 1,
        "qualification_max_response_bytes": MAX_WIRE_BYTES,
        "padding_request_matches_identity_projection": True,
        "capture_limits_changed": False, "scientific_credit": False}


def _read(path):
    path = original._named_regular_file(Path(path).parent, Path(path).name, "AEL input")
    context = current_context()
    return context.watch_file(path) if context is not None else path.read_bytes()


def _sources():
    return {name: {"sha256": hashlib.sha256(_read(path)).hexdigest(),
            "mode": Path(path).stat().st_mode & 0o7777}
        for name, path in {"policy": __file__, "native_qualifier": original.__file__}.items()}


def _named_facts(named_path, *, workload_root, sidecar_root, require_current):
    raw = _read(named_path)
    named = json.loads(raw)
    if named.get("qualification_sidecar_schema_version") != 1:
        raise ValueError("AEL fifteen cannot relabel another sidecar primitive")
    original.load_named_qualification_set(named_path, workload_root=Path(workload_root),
        sidecar_root=Path(sidecar_root), expected_qualification_scope="response-only",
        require_current_implementation=require_current)
    sources = []
    for identifier in named["workload_ids"]:
        sidecar = json.loads(_read(Path(sidecar_root) / (identifier + ".json")))
        validate_sidecar(sidecar, Path(workload_root) / (identifier + ".json"), identifier,
            require_current=require_current)
        sources.append(sidecar["qualification_source"])
    if not sources or any(source != sources[0] for source in sources):
        raise ValueError("AEL prerequisite mixed actual qualification Sources")
    if require_current and sources[0] != original.source_metadata():
        raise ValueError("AEL fifteen requires fresh current installed qualification Source")
    return hashlib.sha256(raw).hexdigest(), sources[0]


def publish_prerequisite(named, *, workload_root):
    """Append a distinct record; original Native/named receipts are unchanged."""
    named_path = Path(named.manifest_path)
    digest, source = _named_facts(named_path, workload_root=workload_root,
        sidecar_root=named_path.parent, require_current=True)
    value = {**record(), "named_manifest_sha256": digest, "producer_sources": _sources(),
        "qualification_source": source}
    context = current_context()
    if context is not None:
        context.check()
    path = named_path.parent / PREREQUISITE_FILE
    with path.open("xb") as output:
        output.write(original.canonical_bytes(value))
    validate_prerequisite(named_path, workload_root=workload_root,
        sidecar_root=named_path.parent, require_current=True)
    if context is not None:
        context.check()
    return value


def validate_prerequisite(named_path, *, workload_root, sidecar_root, require_current):
    marker = Path(sidecar_root) / PREREQUISITE_FILE
    value = json.loads(_read(marker))
    keys = set(record()) | {"named_manifest_sha256", "producer_sources", "qualification_source"}
    if (not isinstance(value, dict) or set(value) != keys
            or {key: value[key] for key in record()} != record()
            or value["producer_sources"] != _sources()):
        raise ValueError("AEL prerequisite policy or executing producer Source changed")
    digest, source = _named_facts(named_path, workload_root=workload_root,
        sidecar_root=sidecar_root, require_current=require_current)
    if value["named_manifest_sha256"] != digest or value["qualification_source"] != source:
        raise ValueError("AEL prerequisite changed its original named Native proof")
    return value


def selected_schema(named_path, *, workload_root, sidecar_root, historical_schema, require_current):
    marker = Path(sidecar_root) / PREREQUISITE_FILE
    if not marker.exists() and not marker.is_symlink():
        context = current_context()
        if context is not None:
            context.watch_optional_tree(marker)
        return historical_schema
    validate_prerequisite(named_path, workload_root=workload_root,
        sidecar_root=sidecar_root, require_current=require_current)
    return 1


def freeze_prerequisite(named_path, destination, *, workload_root):
    marker = Path(named_path).parent / PREREQUISITE_FILE
    if not marker.exists() and not marker.is_symlink():
        return
    validate_prerequisite(named_path, workload_root=workload_root,
        sidecar_root=Path(named_path).parent, require_current=True)
    raw = _read(marker)
    with (Path(destination) / PREREQUISITE_FILE).open("xb") as output:
        output.write(raw)
    if _read(marker) != raw or _read(Path(destination) / PREREQUISITE_FILE) != raw:
        raise ValueError("AEL prerequisite changed during frozen materialization")
