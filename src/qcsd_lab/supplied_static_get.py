"""Zero-credit complete GET evidence for an exact supplied fixed-resource graph.

This producer runs the existing installed Native client. It does not create
browser preparation, expected bodies, qualified chaff or enrollment authority.
Response hashes are Native's actual buffered-body hashes, not retained bodies;
they cannot establish challenge absence or meaningful rendered primary content.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import socket
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import chaff_qualification, class_acquisition, prepare, util
from . import supplied_static_graph as graph

PROOF_TYPE = "supplied-static-complete-native-get-evidence-v1"
PRIMARY_CLAIM = "complete-nonempty-2xx-primary-get-no-browser-or-content-safety-claim-v1"
PUBLIC_POLICY = "all-public-dns-precheck-native-reresolution-and-observed-public-remote-v1"
RESPONSE_POLICY = "completed-terminal-http-errors-v1"
CLIENT = Path("/usr/local/bin/neqo-qcsd-client")
FILES = ("run.json", "packets.csv", "events.csv", "schedule.csv")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EMPTY = graph.digest(b"")
_BINDING_KEYS = {"source_manifest_sha256", "lab_commit", "native_commit",
                 "image_digest", "client_sha256"}
_RESPONSE_KEYS = {"resource_id", "url", "request_headers", "response_headers", "status",
                  "content_length", "bytes", "body_sha256", "request_stream_bytes",
                  "complete", "outcome"}
_ENDPOINT_KEYS = {"id", "origin", "local_address", "remote_address", "tuple",
                  "negotiated_protocol", "transport_stats", "receive_lifecycle"}


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"static GET {label} fields differ")
    return value


def _load(raw: bytes) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=graph._pairs, parse_constant=graph._constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("static GET evidence is not strict JSON") from error


def _read(path: Path) -> bytes:
    value = path.absolute()
    if any(part.is_symlink() for part in (value, *value.parents)) or not value.is_file():
        raise ValueError("static GET evidence needs regular nonlinked files")
    return value.read_bytes()


def _write(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def _json(path: Path, value: Any) -> None:
    _write(path, graph.canonical_bytes(value))


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("static GET timestamp is invalid")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("static GET timestamp is invalid") from error
    if result.tzinfo is None or result.utcoffset() != UTC.utcoffset(result):
        raise ValueError("static GET timestamps must use UTC")
    return result


def _unix_ns(value: str) -> int:
    elapsed = _time(value) - datetime(1970, 1, 1, tzinfo=UTC)
    return ((elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds) * 1000


def runtime_binding(value: Any) -> dict[str, str]:
    result = _exact(value, _BINDING_KEYS, "runtime binding")
    for key in ("source_manifest_sha256", "client_sha256"):
        if not isinstance(result[key], str) or _SHA.fullmatch(result[key]) is None:
            raise ValueError("static GET runtime digest is invalid")
    for key in ("lab_commit", "native_commit"):
        if not isinstance(result[key], str) or _COMMIT.fullmatch(result[key]) is None:
            raise ValueError("static GET runtime commit is invalid")
    if not isinstance(result["image_digest"], str) or _IMAGE.fullmatch(result["image_digest"]) is None:
        raise ValueError("static GET runtime image is invalid")
    return dict(result)


def producer_sources() -> dict[str, str]:
    modules = {"qcsd_lab.supplied_static_get": Path(__file__),
               "qcsd_lab.supplied_static_graph": Path(graph.__file__),
               "qcsd_lab.class_acquisition": Path(class_acquisition.__file__),
               "qcsd_lab.prepare": Path(prepare.__file__),
               "qcsd_lab.chaff_qualification": Path(chaff_qualification.__file__),
               "qcsd_lab.util": Path(util.__file__)}
    return {name: graph.digest(_read(path)) for name, path in modules.items()}


def _runtime(value: Any, expected: dict[str, str]) -> dict[str, Any]:
    _exact(value, {"source_manifest_text", "qualification_implementation"}, "runtime")
    text = value["source_manifest_text"]
    if not isinstance(text, str) or graph.digest(text.encode()) != expected["source_manifest_sha256"]:
        raise ValueError("static GET actual source manifest differs")
    source = _exact(_load(text.encode()), util.SOURCE_METADATA_KEYS, "source manifest")
    if (source["lab_commit"] != expected["lab_commit"]
        or source["neqo_commit"] != expected["native_commit"]
        or source["neqo_pinned_commit"] != expected["native_commit"]
        or source["image_digest"] not in (None, expected["image_digest"])
        or source["lab_dirty"] is not False or source["neqo_dirty"] is not False
        or source["lab_patch_sha256"] != _EMPTY or source["neqo_patch_sha256"] != _EMPTY):
        raise ValueError("static GET runtime source is not the expected clean pinned source")
    implementation = value["qualification_implementation"]
    chaff_qualification._validate_implementation_receipt(implementation, require_current=False)
    if (implementation["schema_version"] != 2
        or implementation["source"]["image_digest"] not in (None, expected["image_digest"])
        or {**implementation["source"], "image_digest": expected["image_digest"]}
        != {**source, "image_digest": expected["image_digest"]}
        or implementation["neqo_qcsd_client"] != {
            "path": str(CLIENT), "sha256": expected["client_sha256"]}):
        raise ValueError("static GET installed client receipt differs from actual source/image binding")
    return source


def native_command(root: Path, max_response_bytes: int, timeout_seconds: int) -> list[str]:
    if (type(max_response_bytes) is not int or max_response_bytes < 1
        or type(timeout_seconds) is not int or timeout_seconds < 1):
        raise ValueError("static GET limits must be positive integers")
    if not root.is_absolute():
        raise ValueError("static GET execution root must be absolute")
    return [str(CLIENT), "run", "--workload", str(root / "native-input.json"),
            "--profile", "live", "--defense", "none", "--request-policy", "as-defined",
            "--application-response-policy", RESPONSE_POLICY, "--seed", "0",
            "--output-dir", str(root / "native"), "--max-response-bytes", str(max_response_bytes),
            "--timeout-seconds", str(timeout_seconds)]


def _origin(url: str) -> str:
    value = urlsplit(url)
    return f"https://{value.hostname}" + (f":{value.port}" if value.port not in (None, 443) else "")


def _csv(raw: bytes, required: set[str], label: str) -> list[dict[str, str]]:
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8")))
        fields = reader.fieldnames
        rows = list(reader)
    except (UnicodeError, csv.Error) as error:
        raise ValueError(f"static GET {label} CSV is invalid") from error
    if (fields is None or len(fields) != len(set(fields)) or not required <= set(fields)
        or any(None in row or any(value is None for value in row.values()) for row in rows)):
        raise ValueError(f"static GET {label} CSV fields differ")
    return rows


def _number(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"static GET {label} needs a nonnegative integer")
    return value


def _csv_number(value: str, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise ValueError(f"static GET {label} is not a canonical integer")
    return int(value)


def _remote(value: Any) -> tuple[str, int]:
    if not isinstance(value, str):
        raise ValueError("static GET socket address is invalid")
    try:
        if value.startswith("["):
            host, port = value[1:].split("]:")
        else:
            host, port = value.rsplit(":", 1)
        parsed_port = _csv_number(port, "remote port")
    except ValueError as error:
        raise ValueError("static GET socket address is invalid") from error
    if not class_acquisition._is_public_network_address(host) or not 1 <= parsed_port <= 65535:
        raise ValueError("static GET remote address is not public")
    return host, parsed_port


def _dns(value: Any, origins: list[str], declared: str, started: str) -> dict[str, list[str]]:
    _exact(value, {"schema_version", "policy", "observations"}, "DNS evidence")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["policy"] != PUBLIC_POLICY:
        raise ValueError("static GET public-origin policy differs")
    observations = value["observations"]
    if not isinstance(observations, list) or len(observations) != len(origins):
        raise ValueError("static GET DNS coverage is incomplete")
    result = {}
    for origin, row in zip(origins, observations, strict=True):
        _exact(row, {"origin", "started_at", "completed_at", "answers"}, "DNS observation")
        answers = row["answers"]
        if (row["origin"] != origin or not isinstance(answers, list) or not answers
            or any(not isinstance(answer, str) or not class_acquisition._is_public_network_address(answer)
                   for answer in answers)
            or len(set(answers)) != len(answers)
            or not _time(declared) <= _time(row["started_at"]) <= _time(row["completed_at"]) <= _time(started)):
            raise ValueError("static GET DNS is unsafe, mismatched or outside actual execution")
        result[origin] = answers
    return result


def _run_proof(run: Any, root: Path, declaration: dict[str, Any], started: dict[str, Any],
               completed: dict[str, Any], manifest: dict[str, Any], dns: Any, *,
               response_policy: str = RESPONSE_POLICY, rejected_primary: bool = False) -> dict[str, Any]:
    # Rejection evidence is used only by operational deferral. Successful GET
    # proofs always use the default, including the exact full graph checks.
    if (type(rejected_primary) is not bool
        or (rejected_primary and (response_policy != "http-2xx-only-v1"
            or len(manifest["resources"]) != 1 or manifest["resources"][0]["id"] != 0
            or type(completed.get("returncode")) is not int or completed["returncode"] != 0
            or completed.get("timed_out") is not False))):
        raise ValueError("static failed Native evidence is not an exact strict primary rejection")
    if response_policy not in {RESPONSE_POLICY, "http-2xx-only-v1"}:
        raise ValueError("static GET raw response policy is unsupported")
    if not isinstance(run, dict):
        raise ValueError("static GET run is missing")
    expected = declaration["runtime_binding"]
    for key in prepare.NEQO_PROVENANCE_KEYS:
        if not isinstance(run.get(key), str) or not run[key]:
            raise ValueError("static GET Native provenance is missing")
    if any(_COMMIT.fullmatch(run[key]) is None for key in ("neqo_base_commit", "published_qcsd_commit")):
        raise ValueError("static GET Native upstream provenance is invalid")
    if run["migration_commit"] != expected["native_commit"]:
        raise ValueError("static GET Native source is not the expected commit")
    if (run.get("method") != "GET" or run.get("request_policy") != "as-defined"
        or run.get("application_response_policy") != response_policy
        or run.get("primary_document_identity_policy") != "exact-response-body-v1"
        or type(run.get("seed")) is not int or run["seed"] != 0
        or run.get("workload_hash_sha256") != graph.digest(_read(root / "native-input.json"))
        or run.get("application_workload_source_hash_sha256") is not None
        or run.get("chaff_manifest_hash_sha256") is not None
        or run.get("chaff_responses") != [] or run.get("defense_parameters") is not None
        or not isinstance(run.get("resolved_configuration"), dict)
        or run["resolved_configuration"].get("defense") != {"kind": "none"}
        or type(run.get("max_response_bytes")) is not int
        or run["max_response_bytes"] != declaration["max_response_bytes"]
        or run.get("completion_status") != ("partial" if rejected_primary else "complete") or run.get("error") is not None
        or run.get("error_class") is not None or run.get("terminal_evidence_render_errors") != []):
        raise ValueError("static GET run contract is incomplete or changed")
    start_ns = _number(run.get("started_unix_ns"), "run start")
    end_ns = _number(run.get("ended_unix_ns"), "run end")
    if (type(run.get("time_anchor_unix_ns")) is not int or run["time_anchor_unix_ns"] != start_ns
        or not _unix_ns(started["started_at"]) - 1000 <= start_ns <= end_ns
        <= _unix_ns(completed["completed_at"]) + 1000):
        raise ValueError("static GET Native time lies outside actual child execution")
    origins = sorted({_origin(row["url"]) for row in manifest["resources"]},
                     key=lambda value: (urlsplit(value).hostname, urlsplit(value).port or 443))
    dns_answers = _dns(dns, origins, declaration["declared_at"], started["started_at"])
    endpoints = run.get("endpoints")
    if not isinstance(endpoints, list) or len(endpoints) != len(origins):
        raise ValueError("static GET endpoint coverage is incomplete")
    origin_ids, endpoint_proofs = {}, []
    for index, (origin, row) in enumerate(zip(origins, endpoints, strict=True)):
        _exact(row, _ENDPOINT_KEYS, "Native endpoint")
        if (type(row["id"]) is not int or row["id"] != index or row["origin"] != origin + "/"
            or row["negotiated_protocol"] != "h3"
            or row["tuple"] != {"protocol": "udp", "local": row["local_address"], "remote": row["remote_address"]}):
            raise ValueError("static GET endpoint ID/origin/H3 identity differs")
        remote, port = _remote(row["remote_address"])
        if remote not in dns_answers[origin] or port != (urlsplit(origin).port or 443):
            raise ValueError("static GET observed remote differs from retained public DNS origin")
        lifecycle = row["receive_lifecycle"]
        _exact(lifecycle, {"schema_version", "source", "time_basis", "polling_stopped_at_elapsed_ns",
                           "polling_stopped_at_unix_ns", "disposition", "scientific_credit"}, "receive lifecycle")
        # A rejected primary can close without a terminal receive clock. This
        # absence is retained as failure evidence, never a successful GET fact.
        rejected_without_drain_clock = (rejected_primary and lifecycle["polling_stopped_at_elapsed_ns"] is None
                                       and lifecycle["polling_stopped_at_unix_ns"] is None)
        if (type(lifecycle["schema_version"]) is not int or lifecycle["schema_version"] != 1
            or lifecycle["source"] != "native-final-udp-receive-drain-v1"
            or lifecycle["time_basis"] != "runner-process-start-elapsed-monotonic-v1"
            or lifecycle["disposition"] != "drained_to_would_block"
            or lifecycle["scientific_credit"] is not False
            or (not rejected_without_drain_clock and (
                _number(lifecycle["polling_stopped_at_elapsed_ns"], "final receive elapsed time") > end_ns - start_ns + 1000
                or not start_ns <= _number(lifecycle["polling_stopped_at_unix_ns"], "final receive time") <= end_ns))):
            raise ValueError("static GET endpoint lifecycle evidence is missing")
        origin_ids[origin] = index
        endpoint_proofs.append({"endpoint": index, "origin": origin, "remote_address": row["remote_address"]})
    by_id = {row["id"]: row for row in manifest["resources"]}
    responses, identities = run.get("responses"), []
    if not isinstance(responses, list) or len(responses) != len(by_id):
        raise ValueError("static GET response coverage is incomplete")
    seen = set()
    for row in responses:
        _exact(row, _RESPONSE_KEYS, "Native response")
        resource_id = _number(row["resource_id"], "resource ID")
        if resource_id not in by_id or resource_id in seen:
            raise ValueError("static GET response resource ID is absent or duplicated")
        resource = by_id[resource_id]
        seen.add(resource_id)
        count = _number(row["bytes"], "response bytes")
        status = _number(row["status"], "status")
        headers = row["response_headers"]
        if (not isinstance(headers, list) or any(not isinstance(pair, list) or len(pair) != 2
            or any(not isinstance(value, str) for value in pair) for pair in headers)):
            raise ValueError("static GET response headers are malformed")
        if (row["url"] != resource["url"] or row["request_headers"] != resource["headers"]
            or row["complete"] is not True or row["outcome"] != ("failed" if rejected_primary else "succeeded")
            or count > declaration["max_response_bytes"]
            or not isinstance(row["body_sha256"], str) or _SHA.fullmatch(row["body_sha256"]) is None
            or _number(row["request_stream_bytes"], "request stream bytes") < 1
            or (count == 0 and row["body_sha256"] != _EMPTY)
            or (count > 0 and row["body_sha256"] == _EMPTY)
            or (row["content_length"] is not None and (
                type(row["content_length"]) is not int or row["content_length"] != count))
            or [value for name, value in headers if name.lower() == ":status"] != [str(status)]
            or (resource_id == 0 and ((not 100 <= status < 600 or 200 <= status < 300) if rejected_primary
                                     else (not 200 <= status < 300 or count == 0)))
            or (resource_id != 0 and not (200 <= status < 300 or 400 <= status < 600))):
            raise ValueError("static GET response is changed, unsuccessful or truncated")
        lengths = [value for name, value in headers if name.lower() == "content-length"]
        if lengths and (len(lengths) != 1 or lengths[0] != str(count) or row["content_length"] != count):
            raise ValueError("static GET response length contradicts actual complete body")
        identities.append({"resource_id": resource_id, "endpoint": origin_ids[_origin(resource["url"])],
                           "status": status, "bytes": count, "body_sha256": row["body_sha256"]})
    events = _csv(_read(root / "native/events.csv"), {"connection", "event", "outcome", "details", "monotonic_us"}, "events")
    starts, completions, opened, finished = {}, {}, {}, {}
    sequences = set()
    for row in events:
        if row["event"] == "application_request":
            if row["outcome"] in {"failed", "skipped_dependency"}:
                raise ValueError("static GET raw application request failed")
            if row["outcome"] == "started":
                resource_id = _number(_load(row["details"].encode()), "started resource")
                endpoint = _csv_number(row["connection"], "request endpoint")
                if resource_id not in by_id or resource_id in starts or endpoint != origin_ids[_origin(by_id[resource_id]["url"])]:
                    raise ValueError("static GET raw started request changed its resource/origin")
                starts[resource_id] = endpoint
        if row["event"] != "observation":
            continue
        detail = _load(row["details"].encode())
        if not isinstance(detail, dict) or row["outcome"] != "recorded":
            raise ValueError("static GET raw observation is malformed")
        seq = _number(detail.get("production_sequence"), "production sequence")
        stamp = _number(detail.get("production_monotonic_ns"), "production time")
        if seq in sequences or stamp > end_ns - start_ns + 1000:
            raise ValueError("static GET observation clock/sequence differs from run")
        sequences.add(seq)
        kind = detail.get("type")
        if kind not in {"resource_completed", "stream_opened", "stream_finished"}:
            continue
        endpoint = _csv_number(row["connection"], "observation endpoint")
        if endpoint >= len(origins):
            raise ValueError("static GET observation endpoint is absent")
        if kind == "resource_completed":
            resource_id = _number(detail.get("resource_id"), "completed resource")
            if (resource_id not in starts or resource_id in completions or detail.get("success") is not (not rejected_primary)
                or starts[resource_id] != endpoint):
                raise ValueError("static GET raw resource completion differs")
            completions[resource_id] = seq
        else:
            stream = _number(detail.get("stream"), "request stream")
            key = (endpoint, stream)
            if detail.get("endpoint") != endpoint or type(detail.get("endpoint")) is not int or stream % 4 != 0:
                raise ValueError("static GET request stream origin/direction differs")
            if kind == "stream_opened":
                if detail.get("role") != "application" or key in opened:
                    raise ValueError("static GET opened stream is duplicated or not application")
                opened[key] = seq
            else:
                if detail.get("finish") != "fin" or key not in opened or key in finished or seq <= opened[key]:
                    raise ValueError("static GET lacks unique actual application FIN")
                finished[key] = seq
    if set(starts) != set(by_id) or set(completions) != set(by_id) or set(opened) != set(finished):
        raise ValueError("static GET raw full-graph request/completion/FIN coverage is incomplete")
    for endpoint in range(len(origins)):
        resource_ids = sorted(resource_id for resource_id, owner in starts.items() if owner == endpoint)
        streams = sorted(stream for owner, stream in opened if owner == endpoint)
        if len(streams) != len(resource_ids):
            raise ValueError("static GET per-origin FIN count differs from request count")
        endpoint_proofs[endpoint].update(resource_ids=resource_ids, fin_stream_ids=streams)
    # Ordinary undefended runs have no scheduled defense slots.
    if _csv(_read(root / "native/schedule.csv"), {"direction", "size", "satisfaction"}, "schedule"):
        raise ValueError("static GET unexpectedly has scheduled defense slots")
    packet_rows = _csv(_read(root / "native/packets.csv"), {"connection", "direction", "observed_udp_length"}, "packets")
    directions = {endpoint: set() for endpoint in range(len(origins))}
    for row in packet_rows:
        endpoint = _csv_number(row["connection"], "packet endpoint")
        if endpoint not in directions or row["direction"] not in {"incoming", "outgoing"}:
            raise ValueError("static GET packet endpoint/direction differs")
        directions[endpoint].add(row["direction"])
    if any(value != {"incoming", "outgoing"} for value in directions.values()):
        raise ValueError("static GET lacks bidirectional packets for every full-graph origin")
    packet_proof = prepare._qualify_udp_payloads(run, root / "native/packets.csv", run_index=0, expected_ceiling=1200)
    return {"responses": sorted(identities, key=lambda row: row["resource_id"]),
            "endpoint_completion": endpoint_proofs, "udp_payloads": packet_proof,
            "native_provenance": {key: run[key] for key in prepare.NEQO_PROVENANCE_KEYS},
            "started_unix_ns": start_ns, "ended_unix_ns": end_ns}


def build_proof(root: Path, *, expected_runtime: dict[str, str], source_sha256: str, domain: str) -> dict[str, Any]:
    """Reconstruct complete GET facts from original inputs, raw outputs and actual process records."""
    root = root.absolute()
    expected = runtime_binding(expected_runtime)
    source = _read(root / "source-list.json")
    manifest = _load(_read(root / "native-input.json"))
    input_binding = _load(_read(root / "input-binding.json"))
    graph.verify_import(source, source_sha256, domain, manifest, input_binding)
    if class_acquisition.unsafe_catalogue_domain_reason(domain) is not None:
        raise ValueError("static GET primary domain is excluded by existing safety policy")
    declaration = _exact(_load(_read(root / "declaration.json")), {
        "schema_version", "record_type", "declared_at", "source_sha256", "domain", "runtime_binding",
        "producer_role", "producer_sources", "input_binding_sha256", "native_input_sha256",
        "max_response_bytes", "timeout_seconds", "primary_claim", "public_origin_policy",
        "scientific_credit", "site_credit", "formal_accepted_trace_count"}, "declaration")
    if (type(declaration["schema_version"]) is not int or declaration["schema_version"] != 1
        or declaration["record_type"] != PROOF_TYPE or declaration["runtime_binding"] != expected
        or declaration["source_sha256"] != source_sha256 or declaration["domain"] != domain
        or declaration["producer_role"] != "external-declared-static-get-authority-v1"
        or declaration["producer_sources"] != producer_sources()
        or declaration["input_binding_sha256"] != graph.digest(_read(root / "input-binding.json"))
        or declaration["native_input_sha256"] != graph.digest(_read(root / "native-input.json"))
        or declaration["primary_claim"] != PRIMARY_CLAIM or declaration["public_origin_policy"] != PUBLIC_POLICY
        or declaration["scientific_credit"] is not False
        or type(declaration["site_credit"]) is not int or declaration["site_credit"] != 0
        or type(declaration["formal_accepted_trace_count"]) is not int or declaration["formal_accepted_trace_count"] != 0):
        raise ValueError("static GET prospective declaration differs from exact inputs/runtime/source")
    _runtime(_load(_read(root / "runtime.json")), expected)
    started = _exact(_load(_read(root / "native-started.json")), {
        "schema_version", "command", "environment", "started_at", "declaration_sha256", "client_sha256"}, "started process")
    environment = {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": expected["image_digest"],
                   "QCSD_LAB_SOURCE_METADATA": str(util.DEFAULT_SOURCE_METADATA)}
    if (type(started["schema_version"]) is not int or started["schema_version"] != 1
        or started["command"] != native_command(root, declaration["max_response_bytes"], declaration["timeout_seconds"])
        or started["environment"] != environment
        or started["declaration_sha256"] != graph.digest(_read(root / "declaration.json"))
        or started["client_sha256"] != expected["client_sha256"]):
        raise ValueError("static GET actual started command/environment differs")
    completed = _exact(_load(_read(root / "native-completed.json")), {
        "schema_version", "returncode", "timed_out", "completed_at", "elapsed_ns", "stdout_sha256",
        "stderr_sha256", "outputs", "client_sha256", "source_manifest_sha256"}, "completed process")
    outputs = {name: graph.digest(_read(root / "native" / name)) for name in FILES}
    if (type(completed["schema_version"]) is not int or completed["schema_version"] != 1
        or type(completed["returncode"]) is not int or completed["returncode"] != 0
        or completed["timed_out"] is not False
        or _number(completed["elapsed_ns"], "actual elapsed time") < 1
        or completed["outputs"] != outputs
        or completed["stdout_sha256"] != graph.digest(_read(root / "native.stdout.log"))
        or completed["stderr_sha256"] != graph.digest(_read(root / "native.stderr.log"))
        or completed["client_sha256"] != expected["client_sha256"]
        or completed["source_manifest_sha256"] != expected["source_manifest_sha256"]
        or not _time(declaration["declared_at"]) <= _time(started["started_at"]) < _time(completed["completed_at"])):
        raise ValueError("static GET lacks a closed actual successful process/raw output binding")
    native = _run_proof(_load(_read(root / "native/run.json")), root, declaration, started, completed,
                        manifest, _load(_read(root / "dns.json")))
    sealed_files = {name: graph.digest(_read(root / name)) for name in (
        "source-list.json", "native-input.json", "input-binding.json", "declaration.json", "runtime.json",
        "dns.json", "native-started.json", "native-completed.json", "native.stdout.log", "native.stderr.log",
        *["native/" + name for name in FILES])}
    return {"schema_version": 1, "record_type": PROOF_TYPE, "data_role": graph.INPUT_ROLE,
            "domain": domain, "source_sha256": source_sha256, "runtime_binding": expected,
            "producer_role": declaration["producer_role"], "producer_sources": declaration["producer_sources"],
            "declared_at": declaration["declared_at"], "completed_at": completed["completed_at"],
            "primary_claim": PRIMARY_CLAIM, "browser_discovery_claim": False,
            "challenge_absence_claim": False, "body_contents_retained": False,
            "resource_count": len(manifest["resources"]), "origin_count": len(input_binding["origins"]),
            "full_list_coverage": True, "native": native, "files": sealed_files,
            "scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0}


def validate_proof(root: Path, *, expected_runtime: dict[str, str], source_sha256: str, domain: str) -> dict[str, Any]:
    expected = build_proof(root, expected_runtime=expected_runtime, source_sha256=source_sha256, domain=domain)
    if graph.canonical_bytes(_load(_read(root / "full-get-proof.json"))) != graph.canonical_bytes(expected):
        raise ValueError("static GET summary differs from independently reopened raw facts")
    return expected


def execute_full_get(source: Path, input_root: Path, output_root: Path, *, expected_runtime: dict[str, str],
                     source_sha256: str, domain: str, max_response_bytes: int = 16_777_216,
                     timeout_seconds: int = 120) -> dict[str, Any]:
    """Run one real complete graph in the declared installed collection image; retain failures."""
    expected = runtime_binding(expected_runtime)
    output_root = output_root.absolute()
    command = native_command(output_root, max_response_bytes, timeout_seconds)
    source_raw, input_raw, binding_raw = (_read(source), _read(input_root / "native-input.json"),
                                         _read(input_root / "input-binding.json"))
    graph.verify_import(source_raw, source_sha256, domain, _load(input_raw), _load(binding_raw))
    if class_acquisition.unsafe_catalogue_domain_reason(domain) is not None:
        raise ValueError("static GET primary domain is excluded by existing safety policy")
    if (os.environ.get("QCSD_LAB_IMAGE_DIGEST") != expected["image_digest"]
        or os.environ.get("QCSD_LAB_SOURCE_METADATA") != str(util.DEFAULT_SOURCE_METADATA)):
        raise ValueError("static GET must execute inside its exact declared installed image")
    implementation, _, _ = chaff_qualification._qualification_execution_context()
    client, client_sha = chaff_qualification._bound_neqo_client(implementation)
    runtime = {"source_manifest_text": _read(util.DEFAULT_SOURCE_METADATA).decode(),
               "qualification_implementation": implementation}
    _runtime(runtime, expected)
    if client != CLIENT or client_sha != expected["client_sha256"]:
        raise ValueError("static GET client is not the declared installed executable")
    for protected in (source, input_root, client, util.DEFAULT_SOURCE_METADATA):
        util.require_disjoint_path(output_root, [protected], label="static GET output")
    output_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    declaration = {"schema_version": 1, "record_type": PROOF_TYPE, "declared_at": datetime.now(UTC).isoformat(),
                   "source_sha256": source_sha256, "domain": domain, "runtime_binding": expected,
                   "producer_role": "external-declared-static-get-authority-v1", "producer_sources": producer_sources(),
                   "input_binding_sha256": graph.digest(binding_raw), "native_input_sha256": graph.digest(input_raw),
                   "max_response_bytes": max_response_bytes, "timeout_seconds": timeout_seconds,
                   "primary_claim": PRIMARY_CLAIM, "public_origin_policy": PUBLIC_POLICY,
                   "scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0}
    for name, raw in (("source-list.json", source_raw), ("native-input.json", input_raw), ("input-binding.json", binding_raw)):
        _write(output_root / name, raw)
    _json(output_root / "runtime.json", runtime)
    _json(output_root / "declaration.json", declaration)
    observations = []
    origins = sorted(_load(binding_raw)["origins"], key=lambda value: (urlsplit(value).hostname, urlsplit(value).port or 443))
    for origin in origins:
        before = datetime.now(UTC).isoformat()
        parsed = urlsplit(origin)
        answers = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443,
                                                                           socket.AF_UNSPEC, socket.SOCK_DGRAM)))
        observations.append({"origin": origin, "started_at": before, "completed_at": datetime.now(UTC).isoformat(), "answers": answers})
    dns = {"schema_version": 1, "policy": PUBLIC_POLICY, "observations": observations}
    _json(output_root / "dns.json", dns)
    start = datetime.now(UTC).isoformat()
    _dns(dns, origins, declaration["declared_at"], start)
    environment = {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": expected["image_digest"],
                   "QCSD_LAB_SOURCE_METADATA": str(util.DEFAULT_SOURCE_METADATA)}
    chaff_qualification._recheck_bound_neqo_client(client, client_sha)
    _json(output_root / "native-started.json", {"schema_version": 1, "command": command,
          "environment": environment, "started_at": start,
          "declaration_sha256": graph.digest(_read(output_root / "declaration.json")), "client_sha256": client_sha})
    child_env = {key: value for key, value in os.environ.items() if not key.startswith("QCSD_")}
    child_env.update(environment)
    monotonic_start = time.monotonic_ns()
    code, timed_out = None, False
    try:
        with (output_root / "native.stdout.log").open("xb") as stdout, (output_root / "native.stderr.log").open("xb") as stderr:
            try:
                code = subprocess.run(command, stdout=stdout, stderr=stderr, env=child_env,
                                      timeout=util.neqo_host_timeout(timeout_seconds), check=False).returncode
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        completion = {"schema_version": 1, "returncode": code, "timed_out": timed_out,
                      "completed_at": datetime.now(UTC).isoformat(), "elapsed_ns": time.monotonic_ns() - monotonic_start,
                      "stdout_sha256": graph.digest(_read(output_root / "native.stdout.log")),
                      "stderr_sha256": graph.digest(_read(output_root / "native.stderr.log")),
                      "outputs": {name: graph.digest(_read(output_root / "native" / name)) for name in FILES
                                  if (output_root / "native" / name).is_file()},
                      "client_sha256": graph.digest(_read(client)),
                      "source_manifest_sha256": graph.digest(_read(util.DEFAULT_SOURCE_METADATA))}
        _json(output_root / "native-completed.json", completion)
    if code != 0 or timed_out:
        raise ValueError("static GET actual Native execution failed; original raw evidence retained")
    if producer_sources() != declaration["producer_sources"]:
        raise ValueError("static GET producer source changed during actual execution")
    proof = build_proof(output_root, expected_runtime=expected, source_sha256=source_sha256, domain=domain)
    _json(output_root / "full-get-proof.json", proof)
    return validate_proof(output_root, expected_runtime=expected, source_sha256=source_sha256, domain=domain)
