"""Actual Native adapters for the prospective exact-resource-host study.

Run this module inside the Linux collector container. The coordinator owns
Docker, observer setup, source/image authentication and independent receipt
verification. These results never award ledger credit. An internal Document
at resource0 is only Native's scheduling anchor: it asserts no HTML, browser
navigation or dependency discovery.
"""
from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from .resource_study_inputs import (
    MODES, RESOURCES_PER_SESSION, canonical_json, native_manifest, sha256_file,
)

DEFAULT_CLIENT = "/usr/local/bin/neqo-qcsd-client"
MAX_RESPONSE_BYTES = 16_777_216
ROLE = "resource-host-direct-native-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
REQUEST_HEADERS = [["accept", "*/*"], ["accept-encoding", "identity"],
                   ["accept-language", "en-US,en;q=0.9"]]


def _regular(path: str | Path) -> Path:
    path = Path(os.path.abspath(path))
    if (any(parent.is_symlink() for parent in (path, *path.parents))
            or not path.is_file()):
        raise ValueError(f"not a regular nonsymlink file: {path}")
    return path


def _new_directory(path: str | Path) -> Path:
    path = Path(os.path.abspath(path))
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("output path contains a symlink")
    path.mkdir(parents=True, exist_ok=False)
    return path


def _write(path: Path, value: Any, *, raw: bool = False) -> Path:
    data = value if raw else canonical_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _object(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("evidence JSON has a duplicate field")
            result[key] = value
        return result

    def nonfinite(value: str) -> None:
        raise ValueError(f"evidence JSON has a nonfinite value: {value}")

    value = json.loads(_regular(path).read_bytes(), object_pairs_hook=unique,
                       parse_constant=nonfinite)
    if not isinstance(value, dict):
        raise ValueError("evidence JSON must be an object")
    return value


def _runtime(runtime: Mapping[str, Any], client: str | Path) -> tuple[Path, dict[str, Any]]:
    if (not isinstance(runtime, Mapping)
            or not isinstance(runtime.get("client_sha256"), str)
            or _SHA256.fullmatch(runtime["client_sha256"]) is None
            or not isinstance(runtime.get("native_commit"), str)
            or _COMMIT.fullmatch(runtime["native_commit"]) is None):
        raise ValueError("runtime needs actual client_sha256 and native_commit")
    canonical_json(dict(runtime))
    path = _regular(client)
    if not os.access(path, os.X_OK) or sha256_file(path) != runtime["client_sha256"]:
        raise ValueError("executed Native client differs from runtime binding")
    return path, dict(runtime)


def _positive(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _manifest(hostname: str, urls: Iterable[str], *, require_twenty: bool) -> dict[str, Any]:
    result = native_manifest(hostname, urls, require_twenty=require_twenty)
    for resource in result["resources"]:
        resource["headers"] = [pair[:] for pair in REQUEST_HEADERS]
    return result


def probe_command(client: str | Path, manifest: str | Path, output: str | Path, *,
                  timeout: int = 120, max_response_bytes: int = MAX_RESPONSE_BYTES) -> list[str]:
    """The strict undefended direct-GET command; no browsing or fitting."""
    _positive(timeout, "timeout")
    _positive(max_response_bytes, "max_response_bytes")
    return [str(client), "run", "--workload", str(manifest),
            "--profile", "research-1200", "--defense", "none",
            "--request-policy", "as-defined", "--application-response-policy",
            "http-2xx-only-v1", "--seed", "0", "--output-dir", str(output),
            "--max-response-bytes", str(max_response_bytes),
            "--timeout-seconds", str(timeout)]


def qualification_command(client: str | Path, prepared: str | Path,
                          output: str | Path, selected_id: int, *,
                          timeout: int = 120) -> list[str]:
    if type(selected_id) is not int or not 0 <= selected_id < RESOURCES_PER_SESSION:
        raise ValueError("chaff resource must be a selected resource")
    _positive(timeout, "timeout")
    return [str(client), "qualify-chaff-response", "--workload", str(prepared),
            "--application-resource-id", "0", "--selected-chaff-resource-id",
            str(selected_id), "--output-dir", str(output), "--timeout-seconds",
            str(timeout), "--max-response-bytes", str(MAX_RESPONSE_BYTES), "--packet-size",
            "1200", "--parallel-requests", "5"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _execute(command: list[str], directory: Path, *, timeout: int,
             client_sha256: str) -> dict[str, Any]:
    """Retain both actual process boundaries and raw outputs, including failure."""
    client = _regular(command[0])
    if sha256_file(client) != client_sha256:
        raise ValueError("Native client changed before execution")
    started = {"schema_version": 1, "argv": command, "started_at": _now(),
               "started_unix_ns": time.time_ns(), "client_sha256": client_sha256}
    _write(directory / "started.json", started)
    code, timed_out, error = None, False, None
    try:
        with (directory / "stdout.txt").open("xb") as stdout, \
                (directory / "stderr.txt").open("xb") as stderr:
            try:
                completed = subprocess.run(command, stdout=stdout, stderr=stderr,
                                           timeout=timeout + 5, check=False)
                code = completed.returncode
            except subprocess.TimeoutExpired as failure:
                timed_out, error = True, str(failure)
            except OSError as failure:
                error = str(failure)
    finally:
        unchanged = client.is_file() and not client.is_symlink() and sha256_file(client) == client_sha256
        result = {"schema_version": 1, "argv": command, "returncode": code,
                  "timed_out": timed_out, "error": error,
                  "completed_at": _now(), "completed_unix_ns": time.time_ns(),
                  "client_sha256": client_sha256, "client_unchanged": unchanged,
                  "stdout_sha256": sha256_file(directory / "stdout.txt"),
                  "stderr_sha256": sha256_file(directory / "stderr.txt")}
        _write(directory / "completed.json", result)
    return result


def inspect_completed_run(run: Mapping[str, Any], manifest: Mapping[str, Any], *,
                          manifest_sha256: str, max_response_bytes: int,
                          native_commit: str | None = None,
                          seed: int = 0) -> list[dict[str, Any]]:
    """Check every actual response. Terminal HTTP errors never qualify here."""
    if (not isinstance(run, Mapping) or run.get("method") != "GET"
            or run.get("request_policy") != "as-defined"
            or type(run.get("seed")) is not int or run["seed"] != seed
            or run.get("workload_hash_sha256") != manifest_sha256
            or type(run.get("max_response_bytes")) is not int
            or run["max_response_bytes"] != max_response_bytes
            or run.get("completion_status") != "complete"
            or run.get("error") is not None or run.get("error_class") is not None
            or run.get("terminal_evidence_render_errors") != []
            or not isinstance(run.get("migration_commit"), str)
            or _COMMIT.fullmatch(run["migration_commit"]) is None
            or native_commit is not None and run["migration_commit"] != native_commit):
        raise ValueError("Native run did not retain its complete bound GET execution")
    resources = manifest.get("resources")
    if not isinstance(resources, list) or not resources:
        raise ValueError("resource input is empty")
    by_id = {resource["id"]: resource for resource in resources}
    if len(by_id) != len(resources):
        raise ValueError("input resource IDs are duplicated")
    origins = {f"https://{urlsplit(resource['url']).hostname}" for resource in resources}
    endpoints = run.get("endpoints")
    if (len(origins) != 1 or not isinstance(endpoints, list) or len(endpoints) != 1
            or not isinstance(endpoints[0], Mapping)
            or type(endpoints[0].get("id")) is not int or endpoints[0]["id"] != 0
            or endpoints[0].get("origin") not in {next(iter(origins)), next(iter(origins)) + "/"}
            or endpoints[0].get("negotiated_protocol") != "h3"):
        raise ValueError("run does not have the one exact-host HTTP3 endpoint")
    responses = run.get("responses")
    if not isinstance(responses, list) or len(responses) != len(resources):
        raise ValueError("Native response coverage differs from every selected resource")
    checked, seen = [], set()
    for response in responses:
        if (not isinstance(response, Mapping) or type(response.get("resource_id")) is not int
                or response["resource_id"] not in by_id or response["resource_id"] in seen):
            raise ValueError("Native response IDs are missing, extra or duplicated")
        identifier = response["resource_id"]
        resource = by_id[identifier]
        headers = response.get("response_headers")
        if (not isinstance(headers, list)
                or any(not isinstance(pair, list) or len(pair) != 2
                       or any(not isinstance(value, str) for value in pair) for pair in headers)):
            raise ValueError("Native response headers are absent or malformed")
        size, status = response.get("bytes"), response.get("status")
        if (response.get("url") != resource["url"]
                or response.get("request_headers") != resource["headers"]
                or type(status) is not int or not 200 <= status < 300
                or type(size) is not int or not 0 < size <= max_response_bytes
                or response.get("complete") is not True or response.get("outcome") != "succeeded"
                or not isinstance(response.get("body_sha256"), str)
                or _SHA256.fullmatch(response["body_sha256"]) is None
                or response["body_sha256"] == _EMPTY_SHA256
                or type(response.get("request_stream_bytes")) is not int
                or response["request_stream_bytes"] <= 0
                or [value for name, value in headers if name.lower() == ":status"] != [str(status)]):
            raise ValueError("selected resource was not delivered complete, nonempty and HTTP2xx")
        lengths = [value for name, value in headers if name.lower() == "content-length"]
        length = response.get("content_length")
        if (length is not None and (type(length) is not int or length != size)
                or lengths and (len(lengths) != 1 or lengths[0] != str(size) or length != size)):
            raise ValueError("actual Content-Length contradicts response completion")
        seen.add(identifier)
        checked.append(dict(response))
    return sorted(checked, key=lambda response: response["resource_id"])


def _checked_operation(directory: Path, manifest: dict[str, Any], *,
                       client: Path, runtime: Mapping[str, Any] | None,
                       client_sha256: str, timeout: int,
                       max_response_bytes: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = _write(directory / "input.json", manifest)
    command = probe_command(client, path, directory / "native", timeout=timeout,
                            max_response_bytes=max_response_bytes)
    completed = _execute(command, directory, timeout=timeout, client_sha256=client_sha256)
    if completed["returncode"] != 0 or completed["timed_out"] or not completed["client_unchanged"]:
        raise ValueError("actual Native GET process failed; retained operation is not qualification")
    run = _object(directory / "native/run.json")
    resolved = run.get("resolved_configuration")
    if (not isinstance(resolved, dict) or resolved.get("defense") != {"kind": "none"}
            or run.get("application_response_policy") != "http-2xx-only-v1"
            or run.get("application_workload_source_hash_sha256") is not None
            or run.get("chaff_manifest_hash_sha256") is not None
            or run.get("chaff_responses") != []):
        raise ValueError("probe changed its strict undefended GET inputs")
    responses = inspect_completed_run(run, manifest, manifest_sha256=sha256_file(path),
        max_response_bytes=max_response_bytes,
        native_commit=runtime["native_commit"] if runtime else None)
    return run, responses


def _probe_transport_evidence(directory: Path, *, client_sha256: str,
                              native_commit: str | None) -> dict[str, Any]:
    """Describe an observed transport failure without declaring a host invalid.

    HTTP errors or any actual H3 negotiation prove transport availability.
    Unrelated CLI/configuration, provenance and artifact failures are not
    silently recategorized as an unsupported transport. A host-enforced child
    timeout without a retained H3 observation is only transport-unconfirmed.
    """
    evidence = {"confirmed_h3": False, "transport_failure": False, "reason": None}
    try:
        completed = _object(directory / "completed.json")
        if (completed.get("client_sha256") != client_sha256
                or completed.get("client_unchanged") is not True):
            return evidence
        run_path = directory / "native/run.json"
        if not run_path.is_file():
            if completed.get("timed_out") is True:
                evidence.update(transport_failure=True, reason="child-timeout-without-retained-http3-evidence")
            return evidence
        run = _object(run_path)
        if (run.get("workload_hash_sha256") != sha256_file(directory / "input.json")
                or run.get("method") != "GET" or run.get("request_policy") != "as-defined"
                or native_commit is not None and run.get("migration_commit") != native_commit):
            return evidence
        endpoints, responses = run.get("endpoints"), run.get("responses")
        h3 = isinstance(endpoints, list) and any(isinstance(endpoint, dict)
            and endpoint.get("negotiated_protocol") == "h3" for endpoint in endpoints)
        # Even a refused or truncated HTTP response is evidence of a working
        # transport; it must not cause the remaining URL pool to be skipped.
        http = isinstance(responses, list) and any(isinstance(response, dict)
            and type(response.get("status")) is int and 100 <= response["status"] < 600
            for response in responses)
        if h3 or http:
            evidence["confirmed_h3"] = h3
            evidence["reason"] = "http3-negotiated" if h3 else "http-response-observed"
            return evidence
        error = run.get("error")
        known_transport_error = (run.get("error_class") == "runner-execution-v1"
            and isinstance(error, str)
            and re.search(r"\b(connection|connect|handshake|transport|protocol|tls|certificate)\b", error, re.I))
        if run.get("error_class") == "timeout-v1" or known_transport_error:
            evidence.update(transport_failure=True, reason="native-fresh-client-transport-failure-before-http3")
        elif completed.get("timed_out") is True:
            evidence.update(transport_failure=True, reason="child-timeout-without-retained-http3-evidence")
    except (ValueError, OSError, json.JSONDecodeError):
        pass  # Unknown/malformed evidence is not a transport diagnosis.
    return evidence


def probe_urls(hostname: str, urls: Iterable[str], output: str | Path, *,
               client: str | Path = DEFAULT_CLIENT, timeout: int = 120,
               max_response_bytes: int = MAX_RESPONSE_BYTES,
               stop_after: int | None = None,
               transport_failure_limit: int = 3,
               runtime: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Probe URLs independently in source order; failed attempts remain on disk.

    A stop_after cutoff leaves the unattempted tail explicitly unassessed. This
    probe establishes no captured connection or scientific session count.
    """
    pool = _manifest(hostname, urls, require_twenty=False)
    _positive(timeout, "timeout")
    _positive(max_response_bytes, "max_response_bytes")
    if stop_after is not None:
        _positive(stop_after, "stop_after")
    _positive(transport_failure_limit, "transport_failure_limit")
    if runtime is not None:
        executable, bound = _runtime(runtime, client)
        digest = bound["client_sha256"]
    else:
        executable = _regular(client)
        if not os.access(executable, os.X_OK):
            raise ValueError("Native client is not executable")
        bound, digest = None, sha256_file(executable)
    root = _new_directory(output)
    records, selected = [], []
    consecutive_transport_failures, transport_established, deferred = 0, False, None
    for index, resource in enumerate(pool["resources"]):
        directory = _new_directory(root / f"url-{index:04d}")
        single = {"resources": [{**resource, "id": 0}]}
        record: dict[str, Any] = {"index": index, "url": resource["url"],
            "directory": str(directory), "run": str(directory / "native/run.json"),
            "accepted": False, "error": None}
        try:
            _, responses = _checked_operation(directory, single, client=executable,
                runtime=bound, client_sha256=digest, timeout=timeout,
                max_response_bytes=max_response_bytes)
            record.update(accepted=True, response=responses[0])
            selected.append(resource["url"])
        except (ValueError, OSError, json.JSONDecodeError) as error:
            record["error"] = str(error)
        transport = _probe_transport_evidence(directory, client_sha256=digest,
            native_commit=bound["native_commit"] if bound else None)
        record["transport"] = transport
        if record["accepted"] or transport["confirmed_h3"] or transport["reason"] == "http-response-observed":
            transport_established = True
        if not transport_established and transport["transport_failure"]:
            consecutive_transport_failures += 1
        else:
            consecutive_transport_failures = 0
        _write(directory / "probe-result.json", record)
        records.append(record)
        if not transport_established and consecutive_transport_failures >= transport_failure_limit:
            deferred = {"status": "transient-deferred", "retryable": True,
                "reason": "consecutive-fresh-client-transport-failures-before-http3",
                "consecutive_failures": consecutive_transport_failures,
                "failure_limit": transport_failure_limit,
                "permanent_host_ineligibility_claimed": False}
            break
        if stop_after is not None and len(selected) >= stop_after:
            break
    result = {"schema_version": 1, "role": ROLE, "client_sha256": digest,
        "hostname": urlsplit(pool["resources"][0]["url"]).hostname,
        "selected_urls": selected, "results": records,
        "transport_established": transport_established, "deferred": deferred,
        "unassessed_urls": [resource["url"] for resource in pool["resources"][len(records):]],
        "scientific_credit": False}
    _write(root / "probe.json", result)
    return result


def mode_policies() -> dict[str, dict[str, Any]]:
    """Expose the existing fixed policies explicitly, before any capture."""
    from . import front_fixed_configuration as front, front_incoming_acceptance as incoming
    from . import tamaraw_fixed_configuration as tamaraw, buflo_duration_budget as buflo
    from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
    common = {"application_body_identity_policy": COMPLETE_APPLICATION_DELIVERY_POLICY}
    return {"undefended": dict(common),
        "front": {**common, front.FIELD: front.POLICY, incoming.FIELD: incoming.POLICY},
        "tamaraw": {**common, tamaraw.FIELD: tamaraw.POLICY},
        "buflo": {**common, "buflo_duration_policy": buflo.CADENCE64_POLICY},
        "cs-buflo": {**common, "parameter_policy": "fixed-cs-buflo-cpsp-live-v1"}}


def _parameter_bundle(root: Path) -> dict[str, Path]:
    from . import front_fixed_configuration as front, tamaraw_fixed_configuration as tamaraw
    from . import buflo_duration_budget as buflo
    from .util import LAB_ROOT
    source = _regular(LAB_ROOT / "config/defense-params/cs-buflo-cpsp-live.json")
    return {"front_config": _write(root / "params/front.toml", front.configuration_bytes(), raw=True),
        "tamaraw_config": _write(root / "params/tamaraw.toml", tamaraw.configuration_bytes(), raw=True),
        "buflo_parameters": _write(root / "params/buflo.json", buflo.cadence64_parameter_bytes(), raw=True),
        "cs_buflo_parameters": _write(root / "params/cs-buflo.json", source.read_bytes(), raw=True)}


def _qualify(prepared: Path, resources: list[dict[str, Any]], responses: list[dict[str, Any]],
             root: Path, client: Path, runtime: Mapping[str, Any]) -> dict[str, Any]:
    from . import chaff_qualification as chaff
    # Native's legacy/schema3 selector includes the resource0 anchor and has
    # no upper length filter. Select exactly its largest body, tie by ID/URL.
    # Choosing a smaller convenient resource would qualify locally and then
    # fail the actual runtime selector. Keep the ordinary lane if the strict
    # explicitly declared new-role16MiB cap cannot cover that selected body.
    candidates = [row for row in responses if row["bytes"] >= 1200]
    candidates.sort(key=lambda row: (-row["bytes"], row["resource_id"], row["url"]))
    candidates = candidates[:1]
    failures = []
    prepared_sha = sha256_file(prepared)
    for candidate in candidates:
        identifier = candidate["resource_id"]
        selected = resources[identifier]
        directory = _new_directory(root / f"resource-{identifier:02d}")
        try:
            if candidate["bytes"] > MAX_RESPONSE_BYTES:
                raise ValueError("deterministic selected chaff body exceeds the declared16MiB ceiling")
            runs = []
            for index in range(chaff.QUALIFICATION_RUNS):
                operation = _new_directory(directory / f"response-{index}")
                command = qualification_command(client, prepared, operation / "native", identifier)
                actual = _execute(command, operation, timeout=120,
                                  client_sha256=runtime["client_sha256"])
                if actual["returncode"] != 0 or actual["timed_out"] or not actual["client_unchanged"]:
                    raise ValueError("actual Native response qualification process failed")
                receipt = _object(operation / "native/qualification.json")
                if chaff._receipt_neqo_provenance(receipt)["migration_commit"] != runtime["native_commit"]:
                    raise ValueError("response qualification changed Native source identity")
                runs.append(receipt)
            expected, request_size = chaff._stable_response_identity(runs,
                application_manifest_sha256=prepared_sha, application_resource_id=0,
                selected_chaff_resource_id=identifier, qualified_parallel_chaff_streams=5,
                url=selected["url"], headers=selected["headers"],
                resource_domain_max_response_bytes=MAX_RESPONSE_BYTES)
            records = [chaff._response_run_record(index, run) for index, run in enumerate(runs)]
            digest = chaff.qualification_digest("qcsd-chaff-response-qualification-v2", records)
            evidence = {"schema_version": 1, "selected_chaff_resource_id": identifier,
                "application_workload_sha256": prepared_sha, "response_runs": records,
                "expected_response": expected, "request_stream_bytes": request_size,
                "response_qualification_sha256": digest, "failures": failures,
                "max_response_bytes": MAX_RESPONSE_BYTES,
                "scientific_credit": False}
            _write(root / "response-qualification.json", evidence)
            core = chaff.derive_chaff_core(application_manifest_sha256=prepared_sha,
                base_resource=selected, headers=selected["headers"], request_stream_bytes=request_size,
                expected_response=expected, response_qualification_sha256=digest,
                application_resource_id=0, selected_chaff_resource_id=identifier,
                qualified_parallel_chaff_streams=5, walkie_talkie_required_chaff_streams=20)
            sidecar = {"base_manifest": {"sha256": prepared_sha}, "application_resource_id": 0,
                "selected_chaff_resource_id": identifier, "resource": {
                    "headers": selected["headers"], "expected_response": expected,
                    "request_stream_bytes": request_size, "response_qualification_sha256": digest}}
            return {"core": core, "manifest": chaff.derive_response_only_chaff_manifest(sidecar, selected),
                    "evidence": evidence, "error": None}
        except (ValueError, OSError, chaff.PreparationError) as error:
            failure = {"resource_id": identifier, "error": str(error)}
            failures.append(failure)
            _write(directory / "failure.json", failure)
    error = "deterministic selected resource did not complete the actual three-run chaff qualification"
    _write(root / "qualification-failed.json", {"error": error, "failures": failures,
                                               "scientific_credit": False})
    return {"core": None, "manifest": None, "evidence": None, "error": error}


def _files(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("enrollment inventory contains a symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha256_file(path)
    return result


def _mode_settings(paths: Mapping[str, Path | None]) -> dict[str, dict[str, Any]]:
    from . import front_fixed_configuration as front, tamaraw_fixed_configuration as tamaraw
    from . import buflo_duration_budget as buflo
    common = {"profile": "research-1200", "request_policy": "as-defined",
              "max_response_bytes": MAX_RESPONSE_BYTES, "udp_payload_ceiling": 1200}
    settings = {mode: {**common, "policies": mode_policies()[mode]} for mode in MODES}
    settings["undefended"].update(defense="none", timeout_seconds=120, capture_seconds=180)
    for mode, module, key in (("front", front, "front_config"),
                               ("tamaraw", tamaraw, "tamaraw_config")):
        settings[mode].update(configuration_sha256=sha256_file(paths[key]),
            resolved_configuration=module.resolved_configuration(),
            timeout_seconds=120, capture_seconds=180)
    for mode, key in (("buflo", "buflo_parameters"), ("cs-buflo", "cs_buflo_parameters")):
        settings[mode].update(parameters_sha256=sha256_file(paths[key]),
            parameters=_object(paths[key]), timeout_seconds=680 if mode == "buflo" else 120,
            capture_seconds=740 if mode == "buflo" else 180)
    buflo.validate_parameters(settings["buflo"]["parameters"])
    return settings


def prepare_domain(hostname: str, urls: Iterable[str], output: str | Path, *,
                   client: str | Path = DEFAULT_CLIENT,
                   runtime: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze20 real GET URLs, with an ordinary lane independent of chaff failures.

    Pools are probed in their given order until20 individually complete URLs
    are found; the selected20 are then replayed together. Every attempted URL
    and failed qualifier remains retained. There is no resource substitution
    after enrollment, no fitter, and no HTML or cross-origin claim.
    """
    pool = _manifest(hostname, urls, require_twenty=False)
    if len(pool["resources"]) < RESOURCES_PER_SESSION:
        raise ValueError("candidate pool has fewer than20 distinct same-host URLs")
    executable, bound = _runtime(runtime, client)
    root = _new_directory(output)
    probe = probe_urls(hostname, [resource["url"] for resource in pool["resources"]],
        root / "probe", client=executable, stop_after=RESOURCES_PER_SESSION, runtime=bound)
    urls20 = probe["selected_urls"]
    if probe["deferred"] is not None:
        _write(root / "preparation-deferred.json", {**probe["deferred"], "role": ROLE,
            "hostname": probe["hostname"], "probe": "probe/probe.json",
            "scientific_credit": False})
        raise ValueError("domain preparation transient-deferred after repeated fresh-client transport failures; retryable")
    if len(urls20) != RESOURCES_PER_SESSION:
        raise ValueError("candidate pool did not yield20 actual complete nonempty HTTP3 GETs")
    input_manifest = _manifest(hostname, urls20, require_twenty=True)
    actual_dir = _new_directory(root / "preparation-get")
    _, responses = _checked_operation(actual_dir, input_manifest, client=executable,
        runtime=bound, client_sha256=bound["client_sha256"], timeout=120,
        max_response_bytes=MAX_RESPONSE_BYTES)
    lengths = {row["url"]: row["bytes"] for row in responses}
    manifest = native_manifest(hostname, urls20, lengths)
    for resource in manifest["resources"]:
        resource["headers"] = [pair[:] for pair in REQUEST_HEADERS]
    manifest["resources"][0]["type"] = "Document"
    from . import capture_acceptance_policy as acceptance
    expected = [{key: row[key] for key in ("resource_id", "status", "bytes", "body_sha256")}
                for row in responses]
    preparation = {"role": ROLE, "hostname": probe["hostname"], "runtime": bound,
        "resource_anchor": {"resource_id": 0, "url": urls20[0],
                            "meaning": "internal-Native-resource-anchor-only",
                            "html_or_navigation_claimed": False},
        "max_response_bytes": MAX_RESPONSE_BYTES, "expected_responses": expected,
        "response_qualification_max_response_bytes": MAX_RESPONSE_BYTES,
        "actual_preparation_run": "preparation-get/native/run.json",
        "actual_preparation_run_sha256": sha256_file(actual_dir / "native/run.json"),
        "application_response_policy": "completed-terminal-http-errors-v1",
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1",
        "approved_origins": [f"https://{probe['hostname']}"],
        acceptance.FRONT_FIELD: acceptance.FRONT_LIGHT_POLICY,
        acceptance.TAMARAW_FIELD: acceptance.TAMARAW_POLICY,
        acceptance.TERMINAL_PRIMARY_FIELD: acceptance.TERMINAL_PRIMARY_POLICY,
        acceptance.FIELD: acceptance.CADENCE64_ACK_START_POLICY,
        acceptance.BUFLO_KERNEL_PREPARATION_FIELD: acceptance.CADENCE64_KERNEL_PREPARATION_POLICY,
        "outer_response_contract": "every-selected-resource-complete-nonempty-http2xx-h3-v1"}
    manifest_path = _write(root / "resources.json", manifest)
    prepared = _write(root / "prepared-workload.json", {"preparation": preparation, **manifest})
    paths: dict[str, Path | None] = {"manifest": manifest_path, "prepared_workload": prepared,
        "expected_responses": _write(root / "expected-responses.json", {"responses": expected}),
        **_parameter_bundle(root)}
    qualified = _qualify(prepared, manifest["resources"], responses,
                         _new_directory(root / "qualification"), executable, bound)
    paths["chaff_core"] = _write(root / "chaff-core.json", qualified["core"]) if qualified["core"] else None
    paths["chaff_manifest"] = _write(root / "chaff-manifest.json", qualified["manifest"]) if qualified["manifest"] else None
    # This self inventory deliberately excludes enrollment.json, whose digest
    # is returned separately for the outer coordinator's immutable reference.
    enrollment = {"schema_version": 1, "role": ROLE, "hostname": probe["hostname"],
        "urls": urls20, "workload_path": "resources.json", "workload_sha256": sha256_file(manifest_path),
        "paths": {key: value.relative_to(root).as_posix() if value else None for key, value in paths.items()},
        "files": _files(root), "runtime": bound, "mode_policies": mode_policies(),
        "mode_settings": _mode_settings(paths),
        "mode_readiness": {mode: mode == "undefended" or qualified["error"] is None for mode in MODES},
        "qualification_error": qualified["error"], "scientific_credit": False}
    enrollment_path = _write(root / "enrollment.json", enrollment)
    return {**enrollment, "workload_path": str(manifest_path),
        "paths": {**{key: str(value) if value else None for key, value in paths.items()},
                  "enrollment": str(enrollment_path)},
        "files": _files(root), "enrollment_sha256": sha256_file(enrollment_path)}


def _same_native_runtime(prepared: Any, actual: Mapping[str, Any]) -> bool:
    if not isinstance(prepared, Mapping):
        return False
    for field in ("client_sha256", "native_commit", "platform"):
        if field in prepared or field in actual:
            if prepared.get(field) != actual.get(field):
                return False
    old_source, new_source = prepared.get("source"), actual.get("source")
    old_commit = old_source.get("neqo_commit") if isinstance(old_source, Mapping) else None
    new_commit = new_source.get("neqo_commit") if isinstance(new_source, Mapping) else None
    return old_commit == new_commit


def _enrollment(directory: str | Path, hostname: str, runtime: Mapping[str, Any]) -> tuple[Path, dict[str, Any]]:
    root = Path(os.path.abspath(directory))
    enrollment = _object(root / "enrollment.json")
    canonical_host = urlsplit(native_manifest(hostname, [f"https://{hostname}/"], require_twenty=False)
                              ["resources"][0]["url"]).hostname
    if (enrollment.get("schema_version") != 1 or enrollment.get("role") != ROLE
            or enrollment.get("hostname") != canonical_host
            or not _same_native_runtime(enrollment.get("runtime"), runtime)
            or enrollment.get("mode_policies") != mode_policies()):
        raise ValueError("enrollment host, role, runtime or fixed policies changed")
    files = enrollment.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("enrollment lacks its actual file inventory")
    for relative, digest in files.items():
        if not isinstance(relative, str):
            raise ValueError("enrollment inventory path must be a string")
        path = Path(relative)
        if (path.is_absolute() or ".." in path.parts or relative != path.as_posix()
                or not isinstance(digest, str) or _SHA256.fullmatch(digest) is None):
            raise ValueError("enrollment file digest or containment changed")
    # Rehash the finite launch inputs here. The coordinator seals and checks
    # the complete preparation inventory once; historical failed URL probes
    # are not rescanned for every one of100,000 prospective sessions.
    for value in enrollment["paths"].values():
        if value is not None:
            if value not in files or sha256_file(_regular(root / value)) != files[value]:
                raise ValueError("enrollment launch path or digest changed")
    if enrollment.get("workload_path") != enrollment["paths"].get("manifest"):
        raise ValueError("enrollment manifest reference changed")
    if files[enrollment["workload_path"]] != enrollment.get("workload_sha256"):
        raise ValueError("enrollment workload digest changed")
    native_manifest(canonical_host, enrollment["urls"])
    actual_paths = {key: root / value if value else None for key, value in enrollment["paths"].items()}
    if enrollment.get("mode_settings") != _mode_settings(actual_paths):
        raise ValueError("enrollment mode settings differ from actual fixed input bytes")
    return root, enrollment


def _capture_inputs(mode: str, root: Path, enrollment: Mapping[str, Any]):
    from . import capture_session as collector
    from . import buflo_duration_budget as buflo
    policies = enrollment["mode_policies"][mode]
    limits = buflo.capture_limits(mode, {"timeout_seconds": 120, "capture_seconds": 180},
        policy=buflo.CADENCE64_POLICY if mode == "buflo" else None)
    context = SimpleNamespace(qcsd_profile="research-1200", request_policy="as-defined",
        udp_payload_ceiling=1200, limits=collector.Limits(**limits, max_response_bytes=MAX_RESPONSE_BYTES,
            capture_megabytes=256, max_attempts=1), **policies)
    if mode == "front":
        context.front_configuration_path = root / enrollment["paths"]["front_config"]
    if mode == "tamaraw":
        context.tamaraw_configuration_path = root / enrollment["paths"]["tamaraw_config"]
    kind = {"undefended": "none", "cs-buflo": "cs_buflo"}.get(mode, mode)
    parameter_key = {"buflo": "buflo_parameters", "cs-buflo": "cs_buflo_parameters"}.get(mode)
    parameters = {}
    if parameter_key:
        from . import parameters as parameter_artifacts
        from .util import LAB_ROOT
        # Enrollment freezes the parameter bytes once. Its original names are
        # intentionally independent of the SDK's provenance filenames.
        relative = enrollment["paths"][parameter_key]
        if (not isinstance(relative, str) or Path(relative).is_absolute()
                or ".." in Path(relative).parts):
            raise ValueError("enrolled defense parameter path is not relative")
        parameter_path = _regular(root / relative)
        source_name = {"buflo": "buflo-cadence64-budget640.json",
                       "cs-buflo": "cs-buflo-cpsp-live.json"}[mode]
        source = _regular(LAB_ROOT / "config/defense-params" / source_name)
        provenance = _regular(parameter_artifacts.parameter_provenance_path(source))
        expected_policy = (buflo.CADENCE64_POLICY if mode == "buflo"
                           else "fixed-cs-buflo-cpsp-live-v1")
        policy_field = "buflo_duration_policy" if mode == "buflo" else "parameter_policy"
        if policies.get(policy_field) != expected_policy:
            raise ValueError("reactive defense policy differs from enrolled fixed mode")
        artifact = parameter_artifacts.validate_parameter_artifact(
            source, provenance_path=provenance, expected_kind=kind,
            allow_study_candidate=True, expected_qcsd_profile=context.qcsd_profile,
            expected_udp_payload_ceiling=context.udp_payload_ceiling)
        expected_input_policy = (buflo.CADENCE64_INPUT_POLICY if mode == "buflo"
                                else parameter_artifacts.BUFLO_STUDY_PARAMETER_INPUT_POLICY)
        if (artifact.sha256 != enrollment["files"][relative]
                or sha256_file(parameter_path) != artifact.sha256
                or artifact.input_policy != expected_input_policy):
            raise ValueError("enrolled defense parameter bytes differ from SDK provenance")
        parameters = {"parameters": relative, "parameters_path": parameter_path,
            "parameters_sha256": artifact.sha256,
            "parameters_provenance": provenance.relative_to(LAB_ROOT).as_posix(),
            "parameters_provenance_path": provenance,
            "parameters_provenance_sha256": artifact.provenance_sha256,
            "parameters_input_policy": artifact.input_policy}
    defense = collector.Defense(name=mode, kind=kind, baseline=mode == "undefended", **parameters)
    return defense, context


def capture_session(hostname: str, mode: str, enrollment_dir: str | Path,
                    attempt_dir: str | Path, *, seed: int,
                    runtime: Mapping[str, Any], client: str | Path = DEFAULT_CLIENT) -> dict[str, Any]:
    """Collect one fresh connection; return actual artifacts, never a receipt.

    The observer and scheduler environment must already satisfy the unchanged
    collector. Failed attempts remain intact and cannot gain scientific credit.
    The attempt directory must not exist; its parent may be store allocated.
    """
    if mode not in MODES or type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError("capture mode or u64 seed is invalid")
    executable, bound = _runtime(runtime, client)
    root, enrollment = _enrollment(enrollment_dir, hostname, bound)
    from . import capture_session as collector
    if _regular(collector.NEQO_CLIENT) != executable:
        raise ValueError("collector executable differs; set NEQO_QCSD_CLIENT before import")
    if enrollment["mode_readiness"].get(mode) is not True:
        raise ValueError("mode has no actual preparation/response-chaff qualification")
    attempt = Path(os.path.abspath(attempt_dir))
    if (attempt.exists() or any(parent.is_symlink() for parent in (attempt, *attempt.parents))
            or attempt == root or attempt.is_relative_to(root) or root.is_relative_to(attempt)):
        raise ValueError("attempt must be a fresh nonsymlink directory disjoint from enrollment")
    manifest = root / enrollment["paths"]["manifest"]
    prepared = root / enrollment["paths"]["prepared_workload"]
    chaff = root / enrollment["paths"]["chaff_manifest"] if mode != "undefended" else None
    defense, context = _capture_inputs(mode, root, enrollment)
    result = collector._collect_attempt(attempt, manifest, chaff, hostname, defense, seed, context,
        application_workload_source=prepared if mode != "undefended" else None,
        application_response_policy="completed-terminal-http-errors-v1" if mode != "undefended" else "http-2xx-only-v1")
    checked, error = None, None
    try:
        if sha256_file(executable) != bound["client_sha256"]:
            raise ValueError("Native executable changed during capture")
        _enrollment(root, hostname, bound)
        checked = inspect_completed_run(_object(attempt / "neqo/run.json"), _object(manifest),
            manifest_sha256=enrollment["workload_sha256"], max_response_bytes=MAX_RESPONSE_BYTES,
            native_commit=bound["native_commit"], seed=seed)
    except (ValueError, OSError, json.JSONDecodeError) as failure:
        error = str(failure)
    resource_check = _write(attempt / "resource-check.json", {
        "schema_version": 1, "role": ROLE, "hostname": enrollment["hostname"], "mode": mode,
        "passed": checked is not None, "error": error, "responses": checked,
        "required_resources": RESOURCES_PER_SESSION, "scientific_credit": False})
    paths = {"native_run": attempt / "neqo/run.json", "native_events": attempt / "neqo/events.csv",
        "native_packets": attempt / "neqo/packets.csv", "native_schedule": attempt / "neqo/schedule.csv",
        "collector_attempt": attempt / "attempt.json", "raw_capture": attempt / "diagnostics/direct-quic-raw.pcapng",
        "capture": attempt / "captures/direct-quic.pcapng", "trace": attempt / "traces/direct-quic.csv",
        "collector_log": attempt / "diagnostics/neqo-client.log", "resource_check": resource_check}
    summary = {"schema_version": 1, "role": ROLE, "hostname": enrollment["hostname"],
        "mode": mode, "seed": seed, "runtime": bound, "mode_policies": enrollment["mode_policies"][mode],
        "mode_settings": enrollment["mode_settings"][mode],
        "success": result.get("success") is True and checked is not None,
        "result": result, "resource_error": error, "scientific_credit": False,
        "paths": {key: str(value) if value.is_file() else None for key, value in paths.items()}}
    summary_path = _write(attempt / "session-result.json", summary)
    return {**summary, **summary["paths"], "session_result": str(summary_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("_prepare", "_capture", "_probe"))
    parser.add_argument("--job", type=Path, required=True)
    args = parser.parse_args(argv)
    job = _object(args.job)
    function = {"_prepare": prepare_domain, "_capture": capture_session, "_probe": probe_urls}[args.action]
    result = function(**job)
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
