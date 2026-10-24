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
BUFLO_CAPPED_SELECTION_POLICY = "resource-domain-buflo-prepared-and-identity-body-cap-descending-prefix-v1"
BUFLO_CAPPED_SELECTION_TYPE = "qcsd-resource-domain-buflo-capped-chaff-selection-v1"
BUFLO_CAPPED_SIDECAR_TYPE = "qcsd-resource-domain-buflo-capped-identity-chaff-qualification-v1"
BUFLO_AGGREGATE_SELECTION_POLICY = "resource-domain-buflo-original-auxiliary-small-response-eight-known-capacity-v1"
BUFLO_AGGREGATE_SELECTION_TYPE = "qcsd-resource-domain-buflo-small-response-eight-aggregate-selection-v1"
BUFLO_AGGREGATE_SIDECAR_TYPE = "qcsd-resource-domain-buflo-small-response-eight-aggregate-qualification-v1"
BUFLO_AGGREGATE_NATIVE = '6ae3dc347be45622efcc723dc669860490142fcc'


def buflo_aggregate_native_supported(value: Any) -> bool:
    return (type(BUFLO_AGGREGATE_NATIVE) is str and _COMMIT.fullmatch(BUFLO_AGGREGATE_NATIVE) is not None
            and type(value) is str and value == BUFLO_AGGREGATE_NATIVE)


def _buflo_aggregate_option(value: Any, cap: int | None = None) -> bool:
    if type(value) is not bool or value and cap is not None:
        raise ValueError("small-response aggregate requires an explicit boolean and excludes the cap option")
    return value


def buflo_aggregate_selection() -> dict[str, Any]:
    from .chaff_qualification import SMALL_RESPONSE_AGGREGATE_CONTRACT_SHA256
    return {"schema_version": 1, "record_type": BUFLO_AGGREGATE_SELECTION_TYPE,
        "selection_policy": BUFLO_AGGREGATE_SELECTION_POLICY,
        "aggregate_capacity_contract_sha256": SMALL_RESPONSE_AGGREGATE_CONTRACT_SHA256}


def _buflo_chaff_cap(value: Any) -> int | None:
    if value is not None and (type(value) is not int or not 1200 <= value <= 1_048_576):
        raise ValueError("BuFLO chaff cap must be an integer from1200 through1048576 bytes")
    return value


def _buflo_capped_candidates(prepared: Mapping[str, Any], cap: int) -> list[tuple[dict, dict]]:
    """Filter the original twenty; never change application resources or order."""
    if _buflo_chaff_cap(cap) is None:
        raise ValueError("capped selection requires an explicit cap")
    resources = prepared["resources"]
    responses = prepared["preparation"]["expected_responses"]
    if (type(resources) is not list or type(responses) is not list
            or len(resources) != 20 or len(responses) != 20
            or [row.get("id") for row in resources] != list(range(20))
            or any(type(row.get("id")) is not int for row in resources)
            or any(type(row.get("resource_id")) is not int for row in responses)
            or {row["resource_id"] for row in responses} != set(range(20))):
        raise ValueError("capped qualification requires all twenty original prepared identities")
    expected = {row["resource_id"]: row for row in responses}
    hosts = {urlsplit(row["url"]).hostname for row in resources}
    if len(hosts) != 1 or None in hosts:
        raise ValueError("capped qualification must stay on the original resource hostname")
    if (prepared["preparation"].get("qualified_chaff_origin_policy") != "prepared-approved-origins-v1"
            or prepared["preparation"].get("approved_origins") != ["https://" + next(iter(hosts))]):
        raise ValueError("capped qualification changed the original approved origin")
    candidates = []
    for resource in resources:
        row = expected[resource["id"]]
        if (resource.get("known_valid") is not True or resource.get("depends_on") != []
                or resource.get("headers") != REQUEST_HEADERS
                or urlsplit(resource["url"]).scheme != "https"
                or type(row.get("status")) is not int or not 200 <= row["status"] < 300
                or type(row.get("bytes")) is not int or not 0 < row["bytes"] <= MAX_RESPONSE_BYTES
                or type(row.get("body_sha256")) is not str
                or _SHA256.fullmatch(row["body_sha256"]) is None):
            raise ValueError("capped qualification changed an original complete prepared GET")
        # The unchanged approved-origin Native schema-four contract selects
        # an auxiliary response; resource0 remains the application anchor.
        if resource["id"] != 0 and 1200 <= row["bytes"] <= cap:
            candidates.append((resource, row))
    return sorted(candidates, key=lambda pair: (-pair[1]["bytes"], pair[0]["id"], pair[0]["url"]))


def _validate_buflo_capped_sidecar(prepared: Mapping[str, Any], prepared_sha256: str,
                                  sidecar: Mapping[str, Any], manifest: Mapping[str, Any],
                                  runtime: Mapping[str, Any], cap: int) -> None:
    """Independently replay the scoped policy and all sustained receipt guards."""
    from . import chaff_qualification as chaff
    fields = {"schema_version", "record_type", "selection_policy", "cap_bytes",
        "application_workload_sha256", "application_resource_id", "selected_chaff_resource_id",
        "qualified_parallel_chaff_streams", "qualification_policy", "runtime", "neqo_provenance",
        "candidate_attempts", "selection_outcomes", "resource", "native_manifest_sha256", "scientific_credit"}
    candidates = _buflo_capped_candidates(prepared, cap)
    if (type(sidecar) is not dict or set(sidecar) != fields
            or type(sidecar["schema_version"]) is not int or sidecar["schema_version"] != 1
            or sidecar["record_type"] != BUFLO_CAPPED_SIDECAR_TYPE
            or sidecar["selection_policy"] != BUFLO_CAPPED_SELECTION_POLICY
            or type(sidecar["cap_bytes"]) is not int or sidecar["cap_bytes"] != cap
            or sidecar["application_workload_sha256"] != prepared_sha256
            or type(sidecar["application_resource_id"]) is not int or sidecar["application_resource_id"] != 0
            or type(sidecar["selected_chaff_resource_id"]) is not int
            or type(sidecar["qualified_parallel_chaff_streams"]) is not int
            or sidecar["qualified_parallel_chaff_streams"] != 5
            or sidecar["qualification_policy"] != chaff.response_only_v2_qualification_policy()
            or canonical_json(sidecar["runtime"]) != canonical_json(dict(runtime))
            or sidecar["scientific_credit"] is not False
            or type(sidecar["neqo_provenance"]) is not dict
            or sidecar["neqo_provenance"].get("migration_commit") != runtime["native_commit"]):
        raise ValueError("capped BuFLO sidecar policy, runtime or workload binding differs")
    chaff._validate_response_only_v2_policy(sidecar["qualification_policy"])
    attempts, outcomes = sidecar["candidate_attempts"], sidecar["selection_outcomes"]
    if (type(attempts) is not list or not 1 <= len(attempts) <= len(candidates)
            or type(outcomes) is not list or len(outcomes) != len(attempts)):
        raise ValueError("capped BuFLO attempts must be the exact nonempty eligible prefix")
    for index, (attempt, outcome) in enumerate(zip(attempts, outcomes)):
        resource, response = candidates[index]
        checked = chaff._validate_response_only_candidate_attempt(attempt,
            candidate_index=index, base_resource=resource, prepared_response=response,
            application_manifest_sha256=prepared_sha256, application_resource_id=0,
            neqo_provenance=sidecar["neqo_provenance"])
        epochs = [(row["process_exit_code"], row["receipt"]) for row in checked["connection_epochs"]]
        _, identity, _ = chaff._candidate_attempt_record_v2(candidate_index=index,
            base_resource=resource, prepared_response=response, epochs=epochs,
            application_manifest_sha256=prepared_sha256, application_resource_id=0,
            neqo_provenance=sidecar["neqo_provenance"])
        actual = "rejected" if identity is None else "over-cap" if identity["body_bytes"] > cap else "selected"
        if outcome != actual or (actual == "selected") != (index == len(attempts) - 1):
            raise ValueError("capped BuFLO selected candidate or earlier outcome differs")
    selected = candidates[len(attempts) - 1][0]
    if sidecar["selected_chaff_resource_id"] != selected["id"]:
        raise ValueError("capped BuFLO selected resource is outside its exact candidate prefix")
    resource = chaff._validate_response_only_v2_resource_receipt(sidecar["resource"], selected,
        selected_attempt=attempts[-1])
    if resource["expected_response"]["body_bytes"] > cap:
        raise ValueError("qualified BuFLO identity response exceeds its explicit cap")
    derived = chaff.derive_response_only_chaff_manifest_v2({"base_manifest": {"sha256": prepared_sha256},
        "application_resource_id": 0, "selected_chaff_resource_id": selected["id"], "resource": resource}, selected)
    digest = hashlib.sha256(canonical_json(derived)).hexdigest()
    if canonical_json(manifest) != canonical_json(derived) or sidecar["native_manifest_sha256"] != digest:
        raise ValueError("capped BuFLO sidecar does not derive the exact Native schema-four manifest")


def validate_buflo_capped_enrollment(root: Path, enrollment: Mapping[str, Any]) -> dict | None:
    """Validate only the explicit new branch; all launch files retain their hashes."""
    if "buflo_chaff_selection" not in enrollment:
        return None
    selection = enrollment["buflo_chaff_selection"]
    if (type(selection) is not dict or set(selection) != {"schema_version", "record_type", "selection_policy", "cap_bytes"}
            or type(selection["schema_version"]) is not int or selection["schema_version"] != 1
            or selection["record_type"] != BUFLO_CAPPED_SELECTION_TYPE
            or selection["selection_policy"] != BUFLO_CAPPED_SELECTION_POLICY
            or _buflo_chaff_cap(selection["cap_bytes"]) is None):
        raise ValueError("capped BuFLO enrollment selection declaration differs")
    keys = ("buflo_chaff_sidecar", "buflo_chaff_manifest")
    if enrollment["mode_readiness"].get("buflo") is not True:
        if (enrollment["mode_readiness"].get("buflo") is not False
                or type(enrollment.get("buflo_chaff_qualification_error")) is not str
                or not enrollment["buflo_chaff_qualification_error"]
                or any(enrollment["paths"].get(key) is not None for key in keys)):
            raise ValueError("unqualified capped BuFLO enrollment has launch inputs")
        return None
    if enrollment.get("buflo_chaff_qualification_error") is not None:
        raise ValueError("qualified capped BuFLO enrollment retains a qualification error")
    paths = {}
    for key in (*keys, "prepared_workload"):
        relative = enrollment["paths"].get(key)
        if (type(relative) is not str or Path(relative).is_absolute() or ".." in Path(relative).parts
                or str(Path(relative)) != relative):
            raise ValueError("capped BuFLO launch input path is not canonical and relative")
        path = _regular(root / relative)
        if sha256_file(path) != enrollment["files"].get(relative):
            raise ValueError("capped BuFLO launch input changed its enrollment digest")
        paths[key] = path
    prepared_sha = sha256_file(paths["prepared_workload"])
    sidecar = _object(paths["buflo_chaff_sidecar"])
    manifest = _object(paths["buflo_chaff_manifest"])
    _validate_buflo_capped_sidecar(_object(paths["prepared_workload"]), prepared_sha,
        sidecar, manifest, enrollment["runtime"], selection["cap_bytes"])
    if sidecar["native_manifest_sha256"] != sha256_file(paths["buflo_chaff_manifest"]):
        raise ValueError("capped BuFLO sidecar differs from the exact Native manifest bytes")
    return {**selection, "application_workload_sha256": prepared_sha,
        "selected_chaff_resource_id": sidecar["selected_chaff_resource_id"],
        "sidecar_sha256": sha256_file(paths["buflo_chaff_sidecar"]),
        "native_manifest_sha256": sha256_file(paths["buflo_chaff_manifest"])}


def _qualify_buflo_capped(prepared: Path, root: Path, client: Path,
                         runtime: Mapping[str, Any], cap: int) -> dict:
    """Run genuine three-by-forty identity qualification for a new BF policy."""
    from . import chaff_qualification as chaff
    base = _object(prepared); digest = sha256_file(prepared)
    attempts, outcomes, receipts = [], [], []
    for index, (candidate, response) in enumerate(_buflo_capped_candidates(base, cap)):
        directory = _new_directory(root / f"candidate-{index:03d}-resource-{candidate['id']:02d}")
        epochs = chaff._run_response_qualifications_v2(prepared, directory,
            selected_chaff_resource_id=candidate["id"], application_manifest_sha256=digest,
            application_resource_id=0, url=candidate["url"], headers=chaff.project_identity_chaff_headers(candidate),
            neqo_client=client, neqo_client_sha256=runtime["client_sha256"], timeout_seconds=120,
            interval_seconds=chaff.RESPONSE_ONLY_EPOCH_SPACING_SECONDS)
        receipts.extend(receipt for _, receipt in epochs)
        attempt, identity, request_bytes = chaff._candidate_attempt_record_v2(candidate_index=index,
            base_resource=candidate, prepared_response=response, epochs=epochs,
            application_manifest_sha256=digest, application_resource_id=0)
        attempts.append(attempt)
        outcome = "rejected" if identity is None else "over-cap" if identity["body_bytes"] > cap else "selected"
        outcomes.append(outcome)
        if outcome != "selected":
            continue
        resource = {"resource_id": candidate["id"], "url": candidate["url"],
            "headers": chaff.project_identity_chaff_headers(candidate), "request_stream_bytes": request_bytes,
            "expected_response": identity, "response_qualification_sha256": attempt["response_qualification_sha256"]}
        manifest = chaff.derive_response_only_chaff_manifest_v2({"base_manifest": {"sha256": digest},
            "application_resource_id": 0, "selected_chaff_resource_id": candidate["id"], "resource": resource}, candidate)
        sidecar = {"schema_version": 1, "record_type": BUFLO_CAPPED_SIDECAR_TYPE,
            "selection_policy": BUFLO_CAPPED_SELECTION_POLICY, "cap_bytes": cap,
            "application_workload_sha256": digest, "application_resource_id": 0,
            "selected_chaff_resource_id": candidate["id"], "qualified_parallel_chaff_streams": 5,
            "qualification_policy": chaff.response_only_v2_qualification_policy(), "runtime": dict(runtime),
            "neqo_provenance": chaff._stable_neqo_provenance(receipts), "candidate_attempts": attempts,
            "selection_outcomes": outcomes, "resource": resource,
            "native_manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(), "scientific_credit": False}
        _validate_buflo_capped_sidecar(base, digest, sidecar, manifest, runtime, cap)
        return {"sidecar": sidecar, "manifest": manifest, "error": None}
    error = "no capped BuFLO candidate passed the genuine sustained identity qualification"
    _write(root / "qualification-failed.json", {"error": error, "candidate_attempts": attempts,
        "selection_outcomes": outcomes, "scientific_credit": False})
    return {"sidecar": None, "manifest": None, "error": error}


def _buflo_aggregate_candidates(prepared: Mapping[str, Any]) -> list[tuple[dict, dict]]:
    """Filter the original twenty; never change application resources or order."""
    resources = prepared["resources"]
    responses = prepared["preparation"]["expected_responses"]
    if (type(resources) is not list or type(responses) is not list
            or len(resources) != 20 or len(responses) != 20
            or [row.get("id") for row in resources] != list(range(20))
            or any(type(row.get("id")) is not int for row in resources)
            or any(type(row.get("resource_id")) is not int for row in responses)
            or {row["resource_id"] for row in responses} != set(range(20))):
        raise ValueError("aggregate qualification requires all twenty original prepared identities")
    expected = {row["resource_id"]: row for row in responses}
    hosts = {urlsplit(row["url"]).hostname for row in resources}
    if len(hosts) != 1 or None in hosts:
        raise ValueError("aggregate qualification must stay on the original resource hostname")
    if (prepared["preparation"].get("qualified_chaff_origin_policy") != "prepared-approved-origins-v1"
            or prepared["preparation"].get("approved_origins") != ["https://" + next(iter(hosts))]):
        raise ValueError("aggregate qualification changed the original approved origin")
    candidates = []
    for resource in resources:
        row = expected[resource["id"]]
        if (resource.get("known_valid") is not True or resource.get("depends_on") != []
                or resource.get("headers") != REQUEST_HEADERS
                or urlsplit(resource["url"]).scheme != "https"
                or type(row.get("status")) is not int or not 200 <= row["status"] < 300
                or type(row.get("bytes")) is not int or not 0 < row["bytes"] <= MAX_RESPONSE_BYTES
                or type(row.get("body_sha256")) is not str
                or _SHA256.fullmatch(row["body_sha256"]) is None):
            raise ValueError("aggregate qualification changed an original complete prepared GET")
        # The approved-origin Native schema-six contract selects
        # an auxiliary response; resource0 remains the application anchor.
        if resource["id"] != 0 and 515 <= row["bytes"] < 1200:
            candidates.append((resource, row))
    return sorted(candidates, key=lambda pair: (-pair[1]["bytes"], pair[0]["id"], pair[0]["url"]))[:1]


def _validate_buflo_aggregate_sidecar(prepared: Mapping[str, Any], prepared_sha256: str,
                                  sidecar: Mapping[str, Any], manifest: Mapping[str, Any],
                                  runtime: Mapping[str, Any]) -> None:
    """Independently replay the scoped policy and all sustained receipt guards."""
    from . import chaff_qualification as chaff
    fields = {"schema_version", "record_type", "selection_policy", "aggregate_capacity_contract_sha256",
        "application_workload_sha256", "application_resource_id", "selected_chaff_resource_id",
        "qualified_parallel_chaff_streams", "qualification_policy", "runtime", "neqo_provenance",
        "candidate_attempts", "selection_outcomes", "resource", "native_manifest_sha256", "scientific_credit"}
    candidates = _buflo_aggregate_candidates(prepared)
    if (type(sidecar) is not dict or set(sidecar) != fields
            or type(sidecar["schema_version"]) is not int or sidecar["schema_version"] != 1
            or sidecar["record_type"] != BUFLO_AGGREGATE_SIDECAR_TYPE
            or sidecar["selection_policy"] != BUFLO_AGGREGATE_SELECTION_POLICY
            or sidecar["aggregate_capacity_contract_sha256"] != chaff.SMALL_RESPONSE_AGGREGATE_CONTRACT_SHA256
            or sidecar["application_workload_sha256"] != prepared_sha256
            or type(sidecar["application_resource_id"]) is not int or sidecar["application_resource_id"] != 0
            or type(sidecar["selected_chaff_resource_id"]) is not int
            or type(sidecar["qualified_parallel_chaff_streams"]) is not int
            or sidecar["qualified_parallel_chaff_streams"] != 8
            or sidecar["qualification_policy"] != chaff.small_response_aggregate_qualification_policy()
            or canonical_json(sidecar["runtime"]) != canonical_json(dict(runtime))
            or sidecar["scientific_credit"] is not False
            or type(sidecar["neqo_provenance"]) is not dict
            or sidecar["neqo_provenance"].get("migration_commit") != runtime["native_commit"]):
        raise ValueError("aggregate BuFLO sidecar policy, runtime or workload binding differs")
    chaff._validate_small_response_aggregate_policy(sidecar["qualification_policy"])
    attempts, outcomes = sidecar["candidate_attempts"], sidecar["selection_outcomes"]
    if (type(attempts) is not list or not 1 <= len(attempts) <= len(candidates)
            or type(outcomes) is not list or len(outcomes) != len(attempts)):
        raise ValueError("aggregate BuFLO attempts must be the exact nonempty eligible prefix")
    for index, (attempt, outcome) in enumerate(zip(attempts, outcomes)):
        resource, response = candidates[index]
        checked = chaff._validate_response_only_candidate_attempt(attempt,
            candidate_index=index, base_resource=resource, prepared_response=response,
            application_manifest_sha256=prepared_sha256, application_resource_id=0,
            neqo_provenance=sidecar["neqo_provenance"], small_response_aggregate=True)
        epochs = [(row["process_exit_code"], row["receipt"]) for row in checked["connection_epochs"]]
        _, identity, _ = chaff._candidate_attempt_record_v2(candidate_index=index,
            base_resource=resource, prepared_response=response, epochs=epochs,
            application_manifest_sha256=prepared_sha256, application_resource_id=0,
            neqo_provenance=sidecar["neqo_provenance"], small_response_aggregate=True)
        actual = "rejected" if identity is None else "selected"
        if outcome != actual or (actual == "selected") != (index == len(attempts) - 1):
            raise ValueError("aggregate BuFLO selected candidate or earlier outcome differs")
    selected = candidates[len(attempts) - 1][0]
    if sidecar["selected_chaff_resource_id"] != selected["id"]:
        raise ValueError("aggregate BuFLO selected resource is outside its exact candidate prefix")
    resource = chaff._validate_response_only_v2_resource_receipt(sidecar["resource"], selected,
        selected_attempt=attempts[-1], small_response_aggregate=True)
    derived = chaff.derive_small_response_aggregate_manifest({"base_manifest": {"sha256": prepared_sha256},
        "application_resource_id": 0, "selected_chaff_resource_id": selected["id"], "resource": resource}, selected)
    digest = hashlib.sha256(canonical_json(derived)).hexdigest()
    if canonical_json(manifest) != canonical_json(derived) or sidecar["native_manifest_sha256"] != digest:
        raise ValueError("aggregate BuFLO sidecar does not derive the exact Native schema-six manifest")


def validate_buflo_aggregate_enrollment(root: Path, enrollment: Mapping[str, Any]) -> dict | None:
    """Validate only the explicit new branch; all launch files retain their hashes."""
    from . import chaff_qualification as chaff
    if "buflo_chaff_selection" in enrollment and "buflo_small_response_aggregate_selection" in enrollment:
        raise ValueError("aggregate and capped BuFLO selections cannot coexist")
    if "buflo_small_response_aggregate_selection" not in enrollment:
        return None
    selection = enrollment["buflo_small_response_aggregate_selection"]
    if not buflo_aggregate_native_supported(enrollment.get("runtime", {}).get("native_commit")):
        raise ValueError("aggregate BuFLO requires the exact Native128 implementation")
    from .buflo_duration_budget import CADENCE64_POLICY
    if enrollment.get("mode_policies", {}).get("buflo", {}).get("buflo_duration_policy") != CADENCE64_POLICY:
        raise ValueError("aggregate BuFLO preserves the fixed64ms640s policy")
    if (type(selection) is not dict or set(selection) != {"schema_version", "record_type", "selection_policy", "aggregate_capacity_contract_sha256"}
            or type(selection["schema_version"]) is not int or selection["schema_version"] != 1
            or selection["record_type"] != BUFLO_AGGREGATE_SELECTION_TYPE
            or selection["selection_policy"] != BUFLO_AGGREGATE_SELECTION_POLICY
            or selection["aggregate_capacity_contract_sha256"] != chaff.SMALL_RESPONSE_AGGREGATE_CONTRACT_SHA256):
        raise ValueError("aggregate BuFLO enrollment selection declaration differs")
    keys = ("buflo_chaff_sidecar", "buflo_chaff_manifest")
    if enrollment["mode_readiness"].get("buflo") is not True:
        if (enrollment["mode_readiness"].get("buflo") is not False
                or type(enrollment.get("buflo_chaff_qualification_error")) is not str
                or not enrollment["buflo_chaff_qualification_error"]
                or any(enrollment["paths"].get(key) is not None for key in keys)):
            raise ValueError("unqualified aggregate BuFLO enrollment has launch inputs")
        return None
    if enrollment.get("buflo_chaff_qualification_error") is not None:
        raise ValueError("qualified aggregate BuFLO enrollment retains a qualification error")
    paths = {}
    for key in (*keys, "prepared_workload"):
        relative = enrollment["paths"].get(key)
        if (type(relative) is not str or Path(relative).is_absolute() or ".." in Path(relative).parts
                or str(Path(relative)) != relative):
            raise ValueError("aggregate BuFLO launch input path is not canonical and relative")
        path = _regular(root / relative)
        if sha256_file(path) != enrollment["files"].get(relative):
            raise ValueError("aggregate BuFLO launch input changed its enrollment digest")
        paths[key] = path
    prepared_sha = sha256_file(paths["prepared_workload"])
    sidecar = _object(paths["buflo_chaff_sidecar"])
    manifest = _object(paths["buflo_chaff_manifest"])
    _validate_buflo_aggregate_sidecar(_object(paths["prepared_workload"]), prepared_sha,
        sidecar, manifest, enrollment["runtime"])
    if sidecar["native_manifest_sha256"] != sha256_file(paths["buflo_chaff_manifest"]):
        raise ValueError("aggregate BuFLO sidecar differs from the exact Native manifest bytes")
    return {**selection, "application_workload_sha256": prepared_sha,
        "selected_chaff_resource_id": sidecar["selected_chaff_resource_id"],
        "sidecar_sha256": sha256_file(paths["buflo_chaff_sidecar"]),
        "native_manifest_sha256": sha256_file(paths["buflo_chaff_manifest"])}


def _qualify_buflo_aggregate(prepared: Path, root: Path, client: Path,
                         runtime: Mapping[str, Any]) -> dict:
    """Run genuine three-by-forty identity qualification for a new BF policy."""
    from . import chaff_qualification as chaff
    base = _object(prepared); digest = sha256_file(prepared)
    attempts, outcomes, receipts = [], [], []
    for index, (candidate, response) in enumerate(_buflo_aggregate_candidates(base)):
        directory = _new_directory(root / f"candidate-{index:03d}-resource-{candidate['id']:02d}")
        epochs = chaff._run_response_qualifications_v2(prepared, directory,
            selected_chaff_resource_id=candidate["id"], application_manifest_sha256=digest,
            application_resource_id=0, url=candidate["url"], headers=chaff.project_identity_chaff_headers(candidate),
            neqo_client=client, neqo_client_sha256=runtime["client_sha256"], timeout_seconds=120,
            interval_seconds=chaff.RESPONSE_ONLY_EPOCH_SPACING_SECONDS, small_response_aggregate=True)
        receipts.extend(receipt for _, receipt in epochs)
        attempt, identity, request_bytes = chaff._candidate_attempt_record_v2(candidate_index=index,
            base_resource=candidate, prepared_response=response, epochs=epochs,
            application_manifest_sha256=digest, application_resource_id=0, small_response_aggregate=True)
        attempts.append(attempt)
        outcome = "rejected" if identity is None else "selected"
        outcomes.append(outcome)
        if outcome != "selected":
            continue
        resource = {"resource_id": candidate["id"], "url": candidate["url"],
            "headers": chaff.project_identity_chaff_headers(candidate), "request_stream_bytes": request_bytes,
            "expected_response": identity, "response_qualification_sha256": attempt["response_qualification_sha256"]}
        manifest = chaff.derive_small_response_aggregate_manifest({"base_manifest": {"sha256": digest},
            "application_resource_id": 0, "selected_chaff_resource_id": candidate["id"], "resource": resource}, candidate)
        sidecar = {"schema_version": 1, "record_type": BUFLO_AGGREGATE_SIDECAR_TYPE,
            "selection_policy": BUFLO_AGGREGATE_SELECTION_POLICY, "aggregate_capacity_contract_sha256": chaff.SMALL_RESPONSE_AGGREGATE_CONTRACT_SHA256,
            "application_workload_sha256": digest, "application_resource_id": 0,
            "selected_chaff_resource_id": candidate["id"], "qualified_parallel_chaff_streams": 8,
            "qualification_policy": chaff.small_response_aggregate_qualification_policy(), "runtime": dict(runtime),
            "neqo_provenance": chaff._stable_neqo_provenance(receipts), "candidate_attempts": attempts,
            "selection_outcomes": outcomes, "resource": resource,
            "native_manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(), "scientific_credit": False}
        _validate_buflo_aggregate_sidecar(base, digest, sidecar, manifest, runtime)
        return {"sidecar": sidecar, "manifest": manifest, "error": None}
    error = "no small-response aggregate BuFLO candidate passed the genuine sustained identity qualification"
    _write(root / "qualification-failed.json", {"error": error, "candidate_attempts": attempts,
        "selection_outcomes": outcomes, "scientific_credit": False})
    return {"sidecar": None, "manifest": None, "error": error}



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
               runtime: Mapping[str, Any] | None = None,
               frozen_application_manifest_raw: bytes | None = None) -> dict[str, Any]:
    """Probe URLs independently in source order; failed attempts remain on disk.

    A stop_after cutoff leaves the unattempted tail explicitly unassessed. This
    probe establishes no captured connection or scientific session count.
    """
    pool = _manifest(hostname, urls, require_twenty=False)
    if frozen_application_manifest_raw is not None:
        # Probes keep their original independent IDs/length rules, while the
        # explicit twenty's authenticated application request headers are exact.
        from .resource_study_selection import validate_frozen_application_manifest_bytes
        frozen = validate_frozen_application_manifest_bytes(frozen_application_manifest_raw, hostname,
            [resource["url"] for resource in pool["resources"]])
        for resource, original in zip(pool["resources"], frozen["resources"]):
            resource["headers"] = [pair[:] for pair in original["headers"]]
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


CS180_POLICY = "qcsd-angkanet26-cs-buflo-cpsp-180s-capture240-v1"
CS180_HOST = "angkanet26.com"
CS180_NATIVE = "ecb507456f114756cdc363efd7a4e39d1fed0aa7"
CS180_WORKLOAD = "79b01f4c6f50f7d3ab5860a85bbe48ddf99f5537b3b6eba12003a11486e8e66e"
CS180_OLD_WORKLOAD = "9b8ccfe92309392476b2d4f0d75056d8952443e57c0e49e6b38dde49bf2c1c16"
CS180_PARAMETERS = "e46036e50bcdef0f10b6711e8a730f9a452e56728da3f1f19288fcfb177839a7"


CS160_POLICY = 'qcsd-native148-cs-buflo-cpsp-160s-capture180-original20-v1'
CS160_NATIVE = '580d25376557ff42dfbb5e030f87d40d695d0663'
CS160_CLIENT = 'db737cc67fc4fd70812d3e831f48ad9a1c053de681302236ee9e4e4f8421bf69'
CS160_PARAMETERS = CS180_PARAMETERS


def cs_duration_policy(value):
    """Only the explicit prospective Ang condition extends the old120s default."""
    if value is not None and value not in (CS180_POLICY, CS160_POLICY):
        raise ValueError("unsupported explicit CS duration policy")
    return value


def _cs180_scope(hostname, runtime, workload_sha256):
    if (hostname != CS180_HOST or runtime.get("native_commit") != CS180_NATIVE
            or not isinstance(runtime.get("source"), Mapping)
            or runtime["source"].get("neqo_commit") != CS180_NATIVE
            or workload_sha256 != CS180_WORKLOAD):
        raise ValueError("CS180 requires exact Ang current20 workload and genuine Native137")


def _cs160_scope(hostname, runtime, workload_sha256):
    """Only the actual Native148 ELF may use this declared future CS condition."""
    _retained_runtime(runtime)
    native_manifest(hostname, ["https://" + hostname + "/"], require_twenty=False)
    if (runtime["native_commit"] != CS160_NATIVE
            or runtime["source"]["neqo_commit"] != CS160_NATIVE
            or runtime["platform"] != "linux/arm64"
            or type(workload_sha256) is not str or _SHA256.fullmatch(workload_sha256) is None):
        raise ValueError("CS160 requires actual Native148 full runtime and exact frozen workload")


def cs_duration_scope(policy, hostname, runtime, workload_sha256):
    selected = cs_duration_policy(policy)
    if selected == CS160_POLICY:
        return _cs160_scope(hostname, runtime, workload_sha256)
    if selected == CS180_POLICY:
        return _cs180_scope(hostname, runtime, workload_sha256)
    raise ValueError("explicit prospective CS duration policy required")


def mode_policies(*, buflo_duration_policy: str | None = None, cs_buflo_duration_policy: str | None = None,
                  tamaraw_configuration_policy: str | None = None) -> dict[str, dict[str, Any]]:
    """Expose the existing fixed policies explicitly, before any capture."""
    from . import front_fixed_configuration as front, front_incoming_acceptance as incoming
    from . import tamaraw_fixed_configuration as tamaraw, buflo_duration_budget as buflo
    from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
    common = {"application_body_identity_policy": COMPLETE_APPLICATION_DELIVERY_POLICY}
    selected_cs = cs_duration_policy(cs_buflo_duration_policy)
    selected_tamaraw = tamaraw.POLICY if tamaraw_configuration_policy is None else tamaraw.validate_policy(tamaraw_configuration_policy)
    result = {"undefended": dict(common),
        "front": {**common, front.FIELD: front.POLICY, incoming.FIELD: incoming.POLICY},
        "tamaraw": {**common, tamaraw.FIELD: selected_tamaraw},
        "buflo": {**common, "buflo_duration_policy": buflo.preparation_policy(buflo_duration_policy)},
        "cs-buflo": {**common, "parameter_policy": "fixed-cs-buflo-cpsp-live-v1"}}
    if selected_cs is not None:
        result["cs-buflo"]["cs_buflo_duration_policy"] = selected_cs
    return result


def _parameter_bundle(root: Path, *, buflo_duration_policy: str | None = None,
                      tamaraw_configuration_policy: str | None = None) -> dict[str, Path]:
    from . import front_fixed_configuration as front, tamaraw_fixed_configuration as tamaraw
    from . import buflo_duration_budget as buflo
    from .util import LAB_ROOT
    selected = buflo.preparation_policy(buflo_duration_policy)
    buflo_raw = (buflo.cadence64_1280_parameter_bytes() if selected == buflo.CADENCE64_1280_POLICY
                 else buflo.cadence64_parameter_bytes())
    source = _regular(LAB_ROOT / "config/defense-params/cs-buflo-cpsp-live.json")
    return {"front_config": _write(root / "params/front.toml", front.configuration_bytes(), raw=True),
        "tamaraw_config": _write(root / "params/tamaraw.toml", tamaraw.configuration_bytes(selected_policy=tamaraw.POLICY if tamaraw_configuration_policy is None else tamaraw_configuration_policy), raw=True),
        "buflo_parameters": _write(root / "params/buflo.json", buflo_raw, raw=True),
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
        qualified_headers = chaff.project_compact_headers(selected)
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
                url=selected["url"], headers=qualified_headers,
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
                base_resource=selected, headers=qualified_headers, request_stream_bytes=request_size,
                expected_response=expected, response_qualification_sha256=digest,
                application_resource_id=0, selected_chaff_resource_id=identifier,
                qualified_parallel_chaff_streams=5, walkie_talkie_required_chaff_streams=20)
            sidecar = {"base_manifest": {"sha256": prepared_sha}, "application_resource_id": 0,
                "selected_chaff_resource_id": identifier, "resource": {
                    "headers": qualified_headers, "expected_response": expected,
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


def _mode_settings(paths: Mapping[str, Path | None], *,
                   buflo_duration_policy: str | None = None,
                   cs_buflo_duration_policy: str | None = None,
                   tamaraw_configuration_policy: str | None = None) -> dict[str, dict[str, Any]]:
    from . import front_fixed_configuration as front, tamaraw_fixed_configuration as tamaraw
    from . import buflo_duration_budget as buflo
    common = {"profile": "research-1200", "request_policy": "as-defined",
              "max_response_bytes": MAX_RESPONSE_BYTES, "udp_payload_ceiling": 1200}
    selected = buflo.preparation_policy(buflo_duration_policy)
    limits = buflo.capture_limits("buflo", {"timeout_seconds": 120, "capture_seconds": 180}, policy=selected)
    settings = {mode: {**common, "policies": mode_policies(buflo_duration_policy=selected, cs_buflo_duration_policy=cs_buflo_duration_policy, tamaraw_configuration_policy=tamaraw_configuration_policy)[mode]} for mode in MODES}
    settings["undefended"].update(defense="none", timeout_seconds=120, capture_seconds=180)
    for mode, module, key in (("front", front, "front_config"),
                               ("tamaraw", tamaraw, "tamaraw_config")):
        settings[mode].update(configuration_sha256=sha256_file(paths[key]),
            resolved_configuration=(module.resolved_configuration(selected_policy=tamaraw.POLICY if tamaraw_configuration_policy is None else tamaraw_configuration_policy) if mode == "tamaraw" else module.resolved_configuration()),
            timeout_seconds=120, capture_seconds=180)
    for mode, key in (("buflo", "buflo_parameters"), ("cs-buflo", "cs_buflo_parameters")):
        settings[mode].update(parameters_sha256=sha256_file(paths[key]),
            parameters=_object(paths[key]), timeout_seconds=limits["timeout_seconds"] if mode == "buflo" else 120,
            capture_seconds=limits["capture_seconds"] if mode == "buflo" else 180)
    if cs_duration_policy(cs_buflo_duration_policy) is not None:
        if settings["cs-buflo"]["parameters_sha256"] != CS180_PARAMETERS:
            raise ValueError("CS180 changes the original CPSP parameter bytes")
        settings["cs-buflo"].update(**({"timeout_seconds":160,"capture_seconds":180}
            if cs_buflo_duration_policy == CS160_POLICY else {"timeout_seconds":180,"capture_seconds":240}))
    buflo.validate_parameters(settings["buflo"]["parameters"])
    if settings["buflo"]["parameters"][buflo.PARAMETER_FIELD] != selected:
        raise ValueError("enrolled BuFLO parameters differ from the explicit duration policy")
    return settings


def prepare_domain(hostname: str, urls: Iterable[str], output: str | Path, *,
                   client: str | Path = DEFAULT_CLIENT,
                   runtime: Mapping[str, Any], buflo_chaff_cap_bytes: int | None = None,
                   buflo_small_response_aggregate: bool = False,
                   buflo_duration_policy: str | None = None,
                   cs_buflo_duration_policy: str | None = None,
                   tamaraw_configuration_policy: str | None = None,
                   frozen_application_manifest: str | Path | None = None,
                   frozen_application_manifest_sha256: str | None = None) -> dict[str, Any]:
    """Freeze20 real GET URLs, with an ordinary lane independent of chaff failures.

    Pools are probed in their given order until20 individually complete URLs
    are found; the selected20 are then replayed together. Every attempted URL
    and failed qualifier remains retained. There is no resource substitution
    after enrollment, no fitter, and no HTML or cross-origin claim.
    """
    from . import buflo_duration_budget as buflo
    selected_duration = buflo.preparation_policy(buflo_duration_policy)
    selected_cs = cs_duration_policy(cs_buflo_duration_policy)
    from . import tamaraw_fixed_configuration as tamaraw
    selected_tamaraw = tamaraw.POLICY if tamaraw_configuration_policy is None else tamaraw.validate_policy(tamaraw_configuration_policy)
    if selected_tamaraw == tamaraw.INITIAL16_POLICY and (runtime.get("native_commit") != tamaraw.INITIAL16_NATIVE
            or not isinstance(runtime.get("source"), Mapping) or runtime["source"].get("neqo_commit") != tamaraw.INITIAL16_NATIVE
            or frozen_application_manifest is None or frozen_application_manifest_sha256 is None
            or buflo_small_response_aggregate is not False or cs_buflo_duration_policy is not None):
        raise ValueError("initial16 requires genuine Native139, exact frozen20 and its separate ordinary condition")
    if selected_cs == CS180_POLICY and (hostname != CS180_HOST or runtime.get("native_commit") != CS180_NATIVE):
        raise ValueError("CS180 preparation is restricted to Ang and Native137")
    if selected_cs == CS160_POLICY:
        _cs160_scope(hostname,runtime,"0"*64)
        if frozen_application_manifest is None or frozen_application_manifest_sha256 is None:
            raise ValueError("CS160 requires paired exact original20 frozen manifest inputs")
    cap = _buflo_chaff_cap(buflo_chaff_cap_bytes)
    aggregate = _buflo_aggregate_option(buflo_small_response_aggregate, cap)
    if aggregate and selected_duration != buflo.CADENCE64_POLICY:
        raise ValueError("small-response aggregate preserves the fixed64ms640s duration")
    if aggregate and not buflo_aggregate_native_supported(runtime.get("native_commit")):
        raise ValueError("small-response aggregate preparation requires the exact Native128 implementation")
    pool = _manifest(hostname, urls, require_twenty=False)
    if len(pool["resources"]) < RESOURCES_PER_SESSION:
        raise ValueError("candidate pool has fewer than20 distinct same-host URLs")
    executable, bound = _runtime(runtime, client)
    frozen_raw = frozen_value = None
    if frozen_application_manifest is not None or frozen_application_manifest_sha256 is not None:
        if frozen_application_manifest is None or frozen_application_manifest_sha256 is None:
            raise ValueError("frozen application manifest requires both path and SHA")
        from .resource_study_selection import _read, validate_frozen_application_manifest_bytes
        frozen_raw = _read(frozen_application_manifest, frozen_application_manifest_sha256)
        frozen_value = validate_frozen_application_manifest_bytes(frozen_raw, hostname,
            [resource["url"] for resource in pool["resources"]])
    root = _new_directory(output)
    probe = probe_urls(hostname, [resource["url"] for resource in pool["resources"]],
        root / "probe", client=executable, stop_after=RESOURCES_PER_SESSION, runtime=bound,
        **({"frozen_application_manifest_raw": frozen_raw} if frozen_raw is not None else {}))
    urls20 = probe["selected_urls"]
    if probe["deferred"] is not None:
        _write(root / "preparation-deferred.json", {**probe["deferred"], "role": ROLE,
            "hostname": probe["hostname"], "probe": "probe/probe.json",
            "scientific_credit": False})
        raise ValueError("domain preparation transient-deferred after repeated fresh-client transport failures; retryable")
    if len(urls20) != RESOURCES_PER_SESSION:
        raise ValueError("candidate pool did not yield20 actual complete nonempty HTTP3 GETs")
    input_manifest = _manifest(hostname, urls20, require_twenty=True)
    if frozen_value is not None:
        if urls20 != [resource["url"] for resource in frozen_value["resources"]]:
            raise ValueError("frozen original twenty did not all complete their exact ordered probes")
        input_manifest = frozen_value
    actual_dir = _new_directory(root / "preparation-get")
    _, responses = _checked_operation(actual_dir, input_manifest, client=executable,
        runtime=bound, client_sha256=bound["client_sha256"], timeout=120,
        max_response_bytes=MAX_RESPONSE_BYTES)
    lengths = {row["url"]: row["bytes"] for row in responses}
    if frozen_value is None:
        manifest = native_manifest(hostname, urls20, lengths)
        for resource in manifest["resources"]:
            resource["headers"] = [pair[:] for pair in REQUEST_HEADERS]
        manifest["resources"][0]["type"] = "Document"
    else:
        manifest = frozen_value
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
        "buflo_fin_permission_policy": "buflo-retained-owned-parser-demand-genuine-fin-permission-release-v1",
        "outer_response_contract": "every-selected-resource-complete-nonempty-http2xx-h3-v1"}
    if buflo_duration_policy is not None:
        preparation["buflo_duration_policy"] = selected_duration
    if selected_cs is not None:
        preparation["cs_buflo_duration_policy"] = selected_cs
    if selected_tamaraw == tamaraw.INITIAL16_POLICY:
        preparation[tamaraw.FIELD] = selected_tamaraw
    if frozen_raw is not None:
        from .resource_study_selection import frozen_application_manifest_declaration
        preparation["frozen_application_manifest"] = frozen_application_manifest_declaration(frozen_application_manifest_sha256)
    manifest_path = _write(root / "resources.json", manifest if frozen_raw is None else frozen_raw,
                           raw=frozen_raw is not None)
    if selected_cs is not None:
        cs_duration_scope(selected_cs, hostname, bound, sha256_file(manifest_path))
    prepared = _write(root / "prepared-workload.json", {"preparation": preparation, **manifest})
    paths: dict[str, Path | None] = {"manifest": manifest_path, "prepared_workload": prepared,
        "expected_responses": _write(root / "expected-responses.json", {"responses": expected}),
        **_parameter_bundle(root, buflo_duration_policy=selected_duration, tamaraw_configuration_policy=selected_tamaraw)}
    qualified = _qualify(prepared, manifest["resources"], responses,
                         _new_directory(root / "qualification"), executable, bound)
    paths["chaff_core"] = _write(root / "chaff-core.json", qualified["core"]) if qualified["core"] else None
    paths["chaff_manifest"] = _write(root / "chaff-manifest.json", qualified["manifest"]) if qualified["manifest"] else None
    capped = None
    if cap is not None:
        capped = _qualify_buflo_capped(prepared, _new_directory(root / "buflo-capped-qualification"), executable, bound, cap)
        paths["buflo_chaff_sidecar"] = _write(root / "buflo-capped-chaff-qualification.json", capped["sidecar"]) if capped["sidecar"] else None
        paths["buflo_chaff_manifest"] = _write(root / "buflo-capped-chaff-manifest.json", capped["manifest"]) if capped["manifest"] else None
    aggregated = None
    if aggregate:
        aggregated = _qualify_buflo_aggregate(prepared, _new_directory(root / "buflo-small-response-aggregate-qualification"), executable, bound)
        paths["buflo_chaff_sidecar"] = _write(root / "buflo-small-response-aggregate-qualification.json", aggregated["sidecar"]) if aggregated["sidecar"] else None
        paths["buflo_chaff_manifest"] = _write(root / "buflo-small-response-aggregate-manifest.json", aggregated["manifest"]) if aggregated["manifest"] else None
    # This self inventory deliberately excludes enrollment.json, whose digest
    # is returned separately for the outer coordinator's immutable reference.
    enrollment = {"schema_version": 1, "role": ROLE, "hostname": probe["hostname"],
        "urls": urls20, "workload_path": "resources.json", "workload_sha256": sha256_file(manifest_path),
        "paths": {key: value.relative_to(root).as_posix() if value else None for key, value in paths.items()},
        "files": _files(root), "runtime": bound, "mode_policies": mode_policies(buflo_duration_policy=selected_duration, cs_buflo_duration_policy=selected_cs, tamaraw_configuration_policy=selected_tamaraw),
        "mode_settings": _mode_settings(paths, buflo_duration_policy=selected_duration, cs_buflo_duration_policy=selected_cs, tamaraw_configuration_policy=selected_tamaraw),
        "mode_readiness": {mode: mode == "undefended" or qualified["error"] is None for mode in MODES},
        "qualification_error": qualified["error"], "scientific_credit": False}
    if cap is not None:
        enrollment["buflo_chaff_selection"] = {"schema_version": 1, "record_type": BUFLO_CAPPED_SELECTION_TYPE,
            "selection_policy": BUFLO_CAPPED_SELECTION_POLICY, "cap_bytes": cap}
        enrollment["mode_readiness"]["buflo"] = capped["error"] is None
        enrollment["buflo_chaff_qualification_error"] = capped["error"]
        validate_buflo_capped_enrollment(root, enrollment)
    if aggregate:
        enrollment["buflo_small_response_aggregate_selection"] = buflo_aggregate_selection()
        enrollment["mode_readiness"]["buflo"] = aggregated["error"] is None
        enrollment["buflo_chaff_qualification_error"] = aggregated["error"]
        validate_buflo_aggregate_enrollment(root, enrollment)
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
    if RETAINED_MODE_KEY in enrollment:
        return _retained_native_enrollment(root, hostname, runtime)
    canonical_host = urlsplit(native_manifest(hostname, [f"https://{hostname}/"], require_twenty=False)
                              ["resources"][0]["url"]).hostname
    from . import buflo_duration_budget as buflo
    recorded_policies = enrollment.get("mode_policies")
    selected_duration = buflo.preparation_policy(
        recorded_policies.get("buflo", {}).get("buflo_duration_policy")
        if isinstance(recorded_policies, Mapping) and isinstance(recorded_policies.get("buflo"), Mapping) else None)
    selected_cs = cs_duration_policy(
        recorded_policies.get("cs-buflo", {}).get("cs_buflo_duration_policy")
        if isinstance(recorded_policies, Mapping) and isinstance(recorded_policies.get("cs-buflo"), Mapping) else None)
    from . import tamaraw_fixed_configuration as tamaraw
    selected_tamaraw = tamaraw.policy(recorded_policies.get("tamaraw", {})) if isinstance(recorded_policies, Mapping) else None
    if (enrollment.get("schema_version") != 1 or enrollment.get("role") != ROLE
            or enrollment.get("hostname") != canonical_host
            or not _same_native_runtime(enrollment.get("runtime"), runtime)
            or enrollment.get("mode_policies") != mode_policies(buflo_duration_policy=selected_duration, cs_buflo_duration_policy=selected_cs, tamaraw_configuration_policy=selected_tamaraw)):
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
    if enrollment.get("mode_settings") != _mode_settings(actual_paths, buflo_duration_policy=selected_duration, cs_buflo_duration_policy=selected_cs, tamaraw_configuration_policy=selected_tamaraw):
        raise ValueError("enrollment mode settings differ from actual fixed input bytes")
    declared_tamaraw = _object(_regular(actual_paths["prepared_workload"])).get("preparation", {}).get(tamaraw.FIELD)
    if selected_tamaraw == tamaraw.INITIAL16_POLICY:
        if (declared_tamaraw != selected_tamaraw or runtime.get("native_commit") != tamaraw.INITIAL16_NATIVE
                or runtime.get("source", {}).get("neqo_commit") != tamaraw.INITIAL16_NATIVE):
            raise ValueError("initial16 lacks its explicit Native139 preparation declaration")
    elif declared_tamaraw == tamaraw.INITIAL16_POLICY:
        raise ValueError("historical preparation cannot inherit the initial16 condition")
    if selected_cs is not None:
        cs_duration_scope(selected_cs, canonical_host, runtime, enrollment["workload_sha256"])
        prepared = _object(_regular(actual_paths["prepared_workload"]))
        if prepared.get("preparation", {}).get("cs_buflo_duration_policy") != selected_cs:
            raise ValueError("CS180 lacks its immutable explicit preparation declaration")
    elif _object(_regular(actual_paths["prepared_workload"])).get("preparation", {}).get("cs_buflo_duration_policy") is not None:
        raise ValueError("ordinary enrollment cannot inherit a CS180 preparation")
    if "buflo_chaff_selection" in enrollment:
        validate_buflo_capped_enrollment(root, enrollment)
    if "buflo_small_response_aggregate_selection" in enrollment:
        validate_buflo_aggregate_enrollment(root, enrollment)
    return root, enrollment


def _capture_inputs(mode: str, root: Path, enrollment: Mapping[str, Any]):
    from . import capture_session as collector
    from . import buflo_duration_budget as buflo
    policies = enrollment["mode_policies"][mode]
    selected_duration = buflo.preparation_policy(policies.get("buflo_duration_policy")) if mode == "buflo" else None
    limits = buflo.capture_limits(mode, {"timeout_seconds": 120, "capture_seconds": 180},
        policy=selected_duration)
    if mode == "cs-buflo" and cs_duration_policy(policies.get("cs_buflo_duration_policy")) is not None:
        selected_cs=cs_duration_policy(policies.get("cs_buflo_duration_policy"))
        cs_duration_scope(selected_cs,enrollment["hostname"], enrollment["runtime"], enrollment["workload_sha256"])
        prepared = _object(_regular(root / enrollment["paths"]["prepared_workload"]))
        if prepared.get("preparation", {}).get("cs_buflo_duration_policy") != selected_cs:
            raise ValueError("CS180 capture requires its original explicit prepared policy")
        limits = ({"timeout_seconds":160,"capture_seconds":180} if selected_cs==CS160_POLICY
                  else {"timeout_seconds":180,"capture_seconds":240})
    context = SimpleNamespace(qcsd_profile="research-1200", request_policy="as-defined",
        udp_payload_ceiling=1200, limits=collector.Limits(**limits, max_response_bytes=MAX_RESPONSE_BYTES,
            capture_megabytes=256, max_attempts=1), **policies)
    if mode == "buflo":
        from . import buflo_fin_permission
        relative = enrollment["paths"]["prepared_workload"]
        if (not isinstance(relative, str) or Path(relative).is_absolute()
                or ".." in Path(relative).parts):
            raise ValueError("prepared BuFLO policy source path is not relative")
        prepared = _object(_regular(root / relative))
        preparation = prepared.get("preparation")
        declared_duration = preparation.get("buflo_duration_policy") if isinstance(preparation, Mapping) else None
        if ((selected_duration == buflo.CADENCE64_1280_POLICY and declared_duration != selected_duration)
                or declared_duration is not None and declared_duration != selected_duration):
            raise ValueError("prepared BuFLO source lacks the matching explicit duration selector")
        selected = buflo_fin_permission.validate_policy(
            preparation.get(buflo_fin_permission.PREPARATION_FIELD)
            if isinstance(preparation, Mapping) else None)
        if selected != buflo_fin_permission.POLICY:
            raise ValueError("prepared BuFLO source lacks the explicit FIN permission policy")
        setattr(context, buflo_fin_permission.PREPARATION_FIELD, selected)
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
        source_name = {"buflo": (Path(buflo.CADENCE64_1280_PARAMETER_PATH).name
            if selected_duration == buflo.CADENCE64_1280_POLICY else "buflo-cadence64-budget640.json"),
                       "cs-buflo": "cs-buflo-cpsp-live.json"}[mode]
        source = _regular(LAB_ROOT / "config/defense-params" / source_name)
        provenance = _regular(parameter_artifacts.parameter_provenance_path(source))
        expected_policy = (selected_duration if mode == "buflo"
                           else "fixed-cs-buflo-cpsp-live-v1")
        policy_field = "buflo_duration_policy" if mode == "buflo" else "parameter_policy"
        if policies.get(policy_field) != expected_policy:
            raise ValueError("reactive defense policy differs from enrolled fixed mode")
        artifact = parameter_artifacts.validate_parameter_artifact(
            source, provenance_path=provenance, expected_kind=kind,
            allow_study_candidate=True, expected_qcsd_profile=context.qcsd_profile,
            expected_udp_payload_ceiling=context.udp_payload_ceiling)
        expected_input_policy = (buflo.CADENCE64_1280_INPUT_POLICY
                                if mode == "buflo" and selected_duration == buflo.CADENCE64_1280_POLICY
                                else buflo.CADENCE64_INPUT_POLICY if mode == "buflo"
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
                    runtime: Mapping[str, Any], client: str | Path = DEFAULT_CLIENT,
                    retained_readiness_core_sha256: str | None = None) -> dict[str, Any]:
    """Collect one fresh connection; return actual artifacts, never a receipt.

    The observer and scheduler environment must already satisfy the unchanged
    collector. Failed attempts remain intact and cannot gain scientific credit.
    The attempt directory must not exist; its parent may be store allocated.
    """
    if mode not in MODES or type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError("capture mode or u64 seed is invalid")
    executable, bound = _runtime(runtime, client)
    if retained_readiness_core_sha256 is None:
        root, enrollment = _enrollment(enrollment_dir, hostname, bound)
    else:
        root, enrollment = _retained_native_enrollment(enrollment_dir, hostname, bound,
            readiness_core_sha256=retained_readiness_core_sha256)
    from . import capture_session as collector
    if _regular(collector.NEQO_CLIENT) != executable:
        raise ValueError("collector executable differs; set NEQO_QCSD_CLIENT before import")
    if enrollment["mode_readiness"].get(mode) is not True:
        if (retained_readiness_core_sha256 is None or mode != 'buflo'
                or RETAINED_MODE_KEY not in enrollment):
            raise ValueError("mode has no actual preparation/response-chaff qualification")
    attempt = Path(os.path.abspath(attempt_dir))
    if (attempt.exists() or any(parent.is_symlink() for parent in (attempt, *attempt.parents))
            or attempt == root or attempt.is_relative_to(root) or root.is_relative_to(attempt)):
        raise ValueError("attempt must be a fresh nonsymlink directory disjoint from enrollment")
    manifest = root / enrollment["paths"]["manifest"]
    prepared = root / enrollment["paths"]["prepared_workload"]
    chaff_key = "buflo_chaff_manifest" if mode == "buflo" and (
        "buflo_chaff_selection" in enrollment or "buflo_small_response_aggregate_selection" in enrollment) else "chaff_manifest"
    if RETAINED_MODE_KEY in enrollment:
        checked_retained = retained_mode_assets(root, enrollment,
            provisional=retained_readiness_core_sha256 is not None)
        chaff_key = checked_retained['chaff_key']
    chaff = root / enrollment["paths"][chaff_key] if mode != "undefended" else None
    defense, context = _capture_inputs(mode, root, enrollment)
    result = collector._collect_attempt(attempt, manifest, chaff, hostname, defense, seed, context,
        application_workload_source=prepared if mode != "undefended" else None,
        application_response_policy="completed-terminal-http-errors-v1" if mode != "undefended" else "http-2xx-only-v1")
    checked, error = None, None
    try:
        if sha256_file(executable) != bound["client_sha256"]:
            raise ValueError("Native executable changed during capture")
        if retained_readiness_core_sha256 is None:
            _enrollment(root, hostname, bound)
        else:
            _retained_native_enrollment(root, hostname, bound,
                readiness_core_sha256=retained_readiness_core_sha256)
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
    parser.add_argument("--buflo-chaff-cap-bytes", type=int)
    parser.add_argument("--buflo-small-response-aggregate", action="store_true")
    parser.add_argument("--buflo-duration-policy")
    parser.add_argument("--cs-buflo-duration-policy")
    parser.add_argument("--tamaraw-configuration-policy")
    parser.add_argument("--frozen-application-manifest", type=Path)
    parser.add_argument("--frozen-application-manifest-sha256")
    args = parser.parse_args(argv)
    if args.buflo_chaff_cap_bytes is not None and args.action != "_prepare":
        parser.error("--buflo-chaff-cap-bytes is only valid for _prepare")
    if args.buflo_duration_policy is not None and args.action != "_prepare":
        parser.error("--buflo-duration-policy is only valid for _prepare")
    if args.buflo_duration_policy is not None:
        from .buflo_duration_budget import preparation_policy
        preparation_policy(args.buflo_duration_policy)
    if args.cs_buflo_duration_policy is not None:
        if args.action != "_prepare":
            parser.error("--cs-buflo-duration-policy is only valid for _prepare")
        cs_duration_policy(args.cs_buflo_duration_policy)
    frozen_requested = args.frozen_application_manifest is not None or args.frozen_application_manifest_sha256 is not None
    if args.tamaraw_configuration_policy is not None:
        if args.action != "_prepare":
            parser.error("--tamaraw-configuration-policy is only valid for _prepare")
        from .tamaraw_fixed_configuration import validate_policy
        validate_policy(args.tamaraw_configuration_policy)
    if frozen_requested and (args.action != "_prepare" or args.frozen_application_manifest is None
                             or args.frozen_application_manifest_sha256 is None):
        parser.error("frozen application manifest needs paired path/SHA only with _prepare")
    cap = _buflo_chaff_cap(args.buflo_chaff_cap_bytes)
    aggregate = _buflo_aggregate_option(args.buflo_small_response_aggregate, cap)
    if aggregate and args.action != "_prepare":
        parser.error("--buflo-small-response-aggregate is only valid for _prepare")
    job = _object(args.job)
    if args.action == "_prepare":
        if "tamaraw_configuration_policy" in job:
            raise ValueError("immutable preparation job has no Tamaraw condition field; use explicit CLI option")
        if args.tamaraw_configuration_policy is not None:
            job = {**job, "tamaraw_configuration_policy": args.tamaraw_configuration_policy}
        if "cs_buflo_duration_policy" in job:
            raise ValueError("immutable preparation job has no CS duration field; use explicit CLI option")
        if args.cs_buflo_duration_policy is not None:
            job = {**job, "cs_buflo_duration_policy": args.cs_buflo_duration_policy}
        if "buflo_duration_policy" in job:
            raise ValueError("the immutable preparation job has no duration field; use the explicit CLI option")
        if args.buflo_duration_policy is not None:
            job = {**job, "buflo_duration_policy": args.buflo_duration_policy}
        if "buflo_chaff_cap_bytes" in job:
            raise ValueError("the immutable preparation job has no cap field; use the explicit CLI option")
        if "buflo_small_response_aggregate" in job:
            raise ValueError("the immutable preparation job has no aggregate field; use the explicit CLI option")
        if aggregate:
            job = {**job, "buflo_small_response_aggregate": True}
        if "frozen_application_manifest" in job or "frozen_application_manifest_sha256" in job:
            raise ValueError("the immutable preparation job has no frozen-manifest field; use explicit CLI options")
        if cap is not None:
            job = {**job, "buflo_chaff_cap_bytes": cap}
        if frozen_requested:
            job = {**job, "frozen_application_manifest": args.frozen_application_manifest,
                   "frozen_application_manifest_sha256": args.frozen_application_manifest_sha256}
    function = {"_prepare": prepare_domain, "_capture": capture_session, "_probe": probe_urls}[args.action]
    result = function(**job)
    sys.stdout.buffer.write(canonical_json(result))
    return 0


# Distinct prospective preparation protocol. Historical qualification is never
# rebound to another runtime, and this record grants no formal session credit.
RETAINED_MODE_INPUT = 'qcsd-resource-domain-retained-parameter-mode-input-v1'
RETAINED_MODE_CORE = 'qcsd-resource-domain-retained-parameter-mode-core-v1'
RETAINED_MODE_BINDING = 'qcsd-resource-domain-retained-parameter-mode-preparation-v1'
RETAINED_MODE_RESULT = 'qcsd-resource-domain-retained-parameter-mode-readiness-result-v1'
RETAINED_MODE_KEY = 'retained_parameter_preparation'


def retained_mode_read(path: Path, digest: str | None = None, *, observations=None, canonical_runtime=False) -> bytes:
    """Read one immutable local regular file through one FD and fence its name."""
    import stat
    path = Path(path)
    if (not path.is_absolute() or str(path) != os.path.abspath(path)
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise ValueError('retained parameter path is not canonical and nonsymlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        def stamp(s):
            return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_nlink,
                    s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in ((0o444, 0o644) if canonical_runtime else (0o444,))
                or not 0 < before.st_size <= 32 * 1024 ** 2):
            raise ValueError('retained parameter file is not immutable, owned and bounded')
        pieces = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            pieces.append(block)
        raw = b''.join(pieces)
        if (stamp(before) != stamp(os.fstat(fd)) or stamp(before) != stamp(path.lstat())
                or any(p.is_symlink() for p in (path, *path.parents))
                or len(raw) != before.st_size
                or digest is not None and hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('retained parameter file or path changed')
        if observations is not None:
            if type(observations) is not dict:
                raise ValueError('foreign retained parameter observation ledger')
            observations[str(path)] = (path, *stamp(before))
        return raw
    finally:
        os.close(fd)


def _retained_ref(value):
    if (type(value) is not dict or set(value) != {'path', 'sha256'}
            or type(value['path']) is not str or type(value['sha256']) is not str
            or _SHA256.fullmatch(value['sha256']) is None):
        raise ValueError('retained parameter reference must have exact path and SHA')
    return Path(value['path']), value['sha256']


def _retained_relative(value):
    if (type(value) is not str or not value or Path(value).is_absolute()
            or '..' in Path(value).parts or Path(value).as_posix() != value):
        raise ValueError('retained parameter relative path differs')
    return value


def _retained_runtime(runtime):
    fields = {'canonical_sha256', 'client_sha256', 'native_commit', 'platform',
              'collection_image_digest', 'prepare_image_digest', 'source'}
    if (type(runtime) is not dict or set(runtime) != fields
            or type(runtime.get('native_commit')) is not str
            or _COMMIT.fullmatch(runtime['native_commit']) is None
            or runtime.get('platform') != 'linux/arm64'
            or type(runtime.get('source')) is not dict
            or runtime['source'].get('neqo_commit') != runtime['native_commit']
            or runtime['source'].get('neqo_dirty') is not False
            or runtime['source'].get('lab_dirty') is not False
            or any(type(runtime.get(key)) is not str or _SHA256.fullmatch(runtime[key]) is None
                   for key in ('canonical_sha256', 'client_sha256'))
            or any(type(runtime.get(key)) is not str
                   or re.fullmatch(r'sha256:[0-9a-f]{64}', runtime[key]) is None
                   for key in ('collection_image_digest', 'prepare_image_digest'))):
        raise ValueError('retained-mode readiness requires the exact complete input-bound runtime')
    return runtime


def _retained_old_assets(old_root, old, science):
    """Validate historical launch bytes as historical, not new qualification."""
    if (type(old) is not dict or old.get('role') != ROLE or old.get('schema_version') != 1
            or old.get('hostname') != science['hostname'] or old.get('scientific_credit') is not False
            or type(old.get('runtime')) is not dict or type(old.get('files')) is not dict
            or type(old.get('paths')) is not dict
            or old.get('urls') != science['urls'] or len(old['urls']) != 20
            or len(set(old['urls'])) != 20 or old.get('workload_sha256') != science['workload_sha256']
            or old.get('mode_settings', {}).get('buflo') != science['settings']
            or old.get('mode_policies', {}).get('buflo') != science['policies']
            or 'buflo_small_response_aggregate_selection' in old):
        raise ValueError('retained historical enrollment changes its frozen mode science')
    # None of the historical readiness flags are promoted or rewritten here.
    native_manifest(old['hostname'], old['urls'])
    paths = {}
    observed = {}
    def observe(path, digest):
        return retained_mode_read(path, digest, observations=observed)
    for key, relative in old['paths'].items():
        if relative is None:
            paths[key] = None
            continue
        _retained_relative(relative)
        digest = old['files'].get(relative)
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise ValueError('historical launch asset has no enrollment digest')
        observe(old_root / relative, digest)
        paths[key] = old_root / relative
    for key in ('manifest', 'prepared_workload', 'buflo_parameters', 'front_config',
                'tamaraw_config', 'cs_buflo_parameters'):
        if paths.get(key) is None:
            raise ValueError('historical fixed launch asset is absent')
    if (hashlib.sha256(retained_mode_read(paths['manifest'])).hexdigest() != science['workload_sha256']
            or _object(paths['manifest'])['resources'] != _object(paths['prepared_workload'])['resources']
            or [r['url'] for r in _object(paths['manifest'])['resources']] != science['urls']):
        raise ValueError('historical prepared workload differs from exact frozen twenty')
    policies = science['policies']
    from . import buflo_duration_budget as buflo
    selected = buflo.preparation_policy(policies.get('buflo_duration_policy'))
    if selected != buflo.CADENCE64_POLICY:
        raise ValueError('retained-mode v1 preserves only original64ms640s BuFLO')
    if _mode_settings(paths, buflo_duration_policy=selected)['buflo'] != science['settings']:
        raise ValueError('retained BuFLO parameters/settings are not the exact fixed policy')
    if 'buflo_chaff_selection' in old:
        checked = validate_buflo_capped_enrollment(old_root, old)
        if checked is None:
            raise ValueError('historical capped launch asset is absent; no fallback to generic')
        chaff_key = 'buflo_chaff_manifest'
        historical_binding = checked
    else:
        if paths.get('chaff_core') is None or paths.get('chaff_manifest') is None:
            raise ValueError('historical same-host generic chaff assets are absent')
        manifest = _object(paths['chaff_manifest'])
        core = _object(paths['chaff_core'])
        from . import chaff_qualification as chaff
        prepared = _object(paths['prepared_workload'])
        base_sha = sha256_file(paths['prepared_workload'])
        evidence_path = paths['prepared_workload'].parent / 'qualification/response-qualification.json'
        evidence_relative = evidence_path.relative_to(old_root).as_posix()
        if evidence_relative not in old['files']:
            raise ValueError('historical generic qualification evidence lacks its enrollment digest')
        raw = observe(evidence_path, old['files'][evidence_relative])
        evidence = json.loads(raw)
        selected_id = evidence.get('selected_chaff_resource_id')
        if (type(selected_id) is not int or not 0 <= selected_id < 20
                or evidence.get('scientific_credit') is not False
                or evidence.get('application_workload_sha256') != base_sha
                or type(evidence.get('response_runs')) is not list
                or len(evidence['response_runs']) != chaff.QUALIFICATION_RUNS):
            raise ValueError('historical generic qualification evidence is absent or changed')
        resource = prepared['resources'][selected_id]
        headers = chaff.project_compact_headers(resource)
        runs = []
        for index in range(chaff.QUALIFICATION_RUNS):
            path = evidence_path.parent / ('resource-%02d' % selected_id) / ('response-%d' % index) / 'native/qualification.json'
            relative = path.relative_to(old_root).as_posix()
            if relative not in old['files']:
                raise ValueError('historical response receipt lacks its enrollment digest')
            receipt = json.loads(observe(path, old['files'][relative]))
            if chaff._receipt_neqo_provenance(receipt)['migration_commit'] != old['runtime']['native_commit']:
                raise ValueError('historical generic qualification has foreign Native provenance')
            runs.append(receipt)
        expected, request_size = chaff._stable_response_identity(runs,
            application_manifest_sha256=base_sha, application_resource_id=0,
            selected_chaff_resource_id=selected_id, qualified_parallel_chaff_streams=5,
            url=resource['url'], headers=headers, resource_domain_max_response_bytes=MAX_RESPONSE_BYTES)
        records = [chaff._response_run_record(index, run) for index, run in enumerate(runs)]
        digest = chaff.qualification_digest('qcsd-chaff-response-qualification-v2', records)
        if (evidence['response_runs'] != records or evidence.get('expected_response') != expected
                or evidence.get('request_stream_bytes') != request_size
                or evidence.get('response_qualification_sha256') != digest):
            raise ValueError('historical generic qualification does not replay its original receipts')
        expected_core = chaff.derive_chaff_core(application_manifest_sha256=base_sha,
            base_resource=resource, headers=headers, request_stream_bytes=request_size,
            expected_response=expected, response_qualification_sha256=digest,
            application_resource_id=0, selected_chaff_resource_id=selected_id,
            qualified_parallel_chaff_streams=5, walkie_talkie_required_chaff_streams=20)
        sidecar = {'base_manifest': {'sha256': base_sha}, 'application_resource_id': 0,
            'selected_chaff_resource_id': selected_id, 'resource': {'headers': headers,
            'expected_response': expected, 'request_stream_bytes': request_size,
            'response_qualification_sha256': digest}}
        if (canonical_json(core) != canonical_json(expected_core)
                or canonical_json(manifest) != canonical_json(chaff.derive_response_only_chaff_manifest(sidecar, resource))):
            raise ValueError('historical generic launch bytes are not derived by the old evidence')
        chaff_key = 'chaff_manifest'
        historical_binding = {'profile': 'historical-generic-response-qualified-v1',
            'application_workload_sha256': base_sha, 'selected_chaff_resource_id': selected_id,
            'native_manifest_sha256': sha256_file(paths[chaff_key])}
    for item in observed.values():
        path = item[0]; info = path.lstat()
        now = (path, info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_nlink,
               info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if now != item or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('historical launch file/path changed during validation')
    return {'paths': paths, 'chaff_key': chaff_key, 'historical_binding': historical_binding}


def validate_retained_mode_input(root, runtime, input_path, input_sha256):
    """Complete fail-before-backend validation of one declared retained-mode input."""
    from .resource_study_cohorts import verifier_contract
    path = Path(input_path)
    input_raw = retained_mode_read(path, input_sha256)
    value = json.loads(input_raw)
    fields = {'record_type', 'schema_version', 'root', 'parent', 'hostname', 'mode',
              'historical_root', 'historical_enrollment', 'runtime', 'science', 'seed',
              'source_contract', 'canonical_runtime', 'resource_selection', 'scientific_credit'}
    if (type(value) is not dict or set(value) != fields or value['record_type'] != RETAINED_MODE_INPUT
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['root'] != str(Path(root).absolute()) or value['mode'] != 'buflo'
            or value['runtime'] != _retained_runtime(runtime) or value['scientific_credit'] is not False
            or type(value['seed']) is not int or not 0 <= value['seed'] < 2 ** 64
            or value['source_contract'] != verifier_contract()
            or type(value['science']) is not dict
            or set(value['science']) != {'hostname', 'urls', 'workload_sha256', 'settings', 'policies'}
            or value['hostname'] != value['science']['hostname']
            or type(value['parent']) is not dict or set(value['parent']) != {'root', 'study_sha256', 'head_sha256'}):
        raise ValueError('retained-mode input changes explicit scope/runtime/science/Source')
    old_root = Path(value['historical_root'])
    old_path, old_sha = _retained_ref(value['historical_enrollment'])
    if (not old_root.is_absolute() or old_root == Path(root).absolute()
            or old_path != old_root / 'classes' / value['hostname'] / 'enrollment.json'):
        raise ValueError('historical enrollment is not its exact same-host immutable root')
    old = json.loads(retained_mode_read(old_path, old_sha))
    checked = _retained_old_assets(old_root, old, value['science'])
    return {'input': value, 'input_raw': input_raw, 'input_sha256': input_sha256, 'historical': old, **checked}


def retained_mode_source_binding(source_contract):
    """Keep an exact126 preparation qualifier under the qualified current reader.

    This transient binding changes execution only. It never rewrites a core,
    receipt, runtime, readiness result, historical qualification or credit.
    No other supported historical profile is a retained-core capability.
    """
    from .resource_study_cohorts import verifier_contract
    from . import resource_study_reader_compatibility as reader
    execution = verifier_contract()
    qualified = reader.qualify_execution(execution)
    exact126 = reader.prior_exact126_execution_contract()
    if type(source_contract) is not dict or source_contract not in (exact126, execution):
        raise ValueError('retained-mode core requires exact126 or exact current qualified Source')
    return reader.execution_binding(source_contract, qualified)


def retained_mode_assets(root, enrollment, *, provisional=False):
    """Pure current launch binding; final raw readiness is replayed at admission."""
    binding = enrollment.get(RETAINED_MODE_KEY)
    if (type(binding) is not dict or set(binding) != {'record_type', 'study_root', 'preparation_dir', 'core_sha256', 'readiness_sha256'}
            or binding['record_type'] != RETAINED_MODE_BINDING):
        raise ValueError('retained-mode preparation binding is incomplete')
    study = Path(binding['study_root']); relative = _retained_relative(binding['preparation_dir'])
    base = study / relative; root = Path(root).absolute()
    if root not in (study, base):
        raise ValueError('retained-mode enrollment has a foreign root')
    core = json.loads(retained_mode_read(base / 'core.json', binding['core_sha256']))
    if (type(core) is not dict or set(core) != {'record_type', 'schema_version', 'input', 'input_sha256', 'historical_enrollment_path', 'assets', 'historical_binding'}
            or core['record_type'] != RETAINED_MODE_CORE or type(core['schema_version']) is not int or core['schema_version'] != 1
            or core['input']['root'] != str(study)
            or core['input']['runtime'] != _retained_runtime(enrollment.get('runtime'))
            or core['input']['mode'] != 'buflo' or core['input']['hostname'] != enrollment.get('hostname')
            or hashlib.sha256(retained_mode_read(base / 'input.json')).hexdigest() != core['input_sha256']
            or json.loads(retained_mode_read(base / 'input.json')) != core['input']):
        raise ValueError('retained-mode core/input/current runtime changed')
    _, canonical_sha = _retained_ref(core['input']['canonical_runtime'])
    if canonical_sha != enrollment['runtime']['canonical_sha256']:
        raise ValueError('retained canonical reference differs from exact current runtime SHA')
    canonical = json.loads(retained_mode_read(base / 'canonical-runtime.json', canonical_sha))
    if (type(canonical) is not dict
            or canonical.get('installed_client_sha256') != enrollment['runtime']['client_sha256']
            or canonical.get('platform') != enrollment['runtime']['platform']
            or canonical.get('collection_image_digest') != enrollment['runtime']['collection_image_digest']
            or canonical.get('prepare_image_digest') != enrollment['runtime']['prepare_image_digest']
            or canonical.get('source') != enrollment['runtime']['source']):
        raise ValueError('retained canonical bytes differ from exact current runtime fields')
    retained_mode_source_binding(core['input']['source_contract'])
    old_path = base / _retained_relative(core['historical_enrollment_path'])
    old = json.loads(retained_mode_read(old_path, core['input']['historical_enrollment']['sha256']))
    assets = core['assets']
    if type(assets) is not dict or not assets:
        raise ValueError('retained-mode core lacks its frozen historical assets')
    for old_relative, row in assets.items():
        _retained_relative(old_relative)
        if type(row) is not dict or set(row) != {'path', 'sha256'} or old['files'].get(old_relative) != row['sha256']:
            raise ValueError('retained historical asset has foreign provenance')
        retained_mode_read(base / _retained_relative(row['path']), row['sha256'])
    # Replay historical validators in their copied original relative namespace.
    historical_root = base / 'historical'
    history = _retained_old_assets(historical_root, old, core['input']['science'])
    if history['historical_binding'] != core['historical_binding']:
        raise ValueError('retained historical parameter profile changed')
    prefix = '' if root == base else relative + '/'
    expected_paths = {key: prefix + 'historical/' + value if value is not None else None
                      for key, value in old['paths'].items()}
    science = core['input']['science']
    if (enrollment.get('paths') != expected_paths or enrollment.get('urls') != science['urls']
            or enrollment.get('workload_sha256') != science['workload_sha256']
            or enrollment.get('workload_path') != expected_paths['manifest']
            or enrollment.get('mode_settings', {}).get('buflo') != science['settings']
            or enrollment.get('mode_policies', {}).get('buflo') != science['policies']
            or enrollment.get('mode_readiness') != {mode: mode == 'buflo' and not provisional for mode in MODES}
            or 'buflo_chaff_selection' in enrollment or 'buflo_small_response_aggregate_selection' in enrollment
            or enrollment.get('scientific_credit') is not False):
        raise ValueError('retained current enrollment changes frozen selected-mode parameters')
    expected_files = {prefix + row['path']: row['sha256'] for row in assets.values()}
    expected_files.update({prefix + 'core.json': binding['core_sha256'],
        prefix + 'input.json': core['input_sha256'],
        prefix + 'canonical-runtime.json': canonical_sha,
        prefix + core['historical_enrollment_path']: core['input']['historical_enrollment']['sha256']})
    for name, digest in expected_files.items():
        if enrollment.get('files', {}).get(name) != digest:
            raise ValueError('retained current enrollment omits an exact asset/core digest')
    if provisional:
        if binding['readiness_sha256'] is not None:
            raise ValueError('pre-readiness enrollment cannot claim a later readiness result')
    else:
        if type(binding['readiness_sha256']) is not str or _SHA256.fullmatch(binding['readiness_sha256']) is None:
            raise ValueError('final retained enrollment lacks positive fresh readiness')
        result = json.loads(retained_mode_read(base / 'readiness-result.json', binding['readiness_sha256']))
        if (set(result) != {'record_type', 'schema_version', 'core_sha256', 'runtime', 'receipt', 'flight', 'scientific_credit'}
                or result['record_type'] != RETAINED_MODE_RESULT or type(result['schema_version']) is not int or result['schema_version'] != 1
                or result['core_sha256'] != binding['core_sha256'] or result['runtime'] != enrollment['runtime']
                or result['scientific_credit'] is not False
                or enrollment['files'].get(prefix + 'readiness-result.json') != binding['readiness_sha256']):
            raise ValueError('final retained readiness result is foreign or mutable')
        for item in [result['receipt'], *result['flight'].values()]:
            path, digest = _retained_ref(item)
            if not path.is_relative_to(study):
                raise ValueError('readiness evidence escaped its owning study')
            retained_mode_read(path, digest)
    return {'binding': binding, 'base': base, 'study_root': study, 'core': core,
            'historical': old, 'chaff_key': history['chaff_key'],
            'historical_binding': history['historical_binding']}


def retained_mode_receipt_binding(root, enrollment, *, provisional=False):
    value = retained_mode_assets(root, enrollment, provisional=provisional)
    return {'record_type': RETAINED_MODE_BINDING,
        'core_sha256': value['binding']['core_sha256'],
        'readiness_sha256': value['binding']['readiness_sha256'],
        'runtime': enrollment['runtime'],
        'historical_runtime': value['historical']['runtime'],
        'historical_enrollment_sha256': value['core']['input']['historical_enrollment']['sha256'],
        'historical_binding': value['historical_binding'],
        'historical_qualification_reexecuted': False}


def _retained_native_enrollment(directory, hostname, runtime, *, readiness_core_sha256=None):
    root = Path(os.path.abspath(directory))
    basename = 'readiness-enrollment.json' if readiness_core_sha256 is not None else 'enrollment.json'
    enrollment = json.loads(retained_mode_read(root / basename))
    provisional = readiness_core_sha256 is not None
    checked = retained_mode_assets(root, enrollment, provisional=provisional)
    if (enrollment['hostname'] != hostname or enrollment['runtime'] != _retained_runtime(runtime)
            or provisional and checked['binding']['core_sha256'] != readiness_core_sha256):
        raise ValueError('retained Native enrollment differs from exact readiness/current runtime')
    return root, enrollment


if __name__ == "__main__":
    raise SystemExit(main())
