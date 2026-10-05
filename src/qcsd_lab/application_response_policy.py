"""Prospective full-graph HTTP response policy, separate from 2xx qualification.

Completed HTTP errors are real responses. This policy permits only auxiliary
terminal leaves and never makes them known-valid navigation/chaff resources.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
import hashlib
import re
from typing import Any
from urllib.parse import urlsplit

HTTP_2XX_ONLY_POLICY = "http-2xx-only-v1"
COMPLETED_TERMINAL_HTTP_ERRORS_POLICY = "completed-terminal-http-errors-v1"
LEGACY_APPLICATION_RESPONSE_POLICY = HTTP_2XX_ONLY_POLICY
TERMINAL_HTTP_ERROR_POLICY = COMPLETED_TERMINAL_HTTP_ERRORS_POLICY
EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY = "exact-response-body-v1"
VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY = "variable-primary-document-body-v1"
EXACT_RESPONSE_BODY_POLICY = EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY = VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
PRIMARY_ORIGIN_CHAFF_POLICY = "primary-origin-v1"
APPROVED_ORIGINS_CHAFF_POLICY = "prepared-approved-origins-v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
APPLICATION_BODY_IDENTITY_FIELD = "application_body_identity_policy"
EXACT_APPLICATION_BODY_IDENTITY_POLICY = "exact-prepared-application-body-v1"
COMPLETE_APPLICATION_DELIVERY_POLICY = "complete-current-application-delivery-v1"


def validate_application_body_identity_policy(value: Any) -> str:
    """A closed prospective capture policy; absence keeps exact body checks."""
    if value is None:
        return EXACT_APPLICATION_BODY_IDENTITY_POLICY
    if not isinstance(value, str) or value not in {
        EXACT_APPLICATION_BODY_IDENTITY_POLICY, COMPLETE_APPLICATION_DELIVERY_POLICY,
    }:
        raise ValueError("application body identity policy is unknown or malformed")
    return value


def application_body_identity_policy(configuration: Mapping[str, Any]) -> str:
    if APPLICATION_BODY_IDENTITY_FIELD not in configuration:
        return EXACT_APPLICATION_BODY_IDENTITY_POLICY
    value = configuration[APPLICATION_BODY_IDENTITY_FIELD]
    if value is None:
        raise ValueError("explicit application body identity policy cannot be null")
    return validate_application_body_identity_policy(value)


def _observed_content_encoding(row: Mapping[str, Any]) -> str:
    headers = row.get("response_headers")
    if (not isinstance(headers, list) or any(not isinstance(pair, list) or len(pair) != 2
        or any(not isinstance(item, str) for item in pair) for pair in headers)):
        raise ValueError("complete application delivery lacks observed response headers")
    values = [value.strip() for name, value in headers if name.lower() == "content-encoding"]
    if any(not value for value in values):
        raise ValueError("complete application delivery has an empty observed encoding")
    lengths = [value.strip() for name, value in headers if name.lower() == "content-length"]
    if any(re.fullmatch(r"[0-9]+", value) is None or int(value) != row["bytes"]
           or row.get("content_length") != int(value) for value in lengths):
        raise ValueError("complete application delivery changed its observed Content-Length facts")
    return ",".join(values) if values else "identity"


def _complete_delivery_endpoints(manifest: Mapping[str, Any], run: Mapping[str, Any]) -> None:
    from .manifest import https_origin
    expected = {https_origin(row["url"]) for row in manifest["resources"]}
    if None in expected:
        raise ValueError("complete application delivery has an invalid prepared HTTPS origin")
    endpoints = run.get("endpoints")
    if not isinstance(endpoints, list) or len(endpoints) != len(expected):
        raise ValueError("complete application delivery lacks its exact endpoint set")
    identities, origins = set(), set()
    for row in endpoints:
        if (not isinstance(row, Mapping) or type(row.get("id")) is not int
            or row["id"] < 0 or row["id"] in identities or row.get("negotiated_protocol") != "h3"
            or not isinstance(row.get("origin"), str)):
            raise ValueError("complete application delivery changed its unique HTTP3 endpoints")
        parts = urlsplit(row["origin"])
        origin = https_origin(row["origin"])
        if (origin not in expected or origin in origins or parts.path not in {"", "/"}
            or parts.query or parts.fragment):
            raise ValueError("complete application delivery changed its prepared endpoint origins")
        identities.add(row["id"])
        origins.add(origin)
    if origins != expected:
        raise ValueError("complete application delivery omits a prepared HTTP3 origin")


def validate_application_response_policy(value: Any) -> str:
    """Validate a prospective opt-in argument or optional prepared field."""
    if value is None:
        return HTTP_2XX_ONLY_POLICY
    if not isinstance(value, str) or value not in {HTTP_2XX_ONLY_POLICY, COMPLETED_TERMINAL_HTTP_ERRORS_POLICY}:
        raise ValueError("application response policy is unknown or malformed")
    return value


def application_response_policy(manifest: Mapping[str, Any]) -> str:
    preparation = manifest.get("preparation")
    if not isinstance(preparation, Mapping) or "application_response_policy" not in preparation:
        return HTTP_2XX_ONLY_POLICY
    value = preparation["application_response_policy"]
    if value is None:
        raise ValueError("explicit application response policy cannot be null")
    return validate_application_response_policy(value)


def validate_primary_document_identity_policy(value: Any) -> str:
    if value is None:
        return EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
    if not isinstance(value, str) or value not in {
        EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY, VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
    }:
        raise ValueError("primary document identity policy is unknown or malformed")
    return value


def primary_document_identity_policy(manifest: Mapping[str, Any]) -> str:
    preparation = manifest.get("preparation")
    if not isinstance(preparation, Mapping) or "primary_document_identity_policy" not in preparation:
        return EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
    if preparation["primary_document_identity_policy"] is None:
        raise ValueError("explicit primary document identity policy cannot be null")
    return validate_primary_document_identity_policy(preparation["primary_document_identity_policy"])


def validate_qualified_chaff_origin_policy(value: Any) -> str:
    """Validate an opt-in argument; absence retains the historical origin rule."""
    if value is None:
        return PRIMARY_ORIGIN_CHAFF_POLICY
    if not isinstance(value, str) or value != APPROVED_ORIGINS_CHAFF_POLICY:
        raise ValueError("qualified chaff origin policy is unknown or malformed")
    return value


def qualified_chaff_origin_policy(manifest: Mapping[str, Any]) -> str:
    preparation = manifest.get("preparation")
    if not isinstance(preparation, Mapping) or "qualified_chaff_origin_policy" not in preparation:
        return PRIMARY_ORIGIN_CHAFF_POLICY
    value = preparation["qualified_chaff_origin_policy"]
    if value is None:
        raise ValueError("explicit qualified chaff origin policy cannot be null")
    return validate_qualified_chaff_origin_policy(value)


def terminal_http_error_resource_allowed(
    resource: Mapping[str, Any], resources: Sequence[Mapping[str, Any]],
) -> bool:
    """The unique primary Document is id 0; negative auxiliary leaves stay False."""
    identifier = resource.get("id")
    return bool(type(identifier) is int and identifier != 0
                and resource.get("known_valid") is False
                and resource.get("chaff_priority") is False
                and bool(resource.get("depends_on"))
                and not any(identifier in row.get("depends_on", []) for row in resources))


def validate_prepared_response_graph(manifest: Mapping[str, Any]) -> dict[str, Any]:
    policy = application_response_policy(manifest)
    primary_policy = primary_document_identity_policy(manifest)
    if (primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
        and policy != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY):
        raise ValueError("variable primary document identity requires the terminal HTTP response policy")
    preparation = manifest.get("preparation")
    resources = manifest.get("resources")
    expected = preparation.get("expected_responses") if isinstance(preparation, Mapping) else None
    if not isinstance(resources, list) or not isinstance(expected, list):
        raise ValueError("prepared application graph or expected responses are missing")
    by_id = {row.get("id"): row for row in resources if isinstance(row, Mapping)}
    responses = {row.get("resource_id"): row for row in expected if isinstance(row, Mapping)}
    if (not by_id or len(by_id) != len(resources) or len(responses) != len(expected)
        or set(by_id) != set(responses)
        or any(type(identifier) is not int for identifier in (*by_id, *responses))):
        raise ValueError("prepared response identities must cover the full unique graph")
    if any(not isinstance(row.get("depends_on"), list)
           or any(type(identifier) is not int or identifier not in by_id for identifier in row["depends_on"])
           for row in resources):
        raise ValueError("prepared application graph contains invalid dependency identifiers")
    negative = []
    for identifier, response in responses.items():
        status, size, digest = response.get("status"), response.get("bytes"), response.get("body_sha256")
        if (type(status) is not int or not 100 <= status <= 599 or type(size) is not int or size < 0
            or not isinstance(digest, str) or SHA256.fullmatch(digest) is None):
            raise ValueError("prepared application response identity is malformed")
        resource = by_id[identifier]
        if 200 <= status < 300:
            if policy == COMPLETED_TERMINAL_HTTP_ERRORS_POLICY and resource.get("known_valid") is not True:
                raise ValueError("2xx resources must retain their actual known-valid qualification")
            continue
        if (policy != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY or not 400 <= status <= 599
            or not terminal_http_error_resource_allowed(resource, resources)):
            raise ValueError("non-2xx response is not an authorized auxiliary terminal leaf")
        negative.append(identifier)
    if policy == COMPLETED_TERMINAL_HTTP_ERRORS_POLICY:
        primary = by_id.get(0)
        if (primary is None or primary.get("type") != "Document" or primary.get("depends_on") != []
            or primary.get("url") not in {preparation.get("source_url"), preparation.get("final_url")}
            or primary.get("known_valid") is not True or not 200 <= responses[0]["status"] < 300):
            raise ValueError("application response policy requires a known-valid 2xx primary Document")
    if primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY:
        from .supplied_static_preparation import COVERAGE, is_static
        from .supplied_static_capture_amendment import is_amended
        from .supplied_static_budget_successor import is_budget
        coverage_policy = COVERAGE if is_static(preparation) or is_amended(preparation) or is_budget(preparation) else "all-approved-origins-and-rendered-resources"
        from .whole_graph_supplement import is_whole, COVERAGE as WHOLE_COVERAGE
        if is_whole(preparation) or is_amended(preparation) and "whole_graph_get_evidence" in preparation:
            coverage_policy = WHOLE_COVERAGE
        from .rapid_selected_capture_input import is_selected, validate_preparation as validate_selected_preparation
        if is_selected(preparation):
            validate_selected_preparation(preparation, resources)
            coverage_policy = WHOLE_COVERAGE if "whole_graph_get_evidence" in preparation else COVERAGE
        coverage = preparation.get("coverage_admission")
        required = coverage.get("required_resources") if isinstance(coverage, Mapping) else None
        if (policy != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY
            or not isinstance(coverage, Mapping)
            or coverage.get("policy") != coverage_policy
            or not isinstance(required, list) or len(required) != len(resources)
            or any(not isinstance(row, Mapping) or type(row.get("id")) is not int
                   or not isinstance(row.get("url"), str) for row in required)
            or {(row["id"], row["url"]) for row in required}
            != {(row["id"], row["url"]) for row in resources}
            or type(preparation.get("max_response_bytes")) is not int
            or preparation["max_response_bytes"] <= 0
            or by_id[0].get("chaff_priority") is not False
            or responses[0]["bytes"] <= 0
            or responses[0]["bytes"] > preparation["max_response_bytes"]):
            raise ValueError("variable primary document identity requires bounded unchanged complete graph coverage")
    return {"policy": policy, "resource_ids": sorted(by_id),
            "terminal_http_error_resource_ids": sorted(negative)}


def _primary_content_type(row: Mapping[str, Any]) -> str:
    headers = row.get("response_headers")
    if (not isinstance(headers, list) or any(not isinstance(pair, list) or len(pair) != 2
        or any(not isinstance(item, str) for item in pair) for pair in headers)):
        raise ValueError("primary Document has no retained response headers")
    values = [value for name, value in headers if name.lower() == "content-type"]
    if len(values) != 1 or values[0].split(";", 1)[0].strip().lower() not in {
        "text/html", "application/xhtml+xml",
    }:
        raise ValueError("primary Document is not an actual public HTML response")
    return values[0]


def validate_primary_document_response(
    manifest: Mapping[str, Any], row: Mapping[str, Any], *,
    expected_content_type: str | None = None,
) -> dict[str, Any]:
    """Validate actual primary delivery; retain its real size and hash unchanged."""
    validate_prepared_response_graph(manifest)
    resource = next(resource for resource in manifest["resources"] if resource["id"] == 0)
    target = next(row for row in manifest["preparation"]["expected_responses"] if row["resource_id"] == 0)
    cap = manifest["preparation"]["max_response_bytes"]
    if (not isinstance(row, Mapping) or type(row.get("resource_id")) is not int or row["resource_id"] != 0
        or row.get("url") != resource["url"] or row.get("complete") is not True
        or row.get("outcome") != "succeeded" or type(row.get("status")) is not int
        or row["status"] != target["status"] or not 200 <= row["status"] < 300
        or type(row.get("bytes")) is not int or not 0 < row["bytes"] <= cap
        or not isinstance(row.get("body_sha256"), str) or SHA256.fullmatch(row["body_sha256"]) is None
        or row["body_sha256"] == hashlib.sha256(b"").hexdigest()
        or row.get("request_headers") != resource["headers"]):
        raise ValueError("primary Document was not delivered complete under its exact public identity")
    if row.get("content_length") is not None and (
        type(row["content_length"]) is not int or row["content_length"] != row["bytes"]
    ):
        raise ValueError("primary Document did not retain its declared complete body")
    content_type = _primary_content_type(row)
    if expected_content_type is not None and content_type != expected_content_type:
        raise ValueError("primary Document changed its prepared HTML content type")
    return {"content_type": content_type, "bytes": row["bytes"], "body_sha256": row["body_sha256"]}


def validate_application_responses(
    manifest: Mapping[str, Any], run: Mapping[str, Any], *, require_identity: bool = True,
    body_identity_policy: str | None = None,
) -> dict[str, Any]:
    """Reopen exact delivery without normalizing raw status or runner outcomes."""
    graph = validate_prepared_response_graph(manifest)
    body_policy = validate_application_body_identity_policy(body_identity_policy)
    complete_delivery = body_policy == COMPLETE_APPLICATION_DELIVERY_POLICY
    cap = manifest["preparation"].get("max_response_bytes")
    if complete_delivery and (type(cap) is not int or cap <= 0
        or type(run.get("max_response_bytes")) is not int or run["max_response_bytes"] != cap):
        raise ValueError("complete application delivery changed its declared observed response cap")
    if complete_delivery:
        _complete_delivery_endpoints(manifest, run)
    policy = graph["policy"]
    primary_policy = primary_document_identity_policy(manifest)
    primary_evidence = (validate_primary_document_identity_evidence(manifest)
                        if primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY else None)
    recorded_policy = run.get("application_response_policy", HTTP_2XX_ONLY_POLICY)
    if recorded_policy != policy:
        raise ValueError("runner application response policy differs from prepared policy")
    if (run.get("completion_status") != "complete" or run.get("error") is not None
        or run.get("error_class") is not None or run.get("terminal_evidence_render_errors", []) != []
        or (policy == COMPLETED_TERMINAL_HTTP_ERRORS_POLICY and run.get("terminal_evidence_render_errors") != [])):
        raise ValueError("application runner did not complete with intact terminal evidence")
    resources = {row["id"]: row for row in manifest["resources"]}
    expected = {row["resource_id"]: row for row in manifest["preparation"]["expected_responses"]}
    rows = run.get("responses")
    if not isinstance(rows, list):
        raise ValueError("application runner has no response ledger")
    seen = set()
    signatures = []
    observed = []
    for row in rows:
        if (not isinstance(row, Mapping) or type(row.get("resource_id")) is not int
            or row["resource_id"] in seen or row["resource_id"] not in resources):
            raise ValueError("application response ledger changed unique full-graph resource IDs")
        identifier = row["resource_id"]
        target = expected[identifier]
        if (row.get("url") != resources[identifier]["url"] or row.get("complete") is not True
            or row.get("outcome") != "succeeded" or type(row.get("status")) is not int
            or row["status"] != target["status"] or type(row.get("bytes")) is not int
            or row["bytes"] < 0 or not isinstance(row.get("body_sha256"), str)
            or SHA256.fullmatch(row["body_sha256"]) is None):
            raise ValueError(f"application resource {identifier} was not delivered under its exact declared status")
        if ((complete_delivery or primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY)
            and row.get("request_headers") != resources[identifier]["headers"]):
            raise ValueError(f"application resource {identifier} changed its frozen request headers")
        variable_primary = identifier == 0 and primary_policy == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
        if complete_delivery and identifier == 0 and not variable_primary:
            validate_primary_document_response(manifest, row)
        if variable_primary:
            from .supplied_static_preparation import is_static
            from .supplied_static_capture_amendment import is_amended
            from .whole_graph_supplement import is_whole
            from .supplied_static_budget_successor import is_budget
            from .rapid_selected_capture_input import is_selected
            primary_rows = (primary_evidence["complete_get_primary_responses"] if is_static(manifest["preparation"]) or is_amended(manifest["preparation"]) or is_whole(manifest["preparation"]) or is_budget(manifest["preparation"]) or is_selected(manifest["preparation"])
                            else primary_evidence["stability_primary_responses"])
            validate_primary_document_response(manifest, row,
                expected_content_type=_primary_content_type(primary_rows[0]))
        if complete_delivery:
            if (row["bytes"] > cap or (target["bytes"] > 0 and row["bytes"] == 0)
                or (row["bytes"] > 0 and row["body_sha256"] == hashlib.sha256(b"").hexdigest())
                or (row["bytes"] == 0 and row["body_sha256"] != hashlib.sha256(b"").hexdigest())):
                raise ValueError(f"application resource {identifier} violates its complete nonempty body bound")
            length = row.get("content_length")
            if length is not None and (type(length) is not int or length < 0 or length != row["bytes"]):
                raise ValueError(f"application resource {identifier} did not retain its declared complete body")
            observed.append({"resource_id": identifier, "status": row["status"], "bytes": row["bytes"],
                "body_sha256": row["body_sha256"], "content_encoding": _observed_content_encoding(row)})
        if require_identity and not complete_delivery and not variable_primary and (
            row["bytes"] != target["bytes"] or row["body_sha256"] != target["body_sha256"]
        ):
            raise ValueError(f"application resource {identifier} differs from prepared response identity")
        if identifier in graph["terminal_http_error_resource_ids"] and row.get("content_length") is not None:
            length = row["content_length"]
            if type(length) is not int or length < 0 or length != row["bytes"]:
                raise ValueError(f"application resource {identifier} did not retain its declared complete body")
        seen.add(identifier)
        signatures.append((identifier, row["status"], row["bytes"], row["body_sha256"], row["outcome"]))
    if seen != set(resources):
        raise ValueError("application response ledger omits a full-graph resource")
    result = {**graph, "response_signature": sorted(signatures)}
    if complete_delivery:
        result.update(application_body_identity_policy=body_policy,
            observed_responses=sorted(observed, key=lambda row: row["resource_id"]),
            content_equality_across_visits_claimed=False)
    return result


def application_response_identity_signature(
    manifest: Mapping[str, Any], signature: list[tuple[Any, ...]] | None,
    *, body_identity_policy: str | None = None,
) -> list[tuple[Any, ...]] | None:
    """Project comparison only, after the caller validates actual raw delivery."""
    body_policy = validate_application_body_identity_policy(body_identity_policy)
    if signature is None:
        return None
    if body_policy == COMPLETE_APPLICATION_DELIVERY_POLICY:
        graph = validate_prepared_response_graph(manifest)
        expected = {row["resource_id"]: row for row in manifest["preparation"]["expected_responses"]}
        if (not isinstance(signature, list) or len(signature) != len(graph["resource_ids"])
            or any(not isinstance(row, (tuple, list)) or len(row) != 5 or type(row[0]) is not int
                   or row[0] not in expected or row[1] != expected[row[0]]["status"]
                   or row[4] != "succeeded" for row in signature)
            or {row[0] for row in signature} != set(graph["resource_ids"])):
            raise ValueError("complete delivery comparison changed its full graph or declared statuses")
        return [(identifier, status, body_policy, body_policy, outcome)
                for identifier, status, _size, _digest, outcome in signature]
    if primary_document_identity_policy(manifest) != VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY:
        return deepcopy(signature)
    validate_primary_document_identity_evidence(manifest)
    identifiers = {row["id"] for row in manifest["resources"]}
    if (not isinstance(signature, list) or len(signature) != len(identifiers)
        or any(not isinstance(row, (tuple, list)) or len(row) != 5
               or type(row[0]) is not int for row in signature)
        or {row[0] for row in signature} != identifiers):
        raise ValueError("application identity signature changed complete resource coverage")
    return [(identifier, status, VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
             VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY, outcome)
            if identifier == 0 else (identifier, status, size, digest, outcome)
            for identifier, status, size, digest, outcome in signature]


_PRIMARY_RESPONSE_KEYS = {"resource_id", "url", "status", "bytes", "body_sha256", "content_length",
                          "request_headers", "response_headers", "complete", "outcome"}


def build_primary_document_identity_evidence(
    manifest: Mapping[str, Any], runs: Sequence[Mapping[str, Any]], *, stability_run_sha256s: list[str],
) -> dict[str, Any]:
    if primary_document_identity_policy(manifest) != VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY:
        raise ValueError("variable primary evidence requires its explicit prospective policy")
    preparation = manifest["preparation"]
    witnesses = []
    for run in runs:
        if (run.get("completion_status") != "complete" or run.get("error") is not None
            or run.get("error_class") is not None or run.get("terminal_evidence_render_errors") != []
            or run.get("application_response_policy") != application_response_policy(manifest)):
            raise ValueError("variable primary evidence requires three complete nonerror full graph replays")
        rows = [row for row in run.get("responses", []) if row.get("resource_id") == 0]
        if len(rows) != 1:
            raise ValueError("variable primary evidence requires one actual primary in each run")
        witnesses.append({key: deepcopy(rows[0].get(key)) for key in _PRIMARY_RESPONSE_KEYS})
    value = {"schema_version": 1, "policy": VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
             "application_response_policy": application_response_policy(manifest), "primary_resource_id": 0,
             "max_response_bytes": preparation["max_response_bytes"], "source_url": preparation["source_url"],
             "final_url": preparation["final_url"], "stability_run_sha256s": stability_run_sha256s,
             "stability_primary_responses": witnesses}
    provisional = deepcopy(dict(manifest))
    provisional["preparation"]["primary_document_identity_evidence"] = value
    validate_primary_document_identity_evidence(provisional)
    return value


def validate_primary_document_identity_evidence(manifest: Mapping[str, Any]) -> dict[str, Any] | None:
    from .rapid_selected_capture_input import is_selected, validate_preparation as validate_selected_preparation
    if is_selected(manifest.get("preparation")):
        validate_selected_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["primary_document_identity_evidence"])
    from .supplied_static_budget_successor import is_budget, validate_preparation as validate_budget_preparation
    if is_budget(manifest.get("preparation")):
        validate_budget_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["primary_document_identity_evidence"])
    from .supplied_static_capture_amendment import is_amended, validate_preparation
    if is_amended(manifest.get("preparation")):
        validate_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["primary_document_identity_evidence"])
    from .supplied_static_preparation import is_static, validate_static_preparation
    if is_static(manifest.get("preparation")):
        validate_static_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["primary_document_identity_evidence"])
    from .whole_graph_supplement import is_whole, validate_preparation as validate_whole_preparation
    if is_whole(manifest.get("preparation")):
        validate_whole_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["primary_document_identity_evidence"])
    graph = validate_prepared_response_graph(manifest)
    preparation = manifest["preparation"]
    evidence = preparation.get("primary_document_identity_evidence")
    if primary_document_identity_policy(manifest) == EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY:
        if evidence is not None:
            raise ValueError("strict primary document identity cannot gain variable-body evidence")
        return None
    fields = {"schema_version", "policy", "application_response_policy", "primary_resource_id",
              "max_response_bytes", "source_url", "final_url", "stability_run_sha256s", "stability_primary_responses"}
    if (not isinstance(evidence, Mapping) or set(evidence) != fields
        or type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1
        or evidence["policy"] != VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
        or evidence["application_response_policy"] != graph["policy"]
        or type(evidence["primary_resource_id"]) is not int or evidence["primary_resource_id"] != 0
        or any(evidence[key] != preparation[key] for key in ("max_response_bytes", "source_url", "final_url"))
        or type(evidence["max_response_bytes"]) is not int or preparation.get("stability_runs") != 3
        or type(preparation.get("stability_runs")) is not int):
        raise ValueError("primary document identity evidence changed its declared policy or preparation")
    hashes, rows = evidence["stability_run_sha256s"], evidence["stability_primary_responses"]
    if (not isinstance(hashes, list) or len(hashes) != 3
        or any(not isinstance(value, str) or SHA256.fullmatch(value) is None for value in hashes)
        or not isinstance(rows, list) or len(rows) != 3
        or any(not isinstance(row, Mapping) or set(row) != _PRIMARY_RESPONSE_KEYS for row in rows)):
        raise ValueError("primary document identity evidence requires all three actual replay witnesses")
    content_type = _primary_content_type(rows[0])
    for row in rows:
        validate_primary_document_response(manifest, row, expected_content_type=content_type)
    first = next(row for row in preparation["expected_responses"] if row["resource_id"] == 0)
    if any(first[key] != rows[0][key] for key in ("status", "bytes", "body_sha256")):
        raise ValueError("primary prepared identity differs from its first actual replay snapshot")
    return deepcopy(dict(evidence))


validate_application_response_graph = validate_prepared_response_graph


def validate_application_response_policy_evidence(
    manifest: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Validate compact actual preflight facts and the three identity witnesses.

    Production probe resolution independently reopens the raw child/run ledger;
    these compact facts preserve the negative GET and hashes without embedding
    bodies, packet CSVs or the whole probe graph in every prepared workload.
    """
    from .rapid_selected_capture_input import is_selected, validate_preparation as validate_selected_preparation
    if is_selected(manifest.get("preparation")):
        validate_selected_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["application_response_policy_evidence"])
    from .supplied_static_budget_successor import is_budget, validate_preparation as validate_budget_preparation
    if is_budget(manifest.get("preparation")):
        validate_budget_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["application_response_policy_evidence"])
    from .supplied_static_capture_amendment import is_amended, validate_preparation
    if is_amended(manifest.get("preparation")):
        validate_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["application_response_policy_evidence"])
    from .supplied_static_preparation import is_static, validate_static_preparation
    if is_static(manifest.get("preparation")):
        validate_static_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["application_response_policy_evidence"])
    from .whole_graph_supplement import is_whole, validate_preparation as validate_whole_preparation
    if is_whole(manifest.get("preparation")):
        validate_whole_preparation(manifest["preparation"], manifest["resources"])
        return deepcopy(manifest["preparation"]["application_response_policy_evidence"])
    graph = validate_prepared_response_graph(manifest)
    preparation = manifest["preparation"]
    evidence = preparation.get("application_response_policy_evidence")
    identifiers = graph["terminal_http_error_resource_ids"]
    if not identifiers:
        if evidence is not None:
            raise ValueError("application response policy evidence has no declared terminal HTTP errors")
        return None
    if graph["policy"] != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY or not isinstance(evidence, Mapping):
        raise ValueError("declared terminal HTTP errors lack their retained preflight evidence")
    keys = {"schema_version", "policy", "probe_input_sha256", "probe_output_sha256",
            "child_execution_sha256", "get_run_sha256", "client_provenance", "get_responses",
            "get_endpoints", "stability_run_sha256s", "stability_responses"}
    if (set(evidence) != keys or type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1
        or evidence["policy"] != graph["policy"]):
        raise ValueError("application response policy evidence fields changed")
    for key in ("probe_input_sha256", "probe_output_sha256", "child_execution_sha256", "get_run_sha256"):
        if not isinstance(evidence[key], str) or SHA256.fullmatch(evidence[key]) is None:
            raise ValueError("application response policy evidence lacks actual raw hashes")
    provenance = evidence["client_provenance"]
    provenance_keys = {"neqo_version", "neqo_base_commit", "published_qcsd_commit", "migration_commit"}
    if (not isinstance(provenance, Mapping) or set(provenance) != provenance_keys
        or any(provenance[key] != preparation[key] for key in provenance_keys)):
        raise ValueError("terminal HTTP error proof differs from the actual preparation client")
    expected = {row["resource_id"]: row for row in preparation["expected_responses"]}
    resources = {row["id"]: row for row in manifest["resources"]}
    rows = evidence["get_responses"]
    row_keys = {"resource_id", "url", "status", "bytes", "body_sha256", "complete", "outcome", "request_headers"}
    if (not isinstance(rows, list) or len(rows) != len(identifiers)
        or [row.get("resource_id") for row in rows if isinstance(row, Mapping)] != identifiers):
        raise ValueError("terminal HTTP error proof changed the negative resource inventory")
    for row in rows:
        identifier = row["resource_id"]
        target = expected[identifier]
        if (set(row) != row_keys or row["url"] != resources[identifier]["url"]
            or type(row["resource_id"]) is not int
            or row["complete"] is not True or row["outcome"] != "failed"
            or any(row[key] != target[key] for key in ("status", "bytes", "body_sha256"))
            or type(row["status"]) is not int or type(row["bytes"]) is not int
            or not isinstance(row["request_headers"], list)
            or any(not isinstance(pair, list) or len(pair) != 2
                   or any(not isinstance(part, str) for part in pair) for pair in row["request_headers"])):
            raise ValueError("retained negative GET differs from the frozen completed response identity")
    endpoints = evidence["get_endpoints"]
    if (not isinstance(endpoints, list) or not endpoints
        or any(not isinstance(row, Mapping) or set(row) != {"id", "origin", "negotiated_protocol"}
               or type(row["id"]) is not int or row["id"] < 0
               or not isinstance(row["origin"], str) or row["negotiated_protocol"] != "h3" for row in endpoints)):
        raise ValueError("negative GET proof lacks actual HTTP/3 endpoint identities")
    def origin(url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("negative GET proof contains a non-public HTTPS origin")
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        suffix = f":{parsed.port}" if parsed.port not in (None, 443) else ""
        return f"https://{host}{suffix}"
    if (len({row["id"] for row in endpoints}) != len(endpoints)
        or len({origin(row["origin"]) for row in endpoints}) != len(endpoints)
        or any(row["origin"] != origin(row["origin"]) + "/" for row in endpoints)
        or {origin(row["origin"]) for row in endpoints} != {origin(row["url"]) for row in rows}):
        raise ValueError("negative GET proof endpoints differ from exact terminal-resource origins")
    witnesses = evidence["stability_responses"]
    hashes = evidence["stability_run_sha256s"]
    count = preparation.get("stability_runs")
    if (type(count) is not int or count < 2 or not isinstance(hashes, list) or len(hashes) != count
        or any(not isinstance(value, str) or SHA256.fullmatch(value) is None for value in hashes)
        or not isinstance(witnesses, list) or len(witnesses) != count):
        raise ValueError("terminal HTTP error proof requires every declared stability witness")
    for witness in witnesses:
        if (not isinstance(witness, list) or len(witness) != len(identifiers)
            or [row.get("resource_id") for row in witness if isinstance(row, Mapping)] != identifiers):
            raise ValueError("terminal HTTP error stability witness changed resource IDs")
        for row in witness:
            target = expected[row["resource_id"]]
            if (set(row) != row_keys or row["url"] != resources[row["resource_id"]]["url"]
                or row["complete"] is not True or row["outcome"] != "succeeded"
                or type(row["resource_id"]) is not int or type(row["status"]) is not int
                or type(row["bytes"]) is not int
                or any(row[key] != target[key] for key in ("status", "bytes", "body_sha256"))
                or row["request_headers"] != resources[row["resource_id"]]["headers"]):
                raise ValueError("terminal HTTP error stability witness differs from frozen identity/headers")
    return deepcopy(dict(evidence))
