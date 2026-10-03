from copy import deepcopy

import pytest

from qcsd_lab.application_response_policy import (
    APPROVED_ORIGINS_CHAFF_POLICY,
    PRIMARY_ORIGIN_CHAFF_POLICY,
    COMPLETED_TERMINAL_HTTP_ERRORS_POLICY as POLICY,
    HTTP_2XX_ONLY_POLICY,
    application_response_policy,
    qualified_chaff_origin_policy,
    validate_qualified_chaff_origin_policy,
    validate_application_response_graph,
    validate_application_response_policy_evidence,
    validate_application_responses,
)


def test_qualified_chaff_origin_policy_requires_explicit_opt_in():
    assert validate_qualified_chaff_origin_policy(None) == PRIMARY_ORIGIN_CHAFF_POLICY
    assert qualified_chaff_origin_policy({"preparation": {}}) == PRIMARY_ORIGIN_CHAFF_POLICY
    assert qualified_chaff_origin_policy({"preparation": {
        "qualified_chaff_origin_policy": APPROVED_ORIGINS_CHAFF_POLICY,
    }}) == APPROVED_ORIGINS_CHAFF_POLICY


@pytest.mark.parametrize("value", [None, True, {}, [], "primary-origin-v1", "all-origins", ""])
def test_prepared_chaff_origin_policy_rejects_null_and_unknown_values(value):
    with pytest.raises(ValueError, match="chaff origin policy"):
        qualified_chaff_origin_policy({"preparation": {"qualified_chaff_origin_policy": value}})


def policy_workload(count=3):
    resources = [
        {"id": 0, "url": "https://page.test/", "type": "Document", "known_valid": True,
         "depends_on": [], "headers": [["accept", "text/html"]], "chaff_priority": False},
        {"id": 1, "url": "https://cdn.test/session", "type": "XHR", "known_valid": False,
         "depends_on": [0], "headers": [["accept", "application/json"]], "chaff_priority": False},
    ]
    expected = [{"resource_id": 0, "status": 200, "bytes": 2000, "body_sha256": "a" * 64},
                {"resource_id": 1, "status": 401, "bytes": 157, "body_sha256": "b" * 64}]
    provenance = {"neqo_version": "0.1", "neqo_base_commit": "c" * 40,
                  "published_qcsd_commit": "d" * 40, "migration_commit": "e" * 40}
    rows = [{**row, "url": resources[row["resource_id"]]["url"], "complete": True,
             "outcome": "succeeded", "request_headers": resources[row["resource_id"]]["headers"]}
            for row in expected]
    probe = deepcopy(rows[1])
    probe["outcome"] = "failed"
    preparation = {"source_url": "https://page.test/", "final_url": "https://page.test/",
        "application_response_policy": POLICY, "expected_responses": expected,
        "stability_runs": count, **provenance,
        "application_response_policy_evidence": {
            "schema_version": 1, "policy": POLICY,
            "probe_input_sha256": "1" * 64, "probe_output_sha256": "2" * 64,
            "child_execution_sha256": "3" * 64, "get_run_sha256": "4" * 64,
            "client_provenance": provenance, "get_responses": [probe],
            "get_endpoints": [{"id": 0, "origin": "https://cdn.test/", "negotiated_protocol": "h3"}],
            "stability_run_sha256s": ["5" * 64] * count,
            "stability_responses": [[deepcopy(rows[1])] for _ in range(count)],
        }}
    run = {"application_response_policy": POLICY, "completion_status": "complete",
           "error": None, "error_class": None, "terminal_evidence_render_errors": [], "responses": rows}
    return {"resources": resources, "preparation": preparation}, run


def test_declared_completed_401_preserves_status_false_qualification_and_full_identity():
    manifest, run = policy_workload()
    original = deepcopy((manifest, run))
    facts = validate_application_responses(manifest, run)
    assert facts["terminal_http_error_resource_ids"] == [1]
    assert facts["resource_ids"] == [0, 1]
    assert facts["response_signature"][1] == (1, 401, 157, "b" * 64, "succeeded")
    assert validate_application_response_policy_evidence(manifest)["get_responses"][0]["outcome"] == "failed"
    assert (manifest, run) == original


@pytest.mark.parametrize("length", [158, -1, True, False, "157", 157.0])
def test_terminal_error_response_rejects_inconsistent_declared_content_length(length):
    manifest, run = policy_workload()
    run["responses"][1]["content_length"] = length
    with pytest.raises(ValueError, match="declared complete body"):
        validate_application_responses(manifest, run)


@pytest.mark.parametrize("length", [None, 157])
def test_terminal_error_response_accepts_absent_or_exact_declared_content_length(length):
    manifest, run = policy_workload()
    run["responses"][1]["content_length"] = length
    assert validate_application_responses(manifest, run)
    run["responses"][1].pop("content_length")
    assert validate_application_responses(manifest, run)


@pytest.mark.parametrize("change", ["primary-error", "parent-error", "known-true", "chaff", "redirect", "bool-resource", "bool-response"])
def test_error_policy_rejects_unqualified_graph_shapes(change):
    manifest, _ = policy_workload()
    if change == "primary-error":
        manifest["preparation"]["expected_responses"][0]["status"] = 401
        manifest["resources"][0]["known_valid"] = False
    elif change == "parent-error":
        manifest["resources"][0]["depends_on"] = [1]
    elif change == "known-true":
        manifest["resources"][1]["known_valid"] = True
    elif change == "chaff":
        manifest["resources"][1]["chaff_priority"] = True
    elif change == "redirect":
        manifest["preparation"]["expected_responses"][1]["status"] = 302
    elif change == "bool-resource":
        manifest["resources"][1]["id"] = True
    else:
        manifest["preparation"]["expected_responses"][1]["resource_id"] = True
    with pytest.raises(ValueError):
        validate_application_response_graph(manifest)


@pytest.mark.parametrize("change", ["legacy-run", "partial", "reset", "incomplete", "status", "bytes", "hash", "missing", "duplicate", "url", "terminal-render"])
def test_actual_capture_must_match_full_declared_delivery(change):
    manifest, run = policy_workload()
    if change == "legacy-run":
        run.pop("application_response_policy")
    elif change == "terminal-render":
        run.pop("terminal_evidence_render_errors")
    elif change == "partial":
        run["completion_status"] = "partial"
    elif change == "reset":
        run["responses"][1]["outcome"] = "reset"
    elif change == "incomplete":
        run["responses"][1]["complete"] = False
    elif change in {"status", "bytes", "hash", "url"}:
        key, value = {"status": ("status", 403), "bytes": ("bytes", 158),
                      "hash": ("body_sha256", "f" * 64), "url": ("url", "https://else.test/")}[change]
        run["responses"][1][key] = value
    elif change == "missing":
        run["responses"].pop()
    else:
        run["responses"].append(deepcopy(run["responses"][1]))
    with pytest.raises(ValueError):
        validate_application_responses(manifest, run)


@pytest.mark.parametrize("count", [2, 3, 4])
def test_compact_proof_requires_declared_number_of_real_stability_witnesses(count):
    manifest, _ = policy_workload(count)
    assert validate_application_response_policy_evidence(manifest) is not None
    manifest["preparation"]["application_response_policy_evidence"]["stability_responses"].pop()
    with pytest.raises(ValueError, match="every declared stability witness"):
        validate_application_response_policy_evidence(manifest)


@pytest.mark.parametrize("change", ["endpoint", "endpoint-protocol", "probe-hash", "witness", "headers", "client", "missing"])
def test_compact_proof_rejects_wrong_origin_or_identity(change):
    manifest, _ = policy_workload()
    evidence = manifest["preparation"]["application_response_policy_evidence"]
    if change == "endpoint":
        evidence["get_endpoints"][0]["origin"] = "https://else.test/"
    elif change == "endpoint-protocol":
        evidence["get_endpoints"][0]["negotiated_protocol"] = "h2"
    elif change == "probe-hash":
        evidence["get_run_sha256"] = "invalid"
    elif change == "witness":
        evidence["stability_responses"][1][0]["body_sha256"] = "f" * 64
    elif change == "headers":
        evidence["stability_responses"][1][0]["request_headers"] = []
    elif change == "client":
        evidence["client_provenance"] = {**evidence["client_provenance"], "migration_commit": "f" * 40}
    else:
        manifest["preparation"].pop("application_response_policy_evidence")
    with pytest.raises(ValueError):
        validate_application_response_policy_evidence(manifest)


def test_legacy_and_new_2xx_runs_keep_existing_behavior_without_compact_error_proof():
    manifest, run = policy_workload()
    manifest["resources"][1]["known_valid"] = True
    manifest["preparation"]["expected_responses"][1]["status"] = 200
    run["responses"][1]["status"] = 200
    manifest["preparation"].pop("application_response_policy_evidence")
    manifest["preparation"].pop("application_response_policy")
    run.pop("application_response_policy")
    assert application_response_policy(manifest) == HTTP_2XX_ONLY_POLICY
    assert validate_application_responses(manifest, run)
    run["application_response_policy"] = HTTP_2XX_ONLY_POLICY
    assert validate_application_responses(manifest, run)
    manifest["preparation"]["application_response_policy"] = POLICY
    run["application_response_policy"] = POLICY
    assert validate_application_response_policy_evidence(manifest) is None
    assert validate_application_responses(manifest, run)


@pytest.mark.parametrize("value", [None, False, {}, "unknown"])
def test_explicit_prepared_policy_requires_exact_known_opt_in(value):
    manifest, _ = policy_workload()
    manifest["preparation"]["application_response_policy"] = value
    with pytest.raises(ValueError):
        application_response_policy(manifest)
