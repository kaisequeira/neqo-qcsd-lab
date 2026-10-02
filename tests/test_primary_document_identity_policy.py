from copy import deepcopy
import hashlib

import pytest

from qcsd_lab.application_response_policy import (
    EXACT_RESPONSE_BODY_POLICY, VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY,
    application_response_identity_signature, build_primary_document_identity_evidence,
    primary_document_identity_policy, validate_application_responses,
    validate_primary_document_identity_evidence, validate_primary_document_identity_policy,
)
from qcsd_lab.prepare import response_stability_evidence
from tests.test_application_response_policy import policy_workload


def variable_workload():
    manifest, first = policy_workload()
    preparation = manifest["preparation"]
    preparation.update(primary_document_identity_policy=VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY,
        max_response_bytes=1_048_576, coverage_admission={
            "policy": "all-approved-origins-and-rendered-resources",
            "required_resources": [{"id": row["id"], "url": row["url"]} for row in manifest["resources"]],
        })
    first["responses"][0].update(content_length=2000,
        response_headers=[["content-type", "text/html; charset=utf-8"], ["date", "actual-first"]])
    runs = [deepcopy(first) for _ in range(3)]
    for index, run in enumerate(runs):
        run["responses"][0].update(bytes=2000 + index, content_length=2000 + index,
            body_sha256=("a", "c", "d")[index] * 64,
            response_headers=[["content-type", "text/html; charset=utf-8"], ["date", str(index)]])
    preparation["primary_document_identity_evidence"] = build_primary_document_identity_evidence(
        manifest, runs, stability_run_sha256s=[str(index + 1) * 64 for index in range(3)])
    return manifest, runs


def test_variable_primary_keeps_actual_snapshots_and_masks_comparison_only():
    manifest, runs = variable_workload()
    original = deepcopy((manifest, runs))
    raw = [validate_application_responses(manifest, run)["response_signature"] for run in runs]
    assert len({repr(row) for row in raw}) == 3
    comparisons = [application_response_identity_signature(manifest, row) for row in raw]
    assert comparisons[0] == comparisons[1] == comparisons[2]
    assert raw[1][0][2:4] == (2001, "c" * 64)
    evidence = response_stability_evidence(runs, primary_document_identity_policy=VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY,
                                          manifest=manifest)
    assert evidence["stable_resource_ids"] == [0, 1]
    assert evidence["expected_responses"][0] == manifest["preparation"]["expected_responses"][0]
    assert manifest["preparation"]["expected_responses"][0]["body_sha256"] == "a" * 64
    assert (manifest, runs) == original


def test_absent_or_exact_policy_retains_strict_primary_identity():
    manifest, runs = variable_workload()
    manifest["preparation"].pop("primary_document_identity_policy")
    manifest["preparation"].pop("primary_document_identity_evidence")
    assert primary_document_identity_policy(manifest) == EXACT_RESPONSE_BODY_POLICY
    assert validate_primary_document_identity_evidence(manifest) is None
    with pytest.raises(ValueError, match="prepared response identity"):
        validate_application_responses(manifest, runs[1])
    manifest["preparation"]["primary_document_identity_policy"] = EXACT_RESPONSE_BODY_POLICY
    with pytest.raises(ValueError, match="prepared response identity"):
        validate_application_responses(manifest, runs[1])
    assert response_stability_evidence(runs)["stable_resource_ids"] == [1]


@pytest.mark.parametrize("field,value", [("bytes", 158), ("body_sha256", "f" * 64), ("status", 403), ("request_headers", [])])
def test_variable_primary_never_relaxes_other_resources(field, value):
    manifest, runs = variable_workload()
    runs[1]["responses"][1][field] = value
    with pytest.raises(ValueError):
        validate_application_responses(manifest, runs[1])


@pytest.mark.parametrize("change", ["empty", "empty-hash", "cap", "partial", "error", "status", "missing",
                                     "length", "bool-length", "non-html", "type-drift", "headers"])
def test_variable_primary_rejects_invalid_actual_delivery(change):
    manifest, runs = variable_workload()
    run = runs[1]
    row = run["responses"][0]
    if change == "empty":
        row["bytes"] = 0
    elif change == "empty-hash":
        row["body_sha256"] = hashlib.sha256(b"").hexdigest()
    elif change == "cap":
        row["bytes"] = 1_048_577
    elif change == "partial":
        row["complete"] = False
    elif change == "error":
        run["error"] = "actual failed operation"
    elif change == "status":
        row["status"] = 401
    elif change == "missing":
        run["responses"].pop(0)
    elif change in {"length", "bool-length"}:
        row["content_length"] = True if change == "bool-length" else 2002
    elif change == "headers":
        row["request_headers"] = []
    else:
        row["response_headers"][0][1] = "application/json" if change == "non-html" else "text/html"
    with pytest.raises(ValueError):
        validate_application_responses(manifest, run)


@pytest.mark.parametrize("policy", [False, {}, "unknown"])
def test_unknown_primary_policy_is_rejected(policy):
    with pytest.raises(ValueError, match="primary document identity policy"):
        validate_primary_document_identity_policy(policy)


@pytest.mark.parametrize("change", ["response-policy", "coverage", "primary-chaff", "missing-run", "first-snapshot"])
def test_variable_primary_proof_requires_exact_declared_scope_and_all_three_runs(change):
    manifest, _ = variable_workload()
    preparation = manifest["preparation"]
    if change == "response-policy":
        preparation["application_response_policy"] = "http-2xx-only-v1"
    elif change == "coverage":
        preparation["coverage_admission"]["required_resources"].pop()
    elif change == "primary-chaff":
        manifest["resources"][0]["chaff_priority"] = True
    elif change == "missing-run":
        preparation["primary_document_identity_evidence"]["stability_primary_responses"].pop()
    else:
        preparation["expected_responses"][0]["body_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        validate_primary_document_identity_evidence(manifest)
