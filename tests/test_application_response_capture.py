"""Capture and independent verification seams for the explicit HTTP leaf policy."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab.capture_session import (
    Defense,
    Limits,
    _client_command,
    _launch_application_response_policy,
)
from qcsd_lab.cli import parser
from qcsd_lab.util import atomic_json, sha256_file
from qcsd_lab.verification import _validate_policy_application_responses

POLICY = "completed-terminal-http-errors-v1"


def _prepared():
    return {
        "preparation": {
            "source_url": "https://page.test/",
            "final_url": "https://page.test/",
            "application_response_policy": POLICY,
            "expected_responses": [
                {"resource_id": 0, "status": 200, "bytes": 100, "body_sha256": "a" * 64},
                {"resource_id": 1, "status": 401, "bytes": 157, "body_sha256": "b" * 64},
            ],
        },
        "resources": [
            {"id": 0, "url": "https://page.test/", "type": "Document",
             "known_valid": True, "chaff_priority": True, "depends_on": []},
            {"id": 1, "url": "https://aux.test/whoami", "type": "Fetch",
             "known_valid": False, "chaff_priority": False, "depends_on": [0]},
        ],
    }


def _run():
    prepared = _prepared()
    return {
        "application_response_policy": POLICY,
        "completion_status": "complete", "error": None, "error_class": None,
        "terminal_evidence_render_errors": [],
        "responses": [
            {**row, "url": prepared["resources"][row["resource_id"]]["url"],
             "complete": True, "outcome": "succeeded"}
            for row in prepared["preparation"]["expected_responses"]
        ],
    }


def test_prepare_cli_requires_an_explicit_known_policy():
    args = ["prepare", "page", "https://page.test/", "https://page.test"]
    assert parser().parse_args(args).application_response_policy is None
    assert parser().parse_args([*args, "--application-response-policy", POLICY]).application_response_policy == POLICY
    with pytest.raises(SystemExit):
        parser().parse_args([*args, "--application-response-policy", "accept-everything"])


def test_baseline_opt_in_is_in_actual_client_command_without_chaff(tmp_path):
    context = SimpleNamespace(limits=Limits(), request_policy="as-defined", qcsd_profile="live")
    baseline = Defense("undefended", "none", True)
    legacy = _client_command(tmp_path / "runtime.json", "page", baseline, 0, context, tmp_path / "out")
    opted = _client_command(tmp_path / "runtime.json", "page", baseline, 0, context, tmp_path / "out",
                            application_response_policy=POLICY)
    assert "--application-response-policy" not in legacy
    assert opted[opted.index("--application-response-policy") + 1] == POLICY
    assert "--application-workload-source" not in opted
    assert "--chaff-manifest" not in opted


def test_defended_policy_is_derived_from_frozen_source_and_mismatch_rejected(tmp_path):
    source = tmp_path / "prepared.json"
    atomic_json(source, _prepared())
    assert _launch_application_response_policy(source, None) == POLICY
    with pytest.raises(ValueError, match="differs"):
        _launch_application_response_policy(source, "http-2xx-only-v1")


def _result_inputs(tmp_path: Path, run):
    prepared_path = tmp_path / "inputs/workloads/page.json"
    atomic_json(prepared_path, _prepared())
    atomic_json(tmp_path / "samples/one/neqo/run.json", run)
    return {
        "configuration": {"workloads": [{"id": "page", "manifest": "inputs/workloads/page.json",
                                           "sha256": sha256_file(prepared_path)}]},
        "samples": [{"state": "accepted", "workload_id": "page", "path": "samples/one"}],
    }


def test_independent_verification_preserves_complete_401_in_full_graph(tmp_path):
    run = _run()
    experiment = _result_inputs(tmp_path, run)
    _validate_policy_application_responses(tmp_path, experiment)
    assert run["responses"][1]["status"] == 401
    assert _prepared()["resources"][1]["known_valid"] is False


@pytest.mark.parametrize("field,value", [
    ("status", 200), ("bytes", 158), ("body_sha256", "c" * 64),
    ("url", "https://aux.test/other"), ("complete", False), ("outcome", "failed"),
])
def test_independent_verification_rejects_response_drift(tmp_path, field, value):
    run = deepcopy(_run())
    run["responses"][1][field] = value
    experiment = _result_inputs(tmp_path, run)
    with pytest.raises(ValueError, match="application resource"):
        _validate_policy_application_responses(tmp_path, experiment)


@pytest.mark.parametrize("change", ["omit", "duplicate", "remove-policy"])
def test_independent_verification_rejects_missing_graph_or_policy(tmp_path, change):
    run = _run()
    if change == "omit":
        run["responses"].pop()
    elif change == "duplicate":
        run["responses"].append(deepcopy(run["responses"][1]))
    else:
        run.pop("application_response_policy")
    experiment = _result_inputs(tmp_path, run)
    with pytest.raises(ValueError):
        _validate_policy_application_responses(tmp_path, experiment)
