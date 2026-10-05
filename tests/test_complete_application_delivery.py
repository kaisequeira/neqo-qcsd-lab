"""Prospective HOST policy contracts; no Native/network/capture or trace credit."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import application_response_policy as app
from qcsd_lab import experiment, orchestrator, verification
from qcsd_lab import rapid_capture_plan as planner
from qcsd_lab.util import atomic_json, sha256_file

POLICY = app.COMPLETE_APPLICATION_DELIVERY_POLICY
EMPTY = hashlib.sha256(b"").hexdigest()


def delivery_fixture():
    resources = [
        {"id": 0, "url": "https://page.example/", "type": "Document", "known_valid": True,
         "depends_on": [], "headers": [["accept", "text/html"]], "chaff_priority": False},
        {"id": 1, "url": "https://cdn.example/app.js", "type": "Script", "known_valid": True,
         "depends_on": [0], "headers": [["accept-encoding", "gzip"]], "chaff_priority": False},
    ]
    expected = [{"resource_id": i, "status": 200, "bytes": size, "body_sha256": digest * 64}
                for i, size, digest in ((0, 20, "a"), (1, 50, "b"))]
    manifest = {"resources": resources, "preparation": {
        "expected_responses": expected, "max_response_bytes": 16_777_216,
        "source_url": resources[0]["url"], "final_url": resources[0]["url"]}}
    run = {"application_response_policy": app.HTTP_2XX_ONLY_POLICY,
           "completion_status": "complete", "error": None, "error_class": None,
           "terminal_evidence_render_errors": [], "max_response_bytes": 16_777_216,
           "endpoints": [{"id": 0, "origin": "https://page.example/", "negotiated_protocol": "h3"},
                         {"id": 1, "origin": "https://cdn.example/", "negotiated_protocol": "h3"}],
           "responses": [{**row, "url": resources[row["resource_id"]]["url"],
                          "request_headers": resources[row["resource_id"]]["headers"],
                          "response_headers": [["content-type", "text/html" if row["resource_id"] == 0 else "application/javascript"]],
                          "content_length": row["bytes"], "complete": True, "outcome": "succeeded"}
                         for row in expected]}
    run["responses"][1].update(bytes=80, body_sha256="c" * 64, content_length=80)
    return manifest, run


def test_complete_delivery_accepts_changed_representation_and_retains_raw_identity():
    manifest, run = delivery_fixture()
    before = deepcopy((manifest, run))
    with pytest.raises(ValueError, match="prepared response identity"):
        app.validate_application_responses(manifest, run)
    facts = app.validate_application_responses(manifest, run, body_identity_policy=POLICY)
    assert facts["observed_responses"][1] == {
        "resource_id": 1, "status": 200, "bytes": 80,
        "body_sha256": "c" * 64, "content_encoding": "identity"}
    assert facts["content_equality_across_visits_claimed"] is False
    assert app.application_response_identity_signature(manifest, facts["response_signature"],
        body_identity_policy=POLICY) == app.application_response_identity_signature(manifest,
        orchestrator._prepared_response_signature(manifest), body_identity_policy=POLICY)
    assert (manifest, run) == before


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra", "url", "headers", "status",
    "incomplete", "outcome", "partial", "native-error", "render-error", "bool-bytes", "negative-bytes",
    "overcap", "empty", "digest", "nonempty-empty-sha", "length", "bool-length", "missing-encoding",
    "encoding-type", "encoding-empty", "cap", "bool-cap", "expected-missing"])
def test_complete_delivery_refuses_incomplete_or_unbound_raw_facts(mutation):
    manifest, run = delivery_fixture()
    row = run["responses"][1]
    changes = {"url": ("url", "https://else.example/app.js"), "headers": ("request_headers", []),
        "status": ("status", 201), "incomplete": ("complete", False), "outcome": ("outcome", "failed"),
        "bool-bytes": ("bytes", True), "negative-bytes": ("bytes", -1),
        "overcap": ("bytes", 16_777_217), "empty": ("bytes", 0), "digest": ("body_sha256", "bad"),
        "nonempty-empty-sha": ("body_sha256", EMPTY), "length": ("content_length", 79),
        "bool-length": ("content_length", True), "encoding-type": ("response_headers", {}),
        "encoding-empty": ("response_headers", [["content-encoding", ""]])}
    if mutation in changes:
        key, value = changes[mutation]
        row[key] = value
    elif mutation == "missing":
        run["responses"].pop()
    elif mutation == "duplicate":
        run["responses"].append(deepcopy(row))
    elif mutation == "extra":
        run["responses"].append({**row, "resource_id": 2})
    elif mutation == "partial":
        run["completion_status"] = "partial"
    elif mutation == "native-error":
        run["error"] = "IdleTimeout"
    elif mutation == "render-error":
        run["terminal_evidence_render_errors"] = ["failed"]
    elif mutation == "missing-encoding":
        row.pop("response_headers")
    elif mutation in {"cap", "bool-cap"}:
        run["max_response_bytes"] = True if mutation == "bool-cap" else 67_108_864
    else:
        manifest["preparation"].pop("expected_responses")
    with pytest.raises(ValueError):
        app.validate_application_responses(manifest, run, body_identity_policy=POLICY)


def test_declared_empty_leaf_keeps_empty_sha_and_complete_status_rules():
    manifest, run = delivery_fixture()
    manifest["preparation"]["expected_responses"][1].update(bytes=0, body_sha256=EMPTY)
    run["responses"][1].update(bytes=0, body_sha256=EMPTY, content_length=0)
    assert app.validate_application_responses(manifest, run, body_identity_policy=POLICY)
    run["responses"][1]["body_sha256"] = "d" * 64
    with pytest.raises(ValueError, match="body bound"):
        app.validate_application_responses(manifest, run, body_identity_policy=POLICY)


@pytest.mark.parametrize("length", ["79", "invalid"])
def test_observed_header_length_cannot_disagree_with_structured_body_facts(length):
    manifest, run = delivery_fixture()
    run["responses"][1]["response_headers"].append(["content-length", length])
    with pytest.raises(ValueError, match="Content-Length"):
        app.validate_application_responses(manifest, run, body_identity_policy=POLICY)


def test_complete_terminal_404_leaf_keeps_exact_declared_status():
    # Existing tracked terminal-policy fixture has no private/archive imports.
    from tests.test_application_response_policy import policy_workload
    manifest, run = policy_workload()
    manifest["preparation"]["max_response_bytes"] = run["max_response_bytes"] = 16_777_216
    run["endpoints"] = [{"id": 0, "origin": "https://page.test/", "negotiated_protocol": "h3"},
                        {"id": 1, "origin": "https://cdn.test/", "negotiated_protocol": "h3"}]
    expected = manifest["preparation"]["expected_responses"][1]
    expected["status"] = 404
    evidence = manifest["preparation"]["application_response_policy_evidence"]
    for row in evidence["get_responses"]:
        row["status"] = 404
    for rows in evidence["stability_responses"]:
        rows[0]["status"] = 404
    run["responses"][0]["response_headers"] = [["content-type", "text/html"]]
    run["responses"][1].update(status=404, bytes=191, body_sha256="c" * 64,
        content_length=191, response_headers=[])
    assert app.validate_application_responses(manifest, run, body_identity_policy=POLICY)["terminal_http_error_resource_ids"] == [1]
    run["responses"][1]["status"] = 200
    with pytest.raises(ValueError, match="declared status"):
        app.validate_application_responses(manifest, run, body_identity_policy=POLICY)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong-origin", "wrong-protocol", "bool-id"])
def test_complete_delivery_reopens_exact_current_http3_endpoint_set(mutation):
    manifest, run = delivery_fixture()
    if mutation == "missing":
        run.pop("endpoints")
    elif mutation == "duplicate":
        run["endpoints"][1] = deepcopy(run["endpoints"][0])
    elif mutation == "wrong-origin":
        run["endpoints"][1]["origin"] = "https://other.example/"
    elif mutation == "wrong-protocol":
        run["endpoints"][1]["negotiated_protocol"] = "h2"
    else:
        run["endpoints"][1]["id"] = True
    with pytest.raises(ValueError):
        app.validate_application_responses(manifest, run, body_identity_policy=POLICY)


@pytest.mark.parametrize("value", [None, False, True, {}, "unknown"])
def test_closed_campaign_configuration_reader_rejects_present_bad_policy(value):
    with pytest.raises(ValueError):
        app.application_body_identity_policy({app.APPLICATION_BODY_IDENTITY_FIELD: value})
    with pytest.raises(ValueError):
        app.application_response_identity_signature({}, None, body_identity_policy=value if value is not None else False)


def test_experiment_schema_carries_closed_policy_without_changing_old_default():
    config = {"campaign_sha256": "a" * 64, "profile": "research-1200",
        "request_policies": ["as-defined"], "workloads": [{"id": "site"}],
        "defenses": [{"name": "undefended"}], "limits": {}}
    experiment._validate_configuration(config)
    config[app.APPLICATION_BODY_IDENTITY_FIELD] = POLICY
    experiment._validate_configuration(config)
    config[app.APPLICATION_BODY_IDENTITY_FIELD] = None
    with pytest.raises(ValueError):
        experiment._validate_configuration(config)


def test_promotion_and_fidelity_comparison_reopen_raw_before_body_projection(tmp_path):
    manifest, run = delivery_fixture()
    attempt = tmp_path / "attempt"
    (attempt / "neqo").mkdir(parents=True)
    atomic_json(attempt / "neqo/run.json", run)
    tagged = SimpleNamespace(id="site", data=manifest, application_body_identity_policy=POLICY)
    strict = SimpleNamespace(id="site", data=manifest, application_body_identity_policy=None)
    assert orchestrator._prepared_response_identity_failure(strict, attempt) is not None
    assert orchestrator._prepared_response_identity_failure(tagged, attempt) is None
    signature = orchestrator.response_signature(attempt)
    assert orchestrator._policy_response_comparison(manifest, attempt, signature, body_identity_policy=POLICY)
    run["responses"][1]["complete"] = False
    atomic_json(attempt / "neqo/run.json", run)
    assert orchestrator._prepared_response_identity_failure(tagged, attempt) is not None
    assert orchestrator._policy_response_comparison(manifest, attempt, signature, body_identity_policy=POLICY) is None


@pytest.mark.parametrize("mutation", ["no-manifest", "empty-inputs", "unbound-sample", "input-hash"])
def test_independent_deep_refuses_tagged_missing_or_changed_workload(tmp_path, mutation):
    manifest, _run = delivery_fixture()
    path = tmp_path / "manifest.json"
    atomic_json(path, manifest)
    workload = {"id": "site", "manifest": "manifest.json", "sha256": sha256_file(path)}
    samples = []
    if mutation == "no-manifest":
        workload["manifest"] = None
    elif mutation == "input-hash":
        workload["sha256"] = "f" * 64
    elif mutation == "unbound-sample":
        samples = [{"state": "accepted", "workload_id": "other"}]
    configuration = {app.APPLICATION_BODY_IDENTITY_FIELD: POLICY,
        "workloads": [] if mutation == "empty-inputs" else [workload]}
    with pytest.raises(ValueError):
        verification._validate_policy_application_responses(tmp_path,
            {"configuration": configuration, "samples": samples})


@pytest.mark.parametrize("mode", ["undefended", "front", "tamaraw", "buflo", "cs-buflo"])
def test_formal_renderer_declares_policy_and_keeps_old_bytes(mode):
    from qcsd_lab.supplied_static_admission import capture_limits
    site = planner.Site("candidate", "workload", "1" * 64, "https://page.example", "qualified", "2" * 64)
    lane = next(item for item in planner.plan_lanes([site], final=True, study_version=6, rolling_batch=1)
                if item.mode == mode)
    original = planner.render_lane_campaign(lane, [site])
    assert app.APPLICATION_BODY_IDENTITY_FIELD not in yaml.safe_load(original)
    limits = capture_limits(16_777_216, 64)
    tagged = yaml.safe_load(planner.render_lane_campaign(lane, [site],
        static_capture_limits=limits, application_body_identity_policy=POLICY))
    assert tagged[app.APPLICATION_BODY_IDENTITY_FIELD] == POLICY
    assert tagged["workloads"] == {"workload": 4}
    with pytest.raises(ValueError):
        planner.render_lane_campaign(lane, [site], application_body_identity_policy=POLICY)


def test_deep_checks_complete_delivery_after_exact_configured_manifest(tmp_path):
    manifest, run = delivery_fixture()
    path = tmp_path / "inputs/workloads/site.json"
    path.parent.mkdir(parents=True)
    atomic_json(path, manifest)
    sample = {"state": "accepted", "workload_id": "site", "path": "samples/observed"}
    sample_root = tmp_path / sample["path"]
    (sample_root / "neqo").mkdir(parents=True)
    atomic_json(sample_root / "neqo/run.json", run)
    value = {"configuration": {app.APPLICATION_BODY_IDENTITY_FIELD: POLICY,
        "workloads": [{"id": "site", "manifest": path.relative_to(tmp_path).as_posix(), "sha256": sha256_file(path)}]},
        "samples": [sample]}
    verification._validate_policy_application_responses(tmp_path, value)
    run["responses"][1]["complete"] = False
    atomic_json(sample_root / "neqo/run.json", run)
    with pytest.raises(ValueError):
        verification._validate_policy_application_responses(tmp_path, value)


def test_public_deep_argv_matches_portable_witness_transport(tmp_path, monkeypatch):
    """Future witness creation is a synthetic boundary; both consumers are real."""
    from qcsd_lab import qualification_delivery_compatibility as compatibility
    from qcsd_lab import rapid_rolling_readiness as readiness
    from qcsd_lab.util import sha256_bytes
    source = Path(__file__).resolve().parents[1]
    recipe_path = source / "tools/_rapid_class_mode_flight/flight/operator.py"
    spec = importlib.util.spec_from_file_location("delivery_portable_recipe", recipe_path)
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    output = tmp_path / "output"
    (output / "lineage").mkdir(parents=True)
    helper = tmp_path / "helpers.py"
    helper.write_text("# retained fixture helper\n")
    original = {"resources": [{"id": 0, "url": "https://page.example/"}]}
    raw = recipe.encode(original)
    (output / "lineage/original-manifest.json").write_bytes(raw)
    (output / "plan.json").write_bytes(b"{}\n")
    root = tmp_path / "witness-runtime"
    root.mkdir()
    witness_file = root / "compatibility.json"
    witness_file.write_text("{}\n")
    witness = recipe.ref(witness_file)
    calls = []
    def authenticated_roots(reference, *, body_policy):
        assert reference == witness and body_policy == POLICY
        calls.append((reference, body_policy))
        return [root]
    monkeypatch.setattr(compatibility, "roots", authenticated_roots)
    value = {"name": "delivery-fixture", "reuse": None,
        "canonical_runtime": {"collection_image_digest": "sha256:" + "a" * 64},
        "clean_runtime_root": str(tmp_path / "source"), "execution_root": str(tmp_path / "execution"),
        "helper_path": str(helper), "helper_sha256": sha256_file(helper),
        "recipe_sha256": sha256_file(recipe_path), "original_workload_sha256": sha256_bytes(raw),
        "static_preparation_roots": [], "group_preparation_roots": [],
        app.APPLICATION_BODY_IDENTITY_FIELD: POLICY, "qualification_delivery_compatibility": witness}
    result = "/lab/results/fixture/run"
    command = recipe.image_argv(value, output, "verify-image", "--mode", "tamaraw", "--result", result)
    expected = readiness._deep_command(value, output, sha256_file(output / "plan.json"), "tamaraw", result, command)
    assert command == expected
    assert len(calls) == 2
    mounts = [command[i + 1] for i, token in enumerate(command) if token == "--volume"]
    assert f"{root}:{root}:ro" in mounts
    assert command[command.index("--network") + 1] == "none"


def test_campaign_reader_refuses_unprepared_and_present_null_policy(tmp_path):
    campaign = tmp_path / "config/campaigns/fixture.yml"
    campaign.parent.mkdir(parents=True)
    document = {"schema": 1, "name": "fixture", "purpose": "smoke", "seed": 1,
        "profile": "research-1200", "workloads": {"native": 1},
        "request_policies": ["as-defined"], "defenses": ["undefended"],
        app.APPLICATION_BODY_IDENTITY_FIELD: None}
    campaign.write_text(yaml.safe_dump(document))
    with pytest.raises(ValueError, match="cannot be null"):
        orchestrator.load_campaign(campaign)


def test_actual_failed_complete_ledger_is_only_a_prospective_host_contract():
    refs_path = os.environ.get("QCSD_COMPLETE_DELIVERY_ACTUAL_INPUTS")
    if refs_path is None:
        pytest.skip("actual failed evidence requires an explicit hash-bound HOST input file")
    refs = json.loads(Path(refs_path).read_bytes())
    for record in refs.values():
        path = Path(record["path"])
        assert path.is_file() and not path.is_symlink()
        assert sha256_file(path) == record["sha256"]
    manifest = json.loads(Path(refs["manifest"]["path"]).read_bytes())
    run = json.loads(Path(refs["run"]["path"]).read_bytes())
    before = deepcopy((manifest, run))
    with pytest.raises(ValueError, match="prepared response identity"):
        app.validate_application_responses(manifest, run)
    facts = app.validate_application_responses(manifest, run, body_identity_policy=POLICY)
    assert len(facts["observed_responses"]) == 20
    assert facts["content_equality_across_visits_claimed"] is False
    assert (manifest, run) == before
