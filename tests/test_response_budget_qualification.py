"""HOST contracts: controlled complete epochs, genuine optional prepared input.

No Native command, image, network qualification or scientific credit is created.
The real prepared input is selected only by an explicit recorded HOST environment.
"""
import copy
from copy import deepcopy
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import response_budget_qualification as budget
from qcsd_lab import chaff_qualification as legacy
from qcsd_lab import cli
from qcsd_lab.util import load_json, atomic_json, sha256_file, sha256_bytes

ORDINARY = 16_777_216
LARGE = 67_108_864
BODY_BYTES = 1_718_637
NATIVE_SOURCE = {"neqo_base_commit": "d" * 40, "published_qcsd_commit": "e" * 40,
                 "migration_commit": "c" * 40}


# Response-only fixtures copied from the tracked legacy helpers. Constructing
# their Source metadata directly avoids the unrelated prefix/Walkie-Talkie
# fixture and keeps this HOST contract usable from a clean clone.
ROOT = Path(__file__).parents[1]
WORKLOAD = ROOT / "config/workloads/cloudflare-quiche-r3.json"
qualification = legacy


def _packet_log(observations: list[dict[str, object]]) -> str:
    import json

    return sha256_bytes(json.dumps(observations, separators=(",", ":")).encode())


def _statistics(
    observations: list[dict[str, object]],
) -> dict[str, dict[str, int]]:
    by_direction = {
        direction: [
            int(row["udp_payload_bytes"]) for row in observations if row["direction"] == direction
        ]
        for direction in ("incoming", "outgoing")
    }
    incoming = by_direction["incoming"]
    outgoing = by_direction["outgoing"]
    return {
        "incoming": {
            "packet_count": len(incoming),
            "observed_udp_payload_max": max(incoming),
            "oversized_packet_count": 0,
        },
        "outgoing": {
            "packet_count": len(outgoing),
            "observed_udp_payload_max": max(outgoing),
            "oversized_packet_count": 0,
        },
        "total": {
            "packet_count": len(incoming) + len(outgoing),
            "observed_udp_payload_max": max(*incoming, *outgoing),
            "oversized_packet_count": 0,
        },
    }


def _response_v2_receipt(
    *,
    run_index: int,
    candidate: dict[str, object],
    application_sha256: str,
    source: dict[str, str],
    identity: tuple[int, str, int, str] | None = None,
    mismatch_request: int | None = None,
    capacity_failure: bool = False,
) -> dict[str, object]:
    headers = qualification.project_identity_chaff_headers(candidate)
    status, encoding, body_bytes, body_sha256 = identity or (
        200,
        "identity",
        6_500,
        "6" * 64,
    )
    failure_class: str | None = None
    if capacity_failure:
        body_bytes = 1_199
        body_sha256 = "7" * 64
        failure_class = "capacity"
    elif mismatch_request is not None:
        failure_class = "identity"
    elif encoding != "identity":
        failure_class = "identity"
    observations: list[dict[str, object]] = [
        {
            "sequence": 0,
            "phase": "handshake",
            "direction": "incoming",
            "udp_payload_bytes": 900,
        },
        {
            "sequence": 1,
            "phase": "qualification",
            "direction": "outgoing",
            "udp_payload_bytes": 1_200,
        },
        {
            "sequence": 2,
            "phase": "qualification",
            "direction": "incoming",
            "udp_payload_bytes": 1_100,
        },
    ]
    requests = []
    for request_index in range(qualification.RESPONSE_ONLY_REQUESTS_PER_EPOCH):
        request_body_bytes = body_bytes
        request_body_sha256 = body_sha256
        if mismatch_request == request_index:
            request_body_bytes += 1
            request_body_sha256 = "8" * 64
        requests.append(
            {
                "request_index": request_index,
                "wave_index": request_index // 5,
                "stream_id": request_index * 4,
                "request_stream_bytes": 151,
                "status": status,
                "content_encoding": encoding,
                "body_bytes": request_body_bytes,
                "body_sha256": request_body_sha256,
                "complete": True,
                "outcome": "complete",
            }
        )
    spacing_ns = qualification.RESPONSE_ONLY_EPOCH_SPACING_SECONDS * 10**9
    started = run_index * (spacing_ns + 100)
    return {
        "schema_version": qualification.RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION,
        "artifact_type": qualification.RESPONSE_ARTIFACT_TYPE,
        "invocation_id": f"response-v2-{candidate['id']}-{run_index}",
        "neqo_version": "test",
        "application_workload_sha256": application_sha256,
        "application_resource_id": 0,
        "selected_chaff_resource_id": candidate["id"],
        "qualified_parallel_chaff_streams": 5,
        "method": "GET",
        "url": candidate["url"],
        "request_headers": headers,
        "request_header_mode": qualification.IDENTITY_REQUEST_HEADER_MODE,
        "parallel_requests": 5,
        "total_requests": 40,
        "request_waves": 8,
        "max_concurrent_requests": 5,
        "connection_count": 1,
        "requests_opened_before_first_network_output": 5,
        "request_stream_bytes": 151,
        "max_response_bytes": 1_048_576,
        "udp_payload_ceiling": 1_200,
        "started_unix_ns": started,
        "ended_unix_ns": started + 100,
        "completion_status": "complete",
        "error": None if failure_class is None else f"synthetic {failure_class} rejection",
        "failure_class": failure_class,
        "source": dict(source),
        "requests": requests,
        "packet_observations": observations,
        "packet_log_sha256": _packet_log(observations),
        "packets": _statistics(observations),
        "passed": failure_class is None,
    }


def _response_v2_epochs(
    *,
    candidate: dict[str, object],
    application_sha256: str,
    source: dict[str, str],
    identity: tuple[int, str, int, str] | None = None,
    mismatch_request: int | None = None,
    capacity_failure: bool = False,
) -> list[tuple[int, dict[str, object]]]:
    receipts = [
        _response_v2_receipt(
            run_index=run_index,
            candidate=candidate,
            application_sha256=application_sha256,
            source=source,
            identity=identity,
            mismatch_request=mismatch_request,
            capacity_failure=capacity_failure,
        )
        for run_index in range(3)
    ]
    return [(0 if receipt["passed"] else 1, receipt) for receipt in receipts]


def _response_only_source_fixture():
    """HOST response-only metadata; no prefix fitting or archived mould input."""
    source = {
        "image_digest": "sha256:" + "a" * 64,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": qualification.EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": qualification.EMPTY_SHA256,
    }
    implementation = qualification.implementation_receipt()
    implementation["source"] = {**source, "image_digest": None}
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    return {
        "qualification_source": source,
        "neqo_provenance": {"neqo_version": "test", **NATIVE_SOURCE},
        "implementation_receipt": implementation,
    }


def _response_only_v2_sidecar(
    workload_path: Path,
    workload_id: str,
    *,
    reject_candidate_indexes: set[int] | None = None,
) -> dict[str, object]:
    manifest = load_json(workload_path)
    candidates = qualification.response_only_candidate_resources(manifest, workload_id)
    combined = _response_only_source_fixture()
    source = copy.deepcopy(combined["qualification_source"])
    neqo_provenance = copy.deepcopy(combined["neqo_provenance"])
    neqo_source = {
        key: neqo_provenance[key]
        for key in qualification.NEQO_PROVENANCE_KEYS
        if key != "neqo_version"
    }
    application_sha256 = sha256_file(workload_path)
    attempts: list[dict[str, object]] = []
    all_receipts: list[dict[str, object]] = []
    selected: dict[str, object] | None = None
    expected_response: dict[str, object] | None = None
    request_stream_bytes: int | None = None
    rejected = reject_candidate_indexes or set()
    for candidate_index, (candidate, prepared) in enumerate(candidates):
        epochs = _response_v2_epochs(
            candidate=candidate,
            application_sha256=application_sha256,
            source=neqo_source,
            mismatch_request=35 if candidate_index in rejected else None,
        )
        attempt, identity, size = qualification._candidate_attempt_record_v2(
            candidate_index=candidate_index,
            base_resource=candidate,
            prepared_response=prepared,
            epochs=epochs,
            application_manifest_sha256=application_sha256,
            application_resource_id=0,
        )
        attempts.append(attempt)
        all_receipts.extend(receipt for _exit_code, receipt in epochs)
        if attempt["outcome"] == "qualified":
            selected = candidate
            expected_response = identity
            request_stream_bytes = size
            break
    assert selected is not None
    assert expected_response is not None
    assert request_stream_bytes is not None
    return {
        "schema_version": qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        "artifact_type": qualification.RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE,
        "qualification_scope": qualification.RESPONSE_ONLY_QUALIFICATION_SCOPE,
        "workload_id": workload_id,
        "base_manifest": {"path": workload_path.name, "sha256": application_sha256},
        "selection_policy": qualification.response_only_selection_policy(manifest),
        "application_resource_id": 0,
        "selected_chaff_resource_id": selected["id"],
        "qualified_parallel_chaff_streams": 5,
        "request_header_primitive": qualification.response_only_request_header_primitive(),
        "method": "GET",
        "qualification_policy": qualification.response_only_v2_qualification_policy(),
        "qualification_source": source,
        "qualification_image_digest": source["image_digest"],
        "neqo_provenance": qualification._stable_neqo_provenance(all_receipts),
        "implementation_receipt": combined["implementation_receipt"],
        "candidate_attempts": attempts,
        "resource": {
            "resource_id": selected["id"],
            "url": selected["url"],
            "headers": qualification.project_identity_chaff_headers(selected),
            "request_stream_bytes": request_stream_bytes,
            "expected_response": expected_response,
            "response_qualification_sha256": attempts[-1]["response_qualification_sha256"],
        },
    }


def epochs(cap=ORDINARY, candidate=None, application_sha256=None):
    manifest = load_json(WORKLOAD)
    candidate = candidate or legacy.response_only_candidate_resources(manifest, "cloudflare-quiche-r3")[0][0]
    values = _response_v2_epochs(candidate=candidate,
        application_sha256=application_sha256 or sha256_file(WORKLOAD), source=NATIVE_SOURCE,
        identity=(200, "identity", BODY_BYTES, "6" * 64))
    for _, receipt in values:
        receipt["max_response_bytes"] = cap
    return candidate, values


@pytest.mark.parametrize("cap", [ORDINARY, LARGE])
def test_complete_oversized_runner_and_120_proof(cap, tmp_path, monkeypatch):
    candidate, values = epochs(cap)
    client = tmp_path / "bound-client"
    client.write_bytes(b"HOST text fixture; never executed")
    client.chmod(0o755)
    commands = []
    def native(command, **kwargs):
        commands.append(command)
        assert command[command.index("--max-response-bytes") + 1] == str(cap)
        assert command[command.index("--packet-size") + 1] == "1200"
        assert command[command.index("--total-requests") + 1] == "40"
        output = Path(command[command.index("--output-dir") + 1])
        output.mkdir()
        atomic_json(output / "qualification.json", values[len(commands) - 1][1])
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(budget, "_run_neqo", native)
    monkeypatch.setattr(budget.time, "sleep", lambda seconds: None)
    result = budget._run_response_qualifications_v2(WORKLOAD, tmp_path,
        selected_chaff_resource_id=candidate["id"], application_manifest_sha256=sha256_file(WORKLOAD),
        application_resource_id=0, url=candidate["url"], headers=legacy.project_identity_chaff_headers(candidate),
        neqo_client=client, neqo_client_sha256=sha256_file(client), timeout_seconds=30,
        interval_seconds=30, max_response_bytes=cap)
    prepared = {"status": 200, "bytes": BODY_BYTES, "body_sha256": "6" * 64}
    attempt, identity, _ = budget._candidate_attempt_record_v2(candidate_index=0,
        base_resource=candidate, prepared_response=prepared, epochs=result,
        application_manifest_sha256=sha256_file(WORKLOAD), application_resource_id=0,
        max_response_bytes=cap)
    assert len(commands) == 3
    assert sum(len(row["receipt"]["requests"]) for row in attempt["connection_epochs"]) == 120
    assert identity["body_bytes"] == BODY_BYTES
    assert attempt["outcome"] == "qualified"
    with pytest.raises(legacy.PreparationError, match="receipt binding"):
        legacy._candidate_attempt_record_v2(candidate_index=0, base_resource=candidate,
            prepared_response=prepared, epochs=result,
            application_manifest_sha256=sha256_file(WORKLOAD), application_resource_id=0)


@pytest.mark.parametrize("mutation", ["cap-drift", "overflow", "truncated", "missing-epoch", "incomplete"])
def test_oversized_full_proof_rejects_independent_drift(mutation):
    candidate, values = epochs()
    if mutation == "cap-drift":
        values[1][1]["max_response_bytes"] = LARGE
    elif mutation == "overflow":
        values[1][1]["requests"][39]["body_bytes"] = ORDINARY + 1
    elif mutation == "truncated":
        values[1][1]["requests"].pop()
    elif mutation == "missing-epoch":
        values.pop()
    else:
        values[1][1]["requests"][0]["complete"] = False
    with pytest.raises(legacy.PreparationError):
        budget._candidate_attempt_record_v2(candidate_index=0, base_resource=candidate,
            prepared_response={"status": 200, "bytes": BODY_BYTES, "body_sha256": "6" * 64},
            epochs=values, application_manifest_sha256=sha256_file(WORKLOAD),
            application_resource_id=0, max_response_bytes=ORDINARY)


@pytest.mark.parametrize("mutation", ["wrong-preparation", "unknown-policy", "no-marker", "boolean", "unsupported"])
def test_closed_prepared_budget_policy(mutation):
    policy = budget.response_only_v2_qualification_policy(ORDINARY)
    prepared = ORDINARY
    if mutation == "wrong-preparation":
        prepared = LARGE
    elif mutation == "unknown-policy":
        policy["response_budget_policy"] = "unregistered"
    elif mutation == "no-marker":
        del policy["response_budget_policy"]
    elif mutation == "boolean":
        policy["max_response_bytes"] = True
    else:
        policy["max_response_bytes"] = ORDINARY + 1
    with pytest.raises(ValueError):
        budget._validate_response_only_v2_policy(policy, prepared_max_response_bytes=prepared)


def test_historical_default_and_exact_unmarked_sidecar_reader(tmp_path):
    assert budget.response_only_v2_qualification_policy() == legacy.response_only_v2_qualification_policy()
    sidecar = _response_only_v2_sidecar(WORKLOAD, "cloudflare-quiche-r3")
    path = tmp_path / "cloudflare-quiche-r3.json"
    atomic_json(path, sidecar)
    old = legacy.load_response_qualified_chaff(path, workload_id=path.stem,
        base_manifest_path=WORKLOAD, expected_sidecar_schema_version=2, require_current_implementation=False)
    new = budget.load_response_qualified_chaff(path, workload_id=path.stem,
        base_manifest_path=WORKLOAD, expected_sidecar_schema_version=2, require_current_implementation=False)
    assert old == new


def test_actual_oversized_preparation_and_new_sidecar_named_reader(tmp_path):
    selected = os.environ.get("QCSD_OVERSIZED_PREPARED_WORKLOAD")
    if selected is None:
        pytest.skip("recorded HOST actual prepared-input path is required")
    source_path = Path(selected)
    assert sha256_file(source_path) == "fb9c0a1610ba7e7e5e462552bcd7dcec68a55832057ba1fcb7a48836b48300f2"
    base = load_json(source_path)
    legacy.validate_research_preparation(base, workload_id=source_path.stem)
    candidate, prepared = legacy.response_only_candidate_resources(base, source_path.stem)[0]
    assert len(base["resources"]) == 70
    assert candidate["id"] == 35
    assert prepared["bytes"] == BODY_BYTES
    assert base["preparation"]["max_response_bytes"] == ORDINARY
    workloads, sidecars, published = (tmp_path / name for name in ("workloads", "sidecars", "published"))
    for directory in (workloads, sidecars, published):
        directory.mkdir()
    workload_path = workloads / source_path.name
    workload_path.write_bytes(source_path.read_bytes())
    _, values = epochs(candidate=candidate, application_sha256=sha256_file(workload_path))
    attempt, identity, size = budget._candidate_attempt_record_v2(candidate_index=0,
        base_resource=candidate, prepared_response=prepared, epochs=values,
        application_manifest_sha256=sha256_file(workload_path), application_resource_id=0,
        max_response_bytes=ORDINARY)
    template = _response_only_v2_sidecar(WORKLOAD, "cloudflare-quiche-r3")
    template.update(schema_version=budget.SIDECAR_SCHEMA_VERSION,
        artifact_type=budget.RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE, workload_id=workload_path.stem,
        base_manifest={"path": workload_path.name, "sha256": sha256_file(workload_path)},
        selection_policy=legacy.response_only_selection_policy(base), selected_chaff_resource_id=candidate["id"],
        qualification_policy=budget.response_only_v2_qualification_policy(ORDINARY),
        response_budget_source=budget._budget_source(), candidate_attempts=[attempt],
        resource={"resource_id": candidate["id"], "url": candidate["url"],
            "headers": legacy.project_identity_chaff_headers(candidate), "request_stream_bytes": size,
            "expected_response": identity, "response_qualification_sha256": attempt["response_qualification_sha256"]})
    sidecar_path = sidecars / workload_path.name
    atomic_json(sidecar_path, template)
    result = budget.publish_named_qualification_set([workload_path.stem], qualification_set="oversized-host-contract",
        qualification_scope="response-only", workload_root=workloads, sidecar_root=sidecars, publication_root=published,
        qualification_sidecar_schema_version=budget.SIDECAR_SCHEMA_VERSION, require_current_implementation=False)
    reopened = budget.load_named_qualification_set(result.manifest_path, workload_root=workloads,
        expected_qualification_scope="response-only", expected_workload_ids=[workload_path.stem],
        require_current_implementation=False)
    assert reopened.manifest_sha256 == result.manifest_sha256
    assert load_json(result.manifest_path)["artifact_type"] == budget.NAMED_ARTIFACT_TYPE
    mutated = deepcopy(template)
    mutated["response_budget_source"]["module_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="producer Source"):
        budget.validate_response_only_sidecar(mutated, workload_id=workload_path.stem,
            base_manifest_path=workload_path, require_current_implementation=False)
    mutated = deepcopy(template)
    mutated["qualification_policy"]["max_response_bytes"] = LARGE
    with pytest.raises(ValueError, match="sustained policy"):
        budget.validate_response_only_sidecar(mutated, workload_id=workload_path.stem,
            base_manifest_path=workload_path, require_current_implementation=False)


def test_public_cli_and_portable_handler_pass_only_validated_cap(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(budget, "qualify_all_response_chaff", lambda ids, **kwargs: calls.append(kwargs) or ())
    cli.main(["qualify-response-chaff", "--max-response-bytes", str(ORDINARY), *[f"site-{i}" for i in range(5)]])
    assert calls[0]["max_response_bytes"] == ORDINARY
    path = Path(__file__).parents[1] / "tools/_rapid_class_mode_flight/flight/operator.py"
    spec = importlib.util.spec_from_file_location("response_budget_portable_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "output"; output.mkdir()
    execution = tmp_path / "execution"; execution.mkdir()
    plan = {"campaigns": [{"mode": "tamaraw"}], "selected_classes": [{"workload_id": "site-0"}],
        "capture_limits": {"max_response_bytes": LARGE, "timeout_seconds": 120}, "reuse": None,
        "group_qualification_set": "group-test", "qualification_set": "singleton-test",
        "workload_id": "site-0", "workload_sha256": "0" * 64}
    monkeypatch.setattr(module, "checked_plan", lambda args, image=False: (plan, output, execution))
    def qualify(identifier, **kwargs):
        calls.append(kwargs)
        atomic_json(kwargs["qualification_root"] / (identifier + ".json"), {"controlled": True})
    monkeypatch.setattr(budget, "qualify_response_chaff_v2", qualify)
    def publish(ids, **kwargs):
        assert kwargs["qualification_sidecar_schema_version"] == budget.SIDECAR_SCHEMA_VERSION
        return SimpleNamespace(manifest_sha256="1" * 64, qualification_set=kwargs["qualification_set"])
    monkeypatch.setattr(budget, "publish_named_qualification_set", publish)
    module.image_action(SimpleNamespace(command="qualify-image", plan_sha256="2" * 64))
    assert calls[-1]["max_response_bytes"] == LARGE
    assert calls[-1]["timeout_seconds"] == 120


@pytest.mark.parametrize("mutation", ["numeric-alias-with-old-digest", "wrong-digest"])
def test_named_digest_independently_reopens_parsed_payload(mutation, tmp_path, monkeypatch):
    value = {"schema_version": 1, "artifact_type": budget.NAMED_ARTIFACT_TYPE,
        "qualification_set": "named-test", "qualification_scope": "response-only",
        "qualification_sidecar_schema_version": budget.SIDECAR_SCHEMA_VERSION,
        "workload_count": 1, "workload_ids": ["site-0"], "workloads": [
            {"index": 0, "workload_id": "site-0", "workload_manifest": {"path": "site-0.json", "sha256": "1" * 64},
             "qualification_sidecar": {"path": "site-0.json", "sha256": "2" * 64},
             "runtime_manifest_sha256": "3" * 64, "prefix_pack_spec": None}]}
    value["bindings_sha256"] = legacy._named_qualification_bindings_sha256(value)
    expected = deepcopy(value)
    # Only the expensive input-reader boundary is structural in this metadata
    # negative. The parsed digest comparison is the real new public validator.
    monkeypatch.setattr(budget, "_named_manifest", lambda *args, **kwargs: expected)
    if mutation == "numeric-alias-with-old-digest":
        value["workloads"][0]["index"] = False
    else:
        value["bindings_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="digest differs"):
        budget.validate_named_qualification_set_manifest(value, workload_root=tmp_path, sidecar_root=tmp_path)
