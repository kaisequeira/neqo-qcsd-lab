"""Scoped capped-BuFLO contracts; synthetic process receipts, no live proof.

The sustained fixture supplies three independent forty-response epochs with
the original thirty-second spacing. Only subprocess/collector boundaries are
controlled; candidate, receipt, sidecar, enrollment and runtime identity
validators run unchanged. These controls never assert scientific credit.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import capture_session as collector
from qcsd_lab import chaff_qualification as chaff
from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_native as native
from qcsd_lab.resource_study_inputs import canonical_json, native_manifest, sha256_file
from qcsd_lab.chaff_qualification import qualification_digest
from qcsd_lab.util import sha256_bytes
from tests.test_resource_study_native import (
    COMMIT, HOST, URLS, get_run, install_process_stub, runtime, write,
)


# Exact pure fixture bodies from test_chaff_qualification.py; importing that
# whole test module would read unrelated historical artifacts at collection.
qualification = chaff


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



def _rehash_response_only_v2_sidecar(sidecar: dict[str, object]) -> None:
    attempts = sidecar["candidate_attempts"]
    assert isinstance(attempts, list)
    for attempt in attempts:
        epochs = attempt["connection_epochs"]
        for epoch in epochs:
            epoch["receipt_object_sha256"] = qualification_digest(
                "qcsd-chaff-sustained-response-receipt-object-v3",
                [epoch["receipt"]],
            )
        attempt["response_qualification_sha256"] = qualification_digest(
            "qcsd-chaff-sustained-response-qualification-v3",
            epochs,
        )
    sidecar["resource"]["response_qualification_sha256"] = attempts[-1][
        "response_qualification_sha256"
    ]


CAP = 10_000
SOURCE = {"neqo_base_commit": "a" * 40, "published_qcsd_commit": "b" * 40,
          "migration_commit": COMMIT}


@pytest.fixture
def executable(tmp_path, monkeypatch):
    path = tmp_path / "client"
    path.write_bytes(b"offline capped-BuFLO fixture executable\n")
    path.chmod(0o755)
    # Physical durability and execution are not claims of these local fixtures.
    monkeypatch.setattr(native.os, "fsync", lambda _fd: None)
    return path


def prepared_data():
    lengths = [9000, 8000, 7000, 6500, *([1100] * 16)]
    value = native_manifest(HOST, URLS[:20], dict(zip(URLS[:20], lengths)))
    for resource in value["resources"]:
        resource["headers"] = copy.deepcopy(native.REQUEST_HEADERS)
    value["resources"][0]["type"] = "Document"
    value["preparation"] = {
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1",
        "approved_origins": ["https://" + HOST],
        "expected_responses": [
            {"resource_id": i, "status": 200, "bytes": size,
             "body_sha256": hashlib.sha256(f"prepared-{i}".encode()).hexdigest()}
            for i, size in enumerate(lengths)
        ],
    }
    return value


def install_sustained(monkeypatch, *, rejected=(), actual_sizes=None):
    calls = []
    actual_sizes = actual_sizes or {}

    def run(prepared, output, **kwargs):
        identifier = kwargs["selected_chaff_resource_id"]
        calls.append((identifier, kwargs))
        assert kwargs["timeout_seconds"] == 120
        assert kwargs["interval_seconds"] == 30
        assert kwargs["application_resource_id"] == 0
        assert kwargs["application_manifest_sha256"] == sha256_file(prepared)
        assert kwargs["neqo_client_sha256"] == sha256_file(kwargs["neqo_client"])
        candidate = json.loads(prepared.read_bytes())["resources"][identifier]
        assert kwargs["url"] == candidate["url"]
        assert kwargs["headers"] == chaff.project_identity_chaff_headers(candidate)
        return _response_v2_epochs(
            candidate=candidate, application_sha256=sha256_file(prepared), source=SOURCE,
            identity=(200, "identity", actual_sizes.get(identifier, 6000), "6" * 64),
            mismatch_request=35 if identifier in rejected else None,
        )

    monkeypatch.setattr(chaff, "_run_response_qualifications_v2", run)
    return calls


def qualified(tmp_path, executable, monkeypatch, *, rejected=(), actual_sizes=None):
    prepared = prepared_data()
    path = tmp_path / "prepared-workload.json"
    write(path, prepared)
    calls = install_sustained(monkeypatch, rejected=rejected, actual_sizes=actual_sizes)
    result = native._qualify_buflo_capped(path, tmp_path / "qualification", executable,
                                        runtime(executable), CAP)
    return prepared, path, result, calls


def enrolled(tmp_path, executable, monkeypatch):
    prepared, path, result, _ = qualified(tmp_path, executable, monkeypatch)
    write(tmp_path / "sidecar.json", result["sidecar"])
    write(tmp_path / "chaff.json", result["manifest"])
    value = {
        "buflo_chaff_selection": {"schema_version": 1,
            "record_type": native.BUFLO_CAPPED_SELECTION_TYPE,
            "selection_policy": native.BUFLO_CAPPED_SELECTION_POLICY, "cap_bytes": CAP},
        "mode_readiness": dict.fromkeys(native.MODES, True),
        "buflo_chaff_qualification_error": None,
        "runtime": runtime(executable),
        "paths": {"prepared_workload": path.name, "buflo_chaff_sidecar": "sidecar.json",
                  "buflo_chaff_manifest": "chaff.json"},
        "files": {name: sha256_file(tmp_path / name)
                  for name in (path.name, "sidecar.json", "chaff.json")},
    }
    return value, prepared, result


@pytest.mark.parametrize("value", [None, 1200, 10_000, 1_048_576])
def test_cap_default_and_exact_integer_bounds(value):
    assert native._buflo_chaff_cap(value) == value


@pytest.mark.parametrize("value", [True, False, 0, 1199, 1_048_577, -1, 1200.0, "1200"])
def test_cap_rejects_aliases_and_out_of_bounds(value):
    with pytest.raises(ValueError, match="integer"):
        native._buflo_chaff_cap(value)


def test_candidates_keep_all_twenty_and_exclude_largest_anchor():
    prepared = prepared_data()
    before = canonical_json(prepared)
    assert [resource["id"] for resource, _ in native._buflo_capped_candidates(prepared, CAP)] == [1, 2, 3]
    assert canonical_json(prepared) == before
    # The lower cap changes only auxiliary eligibility, never the application set.
    assert [resource["id"] for resource, _ in native._buflo_capped_candidates(prepared, 7000)] == [2, 3]
    prepared["preparation"]["expected_responses"][3]["bytes"] = 7000
    assert [resource["id"] for resource, _ in native._buflo_capped_candidates(prepared, 7000)] == [2, 3]
    for row in prepared["preparation"]["expected_responses"][1:]:
        row["bytes"] = 1199
    assert native._buflo_capped_candidates(prepared, CAP) == []
    with pytest.raises(ValueError, match="explicit cap"):
        native._buflo_capped_candidates(prepared, None)


@pytest.mark.parametrize("mutation", [
    lambda p: p["resources"].pop(),
    lambda p: p["preparation"]["expected_responses"].pop(),
    lambda p: p["resources"][1].update(id=True),
    lambda p: p["preparation"]["expected_responses"][1].update(resource_id=0),
    lambda p: p["resources"][19].update(url="https://foreign.example/object"),
    lambda p: p["preparation"].update(approved_origins=["https://foreign.example"]),
    lambda p: p["resources"][19].update(known_valid=False),
    lambda p: p["resources"][19].update(depends_on=[0]),
    lambda p: p["resources"][19].update(headers=[]),
    lambda p: p["preparation"]["expected_responses"][19].update(status=True),
    lambda p: p["preparation"]["expected_responses"][19].update(bytes=True),
    lambda p: p["preparation"]["expected_responses"][19].update(body_sha256="bad"),
])
def test_even_ineligible_original_resources_must_remain_valid(mutation):
    prepared = prepared_data()
    mutation(prepared)
    with pytest.raises(ValueError):
        native._buflo_capped_candidates(prepared, CAP)


def test_real_sustained_validator_enforces_ordered_reject_overcap_selected(tmp_path, executable, monkeypatch):
    prepared, path, result, calls = qualified(tmp_path, executable, monkeypatch,
        rejected={1}, actual_sizes={2: CAP + 1})
    assert [identifier for identifier, _ in calls] == [1, 2, 3]
    sidecar = result["sidecar"]
    assert result["error"] is None and sidecar["selection_outcomes"] == ["rejected", "over-cap", "selected"]
    assert sidecar["selected_chaff_resource_id"] == 3
    assert sidecar["scientific_credit"] is False
    assert result["manifest"]["schema_version"] == 4
    assert result["manifest"]["selected_chaff_resource_id"] == 3
    for attempt in sidecar["candidate_attempts"]:
        assert len(attempt["connection_epochs"]) == 3
        assert sum(len(epoch["receipt"]["requests"]) for epoch in attempt["connection_epochs"]) == 120
        epochs = attempt["connection_epochs"]
        assert all(b["receipt"]["started_unix_ns"] - a["receipt"]["ended_unix_ns"] >= 30 * 10**9
                   for a, b in zip(epochs, epochs[1:]))
    native._validate_buflo_capped_sidecar(prepared, sha256_file(path), sidecar,
                                         result["manifest"], runtime(executable), CAP)


@pytest.mark.parametrize("outcome", ["no-auxiliary", "all-rejected", "all-over-cap"])
def test_unavailable_cap_never_publishes_launch_inputs(tmp_path, executable, monkeypatch, outcome):
    prepared = prepared_data()
    if outcome == "no-auxiliary":
        for row in prepared["preparation"]["expected_responses"][1:]:
            row["bytes"] = 1199
    path = tmp_path / "prepared.json"
    write(path, prepared)
    calls = install_sustained(monkeypatch,
        rejected={1, 2, 3} if outcome == "all-rejected" else (),
        actual_sizes={i: CAP + 1 for i in (1, 2, 3)} if outcome == "all-over-cap" else {})
    result = native._qualify_buflo_capped(path, tmp_path / "qualification", executable,
                                        runtime(executable), CAP)
    assert result["sidecar"] is None and result["manifest"] is None and result["error"]
    assert len(calls) == (0 if outcome == "no-auxiliary" else 3)
    retained = json.loads((tmp_path / "qualification/qualification-failed.json").read_bytes())
    assert retained["scientific_credit"] is False


@pytest.mark.parametrize("mutation", [
    lambda s, m: s.update(schema_version=True),
    lambda s, m: s.update(cap_bytes=True),
    lambda s, m: s.update(application_workload_sha256="f" * 64),
    lambda s, m: s.update(application_resource_id=True),
    lambda s, m: s.update(selected_chaff_resource_id=0),
    lambda s, m: s.update(qualified_parallel_chaff_streams=True),
    lambda s, m: s["runtime"].update(client_sha256="f" * 64),
    lambda s, m: s["neqo_provenance"].update(migration_commit="f" * 40),
    lambda s, m: s.update(scientific_credit=True),
    lambda s, m: s.update(extra="unsupported"),
    lambda s, m: s.update(selection_outcomes=["over-cap"]),
    lambda s, m: s.update(candidate_attempts=[]),
    lambda s, m: s["resource"].update(response_qualification_sha256="f" * 64),
    lambda s, m: s.update(native_manifest_sha256="f" * 64),
    lambda s, m: m.update(selected_chaff_resource_id=0),
])
def test_sidecar_runtime_policy_and_native_manifest_joins(tmp_path, executable, monkeypatch, mutation):
    prepared, path, result, _ = qualified(tmp_path, executable, monkeypatch)
    mutation(result["sidecar"], result["manifest"])
    with pytest.raises(ValueError):
        native._validate_buflo_capped_sidecar(prepared, sha256_file(path), result["sidecar"],
                                             result["manifest"], runtime(executable), CAP)


@pytest.mark.parametrize("mutation", ["request-35", "missing-response", "spacing", "native-drift", "skipped-candidate"])
def test_fully_rehashed_receipts_cannot_bypass_original_sustained_guards(tmp_path, executable, monkeypatch, mutation):
    prepared, path, result, _ = qualified(tmp_path, executable, monkeypatch)
    sidecar = result["sidecar"]
    attempt = sidecar["candidate_attempts"][0]
    epochs = attempt["connection_epochs"]
    if mutation == "request-35":
        epochs[0]["receipt"]["requests"][35]["body_sha256"] = "f" * 64
    elif mutation == "missing-response":
        epochs[0]["receipt"]["requests"].pop()
    elif mutation == "spacing":
        epochs[1]["receipt"]["started_unix_ns"] -= 1
    elif mutation == "native-drift":
        epochs[1]["receipt"]["source"]["migration_commit"] = "f" * 40
    else:
        attempt.update(resource_id=2, url=prepared["resources"][2]["url"])
    _rehash_response_only_v2_sidecar(sidecar)
    with pytest.raises(ValueError):
        native._validate_buflo_capped_sidecar(prepared, sha256_file(path), sidecar,
                                             result["manifest"], runtime(executable), CAP)


def test_enrollment_binds_exact_files_and_default_absence(tmp_path, executable, monkeypatch):
    assert native.validate_buflo_capped_enrollment(tmp_path, {}) is None
    enrollment, _, result = enrolled(tmp_path, executable, monkeypatch)
    binding = native.validate_buflo_capped_enrollment(tmp_path, enrollment)
    assert binding == {**enrollment["buflo_chaff_selection"],
        "application_workload_sha256": sha256_file(tmp_path / "prepared-workload.json"),
        "selected_chaff_resource_id": result["manifest"]["selected_chaff_resource_id"],
        "sidecar_sha256": sha256_file(tmp_path / "sidecar.json"),
        "native_manifest_sha256": sha256_file(tmp_path / "chaff.json")}
    # Equivalent JSON with different bytes is still not the authenticated launch file.
    (tmp_path / "chaff.json").write_text(json.dumps(result["manifest"]))
    enrollment["files"]["chaff.json"] = sha256_file(tmp_path / "chaff.json")
    with pytest.raises(ValueError, match="exact Native manifest bytes"):
        native.validate_buflo_capped_enrollment(tmp_path, enrollment)


@pytest.mark.parametrize("mutation", ["missing-path", "absolute", "traversal", "symlink", "changed-bytes", "missing-cap", "null-cap", "boolean-cap", "extra-selection", "error-with-ready"])
def test_enrollment_refuses_changed_paths_declaration_or_ready_error(tmp_path, executable, monkeypatch, mutation):
    enrollment, _, _ = enrolled(tmp_path, executable, monkeypatch)
    if mutation == "missing-path":
        enrollment["paths"].pop("buflo_chaff_manifest")
    elif mutation == "absolute":
        enrollment["paths"]["buflo_chaff_manifest"] = str(tmp_path / "chaff.json")
    elif mutation == "traversal":
        enrollment["paths"]["buflo_chaff_manifest"] = "../chaff.json"
    elif mutation == "symlink":
        (tmp_path / "alias.json").symlink_to(tmp_path / "chaff.json")
        enrollment["paths"]["buflo_chaff_manifest"] = "alias.json"
    elif mutation == "changed-bytes":
        (tmp_path / "chaff.json").write_bytes(b"{}\n")
    elif mutation == "missing-cap":
        enrollment["buflo_chaff_selection"].pop("cap_bytes")
    elif mutation == "null-cap":
        enrollment["buflo_chaff_selection"]["cap_bytes"] = None
    elif mutation == "boolean-cap":
        enrollment["buflo_chaff_selection"]["cap_bytes"] = True
    elif mutation == "extra-selection":
        enrollment["buflo_chaff_selection"]["extra"] = 1
    else:
        enrollment["buflo_chaff_qualification_error"] = "retained failure"
    with pytest.raises(ValueError):
        native.validate_buflo_capped_enrollment(tmp_path, enrollment)


@pytest.mark.parametrize("mutation", [None, "ready-alias", "empty-error", "missing-error", "launch-path"])
def test_failed_cap_is_explicitly_unavailable_only_for_buflo(tmp_path, mutation):
    enrollment = {"buflo_chaff_selection": {"schema_version": 1,
        "record_type": native.BUFLO_CAPPED_SELECTION_TYPE,
        "selection_policy": native.BUFLO_CAPPED_SELECTION_POLICY, "cap_bytes": CAP},
        "mode_readiness": {**dict.fromkeys(native.MODES, True), "buflo": False},
        "buflo_chaff_qualification_error": "all identity candidates exceeded the cap",
        "paths": {"buflo_chaff_manifest": None, "buflo_chaff_sidecar": None}}
    if mutation == "ready-alias":
        enrollment["mode_readiness"]["buflo"] = 0
    elif mutation == "empty-error":
        enrollment["buflo_chaff_qualification_error"] = ""
    elif mutation == "missing-error":
        enrollment.pop("buflo_chaff_qualification_error")
    elif mutation == "launch-path":
        enrollment["paths"]["buflo_chaff_manifest"] = "chaff.json"
    if mutation is None:
        assert native.validate_buflo_capped_enrollment(tmp_path, enrollment) is None
        assert all(enrollment["mode_readiness"][mode] is True for mode in native.MODES if mode != "buflo")
    else:
        with pytest.raises(ValueError, match="unqualified"):
            native.validate_buflo_capped_enrollment(tmp_path, enrollment)


@pytest.mark.parametrize("cap", [None, CAP])
def test_public_preparation_leaves_scientific_settings_and_other_modes_unchanged(tmp_path, executable, monkeypatch, cap):
    install_process_stub(monkeypatch)
    sustained = install_sustained(monkeypatch)
    root = tmp_path / "enrollment"
    result = native.prepare_domain(HOST, URLS, root, client=executable,
                                   runtime=runtime(executable), buflo_chaff_cap_bytes=cap)
    stored = json.loads((root / "enrollment.json").read_bytes())
    assert result["scientific_credit"] is False
    assert stored["mode_policies"] == native.mode_policies()
    assert stored["mode_readiness"] == dict.fromkeys(native.MODES, True)
    assert json.loads((root / "chaff-manifest.json").read_bytes())["schema_version"] == 3
    assert result["mode_settings"]["buflo"]["parameters"]["interval_us"] == 64000
    assert result["mode_settings"]["cs-buflo"]["parameters"]["packet_size"] == 600
    assert stored["urls"] == URLS[:20]
    if cap is None:
        assert "buflo_chaff_selection" not in stored
        assert "buflo_chaff_manifest" not in stored["paths"]
        assert not sustained
    else:
        assert native.validate_buflo_capped_enrollment(root, stored)["cap_bytes"] == cap
        assert [identifier for identifier, _ in sustained] == [1]


@pytest.mark.parametrize("mode", native.MODES)
def test_only_buflo_capture_uses_new_manifest(tmp_path, executable, monkeypatch, mode):
    install_process_stub(monkeypatch)
    install_sustained(monkeypatch)
    root = tmp_path / "enrollment"
    result = native.prepare_domain(HOST, URLS, root, client=executable,
                                   runtime=runtime(executable), buflo_chaff_cap_bytes=CAP)
    monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))
    observed = []

    def collect(attempt, manifest, chaff_input, hostname, defense, seed, context, **kwargs):
        observed.append(chaff_input)
        attempt.mkdir()
        run = get_run(json.loads(manifest.read_bytes()), sha256_file(manifest), seed=seed)
        run["application_response_policy"] = kwargs["application_response_policy"]
        write(attempt / "neqo/run.json", run)
        write(attempt / "attempt.json", {"success": True})
        return {"success": True}

    monkeypatch.setattr(collector, "_collect_attempt", collect)
    actual = native.capture_session(HOST, mode, root, tmp_path / "attempt", seed=9,
                                    runtime=runtime(executable), client=executable)
    expected = (None if mode == "undefended" else
                Path(result["paths"]["buflo_chaff_manifest" if mode == "buflo" else "chaff_manifest"]))
    assert observed == [expected]
    assert actual["scientific_credit"] is False
    assert actual["mode_settings"] == result["mode_settings"][mode]


@pytest.mark.parametrize("mutation", [None, "bytes", "hash", "headers", "selected-id"])
def test_actual_runtime_chaff_receipt_still_matches_qualified_identity(tmp_path, executable, monkeypatch, mutation):
    _, _, result, _ = qualified(tmp_path, executable, monkeypatch)
    manifest = tmp_path / "runtime-chaff.json"
    write(manifest, result["manifest"])
    resource = result["manifest"]["resources"][0]
    qualification = resource["chaff_qualification"]
    expected = qualification["expected_response"]
    receipt = {"resource_id": resource["id"], "request_id": 0, "url": resource["url"],
        "request_headers": resource["headers"], "request_stream_bytes": qualification["request_stream_bytes"],
        "expected_request_stream_bytes": qualification["request_stream_bytes"],
        "response_headers": [[":status", "200"]], "status": expected["status"],
        "content_encoding": "identity", "bytes": expected["body_bytes"],
        "body_sha256": expected["body_sha256"], "complete": True, "status_match": True,
        "content_encoding_match": True, "body_bytes_match": True, "body_sha256_match": True,
        "identity_verified": True, "outcome": "succeeded"}
    if mutation == "bytes":
        receipt["bytes"] += 1
    elif mutation == "hash":
        receipt["body_sha256"] = "f" * 64
    elif mutation == "headers":
        receipt["request_headers"] = [["accept", "*/*"], ["accept-encoding", "gzip"],
                                      ["accept-language", "en-US,en;q=0.9"]]
    elif mutation == "selected-id":
        receipt["resource_id"] = 0
    run = {"chaff_responses": [receipt], "defense_diagnostics": {
        "buflo_terminal_subcell_stream_cancellations": 0, "cs_buflo_local_et_stream_cancellations": 0}}
    if mutation is None:
        collector._validate_chaff_response_receipts(run, manifest, "buflo")
    else:
        with pytest.raises(ValueError):
            collector._validate_chaff_response_receipts(run, manifest, "buflo")


def test_public_cap_flag_is_prepare_only_and_requires_live_context(tmp_path, capsys):
    args = study.parser().parse_args(["prepare", "--root", str(tmp_path), "--buflo-chaff-cap-bytes", "10000"])
    assert args.buflo_chaff_cap_bytes == CAP
    assert study.main(["prepare", "--root", str(tmp_path), "--buflo-chaff-cap-bytes", "10000"]) == 1
    refused = json.loads(capsys.readouterr().out)
    assert refused["status"] == "refused" and "live --enroll" in refused["reason"]
    with pytest.raises(SystemExit):
        study.parser().parse_args(["capture", "--root", str(tmp_path), "--buflo-chaff-cap-bytes", "10000"])


def test_failed_capped_preparation_keeps_original_other_mode_readiness(tmp_path, executable, monkeypatch):
    install_process_stub(monkeypatch)
    install_sustained(monkeypatch, rejected=set(range(1, 20)))
    root = tmp_path / "enrollment"
    native.prepare_domain(HOST, URLS, root, client=executable, runtime=runtime(executable),
                          buflo_chaff_cap_bytes=CAP)
    stored = json.loads((root / "enrollment.json").read_bytes())
    assert stored["mode_readiness"] == {**dict.fromkeys(native.MODES, True), "buflo": False}
    assert stored["qualification_error"] is None and stored["buflo_chaff_qualification_error"]
    assert stored["paths"]["chaff_manifest"] == "chaff-manifest.json"
    assert stored["paths"]["buflo_chaff_sidecar"] is None
    assert stored["paths"]["buflo_chaff_manifest"] is None
    assert native.validate_buflo_capped_enrollment(root, stored) is None
    monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))
    with pytest.raises(ValueError, match="no actual preparation"):
        native.capture_session(HOST, "buflo", root, tmp_path / "attempt", seed=9,
                                runtime=runtime(executable), client=executable)
    assert not (tmp_path / "attempt").exists()


def test_cap_cannot_rewrite_an_existing_enrollment(tmp_path):
    from qcsd_lab.resource_study_store import StudyStore
    from tests.test_resource_study import _source, _enrollment, _runtime

    source, root = tmp_path / "source.json", tmp_path / "study"
    _source(source, (HOST,))
    study.initialize(source, root)
    store = StudyStore(root)
    store.enroll(_enrollment(root, HOST))
    path = root / "classes" / HOST / "enrollment.json"
    before = path.read_bytes()

    class NeverPrepare:
        def prepare(self, *_args, **_kwargs):
            pytest.fail("a cap cannot recollect or replace an existing enrollment")

    with pytest.raises(ValueError, match="fresh enrollment"):
        study.enroll(root, _runtime(), [HOST], backend=NeverPrepare(), buflo_chaff_cap_bytes=CAP)
    assert path.read_bytes() == before and store.status()["accepted_count"] == 0
