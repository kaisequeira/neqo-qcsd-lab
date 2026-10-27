"""Offline adapter controls. Mock process output never represents a live pass."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_session as collector
from qcsd_lab import chaff_qualification as chaff
from qcsd_lab import resource_study_native as native
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file


HOST = "assets.example.org"
URLS = [f"https://{HOST}/resource-{index}?id={index}" for index in range(22)]
COMMIT = "d" * 40


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


@pytest.fixture
def executable(tmp_path):
    path = tmp_path / "native-client"
    path.write_bytes(b"offline adapter test executable placeholder\n")
    path.chmod(0o755)
    return path


@pytest.fixture(autouse=True)
def offline_durability(monkeypatch):
    # These fixtures prove control flow and schemas, not physical durability.
    # Production still calls fsync; avoid a disk flush for every mock GET log.
    monkeypatch.setattr(native.os, "fsync", lambda _descriptor: None)


def runtime(executable):
    return {"native_commit": COMMIT, "client_sha256": sha256_file(executable),
            "image_digest": "sha256:" + "a" * 64}


def get_run(manifest, digest, *, seed=0):
    rows = [{"resource_id": resource["id"], "url": resource["url"],
        "request_headers": resource["headers"],
        "response_headers": [[":status", "200"], ["content-length", "2000"]],
        "status": 200, "content_length": 2000, "bytes": 2000,
        "body_sha256": hashlib.sha256(resource["url"].encode()).hexdigest(),
        "request_stream_bytes": 150, "complete": True, "outcome": "succeeded"}
        for resource in manifest["resources"]]
    return {"method": "GET", "request_policy": "as-defined", "seed": seed,
        "workload_hash_sha256": digest, "max_response_bytes": native.MAX_RESPONSE_BYTES,
        "completion_status": "complete", "error": None, "error_class": None,
        "terminal_evidence_render_errors": [], "migration_commit": COMMIT,
        "application_response_policy": "http-2xx-only-v1",
        "application_workload_source_hash_sha256": None,
        "chaff_manifest_hash_sha256": None, "chaff_responses": [],
        "resolved_configuration": {"defense": {"kind": "none"}},
        "endpoints": [{"id": 0, "origin": f"https://{HOST}/", "negotiated_protocol": "h3"}],
        "responses": rows}


def response_receipt(prepared, identifier, index):
    selected = json.loads(prepared.read_bytes())["resources"][identifier]
    observations = [{"sequence": i, "phase": "qualification", "direction": direction,
                     "udp_payload_bytes": size}
                    for i, (direction, size) in enumerate((("incoming", 1500), ("outgoing", 1200)))]
    statistics = {direction: {"packet_count": count, "observed_udp_payload_max": maximum,
                              "oversized_packet_count": 0}
                  for direction, count, maximum in (("incoming", 1, 1500), ("outgoing", 1, 1200), ("total", 2, 1500))}
    return {"schema_version": 4, "artifact_type": chaff.RESPONSE_ARTIFACT_TYPE,
        "invocation_id": f"offline-response-{identifier}-{index}", "neqo_version": "offline-test",
        "application_workload_sha256": sha256_file(prepared), "application_resource_id": 0,
        "selected_chaff_resource_id": identifier, "qualified_parallel_chaff_streams": 5,
        "method": "GET", "url": selected["url"], "request_headers": selected["headers"],
        "parallel_requests": 5, "connection_count": 1,
        "requests_opened_before_first_network_output": 5, "request_stream_bytes": 150,
        "max_response_bytes": native.MAX_RESPONSE_BYTES, "udp_payload_ceiling": 1200,
        "incoming_udp_payload_limit": 65527, "outgoing_udp_payload_ceiling": 1200,
        "started_unix_ns": 100 + index * 20, "ended_unix_ns": 110 + index * 20,
        "completion_status": "complete", "error": None,
        "source": {"neqo_base_commit": "a" * 40, "published_qcsd_commit": "b" * 40,
                   "migration_commit": COMMIT},
        "requests": [{"request_index": i, "stream_id": 4 * i, "request_stream_bytes": 150,
            "status": 200, "content_encoding": "identity", "body_bytes": 2000,
            "body_sha256": hashlib.sha256(selected["url"].encode()).hexdigest(),
            "complete": True, "outcome": "complete"} for i in range(5)],
        "packet_observations": observations,
        "packet_log_sha256": hashlib.sha256(json.dumps(observations, separators=(",", ":")).encode()).hexdigest(),
        "packets": statistics, "passed": True}


def install_process_stub(monkeypatch, *, rejected=(), failed_qualification=False,
                         corrupt_qualification=None):
    calls = []

    def fake_run(argv, *, stdout, stderr, timeout, check):
        calls.append(argv)
        stdout.write(b"offline stub stdout\n")
        stderr.write(b"offline stub stderr\n")
        output = Path(argv[argv.index("--output-dir") + 1])
        manifest = Path(argv[argv.index("--workload") + 1])
        if argv[1] == "run":
            content = json.loads(manifest.read_bytes())
            value = get_run(content, sha256_file(manifest))
            if content["resources"][0]["url"] in rejected:
                value["completion_status"] = "partial"
                value["responses"][0]["status"] = 404
            write(output / "run.json", value)
            return SimpleNamespace(returncode=0)
        assert argv[1] == "qualify-chaff-response"
        if failed_qualification:
            return SimpleNamespace(returncode=1)
        identifier = int(argv[argv.index("--selected-chaff-resource-id") + 1])
        index = int(output.parent.name.split("-")[-1])
        receipt = response_receipt(manifest, identifier, index)
        if corrupt_qualification:
            corrupt_qualification(receipt)
        write(output / "qualification.json", receipt)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    return calls


def prepared(tmp_path, executable, monkeypatch, **stub):
    calls = install_process_stub(monkeypatch, **stub)
    root = tmp_path / "enrollment"
    result = native.prepare_domain(HOST, URLS, root, client=executable, runtime=runtime(executable))
    return root, result, calls


def test_real_qualifier_contract_and_frozen_resource_anchor(tmp_path, executable, monkeypatch):
    root, enrollment, calls = prepared(tmp_path, executable, monkeypatch, rejected=(URLS[0],))
    assert enrollment["urls"] == URLS[1:21]
    assert len([call for call in calls if call[1] == "run"]) == 22
    assert len([call for call in calls if call[1] == "qualify-chaff-response"]) == 3
    assert enrollment["mode_readiness"] == dict.fromkeys(native.MODES, True)
    assert enrollment["scientific_credit"] is False
    source = json.loads((root / "prepared-workload.json").read_bytes())
    assert source["resources"][0]["type"] == "Document"
    assert source["preparation"]["resource_anchor"]["html_or_navigation_claimed"] is False
    assert all(resource["depends_on"] == [] and resource["known_valid"] is True
               for resource in source["resources"])
    assert source["preparation"]["approved_origins"] == [f"https://{HOST}"]
    assert source["preparation"]["expected_responses"][0]["body_sha256"] == hashlib.sha256(URLS[1].encode()).hexdigest()
    chaff_input = json.loads((root / "chaff-manifest.json").read_bytes())
    assert chaff_input["schema_version"] == 3
    assert chaff_input["application_workload_sha256"] == sha256_file(root / "prepared-workload.json")
    assert chaff_input["selected_chaff_resource_id"] == 0
    assert chaff_input["qualified_parallel_chaff_streams"] == 5
    assert enrollment["mode_settings"]["front"]["resolved_configuration"]["defense"]["n_client_packets"] == 450
    assert enrollment["mode_settings"]["tamaraw"]["resolved_configuration"]["initial_max_stream_data"] == 8192
    assert enrollment["mode_settings"]["buflo"]["parameters"]["interval_us"] == 64000
    assert enrollment["mode_settings"]["buflo"]["parameters"]["max_events"] == 10000
    assert enrollment["mode_settings"]["cs-buflo"]["parameters"]["packet_size"] == 600
    assert enrollment["files"]["enrollment.json"] == sha256_file(root / "enrollment.json")
    retained = json.loads((root / "probe/url-0000/probe-result.json").read_bytes())
    assert retained["accepted"] is False
    assert (root / "probe/url-0000/started.json").is_file()
    assert (root / "probe/url-0000/completed.json").is_file()
    assert (root / "probe/url-0000/stderr.txt").read_bytes() == b"offline stub stderr\n"
    assert json.loads((root / "probe/probe.json").read_bytes())["unassessed_urls"] == [URLS[21]]


@pytest.mark.parametrize("mutation", [
    lambda run: run.update(completion_status="partial"),
    lambda run: run.update(error_class="native-error"),
    lambda run: run.update(migration_commit="f" * 40),
    lambda run: run["endpoints"][0].update(negotiated_protocol="h2"),
    lambda run: run["endpoints"][0].update(origin="https://other.example.org/"),
    lambda run: run["responses"].pop(),
    lambda run: run["responses"].__setitem__(1, copy.deepcopy(run["responses"][0])),
    lambda run: run["responses"][7].update(status=404),
    lambda run: run["responses"][7].update(complete=False),
    lambda run: run["responses"][7].update(bytes=0),
    lambda run: run["responses"][7].update(body_sha256=hashlib.sha256(b"").hexdigest()),
    lambda run: run["responses"][7].update(request_headers=[]),
    lambda run: run["responses"][7].update(content_length=2001),
    lambda run: run["responses"][7].update(url=URLS[21]),
    lambda run: run["responses"][7].update(status=True),
])
def test_every_resource_completion_controls(mutation):
    manifest = native._manifest(HOST, URLS[:20], require_twenty=True)
    value = get_run(manifest, "c" * 64)
    assert len(native.inspect_completed_run(value, manifest, manifest_sha256="c" * 64,
        max_response_bytes=native.MAX_RESPONSE_BYTES, native_commit=COMMIT)) == 20
    mutation(value)
    with pytest.raises(ValueError):
        native.inspect_completed_run(value, manifest, manifest_sha256="c" * 64,
            max_response_bytes=native.MAX_RESPONSE_BYTES, native_commit=COMMIT)


def test_chaff_failure_preserves_ordinary_and_all_failed_attempts(tmp_path, executable, monkeypatch):
    root, enrollment, calls = prepared(tmp_path, executable, monkeypatch, failed_qualification=True)
    assert enrollment["mode_readiness"] == {mode: mode == "undefended" for mode in native.MODES}
    assert enrollment["paths"]["chaff_manifest"] is None
    assert enrollment["qualification_error"]
    assert len([call for call in calls if call[1] == "qualify-chaff-response"]) == 1
    assert len(list((root / "qualification").glob("resource-*/failure.json"))) == 1
    with pytest.raises(ValueError, match="no actual"):
        monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))
        native.capture_session(HOST, "front", root, tmp_path / "attempt", seed=1,
                               runtime=runtime(executable), client=executable)


@pytest.mark.parametrize("field,value", [("passed", False), ("packet_log_sha256", "0" * 64),
                                         ("requests_opened_before_first_network_output", 1)])
def test_actual_chaff_receipt_validator_refuses_corruption(tmp_path, executable, monkeypatch, field, value):
    _, enrollment, _ = prepared(tmp_path, executable, monkeypatch,
        corrupt_qualification=lambda receipt: receipt.update({field: value}))
    assert enrollment["mode_readiness"]["undefended"] is True
    assert enrollment["mode_readiness"]["front"] is False
    assert enrollment["paths"]["chaff_core"] is None


def test_pool_and_runtime_fail_before_any_process(tmp_path, executable, monkeypatch):
    calls = install_process_stub(monkeypatch)
    with pytest.raises(ValueError, match="hostname"):
        native.prepare_domain(HOST, [*URLS[:19], "https://other.example.org/a"],
                              tmp_path / "bad-pool", client=executable, runtime=runtime(executable))
    changed = {**runtime(executable), "client_sha256": "0" * 64}
    with pytest.raises(ValueError, match="differs"):
        native.prepare_domain(HOST, URLS, tmp_path / "bad-client", client=executable, runtime=changed)
    assert not calls
    assert not (tmp_path / "bad-pool").exists()
    assert not (tmp_path / "bad-client").exists()


def test_timeout_retains_raw_process_boundaries(tmp_path, executable, monkeypatch):
    def timeout(argv, **kwargs):
        kwargs["stdout"].write(b"partial offline output")
        raise subprocess.TimeoutExpired(argv, 125)
    monkeypatch.setattr(native.subprocess, "run", timeout)
    result = native.probe_urls(HOST, URLS[:1], tmp_path / "probe", client=executable)
    assert result["selected_urls"] == []
    completed = json.loads((tmp_path / "probe/url-0000/completed.json").read_bytes())
    assert completed["timed_out"] is True and completed["returncode"] is None
    assert (tmp_path / "probe/url-0000/stdout.txt").read_bytes() == b"partial offline output"


@pytest.mark.parametrize("mode", native.MODES)
def test_public_capture_uses_unchanged_collector_inputs_and_returns_actual_paths(tmp_path, executable, monkeypatch, mode):
    root, enrollment, _ = prepared(tmp_path, executable, monkeypatch)
    monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))
    observed = {}

    def collect(attempt, manifest, chaff_input, hostname, defense, seed, context, **kwargs):
        observed.update(defense=defense, context=context, kwargs=kwargs)
        command = collector._client_command(manifest, chaff_input, hostname, defense, seed,
            context, attempt / "neqo", **kwargs)
        observed["command"] = command
        assert not attempt.exists()
        attempt.mkdir()
        value = get_run(json.loads(manifest.read_bytes()), sha256_file(manifest), seed=seed)
        value["application_response_policy"] = kwargs["application_response_policy"]
        write(attempt / "neqo/run.json", value)
        for relative in ("neqo/events.csv", "neqo/packets.csv", "captures/direct-quic.pcapng",
                         "traces/direct-quic.csv", "diagnostics/direct-quic-raw.pcapng"):
            path = attempt / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"offline collector placeholder")
        write(attempt / "attempt.json", {"success": True})
        return {"success": True}

    monkeypatch.setattr(collector, "_collect_attempt", collect)
    result = native.capture_session(HOST, mode, root, tmp_path / "attempt", seed=9,
                                   runtime=runtime(executable), client=executable)
    assert result["scientific_credit"] is False
    assert result["result"] == {"success": True}
    assert result["mode_settings"] == enrollment["mode_settings"][mode]
    assert result["native_events"].endswith("neqo/events.csv")
    assert result["capture"].endswith("captures/direct-quic.pcapng")
    assert result["native_schedule"] is None
    command = observed["command"]
    if mode == "undefended":
        assert "--chaff-manifest" not in command and "--application-workload-source" not in command
        assert observed["defense"].kind == "none"
    else:
        assert "--chaff-manifest" in command and "--application-workload-source" in command
    if mode in {"front", "tamaraw"}:
        assert "--config" in command and "--defense" not in command
    if mode == "buflo":
        assert "--buflo-parameters" in command
        assert observed["context"].limits.timeout_seconds == 680
        assert observed["context"].limits.capture_seconds == 740
    if mode == "cs-buflo":
        assert "--cs-buflo-parameters" in command
        assert observed["defense"].kind == "cs_buflo"


def test_session_outer_check_cannot_promote_collector_terminal_error(tmp_path, executable, monkeypatch):
    root, _, _ = prepared(tmp_path, executable, monkeypatch)
    monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))

    def collect(attempt, manifest, *_args, **_kwargs):
        attempt.mkdir()
        value = get_run(json.loads(manifest.read_bytes()), sha256_file(manifest), seed=9)
        value["responses"][19]["status"] = 404
        write(attempt / "neqo/run.json", value)
        write(attempt / "attempt.json", {"success": True})
        return {"success": True}
    monkeypatch.setattr(collector, "_collect_attempt", collect)
    result = native.capture_session(HOST, "undefended", root, tmp_path / "attempt", seed=9,
                                   runtime=runtime(executable), client=executable)
    assert result["success"] is False and result["resource_error"]
    assert json.loads(Path(result["resource_check"]).read_bytes())["passed"] is False


def test_frozen_parameter_mutation_and_attempt_reuse_refused(tmp_path, executable, monkeypatch):
    root, _, _ = prepared(tmp_path, executable, monkeypatch)
    monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))
    (root / "params/buflo.json").write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="digest"):
        native.capture_session(HOST, "buflo", root, tmp_path / "attempt", seed=9,
                               runtime=runtime(executable), client=executable)
    with pytest.raises(FileExistsError):
        native.prepare_domain(HOST, URLS, root, client=executable, runtime=runtime(executable))


def test_json_duplicate_job_fields_refused(tmp_path):
    path = tmp_path / "job.json"
    path.write_text('{"mode":"front","mode":"undefended"}')
    with pytest.raises(ValueError, match="duplicate"):
        native.main(["_capture", "--job", str(path)])


def test_runtime_repair_preserves_native_enrollment(tmp_path, executable, monkeypatch):
    root, _, _ = prepared(tmp_path, executable, monkeypatch)
    repaired = {**runtime(executable), "image_digest": "sha256:" + "b" * 64,
                "lab_commit": "e" * 40, "collector_sdk_sha256": "f" * 64}
    checked_root, _ = native._enrollment(root, HOST, repaired)
    assert checked_root == root
    for field, value in (("client_sha256", "0" * 64), ("native_commit", "0" * 40),
                         ("platform", "linux/arm64"),
                         ("source", {"neqo_commit": "0" * 40})):
        with pytest.raises(ValueError, match="runtime"):
            native._enrollment(root, HOST, {**repaired, field: value})


def test_schema3_uses_native_deterministic_largest_including_anchor(tmp_path, executable, monkeypatch):
    manifest = native._manifest(HOST, URLS[:20], require_twenty=True)
    manifest["resources"][0]["type"] = "Document"
    source = tmp_path / "prepared.json"
    write(source, {"preparation": {}, **manifest})
    responses = get_run(manifest, sha256_file(source))["responses"]
    calls = install_process_stub(monkeypatch)
    responses[4]["bytes"] = native.MAX_RESPONSE_BYTES + 1
    qualified = native._qualify(source, manifest["resources"], responses,
        native._new_directory(tmp_path / "oversized"), executable, runtime(executable))
    assert qualified["manifest"] is None and qualified["error"]
    assert not calls
    failure = json.loads((tmp_path / "oversized/resource-04/failure.json").read_bytes())
    assert "16MiB" in failure["error"]
    responses[4]["bytes"] = 2000
    qualified = native._qualify(source, manifest["resources"], responses,
        native._new_directory(tmp_path / "tie"), executable, runtime(executable))
    assert qualified["manifest"]["selected_chaff_resource_id"] == 0
    assert all(command[command.index("--selected-chaff-resource-id") + 1] == "0" for command in calls)


def test_new_role_16mib_qualification_and_legacy_default_are_separate(tmp_path):
    source = tmp_path / "prepared.json"
    write(source, native._manifest(HOST, URLS[:20], require_twenty=True))
    receipt = response_receipt(source, 0, 0)
    kwargs = {"application_manifest_sha256": sha256_file(source),
              "application_resource_id": 0, "selected_chaff_resource_id": 0,
              "qualified_parallel_chaff_streams": 5, "url": URLS[0],
              "headers": native.REQUEST_HEADERS}
    for request in receipt["requests"]:
        request["body_bytes"] = 2 * 1024 * 1024
    with pytest.raises(ValueError, match="binding"):
        chaff._validate_response_receipt(receipt, **kwargs)
    identity, _, _, _, _ = chaff._validate_response_receipt(receipt, **kwargs,
        resource_domain_max_response_bytes=native.MAX_RESPONSE_BYTES)
    assert identity[2] == 2 * 1024 * 1024
    runs = []
    for index in range(3):
        run = copy.deepcopy(receipt)
        run.update(invocation_id=f"separate-{index}", started_unix_ns=100 + index * 20,
                   ended_unix_ns=110 + index * 20)
        runs.append(run)
    expected, _ = chaff._stable_response_identity(runs, **kwargs,
        resource_domain_max_response_bytes=native.MAX_RESPONSE_BYTES)
    assert expected["body_bytes"] == 2 * 1024 * 1024
    legacy = copy.deepcopy(receipt)
    legacy["max_response_bytes"] = 1048576
    for request in legacy["requests"]:
        request["body_bytes"] = 2000
    chaff._validate_response_receipt(legacy, **kwargs)
    legacy["requests"][0]["body_bytes"] = 1048577
    with pytest.raises(ValueError, match="request"):
        chaff._validate_response_receipt(legacy, **kwargs)
    receipt["requests"][0]["body_bytes"] = native.MAX_RESPONSE_BYTES + 1
    with pytest.raises(ValueError, match="request"):
        chaff._validate_response_receipt(receipt, **kwargs,
            resource_domain_max_response_bytes=native.MAX_RESPONSE_BYTES)


@pytest.mark.parametrize("cap", [True, 1048576.0, None, 0, 16777217])
def test_qualification_bound_is_closed_and_typed(cap):
    with pytest.raises(ValueError, match="finite"):
        chaff._validate_response_receipt({}, application_manifest_sha256="a" * 64,
            application_resource_id=0, selected_chaff_resource_id=0,
            qualified_parallel_chaff_streams=5, url=URLS[0], headers=native.REQUEST_HEADERS,
            resource_domain_max_response_bytes=cap)


def transport_process(monkeypatch, sequence):
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        outcome = sequence[min(len(calls) - 1, len(sequence) - 1)]
        if outcome == "host-timeout":
            raise subprocess.TimeoutExpired(argv, 125)
        path = Path(argv[argv.index("--workload") + 1])
        value = get_run(json.loads(path.read_bytes()), sha256_file(path))
        if outcome in {"transport", "configuration", "provenance"}:
            value.update(completion_status="error", error="connection closed before handshake",
                         error_class="runner-execution-v1")
            value["endpoints"][0]["negotiated_protocol"] = None
            value["responses"][0].update(status=None, complete=False, outcome="not_started", bytes=0,
                response_headers=[], content_length=None)
            if outcome == "configuration":
                value.update(error="argument request policy is invalid")
            if outcome == "provenance":
                value["migration_commit"] = "f" * 40
        elif outcome in {403, 404}:
            value["completion_status"] = "partial"
            value["responses"][0].update(status=outcome, outcome="failed",
                response_headers=[[":status", str(outcome)], ["content-length", "2000"]])
        output = Path(argv[argv.index("--output-dir") + 1])
        write(output / "run.json", value)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(native.subprocess, "run", run)
    return calls


@pytest.mark.parametrize("failure", ["transport", "host-timeout"])
def test_three_fresh_transport_failures_defer_and_preserve_unattempted_pool(tmp_path, executable, monkeypatch, failure):
    calls = transport_process(monkeypatch, [failure])
    result = native.probe_urls(HOST, URLS, tmp_path / "probe", client=executable, runtime=runtime(executable))
    assert len(calls) == 3 and len(result["results"]) == 3
    assert result["selected_urls"] == [] and result["unassessed_urls"] == URLS[3:]
    assert result["deferred"]["status"] == "transient-deferred"
    assert result["deferred"]["retryable"] is True
    assert result["deferred"]["permanent_host_ineligibility_claimed"] is False
    for index in range(3):
        directory = tmp_path / "probe" / f"url-{index:04d}"
        assert (directory / "started.json").is_file() and (directory / "completed.json").is_file()
        assert (directory / "probe-result.json").is_file()
        assert (directory / "stderr.txt").is_file()


@pytest.mark.parametrize("status", [403, 404])
def test_real_http_error_does_not_defer_transport_and_later_urls_remain_available(tmp_path, executable, monkeypatch, status):
    calls = transport_process(monkeypatch, [status, status, status, "accepted"])
    result = native.probe_urls(HOST, URLS, tmp_path / "probe", client=executable,
        runtime=runtime(executable), stop_after=1)
    assert len(calls) == 4
    assert result["selected_urls"] == [URLS[3]]
    assert result["transport_established"] is True and result["deferred"] is None
    assert all(record["transport"]["confirmed_h3"] for record in result["results"][:3])


def test_completed_h3_then_transport_failure_does_not_skip_remaining_urls(tmp_path, executable, monkeypatch):
    calls = transport_process(monkeypatch, ["accepted", "transport"])
    result = native.probe_urls(HOST, URLS[:6], tmp_path / "probe", client=executable, runtime=runtime(executable))
    assert len(calls) == 6 and result["deferred"] is None
    assert result["selected_urls"] == [URLS[0]] and result["transport_established"] is True


@pytest.mark.parametrize("failure", ["configuration", "provenance"])
def test_unknown_or_bad_provenance_is_not_a_transport_diagnosis(tmp_path, executable, monkeypatch, failure):
    calls = transport_process(monkeypatch, [failure])
    result = native.probe_urls(HOST, URLS[:4], tmp_path / "probe", client=executable, runtime=runtime(executable))
    assert len(calls) == 4 and result["deferred"] is None
    assert all(not record["transport"]["transport_failure"] for record in result["results"])


def test_prepare_domain_preserves_transient_deferral_without_enrollment(tmp_path, executable, monkeypatch):
    calls = transport_process(monkeypatch, ["transport"])
    with pytest.raises(ValueError, match="transient-deferred.*retryable"):
        native.prepare_domain(HOST, URLS, tmp_path / "prepared", client=executable, runtime=runtime(executable))
    assert len(calls) == 3
    deferred = json.loads((tmp_path / "prepared/preparation-deferred.json").read_bytes())
    assert deferred["retryable"] is True and deferred["scientific_credit"] is False
    assert not (tmp_path / "prepared/enrollment.json").exists()


def test_only_consecutive_transport_failures_trigger_early_deferral(tmp_path, executable, monkeypatch):
    calls = transport_process(monkeypatch, ["transport", "configuration", "transport", "transport", "accepted"])
    result = native.probe_urls(HOST, URLS[:5], tmp_path / "probe", client=executable, runtime=runtime(executable))
    assert len(calls) == 5 and result["deferred"] is None
    assert result["selected_urls"] == [URLS[4]]


# Source063 focused offline adapter controls only. The existing prepared()
# process stub supplies synthetic GET/qualification output; no live proof.
def test_buflo_prepared_FIN_policy_reaches_context_and_one_native_flag(tmp_path, executable, monkeypatch):
    from qcsd_lab import buflo_duration_budget as budget
    from qcsd_lab import buflo_fin_permission as fin
    from qcsd_lab.application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY

    root, enrollment, _ = prepared(tmp_path, executable, monkeypatch)
    monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))
    expected = {"application_body_identity_policy": COMPLETE_APPLICATION_DELIVERY_POLICY,
                "buflo_duration_policy": budget.CADENCE64_POLICY}
    # These are the original enrolled science fields; the new launch intent
    # must remain outside this exact logical mode definition.
    assert native.mode_policies()["buflo"] == enrollment["mode_policies"]["buflo"] == expected
    checked_root, checked = native._enrollment(root, HOST, runtime(executable))
    assert checked_root == root
    relative = checked["paths"]["prepared_workload"]
    source = root / relative
    assert checked["files"][relative] == sha256_file(source)
    assert json.loads(source.read_bytes())["preparation"][fin.PREPARATION_FIELD] == fin.POLICY
    defense, context = native._capture_inputs("buflo", root, checked)
    assert getattr(context, fin.PREPARATION_FIELD) == fin.POLICY
    command = collector._client_command(
        root / checked["paths"]["manifest"], root / checked["paths"]["chaff_manifest"],
        HOST, defense, 9, context, tmp_path / "bf-command",
        application_workload_source=source,
        application_response_policy="completed-terminal-http-errors-v1")
    assert command.count(fin.CLI_FLAG) == 1
    assert command[command.index("--application-workload-source") + 1] == str(source)
    # A prepared BF marker cannot enable the opt-in for an ordinary baseline.
    baseline, ordinary = native._capture_inputs("undefended", root, checked)
    assert getattr(ordinary, fin.PREPARATION_FIELD, None) is None
    ordinary_command = collector._client_command(
        root / checked["paths"]["manifest"], None, HOST, baseline, 10, ordinary,
        tmp_path / "ordinary-command")
    assert fin.CLI_FLAG not in ordinary_command
    assert native._enrollment(root, HOST, runtime(executable))[1] == checked


def test_buflo_missing_or_wrong_rebound_prepared_policy_refuses_before_capture(tmp_path, executable, monkeypatch):
    from qcsd_lab import buflo_fin_permission as fin

    for label, value, message in (
        ("missing", None, "prepared BuFLO source lacks the explicit FIN permission policy"),
        ("wrong", "unreviewed-policy", "unsupported explicit preparation/launch policy"),
    ):
        root, _, _ = prepared(tmp_path / label, executable, monkeypatch)
        monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))
        enrollment_path = root / "enrollment.json"
        enrollment = json.loads(enrollment_path.read_bytes())
        relative = enrollment["paths"]["prepared_workload"]
        source = root / relative
        prepared_source = json.loads(source.read_bytes())
        if value is None:
            del prepared_source["preparation"][fin.PREPARATION_FIELD]
        else:
            prepared_source["preparation"][fin.PREPARATION_FIELD] = value
        # Deliberate private fixture forgery: rebind the modified file so the
        # target refusal is policy semantics, rather than a stale digest.
        write(source, prepared_source)
        enrollment["files"][relative] = sha256_file(source)
        write(enrollment_path, enrollment)
        checked_root, checked = native._enrollment(root, HOST, runtime(executable))
        assert checked_root == root and checked["files"][relative] == sha256_file(source)
        collected = []

        def forbidden_collect(*_args, **_kwargs):
            collected.append(True)
            raise AssertionError("invalid prepared policy reached collector")

        monkeypatch.setattr(collector, "_collect_attempt", forbidden_collect)
        with pytest.raises(ValueError, match=message):
            native.capture_session(HOST, "buflo", root, tmp_path / label / "attempt", seed=9,
                                   runtime=runtime(executable), client=executable)
        assert not collected
        assert native._enrollment(root, HOST, runtime(executable))[1] == checked


# Source070 offline controls. Synthetic GET/qualification output is not a live pass.
def test_source070_exact_opt_in_tuple_receipt_and_historical_bounds(tmp_path):
    from qcsd_lab import buflo_duration_budget as budget
    from qcsd_lab import parameters

    raw = budget.cadence64_1280_parameter_bytes()
    assert hashlib.sha256(raw).hexdigest() == budget.CADENCE64_1280_PARAMETER_SHA256
    assert budget.CADENCE64_PARAMETER_SHA256 == "5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e"
    assert budget.preparation_policy() == budget.CADENCE64_POLICY
    assert budget.preparation_policy(budget.CADENCE64_1280_POLICY) == budget.CADENCE64_1280_POLICY
    assert budget.CADENCE64_1280_PARAMETERS == {
        **budget.CADENCE64_PARAMETERS, "max_events": 20_000,
        budget.PARAMETER_FIELD: budget.CADENCE64_1280_POLICY}
    budget.validate_parameters(json.loads(raw))
    parameters._validate_buflo(json.loads(raw), 1200, tmp_path / "parameters.json")
    for altered in (
        {**json.loads(raw), "max_events": 20_001},
        {**json.loads(raw), "max_events": True},
        {**json.loads(raw), budget.PARAMETER_FIELD: budget.CADENCE64_POLICY},
        {k: v for k, v in json.loads(raw).items() if k != budget.PARAMETER_FIELD},
    ):
        with pytest.raises(ValueError):
            parameters._validate_buflo(altered, 1200, tmp_path / "invalid.json")
    for value in (True, "unknown-duration", budget.POLICY):
        with pytest.raises(ValueError):
            budget.preparation_policy(value)
    path = "/exact/selected-1280.json"
    run = {"method": "GET", "defense_parameters": {
        "kind": "buflo", "path": path, "sha256": budget.CADENCE64_1280_PARAMETER_SHA256,
        "implementation_scope": "client_only_quic", "paper_equivalent": False,
        budget.RUN_FIELD: dict(budget.CADENCE64_1280_RECEIPT)},
        "resolved_configuration": {"defense": {"kind": "buflo", "parameters": path}}}
    metrics = budget.validate_native_receipt(run, raw, expected_path=path)
    assert budget.schedule_bounds(metrics) == (20_000, 1_280_000_000)
    assert budget.schedule_bounds({}) == (6_000, 120_000_000)
    for receipt, digest, expected in (
        (budget.RECEIPT, budget.PARAMETER_SHA256, (10_000, 200_000_000)),
        (budget.CADENCE64_RECEIPT, budget.CADENCE64_PARAMETER_SHA256, (10_000, 640_000_000)),
    ):
        assert budget.schedule_bounds({budget.RUN_FIELD: receipt,
            "buflo_duration_budget_parameter_sha256": digest}) == expected
    assert budget.cadence64_receipt_matches(budget.CADENCE64_1280_RECEIPT,
                                           budget.CADENCE64_1280_PARAMETER_SHA256)
    assert not budget.cadence64_receipt_matches(budget.CADENCE64_1280_RECEIPT,
                                               budget.CADENCE64_PARAMETER_SHA256)
    assert not budget.cadence64_receipt_matches(budget.CADENCE64_RECEIPT,
                                               budget.CADENCE64_1280_PARAMETER_SHA256)
    assert not budget.cadence64_receipt_matches(
        {**budget.CADENCE64_1280_RECEIPT, "max_events": True},
        budget.CADENCE64_1280_PARAMETER_SHA256)
    run["defense_parameters"][budget.RUN_FIELD] = dict(budget.CADENCE64_RECEIPT)
    with pytest.raises(ValueError):
        budget.validate_native_receipt(run, raw, expected_path=path)
    original = {"timeout_seconds": 120, "capture_seconds": 180}
    assert budget.capture_limits("buflo", original, policy=budget.POLICY) == {
        "timeout_seconds": 240, "capture_seconds": 300}
    assert budget.capture_limits("buflo", original, policy=budget.CADENCE64_POLICY) == {
        "timeout_seconds": 680, "capture_seconds": 740}
    assert budget.capture_limits("buflo", original, policy=budget.CADENCE64_1280_POLICY) == {
        "timeout_seconds": 1320, "capture_seconds": 1380}


def test_source070_fresh_preparation_launch_router_and_missing_selector_refusal(tmp_path, executable, monkeypatch):
    from qcsd_lab import buflo_duration_budget as budget
    from qcsd_lab import buflo_fin_permission as fin
    from qcsd_lab import resource_study_runtime as rt

    old_root, old, _ = prepared(tmp_path / "default", executable, monkeypatch)
    assert old["mode_policies"] == native.mode_policies()
    assert old["mode_settings"]["buflo"]["timeout_seconds"] == 680
    assert "buflo_duration_policy" not in json.loads(
        (old_root / old["paths"]["prepared_workload"]).read_bytes())["preparation"]
    assert rt._router_capture_seconds(old) == 740
    install_process_stub(monkeypatch)
    root = tmp_path / "explicit"
    enrollment = native.prepare_domain(HOST, URLS, root, client=executable,
        runtime=runtime(executable), buflo_duration_policy=budget.CADENCE64_1280_POLICY)
    monkeypatch.setattr(collector, "NEQO_CLIENT", str(executable))
    checked_root, checked = native._enrollment(root, HOST, runtime(executable))
    assert checked_root == root
    source = root / checked["paths"]["prepared_workload"]
    assert json.loads(source.read_bytes())["preparation"]["buflo_duration_policy"] == budget.CADENCE64_1280_POLICY
    assert checked["mode_policies"] == native.mode_policies(buflo_duration_policy=budget.CADENCE64_1280_POLICY)
    # This is explicitly changed science: the original C019 Native-only
    # unchanged-science comparison must not erase the policy/settings difference.
    assert checked["mode_policies"]["buflo"] != old["mode_policies"]["buflo"]
    assert checked["mode_settings"]["buflo"] != old["mode_settings"]["buflo"]
    assert all(checked["mode_policies"][mode] == old["mode_policies"][mode]
               for mode in native.MODES if mode != "buflo")
    defense, context = native._capture_inputs("buflo", root, checked)
    assert (context.limits.timeout_seconds, context.limits.capture_seconds) == (1320, 1380)
    assert defense.parameters_sha256 == budget.CADENCE64_1280_PARAMETER_SHA256
    assert getattr(context, fin.PREPARATION_FIELD) == fin.POLICY
    command = collector._client_command(root / checked["paths"]["manifest"],
        root / checked["paths"]["chaff_manifest"], HOST, defense, 9, context,
        tmp_path / "explicit-command", application_workload_source=source,
        application_response_policy="completed-terminal-http-errors-v1")
    assert command.count(fin.CLI_FLAG) == 1
    assert command[command.index("--application-workload-source") + 1] == str(source)
    assert rt._router_capture_seconds(checked) == 1380
    for field, value in (("capture_seconds", 740), ("timeout_seconds", True)):
        forged = copy.deepcopy(checked)
        forged["mode_settings"]["buflo"][field] = value
        with pytest.raises(ValueError, match="router capture bound"):
            rt._router_capture_seconds(forged)
    for value in (None, budget.CADENCE64_POLICY):
        prepared_source = json.loads(source.read_bytes())
        if value is None:
            prepared_source["preparation"].pop("buflo_duration_policy", None)
        else:
            prepared_source["preparation"]["buflo_duration_policy"] = value
        write(source, prepared_source)
        forged = json.loads((root / "enrollment.json").read_bytes())
        forged["files"][forged["paths"]["prepared_workload"]] = sha256_file(source)
        write(root / "enrollment.json", forged)
        # Rebind only the private fixture to reach the semantic launch guard.
        _, rechecked = native._enrollment(root, HOST, runtime(executable))
        with pytest.raises(ValueError, match="matching explicit duration selector"):
            native._capture_inputs("buflo", root, rechecked)


def test_source070_public_selector_and_complete_reader_closure(tmp_path, monkeypatch, capsys):
    from qcsd_lab import buflo_duration_budget as budget
    from qcsd_lab import resource_study as public
    from qcsd_lab import resource_study_cohorts as cohorts
    from qcsd_lab import resource_study_reader_compatibility as helper
    from qcsd_lab import resource_study_runtime as rt

    untouched = tmp_path / "not-created"
    assert public.main(["prepare", "--root", str(untouched),
                        "--buflo-duration-policy", budget.CADENCE64_1280_POLICY]) == 1
    assert "requires fresh live enrollment" in capsys.readouterr().out
    assert not untouched.exists()
    calls = []
    monkeypatch.setattr(native, "prepare_domain", lambda **kw: calls.append(kw) or {})
    job = tmp_path / "job.json"
    write(job, {"sentinel": "same immutable job"})
    assert native.main(["_prepare", "--job", str(job), "--buflo-duration-policy",
                        budget.CADENCE64_1280_POLICY]) == 0
    assert calls == [{"sentinel": "same immutable job",
                      "buflo_duration_policy": budget.CADENCE64_1280_POLICY}]
    write(job, {"buflo_duration_policy": budget.CADENCE64_1280_POLICY})
    with pytest.raises(ValueError, match="immutable preparation job"):
        native.main(["_prepare", "--job", str(job)])
    assert len(calls) == 1
    with pytest.raises(SystemExit):
        native.main(["_capture", "--job", str(job), "--buflo-duration-policy",
                     budget.CADENCE64_1280_POLICY])
    output = tmp_path / "no-runtime-dns-or-GET"
    with pytest.raises(ValueError, match="unknown explicit"):
        rt.PreparationRuntime(tmp_path, {}).prepare({}, output, buflo_duration_policy="unknown")
    assert not output.exists()
    actual = cohorts._fresh_verifier_contract()
    qualified = helper.qualify_execution(actual)
    assert helper.EXECUTION_KIND == "132"
    assert actual == qualified.contract() and actual["transitive_source_files"] == 188
    historical069 = helper.prior_complete_fin069_execution_contract()
    historical070 = helper.prior_explicit_duration070_execution_contract()
    assert historical069["transitive_source_files"] == historical070["transitive_source_files"] == 171
    assert historical069 != historical070
    assert helper.prior_exact131_execution_contract()["transitive_source_files"] == 179
    for prior in (historical069, historical070, helper.prior_exact131_execution_contract()):
        assert helper.require_supported(prior, qualified) is True
        with pytest.raises(ValueError, match="unsupported or changed Source132"):
            helper.qualify_execution(prior)
