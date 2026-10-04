"""Synthetic public-output contract fixtures, never actual Native measurements."""
from __future__ import annotations

import copy
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_get as get

LAB = "9c35eafb0b02f73977849479d66810e15c16463f"
NATIVE = "5f075d37e9715dbd9e4648ee33bec7ee35ded070"
OLD_NATIVE = "8417787ce0da2d83a67b0b77dd6ef6a316611741"
REPOSITORY = Path(__file__).resolve().parents[1]


def write(path, value):
    path.write_bytes(graph.canonical_bytes(value))


def load(path):
    return json.loads(path.read_bytes())


def csv_bytes(fields, rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode()


def reseal_outputs(root):
    path = root / "native-completed.json"
    completed = load(path)
    completed["outputs"] = {name: graph.digest((root / "native" / name).read_bytes()) for name in get.FILES}
    write(path, completed)


@pytest.fixture
def actual_contract_fixture(tmp_path):
    # The fields follow exact Native5f emitters; every value is synthetic.
    root = tmp_path / "get-evidence"
    root.mkdir()
    (root / "native").mkdir()
    source = graph.canonical_bytes([{"crUX_domain": "sample.example", "resources": [
        {"resource_domain": "cdn.example", "resource_urls": ["https://cdn.example/a?q=exact", "https://cdn.example/b"]}]}])
    source_sha = graph.digest(source)
    manifest, input_binding = graph.import_graph(source, source_sha, "sample.example")
    source_metadata = {"image_digest": None, "lab_commit": LAB, "neqo_commit": NATIVE,
                       "neqo_pinned_commit": NATIVE, "lab_dirty": False, "neqo_dirty": False,
                       "lab_patch_sha256": get._EMPTY, "neqo_patch_sha256": get._EMPTY}
    source_text = graph.canonical_bytes(source_metadata).decode()
    binding = {"source_manifest_sha256": graph.digest(source_text.encode()), "lab_commit": LAB,
               "native_commit": NATIVE, "image_digest": "sha256:" + "d" * 64, "client_sha256": "c" * 64}
    files = qualification._implementation_source_files(REPOSITORY)
    implementation = {"schema_version": 2, "artifact_type": "qcsd-chaff-qualification-implementation",
                      "domain": qualification.IMPLEMENTATION_RECEIPT_DOMAIN, "source": source_metadata,
                      "source_files": files,
                      "installed_modules": {name: {"path": "/opt/qcsd-venv/lib/" + name, "sha256": files[name]}
                                            for name in qualification.IMPLEMENTATION_PYTHON_FILES},
                      "installed_entrypoint": {"path": "/usr/local/bin/qcsd-lab-internal", "sha256": files["qcsd-lab"]},
                      "neqo_qcsd_client": {"path": str(get.CLIENT), "sha256": binding["client_sha256"]}}
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    write(root / "runtime.json", {"source_manifest_text": source_text, "qualification_implementation": implementation})
    (root / "source-list.json").write_bytes(source)
    write(root / "native-input.json", manifest)
    write(root / "input-binding.json", input_binding)
    declaration = {"schema_version": 1, "record_type": get.PROOF_TYPE,
                   "declared_at": "2026-10-04T00:00:00+00:00", "source_sha256": source_sha, "domain": "sample.example",
                   "runtime_binding": binding, "producer_role": "external-declared-static-get-authority-v1",
                   "producer_sources": get.producer_sources(), "input_binding_sha256": graph.digest((root / "input-binding.json").read_bytes()),
                   "native_input_sha256": graph.digest((root / "native-input.json").read_bytes()),
                   "max_response_bytes": 1000, "timeout_seconds": 120,
                   "primary_claim": get.PRIMARY_CLAIM, "public_origin_policy": get.PUBLIC_POLICY,
                   "scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0}
    write(root / "declaration.json", declaration)
    origins = ["https://cdn.example", "https://sample.example"]
    write(root / "dns.json", {"schema_version": 1, "policy": get.PUBLIC_POLICY, "observations": [
        {"origin": origin, "started_at": "2026-10-04T00:00:00.100000+00:00",
         "completed_at": "2026-10-04T00:00:00.200000+00:00", "answers": ["1.1.1.1"]} for origin in origins]})
    write(root / "native-started.json", {"schema_version": 1, "command": get.native_command(root, 1000, 120),
          "environment": {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": binding["image_digest"],
                          "QCSD_LAB_SOURCE_METADATA": str(get.util.DEFAULT_SOURCE_METADATA)},
          "started_at": "2026-10-04T00:00:01+00:00", "declaration_sha256": graph.digest((root / "declaration.json").read_bytes()),
          "client_sha256": binding["client_sha256"]})
    start = get._unix_ns("2026-10-04T00:00:01.100000+00:00")
    run = {"neqo_version": "0.1.0", "neqo_base_commit": "a" * 40, "published_qcsd_commit": "b" * 40,
           "migration_commit": NATIVE, "method": "GET", "request_policy": "as-defined",
           "application_response_policy": get.RESPONSE_POLICY, "primary_document_identity_policy": "exact-response-body-v1",
           "seed": 0, "workload_hash_sha256": declaration["native_input_sha256"],
           "application_workload_source_hash_sha256": None, "chaff_manifest_hash_sha256": None,
           "chaff_responses": [], "defense_parameters": None, "max_response_bytes": 1000,
           "resolved_configuration": {"defense": {"kind": "none"}, "max_udp_payload_size": 1200},
           "incoming_udp_payload_limit": 65527, "outgoing_udp_payload_ceiling": 1200,
           "completion_status": "complete", "error": None, "error_class": None, "terminal_evidence_render_errors": [],
           "started_unix_ns": start, "time_anchor_unix_ns": start, "ended_unix_ns": start + 500_000_000,
           "endpoints": [], "responses": []}
    for index, origin in enumerate(origins):
        local = "10.0.0.2:" + str(45000 + index)
        run["endpoints"].append({"id": index, "origin": origin + "/", "local_address": local,
          "remote_address": "1.1.1.1:443", "tuple": {"protocol": "udp", "local": local, "remote": "1.1.1.1:443"},
          "negotiated_protocol": "h3", "transport_stats": "synthetic fixture", "receive_lifecycle": {
             "schema_version": 1, "source": "native-final-udp-receive-drain-v1",
             "time_basis": "runner-process-start-elapsed-monotonic-v1", "disposition": "drained_to_would_block",
             "polling_stopped_at_elapsed_ns": 490_000_000, "polling_stopped_at_unix_ns": start + 490_000_000,
             "scientific_credit": False}})
    events, seq, streams = [], 0, {0: 0, 1: 0}
    for resource in manifest["resources"]:
        resource_id = resource["id"]
        endpoint = origins.index(get._origin(resource["url"]))
        stream = streams[endpoint]
        streams[endpoint] += 4
        run["responses"].append({"resource_id": resource_id, "url": resource["url"],
            "request_headers": resource["headers"], "response_headers": [[":status", "200"], ["content-length", "5"]],
            "status": 200, "content_length": 5, "bytes": 5, "body_sha256": graph.digest(b"hello"),
            "request_stream_bytes": 50, "complete": True, "outcome": "succeeded"})
        events.append({"connection": str(endpoint), "event": "application_request", "outcome": "started",
                       "monotonic_us": "1000", "details": json.dumps(resource_id)})
        for detail in ({"type": "stream_opened", "endpoint": endpoint, "stream": stream, "role": "application"},
                       {"type": "stream_finished", "endpoint": endpoint, "stream": stream, "finish": "fin"},
                       {"type": "resource_completed", "resource_id": resource_id, "success": True}):
            seq += 1
            detail.update(production_sequence=seq, production_monotonic_ns=seq * 100_000)
            events.append({"connection": str(endpoint), "event": "observation", "outcome": "recorded",
                           "monotonic_us": str(seq * 100), "details": json.dumps(detail)})
    write(root / "native/run.json", run)
    (root / "native/events.csv").write_bytes(csv_bytes(["connection", "event", "outcome", "monotonic_us", "details"], events))
    packets = [{"connection": str(endpoint), "direction": direction, "observed_udp_length": "1200"}
               for endpoint in range(2) for direction in ("incoming", "outgoing")]
    (root / "native/packets.csv").write_bytes(csv_bytes(["connection", "direction", "observed_udp_length"], packets))
    (root / "native/schedule.csv").write_bytes(csv_bytes(["direction", "size", "satisfaction"], []))
    (root / "native.stdout.log").write_bytes(b"synthetic contract fixture\n")
    (root / "native.stderr.log").write_bytes(b"")
    write(root / "native-completed.json", {"schema_version": 1, "returncode": 0, "timed_out": False,
          "completed_at": "2026-10-04T00:00:02+00:00", "elapsed_ns": 1_000_000_000,
          "stdout_sha256": graph.digest((root / "native.stdout.log").read_bytes()), "stderr_sha256": get._EMPTY,
          "outputs": {}, "client_sha256": binding["client_sha256"], "source_manifest_sha256": binding["source_manifest_sha256"]})
    reseal_outputs(root)
    return root, {"expected_runtime": binding, "source_sha256": source_sha, "domain": "sample.example"}


def test_complete_exact_list_has_only_zero_credit_get_claim(actual_contract_fixture):
    root, arguments = actual_contract_fixture
    proof = get.build_proof(root, **arguments)
    assert proof["resource_count"] == 3 and proof["origin_count"] == 2
    assert proof["full_list_coverage"] is True
    assert proof["native"]["endpoint_completion"][0]["resource_ids"] == [1, 2]
    assert proof["native"]["endpoint_completion"][0]["fin_stream_ids"] == [0, 4]
    assert proof["primary_claim"] == get.PRIMARY_CLAIM
    assert not any(proof[key] for key in ("scientific_credit", "site_credit", "formal_accepted_trace_count",
                                        "challenge_absence_claim", "browser_discovery_claim", "body_contents_retained"))
    write(root / "full-get-proof.json", proof)
    assert get.validate_proof(root, **arguments) == proof


@pytest.mark.parametrize("mutation", [
    lambda run: run.update(migration_commit=OLD_NATIVE),
    lambda run: run.update(completion_status="error"),
    lambda run: run.update(terminal_evidence_render_errors=["failed output"]),
    lambda run: run["responses"].pop(),
    lambda run: run["responses"][1].update(resource_id=0),
    lambda run: run["responses"][1].update(url="https://wrong.example/a"),
    lambda run: run["responses"][1].update(complete=False),
    lambda run: run["responses"][1].update(outcome="response_limit"),
    lambda run: run["responses"][1].update(content_length=6),
    lambda run: run["responses"][1].update(bytes=1001),
    lambda run: run["responses"][1].update(bytes=True),
    lambda run: run["responses"][0].update(bytes=0, content_length=0, body_sha256=get._EMPTY),
    lambda run: run["responses"][0].update(status=403, response_headers=[[":status", "403"]]),
    lambda run: run["responses"][1].update(status=302, response_headers=[[":status", "302"]]),
    lambda run: run["responses"][1].update(body_sha256="invalid"),
    lambda run: run["endpoints"][0].update(origin="https://wrong.example/"),
    lambda run: run["endpoints"][0].update(negotiated_protocol="h2"),
    lambda run: run["endpoints"][0].update(remote_address="127.0.0.1:443"),
    lambda run: run["endpoints"][0]["receive_lifecycle"].update(polling_stopped_at_elapsed_ns=None),
    lambda run: run.update(started_unix_ns=0),
])
def test_resealed_incomplete_or_wrong_native_outputs_reject(actual_contract_fixture, mutation):
    root, arguments = actual_contract_fixture
    run = load(root / "native/run.json")
    mutation(run)
    write(root / "native/run.json", run)
    reseal_outputs(root)
    with pytest.raises(ValueError):
        get.build_proof(root, **arguments)


def test_complete_auxiliary_http_error_retained_without_pruning(actual_contract_fixture):
    root, arguments = actual_contract_fixture
    run = load(root / "native/run.json")
    run["responses"][1].update(status=404, response_headers=[[":status", "404"], ["content-length", "5"]])
    write(root / "native/run.json", run)
    reseal_outputs(root)
    proof = get.build_proof(root, **arguments)
    assert len(proof["native"]["responses"]) == 3
    assert proof["native"]["responses"][1]["status"] == 404


@pytest.mark.parametrize("change", ["missing_fin", "reset", "wrong_endpoint", "duplicate_fin", "missing_completion", "false_completion", "wrong_request_id", "duplicate_sequence"])
def test_raw_stream_and_resource_completion_required(actual_contract_fixture, change):
    root, arguments = actual_contract_fixture
    path = root / "native/events.csv"
    rows = list(csv.DictReader(io.StringIO(path.read_text())))
    fin_index = next(index for index, row in enumerate(rows) if '"stream_finished"' in row["details"])
    completion_index = next(index for index, row in enumerate(rows) if '"resource_completed"' in row["details"])
    if change == "missing_fin":
        rows.pop(fin_index)
    elif change == "missing_completion":
        rows.pop(completion_index)
    elif change == "wrong_request_id":
        rows[0]["details"] = "999"
    elif change == "duplicate_fin":
        rows.append(copy.deepcopy(rows[fin_index]))
        detail = json.loads(rows[-1]["details"])
        detail["production_sequence"] = 99
        rows[-1]["details"] = json.dumps(detail)
    else:
        index = completion_index if change == "false_completion" else fin_index
        detail = json.loads(rows[index]["details"])
        if change == "reset": detail["finish"] = "reset"
        if change == "wrong_endpoint": detail["endpoint"] = 0
        if change == "false_completion": detail["success"] = False
        if change == "duplicate_sequence": detail["production_sequence"] = 1
        rows[index]["details"] = json.dumps(detail)
    path.write_bytes(csv_bytes(list(rows[0]), rows))
    reseal_outputs(root)
    with pytest.raises(ValueError): get.build_proof(root, **arguments)


@pytest.mark.parametrize("file,field,value", [
    ("native-completed.json", "returncode", True),
    ("native-completed.json", "returncode", 1),
    ("native-completed.json", "timed_out", True),
    ("native-completed.json", "client_sha256", "a" * 64),
    ("native-completed.json", "stdout_sha256", "a" * 64),
    ("native-started.json", "environment", {}),
    ("native-started.json", "started_at", "2026-10-03T00:00:00+00:00"),
    ("declaration.json", "scientific_credit", True),
    ("declaration.json", "producer_sources", {}),
])
def test_actual_process_source_and_chronology_not_summary_flags(actual_contract_fixture, file, field, value):
    root, arguments = actual_contract_fixture
    data = load(root / file)
    data[field] = value
    write(root / file, data)
    with pytest.raises(ValueError): get.build_proof(root, **arguments)


def test_exit_zero_without_actual_native_artifacts_rejects(actual_contract_fixture):
    root, arguments = actual_contract_fixture
    (root / "native/run.json").unlink()
    with pytest.raises(ValueError): get.build_proof(root, **arguments)


def test_dns_unsafe_wrong_origin_and_late_observation_reject(actual_contract_fixture):
    root, arguments = actual_contract_fixture
    original = load(root / "dns.json")
    for field, value in (("origin", "https://wrong.example"), ("answers", ["10.0.0.1"]),
                         ("completed_at", "2026-10-04T00:00:03+00:00")):
        data = copy.deepcopy(original)
        data["observations"][0][field] = value
        write(root / "dns.json", data)
        with pytest.raises(ValueError): get.build_proof(root, **arguments)


def test_pruned_graph_resealed_binding_cannot_replace_original_list(actual_contract_fixture):
    root, arguments = actual_contract_fixture
    manifest = load(root / "native-input.json")
    manifest["resources"].pop()
    write(root / "native-input.json", manifest)
    binding = load(root / "input-binding.json")
    binding["native_manifest_sha256"] = graph.digest(graph.canonical_bytes(manifest))
    write(root / "input-binding.json", binding)
    with pytest.raises(ValueError, match="complete supplied list"): get.build_proof(root, **arguments)


def test_unknown_body_and_browser_claim_cannot_be_added_to_summary(actual_contract_fixture):
    root, arguments = actual_contract_fixture
    proof = get.build_proof(root, **arguments)
    proof.update(challenge_absence_claim=True)
    write(root / "full-get-proof.json", proof)
    with pytest.raises(ValueError, match="summary differs"): get.validate_proof(root, **arguments)


def test_unshimmed_public_cli_help_executes_no_native():
    result = subprocess.run([sys.executable, "-I", "-B", str(REPOSITORY / "tools/supplied_static_get.py"), "execute", "--help"],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "--runtime-binding" in result.stdout and "--input-root" in result.stdout


def test_native_argv_preserves_full_graph_and_public_existing_policies(tmp_path):
    command = get.native_command(tmp_path, 10000, 15)
    assert command[0] == "/usr/local/bin/neqo-qcsd-client"
    assert command[command.index("--workload") + 1] == str(tmp_path / "native-input.json")
    assert "--application-workload-source" not in command and "--chaff-manifest" not in command
    assert command[command.index("--application-response-policy") + 1] == get.RESPONSE_POLICY
    assert command[command.index("--defense") + 1] == "none"


def test_retained_prior_native_run_cannot_be_promoted(actual_contract_fixture):
    reference = os.environ.get("QCSD_STATIC_GET_PRIOR_RUN")
    if not reference:
        pytest.skip("optional retained prior-source rejection oracle not supplied")
    root, arguments = actual_contract_fixture
    prior = load(Path(reference))
    assert prior["migration_commit"] == OLD_NATIVE
    with pytest.raises(ValueError, match="Native source is not the expected commit"):
        get._run_proof(prior, root, load(root / "declaration.json"), load(root / "native-started.json"),
                       load(root / "native-completed.json"), load(root / "native-input.json"), load(root / "dns.json"))


def test_public_execute_rejects_uninstalled_host_before_allocating_output(actual_contract_fixture, monkeypatch):
    root, arguments = actual_contract_fixture
    monkeypatch.delenv("QCSD_LAB_IMAGE_DIGEST", raising=False)
    destination = root.parent / "never-created"
    with pytest.raises(ValueError, match="exact declared installed image"):
        get.execute_full_get(root / "source-list.json", root, destination, **arguments)
    assert not destination.exists()


def test_duplicate_runtime_binding_is_rejected_before_any_execution(tmp_path):
    path = tmp_path / "binding.json"
    path.write_text('{"lab_commit":"first","lab_commit":"second"}')
    result = subprocess.run([sys.executable, "-I", "-B", str(REPOSITORY / "tools/supplied_static_get.py"), "execute",
         "--runtime-binding", str(path), "--source-sha256", "a" * 64, "--domain", "sample.example",
         "--source", str(tmp_path / "absent.json"), "--input-root", str(tmp_path / "absent"),
         "--output-root", str(tmp_path / "never-created")], capture_output=True, text=True, check=False)
    assert result.returncode != 0 and "duplicate key" in result.stderr
    assert not (tmp_path / "never-created").exists()
