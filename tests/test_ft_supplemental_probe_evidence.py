"""Synthetic metadata counterexamples only; no HTTP, Native run or credit.

These fixtures exercise the actual pure/read-only proof consumer. They are
not qualification evidence and must never enter a study enrollment.
"""
import json

import pytest

from qcsd_lab import ft_supplemental_chaff as ft
from qcsd_lab import resource_study_native as native


def put(path, value, *, raw=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if raw else (json.dumps(value, sort_keys=True) + "\n").encode())
    path.chmod(0o644)


def fixture(tmp_path, *, status=200, body_bytes=4096):
    root = tmp_path / "synthetic-noncredit"
    directory = root / "probes" / str(ft.ID_MIN)
    resource = {"id": ft.ID_MIN, "url": "https://example.test/padding.woff2", "type": "Other",
        "content_length": None, "data_length": 0, "chaff_priority": False,
        "known_valid": False, "depends_on": [], "headers": [["accept", "*/*"],
            ["accept-encoding", "identity"], ["accept-language", "en-US,en;q=0.9"]]}
    runtime = {"client_sha256": "a" * 64, "native_commit": "1" * 40}
    client = "/synthetic-noncredit/neqo-qcsd-client"
    put(directory / "input.json", {"resources": [resource]})
    command = native.probe_command(client, directory / "input.json", directory / "native",
                                   timeout=120, max_response_bytes=ft.MAX_BODY)
    put(directory / "stdout.txt", b"", raw=True)
    put(directory / "stderr.txt", b"", raw=True)
    put(directory / "started.json", {"schema_version": 1, "argv": command,
        "started_unix_ns": 100, "client_sha256": runtime["client_sha256"]})
    put(directory / "completed.json", {"schema_version": 1, "argv": command,
        "completed_unix_ns": 1000, "client_sha256": runtime["client_sha256"],
        "returncode": 0, "timed_out": False, "client_unchanged": True, "error": None,
        "stdout_sha256": ft.digest(b""), "stderr_sha256": ft.digest(b"")})
    response = {"resource_id": ft.ID_MIN, "url": resource["url"], "request_headers": resource["headers"],
        "response_headers": [[":status", str(status)], ["content-length", str(body_bytes)]],
        "status": status, "content_length": body_bytes, "bytes": body_bytes,
        "body_sha256": ft.digest(b"x" * body_bytes), "request_stream_bytes": 96,
        "complete": True, "outcome": "succeeded" if 200 <= status < 300 else "failed"}
    run = {"method": "GET", "request_policy": "as-defined", "seed": 0,
        "workload_hash_sha256": ft.digest((directory / "input.json").read_bytes()),
        "max_response_bytes": ft.MAX_BODY, "migration_commit": runtime["native_commit"],
        "resolved_configuration": {"defense": {"kind": "none"}},
        "application_response_policy": "http-2xx-only-v1", "application_workload_source_hash_sha256": None,
        "chaff_manifest_hash_sha256": None, "chaff_responses": [], "terminal_evidence_render_errors": [],
        "completion_status": "complete", "error": None, "error_class": None,
        "started_unix_ns": 200, "ended_unix_ns": 900,
        "endpoints": [{"id": 0, "origin": "https://example.test", "negotiated_protocol": "h3"}],
        "responses": [response]}
    put(directory / "native/run.json", run)
    return root, directory, client, runtime, resource, run


def test_complete_working_probe_cannot_be_hidden_behind_a_failure_label(tmp_path):
    root, directory, client, runtime, resource, _ = fixture(tmp_path)
    assessment = ft._assess_probe(directory, root, client, runtime, resource, ft.read)
    assert assessment["working"] is True
    assert assessment["response"]["bytes"] == 4096
    # The full consumer requires identity with this independently observed
    # value. A false recorded label cannot exclude the larger successful GET.
    assert False is not assessment["working"]


def test_only_complete_actual_http_failure_can_be_ineligible(tmp_path):
    root, directory, client, runtime, resource, run = fixture(tmp_path, status=404)
    assessment = ft._assess_probe(directory, root, client, runtime, resource, ft.read)
    assert assessment["working"] is False
    assert assessment["failure_class"] == "complete-http-non2xx-v1"
    run["responses"][0]["complete"] = False
    put(directory / "native/run.json", run)
    with pytest.raises(ValueError):
        ft._assess_probe(directory, root, client, runtime, resource, ft.read)


def test_native_probe_timestamps_must_join_original_process(tmp_path):
    root, directory, client, runtime, resource, run = fixture(tmp_path)
    run["started_unix_ns"] = 99
    put(directory / "native/run.json", run)
    with pytest.raises(ValueError, match="process interval"):
        ft._assess_probe(directory, root, client, runtime, resource, ft.read)


def test_undeclared_original_proof_file_is_not_a_valid_handoff(tmp_path):
    root, directory, *_ = fixture(tmp_path)
    files = {p.relative_to(tmp_path).as_posix(): ft.digest(p.read_bytes())
             for p in root.rglob("*") if p.is_file()}
    removed = (directory / "native/run.json").relative_to(tmp_path).as_posix()
    files.pop(removed)
    with pytest.raises(ValueError, match="omitted"):
        ft._inventory_reader(tmp_path, root, files)
