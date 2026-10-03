"""Ordinary sealed-result replay; only the TShark subprocess is substituted.

PCAP bytes, exact tuple extraction, canonical six-column rendering, Native
reconciliation, clock checks, accepted artifact hashes and final seals are real.
These tests establish no installed-runtime TShark or live capture authority.
"""
from __future__ import annotations

import csv
import io
import json
import os
import socket
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import dpkt
import pytest

from qcsd_lab import capture, verification
from qcsd_lab.experiment import checkpoint_experiment
from qcsd_lab.fidelity import reconcile_direct_runner_artifacts
from qcsd_lab.util import atomic_json, sha256_file
from tests.test_endpoint_receive_tail import artifacts
from tests.test_verification import _make_result


def _write_pcap(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        for row in rows:
            local_port = 50000 + int(row["connection"])
            outgoing = row["direction"] == "outgoing"
            udp = dpkt.udp.UDP(sport=local_port if outgoing else 443,
                               dport=443 if outgoing else local_port,
                               data=b"x" * (int(row["length_bytes"]) - 42))
            udp.ulen = len(udp)
            packet = dpkt.ip.IP(src=socket.inet_aton("10.0.0.2" if outgoing else "203.0.113.1"),
                                dst=socket.inet_aton("203.0.113.1" if outgoing else "10.0.0.2"),
                                p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
            packet.len = len(packet)
            frame = bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6,
                                                type=dpkt.ethernet.ETH_TYPE_IP, data=packet))
            writer.writepkt(frame, ts=int(row["timestamp_unix_ns"]) / 1_000_000_000)


def _tshark(command, **kwargs):
    """Read actual fixture Ethernet/IP/UDP bytes at the external tool boundary."""
    assert command[0] == "tshark"
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    with Path(command[command.index("-r") + 1]).open("rb") as source:
        for timestamp, raw in dpkt.pcap.Reader(source):
            frame = dpkt.ethernet.Ethernet(raw)
            packet, udp = frame.data, frame.data.data
            writer.writerow([f"{timestamp:.9f}", len(raw), udp.ulen,
                             socket.inet_ntoa(packet.src), "", socket.inet_ntoa(packet.dst), "",
                             udp.sport, udp.dport])
    return subprocess.CompletedProcess(command, 0, output.getvalue(), "")


def _seal(root: Path, experiment: dict) -> None:
    seal = root / "evidence.sha256"
    if seal.exists():
        seal.unlink()  # A test corrupts and coherently reseals its own fixture.
    for sample in experiment["samples"]:
        if sample["state"] == "accepted":
            for relative in sample["artifacts"]:
                sample["artifacts"][relative] = sha256_file(root / relative)
    checkpoint_experiment(root, experiment)
    verification.seal_result(root)


@pytest.fixture
def prospective(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "run", _tshark)
    monkeypatch.setattr(verification.shutil, "which", lambda program: "/fixture/tshark" if program == "tshark" else None)
    root, experiment = _make_result(tmp_path, complete=True)
    golden = tmp_path / "native-golden"
    golden.mkdir()
    run_path, packets_path, direct_path, anchors = artifacts(golden)
    rows = list(csv.DictReader(direct_path.open()))
    sample = experiment["samples"][0]
    directory = root / sample["path"]
    (directory / "neqo/run.json").write_bytes(run_path.read_bytes())
    (directory / "neqo/packets.csv").write_bytes(packets_path.read_bytes())
    _write_pcap(directory / "capture.pcapng", rows)
    result = reconcile_direct_runner_artifacts(run_path, packets_path, direct_path, clock_anchors=anchors)
    sample["diagnostics"]["capture"] = {
        "primary": True, "valid": True, "timestamp_type": "host",
        "capture_path": "capture.pcapng", "capture_sha256": sha256_file(directory / "capture.pcapng"),
        "packet_count": len(rows), "capture_clock_anchors": anchors,
        "direct_runner_reconciliation": {
            **result.metrics, "evidence_eligible": result.evidence_eligible,
            "limitations": list(result.limitations),
        },
    }
    _seal(root, experiment)
    return root, experiment, directory, rows


def test_verify_result_replays_sealed_pcap_without_mutating_evidence(prospective, monkeypatch):
    root, experiment, directory, rows = prospective
    before = {name: path.read_bytes() for name, path in verification.authoritative_files(root).items()}
    before["evidence.sha256"] = (root / "evidence.sha256").read_bytes()
    observed = []
    original = capture.write_normalized_trace
    def write(path, trace):
        observed.append(path)
        assert not path.is_relative_to(root)
        original(path, trace)
        assert path.read_text().splitlines()[0] == (
            "relative_time_ns,direction,length_bytes,signed_length_bytes,connection,timestamp_unix_ns")
    monkeypatch.setattr(capture, "write_normalized_trace", write)
    checked = verification.verify_result(root)
    assert len(checked.accepted_samples) == 1
    assert len(observed) == 1 and not observed[0].exists()
    assert before == {name: (root / name).read_bytes() for name in before}


@pytest.mark.parametrize("field", ["direct_matched_packets", "direct_endpoint_receive_tail_packets",
                                  "direct_trace_sha256", "direct_runner_packets_sha256", "limitations",
                                  "extra-key", "evidence_eligible", "direct_timestamp_tolerance_ns"])
def test_verify_rejects_coherently_resealed_reconciliation_metrics(prospective, field):
    root, experiment, _, _ = prospective
    recorded = experiment["samples"][0]["diagnostics"]["capture"]["direct_runner_reconciliation"]
    if field.endswith("sha256"):
        recorded[field] = "0" * 64
    elif field == "limitations":
        recorded[field] = []
    elif field == "extra-key":
        recorded[field] = "unbound"
    elif field == "evidence_eligible":
        recorded[field] = False
    elif field == "direct_timestamp_tolerance_ns":
        recorded[field] = 100_000_000
    else:
        recorded[field] += 1
    _seal(root, experiment)
    with pytest.raises(ValueError):
        verification.verify_result(root)


@pytest.mark.parametrize("damage", ["capture_path", "capture_sha256", "packet_count", "clock_anchors",
                                   "reconciliation", "primary", "valid", "timestamp_type"])
def test_verify_rejects_resealed_missing_or_substituted_capture_bindings(prospective, damage):
    root, experiment, _, _ = prospective
    record = experiment["samples"][0]["diagnostics"]["capture"]
    if damage == "capture_path":
        record[damage] = "../other.pcapng"
    elif damage == "capture_sha256":
        record[damage] = "0" * 64
    elif damage == "packet_count":
        record[damage] = True
    elif damage == "clock_anchors":
        record.pop("capture_clock_anchors")
    elif damage == "reconciliation":
        record.pop("direct_runner_reconciliation")
    elif damage == "timestamp_type":
        record[damage] = "adapter"
    else:
        record[damage] = False
    _seal(root, experiment)
    with pytest.raises(ValueError):
        verification.verify_result(root)


@pytest.mark.parametrize("marker", ["native_lifecycle", "recorded_policy"])
def test_removing_either_prospective_marker_cannot_disable_replay(prospective, marker):
    root, experiment, directory, _ = prospective
    if marker == "native_lifecycle":
        run_path = directory / "neqo/run.json"
        run = json.loads(run_path.read_bytes())
        for endpoint in run["endpoints"]:
            endpoint.pop("receive_lifecycle")
        atomic_json(run_path, run)
    else:
        experiment["samples"][0]["diagnostics"]["capture"]["direct_runner_reconciliation"].pop("direct_tail_policy")
    _seal(root, experiment)
    with pytest.raises(ValueError):
        verification.verify_result(root)


def test_new_global_policy_alone_still_requires_independent_replay(prospective, tmp_path):
    root, experiment, directory, rows = prospective
    run_path = directory / "neqo/run.json"
    run = json.loads(run_path.read_bytes())
    for endpoint in run["endpoints"]:
        endpoint.pop("receive_lifecycle")
    atomic_json(run_path, run)
    rows = [row for row in rows if row["length_bytes"] != "74"]
    _write_pcap(directory / "capture.pcapng", rows)
    direct = tmp_path / "global-direct.csv"
    capture.write_normalized_trace(direct, capture.extract_trace(directory / "capture.pcapng", run["endpoints"]))
    record = experiment["samples"][0]["diagnostics"]["capture"]
    reconciled = reconcile_direct_runner_artifacts(run_path, directory / "neqo/packets.csv", direct,
                                                 clock_anchors=record["capture_clock_anchors"])
    record.update(capture_sha256=sha256_file(directory / "capture.pcapng"), packet_count=len(rows))
    record["direct_runner_reconciliation"] = {
        **reconciled.metrics, "evidence_eligible": reconciled.evidence_eligible,
        "limitations": list(reconciled.limitations),
    }
    assert record["direct_runner_reconciliation"]["direct_tail_policy"] == "global-last-match-v1"
    _seal(root, experiment)
    verification.verify_result(root)
    record["direct_runner_reconciliation"]["direct_matched_packets"] += 1
    _seal(root, experiment)
    with pytest.raises(ValueError, match="recorded reconciliation metrics"):
        verification.verify_result(root)


@pytest.mark.parametrize("damage", ["missing_packet", "outgoing_tail", "unknown_tuple", "timestamp", "endpoint_id"])
def test_resealed_pcap_and_native_corruption_is_independently_rederived(prospective, damage):
    root, experiment, directory, rows = prospective
    if damage == "missing_packet":
        del rows[1]
    elif damage == "outgoing_tail":
        rows[3]["direction"] = "outgoing"
    elif damage == "unknown_tuple":
        rows[3]["connection"] = "9"
    elif damage == "timestamp":
        rows[3]["timestamp_unix_ns"] = "1002499999"
    else:
        run_path = directory / "neqo/run.json"
        run = json.loads(run_path.read_bytes())
        run["endpoints"][0]["id"] = 9
        atomic_json(run_path, run)
    _write_pcap(directory / "capture.pcapng", rows)
    record = experiment["samples"][0]["diagnostics"]["capture"]
    record["capture_sha256"] = sha256_file(directory / "capture.pcapng")
    record["packet_count"] = len(rows)
    _seal(root, experiment)
    with pytest.raises(ValueError):
        verification.verify_result(root)


def test_legacy_sealed_result_without_prospective_markers_keeps_existing_semantics(tmp_path, monkeypatch):
    root, experiment = _make_result(tmp_path, complete=True)
    verification.seal_result(root)
    def no_replay(*args, **kwargs):
        raise AssertionError("historical four-column evidence must not gain a new replay gate")
    monkeypatch.setattr(capture, "extract_trace", no_replay)
    assert len(verification.verify_result(root).accepted_samples) == 1


@pytest.mark.parametrize("change", ["matching", "baseline", "missing-marker", "missing-source",
                                    "unknown-source", "wrong-window", "boolean-schema", "wrong-kind"])
def test_frozen_accepted_workload_reopens_buflo_source_binding(tmp_path, change):
    from qcsd_lab.capture_acceptance_policy import FIELD, POLICY
    from tests.test_primary_document_identity_policy import variable_workload

    prepared, runs = variable_workload()
    run = runs[0]
    prepared["preparation"][FIELD] = POLICY
    run.update(primary_document_identity_policy="variable-primary-document-body-v1",
               defense_parameters={"kind": "buflo"}, **{FIELD: {
                   "schema_version": 1, "source": "bound-preparation-v1", "policy": POLICY,
                   "incoming_release_window_us": 10_000, "period_us": 20_000,
                   "cell_bytes": 1_200, "scientific_credit": False,
               }})
    if change == "baseline":
        run["defense_parameters"] = {"kind": "none"}
        run.pop(FIELD)
    elif change == "missing-marker":
        run.pop(FIELD)
    elif change == "missing-source":
        prepared["preparation"].pop(FIELD)
    elif change == "unknown-source":
        prepared["preparation"][FIELD] = "unbound-policy"
    elif change == "wrong-window":
        run[FIELD]["incoming_release_window_us"] = 20_000
    elif change == "boolean-schema":
        run[FIELD]["schema_version"] = True
    elif change == "wrong-kind":
        run["defense_parameters"]["kind"] = "tamaraw"
    prepared_path = tmp_path / "inputs/workloads/page.json"
    atomic_json(prepared_path, prepared)
    atomic_json(tmp_path / "samples/one/neqo/run.json", run)
    experiment = {
        "configuration": {"workloads": [{"id": "page", "manifest": "inputs/workloads/page.json",
                                           "sha256": sha256_file(prepared_path)}]},
        "samples": [{"state": "accepted", "workload_id": "page", "path": "samples/one"}],
    }
    if change in {"matching", "baseline"}:
        verification._validate_policy_application_responses(tmp_path, experiment)
    else:
        with pytest.raises(ValueError, match="BufLO"):
            verification._validate_policy_application_responses(tmp_path, experiment)


def test_legacy_prepared_source_cannot_hide_an_unbound_native_buflo_marker(tmp_path):
    from qcsd_lab.capture_acceptance_policy import FIELD

    prepared_path = tmp_path / "inputs/workloads/page.json"
    atomic_json(prepared_path, {"resources": []})
    atomic_json(tmp_path / "samples/one/neqo/run.json", {FIELD: None})
    experiment = {
        "configuration": {"workloads": [{"id": "page", "manifest": "inputs/workloads/page.json",
                                           "sha256": sha256_file(prepared_path)}]},
        "samples": [{"state": "accepted", "workload_id": "page", "path": "samples/one"}],
    }
    with pytest.raises(ValueError, match="matching prepared source"):
        verification._validate_policy_application_responses(tmp_path, experiment)


def _transport_status(command, sample_ids):
    script_index = command.index("-c")
    assert command[script_index + 1] == verification._ENDPOINT_REPLAY_SCRIPT
    root, source, image, source_hash = command[script_index + 2:]
    return {"schema_version": 1, "valid": True, "tool_image_digest": image, "root": root,
            "verifier_source": str(Path(source) / "qcsd_lab/verification.py"),
            "verifier_sha256": source_hash, "sample_ids": sample_ids}


def test_missing_host_tshark_replays_entire_result_in_one_read_only_tool_container(prospective, monkeypatch):
    root, experiment, directory, _ = prospective
    experiment["source"]["image_digest"] = "sha256:" + "a" * 64
    second = deepcopy(experiment["samples"][0])
    second.update(sample_id="second-accepted-sample", path="samples/second")
    verification.shutil.copytree(directory, root / second["path"])
    experiment["samples"].append(second)
    monkeypatch.setattr(verification.shutil, "which", lambda _: None)
    commands = []
    def docker(command, **kwargs):
        commands.append(command)
        assert kwargs == {"cwd": root.resolve()}
        return subprocess.CompletedProcess(command, 0, json.dumps(_transport_status(
            command, [sample["sample_id"] for sample in experiment["samples"]])), "")
    monkeypatch.setattr(verification, "run", docker)
    verification._validate_endpoint_capture_replay(root, experiment)
    assert len(commands) == 1
    command = commands[0]
    assert command[:10] == ["docker", "run", "--rm", "--network", "none", "--read-only",
                           "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    assert command[command.index("--tmpfs") + 1] == "/tmp:rw,nosuid,nodev,noexec"
    assert command[command.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    source = Path(verification.__file__).resolve().parent.parent
    mounts = [command[index + 1] for index, value in enumerate(command) if value == "--volume"]
    assert mounts == [f"{root.resolve()}:{root.resolve()}:ro", f"{source}:{source}:ro"]
    entrypoint = command.index("--entrypoint")
    assert command[entrypoint + 1:entrypoint + 5] == ["/opt/qcsd-venv/bin/python3",
                                                    experiment["source"]["image_digest"], "-I", "-B"]
    assert "--env" not in command
    assert "sys.path.insert(0, str(source))" in command[command.index("-c") + 1]
    assert "verification.__file__" in command[command.index("-c") + 1]


@pytest.mark.parametrize("image", [None, "sha256:bad", "lab:latest", "repository@sha256:" + "a" * 64])
def test_tool_transport_rejects_absent_or_floating_source_image(prospective, monkeypatch, image):
    root, experiment, _, _ = prospective
    experiment["source"]["image_digest"] = image
    monkeypatch.setattr(verification.shutil, "which", lambda _: None)
    def no_docker(*args, **kwargs):
        raise AssertionError("invalid source image must fail before Docker")
    monkeypatch.setattr(verification, "run", no_docker)
    with pytest.raises(ValueError, match="immutable source image digest"):
        verification._validate_endpoint_capture_replay(root, experiment)


@pytest.mark.parametrize("damage", ["wrong-image", "wrong-source", "wrong-hash", "missing-sample",
                                   "extra-field", "boolean-schema", "nonzero", "invalid-json"])
def test_tool_transport_rejects_unchecked_or_substituted_status(prospective, monkeypatch, damage):
    root, experiment, _, _ = prospective
    experiment["source"]["image_digest"] = "sha256:" + "a" * 64
    monkeypatch.setattr(verification.shutil, "which", lambda _: None)
    def docker(command, **kwargs):
        result = _transport_status(command, [experiment["samples"][0]["sample_id"]])
        if damage == "wrong-image":
            result["tool_image_digest"] = "sha256:" + "b" * 64
        elif damage == "wrong-source":
            result["verifier_source"] = "/opt/installed/qcsd_lab/verification.py"
        elif damage == "wrong-hash":
            result["verifier_sha256"] = "0" * 64
        elif damage == "missing-sample":
            result["sample_ids"] = []
        elif damage == "extra-field":
            result["unbound"] = True
        elif damage == "boolean-schema":
            result["schema_version"] = True
        return subprocess.CompletedProcess(command, int(damage == "nonzero"),
                                           "unchecked" if damage == "invalid-json" else json.dumps(result), "")
    monkeypatch.setattr(verification, "run", docker)
    with pytest.raises(ValueError, match="endpoint replay tool transport"):
        verification._validate_endpoint_capture_replay(root, experiment)


def test_tool_transport_propagates_docker_and_replay_failure(prospective, monkeypatch):
    root, experiment, _, _ = prospective
    experiment["source"]["image_digest"] = "sha256:" + "a" * 64
    monkeypatch.setattr(verification.shutil, "which", lambda _: None)
    def fail(*args, **kwargs):
        raise RuntimeError("Docker replay rejected Native endpoint receipts")
    monkeypatch.setattr(verification, "run", fail)
    with pytest.raises(RuntimeError, match="rejected Native"):
        verification._validate_endpoint_capture_replay(root, experiment)


@pytest.mark.parametrize("damage", [None, "source-hash", "tool-image"])
def test_tool_script_imports_explicit_current_source_and_checks_bindings(tmp_path, damage):
    root, experiment = _make_result(tmp_path, complete=True)
    image = "sha256:" + "a" * 64
    experiment["source"]["image_digest"] = image
    atomic_json(root / "experiment.json", experiment)
    verifier = Path(verification.__file__).resolve()
    source = verifier.parent.parent
    result = subprocess.run([sys.executable, "-I", "-B", "-c", verification._ENDPOINT_REPLAY_SCRIPT,
                             str(root.resolve()), str(source),
                             "sha256:" + "b" * 64 if damage == "tool-image" else image,
                             "0" * 64 if damage == "source-hash" else sha256_file(verifier)],
                            cwd=tmp_path, text=True, capture_output=True, check=False)
    if damage is not None:
        assert result.returncode != 0
        assert "bytes changed" in result.stderr if damage == "source-hash" else "sealed runtime source" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        checked = json.loads(result.stdout)
        assert checked["verifier_source"] == str(verifier)
        assert checked["verifier_sha256"] == sha256_file(verifier)
        assert checked["sample_ids"] == []
