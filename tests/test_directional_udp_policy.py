"""Directional UDP evidence and historical receipt compatibility.

These are synthetic host fixtures; they do not qualify a live endpoint.
"""

from __future__ import annotations

import copy
import csv
import io
import socket
from pathlib import Path
from types import SimpleNamespace

import dpkt
import pytest

from qcsd_lab import capture as capture_module
from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import fitting as fitting_module
from qcsd_lab.capture import ObserverPacket, extract_trace, udp_ceiling_evidence
from qcsd_lab.capture_session import _runner_directional_udp_policy
from qcsd_lab.fitting_morphing import fit_traffic_morphing
from qcsd_lab.fitting_trace import load_fitting_trace
from qcsd_lab.util import load_json, sha256_file
from tests import test_chaff_qualification as chaff_fixture
from tests.test_fitting_bundle import _write_fitting_trace
from tests.test_trace import packet


def test_capture_evidence_keeps_legacy_limit_and_records_directional_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = tmp_path / "directional.pcap"
    with capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        writer.writepkt(packet("172.17.0.2", "203.0.113.1", 50000, 443, b"o" * 1_200), ts=1.0)
        writer.writepkt(packet("203.0.113.1", "172.17.0.2", 443, 50000, b"i" * 1_452), ts=1.1)

    def tshark_boundary(command: list[str]) -> SimpleNamespace:
        assert command[0] == "tshark"
        output = io.StringIO()
        rows = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
        with capture.open("rb") as source:
            for timestamp, frame in dpkt.pcap.Reader(source):
                ip = dpkt.ethernet.Ethernet(frame).data
                udp = ip.data
                rows.writerow(
                    [
                        f"{timestamp:.9f}",
                        len(frame),
                        udp.ulen,
                        socket.inet_ntoa(ip.src),
                        "",
                        socket.inet_ntoa(ip.dst),
                        "",
                        udp.sport,
                        udp.dport,
                    ]
                )
        return SimpleNamespace(stdout=output.getvalue())

    monkeypatch.setattr(capture_module, "run", tshark_boundary)
    trace = extract_trace(
        capture,
        [{"local_address": "172.17.0.2:50000", "remote_address": "203.0.113.1:443"}],
    )
    assert [(row.direction, row.udp_payload_len) for row in trace] == [
        ("outgoing", 1_200),
        ("incoming", 1_452),
    ]
    assert udp_ceiling_evidence(trace, 1_200)["valid"] is False
    evidence = udp_ceiling_evidence(trace, 1_200, incoming_limit=65_527)
    assert evidence["valid"] is True
    assert evidence["outgoing_udp_payload_ceiling"] == 1_200
    assert evidence["incoming_udp_payload_limit"] == 65_527
    assert evidence["incoming_observed_udp_payload_max"] == 1_452
    assert evidence["outgoing_observed_udp_payload_max"] == 1_200
    assert evidence["incoming_oversized_udp_payload_packets"] == 0
    assert evidence["outgoing_oversized_udp_payload_packets"] == 0
    trace[0] = ObserverPacket(1, 0, "outgoing", 1_243, 1_243, 1_201)
    assert udp_ceiling_evidence(trace, 1_200, incoming_limit=65_527)["valid"] is False


def test_runner_udp_policy_dispatch_rejects_partial_and_tampered_receipts() -> None:
    assert _runner_directional_udp_policy({}, 1_200) == (False, None, None, True)
    assert _runner_directional_udp_policy(
        {"incoming_udp_payload_limit": 65_527, "outgoing_udp_payload_ceiling": 1_200},
        1_200,
    ) == (True, 65_527, 1_200, True)
    for invalid in (
        {"incoming_udp_payload_limit": 65_527},
        {"incoming_udp_payload_limit": None},
        {"outgoing_udp_payload_ceiling": 1_200},
        {"incoming_udp_payload_limit": 65_527, "outgoing_udp_payload_ceiling": 1_201},
        {"incoming_udp_payload_limit": True, "outgoing_udp_payload_ceiling": 1_200},
    ):
        assert _runner_directional_udp_policy(invalid, 1_200)[-1] is False


def _fitting_sample(root: Path, *, incoming_length: int, outgoing_length: int = 1_200):
    _write_fitting_trace(
        root,
        [
            (
                150_000,
                "classified_datagram",
                {
                    "endpoint": 1,
                    "direction": "outgoing",
                    "length": outgoing_length,
                    "class": "natural",
                },
            ),
            (
                160_000,
                "classified_datagram",
                {
                    "endpoint": 1,
                    "direction": "incoming",
                    "length": incoming_length,
                    "class": "natural",
                },
            ),
        ],
    )
    return load_fitting_trace(
        root,
        sample_id=root.name,
        workload_id=root.name,
        request_policy="as-defined",
        visit=0,
    )


def test_fitting_retains_raw_incoming_length_and_discloses_terminal_bucket_projection(
    tmp_path: Path,
) -> None:
    alpha = _fitting_sample(tmp_path / "alpha", incoming_length=1_452)
    bravo = _fitting_sample(tmp_path / "bravo", incoming_length=1_100)
    assert [packet.length_bytes for packet in alpha.packets] == [1_200, 1_452]
    artifact, diagnostics = fit_traffic_morphing({"alpha": (alpha,), "bravo": (bravo,)})
    assert artifact["schema_version"] == 2
    assert artifact["udp_payload_ceiling"] == 1_200
    assert artifact["buckets"][-1] == 1_200
    assert diagnostics["incoming_projection"] == "top-code-to-terminal-bucket-1200-v1"
    assert diagnostics["corpus_bucket_counts"][0]["incoming"][-1] == 1
    assert diagnostics["incoming_overflow"] == [
        {"workload_id": "alpha", "packet_count": 1, "maximum_udp_payload_bytes": 1_452},
        {"workload_id": "bravo", "packet_count": 0, "maximum_udp_payload_bytes": None},
    ]
    fitting_module._validate_traffic_morphing_receipt(diagnostics, ("alpha", "bravo"))
    invalid = copy.deepcopy(diagnostics)
    invalid["incoming_overflow"][0]["packet_count"] = 2
    with pytest.raises(ValueError, match="incoming overflow"):
        fitting_module._validate_traffic_morphing_receipt(invalid, ("alpha", "bravo"))
    historical = copy.deepcopy(diagnostics)
    historical["algorithm"] = "all-directed-padding-only-lp-then-minimum-cost-derangement"
    historical.pop("incoming_projection")
    historical.pop("incoming_overflow")
    fitting_module._validate_traffic_morphing_receipt(historical, ("alpha", "bravo"))

    with pytest.raises(ValueError, match="outgoing datagram length"):
        _fitting_sample(tmp_path / "outgoing-too-large", incoming_length=1_452, outgoing_length=1_201)


def _directional_packet_receipt(receipt: dict[str, object], schema: int) -> dict[str, object]:
    updated = copy.deepcopy(receipt)
    updated["schema_version"] = schema
    updated["incoming_udp_payload_limit"] = 65_527
    updated["outgoing_udp_payload_ceiling"] = 1_200
    incoming = next(
        packet for packet in updated["packet_observations"] if packet["direction"] == "incoming"
    )
    incoming["udp_payload_bytes"] = 1_452
    updated["packet_log_sha256"] = chaff_fixture._packet_log(updated["packet_observations"])
    updated["packets"] = chaff_fixture._statistics(updated["packet_observations"])
    return updated


def test_response_receipt_dispatch_preserves_schema_two_and_allows_new_incoming() -> None:
    manifest = load_json(chaff_fixture.WORKLOAD)
    root = qualification.selected_navigation_root(manifest, "cloudflare-quiche-r3")
    headers = qualification.project_compact_headers(root)
    receipt = chaff_fixture._response_receipt(
        run_index=0,
        application_sha256=sha256_file(chaff_fixture.WORKLOAD),
        url=root["url"],
        headers=headers,
        source={"neqo_base_commit": "d" * 40, "published_qcsd_commit": "e" * 40, "migration_commit": "c" * 40},
    )
    kwargs = dict(
        application_manifest_sha256=sha256_file(chaff_fixture.WORKLOAD),
        application_resource_id=0,
        selected_chaff_resource_id=0,
        qualified_parallel_chaff_streams=6,
        url=root["url"],
        headers=headers,
    )
    modern = _directional_packet_receipt(receipt, 4)
    qualification._validate_response_receipt(modern, **kwargs)
    old = copy.deepcopy(modern)
    old["schema_version"] = 2
    old.pop("incoming_udp_payload_limit")
    old.pop("outgoing_udp_payload_ceiling")
    with pytest.raises(ValueError, match="packet transcript"):
        qualification._validate_response_receipt(old, **kwargs)
    modern["outgoing_udp_payload_ceiling"] = 1_201
    with pytest.raises(ValueError, match="directional UDP policy"):
        qualification._validate_response_receipt(modern, **kwargs)


def test_sustained_response_receipt_allows_new_incoming() -> None:
    manifest = load_json(chaff_fixture.WORKLOAD)
    candidate, _ = qualification.response_only_candidate_resources(
        manifest, "cloudflare-quiche-r3"
    )[0]
    receipt = chaff_fixture._response_v2_receipt(
        run_index=0,
        candidate=candidate,
        application_sha256=sha256_file(chaff_fixture.WORKLOAD),
        source={"neqo_base_commit": "d" * 40, "published_qcsd_commit": "e" * 40, "migration_commit": "c" * 40},
    )
    modern = _directional_packet_receipt(receipt, 5)
    kwargs = dict(
        application_manifest_sha256=sha256_file(chaff_fixture.WORKLOAD),
        application_resource_id=0,
        selected_chaff_resource_id=candidate["id"],
        url=candidate["url"],
        headers=qualification.project_identity_chaff_headers(candidate),
    )
    qualification._validate_response_receipt_v2(modern, **kwargs)
    outgoing = next(
        packet for packet in modern["packet_observations"] if packet["direction"] == "outgoing"
    )
    outgoing["udp_payload_bytes"] = 1_201
    modern["packet_log_sha256"] = chaff_fixture._packet_log(modern["packet_observations"])
    modern["packets"] = chaff_fixture._statistics(modern["packet_observations"])
    with pytest.raises(ValueError, match="packet transcript"):
        qualification._validate_response_receipt_v2(modern, **kwargs)


def test_prefix_receipt_allows_new_incoming(tmp_path: Path) -> None:
    prefix_path = chaff_fixture._write_prefix_spec(tmp_path)
    sidecar = chaff_fixture._sidecar(prefix_path)
    receipt = sidecar["resource"]["prefix_pack_runs"][0]["receipt"]
    spec = load_json(prefix_path)
    modern = _directional_packet_receipt(receipt, 3)
    kwargs = dict(
        application_manifest_sha256=receipt["application_workload_source_sha256"],
        runtime_manifest_sha256=receipt["runtime_workload_sha256"],
        chaff_core_sha256=receipt["chaff_core_sha256"],
        resource_id=0,
        request_stream_bytes=163,
        prefix_spec=spec,
        prefix_spec_sha256=sha256_file(prefix_path),
    )
    qualification._validate_prefix_receipt(modern, **kwargs)
    old = copy.deepcopy(modern)
    old["schema_version"] = 2
    old.pop("incoming_udp_payload_limit")
    old.pop("outgoing_udp_payload_ceiling")
    with pytest.raises(ValueError, match="packet transcript"):
        qualification._validate_prefix_receipt(old, **kwargs)
