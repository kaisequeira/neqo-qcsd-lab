import socket

import dpkt
import pytest
from types import SimpleNamespace

import qcsd_lab.capture as capture_module
from qcsd_lab.capture import (
    extract_trace,
    offload_evidence_is_valid,
    offload_state_is_safe,
    parse_offload_state,
    read_normalized_trace,
    recompute_offload_verification,
    udp_ceiling_evidence,
    write_normalized_trace,
)


def packet(source, destination, source_port, destination_port, payload=b"quic"):
    udp = dpkt.udp.UDP(sport=source_port, dport=destination_port, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(source),
        dst=socket.inet_aton(destination),
        p=dpkt.ip.IP_PROTO_UDP,
        ttl=64,
        data=udp,
    )
    ip.len = len(ip)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x00" * 6,
            dst=b"\x01" * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
    )


def test_pcap_direction_and_frame_length_extraction(tmp_path):
    capture = tmp_path / "traffic.pcap"
    with capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        writer.writepkt(packet("172.17.0.2", "203.0.113.1", 50000, 443), ts=1.0)
        writer.writepkt(packet("203.0.113.1", "172.17.0.2", 443, 50000), ts=1.1)
    endpoints = [
        {
            "id": 7,
            "local_address": "172.17.0.2:50000",
            "remote_address": "203.0.113.1:443",
        }
    ]
    trace = extract_trace(capture, endpoints)
    assert [packet.direction for packet in trace] == ["outgoing", "incoming"]
    assert [packet.udp_payload_len for packet in trace] == [4, 4]
    assert trace[0].signed_frame_len > 0
    assert trace[1].signed_frame_len < 0
    normalized = tmp_path / "trace.csv"
    write_normalized_trace(normalized, trace)
    assert normalized.read_text(encoding="utf-8").splitlines()[0] == (
        "relative_time_ns,direction,length_bytes,signed_length_bytes"
    )
    assert len(read_normalized_trace(normalized)) == 2


def test_direct_fragment_without_udp_ports_uses_filtered_endpoint_addresses(tmp_path, monkeypatch):
    rows = (
        '"1.000000000","34","","203.0.113.1","","172.17.0.2","","",""\n'
        '"1.100000000","34","","172.17.0.2","","203.0.113.1","","",""\n'
    )
    monkeypatch.setattr(
        capture_module, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=rows)
    )
    endpoints = [
        {"id": 7, "local_address": "172.17.0.2:50000", "remote_address": "203.0.113.1:443"}
    ]
    trace = extract_trace(tmp_path / "synthetic.pcapng", endpoints)
    assert [packet.direction for packet in trace] == ["incoming", "outgoing"]
    assert udp_ceiling_evidence(trace, 1200) == {
        "configured_udp_payload_ceiling": 1200,
        "observed_udp_payload_max": None,
        "packets_with_udp_payload_length": 0,
        "packets_without_udp_payload_length": 2,
        "oversized_udp_payload_packets": 0,
        "valid": False,
    }


def test_extractor_orders_capture_buffer_records_by_packet_timestamp(tmp_path, monkeypatch):
    rows = (
        '"1.100000000","46","12","203.0.113.1","","172.17.0.2","","443","50000"\n'
        '"1.000000000","46","12","172.17.0.2","","203.0.113.1","","50000","443"\n'
    )
    monkeypatch.setattr(
        capture_module,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=rows),
    )
    endpoints = [
        {"id": 7, "local_address": "172.17.0.2:50000", "remote_address": "203.0.113.1:443"}
    ]

    trace = extract_trace(tmp_path / "out-of-order.pcapng", endpoints)

    assert [packet.direction for packet in trace] == ["outgoing", "incoming"]
    assert [packet.relative_time_ns for packet in trace] == [0, 100_000_000]


def test_udp_ceiling_evidence_rejects_oversized_payload():
    trace = [
        capture_module.ObserverPacket(1, 0, "outgoing", 1242, 1242, 1200),
        capture_module.ObserverPacket(2, 1, "incoming", 1243, -1243, 1201),
    ]
    evidence = udp_ceiling_evidence(trace, 1200)
    assert evidence["observed_udp_payload_max"] == 1201
    assert evidence["oversized_udp_payload_packets"] == 1
    assert evidence["valid"] is False


def test_offload_state_requires_verified_packet_unit_features_off():
    output = """
Features for eth0:
tcp-segmentation-offload: off [fixed]
generic-segmentation-offload: off
generic-receive-offload: off
tx-udp-segmentation: off
large-receive-offload: off [fixed]
"""
    state = parse_offload_state(output)
    assert state == {"gro": "off", "gso": "off", "tso": "off", "uso": "off"}
    assert offload_state_is_safe(state) is True
    state["gro"] = "on"
    assert offload_state_is_safe(state) is False
    assert offload_state_is_safe({"gro": "off", "gso": "off", "tso": "off"}) is False


def test_offload_evidence_recomputes_the_exact_command_contract():
    evidence = {
        "interface": "eth0",
        "requested": {"gro": "off", "gso": "off", "tso": "off", "uso": "off"},
        "query_returncodes": {"before": 0, "after": 0},
        "change_returncodes": {"gro": 0, "gso": 0, "tso": 0, "uso": 0},
        "before_state": {"gro": "on", "gso": "on", "tso": "on", "uso": "on"},
        "after_state": {"gro": "off", "gso": "off", "tso": "off", "uso": "off"},
        "before_sha256": "0" * 64,
        "after_sha256": "1" * 64,
        "verified": True,
    }
    assert recompute_offload_verification(evidence, interface="eth0")
    assert offload_evidence_is_valid(evidence, interface="eth0")

    for field, replacement in (
        ("requested", {"gro": "off", "gso": "on", "tso": "off", "uso": "off"}),
        ("query_returncodes", {"before": 1, "after": 0}),
        ("change_returncodes", {"gro": 0, "gso": 1, "tso": 0, "uso": 0}),
        ("after_state", {"gro": "on", "gso": "off", "tso": "off", "uso": "off"}),
        ("before_sha256", "not-a-hash"),
        ("verified", False),
    ):
        tampered = {**evidence, field: replacement}
        assert not offload_evidence_is_valid(tampered, interface="eth0")


def test_direct_trace_rejects_packet_outside_exact_endpoint_tuple(tmp_path):
    capture = tmp_path / "traffic.pcap"
    with capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        writer.writepkt(
            packet("172.17.0.2", "203.0.113.1", 50000, 8443),
            ts=1.0,
        )
    endpoints = [
        {
            "id": 7,
            "local_address": "172.17.0.2:50000",
            "remote_address": "203.0.113.1:443",
        }
    ]
    with pytest.raises(ValueError, match="outside Neqo endpoint tuples"):
        extract_trace(capture, endpoints)
