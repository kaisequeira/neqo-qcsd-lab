import socket

import dpkt
from types import SimpleNamespace

import qcsd_lab.capture as capture_module
from qcsd_lab.capture import extract_trace, read_normalized_trace, write_normalized_trace


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
    assert trace[0].signed_frame_len > 0
    assert trace[1].signed_frame_len < 0
    assert {packet.connection for packet in trace} == {7}


def test_outer_wireguard_uses_udp_length_client_port_direction_and_normalized_contract(tmp_path):
    capture = tmp_path / "outer.pcap"
    with capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        writer.writepkt(packet("172.17.0.2", "172.17.0.3", 51821, 51820, b"x" * 32), ts=1.0)
        writer.writepkt(packet("172.17.0.3", "172.17.0.2", 51820, 51821, b"y" * 48), ts=1.2)
    trace = extract_trace(
        capture,
        kind="wireguard-outer",
        length_basis="udp.length",
        client_port=51821,
    )
    assert [item.direction for item in trace] == ["outgoing", "incoming"]
    assert [item.length_bytes for item in trace] == [40, 56]
    assert [item.signed_length_bytes for item in trace] == [40, -56]
    output = tmp_path / "trace.csv"
    write_normalized_trace(output, trace)
    assert output.read_text(encoding="utf-8").splitlines()[0] == (
        "relative_time_ns,direction,length_bytes,signed_length_bytes"
    )
    assert len(read_normalized_trace(output)) == 2


def test_direct_fragment_without_udp_ports_uses_filtered_endpoint_addresses(tmp_path, monkeypatch):
    rows = (
        '"1.000000000","34","203.0.113.1","","172.17.0.2","","",""\n'
        '"1.100000000","34","172.17.0.2","","203.0.113.1","","",""\n'
    )
    monkeypatch.setattr(capture_module, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=rows))
    endpoints = [
        {"id": 7, "local_address": "172.17.0.2:50000", "remote_address": "203.0.113.1:443"}
    ]
    trace = extract_trace(tmp_path / "synthetic.pcapng", endpoints)
    assert [packet.direction for packet in trace] == ["incoming", "outgoing"]
    assert [packet.connection for packet in trace] == [7, 7]
