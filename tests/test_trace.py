import csv
import socket

import dpkt

from qcsd_lab.campaign import _extract_trace


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
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def test_pcap_direction_and_frame_length_extraction(tmp_path):
    capture = tmp_path / "traffic.pcap"
    with capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        writer.writepkt(packet("172.17.0.2", "203.0.113.1", 50000, 443), ts=1.0)
        writer.writepkt(packet("203.0.113.1", "172.17.0.2", 443, 50000), ts=1.1)
    trace = tmp_path / "traffic.csv"
    endpoints = [
        {
            "id": 7,
            "local_address": "172.17.0.2:50000",
            "remote_address": "203.0.113.1:443",
        }
    ]
    _extract_trace(capture, endpoints, trace)
    with trace.open(newline="") as source:
        rows = list(csv.DictReader(source))
    assert [row["direction"] for row in rows] == ["outgoing", "incoming"]
    assert int(rows[0]["signed_frame_len"]) > 0
    assert int(rows[1]["signed_frame_len"]) < 0
    assert {int(row["connection"]) for row in rows} == {7}
