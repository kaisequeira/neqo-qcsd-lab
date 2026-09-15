"""Outer-layer decoder regressions using generated packets, never campaign evidence."""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import ipaddress
import struct
import subprocess
from pathlib import Path

import pytest

from qcsd_lab.browser_egress_fixture import FIXTURE_TOPOLOGY, vector_by_id
from qcsd_lab.browser_egress_observer import (
    HISTORICAL_TSHARK_FIELDS,
    PacketPolicyError,
    TSHARK_FIELDS,
    _records_from_tshark_output,
    analyse_packet_records,
    tshark_command,
    tshark_fields,
    validate_packet_analysis,
    validate_packet_record,
)


def _dns(*, response: bool = False) -> bytes:
    labels = b"\x07decoder\x06egress\x07invalid\0"
    return (
        struct.pack("!6H", 0x1234, 0x8183 if response else 0x0100, 1, 0, 0, 0)
        + labels + struct.pack("!2H", 1, 1)
    )


def _row(*, overrides: dict[str, str] | None = None, version: int = 5) -> str:
    payload = _dns()
    values = {
        "frame.number": "1", "frame.time_epoch": "123.123456789", "frame.interface_id": "0",
        "frame.protocols": "eth:ethertype:ip:udp:dns",
        "ip.src": "192.0.2.1", "ip.dst": "192.0.2.53",
        "ip.proto": "17", "udp.srcport": "49152", "udp.dstport": "53",
        "udp.length": str(len(payload) + 8),
        "dns.flags.response": "False", "dns.qry.name": "decoder.egress.invalid", "dns.id": "0x1234",
        "dns.count.queries": "1", "dns.qry.type": "1", "dns.qry.class": "0x0001",
        "udp.payload": payload.hex(),
    }
    values.update(overrides or {})
    output = io.StringIO(newline="")
    csv.writer(output, delimiter="\t", quotechar='"').writerow(
        values.get(field, "") for field in tshark_fields(version)
    )
    return output.getvalue()


@pytest.mark.parametrize("flag,kind", [
    ("0", "query"), ("False", "query"), ("1", "response"), ("True", "response"),
])
def test_dns_response_flags_are_strict_and_payload_is_bound(flag: str, kind: str) -> None:
    payload = _dns(response=kind == "response")
    record, = _records_from_tshark_output(_row(overrides={
        "dns.flags.response": flag, "dns.flags.rcode": "3" if kind == "response" else "",
        "udp.payload": payload.hex(),
    }))
    assert record["schema_version"] == 2
    assert record["dns_kind"] == kind
    assert record["dns_id"] == 0x1234
    assert record["dns_type"] == record["dns_class"] == 1
    assert record["dns_rcode"] == (3 if kind == "response" else 0)
    assert record["dns_payload_sha256"] == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("flag", ["", "2", "true", "false", "TRUE", "yes", "False,True"])
def test_unknown_or_ambiguous_dns_flags_are_not_silently_queries(flag: str) -> None:
    with pytest.raises(ValueError, match="DNS response|dns.flags.response"):
        _records_from_tshark_output(_row(overrides={"dns.flags.response": flag}))


@pytest.mark.parametrize("overrides", [
    {"frame.number": "0"}, {"frame.number": "1,2"}, {"frame.time_epoch": "NaN"},
    {"frame.time_epoch": "Infinity"}, {"frame.time_epoch": "-1"},
    {"frame.time_epoch": "1.0000000001"}, {"frame.protocols": ""},
    {"frame.protocols": "eth:ip::udp:dns"}, {"frame.protocols": "eth:ip:icmp:ip:udp:dns"},
    {"ip.proto": ""}, {"ip.proto": "256"}, {"ip.src": ""}, {"ip.src": "192.0.2.1,"},
    {"udp.srcport": "65536"}, {"udp.dstport": ""}, {"udp.length": "7"},
    {"dns.count.queries": "0"}, {"dns.count.queries": "2"}, {"dns.qry.type": "1,65"},
    {"dns.qry.class": "0x10000"}, {"dns.id": "0xXYZ"}, {"dns.id": "-1"},
    {"dns.flags.rcode": "3"}, {"udp.payload": "f"}, {"udp.payload": "gg"},
    {"udp.payload": "00"}, {"udp.payload": "00:01:2"},
    {"dns.flags.response": "True", "dns.flags.rcode": ""},
])
def test_malformed_packet_rows_fail_closed(overrides: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        _records_from_tshark_output(_row(overrides=overrides))


def test_packet_row_shape_and_quoting_are_strict() -> None:
    with pytest.raises(ValueError, match="wrong field count"):
        _records_from_tshark_output("1\t2\n")
    with pytest.raises(ValueError, match="malformed TSV"):
        _records_from_tshark_output('"unterminated')


@pytest.mark.parametrize("version", [3, 4])
def test_historical_fields_and_known_decoder_limitations_are_frozen(version: int) -> None:
    assert tshark_fields(version) == HISTORICAL_TSHARK_FIELDS
    assert tshark_fields(5) == TSHARK_FIELDS
    command = tshark_command(Path("capture.pcap"), analysis_schema_version=version)
    assert "occurrence=f" in command
    assert "frame.protocols" not in command
    # Historical receipts retain the original interpretation of True as a query.
    historical, = _records_from_tshark_output(
        _row(overrides={"dns.flags.response": "True"}, version=version),
        analysis_schema_version=version,
    )
    assert historical["schema_version"] == 1
    assert historical["dns_kind"] == "query"
    assert "dns_id" not in historical
    assert validate_packet_record(historical) == historical
    # There is no outer-protocol field in this exact old input contract.
    assert historical["transport"] == "udp"
    assert "occurrence=a" in tshark_command(Path("capture.pcap"))


def test_historical_four_keeps_timestamp_regression_diagnostics() -> None:
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    fixture = FIXTURE_TOPOLOGY["fixture_addresses"][0]
    row = _row(version=4, overrides={
        "ip.src": browser, "ip.dst": fixture, "tcp.srcport": "49152",
        "tcp.dstport": str(FIXTURE_TOPOLOGY["ports"]["fixture_https"]),
        "tcp.flags.syn": "0", "tcp.flags.ack": "1", "tcp.len": "0",
        "udp.srcport": "", "udp.dstport": "", "dns.flags.response": "", "dns.qry.name": "",
    })
    record, = _records_from_tshark_output(row, analysis_schema_version=4)
    later = {**record, "frame_number": 2, "timestamp_ns": record["timestamp_ns"] - 1}
    vector = vector_by_id("constructor--page--websocket")
    result = analyse_packet_records([record, later], vector=vector, analysis_schema_version=4)
    assert result["timestamp_regressions"] == result["maximum_timestamp_regression_ns"] == 1
    assert "decoded_control_packets" not in result
    validate_packet_analysis(result, vector=vector)
    with pytest.raises(ValueError, match="not capture ordered"):
        analyse_packet_records([record, later], vector=vector, analysis_schema_version=3)


def _ip(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    source, target = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if source.version == 6:
        header = struct.pack("!IHBB", 6 << 28, len(payload), protocol, 64)
    else:
        header = struct.pack("!BBHHHBBH", 0x45, 0, len(payload) + 20, 1, 0, 64, protocol, 0)
    return header + source.packed + target.packed + payload


def _udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!4H", src_port, dst_port, len(payload) + 8, 0) + payload


def _pcap(tmp_path: Path, packets: list[bytes]) -> Path:
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for number, packet in enumerate(packets, 1):
        ether_type = b"\x08\x00" if packet[0] >> 4 == 4 else b"\x86\xdd"
        ethernet = b"\x01\x02\x03\x04\x05\x06" * 2 + ether_type
        frame = ethernet + packet
        data.extend(struct.pack("<4I", number, 0, len(frame), len(frame)))
        data.extend(frame)
    capture = tmp_path / "generated.pcap"
    capture.write_bytes(data)
    return capture


def _decode(pcap: Path, *, version: int = 5) -> list[dict]:
    if not Path("/usr/bin/tshark").is_file():
        pytest.skip("raw-PCAP decoder integration requires tshark")
    decoded = subprocess.run(
        tshark_command(pcap, analysis_schema_version=version),
        capture_output=True, text=True, check=True,
    )
    return _records_from_tshark_output(decoded.stdout, analysis_schema_version=version)


@pytest.mark.parametrize("outer_family,inner_family", [(4, 4), (4, 6), (6, 4), (6, 6)])
def test_real_pcap_icmp_quote_is_never_a_dns_datagram(
    tmp_path: Path, outer_family: int, inner_family: int,
) -> None:
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0 if outer_family == 4 else 1]
    sink = FIXTURE_TOPOLOGY["dns_sink_addresses"][0 if outer_family == 4 else 1]
    inner_src = "192.0.2.53" if inner_family == 4 else "2001:db8::53"
    inner_dst = "192.0.2.1" if inner_family == 4 else "2001:db8::1"
    quoted = _ip(inner_src, inner_dst, 17, _udp(53, 49152, _dns(response=True)))
    kind = 3 if outer_family == 4 else 1
    icmp = struct.pack("!BBHI", kind, 3 if outer_family == 4 else 4, 0, 0) + quoted
    record, = _decode(_pcap(tmp_path, [_ip(browser, sink, 1 if outer_family == 4 else 58, icmp)]))
    assert record["transport"] == ("icmp" if outer_family == 4 else "icmpv6")
    assert (record["ip_version"], record["src"], record["dst"]) == (outer_family, browser, sink)
    # Wireshark's ICMPv6 dissector does not decode a nonstandard IPv4 quote;
    # account only the quoted transport the decoder can actually observe.
    assert record["quoted_transport"] == (None if (outer_family, inner_family) == (6, 4) else "udp")
    assert record["dns_kind"] == "none"
    assert record["src_port"] is record["dst_port"] is record["dns_payload_sha256"] is None
    vector = vector_by_id("constructor--page--websocket")
    analysis = analyse_packet_records([record], vector=vector)
    assert analysis["decoded_transport_packets"] == analysis["dns_udp_queries"] == 0
    assert analysis["decoded_control_packets"] == 1
    assert analysis["quoted_udp_packets"] == int(record["quoted_transport"] == "udp")
    validate_packet_analysis(analysis, vector=vector)


def test_real_pcap_dns_queries_responses_and_quotes_are_separate(tmp_path: Path) -> None:
    browser = FIXTURE_TOPOLOGY["browser_addresses"][0]
    sink = FIXTURE_TOPOLOGY["dns_sink_addresses"][0]
    query = _ip(browser, sink, 17, _udp(49152, 53, _dns()))
    response = _ip(sink, browser, 17, _udp(53, 49152, _dns(response=True)))
    quote = _ip(browser, sink, 1, struct.pack("!BBHI", 3, 3, 0, 0) + response)
    records = _decode(_pcap(tmp_path, [query, response, quote]))
    assert [(record["transport"], record["dns_kind"]) for record in records] == [
        ("udp", "query"), ("udp", "response"), ("icmp", "none"),
    ]
    assert records[1]["dns_rcode"] == 3
    assert records[0]["dns_payload_sha256"] == hashlib.sha256(_dns()).hexdigest()
    vector = vector_by_id("constructor--page--websocket")
    analysis = analyse_packet_records(records, vector=vector)
    assert analysis["dns_udp_queries"] == analysis["dns_udp_datagrams"] == 1
    with pytest.raises(PacketPolicyError, match="dns_udp_queries"):
        validate_packet_analysis(analysis, vector=vector)


def test_real_pcap_ipv6_repeated_extensions_do_not_hide_udp(tmp_path: Path) -> None:
    browser = FIXTURE_TOPOLOGY["browser_addresses"][1]
    sink = FIXTURE_TOPOLOGY["dns_sink_addresses"][1]
    # Two destination-options instances require occurrence=a rather than f.
    payload = (
        bytes([60, 0]) + bytes(6) + bytes([60, 0]) + bytes(6)
        + bytes([17, 0]) + bytes(6) + _udp(49152, 53, _dns())
    )
    record, = _decode(_pcap(tmp_path, [_ip(browser, sink, 0, payload)]))
    assert record["transport"] == "udp"
    assert record["outer_ip_protocol"] == 17
    assert record["ip_version"] == 6
    assert record["dns_kind"] == "query"


@pytest.mark.parametrize("protocol,token,field", [
    (0, "ipv6.hopopts", "ipv6.hopopts.nxt"),
    (43, "ipv6.routing", "ipv6.routing.nxt"),
    (44, "ipv6.fraghdr", "ipv6.fraghdr.nxt"),
    (60, "ipv6.dstopts", "ipv6.dstopts.nxt"),
    (51, "ah", "ah.next_header"),
])
def test_ipv6_extension_next_header_must_match_the_outer_stack(
    protocol: int, token: str, field: str,
) -> None:
    values = {
        "ip.src": "", "ip.dst": "", "ip.proto": "",
        "ipv6.src": "2001:db8::1", "ipv6.dst": "2001:db8::53",
        "ipv6.nxt": str(protocol), field: "17",
        "frame.protocols": f"eth:ethertype:ipv6:{token}:udp:dns",
    }
    record, = _records_from_tshark_output(_row(overrides=values))
    assert record["ip_version"] == 6
    assert record["transport"] == "udp"
    values[field] = "6"
    with pytest.raises(ValueError, match="disagrees"):
        _records_from_tshark_output(_row(overrides=values))
    values[field] = ""
    with pytest.raises(ValueError, match="extension chain"):
        _records_from_tshark_output(_row(overrides=values))


def test_real_pcap_unknown_outer_udp_cannot_be_hidden_by_nested_protocols(tmp_path: Path) -> None:
    packet = _ip("192.0.2.1", "192.0.2.2", 17, _udp(40000, 40001, b"unexpected"))
    record, = _decode(_pcap(tmp_path, [packet]))
    vector = vector_by_id("constructor--page--websocket")
    analysis = analyse_packet_records([record], vector=vector)
    assert analysis["unexpected_browser_egress_packets"] == 1
    with pytest.raises(ValueError, match="unexpected_browser_egress_packets"):
        validate_packet_analysis(analysis, vector=vector)


def test_v2_record_and_historical_analysis_contracts_do_not_mix() -> None:
    record, = _records_from_tshark_output(_row())
    with pytest.raises(ValueError, match="version-1"):
        analyse_packet_records(
            [record], vector=vector_by_id("constructor--page--websocket"),
            analysis_schema_version=4,
        )
    for field, value in (
        ("outer_ip_protocol", 6), ("dns_id", 65536), ("dns_class", True),
        ("dns_payload_sha256", None), ("quoted_transport", "udp"),
    ):
        malformed = copy.deepcopy(record)
        malformed[field] = value
        with pytest.raises(ValueError):
            validate_packet_record(malformed)
