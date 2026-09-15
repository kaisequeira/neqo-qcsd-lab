"""Four-leg DNS packet reconciliation against independent socket wire records."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import struct
from typing import Any

import dpkt
import pytest

from qcsd_lab.browser_egress_dns import dns_control_nxdomain_response
from qcsd_lab.browser_egress_dns_evidence import dns_wire_record, empty_dns_control_evidence
from qcsd_lab.browser_egress_dns_packets import (
    DNS_CONTROL_PACKET_FIELDS,
    DNS_CONTROL_PACKET_ROUTES,
    dns_control_packet_projection,
    dns_control_packet_route,
    reconcile_dns_control_packets,
    validate_dns_control_packets,
)
from qcsd_lab.browser_egress_fixture import FIXTURE_TOPOLOGY, dns_query_message

_HOSTNAME = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
_BROWSER = FIXTURE_TOPOLOGY["browser_addresses"]
_SINK = FIXTURE_TOPOLOGY["dns_sink_addresses"]


def _query(identifier: int, *, qtype: int = 1, rd: bool = True) -> bytes:
    message = dns_query_message(_HOSTNAME, identifier=identifier)
    return (
        message[:2] + struct.pack("!H", 0x0100 if rd else 0)
        + message[4:-4] + struct.pack("!HH", qtype, 1)
    )


def _packet(frame: int, wire: bytes, src: str, src_port: int, dst: str, dst_port: int) -> dict:
    # dpkt provides an independent wire decoder; do not use the production
    # query parser to manufacture expected packet metadata.
    message = dpkt.dns.DNS(wire)
    assert len(message.qd) == 1
    question = message.qd[0]
    return {
        "frame_number": frame,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "ip_version": ipaddress.ip_address(src).version,
        "transport": "udp",
        "dns_kind": "response" if message.qr else "query",
        "dns_name": question.name.lower().rstrip("."),
        "dns_id": message.id,
        "dns_type": question.type,
        "dns_class": question.cls,
        "dns_rcode": message.rcode,
        "dns_payload_sha256": hashlib.sha256(wire).hexdigest(),
        "payload_bytes": len(wire),
    }


def _evidence(
    count: int = 2,
    *,
    families: tuple[int, ...] = (4,),
    listener: int = 58173,
    same_id: bool = False,
    vary_rd: bool = False,
    identical_queries: bool = False,
) -> tuple[list[dict], dict]:
    packets: list[dict] = []
    control = empty_dns_control_evidence(_HOSTNAME)
    for index in range(count):
        family = families[index % len(families)]
        browser, sink = _BROWSER[family == 6], _SINK[family == 6]
        query = _query(
            7 if same_id or identical_queries else index + 1,
            qtype=1 if vary_rd or identical_queries else (1, 28, 65)[index % 3],
            rd=not vary_rd or index % 2 == 0,
        )
        response = dns_control_nxdomain_response(query, hostname=_HOSTNAME)
        local_port, external_port = 10000 + index, 40000 + index
        packets.extend([
            _packet(index * 4 + 1, query, "127.0.0.1", local_port, "127.0.0.11", listener),
            _packet(index * 4 + 2, query, browser, external_port, sink, 53),
            _packet(index * 4 + 3, response, sink, 53, browser, external_port),
            _packet(index * 4 + 4, response, "127.0.0.11", 53, "127.0.0.1", local_port),
        ])
        address = (browser, external_port)
        control["queries"].append(dns_wire_record(query, address, transport="udp"))
        control["responses"].append(dns_wire_record(response, address, transport="udp"))
    return packets, control


def _arguments(*, enabled: bool = True) -> dict[str, Any]:
    return {
        "hostname": _HOSTNAME,
        "browser_addresses": _BROWSER,
        "sink_addresses": _SINK,
        "enabled": enabled,
    }


def _validate(packets: object, *, enabled: bool = True) -> dict[str, list[dict]]:
    return validate_dns_control_packets(packets, **_arguments(enabled=enabled))


def _reconcile(packets: object, control: object, *, enabled: bool = True) -> None:
    reconcile_dns_control_packets(packets, control, **_arguments(enabled=enabled))


@pytest.mark.parametrize("families", [(4,), (6,), (4, 6)])
@pytest.mark.parametrize("listener", [53, 1024, 58173, 65535])
@pytest.mark.parametrize("count", [1, 2, 5])
def test_complete_four_leg_witness_with_variable_count_listener_and_external_family(
    families: tuple[int, ...], listener: int, count: int,
) -> None:
    packets, control = _evidence(count, families=families, listener=listener)
    original = copy.deepcopy(packets)
    routes = _validate(packets)
    assert tuple(routes) == DNS_CONTROL_PACKET_ROUTES
    assert all(len(route) == count for route in routes.values())
    assert routes["resolver-query"][0]["dst_port"] == listener
    assert routes["resolver-response"][0]["src_port"] == 53
    assert packets == original
    assert routes["resolver-query"][0] is not packets[0]
    _reconcile(packets, control)


def test_projection_retains_all_transaction_fields_and_drops_unrelated_packet_metadata() -> None:
    packets, _ = _evidence(1)
    raw = {**packets[0], "timestamp_ns": 1, "tcp_syn": False, "quoted_transport": None}
    assert dns_control_packet_projection(raw) == packets[0]
    assert set(dns_control_packet_projection({})) == DNS_CONTROL_PACKET_FIELDS
    assert all(value is None for value in dns_control_packet_projection({}).values())
    with pytest.raises(ValueError, match="frame_number"):
        _validate([dns_control_packet_projection({})])


def test_route_classification_preserves_every_outer_dns_packet() -> None:
    packets, _ = _evidence(1)
    assert [dns_control_packet_route(packet, browser_addresses=_BROWSER, sink_addresses=_SINK)
            for packet in packets] == list(DNS_CONTROL_PACKET_ROUTES)
    for transport in ("tcp", "icmp", "icmpv6", "other"):
        assert dns_control_packet_route(
            {**packets[0], "transport": transport},
            browser_addresses=_BROWSER, sink_addresses=_SINK,
        ) is None


def test_negative_requires_zero_packets_and_independent_zero_socket_evidence() -> None:
    packets, control = _evidence(0)
    assert _validate(packets, enabled=False) == dict.fromkeys(DNS_CONTROL_PACKET_ROUTES, [])
    _reconcile(packets, control, enabled=False)
    with pytest.raises(ValueError, match="witness"):
        _validate(packets)
    nonempty, nonempty_control = _evidence(1)
    with pytest.raises(ValueError, match="witness"):
        _reconcile(nonempty, nonempty_control, enabled=False)
    with pytest.raises(ValueError, match="witness"):
        _reconcile([], nonempty_control, enabled=False)


@pytest.mark.parametrize("ordinal", range(4))
@pytest.mark.parametrize("change", ["missing", "extra"])
def test_every_transaction_requires_one_copy_of_each_leg(ordinal: int, change: str) -> None:
    packets, control = _evidence(1)
    if change == "missing":
        packets.pop(ordinal)
    else:
        packets.append({**packets[ordinal], "frame_number": 5})
    with pytest.raises(ValueError, match="witness"):
        _reconcile(packets, control)


def test_complete_extra_transaction_is_not_accepted_without_independent_socket_evidence() -> None:
    packets, _ = _evidence(2)
    _, control = _evidence(1)
    assert all(len(route) == 2 for route in _validate(packets).values())
    with pytest.raises(ValueError, match="wire inventories"):
        _reconcile(packets, control)


def test_one_dynamic_listener_is_required_for_the_entire_attempt() -> None:
    packets, _ = _evidence(2)
    packets[4]["dst_port"] += 1
    with pytest.raises(ValueError, match="one observed listener"):
        _validate(packets)


@pytest.mark.parametrize("ordinal,field,value", [
    (0, "src", "127.0.0.2"), (0, "dst", "127.0.0.12"),
    (1, "src", "192.0.2.1"), (1, "dst", "192.0.2.53"), (1, "dst_port", 5353),
    (2, "src", "192.0.2.53"), (2, "dst", "192.0.2.1"), (2, "src_port", 5353),
    (3, "src", "127.0.0.12"), (3, "dst", "127.0.0.2"), (3, "src_port", 58173),
    (0, "transport", "tcp"), (1, "dns_kind", "none"),
    (0, "dns_name", "attacker.test"), (2, "dns_rcode", 2), (0, "dns_rcode", 3),
])
def test_unknown_names_routes_transports_and_non_nxdomain_replies_fail(
    ordinal: int, field: str, value: object,
) -> None:
    packets, _ = _evidence(1)
    packets[ordinal][field] = value
    with pytest.raises(ValueError, match="approved"):
        _validate(packets)


@pytest.mark.parametrize("ordinal", [2, 3])
@pytest.mark.parametrize("field", ["dst_port", "dns_id", "dns_type"])
def test_reply_must_match_its_exact_peer_and_question(ordinal: int, field: str) -> None:
    packets, _ = _evidence(1)
    if field == "dst_port":
        packets[ordinal][field] += 1
    else:
        # Change both reply legs to preserve their mutual byte/metadata multiset,
        # so the query-to-reply check must independently detect the mismatch.
        packets[2][field] += 1
        packets[3][field] += 1
    with pytest.raises(ValueError, match="peer/question"):
        _validate(packets)


@pytest.mark.parametrize("ordinal", range(4))
@pytest.mark.parametrize("field,value", [
    ("dns_payload_sha256", "0" * 64), ("payload_bytes", 99),
])
def test_every_leg_binds_complete_message_bytes_and_length(
    ordinal: int, field: str, value: object,
) -> None:
    packets, _ = _evidence(1)
    packets[ordinal][field] = value
    with pytest.raises(ValueError, match="message bytes"):
        _validate(packets)


def test_forged_but_mutually_equal_packet_hashes_do_not_replace_socket_wire_evidence() -> None:
    packets, control = _evidence(1)
    for packet in packets[:2]:
        packet["dns_payload_sha256"] = "0" * 64
    _validate(packets)
    with pytest.raises(ValueError, match="wire inventories"):
        _reconcile(packets, control)


@pytest.mark.parametrize("ordinal", [2, 3])
def test_same_id_question_different_query_bytes_cannot_swap_response_destinations(
    ordinal: int,
) -> None:
    packets, control = _evidence(2, same_id=True, vary_rd=True)
    assert packets[0]["dns_id"] == packets[4]["dns_id"]
    assert packets[0]["dns_name"] == packets[4]["dns_name"]
    assert packets[0]["dns_type"] == packets[4]["dns_type"]
    assert packets[0]["dns_payload_sha256"] != packets[4]["dns_payload_sha256"]
    assert packets[2]["dns_payload_sha256"] != packets[6]["dns_payload_sha256"]
    _reconcile(packets, control)
    for field in ("dns_payload_sha256", "payload_bytes"):
        packets[ordinal][field], packets[ordinal + 4][field] = (
            packets[ordinal + 4][field], packets[ordinal][field]
        )
    # Aggregate validation intentionally cannot infer which response bytes a
    # query should produce; the independent wire-bound reconciler must do so.
    _validate(packets)
    expected = "wire inventories" if ordinal == 2 else "exact local queries"
    with pytest.raises(ValueError, match=expected):
        _reconcile(packets, control)


def test_identical_repeated_queries_preserve_multiplicity_instead_of_set_deduplication() -> None:
    packets, control = _evidence(2, identical_queries=True)
    assert packets[0]["dns_payload_sha256"] == packets[4]["dns_payload_sha256"]
    _reconcile(packets, control)
    control["queries"].pop()
    control["responses"].pop()
    with pytest.raises(ValueError, match="wire inventories"):
        _reconcile(packets, control)


@pytest.mark.parametrize("field,value", [
    ("frame_number", 0), ("frame_number", True), ("src_port", 0), ("dst_port", 65536),
    ("dns_id", -1), ("dns_id", 65536), ("dns_id", True), ("dns_type", 0),
    ("dns_class", 2), ("dns_class", True), ("dns_rcode", 16),
    ("payload_bytes", 11), ("payload_bytes", 4097), ("ip_version", True),
    ("ip_version", 6), ("src", None), ("src", "not-an-ip"),
    ("dns_payload_sha256", None), ("dns_payload_sha256", "A" * 64),
    ("dns_payload_sha256", "a" * 63), ("extra", 1),
])
def test_projection_fields_and_values_are_strict(field: str, value: object) -> None:
    packets, _ = _evidence(1)
    packets[0][field] = value
    with pytest.raises(ValueError):
        _validate(packets)


@pytest.mark.parametrize("qtype", [41, 249, 250, 251, 252, 253, 254])
def test_meta_transfer_and_opt_question_types_are_not_approved(qtype: int) -> None:
    packets, _ = _evidence(1)
    for packet in packets:
        packet["dns_type"] = qtype
    with pytest.raises(ValueError, match="not approved"):
        _validate(packets)


@pytest.mark.parametrize("mutation", [
    "missing-field", "non-mapping", "duplicate-frame", "reversed",
])
def test_packet_inventory_shape_and_frame_order_are_closed(mutation: str) -> None:
    packets, _ = _evidence(1)
    if mutation == "missing-field":
        packets[0].pop("dns_id")
    elif mutation == "non-mapping":
        packets[0] = None
    elif mutation == "duplicate-frame":
        packets[1]["frame_number"] = packets[0]["frame_number"]
    else:
        packets.reverse()
    with pytest.raises(ValueError):
        _validate(packets)


@pytest.mark.parametrize("packets", [None, {}, (), "", b""])
def test_only_explicit_list_inventory_is_accepted(packets: object) -> None:
    with pytest.raises(ValueError, match="inventory"):
        _validate(packets, enabled=False)


@pytest.mark.parametrize("enabled", [0, 1, "true", None])
def test_enabled_policy_must_be_an_exact_boolean(enabled: object) -> None:
    with pytest.raises(ValueError, match="enabled policy"):
        validate_dns_control_packets([], **{**_arguments(), "enabled": enabled})
