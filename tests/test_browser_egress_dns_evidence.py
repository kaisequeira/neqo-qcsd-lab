from __future__ import annotations

import copy
import hashlib
import socket
import struct
from collections.abc import Callable
from typing import Any

import dpkt
import pytest

from qcsd_lab.browser_egress_dns import dns_control_nxdomain_response
from qcsd_lab.browser_egress_dns_evidence import (
    dns_wire_record,
    dns_wire_transaction_key,
    empty_dns_control_evidence,
    validate_dns_control_evidence,
    validate_dns_wire_record,
)
from qcsd_lab.browser_egress_fixture import (
    FIXTURE_TOPOLOGY,
    IndependentDnsSink,
    combine_sink_receipt,
    dns_query_message,
    expected_sink_counters,
    validate_sink_receipt,
    vector_by_id,
)

_HOSTNAME = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
_LOOPBACK = "127.0.0.1"


def _query(identifier: int = 1, *, hostname: str = _HOSTNAME, qtype: int = 1) -> bytes:
    return dns_query_message(hostname, identifier=identifier)[:-4] + struct.pack("!HH", qtype, 1)


def _control_evidence(count: int, *, peers: list[str] | None = None) -> dict[str, Any]:
    peers = peers or [_LOOPBACK]
    evidence = empty_dns_control_evidence(_HOSTNAME)
    for index in range(count):
        request = _query(index + 1, qtype=(1, 28, 65)[index % 3])
        address = (peers[index % len(peers)], 49000 + index)
        evidence["queries"].append(dns_wire_record(request, address, transport="udp"))
        evidence["responses"].append(dns_wire_record(
            dns_control_nxdomain_response(request, hostname=_HOSTNAME), address, transport="udp"
        ))
    return evidence


def _validate(value: object, *, enabled: bool = True) -> dict[str, Any]:
    return validate_dns_control_evidence(
        value, hostname=_HOSTNAME, allowed_peers=[_LOOPBACK], enabled=enabled
    )


def _vector(*, enabled: bool):
    suffix = "enabled" if enabled else "disabled"
    return vector_by_id(f"browser-service-control--default-profile--dns-prefetch-{suffix}")


def _raw_dns_receipt(count: int, *, peers: list[str]) -> dict[str, Any]:
    control = _control_evidence(count, peers=peers)
    return {
        "udp_names": [_HOSTNAME] * count,
        "tcp_names": [],
        "ip_versions": {
            family: {
                "udp_names": [
                    _HOSTNAME for query in control["queries"]
                    if (":" in query["peer_ip"]) == (family == "ipv6")
                ],
                "tcp_names": [],
            }
            for family in ("ipv4", "ipv6")
        },
        "control": control,
    }


def _combined_receipt(count: int, *, enabled: bool, peers: list[str] | None = None):
    vector = _vector(enabled=enabled)
    expected = expected_sink_counters(vector)
    return combine_sink_receipt(
        vector=vector,
        tcp=expected["tcp"],
        udp=expected["udp"],
        dns=_raw_dns_receipt(count, peers=peers or [FIXTURE_TOPOLOGY["browser_addresses"][0]]),
        forbidden_ready_ns=1,
        dns_ready_ns=2,
        forbidden_stopped_ns=3,
        dns_stopped_ns=4,
    )


@pytest.mark.parametrize("count", [1, 2, 5])
def test_positive_requires_nonzero_wire_bound_transactions_not_a_fixed_count(count: int) -> None:
    evidence = _control_evidence(count)
    validated = _validate(evidence)
    assert validated == evidence and validated is not evidence
    assert validated["queries"] is not evidence["queries"]
    assert len(validated["queries"]) == len(validated["responses"]) == count


def test_negative_requires_zero_queries_and_responses_and_positive_cannot_be_vacuous() -> None:
    empty = _control_evidence(0)
    assert _validate(empty, enabled=False) == empty
    with pytest.raises(ValueError, match="witness"):
        _validate(empty)
    with pytest.raises(ValueError, match="witness"):
        _validate(_control_evidence(1), enabled=False)


@pytest.mark.parametrize("field", ["queries", "responses"])
@pytest.mark.parametrize("operation", ["remove", "duplicate"])
def test_every_query_has_exactly_one_recorded_reply(field: str, operation: str) -> None:
    evidence = _control_evidence(2)
    if operation == "remove":
        evidence[field].pop()
    else:
        evidence[field].append(copy.deepcopy(evidence[field][0]))
    with pytest.raises(ValueError, match="witness"):
        _validate(evidence)


def test_reply_order_and_transaction_id_are_not_interchangeable() -> None:
    evidence = _control_evidence(2)
    evidence["responses"].reverse()
    with pytest.raises(ValueError, match="query peer|wire contract"):
        _validate(evidence)


@pytest.mark.parametrize("field", ["rejected_messages", "send_errors"])
@pytest.mark.parametrize("value", [-1, 1, True, False, 0.0, "0", None])
@pytest.mark.parametrize("enabled", [False, True])
def test_any_rejection_send_error_or_noninteger_counter_prevents_a_pass(
    field: str, value: object, enabled: bool
) -> None:
    evidence = _control_evidence(int(enabled))
    evidence[field] = value
    with pytest.raises(ValueError, match=f"zero {field}"):
        _validate(evidence, enabled=enabled)


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("hostname", "attacker.test"),
    ("queries", ()), ("responses", None), ("extra", 0),
])
def test_evidence_identity_fields_and_inventory_types_are_closed(field: str, value: object) -> None:
    evidence = _control_evidence(1)
    evidence[field] = value
    with pytest.raises(ValueError):
        _validate(evidence)


@pytest.mark.parametrize("field,value", [
    ("transport", "tcp"), ("transport", "UDP"), ("peer_ip", "127.0.0.2"),
    ("peer_ip", "::ffff:127.0.0.1"), ("peer_port", 0), ("peer_port", 65536),
    ("peer_port", True), ("peer_port", 49000.0), ("message_hex", "00" * 11),
    ("message_hex", "aa" * 65536), ("message_hex", "f" * 25),
    ("message_hex", "GG" * 12), ("message_hex", "AA" * 12),
    ("message_hex", "00 " * 12), ("message_hex", b"00" * 12), ("extra", 1),
])
def test_wire_record_rejects_wrong_peer_port_transport_and_noncanonical_bytes(
    field: str, value: object
) -> None:
    record = _control_evidence(1)["queries"][0]
    record[field] = value
    with pytest.raises(ValueError):
        validate_dns_wire_record(record, allowed_peers=[_LOOPBACK])


@pytest.mark.parametrize("field,value", [("peer_ip", "127.0.0.2"), ("peer_port", 49001)])
def test_reply_must_use_exact_query_peer_even_when_both_peers_are_allowed(
    field: str, value: object
) -> None:
    evidence = _control_evidence(1)
    evidence["responses"][0][field] = value
    with pytest.raises(ValueError, match="query peer"):
        validate_dns_control_evidence(
            evidence, hostname=_HOSTNAME, allowed_peers=[_LOOPBACK, "127.0.0.2"], enabled=True
        )


@pytest.mark.parametrize("mutation", ["query-hostname", "query-type", "reply-id", "reply-rcode",
                                      "reply-ttl", "reply-trailing-data", "query-malformed"])
def test_messages_are_validated_and_replies_are_regenerated_from_exact_query(mutation: str) -> None:
    evidence = _control_evidence(1)
    if mutation == "query-hostname":
        wire = _query(hostname="attacker.test")
        evidence["queries"][0]["message_hex"] = wire.hex()
        evidence["responses"][0]["message_hex"] = dns_control_nxdomain_response(
            wire, hostname="attacker.test"
        ).hex()
    elif mutation == "query-type":
        evidence["queries"][0]["message_hex"] = _query(qtype=65).hex()
    elif mutation == "query-malformed":
        evidence["queries"][0]["message_hex"] = (b"\0" * 12).hex()
    else:
        response = bytearray.fromhex(evidence["responses"][0]["message_hex"])
        if mutation == "reply-id":
            response[1] ^= 1
        elif mutation == "reply-rcode":
            response[3] &= 0xF0
        elif mutation == "reply-ttl":
            response[len(_query()) + 9] = 1
        else:
            response.append(0)
        evidence["responses"][0]["message_hex"] = response.hex()
    with pytest.raises(ValueError):
        _validate(evidence)


def test_transaction_key_hashes_exact_wire_bytes_and_retains_peer_identity() -> None:
    query = _query()
    record = dns_wire_record(query, (_LOOPBACK, 49152), transport="udp")
    assert dns_wire_transaction_key(record) == (
        "udp", _LOOPBACK, 49152, hashlib.sha256(query).hexdigest()
    )
    changed = dict(record, message_hex=_query(2).hex())
    assert dns_wire_transaction_key(changed)[3] != dns_wire_transaction_key(record)[3]
    response = dns_control_nxdomain_response(query, hostname=_HOSTNAME)
    assert dns_wire_transaction_key(dict(record, message_hex=response.hex()))[3] == (
        hashlib.sha256(response).hexdigest()
    )


def test_socket_wire_record_normalises_mapped_ipv4_addresses() -> None:
    record = dns_wire_record(_query(), ("::ffff:127.0.0.1", 49152, 0, 0), transport="udp")
    assert record["peer_ip"] == _LOOPBACK
    assert validate_dns_wire_record(record, allowed_peers=[_LOOPBACK]) == record


@pytest.mark.parametrize("count", [1, 2, 5])
@pytest.mark.parametrize("dual_stack", [False, True])
def test_schema_two_sink_derives_actual_counts_and_ip_families_from_wire(
    count: int, dual_stack: bool
) -> None:
    peers = FIXTURE_TOPOLOGY["browser_addresses"] if dual_stack else [
        FIXTURE_TOPOLOGY["browser_addresses"][0]
    ]
    receipt = _combined_receipt(count, enabled=True, peers=peers)
    assert receipt["schema_version"] == 2
    assert receipt["dns"]["udp_queries_received"] == count
    assert receipt["dns"]["tcp_queries_received"] == 0
    assert receipt["dns"]["query_names"] == [_HOSTNAME] * count
    assert receipt["dns"]["ip_versions"]["ipv6"]["udp_queries_received"] == (
        count // 2 if dual_stack else 0
    )
    assert validate_sink_receipt(receipt, vector=_vector(enabled=True)) == receipt


def test_schema_two_disabled_sink_is_empty_and_positive_is_not() -> None:
    receipt = _combined_receipt(0, enabled=False)
    assert receipt["schema_version"] == 2
    assert receipt["dns"]["udp_queries_received"] == 0
    assert not receipt["dns"]["control"]["queries"]
    for count, enabled in [(0, True), (1, False)]:
        with pytest.raises(ValueError, match="witness"):
            _combined_receipt(count, enabled=enabled)


@pytest.mark.parametrize("count", [0, 1, 2, 5])
def test_historical_schema_one_retains_exact_three_positive_queries(count: int) -> None:
    vector = _vector(enabled=True)
    historical = expected_sink_counters(vector)
    assert historical["schema_version"] == 1
    assert historical["dns"]["udp_queries_received"] == 3
    assert validate_sink_receipt(historical, vector=vector) == historical
    altered = copy.deepcopy(historical)
    altered["dns"]["udp_queries_received"] = count
    altered["dns"]["query_names"] = [_HOSTNAME] * count
    altered["dns"]["ip_versions"]["ipv4"]["udp_queries_received"] = count
    altered["dns"]["ip_versions"]["ipv4"]["query_names"] = [_HOSTNAME] * count
    with pytest.raises(ValueError, match="counters differ"):
        validate_sink_receipt(altered, vector=vector)


def test_schema_two_refuses_unrelated_vector_and_schema_one_refuses_control_field() -> None:
    receipt = _combined_receipt(0, enabled=False)
    unrelated = vector_by_id("constructor--page--websocket")
    receipt["vector_id"] = unrelated.vector_id
    with pytest.raises(ValueError, match="not valid for this vector"):
        validate_sink_receipt(receipt, vector=unrelated)
    receipt = _combined_receipt(0, enabled=False)
    receipt["schema_version"] = 1
    with pytest.raises(ValueError, match="DNS sink fields"):
        validate_sink_receipt(receipt, vector=_vector(enabled=False))


@pytest.mark.parametrize("mutation", ["count", "names", "family", "tcp", "response-missing",
                                      "bad-hash-field", "wrong-peer"])
def test_schema_two_sink_counters_cannot_contradict_independent_wire(mutation: str) -> None:
    receipt = _combined_receipt(2, enabled=True)
    dns = receipt["dns"]
    if mutation == "count":
        dns["udp_queries_received"] = dns["ip_versions"]["ipv4"]["udp_queries_received"] = 1
        dns["query_names"] = dns["ip_versions"]["ipv4"]["query_names"] = [_HOSTNAME]
    elif mutation == "names":
        dns["query_names"] = dns["ip_versions"]["ipv4"]["query_names"] = ["attacker.test"] * 2
    elif mutation == "family":
        dns["ip_versions"]["ipv4"], dns["ip_versions"]["ipv6"] = (
            dns["ip_versions"]["ipv6"], dns["ip_versions"]["ipv4"]
        )
    elif mutation == "tcp":
        dns["udp_queries_received"] = dns["ip_versions"]["ipv4"]["udp_queries_received"] = 1
        dns["tcp_queries_received"] = dns["ip_versions"]["ipv4"]["tcp_queries_received"] = 1
    elif mutation == "response-missing":
        dns["control"]["responses"].pop()
    elif mutation == "bad-hash-field":
        dns["control"]["queries"][0]["message_sha256"] = "0" * 64
    else:
        for role in ("queries", "responses"):
            dns["control"][role][0]["peer_ip"] = _LOOPBACK
    with pytest.raises(ValueError):
        validate_sink_receipt(receipt, vector=_vector(enabled=True))


def test_real_udp_control_sink_replies_nxdomain_and_independently_records_both_wires() -> None:
    sink = IndependentDnsSink(_LOOPBACK, 0, control_hostname=_HOSTNAME)
    sink.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind((_LOOPBACK, 0))
            client.settimeout(1)
            peer = client.getsockname()
            request = _query(42, qtype=65)
            client.sendto(request, (_LOOPBACK, sink.port))
            response, sender = client.recvfrom(4096)
            assert sender == (_LOOPBACK, sink.port)
            decoded = dpkt.dns.DNS(response)
            assert decoded.id == 42 and decoded.rcode == 3 and decoded.aa == 1
            assert decoded.qd[0].type == 65 and not decoded.an
    finally:
        receipt = sink.stop()
    assert receipt["udp_names"] == [_HOSTNAME] and receipt["tcp_names"] == []
    assert receipt["control"]["queries"] == [dns_wire_record(request, peer, transport="udp")]
    assert receipt["control"]["responses"] == [dns_wire_record(response, peer, transport="udp")]
    assert _validate(receipt["control"]) == receipt["control"]


@pytest.mark.parametrize("message", [b"malformed", _query(hostname="attacker.test")])
def test_real_udp_bad_control_messages_are_not_answered_and_cannot_validate(message: bytes) -> None:
    sink = IndependentDnsSink(_LOOPBACK, 0, control_hostname=_HOSTNAME)
    sink.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.1)
            client.sendto(message, (_LOOPBACK, sink.port))
            with pytest.raises(TimeoutError):
                client.recvfrom(4096)
    finally:
        receipt = sink.stop()
    assert receipt["control"]["rejected_messages"] >= 1
    assert receipt["control"]["responses"] == []
    for enabled in (False, True):
        with pytest.raises(ValueError, match="rejected_messages"):
            _validate(receipt["control"], enabled=enabled)


@pytest.mark.parametrize("message", [b"", b"\0", b"\0\x20short", b"\0\x04oops",
                                    struct.pack("!H", len(_query())) + _query()])
def test_any_control_tcp_connection_including_malformed_or_empty_is_rejected(
    message: bytes,
) -> None:
    sink = IndependentDnsSink(_LOOPBACK, 0, control_hostname=_HOSTNAME)
    sink.start()
    try:
        with socket.create_connection((_LOOPBACK, sink.port), timeout=1) as client:
            client.sendall(message)
            client.shutdown(socket.SHUT_WR)
            # Wait for the sink's handling of this accepted connection, not a
            # guessed sleep or a mutable-state polling shortcut.
            assert client.recv(4096) == b""
    finally:
        receipt = sink.stop()
    assert receipt["control"]["rejected_messages"] == 1
    assert receipt["control"]["queries"] == receipt["control"]["responses"] == []
    with pytest.raises(ValueError, match="rejected_messages"):
        _validate(receipt["control"], enabled=False)


def test_default_passive_sink_retains_original_udp_tcp_receipt_and_sends_no_reply() -> None:
    sink = IndependentDnsSink(_LOOPBACK, 0)
    sink.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.1)
            client.sendto(_query(), (_LOOPBACK, sink.port))
            with pytest.raises(TimeoutError):
                client.recvfrom(4096)
        wire = _query(2)
        with socket.create_connection((_LOOPBACK, sink.port), timeout=1) as client:
            client.sendall(struct.pack("!H", len(wire)) + wire)
            client.shutdown(socket.SHUT_WR)
            assert client.recv(4096) == b""
    finally:
        receipt = sink.stop()
    assert set(receipt) == {"udp_names", "tcp_names", "ip_versions"}
    assert receipt["udp_names"] == receipt["tcp_names"] == [_HOSTNAME]
    assert receipt["ip_versions"]["ipv4"] == {
        "udp_names": [_HOSTNAME], "tcp_names": [_HOSTNAME]
    }
    assert receipt["ip_versions"]["ipv6"] == {"udp_names": [], "tcp_names": []}


def _failed_send(_message, _address):
    raise OSError("send")


@pytest.mark.parametrize("send", [lambda _message, _address: 0, _failed_send])
def test_sink_records_send_failure_without_fabricating_a_response(
    monkeypatch: pytest.MonkeyPatch, send: Callable
) -> None:
    import qcsd_lab.browser_egress_fixture as fixture

    sink = IndependentDnsSink(_LOOPBACK, 0, control_hostname=_HOSTNAME)

    class Datagram:
        def recvfrom(self, _size):
            return _query(), (_LOOPBACK, 49152)

        def sendto(self, message, address):
            return send(message, address)

    datagram = Datagram()
    sink._udp = datagram
    sink._tcp = object()

    def ready(_read, _write, _error, _timeout):
        sink._stop.set()
        return [datagram], [], []

    monkeypatch.setattr(fixture.select, "select", ready)
    sink._serve()
    assert sink._control["send_errors"] == 1
    assert len(sink._control["queries"]) == 1 and sink._control["responses"] == []
    with pytest.raises(ValueError, match="send_errors"):
        _validate(sink._control)


@pytest.mark.parametrize("shutdown", [False, True])
def test_udp_receive_failure_is_rejected_unless_it_is_deliberate_shutdown(
    monkeypatch: pytest.MonkeyPatch, shutdown: bool
) -> None:
    import qcsd_lab.browser_egress_fixture as fixture

    sink = IndependentDnsSink(_LOOPBACK, 0, control_hostname=_HOSTNAME)

    class Datagram:
        def recvfrom(self, _size):
            if shutdown:
                sink._stop.set()
            raise OSError("closed socket")

    sink._udp = Datagram()
    sink._tcp = object()
    calls = 0

    def ready(_read, _write, _error, _timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            return [sink._udp], [], []
        sink._stop.set()
        return [], [], []

    monkeypatch.setattr(fixture.select, "select", ready)
    sink._serve()
    assert sink._control["rejected_messages"] == int(not shutdown)
    if shutdown:
        assert _validate(sink._control, enabled=False) == sink._control
    else:
        with pytest.raises(ValueError, match="rejected_messages"):
            _validate(sink._control, enabled=False)


@pytest.mark.parametrize("error_type", [OSError, ValueError])
@pytest.mark.parametrize("shutdown", [False, True])
def test_select_failure_is_rejected_unless_it_is_deliberate_shutdown(
    monkeypatch: pytest.MonkeyPatch, error_type: type[Exception], shutdown: bool
) -> None:
    import qcsd_lab.browser_egress_fixture as fixture

    sink = IndependentDnsSink(_LOOPBACK, 0, control_hostname=_HOSTNAME)
    sink._udp = object()
    sink._tcp = object()

    def fail(_read, _write, _error, _timeout):
        if shutdown:
            sink._stop.set()
        raise error_type("bad descriptor")

    monkeypatch.setattr(fixture.select, "select", fail)
    if shutdown:
        sink._serve()
        assert _validate(sink._control, enabled=False) == sink._control
    else:
        with pytest.raises(error_type, match="bad descriptor"):
            sink._serve()
        assert sink._control["rejected_messages"] == 1
        with pytest.raises(ValueError, match="rejected_messages"):
            _validate(sink._control, enabled=False)
