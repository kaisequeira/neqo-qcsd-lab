"""Independent, wire-bound evidence for the isolated DNS-prefetch control.

Browser DNS transactions are not an exact-count emitter: a single prefetch can
ask several question types.  The positive witness therefore requires a real
query and an exact authoritative reply for every observed query.  The disabled
member of the pair must remain completely silent.  No other DNS destination or
hostname is authorised by this contract.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .browser_egress_dns import dns_control_nxdomain_response

DNS_CONTROL_EVIDENCE_SCHEMA_VERSION = 1
DNS_CONTROL_RESPONSE_POLICY = {
    "schema_version": 1,
    "response": "authoritative-nxdomain-zero-ttl-soa",
    "recursion": False,
    "forwarding": False,
    "positive_witness": "nonzero-approved-queries-with-exact-wire-bound-replies",
    "negative_witness": "zero-queries-and-zero-replies",
    "query_count": "observed-not-fixed",
    "packet_reconciliation": "all-sink-transactions-and-resolver-legs",
}


def empty_dns_control_evidence(hostname: str) -> dict[str, Any]:
    return {
        "schema_version": DNS_CONTROL_EVIDENCE_SCHEMA_VERSION,
        "hostname": hostname,
        "queries": [],
        "responses": [],
        "rejected_messages": 0,
        "send_errors": 0,
    }


def dns_wire_record(message: bytes, address: tuple[Any, ...], *, transport: str) -> dict[str, Any]:
    """Record the bytes and peer from a socket call, not from packet analysis."""

    peer = ipaddress.ip_address(address[0])
    if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped is not None:
        peer = peer.ipv4_mapped
    return {
        "transport": transport,
        "peer_ip": str(peer),
        "peer_port": address[1],
        "message_hex": message.hex(),
    }


def validate_dns_wire_record(value: object, *, allowed_peers: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "transport", "peer_ip", "peer_port", "message_hex"
    }:
        raise ValueError("DNS control wire record fields are invalid")
    if value["transport"] != "udp" or value["peer_ip"] not in allowed_peers:
        raise ValueError("DNS control wire record has an unauthorised peer or transport")
    if type(value["peer_port"]) is not int or not 1 <= value["peer_port"] <= 65_535:
        raise ValueError("DNS control peer port is invalid")
    encoded = value["message_hex"]
    if (
        not isinstance(encoded, str)
        or not 24 <= len(encoded) <= 131_070
        or len(encoded) % 2
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        raise ValueError("DNS control wire bytes are not canonical hexadecimal")
    return dict(value)


def validate_dns_control_evidence(
    value: object,
    *,
    hostname: str,
    allowed_peers: Sequence[str],
    enabled: bool,
) -> dict[str, Any]:
    """Validate all independent socket observations and exact paired replies."""

    if (
        not isinstance(value, Mapping)
        or set(value) != {
            "schema_version", "hostname", "queries", "responses",
            "rejected_messages", "send_errors",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != DNS_CONTROL_EVIDENCE_SCHEMA_VERSION
        or value["hostname"] != hostname
    ):
        raise ValueError("DNS control evidence identity or fields are invalid")
    for key in ("rejected_messages", "send_errors"):
        if type(value[key]) is not int or value[key] != 0:
            raise ValueError(f"DNS control requires zero {key}")
    queries, responses = value["queries"], value["responses"]
    if not isinstance(queries, list) or not isinstance(responses, list):
        raise ValueError("DNS control transaction inventories are invalid")
    if len(queries) != len(responses) or bool(queries) != enabled:
        raise ValueError("DNS control lacks its exact positive or negative witness")
    for query, response in zip(queries, responses):
        query = validate_dns_wire_record(query, allowed_peers=allowed_peers)
        response = validate_dns_wire_record(response, allowed_peers=allowed_peers)
        if any(query[key] != response[key] for key in ("transport", "peer_ip", "peer_port")):
            raise ValueError("DNS control reply does not match its query peer")
        expected = dns_control_nxdomain_response(
            bytes.fromhex(query["message_hex"]), hostname=hostname
        )
        if bytes.fromhex(response["message_hex"]) != expected:
            raise ValueError("DNS control reply differs from its authoritative wire contract")
    return json.loads(json.dumps(value))


def dns_wire_transaction_key(record: Mapping[str, Any]) -> tuple[str, str, int, str]:
    """Project independently checked bytes to the PCAP reconciliation key."""

    return (
        record["transport"],
        record["peer_ip"],
        record["peer_port"],
        hashlib.sha256(bytes.fromhex(record["message_hex"])).hexdigest(),
    )
