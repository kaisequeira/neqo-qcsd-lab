"""Reconcile all four legs of the isolated DNS-prefetch control.

This is deliberately not a general DNS transaction matcher. Docker's embedded
resolver changes socket ports, but the bounded query and compressed NXDOMAIN
reply used here retain their complete DNS wire bytes. Unknown routes, missing
legs and unexplained byte changes fail; no namespace-visible copy is discarded.

The forwarding and NAT contract is reviewed against Moby docker-v29.0.1,
commit 198b5e3ed55aa0bcde02ef4502afa7549ad8d355: daemon/libnetwork/resolver.go,
resolver_unix.go and vendor/github.com/miekg/dns/msg.go. The pinned packer leaves
the helper's question, parent-suffix SOA pointer and root names unchanged.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .browser_egress_dns import parse_dns_control_query
from .browser_egress_dns_evidence import validate_dns_control_evidence

DNS_CONTROL_PACKET_FIELDS = frozenset({
    "frame_number", "src", "dst", "src_port", "dst_port", "ip_version",
    "transport", "dns_kind", "dns_name", "dns_id", "dns_type", "dns_class",
    "dns_rcode", "dns_payload_sha256", "payload_bytes",
})
DNS_CONTROL_PACKET_ROUTES = (
    "resolver-query", "sink-query", "sink-response", "resolver-response",
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def dns_control_packet_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve the DNS-relevant projection of one decoded outer UDP packet."""

    return {key: record.get(key) for key in DNS_CONTROL_PACKET_FIELDS}


def dns_control_packet_route(
    packet: Mapping[str, Any],
    *,
    browser_addresses: Sequence[str],
    sink_addresses: Sequence[str],
) -> str | None:
    if packet["transport"] != "udp":
        return None
    if packet["dns_kind"] == "query":
        if packet["src"] == "127.0.0.1" and packet["dst"] == "127.0.0.11":
            return "resolver-query"
        if (
            packet["src"] in browser_addresses and packet["dst"] in sink_addresses
            and packet["dst_port"] == 53
        ):
            return "sink-query"
    if packet["dns_kind"] == "response":
        if (
            packet["src"] == "127.0.0.11" and packet["dst"] == "127.0.0.1"
            and packet["src_port"] == 53
        ):
            return "resolver-response"
        if (
            packet["src"] in sink_addresses and packet["dst"] in browser_addresses
            and packet["src_port"] == 53
        ):
            return "sink-response"
    return None


def _message_key(packet: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(packet[key] for key in (
        "dns_id", "dns_name", "dns_type", "dns_class",
        "dns_payload_sha256", "payload_bytes",
    ))


def _peer_question_key(packet: Mapping[str, Any]) -> tuple[Any, ...]:
    peer = "src" if packet["dns_kind"] == "query" else "dst"
    return (
        packet[peer], packet[f"{peer}_port"],
        packet["dns_id"], packet["dns_name"], packet["dns_type"], packet["dns_class"],
    )


def validate_dns_control_packets(
    value: object,
    *,
    hostname: str,
    browser_addresses: Sequence[str],
    sink_addresses: Sequence[str],
    enabled: bool,
) -> dict[str, list[dict[str, Any]]]:
    """Account for every packet and preserve multiplicity across all four legs."""

    if type(enabled) is not bool or not isinstance(value, list):
        raise ValueError("DNS packet inventory or enabled policy is invalid")
    routes: dict[str, list[dict[str, Any]]] = {
        route: [] for route in DNS_CONTROL_PACKET_ROUTES
    }
    last_frame = 0
    for packet in value:
        if not isinstance(packet, Mapping) or set(packet) != DNS_CONTROL_PACKET_FIELDS:
            raise ValueError("DNS packet projection fields are invalid")
        for key, minimum, maximum in (
            ("frame_number", 1, None), ("src_port", 1, 65535),
            ("dst_port", 1, 65535), ("dns_id", 0, 65535),
            ("dns_type", 1, 65535), ("dns_class", 1, 1),
            ("dns_rcode", 0, 15), ("payload_bytes", 12, 4096),
        ):
            item = packet[key]
            if type(item) is not int or item < minimum or (
                maximum is not None and item > maximum
            ):
                raise ValueError(f"DNS packet {key} is invalid")
        if packet["frame_number"] <= last_frame:
            raise ValueError("DNS packet inventory is not in unique frame order")
        last_frame = packet["frame_number"]
        if type(packet["ip_version"]) is not int:
            raise ValueError("DNS packet IP version is invalid")
        for key in ("src", "dst"):
            if not isinstance(packet[key], str):
                raise ValueError("DNS packet address is invalid")
            address = ipaddress.ip_address(packet[key])
            if str(address) != packet[key] or address.version != packet["ip_version"]:
                raise ValueError("DNS packet address or family is inconsistent")
        digest = packet["dns_payload_sha256"]
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise ValueError("DNS packet lacks its complete wire digest")
        if packet["dns_name"] != hostname or packet["dns_type"] in {
            41, 249, 250, 251, 252, 253, 254,
        }:
            raise ValueError("DNS packet question is not approved")
        route = dns_control_packet_route(
            packet, browser_addresses=browser_addresses, sink_addresses=sink_addresses
        )
        if route is None or packet["dns_rcode"] != (
            0 if packet["dns_kind"] == "query" else 3
        ):
            raise ValueError("DNS packet route or NXDOMAIN response is not approved")
        routes[route].append(dict(packet))
    count = len(routes["sink-query"])
    if bool(count) != enabled or any(len(packets) != count for packets in routes.values()):
        raise ValueError("DNS packet evidence lacks a complete four-leg witness")
    if enabled and len({p["dst_port"] for p in routes["resolver-query"]}) != 1:
        raise ValueError("DNS resolver queries do not share one observed listener port")
    for left, right in (
        ("resolver-query", "sink-query"), ("sink-response", "resolver-response"),
    ):
        if Counter(map(_message_key, routes[left])) != Counter(map(_message_key, routes[right])):
            raise ValueError("DNS resolver and sink message bytes do not reconcile")
    for prefix in ("resolver", "sink"):
        if Counter(map(_peer_question_key, routes[f"{prefix}-query"])) != Counter(
            map(_peer_question_key, routes[f"{prefix}-response"])
        ):
            raise ValueError("DNS packet queries and replies disagree on peer/question")
    return routes


def reconcile_dns_control_packets(
    packets: object,
    control: object,
    *,
    hostname: str,
    browser_addresses: Sequence[str],
    sink_addresses: Sequence[str],
    enabled: bool,
) -> None:
    """Bind socket-observed full bytes to the PCAP, not just aggregate counts."""

    routes = validate_dns_control_packets(
        packets, hostname=hostname, browser_addresses=browser_addresses,
        sink_addresses=sink_addresses, enabled=enabled,
    )
    evidence = validate_dns_control_evidence(
        control, hostname=hostname, allowed_peers=browser_addresses, enabled=enabled,
    )
    expected: dict[str, Counter] = {"query": Counter(), "response": Counter()}
    replies_by_query: dict[str, tuple[str, int]] = {}
    for query, response in zip(evidence["queries"], evidence["responses"], strict=True):
        question = parse_dns_control_query(bytes.fromhex(query["message_hex"]), hostname=hostname)
        for kind, wire in (("query", query), ("response", response)):
            message = bytes.fromhex(wire["message_hex"])
            expected[kind][(
                wire["peer_ip"], wire["peer_port"], question.identifier,
                question.name, question.qtype, question.qclass,
                hashlib.sha256(message).hexdigest(), len(message),
            )] += 1
        replies_by_query[hashlib.sha256(bytes.fromhex(query["message_hex"])).hexdigest()] = (
            hashlib.sha256(bytes.fromhex(response["message_hex"])).hexdigest(),
            len(bytes.fromhex(response["message_hex"])),
        )
    for kind in ("query", "response"):
        observed = Counter(
            (*_peer_question_key(packet), packet["dns_payload_sha256"], packet["payload_bytes"])
            for packet in routes[f"sink-{kind}"]
        )
        if observed != expected[kind]:
            raise ValueError("DNS PCAP and independent sink wire inventories differ")
    # The external and local byte multisets are already equal. Also bind each
    # local reply's exact expected bytes to its own query port, so swapped
    # replies cannot hide behind aggregate equality or a reused DNS ID.
    expected_local = Counter(
        (*_peer_question_key(packet), *replies_by_query[packet["dns_payload_sha256"]])
        for packet in routes["resolver-query"]
    )
    observed_local = Counter(
        (*_peer_question_key(packet), packet["dns_payload_sha256"], packet["payload_bytes"])
        for packet in routes["resolver-response"]
    )
    if observed_local != expected_local:
        raise ValueError("DNS resolver replies do not bind to their exact local queries")
