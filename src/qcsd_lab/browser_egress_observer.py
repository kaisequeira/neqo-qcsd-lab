"""Packet-level evidence for the browser-egress qualification gate.

The observer captures ``any`` without a BPF filter.  PCAP is primary evidence;
the sink counters are an independently produced corroboration.  This module
contains no Docker orchestration and never treats an HTTP hit as proof that a
forbidden transport was prevented.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any

from .browser_egress_dns_packets import (
    dns_control_packet_projection,
    dns_control_packet_route,
    reconcile_dns_control_packets,
    validate_dns_control_packets,
)
from .browser_egress_fixture import (
    FIXTURE_TOPOLOGY,
    BrowserEgressVector,
    validate_sink_receipt,
)
from .class_study import canonical_json_bytes
from .util import sha256_file

PACKET_RECORD_SCHEMA_VERSION = 2
PACKET_ANALYSIS_SCHEMA_VERSION = 5
HISTORICAL_PACKET_ANALYSIS_SCHEMA_VERSIONS = frozenset({3, 4})
SUPPORTED_PACKET_ANALYSIS_SCHEMA_VERSIONS = (
    HISTORICAL_PACKET_ANALYSIS_SCHEMA_VERSIONS | {PACKET_ANALYSIS_SCHEMA_VERSION}
)
CAPTURE_RECEIPT_SCHEMA_VERSION = 2
CAPTURE_ARTIFACT_TYPE = "qcsd-browser-egress-packet-capture"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

HISTORICAL_TSHARK_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.interface_id",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.len",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "dns.flags.response",
    "dns.qry.name",
)
TSHARK_FIELDS = HISTORICAL_TSHARK_FIELDS + (
    "frame.protocols",
    "ip.proto",
    "ipv6.nxt",
    "ipv6.hopopts.nxt",
    "ipv6.routing.nxt",
    "ipv6.fraghdr.nxt",
    "ipv6.dstopts.nxt",
    "ah.next_header",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "icmpv6.code",
    "dns.id",
    "dns.count.queries",
    "dns.qry.type",
    "dns.qry.class",
    "dns.flags.rcode",
    "udp.payload",
)
_V2_RECORD_FIELDS = {
    "outer_ip_protocol", "quoted_transport", "icmp_type", "icmp_code",
    "dns_id", "dns_type", "dns_class", "dns_rcode", "dns_payload_sha256",
}
_CONTROL_DIAGNOSTIC_FIELDS = {
    "decoded_control_packets", "control_ipv4_packets", "control_ipv6_packets",
    "icmp_packets", "icmpv6_packets", "quoted_tcp_packets", "quoted_udp_packets",
    "other_ip_packets",
}
_DNS_CONTROL_POLICIES = {"approved-dns-prefetch-zero", "approved-dns-prefetch-positive"}
_OBSERVED_DNS_CONTROL_FIELDS = {
    "dns_udp_queries", "dns_udp_queries_ipv4", "dns_udp_queries_ipv6",
    "dns_udp_datagrams", "dns_udp_datagrams_ipv4", "dns_udp_datagrams_ipv6",
    "dns_udp_responses", "dns_udp_responses_ipv4", "dns_udp_responses_ipv6",
    "dns_query_names", "dns_control_packets",
}


class PacketPolicyError(ValueError):
    """Well-formed packet evidence violates the selected vector's policy."""


def tshark_fields(analysis_schema_version: int) -> tuple[str, ...]:
    """Bind historical receipts to their original field/decoding contract."""

    if (
        type(analysis_schema_version) is not int
        or analysis_schema_version not in SUPPORTED_PACKET_ANALYSIS_SCHEMA_VERSIONS
    ):
        raise ValueError("browser-egress packet analysis schema is unsupported")
    if analysis_schema_version in HISTORICAL_PACKET_ANALYSIS_SCHEMA_VERSIONS:
        return HISTORICAL_TSHARK_FIELDS
    return TSHARK_FIELDS


def _tool_version_stdout_first_line(executable: Path, *, label: str) -> str:
    """Return a version banner without privilege-dependent stderr diagnostics."""

    try:
        version = subprocess.run(
            [str(executable), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"{label} version query timed out") from error
    lines = version.stdout.splitlines()
    if version.returncode != 0 or not lines or not lines[0].strip():
        raise ValueError(f"{label} version query failed")
    return lines[0]


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def safe_relative_artifact(root: Path, relative: object, *, label: str) -> Path:
    """Resolve one regular artifact beneath a non-symlink evidence root."""

    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError(f"{label} path is invalid")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"{label} path is not a canonical relative path")
    base = Path(os.path.abspath(root))
    try:
        metadata = base.lstat()
    except OSError as error:
        raise ValueError(f"{label} evidence root is unavailable") from error
    if base.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} evidence root is not a regular directory")
    candidate = base.joinpath(*pure.parts)
    current = base
    for part in pure.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ValueError(f"{label} artifact is unavailable: {relative}") from error
        if current.is_symlink():
            raise ValueError(f"{label} artifact has a symlink component: {relative}")
        if current != candidate and not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"{label} parent is not a directory: {relative}")
    if not stat.S_ISREG(candidate.lstat().st_mode):
        raise ValueError(f"{label} artifact is not a regular file: {relative}")
    if candidate.stat().st_nlink != 1:
        raise ValueError(f"{label} artifact must have exactly one hard link: {relative}")
    return candidate


def _canonical_ip(value: object, *, label: str) -> tuple[str, int]:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is invalid")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"{label} is invalid") from error
    canonical = str(parsed)
    if value != canonical:
        raise ValueError(f"{label} is not canonical")
    return canonical, parsed.version


def validate_packet_record(value: object) -> dict[str, Any]:
    fields = {
        "schema_version",
        "frame_number",
        "timestamp_ns",
        "interface_id",
        "ip_version",
        "src",
        "dst",
        "transport",
        "src_port",
        "dst_port",
        "tcp_syn",
        "tcp_ack",
        "payload_bytes",
        "dns_kind",
        "dns_name",
    }
    if not isinstance(value, Mapping):
        raise ValueError("browser-egress packet record fields are invalid")
    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version not in {1, 2}:
        raise ValueError("browser-egress packet record schema is invalid")
    if schema_version == 2:
        fields |= _V2_RECORD_FIELDS
    if set(value) != fields:
        raise ValueError("browser-egress packet record fields are invalid")
    _integer(value["frame_number"], label="frame number", minimum=1)
    _integer(value["timestamp_ns"], label="packet timestamp")
    interface_id = value["interface_id"]
    if interface_id is not None:
        _integer(interface_id, label="interface ID")
    src, src_version = _canonical_ip(value["src"], label="packet source address")
    dst, dst_version = _canonical_ip(value["dst"], label="packet destination address")
    if src_version != dst_version or value["ip_version"] != src_version:
        raise ValueError("browser-egress packet IP family is inconsistent")
    transport = value["transport"]
    transports = {"tcp", "udp"} if schema_version == 1 else {
        "tcp", "udp", "icmp", "icmpv6", "other",
    }
    if transport not in transports:
        raise ValueError("browser-egress packet transport is invalid")
    for key in ("src_port", "dst_port"):
        if transport not in {"tcp", "udp"}:
            if value[key] is not None:
                raise ValueError("control packet cannot carry transport ports")
            continue
        port = _integer(value[key], label=f"packet {key}")
        if port > 65_535:
            raise ValueError(f"packet {key} exceeds 65535")
    for key in ("tcp_syn", "tcp_ack"):
        if type(value[key]) is not bool:
            raise ValueError(f"packet {key} must be a boolean")
    if transport != "tcp" and (value["tcp_syn"] or value["tcp_ack"]):
        raise ValueError("non-TCP packet cannot carry TCP flags")
    _integer(value["payload_bytes"], label="packet payload bytes")
    dns_kind = value["dns_kind"]
    dns_name = value["dns_name"]
    if dns_kind not in {"none", "query", "response"}:
        raise ValueError("browser-egress packet DNS kind is invalid")
    if dns_kind == "none":
        if dns_name is not None:
            raise ValueError("non-DNS packet cannot carry a DNS name")
    elif not isinstance(dns_name, str) or not dns_name or dns_name != dns_name.lower().rstrip("."):
        raise ValueError("browser-egress packet DNS name is not canonical")
    if schema_version == 2:
        protocol = _integer(value["outer_ip_protocol"], label="outer IP protocol")
        if protocol > 255:
            raise ValueError("outer IP protocol exceeds 255")
        expected_transport = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(
            protocol, "other"
        )
        if transport != expected_transport or (
            transport in {"icmp", "icmpv6"}
            and src_version != {"icmp": 4, "icmpv6": 6}[transport]
        ):
            raise ValueError("outer IP protocol and transport are inconsistent")
        if value["quoted_transport"] not in {None, "tcp", "udp"}:
            raise ValueError("quoted transport is invalid")
        if transport in {"icmp", "icmpv6"}:
            for key in ("icmp_type", "icmp_code"):
                if _integer(value[key], label=key) > 255:
                    raise ValueError(f"{key} exceeds 255")
        elif any(value[key] is not None for key in (
            "icmp_type", "icmp_code", "quoted_transport",
        )):
            raise ValueError("non-ICMP packet cannot carry ICMP diagnostics")
        dns_fields = ("dns_id", "dns_type", "dns_class", "dns_rcode")
        if dns_kind == "none":
            if any(value[key] is not None for key in (*dns_fields, "dns_payload_sha256")):
                raise ValueError("non-DNS packet cannot carry DNS transaction fields")
        else:
            if transport not in {"tcp", "udp"}:
                raise ValueError("control packet cannot carry a DNS transaction")
            for key in dns_fields:
                if _integer(value[key], label=key) > (15 if key == "dns_rcode" else 65_535):
                    raise ValueError(f"{key} exceeds its wire range")
            if dns_kind == "query" and value["dns_rcode"] != 0:
                raise ValueError("DNS query cannot carry a response error code")
            if transport == "udp":
                _digest(value["dns_payload_sha256"], label="DNS payload SHA-256")
            elif value["dns_payload_sha256"] is not None:
                raise ValueError("TCP DNS packet cannot carry a UDP payload digest")
    return json.loads(canonical_json_bytes(value))


def _empty_analysis(
    vector_id: str, *, schema_version: int = PACKET_ANALYSIS_SCHEMA_VERSION
) -> dict[str, Any]:
    if (
        type(schema_version) is not int
        or schema_version not in SUPPORTED_PACKET_ANALYSIS_SCHEMA_VERSIONS
    ):
        raise ValueError("browser-egress packet analysis schema is unsupported")
    analysis = {
        "schema_version": schema_version,
        "vector_id": vector_id,
        "decoded_transport_packets": 0,
        "ipv4_packets": 0,
        "ipv6_packets": 0,
        "forbidden_tcp_initial_syn": 0,
        "forbidden_tcp_initial_syn_ipv4": 0,
        "forbidden_tcp_initial_syn_ipv6": 0,
        "forbidden_tcp_syn_ack": 0,
        "forbidden_tcp_syn_ack_ipv4": 0,
        "forbidden_tcp_syn_ack_ipv6": 0,
        "forbidden_tcp_payload_packets": 0,
        "forbidden_tcp_payload_packets_ipv4": 0,
        "forbidden_tcp_payload_packets_ipv6": 0,
        "forbidden_tcp_payload_bytes": 0,
        "forbidden_tcp_payload_bytes_ipv4": 0,
        "forbidden_tcp_payload_bytes_ipv6": 0,
        "forbidden_udp_datagrams": 0,
        "forbidden_udp_datagrams_ipv4": 0,
        "forbidden_udp_datagrams_ipv6": 0,
        "forbidden_udp_payload_bytes": 0,
        "forbidden_udp_payload_bytes_ipv4": 0,
        "forbidden_udp_payload_bytes_ipv6": 0,
        "dns_udp_queries": 0,
        "dns_udp_queries_ipv4": 0,
        "dns_udp_queries_ipv6": 0,
        "dns_tcp_queries": 0,
        "dns_tcp_queries_ipv4": 0,
        "dns_tcp_queries_ipv6": 0,
        "dns_udp_datagrams": 0,
        "dns_udp_datagrams_ipv4": 0,
        "dns_udp_datagrams_ipv6": 0,
        "dns_tcp_initial_syn": 0,
        "dns_tcp_initial_syn_ipv4": 0,
        "dns_tcp_initial_syn_ipv6": 0,
        "dns_tcp_payload_packets": 0,
        "dns_tcp_payload_packets_ipv4": 0,
        "dns_tcp_payload_packets_ipv6": 0,
        "dns_query_names": [],
        "approved_preconnect_initial_syn": 0,
        "approved_preconnect_syn_ack": 0,
        "approved_nel_error_initial_syn": 0,
        "unexpected_browser_egress_packets": 0,
    }
    if schema_version >= 4:
        analysis.update(
            {
                "timestamp_regressions": 0,
                "maximum_timestamp_regression_ns": 0,
            }
        )
    if schema_version >= 5:
        analysis.update(dict.fromkeys(_CONTROL_DIAGNOSTIC_FIELDS, 0))
        analysis["dns_control_packets"] = []
        for transport in ("udp", "tcp"):
            for suffix in ("", "_ipv4", "_ipv6"):
                analysis[f"dns_{transport}_responses{suffix}"] = 0
    return analysis


def analyse_packet_records(
    records: Sequence[Mapping[str, Any]],
    *,
    vector: BrowserEgressVector,
    analysis_schema_version: int = PACKET_ANALYSIS_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Reduce file-ordered IPv4/IPv6 TCP/UDP records to policy-relevant counts."""

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise ValueError("browser-egress packet records must be a sequence")
    analysis = _empty_analysis(
        vector.vector_id, schema_version=analysis_schema_version
    )
    browser = set(FIXTURE_TOPOLOGY["browser_addresses"])
    fixture = set(FIXTURE_TOPOLOGY["fixture_addresses"])
    forbidden = set(FIXTURE_TOPOLOGY["forbidden_sink_addresses"])
    dns_sinks = set(FIXTURE_TOPOLOGY["dns_sink_addresses"])
    paired_dns_control = analysis_schema_version >= 5 and vector.packet_policy in _DNS_CONTROL_POLICIES
    last_frame = 0
    last_time = -1
    names: list[str] = []
    for raw in records:
        record = validate_packet_record(raw)
        if analysis_schema_version < 5 and record["schema_version"] != 1:
            raise ValueError("historical packet analysis requires version-1 records")
        frame = record["frame_number"]
        timestamp = record["timestamp_ns"]
        # frame.number is the file/capture-order authority.  libpcap timestamps
        # are metadata and may legitimately regress when packets are timestamped
        # before different networking-stack paths enqueue them for capture.
        if frame <= last_frame:
            raise ValueError(
                "browser-egress packet record frame numbers are not strictly increasing"
            )
        if last_time >= 0 and timestamp < last_time:
            if analysis_schema_version == 3:
                # Schema 3 made timestamp monotonicity part of its acceptance
                # contract.  Retain that exact historical behaviour when old
                # receipts are replayed; only schema 4 adopts frame-number
                # ordering and records timestamp regressions diagnostically.
                raise ValueError("browser-egress packet records are not capture ordered")
            regression_ns = last_time - timestamp
            analysis["timestamp_regressions"] += 1
            analysis["maximum_timestamp_regression_ns"] = max(
                analysis["maximum_timestamp_regression_ns"], regression_ns
            )
        last_frame = frame
        last_time = timestamp
        if record["transport"] not in {"tcp", "udp"}:
            analysis["decoded_control_packets"] += 1
            analysis[f"control_ipv{record['ip_version']}_packets"] += 1
            if record["transport"] in {"icmp", "icmpv6"}:
                analysis[f"{record['transport']}_packets"] += 1
                if record["quoted_transport"] is not None:
                    analysis[f"quoted_{record['quoted_transport']}_packets"] += 1
            else:
                analysis["other_ip_packets"] += 1
                analysis["unexpected_browser_egress_packets"] += 1
            continue
        analysis["decoded_transport_packets"] += 1
        analysis[f"ipv{record['ip_version']}_packets"] += 1
        outbound = record["src"] in browser
        inbound = record["dst"] in browser
        to_forbidden = outbound and record["dst"] in forbidden
        from_forbidden = inbound and record["src"] in forbidden
        fixture_ports = {
            FIXTURE_TOPOLOGY["ports"]["fixture_https"],
            FIXTURE_TOPOLOGY["ports"]["fixture_cross_https"],
            FIXTURE_TOPOLOGY["ports"]["fixture_preconnect_https"],
            FIXTURE_TOPOLOGY["ports"]["fixture_nel_error_https"],
        }
        fixture_exchange = record["transport"] == "tcp" and (
            outbound
            and record["dst"] in fixture
            and record["dst_port"] in fixture_ports
            or inbound
            and record["src"] in fixture
            and record["src_port"] in fixture_ports
        )
        dns_exchange = record["transport"] in {"tcp", "udp"} and (
            outbound
            and record["dst"] in dns_sinks
            and record["dst_port"] == FIXTURE_TOPOLOGY["ports"]["dns"]
            or inbound
            and record["src"] in dns_sinks
            and record["src_port"] == FIXTURE_TOPOLOGY["ports"]["dns"]
        )
        control_route = None
        if paired_dns_control and (
            record["dns_kind"] != "none" or dns_exchange
            or {record["src"], record["dst"]} == {"127.0.0.1", "127.0.0.11"}
        ):
            projection = dns_control_packet_projection(record)
            analysis["dns_control_packets"].append(projection)
            control_route = dns_control_packet_route(
                projection, browser_addresses=browser, sink_addresses=dns_sinks
            )
        forbidden_tcp = record["transport"] == "tcp" and (
            to_forbidden
            and record["dst_port"] == FIXTURE_TOPOLOGY["ports"]["forbidden_tcp"]
            or from_forbidden
            and record["src_port"] == FIXTURE_TOPOLOGY["ports"]["forbidden_tcp"]
        )
        forbidden_udp = record["transport"] == "udp" and (
            to_forbidden
            and record["dst_port"] == FIXTURE_TOPOLOGY["ports"]["forbidden_udp"]
            or from_forbidden
            and record["src_port"] == FIXTURE_TOPOLOGY["ports"]["forbidden_udp"]
        )
        local_namespace = outbound and inbound
        if not (
            fixture_exchange
            or dns_exchange
            or forbidden_tcp
            or forbidden_udp
            or local_namespace
            or control_route is not None
        ):
            # The capture runs inside the browser network namespace on `any`.
            # Unknown source addresses therefore cannot be discarded as
            # "not-browser": they may be a second interface, a link-local
            # address, or another unreceipted route from the browser process.
            analysis["unexpected_browser_egress_packets"] += 1

        if record["transport"] == "tcp" and to_forbidden:
            if record["tcp_syn"] and not record["tcp_ack"]:
                analysis["forbidden_tcp_initial_syn"] += 1
                analysis[f"forbidden_tcp_initial_syn_ipv{record['ip_version']}"] += 1
            if record["payload_bytes"]:
                analysis["forbidden_tcp_payload_packets"] += 1
                analysis["forbidden_tcp_payload_bytes"] += record["payload_bytes"]
                analysis[f"forbidden_tcp_payload_packets_ipv{record['ip_version']}"] += 1
                analysis[f"forbidden_tcp_payload_bytes_ipv{record['ip_version']}"] += record[
                    "payload_bytes"
                ]
        if (
            record["transport"] == "tcp"
            and from_forbidden
            and record["tcp_syn"]
            and record["tcp_ack"]
        ):
            analysis["forbidden_tcp_syn_ack"] += 1
            analysis[f"forbidden_tcp_syn_ack_ipv{record['ip_version']}"] += 1
        if record["transport"] == "udp" and to_forbidden:
            analysis["forbidden_udp_datagrams"] += 1
            analysis["forbidden_udp_payload_bytes"] += record["payload_bytes"]
            analysis[f"forbidden_udp_datagrams_ipv{record['ip_version']}"] += 1
            analysis[f"forbidden_udp_payload_bytes_ipv{record['ip_version']}"] += record[
                "payload_bytes"
            ]

        if record["transport"] == "tcp":
            preconnect_port = FIXTURE_TOPOLOGY["ports"]["fixture_preconnect_https"]
            nel_error_port = FIXTURE_TOPOLOGY["ports"]["fixture_nel_error_https"]
            if (
                outbound
                and record["dst"] in fixture
                and record["dst_port"] == preconnect_port
                and record["tcp_syn"]
                and not record["tcp_ack"]
            ):
                analysis["approved_preconnect_initial_syn"] += 1
            if (
                inbound
                and record["src"] in fixture
                and record["src_port"] == preconnect_port
                and record["tcp_syn"]
                and record["tcp_ack"]
            ):
                analysis["approved_preconnect_syn_ack"] += 1
            if (
                outbound
                and record["dst"] in fixture
                and record["dst_port"] == nel_error_port
                and record["tcp_syn"]
                and not record["tcp_ack"]
            ):
                analysis["approved_nel_error_initial_syn"] += 1

        # The observer shares the browser network namespace.  Count every DNS
        # query visible there, including Docker's 127.0.0.1 -> 127.0.0.11
        # embedded-resolver leg.  A forwarded copy is intentionally counted a
        # second time: negative acceptance requires zero, while the direct
        # positive control bypasses the resolver and has exact one-per-family
        # expectations.
        if record["dns_kind"] == "query":
            if record["transport"] == "udp":
                analysis["dns_udp_queries"] += 1
                analysis[f"dns_udp_queries_ipv{record['ip_version']}"] += 1
            else:
                analysis["dns_tcp_queries"] += 1
                analysis[f"dns_tcp_queries_ipv{record['ip_version']}"] += 1
            names.append(record["dns_name"])
        elif analysis_schema_version >= 5 and record["dns_kind"] == "response":
            analysis[f"dns_{record['transport']}_responses"] += 1
            analysis[f"dns_{record['transport']}_responses_ipv{record['ip_version']}"] += 1
        if outbound and record["dst_port"] == FIXTURE_TOPOLOGY["ports"]["dns"]:
            if record["transport"] == "udp":
                analysis["dns_udp_datagrams"] += 1
                analysis[f"dns_udp_datagrams_ipv{record['ip_version']}"] += 1
            else:
                if record["tcp_syn"] and not record["tcp_ack"]:
                    analysis["dns_tcp_initial_syn"] += 1
                    analysis[f"dns_tcp_initial_syn_ipv{record['ip_version']}"] += 1
                if record["payload_bytes"]:
                    analysis["dns_tcp_payload_packets"] += 1
                    analysis[f"dns_tcp_payload_packets_ipv{record['ip_version']}"] += 1
    analysis["dns_query_names"] = sorted(names)
    return analysis


def expected_packet_analysis(
    vector: BrowserEgressVector,
    *,
    analysis_schema_version: int = PACKET_ANALYSIS_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Return policy counts; capture-wide packet/family totals remain observed."""

    expected = {
        key: value
        for key, value in _empty_analysis(
            vector.vector_id, schema_version=analysis_schema_version
        ).items()
        if key
        not in _CONTROL_DIAGNOSTIC_FIELDS | {
            "decoded_transport_packets",
            "ipv4_packets",
            "ipv6_packets",
            "timestamp_regressions",
            "maximum_timestamp_regression_ns",
        }
    }
    payload_bytes = FIXTURE_TOPOLOGY["positive_control_payload"]["bytes"]
    if vector.packet_policy == "positive-tcp-control":
        expected.update(
            {
                "forbidden_tcp_initial_syn": 2,
                "forbidden_tcp_initial_syn_ipv4": 1,
                "forbidden_tcp_initial_syn_ipv6": 1,
                "forbidden_tcp_syn_ack": 2,
                "forbidden_tcp_syn_ack_ipv4": 1,
                "forbidden_tcp_syn_ack_ipv6": 1,
                "forbidden_tcp_payload_packets": 2,
                "forbidden_tcp_payload_packets_ipv4": 1,
                "forbidden_tcp_payload_packets_ipv6": 1,
                "forbidden_tcp_payload_bytes": payload_bytes * 2,
                "forbidden_tcp_payload_bytes_ipv4": payload_bytes,
                "forbidden_tcp_payload_bytes_ipv6": payload_bytes,
            }
        )
    elif vector.packet_policy == "positive-udp-control":
        expected.update(
            {
                "forbidden_udp_datagrams": 2,
                "forbidden_udp_datagrams_ipv4": 1,
                "forbidden_udp_datagrams_ipv6": 1,
                "forbidden_udp_payload_bytes": payload_bytes * 2,
                "forbidden_udp_payload_bytes_ipv4": payload_bytes,
                "forbidden_udp_payload_bytes_ipv6": payload_bytes,
            }
        )
    elif vector.packet_policy == "positive-dns-control":
        expected.update(
            {
                "dns_udp_queries": 2,
                "dns_udp_queries_ipv4": 1,
                "dns_udp_queries_ipv6": 1,
                "dns_tcp_queries": 2,
                "dns_tcp_queries_ipv4": 1,
                "dns_tcp_queries_ipv6": 1,
                "dns_udp_datagrams": 2,
                "dns_udp_datagrams_ipv4": 1,
                "dns_udp_datagrams_ipv6": 1,
                "dns_tcp_initial_syn": 2,
                "dns_tcp_initial_syn_ipv4": 1,
                "dns_tcp_initial_syn_ipv6": 1,
                "dns_tcp_payload_packets": 2,
                "dns_tcp_payload_packets_ipv4": 1,
                "dns_tcp_payload_packets_ipv6": 1,
                "dns_query_names": sorted(FIXTURE_TOPOLOGY["positive_control_dns_names"]),
            }
        )
    elif vector.packet_policy == "approved-dns-prefetch-positive":
        if analysis_schema_version >= 5:
            # Browser/resolver query counts are observed. The complete four-leg
            # and independent socket-wire inventories are the exact witness.
            for key in _OBSERVED_DNS_CONTROL_FIELDS:
                expected.pop(key)
        else:
            count = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_positive_query_count"]
            name = FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"]
            expected.update(
                {
                    "dns_udp_queries": count,
                    "dns_udp_queries_ipv4": count,
                    "dns_udp_datagrams": count,
                    "dns_udp_datagrams_ipv4": count,
                    "dns_query_names": [name] * count,
                }
            )
    elif vector.packet_policy == "approved-preconnect-positive":
        expected.update(
            {
                "approved_preconnect_initial_syn": 1,
                "approved_preconnect_syn_ack": 1,
            }
        )
    if vector.packet_policy in {
        "approved-network-error-logging-zero",
        "approved-network-error-logging-positive",
    }:
        expected["approved_nel_error_initial_syn"] = 1
    return expected


def validate_packet_analysis(value: object, *, vector: BrowserEgressVector) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("browser-egress packet analysis fields are invalid")
    schema_version = value.get("schema_version")
    if (
        type(schema_version) is not int
        or schema_version not in SUPPORTED_PACKET_ANALYSIS_SCHEMA_VERSIONS
        or value.get("vector_id") != vector.vector_id
    ):
        raise ValueError("browser-egress packet analysis identity is invalid")
    expected_fields = set(
        _empty_analysis(vector.vector_id, schema_version=schema_version)
    )
    if set(value) != expected_fields:
        raise ValueError("browser-egress packet analysis fields are invalid")
    for key in expected_fields - {"vector_id", "dns_query_names", "dns_control_packets"}:
        if key == "schema_version":
            continue
        _integer(value[key], label=f"packet analysis {key}")
    if value["decoded_transport_packets"] != value["ipv4_packets"] + value["ipv6_packets"]:
        raise ValueError("browser-egress packet family counts do not reconcile")
    if schema_version >= 5:
        if value["decoded_control_packets"] != (
            value["control_ipv4_packets"] + value["control_ipv6_packets"]
        ) or value["decoded_control_packets"] != (
            value["icmp_packets"] + value["icmpv6_packets"] + value["other_ip_packets"]
        ) or value["quoted_tcp_packets"] + value["quoted_udp_packets"] > (
            value["icmp_packets"] + value["icmpv6_packets"]
        ):
            raise ValueError("browser-egress control packet diagnostics do not reconcile")
    if schema_version >= 4:
        regressions = value["timestamp_regressions"]
        maximum_regression = value["maximum_timestamp_regression_ns"]
        possible_adjacent_pairs = max(
            0, value["decoded_transport_packets"] + value.get("decoded_control_packets", 0) - 1
        )
        if (
            regressions > possible_adjacent_pairs
            or (regressions == 0) != (maximum_regression == 0)
        ):
            raise ValueError(
                "browser-egress packet timestamp-regression diagnostics are invalid"
            )
    names = value["dns_query_names"]
    if (
        not isinstance(names, list)
        or any(not isinstance(name, str) or name != name.lower().rstrip(".") for name in names)
        or names != sorted(names)
    ):
        raise ValueError("browser-egress packet DNS inventory is invalid")
    expected = expected_packet_analysis(
        vector, analysis_schema_version=schema_version
    )
    for key, wanted in expected.items():
        if value[key] != wanted:
            raise PacketPolicyError(f"browser-egress packet policy failed at {key}")
    if schema_version >= 5 and vector.packet_policy in _DNS_CONTROL_POLICIES:
        try:
            routes = validate_dns_control_packets(
                value["dns_control_packets"],
                hostname=FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"],
                browser_addresses=FIXTURE_TOPOLOGY["browser_addresses"],
                sink_addresses=FIXTURE_TOPOLOGY["dns_sink_addresses"],
                enabled=vector.packet_policy == "approved-dns-prefetch-positive",
            )
        except ValueError as error:
            raise PacketPolicyError(str(error)) from error
        queries = routes["resolver-query"] + routes["sink-query"]
        responses = routes["sink-response"] + routes["resolver-response"]
        if len(queries) + len(responses) > value["decoded_transport_packets"] or any(
            sum(p["ip_version"] == family for p in queries + responses) > value[f"ipv{family}_packets"]
            for family in (4, 6)
        ):
            raise PacketPolicyError("DNS packet inventory exceeds captured transport/family totals")
        inventories = {
            "dns_udp_queries": queries,
            "dns_udp_responses": responses,
            "dns_udp_datagrams": routes["sink-query"],
        }
        for key, packets in inventories.items():
            if value[key] != len(packets) or any(
                value[f"{key}_ipv{family}"] != sum(p["ip_version"] == family for p in packets)
                for family in (4, 6)
            ):
                raise PacketPolicyError(f"browser-egress DNS packet counts disagree at {key}")
        if value["dns_query_names"] != sorted(p["dns_name"] for p in queries):
            raise PacketPolicyError("browser-egress DNS names disagree with the packet inventory")
    return json.loads(canonical_json_bytes(value))


def reconcile_sink_and_packet_evidence(
    *, vector: BrowserEgressVector, analysis: object, sink: object
) -> None:
    packet = validate_packet_analysis(analysis, vector=vector)
    counters = validate_sink_receipt(sink, vector=vector)
    if packet["schema_version"] >= 5 and vector.packet_policy in _DNS_CONTROL_POLICIES:
        if counters["schema_version"] != 2:
            raise ValueError("current DNS packet evidence requires a schema-2 wire-bound sink")
        reconcile_dns_control_packets(
            packet["dns_control_packets"], counters["dns"]["control"],
            hostname=FIXTURE_TOPOLOGY["browser_service_controls"]["dns_exception_hostname"],
            browser_addresses=FIXTURE_TOPOLOGY["browser_addresses"],
            sink_addresses=FIXTURE_TOPOLOGY["dns_sink_addresses"],
            enabled=vector.packet_policy == "approved-dns-prefetch-positive",
        )
        # The independent sink sees only the external leg. Namespace totals
        # above deliberately retain both copies; never compare those to socket
        # arrivals, and never mutate the sealed analysis while projecting it.
        queries = [p for p in packet["dns_control_packets"] if (
            p["dns_kind"] == "query" and p["src"] in FIXTURE_TOPOLOGY["browser_addresses"]
        )]
        packet["dns_udp_queries"] = len(queries)
        packet["dns_query_names"] = sorted(p["dns_name"] for p in queries)
        for family in (4, 6):
            packet[f"dns_udp_queries_ipv{family}"] = sum(p["ip_version"] == family for p in queries)
    if packet["forbidden_tcp_syn_ack"] != counters["tcp"]["accepted_connections"]:
        raise ValueError("PCAP and sink disagree on accepted TCP connection count")
    if packet["forbidden_tcp_payload_bytes"] != counters["tcp"]["received_payload_bytes"]:
        raise ValueError("PCAP and sink disagree on received TCP payload bytes")
    if packet["forbidden_udp_datagrams"] != counters["udp"]["datagrams_received"]:
        raise ValueError("PCAP and sink disagree on received UDP datagrams")
    if packet["forbidden_udp_payload_bytes"] != counters["udp"]["payload_bytes_received"]:
        raise ValueError("PCAP and sink disagree on received UDP payload bytes")
    if packet["dns_udp_queries"] != counters["dns"]["udp_queries_received"]:
        raise ValueError("PCAP and sink disagree on UDP DNS queries")
    if packet["dns_tcp_queries"] != counters["dns"]["tcp_queries_received"]:
        raise ValueError("PCAP and sink disagree on TCP DNS queries")
    if packet["dns_query_names"] != counters["dns"]["query_names"]:
        raise ValueError("PCAP and sink disagree on DNS query names")
    for family in ("ipv4", "ipv6"):
        if (
            packet[f"forbidden_tcp_syn_ack_{family}"]
            != counters["tcp"]["ip_versions"][family]["accepted_connections"]
            or packet[f"forbidden_tcp_payload_bytes_{family}"]
            != counters["tcp"]["ip_versions"][family]["received_payload_bytes"]
            or packet[f"forbidden_udp_datagrams_{family}"]
            != counters["udp"]["ip_versions"][family]["datagrams_received"]
            or packet[f"forbidden_udp_payload_bytes_{family}"]
            != counters["udp"]["ip_versions"][family]["payload_bytes_received"]
            or packet[f"dns_udp_queries_{family}"]
            != counters["dns"]["ip_versions"][family]["udp_queries_received"]
            or packet[f"dns_tcp_queries_{family}"]
            != counters["dns"]["ip_versions"][family]["tcp_queries_received"]
        ):
            raise ValueError(f"PCAP and sink disagree on {family} evidence")


def tshark_command(
    pcap: Path,
    *,
    tshark: Path = Path("/usr/bin/tshark"),
    analysis_schema_version: int = PACKET_ANALYSIS_SCHEMA_VERSION,
) -> list[str]:
    fields = tshark_fields(analysis_schema_version)
    command = [
        str(tshark),
        "-n",
        "-r",
        str(pcap),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f" if analysis_schema_version < 5 else "occurrence=a",
    ]
    for field in fields:
        command.extend(("-e", field))
    return command


def _field_integer(value: str, *, label: str, default: int | None = None) -> int:
    if value == "" and default is not None:
        return default
    if not value.isdecimal():
        raise ValueError(f"tshark {label} is not an integer")
    return int(value)


def _historical_records_from_tshark_output(output: str) -> list[dict[str, Any]]:
    """Frozen schema-3/4 decoder, including historical dissector limitations."""

    records: list[dict[str, Any]] = []
    reader = csv.reader(output.splitlines(), delimiter="\t", quotechar='"')
    for columns in reader:
        if not columns or all(column == "" for column in columns):
            continue
        if len(columns) != len(HISTORICAL_TSHARK_FIELDS):
            raise ValueError("tshark packet row has the wrong field count")
        values = dict(zip(HISTORICAL_TSHARK_FIELDS, columns))
        ipv4 = values["ip.src"] or values["ip.dst"]
        src = values["ip.src"] if ipv4 else values["ipv6.src"]
        dst = values["ip.dst"] if ipv4 else values["ipv6.dst"]
        if not src or not dst:
            continue
        tcp = bool(values["tcp.srcport"] or values["tcp.dstport"])
        udp = bool(values["udp.srcport"] or values["udp.dstport"])
        if tcp == udp:
            continue
        try:
            timestamp_ns = int(Decimal(values["frame.time_epoch"]) * 1_000_000_000)
        except (InvalidOperation, ValueError) as error:
            raise ValueError("tshark frame timestamp is invalid") from error
        dns_response = values["dns.flags.response"]
        dns_name = values["dns.qry.name"].lower().rstrip(".") or None
        if dns_name is None:
            dns_kind = "none"
        elif dns_response == "1":
            dns_kind = "response"
        else:
            dns_kind = "query"
        if tcp:
            src_port = _field_integer(values["tcp.srcport"], label="TCP source port")
            dst_port = _field_integer(values["tcp.dstport"], label="TCP destination port")
            payload_bytes = _field_integer(values["tcp.len"], label="TCP payload", default=0)
        else:
            src_port = _field_integer(values["udp.srcport"], label="UDP source port")
            dst_port = _field_integer(values["udp.dstport"], label="UDP destination port")
            udp_length = _field_integer(values["udp.length"], label="UDP length")
            if udp_length < 8:
                raise ValueError("tshark UDP length is smaller than its header")
            payload_bytes = udp_length - 8
        interface = values["frame.interface_id"]
        record = {
            "schema_version": 1,
            "frame_number": _field_integer(values["frame.number"], label="frame number"),
            "timestamp_ns": timestamp_ns,
            "interface_id": (
                None if interface == "" else _field_integer(interface, label="interface ID")
            ),
            "ip_version": 4 if ipv4 else 6,
            "src": src,
            "dst": dst,
            "transport": "tcp" if tcp else "udp",
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_syn": values["tcp.flags.syn"] in {"1", "True"} if tcp else False,
            "tcp_ack": values["tcp.flags.ack"] in {"1", "True"} if tcp else False,
            "payload_bytes": payload_bytes,
            "dns_kind": dns_kind,
            "dns_name": dns_name,
        }
        records.append(validate_packet_record(record))
    return records


def _wire_integer(value: str, *, label: str, maximum: int = 65_535) -> int:
    if re.fullmatch(r"0x[0-9a-fA-F]+|[0-9]+", value) is None:
        raise ValueError(f"tshark {label} is not a wire integer")
    number = int(value, 16 if value.startswith("0x") else 10)
    if number > maximum:
        raise ValueError(f"tshark {label} exceeds its wire range")
    return number


def _wire_boolean(value: str, *, label: str) -> bool:
    if value not in {"0", "1", "False", "True"}:
        raise ValueError(f"tshark {label} is not a recognised boolean")
    return value in {"1", "True"}


def _outer_packet_layer(values: Mapping[str, list[str]]) -> tuple[int, int, int, list[str]] | None:
    """Find the first IP header, never a quoted or tunnelled transport header."""

    protocols = values["frame.protocols"]
    if len(protocols) != 1 or not protocols[0]:
        raise ValueError("tshark frame protocol stack is missing or ambiguous")
    stack = protocols[0].split(":")
    if any(not protocol for protocol in stack):
        raise ValueError("tshark frame protocol stack is malformed")
    ip_index = next((index for index, token in enumerate(stack) if token in {"ip", "ipv6"}), None)
    if ip_index is None:
        if any(values[key] for key in ("ip.src", "ipv6.src", "tcp.srcport", "udp.srcport")):
            raise ValueError("tshark network fields have no outer IP layer")
        return None
    family = 4 if stack[ip_index] == "ip" else 6
    header_field = "ip.proto" if family == 4 else "ipv6.nxt"
    if not values[header_field]:
        raise ValueError("tshark outer IP protocol field is missing")
    protocol = _wire_integer(values[header_field][0], label="outer IP protocol", maximum=255)
    extension_headers = {
        0: "ipv6.hopopts", 43: "ipv6.routing", 44: "ipv6.fraghdr",
        60: "ipv6.dstopts", 51: "ah",
    }
    position = ip_index + 1
    consumed: dict[str, int] = {}
    while protocol in extension_headers and (family == 6 or protocol == 51):
        token = extension_headers[protocol]
        field = "ah.next_header" if token == "ah" else f"{token}.nxt"
        occurrence = consumed.get(field, 0)
        if position >= len(stack) or stack[position] != token or occurrence >= len(values[field]):
            raise ValueError("tshark outer IP extension chain is incomplete or inconsistent")
        protocol = _wire_integer(values[field][occurrence], label=field, maximum=255)
        consumed[field] = occurrence + 1
        position += 1
    expected_token = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(protocol)
    if expected_token is not None and (position >= len(stack) or stack[position] != expected_token):
        raise ValueError("tshark outer IP protocol disagrees with its decoded transport")
    return family, protocol, position, stack


def _records_from_tshark_output(
    output: str,
    *,
    analysis_schema_version: int = PACKET_ANALYSIS_SCHEMA_VERSION,
) -> list[dict[str, Any]]:
    """Decode versioned TSV without treating ICMP quotes as new egress."""

    fields = tshark_fields(analysis_schema_version)
    if analysis_schema_version < 5:
        return _historical_records_from_tshark_output(output)
    records: list[dict[str, Any]] = []
    reader = csv.reader(output.splitlines(), delimiter="\t", quotechar='"', strict=True)
    try:
        for columns in reader:
            if not columns or all(column == "" for column in columns):
                continue
            if len(columns) != len(fields):
                raise ValueError("tshark packet row has the wrong field count")
            values = {
                field: ([] if column == "" else column.split(","))
                for field, column in zip(fields, columns)
            }
            if any(any(value == "" for value in group) for group in values.values()):
                raise ValueError("tshark packet row has an empty repeated field")

            def single(field: str, *, optional: bool = False) -> str:
                group = values[field]
                if not group and optional:
                    return ""
                if len(group) != 1:
                    raise ValueError(f"tshark {field} is missing or ambiguous")
                return group[0]

            def first(field: str) -> str:
                if not values[field]:
                    raise ValueError(f"tshark {field} is missing")
                return values[field][0]

            layer = _outer_packet_layer(values)
            if layer is None:
                continue
            family, protocol, position, stack = layer
            transport = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(protocol, "other")
            try:
                timestamp = Decimal(single("frame.time_epoch")) * 1_000_000_000
                if (
                    not timestamp.is_finite()
                    or timestamp < 0
                    or timestamp != timestamp.to_integral_value()
                ):
                    raise ValueError("timestamp is not an exact non-negative nanosecond")
                timestamp_ns = int(timestamp)
            except (InvalidOperation, ValueError, OverflowError) as error:
                raise ValueError("tshark frame timestamp is invalid") from error
            interface = single("frame.interface_id", optional=True)
            prefix = "ip" if family == 4 else "ipv6"
            record = {
                "schema_version": 2,
                "frame_number": _field_integer(single("frame.number"), label="frame number"),
                "timestamp_ns": timestamp_ns,
                "interface_id": (
                    None if not interface else _field_integer(interface, label="interface ID")
                ),
                "ip_version": family,
                "src": first(f"{prefix}.src"),
                "dst": first(f"{prefix}.dst"),
                "transport": transport,
                "outer_ip_protocol": protocol,
                "src_port": None,
                "dst_port": None,
                "tcp_syn": False,
                "tcp_ack": False,
                "payload_bytes": 0,
                "quoted_transport": None,
                "icmp_type": None,
                "icmp_code": None,
                "dns_kind": "none",
                "dns_name": None,
                "dns_id": None,
                "dns_type": None,
                "dns_class": None,
                "dns_rcode": None,
                "dns_payload_sha256": None,
            }
            if transport in {"icmp", "icmpv6"}:
                for key in ("type", "code"):
                    record[f"icmp_{key}"] = _wire_integer(
                        first(f"{transport}.{key}"), label=f"ICMP {key}", maximum=255
                    )
                # Only error messages quote earlier packets.  Their nested DNS
                # fields are diagnostic content, never a new query/response.
                error_types = {3, 4, 5, 11, 12} if family == 4 else {1, 2, 3, 4}
                quoted = stack[position + 1:]
                if record["icmp_type"] in error_types and any(
                    token in {"ip", "ipv6"} for token in quoted
                ):
                    record["quoted_transport"] = next(
                        (token for token in quoted if token in {"tcp", "udp"}), None
                    )
            elif transport in {"tcp", "udp"}:
                for key in ("src", "dst"):
                    record[f"{key}_port"] = _wire_integer(
                        first(f"{transport}.{key}port"), label=f"{transport} {key} port"
                    )
                if transport == "tcp":
                    record["payload_bytes"] = _field_integer(first("tcp.len"), label="TCP payload")
                    record["tcp_syn"] = _wire_boolean(first("tcp.flags.syn"), label="TCP SYN")
                    record["tcp_ack"] = _wire_boolean(first("tcp.flags.ack"), label="TCP ACK")
                else:
                    length = _wire_integer(first("udp.length"), label="UDP length")
                    if length < 8:
                        raise ValueError("tshark UDP length is smaller than its header")
                    record["payload_bytes"] = length - 8
                dns = position + 1 < len(stack) and stack[position + 1] == "dns"
                if dns:
                    response = _wire_boolean(single("dns.flags.response"), label="DNS response")
                    if _wire_integer(single("dns.count.queries"), label="DNS question count") != 1:
                        raise ValueError("tshark DNS transaction must contain exactly one question")
                    record["dns_kind"] = "response" if response else "query"
                    record["dns_name"] = single("dns.qry.name").lower().rstrip(".")
                    for key, field in (
                        ("dns_id", "dns.id"), ("dns_type", "dns.qry.type"),
                        ("dns_class", "dns.qry.class"),
                    ):
                        record[key] = _wire_integer(single(field), label=key)
                    rcode = single("dns.flags.rcode", optional=not response)
                    record["dns_rcode"] = _wire_integer(rcode or "0", label="DNS rcode", maximum=15)
                    if transport == "udp":
                        payload = single("udp.payload")
                        if re.fullmatch(
                            r"(?:[0-9a-fA-F]{2})+|(?:[0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}",
                            payload,
                        ) is None:
                            raise ValueError(
                                "tshark DNS UDP payload is not complete hexadecimal bytes"
                            )
                        payload_bytes = bytes.fromhex(payload.replace(":", ""))
                        if len(payload_bytes) != record["payload_bytes"]:
                            raise ValueError("tshark DNS UDP payload does not match UDP length")
                        record["dns_payload_sha256"] = hashlib.sha256(payload_bytes).hexdigest()
            records.append(validate_packet_record(record))
    except csv.Error as error:
        raise ValueError("tshark packet row is malformed TSV") from error
    return records


def analyse_pcap(
    pcap: Path,
    *,
    vector: BrowserEgressVector,
    tshark: Path = Path("/usr/bin/tshark"),
    analysis_schema_version: int = PACKET_ANALYSIS_SCHEMA_VERSION,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode one PCAP/PCAPNG with pinned tshark and return analysis/tool binding."""

    executable = Path(tshark)
    if executable.is_symlink() or not executable.is_file():
        raise ValueError("tshark executable is unavailable or a symlink")
    version_first_line = _tool_version_stdout_first_line(executable, label="tshark")
    command = tshark_command(
        Path(pcap), tshark=executable, analysis_schema_version=analysis_schema_version
    )
    decoded = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if decoded.returncode != 0:
        raise ValueError(f"tshark failed to decode capture: {decoded.stderr.strip()}")
    records = _records_from_tshark_output(
        decoded.stdout, analysis_schema_version=analysis_schema_version
    )
    analysis = analyse_packet_records(
        records,
        vector=vector,
        analysis_schema_version=analysis_schema_version,
    )
    tool = {
        "path": str(executable),
        "sha256": sha256_file(executable),
        "version_first_line": version_first_line,
        "fields": list(tshark_fields(analysis_schema_version)),
        "argv": [*command[:3], "<PCAP>", *command[4:]],
    }
    return analysis, tool


def validate_capture_receipt(
    value: object,
    *,
    vector: BrowserEgressVector,
    evidence_root: Path | None = None,
    deep: bool = False,
    tshark: Path = Path("/usr/bin/tshark"),
    dumpcap: Path = Path("/usr/bin/dumpcap"),
) -> dict[str, Any]:
    """Validate capture/drop/chronology evidence and optionally re-read PCAP."""

    fields = {
        "schema_version",
        "artifact_type",
        "vector_id",
        "pcap",
        "observer",
        "capture_process",
        "capture_tool",
        "chronology",
        "packet_decoder",
        "analysis",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress capture receipt fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != CAPTURE_RECEIPT_SCHEMA_VERSION
        or value["artifact_type"] != CAPTURE_ARTIFACT_TYPE
        or value["vector_id"] != vector.vector_id
    ):
        raise ValueError("browser-egress capture receipt identity is invalid")
    pcap = value["pcap"]
    if not isinstance(pcap, Mapping) or set(pcap) != {"path", "sha256", "size_bytes"}:
        raise ValueError("browser-egress PCAP binding fields are invalid")
    if not isinstance(pcap["path"], str):
        raise ValueError("browser-egress PCAP path is invalid")
    _digest(pcap["sha256"], label="PCAP SHA-256")
    _integer(pcap["size_bytes"], label="PCAP size", minimum=1)
    observer = value["observer"]
    if not isinstance(observer, Mapping) or canonical_json_bytes(observer) != canonical_json_bytes({
        "network_namespace": "browser",
        "interface": "any",
        "capture_filter": None,
        "privileged": False,
        "cap_drop": ["ALL"],
        "cap_add": ["CAP_NET_RAW"],
        "separate_container": True,
    }):
        raise ValueError("browser-egress observer topology is invalid")
    process = value["capture_process"]
    if not isinstance(process, Mapping) or set(process) != {
        "exit_code",
        "packets_captured",
        "packets_received",
        "packets_dropped_by_kernel",
        "packets_dropped_by_interface",
        "capture_path_drop_breakdown",
    }:
        raise ValueError("browser-egress capture process fields are invalid")
    for key in (
        "exit_code",
        "packets_captured",
        "packets_received",
        "packets_dropped_by_kernel",
        "packets_dropped_by_interface",
    ):
        _integer(process[key], label=f"capture process {key}")
    breakdown = process["capture_path_drop_breakdown"]
    if not isinstance(breakdown, Mapping) or set(breakdown) != {
        "pcap",
        "dumpcap",
        "flushed",
    }:
        raise ValueError("browser-egress capture drop-breakdown fields are invalid")
    for key in breakdown:
        _integer(breakdown[key], label=f"capture drop breakdown {key}")
    if (
        process["exit_code"] != 0
        or process["packets_captured"] < 1
        or process["packets_captured"] > process["packets_received"]
        or process["packets_dropped_by_kernel"]
        != breakdown["pcap"] + breakdown["dumpcap"] + breakdown["flushed"]
        or process["packets_dropped_by_kernel"] != 0
        or process["packets_dropped_by_interface"] != 0
        or any(breakdown.values())
    ):
        raise ValueError("browser-egress capture failed or dropped packets")
    capture_tool = value["capture_tool"]
    if not isinstance(capture_tool, Mapping) or set(capture_tool) != {
        "path",
        "sha256",
        "version_first_line",
        "argv",
    }:
        raise ValueError("browser-egress capture-tool binding fields are invalid")
    if (
        not isinstance(capture_tool["path"], str)
        or not capture_tool["path"].startswith("/")
        or not isinstance(capture_tool["version_first_line"], str)
        or not capture_tool["version_first_line"]
        or not isinstance(capture_tool["argv"], list)
        or capture_tool["argv"][:5]
        != [capture_tool["path"], "-q", "-i", "any", "-w"]
        or len(capture_tool["argv"]) != 6
        or capture_tool["argv"][-1] != "<PCAP>"
        or any(argument in {"-f", "--capture-filter"} for argument in capture_tool["argv"])
    ):
        raise ValueError("browser-egress capture tool is not exact no-filter dumpcap")
    _digest(capture_tool["sha256"], label="capture tool SHA-256")
    chronology = value["chronology"]
    chronology_keys = (
        "observer_started_ns",
        "observer_ready_ns",
        "subject_started_ns",
        "subject_exited_ns",
        "reporting_grace_finished_ns",
        "observer_stopped_ns",
    )
    if not isinstance(chronology, Mapping) or set(chronology) != set(chronology_keys):
        raise ValueError("browser-egress capture chronology fields are invalid")
    times = [_integer(chronology[key], label=f"capture chronology {key}") for key in chronology_keys]
    if times != sorted(times) or any(left == right for left, right in zip(times, times[1:])):
        raise ValueError("browser-egress capture did not span the complete browser lifetime")
    if chronology["reporting_grace_finished_ns"] - chronology["subject_exited_ns"] < 5_000_000_000:
        raise ValueError("browser-egress capture omitted the five-second close/reporting grace")
    decoder = value["packet_decoder"]
    analysis = validate_packet_analysis(value["analysis"], vector=vector)
    if not isinstance(decoder, Mapping) or set(decoder) != {
        "path",
        "sha256",
        "version_first_line",
        "fields",
        "argv",
    }:
        raise ValueError("browser-egress packet decoder binding fields are invalid")
    if (
        not isinstance(decoder["path"], str)
        or not decoder["path"].startswith("/")
        or not isinstance(decoder["version_first_line"], str)
        or not decoder["version_first_line"]
        or decoder["fields"] != list(tshark_fields(analysis["schema_version"]))
        or not isinstance(decoder["argv"], list)
        or any(not isinstance(item, str) for item in decoder["argv"])
        or (
            analysis["schema_version"] >= 5
            and decoder["argv"] != tshark_command(
                Path("<PCAP>"), tshark=Path(decoder["path"]),
                analysis_schema_version=analysis["schema_version"],
            )
        )
    ):
        raise ValueError("browser-egress packet decoder binding is invalid")
    _digest(decoder["sha256"], label="packet decoder SHA-256")

    if deep:
        if evidence_root is None:
            raise ValueError("deep browser-egress capture validation requires an evidence root")
        capture_path = safe_relative_artifact(
            evidence_root, pcap["path"], label="browser-egress PCAP"
        )
        if capture_path.stat().st_size != pcap["size_bytes"] or sha256_file(capture_path) != pcap[
            "sha256"
        ]:
            raise ValueError("browser-egress PCAP binding does not verify")
        recomputed, tool = analyse_pcap(
            capture_path,
            vector=vector,
            tshark=tshark,
            analysis_schema_version=analysis["schema_version"],
        )
        if recomputed != analysis:
            raise ValueError("browser-egress PCAP analysis does not reproduce")
        if tool != decoder:
            raise ValueError("browser-egress packet decoder binding does not reproduce")
        capture_executable = Path(dumpcap)
        if (
            capture_executable.is_symlink()
            or not capture_executable.is_file()
            or str(capture_executable) != capture_tool["path"]
            or sha256_file(capture_executable) != capture_tool["sha256"]
        ):
            raise ValueError("browser-egress capture-tool executable binding does not verify")
        version_first_line = _tool_version_stdout_first_line(capture_executable, label="dumpcap")
        if version_first_line != capture_tool["version_first_line"]:
            raise ValueError("browser-egress capture-tool version binding does not verify")
    return json.loads(canonical_json_bytes(value))


_CAPTURED_RE = re.compile(r"Packets captured:\s*(\d+)")
_DETAILED_RECEIVED_DROPPED_RE = re.compile(
    r"^Packets received/dropped on interface(?: '[^'\r\n]+')?: "
    r"(\d+)/(\d+) \(pcap:(\d+)/dumpcap:(\d+)/flushed:(\d+)/ps_ifdrop:(\d+)\) "
    r"\(\d+(?:[.]\d+)?%\)$",
    re.MULTILINE,
)


def parse_dumpcap_statistics(stderr: str, *, exit_code: int) -> dict[str, int]:
    """Parse dumpcap's terminal counters; absence is a hard evidence failure."""

    if type(exit_code) is not int or not isinstance(stderr, str):
        raise ValueError("dumpcap terminal evidence is malformed")
    captured_matches = _CAPTURED_RE.findall(stderr)
    detailed_matches = _DETAILED_RECEIVED_DROPPED_RE.findall(stderr)
    if len(captured_matches) != 1 or len(detailed_matches) != 1:
        raise ValueError("dumpcap output omitted one unambiguous detailed drop counter")
    captured = int(captured_matches[0])
    received, total_dropped, pcap_dropped, dumpcap_dropped, flushed, ps_ifdrop = map(
        int, detailed_matches[0]
    )
    if total_dropped != pcap_dropped + dumpcap_dropped + flushed or captured > received:
        raise ValueError("dumpcap capture/drop counters are inconsistent")
    return {
        "exit_code": exit_code,
        "packets_captured": captured,
        "packets_received": received,
        # dumpcap's reported total is pcap + its own queue + flushed loss.
        # ps_ifdrop is reported separately by the capture interface.
        "packets_dropped_by_kernel": total_dropped,
        "packets_dropped_by_interface": ps_ifdrop,
        "capture_path_drop_breakdown": {
            "pcap": pcap_dropped,
            "dumpcap": dumpcap_dropped,
            "flushed": flushed,
        },
    }


CAPTURE_CLOSURE_SCHEMA_VERSION = 1
CAPTURE_CLOSURE_ARTIFACT_TYPE = "qcsd-browser-egress-capture-closure"


class LivePacketObserver:
    """Concrete no-filter dumpcap role used by the later Docker coordinator."""

    def __init__(
        self,
        *,
        pcap_path: Path,
        dumpcap: Path = Path("/usr/bin/dumpcap"),
        tshark: Path = Path("/usr/bin/tshark"),
    ) -> None:
        self.pcap_path = Path(pcap_path)
        self.dumpcap = Path(dumpcap)
        self.tshark = Path(tshark)
        self.process: subprocess.Popen[str] | None = None
        self.capture_tool: dict[str, Any] | None = None
        self.times: dict[str, int] = {}
        self._closed_capture: dict[str, Any] | None = None
        self._closed_stderr: str | None = None
        self._analysis_started = False

    def start(self, *, ready_timeout_seconds: float = 10.0) -> None:
        if self.process is not None or self.pcap_path.exists() or self.pcap_path.is_symlink():
            raise ValueError("browser-egress observer is not a fresh capture")
        if self.dumpcap.is_symlink() or not self.dumpcap.is_file():
            raise ValueError("dumpcap executable is unavailable or a symlink")
        version_first_line = _tool_version_stdout_first_line(self.dumpcap, label="dumpcap")
        argv = [str(self.dumpcap), "-q", "-i", "any", "-w", str(self.pcap_path)]
        self.process = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.times["observer_started_ns"] = time.monotonic_ns()
        deadline = time.monotonic() + ready_timeout_seconds
        while not self.pcap_path.is_file() or self.pcap_path.stat().st_size == 0:
            if self.process.poll() is not None:
                stderr = "" if self.process.stderr is None else self.process.stderr.read()
                raise ValueError(f"dumpcap exited before readiness: {stderr.strip()}")
            if time.monotonic() >= deadline:
                self.process.send_signal(signal.SIGINT)
                self.process.communicate(timeout=5)
                raise TimeoutError("dumpcap did not publish a capture header before the deadline")
            time.sleep(0.01)
        self.times["observer_ready_ns"] = time.monotonic_ns()
        self.capture_tool = {
            "path": str(self.dumpcap),
            "sha256": sha256_file(self.dumpcap),
            "version_first_line": version_first_line,
            "argv": [*argv[:-1], "<PCAP>"],
        }

    def mark_subject_started(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise ValueError("browser cannot start before a live observer")
        self.times["subject_started_ns"] = time.monotonic_ns()

    def mark_subject_exited(self) -> None:
        if "subject_started_ns" not in self.times:
            raise ValueError("observed subject exit precedes its start")
        self.times["subject_exited_ns"] = time.monotonic_ns()

    def mark_reporting_grace_finished(self) -> None:
        if "subject_exited_ns" not in self.times:
            raise ValueError("reporting grace precedes observed-subject exit")
        now = time.monotonic_ns()
        if now - self.times["subject_exited_ns"] < 5_000_000_000:
            raise ValueError("five-second reporting grace has not elapsed")
        self.times["reporting_grace_finished_ns"] = now

    def close_capture(
        self,
        *,
        vector: BrowserEgressVector,
        pcap_relative_path: str,
    ) -> dict[str, Any]:
        if self.process is None or self.capture_tool is None:
            raise ValueError("browser-egress observer was not started")
        if self._closed_capture is not None:
            raise ValueError("browser-egress observer capture was already closed")
        if "reporting_grace_finished_ns" not in self.times:
            raise ValueError("browser-egress observer cannot stop before reporting grace")
        self.process.send_signal(signal.SIGINT)
        _stdout, stderr = self.process.communicate(timeout=15)
        self.times["observer_stopped_ns"] = time.monotonic_ns()
        if not isinstance(stderr, str) or type(self.process.returncode) is not int:
            raise ValueError("browser-egress observer terminal process evidence is invalid")
        capture_path = self.pcap_path.absolute()
        if (
            capture_path.is_symlink()
            or not capture_path.is_file()
            or capture_path.stat().st_nlink != 1
            or capture_path.stat().st_size <= 0
        ):
            raise ValueError("browser-egress observer PCAP is not a sole regular file")
        _ = PurePosixPath(pcap_relative_path)
        if (
            not pcap_relative_path
            or "\\" in pcap_relative_path
            or _.is_absolute()
            or any(part in {"", ".", ".."} for part in _.parts)
        ):
            raise ValueError("browser-egress intended PCAP evidence path is invalid")
        capture_before = capture_path.stat()
        pcap_sha256 = sha256_file(capture_path)
        capture_after = capture_path.stat()
        if (
            (capture_before.st_dev, capture_before.st_ino, capture_before.st_size)
            != (capture_after.st_dev, capture_after.st_ino, capture_after.st_size)
            or capture_after.st_nlink != 1
        ):
            raise ValueError("browser-egress observer PCAP changed while it was closed")
        closure = {
            "schema_version": CAPTURE_CLOSURE_SCHEMA_VERSION,
            "artifact_type": CAPTURE_CLOSURE_ARTIFACT_TYPE,
            "vector_id": vector.vector_id,
            "pcap": {
                "path": pcap_relative_path,
                "sha256": pcap_sha256,
                "size_bytes": capture_after.st_size,
            },
            "observer": {
                "network_namespace": "browser",
                "interface": "any",
                "capture_filter": None,
                "privileged": False,
                "cap_drop": ["ALL"],
                "cap_add": ["CAP_NET_RAW"],
                "separate_container": True,
            },
            # Retain the unparsed terminal stream so dumpcap-statistics parsing
            # is itself post-extraction work.  Even malformed terminal output
            # cannot strand the already closed raw PCAP on container tmpfs.
            "capture_process_terminal": {
                "exit_code": self.process.returncode,
                "stderr": stderr,
            },
            "capture_tool": self.capture_tool,
            "chronology": dict(self.times),
        }
        self._closed_capture = json.loads(canonical_json_bytes(closure))
        self._closed_stderr = stderr
        return json.loads(canonical_json_bytes(closure))

    def finish_closed_capture(
        self,
        *,
        vector: BrowserEgressVector,
        closure: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._closed_capture is None or self._closed_stderr is None:
            raise ValueError("browser-egress observer capture is not closed")
        if self._analysis_started:
            raise ValueError("browser-egress closed capture analysis already started")
        if dict(closure) != self._closed_capture:
            raise ValueError("browser-egress capture closure differs from the closed observer")
        if (
            closure.get("schema_version") != CAPTURE_CLOSURE_SCHEMA_VERSION
            or closure.get("artifact_type") != CAPTURE_CLOSURE_ARTIFACT_TYPE
            or closure.get("vector_id") != vector.vector_id
        ):
            raise ValueError("browser-egress capture closure identity is invalid")
        self._analysis_started = True
        process_terminal = closure.get("capture_process_terminal")
        if not isinstance(process_terminal, Mapping) or set(process_terminal) != {
            "exit_code",
            "stderr",
        }:
            raise ValueError("browser-egress capture closure process fields are invalid")
        stats = parse_dumpcap_statistics(
            self._closed_stderr,
            exit_code=process_terminal["exit_code"],
        )
        capture_path = self.pcap_path.absolute()
        pcap = closure.get("pcap")
        if (
            not isinstance(pcap, Mapping)
            or set(pcap) != {"path", "sha256", "size_bytes"}
            or capture_path.is_symlink()
            or not capture_path.is_file()
            or capture_path.stat().st_nlink != 1
            or capture_path.stat().st_size != pcap["size_bytes"]
            or sha256_file(capture_path) != pcap["sha256"]
        ):
            raise ValueError("browser-egress closed PCAP differs from its closure")
        analysis, decoder = analyse_pcap(capture_path, vector=vector, tshark=self.tshark)
        receipt = {
            "schema_version": CAPTURE_RECEIPT_SCHEMA_VERSION,
            "artifact_type": CAPTURE_ARTIFACT_TYPE,
            "vector_id": vector.vector_id,
            "pcap": dict(pcap),
            "observer": closure["observer"],
            "capture_process": stats,
            "capture_tool": closure["capture_tool"],
            "chronology": closure["chronology"],
            "packet_decoder": decoder,
            "analysis": analysis,
        }
        return validate_capture_receipt(receipt, vector=vector)

    def finish(
        self,
        *,
        vector: BrowserEgressVector,
        pcap_relative_path: str,
    ) -> dict[str, Any]:
        """Compatibility wrapper for non-orchestrated observer callers."""

        closure = self.close_capture(
            vector=vector,
            pcap_relative_path=pcap_relative_path,
        )
        return self.finish_closed_capture(vector=vector, closure=closure)
