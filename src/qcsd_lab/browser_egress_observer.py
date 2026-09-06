"""Packet-level evidence for the browser-egress qualification gate.

The observer captures ``any`` without a BPF filter.  PCAP is primary evidence;
the sink counters are an independently produced corroboration.  This module
contains no Docker orchestration and never treats an HTTP hit as proof that a
forbidden transport was prevented.
"""

from __future__ import annotations

import csv
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

from .browser_egress_fixture import (
    FIXTURE_TOPOLOGY,
    BrowserEgressVector,
    validate_sink_receipt,
)
from .class_study import canonical_json_bytes
from .util import sha256_file

PACKET_RECORD_SCHEMA_VERSION = 1
PACKET_ANALYSIS_SCHEMA_VERSION = 3
CAPTURE_RECEIPT_SCHEMA_VERSION = 2
CAPTURE_ARTIFACT_TYPE = "qcsd-browser-egress-packet-capture"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

TSHARK_FIELDS = (
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
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("browser-egress packet record fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PACKET_RECORD_SCHEMA_VERSION
    ):
        raise ValueError("browser-egress packet record schema is invalid")
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
    if transport not in {"tcp", "udp"}:
        raise ValueError("browser-egress packet transport is invalid")
    for key in ("src_port", "dst_port"):
        port = _integer(value[key], label=f"packet {key}")
        if port > 65_535:
            raise ValueError(f"packet {key} exceeds 65535")
    for key in ("tcp_syn", "tcp_ack"):
        if type(value[key]) is not bool:
            raise ValueError(f"packet {key} must be a boolean")
    if transport == "udp" and (value["tcp_syn"] or value["tcp_ack"]):
        raise ValueError("UDP packet cannot carry TCP flags")
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
    return json.loads(canonical_json_bytes(value))


def _empty_analysis(vector_id: str) -> dict[str, Any]:
    return {
        "schema_version": PACKET_ANALYSIS_SCHEMA_VERSION,
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


def analyse_packet_records(
    records: Sequence[Mapping[str, Any]], *, vector: BrowserEgressVector
) -> dict[str, Any]:
    """Reduce decoded IPv4/IPv6 TCP/UDP records to policy-relevant counts."""

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise ValueError("browser-egress packet records must be a sequence")
    analysis = _empty_analysis(vector.vector_id)
    browser = set(FIXTURE_TOPOLOGY["browser_addresses"])
    fixture = set(FIXTURE_TOPOLOGY["fixture_addresses"])
    forbidden = set(FIXTURE_TOPOLOGY["forbidden_sink_addresses"])
    dns_sinks = set(FIXTURE_TOPOLOGY["dns_sink_addresses"])
    last_frame = 0
    last_time = -1
    names: list[str] = []
    for raw in records:
        record = validate_packet_record(raw)
        frame = record["frame_number"]
        timestamp = record["timestamp_ns"]
        if frame <= last_frame or timestamp < last_time:
            raise ValueError("browser-egress packet records are not capture ordered")
        last_frame = frame
        last_time = timestamp
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


def expected_packet_analysis(vector: BrowserEgressVector) -> dict[str, Any]:
    """Return policy counts; capture-wide packet/family totals remain observed."""

    expected = {
        key: value
        for key, value in _empty_analysis(vector.vector_id).items()
        if key
        not in {
            "decoded_transport_packets",
            "ipv4_packets",
            "ipv6_packets",
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
        count = FIXTURE_TOPOLOGY["browser_service_controls"][
            "dns_positive_query_count"
        ]
        name = FIXTURE_TOPOLOGY["browser_service_controls"][
            "dns_exception_hostname"
        ]
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
    expected_fields = set(_empty_analysis(vector.vector_id))
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise ValueError("browser-egress packet analysis fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != PACKET_ANALYSIS_SCHEMA_VERSION
        or value["vector_id"] != vector.vector_id
    ):
        raise ValueError("browser-egress packet analysis identity is invalid")
    for key in expected_fields - {"vector_id", "dns_query_names"}:
        if key == "schema_version":
            continue
        _integer(value[key], label=f"packet analysis {key}")
    if value["decoded_transport_packets"] != value["ipv4_packets"] + value["ipv6_packets"]:
        raise ValueError("browser-egress packet family counts do not reconcile")
    names = value["dns_query_names"]
    if (
        not isinstance(names, list)
        or any(not isinstance(name, str) or name != name.lower().rstrip(".") for name in names)
        or names != sorted(names)
    ):
        raise ValueError("browser-egress packet DNS inventory is invalid")
    expected = expected_packet_analysis(vector)
    for key, wanted in expected.items():
        if value[key] != wanted:
            raise ValueError(f"browser-egress packet policy failed at {key}")
    return json.loads(canonical_json_bytes(value))


def reconcile_sink_and_packet_evidence(
    *, vector: BrowserEgressVector, analysis: object, sink: object
) -> None:
    packet = validate_packet_analysis(analysis, vector=vector)
    counters = validate_sink_receipt(sink, vector=vector)
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


def tshark_command(pcap: Path, *, tshark: Path = Path("/usr/bin/tshark")) -> list[str]:
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
        "occurrence=f",
    ]
    for field in TSHARK_FIELDS:
        command.extend(("-e", field))
    return command


def _field_integer(value: str, *, label: str, default: int | None = None) -> int:
    if value == "" and default is not None:
        return default
    if not value.isdecimal():
        raise ValueError(f"tshark {label} is not an integer")
    return int(value)


def _records_from_tshark_output(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    reader = csv.reader(output.splitlines(), delimiter="\t", quotechar='"')
    for columns in reader:
        if not columns or all(column == "" for column in columns):
            continue
        if len(columns) != len(TSHARK_FIELDS):
            raise ValueError("tshark packet row has the wrong field count")
        values = dict(zip(TSHARK_FIELDS, columns))
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
            "schema_version": PACKET_RECORD_SCHEMA_VERSION,
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


def analyse_pcap(
    pcap: Path, *, vector: BrowserEgressVector, tshark: Path = Path("/usr/bin/tshark")
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode one PCAP/PCAPNG with pinned tshark and return analysis/tool binding."""

    executable = Path(tshark)
    if executable.is_symlink() or not executable.is_file():
        raise ValueError("tshark executable is unavailable or a symlink")
    version = subprocess.run(
        [str(executable), "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if version.returncode != 0 or not version.stdout.strip():
        raise ValueError("tshark version query failed")
    command = tshark_command(Path(pcap), tshark=executable)
    decoded = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if decoded.returncode != 0:
        raise ValueError(f"tshark failed to decode capture: {decoded.stderr.strip()}")
    records = _records_from_tshark_output(decoded.stdout)
    analysis = analyse_packet_records(records, vector=vector)
    tool = {
        "path": str(executable),
        "sha256": sha256_file(executable),
        "version_first_line": version.stdout.splitlines()[0],
        "fields": list(TSHARK_FIELDS),
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
        or decoder["fields"] != list(TSHARK_FIELDS)
        or not isinstance(decoder["argv"], list)
        or any(not isinstance(item, str) for item in decoder["argv"])
    ):
        raise ValueError("browser-egress packet decoder binding is invalid")
    _digest(decoder["sha256"], label="packet decoder SHA-256")
    analysis = validate_packet_analysis(value["analysis"], vector=vector)

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
        recomputed, tool = analyse_pcap(capture_path, vector=vector, tshark=tshark)
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
        version = subprocess.run(
            [str(capture_executable), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if (
            version.returncode != 0
            or not version.stdout
            or version.stdout.splitlines()[0] != capture_tool["version_first_line"]
        ):
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

    def start(self, *, ready_timeout_seconds: float = 10.0) -> None:
        if self.process is not None or self.pcap_path.exists() or self.pcap_path.is_symlink():
            raise ValueError("browser-egress observer is not a fresh capture")
        if self.dumpcap.is_symlink() or not self.dumpcap.is_file():
            raise ValueError("dumpcap executable is unavailable or a symlink")
        version = subprocess.run(
            [str(self.dumpcap), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if version.returncode != 0 or not version.stdout.strip():
            raise ValueError("dumpcap version query failed")
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
            "version_first_line": version.stdout.splitlines()[0],
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

    def finish(
        self,
        *,
        vector: BrowserEgressVector,
        pcap_relative_path: str,
    ) -> dict[str, Any]:
        if self.process is None or self.capture_tool is None:
            raise ValueError("browser-egress observer was not started")
        if "reporting_grace_finished_ns" not in self.times:
            raise ValueError("browser-egress observer cannot stop before reporting grace")
        self.process.send_signal(signal.SIGINT)
        _stdout, stderr = self.process.communicate(timeout=15)
        self.times["observer_stopped_ns"] = time.monotonic_ns()
        stats = parse_dumpcap_statistics(stderr, exit_code=self.process.returncode)
        capture_path = self.pcap_path.absolute()
        if capture_path.is_symlink() or not capture_path.is_file() or capture_path.stat().st_nlink != 1:
            raise ValueError("browser-egress observer PCAP is not a sole regular file")
        _ = PurePosixPath(pcap_relative_path)
        if (
            not pcap_relative_path
            or "\\" in pcap_relative_path
            or _.is_absolute()
            or any(part in {"", ".", ".."} for part in _.parts)
        ):
            raise ValueError("browser-egress intended PCAP evidence path is invalid")
        analysis, decoder = analyse_pcap(capture_path, vector=vector, tshark=self.tshark)
        receipt = {
            "schema_version": CAPTURE_RECEIPT_SCHEMA_VERSION,
            "artifact_type": CAPTURE_ARTIFACT_TYPE,
            "vector_id": vector.vector_id,
            "pcap": {
                "path": pcap_relative_path,
                "sha256": sha256_file(capture_path),
                "size_bytes": capture_path.stat().st_size,
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
            "capture_process": stats,
            "capture_tool": self.capture_tool,
            "chronology": dict(self.times),
            "packet_decoder": decoder,
            "analysis": analysis,
        }
        return validate_capture_receipt(receipt, vector=vector)
