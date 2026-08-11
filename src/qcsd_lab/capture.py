from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from .util import run

REQUIRED_OFFLOAD_FEATURES = {
    "gro": "generic-receive-offload",
    "gso": "generic-segmentation-offload",
    "tso": "tcp-segmentation-offload",
    "uso": "tx-udp-segmentation",
}
OFFLOAD_DISABLED = {feature: "off" for feature in REQUIRED_OFFLOAD_FEATURES}
OFFLOAD_EVIDENCE_FIELDS = {
    "interface",
    "requested",
    "query_returncodes",
    "change_returncodes",
    "before_state",
    "after_state",
    "before_sha256",
    "after_sha256",
    "verified",
}


@dataclass(frozen=True)
class ObserverPacket:
    """One encrypted frame observed at the capture interface."""

    timestamp_unix_ns: int
    relative_time_ns: int
    direction: str
    frame_len: int
    signed_frame_len: int
    udp_payload_len: int | None = None

    @property
    def length_bytes(self) -> int:
        return self.frame_len

    @property
    def signed_length_bytes(self) -> int:
        return self.signed_frame_len


def split_endpoint(value: str) -> tuple[str, int]:
    """Split an IPv4 or bracketed IPv6 socket address."""

    if value.startswith("["):
        address, port = value.rsplit("]:", 1)
        return address[1:], int(port)
    address, port = value.rsplit(":", 1)
    return address, int(port)


def parse_offload_state(output: str) -> dict[str, str | None]:
    """Parse the packet coalescing/segmentation features from ``ethtool -k``."""

    values: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, raw_value = line.strip().partition(":")
        if not separator:
            continue
        fields = raw_value.strip().split(maxsplit=1)
        if not fields:
            continue
        value = fields[0]
        if value in {"on", "off"}:
            values[key] = value
    return {
        short_name: values.get(feature) for short_name, feature in REQUIRED_OFFLOAD_FEATURES.items()
    }


def offload_state_is_safe(state: dict[str, str | None]) -> bool:
    """Return whether capture packet units are protected from host coalescing."""

    return set(state) == set(REQUIRED_OFFLOAD_FEATURES) and all(
        value == "off" for value in state.values()
    )


def recompute_offload_verification(
    evidence: dict[str, Any],
    *,
    interface: str | None = None,
) -> bool:
    """Recompute the packet-offload proof from its sealed command evidence."""

    fields = set(evidence)
    if fields != OFFLOAD_EVIDENCE_FIELDS and fields != (OFFLOAD_EVIDENCE_FIELDS - {"verified"}):
        return False
    recorded_interface = evidence.get("interface")
    if (
        not isinstance(recorded_interface, str)
        or not recorded_interface
        or (interface is not None and recorded_interface != interface)
        or evidence.get("requested") != OFFLOAD_DISABLED
        or not _successful_returncodes(
            evidence.get("query_returncodes"),
            {"before", "after"},
        )
        or not _successful_returncodes(
            evidence.get("change_returncodes"),
            set(REQUIRED_OFFLOAD_FEATURES),
        )
    ):
        return False
    before_state = evidence.get("before_state")
    after_state = evidence.get("after_state")
    if (
        not isinstance(before_state, dict)
        or set(before_state) != set(REQUIRED_OFFLOAD_FEATURES)
        or any(value not in {"on", "off"} for value in before_state.values())
        or not isinstance(after_state, dict)
        or not offload_state_is_safe(after_state)
    ):
        return False
    return all(_is_sha256(evidence.get(field)) for field in ("before_sha256", "after_sha256"))


def offload_evidence_is_valid(
    evidence: object,
    *,
    interface: str | None = None,
) -> bool:
    """Validate the exact stored proof and its recomputed ``verified`` value."""

    return (
        isinstance(evidence, dict)
        and set(evidence) == OFFLOAD_EVIDENCE_FIELDS
        and evidence.get("verified") is True
        and recompute_offload_verification(evidence, interface=interface)
    )


def _successful_returncodes(value: object, expected_keys: set[str]) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == expected_keys
        and all(type(returncode) is int and returncode == 0 for returncode in value.values())
    )


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def tuple_filter(endpoints: list[dict[str, Any]]) -> str:
    """Build an exact bidirectional Wireshark filter for Neqo endpoint tuples."""

    clauses = []
    for endpoint in endpoints:
        local_ip, local_port = split_endpoint(endpoint["local_address"])
        remote_ip, remote_port = split_endpoint(endpoint["remote_address"])
        field = "ipv6" if ipaddress.ip_address(local_ip).version == 6 else "ip"
        forward = (
            f"({field}.src=={local_ip} && udp.srcport=={local_port} && "
            f"{field}.dst=={remote_ip} && udp.dstport=={remote_port})"
        )
        reverse = (
            f"({field}.src=={remote_ip} && udp.srcport=={remote_port} && "
            f"{field}.dst=={local_ip} && udp.dstport=={local_port})"
        )
        clauses.append(f"({forward} || {reverse})")
    if not clauses:
        raise ValueError("run.json contains no endpoint tuples")
    return " || ".join(clauses)


def extract_trace(
    capture: Path,
    endpoints: list[dict[str, Any]],
) -> list[ObserverPacket]:
    """Derive the canonical direct-PCAP direction/size/time sequence."""

    command = [
        "tshark",
        "-r",
        str(capture),
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "udp.length",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.dst",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
    ]
    rows = list(csv.reader(run(command).stdout.splitlines()))
    endpoint_tuples: set[tuple[str, int, str, int]] = set()
    endpoint_addresses: list[tuple[str, str]] = []
    for endpoint in endpoints:
        local_address, local_port = split_endpoint(endpoint["local_address"])
        remote_address, remote_port = split_endpoint(endpoint["remote_address"])
        endpoint_tuples.add((local_address, local_port, remote_address, remote_port))
        endpoint_addresses.append((local_address, remote_address))
    valid_rows = [row for row in rows if len(row) >= 9 and row[0]]
    if not valid_rows:
        return []
    if any(not row[1] for row in valid_rows):
        raise ValueError("frame.len is unavailable for an observer packet")
    timestamped_rows = [
        (int(Decimal(row[0]) * 1_000_000_000), record_order, row)
        for record_order, row in enumerate(valid_rows)
    ]
    # Capture buffers can flush records a few microseconds out of timestamp
    # order. The trace contract is the chronological packet sequence; preserve
    # PCAP record order only as the deterministic tie-breaker.
    timestamped_rows.sort(key=lambda item: (item[0], item[1]))
    first_ns = timestamped_rows[0][0]
    trace = []
    for timestamp, _record_order, row in timestamped_rows:
        frame_len = int(row[1])
        udp_payload_len = int(row[2]) - 8 if row[2] else None
        if udp_payload_len is not None and udp_payload_len < 0:
            raise ValueError("udp.length is smaller than the UDP header")
        source_address = row[3] or row[4]
        destination_address = row[5] or row[6]
        source_port = int(row[7]) if row[7] else None
        destination_port = int(row[8]) if row[8] else None
        if source_port is not None and destination_port is not None:
            forward = (
                source_address,
                source_port,
                destination_address,
                destination_port,
            )
            reverse = (
                destination_address,
                destination_port,
                source_address,
                source_port,
            )
            if forward in endpoint_tuples:
                outgoing = True
            elif reverse in endpoint_tuples:
                outgoing = False
            else:
                raise ValueError("direct capture contains a packet outside Neqo endpoint tuples")
        else:
            # TShark associates every IP fragment with a reassembled UDP
            # display filter but exposes ports only on the first fragment.
            # The already tuple-filtered source/destination pair remains
            # sufficient for client-relative direction.
            forward = any(
                source_address == local and destination_address == remote
                for local, remote in endpoint_addresses
            )
            reverse = any(
                source_address == remote and destination_address == local
                for local, remote in endpoint_addresses
            )
            if forward:
                outgoing = True
            elif reverse:
                outgoing = False
            else:
                raise ValueError("direct capture contains a packet outside Neqo endpoint tuples")
        trace.append(
            ObserverPacket(
                timestamp_unix_ns=timestamp,
                relative_time_ns=timestamp - first_ns,
                direction="outgoing" if outgoing else "incoming",
                frame_len=frame_len,
                signed_frame_len=frame_len if outgoing else -frame_len,
                udp_payload_len=udp_payload_len,
            )
        )
    return trace


def udp_ceiling_evidence(
    trace: list[ObserverPacket],
    expected_ceiling: int,
) -> dict[str, int | bool | None]:
    """Summarize whether direct packets satisfy one UDP-payload ceiling.

    A missing UDP length normally means IP fragmentation.  Such a capture
    cannot prove packet-unit integrity and therefore fails this evidence gate.
    """

    if not 1_200 <= expected_ceiling <= 65_527:
        raise ValueError("expected UDP-payload ceiling is outside the QUIC range")
    observed = [packet.udp_payload_len for packet in trace if packet.udp_payload_len is not None]
    missing = len(trace) - len(observed)
    oversized = sum(length > expected_ceiling for length in observed)
    return {
        "configured_udp_payload_ceiling": expected_ceiling,
        "observed_udp_payload_max": max(observed, default=None),
        "packets_with_udp_payload_length": len(observed),
        "packets_without_udp_payload_length": missing,
        "oversized_udp_payload_packets": oversized,
        "valid": bool(trace) and missing == 0 and oversized == 0,
    }


def write_normalized_trace(path: Path, trace: list[ObserverPacket]) -> None:
    """Write the temporary observer-only trace used for reconciliation."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination, lineterminator="\n")
        writer.writerow(["relative_time_ns", "direction", "length_bytes", "signed_length_bytes"])
        for packet in trace:
            writer.writerow(
                [
                    packet.relative_time_ns,
                    packet.direction,
                    packet.length_bytes,
                    packet.signed_length_bytes,
                ]
            )


def read_normalized_trace(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
    expected = [
        "relative_time_ns",
        "direction",
        "length_bytes",
        "signed_length_bytes",
    ]
    if reader.fieldnames != expected:
        raise ValueError(f"invalid normalized trace columns in {path}")
    return rows
