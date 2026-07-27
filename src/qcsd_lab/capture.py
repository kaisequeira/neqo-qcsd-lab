from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from .util import load_json, run


@dataclass(frozen=True)
class ObserverPacket:
    """One encrypted frame observed at the capture interface."""

    timestamp_unix_ns: int
    relative_time_ns: int
    direction: str
    frame_len: int
    signed_frame_len: int
    connection: int

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
    endpoints: list[dict[str, Any]] | None = None,
    *,
    kind: str = "direct-quic",
    length_basis: str = "frame.len",
    client_port: int | None = None,
) -> list[ObserverPacket]:
    """Derive a direction/size/time sequence from one declared observer."""

    if kind not in {"direct-quic", "wireguard-outer"}:
        raise ValueError(f"unknown observer kind {kind!r}")
    if length_basis not in {"frame.len", "udp.length"}:
        raise ValueError(f"unsupported length basis {length_basis!r}")
    endpoints = endpoints or []

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
        length_basis,
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
    local_ports: dict[int, int] = {}
    endpoint_addresses: list[tuple[str, str, int]] = []
    for endpoint in endpoints:
        local_address, port = split_endpoint(endpoint["local_address"])
        remote_address, _remote_port = split_endpoint(endpoint["remote_address"])
        local_ports[port] = int(endpoint["id"])
        endpoint_addresses.append((local_address, remote_address, int(endpoint["id"])))
    valid_rows = [row for row in rows if len(row) >= 8 and row[0]]
    if not valid_rows:
        return []
    if any(not row[1] for row in valid_rows):
        raise ValueError(f"{length_basis} is unavailable for an observer packet")
    first_ns = int(Decimal(valid_rows[0][0]) * 1_000_000_000)
    trace = []
    for row in valid_rows:
        timestamp = int(Decimal(row[0]) * 1_000_000_000)
        frame_len = int(row[1])
        source_address = row[2] or row[3]
        destination_address = row[4] or row[5]
        source_port = int(row[6]) if row[6] else None
        destination_port = int(row[7]) if row[7] else None
        if kind == "wireguard-outer":
            if client_port is None:
                raise ValueError("wireguard-outer observer requires client_port")
            if source_port == client_port:
                outgoing = True
            elif destination_port == client_port:
                outgoing = False
            else:
                raise ValueError("outer capture contains a packet outside the client tunnel flow")
            connection = 0
        else:
            if source_port in local_ports:
                outgoing = True
            elif destination_port in local_ports:
                outgoing = False
            else:
                # TShark associates every IP fragment with a reassembled UDP
                # display filter but exposes ports only on the first fragment.
                # The already tuple-filtered source/destination pair remains
                # sufficient for client-relative direction.
                forward = [
                    endpoint_id
                    for local, remote, endpoint_id in endpoint_addresses
                    if source_address == local and destination_address == remote
                ]
                reverse = [
                    endpoint_id
                    for local, remote, endpoint_id in endpoint_addresses
                    if source_address == remote and destination_address == local
                ]
                if forward:
                    outgoing = True
                    connection = forward[0] if len(set(forward)) == 1 else -1
                elif reverse:
                    outgoing = False
                    connection = reverse[0] if len(set(reverse)) == 1 else -1
                else:
                    raise ValueError("direct capture contains a packet outside Neqo endpoint tuples")
            if source_port is not None or destination_port is not None:
                connection = local_ports.get(source_port, local_ports.get(destination_port, -1))
        trace.append(
            ObserverPacket(
                timestamp_unix_ns=timestamp,
                relative_time_ns=timestamp - first_ns,
                direction="outgoing" if outgoing else "incoming",
                frame_len=frame_len,
                signed_frame_len=frame_len if outgoing else -frame_len,
                connection=connection,
            )
        )
    return trace


def write_normalized_trace(path: Path, trace: list[ObserverPacket]) -> None:
    """Write the classifier-facing, observer-only trace contract."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination, lineterminator="\n")
        writer.writerow(
            ["relative_time_ns", "direction", "length_bytes", "signed_length_bytes"]
        )
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


def sample_trace(sample: Path, observer_id: str | None = None) -> list[ObserverPacket]:
    """Reproduce one declared observer trace from its canonical PCAPNG."""

    metadata = load_json(sample / "sample.json")
    observers = [
        item
        for item in metadata.get("views", [])
        if item.get("valid")
    ]
    if observer_id is None:
        observer = next(
            (item for item in observers if item.get("kind") == "direct-quic"),
            next((item for item in observers if item.get("primary")), None),
        )
    else:
        observer = next((item for item in observers if item.get("id") == observer_id), None)
    if observer is None:
        raise ValueError(f"sample has no valid observer {observer_id or 'view'}")
    run_data = load_json(sample / "neqo" / "run.json")
    return extract_trace(
        sample / observer["capture_path"],
        run_data.get("endpoints", []),
        kind=observer["kind"],
        length_basis=observer["length_basis"],
        client_port=observer.get("client_port"),
    )
