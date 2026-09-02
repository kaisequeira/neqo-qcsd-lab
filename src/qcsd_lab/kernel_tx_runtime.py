"""Privileged Lab-side runtime support for kernel-timed BuFLO.

This module owns only the collection namespace and router-observer mechanics.
It does not interpret the Rust timing receipt; :mod:`qcsd_lab.kernel_tx` owns
that exact-key evidence contract.  Keeping the two boundaries separate makes
it impossible for a sender-side observation to be relabelled as independent
post-veth evidence.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping, Sequence

from .kernel_tx import (
    KERNEL_TX_ETF_DELTA_NS,
    KERNEL_TX_PRIO_MAP,
)
from .util import run

KERNEL_TX_INTERFACE = "eth0"
KERNEL_TX_FIFO_LIMIT_PACKETS = 1_000
KERNEL_TX_POST_VETH_ENDPOINT_ENV = "QCSD_KERNEL_TX_POST_VETH_CAPTURE_ENDPOINT"
KERNEL_TX_POST_VETH_SECRET_ENV = "QCSD_KERNEL_TX_POST_VETH_CAPTURE_SECRET"
KERNEL_TX_POST_VETH_ROOT_ENV = "QCSD_KERNEL_TX_POST_VETH_CAPTURE_ROOT"
KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV = (
    "QCSD_KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_B64"
)
KERNEL_TX_CONTROLLED_OBSERVER_BINDING_ENV = (
    "QCSD_KERNEL_TX_CONTROLLED_OBSERVER_BINDING_B64"
)
KERNEL_TX_POST_VETH_OBSERVER_ROLE = "router-ingress-post-client-veth-pre-netem"

_CAPTURE_ID = re.compile(r"[0-9a-f]{64}\Z")
_SECRET = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_canonical_base64_environment(name: str) -> dict[str, Any]:
    encoded = os.environ.get(name, "")
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"{name} is missing or invalid") from error
    if (
        not encoded
        or base64.b64encode(raw).decode("ascii") != encoded
        or not isinstance(value, dict)
        or _canonical_json(value) != raw
    ):
        raise ValueError(f"{name} is not canonical JSON base64")
    return value


def require_controlled_observer_binding() -> tuple[dict[str, Any], dict[str, Any], str]:
    """Bind the live router observer to the canonical controlled receipt.

    The normalised receipt proves the namespace/qdisc topology.  The separate
    host-side binding supplies Docker object identities that cannot be observed
    from inside the measured client.  Both are required; neither is inferred
    from the sender-side ``eth0`` capture.
    """

    network = _decode_canonical_base64_environment(
        KERNEL_TX_CONTROLLED_NETWORK_RECEIPT_ENV
    )
    binding = _decode_canonical_base64_environment(
        KERNEL_TX_CONTROLLED_OBSERVER_BINDING_ENV
    )
    image_digest = network.get("image_digest")
    if (
        not isinstance(image_digest, str)
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
        or os.environ.get("QCSD_LAB_IMAGE_DIGEST") != image_digest
    ):
        raise ValueError("kernel-TX observer image does not bind the measured image")
    if network.get("artifact_type") == "qcsd-kernel-tx-public-network-v1":
        return _require_public_observer_binding(network, binding)
    network_keys = {
        "schema_version",
        "artifact_type",
        "image_digest",
        "topology",
        "capture_point",
        "client",
        "router",
        "servers",
        "directional_coverage",
        "rate_aggregation",
        "observation_contract",
    }
    binding_keys = {
        "schema_version",
        "artifact_type",
        "topology_kind",
        "image_digest",
        "observer",
        "client_network",
        "server_network",
        "observed_direction",
        "capture_position",
    }
    if (
        set(network) != network_keys
        or network.get("schema_version") != 2
        or network.get("artifact_type") != "qcsd-buflo-controlled-network-v2"
        or set(binding) != binding_keys
        or binding.get("schema_version") != 1
        or binding.get("artifact_type")
        != "qcsd-kernel-tx-controlled-observer-binding"
        or binding.get("topology_kind") != "shared-two-network-router"
        or binding.get("observed_direction") != "client-to-server"
        or binding.get("capture_position")
        != "router-eth0-ingress-after-client-veth-before-ifb0-ingress-netem"
    ):
        raise ValueError("kernel-TX controlled observer receipt identity is invalid")
    topology = network.get("topology")
    router = network.get("router")
    capture_point = network.get("capture_point")
    directional = network.get("directional_coverage")
    observer = binding.get("observer")
    client_network = binding.get("client_network")
    server_network = binding.get("server_network")
    if (
        not isinstance(topology, Mapping)
        or set(topology)
        != {"kind", "client_network", "server_network", "router_interfaces"}
        or topology.get("kind") != "shared-two-network-router"
        or not isinstance(topology.get("client_network"), Mapping)
        or not isinstance(topology.get("server_network"), Mapping)
        or not isinstance(router, Mapping)
        or not isinstance(capture_point, Mapping)
        or not isinstance(directional, Mapping)
        or not isinstance(observer, Mapping)
        or set(observer)
        != {
            "role",
            "container_name",
            "container_id",
            "interface",
            "interface_direction",
            "ipv4",
        }
        or not isinstance(client_network, Mapping)
        or set(client_network) != {"name", "id", "router_endpoint_id"}
        or not isinstance(server_network, Mapping)
        or set(server_network) != {"name", "id", "router_endpoint_id"}
    ):
        raise ValueError("kernel-TX controlled observer topology is malformed")
    docker_ids = (
        observer.get("container_id"),
        client_network.get("id"),
        client_network.get("router_endpoint_id"),
        server_network.get("id"),
        server_network.get("router_endpoint_id"),
    )
    try:
        observer_ip = str(ipaddress.ip_address(observer.get("ipv4")))
    except (TypeError, ValueError) as error:
        raise ValueError("kernel-TX controlled observer address is invalid") from error
    if (
        any(
            not isinstance(value, str) or _CAPTURE_ID.fullmatch(value) is None
            for value in docker_ids
        )
        or ":" in observer_ip
        or observer.get("ipv4") != observer_ip
        or binding.get("image_digest") != network.get("image_digest")
        or observer.get("role") != KERNEL_TX_POST_VETH_OBSERVER_ROLE
        or observer.get("container_name") != router.get("container")
        or observer.get("interface") != "eth0"
        or observer.get("interface_direction") != "ingress"
        or observer_ip != router.get("client_ipv4")
        or os.environ.get("QCSD_CONTROLLED_ROUTER_CLIENT_IP") != observer_ip
        or client_network.get("name") != topology["client_network"].get("name")
        or server_network.get("name") != topology["server_network"].get("name")
        or capture_point.get("client_to_server_position")
        != "before-router-eth0-ingress-ifb0-netem"
        or not isinstance(directional.get("client_to_server"), Mapping)
        or directional["client_to_server"].get("shaping_site")
        != "router:eth0-ingress-redirect-ifb0-root"
        or directional["client_to_server"].get("capture_position") != "before-impairment"
    ):
        raise ValueError("kernel-TX observer does not bind the controlled router topology")
    digest = hashlib.sha256(_canonical_json(network)).hexdigest()
    return network, binding, digest


def _require_public_observer_binding(
    network: dict[str, Any], binding: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Validate the routed/NAT public observer used by public study stages."""

    network_keys = {
        "schema_version",
        "artifact_type",
        "image_digest",
        "topology",
        "capture_point",
        "client",
        "router",
        "directional_coverage",
        "observation_contract",
    }
    binding_keys = {
        "schema_version",
        "artifact_type",
        "topology_kind",
        "image_digest",
        "observer",
        "client_network",
        "uplink_network",
        "observed_direction",
        "capture_position",
    }
    topology = network.get("topology")
    capture = network.get("capture_point")
    client = network.get("client")
    router = network.get("router")
    directional = network.get("directional_coverage")
    observation_contract = network.get("observation_contract")
    observer = binding.get("observer")
    client_network = binding.get("client_network")
    uplink_network = binding.get("uplink_network")
    if (
        set(network) != network_keys
        or network.get("schema_version") != 1
        or set(binding) != binding_keys
        or binding.get("schema_version") != 1
        or binding.get("artifact_type") != "qcsd-kernel-tx-public-observer-binding"
        or binding.get("topology_kind") != "routed-public-egress"
        or binding.get("image_digest") != network.get("image_digest")
        or binding.get("observed_direction") != "client-to-public-origin"
        or binding.get("capture_position")
        != "router-eth0-ingress-after-client-veth-before-forwarding-and-masquerade"
        or not isinstance(topology, Mapping)
        or set(topology)
        != {"kind", "client_network", "uplink_network", "router_interfaces"}
        or topology.get("kind") != "routed-public-egress"
        or not isinstance(topology.get("client_network"), Mapping)
        or set(topology["client_network"]) != {"name", "subnet"}
        or not isinstance(topology.get("uplink_network"), Mapping)
        or topology["uplink_network"] != {"name": "bridge"}
        or topology.get("router_interfaces") != {"client": "eth0", "uplink": "eth1"}
        or not isinstance(capture, Mapping)
        or set(capture) != {"client_to_server_position"}
        or capture.get("client_to_server_position")
        != "before-router-eth0-forwarding-and-masquerade"
        or not isinstance(client, Mapping)
        or set(client) != {"network", "default_route_via"}
        or not isinstance(router, Mapping)
        or set(router)
        != {
            "container",
            "client_ipv4",
            "client_interface",
            "uplink_interface",
            "ipv4_forwarding",
            "source_masquerade",
        }
        or router.get("client_interface") != "eth0"
        or router.get("uplink_interface") != "eth1"
        or router.get("ipv4_forwarding") is not True
        or router.get("source_masquerade") is not True
        or not isinstance(directional, Mapping)
        or set(directional) != {"client_to_server"}
        or not isinstance(directional.get("client_to_server"), Mapping)
        or directional["client_to_server"].get("capture_position") != "before-forwarding"
        or directional["client_to_server"].get("nat_position") != "after-capture"
        or observation_contract
        != {"client_only": True, "ordinary_public_origins": True}
        or not isinstance(observer, Mapping)
        or set(observer)
        != {
            "role",
            "container_name",
            "container_id",
            "interface",
            "interface_direction",
            "ipv4",
        }
        or observer.get("role") != KERNEL_TX_POST_VETH_OBSERVER_ROLE
        or observer.get("container_name") != router.get("container")
        or observer.get("interface") != "eth0"
        or observer.get("interface_direction") != "ingress"
        or observer.get("ipv4") != router.get("client_ipv4")
        or client.get("default_route_via") != router.get("client_ipv4")
        or client.get("network") != topology["client_network"].get("name")
        or not isinstance(client_network, Mapping)
        or set(client_network) != {"name", "id", "router_endpoint_id"}
        or client_network.get("name") != topology["client_network"].get("name")
        or not isinstance(uplink_network, Mapping)
        or set(uplink_network) != {"name", "id", "router_endpoint_id"}
        or uplink_network.get("name") != topology["uplink_network"].get("name")
    ):
        raise ValueError("kernel-TX public observer topology is malformed")
    docker_ids = (
        observer.get("container_id"),
        client_network.get("id"),
        client_network.get("router_endpoint_id"),
        uplink_network.get("id"),
        uplink_network.get("router_endpoint_id"),
    )
    try:
        observer_ip = str(ipaddress.ip_address(observer.get("ipv4")))
        client_subnet = ipaddress.ip_network(topology["client_network"].get("subnet"), strict=True)
    except (TypeError, ValueError) as error:
        raise ValueError("kernel-TX public observer address is invalid") from error
    if (
        any(
            not isinstance(value, str) or _CAPTURE_ID.fullmatch(value) is None
            for value in docker_ids
        )
        or ":" in observer_ip
        or observer.get("ipv4") != observer_ip
        or client_subnet.version != 4
        or str(client_subnet) != topology["client_network"].get("subnet")
        or ipaddress.ip_address(observer_ip) not in client_subnet
        or os.environ.get("QCSD_CONTROLLED_ROUTER_CLIENT_IP") != observer_ip
    ):
        raise ValueError("kernel-TX public observer identity is invalid")
    default_route = run(
        ["ip", "-j", "-4", "route", "show", "default"],
        check=False,
    )
    try:
        routes = json.loads(default_route.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("kernel-TX public client default route is not JSON") from error
    if (
        default_route.returncode != 0
        or not isinstance(routes, list)
        or len(routes) != 1
        or not isinstance(routes[0], Mapping)
        or routes[0].get("dst") != "default"
        or routes[0].get("gateway") != observer_ip
        or routes[0].get("dev") != "eth0"
    ):
        raise ValueError("kernel-TX public client does not route exclusively via the observer")
    digest = hashlib.sha256(_canonical_json(network)).hexdigest()
    return network, binding, digest


def _socket_address(ip_text: str, port_text: str) -> str:
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError as error:
        raise RuntimeError("router capture contains an invalid IP address") from error
    if not port_text.isdecimal() or not 1 <= int(port_text) <= 65_535:
        raise RuntimeError("router capture contains an invalid UDP port")
    host = address.compressed
    return f"[{host}]:{port_text}" if address.version == 6 else f"{host}:{port_text}"


def extract_router_udp_packets(capture: Path) -> list[dict[str, Any]]:
    """Extract exact encrypted UDP identities from the router-side PCAPNG."""

    if capture.is_symlink() or not capture.is_file():
        raise RuntimeError("router post-veth capture is not a regular file")
    fields = (
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ipv6.src",
        "udp.srcport",
        "ip.dst",
        "ipv6.dst",
        "udp.dstport",
        "udp.length",
        "udp.payload",
    )
    command = [
        "tshark",
        "-r",
        str(capture),
        "-Y",
        "udp",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ]
    for field in fields:
        command.extend(("-e", field))
    completed = run(command, check=False)
    if completed.returncode != 0:
        raise RuntimeError("cannot extract the router post-veth UDP packets")
    packets: list[dict[str, Any]] = []
    for packet_index, line in enumerate(completed.stdout.splitlines()):
        columns = line.split("\t")
        if len(columns) != len(fields):
            raise RuntimeError("router packet extraction has an ambiguous field layout")
        (
            frame_number_text,
            epoch_text,
            ipv4_source,
            ipv6_source,
            source_port,
            ipv4_destination,
            ipv6_destination,
            destination_port,
            udp_length_text,
            payload_hex,
        ) = columns
        if (
            not frame_number_text.isdecimal()
            or int(frame_number_text) != packet_index + 1
            or bool(ipv4_source) == bool(ipv6_source)
            or bool(ipv4_destination) == bool(ipv6_destination)
            or not udp_length_text.isdecimal()
            or int(udp_length_text) < 8
        ):
            raise RuntimeError("router packet identity fields are invalid")
        try:
            epoch_nanoseconds = Decimal(epoch_text) * 1_000_000_000
            integral_epoch = epoch_nanoseconds.to_integral_exact()
            payload = bytes.fromhex(payload_hex.replace(":", ""))
        except (InvalidOperation, ValueError) as error:
            raise RuntimeError("router packet timestamp or payload is invalid") from error
        if epoch_nanoseconds != integral_epoch or len(payload) != int(udp_length_text) - 8:
            raise RuntimeError("router UDP payload length or timestamp precision is inconsistent")
        source_ip = ipv4_source or ipv6_source
        destination_ip = ipv4_destination or ipv6_destination
        packets.append(
            {
                "schema_version": 1,
                "packet_index": packet_index,
                "frame_number": int(frame_number_text),
                "capture_realtime_ns": int(integral_epoch),
                "source_address": _socket_address(source_ip, source_port),
                "destination_address": _socket_address(destination_ip, destination_port),
                "udp_payload_bytes": len(payload),
                "datagram_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return packets


def kernel_tx_lab_runtime_required(*, defense_kind: str, scheduler_contract: str | None) -> bool:
    """Return whether this attempt must produce independent kernel-TX evidence."""

    return bool(
        defense_kind == "buflo"
        and scheduler_contract == "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"
    )


def require_post_veth_capture_configuration() -> tuple[str, int, str, Path]:
    """Validate the controlled-router observer configuration before mutation."""

    endpoint = os.environ.get(KERNEL_TX_POST_VETH_ENDPOINT_ENV, "")
    secret = os.environ.get(KERNEL_TX_POST_VETH_SECRET_ENV, "")
    raw_root = os.environ.get(KERNEL_TX_POST_VETH_ROOT_ENV, "")
    host, separator, port_text = endpoint.rpartition(":")
    if not separator or not host or not port_text.isdecimal():
        raise ValueError(
            "kernel-timed BuFLO requires the controlled router post-veth capture endpoint"
        )
    port = int(port_text)
    if not 1 <= port <= 65_535:
        raise ValueError("kernel-TX router capture port is outside the valid range")
    if _SECRET.fullmatch(secret) is None:
        raise ValueError("kernel-TX router capture secret is missing or malformed")
    root = Path(raw_root)
    if not raw_root or not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("kernel-TX router capture root is not a safe mounted directory")
    return host, port, secret, root


def _tc_json(interface: str) -> list[dict[str, Any]]:
    completed = run(
        ["tc", "-details", "-statistics", "-json", "qdisc", "show", "dev", interface],
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("cannot observe the client qdisc tree")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("client qdisc observation is not JSON") from error
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise RuntimeError("client qdisc observation is not an array of objects")
    return [dict(row) for row in value]


def _tc_apply(arguments: Sequence[str]) -> None:
    completed = run(["tc", *arguments], check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"client qdisc command failed: {' '.join(arguments)}")


def _canonical_initial_qdisc(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Accept only Docker-veth ``noqueue``, whose restoration is deterministic."""

    if len(rows) != 1:
        raise RuntimeError("kernel-TX setup requires one restorable initial root qdisc")
    row = rows[0]
    if (
        row.get("kind") != "noqueue"
        or row.get("handle") != "0:"
        or row.get("root") is not True
        or row.get("parent") is not None
    ):
        raise RuntimeError("kernel-TX setup supports only the Docker-veth noqueue baseline")
    return [{"kind": "noqueue", "handle": "0:", "root": True, "parent": None}]


def _normalise_toggle(value: Any) -> bool:
    if value in {False, 0, "off", None}:
        return False
    if value in {True, 1, "on"}:
        return True
    raise RuntimeError(f"qdisc toggle has an unknown representation: {value!r}")


def _installed_entries(rows: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    by_kind: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        kind = row.get("kind")
        if not isinstance(kind, str) or kind in by_kind:
            raise RuntimeError("installed qdisc tree has a missing or duplicate kind")
        by_kind[kind] = row
    if set(by_kind) != {"prio", "pfifo", "etf"}:
        raise RuntimeError("installed qdisc tree differs from PRIO/FIFO/ETF")
    prio = by_kind["prio"]
    fifo = by_kind["pfifo"]
    etf = by_kind["etf"]
    prio_options = prio.get("options")
    fifo_options = fifo.get("options")
    etf_options = etf.get("options")
    if (
        prio.get("handle") != "1:"
        or prio.get("root") is not True
        or not isinstance(prio_options, Mapping)
        or prio_options.get("bands") != 2
        or prio_options.get("priomap") != KERNEL_TX_PRIO_MAP
        or fifo.get("handle") != "10:"
        or fifo.get("parent") != "1:2"
        or not isinstance(fifo_options, Mapping)
        or fifo_options.get("limit") != KERNEL_TX_FIFO_LIMIT_PACKETS
        or etf.get("handle") != "20:"
        or etf.get("parent") != "1:1"
        or not isinstance(etf_options, Mapping)
        or etf_options.get("clockid") not in {"TAI", "CLOCK_TAI"}
        or etf_options.get("delta") != KERNEL_TX_ETF_DELTA_NS
        or _normalise_toggle(etf_options.get("offload"))
        or _normalise_toggle(etf_options.get("deadline_mode"))
        or _normalise_toggle(etf_options.get("skip_sock_check"))
    ):
        raise RuntimeError("installed qdisc options differ from the kernel-TX contract")
    return by_kind


def _nonnegative_counter(row: Mapping[str, Any], key: str) -> int:
    value = row.get(key, 0)
    if type(value) is not int or value < 0:
        raise RuntimeError(f"ETF qdisc counter {key} is unavailable")
    return value


def _backlog(row: Mapping[str, Any], *, qlen: int) -> tuple[int, int]:
    value = row.get("backlog", 0)
    if type(value) is int and value == 0 and qlen == 0:
        return 0, 0
    if isinstance(value, str):
        match = re.fullmatch(r"([0-9]+)b(?:\s+([0-9]+)p)?", value)
        if match is not None:
            backlog_bytes = int(match.group(1))
            backlog_packets = int(match.group(2) or 0)
            if backlog_packets == qlen and (match.group(2) is not None or qlen == 0):
                return backlog_bytes, backlog_packets
    raise RuntimeError("ETF qdisc backlog counter is unavailable")


def _qdisc_counter_snapshot(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    etf = _installed_entries(rows)["etf"]
    qlen = _nonnegative_counter(etf, "qlen")
    backlog_bytes, backlog_packets = _backlog(etf, qlen=qlen)
    return {
        "packets": _nonnegative_counter(etf, "packets"),
        "bytes": _nonnegative_counter(etf, "bytes"),
        "drops": _nonnegative_counter(etf, "drops"),
        "overlimits": _nonnegative_counter(etf, "overlimits"),
        "requeues": _nonnegative_counter(etf, "requeues"),
        "backlog_bytes": backlog_bytes,
        "backlog_packets": backlog_packets,
        "qlen": qlen,
    }


def expected_qdisc_contract(interface: str = KERNEL_TX_INTERFACE) -> dict[str, Any]:
    """Return the Lab-observable, socket-independent part of the Rust contract."""

    return {
        "interface": interface,
        "root_kind": "prio",
        "root_handle": "1:",
        "bands": 2,
        "priomap": list(KERNEL_TX_PRIO_MAP),
        "timed_kind": "etf",
        "timed_parent": "1:1",
        "timed_handle": "20:",
        "ordinary_kind": "pfifo",
        "ordinary_parent": "1:2",
        "ordinary_handle": "10:",
        "clock_id": "CLOCK_TAI",
        "delta_ns": KERNEL_TX_ETF_DELTA_NS,
        "deadline_mode": False,
        "offload": False,
        "skip_socket_check": False,
        "timed_socket_priority": 6,
        "ordinary_socket_priority": 0,
    }


@dataclass
class KernelTxQdiscSession:
    """Install, observe, and exactly restore one client-side qdisc tree."""

    interface: str = KERNEL_TX_INTERFACE
    _initial: list[dict[str, Any]] | None = None
    _before: dict[str, int] | None = None
    _root_replaced: bool = False
    _restored: bool = False

    def install(self) -> dict[str, int]:
        if self._initial is not None:
            raise RuntimeError("kernel-TX qdisc session was already installed")
        initial_rows = _tc_json(self.interface)
        self._initial = _canonical_initial_qdisc(initial_rows)
        try:
            _tc_apply(
                [
                    "qdisc",
                    "replace",
                    "dev",
                    self.interface,
                    "root",
                    "handle",
                    "1:",
                    "prio",
                    "bands",
                    "2",
                    "priomap",
                    *(str(value) for value in KERNEL_TX_PRIO_MAP),
                ]
            )
            self._root_replaced = True
            _tc_apply(
                [
                    "qdisc",
                    "replace",
                    "dev",
                    self.interface,
                    "parent",
                    "1:2",
                    "handle",
                    "10:",
                    "pfifo",
                    "limit",
                    str(KERNEL_TX_FIFO_LIMIT_PACKETS),
                ]
            )
            _tc_apply(
                [
                    "qdisc",
                    "replace",
                    "dev",
                    self.interface,
                    "parent",
                    "1:1",
                    "handle",
                    "20:",
                    "etf",
                    "clockid",
                    "CLOCK_TAI",
                    "delta",
                    str(KERNEL_TX_ETF_DELTA_NS),
                ]
            )
            self._before = _qdisc_counter_snapshot(_tc_json(self.interface))
        except BaseException:
            self.restore()
            raise
        if any(self._before[key] for key in self._before):
            self.restore()
            raise RuntimeError("fresh ETF qdisc did not begin with zero counters and backlog")
        return dict(self._before)

    def finish_observation(self) -> dict[str, Any]:
        if self._initial is None or self._before is None or self._restored:
            raise RuntimeError("kernel-TX qdisc session is not active")
        after = _qdisc_counter_snapshot(_tc_json(self.interface))
        self.restore()
        return {
            "schema_version": 1,
            "source": "tc-json-v1",
            "installed_before_runner": True,
            "verified_after_runner": True,
            "restored_after_capture": True,
            "before": dict(self._before),
            "after": after,
        }

    def restore(self) -> None:
        if self._initial is None or self._restored:
            return
        if self._root_replaced:
            completed = run(
                ["tc", "qdisc", "delete", "dev", self.interface, "root"],
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError("failed to remove the kernel-TX root qdisc")
        restored = _canonical_initial_qdisc(_tc_json(self.interface))
        if restored != self._initial:
            raise RuntimeError("client qdisc baseline was not restored exactly")
        self._restored = True


def bind_qdisc_observation(
    observation: Mapping[str, Any], runner_contract: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind restored Lab counters to the full socket-aware runner contract."""

    expected_keys = {
        "schema_version",
        "source",
        "installed_before_runner",
        "verified_after_runner",
        "restored_after_capture",
        "before",
        "after",
    }
    if set(observation) != expected_keys:
        raise RuntimeError("kernel-TX qdisc observation schema is invalid")
    observable = expected_qdisc_contract()
    if any(runner_contract.get(key) != value for key, value in observable.items()):
        raise RuntimeError("runner and Lab qdisc contracts differ")
    return {**dict(observation), "observed_contract": dict(runner_contract)}


class RouterCaptureClient:
    """Authenticated controller for the independent router capture service."""

    def __init__(self, capture_id: str) -> None:
        if _CAPTURE_ID.fullmatch(capture_id) is None:
            raise ValueError("kernel-TX capture identity is malformed")
        host, port, secret, root = require_post_veth_capture_configuration()
        self._host = host
        self._port = port
        self._secret = secret
        self.root = root
        self.capture_id = capture_id
        self._started = False
        self._stopped = False
        self._consumed = False

    def _request(self, action: str, **fields: Any) -> dict[str, Any]:
        request = {
            "schema_version": 1,
            "action": action,
            "secret": self._secret,
            "capture_id": self.capture_id,
            **fields,
        }
        encoded = json.dumps(
            request,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        with socket.create_connection((self._host, self._port), timeout=10.0) as connection:
            connection.sendall(encoded)
            reader = connection.makefile("rb")
            response_raw = reader.readline(65_537)
        if not response_raw.endswith(b"\n") or len(response_raw) > 65_536:
            raise RuntimeError("router capture service returned an invalid response frame")
        try:
            response = json.loads(response_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("router capture service response is not JSON") from error
        if (
            not isinstance(response, dict)
            or response.get("schema_version") != 1
            or response.get("capture_id") != self.capture_id
            or response.get("status") != "ok"
        ):
            detail = response.get("error") if isinstance(response, dict) else None
            raise RuntimeError(f"router capture service rejected {action}: {detail or 'unknown'}")
        return response

    def start(self, *, duration_seconds: int, max_megabytes: int) -> None:
        if self._started or self._stopped or self._consumed:
            raise RuntimeError("router capture identity was already used")
        self._request(
            "start",
            duration_seconds=duration_seconds,
            max_megabytes=max_megabytes,
        )
        self._started = True

    def stop(self) -> tuple[Path, dict[str, Any]]:
        if not self._started:
            raise RuntimeError("router capture was not started")
        self._request("stop")
        capture = self.root / f"{self.capture_id}.pcapng"
        receipt = self.root / f"{self.capture_id}.json"
        if (
            capture.is_symlink()
            or receipt.is_symlink()
            or not capture.is_file()
            or not receipt.is_file()
        ):
            raise RuntimeError("router capture service did not publish regular artifacts")
        try:
            value = json.loads(receipt.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("router capture receipt is unavailable or invalid") from error
        if not isinstance(value, dict) or value.get("capture_id") != self.capture_id:
            raise RuntimeError("router capture receipt identity differs from the request")
        self._started = False
        self._stopped = True
        return capture, value

    def consume(
        self,
        *,
        pcapng_sha256: str,
        receipt_sha256: str,
        log_sha256: str,
    ) -> None:
        """Ask the privileged service to remove one copied, hash-bound triplet."""

        if not self._stopped or self._started:
            raise RuntimeError("router capture was not stopped before consume")
        digests = (pcapng_sha256, receipt_sha256, log_sha256)
        if any(
            not isinstance(value, str) or _CAPTURE_ID.fullmatch(value) is None
            for value in digests
        ):
            raise ValueError("router capture consume hash is malformed")
        self._request(
            "consume",
            pcapng_sha256=pcapng_sha256,
            receipt_sha256=receipt_sha256,
            log_sha256=log_sha256,
        )
        self._stopped = False
        self._consumed = True
