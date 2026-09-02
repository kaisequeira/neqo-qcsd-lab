"""Authenticated post-veth capture service for controlled and public campaigns.

The service runs in the router namespace.  Each immutable capture receipt
therefore records the interface, route, qdisc and NAT state immediately after
capture activation and again after the dumpcap child has terminated.  This is
the independent boundary that a sender-side client receipt cannot provide.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socketserver
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

_CAPTURE_ID = re.compile(r"[0-9a-f]{64}\Z")
_SECRET = re.compile(r"[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DROP_LINE = re.compile(
    r"Packets received/dropped on interface .+: ([0-9]+)/([0-9]+) "
    r"\(pcap:([0-9]+)/dumpcap:([0-9]+)/flushed:([0-9]+)/ps_ifdrop:([0-9]+)\)"
)
_PACKET_COUNT = re.compile(r"^Number of packets:\s+([0-9]+)$", re.MULTILINE)
_MAX_REQUEST_BYTES = 4_096
_TOPOLOGY_KINDS = {"shared-two-network-router", "routed-public-egress"}


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


class CaptureState:
    """Own exactly one dumpcap child at a time."""

    def __init__(
        self,
        *,
        root: Path,
        secret: str,
        interface: str,
        topology_kind: str,
        uplink_interface: str,
        client_subnet: str | None,
        require_masquerade: bool,
    ) -> None:
        if root.is_symlink() or not root.is_dir() or not root.is_absolute():
            raise ValueError("router capture root must be an existing absolute directory")
        if _SECRET.fullmatch(secret) is None:
            raise ValueError("router capture secret must be 32 random bytes in lowercase hex")
        if not interface or "/" in interface or interface.strip() != interface:
            raise ValueError("router capture interface is malformed")
        if topology_kind not in _TOPOLOGY_KINDS:
            raise ValueError("router capture topology kind is invalid")
        if (
            not uplink_interface
            or "/" in uplink_interface
            or uplink_interface.strip() != uplink_interface
            or uplink_interface == interface
        ):
            raise ValueError("router capture uplink interface is malformed")
        if require_masquerade != (topology_kind == "routed-public-egress"):
            raise ValueError("router capture NAT requirement differs from topology")
        if client_subnet is not None:
            import ipaddress

            try:
                canonical_subnet = str(ipaddress.ip_network(client_subnet, strict=True))
            except ValueError as error:
                raise ValueError("router capture client subnet is invalid") from error
            if canonical_subnet != client_subnet or ":" in canonical_subnet:
                raise ValueError("router capture client subnet is not canonical IPv4")
        elif require_masquerade:
            raise ValueError("public router capture requires a client subnet")
        self.root = root
        self.secret = secret
        self.interface = interface
        self.topology_kind = topology_kind
        self.uplink_interface = uplink_interface
        self.client_subnet = client_subnet
        self.require_masquerade = require_masquerade
        self.capture_id: str | None = None
        self.process: subprocess.Popen[str] | None = None
        self.log_handle: Any = None
        self.start_realtime_ns: int | None = None
        self.router_state_start: dict[str, Any] | None = None
        self.consumed_capture_ids: set[str] = set()

    @staticmethod
    def _json_command(command: list[str]) -> Any:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"router state command failed ({command!r}): {completed.stderr.strip()}"
            )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"router state command was not JSON ({command!r})") from error

    def _router_state(self, *, capture_process_state: str) -> dict[str, Any]:
        if capture_process_state not in {"capturing", "idle"}:
            raise ValueError("router capture process state is invalid")
        interfaces = {
            name: self._json_command(["ip", "-j", "address", "show", "dev", name])
            for name in (self.interface, self.uplink_interface)
        }
        qdiscs = {
            name: self._json_command(
                ["tc", "-details", "-statistics", "-j", "qdisc", "show", "dev", name]
            )
            for name in (self.interface, self.uplink_interface)
        }
        offloads = {
            name: self._json_command(["ethtool", "--json", "--show-features", name])
            for name in (self.interface, self.uplink_interface)
        }
        routes = self._json_command(["ip", "-j", "-4", "route", "show", "table", "main"])
        nat = subprocess.run(
            ["iptables-save", "-t", "nat"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if nat.returncode != 0:
            raise RuntimeError(f"router NAT table observation failed: {nat.stderr.strip()}")
        nat_rules = [
            line
            for line in nat.stdout.splitlines()
            if line and not line.startswith("#")
        ]
        ipv4_forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text(
            encoding="ascii"
        ).strip()
        if ipv4_forwarding not in {"0", "1"}:
            raise RuntimeError("router IPv4 forwarding observation is invalid")
        masquerade_present = False
        if self.client_subnet is not None:
            masquerade = subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-s",
                    self.client_subnet,
                    "-o",
                    self.uplink_interface,
                    "-j",
                    "MASQUERADE",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if masquerade.returncode not in {0, 1}:
                raise RuntimeError("router masquerade rule observation failed")
            masquerade_present = masquerade.returncode == 0
        default_uplink = any(
            isinstance(route, Mapping)
            and route.get("dst") == "default"
            and route.get("dev") == self.uplink_interface
            for route in routes
        )
        capture_active = self.process is not None and self.process.poll() is None
        if capture_active != (capture_process_state == "capturing"):
            raise RuntimeError("router dumpcap child state does not match the receipt phase")
        return {
            "schema_version": 1,
            "topology_kind": self.topology_kind,
            "capture_process_state": capture_process_state,
            "capture_process_active": capture_active,
            "client_interface": self.interface,
            "uplink_interface": self.uplink_interface,
            "client_subnet": self.client_subnet,
            "ipv4_forwarding": int(ipv4_forwarding),
            "interfaces": interfaces,
            "routes": routes,
            "qdiscs": qdiscs,
            "offloads": offloads,
            "nat_rules": nat_rules,
            "invariants": {
                "client_interface_present": bool(interfaces[self.interface]),
                "uplink_interface_present": bool(interfaces[self.uplink_interface]),
                "ipv4_forwarding_enabled": ipv4_forwarding == "1",
                "uplink_default_route_present": default_uplink,
                "source_masquerade_required": self.require_masquerade,
                "source_masquerade_present": masquerade_present,
            },
        }

    def _paths(self, capture_id: str) -> tuple[Path, Path, Path]:
        return (
            self.root / f"{capture_id}.pcapng",
            self.root / f"{capture_id}.log",
            self.root / f"{capture_id}.json",
        )

    def _validate_common(self, request: Any, *, action: str, keys: set[str]) -> str:
        if not isinstance(request, Mapping) or set(request) != keys:
            raise ValueError(f"router capture {action} request schema is invalid")
        capture_id = request.get("capture_id")
        if (
            request.get("schema_version") != 1
            or request.get("action") != action
            or request.get("secret") != self.secret
            or not isinstance(capture_id, str)
            or _CAPTURE_ID.fullmatch(capture_id) is None
        ):
            raise ValueError(f"router capture {action} request identity is invalid")
        return capture_id

    def start(self, request: Any) -> None:
        capture_id = self._validate_common(
            request,
            action="start",
            keys={
                "schema_version",
                "action",
                "secret",
                "capture_id",
                "duration_seconds",
                "max_megabytes",
            },
        )
        duration = request["duration_seconds"]
        max_megabytes = request["max_megabytes"]
        if (
            type(duration) is not int
            or not 1 <= duration <= 300
            or type(max_megabytes) is not int
            or not 1 <= max_megabytes <= 1_024
            or self.process is not None
            or capture_id in self.consumed_capture_ids
        ):
            raise ValueError("router capture start bounds/state are invalid")
        capture_path, log_path, receipt_path = self._paths(capture_id)
        if any(
            path.exists() or path.is_symlink()
            for path in (capture_path, log_path, receipt_path)
        ):
            raise ValueError("router capture identity already exists")
        self.log_handle = log_path.open("x", encoding="utf-8")
        self.start_realtime_ns = time.time_ns()
        self.process = subprocess.Popen(
            [
                "dumpcap",
                "-i",
                self.interface,
                "--time-stamp-type",
                "host",
                "-f",
                "udp",
                "-w",
                str(capture_path),
                "-a",
                f"duration:{duration}",
                "-a",
                f"filesize:{max_megabytes * 1024}",
            ],
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            self.log_handle.flush()
            if self.process.poll() is not None:
                break
            try:
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                log_text = ""
            if (
                "Capturing on " in log_text
                and capture_path.is_file()
                and capture_path.stat().st_size > 0
            ):
                # The pcapng section header can precede activation of the
                # packet loop.  Keep this bounded service-side settle outside
                # the measured client interval, then verify dumpcap survived.
                time.sleep(0.05)
                if self.process.poll() is not None:
                    break
                self.capture_id = capture_id
                try:
                    self.router_state_start = self._router_state(
                        capture_process_state="capturing"
                    )
                except Exception:
                    process = self.process
                    self._clear_process()
                    if process is not None and process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
                    raise
                return
            time.sleep(0.01)
        process = self.process
        self._clear_process()
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        raise RuntimeError("router dumpcap did not become ready")

    def _clear_process(self) -> None:
        if self.log_handle is not None:
            self.log_handle.close()
        self.log_handle = None
        self.process = None
        self.capture_id = None
        self.start_realtime_ns = None
        self.router_state_start = None

    def stop(self, request: Any) -> None:
        capture_id = self._validate_common(
            request,
            action="stop",
            keys={"schema_version", "action", "secret", "capture_id"},
        )
        if self.process is None or self.capture_id != capture_id or self.start_realtime_ns is None:
            raise ValueError("router capture stop does not match the active capture")
        process = self.process
        start_realtime_ns = self.start_realtime_ns
        router_state_start = self.router_state_start
        capture_path, log_path, receipt_path = self._paths(capture_id)
        if process.poll() is not None:
            self.log_handle.flush()
            self._clear_process()
            raise RuntimeError("router dumpcap exited before the explicit stop boundary")
        capture_active_at_stop = True
        process.send_signal(signal.SIGINT)
        try:
            returncode = process.wait(timeout=10)
        except subprocess.TimeoutExpired as error:
            process.terminate()
            process.wait(timeout=5)
            self._clear_process()
            raise RuntimeError("router dumpcap did not stop after SIGINT") from error
        end_realtime_ns = time.time_ns()
        self.log_handle.flush()
        self._clear_process()
        router_state_end = self._router_state(capture_process_state="idle")
        if (
            returncode not in {0, 2}
            or not capture_path.is_file()
            or capture_path.stat().st_size == 0
        ):
            raise RuntimeError("router dumpcap did not produce a complete capture")
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        drop_matches = list(_DROP_LINE.finditer(log_text))
        if len(drop_matches) != 1:
            raise RuntimeError("router dumpcap did not report one exact drop summary")
        received, dropped, pcap_drop, dumpcap_drop, flushed, ps_ifdrop = (
            int(value) for value in drop_matches[0].groups()
        )
        if dropped != pcap_drop + dumpcap_drop + flushed + ps_ifdrop:
            raise RuntimeError("router dumpcap drop summary does not reconcile")
        capinfos = subprocess.run(
            ["capinfos", "-c", "-M", str(capture_path)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        packet_matches = _PACKET_COUNT.findall(capinfos.stdout)
        if capinfos.returncode != 0 or len(packet_matches) != 1:
            raise RuntimeError("router capture packet count is unavailable")
        packets = int(packet_matches[0])
        if packets > received:
            raise RuntimeError("router capture contains more packets than dumpcap received")
        receipt = {
            "schema_version": 2,
            "artifact_type": "qcsd-kernel-tx-router-capture",
            "capture_id": capture_id,
            "observer_role": "router-ingress-post-client-veth-pre-netem",
            "interface": self.interface,
            "timestamp_clock_id": "CLOCK_REALTIME",
            "timestamp_type": "host",
            "capture_start_realtime_ns": start_realtime_ns,
            "capture_end_realtime_ns": end_realtime_ns,
            "packets_received": packets,
            "packets_dropped": pcap_drop + dumpcap_drop + flushed,
            "interface_packets_dropped": ps_ifdrop,
            "dumpcap_received_packets": received,
            "dumpcap_returncode": returncode,
            "pcapng_sha256": _sha256(capture_path),
            "capture_active_at_stop": capture_active_at_stop,
            "router_state_start": router_state_start,
            "router_state_end": router_state_end,
            "capture_service_end_state": "idle-no-dumpcap-child",
        }
        temporary = receipt_path.with_suffix(".json.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise RuntimeError("router capture temporary receipt path already exists")
        temporary.write_bytes(_canonical_json(receipt))
        os.replace(temporary, receipt_path)
        capture_path.chmod(0o444)
        log_path.chmod(0o444)
        receipt_path.chmod(0o444)

    def consume(self, request: Any) -> None:
        """Delete only an exactly hash-bound capture triplet after publication.

        The measured collection mount is read-only.  The authenticated parent
        therefore asks the router service to remove its originals only after
        all three immutable copies have been published and independently
        hashed in the attempt directory.
        """

        capture_id = self._validate_common(
            request,
            action="consume",
            keys={
                "schema_version",
                "action",
                "secret",
                "capture_id",
                "pcapng_sha256",
                "receipt_sha256",
                "log_sha256",
            },
        )
        if self.process is not None or self.capture_id is not None:
            raise ValueError("router capture consume requires an idle service")
        expected = (
            request.get("pcapng_sha256"),
            request.get("log_sha256"),
            request.get("receipt_sha256"),
        )
        if any(
            not isinstance(value, str) or _SHA256.fullmatch(value) is None
            for value in expected
        ):
            raise ValueError("router capture consume hashes are malformed")
        paths = self._paths(capture_id)
        if any(path.is_symlink() or not path.is_file() for path in paths):
            raise RuntimeError("router capture consume artifacts are missing or unsafe")
        if tuple(_sha256(path) for path in paths) != expected:
            raise RuntimeError("router capture consume artifact hashes differ")
        for path in paths:
            path.unlink()
        self.consumed_capture_ids.add(capture_id)
        descriptor = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class _CaptureServer(socketserver.TCPServer):
    allow_reuse_address = False

    def __init__(self, server_address: tuple[str, int], state: CaptureState) -> None:
        self.state = state
        super().__init__(server_address, _CaptureHandler)


class _CaptureHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(_MAX_REQUEST_BYTES + 1)
        capture_id: Any = None
        try:
            if not raw.endswith(b"\n") or len(raw) > _MAX_REQUEST_BYTES:
                raise ValueError("router capture request frame is invalid")
            request = json.loads(raw)
            capture_id = request.get("capture_id") if isinstance(request, Mapping) else None
            action = request.get("action") if isinstance(request, Mapping) else None
            if action == "start":
                self.server.state.start(request)  # type: ignore[attr-defined]
            elif action == "stop":
                self.server.state.stop(request)  # type: ignore[attr-defined]
            elif action == "consume":
                self.server.state.consume(request)  # type: ignore[attr-defined]
            else:
                raise ValueError("router capture action is unsupported")
            response = {"schema_version": 1, "capture_id": capture_id, "status": "ok"}
        except Exception as error:  # noqa: BLE001 - service boundary reports typed failure.
            response = {
                "schema_version": 1,
                "capture_id": capture_id,
                "status": "error",
                "error": f"{type(error).__name__}: {error}"[:1_024],
            }
        self.wfile.write(_canonical_json(response))


def main() -> None:
    root = Path(os.environ["QCSD_KERNEL_TX_ROUTER_CAPTURE_ROOT"])
    secret = os.environ["QCSD_KERNEL_TX_ROUTER_CAPTURE_SECRET"]
    interface = os.environ.get("QCSD_KERNEL_TX_ROUTER_CAPTURE_INTERFACE", "eth0")
    topology_kind = os.environ.get(
        "QCSD_KERNEL_TX_ROUTER_TOPOLOGY_KIND", "shared-two-network-router"
    )
    uplink_interface = os.environ.get("QCSD_KERNEL_TX_ROUTER_UPLINK_INTERFACE", "eth1")
    client_subnet = os.environ.get("QCSD_KERNEL_TX_ROUTER_CLIENT_SUBNET") or None
    require_masquerade = (
        os.environ.get("QCSD_KERNEL_TX_ROUTER_REQUIRE_MASQUERADE", "0") == "1"
    )
    raw_port = os.environ.get("QCSD_KERNEL_TX_ROUTER_CAPTURE_PORT", "19090")
    if not raw_port.isdecimal() or not 1 <= int(raw_port) <= 65_535:
        raise SystemExit("router capture service port is invalid")
    state = CaptureState(
        root=root,
        secret=secret,
        interface=interface,
        topology_kind=topology_kind,
        uplink_interface=uplink_interface,
        client_subnet=client_subnet,
        require_masquerade=require_masquerade,
    )
    with _CaptureServer(("0.0.0.0", int(raw_port)), state) as server:
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
