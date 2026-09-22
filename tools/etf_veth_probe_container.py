#!/usr/bin/env python3
"""Container workers for the non-evidentiary repeated ETF/veth probe.

The sender records Linux TX_SCHED and TX_SOFTWARE error-queue timestamps and
the peer records SO_TIMESTAMPNS after the sender-side veth. This tests only
kernel timing geometry and post-veth isolation: it does not execute Rust or
QUIC, reproduce the production priority transaction, or exercise a main/helper
split. The HTTP/3 timing-stress PCAP gate remains mandatory.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import select
import socket
import struct
import time
from pathlib import Path
from typing import Any

import etf_probe_container as capability


SCHEMA_VERSION = 2
MAGIC = b"QCSDVETH"
PAYLOAD_BYTES = 1_200
INTERVAL_NS = 20_000_000
STRICT_WINDOW_NS = 5_000_000
ENQUEUE_LEAD_NS = 5_000_000
ACTIVE_WAIT_START_LEAD_NS = 10_000_000
START_LEAD_NS = 500_000_000
ETF_DELTA_NS = 10_000_000
SCM_TSTAMP_SND = 0
SCM_TSTAMP_SCHED = 1


def _payload(series_id: str, sequence: int) -> bytes:
    prefix = MAGIC + bytes.fromhex(series_id) + sequence.to_bytes(8, "big")
    fill = hashlib.sha256(prefix).digest()
    repeats = (PAYLOAD_BYTES - len(prefix) + len(fill) - 1) // len(fill)
    return prefix + (fill * repeats)[: PAYLOAD_BYTES - len(prefix)]


def _identity(data: bytes, series_id: str) -> tuple[int, str] | None:
    prefix_bytes = len(MAGIC) + 16 + 8
    if len(data) != PAYLOAD_BYTES or data[: len(MAGIC)] != MAGIC:
        return None
    if data[len(MAGIC) : len(MAGIC) + 16] != bytes.fromhex(series_id):
        return None
    sequence = int.from_bytes(data[len(MAGIC) + 16 : prefix_bytes], "big")
    expected = _payload(series_id, sequence)
    if data != expected:
        return None
    return sequence, hashlib.sha256(data).hexdigest()


def _queue_masks() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    queue_root = Path("/sys/class/net/eth0/queues")
    for queue in sorted(queue_root.glob("*")):
        fields: dict[str, str] = {}
        for name in ("rps_cpus", "rps_flow_cnt", "xps_cpus", "xps_rxqs"):
            path = queue / name
            try:
                fields[name] = path.read_text(encoding="ascii").strip()
            except OSError:
                continue
        result[queue.name] = fields
    return result


def _scheduler_observation() -> dict[str, Any]:
    policy = os.sched_getscheduler(0)
    names = {
        os.SCHED_OTHER: "SCHED_OTHER",
        os.SCHED_FIFO: "SCHED_FIFO",
        os.SCHED_RR: "SCHED_RR",
    }
    return {
        "pid": os.getpid(),
        "affinity": sorted(os.sched_getaffinity(0)),
        "policy": policy,
        "policy_name": names.get(policy, f"UNKNOWN({policy})"),
        "priority": os.sched_getparam(0).sched_priority,
    }


def _wait_until_tai(target_ns: int, active_wait_start_ns: int) -> dict[str, int]:
    entered_active_tai_ns: int | None = None
    iterations = 0
    while True:
        now = time.clock_gettime_ns(capability.CLOCK_TAI)
        if now >= target_ns:
            return {
                "active_wait_entered_tai_ns": (
                    now if entered_active_tai_ns is None else entered_active_tai_ns
                ),
                "target_reached_tai_ns": now,
                "active_wait_iterations": iterations,
            }
        if now < active_wait_start_ns:
            remaining = active_wait_start_ns - now
            if remaining > 1_000_000:
                time.sleep((remaining - 500_000) / 1_000_000_000)
            continue
        if entered_active_tai_ns is None:
            entered_active_tai_ns = now
        iterations += 1


def _drain_available(sock: socket.socket) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    while True:
        try:
            _data, ancillary, flags, _address = sock.recvmsg(
                256, 1024, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT
            )
        except BlockingIOError:
            break
        delivered_tai_ns = time.clock_gettime_ns(capability.CLOCK_TAI)
        clock_pair = capability._clock_pair()
        errors = capability._extended_error(ancillary)
        timestamp = capability._scm_timestamping_ts0(ancillary)
        converted: dict[str, int] | None = None
        if timestamp is not None:
            converted = {
                **timestamp,
                "realtime_ns": timestamp["raw_ns"],
                "tai_lower_ns": timestamp["raw_ns"] + clock_pair["offset_lower_ns"],
                "tai_upper_ns": timestamp["raw_ns"] + clock_pair["offset_upper_ns"],
            }
        messages.append(
            {
                "flags": flags,
                "delivered_tai_ns": delivered_tai_ns,
                "clock_pair": clock_pair,
                "timestamp": converted,
                "extended_errors": errors,
            }
        )
    return messages


def _write_done(path: Path) -> None:
    path.write_text("done\n", encoding="ascii")
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def receive(args: argparse.Namespace) -> int:
    output = Path(args.output)
    ready = Path(args.ready)
    done = Path(args.done)
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "role": "post-veth-peer",
        "status": "failed",
        "series_id": args.series_id,
        "expected_samples": args.samples,
        "interface": "eth0",
        "observer_role": "peer-ingress-after-sender-veth",
        "configuration": {
            "payload_bytes": PAYLOAD_BYTES,
            "port": args.port,
            "rps_profile": "observe-only-unmodified",
        },
        "available_affinity": sorted(os.sched_getaffinity(0)),
        "scheduler": _scheduler_observation(),
        "queue_masks_start": _queue_masks(),
        "clock_pair_start": capability._clock_pair(),
        "events": [],
    }
    sock: socket.socket | None = None
    done_seen_at_ns: int | None = None
    post_done_drain_completed = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, capability.SO_TIMESTAMPNS, 1)
        sock.bind(("0.0.0.0", args.port))
        ready.write_text("ready\n", encoding="ascii")
        deadline_ns = time.monotonic_ns() + round(args.timeout_seconds * 1_000_000_000)
        seen: set[int] = set()
        while time.monotonic_ns() < deadline_ns:
            now_ns = time.monotonic_ns()
            if done.is_file() and done_seen_at_ns is None:
                done_seen_at_ns = now_ns
            if (
                done_seen_at_ns is not None
                and now_ns - done_seen_at_ns >= 500_000_000
            ):
                post_done_drain_completed = True
                break
            readable, _, _ = select.select([sock], [], [], 0.05)
            if not readable:
                continue
            data, ancillary, flags, address = sock.recvmsg(PAYLOAD_BYTES + 1, 512)
            user_tai_ns = time.clock_gettime_ns(capability.CLOCK_TAI)
            clock_pair = capability._clock_pair()
            kernel = capability._parse_kernel_timestamp(ancillary)
            if kernel is not None:
                kernel["raw_ns"] = kernel["realtime_ns"]
                kernel["tai_lower_ns"] = (
                    kernel["realtime_ns"] + clock_pair["offset_lower_ns"]
                )
                kernel["tai_upper_ns"] = (
                    kernel["realtime_ns"] + clock_pair["offset_upper_ns"]
                )
            identity = _identity(data, args.series_id)
            sequence = identity[0] if identity is not None else None
            if sequence is not None:
                seen.add(sequence)
            receipt["events"].append(
                {
                    "sequence": sequence,
                    "payload_sha256": identity[1] if identity is not None else None,
                    "payload_bytes": len(data),
                    "source": {"address": address[0], "port": address[1]},
                    "message_flags": flags,
                    "kernel_software_timestamp": kernel,
                    "user_tai_ns": user_tai_ns,
                    "clock_pair": clock_pair,
                }
            )
        receipt["status"] = "peer-complete"
    except BaseException as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if sock is not None:
            sock.close()
        receipt["done_marker_observed"] = done_seen_at_ns is not None
        receipt["post_done_drain_completed"] = post_done_drain_completed
        receipt["post_done_drain_elapsed_ns"] = (
            None
            if done_seen_at_ns is None
            else time.monotonic_ns() - done_seen_at_ns
        )
        receipt["queue_masks_end"] = _queue_masks()
        receipt["clock_pair_end"] = capability._clock_pair()
        capability._write_json(output, receipt)
    return 0 if receipt["status"] == "peer-complete" else 1


def _series_send(
    destination: tuple[str, int], *, series_id: str, samples: int
) -> dict[str, Any]:
    sock = capability._txtime_socket(capability.CLOCK_TAI, timestamping=True)
    sock.setblocking(False)
    sock.setsockopt(socket.IPPROTO_IP, capability.IP_TOS, 0x02)
    sock.setsockopt(socket.SOL_SOCKET, capability.SO_PRIORITY, 6)
    start_tai_ns = time.clock_gettime_ns(capability.CLOCK_TAI) + START_LEAD_NS
    events: list[dict[str, Any]] = []
    error_queue: list[dict[str, Any]] = []
    send_id = 0
    try:
        for sequence in range(samples):
            release = start_tai_ns + sequence * INTERVAL_NS
            deadline = release + STRICT_WINDOW_NS
            wait = _wait_until_tai(
                release - ENQUEUE_LEAD_NS,
                release - ACTIVE_WAIT_START_LEAD_NS,
            )
            wake = wait["target_reached_tai_ns"]
            data = _payload(series_id, sequence)
            event: dict[str, Any] = {
                "sequence": sequence,
                "payload_sha256": hashlib.sha256(data).hexdigest(),
                "payload_bytes": len(data),
                "release_tai_ns": release,
                "deadline_tai_ns": deadline,
                "scm_txtime_tai_ns": release + ETF_DELTA_NS,
                "enqueue_wake_tai_ns": wake,
                "active_wait_entered_tai_ns": wait["active_wait_entered_tai_ns"],
                "active_wait_iterations": wait["active_wait_iterations"],
                "send_id": None,
                "sent_bytes": None,
                "send_error": None,
                "outcome": "suppressed-late",
            }
            if wake < release:
                before = time.clock_gettime_ns(capability.CLOCK_TAI)
                try:
                    sent = sock.sendmsg(
                        [data],
                        [
                            (
                                socket.SOL_SOCKET,
                                capability.SCM_TXTIME,
                                struct.pack("=Q", release + ETF_DELTA_NS),
                            )
                        ],
                        0,
                        destination,
                    )
                    after = time.clock_gettime_ns(capability.CLOCK_TAI)
                    event.update(
                        {
                            "send_id": send_id,
                            "sent_bytes": sent,
                            "enqueue_before_tai_ns": before,
                            "enqueue_after_tai_ns": after,
                            "outcome": "enqueued",
                        }
                    )
                    send_id += 1
                except OSError as error:
                    event["send_error"] = {
                        "errno": error.errno,
                        "name": errno.errorcode.get(error.errno, "UNKNOWN"),
                        "message": str(error),
                    }
                    event["outcome"] = "send-error"
            events.append(event)
            error_queue.extend(_drain_available(sock))
        drain_deadline = time.monotonic() + 0.5
        while time.monotonic() < drain_deadline:
            error_queue.extend(_drain_available(sock))
            if len(error_queue) >= send_id * 2:
                break
            time.sleep(0.001)
    finally:
        priority_before_reset = sock.getsockopt(socket.SOL_SOCKET, capability.SO_PRIORITY)
        ip_tos_before_reset = sock.getsockopt(socket.IPPROTO_IP, capability.IP_TOS)
        sock.setsockopt(socket.IPPROTO_IP, capability.IP_TOS, 0)
        sock.setsockopt(socket.SOL_SOCKET, capability.SO_PRIORITY, 0)
        restored = {
            "priority_before_reset": priority_before_reset,
            "ip_tos_before_reset": ip_tos_before_reset,
            "priority_after_reset": sock.getsockopt(
                socket.SOL_SOCKET, capability.SO_PRIORITY
            ),
            "ip_tos_after_reset": sock.getsockopt(socket.IPPROTO_IP, capability.IP_TOS),
        }
        sock.close()
    return {
        "start_tai_ns": start_tai_ns,
        "events": events,
        "error_queue": error_queue,
        "socket_restoration": restored,
    }


def send(args: argparse.Namespace) -> int:
    output = Path(args.output)
    done = Path(args.done)
    commands: list[dict[str, Any]] = []
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "role": "etf-series-sender",
        "status": "failed",
        "series_id": args.series_id,
        "expected_samples": args.samples,
        "interface": "eth0",
        "configuration": {
            "profile": "kernel-timing-geometry-baseline",
            "clockid": "CLOCK_TAI",
            "delta_ns": ETF_DELTA_NS,
            "strict_window_ns": STRICT_WINDOW_NS,
            "interval_ns": INTERVAL_NS,
            "payload_bytes": PAYLOAD_BYTES,
            "enqueue_lead_ns": ENQUEUE_LEAD_NS,
            "active_wait_start_lead_ns": ACTIVE_WAIT_START_LEAD_NS,
            "active_wait_window_ns": ACTIVE_WAIT_START_LEAD_NS - ENQUEUE_LEAD_NS,
            "start_lead_ns": START_LEAD_NS,
            "deadline_mode": False,
            "timed_priority": 6,
            "ipv4_ds_field": 0x02,
            "receiver_name": args.receiver,
            "receiver_port": args.port,
            "main_cpu": args.main_cpu,
            "helper_cpu": args.helper_cpu,
            "cpu_profile": "docker-last-three-baseline",
            "rps_profile": "observe-only-unmodified",
            "scope": "kernel-timing-geometry-and-post-veth-isolation-only",
            "exercises_rust_quic": False,
            "production_priority_transaction": False,
            "main_helper_split_exercised": False,
            "authorizes_http3_gate": False,
        },
        "commands": commands,
        "available_affinity": sorted(os.sched_getaffinity(0)),
        "queue_masks_start": _queue_masks(),
        "clock_pair_start": capability._clock_pair(),
    }
    initial: dict[str, Any] | None = None
    try:
        if args.main_cpu == args.helper_cpu:
            raise RuntimeError("main and helper CPUs must differ")
        available = os.sched_getaffinity(0)
        if args.main_cpu not in available or args.helper_cpu not in available:
            raise RuntimeError("requested series CPUs are outside the container cpuset")
        receiver_ipv4, resolution = capability._resolve_receiver_ipv4(
            args.receiver, args.port
        )
        receipt["receiver_resolution"] = resolution
        receipt["configuration"]["resolved_receiver_ipv4"] = receiver_ipv4
        initial = capability._qdisc_snapshot()
        receipt["qdisc_initial"] = initial
        capability._install_qdisc(commands)
        installed = capability._qdisc_snapshot()
        receipt["qdisc_installed"] = installed
        capability._validate_installed_qdisc(installed)
        os.sched_setaffinity(0, {args.helper_cpu})
        os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(1))
        receipt["scheduler"] = _scheduler_observation()
        receipt["series"] = _series_send(
            (receiver_ipv4, args.port),
            series_id=args.series_id,
            samples=args.samples,
        )
        receipt["qdisc_after_series"] = capability._qdisc_snapshot()
        receipt["status"] = "sender-complete"
    except BaseException as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        commands.append(
            capability._command(
                ["tc", "qdisc", "del", "dev", "eth0", "root"], check=False
            )
        )
        try:
            restored = capability._qdisc_snapshot()
            receipt["qdisc_restored"] = restored
            receipt["qdisc_restoration_exact"] = (
                initial is not None
                and capability._qdisc_shape(initial) == capability._qdisc_shape(restored)
            )
        except BaseException as error:
            receipt["qdisc_restoration_error"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
            receipt["qdisc_restoration_exact"] = False
        receipt["queue_masks_end"] = _queue_masks()
        receipt["clock_pair_end"] = capability._clock_pair()
        capability._write_json(output, receipt)
        _write_done(done)
    return 0 if receipt["status"] == "sender-complete" and receipt["qdisc_restoration_exact"] else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="role", required=True)
    peer = commands.add_parser("receive")
    peer.add_argument("--output", required=True)
    peer.add_argument("--ready", required=True)
    peer.add_argument("--done", required=True)
    peer.add_argument("--series-id", required=True)
    peer.add_argument("--samples", required=True, type=int)
    peer.add_argument("--port", required=True, type=int)
    peer.add_argument("--timeout-seconds", required=True, type=float)
    sender = commands.add_parser("send")
    sender.add_argument("--output", required=True)
    sender.add_argument("--done", required=True)
    sender.add_argument("--receiver", required=True)
    sender.add_argument("--series-id", required=True)
    sender.add_argument("--samples", required=True, type=int)
    sender.add_argument("--port", required=True, type=int)
    sender.add_argument("--main-cpu", required=True, type=int)
    sender.add_argument("--helper-cpu", required=True, type=int)
    return root


def main() -> None:
    args = parser().parse_args()
    if args.role == "receive":
        raise SystemExit(receive(args))
    raise SystemExit(send(args))


if __name__ == "__main__":
    main()
