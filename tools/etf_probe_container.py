#!/usr/bin/env python3
"""Container half of the non-evidentiary QCSD ETF capability probe.

This file is mounted read-only into two disposable containers by the guarded
``qcsd-lab etf-probe`` launcher.  It deliberately has no dependency on the Lab package
so that the probe exercises the selected image's kernel-facing Python and
iproute2 interfaces directly.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import select
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any


CLOCK_TAI = 11
SO_PRIORITY = 12
SO_TIMESTAMPNS = 35
SO_TIMESTAMPING = 37
SO_TXTIME = 61
SCM_TXTIME = SO_TXTIME
SCM_PRIORITY = SO_PRIORITY
IP_RECVERR = 11
IP_TOS = 1
IP_RECVTOS = 13
SOF_TIMESTAMPING_TX_SOFTWARE = 1 << 1
SOF_TIMESTAMPING_SOFTWARE = 1 << 4
SOF_TIMESTAMPING_OPT_ID = 1 << 7
SOF_TIMESTAMPING_TX_SCHED = 1 << 8
SOF_TIMESTAMPING_OPT_TSONLY = 1 << 11
SOF_TXTIME_REPORT_ERRORS = 1 << 1
PROBE_SCHEMA_VERSION = 2
ETF_DELTA_NS = 4_500_000
STRICT_REALIZATION_WINDOW_NS = 5_000_000
PROBE_PAYLOADS = {
    "fifo": b"qcsd-etf-probe:fifo-v1",
    "fifo_concurrent": b"qcsd-etf-probe:fifo-concurrent-v1",
    "scm_priority_preflight": b"qcsd-etf-probe:scm-priority-preflight-v1",
    "missing_socket": b"qcsd-etf-probe:missing-socket-v1",
    "missing_cmsg": b"qcsd-etf-probe:missing-cmsg-v1",
    "wrong_clock": b"qcsd-etf-probe:wrong-clock-v1",
    "past_txtime": b"qcsd-etf-probe:past-txtime-v1",
    "positive": b"qcsd-etf-probe:positive-v1",
}


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _write_json(path: Path, value: Any) -> None:
    path.write_bytes(_canonical_json(value))
    with path.open("rb") as source:
        os.fsync(source.fileno())


def _clock_pair() -> dict[str, int]:
    realtime_before = time.clock_gettime_ns(time.CLOCK_REALTIME)
    tai = time.clock_gettime_ns(CLOCK_TAI)
    realtime_after = time.clock_gettime_ns(time.CLOCK_REALTIME)
    return {
        "realtime_before_ns": realtime_before,
        "tai_ns": tai,
        "realtime_after_ns": realtime_after,
        "offset_lower_ns": tai - realtime_after,
        "offset_upper_ns": tai - realtime_before,
        "bracket_width_ns": realtime_after - realtime_before,
    }


def _parse_kernel_timestamp(ancillary: list[tuple[int, int, bytes]]) -> dict[str, int] | None:
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS and len(data) >= 16:
            seconds, nanoseconds = struct.unpack_from("=qq", data)
            return {
                "seconds": seconds,
                "nanoseconds": nanoseconds,
                "realtime_ns": seconds * 1_000_000_000 + nanoseconds,
            }
    return None


def _parse_ipv4_ds_field(ancillary: list[tuple[int, int, bytes]]) -> int | None:
    for level, kind, data in ancillary:
        if level == socket.IPPROTO_IP and kind == IP_TOS and data:
            return data[0]
    return None


def receive(args: argparse.Namespace) -> int:
    output = Path(args.output)
    ready = Path(args.ready)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    sock.setsockopt(socket.IPPROTO_IP, IP_RECVTOS, 1)
    sock.bind(("0.0.0.0", args.port))
    ready.write_text("ready\n", encoding="ascii")
    events: list[dict[str, Any]] = []
    started_tai_ns = time.clock_gettime_ns(CLOCK_TAI)
    deadline = time.monotonic() + args.timeout_seconds
    try:
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select([sock], [], [], remaining)
            if not readable:
                break
            data, ancillary, _flags, address = sock.recvmsg(2048, 512)
            user_tai_ns = time.clock_gettime_ns(CLOCK_TAI)
            clock_pair = _clock_pair()
            kernel = _parse_kernel_timestamp(ancillary)
            if kernel is not None:
                kernel["tai_lower_ns"] = kernel["realtime_ns"] + clock_pair["offset_lower_ns"]
                kernel["tai_upper_ns"] = kernel["realtime_ns"] + clock_pair["offset_upper_ns"]
            events.append(
                {
                    "payload_ascii": data.decode("ascii", errors="replace"),
                    "payload_hex": data.hex(),
                    "payload_bytes": len(data),
                    "source": {"address": address[0], "port": address[1]},
                    "user_tai_ns": user_tai_ns,
                    "kernel_software_timestamp": kernel,
                    "ipv4_ds_field": _parse_ipv4_ds_field(ancillary),
                    "clock_pair": clock_pair,
                }
            )
    finally:
        sock.close()
    _write_json(
        output,
        {
            "schema_version": PROBE_SCHEMA_VERSION,
            "role": "post-veth-receiver",
            "timeout_seconds": args.timeout_seconds,
            "started_tai_ns": started_tai_ns,
            "finished_tai_ns": time.clock_gettime_ns(CLOCK_TAI),
            "events": events,
        },
    )
    return 0


def _command(arguments: list[str], *, check: bool = True) -> dict[str, Any]:
    started = time.clock_gettime_ns(CLOCK_TAI)
    result = subprocess.run(arguments, capture_output=True, text=True, check=False)
    receipt = {
        "argv": arguments,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "started_tai_ns": started,
        "finished_tai_ns": time.clock_gettime_ns(CLOCK_TAI),
    }
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(arguments)}: {result.stderr.strip()}"
        )
    return receipt


def _qdisc_snapshot() -> dict[str, Any]:
    command = _command(["tc", "-details", "-statistics", "-json", "qdisc", "show", "dev", "eth0"])
    try:
        parsed = json.loads(command["stdout"])
    except json.JSONDecodeError as error:
        raise RuntimeError("tc returned invalid JSON for the qdisc snapshot") from error
    return {"command": command, "qdiscs": parsed}


def _qdisc_shape(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    shape: list[dict[str, Any]] = []
    for raw in snapshot["qdiscs"]:
        item = {
            key: value
            for key, value in raw.items()
            if key not in {"bytes", "packets", "drops", "overlimits", "requeues", "backlog", "qlen"}
        }
        shape.append(item)
    return shape


def _install_qdisc(commands: list[dict[str, Any]]) -> None:
    commands.append(
        _command(
            [
                "tc",
                "qdisc",
                "replace",
                "dev",
                "eth0",
                "root",
                "handle",
                "1:",
                "prio",
                "bands",
                "2",
                "priomap",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "0",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
            ]
        )
    )
    commands.append(
        _command(
            [
                "tc",
                "qdisc",
                "replace",
                "dev",
                "eth0",
                "parent",
                "1:2",
                "handle",
                "10:",
                "pfifo",
                "limit",
                "1000",
            ]
        )
    )
    commands.append(
        _command(
            [
                "tc",
                "qdisc",
                "replace",
                "dev",
                "eth0",
                "parent",
                "1:1",
                "handle",
                "20:",
                "etf",
                "clockid",
                "CLOCK_TAI",
                "delta",
                str(ETF_DELTA_NS),
            ]
        )
    )


def _validate_installed_qdisc(snapshot: dict[str, Any]) -> None:
    by_kind = {entry.get("kind"): entry for entry in snapshot["qdiscs"]}
    if set(by_kind) != {"prio", "pfifo", "etf"}:
        raise RuntimeError(f"unexpected installed qdisc kinds: {sorted(by_kind)}")
    prio = by_kind["prio"]
    fifo = by_kind["pfifo"]
    etf = by_kind["etf"]
    if prio.get("handle") != "1:" or not prio.get("root"):
        raise RuntimeError("root PRIO qdisc identity is incorrect")
    options = prio.get("options", {})
    if options.get("bands") != 2 or options.get("priomap") != [1] * 6 + [0] + [1] * 9:
        raise RuntimeError("root PRIO qdisc options are incorrect")
    if fifo.get("handle") != "10:" or fifo.get("parent") != "1:2":
        raise RuntimeError("normal FIFO qdisc identity is incorrect")
    if fifo.get("options", {}).get("limit") != 1000:
        raise RuntimeError("normal FIFO qdisc limit is incorrect")
    if etf.get("handle") != "20:" or etf.get("parent") != "1:1":
        raise RuntimeError("ETF qdisc identity is incorrect")
    etf_options = etf.get("options", {})
    if etf_options.get("clockid") not in {"TAI", "CLOCK_TAI"}:
        raise RuntimeError("ETF qdisc does not use CLOCK_TAI")
    if etf_options.get("delta") != ETF_DELTA_NS:
        raise RuntimeError("ETF qdisc delta is incorrect")
    if any(
        etf_options.get(key) not in {False, "off", 0, None}
        for key in ("offload", "deadline_mode", "skip_sock_check")
    ):
        raise RuntimeError("ETF qdisc enabled a forbidden mode")


def _txtime_socket(clockid: int, *, timestamping: bool) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(
        socket.SOL_SOCKET,
        SO_TXTIME,
        struct.pack("=iI", clockid, SOF_TXTIME_REPORT_ERRORS),
    )
    sock.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
    if timestamping:
        flags = (
            SOF_TIMESTAMPING_TX_SOFTWARE
            | SOF_TIMESTAMPING_SOFTWARE
            | SOF_TIMESTAMPING_OPT_ID
            | SOF_TIMESTAMPING_TX_SCHED
            | SOF_TIMESTAMPING_OPT_TSONLY
        )
        sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPING, flags)
    return sock


def _extended_error(ancillary: list[tuple[int, int, bytes]]) -> list[dict[str, int]]:
    errors: list[dict[str, int]] = []
    for level, kind, data in ancillary:
        if level == socket.SOL_IP and kind == IP_RECVERR and len(data) >= 16:
            values = struct.unpack_from("=IBBBxII", data)
            errors.append(
                {
                    "errno": values[0],
                    "origin": values[1],
                    "type": values[2],
                    "code": values[3],
                    "info": values[4],
                    "data": values[5],
                }
            )
    return errors


def _scm_timestamping_ts0(
    ancillary: list[tuple[int, int, bytes]],
) -> dict[str, int] | None:
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPING and len(data) >= 48:
            values = struct.unpack_from("=qqqqqq", data)
            if values[0] or values[1]:
                return {
                    "seconds": values[0],
                    "nanoseconds": values[1],
                    "raw_ns": values[0] * 1_000_000_000 + values[1],
                }
    return None


def _drain_error_queue(sock: socket.socket, *, until_monotonic: float) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    sock.setblocking(False)
    while time.monotonic() < until_monotonic:
        try:
            _data, ancillary, flags, _address = sock.recvmsg(
                256, 1024, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT
            )
        except BlockingIOError:
            time.sleep(0.001)
            continue
        errors = _extended_error(ancillary)
        timestamp = _scm_timestamping_ts0(ancillary)
        origins = {error["origin"] for error in errors}
        timestamp_origin = origins == {4}
        txtime_origin = origins == {6}
        messages.append(
            {
                "flags": flags,
                "tx_software_timestamp": (
                    None
                    if timestamp is None or not timestamp_origin
                    else {
                        **timestamp,
                        "realtime_ns": timestamp["raw_ns"],
                    }
                ),
                "txtime_context_timestamp": (
                    None
                    if timestamp is None or not txtime_origin
                    else {
                        **timestamp,
                        "requested_txtime_tai_ns": timestamp["raw_ns"],
                    }
                ),
                "extended_errors": errors,
            }
        )
    return messages


def _control_send(
    name: str,
    destination: tuple[str, int],
    *,
    clockid: int | None,
    include_cmsg: bool,
    target_ns: int | None,
    timestamping: bool = False,
) -> dict[str, Any]:
    started = time.clock_gettime_ns(CLOCK_TAI)
    sock = (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if clockid is None
        else _txtime_socket(clockid, timestamping=timestamping)
    )
    sock.setsockopt(socket.SOL_SOCKET, SO_PRIORITY, 6)
    priority_before = sock.getsockopt(socket.SOL_SOCKET, SO_PRIORITY)
    send_error: dict[str, Any] | None = None
    sent_bytes: int | None = None
    ancillary = []
    if include_cmsg:
        if target_ns is None:
            raise AssertionError("SCM_TXTIME requires a target")
        ancillary.append((socket.SOL_SOCKET, SCM_TXTIME, struct.pack("=Q", target_ns)))
    try:
        sent_bytes = sock.sendmsg([PROBE_PAYLOADS[name]], ancillary, 0, destination)
    except OSError as error:
        send_error = {
            "errno": error.errno,
            "name": errno.errorcode.get(error.errno, "UNKNOWN"),
            "message": str(error),
        }
    queue = _drain_error_queue(sock, until_monotonic=time.monotonic() + 0.08)
    sock.setsockopt(socket.SOL_SOCKET, SO_PRIORITY, 0)
    priority_after = sock.getsockopt(socket.SOL_SOCKET, SO_PRIORITY)
    sock.close()
    return {
        "name": name,
        "destination": {"ipv4": destination[0], "port": destination[1]},
        "started_tai_ns": started,
        "finished_tai_ns": time.clock_gettime_ns(CLOCK_TAI),
        "clockid": clockid,
        "include_cmsg": include_cmsg,
        "timestamping": timestamping,
        "target_ns": target_ns,
        "priority_mechanism": "serialized-socket-global-SO_PRIORITY",
        "priority_before_send": priority_before,
        "priority_after_reset": priority_after,
        "sent_bytes": sent_bytes,
        "send_error": send_error,
        "error_queue": queue,
    }


def _send_fifo(destination: tuple[str, int]) -> dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, SO_PRIORITY, 0)
    before = time.clock_gettime_ns(CLOCK_TAI)
    sent = sock.sendto(PROBE_PAYLOADS["fifo"], destination)
    after = time.clock_gettime_ns(CLOCK_TAI)
    sock.close()
    return {
        "destination": {"ipv4": destination[0], "port": destination[1]},
        "sent_bytes": sent,
        "before_tai_ns": before,
        "after_tai_ns": after,
    }


def _scm_priority_preflight(destination: tuple[str, int]) -> dict[str, Any]:
    """Test the ancillary API before ETF can reject an otherwise valid packet."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    before = time.clock_gettime_ns(CLOCK_TAI)
    sent: int | None = None
    error_value: dict[str, Any] | None = None
    try:
        sent = sock.sendmsg(
            [PROBE_PAYLOADS["scm_priority_preflight"]],
            [(socket.SOL_SOCKET, SCM_PRIORITY, struct.pack("=i", 6))],
            0,
            destination,
        )
    except OSError as error:
        error_value = {
            "errno": error.errno,
            "name": errno.errorcode.get(error.errno, "UNKNOWN"),
            "message": str(error),
        }
    after = time.clock_gettime_ns(CLOCK_TAI)
    sock.close()
    return {
        "mechanism": "per-datagram-SCM_PRIORITY",
        "destination": {"ipv4": destination[0], "port": destination[1]},
        "priority": 6,
        "sent_bytes": sent,
        "send_error": error_value,
        "before_tai_ns": before,
        "after_tai_ns": after,
        "supported": sent == len(PROBE_PAYLOADS["scm_priority_preflight"]),
    }


def _positive_helper(
    write_fd: int,
    parent_pid: int,
    destination: tuple[str, int],
    helper_cpu: int,
    lead_ns: int,
) -> None:
    stream = os.fdopen(write_fd, "w", encoding="utf-8", buffering=1)
    release_tai_ns = time.clock_gettime_ns(CLOCK_TAI) + lead_ns
    ready: dict[str, Any] = {
        "phase": "ready-for-serialized-priority-transaction",
        "release_tai_ns": release_tai_ns,
        "deadline_tai_ns": release_tai_ns + STRICT_REALIZATION_WINDOW_NS,
        "scm_txtime_tai_ns": release_tai_ns + ETF_DELTA_NS,
        "so_txtime_flags": SOF_TXTIME_REPORT_ERRORS,
        "deadline_mode": False,
        "destination": {"ipv4": destination[0], "port": destination[1]},
    }
    final: dict[str, Any] = {"phase": "final", **ready}
    sock: socket.socket | None = None
    try:
        os.sched_setaffinity(0, {helper_cpu})
        ready["affinity"] = sorted(os.sched_getaffinity(0))
        ready["helper_pid"] = os.getpid()
        ready["parent_pid"] = parent_pid
        stream.write(json.dumps(ready, sort_keys=True) + "\n")
        # The parent stops immediately after consuming the ready record.  This
        # bounded lead separates its authoritative stop timestamp from the
        # beginning of the one-owner socket-priority transaction.
        time.sleep(0.02)
        sock = _txtime_socket(CLOCK_TAI, timestamping=True)
        transaction_before = time.clock_gettime_ns(CLOCK_TAI)
        original_ip_tos = sock.getsockopt(socket.IPPROTO_IP, IP_TOS)
        original_priority = sock.getsockopt(socket.SOL_SOCKET, SO_PRIORITY)
        ip_tos_set_before = time.clock_gettime_ns(CLOCK_TAI)
        sock.setsockopt(socket.IPPROTO_IP, IP_TOS, 0x02)
        ip_tos_set_after = time.clock_gettime_ns(CLOCK_TAI)
        ip_tos_readback = sock.getsockopt(socket.IPPROTO_IP, IP_TOS)
        priority_set_before = time.clock_gettime_ns(CLOCK_TAI)
        sock.setsockopt(socket.SOL_SOCKET, SO_PRIORITY, 6)
        priority_set_after = time.clock_gettime_ns(CLOCK_TAI)
        priority_during = sock.getsockopt(socket.SOL_SOCKET, SO_PRIORITY)
        enqueue_before = time.clock_gettime_ns(CLOCK_TAI)
        try:
            sent = sock.sendmsg(
                [PROBE_PAYLOADS["positive"]],
                [
                    (
                        socket.SOL_SOCKET,
                        SCM_TXTIME,
                        struct.pack("=Q", ready["scm_txtime_tai_ns"]),
                    )
                ],
                0,
                destination,
            )
            enqueue_after = time.clock_gettime_ns(CLOCK_TAI)
        finally:
            reset_before = time.clock_gettime_ns(CLOCK_TAI)
            ip_tos_restore_before = time.clock_gettime_ns(CLOCK_TAI)
            try:
                sock.setsockopt(socket.IPPROTO_IP, IP_TOS, original_ip_tos)
                ip_tos_after = sock.getsockopt(socket.IPPROTO_IP, IP_TOS)
                ip_tos_restore_after = time.clock_gettime_ns(CLOCK_TAI)
            finally:
                priority_restore_before = time.clock_gettime_ns(CLOCK_TAI)
                sock.setsockopt(socket.SOL_SOCKET, SO_PRIORITY, original_priority)
                priority_after = sock.getsockopt(socket.SOL_SOCKET, SO_PRIORITY)
                priority_restore_after = time.clock_gettime_ns(CLOCK_TAI)
            reset_after = time.clock_gettime_ns(CLOCK_TAI)
        transaction_after = time.clock_gettime_ns(CLOCK_TAI)
        final["serialized_priority_transaction"] = {
            "mechanism": "socket-global-SO_PRIORITY",
            "single_owner": "helper child while parent is SIGSTOPped",
            "destination": {"ipv4": destination[0], "port": destination[1]},
            "transaction_before_tai_ns": transaction_before,
            "ipv4_ds_field": 0x02,
            "ipv4_ecn": "ECT(0)",
            "ip_tos_set_before_tai_ns": ip_tos_set_before,
            "ip_tos_set_after_tai_ns": ip_tos_set_after,
            "ip_tos_readback_before_priority": ip_tos_readback,
            "priority_set_before_tai_ns": priority_set_before,
            "priority_set_after_tai_ns": priority_set_after,
            "socket_option_order": ["IP_TOS=0x02", "SO_PRIORITY=6"],
            "per_message_ancillary": ["SCM_TXTIME"],
            "original_ip_tos": original_ip_tos,
            "original_priority": original_priority,
            "priority_during_send": priority_during,
            "enqueue_before_tai_ns": enqueue_before,
            "enqueue_after_tai_ns": enqueue_after,
            "sent_bytes": sent,
            "reset_before_tai_ns": reset_before,
            "ip_tos_restore_before_tai_ns": ip_tos_restore_before,
            "ip_tos_restore_after_tai_ns": ip_tos_restore_after,
            "ip_tos_after_reset": ip_tos_after,
            "priority_restore_before_tai_ns": priority_restore_before,
            "priority_restore_after_tai_ns": priority_restore_after,
            "reset_after_tai_ns": reset_after,
            "priority_after_reset": priority_after,
            "socket_restore_order": ["IP_TOS=0x00", "SO_PRIORITY=0"],
            "transaction_after_tai_ns": transaction_after,
        }
        # Use the same socket after the verified reset.  The ordinary datagram
        # must enter the low FIFO band while the timed packet remains queued in
        # the high ETF band.
        normal_before = time.clock_gettime_ns(CLOCK_TAI)
        normal_ip_tos_before = sock.getsockopt(socket.IPPROTO_IP, IP_TOS)
        normal_priority_before = sock.getsockopt(socket.SOL_SOCKET, SO_PRIORITY)
        normal_sent = sock.sendmsg(
            [PROBE_PAYLOADS["fifo_concurrent"]],
            [(socket.IPPROTO_IP, IP_TOS, struct.pack("=i", 0x02))],
            0,
            destination,
        )
        normal_after = time.clock_gettime_ns(CLOCK_TAI)
        final["concurrent_priority_zero"] = {
            "socket_priority_configuration": "same-socket-read-back-zero-after-reset",
            "destination": {"ipv4": destination[0], "port": destination[1]},
            "socket_ip_tos_before_send": normal_ip_tos_before,
            "priority_readback": normal_priority_before,
            "per_message_ancillary": ["IP_TOS=0x02"],
            "ipv4_ds_field": 0x02,
            "ipv4_ecn": "ECT(0)",
            "sent_bytes": normal_sent,
            "before_tai_ns": normal_before,
            "after_tai_ns": normal_after,
            "socket_ip_tos_after_send": sock.getsockopt(socket.IPPROTO_IP, IP_TOS),
            "priority_after_send": sock.getsockopt(socket.SOL_SOCKET, SO_PRIORITY),
        }
        messages = _drain_error_queue(
            sock,
            until_monotonic=time.monotonic() + (lead_ns / 1_000_000_000) + 0.15,
        )
        final["error_queue"] = messages
        final["clock_pair"] = _clock_pair()
    except BaseException as error:  # helper must always resume the stopped parent
        final["error"] = {"type": type(error).__name__, "message": str(error)}
        if "helper_pid" not in ready:
            stream.write(json.dumps(ready, sort_keys=True) + "\n")
    finally:
        if sock is not None:
            sock.close()
        resume_at = release_tai_ns + 30_000_000
        while time.clock_gettime_ns(CLOCK_TAI) < resume_at:
            time.sleep(0.001)
        final["sigcont_tai_ns"] = time.clock_gettime_ns(CLOCK_TAI)
        os.kill(parent_pid, signal.SIGCONT)
        stream.write(json.dumps(final, sort_keys=True) + "\n")
        stream.close()


def _positive_send(
    destination: tuple[str, int], *, main_cpu: int, helper_cpu: int, lead_ns: int
) -> dict[str, Any]:
    os.sched_setaffinity(0, {main_cpu})
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            _positive_helper(write_fd, os.getppid(), destination, helper_cpu, lead_ns)
        finally:
            os._exit(0)
    os.close(write_fd)
    stream = os.fdopen(read_fd, "r", encoding="utf-8")
    first = stream.readline()
    if not first:
        os.waitpid(child, 0)
        raise RuntimeError("timed helper exited before reporting its queued send")
    ready = json.loads(first)
    stop_before = time.clock_gettime_ns(CLOCK_TAI)
    os.kill(os.getpid(), signal.SIGSTOP)
    resumed = time.clock_gettime_ns(CLOCK_TAI)
    second = stream.readline()
    stream.close()
    _pid, status = os.waitpid(child, 0)
    if not second:
        raise RuntimeError("timed helper did not report its final result")
    final = json.loads(second)
    return {
        "main_affinity": sorted(os.sched_getaffinity(0)),
        "helper_wait_status": status,
        "ready": ready,
        "final": final,
        "main_sigstop_before_tai_ns": stop_before,
        "main_resumed_tai_ns": resumed,
    }


def _resolve_receiver_ipv4(receiver: str, port: int) -> tuple[str, dict[str, Any]]:
    """Resolve exactly one numeric IPv4 destination before qdisc accounting."""

    started = time.clock_gettime_ns(CLOCK_TAI)
    try:
        answers = socket.getaddrinfo(
            receiver,
            port,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
    except socket.gaierror as error:
        raise RuntimeError(f"cannot resolve ETF receiver IPv4 address: {error}") from error
    candidates: set[str] = set()
    for family, kind, protocol, _canonical_name, sockaddr in answers:
        if (
            family != socket.AF_INET
            or kind != socket.SOCK_DGRAM
            or protocol not in {0, socket.IPPROTO_UDP}
            or not isinstance(sockaddr, tuple)
            or len(sockaddr) < 2
        ):
            raise RuntimeError("ETF receiver resolution returned an unexpected address record")
        try:
            address = str(ipaddress.IPv4Address(sockaddr[0]))
        except ipaddress.AddressValueError as error:
            raise RuntimeError("ETF receiver resolution returned a non-IPv4 address") from error
        candidates.add(address)
    if len(candidates) != 1:
        raise RuntimeError(
            f"ETF receiver resolution requires exactly one IPv4 address, got {len(candidates)}"
        )
    address = next(iter(candidates))
    finished = time.clock_gettime_ns(CLOCK_TAI)
    return address, {
        "mechanism": "AF_INET/SOCK_DGRAM-getaddrinfo-before-qdisc",
        "requested_name": receiver,
        "port": port,
        "candidate_ipv4": sorted(candidates),
        "resolved_ipv4": address,
        "started_tai_ns": started,
        "finished_tai_ns": finished,
    }


def send(args: argparse.Namespace) -> int:
    output = Path(args.output)
    commands: list[dict[str, Any]] = []
    receipt: dict[str, Any] = {
        "schema_version": PROBE_SCHEMA_VERSION,
        "role": "etf-sender",
        "status": "failed",
        "interface": "eth0",
        "configuration": {
            "clockid": "CLOCK_TAI",
            "delta_ns": ETF_DELTA_NS,
            "realization_window_ns": STRICT_REALIZATION_WINDOW_NS,
            "normal_priority": 0,
            "timed_priority": 6,
            "timed_priority_mechanism": "serialized-socket-global-SO_PRIORITY",
            "so_txtime_flags": SOF_TXTIME_REPORT_ERRORS,
            "deadline_mode": False,
            "ipv4_ds_field": 0x02,
            "ipv4_ecn": "ECT(0)",
            "ipv4_ds_field_mechanism": "socket-global-IP_TOS-before-SO_PRIORITY",
            "per_message_ip_tos": False,
            "receiver_name": args.receiver,
            "receiver_port": args.port,
            "main_cpu": args.main_cpu,
            "helper_cpu": args.helper_cpu,
            "lead_ns": args.lead_ns,
        },
        "commands": commands,
        "kernel_release": os.uname().release,
        "available_affinity": sorted(os.sched_getaffinity(0)),
        "clock_pair_start": _clock_pair(),
    }
    initial: dict[str, Any] | None = None
    try:
        if args.main_cpu == args.helper_cpu:
            raise RuntimeError("main and helper CPUs must differ")
        available = os.sched_getaffinity(0)
        if args.main_cpu not in available or args.helper_cpu not in available:
            raise RuntimeError("requested probe CPUs are outside the container cpuset")
        receiver_ipv4, resolution = _resolve_receiver_ipv4(args.receiver, args.port)
        receipt["receiver_resolution"] = resolution
        receipt["configuration"]["resolved_receiver_ipv4"] = receiver_ipv4
        destination = (receiver_ipv4, args.port)
        initial = _qdisc_snapshot()
        receipt["qdisc_initial"] = initial
        receipt["scm_priority_preflight"] = _scm_priority_preflight(destination)
        _install_qdisc(commands)
        installed = _qdisc_snapshot()
        receipt["qdisc_installed"] = installed
        _validate_installed_qdisc(installed)
        receipt["fifo_control"] = _send_fifo(destination)
        now_tai = time.clock_gettime_ns(CLOCK_TAI)
        receipt["negative_controls"] = [
            _control_send(
                "missing_socket",
                destination,
                clockid=None,
                include_cmsg=True,
                target_ns=now_tai + 100_000_000,
            ),
            _control_send(
                "missing_cmsg",
                destination,
                clockid=CLOCK_TAI,
                include_cmsg=False,
                target_ns=None,
            ),
            _control_send(
                "wrong_clock",
                destination,
                clockid=time.CLOCK_MONOTONIC,
                include_cmsg=True,
                target_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC) + 100_000_000,
            ),
            _control_send(
                "past_txtime",
                destination,
                clockid=CLOCK_TAI,
                include_cmsg=True,
                target_ns=time.clock_gettime_ns(CLOCK_TAI) - 1_000_000,
                timestamping=True,
            ),
        ]
        receipt["qdisc_after_negative_controls"] = _qdisc_snapshot()
        receipt["positive"] = _positive_send(
            destination,
            main_cpu=args.main_cpu,
            helper_cpu=args.helper_cpu,
            lead_ns=args.lead_ns,
        )
        receipt["qdisc_after_positive"] = _qdisc_snapshot()
        receipt["status"] = "sender-complete"
    except BaseException as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        commands.append(_command(["tc", "qdisc", "del", "dev", "eth0", "root"], check=False))
        try:
            restored = _qdisc_snapshot()
            receipt["qdisc_restored"] = restored
            receipt["qdisc_restoration_exact"] = (
                initial is not None and _qdisc_shape(initial) == _qdisc_shape(restored)
            )
        except BaseException as error:
            receipt["qdisc_restoration_error"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
            receipt["qdisc_restoration_exact"] = False
        receipt["clock_pair_end"] = _clock_pair()
        _write_json(output, receipt)
    return 0 if receipt["status"] == "sender-complete" and receipt["qdisc_restoration_exact"] else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="role", required=True)
    receiver = commands.add_parser("receive")
    receiver.add_argument("--output", required=True)
    receiver.add_argument("--ready", required=True)
    receiver.add_argument("--port", required=True, type=int)
    receiver.add_argument("--timeout-seconds", required=True, type=float)
    sender = commands.add_parser("send")
    sender.add_argument("--output", required=True)
    sender.add_argument("--receiver", required=True)
    sender.add_argument("--port", required=True, type=int)
    sender.add_argument("--main-cpu", required=True, type=int)
    sender.add_argument("--helper-cpu", required=True, type=int)
    sender.add_argument("--lead-ns", required=True, type=int)
    return root


def main() -> None:
    args = parser().parse_args()
    if args.role == "receive":
        raise SystemExit(receive(args))
    raise SystemExit(send(args))


if __name__ == "__main__":
    main()
