"""Create-only repeated ETF/veth timing diagnostic.

This preflight is deliberately non-evidentiary. It tests only kernel timing
geometry and post-veth isolation. It does not execute Rust or QUIC, reproduce
the production priority transaction, or exercise a main/helper split. The
HTTP/3 timing stress remains mandatory.
"""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import json
import os
import platform
import re
import secrets
import stat
from pathlib import Path
from typing import Any

from .etf_probe import (
    DEFAULT_IMAGE,
    DOCKER_SUPERVISOR,
    _canonical_json,
    _docker_provenance,
    _git_command,
    _load_json_value,
    _sha256_bytes,
    _validate_image_reference,
)
from .util import LAB_ROOT, durable_create, fsync_directory, sha256_file


ARTIFACT_TYPE = "qcsd-etf-veth-series-probe"
SCHEMA_VERSION = 2
PREVIOUS_SCHEMA_VERSION = 1
REQUEST_TYPE = "qcsd-etf-veth-supervised-request"
REQUEST_SCHEMA_VERSION = 1
CONTAINER_TOOL = LAB_ROOT / "tools/etf_veth_probe_container.py"
CAPABILITY_TOOL = LAB_ROOT / "tools/etf_probe_container.py"
PORT = 45679
MIN_SAMPLES = 16
MAX_SAMPLES = 4_096
DEFAULT_SAMPLES = 2_048
PAYLOAD_BYTES = 1_200
# Linux tc accounts this veth packet as UDP payload plus IPv4, UDP, and
# Ethernet headers (the live schema-1 baseline independently observed 1,242).
ETF_QDISC_BYTES_PER_PACKET = PAYLOAD_BYTES + 20 + 8 + 14
INTERVAL_NS = 20_000_000
STRICT_WINDOW_NS = 5_000_000
ETF_DELTA_NS = 10_000_000
ENQUEUE_LEAD_NS = 5_000_000
ACTIVE_WAIT_START_LEAD_NS = 10_000_000
MAX_CLOCK_BRACKET_NS = 250_000
PROFILE = "kernel-timing-geometry-baseline"
HISTORICAL_PROFILE = "production-baseline"
CPU_PROFILE = "docker-last-three-baseline"
RPS_PROFILE = "observe-only-unmodified"
PURPOSE = (
    "Kernel timing-geometry/post-veth-isolation preflight only. It does not "
    "execute Rust/QUIC construction, the production priority transaction, "
    "or a main/helper split and cannot authorise the mandatory HTTP/3 PCAP, "
    "qualification, campaign, capture, or attestation gate."
)
HISTORICAL_PURPOSE = (
    "Repeated sender-kernel/peer-kernel ETF-veth preflight only; the bundle "
    "cannot satisfy a qualification, campaign, capture, or attestation gate."
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SERIES_ID = re.compile(r"[0-9a-f]{32}\Z")


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def _validate_destination(destination: Path) -> Path:
    destination = destination.absolute()
    parent = destination.parent
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"ETF/veth probe bundle already exists: {destination}")
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError(f"ETF/veth probe destination parent is unsafe: {parent}")
    if not stat.S_ISDIR(parent.lstat().st_mode):
        raise ValueError("ETF/veth probe destination parent is not a directory")
    return destination


def _host_provenance() -> dict[str, Any]:
    def git(*arguments: str) -> str:
        return _git_command(LAB_ROOT, *arguments).strip()

    status = git("status", "--porcelain", "--untracked-files=all")
    return {
        "lab_commit": git("rev-parse", "HEAD"),
        "lab_dirty": bool(status),
        "lab_status": status.splitlines(),
        "neqo_commit": _git_command(
            LAB_ROOT / "neqo-qcsd", "rev-parse", "HEAD"
        ).strip(),
        "neqo_gitlink": git("ls-files", "--stage", "--", "neqo-qcsd").split()[1],
        "source_files": {
            path.relative_to(LAB_ROOT).as_posix(): sha256_file(path)
            for path in (
                Path(__file__),
                LAB_ROOT / "src/qcsd_lab/etf_probe.py",
                CONTAINER_TOOL,
                CAPABILITY_TOOL,
                LAB_ROOT / "qcsd-lab",
                DOCKER_SUPERVISOR,
            )
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
    }


def prepare_supervised_request(path: Path, argv: list[str]) -> dict[str, Any]:
    """Validate public arguments before the guarded launcher mutates Docker."""

    args = parser().parse_args(argv)
    destination = _validate_destination(args.destination)
    image = _validate_image_reference(args.image)
    if args.profile != PROFILE:
        raise ValueError(
            "ETF/veth probe supports only the kernel-timing-geometry-baseline profile"
        )
    if type(args.samples) is not int or not MIN_SAMPLES <= args.samples <= MAX_SAMPLES:
        raise ValueError(
            f"ETF/veth probe samples must be between {MIN_SAMPLES} and {MAX_SAMPLES}"
        )
    for source in (CONTAINER_TOOL, CAPABILITY_TOOL, DOCKER_SUPERVISOR):
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"ETF/veth probe source file is unavailable: {source.name}")
    request = {
        "artifact_type": REQUEST_TYPE,
        "schema_version": REQUEST_SCHEMA_VERSION,
        "destination": str(destination),
        "image": image,
        "samples": args.samples,
        "profile": PROFILE,
        "series_id": secrets.token_hex(16),
        "started_at": _utc_now(),
        "source": _host_provenance(),
    }
    durable_create(path, _canonical_json(request))
    path.chmod(0o400)
    fsync_directory(path.parent)
    return request


def load_supervised_request(path: Path) -> dict[str, Any]:
    value = _load_json_value(path, label="ETF/veth supervised request")
    if not isinstance(value, dict) or set(value) != {
        "artifact_type",
        "schema_version",
        "destination",
        "image",
        "samples",
        "profile",
        "series_id",
        "started_at",
        "source",
    }:
        raise ValueError("ETF/veth supervised request fields are invalid")
    if (
        value.get("artifact_type") != REQUEST_TYPE
        or value.get("schema_version") != REQUEST_SCHEMA_VERSION
        or value.get("profile") != PROFILE
        or not isinstance(value.get("source"), dict)
        or not isinstance(value.get("started_at"), str)
        or _SERIES_ID.fullmatch(str(value.get("series_id"))) is None
        or type(value.get("samples")) is not int
        or not MIN_SAMPLES <= value["samples"] <= MAX_SAMPLES
    ):
        raise ValueError("ETF/veth supervised request identity is invalid")
    return {
        **value,
        "destination": str(_validate_destination(Path(value["destination"]))),
        "image": _validate_image_reference(value["image"]),
    }


def supervised_docker_binding(
    request_path: Path,
    version_path: Path,
    info_path: Path,
    image_path: Path,
) -> tuple[str, int, int, str]:
    request = load_supervised_request(request_path)
    docker = _docker_provenance(
        image=request["image"],
        version_path=version_path,
        info_path=info_path,
        image_path=image_path,
    )
    return (
        docker["image"]["id"],
        docker["info"]["NCPU"],
        request["samples"],
        request["series_id"],
    )


def _qdisc(sender: dict[str, Any], snapshot: str, kind: str) -> dict[str, Any] | None:
    rows = sender.get(snapshot, {}).get("qdiscs", [])
    matches = [row for row in rows if isinstance(row, dict) and row.get("kind") == kind]
    return matches[0] if len(matches) == 1 else None


def _counter(row: dict[str, Any] | None, name: str) -> int | None:
    if row is None:
        return None
    value = row.get(name)
    return value if type(value) is int and value >= 0 else None


def _percentile(values: list[int], numerator: int, denominator: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, (len(ordered) * numerator + denominator - 1) // denominator)
    return ordered[min(rank, len(ordered)) - 1]


def _summary(values: list[int]) -> dict[str, int | None]:
    return {
        "count": len(values),
        "min_ns": min(values) if values else None,
        "p50_ns": _percentile(values, 50, 100),
        "p90_ns": _percentile(values, 90, 100),
        "p95_ns": _percentile(values, 95, 100),
        "p99_ns": _percentile(values, 99, 100),
        "p999_ns": _percentile(values, 999, 1_000),
        "max_ns": max(values) if values else None,
    }


def _timestamp_messages(sender: dict[str, Any]) -> tuple[dict[tuple[int, int], Any], list[Any]]:
    indexed: dict[tuple[int, int], Any] = {}
    invalid: list[Any] = []
    for message in sender.get("series", {}).get("error_queue", []):
        if not isinstance(message, dict):
            invalid.append(message)
            continue
        errors = message.get("extended_errors")
        timestamp = message.get("timestamp")
        if not isinstance(errors, list) or len(errors) != 1 or not isinstance(timestamp, dict):
            invalid.append(message)
            continue
        error = errors[0]
        if (
            not isinstance(error, dict)
            or error.get("origin") != 4
            or error.get("errno") != errno.ENOMSG
            or error.get("info") not in {0, 1}
            or type(error.get("data")) is not int
            or error["data"] < 0
        ):
            invalid.append(message)
            continue
        key = (error["data"], error["info"])
        if key in indexed:
            invalid.append(message)
            continue
        indexed[key] = message
    return indexed, invalid


def _window_state(timestamp: Any, release: int, deadline: int) -> str:
    if (
        not isinstance(timestamp, dict)
        or type(timestamp.get("tai_lower_ns")) is not int
        or type(timestamp.get("tai_upper_ns")) is not int
        or timestamp["tai_lower_ns"] > timestamp["tai_upper_ns"]
    ):
        return "invalid"
    lower = timestamp["tai_lower_ns"]
    upper = timestamp["tai_upper_ns"]
    if upper < release:
        return "before-release"
    if lower < release:
        return "spans-complete-window" if upper >= deadline else "release-straddle"
    if lower >= deadline:
        return "proven-late"
    if upper >= deadline:
        return "deadline-straddle"
    return "within"


def _clock_pair_values(value: Any) -> tuple[int, int] | None:
    if not isinstance(value, dict):
        return None
    names = (
        "realtime_before_ns",
        "tai_ns",
        "realtime_after_ns",
        "offset_lower_ns",
        "offset_upper_ns",
        "bracket_width_ns",
    )
    if any(type(value.get(name)) is not int for name in names):
        return None
    before = value["realtime_before_ns"]
    tai = value["tai_ns"]
    after = value["realtime_after_ns"]
    lower = value["offset_lower_ns"]
    upper = value["offset_upper_ns"]
    width = value["bracket_width_ns"]
    if (
        before > after
        or width != after - before
        or width > MAX_CLOCK_BRACKET_NS
        or lower != tai - after
        or upper != tai - before
        or lower > upper
    ):
        return None
    return lower, upper


def _timestamp_matches_pair(
    timestamp: Any, pair: Any, *, require_raw_ns: bool
) -> bool:
    offsets = _clock_pair_values(pair)
    if not isinstance(timestamp, dict) or offsets is None:
        return False
    if any(
        type(timestamp.get(name)) is not int
        for name in (
            "seconds",
            "nanoseconds",
            "realtime_ns",
            "tai_lower_ns",
            "tai_upper_ns",
        )
    ):
        return False
    nanoseconds = timestamp["nanoseconds"]
    if not 0 <= nanoseconds < 1_000_000_000:
        return False
    raw = timestamp["seconds"] * 1_000_000_000 + nanoseconds
    if timestamp["realtime_ns"] != raw:
        return False
    if require_raw_ns and timestamp.get("raw_ns") != raw:
        return False
    if "raw_ns" in timestamp and timestamp.get("raw_ns") != raw:
        return False
    lower, upper = offsets
    return (
        timestamp["tai_lower_ns"] == raw + lower
        and timestamp["tai_upper_ns"] == raw + upper
        and timestamp["tai_lower_ns"] <= timestamp["tai_upper_ns"]
    )


def _clock_integrity(
    *,
    start: Any,
    end: Any,
    observations: list[tuple[str, Any, Any]],
    require_raw_ns: bool,
) -> tuple[bool, dict[str, Any]]:
    labelled_pairs: list[tuple[str, Any]] = [("start", start), ("end", end)]
    labelled_pairs.extend((label, pair) for label, _timestamp, pair in observations)
    invalid_pairs = [
        label for label, pair in labelled_pairs if _clock_pair_values(pair) is None
    ]
    invalid_timestamps = [
        label
        for label, timestamp, pair in observations
        if not _timestamp_matches_pair(
            timestamp, pair, require_raw_ns=require_raw_ns
        )
    ]
    valid_offsets = [
        offsets
        for _label, pair in labelled_pairs
        if (offsets := _clock_pair_values(pair)) is not None
    ]
    common_lower = max((value[0] for value in valid_offsets), default=None)
    common_upper = min((value[1] for value in valid_offsets), default=None)
    common_envelope = (
        len(valid_offsets) == len(labelled_pairs)
        and common_lower is not None
        and common_upper is not None
        and common_lower <= common_upper
    )
    chronology = False
    if _clock_pair_values(start) is not None and _clock_pair_values(end) is not None:
        chronology = bool(
            start["realtime_before_ns"] <= start["realtime_after_ns"]
            <= end["realtime_before_ns"] <= end["realtime_after_ns"]
            and start["tai_ns"] <= end["tai_ns"]
            and all(
                start["realtime_before_ns"]
                <= pair.get("realtime_before_ns", -1)
                <= pair.get("realtime_after_ns", -1)
                <= end["realtime_after_ns"]
                for _label, _timestamp, pair in observations
                if isinstance(pair, dict)
            )
        )
    passed = bool(
        observations
        and not invalid_pairs
        and not invalid_timestamps
        and common_envelope
        and chronology
    )
    widths = [
        pair["bracket_width_ns"]
        for _label, pair in labelled_pairs
        if _clock_pair_values(pair) is not None
    ]
    return passed, {
        "observation_count": len(observations),
        "pair_count": len(labelled_pairs),
        "max_bracket_width_ns": max(widths, default=None),
        "configured_max_bracket_width_ns": MAX_CLOCK_BRACKET_NS,
        "raw_realtime_and_derived_intervals_exact": not invalid_timestamps,
        "all_pairs_well_formed_and_bounded": not invalid_pairs,
        "common_offset_lower_ns": common_lower,
        "common_offset_upper_ns": common_upper,
        "common_offset_envelope_intersects": common_envelope,
        "start_event_end_chronology": chronology,
        "invalid_pairs": invalid_pairs[:20],
        "invalid_timestamps": invalid_timestamps[:20],
        "invalid_pair_count": len(invalid_pairs),
        "invalid_timestamp_count": len(invalid_timestamps),
    }


def evaluate_series(
    sender: dict[str, Any], peer: dict[str, Any], *, samples: int, series_id: str
) -> dict[str, Any]:
    """Correlate unique packets and separate integrity from diagnosed tails."""

    gates: dict[str, dict[str, Any]] = {}

    def gate(name: str, passed: bool, detail: Any) -> None:
        gates[name] = {"passed": bool(passed), "detail": detail}

    configuration = sender.get("configuration", {})
    gate(
        "output_identity",
        sender.get("schema_version") == SCHEMA_VERSION
        and peer.get("schema_version") == SCHEMA_VERSION
        and sender.get("role") == "etf-series-sender"
        and peer.get("role") == "post-veth-peer"
        and sender.get("status") == "sender-complete"
        and peer.get("status") == "peer-complete"
        and sender.get("series_id") == peer.get("series_id") == series_id
        and sender.get("expected_samples") == peer.get("expected_samples") == samples,
        {
            "sender_schema": sender.get("schema_version"),
            "peer_schema": peer.get("schema_version"),
            "sender_status": sender.get("status"),
            "peer_status": peer.get("status"),
            "sender_series_id": sender.get("series_id"),
            "peer_series_id": peer.get("series_id"),
        },
    )
    gate(
        "kernel_timing_geometry_profile",
        configuration.get("profile") == PROFILE
        and configuration.get("clockid") == "CLOCK_TAI"
        and configuration.get("delta_ns") == ETF_DELTA_NS
        and configuration.get("strict_window_ns") == STRICT_WINDOW_NS
        and configuration.get("interval_ns") == INTERVAL_NS
        and configuration.get("payload_bytes") == PAYLOAD_BYTES
        and configuration.get("enqueue_lead_ns") == ENQUEUE_LEAD_NS
        and configuration.get("active_wait_start_lead_ns")
        == ACTIVE_WAIT_START_LEAD_NS
        and configuration.get("active_wait_window_ns")
        == ACTIVE_WAIT_START_LEAD_NS - ENQUEUE_LEAD_NS
        and configuration.get("deadline_mode") is False
        and configuration.get("cpu_profile") == CPU_PROFILE
        and configuration.get("rps_profile") == RPS_PROFILE
        and configuration.get("scope")
        == "kernel-timing-geometry-and-post-veth-isolation-only"
        and configuration.get("exercises_rust_quic") is False
        and configuration.get("production_priority_transaction") is False
        and configuration.get("main_helper_split_exercised") is False
        and configuration.get("authorizes_http3_gate") is False,
        configuration,
    )
    sender_clock_observations: list[tuple[str, Any, Any]] = []
    raw_error_queue = sender.get("series", {}).get("error_queue", [])
    if isinstance(raw_error_queue, list):
        for index, message in enumerate(raw_error_queue):
            if isinstance(message, dict):
                sender_clock_observations.append(
                    (
                        f"error_queue[{index}]",
                        message.get("timestamp"),
                        message.get("clock_pair"),
                    )
                )
            else:
                sender_clock_observations.append(
                    (f"error_queue[{index}]", None, None)
                )
    sender_clock_passed, sender_clock_detail = _clock_integrity(
        start=sender.get("clock_pair_start"),
        end=sender.get("clock_pair_end"),
        observations=sender_clock_observations,
        require_raw_ns=True,
    )
    gate("sender_clock_integrity", sender_clock_passed, sender_clock_detail)

    peer_clock_observations: list[tuple[str, Any, Any]] = []
    raw_peer_events = peer.get("events", [])
    if isinstance(raw_peer_events, list):
        for index, event in enumerate(raw_peer_events):
            if isinstance(event, dict):
                peer_clock_observations.append(
                    (
                        f"events[{index}]",
                        event.get("kernel_software_timestamp"),
                        event.get("clock_pair"),
                    )
                )
            else:
                peer_clock_observations.append((f"events[{index}]", None, None))
    peer_clock_passed, peer_clock_detail = _clock_integrity(
        start=peer.get("clock_pair_start"),
        end=peer.get("clock_pair_end"),
        observations=peer_clock_observations,
        require_raw_ns=True,
    )
    gate("peer_clock_integrity", peer_clock_passed, peer_clock_detail)
    sender_lower = sender_clock_detail.get("common_offset_lower_ns")
    sender_upper = sender_clock_detail.get("common_offset_upper_ns")
    peer_lower = peer_clock_detail.get("common_offset_lower_ns")
    peer_upper = peer_clock_detail.get("common_offset_upper_ns")
    cross_lower = (
        max(sender_lower, peer_lower)
        if type(sender_lower) is int and type(peer_lower) is int
        else None
    )
    cross_upper = (
        min(sender_upper, peer_upper)
        if type(sender_upper) is int and type(peer_upper) is int
        else None
    )
    cross_observer_clock = bool(
        sender_clock_passed
        and peer_clock_passed
        and cross_lower is not None
        and cross_upper is not None
        and cross_lower <= cross_upper
    )
    gate(
        "cross_observer_clock_envelope",
        cross_observer_clock,
        {
            "sender_offset_lower_ns": sender_lower,
            "sender_offset_upper_ns": sender_upper,
            "peer_offset_lower_ns": peer_lower,
            "peer_offset_upper_ns": peer_upper,
            "common_offset_lower_ns": cross_lower,
            "common_offset_upper_ns": cross_upper,
            "common_offset_envelope_intersects": cross_observer_clock,
        },
    )
    drain_elapsed = peer.get("post_done_drain_elapsed_ns")
    gate(
        "peer_completed_post_sender_drain",
        peer.get("done_marker_observed") is True
        and peer.get("post_done_drain_completed") is True
        and type(drain_elapsed) is int
        and drain_elapsed >= 500_000_000,
        {
            "done_marker_observed": peer.get("done_marker_observed"),
            "post_done_drain_completed": peer.get("post_done_drain_completed"),
            "post_done_drain_elapsed_ns": drain_elapsed,
            "required_post_done_drain_ns": 500_000_000,
        },
    )
    scheduler = sender.get("scheduler", {})
    gate(
        "sender_scheduler_profile",
        scheduler.get("affinity") == [configuration.get("helper_cpu")]
        and scheduler.get("policy_name") == "SCHED_RR"
        and scheduler.get("priority") == 1,
        scheduler,
    )
    gate(
        "rps_xps_observe_only",
        sender.get("queue_masks_start") == sender.get("queue_masks_end")
        and peer.get("queue_masks_start") == peer.get("queue_masks_end")
        and configuration.get("rps_profile") == RPS_PROFILE,
        {
            "sender_start": sender.get("queue_masks_start"),
            "sender_end": sender.get("queue_masks_end"),
            "peer_start": peer.get("queue_masks_start"),
            "peer_end": peer.get("queue_masks_end"),
        },
    )
    gate(
        "qdisc_restored",
        sender.get("qdisc_restoration_exact") is True,
        sender.get("qdisc_restoration_exact"),
    )
    socket_restoration = sender.get("series", {}).get("socket_restoration", {})
    gate(
        "socket_options_restored",
        socket_restoration
        == {
            "priority_before_reset": 6,
            "ip_tos_before_reset": 2,
            "priority_after_reset": 0,
            "ip_tos_after_reset": 0,
        },
        socket_restoration,
    )

    raw_sender_events = sender.get("series", {}).get("events", [])
    sender_by_sequence: dict[int, dict[str, Any]] = {}
    sender_inventory_valid = (
        isinstance(raw_sender_events, list) and len(raw_sender_events) == samples
    )
    if sender_inventory_valid:
        for expected_sequence, event in enumerate(raw_sender_events):
            if (
                not isinstance(event, dict)
                or event.get("sequence") != expected_sequence
                or not isinstance(event.get("payload_sha256"), str)
                or _SHA256.fullmatch(event["payload_sha256"]) is None
                or event.get("payload_bytes") != PAYLOAD_BYTES
                or event.get("release_tai_ns")
                != sender.get("series", {}).get("start_tai_ns", -1)
                + expected_sequence * INTERVAL_NS
                or event.get("deadline_tai_ns")
                != event.get("release_tai_ns", -1) + STRICT_WINDOW_NS
                or event.get("scm_txtime_tai_ns")
                != event.get("release_tai_ns", -1) + ETF_DELTA_NS
                or event.get("outcome") not in {
                    "enqueued",
                    "suppressed-late",
                    "send-error",
                }
            ):
                sender_inventory_valid = False
                break
            sender_by_sequence[expected_sequence] = event
    gate(
        "sender_event_inventory",
        sender_inventory_valid,
        {
            "expected": samples,
            "observed": (
                len(raw_sender_events) if isinstance(raw_sender_events, list) else None
            ),
        },
    )

    peer_events = peer.get("events", [])
    peer_by_sequence: dict[int, list[dict[str, Any]]] = {}
    peer_inventory_shape = isinstance(peer_events, list)
    if peer_inventory_shape:
        for event in peer_events:
            if not isinstance(event, dict) or type(event.get("sequence")) is not int:
                peer_inventory_shape = False
                continue
            peer_by_sequence.setdefault(event["sequence"], []).append(event)

    timestamps, invalid_timestamps = _timestamp_messages(sender)
    enqueued = [
        event
        for event in sender_by_sequence.values()
        if event.get("outcome") == "enqueued"
    ]
    send_ids = [event.get("send_id") for event in enqueued]
    timestamp_complete = (
        not invalid_timestamps
        and send_ids == list(range(len(enqueued)))
        and set(timestamps)
        == {(send_id, kind) for send_id in range(len(enqueued)) for kind in (0, 1)}
    )
    gate(
        "kernel_tx_timestamp_inventory",
        timestamp_complete,
        {
            "enqueued": len(enqueued),
            "timestamp_messages": len(timestamps),
            "invalid_or_duplicate": len(invalid_timestamps),
        },
    )
    no_catch_up = sender_inventory_valid
    if no_catch_up:
        for event in sender_by_sequence.values():
            release = event["release_tai_ns"]
            outcome = event["outcome"]
            if outcome == "enqueued":
                active_wait_start = release - ACTIVE_WAIT_START_LEAD_NS
                active_wait_target = release - ENQUEUE_LEAD_NS
                valid = (
                    type(event.get("send_id")) is int
                    and event.get("sent_bytes") == PAYLOAD_BYTES
                    and event.get("send_error") is None
                    and type(event.get("enqueue_before_tai_ns")) is int
                    and type(event.get("enqueue_after_tai_ns")) is int
                    and event["enqueue_before_tai_ns"]
                    <= event["enqueue_after_tai_ns"]
                    < release
                    and type(event.get("active_wait_entered_tai_ns")) is int
                    and active_wait_start
                    <= event["active_wait_entered_tai_ns"]
                    < active_wait_target
                    and type(event.get("active_wait_iterations")) is int
                    and event["active_wait_iterations"] > 0
                )
            elif outcome == "suppressed-late":
                valid = (
                    event.get("send_id") is None
                    and event.get("sent_bytes") is None
                    and event.get("enqueue_wake_tai_ns", release - 1) >= release
                    and type(event.get("active_wait_entered_tai_ns")) is int
                    and type(event.get("active_wait_iterations")) is int
                    and event["active_wait_iterations"] >= 0
                )
            else:
                valid = (
                    event.get("send_id") is None
                    and event.get("sent_bytes") is None
                    and isinstance(event.get("send_error"), dict)
                    and event.get("enqueue_wake_tai_ns", release) < release
                    and type(event.get("active_wait_entered_tai_ns")) is int
                    and type(event.get("active_wait_iterations")) is int
                    and event["active_wait_iterations"] > 0
                )
            if not valid:
                no_catch_up = False
                break
    gate(
        "pre_release_enqueue_without_catch_up",
        no_catch_up,
        {
            "semantics": (
                "each event is enqueued before its own release or terminally "
                "suppressed/failed; no later catch-up send is allowed"
            )
        },
    )

    peer_exact = peer_inventory_shape
    expected_peer_sequences = {event["sequence"] for event in enqueued}
    if set(peer_by_sequence) != expected_peer_sequences:
        peer_exact = False
    for event in enqueued:
        matches = peer_by_sequence.get(event["sequence"], [])
        if (
            len(matches) != 1
            or matches[0].get("payload_sha256") != event.get("payload_sha256")
            or matches[0].get("payload_bytes") != PAYLOAD_BYTES
            or not isinstance(matches[0].get("kernel_software_timestamp"), dict)
        ):
            peer_exact = False
    if any(sequence not in sender_by_sequence for sequence in peer_by_sequence):
        peer_exact = False
    gate(
        "peer_packet_matching",
        peer_exact,
        {
            "enqueued": len(enqueued),
            "peer_events": len(peer_events) if isinstance(peer_events, list) else None,
            "unique_peer_sequences": len(peer_by_sequence),
        },
    )

    before_etf = _qdisc(sender, "qdisc_installed", "etf")
    after_etf = _qdisc(sender, "qdisc_after_series", "etf")
    before_packets = _counter(before_etf, "packets")
    after_packets = _counter(after_etf, "packets")
    before_drops = _counter(before_etf, "drops")
    after_drops = _counter(after_etf, "drops")
    required_qdisc_ok = (
        None not in {before_packets, after_packets, before_drops, after_drops}
        and after_packets - before_packets == len(enqueued)
        and after_drops - before_drops == 0
    )
    optional_qdisc: dict[str, dict[str, Any]] = {}
    for name, expected_delta, require_terminal_zero in (
        ("bytes", len(enqueued) * ETF_QDISC_BYTES_PER_PACKET, False),
        ("overlimits", 0, False),
        ("requeues", 0, False),
        ("backlog", 0, True),
        ("qlen", 0, True),
    ):
        before_present = isinstance(before_etf, dict) and name in before_etf
        after_present = isinstance(after_etf, dict) and name in after_etf
        before_value = _counter(before_etf, name) if before_present else None
        after_value = _counter(after_etf, name) if after_present else None
        supported = before_present and after_present
        if not before_present and not after_present:
            passed = True
        else:
            passed = bool(
                supported
                and before_value is not None
                and after_value is not None
                and after_value - before_value == expected_delta
                and (
                    not require_terminal_zero
                    or (before_value == 0 and after_value == 0)
                )
            )
        optional_qdisc[name] = {
            "supported": supported,
            "passed": passed,
            "before": before_value,
            "after": after_value,
            "expected_delta": expected_delta,
            "requires_zero_before_and_after": require_terminal_zero,
        }
    qdisc_ok = required_qdisc_ok and all(
        value["passed"] for value in optional_qdisc.values()
    )
    gate(
        "etf_qdisc_accounting",
        qdisc_ok,
        {
            "before_packets": before_packets,
            "after_packets": after_packets,
            "before_drops": before_drops,
            "after_drops": after_drops,
            "expected_packets": len(enqueued),
            "expected_bytes_per_packet_when_available": ETF_QDISC_BYTES_PER_PACKET,
            "optional_counters": optional_qdisc,
        },
    )

    rows: list[dict[str, Any]] = []
    post_veth_delays: list[int] = []
    peer_lateness: list[int] = []
    classification_counts: dict[str, int] = {}
    for sequence in range(samples):
        event = sender_by_sequence.get(sequence)
        row: dict[str, Any] = {"sequence": sequence}
        if event is None:
            classification = "sender-inventory-missing"
        elif event.get("outcome") != "enqueued":
            classification = (
                "sender-admission-missed"
                if event.get("outcome") == "suppressed-late"
                else "sender-send-error"
            )
            row.update(
                {
                    "release_tai_ns": event.get("release_tai_ns"),
                    "deadline_tai_ns": event.get("deadline_tai_ns"),
                    "sender_outcome": event.get("outcome"),
                }
            )
        else:
            release = event["release_tai_ns"]
            deadline = event["deadline_tai_ns"]
            send_id = event["send_id"]
            sched = timestamps.get((send_id, 1), {}).get("timestamp")
            software = timestamps.get((send_id, 0), {}).get("timestamp")
            peers = peer_by_sequence.get(sequence, [])
            peer_timestamp = (
                peers[0].get("kernel_software_timestamp") if len(peers) == 1 else None
            )
            sender_state = _window_state(software, release, deadline)
            peer_state = _window_state(peer_timestamp, release, deadline)
            sender_strict = sender_state == "within"
            peer_strict = peer_state == "within"
            if sched is None or software is None:
                classification = "tx-evidence-missing"
            elif len(peers) != 1:
                classification = "peer-observation-missing-or-duplicate"
            elif sender_state != "within":
                classification = f"sender-{sender_state}"
            elif peer_state == "proven-late":
                classification = "post-veth-tail"
            elif peer_state != "within":
                classification = f"peer-{peer_state}"
            else:
                classification = "matched"
            sender_to_peer_lower = None
            sender_to_peer_upper = None
            if isinstance(software, dict) and isinstance(peer_timestamp, dict):
                sender_to_peer_lower = (
                    peer_timestamp["tai_lower_ns"] - software["tai_upper_ns"]
                )
                sender_to_peer_upper = (
                    peer_timestamp["tai_upper_ns"] - software["tai_lower_ns"]
                )
                post_veth_delays.append(sender_to_peer_upper)
                peer_lateness.append(peer_timestamp["tai_upper_ns"] - release)
            row.update(
                {
                    "release_tai_ns": release,
                    "deadline_tai_ns": deadline,
                    "payload_sha256": event.get("payload_sha256"),
                    "send_id": send_id,
                    "tx_sched": sched,
                    "tx_software": software,
                    "peer_kernel": peer_timestamp,
                    "sender_window_state": sender_state,
                    "peer_window_state": peer_state,
                    "sender_strict_5ms": sender_strict,
                    "peer_strict_5ms": peer_strict,
                    "sender_to_peer_lower_ns": sender_to_peer_lower,
                    "sender_to_peer_upper_ns": sender_to_peer_upper,
                }
            )
        row["classification"] = classification
        classification_counts[classification] = classification_counts.get(classification, 0) + 1
        rows.append(row)

    integrity_passed = all(item["passed"] for item in gates.values())
    strict_passed = (
        integrity_passed
        and classification_counts == {"matched": samples}
    )
    worst = sorted(
        (
            row
            for row in rows
            if type(row.get("sender_to_peer_upper_ns")) is int
        ),
        key=lambda row: row["sender_to_peer_upper_ns"],
        reverse=True,
    )[:10]
    return {
        "integrity_passed": integrity_passed,
        "failed_integrity_gates": [
            name for name, value in gates.items() if not value["passed"]
        ],
        "integrity_gates": gates,
        "diagnosis": {
            "strict_5ms_passed": strict_passed,
            "classification_counts": classification_counts,
            "post_veth_tail_observed": classification_counts.get("post-veth-tail", 0) > 0,
            "clock_interval_straddle_observed": any(
                "straddle" in name or name.endswith("spans-complete-window")
                for name in classification_counts
            ),
            "post_veth_delay": _summary(post_veth_delays),
            "peer_release_lateness": _summary(peer_lateness),
            "threshold_counts": {
                "sender_to_peer_over_1ms": sum(value > 1_000_000 for value in post_veth_delays),
                "sender_to_peer_at_least_5ms": sum(
                    value >= STRICT_WINDOW_NS for value in post_veth_delays
                ),
            },
            "worst_events": worst,
        },
        "events": rows,
    }


_STATE_KEYS = frozenset(
    {
        "network_name",
        "peer_name",
        "sender_name",
        "network_id",
        "peer_id",
        "peer_cpu",
        "main_cpu",
        "helper_cpu",
        "sender_exit_code",
        "peer_exit_code",
        "launcher_exit_code",
        "signal_status",
        "stage",
        "peer_presence_before",
        "peer_remove_status",
        "peer_presence_after",
        "peer_handoff_retired",
        "network_presence_before",
        "network_remove_status",
        "network_presence_after",
        "network_handoff_retired",
        "cleanup_passed",
    }
)


def _load_state(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("ETF/veth lifecycle state is not a regular file")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values or "\x00" in value:
            raise ValueError("ETF/veth lifecycle state is malformed")
        values[key] = value
    if set(values) != _STATE_KEYS:
        raise ValueError("ETF/veth lifecycle state fields are invalid")
    return values


def _state_int(value: str) -> int | None:
    if value == "unavailable":
        return None
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise ValueError("ETF/veth lifecycle integer is invalid")
    return int(value)


def _terminal_cleanup(state: dict[str, str], prefix: str, created: bool) -> bool:
    if created:
        return (
            state[f"{prefix}_presence_before"] == "present"
            and state[f"{prefix}_remove_status"] == "0"
            and state[f"{prefix}_presence_after"] == "absent"
            and state[f"{prefix}_handoff_retired"] == "1"
        )
    return (
        state[f"{prefix}_presence_before"] == "not-created"
        and state[f"{prefix}_remove_status"] == "not-attempted"
        and state[f"{prefix}_presence_after"] == "not-created"
        and state[f"{prefix}_handoff_retired"] == "0"
    )


def _resource_identity(resources: Any) -> bool:
    if not isinstance(resources, dict):
        return False
    network_name = resources.get("network")
    peer_name = resources.get("peer_container")
    sender_name = resources.get("sender_container")
    network_id = resources.get("network_id")
    peer_id = resources.get("peer_container_id")
    return bool(
        isinstance(network_name, str)
        and re.fullmatch(r"qcsd-etf-veth-probe-[0-9a-f]{32}", network_name)
        and peer_name == f"{network_name}-peer"
        and sender_name == f"{network_name}-sender"
        and isinstance(network_id, str)
        and re.fullmatch(r"[0-9a-f]{64}", network_id)
        and isinstance(peer_id, str)
        and re.fullmatch(r"[0-9a-f]{64}", peer_id)
    )


def _apply_runtime_gates(
    evaluation: dict[str, Any],
    *,
    sender: dict[str, Any],
    peer: dict[str, Any],
    docker: Any,
    resources: Any,
    cpu_assignment: Any,
    container_exit_codes: Any,
    lifecycle: Any,
) -> dict[str, Any]:
    info = docker.get("info", {}) if isinstance(docker, dict) else {}
    image = docker.get("image", {}) if isinstance(docker, dict) else {}
    cpu_count = info.get("NCPU")
    expected_cpus = None
    if type(cpu_count) is int and cpu_count >= 3:
        expected_cpus = {
            "peer": cpu_count - 3,
            "main": cpu_count - 2,
            "helper": cpu_count - 1,
        }
    observed_cpus = cpu_assignment if isinstance(cpu_assignment, dict) else None
    sender_configuration = sender.get("configuration", {})
    sender_scheduler = sender.get("scheduler", {})
    peer_scheduler = peer.get("scheduler", {})
    cpu_binding = bool(
        observed_cpus == expected_cpus
        and isinstance(observed_cpus, dict)
        and sender_configuration.get("main_cpu") == observed_cpus.get("main")
        and sender_configuration.get("helper_cpu") == observed_cpus.get("helper")
        and sender.get("available_affinity")
        == sorted([observed_cpus.get("main"), observed_cpus.get("helper")])
        and sender_scheduler.get("affinity") == [observed_cpus.get("helper")]
        and peer.get("available_affinity") == [observed_cpus.get("peer")]
        and peer_scheduler.get("affinity") == [observed_cpus.get("peer")]
    )
    runtime_gates = {
        "resource_identity": _resource_identity(resources),
        "docker_provenance": bool(
            isinstance(docker, dict)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", str(image.get("id")))
        ),
        "launcher_complete": bool(
            isinstance(lifecycle, dict)
            and lifecycle.get("launcher_exit_code") == 0
            and lifecycle.get("signal_status") == 0
            and lifecycle.get("terminal_stage") == "complete"
        ),
        "worker_exit_codes": container_exit_codes == {"sender": 0, "peer": 0},
        "baseline_cpu_assignment_and_observation": cpu_binding,
        "durable_cleanup": bool(
            isinstance(lifecycle, dict)
            and lifecycle.get("cleanup_passed") is True
        ),
        "objects_created": bool(
            isinstance(resources, dict)
            and resources.get("network_id") is not None
            and resources.get("peer_container_id") is not None
        ),
    }
    gates = evaluation.get("integrity_gates")
    if not isinstance(gates, dict):
        raise ValueError("ETF/veth evaluation has no integrity-gate mapping")
    detail = {
        "terminal_stage": (
            lifecycle.get("terminal_stage") if isinstance(lifecycle, dict) else None
        ),
        "observed_cpus": observed_cpus,
        "expected_cpus": expected_cpus,
        "sender_configured_cpus": {
            "main": sender_configuration.get("main_cpu"),
            "helper": sender_configuration.get("helper_cpu"),
        },
        "sender_available_affinity": sender.get("available_affinity"),
        "sender_scheduler_affinity": sender_scheduler.get("affinity"),
        "peer_available_affinity": peer.get("available_affinity"),
        "peer_scheduler_affinity": peer_scheduler.get("affinity"),
        "cleanup_passed": (
            lifecycle.get("cleanup_passed") if isinstance(lifecycle, dict) else None
        ),
    }
    for name, passed in runtime_gates.items():
        gates[name] = {"passed": passed, "detail": detail}
    failed = [name for name, value in gates.items() if value.get("passed") is not True]
    evaluation["failed_integrity_gates"] = failed
    evaluation["integrity_passed"] = not failed
    if not evaluation["integrity_passed"]:
        evaluation["diagnosis"]["strict_5ms_passed"] = False
    return evaluation


def _replay_evaluation(
    sender: dict[str, Any],
    peer: dict[str, Any],
    *,
    samples: int,
    series_id: str,
) -> dict[str, Any]:
    """Evaluate worker output deterministically, including malformed-output failure."""

    try:
        return evaluate_series(
            sender,
            peer,
            samples=samples,
            series_id=series_id,
        )
    except Exception as error:
        detail = {"type": type(error).__name__, "message": str(error)}
        return {
            "integrity_passed": False,
            "failed_integrity_gates": ["worker_outputs"],
            "integrity_gates": {
                "worker_outputs": {"passed": False, "detail": detail}
            },
            "diagnosis": {
                "strict_5ms_passed": False,
                "classification_counts": {},
                "post_veth_tail_observed": False,
                "clock_interval_straddle_observed": False,
            },
            "events": [],
        }


def _publish_bundle(destination: Path, files: dict[str, bytes]) -> None:
    destination.mkdir(mode=0o700)
    try:
        for name, value in files.items():
            path = destination / name
            durable_create(path, value)
            path.chmod(0o444)
        fsync_directory(destination)
        destination.chmod(0o555)
        fsync_directory(destination.parent)
    except BaseException:
        # Preserve a partial create-only diagnostic instead of silently reusing
        # its identity on a later invocation.
        raise


def _receipt_payload_sha256(receipt: dict[str, Any]) -> str:
    payload = dict(receipt)
    payload.pop("payload_sha256", None)
    schema_version = payload.get("schema_version")
    if type(schema_version) is not int or schema_version not in {
        PREVIOUS_SCHEMA_VERSION,
        SCHEMA_VERSION,
    }:
        raise ValueError("ETF/veth receipt schema is invalid")
    return _sha256_bytes(
        f"qcsd-etf-veth-series-probe-v{schema_version}\0".encode()
        + _canonical_json(payload)
    )


def _validate_schema_one_contract(
    receipt: dict[str, Any], sender: dict[str, Any], peer: dict[str, Any]
) -> None:
    configuration = receipt.get("configuration")
    if not isinstance(configuration, dict):
        raise ValueError("ETF/veth schema-1 configuration is invalid")
    samples = configuration.get("samples")
    series_id = configuration.get("series_id")
    expected_configuration = {
        "profile": HISTORICAL_PROFILE,
        "samples": samples,
        "series_id": series_id,
        "payload_bytes": PAYLOAD_BYTES,
        "interval_ns": INTERVAL_NS,
        "strict_window_ns": STRICT_WINDOW_NS,
        "etf_delta_ns": ETF_DELTA_NS,
        "enqueue_lead_ns": ENQUEUE_LEAD_NS,
        "observer_boundary": "peer-ingress-after-sender-veth",
        "cpu_profile": CPU_PROFILE,
        "rps_profile": RPS_PROFILE,
        "rps_xps_mutated": False,
    }
    sender_configuration = sender.get("configuration", {})
    peer_configuration = peer.get("configuration", {})
    sender_events = sender.get("series", {}).get("events", [])
    if (
        receipt.get("purpose") != HISTORICAL_PURPOSE
        or configuration != expected_configuration
        or type(samples) is not int
        or not MIN_SAMPLES <= samples <= MAX_SAMPLES
        or not isinstance(series_id, str)
        or _SERIES_ID.fullmatch(series_id) is None
        or sender.get("schema_version") != PREVIOUS_SCHEMA_VERSION
        or peer.get("schema_version") != PREVIOUS_SCHEMA_VERSION
        or sender.get("role") != "etf-series-sender"
        or peer.get("role") != "post-veth-peer"
        or sender.get("status") != "sender-complete"
        or peer.get("status") != "peer-complete"
        or sender.get("series_id") != series_id
        or peer.get("series_id") != series_id
        or sender.get("expected_samples") != samples
        or peer.get("expected_samples") != samples
        or not isinstance(sender_configuration, dict)
        or sender_configuration.get("profile") != HISTORICAL_PROFILE
        or sender_configuration.get("clockid") != "CLOCK_TAI"
        or sender_configuration.get("delta_ns") != ETF_DELTA_NS
        or sender_configuration.get("strict_window_ns") != STRICT_WINDOW_NS
        or sender_configuration.get("interval_ns") != INTERVAL_NS
        or sender_configuration.get("payload_bytes") != PAYLOAD_BYTES
        or sender_configuration.get("enqueue_lead_ns") != ENQUEUE_LEAD_NS
        or sender_configuration.get("cpu_profile") != CPU_PROFILE
        or sender_configuration.get("rps_profile") != RPS_PROFILE
        or "active_wait_start_lead_ns" in sender_configuration
        or "active_wait_window_ns" in sender_configuration
        or "scope" in sender_configuration
        or not isinstance(peer_configuration, dict)
        or peer_configuration.get("payload_bytes") != PAYLOAD_BYTES
        or peer_configuration.get("port") != PORT
        or peer_configuration.get("rps_profile") != RPS_PROFILE
        or not isinstance(sender_events, list)
        or len(sender_events) != samples
    ):
        raise ValueError("ETF/veth schema-1 historical contract is invalid")


def finalize_supervised_bundle(
    request_path: Path, bundle_root: Path
) -> tuple[Path, str, bool]:
    request = load_supervised_request(request_path)
    destination = Path(request["destination"])
    bundle_root = bundle_root.absolute()
    if not bundle_root.is_dir() or bundle_root.is_symlink():
        raise ValueError("ETF/veth supervised bundle root is unsafe")
    state = _load_state(bundle_root / "lifecycle.state")
    output = bundle_root / "output"
    errors: list[dict[str, str]] = []
    sender: dict[str, Any] = {}
    peer: dict[str, Any] = {}
    try:
        sender_value = _load_json_value(output / "sender.json", label="ETF/veth sender")
        peer_value = _load_json_value(output / "peer.json", label="ETF/veth peer")
        if not isinstance(sender_value, dict) or not isinstance(peer_value, dict):
            raise ValueError("ETF/veth worker output roots must be objects")
        sender = sender_value
        peer = peer_value
    except BaseException as error:
        errors.append({"type": type(error).__name__, "message": str(error)})
    evaluation = _replay_evaluation(
        sender,
        peer,
        samples=request["samples"],
        series_id=request["series_id"],
    )

    docker: dict[str, Any] | None = None
    try:
        docker = _docker_provenance(
            image=request["image"],
            version_path=bundle_root / "docker-version.json",
            info_path=bundle_root / "docker-info.json",
            image_path=bundle_root / "docker-image.json",
        )
    except BaseException as error:
        errors.append({"type": type(error).__name__, "message": str(error)})

    network_created = state["network_id"] != "unavailable"
    peer_created = state["peer_id"] != "unavailable"
    cleanup_passed = (
        state["cleanup_passed"] == "1"
        and _terminal_cleanup(state, "peer", peer_created)
        and _terminal_cleanup(state, "network", network_created)
    )
    observed_cpus = {
        "peer": _state_int(state["peer_cpu"]),
        "main": _state_int(state["main_cpu"]),
        "helper": _state_int(state["helper_cpu"]),
    }
    resources = {
        "network": state["network_name"],
        "network_id": None if not network_created else state["network_id"],
        "peer_container": state["peer_name"],
        "peer_container_id": None if not peer_created else state["peer_id"],
        "sender_container": state["sender_name"],
    }
    container_exit_codes = {
        "sender": _state_int(state["sender_exit_code"]),
        "peer": _state_int(state["peer_exit_code"]),
    }
    lifecycle = {
        "launcher_exit_code": _state_int(state["launcher_exit_code"]),
        "signal_status": _state_int(state["signal_status"]),
        "terminal_stage": state["stage"],
        "cleanup_passed": cleanup_passed,
    }
    evaluation = _apply_runtime_gates(
        evaluation,
        sender=sender,
        peer=peer,
        docker=docker,
        resources=resources,
        cpu_assignment=observed_cpus,
        container_exit_codes=container_exit_codes,
        lifecycle=lifecycle,
    )

    sender_bytes = _canonical_json(sender)
    peer_bytes = _canonical_json(peer)
    manifest = {
        "sender.json": _sha256_bytes(sender_bytes),
        "peer.json": _sha256_bytes(peer_bytes),
    }
    receipt: dict[str, Any] = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "evidentiary": False,
        "authorizes_capture": False,
        "purpose": PURPOSE,
        "status": "complete" if evaluation["integrity_passed"] else "incomplete",
        "started_at": request["started_at"],
        "finished_at": _utc_now(),
        "configuration": {
            "profile": PROFILE,
            "samples": request["samples"],
            "series_id": request["series_id"],
            "payload_bytes": PAYLOAD_BYTES,
            "interval_ns": INTERVAL_NS,
            "strict_window_ns": STRICT_WINDOW_NS,
            "etf_delta_ns": ETF_DELTA_NS,
            "enqueue_lead_ns": ENQUEUE_LEAD_NS,
            "active_wait_start_lead_ns": ACTIVE_WAIT_START_LEAD_NS,
            "active_wait_window_ns": ACTIVE_WAIT_START_LEAD_NS - ENQUEUE_LEAD_NS,
            "observer_boundary": "peer-ingress-after-sender-veth",
            "cpu_profile": CPU_PROFILE,
            "rps_profile": RPS_PROFILE,
            "rps_xps_mutated": False,
            "scope": "kernel-timing-geometry-and-post-veth-isolation-only",
            "exercises_rust_quic": False,
            "production_priority_transaction": False,
            "main_helper_split_exercised": False,
            "authorizes_http3_gate": False,
        },
        "source": request["source"],
        "docker": docker,
        "resources": resources,
        "cpu_assignment": observed_cpus,
        "container_exit_codes": container_exit_codes,
        "lifecycle": lifecycle,
        "evaluation": evaluation,
        "manifest": manifest,
    }
    if errors:
        receipt["execution_errors"] = errors
    receipt["payload_sha256"] = _receipt_payload_sha256(receipt)
    receipt_bytes = _canonical_json(receipt)
    _publish_bundle(
        destination,
        {
            "sender.json": sender_bytes,
            "peer.json": peer_bytes,
            "receipt.json": receipt_bytes,
        },
    )
    validate_bundle(destination)
    return destination, _sha256_bytes(receipt_bytes), evaluation["integrity_passed"]


def validate_bundle(path: Path) -> dict[str, Any]:
    path = Path(path)
    if not path.is_dir() or path.is_symlink() or path.stat().st_mode & 0o222:
        raise ValueError("ETF/veth bundle is not an immutable regular directory")
    expected = {"receipt.json", "sender.json", "peer.json"}
    if {entry.name for entry in path.iterdir()} != expected:
        raise ValueError("ETF/veth bundle inventory is invalid")
    for name in expected:
        item = path / name
        if not item.is_file() or item.is_symlink() or item.stat().st_mode & 0o222:
            raise ValueError(f"ETF/veth bundle member is unsafe: {name}")
    receipt = _load_json_value(path / "receipt.json", label="ETF/veth receipt")
    if not isinstance(receipt, dict):
        raise ValueError("ETF/veth receipt root is invalid")
    if (
        receipt.get("artifact_type") != ARTIFACT_TYPE
        or type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version")
        not in {PREVIOUS_SCHEMA_VERSION, SCHEMA_VERSION}
        or receipt.get("evidentiary") is not False
        or receipt.get("authorizes_capture") is not False
        or receipt.get("status") not in {"complete", "incomplete"}
        or receipt.get("payload_sha256") != _receipt_payload_sha256(receipt)
    ):
        raise ValueError("ETF/veth receipt identity or binding is invalid")
    manifest = receipt.get("manifest")
    if not isinstance(manifest, dict) or manifest != {
        name: sha256_file(path / name) for name in ("sender.json", "peer.json")
    }:
        raise ValueError("ETF/veth bundle manifest is invalid")
    integrity = receipt.get("evaluation", {}).get("integrity_passed") is True
    if (receipt["status"] == "complete") is not integrity:
        raise ValueError("ETF/veth receipt status differs from execution integrity")
    sender = _load_json_value(path / "sender.json", label="ETF/veth sender")
    peer = _load_json_value(path / "peer.json", label="ETF/veth peer")
    if not isinstance(sender, dict) or not isinstance(peer, dict):
        raise ValueError("ETF/veth worker outputs are invalid")
    if receipt["schema_version"] == PREVIOUS_SCHEMA_VERSION:
        _validate_schema_one_contract(receipt, sender, peer)
    if receipt["schema_version"] == SCHEMA_VERSION:
        if receipt.get("purpose") != PURPOSE:
            raise ValueError("ETF/veth schema-2 purpose limitation is invalid")
        configuration = receipt.get("configuration")
        if not isinstance(configuration, dict):
            raise ValueError("ETF/veth schema-2 configuration is invalid")
        samples = configuration.get("samples")
        series_id = configuration.get("series_id")
        expected_configuration = {
            "profile": PROFILE,
            "samples": samples,
            "series_id": series_id,
            "payload_bytes": PAYLOAD_BYTES,
            "interval_ns": INTERVAL_NS,
            "strict_window_ns": STRICT_WINDOW_NS,
            "etf_delta_ns": ETF_DELTA_NS,
            "enqueue_lead_ns": ENQUEUE_LEAD_NS,
            "active_wait_start_lead_ns": ACTIVE_WAIT_START_LEAD_NS,
            "active_wait_window_ns": ACTIVE_WAIT_START_LEAD_NS - ENQUEUE_LEAD_NS,
            "observer_boundary": "peer-ingress-after-sender-veth",
            "cpu_profile": CPU_PROFILE,
            "rps_profile": RPS_PROFILE,
            "rps_xps_mutated": False,
            "scope": "kernel-timing-geometry-and-post-veth-isolation-only",
            "exercises_rust_quic": False,
            "production_priority_transaction": False,
            "main_helper_split_exercised": False,
            "authorizes_http3_gate": False,
        }
        if (
            configuration != expected_configuration
            or type(samples) is not int
            or not MIN_SAMPLES <= samples <= MAX_SAMPLES
            or not isinstance(series_id, str)
            or _SERIES_ID.fullmatch(series_id) is None
        ):
            raise ValueError("ETF/veth schema-2 configuration contract is invalid")
        replayed = _replay_evaluation(
            sender,
            peer,
            samples=samples,
            series_id=series_id,
        )
        replayed = _apply_runtime_gates(
            replayed,
            sender=sender,
            peer=peer,
            docker=receipt.get("docker"),
            resources=receipt.get("resources"),
            cpu_assignment=receipt.get("cpu_assignment"),
            container_exit_codes=receipt.get("container_exit_codes"),
            lifecycle=receipt.get("lifecycle"),
        )
        if receipt.get("evaluation") != replayed:
            raise ValueError("ETF/veth schema-2 embedded evaluation differs from replay")
    return receipt


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="qcsd-lab etf-veth-probe",
        description=(
            "Run a repeated, non-evidentiary ETF/veth kernel timing-geometry preflight"
        ),
    )
    root.add_argument("--destination", required=True, type=Path)
    root.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    root.add_argument("--profile", default=PROFILE, choices=[PROFILE])
    root.add_argument(
        "--image",
        default=os.environ.get("QCSD_LAB_COLLECTION_IMAGE", DEFAULT_IMAGE),
        help="collection image to probe (default: %(default)s)",
    )
    return root


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        _validate_destination(args.destination)
        _validate_image_reference(args.image)
        if not MIN_SAMPLES <= args.samples <= MAX_SAMPLES:
            raise ValueError(
                f"ETF/veth probe samples must be between {MIN_SAMPLES} and {MAX_SAMPLES}"
            )
    except (FileExistsError, OSError, ValueError) as error:
        raise SystemExit(str(error)) from None
    raise SystemExit(
        "ETF/veth Docker execution is available only through ./qcsd-lab etf-veth-probe"
    )


if __name__ == "__main__":
    main()
