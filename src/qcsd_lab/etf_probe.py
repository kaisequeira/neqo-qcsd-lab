"""Validation and receipt support for the non-evidentiary ETF probe.

Docker ownership deliberately lives in the guarded :file:`qcsd-lab` shell
launcher.  This module cannot create, run, or remove Docker objects; it only
validates a request, consumes the launcher's completed execution bundle, and
writes the create-only diagnostic receipt.
"""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import ipaddress
import json
import os
import platform
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from .util import LAB_ROOT, durable_create, fsync_directory, sha256_file


ARTIFACT_TYPE = "qcsd-etf-capability-probe"
SCHEMA_VERSION = 3
PREVIOUS_SCHEMA_VERSION = 2
HISTORICAL_SCHEMA_VERSION = 1
SUPERVISED_REQUEST_TYPE = "qcsd-etf-supervised-request"
CONTAINER_TOOL = LAB_ROOT / "tools/etf_probe_container.py"
DOCKER_SUPERVISOR = LAB_ROOT / "tools/docker_signal_supervisor.sh"
DEFAULT_IMAGE = "neqo-qcsd-lab-collection:local"
PORT = 45678
RECEIVER_TIMEOUT_SECONDS = 12.0
RELEASE_LEAD_NS = 500_000_000
ETF_DELTA_NS = 10_000_000
PREVIOUS_ETF_DELTA_NS = 4_500_000
HISTORICAL_ETF_DELTA_NS = 4_000_000
STRICT_REALIZATION_WINDOW_NS = 5_000_000
IPV4_UDP_HEADER_BYTES = 20 + 8
UNTAGGED_ETHERNET_HEADER_BYTES = 14
ETHERNET_ARP_FRAME_BYTES = 14 + 28
NEGATIVE_NAMES = frozenset(
    {"missing_socket", "missing_cmsg", "wrong_clock", "past_txtime"}
)
EXPECTED_PAYLOADS = {
    "fifo": "qcsd-etf-probe:fifo-v1",
    "fifo_concurrent": "qcsd-etf-probe:fifo-concurrent-v1",
    "scm_priority_preflight": "qcsd-etf-probe:scm-priority-preflight-v1",
    "positive": "qcsd-etf-probe:positive-v1",
    **{name: f"qcsd-etf-probe:{name.replace('_', '-')}-v1" for name in NEGATIVE_NAMES},
}
_RECEIPT_REQUIRED_KEYS = frozenset(
    {
        "artifact_type",
        "schema_version",
        "evidentiary",
        "authorizes_capture",
        "purpose",
        "status",
        "started_at",
        "configuration",
        "resources",
        "source",
        "cpu_assignment",
        "container_exit_codes",
        "lifecycle_supervision",
        "validation",
        "cleanup",
        "cleanup_passed",
        "finished_at",
        "payload_sha256",
    }
)
_RECEIPT_OPTIONAL_KEYS = frozenset(
    {"docker", "sender", "receiver", "execution_errors"}
)


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _payload_sha256(value: dict[str, Any]) -> str:
    payload = dict(value)
    payload.pop("payload_sha256", None)
    schema_version = payload.get("schema_version")
    if type(schema_version) is not int or schema_version not in {
        HISTORICAL_SCHEMA_VERSION,
        PREVIOUS_SCHEMA_VERSION,
        SCHEMA_VERSION,
    }:
        raise ValueError("ETF probe payload schema is invalid")
    return _sha256_bytes(
        f"qcsd-etf-capability-probe-v{schema_version}\0".encode()
        + _canonical_json(payload)
    )


def _validate_receipt_structure(value: dict[str, Any]) -> None:
    """Bind immutable outer schemas to their probe and timing contracts."""

    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version not in {
        HISTORICAL_SCHEMA_VERSION,
        PREVIOUS_SCHEMA_VERSION,
        SCHEMA_VERSION,
    }:
        raise ValueError("ETF probe receipt schema is invalid")
    if not _RECEIPT_REQUIRED_KEYS.issubset(value) or not set(value).issubset(
        _RECEIPT_REQUIRED_KEYS | _RECEIPT_OPTIONAL_KEYS
    ):
        raise ValueError("ETF probe receipt fields are invalid")

    configuration = value.get("configuration")
    validation = value.get("validation")
    cleanup = value.get("cleanup")
    if not all(isinstance(item, dict) for item in (configuration, validation, cleanup)):
        raise ValueError("ETF probe receipt structure is invalid")
    expected_delta_ns = {
        HISTORICAL_SCHEMA_VERSION: HISTORICAL_ETF_DELTA_NS,
        PREVIOUS_SCHEMA_VERSION: PREVIOUS_ETF_DELTA_NS,
        SCHEMA_VERSION: ETF_DELTA_NS,
    }[schema_version]
    if (
        configuration.get("clockid") != "CLOCK_TAI"
        or configuration.get("etf_delta_ns") != expected_delta_ns
        or configuration.get("strict_realization_window_ns")
        != STRICT_REALIZATION_WINDOW_NS
    ):
        raise ValueError("ETF probe receipt timing contract is invalid")
    if schema_version == HISTORICAL_SCHEMA_VERSION:
        if any(
            name in configuration
            for name in (
                "post_etf_observer_guard_ns",
                "scm_txtime_offset_ns",
                "etf_dequeue_target_offset_ns",
                "etf_expiry_horizon_ns",
            )
        ):
            raise ValueError("historical ETF probe receipt contains a future timing field")
    elif schema_version == PREVIOUS_SCHEMA_VERSION:
        if (
            configuration.get("post_etf_observer_guard_ns")
            != STRICT_REALIZATION_WINDOW_NS - PREVIOUS_ETF_DELTA_NS
            or any(
                name in configuration
                for name in (
                    "scm_txtime_offset_ns",
                    "etf_dequeue_target_offset_ns",
                    "etf_expiry_horizon_ns",
                )
            )
        ):
            raise ValueError("ETF probe receipt observer guard is invalid")
    elif (
        "post_etf_observer_guard_ns" in configuration
        or configuration.get("scm_txtime_offset_ns") != ETF_DELTA_NS
        or configuration.get("etf_dequeue_target_offset_ns") != 0
        or configuration.get("etf_expiry_horizon_ns") != ETF_DELTA_NS
    ):
        raise ValueError("ETF probe receipt schema-3 timing semantics are invalid")

    passed = value.get("status") == "passed"
    failed_gates = validation.get("failed_gates")
    if (
        value.get("status") not in {"passed", "failed"}
        or validation.get("passed") is not passed
        or not isinstance(failed_gates, list)
        or any(not isinstance(item, str) or not item for item in failed_gates)
        or (passed and failed_gates)
        or (not passed and not failed_gates)
    ):
        raise ValueError("ETF probe receipt status binding is invalid")

    sender = value.get("sender")
    receiver = value.get("receiver")
    if passed:
        if not isinstance(sender, dict) or not isinstance(receiver, dict):
            raise ValueError("passed ETF probe receipt lacks probe outputs")
        if (
            type(sender.get("schema_version")) is not int
            or type(receiver.get("schema_version")) is not int
            or sender.get("schema_version") != schema_version
            or receiver.get("schema_version") != schema_version
        ):
            raise ValueError("ETF probe receipt schemas are not paired")
        if (
            value.get("cleanup_passed") is not True
            or cleanup.get("passed") is not True
            or value.get("container_exit_codes")
            != {"sender": 0, "receiver": 0}
        ):
            raise ValueError("passed ETF probe receipt runtime outcome is invalid")

        if schema_version == SCHEMA_VERSION:
            replayed = validate_probe(sender, receiver)
            gates = validation.get("gates")
            if replayed.get("passed") is not True or not isinstance(gates, dict):
                raise ValueError("ETF probe receipt outputs do not replay as passed")
            if any(gates.get(name) != gate for name, gate in replayed["gates"].items()):
                raise ValueError("ETF probe receipt validation replay differs")


def validate_probe_receipt(path: Path) -> dict[str, Any]:
    """Reopen the create-only diagnostic receipt and verify its content binding."""

    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"ETF probe receipt is not a regular file: {path}")
    if path.stat().st_mode & 0o222:
        raise ValueError("ETF probe receipt is writable")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("ETF probe receipt is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("ETF probe receipt root is not an object")
    if value.get("artifact_type") != ARTIFACT_TYPE:
        raise ValueError("ETF probe receipt identity is invalid")
    if value.get("evidentiary") is not False or value.get("authorizes_capture") is not False:
        raise ValueError("ETF probe receipt makes a forbidden evidence claim")
    _validate_receipt_structure(value)
    if value.get("payload_sha256") != _payload_sha256(value):
        raise ValueError("ETF probe receipt payload hash is invalid")
    return value


def _git_command(repository: Path, *arguments: str) -> str:
    """Run one read-only Git provenance command.

    The executable is deliberately fixed here so this module cannot be turned
    into a second Docker lifecycle owner by supplying a different command.
    """

    argv = [
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-C",
        str(repository),
        *arguments,
    ]
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    process = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=30.0,
        env=environment,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(
            f"host command failed ({process.returncode}): {' '.join(argv)}: {detail}"
        )
    return process.stdout


def _validate_destination(destination: Path) -> Path:
    destination = destination.absolute()
    parent = destination.parent
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"ETF probe receipt already exists: {destination}")
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError(f"ETF probe destination parent is unsafe: {parent}")
    mode = parent.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise ValueError(f"ETF probe destination parent is not a directory: {parent}")
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
                CONTAINER_TOOL,
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


def _load_json_value(path: Path, *, label: str) -> Any:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"{label} is not a regular file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} is invalid JSON") from error


def _docker_provenance(
    *,
    image: str,
    version_path: Path,
    info_path: Path,
    image_path: Path,
) -> dict[str, Any]:
    """Validate Docker facts already captured through the pinned shell API."""

    version = _load_json_value(version_path, label="Docker version observation")
    info = _load_json_value(info_path, label="Docker info observation")
    image_value = _load_json_value(image_path, label="Docker image observation")
    if not isinstance(version, dict) or not isinstance(info, dict):
        raise RuntimeError("Docker version/info observations are not objects")
    if not isinstance(image_value, dict):
        raise RuntimeError("Docker image observation is not an object")
    image_id = image_value.get("Id")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(image_id)) is None:
        raise RuntimeError("Docker image observation has no immutable image ID")
    cpu_count = info.get("NCPU")
    if not isinstance(cpu_count, int) or isinstance(cpu_count, bool) or cpu_count < 3:
        raise RuntimeError("ETF probe requires at least three Docker CPUs")
    return {
        "version": version,
        "info": {
            "ID": info.get("ID"),
            "Architecture": info.get("Architecture"),
            "OSType": info.get("OSType"),
            "NCPU": info.get("NCPU"),
            "DockerRootDir": info.get("DockerRootDir"),
            "Driver": info.get("Driver"),
            "KernelVersion": info.get("KernelVersion"),
            "OperatingSystem": info.get("OperatingSystem"),
            "ServerVersion": info.get("ServerVersion"),
        },
        "image": {
            "reference": image,
            "id": image_id,
            "repo_digests": image_value.get("RepoDigests") or [],
            "architecture": image_value.get("Architecture"),
            "os": image_value.get("Os"),
        },
    }


def _validate_image_reference(image: str) -> str:
    if (
        not image
        or len(image) > 512
        or image.startswith("-")
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in image)
    ):
        raise ValueError("ETF probe image reference is unsafe")
    return image


def prepare_supervised_request(path: Path, argv: list[str]) -> dict[str, Any]:
    """Validate a public request before the guarded shell mutates Docker."""

    args = parser().parse_args(argv)
    destination = _validate_destination(args.destination)
    image = _validate_image_reference(args.image)
    if (
        not CONTAINER_TOOL.is_file()
        or CONTAINER_TOOL.is_symlink()
        or not DOCKER_SUPERVISOR.is_file()
        or DOCKER_SUPERVISOR.is_symlink()
    ):
        raise ValueError("ETF probe source files are unavailable")
    request = {
        "artifact_type": SUPERVISED_REQUEST_TYPE,
        "schema_version": 1,
        "destination": str(destination),
        "image": image,
        "started_at": _utc_now(),
        "source": _host_provenance(),
    }
    encoded = _canonical_json(request)
    durable_create(path, encoded)
    path.chmod(0o400)
    fsync_directory(path.parent)
    return request


def load_supervised_request(path: Path) -> dict[str, Any]:
    value = _load_json_value(path, label="ETF supervised request")
    if not isinstance(value, dict):
        raise ValueError("ETF supervised request root is not an object")
    if (
        value.get("artifact_type") != SUPERVISED_REQUEST_TYPE
        or value.get("schema_version") != 1
        or not isinstance(value.get("source"), dict)
        or not isinstance(value.get("started_at"), str)
    ):
        raise ValueError("ETF supervised request identity is invalid")
    destination = _validate_destination(Path(str(value.get("destination", ""))))
    image = _validate_image_reference(str(value.get("image", "")))
    return {**value, "destination": str(destination), "image": image}


def supervised_docker_binding(
    request_path: Path,
    version_path: Path,
    info_path: Path,
    image_path: Path,
) -> tuple[str, int]:
    """Return the validated immutable image ID and Docker CPU count."""

    request = load_supervised_request(request_path)
    docker = _docker_provenance(
        image=request["image"],
        version_path=version_path,
        info_path=info_path,
        image_path=image_path,
    )
    return docker["image"]["id"], docker["info"]["NCPU"]


def _event_index(receiver: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for event in receiver.get("events", []):
        index.setdefault(str(event.get("payload_ascii")), []).append(event)
    return index


def _qdisc_entry(
    sender: dict[str, Any], snapshot: str, *, kind: str, parent: str
) -> dict[str, Any]:
    entries = sender[snapshot]["qdiscs"]
    matches = [
        entry
        for entry in entries
        if entry.get("kind") == kind and entry.get("parent") == parent
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{snapshot} does not contain exactly one {kind} qdisc at {parent}"
        )
    return matches[0]


def _etf_entry(sender: dict[str, Any], snapshot: str) -> dict[str, Any]:
    return _qdisc_entry(sender, snapshot, kind="etf", parent="1:1")


def _fifo_entry(sender: dict[str, Any], snapshot: str) -> dict[str, Any]:
    return _qdisc_entry(sender, snapshot, kind="pfifo", parent="1:2")


def _root_entry(sender: dict[str, Any], snapshot: str) -> dict[str, Any]:
    entries = sender[snapshot]["qdiscs"]
    matches = [
        entry
        for entry in entries
        if entry.get("kind") == "prio"
        and entry.get("handle") == "1:"
        and entry.get("root") is True
    ]
    if len(matches) != 1:
        raise ValueError(f"{snapshot} does not contain exactly one root prio qdisc")
    return matches[0]


def _qdisc_counters(entry: dict[str, Any]) -> dict[str, int]:
    counters: dict[str, int] = {}
    for name in ("packets", "bytes", "drops"):
        value = entry.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"qdisc {name} is not a non-negative integer")
        counters[name] = value
    return counters


def _counter_delta(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    return {name: after[name] - before[name] for name in ("packets", "bytes", "drops")}


def _canonical_ipv4(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return None
    canonical = str(parsed)
    return canonical if value == canonical else None


def validate_probe(sender: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
    """Return explicit fail-closed gates for one sender/receiver probe pair."""

    gates: dict[str, dict[str, Any]] = {}

    def gate(name: str, passed: bool, detail: Any) -> None:
        gates[name] = {"passed": bool(passed), "detail": detail}

    gate(
        "sender_completed_and_restored",
        sender.get("schema_version") == SCHEMA_VERSION
        and receiver.get("schema_version") == SCHEMA_VERSION
        and sender.get("status") == "sender-complete"
        and sender.get("qdisc_restoration_exact") is True,
        {
            "sender_schema_version": sender.get("schema_version"),
            "receiver_schema_version": receiver.get("schema_version"),
            "status": sender.get("status"),
            "qdisc_restoration_exact": sender.get("qdisc_restoration_exact"),
            "error": sender.get("error"),
        },
    )
    configuration = sender.get("configuration", {})
    gate(
        "fixed_qdisc_contract",
        configuration.get("clockid") == "CLOCK_TAI"
        and configuration.get("delta_ns") == ETF_DELTA_NS
        and configuration.get("realization_window_ns")
        == STRICT_REALIZATION_WINDOW_NS
        and ETF_DELTA_NS == 10_000_000
        and configuration.get("timed_priority") == 6
        and configuration.get("timed_priority_mechanism")
        == "serialized-socket-global-SO_PRIORITY"
        and configuration.get("ipv4_ds_field") == 0x02
        and configuration.get("ipv4_ecn") == "ECT(0)"
        and configuration.get("ipv4_ds_field_mechanism")
        == "socket-global-IP_TOS-before-SO_PRIORITY"
        and configuration.get("per_message_ip_tos") is False,
        configuration,
    )
    index = _event_index(receiver)
    expected_event_names = {"fifo", "fifo_concurrent", "positive"}
    event_counts = {
        name: len(index.get(payload, [])) for name, payload in EXPECTED_PAYLOADS.items()
    }
    unknown = sorted(set(index) - set(EXPECTED_PAYLOADS.values()))
    preflight = sender.get("scm_priority_preflight", {})
    preflight_supported = preflight.get("supported") is True
    preflight_expected_count = 1 if preflight_supported else 0
    gate(
        "receiver_inventory",
        all(event_counts[name] == 1 for name in expected_event_names)
        and event_counts["scm_priority_preflight"] == preflight_expected_count
        and all(event_counts[name] == 0 for name in NEGATIVE_NAMES)
        and not unknown
        and receiver.get("timeout_seconds") == RECEIVER_TIMEOUT_SECONDS,
        {
            "counts": event_counts,
            "unknown_payloads": unknown,
            "receiver_timeout_seconds": receiver.get("timeout_seconds"),
        },
    )
    positive = sender.get("positive", {})
    ready = positive.get("ready", {})
    final = positive.get("final", {})
    transaction = final.get("serialized_priority_transaction", {})
    release = ready.get("release_tai_ns")
    deadline = ready.get("deadline_tai_ns")
    resolution = sender.get("receiver_resolution", {})
    resolved_ipv4 = _canonical_ipv4(resolution.get("resolved_ipv4"))
    receiver_port = configuration.get("receiver_port")
    expected_destination = {"ipv4": resolved_ipv4, "port": receiver_port}
    destinations = {
        "scm_priority_preflight": preflight.get("destination"),
        "fifo_control": sender.get("fifo_control", {}).get("destination"),
        "positive_ready": ready.get("destination"),
        "positive_timed": transaction.get("destination"),
        "fifo_concurrent": final.get("concurrent_priority_zero", {}).get(
            "destination"
        ),
        **{
            f"negative_{item.get('name')}": item.get("destination")
            for item in sender.get("negative_controls", [])
            if isinstance(item, dict)
        },
    }
    resolution_started = resolution.get("started_tai_ns")
    resolution_finished = resolution.get("finished_tai_ns")
    initial_snapshot_started = (
        sender.get("qdisc_initial", {}).get("command", {}).get("started_tai_ns")
    )
    preflight_started = preflight.get("before_tai_ns")
    resolution_timing_valid = all(
        isinstance(value, int)
        for value in (
            resolution_started,
            resolution_finished,
            initial_snapshot_started,
            preflight_started,
        )
    )
    gate(
        "numeric_receiver_resolved_before_traffic",
        resolved_ipv4 is not None
        and configuration.get("receiver_name") == resolution.get("requested_name")
        and isinstance(receiver_port, int)
        and not isinstance(receiver_port, bool)
        and receiver_port == PORT
        and resolution.get("port") == receiver_port
        and resolution.get("mechanism")
        == "AF_INET/SOCK_DGRAM-getaddrinfo-before-qdisc"
        and resolution.get("candidate_ipv4") == [resolved_ipv4]
        and resolution_timing_valid
        and resolution_started <= resolution_finished
        <= initial_snapshot_started
        <= preflight_started
        and set(destinations)
        == {
            "scm_priority_preflight",
            "fifo_control",
            "positive_ready",
            "positive_timed",
            "fifo_concurrent",
            *(f"negative_{name}" for name in NEGATIVE_NAMES),
        }
        and all(value == expected_destination for value in destinations.values()),
        {
            "resolution": resolution,
            "qdisc_initial_started_tai_ns": initial_snapshot_started,
            "preflight_started_tai_ns": preflight_started,
            "expected_destination": expected_destination,
            "send_destinations": destinations,
        },
    )
    preflight_fact_valid = (
        (
            preflight_supported
            and preflight.get("sent_bytes")
            == len(EXPECTED_PAYLOADS["scm_priority_preflight"].encode())
            and preflight.get("send_error") is None
            and event_counts.get("scm_priority_preflight") == 1
        )
        or (
            not preflight_supported
            and preflight.get("sent_bytes") is None
            and preflight.get("send_error", {}).get("errno") == 22
            and event_counts.get("scm_priority_preflight") == 0
        )
    )
    gate(
        "scm_priority_capability_receipted",
        preflight_fact_valid,
        {
            "preflight": preflight,
            "preflight_receiver_count": event_counts.get("scm_priority_preflight"),
        },
    )
    gate(
        "serialized_socket_priority_transaction",
        transaction.get("mechanism") == "socket-global-SO_PRIORITY"
        and transaction.get("single_owner") == "helper child while parent is SIGSTOPped"
        and transaction.get("original_priority") == 0
        and transaction.get("priority_during_send") == 6
        and transaction.get("sent_bytes") == len(EXPECTED_PAYLOADS["positive"].encode())
        and transaction.get("priority_after_reset") == 0
        and transaction.get("reset_before_tai_ns", 1)
        <= transaction.get("reset_after_tai_ns", 0)
        and transaction.get("reset_after_tai_ns", 1)
        <= transaction.get("transaction_after_tai_ns", 0)
        and positive.get("main_sigstop_before_tai_ns", 1)
        < transaction.get("transaction_before_tai_ns", 0)
        and transaction.get("transaction_after_tai_ns", 1)
        < positive.get("main_resumed_tai_ns", 0)
        and "error" not in final
        and event_counts.get("positive") == 1,
        {"transaction": transaction, "helper_error": final.get("error")},
    )
    gate(
        "txtime_deadline_mode_forbidden",
        configuration.get("so_txtime_flags") == 2
        and configuration.get("deadline_mode") is False
        and ready.get("so_txtime_flags") == 2
        and ready.get("deadline_mode") is False,
        {
            "configuration_flags": configuration.get("so_txtime_flags"),
            "configuration_deadline_mode": configuration.get("deadline_mode"),
            "ready_flags": ready.get("so_txtime_flags"),
            "ready_deadline_mode": ready.get("deadline_mode"),
        },
    )
    numeric_window = isinstance(release, int) and isinstance(deadline, int)
    positive_event = (
        index.get(EXPECTED_PAYLOADS["positive"], [None])[0]
        if event_counts.get("positive") == 1
        else None
    )
    positive_kernel = (
        positive_event.get("kernel_software_timestamp") if positive_event is not None else None
    )
    positive_ds_field = positive_event.get("ipv4_ds_field") if positive_event else None
    gate(
        "ipv4_ect0_socket_and_observer",
        transaction.get("ipv4_ds_field") == 0x02
        and transaction.get("ipv4_ecn") == "ECT(0)"
        and transaction.get("ip_tos_readback_before_priority") == 0x02
        and transaction.get("socket_option_order") == ["IP_TOS=0x02", "SO_PRIORITY=6"]
        and transaction.get("per_message_ancillary") == ["SCM_TXTIME"]
        and transaction.get("original_ip_tos") == 0
        and transaction.get("original_priority") == 0
        and transaction.get("ip_tos_set_after_tai_ns", 1)
        <= transaction.get("priority_set_before_tai_ns", 0)
        and transaction.get("socket_restore_order")
        == ["IP_TOS=0x00", "SO_PRIORITY=0"]
        and transaction.get("ip_tos_after_reset") == 0
        and transaction.get("priority_after_reset") == 0
        and transaction.get("reset_before_tai_ns", 1)
        <= transaction.get("ip_tos_restore_before_tai_ns", 0)
        <= transaction.get("ip_tos_restore_after_tai_ns", 0)
        <= transaction.get("priority_restore_before_tai_ns", 0)
        <= transaction.get("priority_restore_after_tai_ns", 0)
        <= transaction.get("reset_after_tai_ns", 0)
        <= transaction.get("transaction_after_tai_ns", 0)
        and positive_ds_field == 0x02,
        {
            "transaction": {
                "ipv4_ds_field": transaction.get("ipv4_ds_field"),
                "ipv4_ecn": transaction.get("ipv4_ecn"),
                "ip_tos_readback_before_priority": transaction.get(
                    "ip_tos_readback_before_priority"
                ),
                "socket_option_order": transaction.get("socket_option_order"),
                "per_message_ancillary": transaction.get("per_message_ancillary"),
                "ip_tos_set_after_tai_ns": transaction.get(
                    "ip_tos_set_after_tai_ns"
                ),
                "priority_set_before_tai_ns": transaction.get(
                    "priority_set_before_tai_ns"
                ),
                "original_ip_tos": transaction.get("original_ip_tos"),
                "original_priority": transaction.get("original_priority"),
                "socket_restore_order": transaction.get("socket_restore_order"),
                "ip_tos_after_reset": transaction.get("ip_tos_after_reset"),
                "priority_after_reset": transaction.get("priority_after_reset"),
                "ip_tos_restore_before_tai_ns": transaction.get(
                    "ip_tos_restore_before_tai_ns"
                ),
                "ip_tos_restore_after_tai_ns": transaction.get(
                    "ip_tos_restore_after_tai_ns"
                ),
                "priority_restore_before_tai_ns": transaction.get(
                    "priority_restore_before_tai_ns"
                ),
                "priority_restore_after_tai_ns": transaction.get(
                    "priority_restore_after_tai_ns"
                ),
            },
            "receiver_ipv4_ds_field": positive_ds_field,
        },
    )
    in_window = (
        numeric_window
        and positive_kernel is not None
        and positive_kernel.get("tai_lower_ns", release - 1) >= release
        and positive_kernel.get("tai_upper_ns", deadline) < deadline
        and positive_event.get("user_tai_ns", deadline) >= release
        and positive_event.get("user_tai_ns", deadline) < deadline
    )
    gate(
        "strict_half_open_post_veth_window",
        in_window,
        {
            "release_tai_ns": release,
            "deadline_tai_ns": deadline,
            "receiver_kernel_timestamp": positive_kernel,
            "receiver_user_tai_ns": (
                positive_event.get("user_tai_ns") if positive_event is not None else None
            ),
        },
    )
    gate(
        "main_stopped_across_full_window",
        numeric_window
        and positive.get("main_sigstop_before_tai_ns", release + 1) < release
        and positive.get("main_resumed_tai_ns", deadline - 1) >= deadline,
        {
            "stopped_before_tai_ns": positive.get("main_sigstop_before_tai_ns"),
            "resumed_tai_ns": positive.get("main_resumed_tai_ns"),
            "release_tai_ns": release,
            "deadline_tai_ns": deadline,
        },
    )
    gate(
        "dedicated_cpu_contract",
        positive.get("main_affinity") == [configuration.get("main_cpu")]
        and ready.get("affinity") == [configuration.get("helper_cpu")]
        and configuration.get("main_cpu") != configuration.get("helper_cpu"),
        {
            "main_affinity": positive.get("main_affinity"),
            "helper_affinity": ready.get("affinity"),
            "main_cpu": configuration.get("main_cpu"),
            "helper_cpu": configuration.get("helper_cpu"),
        },
    )
    gate(
        "pre_release_enqueue",
        numeric_window
        and ready.get("scm_txtime_tai_ns")
        == release + configuration.get("delta_ns", -1)
        and transaction.get("enqueue_before_tai_ns", release) < release
        and transaction.get("enqueue_after_tai_ns", release) < release,
        {
            "enqueue_before_tai_ns": transaction.get("enqueue_before_tai_ns"),
            "enqueue_after_tai_ns": transaction.get("enqueue_after_tai_ns"),
            "scm_txtime_tai_ns": ready.get("scm_txtime_tai_ns"),
            "physical_target_tai_ns": release,
            "etf_delta_ns": configuration.get("delta_ns"),
            "release_tai_ns": release,
        },
    )
    concurrent_event = (
        index.get(EXPECTED_PAYLOADS["fifo_concurrent"], [None])[0]
        if event_counts.get("fifo_concurrent") == 1
        else None
    )
    concurrent_kernel = (
        concurrent_event.get("kernel_software_timestamp")
        if concurrent_event is not None
        else None
    )
    concurrent_send = final.get("concurrent_priority_zero", {})
    concurrent_ds_field = (
        concurrent_event.get("ipv4_ds_field") if concurrent_event is not None else None
    )
    gate(
        "priority_zero_bypasses_pending_etf",
        numeric_window
        and concurrent_send.get("socket_priority_configuration")
        == "same-socket-read-back-zero-after-reset"
        and concurrent_send.get("priority_readback") == 0
        and concurrent_send.get("socket_ip_tos_before_send") == 0
        and concurrent_send.get("per_message_ancillary") == ["IP_TOS=0x02"]
        and concurrent_send.get("ipv4_ds_field") == 0x02
        and concurrent_send.get("ipv4_ecn") == "ECT(0)"
        and concurrent_send.get("sent_bytes")
        == len(EXPECTED_PAYLOADS["fifo_concurrent"].encode())
        and concurrent_send.get("before_tai_ns", release) < release
        and concurrent_kernel is not None
        and concurrent_kernel.get("tai_upper_ns", release) < release
        and concurrent_send.get("socket_ip_tos_after_send") == 0
        and concurrent_send.get("priority_after_send") == 0
        and concurrent_ds_field == 0x02,
        {
            "send": concurrent_send,
            "receiver_kernel_timestamp": concurrent_kernel,
            "receiver_ipv4_ds_field": concurrent_ds_field,
            "timed_release_tai_ns": release,
        },
    )
    controls = {item.get("name"): item for item in sender.get("negative_controls", [])}
    missing_socket = controls.get("missing_socket", {})
    gate(
        "negative_controls_rejected",
        set(controls) == NEGATIVE_NAMES
        and all(event_counts.get(name) == 0 for name in NEGATIVE_NAMES)
        and missing_socket.get("send_error", {}).get("errno") == 22,
        {
            "controls": controls,
            "receiver_counts": {name: event_counts.get(name) for name in NEGATIVE_NAMES},
        },
    )
    past_txtime = controls.get("past_txtime", {})
    past_target = past_txtime.get("target_ns")
    past_started = past_txtime.get("started_tai_ns")
    past_messages = past_txtime.get("error_queue", [])

    def single_extended_error(message: dict[str, Any]) -> dict[str, Any]:
        errors = message.get("extended_errors", [])
        return errors[0] if len(errors) == 1 and isinstance(errors[0], dict) else {}

    past_sched_messages = [
        message
        for message in past_messages
        if isinstance(message, dict)
        and single_extended_error(message).get("origin") == 4
    ]
    past_txtime_messages = [
        message
        for message in past_messages
        if isinstance(message, dict)
        and single_extended_error(message).get("origin") == 6
    ]
    past_sched_message = (
        past_sched_messages[0] if len(past_sched_messages) == 1 else {}
    )
    past_txtime_message = (
        past_txtime_messages[0] if len(past_txtime_messages) == 1 else {}
    )
    past_sched_error = single_extended_error(past_sched_message)
    past_error = single_extended_error(past_txtime_message)
    past_sched_timestamp = past_sched_message.get("tx_software_timestamp", {})
    past_context = past_txtime_message.get("txtime_context_timestamp", {})
    past_sched_timestamp_valid = (
        isinstance(past_sched_timestamp, dict)
        and all(
            isinstance(past_sched_timestamp.get(name), int)
            and not isinstance(past_sched_timestamp.get(name), bool)
            for name in ("seconds", "nanoseconds", "raw_ns", "realtime_ns")
        )
        and 0 <= past_sched_timestamp.get("nanoseconds", -1) < 1_000_000_000
        and past_sched_timestamp.get("raw_ns")
        == past_sched_timestamp.get("seconds", 0) * 1_000_000_000
        + past_sched_timestamp.get("nanoseconds", -1)
        and past_sched_timestamp.get("realtime_ns")
        == past_sched_timestamp.get("raw_ns")
    )
    encoded_past_target = (
        (past_error.get("data") << 32) | past_error.get("info")
        if isinstance(past_error.get("data"), int)
        and isinstance(past_error.get("info"), int)
        else None
    )
    gate(
        "txtime_error_queue_context",
        isinstance(past_target, int)
        and not isinstance(past_target, bool)
        and isinstance(past_started, int)
        and not isinstance(past_started, bool)
        and past_target < past_started
        and past_txtime.get("clockid") == 11
        and past_txtime.get("include_cmsg") is True
        and past_txtime.get("timestamping") is True
        and past_txtime.get("sent_bytes") is None
        and past_txtime.get("send_error", {}).get("errno") == errno.ENOBUFS
        and past_txtime.get("send_error", {}).get("name") == "ENOBUFS"
        and len(past_messages) == 2
        and len(past_sched_messages) == 1
        and len(past_txtime_messages) == 1
        and past_sched_timestamp_valid
        and past_sched_message.get("txtime_context_timestamp") is None
        and past_sched_error.get("errno") == errno.ENOMSG
        and past_sched_error.get("origin") == 4
        and past_sched_error.get("type") == 0
        and past_sched_error.get("code") == 0
        and past_sched_error.get("info") == 1
        and past_sched_error.get("data") == 0
        and past_txtime_message.get("tx_software_timestamp") is None
        and past_context.get("requested_txtime_tai_ns") == past_target
        and past_context.get("raw_ns") == past_target
        and past_context.get("seconds") == past_target // 1_000_000_000
        and past_context.get("nanoseconds") == past_target % 1_000_000_000
        and past_error.get("errno") == errno.EINVAL
        and past_error.get("origin") == 6
        and past_error.get("type") == 0
        and past_error.get("code") == 1
        and encoded_past_target == past_target,
        {
            "control": past_txtime,
            "scheduler_receipts": past_sched_messages,
            "txtime_receipts": past_txtime_messages,
            "scheduler_timestamp_valid": past_sched_timestamp_valid,
            "encoded_requested_txtime_tai_ns": encoded_past_target,
            "semantics": (
                "SCM_TSTAMP_SCHED precedes ETF validation and is not transmit "
                "proof; SCM_TIMESTAMPING ts0 on a TXTIME-origin error is "
                "requested-TAI correlation context, never transmit evidence"
            ),
        },
    )
    timestamp_messages = [
        item for item in final.get("error_queue", []) if item.get("tx_software_timestamp")
    ]
    positive_timestamp_messages = [
        item
        for item in timestamp_messages
        if any(
            error.get("origin") == 4 and error.get("data") == 0
            for error in item.get("extended_errors", [])
        )
    ]
    positive_timestamp_types = [
        error.get("info")
        for item in positive_timestamp_messages
        for error in item.get("extended_errors", [])
        if error.get("origin") == 4 and error.get("data") == 0
    ]
    fifo_timestamp_types = [
        error.get("info")
        for item in timestamp_messages
        for error in item.get("extended_errors", [])
        if error.get("origin") == 4 and error.get("data") == 1
    ]
    txtime_errors = [
        error
        for item in final.get("error_queue", [])
        for error in item.get("extended_errors", [])
        if error.get("origin") == 6
    ]
    gate(
        "positive_tx_feedback",
        len(positive_timestamp_messages) == 2
        and sorted(positive_timestamp_types) == [0, 1]
        and sorted(fifo_timestamp_types) == [0, 1]
        and not txtime_errors,
        {
            "all_software_timestamp_messages": timestamp_messages,
            "positive_datagram_id": 0,
            "positive_timestamp_types": positive_timestamp_types,
            "fifo_datagram_id": 1,
            "fifo_timestamp_types": fifo_timestamp_types,
            "txtime_errors": txtime_errors,
        },
    )
    derived_l2_overhead_bytes: int | None = None
    try:
        etf_before = _qdisc_counters(
            _etf_entry(sender, "qdisc_after_negative_controls")
        )
        etf_after = _qdisc_counters(_etf_entry(sender, "qdisc_after_positive"))
        etf_positive_delta = _counter_delta(etf_after, etf_before)
        positive_ipv4_udp_bytes = (
            len(EXPECTED_PAYLOADS["positive"].encode()) + IPV4_UDP_HEADER_BYTES
        )
        derived_l2_overhead_bytes = (
            etf_positive_delta["bytes"] - positive_ipv4_udp_bytes
        )
        expected_positive_frame_bytes = (
            positive_ipv4_udp_bytes + UNTAGGED_ETHERNET_HEADER_BYTES
        )
        etf_accounting_passed = (
            etf_before["drops"] >= 3
            and etf_positive_delta["drops"] == 0
            and etf_positive_delta["packets"] == 1
            and etf_positive_delta["bytes"] == expected_positive_frame_bytes
            and derived_l2_overhead_bytes == UNTAGGED_ETHERNET_HEADER_BYTES
        )
        etf_detail: Any = {
            "before_positive": etf_before,
            "after_positive": etf_after,
            "positive_delta": etf_positive_delta,
            "positive_ipv4_udp_bytes": positive_ipv4_udp_bytes,
            "derived_l2_overhead_bytes": derived_l2_overhead_bytes,
            "expected_l2_overhead_bytes": UNTAGGED_ETHERNET_HEADER_BYTES,
            "expected_positive_frame_bytes": expected_positive_frame_bytes,
        }
    except (KeyError, TypeError, ValueError) as error:
        etf_accounting_passed = False
        etf_detail = {"error": str(error)}
    gate("etf_accounting", etf_accounting_passed, etf_detail)

    try:
        fifo_installed = _qdisc_counters(_fifo_entry(sender, "qdisc_installed"))
        fifo_before = _qdisc_counters(
            _fifo_entry(sender, "qdisc_after_negative_controls")
        )
        fifo_after = _qdisc_counters(_fifo_entry(sender, "qdisc_after_positive"))
        fifo_baseline_delta = _counter_delta(fifo_before, fifo_installed)
        fifo_positive_delta = _counter_delta(fifo_after, fifo_before)
        if derived_l2_overhead_bytes is None:
            raise ValueError("ETF accounting did not yield an L2 overhead")

        def fifo_decomposition(
            delta: dict[str, int], *, payload_name: str
        ) -> dict[str, Any]:
            expected_udp_frame_bytes = (
                len(EXPECTED_PAYLOADS[payload_name].encode())
                + IPV4_UDP_HEADER_BYTES
                + derived_l2_overhead_bytes
            )
            extra_link_control_packets = delta["packets"] - 1
            residual_link_control_bytes = delta["bytes"] - expected_udp_frame_bytes
            expected_link_control_bytes = (
                extra_link_control_packets * ETHERNET_ARP_FRAME_BYTES
            )
            return {
                "passed": (
                    delta["packets"] >= 1
                    and delta["drops"] == 0
                    and extra_link_control_packets >= 0
                    and residual_link_control_bytes == expected_link_control_bytes
                ),
                "delta": delta,
                "payload_name": payload_name,
                "expected_udp_frame_bytes": expected_udp_frame_bytes,
                "extra_link_control_packets": extra_link_control_packets,
                "link_control_frame_bytes": ETHERNET_ARP_FRAME_BYTES,
                "residual_link_control_bytes": residual_link_control_bytes,
                "expected_link_control_bytes": expected_link_control_bytes,
            }

        baseline_decomposition = fifo_decomposition(
            fifo_baseline_delta, payload_name="fifo"
        )
        positive_decomposition = fifo_decomposition(
            fifo_positive_delta, payload_name="fifo_concurrent"
        )
        fifo_accounting_passed = (
            derived_l2_overhead_bytes == UNTAGGED_ETHERNET_HEADER_BYTES
            and baseline_decomposition["passed"]
            and positive_decomposition["passed"]
        )
        fifo_detail: Any = {
            "installed": fifo_installed,
            "before_positive": fifo_before,
            "after_positive": fifo_after,
            "derived_l2_overhead_bytes": derived_l2_overhead_bytes,
            "baseline": baseline_decomposition,
            "positive": positive_decomposition,
        }
    except (KeyError, TypeError, ValueError) as error:
        fifo_accounting_passed = False
        fifo_detail = {"error": str(error)}
    gate("fifo_accounting", fifo_accounting_passed, fifo_detail)

    try:
        hierarchy_detail: dict[str, Any] = {}
        hierarchy_passed = True
        for snapshot in (
            "qdisc_after_negative_controls",
            "qdisc_after_positive",
        ):
            root_counters = _qdisc_counters(_root_entry(sender, snapshot))
            fifo_counters = _qdisc_counters(_fifo_entry(sender, snapshot))
            etf_counters = _qdisc_counters(_etf_entry(sender, snapshot))
            child_totals = {
                name: fifo_counters[name] + etf_counters[name]
                for name in ("packets", "bytes", "drops")
            }
            differences = {
                name: root_counters[name] - child_totals[name]
                for name in ("packets", "bytes", "drops")
            }
            snapshot_passed = all(value == 0 for value in differences.values())
            hierarchy_passed = hierarchy_passed and snapshot_passed
            hierarchy_detail[snapshot] = {
                "passed": snapshot_passed,
                "root": root_counters,
                "fifo": fifo_counters,
                "etf": etf_counters,
                "child_totals": child_totals,
                "root_minus_children": differences,
            }
    except (KeyError, TypeError, ValueError) as error:
        hierarchy_passed = False
        hierarchy_detail = {"error": str(error)}
    gate("qdisc_hierarchy_conservation", hierarchy_passed, hierarchy_detail)
    failed = [name for name, value in gates.items() if not value["passed"]]
    return {"passed": not failed, "failed_gates": failed, "gates": gates}


def _wait_for_file(path: Path, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_file() and not path.is_symlink():
            return
        time.sleep(0.025)
    raise RuntimeError(f"timed out waiting for probe file: {path.name}")


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"{label} did not publish a regular JSON result")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} published invalid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} JSON root is not an object")
    return value


def _exit_code(value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError("ETF probe exit code is invalid")
    return value


def finalize_supervised_probe(
    request_path: Path,
    *,
    version_path: Path,
    info_path: Path,
    image_path: Path,
    sender_path: Path,
    receiver_path: Path,
    network_name: str,
    receiver_name: str,
    sender_name: str,
    network_id: str | None,
    receiver_id: str | None,
    receiver_cpu: int | None,
    main_cpu: int | None,
    helper_cpu: int | None,
    sender_exit_code: int | None,
    receiver_exit_code: int | None,
    launcher_exit_code: int | None,
    signal_status: int | None,
    stage: str,
    cleanup: dict[str, Any],
) -> tuple[Path, str, bool]:
    """Write one receipt from a completed shell-supervised execution.

    All Docker observations and object states are inputs produced by the
    guardian-held shell.  This function performs no Docker operation.
    """

    request = load_supervised_request(request_path)
    destination = Path(request["destination"])
    sender_status = _exit_code(sender_exit_code)
    receiver_status = _exit_code(receiver_exit_code)
    launcher_status = _exit_code(launcher_exit_code)
    latched_signal = _exit_code(signal_status)
    resources_unavailable = (
        network_name == receiver_name == sender_name == "unavailable"
        and network_id is None
        and receiver_id is None
    )
    if not resources_unavailable:
        if not re.fullmatch(r"qcsd-etf-probe-[0-9a-f]{32}", network_name):
            raise ValueError("ETF probe network name is invalid")
        if receiver_name != f"{network_name}-receiver":
            raise ValueError("ETF probe receiver name is invalid")
        if sender_name != f"{network_name}-sender":
            raise ValueError("ETF probe sender name is invalid")
    for label, identity in (("network", network_id), ("receiver", receiver_id)):
        if identity is not None and re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise ValueError(f"ETF probe {label} ID is invalid")
    cpu_values = (receiver_cpu, main_cpu, helper_cpu)
    if any(
        value is not None and (isinstance(value, bool) or not isinstance(value, int))
        for value in cpu_values
    ):
        raise ValueError("ETF probe CPU assignment is invalid")
    if not isinstance(stage, str) or not stage or len(stage) > 80:
        raise ValueError("ETF probe launcher stage is invalid")
    if not isinstance(cleanup, dict) or cleanup.get("passed") not in {True, False}:
        raise ValueError("ETF probe cleanup result is invalid")

    receipt: dict[str, Any] = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "evidentiary": False,
        "authorizes_capture": False,
        "purpose": (
            "Disposable host capability diagnostic only; this receipt cannot satisfy "
            "any QCSD reference, code, qualification, capture, or attestation gate."
        ),
        "status": "failed",
        "started_at": request["started_at"],
        "configuration": {
            "topology": "disposable-docker-bridge-veth",
            "qdisc": "root-prio/normal-pfifo/timed-etf",
            "clockid": "CLOCK_TAI",
            "etf_delta_ns": ETF_DELTA_NS,
            "strict_realization_window_ns": STRICT_REALIZATION_WINDOW_NS,
            "scm_txtime_offset_ns": ETF_DELTA_NS,
            "etf_dequeue_target_offset_ns": 0,
            "etf_expiry_horizon_ns": ETF_DELTA_NS,
            "timed_priority": 6,
            "timed_priority_mechanism": "serialized-socket-global-SO_PRIORITY",
            "scm_priority_probe": "receipted capability fact; never used as fallback",
            "so_txtime_flags": 2,
            "deadline_mode": False,
            "normal_priority": 0,
            "ipv4_ds_field": 0x02,
            "ipv4_ecn": "ECT(0)",
            "ipv4_ds_field_mechanism": "socket-global-IP_TOS-before-SO_PRIORITY",
            "per_message_ip_tos": False,
            "release_lead_ns": RELEASE_LEAD_NS,
            "receiver_timeout_seconds": RECEIVER_TIMEOUT_SECONDS,
            "negative_controls": sorted(NEGATIVE_NAMES),
            "main_stop_test": "SIGSTOP main across the complete realization window",
        },
        "resources": {
            "network": network_name,
            "network_id": network_id,
            "receiver_container": receiver_name,
            "receiver_container_id": receiver_id,
            "sender_container": sender_name,
        },
        "source": request["source"],
        "cpu_assignment": {
            "receiver": receiver_cpu,
            "main": main_cpu,
            "timed_helper": helper_cpu,
        },
        "container_exit_codes": {
            "sender": sender_status,
            "receiver": receiver_status,
        },
        "lifecycle_supervision": {
            "guardian_admission": "qcsd-lab-require_docker",
            "helper": "tools/docker_signal_supervisor.sh",
            "network_create": "qcsd_create_docker_network",
            "receiver_run": "qcsd_run_detached_docker",
            "sender_run": "qcsd_run_attached_docker",
            "detached_handoff_retirement": "qcsd_retire_docker_handoff",
            "launcher_exit_code": launcher_status,
            "latched_signal_status": latched_signal,
            "terminal_stage": stage,
            "cleanup": cleanup,
        },
    }
    errors: list[dict[str, str]] = []
    sender: dict[str, Any] | None = None
    try:
        receipt["docker"] = _docker_provenance(
            image=request["image"],
            version_path=version_path,
            info_path=info_path,
            image_path=image_path,
        )
        expected_cpu = receipt["docker"]["info"]["NCPU"]
        if (receiver_cpu, main_cpu, helper_cpu) != (
            expected_cpu - 3,
            expected_cpu - 2,
            expected_cpu - 1,
        ):
            raise RuntimeError("ETF probe CPU assignment differs from Docker capacity")
        sender = _load_json(sender_path, label="ETF sender")
        receiver = _load_json(receiver_path, label="post-veth receiver")
        receipt["sender"] = sender
        receipt["receiver"] = receiver
        validation = validate_probe(sender, receiver)
    except BaseException as error:
        errors.append({"type": type(error).__name__, "message": str(error)})
        validation = {
            "passed": False,
            "failed_gates": ["probe_outputs"],
            "gates": {
                "probe_outputs": {"passed": False, "detail": errors[-1]},
            },
        }

    def terminal_cleanup(
        value: Any, *, object_created: bool
    ) -> bool:
        if not isinstance(value, dict):
            return False
        if object_created:
            return (
                value.get("presence_before") == "present"
                and value.get("remove_status") == "0"
                and value.get("presence_after") == "absent"
                and value.get("handoff_retired") is True
            )
        return (
            value.get("presence_before") == "not-created"
            and value.get("remove_status") == "not-attempted"
            and value.get("presence_after") == "not-created"
            and value.get("handoff_retired") is False
        )

    cleanup_terminal = (
        cleanup.get("passed") is True
        and terminal_cleanup(cleanup.get("receiver"), object_created=receiver_id is not None)
        and terminal_cleanup(cleanup.get("network"), object_created=network_id is not None)
    )
    runtime_gates = {
        "launcher_execution_status": (
            launcher_status == 0 and latched_signal == 0 and stage == "complete"
        ),
        "sender_exit_code": sender_status == 0,
        "receiver_exit_code": receiver_status == 0,
        "receiver_resource_binding": (
            sender is not None
            and sender.get("configuration", {}).get("receiver_name") == receiver_name
            and sender.get("configuration", {}).get("receiver_port") == PORT
        ),
        "durable_lifecycle_cleanup": cleanup_terminal,
        "durable_lifecycle_objects_created": network_id is not None
        and receiver_id is not None,
    }
    for name, passed in runtime_gates.items():
        validation["gates"][name] = {
            "passed": passed,
            "detail": {
                "launcher_exit_code": launcher_status,
                "latched_signal_status": latched_signal,
                "sender_exit_code": sender_status,
                "receiver_exit_code": receiver_status,
                "receiver_container": receiver_name,
                "sender_receiver_name": (
                    sender.get("configuration", {}).get("receiver_name")
                    if sender is not None
                    else None
                ),
                "sender_receiver_port": (
                    sender.get("configuration", {}).get("receiver_port")
                    if sender is not None
                    else None
                ),
                "network_id": network_id,
                "receiver_id": receiver_id,
                "cleanup": cleanup,
            },
        }
        if not passed and name not in validation["failed_gates"]:
            validation["failed_gates"].append(name)
    validation["passed"] = not validation["failed_gates"]
    receipt["validation"] = validation
    if errors:
        receipt["execution_errors"] = errors
    receipt["cleanup"] = cleanup
    receipt["cleanup_passed"] = cleanup.get("passed") is True
    receipt["status"] = "passed" if validation["passed"] else "failed"
    receipt["finished_at"] = _utc_now()
    receipt["payload_sha256"] = _payload_sha256(receipt)
    encoded = _canonical_json(receipt)
    durable_create(destination, encoded)
    destination.chmod(0o444)
    fsync_directory(destination.parent)
    validate_probe_receipt(destination)
    return destination, _sha256_bytes(encoded), receipt["status"] == "passed"


_SUPERVISED_STATE_KEYS = frozenset(
    {
        "network_name",
        "receiver_name",
        "sender_name",
        "network_id",
        "receiver_id",
        "receiver_cpu",
        "main_cpu",
        "helper_cpu",
        "sender_exit_code",
        "receiver_exit_code",
        "launcher_exit_code",
        "signal_status",
        "stage",
        "receiver_presence_before",
        "receiver_remove_status",
        "receiver_presence_after",
        "receiver_handoff_retired",
        "network_presence_before",
        "network_remove_status",
        "network_presence_after",
        "network_handoff_retired",
        "cleanup_passed",
    }
)


def _load_supervised_state(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("ETF supervised lifecycle state is not a regular file")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values or "\x00" in value or "\n" in value:
            raise ValueError("ETF supervised lifecycle state is malformed")
        values[key] = value
    if set(values) != _SUPERVISED_STATE_KEYS:
        raise ValueError("ETF supervised lifecycle state fields are invalid")
    return values


def _optional_state_value(value: str) -> str | None:
    return None if value == "unavailable" else value


def _optional_state_int(value: str) -> int | None:
    if value == "unavailable":
        return None
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise ValueError("ETF supervised lifecycle integer is invalid")
    return int(value)


def _state_bool(value: str) -> bool:
    if value not in {"0", "1"}:
        raise ValueError("ETF supervised lifecycle boolean is invalid")
    return value == "1"


def finalize_supervised_bundle(
    request_path: Path, bundle_root: Path
) -> tuple[Path, str, bool]:
    """Consume the shell's fixed-layout, completed lifecycle bundle."""

    bundle_root = bundle_root.absolute()
    if not bundle_root.is_dir() or bundle_root.is_symlink():
        raise ValueError("ETF supervised bundle root is unsafe")
    state = _load_supervised_state(bundle_root / "lifecycle.state")
    cleanup = {
        "passed": _state_bool(state["cleanup_passed"]),
        "receiver": {
            "presence_before": state["receiver_presence_before"],
            "remove_status": state["receiver_remove_status"],
            "presence_after": state["receiver_presence_after"],
            "handoff_retired": _state_bool(state["receiver_handoff_retired"]),
        },
        "network": {
            "presence_before": state["network_presence_before"],
            "remove_status": state["network_remove_status"],
            "presence_after": state["network_presence_after"],
            "handoff_retired": _state_bool(state["network_handoff_retired"]),
        },
    }
    return finalize_supervised_probe(
        request_path,
        version_path=bundle_root / "docker-version.json",
        info_path=bundle_root / "docker-info.json",
        image_path=bundle_root / "docker-image.json",
        sender_path=bundle_root / "output" / "sender.json",
        receiver_path=bundle_root / "output" / "receiver.json",
        network_name=state["network_name"],
        receiver_name=state["receiver_name"],
        sender_name=state["sender_name"],
        network_id=_optional_state_value(state["network_id"]),
        receiver_id=_optional_state_value(state["receiver_id"]),
        receiver_cpu=_optional_state_int(state["receiver_cpu"]),
        main_cpu=_optional_state_int(state["main_cpu"]),
        helper_cpu=_optional_state_int(state["helper_cpu"]),
        sender_exit_code=_optional_state_int(state["sender_exit_code"]),
        receiver_exit_code=_optional_state_int(state["receiver_exit_code"]),
        launcher_exit_code=_optional_state_int(state["launcher_exit_code"]),
        signal_status=_optional_state_int(state["signal_status"]),
        stage=state["stage"],
        cleanup=cleanup,
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="qcsd-lab etf-probe",
        description=(
            "Run a disposable, non-evidentiary CLOCK_TAI/PRIO/FIFO/ETF capability probe"
        ),
    )
    root.add_argument("--destination", required=True, type=Path)
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
    except (FileExistsError, OSError, ValueError) as error:
        raise SystemExit(str(error)) from None
    raise SystemExit(
        "ETF probe Docker execution is available only through ./qcsd-lab etf-probe"
    )


if __name__ == "__main__":
    main()
