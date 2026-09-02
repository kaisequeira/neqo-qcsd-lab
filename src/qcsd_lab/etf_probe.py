"""Host orchestrator for the versioned, non-evidentiary ETF capability probe."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import secrets
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import LAB_ROOT, durable_create, fsync_directory, sha256_file


ARTIFACT_TYPE = "qcsd-etf-capability-probe"
SCHEMA_VERSION = 1
CONTAINER_TOOL = LAB_ROOT / "tools/etf_probe_container.py"
DEFAULT_IMAGE = "neqo-qcsd-lab-collection:local"
PORT = 45678
RECEIVER_TIMEOUT_SECONDS = 4.0
RELEASE_LEAD_NS = 500_000_000
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


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _payload_sha256(value: dict[str, Any]) -> str:
    payload = dict(value)
    payload.pop("payload_sha256", None)
    return _sha256_bytes(
        b"qcsd-etf-capability-probe-v1\0" + _canonical_json(payload)
    )


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
    if value.get("artifact_type") != ARTIFACT_TYPE or value.get("schema_version") != 1:
        raise ValueError("ETF probe receipt identity is invalid")
    if value.get("evidentiary") is not False or value.get("authorizes_capture") is not False:
        raise ValueError("ETF probe receipt makes a forbidden evidence claim")
    if value.get("status") not in {"passed", "failed"}:
        raise ValueError("ETF probe receipt status is invalid")
    if value.get("payload_sha256") != _payload_sha256(value):
        raise ValueError("ETF probe receipt payload hash is invalid")
    return value


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    finished_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class DockerCommands:
    def __init__(self) -> None:
        self.receipts: list[dict[str, Any]] = []

    def run(
        self,
        argv: list[str],
        *,
        check: bool = True,
        timeout: float = 30.0,
        record: bool = True,
    ) -> CommandResult:
        started = _utc_now()
        try:
            process = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
            result = CommandResult(
                argv=argv,
                returncode=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                started_at=started,
                finished_at=_utc_now(),
            )
        except subprocess.TimeoutExpired as error:
            result = CommandResult(
                argv=argv,
                returncode=124,
                stdout=(error.stdout or "") if isinstance(error.stdout, str) else "",
                stderr=(error.stderr or "") if isinstance(error.stderr, str) else "",
                started_at=started,
                finished_at=_utc_now(),
            )
        if record:
            self.receipts.append(result.as_dict())
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(
                f"command failed ({result.returncode}): {' '.join(argv)}: {detail}"
            )
        return result


def _json_command(commands: DockerCommands, argv: list[str]) -> Any:
    result = commands.run(argv)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"command returned invalid JSON: {' '.join(argv)}") from error


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


def _host_provenance(commands: DockerCommands) -> dict[str, Any]:
    def git(*arguments: str) -> str:
        return commands.run(
            ["git", "-C", str(LAB_ROOT), *arguments], record=False
        ).stdout.strip()

    status = git("status", "--porcelain", "--untracked-files=all")
    return {
        "lab_commit": git("rev-parse", "HEAD"),
        "lab_dirty": bool(status),
        "lab_status": status.splitlines(),
        "neqo_commit": commands.run(
            ["git", "-C", str(LAB_ROOT / "neqo-qcsd"), "rev-parse", "HEAD"],
            record=False,
        ).stdout.strip(),
        "neqo_gitlink": git("ls-files", "--stage", "--", "neqo-qcsd").split()[1],
        "source_files": {
            path.relative_to(LAB_ROOT).as_posix(): sha256_file(path)
            for path in (Path(__file__), CONTAINER_TOOL, LAB_ROOT / "qcsd-lab")
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
    }


def _docker_provenance(commands: DockerCommands, image: str) -> dict[str, Any]:
    version = _json_command(commands, ["docker", "version", "--format", "{{json .}}"])
    info = _json_command(
        commands,
        [
            "docker",
            "info",
            "--format",
            "{{json .}}",
        ],
    )
    inspected = _json_command(commands, ["docker", "image", "inspect", image])
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise RuntimeError("Docker returned an ambiguous image inspection")
    image_value = inspected[0]
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
            "id": image_value.get("Id"),
            "repo_digests": image_value.get("RepoDigests") or [],
            "architecture": image_value.get("Architecture"),
            "os": image_value.get("Os"),
        },
    }


def _event_index(receiver: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for event in receiver.get("events", []):
        index.setdefault(str(event.get("payload_ascii")), []).append(event)
    return index


def _etf_entry(sender: dict[str, Any], snapshot: str) -> dict[str, Any]:
    entries = sender[snapshot]["qdiscs"]
    matches = [entry for entry in entries if entry.get("kind") == "etf"]
    if len(matches) != 1:
        raise ValueError(f"{snapshot} does not contain exactly one ETF qdisc")
    return matches[0]


def validate_probe(sender: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
    """Return explicit fail-closed gates for one sender/receiver probe pair."""

    gates: dict[str, dict[str, Any]] = {}

    def gate(name: str, passed: bool, detail: Any) -> None:
        gates[name] = {"passed": bool(passed), "detail": detail}

    gate(
        "sender_completed_and_restored",
        sender.get("status") == "sender-complete"
        and sender.get("qdisc_restoration_exact") is True,
        {
            "status": sender.get("status"),
            "qdisc_restoration_exact": sender.get("qdisc_restoration_exact"),
            "error": sender.get("error"),
        },
    )
    configuration = sender.get("configuration", {})
    gate(
        "fixed_qdisc_contract",
        configuration.get("clockid") == "CLOCK_TAI"
        and configuration.get("delta_ns") == 4_000_000
        and configuration.get("realization_window_ns") == 5_000_000
        and configuration.get("timed_priority") == 6
        and configuration.get("timed_priority_mechanism")
        == "serialized-socket-global-SO_PRIORITY",
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
        and not unknown,
        {"counts": event_counts, "unknown_payloads": unknown},
    )
    positive = sender.get("positive", {})
    ready = positive.get("ready", {})
    final = positive.get("final", {})
    transaction = final.get("serialized_priority_transaction", {})
    release = ready.get("release_tai_ns")
    deadline = ready.get("deadline_tai_ns")
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
    gate(
        "priority_zero_bypasses_pending_etf",
        numeric_window
        and concurrent_send.get("socket_priority_configuration")
        == "same-socket-read-back-zero-after-reset"
        and concurrent_send.get("priority_readback") == 0
        and concurrent_send.get("sent_bytes")
        == len(EXPECTED_PAYLOADS["fifo_concurrent"].encode())
        and concurrent_send.get("before_tai_ns", release) < release
        and concurrent_kernel is not None
        and concurrent_kernel.get("tai_upper_ns", release) < release,
        {
            "send": concurrent_send,
            "receiver_kernel_timestamp": concurrent_kernel,
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
    try:
        before = _etf_entry(sender, "qdisc_after_negative_controls")
        after = _etf_entry(sender, "qdisc_after_positive")
        drops = int(before.get("drops", 0))
        packets_before = int(before.get("packets", 0))
        packets_after = int(after.get("packets", 0))
    except (KeyError, TypeError, ValueError) as error:
        drops = -1
        packets_before = -1
        packets_after = -1
        qdisc_detail: Any = {"error": str(error)}
    else:
        qdisc_detail = {
            "drops_after_negative_controls": drops,
            "packets_before_positive": packets_before,
            "packets_after_positive": packets_after,
        }
    gate(
        "etf_accounting",
        drops >= 3 and packets_after == packets_before + 1,
        qdisc_detail,
    )
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


def run_probe(destination: Path, *, image: str = DEFAULT_IMAGE) -> tuple[Path, str, bool]:
    destination = _validate_destination(destination)
    if not CONTAINER_TOOL.is_file() or CONTAINER_TOOL.is_symlink():
        raise ValueError(f"ETF container probe tool is unavailable: {CONTAINER_TOOL}")
    commands = DockerCommands()
    started_at = _utc_now()
    resource_token = secrets.token_hex(6)
    network = f"qcsd-etf-probe-{resource_token}"
    receiver_name = f"{network}-receiver"
    sender_name = f"{network}-sender"
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
        "started_at": started_at,
        "configuration": {
            "topology": "disposable-docker-bridge-veth",
            "qdisc": "root-prio/normal-pfifo/timed-etf",
            "clockid": "CLOCK_TAI",
            "etf_delta_ns": 4_000_000,
            "strict_realization_window_ns": 5_000_000,
            "timed_priority": 6,
            "timed_priority_mechanism": "serialized-socket-global-SO_PRIORITY",
            "scm_priority_probe": "receipted capability fact; never used as fallback",
            "so_txtime_flags": 2,
            "deadline_mode": False,
            "normal_priority": 0,
            "release_lead_ns": RELEASE_LEAD_NS,
            "negative_controls": sorted(NEGATIVE_NAMES),
            "main_stop_test": "SIGSTOP main across the complete realization window",
        },
        "resources": {
            "network": network,
            "receiver_container": receiver_name,
            "sender_container": sender_name,
        },
    }
    cleanup: list[dict[str, Any]] = []
    execution_error: dict[str, str] | None = None
    try:
        receipt["source"] = _host_provenance(commands)
        receipt["docker"] = _docker_provenance(commands, image)
        cpu_count = receipt["docker"]["info"].get("NCPU")
        if not isinstance(cpu_count, int) or cpu_count < 3:
            raise RuntimeError("ETF probe requires at least three Docker CPUs")
        main_cpu = cpu_count - 2
        helper_cpu = cpu_count - 1
        receiver_cpu = cpu_count - 3
        receipt["cpu_assignment"] = {
            "receiver": receiver_cpu,
            "main": main_cpu,
            "timed_helper": helper_cpu,
        }
        with tempfile.TemporaryDirectory(prefix="qcsd-etf-probe-") as raw_temp:
            temporary = Path(raw_temp)
            temporary.chmod(0o777)
            receiver_output = temporary / "receiver.json"
            sender_output = temporary / "sender.json"
            ready = temporary / "receiver.ready"
            commands.run(["docker", "network", "create", "--driver", "bridge", network])
            receiver_command = [
                "docker",
                "run",
                "--detach",
                "--name",
                receiver_name,
                "--network",
                network,
                "--cpuset-cpus",
                str(receiver_cpu),
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "--volume",
                f"{CONTAINER_TOOL}:/probe/etf_probe_container.py:ro",
                "--volume",
                f"{temporary}:/probe-output:rw",
                "--entrypoint",
                "/usr/bin/tini",
                image,
                "--",
                "/usr/bin/python3",
                "-B",
                "/probe/etf_probe_container.py",
                "receive",
                "--output",
                "/probe-output/receiver.json",
                "--ready",
                "/probe-output/receiver.ready",
                "--port",
                str(PORT),
                "--timeout-seconds",
                str(RECEIVER_TIMEOUT_SECONDS),
            ]
            commands.run(receiver_command)
            _wait_for_file(ready, timeout_seconds=5.0)
            sender_command = [
                "docker",
                "run",
                "--name",
                sender_name,
                "--network",
                network,
                "--cpuset-cpus",
                f"{main_cpu},{helper_cpu}",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "NET_ADMIN",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "--volume",
                f"{CONTAINER_TOOL}:/probe/etf_probe_container.py:ro",
                "--volume",
                f"{temporary}:/probe-output:rw",
                "--entrypoint",
                "/usr/bin/tini",
                image,
                "--",
                "/usr/bin/python3",
                "-B",
                "/probe/etf_probe_container.py",
                "send",
                "--output",
                "/probe-output/sender.json",
                "--receiver",
                receiver_name,
                "--port",
                str(PORT),
                "--main-cpu",
                str(main_cpu),
                "--helper-cpu",
                str(helper_cpu),
                "--lead-ns",
                str(RELEASE_LEAD_NS),
            ]
            sender_result = commands.run(sender_command, check=False, timeout=10.0)
            receiver_wait = commands.run(
                ["docker", "wait", receiver_name], check=False, timeout=8.0
            )
            receipt["container_exit_codes"] = {
                "sender": sender_result.returncode,
                "receiver": (
                    int(receiver_wait.stdout.strip())
                    if receiver_wait.returncode == 0
                    and receiver_wait.stdout.strip().isdigit()
                    else None
                ),
            }
            sender = _load_json(sender_output, label="ETF sender")
            receiver = _load_json(receiver_output, label="post-veth receiver")
            receipt["sender"] = sender
            receipt["receiver"] = receiver
            receipt["validation"] = validate_probe(sender, receiver)
            if sender_result.returncode != 0:
                receipt["validation"]["passed"] = False
                receipt["validation"]["failed_gates"].append("sender_exit_code")
            if receipt["container_exit_codes"]["receiver"] != 0:
                receipt["validation"]["passed"] = False
                receipt["validation"]["failed_gates"].append("receiver_exit_code")
            receipt["status"] = (
                "passed" if receipt["validation"]["passed"] else "failed"
            )
    except BaseException as error:
        execution_error = {"type": type(error).__name__, "message": str(error)}
        receipt["execution_error"] = execution_error
    finally:
        for argv in (
            ["docker", "rm", "--force", sender_name],
            ["docker", "rm", "--force", receiver_name],
            ["docker", "network", "rm", network],
        ):
            cleanup.append(commands.run(argv, check=False, timeout=10.0).as_dict())
        receipt["cleanup"] = cleanup
        receipt["cleanup_passed"] = all(
            item["returncode"] == 0
            or (item["returncode"] == 1 and "No such" in item["stderr"])
            for item in cleanup
        )
        if not receipt["cleanup_passed"]:
            receipt["status"] = "failed"
        receipt["finished_at"] = _utc_now()
        receipt["docker_commands"] = commands.receipts
        receipt["payload_sha256"] = _payload_sha256(receipt)
        encoded = _canonical_json(receipt)
        durable_create(destination, encoded)
        destination.chmod(0o444)
        fsync_directory(destination.parent)
        validate_probe_receipt(destination)
    return destination, _sha256_bytes(encoded), receipt["status"] == "passed"


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
        path, sha256, passed = run_probe(args.destination, image=args.image)
    except (FileExistsError, OSError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from None
    print(json.dumps({"path": str(path), "sha256": sha256, "passed": passed}, sort_keys=True))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
