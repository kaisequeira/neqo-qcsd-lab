from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from qcsd_lab import etf_probe


RELEASE = 2_000_000_000
DEADLINE = RELEASE + 5_000_000
RECEIVER_NAME = f"qcsd-etf-probe-{'1' * 32}-receiver"
RECEIVER_IPV4 = "172.18.0.2"


def _destination() -> dict[str, Any]:
    return {"ipv4": RECEIVER_IPV4, "port": etf_probe.PORT}


def _event(payload: str, tai_ns: int, *, ipv4_ds_field: int = 0) -> dict[str, Any]:
    return {
        "payload_ascii": payload,
        "user_tai_ns": tai_ns + 1_000,
        "ipv4_ds_field": ipv4_ds_field,
        "kernel_software_timestamp": {
            "realtime_ns": tai_ns - 37_000_000_000,
            "tai_lower_ns": tai_ns,
            "tai_upper_ns": tai_ns + 100,
        },
    }


def _etf(*, drops: int, packets: int, bytes_: int) -> dict[str, Any]:
    return {
        "kind": "etf",
        "handle": "20:",
        "parent": "1:1",
        "drops": drops,
        "packets": packets,
        "bytes": bytes_,
        "options": {
            "clockid": "TAI",
            "delta": 4_000_000,
            "offload": "off",
            "deadline_mode": "off",
            "skip_sock_check": "off",
        },
    }


def _fifo(*, drops: int, packets: int, bytes_: int) -> dict[str, Any]:
    return {
        "kind": "pfifo",
        "handle": "10:",
        "parent": "1:2",
        "drops": drops,
        "packets": packets,
        "bytes": bytes_,
        "options": {"limit": 1000},
    }


def _root(*, drops: int, packets: int, bytes_: int) -> dict[str, Any]:
    return {
        "kind": "prio",
        "handle": "1:",
        "root": True,
        "drops": drops,
        "packets": packets,
        "bytes": bytes_,
        "options": {"bands": 2, "priomap": [1] * 6 + [0] + [1] * 9},
    }


def _qdisc(sender: dict[str, Any], snapshot: str, kind: str) -> dict[str, Any]:
    return next(item for item in sender[snapshot]["qdiscs"] if item["kind"] == kind)


def _valid_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    payloads = etf_probe.EXPECTED_PAYLOADS
    sender = {
        "status": "sender-complete",
        "qdisc_restoration_exact": True,
        "configuration": {
            "clockid": "CLOCK_TAI",
            "delta_ns": 4_000_000,
            "realization_window_ns": 5_000_000,
            "timed_priority": 6,
            "timed_priority_mechanism": "serialized-socket-global-SO_PRIORITY",
            "ipv4_ds_field": 0x02,
            "ipv4_ecn": "ECT(0)",
            "ipv4_ds_field_mechanism": "socket-global-IP_TOS-before-SO_PRIORITY",
            "per_message_ip_tos": False,
            "so_txtime_flags": 2,
            "deadline_mode": False,
            "receiver_name": RECEIVER_NAME,
            "receiver_port": etf_probe.PORT,
            "resolved_receiver_ipv4": RECEIVER_IPV4,
            "main_cpu": 10,
            "helper_cpu": 11,
        },
        "receiver_resolution": {
            "mechanism": "AF_INET/SOCK_DGRAM-getaddrinfo-before-qdisc",
            "requested_name": RECEIVER_NAME,
            "port": etf_probe.PORT,
            "candidate_ipv4": [RECEIVER_IPV4],
            "resolved_ipv4": RECEIVER_IPV4,
            "started_tai_ns": RELEASE - 700_000_000,
            "finished_tai_ns": RELEASE - 690_000_000,
        },
        "qdisc_initial": {
            "command": {"started_tai_ns": RELEASE - 680_000_000},
            "qdiscs": [],
        },
        "qdisc_installed": {
            "qdiscs": [
                _root(drops=0, packets=0, bytes_=0),
                _fifo(drops=0, packets=0, bytes_=0),
                _etf(drops=0, packets=0, bytes_=0),
            ]
        },
        "scm_priority_preflight": {
            "destination": _destination(),
            "before_tai_ns": RELEASE - 670_000_000,
            "after_tai_ns": RELEASE - 660_000_000,
            "supported": True,
            "sent_bytes": len(payloads["scm_priority_preflight"].encode()),
            "send_error": None,
        },
        "fifo_control": {
            "destination": _destination(),
            "before_tai_ns": RELEASE - 440_100_000,
            "after_tai_ns": RELEASE - 440_000_000,
            "sent_bytes": len(payloads["fifo"].encode()),
        },
        "negative_controls": [
            {
                "name": "missing_socket",
                "destination": _destination(),
                "send_error": {"errno": 22, "name": "EINVAL"},
            },
            {
                "name": "missing_cmsg",
                "destination": _destination(),
                "send_error": None,
            },
            {
                "name": "wrong_clock",
                "destination": _destination(),
                "send_error": None,
            },
            {
                "name": "past_txtime",
                "destination": _destination(),
                "send_error": None,
            },
        ],
        "positive": {
            "main_affinity": [10],
            "main_sigstop_before_tai_ns": RELEASE - 300_000_000,
            "main_resumed_tai_ns": DEADLINE + 25_000_000,
            "ready": {
                "release_tai_ns": RELEASE,
                "deadline_tai_ns": DEADLINE,
                "scm_txtime_tai_ns": RELEASE + 4_000_000,
                "so_txtime_flags": 2,
                "deadline_mode": False,
                "destination": _destination(),
                "affinity": [11],
            },
            "final": {
                "serialized_priority_transaction": {
                    "mechanism": "socket-global-SO_PRIORITY",
                    "single_owner": "helper child while parent is SIGSTOPped",
                    "destination": _destination(),
                    "transaction_before_tai_ns": RELEASE - 280_000_000,
                    "original_ip_tos": 0,
                    "original_priority": 0,
                    "ipv4_ds_field": 0x02,
                    "ipv4_ecn": "ECT(0)",
                    "ip_tos_set_before_tai_ns": RELEASE - 279_990_000,
                    "ip_tos_set_after_tai_ns": RELEASE - 279_980_000,
                    "ip_tos_readback_before_priority": 0x02,
                    "priority_set_before_tai_ns": RELEASE - 279_970_000,
                    "priority_set_after_tai_ns": RELEASE - 279_960_000,
                    "socket_option_order": ["IP_TOS=0x02", "SO_PRIORITY=6"],
                    "per_message_ancillary": ["SCM_TXTIME"],
                    "priority_during_send": 6,
                    "enqueue_before_tai_ns": RELEASE - 279_900_000,
                    "enqueue_after_tai_ns": RELEASE - 279_800_000,
                    "sent_bytes": len(payloads["positive"].encode()),
                    "reset_before_tai_ns": RELEASE - 279_700_000,
                    "ip_tos_restore_before_tai_ns": RELEASE - 279_690_000,
                    "ip_tos_restore_after_tai_ns": RELEASE - 279_680_000,
                    "ip_tos_after_reset": 0,
                    "priority_restore_before_tai_ns": RELEASE - 279_670_000,
                    "priority_restore_after_tai_ns": RELEASE - 279_660_000,
                    "reset_after_tai_ns": RELEASE - 279_650_000,
                    "priority_after_reset": 0,
                    "socket_restore_order": ["IP_TOS=0x00", "SO_PRIORITY=0"],
                    "transaction_after_tai_ns": RELEASE - 279_500_000,
                },
                "concurrent_priority_zero": {
                    "socket_priority_configuration": (
                        "same-socket-read-back-zero-after-reset"
                    ),
                    "destination": _destination(),
                    "socket_ip_tos_before_send": 0,
                    "priority_readback": 0,
                    "per_message_ancillary": ["IP_TOS=0x02"],
                    "ipv4_ds_field": 0x02,
                    "ipv4_ecn": "ECT(0)",
                    "sent_bytes": len(payloads["fifo_concurrent"].encode()),
                    "before_tai_ns": RELEASE - 100_000_000,
                    "after_tai_ns": RELEASE - 99_900_000,
                    "socket_ip_tos_after_send": 0,
                    "priority_after_send": 0,
                },
                "error_queue": [
                    {
                        "tx_software_timestamp": {"realtime_ns": 1},
                        "extended_errors": [{"origin": 4, "info": 1, "data": 0}],
                    },
                    {
                        "tx_software_timestamp": {"realtime_ns": 2},
                        "extended_errors": [{"origin": 4, "info": 0, "data": 0}],
                    },
                    {
                        "tx_software_timestamp": {"realtime_ns": 3},
                        "extended_errors": [{"origin": 4, "info": 1, "data": 1}],
                    },
                    {
                        "tx_software_timestamp": {"realtime_ns": 4},
                        "extended_errors": [{"origin": 4, "info": 0, "data": 1}],
                    },
                ],
            },
        },
        "qdisc_after_negative_controls": {
            "qdiscs": [
                _root(drops=3, packets=1, bytes_=64),
                _fifo(drops=0, packets=1, bytes_=64),
                _etf(drops=3, packets=0, bytes_=0),
            ]
        },
        "qdisc_after_positive": {
            "qdiscs": [
                _root(drops=3, packets=3, bytes_=207),
                _fifo(drops=0, packets=2, bytes_=139),
                _etf(drops=3, packets=1, bytes_=68),
            ]
        },
    }
    receiver = {
        "timeout_seconds": etf_probe.RECEIVER_TIMEOUT_SECONDS,
        "events": [
            _event(payloads["scm_priority_preflight"], RELEASE - 450_000_000),
            _event(payloads["fifo"], RELEASE - 440_000_000),
            _event(
                payloads["fifo_concurrent"], RELEASE - 90_000_000, ipv4_ds_field=2
            ),
            _event(payloads["positive"], RELEASE + 200_000, ipv4_ds_field=2),
        ]
    }
    return sender, receiver


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _valid_supervised_bundle(
    tmp_path: Path,
) -> tuple[Path, Path, Path]:
    destination = tmp_path / "etf-receipt.json"
    bundle = tmp_path / "bundle"
    output = bundle / "output"
    output.mkdir(parents=True)
    request = bundle / "request.json"
    _write_json(
        request,
        {
            "artifact_type": etf_probe.SUPERVISED_REQUEST_TYPE,
            "schema_version": 1,
            "destination": str(destination),
            "image": "qcsd-test:fixed",
            "started_at": "2026-09-04T00:00:00Z",
            "source": {"test_fixture": True},
        },
    )
    request.chmod(0o400)
    _write_json(bundle / "docker-version.json", {"Server": {"Version": "test"}})
    _write_json(
        bundle / "docker-info.json",
        {
            "ID": "test-daemon",
            "Architecture": "x86_64",
            "OSType": "linux",
            "NCPU": 12,
        },
    )
    _write_json(
        bundle / "docker-image.json",
        {
            "Id": f"sha256:{'c' * 64}",
            "RepoDigests": [f"qcsd-test@sha256:{'d' * 64}"],
            "Architecture": "amd64",
            "Os": "linux",
        },
    )
    sender, receiver = _valid_pair()
    _write_json(output / "sender.json", sender)
    _write_json(output / "receiver.json", receiver)
    token = "1" * 32
    state = {
        "network_name": f"qcsd-etf-probe-{token}",
        "receiver_name": f"qcsd-etf-probe-{token}-receiver",
        "sender_name": f"qcsd-etf-probe-{token}-sender",
        "network_id": "a" * 64,
        "receiver_id": "b" * 64,
        "receiver_cpu": "9",
        "main_cpu": "10",
        "helper_cpu": "11",
        "sender_exit_code": "0",
        "receiver_exit_code": "0",
        "launcher_exit_code": "0",
        "signal_status": "0",
        "stage": "complete",
        "receiver_presence_before": "present",
        "receiver_remove_status": "0",
        "receiver_presence_after": "absent",
        "receiver_handoff_retired": "1",
        "network_presence_before": "present",
        "network_remove_status": "0",
        "network_presence_after": "absent",
        "network_handoff_retired": "1",
        "cleanup_passed": "1",
    }
    (bundle / "lifecycle.state").write_text(
        "".join(f"{key}={value}\n" for key, value in state.items()),
        encoding="ascii",
    )
    return request, bundle, destination


def test_git_provenance_ignores_path_and_local_fsmonitor_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["/usr/bin/git", "-C", str(repository), "init", "-q"], check=True)

    fsmonitor_marker = tmp_path / "fsmonitor-ran"
    fsmonitor = tmp_path / "fsmonitor"
    fsmonitor.write_text(
        f"#!/bin/sh\ntouch -- {fsmonitor_marker}\nexit 1\n",
        encoding="utf-8",
    )
    fsmonitor.chmod(0o755)
    subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(repository),
            "config",
            "core.fsmonitor",
            str(fsmonitor),
        ],
        check=True,
    )

    path_marker = tmp_path / "path-git-ran"
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    shadow_git = binary_root / "git"
    shadow_git.write_text(
        f"#!/bin/sh\ntouch -- {path_marker}\nexit 99\n",
        encoding="utf-8",
    )
    shadow_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_root))

    assert etf_probe._git_command(repository, "status", "--porcelain") == ""
    assert not fsmonitor_marker.exists()
    assert not path_marker.exists()


def test_validate_probe_accepts_exact_fail_closed_contract() -> None:
    sender, receiver = _valid_pair()
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is True
    assert result["failed_gates"] == []
    assert all(gate["passed"] for gate in result["gates"].values())


def test_validate_probe_requires_pre_qdisc_numeric_destination_binding() -> None:
    sender, receiver = _valid_pair()
    sender["receiver_resolution"]["finished_tai_ns"] = RELEASE - 600_000_000
    sender["negative_controls"][0]["destination"]["ipv4"] = "172.18.0.3"
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is False
    assert "numeric_receiver_resolved_before_traffic" in result["failed_gates"]


def test_validate_probe_requires_observed_ect0_and_exact_socket_restoration() -> None:
    sender, receiver = _valid_pair()
    transaction = sender["positive"]["final"]["serialized_priority_transaction"]
    transaction["ip_tos_after_reset"] = 2
    positive = next(
        item
        for item in receiver["events"]
        if item["payload_ascii"] == etf_probe.EXPECTED_PAYLOADS["positive"]
    )
    positive["ipv4_ds_field"] = 0
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is False
    assert "ipv4_ect0_socket_and_observer" in result["failed_gates"]


def test_validate_probe_requires_fifo_wire_mark_and_counters() -> None:
    sender, receiver = _valid_pair()
    fifo = next(
        item
        for item in receiver["events"]
        if item["payload_ascii"] == etf_probe.EXPECTED_PAYLOADS["fifo_concurrent"]
    )
    fifo["ipv4_ds_field"] = 0
    _qdisc(sender, "qdisc_after_positive", "etf")["drops"] = 4
    _qdisc(sender, "qdisc_after_positive", "pfifo")["packets"] = 1
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is False
    assert "priority_zero_bypasses_pending_etf" in result["failed_gates"]
    assert "etf_accounting" in result["failed_gates"]
    assert "fifo_accounting" in result["failed_gates"]


def test_validate_probe_accepts_exact_arp_sized_link_control_accounting() -> None:
    sender, receiver = _valid_pair()
    before_root = _qdisc(sender, "qdisc_after_negative_controls", "prio")
    before_fifo = _qdisc(sender, "qdisc_after_negative_controls", "pfifo")
    before_root.update({"packets": 2, "bytes": 106})
    before_fifo.update({"packets": 2, "bytes": 106})
    after_root = _qdisc(sender, "qdisc_after_positive", "prio")
    after_fifo = _qdisc(sender, "qdisc_after_positive", "pfifo")
    after_root.update({"packets": 5, "bytes": 291})
    after_fifo.update({"packets": 4, "bytes": 223})

    result = etf_probe.validate_probe(sender, receiver)

    assert result["passed"] is True
    fifo = result["gates"]["fifo_accounting"]["detail"]
    assert fifo["baseline"]["extra_link_control_packets"] == 1
    assert fifo["baseline"]["residual_link_control_bytes"] == 42
    assert fifo["positive"]["extra_link_control_packets"] == 1
    assert fifo["positive"]["residual_link_control_bytes"] == 42


def test_validate_probe_rejects_non_arp_sized_fifo_residual() -> None:
    sender, receiver = _valid_pair()
    _qdisc(sender, "qdisc_after_positive", "pfifo")["bytes"] += 1
    _qdisc(sender, "qdisc_after_positive", "prio")["bytes"] += 1

    result = etf_probe.validate_probe(sender, receiver)

    assert result["passed"] is False
    assert "fifo_accounting" in result["failed_gates"]
    assert "qdisc_hierarchy_conservation" not in result["failed_gates"]


def test_validate_probe_rejects_fifo_delta_missing_expected_datagram_bytes() -> None:
    sender, receiver = _valid_pair()
    before_fifo = _qdisc(sender, "qdisc_after_negative_controls", "pfifo")
    after_fifo = _qdisc(sender, "qdisc_after_positive", "pfifo")
    after_fifo.update(
        {
            "packets": before_fifo["packets"] + 1,
            "bytes": before_fifo["bytes"] + 42,
        }
    )
    after_root = _qdisc(sender, "qdisc_after_positive", "prio")
    after_etf = _qdisc(sender, "qdisc_after_positive", "etf")
    after_root.update(
        {
            "packets": after_fifo["packets"] + after_etf["packets"],
            "bytes": after_fifo["bytes"] + after_etf["bytes"],
        }
    )

    result = etf_probe.validate_probe(sender, receiver)

    assert result["passed"] is False
    assert "fifo_accounting" in result["failed_gates"]
    assert "qdisc_hierarchy_conservation" not in result["failed_gates"]


def test_validate_probe_rejects_etf_positive_byte_mismatch() -> None:
    sender, receiver = _valid_pair()
    _qdisc(sender, "qdisc_after_positive", "etf")["bytes"] += 1
    _qdisc(sender, "qdisc_after_positive", "prio")["bytes"] += 1

    result = etf_probe.validate_probe(sender, receiver)

    assert result["passed"] is False
    assert "etf_accounting" in result["failed_gates"]
    assert "qdisc_hierarchy_conservation" not in result["failed_gates"]


def test_validate_probe_rejects_fifo_drop_with_conserved_parent_count() -> None:
    sender, receiver = _valid_pair()
    _qdisc(sender, "qdisc_after_positive", "pfifo")["drops"] += 1
    _qdisc(sender, "qdisc_after_positive", "prio")["drops"] += 1

    result = etf_probe.validate_probe(sender, receiver)

    assert result["passed"] is False
    assert "fifo_accounting" in result["failed_gates"]
    assert "qdisc_hierarchy_conservation" not in result["failed_gates"]


@pytest.mark.parametrize(
    "snapshot",
    ["qdisc_after_negative_controls", "qdisc_after_positive"],
)
def test_validate_probe_rejects_root_child_accounting_mismatch(snapshot: str) -> None:
    sender, receiver = _valid_pair()
    _qdisc(sender, snapshot, "prio")["packets"] += 1

    result = etf_probe.validate_probe(sender, receiver)

    assert result["passed"] is False
    assert "qdisc_hierarchy_conservation" in result["failed_gates"]


def test_validate_probe_rejects_deadline_equality() -> None:
    sender, receiver = _valid_pair()
    event = next(
        item
        for item in receiver["events"]
        if item["payload_ascii"] == etf_probe.EXPECTED_PAYLOADS["positive"]
    )
    event["kernel_software_timestamp"]["tai_upper_ns"] = DEADLINE
    event["user_tai_ns"] = DEADLINE
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is False
    assert "strict_half_open_post_veth_window" in result["failed_gates"]


def test_validate_probe_receipts_scm_priority_unavailability_without_using_it() -> None:
    sender, receiver = _valid_pair()
    sender["scm_priority_preflight"].update(
        {
            "supported": False,
            "sent_bytes": None,
            "send_error": {"errno": 22, "name": "EINVAL"},
        }
    )
    receiver["events"] = [
        event
        for event in receiver["events"]
        if event["payload_ascii"]
        != etf_probe.EXPECTED_PAYLOADS["scm_priority_preflight"]
    ]
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is True
    assert result["gates"]["scm_priority_capability_receipted"]["detail"][
        "preflight"
    ]["send_error"]["errno"] == 22


def test_validate_probe_rejects_negative_control_delivery() -> None:
    sender, receiver = _valid_pair()
    receiver["events"].append(
        _event(etf_probe.EXPECTED_PAYLOADS["wrong_clock"], RELEASE + 1_000_000)
    )
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is False
    assert "receiver_inventory" in result["failed_gates"]
    assert "negative_controls_rejected" in result["failed_gates"]


def test_validate_probe_requires_distinct_sched_and_send_tx_receipts() -> None:
    sender, receiver = _valid_pair()
    sender["positive"]["final"]["error_queue"][1]["extended_errors"][0]["info"] = 1
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is False
    assert "positive_tx_feedback" in result["failed_gates"]


def test_validate_probe_forbids_txtime_deadline_mode() -> None:
    sender, receiver = _valid_pair()
    sender["configuration"]["so_txtime_flags"] = 3
    sender["configuration"]["deadline_mode"] = True
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is False
    assert "txtime_deadline_mode_forbidden" in result["failed_gates"]


def test_destination_is_create_only(tmp_path: Path) -> None:
    destination = tmp_path / "probe.json"
    destination.write_text("existing\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="already exists"):
        etf_probe._validate_destination(destination)


def test_probe_receipt_is_read_only_and_payload_bound(tmp_path: Path) -> None:
    receipt = {
        "artifact_type": etf_probe.ARTIFACT_TYPE,
        "schema_version": 1,
        "evidentiary": False,
        "authorizes_capture": False,
        "status": "passed",
    }
    receipt["payload_sha256"] = etf_probe._payload_sha256(receipt)
    path = tmp_path / "probe.json"
    path.write_bytes(etf_probe._canonical_json(receipt))
    path.chmod(0o444)
    assert etf_probe.validate_probe_receipt(path) == receipt

    path.chmod(0o644)
    receipt["status"] = "failed"
    path.write_bytes(etf_probe._canonical_json(receipt))
    path.chmod(0o444)
    with pytest.raises(ValueError, match="payload hash"):
        etf_probe.validate_probe_receipt(path)


def test_supervised_bundle_finalises_non_evidentiary_receipt(tmp_path: Path) -> None:
    request, bundle, destination = _valid_supervised_bundle(tmp_path)
    path, digest, passed = etf_probe.finalize_supervised_bundle(request, bundle)
    assert path == destination
    assert passed is True
    assert digest == etf_probe.sha256_file(destination)
    receipt = etf_probe.validate_probe_receipt(destination)
    assert receipt["evidentiary"] is False
    assert receipt["authorizes_capture"] is False
    assert receipt["lifecycle_supervision"]["helper"] == (
        "tools/docker_signal_supervisor.sh"
    )
    assert receipt["validation"]["gates"]["durable_lifecycle_cleanup"][
        "passed"
    ] is True


def test_supervised_bundle_emits_failed_receipt_after_output_failure(
    tmp_path: Path,
) -> None:
    request, bundle, destination = _valid_supervised_bundle(tmp_path)
    (bundle / "output" / "sender.json").unlink()
    _path, _digest, passed = etf_probe.finalize_supervised_bundle(request, bundle)
    assert passed is False
    receipt = etf_probe.validate_probe_receipt(destination)
    assert receipt["status"] == "failed"
    assert "probe_outputs" in receipt["validation"]["failed_gates"]
    assert "receiver_resource_binding" in receipt["validation"]["failed_gates"]


def test_supervised_bundle_rejects_false_cleanup_claim(tmp_path: Path) -> None:
    request, bundle, destination = _valid_supervised_bundle(tmp_path)
    state_path = bundle / "lifecycle.state"
    state_path.write_text(
        state_path.read_text(encoding="ascii").replace(
            "receiver_presence_after=absent", "receiver_presence_after=present"
        ),
        encoding="ascii",
    )
    _path, _digest, passed = etf_probe.finalize_supervised_bundle(request, bundle)
    assert passed is False
    receipt = etf_probe.validate_probe_receipt(destination)
    assert "durable_lifecycle_cleanup" in receipt["validation"]["failed_gates"]


def test_direct_python_entry_cannot_start_a_docker_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_subprocess(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("direct Python entry attempted a subprocess")

    monkeypatch.setattr(subprocess, "run", forbidden_subprocess)
    with pytest.raises(SystemExit, match="only through ./qcsd-lab etf-probe"):
        etf_probe.main(["--destination", str(tmp_path / "probe.json")])


def test_launcher_composes_probe_through_durable_helpers_and_latches_signal() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    branch = launcher[launcher.index('if [[ "${1:-}" == "etf-probe" ]]'):]
    branch = branch[: branch.index('\nif [[ "${1:-}" == "build" ]]')]
    assert "qcsd_create_docker_network QCSD_DOCKER_IDS_ETF_NETWORKS" in branch
    assert "qcsd_run_detached_docker QCSD_DOCKER_IDS_ETF_RECEIVERS" in branch
    assert "qcsd_run_attached_docker" in branch
    assert "qcsd_retire_docker_handoff run" in branch
    assert "qcsd_retire_docker_handoff network" in branch
    assert '129|130|131|143)' in branch
    assert '[[ -L "${etf_probe_request}" || ! -f "${etf_probe_request}" ]]' in branch
    assert "request validation returned without a regular request" in branch
    assert "if ! rm -f --" in branch
    assert "--port 45678 --timeout-seconds 12.0" in branch
    assert '_qcsd_docker_api_with_timeout 15 \\' in branch
    latch = branch.index(
        '_QCSD_LIFETIME_SIGNAL_STATUS="${etf_probe_sender_exit}"'
    )
    immediate_exit = branch.index('exit "${etf_probe_sender_exit}"', latch)
    receiver_wait = branch.index('etf_probe_stage="receiver-wait"')
    assert latch < immediate_exit < receiver_wait
    assert "etf-probe is disabled" not in branch
    assert "docker_signal_supervisor.sh" not in branch


def test_container_qdisc_contract_uses_high_priority_etf_band() -> None:
    source = Path(__file__).parents[1] / "tools/etf_probe_container.py"
    spec = importlib.util.spec_from_file_location("qcsd_etf_probe_container_test", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    observed: list[list[str]] = []

    def command(argv: list[str], *, check: bool = True) -> dict[str, Any]:
        observed.append(argv)
        return {"returncode": 0}

    module._command = command
    receipts: list[dict[str, Any]] = []
    module._install_qdisc(receipts)
    priomap = observed[0][observed[0].index("priomap") + 1 :]
    assert priomap == ["1"] * 6 + ["0"] + ["1"] * 9
    assert ["parent", "1:2"] == observed[1][5:7]
    assert ["parent", "1:1"] == observed[2][5:7]

    snapshot = {
        "qdiscs": [
            {
                "kind": "prio",
                "handle": "1:",
                "root": True,
                "options": {"bands": 2, "priomap": [1] * 6 + [0] + [1] * 9},
            },
            {
                "kind": "pfifo",
                "handle": "10:",
                "parent": "1:2",
                "options": {"limit": 1000},
            },
            {
                "kind": "etf",
                "handle": "20:",
                "parent": "1:1",
                "options": {
                    "clockid": "TAI",
                    "delta": 4_000_000,
                    "offload": "off",
                    "deadline_mode": "off",
                    "skip_sock_check": "off",
                },
            },
        ]
    }
    module._validate_installed_qdisc(copy.deepcopy(snapshot))


def test_container_positive_path_matches_production_ipv4_state_mix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = Path(__file__).parents[1] / "tools/etf_probe_container.py"
    spec = importlib.util.spec_from_file_location("qcsd_etf_probe_container_mix", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class FakeSocket:
        def __init__(self) -> None:
            self.options = {
                (module.socket.IPPROTO_IP, module.IP_TOS): 0,
                (module.socket.SOL_SOCKET, module.SO_PRIORITY): 0,
            }
            self.set_calls: list[tuple[int, int, int]] = []
            self.send_calls: list[list[tuple[int, int, bytes]]] = []

        def setsockopt(self, level: int, kind: int, value: int) -> None:
            assert isinstance(value, int)
            self.options[(level, kind)] = value
            self.set_calls.append((level, kind, value))

        def getsockopt(self, level: int, kind: int) -> int:
            return self.options[(level, kind)]

        def sendmsg(
            self,
            buffers: list[bytes],
            ancillary: list[tuple[int, int, bytes]],
            _flags: int,
            _destination: tuple[str, int],
        ) -> int:
            self.send_calls.append(ancillary)
            return sum(len(buffer) for buffer in buffers)

        def close(self) -> None:
            pass

    fake_socket = FakeSocket()
    clock_ns = 1_000_000_000

    def clock_gettime_ns(_clockid: int) -> int:
        nonlocal clock_ns
        clock_ns += 1_000_000
        return clock_ns

    monkeypatch.setattr(module, "_txtime_socket", lambda *_args, **_kwargs: fake_socket)
    monkeypatch.setattr(module, "_drain_error_queue", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "_clock_pair", lambda: {"test": 1})
    monkeypatch.setattr(module.os, "sched_setaffinity", lambda *_args: None)
    monkeypatch.setattr(module.os, "sched_getaffinity", lambda *_args: {11})
    monkeypatch.setattr(module.os, "getpid", lambda: 123)
    monkeypatch.setattr(module.os, "kill", lambda *_args: None)
    monkeypatch.setattr(module.time, "clock_gettime_ns", clock_gettime_ns)
    monkeypatch.setattr(module.time, "sleep", lambda *_args: None)

    read_fd, write_fd = module.os.pipe()
    module._positive_helper(write_fd, 456, ("127.0.0.1", 45678), 11, 0)
    with module.os.fdopen(read_fd, "r", encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream]
    assert len(records) == 2
    transaction = records[1]["serialized_priority_transaction"]
    immediate = records[1]["concurrent_priority_zero"]
    assert fake_socket.set_calls == [
        (module.socket.IPPROTO_IP, module.IP_TOS, 0x02),
        (module.socket.SOL_SOCKET, module.SO_PRIORITY, 6),
        (module.socket.IPPROTO_IP, module.IP_TOS, 0),
        (module.socket.SOL_SOCKET, module.SO_PRIORITY, 0),
    ]
    assert [(level, kind) for level, kind, _data in fake_socket.send_calls[0]] == [
        (module.socket.SOL_SOCKET, module.SCM_TXTIME)
    ]
    assert [(level, kind) for level, kind, _data in fake_socket.send_calls[1]] == [
        (module.socket.IPPROTO_IP, module.IP_TOS)
    ]
    assert module.struct.unpack("=i", fake_socket.send_calls[1][0][2]) == (0x02,)
    assert transaction["socket_restore_order"] == ["IP_TOS=0x00", "SO_PRIORITY=0"]
    assert transaction["ip_tos_after_reset"] == 0
    assert transaction["priority_after_reset"] == 0
    assert immediate["socket_ip_tos_after_send"] == 0
    assert immediate["priority_after_send"] == 0
    assert module._parse_ipv4_ds_field(
        [(module.socket.IPPROTO_IP, module.IP_TOS, b"\x02")]
    ) == 0x02


def test_container_receiver_resolution_requires_one_numeric_ipv4(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = Path(__file__).parents[1] / "tools/etf_probe_container.py"
    spec = importlib.util.spec_from_file_location(
        "qcsd_etf_probe_container_resolution", source
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    answer = (
        module.socket.AF_INET,
        module.socket.SOCK_DGRAM,
        module.socket.IPPROTO_UDP,
        "",
        (RECEIVER_IPV4, etf_probe.PORT),
    )
    monkeypatch.setattr(module.time, "clock_gettime_ns", lambda _clockid: RELEASE)
    monkeypatch.setattr(module.socket, "getaddrinfo", lambda *_args, **_kwargs: [answer, answer])
    address, receipt = module._resolve_receiver_ipv4(RECEIVER_NAME, etf_probe.PORT)
    assert address == RECEIVER_IPV4
    assert receipt["candidate_ipv4"] == [RECEIVER_IPV4]
    assert receipt["resolved_ipv4"] == RECEIVER_IPV4

    second = (*answer[:-1], ("172.18.0.3", etf_probe.PORT))
    monkeypatch.setattr(
        module.socket, "getaddrinfo", lambda *_args, **_kwargs: [answer, second]
    )
    with pytest.raises(RuntimeError, match="exactly one IPv4 address, got 2"):
        module._resolve_receiver_ipv4(RECEIVER_NAME, etf_probe.PORT)
