from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from typing import Any

import pytest

from qcsd_lab import etf_probe


RELEASE = 2_000_000_000
DEADLINE = RELEASE + 5_000_000


def _event(payload: str, tai_ns: int) -> dict[str, Any]:
    return {
        "payload_ascii": payload,
        "user_tai_ns": tai_ns + 1_000,
        "kernel_software_timestamp": {
            "realtime_ns": tai_ns - 37_000_000_000,
            "tai_lower_ns": tai_ns,
            "tai_upper_ns": tai_ns + 100,
        },
    }


def _etf(*, drops: int, packets: int) -> dict[str, Any]:
    return {
        "kind": "etf",
        "handle": "20:",
        "parent": "1:1",
        "drops": drops,
        "packets": packets,
        "options": {
            "clockid": "TAI",
            "delta": 4_000_000,
            "offload": "off",
            "deadline_mode": "off",
            "skip_sock_check": "off",
        },
    }


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
            "so_txtime_flags": 2,
            "deadline_mode": False,
            "main_cpu": 10,
            "helper_cpu": 11,
        },
        "scm_priority_preflight": {
            "supported": True,
            "sent_bytes": len(payloads["scm_priority_preflight"].encode()),
            "send_error": None,
        },
        "negative_controls": [
            {
                "name": "missing_socket",
                "send_error": {"errno": 22, "name": "EINVAL"},
            },
            {"name": "missing_cmsg", "send_error": None},
            {"name": "wrong_clock", "send_error": None},
            {"name": "past_txtime", "send_error": None},
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
                "affinity": [11],
            },
            "final": {
                "serialized_priority_transaction": {
                    "mechanism": "socket-global-SO_PRIORITY",
                    "single_owner": "helper child while parent is SIGSTOPped",
                    "transaction_before_tai_ns": RELEASE - 280_000_000,
                    "priority_during_send": 6,
                    "enqueue_before_tai_ns": RELEASE - 279_900_000,
                    "enqueue_after_tai_ns": RELEASE - 279_800_000,
                    "sent_bytes": len(payloads["positive"].encode()),
                    "reset_before_tai_ns": RELEASE - 279_700_000,
                    "reset_after_tai_ns": RELEASE - 279_600_000,
                    "priority_after_reset": 0,
                    "transaction_after_tai_ns": RELEASE - 279_500_000,
                },
                "concurrent_priority_zero": {
                    "socket_priority_configuration": (
                        "same-socket-read-back-zero-after-reset"
                    ),
                    "priority_readback": 0,
                    "sent_bytes": len(payloads["fifo_concurrent"].encode()),
                    "before_tai_ns": RELEASE - 100_000_000,
                    "after_tai_ns": RELEASE - 99_900_000,
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
        "qdisc_after_negative_controls": {"qdiscs": [_etf(drops=3, packets=0)]},
        "qdisc_after_positive": {"qdiscs": [_etf(drops=3, packets=1)]},
    }
    receiver = {
        "events": [
            _event(payloads["scm_priority_preflight"], RELEASE - 450_000_000),
            _event(payloads["fifo"], RELEASE - 440_000_000),
            _event(payloads["fifo_concurrent"], RELEASE - 90_000_000),
            _event(payloads["positive"], RELEASE + 200_000),
        ]
    }
    return sender, receiver


def test_validate_probe_accepts_exact_fail_closed_contract() -> None:
    sender, receiver = _valid_pair()
    result = etf_probe.validate_probe(sender, receiver)
    assert result["passed"] is True
    assert result["failed_gates"] == []
    assert all(gate["passed"] for gate in result["gates"].values())


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
    sender["scm_priority_preflight"] = {
        "supported": False,
        "sent_bytes": None,
        "send_error": {"errno": 22, "name": "EINVAL"},
    }
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
