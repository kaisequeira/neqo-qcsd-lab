from __future__ import annotations

import copy
import errno
import json
from pathlib import Path
from typing import Any

import pytest

from qcsd_lab import etf_veth_probe


SERIES_ID = "1" * 32
START = 2_000_000_000
OFFSET_NS = 37_000_000_000


def _clock_pair(
    at_ns: int,
    *,
    offset_lower_ns: int = OFFSET_NS,
    offset_upper_ns: int = OFFSET_NS + 100,
) -> dict[str, int]:
    width = offset_upper_ns - offset_lower_ns
    realtime_before = at_ns
    realtime_after = at_ns + width
    tai = realtime_after + offset_lower_ns
    return {
        "realtime_before_ns": realtime_before,
        "tai_ns": tai,
        "realtime_after_ns": realtime_after,
        "offset_lower_ns": offset_lower_ns,
        "offset_upper_ns": offset_upper_ns,
        "bracket_width_ns": width,
    }


def _timestamp_from_raw(raw_ns: int, pair: dict[str, int]) -> dict[str, int]:
    seconds, nanoseconds = divmod(raw_ns, 1_000_000_000)
    return {
        "seconds": seconds,
        "nanoseconds": nanoseconds,
        "raw_ns": raw_ns,
        "realtime_ns": raw_ns,
        "tai_lower_ns": raw_ns + pair["offset_lower_ns"],
        "tai_upper_ns": raw_ns + pair["offset_upper_ns"],
    }


def _timestamp(value: int, pair: dict[str, int] | None = None) -> dict[str, int]:
    pair = pair or _clock_pair(10_000)
    return _timestamp_from_raw(value - pair["offset_lower_ns"], pair)


def _valid_outputs(samples: int = 2) -> tuple[dict[str, Any], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    queue: list[dict[str, Any]] = []
    peer_events: list[dict[str, Any]] = []
    for sequence in range(samples):
        release = START + sequence * etf_veth_probe.INTERVAL_NS
        digest = f"{sequence + 1:064x}"
        events.append(
            {
                "sequence": sequence,
                "payload_sha256": digest,
                "payload_bytes": etf_veth_probe.PAYLOAD_BYTES,
                "release_tai_ns": release,
                "deadline_tai_ns": release + etf_veth_probe.STRICT_WINDOW_NS,
                "scm_txtime_tai_ns": release + etf_veth_probe.ETF_DELTA_NS,
                "enqueue_wake_tai_ns": release - etf_veth_probe.ENQUEUE_LEAD_NS,
                "active_wait_entered_tai_ns": (
                    release - etf_veth_probe.ACTIVE_WAIT_START_LEAD_NS
                ),
                "active_wait_iterations": 100,
                "enqueue_before_tai_ns": release - 4_900_000,
                "enqueue_after_tai_ns": release - 4_800_000,
                "send_id": sequence,
                "sent_bytes": etf_veth_probe.PAYLOAD_BYTES,
                "send_error": None,
                "outcome": "enqueued",
            }
        )
        for kind_index, (kind, offset) in enumerate(((1, 50_000), (0, 100_000))):
            pair = _clock_pair(10_000 + sequence * 10_000 + kind_index * 1_000)
            queue.append(
                {
                    "timestamp": _timestamp(release + offset, pair),
                    "clock_pair": pair,
                    "extended_errors": [
                        {
                            "errno": errno.ENOMSG,
                            "origin": 4,
                            "info": kind,
                            "data": sequence,
                        }
                    ],
                }
            )
        peer_pair = _clock_pair(20_000 + sequence * 10_000)
        peer_events.append(
            {
                "sequence": sequence,
                "payload_sha256": digest,
                "payload_bytes": etf_veth_probe.PAYLOAD_BYTES,
                "kernel_software_timestamp": _timestamp(
                    release + 200_000, peer_pair
                ),
                "clock_pair": peer_pair,
            }
        )
    masks = {"rx-0": {"rps_cpus": "000"}, "tx-0": {"xps_cpus": "000"}}
    sender = {
        "schema_version": etf_veth_probe.SCHEMA_VERSION,
        "role": "etf-series-sender",
        "status": "sender-complete",
        "series_id": SERIES_ID,
        "expected_samples": samples,
        "configuration": {
            "profile": etf_veth_probe.PROFILE,
            "clockid": "CLOCK_TAI",
            "delta_ns": etf_veth_probe.ETF_DELTA_NS,
            "strict_window_ns": etf_veth_probe.STRICT_WINDOW_NS,
            "interval_ns": etf_veth_probe.INTERVAL_NS,
            "payload_bytes": etf_veth_probe.PAYLOAD_BYTES,
            "enqueue_lead_ns": etf_veth_probe.ENQUEUE_LEAD_NS,
            "active_wait_start_lead_ns": (
                etf_veth_probe.ACTIVE_WAIT_START_LEAD_NS
            ),
            "active_wait_window_ns": (
                etf_veth_probe.ACTIVE_WAIT_START_LEAD_NS
                - etf_veth_probe.ENQUEUE_LEAD_NS
            ),
            "deadline_mode": False,
            "main_cpu": 10,
            "helper_cpu": 11,
            "cpu_profile": etf_veth_probe.CPU_PROFILE,
            "rps_profile": etf_veth_probe.RPS_PROFILE,
            "scope": "kernel-timing-geometry-and-post-veth-isolation-only",
            "exercises_rust_quic": False,
            "production_priority_transaction": False,
            "main_helper_split_exercised": False,
            "authorizes_http3_gate": False,
        },
        "available_affinity": [10, 11],
        "scheduler": {
            "affinity": [11],
            "policy_name": "SCHED_RR",
            "priority": 1,
        },
        "queue_masks_start": masks,
        "queue_masks_end": copy.deepcopy(masks),
        "clock_pair_start": _clock_pair(1_000),
        "clock_pair_end": _clock_pair(2_000_000),
        "qdisc_restoration_exact": True,
        "qdisc_installed": {
            "qdiscs": [
                {
                    "kind": "etf",
                    "packets": 0,
                    "bytes": 0,
                    "drops": 0,
                    "overlimits": 0,
                    "requeues": 0,
                    "backlog": 0,
                    "qlen": 0,
                }
            ]
        },
        "qdisc_after_series": {
            "qdiscs": [
                {
                    "kind": "etf",
                    "packets": samples,
                    "bytes": samples * etf_veth_probe.ETF_QDISC_BYTES_PER_PACKET,
                    "drops": 0,
                    "overlimits": 0,
                    "requeues": 0,
                    "backlog": 0,
                    "qlen": 0,
                }
            ]
        },
        "series": {
            "start_tai_ns": START,
            "events": events,
            "error_queue": queue,
            "socket_restoration": {
                "priority_before_reset": 6,
                "ip_tos_before_reset": 2,
                "priority_after_reset": 0,
                "ip_tos_after_reset": 0,
            },
        },
    }
    peer = {
        "schema_version": etf_veth_probe.SCHEMA_VERSION,
        "role": "post-veth-peer",
        "status": "peer-complete",
        "series_id": SERIES_ID,
        "expected_samples": samples,
        "configuration": {
            "payload_bytes": etf_veth_probe.PAYLOAD_BYTES,
            "port": etf_veth_probe.PORT,
            "rps_profile": etf_veth_probe.RPS_PROFILE,
        },
        "available_affinity": [9],
        "scheduler": {
            "affinity": [9],
            "policy_name": "SCHED_OTHER",
            "priority": 0,
        },
        "queue_masks_start": masks,
        "queue_masks_end": copy.deepcopy(masks),
        "clock_pair_start": _clock_pair(2_000),
        "clock_pair_end": _clock_pair(2_000_000),
        "done_marker_observed": True,
        "post_done_drain_completed": True,
        "post_done_drain_elapsed_ns": 500_000_000,
        "events": peer_events,
    }
    return sender, peer


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _supervised_bundle(tmp_path: Path) -> tuple[Path, Path, Path]:
    bundle = tmp_path / "scratch"
    output = bundle / "output"
    output.mkdir(parents=True)
    destination = tmp_path / "probe-bundle"
    request = bundle / "request.json"
    _write_json(
        request,
        {
            "artifact_type": etf_veth_probe.REQUEST_TYPE,
            "schema_version": etf_veth_probe.REQUEST_SCHEMA_VERSION,
            "destination": str(destination),
            "image": "qcsd-test:fixed",
            "samples": etf_veth_probe.MIN_SAMPLES,
            "profile": etf_veth_probe.PROFILE,
            "series_id": SERIES_ID,
            "started_at": "2026-09-23T00:00:00Z",
            "source": {"fixture": True},
        },
    )
    _write_json(bundle / "docker-version.json", {"Server": {"Version": "test"}})
    _write_json(
        bundle / "docker-info.json",
        {"ID": "daemon", "Architecture": "x86_64", "OSType": "linux", "NCPU": 12},
    )
    _write_json(
        bundle / "docker-image.json",
        {
            "Id": f"sha256:{'a' * 64}",
            "RepoDigests": [f"qcsd-test@sha256:{'b' * 64}"],
            "Architecture": "amd64",
            "Os": "linux",
        },
    )
    sender, peer = _valid_outputs(etf_veth_probe.MIN_SAMPLES)
    _write_json(output / "sender.json", sender)
    _write_json(output / "peer.json", peer)
    network = f"qcsd-etf-veth-probe-{'c' * 32}"
    state = {
        "network_name": network,
        "peer_name": f"{network}-peer",
        "sender_name": f"{network}-sender",
        "network_id": "d" * 64,
        "peer_id": "e" * 64,
        "peer_cpu": "9",
        "main_cpu": "10",
        "helper_cpu": "11",
        "sender_exit_code": "0",
        "peer_exit_code": "0",
        "launcher_exit_code": "0",
        "signal_status": "0",
        "stage": "complete",
        "peer_presence_before": "present",
        "peer_remove_status": "0",
        "peer_presence_after": "absent",
        "peer_handoff_retired": "1",
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


def test_series_accepts_exact_kernel_timing_geometry_profile() -> None:
    sender, peer = _valid_outputs()
    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is True
    assert result["diagnosis"]["strict_5ms_passed"] is True
    assert result["diagnosis"]["classification_counts"] == {"matched": 2}


def test_series_detects_v115_class_post_veth_tail_without_integrity_failure() -> None:
    sender, peer = _valid_outputs()
    release = sender["series"]["events"][1]["release_tai_ns"]
    peer_event = peer["events"][1]
    peer_event["kernel_software_timestamp"] = _timestamp(
        release + 14_500_000, peer_event["clock_pair"]
    )

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is True
    assert result["diagnosis"]["strict_5ms_passed"] is False
    assert result["diagnosis"]["post_veth_tail_observed"] is True
    assert result["diagnosis"]["classification_counts"] == {
        "matched": 1,
        "post-veth-tail": 1,
    }


def test_series_enforces_half_open_deadline() -> None:
    sender, peer = _valid_outputs()
    deadline = sender["series"]["events"][0]["deadline_tai_ns"]
    pair = _clock_pair(20_000, offset_upper_ns=OFFSET_NS)
    peer["events"][0]["clock_pair"] = pair
    peer["events"][0]["kernel_software_timestamp"] = _timestamp(deadline, pair)

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is True
    assert result["events"][0]["classification"] == "post-veth-tail"
    assert result["events"][0]["peer_strict_5ms"] is False


@pytest.mark.parametrize("observer", ["sender", "peer"])
def test_series_reports_release_clock_straddle_separately_from_tail(
    observer: str,
) -> None:
    sender, peer = _valid_outputs()
    release = sender["series"]["events"][0]["release_tai_ns"]
    pair = _clock_pair(
        20_000,
        offset_lower_ns=OFFSET_NS - 50_000,
        offset_upper_ns=OFFSET_NS + 50_000,
    )
    uncertain = _timestamp_from_raw(release - OFFSET_NS, pair)
    if observer == "sender":
        sender["series"]["error_queue"][1]["timestamp"] = uncertain
        sender["series"]["error_queue"][1]["clock_pair"] = pair
    else:
        peer["events"][0]["kernel_software_timestamp"] = uncertain
        peer["events"][0]["clock_pair"] = pair

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is True
    assert result["events"][0]["classification"] == f"{observer}-release-straddle"
    assert result["diagnosis"]["clock_interval_straddle_observed"] is True
    assert result["diagnosis"]["post_veth_tail_observed"] is False


def test_series_rejects_duplicate_peer_observation_as_integrity_failure() -> None:
    sender, peer = _valid_outputs()
    peer["events"].append(copy.deepcopy(peer["events"][0]))

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is False
    assert "peer_packet_matching" in result["failed_integrity_gates"]


def test_series_rejects_post_release_catch_up_enqueue() -> None:
    sender, peer = _valid_outputs()
    event = sender["series"]["events"][0]
    event["enqueue_after_tai_ns"] = event["release_tai_ns"]

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is False
    assert "pre_release_enqueue_without_catch_up" in result["failed_integrity_gates"]


@pytest.mark.parametrize("field", ["raw_ns", "realtime_ns", "tai_upper_ns"])
def test_series_rejects_forged_clock_timestamp_derivation(field: str) -> None:
    sender, peer = _valid_outputs()
    timestamp = sender["series"]["error_queue"][0]["timestamp"]
    timestamp[field] += 1

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is False
    assert "sender_clock_integrity" in result["failed_integrity_gates"]
    detail = result["integrity_gates"]["sender_clock_integrity"]["detail"]
    assert detail["raw_realtime_and_derived_intervals_exact"] is False


def test_series_rejects_peer_raw_realtime_mismatch() -> None:
    sender, peer = _valid_outputs()
    peer["events"][0]["kernel_software_timestamp"]["raw_ns"] += 1

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is False
    assert "peer_clock_integrity" in result["failed_integrity_gates"]


def test_series_rejects_clock_step_without_a_common_offset_envelope() -> None:
    sender, peer = _valid_outputs()
    peer["clock_pair_end"] = _clock_pair(
        2_000_000,
        offset_lower_ns=OFFSET_NS + 1_000_000,
        offset_upper_ns=OFFSET_NS + 1_000_100,
    )

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is False
    assert "peer_clock_integrity" in result["failed_integrity_gates"]
    detail = result["integrity_gates"]["peer_clock_integrity"]["detail"]
    assert detail["common_offset_envelope_intersects"] is False


def test_series_rejects_coherent_cross_observer_clock_offset_shift() -> None:
    sender, peer = _valid_outputs()
    shift_ns = 1_000_000
    for name in ("clock_pair_start", "clock_pair_end"):
        old_pair = peer[name]
        peer[name] = _clock_pair(
            old_pair["realtime_before_ns"],
            offset_lower_ns=old_pair["offset_lower_ns"] + shift_ns,
            offset_upper_ns=old_pair["offset_upper_ns"] + shift_ns,
        )
    for event in peer["events"]:
        old_pair = event["clock_pair"]
        old_timestamp = event["kernel_software_timestamp"]
        pair = _clock_pair(
            old_pair["realtime_before_ns"],
            offset_lower_ns=old_pair["offset_lower_ns"] + shift_ns,
            offset_upper_ns=old_pair["offset_upper_ns"] + shift_ns,
        )
        event["clock_pair"] = pair
        event["kernel_software_timestamp"] = _timestamp_from_raw(
            old_timestamp["raw_ns"], pair
        )

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_gates"]["sender_clock_integrity"]["passed"] is True
    assert result["integrity_gates"]["peer_clock_integrity"]["passed"] is True
    assert result["integrity_passed"] is False
    assert "cross_observer_clock_envelope" in result["failed_integrity_gates"]


def test_series_rejects_unbounded_clock_bracket() -> None:
    sender, peer = _valid_outputs()
    pair = _clock_pair(
        20_000,
        offset_upper_ns=OFFSET_NS + etf_veth_probe.MAX_CLOCK_BRACKET_NS + 1,
    )
    peer["events"][0]["clock_pair"] = pair
    peer["events"][0]["kernel_software_timestamp"] = _timestamp(
        START + 200_000, pair
    )

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is False
    assert "peer_clock_integrity" in result["failed_integrity_gates"]
    detail = result["integrity_gates"]["peer_clock_integrity"]["detail"]
    assert detail["all_pairs_well_formed_and_bounded"] is False


def test_series_requires_peer_done_marker_and_optional_qdisc_accounting() -> None:
    sender, peer = _valid_outputs()
    peer["done_marker_observed"] = False
    sender["qdisc_after_series"]["qdiscs"][0]["bytes"] += 1

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is False
    assert "peer_completed_post_sender_drain" in result["failed_integrity_gates"]
    assert "etf_qdisc_accounting" in result["failed_integrity_gates"]
    byte_gate = result["integrity_gates"]["etf_qdisc_accounting"]["detail"][
        "optional_counters"
    ]["bytes"]
    assert byte_gate["supported"] is True
    assert byte_gate["passed"] is False


def test_series_rejects_done_marker_without_completed_post_done_drain() -> None:
    sender, peer = _valid_outputs()
    peer["post_done_drain_completed"] = False
    peer["post_done_drain_elapsed_ns"] = 499_999_999

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is False
    assert "peer_completed_post_sender_drain" in result["failed_integrity_gates"]


def test_series_does_not_invent_absent_optional_qdisc_counters() -> None:
    sender, peer = _valid_outputs()
    for snapshot in ("qdisc_installed", "qdisc_after_series"):
        qdisc = sender[snapshot]["qdiscs"][0]
        for field in ("bytes", "overlimits", "requeues", "backlog", "qlen"):
            del qdisc[field]

    result = etf_veth_probe.evaluate_series(
        sender, peer, samples=2, series_id=SERIES_ID
    )

    assert result["integrity_passed"] is True
    optional = result["integrity_gates"]["etf_qdisc_accounting"]["detail"][
        "optional_counters"
    ]
    assert all(item["supported"] is False for item in optional.values())
    assert all(item["passed"] is True for item in optional.values())


def test_bundle_is_create_only_non_evidentiary_and_hash_bound(tmp_path: Path) -> None:
    request, scratch, destination = _supervised_bundle(tmp_path)
    path, digest, passed = etf_veth_probe.finalize_supervised_bundle(request, scratch)

    assert path == destination
    assert passed is True
    receipt = etf_veth_probe.validate_bundle(path)
    assert digest == etf_veth_probe.sha256_file(path / "receipt.json")
    assert receipt["evidentiary"] is False
    assert receipt["authorizes_capture"] is False
    assert receipt["status"] == "complete"
    assert receipt["configuration"]["rps_xps_mutated"] is False
    with pytest.raises(FileExistsError, match="already exists"):
        etf_veth_probe.finalize_supervised_bundle(request, scratch)


def test_bundle_validation_rejects_tampered_worker_output(tmp_path: Path) -> None:
    request, scratch, destination = _supervised_bundle(tmp_path)
    etf_veth_probe.finalize_supervised_bundle(request, scratch)
    destination.chmod(0o755)
    sender_path = destination / "sender.json"
    sender_path.chmod(0o644)
    sender_path.write_text("{}\n", encoding="utf-8")
    sender_path.chmod(0o444)
    destination.chmod(0o555)

    with pytest.raises(ValueError, match="manifest"):
        etf_veth_probe.validate_bundle(destination)


def test_schema_two_replay_rejects_coherently_resealed_false_evaluation(
    tmp_path: Path,
) -> None:
    request, scratch, destination = _supervised_bundle(tmp_path)
    etf_veth_probe.finalize_supervised_bundle(request, scratch)
    destination.chmod(0o755)
    sender_path = destination / "sender.json"
    receipt_path = destination / "receipt.json"
    sender_path.chmod(0o644)
    receipt_path.chmod(0o644)
    sender = json.loads(sender_path.read_text(encoding="utf-8"))
    sender["series"]["events"][0]["enqueue_after_tai_ns"] = START
    _write_json(sender_path, sender)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["manifest"]["sender.json"] = etf_veth_probe.sha256_file(sender_path)
    receipt["payload_sha256"] = etf_veth_probe._receipt_payload_sha256(receipt)
    _write_json(receipt_path, receipt)
    sender_path.chmod(0o444)
    receipt_path.chmod(0o444)
    destination.chmod(0o555)

    with pytest.raises(ValueError, match="embedded evaluation differs from replay"):
        etf_veth_probe.validate_bundle(destination)


def test_schema_one_bundle_validation_remains_supported(tmp_path: Path) -> None:
    request, scratch, destination = _supervised_bundle(tmp_path)
    etf_veth_probe.finalize_supervised_bundle(request, scratch)
    destination.chmod(0o755)
    sender_path = destination / "sender.json"
    peer_path = destination / "peer.json"
    receipt_path = destination / "receipt.json"
    sender_path.chmod(0o644)
    peer_path.chmod(0o644)
    receipt_path.chmod(0o644)
    sender = json.loads(sender_path.read_text(encoding="utf-8"))
    peer = json.loads(peer_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    sender["schema_version"] = etf_veth_probe.PREVIOUS_SCHEMA_VERSION
    sender["configuration"]["profile"] = etf_veth_probe.HISTORICAL_PROFILE
    for name in (
        "active_wait_start_lead_ns",
        "active_wait_window_ns",
        "scope",
        "exercises_rust_quic",
        "production_priority_transaction",
        "main_helper_split_exercised",
        "authorizes_http3_gate",
    ):
        sender["configuration"].pop(name)
    for event in sender["series"]["events"]:
        event.pop("active_wait_entered_tai_ns")
        event.pop("active_wait_iterations")
    peer["schema_version"] = etf_veth_probe.PREVIOUS_SCHEMA_VERSION
    peer.pop("post_done_drain_completed")
    peer.pop("post_done_drain_elapsed_ns")
    _write_json(sender_path, sender)
    _write_json(peer_path, peer)
    receipt["schema_version"] = etf_veth_probe.PREVIOUS_SCHEMA_VERSION
    receipt["purpose"] = etf_veth_probe.HISTORICAL_PURPOSE
    receipt["configuration"] = {
        "profile": etf_veth_probe.HISTORICAL_PROFILE,
        "samples": etf_veth_probe.MIN_SAMPLES,
        "series_id": SERIES_ID,
        "payload_bytes": etf_veth_probe.PAYLOAD_BYTES,
        "interval_ns": etf_veth_probe.INTERVAL_NS,
        "strict_window_ns": etf_veth_probe.STRICT_WINDOW_NS,
        "etf_delta_ns": etf_veth_probe.ETF_DELTA_NS,
        "enqueue_lead_ns": etf_veth_probe.ENQUEUE_LEAD_NS,
        "observer_boundary": "peer-ingress-after-sender-veth",
        "cpu_profile": etf_veth_probe.CPU_PROFILE,
        "rps_profile": etf_veth_probe.RPS_PROFILE,
        "rps_xps_mutated": False,
    }
    receipt["manifest"] = {
        "sender.json": etf_veth_probe.sha256_file(sender_path),
        "peer.json": etf_veth_probe.sha256_file(peer_path),
    }
    receipt["payload_sha256"] = etf_veth_probe._receipt_payload_sha256(receipt)
    _write_json(receipt_path, receipt)
    sender_path.chmod(0o444)
    peer_path.chmod(0o444)
    receipt_path.chmod(0o444)
    destination.chmod(0o555)

    validated = etf_veth_probe.validate_bundle(destination)

    assert validated["schema_version"] == etf_veth_probe.PREVIOUS_SCHEMA_VERSION


def test_schema_two_bundle_cannot_bypass_replay_by_downgrade_relabelling(
    tmp_path: Path,
) -> None:
    request, scratch, destination = _supervised_bundle(tmp_path)
    etf_veth_probe.finalize_supervised_bundle(request, scratch)
    destination.chmod(0o755)
    sender_path = destination / "sender.json"
    receipt_path = destination / "receipt.json"
    sender_path.chmod(0o644)
    receipt_path.chmod(0o644)
    sender = json.loads(sender_path.read_text(encoding="utf-8"))
    sender["series"]["events"][0]["enqueue_after_tai_ns"] = START
    _write_json(sender_path, sender)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["schema_version"] = etf_veth_probe.PREVIOUS_SCHEMA_VERSION
    receipt["manifest"]["sender.json"] = etf_veth_probe.sha256_file(sender_path)
    receipt["payload_sha256"] = etf_veth_probe._receipt_payload_sha256(receipt)
    _write_json(receipt_path, receipt)
    sender_path.chmod(0o444)
    receipt_path.chmod(0o444)
    destination.chmod(0o555)

    with pytest.raises(ValueError, match="schema-1 historical contract"):
        etf_veth_probe.validate_bundle(destination)


def test_bundle_rejects_mismatched_lifecycle_cpu_observations(tmp_path: Path) -> None:
    request, scratch, destination = _supervised_bundle(tmp_path)
    sender_path = scratch / "output" / "sender.json"
    sender = json.loads(sender_path.read_text(encoding="utf-8"))
    sender["available_affinity"] = [11]
    _write_json(sender_path, sender)

    _path, _digest, passed = etf_veth_probe.finalize_supervised_bundle(
        request, scratch
    )
    receipt = etf_veth_probe.validate_bundle(destination)

    assert passed is False
    assert receipt["status"] == "incomplete"
    assert (
        "baseline_cpu_assignment_and_observation"
        in receipt["evaluation"]["failed_integrity_gates"]
    )


def test_public_cli_and_launcher_are_bounded_and_do_not_mutate_rps() -> None:
    args = etf_veth_probe.parser().parse_args(
        ["--destination", "/tmp/probe-bundle"]
    )
    assert args.samples == 2_048
    assert args.profile == etf_veth_probe.PROFILE

    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    start = launcher.index('if [[ "${1:-}" == "etf-veth-probe" ]]')
    end = launcher.index('\nif [[ "${1:-}" == "build" ]]', start)
    branch = launcher[start:end]
    assert "--samples \"${etf_veth_probe_samples}\"" in branch
    assert "--ulimit rtprio=1:1" in branch
    assert "--cpuset-cpus \"${etf_veth_probe_main_cpu},${etf_veth_probe_helper_cpu}\"" in branch
    assert "rps_cpus" not in branch
    assert "xps_cpus" not in branch
    assert "cannot authorise the mandatory HTTP/3 post-veth PCAP" in launcher


def test_host_provenance_hashes_imported_etf_probe_dependency() -> None:
    provenance = etf_veth_probe._host_provenance()

    assert "src/qcsd_lab/etf_probe.py" in provenance["source_files"]
