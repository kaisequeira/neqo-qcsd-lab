"""Prospective schema15 controls: synthetic fixtures, no recording credit.

No saved aborted run is upgraded. The legacy14 fixtures and branch remain
literal; only a newly emitted eligible helper witness enables kernel15.
"""
from copy import deepcopy

import pytest

from qcsd_lab import buflo_handoff, capture_acceptance_policy as policy
from qcsd_lab import capture_session, fidelity, kernel_tx
from tests import test_buflo_cadence64_budget640 as cadence
from tests import test_kernel_tx as wire
from tests import test_kernel_tx_layered_feedback as layered


def receipt(*, late_userspace=False):
    raw = layered.layered_receipt()
    job = raw["jobs"][0]
    item = job["items"][0]
    if late_userspace:
        # The unchanged synthetic incoming item is at6.1ms. The main event was
        # at3.1ms, but helper send-return observation resumes only at5.5ms.
        upper = job["release_tai_ns"] + 5_500_000
        item.update(enqueue_tai_upper_ns=upper,
            enqueue_tai_ns=(item["enqueue_tai_lower_ns"] + upper) // 2,
            enqueue_monotonic_ns=upper - 1 - wire._MONOTONIC_TO_TAI_NS,
            post_tx_clock_phase={
                "monotonic": wire._clock_sample(upper + 1 - wire._MONOTONIC_TO_TAI_NS,
                    wire._MONOTONIC_TO_TAI_NS),
                "realtime": wire._clock_sample(upper + 1 - wire._REALTIME_TO_TAI_NS,
                    wire._REALTIME_TO_TAI_NS),
            })
    setup = raw["runtime_contract"]["socket_setup"][item["endpoint_index"]]
    socket = {"schema_version": 1, "family": setup["family"],
        "local_address": setup["local_address"], "socket_type": 2, "protocol": 17,
        "timestamping_report_flags": 2192, "so_timestamp": 0, "so_timestampns": 0,
        "fragment_policy": 3}
    helper = {"schema_version": 1, "before": deepcopy(socket), "after": deepcopy(socket),
        "datagram_sha256": item["datagram_sha256"], "source": item["source_address"],
        "destination": item["destination_address"], "udp_payload_bytes": 1200,
        "requested_txtime_tai_ns": item["scm_txtime_tai_ns"],
        "latest_enqueue_tai_ns": job["deadline_tai_ns"], "per_message_timestamp_flags": 258}
    witness = {"schema_version": 1,
        "basis": "same-datagram-kernel-software-upper" if late_userspace else "direct-userspace-upper",
        **{key: item[key] for key in ("item_id", "job_id", "event_id", "endpoint_index", "endpoint",
            "datagram_sha256", "source_address", "destination_address", "udp_payload_bytes")},
        "release_tai_ns": job["release_tai_ns"], "deadline_tai_ns": job["deadline_tai_ns"],
        "observed_enqueue_tai_lower_ns": item["enqueue_tai_lower_ns"],
        "observed_enqueue_tai_upper_ns": item["enqueue_tai_upper_ns"],
        "kernel_timestamp_id": item["socket_timestamp_id"],
        "tx_sched_realtime_ns": item["tx_sched_realtime_ns"],
        "tx_software_realtime_ns": item["tx_software_realtime_ns"],
        "provisional_software_tai_lower_ns": item["provisional_tx_software_tai_lower_ns"],
        "provisional_software_tai_upper_ns": item["provisional_tx_software_tai_upper_ns"],
        "enqueue_event_tai_upper_ns": (item["provisional_tx_software_tai_upper_ns"]
            if late_userspace else item["enqueue_tai_upper_ns"]), "helper_guard": helper}
    raw.update(schema_version=15, semantics=kernel_tx.KERNEL_TX_CONSERVATIVE_ENQUEUE_TX_SEMANTICS,
        enqueue_witnesses=[witness])
    return raw


def run(raw):
    value = cadence.native_run(raw)
    value["runner_wakeup_metrics"].update(schema_version=23,
        semantics=fidelity.RUNNER_WAKEUP_V23_SEMANTICS)
    return value


@pytest.mark.parametrize("late", [False, True])
def test_new_witness_keeps_observed_U_and_requires_independent_physical_evidence(late):
    raw = receipt(late_userspace=late)
    original = deepcopy(raw)
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    assert raw == original
    value = run(raw)
    assert fidelity._runner_wakeup_metrics_valid(value["runner_wakeup_metrics"])
    assert capture_session._runner_wakeup_metrics_valid(value["runner_wakeup_metrics"])
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(value)
    policy.validate_buflo_kernel_preparation_source_binding(cadence.source(), value)
    required, actual = buflo_handoff._runner_kernel_tx_requirement(value, runtime_kind="buflo")
    assert required and actual is raw
    assert buflo_handoff._buflo_diagnostic_period_us(value, runtime_kind="buflo") == 64_000
    evidence, capture, packets = wire._evidence(raw, capture_times=[
        wire._RELEASE_TAI_NS + 3_400_000, wire._RELEASE_TAI_NS + 6_200_000])
    assert evidence["runner_kernel_tx_sha256"] == kernel_tx.kernel_tx_receipt_sha256(raw)
    assert kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))
    evidence["runner_kernel_tx_sha256"] = "0" * 64
    assert not kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))
    assert raw == original


def test_legacy14_is_unchanged_and_late_U_is_not_relabelled():
    old = layered.layered_receipt()
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(old)
    new = receipt(late_userspace=True)
    del new["enqueue_witnesses"]
    new.update(schema_version=14, semantics=kernel_tx.KERNEL_TX_LAYERED_TX_SEMANTICS)
    assert not kernel_tx.kernel_tx_runner_receipt_valid(new)
    # A saved failure cannot become a positive merely by adding a schema label.
    failed = receipt(late_userspace=True)
    failed["jobs"][0]["items"][0].update(terminal_outcome="window-violation",
        finalization_state="physical-transmit-proven")
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(failed)


@pytest.mark.parametrize("mutation", [
    "missing", "duplicate", "wrong-id", "wrong-hash", "wrong-endpoint", "wrong-destination",
    "wrong-bytes", "sched-only", "wrong-report-flags", "timestamp-fallback", "timestampns-fallback",
    "fragmentable", "changed-socket", "bool-socket-option", "wrong-request-flags",
    "late-presend", "late-software", "equal-deadline", "overlap-bound", "wrong-clock",
    "wrong-original-U", "partial-send", "missing-pair", "missing-wire-clock", "unfinalized-controller",
    "wrong-txtime", "wrong-deadline", "wrong-release", "wrong-basis", "old-wakeup", "new-wakeup-old-kernel",
])
def test_missing_ambiguous_late_or_unbound_evidence_fails_closed(mutation):
    raw = receipt(late_userspace=True)
    item = raw["jobs"][0]["items"][0]
    witness = raw["enqueue_witnesses"][0]
    helper = witness["helper_guard"]
    if mutation == "missing": raw["enqueue_witnesses"] = []
    elif mutation == "duplicate": raw["enqueue_witnesses"].append(deepcopy(witness))
    elif mutation == "wrong-id": witness["kernel_timestamp_id"] += 1
    elif mutation == "wrong-hash": helper["datagram_sha256"] = "0" * 64
    elif mutation == "wrong-endpoint": witness["endpoint"] += 1
    elif mutation == "wrong-destination": helper["destination"] = "127.0.0.1:1"
    elif mutation == "wrong-bytes": helper["udp_payload_bytes"] = 1199
    elif mutation == "sched-only": witness["basis"] = "same-datagram-kernel-sched-upper"
    elif mutation == "wrong-report-flags":
        helper["before"]["timestamping_report_flags"] = helper["after"]["timestamping_report_flags"] = 0
    elif mutation == "timestamp-fallback":
        helper["before"]["so_timestamp"] = helper["after"]["so_timestamp"] = 1
    elif mutation == "timestampns-fallback":
        helper["before"]["so_timestampns"] = helper["after"]["so_timestampns"] = 1
    elif mutation == "fragmentable":
        helper["before"]["fragment_policy"] = helper["after"]["fragment_policy"] = 1
    elif mutation == "changed-socket": helper["after"]["protocol"] = 6
    elif mutation == "bool-socket-option": helper["after"]["so_timestamp"] = False
    elif mutation == "wrong-request-flags": helper["per_message_timestamp_flags"] = 256
    elif mutation == "late-presend":
        witness["observed_enqueue_tai_lower_ns"] = item["enqueue_tai_lower_ns"] = witness["deadline_tai_ns"]
    elif mutation == "late-software":
        bound = witness["deadline_tai_ns"] + 1
        witness["provisional_software_tai_upper_ns"] = item["provisional_tx_software_tai_upper_ns"] = bound
        witness["enqueue_event_tai_upper_ns"] = bound
    elif mutation == "equal-deadline":
        bound = witness["deadline_tai_ns"]
        witness["provisional_software_tai_upper_ns"] = item["provisional_tx_software_tai_upper_ns"] = bound
        witness["enqueue_event_tai_upper_ns"] = bound
    elif mutation == "overlap-bound":
        bound = witness["release_tai_ns"] - 1
        witness["provisional_software_tai_lower_ns"] = item["provisional_tx_software_tai_lower_ns"] = bound
    elif mutation == "wrong-clock": raw["clock_mapping"]["end"]["realtime"]["tai_after_ns"] += 1_000_000
    elif mutation == "wrong-original-U": item["enqueue_tai_upper_ns"] += 1
    elif mutation == "partial-send": item["send_attempt"] = {"returned_bytes": 1199}
    elif mutation == "missing-pair":
        inv = raw["runtime_contract"]["helper_shutdown"]["socket_state"]["timestamp_inventories"]
        inv[item["endpoint_index"]]["events"] = []
    elif mutation == "missing-wire-clock": del raw["clock_mapping"]
    elif mutation == "unfinalized-controller": item["finalization_state"] = "physical-transmit-proven"
    elif mutation == "wrong-txtime": helper["requested_txtime_tai_ns"] += 1
    elif mutation == "wrong-deadline": witness["deadline_tai_ns"] += 1
    elif mutation == "wrong-release": witness["release_tai_ns"] += 1
    elif mutation == "wrong-basis": witness["basis"] = "direct-userspace-upper"
    elif mutation == "old-wakeup":
        value = run(raw)
        value["runner_wakeup_metrics"]["schema_version"] = 22
        assert not fidelity._runner_wakeup_metrics_valid(value["runner_wakeup_metrics"])
        return
    else:
        value = run(raw)
        value["runner_wakeup_metrics"]["buflo_kernel_tx"] = layered.layered_receipt()
        assert not fidelity._runner_wakeup_metrics_valid(value["runner_wakeup_metrics"])
        return
    assert not kernel_tx.kernel_tx_runner_receipt_valid(raw)
    assert not fidelity._runner_wakeup_metrics_valid(run(raw)["runner_wakeup_metrics"])
