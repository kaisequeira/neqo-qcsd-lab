"""Prospective layered kernel reports retain strict timing and wire authority.

All fixtures are synthetic and carry zero recording credit.
"""
from copy import deepcopy
from pathlib import Path
import re

import pytest

from qcsd_lab import buflo_handoff, capture_acceptance_policy as policy, capture_session, fidelity, kernel_tx
from tests import test_buflo_cadence64_budget640 as cadence
from tests import test_kernel_tx as wire


def layered_receipt():
    raw = cadence.raw_receipt()
    raw.update(schema_version=14, semantics=kernel_tx.KERNEL_TX_LAYERED_TX_SEMANTICS)
    runtime = raw["runtime_contract"]
    state = runtime["helper_shutdown"]["socket_state"]
    inventories = []
    for index, setup in enumerate(runtime["socket_setup"]):
        items = [item for job in raw["jobs"] for item in job["items"]
                 if item["source_address"] == setup["local_address"]]
        events = []
        for item in items:
            for kind in ("scheduled", "software"):
                events.append({"sequence": len(events), "kernel_timestamp_id": item["socket_timestamp_id"],
                    "kind": kind, "realtime_ns": item["tx_sched_realtime_ns" if kind == "scheduled" else "tx_software_realtime_ns"],
                    "phase": "pending", "required_first_of_kind": True, "already_completed": False})
        if items:
            base = items[-1]["tx_software_realtime_ns"]
            for offset, kind in enumerate(("scheduled", "software"), 1):
                events.append({"sequence": len(events), "kernel_timestamp_id": items[-1]["socket_timestamp_id"],
                    "kind": kind, "realtime_ns": base + offset,
                    "phase": "shutdown", "required_first_of_kind": False, "already_completed": True})
        inventories.append({"schema_version": 1, "socket_index": index,
            "local_address": setup["local_address"], "completed_history_limit": 128,
            "events_per_transmission_limit": 16, "event_inventory_limit": 1_048_576,
            "completed_transmissions": len(items), "evicted_completed_ids": 0,
            "highest_completed_id": items[-1]["socket_timestamp_id"] if items else None,
            "observed_timestamp_events": len(events), "events": events})
    state.update(schema_version=2, timestamp_inventories=inventories)
    return raw


def _inventory(raw, index=0):
    return raw["runtime_contract"]["helper_shutdown"]["socket_state"]["timestamp_inventories"][index]


def _renumber(inventory):
    for index, event in enumerate(inventory["events"]):
        event["sequence"] = index
    inventory["observed_timestamp_events"] = len(inventory["events"])


def test_layered_raw_runner_scheduler_and_independent_wire_are_all_required():
    raw = layered_receipt()
    before = deepcopy(raw)
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    assert raw == before
    run = cadence.native_run(raw)
    run["migration_commit"] = "01e226fb43000691acbda57feb338855b26e66ca"
    run["runner_wakeup_metrics"]["semantics"] = fidelity.RUNNER_WAKEUP_V22_LAYERED_SEMANTICS
    assert fidelity._runner_wakeup_metrics_valid(run["runner_wakeup_metrics"])
    assert capture_session._runner_wakeup_metrics_valid(run["runner_wakeup_metrics"])
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    policy.validate_buflo_kernel_preparation_source_binding(cadence.source(), run)
    assert buflo_handoff._buflo_diagnostic_period_us(run, runtime_kind="buflo") == 64_000
    with pytest.raises(ValueError):
        buflo_handoff._buflo_diagnostic_period_us(
            {"runner_wakeup_metrics": {"buflo_kernel_tx": {"schema_version": 14}}}, runtime_kind="buflo")
    evidence, capture, packets = wire._evidence(raw, capture_times=[
        wire._RELEASE_TAI_NS + 3_400_000, wire._RELEASE_TAI_NS + 6_200_000])
    assert kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))
    evidence["runner_kernel_tx_sha256"] = "0" * 64
    assert not kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))


@pytest.mark.parametrize("mutation", [
    "delete-inventory", "empty-inventory", "empty-reports", "downgrade-shutdown", "wrong-count",
    "delete-extra", "duplicate", "reverse", "wrong-sequence", "unknown-id", "unknown-phase",
    "false-first", "false-completed", "wrong-pair", "missing-pair", "wrong-address", "wrong-index",
    "bad-bound", "bool-bound", "negative-time", "u32-overflow", "u64-overflow", "pending-after-shutdown",
])
def test_inventory_mutation_cannot_be_accepted(mutation):
    raw = layered_receipt()
    state = raw["runtime_contract"]["helper_shutdown"]["socket_state"]
    inventory = _inventory(raw)
    events = inventory["events"]
    if mutation == "delete-inventory": del state["timestamp_inventories"]
    elif mutation == "empty-inventory": state["timestamp_inventories"] = []
    elif mutation == "empty-reports":
        inventory.update(events=[], observed_timestamp_events=0, completed_transmissions=0, highest_completed_id=None)
    elif mutation == "downgrade-shutdown": state["schema_version"] = 1
    elif mutation == "wrong-count": inventory["completed_transmissions"] += 1
    elif mutation == "delete-extra": events.pop()
    elif mutation == "duplicate":
        events.append(deepcopy(events[-1])); _renumber(inventory)
    elif mutation == "reverse":
        events[-1], events[-2] = events[-2], events[-1]; _renumber(inventory)
    elif mutation == "wrong-sequence": events[-1]["sequence"] += 1
    elif mutation == "unknown-id": events[-1]["kernel_timestamp_id"] += 1
    elif mutation == "unknown-phase": events[-1]["phase"] = "ignored"
    elif mutation == "false-first": events[-1]["required_first_of_kind"] = True
    elif mutation == "false-completed": events[-1]["already_completed"] = False
    elif mutation == "wrong-pair": events[0]["realtime_ns"] += 1
    elif mutation == "missing-pair":
        del events[:2]; _renumber(inventory)
    elif mutation == "wrong-address": inventory["local_address"] = "10.0.0.2:1"
    elif mutation == "wrong-index": inventory["socket_index"] += 1
    elif mutation == "bad-bound": inventory["completed_history_limit"] += 1
    elif mutation == "bool-bound": inventory["event_inventory_limit"] = True
    elif mutation == "negative-time": events[-1]["realtime_ns"] = -1
    elif mutation == "u32-overflow": events[-1]["kernel_timestamp_id"] = 2**32
    elif mutation == "u64-overflow": events[-1]["realtime_ns"] = 2**64
    else: events[-1]["phase"] = "pending"
    assert not kernel_tx.kernel_tx_runner_receipt_valid(raw)


def test_pending_repeated_layer_keeps_first_pair_and_does_not_relax_deadline():
    raw = layered_receipt()
    inventory = _inventory(raw)
    repeated = deepcopy(inventory["events"][0])
    repeated.update(realtime_ns=repeated["realtime_ns"] + 1, required_first_of_kind=False)
    inventory["events"].insert(1, repeated)
    _renumber(inventory)
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    item = next(item for job in raw["jobs"] for item in job["items"]
                if item["source_address"] == inventory["local_address"])
    item["tx_sched_realtime_ns"] += 1
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_timestamp_report_bound_rejects_the_next_report():
    raw = layered_receipt()
    inventory = _inventory(raw)
    while len(inventory["events"]) < 16:
        event = deepcopy(inventory["events"][-1])
        event.update(kind="scheduled" if event["kind"] == "software" else "software",
                     realtime_ns=event["realtime_ns"] + 1)
        inventory["events"].append(event)
    _renumber(inventory)
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    event = deepcopy(inventory["events"][-1])
    event.update(kind="software" if event["kind"] == "scheduled" else "scheduled",
                 realtime_ns=event["realtime_ns"] + 1)
    inventory["events"].append(event)
    _renumber(inventory)
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_socket_local_identity_cannot_borrow_another_sockets_pair():
    raw = layered_receipt()
    first, second = _inventory(raw, 0), _inventory(raw, 1)
    first["events"], second["events"] = second["events"], first["events"]
    first["highest_completed_id"], second["highest_completed_id"] = (
        second["highest_completed_id"], first["highest_completed_id"])
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def _history_inventory(ids):
    """Independent replay fixture isolates ID lifetime from timing fixtures."""
    address = "10.0.0.2:40000"
    items, events = [], []
    for index, kernel_id in enumerate(ids):
        scheduled = 1_000 + index * 100
        items.append({"source_address": address, "socket_timestamp_id": kernel_id,
            "tx_sched_realtime_ns": scheduled, "tx_software_realtime_ns": scheduled + 10})
        for kind, stamp in (("scheduled", scheduled), ("software", scheduled + 10)):
            events.append({"sequence": len(events), "kernel_timestamp_id": kernel_id,
                "kind": kind, "realtime_ns": stamp, "phase": "pending",
                "required_first_of_kind": True, "already_completed": False})
    inventory = {"schema_version": 1, "socket_index": 0, "local_address": address,
        "completed_history_limit": 128, "events_per_transmission_limit": 16,
        "event_inventory_limit": 1_048_576, "completed_transmissions": len(ids),
        "evicted_completed_ids": max(0, len(ids) - 128), "highest_completed_id": ids[-1],
        "observed_timestamp_events": len(events), "events": events}
    return {"terminal_outcome": "complete", "jobs": [{"items": items}],
        "runtime_contract": {"socket_count": 1, "socket_setup": [{"local_address": address}],
            "helper_shutdown": {"socket_state": {"schema_version": 2, "socket_count": 1,
                "active_job_id": None, "pending_socket_count": 0, "stale_error_queue_socket_count": 0,
                "nonzero_priority_socket_count": 0, "inspection_errors": [], "clean": True,
                "timestamp_inventories": [inventory]}}}}


def test_id_gaps_are_valid_but_reuse_wrap_and_evicted_feedback_are_not():
    for ids in ([1, 3, 7], list(range(129)), [2**32 - 1]):
        assert kernel_tx._layered_timestamp_inventory_valid(_history_inventory(ids))
    for ids in ([7, 7], [7, 6], [2**32 - 1, 0]):
        assert not kernel_tx._layered_timestamp_inventory_valid(_history_inventory(ids))
    raw = _history_inventory(list(range(129)))
    inventory = _inventory(raw)
    inventory["events"].append({"sequence": len(inventory["events"]), "kernel_timestamp_id": 0,
        "kind": "scheduled", "realtime_ns": 50_000, "phase": "shutdown",
        "required_first_of_kind": False, "already_completed": True})
    _renumber(inventory)
    assert not kernel_tx._layered_timestamp_inventory_valid(raw)
    inventory["events"][-1]["kernel_timestamp_id"] = 128
    assert kernel_tx._layered_timestamp_inventory_valid(raw)


def test_missing_required_timestamp_and_original_physical_boundary_stay_fatal():
    raw = layered_receipt()
    item = raw["jobs"][0]["items"][0]
    item["tx_software_realtime_ns"] = None
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    raw = layered_receipt()
    # Extra reports cannot move the first pair away from the unchanged
    # half-open 5ms outgoing deadline.
    raw["jobs"][0]["items"][0]["tx_software_tai_upper_ns"] = (
        raw["jobs"][0]["release_tai_ns"] + 5_000_000)
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_socket_inventory_bound_rejects_overflow_before_replay():
    raw = layered_receipt()
    inventory = _inventory(raw)
    inventory["events"] = [inventory["events"][0]] * (1_048_576 + 1)
    inventory["observed_timestamp_events"] = len(inventory["events"])
    assert not kernel_tx.kernel_tx_runner_receipt_valid(raw)


def test_source_identity_prevents_entire_receipt_downgrade():
    identity = "01e226fb43000691acbda57feb338855b26e66ca"
    assert policy.LAYERED_TX_REQUIRED_NATIVE_COMMITS == frozenset({identity})
    historical = cadence.native_run()
    historical["migration_commit"] = "d2c4ec0e7dcc358fb0915d7b09c9a9b91715da8c"
    policy.validate_buflo_kernel_preparation_source_binding(cadence.source(), historical)
    historical["migration_commit"] = identity
    with pytest.raises(ValueError, match="requires schema-14"):
        policy.validate_buflo_kernel_preparation_source_binding(cadence.source(), historical)
    with pytest.raises(ValueError, match="requires schema-14"):
        policy.buflo_incoming_release_window(historical)
    current = cadence.native_run(layered_receipt())
    current["migration_commit"] = identity
    current["runner_wakeup_metrics"]["semantics"] = fidelity.RUNNER_WAKEUP_V22_LAYERED_SEMANTICS
    policy.validate_buflo_kernel_preparation_source_binding(cadence.source(), current)


def test_current_native_semantics_match_the_new_reader_without_changing_history():
    text = (Path(__file__).resolve().parents[1] / "neqo-qcsd/neqo-bin/src/qcsd/mod.rs").read_text()
    for name, expected in {
        "BUFLO_KERNEL_LAYERED_TX_SEMANTICS": kernel_tx.KERNEL_TX_LAYERED_TX_SEMANTICS,
        "BUFLO_KERNEL_CADENCE64_TX_SEMANTICS": kernel_tx.KERNEL_TX_CADENCE64_TX_SEMANTICS,
    }.items():
        match = re.search(r"const " + name + r': &str = "([^"]*)";', text)
        assert match and match.group(1) == expected
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(cadence.raw_receipt())
