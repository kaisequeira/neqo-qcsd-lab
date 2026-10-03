from __future__ import annotations

import copy
from pathlib import Path

import pytest

from qcsd_lab import buflo_handoff, capture_session, experiment, fidelity, kernel_tx
from qcsd_lab.util import atomic_json
from tests import test_kernel_tx as fixtures
from tests.test_buflo_handoff import _complete_buflo_run
from tests.test_experiment import _sample


@pytest.mark.parametrize("schema", range(1, 9))
def test_bounded_enqueue_preserves_historical_runner_schemas(schema: int) -> None:
    factory = fixtures._runner_receipt if schema == 1 else getattr(fixtures, f"_runner_receipt_v{schema}")
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(factory())


def test_bounded_enqueue_requires_new_source_semantics_and_keeps_wire_window() -> None:
    raw = fixtures._runner_receipt_v9_late_enqueue()
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    evidence, capture, packets = fixtures._evidence(
        raw,
        capture_times=[fixtures._RELEASE_TAI_NS + 3_400_000, fixtures._RELEASE_TAI_NS + 3_500_000],
    )
    assert kernel_tx.kernel_tx_evidence_success_valid(
        evidence, runner_receipt=raw, **fixtures._evidence_arguments(capture, packets)
    )

    historical = copy.deepcopy(raw)
    historical["schema_version"] = 8
    historical["semantics"] = kernel_tx.KERNEL_TX_RUNNER_V8_SEMANTICS
    historical["clock_mapping"]["schema_version"] = 5
    historical["clock_mapping"]["effective_envelope_semantics"] = kernel_tx._EFFECTIVE_ENVELOPE_SEMANTICS_V5
    for item in historical["jobs"][0]["items"]:
        item["schema_version"] = 5
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(historical)

    changed_packets = copy.deepcopy(packets)
    changed_packets[0]["datagram_sha256"] = "f" * 64
    assert not kernel_tx.kernel_tx_evidence_success_valid(
        evidence, runner_receipt=raw, **fixtures._evidence_arguments(capture, changed_packets)
    )


@pytest.mark.parametrize("offset", [0, 1])
def test_bounded_enqueue_rejects_the_exact_deadline_and_later(offset: int) -> None:
    raw = fixtures._runner_receipt_v9_late_enqueue()
    item = raw["jobs"][0]["items"][0]
    enqueue = raw["jobs"][0]["deadline_tai_ns"] + offset
    item.update(
        enqueue_monotonic_ns=enqueue - fixtures._MONOTONIC_TO_TAI_NS,
        enqueue_tai_ns=enqueue,
        enqueue_tai_lower_ns=enqueue,
        enqueue_tai_upper_ns=enqueue,
    )
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_bounded_enqueue_does_not_accept_physical_tx_at_the_deadline() -> None:
    raw = fixtures._runner_receipt_v9_late_enqueue()
    item = raw["jobs"][0]["items"][0]
    tx = raw["jobs"][0]["deadline_tai_ns"]
    item.update(
        tx_sched_realtime_ns=tx - fixtures._REALTIME_TO_TAI_NS,
        tx_sched_tai_ns=tx,
        tx_sched_tai_lower_ns=tx,
        tx_sched_tai_upper_ns=tx,
        tx_software_realtime_ns=tx - fixtures._REALTIME_TO_TAI_NS,
        tx_software_tai_ns=tx,
        tx_software_tai_lower_ns=tx,
        tx_software_tai_upper_ns=tx,
        provisional_tx_software_tai_lower_ns=tx,
        provisional_tx_software_tai_upper_ns=tx,
    )
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_bounded_enqueue_retains_direct_enqueue_before_physical_tx_causality() -> None:
    raw = fixtures._runner_receipt_v9_late_enqueue()
    item = raw["jobs"][0]["items"][0]
    enqueue = item["tx_software_tai_lower_ns"] + 1
    item.update(
        enqueue_monotonic_ns=enqueue - fixtures._MONOTONIC_TO_TAI_NS,
        enqueue_tai_ns=enqueue,
        enqueue_tai_lower_ns=enqueue,
        enqueue_tai_upper_ns=enqueue,
    )
    assert kernel_tx._item_local_enqueue_operation_ordered(
        item["post_tx_clock_phase"],
        enqueue_monotonic_ns=item["enqueue_monotonic_ns"],
        enqueue_tai_lower_ns=enqueue,
        enqueue_tai_upper_ns=enqueue,
    )
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


@pytest.mark.parametrize("kind", ["semantics", "mapping", "item", "clock", "identity"])
def test_bounded_enqueue_rejects_changed_source_clock_and_packet_identity(kind: str) -> None:
    raw = fixtures._runner_receipt_v9_late_enqueue()
    if kind == "semantics":
        raw["semantics"] = kernel_tx.KERNEL_TX_RUNNER_V8_SEMANTICS
    elif kind == "mapping":
        raw["clock_mapping"]["schema_version"] = 5
    elif kind == "item":
        raw["jobs"][0]["items"][0]["schema_version"] = 5
    elif kind == "clock":
        raw["jobs"][0]["items"][0]["post_tx_clock_phase"]["monotonic"]["tai_before_ns"] += 1
    else:
        raw["jobs"][0]["items"][0]["event_id"] += 2
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_bounded_enqueue_wakeup_collection_handoff_and_summary_dispatch() -> None:
    modern = fixtures._runner_wakeup_v18()
    modern["buflo_kernel_tx"] = fixtures._runner_receipt_v9_late_enqueue()
    old = fixtures._runner_wakeup_v17()
    for wakeups in (old, modern):
        assert fidelity._runner_wakeup_metrics_valid(wakeups)
        assert capture_session._runner_wakeup_metrics_valid(wakeups)
        required, retained = buflo_handoff._runner_kernel_tx_requirement(
            {"runner_wakeup_metrics": wakeups}, runtime_kind="buflo"
        )
        assert required and retained is wakeups["buflo_kernel_tx"]
        scheduler = copy.deepcopy(retained["runtime_contract"]["scheduler_initial"])
        run = _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1)
        run.update(process_scheduler=scheduler, runner_wakeup_metrics=wakeups)
        assert capture_session._process_scheduler_bound_to_run_valid(
            run, expected_contract=scheduler["contract"]
        )
        assert fidelity.new_defense_terminal_receipts_valid(
            run, "buflo", require_application_complete=True, require_current_schema=True
        )
    for wakeups, other in ((modern, old), (old, modern)):
        mismatched = copy.deepcopy(wakeups)
        mismatched["buflo_kernel_tx"] = other["buflo_kernel_tx"]
        assert not fidelity._runner_wakeup_metrics_valid(mismatched)
        assert not capture_session._runner_wakeup_metrics_valid(mismatched)


def test_bounded_enqueue_accepted_sample_still_requires_scheduler_and_wire_sidecars(tmp_path: Path) -> None:
    sample = {**_sample(), "state": "accepted", "defense": "buflo", "runtime_kind": "buflo", "baseline": False}
    wakeups = fixtures._runner_wakeup_v18()
    atomic_json(tmp_path / sample["path"] / "neqo/run.json", {
        "terminal_evidence_render_errors": [], "runner_wakeup_metrics": wakeups,
        "process_scheduler": wakeups["buflo_kernel_tx"]["runtime_contract"]["scheduler_initial"],
        "resolved_configuration": {"defense": {"kind": "buflo"}},
    })
    with pytest.raises(ValueError, match="lacks its evidence sidecar"):
        experiment.validate_accepted_kernel_tx_evidence(tmp_path, sample)
    with pytest.raises(ValueError, match="lacks its scheduler runtime receipt"):
        experiment.validate_accepted_scheduler_runtime_receipt(
            tmp_path, {"configuration": {"evidence_role": "formal"}}, sample
        )
