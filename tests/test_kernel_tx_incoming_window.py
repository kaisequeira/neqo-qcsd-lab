from __future__ import annotations

import copy
from pathlib import Path

import pytest

from qcsd_lab import buflo_handoff, capture_session, experiment, fidelity, kernel_tx
from qcsd_lab.capture_acceptance_policy import FIELD, POLICY
from qcsd_lab.util import atomic_json
from tests import test_kernel_tx as fixtures
from tests.test_buflo_handoff import _complete_buflo_run
from tests.test_experiment import _sample


def _set_item_times(item, *, enqueue_offset_ns: int, tx_offset_ns: int) -> None:
    enqueue = fixtures._RELEASE_TAI_NS + enqueue_offset_ns
    tx = fixtures._RELEASE_TAI_NS + tx_offset_ns
    item.update(
        enqueue_monotonic_ns=enqueue - fixtures._MONOTONIC_TO_TAI_NS,
        enqueue_tai_ns=enqueue, enqueue_tai_lower_ns=enqueue, enqueue_tai_upper_ns=enqueue,
        tx_sched_realtime_ns=tx - 10_000 - fixtures._REALTIME_TO_TAI_NS,
        tx_sched_tai_ns=tx - 10_000, tx_sched_tai_lower_ns=tx - 10_000,
        tx_sched_tai_upper_ns=tx - 10_000,
        tx_software_realtime_ns=tx - fixtures._REALTIME_TO_TAI_NS,
        tx_software_tai_ns=tx, tx_software_tai_lower_ns=tx, tx_software_tai_upper_ns=tx,
        provisional_tx_software_tai_lower_ns=tx, provisional_tx_software_tai_upper_ns=tx,
        post_tx_clock_phase={
            "monotonic": fixtures._clock_sample(tx + 1 - fixtures._MONOTONIC_TO_TAI_NS, fixtures._MONOTONIC_TO_TAI_NS),
            "realtime": fixtures._clock_sample(tx + 1 - fixtures._REALTIME_TO_TAI_NS, fixtures._REALTIME_TO_TAI_NS),
        },
    )


def _raw(window_ns: int = 10_000_000):
    raw = fixtures._runner_receipt_v9_late_enqueue()
    raw.update(schema_version=10, semantics=kernel_tx.KERNEL_TX_RUNNER_V10_SEMANTICS,
               incoming_credit_release_window_ns=window_ns)
    for job in raw["jobs"]:
        job.update(schema_version=2,
            incoming_deadline_monotonic_ns=job["release_monotonic_ns"] + window_ns,
            incoming_deadline_tai_ns=job["release_tai_ns"] + window_ns)
    if window_ns == 10_000_000:
        _set_item_times(raw["jobs"][0]["items"][1], enqueue_offset_ns=6_000_000, tx_offset_ns=6_100_000)
        raw["aggregate"]["max_tx_software_lateness_ns"] = 6_100_000
    return raw


def _wakeups(raw):
    value = fixtures._runner_wakeup_v18()
    value.update(schema_version=19, semantics=fidelity.RUNNER_WAKEUP_V19_SEMANTICS, buflo_kernel_tx=raw)
    return value


def _run(raw):
    run = _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1)
    run.update(runner_wakeup_metrics=_wakeups(raw),
               process_scheduler=copy.deepcopy(raw["runtime_contract"]["scheduler_initial"]))
    if raw["incoming_credit_release_window_ns"] == 10_000_000:
        run.update(primary_document_identity_policy="variable-primary-document-body-v1",
                   application_response_policy="completed-terminal-http-errors-v1",
                   defense_parameters={"kind": "buflo"})
        run[FIELD] = {"schema_version": 1, "source": "bound-preparation-v1", "policy": POLICY,
                      "incoming_release_window_us": 10_000, "period_us": 20_000,
                      "cell_bytes": 1_200, "scientific_credit": False}
    return run


@pytest.mark.parametrize("schema", range(1, 10))
def test_incoming_window_preserves_all_historical_receipts(schema: int) -> None:
    factory = fixtures._runner_receipt if schema == 1 else getattr(fixtures, f"_runner_receipt_v{schema}")
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(factory())


def test_incoming_carrier_at_six_ms_passes_raw_and_independent_wire_proof() -> None:
    raw = _raw()
    assert raw["jobs"][0]["deadline_tai_ns"] - raw["jobs"][0]["release_tai_ns"] == 5_000_000
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    evidence, capture, packets = fixtures._evidence(raw, capture_times=[
        fixtures._RELEASE_TAI_NS + 3_400_000, fixtures._RELEASE_TAI_NS + 6_200_000])
    assert kernel_tx.kernel_tx_evidence_success_valid(
        evidence, runner_receipt=raw, **fixtures._evidence_arguments(capture, packets))
    historical = fixtures._runner_receipt_v9_late_enqueue()
    historical["jobs"][0]["items"][1] = copy.deepcopy(raw["jobs"][0]["items"][1])
    historical["aggregate"]["max_tx_software_lateness_ns"] = 6_100_000
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(historical)


@pytest.mark.parametrize("role,offset", [("incoming", 10_000_000), ("incoming", 10_000_001),
                                         ("outgoing", 5_000_000), ("outgoing", 5_000_001)])
def test_role_specific_physical_deadline_is_strict(role: str, offset: int) -> None:
    raw = _raw()
    item = raw["jobs"][0]["items"][1 if role == "incoming" else 0]
    _set_item_times(item, enqueue_offset_ns=6_000_000 if role == "incoming" else 3_000_000,
                    tx_offset_ns=offset)
    raw["aggregate"]["max_tx_software_lateness_ns"] = max(offset, 6_100_000)
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_incoming_enqueue_at_its_ten_ms_deadline_is_rejected() -> None:
    raw = _raw()
    _set_item_times(raw["jobs"][0]["items"][1], enqueue_offset_ns=10_000_000, tx_offset_ns=10_100_000)
    raw["aggregate"]["max_tx_software_lateness_ns"] = 10_100_000
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


@pytest.mark.parametrize("role,offset", [("incoming", 10_000_000), ("outgoing", 5_000_000)])
def test_post_veth_observation_uses_the_correct_strict_role_deadline(role: str, offset: int) -> None:
    raw = _raw()
    times = [fixtures._RELEASE_TAI_NS + 3_400_000, fixtures._RELEASE_TAI_NS + 6_200_000]
    times[1 if role == "incoming" else 0] = fixtures._RELEASE_TAI_NS + offset
    evidence, capture, packets = fixtures._evidence(raw, capture_times=times)
    assert kernel_tx.kernel_tx_evidence_valid(evidence, runner_receipt=raw,
        **fixtures._evidence_arguments(capture, packets))
    assert not kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **fixtures._evidence_arguments(capture, packets))
    assert evidence["reconciliations"][1 if role == "incoming" else 0]["terminal_outcome"] == "window-violation"


@pytest.mark.parametrize("kind", ["bool_window", "float_window", "wrong_window", "missing_deadline",
                                   "tai_deadline", "mono_deadline", "job_schema", "packet", "clock"])
def test_schema_ten_rejects_unbound_fields_and_original_evidence_mutations(kind: str) -> None:
    raw = _raw()
    job = raw["jobs"][0]
    if kind == "bool_window": raw["incoming_credit_release_window_ns"] = True
    elif kind == "float_window": raw["incoming_credit_release_window_ns"] = 10_000_000.0
    elif kind == "wrong_window": raw["incoming_credit_release_window_ns"] = 5_000_000
    elif kind == "missing_deadline": del job["incoming_deadline_tai_ns"]
    elif kind == "tai_deadline": job["incoming_deadline_tai_ns"] += 1
    elif kind == "mono_deadline": job["incoming_deadline_monotonic_ns"] += 1
    elif kind == "job_schema": job["schema_version"] = 1
    elif kind == "packet": job["items"][1]["event_id"] += 2
    else: job["items"][1]["post_tx_clock_phase"]["monotonic"]["tai_before_ns"] += 1
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_schema_ten_keeps_legacy_incoming_window_without_opt_in() -> None:
    raw = _raw(5_000_000)
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(_run(raw))
    _set_item_times(raw["jobs"][0]["items"][1], enqueue_offset_ns=5_000_000, tx_offset_ns=5_100_000)
    raw["aggregate"]["max_tx_software_lateness_ns"] = 5_100_000
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


@pytest.mark.parametrize("window", [5_000_000, 10_000_000])
def test_wakeup_collection_handoff_and_terminal_consumers_accept_only_correct_pairing(window: int) -> None:
    raw = _raw(window)
    run = _run(raw)
    wakeups = run["runner_wakeup_metrics"]
    assert fidelity._runner_wakeup_metrics_valid(wakeups)
    assert capture_session._runner_wakeup_metrics_valid(wakeups)
    required, retained = buflo_handoff._runner_kernel_tx_requirement(run, runtime_kind="buflo")
    assert required and retained is raw
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    assert capture_session._process_scheduler_bound_to_run_valid(run, expected_contract=run["process_scheduler"]["contract"])
    assert fidelity.new_defense_terminal_receipts_valid(run, "buflo", require_application_complete=True, require_current_schema=True)
    old = fixtures._runner_wakeup_v18()
    mismatched = copy.deepcopy(wakeups)
    mismatched["buflo_kernel_tx"] = old["buflo_kernel_tx"]
    assert not fidelity._runner_wakeup_metrics_valid(mismatched)
    old["buflo_kernel_tx"] = raw
    assert not fidelity._runner_wakeup_metrics_valid(old)


@pytest.mark.parametrize("kind", ["absent", "source", "period", "window", "null"])
def test_incoming_window_requires_the_actual_closed_native_policy_marker(kind: str) -> None:
    run = _run(_raw())
    if kind == "absent": del run[FIELD]
    elif kind == "null": run[FIELD] = None
    else: run[FIELD][{"source": "source", "period": "period_us", "window": "incoming_release_window_us"}[kind]] = 0
    assert not kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    assert not capture_session._process_scheduler_bound_to_run_valid(run, expected_contract=run["process_scheduler"]["contract"])
    assert not fidelity.new_defense_terminal_receipts_valid(run, "buflo", require_application_complete=True, require_current_schema=True)


def test_current_nineteen_still_requires_actual_wire_and_scheduler_sidecars(tmp_path: Path) -> None:
    sample = {**_sample(), "state": "accepted", "defense": "buflo", "runtime_kind": "buflo", "baseline": False}
    atomic_json(tmp_path / sample["path"] / "neqo/run.json", {**_run(_raw()), "terminal_evidence_render_errors": []})
    with pytest.raises(ValueError, match="lacks its evidence sidecar"):
        experiment.validate_accepted_kernel_tx_evidence(tmp_path, sample)
    with pytest.raises(ValueError, match="lacks its scheduler runtime receipt"):
        experiment.validate_accepted_scheduler_runtime_receipt(tmp_path, {"configuration": {"evidence_role": "formal"}}, sample)
