from __future__ import annotations

import copy
import hashlib

import pytest

from qcsd_lab import capture_session, fidelity, kernel_tx
from tests import test_kernel_tx as fixtures
from tests import test_kernel_tx_incoming_window as incoming


def _historical_ten(window: int = 10_000_000):
    raw = incoming._raw(window)
    # The historical fixture predates the new current constant. Its literal
    # schema 10 must keep the frozen schema 10 semantics.
    raw["semantics"] = kernel_tx.KERNEL_TX_RUNNER_V10_SEMANTICS
    return raw


def _refresh_wait(wait):
    entries = wait["entries"]
    failures = [entry["failure"] for entry in entries if entry["outcome"] == "failed"]
    wait.update(
        entry_count=len(entries), completed_count=len(entries) - len(failures),
        failed_count=len(failures),
        clock_read_attempts=sum(entry["clock_read_attempts"] for entry in entries),
        confirmation_attempts=sum(entry["confirmation_attempts"] for entry in entries),
        total_wait_duration_ns=sum(entry["wait_duration_ns"] for entry in entries),
        max_wait_duration_ns=max((entry["wait_duration_ns"] for entry in entries), default=0),
        max_sample_gap_ns=max((entry["max_sample_gap_ns"] for entry in entries), default=0),
        max_entry_lateness_ns=max((entry["entry_lateness_ns"] for entry in entries), default=0),
        last_failure=copy.deepcopy(failures[-1]) if failures else None,
    )


def _modern(*, offset: int | None = -4_000_000, window: int = 10_000_000):
    raw = _historical_ten(window)
    raw.update(schema_version=11, semantics=kernel_tx.KERNEL_TX_RUNNER_SEMANTICS)
    raw["runtime_contract"]["prebuild_selection_semantics"] = (
        kernel_tx.KERNEL_TX_PROTECTED_PREBUILD_SELECTION_V2_SEMANTICS
    )
    wait = raw["protected_selection_wait"]
    wait.update(schema_version=2, semantics=kernel_tx.KERNEL_TX_PROTECTED_SELECTION_WAIT_V2_SEMANTICS)
    if offset is not None:
        entry = wait["entries"][0]
        entered = entry["release_tai_ns"] + offset
        entry.update(
            entered_tai_ns=entered, completed_tai_ns=entered,
            staging_confirmed_tai_ns=entered + 100_000,
            dispatch_confirmed_tai_ns=entered + 200_000,
            clock_read_attempts=3, wait_duration_ns=0, max_sample_gap_ns=0,
            entry_lateness_ns=entered - entry["admission_tai_ns"],
        )
    _refresh_wait(wait)
    return raw


def _wakeups(raw):
    value = fixtures._runner_wakeup_v18()
    value.update(schema_version=20, semantics=fidelity.RUNNER_WAKEUP_V20_SEMANTICS, buflo_kernel_tx=raw)
    return value


def _run(raw):
    run = incoming._run(raw)
    run["runner_wakeup_metrics"] = _wakeups(raw)
    return run


def test_frozen_ten_nineteen_and_protected_one_semantics_are_byte_exact() -> None:
    expected = {
        kernel_tx.KERNEL_TX_RUNNER_V10_SEMANTICS: "ec5e46ad655ad7f1dbfb1527763f684e03da0e62bc344fbbe7a4dc2de95c928d",
        kernel_tx.KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS: "f7f82c097a0434675f1d8e28dc283eb2f7b1f23db3f908116beef09e7baad46c",
        kernel_tx.KERNEL_TX_PROTECTED_PREBUILD_SELECTION_SEMANTICS: "9f9ceca5383828771c0ce10723843d4d0a90b7cddaa2f1787c3677a9b34f0956",
        fidelity.RUNNER_WAKEUP_V19_SEMANTICS: "c94e6b7e1917423b1b9f4385ade06ba580bcb4d84194c9b323389d21fdb56ac2",
    }
    for literal, digest in expected.items():
        assert hashlib.sha256(literal.encode()).hexdigest() == digest


@pytest.mark.parametrize("schema", range(1, 11))
def test_all_historical_raw_receipts_remain_valid(schema: int) -> None:
    raw = _historical_ten() if schema == 10 else (
        fixtures._runner_receipt() if schema == 1 else getattr(fixtures, f"_runner_receipt_v{schema}")()
    )
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    if schema == 10:
        wakeups = incoming._wakeups(raw)
        assert fidelity._runner_wakeup_metrics_valid(wakeups)
        assert capture_session._runner_wakeup_metrics_valid(wakeups)


@pytest.mark.parametrize("offset", [-5_000_000, -4_000_000, -200_001, None])
def test_measured_immediate_and_waited_paths_keep_full_physical_evidence(offset) -> None:
    raw = _modern(offset=offset)
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    assert fidelity._runner_wakeup_metrics_valid(_wakeups(raw))
    assert capture_session._runner_wakeup_metrics_valid(_wakeups(raw))
    evidence, capture, packets = fixtures._evidence(raw, capture_times=[
        fixtures._RELEASE_TAI_NS + 3_400_000, fixtures._RELEASE_TAI_NS + 6_200_000,
    ])
    assert kernel_tx.kernel_tx_evidence_success_valid(
        evidence, runner_receipt=raw, **fixtures._evidence_arguments(capture, packets),
    )
    run = _run(raw)
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    assert capture_session._process_scheduler_bound_to_run_valid(
        run, expected_contract=run["process_scheduler"]["contract"],
    )
    assert fidelity.new_defense_terminal_receipts_valid(
        run, "buflo", require_application_complete=True, require_current_schema=True,
    )


@pytest.mark.parametrize("mutation", [
    "expiry", "completed", "wait", "gap", "too-few-reads", "too-many-reads",
    "confirmation-before-entry", "confirmation-expired", "wrong-entry-schema",
    "top-schema", "old-wait-semantics", "old-prebuild-semantics", "old-raw-semantics",
    "slot", "epoch", "packet", "clock", "incoming-deadline", "outgoing-deadline",
])
def test_new_receipt_rejects_forged_wait_clock_ownership_and_deadline_fields(mutation: str) -> None:
    raw = _modern()
    wait = raw["protected_selection_wait"]
    entry = wait["entries"][0]
    if mutation == "expiry":
        entry.update(entered_tai_ns=entry["release_tai_ns"], completed_tai_ns=entry["release_tai_ns"],
                     entry_lateness_ns=10_000_000)
    elif mutation == "completed": entry["completed_tai_ns"] += 1
    elif mutation == "wait": entry["wait_duration_ns"] = 1
    elif mutation == "gap": entry["max_sample_gap_ns"] = 1
    elif mutation == "too-few-reads": entry["clock_read_attempts"] = 2
    elif mutation == "too-many-reads": entry["clock_read_attempts"] = 4
    elif mutation == "confirmation-before-entry": entry["staging_confirmed_tai_ns"] = entry["entered_tai_ns"] - 1
    elif mutation == "confirmation-expired": entry["dispatch_confirmed_tai_ns"] = entry["release_tai_ns"]
    elif mutation == "wrong-entry-schema": entry["schema_version"] = 2
    elif mutation == "top-schema": wait["schema_version"] = 1
    elif mutation == "old-wait-semantics": wait["semantics"] = kernel_tx.KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS
    elif mutation == "old-prebuild-semantics": raw["runtime_contract"]["prebuild_selection_semantics"] = kernel_tx.KERNEL_TX_PROTECTED_PREBUILD_SELECTION_SEMANTICS
    elif mutation == "old-raw-semantics": raw["semantics"] = kernel_tx.KERNEL_TX_RUNNER_V10_SEMANTICS
    elif mutation == "slot": entry["slot"] = 2
    elif mutation == "epoch": entry["release_tai_ns"] += 1
    elif mutation == "packet": raw["jobs"][0]["items"][1]["event_id"] += 2
    elif mutation == "clock": raw["jobs"][0]["items"][1]["post_tx_clock_phase"]["monotonic"]["tai_before_ns"] += 1
    elif mutation == "incoming-deadline": raw["jobs"][0]["incoming_deadline_tai_ns"] += 1
    else: raw["jobs"][0]["deadline_tai_ns"] += 1
    _refresh_wait(wait)
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def test_immediate_entry_cannot_be_promoted_to_historical_ten() -> None:
    raw = _modern()
    raw.update(schema_version=10, semantics=kernel_tx.KERNEL_TX_RUNNER_V10_SEMANTICS)
    raw["runtime_contract"]["prebuild_selection_semantics"] = kernel_tx.KERNEL_TX_PROTECTED_PREBUILD_SELECTION_SEMANTICS
    raw["protected_selection_wait"].update(
        schema_version=1, semantics=kernel_tx.KERNEL_TX_PROTECTED_SELECTION_WAIT_SEMANTICS,
    )
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


def _rolling_wait():
    raw = _modern()
    wait = raw["protected_selection_wait"]
    first = wait["entries"][0]
    second = copy.deepcopy(first)
    for key in ("admission_tai_ns", "selection_tai_ns", "release_tai_ns",
                "entered_tai_ns", "completed_tai_ns", "dispatch_confirmed_tai_ns"):
        second[key] += kernel_tx.KERNEL_TX_CADENCE_NS
    second.update(slot=2, tick=1, tick_zero=False, staging_confirmed_tai_ns=None,
                  confirmation_attempts=1, clock_read_attempts=2)
    wait["entries"].append(second)
    _refresh_wait(wait)
    jobs = [{"release_tai_ns": entry["release_tai_ns"],
             "deadline_tai_ns": entry["release_tai_ns"] + 5_000_000}
            for entry in wait["entries"]]
    return raw, wait, jobs


def test_rolling_immediate_entry_requires_its_one_fresh_dispatch_confirmation() -> None:
    raw, wait, jobs = _rolling_wait()
    assert kernel_tx._protected_selection_wait_v2_valid(
        wait, defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs, success=True,
    )
    wait["entries"][1]["staging_confirmed_tai_ns"] = wait["entries"][1]["completed_tai_ns"]
    assert not kernel_tx._protected_selection_wait_v2_valid(
        wait, defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs, success=True,
    )


def test_immediate_confirmation_expiry_retains_actual_zero_wait_and_fails_closed() -> None:
    raw, wait, jobs = _rolling_wait()
    entry = wait["entries"][1]
    entry.update(outcome="failed", dispatch_confirmed_tai_ns=None)
    entry["failure"] = {
        "schema_version": 1, "slot": 2, "tick": 1, "tick_zero": False,
        "kind": "selection-expired", "detail": "actual confirmation reached release",
        "admission_tai_ns": entry["admission_tai_ns"],
        "selection_tai_ns": entry["selection_tai_ns"],
        "release_tai_ns": entry["release_tai_ns"],
        "entered_tai_ns": entry["entered_tai_ns"],
        "previous_tai_ns": entry["completed_tai_ns"],
        "observed_tai_ns": entry["release_tai_ns"], "clock_read_attempts": 2,
    }
    _refresh_wait(wait)
    assert kernel_tx._protected_selection_wait_v2_valid(
        wait, defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs[:1], success=False,
    )
    assert not kernel_tx._protected_selection_wait_v2_valid(
        wait, defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs[:1], success=True,
    )
    entry["failure"]["observed_tai_ns"] -= 1
    _refresh_wait(wait)
    assert not kernel_tx._protected_selection_wait_v2_valid(
        wait, defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs[:1], success=False,
    )


def test_first_entry_at_release_remains_a_typed_terminal_expiry() -> None:
    raw, wait, jobs = _rolling_wait()
    entry = wait["entries"][1]
    release = entry["release_tai_ns"]
    entry.update(outcome="failed", entered_tai_ns=release, completed_tai_ns=None,
        dispatch_confirmed_tai_ns=None, confirmation_attempts=0, clock_read_attempts=1,
        entry_lateness_ns=10_000_000)
    entry["failure"] = {
        "schema_version": 1, "slot": 2, "tick": 1, "tick_zero": False,
        "kind": "selection-expired", "detail": "first clock read reached exact release",
        "admission_tai_ns": entry["admission_tai_ns"],
        "selection_tai_ns": entry["selection_tai_ns"], "release_tai_ns": release,
        "entered_tai_ns": release, "previous_tai_ns": release, "observed_tai_ns": release,
        "clock_read_attempts": 1,
    }
    _refresh_wait(wait)
    assert kernel_tx._protected_selection_wait_v2_valid(
        wait, defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs[:1], success=False,
    )
    assert not kernel_tx._protected_selection_wait_v2_valid(
        wait, defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs[:1], success=True,
    )
    entry["failure"]["kind"] = "selection-entry-late"
    _refresh_wait(wait)
    assert not kernel_tx._protected_selection_wait_v2_valid(
        wait, defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs[:1], success=False,
    )


@pytest.mark.parametrize("role,deadline", [("outgoing", 5_000_000), ("incoming", 10_000_000)])
def test_immediate_readiness_does_not_extend_either_physical_deadline(role: str, deadline: int) -> None:
    raw = _modern()
    incoming._set_item_times(raw["jobs"][0]["items"][role == "incoming"],
        enqueue_offset_ns=3_000_000 if role == "outgoing" else 6_000_000, tx_offset_ns=deadline)
    raw["aggregate"]["max_tx_software_lateness_ns"] = max(deadline, 6_100_000)
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)


@pytest.mark.parametrize("role,deadline", [("outgoing", 5_000_000), ("incoming", 10_000_000)])
def test_new_receipt_requires_independent_post_veth_observation_before_deadline(role: str, deadline: int) -> None:
    raw = _modern()
    times = [fixtures._RELEASE_TAI_NS + 3_400_000, fixtures._RELEASE_TAI_NS + 6_200_000]
    times[role == "incoming"] = fixtures._RELEASE_TAI_NS + deadline
    evidence, capture, packets = fixtures._evidence(raw, capture_times=times)
    assert not kernel_tx.kernel_tx_evidence_success_valid(
        evidence, runner_receipt=raw, **fixtures._evidence_arguments(capture, packets),
    )


def test_wakeup_versions_cannot_mix_raw_receipts() -> None:
    new = _wakeups(_modern())
    new["buflo_kernel_tx"] = _historical_ten()
    assert not fidelity._runner_wakeup_metrics_valid(new)
    old = incoming._wakeups(_historical_ten())
    old["buflo_kernel_tx"] = _modern()
    assert not fidelity._runner_wakeup_metrics_valid(old)
