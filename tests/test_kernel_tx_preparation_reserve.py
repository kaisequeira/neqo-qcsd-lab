"""Prospective reserve accepts measured preparation, never late physical cells."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import re

import pytest

from qcsd_lab import buflo_handoff, capture_acceptance_policy as policy
from qcsd_lab import capture_session, experiment, fidelity, kernel_tx
from qcsd_lab.manifest import validate_manifest
from qcsd_lab.util import atomic_json
from tests import test_kernel_tx as fixtures
from tests import test_kernel_tx_incoming_window as incoming
from tests import test_kernel_tx_late_selection as selection
from tests.test_capture_buflo_ack_start import startup
from tests.test_experiment import _sample
from tests.test_manifest import prepared_manifest
from tests.test_primary_document_identity_policy import variable_workload


def marker():
    # Independent closed producer oracle, including all JSON types.
    return {"schema_version": 1, "source": "bound-preparation-v1",
        "policy": "rapid-v6-buflo-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1",
        "period_us": 20_000, "cell_bytes": 1_200, "nominal_selection_lead_us": 5_000,
        "rolling_preparation_after_release_us": 4_000, "outgoing_physical_window_us": 5_000,
        "preparation_reserve_us": 1_000, "tick_zero_before_release": True,
        "allow_omissions": False, "paper_equivalent": False, "scientific_credit": False}


def prepared():
    value = prepared_manifest()
    variable, _ = variable_workload()
    value["resources"] = variable["resources"]
    value["preparation"].update(variable["preparation"])
    value["preparation"].update(
        observed_origins=["https://cdn.test", "https://page.test"],
        approved_origins=["https://cdn.test", "https://page.test"],
        qualified_chaff_origin_policy="prepared-approved-origins-v1",
        buflo_incoming_credit_release_policy=policy.ACK_START_POLICY)
    value["preparation"]["coverage_admission"].update(
        schema_version=1, required_origins=value["preparation"]["approved_origins"])
    return value


def raw_receipt():
    raw = selection._modern()
    raw.update(schema_version=12, semantics=kernel_tx.KERNEL_TX_RESERVE_TX_SEMANTICS,
               preparation_policy=marker())
    raw["runtime_contract"]["prebuild_selection_semantics"] = kernel_tx.KERNEL_TX_RESERVE_PREBUILD_SELECTION_SEMANTICS
    wait = raw["protected_selection_wait"]
    wait.update(schema_version=3, semantics=kernel_tx.KERNEL_TX_RESERVE_SELECTION_WAIT_SEMANTICS)
    for entry in wait["entries"]:
        entry.update(schema_version=2, preparation_deadline_tai_ns=entry["release_tai_ns"])
    return raw


def wakeups(raw):
    value = selection._wakeups(raw)
    value.update(schema_version=21, semantics=fidelity.RUNNER_WAKEUP_V21_SEMANTICS)
    return value


def native_run(raw):
    value = selection._run(raw)
    value["runner_wakeup_metrics"] = wakeups(raw)
    value[policy.FIELD]["policy"] = policy.ACK_START_POLICY
    value[policy.BUFLO_KERNEL_PREPARATION_FIELD] = marker()
    value["resolved_configuration"]["control_interval_us"] = 5_000
    value["buflo_summary"]["incoming_startup"] = startup()
    value["defense_diagnostics"]["buflo_incoming_startup"] = startup()
    return value


def rolling_wait(offset=1_500_000):
    raw, wait, jobs = selection._rolling_wait()
    wait.update(schema_version=3, semantics=kernel_tx.KERNEL_TX_RESERVE_SELECTION_WAIT_SEMANTICS)
    for entry in wait["entries"]:
        entry.update(schema_version=2, preparation_deadline_tai_ns=
            entry["release_tai_ns"] + (0 if entry["tick_zero"] else 4_000_000))
    entry = wait["entries"][1]
    entered = entry["release_tai_ns"] + offset
    entry.update(entered_tai_ns=entered, completed_tai_ns=entered,
        dispatch_confirmed_tai_ns=entered + 100_000,
        entry_lateness_ns=entered - entry["admission_tai_ns"])
    selection._refresh_wait(wait)
    return raw, wait, jobs


def valid_wait(raw, wait, jobs, *, success=True):
    return kernel_tx._protected_selection_wait_v3_valid(wait,
        defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs, success=success)


def test_public_opt_in_derives_only_the_explicit_field_and_keeps_full_graph():
    original = prepared()
    validate_manifest(original)
    before = copy.deepcopy(original)
    changed = policy.apply_buflo_kernel_preparation_policy(original,
        policy=policy.BUFLO_KERNEL_PREPARATION_POLICY)
    assert original == before
    assert changed["resources"] == before["resources"]
    assert policy.validate_buflo_kernel_preparation_policy(changed["preparation"]) == marker()["policy"]
    validate_manifest(changed)
    changed["preparation"].pop(policy.BUFLO_KERNEL_PREPARATION_FIELD)
    assert changed == original
    changed["resources"][0]["headers"].append(["x-new", "new"])
    assert original == before  # No shared graph or header mutation.


@pytest.mark.parametrize("mutation", ["unknown", "null", "legacy-incoming", "missing-chaff", "missing-graph", "already-opted", "truncated-graph"])
def test_opt_in_rejects_unbound_contract_or_graph_mutation(mutation):
    value = prepared()
    selected = policy.BUFLO_KERNEL_PREPARATION_POLICY
    if mutation == "unknown": selected = "future"
    elif mutation == "null": selected = None
    elif mutation == "legacy-incoming": value["preparation"][policy.FIELD] = policy.POLICY
    elif mutation == "missing-chaff": value["preparation"].pop("qualified_chaff_origin_policy")
    elif mutation == "missing-graph": value["resources"] = []
    elif mutation == "already-opted": value["preparation"][policy.BUFLO_KERNEL_PREPARATION_FIELD] = selected
    else: value["resources"].pop()
    with pytest.raises(ValueError):
        policy.apply_buflo_kernel_preparation_policy(value, policy=selected)


def test_current_raw_outer_physical_and_scheduler_receipts_still_reopen():
    raw = raw_receipt()
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    assert fidelity._runner_wakeup_metrics_valid(wakeups(raw))
    assert capture_session._runner_wakeup_metrics_valid(wakeups(raw))
    evidence, capture, packets = fixtures._evidence(raw, capture_times=[
        fixtures._RELEASE_TAI_NS + 3_400_000, fixtures._RELEASE_TAI_NS + 6_200_000])
    assert kernel_tx.kernel_tx_evidence_success_valid(evidence,
        runner_receipt=raw, **fixtures._evidence_arguments(capture, packets))
    run = native_run(raw)
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    assert capture_session._process_scheduler_bound_to_run_valid(run,
        expected_contract=run["process_scheduler"]["contract"])
    source = policy.apply_buflo_kernel_preparation_policy(prepared(),
        policy=policy.BUFLO_KERNEL_PREPARATION_POLICY)
    policy.validate_buflo_kernel_preparation_source_binding(source, run)


@pytest.mark.parametrize("offset", [-5_000_000, 0, 1_500_000, 3_899_999])
def test_rolling_measured_preparation_before_four_ms_has_no_full_dwell_claim(offset):
    raw, wait, jobs = rolling_wait(offset)
    assert valid_wait(raw, wait, jobs)
    entry = wait["entries"][1]
    assert entry["completed_tai_ns"] == entry["entered_tai_ns"]
    assert entry["wait_duration_ns"] == entry["max_sample_gap_ns"] == 0
    assert entry["clock_read_attempts"] == 2  # Initial read plus fresh confirmation.
    assert jobs[1]["deadline_tai_ns"] - jobs[1]["release_tai_ns"] == 5_000_000


@pytest.mark.parametrize("mutation", ["entry-boundary", "confirmation-boundary", "tick-zero", "reserve", "release", "wait", "reads", "old-entry", "old-wait", "omission", "bool-slot", "bool-tick"])
def test_preparation_cutoff_tick_zero_counts_and_original_window_stay_strict(mutation):
    raw, wait, jobs = rolling_wait()
    entry = wait["entries"][1]
    if mutation == "entry-boundary":
        entry.update(entered_tai_ns=entry["preparation_deadline_tai_ns"],
            completed_tai_ns=entry["preparation_deadline_tai_ns"],
            dispatch_confirmed_tai_ns=entry["preparation_deadline_tai_ns"])
        entry["entry_lateness_ns"] = entry["entered_tai_ns"] - entry["admission_tai_ns"]
    elif mutation == "confirmation-boundary": entry["dispatch_confirmed_tai_ns"] = entry["preparation_deadline_tai_ns"]
    elif mutation == "tick-zero": wait["entries"][0]["preparation_deadline_tai_ns"] += 4_000_000
    elif mutation == "reserve": entry["preparation_deadline_tai_ns"] += 1
    elif mutation == "release": jobs[1]["deadline_tai_ns"] += 1
    elif mutation == "wait": entry["wait_duration_ns"] = 1
    elif mutation == "reads": entry["clock_read_attempts"] += 1
    elif mutation == "old-entry": entry["schema_version"] = 1
    elif mutation == "old-wait": wait["semantics"] = kernel_tx.KERNEL_TX_PROTECTED_SELECTION_WAIT_V2_SEMANTICS
    elif mutation == "bool-slot": wait["entries"][0]["slot"] = False
    elif mutation == "bool-tick": entry["tick"] = True
    else: wait["entries"].pop(0)
    selection._refresh_wait(wait)
    assert not valid_wait(raw, wait, jobs)


def test_true_expiry_retains_typed_failure_and_never_counts_as_success():
    raw, wait, jobs = rolling_wait()
    entry = wait["entries"][1]
    entry.update(outcome="failed", dispatch_confirmed_tai_ns=None)
    entry["failure"] = {"schema_version": 2, "slot": 2, "tick": 1, "tick_zero": False,
        "kind": "selection-expired", "detail": "fresh confirmation reached its recorded cutoff",
        **{key: entry[key] for key in ("admission_tai_ns", "selection_tai_ns", "release_tai_ns",
            "preparation_deadline_tai_ns", "entered_tai_ns")},
        "previous_tai_ns": entry["completed_tai_ns"],
        "observed_tai_ns": entry["preparation_deadline_tai_ns"], "clock_read_attempts": 2}
    selection._refresh_wait(wait)
    assert valid_wait(raw, wait, jobs[:1], success=False)
    assert not valid_wait(raw, wait, jobs[:1])
    original_tick = entry["failure"]["tick"]
    entry["failure"]["tick"] = True
    selection._refresh_wait(wait)
    assert not valid_wait(raw, wait, jobs[:1], success=False)
    entry["failure"]["tick"] = original_tick
    entry["failure"]["observed_tai_ns"] -= 1
    selection._refresh_wait(wait)
    assert not valid_wait(raw, wait, jobs[:1], success=False)


@pytest.mark.parametrize("role,offset", [("outgoing", 5_000_000), ("incoming", 10_000_000)])
def test_actual_tx_and_post_veth_at_original_role_deadlines_are_rejected(role, offset):
    raw = raw_receipt()
    index = 0 if role == "outgoing" else 1
    item = raw["jobs"][0]["items"][index]
    incoming._set_item_times(item, enqueue_offset_ns=3_000_000 if index == 0 else 6_000_000,
        tx_offset_ns=offset)
    raw["aggregate"]["max_tx_software_lateness_ns"] = max(offset, 6_100_000)
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    raw = raw_receipt()
    times = [fixtures._RELEASE_TAI_NS + 3_400_000, fixtures._RELEASE_TAI_NS + 6_200_000]
    times[index] = fixtures._RELEASE_TAI_NS + offset
    evidence, capture, packets = fixtures._evidence(raw, capture_times=times)
    assert not kernel_tx.kernel_tx_evidence_success_valid(evidence,
        runner_receipt=raw, **fixtures._evidence_arguments(capture, packets))


@pytest.mark.parametrize("mutation", ["source-absent", "null", "wrong-policy", "wrong-ack", "marker-absent", "typed-marker", "marker-cap", "raw-marker", "old-raw", "other-mode"])
def test_prepared_native_raw_binding_rejects_missing_forged_or_prior_source(mutation):
    source = policy.apply_buflo_kernel_preparation_policy(prepared(), policy=policy.BUFLO_KERNEL_PREPARATION_POLICY)
    run = native_run(raw_receipt())
    if mutation == "source-absent": source["preparation"].pop(policy.BUFLO_KERNEL_PREPARATION_FIELD)
    elif mutation == "null": source["preparation"][policy.BUFLO_KERNEL_PREPARATION_FIELD] = None
    elif mutation == "wrong-policy": source["preparation"][policy.BUFLO_KERNEL_PREPARATION_FIELD] = "future"
    elif mutation == "wrong-ack": run[policy.FIELD]["policy"] = policy.POLICY
    elif mutation == "marker-absent": run.pop(policy.BUFLO_KERNEL_PREPARATION_FIELD)
    elif mutation == "typed-marker": run[policy.BUFLO_KERNEL_PREPARATION_FIELD]["period_us"] = 20_000.0
    elif mutation == "marker-cap": run[policy.BUFLO_KERNEL_PREPARATION_FIELD]["allow_omissions"] = True
    elif mutation == "raw-marker": run["runner_wakeup_metrics"]["buflo_kernel_tx"]["preparation_policy"]["preparation_reserve_us"] = 0
    elif mutation == "old-raw": run["runner_wakeup_metrics"] = selection._wakeups(selection._modern())
    else: run["resolved_configuration"]["defense"]["kind"] = "cs_buflo"
    with pytest.raises(ValueError):
        policy.validate_buflo_kernel_preparation_source_binding(source, run)


def test_historical_nine_ten_eleven_and_default_outer_twenty_are_unchanged():
    assert kernel_tx.KERNEL_TX_RUNNER_SCHEMA_VERSION == 11
    for raw in (fixtures._runner_receipt_v9(), selection._historical_ten(), selection._modern()):
        assert "preparation_policy" not in raw
        assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    assert fidelity._runner_wakeup_metrics_valid(selection._wakeups(selection._modern()))
    raw, wait, jobs = rolling_wait()
    wait.update(schema_version=2, semantics=kernel_tx.KERNEL_TX_PROTECTED_SELECTION_WAIT_V2_SEMANTICS)
    for entry in wait["entries"]:
        entry.update(schema_version=1)
        entry.pop("preparation_deadline_tai_ns")
    assert not kernel_tx._protected_selection_wait_v2_valid(wait,
        defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs, success=True)
    assert policy.validate_buflo_kernel_preparation_policy({}) is None
    policy.validate_buflo_kernel_preparation_source_binding({}, {})


def test_new_handoff_and_accepted_results_still_require_actual_wire_and_scheduler(tmp_path):
    run = native_run(raw_receipt())
    required, raw = buflo_handoff._runner_kernel_tx_requirement(run, runtime_kind="buflo")
    assert required and raw is run["runner_wakeup_metrics"]["buflo_kernel_tx"]
    sample = {**_sample(), "state": "accepted", "defense": "buflo", "runtime_kind": "buflo", "baseline": False}
    run["terminal_evidence_render_errors"] = []
    atomic_json(tmp_path / sample["path"] / "neqo/run.json", run)
    with pytest.raises(ValueError, match="lacks its evidence sidecar"):
        experiment.validate_accepted_kernel_tx_evidence(tmp_path, sample)
    with pytest.raises(ValueError, match="lacks its scheduler runtime receipt"):
        experiment.validate_accepted_scheduler_runtime_receipt(tmp_path,
            {"configuration": {"evidence_role": "formal"}}, sample)
    sample.update(defense="cs-buflo", runtime_kind="cs_buflo")
    with pytest.raises(ValueError, match="CS-BuFLO sample requires runner-wakeup schema 10"):
        experiment.validate_accepted_scheduler_runtime_receipt(tmp_path,
            {"configuration": {"evidence_role": "formal"}}, sample)


def test_exact_held_native_constants_and_marker_match_new_consumer():
    # Root provides the independently held producer, never a stale editable
    # Main import or the uninitialized authoring submodule.
    native_path = Path(os.environ["QCSD_LAB_TEST_RESERVE_NATIVE_SOURCE"])
    raw = native_path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == os.environ["QCSD_LAB_TEST_RESERVE_NATIVE_SHA256"]
    text = raw.decode()
    pairs = {
        "BUFLO_KERNEL_RESERVE_TX_SEMANTICS": kernel_tx.KERNEL_TX_RESERVE_TX_SEMANTICS,
        "BUFLO_KERNEL_RESERVE_SELECTION_WAIT_SEMANTICS": kernel_tx.KERNEL_TX_RESERVE_SELECTION_WAIT_SEMANTICS,
        "BUFLO_KERNEL_RESERVE_PREBUILD_SELECTION_SEMANTICS": kernel_tx.KERNEL_TX_RESERVE_PREBUILD_SELECTION_SEMANTICS,
    }
    for name, expected in pairs.items():
        match = re.search(r"const " + name + r': &str = "([^"]*)";', text)
        assert match and match.group(1) == expected
    retention = re.search(r'const BUFLO_KERNEL_RESERVE_RUNNER_RETENTION_SEMANTICS: &str = "([^"]*)";', text)
    assert retention and retention.group(1) + "; " in fidelity.RUNNER_WAKEUP_V21_SEMANTICS
    assert '"' + marker()["policy"] + '"' in text
    assert "truthful_main_construction_lateness_us_lt_5000=true" in kernel_tx.KERNEL_TX_RESERVE_TX_SEMANTICS
