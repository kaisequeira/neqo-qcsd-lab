"""Finite prospective64/640 reader controls; synthetic fixtures grant no capture credit."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import buflo_duration_budget as budget, buflo_handoff as handoff
from qcsd_lab import capture_acceptance_policy as policy, capture_session, experiment, fidelity, kernel_tx
from qcsd_lab.util import atomic_json
from tests import test_kernel_tx as wire
from tests import test_kernel_tx_incoming_window as incoming
from tests import test_kernel_tx_late_selection as selection
from tests import test_kernel_tx_preparation_reserve as legacy
from tests import test_capture_buflo_ack_start as ack
from tests.test_experiment import _sample
from tests.test_buflo_handoff import _complete_buflo_run

INCOMING = "rapid-v7-half-period-32000us-ack-start-v1"
PREPARATION = "rapid-v7-buflo-cadence64ms-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1"
DURATION = "rapid-v7-fixed-64ms-640s-duration-budget-v1"
PARAMETERS = {"schema_version": 1, "interval_us": 64_000, "minimum_duration_us": 10_000_000,
    "packet_size": 1_200, "max_events": 10_000, "implementation_scope": "client_only_quic",
    "paper_equivalent": False, "duration_budget_policy": DURATION}
RECEIPT = {"schema_version": 1, "policy": DURATION, "interval_us": 64_000,
    "minimum_duration_us": 10_000_000, "packet_size": 1_200, "max_events": 10_000,
    "duration_budget_us": 640_000_000}
RAW_PARAMETERS = (json.dumps(PARAMETERS, indent=2) + "\n").encode()


def marker():
    value = legacy.marker()
    value.update(policy=PREPARATION, period_us=64_000)
    return value


def raw_receipt():
    value = legacy.raw_receipt()
    value.update(schema_version=13, semantics=kernel_tx.KERNEL_TX_CADENCE64_TX_SEMANTICS,
        incoming_credit_release_window_ns=32_000_000, preparation_policy=marker())
    for job in value["jobs"]:
        job.update(incoming_deadline_monotonic_ns=job["release_monotonic_ns"] + 32_000_000,
            incoming_deadline_tai_ns=job["release_tai_ns"] + 32_000_000)
    value["protected_selection_wait"].update(schema_version=4,
        semantics=kernel_tx.KERNEL_TX_CADENCE64_SELECTION_WAIT_SEMANTICS)
    return value


def native_run(raw=None):
    # Structural fixture, not a newly measured Native run or completed capture.
    raw = raw or raw_receipt()
    # The historical builder declares the rapid contract only for its exact10ms
    # incoming raw receipt. Use that unchanged run shape, then bind the actual
    # prospective raw receipt and its scheduler; never relabel32ms raw as10ms.
    run = legacy.native_run(legacy.raw_receipt())
    run["runner_wakeup_metrics"] = legacy.wakeups(raw)
    run["process_scheduler"] = deepcopy(raw["runtime_contract"]["scheduler_initial"])
    run["runner_wakeup_metrics"].update(schema_version=22, semantics=fidelity.RUNNER_WAKEUP_V22_SEMANTICS)
    run.update(method="GET")
    run[policy.FIELD].update(policy=INCOMING, period_us=64_000, incoming_release_window_us=32_000)
    run[policy.BUFLO_KERNEL_PREPARATION_FIELD] = marker()
    path = "/prospective/config/buflo-cadence64-budget640.json"
    run["defense_parameters"].update(path=path, sha256=hashlib.sha256(RAW_PARAMETERS).hexdigest(),
        implementation_scope="client_only_quic", paper_equivalent=False, buflo_duration_budget=deepcopy(RECEIPT))
    run["resolved_configuration"]["defense"].update(parameters=path)
    dto = ack.startup()
    dto.update(period_us=64_000, armed_at_us=64_000, startup_suppressed_opportunities=1)
    run["buflo_summary"]["incoming_startup"] = dto
    run["defense_diagnostics"]["buflo_incoming_startup"] = deepcopy(dto)
    return run


def source():
    value = legacy.prepared()
    value["preparation"].update(buflo_incoming_credit_release_policy=INCOMING,
        buflo_kernel_preparation_policy=PREPARATION)
    return value


def test_exact_policy_native_provenance_and_old_hashes():
    assert budget.CADENCE64_PARAMETERS == PARAMETERS
    assert budget.CADENCE64_RECEIPT == RECEIPT
    assert budget.cadence64_parameter_bytes() == RAW_PARAMETERS
    assert budget.CADENCE64_PARAMETER_SHA256 == "5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e"
    assert hashlib.sha256(budget.parameter_bytes()).hexdigest() == "1c6043157fe9548d426682ab36af33a6da21ba7bbdecc5eb808bee7996691242"
    assert hashlib.sha256(kernel_tx.KERNEL_TX_RESERVE_TX_SEMANTICS.encode()).hexdigest() == "852f3967e369ebd3b9df594b46d74fe05b646a63e4b032e4d65367bcdbb0aa6b"
    assert hashlib.sha256(kernel_tx.KERNEL_TX_RESERVE_SELECTION_WAIT_SEMANTICS.encode()).hexdigest() == "07d229d9828d8f23ce3f9f56548f93f6e4ab90446e1688929a05eceaa167e772"
    run = native_run()
    joined = budget.validate_native_receipt(run, RAW_PARAMETERS)
    assert budget.schedule_bounds(joined) == (10_000, 640_000_000)
    original = {"timeout_seconds": 120, "capture_seconds": 180}
    assert budget.capture_limits("buflo", original, policy=DURATION) == {"timeout_seconds": 680, "capture_seconds": 740}
    assert budget.capture_limits("buflo", original, policy=budget.POLICY) == {"timeout_seconds": 240, "capture_seconds": 300}
    for mode in ("none", "front", "tamaraw", "cs_buflo"):
        assert budget.capture_limits(mode, original, policy=DURATION) == original


@pytest.mark.parametrize("field,value", [
    ("interval_us", 20_000), ("interval_us", 64_000.0), ("max_events", 3_125),
    ("max_events", True), ("minimum_duration_us", 10_000_001), ("packet_size", 1_199),
    ("paper_equivalent", True), ("duration_budget_policy", budget.POLICY),
])
def test_parameters_cannot_mix_a_legacy_or_custom_tuple(field, value):
    changed = {**PARAMETERS, field: value}
    with pytest.raises(ValueError):
        budget.parse_parameters((json.dumps(changed) + "\n").encode())


@pytest.mark.parametrize("mutation", ["hash", "path", "old-receipt", "scope", "method", "extra-receipt"])
def test_native_parameter_provenance_cannot_be_substituted(mutation):
    run = native_run()
    if mutation == "hash": run["defense_parameters"]["sha256"] = "0" * 64
    elif mutation == "path": run["resolved_configuration"]["defense"]["parameters"] = "/other"
    elif mutation == "old-receipt": run["defense_parameters"][budget.RUN_FIELD] = deepcopy(budget.RECEIPT)
    elif mutation == "scope": run["defense_parameters"]["implementation_scope"] = "bilateral"
    elif mutation == "method": run["method"] = "HEAD"
    else: run["defense_parameters"][budget.RUN_FIELD]["allow_omissions"] = True
    with pytest.raises(ValueError):
        budget.validate_native_receipt(run, RAW_PARAMETERS)


def test_raw_wakeup_source_and_independent_pcap_joins_are_required():
    raw = raw_receipt()
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    run = native_run(raw)
    assert fidelity._runner_wakeup_metrics_valid(run["runner_wakeup_metrics"])
    assert capture_session._runner_wakeup_metrics_valid(run["runner_wakeup_metrics"])
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    policy.validate_buflo_kernel_preparation_source_binding(source(), run)
    required, retained = handoff._runner_kernel_tx_requirement(run, runtime_kind="buflo")
    assert required and retained is raw
    evidence, capture, packets = wire._evidence(raw, capture_times=[
        wire._RELEASE_TAI_NS + 3_400_000, wire._RELEASE_TAI_NS + 6_200_000])
    assert kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))
    evidence["runner_kernel_tx_sha256"] = "0" * 64
    assert not kernel_tx.kernel_tx_evidence_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))


@pytest.mark.parametrize("mutation", ["old-kernel", "old-wakeup", "old-wait", "period", "prep", "incoming", "budget", "hash", "path", "method", "outgoing-mode"])
def test_new_source_cannot_accept_mixed_native_versions_or_markers(mutation):
    run = native_run()
    raw = run["runner_wakeup_metrics"]["buflo_kernel_tx"]
    if mutation == "old-kernel": raw["schema_version"] = 12
    elif mutation == "old-wakeup": run["runner_wakeup_metrics"]["schema_version"] = 21
    elif mutation == "old-wait": raw["protected_selection_wait"]["schema_version"] = 3
    elif mutation == "period": raw["preparation_policy"]["period_us"] = 20_000
    elif mutation == "prep": run[policy.BUFLO_KERNEL_PREPARATION_FIELD]["policy"] = policy.BUFLO_KERNEL_PREPARATION_POLICY
    elif mutation == "incoming": run[policy.FIELD]["policy"] = policy.ACK_START_POLICY
    elif mutation == "budget": run["defense_parameters"][budget.RUN_FIELD] = deepcopy(budget.RECEIPT)
    elif mutation == "hash": run["defense_parameters"]["sha256"] = "0" * 64
    elif mutation == "path": run["resolved_configuration"]["defense"]["parameters"] = "/different"
    elif mutation == "method": run["method"] = "HEAD"
    else: run["resolved_configuration"]["defense"]["kind"] = "cs_buflo"
    with pytest.raises(ValueError):
        handoff._runner_kernel_tx_requirement(run, runtime_kind="buflo")
    assert not capture_session._process_scheduler_bound_to_run_valid(run,
        expected_contract=run["process_scheduler"]["contract"])


@pytest.mark.parametrize("role,offset", [("incoming", 32_000_000), ("incoming", 32_000_001), ("outgoing", 5_000_000)])
def test_raw_and_post_veth_physical_deadlines_remain_half_open(role, offset):
    raw = raw_receipt()
    index = 1 if role == "incoming" else 0
    incoming._set_item_times(raw["jobs"][0]["items"][index],
        enqueue_offset_ns=6_000_000 if index else 3_000_000, tx_offset_ns=offset)
    raw["aggregate"]["max_tx_software_lateness_ns"] = max(offset, 6_100_000)
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    raw = raw_receipt()
    times = [wire._RELEASE_TAI_NS + 3_400_000, wire._RELEASE_TAI_NS + 6_200_000]
    times[index] = wire._RELEASE_TAI_NS + offset
    evidence, capture, packets = wire._evidence(raw, capture_times=times)
    assert not kernel_tx.kernel_tx_evidence_success_valid(evidence, runner_receipt=raw,
        **wire._evidence_arguments(capture, packets))


def test_observed_service_delay_is_a_new_bound_only_and_credit_owner_is_still_exact():
    raw = raw_receipt()
    incoming._set_item_times(raw["jobs"][0]["items"][1],
        enqueue_offset_ns=21_800_000, tx_offset_ns=21_858_679)
    raw["aggregate"]["max_tx_software_lateness_ns"] = 21_858_679
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    # The same physical carrier cannot be promoted through historical10ms receipts.
    old = legacy.raw_receipt()
    old["jobs"][0]["items"][1] = deepcopy(raw["jobs"][0]["items"][1])
    old["aggregate"]["max_tx_software_lateness_ns"] = 21_858_679
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(old)
    for mutation in ("owner", "duplicate", "unresolved"):
        changed = deepcopy(raw)
        identities = changed["jobs"][0]["credit_identities"]
        if mutation == "owner": identities[0]["endpoint_index"] += 1
        elif mutation == "duplicate": identities.append(deepcopy(identities[0]))
        else: identities[0].update(resolution="pending", carrier_item_id=None)
        assert not kernel_tx.kernel_tx_runner_receipt_success_valid(changed)


def test_two_protected_ticks_use64ms_without_changing_four_ms_preparation():
    raw, wait, jobs = legacy.rolling_wait()
    wait.update(schema_version=4, semantics=kernel_tx.KERNEL_TX_CADENCE64_SELECTION_WAIT_SEMANTICS)
    entry = wait["entries"][1]
    for key in ("admission_tai_ns", "selection_tai_ns", "release_tai_ns", "preparation_deadline_tai_ns",
                "entered_tai_ns", "completed_tai_ns", "dispatch_confirmed_tai_ns"):
        entry[key] += 44_000_000
    jobs[1] = {key: value + 44_000_000 for key, value in jobs[1].items()}
    selection._refresh_wait(wait)
    valid = lambda value: kernel_tx._protected_selection_wait_v4_valid(value,
        defense_start_tai_ns=raw["defense_start_tai_ns"], jobs=jobs, success=True)
    assert valid(wait)
    for key in ("release_tai_ns", "preparation_deadline_tai_ns", "dispatch_confirmed_tai_ns"):
        changed = deepcopy(wait)
        if key == "dispatch_confirmed_tai_ns":
            changed["entries"][1][key] = changed["entries"][1]["preparation_deadline_tai_ns"]
        else: changed["entries"][1][key] += 1
        selection._refresh_wait(changed)
        assert not valid(changed)


def test_full_event_budget_does_not_drop_tail_or_use20ms_grid():
    startup = native_run()["buflo_summary"]["incoming_startup"]
    targets = list(range(0, 640_000_000, 64_000))
    schedule = {"target_times_us_by_direction": {"outgoing": targets, "incoming": targets[1:]},
        "scheduled_sizes_by_direction": {"outgoing": [1_200] * 10_000, "incoming": [1_200] * 9_999},
        "terminal_satisfactions": {"satisfied": 19_999}, budget.RUN_FIELD: deepcopy(RECEIPT),
        "buflo_duration_budget_parameter_sha256": hashlib.sha256(RAW_PARAMETERS).hexdigest(),
        "incoming_credit_release_policy": native_run()[policy.FIELD], "incoming_credit_release_window_us": 32_000,
        "incoming_credit_release_original_5000us_violations": 0,
        "buflo_incoming_startup": startup, "buflo_incoming_startup_events_sha256": "a" * 64}
    assert fidelity._buflo_schedule_matches_canonical_parameters(schedule)
    changed = deepcopy(schedule)
    changed["target_times_us_by_direction"]["incoming"].pop()
    changed["scheduled_sizes_by_direction"]["incoming"].pop()
    changed["terminal_satisfactions"]["satisfied"] -= 1
    assert not fidelity._buflo_schedule_matches_canonical_parameters(changed)
    changed = deepcopy(schedule)
    changed["target_times_us_by_direction"]["outgoing"][1] = 20_000
    assert not fidelity._buflo_schedule_matches_canonical_parameters(changed)


@pytest.mark.parametrize('ready_at_us', [22_000, 154_000])
def test_canonical_ack_csv_reopens_real_sequences_at64ms(tmp_path, ready_at_us):
    ack_observed_at_us = ready_at_us - 1_000
    run, events, _ = ack.fixture(tmp_path, ready_at_us=ready_at_us,
        ack_observed_at_us=ack_observed_at_us, acknowledgments=[
            (100, 85, True, ack_observed_at_us - 1_000),
            (0, 100, False, ack_observed_at_us)])
    updated = native_run()
    run.update({key: updated[key] for key in ("method", "defense_parameters", "runner_wakeup_metrics", policy.FIELD,
        policy.BUFLO_KERNEL_PREPARATION_FIELD)})
    run["resolved_configuration"]["defense"].update(updated["resolved_configuration"]["defense"])
    dto = updated["buflo_summary"]["incoming_startup"]
    dto.update(ready_at_us=ready_at_us, ack_observed_at_us=ack_observed_at_us,
        armed_at_us=(ready_at_us // 64_000 + 1) * 64_000,
        startup_suppressed_opportunities=ready_at_us // 64_000 + 1)
    run["buflo_summary"]["incoming_startup"] = dto
    run["defense_diagnostics"]["buflo_incoming_startup"] = deepcopy(dto)
    for event in events:
        if event["event"] == "buflo_incoming_startup_ready":
            event["details"] = json.dumps(dto)
    rows = [{"direction": direction, "target_time_us": str(target), "size": "1200"}
        for target in range(0, 10_048_001, 64_000) for direction in ("outgoing", "incoming")
        if direction != "incoming" or target >= dto["armed_at_us"]]
    ack.write_csv(tmp_path / "events.csv", ("monotonic_us", "connection", "event", "outcome", "details"), events)
    assert policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path, schedule_rows=rows) == dto
    # Original production ACK/FIN coverage cannot be replaced by a summary.
    events.pop(next(index for index, row in enumerate(events) if row["event"] == "observation" and "acknowledged" in row["details"]))
    ack.write_csv(tmp_path / "events.csv", ("monotonic_us", "connection", "event", "outcome", "details"), events)
    with pytest.raises(ValueError):
        policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path, schedule_rows=rows)


@pytest.mark.parametrize('ready_at_us', [22_000, 64_000, 154_000])
def test_cadence64_startup_count_uses_exact_grid_including_delayed_ack(ready_at_us):
    dto = ack.startup()
    armed = (ready_at_us // 64_000 + 1) * 64_000
    dto.update(period_us=64_000, ready_at_us=ready_at_us, ack_observed_at_us=ready_at_us - 1_000,
        armed_at_us=armed, startup_suppressed_opportunities=armed // 64_000)
    assert policy.validate_buflo_startup_receipt(dto, period_us=64_000) == dto
    changed = deepcopy(dto)
    changed['startup_suppressed_opportunities'] = armed // 20_000
    with pytest.raises(ValueError, match='cadence barrier'):
        policy.validate_buflo_startup_receipt(changed, period_us=64_000)
    with pytest.raises(ValueError):
        policy.validate_buflo_startup_receipt(dto)
    assert policy.validate_buflo_startup_receipt(ack.startup()) == ack.startup()


def test_handoff_cadence_diagnostics_join_exact_native64_and_keep20_default():
    run = native_run()
    assert handoff._buflo_diagnostic_period_us(run, runtime_kind="buflo") == 64_000
    assert handoff._buflo_diagnostic_period_us(legacy.native_run(legacy.raw_receipt()), runtime_kind="buflo") == 20_000
    rows = []
    for target in (0, 64_000, 128_000):
        row = {field: "" for field in fidelity.SCHEDULE_PREFIX_FIELDS + fidelity.SCHEDULE_QCSD_FIELDS}
        row.update(direction="outgoing", target_time_us=str(target), size="1200", satisfaction="satisfied")
        rows.append(row)
    new = handoff._direction_algorithm_metrics(rows, direction="outgoing", runtime_kind="buflo", buflo_period_us=64_000)
    old = handoff._direction_algorithm_metrics(rows, direction="outgoing", runtime_kind="buflo")
    assert new["estimated_jitter_from_nearest_nominal_us"]["maximum"] == 0
    assert old["estimated_jitter_from_nearest_nominal_us"]["maximum"] == 44_000
    changed = deepcopy(run)
    changed["defense_parameters"]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        handoff._buflo_diagnostic_period_us(changed, runtime_kind="buflo")
    with pytest.raises(ValueError):
        handoff._direction_algorithm_metrics(rows, direction="outgoing", runtime_kind="cs_buflo", buflo_period_us=64_000)


def test_accepted_scheduler_cannot_fall_back_before_independent_sidecar(tmp_path):
    sample = {**_sample(), "state": "accepted", "defense": "buflo", "runtime_kind": "buflo", "baseline": False}
    run = native_run()
    run["terminal_evidence_render_errors"] = []
    atomic_json(tmp_path / sample["path"] / "neqo/run.json", run)
    with pytest.raises(ValueError, match="lacks its scheduler runtime receipt"):
        experiment.validate_accepted_scheduler_runtime_receipt(tmp_path, {"configuration": {"evidence_role": "formal"}}, sample)
    run["defense_parameters"][budget.RUN_FIELD] = deepcopy(budget.RECEIPT)
    atomic_json(tmp_path / sample["path"] / "neqo/run.json", run)
    with pytest.raises(ValueError, match="exact64ms"):
        experiment.validate_accepted_scheduler_runtime_receipt(tmp_path, {"configuration": {"evidence_role": "formal"}}, sample)


@pytest.mark.parametrize('mutation', [None, 'parameters', 'pairing', 'pcap-bytes', 'missing-evidence'])
def test_accepted_kernel_sidecar_reopens_exact64_native_raw_and_physical_evidence(tmp_path, monkeypatch, mutation):
    from qcsd_lab import kernel_tx_runtime
    sample = {**_sample(), 'state': 'accepted', 'defense': 'buflo', 'runtime_kind': 'buflo', 'baseline': False}
    run = native_run()
    run['terminal_evidence_render_errors'] = []
    run_path = tmp_path / sample['path'] / 'neqo/run.json'
    atomic_json(run_path, run)
    raw = run['runner_wakeup_metrics']['buflo_kernel_tx']
    evidence, capture, packets = wire._evidence(raw, capture_times=[
        wire._RELEASE_TAI_NS + 3_400_000, wire._RELEASE_TAI_NS + 6_200_000])
    sidecar = tmp_path / experiment.KERNEL_TX_EVIDENCE_DIRECTORY / sample['sample_id']
    sidecar.mkdir(parents=True)
    # Packet decoding is an explicit structural-fixture boundary. Every sealed
    # file hash, Native policy/raw join, owner, timestamp and pcap reconciliation
    # validator executes; these bytes never claim an actual capture.
    pcap = sidecar / 'router-capture.pcapng'
    pcap.write_bytes(b'controlled router packet decoding boundary')
    capture['pcapng_sha256'] = hashlib.sha256(pcap.read_bytes()).hexdigest()
    evidence.update(runner_run_json_sha256=hashlib.sha256(run_path.read_bytes()).hexdigest(),
        post_veth_capture=deepcopy(capture))
    atomic_json(sidecar / 'router-receipt.json', capture)
    atomic_json(sidecar / 'kernel-tx-evidence.json', evidence)
    sample['diagnostics'] = {experiment.KERNEL_TX_EVIDENCE_RECEIPT_KEY: {
        'schema_version': experiment.KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION,
        'source': experiment.KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
        'directory': sidecar.relative_to(tmp_path).as_posix(),
        'artifacts': {name: hashlib.sha256((sidecar / name).read_bytes()).hexdigest()
            for name in experiment.KERNEL_TX_EVIDENCE_FILES}}}
    monkeypatch.setattr(kernel_tx_runtime, 'extract_router_udp_packets', lambda path: packets)
    if mutation == 'parameters':
        run['defense_parameters'][budget.RUN_FIELD] = deepcopy(budget.RECEIPT)
        atomic_json(run_path, run)
    elif mutation == 'pairing':
        run['runner_wakeup_metrics']['buflo_kernel_tx'] = legacy.raw_receipt()
        atomic_json(run_path, run)
    elif mutation == 'pcap-bytes':
        pcap.write_bytes(pcap.read_bytes() + b'changed')
    elif mutation == 'missing-evidence':
        (sidecar / 'kernel-tx-evidence.json').unlink()
    if mutation is None:
        experiment.validate_accepted_kernel_tx_evidence(tmp_path, sample)
    else:
        with pytest.raises(ValueError):
            experiment.validate_accepted_kernel_tx_evidence(tmp_path, sample)


def terminal_two_tick_raw():
    # Synthetic component ledger: the first incoming opportunity is suppressed;
    # tick one carries the first incoming credit after the 64ms startup barrier.
    # These two ticks grant no whole-run cadence, capture or scientific credit.
    raw = raw_receipt()
    first = raw["jobs"][0]
    second = deepcopy(first)
    shift_ns = 64_000_000
    for key, value in second.items():
        if key.endswith("_ns") and type(value) is int:
            second[key] = value + shift_ns
    second.update(job_id=1, tick=1)
    second["helper_job_close"]["job_id"] = 1
    for item_id, item in enumerate(second["items"], 1):
        for key, value in item.items():
            if key.endswith("_ns") and type(value) is int:
                item[key] = value + shift_ns
        for sample in item["post_tx_clock_phase"].values():
            for key in ("tai_before_ns", "tai_after_ns", "clock_ns"):
                sample[key] += shift_ns
        item.update(item_id=item_id, job_id=1, event_id=2 + item["order_index"],
            socket_timestamp_id=item_id + 10, datagram_sha256=f"{item_id + 1:064x}")
    second["credit_identities"][0].update(slot=3, carrier_item_id=2)
    first["items"] = first["items"][:1]
    first["credit_identities"] = []
    first["helper_job_close"]["unused_post_main_datagrams"] = 2
    raw["jobs"] = [first, second]

    # The original helper returns complete two-entry selection evidence and
    # separate minimal job DTOs. Bind the evidence to our full two-job ledger.
    _, wait, _ = legacy.rolling_wait()
    wait.update(schema_version=4, semantics=kernel_tx.KERNEL_TX_CADENCE64_SELECTION_WAIT_SEMANTICS)
    for key in ("admission_tai_ns", "selection_tai_ns", "release_tai_ns", "preparation_deadline_tai_ns",
                "entered_tai_ns", "completed_tai_ns", "dispatch_confirmed_tai_ns"):
        wait["entries"][1][key] += 44_000_000  # Existing 20ms second tick becomes 64ms.
    selection._refresh_wait(wait)
    raw["protected_selection_wait"] = wait
    raw["clock_mapping"].update(per_item_monotonic_evidence_count=3,
        per_item_realtime_evidence_count=3)
    lifecycle = raw["runtime_contract"]["helper_lifecycle"]
    lifecycle.update(completed_main_jobs=2, completed_immediate_datagrams=1, last_main_job_id=1)
    raw["runtime_contract"]["helper_shutdown"]["lifecycle"] = deepcopy(lifecycle)
    raw["aggregate"].update(job_count=2, item_count=3, etf_item_count=2, ordered_item_count=1,
        captured_credit_identity_count=1, carrier_credit_identity_count=1,
        transmitted_item_count=3, tx_sched_timestamp_count=3, tx_software_timestamp_count=3)
    return raw


@pytest.mark.parametrize('mutation', [None, 'period', 'summary-startup', 'parameter-receipt', 'raw-pairing',
    'raw-count', 'raw-grid', 'primary-policy', 'response-policy'])
def test_complete_terminal_summary_threads_source_bound64_startup(tmp_path, mutation):
    # A coherent synthetic two-tick terminal component, with one suppressed
    # incoming opportunity. Independent full-tail and physical joins are tested
    # elsewhere; this component establishes no scientific eligibility.
    original, events, _ = ack.fixture(tmp_path)
    raw = terminal_two_tick_raw()
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    run = _complete_buflo_run(scheduled_outgoing=2, scheduled_incoming=1, current_runner=False)
    updated = native_run(raw)
    run.update({key: updated[key] for key in ('method', 'resolved_configuration', 'defense_parameters',
        'runner_wakeup_metrics', 'process_scheduler', 'primary_document_identity_policy',
        'application_response_policy', policy.FIELD, policy.BUFLO_KERNEL_PREPARATION_FIELD)})
    run['defense_start_monotonic_ns'] = raw['defense_start_monotonic_ns']
    run['chaff_responses'] = original['chaff_responses']
    startup = deepcopy(updated['buflo_summary']['incoming_startup'])
    run['buflo_summary']['incoming_startup'] = startup
    run['defense_diagnostics']['buflo_incoming_startup'] = deepcopy(startup)
    assert fidelity._runner_wakeup_metrics_valid(run['runner_wakeup_metrics'])
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    assert capture_session._process_scheduler_bound_to_run_valid(run,
        expected_contract=run['process_scheduler']['contract'])
    clock_shift_ns = run['defense_start_monotonic_ns'] - original['defense_start_monotonic_ns']
    for event in events:
        event['monotonic_us'] = str(int(event['monotonic_us']) + clock_shift_ns // 1_000)
        details = json.loads(event['details'])
        if 'production_monotonic_ns' in details:
            details['production_monotonic_ns'] += clock_shift_ns
        if event['event'] == 'buflo_incoming_startup_ready':
            details = startup
        event['details'] = json.dumps(details)
    rows = [{'direction': direction, 'target_time_us': str(target), 'size': '1200'}
        for target in (0, 64_000) for direction in ('outgoing', 'incoming')
        if direction != 'incoming' or target >= startup['armed_at_us']]
    ack.write_csv(tmp_path / 'events.csv', ('monotonic_us', 'connection', 'event', 'outcome', 'details'), events)
    ack.write_csv(tmp_path / 'schedule.csv', ('direction', 'target_time_us', 'size'), rows)
    if mutation == 'period':
        run['defense_diagnostics']['buflo_incoming_startup']['period_us'] = 20_000
    elif mutation == 'summary-startup':
        run['buflo_summary']['incoming_startup']['armed_at_us'] += 64_000
    elif mutation == 'parameter-receipt':
        run['defense_parameters'][budget.RUN_FIELD] = deepcopy(budget.RECEIPT)
    elif mutation == 'raw-pairing':
        run['runner_wakeup_metrics']['buflo_kernel_tx'] = legacy.raw_receipt()
    elif mutation == 'raw-count':
        run['runner_wakeup_metrics']['buflo_kernel_tx']['aggregate']['job_count'] = 1
    elif mutation == 'raw-grid':
        run['runner_wakeup_metrics']['buflo_kernel_tx']['jobs'][1]['release_tai_ns'] += 1
    elif mutation == 'primary-policy':
        run.pop('primary_document_identity_policy')
    elif mutation == 'response-policy':
        run.pop('application_response_policy')
    valid = fidelity.new_defense_terminal_receipts_valid(run, 'buflo',
        require_application_complete=True, require_current_schema=True, runner_directory=tmp_path)
    assert valid is (mutation is None)
    if mutation is None:
        assert fidelity._diagnostics_match_contract('buflo', run['defense_diagnostics'], buflo_period_us=64_000)
        assert not fidelity._diagnostics_match_contract('buflo', run['defense_diagnostics'])
        assert fidelity.buflo_terminal_diagnostics_valid(run['defense_diagnostics'],
            require_current=True, incoming_startup=startup, buflo_period_us=64_000)
        assert not fidelity.buflo_terminal_diagnostics_valid(run['defense_diagnostics'],
            require_current=True, incoming_startup=startup)


def test_authentic_legacy_failed_raw_is_preserved_when_supplied():
    value = os.environ.get("QCSD_LAB_TEST_LEGACY_BUFLO_RUN_JSON")
    if not value:
        pytest.skip("authentic frozen Native818 failed run not supplied")
    path = Path(value)
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == os.environ["QCSD_LAB_TEST_LEGACY_BUFLO_RUN_SHA256"]
    assert format(path.stat().st_mode & 0o7777, "04o") == os.environ["QCSD_LAB_TEST_LEGACY_BUFLO_RUN_MODE"]
    run = json.loads(raw)
    receipt = run["runner_wakeup_metrics"]["buflo_kernel_tx"]
    assert receipt["schema_version"] == 12
    assert receipt["terminal_outcome"] == "failed"
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(receipt)
    assert run["defense_parameters"][budget.RUN_FIELD] == budget.RECEIPT
