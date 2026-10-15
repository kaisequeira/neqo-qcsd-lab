"""Strict local-abandonment metadata controls, with real CSV reader boundaries.

The inherited kernel and runner components are synthetic engineering fixtures.
No HTTP capture, Native qualification, admission or scientific credit is claimed.
ROOT alone executes these controls.
"""
from copy import deepcopy
import csv
import json

import pytest

from qcsd_lab import buflo_evaluation as evaluation
from qcsd_lab import buflo_handoff as handoff
from qcsd_lab import fidelity
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as compatibility
from tests.test_buflo_handoff import _complete_buflo_run


def proof():
    return {"endpoint": 0, "stream": 348, "resource_id": 19, "request_id": 0,
        "encoded_receive_limit": 1763, "manual_receive_limit": 1763, "consumed": 1763,
        "retired": 1763, "buffered_bytes": 0, "pending_receive_actions": 0,
        "http3_response_headers_decoded": True, "http3_receive_state": "reading-data",
        "qpack_blocked": False, "qpack_decoder_pending": False, "request_send_peer_confirmed": True,
        "stop_sending_queued": False, "reset_stream_queued": False,
        "receive_credit_increase": 0, "unshaped_data_bytes": 0}


def write_rows(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


@pytest.fixture
def local(tmp_path):
    run = _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1,
        stream_cancellations=1, cancelled_capacity=69, terminal_incoming_at_stop=0)
    run["buflo_summary"].update(schema_version=5,
        terminal_subcell_policy=fidelity.BUFLO_LOCAL_ABANDON_POLICY,
        terminal_subcell_observer_effect=fidelity.BUFLO_LOCAL_ABANDON_OBSERVER_EFFECT,
        terminal_local_abandonments=[proof()])
    run["chaff_responses"] = [{"resource_id": 19, "request_id": 0, "complete": False,
        "outcome": "buflo_terminal_subcell_tail_cancelled"}]
    schedule_fields = (*handoff.SCHEDULE_PREFIX_FIELDS, *fidelity.SCHEDULE_QCSD_FIELDS)
    outgoing = dict.fromkeys(schedule_fields, "")
    outgoing.update(target_time_us="0", direction="outgoing", size="1200", connection="0",
        action_time_us="0", satisfaction="satisfied", observed_size="1200", slot_id="1",
        qcsd_outcome_schema_version="3", send_policy="exact", desired_udp_bytes="1200",
        observed_udp_bytes="1200", terminal_defense_elapsed_us="4999")
    incoming = dict.fromkeys(schedule_fields, "")
    incoming.update(target_time_us="0", direction="incoming", size="1200", connection="",
        action_time_us="0", satisfaction="satisfied", slot_id="2", qcsd_outcome_schema_version="3",
        send_policy="exact", desired_udp_bytes="1200", credit_advertised_at_us="0",
        credit_advertisement_delay_us="0", credit_consumed_at_us="10000001",
        credit_consumption_delay_us="10000001", terminal_defense_elapsed_us="10000001")
    event_fields = (*handoff._EVENT_PREFIX_FIELDS, *fidelity.SCHEDULE_QCSD_FIELDS)
    action = dict.fromkeys(event_fields, "")
    action.update(monotonic_us="10000010", connection="0", event="action", outcome="applied",
        details=json.dumps({"type": "cancel_chaff", "endpoint": 0, "stream": 348,
            "reason": "buflo_terminal_subcell_tail"}))
    abandon = {**action, "event": "chaff_local_abandonment", "details": json.dumps(proof())}
    packet_fields = (*handoff._PACKET_PREFIX_FIELDS, *fidelity.SCHEDULE_QCSD_FIELDS)
    packet = dict.fromkeys(packet_fields, "")
    packet.update(direction="outgoing", monotonic_us="4999", connection="0",
        observed_udp_length="1200", scheduled_target="1200", satisfaction="satisfied", slot_id="1",
        qcsd_outcome_schema_version="2", send_policy="exact", desired_udp_bytes="1200",
        observed_udp_bytes="1200", application_stream_bytes="0", retransmission_stream_bytes="0",
        chaff_stream_bytes="1200", defense_control_bytes="0", quic_padding_bytes="0",
        other_quic_bytes="0", lateness_us="0")
    paths = {name: tmp_path / (name + ".csv") for name in ("schedule", "events", "packets")}
    fields = {"schedule": schedule_fields, "events": event_fields, "packets": packet_fields}
    rows = {"schedule": [outgoing, incoming], "events": [abandon, action], "packets": [packet]}
    for name in paths: write_rows(paths[name], fields[name], rows[name])
    return run, paths, fields, rows


def direct(run, paths):
    return fidelity.new_defense_terminal_receipts_valid(run, "buflo",
        require_application_complete=True, require_current_schema=True,
        terminal_trace_paths={"events": paths["events"], "packets": paths["packets"]})


def algorithm(run, paths):
    return handoff._algorithm_diagnostics(run, defense="buflo", runtime_kind="buflo",
        schedule_path=paths["schedule"], events_path=paths["events"], packets_path=paths["packets"])


def test_actual_trace_join_and_retained_state_use_only_new_typed_branches(local):
    run, paths, _, _ = local; original = deepcopy(run)
    assert direct(run, paths)
    result = algorithm(run, paths)
    assert result["schema_version"] == 5 and result["buflo_state"]["schema_version"] == 4
    state = result["buflo_state"]
    assert state["local_abandonments"] == [proof()]
    assert state["post_cancellation_unscheduled_defense_control_packets"] == 0
    assert fidelity.buflo_terminal_state_valid(state)
    assert evaluation._load_algorithm_diagnostics(result, defense="buflo") == result
    assert run == original
    old_state = {key: value for key, value in state.items()
        if key not in {"local_abandonments", "local_abandonment_events"}}
    old_state.update(schema_version=3, terminal_subcell_policy=fidelity.BUFLO_TERMINAL_SUBCELL_POLICY,
        terminal_subcell_observer_effect=fidelity.BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
        control_evidence_semantics=fidelity.BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS)
    assert not fidelity.buflo_terminal_state_valid(old_state)


@pytest.mark.parametrize("key,value", [
    ("endpoint", True), ("stream", -1), ("resource_id", 20), ("request_id", 0.0),
    ("manual_receive_limit", 1983), ("consumed", 1762), ("retired", 1762),
    ("encoded_receive_limit", 0), ("buffered_bytes", 1), ("pending_receive_actions", 1),
    ("http3_response_headers_decoded", False), ("http3_receive_state", "decoding-headers"),
    ("qpack_blocked", True), ("qpack_decoder_pending", True), ("request_send_peer_confirmed", False),
    ("stop_sending_queued", True), ("reset_stream_queued", True),
    ("receive_credit_increase", 1), ("unshaped_data_bytes", 1),
])
def test_unsafe_or_mistyped_native_proof_refuses_before_common_acceptance(local, key, value):
    run, paths, _, _ = local
    run["buflo_summary"]["terminal_local_abandonments"][0][key] = value
    assert not direct(run, paths)
    with pytest.raises(ValueError): algorithm(run, paths)


@pytest.mark.parametrize("change", ["missing-proof", "duplicate-proof", "extra-proof-field",
    "missing-event", "duplicate-event", "event-proof", "action-stream", "action-reason", "clock",
    "response-request", "response-complete", "extra-cancelled-response"])
def test_real_event_and_response_joins_refuse_missing_duplicate_or_changed_identity(local, change):
    run, paths, fields, rows = local
    proofs = run["buflo_summary"]["terminal_local_abandonments"]
    if change == "missing-proof": proofs.clear()
    elif change == "duplicate-proof": proofs.append(deepcopy(proofs[0]))
    elif change == "extra-proof-field": proofs[0]["operator_waiver"] = True
    elif change == "missing-event": rows["events"].pop(0)
    elif change == "duplicate-event": rows["events"].append(deepcopy(rows["events"][0]))
    elif change == "event-proof":
        changed = proof(); changed["request_id"] = 1; rows["events"][0]["details"] = json.dumps(changed)
    elif change in {"action-stream", "action-reason"}:
        changed = json.loads(rows["events"][1]["details"])
        changed["stream" if change == "action-stream" else "reason"] = 352 if change == "action-stream" else "cs_buflo_local_early_termination"
        rows["events"][1]["details"] = json.dumps(changed)
    elif change == "clock":
        for row in rows["events"]: row["monotonic_us"] = "9999999"
    elif change == "response-request": run["chaff_responses"][0]["request_id"] = 1
    elif change == "response-complete": run["chaff_responses"][0]["complete"] = True
    else: run["chaff_responses"].append(deepcopy(run["chaff_responses"][0]))
    write_rows(paths["events"], fields["events"], rows["events"])
    assert not direct(run, paths)
    with pytest.raises(ValueError): algorithm(run, paths)


@pytest.mark.parametrize("field", ["application_stream_bytes", "retransmission_stream_bytes",
    "chaff_stream_bytes", "defense_control_bytes"])
def test_actual_post_abandonment_packet_bytes_cannot_be_waived(local, field):
    run, paths, fields, rows = local
    packet = {**rows["packets"][0], "monotonic_us": "10000020", "scheduled_target": "", "slot_id": "",
        "satisfaction": "unshaped", "send_policy": "unscheduled", "observed_udp_length": "50",
        "desired_udp_bytes": "50", "observed_udp_bytes": "50", "chaff_stream_bytes": "0",
        "other_quic_bytes": "49", field: "1"}
    rows["packets"].append(packet); write_rows(paths["packets"], fields["packets"], rows["packets"])
    assert not direct(run, paths)
    with pytest.raises(ValueError): algorithm(run, paths)


@pytest.mark.parametrize("change", ["application", "scheduled-cell-count", "kernel", "summary-kind", "unknown-schema"])
def test_new_variant_retains_old_application_cadence_and_kernel_gates(local, change):
    run, paths, _, _ = local
    if change == "application": run["defense_diagnostics"]["buflo_application_complete"] = False
    elif change == "scheduled-cell-count": run["defense_diagnostics"]["buflo_scheduled_outgoing_cells"] = 2
    elif change == "kernel": run["runner_wakeup_metrics"]["buflo_kernel_tx"]["terminal_outcome"] = "failed"
    elif change == "summary-kind": run["buflo_summary"]["kind"] = "cs_buflo"
    else: run["buflo_summary"]["schema_version"] = 6
    assert not direct(run, paths)


def test_missing_trace_paths_and_legacy_or_wrong_algorithm_labels_refuse(local):
    run, paths, _, _ = local
    assert not fidelity.new_defense_terminal_receipts_valid(run, "buflo", require_current_schema=True)
    result = algorithm(run, paths)
    for key, value in (("schema_version", 4), ("runtime_kind", "cs_buflo")):
        changed = deepcopy(result); changed[key] = value
        with pytest.raises(ValueError): evaluation._load_algorithm_diagnostics(changed, defense="buflo")


def test_source039_reader_is_honest_and_preserves_dated_admission_profiles():
    actual = cohorts.verifier_contract(); qualified = compatibility.qualify_execution(actual)
    assert compatibility.EXECUTION_KIND == "039" and actual["transitive_source_files"] == 170
    old = compatibility.legacy_contract()
    assert compatibility.require_supported(old, qualified)
    binding = compatibility.execution_binding(old, qualified)
    assert binding["record_type"] == "qcsd-resource-domain-017-018-019-039-reader-execution-binding-v1"
    assert binding["buflo_local_abandonment_reader_changed"] is True
    assert binding["buflo_typed_partial_advertisement_observations_changed"] is True
    assert binding["buflo_ack_start_retained_directory_binding_changed"] is True
    assert binding["buflo_ack_start_retained_stop_schedule_changed"] is True
    assert binding["buflo_ack_start_retained_evaluation_join_changed"] is True
    assert binding["buflo_startup_ack_sparse_false_fin_changed"] is True
    assert binding["prospective_buflo_terminal_protocol_changed"] is True
    assert binding["scientific_truth_conditions_changed"] is True
    assert binding["historical_receipts_requalified_by_compatibility"] is False
    assert binding["scientific_credit_added"] == 0 and binding["authority_issued"] is False
    with pytest.raises(ValueError, match="Source039 execution"):
        compatibility.qualify_execution(old)


def test_unknown_admission_reader_cannot_borrow_the_new_terminal_protocol():
    actual = cohorts.verifier_contract(); qualified = compatibility.qualify_execution(actual)
    changed = compatibility.legacy_contract(); changed["implementation"] = "operator-approved-alias"
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(changed, qualified)
