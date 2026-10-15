"""Typed partial-advertisement controls; synthetic common receipt, real CSV IO.

The positive observation reproduces the original Native098 event DTO supplied
by ROOT. It is physical observation provenance, never whole-slot realization
or an independent raw/session qualification. ROOT alone executes these tests.
"""
from copy import deepcopy
import json

import pytest

from qcsd_lab import buflo_handoff as handoff
from qcsd_lab import fidelity
from tests.test_buflo_local_abandon_reader import algorithm, direct, local, write_rows


def partial_row():
    row = dict.fromkeys((*handoff._EVENT_PREFIX_FIELDS, *fidelity.SCHEDULE_QCSD_FIELDS), "")
    row.update(monotonic_us="232544", connection="0", event="observation", outcome="recorded",
        details=json.dumps({"type": "receive_limit_advertised", "endpoint": 0, "stream": 0,
            "absolute_limit": 1940, "slot": 5, "production_monotonic_ns": 232544632,
            "production_sequence": 292}), qcsd_outcome_schema_version="2")
    return row


def test_actual_partial_observation_has_an_explicit_leaf_reader():
    row = partial_row(); original = deepcopy(row)
    with pytest.raises(ValueError, match="schema-only"):
        fidelity._validate_qcsd_trace_extension(row, label="original row358")
    fidelity._validate_buflo_partial_advertisement_extension(row, label="typed row358")
    assert row == original
    assert row["credit_advertised_at_us"] == row["credit_advertisement_delay_us"] == ""


def test_real_csv_opt_in_preserves_old_default_and_both_new_paths(local):
    run, paths, fields, rows = local; original = deepcopy(run)
    rows["events"].insert(0, partial_row())
    write_rows(paths["events"], fields["events"], rows["events"])
    with pytest.raises(ValueError, match="schema-only"):
        handoff._read_extended_runner_csv(paths["events"], handoff._EVENT_PREFIX_FIELDS,
            label="legacy events.csv")
    actual = handoff._read_extended_runner_csv(paths["events"], handoff._EVENT_PREFIX_FIELDS,
        label="new events.csv", allow_buflo_partial_advertisement=True)
    assert actual[0] == partial_row()
    assert direct(run, paths)
    assert algorithm(run, paths)["schema_version"] == 5
    assert run == original
    # The dated summary4 path keeps its original generic CSV gate.
    legacy = deepcopy(run)
    legacy["buflo_summary"].pop("terminal_local_abandonments")
    legacy["buflo_summary"].update(schema_version=4,
        terminal_subcell_policy=fidelity.BUFLO_TERMINAL_SUBCELL_POLICY,
        terminal_subcell_observer_effect=fidelity.BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT)
    with pytest.raises(ValueError, match="schema-only"):
        algorithm(legacy, paths)


@pytest.mark.parametrize("key,value", [
    ("type", "receive_credit_consumed"), ("endpoint", True), ("stream", -1),
    ("absolute_limit", 1940.0), ("slot", None), ("production_monotonic_ns", 2**64),
    ("production_sequence", False), ("production_sequence", "292"),
])
def test_exact_native_dto_types_cannot_be_substituted(local, key, value):
    row = partial_row(); details = json.loads(row["details"]); details[key] = value
    row["details"] = json.dumps(details)
    with pytest.raises(ValueError):
        fidelity._validate_buflo_partial_advertisement_extension(row, label="changed DTO")
    run, paths, fields, rows = local
    rows["events"].insert(0, row); write_rows(paths["events"], fields["events"], rows["events"])
    assert not direct(run, paths)
    with pytest.raises(ValueError): algorithm(run, paths)


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate-json", "malformed-json",
    "wrong-event", "wrong-outcome", "wrong-endpoint", "noncanonical-endpoint", "wrong-clock",
    "noncanonical-clock", "schema1", "schema3", "schema4", "mixed-size", "partial-timestamp"])
def test_schema_only_rows_need_the_entire_physical_observation_binding(local, change):
    row = partial_row(); details = json.loads(row["details"])
    if change == "missing":
        details.pop("slot"); row["details"] = json.dumps(details)
    elif change == "extra":
        details["whole_slot_realized"] = True; row["details"] = json.dumps(details)
    elif change == "duplicate-json": row["details"] = row["details"][:-1] + ', "slot": 5}'
    elif change == "malformed-json": row["details"] = "{"
    elif change == "wrong-event": row["event"] = "action"
    elif change == "wrong-outcome": row["outcome"] = "applied"
    elif change == "wrong-endpoint": row["connection"] = "1"
    elif change == "noncanonical-endpoint": row["connection"] = "00"
    elif change == "wrong-clock": row["monotonic_us"] = "232545"
    elif change == "noncanonical-clock": row["monotonic_us"] = "0232544"
    elif change.startswith("schema"): row["qcsd_outcome_schema_version"] = change[-1]
    elif change == "mixed-size": row["desired_udp_bytes"] = "1200"
    else: row["credit_advertised_at_us"] = "232544"
    with pytest.raises(ValueError):
        fidelity._validate_buflo_partial_advertisement_extension(row, label="unbound row")
    run, paths, fields, rows = local
    rows["events"].insert(0, row); write_rows(paths["events"], fields["events"], rows["events"])
    assert not direct(run, paths)
    with pytest.raises(ValueError): algorithm(run, paths)


@pytest.mark.parametrize("flag,prefix", [(True, handoff._PACKET_PREFIX_FIELDS),
    (True, handoff.SCHEDULE_PREFIX_FIELDS), (1, handoff._EVENT_PREFIX_FIELDS),
    ("yes", handoff._EVENT_PREFIX_FIELDS)])
def test_opt_in_cannot_enable_packet_schedule_or_untyped_readers(local, flag, prefix):
    _, paths, _, _ = local
    with pytest.raises(ValueError, match="explicit BuFLO event reader"):
        handoff._read_extended_runner_csv(paths["events"], prefix,
            label="wrong reader", allow_buflo_partial_advertisement=flag)


def test_real_advertisement_timestamps_keep_original_validation():
    row = partial_row()
    row.update(credit_advertised_at_us="232544", credit_advertisement_delay_us="100")
    fidelity._validate_qcsd_trace_extension(row, label="whole-slot metadata")
    fidelity._validate_buflo_partial_advertisement_extension(row, label="whole-slot metadata")
    row["credit_advertisement_delay_us"] = ""
    with pytest.raises(ValueError):
        fidelity._validate_buflo_partial_advertisement_extension(row, label="partial metadata")
