"""PROPOSED Source045 analysis-only component regressions; ROOT materializes/tests.

No fake validation-success callback or copied giant fixture is used. Existing
partial_fixture supplies real raw events, FIN, owned ranges and typed policy;
the unchanged complete validator must accept each positive before metrics run.
The two actual observed positive split patterns are represented synthetically
inside that original fixture; no test asserts these bytes are ROOT evidence.
Root's real retained two-pilot RED/GREEN remains the whole-chain regression.
"""
from copy import deepcopy
import json

import pytest

from qcsd_lab import buflo_handoff as handoff, capture_acceptance_policy as policy
from tests.test_capture_terminal_primary_partial import partial_fixture, save_partial
from tests.test_capture_buflo_ack_start import fixture as complete_fixture


def case(root, consumed=600):
    native, events, rows, packets = partial_fixture(root, "buflo")
    proof = native[policy.TERMINAL_PRIMARY_PROOF_FIELD]
    partial = next(row for row in rows if int(row["slot_id"]) == proof["slot"])
    # Match the real Native099 exact incoming retired-row representation.
    partial.update(send_policy="exact", desired_udp_bytes="1200")
    proof.update(consumed_bytes=consumed, retired_bytes=1200-consumed)
    native["defense_diagnostics"].update(
        scheduled_incoming_consumed_bytes=sum(row["direction"] == "incoming" for row in rows)*1200-proof["retired_bytes"],
        scheduled_incoming_retired_bytes=proof["retired_bytes"])
    for event in events:
        detail = json.loads(event["details"])
        if event["event"] == "terminal_primary_partial_cell":
            event["details"] = json.dumps(proof)
        elif isinstance(detail, dict) and detail.get("endpoint") == proof["endpoint"] and detail.get("stream") == proof["stream"]:
            if detail.get("type") == "response_headers":
                detail["frame_bytes"] = 16+consumed-103
            elif detail.get("type") == "bytes_read":
                detail["bytes"] = 16+consumed
            event["details"] = json.dumps(detail)
    save_partial(root, native, events, rows, packets)
    return native, events, rows, packets, partial


def metrics(root, native, rows):
    return handoff._direction_algorithm_metrics(rows, direction="incoming", runtime_kind="buflo",
        run=native, runner_directory=root)


@pytest.mark.parametrize("consumed", [467, 406, 600])
def test_exact_complete_primary_partial_proof_allows_only_its_blank_consumption(tmp_path, consumed):
    native, events, rows, packets, partial = case(tmp_path, consumed)
    proof = policy.validate_terminal_primary_partial_evidence(native,
        runner_directory=tmp_path, schedule_rows=rows)
    assert proof["terminal_primary_partial_cells"] == 1
    assert proof["terminal_primary_partial_consumed_bytes"] == consumed
    assert proof["terminal_primary_partial_retired_bytes"] == 1200-consumed
    assert partial["credit_consumed_at_us"] == partial["credit_consumption_delay_us"] == ""
    result = metrics(tmp_path, native, rows)
    incoming = sum(row["direction"] == "incoming" for row in rows)
    assert result["scheduled_cells"] == incoming
    assert result["satisfaction_counts"] == {"missed": 1, "satisfied": incoming-1}
    assert result["receive_credit_advertisement"]["advertised_cells"] == incoming
    assert result["receive_credit_consumption"]["consumed_cells"] == incoming-1


def test_default_legacy_call_does_not_borrow_an_unprovided_partial_proof(tmp_path):
    native, events, rows, packets, partial = case(tmp_path)
    with pytest.raises(ValueError, match="incoming credit consumed time"):
        handoff._direction_algorithm_metrics(rows, direction="incoming", runtime_kind="buflo")


def test_complete_consumed_rows_keep_original_metrics_with_or_without_context(tmp_path):
    native, events, rows = complete_fixture(tmp_path)
    original = handoff._direction_algorithm_metrics(rows, direction="incoming", runtime_kind="buflo")
    assert metrics(tmp_path, native, rows) == original
    assert original["receive_credit_consumption"]["consumed_cells"] == original["scheduled_cells"]


@pytest.mark.parametrize("mutation", [
    "missing-policy", "missing-proof", "malformed-proof", "stale-proof", "wrong-slot",
    "double-partial", "generic-miss", "generic-blank", "wrong-primary", "missing-fin",
    "other-mode", "wrong-endpoint", "forged-sum", "no-advertisement",
])
def test_blank_consumption_requires_the_whole_unchanged_primary_proof(tmp_path, mutation):
    native, events, rows, packets, partial = case(tmp_path)
    proof = native[policy.TERMINAL_PRIMARY_PROOF_FIELD]
    if mutation == "missing-policy":
        native.pop(policy.TERMINAL_PRIMARY_FIELD)
    elif mutation == "missing-proof":
        native.pop(policy.TERMINAL_PRIMARY_PROOF_FIELD)
    elif mutation == "malformed-proof":
        proof["consumed_bytes"] = True
    elif mutation == "stale-proof":
        proof["fin_at_us"] += 1
    elif mutation == "wrong-slot":
        partial["slot_id"] = str(proof["slot"]+1_000_000)
    elif mutation in {"double-partial", "generic-blank"}:
        other = next(row for row in rows if row["direction"] == "incoming" and row is not partial)
        other.update(credit_consumed_at_us="", credit_consumption_delay_us="")
        if mutation == "double-partial":
            other.update(satisfaction="missed", miss_reason="ReceiveCreditRetired")
    elif mutation == "generic-miss":
        partial["miss_reason"] = "DeadlineExpired"
    elif mutation == "wrong-primary":
        native["responses"][0]["complete"] = False
    elif mutation == "missing-fin":
        events = [event for event in events if not isinstance(json.loads(event["details"]), dict)
            or json.loads(event["details"]).get("type") != "stream_finished"]
    elif mutation == "other-mode":
        native["resolved_configuration"]["defense"]["kind"] = "tamaraw"
    elif mutation == "wrong-endpoint":
        partial["connection"] = str(proof["endpoint"]+1)
    elif mutation == "forged-sum":
        proof["consumed_bytes"] += 1
    elif mutation == "no-advertisement":
        partial.update(credit_advertised_at_us="", credit_advertisement_delay_us="")
    save_partial(tmp_path, native, events, rows, packets)
    with pytest.raises(ValueError):
        metrics(tmp_path, native, rows)


@pytest.mark.parametrize("field", ["credit_consumed_at_us", "credit_consumption_delay_us"])
def test_one_empty_consumption_field_is_never_a_proved_absence(tmp_path, field):
    native, events, rows, packets, partial = case(tmp_path)
    partial[field] = "123456"
    save_partial(tmp_path, native, events, rows, packets)
    with pytest.raises(ValueError):
        metrics(tmp_path, native, rows)

