"""Canonical sparse ACK DTO controls; synthetic traces grant no capture credit."""
from copy import deepcopy
import json

import pytest

from qcsd_lab import capture_acceptance_policy as policy
from tests import test_capture_buflo_ack_start as ack
from tests import test_buflo_cadence64_budget640 as cadence64


def fixture(root, *, period_us=64_000, fin_only=False, sparse=True):
    acknowledgments = ([(0, 103, False, 82_100), (103, 0, True, 142_800)] if fin_only
        else [(0, 95, False, 82_100), (95, 8, True, 142_800)])
    run, events, rows = ack.fixture(root, acknowledgments=acknowledgments,
        ack_observed_at_us=142_800, ready_at_us=143_000)
    run["defense_start_monotonic_ns"] = 100_000_000
    startup = run["buflo_summary"]["incoming_startup"]
    startup.update(ready_endpoint=0, ready_stream=80, ready_resource_id=13,
        request_stream_final_size=103, period_us=period_us,
        armed_at_us=(143_000 // period_us + 1) * period_us,
        startup_suppressed_opportunities=143_000 // period_us + 1)
    run["defense_diagnostics"]["buflo_incoming_startup"] = deepcopy(startup)
    run["chaff_responses"][0].update(resource_id=13, request_stream_bytes=103,
        expected_request_stream_bytes=103)
    role = {"chaff": {"resource_id": 13, "request_id": 0}}
    # Reproduce the actual Zappos ACK DTO sizes, production clocks and sequences.
    # The surrounding complete fixture is synthetic, not a retained receipt.
    clocks = ((176, 182_076_272), (251, 242_740_544))
    for index, row in enumerate(events):
        row["connection"] = "0"
        details = json.loads(row["details"])
        if row["event"] == "buflo_incoming_startup_ready":
            details = deepcopy(startup)
            row["monotonic_us"] = "243000"
        else:
            observation = details["observation"] if row["event"] == "buflo_incoming_startup_ack" else details
            observation.update(endpoint=0, stream=80, role=deepcopy(role))
            if index:
                sequence, produced_ns = clocks[(index - 1) // 2]
                details.update(production_sequence=sequence, production_monotonic_ns=produced_ns)
                row["monotonic_us"] = str(produced_ns // 1_000)
                if sparse and observation["fin"] is False:
                    del observation["fin"]
        row["details"] = json.dumps(details)
    if period_us == 64_000:
        current = cadence64.native_run()
        run.update({key: current[key] for key in ("method", "defense_parameters", "runner_wakeup_metrics",
            policy.FIELD, policy.BUFLO_KERNEL_PREPARATION_FIELD)})
        run["resolved_configuration"]["defense"].update(current["resolved_configuration"]["defense"])
        rows = [{"direction": direction, "target_time_us": str(target), "size": "1200"}
            for target in range(0, 10_048_001, period_us) for direction in ("outgoing", "incoming")
            if direction != "incoming" or target >= startup["armed_at_us"]]
    ack.save(root, run, events, rows)
    return run, events, rows


def change_pair(events, first, mutate):
    for index in ((1, 2) if first else (3, 4)):
        details = json.loads(events[index]["details"])
        observation = details["observation"] if index % 2 == 0 else details
        mutate(observation)
        events[index]["details"] = json.dumps(details)


@pytest.mark.parametrize("period_us,sparse,fin_only", [
    (20_000, True, False), (64_000, True, False),
    (64_000, False, False), (64_000, True, True),
])
def test_canonical_omitted_false_and_explicit_fin_preserve_full_request_coverage(tmp_path, period_us, sparse, fin_only):
    run, _, _ = fixture(tmp_path, period_us=period_us, sparse=sparse, fin_only=fin_only)
    assert policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path) == run["buflo_summary"]["incoming_startup"]


@pytest.mark.parametrize("mutation", [
    "missing-true", "false-final", "integer-fin", "float-fin", "null-fin", "string-fin",
    "extra-key", "missing-bytes", "gap", "range-overrun", "premature-fin",
    "pair-presence", "pair-fin", "production-clock", "reduction-clock",
    "sequence", "wrong-source", "wrong-policy", "missing-original",
])
def test_sparse_ack_keeps_explicit_fin_shape_pair_range_and_clock_guards(tmp_path, mutation):
    run, events, rows = fixture(tmp_path)
    if mutation == "missing-true": change_pair(events, False, lambda value: value.pop("fin"))
    elif mutation == "false-final": change_pair(events, False, lambda value: value.update(fin=False))
    elif mutation in {"integer-fin", "float-fin", "null-fin", "string-fin"}:
        value = {"integer-fin": 0, "float-fin": 0.0, "null-fin": None, "string-fin": "false"}[mutation]
        change_pair(events, True, lambda observation: observation.update(fin=value))
    elif mutation == "extra-key": change_pair(events, True, lambda value: value.update(final=False))
    elif mutation == "missing-bytes": change_pair(events, True, lambda value: value.pop("bytes"))
    elif mutation == "gap": change_pair(events, False, lambda value: value.update(offset=96, bytes=7))
    elif mutation == "range-overrun": change_pair(events, False, lambda value: value.update(bytes=9))
    elif mutation == "premature-fin": change_pair(events, True, lambda value: value.update(fin=True))
    elif mutation in {"pair-presence", "pair-fin", "reduction-clock", "sequence", "wrong-source"}:
        details = json.loads(events[2]["details"])
        if mutation == "pair-presence": details["observation"]["fin"] = False
        elif mutation == "pair-fin": details["observation"]["fin"] = True
        elif mutation == "reduction-clock": details["controller_defense_elapsed_us"] = 142_801
        elif mutation == "sequence": details["production_sequence"] += 1
        else: details["source"] = "unbound-clock"
        events[2]["details"] = json.dumps(details)
    elif mutation == "production-clock": events[1]["monotonic_us"] = "182077"
    elif mutation == "wrong-policy": run[policy.FIELD]["policy"] = policy.POLICY
    else: events.pop(1)
    ack.save(tmp_path, run, events, rows)
    with pytest.raises(ValueError):
        policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path)


@pytest.mark.parametrize("present", [False, True])
def test_zero_byte_final_ack_still_requires_explicit_true_fin(tmp_path, present):
    run, events, rows = fixture(tmp_path, fin_only=True)
    if present:
        change_pair(events, False, lambda value: value.update(fin=False))
    else:
        change_pair(events, False, lambda value: value.pop("fin"))
    ack.save(tmp_path, run, events, rows)
    with pytest.raises(ValueError, match="full terminal request ACK coverage"):
        policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path)
