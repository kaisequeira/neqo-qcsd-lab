from __future__ import annotations

import json
from copy import deepcopy

import pytest

from qcsd_lab.defenses import defense_from_runtime_identity
from qcsd_lab.fidelity import (
    fidelity_eligible,
    reconcile_direct_runner_artifacts,
    write_fidelity_record,
)


@pytest.mark.parametrize(
    ("name", "runtime_kind", "expected"),
    [
        ("undefended", "none", "undefended"),
        ("baseline", "none", "undefended"),
        ("traffic-morphing", "traffic_morphing", "traffic-morphing"),
        ("selected", "traffic_morphing", "traffic-morphing"),
    ],
)
def test_fidelity_identity_is_runtime_derived(name, runtime_kind, expected):
    assert defense_from_runtime_identity(name, runtime_kind) == expected


def test_fidelity_identity_rejects_unknown_or_mismatched_runtime_bindings():
    with pytest.raises(ValueError, match="unsupported defense runtime kind"):
        defense_from_runtime_identity("selected", "opaque-runtime")
    with pytest.raises(ValueError, match="not bound"):
        defense_from_runtime_identity("undefended", "traffic_morphing")


def test_failed_traffic_morphing_sample_records_failure_without_direct_reconciliation(
    tmp_path,
):
    (tmp_path / "sample.json").write_text(
        json.dumps(
            {
                "defense": "traffic-morphing",
                "runtime_kind": "traffic_morphing",
                "state": "failed",
                "eligible": False,
                "views": [],
            }
        ),
        encoding="utf-8",
    )

    path, eligible = write_fidelity_record(tmp_path, baseline_wire_bytes=None)

    record = json.loads(path.read_text(encoding="utf-8"))
    assert eligible is False
    assert record["sample_eligible"] is False
    assert record["fidelity_eligible"] is False
    assert "direct_runner_reconciled" not in record["realization_metrics"]


def test_direct_runner_reconciliation_preserves_packet_and_tail_evidence(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="incoming")

    result = reconcile_direct_runner_artifacts(run, packets, trace)

    assert result.evidence_eligible is True
    assert result.metrics["direct_runner_reconciled"] is True
    assert result.metrics["direct_runner_packets"] == 2
    assert result.metrics["direct_matched_packets"] == 2
    assert result.metrics["direct_unmatched_tail_packets"] == 1
    assert result.metrics["direct_unmatched_tail_bytes"] == 100
    assert result.metrics["direct_timestamp_error_max_ns"] == 0
    assert result.metrics["direct_trace_sha256"]
    assert result.metrics["direct_runner_packets_sha256"]


def test_direct_runner_reconciliation_rejects_unrecorded_outgoing_tail(tmp_path):
    run, packets, trace = _reconciliation_artifacts(tmp_path, tail_direction="outgoing")

    with pytest.raises(ValueError, match="unrecorded outgoing tail"):
        reconcile_direct_runner_artifacts(run, packets, trace)


def test_defended_sample_requires_exact_zero_miss_schedule_contract():
    diagnostics = _traffic_morphing_diagnostics()

    assert _eligible("traffic-morphing", diagnostics)
    assert not _eligible("traffic-morphing", diagnostics, missed_events=1)
    assert not _eligible("traffic-morphing", diagnostics, missed_events=None)
    assert not _eligible("traffic-morphing", diagnostics, outgoing_size_mismatches=1)
    assert not _eligible("traffic-morphing", diagnostics, outgoing_size_mismatches=None)


def test_wtf_pad_size_error_is_distinct_from_byte_shortfall():
    diagnostics = _wtf_pad_diagnostics()
    diagnostics["wtf_pad_incoming_size_error_bytes"] = 600

    assert diagnostics["wtf_pad_incoming_shortfall_bytes"] == 0
    assert _eligible("wtf-pad", diagnostics)


@pytest.mark.parametrize(
    ("defense", "required_key"),
    [
        ("traffic-morphing", "morphing_egress_packets"),
        ("wtf-pad", "wtf_pad_gap_to_burst"),
        (
            "walkie-talkie",
            "walkie_talkie_application_stream_crossing_bytes",
        ),
    ],
)
def test_defense_diagnostics_are_exact_typed_contracts(
    defense,
    required_key,
):
    diagnostics = {
        "traffic-morphing": _traffic_morphing_diagnostics,
        "wtf-pad": _wtf_pad_diagnostics,
        "walkie-talkie": _walkie_talkie_diagnostics,
    }[defense]()
    assert _eligible(defense, diagnostics)

    missing = deepcopy(diagnostics)
    del missing[required_key]
    assert not _eligible(defense, missing)

    extra = deepcopy(diagnostics)
    extra[f"{required_key}_stale"] = 0
    assert not _eligible(defense, extra)

    wrong_type = deepcopy(diagnostics)
    wrong_type[required_key] = False
    assert not _eligible(defense, wrong_type)


def test_walkie_talkie_rejects_crossing_lifecycle_and_burst_realization_errors():
    diagnostics = _walkie_talkie_diagnostics()

    crossing = deepcopy(diagnostics)
    crossing["walkie_talkie_application_stream_crossing_bytes"] = 1
    assert not _eligible("walkie-talkie", crossing)

    active = deepcopy(diagnostics)
    active["walkie_talkie_application_batch_active"] = True
    assert not _eligible("walkie-talkie", active)

    incomplete = deepcopy(diagnostics)
    incomplete["walkie_talkie_application_batches_completed"] = 0
    assert not _eligible("walkie-talkie", incomplete)

    missing_batch = deepcopy(diagnostics)
    missing_batch["walkie_talkie_observed_application_batches"] = 0
    assert not _eligible("walkie-talkie", missing_batch)

    overflow = deepcopy(diagnostics)
    overflow["walkie_talkie_observed_application_batches"] = 2
    overflow["walkie_talkie_application_batches_completed"] = 2
    overflow["walkie_talkie_application_batch_overflow"] = 1
    assert not _eligible("walkie-talkie", overflow)

    unrealized = deepcopy(diagnostics)
    unrealized["walkie_talkie_burst_realization"][0]["observed_incoming_cells"] = 1
    assert not _eligible("walkie-talkie", unrealized)


def test_walkie_talkie_rejects_source_envelope_overflow_even_when_mould_is_exact():
    diagnostics = _walkie_talkie_diagnostics()
    diagnostics["walkie_talkie_source_envelope_overflow_cells"] = 2

    assert (
        diagnostics["walkie_talkie_target_outgoing_cells"]
        == diagnostics["walkie_talkie_observed_outgoing_cells"]
    )
    assert (
        diagnostics["walkie_talkie_target_incoming_cells"]
        == diagnostics["walkie_talkie_observed_incoming_cells"]
    )
    assert diagnostics["walkie_talkie_target_observed_burst_l1"] == 0
    assert not _eligible("walkie-talkie", diagnostics)


def _eligible(
    defense: str,
    diagnostics: dict,
    *,
    missed_events: object = 0,
    outgoing_size_mismatches: object = 0,
) -> bool:
    return fidelity_eligible(
        defense,
        diagnostics,
        sample_eligible=True,
        missed_events=missed_events,
        outgoing_size_mismatches=outgoing_size_mismatches,
    )


def _traffic_morphing_diagnostics() -> dict:
    return {
        "morphing_egress_packets": 2,
        "morphing_egress_source_bytes": 230,
        "morphing_egress_target_bytes": 400,
        "morphing_egress_bypasses": 0,
        "morphing_egress_pacing_bypasses": 0,
        "morphing_egress_congestion_bypasses": 0,
        "morphing_egress_coalesced_bypasses": 0,
        "morphing_egress_invalid_size_bypasses": 0,
        "morphing_egress_target_selection_bypasses": 0,
        "morphing_egress_target_l1_ppm": 0,
        "morphing_ingress_requested_bytes": 100,
        "morphing_ingress_received_bytes": 100,
        "morphing_ingress_shortfall_bytes": 0,
        "morphing_ingress_target_l1_ppm": 0,
        "suppressed_cover_feedback": 1,
    }


def _wtf_pad_diagnostics() -> dict:
    return {
        "padding_events": 2,
        "padding_event_guard_triggered": False,
        "wtf_pad_incoming_desired_bytes": 100,
        "wtf_pad_incoming_requested_bytes": 100,
        "wtf_pad_incoming_received_bytes": 100,
        "wtf_pad_incoming_shortfall_bytes": 0,
        "wtf_pad_incoming_size_error_bytes": 0,
        "wtf_pad_incoming_observed_events": 1,
        "wtf_pad_incoming_lag_us_total": 10,
        "wtf_pad_incoming_lag_us_max": 10,
        "wtf_pad_silent_to_burst": 1,
        "wtf_pad_burst_to_gap": 1,
        "wtf_pad_gap_to_burst": 1,
        "wtf_pad_burst_to_silent": 1,
        "suppressed_cover_feedback": 1,
    }


def _walkie_talkie_diagnostics() -> dict:
    return {
        "retried_outgoing_events": 0,
        "walkie_talkie_target_outgoing_cells": 2,
        "walkie_talkie_target_incoming_cells": 2,
        "walkie_talkie_observed_outgoing_cells": 2,
        "walkie_talkie_observed_incoming_cells": 2,
        "walkie_talkie_outgoing_shortfall_cells": 0,
        "walkie_talkie_incoming_shortfall_cells": 0,
        "walkie_talkie_outgoing_overflow_cells": 0,
        "walkie_talkie_incoming_overflow_cells": 0,
        "walkie_talkie_incoming_shortfall_bytes": 0,
        "walkie_talkie_incoming_chaff_bytes": 0,
        "walkie_talkie_target_observed_cell_l1": 0,
        "walkie_talkie_target_observed_burst_l1": 0,
        "walkie_talkie_control_only_crossings": 0,
        "walkie_talkie_application_stream_crossing_bytes": 0,
        "walkie_talkie_natural_outgoing_bytes": 150,
        "walkie_talkie_natural_incoming_bytes": 175,
        "walkie_talkie_source_envelope_overflow_cells": 0,
        "walkie_talkie_expected_application_batches": 1,
        "walkie_talkie_observed_application_batches": 1,
        "walkie_talkie_application_batch_overflow": 0,
        "walkie_talkie_application_batches_completed": 1,
        "walkie_talkie_batch_lifecycle_errors": 0,
        "walkie_talkie_application_batch_active": False,
        "walkie_talkie_burst_realization": [
            {
                "index": 0,
                "target_outgoing_cells": 2,
                "target_incoming_cells": 2,
                "observed_outgoing_cells": 2,
                "observed_incoming_cells": 2,
            }
        ],
    }


def _reconciliation_artifacts(
    root,
    *,
    tail_direction: str,
):
    run = root / "run.json"
    packets = root / "packets.csv"
    trace = root / "direct.csv"
    run.write_text(
        json.dumps(
            {
                "completion_status": "complete",
                "endpoints": [
                    {
                        "id": 0,
                        "local_address": "10.0.0.2:50000",
                        "remote_address": "203.0.113.1:443",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    packets.write_text(
        "direction,monotonic_us,connection,observed_udp_length,"
        "scheduled_target,satisfaction,slot_id\n"
        "outgoing,1000,0,1200,,unshaped,\n"
        "incoming,2000,0,1200,,observed,\n",
        encoding="utf-8",
    )
    signed_tail = 100 if tail_direction == "outgoing" else -100
    trace.write_text(
        "relative_time_ns,direction,length_bytes,signed_length_bytes\n"
        "0,outgoing,1242,1242\n"
        "1000000,incoming,1242,-1242\n"
        f"2000000,{tail_direction},100,{signed_tail}\n",
        encoding="utf-8",
    )
    return run, packets, trace
