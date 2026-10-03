import json

import pytest

from qcsd_lab.fidelity import reconcile_direct_runner_artifacts


def artifacts(root):
    first_unix = 1_000_000_000
    endpoints = []
    for identifier, elapsed, unix in [(0, 3_500_000, first_unix + 2_500_000),
                                     (1, 6_000_000, first_unix + 5_000_000)]:
        endpoints.append({
            "id": identifier, "local_address": f"10.0.0.2:{50000 + identifier}",
            "remote_address": "203.0.113.1:443",
            "receive_lifecycle": {
                "schema_version": 1, "source": "native-final-udp-receive-drain-v1",
                "time_basis": "runner-process-start-elapsed-monotonic-v1",
                "disposition": "drained_to_would_block", "scientific_credit": False,
                "polling_stopped_at_elapsed_ns": elapsed,
                "polling_stopped_at_unix_ns": unix,
            },
        })
    run = root / "run.json"
    run.write_text(json.dumps({"completion_status": "complete", "endpoints": endpoints,
                              "time_anchor_unix_ns": first_unix - 1_000_000,
                              "ended_unix_ns": first_unix + 5_100_000}))
    packets = root / "packets.csv"
    packets.write_text(
        "direction,monotonic_us,connection,observed_udp_length,scheduled_target,satisfaction,slot_id\n"
        "outgoing,1000,0,1200,,unshaped,\n"
        "incoming,2000,0,1200,,observed,\n"
        "outgoing,3000,1,1200,,unshaped,\n"
        "incoming,5000,1,1200,,observed,\n")
    trace = root / "direct.csv"
    rows = [(0, "outgoing", 1242, 0), (1_000_000, "incoming", 1242, 0),
            (2_000_000, "outgoing", 1242, 1), (3_500_000, "incoming", 74, 0),
            (4_000_000, "incoming", 1242, 1), (6_000_000, "incoming", 74, 1)]
    trace.write_text("relative_time_ns,direction,length_bytes,signed_length_bytes,connection,timestamp_unix_ns\n"
                     + "".join(f"{time},{direction},{size},{size if direction == 'outgoing' else -size},"
                               f"{connection},{first_unix + time}\n"
                               for time, direction, size, connection in rows))
    anchors = {"start_realtime_unix_ns": first_unix - 2_000_000,
               "start_monotonic_ns": 100, "end_monotonic_ns": 10_000_100,
               "end_realtime_unix_ns": first_unix + 8_000_000,
               "start_pairing_uncertainty_ns": 100, "end_pairing_uncertainty_ns": 100}
    return run, packets, trace, anchors


def change_run(path, mutate):
    value = json.loads(path.read_text())
    mutate(value)
    path.write_text(json.dumps(value))


def test_tail_is_bound_to_each_actual_endpoint_drain(tmp_path):
    run, packets, trace, anchors = artifacts(tmp_path)
    result = reconcile_direct_runner_artifacts(run, packets, trace, clock_anchors=anchors)
    assert result.evidence_eligible
    assert result.metrics["direct_matched_packets"] == 4
    assert result.metrics["direct_unmatched_tail_packets"] == 2
    assert result.metrics["direct_endpoint_receive_tail_packets"] == 2
    assert result.metrics["direct_tail_policy"] == "native-final-udp-receive-drain-v1"


def test_legacy_run_cannot_gain_endpoint_tail_authority(tmp_path):
    run, packets, trace, anchors = artifacts(tmp_path)
    change_run(run, lambda value: [endpoint.pop("receive_lifecycle") for endpoint in value["endpoints"]])
    with pytest.raises(ValueError, match="before the runner-correlated capture tail"):
        reconcile_direct_runner_artifacts(run, packets, trace, clock_anchors=anchors)


@pytest.mark.parametrize("mutation,pattern", [
    (lambda value: value["endpoints"][0]["receive_lifecycle"].update(polling_stopped_at_unix_ns=1_003_500_001), "before its endpoint final drain"),
    (lambda value: value["endpoints"][0]["receive_lifecycle"].update(polling_stopped_at_elapsed_ns=1_999_999), "stale"),
    (lambda value: value["endpoints"][0]["receive_lifecycle"].update(polling_stopped_at_unix_ns=1_006_000_000), "outside the run"),
    (lambda value: value["endpoints"][0]["receive_lifecycle"].update(source="guessed-last-packet"), "schema or source"),
    (lambda value: value["endpoints"][0]["receive_lifecycle"].update(schema_version=True), "schema or source"),
    (lambda value: value["endpoints"][0].pop("receive_lifecycle"), "fields differ"),
    (lambda value: value["endpoints"][0]["receive_lifecycle"].update(disposition="bounded_one_batch"), "unproven"),
])
def test_invalid_receive_boundaries_cannot_authorize_a_tail(tmp_path, mutation, pattern):
    run, packets, trace, anchors = artifacts(tmp_path)
    change_run(run, mutation)
    with pytest.raises(ValueError, match=pattern):
        reconcile_direct_runner_artifacts(run, packets, trace, clock_anchors=anchors)


@pytest.mark.parametrize("damage,pattern", [
    (lambda text: text.replace("3500000,incoming,74,-74,0", "3500000,outgoing,74,74,0"), "unrecorded outgoing"),
    (lambda text: text.replace("3500000,incoming,74,-74,0", "3500000,incoming,74,-74,9"), "unknown endpoint"),
    (lambda text: text.replace("3500000,incoming,74,-74,0,1003500000", "3500000,incoming,74,-74,0,1003500001"), "timestamps differ"),
    (lambda text: text.replace("1000000,incoming,1242,-1242,0,1001000000\n", ""), "no frame for runner"),
])
def test_tail_does_not_hide_missing_or_misattributed_packets(tmp_path, damage, pattern):
    run, packets, trace, anchors = artifacts(tmp_path)
    trace.write_text(damage(trace.read_text()))
    with pytest.raises(ValueError, match=pattern):
        reconcile_direct_runner_artifacts(run, packets, trace, clock_anchors=anchors)


@pytest.mark.parametrize("anchors_damage,pattern", [
    (lambda anchors: None, "requires wrapper clock anchors"),
    (lambda anchors: {key: value for key, value in anchors.items() if key != "start_pairing_uncertainty_ns"}, "invalid fields"),
    (lambda anchors: {**anchors, "end_realtime_unix_ns": anchors["end_realtime_unix_ns"] + 20_000_000}, "elapsed difference"),
])
def test_endpoint_tail_requires_sealed_stable_host_clocks(tmp_path, anchors_damage, pattern):
    run, packets, trace, anchors = artifacts(tmp_path)
    with pytest.raises(ValueError, match=pattern):
        reconcile_direct_runner_artifacts(run, packets, trace, clock_anchors=anchors_damage(anchors))


def test_bounded_exact_mode_metadata_retains_strict_global_tail(tmp_path):
    run, packets, trace, anchors = artifacts(tmp_path)
    def bounded(value):
        for endpoint in value["endpoints"]:
            endpoint["receive_lifecycle"].update(disposition="bounded_one_batch",
                                                polling_stopped_at_elapsed_ns=None,
                                                polling_stopped_at_unix_ns=None)
    change_run(run, bounded)
    with pytest.raises(ValueError, match="before the runner-correlated capture tail"):
        reconcile_direct_runner_artifacts(run, packets, trace, clock_anchors=anchors)


def test_endpoint_matching_remains_strict_without_tail_authority(tmp_path):
    run, packets, trace, anchors = artifacts(tmp_path)
    change_run(run, lambda value: [endpoint.pop("receive_lifecycle") for endpoint in value["endpoints"]])
    packets.write_text(packets.read_text().replace("3000,1,1200", "3000,1,1258")
                       .replace("5000,1,1200", "5000,1,1258"))
    lines = trace.read_text().splitlines()
    lines = [line.replace("1242,1242,1", "1300,1300,1")
             .replace("1242,-1242,1", "1300,-1300,1") for line in lines if ",74," not in line]
    trace.write_text("\n".join(lines) + "\n")
    assert reconcile_direct_runner_artifacts(run, packets, trace, clock_anchors=anchors).evidence_eligible
    swapped = []
    for line in lines[1:]:
        row = line.split(",")
        row[4] = str(1 - int(row[4]))
        swapped.append(",".join(row))
    trace.write_text(lines[0] + "\n" + "\n".join(swapped) + "\n")
    with pytest.raises(ValueError, match="no frame for runner packet"):
        reconcile_direct_runner_artifacts(run, packets, trace, clock_anchors=anchors)
