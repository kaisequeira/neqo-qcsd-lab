from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import qcsd_lab.buflo_handoff as handoff_module
import qcsd_lab.buflo_study as study_module

import qcsd_lab.buflo_handoff as handoff

from qcsd_lab.buflo_handoff import (
    FORMAL_RESULT_NAMES,
    _algorithm_diagnostics,
    _performance_metadata,
    _read_shape_only_pcap,
    _validate_handoff_sample_correctness,
    _validate_formal_sample_redirect_attestation,
    _validate_runner_extension,
    _validate_run_sample_binding,
    _write_checksums,
    _write_shape_only_pcap,
    validate_study_handoff,
)
from qcsd_lab.capture import ObserverPacket
from qcsd_lab.fidelity import SCHEDULE_QCSD_FIELDS
from qcsd_lab.orchestrator import Workload, _redirect_attestation
from qcsd_lab.verification import VerifiedResult


def _packet(relative_time_ns: int, direction: str, frame_len: int) -> ObserverPacket:
    signed = frame_len if direction == "outgoing" else -frame_len
    return ObserverPacket(
        timestamp_unix_ns=1_000_000_000 + relative_time_ns,
        relative_time_ns=relative_time_ns,
        direction=direction,
        frame_len=frame_len,
        signed_frame_len=signed,
    )


def test_shape_only_pcap_round_trip(tmp_path: Path) -> None:
    trace = (
        _packet(0, "outgoing", 1_242),
        _packet(8_192_123, "incoming", 642),
        _packet(2_000_000_000, "outgoing", 100),
    )
    path = tmp_path / "shape.pcap"

    _write_shape_only_pcap(trace, path)

    assert _read_shape_only_pcap(path) == tuple(
        (packet.relative_time_ns, packet.direction, packet.frame_len) for packet in trace
    )
    assert b"192.0.2.1" not in path.read_bytes()


def test_shape_only_pcap_rejects_non_monotonic_input(tmp_path: Path) -> None:
    trace = (
        _packet(10, "outgoing", 100),
        _packet(9, "incoming", 100),
    )
    with pytest.raises(ValueError, match="not monotonic"):
        _write_shape_only_pcap(trace, tmp_path / "shape.pcap")


def test_runner_extension_accepts_current_exact_packet_composition() -> None:
    row = {field: "" for field in SCHEDULE_QCSD_FIELDS}
    row.update(
        qcsd_outcome_schema_version="2",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        application_stream_bytes="900",
        retransmission_stream_bytes="100",
        chaff_stream_bytes="100",
        defense_control_bytes="0",
        quic_padding_bytes="50",
        other_quic_bytes="50",
        lateness_us="4",
    )
    _validate_runner_extension(row, label="packets.csv row")
    row["chaff_stream_bytes"] = "99"
    with pytest.raises(ValueError, match="composition"):
        _validate_runner_extension(row, label="packets.csv row")


@pytest.mark.parametrize("detailed", [False, True])
def test_nonformal_handoff_closed_inventory(tmp_path: Path, detailed: bool) -> None:
    root = tmp_path / "handoff"
    directories = [root / "raw", root / "stripped", root / "traces"]
    if detailed:
        directories.append(root / "diagnostics")
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    trace = root / "traces/sample.csv"
    trace.write_text(
        "relative_time_ns,direction,length_bytes,signed_length_bytes\n"
        "0,outgoing,1242,1242\n"
        "100,incoming,642,-642\n",
        encoding="utf-8",
    )
    import hashlib

    artifacts = {
        "raw_pcapng_path": "raw/sample.pcapng",
        "raw_pcap_path": "raw/sample.pcap",
        "raw_run_path": "raw/sample.run.json",
        "shape_pcap_path": "stripped/sample.pcap",
        "trace_path": "traces/sample.csv",
    }
    for key, relative in artifacts.items():
        if key != "trace_path":
            (root / relative).write_bytes(
                b"{}\n" if detailed and key == "raw_run_path" else key.encode()
            )
    digests = {
        key.replace("_path", "_sha256"): hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for key, relative in artifacts.items()
    }
    row = {
        "schema_version": 1,
        "sample_id": "sample",
        "class_label": "example-r1",
        "workload_id": "example-r1",
        "defense": "buflo",
        "runtime_kind": "buflo",
        "baseline": False,
        "request_policy": "as-defined",
        "visit": 1,
        "seed": 2,
        "attempts": 1,
        "acquisition_block_index": 0,
        "acquisition_block_id": "acquisition-block-001",
        "split": "train",
        "paired_visit_id": "block-001/example-r1/as-defined/visit-001",
        "source_result": "test-result",
        "source_sample_path": "samples/example-r1/as-defined/visit-001/buflo",
        **artifacts,
        **digests,
        "packet_count": 2,
        "performance": None,
        "input_bindings": {
            "campaign_sha256": "1" * 64,
            "application_workload_sha256": "2" * 64,
            "runtime_workload_sha256": "3" * 64,
            "chaff_qualification_sha256": "4" * 64,
            "chaff_manifest_sha256": "5" * 64,
            "defense_parameters_sha256": "6" * 64,
            "defense_parameters_provenance_sha256": "7" * 64,
            "max_response_bytes": 1_048_576,
            "max_udp_payload_size": 1_200,
        },
    }
    if detailed:
        suffix = (
            "qcsd_outcome_schema_version,send_policy,desired_udp_bytes,"
            "observed_udp_bytes,application_stream_bytes,retransmission_stream_bytes,"
            "chaff_stream_bytes,defense_control_bytes,quic_padding_bytes,other_quic_bytes,"
            "lateness_us,congestion_reason,credit_advertised_at_us,"
            "credit_advertisement_delay_us,credit_consumed_at_us,"
            "credit_consumption_delay_us\n"
        )
        schedule = root / "diagnostics/sample.schedule.csv"
        events = root / "diagnostics/sample.events.csv"
        packets = root / "diagnostics/sample.packets.csv"
        schedule.write_text(
            "target_time_us,direction,size,connection,action_time_us,satisfaction,"
            "observed_size,miss_reason,slot_id,"
            + suffix
            + "0,outgoing,1200,0,0,satisfied,1200,,0,1,exact,1200,1200,,,,,,,,,,,,\n"
            + "0,incoming,1200,0,0,satisfied,,,1,2,exact,1200,,,,,,,,,,100,100,500,500\n",
            encoding="utf-8",
        )
        events.write_text(
            "monotonic_us,connection,event,outcome,details," + suffix,
            encoding="utf-8",
        )
        packets.write_text(
            "direction,monotonic_us,connection,observed_udp_length,scheduled_target,"
            "satisfaction,slot_id,"
            + suffix,
            encoding="utf-8",
        )
        diagnostics_artifacts = {
            "runner_schedule_path": "diagnostics/sample.schedule.csv",
            "runner_events_path": "diagnostics/sample.events.csv",
            "runner_packets_path": "diagnostics/sample.packets.csv",
        }
        row.update(diagnostics_artifacts)
        row.update(
            {
                key.replace("_path", "_sha256"): hashlib.sha256(
                    (root / relative).read_bytes()
                ).hexdigest()
                for key, relative in diagnostics_artifacts.items()
            }
        )
        row["algorithm_diagnostics"] = _algorithm_diagnostics(
            {},
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    (root / "samples.jsonl").write_text(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    (root / "dataset.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_type": "qcsd-buflo-csbuflo-study-handoff",
                "purpose": "buflo-csbuflo-focused-evaluation",
                "formal": False,
                "paper_equivalent": False,
                "implementation_scope": "client_only_quic",
                "result_names": ["test-result"],
                "blocks": [
                    {
                        "acquisition_block_index": 0,
                        "acquisition_block_id": "acquisition-block-001",
                        "split": "train",
                        "result_name": "test-result",
                        "result_root": "/test/result",
                        "result_evidence_sha256": "0" * 64,
                        "authoritative_files": 1,
                        "campaign_path": None,
                        "campaign_sha256": "1" * 64,
                        "configuration": {"campaign_sha256": "1" * 64},
                        "configuration_sha256": (
                            "813674db0efcfd612766349adc393983af6f4963e4100e22934d15b7aae2e83e"
                        ),
                    }
                ],
                "sample_count": 1,
                "classes": ["example-r1"],
                "defenses": ["buflo"],
                "counts_by_defense": {"buflo": 1},
                "counts_by_split": {"train": 1},
                "observation": {
                    "length_basis": "Ethernet frame.len",
                    "direction_rule": "client egress positive; server ingress negative",
                    "model_input": "traces/*.csv or stripped/*.pcap",
                    "raw_restricted": True,
                },
                "execution_source": {},
                "exporter_source": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text("test\n", encoding="utf-8")
    _write_checksums(root)

    assert validate_study_handoff(root, formal=False, deep=False) == root.resolve()

    trace.write_text(trace.read_text(encoding="utf-8") + "1,outgoing,42,42\n", encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_study_handoff(root, formal=False, deep=False)


def test_formal_result_names_are_ten_ordered_blocks() -> None:
    assert len(FORMAL_RESULT_NAMES) == 10
    assert FORMAL_RESULT_NAMES[0].endswith("formal-01-1200")
    assert FORMAL_RESULT_NAMES[-1].endswith("formal-10-1200")


@pytest.mark.parametrize("mutation", ["missing", "altered"])
def test_formal_redirect_attestation_tampering_blocks_source_validation(
    tmp_path: Path,
    mutation: str,
) -> None:
    data = {
        "preparation": {
            "source_url": "https://example.com/",
            "final_url": "https://example.com/",
            "expected_responses": [{"resource_id": 0, "status": 200}],
        },
        "resources": [{"id": 0, "url": "https://example.com/"}],
    }
    sample_path = tmp_path / "samples/example/as-defined/visit-001/undefended"
    neqo = sample_path / "neqo"
    neqo.mkdir(parents=True)
    (neqo / "run.json").write_text(
        json.dumps(
            {
                "responses": [
                    {
                        "resource_id": 0,
                        "url": "https://example.com/",
                        "status": 200,
                        "complete": True,
                        "outcome": "succeeded",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    workload = SimpleNamespace(id="example-r1", data=data)
    receipt = _redirect_attestation(workload, sample_path)
    _validate_formal_sample_redirect_attestation(
        {"redirect_attestation": receipt}, workload, sample_path
    )

    diagnostics = (
        {}
        if mutation == "missing"
        else {
            "redirect_attestation": {
                **receipt,
                "all_redirect_sequences_empty": False,
            }
        }
    )
    with pytest.raises(ValueError, match="explicitly attest empty"):
        _validate_formal_sample_redirect_attestation(diagnostics, workload, sample_path)


@pytest.mark.parametrize("mutation", ["missing", "altered"])
def test_formal_source_result_rejects_redirect_attestation_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    data = {
        "preparation": {
            "source_url": "https://example.com/",
            "final_url": "https://example.com/",
            "expected_responses": [{"resource_id": 0, "status": 200}],
        },
        "resources": [{"id": 0, "url": "https://example.com/"}],
    }
    workload_bytes = (json.dumps(data, sort_keys=True) + "\n").encode()
    workload_digest = hashlib.sha256(workload_bytes).hexdigest()
    checked_workload = tmp_path / "checked-workload.json"
    checked_workload.write_bytes(workload_bytes)
    workload = Workload(
        id="example-r1",
        visits=1,
        path=checked_workload,
        source_bytes=workload_bytes,
        sha256=workload_digest,
        data=data,
        resource_count=1,
        origin_count=1,
    )
    campaign = SimpleNamespace(name="formal-test", workloads=(workload,))
    root = tmp_path / "result"
    sealed_workload = root / "inputs/workloads/example-r1.json"
    sealed_workload.parent.mkdir(parents=True)
    sealed_workload.write_bytes(workload_bytes)
    sample_path = root / "samples/example-r1/as-defined/visit-001/undefended"
    neqo = sample_path / "neqo"
    neqo.mkdir(parents=True)
    (neqo / "run.json").write_text(
        json.dumps(
            {
                "responses": [
                    {
                        "resource_id": 0,
                        "url": "https://example.com/",
                        "status": 200,
                        "complete": True,
                        "outcome": "succeeded",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    redirect_receipt = _redirect_attestation(workload, sample_path)
    sample = {
        "sample_id": "sample-001",
        "workload_id": "example-r1",
        "request_policy": "as-defined",
        "visit": 1,
        "defense": "undefended",
        "runtime_kind": "none",
        "baseline": True,
        "seed": 7,
        "path": "samples/example-r1/as-defined/visit-001/undefended",
        "state": "accepted",
        "eligible": True,
        "attempts": 1,
        "diagnostics": {"redirect_attestation": redirect_receipt},
    }
    experiment = {
        "name": "formal-test",
        "purpose": "evaluation",
        "status": "complete",
        "configuration": {},
        "source": {},
        "samples": [sample],
        "summary": {
            "planned": 1,
            "accepted": 1,
            "eligible": 1,
            "failed": 0,
            "passed": True,
        },
        "started_at": "2027-01-01T00:00:00+00:00",
        "completed_at": "2027-01-01T00:00:01+00:00",
    }
    verified = VerifiedResult(root=root, experiment=experiment, checksums={}, accepted_samples={})

    monkeypatch.setattr(handoff_module, "FORMAL_BLOCKS", (0,))
    monkeypatch.setattr(handoff_module, "FORMAL_RESULT_NAMES", ("formal-test",))
    monkeypatch.setattr(handoff_module, "FORMAL_DEFENSES", ("undefended",))
    monkeypatch.setattr(handoff_module, "CLASS_LABELS", {"example-r1": "example"})
    monkeypatch.setattr(handoff_module, "_FORMAL_DYNAMIC_CONFIGURATION_KEYS", set())
    monkeypatch.setattr(
        handoff_module,
        "_formal_campaign_path_for_result",
        lambda _receipt, _index: tmp_path / "campaign.yml",
    )
    monkeypatch.setattr(
        handoff_module,
        "_expected_formal_configuration",
        lambda _path: (campaign, {}),
    )
    monkeypatch.setattr(
        handoff_module,
        "_validate_formal_result_admission",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(handoff_module, "plan_campaign", lambda _campaign: [sample])
    monkeypatch.setattr(handoff_module, "_immutable_source", lambda _source: True)
    monkeypatch.setattr(handoff_module, "_formal_temporal_proof", lambda _blocks: {})
    monkeypatch.setattr(study_module, "_validate_public_network_condition", lambda _value: None)

    handoff_module._validate_source_results((verified,), formal=True)
    if mutation == "missing":
        sample["diagnostics"] = {}
    else:
        sample["diagnostics"] = {
            "redirect_attestation": {
                **redirect_receipt,
                "all_redirect_sequences_empty": False,
            }
        }
    with pytest.raises(ValueError, match="explicitly attest empty"):
        handoff_module._validate_source_results((verified,), formal=True)


def test_performance_metadata_binds_trace_run_and_resource_usage() -> None:
    trace = (
        ObserverPacket(1, 0, "outgoing", 1_242, 1_242, 1_200),
        ObserverPacket(2, 100, "incoming", 642, -642, 600),
    )
    usage = {
        "schema_version": 1,
        "source": "gnu-time-v",
        "user_cpu_seconds": 0.1,
        "system_cpu_seconds": 0.2,
        "wall_time_seconds": 1.0,
        "maximum_rss_bytes": 123_000,
        "voluntary_context_switches": 2,
        "involuntary_context_switches": 3,
        "timer_wakeups": None,
        "timer_wakeups_unavailable_reason": "unavailable in container",
        "rapl_energy_joules": None,
        "rapl_unavailable_reason": "unavailable in container",
    }
    run = {
        "defense_start_monotonic_ns": 1_000,
        "application_completion_monotonic_ns": 2_001_000,
        "responses": [{"bytes": 400}, {"bytes": 600}],
        "client_resource_usage": usage,
        "endpoints": [{"transport_stats": "  tx: 20 lost 4 lateack 0\n"}],
    }

    performance = _performance_metadata(run, trace)

    assert performance["application_duration_ns"] == 2_000_000
    assert performance["application_response_bytes"] == 1_000
    assert performance["udp_payload_bytes"] == {"outgoing": 1_200, "incoming": 600}
    assert performance["transport_retransmissions"] == 4


def test_raw_run_binding_covers_workload_chaff_parameters_and_limits() -> None:
    bindings = {
        "campaign_sha256": "1" * 64,
        "application_workload_sha256": "2" * 64,
        "runtime_workload_sha256": "3" * 64,
        "chaff_qualification_sha256": "4" * 64,
        "chaff_manifest_sha256": "5" * 64,
        "defense_parameters_sha256": "6" * 64,
        "defense_parameters_provenance_sha256": "7" * 64,
        "max_response_bytes": 1_048_576,
        "max_udp_payload_size": 1_200,
    }
    sample = {
        "seed": 9,
        "request_policy": "as-defined",
        "runtime_kind": "buflo",
        "baseline": False,
    }
    run = {
        "completion_status": "complete",
        "error": None,
        "seed": 9,
        "request_policy": "as-defined",
        "workload_hash_sha256": "3" * 64,
        "application_workload_source_hash_sha256": "2" * 64,
        "chaff_manifest_hash_sha256": "5" * 64,
        "max_response_bytes": 1_048_576,
        "resolved_configuration": {
            "max_udp_payload_size": 1_200,
            "defense": {"kind": "buflo"},
        },
        "defense_parameters": {
            "kind": "buflo",
            "path": "/sealed/parameters.json",
            "sha256": "6" * 64,
        },
    }

    _validate_run_sample_binding(run, sample, bindings)

    run["workload_hash_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="accepted sample"):
        _validate_run_sample_binding(run, sample, bindings)
    run["workload_hash_sha256"] = "3" * 64
    run["chaff_manifest_hash_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="defended run"):
        _validate_run_sample_binding(run, sample, bindings)


def test_handoff_recomputes_prepared_response_identity(tmp_path: Path) -> None:
    workload = tmp_path / "workload.json"
    workload.write_text(
        json.dumps(
            {
                "preparation": {
                    "expected_responses": [
                        {
                            "resource_id": 0,
                            "status": 200,
                            "bytes": 4,
                            "body_sha256": "a" * 64,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    row = {
        "workload_id": "example-r1",
        "defense": "undefended",
        "runtime_kind": "none",
    }
    run = {
        "responses": [
            {
                "resource_id": 0,
                "status": 200,
                "bytes": 4,
                "body_sha256": "a" * 64,
                "complete": True,
                "outcome": "succeeded",
            }
        ],
        "defense_diagnostics": {},
    }

    _validate_handoff_sample_correctness(
        row,
        run=run,
        workload_path=workload,
        schedule_path=tmp_path / "absent-schedule.csv",
        formal=False,
    )
    run["responses"][0]["body_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="response/fidelity"):
        _validate_handoff_sample_correctness(
            row,
            run=run,
            workload_path=workload,
            schedule_path=tmp_path / "absent-schedule.csv",
            formal=False,
        )


def test_export_destination_cannot_overlap_result_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result_root = tmp_path / "result"
    result_root.mkdir()
    monkeypatch.setattr(handoff, "verify_result", lambda root: SimpleNamespace(root=Path(root)))
    monkeypatch.setattr(handoff, "_validate_source_results", lambda *args, **kwargs: None)

    with pytest.raises(ValueError, match="overlaps protected input"):
        handoff.export_study_handoff(
            (result_root,),
            result_root / "handoff",
            formal=False,
        )
