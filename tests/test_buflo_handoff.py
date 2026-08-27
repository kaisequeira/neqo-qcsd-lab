from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import qcsd_lab.buflo_handoff as handoff
import qcsd_lab.buflo_handoff as handoff_module
import qcsd_lab.buflo_study as study_module
from qcsd_lab.buflo_handoff import (
    FORMAL_RESULT_NAMES,
    _algorithm_diagnostics,
    _performance_metadata,
    _read_shape_only_pcap,
    _validate_formal_sample_redirect_attestation,
    _validate_handoff_sample_correctness,
    _validate_run_sample_binding,
    _validate_runner_extension,
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


def _complete_buflo_run(
    *,
    scheduled_outgoing: int,
    scheduled_incoming: int,
    stream_cancellations: int = 0,
    cancelled_capacity: int = 0,
    pending_parser_boundaries: int = 0,
) -> dict[str, object]:
    diagnostics = {
        "buflo_scheduled_outgoing_cells": scheduled_outgoing,
        "buflo_scheduled_incoming_cells": scheduled_incoming,
        "buflo_full_outgoing_cells": scheduled_outgoing,
        "buflo_partial_outgoing_cells": 0,
        "buflo_suppressed_outgoing_cells": 0,
        "buflo_missed_outgoing_cells": 0,
        "buflo_missed_incoming_cells": 0,
        "buflo_outgoing_unresolved_cells": 0,
        "buflo_incoming_unresolved_cells": 0,
        "buflo_catch_up_outgoing_cells": 0,
        "buflo_catch_up_incoming_cells": 0,
        "buflo_terminal_subcell_pending_request_cancellations": 0,
        "buflo_terminal_subcell_stream_cancellations": stream_cancellations,
        "buflo_terminal_subcell_exact_capacity_bytes_cancelled": cancelled_capacity,
        "buflo_terminal_subcell_latched": True,
        "buflo_terminal_subcell_latched_at_us": 10_000_001,
        "buflo_terminal_subcell_open_streams_at_latch": stream_cancellations,
        "buflo_terminal_subcell_parser_lease_bytes_at_latch": 0,
        "buflo_terminal_subcell_pending_parser_boundaries_at_latch": (
            pending_parser_boundaries
        ),
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch": 0,
        "buflo_paper_equivalent": False,
        "buflo_client_only": True,
        "buflo_egress_backlog_pending": False,
        "buflo_application_complete": True,
        "buflo_minimum_duration_reached": True,
        "buflo_event_guard_triggered": False,
    }
    return {
        "completion_status": "complete",
        "error": None,
        "resolved_configuration": {
            "schema_version": 2,
            "defense": {"kind": "buflo"},
        },
        "runner_wakeup_metrics": {
            "schema_version": 1,
            "semantics": (
                "actual_select_return_source; socket_wins_simultaneous_readiness; "
                "controller_subset_is_effective_earliest_deadline; "
                "scheduled_cells_are_not_wakeups"
            ),
            "wait_returns": 0,
            "socket_readiness_wakeups": 0,
            "timer_wakeups": 0,
            "controller_deadline_timer_wakeups": 0,
            "other_timer_wakeups": 0,
        },
        "defense_diagnostics": diagnostics,
        "chaff_responses": [
            {"outcome": "buflo_terminal_subcell_tail_cancelled"}
            for _ in range(stream_cancellations)
        ],
        "buflo_summary": {
            "schema_version": 3,
            "kind": "buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": False,
            "incoming_opportunity_semantics": (
                "client_receive_credit_and_response_qualified_chaff_attempt"
            ),
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "terminal_subcell_policy": (
                "drain_whole_cells_then_client_local_http3_cancel_"
                "unallocatable_reviewed_chaff_tail"
            ),
            "terminal_subcell_observer_effect": (
                "typed_stop_sending_and_reset_stream_defense_control_may_follow_"
                "the_last_exact_cell"
            ),
            "diagnostics": diagnostics,
        },
        "cs_buflo_summary": None,
    }


def _formal_source_binding_fixture(tmp_path: Path) -> tuple[
    Path,
    dict[str, object],
    list[dict[str, object]],
    dict[str, str],
    VerifiedResult,
]:
    source_root = (tmp_path / "formal-result").resolve()
    source_sample_relative = "samples/example-r1/as-defined/visit-001/buflo"
    source_sample_root = source_root / source_sample_relative
    (source_sample_root / "neqo").mkdir(parents=True)
    source_files = {
        "capture.pcapng": b"sealed-pcapng\n",
        "neqo/run.json": b'{"completion_status":"complete"}\n',
        "neqo/schedule.csv": b"target_time_us\n0\n",
        "neqo/events.csv": b"monotonic_us\n0\n",
        "neqo/packets.csv": b"monotonic_us\n0\n",
    }
    for relative, content in source_files.items():
        path = source_sample_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    workload_relative = "inputs/workloads/example-r1.json"
    workload = source_root / workload_relative
    workload.parent.mkdir(parents=True)
    workload.write_bytes(b'{"id":"example-r1"}\n')

    checksums = {
        f"{source_sample_relative}/{relative}": hashlib.sha256(content).hexdigest()
        for relative, content in source_files.items()
    }
    checksums[workload_relative] = hashlib.sha256(workload.read_bytes()).hexdigest()
    evidence = source_root / "evidence.sha256"
    evidence.write_text(
        "".join(f"{checksums[path]}  {path}\n" for path in sorted(checksums)),
        encoding="utf-8",
    )

    sample = {
        "sample_id": "sample-001",
        "workload_id": "example-r1",
        "request_policy": "as-defined",
        "visit": 1,
        "defense": "buflo",
        "runtime_kind": "buflo",
        "baseline": False,
        "seed": 7,
        "attempts": 1,
        "path": source_sample_relative,
    }
    source = {"immutable": True}
    experiment = {
        "name": "formal-test",
        "configuration": {"campaign_sha256": "1" * 64},
        "source": source,
        "samples": [sample],
        "started_at": "2027-01-01T00:00:00+00:00",
        "completed_at": "2027-01-01T00:00:01+00:00",
    }
    receipt = VerifiedResult(
        root=source_root,
        experiment=experiment,
        checksums=checksums,
        accepted_samples={
            "sample-001": {
                relative: digest
                for relative, digest in checksums.items()
                if relative.startswith(f"{source_sample_relative}/")
            }
        },
    )

    handoff_root = (tmp_path / "handoff").resolve()
    local_bindings = {
        "raw_pcapng_path": ("raw/sample-001.pcapng", "capture.pcapng"),
        "raw_run_path": ("raw/sample-001.run.json", "neqo/run.json"),
        "runner_schedule_path": (
            "diagnostics/sample-001.schedule.csv",
            "neqo/schedule.csv",
        ),
        "runner_events_path": (
            "diagnostics/sample-001.events.csv",
            "neqo/events.csv",
        ),
        "runner_packets_path": (
            "diagnostics/sample-001.packets.csv",
            "neqo/packets.csv",
        ),
    }
    row: dict[str, object] = dict(sample)
    row["source_sample_path"] = row.pop("path")
    handoff_checksums: dict[str, str] = {}
    for path_key, (local_relative, source_suffix) in local_bindings.items():
        destination = handoff_root / local_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((source_sample_root / source_suffix).read_bytes())
        digest_key = path_key.replace("_path", "_sha256")
        row[path_key] = local_relative
        row[digest_key] = checksums[f"{source_sample_relative}/{source_suffix}"]
        handoff_checksums[local_relative] = str(row[digest_key])
    application_relative = "inputs/acquisition-block-001/example-r1.json"
    application = handoff_root / application_relative
    application.parent.mkdir(parents=True)
    application.write_bytes(workload.read_bytes())
    row["application_workload_path"] = application_relative
    row["application_workload_sha256"] = checksums[workload_relative]
    row["acquisition_block_index"] = 0
    handoff_checksums[application_relative] = checksums[workload_relative]

    dataset: dict[str, object] = {
        "execution_source": source,
        "blocks": [
            {
                "acquisition_block_index": 0,
                "result_name": "formal-test",
                "result_root": str(source_root),
                "result_evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                "authoritative_files": len(checksums),
                "configuration": experiment["configuration"],
                "started_at": experiment["started_at"],
                "completed_at": experiment["completed_at"],
                "elapsed_seconds": 1.0,
            }
        ],
    }
    return handoff_root, dataset, [row], handoff_checksums, receipt


def _install_formal_source_verifier(
    monkeypatch: pytest.MonkeyPatch,
    receipt: VerifiedResult,
) -> list[Path]:
    verified_roots: list[Path] = []

    def verify(root: Path) -> VerifiedResult:
        verified_roots.append(Path(root))
        return receipt

    monkeypatch.setattr(handoff, "FORMAL_BLOCKS", (0,))
    monkeypatch.setattr(handoff, "verify_result", verify)
    monkeypatch.setattr(handoff, "_validate_source_results", lambda *_args, **_kwargs: None)
    return verified_roots


def test_formal_handoff_reverifies_and_binds_authoritative_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, dataset, rows, checksums, receipt = _formal_source_binding_fixture(tmp_path)
    verified_roots = _install_formal_source_verifier(monkeypatch, receipt)

    handoff._validate_formal_source_bindings(
        root,
        dataset,
        rows,
        handoff_checksums=checksums,
    )

    assert verified_roots == [receipt.root]


def test_public_formal_handoff_validation_rechecks_sources_when_not_deep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, dataset, rows, _checksums, receipt = _formal_source_binding_fixture(tmp_path)
    verified_roots = _install_formal_source_verifier(monkeypatch, receipt)
    for directory in ("stripped", "traces"):
        (root / directory).mkdir(parents=True)
    (root / "README.md").write_text("formal test handoff\n", encoding="utf-8")
    dataset.update(
        {
            "formal": True,
            "result_names": ["formal-test"],
            "counts_by_defense": {"buflo": 1},
        }
    )
    rows[0].update(schema_version=1, packet_count=0)
    (root / "dataset.json").write_text(
        json.dumps(dataset, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "samples.jsonl").write_text(
        json.dumps(rows[0], sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _write_checksums(root)

    sample = SimpleNamespace(sample_id="sample-001", defense="buflo", trace=())
    monkeypatch.setattr(handoff, "_validate_handoff_rows", lambda *_args, **_kwargs: (True, False))
    monkeypatch.setattr(handoff, "_validate_dataset", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handoff, "load_study_handoff", lambda _root: (sample,))
    monkeypatch.setattr(handoff, "validate_formal_cohort", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handoff, "FORMAL_RESULT_NAMES", ("formal-test",))

    assert validate_study_handoff(root, formal=True, deep=False) == root
    assert verified_roots == [receipt.root]


@pytest.mark.parametrize(
    ("path_key", "digest_key"),
    [
        ("raw_pcapng_path", "raw_pcapng_sha256"),
        ("raw_run_path", "raw_run_sha256"),
        ("runner_schedule_path", "runner_schedule_sha256"),
        ("runner_events_path", "runner_events_sha256"),
        ("runner_packets_path", "runner_packets_sha256"),
        ("application_workload_path", "application_workload_sha256"),
    ],
)
def test_formal_handoff_rejects_rechecksummed_source_copy_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path_key: str,
    digest_key: str,
) -> None:
    root, dataset, rows, checksums, receipt = _formal_source_binding_fixture(tmp_path)
    _install_formal_source_verifier(monkeypatch, receipt)
    row = rows[0]
    local_relative = str(row[path_key])
    (root / local_relative).write_bytes(b"locally substituted and rechecksummed\n")
    substituted_digest = hashlib.sha256((root / local_relative).read_bytes()).hexdigest()
    row[digest_key] = substituted_digest
    checksums[local_relative] = substituted_digest

    with pytest.raises(ValueError, match="differs from its sealed source artifact"):
        handoff._validate_formal_source_bindings(
            root,
            dataset,
            rows,
            handoff_checksums=checksums,
        )


@pytest.mark.parametrize("binding", ["result_evidence_sha256", "authoritative_files"])
def test_formal_handoff_rejects_result_seal_binding_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    binding: str,
) -> None:
    root, dataset, rows, checksums, receipt = _formal_source_binding_fixture(tmp_path)
    _install_formal_source_verifier(monkeypatch, receipt)
    block = dataset["blocks"][0]
    assert isinstance(block, dict)
    block[binding] = "0" * 64 if binding.endswith("sha256") else 999

    with pytest.raises(ValueError, match="source result seal or lineage differs"):
        handoff._validate_formal_source_bindings(
            root,
            dataset,
            rows,
            handoff_checksums=checksums,
        )


def test_formal_handoff_rejects_noncanonical_source_result_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, dataset, rows, checksums, receipt = _formal_source_binding_fixture(tmp_path)
    verified_roots = _install_formal_source_verifier(monkeypatch, receipt)
    alias = tmp_path / "result-alias"
    alias.symlink_to(receipt.root, target_is_directory=True)
    block = dataset["blocks"][0]
    assert isinstance(block, dict)
    block["result_root"] = str(alias)

    with pytest.raises(ValueError, match="source result root is not canonical"):
        handoff._validate_formal_source_bindings(
            root,
            dataset,
            rows,
            handoff_checksums=checksums,
        )
    assert verified_roots == []


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
    buflo_run = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=1,
    )
    for key, relative in artifacts.items():
        if key != "trace_path":
            (root / relative).write_bytes(
                (
                    (json.dumps(buflo_run, sort_keys=True) + "\n").encode()
                    if detailed and key == "raw_run_path"
                    else key.encode()
                )
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
            + suffix
            + "outgoing,0,0,1200,1200,satisfied,0,2,exact,1200,1200,0,0,1200,0,0,0,0,,,,,\n",
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
            buflo_run,
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


def test_buflo_algorithm_diagnostics_bind_typed_tail_action_and_control_packet(
    tmp_path: Path,
) -> None:
    schedule = tmp_path / "schedule.csv"
    events = tmp_path / "events.csv"
    packets = tmp_path / "packets.csv"

    def write_rows(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
        with path.open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    schedule_fields = (*handoff.SCHEDULE_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    schedule_row = {field: "" for field in schedule_fields}
    schedule_row.update(
        target_time_us="0",
        direction="outgoing",
        size="1200",
        connection="0",
        action_time_us="0",
        satisfaction="satisfied",
        observed_size="1200",
        slot_id="1",
        qcsd_outcome_schema_version="1",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
    )
    write_rows(schedule, schedule_fields, [schedule_row])

    event_fields = (*handoff._EVENT_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    event_row = {field: "" for field in event_fields}
    event_row.update(
        monotonic_us="10000010",
        connection="0",
        event="action",
        outcome="applied",
        details=json.dumps(
            {
                "type": "cancel_chaff",
                "endpoint": 0,
                "stream": 4,
                "reason": "buflo_terminal_subcell_tail",
            },
            sort_keys=True,
        ),
    )
    write_rows(events, event_fields, [event_row])

    packet_fields = (*handoff._PACKET_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    exact_packet = {field: "" for field in packet_fields}
    exact_packet.update(
        direction="outgoing",
        monotonic_us="9999990",
        connection="0",
        observed_udp_length="1200",
        scheduled_target="1200",
        satisfaction="satisfied",
        slot_id="1",
        qcsd_outcome_schema_version="2",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="1200",
        defense_control_bytes="0",
        quic_padding_bytes="0",
        other_quic_bytes="0",
        lateness_us="0",
    )
    control_packet = {field: "" for field in packet_fields}
    control_packet.update(
        direction="outgoing",
        monotonic_us="10000020",
        connection="0",
        observed_udp_length="50",
        satisfaction="unshaped",
        qcsd_outcome_schema_version="2",
        send_policy="unscheduled",
        desired_udp_bytes="50",
        observed_udp_bytes="50",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="0",
        defense_control_bytes="4",
        quic_padding_bytes="0",
        other_quic_bytes="46",
        lateness_us="0",
    )
    write_rows(packets, packet_fields, [exact_packet, control_packet])

    run = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=0,
        stream_cancellations=1,
        cancelled_capacity=1_199,
    )
    algorithm = _algorithm_diagnostics(
        run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert algorithm["schema_version"] == 3
    assert algorithm["buflo_state"]["schema_version"] == 2
    assert algorithm["buflo_state"]["typed_cancellation_action_events"] == 1
    assert (
        algorithm["buflo_state"][
            "post_cancellation_unscheduled_defense_control_packets"
        ]
        == 1
    )
    assert (
        algorithm["buflo_state"][
            "post_cancellation_unscheduled_defense_control_bytes"
        ]
        == 4
    )

    legacy_run = json.loads(json.dumps(run))
    legacy_run["buflo_summary"]["schema_version"] = 2
    legacy_run["defense_diagnostics"].pop(
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    )
    legacy_run["buflo_summary"]["diagnostics"].pop(
        "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
    )
    with pytest.raises(ValueError, match="terminal-tail evidence is unavailable"):
        _algorithm_diagnostics(
            legacy_run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    legacy_algorithm = _algorithm_diagnostics(
        legacy_run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
        require_current=False,
    )
    assert legacy_algorithm["schema_version"] == 2
    assert "schema_version" not in legacy_algorithm["buflo_state"]

    event_row["details"] = event_row["details"].replace(
        "buflo_terminal_subcell_tail", "cs_buflo_local_early_termination"
    )
    write_rows(events, event_fields, [event_row])
    with pytest.raises(ValueError, match="terminal-tail evidence is inconsistent"):
        _algorithm_diagnostics(
            run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )

    event_row["details"] = event_row["details"].replace(
        "cs_buflo_local_early_termination", "buflo_terminal_subcell_tail"
    )
    write_rows(events, event_fields, [event_row])
    for diagnostic, changed in (
        ("buflo_terminal_subcell_parser_lease_bytes_at_latch", 1),
        ("buflo_terminal_subcell_exact_capacity_bytes_cancelled", 1_200),
    ):
        invalid_run = json.loads(json.dumps(run))
        invalid_run["defense_diagnostics"][diagnostic] = changed
        invalid_run["buflo_summary"]["diagnostics"][diagnostic] = changed
        with pytest.raises(ValueError, match="terminal-tail evidence"):
            _algorithm_diagnostics(
                invalid_run,
                defense="buflo",
                runtime_kind="buflo",
                schedule_path=schedule,
                events_path=events,
                packets_path=packets,
            )

    second_event = dict(event_row)
    second_event.update(
        monotonic_us="10000030",
        details=json.dumps(
            {
                "type": "cancel_chaff",
                "endpoint": 0,
                "stream": 8,
                "reason": "buflo_terminal_subcell_tail",
            },
            sort_keys=True,
        ),
    )
    write_rows(events, event_fields, [event_row, second_event])
    two_stream_run = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=0,
        stream_cancellations=2,
        cancelled_capacity=1_199,
    )
    with pytest.raises(ValueError, match="terminal-tail evidence is inconsistent"):
        _algorithm_diagnostics(
            two_stream_run,
            defense="buflo",
            runtime_kind="buflo",
            schedule_path=schedule,
            events_path=events,
            packets_path=packets,
        )
    control_packet["monotonic_us"] = "10000040"
    write_rows(packets, packet_fields, [exact_packet, control_packet])
    two_stream = _algorithm_diagnostics(
        two_stream_run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert two_stream["buflo_state"]["stream_cancellations"] == 2
    assert (
        two_stream["buflo_state"][
            "first_post_cancellation_defense_control_monotonic_us"
        ]
        == 10_000_040
    )

    retained_boundary_run = _complete_buflo_run(
        scheduled_outgoing=1,
        scheduled_incoming=0,
        stream_cancellations=2,
        cancelled_capacity=624,
        pending_parser_boundaries=1,
    )
    retained_boundary = _algorithm_diagnostics(
        retained_boundary_run,
        defense="buflo",
        runtime_kind="buflo",
        schedule_path=schedule,
        events_path=events,
        packets_path=packets,
    )
    assert retained_boundary["buflo_state"][
        "pending_parser_boundaries_at_latch"
    ] == 1
    assert retained_boundary["buflo_state"][
        "pending_application_parser_boundaries_at_latch"
    ] == 0

    for diagnostic, changed in (
        (
            "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch",
            1,
        ),
        ("buflo_terminal_subcell_pending_parser_boundaries_at_latch", 3),
    ):
        invalid_run = json.loads(json.dumps(retained_boundary_run))
        invalid_run["defense_diagnostics"][diagnostic] = changed
        invalid_run["buflo_summary"]["diagnostics"][diagnostic] = changed
        with pytest.raises(ValueError, match="terminal-tail evidence"):
            _algorithm_diagnostics(
                invalid_run,
                defense="buflo",
                runtime_kind="buflo",
                schedule_path=schedule,
                events_path=events,
                packets_path=packets,
            )


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
