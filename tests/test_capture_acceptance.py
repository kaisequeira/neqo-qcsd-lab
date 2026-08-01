import csv
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest
import yaml

from qcsd_lab.campaign import collect_campaign
from qcsd_lab.capture import extract_trace, read_normalized_trace
from qcsd_lab.dataset import validate_dataset
from qcsd_lab.util import load_json, sha256_file


CAPTURE_GATE = os.environ.get("QCSD_RUN_CAPTURE_ACCEPTANCE") == "1"
DEFENSES = (
    "undefended",
    "static",
    "front",
    "tamaraw",
    "traffic-morphing",
    "wtf-pad",
    "walkie-talkie",
)
PARAMETER_FILES = {
    "static": Path("/lab/config/defense-params/static-migration.csv"),
    "traffic-morphing": Path("/lab/config/defense-params/traffic-morphing-live.json"),
    "wtf-pad": Path("/lab/config/defense-params/wtfpad-live.json"),
    "walkie-talkie": Path("/lab/config/defense-params/walkie-talkie-live.json"),
}
CORE_ARTIFACT_SURFACE = {
    "captures/direct-quic.pcapng",
    "traces/direct-quic.csv",
    "neqo/events.csv",
    "neqo/packets.csv",
    "neqo/qlog/",
    "neqo/run.json",
    "neqo/schedule.csv",
}
PARAMETER_BUNDLE_SURFACE = {
    "neqo/defense-parameters.json",
    "neqo/defense-parameters.provenance.json",
}
PARAMETERIZED_DEFENSES = {"traffic-morphing", "wtf-pad", "walkie-talkie"}


@pytest.mark.skipif(
    not CAPTURE_GATE,
    reason="direct container-edge capture acceptance is launcher-provisioned",
)
def test_direct_capture_simple_and_complex_workloads_under_all_defenses(tmp_path):
    address = os.environ["QCSD_CAPTURE_SERVER_ADDRESS"]
    port = int(os.environ["QCSD_CAPTURE_SERVER_PORT"])
    second_address = os.environ["QCSD_CAPTURE_SERVER_TWO_ADDRESS"]
    second_port = int(os.environ["QCSD_CAPTURE_SERVER_TWO_PORT"])
    campaign_path = _configuration(
        tmp_path / "direct",
        address,
        port,
        second_address,
        second_port,
    )
    result = collect_campaign(
        campaign_path,
        tmp_path / "results",
        network_condition="acceptance-direct",
    )
    receipt = load_json(result / "campaign.json")
    capture = receipt["configuration"]["capture"]
    assert (
        capture["mode"],
        capture["purpose"],
        capture["primary_view"],
        [view["id"] for view in capture["views"]],
    ) == ("direct", "classification", "direct-quic", ["direct-quic"])
    assert load_json(result / "dataset.json")["data_license"] == "not-for-release"

    samples = [path.parent for path in result.rglob("sample.json") if "attempts" not in path.parts]
    assert len(samples) == 2 * len(DEFENSES)
    by_workload: dict[str, dict[str, Path]] = defaultdict(dict)
    response_signatures: dict[str, dict[str, tuple[tuple[object, ...], ...]]] = defaultdict(dict)
    normalized_artifact_surfaces = []
    expected_servers = {
        "simple": {address},
        "complex": {address, second_address},
    }
    expected_endpoints = {"simple": 1, "complex": 2}

    for sample in samples:
        metadata = load_json(sample / "sample.json")
        workload = metadata["workload_id"]
        defense = metadata["defense"]
        by_workload[workload][defense] = sample
        assert metadata["state"] == "captured"
        assert metadata["eligible"] is True
        assert metadata["fidelity_eligible"] is True
        fidelity = load_json(sample / "fidelity.yml")
        assert fidelity["defense"] == defense
        assert fidelity["sample_eligible"] is True
        assert fidelity["fidelity_eligible"] is True
        realization = fidelity["realization_metrics"]
        assert realization["direct_runner_reconciled"] is True
        assert realization["direct_matched_packets"] == realization["direct_runner_packets"] > 0
        assert (
            realization["direct_timestamp_error_max_ns"]
            <= realization["direct_timestamp_tolerance_ns"]
        )
        assert metadata["operationally_valid"] is True
        assert metadata["endpoint_count"] == metadata["expected_endpoint_count"]
        assert metadata["endpoint_count"] == expected_endpoints[workload]
        assert len(metadata["views"]) == 1
        observer = metadata["views"][0]
        assert observer["capture_active_through_settle"] is True
        assert (
            observer["id"],
            observer["kind"],
            observer["interface"],
            observer["link_type"],
            observer["length_basis"],
            observer["primary"],
            observer["valid"],
        ) == (
            "direct-quic",
            "direct-quic",
            "eth0",
            "Ethernet",
            "frame.len",
            True,
            True,
        )
        assert {path.name for path in (sample / "captures").iterdir()} == {"direct-quic.pcapng"}
        assert {path.name for path in (sample / "traces").iterdir()} == {"direct-quic.csv"}
        assert {
            "events.csv",
            "packets.csv",
            "run.json",
            "schedule.csv",
        } <= {path.name for path in (sample / "neqo").iterdir()}
        qlogs = list((sample / "neqo/qlog").iterdir())
        assert qlogs and all(path.is_file() and path.stat().st_size > 0 for path in qlogs)
        artifact_surface = _core_artifact_surface(sample)
        expected_surface = set(CORE_ARTIFACT_SURFACE)
        if defense in PARAMETERIZED_DEFENSES:
            expected_surface.update(PARAMETER_BUNDLE_SURFACE)
        assert artifact_surface == expected_surface
        normalized_artifact_surfaces.append(artifact_surface - PARAMETER_BUNDLE_SURFACE)
        _assert_trace_reproduction(sample, observer)
        _assert_direct_destination_isolation(
            sample,
            observer,
            *expected_servers[workload],
        )

        run_data = load_json(sample / "neqo/run.json")
        _assert_capture_packet_units(sample, metadata, observer, run_data)
        _assert_all_resources_complete(sample, run_data)
        _assert_diagnostics(run_data)
        if defense != "undefended":
            _assert_terminal_schedule(sample / "neqo", run_data)
        _assert_parameter_binding(sample, defense, run_data)
        response_signatures[workload][defense] = tuple(
            (
                response["resource_id"],
                response["status"],
                response["outcome"],
                response["bytes"],
                response["body_sha256"],
            )
            for response in sorted(
                run_data["responses"],
                key=lambda response: response["resource_id"],
            )
        )

    assert len(normalized_artifact_surfaces) == 2 * len(DEFENSES)
    assert len({frozenset(surface) for surface in normalized_artifact_surfaces}) == 1
    assert set(by_workload) == {"simple", "complex"}
    for workload, variants in by_workload.items():
        assert set(variants) == set(DEFENSES)
        assert len(set(response_signatures[workload].values())) == 1
        visit = next(iter(variants.values())).parent
        assert {
            path.name for path in visit.glob("trace-comparison*") if path.suffix in {".pdf", ".svg"}
        } == {
            "trace-comparison.pdf",
            "trace-comparison.svg",
            "trace-comparison-2.pdf",
            "trace-comparison-2.svg",
        }
        assert all(path.stat().st_size > 0 for path in visit.glob("trace-comparison*"))

        _assert_traffic_morphing_size_shift(
            variants["undefended"],
            variants["traffic-morphing"],
        )
        _assert_wtfpad_guard(variants["wtf-pad"])
        _assert_walkie_talkie_turns(variants["walkie-talkie"])

    report = (result / "report.html").read_text(encoding="utf-8")
    assert "Direct-PCAP trace comparisons" in report
    assert report.count("trace-comparison.pdf") == 2
    assert report.count("trace-comparison-2.pdf") == 2
    assert "not for release" in report
    assert (result / "SHA256SUMS").is_file()
    validation = validate_dataset(result)
    assert validation["valid"] is True
    assert validation["purpose"] == "classification"


def _configuration(
    directory: Path,
    address: str,
    port: int,
    second_address: str,
    second_port: int,
) -> Path:
    directory.mkdir()
    workloads = directory / "workloads"
    workloads.mkdir()
    simple_origin = f"https://{address}:{port}"
    complex_origins = (
        simple_origin,
        f"https://{second_address}:{second_port}",
    )
    (workloads / "simple.json").write_text(
        json.dumps(
            _manifest(
                [
                    _resource(
                        0,
                        f"{simple_origin}/131072",
                        "Document",
                        131_072,
                    )
                ],
                origins=(simple_origin,),
            )
        ),
        encoding="utf-8",
    )
    (workloads / "complex.json").write_text(
        json.dumps(
            _manifest(
                [
                    _resource(
                        0,
                        f"{complex_origins[0]}/131072",
                        "Document",
                        131_072,
                    ),
                    _resource(
                        1,
                        f"{complex_origins[0]}/1024",
                        "Script",
                        1_024,
                        depends_on=[0],
                    ),
                    _resource(
                        2,
                        f"{complex_origins[1]}/4096",
                        "Script",
                        4_096,
                        depends_on=[0],
                    ),
                    _resource(
                        3,
                        f"{complex_origins[1]}/2048",
                        "Image",
                        2_048,
                        depends_on=[2],
                    ),
                ],
                origins=complex_origins,
            )
        ),
        encoding="utf-8",
    )
    campaign = {
        "name": "direct-capture-acceptance",
        "seed": 20_260_730,
        "stage": "acceptance",
        "qcsd_profile": "live",
        "workloads": {
            "root": "workloads",
            "source": "controlled",
            # Both dynamically allocated origins are created by this gate and
            # enumerated in each replay manifest.  Mark the controlled
            # workloads reviewed so the retained acceptance pilot records the
            # same explicit-origin trust decision as a checked-in pilot.
            "reviewed": True,
            "scope": "as-defined",
            "request_policy": "as-defined",
            "monitored": {"simple": 1, "complex": 1},
            "unmonitored": {},
        },
        "limits": {
            "timeout_seconds": 120,
            "max_response_bytes": 2_097_152,
            "capture_seconds": 180,
            "capture_megabytes": 64,
            "settle_seconds": 1,
            "max_attempts": 3,
            "inter_sample_seconds": 0,
            "per_origin_cooldown_seconds": 0,
        },
        "defenses": [
            "undefended",
            {
                "name": "static",
                "kind": "static",
                "schedule": str(PARAMETER_FILES["static"]),
                "mode": "chaff-only",
            },
            "front",
            "tamaraw",
            {
                "name": "traffic-morphing",
                "kind": "traffic_morphing",
                "parameters": str(PARAMETER_FILES["traffic-morphing"]),
                "allow_reviewed_fixture": True,
            },
            {
                "name": "wtf-pad",
                "kind": "wtf_pad",
                "parameters": str(PARAMETER_FILES["wtf-pad"]),
                "allow_reviewed_fixture": True,
            },
            {
                "name": "walkie-talkie",
                "kind": "walkie_talkie",
                "parameters": str(PARAMETER_FILES["walkie-talkie"]),
                "allow_reviewed_fixture": True,
            },
        ],
    }
    path = directory / "campaign.yml"
    path.write_text(yaml.safe_dump(campaign, sort_keys=False), encoding="utf-8")
    return path


def _manifest(resources: list[dict], *, origins: tuple[str, ...]) -> dict:
    return {
        "header_policy": {"mode": "minimal", "overrides": []},
        "resources": resources,
        "replay": {
            "source_url": f"{origins[0]}/",
            "final_url": f"{origins[0]}/",
            "chromium_version": "controlled-acceptance",
            "settle_ms": 0,
            "observed_request_count": len(resources),
            "observed_origins": list(origins),
            "reviewed_origins": list(origins),
            "exclusions": [],
        },
    }


def _resource(
    identifier: int,
    url: str,
    resource_type: str,
    size: int,
    *,
    depends_on: list[int] | None = None,
) -> dict:
    return {
        "id": identifier,
        "url": url,
        "type": resource_type,
        "content_length": size,
        "data_length": size,
        "chaff_priority": identifier == 0,
        "known_valid": True,
        "depends_on": depends_on or [],
        "headers": [],
    }


def _assert_trace_reproduction(sample: Path, observer: dict) -> None:
    run_data = load_json(sample / "neqo/run.json")
    derived = extract_trace(
        sample / observer["capture_path"],
        run_data["endpoints"],
    )
    expected = [
        {
            "relative_time_ns": str(packet.relative_time_ns),
            "direction": packet.direction,
            "length_bytes": str(packet.length_bytes),
            "signed_length_bytes": str(packet.signed_length_bytes),
        }
        for packet in derived
    ]
    assert read_normalized_trace(sample / observer["trace_path"]) == expected
    assert len(expected) == observer["packet_count"]


def _core_artifact_surface(sample: Path) -> set[str]:
    surface = {
        path.relative_to(sample).as_posix()
        for directory in ("captures", "traces")
        for path in (sample / directory).iterdir()
        if path.is_file()
    }
    for path in (sample / "neqo").iterdir():
        relative = path.relative_to(sample).as_posix()
        if path.is_file():
            surface.add(relative)
        elif path.is_dir():
            surface.add(relative + "/")
    return surface


def _capture_addresses(sample: Path, observer: dict) -> set[str]:
    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(sample / observer["capture_path"]),
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    return {
        address for line in result.stdout.splitlines() for address in line.split("\t") if address
    }


def _assert_direct_destination_isolation(
    sample: Path,
    observer: dict,
    *server_addresses: str,
) -> None:
    run_data = load_json(sample / "neqo/run.json")
    local_addresses = {
        endpoint["local_address"].rsplit(":", 1)[0] for endpoint in run_data["endpoints"]
    }
    assert len(local_addresses) == 1
    assert _capture_addresses(sample, observer) == {
        *local_addresses,
        *server_addresses,
    }


def _assert_all_resources_complete(sample: Path, run_data: dict) -> None:
    assert run_data["completion_status"] == "complete"
    expected = list(range(int(load_json(sample / "sample.json")["resource_count"])))
    assert sorted(response["resource_id"] for response in run_data["responses"]) == expected
    assert all(response["status"] == 200 for response in run_data["responses"])
    assert all(response["complete"] is True for response in run_data["responses"])
    assert all(response["outcome"] == "succeeded" for response in run_data["responses"])


def _assert_diagnostics(run_data: dict) -> None:
    diagnostics = run_data["defense_diagnostics"]
    assert diagnostics["padding_event_guard_triggered"] is False
    for value in diagnostics.values():
        if type(value) is bool:
            continue
        if type(value) is int:
            assert value >= 0
            continue
        assert isinstance(value, list)
        assert all(
            isinstance(item, dict)
            and all(type(field) is int and field >= 0 for field in item.values())
            for item in value
        )


def _assert_capture_packet_units(
    sample: Path,
    metadata: dict,
    observer: dict,
    run_data: dict,
) -> None:
    assert metadata["udp_payload_ceiling"] == 1_200
    assert run_data["resolved_configuration"]["max_udp_payload_size"] == 1_200

    ceiling = observer["udp_payload_ceiling_evidence"]
    assert ceiling["configured_udp_payload_ceiling"] == 1_200
    assert ceiling["runner_resolved_udp_payload_ceiling"] == 1_200
    assert ceiling["runner_binding_valid"] is True
    assert ceiling["packets_with_udp_payload_length"] == observer["packet_count"]
    assert ceiling["packets_without_udp_payload_length"] == 0
    assert ceiling["oversized_udp_payload_packets"] == 0
    assert 0 < ceiling["observed_udp_payload_max"] <= 1_200
    assert ceiling["valid"] is True

    offload = observer["capture_offload_evidence"]
    assert metadata["capture_offloads"] == [offload]
    assert offload["interface"] == "eth0"
    assert offload["requested"] == {
        "gro": "off",
        "gso": "off",
        "tso": "off",
        "uso": "off",
    }
    assert offload["after_state"] == {
        "gro": "off",
        "gso": "off",
        "tso": "off",
        "uso": "off",
    }
    assert offload["query_returncodes"] == {"before": 0, "after": 0}
    assert offload["change_returncodes"] == {
        "gro": 0,
        "gso": 0,
        "tso": 0,
        "uso": 0,
    }
    assert offload["verified"] is True

    with (sample / "neqo/packets.csv").open(newline="", encoding="utf-8") as source:
        runner_lengths = [row["observed_udp_length"] for row in csv.DictReader(source)]
    assert runner_lengths
    assert all(length and 0 < int(length) <= 1_200 for length in runner_lengths)


def _assert_parameter_binding(sample: Path, defense: str, run_data: dict) -> None:
    parameter = run_data["defense_parameters"]
    expected = PARAMETER_FILES.get(defense)
    if expected is None:
        assert parameter is None
        return
    digest = sha256_file(expected)
    assert parameter["sha256"] == digest
    if defense in {"traffic-morphing", "wtf-pad", "walkie-talkie"}:
        copied = sample / "neqo/defense-parameters.json"
        provenance = sample / "neqo/defense-parameters.provenance.json"
        assert sha256_file(copied) == digest
        assert provenance.is_file() and provenance.stat().st_size > 0


def _assert_terminal_schedule(output: Path, run_data: dict) -> None:
    with (output / "schedule.csv").open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    assert rows
    allowed_satisfaction = {"satisfied", "credit_advertised", "missed"}
    allowed_misses = {
        "NoEndpoint",
        "InsufficientIncomingCapacity",
        "CongestionLimited",
        "PacingLimited",
        "KeysUnavailable",
        "PathMtu",
        "MandatoryFrames",
        "EndpointClosed",
        "DeadlineExpired",
        "RunAborted",
    }
    defense_start_us = run_data["defense_start_monotonic_ns"] // 1_000
    for row in rows:
        assert row["slot_id"]
        assert row["satisfaction"] in allowed_satisfaction
        if row["satisfaction"] == "missed":
            assert row["miss_reason"] in allowed_misses
        else:
            assert not row["miss_reason"]
            assert int(row["action_time_us"]) >= (defense_start_us + int(row["target_time_us"]))
        if row["direction"] == "outgoing" and row["satisfaction"] == "satisfied":
            assert row["observed_size"]
            assert int(row["observed_size"]) == int(row["size"])


def _active_packet_sizes(sample: Path, direction: str) -> list[int]:
    run_data = load_json(sample / "neqo/run.json")
    start_us = (int(run_data["defense_start_monotonic_ns"]) + 999) // 1_000
    with (sample / "neqo/packets.csv").open(
        newline="",
        encoding="utf-8",
    ) as source:
        return [
            int(row["observed_udp_length"])
            for row in csv.DictReader(source)
            if row["direction"] == direction and int(row["monotonic_us"]) >= start_us
        ]


def _assert_traffic_morphing_size_shift(
    baseline: Path,
    morphed: Path,
) -> None:
    baseline_sizes = _active_packet_sizes(baseline, "outgoing")
    morphed_sizes = _active_packet_sizes(morphed, "outgoing")
    assert baseline_sizes and morphed_sizes
    baseline_ratio = sum(900 <= size <= 1_200 for size in baseline_sizes) / len(baseline_sizes)
    morphed_ratio = sum(900 <= size <= 1_200 for size in morphed_sizes) / len(morphed_sizes)
    assert morphed_ratio > baseline_ratio


def _assert_wtfpad_guard(sample: Path) -> None:
    diagnostics = load_json(sample / "neqo/run.json")["defense_diagnostics"]
    assert diagnostics["padding_events"] > 0
    assert diagnostics["padding_event_guard_triggered"] is False
    assert diagnostics["suppressed_cover_feedback"] > 0


def _assert_walkie_talkie_turns(sample: Path) -> None:
    parameter = load_json(PARAMETER_FILES["walkie-talkie"])
    packet_size = int(parameter["packet_size"])
    workload_id = load_json(sample / "sample.json")["workload_id"]
    matching = [
        profile
        for profile in parameter["profiles"]
        if workload_id in {profile["real"], profile["decoy"]}
    ]
    assert len(matching) == 1
    profile = matching[0]
    with (sample / "neqo/schedule.csv").open(
        newline="",
        encoding="utf-8",
    ) as source:
        rows = list(csv.DictReader(source))
    groups: list[tuple[str, list[dict[str, str]]]] = []
    for row in rows:
        if not groups or groups[-1][0] != row["direction"]:
            groups.append((row["direction"], [row]))
        else:
            groups[-1][1].append(row)
    expected: list[tuple[str, int]] = []
    for burst in profile["bursts"]:
        for direction in ("outgoing", "incoming"):
            count = int(burst[direction])
            if count == 0:
                continue
            if expected and expected[-1][0] == direction:
                expected[-1] = (direction, expected[-1][1] + count)
            else:
                expected.append((direction, count))
    assert [direction for direction, _rows in groups] == [
        direction for direction, _count in expected
    ]
    for (direction, rows), (_expected_direction, count) in zip(
        groups,
        expected,
        strict=True,
    ):
        if direction == "incoming":
            # The first target-time cohort is the mould itself.  A stream FIN
            # can retire unused advertised offsets later in the same turn;
            # exact replacement credit is then recorded as additional schedule
            # rows without adding logical target or observed cells.
            initial_target_us = min(int(row["target_time_us"]) for row in rows)
            initial = [row for row in rows if int(row["target_time_us"]) == initial_target_us]
            residual = [row for row in rows if int(row["target_time_us"]) != initial_target_us]
            assert len(initial) == count
            assert all(int(row["size"]) == packet_size for row in initial)
            assert all(
                int(row["target_time_us"]) > initial_target_us
                and 0 < int(row["size"]) <= packet_size
                and row["satisfaction"] == "credit_advertised"
                for row in residual
            )
        else:
            assert len(rows) >= count
    diagnostics = load_json(sample / "neqo/run.json")["defense_diagnostics"]
    assert "timed_out_turns" not in diagnostics
    assert diagnostics["walkie_talkie_target_outgoing_cells"] == sum(
        int(burst["outgoing"]) for burst in profile["bursts"]
    )
    assert diagnostics["walkie_talkie_target_incoming_cells"] == sum(
        int(burst["incoming"]) for burst in profile["bursts"]
    )
    assert (
        diagnostics["walkie_talkie_observed_outgoing_cells"]
        == diagnostics["walkie_talkie_target_outgoing_cells"]
    )
    assert diagnostics["walkie_talkie_outgoing_shortfall_cells"] == 0
    assert diagnostics["walkie_talkie_incoming_shortfall_cells"] == 0
    assert diagnostics["walkie_talkie_outgoing_overflow_cells"] == 0
    assert diagnostics["walkie_talkie_incoming_overflow_cells"] == 0
    assert diagnostics["walkie_talkie_incoming_shortfall_bytes"] == 0
    assert diagnostics["walkie_talkie_target_observed_cell_l1"] == 0
    assert diagnostics["walkie_talkie_target_observed_burst_l1"] == 0
    assert diagnostics["walkie_talkie_control_only_crossings"] >= 0
    assert diagnostics["walkie_talkie_application_stream_crossing_bytes"] == 0
    source_side = "real" if profile["real"] == workload_id else "decoy"
    expected_batches = len(profile["batch_ends"][source_side])
    assert diagnostics["walkie_talkie_expected_application_batches"] == expected_batches
    assert (
        diagnostics["walkie_talkie_observed_application_batches"]
        == diagnostics["walkie_talkie_application_batches_completed"]
        == expected_batches
    )
    assert diagnostics["walkie_talkie_application_batch_overflow"] == 0
    assert diagnostics["walkie_talkie_batch_lifecycle_errors"] == 0
    assert diagnostics["walkie_talkie_application_batch_active"] is False
    assert diagnostics["walkie_talkie_burst_realization"] == [
        {
            "index": index,
            "target_outgoing_cells": int(burst["outgoing"]),
            "target_incoming_cells": int(burst["incoming"]),
            "observed_outgoing_cells": int(burst["outgoing"]),
            "observed_incoming_cells": int(burst["incoming"]),
        }
        for index, burst in enumerate(profile["bursts"])
    ]
    endpoint_count = load_json(sample / "sample.json")["endpoint_count"]
    if endpoint_count > 1:
        final_outgoing = next(
            rows for direction, rows in reversed(groups) if direction == "outgoing"
        )
        assert {int(row["connection"]) for row in final_outgoing} == set(range(endpoint_count))
        assert all(row["satisfaction"] == "satisfied" for row in final_outgoing)
