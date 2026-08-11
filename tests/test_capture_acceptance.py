from __future__ import annotations

import csv
import json
import os
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
import yaml

from qcsd_lab.analysis import analyze_result
from qcsd_lab.capture import extract_trace
from qcsd_lab.orchestrator import run_campaign
from qcsd_lab.util import load_json, response_signature, sha256_file
from qcsd_lab.verification import verify_result


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
CANONICAL_SAMPLE_FILES = {
    "capture.pcapng",
    "neqo/events.csv",
    "neqo/packets.csv",
    "neqo/run.json",
    "neqo/schedule.csv",
}


@pytest.mark.skipif(
    not CAPTURE_GATE,
    reason="direct container-edge capture acceptance is launcher-provisioned",
)
def test_controlled_local_capture_uses_the_canonical_sealed_workflow(tmp_path: Path) -> None:
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

    result = run_campaign(campaign_path, tmp_path / "results")
    verified = verify_result(result)
    experiment = verified.experiment
    assert experiment["status"] == "complete"
    assert experiment["summary"] == {
        "planned": 2 * len(DEFENSES),
        "accepted": 2 * len(DEFENSES),
        "failed": 0,
        "eligible": 2 * len(DEFENSES),
        "passed": True,
    }
    assert len(experiment["samples"]) == 2 * len(DEFENSES)
    assert not list(result.rglob("sample.json"))
    assert not list(result.rglob("fidelity.yml"))
    assert not list(result.rglob("*.jsonl"))
    assert not list(result.rglob("qlog"))

    by_workload: dict[str, dict[str, Path]] = defaultdict(dict)
    response_signatures: dict[str, list[list[tuple[Any, ...]]]] = defaultdict(list)
    expected_servers = {
        "simple": {address},
        "complex": {address, second_address},
    }
    expected_endpoints = {"simple": 1, "complex": 2}
    expected_resource_ids = {"simple": {0}, "complex": {0, 1, 2, 3}}
    for sample in experiment["samples"]:
        sample_path = result / sample["path"]
        workload = sample["workload_id"]
        defense = sample["defense"]
        by_workload[workload][defense] = sample_path
        assert sample["state"] == "accepted"
        assert sample["eligible"] is True
        assert sample["diagnostics"]["response_match"] is True
        assert sample["diagnostics"]["fidelity_eligible"] is True
        assert sample["diagnostics"]["endpoint_count"] == expected_endpoints[workload]
        assert sample["diagnostics"]["endpoint_count_valid"] is True
        assert sample["diagnostics"]["operationally_valid"] is True

        actual_files = {
            path.relative_to(sample_path).as_posix()
            for path in sample_path.rglob("*")
            if path.is_file()
        }
        assert actual_files == CANONICAL_SAMPLE_FILES
        run = load_json(sample_path / "neqo/run.json")
        assert run["completion_status"] == "complete"
        assert len(run["endpoints"]) == expected_endpoints[workload]
        assert len(run["responses"]) == len(expected_resource_ids[workload])
        assert {response["resource_id"] for response in run["responses"]} == (
            expected_resource_ids[workload]
        )
        assert all(
            response["status"] == 200
            and response["complete"] is True
            and response["outcome"] == "succeeded"
            for response in run["responses"]
        )
        trace = extract_trace(sample_path / "capture.pcapng", run["endpoints"])
        assert trace
        _assert_direct_destination_isolation(
            sample_path / "capture.pcapng",
            run,
            *expected_servers[workload],
        )
        _assert_capture_contract(sample, run, trace)
        _assert_parameter_binding(result, experiment, sample, run)
        response_signatures[workload].append(response_signature(sample_path) or [])
        if workload == "complex":
            _assert_two_origins_share_the_same_sample(sample_path, run)

    assert set(by_workload) == {"simple", "complex"}
    assert all(set(variants) == set(DEFENSES) for variants in by_workload.values())
    assert all(
        len({tuple(signature) for signature in values}) == 1
        for values in response_signatures.values()
    )

    before_evidence = (result / "evidence.sha256").read_bytes()
    analysis = analyze_result(result)
    assert analysis.result_root == result
    assert (result / "derived/summary.csv").is_file()
    assert (result / "derived/report.html").is_file()
    plots = list((result / "derived/plots").glob("*.svg"))
    assert plots and not list((result / "derived/plots").glob("*.pdf"))
    assert (result / "evidence.sha256").read_bytes() == before_evidence
    verify_result(result)


def _configuration(
    directory: Path,
    address: str,
    port: int,
    second_address: str,
    second_port: int,
) -> Path:
    campaign_dir = directory / "config/campaigns"
    workload_dir = directory / "config/workloads"
    campaign_dir.mkdir(parents=True)
    workload_dir.mkdir()
    first_origin = f"https://{address}:{port}"
    second_origin = f"https://{second_address}:{second_port}"
    (workload_dir / "simple.json").write_text(
        json.dumps(
            {"resources": [_resource(0, f"{first_origin}/131072", "Document", 131_072)]},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (workload_dir / "complex.json").write_text(
        json.dumps(
            {
                "resources": [
                    _resource(0, f"{first_origin}/131072", "Document", 131_072),
                    _resource(
                        1,
                        f"{first_origin}/1024",
                        "Script",
                        1_024,
                        depends_on=[0],
                    ),
                    _resource(
                        2,
                        f"{second_origin}/4096",
                        "Script",
                        4_096,
                        depends_on=[0],
                    ),
                    _resource(
                        3,
                        f"{second_origin}/2048",
                        "Image",
                        2_048,
                        depends_on=[2],
                    ),
                ]
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    campaign = {
        "schema": 1,
        "name": "direct-capture-acceptance",
        "purpose": "smoke",
        "seed": 20_260_730,
        "profile": "live",
        "workloads": {"simple": 1, "complex": 1},
        "request_policies": ["as-defined"],
        "limits": {
            "timeout_seconds": 120,
            "max_response_bytes": 2_097_152,
            "capture_seconds": 180,
            "capture_megabytes": 64,
            "settle_seconds": 1,
            "max_attempts": 3,
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
            },
            {
                "name": "wtf-pad",
                "kind": "wtf_pad",
                "parameters": str(PARAMETER_FILES["wtf-pad"]),
            },
            {
                "name": "walkie-talkie",
                "kind": "walkie_talkie",
                "parameters": str(PARAMETER_FILES["walkie-talkie"]),
            },
        ],
    }
    path = campaign_dir / "campaign.yml"
    path.write_text(yaml.safe_dump(campaign, sort_keys=False), encoding="utf-8")
    return path


def _resource(
    identifier: int,
    url: str,
    resource_type: str,
    size: int,
    *,
    depends_on: list[int] | None = None,
) -> dict[str, Any]:
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


def _capture_addresses(capture: Path) -> set[str]:
    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(capture),
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
    capture: Path, run: dict[str, Any], *server_addresses: str
) -> None:
    local_addresses = {endpoint["local_address"].rsplit(":", 1)[0] for endpoint in run["endpoints"]}
    assert len(local_addresses) == 1
    assert _capture_addresses(capture) == {*local_addresses, *server_addresses}


def _assert_capture_contract(sample: dict[str, Any], run: dict[str, Any], trace: list[Any]) -> None:
    capture = sample["diagnostics"]["capture"]
    assert capture["valid"] is True
    assert capture["capture_active_through_settle"] is True
    assert capture["link_type"] == "Ethernet"
    assert capture["length_basis"] == "frame.len"
    assert capture["packet_count"] == len(trace)
    assert capture["capture_path"] == "capture.pcapng"
    assert "trace_path" not in capture
    assert "trace_sha256" not in capture
    ceiling = capture["udp_payload_ceiling_evidence"]
    assert ceiling["configured_udp_payload_ceiling"] == 1_200
    assert ceiling["runner_resolved_udp_payload_ceiling"] == 1_200
    assert ceiling["oversized_udp_payload_packets"] == 0
    assert ceiling["valid"] is True
    assert run["resolved_configuration"]["max_udp_payload_size"] == 1_200
    offload = capture["capture_offload_evidence"]
    assert offload["after_state"] == {
        "gro": "off",
        "gso": "off",
        "tso": "off",
        "uso": "off",
    }
    assert offload["verified"] is True


def _assert_parameter_binding(
    root: Path,
    experiment: dict[str, Any],
    sample: dict[str, Any],
    run: dict[str, Any],
) -> None:
    expected = PARAMETER_FILES.get(sample["defense"])
    parameter = run["defense_parameters"]
    if expected is None:
        assert parameter is None
        return
    record = next(
        item
        for item in experiment["configuration"]["defenses"]
        if item["name"] == sample["defense"]
    )
    field = "schedule" if sample["defense"] == "static" else "parameters"
    frozen = root / record[field]
    assert parameter == {
        "kind": sample["runtime_kind"],
        "path": str(frozen),
        "sha256": sha256_file(expected),
    }
    assert sha256_file(frozen) == parameter["sha256"]
    if sample["defense"] != "static":
        assert sha256_file(root / record["provenance"]) == record["provenance_sha256"]


def _assert_two_origins_share_the_same_sample(sample: Path, run: dict[str, Any]) -> None:
    assert len(run["endpoints"]) == 2
    assert len({endpoint["remote_address"] for endpoint in run["endpoints"]}) == 2
    with (sample / "neqo/packets.csv").open(newline="", encoding="utf-8") as source:
        connections = {int(row["connection"]) for row in csv.DictReader(source)}
    assert connections == {0, 1}
    with (sample / "neqo/events.csv").open(newline="", encoding="utf-8") as source:
        starts = [
            row
            for row in csv.DictReader(source)
            if row["event"] == "application_request" and row["outcome"] == "started"
        ]
    simultaneous: dict[int, set[int]] = defaultdict(set)
    for row in starts:
        simultaneous[int(row["monotonic_us"])].add(int(row["connection"]))
    assert {0, 1} in simultaneous.values()
