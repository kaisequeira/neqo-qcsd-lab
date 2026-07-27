import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

import qcsd_lab.campaign as campaign_module
from qcsd_lab.campaign import collect_campaign
from qcsd_lab.capture import extract_trace, read_normalized_trace
from qcsd_lab.dataset import validate_dataset
from qcsd_lab.util import atomic_json, load_json

from tests.test_local_acceptance import _manifest


CAPTURE_GATE = os.environ.get("QCSD_RUN_CAPTURE_ACCEPTANCE") == "1"
CAPTURE_PART = os.environ.get("QCSD_CAPTURE_ACCEPTANCE_PART")


@pytest.mark.skipif(
    not CAPTURE_GATE or CAPTURE_PART != "direct",
    reason="direct container-edge capture acceptance is launcher-provisioned",
)
def test_direct_container_eth0_capture_without_tunnel(tmp_path):
    address = os.environ["QCSD_CAPTURE_SERVER_ADDRESS"]
    port = int(os.environ["QCSD_CAPTURE_SERVER_PORT"])
    second_address = os.environ["QCSD_CAPTURE_SERVER_TWO_ADDRESS"]
    second_port = int(os.environ["QCSD_CAPTURE_SERVER_TWO_PORT"])
    assert "QCSD_WG_GATEWAY_ADDRESS" not in os.environ
    assert not Path("/sys/class/net/wg0").exists()

    campaign_path = _configuration(
        tmp_path / "direct",
        address,
        port,
        second_address,
        second_port,
    )
    result = collect_campaign(
        campaign_path,
        tmp_path / "direct-results",
        capture="direct",
        network_condition="acceptance-direct",
    )
    sample = _only_sample(result)
    metadata = load_json(sample / "sample.json")
    assert metadata["eligible"] is True
    assert metadata["endpoint_count"] == metadata["expected_endpoint_count"] == 2
    _assert_all_resources_complete(sample)
    assert len(metadata["views"]) == 1
    observer = metadata["views"][0]
    assert (
        observer["id"],
        observer["interface"],
        observer["link_type"],
        observer["length_basis"],
        observer["primary"],
    ) == ("direct-quic", "eth0", "Ethernet", "frame.len", True)
    _assert_trace_reproduction(sample, observer)
    _assert_direct_destination_isolation(sample, observer, address, second_address)
    assert (sample.parent / "trace-comparison.svg").stat().st_size > 0
    validation = validate_dataset(result)
    assert validation["valid"] is True
    assert validation["purpose"] == "diagnostics"


@pytest.mark.skipif(
    not CAPTURE_GATE or CAPTURE_PART != "wireguard",
    reason="WireGuard capture acceptance is launcher-provisioned",
)
def test_wireguard_dual_outer_only_and_auxiliary_failure(tmp_path, monkeypatch):
    address = os.environ["QCSD_CAPTURE_SERVER_ADDRESS"]
    port = int(os.environ["QCSD_CAPTURE_SERVER_PORT"])
    second_address = os.environ["QCSD_CAPTURE_SERVER_TWO_ADDRESS"]
    second_port = int(os.environ["QCSD_CAPTURE_SERVER_TWO_PORT"])
    assert Path("/sys/class/net/wg0").exists()

    dconn_campaign = _configuration(
        tmp_path / "dconn",
        address,
        port,
        second_address,
        second_port,
        scope="primary-origin",
    )
    dconn_root = collect_campaign(
        dconn_campaign,
        tmp_path / "dconn-results",
        capture="wireguard",
        network_condition="acceptance-wireguard",
    )
    dconn_sample = _only_sample(dconn_root)
    dconn_metadata = load_json(dconn_sample / "sample.json")
    assert dconn_metadata["workload_model"] == "Dconn"
    assert dconn_metadata["endpoint_count"] == 1
    _assert_all_resources_complete(dconn_sample)

    dual_campaign = _configuration(
        tmp_path / "dual",
        address,
        port,
        second_address,
        second_port,
    )
    dual_root = collect_campaign(
        dual_campaign,
        tmp_path / "dual-results",
        capture="wireguard",
        network_condition="acceptance-wireguard",
    )
    dual_sample = _only_sample(dual_root)
    dual_metadata = load_json(dual_sample / "sample.json")
    assert dual_metadata["eligible"] is True
    assert dual_metadata["workload_model"] == "Dmc"
    assert dual_metadata["endpoint_count"] == 2
    _assert_all_resources_complete(dual_sample)
    observers = {item["id"]: item for item in dual_metadata["views"]}
    assert (
        observers["wireguard-outer"]["interface"],
        observers["wireguard-outer"]["link_type"],
        observers["wireguard-outer"]["length_basis"],
    ) == ("eth0", "Ethernet", "udp.length")
    assert observers["wireguard-outer"]["resolved_gateway_address"] == os.environ[
        "QCSD_WG_GATEWAY_ADDRESS"
    ]
    assert (
        observers["direct-quic"]["interface"],
        observers["direct-quic"]["link_type"],
        observers["direct-quic"]["length_basis"],
    ) == ("wg0", "Raw IP", "frame.len")
    for observer in observers.values():
        _assert_trace_reproduction(dual_sample, observer)
    _assert_outer_peer_isolation(dual_sample, observers["wireguard-outer"])
    _assert_direct_destination_isolation(
        dual_sample, observers["direct-quic"], address, second_address
    )
    assert validate_dataset(dual_root)["valid"] is True

    outer_campaign = _configuration(
        tmp_path / "outer-only",
        address,
        port,
        second_address,
        second_port,
    )
    outer_root = collect_campaign(
        outer_campaign,
        tmp_path / "outer-results",
        capture="wireguard",
        outer_only=True,
        network_condition="acceptance-wireguard",
    )
    outer_metadata = load_json(_only_sample(outer_root) / "sample.json")
    assert outer_metadata["eligible"] is True
    assert [item["id"] for item in outer_metadata["views"]] == [
        "wireguard-outer"
    ]
    assert validate_dataset(outer_root)["valid"] is True

    original_collect_attempt = campaign_module._collect_attempt

    def fail_auxiliary(attempt, manifest, defense, seed, campaign):
        result = original_collect_attempt(attempt, manifest, defense, seed, campaign)
        direct = next(item for item in result["views"] if item["id"] == "direct-quic")
        direct["valid"] = False
        (attempt / direct["capture_path"]).unlink()
        (attempt / direct["trace_path"]).unlink()
        result["auxiliary_failures"] = [
            {"view": "direct-quic", "reason": "injected acceptance failure"}
        ]
        atomic_json(attempt / "attempt.json", result)
        return result

    monkeypatch.setattr(campaign_module, "_collect_attempt", fail_auxiliary)
    failure_campaign = _configuration(
        tmp_path / "auxiliary-failure",
        address,
        port,
        second_address,
        second_port,
    )
    failure_root = collect_campaign(
        failure_campaign,
        tmp_path / "auxiliary-failure-results",
        capture="wireguard",
        network_condition="acceptance-wireguard",
    )
    failure_metadata = load_json(_only_sample(failure_root) / "sample.json")
    assert failure_metadata["attempts"] == 1
    assert failure_metadata["eligible"] is True
    assert {view["id"]: view["valid"] for view in failure_metadata["views"]} == {
        "direct-quic": False,
        "wireguard-outer": True,
    }
    assert failure_metadata["auxiliary_failures"]
    assert validate_dataset(failure_root)["valid"] is True


def _configuration(
    directory: Path,
    address: str,
    port: int,
    second_address: str,
    second_port: int,
    *,
    scope: str = "all-reviewed-origins",
) -> Path:
    directory.mkdir()
    workload = _manifest(port, second_port)
    for resource in workload["resources"]:
        host = address if resource["id"] < 2 else second_address
        resource_port = port if resource["id"] < 2 else second_port
        resource["url"] = f"https://{host}:{resource_port}/{resource['data_length']}"
    first_origin = f"https://{address}:{port}"
    second_origin = f"https://{second_address}:{second_port}"
    workload["replay"] = {
        "source_url": f"{first_origin}/",
        "final_url": f"{first_origin}/",
        "chromium_version": "controlled-acceptance",
        "settle_ms": 0,
        "observed_request_count": 4,
        "observed_origins": [first_origin, second_origin],
        "reviewed_origins": [first_origin, second_origin],
        "exclusions": [],
    }
    (directory / "workloads").mkdir()
    (directory / "workloads/controlled.json").write_text(
        json.dumps(workload), encoding="utf-8"
    )
    campaign = {
        "name": f"capture-{directory.name}",
        "seed": 42,
        "qcsd_profile": "live",
        "workloads": {
            "source": "controlled",
            "reviewed": False,
            "scope": scope,
            "monitored": {"controlled": 1},
            "unmonitored": {},
        },
        "limits": {
            "timeout_seconds": 15,
            "max_response_bytes": 1_048_576,
            "capture_seconds": 20,
            "capture_megabytes": 16,
            "settle_seconds": 1,
            "max_attempts": 1,
            "inter_sample_seconds": 0,
            "per_origin_cooldown_seconds": 0,
        },
        "defenses": ["undefended"],
    }
    path = directory / "campaign.yml"
    path.write_text(yaml.safe_dump(campaign, sort_keys=False), encoding="utf-8")
    return path


def _only_sample(root: Path) -> Path:
    samples = list(root.rglob("sample.json"))
    assert len(samples) == 1
    return samples[0].parent


def _assert_trace_reproduction(sample: Path, observer: dict) -> None:
    run_data = load_json(sample / "neqo/run.json")
    derived = extract_trace(
        sample / observer["capture_path"],
        run_data["endpoints"],
        kind=observer["kind"],
        length_basis=observer["length_basis"],
        client_port=observer.get("client_port"),
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
        address
        for line in result.stdout.splitlines()
        for address in line.split("\t")
        if address
    }


def _assert_direct_destination_isolation(
    sample: Path, observer: dict, *server_addresses: str
) -> None:
    run_data = load_json(sample / "neqo/run.json")
    local = run_data["endpoints"][0]["local_address"].rsplit(":", 1)[0]
    assert _capture_addresses(sample, observer) == {local, *server_addresses}


def _assert_all_resources_complete(sample: Path) -> None:
    run_data = load_json(sample / "neqo/run.json")
    expected = list(range(int(load_json(sample / "sample.json")["resource_count"])))
    assert sorted(response["resource_id"] for response in run_data["responses"]) == expected
    assert all(response["status"] == 200 for response in run_data["responses"])
    assert all(response["outcome"] == "succeeded" for response in run_data["responses"])


def _assert_outer_peer_isolation(sample: Path, observer: dict) -> None:
    addresses = _capture_addresses(sample, observer)
    assert os.environ["QCSD_WG_GATEWAY_ADDRESS"] in addresses
    assert "10.203.0.1" not in addresses
    assert len(addresses) == 2
