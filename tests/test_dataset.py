import json
import socket
import subprocess
import tarfile
from pathlib import Path

import dpkt
import pytest

from qcsd_lab.capture import extract_trace, write_normalized_trace
from qcsd_lab.dataset import package_dataset, validate_dataset
from qcsd_lab.util import atomic_json, atomic_text, load_json, sha256_file


def _packet(source, destination, source_port, destination_port, payload=b"quic"):
    udp = dpkt.udp.UDP(sport=source_port, dport=destination_port, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(source),
        dst=socket.inet_aton(destination),
        p=dpkt.ip.IP_PROTO_UDP,
        ttl=64,
        data=udp,
    )
    ip.len = len(ip)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x00" * 6,
            dst=b"\x01" * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
    )


def _pcapng(path: Path, packets: list[bytes]) -> None:
    legacy = path.with_suffix(".pcap")
    with legacy.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        for offset, packet in enumerate(packets):
            writer.writepkt(packet, ts=1.0 + offset / 10)
    subprocess.run(["editcap", "-F", "pcapng", str(legacy), str(path)], check=True)
    legacy.unlink()


def _observer(
    sample: Path,
    identifier: str,
    *,
    kind: str,
    interface: str,
    link_type: str,
    length_basis: str,
    primary: bool,
    endpoints: list[dict],
    client_port: int | None = None,
) -> dict:
    capture = sample / f"captures/{identifier}.pcapng"
    trace_path = sample / f"traces/{identifier}.csv"
    trace = extract_trace(
        capture,
        endpoints,
        kind=kind,
        length_basis=length_basis,
        client_port=client_port,
    )
    write_normalized_trace(trace_path, trace)
    value = {
        "id": identifier,
        "kind": kind,
        "interface": interface,
        "required": primary,
        "primary": primary,
        "role": "classifier" if primary else "diagnostic",
        "link_type": link_type,
        "length_basis": length_basis,
        "flow_filter": "exact",
        "direction_rule": "declared",
        "capture_boundary": "known",
        "packet_count": len(trace),
        "truncated": False,
        "capture_path": f"captures/{identifier}.pcapng",
        "trace_path": f"traces/{identifier}.csv",
        "capture_sha256": sha256_file(capture),
        "trace_sha256": sha256_file(trace_path),
        "pcapng_bytes": capture.stat().st_size,
        "valid": True,
    }
    if client_port is not None:
        value["client_port"] = client_port
    return value


def _dataset(root: Path) -> tuple[Path, dict]:
    sample = root / "site/site-visit-00000/opaque-baseline"
    (sample / "captures").mkdir(parents=True)
    (sample / "traces").mkdir()
    (sample / "neqo/qlog").mkdir(parents=True)
    endpoints = [
        {
            "id": 0,
            "local_address": "10.203.0.2:50000",
            "remote_address": "203.0.113.1:443",
        }
    ]
    _pcapng(
        sample / "captures/wireguard-outer.pcapng",
        [
            _packet("172.17.0.2", "172.17.0.3", 51821, 51820),
            _packet("172.17.0.3", "172.17.0.2", 51820, 51821),
        ],
    )
    _pcapng(
        sample / "captures/direct-quic.pcapng",
        [
            _packet("10.203.0.2", "203.0.113.1", 50000, 443),
            _packet("203.0.113.1", "10.203.0.2", 443, 50000),
        ],
    )
    outer = _observer(
        sample,
        "wireguard-outer",
        kind="wireguard-outer",
        interface="eth0",
        link_type="Ethernet",
        length_basis="udp.length",
        primary=True,
        endpoints=endpoints,
        client_port=51821,
    )
    direct = _observer(
        sample,
        "direct-quic",
        kind="direct-quic",
        interface="wg0",
        link_type="Ethernet",
        length_basis="frame.len",
        primary=False,
        endpoints=endpoints,
    )
    atomic_json(
        sample / "neqo/run.json",
        {
            "endpoints": endpoints,
            "resolved_configuration": {"defense": "opaque-runtime"},
            "responses": [],
        },
    )
    (sample / "neqo/events.csv").write_text("secret\n", encoding="utf-8")
    (sample / "neqo/schedule.csv").write_text("secret\n", encoding="utf-8")
    (sample / "neqo/qlog/endpoint.sqlog").write_text("secret\n", encoding="utf-8")

    metadata = {
        "sample_id": "b" * 64,
        "visit_id": "a" * 64,
        "workload_id": "site",
        "class_label": "site",
        "role": "monitored",
        "repetition": 0,
        "purpose": "classification",
        "defense": "opaque-baseline",
        "runtime_kind": "opaque-runtime",
        "baseline": True,
        "seed": 42,
        "state": "captured",
        "attempts": 1,
        "eligible": True,
        "content_drift": False,
        "response_match": True,
        "resolved_defense": {"defense": "opaque-runtime"},
        "views": [outer, direct],
    }
    atomic_json(sample / "sample.json", metadata)
    record = {
        key: metadata[key]
        for key in (
            "sample_id",
            "visit_id",
            "workload_id",
            "class_label",
            "role",
            "repetition",
            "defense",
            "runtime_kind",
            "seed",
            "state",
            "attempts",
            "eligible",
            "content_drift",
            "response_match",
        )
    }
    record["views"] = {"wireguard-outer": True, "direct-quic": True}
    record["path"] = str(sample.relative_to(root))
    record["split"] = "train"
    atomic_text(root / "samples.jsonl", json.dumps(record, sort_keys=True) + "\n")
    atomic_json(
        root / "campaign.json",
        {
            "campaign": {"name": "test", "purpose": "classification", "status": "complete"},
            "configuration": {"defenses": [{"name": "opaque-baseline"}]},
            "visits": [
                {
                    "visit_id": "a" * 64,
                }
            ],
        },
    )
    definitions = [
        {
            key: observer[key]
            for key in (
                "id",
                "kind",
                "interface",
                "required",
                "primary",
                "role",
                "link_type",
                "length_basis",
            )
        }
        | ({"client_port": observer["client_port"]} if "client_port" in observer else {})
        for observer in (outer, direct)
    ]
    atomic_json(
        root / "dataset.json",
        {
            "title": "test",
            "purpose": "classification",
            "publication_eligible": True,
            "primary_observer": "wireguard-outer",
            "data_license": "not-for-release",
            "observer_definitions": definitions,
            "defenses": [{"name": "opaque-baseline", "baseline": True}],
        },
    )
    atomic_json(
        root / "splits.json",
        {
            "assignments": {"a" * 64: "train"},
            "views": {
                "open-world": {"roles": ["monitored", "unmonitored"]},
                "closed-world": {"roles": ["monitored"]},
            },
        },
    )
    (root / "metrics.csv").write_text("sample\n", encoding="utf-8")
    atomic_json(root / "projection.json", {"measured": {}})
    (root / "report.html").write_text("<!doctype html>", encoding="utf-8")
    return sample, record


def test_dataset_validation_reproduces_each_view_and_detects_split_leakage(tmp_path):
    _sample, record = _dataset(tmp_path)
    result = validate_dataset(tmp_path)
    assert result["valid"] is True
    assert result["purpose"] == "classification"
    assert result["eligible_samples"] == 1

    record["split"] = "test"
    atomic_text(tmp_path / "samples.jsonl", json.dumps(record) + "\n")
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert invalid["valid"] is False
    assert any("wrong split" in error for error in invalid["errors"])


def test_package_scopes_primary_and_auxiliary_views(tmp_path):
    _dataset(tmp_path)
    with pytest.raises(ValueError, match="data license"):
        package_dataset(tmp_path, pcaps="none")

    for policy, expected, captures in (
        ("none", {"wireguard-outer"}, False),
        ("primary", {"wireguard-outer"}, True),
        ("all", {"wireguard-outer", "direct-quic"}, True),
    ):
        output = tmp_path.parent / f"publication-{policy}.tar.gz"
        package_dataset(
            tmp_path,
            pcaps=policy,
            output=output,
            data_license="CC-BY-4.0",
        )
        with tarfile.open(output) as archive:
            names = set(archive.getnames())
        trace_names = {
            Path(name).stem for name in names if "/traces/" in name and name.endswith(".csv")
        }
        capture_names = {
            Path(name).stem
            for name in names
            if "/captures/" in name and name.endswith(".pcapng")
        }
        assert trace_names == expected
        assert capture_names == (expected if captures else set())
        assert not any("neqo/" in name for name in names)
        assert not any(name.endswith("sample.json") for name in names)
        assert not any(name.endswith("events.csv") or name.endswith("schedule.csv") for name in names)


def test_direct_diagnostics_validate_but_cannot_be_packaged(tmp_path):
    _dataset(tmp_path)
    dataset_path = tmp_path / "dataset.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    direct = next(item for item in dataset["observer_definitions"] if item["id"] == "direct-quic")
    direct.update(interface="eth0", link_type="Ethernet", required=True, primary=True)
    dataset.update(
        purpose="diagnostics",
        publication_eligible=False,
        primary_observer="direct-quic",
        observer_definitions=[direct],
    )
    atomic_json(dataset_path, dataset)
    sample_path = next(tmp_path.rglob("sample.json"))
    metadata = json.loads(sample_path.read_text(encoding="utf-8"))
    metadata["views"] = [next(item for item in metadata["views"] if item["id"] == "direct-quic")]
    metadata["views"][0].update(interface="eth0", link_type="Ethernet", required=True, primary=True)
    metadata["purpose"] = "diagnostics"
    atomic_json(sample_path, metadata)
    records = [json.loads(line) for line in (tmp_path / "samples.jsonl").read_text().splitlines()]
    records[0]["views"] = {"direct-quic": True}
    atomic_text(tmp_path / "samples.jsonl", json.dumps(records[0], sort_keys=True) + "\n")
    result = validate_dataset(tmp_path)
    assert result["valid"] is True
    assert any("cannot support" in warning for warning in result["warnings"])
    with pytest.raises(ValueError, match="WireGuard classification"):
        package_dataset(tmp_path, pcaps="none", data_license="CC-BY-4.0")


def test_existing_group_id_result_contract_remains_readable(tmp_path):
    sample, record = _dataset(tmp_path)
    metadata = json.loads((sample / "sample.json").read_text())
    metadata["group_id"] = metadata.pop("visit_id")
    metadata["visit"] = metadata.pop("repetition")
    metadata["observers"] = metadata.pop("views")
    metadata["classifier_eligible"] = metadata.pop("eligible")
    atomic_json(sample / "sample.json", metadata)
    record["group_id"] = record.pop("visit_id")
    record["visit"] = record.pop("repetition")
    record["splits"] = {"parity": record.pop("split")}
    record["classifier_eligible"] = record.pop("eligible")
    record.pop("views")
    atomic_text(tmp_path / "samples.jsonl", json.dumps(record) + "\n")
    campaign = load_json(tmp_path / "campaign.json")
    campaign["groups"] = [{"group_id": "a" * 64}]
    campaign.pop("visits")
    atomic_json(tmp_path / "campaign.json", campaign)
    splits = load_json(tmp_path / "splits.json")
    splits["assignments"] = {"a" * 64: {"parity": "train"}}
    atomic_json(tmp_path / "splits.json", splits)
    assert validate_dataset(tmp_path)["valid"] is True
