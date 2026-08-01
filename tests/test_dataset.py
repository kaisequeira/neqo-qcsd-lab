import json
import socket
import subprocess
from pathlib import Path

import dpkt
import pytest

from qcsd_lab.capture import extract_trace, udp_ceiling_evidence, write_normalized_trace
from qcsd_lab.campaign import create_splits, stable_digest, visit_plan_for_workloads
from qcsd_lab.dataset import (
    CLASSIC_FIGURE_FILES,
    _validate_classic_figure_surface,
    validate_dataset,
    write_classifier_indexes,
)
from qcsd_lab.fidelity import write_fidelity_record
from qcsd_lab.seal import verify_checksum_seal
from qcsd_lab.util import (
    atomic_json,
    atomic_text,
    load_json,
    sha256_file,
    write_checksums,
)


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
    interface: str,
    link_type: str,
    primary: bool,
    endpoints: list[dict],
) -> dict:
    capture = sample / f"captures/{identifier}.pcapng"
    trace_path = sample / f"traces/{identifier}.csv"
    trace = extract_trace(capture, endpoints)
    write_normalized_trace(trace_path, trace)
    offload = {
        "interface": interface,
        "requested": {"gro": "off", "gso": "off", "tso": "off", "uso": "off"},
        "query_returncodes": {"before": 0, "after": 0},
        "change_returncodes": {"gro": 0, "gso": 0, "tso": 0, "uso": 0},
        "before_state": {"gro": "on", "gso": "on", "tso": "on", "uso": "on"},
        "after_state": {"gro": "off", "gso": "off", "tso": "off", "uso": "off"},
        "before_sha256": "0" * 64,
        "after_sha256": "1" * 64,
        "verified": True,
    }
    ceiling = udp_ceiling_evidence(trace, 1_200)
    ceiling.update(
        {
            "runner_resolved_udp_payload_ceiling": 1_200,
            "runner_binding_valid": True,
            "valid": True,
        }
    )
    value = {
        "id": identifier,
        "kind": "direct-quic",
        "interface": interface,
        "required": primary,
        "primary": primary,
        "role": "classifier" if primary else "diagnostic",
        "link_type": link_type,
        "length_basis": "frame.len",
        "flow_filter": "exact",
        "direction_rule": "declared",
        "capture_boundary": "known",
        "packet_count": len(trace),
        "truncated": False,
        "capture_active_through_settle": True,
        "capture_path": f"captures/{identifier}.pcapng",
        "trace_path": f"traces/{identifier}.csv",
        "capture_sha256": sha256_file(capture),
        "trace_sha256": sha256_file(trace_path),
        "pcapng_bytes": capture.stat().st_size,
        "udp_payload_ceiling_evidence": ceiling,
        "capture_offload_evidence": offload,
        "valid": True,
    }
    return value


def _dataset(root: Path) -> tuple[Path, dict]:
    resolved = root / "resolved-workloads/site.json"
    atomic_json(
        resolved,
        {
            "header_policy": {"mode": "minimal", "overrides": []},
            "resources": [
                {
                    "id": 0,
                    "url": "https://203.0.113.1/",
                    "headers": [],
                    "depends_on": [],
                }
            ],
        },
    )
    resolved_sha256 = sha256_file(resolved)
    workload_root = root / "source-workloads"
    workload = {
        "workload_id": "site",
        "class_label": "site",
        "role": "monitored",
        "visits": 1,
        "manifest": "source-workloads/site.json",
        "manifest_sha256": resolved_sha256,
        "source_manifest_sha256": resolved_sha256,
        "resolved_manifest_sha256": resolved_sha256,
        "workload_model": "as-defined",
        "resource_count": 1,
        "origin_count": 1,
        "expected_endpoint_count": 1,
    }
    study_id, visits = visit_plan_for_workloads(
        campaign_seed=42,
        request_policy="as-defined",
        workload_scope="as-defined",
        workload_root=workload_root,
        workloads=[workload],
    )
    [visit] = visits
    splits = create_splits([visit], 42)
    sample = root / "site/site-visit-00000/selected"
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
        sample / "captures/direct-quic.pcapng",
        [
            _packet("10.203.0.2", "203.0.113.1", 50000, 443),
            _packet("203.0.113.1", "10.203.0.2", 443, 50000),
        ],
    )
    direct = _observer(
        sample,
        "direct-quic",
        interface="eth0",
        link_type="Ethernet",
        primary=True,
        endpoints=endpoints,
    )
    atomic_json(
        sample / "neqo/run.json",
        {
            "completion_status": "complete",
            "endpoints": endpoints,
            "seed": visit["seed"],
            "workload_hash_sha256": resolved_sha256,
            "resolved_configuration": {
                "defense": {"kind": "none"},
                "max_udp_payload_size": 1_200,
            },
            "responses": [
                {
                    "resource_id": 0,
                    "status": 200,
                    "bytes": 4,
                    "body_sha256": "same",
                    "complete": True,
                    "outcome": "succeeded",
                }
            ],
        },
    )
    (sample / "neqo/packets.csv").write_text(
        "direction,monotonic_us,connection,observed_udp_length,"
        "scheduled_target,satisfaction,slot_id\n"
        "outgoing,1000,0,4,,unshaped,\n"
        "incoming,101000,0,4,,observed,\n",
        encoding="utf-8",
    )
    (sample / "neqo/events.csv").write_text("secret\n", encoding="utf-8")
    (sample / "neqo/schedule.csv").write_text("secret\n", encoding="utf-8")
    (sample / "neqo/qlog/endpoint.sqlog").write_text("secret\n", encoding="utf-8")

    sample_id = stable_digest(
        "sample",
        visit["visit_id"],
        "as-defined",
        "direct",
        "test",
        "selected",
    )
    metadata = {
        "sample_id": sample_id,
        "visit_id": visit["visit_id"],
        "split_group_id": visit["split_group_id"],
        "workload_id": "site",
        "workload_scope": "as-defined",
        "workload_model": "as-defined",
        "source_manifest_sha256": resolved_sha256,
        "resolved_manifest_sha256": resolved_sha256,
        "resource_count": 1,
        "origin_count": 1,
        "expected_endpoint_count": 1,
        "class_label": "site",
        "role": "monitored",
        "repetition": 0,
        "stage": "acceptance",
        "purpose": "classification",
        "request_policy": "as-defined",
        "defense": "selected",
        "runtime_kind": "none",
        "baseline": True,
        "seed": visit["seed"],
        "split": splits["assignments"][visit["split_group_id"]],
        "state": "captured",
        "attempts": 1,
        "eligible": True,
        "content_drift": False,
        "response_match": True,
        "resolved_defense": {
            "defense": {"kind": "none"},
            "max_udp_payload_size": 1_200,
        },
        "udp_payload_ceiling": 1_200,
        "capture_offloads": [direct["capture_offload_evidence"]],
        "views": [direct],
    }
    signature = [
        (0, 200, 4, "same", "succeeded"),
    ]
    metadata["response_signature_sha256"] = stable_digest(
        "responses", json.dumps(signature, sort_keys=True)
    )
    atomic_json(sample / "sample.json", metadata)
    trace_rows = extract_trace(sample / "captures/direct-quic.pcapng", endpoints)
    fidelity_path, fidelity_eligible = write_fidelity_record(
        sample,
        baseline_wire_bytes=sum(packet.length_bytes for packet in trace_rows),
    )
    metadata.update(
        fidelity_path=fidelity_path.name,
        fidelity_eligible=fidelity_eligible,
    )
    atomic_json(sample / "sample.json", metadata)
    record = {
        key: metadata[key]
        for key in (
            "sample_id",
            "visit_id",
            "split_group_id",
            "workload_id",
            "source_manifest_sha256",
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
            "fidelity_path",
            "fidelity_eligible",
        )
    }
    record["views"] = {"direct-quic": True}
    record["path"] = str(sample.relative_to(root))
    record["split"] = splits["assignments"][visit["split_group_id"]]
    atomic_text(root / "samples.jsonl", json.dumps(record, sort_keys=True) + "\n")
    atomic_json(
        root / "campaign.json",
        {
            "campaign": {
                "name": "test",
                "stage": "acceptance",
                "purpose": "classification",
                "status": "complete",
            },
            "configuration": {
                "stage": "acceptance",
                "study_id": study_id,
                "seed": 42,
                "qcsd_profile": "live",
                "capture": {
                    "mode": "direct",
                    "purpose": "classification",
                    "network_condition": "test",
                    "udp_payload_ceiling": 1_200,
                    "primary_view": "direct-quic",
                    "views": [
                        {
                            "id": "direct-quic",
                            "kind": "direct-quic",
                            "interface": "eth0",
                            "link_type": "Ethernet",
                            "length_basis": "frame.len",
                            "primary": True,
                        }
                    ],
                },
                "defenses": [
                    {
                        "name": "selected",
                        "kind": "none",
                        "baseline": True,
                    }
                ],
                "workloads": {
                    "root": str(workload_root),
                    "scope": "as-defined",
                    "request_policy": "as-defined",
                    "entries": [workload],
                },
            },
            "visits": [visit],
            "summary": {
                "eligible_visits": 1,
                "operationally_eligible_visits": 1,
                "fidelity_eligible_visits": 1,
                "required_visits": 1,
                "logical_samples": 1,
                "passed": True,
            },
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
        for observer in (direct,)
    ]
    atomic_json(
        root / "dataset.json",
        {
            "title": "test",
            "stage": "acceptance",
            "status": "complete",
            "purpose": "classification",
            "primary_observer": "direct-quic",
            "data_license": "not-for-release",
            "observer_definitions": definitions,
            "defenses": [{"name": "selected", "baseline": True}],
        },
    )
    atomic_json(root / "splits.json", splits)
    (root / "metrics.csv").write_text("sample\n", encoding="utf-8")
    atomic_json(root / "projection.json", {"measured": {}})
    (root / "report.html").write_text("<!doctype html>", encoding="utf-8")
    write_classifier_indexes(root)
    _seal(root)
    return sample, record


def _seal(root: Path) -> None:
    write_checksums(
        root,
        [path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"],
    )


def test_checksum_manifest_is_path_safe_unique_and_complete(tmp_path):
    first = tmp_path / "first.txt"
    second = tmp_path / "nested/second.txt"
    first.write_text("first\n", encoding="utf-8")
    second.parent.mkdir()
    second.write_text("second\n", encoding="utf-8")
    _seal(tmp_path)
    assert set(verify_checksum_seal(tmp_path)) == {
        "first.txt",
        "nested/second.txt",
    }

    valid = (tmp_path / "SHA256SUMS").read_text(encoding="utf-8")
    atomic_text(
        tmp_path / "SHA256SUMS",
        valid + f"{sha256_file(first)}  first.txt\n",
    )
    with pytest.raises(ValueError, match="duplicate SHA256SUMS entry"):
        verify_checksum_seal(tmp_path)

    atomic_text(
        tmp_path / "SHA256SUMS",
        valid + f"{'0' * 64}  ../outside.txt\n",
    )
    with pytest.raises(ValueError, match="invalid SHA256SUMS line"):
        verify_checksum_seal(tmp_path)

    atomic_text(
        tmp_path / "SHA256SUMS",
        valid.replace(sha256_file(first), "INVALID", 1),
    )
    with pytest.raises(ValueError, match="invalid SHA256SUMS line"):
        verify_checksum_seal(tmp_path)

    atomic_text(
        tmp_path / "SHA256SUMS",
        "".join(
            line + "\n" for line in valid.splitlines() if not line.endswith("nested/second.txt")
        ),
    )
    with pytest.raises(ValueError, match="does not exactly cover sealed files"):
        verify_checksum_seal(tmp_path)


def test_dataset_validation_reproduces_each_view_and_detects_split_leakage(tmp_path):
    _sample, record = _dataset(tmp_path)
    result = validate_dataset(tmp_path)
    assert result["valid"] is True
    assert result["purpose"] == "classification"
    assert result["eligible_samples"] == 1

    record["split"] = {
        "train": "test",
        "validation": "train",
        "test": "train",
    }[record["split"]]
    atomic_text(tmp_path / "samples.jsonl", json.dumps(record) + "\n")
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert invalid["valid"] is False
    assert any("wrong split" in error for error in invalid["errors"])


def test_dataset_validation_requires_an_exact_checksum_seal(tmp_path):
    _dataset(tmp_path)
    (tmp_path / "SHA256SUMS").unlink()

    invalid = validate_dataset(tmp_path, raise_on_error=False)

    assert invalid["valid"] is False
    assert "missing required root artifact: SHA256SUMS" in invalid["errors"]


def test_dataset_defenses_and_sample_ids_reproduce_from_campaign_plan(tmp_path):
    sample, record = _dataset(tmp_path)
    dataset = load_json(tmp_path / "dataset.json")
    dataset["defenses"][0]["name"] = "coordinated-alias"
    atomic_json(tmp_path / "dataset.json", dataset)
    replacement = "f" * 64
    record["sample_id"] = replacement
    atomic_text(tmp_path / "samples.jsonl", json.dumps(record, sort_keys=True) + "\n")
    metadata_path = sample / "sample.json"
    metadata = load_json(metadata_path)
    metadata["sample_id"] = replacement
    atomic_json(metadata_path, metadata)
    classifier_path = tmp_path / "classifier-samples.jsonl"
    [classifier] = [
        json.loads(line) for line in classifier_path.read_text(encoding="utf-8").splitlines()
    ]
    classifier["sample_id"] = replacement
    atomic_text(classifier_path, json.dumps(classifier, sort_keys=True) + "\n")
    _seal(tmp_path)

    invalid = validate_dataset(tmp_path, raise_on_error=False)

    assert any(
        "dataset defense declarations do not match the campaign" in error
        for error in invalid["errors"]
    )
    assert any(
        "sample index does not exactly match the reproduced campaign plan" in error
        for error in invalid["errors"]
    )


def test_classifier_index_uses_only_full_direct_delta_sequences(tmp_path):
    _sample, _record = _dataset(tmp_path)
    contract = load_json(tmp_path / "classifier.json")
    [record] = [
        json.loads(line)
        for line in (tmp_path / "classifier-samples.jsonl").read_text().splitlines()
    ]
    assert contract["feature_contract"]["model_features"] == ["sequence"]
    assert contract["feature_contract"]["normalization"] == "none"
    assert contract["feature_contract"]["defense_tail"] == "retained"
    assert record["sequence"][0][0] == 0
    assert {row[1] for row in record["sequence"]} == {-1, 1}
    assert not {
        "path",
        "endpoints",
        "schedule",
        "seed",
        "application_completion",
        "diagnostics",
        "duration",
    } & set(record)

    record["sequence"][0][2] += 1
    atomic_text(
        tmp_path / "classifier-samples.jsonl",
        json.dumps(record, sort_keys=True) + "\n",
    )
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any("classifier sequence mismatch" in error for error in invalid["errors"])


@pytest.mark.parametrize(
    "target",
    ["stage", "direction", "masking", "counts", "extra-key"],
)
def test_classifier_contract_is_exactly_bound_to_campaign_and_generation(tmp_path, target):
    _dataset(tmp_path)
    contract_path = tmp_path / "classifier.json"
    contract = load_json(contract_path)
    if target == "stage":
        contract["stage"] = "nonsense"
    elif target == "direction":
        contract["feature_contract"]["direction"]["client_egress"] = -1
    elif target == "masking":
        contract["feature_contract"]["batch_padding"] = "none"
    elif target == "counts":
        contract["record_count"] += 1
        contract["complete_pair_count"] += 1
    else:
        contract["endpoint_ip"] = "203.0.113.1"
    atomic_json(contract_path, contract)

    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert (
        "classifier.json does not exactly match the generated classifier contract"
        in invalid["errors"]
    )


def test_classifier_record_schema_rejects_additional_metadata(tmp_path):
    _dataset(tmp_path)
    records_path = tmp_path / "classifier-samples.jsonl"
    [record] = [json.loads(line) for line in records_path.read_text().splitlines()]
    record["endpoint_ip"] = "203.0.113.1"
    atomic_text(records_path, json.dumps(record, sort_keys=True) + "\n")

    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any("classifier record schema is not exact" in error for error in invalid["errors"])


def test_split_index_is_recomputed_after_coordinated_assignment_tamper(tmp_path):
    _dataset(tmp_path)
    splits_path = tmp_path / "splits.json"
    samples_path = tmp_path / "samples.jsonl"
    classifier_path = tmp_path / "classifier-samples.jsonl"
    splits = load_json(splits_path)
    [sample] = [json.loads(line) for line in samples_path.read_text().splitlines()]
    [classifier] = [json.loads(line) for line in classifier_path.read_text().splitlines()]
    replacement = {
        "train": "test",
        "validation": "train",
        "test": "train",
    }[sample["split"]]
    splits["assignments"][sample["split_group_id"]] = replacement
    sample["split"] = replacement
    classifier["split"] = replacement
    atomic_json(splits_path, splits)
    atomic_text(samples_path, json.dumps(sample, sort_keys=True) + "\n")
    atomic_text(classifier_path, json.dumps(classifier, sort_keys=True) + "\n")

    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any("split index does not exactly reproduce" in error for error in invalid["errors"])


def test_resealed_visit_identity_cannot_choose_a_different_split_group(tmp_path):
    sample_path, _record = _dataset(tmp_path)
    campaign_path = tmp_path / "campaign.json"
    samples_path = tmp_path / "samples.jsonl"
    campaign = load_json(campaign_path)
    [record] = [json.loads(line) for line in samples_path.read_text().splitlines()]
    [visit] = campaign["visits"]

    replacement_visit_id = "b" * 64
    replacement_seed = int(stable_digest("seed", 42, replacement_visit_id)[:16], 16)
    visit["visit_id"] = replacement_visit_id
    visit["seed"] = replacement_seed
    replacement_splits = create_splits([visit], 42)
    replacement_sample_id = stable_digest(
        "sample",
        replacement_visit_id,
        "as-defined",
        "direct",
        "test",
        "selected",
    )
    record.update(
        sample_id=replacement_sample_id,
        visit_id=replacement_visit_id,
        seed=replacement_seed,
        split=replacement_splits["assignments"][visit["split_group_id"]],
    )
    metadata_path = sample_path / "sample.json"
    metadata = load_json(metadata_path)
    metadata.update(
        sample_id=replacement_sample_id,
        visit_id=replacement_visit_id,
        seed=replacement_seed,
        split=replacement_splits["assignments"][visit["split_group_id"]],
    )
    run_path = sample_path / "neqo/run.json"
    run_data = load_json(run_path)
    run_data["seed"] = replacement_seed

    atomic_json(campaign_path, campaign)
    atomic_json(tmp_path / "splits.json", replacement_splits)
    atomic_text(samples_path, json.dumps(record, sort_keys=True) + "\n")
    atomic_json(metadata_path, metadata)
    atomic_json(run_path, run_data)
    write_classifier_indexes(tmp_path)
    _seal(tmp_path)

    invalid = validate_dataset(tmp_path, raise_on_error=False)

    assert invalid["valid"] is False
    assert "campaign visits do not exactly reproduce from workload provenance" in invalid["errors"]


def test_resealed_split_group_identity_cannot_launder_assignment(tmp_path):
    sample_path, _record = _dataset(tmp_path)
    campaign_path = tmp_path / "campaign.json"
    samples_path = tmp_path / "samples.jsonl"
    campaign = load_json(campaign_path)
    [record] = [json.loads(line) for line in samples_path.read_text().splitlines()]
    [visit] = campaign["visits"]
    original_split = record["split"]

    for index in range(10_000):
        replacement_split_group_id = stable_digest("laundered-split-group", index)
        visit["split_group_id"] = replacement_split_group_id
        replacement_splits = create_splits([visit], 42)
        replacement_split = replacement_splits["assignments"][replacement_split_group_id]
        if replacement_split != original_split:
            break
    else:
        raise AssertionError("could not construct a different split assignment")

    record.update(
        split_group_id=replacement_split_group_id,
        split=replacement_split,
    )
    metadata_path = sample_path / "sample.json"
    metadata = load_json(metadata_path)
    metadata.update(
        split_group_id=replacement_split_group_id,
        split=replacement_split,
    )

    atomic_json(campaign_path, campaign)
    atomic_json(tmp_path / "splits.json", replacement_splits)
    atomic_text(samples_path, json.dumps(record, sort_keys=True) + "\n")
    atomic_json(metadata_path, metadata)
    write_classifier_indexes(tmp_path)
    _seal(tmp_path)

    invalid = validate_dataset(tmp_path, raise_on_error=False)

    assert invalid["valid"] is False
    assert "campaign visits do not exactly reproduce from workload provenance" in invalid["errors"]


@pytest.mark.parametrize("target", ["seed", "workload-hash", "resolved-defense"])
def test_resealed_runner_input_binding_tamper_is_rejected(tmp_path, target):
    sample_path, _record = _dataset(tmp_path)
    run_path = sample_path / "neqo/run.json"
    run_data = load_json(run_path)
    if target == "seed":
        run_data["seed"] += 1
    elif target == "workload-hash":
        run_data["workload_hash_sha256"] = "f" * 64
    else:
        run_data["resolved_configuration"]["defense"]["kind"] = "front"
    atomic_json(run_path, run_data)
    _seal(tmp_path)

    invalid = validate_dataset(tmp_path, raise_on_error=False)

    assert invalid["valid"] is False
    assert any("sample run binding is invalid" in error for error in invalid["errors"])


def test_fidelity_record_is_required_reproduced_and_partial_suite_cannot_be_research(
    tmp_path,
):
    sample, record = _dataset(tmp_path)
    fidelity = load_json(sample / "fidelity.yml")
    assert fidelity["adaptation"] == "none"
    assert fidelity["sample_eligible"] is True
    assert fidelity["fidelity_eligible"] is True
    assert fidelity["realization_metrics"]["direct_wire_bytes"] > 0

    campaign = load_json(tmp_path / "campaign.json")
    campaign["campaign"]["stage"] = "research"
    campaign["configuration"]["stage"] = "research"
    atomic_json(tmp_path / "campaign.json", campaign)
    write_classifier_indexes(tmp_path)
    [classifier_record] = [
        json.loads(line)
        for line in (tmp_path / "classifier-samples.jsonl").read_text().splitlines()
    ]
    assert classifier_record["eligibility"] == {
        "sample": True,
        "fidelity": True,
        "seven_way_pair": False,
        "research": False,
    }
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any(
        "research classifier data requires the canonical seven-defense suite" in error
        for error in invalid["errors"]
    )

    fidelity["realization_metrics"]["direct_wire_bytes"] += 1
    atomic_json(sample / "fidelity.yml", fidelity)
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any("fidelity direct-byte metric" in error for error in invalid["errors"])

    fidelity["realization_metrics"]["direct_wire_bytes"] -= 1
    fidelity["realization_metrics"]["scheduled_events"] += 1
    atomic_json(sample / "fidelity.yml", fidelity)
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any(
        "fidelity record does not reproduce from sealed evidence" in error
        for error in invalid["errors"]
    )

    (sample / "fidelity.yml").unlink()
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any("fidelity record is missing" in error for error in invalid["errors"])


def test_dataset_requires_sample_parameter_artifacts_in_checksum_seal(tmp_path):
    sample, record = _dataset(tmp_path)
    parameter = sample / "neqo/defense-parameters.json"
    provenance = sample / "neqo/defense-parameters.provenance.json"
    parameter.write_text("{}\n", encoding="utf-8")
    atomic_json(
        provenance,
        {
            "schema_version": 1,
            "generator": "test-fixture",
            "input_policy": "reviewed-engineering-fixture",
            "unsealed_engineering_opt_in": True,
            "parameter_file": {
                "path": "external-parameter.json",
                "sha256": sha256_file(parameter),
            },
            "inputs": {},
        },
    )
    campaign = load_json(tmp_path / "campaign.json")
    campaign["configuration"]["defenses"] = [
        {
            "name": "selected",
            "kind": "none",
            "baseline": True,
            "parameters": "external-parameter.json",
            "parameters_sha256": sha256_file(parameter),
            "parameters_provenance_sha256": sha256_file(provenance),
            "parameters_input_policy": "reviewed-engineering-fixture",
        }
    ]
    atomic_json(tmp_path / "campaign.json", campaign)
    run_path = sample / "neqo/run.json"
    run_data = load_json(run_path)
    run_data["defense_parameters"] = {
        "kind": "none",
        "path": "/external/parameter.json",
        "sha256": sha256_file(parameter),
    }
    atomic_json(run_path, run_data)
    _seal(tmp_path)
    assert validate_dataset(tmp_path)["valid"] is True

    run_data["defense_parameters"]["sha256"] = "0" * 64
    atomic_json(run_path, run_data)
    _seal(tmp_path)
    result = validate_dataset(tmp_path, raise_on_error=False)
    assert result["valid"] is False
    assert any("parameter run binding mismatch" in error for error in result["errors"])
    run_data["defense_parameters"]["sha256"] = sha256_file(parameter)
    run_data["defense_parameters"]["kind"] = "wrong-runtime"
    atomic_json(run_path, run_data)
    _seal(tmp_path)
    result = validate_dataset(tmp_path, raise_on_error=False)
    assert result["valid"] is False
    assert any("parameter run binding mismatch" in error for error in result["errors"])
    run_data["defense_parameters"]["kind"] = "none"
    atomic_json(run_path, run_data)

    record["runtime_kind"] = "wrong-runtime"
    atomic_text(tmp_path / "samples.jsonl", json.dumps(record, sort_keys=True) + "\n")
    _seal(tmp_path)
    result = validate_dataset(tmp_path, raise_on_error=False)
    assert result["valid"] is False
    assert any("indexed runtime kind mismatch" in error for error in result["errors"])
    record["runtime_kind"] = "none"
    atomic_text(tmp_path / "samples.jsonl", json.dumps(record, sort_keys=True) + "\n")

    metadata_path = sample / "sample.json"
    metadata = load_json(metadata_path)
    metadata["runtime_kind"] = "wrong-runtime"
    atomic_json(metadata_path, metadata)
    _seal(tmp_path)
    result = validate_dataset(tmp_path, raise_on_error=False)
    assert result["valid"] is False
    assert any("metadata runtime kind mismatch" in error for error in result["errors"])
    metadata["runtime_kind"] = "none"
    atomic_json(metadata_path, metadata)
    _seal(tmp_path)

    atomic_text(
        tmp_path / "SHA256SUMS",
        "".join(
            line + "\n"
            for line in (tmp_path / "SHA256SUMS").read_text().splitlines()
            if not line.endswith("defense-parameters.provenance.json")
        ),
    )
    result = validate_dataset(tmp_path, raise_on_error=False)
    assert result["valid"] is False
    assert any("parameter artifact is not checksum-sealed" in error for error in result["errors"])


def test_dataset_rejects_passed_campaign_with_guarded_ineligible_sample(tmp_path):
    sample, record = _dataset(tmp_path)
    run_path = sample / "neqo/run.json"
    run_data = load_json(run_path)
    run_data["defense_diagnostics"] = {
        "padding_events": 100,
        "padding_event_guard_triggered": True,
    }
    atomic_json(run_path, run_data)

    metadata_path = sample / "sample.json"
    metadata = load_json(metadata_path)
    metadata.update(eligible=False, operationally_valid=False)
    atomic_json(metadata_path, metadata)
    baseline_wire_bytes = load_json(sample / "fidelity.yml")["realization_metrics"][
        "direct_wire_bytes"
    ]
    _path, fidelity_eligible = write_fidelity_record(
        sample,
        baseline_wire_bytes=baseline_wire_bytes,
    )
    metadata.update(fidelity_eligible=fidelity_eligible)
    atomic_json(metadata_path, metadata)
    record.update(
        eligible=False,
        operationally_valid=False,
        fidelity_eligible=fidelity_eligible,
    )
    atomic_text(
        tmp_path / "samples.jsonl",
        json.dumps(record, sort_keys=True) + "\n",
    )
    write_classifier_indexes(tmp_path)
    _seal(tmp_path)

    result = validate_dataset(tmp_path, raise_on_error=False)
    assert result["valid"] is False
    assert result["eligible_samples"] == 0
    assert (
        "campaign summary does not exactly match validated sample eligibility" in result["errors"]
    )
    assert "passed campaign contains incomplete or ineligible planned visits" in result["errors"]


def test_dataset_rejects_resealed_campaign_summary_tamper(tmp_path):
    _dataset(tmp_path)
    campaign_path = tmp_path / "campaign.json"
    campaign = load_json(campaign_path)
    campaign["summary"]["eligible_visits"] = 0
    campaign["summary"]["logical_samples"] = 2
    atomic_json(campaign_path, campaign)
    _seal(tmp_path)

    result = validate_dataset(tmp_path, raise_on_error=False)
    assert result["valid"] is False
    assert (
        "campaign summary does not exactly match validated sample eligibility" in result["errors"]
    )


def test_dataset_requires_supported_purpose_and_canonical_direct_view(tmp_path):
    _dataset(tmp_path)
    dataset_path = tmp_path / "dataset.json"
    dataset = load_json(dataset_path)
    dataset["purpose"] = "diagnostics"
    atomic_json(dataset_path, dataset)
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert "dataset purpose must be classification or parameter-fitting" in invalid["errors"]

    dataset["purpose"] = "classification"
    dataset["observer_definitions"][0]["length_basis"] = "udp.length"
    atomic_json(dataset_path, dataset)
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert "dataset must use the canonical direct QUIC view" in invalid["errors"]


@pytest.mark.parametrize(
    ("target", "value", "message"),
    [
        (
            "capture-mode",
            "alternate",
            "campaign must declare one supported direct-capture purpose "
            "(classification or parameter-fitting)",
        ),
        (
            "campaign-primary",
            "other",
            "campaign must configure exactly one canonical direct QUIC view",
        ),
        ("dataset-primary", "other", "dataset must use the canonical direct QUIC view"),
        ("license", "CC-BY-4.0", "dataset data license must be not-for-release"),
    ],
)
def test_dataset_rejects_direct_contract_metadata_drift(tmp_path, target, value, message):
    _dataset(tmp_path)
    campaign_path = tmp_path / "campaign.json"
    dataset_path = tmp_path / "dataset.json"
    campaign = load_json(campaign_path)
    dataset = load_json(dataset_path)
    if target == "capture-mode":
        campaign["configuration"]["capture"]["mode"] = value
    elif target == "campaign-primary":
        campaign["configuration"]["capture"]["primary_view"] = value
    elif target == "dataset-primary":
        dataset["primary_observer"] = value
    else:
        dataset["data_license"] = value
    atomic_json(campaign_path, campaign)
    atomic_json(dataset_path, dataset)

    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert message in invalid["errors"]


@pytest.mark.parametrize(
    "target",
    [
        "ceiling",
        "offload-state",
        "offload-request",
        "offload-query-returncode",
        "offload-change-returncode",
    ],
)
def test_dataset_rejects_tampered_packet_unit_evidence(tmp_path, target):
    sample, _record = _dataset(tmp_path)
    metadata_path = sample / "sample.json"
    metadata = load_json(metadata_path)
    view = metadata["views"][0]
    if target == "ceiling":
        view["udp_payload_ceiling_evidence"]["observed_udp_payload_max"] = 1_201
        message = "UDP-payload ceiling evidence mismatch"
    else:
        offload = view["capture_offload_evidence"]
        if target == "offload-state":
            offload["after_state"]["gro"] = "on"
        elif target == "offload-request":
            offload["requested"]["gro"] = "on"
        elif target == "offload-query-returncode":
            offload["query_returncodes"]["after"] = 1
        else:
            offload["change_returncodes"]["gso"] = 1
        metadata["capture_offloads"] = [view["capture_offload_evidence"]]
        message = "capture offload evidence is invalid"
    atomic_json(metadata_path, metadata)

    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any(message in error for error in invalid["errors"])


def test_dataset_requires_exactly_one_view_and_fixed_contained_paths(tmp_path):
    sample, _record = _dataset(tmp_path)
    campaign_path = tmp_path / "campaign.json"
    campaign = load_json(campaign_path)
    campaign["configuration"]["capture"]["views"].append(
        dict(campaign["configuration"]["capture"]["views"][0])
    )
    atomic_json(campaign_path, campaign)
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any("exactly one canonical direct QUIC view" in error for error in invalid["errors"])
    campaign["configuration"]["capture"]["views"] = campaign["configuration"]["capture"]["views"][
        :1
    ]
    atomic_json(campaign_path, campaign)

    dataset_path = tmp_path / "dataset.json"
    dataset = load_json(dataset_path)
    dataset["observer_definitions"].append(dict(dataset["observer_definitions"][0]))
    atomic_json(dataset_path, dataset)
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert "dataset must declare exactly one observer definition" in invalid["errors"]
    dataset["observer_definitions"] = dataset["observer_definitions"][:1]
    atomic_json(dataset_path, dataset)

    metadata_path = sample / "sample.json"
    metadata = load_json(metadata_path)
    metadata["views"].append(dict(metadata["views"][0]))
    atomic_json(metadata_path, metadata)
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any("exactly one direct view" in error for error in invalid["errors"])

    metadata["views"] = metadata["views"][:1]
    metadata["views"][0]["capture_path"] = "../../outside.pcapng"
    atomic_json(metadata_path, metadata)
    invalid = validate_dataset(tmp_path, raise_on_error=False)
    assert any("fixed direct artifact paths" in error for error in invalid["errors"])
    assert any("capture path escapes sample directory" in error for error in invalid["errors"])


@pytest.mark.parametrize(
    ("directory", "filename"),
    [
        ("captures", "alternate.pcapng"),
        ("traces", "alternate.csv"),
    ],
)
def test_dataset_rejects_extra_direct_artifacts(tmp_path, directory, filename):
    sample, _record = _dataset(tmp_path)
    (sample / directory / filename).write_text("extra\n", encoding="utf-8")
    _seal(tmp_path)

    invalid = validate_dataset(tmp_path, raise_on_error=False)

    assert any(
        f"sample {directory} artifacts must be exactly" in error for error in invalid["errors"]
    )


def test_classic_figure_surface_requires_two_pages_formats_seal_and_report_links(tmp_path):
    group = tmp_path / "site/site-visit-00000"
    group.mkdir(parents=True)
    report_parts = []
    for name in sorted(CLASSIC_FIGURE_FILES):
        path = group / name
        relative = path.relative_to(tmp_path).as_posix()
        if path.suffix == ".pdf":
            path.write_bytes(b"%PDF-1.7\n")
            report_parts.append(f'<a href="{relative}">PDF</a>')
        else:
            path.write_text("<svg></svg>\n", encoding="utf-8")
            report_parts.append(f'<img src="{relative}">')
    (tmp_path / "report.html").write_text("".join(report_parts), encoding="utf-8")
    sealed = {path.relative_to(tmp_path).as_posix() for path in group.iterdir() if path.is_file()}
    errors = []

    _validate_classic_figure_surface(
        tmp_path,
        [{"path": "site/site-visit-00000"}],
        sealed,
        errors,
    )
    assert errors == []

    (group / "trace-comparison-2.svg").unlink()
    errors = []
    _validate_classic_figure_surface(
        tmp_path,
        [{"path": "site/site-visit-00000"}],
        sealed,
        errors,
    )
    assert any("exact two-page PDF/SVG surface" in error for error in errors)
