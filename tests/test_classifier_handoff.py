from __future__ import annotations

import csv
import json
import os
import socket
import subprocess
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import dpkt
import pytest

import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.capture import ObserverPacket
from tools import classifier_handoff
from tools.classifier_handoff import (
    export_classifier_handoff,
    validate_classifier_handoff,
    write_shape_only_pcap,
)
from qcsd_lab.experiment import (
    accept_sample,
    finalize_experiment,
    initialize_experiment,
    transition_sample,
)
from qcsd_lab.util import atomic_json, atomic_text, sha256_file
from qcsd_lab.verification import seal_result


CLIENT_MAC = b"\x02\x00\x00\x00\x00\x01"
SERVER_MAC = b"\x02\x00\x00\x00\x00\x02"
CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_PORT = 49_152
SERVER_PORT = 443
TRACE_HEADER = [
    "relative_time_ns",
    "direction",
    "length_bytes",
    "signed_length_bytes",
]
ROOT = Path(__file__).parents[1]


def test_classifier_pilot_launcher_is_external_offline_and_least_privilege() -> None:
    root = Path(__file__).parents[1]
    launcher_path = root / "classifier-pilot"
    launcher = launcher_path.read_text(encoding="utf-8")

    assert os.access(launcher_path, os.X_OK)
    subprocess.run(["bash", "-n", launcher_path], check=True)
    assert "--network none" in launcher
    assert "--cap-drop ALL" in launcher
    assert "--security-opt no-new-privileges" in launcher
    assert '--volume "${ROOT}:/lab:ro"' in launcher
    assert '--volume "${HANDOFF_ROOT}:/lab/handoffs:rw"' in launcher
    assert '--volume "${TOOL}:/opt/qcsd-tools/classifier_handoff.py:ro"' in launcher
    assert "tools/classifier_handoff.py" in launcher
    assert not (root / "src/qcsd_lab/classifier_handoff.py").exists()


def _ethernet_udp_packet(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    *,
    frame_len: int,
    fill: bytes,
) -> bytes:
    payload_len = frame_len - 14 - 20 - 8
    assert payload_len >= 0
    payload = (fill * (payload_len // len(fill) + 1))[:payload_len]
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
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\xaa\xbb\xcc\xdd\xee\xff",
        dst=b"\x10\x20\x30\x40\x50\x60",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    encoded = bytes(ethernet)
    assert len(encoded) == frame_len
    return encoded


def _write_raw_capture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        writer.writepkt(
            _ethernet_udp_packet(
                "172.17.0.2",
                "203.0.113.10",
                50_000,
                443,
                frame_len=64,
                fill=b"raw-client-secret",
            ),
            ts=100.0,
        )
        writer.writepkt(
            _ethernet_udp_packet(
                "203.0.113.10",
                "172.17.0.2",
                443,
                50_000,
                frame_len=75,
                fill=b"raw-server-secret",
            ),
            ts=100.125,
        )


def _make_result(
    parent: Path,
    *,
    block_number: int = 0,
    accepted: bool = True,
    eligible: bool = True,
    sealed: bool = True,
) -> tuple[Path, dict]:
    fixture_root = parent / f"source-{block_number:03d}"
    root = fixture_root / "results" / f"run-{block_number:03d}"
    config = fixture_root / "config"
    (config / "campaigns").mkdir(parents=True)
    (config / "workloads").mkdir()
    atomic_text(
        config / "workloads/site.json",
        '{"resources":[{"id":0,"url":"https://site.test/","type":"Document",'
        '"content_length":64,"data_length":64,"chaff_priority":true,'
        '"known_valid":true,"depends_on":[],"headers":[]}]}\n',
    )
    campaign_path = config / "campaigns/pilot.yml"
    atomic_text(
        campaign_path,
        "schema: 1\n"
        f"name: pilot-block-{block_number:03d}\n"
        "purpose: smoke\n"
        f"seed: {10_000 + block_number}\n"
        "profile: live\n"
        "workloads:\n  site: 1\n"
        "request_policies:\n  - as-defined\n"
        "defenses:\n  - undefended\n",
    )
    source = {"lab_commit": f"{block_number + 1:040x}"}
    campaign = orchestrator.load_campaign(campaign_path)
    runtime, configuration = orchestrator._materialize_inputs(root, campaign, source)
    [planned] = orchestrator.plan_campaign(runtime)
    experiment = initialize_experiment(
        root,
        name=campaign.name,
        purpose=campaign.purpose,
        run_id=root.name,
        source=source,
        configuration=configuration,
        samples=[planned],
        started_at=f"2026-08-{block_number + 1:02d}T00:00:00+00:00",
    )
    transition_sample(experiment, planned["sample_id"], "running", increment_attempt=True)
    if accepted:
        sample_root = root / planned["path"]
        _write_raw_capture(sample_root / "capture.pcapng")
        atomic_json(
            sample_root / "neqo/run.json",
            {
                "endpoints": [
                    {
                        "id": 0,
                        "local_address": "172.17.0.2:50000",
                        "remote_address": "203.0.113.10:443",
                    }
                ]
            },
        )
        atomic_text(sample_root / "neqo/packets.csv", "time,size\n")
        atomic_text(sample_root / "neqo/events.csv", "time,event\n")
        atomic_text(sample_root / "neqo/schedule.csv", "time,size\n")
        accept_sample(root, experiment, planned["sample_id"], eligible=eligible)
    else:
        transition_sample(
            experiment,
            planned["sample_id"],
            "failed",
            failure={"kind": "synthetic-test-failure"},
        )
    finalize_experiment(
        root,
        experiment,
        status="complete" if accepted and eligible else "incomplete",
        completed_at=f"2026-08-{block_number + 1:02d}T00:01:00+00:00",
    )
    if sealed:
        seal_result(root)
    return root, experiment


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _checksums(root: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    for line in lines:
        digest, separator, relative = line.partition("  ")
        assert separator == "  "
        assert len(digest) == 64
        assert digest == digest.lower()
        assert relative and relative not in checksums
        checksums[relative] = digest
    return checksums


def _rewrite_handoff_checksums(root: Path) -> None:
    files = sorted(path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    atomic_text(
        root / "SHA256SUMS",
        "".join(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}\n" for path in files),
    )


def _read_shape_pcap(path: Path) -> list[tuple[Decimal, dpkt.ethernet.Ethernet, bytes]]:
    with path.open("rb") as source:
        reader = dpkt.pcap.Reader(source)
        assert reader._divisor == Decimal("1E9")
        return [(timestamp, dpkt.ethernet.Ethernet(packet), packet) for timestamp, packet in reader]


def _assert_shape_packets(
    packets: list[tuple[Decimal, dpkt.ethernet.Ethernet, bytes]],
    expected: list[tuple[int, str, int]],
) -> None:
    assert len(packets) == len(expected)
    for (timestamp, ethernet, encoded), (relative_ns, direction, frame_len) in zip(
        packets, expected, strict=True
    ):
        assert timestamp == Decimal(relative_ns) / Decimal(1_000_000_000)
        assert len(encoded) == frame_len
        ip = ethernet.data
        udp = ip.data
        if direction == "outgoing":
            assert ethernet.src == CLIENT_MAC
            assert ethernet.dst == SERVER_MAC
            assert socket.inet_ntoa(ip.src) == CLIENT_IP
            assert socket.inet_ntoa(ip.dst) == SERVER_IP
            assert (udp.sport, udp.dport) == (CLIENT_PORT, SERVER_PORT)
        else:
            assert ethernet.src == SERVER_MAC
            assert ethernet.dst == CLIENT_MAC
            assert socket.inet_ntoa(ip.src) == SERVER_IP
            assert socket.inet_ntoa(ip.dst) == CLIENT_IP
            assert (udp.sport, udp.dport) == (SERVER_PORT, CLIENT_PORT)
        assert bytes(udp.data) == b"\0" * (frame_len - 14 - 20 - 8)


def test_shape_only_pcap_has_fixed_identifiers_zero_payload_and_exact_shape(
    tmp_path: Path,
) -> None:
    trace = [
        ObserverPacket(7_000_000_000, 0, "outgoing", 64, 64, 22),
        ObserverPacket(7_125_000_000, 125_000_000, "incoming", 75, -75, 33),
        ObserverPacket(7_500_000_000, 500_000_000, "outgoing", 128, 128, 86),
    ]
    path = tmp_path / "shape.pcap"

    write_shape_only_pcap(trace, path)

    _assert_shape_packets(
        _read_shape_pcap(path),
        [
            (0, "outgoing", 64),
            (125_000_000, "incoming", 75),
            (500_000_000, "outgoing", 128),
        ],
    )
    assert b"raw-client-secret" not in path.read_bytes()
    assert b"raw-server-secret" not in path.read_bytes()


@pytest.mark.parametrize(
    ("trace", "message"),
    [
        ([ObserverPacket(0, 0, "sideways", 64, 64, 22)], "direction"),
        ([ObserverPacket(0, 0, "outgoing", 41, 41, 0)], "frame"),
        (
            [
                ObserverPacket(0, 10, "outgoing", 64, 64, 22),
                ObserverPacket(0, 9, "incoming", 64, -64, 22),
            ],
            "time",
        ),
    ],
)
def test_shape_only_pcap_rejects_unrepresentable_traces(
    tmp_path: Path,
    trace: list[ObserverPacket],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        write_shape_only_pcap(trace, tmp_path / "invalid.pcap")


def test_export_preserves_raw_evidence_and_emits_portable_shape_artifacts(
    tmp_path: Path,
) -> None:
    source, experiment = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    sample = experiment["samples"][0]
    source_sample = source / sample["path"]

    export_classifier_handoff([source], destination)

    assert destination.is_dir() and not destination.is_symlink()
    assert sorted(path.name for path in destination.iterdir()) == [
        "README.md",
        "SHA256SUMS",
        "dataset.json",
        "raw",
        "samples.jsonl",
        "stripped",
        "traces",
    ]
    dataset = json.loads((destination / "dataset.json").read_text(encoding="utf-8"))
    assert dataset["schema_version"] == 1
    assert dataset["artifact_type"] == "qcsd-classifier-pilot-handoff"
    assert dataset["sample_count"] == 1
    assert dataset["counts_by_split"] == {"unassigned": 1}
    assert dataset["observer"]["trace_columns"] == TRACE_HEADER
    assert len(dataset["blocks"]) == 1
    block = dataset["blocks"][0]
    assert block["block_id"] == "block-001"
    assert block["split"] is None
    assert block["result_name"] == experiment["name"]
    assert block["run_id"] == source.name
    assert block["input_digest"] == experiment["input_digest"]
    assert block["campaign_sha256"] == experiment["configuration"]["campaign_sha256"]
    assert block["evidence_index_sha256"] == sha256_file(source / "evidence.sha256")

    [row] = _jsonl(destination / "samples.jsonl")
    assert {
        key: row[key]
        for key in (
            "sample_id",
            "workload_id",
            "class_label",
            "request_policy",
            "visit",
            "defense",
            "seed",
            "block_id",
            "split",
        )
    } == {
        "sample_id": sample["sample_id"],
        "workload_id": "site",
        "class_label": "site",
        "request_policy": "as-defined",
        "visit": 0,
        "defense": "undefended",
        "seed": sample["seed"],
        "block_id": "block-001",
        "split": None,
    }
    sample_id = sample["sample_id"]
    paths = {
        "raw_pcapng_path": f"raw/{sample_id}.pcapng",
        "raw_pcap_path": f"raw/{sample_id}.pcap",
        "raw_run_path": f"raw/{sample_id}.run.json",
        "shape_pcap_path": f"stripped/{sample_id}.pcap",
        "trace_path": f"traces/{sample_id}.csv",
    }
    assert {key: row[key] for key in paths} == paths
    assert (destination / row["raw_pcapng_path"]).read_bytes() == (
        source_sample / "capture.pcapng"
    ).read_bytes()
    with (
        (source_sample / "capture.pcapng").open("rb") as source_capture,
        (destination / row["raw_pcap_path"]).open("rb") as compatible_capture,
    ):
        assert list(dpkt.pcap.Reader(compatible_capture)) == list(dpkt.pcap.Reader(source_capture))
    assert (destination / row["raw_run_path"]).read_bytes() == (
        source_sample / "neqo/run.json"
    ).read_bytes()

    with (destination / row["trace_path"]).open(newline="", encoding="utf-8") as source:
        assert list(csv.reader(source)) == [
            TRACE_HEADER,
            ["0", "outgoing", "64", "64"],
            ["125000000", "incoming", "75", "-75"],
        ]
    _assert_shape_packets(
        _read_shape_pcap(destination / row["shape_pcap_path"]),
        [(0, "outgoing", 64), (125_000_000, "incoming", 75)],
    )

    checksums = _checksums(destination)
    assert list(checksums) == sorted(checksums)
    actual = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    assert set(checksums) == actual
    assert all(sha256_file(destination / path) == digest for path, digest in checksums.items())
    validate_classifier_handoff(destination)


@pytest.mark.parametrize(
    ("accepted", "eligible", "sealed", "message"),
    [
        (True, True, False, "seal|evidence"),
        (True, False, True, "eligible"),
        (False, False, True, "accepted|all-eligible"),
    ],
)
def test_export_requires_sealed_fully_accepted_eligible_results(
    tmp_path: Path,
    accepted: bool,
    eligible: bool,
    sealed: bool,
    message: str,
) -> None:
    source, _ = _make_result(
        tmp_path,
        accepted=accepted,
        eligible=eligible,
        sealed=sealed,
    )
    destination = tmp_path / "handoff"

    with pytest.raises(ValueError, match=message):
        export_classifier_handoff([source], destination)

    assert not destination.exists()


def test_export_rejects_duplicate_sample_ids_across_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _ = _make_result(tmp_path / "first")
    second, _ = _make_result(tmp_path / "second")
    destination = tmp_path / "handoff"
    monkeypatch.setattr(classifier_handoff, "_validate_pilot_collection", lambda *_args: None)

    with pytest.raises(ValueError, match="duplicate.*sample ID"):
        export_classifier_handoff(
            [first, second],
            destination,
            block_splits=["train", "test"],
        )

    assert not destination.exists()


def test_pilot_contract_rejects_named_block_with_wrong_42_sample_shape() -> None:
    receipt = SimpleNamespace(
        experiment={
            "name": "research-classifier-pilot-01-1200",
            "purpose": "evaluation",
            "samples": [
                {
                    "workload_id": "getbootstrap-home-r3",
                    "defense": "undefended",
                    "request_policy": "as-defined",
                    "visit": 0,
                    "runtime_kind": "none",
                    "baseline": True,
                }
            ],
        }
    )

    with pytest.raises(ValueError, match="42-sample cohort"):
        classifier_handoff._validate_pilot_collection([receipt], [None])


def test_pilot_contract_rejects_training_split_for_nonpilot_evaluation() -> None:
    receipt = SimpleNamespace(
        experiment={"name": "other-evaluation", "purpose": "evaluation", "samples": []}
    )

    with pytest.raises(ValueError, match="one interface result only"):
        classifier_handoff._validate_pilot_collection([receipt], ["train"])


def _pilot_receipts() -> list[SimpleNamespace]:
    receipts: list[SimpleNamespace] = []
    for block, name in enumerate(classifier_handoff.PILOT_RESULT_NAMES, 1):
        samples = []
        for workload_id in classifier_handoff.PILOT_CLASSES:
            for defense in classifier_handoff.PILOT_DEFENSES:
                runtime_kind, baseline = classifier_handoff.PILOT_RUNTIME[defense]
                samples.append(
                    {
                        "workload_id": workload_id,
                        "defense": defense,
                        "request_policy": "as-defined",
                        "visit": 0,
                        "runtime_kind": runtime_kind,
                        "baseline": baseline,
                    }
                )
        campaign = ROOT / f"config/campaigns/classifier-pilot-{block:02d}.yml"
        receipts.append(
            SimpleNamespace(
                experiment={
                    "name": name,
                    "purpose": "evaluation",
                    "samples": samples,
                    "configuration": {"campaign_sha256": sha256_file(campaign)},
                }
            )
        )
    return receipts


def test_pilot_contract_accepts_interface_block_01_and_exact_seven_block_split() -> None:
    receipts = _pilot_receipts()

    classifier_handoff._validate_pilot_collection([receipts[0]], [None])
    classifier_handoff._validate_pilot_collection([receipts[0]], ["interface"])
    classifier_handoff._validate_pilot_collection(receipts, list(classifier_handoff.PILOT_SPLITS))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("wrong-order", "ordered blocks"),
        ("wrong-split", "5/1/1"),
        ("wrong-count", "block 01 alone or all seven"),
        ("wrong-runtime", "42-sample cohort"),
        ("wrong-campaign", "checked-in campaign"),
    ],
)
def test_pilot_contract_rejects_wrong_block_identity(
    mutation: str,
    message: str,
) -> None:
    receipts = _pilot_receipts()
    splits = list(classifier_handoff.PILOT_SPLITS)
    if mutation == "wrong-order":
        receipts[0], receipts[1] = receipts[1], receipts[0]
    elif mutation == "wrong-split":
        splits[-1] = "validation"
    elif mutation == "wrong-count":
        receipts = receipts[:-1]
        splits = splits[:-1]
    elif mutation == "wrong-runtime":
        receipts[0].experiment["samples"][0]["runtime_kind"] = "front"
    elif mutation == "wrong-campaign":
        receipts[0].experiment["configuration"]["campaign_sha256"] = "0" * 64
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match=message):
        classifier_handoff._validate_pilot_collection(receipts, splits)


def test_export_rejects_symlinks_in_sealed_source_evidence(tmp_path: Path) -> None:
    source, experiment = _make_result(tmp_path)
    capture = source / experiment["samples"][0]["path"] / "capture.pcapng"
    outside = tmp_path / "same-capture.pcapng"
    outside.write_bytes(capture.read_bytes())
    capture.unlink()
    capture.symlink_to(outside)
    destination = tmp_path / "handoff"

    with pytest.raises(ValueError, match="symlink|escapes"):
        export_classifier_handoff([source], destination)

    assert not destination.exists()


def test_export_rechecks_copied_bytes_against_sealed_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    copy_regular = classifier_handoff._copy_regular_file

    def corrupt_copy(source_path: Path, destination_path: Path) -> None:
        copy_regular(source_path, destination_path)
        if destination_path.suffix == ".pcapng":
            with destination_path.open("ab") as output:
                output.write(b"changed-after-verification")

    monkeypatch.setattr(classifier_handoff, "_copy_regular_file", corrupt_copy)
    with pytest.raises(ValueError, match="changed after verification"):
        export_classifier_handoff([source], destination)

    assert not destination.exists()


def test_export_is_create_only_and_does_not_touch_existing_destination(tmp_path: Path) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    destination.mkdir()
    sentinel = destination / "belongs-to-user.txt"
    sentinel.write_text("preserve me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        export_classifier_handoff([source], destination)

    assert sentinel.read_text(encoding="utf-8") == "preserve me"
    assert list(destination.iterdir()) == [sentinel]


def test_failed_export_leaves_no_destination_or_staging_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    before = {path.name for path in tmp_path.iterdir()}

    def fail_extraction(*_args, **_kwargs):
        raise RuntimeError("synthetic extraction failure")

    monkeypatch.setattr(classifier_handoff, "extract_trace", fail_extraction)
    with pytest.raises(RuntimeError, match="synthetic extraction failure"):
        export_classifier_handoff([source], destination)

    assert not destination.exists()
    assert {path.name for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize(
    "block_splits",
    [[], ["train", "test"], ["holdout"], "train"],
)
def test_export_rejects_invalid_block_split_contract(
    tmp_path: Path,
    block_splits,
) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"

    with pytest.raises(ValueError, match="block split"):
        export_classifier_handoff([source], destination, block_splits=block_splits)

    assert not destination.exists()


def test_multiple_nonpilot_results_cannot_be_mislabeled_as_training_blocks(
    tmp_path: Path,
) -> None:
    sources = [_make_result(tmp_path, block_number=index)[0] for index in range(7)]
    splits = ["train"] * 5 + ["validation", "test"]
    destination = tmp_path / "handoff"

    with pytest.raises(ValueError, match="one interface result only"):
        export_classifier_handoff(sources, destination, block_splits=splits)

    assert not destination.exists()


def test_validator_rejects_modified_artifact(tmp_path: Path) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    export_classifier_handoff([source], destination)
    [row] = _jsonl(destination / "samples.jsonl")
    trace = destination / row["trace_path"]
    trace.write_bytes(trace.read_bytes() + b"0,outgoing,64,64\n")

    with pytest.raises(ValueError, match="checksum|modified|hash mismatch"):
        validate_classifier_handoff(destination)


def test_validator_rederives_raw_classic_pcap_even_with_fresh_hashes(tmp_path: Path) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    export_classifier_handoff([source], destination)
    [row] = _jsonl(destination / "samples.jsonl")
    raw_pcap = destination / row["raw_pcap_path"]
    with raw_pcap.open("ab") as output:
        output.write(b"not-the-declared-conversion")
    row["raw_pcap_sha256"] = sha256_file(raw_pcap)
    atomic_text(
        destination / "samples.jsonl",
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n",
    )
    _rewrite_handoff_checksums(destination)

    with pytest.raises(ValueError, match="exact declared conversion"):
        validate_classifier_handoff(destination)


def test_validator_rejects_unsafe_manifest_paths_even_with_fresh_checksums(
    tmp_path: Path,
) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    export_classifier_handoff([source], destination)
    [row] = _jsonl(destination / "samples.jsonl")
    row["raw_pcapng_path"] = "../escape.pcapng"
    atomic_text(
        destination / "samples.jsonl",
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n",
    )
    _rewrite_handoff_checksums(destination)

    with pytest.raises(ValueError, match="unsafe|relative|path"):
        validate_classifier_handoff(destination)


def test_validator_rejects_symlink_even_when_target_has_expected_bytes(tmp_path: Path) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    export_classifier_handoff([source], destination)
    [row] = _jsonl(destination / "samples.jsonl")
    raw = destination / row["raw_pcapng_path"]
    outside = tmp_path / "outside-identical.pcapng"
    outside.write_bytes(raw.read_bytes())
    raw.unlink()
    raw.symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        validate_classifier_handoff(destination)


def test_validator_rejects_unlisted_extra_files(tmp_path: Path) -> None:
    source, _ = _make_result(tmp_path)
    destination = tmp_path / "handoff"
    export_classifier_handoff([source], destination)
    (destination / "unbound.txt").write_text("not checksummed", encoding="utf-8")

    with pytest.raises(ValueError, match="extra|cover|unlisted|inventory"):
        validate_classifier_handoff(destination)
