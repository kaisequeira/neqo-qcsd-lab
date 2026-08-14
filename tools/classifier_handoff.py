from __future__ import annotations

import argparse
import csv
import ctypes
import errno
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from qcsd_lab.capture import ObserverPacket, extract_trace
from qcsd_lab.experiment import resolved_sample_directory
from qcsd_lab.util import load_json, sha256_file, source_metadata
from qcsd_lab.verification import verify_result


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "qcsd-classifier-pilot-handoff"
PURPOSE = "classifier-pipeline-pilot"
SPLITS = {"train", "validation", "test", "interface"}
PILOT_CLASSES = (
    "getbootstrap-home-r3",
    "bootstrap-introduction-r3",
    "apache-traffic-server-docs-r3",
    "nginx-quic-r3",
    "cloudflare-quiche-r3",
    "nghttp2-ngtcp2-r3",
)
STABLE3_PILOT_CLASSES = (
    "getbootstrap-home-r3",
    "bootstrap-introduction-r3",
    "cloudflare-quiche-r3",
)
PILOT_DEFENSES = (
    "undefended",
    "static-control",
    "front",
    "tamaraw",
    "traffic-morphing",
    "wtf-pad",
    "walkie-talkie",
)
PILOT_RESULT_NAMES = tuple(f"research-classifier-pilot-{block:02d}-1200" for block in range(1, 8))
STABLE3_PILOT_RESULT_NAMES = tuple(
    f"research-classifier-stable3-pilot-{block:02d}-1200" for block in range(1, 8)
)
PILOT_SPLITS = ("train", "train", "train", "train", "train", "validation", "test")
PILOT_RUNTIME = {
    "undefended": ("none", True),
    "static-control": ("static", False),
    "front": ("front", False),
    "tamaraw": ("tamaraw", False),
    "traffic-morphing": ("traffic_morphing", False),
    "wtf-pad": ("wtf_pad", False),
    "walkie-talkie": ("walkie_talkie", False),
}


@dataclass(frozen=True)
class PilotContract:
    """One exact, checked-in classifier-pilot cohort and block lineage."""

    result_names: tuple[str, ...]
    campaign_files: tuple[str, ...]
    classes: tuple[str, ...]


PILOT_CONTRACTS = (
    PilotContract(
        result_names=PILOT_RESULT_NAMES,
        campaign_files=tuple(f"classifier-pilot-{block:02d}.yml" for block in range(1, 8)),
        classes=PILOT_CLASSES,
    ),
    PilotContract(
        result_names=STABLE3_PILOT_RESULT_NAMES,
        campaign_files=tuple(f"classifier-stable3-pilot-{block:02d}.yml" for block in range(1, 8)),
        classes=STABLE3_PILOT_CLASSES,
    ),
)

CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_PORT = 49_152
SERVER_PORT = 443
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
MAX_CLOCK_ANCHOR_ELAPSED_DELTA_NS = 10_000_000

_PCAP_MAGIC_NS = 0xA1B23C4D
_PCAP_GLOBAL = struct.Struct("<IHHIIII")
_PCAP_RECORD = struct.Struct("<IIII")
_ETHERNET_HEADER_BYTES = 14
_IPV4_HEADER_BYTES = 20
_UDP_HEADER_BYTES = 8
_MINIMUM_SHAPE_FRAME_BYTES = _ETHERNET_HEADER_BYTES + _IPV4_HEADER_BYTES + _UDP_HEADER_BYTES
_DATASET_KEYS = {
    "schema_version",
    "artifact_type",
    "purpose",
    "pilot_only",
    "exporter_source",
    "exporter_implementation_sha256",
    "observer",
    "privacy",
    "blocks",
    "classes",
    "defenses",
    "request_policies",
    "sample_count",
    "counts_by_class",
    "counts_by_defense",
    "counts_by_split",
}
_BLOCK_KEYS = {
    "block_index",
    "block_id",
    "split",
    "result_name",
    "run_id",
    "source_result",
    "experiment_sha256",
    "evidence_index_sha256",
    "authoritative_files",
    "input_digest",
    "campaign_sha256",
    "started_at",
    "completed_at",
    "source",
}
_SAMPLE_KEYS = {
    "schema_version",
    "sample_id",
    "block_index",
    "block_id",
    "split",
    "paired_visit_id",
    "class_label",
    "workload_id",
    "defense",
    "defense_role",
    "runtime_kind",
    "baseline",
    "request_policy",
    "visit",
    "seed",
    "attempts",
    "source_sample_path",
    "raw_pcapng_path",
    "raw_pcapng_sha256",
    "raw_pcap_path",
    "raw_pcap_sha256",
    "raw_run_path",
    "raw_run_sha256",
    "shape_pcap_path",
    "shape_pcap_sha256",
    "trace_path",
    "trace_sha256",
    "packet_count",
}
_TOP_LEVEL_ENTRIES = {
    "README.md",
    "SHA256SUMS",
    "dataset.json",
    "samples.jsonl",
    "raw",
    "stripped",
    "traces",
}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="qcsd-classifier-handoff",
        description="Export or verify an offline QCSD classifier-pilot handoff",
    )
    commands = root.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export", help="create one immutable handoff")
    export.add_argument("destination", type=Path)
    export.add_argument("results", nargs="+", type=Path)
    export.add_argument(
        "--splits",
        help=(
            "comma-separated block splits aligned with results; "
            "allowed: train,validation,test,interface"
        ),
    )
    verify = commands.add_parser("verify", help="verify a previously exported handoff")
    verify.add_argument("handoff", type=Path)
    return root


def main(argv: Sequence[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        if args.command == "export":
            splits = None if args.splits is None else tuple(args.splits.split(","))
            output = export_classifier_handoff(
                args.results,
                args.destination,
                block_splits=splits,
            )
            receipt = load_json(output / "dataset.json")
            print(
                json.dumps(
                    {
                        "root": str(output),
                        "samples": receipt["sample_count"],
                        "sha256sums_sha256": sha256_file(output / "SHA256SUMS"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return
        output = validate_classifier_handoff(args.handoff)
        receipt = load_json(output / "dataset.json")
        print(
            json.dumps(
                {
                    "valid": True,
                    "root": str(output),
                    "samples": receipt["sample_count"],
                    "sha256sums_sha256": sha256_file(output / "SHA256SUMS"),
                },
                indent=2,
                sort_keys=True,
            )
        )
    except (FileExistsError, OSError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from None


def export_classifier_handoff(
    result_roots: Sequence[Path],
    destination: Path,
    *,
    block_splits: Sequence[str | None] | None = None,
) -> Path:
    """Create one immutable classifier-pilot handoff from sealed results.

    Raw PCAPNG and run receipts are copied byte-for-byte.  A valid classic-PCAP
    conversion is included for readers that do not accept PCAPNG.  The default
    classifier-facing products are derived only from the verified direct
    observer trace: a CSV time/direction/length projection and a synthetic
    Ethernet/IPv4/UDP PCAP whose identifiers are fixed and whose UDP payload is
    entirely zero.
    """

    roots = tuple(_regular_source_root(Path(root)) for root in result_roots)
    if not roots:
        raise ValueError("classifier handoff requires at least one result")
    if len(roots) != len(set(roots)):
        raise ValueError("classifier handoff result roots must be unique")
    splits = _normalize_splits(block_splits, len(roots))
    destination = Path(os.path.abspath(destination))
    parent = _regular_destination_parent(destination.parent)
    if destination.parent.resolve() != parent:
        raise ValueError("classifier handoff destination parent changed during resolution")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"classifier handoff destination already exists: {destination}")

    verified = [verify_result(root) for root in roots]
    _validate_source_results(verified)
    _validate_pilot_collection(verified, splits)

    candidate = Path(tempfile.mkdtemp(prefix=f".{destination.name}.qcsd-handoff-", dir=parent))
    try:
        for directory in ("raw", "stripped", "traces"):
            (candidate / directory).mkdir()

        rows: list[dict[str, Any]] = []
        blocks: list[dict[str, Any]] = []
        seen_samples: set[str] = set()
        expected_classes: set[str] | None = None
        expected_defenses: set[str] | None = None
        expected_policies: set[str] | None = None

        for block_index, (receipt, split) in enumerate(zip(verified, splits, strict=True)):
            experiment = receipt.experiment
            classes = {str(sample["workload_id"]) for sample in experiment["samples"]}
            defenses = {str(sample["defense"]) for sample in experiment["samples"]}
            policies = {str(sample["request_policy"]) for sample in experiment["samples"]}
            if expected_classes is None:
                expected_classes = classes
                expected_defenses = defenses
                expected_policies = policies
            elif (
                classes != expected_classes
                or defenses != expected_defenses
                or policies != expected_policies
            ):
                raise ValueError("classifier handoff blocks do not use one exact cohort")

            block_id = f"block-{block_index + 1:03d}"
            blocks.append(_block_receipt(receipt, block_index, block_id, split))
            for sample in experiment["samples"]:
                sample_id = str(sample["sample_id"])
                if sample_id in seen_samples:
                    raise ValueError(f"duplicate classifier handoff sample ID: {sample_id}")
                seen_samples.add(sample_id)
                sample_root = resolved_sample_directory(
                    receipt.root, sample, require_directory=True
                )
                raw_pcap = sample_root / "capture.pcapng"
                raw_run = sample_root / "neqo/run.json"
                raw_pcapng_relative = f"raw/{sample_id}.pcapng"
                raw_pcap_relative = f"raw/{sample_id}.pcap"
                raw_run_relative = f"raw/{sample_id}.run.json"
                shape_relative = f"stripped/{sample_id}.pcap"
                trace_relative = f"traces/{sample_id}.csv"
                copied_pcapng = candidate / raw_pcapng_relative
                copied_run = candidate / raw_run_relative
                _copy_sealed_file(receipt, raw_pcap, copied_pcapng)
                _copy_sealed_file(receipt, raw_run, copied_run)
                run_data = load_json(copied_run)
                endpoints = run_data.get("endpoints")
                if not isinstance(endpoints, list):
                    raise ValueError(f"sample run receipt has no endpoint list: {sample_id}")
                trace = extract_trace(copied_pcapng, endpoints)
                if not trace:
                    raise ValueError(f"sample observer trace is empty: {sample_id}")
                _write_classic_raw_pcap(copied_pcapng, candidate / raw_pcap_relative)
                write_shape_only_pcap(trace, candidate / shape_relative)
                _write_trace_csv(trace, candidate / trace_relative)

                rows.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "sample_id": sample_id,
                        "block_index": block_index,
                        "block_id": block_id,
                        "split": split,
                        "paired_visit_id": (
                            f"{block_id}/{sample['workload_id']}/"
                            f"{sample['request_policy']}/visit-{sample['visit']:03d}"
                        ),
                        "class_label": sample["workload_id"],
                        "workload_id": sample["workload_id"],
                        "defense": sample["defense"],
                        "defense_role": _defense_role(sample),
                        "runtime_kind": sample["runtime_kind"],
                        "baseline": sample["baseline"],
                        "request_policy": sample["request_policy"],
                        "visit": sample["visit"],
                        "seed": sample["seed"],
                        "attempts": sample["attempts"],
                        "source_sample_path": sample["path"],
                        "raw_pcapng_path": raw_pcapng_relative,
                        "raw_pcapng_sha256": sha256_file(candidate / raw_pcapng_relative),
                        "raw_pcap_path": raw_pcap_relative,
                        "raw_pcap_sha256": sha256_file(candidate / raw_pcap_relative),
                        "raw_run_path": raw_run_relative,
                        "raw_run_sha256": sha256_file(candidate / raw_run_relative),
                        "shape_pcap_path": shape_relative,
                        "shape_pcap_sha256": sha256_file(candidate / shape_relative),
                        "trace_path": trace_relative,
                        "trace_sha256": sha256_file(candidate / trace_relative),
                        "packet_count": len(trace),
                    }
                )

        dataset = _dataset_receipt(rows, blocks)
        _write_json(candidate / "dataset.json", dataset)
        _write_json_lines(candidate / "samples.jsonl", rows)
        _write_text(candidate / "README.md", _handoff_readme())
        _write_checksums(candidate)
        validate_classifier_handoff(candidate)
        _fsync_tree(candidate)
        _rename_noreplace(candidate, destination)
        _fsync_directory(parent)
        return validate_classifier_handoff(destination)
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)


def write_shape_only_pcap(trace: Sequence[ObserverPacket], path: Path) -> None:
    """Write a deterministic identifier-free packet-shape PCAP.

    This is deliberately not a valid QUIC transcript.  It contains synthetic
    Ethernet/IPv4/UDP frames with fixed documentation addresses and ports.
    Timestamps, direction, packet count, and Ethernet frame length are retained;
    every UDP payload byte is zero, removing QUIC headers, CIDs, TLS, and SNI.
    """

    if not trace:
        raise ValueError("shape-only PCAP requires a non-empty trace")
    previous_time = -1
    with path.open("xb") as output:
        output.write(_PCAP_GLOBAL.pack(_PCAP_MAGIC_NS, 2, 4, 0, 0, 65_535, 1))
        for packet in trace:
            if packet.relative_time_ns < previous_time:
                raise ValueError("shape-only PCAP trace timestamps are not monotonic")
            previous_time = packet.relative_time_ns
            frame = _shape_frame(packet.direction, packet.frame_len)
            seconds, nanoseconds = divmod(packet.relative_time_ns, 1_000_000_000)
            if seconds > 0xFFFFFFFF:
                raise ValueError("shape-only PCAP timestamp exceeds classic PCAP range")
            output.write(_PCAP_RECORD.pack(seconds, nanoseconds, len(frame), len(frame)))
            output.write(frame)
        output.flush()
        os.fsync(output.fileno())


def validate_classifier_handoff(path: Path) -> Path:
    """Validate a self-contained classifier handoff and return its root."""

    root = Path(os.path.abspath(path))
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"classifier handoff is not a regular directory: {root}")
    entries = {entry.name for entry in root.iterdir()}
    if entries != _TOP_LEVEL_ENTRIES:
        raise ValueError("classifier handoff top-level inventory is invalid")
    for directory in ("raw", "stripped", "traces"):
        child = root / directory
        if child.is_symlink() or not child.is_dir():
            raise ValueError(f"classifier handoff directory is unsafe: {directory}")
    files = _regular_tree_files(root)
    checksums = _read_checksums(root / "SHA256SUMS")
    governed = {relative: file for relative, file in files.items() if relative != "SHA256SUMS"}
    if set(checksums) != set(governed):
        raise ValueError("classifier handoff checksum inventory is not closed")
    for relative, expected in checksums.items():
        if sha256_file(governed[relative]) != expected:
            raise ValueError(f"classifier handoff file hash mismatch: {relative}")

    dataset = load_json(root / "dataset.json")
    if not isinstance(dataset, Mapping) or set(dataset) != _DATASET_KEYS:
        raise ValueError("classifier handoff dataset schema is invalid")
    if (root / "dataset.json").read_text(encoding="utf-8") != (
        json.dumps(dataset, indent=2, sort_keys=True) + "\n"
    ):
        raise ValueError("classifier handoff dataset JSON is not canonical")
    if (
        dataset["schema_version"] != SCHEMA_VERSION
        or dataset["artifact_type"] != ARTIFACT_TYPE
        or dataset["purpose"] != PURPOSE
        or dataset["pilot_only"] is not True
    ):
        raise ValueError("classifier handoff dataset identity is invalid")
    rows = _read_json_lines(root / "samples.jsonl")
    _validate_dataset_rows(root, dataset, rows)
    return root


def _validate_source_results(receipts: Sequence[Any]) -> None:
    for receipt in receipts:
        experiment = receipt.experiment
        if experiment["status"] != "complete" or experiment["summary"] != {
            "planned": len(experiment["samples"]),
            "accepted": len(experiment["samples"]),
            "failed": 0,
            "eligible": len(experiment["samples"]),
            "passed": True,
        }:
            raise ValueError("classifier handoff requires a complete all-eligible result")
        if experiment["purpose"] not in {"evaluation", "smoke"}:
            raise ValueError("classifier handoff requires an evaluation or smoke result")
        for sample in experiment["samples"]:
            if sample["state"] != "accepted" or sample["eligible"] is not True:
                raise ValueError("classifier handoff rejects ineligible samples")
            _validate_primary_capture_clock(sample)


def _validate_primary_capture_clock(sample: Mapping[str, Any]) -> None:
    """Reject accepted evidence whose direct-capture timing needed clock-step repair."""

    sample_id = sample.get("sample_id")
    prefix = f"classifier handoff rejects timing-contaminated sample {sample_id}:"
    diagnostics = sample.get("diagnostics")
    capture = diagnostics.get("capture") if isinstance(diagnostics, Mapping) else None
    if not isinstance(capture, Mapping) or capture.get("primary") is not True:
        raise ValueError(f"{prefix} primary capture diagnostics are missing")
    reconciliation = capture.get("direct_runner_reconciliation")
    if not isinstance(reconciliation, Mapping):
        raise ValueError(f"{prefix} direct/runner reconciliation is missing")
    if reconciliation.get("direct_clock_model") != "constant-offset":
        raise ValueError(f"{prefix} direct clock model is not constant-offset")

    segments = reconciliation.get("direct_clock_segments")
    if (
        reconciliation.get("direct_clock_segment_count") != 1
        or not isinstance(segments, list)
        or len(segments) != 1
    ):
        raise ValueError(f"{prefix} direct clock must contain exactly one segment")
    steps = reconciliation.get("direct_clock_steps")
    if reconciliation.get("direct_clock_step_count") != 0 or not isinstance(steps, list) or steps:
        raise ValueError(f"{prefix} direct clock must contain zero steps")
    if (
        reconciliation.get("direct_runner_reconciled") is not True
        or reconciliation.get("evidence_eligible") is not True
    ):
        raise ValueError(f"{prefix} direct/runner reconciliation is not evidence-eligible")

    maximum_error = reconciliation.get("direct_timestamp_error_max_ns")
    tolerance = reconciliation.get("direct_timestamp_tolerance_ns")
    if (
        type(maximum_error) is not int
        or maximum_error < 0
        or type(tolerance) is not int
        or tolerance < 0
        or maximum_error > tolerance
    ):
        raise ValueError(f"{prefix} direct timestamp error exceeds its tolerance")

    anchors = capture.get("capture_clock_anchors")
    anchor_fields = (
        "start_monotonic_ns",
        "end_monotonic_ns",
        "start_realtime_unix_ns",
        "end_realtime_unix_ns",
    )
    if not isinstance(anchors, Mapping) or any(
        type(anchors.get(field)) is not int for field in anchor_fields
    ):
        raise ValueError(f"{prefix} wrapper clock anchors are missing")
    monotonic_elapsed = anchors["end_monotonic_ns"] - anchors["start_monotonic_ns"]
    realtime_elapsed = anchors["end_realtime_unix_ns"] - anchors["start_realtime_unix_ns"]
    if (
        monotonic_elapsed < 0
        or realtime_elapsed < 0
        or abs(realtime_elapsed - monotonic_elapsed) > MAX_CLOCK_ANCHOR_ELAPSED_DELTA_NS
    ):
        raise ValueError(f"{prefix} wrapper realtime/monotonic elapsed difference exceeds 10 ms")


def _validate_pilot_collection(receipts: Sequence[Any], splits: Sequence[str | None]) -> None:
    names = tuple(receipt.experiment["name"] for receipt in receipts)
    contracts = tuple(
        contract
        for contract in PILOT_CONTRACTS
        if any(name in contract.result_names for name in names)
    )
    if not contracts:
        if len(receipts) != 1 or splits[0] not in {None, "interface"}:
            raise ValueError("non-pilot handoff supports one interface result only")
        return
    if len(contracts) != 1:
        raise ValueError("classifier pilot export cannot mix pilot cohort contracts")
    contract = contracts[0]

    if len(receipts) == 1:
        if names != contract.result_names[:1] or splits[0] not in {None, "interface"}:
            raise ValueError("single-block classifier handoff must be unassigned pilot block 01")
    elif len(receipts) == len(contract.result_names):
        if names != contract.result_names or tuple(splits) != PILOT_SPLITS:
            raise ValueError(
                "complete classifier pilot requires ordered blocks 01--07 and 5/1/1 splits"
            )
    else:
        raise ValueError("classifier pilot export requires block 01 alone or all seven blocks")

    expected = Counter(
        (
            workload_id,
            defense,
            "as-defined",
            0,
            PILOT_RUNTIME[defense][0],
            PILOT_RUNTIME[defense][1],
        )
        for workload_id in contract.classes
        for defense in PILOT_DEFENSES
    )
    block_samples = len(contract.classes) * len(PILOT_DEFENSES)
    lab_root = _lab_root()
    for block_index, receipt in enumerate(receipts, 1):
        experiment = receipt.experiment
        actual = Counter(
            (
                sample["workload_id"],
                sample["defense"],
                sample["request_policy"],
                sample["visit"],
                sample["runtime_kind"],
                sample["baseline"],
            )
            for sample in experiment["samples"]
        )
        if experiment["purpose"] != "evaluation" or actual != expected:
            raise ValueError(
                f"classifier pilot block is not the exact {block_samples}-sample cohort"
            )
        configuration = experiment.get("configuration")
        campaign = lab_root / "config/campaigns" / contract.campaign_files[block_index - 1]
        if not isinstance(configuration, Mapping) or configuration.get(
            "campaign_sha256"
        ) != sha256_file(campaign):
            raise ValueError("classifier pilot block does not bind its checked-in campaign")


def _normalize_splits(splits: Sequence[str | None] | None, blocks: int) -> tuple[str | None, ...]:
    if splits is None:
        return (None,) * blocks
    result = tuple(splits)
    if len(result) != blocks:
        raise ValueError("block split count must match classifier handoff result count")
    if any(split not in SPLITS for split in result):
        raise ValueError("classifier handoff block split is invalid")
    return result


def _block_receipt(
    verified: Any,
    block_index: int,
    block_id: str,
    split: str | None,
) -> dict[str, Any]:
    experiment = verified.experiment
    return {
        "block_index": block_index,
        "block_id": block_id,
        "split": split,
        "result_name": experiment["name"],
        "run_id": verified.root.name,
        "source_result": f"{experiment['name']}/{verified.root.name}",
        "experiment_sha256": sha256_file(verified.root / "experiment.json"),
        "evidence_index_sha256": sha256_file(verified.root / "evidence.sha256"),
        "authoritative_files": len(verified.checksums),
        "input_digest": experiment["input_digest"],
        "campaign_sha256": experiment["configuration"]["campaign_sha256"],
        "started_at": experiment["started_at"],
        "completed_at": experiment["completed_at"],
        "source": experiment["source"],
    }


def _dataset_receipt(
    rows: Sequence[Mapping[str, Any]], blocks: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    classes = sorted({str(row["class_label"]) for row in rows})
    defenses = sorted({str(row["defense"]) for row in rows})
    policies = sorted({str(row["request_policy"]) for row in rows})
    roles = {
        defense: sorted({str(row["defense_role"]) for row in rows if row["defense"] == defense})
        for defense in defenses
    }
    if any(len(value) != 1 for value in roles.values()):
        raise ValueError("classifier handoff defense roles are inconsistent")
    split_counts = Counter("unassigned" if row["split"] is None else row["split"] for row in rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "purpose": PURPOSE,
        "pilot_only": True,
        "exporter_source": _exporter_source_receipt(),
        "exporter_implementation_sha256": sha256_file(Path(__file__)),
        "observer": {
            "raw": "direct Ethernet capture on collection-container eth0",
            "raw_formats": {
                "pcapng": "byte-exact sealed-evidence copy",
                "pcap": "valid nanosecond classic-PCAP conversion via editcap",
            },
            "length_basis": "Ethernet frame.len",
            "direction_rule": "client egress is positive; server ingress is negative",
            "trace_columns": [
                "relative_time_ns",
                "direction",
                "length_bytes",
                "signed_length_bytes",
            ],
            "shape_pcap": {
                "format": "classic-pcap-nanosecond",
                "link_type": "Ethernet",
                "client": f"{CLIENT_IP}:{CLIENT_PORT}",
                "server": f"{SERVER_IP}:{SERVER_PORT}",
                "udp_payload": "all-zero",
                "preserves": ["relative timestamp", "direction", "Ethernet frame length"],
                "valid_quic": False,
            },
        },
        "privacy": {
            "raw_restricted": True,
            "raw_contains_endpoint_and_encrypted_protocol_metadata": True,
            "raw_run_contains_urls_headers_addresses_and_absolute_times": True,
            "shape_products_remove": [
                "MAC addresses",
                "IP addresses",
                "ports",
                "absolute timestamps",
                "QUIC headers",
                "connection IDs",
                "TLS ClientHello and SNI",
                "application and controller events",
            ],
            "model_input_default": "traces/*.csv or stripped/*.pcap",
        },
        "blocks": list(blocks),
        "classes": classes,
        "defenses": [{"id": defense, "role": roles[defense][0]} for defense in defenses],
        "request_policies": policies,
        "sample_count": len(rows),
        "counts_by_class": dict(sorted(Counter(row["class_label"] for row in rows).items())),
        "counts_by_defense": dict(sorted(Counter(row["defense"] for row in rows).items())),
        "counts_by_split": dict(sorted(split_counts.items())),
    }


def _defense_role(sample: Mapping[str, Any]) -> str:
    if sample["baseline"] is True:
        return "baseline"
    if sample["runtime_kind"] == "static" or sample["defense"] == "static-control":
        return "mechanical-control"
    return "defense"


def _write_trace_csv(trace: Sequence[ObserverPacket], path: Path) -> None:
    with path.open("x", newline="", encoding="utf-8") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["relative_time_ns", "direction", "length_bytes", "signed_length_bytes"])
        for packet in trace:
            writer.writerow(
                [
                    packet.relative_time_ns,
                    packet.direction,
                    packet.frame_len,
                    packet.signed_frame_len,
                ]
            )
        output.flush()
        os.fsync(output.fileno())


def _shape_frame(direction: str, frame_len: int) -> bytes:
    if frame_len < _MINIMUM_SHAPE_FRAME_BYTES or frame_len > 65_535 + 14:
        raise ValueError(f"observer frame length cannot be represented safely: {frame_len}")
    if direction == "outgoing":
        source_mac, destination_mac = CLIENT_MAC, SERVER_MAC
        source_ip, destination_ip = CLIENT_IP, SERVER_IP
        source_port, destination_port = CLIENT_PORT, SERVER_PORT
    elif direction == "incoming":
        source_mac, destination_mac = SERVER_MAC, CLIENT_MAC
        source_ip, destination_ip = SERVER_IP, CLIENT_IP
        source_port, destination_port = SERVER_PORT, CLIENT_PORT
    else:
        raise ValueError(f"invalid observer packet direction: {direction!r}")
    ip_total = frame_len - _ETHERNET_HEADER_BYTES
    udp_total = ip_total - _IPV4_HEADER_BYTES
    payload_bytes = udp_total - _UDP_HEADER_BYTES
    ethernet = destination_mac + source_mac + struct.pack("!H", 0x0800)
    source_packed = socket.inet_aton(source_ip)
    destination_packed = socket.inet_aton(destination_ip)
    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total,
        0,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        source_packed,
        destination_packed,
    )
    checksum = _internet_checksum(ip_without_checksum)
    ip_header = ip_without_checksum[:10] + struct.pack("!H", checksum) + ip_without_checksum[12:]
    udp_header = struct.pack("!HHHH", source_port, destination_port, udp_total, 0)
    return ethernet + ip_header + udp_header + bytes(payload_bytes)


def _internet_checksum(value: bytes) -> int:
    if len(value) % 2:
        value += b"\0"
    total = sum(struct.unpack(f"!{len(value) // 2}H", value))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _copy_regular_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"classifier handoff source is not a regular file: {source}")
    with source.open("rb") as input_file, destination.open("xb") as output:
        for block in iter(lambda: input_file.read(1024 * 1024), b""):
            output.write(block)
        output.flush()
        os.fsync(output.fileno())


def _copy_sealed_file(verified: Any, source: Path, destination: Path) -> None:
    try:
        relative = source.relative_to(verified.root).as_posix()
    except ValueError as error:
        raise ValueError(f"classifier handoff source escapes sealed result: {source}") from error
    expected = verified.checksums.get(relative)
    if not _valid_sha256(expected):
        raise ValueError(f"classifier handoff source is absent from evidence seal: {relative}")
    _copy_regular_file(source, destination)
    if sha256_file(destination) != expected:
        raise ValueError(f"classifier handoff source changed after verification: {relative}")


def _write_classic_raw_pcap(source: Path, destination: Path) -> None:
    """Convert one exact capture to a valid nanosecond classic PCAP."""

    if source.is_symlink() or not source.is_file():
        raise ValueError(f"classifier handoff source is not a regular file: {source}")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"classifier handoff raw PCAP already exists: {destination}")
    editcap = shutil.which("editcap")
    if editcap is None:
        raise RuntimeError("classifier handoff requires editcap for raw PCAP conversion")
    completed = subprocess.run(
        [editcap, "-F", "nsecpcap", os.fspath(source), os.fspath(destination)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        destination.unlink(missing_ok=True)
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown editcap error"
        raise RuntimeError(f"raw PCAP conversion failed: {detail}")
    if destination.is_symlink() or not destination.is_file() or destination.stat().st_size == 0:
        destination.unlink(missing_ok=True)
        raise RuntimeError("raw PCAP conversion did not create a regular non-empty file")
    with destination.open("rb") as output:
        os.fsync(output.fileno())


def _validate_classic_raw_pcap(source: Path, expected: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix="qcsd-raw-pcap-", suffix=".pcap")
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    try:
        _write_classic_raw_pcap(source, temporary)
        if sha256_file(temporary) != sha256_file(expected):
            raise ValueError("classifier handoff raw PCAP is not the exact declared conversion")
    finally:
        temporary.unlink(missing_ok=True)


def _exporter_source_receipt() -> dict[str, Any]:
    dirty_value = os.environ.get("QCSD_HANDOFF_LAB_DIRTY")
    if dirty_value not in {None, "true", "false"}:
        raise ValueError("QCSD_HANDOFF_LAB_DIRTY must be true or false when set")
    commit = os.environ.get("QCSD_HANDOFF_LAB_COMMIT")
    if commit is not None and (
        len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise ValueError("QCSD_HANDOFF_LAB_COMMIT is invalid")
    return {
        "execution_image": source_metadata(),
        "companion": {
            "logical_path": os.environ.get("QCSD_HANDOFF_TOOL_PATH", "tools/classifier_handoff.py"),
            "sha256": sha256_file(Path(__file__)),
            "lab_commit": commit,
            "lab_dirty": None if dirty_value is None else dirty_value == "true",
        },
    }


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _write_json_lines(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    value = "".join(
        json.dumps(dict(row), sort_keys=True, separators=(",", ":")) + "\n" for row in rows
    )
    _write_text(path, value)


def _write_text(path: Path, value: str) -> None:
    with path.open("x", encoding="utf-8") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def _write_checksums(root: Path) -> None:
    files = _regular_tree_files(root)
    if "SHA256SUMS" in files:
        raise ValueError("classifier handoff checksum file already exists")
    value = "".join(f"{sha256_file(files[path])}  {path}\n" for path in sorted(files))
    _write_text(root / "SHA256SUMS", value)


def _read_checksums(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("classifier handoff has no regular SHA256SUMS")
    result: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            digest, relative = line.split("  ", 1)
        except ValueError as error:
            raise ValueError(f"invalid classifier checksum line {line_number}") from error
        relative_path = Path(relative)
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path.as_posix() != relative
            or relative == "SHA256SUMS"
            or relative in result
        ):
            raise ValueError(f"invalid classifier checksum line {line_number}")
        result[relative] = digest
    if not result:
        raise ValueError("classifier handoff checksum index is empty")
    return result


def _read_json_lines(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid samples.jsonl line {line_number}") from error
        if not isinstance(value, dict) or set(value) != _SAMPLE_KEYS:
            raise ValueError(f"invalid samples.jsonl schema on line {line_number}")
        if line != json.dumps(value, sort_keys=True, separators=(",", ":")):
            raise ValueError(f"non-canonical samples.jsonl line {line_number}")
        rows.append(value)
    if not rows:
        raise ValueError("classifier handoff contains no samples")
    return rows


def _validate_dataset_rows(
    root: Path, dataset: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    if dataset["sample_count"] != len(rows):
        raise ValueError("classifier handoff sample count mismatch")
    sample_ids = [row["sample_id"] for row in rows]
    if any(
        not isinstance(item, str)
        or len(item) != 64
        or any(character not in "0123456789abcdef" for character in item)
        for item in sample_ids
    ):
        raise ValueError("classifier handoff sample ID is invalid")
    if len(sample_ids) != len(set(sample_ids)):
        raise ValueError("classifier handoff sample IDs are not unique")
    block_records = dataset["blocks"]
    if not isinstance(block_records, list) or not block_records:
        raise ValueError("classifier handoff block receipts are invalid")
    block_splits = _validate_block_records(block_records)
    _validate_exporter_source(dataset)

    expected_inventory = {"README.md", "dataset.json", "samples.jsonl", "SHA256SUMS"}
    class_counts: Counter[str] = Counter()
    defense_counts: Counter[str] = Counter()
    split_counts: Counter[str] = Counter()
    for row in rows:
        _validate_sample_row(row, block_splits)
        sample_id = row["sample_id"]
        expected_paths = {
            "raw_pcapng_path": f"raw/{sample_id}.pcapng",
            "raw_pcap_path": f"raw/{sample_id}.pcap",
            "raw_run_path": f"raw/{sample_id}.run.json",
            "shape_pcap_path": f"stripped/{sample_id}.pcap",
            "trace_path": f"traces/{sample_id}.csv",
        }
        for key, expected in expected_paths.items():
            if row[key] != expected:
                raise ValueError(f"classifier handoff sample path is invalid: {key}")
            expected_inventory.add(expected)
        hash_bindings = {
            "raw_pcapng_path": "raw_pcapng_sha256",
            "raw_pcap_path": "raw_pcap_sha256",
            "raw_run_path": "raw_run_sha256",
            "shape_pcap_path": "shape_pcap_sha256",
            "trace_path": "trace_sha256",
        }
        for path_key, digest_key in hash_bindings.items():
            file = root / row[path_key]
            if file.is_symlink() or not file.is_file() or sha256_file(file) != row[digest_key]:
                raise ValueError(f"classifier handoff sample file binding failed: {path_key}")
        trace = _read_trace_csv(root / row["trace_path"])
        if len(trace) != row["packet_count"]:
            raise ValueError("classifier handoff packet count mismatch")
        run_data = load_json(root / row["raw_run_path"])
        endpoints = run_data.get("endpoints") if isinstance(run_data, Mapping) else None
        if not isinstance(endpoints, list):
            raise ValueError("classifier handoff raw run endpoint binding is invalid")
        _validate_classic_raw_pcap(root / row["raw_pcapng_path"], root / row["raw_pcap_path"])
        raw_pcapng_trace = extract_trace(root / row["raw_pcapng_path"], endpoints)
        raw_pcap_trace = extract_trace(root / row["raw_pcap_path"], endpoints)
        if _trace_identity(raw_pcapng_trace) != _trace_identity(trace):
            raise ValueError("classifier handoff normalized trace differs from raw PCAPNG")
        if _trace_identity(raw_pcap_trace) != _trace_identity(trace):
            raise ValueError("classifier handoff raw PCAP conversion differs from raw PCAPNG")
        stripped_trace = _read_shape_only_pcap(root / row["shape_pcap_path"])
        if _trace_identity(stripped_trace) != _trace_identity(trace):
            raise ValueError("classifier handoff stripped PCAP differs from normalized trace")
        class_counts[row["class_label"]] += 1
        defense_counts[row["defense"]] += 1
        split_counts["unassigned" if row["split"] is None else row["split"]] += 1

    actual_inventory = set(_regular_tree_files(root))
    if actual_inventory != expected_inventory:
        raise ValueError("classifier handoff per-sample inventory is invalid")
    if dataset["classes"] != sorted(class_counts):
        raise ValueError("classifier handoff class list mismatch")
    if dataset["request_policies"] != sorted({row["request_policy"] for row in rows}):
        raise ValueError("classifier handoff request-policy list mismatch")
    expected_defenses = [
        {
            "id": defense,
            "role": next(row["defense_role"] for row in rows if row["defense"] == defense),
        }
        for defense in sorted(defense_counts)
    ]
    if dataset["defenses"] != expected_defenses:
        raise ValueError("classifier handoff defense list mismatch")
    if dataset["counts_by_class"] != dict(sorted(class_counts.items())):
        raise ValueError("classifier handoff class counts mismatch")
    if dataset["counts_by_defense"] != dict(sorted(defense_counts.items())):
        raise ValueError("classifier handoff defense counts mismatch")
    if dataset["counts_by_split"] != dict(sorted(split_counts.items())):
        raise ValueError("classifier handoff split counts mismatch")


def _validate_block_records(records: Sequence[Any]) -> dict[int, str | None]:
    result: dict[int, str | None] = {}
    for expected_index, record in enumerate(records):
        if not isinstance(record, Mapping) or set(record) != _BLOCK_KEYS:
            raise ValueError("classifier handoff block receipt schema is invalid")
        index = record["block_index"]
        split = record["split"]
        if type(index) is not int or index != expected_index:
            raise ValueError("classifier handoff block indexes are invalid")
        if record["block_id"] != f"block-{index + 1:03d}":
            raise ValueError("classifier handoff block ID is invalid")
        if split is not None and split not in SPLITS:
            raise ValueError("classifier handoff block split is invalid")
        strings = ("result_name", "run_id", "source_result", "started_at", "completed_at")
        if any(not isinstance(record[field], str) or not record[field] for field in strings):
            raise ValueError("classifier handoff block string is invalid")
        if record["source_result"] != f"{record['result_name']}/{record['run_id']}":
            raise ValueError("classifier handoff block result binding is invalid")
        for field in (
            "experiment_sha256",
            "evidence_index_sha256",
            "input_digest",
            "campaign_sha256",
        ):
            if not _valid_sha256(record[field]):
                raise ValueError("classifier handoff block digest is invalid")
        if type(record["authoritative_files"]) is not int or record["authoritative_files"] <= 0:
            raise ValueError("classifier handoff authoritative-file count is invalid")
        if not isinstance(record["source"], Mapping):
            raise ValueError("classifier handoff block source receipt is invalid")
        result[index] = split
    return result


def _validate_exporter_source(dataset: Mapping[str, Any]) -> None:
    implementation = dataset["exporter_implementation_sha256"]
    if not _valid_sha256(implementation):
        raise ValueError("classifier handoff exporter digest is invalid")
    source = dataset["exporter_source"]
    if not isinstance(source, Mapping) or set(source) != {"execution_image", "companion"}:
        raise ValueError("classifier handoff exporter source receipt is invalid")
    if not isinstance(source["execution_image"], Mapping):
        raise ValueError("classifier handoff execution-image receipt is invalid")
    companion = source["companion"]
    if not isinstance(companion, Mapping) or set(companion) != {
        "logical_path",
        "sha256",
        "lab_commit",
        "lab_dirty",
    }:
        raise ValueError("classifier handoff companion receipt is invalid")
    if companion["logical_path"] != "tools/classifier_handoff.py":
        raise ValueError("classifier handoff companion path is invalid")
    if companion["sha256"] != implementation:
        raise ValueError("classifier handoff companion digest binding is invalid")
    commit = companion["lab_commit"]
    if commit is not None and (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise ValueError("classifier handoff companion commit is invalid")
    if companion["lab_dirty"] is not None and type(companion["lab_dirty"]) is not bool:
        raise ValueError("classifier handoff companion dirty flag is invalid")


def _validate_sample_row(row: Mapping[str, Any], block_splits: Mapping[Any, Any]) -> None:
    integer_fields = ("block_index", "visit", "seed", "attempts", "packet_count")
    if any(type(row[field]) is not int for field in integer_fields):
        raise ValueError("classifier handoff integer field is invalid")
    if row["block_index"] not in block_splits or row["split"] != block_splits[row["block_index"]]:
        raise ValueError("classifier handoff sample block binding is invalid")
    if row["split"] is not None and row["split"] not in SPLITS:
        raise ValueError("classifier handoff sample split is invalid")
    if type(row["baseline"]) is not bool:
        raise ValueError("classifier handoff baseline field is invalid")
    string_fields = (
        "sample_id",
        "block_id",
        "paired_visit_id",
        "class_label",
        "workload_id",
        "defense",
        "defense_role",
        "runtime_kind",
        "request_policy",
        "source_sample_path",
    )
    if any(not isinstance(row[field], str) or not row[field] for field in string_fields):
        raise ValueError("classifier handoff string field is invalid")
    if row["class_label"] != row["workload_id"]:
        raise ValueError("classifier handoff class/workload binding is invalid")
    for field in (
        "raw_pcapng_sha256",
        "raw_pcap_sha256",
        "raw_run_sha256",
        "shape_pcap_sha256",
        "trace_sha256",
    ):
        if not _valid_sha256(row[field]):
            raise ValueError("classifier handoff sample digest is invalid")


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _read_trace_csv(path: Path) -> list[ObserverPacket]:
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != [
            "relative_time_ns",
            "direction",
            "length_bytes",
            "signed_length_bytes",
        ]:
            raise ValueError("classifier handoff trace columns are invalid")
        rows = list(reader)
    trace: list[ObserverPacket] = []
    previous = -1
    for row in rows:
        try:
            relative = int(row["relative_time_ns"])
            length = int(row["length_bytes"])
            signed = int(row["signed_length_bytes"])
        except (TypeError, ValueError) as error:
            raise ValueError("classifier handoff trace contains a non-integer") from error
        direction = row["direction"]
        if relative < 0 or relative < previous or length <= 0:
            raise ValueError("classifier handoff trace value is out of range")
        if direction not in {"outgoing", "incoming"}:
            raise ValueError("classifier handoff trace direction is invalid")
        if signed != (length if direction == "outgoing" else -length):
            raise ValueError("classifier handoff trace signed length is invalid")
        previous = relative
        trace.append(ObserverPacket(0, relative, direction, length, signed, None))
    if not trace or trace[0].relative_time_ns != 0:
        raise ValueError("classifier handoff trace must start at relative time zero")
    return trace


def _read_shape_only_pcap(path: Path) -> list[ObserverPacket]:
    data = path.read_bytes()
    if len(data) < _PCAP_GLOBAL.size:
        raise ValueError("classifier handoff shape PCAP is truncated")
    if _PCAP_GLOBAL.unpack_from(data, 0) != (_PCAP_MAGIC_NS, 2, 4, 0, 0, 65_535, 1):
        raise ValueError("classifier handoff shape PCAP header is invalid")
    offset = _PCAP_GLOBAL.size
    trace: list[ObserverPacket] = []
    previous = -1
    while offset < len(data):
        if len(data) - offset < _PCAP_RECORD.size:
            raise ValueError("classifier handoff shape PCAP record is truncated")
        seconds, nanoseconds, included, original = _PCAP_RECORD.unpack_from(data, offset)
        offset += _PCAP_RECORD.size
        if included != original or included < _MINIMUM_SHAPE_FRAME_BYTES:
            raise ValueError("classifier handoff shape PCAP record length is invalid")
        frame = data[offset : offset + included]
        if len(frame) != included:
            raise ValueError("classifier handoff shape PCAP frame is truncated")
        offset += included
        relative = seconds * 1_000_000_000 + nanoseconds
        if nanoseconds >= 1_000_000_000 or relative < previous:
            raise ValueError("classifier handoff shape PCAP timestamp is invalid")
        previous = relative
        direction = _validate_shape_frame(frame)
        signed = included if direction == "outgoing" else -included
        trace.append(ObserverPacket(0, relative, direction, included, signed, None))
    if not trace or trace[0].relative_time_ns != 0:
        raise ValueError("classifier handoff shape PCAP must start at relative time zero")
    return trace


def _validate_shape_frame(frame: bytes) -> str:
    if len(frame) < _MINIMUM_SHAPE_FRAME_BYTES or frame[12:14] != b"\x08\x00":
        raise ValueError("classifier handoff shape Ethernet frame is invalid")
    ip_header = frame[14:34]
    if (
        len(ip_header) != _IPV4_HEADER_BYTES
        or ip_header[0] != 0x45
        or ip_header[9] != socket.IPPROTO_UDP
        or struct.unpack("!H", ip_header[2:4])[0] != len(frame) - 14
        or _internet_checksum(ip_header) != 0
    ):
        raise ValueError("classifier handoff shape IPv4 header is invalid")
    source_ip = socket.inet_ntoa(ip_header[12:16])
    destination_ip = socket.inet_ntoa(ip_header[16:20])
    source_port, destination_port, udp_length, udp_checksum = struct.unpack("!HHHH", frame[34:42])
    if udp_length != len(frame) - 34 or udp_checksum != 0 or any(frame[42:]):
        raise ValueError("classifier handoff shape UDP payload is invalid")
    outgoing = (
        frame[:6] == SERVER_MAC
        and frame[6:12] == CLIENT_MAC
        and source_ip == CLIENT_IP
        and destination_ip == SERVER_IP
        and source_port == CLIENT_PORT
        and destination_port == SERVER_PORT
    )
    incoming = (
        frame[:6] == CLIENT_MAC
        and frame[6:12] == SERVER_MAC
        and source_ip == SERVER_IP
        and destination_ip == CLIENT_IP
        and source_port == SERVER_PORT
        and destination_port == CLIENT_PORT
    )
    if outgoing == incoming:
        raise ValueError("classifier handoff shape endpoint direction is invalid")
    return "outgoing" if outgoing else "incoming"


def _trace_identity(trace: Sequence[ObserverPacket]) -> list[tuple[int, str, int, int]]:
    return [
        (
            packet.relative_time_ns,
            packet.direction,
            packet.frame_len,
            packet.signed_frame_len,
        )
        for packet in trace
    ]


def _regular_destination_parent(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"classifier handoff destination contains a symlink: {current}")
    if not absolute.is_dir():
        raise ValueError(f"classifier handoff parent must be an existing directory: {absolute}")
    return absolute.resolve(strict=True)


def _regular_source_root(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"classifier handoff result path contains a symlink: {current}")
    if not absolute.is_dir():
        raise ValueError(f"classifier handoff result must be an existing directory: {absolute}")
    return absolute.resolve(strict=True)


def _lab_root() -> Path:
    configured = os.environ.get("QCSD_HANDOFF_LAB_ROOT")
    root = Path(configured) if configured is not None else Path(__file__).resolve().parents[1]
    absolute = Path(os.path.abspath(root))
    if absolute.is_symlink() or not absolute.is_dir():
        raise ValueError("classifier handoff lab root is not a regular directory")
    return absolute.resolve(strict=True)


def _regular_tree_files(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"classifier handoff contains a symbolic link: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"classifier handoff contains a special file: {path}")
        result[path.relative_to(root).as_posix()] = path
    return dict(sorted(result.items()))


def _fsync_tree(root: Path) -> None:
    for directory in sorted(
        (path for path in root.rglob("*") if path.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        _fsync_directory(directory)
    _fsync_directory(root)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for create-only handoff publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1) == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(f"classifier handoff destination already exists: {destination}")
    raise OSError(error, os.strerror(error), destination)


def _handoff_readme() -> str:
    return """# QCSD classifier-pilot handoff

This package is a pipeline pilot, not evidence of classifier or defence efficacy.

`raw/*.pcapng` and `raw/*.run.json` are exact restricted evidence copies.
`raw/*.pcap` is a valid nanosecond classic-PCAP conversion for readers without
PCAPNG support. All raw forms contain endpoint identity, absolute timing,
QUIC/TLS metadata, URLs, or headers. They must not be used directly as
website-classification features unless that is an explicitly declared threat
model.

`stripped/*.pcap` is a shape-only synthetic Ethernet/IPv4/UDP projection. It
preserves relative packet timestamp, client-relative direction, and Ethernet
`frame.len`; identifiers are fixed and every UDP payload byte is zero. It is not
a valid QUIC transcript.

`traces/*.csv` is the canonical classifier-facing projection. Positive signed
lengths are client egress and negative signed lengths are server ingress.
`samples.jsonl` contains labels, collection-block splits, provenance bindings,
and hashes. Keep all samples with the same `paired_visit_id` in the same split.

Neqo controller/event/schedule records are intentionally excluded because they
would disclose defence-internal labels unavailable to a network observer.
Validate every file from this directory with:

    sha256sum -c SHA256SUMS
"""


if __name__ == "__main__":
    main()
