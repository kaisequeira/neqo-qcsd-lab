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
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Sequence

from qcsd_lab.capture import ObserverPacket, extract_trace
from qcsd_lab.experiment import resolved_sample_directory, validate_planned_sample_identity
from qcsd_lab.fidelity import validate_primary_capture_clock_integrity
from qcsd_lab.orchestrator import (
    FULL_CHAFF_SCOPE,
    RESPONSE_ONLY_CHAFF_SCOPE,
    load_campaign,
    plan_campaign,
)
from qcsd_lab.util import load_json, sha256_file, source_metadata
from qcsd_lab.verification import verify_result


SCHEMA_VERSION = 1
POC5_SCHEMA_VERSION = 2
ARTIFACT_TYPE = "qcsd-classifier-pilot-handoff"
PURPOSE = "classifier-pipeline-pilot"
SPLITS = {"train", "validation", "test", "interface"}
POC5_SPLITS = SPLITS | {"inference"}
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

POC5_CLASSES = (
    "getbootstrap-home-r3",
    "cloudflare-quiche-r3",
    "hyper-basic-client-r2",
    "serde-home-r1",
    "rfc9114-text-r1",
)
POC5_CLASS_LABELS = {
    "getbootstrap-home-r3": "getbootstrap.com",
    "cloudflare-quiche-r3": "cloudflare-quic.com",
    "hyper-basic-client-r2": "hyper.rs",
    "serde-home-r1": "serde.rs",
    "rfc9114-text-r1": "www.rfc-editor.org",
}
POC5_DEFENSES = ("undefended", "front", "tamaraw")
POC5_RUNTIME = {
    "undefended": ("none", True),
    "front": ("front", False),
    "tamaraw": ("tamaraw", False),
}
POC5_TEMPORAL_SPLITS = (
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "validation",
    "test",
)
POC5_BASELINE_RESULT_NAMES = tuple(
    f"research-classifier-poc5-baseline-{block:02d}-1200" for block in range(1, 11)
)
POC5_PAIRED_RESULT_NAMES = tuple(
    f"research-classifier-poc5-paired-{block:02d}-1200" for block in range(1, 11)
)
POC5_RESULT_NAMES = tuple(
    name
    for block in range(10)
    for name in (POC5_BASELINE_RESULT_NAMES[block], POC5_PAIRED_RESULT_NAMES[block])
)
POC5_CAMPAIGN_FILES = tuple(
    name
    for block in range(1, 11)
    for name in (
        f"classifier-poc5-baseline-{block:02d}.yml",
        f"classifier-poc5-paired-{block:02d}.yml",
    )
)
POC5_REHEARSAL_RESULT_NAME = "research-classifier-poc5-rehearsal-1200"

MULTIORIGIN5_COHORT = "classifier-multiorigin5-v1"
MULTIORIGIN5_QUALIFICATION_SET = MULTIORIGIN5_COHORT
MULTIORIGIN5_CLASSES = (
    "getbootstrap-home-r4",
    "cloudflare-quiche-r4",
    "hyper-basic-client-r3",
    "serde-home-r2",
    "rfc9114-text-r2",
)
MULTIORIGIN5_CLASS_LABELS = {
    "getbootstrap-home-r4": "getbootstrap.com",
    "cloudflare-quiche-r4": "cloudflare-quic.com",
    "hyper-basic-client-r3": "hyper.rs",
    "serde-home-r2": "serde.rs",
    "rfc9114-text-r2": "www.rfc-editor.org",
}
MULTIORIGIN5_DEFENSES = ("undefended", "front", "tamaraw")
MULTIORIGIN5_RUNTIME = {
    "undefended": ("none", True),
    "front": ("front", False),
    "tamaraw": ("tamaraw", False),
}
MULTIORIGIN5_TEMPORAL_SPLITS = (
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "validation",
    "test",
)
MULTIORIGIN5_BASELINE_RESULT_NAMES = tuple(
    f"research-{MULTIORIGIN5_COHORT}-baseline-{block:02d}-1200" for block in range(1, 11)
)
MULTIORIGIN5_PAIRED_RESULT_NAMES = tuple(
    f"research-{MULTIORIGIN5_COHORT}-paired-{block:02d}-1200" for block in range(1, 11)
)
MULTIORIGIN5_RESULT_NAMES = tuple(
    name
    for block in range(10)
    for name in (
        MULTIORIGIN5_BASELINE_RESULT_NAMES[block],
        MULTIORIGIN5_PAIRED_RESULT_NAMES[block],
    )
)
MULTIORIGIN5_BASELINE_CAMPAIGN_FILES = tuple(
    f"{MULTIORIGIN5_COHORT}-baseline-{block:02d}.yml" for block in range(1, 11)
)
MULTIORIGIN5_PAIRED_CAMPAIGN_FILES = tuple(
    f"{MULTIORIGIN5_COHORT}-paired-{block:02d}.yml" for block in range(1, 11)
)
MULTIORIGIN5_CAMPAIGN_FILES = tuple(
    name
    for block in range(10)
    for name in (
        MULTIORIGIN5_BASELINE_CAMPAIGN_FILES[block],
        MULTIORIGIN5_PAIRED_CAMPAIGN_FILES[block],
    )
)
MULTIORIGIN5_REHEARSAL_RESULT_NAME = f"research-{MULTIORIGIN5_COHORT}-rehearsal-1200"
MULTIORIGIN5_REHEARSAL_CAMPAIGN_FILE = f"{MULTIORIGIN5_COHORT}-rehearsal.yml"

MULTIORIGIN5_V2_COHORT = "classifier-multiorigin5-v2"
MULTIORIGIN5_V2_QUALIFICATION_SET = MULTIORIGIN5_V2_COHORT
MULTIORIGIN5_V2_CLASSES = (
    "getbootstrap-home-r4",
    "cloudflare-quiche-r4",
    "hyper-basic-client-r3",
    "serde-home-r2",
    "rfc9114-text-r2",
)
MULTIORIGIN5_V2_CLASS_LABELS = {
    "getbootstrap-home-r4": "getbootstrap.com",
    "cloudflare-quiche-r4": "cloudflare-quic.com",
    "hyper-basic-client-r3": "hyper.rs",
    "serde-home-r2": "serde.rs",
    "rfc9114-text-r2": "www.rfc-editor.org",
}
MULTIORIGIN5_V2_DEFENSES = ("undefended", "front", "tamaraw")
MULTIORIGIN5_V2_RUNTIME = {
    "undefended": ("none", True),
    "front": ("front", False),
    "tamaraw": ("tamaraw", False),
}
MULTIORIGIN5_V2_TEMPORAL_SPLITS = (
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "train",
    "validation",
    "test",
)
MULTIORIGIN5_V2_BASELINE_RESULT_NAMES = tuple(
    f"research-{MULTIORIGIN5_V2_COHORT}-baseline-{block:02d}-1200" for block in range(1, 11)
)
MULTIORIGIN5_V2_PAIRED_RESULT_NAMES = tuple(
    f"research-{MULTIORIGIN5_V2_COHORT}-paired-{block:02d}-1200" for block in range(1, 11)
)
MULTIORIGIN5_V2_RESULT_NAMES = tuple(
    name
    for block in range(10)
    for name in (
        MULTIORIGIN5_V2_BASELINE_RESULT_NAMES[block],
        MULTIORIGIN5_V2_PAIRED_RESULT_NAMES[block],
    )
)
MULTIORIGIN5_V2_BASELINE_CAMPAIGN_FILES = tuple(
    f"{MULTIORIGIN5_V2_COHORT}-baseline-{block:02d}.yml" for block in range(1, 11)
)
MULTIORIGIN5_V2_PAIRED_CAMPAIGN_FILES = tuple(
    f"{MULTIORIGIN5_V2_COHORT}-paired-{block:02d}.yml" for block in range(1, 11)
)
MULTIORIGIN5_V2_CAMPAIGN_FILES = tuple(
    name
    for block in range(10)
    for name in (
        MULTIORIGIN5_V2_BASELINE_CAMPAIGN_FILES[block],
        MULTIORIGIN5_V2_PAIRED_CAMPAIGN_FILES[block],
    )
)
MULTIORIGIN5_V2_REHEARSAL_RESULT_NAME = f"research-{MULTIORIGIN5_V2_COHORT}-rehearsal-1200"
MULTIORIGIN5_V2_REHEARSAL_CAMPAIGN_FILE = f"{MULTIORIGIN5_V2_COHORT}-rehearsal.yml"
_SCHEMA_V2_RESULT_NAMES = frozenset(
    (
        *POC5_RESULT_NAMES,
        POC5_REHEARSAL_RESULT_NAME,
        *MULTIORIGIN5_RESULT_NAMES,
        MULTIORIGIN5_REHEARSAL_RESULT_NAME,
        *MULTIORIGIN5_V2_RESULT_NAMES,
        MULTIORIGIN5_V2_REHEARSAL_RESULT_NAME,
    )
)


@dataclass(frozen=True)
class PilotContract:
    """One exact, checked-in classifier-pilot cohort and block lineage."""

    result_names: tuple[str, ...]
    campaign_files: tuple[str, ...]
    classes: tuple[str, ...]


@dataclass(frozen=True)
class Poc5CollectionPlan:
    """Per-result sample split policies for the exact advisor POC."""

    sample_splits: tuple[Mapping[str, str], ...]
    protocol: str


@dataclass(frozen=True)
class Multiorigin5CollectionPlan:
    """Per-result split policies for the fresh multi-origin cohort."""

    sample_splits: tuple[Mapping[str, str], ...]
    protocol: str


@dataclass(frozen=True)
class Multiorigin5V2CollectionPlan:
    """Per-result split policies for the repaired multi-origin cohort."""

    sample_splits: tuple[Mapping[str, str], ...]
    protocol: str


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
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_POC5_SOURCE_KEYS = {
    "image_digest",
    "lab_commit",
    "lab_dirty",
    "lab_patch_sha256",
    "neqo_commit",
    "neqo_dirty",
    "neqo_patch_sha256",
    "neqo_pinned_commit",
}

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
_BLOCK_KEYS_V2 = _BLOCK_KEYS | {
    "acquisition_block_index",
    "acquisition_block_id",
    "sample_splits",
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
_SAMPLE_KEYS_V2 = _SAMPLE_KEYS | {"acquisition_block_index", "acquisition_block_id"}
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
        description="Export or verify an offline QCSD classifier handoff",
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
    """Create one immutable classifier handoff from sealed results.

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
    collection_plan = _validate_pilot_collection(verified, splits)
    schema_v2_plan = (
        collection_plan
        if isinstance(
            collection_plan,
            (Poc5CollectionPlan, Multiorigin5CollectionPlan, Multiorigin5V2CollectionPlan),
        )
        else None
    )
    schema_version = POC5_SCHEMA_VERSION if schema_v2_plan is not None else SCHEMA_VERSION
    if isinstance(schema_v2_plan, Poc5CollectionPlan):
        _validate_poc5_export_environment(verified)
    elif isinstance(schema_v2_plan, Multiorigin5CollectionPlan):
        _validate_multiorigin5_export_environment(verified)
    elif isinstance(schema_v2_plan, Multiorigin5V2CollectionPlan):
        _validate_multiorigin5_v2_export_environment(verified)

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
                or policies != expected_policies
                or (schema_v2_plan is None and defenses != expected_defenses)
            ):
                raise ValueError("classifier handoff blocks do not use one exact cohort")

            block_id = f"block-{block_index + 1:03d}"
            sample_splits = (
                None if schema_v2_plan is None else schema_v2_plan.sample_splits[block_index]
            )
            blocks.append(
                _block_receipt(
                    receipt,
                    block_index,
                    block_id,
                    split,
                    sample_splits=sample_splits,
                    acquisition_block_index=(None if schema_v2_plan is None else block_index // 2),
                )
            )
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
                        "schema_version": schema_version,
                        "sample_id": sample_id,
                        "block_index": block_index,
                        "block_id": block_id,
                        **(
                            {}
                            if schema_v2_plan is None
                            else {
                                "acquisition_block_index": block_index // 2,
                                "acquisition_block_id": (
                                    f"acquisition-block-{block_index // 2 + 1:03d}"
                                ),
                            }
                        ),
                        "split": (
                            split
                            if sample_splits is None
                            else sample_splits[str(sample["defense"])]
                        ),
                        "paired_visit_id": (
                            f"{block_id}/{sample['workload_id']}/"
                            f"{sample['request_policy']}/visit-{sample['visit']:03d}"
                        ),
                        "class_label": (
                            sample["workload_id"]
                            if schema_v2_plan is None
                            else _schema_v2_class_labels(schema_v2_plan)[str(sample["workload_id"])]
                        ),
                        "workload_id": sample["workload_id"],
                        "defense": sample["defense"],
                        "defense_role": (
                            _defense_role(sample)
                            if schema_v2_plan is None or sample["baseline"] is True
                            else "inference-only"
                        ),
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

        dataset = _dataset_receipt(rows, blocks, schema_version=schema_version)
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
    schema_version = dataset["schema_version"]
    if (
        schema_version not in {SCHEMA_VERSION, POC5_SCHEMA_VERSION}
        or dataset["artifact_type"] != ARTIFACT_TYPE
        or dataset["purpose"] != PURPOSE
        or dataset["pilot_only"] is not True
    ):
        raise ValueError("classifier handoff dataset identity is invalid")
    rows = _read_json_lines(root / "samples.jsonl", schema_version=schema_version)
    _validate_dataset_rows(root, dataset, rows, schema_version=schema_version)
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
    diagnostics = sample.get("diagnostics")
    capture = diagnostics.get("capture") if isinstance(diagnostics, Mapping) else None
    validate_primary_capture_clock_integrity(
        capture,
        label=f"classifier handoff rejects timing-contaminated sample {sample_id}",
    )


def _schema_v2_class_labels(
    plan: Poc5CollectionPlan | Multiorigin5CollectionPlan | Multiorigin5V2CollectionPlan,
) -> Mapping[str, str]:
    if isinstance(plan, Multiorigin5V2CollectionPlan):
        return MULTIORIGIN5_V2_CLASS_LABELS
    if isinstance(plan, Multiorigin5CollectionPlan):
        return MULTIORIGIN5_CLASS_LABELS
    return POC5_CLASS_LABELS


def _validate_pilot_collection(
    receipts: Sequence[Any], splits: Sequence[str | None]
) -> Poc5CollectionPlan | Multiorigin5CollectionPlan | Multiorigin5V2CollectionPlan | None:
    names = tuple(receipt.experiment["name"] for receipt in receipts)
    if names == (MULTIORIGIN5_V2_REHEARSAL_RESULT_NAME,):
        return _validate_multiorigin5_v2_rehearsal_collection(receipts[0], splits)
    if names == (MULTIORIGIN5_REHEARSAL_RESULT_NAME,):
        return _validate_multiorigin5_rehearsal_collection(receipts[0], splits)
    if names == (POC5_REHEARSAL_RESULT_NAME,):
        return _validate_poc5_rehearsal_collection(receipts[0], splits)
    if (
        POC5_REHEARSAL_RESULT_NAME in names
        or MULTIORIGIN5_REHEARSAL_RESULT_NAME in names
        or MULTIORIGIN5_V2_REHEARSAL_RESULT_NAME in names
    ):
        raise ValueError("classifier rehearsal cannot mix with another handoff lineage")
    has_poc5 = any(name.startswith("research-classifier-poc5-") for name in names)
    has_multiorigin5 = any(name.startswith(f"research-{MULTIORIGIN5_COHORT}-") for name in names)
    has_multiorigin5_v2 = any(
        name.startswith(f"research-{MULTIORIGIN5_V2_COHORT}-") for name in names
    )
    if has_poc5 and has_multiorigin5:
        raise ValueError("classifier handoff cannot mix POC5 and multi-origin lineages")
    if sum((has_poc5, has_multiorigin5, has_multiorigin5_v2)) > 1:
        raise ValueError("classifier handoff cannot mix POC5, v1, and v2 result lineages")
    if has_multiorigin5_v2:
        return _validate_multiorigin5_v2_collection(receipts, splits)
    if has_multiorigin5:
        return _validate_multiorigin5_collection(receipts, splits)
    if has_poc5:
        return _validate_poc5_collection(receipts, splits)
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


def _validate_poc5_collection(
    receipts: Sequence[Any], splits: Sequence[str | None]
) -> Poc5CollectionPlan:
    """Validate the exact 20-result, 2,500-capture advisor POC lineage."""

    names = tuple(receipt.experiment["name"] for receipt in receipts)
    if names != POC5_RESULT_NAMES:
        raise ValueError(
            "complete classifier POC5 requires 20 ordered baseline/paired results for blocks 01--10"
        )
    if any(split is not None for split in splits):
        raise ValueError("classifier POC5 sample splits are assigned automatically by protocol")

    lab_root = _lab_root()
    policies: list[Mapping[str, str]] = []
    for result_index, (receipt, campaign_file) in enumerate(
        zip(receipts, POC5_CAMPAIGN_FILES, strict=True)
    ):
        experiment = receipt.experiment
        block_index = result_index // 2
        temporal_split = POC5_TEMPORAL_SPLITS[block_index]
        baseline_result = result_index % 2 == 0
        if baseline_result:
            expected = Counter(
                (
                    workload_id,
                    "undefended",
                    "as-defined",
                    visit,
                    "none",
                    True,
                )
                for workload_id in POC5_CLASSES
                for visit in range(20)
            )
            policies.append({"undefended": temporal_split})
            expected_count = 100
        else:
            expected = Counter(
                (
                    workload_id,
                    defense,
                    "as-defined",
                    visit,
                    POC5_RUNTIME[defense][0],
                    POC5_RUNTIME[defense][1],
                )
                for workload_id in POC5_CLASSES
                for defense in POC5_DEFENSES
                for visit in range(10)
            )
            policies.append(
                {
                    "undefended": temporal_split,
                    "front": "inference",
                    "tamaraw": "inference",
                }
            )
            expected_count = 150
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
                f"classifier POC5 result is not the exact {expected_count}-sample cohort"
            )
        campaign = lab_root / "config/campaigns" / campaign_file
        _validate_poc5_configuration(experiment, campaign)
    _validate_poc5_temporal_intervals(
        [
            (receipt.experiment["started_at"], receipt.experiment["completed_at"])
            for receipt in receipts
        ]
    )
    _validate_poc5_execution_sources([receipt.experiment["source"] for receipt in receipts])
    return Poc5CollectionPlan(tuple(policies), "formal")


def _validate_poc5_rehearsal_collection(
    receipt: Any, splits: Sequence[str | None]
) -> Poc5CollectionPlan:
    if tuple(splits) != ("interface",):
        raise ValueError("classifier POC5 rehearsal requires the interface split")
    experiment = receipt.experiment
    expected = Counter(
        (
            workload_id,
            defense,
            "as-defined",
            visit,
            POC5_RUNTIME[defense][0],
            POC5_RUNTIME[defense][1],
        )
        for workload_id in POC5_CLASSES
        for defense in POC5_DEFENSES
        for visit in range(2)
    )
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
        raise ValueError("classifier POC5 rehearsal is not the exact 30-sample cohort")
    campaign = _lab_root() / "config/campaigns/classifier-poc5-rehearsal.yml"
    _validate_poc5_configuration(experiment, campaign)
    _validate_poc5_execution_sources([experiment["source"]])
    return Poc5CollectionPlan(({defense: "interface" for defense in POC5_DEFENSES},), "rehearsal")


def _validate_multiorigin5_collection(
    receipts: Sequence[Any], splits: Sequence[str | None]
) -> Multiorigin5CollectionPlan:
    """Validate the exact fresh 20-result, 2,500-capture lineage."""

    names = tuple(receipt.experiment["name"] for receipt in receipts)
    if names != MULTIORIGIN5_RESULT_NAMES:
        raise ValueError(
            "complete classifier multi-origin cohort requires 20 ordered "
            "baseline/paired results for blocks 01--10"
        )
    if any(split is not None for split in splits):
        raise ValueError(
            "classifier multi-origin sample splits are assigned automatically by protocol"
        )

    lab_root = _lab_root()
    policies: list[Mapping[str, str]] = []
    for result_index, (receipt, campaign_file) in enumerate(
        zip(receipts, MULTIORIGIN5_CAMPAIGN_FILES, strict=True)
    ):
        experiment = receipt.experiment
        block_index = result_index // 2
        temporal_split = MULTIORIGIN5_TEMPORAL_SPLITS[block_index]
        baseline_result = result_index % 2 == 0
        if baseline_result:
            expected = Counter(
                (
                    workload_id,
                    "undefended",
                    "as-defined",
                    visit,
                    "none",
                    True,
                )
                for workload_id in MULTIORIGIN5_CLASSES
                for visit in range(20)
            )
            policies.append({"undefended": temporal_split})
            expected_count = 100
        else:
            expected = Counter(
                (
                    workload_id,
                    defense,
                    "as-defined",
                    visit,
                    MULTIORIGIN5_RUNTIME[defense][0],
                    MULTIORIGIN5_RUNTIME[defense][1],
                )
                for workload_id in MULTIORIGIN5_CLASSES
                for defense in MULTIORIGIN5_DEFENSES
                for visit in range(10)
            )
            policies.append(
                {
                    "undefended": temporal_split,
                    "front": "inference",
                    "tamaraw": "inference",
                }
            )
            expected_count = 150
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
                f"classifier multi-origin result is not the exact {expected_count}-sample cohort"
            )
        campaign = lab_root / "config/campaigns" / campaign_file
        _validate_multiorigin5_configuration(
            experiment,
            campaign,
            qualification_set=(None if baseline_result else MULTIORIGIN5_QUALIFICATION_SET),
        )
    _validate_multiorigin5_temporal_intervals(
        [
            (receipt.experiment["started_at"], receipt.experiment["completed_at"])
            for receipt in receipts
        ]
    )
    _validate_multiorigin5_execution_sources([receipt.experiment["source"] for receipt in receipts])
    return Multiorigin5CollectionPlan(tuple(policies), "formal")


def _validate_multiorigin5_rehearsal_collection(
    receipt: Any, splits: Sequence[str | None]
) -> Multiorigin5CollectionPlan:
    if tuple(splits) != ("interface",):
        raise ValueError("classifier multi-origin rehearsal requires the interface split")
    experiment = receipt.experiment
    expected = Counter(
        (
            workload_id,
            defense,
            "as-defined",
            visit,
            MULTIORIGIN5_RUNTIME[defense][0],
            MULTIORIGIN5_RUNTIME[defense][1],
        )
        for workload_id in MULTIORIGIN5_CLASSES
        for defense in MULTIORIGIN5_DEFENSES
        for visit in range(2)
    )
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
        raise ValueError("classifier multi-origin rehearsal is not the exact 30-sample cohort")
    campaign = _lab_root() / "config/campaigns" / MULTIORIGIN5_REHEARSAL_CAMPAIGN_FILE
    _validate_multiorigin5_configuration(
        experiment,
        campaign,
        qualification_set=MULTIORIGIN5_QUALIFICATION_SET,
    )
    _validate_multiorigin5_execution_sources([experiment["source"]])
    return Multiorigin5CollectionPlan(
        ({defense: "interface" for defense in MULTIORIGIN5_DEFENSES},),
        "rehearsal",
    )


def _validate_multiorigin5_v2_collection(
    receipts: Sequence[Any], splits: Sequence[str | None]
) -> Multiorigin5V2CollectionPlan:
    """Validate the repaired 20-result, 2,500-capture multi-origin lineage."""

    names = tuple(receipt.experiment["name"] for receipt in receipts)
    if names != MULTIORIGIN5_V2_RESULT_NAMES:
        raise ValueError(
            "complete classifier multi-origin v2 cohort requires 20 ordered "
            "baseline/paired results for blocks 01--10"
        )
    if any(split is not None for split in splits):
        raise ValueError(
            "classifier multi-origin v2 sample splits are assigned automatically by protocol"
        )

    lab_root = _lab_root()
    policies: list[Mapping[str, str]] = []
    for result_index, (receipt, campaign_file) in enumerate(
        zip(receipts, MULTIORIGIN5_V2_CAMPAIGN_FILES, strict=True)
    ):
        experiment = receipt.experiment
        block_index = result_index // 2
        temporal_split = MULTIORIGIN5_V2_TEMPORAL_SPLITS[block_index]
        baseline_result = result_index % 2 == 0
        if baseline_result:
            expected = Counter(
                (
                    workload_id,
                    "undefended",
                    "as-defined",
                    visit,
                    "none",
                    True,
                )
                for workload_id in MULTIORIGIN5_V2_CLASSES
                for visit in range(20)
            )
            policies.append({"undefended": temporal_split})
            expected_count = 100
        else:
            expected = Counter(
                (
                    workload_id,
                    defense,
                    "as-defined",
                    visit,
                    MULTIORIGIN5_V2_RUNTIME[defense][0],
                    MULTIORIGIN5_V2_RUNTIME[defense][1],
                )
                for workload_id in MULTIORIGIN5_V2_CLASSES
                for defense in MULTIORIGIN5_V2_DEFENSES
                for visit in range(10)
            )
            policies.append(
                {
                    "undefended": temporal_split,
                    "front": "inference",
                    "tamaraw": "inference",
                }
            )
            expected_count = 150
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
                f"classifier multi-origin v2 result is not the exact {expected_count}-sample cohort"
            )
        campaign = lab_root / "config/campaigns" / campaign_file
        _validate_multiorigin5_v2_configuration(
            experiment,
            campaign,
            qualification_set=(None if baseline_result else MULTIORIGIN5_V2_QUALIFICATION_SET),
        )
    _validate_multiorigin5_v2_temporal_intervals(
        [
            (receipt.experiment["started_at"], receipt.experiment["completed_at"])
            for receipt in receipts
        ]
    )
    _validate_multiorigin5_v2_execution_sources(
        [receipt.experiment["source"] for receipt in receipts]
    )
    return Multiorigin5V2CollectionPlan(tuple(policies), "formal")


def _validate_multiorigin5_v2_rehearsal_collection(
    receipt: Any, splits: Sequence[str | None]
) -> Multiorigin5V2CollectionPlan:
    if tuple(splits) != ("interface",):
        raise ValueError("classifier multi-origin v2 rehearsal requires the interface split")
    experiment = receipt.experiment
    expected = Counter(
        (
            workload_id,
            defense,
            "as-defined",
            visit,
            MULTIORIGIN5_V2_RUNTIME[defense][0],
            MULTIORIGIN5_V2_RUNTIME[defense][1],
        )
        for workload_id in MULTIORIGIN5_V2_CLASSES
        for defense in MULTIORIGIN5_V2_DEFENSES
        for visit in range(2)
    )
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
        raise ValueError("classifier multi-origin v2 rehearsal is not the exact 30-sample cohort")
    campaign = _lab_root() / "config/campaigns" / MULTIORIGIN5_V2_REHEARSAL_CAMPAIGN_FILE
    _validate_multiorigin5_v2_configuration(
        experiment,
        campaign,
        qualification_set=MULTIORIGIN5_V2_QUALIFICATION_SET,
    )
    _validate_multiorigin5_v2_execution_sources([experiment["source"]])
    return Multiorigin5V2CollectionPlan(
        ({defense: "interface" for defense in MULTIORIGIN5_V2_DEFENSES},),
        "rehearsal",
    )


def _validate_poc5_response_only_binding(workload: Any) -> None:
    """Require the active POC to bind sustained identity-response evidence.

    ``load_campaign`` performs the authoritative semantic validation. This
    exporter gate also makes the active POC format explicit: the sidecar hash
    binds schema-two candidate/epoch receipts, and the derived-manifest hash
    binds the matching schema-four request primitive. Frozen schema-one and
    schema-three evidence remains a verifier input, but cannot be mistaken for
    the active collection contract.
    """

    from qcsd_lab import chaff_qualification

    path = workload.chaff_qualification_path
    manifest = workload.chaff_manifest_data
    if path is None or not isinstance(manifest, Mapping):
        raise ValueError("classifier POC5 response-only chaff binding is incomplete")
    sidecar = load_json(path)
    if not isinstance(sidecar, Mapping):
        raise ValueError("classifier POC5 response-only chaff sidecar is invalid")

    primitive = chaff_qualification.response_only_request_header_primitive()
    attempts = sidecar.get("candidate_attempts")
    resources = manifest.get("resources")
    if (
        sidecar.get("schema_version") != chaff_qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
        or manifest.get("schema_version")
        != chaff_qualification.RESPONSE_ONLY_MANIFEST_V2_SCHEMA_VERSION
        or sidecar.get("request_header_primitive") != primitive
        or not isinstance(attempts, list)
        or not attempts
        or not isinstance(resources, list)
        or len(resources) != 1
        or not isinstance(resources[0], Mapping)
    ):
        raise ValueError(
            "classifier POC5 response-only chaff binding is not v2/schema-four identity evidence"
        )

    final_attempt = attempts[-1]
    qualification = resources[0].get("chaff_qualification")
    if (
        not isinstance(final_attempt, Mapping)
        or final_attempt.get("outcome") != "qualified"
        or final_attempt.get("failure_class") is not None
        or any(
            not isinstance(attempt, Mapping)
            or not isinstance(attempt.get("connection_epochs"), list)
            or len(attempt["connection_epochs"]) != chaff_qualification.QUALIFICATION_RUNS
            or any(
                not isinstance(epoch, Mapping)
                or not isinstance(epoch.get("receipt"), Mapping)
                or epoch["receipt"].get("schema_version")
                != chaff_qualification.RESPONSE_QUALIFICATION_V2_RECEIPT_SCHEMA_VERSION
                or epoch["receipt"].get("request_header_mode")
                != chaff_qualification.IDENTITY_REQUEST_HEADER_MODE
                for epoch in attempt["connection_epochs"]
            )
            for attempt in attempts
        )
        or not isinstance(qualification, Mapping)
        or qualification.get("schema_version")
        != chaff_qualification.RESPONSE_ONLY_MANIFEST_V2_SCHEMA_VERSION
        or qualification.get("request_header_primitive") != primitive
        or qualification.get("qualified_completion_count")
        != chaff_qualification.RESPONSE_ONLY_COMPLETIONS_PER_CANDIDATE
        or qualification.get("response_qualification_sha256")
        != final_attempt.get("response_qualification_sha256")
    ):
        raise ValueError(
            "classifier POC5 response-only chaff candidate/identity binding is invalid"
        )


@lru_cache(maxsize=21)
def _cached_poc5_configuration(campaign_path: Path) -> tuple[Any, str]:
    campaign = load_campaign(campaign_path)
    workload_records: list[dict[str, Any]] = []
    for workload in campaign.workloads:
        record: dict[str, Any] = {
            "id": workload.id,
            "visits": workload.visits,
            "manifest": f"inputs/workloads/{workload.id}.json",
            "sha256": workload.sha256,
            "resource_count": workload.resource_count,
            "origin_count": workload.origin_count,
        }
        if workload.chaff_qualification_path is not None:
            common_values = (
                workload.chaff_qualification_sha256,
                workload.chaff_manifest_sha256,
                workload.runtime_sha256,
            )
            scope = workload.chaff_qualification_scope
            if any(not _valid_sha256(value) for value in common_values) or scope not in {
                RESPONSE_ONLY_CHAFF_SCOPE,
                FULL_CHAFF_SCOPE,
            }:
                raise ValueError("classifier POC5 checked-in chaff binding is incomplete")
            record.update(
                chaff_qualification=f"inputs/chaff-qualifications/{workload.id}.json",
                chaff_qualification_sha256=workload.chaff_qualification_sha256,
                chaff_manifest=f"inputs/chaff-manifests/{workload.id}.json",
                chaff_manifest_sha256=workload.chaff_manifest_sha256,
                runtime_manifest=f"inputs/runtime-workloads/{workload.id}.json",
                runtime_manifest_sha256=workload.runtime_sha256,
            )
            if scope == RESPONSE_ONLY_CHAFF_SCOPE:
                if (
                    workload.chaff_prefix_spec_path is not None
                    or workload.chaff_prefix_spec_sha256 is not None
                ):
                    raise ValueError(
                        "classifier POC5 response-only chaff binding unexpectedly has a prefix spec"
                    )
                _validate_poc5_response_only_binding(workload)
                record["chaff_qualification_scope"] = RESPONSE_ONLY_CHAFF_SCOPE
            else:
                if workload.chaff_prefix_spec_path is None or not _valid_sha256(
                    workload.chaff_prefix_spec_sha256
                ):
                    raise ValueError("classifier POC5 checked-in chaff binding is incomplete")
                record.update(
                    chaff_prefix_spec=f"inputs/chaff-prefix-specs/{workload.id}.json",
                    chaff_prefix_spec_sha256=workload.chaff_prefix_spec_sha256,
                )
        workload_records.append(record)

    defense_records: list[dict[str, Any]] = []
    for defense in campaign.defenses:
        if defense.schedule_path is not None or defense.parameters_path is not None:
            raise ValueError("classifier POC5 defense unexpectedly consumes an external artifact")
        defense_records.append(
            {
                "name": defense.name,
                "kind": defense.kind,
                "baseline": defense.baseline,
            }
        )
    expected = {
        "campaign_sha256": sha256_file(campaign_path),
        "profile": campaign.profile,
        "request_policies": list(campaign.request_policies),
        "workloads": workload_records,
        "defenses": defense_records,
        "limits": campaign.limits.as_dict(),
    }
    return campaign, json.dumps(expected, sort_keys=True, separators=(",", ":"))


def _expected_poc5_configuration(campaign_path: Path) -> tuple[Any, dict[str, Any]]:
    """Return a fresh configuration object from one immutable cached snapshot."""

    campaign, encoded = _cached_poc5_configuration(campaign_path)
    value = json.loads(encoded)
    if not isinstance(value, dict):  # pragma: no cover - construction above is closed
        raise AssertionError("cached POC5 configuration is not an object")
    return campaign, value


def _validate_poc5_configuration(experiment: Mapping[str, Any], campaign_path: Path) -> None:
    """Bind one result to the exact current campaign, inputs, and sample plan."""

    campaign, expected = _expected_poc5_configuration(campaign_path)
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping) or dict(configuration) != expected:
        raise ValueError(
            "classifier POC5 result does not bind its exact checked-in campaign/input configuration"
        )
    try:
        validate_planned_sample_identity(experiment, plan_campaign(campaign))
    except ValueError as error:
        raise ValueError("classifier POC5 result planned sample identity/order mismatch") from error


@lru_cache(maxsize=21)
def _cached_multiorigin5_configuration(campaign_path: Path) -> tuple[Any, str]:
    paired_files = {
        *MULTIORIGIN5_PAIRED_CAMPAIGN_FILES,
        MULTIORIGIN5_REHEARSAL_CAMPAIGN_FILE,
    }
    if campaign_path.name in MULTIORIGIN5_BASELINE_CAMPAIGN_FILES:
        qualification_set = None
    elif campaign_path.name in paired_files:
        qualification_set = MULTIORIGIN5_QUALIFICATION_SET
    else:
        raise ValueError("classifier multi-origin campaign path is outside its exact contract")

    campaign = load_campaign(campaign_path)
    if campaign.chaff_qualification_set != qualification_set:
        raise ValueError("classifier multi-origin campaign qualification-set binding is invalid")

    workload_records: list[dict[str, Any]] = []
    for workload in campaign.workloads:
        record: dict[str, Any] = {
            "id": workload.id,
            "visits": workload.visits,
            "manifest": f"inputs/workloads/{workload.id}.json",
            "sha256": workload.sha256,
            "resource_count": workload.resource_count,
            "origin_count": workload.origin_count,
        }
        if workload.chaff_qualification_path is not None:
            common_values = (
                workload.chaff_qualification_sha256,
                workload.chaff_manifest_sha256,
                workload.runtime_sha256,
            )
            scope = workload.chaff_qualification_scope
            if any(not _valid_sha256(value) for value in common_values) or scope not in {
                RESPONSE_ONLY_CHAFF_SCOPE,
                FULL_CHAFF_SCOPE,
            }:
                raise ValueError("classifier multi-origin checked-in chaff binding is incomplete")
            record.update(
                chaff_qualification=f"inputs/chaff-qualifications/{workload.id}.json",
                chaff_qualification_sha256=workload.chaff_qualification_sha256,
                chaff_manifest=f"inputs/chaff-manifests/{workload.id}.json",
                chaff_manifest_sha256=workload.chaff_manifest_sha256,
                runtime_manifest=f"inputs/runtime-workloads/{workload.id}.json",
                runtime_manifest_sha256=workload.runtime_sha256,
            )
            if scope == RESPONSE_ONLY_CHAFF_SCOPE:
                if (
                    workload.chaff_prefix_spec_path is not None
                    or workload.chaff_prefix_spec_sha256 is not None
                ):
                    raise ValueError(
                        "classifier multi-origin response-only chaff binding "
                        "unexpectedly has a prefix spec"
                    )
                _validate_poc5_response_only_binding(workload)
                record["chaff_qualification_scope"] = RESPONSE_ONLY_CHAFF_SCOPE
            else:
                if workload.chaff_prefix_spec_path is None or not _valid_sha256(
                    workload.chaff_prefix_spec_sha256
                ):
                    raise ValueError(
                        "classifier multi-origin checked-in chaff binding is incomplete"
                    )
                record.update(
                    chaff_prefix_spec=f"inputs/chaff-prefix-specs/{workload.id}.json",
                    chaff_prefix_spec_sha256=workload.chaff_prefix_spec_sha256,
                )
        workload_records.append(record)

    defense_records: list[dict[str, Any]] = []
    for defense in campaign.defenses:
        if defense.schedule_path is not None or defense.parameters_path is not None:
            raise ValueError(
                "classifier multi-origin defense unexpectedly consumes an external artifact"
            )
        defense_records.append(
            {
                "name": defense.name,
                "kind": defense.kind,
                "baseline": defense.baseline,
            }
        )
    expected = {
        "campaign_sha256": sha256_file(campaign_path),
        "profile": campaign.profile,
        "request_policies": list(campaign.request_policies),
        "workloads": workload_records,
        "defenses": defense_records,
        "limits": campaign.limits.as_dict(),
    }
    if qualification_set is not None:
        expected["chaff_qualification_set"] = qualification_set
    return campaign, json.dumps(expected, sort_keys=True, separators=(",", ":"))


def _expected_multiorigin5_configuration(campaign_path: Path) -> tuple[Any, dict[str, Any]]:
    """Return a fresh configuration object from one immutable cached snapshot."""

    campaign, encoded = _cached_multiorigin5_configuration(campaign_path)
    value = json.loads(encoded)
    if not isinstance(value, dict):  # pragma: no cover - construction above is closed
        raise AssertionError("cached classifier multi-origin configuration is not an object")
    return campaign, value


def _validate_multiorigin5_configuration(
    experiment: Mapping[str, Any],
    campaign_path: Path,
    *,
    qualification_set: str | None,
) -> None:
    """Bind one result to its exact campaign, inputs, plan, and qualification set."""

    campaign, expected = _expected_multiorigin5_configuration(campaign_path)
    if campaign.chaff_qualification_set != qualification_set:
        raise ValueError("classifier multi-origin result qualification-set binding is invalid")
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping) or dict(configuration) != expected:
        raise ValueError(
            "classifier multi-origin result does not bind its exact "
            "checked-in campaign/input configuration"
        )
    if ("chaff_qualification_set" in configuration) != (qualification_set is not None):
        raise ValueError("classifier multi-origin result qualification-set presence is invalid")
    if qualification_set is not None and (
        configuration["chaff_qualification_set"] != qualification_set
    ):
        raise ValueError("classifier multi-origin result qualification-set binding is invalid")
    try:
        validate_planned_sample_identity(experiment, plan_campaign(campaign))
    except ValueError as error:
        raise ValueError(
            "classifier multi-origin result planned sample identity/order mismatch"
        ) from error


@lru_cache(maxsize=21)
def _cached_multiorigin5_v2_configuration(campaign_path: Path) -> tuple[Any, str]:
    paired_files = {
        *MULTIORIGIN5_V2_PAIRED_CAMPAIGN_FILES,
        MULTIORIGIN5_V2_REHEARSAL_CAMPAIGN_FILE,
    }
    if campaign_path.name in MULTIORIGIN5_V2_BASELINE_CAMPAIGN_FILES:
        qualification_set = None
    elif campaign_path.name in paired_files:
        qualification_set = MULTIORIGIN5_V2_QUALIFICATION_SET
    else:
        raise ValueError("classifier multi-origin v2 campaign path is outside its exact contract")

    campaign = load_campaign(campaign_path)
    if campaign.chaff_qualification_set != qualification_set:
        raise ValueError("classifier multi-origin v2 campaign qualification-set binding is invalid")

    workload_records: list[dict[str, Any]] = []
    for workload in campaign.workloads:
        record: dict[str, Any] = {
            "id": workload.id,
            "visits": workload.visits,
            "manifest": f"inputs/workloads/{workload.id}.json",
            "sha256": workload.sha256,
            "resource_count": workload.resource_count,
            "origin_count": workload.origin_count,
        }
        if workload.chaff_qualification_path is not None:
            common_values = (
                workload.chaff_qualification_sha256,
                workload.chaff_manifest_sha256,
                workload.runtime_sha256,
            )
            scope = workload.chaff_qualification_scope
            if any(not _valid_sha256(value) for value in common_values) or scope not in {
                RESPONSE_ONLY_CHAFF_SCOPE,
                FULL_CHAFF_SCOPE,
            }:
                raise ValueError(
                    "classifier multi-origin v2 checked-in chaff binding is incomplete"
                )
            record.update(
                chaff_qualification=f"inputs/chaff-qualifications/{workload.id}.json",
                chaff_qualification_sha256=workload.chaff_qualification_sha256,
                chaff_manifest=f"inputs/chaff-manifests/{workload.id}.json",
                chaff_manifest_sha256=workload.chaff_manifest_sha256,
                runtime_manifest=f"inputs/runtime-workloads/{workload.id}.json",
                runtime_manifest_sha256=workload.runtime_sha256,
            )
            if scope == RESPONSE_ONLY_CHAFF_SCOPE:
                if (
                    workload.chaff_prefix_spec_path is not None
                    or workload.chaff_prefix_spec_sha256 is not None
                ):
                    raise ValueError(
                        "classifier multi-origin v2 response-only chaff binding "
                        "unexpectedly has a prefix spec"
                    )
                _validate_poc5_response_only_binding(workload)
                record["chaff_qualification_scope"] = RESPONSE_ONLY_CHAFF_SCOPE
            else:
                if workload.chaff_prefix_spec_path is None or not _valid_sha256(
                    workload.chaff_prefix_spec_sha256
                ):
                    raise ValueError(
                        "classifier multi-origin v2 checked-in chaff binding is incomplete"
                    )
                record.update(
                    chaff_prefix_spec=f"inputs/chaff-prefix-specs/{workload.id}.json",
                    chaff_prefix_spec_sha256=workload.chaff_prefix_spec_sha256,
                )
        workload_records.append(record)

    defense_records: list[dict[str, Any]] = []
    for defense in campaign.defenses:
        if defense.schedule_path is not None or defense.parameters_path is not None:
            raise ValueError(
                "classifier multi-origin v2 defense unexpectedly consumes an external artifact"
            )
        defense_records.append(
            {
                "name": defense.name,
                "kind": defense.kind,
                "baseline": defense.baseline,
            }
        )
    expected = {
        "campaign_sha256": sha256_file(campaign_path),
        "profile": campaign.profile,
        "request_policies": list(campaign.request_policies),
        "workloads": workload_records,
        "defenses": defense_records,
        "limits": campaign.limits.as_dict(),
    }
    if qualification_set is not None:
        expected["chaff_qualification_set"] = qualification_set
    return campaign, json.dumps(expected, sort_keys=True, separators=(",", ":"))


def _expected_multiorigin5_v2_configuration(campaign_path: Path) -> tuple[Any, dict[str, Any]]:
    """Return a fresh v2 configuration from one immutable cached snapshot."""

    campaign, encoded = _cached_multiorigin5_v2_configuration(campaign_path)
    value = json.loads(encoded)
    if not isinstance(value, dict):  # pragma: no cover - construction above is closed
        raise AssertionError("cached classifier multi-origin v2 configuration is not an object")
    return campaign, value


def _validate_multiorigin5_v2_configuration(
    experiment: Mapping[str, Any],
    campaign_path: Path,
    *,
    qualification_set: str | None,
) -> None:
    """Bind one v2 result to its exact campaign, inputs, plan, and qualification set."""

    campaign, expected = _expected_multiorigin5_v2_configuration(campaign_path)
    if campaign.chaff_qualification_set != qualification_set:
        raise ValueError("classifier multi-origin v2 result qualification-set binding is invalid")
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping) or dict(configuration) != expected:
        raise ValueError(
            "classifier multi-origin v2 result does not bind its exact "
            "checked-in campaign/input configuration"
        )
    if ("chaff_qualification_set" in configuration) != (qualification_set is not None):
        raise ValueError("classifier multi-origin v2 result qualification-set presence is invalid")
    if qualification_set is not None and (
        configuration["chaff_qualification_set"] != qualification_set
    ):
        raise ValueError("classifier multi-origin v2 result qualification-set binding is invalid")
    try:
        validate_planned_sample_identity(experiment, plan_campaign(campaign))
    except ValueError as error:
        raise ValueError(
            "classifier multi-origin v2 result planned sample identity/order mismatch"
        ) from error


def _validate_poc5_execution_sources(sources: Sequence[Any]) -> None:
    """Require one exact clean Lab/Neqo/image lineage for a POC5 collection."""

    if not sources or any(not isinstance(source, Mapping) for source in sources):
        raise ValueError("classifier POC5 execution source receipt is invalid")
    first = sources[0]
    if any(source != first for source in sources[1:]):
        raise ValueError("classifier POC5 requires one identical execution source")
    if set(first) != _POC5_SOURCE_KEYS:
        raise ValueError("classifier POC5 execution source receipt is invalid")
    image_digest = first["image_digest"]
    lab_commit = first["lab_commit"]
    neqo_commit = first["neqo_commit"]
    pinned_commit = first["neqo_pinned_commit"]
    if (
        not isinstance(image_digest, str)
        or not image_digest.startswith("sha256:")
        or not _valid_sha256(image_digest.removeprefix("sha256:"))
        or not isinstance(lab_commit, str)
        or len(lab_commit) != 40
        or any(character not in "0123456789abcdef" for character in lab_commit)
        or not isinstance(neqo_commit, str)
        or len(neqo_commit) != 40
        or any(character not in "0123456789abcdef" for character in neqo_commit)
        or pinned_commit != neqo_commit
        or first["lab_dirty"] is not False
        or first["neqo_dirty"] is not False
        or first["lab_patch_sha256"] != EMPTY_SHA256
        or first["neqo_patch_sha256"] != EMPTY_SHA256
    ):
        raise ValueError("classifier POC5 requires one clean immutable execution source")


def _validate_poc5_export_environment(receipts: Sequence[Any]) -> None:
    """Require export from the same clean checkout and immutable collection image."""

    source = receipts[0].experiment["source"]
    exporter = _exporter_source_receipt()
    companion = exporter["companion"]
    if (
        companion["lab_dirty"] is not False
        or companion["lab_commit"] != source["lab_commit"]
        or exporter["execution_image"] != source
    ):
        raise ValueError(
            "classifier POC5 export requires its clean capture checkout and collection image"
        )


def _validate_poc5_exporter_lineage(dataset: Mapping[str, Any], source: Mapping[str, Any]) -> None:
    exporter = dataset["exporter_source"]
    companion = exporter["companion"]
    if (
        exporter["execution_image"] != source
        or companion["lab_commit"] != source["lab_commit"]
        or companion["lab_dirty"] is not False
    ):
        raise ValueError("classifier POC5 handoff exporter lineage is invalid")


def _validate_poc5_temporal_intervals(
    intervals: Sequence[tuple[Any, Any]],
) -> None:
    """Require ten ordered, non-overlapping baseline/paired acquisition blocks."""

    if len(intervals) != 20:
        raise ValueError("classifier POC5 temporal protocol requires 20 result intervals")
    parsed: list[tuple[datetime, datetime]] = []
    for started_at, completed_at in intervals:
        try:
            start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
            completed = datetime.fromisoformat(str(completed_at).replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("classifier POC5 result timestamp is invalid") from error
        if start.utcoffset() is None or completed.utcoffset() is None or completed < start:
            raise ValueError("classifier POC5 result interval is invalid")
        parsed.append((start, completed))

    for acquisition_block in range(10):
        baseline, paired = parsed[acquisition_block * 2 : acquisition_block * 2 + 2]
        baseline_first = acquisition_block % 2 == 0
        if (baseline_first and baseline[1] > paired[0]) or (
            not baseline_first and paired[1] > baseline[0]
        ):
            raise ValueError("classifier POC5 within-block capture order does not alternate")
        if acquisition_block < 9:
            next_pair = parsed[(acquisition_block + 1) * 2 : (acquisition_block + 1) * 2 + 2]
            if max(baseline[1], paired[1]) > min(next_pair[0][0], next_pair[1][0]):
                raise ValueError("classifier POC5 acquisition blocks are not temporally ordered")


def _validate_multiorigin5_execution_sources(sources: Sequence[Any]) -> None:
    """Require one clean Lab/Neqo/image lineage for the fresh collection."""

    if not sources or any(not isinstance(source, Mapping) for source in sources):
        raise ValueError("classifier multi-origin execution source receipt is invalid")
    first = sources[0]
    if any(source != first for source in sources[1:]):
        raise ValueError("classifier multi-origin requires one identical execution source")
    if set(first) != _POC5_SOURCE_KEYS:
        raise ValueError("classifier multi-origin execution source receipt is invalid")
    image_digest = first["image_digest"]
    lab_commit = first["lab_commit"]
    neqo_commit = first["neqo_commit"]
    pinned_commit = first["neqo_pinned_commit"]
    if (
        not isinstance(image_digest, str)
        or not image_digest.startswith("sha256:")
        or not _valid_sha256(image_digest.removeprefix("sha256:"))
        or not isinstance(lab_commit, str)
        or len(lab_commit) != 40
        or any(character not in "0123456789abcdef" for character in lab_commit)
        or not isinstance(neqo_commit, str)
        or len(neqo_commit) != 40
        or any(character not in "0123456789abcdef" for character in neqo_commit)
        or pinned_commit != neqo_commit
        or first["lab_dirty"] is not False
        or first["neqo_dirty"] is not False
        or first["lab_patch_sha256"] != EMPTY_SHA256
        or first["neqo_patch_sha256"] != EMPTY_SHA256
    ):
        raise ValueError("classifier multi-origin requires one clean immutable execution source")


def _validate_multiorigin5_export_environment(receipts: Sequence[Any]) -> None:
    """Require export from the clean collection checkout and image."""

    source = receipts[0].experiment["source"]
    exporter = _exporter_source_receipt()
    companion = exporter["companion"]
    if (
        companion["lab_dirty"] is not False
        or companion["lab_commit"] != source["lab_commit"]
        or exporter["execution_image"] != source
    ):
        raise ValueError(
            "classifier multi-origin export requires its clean capture checkout "
            "and collection image"
        )


def _validate_multiorigin5_exporter_lineage(
    dataset: Mapping[str, Any], source: Mapping[str, Any]
) -> None:
    exporter = dataset["exporter_source"]
    companion = exporter["companion"]
    if (
        exporter["execution_image"] != source
        or companion["lab_commit"] != source["lab_commit"]
        or companion["lab_dirty"] is not False
    ):
        raise ValueError("classifier multi-origin handoff exporter lineage is invalid")


def _validate_multiorigin5_temporal_intervals(
    intervals: Sequence[tuple[Any, Any]],
) -> None:
    """Require ten ordered pairs with alternating within-pair acquisition order."""

    if len(intervals) != 20:
        raise ValueError("classifier multi-origin temporal protocol requires 20 result intervals")
    parsed: list[tuple[datetime, datetime]] = []
    for started_at, completed_at in intervals:
        try:
            start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
            completed = datetime.fromisoformat(str(completed_at).replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("classifier multi-origin result timestamp is invalid") from error
        if start.utcoffset() is None or completed.utcoffset() is None or completed < start:
            raise ValueError("classifier multi-origin result interval is invalid")
        parsed.append((start, completed))

    for acquisition_block in range(10):
        baseline, paired = parsed[acquisition_block * 2 : acquisition_block * 2 + 2]
        baseline_first = acquisition_block % 2 == 0
        if (baseline_first and baseline[1] > paired[0]) or (
            not baseline_first and paired[1] > baseline[0]
        ):
            raise ValueError(
                "classifier multi-origin within-block capture order does not alternate"
            )
        if acquisition_block < 9:
            next_pair = parsed[(acquisition_block + 1) * 2 : (acquisition_block + 1) * 2 + 2]
            if max(baseline[1], paired[1]) > min(next_pair[0][0], next_pair[1][0]):
                raise ValueError(
                    "classifier multi-origin acquisition blocks are not temporally ordered"
                )


def _validate_multiorigin5_v2_execution_sources(sources: Sequence[Any]) -> None:
    """Require one clean Lab/Neqo/image lineage for the repaired collection."""

    if not sources or any(not isinstance(source, Mapping) for source in sources):
        raise ValueError("classifier multi-origin v2 execution source receipt is invalid")
    first = sources[0]
    if any(source != first for source in sources[1:]):
        raise ValueError("classifier multi-origin v2 requires one identical execution source")
    if set(first) != _POC5_SOURCE_KEYS:
        raise ValueError("classifier multi-origin v2 execution source receipt is invalid")
    image_digest = first["image_digest"]
    lab_commit = first["lab_commit"]
    neqo_commit = first["neqo_commit"]
    pinned_commit = first["neqo_pinned_commit"]
    if (
        not isinstance(image_digest, str)
        or not image_digest.startswith("sha256:")
        or not _valid_sha256(image_digest.removeprefix("sha256:"))
        or not isinstance(lab_commit, str)
        or len(lab_commit) != 40
        or any(character not in "0123456789abcdef" for character in lab_commit)
        or not isinstance(neqo_commit, str)
        or len(neqo_commit) != 40
        or any(character not in "0123456789abcdef" for character in neqo_commit)
        or pinned_commit != neqo_commit
        or first["lab_dirty"] is not False
        or first["neqo_dirty"] is not False
        or first["lab_patch_sha256"] != EMPTY_SHA256
        or first["neqo_patch_sha256"] != EMPTY_SHA256
    ):
        raise ValueError("classifier multi-origin v2 requires one clean immutable execution source")


def _validate_multiorigin5_v2_export_environment(receipts: Sequence[Any]) -> None:
    """Require v2 export from the clean collection checkout and image."""

    source = receipts[0].experiment["source"]
    exporter = _exporter_source_receipt()
    companion = exporter["companion"]
    if (
        companion["lab_dirty"] is not False
        or companion["lab_commit"] != source["lab_commit"]
        or exporter["execution_image"] != source
    ):
        raise ValueError(
            "classifier multi-origin v2 export requires its clean capture checkout "
            "and collection image"
        )


def _validate_multiorigin5_v2_exporter_lineage(
    dataset: Mapping[str, Any], source: Mapping[str, Any]
) -> None:
    exporter = dataset["exporter_source"]
    companion = exporter["companion"]
    if (
        exporter["execution_image"] != source
        or companion["lab_commit"] != source["lab_commit"]
        or companion["lab_dirty"] is not False
    ):
        raise ValueError("classifier multi-origin v2 handoff exporter lineage is invalid")


def _validate_multiorigin5_v2_temporal_intervals(
    intervals: Sequence[tuple[Any, Any]],
) -> None:
    """Require ten ordered v2 pairs with alternating within-pair acquisition order."""

    if len(intervals) != 20:
        raise ValueError(
            "classifier multi-origin v2 temporal protocol requires 20 result intervals"
        )
    parsed: list[tuple[datetime, datetime]] = []
    for started_at, completed_at in intervals:
        try:
            start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
            completed = datetime.fromisoformat(str(completed_at).replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("classifier multi-origin v2 result timestamp is invalid") from error
        if start.utcoffset() is None or completed.utcoffset() is None or completed < start:
            raise ValueError("classifier multi-origin v2 result interval is invalid")
        parsed.append((start, completed))

    for acquisition_block in range(10):
        baseline, paired = parsed[acquisition_block * 2 : acquisition_block * 2 + 2]
        baseline_first = acquisition_block % 2 == 0
        if (baseline_first and baseline[1] > paired[0]) or (
            not baseline_first and paired[1] > baseline[0]
        ):
            raise ValueError(
                "classifier multi-origin v2 within-block capture order does not alternate"
            )
        if acquisition_block < 9:
            next_pair = parsed[(acquisition_block + 1) * 2 : (acquisition_block + 1) * 2 + 2]
            if max(baseline[1], paired[1]) > min(next_pair[0][0], next_pair[1][0]):
                raise ValueError(
                    "classifier multi-origin v2 acquisition blocks are not temporally ordered"
                )


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
    *,
    sample_splits: Mapping[str, str] | None = None,
    acquisition_block_index: int | None = None,
) -> dict[str, Any]:
    experiment = verified.experiment
    result = {
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
    if sample_splits is not None:
        if acquisition_block_index is None:
            raise ValueError("classifier POC5 acquisition block index is missing")
        result["acquisition_block_index"] = acquisition_block_index
        result["acquisition_block_id"] = f"acquisition-block-{acquisition_block_index + 1:03d}"
        result["sample_splits"] = dict(sorted(sample_splits.items()))
    return result


def _dataset_receipt(
    rows: Sequence[Mapping[str, Any]],
    blocks: Sequence[Mapping[str, Any]],
    *,
    schema_version: int = SCHEMA_VERSION,
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
        "schema_version": schema_version,
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


def _read_json_lines(path: Path, *, schema_version: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid samples.jsonl line {line_number}") from error
        expected_keys = _SAMPLE_KEYS_V2 if schema_version == POC5_SCHEMA_VERSION else _SAMPLE_KEYS
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise ValueError(f"invalid samples.jsonl schema on line {line_number}")
        if value["schema_version"] != schema_version:
            raise ValueError(f"samples.jsonl schema version mismatch on line {line_number}")
        if line != json.dumps(value, sort_keys=True, separators=(",", ":")):
            raise ValueError(f"non-canonical samples.jsonl line {line_number}")
        rows.append(value)
    if not rows:
        raise ValueError("classifier handoff contains no samples")
    return rows


def _validate_dataset_rows(
    root: Path,
    dataset: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    *,
    schema_version: int,
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
    block_splits = _validate_block_records(block_records, schema_version=schema_version)
    result_names = [block["result_name"] for block in block_records]
    if schema_version != POC5_SCHEMA_VERSION and any(
        name in _SCHEMA_V2_RESULT_NAMES for name in result_names
    ):
        raise ValueError("classifier schema-v2 result lineage requires schema version 2")
    _validate_exporter_source(dataset)

    expected_inventory = {"README.md", "dataset.json", "samples.jsonl", "SHA256SUMS"}
    class_counts: Counter[str] = Counter()
    defense_counts: Counter[str] = Counter()
    split_counts: Counter[str] = Counter()
    for row in rows:
        _validate_sample_row(row, block_splits, schema_version=schema_version)
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
    if schema_version == POC5_SCHEMA_VERSION:
        if result_names == list(POC5_RESULT_NAMES):
            _validate_poc5_handoff_protocol(dataset, rows)
        elif result_names == [POC5_REHEARSAL_RESULT_NAME]:
            _validate_poc5_rehearsal_handoff_protocol(dataset, rows)
        elif result_names == list(MULTIORIGIN5_RESULT_NAMES):
            _validate_multiorigin5_handoff_protocol(dataset, rows)
        elif result_names == [MULTIORIGIN5_REHEARSAL_RESULT_NAME]:
            _validate_multiorigin5_rehearsal_handoff_protocol(dataset, rows)
        elif result_names == list(MULTIORIGIN5_V2_RESULT_NAMES):
            _validate_multiorigin5_v2_handoff_protocol(dataset, rows)
        elif result_names == [MULTIORIGIN5_V2_REHEARSAL_RESULT_NAME]:
            _validate_multiorigin5_v2_rehearsal_handoff_protocol(dataset, rows)
        else:
            poc5_names = {*POC5_RESULT_NAMES, POC5_REHEARSAL_RESULT_NAME}
            multiorigin_names = {
                *MULTIORIGIN5_RESULT_NAMES,
                MULTIORIGIN5_REHEARSAL_RESULT_NAME,
            }
            if any(name in poc5_names for name in result_names) and any(
                name in multiorigin_names for name in result_names
            ):
                raise ValueError("classifier handoff cannot mix schema-v2 result lineages")
            multiorigin_v2_names = {
                *MULTIORIGIN5_V2_RESULT_NAMES,
                MULTIORIGIN5_V2_REHEARSAL_RESULT_NAME,
            }
            represented_lineages = sum(
                any(name in lineage for name in result_names)
                for lineage in (poc5_names, multiorigin_names, multiorigin_v2_names)
            )
            if represented_lineages > 1:
                raise ValueError("classifier handoff cannot mix schema-v2 result lineages")
            raise ValueError("classifier schema-v2 handoff result lineage is invalid")


def _validate_poc5_handoff_protocol(
    dataset: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    """Enforce the formal five-domain, undefended-trained POC design."""

    blocks = dataset["blocks"]
    if [block["result_name"] for block in blocks] != list(POC5_RESULT_NAMES):
        raise ValueError("classifier POC5 handoff result lineage is invalid")
    _validate_poc5_temporal_intervals(
        [(block["started_at"], block["completed_at"]) for block in blocks]
    )
    _validate_poc5_execution_sources([block["source"] for block in blocks])
    _validate_poc5_exporter_lineage(dataset, blocks[0]["source"])

    expected_rows: Counter[tuple[Any, ...]] = Counter()
    for result_index in range(len(POC5_RESULT_NAMES)):
        acquisition_block = result_index // 2
        temporal_split = POC5_TEMPORAL_SPLITS[acquisition_block]
        baseline_result = result_index % 2 == 0
        expected_policy = (
            {"undefended": temporal_split}
            if baseline_result
            else {
                "front": "inference",
                "tamaraw": "inference",
                "undefended": temporal_split,
            }
        )
        block = blocks[result_index]
        expected_acquisition_id = f"acquisition-block-{acquisition_block + 1:03d}"
        if (
            block["split"] is not None
            or block["sample_splits"] != expected_policy
            or block["acquisition_block_index"] != acquisition_block
            or block["acquisition_block_id"] != expected_acquisition_id
        ):
            raise ValueError("classifier POC5 handoff sample-split policy is invalid")
        defenses = ("undefended",) if baseline_result else POC5_DEFENSES
        visits = range(20) if baseline_result else range(10)
        for workload_id in POC5_CLASSES:
            for defense in defenses:
                runtime_kind, baseline = POC5_RUNTIME[defense]
                role = "baseline" if baseline else "inference-only"
                for visit in visits:
                    expected_rows[
                        (
                            result_index,
                            f"block-{result_index + 1:03d}",
                            acquisition_block,
                            expected_acquisition_id,
                            workload_id,
                            POC5_CLASS_LABELS[workload_id],
                            defense,
                            role,
                            runtime_kind,
                            baseline,
                            "as-defined",
                            visit,
                            expected_policy[defense],
                        )
                    ] += 1

    actual_rows = Counter(
        (
            row["block_index"],
            row["block_id"],
            row["acquisition_block_index"],
            row["acquisition_block_id"],
            row["workload_id"],
            row["class_label"],
            row["defense"],
            row["defense_role"],
            row["runtime_kind"],
            row["baseline"],
            row["request_policy"],
            row["visit"],
            row["split"],
        )
        for row in rows
    )
    if actual_rows != expected_rows:
        raise ValueError("classifier POC5 handoff is not the exact 2,500-sample protocol")

    for row in rows:
        expected_pair = (
            f"{row['block_id']}/{row['workload_id']}/{row['request_policy']}/"
            f"visit-{row['visit']:03d}"
        )
        if row["paired_visit_id"] != expected_pair:
            raise ValueError("classifier POC5 paired-visit binding is invalid")

    expected_class_counts = {label: 500 for label in sorted(POC5_CLASS_LABELS.values())}
    expected_defense_counts = {"front": 500, "tamaraw": 500, "undefended": 1_500}
    expected_split_counts = {
        "inference": 1_000,
        "test": 150,
        "train": 1_200,
        "validation": 150,
    }
    if (
        dataset["sample_count"] != 2_500
        or dataset["classes"] != sorted(POC5_CLASS_LABELS.values())
        or dataset["counts_by_class"] != expected_class_counts
        or dataset["counts_by_defense"] != expected_defense_counts
        or dataset["counts_by_split"] != expected_split_counts
    ):
        raise ValueError("classifier POC5 aggregate counts are invalid")


def _validate_poc5_rehearsal_handoff_protocol(
    dataset: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    """Validate the separate 30-sample schema-v2 importer gate."""

    blocks = dataset["blocks"]
    policy = {defense: "interface" for defense in POC5_DEFENSES}
    if (
        len(blocks) != 1
        or blocks[0]["result_name"] != POC5_REHEARSAL_RESULT_NAME
        or blocks[0]["split"] != "interface"
        or blocks[0]["sample_splits"] != policy
        or blocks[0]["acquisition_block_index"] != 0
        or blocks[0]["acquisition_block_id"] != "acquisition-block-001"
    ):
        raise ValueError("classifier POC5 rehearsal block contract is invalid")
    _validate_poc5_execution_sources([blocks[0]["source"]])
    _validate_poc5_exporter_lineage(dataset, blocks[0]["source"])

    expected = Counter(
        (
            0,
            "block-001",
            0,
            "acquisition-block-001",
            workload_id,
            POC5_CLASS_LABELS[workload_id],
            defense,
            "baseline" if POC5_RUNTIME[defense][1] else "inference-only",
            POC5_RUNTIME[defense][0],
            POC5_RUNTIME[defense][1],
            "as-defined",
            visit,
            "interface",
        )
        for workload_id in POC5_CLASSES
        for defense in POC5_DEFENSES
        for visit in range(2)
    )
    actual = Counter(
        (
            row["block_index"],
            row["block_id"],
            row["acquisition_block_index"],
            row["acquisition_block_id"],
            row["workload_id"],
            row["class_label"],
            row["defense"],
            row["defense_role"],
            row["runtime_kind"],
            row["baseline"],
            row["request_policy"],
            row["visit"],
            row["split"],
        )
        for row in rows
    )
    if actual != expected:
        raise ValueError("classifier POC5 rehearsal is not the exact 30-sample interface gate")
    for row in rows:
        expected_pair = (
            f"{row['block_id']}/{row['workload_id']}/{row['request_policy']}/"
            f"visit-{row['visit']:03d}"
        )
        if row["paired_visit_id"] != expected_pair:
            raise ValueError("classifier POC5 rehearsal paired-visit binding is invalid")

    expected_class_counts = {label: 6 for label in sorted(POC5_CLASS_LABELS.values())}
    if (
        dataset["sample_count"] != 30
        or dataset["classes"] != sorted(POC5_CLASS_LABELS.values())
        or dataset["counts_by_class"] != expected_class_counts
        or dataset["counts_by_defense"] != {"front": 10, "tamaraw": 10, "undefended": 10}
        or dataset["counts_by_split"] != {"interface": 30}
    ):
        raise ValueError("classifier POC5 rehearsal aggregate counts are invalid")


def _validate_multiorigin5_handoff_protocol(
    dataset: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    """Enforce the formal five-domain fresh multi-origin collection design."""

    blocks = dataset["blocks"]
    if [block["result_name"] for block in blocks] != list(MULTIORIGIN5_RESULT_NAMES):
        raise ValueError("classifier multi-origin handoff result lineage is invalid")
    _validate_multiorigin5_temporal_intervals(
        [(block["started_at"], block["completed_at"]) for block in blocks]
    )
    _validate_multiorigin5_execution_sources([block["source"] for block in blocks])
    _validate_multiorigin5_exporter_lineage(dataset, blocks[0]["source"])

    expected_rows: Counter[tuple[Any, ...]] = Counter()
    for result_index in range(len(MULTIORIGIN5_RESULT_NAMES)):
        acquisition_block = result_index // 2
        temporal_split = MULTIORIGIN5_TEMPORAL_SPLITS[acquisition_block]
        baseline_result = result_index % 2 == 0
        expected_policy = (
            {"undefended": temporal_split}
            if baseline_result
            else {
                "front": "inference",
                "tamaraw": "inference",
                "undefended": temporal_split,
            }
        )
        block = blocks[result_index]
        expected_acquisition_id = f"acquisition-block-{acquisition_block + 1:03d}"
        if (
            block["split"] is not None
            or block["sample_splits"] != expected_policy
            or block["acquisition_block_index"] != acquisition_block
            or block["acquisition_block_id"] != expected_acquisition_id
        ):
            raise ValueError("classifier multi-origin handoff sample-split policy is invalid")
        defenses = ("undefended",) if baseline_result else MULTIORIGIN5_DEFENSES
        visits = range(20) if baseline_result else range(10)
        for workload_id in MULTIORIGIN5_CLASSES:
            for defense in defenses:
                runtime_kind, baseline = MULTIORIGIN5_RUNTIME[defense]
                role = "baseline" if baseline else "inference-only"
                for visit in visits:
                    expected_rows[
                        (
                            result_index,
                            f"block-{result_index + 1:03d}",
                            acquisition_block,
                            expected_acquisition_id,
                            workload_id,
                            MULTIORIGIN5_CLASS_LABELS[workload_id],
                            defense,
                            role,
                            runtime_kind,
                            baseline,
                            "as-defined",
                            visit,
                            expected_policy[defense],
                        )
                    ] += 1

    actual_rows = Counter(
        (
            row["block_index"],
            row["block_id"],
            row["acquisition_block_index"],
            row["acquisition_block_id"],
            row["workload_id"],
            row["class_label"],
            row["defense"],
            row["defense_role"],
            row["runtime_kind"],
            row["baseline"],
            row["request_policy"],
            row["visit"],
            row["split"],
        )
        for row in rows
    )
    if actual_rows != expected_rows:
        raise ValueError("classifier multi-origin handoff is not the exact 2,500-sample protocol")

    for row in rows:
        expected_pair = (
            f"{row['block_id']}/{row['workload_id']}/{row['request_policy']}/"
            f"visit-{row['visit']:03d}"
        )
        if row["paired_visit_id"] != expected_pair:
            raise ValueError("classifier multi-origin paired-visit binding is invalid")

    expected_class_counts = {label: 500 for label in sorted(MULTIORIGIN5_CLASS_LABELS.values())}
    expected_defense_counts = {"front": 500, "tamaraw": 500, "undefended": 1_500}
    expected_split_counts = {
        "inference": 1_000,
        "test": 150,
        "train": 1_200,
        "validation": 150,
    }
    if (
        dataset["sample_count"] != 2_500
        or dataset["classes"] != sorted(MULTIORIGIN5_CLASS_LABELS.values())
        or dataset["counts_by_class"] != expected_class_counts
        or dataset["counts_by_defense"] != expected_defense_counts
        or dataset["counts_by_split"] != expected_split_counts
    ):
        raise ValueError("classifier multi-origin aggregate counts are invalid")


def _validate_multiorigin5_rehearsal_handoff_protocol(
    dataset: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    """Validate the separate fresh 30-sample schema-v2 importer gate."""

    blocks = dataset["blocks"]
    policy = {defense: "interface" for defense in MULTIORIGIN5_DEFENSES}
    if (
        len(blocks) != 1
        or blocks[0]["result_name"] != MULTIORIGIN5_REHEARSAL_RESULT_NAME
        or blocks[0]["split"] != "interface"
        or blocks[0]["sample_splits"] != policy
        or blocks[0]["acquisition_block_index"] != 0
        or blocks[0]["acquisition_block_id"] != "acquisition-block-001"
    ):
        raise ValueError("classifier multi-origin rehearsal block contract is invalid")
    _validate_multiorigin5_execution_sources([blocks[0]["source"]])
    _validate_multiorigin5_exporter_lineage(dataset, blocks[0]["source"])

    expected = Counter(
        (
            0,
            "block-001",
            0,
            "acquisition-block-001",
            workload_id,
            MULTIORIGIN5_CLASS_LABELS[workload_id],
            defense,
            "baseline" if MULTIORIGIN5_RUNTIME[defense][1] else "inference-only",
            MULTIORIGIN5_RUNTIME[defense][0],
            MULTIORIGIN5_RUNTIME[defense][1],
            "as-defined",
            visit,
            "interface",
        )
        for workload_id in MULTIORIGIN5_CLASSES
        for defense in MULTIORIGIN5_DEFENSES
        for visit in range(2)
    )
    actual = Counter(
        (
            row["block_index"],
            row["block_id"],
            row["acquisition_block_index"],
            row["acquisition_block_id"],
            row["workload_id"],
            row["class_label"],
            row["defense"],
            row["defense_role"],
            row["runtime_kind"],
            row["baseline"],
            row["request_policy"],
            row["visit"],
            row["split"],
        )
        for row in rows
    )
    if actual != expected:
        raise ValueError(
            "classifier multi-origin rehearsal is not the exact 30-sample interface gate"
        )
    for row in rows:
        expected_pair = (
            f"{row['block_id']}/{row['workload_id']}/{row['request_policy']}/"
            f"visit-{row['visit']:03d}"
        )
        if row["paired_visit_id"] != expected_pair:
            raise ValueError("classifier multi-origin rehearsal paired-visit binding is invalid")

    expected_class_counts = {label: 6 for label in sorted(MULTIORIGIN5_CLASS_LABELS.values())}
    if (
        dataset["sample_count"] != 30
        or dataset["classes"] != sorted(MULTIORIGIN5_CLASS_LABELS.values())
        or dataset["counts_by_class"] != expected_class_counts
        or dataset["counts_by_defense"] != {"front": 10, "tamaraw": 10, "undefended": 10}
        or dataset["counts_by_split"] != {"interface": 30}
    ):
        raise ValueError("classifier multi-origin rehearsal aggregate counts are invalid")


def _validate_multiorigin5_v2_handoff_protocol(
    dataset: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    """Enforce the formal repaired five-domain multi-origin collection design."""

    blocks = dataset["blocks"]
    if [block["result_name"] for block in blocks] != list(MULTIORIGIN5_V2_RESULT_NAMES):
        raise ValueError("classifier multi-origin v2 handoff result lineage is invalid")
    _validate_multiorigin5_v2_temporal_intervals(
        [(block["started_at"], block["completed_at"]) for block in blocks]
    )
    _validate_multiorigin5_v2_execution_sources([block["source"] for block in blocks])
    _validate_multiorigin5_v2_exporter_lineage(dataset, blocks[0]["source"])

    expected_rows: Counter[tuple[Any, ...]] = Counter()
    for result_index in range(len(MULTIORIGIN5_V2_RESULT_NAMES)):
        acquisition_block = result_index // 2
        temporal_split = MULTIORIGIN5_V2_TEMPORAL_SPLITS[acquisition_block]
        baseline_result = result_index % 2 == 0
        expected_policy = (
            {"undefended": temporal_split}
            if baseline_result
            else {
                "front": "inference",
                "tamaraw": "inference",
                "undefended": temporal_split,
            }
        )
        block = blocks[result_index]
        expected_acquisition_id = f"acquisition-block-{acquisition_block + 1:03d}"
        if (
            block["split"] is not None
            or block["sample_splits"] != expected_policy
            or block["acquisition_block_index"] != acquisition_block
            or block["acquisition_block_id"] != expected_acquisition_id
        ):
            raise ValueError("classifier multi-origin v2 handoff sample-split policy is invalid")
        defenses = ("undefended",) if baseline_result else MULTIORIGIN5_V2_DEFENSES
        visits = range(20) if baseline_result else range(10)
        for workload_id in MULTIORIGIN5_V2_CLASSES:
            for defense in defenses:
                runtime_kind, baseline = MULTIORIGIN5_V2_RUNTIME[defense]
                role = "baseline" if baseline else "inference-only"
                for visit in visits:
                    expected_rows[
                        (
                            result_index,
                            f"block-{result_index + 1:03d}",
                            acquisition_block,
                            expected_acquisition_id,
                            workload_id,
                            MULTIORIGIN5_V2_CLASS_LABELS[workload_id],
                            defense,
                            role,
                            runtime_kind,
                            baseline,
                            "as-defined",
                            visit,
                            expected_policy[defense],
                        )
                    ] += 1

    actual_rows = Counter(
        (
            row["block_index"],
            row["block_id"],
            row["acquisition_block_index"],
            row["acquisition_block_id"],
            row["workload_id"],
            row["class_label"],
            row["defense"],
            row["defense_role"],
            row["runtime_kind"],
            row["baseline"],
            row["request_policy"],
            row["visit"],
            row["split"],
        )
        for row in rows
    )
    if actual_rows != expected_rows:
        raise ValueError(
            "classifier multi-origin v2 handoff is not the exact 2,500-sample protocol"
        )

    for row in rows:
        expected_pair = (
            f"{row['block_id']}/{row['workload_id']}/{row['request_policy']}/"
            f"visit-{row['visit']:03d}"
        )
        if row["paired_visit_id"] != expected_pair:
            raise ValueError("classifier multi-origin v2 paired-visit binding is invalid")

    expected_class_counts = {label: 500 for label in sorted(MULTIORIGIN5_V2_CLASS_LABELS.values())}
    expected_defense_counts = {"front": 500, "tamaraw": 500, "undefended": 1_500}
    expected_split_counts = {
        "inference": 1_000,
        "test": 150,
        "train": 1_200,
        "validation": 150,
    }
    if (
        dataset["sample_count"] != 2_500
        or dataset["classes"] != sorted(MULTIORIGIN5_V2_CLASS_LABELS.values())
        or dataset["counts_by_class"] != expected_class_counts
        or dataset["counts_by_defense"] != expected_defense_counts
        or dataset["counts_by_split"] != expected_split_counts
    ):
        raise ValueError("classifier multi-origin v2 aggregate counts are invalid")


def _validate_multiorigin5_v2_rehearsal_handoff_protocol(
    dataset: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    """Validate the repaired lineage's separate 30-sample schema-v2 importer gate."""

    blocks = dataset["blocks"]
    policy = {defense: "interface" for defense in MULTIORIGIN5_V2_DEFENSES}
    if (
        len(blocks) != 1
        or blocks[0]["result_name"] != MULTIORIGIN5_V2_REHEARSAL_RESULT_NAME
        or blocks[0]["split"] != "interface"
        or blocks[0]["sample_splits"] != policy
        or blocks[0]["acquisition_block_index"] != 0
        or blocks[0]["acquisition_block_id"] != "acquisition-block-001"
    ):
        raise ValueError("classifier multi-origin v2 rehearsal block contract is invalid")
    _validate_multiorigin5_v2_execution_sources([blocks[0]["source"]])
    _validate_multiorigin5_v2_exporter_lineage(dataset, blocks[0]["source"])

    expected = Counter(
        (
            0,
            "block-001",
            0,
            "acquisition-block-001",
            workload_id,
            MULTIORIGIN5_V2_CLASS_LABELS[workload_id],
            defense,
            "baseline" if MULTIORIGIN5_V2_RUNTIME[defense][1] else "inference-only",
            MULTIORIGIN5_V2_RUNTIME[defense][0],
            MULTIORIGIN5_V2_RUNTIME[defense][1],
            "as-defined",
            visit,
            "interface",
        )
        for workload_id in MULTIORIGIN5_V2_CLASSES
        for defense in MULTIORIGIN5_V2_DEFENSES
        for visit in range(2)
    )
    actual = Counter(
        (
            row["block_index"],
            row["block_id"],
            row["acquisition_block_index"],
            row["acquisition_block_id"],
            row["workload_id"],
            row["class_label"],
            row["defense"],
            row["defense_role"],
            row["runtime_kind"],
            row["baseline"],
            row["request_policy"],
            row["visit"],
            row["split"],
        )
        for row in rows
    )
    if actual != expected:
        raise ValueError(
            "classifier multi-origin v2 rehearsal is not the exact 30-sample interface gate"
        )
    for row in rows:
        expected_pair = (
            f"{row['block_id']}/{row['workload_id']}/{row['request_policy']}/"
            f"visit-{row['visit']:03d}"
        )
        if row["paired_visit_id"] != expected_pair:
            raise ValueError("classifier multi-origin v2 rehearsal paired-visit binding is invalid")

    expected_class_counts = {label: 6 for label in sorted(MULTIORIGIN5_V2_CLASS_LABELS.values())}
    if (
        dataset["sample_count"] != 30
        or dataset["classes"] != sorted(MULTIORIGIN5_V2_CLASS_LABELS.values())
        or dataset["counts_by_class"] != expected_class_counts
        or dataset["counts_by_defense"] != {"front": 10, "tamaraw": 10, "undefended": 10}
        or dataset["counts_by_split"] != {"interface": 30}
    ):
        raise ValueError("classifier multi-origin v2 rehearsal aggregate counts are invalid")


def _validate_block_records(
    records: Sequence[Any], *, schema_version: int
) -> dict[int, Mapping[str, str | None]]:
    result: dict[int, Mapping[str, str | None]] = {}
    for expected_index, record in enumerate(records):
        expected_keys = _BLOCK_KEYS_V2 if schema_version == POC5_SCHEMA_VERSION else _BLOCK_KEYS
        if not isinstance(record, Mapping) or set(record) != expected_keys:
            raise ValueError("classifier handoff block receipt schema is invalid")
        index = record["block_index"]
        split = record["split"]
        if type(index) is not int or index != expected_index:
            raise ValueError("classifier handoff block indexes are invalid")
        if record["block_id"] != f"block-{index + 1:03d}":
            raise ValueError("classifier handoff block ID is invalid")
        allowed_splits = POC5_SPLITS if schema_version == POC5_SCHEMA_VERSION else SPLITS
        if split is not None and split not in allowed_splits:
            raise ValueError("classifier handoff block split is invalid")
        if schema_version == POC5_SCHEMA_VERSION:
            sample_splits = record["sample_splits"]
            acquisition_index = record["acquisition_block_index"]
            if (
                type(acquisition_index) is not int
                or acquisition_index != index // 2
                or record["acquisition_block_id"]
                != f"acquisition-block-{acquisition_index + 1:03d}"
                or not isinstance(sample_splits, Mapping)
                or not sample_splits
                or (split is not None and set(sample_splits.values()) != {split})
                or any(
                    not isinstance(defense, str)
                    or not defense
                    or sample_split not in allowed_splits
                    for defense, sample_split in sample_splits.items()
                )
            ):
                raise ValueError("classifier handoff block sample-split policy is invalid")
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
        result[index] = (
            dict(sample_splits) if schema_version == POC5_SCHEMA_VERSION else {"*": split}
        )
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


def _validate_sample_row(
    row: Mapping[str, Any],
    block_splits: Mapping[int, Mapping[str, str | None]],
    *,
    schema_version: int,
) -> None:
    integer_fields = ["block_index", "visit", "seed", "attempts", "packet_count"]
    if schema_version == POC5_SCHEMA_VERSION:
        integer_fields.append("acquisition_block_index")
    if any(type(row[field]) is not int for field in integer_fields):
        raise ValueError("classifier handoff integer field is invalid")
    if row["schema_version"] != schema_version:
        raise ValueError("classifier handoff sample schema version is invalid")
    if schema_version == POC5_SCHEMA_VERSION and (
        row["acquisition_block_index"] != row["block_index"] // 2
        or row["acquisition_block_id"]
        != f"acquisition-block-{row['acquisition_block_index'] + 1:03d}"
    ):
        raise ValueError("classifier handoff sample acquisition-block binding is invalid")
    policy = block_splits.get(row["block_index"])
    if policy is None:
        raise ValueError("classifier handoff sample block binding is invalid")
    expected_split = policy.get("*", policy.get(row["defense"]))
    if row["defense"] not in policy and "*" not in policy:
        raise ValueError("classifier handoff sample defense is absent from its split policy")
    if row["split"] != expected_split:
        raise ValueError("classifier handoff sample block binding is invalid")
    allowed_splits = POC5_SPLITS if schema_version == POC5_SCHEMA_VERSION else SPLITS
    if row["split"] is not None and row["split"] not in allowed_splits:
        raise ValueError("classifier handoff sample split is invalid")
    if type(row["baseline"]) is not bool:
        raise ValueError("classifier handoff baseline field is invalid")
    string_fields = [
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
    ]
    if schema_version == POC5_SCHEMA_VERSION:
        string_fields.append("acquisition_block_id")
    if any(not isinstance(row[field], str) or not row[field] for field in string_fields):
        raise ValueError("classifier handoff string field is invalid")
    if schema_version == SCHEMA_VERSION and row["class_label"] != row["workload_id"]:
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
and hashes. In schema v2, `class_label` is the frozen domain class while
`workload_id` identifies its prepared workload. The per-sample `split` is
authoritative: `inference` samples are evaluation-only and must never enter
classifier training or model selection. `paired_visit_id` groups conditions
from one paired acquisition result for audit and paired analysis. Schema-v2
`acquisition_block_id` groups the adjacent baseline and paired source results
that form one of the ten temporal collection blocks; use it for block-aware
resampling and dependence control.

Neqo controller/event/schedule records are intentionally excluded because they
would disclose defence-internal labels unavailable to a network observer.
Validate every file from this directory with:

    sha256sum -c SHA256SUMS
"""


if __name__ == "__main__":
    main()
