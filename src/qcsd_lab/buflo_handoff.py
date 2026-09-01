"""Create-only handoff protocol for the focused BuFLO/CS-BuFLO study.

This module is intentionally independent of the sealed historical classifier
handoff implementation.  It accepts only verified result roots, copies raw
evidence byte-for-byte, and derives identifier-free shape products solely from
the direct observer capture.
"""

from __future__ import annotations

import csv
import ctypes
import errno
import hashlib
import json
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from .buflo_evaluation import (
    FORMAL_BLOCKS,
    FORMAL_CLASS_BY_WORKLOAD,
    FORMAL_DEFENSES,
    SCHEMA_VERSION,
    load_study_handoff,
    validate_formal_cohort,
)
from .capture import ObserverPacket, extract_trace
from .defenses import defense_from_runtime_identity
from .experiment import (
    resolved_sample_directory,
    validate_accepted_scheduler_runtime_receipt,
)
from .fidelity import (
    ADVERTISEMENT_SCHEDULE_QCSD_FIELDS,
    BUFLO_SCHEDULE_STOP_POLICY,
    BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS,
    BUFLO_SCHEDULE_STOP_V4_KEYS,
    BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS,
    BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
    BUFLO_TERMINAL_SUBCELL_POLICY,
    CS_BUFLO_AUTHOR_RATE_BOUNDARY_COUNTER_SEMANTICS,
    CS_BUFLO_EARLY_TERMINATION_SEMANTICS,
    CS_BUFLO_EARLY_TERMINATION_TRANSLATION_VERSION,
    CS_BUFLO_INCOMING_BOUNDARY_SEPARATION,
    CS_BUFLO_INCOMING_CADENCE_BOUNDARY,
    CS_BUFLO_INCOMING_TERMINAL_BOUNDARY,
    CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS,
    CS_BUFLO_LOCAL_ET_V3_KEYS,
    CS_BUFLO_RATE_BOUNDARY_COUNTER_SEMANTICS,
    CS_BUFLO_RATE_BOUNDARY_TRANSLATION_VERSION,
    CS_BUFLO_STOP_DRAIN_V4_KEYS,
    CS_BUFLO_TERMINATION_STOP_POLICY,
    CONSUMPTION_SCHEDULE_QCSD_FIELDS,
    LEGACY_SCHEDULE_QCSD_FIELDS,
    SCHEDULE_PREFIX_FIELDS,
    SCHEDULE_QCSD_FIELDS,
    _cs_buflo_rate_transition_vector_valid,
    _schedule_realization_metrics_from_path,
    buflo_terminal_diagnostics_valid,
    buflo_terminal_state_valid,
    cs_buflo_local_et_handoff_valid,
    fidelity_eligible,
    new_defense_terminal_receipts_valid,
)
from .manifest import validate_research_preparation
from .orchestrator import (
    FULL_CHAFF_SCOPE,
    RESPONSE_ONLY_CHAFF_SCOPE,
    _redirect_attestation,
    load_campaign,
    plan_campaign,
)
from .util import LAB_ROOT, load_json, require_disjoint_path, sha256_file, source_metadata
from .verification import VerifiedResult, verify_result

ARTIFACT_TYPE = "qcsd-buflo-csbuflo-study-handoff"
PURPOSE = "buflo-csbuflo-focused-evaluation"
FORMAL_RESULT_NAMES = tuple(
    f"buflo-study-v1-formal-{block + 1:02d}-1200" for block in FORMAL_BLOCKS
)
FORMAL_CAMPAIGN_FILES = tuple(
    f"buflo-study-v1-formal-{block + 1:02d}.yml" for block in FORMAL_BLOCKS
)
_FORMAL_CAMPAIGN_ROOT = (LAB_ROOT / "config/campaigns").resolve()
_FORMAL_COHORT_INPUT_ROOT = (LAB_ROOT / "artifacts/buflo-study/cohort-inputs").resolve()
CLASS_LABELS = FORMAL_CLASS_BY_WORKLOAD

CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_PORT = 49_152
SERVER_PORT = 443
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
_PCAP_MAGIC_NS = 0xA1B23C4D
_PCAP_GLOBAL = struct.Struct("<IHHIIII")
_PCAP_RECORD = struct.Struct("<IIII")
_MINIMUM_FRAME_BYTES = 14 + 20 + 8
_BUFLO_EXACT_REALIZATION_WINDOW_US = 5_000
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_CONTROLLER_ACTION_REDUCTION_LIMIT_US = 10_000
_SOURCE_KEYS = frozenset(
    {
        "image_digest",
        "lab_commit",
        "lab_dirty",
        "lab_patch_sha256",
        "neqo_commit",
        "neqo_pinned_commit",
        "neqo_dirty",
        "neqo_patch_sha256",
    }
)
_ROW_KEYS = frozenset(
    {
        "schema_version",
        "sample_id",
        "class_label",
        "workload_id",
        "defense",
        "runtime_kind",
        "baseline",
        "request_policy",
        "visit",
        "seed",
        "attempts",
        "acquisition_block_index",
        "acquisition_block_id",
        "split",
        "paired_visit_id",
        "source_result",
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
        "performance",
        "input_bindings",
    }
)
_RUNNER_DIAGNOSTIC_ROW_KEYS = frozenset(
    {
        "application_workload_path",
        "application_workload_sha256",
        "runner_schedule_path",
        "runner_schedule_sha256",
        "runner_events_path",
        "runner_events_sha256",
        "runner_packets_path",
        "runner_packets_sha256",
        "algorithm_diagnostics",
    }
)
_LEGACY_RUNNER_DIAGNOSTIC_ROW_KEYS = _RUNNER_DIAGNOSTIC_ROW_KEYS - {
    "application_workload_path",
    "application_workload_sha256",
}
_PACKET_PREFIX_FIELDS = (
    "direction",
    "monotonic_us",
    "connection",
    "observed_udp_length",
    "scheduled_target",
    "satisfaction",
    "slot_id",
)
_EVENT_PREFIX_FIELDS = (
    "monotonic_us",
    "connection",
    "event",
    "outcome",
    "details",
)
_DATASET_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "purpose",
        "formal",
        "paper_equivalent",
        "implementation_scope",
        "result_names",
        "blocks",
        "sample_count",
        "classes",
        "defenses",
        "counts_by_defense",
        "counts_by_split",
        "observation",
        "execution_source",
        "exporter_source",
    }
)
_BLOCK_KEYS = frozenset(
    {
        "acquisition_block_index",
        "acquisition_block_id",
        "split",
        "result_name",
        "result_root",
        "result_evidence_sha256",
        "authoritative_files",
        "campaign_path",
        "campaign_sha256",
        "configuration",
        "configuration_sha256",
    }
)
_FORMAL_BLOCK_KEYS = _BLOCK_KEYS | {
    "started_at",
    "completed_at",
    "elapsed_seconds",
}
_FORMAL_DATASET_KEYS = _DATASET_KEYS | {"temporal_acquisition"}
_FORMAL_DYNAMIC_CONFIGURATION_KEYS = {
    "study_environment_sha256",
    "capture_admission_sha256",
    "formal_cohort_sha256",
}
_INPUT_BINDING_KEYS = frozenset(
    {
        "campaign_sha256",
        "application_workload_sha256",
        "runtime_workload_sha256",
        "chaff_qualification_sha256",
        "chaff_manifest_sha256",
        "defense_parameters_sha256",
        "defense_parameters_provenance_sha256",
        "max_response_bytes",
        "max_udp_payload_size",
    }
)

_SEALED_SAMPLE_COPY_BINDINGS = (
    ("raw_pcapng_path", "raw_pcapng_sha256", "capture.pcapng"),
    ("raw_run_path", "raw_run_sha256", "neqo/run.json"),
    ("runner_schedule_path", "runner_schedule_sha256", "neqo/schedule.csv"),
    ("runner_events_path", "runner_events_sha256", "neqo/events.csv"),
    ("runner_packets_path", "runner_packets_sha256", "neqo/packets.csv"),
)


def export_study_handoff(
    result_roots: Sequence[Path],
    destination: Path,
    *,
    formal: bool,
) -> Path:
    """Create and validate one immutable focused-study handoff."""

    roots = tuple(Path(root).resolve() for root in result_roots)
    if not roots or len(roots) != len(set(roots)):
        raise ValueError("study handoff requires unique result roots")
    verified = tuple(verify_result(root) for root in roots)
    _validate_source_results(verified, formal=formal)
    destination = require_disjoint_path(
        destination,
        (*roots, LAB_ROOT / "handoffs/classifier-multiorigin5-v2"),
        label="study handoff destination",
    )
    parent = destination.parent.resolve()
    if destination.parent.resolve() != parent or parent.is_symlink() or not parent.is_dir():
        raise ValueError("study handoff destination parent is invalid")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"study handoff destination already exists: {destination}")

    candidate = Path(tempfile.mkdtemp(prefix=f".{destination.name}.qcsd-study-", dir=parent))
    try:
        for directory in ("raw", "stripped", "traces", "diagnostics", "inputs"):
            (candidate / directory).mkdir()
        rows: list[dict[str, Any]] = []
        blocks: list[dict[str, Any]] = []
        seen: set[str] = set()
        for block_index, receipt in enumerate(verified):
            split = _split_for_block(block_index)
            blocks.append(_block_receipt(receipt, block_index, split, formal=formal))
            for sample in receipt.experiment["samples"]:
                sample_id = str(sample["sample_id"])
                if sample_id in seen:
                    raise ValueError("study handoff sample IDs are not unique")
                seen.add(sample_id)
                sample_root = resolved_sample_directory(
                    receipt.root, sample, require_directory=True
                )
                raw_pcapng = sample_root / "capture.pcapng"
                raw_run = sample_root / "neqo/run.json"
                raw_pcapng_relative = f"raw/{sample_id}.pcapng"
                raw_pcap_relative = f"raw/{sample_id}.pcap"
                raw_run_relative = f"raw/{sample_id}.run.json"
                shape_relative = f"stripped/{sample_id}.pcap"
                trace_relative = f"traces/{sample_id}.csv"
                schedule_relative = f"diagnostics/{sample_id}.schedule.csv"
                events_relative = f"diagnostics/{sample_id}.events.csv"
                packets_relative = f"diagnostics/{sample_id}.packets.csv"
                workload_relative = (
                    f"inputs/acquisition-block-{block_index + 1:03d}/{sample['workload_id']}.json"
                )
                _copy_sealed_file(receipt, raw_pcapng, candidate / raw_pcapng_relative)
                _copy_sealed_file(receipt, raw_run, candidate / raw_run_relative)
                _copy_sealed_file(
                    receipt,
                    sample_root / "neqo/schedule.csv",
                    candidate / schedule_relative,
                )
                _copy_sealed_file(
                    receipt,
                    sample_root / "neqo/events.csv",
                    candidate / events_relative,
                )
                _copy_sealed_file(
                    receipt,
                    sample_root / "neqo/packets.csv",
                    candidate / packets_relative,
                )
                workload_destination = candidate / workload_relative
                if not workload_destination.exists():
                    workload_destination.parent.mkdir(parents=True, exist_ok=True)
                    _copy_sealed_file(
                        receipt,
                        receipt.root / f"inputs/workloads/{sample['workload_id']}.json",
                        workload_destination,
                    )
                run = load_json(candidate / raw_run_relative)
                input_bindings = _sample_input_bindings(receipt.experiment["configuration"], sample)
                _validate_run_sample_binding(run, sample, input_bindings)
                endpoints = run.get("endpoints") if isinstance(run, Mapping) else None
                if not isinstance(endpoints, list) or not endpoints:
                    raise ValueError("study handoff raw run has no endpoint list")
                trace = extract_trace(candidate / raw_pcapng_relative, endpoints)
                if not trace:
                    raise ValueError("study handoff observer trace is empty")
                _write_classic_raw_pcap(
                    candidate / raw_pcapng_relative, candidate / raw_pcap_relative
                )
                _write_shape_only_pcap(trace, candidate / shape_relative)
                _write_trace_csv(trace, candidate / trace_relative)

                workload_id = str(sample["workload_id"])
                defense = str(sample["defense"])
                algorithm_diagnostics = _algorithm_diagnostics(
                    run,
                    defense=defense,
                    runtime_kind=str(sample["runtime_kind"]),
                    schedule_path=candidate / schedule_relative,
                    events_path=candidate / events_relative,
                    packets_path=candidate / packets_relative,
                )
                row = {
                    "schema_version": SCHEMA_VERSION,
                    "sample_id": sample_id,
                    "class_label": CLASS_LABELS.get(workload_id, workload_id),
                    "workload_id": workload_id,
                    "defense": defense,
                    "runtime_kind": sample["runtime_kind"],
                    "baseline": sample["baseline"],
                    "request_policy": sample["request_policy"],
                    "visit": sample["visit"],
                    "seed": sample["seed"],
                    "attempts": sample["attempts"],
                    "acquisition_block_index": block_index,
                    "acquisition_block_id": f"acquisition-block-{block_index + 1:03d}",
                    "split": split,
                    "paired_visit_id": (
                        f"block-{block_index + 1:03d}/{workload_id}/"
                        f"{sample['request_policy']}/visit-{int(sample['visit']):03d}"
                    ),
                    "source_result": receipt.experiment["name"],
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
                    "runner_schedule_path": schedule_relative,
                    "runner_schedule_sha256": sha256_file(candidate / schedule_relative),
                    "runner_events_path": events_relative,
                    "runner_events_sha256": sha256_file(candidate / events_relative),
                    "runner_packets_path": packets_relative,
                    "runner_packets_sha256": sha256_file(candidate / packets_relative),
                    "application_workload_path": workload_relative,
                    "application_workload_sha256": sha256_file(workload_destination),
                    "algorithm_diagnostics": algorithm_diagnostics,
                    "packet_count": len(trace),
                    "performance": _performance_metadata(run, trace),
                    "input_bindings": input_bindings,
                }
                rows.append(row)

        dataset = _dataset_receipt(
            rows,
            blocks,
            formal=formal,
            execution_source=verified[0].experiment["source"],
        )
        _write_json(candidate / "dataset.json", dataset)
        _write_json_lines(candidate / "samples.jsonl", rows)
        _write_text(candidate / "README.md", _readme())
        _write_checksums(candidate)
        validate_study_handoff(candidate, formal=formal, deep=True)
        _fsync_tree(candidate)
        _rename_noreplace(candidate, destination)
        _fsync_directory(parent)
        return validate_study_handoff(destination, formal=formal, deep=True)
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)


def validate_study_handoff(path: Path, *, formal: bool, deep: bool = True) -> Path:
    """Verify closed inventory, sample bindings, and optional raw-PCAP replay."""

    root = path.resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("study handoff is not a regular directory")
    top_level = {item.name for item in root.iterdir()}
    historical_top_level = {
        "README.md",
        "dataset.json",
        "samples.jsonl",
        "SHA256SUMS",
        "raw",
        "stripped",
        "traces",
    }
    legacy_detailed_top_level = historical_top_level | {"diagnostics"}
    detailed_top_level = legacy_detailed_top_level | {"inputs"}
    if top_level not in {
        frozenset(historical_top_level),
        frozenset(legacy_detailed_top_level),
        frozenset(detailed_top_level),
    }:
        raise ValueError("study handoff top-level inventory is invalid")
    checksums = _read_checksums(root / "SHA256SUMS")
    actual = _regular_tree_files(root, exclude={"SHA256SUMS"})
    if set(checksums) != set(actual):
        raise ValueError("study handoff checksum inventory is not closed")
    for relative, digest in checksums.items():
        if sha256_file(actual[relative]) != digest:
            raise ValueError(f"study handoff digest mismatch: {relative}")

    dataset = load_json(root / "dataset.json")
    rows = _read_json_lines(root / "samples.jsonl")
    detailed, legacy_detailed = _validate_handoff_rows(root, rows, formal=formal)
    if ("diagnostics" in top_level) is not detailed or (
        ("inputs" in top_level) is not (detailed and not legacy_detailed)
    ):
        raise ValueError("study handoff diagnostic inventory declaration is inconsistent")
    _validate_dataset(dataset, rows, formal=formal)
    if formal:
        _validate_formal_source_bindings(
            root,
            dataset,
            rows,
            handoff_checksums=checksums,
        )
    loaded = load_study_handoff(root)
    row_by_id = {row["sample_id"]: row for row in rows}
    if any(row_by_id[sample.sample_id]["packet_count"] != len(sample.trace) for sample in loaded):
        raise ValueError("study handoff packet count differs from its trace")
    if formal:
        validate_formal_cohort(loaded, require_performance=True)
        if dataset.get("formal") is not True or dataset.get("result_names") != list(
            FORMAL_RESULT_NAMES
        ):
            raise ValueError("formal study handoff lineage is invalid")
    elif dataset.get("formal") is not False:
        raise ValueError("non-formal study handoff declaration is invalid")
    expected_counts = dict(sorted(Counter(sample.defense for sample in loaded).items()))
    if dataset.get("counts_by_defense") != expected_counts:
        raise ValueError("study handoff defense counts mismatch")

    if deep:
        for sample in loaded:
            row = row_by_id[sample.sample_id]
            raw_run = load_json(root / row["raw_run_path"])
            _validate_run_sample_binding(raw_run, row, row["input_bindings"])
            endpoints = raw_run.get("endpoints") if isinstance(raw_run, Mapping) else None
            if not isinstance(endpoints, list) or not endpoints:
                raise ValueError("study handoff raw run endpoint binding is invalid")
            raw_trace = extract_trace(root / row["raw_pcapng_path"], endpoints)
            classic_trace = extract_trace(root / row["raw_pcap_path"], endpoints)
            expected = tuple(
                (packet.relative_time_ns, packet.direction, packet.length_bytes)
                for packet in sample.trace
            )
            if _trace_identity(raw_trace) != expected or _trace_identity(classic_trace) != expected:
                raise ValueError("study handoff raw capture replay differs from its trace")
            if _read_shape_only_pcap(root / row["shape_pcap_path"]) != expected:
                raise ValueError("study handoff stripped capture differs from its trace")
    return root


def _validate_formal_source_bindings(
    handoff_root: Path,
    dataset: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    *,
    handoff_checksums: Mapping[str, str],
) -> None:
    """Bind every formal handoff copy to its still-valid authoritative seal.

    ``SHA256SUMS`` closes the handoff itself, but it is not an authentication
    boundary: a substituted artifact and a rewritten local inventory would be
    internally consistent.  Formal validation therefore re-verifies each
    recorded result root and requires all byte-for-byte copies to retain the
    digest recorded by that result's ``evidence.sha256``.
    """

    blocks = dataset.get("blocks")
    if not isinstance(blocks, list) or len(blocks) != len(FORMAL_BLOCKS):
        raise ValueError("formal handoff source block inventory is invalid")

    receipts: list[VerifiedResult] = []
    for index, block in enumerate(blocks):
        if not isinstance(block, Mapping):
            raise ValueError("formal handoff source block is invalid")
        root_value = block.get("result_root")
        if not isinstance(root_value, str):
            raise ValueError("formal handoff source result root is invalid")
        recorded_root = Path(root_value)
        try:
            source_root = recorded_root.resolve(strict=True)
        except (FileNotFoundError, OSError) as error:
            raise ValueError("formal handoff source result root is unavailable") from error
        if (
            not recorded_root.is_absolute()
            or recorded_root.is_symlink()
            or root_value != str(source_root)
            or not source_root.is_dir()
        ):
            raise ValueError("formal handoff source result root is not canonical")
        evidence = source_root / "evidence.sha256"
        if evidence.is_symlink() or not evidence.is_file():
            raise ValueError("formal handoff source result has no regular evidence seal")

        receipt = verify_result(source_root)
        experiment = receipt.experiment
        if (
            receipt.root != source_root
            or experiment.get("name") != block.get("result_name")
            or experiment.get("configuration") != block.get("configuration")
            or experiment.get("source") != dataset.get("execution_source")
            or sha256_file(evidence) != block.get("result_evidence_sha256")
            or len(receipt.checksums) != block.get("authoritative_files")
            or experiment.get("started_at") != block.get("started_at")
            or experiment.get("completed_at") != block.get("completed_at")
            or _elapsed_seconds(experiment) != block.get("elapsed_seconds")
            or index != block.get("acquisition_block_index")
        ):
            raise ValueError("formal handoff source result seal or lineage differs")
        receipts.append(receipt)

    # Reapply the formal source-result contract to the newly verified receipts,
    # rather than trusting the export-time validation that created the handoff.
    _validate_source_results(tuple(receipts), formal=True)

    rows_by_block: dict[int, list[Mapping[str, Any]]] = {
        index: [] for index in range(len(receipts))
    }
    for row in rows:
        block_index = row.get("acquisition_block_index")
        if type(block_index) is not int or block_index not in rows_by_block:
            raise ValueError("formal handoff sample has no authoritative source block")
        rows_by_block[block_index].append(row)

    for block_index, receipt in enumerate(receipts):
        source_samples = receipt.experiment.get("samples")
        if not isinstance(source_samples, list):
            raise ValueError("formal handoff source result has no sample inventory")
        source_by_id: dict[str, Mapping[str, Any]] = {}
        for source_sample in source_samples:
            sample_id = (
                source_sample.get("sample_id") if isinstance(source_sample, Mapping) else None
            )
            if not isinstance(sample_id, str) or sample_id in source_by_id:
                raise ValueError("formal handoff source sample identity is invalid")
            source_by_id[sample_id] = source_sample

        block_rows = rows_by_block[block_index]
        row_ids = [row.get("sample_id") for row in block_rows]
        if (
            any(not isinstance(sample_id, str) for sample_id in row_ids)
            or len(row_ids) != len(set(row_ids))
            or set(row_ids) != set(source_by_id)
            or set(row_ids) != set(receipt.accepted_samples)
        ):
            raise ValueError("formal handoff sample inventory differs from its sealed result")

        for row in block_rows:
            sample_id = str(row["sample_id"])
            source_sample = source_by_id[sample_id]
            identity_bindings = (
                ("workload_id", "workload_id"),
                ("request_policy", "request_policy"),
                ("visit", "visit"),
                ("defense", "defense"),
                ("runtime_kind", "runtime_kind"),
                ("baseline", "baseline"),
                ("seed", "seed"),
                ("attempts", "attempts"),
                ("source_sample_path", "path"),
            )
            if any(
                row.get(row_key) != source_sample.get(source_key)
                for row_key, source_key in identity_bindings
            ):
                raise ValueError("formal handoff sample identity differs from its sealed result")

            source_sample_root = resolved_sample_directory(
                receipt.root,
                source_sample,
                require_directory=True,
            )
            source_relative = str(row["source_sample_path"])
            if source_sample_root.relative_to(receipt.root).as_posix() != source_relative:
                raise ValueError("formal handoff source sample path is not canonical")
            accepted_hashes = receipt.accepted_samples[sample_id]
            for path_key, digest_key, source_suffix in _SEALED_SAMPLE_COPY_BINDINGS:
                _validate_sealed_source_copy(
                    handoff_root,
                    row,
                    path_key=path_key,
                    digest_key=digest_key,
                    source_path=source_sample_root / source_suffix,
                    source_relative=f"{source_relative}/{source_suffix}",
                    receipt=receipt,
                    accepted_hashes=accepted_hashes,
                    handoff_checksums=handoff_checksums,
                )

            workload_id = str(row["workload_id"])
            workload_relative = f"inputs/workloads/{workload_id}.json"
            _validate_sealed_source_copy(
                handoff_root,
                row,
                path_key="application_workload_path",
                digest_key="application_workload_sha256",
                source_path=receipt.root / workload_relative,
                source_relative=workload_relative,
                receipt=receipt,
                accepted_hashes=None,
                handoff_checksums=handoff_checksums,
            )


def _validate_sealed_source_copy(
    handoff_root: Path,
    row: Mapping[str, Any],
    *,
    path_key: str,
    digest_key: str,
    source_path: Path,
    source_relative: str,
    receipt: VerifiedResult,
    accepted_hashes: Mapping[str, str] | None,
    handoff_checksums: Mapping[str, str],
) -> None:
    local_relative = row.get(path_key)
    row_digest = row.get(digest_key)
    seal_digest = receipt.checksums.get(source_relative)
    if not isinstance(local_relative, str) or seal_digest is None:
        raise ValueError("formal handoff copy is absent from its source evidence seal")
    if accepted_hashes is not None and accepted_hashes.get(source_relative) != seal_digest:
        raise ValueError("formal handoff copy differs from accepted-sample evidence")

    local_candidate = handoff_root / local_relative
    local_path = local_candidate.resolve()
    if (
        not local_path.is_relative_to(handoff_root)
        or local_candidate.is_symlink()
        or not local_path.is_file()
        or source_path.is_symlink()
        or not source_path.is_file()
        or row_digest != seal_digest
        or handoff_checksums.get(local_relative) != seal_digest
        or sha256_file(local_path) != seal_digest
        or sha256_file(source_path) != seal_digest
    ):
        raise ValueError("formal handoff copy differs from its sealed source artifact")


def _sample_input_bindings(
    configuration: Any,
    sample: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(configuration, Mapping):
        raise ValueError("study handoff source configuration is invalid")
    workloads = configuration.get("workloads")
    defenses = configuration.get("defenses")
    limits = configuration.get("limits")
    if (
        not isinstance(workloads, list)
        or not isinstance(defenses, list)
        or not isinstance(limits, Mapping)
    ):
        raise ValueError("study handoff source configuration is incomplete")
    workload_matches = [
        value
        for value in workloads
        if isinstance(value, Mapping) and value.get("id") == sample.get("workload_id")
    ]
    defense_matches = [
        value
        for value in defenses
        if isinstance(value, Mapping) and value.get("name") == sample.get("defense")
    ]
    if len(workload_matches) != 1 or len(defense_matches) != 1:
        raise ValueError("study handoff sample is absent from its source configuration")
    workload = workload_matches[0]
    defense = defense_matches[0]
    baseline = sample.get("baseline")
    if type(baseline) is not bool or defense.get("baseline") is not baseline:
        raise ValueError("study handoff sample baseline differs from its source configuration")
    application_sha256 = workload.get("sha256")
    runtime_sha256 = workload.get("runtime_manifest_sha256", application_sha256)
    chaff_qualification_sha256 = workload.get("chaff_qualification_sha256")
    chaff_manifest_sha256 = workload.get("chaff_manifest_sha256")
    parameters_sha256 = defense.get("parameters_sha256", defense.get("schedule_sha256"))
    provenance_sha256 = defense.get("provenance_sha256")
    bindings = {
        "campaign_sha256": configuration.get("campaign_sha256"),
        "application_workload_sha256": application_sha256,
        "runtime_workload_sha256": runtime_sha256,
        "chaff_qualification_sha256": (None if baseline else chaff_qualification_sha256),
        "chaff_manifest_sha256": None if baseline else chaff_manifest_sha256,
        "defense_parameters_sha256": parameters_sha256,
        "defense_parameters_provenance_sha256": provenance_sha256,
        "max_response_bytes": limits.get("max_response_bytes"),
        "max_udp_payload_size": 1_200,
    }
    _validate_input_bindings(
        bindings,
        baseline=baseline,
        runtime_kind=str(defense.get("kind")),
    )
    return bindings


def _validate_input_bindings(
    value: Any, *, baseline: bool, runtime_kind: str | None = None
) -> None:
    if not isinstance(value, Mapping) or set(value) != _INPUT_BINDING_KEYS:
        raise ValueError("study handoff sample input binding schema is invalid")
    required_digests = (
        "campaign_sha256",
        "application_workload_sha256",
        "runtime_workload_sha256",
    )
    if any(_DIGEST.fullmatch(str(value.get(key))) is None for key in required_digests):
        raise ValueError("study handoff sample input digest is invalid")
    optional_digests = (
        "chaff_qualification_sha256",
        "chaff_manifest_sha256",
        "defense_parameters_sha256",
        "defense_parameters_provenance_sha256",
    )
    if any(
        item is not None and _DIGEST.fullmatch(str(item)) is None
        for item in (value.get(key) for key in optional_digests)
    ):
        raise ValueError("study handoff optional sample input digest is invalid")
    if (
        type(value.get("max_response_bytes")) is not int
        or value["max_response_bytes"] <= 0
        or value.get("max_udp_payload_size") != 1_200
    ):
        raise ValueError("study handoff sample limit binding is invalid")
    if baseline:
        if any(
            value.get(key) is not None
            for key in ("chaff_qualification_sha256", "chaff_manifest_sha256")
        ):
            raise ValueError("study handoff baseline binds unexpected chaff inputs")
        if value.get("defense_parameters_sha256") is not None:
            raise ValueError("study handoff baseline binds unexpected defense parameters")
    else:
        required = (
            "chaff_qualification_sha256",
            "chaff_manifest_sha256",
            "defense_parameters_sha256",
        )
        if any(value.get(key) is None for key in required):
            raise ValueError("study handoff defended sample input binding is incomplete")
        provenance = value.get("defense_parameters_provenance_sha256")
        if runtime_kind == "static":
            if provenance is not None:
                raise ValueError("study handoff static schedule has unexpected provenance")
        elif provenance is None:
            raise ValueError("study handoff defended sample provenance binding is incomplete")


def _validate_run_sample_binding(
    run: Any,
    sample: Mapping[str, Any],
    input_bindings: Any,
) -> None:
    baseline = sample.get("baseline")
    if type(baseline) is not bool:
        raise ValueError("study handoff sample baseline declaration is invalid")
    _validate_input_bindings(
        input_bindings,
        baseline=baseline,
        runtime_kind=str(sample.get("runtime_kind")),
    )
    resolved = run.get("resolved_configuration") if isinstance(run, Mapping) else None
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    parameter = run.get("defense_parameters") if isinstance(run, Mapping) else None
    expected_parameter = input_bindings["defense_parameters_sha256"]
    if (
        not isinstance(run, Mapping)
        or run.get("completion_status") != "complete"
        or run.get("error") is not None
        or run.get("error_class") is not None
        or run.get("seed") != sample.get("seed")
        or run.get("request_policy") != sample.get("request_policy")
        or run.get("workload_hash_sha256") != input_bindings["runtime_workload_sha256"]
        or run.get("max_response_bytes") != input_bindings["max_response_bytes"]
        or not isinstance(defense, Mapping)
        or defense.get("kind") != sample.get("runtime_kind")
        or resolved.get("max_udp_payload_size") != input_bindings["max_udp_payload_size"]
    ):
        raise ValueError("study handoff run is not bound to its accepted sample")
    if baseline:
        if (
            run.get("application_workload_source_hash_sha256") is not None
            or run.get("chaff_manifest_hash_sha256") is not None
            or parameter is not None
        ):
            raise ValueError("study handoff baseline run binds unexpected defended inputs")
    elif (
        run.get("application_workload_source_hash_sha256")
        != input_bindings["application_workload_sha256"]
        or run.get("chaff_manifest_hash_sha256") != input_bindings["chaff_manifest_sha256"]
        or not isinstance(parameter, Mapping)
        or parameter.get("kind") != sample.get("runtime_kind")
        or parameter.get("sha256") != expected_parameter
    ):
        raise ValueError("study handoff defended run input binding is invalid")


def _validate_handoff_sample_correctness(
    row: Mapping[str, Any],
    *,
    run: Mapping[str, Any],
    workload_path: Path,
    schedule_path: Path,
    formal: bool,
) -> None:
    workload = load_json(workload_path)
    workload_id = str(row["workload_id"])
    if formal:
        validate_research_preparation(workload, workload_id=workload_id)
    preparation = workload.get("preparation") if isinstance(workload, Mapping) else None
    expected_responses = (
        preparation.get("expected_responses") if isinstance(preparation, Mapping) else None
    )
    response_match = True
    if isinstance(expected_responses, list):
        expected = sorted(
            (
                response.get("resource_id"),
                response.get("status"),
                response.get("bytes"),
                response.get("body_sha256"),
                "succeeded",
            )
            for response in expected_responses
            if isinstance(response, Mapping)
        )
        responses = run.get("responses")
        if not isinstance(responses, list):
            raise ValueError("study handoff run has no application response receipts")
        observed = sorted(
            (
                response.get("resource_id"),
                response.get("status"),
                response.get("bytes"),
                response.get("body_sha256"),
                response.get("outcome"),
            )
            for response in responses
            if isinstance(response, Mapping)
            and response.get("complete") is True
            and not (type(response.get("status")) is int and 300 <= response["status"] < 400)
        )
        response_match = len(observed) == len(responses) and observed == expected
    elif formal:
        raise ValueError("formal study handoff workload has no prepared response identity")

    runtime_kind = str(row["runtime_kind"])
    diagnostics = run.get("defense_diagnostics")
    if not isinstance(diagnostics, dict):
        diagnostics = {}
    schedule = _schedule_realization_metrics_from_path(schedule_path)
    defense = defense_from_runtime_identity(str(row["defense"]), runtime_kind)
    eligible = fidelity_eligible(
        defense,
        diagnostics,
        sample_eligible=response_match,
        missed_events=schedule.get("missed_events"),
        outgoing_size_mismatches=schedule.get("outgoing_size_mismatch_events"),
        schedule_metrics=schedule,
    )
    if runtime_kind in {"buflo", "cs_buflo"} and not new_defense_terminal_receipts_valid(
        run,
        runtime_kind,
        require_application_complete=True,
        require_current_schema=formal,
    ):
        eligible = False
    if not response_match or not eligible:
        raise ValueError(
            "study handoff independently recomputed response/fidelity eligibility failed"
        )


def _expected_formal_configuration(campaign_path: Path) -> tuple[Any, dict[str, Any]]:
    """Reconstruct the exact immutable configuration materialized by the runner."""

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
            if (
                workload.runtime_sha256 is None
                or workload.chaff_qualification_sha256 is None
                or workload.chaff_manifest_sha256 is None
                or workload.chaff_qualification_scope
                not in {RESPONSE_ONLY_CHAFF_SCOPE, FULL_CHAFF_SCOPE}
            ):
                raise ValueError("formal workload chaff binding is incomplete")
            record.update(
                {
                    "chaff_qualification": (f"inputs/chaff-qualifications/{workload.id}.json"),
                    "chaff_qualification_sha256": (workload.chaff_qualification_sha256),
                    "chaff_manifest": f"inputs/chaff-manifests/{workload.id}.json",
                    "chaff_manifest_sha256": workload.chaff_manifest_sha256,
                    "runtime_manifest": f"inputs/runtime-workloads/{workload.id}.json",
                    "runtime_manifest_sha256": workload.runtime_sha256,
                }
            )
            if workload.chaff_qualification_scope == RESPONSE_ONLY_CHAFF_SCOPE:
                record["chaff_qualification_scope"] = RESPONSE_ONLY_CHAFF_SCOPE
            else:
                if workload.chaff_prefix_spec_sha256 is None:
                    raise ValueError("formal workload chaff prefix binding is incomplete")
                record.update(
                    {
                        "chaff_prefix_spec": (f"inputs/chaff-prefix-specs/{workload.id}.json"),
                        "chaff_prefix_spec_sha256": workload.chaff_prefix_spec_sha256,
                    }
                )
        workload_records.append(record)

    defense_records: list[dict[str, Any]] = []
    for defense in campaign.defenses:
        record = {
            "name": defense.name,
            "kind": defense.kind,
            "baseline": defense.baseline,
        }
        if defense.schedule_path is not None:
            record.update(
                {
                    "schedule": (f"inputs/defense-parameters/{defense.name}/schedule.csv"),
                    "schedule_sha256": defense.schedule_sha256,
                    "mode": defense.mode,
                }
            )
        if defense.parameters_path is not None:
            if (
                defense.parameters_sha256 is None
                or defense.parameters_provenance_sha256 is None
                or defense.parameters_input_policy is None
            ):
                raise ValueError("formal defense parameter binding is incomplete")
            record.update(
                {
                    "parameters": (f"inputs/defense-parameters/{defense.name}/parameters.json"),
                    "parameters_sha256": defense.parameters_sha256,
                    "provenance": (f"inputs/defense-parameters/{defense.name}/provenance.json"),
                    "provenance_sha256": defense.parameters_provenance_sha256,
                    "input_policy": defense.parameters_input_policy,
                }
            )
        defense_records.append(record)

    expected: dict[str, Any] = {
        "campaign_sha256": sha256_file(campaign_path),
        "profile": campaign.profile,
        "request_policies": list(campaign.request_policies),
        "workloads": workload_records,
        "defenses": defense_records,
        "limits": campaign.limits.as_dict(),
    }
    if campaign.chaff_qualification_set is not None:
        expected["chaff_qualification_set"] = campaign.chaff_qualification_set
    if campaign.defense_order_scheme != "seeded-shuffle":
        expected["defense_order"] = {
            "scheme": campaign.defense_order_scheme,
            "block": campaign.defense_order_block,
        }
    return campaign, expected


def _validate_formal_result_admission(
    result_root: Path,
    campaign_path: Path,
    configuration: Mapping[str, Any],
    *,
    expected_source: Mapping[str, Any],
) -> None:
    from .buflo_study import (
        validate_capture_admission,
        validate_formal_cohort_manifest,
        validate_study_environment_receipt,
    )

    result_root = result_root.resolve()
    inputs = result_root / "inputs"
    environment_path = inputs / "study-environment.json"
    admission_path = inputs / "capture-admission.json"
    cohort_path = inputs / "formal-cohort.json"
    expected_files = {
        "study_environment_sha256": environment_path,
        "capture_admission_sha256": admission_path,
        "formal_cohort_sha256": cohort_path,
    }
    for key, path in expected_files.items():
        if path.is_symlink() or not path.is_file() or configuration.get(key) != sha256_file(path):
            raise ValueError(f"formal result does not bind its frozen {key}")
    validate_study_environment_receipt(
        load_json(environment_path),
        expected_image_digest=expected_source["image_digest"],
    )
    admission = validate_capture_admission(admission_path)
    cohort = validate_formal_cohort_manifest(cohort_path)
    if (
        admission.get("stage") != "formal"
        or admission.get("source") != expected_source
        or cohort.get("source") != expected_source
        or admission.get("formal_cohort")
        != {
            "path": str(Path(admission["formal_cohort"]["path"]).resolve()),
            "sha256": sha256_file(cohort_path),
        }
    ):
        raise ValueError("formal result admission/cohort source lineage is invalid")
    campaign_sha256 = sha256_file(campaign_path)
    allowed = [
        row
        for row in admission["allowed_campaigns"]
        if row["campaign_sha256"] == campaign_sha256
        and row["campaign_name"] == result_root.parent.name
        and Path(row["result_root"]) == result_root
    ]
    cohort_rows = [
        row
        for row in cohort["formal_campaigns"]
        if row["campaign_sha256"] == campaign_sha256 and Path(row["result_root"]) == result_root
    ]
    if len(allowed) != 1 or len(cohort_rows) != 1:
        raise ValueError("formal result is not the prospectively selected cohort root")


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_dataset(dataset: Any, rows: Sequence[Mapping[str, Any]], *, formal: bool) -> None:
    if (
        not isinstance(dataset, dict)
        or set(dataset) != (_FORMAL_DATASET_KEYS if formal else _DATASET_KEYS)
        or dataset.get("schema_version") != SCHEMA_VERSION
        or dataset.get("artifact_type") != ARTIFACT_TYPE
        or dataset.get("purpose") != PURPOSE
        or dataset.get("formal") is not formal
        or dataset.get("paper_equivalent") is not False
        or dataset.get("implementation_scope") != "client_only_quic"
        or dataset.get("sample_count") != len(rows)
    ):
        raise ValueError("study handoff dataset schema is invalid")
    expected_classes = sorted({str(row.get("class_label")) for row in rows})
    expected_defenses = sorted({str(row.get("defense")) for row in rows})
    expected_defense_counts = dict(sorted(Counter(str(row.get("defense")) for row in rows).items()))
    expected_split_counts = dict(sorted(Counter(str(row.get("split")) for row in rows).items()))
    if (
        dataset.get("classes") != expected_classes
        or dataset.get("defenses") != expected_defenses
        or dataset.get("counts_by_defense") != expected_defense_counts
        or dataset.get("counts_by_split") != expected_split_counts
        or dataset.get("observation")
        != {
            "length_basis": "Ethernet frame.len",
            "direction_rule": "client egress positive; server ingress negative",
            "model_input": "traces/*.csv or stripped/*.pcap",
            "raw_restricted": True,
        }
        or not isinstance(dataset.get("exporter_source"), Mapping)
        or not isinstance(dataset.get("execution_source"), Mapping)
    ):
        raise ValueError("study handoff dataset declarations are invalid")
    if formal:
        execution_source = dataset["execution_source"]
        exporter_source = dataset["exporter_source"]
        if execution_source != exporter_source or any(
            not _immutable_source(source) for source in (execution_source, exporter_source)
        ):
            raise ValueError("formal study handoff source provenance is not immutable")
    blocks = dataset.get("blocks")
    names = dataset.get("result_names")
    if not isinstance(blocks, list) or not blocks or not isinstance(names, list):
        raise ValueError("study handoff block lineage is invalid")
    if formal and len(blocks) != len(FORMAL_BLOCKS):
        raise ValueError("formal study handoff block count is invalid")
    for index, block in enumerate(blocks):
        if (
            not isinstance(block, Mapping)
            or set(block) != (_FORMAL_BLOCK_KEYS if formal else _BLOCK_KEYS)
            or block.get("acquisition_block_index") != index
            or block.get("acquisition_block_id") != f"acquisition-block-{index + 1:03d}"
            or block.get("split") != _split_for_block(index)
            or not isinstance(block.get("result_name"), str)
            or not block["result_name"]
            or not isinstance(block.get("result_root"), str)
            or not block["result_root"]
            or _DIGEST.fullmatch(str(block.get("result_evidence_sha256"))) is None
            or type(block.get("authoritative_files")) is not int
            or block["authoritative_files"] <= 0
            or (
                block.get("campaign_path") is not None
                and (not isinstance(block["campaign_path"], str) or not block["campaign_path"])
            )
            or _DIGEST.fullmatch(str(block.get("campaign_sha256"))) is None
            or not isinstance(block.get("configuration"), Mapping)
            or _DIGEST.fullmatch(str(block.get("configuration_sha256"))) is None
            or _canonical_digest(block["configuration"]) != block["configuration_sha256"]
            or block["configuration"].get("campaign_sha256") != block["campaign_sha256"]
        ):
            raise ValueError("study handoff block lineage is invalid")
        if formal:
            campaign_relative = block.get("campaign_path")
            if not isinstance(campaign_relative, str):
                raise ValueError("formal study handoff block has no campaign path")
            campaign_path = _trusted_formal_campaign_path(
                LAB_ROOT / campaign_relative,
                index,
            )
            _campaign, expected_configuration = _expected_formal_configuration(campaign_path)
            if (
                block.get("campaign_path") != campaign_relative
                or block.get("campaign_sha256") != sha256_file(campaign_path)
                or {
                    key: value
                    for key, value in block["configuration"].items()
                    if key not in _FORMAL_DYNAMIC_CONFIGURATION_KEYS
                }
                != expected_configuration
                or set(block["configuration"])
                != set(expected_configuration) | _FORMAL_DYNAMIC_CONFIGURATION_KEYS
            ):
                raise ValueError("formal study handoff block differs from its checked-in campaign")
            _validate_formal_result_admission(
                Path(block["result_root"]),
                campaign_path,
                block["configuration"],
                expected_source=dataset["execution_source"],
            )
    if formal and dataset.get("temporal_acquisition") != _formal_temporal_proof(blocks):
        raise ValueError("formal study handoff temporal acquisition proof is invalid")
    if names != [block["result_name"] for block in blocks]:
        raise ValueError("study handoff result names differ from block lineage")
    if len(names) != len(set(names)):
        raise ValueError("study handoff result names are not unique")
    row_blocks = {row.get("acquisition_block_index") for row in rows}
    if row_blocks != set(range(len(blocks))) or any(
        row.get("source_result") != names[int(row["acquisition_block_index"])] for row in rows
    ):
        raise ValueError("study handoff samples differ from block lineage")


def _immutable_source(value: Mapping[str, Any]) -> bool:
    return bool(
        set(value) == _SOURCE_KEYS
        and _IMAGE_DIGEST.fullmatch(str(value.get("image_digest")))
        and _COMMIT.fullmatch(str(value.get("lab_commit")))
        and _COMMIT.fullmatch(str(value.get("neqo_commit")))
        and value.get("neqo_pinned_commit") == value.get("neqo_commit")
        and value.get("lab_dirty") is False
        and value.get("neqo_dirty") is False
        and value.get("lab_patch_sha256") == _EMPTY_SHA256
        and value.get("neqo_patch_sha256") == _EMPTY_SHA256
    )


_COMPOSITION_FIELDS = SCHEDULE_QCSD_FIELDS[4:10]
_CS_INTERVALS_US = (4_096, 8_192, 16_384, 32_768)


def _read_extended_runner_csv(
    path: Path,
    prefix: tuple[str, ...],
    *,
    label: str,
    require_current_schema: bool = True,
) -> list[dict[str, str]]:
    """Read one exact source-stable runner CSV and validate its typed suffix."""

    if path.is_symlink() or not path.is_file():
        raise ValueError(f"study handoff {label} is not a regular file")
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
        fieldnames = tuple(reader.fieldnames or ())
    compatible_suffixes = (
        SCHEDULE_QCSD_FIELDS,
        CONSUMPTION_SCHEDULE_QCSD_FIELDS,
        ADVERTISEMENT_SCHEDULE_QCSD_FIELDS,
        LEGACY_SCHEDULE_QCSD_FIELDS,
    )
    if fieldnames not in {prefix + suffix for suffix in compatible_suffixes} or (
        require_current_schema and fieldnames != prefix + SCHEDULE_QCSD_FIELDS
    ):
        raise ValueError(f"study handoff {label} does not use the exact extended schema")
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError(f"study handoff {label} contains a malformed CSV row")
    for row in rows:
        for field in SCHEDULE_QCSD_FIELDS:
            row.setdefault(field, "")
    for index, row in enumerate(rows, 1):
        _validate_runner_extension(row, label=f"{label} row {index}")
    return rows


def _validate_runner_extension(row: Mapping[str, str], *, label: str) -> None:
    values = {field: row[field] for field in SCHEDULE_QCSD_FIELDS}
    schema = values["qcsd_outcome_schema_version"]
    if not schema:
        if any(values.values()):
            raise ValueError(f"{label} has typed values without a schema version")
        return
    if schema not in {"1", "2", "3"}:
        raise ValueError(f"{label} has an invalid typed outcome identity")
    advertisement_fields = (
        "credit_advertised_at_us",
        "credit_advertisement_delay_us",
    )
    consumption_fields = ("credit_consumed_at_us", "credit_consumption_delay_us")
    terminal_field = "terminal_defense_elapsed_us"
    advertisement_present = any(values[field] for field in advertisement_fields)
    consumption_present = any(values[field] for field in consumption_fields)
    advertisement_complete = all(values[field].isdecimal() for field in advertisement_fields)
    consumption_complete = all(values[field].isdecimal() for field in consumption_fields)
    if advertisement_present and not advertisement_complete:
        raise ValueError(f"{label} has incomplete receive-credit advertisement evidence")
    if consumption_present and not consumption_complete:
        raise ValueError(f"{label} has incomplete receive-credit consumption evidence")
    terminal_present = bool(values[terminal_field])
    if terminal_present != (schema == "3") or (
        terminal_present and not values[terminal_field].isdecimal()
    ):
        raise ValueError(f"{label} has invalid controller terminal-time evidence")
    target = row.get("target_time_us", "")
    if (
        terminal_present
        and target
        and (not target.isdecimal() or int(values[terminal_field]) < int(target))
    ):
        raise ValueError(f"{label} terminal time predates its defense target")
    if consumption_present and (schema not in {"2", "3"} or not advertisement_complete):
        raise ValueError(f"{label} has unbound receive-credit consumption evidence")
    if not values["send_policy"]:
        if any(values[field] for field in LEGACY_SCHEDULE_QCSD_FIELDS[1:]):
            raise ValueError(f"{label} mixes credit-only metadata with an outcome")
        if (
            schema == "3"
            and not consumption_present
            and (not advertisement_present or advertisement_complete)
        ):
            return
        if schema != "2" or not advertisement_complete or consumption_present:
            raise ValueError(f"{label} has a schema-only row without typed evidence")
        return
    if values["send_policy"] not in {"exact", "congestion_sensitive", "unscheduled"}:
        raise ValueError(f"{label} has an invalid typed send policy")
    desired = values["desired_udp_bytes"]
    if not desired.isdecimal() or int(desired) <= 0:
        raise ValueError(f"{label} has an invalid desired UDP size")
    observed = values["observed_udp_bytes"]
    suffix = (*_COMPOSITION_FIELDS, "lateness_us", "congestion_reason")
    if not observed:
        incoming_terminal = (
            row.get("direction") == "incoming"
            and values["send_policy"] == "exact"
            and advertisement_complete
        )
        if any(values[field] for field in suffix) or (
            consumption_present and not incoming_terminal
        ):
            raise ValueError(f"{label} has terminal evidence before an observed size")
        return
    if not observed.isdecimal():
        raise ValueError(f"{label} has an invalid observed UDP size")
    components = [values[field] for field in _COMPOSITION_FIELDS]
    if consumption_present:
        raise ValueError(f"{label} attaches peer-consumption timing to an observed UDP row")
    if values["send_policy"] == "exact":
        if any(components):
            if (
                schema not in {"2", "3"}
                or not all(component.isdecimal() for component in components)
                or sum(int(component) for component in components) != int(observed)
                or not values["lateness_us"].isdecimal()
            ):
                raise ValueError(f"{label} has incomplete exact packet composition")
        elif values["lateness_us"]:
            raise ValueError(f"{label} gives an exact outcome unexplained lateness")
        if values["congestion_reason"]:
            raise ValueError(f"{label} gives an exact outcome congestion metadata")
        return
    if not all(component.isdecimal() for component in components):
        raise ValueError(f"{label} has incomplete traffic composition")
    if sum(int(component) for component in components) != int(observed):
        raise ValueError(f"{label} traffic composition does not equal observed UDP bytes")
    if not values["lateness_us"].isdecimal():
        raise ValueError(f"{label} has no numeric scheduling lateness")
    if values["congestion_reason"] not in {
        "",
        "congestion_limited",
        "pacing_limited",
    }:
        raise ValueError(f"{label} has an invalid congestion reason")
    if values["send_policy"] == "unscheduled" and values["congestion_reason"]:
        raise ValueError(f"{label} gives an unscheduled datagram a congestion reason")


def _csv_unsigned(value: Any, *, label: str, positive: bool = False) -> int:
    if not isinstance(value, str) or not value.isdecimal():
        raise ValueError(f"{label} is not an unsigned integer")
    parsed = int(value)
    if positive and parsed <= 0:
        raise ValueError(f"{label} is not positive")
    return parsed


def _numeric_summary(values: Sequence[int]) -> dict[str, Any]:
    ordered = sorted(values)
    if not ordered:
        return {
            "count": 0,
            "minimum": None,
            "maximum": None,
            "mean": None,
            "p50": None,
            "p95": None,
        }

    def percentile(fraction: float) -> int:
        return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]

    return {
        "count": len(ordered),
        "minimum": ordered[0],
        "maximum": ordered[-1],
        "mean": sum(ordered) / len(ordered),
        "p50": percentile(0.50),
        "p95": percentile(0.95),
    }


def _nearest_cs_interval(value: int) -> int:
    return min(_CS_INTERVALS_US, key=lambda interval: (abs(value - interval), interval))


def _direction_algorithm_metrics(
    rows: Sequence[Mapping[str, str]],
    *,
    direction: str,
    runtime_kind: str,
) -> dict[str, Any]:
    selected = [row for row in rows if row["direction"] == direction]
    credit_delays: list[int] = []
    credit_consumption_delays: list[int] = []
    for row in selected:
        advertised = row["credit_advertised_at_us"]
        delay = row["credit_advertisement_delay_us"]
        consumed = row["credit_consumed_at_us"]
        consumption_delay = row["credit_consumption_delay_us"]
        if direction == "outgoing":
            if advertised or delay or consumed or consumption_delay:
                raise ValueError("study handoff outgoing schedule carries receive-credit evidence")
            continue
        advertised_at_us = _csv_unsigned(
            advertised,
            label="incoming credit advertised time",
        )
        delay_us = _csv_unsigned(delay, label="incoming credit advertisement delay")
        action_time_us = _csv_unsigned(row["action_time_us"], label="schedule action time")
        if advertised_at_us < action_time_us or delay_us != advertised_at_us - action_time_us:
            raise ValueError("study handoff incoming credit advertisement timing is invalid")
        consumed_at_us = _csv_unsigned(
            consumed,
            label="incoming credit consumed time",
        )
        consumption_delay_us = _csv_unsigned(
            consumption_delay,
            label="incoming credit consumption delay",
        )
        if (
            consumed_at_us < advertised_at_us
            or consumption_delay_us != consumed_at_us - action_time_us
        ):
            raise ValueError("study handoff incoming credit consumption timing is invalid")
        credit_delays.append(delay_us)
        credit_consumption_delays.append(consumption_delay_us)
    targeted_rows = [
        (
            _csv_unsigned(row["target_time_us"], label="schedule target time"),
            row,
        )
        for row in selected
    ]
    targeted_rows.sort(key=lambda item: item[0])
    targets = [target for target, _ in targeted_rows]
    if any(current <= previous for previous, current in zip(targets, targets[1:])):
        raise ValueError("study handoff schedule targets are not unique")
    sizes = [
        _csv_unsigned(row["size"], label="schedule target size", positive=True)
        for _, row in targeted_rows
    ]
    deltas = [current - previous for previous, current in zip(targets, targets[1:])]
    nominal_intervals: list[int] = []
    if runtime_kind == "buflo":
        nominal_intervals = [20_000 for _ in deltas]
    elif runtime_kind == "cs_buflo":
        nominal_intervals = [_nearest_cs_interval(delta) for delta in deltas]
    jitter = [delta - nominal for delta, nominal in zip(deltas, nominal_intervals, strict=True)]
    transitions = []
    for index, (previous, current) in enumerate(zip(nominal_intervals, nominal_intervals[1:]), 1):
        if current != previous:
            transitions.append(
                {
                    "target_time_us": targets[index + 1],
                    "from_interval_us": previous,
                    "to_interval_us": current,
                }
            )
    satisfactions = Counter(row["satisfaction"] for row in selected)
    congestion = Counter(row["congestion_reason"] for row in selected if row["congestion_reason"])
    typed = [row for row in selected if row["qcsd_outcome_schema_version"] in {"1", "2", "3"}]
    desired = sum(
        _csv_unsigned(row["desired_udp_bytes"], label="schedule desired UDP bytes") for row in typed
    )
    terminal = [row for row in typed if row["observed_udp_bytes"]]
    observed = sum(
        _csv_unsigned(row["observed_udp_bytes"], label="schedule observed UDP bytes")
        for row in terminal
    )
    composition = {
        field: sum(
            _csv_unsigned(row[field], label=f"schedule {field}") for row in terminal if row[field]
        )
        for field in _COMPOSITION_FIELDS
    }
    lateness = [
        _csv_unsigned(row["lateness_us"], label="schedule lateness")
        for row in terminal
        if row["lateness_us"]
    ]
    return {
        "scheduled_cells": len(selected),
        "target_size_bytes": {
            "summary": _numeric_summary(sizes),
            "histogram": dict(sorted(Counter(str(value) for value in sizes).items())),
        },
        "desired_udp_bytes": desired,
        "observed_udp_bytes": observed,
        "realization_ratio": (observed / desired if direction == "outgoing" and desired else None),
        "realization_semantics": (
            "locally observed outgoing UDP realization"
            if direction == "outgoing"
            else "unavailable for scheduled server datagram timing and size"
        ),
        "satisfaction_counts": dict(sorted(satisfactions.items())),
        "congestion_reason_counts": dict(sorted(congestion.items())),
        "inter_target_delta_us": _numeric_summary(deltas),
        "nearest_nominal_interval_us": _numeric_summary(nominal_intervals),
        "estimated_jitter_from_nearest_nominal_us": _numeric_summary(jitter),
        "inferred_nearest_nominal_transitions": transitions,
        "jitter_semantics": ("target-delta-minus-nearest-allowed-live-interval; descriptive-only"),
        "scheduling_lateness_us": _numeric_summary(lateness),
        "traffic_composition_bytes": composition,
        "receive_credit_advertisement": {
            "semantics": (
                "complete local MAX_STREAM_DATA on-wire advertisement; this rearms cadence "
                "without claiming peer datagram timing, size, or consumption"
            ),
            "advertised_cells": len(credit_delays),
            "delay_us": _numeric_summary(credit_delays),
        },
        "receive_credit_consumption": {
            "semantics": (
                "eventual peer stream-offset consumption terminal boundary; measured "
                "separately from allocation and local advertisement"
            ),
            "consumed_cells": len(credit_consumption_delays),
            "delay_us": _numeric_summary(credit_consumption_delays),
        },
    }


def _cs_buflo_stop_drain_ledger(
    diagnostics: Mapping[str, Any],
    schedule_rows: Sequence[Mapping[str, str]],
) -> dict[str, dict[str, int]]:
    """Bind a schema-4 stop snapshot to the terminal schedule chronology."""

    local_latch_us = diagnostics["cs_buflo_local_et_latched_at_us"]
    evidence: dict[str, dict[str, int]] = {}
    for direction in ("outgoing", "incoming"):
        selected = [row for row in schedule_rows if row["direction"] == direction]
        stop_us = diagnostics[f"cs_buflo_{direction}_termination_stop_latched_at_us"]
        scheduled_at_stop = diagnostics[
            f"cs_buflo_{direction}_termination_stop_scheduled_cells_at_stop"
        ]
        terminal_at_stop = diagnostics[
            f"cs_buflo_{direction}_termination_stop_terminal_cells_at_stop"
        ]
        target_times = [
            _csv_unsigned(row["target_time_us"], label="schedule target time") for row in selected
        ]
        terminal_times = [
            _csv_unsigned(
                row["terminal_defense_elapsed_us"],
                label=f"{direction} controller terminal time",
            )
            for row in selected
        ]
        terminal_before_stop = sum(terminal < stop_us for terminal in terminal_times)
        terminal_at_or_before_stop = sum(terminal <= stop_us for terminal in terminal_times)
        if (
            type(local_latch_us) is not int
            or type(stop_us) is not int
            or stop_us < 0
            or stop_us > local_latch_us
            or scheduled_at_stop != len(selected)
            or not 0 <= terminal_at_stop <= scheduled_at_stop
            or any(target > stop_us for target in target_times)
            or not (terminal_before_stop <= terminal_at_stop <= terminal_at_or_before_stop)
            or any(terminal > local_latch_us for terminal in terminal_times)
        ):
            raise ValueError("study handoff CS-BuFLO stop/drain schedule chronology is invalid")
        evidence[direction] = {
            "drained_cells_after_stop": scheduled_at_stop - terminal_at_stop,
            "last_scheduled_target_us": max(target_times, default=0),
            "last_terminal_at_us": max(terminal_times, default=0),
            "terminal_cells_strictly_before_stop": terminal_before_stop,
            "terminal_cells_at_or_before_stop": terminal_at_or_before_stop,
            "terminal_cells_at_stop_timestamp": (terminal_at_or_before_stop - terminal_before_stop),
        }
    return evidence


def _defense_elapsed_us_bounds(
    process_elapsed_us: int,
    *,
    defense_start_monotonic_ns: int,
    label: str,
) -> tuple[int, int]:
    """Translate a process-clock microsecond stamp to exact defense-clock bounds.

    Runner CSV timestamps floor a process-relative nanosecond duration to
    microseconds, whereas defense diagnostics floor a duration relative to the
    (generally sub-microsecond-aligned) defense start.  The original nanosecond
    instant is therefore recoverable only as a one-microsecond interval.  The
    returned inclusive lower/upper bounds preserve that uncertainty instead of
    silently comparing the two different clock domains.
    """

    if (
        type(process_elapsed_us) is not int
        or process_elapsed_us < 0
        or type(defense_start_monotonic_ns) is not int
        or defense_start_monotonic_ns < 0
    ):
        raise ValueError(f"{label} has an invalid process/defense clock binding")
    start_us_floor, start_ns_remainder = divmod(defense_start_monotonic_ns, 1_000)
    if process_elapsed_us < start_us_floor:
        raise ValueError(f"{label} predates the defense clock")
    upper = process_elapsed_us - start_us_floor
    lower = upper - int(start_ns_remainder > 0)
    return max(0, lower), upper


def _validate_incoming_terminal_clock_bindings(
    schedule_rows: Sequence[Mapping[str, str]],
    *,
    defense_start_monotonic_ns: int,
    runtime_kind: str,
) -> None:
    """Reconcile process-clock credit consumption with controller time.

    ``credit_consumed_at_us`` is the terminal action's serialization timestamp
    relative to the runner trace origin. ``terminal_defense_elapsed_us`` is the
    earlier controller resolution relative to defense activation. Reduction
    can be delayed while the single-threaded runner reserves an exact outgoing
    window, so the two are ordered and bounded after translating the former
    through the exact recorded defense-start offset.  The translation retains
    the one-microsecond floor uncertainty.
    """

    for index, row in enumerate(schedule_rows, 1):
        if row["direction"] != "incoming":
            continue
        terminal_value = row["terminal_defense_elapsed_us"]
        if not terminal_value:
            continue
        terminal_us = _csv_unsigned(
            terminal_value,
            label=f"schedule.csv row {index} incoming controller terminal time",
        )
        consumption_value = row["credit_consumed_at_us"]
        if row["satisfaction"] in {"satisfied", "full"}:
            if not consumption_value:
                raise ValueError(
                    f"study handoff {runtime_kind} incoming terminal row lacks "
                    "credit-consumption evidence"
                )
            consumption_bounds = _defense_elapsed_us_bounds(
                _csv_unsigned(
                    consumption_value,
                    label=f"schedule.csv row {index} credit-consumption time",
                ),
                defense_start_monotonic_ns=defense_start_monotonic_ns,
                label=f"schedule.csv row {index} credit-consumption time",
            )
            if (
                terminal_us > consumption_bounds[1]
                or consumption_bounds[1] - terminal_us > _CONTROLLER_ACTION_REDUCTION_LIMIT_US
            ):
                raise ValueError(
                    f"study handoff {runtime_kind} incoming controller terminal "
                    "time differs from translated credit consumption"
                )
        elif consumption_value:
            raise ValueError(
                f"study handoff {runtime_kind} non-realized incoming row carries "
                "credit-consumption evidence"
            )


def _validate_candidate_schedule_diagnostic_counts(
    diagnostics: Mapping[str, Any],
    schedule_rows: Sequence[Mapping[str, str]],
    *,
    runtime_kind: str,
) -> None:
    """Bind terminal schedule outcomes and CS composition to flat counters."""

    outgoing = [row for row in schedule_rows if row["direction"] == "outgoing"]
    incoming = [row for row in schedule_rows if row["direction"] == "incoming"]
    outgoing_counts = Counter(row["satisfaction"] for row in outgoing)
    incoming_counts = Counter(row["satisfaction"] for row in incoming)
    prefix = "buflo" if runtime_kind == "buflo" else "cs_buflo"
    counter_keys = {
        f"{prefix}_scheduled_outgoing_cells",
        f"{prefix}_scheduled_incoming_cells",
        f"{prefix}_full_outgoing_cells",
        f"{prefix}_partial_outgoing_cells",
        f"{prefix}_suppressed_outgoing_cells",
        f"{prefix}_missed_outgoing_cells",
        f"{prefix}_missed_incoming_cells",
    }
    if any(type(diagnostics.get(key)) is not int for key in counter_keys):
        raise ValueError("study handoff candidate schedule counters are unavailable")
    full_satisfaction = "satisfied" if runtime_kind == "buflo" else "full"
    if (
        diagnostics[f"{prefix}_scheduled_outgoing_cells"] != len(outgoing)
        or diagnostics[f"{prefix}_scheduled_incoming_cells"] != len(incoming)
        or diagnostics[f"{prefix}_full_outgoing_cells"] != outgoing_counts[full_satisfaction]
        or diagnostics[f"{prefix}_partial_outgoing_cells"] != outgoing_counts["partial"]
        or diagnostics[f"{prefix}_suppressed_outgoing_cells"] != outgoing_counts["suppressed"]
        or diagnostics[f"{prefix}_missed_outgoing_cells"] != outgoing_counts["missed"]
        or diagnostics[f"{prefix}_missed_incoming_cells"] != incoming_counts["missed"]
        or set(incoming_counts) - {"satisfied", "missed"}
        or (runtime_kind == "buflo" and set(outgoing_counts) - {"satisfied", "missed"})
        or (
            runtime_kind == "cs_buflo"
            and set(outgoing_counts) - {"full", "partial", "suppressed", "missed"}
        )
    ):
        raise ValueError("study handoff candidate terminal schedule differs from runner counters")

    if runtime_kind != "cs_buflo":
        return
    realized = [row for row in outgoing if row["satisfaction"] in {"full", "partial"}]
    desired_bytes = sum(
        _csv_unsigned(row["desired_udp_bytes"], label="CS schedule desired UDP bytes")
        for row in outgoing
        if row["desired_udp_bytes"]
    )
    observed_bytes = sum(
        _csv_unsigned(row["observed_udp_bytes"], label="CS schedule observed UDP bytes")
        for row in realized
    )
    composition = {
        field: sum(_csv_unsigned(row[field], label=f"CS schedule {field}") for row in realized)
        for field in _COMPOSITION_FIELDS
    }
    lateness = [_csv_unsigned(row["lateness_us"], label="CS schedule lateness") for row in realized]
    incoming_credit_bytes = sum(
        _csv_unsigned(row["size"], label="CS incoming cell size", positive=True)
        for row in incoming
        if row["satisfaction"] == "satisfied"
    )
    if (
        diagnostics.get("cs_buflo_desired_udp_bytes") != desired_bytes
        or diagnostics.get("cs_buflo_realized_udp_bytes") != observed_bytes
        or diagnostics.get("cs_buflo_realized_incoming_credit_bytes") != incoming_credit_bytes
        or any(
            diagnostics.get(f"cs_buflo_{field}") != value for field, value in composition.items()
        )
        or diagnostics.get("cs_buflo_lateness_us_total") != sum(lateness)
        or diagnostics.get("cs_buflo_lateness_us_max") != max(lateness, default=0)
    ):
        raise ValueError("study handoff CS-BuFLO schedule composition differs from runner counters")


def _validate_cs_buflo_outgoing_packet_evidence(
    schedule_rows: Sequence[Mapping[str, str]],
    packets_rows: Sequence[Mapping[str, str]],
    *,
    defense_start_monotonic_ns: int | None,
) -> None:
    """Bind each realized CS opportunity to one packet-builder transcript."""

    scheduled = [
        row
        for row in schedule_rows
        if row["direction"] == "outgoing" and row["satisfaction"] in {"full", "partial"}
    ]
    packets = [
        row for row in packets_rows if row["direction"] == "outgoing" and row["scheduled_target"]
    ]
    packets_by_slot: dict[int, list[Mapping[str, str]]] = {}
    for row in packets:
        slot = _csv_unsigned(row["slot_id"], label="packets.csv CS-BuFLO slot")
        packets_by_slot.setdefault(slot, []).append(row)
    scheduled_slots = {
        _csv_unsigned(row["slot_id"], label="schedule.csv CS-BuFLO slot") for row in scheduled
    }
    if len(scheduled_slots) != len(scheduled) or set(packets_by_slot) != scheduled_slots:
        raise ValueError("study handoff CS-BuFLO outgoing packet inventory is not one-to-one")

    compared_fields = (
        *_COMPOSITION_FIELDS,
        "lateness_us",
        "congestion_reason",
    )
    for row in scheduled:
        slot = _csv_unsigned(row["slot_id"], label="schedule.csv CS-BuFLO slot")
        matches = packets_by_slot[slot]
        packet = matches[0]
        target_size = _csv_unsigned(row["size"], label="schedule.csv CS-BuFLO size", positive=True)
        observed = _csv_unsigned(
            row["observed_udp_bytes"],
            label="schedule.csv CS-BuFLO observed UDP bytes",
            positive=True,
        )
        if (
            len(matches) != 1
            or packet["connection"] != row["connection"]
            or packet["satisfaction"] != row["satisfaction"]
            or packet["qcsd_outcome_schema_version"] != "2"
            or packet["send_policy"] != "congestion_sensitive"
            or _csv_unsigned(
                packet["scheduled_target"],
                label="packets.csv CS-BuFLO scheduled target",
                positive=True,
            )
            != target_size
            or _csv_unsigned(
                packet["desired_udp_bytes"],
                label="packets.csv CS-BuFLO desired UDP bytes",
                positive=True,
            )
            != target_size
            or _csv_unsigned(
                packet["observed_udp_bytes"],
                label="packets.csv CS-BuFLO observed UDP bytes",
                positive=True,
            )
            != observed
            or _csv_unsigned(
                packet["observed_udp_length"],
                label="packets.csv CS-BuFLO observed UDP length",
                positive=True,
            )
            != observed
            or any(packet[field] != row[field] for field in compared_fields)
        ):
            raise ValueError("study handoff CS-BuFLO outgoing packet binding is invalid")

        terminal_value = row["terminal_defense_elapsed_us"]
        if terminal_value:
            if type(defense_start_monotonic_ns) is not int or defense_start_monotonic_ns < 0:
                raise ValueError("study handoff CS-BuFLO defense clock binding is unavailable")
            packet_bounds = _defense_elapsed_us_bounds(
                _csv_unsigned(
                    packet["monotonic_us"],
                    label="packets.csv CS-BuFLO packet time",
                ),
                defense_start_monotonic_ns=defense_start_monotonic_ns,
                label="packets.csv CS-BuFLO packet time",
            )
            terminal_us = _csv_unsigned(
                terminal_value,
                label="schedule.csv CS-BuFLO controller terminal time",
            )
            realized_us = _csv_unsigned(
                row["target_time_us"], label="schedule.csv CS-BuFLO target time"
            ) + _csv_unsigned(row["lateness_us"], label="schedule.csv CS-BuFLO lateness")
            # The transport computes composition lateness while building the
            # datagram, then the runner timestamps the packet and controller
            # resolution at the successful socket handoff.  Those instants
            # are causally ordered but need not be the same microsecond.
            if not (
                packet_bounds[0] <= terminal_us <= packet_bounds[1] and realized_us <= terminal_us
            ):
                raise ValueError(
                    "study handoff CS-BuFLO outgoing packet/controller timing is inconsistent"
                )


def _buflo_terminal_times(
    schedule_rows: Sequence[Mapping[str, str]],
    packets_rows: Sequence[Mapping[str, str]],
    *,
    defense_start_monotonic_ns: int,
) -> dict[str, list[int]]:
    """Bind every BuFLO slot to its exact controller terminal time."""

    outgoing_schedule = [row for row in schedule_rows if row["direction"] == "outgoing"]
    outgoing_packets = [
        row for row in packets_rows if row["direction"] == "outgoing" and row["scheduled_target"]
    ]
    packets_by_slot: dict[int, list[Mapping[str, str]]] = {}
    for row in outgoing_packets:
        slot = _csv_unsigned(row["slot_id"], label="packets.csv BuFLO slot")
        packets_by_slot.setdefault(slot, []).append(row)
    scheduled_slots = {
        _csv_unsigned(row["slot_id"], label="schedule.csv BuFLO slot") for row in outgoing_schedule
    }
    if len(scheduled_slots) != len(outgoing_schedule) or set(packets_by_slot) != scheduled_slots:
        raise ValueError("study handoff BuFLO outgoing terminal packet inventory is not one-to-one")

    outgoing: list[int] = []
    for row in outgoing_schedule:
        slot = _csv_unsigned(row["slot_id"], label="schedule.csv BuFLO slot")
        matches = packets_by_slot[slot]
        size = _csv_unsigned(row["size"], label="schedule.csv BuFLO size", positive=True)
        if (
            len(matches) != 1
            or row["satisfaction"] != "satisfied"
            or row["qcsd_outcome_schema_version"] != "3"
            or matches[0]["connection"] != row["connection"]
            or matches[0]["satisfaction"] != "satisfied"
            or matches[0]["qcsd_outcome_schema_version"] != "2"
            or matches[0]["send_policy"] != "exact"
            or _csv_unsigned(
                matches[0]["scheduled_target"],
                label="packets.csv BuFLO scheduled target",
                positive=True,
            )
            != size
            or _csv_unsigned(
                matches[0]["desired_udp_bytes"],
                label="packets.csv BuFLO desired UDP bytes",
                positive=True,
            )
            != size
            or _csv_unsigned(
                matches[0]["observed_udp_length"],
                label="packets.csv BuFLO observed UDP length",
                positive=True,
            )
            != size
            or _csv_unsigned(
                matches[0]["observed_udp_bytes"],
                label="packets.csv BuFLO observed UDP bytes",
                positive=True,
            )
            != size
            or any(
                not matches[0][field].isdecimal() for field in (*_COMPOSITION_FIELDS, "lateness_us")
            )
        ):
            raise ValueError("study handoff BuFLO outgoing terminal packet binding is invalid")
        terminal_us = _csv_unsigned(
            row["terminal_defense_elapsed_us"],
            label="schedule.csv BuFLO controller terminal time",
        )
        target_us = _csv_unsigned(
            row["target_time_us"],
            label="schedule.csv BuFLO target time",
        )
        packet_lateness_us = _csv_unsigned(
            matches[0]["lateness_us"],
            label="packets.csv BuFLO lateness",
        )
        if (
            terminal_us - target_us >= _BUFLO_EXACT_REALIZATION_WINDOW_US
            or packet_lateness_us >= _BUFLO_EXACT_REALIZATION_WINDOW_US
        ):
            raise ValueError(
                "study handoff BuFLO exact outgoing cell exceeds its half-open realization window"
            )
        packet_bounds = _defense_elapsed_us_bounds(
            _csv_unsigned(
                matches[0]["monotonic_us"],
                label="packets.csv BuFLO packet time",
            ),
            defense_start_monotonic_ns=defense_start_monotonic_ns,
            label="packets.csv BuFLO packet time",
        )
        if not packet_bounds[0] <= terminal_us <= packet_bounds[1]:
            raise ValueError(
                "study handoff BuFLO outgoing controller terminal time differs from its packet"
            )
        realized_us = target_us + packet_lateness_us
        if realized_us > terminal_us:
            raise ValueError(
                "study handoff BuFLO packet-build time follows controller terminalization"
            )
        outgoing.append(terminal_us)

    incoming = [
        _csv_unsigned(
            row["terminal_defense_elapsed_us"],
            label="schedule.csv BuFLO incoming controller terminal time",
        )
        for row in schedule_rows
        if row["direction"] == "incoming"
    ]
    return {"outgoing": outgoing, "incoming": incoming}


def _buflo_stop_drain_ledger(
    diagnostics: Mapping[str, Any],
    schedule_rows: Sequence[Mapping[str, str]],
    terminal_times_by_direction: Mapping[str, Sequence[int]],
) -> dict[str, dict[str, int]]:
    """Bind a schema-4 BuFLO schedule-stop snapshot to terminal rows."""

    stop_us = diagnostics["buflo_schedule_stop_latched_at_us"]
    terminal_latch_us = diagnostics["buflo_terminal_subcell_latched_at_us"]
    if (
        type(stop_us) is not int
        or type(terminal_latch_us) is not int
        or stop_us < 10_000_000
        or stop_us > terminal_latch_us
    ):
        raise ValueError("study handoff BuFLO stop/drain latch chronology is invalid")
    evidence: dict[str, dict[str, int]] = {}
    for direction in ("outgoing", "incoming"):
        selected = [row for row in schedule_rows if row["direction"] == direction]
        scheduled_at_stop = diagnostics[f"buflo_schedule_stop_scheduled_{direction}_cells"]
        terminal_at_stop = diagnostics[f"buflo_schedule_stop_terminal_{direction}_cells"]
        target_times = [
            _csv_unsigned(row["target_time_us"], label="schedule target time") for row in selected
        ]
        terminal_times = list(terminal_times_by_direction.get(direction, ()))
        terminal_before_stop = sum(terminal < stop_us for terminal in terminal_times)
        terminal_at_or_before_stop = sum(terminal <= stop_us for terminal in terminal_times)
        drained_after_stop = scheduled_at_stop - terminal_at_stop
        if (
            type(scheduled_at_stop) is not int
            or type(terminal_at_stop) is not int
            or scheduled_at_stop != len(selected)
            or scheduled_at_stop != len(terminal_times)
            or not 0 <= terminal_at_stop <= scheduled_at_stop
            or any(target > stop_us for target in target_times)
            or not (terminal_before_stop <= terminal_at_stop <= terminal_at_or_before_stop)
            or any(terminal > terminal_latch_us for terminal in terminal_times)
            or (direction == "outgoing" and drained_after_stop != 0)
        ):
            raise ValueError("study handoff BuFLO stop/drain schedule chronology is invalid")
        evidence[direction] = {
            "scheduled_cells_at_stop": scheduled_at_stop,
            "terminal_cells_at_stop": terminal_at_stop,
            "drained_cells_after_stop": drained_after_stop,
            "last_scheduled_target_us": max(target_times, default=0),
            "last_terminal_at_us": max(terminal_times, default=0),
            "terminal_cells_strictly_before_stop": terminal_before_stop,
            "terminal_cells_at_or_before_stop": terminal_at_or_before_stop,
            "terminal_cells_at_stop_timestamp": (terminal_at_or_before_stop - terminal_before_stop),
        }
    outgoing = evidence["outgoing"]
    incoming = evidence["incoming"]
    if (
        outgoing["scheduled_cells_at_stop"] != incoming["scheduled_cells_at_stop"]
        or outgoing["last_scheduled_target_us"] != incoming["last_scheduled_target_us"]
    ):
        raise ValueError("study handoff BuFLO paired stop schedule is inconsistent")
    return evidence


def _algorithm_diagnostics(
    run: Any,
    *,
    defense: str,
    runtime_kind: str,
    schedule_path: Path,
    events_path: Path,
    packets_path: Path,
    require_current: bool = True,
    require_latest_cs: bool | None = None,
) -> dict[str, Any]:
    if require_latest_cs is None:
        require_latest_cs = require_current
    require_current_trace = require_latest_cs if runtime_kind == "cs_buflo" else require_current
    if not isinstance(run, Mapping):
        raise ValueError("study handoff runner receipt is invalid")
    schedule_rows = _read_extended_runner_csv(
        schedule_path,
        SCHEDULE_PREFIX_FIELDS,
        label="schedule.csv",
        require_current_schema=require_current_trace,
    )
    events_rows = _read_extended_runner_csv(
        events_path,
        _EVENT_PREFIX_FIELDS,
        label="events.csv",
        require_current_schema=require_current_trace,
    )
    packets_rows = _read_extended_runner_csv(
        packets_path,
        _PACKET_PREFIX_FIELDS,
        label="packets.csv",
        require_current_schema=require_current_trace,
    )
    for index, row in enumerate(events_rows, 1):
        if row["terminal_defense_elapsed_us"]:
            raise ValueError(f"events.csv row {index} incorrectly carries a schedule terminal time")
        _csv_unsigned(row["monotonic_us"], label=f"events.csv row {index} monotonic_us")
        if row["connection"]:
            _csv_unsigned(row["connection"], label=f"events.csv row {index} connection")
        if not row["event"]:
            raise ValueError(f"events.csv row {index} has no event identity")
    for index, row in enumerate(packets_rows, 1):
        if row["terminal_defense_elapsed_us"]:
            raise ValueError(
                f"packets.csv row {index} incorrectly carries a schedule terminal time"
            )
        if row["direction"] not in {"outgoing", "incoming"}:
            raise ValueError(f"packets.csv row {index} has an invalid direction")
        if bool(row["scheduled_target"]) != bool(row["slot_id"]):
            raise ValueError(f"packets.csv row {index} has an incomplete scheduled packet identity")
        if row["direction"] == "incoming" and (row["scheduled_target"] or row["slot_id"]):
            raise ValueError(
                f"packets.csv row {index} incorrectly claims a scheduled incoming datagram"
            )
        if (
            row["direction"] == "outgoing"
            and not row["scheduled_target"]
            and row["qcsd_outcome_schema_version"]
            and row["send_policy"] != "unscheduled"
        ):
            raise ValueError(
                f"packets.csv row {index} gives an unscheduled packet a scheduled send policy"
            )
        for field in ("monotonic_us", "connection"):
            _csv_unsigned(row[field], label=f"packets.csv row {index} {field}")
        _csv_unsigned(
            row["observed_udp_length"],
            label=f"packets.csv row {index} observed UDP length",
            positive=True,
        )
        for field in ("scheduled_target", "slot_id"):
            if row[field]:
                _csv_unsigned(row[field], label=f"packets.csv row {index} {field}")
    for index, row in enumerate(schedule_rows, 1):
        direction = row["direction"]
        satisfaction = row["satisfaction"]
        if direction not in {"outgoing", "incoming"}:
            raise ValueError(f"schedule.csv row {index} has an invalid direction")
        size = _csv_unsigned(row["size"], label="schedule target size", positive=True)
        for field in ("target_time_us", "action_time_us", "slot_id"):
            _csv_unsigned(row[field], label=f"schedule {field}")
        connection = row["connection"]
        if connection:
            _csv_unsigned(connection, label="schedule connection")
        elif direction == "outgoing" and satisfaction != "missed":
            raise ValueError(f"schedule.csv row {index} realized outgoing event has no connection")
        if satisfaction not in {"satisfied", "missed", "full", "partial", "suppressed"}:
            raise ValueError(f"schedule.csv row {index} has an invalid satisfaction")
        if require_current_trace:
            if (
                row["qcsd_outcome_schema_version"] != "3"
                or not row["terminal_defense_elapsed_us"].isdecimal()
            ):
                raise ValueError(
                    "study handoff current schedule row lacks exact controller terminal time"
                )
            if _csv_unsigned(
                row["terminal_defense_elapsed_us"],
                label="schedule controller terminal time",
            ) < _csv_unsigned(row["target_time_us"], label="schedule target time"):
                raise ValueError("study handoff schedule terminal time predates its defense target")
        elif row["qcsd_outcome_schema_version"] == "3":
            _csv_unsigned(
                row["terminal_defense_elapsed_us"],
                label="schedule controller terminal time",
            )
        if satisfaction != "missed":
            expected_schema = (
                "3"
                if require_current_trace or row["qcsd_outcome_schema_version"] == "3"
                else ("2" if direction == "incoming" else "1")
            )
            if row["qcsd_outcome_schema_version"] != expected_schema:
                raise ValueError("study handoff terminal schedule row lacks typed evidence")
            if (
                _csv_unsigned(
                    row["desired_udp_bytes"], label="schedule desired size", positive=True
                )
                != size
            ):
                raise ValueError("study handoff schedule desired size differs from its target")
        if satisfaction == "satisfied":
            exact_observation_valid = (
                _csv_unsigned(row["observed_size"], label="schedule observed size") == size
                and _csv_unsigned(row["observed_udp_bytes"], label="schedule observed UDP size")
                == size
                if direction == "outgoing"
                else not row["observed_size"] and not row["observed_udp_bytes"]
            )
            if (
                row["send_policy"] != "exact"
                or not exact_observation_valid
                or row["miss_reason"]
                or any(row[field] for field in (*_COMPOSITION_FIELDS, "lateness_us"))
                or row["congestion_reason"]
            ):
                raise ValueError("study handoff exact schedule realization is invalid")
        elif satisfaction in {"full", "partial", "suppressed"}:
            observed = _csv_unsigned(row["observed_udp_bytes"], label="schedule observed UDP size")
            if row["send_policy"] != "congestion_sensitive":
                raise ValueError("study handoff CS schedule send policy is invalid")
            expected_reason = {
                "partial": {
                    "congestion_limited": "CongestionLimited",
                    "pacing_limited": "PacingLimited",
                }.get(row["congestion_reason"]),
                "suppressed": {
                    "congestion_limited": "CongestionLimited",
                    "pacing_limited": "PacingLimited",
                }.get(row["congestion_reason"]),
            }.get(satisfaction)
            if satisfaction == "full":
                valid = observed == size and row["observed_size"] == str(size)
                valid = valid and not row["miss_reason"] and not row["congestion_reason"]
            elif satisfaction == "partial":
                valid = 0 < observed < size and row["observed_size"] == str(observed)
                valid = valid and expected_reason == row["miss_reason"]
            else:
                valid = observed == 0 and not row["observed_size"]
                valid = valid and expected_reason == row["miss_reason"]
            if not valid:
                raise ValueError("study handoff CS schedule realization is invalid")
    diagnostics = run.get("defense_diagnostics")
    if not isinstance(diagnostics, Mapping):
        diagnostics = {}
    defense_start_ns = run.get("defense_start_monotonic_ns")
    if runtime_kind in {"buflo", "cs_buflo"}:
        _validate_candidate_schedule_diagnostic_counts(
            diagnostics,
            schedule_rows,
            runtime_kind=runtime_kind,
        )
        if require_current_trace:
            if type(defense_start_ns) is not int or defense_start_ns < 0:
                raise ValueError("study handoff candidate defense clock binding is unavailable")
            _validate_incoming_terminal_clock_bindings(
                schedule_rows,
                defense_start_monotonic_ns=defense_start_ns,
                runtime_kind=runtime_kind,
            )
    if runtime_kind == "cs_buflo":
        _validate_cs_buflo_outgoing_packet_evidence(
            schedule_rows,
            packets_rows,
            defense_start_monotonic_ns=(
                defense_start_ns if isinstance(defense_start_ns, int) else None
            ),
        )
    buflo_state: dict[str, Any] | None = None
    if runtime_kind == "buflo":
        summary = run.get("buflo_summary")
        summary_schema = summary.get("schema_version") if isinstance(summary, Mapping) else None
        parser_current = summary_schema in {3, 4}
        stop_drain_current = summary_schema == 4
        required = {
            "buflo_terminal_subcell_pending_request_cancellations",
            "buflo_terminal_subcell_stream_cancellations",
            "buflo_terminal_subcell_exact_capacity_bytes_cancelled",
        }
        if parser_current:
            required.add("buflo_terminal_subcell_pending_application_parser_boundaries_at_latch")
        required_diagnostics = required | (
            BUFLO_SCHEDULE_STOP_V4_KEYS if stop_drain_current else set()
        )
        if (
            not isinstance(summary, Mapping)
            or summary_schema not in {2, 3, 4}
            or (require_current and not stop_drain_current)
            or not required_diagnostics <= set(diagnostics)
            or not new_defense_terminal_receipts_valid(
                run,
                "buflo",
                require_application_complete=True,
                require_current_schema=require_current,
            )
        ):
            raise ValueError("study handoff BuFLO terminal-tail evidence is unavailable")
        counters = {key: diagnostics[key] for key in required}
        if any(type(value) is not int or value < 0 for value in counters.values()):
            raise ValueError("study handoff BuFLO terminal-tail counters are invalid")
        pending = counters["buflo_terminal_subcell_pending_request_cancellations"]
        streams = counters["buflo_terminal_subcell_stream_cancellations"]
        capacity = counters["buflo_terminal_subcell_exact_capacity_bytes_cancelled"]
        terminal_latched = diagnostics["buflo_terminal_subcell_latched"]
        terminal_latched_at_us = diagnostics["buflo_terminal_subcell_latched_at_us"]
        open_streams_at_latch = diagnostics["buflo_terminal_subcell_open_streams_at_latch"]
        parser_lease_bytes_at_latch = diagnostics[
            "buflo_terminal_subcell_parser_lease_bytes_at_latch"
        ]
        pending_parser_boundaries_at_latch = diagnostics[
            "buflo_terminal_subcell_pending_parser_boundaries_at_latch"
        ]
        pending_application_parser_boundaries_at_latch = diagnostics.get(
            "buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"
        )
        terminal_times: dict[str, list[int]] | None = None
        if stop_drain_current:
            if type(defense_start_ns) is not int or defense_start_ns < 0:
                raise ValueError("study handoff BuFLO defense clock binding is unavailable")
            terminal_times = _buflo_terminal_times(
                schedule_rows,
                packets_rows,
                defense_start_monotonic_ns=defense_start_ns,
            )
        responses = run.get("chaff_responses")
        if not isinstance(responses, list):
            raise ValueError("study handoff BuFLO chaff receipts are unavailable")
        receipt_cancellations = sum(
            isinstance(response, Mapping)
            and response.get("outcome") == "buflo_terminal_subcell_tail_cancelled"
            for response in responses
        )
        cancellation_events: list[tuple[int, str, Mapping[str, Any]]] = []
        for index, row in enumerate(events_rows, 1):
            if row["event"] != "action":
                continue
            try:
                details = json.loads(row["details"])
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"events.csv row {index} action details are invalid JSON"
                ) from error
            if isinstance(details, Mapping) and details.get("type") == "cancel_chaff":
                cancellation_events.append(
                    (
                        _csv_unsigned(
                            row["monotonic_us"],
                            label=f"events.csv row {index} cancellation time",
                        ),
                        row["outcome"],
                        details,
                    )
                )
        typed_cancellation_events = [
            item
            for item in cancellation_events
            if item[1] == "applied"
            and set(item[2]) == {"type", "endpoint", "stream", "reason"}
            and item[2].get("reason") == "buflo_terminal_subcell_tail"
            and type(item[2].get("endpoint")) is int
            and item[2]["endpoint"] >= 0
            and type(item[2].get("stream")) is int
            and item[2]["stream"] >= 0
        ]
        cancellation_targets = {
            (item[2]["endpoint"], item[2]["stream"]) for item in typed_cancellation_events
        }
        exact_outgoing_times = (
            terminal_times["outgoing"]
            if terminal_times is not None
            else [
                _csv_unsigned(row["monotonic_us"], label="packets.csv exact outgoing time")
                for row in packets_rows
                if row["direction"] == "outgoing"
                and row["scheduled_target"]
                and row["send_policy"] == "exact"
            ]
        )
        raw_typed_cancellation_times = [at for at, _, _ in typed_cancellation_events]
        cancellation_time_bounds = (
            [
                _defense_elapsed_us_bounds(
                    at,
                    defense_start_monotonic_ns=defense_start_ns,
                    label="events.csv BuFLO cancellation time",
                )
                for at in raw_typed_cancellation_times
            ]
            if terminal_times is not None
            else [(at, at) for at in raw_typed_cancellation_times]
        )
        first_cancellation_us = (
            min(lower for lower, _ in cancellation_time_bounds)
            if cancellation_time_bounds
            else None
        )
        first_cancellation_upper_us = (
            min(upper for _, upper in cancellation_time_bounds)
            if cancellation_time_bounds
            else None
        )
        incoming_terminal_times = (
            terminal_times["incoming"]
            if terminal_times is not None
            else [
                _csv_unsigned(
                    row["credit_consumed_at_us"],
                    label="schedule incoming terminal consumption time",
                )
                for row in schedule_rows
                if row["direction"] == "incoming" and row["satisfaction"] == "satisfied"
            ]
        )
        scheduled_terminal_times = exact_outgoing_times + incoming_terminal_times
        last_scheduled_terminal_us = (
            max(scheduled_terminal_times) if scheduled_terminal_times else None
        )
        post_cancellation_control_rows = [
            row
            for row in packets_rows
            if raw_typed_cancellation_times
            and row["direction"] == "outgoing"
            and row["qcsd_outcome_schema_version"] == "2"
            and row["send_policy"] == "unscheduled"
            and _csv_unsigned(
                row["defense_control_bytes"],
                label="packets.csv terminal defense-control bytes",
            )
            > 0
            and _csv_unsigned(row["monotonic_us"], label="packets.csv terminal control time")
            >= max(raw_typed_cancellation_times)
        ]
        raw_post_cancellation_control_times = [
            _csv_unsigned(row["monotonic_us"], label="packets.csv terminal control time")
            for row in post_cancellation_control_rows
        ]
        post_cancellation_control_times = (
            [
                _defense_elapsed_us_bounds(
                    at,
                    defense_start_monotonic_ns=defense_start_ns,
                    label="packets.csv terminal control time",
                )[0]
                for at in raw_post_cancellation_control_times
            ]
            if terminal_times is not None
            else raw_post_cancellation_control_times
        )
        post_cancellation_control_bytes = sum(
            _csv_unsigned(
                row["defense_control_bytes"],
                label="packets.csv terminal defense-control bytes",
                positive=True,
            )
            for row in post_cancellation_control_rows
        )
        policy = BUFLO_TERMINAL_SUBCELL_POLICY
        observer_effect = BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT
        if (
            summary.get("terminal_subcell_policy") != policy
            or summary.get("terminal_subcell_observer_effect") != observer_effect
            or (
                stop_drain_current
                and summary.get("terminal_schedule_stop_policy") != BUFLO_SCHEDULE_STOP_POLICY
            )
            or summary.get("diagnostics") != diagnostics
            or not buflo_terminal_diagnostics_valid(diagnostics, require_current=stop_drain_current)
            or receipt_cancellations != streams
            or len(cancellation_events) != streams
            or len(typed_cancellation_events) != streams
            or len(cancellation_targets) != streams
            or (streams == 0 and capacity != 0)
            or (streams > 0 and not 0 <= capacity < 1_200)
            or (
                streams > 0
                and (
                    first_cancellation_us is None
                    or first_cancellation_upper_us is None
                    or not exact_outgoing_times
                    or last_scheduled_terminal_us is None
                    or first_cancellation_us < last_scheduled_terminal_us
                    or first_cancellation_upper_us < terminal_latched_at_us
                    or not post_cancellation_control_rows
                )
            )
            or (
                last_scheduled_terminal_us is not None
                and terminal_latched_at_us < last_scheduled_terminal_us
            )
        ):
            raise ValueError("study handoff BuFLO terminal-tail evidence is inconsistent")
        buflo_state = {
            "terminal_subcell_policy": policy,
            "terminal_subcell_observer_effect": observer_effect,
            "pending_request_cancellations": pending,
            "stream_cancellations": streams,
            "receipt_cancellations": receipt_cancellations,
            "exact_capacity_bytes_cancelled": capacity,
            "whole_cell_floor_bytes": 1_200,
            "terminal_latched": terminal_latched,
            "terminal_latched_at_us": terminal_latched_at_us,
            "open_streams_at_latch": open_streams_at_latch,
            "parser_lease_bytes_at_latch": parser_lease_bytes_at_latch,
            "pending_parser_boundaries_at_latch": pending_parser_boundaries_at_latch,
            "typed_cancellation_action_events": len(typed_cancellation_events),
            "first_cancellation_monotonic_us": first_cancellation_us,
            "last_exact_outgoing_cell_monotonic_us": (
                max(exact_outgoing_times) if exact_outgoing_times else None
            ),
            "last_scheduled_terminal_monotonic_us": last_scheduled_terminal_us,
            "control_evidence_semantics": BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS,
            "post_cancellation_unscheduled_defense_control_packets": len(
                post_cancellation_control_rows
            ),
            "post_cancellation_unscheduled_defense_control_bytes": (
                post_cancellation_control_bytes
            ),
            "first_post_cancellation_defense_control_monotonic_us": (
                min(post_cancellation_control_times) if post_cancellation_control_times else None
            ),
            "last_post_cancellation_defense_control_monotonic_us": (
                max(post_cancellation_control_times) if post_cancellation_control_times else None
            ),
            "paper_equivalent": False,
            "implementation_scope": "client_only_quic",
        }
        if parser_current:
            buflo_state = {
                "schema_version": 2,
                **buflo_state,
                "pending_application_parser_boundaries_at_latch": (
                    pending_application_parser_boundaries_at_latch
                ),
            }
        if stop_drain_current:
            assert terminal_times is not None
            stop_drain_ledger = _buflo_stop_drain_ledger(diagnostics, schedule_rows, terminal_times)
            buflo_state = {
                **buflo_state,
                "schema_version": 3,
                "schedule_stop": {
                    "policy": BUFLO_SCHEDULE_STOP_POLICY,
                    "terminal_time_semantics": (BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS),
                    "latched": diagnostics["buflo_schedule_stop_latched"],
                    "latched_at_us": diagnostics["buflo_schedule_stop_latched_at_us"],
                    "available_bytes": diagnostics["buflo_schedule_stop_available_bytes"],
                    "required_bytes": diagnostics["buflo_schedule_stop_required_bytes"],
                    "directions": stop_drain_ledger,
                },
            }
        if not buflo_terminal_state_valid(buflo_state):
            raise ValueError("study handoff BuFLO terminal-tail state is invalid")
    cs_state: dict[str, Any] | None = None
    if runtime_kind == "cs_buflo":
        summary = run.get("cs_buflo_summary")
        if not isinstance(summary, Mapping):
            raise ValueError("study handoff CS-BuFLO summary is unavailable")
        cs_summary_schema = summary.get("schema_version")
        current_cs_summary = cs_summary_schema in {3, 4}
        stop_drain_current = cs_summary_schema == 4
        required = {
            "cs_buflo_payload_padding",
            "cs_buflo_total_padding",
            "cs_buflo_early_termination_semantics",
            "cs_buflo_outgoing_padding_basis_natural_bytes",
            "cs_buflo_incoming_padding_basis_natural_bytes",
            "cs_buflo_outgoing_padding_basis_cover_bytes",
            "cs_buflo_incoming_padding_basis_cover_bytes",
            "cs_buflo_outgoing_padding_basis_total_bytes",
            "cs_buflo_incoming_padding_basis_total_bytes",
            "cs_buflo_outgoing_padding_target_bytes",
            "cs_buflo_incoming_padding_target_bytes",
            "cs_buflo_outgoing_interval_us",
            "cs_buflo_incoming_interval_us",
            "cs_buflo_outgoing_rate_adaptations",
            "cs_buflo_incoming_rate_adaptations",
            "cs_buflo_rate_boundary_translation_version",
            "cs_buflo_rate_boundary_counter_semantics",
            "cs_buflo_author_rate_boundary_counter_semantics",
            "cs_buflo_rate_transitions",
            "cs_buflo_next_outgoing_adaptation_boundary_bytes",
            "cs_buflo_next_incoming_adaptation_boundary_bytes",
            "cs_buflo_outgoing_estimator_samples",
            "cs_buflo_incoming_estimator_samples",
            "cs_buflo_outgoing_power_of_two_crossed",
            "cs_buflo_incoming_power_of_two_crossed",
            "cs_buflo_outgoing_minimum_interval_opportunities",
            "cs_buflo_incoming_minimum_interval_opportunities",
            "cs_buflo_incoming_minimum_interval_local_realized",
            "cs_buflo_outgoing_minimum_interval_terminal",
            "cs_buflo_incoming_minimum_interval_terminal",
            "cs_buflo_outgoing_minimum_interval_full",
            "cs_buflo_incoming_minimum_interval_full",
            "cs_buflo_incoming_local_realized_cells",
            "cs_buflo_local_termination_latched",
            "cs_buflo_local_et_pending_request_cancellations",
            "cs_buflo_local_et_stream_cancellations",
        }
        if current_cs_summary:
            required.update(CS_BUFLO_LOCAL_ET_V3_KEYS)
        if stop_drain_current:
            required.update(
                {
                    *CS_BUFLO_STOP_DRAIN_V4_KEYS,
                    "cs_buflo_outgoing_termination_accounted_bytes",
                    "cs_buflo_incoming_termination_accounted_bytes",
                    "cs_buflo_outgoing_last_termination_increment_bytes",
                    "cs_buflo_incoming_last_termination_increment_bytes",
                }
            )
        if (
            not required <= set(diagnostics)
            or (require_current and not current_cs_summary)
            or (not require_current and cs_summary_schema != 2)
            or (require_latest_cs and cs_summary_schema != 4)
            or not new_defense_terminal_receipts_valid(
                run,
                "cs_buflo",
                require_application_complete=True,
                require_current_schema=require_latest_cs,
            )
            or not cs_buflo_local_et_handoff_valid(diagnostics, require_current=current_cs_summary)
        ):
            raise ValueError("study handoff CS-BuFLO runner diagnostics are incomplete")
        stop_drain_ledger = (
            _cs_buflo_stop_drain_ledger(diagnostics, schedule_rows) if stop_drain_current else None
        )
        cs_state = {
            "padding_variant": (
                "CPSP"
                if diagnostics["cs_buflo_payload_padding"] is True
                and diagnostics["cs_buflo_total_padding"] is False
                else "CTSP"
                if diagnostics["cs_buflo_total_padding"] is True
                and diagnostics["cs_buflo_payload_padding"] is False
                else "invalid"
            ),
            "early_termination_semantics": diagnostics["cs_buflo_early_termination_semantics"],
            **(
                {
                    "early_termination_translation": {
                        "version": diagnostics["cs_buflo_early_termination_translation_version"],
                        "stop_policy": diagnostics["cs_buflo_termination_stop_policy"],
                    }
                }
                if stop_drain_current
                else {}
            ),
            "incoming_boundaries": {
                "cadence": summary.get("incoming_cadence_boundary"),
                "terminal": summary.get("incoming_terminal_boundary"),
                "separation": summary.get("incoming_boundary_separation"),
            },
            "rate_boundary_translation": {
                "version": diagnostics["cs_buflo_rate_boundary_translation_version"],
                "live_counter_semantics": diagnostics["cs_buflo_rate_boundary_counter_semantics"],
                "author_counter_semantics": diagnostics[
                    "cs_buflo_author_rate_boundary_counter_semantics"
                ],
                "expected_difference": (
                    "author advances on actually transmitted real-plus-junk bytes; "
                    "the client-only QCSD translation advances on exact fresh application "
                    "STREAM bytes and excludes retransmission and defense-added bytes"
                ),
            },
            "rate_transitions": diagnostics["cs_buflo_rate_transitions"],
            "local_termination": {
                "latched": diagnostics["cs_buflo_local_termination_latched"],
                "pending_request_cancellations": diagnostics[
                    "cs_buflo_local_et_pending_request_cancellations"
                ],
                "stream_cancellations": diagnostics["cs_buflo_local_et_stream_cancellations"],
                **(
                    {
                        "latched_at_us": diagnostics["cs_buflo_local_et_latched_at_us"],
                        "before_application_complete": diagnostics[
                            "cs_buflo_local_et_before_application_complete"
                        ],
                        "application_receive_streams_handed_off": diagnostics[
                            "cs_buflo_local_et_application_receive_streams_handed_off"
                        ],
                        "application_parser_boundaries_handed_off": diagnostics[
                            "cs_buflo_local_et_application_parser_boundaries_handed_off"
                        ],
                        "application_parser_lease_bytes_handed_off": diagnostics[
                            "cs_buflo_local_et_application_parser_lease_bytes_handed_off"
                        ],
                        "application_send_endpoints_released": diagnostics[
                            "cs_buflo_local_et_application_send_endpoints_released"
                        ],
                        "post_local_et_natural_outgoing_bytes": diagnostics[
                            "cs_buflo_post_local_et_natural_outgoing_bytes"
                        ],
                        "post_local_et_natural_incoming_bytes": diagnostics[
                            "cs_buflo_post_local_et_natural_incoming_bytes"
                        ],
                    }
                    if require_current
                    else {}
                ),
            },
            "incoming_local_realized_cells": diagnostics["cs_buflo_incoming_local_realized_cells"],
            "directions": {
                direction: {
                    **(
                        {
                            "natural_bytes": diagnostics[f"cs_buflo_natural_{direction}_bytes"],
                            "real_bearing_bytes": diagnostics[
                                f"cs_buflo_real_bearing_{direction}_bytes"
                            ],
                            "post_local_et_natural_bytes": diagnostics[
                                f"cs_buflo_post_local_et_natural_{direction}_bytes"
                            ],
                        }
                        if require_current
                        else {}
                    ),
                    "terminal_interval_us": diagnostics[f"cs_buflo_{direction}_interval_us"],
                    "rate_adaptations": diagnostics[f"cs_buflo_{direction}_rate_adaptations"],
                    "next_adaptation_boundary_bytes": diagnostics[
                        f"cs_buflo_next_{direction}_adaptation_boundary_bytes"
                    ],
                    "estimator_samples": diagnostics[f"cs_buflo_{direction}_estimator_samples"],
                    "padding_basis_natural_bytes": diagnostics[
                        f"cs_buflo_{direction}_padding_basis_natural_bytes"
                    ],
                    "padding_basis_cover_bytes": diagnostics[
                        f"cs_buflo_{direction}_padding_basis_cover_bytes"
                    ],
                    "padding_basis_total_bytes": diagnostics[
                        f"cs_buflo_{direction}_padding_basis_total_bytes"
                    ],
                    "padding_target_bytes": diagnostics[
                        f"cs_buflo_{direction}_padding_target_bytes"
                    ],
                    "power_of_two_crossed": diagnostics[
                        f"cs_buflo_{direction}_power_of_two_crossed"
                    ],
                    **(
                        {
                            "termination_accounted_bytes": diagnostics[
                                f"cs_buflo_{direction}_termination_accounted_bytes"
                            ],
                            "last_termination_increment_bytes": diagnostics[
                                f"cs_buflo_{direction}_last_termination_increment_bytes"
                            ],
                            "termination_stop_latched": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_latched"
                            ],
                            "termination_stop_crossing_total_bytes": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_crossing_total_bytes"
                            ],
                            "termination_stop_crossing_increment_bytes": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_crossing_increment_bytes"
                            ],
                            "termination_stop_reason": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_reason"
                            ],
                            "termination_stop_phase": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_phase"
                            ],
                            "termination_stop_latched_at_us": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_latched_at_us"
                            ],
                            "termination_stop_scheduled_cells_at_stop": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_scheduled_cells_at_stop"
                            ],
                            "termination_stop_terminal_cells_at_stop": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_terminal_cells_at_stop"
                            ],
                            "termination_stop_progress_bytes_at_stop": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_progress_bytes_at_stop"
                            ],
                            "termination_stop_padding_target_bytes_at_stop": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_padding_target_bytes_at_stop"
                            ],
                            "termination_stop_provisional_invalidation_count": diagnostics[
                                f"cs_buflo_{direction}_termination_stop_provisional_invalidation_count"
                            ],
                            "stop_drain_ledger": stop_drain_ledger[direction],
                        }
                        if stop_drain_current
                        else {}
                    ),
                    "minimum_interval_opportunities": diagnostics[
                        f"cs_buflo_{direction}_minimum_interval_opportunities"
                    ],
                    "minimum_interval_terminal": diagnostics[
                        f"cs_buflo_{direction}_minimum_interval_terminal"
                    ],
                    "minimum_interval_full": diagnostics[
                        f"cs_buflo_{direction}_minimum_interval_full"
                    ],
                    "minimum_interval_local_realized": (
                        diagnostics["cs_buflo_incoming_minimum_interval_local_realized"]
                        if direction == "incoming"
                        else None
                    ),
                    "incoming_local_realized_cells": (
                        diagnostics["cs_buflo_incoming_local_realized_cells"]
                        if direction == "incoming"
                        else None
                    ),
                    "rate_transitions": [
                        transition
                        for transition in diagnostics["cs_buflo_rate_transitions"]
                        if transition["direction"] == direction
                    ],
                }
                for direction in ("outgoing", "incoming")
            },
        }
        if cs_state["padding_variant"] == "invalid":
            raise ValueError("study handoff CS-BuFLO padding variant is invalid")
        expected_early_termination_semantics = (
            CS_BUFLO_EARLY_TERMINATION_SEMANTICS
            if stop_drain_current
            else CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS
        )
        if (
            cs_state["early_termination_semantics"] != expected_early_termination_semantics
            or (
                stop_drain_current
                and cs_state.get("early_termination_translation")
                != {
                    "version": CS_BUFLO_EARLY_TERMINATION_TRANSLATION_VERSION,
                    "stop_policy": CS_BUFLO_TERMINATION_STOP_POLICY,
                }
            )
            or cs_state["incoming_boundaries"]
            != {
                "cadence": CS_BUFLO_INCOMING_CADENCE_BOUNDARY,
                "terminal": CS_BUFLO_INCOMING_TERMINAL_BOUNDARY,
                "separation": CS_BUFLO_INCOMING_BOUNDARY_SEPARATION,
            }
            or cs_state["rate_boundary_translation"]
            != {
                "version": CS_BUFLO_RATE_BOUNDARY_TRANSLATION_VERSION,
                "live_counter_semantics": CS_BUFLO_RATE_BOUNDARY_COUNTER_SEMANTICS,
                "author_counter_semantics": (CS_BUFLO_AUTHOR_RATE_BOUNDARY_COUNTER_SEMANTICS),
                "expected_difference": (
                    "author advances on actually transmitted real-plus-junk bytes; "
                    "the client-only QCSD translation advances on exact fresh application "
                    "STREAM bytes and excludes retransmission and defense-added bytes"
                ),
            }
            or not _cs_buflo_rate_transition_vector_valid(cs_state["rate_transitions"])
            or cs_state["local_termination"]["latched"] is not True
        ):
            raise ValueError("study handoff CS-BuFLO translation/termination state is invalid")
    return {
        "schema_version": (
            4
            if (
                runtime_kind == "cs_buflo"
                and isinstance(cs_state, Mapping)
                and "early_termination_translation" in cs_state
            )
            or (
                runtime_kind == "buflo"
                and isinstance(buflo_state, Mapping)
                and buflo_state.get("schema_version") == 3
            )
            else 3
            if require_current
            or (
                runtime_kind == "buflo"
                and isinstance(buflo_state, Mapping)
                and buflo_state.get("schema_version") == 2
            )
            else 2
        ),
        "mode": defense,
        "runtime_kind": runtime_kind,
        "classifier_input": False,
        "peer_reproduction": {
            "incoming_scheduled_cells_semantics": "client-receive-credit-and-chaff-attempts",
            "incoming_cadence_boundary": (
                CS_BUFLO_INCOMING_CADENCE_BOUNDARY
                if runtime_kind == "cs_buflo"
                else "fixed_local_on_wire_receive_credit_advertisement"
            ),
            "incoming_terminal_boundary": (
                CS_BUFLO_INCOMING_TERMINAL_BOUNDARY
                if runtime_kind == "cs_buflo"
                else "eventual_peer_stream_offset_consumption"
            ),
            "scheduled_server_datagram_timing_available": False,
            "scheduled_server_datagram_size_available": False,
            "bilateral_peer_defense_reproduced": False,
        },
        "runner_rows": {
            "schedule": len(schedule_rows),
            "events": len(events_rows),
            "packets": len(packets_rows),
            "typed_events": sum(bool(row["qcsd_outcome_schema_version"]) for row in events_rows),
            "typed_packets": sum(bool(row["qcsd_outcome_schema_version"]) for row in packets_rows),
        },
        "directions": {
            direction: _direction_algorithm_metrics(
                schedule_rows, direction=direction, runtime_kind=runtime_kind
            )
            for direction in ("outgoing", "incoming")
        },
        "buflo_state": buflo_state,
        "cs_buflo_state": cs_state,
    }


def _validate_handoff_rows(
    root: Path, rows: Sequence[Mapping[str, Any]], *, formal: bool
) -> tuple[bool, bool]:
    expected_files = {"README.md", "dataset.json", "samples.jsonl"}
    seen_samples: set[str] = set()
    seen_paths: set[str] = set()
    current_detailed_rows = [set(row) == _ROW_KEYS | _RUNNER_DIAGNOSTIC_ROW_KEYS for row in rows]
    legacy_detailed_rows = [
        set(row) == _ROW_KEYS | _LEGACY_RUNNER_DIAGNOSTIC_ROW_KEYS for row in rows
    ]
    historical_rows = [set(row) == _ROW_KEYS for row in rows]
    if not rows or not (
        all(current_detailed_rows) or all(legacy_detailed_rows) or all(historical_rows)
    ):
        raise ValueError("study handoff sample row schema is invalid")
    current_detailed = all(current_detailed_rows)
    legacy_detailed = all(legacy_detailed_rows)
    detailed = current_detailed or legacy_detailed
    if formal and not current_detailed:
        raise ValueError(
            "formal study handoff requires sealed runner diagnostics and workload inputs"
        )
    for row in rows:
        if row.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("study handoff sample row schema is invalid")
        sample_id = row.get("sample_id")
        workload_id = row.get("workload_id")
        defense = row.get("defense")
        request_policy = row.get("request_policy")
        for label, value in (
            ("sample ID", sample_id),
            ("workload ID", workload_id),
            ("defense", defense),
            ("request policy", request_policy),
        ):
            if not isinstance(value, str) or _COMPONENT.fullmatch(value) is None:
                raise ValueError(f"study handoff {label} is invalid")
        if sample_id in seen_samples:
            raise ValueError("study handoff sample IDs are not unique")
        seen_samples.add(sample_id)
        visit = row.get("visit")
        block = row.get("acquisition_block_index")
        if (
            type(visit) is not int
            or visit < 0
            or type(row.get("seed")) is not int
            or type(row.get("attempts")) is not int
            or row["attempts"] <= 0
            or type(block) is not int
            or block < 0
            or type(row.get("packet_count")) is not int
            or row["packet_count"] <= 0
            or type(row.get("baseline")) is not bool
        ):
            raise ValueError("study handoff sample numeric identity is invalid")
        if (
            not isinstance(row.get("class_label"), str)
            or row["class_label"] != CLASS_LABELS.get(workload_id, workload_id)
            or not isinstance(row.get("runtime_kind"), str)
            or not row["runtime_kind"]
            or not isinstance(row.get("source_result"), str)
            or not row["source_result"]
            or row.get("acquisition_block_id") != f"acquisition-block-{block + 1:03d}"
            or row.get("split") != _split_for_block(block)
        ):
            raise ValueError("study handoff sample declarations are invalid")
        expected_source = f"samples/{workload_id}/{request_policy}/visit-{visit:03d}/{defense}"
        expected_pair = f"block-{block + 1:03d}/{workload_id}/{request_policy}/visit-{visit:03d}"
        if (
            row.get("source_sample_path") != expected_source
            or row.get("paired_visit_id") != expected_pair
        ):
            raise ValueError("study handoff sample source or pair binding is invalid")
        if formal and ((defense == "undefended") is not row["baseline"]):
            raise ValueError("formal study handoff baseline role is invalid")
        if formal and workload_id not in CLASS_LABELS:
            raise ValueError("formal study handoff workload identity is invalid")
        _validate_input_bindings(
            row.get("input_bindings"),
            baseline=row["baseline"],
            runtime_kind=str(row["runtime_kind"]),
        )

        artifacts: tuple[tuple[str, str, str], ...] = (
            ("raw_pcapng_path", "raw_pcapng_sha256", f"raw/{sample_id}.pcapng"),
            ("raw_pcap_path", "raw_pcap_sha256", f"raw/{sample_id}.pcap"),
            ("raw_run_path", "raw_run_sha256", f"raw/{sample_id}.run.json"),
            ("shape_pcap_path", "shape_pcap_sha256", f"stripped/{sample_id}.pcap"),
            ("trace_path", "trace_sha256", f"traces/{sample_id}.csv"),
        )
        if detailed:
            artifacts += (
                (
                    "runner_schedule_path",
                    "runner_schedule_sha256",
                    f"diagnostics/{sample_id}.schedule.csv",
                ),
                (
                    "runner_events_path",
                    "runner_events_sha256",
                    f"diagnostics/{sample_id}.events.csv",
                ),
                (
                    "runner_packets_path",
                    "runner_packets_sha256",
                    f"diagnostics/{sample_id}.packets.csv",
                ),
            )
        for path_key, digest_key, expected_relative in artifacts:
            relative = row.get(path_key)
            digest = row.get(digest_key)
            if relative != expected_relative or _DIGEST.fullmatch(str(digest)) is None:
                raise ValueError("study handoff sample artifact binding is invalid")
            if relative in seen_paths:
                raise ValueError("study handoff artifact path is shared by samples")
            seen_paths.add(relative)
            candidate = (root / relative).resolve()
            if (
                not candidate.is_relative_to(root)
                or candidate.is_symlink()
                or not candidate.is_file()
                or sha256_file(candidate) != digest
            ):
                raise ValueError("study handoff sample artifact digest mismatch")
            expected_files.add(relative)
        if current_detailed:
            workload_relative = f"inputs/acquisition-block-{block + 1:03d}/{workload_id}.json"
            workload_digest = row.get("application_workload_sha256")
            workload_path = row.get("application_workload_path")
            if (
                workload_path != workload_relative
                or workload_digest != row["input_bindings"]["application_workload_sha256"]
                or _DIGEST.fullmatch(str(workload_digest)) is None
            ):
                raise ValueError("study handoff application workload binding is invalid")
            workload_candidate = (root / workload_relative).resolve()
            if (
                not workload_candidate.is_relative_to(root)
                or workload_candidate.is_symlink()
                or not workload_candidate.is_file()
                or sha256_file(workload_candidate) != workload_digest
            ):
                raise ValueError("study handoff application workload digest is invalid")
            expected_files.add(workload_relative)
        if detailed:
            run = load_json(root / str(row["raw_run_path"]))
            stored_diagnostics = row.get("algorithm_diagnostics")
            stored_schema = (
                stored_diagnostics.get("schema_version")
                if isinstance(stored_diagnostics, Mapping)
                else None
            )
            stored_runtime_kind = row.get("runtime_kind")
            supported_stored_schemas = (
                {3, 4} if stored_runtime_kind in {"buflo", "cs_buflo"} else {3}
            )
            if formal and stored_runtime_kind in {"buflo", "cs_buflo"} and stored_schema != 4:
                raise ValueError(
                    "formal study handoff requires current candidate algorithm evidence"
                )
            if current_detailed and stored_schema not in supported_stored_schemas:
                raise ValueError(
                    "current study handoff requires the current mode-specific "
                    "algorithm diagnostic schema"
                )
            expected_diagnostics = _algorithm_diagnostics(
                run,
                defense=str(defense),
                runtime_kind=str(row["runtime_kind"]),
                schedule_path=root / str(row["runner_schedule_path"]),
                events_path=root / str(row["runner_events_path"]),
                packets_path=root / str(row["runner_packets_path"]),
                require_current=(
                    stored_schema == 4
                    if stored_runtime_kind == "buflo"
                    else stored_schema in {3, 4}
                ),
                require_latest_cs=stored_schema == 4,
            )
            if row.get("algorithm_diagnostics") != expected_diagnostics:
                raise ValueError("study handoff algorithm diagnostics do not match runner evidence")
            if current_detailed:
                _validate_handoff_sample_correctness(
                    row,
                    run=run,
                    workload_path=workload_candidate,
                    schedule_path=root / str(row["runner_schedule_path"]),
                    formal=formal,
                )

    actual_files = set(_regular_tree_files(root, exclude={"SHA256SUMS"}))
    if actual_files != expected_files:
        raise ValueError("study handoff sample inventory is not exact")
    return detailed, legacy_detailed


def _validate_formal_sample_redirect_attestation(
    diagnostics: Mapping[str, Any],
    workload: Any,
    sample_path: Path,
) -> None:
    """Recompute the stored empty-redirect proof from sealed sample evidence."""

    expected = _redirect_attestation(workload, sample_path)
    if diagnostics.get("redirect_attestation") != expected:
        raise ValueError("formal result does not explicitly attest empty prepared/final redirects")


def _validate_source_results(receipts: Sequence[VerifiedResult], *, formal: bool) -> None:
    if formal and len(receipts) != len(FORMAL_BLOCKS):
        raise ValueError("formal handoff requires ten ordered result roots")
    names = tuple(str(receipt.experiment["name"]) for receipt in receipts)
    if formal and names != FORMAL_RESULT_NAMES:
        raise ValueError("formal handoff result order or identity is invalid")
    sources: list[Any] = []
    identity_keys = (
        "sample_id",
        "workload_id",
        "request_policy",
        "visit",
        "defense",
        "runtime_kind",
        "baseline",
        "seed",
        "path",
    )
    for block_index, receipt in enumerate(receipts):
        experiment = receipt.experiment
        summary = experiment.get("summary")
        samples = experiment.get("samples")
        if (
            experiment.get("status") != "complete"
            or experiment.get("purpose") != "evaluation"
            or not isinstance(samples, list)
            or not samples
            or not isinstance(summary, Mapping)
            or summary.get("planned") != len(samples)
            or summary.get("accepted") != len(samples)
            or summary.get("eligible") != len(samples)
            or summary.get("failed") != 0
            or summary.get("passed") is not True
        ):
            raise ValueError("study handoff requires complete all-eligible results")
        if any(
            sample.get("state") != "accepted" or sample.get("eligible") is not True
            for sample in samples
        ):
            raise ValueError("study handoff rejects ineligible samples")
        for sample in samples:
            validate_accepted_scheduler_runtime_receipt(
                receipt.root,
                experiment,
                sample,
            )
        if formal and any(
            type(sample.get("attempts")) is not int or not 1 <= sample["attempts"] <= 3
            for sample in samples
        ):
            raise ValueError("formal result exceeds the prospective three-attempt total cap")
        if formal and {str(sample["defense"]) for sample in samples} != set(FORMAL_DEFENSES):
            raise ValueError("formal result defense set is invalid")
        if formal:
            campaign_path = _formal_campaign_path_for_result(receipt, block_index)
            campaign, expected_configuration = _expected_formal_configuration(campaign_path)
            configuration = experiment.get("configuration")
            if (
                experiment.get("name") != campaign.name
                or not isinstance(configuration, Mapping)
                or set(configuration)
                != set(expected_configuration) | _FORMAL_DYNAMIC_CONFIGURATION_KEYS
                or {
                    key: value
                    for key, value in configuration.items()
                    if key not in _FORMAL_DYNAMIC_CONFIGURATION_KEYS
                }
                != expected_configuration
            ):
                raise ValueError("formal result does not bind its exact checked-in campaign inputs")
            _validate_formal_result_admission(
                receipt.root,
                campaign_path,
                configuration,
                expected_source=experiment["source"],
            )
            sealed_workloads = {}
            for workload in campaign.workloads:
                sealed_candidate = receipt.root / f"inputs/workloads/{workload.id}.json"
                sealed_path = sealed_candidate.resolve()
                if (
                    not sealed_path.is_relative_to(receipt.root.resolve())
                    or sealed_candidate.is_symlink()
                    or not sealed_candidate.is_file()
                ):
                    raise ValueError(
                        "formal result sealed workload differs from its checked-in campaign"
                    )
                sealed_bytes = sealed_candidate.read_bytes()
                if hashlib.sha256(sealed_bytes).hexdigest() != workload.sha256:
                    raise ValueError(
                        "formal result sealed workload differs from its checked-in campaign"
                    )
                sealed_data = json.loads(sealed_bytes)
                if not isinstance(sealed_data, dict):
                    raise ValueError("formal result sealed workload is not an object")
                sealed_workloads[workload.id] = replace(
                    workload,
                    path=sealed_path,
                    source_bytes=sealed_bytes,
                    data=sealed_data,
                )
            expected_plan = plan_campaign(campaign)
            actual_identity = [
                tuple(sample.get(key) for key in identity_keys) for sample in samples
            ]
            expected_identity = [
                tuple(sample.get(key) for key in identity_keys) for sample in expected_plan
            ]
            if actual_identity != expected_identity:
                raise ValueError("formal result sample identity/order differs from its campaign")
            if {str(sample["workload_id"]) for sample in samples} != set(CLASS_LABELS):
                raise ValueError("formal result workload set is invalid")
            from .buflo_study import _validate_public_network_condition

            for sample in samples:
                diagnostics = sample.get("diagnostics")
                if not isinstance(diagnostics, Mapping):
                    raise ValueError("formal result sample diagnostics are missing")
                _validate_public_network_condition(diagnostics)
                workload = sealed_workloads.get(str(sample.get("workload_id")))
                if workload is None:
                    raise ValueError("formal result sample workload is not sealed")
                _validate_formal_sample_redirect_attestation(
                    diagnostics,
                    workload,
                    resolved_sample_directory(
                        receipt.root,
                        sample,
                        require_directory=True,
                    ),
                )
        source = experiment.get("source")
        sources.append(source)
        if formal and (not isinstance(source, Mapping) or not _immutable_source(source)):
            raise ValueError("formal handoff requires a clean immutable execution source")
    if any(source != sources[0] for source in sources[1:]):
        raise ValueError("study handoff result roots do not share one execution source")
    if formal:
        _formal_temporal_proof(
            [
                {
                    "acquisition_block_index": index,
                    "acquisition_block_id": f"acquisition-block-{index + 1:03d}",
                    "result_name": receipt.experiment["name"],
                    "started_at": receipt.experiment["started_at"],
                    "completed_at": receipt.experiment["completed_at"],
                    "elapsed_seconds": _elapsed_seconds(receipt.experiment),
                }
                for index, receipt in enumerate(receipts)
            ]
        )


def _parse_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{label} timestamp must include a timezone")
    return parsed


def _elapsed_seconds(experiment: Mapping[str, Any]) -> float:
    started = _parse_timestamp(experiment.get("started_at"), label="experiment start")
    completed = _parse_timestamp(experiment.get("completed_at"), label="experiment completion")
    elapsed = (completed - started).total_seconds()
    if not math.isfinite(elapsed) or elapsed <= 0:
        raise ValueError("experiment completion must be after its start")
    return elapsed


def _formal_temporal_proof(blocks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if len(blocks) != len(FORMAL_BLOCKS):
        raise ValueError("formal temporal proof requires all ten acquisition blocks")
    timeline = []
    prior_completed: datetime | None = None
    for index, block in enumerate(blocks):
        started = _parse_timestamp(block.get("started_at"), label=f"formal block {index + 1} start")
        completed = _parse_timestamp(
            block.get("completed_at"), label=f"formal block {index + 1} completion"
        )
        elapsed = (completed - started).total_seconds()
        if (
            block.get("acquisition_block_index") != index
            or block.get("acquisition_block_id") != f"acquisition-block-{index + 1:03d}"
            or block.get("result_name") != FORMAL_RESULT_NAMES[index]
            or not math.isfinite(elapsed)
            or elapsed <= 0
            or not math.isclose(float(block.get("elapsed_seconds", -1)), elapsed, abs_tol=1e-9)
            or (prior_completed is not None and started < prior_completed)
        ):
            raise ValueError("formal blocks are not chronological and non-overlapping")
        timeline.append(
            {
                "acquisition_block_index": index,
                "acquisition_block_id": f"acquisition-block-{index + 1:03d}",
                "result_name": FORMAL_RESULT_NAMES[index],
                "started_at": block["started_at"],
                "completed_at": block["completed_at"],
                "elapsed_seconds": elapsed,
            }
        )
        prior_completed = completed
    return {
        "schema_version": 1,
        "ordering": "authoritative-experiment-started-at-and-completed-at",
        "chronological": True,
        "non_overlapping": True,
        "timeline": timeline,
    }


def _dataset_receipt(
    rows: Sequence[Mapping[str, Any]],
    blocks: Sequence[Mapping[str, Any]],
    *,
    formal: bool,
    execution_source: Any,
) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "purpose": PURPOSE,
        "formal": formal,
        "paper_equivalent": False,
        "implementation_scope": "client_only_quic",
        "result_names": [block["result_name"] for block in blocks],
        "blocks": list(blocks),
        "sample_count": len(rows),
        "classes": sorted({str(row["class_label"]) for row in rows}),
        "defenses": sorted({str(row["defense"]) for row in rows}),
        "counts_by_defense": dict(sorted(Counter(str(row["defense"]) for row in rows).items())),
        "counts_by_split": dict(sorted(Counter(str(row["split"]) for row in rows).items())),
        "observation": {
            "length_basis": "Ethernet frame.len",
            "direction_rule": "client egress positive; server ingress negative",
            "model_input": "traces/*.csv or stripped/*.pcap",
            "raw_restricted": True,
        },
        "execution_source": execution_source,
        "exporter_source": source_metadata(),
    }
    if formal:
        value["temporal_acquisition"] = _formal_temporal_proof(blocks)
    return value


def _block_receipt(
    receipt: VerifiedResult,
    block_index: int,
    split: str,
    *,
    formal: bool,
) -> dict[str, Any]:
    configuration = receipt.experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise ValueError("study handoff result has no configuration receipt")
    campaign_path = (
        _formal_campaign_path_for_result(receipt, block_index).relative_to(LAB_ROOT).as_posix()
        if formal
        else None
    )
    value = {
        "acquisition_block_index": block_index,
        "acquisition_block_id": f"acquisition-block-{block_index + 1:03d}",
        "split": split,
        "result_name": receipt.experiment["name"],
        "result_root": str(receipt.root),
        "result_evidence_sha256": sha256_file(receipt.root / "evidence.sha256"),
        "authoritative_files": len(receipt.checksums),
        "campaign_path": campaign_path,
        "campaign_sha256": configuration.get("campaign_sha256"),
        "configuration": dict(configuration),
        "configuration_sha256": _canonical_digest(configuration),
    }
    if formal:
        value.update(
            started_at=receipt.experiment["started_at"],
            completed_at=receipt.experiment["completed_at"],
            elapsed_seconds=_elapsed_seconds(receipt.experiment),
        )
    return value


def _trusted_formal_campaign_path(path: Path, block_index: int) -> Path:
    candidate = Path(path).resolve()
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("formal campaign path is not a regular file")
    if candidate.name != FORMAL_CAMPAIGN_FILES[block_index]:
        raise ValueError("formal campaign basename does not match its acquisition block")
    if candidate.parent == _FORMAL_CAMPAIGN_ROOT:
        return candidate
    if not candidate.is_relative_to(_FORMAL_COHORT_INPUT_ROOT):
        raise ValueError("formal campaign path is outside the immutable campaign roots")
    relative = candidate.relative_to(_FORMAL_COHORT_INPUT_ROOT)
    if (
        len(relative.parts) != 3
        or re.fullmatch(r"v[1-9][0-9]*", relative.parts[0]) is None
        or relative.parts[1] != "campaigns"
    ):
        raise ValueError("resolved formal campaign path has an invalid cohort layout")
    return candidate


def _formal_campaign_path_for_result(receipt: VerifiedResult, block_index: int) -> Path:
    admission_path = receipt.root / "inputs/capture-admission.json"
    if admission_path.is_symlink() or not admission_path.is_file():
        raise ValueError("formal result has no frozen capture admission")
    admission = load_json(admission_path)
    rows = admission.get("allowed_campaigns") if isinstance(admission, Mapping) else None
    if not isinstance(rows, list):
        raise ValueError("formal result frozen admission has no campaign inventory")
    matches = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and row.get("block") == block_index + 1
        and row.get("result_root") == str(receipt.root)
        and isinstance(row.get("campaign_path"), str)
        and isinstance(row.get("campaign_sha256"), str)
    ]
    if len(matches) != 1:
        raise ValueError("formal result does not select exactly one block campaign")
    path = _trusted_formal_campaign_path(Path(matches[0]["campaign_path"]), block_index)
    if sha256_file(path) != matches[0]["campaign_sha256"]:
        raise ValueError("formal result campaign differs from its frozen admission")
    return path


def _split_for_block(index: int) -> str:
    if index < 8:
        return "train"
    if index == 8:
        return "validation"
    if index == 9:
        return "test"
    return "interface"


def _copy_sealed_file(receipt: VerifiedResult, source: Path, destination: Path) -> None:
    relative = source.relative_to(receipt.root).as_posix()
    expected = receipt.checksums.get(relative)
    if expected is None or source.is_symlink() or not source.is_file():
        raise ValueError("study handoff source is absent from its evidence seal")
    _copy_regular_file(source, destination)
    if sha256_file(destination) != expected:
        raise ValueError("study handoff copied source differs from its evidence seal")


def _copy_regular_file(source: Path, destination: Path) -> None:
    with source.open("rb") as input_file, destination.open("xb") as output:
        for block in iter(lambda: input_file.read(1024 * 1024), b""):
            output.write(block)
        output.flush()
        os.fsync(output.fileno())


def _write_classic_raw_pcap(source: Path, destination: Path) -> None:
    editcap = shutil.which("editcap")
    if editcap is None:
        raise RuntimeError("study handoff requires editcap")
    completed = subprocess.run(
        [editcap, "-F", "nsecpcap", os.fspath(source), os.fspath(destination)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        destination.unlink(missing_ok=True)
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown editcap error"
        raise RuntimeError(f"study handoff PCAP conversion failed: {detail}")
    if destination.is_symlink() or not destination.is_file() or destination.stat().st_size == 0:
        destination.unlink(missing_ok=True)
        raise RuntimeError("study handoff PCAP conversion produced no regular file")


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


def _write_shape_only_pcap(trace: Sequence[ObserverPacket], path: Path) -> None:
    if not trace:
        raise ValueError("shape-only PCAP requires a non-empty trace")
    previous = -1
    with path.open("xb") as output:
        output.write(_PCAP_GLOBAL.pack(_PCAP_MAGIC_NS, 2, 4, 0, 0, 65_535, 1))
        for packet in trace:
            if packet.relative_time_ns < previous:
                raise ValueError("shape-only trace timestamps are not monotonic")
            previous = packet.relative_time_ns
            frame = _shape_frame(packet.direction, packet.frame_len)
            seconds, nanoseconds = divmod(packet.relative_time_ns, 1_000_000_000)
            if seconds > 0xFFFFFFFF:
                raise ValueError("shape-only timestamp exceeds classic PCAP range")
            output.write(_PCAP_RECORD.pack(seconds, nanoseconds, len(frame), len(frame)))
            output.write(frame)
        output.flush()
        os.fsync(output.fileno())


def _shape_frame(direction: str, frame_len: int) -> bytes:
    if frame_len < _MINIMUM_FRAME_BYTES or frame_len > 65_535 + 14:
        raise ValueError("observer frame length cannot be represented")
    if direction == "outgoing":
        source_mac, destination_mac = CLIENT_MAC, SERVER_MAC
        source_ip, destination_ip = CLIENT_IP, SERVER_IP
        source_port, destination_port = CLIENT_PORT, SERVER_PORT
    elif direction == "incoming":
        source_mac, destination_mac = SERVER_MAC, CLIENT_MAC
        source_ip, destination_ip = SERVER_IP, CLIENT_IP
        source_port, destination_port = SERVER_PORT, CLIENT_PORT
    else:
        raise ValueError("observer packet direction is invalid")
    ip_total = frame_len - 14
    udp_total = ip_total - 20
    payload_bytes = udp_total - 8
    ethernet = destination_mac + source_mac + struct.pack("!H", 0x0800)
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
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
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


def _read_shape_only_pcap(path: Path) -> tuple[tuple[int, str, int], ...]:
    data = path.read_bytes()
    if len(data) < _PCAP_GLOBAL.size or _PCAP_GLOBAL.unpack_from(data, 0) != (
        _PCAP_MAGIC_NS,
        2,
        4,
        0,
        0,
        65_535,
        1,
    ):
        raise ValueError("shape-only PCAP global header is invalid")
    rows: list[tuple[int, str, int]] = []
    offset = _PCAP_GLOBAL.size
    previous = -1
    while offset < len(data):
        if offset + _PCAP_RECORD.size > len(data):
            raise ValueError("shape-only PCAP record is truncated")
        seconds, nanoseconds, included, original = _PCAP_RECORD.unpack_from(data, offset)
        offset += _PCAP_RECORD.size
        if (
            nanoseconds >= 1_000_000_000
            or included != original
            or included < _MINIMUM_FRAME_BYTES
            or offset + included > len(data)
        ):
            raise ValueError("shape-only PCAP record length is invalid")
        frame = data[offset : offset + included]
        offset += included
        direction = _shape_frame_direction(frame)
        timestamp = seconds * 1_000_000_000 + nanoseconds
        if timestamp < previous:
            raise ValueError("shape-only PCAP timestamps are not monotonic")
        previous = timestamp
        rows.append((timestamp, direction, included))
    if not rows or rows[0][0] != 0:
        raise ValueError("shape-only PCAP must be non-empty and relative")
    return tuple(rows)


def _shape_frame_direction(frame: bytes) -> str:
    if len(frame) < _MINIMUM_FRAME_BYTES or frame[12:14] != b"\x08\x00":
        raise ValueError("shape-only PCAP contains unexpected data")
    source_mac, destination_mac = frame[6:12], frame[:6]
    source_ip, destination_ip = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
    source_port, destination_port = struct.unpack("!HH", frame[34:38])
    if (
        source_mac,
        destination_mac,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
    ) == (CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT):
        direction = "outgoing"
    elif (
        source_mac,
        destination_mac,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
    ) == (SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT):
        direction = "incoming"
    else:
        raise ValueError("shape-only PCAP contains an unexpected identifier")
    if frame != _shape_frame(direction, len(frame)):
        raise ValueError("shape-only PCAP contains unexpected protocol data")
    return direction


def _trace_identity(trace: Sequence[ObserverPacket]) -> tuple[tuple[int, str, int], ...]:
    return tuple((packet.relative_time_ns, packet.direction, packet.frame_len) for packet in trace)


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _write_json_lines(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    value = "".join(
        json.dumps(dict(row), sort_keys=True, separators=(",", ":")) + "\n" for row in rows
    )
    _write_text(path, value)


def _performance_metadata(
    run: Mapping[str, Any], trace: Sequence[ObserverPacket]
) -> dict[str, Any]:
    start = run.get("defense_start_monotonic_ns")
    completion = run.get("application_completion_monotonic_ns")
    if type(start) is not int or type(completion) is not int or completion <= start:
        raise ValueError("study handoff run has no valid application completion interval")
    responses = run.get("responses")
    if not isinstance(responses, list) or not responses:
        raise ValueError("study handoff run has no application responses")
    response_bytes = 0
    for response in responses:
        if not isinstance(response, Mapping) or type(response.get("bytes")) is not int:
            raise ValueError("study handoff response byte evidence is invalid")
        response_bytes += int(response["bytes"])
    resource_usage = run.get("client_resource_usage")
    if not isinstance(resource_usage, Mapping):
        resource_usage = None
    udp_by_direction: dict[str, int | None] = {}
    missing_by_direction: dict[str, int] = {}
    for direction in ("outgoing", "incoming"):
        selected = [packet for packet in trace if packet.direction == direction]
        known = [
            packet.udp_payload_len for packet in selected if packet.udp_payload_len is not None
        ]
        udp_by_direction[direction] = sum(known) if len(known) == len(selected) else None
        missing_by_direction[direction] = len(selected) - len(known)
    return {
        "schema_version": 1,
        "application_duration_ns": completion - start,
        "application_response_bytes": response_bytes,
        "wire_bytes": {
            direction: sum(packet.frame_len for packet in trace if packet.direction == direction)
            for direction in ("outgoing", "incoming")
        },
        "packet_count": {
            direction: sum(packet.direction == direction for packet in trace)
            for direction in ("outgoing", "incoming")
        },
        "udp_payload_bytes": udp_by_direction,
        "udp_payload_lengths_missing": missing_by_direction,
        "client_resource_usage": dict(resource_usage) if resource_usage is not None else None,
        "transport_retransmissions": _transport_retransmissions(run),
    }


def _transport_retransmissions(run: Mapping[str, Any]) -> int | None:
    endpoints = run.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        return None
    total = 0
    matched = False
    for endpoint in endpoints:
        stats = endpoint.get("transport_stats") if isinstance(endpoint, Mapping) else None
        if not isinstance(stats, str):
            continue
        match = re.search(r"(?m)^\s*tx:\s+\d+\s+lost\s+(\d+)\b", stats)
        if match is not None:
            total += int(match.group(1))
            matched = True
    return total if matched else None


def _write_text(path: Path, value: str) -> None:
    with path.open("x", encoding="utf-8") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def _write_checksums(root: Path) -> None:
    files = _regular_tree_files(root)
    if "SHA256SUMS" in files:
        raise ValueError("study handoff checksum file already exists")
    _write_text(
        root / "SHA256SUMS",
        "".join(f"{sha256_file(files[path])}  {path}\n" for path in sorted(files)),
    )


def _read_checksums(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("study handoff has no regular checksum file")
    result: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            digest, relative = line.split("  ", 1)
        except ValueError as error:
            raise ValueError(f"invalid study checksum line {line_number}") from error
        relative_path = Path(relative)
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path.as_posix() != relative
            or relative in result
            or relative == "SHA256SUMS"
        ):
            raise ValueError(f"invalid study checksum line {line_number}")
        result[relative] = digest
    if not result:
        raise ValueError("study handoff checksum inventory is empty")
    return result


def _read_json_lines(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid study JSONL line {line_number}") from error
        if not isinstance(row, dict) or row.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"invalid study JSONL schema on line {line_number}")
        if line != json.dumps(row, sort_keys=True, separators=(",", ":")):
            raise ValueError(f"non-canonical study JSONL line {line_number}")
        rows.append(row)
    if not rows:
        raise ValueError("study handoff contains no sample rows")
    return rows


def _regular_tree_files(root: Path, *, exclude: set[str] | None = None) -> dict[str, Path]:
    excluded = set() if exclude is None else exclude
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"study handoff cannot contain symlinks: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative not in excluded:
                files[relative] = path
    return files


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for create-only publication")
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
        raise FileExistsError(f"study handoff destination already exists: {destination}")
    raise OSError(error, os.strerror(error), destination)


def _fsync_tree(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            with path.open("rb") as source:
                os.fsync(source.fileno())
    for path in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
        _fsync_directory(path)
    _fsync_directory(root)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _readme() -> str:
    return """# QCSD BuFLO/CS-BuFLO focused-study handoff

This handoff is separate from and does not alter the historical classifier
handoff. Raw captures and run receipts are restricted evidence. The default
classifier inputs are the identifier-free `traces/*.csv` or `stripped/*.pcap`
products, which retain only relative time, client-relative direction, and
Ethernet frame length. They are not valid QUIC transcripts.

The defenses are client-only QUIC adaptations and are not paper-equivalent
bilateral implementations. `samples.jsonl` is authoritative for temporal block
splits and paired-visit membership. Validate the closed inventory with
`sha256sum -c SHA256SUMS` and the semantic protocol with `buflo-study verify`.

For BuFLO, `algorithm_diagnostics.buflo_state` binds the inclusive-minimum
terminal latch, zero live parser-lease bytes, zero pending application parser
boundaries, the counted reviewed-chaff parser boundaries canceled with their
streams, the unallocatable sub-cell capacity, typed client-local cancellation
actions, and later unscheduled defense-control packet composition. Packet
composition does not expose individual QUIC frame identity; this is a separately
classified QCSD-only expected difference, not bilateral BuFLO behavior.
Schema 4 also binds the first terminal whole-cell-capacity boundary that stops
new opportunities. Its schedule ledger proves that no later cell was scheduled,
that outgoing work was already terminal, and that any already-advertised
incoming credit drained exactly once before the client-local terminal latch.

For CS-BuFLO, `algorithm_diagnostics.cs_buflo_state.local_termination`
distinguishes a post-onLoad latch from a pre-onLoad latch. The current schema
counts application receive streams, parser state, and send endpoints handed
back to ordinary HTTP/3, plus later natural bytes by direction. Those later
bytes reconcile final accounting but do not update the frozen padding basis,
estimator, rate transitions, or terminal interval. Schema 4 additionally binds
the phase, reason, timestamp, progress, target, and scheduled/terminal snapshot
for the first eligible padding-target or directional power-of-two stop. The
sealed schedule ledger proves that no later opportunity was scheduled and that
every already-advertised receive-credit opportunity drained exactly once before
the client-local latch. Strictly-before, same-timestamp, and at-or-before counts
bound the Rust stop snapshot without imposing a false order on controller events
that share one timestamp. Incoming crossings are consumed scheduled credit, not
an observation of peer datagram timing or size.
"""
