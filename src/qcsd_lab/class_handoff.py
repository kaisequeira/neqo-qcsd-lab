"""Create-only handoff for the 100-class QCSD formal classifier study.

This exporter is deliberately disjoint from the historical classifier and
BuFLO-study handoffs.  It accepts only the ten sealed schema-two ``formal``
results, preserves the five accepted source artifacts byte-for-byte, retains
schema-11/12/13 BuFLO kernel-TX evidence in a separate subtree, and derives
classifier products solely from observer time, client-relative direction,
and Ethernet frame length.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .buflo_evaluation import ShapePacket, _load_performance
from .buflo_handoff import (
    _fsync_directory,
    _fsync_tree,
    _performance_metadata,
    _read_shape_only_pcap,
    _rename_noreplace,
    _trace_identity,
    _validate_handoff_sample_correctness,
    _write_classic_raw_pcap,
    _write_shape_only_pcap,
)
from .capture import ObserverPacket, extract_trace
from .class_acquisition import validate_class_study_preparation
from .class_cohort import validate_cohort_assembly_receipt
from .class_run_binding import (
    resolve_class_sample_run_binding,
    validate_class_sample_run_binding,
)
from .class_study import (
    EVIDENCE_ROLES,
    FINAL_CLASS_COUNT,
    FORMAL_BLOCK_COUNT,
    FORMAL_MODES,
    FORMAL_VISITS_PER_BLOCK,
    STUDY_ID,
    class_study_launch_identity,
    class_study_launch_key,
    is_class_study_id,
    is_successor_study_id,
    load_study_receipt,
)
from .discover import origin
from .experiment import (
    ACCEPTED_ARTIFACTS,
    KERNEL_TX_EVIDENCE_DIRECTORY,
    KERNEL_TX_EVIDENCE_FILES,
    KERNEL_TX_EVIDENCE_RECEIPT_KEY,
    KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION,
    KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
    resolved_sample_directory,
    validate_accepted_scheduler_runtime_receipt,
)
from .util import LAB_ROOT, load_json, require_disjoint_path, sha256_file, source_metadata
from .verification import VerifiedResult, verify_result

SCHEMA_VERSION = 3
ARTIFACT_TYPE = "qcsd-classifier-multiorigin100-formal-handoff"
PURPOSE = "closed-world-website-traffic-classification"
COHORT_INPUT = "inputs/class-study-cohort.json"
COHORT_ASSEMBLY_INPUT = "inputs/class-study-cohort-assembly.json"
CLASS_STUDY_LAUNCH_INPUT = "inputs/class-study-launch.json"
CLASS_STUDY_LAUNCHES_PATH = "inputs/class-study-launches"
CLASS_STUDY_FOUNDATION_INPUT = "inputs/class-study-foundation.json"
CLASS_STUDY_READINESS_INPUT = "inputs/class-study-readiness.json"
CLASS_STUDY_HISTORICAL_PRE_INPUT = "inputs/class-study-historical-pre-snapshot.json"
CLASS_STUDY_HISTORICAL_POST_INPUT = "inputs/class-study-historical-post-snapshot.json"
CLASS_MANIFEST_PATH = "inputs/class-manifest.json"
EXECUTION_SOURCE_PATH = "inputs/execution-source.json"
CLASSIFIER_FIELDS = (
    "relative_time_ns",
    "direction",
    "observer_frame_length_bytes",
)
FORBIDDEN_CLASSIFIER_FIELDS = (
    "address",
    "connection_id",
    "hostname",
    "metadata",
    "payload",
    "port",
    "quic_header",
    "tls",
)
RUNTIME_KINDS = {
    "undefended": "none",
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
    "buflo": "buflo",
    "cs-buflo": "cs_buflo",
}

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
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
_SOURCE_ARTIFACTS = {
    "pcapng": "capture.pcapng",
    "run": "neqo/run.json",
    "schedule": "neqo/schedule.csv",
    "events": "neqo/events.csv",
    "packets": "neqo/packets.csv",
}
_TOP_LEVEL = {
    "README.md",
    "SHA256SUMS",
    "dataset.json",
    "samples.jsonl",
    "inputs",
    KERNEL_TX_EVIDENCE_DIRECTORY,
    "raw",
    "shape",
    "traces",
}
_DATASET_KEYS = {
    "schema_version",
    "artifact_type",
    "purpose",
    "study_id",
    "evidence_role",
    "closed_world",
    "paper_equivalent",
    "implementation_scope",
    "sample_count",
    "class_count",
    "classes",
    "modes",
    "counts_by_mode",
    "counts_by_split",
    "resource_origin_profile",
    "temporal_protocol",
    "observation",
    "role_exclusion",
    "class_cohort",
    "class_cohort_assembly",
    "class_study_launches",
    "class_study_successor",
    "capture_authority",
    "historical_post_snapshot",
    "runtime_contract",
    "class_manifest",
    "execution_source",
    "blocks",
    "exporter_source",
}
_ROW_KEYS = {
    "schema_version",
    "sample_id",
    "class_label",
    "workload_id",
    "mode",
    "runtime_kind",
    "baseline",
    "request_policy",
    "visit",
    "seed",
    "attempts",
    "evidence_role",
    "acquisition_block",
    "split",
    "paired_class_visit_id",
    "input_bindings",
    "kernel_tx_evidence",
    "source",
    "products",
    "observer_packet_count",
    "classifier_feature_fields",
    "correctness",
    "performance",
}
_KERNEL_TX_BINDING_SCHEMA_VERSION = 1
_KERNEL_TX_RECEIPT_KEYS = {
    "schema_version",
    "source",
    "directory",
    "artifacts",
}
_CORRECTNESS_RECEIPT = {
    "schema_version": 1,
    "passed": True,
    "prepared_response_identity": "exact",
    "defense_fidelity": "independently-recomputed-eligible",
}


@dataclass(frozen=True)
class _StudyDimensions:
    study_id: str
    result_names: tuple[str, ...]
    modes: tuple[str, ...]
    runtime_kinds: Mapping[str, str]
    class_count: int
    visits_per_block: int
    require_immutable_source: bool = True

    @property
    def block_count(self) -> int:
        return len(self.result_names)

    @property
    def samples_per_block(self) -> int:
        return self.class_count * self.visits_per_block * len(self.modes)

    @property
    def sample_count(self) -> int:
        return self.block_count * self.samples_per_block


_DIMENSIONS = _StudyDimensions(
    study_id=STUDY_ID,
    result_names=tuple(
        f"{STUDY_ID}-formal-{block:02d}-1200" for block in range(1, FORMAL_BLOCK_COUNT + 1)
    ),
    modes=FORMAL_MODES,
    runtime_kinds=RUNTIME_KINDS,
    class_count=FINAL_CLASS_COUNT,
    visits_per_block=FORMAL_VISITS_PER_BLOCK,
)


def _dimensions_for_study(study_id: str) -> _StudyDimensions:
    if not is_class_study_id(study_id):
        raise ValueError("formal class handoff study identity is invalid")
    return _StudyDimensions(
        study_id=study_id,
        result_names=tuple(
            f"{study_id}-formal-{block:02d}-1200" for block in range(1, FORMAL_BLOCK_COUNT + 1)
        ),
        modes=FORMAL_MODES,
        runtime_kinds=RUNTIME_KINDS,
        class_count=FINAL_CLASS_COUNT,
        visits_per_block=FORMAL_VISITS_PER_BLOCK,
    )


@dataclass(frozen=True)
class _SourceContext:
    receipts: tuple[VerifiedResult, ...]
    class_ids: tuple[str, ...]
    workload_records: tuple[dict[str, Any], ...]
    class_manifest_sha256: str
    cohort_sha256: str
    cohort_payload_sha256: str
    cohort_assembly_sha256: str
    cohort_assembly_payload_sha256: str
    class_study_launch_sha256s: tuple[str, ...]
    class_study_successor_sha256: str | None
    class_study_foundation_sha256: str
    class_study_readiness_sha256: str
    class_study_historical_pre_snapshot_sha256: str
    defense_runtime_inputs: dict[str, dict[str, Any]]
    chaff_qualification_set: str
    chaff_qualification_set_manifest_sha256: str
    execution_source: dict[str, Any]
    class_study_historical_post_snapshot_source: Path | None = None
    class_study_historical_post_snapshot_sha256: str | None = None
    class_study_historical_post_snapshot_payload_sha256: str | None = None


SourceVerifier = Callable[[Path], VerifiedResult]
TraceExtractor = Callable[[Path, Sequence[Mapping[str, Any]]], list[ObserverPacket]]
ClassicPcapWriter = Callable[[Path, Path], None]
CorrectnessValidator = Callable[..., None]
PerformanceExtractor = Callable[[Mapping[str, Any], Sequence[ObserverPacket]], dict[str, Any]]
CohortLoader = Callable[[Path], tuple[dict[str, Any], Any]]
AssemblyValidator = Callable[..., dict[str, Any]]
HistoricalPostValidator = Callable[..., Mapping[str, Any]]


def export_class_handoff(
    result_roots: Sequence[Path],
    destination: Path,
    *,
    historical_post_snapshot: Path,
    source_verifier: SourceVerifier = verify_result,
    trace_extractor: TraceExtractor = extract_trace,
    classic_pcap_writer: ClassicPcapWriter = _write_classic_raw_pcap,
    correctness_validator: CorrectnessValidator = _validate_handoff_sample_correctness,
    performance_extractor: PerformanceExtractor = _performance_metadata,
) -> Path:
    """Atomically publish the exact 16,000-sample formal handoff.

    The injectable callables are verification seams for synthetic tests.  A
    research export must use the defaults, which reverify every source seal and
    extract each trace directly from its raw PCAPNG.
    """

    if not result_roots:
        raise ValueError("formal class handoff requires source results")
    first = source_verifier(Path(result_roots[0]))
    configuration = first.experiment.get("configuration")
    study_id = (
        configuration.get("class_study_id", STUDY_ID)
        if isinstance(configuration, Mapping)
        else STUDY_ID
    )
    if not isinstance(study_id, str):
        raise ValueError("formal class handoff source has no study identity")
    return _export_class_handoff(
        result_roots,
        destination,
        historical_post_snapshot=historical_post_snapshot,
        dimensions=_dimensions_for_study(study_id),
        source_verifier=source_verifier,
        trace_extractor=trace_extractor,
        classic_pcap_writer=classic_pcap_writer,
        correctness_validator=correctness_validator,
        performance_extractor=performance_extractor,
        cohort_loader=load_study_receipt,
        assembly_validator=validate_cohort_assembly_receipt,
    )


def verify_class_handoff(
    path: Path,
    *,
    deep: bool = True,
    source_verifier: SourceVerifier = verify_result,
    trace_extractor: TraceExtractor = extract_trace,
    classic_pcap_writer: ClassicPcapWriter = _write_classic_raw_pcap,
    correctness_validator: CorrectnessValidator = _validate_handoff_sample_correctness,
    performance_extractor: PerformanceExtractor = _performance_metadata,
) -> Path:
    """Reverify the closed inventory, formal lineage, and observer products.

    Deep verification reopens current BuFLO/CS-BuFLO terminal chronology and
    regenerates both observer projections from copied raw evidence.  The
    classic-PCAP writer is injectable solely so compact synthetic tests do not
    need to manufacture a valid PCAPNG container.
    """

    dataset = _read_json_object(Path(path) / "dataset.json", "formal class dataset")
    study_id = dataset.get("study_id")
    if not isinstance(study_id, str):
        raise ValueError("formal class handoff has no study identity")
    return _verify_class_handoff(
        path,
        dimensions=_dimensions_for_study(study_id),
        deep=deep,
        source_verifier=source_verifier,
        trace_extractor=trace_extractor,
        classic_pcap_writer=classic_pcap_writer,
        correctness_validator=correctness_validator,
        performance_extractor=performance_extractor,
        cohort_loader=load_study_receipt,
        assembly_validator=validate_cohort_assembly_receipt,
    )


def _export_class_handoff(
    result_roots: Sequence[Path],
    destination: Path,
    *,
    historical_post_snapshot: Path,
    dimensions: _StudyDimensions,
    source_verifier: SourceVerifier,
    trace_extractor: TraceExtractor,
    classic_pcap_writer: ClassicPcapWriter,
    correctness_validator: CorrectnessValidator,
    performance_extractor: PerformanceExtractor,
    cohort_loader: CohortLoader,
    assembly_validator: AssemblyValidator,
    historical_post_validator: HistoricalPostValidator | None = None,
) -> Path:
    roots = tuple(Path(root).resolve() for root in result_roots)
    if len(roots) != dimensions.block_count or len(set(roots)) != len(roots):
        raise ValueError(
            f"formal class handoff requires exactly {dimensions.block_count} unique result roots"
        )
    receipts = tuple(source_verifier(root) for root in roots)
    if tuple(receipt.root.resolve() for receipt in receipts) != roots:
        raise ValueError("source verifier returned a different result root")
    context = _validate_source_results(
        receipts,
        dimensions=dimensions,
        cohort_loader=cohort_loader,
        assembly_validator=assembly_validator,
    )
    context = _bind_historical_post_snapshot(
        context,
        historical_post_snapshot,
        dimensions=dimensions,
        validator=historical_post_validator,
    )

    existing_handoffs = _existing_handoffs_except(destination)
    destination = require_disjoint_path(
        destination,
        (
            *roots,
            Path(historical_post_snapshot),
            *existing_handoffs,
        ),
        label="formal class handoff destination",
    )
    parent = destination.parent.resolve()
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("formal class handoff destination parent is invalid")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"formal class handoff destination already exists: {destination}")

    candidate = Path(tempfile.mkdtemp(prefix=f".{destination.name}.qcsd-class-", dir=parent))
    try:
        for directory in (
            "inputs/workloads",
            CLASS_STUDY_LAUNCHES_PATH,
            KERNEL_TX_EVIDENCE_DIRECTORY,
            "raw",
            "shape",
            "traces",
        ):
            (candidate / directory).mkdir(parents=True, exist_ok=True)
        _copy_study_inputs(candidate, context, dimensions=dimensions)

        rows: list[dict[str, Any]] = []
        blocks: list[dict[str, Any]] = []
        seen_sample_ids: set[str] = set()
        for block_index, receipt in enumerate(context.receipts, start=1):
            split = _split_for_block(block_index, dimensions.block_count)
            evidence_sha256 = sha256_file(receipt.root / "evidence.sha256")
            blocks.append(
                _block_receipt(
                    receipt,
                    block_index=block_index,
                    split=split,
                    context=context,
                )
            )
            for sample in receipt.experiment["samples"]:
                sample_id = str(sample["sample_id"])
                if sample_id in seen_sample_ids:
                    raise ValueError("formal class sample IDs are not globally unique")
                seen_sample_ids.add(sample_id)
                rows.append(
                    _export_sample(
                        candidate,
                        receipt,
                        sample,
                        block_index=block_index,
                        split=split,
                        result_evidence_sha256=evidence_sha256,
                        trace_extractor=trace_extractor,
                        classic_pcap_writer=classic_pcap_writer,
                        correctness_validator=correctness_validator,
                        performance_extractor=performance_extractor,
                    )
                )

        dataset = _dataset_receipt(
            rows,
            blocks,
            context,
            dimensions=dimensions,
            handoff_root=candidate,
        )
        _write_json(candidate / "dataset.json", dataset)
        _write_json_lines(candidate / "samples.jsonl", rows)
        _write_text(candidate / "README.md", _handoff_readme(dimensions))
        _write_checksums(candidate)
        _validate_published_tree(
            candidate,
            context=context,
            dimensions=dimensions,
            deep=False,
            trace_extractor=trace_extractor,
            classic_pcap_writer=classic_pcap_writer,
            correctness_validator=correctness_validator,
            performance_extractor=performance_extractor,
        )
        _fsync_tree(candidate)
        _rename_noreplace(candidate, destination)
        _fsync_directory(parent)
        return destination.resolve()
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)


def _verify_class_handoff(
    path: Path,
    *,
    dimensions: _StudyDimensions,
    deep: bool,
    source_verifier: SourceVerifier,
    trace_extractor: TraceExtractor,
    classic_pcap_writer: ClassicPcapWriter,
    correctness_validator: CorrectnessValidator,
    performance_extractor: PerformanceExtractor,
    cohort_loader: CohortLoader,
    assembly_validator: AssemblyValidator,
    historical_post_validator: HistoricalPostValidator | None = None,
) -> Path:
    root = Path(path).resolve()
    dataset = _read_json_object(root / "dataset.json", "formal class dataset")
    blocks = dataset.get("blocks")
    if not isinstance(blocks, list):
        raise ValueError("formal class dataset has no source block inventory")
    roots = []
    for block in blocks:
        if not isinstance(block, Mapping) or not isinstance(block.get("result_root"), str):
            raise ValueError("formal class source block is invalid")
        roots.append(Path(block["result_root"]).resolve())
    receipts = tuple(source_verifier(source) for source in roots)
    context = _validate_source_results(
        receipts,
        dimensions=dimensions,
        cohort_loader=cohort_loader,
        assembly_validator=assembly_validator,
    )
    context = _bind_historical_post_snapshot(
        context,
        root / CLASS_STUDY_HISTORICAL_POST_INPUT,
        dimensions=dimensions,
        validator=historical_post_validator,
    )
    _validate_published_tree(
        root,
        context=context,
        dimensions=dimensions,
        deep=deep,
        trace_extractor=trace_extractor,
        classic_pcap_writer=classic_pcap_writer,
        correctness_validator=correctness_validator,
        performance_extractor=performance_extractor,
    )
    return root


def _validate_source_results(
    receipts: Sequence[VerifiedResult],
    *,
    dimensions: _StudyDimensions,
    cohort_loader: CohortLoader,
    assembly_validator: AssemblyValidator,
) -> _SourceContext:
    if len(receipts) != dimensions.block_count:
        raise ValueError("formal class source block count is invalid")
    names = tuple(str(receipt.experiment.get("name")) for receipt in receipts)
    if names != dimensions.result_names:
        raise ValueError("formal class result order or identity is invalid")

    first_workloads: tuple[dict[str, Any], ...] | None = None
    first_source: dict[str, Any] | None = None
    class_ids: tuple[str, ...] | None = None
    cohort_sha256: str | None = None
    cohort_payload_sha256: str | None = None
    cohort_assembly_sha256: str | None = None
    cohort_assembly_payload_sha256: str | None = None
    class_study_launch_sha256s: list[str] = []
    class_study_successor_sha256: str | None = None
    class_study_foundation_sha256: str | None = None
    class_study_readiness_sha256: str | None = None
    class_study_historical_pre_snapshot_sha256: str | None = None
    defense_runtime_inputs: dict[str, dict[str, Any]] | None = None
    chaff_qualification_set: str | None = None
    chaff_qualification_set_manifest_sha256: str | None = None
    prior_completion: datetime | None = None
    for block_index, receipt in enumerate(receipts, start=1):
        experiment = receipt.experiment
        samples = experiment.get("samples")
        summary = experiment.get("summary")
        if (
            experiment.get("status") != "complete"
            or experiment.get("purpose") != "evaluation"
            or not isinstance(samples, list)
            or len(samples) != dimensions.samples_per_block
            or not isinstance(summary, Mapping)
            or summary.get("planned") != dimensions.samples_per_block
            or summary.get("accepted") != dimensions.samples_per_block
            or summary.get("eligible") != dimensions.samples_per_block
            or summary.get("failed") != 0
            or summary.get("passed") is not True
        ):
            raise ValueError("formal class handoff requires complete all-eligible source results")
        if len(receipt.accepted_samples) != dimensions.samples_per_block:
            raise ValueError("formal class accepted-sample seal count is invalid")
        if any(
            sample.get("state") != "accepted"
            or sample.get("eligible") is not True
            or type(sample.get("attempts")) is not int
            or not 1 <= sample["attempts"] <= 3
            or sample.get("failure") is not None
            for sample in samples
        ):
            raise ValueError(
                "formal class samples must be accepted and eligible within the retry budget"
            )
        if any(
            receipt.accepted_samples.get(str(sample["sample_id"])) != sample["artifacts"]
            for sample in samples
        ):
            raise ValueError("formal class accepted-sample identities differ from their seals")
        for sample in samples:
            validate_accepted_scheduler_runtime_receipt(
                receipt.root,
                experiment,
                sample,
            )
        if experiment.get("execution_order") != [sample["sample_id"] for sample in samples]:
            raise ValueError("formal class source execution order is invalid")

        _require_schema_two_campaign(receipt)
        configuration = experiment.get("configuration")
        if not isinstance(configuration, Mapping):
            raise ValueError("formal class source configuration is invalid")
        _validate_formal_configuration(
            configuration,
            dimensions=dimensions,
            block_index=block_index,
        )
        current_foundation_sha256 = _sealed_configuration_input(
            receipt,
            configuration=configuration,
            relative=CLASS_STUDY_FOUNDATION_INPUT,
            configuration_key="class_study_foundation_sha256",
            label="foundation",
        )
        current_readiness_sha256 = _sealed_configuration_input(
            receipt,
            configuration=configuration,
            relative=CLASS_STUDY_READINESS_INPUT,
            configuration_key="class_study_readiness_sha256",
            label="readiness",
        )
        current_historical_pre_sha256 = _sealed_configuration_input(
            receipt,
            configuration=configuration,
            relative=CLASS_STUDY_HISTORICAL_PRE_INPUT,
            configuration_key="class_study_historical_pre_snapshot_sha256",
            label="historical-pre",
        )
        current_runtime_inputs = _formal_runtime_inputs(
            configuration.get("defense_runtime_inputs"),
            dimensions=dimensions,
        )
        current_qualification_set = configuration.get("chaff_qualification_set")
        current_qualification_manifest_sha256 = configuration.get(
            "chaff_qualification_set_manifest_sha256"
        )
        if (
            not isinstance(current_qualification_set, str)
            or not current_qualification_set
            or not _is_digest(current_qualification_manifest_sha256)
        ):
            raise ValueError("formal class source has no frozen chaff-qualification identity")
        current_successor_sha256 = configuration.get("class_study_successor_sha256")
        if is_successor_study_id(dimensions.study_id):
            if not _is_digest(current_successor_sha256):
                raise ValueError("formal successor block has no restart authority")
        elif current_successor_sha256 is not None:
            raise ValueError("v1 formal block unexpectedly has successor authority")
        workloads = _normalise_workload_records(
            configuration.get("workloads"), dimensions=dimensions
        )

        cohort_path = receipt.root / COHORT_INPUT
        cohort_relative = cohort_path.relative_to(receipt.root).as_posix()
        if (
            receipt.checksums.get(cohort_relative) != sha256_file(cohort_path)
            or cohort_path.is_symlink()
            or not cohort_path.is_file()
        ):
            raise ValueError("formal class cohort receipt is not sealed")
        cohort_value, selection = cohort_loader(cohort_path)
        selected = tuple(candidate.candidate_id for candidate in selection.final)
        if len(selected) != dimensions.class_count:
            raise ValueError("formal class cohort has the wrong final-class count")
        if tuple(record["id"] for record in workloads) != selected:
            raise ValueError("formal class workload order differs from the frozen cohort")
        current_cohort_sha256 = sha256_file(cohort_path)
        current_payload_sha256 = cohort_value.get("payload_sha256")
        if not _is_digest(current_payload_sha256):
            raise ValueError("formal class cohort payload hash is invalid")

        assembly_path = receipt.root / COHORT_ASSEMBLY_INPUT
        assembly_relative = assembly_path.relative_to(receipt.root).as_posix()
        if (
            receipt.checksums.get(assembly_relative) != sha256_file(assembly_path)
            or assembly_path.is_symlink()
            or not assembly_path.is_file()
        ):
            raise ValueError("formal class cohort-assembly receipt is not sealed")
        assembly_value = load_json(assembly_path)
        assembly_payload = assembly_validator(assembly_value, cohort=cohort_value)
        current_assembly_sha256 = sha256_file(assembly_path)
        current_assembly_payload_sha256 = assembly_value.get("payload_sha256")
        if not _is_digest(current_assembly_payload_sha256):
            raise ValueError("formal class cohort-assembly payload hash is invalid")
        admitted = _assembly_workload_hashes(assembly_payload, selected)
        if any(record["sha256"] != admitted[record["id"]] for record in workloads):
            raise ValueError("formal class workload differs from cohort admission evidence")
        if (
            configuration.get("class_study_cohort_sha256") != current_cohort_sha256
            or configuration.get("class_study_cohort_assembly_sha256") != current_assembly_sha256
        ):
            raise ValueError("formal class configuration cohort hashes are invalid")

        _validate_sample_matrix(
            samples,
            class_ids=selected,
            dimensions=dimensions,
        )
        _validate_sealed_workloads(receipt, workloads)
        started = _timestamp(experiment.get("started_at"), label=f"block {block_index} start")
        completed = _timestamp(
            experiment.get("completed_at"), label=f"block {block_index} completion"
        )
        if completed <= started or (prior_completion is not None and started < prior_completion):
            raise ValueError("formal class blocks are not chronological and non-overlapping")
        prior_completion = completed

        execution_source = experiment.get("source")
        if not isinstance(execution_source, Mapping):
            raise ValueError("formal class execution source is missing")
        source_value = dict(execution_source)
        if dimensions.require_immutable_source and not _immutable_source(source_value):
            raise ValueError("formal class handoff requires one clean immutable source image")
        class_study_launch_sha256s.append(
            _validate_class_study_launch_receipt(
                receipt,
                configuration=configuration,
                source=source_value,
                dimensions=dimensions,
            )
        )

        if first_workloads is None:
            first_workloads = workloads
            first_source = source_value
            class_ids = selected
            cohort_sha256 = current_cohort_sha256
            cohort_payload_sha256 = current_payload_sha256
            cohort_assembly_sha256 = current_assembly_sha256
            cohort_assembly_payload_sha256 = current_assembly_payload_sha256
            class_study_successor_sha256 = current_successor_sha256
            class_study_foundation_sha256 = current_foundation_sha256
            class_study_readiness_sha256 = current_readiness_sha256
            class_study_historical_pre_snapshot_sha256 = current_historical_pre_sha256
            defense_runtime_inputs = current_runtime_inputs
            chaff_qualification_set = current_qualification_set
            chaff_qualification_set_manifest_sha256 = current_qualification_manifest_sha256
        elif (
            workloads != first_workloads
            or source_value != first_source
            or selected != class_ids
            or current_cohort_sha256 != cohort_sha256
            or current_payload_sha256 != cohort_payload_sha256
            or current_assembly_sha256 != cohort_assembly_sha256
            or current_assembly_payload_sha256 != cohort_assembly_payload_sha256
            or current_successor_sha256 != class_study_successor_sha256
            or current_foundation_sha256 != class_study_foundation_sha256
            or current_readiness_sha256 != class_study_readiness_sha256
            or current_historical_pre_sha256 != class_study_historical_pre_snapshot_sha256
            or current_runtime_inputs != defense_runtime_inputs
            or current_qualification_set != chaff_qualification_set
            or current_qualification_manifest_sha256 != chaff_qualification_set_manifest_sha256
        ):
            raise ValueError("formal class blocks do not share one frozen class/source contract")

    assert first_workloads is not None
    assert first_source is not None
    assert class_ids is not None
    assert cohort_sha256 is not None
    assert cohort_payload_sha256 is not None
    assert cohort_assembly_sha256 is not None
    assert cohort_assembly_payload_sha256 is not None
    assert class_study_foundation_sha256 is not None
    assert class_study_readiness_sha256 is not None
    assert class_study_historical_pre_snapshot_sha256 is not None
    assert defense_runtime_inputs is not None
    assert chaff_qualification_set is not None
    assert chaff_qualification_set_manifest_sha256 is not None
    if len(set(class_study_launch_sha256s)) != dimensions.block_count:
        raise ValueError("formal class blocks do not have unique first-launch receipts")
    return _SourceContext(
        receipts=tuple(receipts),
        class_ids=class_ids,
        workload_records=first_workloads,
        class_manifest_sha256=_canonical_digest(list(first_workloads)),
        cohort_sha256=cohort_sha256,
        cohort_payload_sha256=cohort_payload_sha256,
        cohort_assembly_sha256=cohort_assembly_sha256,
        cohort_assembly_payload_sha256=cohort_assembly_payload_sha256,
        class_study_launch_sha256s=tuple(class_study_launch_sha256s),
        class_study_successor_sha256=class_study_successor_sha256,
        class_study_foundation_sha256=class_study_foundation_sha256,
        class_study_readiness_sha256=class_study_readiness_sha256,
        class_study_historical_pre_snapshot_sha256=(class_study_historical_pre_snapshot_sha256),
        defense_runtime_inputs=defense_runtime_inputs,
        chaff_qualification_set=chaff_qualification_set,
        chaff_qualification_set_manifest_sha256=(chaff_qualification_set_manifest_sha256),
        execution_source=first_source,
    )


def _bind_historical_post_snapshot(
    context: _SourceContext,
    snapshot: Path,
    *,
    dimensions: _StudyDimensions,
    validator: HistoricalPostValidator | None,
) -> _SourceContext:
    """Bind the independently reconstructed post-formal snapshot to all blocks."""

    candidate = Path(snapshot).absolute()
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("formal class historical-post snapshot is not a regular file")
    source = candidate.resolve()
    if validator is None:
        # Local import avoids the intentional class_attestation -> class_handoff
        # import used by the final promotion verifier.
        from .class_attestation import validate_class_historical_snapshot

        validator = validate_class_historical_snapshot
    post = validator(source, expected_phase="post-formal")
    if not isinstance(post, Mapping):
        raise ValueError("formal class historical-post validator returned no mapping")
    readiness = post.get("readiness")
    pre = post.get("pre_formal_snapshot")
    expected_results: list[dict[str, str]] = []
    for receipt, launch_sha256 in zip(
        context.receipts, context.class_study_launch_sha256s, strict=True
    ):
        binding = {
            "root": str(receipt.root.resolve()),
            "evidence_sha256": sha256_file(receipt.root / "evidence.sha256"),
            "class_study_launch_sha256": launch_sha256,
            "class_study_foundation_sha256": context.class_study_foundation_sha256,
            "class_study_readiness_sha256": context.class_study_readiness_sha256,
            "class_study_historical_pre_snapshot_sha256": (
                context.class_study_historical_pre_snapshot_sha256
            ),
        }
        if context.class_study_successor_sha256 is not None:
            binding["class_study_id"] = dimensions.study_id
            binding["class_study_successor_sha256"] = (
                context.class_study_successor_sha256
            )
        expected_results.append(binding)
    payload_sha256 = post.get("payload_sha256")
    digest = sha256_file(source)
    if (
        post.get("phase") != "post-formal"
        or post.get("study_id") != dimensions.study_id
        or post.get("source") != context.execution_source
        or not isinstance(readiness, Mapping)
        or readiness.get("sha256") != context.class_study_readiness_sha256
        or not isinstance(pre, Mapping)
        or pre.get("sha256")
        != context.class_study_historical_pre_snapshot_sha256
        or post.get("formal_results") != expected_results
        or post.get("sha256") != digest
        or not isinstance(payload_sha256, str)
        or _DIGEST.fullmatch(payload_sha256) is None
    ):
        raise ValueError(
            "formal class historical-post snapshot differs from the exact source blocks"
        )
    post_time = _timestamp(post.get("recorded_at"), label="historical-post snapshot")
    last_completion = max(
        _timestamp(
            receipt.experiment.get("completed_at"),
            label="source block completion",
        )
        for receipt in context.receipts
    )
    if post_time < last_completion:
        raise ValueError("formal class historical-post snapshot predates source completion")
    return replace(
        context,
        class_study_historical_post_snapshot_source=source,
        class_study_historical_post_snapshot_sha256=digest,
        class_study_historical_post_snapshot_payload_sha256=payload_sha256,
    )


def _sealed_configuration_input(
    receipt: VerifiedResult,
    *,
    configuration: Mapping[str, Any],
    relative: str,
    configuration_key: str,
    label: str,
) -> str:
    path = receipt.root / relative
    configured = configuration.get(configuration_key)
    if (
        not _is_digest(configured)
        or path.is_symlink()
        or not path.is_file()
        or sha256_file(path) != configured
        or receipt.checksums.get(relative) != configured
    ):
        raise ValueError(f"formal class {label} authority is not sealed and bound")
    return str(configured)


def _formal_runtime_inputs(
    value: object,
    *,
    dimensions: _StudyDimensions,
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != set(dimensions.modes):
        raise ValueError("formal class runtime-input inventory is incomplete")
    result: dict[str, dict[str, Any]] = {}
    for mode in dimensions.modes:
        raw = value.get(mode)
        if not isinstance(raw, Mapping):
            raise ValueError(f"formal class {mode} runtime identity is malformed")
        identity = json.loads(_canonical_json_bytes(raw))
        runtime_kind = dimensions.runtime_kinds[mode]
        if identity.get("runtime_kind") != runtime_kind:
            raise ValueError(f"formal class {mode} runtime kind is invalid")
        if runtime_kind == "none":
            expected = {
                "identity_type": "source-bound-no-defense",
                "runtime_kind": runtime_kind,
            }
        elif runtime_kind in {"front", "tamaraw"}:
            expected = {
                "identity_type": "source-bound-built-in",
                "runtime_kind": runtime_kind,
            }
        else:
            expected = (
                identity
                if (
                    set(identity)
                    == {
                        "identity_type",
                        "runtime_kind",
                        "parameters_sha256",
                        "provenance_sha256",
                        "input_policy",
                    }
                    and identity.get("identity_type") == "hash-bound-parameter-artifact"
                    and _is_digest(identity.get("parameters_sha256"))
                    and _is_digest(identity.get("provenance_sha256"))
                    and isinstance(identity.get("input_policy"), str)
                    and identity["input_policy"]
                )
                else None
            )
        if expected is None or identity != expected:
            raise ValueError(f"formal class {mode} runtime identity is invalid")
        result[mode] = identity
    return result


def _require_schema_two_campaign(receipt: VerifiedResult) -> None:
    path = receipt.root / "inputs/campaign.yml"
    relative = path.relative_to(receipt.root).as_posix()
    if (
        path.is_symlink()
        or not path.is_file()
        or receipt.checksums.get(relative) != sha256_file(path)
    ):
        raise ValueError("formal class campaign is not sealed")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ValueError("formal class campaign is unreadable") from error
    if not isinstance(value, Mapping) or value.get("schema") != 2:
        raise ValueError("formal class handoff accepts only schema-two campaigns")


def _validate_class_study_launch_receipt(
    receipt: VerifiedResult,
    *,
    configuration: Mapping[str, Any],
    source: Mapping[str, Any],
    dimensions: _StudyDimensions,
) -> str:
    path = receipt.root / CLASS_STUDY_LAUNCH_INPUT
    relative = path.relative_to(receipt.root).as_posix()
    if path.is_symlink() or not path.is_file():
        raise ValueError("formal class source has no frozen first-launch receipt")
    digest = sha256_file(path)
    if (
        receipt.checksums.get(relative) != digest
        or configuration.get("class_study_launch_sha256") != digest
    ):
        raise ValueError("formal class first-launch receipt is not sealed and configuration-bound")
    value = load_json(path)
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "artifact_type",
        "payload_sha256",
        "payload",
    }:
        raise ValueError("formal class first-launch receipt envelope is invalid")
    payload = value.get("payload")
    if (
        value.get("schema_version") != 1
        or value.get("artifact_type") != "qcsd-class-study-first-launch-claim"
        or not isinstance(payload, Mapping)
        or not _is_digest(value.get("payload_sha256"))
        or value.get("payload_sha256") != _compact_json_digest(payload)
    ):
        raise ValueError("formal class first-launch receipt does not verify")
    campaign_sha256 = configuration.get("campaign_sha256")
    cohort_sha256 = configuration.get("class_study_cohort_sha256")
    cohort_assembly_sha256 = configuration.get("class_study_cohort_assembly_sha256")
    identity = class_study_launch_identity(
        study_id=dimensions.study_id,
        campaign_name=receipt.experiment["name"],
        evidence_role="formal",
        cohort_sha256=cohort_sha256,
        cohort_assembly_sha256=cohort_assembly_sha256,
    )
    expected = {
        "study_id": dimensions.study_id,
        "launch_key": class_study_launch_key(**identity),
        "campaign_name": receipt.experiment["name"],
        "campaign_sha256": campaign_sha256,
        "evidence_role": "formal",
        "class_study_cohort_sha256": cohort_sha256,
        "class_study_cohort_assembly_sha256": cohort_assembly_sha256,
        "result_root": str(receipt.root.resolve()),
        "created_at": receipt.experiment["started_at"],
        "source": dict(source),
        "policy": "one-result-root-per-campaign-and-cohort-assembly",
    }
    successor_path = receipt.root / "inputs/class-study-successor.json"
    successor_key = "class_study_successor_sha256"
    if is_successor_study_id(dimensions.study_id):
        successor_sha256 = configuration.get(successor_key)
        successor_relative = successor_path.relative_to(receipt.root).as_posix()
        if (
            not _is_digest(successor_sha256)
            or successor_path.is_symlink()
            or not successor_path.is_file()
            or sha256_file(successor_path) != successor_sha256
            or receipt.checksums.get(successor_relative) != successor_sha256
        ):
            raise ValueError("formal successor source has no sealed restart authority")
        expected[successor_key] = successor_sha256
        expected["launch_namespace"] = f".{dimensions.study_id}-launches"
    elif successor_key in configuration or successor_path.exists() or successor_path.is_symlink():
        raise ValueError("v1 formal source unexpectedly carries successor authority")
    if dict(payload) != expected:
        raise ValueError("formal class first-launch receipt differs from its source result")
    return digest


def _validate_formal_configuration(
    configuration: Mapping[str, Any],
    *,
    dimensions: _StudyDimensions,
    block_index: int,
) -> None:
    defenses = configuration.get("defenses")
    limits = configuration.get("limits")
    defense_order = configuration.get("defense_order")
    if (
        configuration.get("evidence_role") != "formal"
        or configuration.get("profile") != "research-1200"
        or configuration.get("request_policies") != ["as-defined"]
        or not isinstance(defenses, list)
        or [entry.get("name") if isinstance(entry, Mapping) else None for entry in defenses]
        != list(dimensions.modes)
        or not isinstance(limits, Mapping)
        or limits.get("max_attempts") != 3
        or defense_order != {"scheme": "cyclic-latin-square", "block": block_index - 1}
    ):
        raise ValueError("formal class source configuration differs from the protocol")


def _normalise_workload_records(
    value: Any,
    *,
    dimensions: _StudyDimensions,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or len(value) != dimensions.class_count:
        raise ValueError("formal class workload configuration has the wrong size")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("formal class workload configuration entry is invalid")
        record = json.loads(_canonical_json_bytes(item))
        workload_id = record.get("id")
        if (
            not isinstance(workload_id, str)
            or not workload_id
            or workload_id in seen
            or record.get("visits") != dimensions.visits_per_block
            or not _is_digest(record.get("sha256"))
            or not isinstance(record.get("manifest"), str)
            or type(record.get("resource_count")) is not int
            or record["resource_count"] <= 0
            or type(record.get("origin_count")) is not int
            or record["origin_count"] <= 0
        ):
            raise ValueError("formal class workload configuration entry is invalid")
        seen.add(workload_id)
        records.append(record)
    return tuple(records)


def _validate_sealed_workloads(
    receipt: VerifiedResult,
    workloads: Sequence[Mapping[str, Any]],
) -> None:
    root = receipt.root.resolve()
    for workload in workloads:
        relative = str(workload["manifest"])
        path = (root / relative).resolve()
        if (
            not path.is_relative_to(root)
            or Path(root / relative).is_symlink()
            or not path.is_file()
            or receipt.checksums.get(relative) != workload["sha256"]
            or sha256_file(path) != workload["sha256"]
        ):
            raise ValueError("formal class prepared workload is not sealed")
        manifest = load_json(path)
        validate_class_study_preparation(manifest, workload_id=str(workload["id"]))
        resources = manifest.get("resources") if isinstance(manifest, Mapping) else None
        if not isinstance(resources, list) or not resources:
            raise ValueError("formal class prepared workload has no resource inventory")
        resource_origins: set[str] = set()
        for resource in resources:
            resource_origin = origin(resource.get("url")) if isinstance(resource, Mapping) else None
            if resource_origin is None:
                raise ValueError("formal class prepared workload has an invalid resource URL")
            resource_origins.add(resource_origin)
        if (
            len(resources) != workload["resource_count"]
            or len(resource_origins) != workload["origin_count"]
        ):
            raise ValueError(
                "formal class prepared workload resource/origin counts differ from its manifest"
            )


def _assembly_workload_hashes(
    payload: Mapping[str, Any],
    workload_ids: Sequence[str],
) -> dict[str, str]:
    records = payload.get("candidates")
    if not isinstance(records, list):
        raise ValueError("formal class cohort assembly has no candidate evidence")
    by_id = {
        record.get("candidate_id"): record
        for record in records
        if isinstance(record, Mapping) and isinstance(record.get("candidate_id"), str)
    }
    result: dict[str, str] = {}
    for workload_id in workload_ids:
        record = by_id.get(workload_id)
        prepared = record.get("prepared_workload") if isinstance(record, Mapping) else None
        digest = prepared.get("sha256") if isinstance(prepared, Mapping) else None
        if record is None or record.get("eligible") is not True or not _is_digest(digest):
            raise ValueError(f"formal class cohort assembly has no admitted workload {workload_id}")
        result[workload_id] = str(digest)
    return result


def _validate_sample_matrix(
    samples: Sequence[Mapping[str, Any]],
    *,
    class_ids: Sequence[str],
    dimensions: _StudyDimensions,
) -> None:
    expected = Counter(
        (class_id, visit, mode)
        for class_id in class_ids
        for visit in range(dimensions.visits_per_block)
        for mode in dimensions.modes
    )
    actual: Counter[tuple[str, int, str]] = Counter()
    for sample in samples:
        workload_id = sample.get("workload_id")
        visit = sample.get("visit")
        mode = sample.get("defense")
        if (
            not isinstance(workload_id, str)
            or type(visit) is not int
            or not isinstance(mode, str)
            or sample.get("request_policy") != "as-defined"
            or sample.get("runtime_kind") != dimensions.runtime_kinds.get(mode)
            or sample.get("baseline") is not (mode == "undefended")
            or set(sample.get("artifacts", {}))
            != {f"{sample.get('path')}/{relative}" for relative in ACCEPTED_ARTIFACTS}
        ):
            raise ValueError("formal class sample identity or artifact contract is invalid")
        actual[(workload_id, visit, mode)] += 1
    if actual != expected:
        raise ValueError("formal class block is not exactly class/mode/visit balanced")


def _copy_study_inputs(
    candidate: Path,
    context: _SourceContext,
    *,
    dimensions: _StudyDimensions,
) -> None:
    first = context.receipts[0]
    cohort_source = first.root / COHORT_INPUT
    _copy_sealed_file(first, cohort_source, candidate / COHORT_INPUT)
    assembly_source = first.root / COHORT_ASSEMBLY_INPUT
    _copy_sealed_file(first, assembly_source, candidate / COHORT_ASSEMBLY_INPUT)
    for relative in (
        CLASS_STUDY_FOUNDATION_INPUT,
        CLASS_STUDY_READINESS_INPUT,
        CLASS_STUDY_HISTORICAL_PRE_INPUT,
    ):
        _copy_sealed_file(first, first.root / relative, candidate / relative)
    if (
        context.class_study_historical_post_snapshot_source is None
        or context.class_study_historical_post_snapshot_sha256 is None
    ):
        raise ValueError("formal class handoff has no historical-post authority")
    _copy_bound_file(
        context.class_study_historical_post_snapshot_source,
        candidate / CLASS_STUDY_HISTORICAL_POST_INPUT,
        expected_sha256=context.class_study_historical_post_snapshot_sha256,
    )
    if context.class_study_successor_sha256 is not None:
        successor_source = first.root / "inputs/class-study-successor.json"
        _copy_sealed_file(first, successor_source, candidate / "inputs/class-study-successor.json")
        if sha256_file(candidate / "inputs/class-study-successor.json") != (
            context.class_study_successor_sha256
        ):
            raise ValueError("formal successor authority changed during handoff export")
    for block_index, receipt in enumerate(context.receipts, start=1):
        _copy_sealed_file(
            receipt,
            receipt.root / CLASS_STUDY_LAUNCH_INPUT,
            candidate / _launch_copy_path(block_index),
        )
    _write_json(candidate / CLASS_MANIFEST_PATH, _class_manifest(context, dimensions))
    _write_json(candidate / EXECUTION_SOURCE_PATH, context.execution_source)
    for workload in context.workload_records:
        source = first.root / str(workload["manifest"])
        destination = candidate / f"inputs/workloads/{workload['id']}.json"
        _copy_sealed_file(first, source, destination)


def _launch_copy_path(block_index: int) -> str:
    return f"{CLASS_STUDY_LAUNCHES_PATH}/block-{block_index:02d}.json"


def _expected_kernel_tx_binding(
    receipt: VerifiedResult,
    sample: Mapping[str, Any],
    *,
    block_index: int,
) -> dict[str, Any] | None:
    """Bind a source sidecar without adding it to the five-file sample inventory."""

    diagnostics = sample.get("diagnostics")
    retained_value = (
        diagnostics.get(KERNEL_TX_EVIDENCE_RECEIPT_KEY)
        if isinstance(diagnostics, Mapping)
        else None
    )
    if sample.get("runtime_kind") != "buflo":
        if retained_value is not None:
            raise ValueError("non-BuFLO formal class sample claims kernel-TX evidence")
        return None

    sample_id = sample.get("sample_id")
    if (
        not isinstance(sample_id, str)
        or not sample_id
        or Path(sample_id).parts != (sample_id,)
        or sample_id in {".", ".."}
        or not isinstance(retained_value, Mapping)
    ):
        raise ValueError("formal class BuFLO kernel-TX source receipt is invalid")
    retained = retained_value
    source_directory = f"{KERNEL_TX_EVIDENCE_DIRECTORY}/{sample_id}"
    source_artifacts = retained.get("artifacts")
    if (
        set(retained) != _KERNEL_TX_RECEIPT_KEYS
        or retained.get("schema_version") != KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION
        or retained.get("source") != KERNEL_TX_EVIDENCE_RECEIPT_SOURCE
        or retained.get("directory") != source_directory
        or not isinstance(source_artifacts, Mapping)
        or set(source_artifacts) != KERNEL_TX_EVIDENCE_FILES
        or any(not _is_digest(value) for value in source_artifacts.values())
    ):
        raise ValueError("formal class BuFLO kernel-TX source receipt is invalid")

    artifacts: dict[str, dict[str, str]] = {}
    for name in sorted(KERNEL_TX_EVIDENCE_FILES):
        source_path = f"{source_directory}/{name}"
        digest = str(source_artifacts[name])
        source = receipt.root / source_path
        if (
            receipt.checksums.get(source_path) != digest
            or source.is_symlink()
            or not source.is_file()
        ):
            raise ValueError("formal class BuFLO kernel-TX source differs from its evidence seal")
        artifacts[name] = {
            "source_path": source_path,
            "path": (
                f"{KERNEL_TX_EVIDENCE_DIRECTORY}/block-{block_index:02d}/"
                f"{sample_id}/{name}"
            ),
            "sha256": digest,
        }
    return {
        "schema_version": _KERNEL_TX_BINDING_SCHEMA_VERSION,
        "source_receipt": {
            "diagnostics_key": KERNEL_TX_EVIDENCE_RECEIPT_KEY,
            "schema_version": KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION,
            "source": KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
            "directory": source_directory,
        },
        "artifacts": artifacts,
    }


def _export_kernel_tx_sidecar(
    candidate: Path,
    receipt: VerifiedResult,
    sample: Mapping[str, Any],
    *,
    block_index: int,
) -> dict[str, Any] | None:
    binding = _expected_kernel_tx_binding(receipt, sample, block_index=block_index)
    if binding is None:
        return None
    for artifact in binding["artifacts"].values():
        source = receipt.root / artifact["source_path"]
        destination = candidate / artifact["path"]
        _copy_sealed_file(receipt, source, destination)
        if sha256_file(destination) != artifact["sha256"]:
            raise ValueError("formal class copied BuFLO kernel-TX evidence changed")
    return binding


def _export_sample(
    candidate: Path,
    receipt: VerifiedResult,
    sample: Mapping[str, Any],
    *,
    block_index: int,
    split: str,
    result_evidence_sha256: str,
    trace_extractor: TraceExtractor,
    classic_pcap_writer: ClassicPcapWriter,
    correctness_validator: CorrectnessValidator,
    performance_extractor: PerformanceExtractor,
) -> dict[str, Any]:
    sample_id = str(sample["sample_id"])
    sample_root = resolved_sample_directory(receipt.root, sample, require_directory=True)
    output_root = candidate / f"raw/block-{block_index:02d}/{sample_id}"
    output_root.mkdir(parents=True)
    products: dict[str, dict[str, str]] = {}
    source_artifacts: dict[str, dict[str, str]] = {}
    for label, relative in _SOURCE_ARTIFACTS.items():
        source = sample_root / relative
        destination = output_root / Path(relative).name
        _copy_sealed_file(receipt, source, destination)
        path = destination.relative_to(candidate).as_posix()
        digest = sha256_file(destination)
        products[label] = {"path": path, "sha256": digest}
        source_artifacts[label] = {
            "path": source.relative_to(receipt.root).as_posix(),
            "sha256": digest,
        }

    run = load_json(candidate / products["run"]["path"])
    run_binding = resolve_class_sample_run_binding(
        receipt.root,
        receipt.experiment["configuration"],
        sample,
    )
    input_bindings = run_binding.receipt()
    validate_class_sample_run_binding(run, sample, run_binding)
    _verify_current_candidate_algorithm_evidence(
        run,
        mode=str(sample["defense"]),
        runtime_kind=str(sample["runtime_kind"]),
        sample_id=sample_id,
        schedule_path=candidate / products["schedule"]["path"],
        events_path=candidate / products["events"]["path"],
        packets_path=candidate / products["packets"]["path"],
    )
    kernel_tx_evidence = _export_kernel_tx_sidecar(
        candidate,
        receipt,
        sample,
        block_index=block_index,
    )
    endpoints = run.get("endpoints") if isinstance(run, Mapping) else None
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError("formal class raw run has no endpoint inventory")
    trace = trace_extractor(candidate / products["pcapng"]["path"], endpoints)
    if not trace:
        raise ValueError("formal class observer trace is empty")

    classic = output_root / "capture.pcap"
    classic_pcap_writer(candidate / products["pcapng"]["path"], classic)
    products["classic_pcap"] = _file_binding(candidate, classic)
    shape = candidate / f"shape/block-{block_index:02d}/{sample_id}.pcap"
    shape.parent.mkdir(parents=True, exist_ok=True)
    _write_shape_only_pcap(trace, shape)
    products["shape_pcap"] = _file_binding(candidate, shape)
    trace_path = candidate / f"traces/block-{block_index:02d}/{sample_id}.csv"
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    _write_classifier_trace(trace, trace_path)
    products["trace_csv"] = _file_binding(candidate, trace_path)

    workload_id = str(sample["workload_id"])
    correctness_validator(
        {
            "workload_id": workload_id,
            "runtime_kind": sample["runtime_kind"],
            "defense": sample["defense"],
        },
        run=run,
        workload_path=candidate / f"inputs/workloads/{workload_id}.json",
        schedule_path=candidate / products["schedule"]["path"],
        formal=True,
    )
    performance = performance_extractor(run, trace)
    if not isinstance(performance, dict):
        raise ValueError("formal class performance extractor returned no mapping")
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": sample_id,
        "class_label": workload_id,
        "workload_id": workload_id,
        "mode": sample["defense"],
        "runtime_kind": sample["runtime_kind"],
        "baseline": sample["baseline"],
        "request_policy": sample["request_policy"],
        "visit": sample["visit"],
        "seed": sample["seed"],
        "attempts": sample["attempts"],
        "evidence_role": "formal",
        "acquisition_block": block_index,
        "split": split,
        "paired_class_visit_id": (
            f"block-{block_index:02d}/{workload_id}/visit-{sample['visit']:02d}"
        ),
        "input_bindings": input_bindings,
        "kernel_tx_evidence": kernel_tx_evidence,
        "source": {
            "result_name": receipt.experiment["name"],
            "result_root": str(receipt.root),
            "result_evidence_sha256": result_evidence_sha256,
            "sample_path": sample["path"],
            "artifacts": source_artifacts,
        },
        "products": products,
        "observer_packet_count": len(trace),
        "classifier_feature_fields": list(CLASSIFIER_FIELDS),
        "correctness": dict(_CORRECTNESS_RECEIPT),
        "performance": performance,
    }


def _block_receipt(
    receipt: VerifiedResult,
    *,
    block_index: int,
    split: str,
    context: _SourceContext,
) -> dict[str, Any]:
    experiment = receipt.experiment
    configuration = experiment["configuration"]
    return {
        "block": block_index,
        "split": split,
        "result_name": experiment["name"],
        "result_root": str(receipt.root),
        "result_evidence_sha256": sha256_file(receipt.root / "evidence.sha256"),
        "authoritative_file_count": len(receipt.checksums),
        "input_digest": experiment["input_digest"],
        "campaign_sha256": configuration["campaign_sha256"],
        "configuration_sha256": _canonical_digest(configuration),
        "class_study_launch_sha256": configuration["class_study_launch_sha256"],
        "class_study_foundation_sha256": context.class_study_foundation_sha256,
        "class_study_readiness_sha256": context.class_study_readiness_sha256,
        "class_study_historical_pre_snapshot_sha256": (
            context.class_study_historical_pre_snapshot_sha256
        ),
        "defense_runtime_inputs_sha256": _canonical_digest(context.defense_runtime_inputs),
        "chaff_qualification_set": context.chaff_qualification_set,
        "chaff_qualification_set_manifest_sha256": (
            context.chaff_qualification_set_manifest_sha256
        ),
        "class_cohort_sha256": context.cohort_sha256,
        "class_cohort_assembly_sha256": context.cohort_assembly_sha256,
        "class_manifest_sha256": context.class_manifest_sha256,
        "sample_count": len(experiment["samples"]),
        "started_at": experiment["started_at"],
        "completed_at": experiment["completed_at"],
    }


def _dataset_receipt(
    rows: Sequence[Mapping[str, Any]],
    blocks: Sequence[Mapping[str, Any]],
    context: _SourceContext,
    *,
    dimensions: _StudyDimensions,
    handoff_root: Path,
) -> dict[str, Any]:
    split_counts = Counter(str(row["split"]) for row in rows)
    mode_counts = Counter(str(row["mode"]) for row in rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "purpose": PURPOSE,
        "study_id": dimensions.study_id,
        "evidence_role": "formal",
        "closed_world": True,
        "paper_equivalent": False,
        "implementation_scope": "client_only_quic",
        "sample_count": len(rows),
        "class_count": len(context.class_ids),
        "classes": list(context.class_ids),
        "modes": list(dimensions.modes),
        "counts_by_mode": {mode: mode_counts[mode] for mode in dimensions.modes},
        "counts_by_split": {
            split: split_counts[split] for split in ("train", "validation", "test")
        },
        "resource_origin_profile": _resource_origin_profile(context),
        "temporal_protocol": {
            "train_blocks": list(range(1, dimensions.block_count - 1)),
            "validation_blocks": [dimensions.block_count - 1],
            "test_blocks": [dimensions.block_count],
            "visits_per_class_mode": {
                "train": (dimensions.block_count - 2) * dimensions.visits_per_block,
                "validation": dimensions.visits_per_block,
                "test": dimensions.visits_per_block,
                "total": dimensions.block_count * dimensions.visits_per_block,
            },
        },
        "observation": {
            "layer": "capture-interface Ethernet frame",
            "direction": "client egress outgoing; server ingress incoming",
            "classifier_fields": list(CLASSIFIER_FIELDS),
            "forbidden_fields": list(FORBIDDEN_CLASSIFIER_FIELDS),
            "raw_evidence_restricted": True,
            "shape_pcap_identifiers": "fixed synthetic non-source identifiers",
        },
        "role_exclusion": {
            "included_evidence_roles": ["formal"],
            "excluded_evidence_roles": [role for role in EVIDENCE_ROLES if role != "formal"],
            "excluded_modes": ["static"],
        },
        "class_cohort": {
            "path": COHORT_INPUT,
            "sha256": context.cohort_sha256,
            "payload_sha256": context.cohort_payload_sha256,
        },
        "class_cohort_assembly": {
            "path": COHORT_ASSEMBLY_INPUT,
            "sha256": context.cohort_assembly_sha256,
            "payload_sha256": context.cohort_assembly_payload_sha256,
        },
        "class_study_launches": {
            "source_path": CLASS_STUDY_LAUNCH_INPUT,
            "blocks": [
                {
                    "block": block_index,
                    "path": _launch_copy_path(block_index),
                    "sha256": digest,
                }
                for block_index, digest in enumerate(
                    context.class_study_launch_sha256s,
                    start=1,
                )
            ],
        },
        "class_study_successor": (
            {
                "path": "inputs/class-study-successor.json",
                "sha256": context.class_study_successor_sha256,
            }
            if context.class_study_successor_sha256 is not None
            else None
        ),
        "capture_authority": {
            "foundation": {
                "path": CLASS_STUDY_FOUNDATION_INPUT,
                "sha256": context.class_study_foundation_sha256,
            },
            "readiness": {
                "path": CLASS_STUDY_READINESS_INPUT,
                "sha256": context.class_study_readiness_sha256,
            },
            "historical_pre_snapshot": {
                "path": CLASS_STUDY_HISTORICAL_PRE_INPUT,
                "sha256": context.class_study_historical_pre_snapshot_sha256,
            },
        },
        "historical_post_snapshot": {
            "path": CLASS_STUDY_HISTORICAL_POST_INPUT,
            "sha256": context.class_study_historical_post_snapshot_sha256,
            "payload_sha256": (
                context.class_study_historical_post_snapshot_payload_sha256
            ),
        },
        "runtime_contract": {
            "defense_runtime_inputs": context.defense_runtime_inputs,
            "defense_runtime_inputs_sha256": _canonical_digest(context.defense_runtime_inputs),
            "chaff_qualification_set": context.chaff_qualification_set,
            "chaff_qualification_set_manifest_sha256": (
                context.chaff_qualification_set_manifest_sha256
            ),
        },
        "class_manifest": {
            "path": CLASS_MANIFEST_PATH,
            "sha256": sha256_file(handoff_root / CLASS_MANIFEST_PATH),
            "classes_sha256": context.class_manifest_sha256,
        },
        "execution_source": {
            "path": EXECUTION_SOURCE_PATH,
            "sha256": _canonical_digest(context.execution_source),
            "value": context.execution_source,
        },
        "blocks": list(blocks),
        "exporter_source": source_metadata(),
    }


def _validate_published_tree(
    root: Path,
    *,
    context: _SourceContext,
    dimensions: _StudyDimensions,
    deep: bool,
    trace_extractor: TraceExtractor,
    classic_pcap_writer: ClassicPcapWriter,
    correctness_validator: CorrectnessValidator,
    performance_extractor: PerformanceExtractor,
) -> None:
    root = root.resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("formal class handoff is not a regular directory")
    if {item.name for item in root.iterdir()} != _TOP_LEVEL:
        raise ValueError("formal class handoff top-level inventory is invalid")
    checksums = _read_checksums(root / "SHA256SUMS")
    files = _regular_tree_files(root, exclude={"SHA256SUMS"})
    if set(checksums) != set(files):
        raise ValueError("formal class checksum inventory is not closed")
    for relative, digest in checksums.items():
        if sha256_file(files[relative]) != digest:
            raise ValueError(f"formal class handoff digest mismatch: {relative}")

    dataset = _read_json_object(root / "dataset.json", "formal class dataset")
    rows = _read_json_lines(root / "samples.jsonl")
    _validate_dataset(dataset, rows, context=context, dimensions=dimensions, root=root)
    _validate_rows(
        root,
        rows,
        context=context,
        dimensions=dimensions,
        deep=deep,
        trace_extractor=trace_extractor,
        classic_pcap_writer=classic_pcap_writer,
        correctness_validator=correctness_validator,
        performance_extractor=performance_extractor,
        handoff_checksums=checksums,
    )


def _validate_dataset(
    dataset: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    *,
    context: _SourceContext,
    dimensions: _StudyDimensions,
    root: Path,
) -> None:
    blocks = dataset.get("blocks")
    if (
        set(dataset) != _DATASET_KEYS
        or dataset.get("schema_version") != SCHEMA_VERSION
        or dataset.get("artifact_type") != ARTIFACT_TYPE
        or dataset.get("purpose") != PURPOSE
        or dataset.get("study_id") != dimensions.study_id
        or dataset.get("evidence_role") != "formal"
        or dataset.get("closed_world") is not True
        or dataset.get("paper_equivalent") is not False
        or dataset.get("implementation_scope") != "client_only_quic"
        or dataset.get("sample_count") != dimensions.sample_count
        or len(rows) != dimensions.sample_count
        or dataset.get("class_count") != dimensions.class_count
        or dataset.get("classes") != list(context.class_ids)
        or dataset.get("modes") != list(dimensions.modes)
        or not isinstance(blocks, list)
        or len(blocks) != dimensions.block_count
    ):
        raise ValueError("formal class dataset identity or dimensions are invalid")
    if dataset.get("counts_by_mode") != {
        mode: dimensions.block_count * dimensions.class_count * dimensions.visits_per_block
        for mode in dimensions.modes
    }:
        raise ValueError("formal class dataset mode counts are invalid")
    split_per_block = dimensions.samples_per_block
    if dataset.get("counts_by_split") != {
        "train": (dimensions.block_count - 2) * split_per_block,
        "validation": split_per_block,
        "test": split_per_block,
    }:
        raise ValueError("formal class dataset split counts are invalid")
    if dataset.get("resource_origin_profile") != _resource_origin_profile(context):
        raise ValueError("formal class resource-origin profile is invalid")
    expected_successor = (
        {
            "path": "inputs/class-study-successor.json",
            "sha256": context.class_study_successor_sha256,
        }
        if context.class_study_successor_sha256 is not None
        else None
    )
    if dataset.get("class_study_successor") != expected_successor:
        raise ValueError("formal class dataset successor authority is invalid")
    if expected_successor is not None:
        successor_path = _safe_handoff_file(root, expected_successor["path"])
        if sha256_file(successor_path) != expected_successor["sha256"]:
            raise ValueError("formal class handoff successor authority is invalid")
    expected_authority = {
        "foundation": {
            "path": CLASS_STUDY_FOUNDATION_INPUT,
            "sha256": context.class_study_foundation_sha256,
        },
        "readiness": {
            "path": CLASS_STUDY_READINESS_INPUT,
            "sha256": context.class_study_readiness_sha256,
        },
        "historical_pre_snapshot": {
            "path": CLASS_STUDY_HISTORICAL_PRE_INPUT,
            "sha256": context.class_study_historical_pre_snapshot_sha256,
        },
    }
    if dataset.get("capture_authority") != expected_authority or any(
        sha256_file(_safe_handoff_file(root, binding["path"])) != binding["sha256"]
        for binding in expected_authority.values()
    ):
        raise ValueError("formal class handoff capture authority is invalid")
    expected_post = {
        "path": CLASS_STUDY_HISTORICAL_POST_INPUT,
        "sha256": context.class_study_historical_post_snapshot_sha256,
        "payload_sha256": (
            context.class_study_historical_post_snapshot_payload_sha256
        ),
    }
    if (
        dataset.get("historical_post_snapshot") != expected_post
        or not _is_digest(expected_post["sha256"])
        or not _is_digest(expected_post["payload_sha256"])
        or sha256_file(_safe_handoff_file(root, CLASS_STUDY_HISTORICAL_POST_INPUT))
        != expected_post["sha256"]
    ):
        raise ValueError("formal class handoff historical-post authority is invalid")
    if dataset.get("runtime_contract") != {
        "defense_runtime_inputs": context.defense_runtime_inputs,
        "defense_runtime_inputs_sha256": _canonical_digest(context.defense_runtime_inputs),
        "chaff_qualification_set": context.chaff_qualification_set,
        "chaff_qualification_set_manifest_sha256": (
            context.chaff_qualification_set_manifest_sha256
        ),
    }:
        raise ValueError("formal class handoff runtime contract is invalid")
    if dataset.get("temporal_protocol") != {
        "train_blocks": list(range(1, dimensions.block_count - 1)),
        "validation_blocks": [dimensions.block_count - 1],
        "test_blocks": [dimensions.block_count],
        "visits_per_class_mode": {
            "train": (dimensions.block_count - 2) * dimensions.visits_per_block,
            "validation": dimensions.visits_per_block,
            "test": dimensions.visits_per_block,
            "total": dimensions.block_count * dimensions.visits_per_block,
        },
    }:
        raise ValueError("formal class temporal split receipt is invalid")
    if dataset.get("observation") != {
        "layer": "capture-interface Ethernet frame",
        "direction": "client egress outgoing; server ingress incoming",
        "classifier_fields": list(CLASSIFIER_FIELDS),
        "forbidden_fields": list(FORBIDDEN_CLASSIFIER_FIELDS),
        "raw_evidence_restricted": True,
        "shape_pcap_identifiers": "fixed synthetic non-source identifiers",
    }:
        raise ValueError("formal class classifier feature restriction is invalid")
    if dataset.get("role_exclusion") != {
        "included_evidence_roles": ["formal"],
        "excluded_evidence_roles": [role for role in EVIDENCE_ROLES if role != "formal"],
        "excluded_modes": ["static"],
    }:
        raise ValueError("formal class evidence-role exclusion is invalid")
    exporter_source = dataset.get("exporter_source")
    if (
        not isinstance(exporter_source, Mapping)
        or exporter_source != context.execution_source
        or (dimensions.require_immutable_source and not _immutable_source(exporter_source))
    ):
        raise ValueError("formal class exporter source differs from the capture execution source")

    cohort = dataset.get("class_cohort")
    cohort_assembly = dataset.get("class_cohort_assembly")
    launches = dataset.get("class_study_launches")
    manifest = dataset.get("class_manifest")
    execution = dataset.get("execution_source")
    if (
        cohort
        != {
            "path": COHORT_INPUT,
            "sha256": context.cohort_sha256,
            "payload_sha256": context.cohort_payload_sha256,
        }
        or cohort_assembly
        != {
            "path": COHORT_ASSEMBLY_INPUT,
            "sha256": context.cohort_assembly_sha256,
            "payload_sha256": context.cohort_assembly_payload_sha256,
        }
        or launches
        != {
            "source_path": CLASS_STUDY_LAUNCH_INPUT,
            "blocks": [
                {
                    "block": block_index,
                    "path": _launch_copy_path(block_index),
                    "sha256": digest,
                }
                for block_index, digest in enumerate(
                    context.class_study_launch_sha256s,
                    start=1,
                )
            ],
        }
        or not isinstance(manifest, Mapping)
        or manifest.get("path") != CLASS_MANIFEST_PATH
        or manifest.get("classes_sha256") != context.class_manifest_sha256
        or not isinstance(execution, Mapping)
        or execution.get("path") != EXECUTION_SOURCE_PATH
        or execution.get("value") != context.execution_source
    ):
        raise ValueError("formal class frozen input bindings are invalid")
    if (
        sha256_file(root / COHORT_INPUT) != context.cohort_sha256
        or sha256_file(root / COHORT_ASSEMBLY_INPUT) != context.cohort_assembly_sha256
        or any(
            sha256_file(root / _launch_copy_path(block_index)) != digest
            for block_index, digest in enumerate(
                context.class_study_launch_sha256s,
                start=1,
            )
        )
        or sha256_file(root / CLASS_MANIFEST_PATH) != manifest.get("sha256")
        or sha256_file(root / EXECUTION_SOURCE_PATH) != execution.get("sha256")
    ):
        raise ValueError("formal class copied input digest is invalid")
    if load_json(root / CLASS_MANIFEST_PATH) != _class_manifest(context, dimensions):
        raise ValueError("formal class copied class manifest is invalid")
    for workload in context.workload_records:
        copied = root / f"inputs/workloads/{workload['id']}.json"
        if copied.is_symlink() or not copied.is_file() or sha256_file(copied) != workload["sha256"]:
            raise ValueError("formal class copied prepared workload differs from its source")

    expected_blocks = [
        _block_receipt(
            receipt,
            block_index=index,
            split=_split_for_block(index, dimensions.block_count),
            context=context,
        )
        for index, receipt in enumerate(context.receipts, start=1)
    ]
    if blocks != expected_blocks:
        raise ValueError("formal class source block lineage is invalid")


def _validate_rows(
    root: Path,
    rows: Sequence[Mapping[str, Any]],
    *,
    context: _SourceContext,
    dimensions: _StudyDimensions,
    deep: bool,
    trace_extractor: TraceExtractor,
    classic_pcap_writer: ClassicPcapWriter,
    correctness_validator: CorrectnessValidator,
    performance_extractor: PerformanceExtractor,
    handoff_checksums: Mapping[str, str],
) -> None:
    source_samples = {
        (block_index, str(sample["sample_id"])): (receipt, sample)
        for block_index, receipt in enumerate(context.receipts, start=1)
        for sample in receipt.experiment["samples"]
    }
    expected_pairs = Counter(
        (block, class_id, visit, mode)
        for block in range(1, dimensions.block_count + 1)
        for class_id in context.class_ids
        for visit in range(dimensions.visits_per_block)
        for mode in dimensions.modes
    )
    actual_pairs: Counter[tuple[int, str, int, str]] = Counter()
    seen_ids: set[str] = set()
    source_evidence = {
        block: sha256_file(receipt.root / "evidence.sha256")
        for block, receipt in enumerate(context.receipts, start=1)
    }
    expected_files = {
        "README.md",
        "dataset.json",
        "samples.jsonl",
        COHORT_INPUT,
        COHORT_ASSEMBLY_INPUT,
        CLASS_STUDY_FOUNDATION_INPUT,
        CLASS_STUDY_READINESS_INPUT,
        CLASS_STUDY_HISTORICAL_PRE_INPUT,
        CLASS_STUDY_HISTORICAL_POST_INPUT,
        CLASS_MANIFEST_PATH,
        EXECUTION_SOURCE_PATH,
        *(_launch_copy_path(block_index) for block_index in range(1, dimensions.block_count + 1)),
        *(f"inputs/workloads/{workload_id}.json" for workload_id in context.class_ids),
    }
    if context.class_study_successor_sha256 is not None:
        expected_files.add("inputs/class-study-successor.json")
    replay_root = Path(tempfile.mkdtemp(prefix="qcsd-classic-pcap-replay-")) if deep else None
    try:
        for row_index, row in enumerate(rows):
            block = row.get("acquisition_block")
            sample_id = row.get("sample_id")
            if type(block) is not int or not isinstance(sample_id, str):
                raise ValueError("formal class row source identity is invalid")
            key = (block, sample_id)
            source_value = source_samples.get(key)
            if source_value is None or sample_id in seen_ids:
                raise ValueError("formal class row does not map one-to-one to a source sample")
            seen_ids.add(sample_id)
            receipt, sample = source_value
            mode = str(sample["defense"])
            workload_id = str(sample["workload_id"])
            visit = int(sample["visit"])
            expected_split = _split_for_block(block, dimensions.block_count)
            run_binding = resolve_class_sample_run_binding(
                receipt.root,
                receipt.experiment["configuration"],
                sample,
            )
            expected_input_bindings = run_binding.receipt()
            expected_source_artifacts = {
                label: {
                    "path": f"{sample['path']}/{relative}",
                    "sha256": sample["artifacts"][f"{sample['path']}/{relative}"],
                }
                for label, relative in _SOURCE_ARTIFACTS.items()
            }
            expected_kernel_tx = _expected_kernel_tx_binding(
                receipt,
                sample,
                block_index=block,
            )
            source = row.get("source")
            products = row.get("products")
            if (
                set(row) != _ROW_KEYS
                or row.get("schema_version") != SCHEMA_VERSION
                or row.get("class_label") != workload_id
                or row.get("workload_id") != workload_id
                or row.get("mode") != mode
                or row.get("runtime_kind") != sample["runtime_kind"]
                or row.get("baseline") != sample["baseline"]
                or row.get("request_policy") != "as-defined"
                or row.get("visit") != visit
                or row.get("seed") != sample["seed"]
                or type(row.get("attempts")) is not int
                or row.get("attempts") != sample["attempts"]
                or row.get("evidence_role") != "formal"
                or row.get("split") != expected_split
                or row.get("paired_class_visit_id")
                != f"block-{block:02d}/{workload_id}/visit-{visit:02d}"
                or row.get("input_bindings") != expected_input_bindings
                or row.get("kernel_tx_evidence") != expected_kernel_tx
                or row.get("classifier_feature_fields") != list(CLASSIFIER_FIELDS)
                or not isinstance(source, Mapping)
                or set(source)
                != {
                    "result_name",
                    "result_root",
                    "result_evidence_sha256",
                    "sample_path",
                    "artifacts",
                }
                or source.get("result_name") != receipt.experiment["name"]
                or source.get("result_root") != str(receipt.root)
                or source.get("result_evidence_sha256") != source_evidence[block]
                or source.get("sample_path") != sample["path"]
                or source.get("artifacts") != expected_source_artifacts
                or not isinstance(products, Mapping)
                or set(products) != {*_SOURCE_ARTIFACTS, "classic_pcap", "shape_pcap", "trace_csv"}
            ):
                raise ValueError("formal class row differs from its source identity")
            actual_pairs[(block, workload_id, visit, mode)] += 1

            for label in (*_SOURCE_ARTIFACTS, "classic_pcap", "shape_pcap", "trace_csv"):
                binding = products.get(label)
                if not isinstance(binding, Mapping):
                    raise ValueError("formal class row product binding is missing")
                relative = binding.get("path")
                if (
                    set(binding) != {"path", "sha256"}
                    or not isinstance(relative, str)
                    or not _is_digest(binding.get("sha256"))
                ):
                    raise ValueError("formal class row product binding is invalid")
                _safe_handoff_file(root, relative)
                if handoff_checksums.get(relative) != binding["sha256"]:
                    raise ValueError("formal class row product digest is invalid")
                expected_files.add(relative)
            expected_product_paths = {
                **{
                    label: f"raw/block-{block:02d}/{sample_id}/{Path(relative).name}"
                    for label, relative in _SOURCE_ARTIFACTS.items()
                },
                "classic_pcap": f"raw/block-{block:02d}/{sample_id}/capture.pcap",
                "shape_pcap": f"shape/block-{block:02d}/{sample_id}.pcap",
                "trace_csv": f"traces/block-{block:02d}/{sample_id}.csv",
            }
            if {
                label: products[label]["path"] for label in expected_product_paths
            } != expected_product_paths:
                raise ValueError(
                    "formal class row product path differs from its canonical identity"
                )
            for label in _SOURCE_ARTIFACTS:
                if products[label]["sha256"] != expected_source_artifacts[label]["sha256"]:
                    raise ValueError("formal class copied source artifact changed")
            if expected_kernel_tx is not None:
                for artifact in expected_kernel_tx["artifacts"].values():
                    relative = artifact["path"]
                    _safe_handoff_file(root, relative)
                    if handoff_checksums.get(relative) != artifact["sha256"]:
                        raise ValueError(
                            "formal class copied BuFLO kernel-TX evidence digest is invalid"
                        )
                    expected_files.add(relative)

            csv_trace = _read_classifier_trace(root / products["trace_csv"]["path"])
            shape_trace = _read_shape_only_pcap(root / products["shape_pcap"]["path"])
            if tuple(csv_trace) != shape_trace or row.get("observer_packet_count") != len(
                csv_trace
            ):
                raise ValueError("formal class shape PCAP and trace CSV differ")
            run = load_json(root / products["run"]["path"])
            validate_class_sample_run_binding(run, sample, run_binding)
            if deep:
                _verify_current_candidate_algorithm_evidence(
                    run,
                    mode=mode,
                    runtime_kind=str(sample["runtime_kind"]),
                    sample_id=sample_id,
                    schedule_path=root / products["schedule"]["path"],
                    events_path=root / products["events"]["path"],
                    packets_path=root / products["packets"]["path"],
                )
            correctness_validator(
                {
                    "workload_id": workload_id,
                    "runtime_kind": sample["runtime_kind"],
                    "defense": sample["defense"],
                },
                run=run,
                workload_path=root / f"inputs/workloads/{workload_id}.json",
                schedule_path=root / products["schedule"]["path"],
                formal=True,
            )
            if row.get("correctness") != _CORRECTNESS_RECEIPT:
                raise ValueError("formal class correctness receipt is invalid")
            shape_packets = tuple(ShapePacket(*packet) for packet in shape_trace)
            performance = _load_performance(row.get("performance"), shape_packets)
            if (
                not isinstance(performance, Mapping)
                or not isinstance(performance.get("client_resource_usage"), Mapping)
                or type(performance.get("transport_retransmissions")) is not int
                or performance.get("udp_payload_lengths_missing") != {"outgoing": 0, "incoming": 0}
            ):
                raise ValueError("formal class performance evidence is incomplete")
            if deep:
                assert replay_root is not None
                endpoints = run.get("endpoints") if isinstance(run, Mapping) else None
                if not isinstance(endpoints, list) or not endpoints:
                    raise ValueError("formal class raw run has no endpoint inventory")
                pcapng = root / products["pcapng"]["path"]
                raw_trace = trace_extractor(pcapng, endpoints)
                if _trace_identity(raw_trace) != tuple(csv_trace):
                    raise ValueError(
                        "formal class derived trace differs from raw observer evidence"
                    )
                if performance_extractor(run, raw_trace) != performance:
                    raise ValueError("formal class performance differs from raw observer evidence")
                regenerated = replay_root / f"{row_index:06d}.pcap"
                classic_pcap_writer(pcapng, regenerated)
                if (
                    regenerated.is_symlink()
                    or not regenerated.is_file()
                    or regenerated.stat().st_size == 0
                    or sha256_file(regenerated) != products["classic_pcap"]["sha256"]
                ):
                    raise ValueError(
                        "formal class classic PCAP differs from regenerated raw evidence"
                    )
                regenerated.unlink()
    finally:
        if replay_root is not None:
            shutil.rmtree(replay_root)

    if actual_pairs != expected_pairs or len(source_samples) != len(rows):
        raise ValueError("formal class rows are not exactly block/class/visit/mode balanced")
    actual_files = set(_regular_tree_files(root, exclude={"SHA256SUMS"}))
    if actual_files != expected_files:
        raise ValueError("formal class handoff contains unbound product files")


def _verify_current_candidate_algorithm_evidence(
    run: Any,
    *,
    mode: str,
    runtime_kind: str,
    sample_id: str,
    schedule_path: Path,
    events_path: Path,
    packets_path: Path,
) -> None:
    """Reopen current candidate chronology from the copied raw evidence.

    The source-result coordinator applies the same gate before a result may be
    promoted, but a handoff is a separately sealed evidence product and its
    public verifier must not rely on that earlier process having run.  Import
    lazily to keep the generic class-handoff module independent of the heavier
    BuFLO parsers for non-candidate rows.
    """

    if runtime_kind not in {"buflo", "cs_buflo"}:
        return
    from .buflo_handoff import _algorithm_diagnostics

    try:
        diagnostics = _algorithm_diagnostics(
            run,
            defense=mode,
            runtime_kind=runtime_kind,
            schedule_path=schedule_path,
            events_path=events_path,
            packets_path=packets_path,
            require_current=True,
            require_latest_cs=True,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(
            f"formal class {mode} sample {sample_id} has invalid current "
            "terminal/schedule chronology"
        ) from error
    if diagnostics.get("schema_version") != 4:
        raise ValueError(
            f"formal class {mode} sample {sample_id} did not derive current "
            "schema-4 algorithm evidence"
        )


def _copy_sealed_file(receipt: VerifiedResult, source: Path, destination: Path) -> None:
    root = receipt.root.resolve()
    source_candidate = source
    source = source_candidate.resolve()
    if not source.is_relative_to(root):
        raise ValueError("formal class source file escapes its result root")
    relative = source.relative_to(root).as_posix()
    expected = receipt.checksums.get(relative)
    if not _is_digest(expected) or source_candidate.is_symlink() or not source.is_file():
        raise ValueError("formal class source file is absent from its evidence seal")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_file, destination.open("xb") as output:
        for block in iter(lambda: input_file.read(1024 * 1024), b""):
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    if sha256_file(destination) != expected:
        raise ValueError("formal class copied source differs from its evidence seal")


def _copy_bound_file(source: Path, destination: Path, *, expected_sha256: str) -> None:
    """Copy one externally sealed authority while retaining its exact digest."""

    source_candidate = Path(source).absolute()
    if (
        source_candidate.is_symlink()
        or not source_candidate.is_file()
        or not _is_digest(expected_sha256)
        or sha256_file(source_candidate) != expected_sha256
    ):
        raise ValueError("formal class bound input changed before handoff export")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source_candidate.open("rb") as input_file, destination.open("xb") as output:
        for block in iter(lambda: input_file.read(1024 * 1024), b""):
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    if (
        sha256_file(source_candidate) != expected_sha256
        or sha256_file(destination) != expected_sha256
    ):
        raise ValueError("formal class bound input changed during handoff export")


def _write_classifier_trace(trace: Sequence[ObserverPacket], path: Path) -> None:
    with path.open("x", newline="", encoding="utf-8") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(CLASSIFIER_FIELDS)
        for packet in trace:
            writer.writerow((packet.relative_time_ns, packet.direction, packet.frame_len))
        output.flush()
        os.fsync(output.fileno())


def _read_classifier_trace(path: Path) -> tuple[tuple[int, str, int], ...]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("formal class trace CSV is not a regular file")
    result: list[tuple[int, str, int]] = []
    previous = -1
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != list(CLASSIFIER_FIELDS):
            raise ValueError("formal class trace exposes fields outside the classifier contract")
        for row in reader:
            if set(row) != set(CLASSIFIER_FIELDS) or row["direction"] not in {
                "outgoing",
                "incoming",
            }:
                raise ValueError("formal class trace row is invalid")
            try:
                timestamp = int(row["relative_time_ns"])
                length = int(row["observer_frame_length_bytes"])
            except (TypeError, ValueError) as error:
                raise ValueError("formal class trace numeric field is invalid") from error
            if timestamp < previous or timestamp < 0 or length <= 0:
                raise ValueError("formal class trace timing or frame length is invalid")
            previous = timestamp
            result.append((timestamp, row["direction"], length))
    if not result or result[0][0] != 0:
        raise ValueError("formal class trace must be non-empty and relative")
    return tuple(result)


def _read_json_lines(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("formal class sample index is not a regular file")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"formal class sample row {line_number} is invalid JSON") from error
        if not isinstance(value, dict) or line != json.dumps(
            value, sort_keys=True, separators=(",", ":")
        ):
            raise ValueError(f"formal class sample row {line_number} is not canonical")
        rows.append(value)
    if not rows:
        raise ValueError("formal class sample index is empty")
    return rows


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is not a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, _canonical_json_bytes(value).decode("utf-8"))


def _write_json_lines(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    value = "".join(
        json.dumps(dict(row), sort_keys=True, separators=(",", ":")) + "\n" for row in rows
    )
    _write_text(
        path,
        value,
    )


def _write_text(path: Path, value: str) -> None:
    with path.open("x", encoding="utf-8") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def _write_checksums(root: Path) -> None:
    files = _regular_tree_files(root)
    if "SHA256SUMS" in files:
        raise ValueError("formal class checksum index already exists")
    _write_text(
        root / "SHA256SUMS",
        "".join(f"{sha256_file(files[path])}  {path}\n" for path in sorted(files)),
    )


def _read_checksums(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("formal class handoff has no regular SHA256SUMS")
    result: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            digest, relative = line.split("  ", 1)
        except ValueError as error:
            raise ValueError(f"formal class checksum line {number} is invalid") from error
        value = Path(relative)
        if (
            not _is_digest(digest)
            or value.is_absolute()
            or ".." in value.parts
            or value.as_posix() != relative
            or relative in result
            or relative == "SHA256SUMS"
        ):
            raise ValueError(f"formal class checksum line {number} is invalid")
        result[relative] = digest
    if not result:
        raise ValueError("formal class checksum inventory is empty")
    return result


def _regular_tree_files(root: Path, *, exclude: set[str] | None = None) -> dict[str, Path]:
    excluded = set() if exclude is None else exclude
    result: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"formal class handoff cannot contain symlinks: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(
                f"formal class handoff contains a special filesystem entry: {path}"
            )
        relative = path.relative_to(root).as_posix()
        if relative not in excluded:
            result[relative] = path
    return result


def _safe_handoff_file(root: Path, relative: str) -> Path:
    value = Path(relative)
    if value.is_absolute() or ".." in value.parts or value.as_posix() != relative:
        raise ValueError("formal class product path is unsafe")
    candidate = (root / value).resolve()
    if not candidate.is_relative_to(root) or candidate.is_symlink() or not candidate.is_file():
        raise ValueError("formal class product is not a regular handoff file")
    return candidate


def _file_binding(root: Path, path: Path) -> dict[str, str]:
    return {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _class_manifest(
    context: _SourceContext,
    dimensions: _StudyDimensions,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "study_id": dimensions.study_id,
        "class_count": len(context.class_ids),
        "classes_sha256": context.class_manifest_sha256,
        "workloads": list(context.workload_records),
    }


def _resource_origin_profile(context: _SourceContext) -> dict[str, Any]:
    class_origin_counts = [
        {
            "class_id": str(workload["id"]),
            "origin_count": int(workload["origin_count"]),
        }
        for workload in context.workload_records
    ]
    distribution = Counter(record["origin_count"] for record in class_origin_counts)
    multi_origin_count = sum(record["origin_count"] > 1 for record in class_origin_counts)
    return {
        "policy": {
            "single_origin_allowed": True,
            "multi_origin_allowed": True,
            "selection_uses_origin_count": False,
            "minimum_multi_origin_classes": 0,
        },
        "single_origin_class_count": len(class_origin_counts) - multi_origin_count,
        "multi_origin_class_count": multi_origin_count,
        "minimum_origin_count": min(record["origin_count"] for record in class_origin_counts),
        "maximum_origin_count": max(record["origin_count"] for record in class_origin_counts),
        "classes_by_origin_count": {
            str(origin_count): distribution[origin_count] for origin_count in sorted(distribution)
        },
        "class_origin_counts": class_origin_counts,
    }


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _compact_json_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


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


def _timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"formal class {label} timestamp is missing")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"formal class {label} timestamp is invalid") from error
    if result.tzinfo is None:
        raise ValueError(f"formal class {label} timestamp has no timezone")
    return result


def _split_for_block(block: int, block_count: int) -> str:
    if block <= block_count - 2:
        return "train"
    if block == block_count - 1:
        return "validation"
    if block == block_count:
        return "test"
    raise ValueError("formal class acquisition block is outside the protocol")


def _existing_handoffs_except(destination: Path) -> tuple[Path, ...]:
    handoffs = (LAB_ROOT / "handoffs").resolve()
    destination = destination.resolve()
    if not handoffs.is_dir():
        return ()
    return tuple(
        child.resolve()
        for child in handoffs.iterdir()
        if child.resolve() != destination and (child.is_dir() or child.is_symlink())
    )


def _handoff_readme(dimensions: _StudyDimensions) -> str:
    return f"""# {dimensions.study_id} formal classifier handoff

This create-only artifact contains {dimensions.sample_count:,} accepted formal
samples: {dimensions.class_count} prepared public-page classes, {len(dimensions.modes)}
modes, {dimensions.block_count} temporal acquisition blocks, and
{dimensions.visits_per_block} visits per class/mode/block. Blocks 1-8 are
training, block 9 is validation, and block 10 is held-out test evidence.

The five accepted source files are preserved under `raw/`; classic raw PCAP is
derived alongside them. Schema-11/12/13 BuFLO kernel-TX sidecars are copied into the
separate `kernel-tx-evidence/` subtree and do not alter that five-file source
inventory. Classifiers must consume only `traces/*.csv` or `shape/*.pcap`.
Those products contain only relative timestamp, client-relative direction, and
observer-frame length. The fixed addresses and ports in shape PCAPs are
synthetic framing and never copied from source traffic. All non-formal campaign
roles and the `static` compatibility mode are excluded.

Schema 3 `dataset.json` and `samples.jsonl` bind class labels, paired visits,
source result seals, cohort/class hashes, modes, blocks, and splits. Every
handoff also copies and hash-binds the independently reconstructed post-formal
historical snapshot for those exact ordered blocks. Every
sample row also binds its prepared application graph, executed runtime graph,
qualified chaff inputs, mode-appropriate defense parameters, and launch limits.
BuFLO rows additionally bind the source sidecar receipt and every copied
kernel-TX artifact by canonical path and SHA-256; all other rows carry `null`.
The semantic verifier checks those receipts against copied evidence.
`SHA256SUMS` is a closed inventory. Run the semantic verifier as well as
`sha256sum -c` before analysis. This is a paper-informed, 100-class closed-world QUIC
study; it is not a reproduction of a bilateral defense or any paper dataset.
"""
